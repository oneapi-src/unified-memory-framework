/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

/*
 * This file defines a benchmarking framework for evaluating memory allocation
 * and deallocation performance using the Unified Memory Framework (UMF). The
 * design is modular and extensible, allowing for flexible benchmarking of different
 * allocation strategies, size distributions, and memory providers.
 *
 * **Key Design Features:**
 * - **Modular Components**: The framework is built using interfaces and templates,
 *   which allows for easy extension and customization of allocation strategies,
 *   size distributions, and memory providers.
 * - **Flexible Allocation Size Generators**: Includes classes like `fixed_alloc_size`
 *   and `uniform_alloc_size` that generate allocation sizes based on different
 *   strategies. These classes implement the `alloc_size_interface`.
 * - **Abstract Allocator Interface**: The `allocator_interface` defines the basic
 *   methods for memory allocation and deallocation. Concrete allocators like
 *   `provider_allocator` and `pool_allocator` implement this interface to work
 *   with different memory providers and pools.
 * - **Benchmarking Classes**: Classes like `alloc_benchmark` and `multiple_malloc_free_benchmark`
 *   templates the allocation size generator and allocator to perform benchmarks.
 *   It manages the setup, execution, and teardown of the benchmark.
 * - **Threaded Execution Support**: The benchmarks support multi-threaded execution
 *   by maintaining thread-specific allocation data and synchronization.
 *
 * **Component Interactions:**
 * - **Size Generators and Allocators**: The `alloc_benchmark` class uses a size
 *   generator (e.g., `fixed_alloc_size` or `uniform_alloc_size`) to determine the
 *   sizes of memory allocations, and an allocator (e.g., `provider_allocator` or
 *   `pool_allocator`) to perform the actual memory operations.
 * - **Benchmark Execution**: During the benchmark, `alloc_benchmark` repeatedly
 *   calls the `bench` method, which performs allocations and deallocations using
 *   the allocator and size generator.
 * - **Allocator Adapters**: The `provider_allocator` and `pool_allocator` adapt
 *   specific memory providers and pools to the `allocator_interface`, allowing
 *   them to be used interchangeably in the benchmark classes. This abstraction
 *   enables benchmarking different memory management strategies without changing
 *   the core benchmarking logic.
 * - **Pre-allocations and Iterations**: The `alloc_benchmark` can perform a set
 *   number of pre-allocations before the benchmark starts, and manages allocation
 *   and deallocation cycles to simulate memory pressure and fragmentation.
 * - **Derived Benchmarks**: `multiple_malloc_free_benchmark` extends
 *   `alloc_benchmark` to perform multiple random deallocations and reallocations
 *   in each iteration, using a uniform distribution to select which allocations
 *   to free and reallocate. This models workloads with frequent memory churn.
 *
 * **Execution Flow:**
 * 1. **Setup Phase**:
 *    - The benchmark class initializes the size generator and allocator.
 *    - Pre-allocations are performed if specified.
 *    - Thread-specific data structures for allocations are prepared.
 * 2. **Benchmark Loop**:
 *    - For each iteration, the `bench` method is called.
 *    - The size generator provides the next allocation size.
 *    - The allocator performs the allocation.
 *    - Allocations are tracked per thread.
 * 3. **Teardown Phase**:
 *    - All remaining allocations are freed.
 *    - Allocator and size generator are cleaned up.
 *
 * **Customization and Extension:**
 * - New size generators can be created by implementing the `alloc_size_interface`.
 * - New allocators can be adapted by implementing the `allocator_interface`.
 * - Additional benchmarking scenarios can be created by extending `benchmark_interface`.
 */

#include <benchmark/benchmark.h>
#include <random>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>

#include "benchmark_interfaces.hpp"

struct alloc_data {
    void *ptr;
    size_t size;
};

#define UMF_BENCHMARK_TEMPLATE_DEFINE(BaseClass, Method, ...)                  \
    BENCHMARK_TEMPLATE_DEFINE_F(BaseClass, Method, __VA_ARGS__)                \
    (benchmark::State & state) {                                               \
        for (auto _ : state) {                                                 \
            bench(state);                                                      \
        }                                                                      \
    }

#define UMF_BENCHMARK_REGISTER_F(BaseClass, Method)                            \
    BENCHMARK_REGISTER_F(BaseClass, Method)                                    \
        ->ArgNames(                                                            \
            BENCHMARK_PRIVATE_CONCAT_NAME(BaseClass, Method)::argsName())      \
        ->Name(BENCHMARK_PRIVATE_CONCAT_NAME(BaseClass, Method)::name())       \
        ->MinWarmUpTime(1)

class fixed_alloc_size : public alloc_size_interface {
  public:
    unsigned SetUp(::benchmark::State &state, unsigned argPos) override {
        size = state.range(argPos);
        return argPos + 1;
    }
    void TearDown([[maybe_unused]] ::benchmark::State &state) override {}
    size_t nextSize() override { return size; };
    static std::vector<std::string> argsName() { return {"size"}; }

  private:
    size_t size;
};

class uniform_alloc_size : public alloc_size_interface {
    using distribution = std::uniform_int_distribution<int64_t>;

  public:
    unsigned SetUp(::benchmark::State &state, unsigned argPos) override {
        auto min = state.range(argPos++);
        auto max = state.range(argPos++);
        auto gran = state.range(argPos++);
        if (min % gran != 0 && max % gran != 0) {
            state.SkipWithError("min and max must be divisible by granularity");
            return argPos;
        }

        dist.param(distribution::param_type(min / gran, max / gran));
        multiplier = gran;
        return argPos;
    }
    void TearDown([[maybe_unused]] ::benchmark::State &state) override {}
    size_t nextSize() override { return dist(generator) * multiplier; }
    static std::vector<std::string> argsName() {
        return {"min size", "max size", "granularity"};
    }

  private:
    std::default_random_engine generator;
    distribution dist;
    size_t multiplier;
};

// This class benchmarks speed of alloc() operations.
template <
    typename Size, typename Alloc,
    typename =
        std::enable_if_t<std::is_base_of<alloc_size_interface, Size>::value>,
    typename =
        std::enable_if_t<std::is_base_of<allocator_interface, Alloc>::value>>
class alloc_benchmark : public benchmark_interface<Size, Alloc> {
  public:
    size_t max_allocs = 1000;
    size_t pre_allocs = 0;
    void SetUp(::benchmark::State &state) override {
        if (state.thread_index() != 0) {
            return;
        }

        // unpack arguments
        int argPos = 0;
        max_allocs = state.range(argPos++);
        pre_allocs = state.range(argPos++);
        // pass rest of the arguments to "alloc_size" and "allocator"
        argPos = base::alloc_size.SetUp(state, argPos);
        base::allocator.SetUp(state, argPos);

        // initialize allocations tracking vectors (one per thread)
        // and iterators for these vectors.
        allocations.resize(state.threads());
        iters.resize(state.threads());

        for (auto &i : iters) {
            i = pre_allocs;
        }

        // do "pre_alloc" allocations before actual benchmark.
        for (auto &i : allocations) {
            i.resize(max_allocs + pre_allocs);

            for (size_t j = 0; j < pre_allocs; j++) {
                i[j].ptr =
                    base::allocator.benchAlloc(base::alloc_size.nextSize());
                if (i[j].ptr == NULL) {
                    state.SkipWithError("preallocation failed");
                    return;
                }
                i[j].size = base::alloc_size.nextSize();
            }
        }
    }

    void TearDown(::benchmark::State &state) override {
        if (state.thread_index() != 0) {
            return;
        }
        for (auto &i : allocations) {
            for (auto &j : i) {
                if (j.ptr != NULL) {
                    base::allocator.benchFree(j.ptr, j.size);
                    j.ptr = NULL;
                    j.size = 0;
                }
            }
        }

        base::TearDown(state);
    }

    void bench(benchmark::State &state) override {
        auto tid = state.thread_index();
        auto s = base::alloc_size.nextSize();
        auto &i = iters[tid];
        allocations[tid][i].ptr = base::allocator.benchAlloc(s);
        if (allocations[tid][i].ptr == NULL) {
            state.SkipWithError("allocation failed");
            return;
        }
        allocations[tid][i].size = s;
        i++;
        if (i >= max_allocs + pre_allocs) {
            // This benchmark tests only allocations -
            // if allocation tracker is full we pause benchmark to dealloc all allocations -
            // excluding pre-allocated ones.
            state.PauseTiming();
            while (i > pre_allocs) {
                auto &allocation = allocations[tid][--i];
                base::allocator.benchFree(allocation.ptr, allocation.size);
                allocation.ptr = NULL;
                allocation.size = 0;
            }
            state.ResumeTiming();
        }
    }
    static std::vector<std::string> argsName() {
        auto n = benchmark_interface<Size, Alloc>::argsName();
        std::vector<std::string> res = {"max_allocs", "pre_allocs"};
        res.insert(res.end(), n.begin(), n.end());
        return res;
    }
    static std::string name() { return base::name() + "/alloc"; }

  protected:
    using base = benchmark_interface<Size, Alloc>;
    std::vector<std::vector<alloc_data>> allocations;
    std::vector<size_t> iters;
};

// This class benchmarks performance of random deallocations and (re)allocations
template <
    typename Size, typename Alloc,
    typename =
        std::enable_if_t<std::is_base_of<alloc_size_interface, Size>::value>,
    typename =
        std::enable_if_t<std::is_base_of<allocator_interface, Alloc>::value>>
class multiple_malloc_free_benchmark : public alloc_benchmark<Size, Alloc> {
    using distribution = std::uniform_int_distribution<size_t>;
    using base = alloc_benchmark<Size, Alloc>;

  public:
    int reallocs = 100;
    void SetUp(::benchmark::State &state) override {
        if (state.thread_index() != 0) {
            return;
        }
        // unpack arguments
        int argPos = 0;
        base::max_allocs = state.range(argPos++);

        // pass rest of the arguments to "alloc_size" and "allocator"
        argPos = base::alloc_size.SetUp(state, argPos);
        base::allocator.SetUp(state, argPos);

        // perform initial allocations which will be later freed and reallocated
        base::allocations.resize(state.threads());
        for (auto &i : base::allocations) {
            i.resize(base::max_allocs);

            for (size_t j = 0; j < base::max_allocs; j++) {
                i[j].ptr =
                    base::allocator.benchAlloc(base::alloc_size.nextSize());
                if (i[j].ptr == NULL) {
                    state.SkipWithError("preallocation failed");
                    return;
                }
                i[j].size = base::alloc_size.nextSize();
            }
        }
        dist.param(distribution::param_type(0, base::max_allocs - 1));
    }

    void bench(benchmark::State &state) override {
        auto tid = state.thread_index();
        auto &allocation = base::allocations[tid];
        std::vector<size_t> to_alloc;
        for (int j = 0; j < reallocs; j++) {
            auto idx = dist(generator);
            if (allocation[idx].ptr == NULL) {
                continue;
            }
            to_alloc.push_back(idx);

            base::allocator.benchFree(allocation[idx].ptr,
                                      allocation[idx].size);
            allocation[idx].ptr = NULL;
            allocation[idx].size = 0;
        }

        for (auto idx : to_alloc) {
            auto s = base::alloc_size.nextSize();
            allocation[idx].ptr = base::allocator.benchAlloc(s);
            if (allocation[idx].ptr == NULL) {
                state.SkipWithError("allocation failed");
            }
            allocation[idx].size = s;
        }
    }

    static std::string name() {
        return base::base::name() + "/multiple_malloc_free";
    }
    static std::vector<std::string> argsName() {
        auto n = benchmark_interface<Size, Alloc>::argsName();
        std::vector<std::string> res = {"max_allocs"};
        res.insert(res.end(), n.begin(), n.end());
        return res;
    }
    std::default_random_engine generator;
    distribution dist;
};

template <typename Provider, typename = std::enable_if_t<std::is_base_of<
                                 provider_interface, Provider>::value>>
class provider_allocator : public allocator_interface {
  public:
    unsigned SetUp(::benchmark::State &state, unsigned r) override {
        provider.SetUp(state);
        return r;
    }

    void TearDown(::benchmark::State &state) override {
        provider.TearDown(state);
    }

    void *benchAlloc(size_t size) override {
        void *ptr;
        if (umfMemoryProviderAlloc(provider.provider, size, 0, &ptr) !=
            UMF_RESULT_SUCCESS) {
            return NULL;
        }
        return ptr;
    }
    void benchFree(void *ptr, size_t size) override {
        umfMemoryProviderFree(provider.provider, ptr, size);
    }
    static std::string name() { return Provider::name(); }

  private:
    Provider provider;
};

// TODO: assert Pool to be a pool_interface<provider_interface>.
template <typename Pool> class pool_allocator : public allocator_interface {
  public:
    unsigned SetUp(::benchmark::State &state, unsigned r) override {
        pool.SetUp(state);
        return r;
    }

    void TearDown(::benchmark::State &state) override { pool.TearDown(state); }

    virtual void *benchAlloc(size_t size) override {
        return umfPoolMalloc(pool.pool, size);
    }
    virtual void benchFree(void *ptr, [[maybe_unused]] size_t size) override {
        umfPoolFree(pool.pool, ptr);
    }

    static std::string name() { return Pool::name(); }

  private:
    Pool pool;
};
