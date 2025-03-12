/*
 * Copyright (C) 2024-2025 Intel Corporation
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

#include <malloc.h>
#include <random>

#include <benchmark/benchmark.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>

#include "benchmark_size.hpp"
#include "benchmark_umf.hpp"

struct alloc_data {
    void *ptr;
    size_t size;
};

struct next_alloc_data {
    size_t offset;
    size_t size;
};

#ifndef WIN32
std::vector<cpu_set_t> affinityMask;

int initAffinityMask() {
    cpu_set_t mask;
    CPU_ZERO(&mask);

    if (sched_getaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_getaffinity");
        return 1;
    }

    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (CPU_ISSET(cpu, &mask)) {
            cpu_set_t mask;
            CPU_ZERO(&mask);
            CPU_SET(cpu, &mask);
            affinityMask.push_back(mask);
        }
    }
    // we reverse affinityMask to avoid using cpu 0 if possible.
    // CPU 0 is usually the most used one by other applications on the system.
    std::reverse(affinityMask.begin(), affinityMask.end());
    return 0;
}

void setAffinity(benchmark::State &state) {
    size_t tid = state.thread_index();
    if (tid >= affinityMask.size()) {
        state.SkipWithError("Not enough CPUs available to set affinity");
    }

    auto &mask = affinityMask[tid];

    if (sched_setaffinity(0, sizeof(mask), &mask) != 0) {
        state.SkipWithError("Failed to set affinity");
    }
}

#else
int initAffinityMask() {
    printf(
        "Affinity set not supported on Windows, benchmark can be unstable\n");
    return 0;
}

void setAffinity([[maybe_unused]] benchmark::State &state) {
    // Not implemented for Windows
}

#endif

// function that ensures that all threads have reached the same point
inline void waitForAllThreads(const benchmark::State &state) {
    static std::atomic<int> count{0};
    static std::atomic<int> generation{0};

    const int totalThreads = state.threads();
    int gen = generation.load(std::memory_order_relaxed);

    int c = count.fetch_add(1, std::memory_order_acq_rel) + 1;

    if (c == totalThreads) {
        // Last thread - reset count and bump generation
        count.store(0, std::memory_order_relaxed);
        generation.fetch_add(1, std::memory_order_acq_rel);
    } else {
        // Not the last thread: spin until the generation changes
        while (generation.load(std::memory_order_acquire) == gen) {
            std::this_thread::yield();
        }
    }
}

template <typename Provider, typename = std::enable_if_t<std::is_base_of<
                                 provider_interface, Provider>::value>>
class provider_allocator : public allocator_interface {
  public:
    unsigned SetUp(::benchmark::State &state, unsigned argPos) override {
        provider.SetUp(state);
        return argPos;
    }

    void preBench(::benchmark::State &state) override {
        provider.preBench(state);
    }

    void postBench(::benchmark::State &state) override {
        provider.postBench(state);
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
    unsigned SetUp(::benchmark::State &state, unsigned argPos) override {
        pool.SetUp(state);
        return argPos;
    }

    void preBench(::benchmark::State &state) override { pool.preBench(state); }
    void postBench(::benchmark::State &state) override {
        pool.postBench(state);
    }

    void TearDown(::benchmark::State &state) override { pool.TearDown(state); }

    void *benchAlloc(size_t size) override {
        return umfPoolMalloc(pool.pool, size);
    }

    void benchFree(void *ptr, [[maybe_unused]] size_t size) override {
        umfPoolFree(pool.pool, ptr);
    }

    static std::string name() { return Pool::name(); }

  private:
    Pool pool;
};

template <typename Size, typename Allocator>
struct benchmark_interface : public benchmark::Fixture {
    int parseArgs(::benchmark::State &state, int argPos) {
        Size generator;
        argPos = generator.SetUp(state, argPos);
        argPos = allocator.SetUp(state, argPos);
        alloc_sizes.resize(state.threads());
        for (auto &i : alloc_sizes) {
            i = generator;
        }
        return argPos;
    }
    void SetUp(::benchmark::State &state) { parseArgs(state, 0); }

    void TearDown(::benchmark::State &state) {
        for (auto &i : alloc_sizes) {
            i.TearDown(state);
        }
        allocator.TearDown(state);
    }

    void bench([[maybe_unused]] ::benchmark::State &state){};

    virtual std::vector<std::string> argsName() {
        auto s = Size::argsName();
        auto a = Allocator::argsName();
        std::vector<std::string> res = {};
        res.insert(res.end(), s.begin(), s.end());
        res.insert(res.end(), a.begin(), a.end());
        return res;
    }

    virtual std::string name() { return Allocator::name(); }

    static void defaultArgs(Benchmark *benchmark) {
        auto *bench =
            static_cast<benchmark_interface<Size, Allocator> *>(benchmark);
        benchmark->ArgNames(bench->argsName())->Name(bench->name());
    }

    void custom_counters(::benchmark::State &state) {
        allocator.custom_counters(state);
    }
    std::vector<Size> alloc_sizes;
    Allocator allocator;
};

// This class benchmarks performance of random deallocations and (re)allocations
template <
    typename Size, typename Alloc,
    typename =
        std::enable_if_t<std::is_base_of<alloc_size_interface, Size>::value>,
    typename =
        std::enable_if_t<std::is_base_of<allocator_interface, Alloc>::value>>
class multiple_malloc_free_benchmark : public benchmark_interface<Size, Alloc> {
    using distribution = std::uniform_int_distribution<size_t>;
    template <class T> using vector2d = std::vector<std::vector<T>>;
    using base = benchmark_interface<Size, Alloc>;

    int allocsPerIterations = 10;
    bool thread_local_allocations = true;
    size_t max_allocs = 0;

    vector2d<alloc_data> allocations;
    std::vector<unsigned> iters;
    std::vector<size_t> memused;
    vector2d<next_alloc_data> next;
    std::vector<std::vector<next_alloc_data>::const_iterator> next_iter;
    int64_t iterations;

  public:
    void SetUp(::benchmark::State &state) override {
        auto tid = state.thread_index();

        if (tid == 0) {
            // unpack arguments
            iterations = state.max_iterations;
            int argPos = 0;
            max_allocs = state.range(argPos++);
            thread_local_allocations = state.range(argPos++);
            base::parseArgs(state, argPos);

            allocations.resize(state.threads());
            next.resize(state.threads());
            next_iter.resize(state.threads());
            memused.assign(state.threads(), 0);

#ifndef WIN32
            // Ensure that system malloc does not have memory pooled on the heap
            malloc_trim(0);
#endif
        }
        setAffinity(state);
        // sync thread to ensure that thread 0 parsed args and did all initialization
        waitForAllThreads(state);
        // Prepare workload for warp up
        prealloc(state);
        prepareWorkload(state);
        // Start warm up with all threads at once
        waitForAllThreads(state);
        // warm up
        for (int j = 0; j < iterations; j++) {
            bench(state);
        }
        waitForAllThreads(state);
        // prepare workload for actual benchmark.
        freeAllocs(state);

        prealloc(state);
        prepareWorkload(state);
        waitForAllThreads(state);
        base::allocator.preBench(state);
    }

    void TearDown(::benchmark::State &state) override {
        base::allocator.postBench(state);
        auto tid = state.thread_index();
        if (tid == 0) {
            size_t current_memory_allocated = 0;
            for (const auto &used : memused) {
                current_memory_allocated += used;
            }

            auto memory_used = state.counters["provider_memory_allocated"];

            if (memory_used != 0) {
                state.counters["benchmark_memory_allocated"] =
                    static_cast<double>(current_memory_allocated);
                state.counters["memory_overhead"] =
                    100.0 * (memory_used - current_memory_allocated) /
                    memory_used;
            } else {
                state.counters.erase("provider_memory_allocated");
            }
        }

        waitForAllThreads(state);
        freeAllocs(state);
        waitForAllThreads(state);
        if (tid == 0) {
            // release memory used by benchmark
            next.clear();
            next_iter.clear();
            allocations.clear();
            iters.clear();
        }
        base::TearDown(state);
    }

    void bench(benchmark::State &state) {
        auto tid = state.thread_index();
        auto &allocation = allocations[tid];
        auto &memuse = memused[tid];
        for (int i = 0; i < allocsPerIterations; i++) {
            auto &n = *next_iter[tid]++;
            auto &alloc = allocation[n.offset];
            base::allocator.benchFree(alloc.ptr, alloc.size);
            memuse -= alloc.size;
            alloc.size = n.size;
            alloc.ptr = base::allocator.benchAlloc(alloc.size);

            if (alloc.ptr == NULL) {
                state.SkipWithError("allocation failed");
            }
            memuse += alloc.size;
        }
    }

    virtual std::string name() {
        return base::name() + "/multiple_malloc_free";
    }

    virtual std::vector<std::string> argsName() {
        auto n = benchmark_interface<Size, Alloc>::argsName();
        std::vector<std::string> res = {"max_allocs",
                                        "thread_local_allocations"};
        res.insert(res.end(), n.begin(), n.end());
        return res;
    }

  private:
    void prealloc(benchmark::State &state) {
        auto tid = state.thread_index();
        auto &i = allocations[tid];
        i.resize(max_allocs);
        auto &memuse = memused[tid];
        auto sizeGenerator = base::alloc_sizes[tid];

        for (size_t j = 0; j < max_allocs; j++) {
            auto size = sizeGenerator.nextSize();
            i[j].ptr = base::allocator.benchAlloc(size);
            if (i[j].ptr == NULL) {
                state.SkipWithError("preallocation failed");
                return;
            }
            i[j].size = size;
            memuse += size;
        }
    }

    void freeAllocs(benchmark::State &state) {
        auto tid = state.thread_index();
        auto &i = allocations[tid];
        for (auto &j : i) {
            if (j.ptr != NULL) {
                base::allocator.benchFree(j.ptr, j.size);
                memused[tid] -= j.size;
                j.ptr = NULL;
                j.size = 0;
            }
        }
    }

    void prepareWorkload(benchmark::State &state) {
        auto tid = state.thread_index();
        auto &n = next[tid];
        std::default_random_engine generator;
        distribution dist;
        generator.seed(0);
        dist.param(distribution::param_type(0, max_allocs - 1));
        auto sizeGenerator = base::alloc_sizes[tid];

        n.clear();
        for (int64_t j = 0; j < state.max_iterations * allocsPerIterations;
             j++) {
            n.push_back({dist(generator), sizeGenerator.nextSize()});
        }
        next_iter[tid] = n.cbegin();
    }
};
