/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <benchmark/benchmark.h>
#include <umf/pools/pool_proxy.h>
#ifdef UMF_POOL_SCALABLE_ENABLED
#include <umf/pools/pool_scalable.h>
#endif
#include <umf/providers/provider_os_memory.h>

#ifdef UMF_POOL_DISJOINT_ENABLED
#include <umf/pools/pool_disjoint.h>
#endif

#ifdef UMF_POOL_JEMALLOC_ENABLED
#include <umf/pools/pool_jemalloc.h>
#endif

#include "benchmark.hpp"

struct glibc_malloc : public allocator_interface {
    unsigned SetUp([[maybe_unused]] ::benchmark::State &state,
                   unsigned argPos) override {
        return argPos;
    }
    void TearDown([[maybe_unused]] ::benchmark::State &state) override{};
    void *benchAlloc(size_t size) override { return malloc(size); }
    void benchFree(void *ptr, [[maybe_unused]] size_t size) override {
        free(ptr);
    }
    static std::string name() { return "glibc"; }
};

struct os_provider : public provider_interface {
    umf_os_memory_provider_params_handle_t params = NULL;
    os_provider() {
        umfOsMemoryProviderParamsCreate(&params);
        return;
    }

    ~os_provider() {
        if (params != NULL) {
            umfOsMemoryProviderParamsDestroy(params);
        }
    }

    void *getParams() override { return params; }
    umf_memory_provider_ops_t *getOps() override {
        return umfOsMemoryProviderOps();
    }
    static std::string name() { return "os_provider"; }
};

template <typename Provider>
struct proxy_pool : public pool_interface<Provider> {
    umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfProxyPoolOps();
    }
    void *getParams([[maybe_unused]] ::benchmark::State &state) override {
        return nullptr;
    }
    static std::string name() { return "proxy_pool<" + Provider::name() + ">"; }
};

#ifdef UMF_POOL_DISJOINT_ENABLED
template <typename Provider>
struct disjoint_pool : public pool_interface<Provider> {
    umf_disjoint_pool_params_handle_t disjoint_memory_pool_params;

    disjoint_pool() {
        disjoint_memory_pool_params = NULL;
        auto ret = umfDisjointPoolParamsCreate(&disjoint_memory_pool_params);
        if (ret != UMF_RESULT_SUCCESS) {
            return;
        }

        // those function should never fail, so error handling is minimal.
        ret = umfDisjointPoolParamsSetSlabMinSize(disjoint_memory_pool_params,
                                                  4096);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err;
        }

        ret = umfDisjointPoolParamsSetCapacity(disjoint_memory_pool_params, 4);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err;
        }

        ret = umfDisjointPoolParamsSetMinBucketSize(disjoint_memory_pool_params,
                                                    4096);
        if (ret != UMF_RESULT_SUCCESS) {
            goto err;
        }

        ret = umfDisjointPoolParamsSetMaxPoolableSize(
            disjoint_memory_pool_params, 4096 * 16);

        if (ret != UMF_RESULT_SUCCESS) {
            goto err;
        }
        return;
    err:

        umfDisjointPoolParamsDestroy(disjoint_memory_pool_params);
        disjoint_memory_pool_params = NULL;
    }

    ~disjoint_pool() {
        if (disjoint_memory_pool_params != NULL) {
            umfDisjointPoolParamsDestroy(disjoint_memory_pool_params);
        }
    }

    umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfDisjointPoolOps();
    }
    void *getParams([[maybe_unused]] ::benchmark::State &state) override {

        if (disjoint_memory_pool_params == NULL) {
            state.SkipWithError("Failed to create disjoint pool params");
        }

        return disjoint_memory_pool_params;
    }
    static std::string name() {
        return "disjoint_pool<" + Provider::name() + ">";
    }
};
#endif

#ifdef UMF_POOL_JEMALLOC_ENABLED
template <typename Provider>
struct jemalloc_pool : public pool_interface<Provider> {
    umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfJemallocPoolOps();
    }
    void *getParams([[maybe_unused]] ::benchmark::State &state) override {
        return NULL;
    }
    static std::string name() {
        return "jemalloc_pool<" + Provider::name() + ">";
    }
};
#endif

#ifdef UMF_POOL_SCALABLE_ENABLED
template <typename Provider>
struct scalable_pool : public pool_interface<Provider> {
    virtual umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfScalablePoolOps();
    }
    virtual void *
    getParams([[maybe_unused]] ::benchmark::State &state) override {
        return NULL;
    }
    static std::string name() {
        return "scalable_pool<" + Provider::name() + ">";
    }
};
#endif
// Benchmarks scenarios:

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, glibc_fix, fixed_alloc_size,
                              glibc_malloc);

// The benchmark arguments specified in Args() are, in order:
// benchmark arguments, allocator arguments, size generator arguments.
// The exact meaning of each argument depends on the benchmark, allocator, and size components used.
// Refer to the 'argsName()' function in each component to find detailed descriptions of these arguments.
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, glibc_fix)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, glibc_uniform,
                              uniform_alloc_size, glibc_malloc);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, glibc_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, os_provider, fixed_alloc_size,
                              provider_allocator<os_provider>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, os_provider)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, proxy_pool, fixed_alloc_size,
                              pool_allocator<proxy_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(alloc_benchmark, proxy_pool)
    ->Args({1000, 0, 4096})
    ->Args({1000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

#ifdef UMF_POOL_DISJOINT_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, disjoint_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, disjoint_pool_fix)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

// TODO: debug why this crashes
/*UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, disjoint_pool_uniform,
                              uniform_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, disjoint_pool_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    //    ->Threads(4)
    ->Threads(1);
*/
#endif

#ifdef UMF_POOL_JEMALLOC_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, jemalloc_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, jemalloc_pool_fix)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, jemalloc_pool_uniform,
                              uniform_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(alloc_benchmark, jemalloc_pool_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, scalable_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(alloc_benchmark, scalable_pool_fix)
    ->Args({10000, 0, 4096})
    ->Args({10000, 100000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(alloc_benchmark, scalable_pool_uniform,
                              uniform_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(alloc_benchmark, scalable_pool_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);
#endif
// Multiple allocs/free

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, glibc_fix,
                              fixed_alloc_size, glibc_malloc);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, glibc_fix)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, glibc_uniform,
                              uniform_alloc_size, glibc_malloc);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, glibc_uniform)
    ->Args({10000, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, proxy_pool,
                              fixed_alloc_size,
                              pool_allocator<proxy_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, proxy_pool)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, os_provider,
                              fixed_alloc_size,
                              provider_allocator<os_provider>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, os_provider)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

#ifdef UMF_POOL_DISJOINT_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, disjoint_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, disjoint_pool_fix)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

// TODO: debug why this crashes
/*UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              disjoint_pool_uniform, uniform_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, disjoint_pool_uniform)
    ->Args({10000, 0, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);
*/
#endif

#ifdef UMF_POOL_JEMALLOC_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, jemalloc_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, jemalloc_pool_fix)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              jemalloc_pool_uniform, uniform_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, jemalloc_pool_uniform)
    ->Args({1000, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

#endif

#ifdef UMF_POOL_SCALABLE_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, scalable_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, scalable_pool_fix)
    ->Args({10000, 4096})
    ->Threads(4)
    ->Threads(1);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              scalable_pool_uniform, uniform_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, scalable_pool_uniform)
    ->Args({10000, 8, 64 * 1024, 8})
    ->Threads(4)
    ->Threads(1);

#endif
BENCHMARK_MAIN();
