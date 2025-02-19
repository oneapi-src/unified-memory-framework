/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <benchmark/benchmark.h>

#include "benchmark.hpp"

#define UMF_BENCHMARK_TEMPLATE_DEFINE(BaseClass, Method, ...)                  \
    BENCHMARK_TEMPLATE_DEFINE_F(BaseClass, Method, __VA_ARGS__)                \
    (benchmark::State & state) {                                               \
        for (auto _ : state) {                                                 \
            bench(state);                                                      \
        }                                                                      \
    }

#define UMF_BENCHMARK_REGISTER_F(BaseClass, Method)                            \
    BENCHMARK_REGISTER_F(BaseClass, Method)                                    \
        ->Apply(                                                               \
            &BENCHMARK_PRIVATE_CONCAT_NAME(BaseClass, Method)::defaultArgs)

// Benchmarks scenarios:

// The benchmark arguments specified in Args() are, in order:
// benchmark arguments, allocator arguments, size generator arguments.
// The exact meaning of each argument depends on the benchmark, allocator, and size components used.
// Refer to the 'argsName()' function in each component to find detailed descriptions of these arguments.

static void multithreaded(benchmark::internal::Benchmark *benchmark) {
    benchmark->Threads(4);
    benchmark->Threads(1);
}

static void
default_multiple_alloc_fix_size(benchmark::internal::Benchmark *benchmark) {
    benchmark->Args({10000, 1, 4096});
    benchmark->Iterations(500000);
}

static void
default_multiple_alloc_uniform_size(benchmark::internal::Benchmark *benchmark) {
    benchmark->Args({10000, 1, 8, 4096, 8});
    benchmark->Args({10000, 1, 8, 128, 8});
    benchmark->Iterations(500000);
}

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, glibc_fix,
                              fixed_alloc_size, glibc_malloc);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, glibc_fix)
    ->Apply(&default_multiple_alloc_fix_size)
    ->Apply(&multithreaded);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, glibc_uniform,
                              uniform_alloc_size, glibc_malloc);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, glibc_uniform)
    ->Apply(&default_multiple_alloc_uniform_size)
    ->Apply(&multithreaded);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, proxy_pool,
                              fixed_alloc_size,
                              pool_allocator<proxy_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, proxy_pool)
    ->Apply(&default_multiple_alloc_fix_size)
    // reduce iterations, as this benchmark is slower than others
    ->Iterations(50000);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, os_provider,
                              fixed_alloc_size,
                              provider_allocator<os_provider>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, os_provider)
    ->Apply(&default_multiple_alloc_fix_size)
    // reduce iterations, as this benchmark is slower than others
    ->Iterations(50000);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, disjoint_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, disjoint_pool_fix)
    ->Apply(&default_multiple_alloc_fix_size)
    ->Apply(&multithreaded);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              disjoint_pool_uniform, uniform_alloc_size,
                              pool_allocator<disjoint_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, disjoint_pool_uniform)
    ->Apply(&default_multiple_alloc_uniform_size)
    ->Apply(&multithreaded);

#ifdef UMF_POOL_JEMALLOC_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, jemalloc_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, jemalloc_pool_fix)
    ->Apply(&default_multiple_alloc_fix_size)
    ->Apply(&multithreaded);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              jemalloc_pool_uniform, uniform_alloc_size,
                              pool_allocator<jemalloc_pool<os_provider>>);
UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, jemalloc_pool_uniform)
    ->Apply(&default_multiple_alloc_uniform_size)
    ->Apply(&multithreaded);

#endif

#ifdef UMF_POOL_SCALABLE_ENABLED
UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark, scalable_pool_fix,
                              fixed_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, scalable_pool_fix)
    ->Apply(&default_multiple_alloc_fix_size)
    ->Apply(&multithreaded);

UMF_BENCHMARK_TEMPLATE_DEFINE(multiple_malloc_free_benchmark,
                              scalable_pool_uniform, uniform_alloc_size,
                              pool_allocator<scalable_pool<os_provider>>);

UMF_BENCHMARK_REGISTER_F(multiple_malloc_free_benchmark, scalable_pool_uniform)
    ->Apply(&default_multiple_alloc_uniform_size)
    ->Apply(&multithreaded);

#endif

//BENCHMARK_MAIN();
int main(int argc, char **argv) {
    if (initAffinityMask()) {
        return -1;
    }
    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
}
