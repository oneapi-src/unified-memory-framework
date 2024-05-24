/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "multithread.hpp"

#include <umf/memory_pool.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/pools/pool_jemalloc.h>
#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_os_memory.h>

#include <iostream>
#include <memory>
#include <numeric>

struct bench_params {
    // bench_params() = default;
    size_t n_repeats = 5;
    size_t n_iterations = 50000;
    size_t n_threads = 20;
    size_t alloc_size = 64;
};

using poolCreateExtParams = std::tuple<umf_memory_pool_ops_t *, void *,
                                       umf_memory_provider_ops_t *, void *>;

static auto poolCreateExtUnique(poolCreateExtParams params) {
    umf_memory_pool_handle_t hPool;
    auto [pool_ops, pool_params, provider_ops, provider_params] = params;

    umf_memory_provider_handle_t provider = nullptr;
    auto ret =
        umfMemoryProviderCreate(provider_ops, provider_params, &provider);
    if (ret != UMF_RESULT_SUCCESS) {
        std::cerr << "provider create failed" << std::endl;
        abort();
    }

    ret = umfPoolCreate(pool_ops, provider, pool_params,
                        UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &hPool);
    if (ret != UMF_RESULT_SUCCESS) {
        std::cerr << "pool create failed" << std::endl;
        abort();
    }

    return std::shared_ptr<umf_memory_pool_t>(hPool, &umfPoolDestroy);
}

static void mt_alloc_free(poolCreateExtParams params,
                          const bench_params &bench = bench_params()) {
    auto pool = poolCreateExtUnique(params);

    std::vector<std::vector<void *>> allocs(bench.n_threads);
    std::vector<size_t> numFailures(bench.n_threads);
    for (auto &v : allocs) {
        v.reserve(bench.n_iterations);
    }

    auto values = umf_bench::measure<std::chrono::milliseconds>(
        bench.n_repeats, bench.n_threads,
        [&, pool = pool.get()](auto thread_id) {
            for (size_t i = 0; i < bench.n_iterations; i++) {
                allocs[thread_id].push_back(
                    umfPoolMalloc(pool, bench.alloc_size));
                if (!allocs[thread_id].back()) {
                    numFailures[thread_id]++;
                }
            }

            for (size_t i = 0; i < bench.n_iterations; i++) {
                umfPoolFree(pool, allocs[thread_id][i]);
            }

            // clear the vector as this function might be called multiple times
            allocs[thread_id].clear();
        });

    std::cout << "mean: " << umf_bench::mean(values)
              << " [ms] std_dev: " << umf_bench::std_dev(values) << " [ms]"
              << " (total alloc failures: "
              << std::accumulate(numFailures.begin(), numFailures.end(), 0ULL)
              << " out of "
              << bench.n_iterations * bench.n_repeats * bench.n_threads << ")"
              << std::endl;
}

int main() {
    auto osParams = umfOsMemoryProviderParamsDefault();

#if defined(UMF_POOL_SCALABLE_ENABLED)

    // Increase iterations for scalable pool since it runs much faster than the remaining
    // ones.
    bench_params params;
    params.n_iterations *= 20;

    std::cout << "scalable_pool mt_alloc_free: ";
    mt_alloc_free(poolCreateExtParams{umfScalablePoolOps(), nullptr,
                                      umfOsMemoryProviderOps(), &osParams},
                  params);
#else
    std::cout << "skipping scalable_pool mt_alloc_free" << std::endl;
#endif

#if defined(UMF_BUILD_LIBUMF_POOL_JEMALLOC)
    std::cout << "jemalloc_pool mt_alloc_free: ";
    mt_alloc_free(poolCreateExtParams{umfJemallocPoolOps(), nullptr,
                                      umfOsMemoryProviderOps(), &osParams});
#else
    std::cout << "skipping jemalloc_pool mt_alloc_free" << std::endl;
#endif

#if defined(UMF_BUILD_LIBUMF_POOL_DISJOINT)
    auto disjointParams = umfDisjointPoolParamsDefault();

    std::cout << "disjoint_pool mt_alloc_free: ";
    mt_alloc_free(poolCreateExtParams{umfDisjointPoolOps(), &disjointParams,
                                      umfOsMemoryProviderOps(), &osParams});
#else
    std::cout << "skipping disjoint_pool mt_alloc_free" << std::endl;
#endif

    // ctest looks for "PASSED" in the output
    std::cout << "PASSED" << std::endl;

    return 0;
}
