/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_BENCH_MULTITHREAD_HPP
#define UMF_BENCH_MULTITHREAD_HPP

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <numeric>
#include <stdexcept>
#include <thread>
#include <vector>

#include "multithread_helpers.hpp"

namespace umf_bench {

template <typename TimeUnit, typename F>
typename TimeUnit::rep measure(F &&func) {
    auto start = std::chrono::steady_clock::now();

    func();

    auto duration = std::chrono::duration_cast<TimeUnit>(
        std::chrono::steady_clock::now() - start);
    return duration.count();
}

/* Measure time of execution of run_workload(thread_id) function. */
template <typename TimeUnit, typename F>
auto measure(size_t iterations, size_t concurrency, F &&run_workload) {
    if (iterations == 1) {
        throw std::runtime_error("iterations must be > 1");
    }

    using ResultsType = typename TimeUnit::rep;
    std::vector<ResultsType> results;

    for (size_t i = 0; i < iterations; i++) {
        std::vector<ResultsType> iteration_results(concurrency);
        umf_test::syncthreads_barrier syncthreads(concurrency);
        umf_test::parallel_exec(concurrency, [&](size_t id) {
            syncthreads();

            iteration_results[id] =
                measure<TimeUnit>([&]() { run_workload(id); });
        });

        // skip the first 'warmup' iteration
        if (i != 0) {
            results.insert(results.end(), iteration_results.begin(),
                           iteration_results.end());
        }
    }

    return results;
}

template <typename T> T min(const std::vector<T> &values) {
    return *std::min_element(values.begin(), values.end());
}

template <typename T> T max(const std::vector<T> &values) {
    return *std::max_element(values.begin(), values.end());
}

template <typename T> double mean(const std::vector<T> &values) {
    return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
}

template <typename T> double std_dev(const std::vector<T> &values) {
    auto m = mean(values);
    std::vector<double> diff_squares;
    diff_squares.reserve(values.size());

    for (auto &v : values) {
        diff_squares.push_back((v - m) * (v - m));
    }

    return std::sqrt(mean(diff_squares));
}

} // namespace umf_bench

#endif /* UMF_BENCH_MULTITHREAD_HPP */
