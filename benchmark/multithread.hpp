/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <numeric>
#include <thread>
#include <vector>

namespace umf_bench {

template <typename Function>
void parallel_exec(size_t threads_number, Function &&f) {
    std::vector<std::thread> threads;
    threads.reserve(threads_number);

    for (size_t i = 0; i < threads_number; ++i) {
        threads.emplace_back([&](size_t id) { f(id); }, i);
    }

    for (auto &t : threads) {
        t.join();
    }
}

class latch {
  public:
    latch(size_t desired) : counter(desired) {}

    /* Returns true for the last thread arriving at the latch, false for all
     * other threads. */
    bool wait(std::unique_lock<std::mutex> &lock) {
        counter--;
        if (counter > 0) {
            cv.wait(lock, [&] { return counter == 0; });
            return false;
        } else {
            /*
             * notify_call could be called outside of a lock
             * (it would perform better) but drd complains
             * in that case
             */
            cv.notify_all();
            return true;
        }
    }

  private:
    std::condition_variable cv;
    size_t counter = 0;
};

/* Implements multi-use barrier (latch). Once all threads arrive at the
 * latch, a new latch is allocated and used by all subsequent calls to
 * syncthreads. */
struct syncthreads_barrier {
    syncthreads_barrier(size_t num_threads) : num_threads(num_threads) {
        mutex = std::shared_ptr<std::mutex>(new std::mutex);
        current_latch = std::shared_ptr<latch>(new latch(num_threads));
    }

    syncthreads_barrier(const syncthreads_barrier &) = delete;
    syncthreads_barrier &operator=(const syncthreads_barrier &) = delete;
    syncthreads_barrier(syncthreads_barrier &&) = default;

    void operator()() {
        std::unique_lock<std::mutex> lock(*mutex);
        auto l = current_latch;
        if (l->wait(lock)) {
            current_latch = std::shared_ptr<latch>(new latch(num_threads));
        }
    }

  private:
    size_t num_threads;
    std::shared_ptr<std::mutex> mutex;
    std::shared_ptr<latch> current_latch;
};

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
    using ResultsType = typename TimeUnit::rep;
    std::vector<ResultsType> results;

    for (size_t i = 0; i < iterations; i++) {
        std::vector<ResultsType> iteration_results(concurrency);
        syncthreads_barrier syncthreads(concurrency);
        parallel_exec(concurrency, [&](size_t id) {
            syncthreads();

            iteration_results[id] =
                measure<TimeUnit>([&]() { run_workload(id); });

            syncthreads();
        });
        results.insert(results.end(), iteration_results.begin(),
                       iteration_results.end());
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
    std::vector<T> diff_squares;
    diff_squares.reserve(values.size());

    for (auto &v : values) {
        diff_squares.push_back(std::pow((v - m), 2.0));
    }

    return std::sqrt(mean(diff_squares));
}

} // namespace umf_bench
