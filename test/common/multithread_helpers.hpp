/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_TEST_MULTITHREAD_HELPERS_HPP
#define UMF_TEST_MULTITHREAD_HELPERS_HPP

#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace umf_test {

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

} // namespace umf_test

#endif /* UMF_TEST_MULTITHREAD_HELPERS_HPP */
