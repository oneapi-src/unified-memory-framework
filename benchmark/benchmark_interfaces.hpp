/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <string>
#include <thread>
#include <vector>

#include <benchmark/benchmark.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>

class alloc_size_interface {
  public:
    virtual unsigned SetUp([[maybe_unused]] ::benchmark::State &state,
                           [[maybe_unused]] unsigned argPos) = 0;
    virtual void TearDown([[maybe_unused]] ::benchmark::State &state) = 0;
    virtual size_t nextSize() = 0;
    static std::vector<std::string> argsName() { return {""}; };
};

class allocator_interface {
  public:
    virtual unsigned SetUp([[maybe_unused]] ::benchmark::State &state,
                           [[maybe_unused]] unsigned argPos) = 0;
    virtual void TearDown([[maybe_unused]] ::benchmark::State &state) = 0;
    virtual void *benchAlloc(size_t size) = 0;
    virtual void benchFree(void *ptr, [[maybe_unused]] size_t size) = 0;
    static std::vector<std::string> argsName() { return {}; }
};

template <typename Size, typename Allocator>
struct benchmark_interface : public benchmark::Fixture {
    void SetUp(::benchmark::State &state) {
        int argPos = alloc_size.SetUp(state, 0);
        allocator.SetUp(state, argPos);
    }
    void TearDown(::benchmark::State &state) {
        alloc_size.TearDown(state);
        allocator.TearDown(state);
    }

    virtual void bench(::benchmark::State &state) = 0;

    static std::vector<std::string> argsName() {
        auto s = Size::argsName();
        auto a = Allocator::argsName();
        std::vector<std::string> res = {};
        res.insert(res.end(), s.begin(), s.end());
        res.insert(res.end(), a.begin(), a.end());
        return res;
    }
    static std::string name() { return Allocator::name(); }

    Size alloc_size;
    Allocator allocator;
};

struct provider_interface {
    umf_memory_provider_handle_t provider = NULL;
    virtual void SetUp(::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }
        auto umf_result =
            umfMemoryProviderCreate(getOps(), getParams(), &provider);
        if (umf_result != UMF_RESULT_SUCCESS) {
            state.SkipWithError("umfMemoryProviderCreate() failed");
        }
    }

    virtual void TearDown([[maybe_unused]] ::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }

        if (provider) {
            umfMemoryProviderDestroy(provider);
        }
    }

    virtual umf_memory_provider_ops_t *getOps() { return nullptr; }
    virtual void *getParams() { return nullptr; }
};

template <typename T,
          typename =
              std::enable_if_t<std::is_base_of<provider_interface, T>::value>>
struct pool_interface {
    virtual void SetUp(::benchmark::State &state) {
        provider.SetUp(state);
        if (state.thread_index() != 0) {
            return;
        }
        auto umf_result = umfPoolCreate(getOps(state), provider.provider,
                                        getParams(state), 0, &pool);
        if (umf_result != UMF_RESULT_SUCCESS) {
            state.SkipWithError("umfPoolCreate() failed");
        }
    }
    virtual void TearDown([[maybe_unused]] ::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }
        // TODO: The scalable pool destruction process can race with other threads
        // performing TLS (Thread-Local Storage) destruction.
        // As a temporary workaround, we introduce a delay (sleep)
        // to ensure the pool is destroyed only after all threads have completed.
        // Issue: #933
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (pool) {
            umfPoolDestroy(pool);
        }
    };

    virtual umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) {
        return nullptr;
    }
    virtual void *getParams([[maybe_unused]] ::benchmark::State &state) {
        return nullptr;
    }
    T provider;
    umf_memory_pool_handle_t pool;
};
