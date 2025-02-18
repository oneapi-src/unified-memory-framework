/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */
#include <memory>
#include <thread>

#include <benchmark/benchmark.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>

#include <benchmark/benchmark.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/pools/pool_proxy.h>

#ifdef UMF_POOL_SCALABLE_ENABLED
#include <umf/pools/pool_scalable.h>
#endif
#include <umf/providers/provider_os_memory.h>

#ifdef UMF_POOL_JEMALLOC_ENABLED
#include <umf/pools/pool_jemalloc.h>
#endif

struct provider_interface {
    using params_ptr = std::unique_ptr<void, void (*)(void *)>;

    umf_memory_provider_handle_t provider = NULL;
    virtual void SetUp(::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }
        auto params = getParams(state);
        auto umf_result =
            umfMemoryProviderCreate(getOps(state), params.get(), &provider);
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

    virtual umf_memory_provider_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) {
        return nullptr;
    }

    virtual params_ptr getParams([[maybe_unused]] ::benchmark::State &state) {
        return {nullptr, [](void *) {}};
    }
};

template <typename T,
          typename =
              std::enable_if_t<std::is_base_of<provider_interface, T>::value>>
struct pool_interface {
    using params_ptr = std::unique_ptr<void, void (*)(void *)>;

    virtual void SetUp(::benchmark::State &state) {
        provider.SetUp(state);
        if (state.thread_index() != 0) {
            return;
        }
        auto params = getParams(state);
        auto umf_result = umfPoolCreate(getOps(state), provider.provider,
                                        params.get(), 0, &pool);
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
    virtual params_ptr getParams([[maybe_unused]] ::benchmark::State &state) {
        return {nullptr, [](void *) {}};
    }
    T provider;
    umf_memory_pool_handle_t pool;
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
    provider_interface::params_ptr
    getParams(::benchmark::State &state) override {
        umf_os_memory_provider_params_handle_t raw_params = nullptr;
        umfOsMemoryProviderParamsCreate(&raw_params);
        if (!raw_params) {
            state.SkipWithError("Failed to create os provider params");
            return {nullptr, [](void *) {}};
        }

        // Use a lambda as the custom deleter
        auto deleter = [](void *p) {
            auto handle =
                static_cast<umf_os_memory_provider_params_handle_t>(p);
            umfOsMemoryProviderParamsDestroy(handle);
        };

        return {static_cast<void *>(raw_params), deleter};
    }

    umf_memory_provider_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
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

    static std::string name() { return "proxy_pool<" + Provider::name() + ">"; }
};

template <typename Provider>
struct disjoint_pool : public pool_interface<Provider> {
    umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfDisjointPoolOps();
    }

    typename pool_interface<Provider>::params_ptr
    getParams(::benchmark::State &state) override {
        umf_disjoint_pool_params_handle_t raw_params = nullptr;
        auto ret = umfDisjointPoolParamsCreate(&raw_params);
        if (ret != UMF_RESULT_SUCCESS) {
            state.SkipWithError("Failed to create disjoint pool params");
            return {nullptr, [](void *) {}};
        }

        typename pool_interface<Provider>::params_ptr params(
            raw_params, [](void *p) {
                umfDisjointPoolParamsDestroy(
                    static_cast<umf_disjoint_pool_params_handle_t>(p));
            });

        ret = umfDisjointPoolParamsSetSlabMinSize(raw_params, 4096);
        if (ret != UMF_RESULT_SUCCESS) {
            state.SkipWithError("Failed to set slab min size");
            return {nullptr, [](void *) {}};
        }

        ret = umfDisjointPoolParamsSetCapacity(raw_params, 4);
        if (ret != UMF_RESULT_SUCCESS) {
            state.SkipWithError("Failed to set capacity");
            return {nullptr, [](void *) {}};
        }

        ret = umfDisjointPoolParamsSetMinBucketSize(raw_params, 4096);
        if (ret != UMF_RESULT_SUCCESS) {
            state.SkipWithError("Failed to set min bucket size");
            return {nullptr, [](void *) {}};
        }

        ret = umfDisjointPoolParamsSetMaxPoolableSize(raw_params, 4096 * 16);
        if (ret != UMF_RESULT_SUCCESS) {
            state.SkipWithError("Failed to set max poolable size");
            return {nullptr, [](void *) {}};
        }

        return params;
    }

    static std::string name() {
        return "disjoint_pool<" + Provider::name() + ">";
    }
};

#ifdef UMF_POOL_JEMALLOC_ENABLED
template <typename Provider>
struct jemalloc_pool : public pool_interface<Provider> {
    umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfJemallocPoolOps();
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

    static std::string name() {
        return "scalable_pool<" + Provider::name() + ">";
    }
};
#endif
