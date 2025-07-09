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
#include <umf/experimental/ctl.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/pools/pool_proxy.h>

#ifdef UMF_POOL_SCALABLE_ENABLED
#include <umf/pools/pool_scalable.h>
#endif
#include <umf/providers/provider_fixed_memory.h>
#include <umf/providers/provider_os_memory.h>

#ifdef UMF_POOL_JEMALLOC_ENABLED
#include <umf/pools/pool_jemalloc.h>
#endif

struct provider_interface {
    using params_ptr = std::unique_ptr<void, void (*)(void *)>;

    umf_memory_provider_handle_t provider = NULL;
    void SetUp(::benchmark::State &state) {
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

    void preBench([[maybe_unused]] ::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }
        umfCtlExec("umf.provider.by_handle.{}.stats.peak_memory.reset", NULL, 0,
                   provider);
    }

    void postBench([[maybe_unused]] ::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }
        size_t arg;
        umf_result_t ret =
            umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory", &arg,
                      sizeof(arg), provider);
        if (ret == UMF_RESULT_SUCCESS) {
            state.counters["provider_memory_allocated"] =
                static_cast<double>(arg);
        }
    }

    void TearDown([[maybe_unused]] ::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }

        if (provider) {
            umfMemoryProviderDestroy(provider);
        }
    }

    virtual const umf_memory_provider_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) = 0;

    virtual params_ptr getParams([[maybe_unused]] ::benchmark::State &state) {
        return {nullptr, [](void *) {}};
    }
};

template <typename T,
          typename =
              std::enable_if_t<std::is_base_of<provider_interface, T>::value>>
struct pool_interface {
    using params_ptr = std::unique_ptr<void, void (*)(void *)>;

    void SetUp(::benchmark::State &state) {
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

    void preBench([[maybe_unused]] ::benchmark::State &state) {
        provider.preBench(state);
        if (state.thread_index() != 0) {
            return;
        }
    }

    void postBench([[maybe_unused]] ::benchmark::State &state) {
        provider.postBench(state);
        if (state.thread_index() != 0) {
            return;
        }
    }

    void TearDown([[maybe_unused]] ::benchmark::State &state) {
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

        provider.TearDown(state);
    };

    virtual const umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) = 0;

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
    virtual void preBench([[maybe_unused]] ::benchmark::State &state) = 0;
    virtual void postBench([[maybe_unused]] ::benchmark::State &state) = 0;
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
    void preBench([[maybe_unused]] ::benchmark::State &state) override {}
    void postBench([[maybe_unused]] ::benchmark::State &state) override {}
    void TearDown([[maybe_unused]] ::benchmark::State &state) override {}
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

        return {static_cast<provider_interface::params_ptr::element_type *>(
                    raw_params),
                deleter};
    }

    const umf_memory_provider_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfOsMemoryProviderOps();
    }
    static std::string name() { return "os_provider"; }
};

struct fixed_provider : public provider_interface {
  private:
    char *mem = NULL;
    const size_t size = 1024 * 1024 * 1024; // 1GB
  public:
    void SetUp(::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }

        if (!mem) {
            mem = new char[size];
        }

        provider_interface::SetUp(state);
    }

    void TearDown(::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }

        delete[] mem;
        mem = nullptr;

        provider_interface::TearDown(state);
    }

    provider_interface::params_ptr
    getParams(::benchmark::State &state) override {
        umf_fixed_memory_provider_params_handle_t raw_params = nullptr;
        umfFixedMemoryProviderParamsCreate(mem, size, &raw_params);
        if (!raw_params) {
            state.SkipWithError("Failed to create fixed provider params");
            return {nullptr, [](void *) {}};
        }

        // Use a lambda as the custom deleter
        auto deleter = [](void *p) {
            auto handle =
                static_cast<umf_fixed_memory_provider_params_handle_t>(p);
            umfFixedMemoryProviderParamsDestroy(handle);
        };

        return {static_cast<provider_interface::params_ptr::element_type *>(
                    raw_params),
                deleter};
    }

    const umf_memory_provider_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfFixedMemoryProviderOps();
    }
    static std::string name() { return "fixed_provider"; }
};

template <typename Provider>
struct proxy_pool : public pool_interface<Provider> {
    const umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfProxyPoolOps();
    }

    static std::string name() { return "proxy_pool<" + Provider::name() + ">"; }
};

template <typename Provider>
struct disjoint_pool : public pool_interface<Provider> {
    const umf_memory_pool_ops_t *
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

        ret = umfDisjointPoolParamsSetMinBucketSize(raw_params, 8);
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

// benchmark tracking provider, by creating big number pools(2^7) stacked
template <typename Provider>
struct disjoint_pool_stack : public disjoint_pool<Provider> {
    using base = disjoint_pool<Provider>;

    std::vector<umf_memory_provider_handle_t> providers;
    std::vector<umf_memory_pool_handle_t> pools;
    std::vector<void *> pool_ptrs;

    static constexpr size_t firstPoolSize = 2ull * 1024 * 1024 * 1024; // 2GB
    static constexpr size_t levels = 7;

    void SetUp(::benchmark::State &state) {
        base::provider.SetUp(state);
        if (state.thread_index() != 0) {
            return;
        }

        providers.push_back(base::provider.provider);
        base::provider.provider = nullptr;

        auto params = base::getParams(state);
        umf_memory_pool_handle_t rootPool = nullptr;
        auto umf_result = umfPoolCreate(base::getOps(state), providers[0],
                                        params.get(), 0, &rootPool);
        if (umf_result != UMF_RESULT_SUCCESS) {
            state.SkipWithError("umfPoolCreate() failed");
            return;
        }

        pools.push_back(rootPool); // root pool

        umf_fixed_memory_provider_params_handle_t params_fixed = nullptr;
        umf_result = umfFixedMemoryProviderParamsCreate((void *)0x1, 0x1,
                                                        &params_fixed); // dummy

        size_t poolSize = firstPoolSize;
        size_t level_start = 0;
        size_t level_pools = 1;

        for (size_t level = 1; level < levels; ++level) {
            // split each pools for 3 parts - two for children, and third from other allocations from this pool
            poolSize /= 3;
            size_t new_level_pools = level_pools * 2;

            for (size_t parent_idx = 0; parent_idx < level_pools;
                 ++parent_idx) {
                umf_memory_pool_handle_t parent_pool =
                    pools[level_start + parent_idx];

                for (int child = 0; child < 2; ++child) {
                    void *ptr = umfPoolMalloc(parent_pool, poolSize);
                    if (!ptr) {
                        state.SkipWithError("umfPoolMalloc() failed");
                        return;
                    }
                    pool_ptrs.push_back(ptr);

                    umf_result = umfFixedMemoryProviderParamsSetMemory(
                        params_fixed, ptr, poolSize);
                    umf_memory_provider_handle_t prov;
                    umf_result = umfMemoryProviderCreate(
                        umfFixedMemoryProviderOps(), params_fixed, &prov);
                    if (umf_result != UMF_RESULT_SUCCESS) {
                        state.SkipWithError("umfMemoryProviderCreate() failed");
                        return;
                    }
                    providers.push_back(prov);

                    umf_memory_pool_handle_t newPool;
                    umf_result = umfPoolCreate(base::getOps(state), prov,
                                               params.get(), 0, &newPool);
                    if (umf_result != UMF_RESULT_SUCCESS) {
                        state.SkipWithError("umfPoolCreate() failed");
                        return;
                    }

                    pools.push_back(newPool);
                }
            }

            level_start += level_pools;
            level_pools = new_level_pools;
        }

        umfFixedMemoryProviderParamsDestroy(params_fixed);
    }

    void TearDown(::benchmark::State &state) {
        if (state.thread_index() != 0) {
            return;
        }

        size_t pool_index = pools.size();
        size_t provider_index = providers.size();
        size_t ptr_index = pool_ptrs.size();

        // Go from last level to first (excluding level 0, root)
        for (int level = levels - 1; level > 0; --level) {
            size_t level_pools = 1ull << level; // 2^level pools

            // Destroy pools
            for (size_t i = 0; i < level_pools; ++i) {
                --pool_index;
                umfPoolDestroy(pools[pool_index]);
            }

            // Destroy providers and free pointers
            for (size_t i = 0; i < level_pools; ++i) {
                --provider_index;
                umfMemoryProviderDestroy(providers[provider_index]);

                --ptr_index;
                void *ptr = pool_ptrs[ptr_index];
                if (ptr) {
                    umfFree(ptr);
                }
            }
        }

        // Root pool and provider
        umfPoolDestroy(pools[0]);
        umfMemoryProviderDestroy(providers[0]);

        pools.clear();
        providers.clear();
        pool_ptrs.clear();

        base::TearDown(state);
    }

    static std::string name() {
        return "disjoint_pool_stacked<" + Provider::name() + ">";
    }
};

#ifdef UMF_POOL_JEMALLOC_ENABLED
template <typename Provider>
struct jemalloc_pool : public pool_interface<Provider> {
    const umf_memory_pool_ops_t *
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
    const umf_memory_pool_ops_t *
    getOps([[maybe_unused]] ::benchmark::State &state) override {
        return umfScalablePoolOps();
    }

    static std::string name() {
        return "scalable_pool<" + Provider::name() + ">";
    }
};
#endif
