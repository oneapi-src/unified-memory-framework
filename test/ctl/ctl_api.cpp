/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <atomic>
#include <exception>
#include <functional> // For std::ref
#include <thread>

#include <umf.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_os_memory.h>

#include "../common/base.hpp"
#include "umf/base.h"
#include "gtest/gtest.h"

using namespace umf_test;

TEST_F(test, ctl_by_handle_os_provider) {
    umf_memory_provider_handle_t hProvider = NULL;
    umf_os_memory_provider_params_handle_t os_memory_provider_params = NULL;
    umf_memory_provider_ops_t *os_provider_ops = umfOsMemoryProviderOps();
    if (os_provider_ops == NULL) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    int ret = umfOsMemoryProviderParamsCreate(&os_memory_provider_params);
    ret = umfMemoryProviderCreate(os_provider_ops, os_memory_provider_params,
                                  &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    int ipc_enabled = 0xBAD;
    ret = umfCtlGet("umf.provider.by_handle.params.ipc_enabled", hProvider,
                    &ipc_enabled, 0); // Some handlers omit size
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(ipc_enabled, 0);

    umfOsMemoryProviderParamsDestroy(os_memory_provider_params);
    umfMemoryProviderDestroy(hProvider);
}

// Create a memory provider and a memory pool
umf_memory_provider_handle_t create_memory_provider() {
    umf_memory_provider_ops_t *provider_ops = umfOsMemoryProviderOps();
    umf_os_memory_provider_params_handle_t params = NULL;
    umf_memory_provider_handle_t provider;

    int ret = umfOsMemoryProviderParamsCreate(&params);
    if (ret != UMF_RESULT_SUCCESS) {
        return 0;
    }

    ret = umfMemoryProviderCreate(provider_ops, params, &provider);
    umfOsMemoryProviderParamsDestroy(params);
    if (ret != UMF_RESULT_SUCCESS) {
        return 0;
    }

    return provider;
}

class CtlTest : public ::testing::Test {
  public:
    class CtlException : public std::exception {
      public:
        CtlException(const char *msg) : msg(msg) {}
        const char *what() const noexcept override { return msg; }

      private:
        const char *msg;
    };

    CtlTest() : provider(NULL), pool(NULL) {}

    void SetUp() override {
        provider = NULL;
        pool = NULL;
    }

    void instantiatePool(umf_memory_pool_ops_t *pool_ops, void *pool_params,
                         umf_pool_create_flags_t flags = 0) {
        freeResources();
        provider = create_memory_provider();
        if (provider == NULL) {
            throw CtlException("Failed to create a memory provider!");
        }
        int ret = umfPoolCreate(pool_ops, provider, pool_params, flags, &pool);
        if (ret != UMF_RESULT_SUCCESS) {
            throw CtlException("Failed to create a memory provider!");
        }
    }

    template <typename T>
    void validateQuery(std::function<umf_result_t(const char *name, void *ctx,
                                                  void *arg, size_t)>
                           ctlApiFunction,
                       const char *name, T expectedValue, umf_result_t expected,
                       bool disableContext = 0) {
        T value = 0xBAD;
        umf_result_t ret = ctlApiFunction(name, disableContext ? nullptr : pool,
                                          &value, sizeof(value)); // Omit size
        ASSERT_EQ(ret, expected);
        if (ret == UMF_RESULT_SUCCESS) {
            ASSERT_EQ(value, expectedValue);
        }
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    template <typename T>
    void executeQuery(std::function<umf_result_t(const char *name, void *ctx,
                                                 void *arg, size_t)>
                          ctlApiFunction,
                      const char *name, T &value, bool disableContext = 0) {
        umf_result_t ret = ctlApiFunction(name, disableContext ? nullptr : pool,
                                          &value, sizeof(value)); // Omit size
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    void TearDown() override { freeResources(); }

  private:
    void freeResources() {
        if (pool) {
            umfPoolDestroy(pool);
        }
        if (provider) {
            umfMemoryProviderDestroy(provider);
        }
    }

    umf_memory_provider_handle_t provider;
    umf_memory_pool_handle_t pool;
};

TEST_F(CtlTest, ctl_by_handle_scalablePool) {
    try {
        instantiatePool(umfScalablePoolOps(), NULL);
        validateQuery<int>(umfCtlGet,
                           "umf.pool.by_handle.params.tracking_enabled", 1,
                           UMF_RESULT_SUCCESS);

        instantiatePool(umfScalablePoolOps(), NULL,
                        UMF_POOL_CREATE_FLAG_DISABLE_TRACKING);
        validateQuery<int>(umfCtlGet,
                           "umf.pool.by_handle.params.tracking_enabled", 0,
                           UMF_RESULT_SUCCESS);
    } catch (CtlTest::CtlException &e) {
        GTEST_SKIP() << e.what();
    } catch (...) {
        GTEST_FAIL() << "Unknown exception!";
    }
}

TEST_F(CtlTest, ctlDefaultNegative) {
    void *ctx = (void *)0xBABE;
    void *arg = (void *)0xBABE;

    auto res = umfCtlGet("umf.pool.default.disjoint.some_path", ctx, arg, 0);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfCtlSet("umf.pool.default.disjoint.some_path", ctx, arg, 0);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(CtlTest, ctlDefault) {
    void *ctx = NULL;
    const char *arg = "default_name";

    auto res = umfCtlSet("umf.pool.default.some_pool.some_path", ctx,
                         (void *)arg, strlen(arg));
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    char output[64] = {0};
    res = umfCtlGet("umf.pool.default.some_pool.some_path", ctx, (void *)output,
                    sizeof(output));
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_STREQ(output, arg);
}

// Multi-threaded test
TEST_F(CtlTest, ctlDefaultMultithreadedPool) {
    std::vector<std::thread> threads;
    std::atomic<size_t> totalRecords = 0;
    const char *predefined_value = "xyzzyx";
    std::string name_prefix = "umf.pool.default.some_pool.";
    for (int i = 0; i < 8; i++) {
        threads.emplace_back(
            [i, &totalRecords, &predefined_value, &name_prefix]() {
                for (int j = 0; j < 10; j++) {
                    std::string name = name_prefix + std::to_string(i * 10 + j);
                    umfCtlSet(name.c_str(), NULL, (void *)predefined_value,
                              strlen(predefined_value));
                    std::atomic_fetch_add(&totalRecords, 1);
                }
            });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    char output[100] = {0};
    for (size_t i = 0; i < totalRecords.load(); i++) {
        std::string name = name_prefix + std::to_string(i);
        auto status =
            umfCtlGet(name.c_str(), nullptr, (void *)output, sizeof(output));
        ASSERT_EQ(status, UMF_RESULT_SUCCESS);
        ASSERT_EQ(std::string(output), std::string(predefined_value));
    }
}

#ifdef NOT_IMPLEMENTED
TEST_F(CtlTest, ctlDefaultMultithreadedProvider) {
    std::vector<std::thread> threads;
    std::atomic<size_t> totalRecords = 0;
    const char *predefined_value = "xyzzyx";
    std::string name_prefix = "umf.provider.default.some_pool.";
    for (int i = 0; i < 8; i++) {
        threads.emplace_back(
            [i, &totalRecords, &predefined_value, &name_prefix]() {
                for (int j = 0; j < 10; j++) {
                    std::string name = name_prefix + std::to_string(i * 10 + j);
                    umfCtlSet(name.c_str(), NULL, (void *)predefined_value,
                              strlen(predefined_value));
                    std::atomic_fetch_add(&totalRecords, 1);
                }
            });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    char output[100] = {0};
    for (size_t i = 0; i < totalRecords.load(); i++) {
        std::string name = name_prefix + std::to_string(i);
        auto status =
            umfCtlGet(name.c_str(), nullptr, (void *)output, sizeof(output));
        ASSERT_EQ(status, UMF_RESULT_SUCCESS);
        ASSERT_EQ(std::string(output), std::string(predefined_value));
    }
}
#endif