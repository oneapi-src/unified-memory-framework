/*
 *
 * Copyright (C) 2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <atomic>
#include <cstring>
#include <exception>
#include <functional> // For std::ref
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <umf.h>
#include <umf/base.h>
#include <umf/experimental/ctl.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/pools/pool_scalable.h>
#include <umf/providers/provider_fixed_memory.h>
#include <umf/providers/provider_os_memory.h>

#include "../common/base.hpp"
#include "gtest/gtest.h"

using namespace umf_test;

TEST_F(test, ctl_by_handle_os_provider) {
    umf_memory_provider_handle_t hProvider = NULL;
    umf_os_memory_provider_params_handle_t os_memory_provider_params = NULL;
    const umf_memory_provider_ops_t *os_provider_ops = umfOsMemoryProviderOps();
    if (os_provider_ops == NULL) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    int ret = umfOsMemoryProviderParamsCreate(&os_memory_provider_params);
    ret = umfMemoryProviderCreate(os_provider_ops, os_memory_provider_params,
                                  &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    int ipc_enabled = 0xBAD;
    ret = umfCtlGet("umf.provider.by_handle.{}.params.ipc_enabled",
                    &ipc_enabled, sizeof(ipc_enabled), hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(ipc_enabled, 0);

    umfOsMemoryProviderParamsDestroy(os_memory_provider_params);
    umfMemoryProviderDestroy(hProvider);
}

class Pool {
  public:
    Pool() : provider(NULL), pool(NULL) {}

    int instantiatePool(const umf_memory_pool_ops_t *pool_ops,
                        const void *pool_params,
                        umf_pool_create_flags_t flags = 0) {
        freeResources();
        provider = create_memory_provider();
        if (provider == NULL) {
            return -1; // Provider not supported
        }
        int ret = umfPoolCreate(pool_ops, provider, pool_params, flags, &pool);
        if (ret != UMF_RESULT_SUCCESS) {
            umfMemoryProviderDestroy(provider);
            provider = NULL;
            return -2; // Failed to create memory pool
        }
        return 0; // Success
    }

    // Template specialization for different types of reference value
    template <typename T> T getReferenceValue() {
        if constexpr (std::is_arithmetic_v<T>) {
            return 0xBAD;
        } else if constexpr (std::is_same_v<T, std::string>) {
            return "0xBAD";
        }
    }

    template <typename T>
    void validateQuery(umf_result_t (*ctlApiFunction)(const char *name,
                                                      void *arg, size_t, ...),
                       const char *name, T expectedValue,
                       umf_result_t expected) {
        T value = getReferenceValue<T>();
        umf_result_t ret;
        char ret_buf[256] = {0};
        if constexpr (std::is_same_v<T, std::string>) {
            strncpy(ret_buf, value.c_str(), sizeof(ret_buf) - 1);
            ret_buf[sizeof(ret_buf) - 1] = '\0'; // Ensure null-termination
            ret = ctlApiFunction(name, (void *)ret_buf, sizeof(ret_buf), pool);
        } else if constexpr (std::is_arithmetic_v<T>) {
            std::string value_str = std::to_string(value);
            strncpy(ret_buf, value_str.c_str(), sizeof(ret_buf) - 1);
            ret_buf[sizeof(ret_buf) - 1] = '\0'; // Ensure null-termination
            ret = ctlApiFunction(name, (void *)ret_buf, sizeof(ret_buf), pool);
        } else {
            ret = ctlApiFunction(name, &value, sizeof(value), pool);
        }

        ASSERT_EQ(ret, expected);
        if (ret == UMF_RESULT_SUCCESS) {
            ASSERT_EQ(ret_buf, expectedValue);
        }
    }

    template <typename T>
    void executeQuery(umf_result_t (*ctlApiFunction)(const char *name,
                                                     void *arg, size_t, ...),
                      const char *name, T value) {
        size_t value_len;
        if constexpr (std::is_arithmetic_v<T>) {
            value_len = sizeof(value);
        } else if constexpr (std::is_same_v<T, std::string>) {
            value_len = strlen(value.c_str());
        } else if constexpr (std::is_same_v<T, const char *>) {
            value_len = strlen(value);
        } else {
            throw std::runtime_error("Unsupported type for value");
        }
        umf_result_t ret = ctlApiFunction(name, (void *)value, value_len);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    void freeResources() {
        if (pool) {
            umfPoolDestroy(pool);
            pool = NULL;
        }
        if (provider) {
            umfMemoryProviderDestroy(provider);
            provider = NULL;
        }
        if (data) {
            free(data);
            data = nullptr;
        }
    }

    umf_memory_provider_handle_t provider;
    umf_memory_pool_handle_t pool;
    void *data = nullptr;

  private:
    // Create a memory provider
    umf_memory_provider_handle_t create_memory_provider() {
        const umf_memory_provider_ops_t *provider_ops =
            umfFixedMemoryProviderOps();
        umf_fixed_memory_provider_params_handle_t params = NULL;

        data = malloc(1024 * 1024);
        int ret =
            umfFixedMemoryProviderParamsCreate(data, 1024 * 1024, &params);
        if (ret != UMF_RESULT_SUCCESS) {
            return 0;
        }

        ret = umfMemoryProviderCreate(provider_ops, params, &provider);
        umfFixedMemoryProviderParamsDestroy(params);
        if (ret != UMF_RESULT_SUCCESS) {
            return 0;
        }

        return provider;
    }
};

class CtlTest : public ::testing::Test {
  public:
    CtlTest() {}

    void SetUp() override {}

    void TearDown() override {}

  private:
};

/* Case: default settings
 * This test sets a default value and then retrieves it */
TEST_F(CtlTest, ctlDefault) {
    const char *arg = "default_name";

    auto res = umfCtlSet("umf.pool.default.some_pool.some_path", (void *)arg,
                         strlen(arg));
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    char output[64] = {1};
    res = umfCtlGet("umf.pool.default.some_pool.some_path", (void *)output,
                    sizeof(output));
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    ASSERT_STREQ(output, arg);
}

/* Case: umfCtlSet negative test */
TEST_F(CtlTest, ctlSetInvalid) {
    const char *valid_arg = "default_name";
    const char *valid_path = "umf.pool.default.some_pool.some_path";
    // umfCtlSet - invalid path
    auto res = umfCtlSet(NULL, (void *)valid_arg, strlen(valid_arg));
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // umfCtlSet - invalid size
    res = umfCtlSet(valid_path, (void *)valid_arg, 0);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // umfCtlSet - invalid arg
    res = umfCtlSet(valid_path, NULL, strlen(valid_arg));
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

/* Case: umfCtlGet negative test */
TEST_F(CtlTest, ctlGetInvalid) {
    const char *valid_arg = "default_name";
    const char *valid_path = "umf.pool.default.some_pool.some_path";

    // umfCtlGet - invalid path
    auto res = umfCtlGet(NULL, (void *)valid_arg, strlen(valid_arg));
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // umfCtlGet - invalid arg
    res = umfCtlGet(valid_path, NULL, strlen(valid_arg));
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

/* Case: multi-threaded test for pool defaults
 * This test sets a default value in multiple threads and then retrieves it */
TEST_F(CtlTest, ctlDefaultPoolMultithreaded) {
    const size_t max_size = 10;
    const size_t num_threads = 8;
    std::vector<std::thread> threads;
    std::atomic<size_t> totalRecords = 0;
    const char *predefined_value = "xyzzyx";
    std::string name_prefix = "umf.pool.default.some_pool.";
    for (size_t i = 0; i < num_threads; i++) {
        threads.emplace_back([i, &totalRecords, &predefined_value, &name_prefix,
                              max_size = max_size]() {
            for (size_t j = 0; j < max_size; j++) {
                std::string name = name_prefix + std::to_string(i * 10 + j);
                umfCtlSet(name.c_str(), (void *)predefined_value,
                          strlen(predefined_value));
                std::atomic_fetch_add(&totalRecords, 1UL);
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }

    // Check if all threads set the value correctly
    // and retrieve it
    ASSERT_EQ(totalRecords.load(), num_threads * max_size);

    char output[100] = {0};
    for (size_t i = 0; i < totalRecords.load(); i++) {
        std::string name = name_prefix + std::to_string(i);
        auto status = umfCtlGet(name.c_str(), (void *)output, sizeof(output));
        ASSERT_EQ(status, UMF_RESULT_SUCCESS);
        ASSERT_EQ(std::string(output), std::string(predefined_value));
    }
}

/* Case: overwriting an existing value for pool defaults
 * This test sets a default value and then overwrites it with a new value */
TEST_F(CtlTest, ctlDefaultPoolOverwrite) {
    constexpr int max_size = 10;
    std::vector<std::string> values;
    const std::string name = "umf.pool.default.some_pool";

    for (int i = 0; i < max_size; i++) {
        values.push_back("value_" + std::to_string(i));
        umfCtlSet(name.c_str(), (void *)values.back().c_str(),
                  values.back().size());
    }

    char output[100] = {0};
    umf_result_t status =
        umfCtlGet(name.c_str(), (void *)output, sizeof(output));
    ASSERT_EQ(status, UMF_RESULT_SUCCESS);
    ASSERT_EQ(std::string(output), values.back());
}

TEST_F(CtlTest, DISABLED_ctlNameValidation) {
    std::string name = "umf.pool.default.disjoint.name";
    std::string value = "new_disjoint_pool_name";
    umf_disjoint_pool_params_handle_t params = NULL;

    Pool p;
    try {
        p.executeQuery(umfCtlSet, name.c_str(), value.c_str());
        umf_result_t res = umfDisjointPoolParamsCreate(&params);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);

        auto ret = p.instantiatePool(umfDisjointPoolOps(), params);
        ASSERT_EQ(ret, 0);

        p.validateQuery(umfCtlGet, "umf.pool.by_handle.{}.disjoint.name",
                        std::move(value), UMF_RESULT_SUCCESS);
    } catch (...) {
        GTEST_FAIL() << "Unknown exception!";
    }
    umfDisjointPoolParamsDestroy(params);
    p.freeResources();
}

TEST_F(CtlTest, DISABLED_ctlSizeValidation) {
    std::string name = "umf.pool.default.disjoint.name";
    std::string value = "1234567890";
    umf_disjoint_pool_params_handle_t params = NULL;

    Pool p;
    try {
        p.executeQuery(umfCtlSet, name.c_str(), value.c_str());
        umf_result_t res = umfDisjointPoolParamsCreate(&params);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);

        auto ret = p.instantiatePool(umfDisjointPoolOps(), params);
        ASSERT_EQ(ret, 0);

        char output[100] = {0};
        umfCtlGet("umf.pool.default.disjoint.name", output, sizeof(output));
        ASSERT_EQ(std::string(output), value);

        memset(output, 0, sizeof(output));
        umfCtlGet("umf.pool.default.disjoint.name", output, value.size() / 2);
        auto half_value = value.substr(0, value.size() / 2);
        ASSERT_EQ(half_value, std::string(output));
    } catch (...) {
        GTEST_FAIL() << "Unknown exception!";
    }
    umfDisjointPoolParamsDestroy(params);
    p.freeResources();
}

TEST_F(CtlTest, DISABLED_ctlExecInvalidSize) {
    std::string name = "umf.pool.default.disjoint.name";
    ASSERT_EQ(umfCtlSet(name.c_str(), (void *)"test_value", 0),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
    ASSERT_EQ(umfCtlSet(name.c_str(), NULL, 10),
              UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

#ifdef PROVIDER_DEFAULTS_NOT_IMPLEMENTED_YET
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
                    umfCtlSet(name.c_str(), (void *)predefined_value,
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
        auto status = umfCtlGet(name.c_str(), (void *)output, sizeof(output));
        ASSERT_EQ(status, UMF_RESULT_SUCCESS);
        ASSERT_EQ(std::string(output), std::string(predefined_value));
    }
}
#endif

TEST_F(test, ctl_logger_basic_rw) {
    bool ts_set = true;
    ASSERT_EQ(umfCtlSet("umf.logger.timestamp", &ts_set, sizeof(ts_set)),
              UMF_RESULT_SUCCESS);
    bool ts_get = false;
    ASSERT_EQ(umfCtlGet("umf.logger.timestamp", &ts_get, sizeof(ts_get)),
              UMF_RESULT_SUCCESS);
    EXPECT_TRUE(ts_get);

    bool pid_set = 1;
    ASSERT_EQ(umfCtlSet("umf.logger.pid", &pid_set, sizeof(pid_set)),
              UMF_RESULT_SUCCESS);
    bool pid_get = 0;
    ASSERT_EQ(umfCtlGet("umf.logger.pid", &pid_get, sizeof(pid_get)),
              UMF_RESULT_SUCCESS);
    EXPECT_EQ(pid_get, 1);

    int level_set = 1;
    ASSERT_EQ(umfCtlSet("umf.logger.level", &level_set, sizeof(level_set)),
              UMF_RESULT_SUCCESS);
    int level_get = 0;
    ASSERT_EQ(umfCtlGet("umf.logger.level", &level_get, sizeof(level_get)),
              UMF_RESULT_SUCCESS);
    EXPECT_EQ(level_get, 1);

    int flush_set = 2;
    ASSERT_EQ(
        umfCtlSet("umf.logger.flush_level", &flush_set, sizeof(flush_set)),
        UMF_RESULT_SUCCESS);
    int flush_get = 0;
    ASSERT_EQ(
        umfCtlGet("umf.logger.flush_level", &flush_get, sizeof(flush_get)),
        UMF_RESULT_SUCCESS);
    EXPECT_EQ(flush_get, 2);

    const char *out_name = "stdout";
    ASSERT_EQ(umfCtlSet("umf.logger.output", &out_name, sizeof(out_name)),
              UMF_RESULT_SUCCESS);
    const char *out_get = NULL;
    ASSERT_EQ(umfCtlGet("umf.logger.output", &out_get, sizeof(out_get)),
              UMF_RESULT_SUCCESS);
    EXPECT_STREQ(out_get, "stdout");
}

TEST_F(test, ctl_logger_output_file) {
    const char *file_name = "ctl_log.txt";
    ASSERT_EQ(umfCtlSet("umf.logger.output", &file_name, sizeof(file_name)),
              UMF_RESULT_SUCCESS);
    const char *out_get = NULL;
    ASSERT_EQ(umfCtlGet("umf.logger.output", &out_get, sizeof(out_get)),
              UMF_RESULT_SUCCESS);
    EXPECT_STREQ(out_get, file_name);
}

TEST_F(test, ctl_by_name) {
    umf_memory_provider_handle_t hProvider = NULL;
    umf_os_memory_provider_params_handle_t os_memory_provider_params = NULL;
    const umf_memory_provider_ops_t *os_provider_ops = umfOsMemoryProviderOps();
    if (os_provider_ops == NULL) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    int ret = umfOsMemoryProviderParamsCreate(&os_memory_provider_params);
    ret = umfMemoryProviderCreate(os_provider_ops, os_memory_provider_params,
                                  &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    umfOsMemoryProviderParamsDestroy(os_memory_provider_params);

    umf_disjoint_pool_params_handle_t disjoint_pool_params = NULL;
    ret = umfDisjointPoolParamsCreate(&disjoint_pool_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    const char *pool_name = "test_disjoint_pool";
    ret = umfDisjointPoolParamsSetName(disjoint_pool_params, pool_name);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t hPool = NULL;
    ret = umfPoolCreate(umfDisjointPoolOps(), hProvider, disjoint_pool_params,
                        0, &hPool);

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    const char *pool_name2 = "test_disjoint_pool2";
    ret = umfDisjointPoolParamsSetName(disjoint_pool_params, pool_name2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t hPool2 = NULL;
    ret = umfPoolCreate(umfDisjointPoolOps(), hProvider, disjoint_pool_params,
                        0, &hPool2);
    umfDisjointPoolParamsDestroy(disjoint_pool_params);

    size_t pool_count;

    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool.count", &pool_count,
                    sizeof(pool_count));

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(pool_count, 1ull);

    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool2.count", &pool_count,
                    sizeof(pool_count));

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(pool_count, 1ull);

    size_t alloc_count;
    ret = umfCtlGet("umf.pool.by_name.{}.stats.alloc_count", &alloc_count,
                    sizeof(alloc_count), pool_name);

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 0ull);

    ret = umfCtlGet("umf.pool.by_name.{}.stats.alloc_count", &alloc_count,
                    sizeof(alloc_count), pool_name2);

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 0ull);

    // allocate from pool1
    void *ptr1 = umfPoolMalloc(hPool, 1024);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr1, nullptr);

    // we can use pool name in the string without {} too
    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool.stats.alloc_count",
                    &alloc_count, sizeof(alloc_count));

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 1ull);

    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool2.stats.alloc_count",
                    &alloc_count, sizeof(alloc_count));

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 0ull);

    ret = umfPoolFree(hPool, ptr1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    // we can use index parameter too
    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool.0.stats.alloc_count",
                    &alloc_count, sizeof(alloc_count));

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 0ull);

    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool2.{}.stats.alloc_count",
                    &alloc_count, sizeof(alloc_count), 0);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 0ull);

    // test too big pool index
    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool2.10.stats.alloc_count",
                    &alloc_count, sizeof(alloc_count));
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    ret = umfPoolDestroy(hPool);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfPoolDestroy(hPool2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemoryProviderDestroy(hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}

TEST_F(test, ctl_by_name_collision) {
    umf_memory_provider_handle_t hProvider = NULL;
    umf_os_memory_provider_params_handle_t os_memory_provider_params = NULL;
    const umf_memory_provider_ops_t *os_provider_ops = umfOsMemoryProviderOps();
    if (os_provider_ops == NULL) {
        GTEST_SKIP() << "OS memory provider is not supported!";
    }

    int ret = umfOsMemoryProviderParamsCreate(&os_memory_provider_params);
    ret = umfMemoryProviderCreate(os_provider_ops, os_memory_provider_params,
                                  &hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    umfOsMemoryProviderParamsDestroy(os_memory_provider_params);

    umf_disjoint_pool_params_handle_t disjoint_pool_params = NULL;
    ret = umfDisjointPoolParamsCreate(&disjoint_pool_params);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    const char *pool_name = "test_disjoint_pool";
    ret = umfDisjointPoolParamsSetName(disjoint_pool_params, pool_name);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t hPool = NULL;
    ret = umfPoolCreate(umfDisjointPoolOps(), hProvider, disjoint_pool_params,
                        0, &hPool);

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_pool_handle_t hPool2 = NULL;
    ret = umfPoolCreate(umfDisjointPoolOps(), hProvider, disjoint_pool_params,
                        0, &hPool2);
    umfDisjointPoolParamsDestroy(disjoint_pool_params);

    // allocate from pool1
    void *ptr1 = umfPoolMalloc(hPool, 1024);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr1, nullptr);

    size_t pool_count;
    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool.count", &pool_count,
                    sizeof(pool_count));

    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(pool_count, 2ull);

    // If there is more than one pool with the same name,
    // CtlGet by_name will return an error
    size_t alloc_count;
    ret = umfCtlGet("umf.pool.by_name.{}.stats.alloc_count", &alloc_count,
                    sizeof(alloc_count), pool_name);

    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    // ctl set and exec will still work. But there is no CTL entry for now to test it

    // todo: add test when ctl entries will be extended

    // we can read from specific pool with index argument
    ret = umfCtlGet("umf.pool.by_name.test_disjoint_pool.0.stats.alloc_count",
                    &alloc_count, sizeof(alloc_count), pool_name, 0);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 1ull);

    ret = umfCtlGet("umf.pool.by_name.{}.1.stats.alloc_count", &alloc_count,
                    sizeof(alloc_count), pool_name);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(alloc_count, 0ull);

    ret = umfPoolFree(hPool, ptr1);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfPoolDestroy(hPool);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfPoolDestroy(hPool2);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ret = umfMemoryProviderDestroy(hProvider);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
}
