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
#include <string>
#include <thread>
#include <vector>

#include <umf.h>
#include <umf/base.h>
#include <umf/experimental/ctl.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_os_memory.h>

#include "../common/base.hpp"
#include "../common/fork_helpers.hpp"
#include "../common/provider.hpp"
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

class CtlTest : public ::testing::Test {
  public:
    CtlTest() {}

    void SetUp() override {}

    void TearDown() override {}

  private:
};

// setting default modifies global state -
// tests doing so should run in fork to ensure correct test isolation
TEST_F(CtlTest, ctlDefault) {
    umf_test::run_in_fork([] {
        const char *arg = "default_name";
        ASSERT_EQ(umfCtlSet("umf.pool.default.some_pool.some_path", (void *)arg,
                            strlen(arg)),
                  UMF_RESULT_SUCCESS);

        char output[64] = {1};
        ASSERT_EQ(umfCtlGet("umf.pool.default.some_pool.some_path",
                            (void *)output, sizeof(output)),
                  UMF_RESULT_SUCCESS);
        ASSERT_STREQ(output, arg);
    });
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
    umf_test::run_in_fork([] {
        const size_t max_size = 10;
        const size_t num_threads = 8;
        std::vector<std::thread> threads;
        std::atomic<size_t> totalRecords = 0;
        const char *predefined_value = "xyzzyx";
        std::string name_prefix = "umf.pool.default.some_pool.";
        for (size_t i = 0; i < num_threads; i++) {
            threads.emplace_back([i, &totalRecords, &predefined_value,
                                  &name_prefix, max_size = max_size]() {
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

        ASSERT_EQ(totalRecords.load(), num_threads * max_size);

        char output[100] = {0};
        for (size_t i = 0; i < totalRecords.load(); i++) {
            std::string name = name_prefix + std::to_string(i);
            umf_result_t status =
                umfCtlGet(name.c_str(), (void *)output, sizeof(output));
            ASSERT_EQ(status, UMF_RESULT_SUCCESS);
            ASSERT_STREQ(output, predefined_value);
        }
    });
}

struct ctl_provider_params {
    const char *name;
    int initial_value;
};

class ctl_provider : public umf_test::provider_base_t {
  public:
    ctl_provider() : name_ptr_(kDefaultName), stored_value_(0) {}

    umf_result_t initialize(const ctl_provider_params *params) noexcept {
        if (!params) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }

        stored_value_ = params->initial_value;
        if (params->name) {
            name_storage_ = params->name;
            name_ptr_ = name_storage_.c_str();
        } else {
            name_ptr_ = kDefaultName;
        }

        return UMF_RESULT_SUCCESS;
    }

    umf_result_t get_name(const char **name) noexcept {
        if (!name) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *name = name_ptr_;
        return UMF_RESULT_SUCCESS;
    }

    umf_result_t ext_ctl(umf_ctl_query_source_t, const char *path, void *arg,
                         size_t size, umf_ctl_query_type_t queryType,
                         va_list) noexcept {
        if (std::strcmp(path, "params.value") != 0) {
            return UMF_RESULT_ERROR_INVALID_CTL_PATH;
        }

        if (!arg || size != sizeof(int)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }

        if (queryType == CTL_QUERY_WRITE) {
            stored_value_ = *static_cast<int *>(arg);
            return UMF_RESULT_SUCCESS;
        }

        if (queryType == CTL_QUERY_READ) {
            *static_cast<int *>(arg) = stored_value_;
            return UMF_RESULT_SUCCESS;
        }

        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

  private:
    static constexpr const char *kDefaultName = "mock";
    std::string name_storage_;
    const char *name_ptr_;
    int stored_value_;
};

TEST_F(CtlTest, ctlProviderDefaultsCustomName) {
    umf_test::run_in_fork([] {
        static auto provider_ops =
            umf_test::providerMakeCOps<ctl_provider, ctl_provider_params>();

        int canonical_default = 21;
        ASSERT_EQ(umfCtlSet("umf.provider.default.mock.params.value",
                            &canonical_default, sizeof(canonical_default)),
                  UMF_RESULT_SUCCESS);

        const std::string custom_name = "custom_provider";
        int custom_default = 37;
        const std::string custom_path =
            "umf.provider.default." + custom_name + ".params.value";
        ASSERT_EQ(umfCtlSet(custom_path.c_str(), &custom_default,
                            sizeof(custom_default)),
                  UMF_RESULT_SUCCESS);

        ctl_provider_params custom_params{custom_name.c_str(), 0};
        umf_memory_provider_handle_t custom_handle = nullptr;
        ASSERT_EQ(umfMemoryProviderCreate(&provider_ops, &custom_params,
                                          &custom_handle),
                  UMF_RESULT_SUCCESS);

        int value = 0;
        ASSERT_EQ(umfCtlGet("umf.provider.by_handle.{}.params.value", &value,
                            sizeof(value), custom_handle),
                  UMF_RESULT_SUCCESS);
        EXPECT_EQ(value, custom_default);
        ASSERT_EQ(umfMemoryProviderDestroy(custom_handle), UMF_RESULT_SUCCESS);

        ctl_provider_params canonical_params{nullptr, 7};
        umf_memory_provider_handle_t canonical_handle = nullptr;
        ASSERT_EQ(umfMemoryProviderCreate(&provider_ops, &canonical_params,
                                          &canonical_handle),
                  UMF_RESULT_SUCCESS);

        ASSERT_EQ(umfCtlGet("umf.provider.by_handle.{}.params.value", &value,
                            sizeof(value), canonical_handle),
                  UMF_RESULT_SUCCESS);
        EXPECT_EQ(value, canonical_default);
        ASSERT_EQ(umfMemoryProviderDestroy(canonical_handle),
                  UMF_RESULT_SUCCESS);
    });
}

/* Case: overwriting an existing value for pool defaults
 * This test sets a default value and then overwrites it with a new value */
TEST_F(CtlTest, ctlDefaultPoolOverwrite) {
    umf_test::run_in_fork([] {
        constexpr int max_size = 10;
        std::vector<std::string> values;
        const std::string name = "umf.pool.default.some_pool";

        for (int i = 0; i < max_size; i++) {
            values.push_back("value_" + std::to_string(i));
            umf_result_t set_status =
                umfCtlSet(name.c_str(), (void *)values.back().c_str(),
                          values.back().size());
            ASSERT_EQ(set_status, UMF_RESULT_SUCCESS);
        }

        char output[100] = {0};
        umf_result_t status =
            umfCtlGet(name.c_str(), (void *)output, sizeof(output));
        ASSERT_EQ(status, UMF_RESULT_SUCCESS);
        ASSERT_STREQ(output, values.back().c_str());
    });
}

TEST_F(CtlTest, ctlDefaultMultithreadedProvider) {
    umf_test::run_in_fork([] {
        std::vector<std::thread> threads;
        std::atomic<size_t> totalRecords = 0;
        const char *predefined_value = "xyzzyx";
        std::string name_prefix = "umf.provider.default.some_provider.";
        for (int i = 0; i < 8; i++) {
            threads.emplace_back([i, &totalRecords, &predefined_value,
                                  &name_prefix]() {
                for (int j = 0; j < 10; j++) {
                    std::string name = name_prefix + std::to_string(i * 10 + j);
                    umfCtlSet(name.c_str(), (void *)predefined_value,
                              strlen(predefined_value));
                    std::atomic_fetch_add(&totalRecords, (size_t)1);
                }
            });
        }
        for (auto &thread : threads) {
            thread.join();
        }

        char output[100] = {0};
        for (size_t i = 0; i < totalRecords.load(); i++) {
            std::string name = name_prefix + std::to_string(i);
            umf_result_t status =
                umfCtlGet(name.c_str(), (void *)output, sizeof(output));
            ASSERT_EQ(status, UMF_RESULT_SUCCESS);
            ASSERT_STREQ(output, predefined_value);
        }
    });
}

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

    const char out_name[] = "stdout";
    ASSERT_EQ(
        umfCtlSet("umf.logger.output", (void *)out_name, sizeof(out_name)),
        UMF_RESULT_SUCCESS);
    const char out_get[256] = "";
    ASSERT_EQ(umfCtlGet("umf.logger.output", (void *)out_get, sizeof(out_get)),
              UMF_RESULT_SUCCESS);
    EXPECT_STREQ(out_get, "stdout");
}

TEST_F(test, ctl_logger_output_file) {
    const char file_name[] = "ctl_log.txt";
    ASSERT_EQ(
        umfCtlSet("umf.logger.output", (void *)file_name, sizeof(file_name)),
        UMF_RESULT_SUCCESS);
    const char out_get[256] = "";
    ASSERT_EQ(umfCtlGet("umf.logger.output", (void *)out_get, sizeof(out_get)),
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
