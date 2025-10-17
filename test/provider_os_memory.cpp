// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <umf/experimental/ctl.h>
#include <umf/memory_provider.h>
#include <umf/pools/pool_disjoint.h>
#include <umf/providers/provider_os_memory.h>
#ifdef UMF_POOL_JEMALLOC_ENABLED
#include <umf/pools/pool_jemalloc.h>
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
#include <umf/pools/pool_scalable.h>
#endif

#include "base.hpp"
#include "ipcFixtures.hpp"
#include "provider.hpp"
#include "test_helpers.h"
#include "utils/cpp_helpers.hpp"

using umf_test::test;

#define INVALID_PTR ((void *)0x01)

typedef enum purge_t {
    PURGE_NONE = 0,
    PURGE_LAZY = 1,
    PURGE_FORCE = 2,
} purge_t;

static const char *Native_error_str[] = {
    "success",                          // UMF_OS_RESULT_SUCCESS
    "memory allocation failed",         // UMF_OS_RESULT_ERROR_ALLOC_FAILED
    "allocated address is not aligned", // UMF_OS_RESULT_ERROR_ADDRESS_NOT_ALIGNED
    "binding memory to NUMA node failed", // UMF_OS_RESULT_ERROR_BIND_FAILED
    "memory deallocation failed",         // UMF_OS_RESULT_ERROR_FREE_FAILED
    "lazy purging failed",             // UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED
    "force purging failed",            // UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED
    "HWLOC topology discovery failed", // UMF_OS_RESULT_ERROR_TOPO_DISCOVERY_FAILED
};

// test helpers

static int compare_native_error_str(const char *message, int error) {
    const char *error_str = Native_error_str[error - UMF_OS_RESULT_SUCCESS];
    size_t len = strlen(error_str);
    return strncmp(message, error_str, len);
}

struct umfProviderTest
    : umf_test::test,
      ::testing::WithParamInterface<providerCreateExtParams> {
    void SetUp() override {
        test::SetUp();
        providerCreateExt(this->GetParam(), &provider);
        umf_result_t umf_result =
            umfMemoryProviderGetMinPageSize(provider.get(), NULL, &page_size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);

        page_plus_64 = page_size + 64;
    }

    void TearDown() override { test::TearDown(); }

    umf_test::provider_unique_handle_t provider;
    size_t page_size;
    size_t page_plus_64;
};

static void test_alloc_free_success(umf_memory_provider_handle_t provider,
                                    size_t size, size_t alignment,
                                    purge_t purge) {
    void *ptr = nullptr;

    umf_result_t umf_result =
        umfMemoryProviderAlloc(provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    memset(ptr, 0xFF, size);

    if (purge == PURGE_LAZY) {
        umf_result = umfMemoryProviderPurgeLazy(provider, ptr, size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    } else if (purge == PURGE_FORCE) {
        umf_result = umfMemoryProviderPurgeForce(provider, ptr, size);
        ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    }

    umf_result = umfMemoryProviderFree(provider, ptr, size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

static void verify_last_native_error(umf_memory_provider_handle_t provider,
                                     int32_t err) {
    const char *message;
    int32_t error;
    umf_result_t ret =
        umfMemoryProviderGetLastNativeError(provider, &message, &error);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(error, err);
    ASSERT_EQ(compare_native_error_str(message, error), 0);
}

static void test_alloc_failure(umf_memory_provider_handle_t provider,
                               size_t size, size_t alignment,
                               umf_result_t result, int32_t err) {
    void *ptr = nullptr;
    umf_result_t umf_result =
        umfMemoryProviderAlloc(provider, size, alignment, &ptr);
    ASSERT_EQ(umf_result, result);
    ASSERT_EQ(ptr, nullptr);

    if (umf_result == UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC) {
        verify_last_native_error(provider, err);
    }
}

// TESTS

// negative tests for umfMemoryProviderCreate()

static umf_result_t create_os_provider_with_mode(umf_numa_mode_t mode,
                                                 unsigned *node_list,
                                                 unsigned node_list_size) {
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_handle_t os_memory_provider_params = nullptr;

    umf_result = umfOsMemoryProviderParamsCreate(&os_memory_provider_params);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result =
        umfOsMemoryProviderParamsSetNumaMode(os_memory_provider_params, mode);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfOsMemoryProviderParamsSetNumaList(
        os_memory_provider_params, node_list, node_list_size);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result =
        umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                os_memory_provider_params, &os_memory_provider);
    umfOsMemoryProviderParamsDestroy(os_memory_provider_params);
    if (umf_result == UMF_RESULT_SUCCESS) {
        EXPECT_NE(os_memory_provider, nullptr);
        umfMemoryProviderDestroy(os_memory_provider);
    } else {
        EXPECT_EQ(os_memory_provider, nullptr);
    }

    return umf_result;
}

static unsigned valid_list = 0x1;
static unsigned long valid_list_len = 1;

TEST_F(test, create_WRONG_NUMA_MODE_DEFAULT) {
    auto ret = create_os_provider_with_mode(UMF_NUMA_MODE_DEFAULT, &valid_list,
                                            valid_list_len);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, create_WRONG_NUMA_MODE_LOCAL) {
    auto ret = create_os_provider_with_mode(UMF_NUMA_MODE_LOCAL, &valid_list,
                                            valid_list_len);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, create_WRONG_NUMA_MODE_BIND) {
    auto ret = create_os_provider_with_mode(UMF_NUMA_MODE_BIND, nullptr, 0);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, create_WRONG_NUMA_MODE_INTERLEAVE) {
    auto ret =
        create_os_provider_with_mode(UMF_NUMA_MODE_INTERLEAVE, nullptr, 0);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, create_WRONG_NUMA_MODE_SPLIT) {
    auto ret = create_os_provider_with_mode(UMF_NUMA_MODE_SPLIT, nullptr, 0);
    ASSERT_EQ(ret, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(test, create_ZERO_WEIGHT_PARTITION) {
    umf_numa_split_partition_t p = {0, 0};
    umf_result_t umf_result;
    umf_memory_provider_handle_t os_memory_provider = nullptr;
    umf_os_memory_provider_params_handle_t os_memory_provider_params = NULL;

    umf_result = umfOsMemoryProviderParamsCreate(&os_memory_provider_params);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfOsMemoryProviderParamsSetNumaMode(os_memory_provider_params,
                                                      UMF_NUMA_MODE_SPLIT);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfOsMemoryProviderParamsSetNumaList(
        os_memory_provider_params, &valid_list, valid_list_len);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result = umfOsMemoryProviderParamsSetPartitions(
        os_memory_provider_params, &p, 1);
    EXPECT_EQ(umf_result, UMF_RESULT_SUCCESS);

    umf_result =
        umfMemoryProviderCreate(umfOsMemoryProviderOps(),
                                os_memory_provider_params, &os_memory_provider);

    umfOsMemoryProviderParamsDestroy(os_memory_provider_params);

    EXPECT_EQ(os_memory_provider, nullptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

// positive tests using test_alloc_free_success

using os_params_unique_handle_t =
    std::unique_ptr<umf_os_memory_provider_params_t,
                    decltype(&umfOsMemoryProviderParamsDestroy)>;

os_params_unique_handle_t createOsMemoryProviderParams() {
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create os memory provider params");
    }

    return os_params_unique_handle_t(params, &umfOsMemoryProviderParamsDestroy);
}
auto defaultParams = createOsMemoryProviderParams();

INSTANTIATE_TEST_SUITE_P(osProviderTest, umfProviderTest,
                         ::testing::Values(providerCreateExtParams{
                             umfOsMemoryProviderOps(), defaultParams.get()}),
                         providerCreateExtParamsNameGen);

TEST_P(umfProviderTest, create_destroy) {}

TEST_P(umfProviderTest, alloc_page64_align_0) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_NONE);
}

TEST_P(umfProviderTest, alloc_page64_align_page_div_2) {
    test_alloc_free_success(provider.get(), page_plus_64, page_size / 2,
                            PURGE_NONE);
}

TEST_P(umfProviderTest, alloc_page64_align_3_pages) {
    test_alloc_free_success(provider.get(), page_plus_64, 3 * page_size,
                            PURGE_NONE);
}

TEST_P(umfProviderTest, alloc_3pages_align_3pages) {
    test_alloc_free_success(provider.get(), 3 * page_size, 3 * page_size,
                            PURGE_NONE);
}

TEST_P(umfProviderTest, purge_lazy) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_LAZY);
}

TEST_P(umfProviderTest, purge_force) {
    test_alloc_free_success(provider.get(), page_plus_64, 0, PURGE_FORCE);
}

// negative tests using test_alloc_failure

TEST_P(umfProviderTest, alloc_page64_align_page_minus_1_WRONG_ALIGNMENT_1) {
    test_alloc_failure(provider.get(), page_plus_64, page_size - 1,
                       UMF_RESULT_ERROR_INVALID_ARGUMENT, 0);
}

TEST_P(umfProviderTest, alloc_page64_align_one_half_pages_WRONG_ALIGNMENT_2) {
    test_alloc_failure(provider.get(), page_plus_64,
                       page_size + (page_size / 2),
                       UMF_RESULT_ERROR_INVALID_ARGUMENT, 0);
}

TEST_P(umfProviderTest, alloc_WRONG_SIZE) {
    test_alloc_failure(provider.get(), -1, 0,
                       UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC,
                       UMF_OS_RESULT_ERROR_ALLOC_FAILED);
}

TEST_P(umfProviderTest, alloc_MAX_SIZE) {
    test_alloc_failure(provider.get(), SIZE_MAX, 0,
                       UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC,
                       UMF_OS_RESULT_ERROR_ALLOC_FAILED);
}

// other positive tests

TEST_P(umfProviderTest, get_min_page_size) {
    size_t min_page_size;
    umf_result_t umf_result = umfMemoryProviderGetMinPageSize(
        provider.get(), nullptr, &min_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_LE(min_page_size, page_size);
}

TEST_P(umfProviderTest, get_recommended_page_size) {
    size_t min_page_size;
    umf_result_t umf_result = umfMemoryProviderGetMinPageSize(
        provider.get(), nullptr, &min_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_LE(min_page_size, page_size);

    size_t recommended_page_size;
    umf_result = umfMemoryProviderGetRecommendedPageSize(
        provider.get(), 0, &recommended_page_size);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
    ASSERT_GE(recommended_page_size, min_page_size);
}

TEST_P(umfProviderTest, get_name) {
    const char *name = nullptr;
    umf_result_t ret = umfMemoryProviderGetName(provider.get(), &name);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_STREQ(name, "OS");
}

TEST(OsProviderName, custom_name) {
    auto params = createOsMemoryProviderParams();
    ASSERT_NE(params.get(), nullptr);
    const char *custom = "my_os";
    auto ret = umfOsMemoryProviderParamsSetName(params.get(), custom);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    umf_memory_provider_handle_t prov = nullptr;
    ret =
        umfMemoryProviderCreate(umfOsMemoryProviderOps(), params.get(), &prov);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    const char *name = nullptr;
    ret = umfMemoryProviderGetName(prov, &name);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, custom);
    umfMemoryProviderDestroy(prov);
}

TEST(OsProviderName, default_name_null_handle) {
    const char *name = nullptr;
    auto ret = umfOsMemoryProviderOps()->get_name(nullptr, &name);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    EXPECT_STREQ(name, "OS");
}

TEST_P(umfProviderTest, free_size_0_ptr_not_null) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);
}

TEST_P(umfProviderTest, free_NULL) {
    umf_result_t umf_result = umfMemoryProviderFree(provider.get(), nullptr, 0);
    ASSERT_EQ(umf_result, UMF_RESULT_SUCCESS);
}

// other negative tests

TEST_P(umfProviderTest, free_INVALID_POINTER_SIZE_GT_0) {
    umf_result_t umf_result =
        umfMemoryProviderFree(provider.get(), INVALID_PTR, page_plus_64);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(provider.get(), UMF_OS_RESULT_ERROR_FREE_FAILED);
}

TEST_P(umfProviderTest, purge_lazy_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeLazy(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(provider.get(),
                             UMF_OS_RESULT_ERROR_PURGE_LAZY_FAILED);
}

TEST_P(umfProviderTest, purge_force_INVALID_POINTER) {
    umf_result_t umf_result =
        umfMemoryProviderPurgeForce(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC);

    verify_last_native_error(provider.get(),
                             UMF_OS_RESULT_ERROR_PURGE_FORCE_FAILED);
}

TEST_P(umfProviderTest, get_ipc_handle_size_wrong_visibility) {
    size_t size;
    umf_result_t umf_result =
        umfMemoryProviderGetIPCHandleSize(provider.get(), &size);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfProviderTest, get_ipc_handle_wrong_visibility) {
    char providerIpcData;
    umf_result_t umf_result = umfMemoryProviderGetIPCHandle(
        provider.get(), INVALID_PTR, 1, &providerIpcData);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfProviderTest, put_ipc_handle_wrong_visibility) {
    char providerIpcData;
    umf_result_t umf_result =
        umfMemoryProviderPutIPCHandle(provider.get(), &providerIpcData);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfProviderTest, open_ipc_handle_wrong_visibility) {
    char providerIpcData;
    void *ptr;
    umf_result_t umf_result =
        umfMemoryProviderOpenIPCHandle(provider.get(), &providerIpcData, &ptr);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfProviderTest, close_ipc_handle_wrong_visibility) {
    umf_result_t umf_result =
        umfMemoryProviderCloseIPCHandle(provider.get(), INVALID_PTR, 1);
    ASSERT_EQ(umf_result, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_P(umfProviderTest, ctl_stats) {
    size_t allocated = 0, peak = 0;
    umf_result_t ret =
        umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                  &allocated, sizeof(allocated), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, 0u);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, 0u);

    void *ptr = nullptr;
    size_t size = page_size;
    ret = umfMemoryProviderAlloc(provider.get(), size, 0, &ptr);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_NE(ptr, nullptr);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                    &allocated, sizeof(allocated), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, size);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, size);

    ret = umfMemoryProviderFree(provider.get(), ptr, size);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.allocated_memory",
                    &allocated, sizeof(allocated), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(allocated, 0u);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, size);

    ret = umfCtlExec("umf.provider.by_handle.{}.stats.peak_memory.reset", NULL,
                     0, provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfCtlGet("umf.provider.by_handle.{}.stats.peak_memory", &peak,
                    sizeof(peak), provider.get());
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    ASSERT_EQ(peak, 0u);
}

GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(umfIpcTest);

void *createOsMemoryProviderParamsShared() {
    umf_os_memory_provider_params_handle_t params = nullptr;
    umf_result_t res = umfOsMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create os memory provider params");
    }
    res = umfOsMemoryProviderParamsSetVisibility(params, UMF_MEM_MAP_SHARED);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to set protection");
    }

    return params;
}

umf_result_t destroyOsMemoryProviderParamsShared(void *params) {
    return umfOsMemoryProviderParamsDestroy(
        static_cast<umf_os_memory_provider_params_handle_t>(params));
}

HostMemoryAccessor hostAccessor;

void *createDisjointPoolParams() {
    umf_disjoint_pool_params_handle_t params = nullptr;
    umf_result_t res = umfDisjointPoolParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create pool params");
    }
    res = umfDisjointPoolParamsSetSlabMinSize(params, 4096);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(params);
        throw std::runtime_error("Failed to set slab min size");
    }
    res = umfDisjointPoolParamsSetMaxPoolableSize(params, 4096);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(params);
        throw std::runtime_error("Failed to set max poolable size");
    }
    res = umfDisjointPoolParamsSetCapacity(params, 4);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(params);
        throw std::runtime_error("Failed to set capacity");
    }
    res = umfDisjointPoolParamsSetMinBucketSize(params, 64);
    if (res != UMF_RESULT_SUCCESS) {
        umfDisjointPoolParamsDestroy(params);
        throw std::runtime_error("Failed to set min bucket size");
    }

    return params;
}

umf_result_t destroyDisjointPoolParams(void *params) {
    return umfDisjointPoolParamsDestroy(
        static_cast<umf_disjoint_pool_params_handle_t>(params));
}

#ifdef UMF_POOL_JEMALLOC_ENABLED
void *createJemallocParams() {
    umf_jemalloc_pool_params_handle_t jemalloc_params = NULL;
    umf_result_t res = umfJemallocPoolParamsCreate(&jemalloc_params);
    if (res != UMF_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to create Jemalloc Pool params");
    }

    // This test creates multiple pools, so we need to reduce the number of arenas
    // to avoid hitting the maximum arena limit on systems with many cores.
    res = umfJemallocPoolParamsSetNumArenas(jemalloc_params, 1);
    if (res != UMF_RESULT_SUCCESS) {
        umfJemallocPoolParamsDestroy(jemalloc_params);
        throw std::runtime_error("Failed to set number of arenas for Jemalloc "
                                 "Pool params");
    }
    return jemalloc_params;
}

umf_result_t destroyJemallocParams(void *params) {
    return umfJemallocPoolParamsDestroy(
        (umf_jemalloc_pool_params_handle_t)params);
}

#endif

static std::vector<ipcTestParams> ipcTestParamsList = {
    {umfDisjointPoolOps(), createDisjointPoolParams, destroyDisjointPoolParams,
     umfOsMemoryProviderOps(), createOsMemoryProviderParamsShared,
     destroyOsMemoryProviderParamsShared, &hostAccessor},
#ifdef UMF_POOL_JEMALLOC_ENABLED
    {umfJemallocPoolOps(), createJemallocParams, destroyJemallocParams,
     umfOsMemoryProviderOps(), createOsMemoryProviderParamsShared,
     destroyOsMemoryProviderParamsShared, &hostAccessor},
#endif
#ifdef UMF_POOL_SCALABLE_ENABLED
    {umfScalablePoolOps(), nullptr, nullptr, umfOsMemoryProviderOps(),
     createOsMemoryProviderParamsShared, destroyOsMemoryProviderParamsShared,
     &hostAccessor},
#endif
};

INSTANTIATE_TEST_SUITE_P(osProviderTest, umfIpcTest,
                         ::testing::ValuesIn(ipcTestParamsList),
                         ipcTestParamsNameGen);
