/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include "base.hpp"

#include <umf/memory_provider.h>
#include <umf/providers/provider_os_memory.h>

#include <numa.h>
#include <numaif.h>

static constexpr size_t allocSize = 4096;

struct providerConfigTest : testing::Test {
    umf_memory_provider_handle_t provider = nullptr;
    const size_t size = 128;
    void *ptr = nullptr;
    std::string dest = "destination";
    umf_os_memory_provider_params_handle_t params = nullptr;

    void SetUp() override {
        int ret = numa_available();
        if (ret) {
            GTEST_SKIP() << "Test skipped, NUMA not available";
        }

        auto res = umfOsMemoryProviderParamsCreate(&params);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    }

    void TearDown() override {
        if (ptr) {
            umfMemoryProviderFree(provider, ptr, size);
        }
        if (provider) {
            umfMemoryProviderDestroy(provider);
        }

        umfOsMemoryProviderParamsDestroy(params);
    }

    void create_provider(umf_os_memory_provider_params_handle_t params) {
        auto res = umfMemoryProviderCreate(umfOsMemoryProviderOps(), params,
                                           &provider);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        ASSERT_NE(provider, nullptr);
    }

    void allocate_memory() {
        auto res = umfMemoryProviderAlloc(provider, size, allocSize, &ptr);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
        ASSERT_NE(ptr, nullptr);
    }

    void read_memory() {
        dest.assign((char *)ptr, size);
        int ret = memcmp(ptr, dest.data(), size);
        ASSERT_EQ(ret, 0);
    }

    void write_memory(std::string_view str) {
        memset(ptr, '\0', size);
        str.copy((char *)ptr, str.size());
        EXPECT_EQ(std::string_view((char *)ptr), str);
    }
};

TEST_F(providerConfigTest, protection_flag_none) {
    // pages may not be accessed - PROT_NONE
    umfOsMemoryProviderParamsSetProtection(params, UMF_PROTECTION_NONE);

    create_provider(params);
    allocate_memory();

    // read failure
    EXPECT_DEATH(read_memory(), "");

    // write failure
    EXPECT_DEATH(write_memory("write string"), "");
}

TEST_F(providerConfigTest, protection_flag_read) {
    // pages may be read - PROT_READ
    umfOsMemoryProviderParamsSetProtection(params, UMF_PROTECTION_READ);

    create_provider(params);
    allocate_memory();

    // read success
    read_memory();

    // write failure
    EXPECT_DEATH(write_memory("write string"), "");
}

TEST_F(providerConfigTest, protection_flag_write) {
    // pages may be written to - PROT_WRITE
    umfOsMemoryProviderParamsSetProtection(params, UMF_PROTECTION_WRITE);

    create_provider(params);
    allocate_memory();

    // write success
    write_memory("write string");
}

TEST_F(providerConfigTest, protection_flag_read_write) {
    // pages may be read and written to - PROT_READ | PROT_WRITE
    umfOsMemoryProviderParamsSetProtection(params, UMF_PROTECTION_READ |
                                                       UMF_PROTECTION_WRITE);

    create_provider(params);
    allocate_memory();

    // read success
    read_memory();

    // write success
    write_memory("write string");
}

TEST_F(providerConfigTest, set_params_null_params_handle) {
    umf_result_t res = umfOsMemoryProviderParamsCreate(nullptr);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsDestroy(nullptr);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfOsMemoryProviderParamsSetProtection(nullptr, UMF_PROTECTION_READ);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsSetVisibility(nullptr, UMF_MEM_MAP_PRIVATE);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsSetShmName(nullptr, "shm_name");
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsSetNumaList(nullptr, nullptr, 0);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsSetNumaMode(nullptr, UMF_NUMA_MODE_DEFAULT);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsSetPartSize(nullptr, 0);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsSetPartitions(nullptr, nullptr, 0);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);
}

TEST_F(providerConfigTest, set_params_shm_name) {
    umf_result_t res = umfOsMemoryProviderParamsSetShmName(params, nullptr);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfOsMemoryProviderParamsSetShmName(params, "shm_name");
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfOsMemoryProviderParamsSetShmName(params, "");
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfOsMemoryProviderParamsSetShmName(params, nullptr);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
}

TEST_F(providerConfigTest, set_params_numa_list) {
    unsigned numa_list[1] = {0};

    umf_result_t res = umfOsMemoryProviderParamsSetNumaList(params, nullptr, 0);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfOsMemoryProviderParamsSetNumaList(params, numa_list, 1);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfOsMemoryProviderParamsSetNumaList(params, nullptr, 1);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsSetNumaList(params, numa_list, 0);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    // repeat the valid set to check memory leaks under Valgrind
    res = umfOsMemoryProviderParamsSetNumaList(params, numa_list, 1);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
}

TEST_F(providerConfigTest, set_params_partitions) {
    umf_numa_split_partition_t partitions[1] = {{0, 1}};

    umf_result_t res =
        umfOsMemoryProviderParamsSetPartitions(params, nullptr, 0);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfOsMemoryProviderParamsSetPartitions(params, partitions, 1);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    res = umfOsMemoryProviderParamsSetPartitions(params, nullptr, 1);
    ASSERT_EQ(res, UMF_RESULT_ERROR_INVALID_ARGUMENT);

    res = umfOsMemoryProviderParamsSetPartitions(params, partitions, 0);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);

    // repeat the valid set to check memory leaks under Valgrind
    res = umfOsMemoryProviderParamsSetPartitions(params, partitions, 1);
    ASSERT_EQ(res, UMF_RESULT_SUCCESS);
}

struct providerConfigTestNumaMode
    : providerConfigTest,
      testing::WithParamInterface<umf_numa_mode_t> {
    struct bitmask *allowed_nodes = nullptr;
    umf_numa_mode_t expected_numa_mode;

    void SetUp() override {
        providerConfigTest::SetUp();

        if (::providerConfigTest::IsSkipped()) {
            GTEST_SKIP();
        }

        expected_numa_mode = GetParam();

        auto res =
            umfOsMemoryProviderParamsSetNumaMode(params, expected_numa_mode);
        ASSERT_EQ(res, UMF_RESULT_SUCCESS);
    }

    void TearDown() override {
        if (allowed_nodes) {
            numa_bitmask_free(allowed_nodes);
        }

        providerConfigTest::TearDown();
    }
};

INSTANTIATE_TEST_SUITE_P(numa_modes, providerConfigTestNumaMode,
                         testing::Values(UMF_NUMA_MODE_DEFAULT,
                                         UMF_NUMA_MODE_BIND,
                                         UMF_NUMA_MODE_INTERLEAVE,
                                         UMF_NUMA_MODE_LOCAL));
#ifndef MPOL_LOCAL
#define MPOL_LOCAL 4
#endif

#ifndef MPOL_PREFERRED_MANY
#define MPOL_PREFERRED_MANY 5
#endif

TEST_P(providerConfigTestNumaMode, numa_modes) {
    unsigned numa_list_len = 0;
    unsigned *numa_list = nullptr;
    if (expected_numa_mode != UMF_NUMA_MODE_DEFAULT &&
        expected_numa_mode != UMF_NUMA_MODE_LOCAL) {
        allowed_nodes = numa_get_mems_allowed();
        // convert bitmask to array of nodes
        numa_list_len = numa_bitmask_weight(allowed_nodes);
        numa_list = (unsigned *)malloc(numa_list_len * sizeof(*numa_list));
        ASSERT_NE(numa_list, nullptr);
        unsigned count = 0;
        for (unsigned i = 0; i < numa_list_len; i++) {
            if (numa_bitmask_isbitset(allowed_nodes, i)) {
                numa_list[count++] = i;
            }
        }
        ASSERT_EQ(count, numa_list_len);

        umfOsMemoryProviderParamsSetNumaList(params, numa_list, numa_list_len);
    }

    create_provider(params);
    allocate_memory();
    write_memory("write string");

    int actual_mode = -1;
    long ret = get_mempolicy(&actual_mode, nullptr, 0, ptr, MPOL_F_ADDR);
    ASSERT_EQ(ret, 0);

    if (expected_numa_mode == UMF_NUMA_MODE_DEFAULT) {
        ASSERT_EQ(actual_mode, MPOL_DEFAULT);
    } else if (expected_numa_mode == UMF_NUMA_MODE_BIND) {
        ASSERT_EQ(actual_mode, MPOL_BIND);
    } else if (expected_numa_mode == UMF_NUMA_MODE_INTERLEAVE) {
        ASSERT_EQ(actual_mode, MPOL_INTERLEAVE);
    } else if (expected_numa_mode == UMF_NUMA_MODE_PREFERRED) {
        // MPOL_PREFERRED_MANY is equivalent to MPOL_PREFERRED if a single node is set
        if (actual_mode != MPOL_PREFERRED_MANY) {
            ASSERT_EQ(actual_mode, MPOL_PREFERRED);
        }
    } else if (expected_numa_mode == UMF_NUMA_MODE_LOCAL) {
        // MPOL_PREFERRED_* is equivalent to MPOL_LOCAL if no node is set
        if (actual_mode == MPOL_PREFERRED ||
            actual_mode == MPOL_PREFERRED_MANY) {
            ASSERT_EQ(numa_list_len, 0);
        } else {
            ASSERT_EQ(actual_mode, MPOL_LOCAL);
        }
    }
    free(numa_list);
}
