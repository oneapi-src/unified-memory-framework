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
    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();

    void SetUp() override {
        int ret = numa_available();
        if (ret) {
            GTEST_SKIP() << "Test skipped, NUMA not available";
        }
    }

    void TearDown() override {
        if (ptr) {
            umfMemoryProviderFree(provider, ptr, size);
        }
        if (provider) {
            umfMemoryProviderDestroy(provider);
        }
    }

    void create_provider(umf_os_memory_provider_params_t *params) {
        auto res = umfMemoryProviderCreate(&UMF_OS_MEMORY_PROVIDER_OPS, params,
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

TEST_F(providerConfigTest, protection_flag_none_read) {
    // pages may not be accessed - PROT_NONE
    params.protection = UMF_PROTECTION_NONE;

    create_provider(&params);
    allocate_memory();

    // read failure
    EXPECT_DEATH(read_memory(), "");
}

TEST_F(providerConfigTest, protection_flag_none_write) {
    // pages may not be accessed - PROT_NONE
    params.protection = UMF_PROTECTION_NONE;

    create_provider(&params);
    allocate_memory();

    // write failure
    EXPECT_DEATH(write_memory("write string"), "");
}

TEST_F(providerConfigTest, protection_flag_read) {
    // pages may be read - PROT_READ
    params.protection = UMF_PROTECTION_READ;

    create_provider(&params);
    allocate_memory();

    // read success
    read_memory();

    // write failure
    EXPECT_DEATH(write_memory("write string"), "");
}

TEST_F(providerConfigTest, protection_flag_write) {
    // pages may be written to - PROT_WRITE
    params.protection = UMF_PROTECTION_WRITE;

    create_provider(&params);
    allocate_memory();

    // write success
    write_memory("write string");
}

TEST_F(providerConfigTest, protection_flag_read_write) {
    // pages may be read and written to - PROT_READ | PROT_WRITE
    params.protection = UMF_PROTECTION_READ | UMF_PROTECTION_WRITE;

    create_provider(&params);
    allocate_memory();

    // read success
    read_memory();

    // write success
    write_memory("write string");
}

struct providerConfigTestNumaMode
    : providerConfigTest,
      testing::WithParamInterface<umf_numa_mode_t> {
    struct bitmask *allowed_nodes = nullptr;
    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();

    void SetUp() override {
        providerConfigTest::SetUp();
        params.numa_mode = GetParam();
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
                                         UMF_NUMA_MODE_PREFERRED,
                                         UMF_NUMA_MODE_LOCAL));
#ifndef MPOL_LOCAL
#define MPOL_LOCAL 4
#endif

#ifndef MPOL_PREFERRED_MANY
#define MPOL_PREFERRED_MANY 5
#endif

TEST_P(providerConfigTestNumaMode, numa_modes) {
    if (params.numa_mode != UMF_NUMA_MODE_DEFAULT &&
        params.numa_mode != UMF_NUMA_MODE_LOCAL) {
        allowed_nodes = numa_get_mems_allowed();
        params.nodemask = allowed_nodes->maskp;
        params.maxnode = allowed_nodes->size;
    }

    create_provider(&params);
    allocate_memory();
    write_memory("write string");

    int actual_mode = -1;
    long ret = get_mempolicy(&actual_mode, nullptr, 0, ptr, MPOL_F_ADDR);
    ASSERT_EQ(ret, 0);

    if (params.numa_mode == UMF_NUMA_MODE_DEFAULT) {
        ASSERT_EQ(actual_mode, MPOL_DEFAULT);
    } else if (params.numa_mode == UMF_NUMA_MODE_BIND) {
        ASSERT_EQ(actual_mode, MPOL_BIND);
    } else if (params.numa_mode == UMF_NUMA_MODE_INTERLEAVE) {
        ASSERT_EQ(actual_mode, MPOL_INTERLEAVE);
    } else if (params.numa_mode == UMF_NUMA_MODE_PREFERRED) {
        // MPOL_PREFERRED_MANY is equivalent to MPOL_PREFERRED if a single node is set
        if (actual_mode != MPOL_PREFERRED_MANY) {
            ASSERT_EQ(actual_mode, MPOL_PREFERRED);
        }
    } else if (params.numa_mode == UMF_NUMA_MODE_LOCAL) {
        // MPOL_PREFERRED_* is equivalent to MPOL_LOCAL if no node is set
        if (actual_mode == MPOL_PREFERRED ||
            actual_mode == MPOL_PREFERRED_MANY) {
            ASSERT_EQ(params.maxnode, 0);
        } else {
            ASSERT_EQ(actual_mode, MPOL_LOCAL);
        }
    }
}

struct providerConfigTestVisibility
    : providerConfigTest,
      testing::WithParamInterface<umf_mem_visibility_t> {
    std::string primary_str = "primary";
    std::string new_str = "new";
    std::string expected_str;
    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();

    void SetUp() override {
        providerConfigTest::SetUp();
        params.visibility = GetParam();
        if (params.visibility == UMF_VISIBILITY_PRIVATE) {
            expected_str = primary_str;
        } else if (params.visibility == UMF_VISIBILITY_SHARED) {
            expected_str = new_str;
        }
    }
};

INSTANTIATE_TEST_SUITE_P(visibility, providerConfigTestVisibility,
                         testing::Values(UMF_VISIBILITY_PRIVATE,
                                         UMF_VISIBILITY_SHARED));

TEST_P(providerConfigTestVisibility, visibility) {
    create_provider(&params);
    allocate_memory();
    write_memory(primary_str);

    int pid = fork();
    if (pid == 0) {
        // child process
        write_memory(new_str);
    } else if (pid > 0) {
        // main process
        int status;
        while (-1 == waitpid(0, &status, 0)) {
            // wait for the child process to complete
        }
        EXPECT_EQ(static_cast<char *>(ptr), expected_str);
    }
}
