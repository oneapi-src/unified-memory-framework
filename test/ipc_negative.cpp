// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include "base.hpp"
#include "pool_null.h"
#include "provider_null.h"

#include <umf/ipc.h>
#include <umf/memory_pool.h>
#include <umf/memory_provider.h>

#include <array>

struct IpcNotSupported : umf_test::test {
  protected:
    void SetUp() override {
        umf_memory_provider_ops_t provider_ops = UMF_NULL_PROVIDER_OPS;
        provider_ops.ipc.get_ipc_handle_size = nullptr;
        provider_ops.ipc.get_ipc_handle = nullptr;
        provider_ops.ipc.open_ipc_handle = nullptr;
        provider_ops.ipc.put_ipc_handle = nullptr;
        provider_ops.ipc.close_ipc_handle = nullptr;

        umf_result_t ret;
        ret = umfMemoryProviderCreate(&provider_ops, nullptr, &provider);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

        ret = umfPoolCreate(&UMF_NULL_POOL_OPS, provider, nullptr,
                            UMF_POOL_CREATE_FLAG_OWN_PROVIDER, &pool);
        ASSERT_EQ(ret, UMF_RESULT_SUCCESS);
    }

    void TearDown() override { umfPoolDestroy(pool); }

    umf_memory_provider_handle_t provider;
    umf_memory_pool_handle_t pool;
};

TEST_F(IpcNotSupported, GetIPCHandleSizeNotSupported) {
    size_t size;
    auto ret = umfPoolGetIPCHandleSize(pool, &size);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_NOT_SUPPORTED);
}

TEST_F(IpcNotSupported, OpenIPCHandleNotSupported) {
    // This data doesn't matter, as the ipc call is no-op
    std::array<uint8_t, 128> ipc_data = {};
    void *ptr;
    umf_ipc_handler_handle_t ipc_handler;
    auto ret = umfPoolGetIPCHandler(pool, &ipc_handler);
    ASSERT_EQ(ret, UMF_RESULT_SUCCESS);

    ret = umfOpenIPCHandle(ipc_handler,
                           reinterpret_cast<umf_ipc_handle_t>(&ipc_data), &ptr);
    EXPECT_EQ(ret, UMF_RESULT_ERROR_NOT_SUPPORTED);
}
