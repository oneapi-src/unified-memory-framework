/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_IPC_H
#define UMF_IPC_H 1

#include <umf/base.h>
#include <umf/memory_pool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umf_ipc_data_t *umf_ipc_handle_t;
typedef struct umf_ipc_handler *umf_ipc_handler_t;
typedef const struct umf_ipc_handler *umf_const_ipc_handler_t;
///
/// @brief Returns the size of IPC handles for the specified pool.
/// @param hPool [in] Pool handle
/// @param size [out] size of IPC handle in bytes.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t umfPoolGetIPCHandleSize(umf_memory_pool_handle_t hPool,
                                     size_t *size);

///
/// @brief Creates an IPC handle for the specified UMF allocation.
/// @param ptr pointer to the allocated memory.
/// @param ipcHandle [out] returned IPC handle.
/// @param size [out] size of IPC handle in bytes.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t umfGetIPCHandle(const void *ptr, umf_ipc_handle_t *ipcHandle,
                             size_t *size);

///
/// @brief Release IPC handle retrieved by umfGetIPCHandle.
/// @param ipcHandle IPC handle.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t umfPutIPCHandle(umf_ipc_handle_t ipcHandle);

///
/// @bries Retrivies an IPC handler which is used to open IPC handles.
/// @param hpool [in] Pool handle.
/// @param ipcHandler [out] IPC handler.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t umfGetIPCHandler(umf_memory_pool_handle_t hpool,
                              umf_const_ipc_handler_t *ipcHandler);

///
/// @brief Creates an IPC handler, which is used to open IPC handles.
/// @param ops [in] instance of umf_memory_provider_ops_t.
/// @param params [in] pointer to provider specific parameters. This is the same stucture that is used to create a memory provider. But some fileds may be ignored. See your memory provider documentation for details.
/// @param ipcHandler [out] handle to the newly created IPC handler.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
/// @details this function is should be used if user only want to open IPC handles,
///          and do not need a memory pool, to allocate memory on client side.
umf_result_t umfCreateIPCHandler(const umf_memory_provider_ops_t *ops,
                                 void *params, umf_ipc_handler_t *ipcHandler);
///
/// @brief Open IPC handle retrieved by umfGetIPCHandle.
/// @param handler [in] IPC handler.
/// @param ipcHandle [in] IPC handle.
/// @param ptr [out] pointer to the memory in the current process.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t umfOpenIPCHandle(umf_const_ipc_handler_t handler,
                              umf_ipc_handle_t ipcHandle, void **ptr);

///
/// @brief Close IPC handle.
/// @param ptr [in] pointer to the memory.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t umfCloseIPCHandle(void *ptr);

///
/// @brief Destroys IPC handler, created by umfCreateIPCHandler.
/// @param handler [in] IPC handler.
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
umf_result_t umfDestroyIPCHandler(umf_ipc_handler_t handler);

#ifdef __cplusplus
}
#endif

#endif /* UMF_IPC_H */
