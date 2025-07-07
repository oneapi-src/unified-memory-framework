/*
 *
 * Copyright (C) 2023-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_PROVIDER_OPS_H
#define UMF_MEMORY_PROVIDER_OPS_H 1

#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Version of the Memory Provider ops structure.
/// NOTE: This is equal to the latest UMF version, in which the ops structure
/// has been modified.
#define UMF_PROVIDER_OPS_VERSION_CURRENT UMF_MAKE_VERSION(1, 0)

///
/// @brief This structure comprises function pointers used by corresponding
/// umfMemoryProvider* calls. Each memory provider implementation should
/// initialize all function pointers.
///
typedef struct umf_memory_provider_ops_t {
    /// Version of the ops structure.
    /// Should be initialized using UMF_PROVIDER_OPS_VERSION_CURRENT.
    uint32_t version;

    ///
    /// @brief Initializes memory provider.
    /// @param params provider-specific params
    /// @param provider returns pointer to the provider
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///
    umf_result_t (*initialize)(const void *params, void **provider);

    ///
    /// @brief Finalizes memory provider.
    /// @param provider provider to finalize
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///
    umf_result_t (*finalize)(void *provider);

    ///
    /// @brief Allocates \p size bytes of uninitialized storage from memory \p provider
    ///        with the specified \p alignment
    /// @param provider pointer to the memory provider
    /// @param size number of bytes to allocate
    /// @param alignment alignment of the allocation in bytes, it has to be a multiple or a divider of the minimum page size
    /// @param ptr [out] pointer to the allocated memory
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
    ///
    umf_result_t (*alloc)(void *provider, size_t size, size_t alignment,
                          void **ptr);

    ///
    /// @brief Frees the memory space pointed by \p ptr from the memory \p provider
    /// @param provider pointer to the memory provider
    /// @param ptr pointer to the allocated memory to free
    /// @param size size of the allocation
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
    ///
    umf_result_t (*free)(void *provider, void *ptr, size_t size);

    ///
    /// @brief Retrieve string representation of the underlying provider specific
    ///        result reported by the last API that returned
    ///        UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC. Allows for a provider
    ///        independent way to return a provider specific result.
    ///
    /// \details
    /// * Implementations *must* store the message and error code in thread-local
    ///   storage prior to returning UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC.
    ///
    /// * The message and error code will only be valid if a previously
    ///   called entry-point returned UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC.
    ///
    /// * The memory pointed to by the C string returned in \p ppMessage is owned by
    ///   the adapter and *must* be null terminated.
    ///
    /// * The application *may* call this function from simultaneous threads.
    ///
    /// * The implementation of this function *should* be lock-free.
    /// @param provider pointer to the memory provider
    /// @param ppMessage [out] pointer to a string containing provider specific
    ///        result in string representation
    /// @param pError [out] pointer to an integer where the adapter specific error code will be stored
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///
    umf_result_t (*get_last_native_error)(void *provider,
                                          const char **ppMessage,
                                          int32_t *pError);

    ///
    /// @brief Retrieve recommended page size for a given allocation size.
    /// @param provider pointer to the memory provider
    /// @param size allocation size
    /// @param pageSize [out] pointer to the recommended page size
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///
    umf_result_t (*get_recommended_page_size)(void *provider, size_t size,
                                              size_t *pageSize);

    ///
    /// @brief Retrieve minimum possible page size used by memory region referenced by a given \p ptr
    ///        or minimum possible page size that can be used by the \p provider if \p ptr is NULL.
    /// @param provider pointer to the memory provider
    /// @param ptr [optional] pointer to memory allocated by the memory \p provider
    /// @param pageSize [out] pointer to the minimum possible page size
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///
    umf_result_t (*get_min_page_size)(void *provider, const void *ptr,
                                      size_t *pageSize);

    ///
    /// @brief Retrieve name of a given memory \p provider.
    /// @param provider pointer to the memory provider
    /// @param name [out] pointer to a string containing the name of the \p provider
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///
    umf_result_t (*get_name)(void *provider, const char **name);

    ///
    /// Following functions, with ext prefix, are optional and memory provider implementation
    /// can keep them NULL.
    ///

    ///
    /// @brief Discard physical pages within the virtual memory mapping associated at the given addr
    ///        and \p size. This call is asynchronous and may delay purging the pages indefinitely.
    /// @param provider pointer to the memory provider
    /// @param ptr beginning of the virtual memory range
    /// @param size size of the virtual memory range
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///         UMF_RESULT_ERROR_INVALID_ALIGNMENT if ptr or size is not page-aligned.
    ///         UMF_RESULT_ERROR_NOT_SUPPORTED if operation is not supported by this provider.
    ///
    umf_result_t (*ext_purge_lazy)(void *provider, void *ptr, size_t size);

    ///
    /// @brief Discard physical pages within the virtual memory mapping associated at the given addr and \p size.
    ///        This call is synchronous and if it succeeds, pages are guaranteed to be zero-filled on the next access.
    /// @param provider pointer to the memory provider
    /// @param ptr beginning of the virtual memory range
    /// @param size size of the virtual memory range
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
    ///         UMF_RESULT_ERROR_INVALID_ALIGNMENT if ptr or size is not page-aligned.
    ///         UMF_RESULT_ERROR_NOT_SUPPORTED if operation is not supported by this provider.
    ///
    umf_result_t (*ext_purge_force)(void *provider, void *ptr, size_t size);

    ///
    /// @brief Merges two coarse grain allocations into a single allocation that
    ///        can be managed (freed) as a whole.
    ///        allocation_split and allocation_merge should be both set or both NULL.
    ///        allocation_merge should NOT be called concurrently with allocation_split()
    ///        with the same pointer.
    /// @param hProvider handle to the memory provider
    /// @param lowPtr pointer to the first allocation
    /// @param highPtr pointer to the second allocation (should be > lowPtr)
    /// @param totalSize size of a new merged allocation. Should be equal
    ///        to the sum of sizes of allocations beginning at lowPtr and highPtr
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
    ///
    umf_result_t (*ext_allocation_merge)(void *hProvider, void *lowPtr,
                                         void *highPtr, size_t totalSize);

    ///
    /// @brief Splits a coarse grain allocation into 2 adjacent allocations that
    ///        can be managed (freed) separately.
    ///        allocation_split and allocation_merge should be both set or both NULL.
    ///        allocation_split should NOT be called concurrently with allocation_merge()
    ///        with the same pointer.
    /// @param hProvider handle to the memory provider
    /// @param ptr pointer to the beginning of the allocation
    /// @param totalSize total size of the allocation to be split
    /// @param firstSize size of the first new allocation, second allocation
    //         has a size equal to totalSize - firstSize
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
    ///
    umf_result_t (*ext_allocation_split)(void *hProvider, void *ptr,
                                         size_t totalSize, size_t firstSize);
    /// @brief Retrieve the size of opaque data structure required to store IPC data.
    /// \details
    /// * If provider supports IPC, all following functions pointers:
    ///   ext_get_ipc_handle_size, ext_get_ipc_handle, ext_put_ipc_handle, ext_open_ipc_handle, ext_close_ipc_handle,
    ///   must either be all set or all NULL.
    /// @param provider pointer to the memory provider.
    /// @param size [out] pointer to the size.
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///         UMF_RESULT_ERROR_NOT_SUPPORTED if IPC functionality is not supported by this provider.
    umf_result_t (*ext_get_ipc_handle_size)(void *provider, size_t *size);

    ///
    /// @brief Retrieve an IPC memory handle for the specified allocation.
    /// \details
    /// * If provider supports IPC, all following functions pointers:
    ///   ext_get_ipc_handle_size, ext_get_ipc_handle, ext_put_ipc_handle, ext_open_ipc_handle, ext_close_ipc_handle,
    ///   must either be all set or all NULL.
    /// @param provider pointer to the memory provider.
    /// @param ptr beginning of the virtual memory range.
    /// @param size size of the memory address range.
    /// @param providerIpcData [out] pointer to the preallocated opaque data structure to store IPC handle.
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///         UMF_RESULT_ERROR_INVALID_ARGUMENT if ptr was not allocated by this provider.
    ///         UMF_RESULT_ERROR_NOT_SUPPORTED if IPC functionality is not supported by this provider.
    umf_result_t (*ext_get_ipc_handle)(void *provider, const void *ptr,
                                       size_t size, void *providerIpcData);

    ///
    /// @brief Release IPC handle retrieved with get_ipc_handle function.
    /// \details
    /// * If provider supports IPC, all following functions pointers:
    ///   ext_get_ipc_handle_size, ext_get_ipc_handle, ext_put_ipc_handle, ext_open_ipc_handle, ext_close_ipc_handle,
    ///   must either be all set or all NULL.
    /// @param provider pointer to the memory provider.
    /// @param providerIpcData pointer to the IPC opaque data structure.
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///         UMF_RESULT_ERROR_INVALID_ARGUMENT if providerIpcData was not created by this provider.
    ///         UMF_RESULT_ERROR_NOT_SUPPORTED if IPC functionality is not supported by this provider.
    umf_result_t (*ext_put_ipc_handle)(void *provider, void *providerIpcData);

    ///
    /// @brief Open IPC handle.
    /// \details
    /// * If provider supports IPC, all following functions pointers:
    ///   ext_get_ipc_handle_size, ext_get_ipc_handle, ext_put_ipc_handle, ext_open_ipc_handle, ext_close_ipc_handle,
    ///   must either be all set or all NULL.
    /// @param provider pointer to the memory provider.
    /// @param providerIpcData pointer to the IPC opaque data structure.
    /// @param ptr [out] pointer to the memory to be used in the current process.
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///         UMF_RESULT_ERROR_INVALID_ARGUMENT if providerIpcData cannot be handled by the provider.
    ///         UMF_RESULT_ERROR_NOT_SUPPORTED if IPC functionality is not supported by this provider.
    umf_result_t (*ext_open_ipc_handle)(void *provider, void *providerIpcData,
                                        void **ptr);
    ///
    /// @brief Closes an IPC memory handle.
    /// \details
    /// * If provider supports IPC, all following functions pointers:
    ///   ext_get_ipc_handle_size, ext_get_ipc_handle, ext_put_ipc_handle, ext_open_ipc_handle, ext_close_ipc_handle,
    ///   must either be all set or all NULL.
    /// @param provider pointer to the memory provider.
    /// @param ptr pointer to the memory retrieved with open_ipc_handle function.
    /// @param size size of the memory address range.
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///         UMF_RESULT_ERROR_INVALID_ARGUMENT if invalid \p ptr is passed.
    ///         UMF_RESULT_ERROR_NOT_SUPPORTED if IPC functionality is not supported by this provider.
    umf_result_t (*ext_close_ipc_handle)(void *provider, void *ptr,
                                         size_t size);

    ///
    /// @brief Control operation for the memory provider.
    ///        The function is used to perform various control operations
    ///        on the memory provider.
    /// \details
    /// * This API is experimental and may change in future releases.
    ///   Backward compatibility is not guaranteed.
    ///
    /// @param provider handle to the memory provider.
    /// @param operationType type of the operation to be performed.
    /// @param name name associated with the operation.
    /// @param arg argument for the operation.
    /// @param size size of the argument [optional - check name requirements]
    /// @param queryType type of the query to be performed.
    ///
    /// @return umf_result_t result of the control operation.
    ///
    umf_result_t (*ext_ctl)(void *provider, int operationType, const char *name,
                            void *arg, size_t size,
                            umf_ctl_query_type_t queryType);

} umf_memory_provider_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* #ifndef UMF_MEMORY_PROVIDER_OPS_H */
