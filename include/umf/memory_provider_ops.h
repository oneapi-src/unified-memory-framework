/*
 *
 * Copyright (C) 2023 Intel Corporation
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

///
/// @brief This structure comprises function pointers used by corresponding
/// umfMemoryProvider* calls. Each memory provider implementation should
/// initialize all function pointers.
///
typedef struct umf_memory_provider_ops_t {
    /// Version of the ops structure.
    /// Should be initialized using UMF_VERSION_CURRENT.
    uint32_t version;

    ///
    /// @brief Initializes memory provider.
    /// @param params provider-specific params
    /// @param provider returns pointer to the provider
    /// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
    ///
    umf_result_t (*initialize)(void *params, void **provider);

    ///
    /// @brief Finalizes memory provider.
    /// @param provider provider to finalize
    ///
    void (*finalize)(void *provider);

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
    ///
    void (*get_last_native_error)(void *provider, const char **ppMessage,
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
    umf_result_t (*get_min_page_size)(void *provider, void *ptr,
                                      size_t *pageSize);

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
    umf_result_t (*purge_lazy)(void *provider, void *ptr, size_t size);

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
    umf_result_t (*purge_force)(void *provider, void *ptr, size_t size);

    ///
    /// @brief Retrieve name of a given memory \p provider.
    /// @param provider pointer to the memory provider
    /// @return pointer to a string containing the name of the \p provider
    ///
    const char *(*get_name)(void *provider);

    umf_result_t (*allocation_split)(void *provider, void *ptr,
                                     size_t totalSize, size_t leftSize);
    umf_result_t (*allocation_merge)(void *provider, void *leftPtr,
                                     void *rightPtr, size_t totalSize);
} umf_memory_provider_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* #ifndef UMF_MEMORY_PROVIDER_OPS_H */
