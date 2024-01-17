/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMORY_PROVIDER_H
#define UMF_MEMORY_PROVIDER_H 1

#include <umf/base.h>
#include <umf/memory_provider_ops.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief A struct containing memory provider specific set of functions
typedef struct umf_memory_provider_t *umf_memory_provider_handle_t;

///
/// @brief Creates new memory provider.
/// @param ops instance of umf_memory_provider_ops_t
/// @param params pointer to provider-specific parameters
/// @param hProvider [out] pointer to the newly created memory provider
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
///
UMF_EXPORT umf_result_t
umfMemoryProviderCreate(const umf_memory_provider_ops_t *ops, void *params,
                        umf_memory_provider_handle_t *hProvider);

///
/// @brief Destroys memory provider.
/// @param hProvider handle to the memory provider
///
UMF_EXPORT void
umfMemoryProviderDestroy(umf_memory_provider_handle_t hProvider);

///
/// @brief Allocates \p size bytes of uninitialized storage from memory \p hProvider
///        with the specified \p alignment
/// @param hProvider handle to the memory provider
/// @param size number of bytes to allocate
/// @param alignment alignment of the allocation in bytes, it has to be a multiple or a divider of the minimum page size
/// @param ptr [out] pointer to the allocated memory
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
///
UMF_EXPORT umf_result_t
umfMemoryProviderAlloc(umf_memory_provider_handle_t hProvider, size_t size,
                       size_t alignment, void **ptr);

///
/// @brief Frees the memory space pointed by \p ptr from the memory \p hProvider
/// @param hProvider handle to the memory provider
/// @param ptr pointer to the allocated memory to free
/// @param size size of the allocation
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
///
UMF_EXPORT umf_result_t umfMemoryProviderFree(
    umf_memory_provider_handle_t hProvider, void *ptr, size_t size);

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
/// @param hProvider handle to the memory provider
/// @param ppMessage [out] pointer to a string containing provider specific
///        result in string representation
/// @param pError [out] pointer to an integer where the adapter specific error code will be stored
///
UMF_EXPORT void
umfMemoryProviderGetLastNativeError(umf_memory_provider_handle_t hProvider,
                                    const char **ppMessage, int32_t *pError);

///
/// @brief Retrieve recommended page size for a given allocation size.
/// @param hProvider handle to the memory provider
/// @param size allocation size
/// @param pageSize [out] pointer to the recommended page size
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
///
UMF_EXPORT umf_result_t umfMemoryProviderGetRecommendedPageSize(
    umf_memory_provider_handle_t hProvider, size_t size, size_t *pageSize);

///
/// @brief Retrieve minimum possible page size used by memory region referenced by a given \p ptr
///        or minimum possible page size that can be used by the \p hProvider if \p ptr is NULL.
/// @param hProvider handle to the memory provider
/// @param ptr [optional] pointer to memory allocated by the memory \p hProvider
/// @param pageSize [out] pointer to the minimum possible page size
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
///
UMF_EXPORT umf_result_t umfMemoryProviderGetMinPageSize(
    umf_memory_provider_handle_t hProvider, void *ptr, size_t *pageSize);

///
/// @brief Discard physical pages within the virtual memory mapping associated at the given addr
///        and \p size. This call is asynchronous and may delay purging the pages indefinitely.
/// @param hProvider handle to the memory provider
/// @param ptr beginning of the virtual memory range
/// @param size size of the virtual memory range
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
///         UMF_RESULT_ERROR_INVALID_ALIGNMENT if ptr or size is not page-aligned.
///         UMF_RESULT_ERROR_NOT_SUPPORTED if operation is not supported by this provider.
///
UMF_EXPORT umf_result_t umfMemoryProviderPurgeLazy(
    umf_memory_provider_handle_t hProvider, void *ptr, size_t size);

///
/// @brief Discard physical pages within the virtual memory mapping associated at the given addr and \p size.
///        This call is synchronous and if it succeeds, pages are guaranteed to be zero-filled on the next access.
/// @param hProvider handle to the memory provider
/// @param ptr beginning of the virtual memory range
/// @param size size of the virtual memory range
/// @return UMF_RESULT_SUCCESS on success or appropriate error code on failure
///         UMF_RESULT_ERROR_INVALID_ALIGNMENT if ptr or size is not page-aligned.
///         UMF_RESULT_ERROR_NOT_SUPPORTED if operation is not supported by this provider.
///
UMF_EXPORT umf_result_t umfMemoryProviderPurgeForce(
    umf_memory_provider_handle_t hProvider, void *ptr, size_t size);

///
/// @brief Retrieve name of a given memory \p hProvider.
/// @param hProvider handle to the memory provider
/// @return pointer to a string containing the name of the \p hProvider
///
UMF_EXPORT const char *
umfMemoryProviderGetName(umf_memory_provider_handle_t hProvider);

///
/// @brief Retrieve handle to the last memory provider that returned status other
///        than UMF_RESULT_SUCCESS on the calling thread.
///
/// \details Handle to the memory provider is stored in  the thread local
///          storage. The handle is updated every time a memory provider
///          returns status other than UMF_RESULT_SUCCESS.
///
/// @return Handle to the memory provider
///
UMF_EXPORT umf_memory_provider_handle_t umfGetLastFailedMemoryProvider(void);

UMF_EXPORT umf_result_t
umfMemoryProviderAllocationSplit(umf_memory_provider_handle_t hProvider,
                                 void *ptr, size_t totalSize, size_t leftSize);
UMF_EXPORT umf_result_t umfMemoryProviderAllocationMerge(
    umf_memory_provider_handle_t hProvider, void *leftPtr, void *rightPtr,
    size_t totalSize);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMORY_PROVIDER_H */
