/*
 *
 * Copyright (C) 2023 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_MEMSPACE_NUMA_H
#define UMF_MEMSPACE_NUMA_H 1

#include <umf/base.h>
#include <umf/memspace.h>

#ifdef __cplusplus
extern "C" {
#endif

///
/// \brief Creates new memspace from array of NUMA node ids.
/// \param nodeIds array of NUMA node ids
/// \param numIds size of the array
/// \param hMemspace [out] handle to the newly created memspace
/// \return UMF_RESULT_SUCCESS on success or appropriate error code on failure.
///
umf_result_t umfMemspaceCreateFromNumaArray(unsigned *nodeIds, unsigned numIds,
                                            umf_memspace_handle_t *hMemspace);

#ifdef __cplusplus
}
#endif

#endif /* UMF_MEMSPACE_NUMA_H */
