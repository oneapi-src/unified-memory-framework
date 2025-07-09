/*
 *
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_CTL_H
#define UMF_CTL_H 1

#include <umf/base.h>

#ifdef __cplusplus
extern "C" {
#endif

///
/// @brief Get value of a specified attribute at the given name.
/// @param name name of an attribute to be retrieved
/// @param arg [out] pointer to the variable where the value will be stored
/// @param size size of the value, depends on the context
/// @param ... additional arguments that can be passed to the callback
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlGet(const char *name, void *arg, size_t size, ...);

///
/// @brief Set value of a specified attribute at the given name.
/// @param name name of an attribute to be set
/// @param arg [in] pointer to the value that will be set
/// @param size [in] size of the value, depends on the context
/// @param ... additional arguments that can be passed to the callback
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlSet(const char *name, void *arg, size_t size, ...);

///
/// @brief Execute callback related with the specified attribute.
/// @param name name of an attribute to be executed
/// @param arg [in/out] pointer to the value, can be used as an input or output
/// @param size [in] size of the value, depends on the context
/// @param ... additional arguments that can be passed to the callback
/// @return UMF_RESULT_SUCCESS on success or UMF_RESULT_ERROR_UNKNOWN on failure.
///
umf_result_t umfCtlExec(const char *name, void *arg, size_t size, ...);

#ifdef __cplusplus
}
#endif

#endif /* UMF_CTL_H */
