/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_TOPOLOGY_H
#define UMF_TOPOLOGY_H 1

#include "umf_hwloc.h"

#ifdef __cplusplus
extern "C" {
#endif

hwloc_topology_t umfGetTopology(void);
void umfDestroyTopology(void);

#ifdef __cplusplus
}
#endif

#endif /* UMF_TOPOLOGY_H */
