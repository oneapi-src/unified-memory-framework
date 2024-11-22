/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright 2018-2020, Intel Corporation */

/*
 * ctl_debug.h -- definitions for CTL test
 */
#ifndef LIBPMEMOBJ_CTL_DEBUG_H
#define LIBPMEMOBJ_CTL_DEBUG_H 1

#include "ctl.h"

#ifdef __cplusplus
extern "C" {
#endif

void debug_ctl_register(struct ctl *ctl);
struct ctl *get_debug_ctl(void);
void initialize_debug_ctl(void);
void deinitialize_debug_ctl(void);

#ifdef __cplusplus
}
#endif

#endif
