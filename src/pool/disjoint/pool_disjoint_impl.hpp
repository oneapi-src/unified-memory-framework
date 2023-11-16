// Copyright (C) 2023 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef USM_ALLOCATOR
#define USM_ALLOCATOR

#include <atomic>
#include <memory>
#include <string>

#include "pool/pool_disjoint.h"
#include "umf.h"

struct umf_disjoint_pool_shared_limits {
    size_t MaxSize;
    std::atomic<size_t> TotalSize;
};

namespace usm {

class DisjointPool {
  public:
    class AllocImpl;
    using Config = umf_disjoint_pool_params;

    umf_result_t initialize(umf_memory_provider_handle_t provider,
                            Config parameters);
    void *malloc(size_t size);
    void *calloc(size_t, size_t);
    void *realloc(void *, size_t);
    void *aligned_malloc(size_t size, size_t alignment);
    size_t malloc_usable_size(void *);
    enum umf_result_t free(void *ptr);
    enum umf_result_t get_last_allocation_error();

    DisjointPool();
    ~DisjointPool();

  private:
    std::unique_ptr<AllocImpl> impl;
};

} // namespace usm

#endif
