/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#ifndef UMF_TEST_POOL_HPP
#define UMF_TEST_POOL_HPP 1

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#include <stdlib.h>
#endif

#include <umf/base.h>
#include <umf/memory_provider.h>

#include "base.hpp"
#include "cpp_helpers.hpp"
#include "provider.hpp"

namespace umf_test {

umf_memory_pool_handle_t
createPoolChecked(umf_memory_pool_ops_t *ops,
                  umf_memory_provider_handle_t hProvider, void *params,
                  umf_pool_create_flags_t flags = 0) {
    umf_memory_pool_handle_t hPool;
    auto ret = umfPoolCreate(ops, hProvider, params, flags, &hPool);
    EXPECT_EQ(ret, UMF_RESULT_SUCCESS);
    return hPool;
}

auto wrapPoolUnique(umf_memory_pool_handle_t hPool) {
    return umf::pool_unique_handle_t(hPool, &umfPoolDestroy);
}

bool isReallocSupported(umf_memory_pool_handle_t hPool) {
    static constexpr size_t allocSize = 8;
    bool supported = false;
    auto *ptr = umfPoolMalloc(hPool, allocSize);
    memset(ptr, 0, allocSize);
    auto *new_ptr = umfPoolRealloc(hPool, ptr, allocSize * 2);

    if (new_ptr) {
        supported = true;
        umfPoolFree(hPool, new_ptr);
    } else if (umfPoolGetLastAllocationError(hPool) ==
               UMF_RESULT_ERROR_NOT_SUPPORTED) {
        umfPoolFree(hPool, ptr);
        supported = false;
    } else {
        umfPoolFree(hPool, new_ptr);
        throw std::runtime_error("realloc failed with unexpected error");
    }

    return supported;
}

bool isCallocSupported(umf_memory_pool_handle_t hPool) {
    static constexpr size_t num = 8;
    static constexpr size_t size = sizeof(int);
    bool supported = false;
    auto *ptr = umfPoolCalloc(hPool, num, size);

    if (ptr) {
        supported = true;
        umfPoolFree(hPool, ptr);
    } else if (umfPoolGetLastAllocationError(hPool) ==
               UMF_RESULT_ERROR_NOT_SUPPORTED) {
        supported = false;
    } else {
        umfPoolFree(hPool, ptr);
        throw std::runtime_error("calloc failed with unexpected error");
    }

    return supported;
}

bool isAlignedAllocSupported(umf_memory_pool_handle_t hPool) {
    static constexpr size_t allocSize = 8;
    static constexpr size_t alignment = 8;
    auto *ptr = umfPoolAlignedMalloc(hPool, allocSize, alignment);

    if (ptr) {
        umfPoolFree(hPool, ptr);
        return true;
    } else if (umfPoolGetLastAllocationError(hPool) ==
               UMF_RESULT_ERROR_NOT_SUPPORTED) {
        return false;
    } else {
        throw std::runtime_error("AlignedMalloc failed with unexpected error");
    }
}

typedef struct pool_base_t {
    umf_result_t initialize(umf_memory_provider_handle_t) noexcept {
        return UMF_RESULT_SUCCESS;
    };
    void *malloc([[maybe_unused]] size_t size) noexcept { return nullptr; }
    void *calloc(size_t, size_t) noexcept { return nullptr; }
    void *realloc(void *, size_t) noexcept { return nullptr; }
    void *aligned_malloc(size_t, size_t) noexcept { return nullptr; }
    size_t malloc_usable_size(void *) noexcept { return 0; }
    umf_result_t free(void *) noexcept { return UMF_RESULT_SUCCESS; }
    umf_result_t get_last_allocation_error() noexcept {
        return UMF_RESULT_SUCCESS;
    }
} pool_base_t;

struct malloc_pool : public pool_base_t {
    void *malloc(size_t size) noexcept { return ::malloc(size); }
    void *calloc(size_t num, size_t size) noexcept {
        return ::calloc(num, size);
    }
    void *realloc(void *ptr, size_t size) noexcept {
        return ::realloc(ptr, size);
    }
    void *aligned_malloc(size_t size, size_t alignment) noexcept {
#ifdef _WIN32
        (void)size;      // unused
        (void)alignment; // unused

        // we could use _aligned_malloc but it requires using _aligned_free...
        return nullptr;
#else
        return ::aligned_alloc(alignment, size);
#endif
    }
    size_t malloc_usable_size(void *ptr) noexcept {
#ifdef _WIN32
        return _msize(ptr);
#elif __APPLE__
        return ::malloc_size(ptr);
#else
        return ::malloc_usable_size(ptr);
#endif
    }
    umf_result_t free(void *ptr) noexcept {
        ::free(ptr);
        return UMF_RESULT_SUCCESS;
    }
};

umf_memory_pool_ops_t MALLOC_POOL_OPS =
    umf::poolMakeCOps<umf_test::malloc_pool, void>();

} // namespace umf_test

#endif /* UMF_TEST_POOL_HPP */
