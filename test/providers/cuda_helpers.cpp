/*
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <assert.h>
#include <memory>
#include <stdlib.h>

#include "cuda_helpers.h"
#include "utils_concurrency.h"
#include "utils_load_library.h"

struct libcu_ops {
    CUresult (*cuInit)(unsigned int flags);
    CUresult (*cuCtxCreate)(CUcontext *pctx, unsigned int flags, CUdevice dev);
    CUresult (*cuCtxDestroy)(CUcontext ctx);
    CUresult (*cuCtxGetCurrent)(CUcontext *pctx);
    CUresult (*cuCtxSetCurrent)(CUcontext ctx);
    CUresult (*cuDeviceGet)(CUdevice *device, int ordinal);
    CUresult (*cuMemAlloc)(CUdeviceptr *dptr, size_t size);
    CUresult (*cuMemFree)(CUdeviceptr dptr);
    CUresult (*cuMemAllocHost)(void **pp, size_t size);
    CUresult (*cuMemAllocManaged)(CUdeviceptr *dptr, size_t bytesize,
                                  unsigned int flags);
    CUresult (*cuMemFreeHost)(void *p);
    CUresult (*cuMemsetD32)(CUdeviceptr dstDevice, unsigned int pattern,
                            size_t size);
    CUresult (*cuMemcpy)(CUdeviceptr dst, CUdeviceptr src, size_t size);
    CUresult (*cuPointerGetAttribute)(void *data, CUpointer_attribute attribute,
                                      CUdeviceptr ptr);
    CUresult (*cuPointerGetAttributes)(unsigned int numAttributes,
                                       CUpointer_attribute *attributes,
                                       void **data, CUdeviceptr ptr);
    CUresult (*cuStreamSynchronize)(CUstream hStream);
    CUresult (*cuCtxSynchronize)(void);
} libcu_ops;

#if USE_DLOPEN
// Generic no-op stub function for all callbacks
template <typename... Args> CUresult noop_stub(Args &&...) {
    return CUDA_SUCCESS; // Always return CUDA_SUCCESS
}

struct DlHandleCloser {
    void operator()(void *dlHandle) {
        if (dlHandle) {
            libcu_ops.cuInit = [](auto... args) { return noop_stub(args...); };
            libcu_ops.cuCtxCreate = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuCtxDestroy = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuCtxGetCurrent = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuCtxSetCurrent = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuDeviceGet = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuMemAlloc = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuMemFree = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuMemAllocHost = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuMemAllocManaged = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuMemFreeHost = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuMemsetD32 = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuMemcpy = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuPointerGetAttribute = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuPointerGetAttributes = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuStreamSynchronize = [](auto... args) {
                return noop_stub(args...);
            };
            libcu_ops.cuCtxSynchronize = [](auto... args) {
                return noop_stub(args...);
            };
            utils_close_library(dlHandle);
        }
    }
};

std::unique_ptr<void, DlHandleCloser> cuDlHandle = nullptr;
int InitCUDAOps() {
#ifdef _WIN32
    const char *lib_name = "nvcuda.dll";
#else
    const char *lib_name = "libcuda.so";
#endif
    // CUDA symbols
    // NOTE that we use UMF_UTIL_OPEN_LIBRARY_GLOBAL which add all loaded
    // symbols to the global symbol table.
    cuDlHandle = std::unique_ptr<void, DlHandleCloser>(
        utils_open_library(lib_name, UMF_UTIL_OPEN_LIBRARY_GLOBAL));

    // NOTE: some symbols defined in the lib have _vX postfixes - this is
    // important to load the proper version of functions
    *(void **)&libcu_ops.cuInit =
        utils_get_symbol_addr(cuDlHandle.get(), "cuInit", lib_name);
    if (libcu_ops.cuInit == nullptr) {
        fprintf(stderr, "cuInit symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuCtxCreate =
        utils_get_symbol_addr(cuDlHandle.get(), "cuCtxCreate_v2", lib_name);
    if (libcu_ops.cuCtxCreate == nullptr) {
        fprintf(stderr, "cuCtxCreate_v2 symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuCtxDestroy =
        utils_get_symbol_addr(cuDlHandle.get(), "cuCtxDestroy_v2", lib_name);
    if (libcu_ops.cuCtxDestroy == nullptr) {
        fprintf(stderr, "cuCtxDestroy symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuCtxGetCurrent =
        utils_get_symbol_addr(cuDlHandle.get(), "cuCtxGetCurrent", lib_name);
    if (libcu_ops.cuCtxGetCurrent == nullptr) {
        fprintf(stderr, "cuCtxGetCurrent symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuCtxSetCurrent =
        utils_get_symbol_addr(cuDlHandle.get(), "cuCtxSetCurrent", lib_name);
    if (libcu_ops.cuCtxSetCurrent == nullptr) {
        fprintf(stderr, "cuCtxSetCurrent symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuDeviceGet =
        utils_get_symbol_addr(cuDlHandle.get(), "cuDeviceGet", lib_name);
    if (libcu_ops.cuDeviceGet == nullptr) {
        fprintf(stderr, "cuDeviceGet symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuMemAlloc =
        utils_get_symbol_addr(cuDlHandle.get(), "cuMemAlloc_v2", lib_name);
    if (libcu_ops.cuMemAlloc == nullptr) {
        fprintf(stderr, "cuMemAlloc_v2 symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuMemFree =
        utils_get_symbol_addr(cuDlHandle.get(), "cuMemFree_v2", lib_name);
    if (libcu_ops.cuMemFree == nullptr) {
        fprintf(stderr, "cuMemFree_v2 symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuMemAllocHost =
        utils_get_symbol_addr(cuDlHandle.get(), "cuMemAllocHost_v2", lib_name);
    if (libcu_ops.cuMemAllocHost == nullptr) {
        fprintf(stderr, "cuMemAllocHost_v2 symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuMemAllocManaged =
        utils_get_symbol_addr(cuDlHandle.get(), "cuMemAllocManaged", lib_name);
    if (libcu_ops.cuMemAllocManaged == nullptr) {
        fprintf(stderr, "cuMemAllocManaged symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuMemFreeHost =
        utils_get_symbol_addr(cuDlHandle.get(), "cuMemFreeHost", lib_name);
    if (libcu_ops.cuMemFreeHost == nullptr) {
        fprintf(stderr, "cuMemFreeHost symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuMemsetD32 =
        utils_get_symbol_addr(cuDlHandle.get(), "cuMemsetD32_v2", lib_name);
    if (libcu_ops.cuMemsetD32 == nullptr) {
        fprintf(stderr, "cuMemsetD32_v2 symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuMemcpy =
        utils_get_symbol_addr(cuDlHandle.get(), "cuMemcpy", lib_name);
    if (libcu_ops.cuMemcpy == nullptr) {
        fprintf(stderr, "cuMemcpy symbol not found in %s\n", lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuPointerGetAttribute = utils_get_symbol_addr(
        cuDlHandle.get(), "cuPointerGetAttribute", lib_name);
    if (libcu_ops.cuPointerGetAttribute == nullptr) {
        fprintf(stderr, "cuPointerGetAttribute symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuPointerGetAttributes = utils_get_symbol_addr(
        cuDlHandle.get(), "cuPointerGetAttributes", lib_name);
    if (libcu_ops.cuPointerGetAttributes == nullptr) {
        fprintf(stderr, "cuPointerGetAttributes symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuStreamSynchronize = utils_get_symbol_addr(
        cuDlHandle.get(), "cuStreamSynchronize", lib_name);
    if (libcu_ops.cuStreamSynchronize == nullptr) {
        fprintf(stderr, "cuStreamSynchronize symbol not found in %s\n",
                lib_name);
        return -1;
    }
    *(void **)&libcu_ops.cuCtxSynchronize =
        utils_get_symbol_addr(cuDlHandle.get(), "cuCtxSynchronize", lib_name);
    if (libcu_ops.cuCtxSynchronize == nullptr) {
        fprintf(stderr, "cuCtxSynchronize symbol not found in %s\n", lib_name);
        return -1;
    }

    return 0;
}

#else  // USE_DLOPEN
int InitCUDAOps() {
    // CUDA is linked statically but we prepare ops structure to
    // make test code consistent
    libcu_ops.cuInit = cuInit;
    libcu_ops.cuCtxCreate = cuCtxCreate;
    libcu_ops.cuCtxDestroy = cuCtxDestroy;
    libcu_ops.cuCtxGetCurrent = cuCtxGetCurrent;
    libcu_ops.cuCtxSetCurrent = cuCtxSetCurrent;
    libcu_ops.cuDeviceGet = cuDeviceGet;
    libcu_ops.cuMemAlloc = cuMemAlloc;
    libcu_ops.cuMemAllocHost = cuMemAllocHost;
    libcu_ops.cuMemAllocManaged = cuMemAllocManaged;
    libcu_ops.cuMemFree = cuMemFree;
    libcu_ops.cuMemFreeHost = cuMemFreeHost;
    libcu_ops.cuMemsetD32 = cuMemsetD32;
    libcu_ops.cuMemcpy = cuMemcpy;
    libcu_ops.cuPointerGetAttribute = cuPointerGetAttribute;
    libcu_ops.cuPointerGetAttributes = cuPointerGetAttributes;
    libcu_ops.cuStreamSynchronize = cuStreamSynchronize;
    libcu_ops.cuCtxSynchronize = cuCtxSynchronize;

    return 0;
}
#endif // USE_DLOPEN

static CUresult set_context(CUcontext required_ctx, CUcontext *restore_ctx) {
    CUcontext current_ctx = NULL;
    CUresult cu_result = libcu_ops.cuCtxGetCurrent(&current_ctx);
    if (cu_result != CUDA_SUCCESS) {
        fprintf(stderr, "cuCtxGetCurrent() failed.\n");
        return cu_result;
    }

    *restore_ctx = current_ctx;
    if (current_ctx != required_ctx) {
        cu_result = libcu_ops.cuCtxSetCurrent(required_ctx);
        if (cu_result != CUDA_SUCCESS) {
            fprintf(stderr, "cuCtxSetCurrent() failed.\n");
        }
    }

    return cu_result;
}

static int init_cuda_lib(void) {
    CUresult result = libcu_ops.cuInit(0);
    if (result != CUDA_SUCCESS) {
        return -1;
    }
    return 0;
}

int cuda_fill(CUcontext context, CUdevice device, void *ptr, size_t size,
              const void *pattern, size_t pattern_size) {
    (void)device;
    (void)pattern_size;

    // TODO support patterns > sizeof(unsigned int)
    if (pattern_size > sizeof(unsigned int)) {
        fprintf(stderr, "patterns > sizeof(unsigned int) are unsupported!\n");
        return -1;
    }

    // set required context
    CUcontext curr_context = nullptr;
    set_context(context, &curr_context);

    int ret = 0;
    CUresult res =
        libcu_ops.cuMemsetD32((CUdeviceptr)ptr, *(unsigned int *)pattern,
                              size / sizeof(unsigned int));
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuMemsetD32(%llu, %u, %zu) failed!\n",
                (CUdeviceptr)ptr, *(unsigned int *)pattern,
                size / pattern_size);
        return -1;
    }

    res = libcu_ops.cuCtxSynchronize();
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuCtxSynchronize() failed!\n");
        return -1;
    }

    // restore context
    set_context(curr_context, &curr_context);
    return ret;
}

int cuda_copy(CUcontext context, CUdevice device, void *dst_ptr,
              const void *src_ptr, size_t size) {
    (void)device;

    // set required context
    CUcontext curr_context = nullptr;
    set_context(context, &curr_context);

    int ret = 0;
    CUresult res =
        libcu_ops.cuMemcpy((CUdeviceptr)dst_ptr, (CUdeviceptr)src_ptr, size);
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuMemcpy() failed!\n");
        return -1;
    }

    res = libcu_ops.cuCtxSynchronize();
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuCtxSynchronize() failed!\n");
        return -1;
    }

    // restore context
    set_context(curr_context, &curr_context);
    return ret;
}

umf_usm_memory_type_t get_mem_type(CUcontext context, void *ptr) {

    (void)context;

    unsigned int managed;
    unsigned int type;
    void *attrib_vals[2] = {&managed, &type};
    CUpointer_attribute attribs[2] = {CU_POINTER_ATTRIBUTE_IS_MANAGED,
                                      CU_POINTER_ATTRIBUTE_MEMORY_TYPE};

    CUresult res = libcu_ops.cuPointerGetAttributes(2, attribs, attrib_vals,
                                                    (CUdeviceptr)ptr);
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuPointerGetAttributes() failed!\n");
        return UMF_MEMORY_TYPE_UNKNOWN;
    }

    if (type == CU_MEMORYTYPE_DEVICE && managed == 0) {
        return UMF_MEMORY_TYPE_DEVICE;
    } else if (type == CU_MEMORYTYPE_DEVICE && managed == 1) {
        return UMF_MEMORY_TYPE_SHARED;
    } else if (type == CU_MEMORYTYPE_HOST) {
        return UMF_MEMORY_TYPE_HOST;
    }

    return UMF_MEMORY_TYPE_UNKNOWN;
}

CUcontext get_mem_context(void *ptr) {
    CUcontext context;
    CUresult res = libcu_ops.cuPointerGetAttribute(
        &context, CU_POINTER_ATTRIBUTE_CONTEXT, (CUdeviceptr)ptr);
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuPointerGetAttribute() failed!\n");
        return nullptr;
    }

    return context;
}

CUcontext get_current_context() {
    CUcontext context;
    CUresult res = libcu_ops.cuCtxGetCurrent(&context);
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuCtxGetCurrent() failed!\n");
        return nullptr;
    }

    return context;
}

UTIL_ONCE_FLAG cuda_init_flag;
int InitResult;
void init_cuda_once() {
    InitResult = InitCUDAOps();
    if (InitResult != 0) {
        return;
    }
    InitResult = init_cuda_lib();
}

int init_cuda() {
    utils_init_once(&cuda_init_flag, init_cuda_once);

    return InitResult;
}

int get_cuda_device(CUdevice *device) {
    CUdevice cuDevice = -1;

    int ret = init_cuda();
    if (ret != 0) {
        fprintf(stderr, "init_cuda() failed!\n");
        return ret;
    }

    CUresult res = libcu_ops.cuDeviceGet(&cuDevice, 0);
    if (res != CUDA_SUCCESS || cuDevice < 0) {
        return -1;
    }

    *device = cuDevice;
    return 0;
}

int create_context(CUdevice device, CUcontext *context) {
    CUcontext cuContext = nullptr;

    int ret = init_cuda();
    if (ret != 0) {
        fprintf(stderr, "init_cuda() failed!\n");
        return ret;
    }

    CUresult res = libcu_ops.cuCtxCreate(&cuContext, 0, device);
    if (res != CUDA_SUCCESS || cuContext == nullptr) {
        return -1;
    }

    *context = cuContext;
    return 0;
}

int destroy_context(CUcontext context) {
    CUresult res = libcu_ops.cuCtxDestroy(context);
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuCtxDestroy() failed!\n");
        return -1;
    }

    return 0;
}
