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
} libcu_ops;

#if USE_DLOPEN
struct DlHandleCloser {
    void operator()(void *dlHandle) {
        if (dlHandle) {
            utils_close_library(dlHandle);
        }
    }
};

std::unique_ptr<void, DlHandleCloser> cuDlHandle = nullptr;
int InitCUDAOps() {
#ifdef _WIN32
    const char *lib_name = "cudart.dll";
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

    return 0;
}
#endif // USE_DLOPEN

static int init_cuda_lib(void) {
    CUresult result = libcu_ops.cuInit(0);
    if (result != CUDA_SUCCESS) {
        return -1;
    }
    return 0;
}

int cuda_fill(CUcontext context, CUdevice device, void *ptr, size_t size,
              const void *pattern, size_t pattern_size) {

    (void)context;
    (void)device;
    (void)pattern_size;

    // TODO support patterns > sizeof(unsigned int)
    if (pattern_size > sizeof(unsigned int)) {
        fprintf(stderr, "patterns > sizeof(unsigned int) are unsupported!\n");
        return -1;
    }

    int ret = 0;
    CUresult res =
        libcu_ops.cuMemsetD32((CUdeviceptr)ptr, *(unsigned int *)pattern,
                              size / sizeof(unsigned int));
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuMemsetD32() failed!\n");
        return -1;
    }

    return ret;
}

int cuda_copy(CUcontext context, CUdevice device, void *dst_ptr, void *src_ptr,
              size_t size) {
    (void)context;
    (void)device;

    int ret = 0;
    CUresult res =
        libcu_ops.cuMemcpy((CUdeviceptr)dst_ptr, (CUdeviceptr)src_ptr, size);
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuMemcpy() failed!\n");
        return -1;
    }

    res = libcu_ops.cuStreamSynchronize(0);
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuStreamSynchronize() failed!\n");
        return -1;
    }

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

cuda_memory_provider_params_t
create_cuda_prov_params(umf_usm_memory_type_t memory_type) {
    cuda_memory_provider_params_t params = {NULL, 0, UMF_MEMORY_TYPE_UNKNOWN};
    int ret = -1;

    ret = init_cuda();
    if (ret != 0) {
        // Return empty params. Test will be skipped.
        return params;
    }

    // Get the first CUDA device
    CUdevice cuDevice = -1;
    CUresult res = libcu_ops.cuDeviceGet(&cuDevice, 0);
    if (res != CUDA_SUCCESS || cuDevice < 0) {
        // Return empty params. Test will be skipped.
        return params;
    }

    // Create a CUDA context
    CUcontext cuContext = nullptr;
    res = libcu_ops.cuCtxCreate(&cuContext, 0, cuDevice);
    if (res != CUDA_SUCCESS || cuContext == nullptr) {
        // Return empty params. Test will be skipped.
        return params;
    }

    params.cuda_context_handle = cuContext;
    params.cuda_device_handle = cuDevice;
    params.memory_type = memory_type;

    return params;
}

int destroy_context(CUcontext context) {
    CUresult res = libcu_ops.cuCtxDestroy(context);
    if (res != CUDA_SUCCESS) {
        fprintf(stderr, "cuCtxDestroy() failed!\n");
        return -1;
    }

    return 0;
}
