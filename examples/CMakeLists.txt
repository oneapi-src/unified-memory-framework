# Copyright (C) 2024 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# basic example
add_subdirectory(basic)

# gpu_shared_memory example
if(UMF_BUILD_GPU_EXAMPLES
   AND UMF_BUILD_LIBUMF_POOL_DISJOINT
   AND UMF_BUILD_LEVEL_ZERO_PROVIDER)
    add_subdirectory(gpu_shared_memory)
else()
    message(
        STATUS
            "GPU shared memory example requires UMF_BUILD_GPU_EXAMPLES, "
            "UMF_BUILD_LEVEL_ZERO_PROVIDER and UMF_BUILD_LIBUMF_POOL_DISJOINT "
            "to be turned ON - skipping")
endif()

# ipc_level_zero example TODO: it looks like there is some problem with IPC
# implementation in Level Zero on windows
if(UMF_BUILD_GPU_EXAMPLES
   AND UMF_BUILD_LIBUMF_POOL_DISJOINT
   AND UMF_BUILD_LEVEL_ZERO_PROVIDER
   AND LINUX)
    add_subdirectory(ipc_level_zero)
else()
    message(
        STATUS
            "IPC Level 0 example requires UMF_BUILD_GPU_EXAMPLES, UMF_BUILD_LEVEL_ZERO_PROVIDER and UMF_BUILD_LIBUMF_POOL_DISJOINT to be turned ON - skipping"
    )
endif()

if(LINUX)
    add_subdirectory(ipc_ipcapi)
else()
    message(
        STATUS
            "IPC examples with UMF pool API are supported on Linux only - skipping"
    )
endif()
