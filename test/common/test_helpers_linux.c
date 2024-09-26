// Copyright (C) 2024 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// This file contains tests for UMF pool API

#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_helpers_linux.h"

// Check if the file given by the 'path' argument was mapped with the MAP_SYNC flag:
// 1) Open and read the /proc/self/smaps file.
// 2) Look for the section of the 'path' file.
// 3) Check if the VmFlags of the 'path' file contains the "sf" flag
//    marking that the file was mapped with the MAP_SYNC flag.
bool is_mapped_with_MAP_SYNC(char *path, char *buf, size_t size_buf) {
    memset(buf, 0, size_buf);

    int fd = open("/proc/self/smaps", O_RDONLY);
    if (fd == -1) {
        return false;
    }

    // number of bytes read from the file
    ssize_t nbytes = 1;
    // string starting from the path of the smaps
    char *smaps = NULL;

    // Read the "/proc/self/smaps" file
    // until the path of the smaps is found
    // or EOF is reached.
    while (nbytes > 0 && smaps == NULL) {
        memset(buf, 0, nbytes); // erase previous data
        nbytes = read(fd, buf, size_buf);
        // look for the path of the smaps
        smaps = strstr(buf, path);
    }

    (void)close(fd);

    // String starting from the "sf" flag
    // marking that memory was mapped with the MAP_SYNC flag.
    char *sf_flag = NULL;

    if (smaps) {
        // look for the "VmFlags:" string
        char *VmFlags = strstr(smaps, "VmFlags:");
        if (VmFlags) {
            // look for the EOL
            char *eol = strstr(VmFlags, "\n");
            if (eol) {
                // End the VmFlags string at EOL.
                *eol = 0;
                // Now the VmFlags string contains only one line with all VmFlags.

                // Look for the "sf" flag in VmFlags
                // marking that memory was mapped
                // with the MAP_SYNC flag.
                sf_flag = strstr(VmFlags, "sf");
            }
        }
    }

    return (sf_flag != NULL);
}
