/*
 *
 * Copyright (C) 2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <windows.h>

#include <processenv.h>
#include <processthreadsapi.h>

#include "utils_common.h"
#include "utils_concurrency.h"

#define BUFFER_SIZE 1024

static UTIL_ONCE_FLAG Page_size_is_initialized = UTIL_ONCE_FLAG_INIT;
static size_t Page_size;

static void _util_get_page_size(void) {
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    Page_size = SystemInfo.dwPageSize;
}

size_t util_get_page_size(void) {
    util_init_once(&Page_size_is_initialized, _util_get_page_size);
    return Page_size;
}

int utils_getpid(void) { return GetCurrentProcessId(); }

int utils_gettid(void) { return GetCurrentThreadId(); }

int utils_close_fd(int fd) {
    (void)fd; // unused
    return -1;
}

umf_result_t utils_duplicate_fd(int pid, int fd_in, int *fd_out) {
    (void)pid;    // unused
    (void)fd_in;  // unused
    (void)fd_out; // unused
    return UMF_RESULT_ERROR_NOT_SUPPORTED;
}

int util_is_symlink(const char *path) {
    DWORD attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        // Handle error, could not get file attributes
        return -1;
    }

    // Check if the file is a reparse point
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        // It's a reparse point, which could be a symlink or a junction

        // Open the file or directory with CreateFile
        HANDLE fileHandle = CreateFileA(
            path, 0, 0, NULL, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            // Handle error, could not open file
            return -1;
        }

        // Allocate a buffer for the reparse data
        BYTE buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
        DWORD returnedLength;

        // Query the reparse data
        BOOL result = DeviceIoControl(
            fileHandle, FSCTL_GET_REPARSE_POINT, NULL, 0, buffer,
            MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &returnedLength, NULL);
        if (!result) {
            // Handle error, could not read reparse point data
            CloseHandle(fileHandle);
            return -1;
        }

        // Cast the buffer to a REPARSE_DATA_BUFFER pointer
        REPARSE_DATA_BUFFER *reparseData = (REPARSE_DATA_BUFFER *)buffer;

        // Check the reparse tag to see if it's a symbolic link
        if (reparseData->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
            // It's a symbolic link
            CloseHandle(fileHandle);
            return 1;
        } else {
            // It's not a symbolic link
            CloseHandle(fileHandle);
            return 0;
        }
    } else {
        // It's not a reparse point, so it's not a symbolic link
        return 0;
    }
}
