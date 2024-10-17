/*
 *
 * Copyright (C) 2023-2024 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <umf/base.h>
#include <umf/memory_provider.h>

#include "utils_common.h"
#include "utils_log.h"

umf_result_t
utils_translate_mem_visibility_flag(umf_memory_visibility_t in_flag,
                                    unsigned *out_flag) {
    switch (in_flag) {
    case UMF_MEM_MAP_PRIVATE:
        *out_flag = MAP_PRIVATE;
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SHARED:
        *out_flag = MAP_SHARED;
        return UMF_RESULT_SUCCESS;
    case UMF_MEM_MAP_SYNC:
        *out_flag = MAP_SYNC;
        return UMF_RESULT_SUCCESS;
    }
    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

/*
 * Map given file into memory.
 * If (flags & MAP_PRIVATE) it uses just mmap. Otherwise, if (flags & MAP_SYNC)
 * it tries to mmap with (flags | MAP_SHARED_VALIDATE | MAP_SYNC)
 * which allows flushing from the user-space. If MAP_SYNC fails and the user
 * did not specify it by himself it tries to mmap with (flags | MAP_SHARED).
 */
void *utils_mmap_file(void *hint_addr, size_t length, int prot, int flags,
                      int fd, size_t fd_offset) {
    void *addr;

    /*
     * MAP_PRIVATE and MAP_SHARED are mutually exclusive,
     * therefore mmap with MAP_PRIVATE is executed separately.
     */
    if (flags & MAP_PRIVATE) {
        addr = utils_mmap(hint_addr, length, prot, flags, fd, fd_offset);
        if (addr == MAP_FAILED) {
            LOG_PERR("mapping file with the MAP_PRIVATE flag failed");
            return NULL;
        }

        LOG_DEBUG("file mapped with the MAP_PRIVATE flag (fd=%i, offset=%zu, "
                  "length=%zu)",
                  fd, fd_offset, length);

        return addr;
    }

    errno = 0;

    if (flags & MAP_SYNC) {
        /* try to mmap with MAP_SYNC flag */
        const int sync_flags = MAP_SHARED_VALIDATE | MAP_SYNC;
        addr = utils_mmap(hint_addr, length, prot, flags | sync_flags, fd,
                          fd_offset);
        if (addr) {
            LOG_DEBUG("file mapped with the MAP_SYNC flag (fd=%i, offset=%zu, "
                      "length=%zu)",
                      fd, fd_offset, length);
            return addr;
        }

        LOG_PERR("mapping file with the MAP_SYNC flag failed");
    }

    if ((!(flags & MAP_SYNC)) || errno == EINVAL || errno == ENOTSUP ||
        errno == EOPNOTSUPP) {
        /* try to mmap with MAP_SHARED flag (without MAP_SYNC) */
        const int shared_flags = (flags & (~MAP_SYNC)) | MAP_SHARED;
        addr = utils_mmap(hint_addr, length, prot, shared_flags, fd, fd_offset);
        if (addr) {
            LOG_DEBUG("file mapped with the MAP_SHARED flag (fd=%i, "
                      "offset=%zu, length=%zu)",
                      fd, fd_offset, length);
            return addr;
        }

        LOG_PERR("mapping file with the MAP_SHARED flag failed");
    }

    return NULL;
}

int utils_get_file_size(int fd, size_t *size) {
    struct stat statbuf;
    int ret = fstat(fd, &statbuf);
    if (ret) {
        LOG_PERR("fstat(%i) failed", fd);
        return ret;
    }

    *size = statbuf.st_size;
    return 0;
}

int utils_set_file_size(int fd, size_t size) {
    errno = 0;
    int ret = ftruncate(fd, size);
    if (ret) {
        LOG_PERR("setting size %zu of a file failed", size);
    } else {
        LOG_DEBUG("set size of a file to %zu bytes", size);
    }

    return ret;
}

int utils_fallocate(int fd, long offset, long len) {
    return posix_fallocate(fd, offset, len);
}

// create a shared memory file
int utils_shm_create(const char *shm_name, size_t size) {
    if (shm_name == NULL) {
        LOG_ERR("empty name of a shared memory file");
        return -1;
    }

    (void)shm_unlink(shm_name);

    int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd == -1) {
        LOG_PERR("cannot create a shared memory file /dev/shm/%s", shm_name);
        return fd;
    }

    int ret = utils_set_file_size(fd, size);
    if (ret) {
        LOG_ERR("setting size (%zu) of a file /dev/shm/%s failed", size,
                shm_name);
        close(fd);
        (void)shm_unlink(shm_name);
        return -1;
    }

    return fd;
}

// open a shared memory file
int utils_shm_open(const char *shm_name) {
    if (shm_name == NULL) {
        LOG_ERR("empty name of a shared memory file");
        return -1;
    }

    int fd = shm_open(shm_name, O_RDWR, 0600);
    if (fd == -1) {
        LOG_PERR("cannot open a shared memory file /dev/shm/%s", shm_name);
    }

    return fd;
}

// unlink a shared memory file
int utils_shm_unlink(const char *shm_name) { return shm_unlink(shm_name); }

static int syscall_memfd_secret(void) {
    int fd = -1;
#ifdef __NR_memfd_secret
    // SYS_memfd_secret is supported since Linux 5.14
    // not using SYS_memfd_secret as SLES does not define it
    fd = syscall(__NR_memfd_secret, 0);
    if (fd == -1) {
        LOG_PERR("memfd_secret() failed");
    }
    if (fd > 0) {
        LOG_DEBUG("anonymous file descriptor created using memfd_secret()");
    }
#endif /* __NR_memfd_secret */
    return fd;
}

static int syscall_memfd_create(void) {
    int fd = -1;
#ifdef __NR_memfd_create
    // SYS_memfd_create is supported since Linux 3.17, glibc 2.27
    // not using SYS_memfd_create for consistency with syscall_memfd_secret
    fd = syscall(__NR_memfd_create, "anon_fd_name", 0);
    if (fd == -1) {
        LOG_PERR("memfd_create() failed");
    }
    if (fd > 0) {
        LOG_DEBUG("anonymous file descriptor created using memfd_create()");
    }
#endif /* __NR_memfd_create */
    return fd;
}

// create an anonymous file descriptor
int utils_create_anonymous_fd(void) {
    int fd = -1;

    if (!utils_env_var_has_str("UMF_MEM_FD_FUNC", "memfd_create")) {
        fd = syscall_memfd_secret();
        if (fd > 0) {
            return fd;
        }
    }

    // The SYS_memfd_secret syscall can fail with errno == ENOTSYS (function not implemented).
    // We should try to call the SYS_memfd_create syscall in this case.

    fd = syscall_memfd_create();

#if !(defined __NR_memfd_secret) && !(defined __NR_memfd_create)
    if (fd == -1) {
        LOG_ERR("cannot create an anonymous file descriptor - neither "
                "memfd_secret() nor memfd_create() are defined");
    }
#endif /* !(defined __NR_memfd_secret) && !(defined __NR_memfd_create) */

    return fd;
}
