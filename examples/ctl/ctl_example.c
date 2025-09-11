#define _GNU_SOURCE 1
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <umf.h>
#include <umf/base.h>
#include <umf/experimental/ctl.h>
#include <umf/memory_provider.h>
#include <umf/memory_provider_ops.h>

// Minimal memory provider demonstrating CTL integration

// Provider state exposed via CTL
typedef struct ctl_provider_t {
    int a;
    int b;
    int c;
    int m; // modulus value, optional
} ctl_provider_t;

static umf_result_t ctl_init(const void *params, void **provider) {
    (void)params;
    ctl_provider_t *p = calloc(1, sizeof(*p));
    if (!p) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    *provider = p;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ctl_finalize(void *provider) {
    free(provider);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ctl_alloc(void *provider, size_t size, size_t alignment,
                              void **ptr) {
    (void)provider;
    (void)alignment;
    *ptr = malloc(size);
    if (*ptr == NULL) {
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ctl_free(void *provider, void *ptr, size_t size) {
    (void)provider;
    (void)size;
    free(ptr);
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ctl_get_last_native_error(void *provider,
                                              const char **ppMessage,
                                              int32_t *pError) {
    (void)provider;
    if (ppMessage) {
        *ppMessage = NULL;
    }
    if (pError) {
        *pError = 0;
    }
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ctl_get_recommended_page_size(void *provider, size_t size,
                                                  size_t *pageSize) {
    (void)provider;
    (void)size;
    *pageSize = 4096;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ctl_get_min_page_size(void *provider, const void *ptr,
                                          size_t *pageSize) {
    (void)provider;
    (void)ptr;
    *pageSize = 4096;
    return UMF_RESULT_SUCCESS;
}

static umf_result_t ctl_get_name(void *provider, const char **name) {
    (void)provider;
    if (name) {
        *name = "ctl";
    }
    return UMF_RESULT_SUCCESS;
}

// Wildcards (`{}`) become extra args; convert them to `%s` for `vsnprintf`.
static void replace_braces_with_percent_s(const char *name, char *fmt,
                                          size_t fmt_size) {
    size_t i = 0, j = 0;
    while (name[i] != '\0' && j < fmt_size - 1) {
        if (name[i] == '{' && name[i + 1] == '}' && j < fmt_size - 2) {
            fmt[j++] = '%';
            fmt[j++] = 's';
            i += 2;
        } else {
            fmt[j++] = name[i++];
        }
    }
    fmt[j] = '\0';
}

// Parse an integer from programmatic (binary) or configuration (string) input.
static umf_result_t parse_int(void *arg, size_t size,
                              umf_ctl_query_source_t source, int *out) {
    if (!arg || !out) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    if (source == CTL_QUERY_PROGRAMMATIC) {
        if (size != sizeof(int)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *out = *(int *)arg;
        return UMF_RESULT_SUCCESS;
    } else if (source == CTL_QUERY_CONFIG_INPUT) {
        char *buf = malloc(size + 1);
        if (!buf) {
            return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
        }
        memcpy(buf, arg, size);
        buf[size] = '\0';
        *out = (int)strtol(buf, NULL, 10);
        free(buf);
        return UMF_RESULT_SUCCESS;
    }

    return UMF_RESULT_ERROR_INVALID_ARGUMENT;
}

// CTL callback interpreting provider-specific paths and actions
static umf_result_t ctl_ctl(void *provider, umf_ctl_query_source_t source,
                            const char *name, void *arg, size_t size,
                            umf_ctl_query_type_t queryType, va_list args) {
    ctl_provider_t *p = (ctl_provider_t *)provider;

    char fmt[128];
    char formatted[128];
    replace_braces_with_percent_s(name, fmt, sizeof(fmt));
    va_list args_copy;
    va_copy(args_copy, args);
    vsnprintf(formatted, sizeof(formatted), fmt, args_copy);
    va_end(args_copy);

    if (queryType == CTL_QUERY_RUNNABLE &&
        strcmp(formatted, "post_initialize") == 0) {
        // Called once defaults have been loaded
        printf("post_initialize: a=%d b=%d c=%d m=%d\n", p->a, p->b, p->c,
               p->m);
        return UMF_RESULT_SUCCESS;
    }

    if (queryType == CTL_QUERY_WRITE && strcmp(formatted, "a") == 0) {
        int val = 0;
        umf_result_t ret = parse_int(arg, size, source, &val);
        if (ret != UMF_RESULT_SUCCESS) {
            return ret;
        }
        p->a = val;
        return UMF_RESULT_SUCCESS;
    }
    if (queryType == CTL_QUERY_WRITE && strcmp(formatted, "b") == 0) {
        int val = 0;
        umf_result_t ret = parse_int(arg, size, source, &val);
        if (ret != UMF_RESULT_SUCCESS) {
            return ret;
        }
        p->b = val;
        return UMF_RESULT_SUCCESS;
    }
    if (queryType == CTL_QUERY_WRITE && strcmp(formatted, "m") == 0) {
        int val = 0;
        umf_result_t ret = parse_int(arg, size, source, &val);
        if (ret != UMF_RESULT_SUCCESS) {
            return ret;
        }
        p->m = val;
        return UMF_RESULT_SUCCESS;
    }
    if (queryType == CTL_QUERY_RUNNABLE && strcmp(formatted, "addition") == 0) {
        if (p->m) {
            p->c = (p->a + p->b) % p->m;
        } else {
            p->c = p->a + p->b;
        }
        if (arg && size == sizeof(int)) {
            *(int *)arg = p->c;
        }
        return UMF_RESULT_SUCCESS;
    }
    if (queryType == CTL_QUERY_RUNNABLE &&
        strcmp(formatted, "substraction") == 0) {
        if (p->m) {
            p->c = (p->a - p->b) % p->m;
        } else {
            p->c = p->a - p->b;
        }
        if (arg && size == sizeof(int)) {
            *(int *)arg = p->c;
        }
        return UMF_RESULT_SUCCESS;
    }
    if (queryType == CTL_QUERY_READ && strcmp(formatted, "c") == 0) {
        if (arg == NULL || size != sizeof(int)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *(int *)arg = p->c;
        return UMF_RESULT_SUCCESS;
    }
    if (queryType == CTL_QUERY_READ && strcmp(formatted, "m") == 0) {
        if (arg == NULL || size != sizeof(int)) {
            return UMF_RESULT_ERROR_INVALID_ARGUMENT;
        }
        *(int *)arg = p->m;
        return UMF_RESULT_SUCCESS;
    }

    return UMF_RESULT_ERROR_INVALID_CTL_PATH;
}

static umf_memory_provider_ops_t ctl_ops = {
    .version = UMF_PROVIDER_OPS_VERSION_CURRENT,
    .initialize = ctl_init,
    .finalize = ctl_finalize,
    .alloc = ctl_alloc,
    .free = ctl_free,
    .get_last_native_error = ctl_get_last_native_error,
    .get_recommended_page_size = ctl_get_recommended_page_size,
    .get_min_page_size = ctl_get_min_page_size,
    .get_name = ctl_get_name,
    .ext_ctl = ctl_ctl, // register CTL handler
};

int main(void) {
    umf_result_t res;
    umf_memory_provider_handle_t provider;

    // Create provider instance and wire in CTL callbacks
    res = umfMemoryProviderCreate(&ctl_ops, NULL, &provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create a memory provider!\n");
        return -1;
    }
    printf("ctl provider created at %p\n", (void *)provider);
    // Defaults are now applied and `post_initialize` has run

    int a = 10;
    int b = 7;
    // Set variables via CTL; `{}` is replaced by the provider handle
    res = umfCtlSet("umf.provider.by_handle.{}.a", &a, sizeof(a), provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set a!\n");
        goto out;
    }
    res = umfCtlSet("umf.provider.by_handle.{}.b", &b, sizeof(b), provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to set b!\n");
        goto out;
    }
    int m = 0;
    // Read optional modulus from config or environment you can use {} to replace any node
    res =
        umfCtlGet("umf.provider.by_handle.{}.{}", &m, sizeof(m), provider, "c");
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to get m!\n");
        goto out;
    }
    printf("using modulus m=%d\n", m);

    int result = 0;

    // Execute addition and fetch the result
    res = umfCtlExec("umf.provider.by_handle.{}.addition", NULL, 0, provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to execute addition!\n");
        goto out;
    }
    res = umfCtlGet("umf.provider.by_handle.{}.c", &result, sizeof(result),
                    provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to get c!\n");
        goto out;
    }
    printf("addition result: %d\n", result);

    // Execute subtraction and fetch the result
    res =
        umfCtlExec("umf.provider.by_handle.{}.substraction", NULL, 0, provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to execute substraction!\n");
        goto out;
    }
    res = umfCtlGet("umf.provider.by_handle.{}.c", &result, sizeof(result),
                    provider);
    if (res != UMF_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to get c!\n");
        goto out;
    }
    printf("substraction result: %d\n", result);

out:
    umfMemoryProviderDestroy(provider);
    return 0;
}
