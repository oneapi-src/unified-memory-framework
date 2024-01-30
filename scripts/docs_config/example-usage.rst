.. highlight:: c
    :linenothreshold: 10

==============================================================================
Example usage
==============================================================================

This section will walk you through a basic usage
of :ref:`memory provider <glossary-memory-provider>`
and :ref:`pool allocator <glossary-pool-allocator>`. OS Memory Provider
and Scalable Pool will be used for this purpose.

There are also other memory pools available in the UMF. See `README`_ for
more information.

There are some API functions that are supported only when the UMF is built
with the memory tracking enabled (UMF_ENABLE_POOL_TRACKING=ON). These functions
are explicitly described in this tutorial as requiring memory tracking.

You can find the full example code in the `examples/basic/basic.c`_ file
in the UMF repository.

Memory provider usage
------------------------------------------------------------------------------

First, let's create a memory provider object for coarse-grained allocations.
You have to include the `provider_os_memory.h`_ header with
the OS Memory Provider API::

    #include "umf/providers/provider_os_memory.h"

Get a pointer to the OS memory provider operations struct and
a copy of default parameters::

    umf_memory_provider_ops_t *provider_ops = umfOsMemoryProviderOps();
    umf_os_memory_provider_params_t params = umfOsMemoryProviderParamsDefault();

The handle to created memory ``provider`` object is returned as the last argument
of :any:`umfMemoryProviderCreate`::

    umf_memory_provider_handle_t provider;
    umfMemoryProviderCreate(provider_ops, &params, &provider);

With this handle we can allocate a chunk of memory, call :any:`umfMemoryProviderAlloc`::

    size_t alloc_size = 5000;
    size_t alignment = 0;
    void *ptr_provider = NULL;
    umfMemoryProviderAlloc(provider, alloc_size, alignment, &ptr_provider);

To free the memory allocated with a ``provider``, you have to pass the allocated
size as the last parameter of :any:`umfMemoryProviderFree`::

    umfMemoryProviderFree(provider, ptr_provider, alloc_size);

Memory pool usage
------------------------------------------------------------------------------

Having created a memory ``provider``, you can create a Scalable Memory ``pool``
to be used for fine-grained allocations. You have to include
the `pool_scalable.h`_ header with the Scalable Memory Pool API::

    #include "umf/pools/pool_scalable.h"

Use the default set of operations for the Scalable memory pool
by retrieving an address of the default ops struct::
  
    umf_memory_pool_ops_t *pool_ops = umfScalablePoolOps();

Argument ``pool_params`` is not used by the Scalable Pool, set it to ``NULL``::

    void *pool_params = NULL;

Here we don't make use of additional ``flags``.
See the :any:`documentation <umf_pool_create_flags_t>` for available flags::

    umf_pool_create_flags_t flags = 0;
    
The ``pool`` handle is retrieved as the last argument of
the :any:`umfPoolCreate` function::

    umf_memory_pool_handle_t pool;
    umfPoolCreate(pool_ops, provider, pool_params, flags, &pool);

The ``pool`` has been created, we can allocate some memory now
with ie. :any:`umfPoolCalloc`::

    size_t num = 1;
    alloc_size = 128;
    char *ptr = umfPoolCalloc(pool, num, alloc_size);

With the memory tracking enabled, we can retrieve the pool handle used
for allocating memory::

    umf_memory_pool_handle_t check_pool = umfPoolByPtr(ptr);

For any pool, you can retrieve the memory provider's handle
that was used to create the ``pool`` with :any:`umfPoolGetMemoryProvider`::

    umf_memory_provider_handle_t check_provider;
    umfPoolGetMemoryProvider(pool, &check_provider);

Freeing memory is as easy as can be::

    umfFree(ptr);
    umfPoolDestroy(pool);
    umfMemoryProviderDestroy(provider);

.. note::
    To free a pointer using the :any:`umfFree` function, ensure that memory tracking is enabled
    by setting the UMF_ENABLE_POOL_TRACKING option in the CMake configuration.
    If the memory tracking is disabled, you should call a different function:
    :any:`umfPoolFree`.

.. _examples/basic/basic.c: https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/basic/basic.c
.. _README: https://github.com/oneapi-src/unified-memory-framework/blob/main/README.md#memory-pool-managers
.. _provider_os_memory.h: https://github.com/oneapi-src/unified-memory-framework/blob/main/include/umf/providers/provider_os_memory.h
.. _pool_scalable.h: https://github.com/oneapi-src/unified-memory-framework/blob/main/include/umf/pools/pool_scalable.h
