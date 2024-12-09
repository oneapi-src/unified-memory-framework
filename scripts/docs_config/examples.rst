.. highlight:: c
    :linenothreshold: 10

==============================================================================
Examples
==============================================================================

This section will walk you through a basic usage
of :ref:`memory provider <glossary-memory-provider>`
and :ref:`pool allocator <glossary-pool-allocator>` APIs.
There are two examples described here: basic and GPU shared.

Basic example uses OS Memory Provider and Scalable Pool,
while the GPU shared uses Level Zero Memory Provider and Disjoint Pool.

There are also other memory providers and pools available in the UMF.
See `README`_ for more information.

Basic
==============================================================================

You can find the full example code in the `examples/basic/basic.c`_ file
in the UMF repository.

Memory provider usage
------------------------------------------------------------------------------

First, let's create a memory provider object for coarse-grained allocations.
You have to include the `provider_os_memory.h`_ header with
the OS Memory Provider API::

    #include "umf/providers/provider_os_memory.h"

Get a pointer to the OS memory provider operations struct::

    umf_memory_provider_ops_t *provider_ops = umfOsMemoryProviderOps();

Get a default OS memory provider parameters. The handle to the parameters object
is returned by the :any:`umfOsMemoryProviderParamsCreate` function::

    umf_os_memory_provider_params_handle_t params = NULL;

    res = umfOsMemoryProviderParamsCreate(&params);
    if (res != UMF_RESULT_SUCCESS) {
        printf("Failed to create OS memory provider params!\n");
        return -1;
    }

The handle to created memory ``provider`` object is returned as the last argument
of :any:`umfMemoryProviderCreate`::

    umf_memory_provider_handle_t provider;
    umfMemoryProviderCreate(provider_ops, &params, &provider);

The ``params`` object can be destroyed after the provider is created::
    umfOsMemoryProviderParamsDestroy(params);

With the ``provider`` handle we can allocate a chunk of memory, call :any:`umfMemoryProviderAlloc`::

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
with i.e. :any:`umfPoolCalloc`::

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

GPU shared memory
==============================================================================

You can find the full example code in the `examples/level_zero_shared_memory/level_zero_shared_memory.c`_ file
or `examples/cuda_shared_memory/cuda_shared_memory.c`_ file in the UMF repository.

TODO

Memspace
==============================================================================

You can find the full examples code in the `examples/memspace`_ directory
in the UMF repository.

TODO

Custom memory provider
==============================================================================

You can find the full examples code in the `examples/custom_file_provider/custom_file_provider.c`_ file
in the UMF repository.

TODO

IPC example with Level Zero Memory Provider
==============================================================================
The full code of the example is in the `examples/ipc_level_zero/ipc_level_zero.c`_ file in the UMF repository.
The example demonstrates how to use UMF :ref:`IPC API <ipc-api>`. For demonstration purpose the example uses
Level Zero memory provider to instantiate a pool. But the same flow will work with any memory provider that
supports IPC capabilities.

Here we omit describing how memory pools are created as its orthogonal to the IPC API usage. For more information
on how to create memory pools refer to the previous examples. Also for simplification, our example is single process
while :ref:`IPC API <ipc-api>` targeted for interprocess communication when IPC handle is created by one process
to be used in another process.

To use :ref:`IPC API <ipc-api>` the `umf/ipc.h`_ header should be included.

.. code-block:: c

   #include <umf/ipc.h>

To get IPC handle for the memory allocated by UMF the :any:`umfGetIPCHandle` function should be used.

.. code-block:: c

    umf_ipc_handle_t ipc_handle = NULL;
    size_t handle_size = 0;
    umf_result_t umf_result = umfGetIPCHandle(initial_buf, &ipc_handle, &handle_size);

The :any:`umfGetIPCHandle` function requires only the memory pointer as an input parameter and internally determines
the memory pool to which the memory region belongs. While in our example the :any:`umfPoolMalloc` function is called
a few lines before the :any:`umfGetIPCHandle` function is called, in a real application, memory might be allocated even
by a different library and the caller of the :any:`umfGetIPCHandle` function may not know the corresponding memory pool.

The :any:`umfGetIPCHandle` function returns the IPC handle and its size. The IPC handle is a byte-copyable opaque
data structure. The :any:`umf_ipc_handle_t` type is defined as a pointer to a byte array. The size of the handle
might be different for different memory provider types. The code snippet below demonstrates how the IPC handle can
be serialized for marshalling purposes.

.. code-block:: c

    // Serialize IPC handle
    void *serialized_ipc_handle = malloc(handle_size);
    memcpy(serialized_ipc_handle, (void*)ipc_handle, handle_size);

.. note::
    The method of sending the IPC handle between processes is not defined by the UMF.

When the IPC handle is transferred
to another process it can be opened by the :any:`umfOpenIPCHandle` function.

.. code-block:: c

    umf_ipc_handler_handle_t ipc_handler = 0;
    umf_result = umfPoolGetIPCHandler(consumer_pool, &ipc_handler);

    void *mapped_buf = NULL;
    umf_result = umfOpenIPCHandle(ipc_handler, ipc_handle, &mapped_buf);

The :any:`umfOpenIPCHandle` function requires the IPC handler and the IPC handle as input parameters. The IPC handler maps
the handle to the current process address space and returns the pointer to the same memory region that was allocated
in the producer process. To retrieve the IPC handler, the :any:`umfPoolGetIPCHandler` function is used.

.. note::
    The virtual addresses of the memory region referred to by the IPC handle may not be the same in the producer and consumer processes.

To release IPC handle on the producer side the :any:`umfPutIPCHandle` function should be used.

.. code-block:: c

    umf_result = umfPutIPCHandle(ipc_handle);

To close IPC handle on the consumer side the :any:`umfCloseIPCHandle` function should be used.

.. code-block:: c

    umf_result = umfCloseIPCHandle(mapped_buf);

The :any:`umfPutIPCHandle` function on the producer side might be called even before the :any:`umfCloseIPCHandle`
function is called on the consumer side. The memory mappings on the consumer side remains valid until
the :any:`umfCloseIPCHandle` function is called.

.. _examples/basic/basic.c: https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/basic/basic.c
.. _examples/level_zero_shared_memory/level_zero_shared_memory.c: https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/level_zero_shared_memory/level_zero_shared_memory.c
.. _examples/cuda_shared_memory/cuda_shared_memory.c: https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/cuda_shared_memory/cuda_shared_memory.c
.. _examples/ipc_level_zero/ipc_level_zero.c: https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/ipc_level_zero/ipc_level_zero.c
.. _examples/custom_file_provider/custom_file_provider.c: https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/custom_file_provider/custom_file_provider.c
.. _examples/memspace: https://github.com/oneapi-src/unified-memory-framework/blob/main/examples/memspace/
.. _README: https://github.com/oneapi-src/unified-memory-framework/blob/main/README.md#memory-pool-managers
.. _umf/ipc.h: https://github.com/oneapi-src/unified-memory-framework/blob/main/include/umf/ipc.h
.. _provider_os_memory.h: https://github.com/oneapi-src/unified-memory-framework/blob/main/include/umf/providers/provider_os_memory.h
.. _pool_scalable.h: https://github.com/oneapi-src/unified-memory-framework/blob/main/include/umf/pools/pool_scalable.h
