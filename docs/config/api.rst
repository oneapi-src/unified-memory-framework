==========================================
API Documentation
==========================================

Globals
==========================================
.. doxygenfile:: base.h
    :sections: define enum

Pools
==========================================

The UMF memory pool is a combination of a pool allocator and a memory provider. 
The pool allocator controls the memory pool and handles fine-grained memory 
allocations memory allocations.

UMF includes predefined pool allocators. UMF can also work with user-defined 
pools which implement the memory pool API.

.. _allocation API:

Memory Pool
------------------------------------------

The memory pool API provides a malloc-like API for allocating and deallocating 
memory as well as functions that create, destroy and operate on the pool.

.. doxygenfile:: memory_pool.h
    :sections: define enum typedef func var
    
Disjoint Pool
------------------------------------------

The Disjoint Pool allocates user data using the configured provider, while also 
preserving metadata in DRAM.

.. doxygenfile:: pool_disjoint.h
    :sections: define enum typedef func var

Jemalloc Pool
------------------------------------------

A jemalloc-based memory pool manager. More info about jemalloc could be found
here: https://github.com/jemalloc/jemalloc.

.. doxygenfile:: pool_jemalloc.h
    :sections: define enum typedef func var

Proxy Pool
------------------------------------------

Proxy Pool forwards all requests to the underlying memory provider. Currently 
umfPoolRealloc, umfPoolCalloc and umfPoolMallocUsableSize functions are not 
supported by the Proxy Pool.

.. doxygenfile:: pool_proxy.h
    :sections: define enum typedef func var

Scalable Pool
------------------------------------------

A oneTBB-based memory pool manager.

.. doxygenfile:: pool_scalable.h
    :sections: define enum typedef func var

Providers
==========================================

The memory provider is responsible for coarse-grained memory allocations and 
memory page management. 

UMF includes predefined providers, but can also work with providers which 
implement the memory provider API.

Memory Provider
------------------------------------------

The memory provider API provides a functions for allocating, deallocating and 
manipulating coarse-grained memory as well as functions that create, destroy 
and operate on the provider.

.. doxygenfile:: memory_provider.h
    :sections: define enum typedef func var

Fixed Memory Provider
------------------------------------------

A memory provider that can provide memory from a given preallocated buffer.

.. doxygenfile:: provider_fixed_memory.h
    :sections: define enum typedef func var

OS Memory Provider
------------------------------------------

A memory provider that provides memory from an operating system.

.. doxygenfile:: provider_os_memory.h
    :sections: define enum typedef func var

Level Zero Provider
------------------------------------------

A memory provider that provides memory from L0 device.

.. doxygenfile:: provider_level_zero.h
    :sections: define enum typedef func var

CUDA Provider
------------------------------------------

A memory provider that provides memory from CUDA device.

.. doxygenfile:: provider_cuda.h
    :sections: define enum typedef func var

DevDax Memory Provider
------------------------------------------

A memory provider that provides memory from a device DAX (a character device file like /dev/daxX.Y).

.. doxygenfile:: provider_devdax_memory.h
    :sections: define enum typedef func var

File Memory Provider
------------------------------------------

A memory provider that provides memory by mapping a regular, extendable file.

.. doxygenfile:: provider_file_memory.h
    :sections: define enum typedef func var

Memspace
==========================================

TODO: Add general information about memspaces.

.. note::
   The memspace APIs are experimental and may change in future releases.

Memspace
------------------------------------------
.. doxygenfile:: experimental/memspace.h
    :sections: define enum typedef func

Mempolicy             
==========================================

TODO: Add general information about mempolicies.

.. note::
   The mempolicy APIs are experimental and may change in future releases.

Mempolicy
------------------------------------------
.. doxygenfile:: experimental/mempolicy.h
    :sections: define enum typedef func

Memtarget
==========================================

TODO: Add general information about memtargets.

.. note::
   The memtarget APIs are experimental and may change in future releases.

Memtarget
------------------------------------------
.. doxygenfile:: experimental/memtarget.h
    :sections: define enum typedef func

Memory Properties
==========================================

TODO: Add general information about memory properties.

.. note::
   The memory properties APIs are experimental and may change in future releases.

Memory Properties
------------------------------------------
.. doxygenfile::  experimental/memory_props.h
    :sections: define enum typedef func var

Inter-Process Communication
==========================================

IPC API allows retrieving IPC handles for the memory buffers allocated from 
UMF memory pools. The memory provider used by the pool should support IPC 
operations for this API to work. Otherwise IPC APIs return an error.

IPC caching
------------------------------------------

UMF employs IPC caching to avoid multiple IPC handles being created for the same 
coarse-grain memory region allocated by the memory provider. UMF guarantees that 
for each coarse-grain memory region allocated by the memory provider, only one 
IPC handle is created when the :any:`umfGetIPCHandle` function is called. All 
subsequent calls to the :any:`umfGetIPCHandle` function for the pointer to the 
same memory region will return the entry from the cache.

The same is true for the :any:`umfOpenIPCHandle` function. The actual mapping
of the IPC handle to the virtual address space is created only once, and all
subsequent calls to open the same IPC handle will return the entry from the cache.
The size of the cache for opened IPC handles is controlled by the ``UMF_MAX_OPENED_IPC_HANDLES``
environment variable. By default, the cache size is unlimited. However, if the environment 
variable is set and the cache size exceeds the limit, old items will be evicted. UMF tracks 
the ref count for each entry in the cache and can evict only items with the ref count equal to 0. 
The ref count is increased when the :any:`umfOpenIPCHandle` function is called and decreased 
when the :any:`umfCloseIPCHandle` function is called for the corresponding IPC handle.

.. _ipc-api:

IPC API
------------------------------------------
.. doxygenfile:: ipc.h
    :sections: define enum typedef func var
