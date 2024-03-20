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

Coarse Provider
------------------------------------------

A memory provider that should be used as a "cache" for pre-allocated buffer or 
with additional upstream provider (e.g. OS Memory Provider).

.. doxygenfile:: provider_coarse.h
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

Memspace
==========================================

TODO: Add general information about memspaces.

Memspace
------------------------------------------
.. doxygenfile:: memspace.h
    :sections: define enum typedef func var

Inter-Process Communication
==========================================

IPC API allows retrieving IPC handles for the memory buffers allocated from 
UMF memory pools. The memory provider used by the pool should support IPC 
operations for this API to work. Otherwise IPC APIs return an error.

.. _ipc-api:

IPC API
------------------------------------------
.. doxygenfile:: ipc.h
    :sections: define enum typedef func var