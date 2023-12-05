==========================================
Unified Memory Framework API Documentation
==========================================

Globals
----------------------------------------------------------
.. doxygenfile:: base.h
    :sections: enum

Pools
----------------------------------------------------------
Disjoint Pool
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. rubric:: Structs
.. doxygenstruct:: umf_disjoint_pool_params
.. doxygenfile:: pool_disjoint.h
    :sections: enum typedef func var

Memory Pool
----------------------------------------------------------
.. rubric:: Structs
.. doxygenfile:: memory_pool_ops.h
.. doxygenfile:: memory_pool.h
    :sections: enum typedef func var

Memory Provider
----------------------------------------------------------
.. rubric:: Structs
.. doxygenfile:: memory_provider_ops.h
.. doxygenfile:: memory_provider.h
