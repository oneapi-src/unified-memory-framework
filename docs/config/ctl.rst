================
Introduction
================

UMF's CTL is a mechanism for advanced configuration and control of UMF pools
and providers. It allows programmatic access to provider- or pool-specific
configuration options, statistics and auxiliary APIs. CTL entries can also be
set through environment variables or a configuration file, allowing adjustment
of UMF behavior without modifying the program.

.. note::
   The CTL API is experimental and may change in future releases.

Main concepts
=============

The core concept is a *path*. A path is a string of nodes separated by periods.
You can imagine nodes as directories where the last element is a file that can
be read, written or executed (similar to ``sysfs`` but with periods instead of
slashes). Example path ``umf.logger.level`` controls the log level. You can
access it with::

  int level;
  umf_result_t ret = umfCtlGet("umf.logger.level", &level, sizeof(level));

To change the level programmatically use::

  int level = LOG_WARNING;
  umf_result_t ret = umfCtlSet("umf.logger.level", &level, sizeof(level));

Accessing pool or provider paths is slightly more involved. For example::

  size_t alloc_count;
  umf_memory_pool_handle_t hPool = createPool();
  umf_result_t ret = umfCtlGet("umf.pool.by_handle.{}.stats.alloc_count",
                               &alloc_count, sizeof(alloc_count), hPool);

The ``umf.pool.by_handle`` prefix selects a pool addressed by its handle.
Every ``{}`` in the path is replaced with an extra argument passed to the CTL
function. Alternative addressing methods are described below.

Pool / Provider addressing
============================

Two addressing schemes are provided: ``by_handle`` and ``by_name``. Each pool
and provider has a unique handle and an optional user-defined name that can be
queried with ``umfMemoryProviderGetName()`` or ``umfMemoryPoolGetName()``.
When using ``by_name`` the name appears in the path, e.g.::

  umfCtlGet("umf.pool.by_name.myPool.stats.alloc_count",
            &alloc_count, sizeof(alloc_count));

If multiple pools share a name, read operations must disambiguate the target by
appending an index after the name::

  umfCtlGet("umf.pool.by_name.myPool.0.stats.alloc_count",
            &alloc_count, sizeof(alloc_count));

The number of pools with a given name can be obtained with the ``count`` node.

Wildcards
===========

A ``{}`` in the path acts as a wildcard and is replaced with successive
arguments of ``umfCtlGet``, ``umfCtlSet`` or ``umfCtlExec``. Wildcards can
replace any node, not only handles. For example::

  size_t pool_count;
  const char *name = "myPool";
  umfCtlGet("umf.pool.by_name.{}.count", &pool_count, sizeof(pool_count),
            name);
  for (size_t i = 0; i < pool_count; i++) {
      umfCtlGet("umf.pool.by_name.{}.{}.stats.alloc_count", &alloc_count,
                sizeof(alloc_count), name, i);
  }

Ensure that the types of wildcard arguments match the expected node types.

Default addressing
===================

``umf.provider.default`` and ``umf.pool.default`` store default values applied
to providers or pools created after the defaults are set. For example::

  size_t capacity = 16;
  umfCtlSet("umf.pool.default.disjoint.params.capacity", &capacity,
            sizeof(capacity));

Every subsequently created disjoint pool will use ``16`` as its starting
capacity overriding its creation parameters. Defaults are keyed by the
name returned from the provider or pool ``get_name`` callback, so if pool/provider
has custom name it must be addressed explicitly.  Defaults may be supplied programmatically
or via environment variable and are saved internally and applied during initialization of a
matching provider or pool.

Environment variables
=====================

CTL entries may also be specified in the ``UMF_CONF`` environment variable or
a configuration file specified in the ``UMF_CONF_FILE``.
Multiple entries are separated with semicolons, e.g.::

  UMF_CONF="umf.logger.output=stdout;umf.logger.level=0"

CTL options available through environment variables are limited — you can only
target default nodes when addressing pools. This means that configuration
strings can influence values consumed during pool creation but cannot alter
runtime-only parameters.

============
CTL nodes
============

The CTL hierarchy is rooted at ``umf``. The next component selects one of the
major subsystems:

* ``umf.logger`` – logging configuration and diagnostics.
* ``umf.provider`` – provider-specific parameters, statistics and commands.
* ``umf.pool`` – pool-specific parameters, statistics and inspection helpers.

Within each subsystem the path continues with an addressing scheme followed by
the module or leaf of interest.

Reading below sections
=======================

Parameter annotations describe the values stored in the node rather than the
pointer types passed to ``umfCtlGet``/``umfCtlSet``/``umfCtlExec``. The
**Access** field indicates whether the node can be read, written, or executed.
The **Defaults / Env** field notes whether the entry can be controlled through
defaults written under ``umf.provider.default.<name>`` or
``umf.pool.default.<name>`` and via ``UMF_CONF``/``UMF_CONF_FILE``. Nodes that do
not accept either configuration source are marked as not supported.

Logger nodes
================

.. py:function:: umf.logger.timestamp(enabled)

   :param enabled: Receives or supplies ``0`` when timestamps are disabled and
      ``1`` when they are emitted.
   :type enabled: ``int``

   **Access:** read-write.
   **Defaults / Env:** supported.

   Toggle timestamp prefixes in future log records. Logging starts with
   timestamps disabled, and the flag affects only messages emitted after the
   change.

.. py:function:: umf.logger.pid(enabled)

   :param enabled: Receives or supplies ``0`` to omit the process identifier and
      ``1`` to include it in every message header.
   :type enabled: ``int``

   **Access:** read-write.
   **Defaults / Env:** supported.

   Controls whether each log line is annotated with the current process id.
   Logging omits the pid by default. Setting non-boolean values results in
   coercion to zero/non-zero; the change applies to subsequent messages only.

.. py:function:: umf.logger.level(level)

   :param level: Receives or supplies the minimum severity that will be written.
   :type level: ``int`` (``0`` .. ``4``)

   **Access:** read-write.
   **Defaults / Env:** supported.

   Sets the filtering threshold for the logger. Records below the configured
   level are dropped. Writes that fall outside the enumerated range are
   rejected. 0 means debug logs, 1 means info logs, 2 means warnings, 3 means
   errors, and 4 means fatal logs. Until an output is selected the logger
   ignores the level because logging is disabled.

.. py:function:: umf.logger.flush_level(level)

   :param level: Receives or supplies the severity at which the logger forces a
      flush of the output stream.
   :type level: ``int`` (``0`` .. ``4``)

   **Access:** read-write.
   **Defaults / Env:** supported.

   Adjusts when buffered log data is synchronously flushed. Writes outside the
   valid severity range fail, and lowering the level can incur additional flush
   overhead for future messages. With logging disabled no flushing occurs.

.. py:function:: umf.logger.output(path)

   :param path: Receives the currently selected sink on reads. On writes, pass
      ``"stdout"`` or ``"stderr"`` to redirect to standard streams, a
      NULL-terminated file path to append to a file, or ``NULL`` to disable
      logging altogether.
   :type path: ``char *`` when reading, ``const char *`` when writing

   **Access:** read-write.
   **Defaults / Env:** supported.

   Controls the destination for log messages. The logger closes any previously
   opened file when switching targets. Providing a path longer than 256 bytes or
   pointing to a file that cannot be opened causes the write to fail. Special
   values ``"stdout"`` and ``"stderr"`` redirect output to the corresponding
   streams. Passing ``NULL`` disables logging entirely, which is also the
   initial state until a path is provided.

Provider nodes
================

Provider entries are organized beneath ``umf.provider``. Use
``umf.provider.by_handle.{provider}`` with a
:type:`umf_memory_provider_handle_t` argument to reach a specific provider.
Providers can also be addressed by name through ``umf.provider.by_name.{provider}``;
append ``.{index}`` to address specific provider when multiple providers share the same label.
Defaults for future providers reside under ``umf.provider.default.{provider}`` where ``{provider}`` is
a name returned by each provider's ``get_name`` implementation. Providers have their
default names (``OS``, ``FILE``, ``DEVDAX``, ``FIXED``, ``CUDA`` or ``LEVEL_ZERO``),
unless their name was changed during creation, those renamed providers must be addressed explicitly.
Defaults can be written via ``umf.provider.default.<name>`` either programmatically or through
configuration strings. The entries below list only the suffix of each node;
prefix them with the appropriate ``umf.provider`` path.

Common provider statistics
--------------------------

.. py:function:: .stats.allocated_memory(bytes)

   Accessible through both ``umf.provider.by_handle.{provider}`` and
   ``umf.provider.by_name.{name}``. Supply the provider handle or name (with an
   optional ``.{index}`` suffix for duplicates) as the first wildcard argument.

   :param bytes: Receives the total number of bytes currently outstanding.
   :type bytes: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Returns the amount of memory the provider has allocated but not yet freed.
   The counter updates atomically as the provider serves requests and is not
   resettable.

.. py:function:: .stats.peak_memory(bytes)

   Available via ``umf.provider.by_handle.{provider}`` or
   ``umf.provider.by_name.{name}``. Pass the provider selector as the first
   wildcard argument.

   :param bytes: Receives the highest observed outstanding allocation size since
      the last reset.
   :type bytes: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Reports the historical maximum allocation footprint of the provider. Combine
   with :py:func:`.stats.peak_memory.reset()` to discard stale peaks when
   desired.

.. py:function:: .stats.peak_memory.reset()

   Invoke through ``umf.provider.by_handle.{provider}`` or
   ``umf.provider.by_name.{name}`` after supplying the provider selector as the
   first wildcard argument.

   **Access:** execute.
   **Defaults / Env:** not supported.

   Resets the peak allocation counter to the provider's current outstanding
   usage. The operation does not affect other statistics and can be invoked at
   any time.

OS memory provider (``OS``)
---------------------------

The OS provider supports the common statistics nodes described above and adds
the following parameter entry.

.. py:function:: .params.ipc_enabled(enabled)

   :param enabled: Receives ``0`` when inter-process sharing is disabled and a
      non-zero value when it is active.
   :type enabled: ``int``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Indicates whether the OS memory provider has been initialized with IPC
   support. The value is fixed at provider creation time and cannot be modified
   afterwards.

Fixed memory provider (``FIXED``)
-----------------------------------

The fixed-size allocation provider currently exposes only the common statistics
nodes.

DevDAX memory provider (``DEVDAX``)
-------------------------------------

The DevDAX provider exposes the common statistics nodes described earlier.

File memory provider (``FILE``)
-----------------------------------

The file-backed provider exposes the common statistics nodes.

CUDA memory provider (``CUDA``)
-----------------------------------

The CUDA provider currently exposes only the common statistics nodes.

Level Zero memory provider (``LEVEL_ZERO``)
-----------------------------------------------

The Level Zero provider implements the same statistics nodes as the other providers.

Pool nodes
==========

Pool entries mirror the provider layout. ``umf.pool.by_handle.{pool}`` accepts a
:type:`umf_memory_pool_handle_t`, while ``umf.pool.by_name.{pool}`` addresses
pools by name with an optional ``.{index}`` suffix when names are reused.
Defaults for future pools reside under ``umf.pool.default.{pool}`` and track the
name returned by each pool's ``get_name`` implementation. Pools that keep their
default names (``disjoint``, ``scalable`` and ``jemalloc``) continue to match
those entries, while renamed pools must be addressed explicitly. Defaults can be
written via ``umf.pool.default.<pool>`` either programmatically or through
configuration strings. The entries below list only the suffix of each node;
prefix them with the appropriate ``umf.pool`` path.

Common pool statistics
--------------------------

.. py:function:: .stats.alloc_count(count)

   :param count: Receives the number of live allocations tracked by the pool.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Counts the allocations currently outstanding according to the pool's public
   allocation API. The value increments on successful allocations and
   decrements when memory is released.

Disjoint pool (``disjoint``)
--------------------------------

.. py:function:: .params.slab_min_size(bytes)

   :param bytes: Receives or supplies the minimum slab size requested from the
      provider.
   :type bytes: ``size_t``

   **Access:** read-write. (write is only available through defaults)
   **Defaults / Env:** supported.

   Governs how much memory the pool grabs in each slab. Lower values reduce
   per-allocation slack while higher values amortize provider overhead. Writes
   are accepted only before the pool completes its ``post_initialize`` phase.

.. py:function:: .params.max_poolable_size(bytes)

   :param bytes: Receives or supplies the largest allocation size that is still
      cached by the pool.
   :type bytes: ``size_t``

   **Access:** read-write. (write is only available through defaults)
   **Defaults / Env:** supported.

   Sets the cut-off for pooling allocations. Requests larger than this value are
   delegated directly to the provider. Updates must occur before
   ``post_initialize`` completes.

.. py:function:: .params.capacity(count)

   :param count: Receives or supplies the maximum number of slabs each bucket
      may retain.
   :type count: ``size_t``

   **Access:** read-write. (write is only available through defaults)
   **Defaults / Env:** supported.

   Caps the pool's cached slabs per bucket to limit memory retention. Shrinking
   the capacity may cause future frees to return slabs to the provider. Writes
   are rejected after ``post_initialize``.

.. py:function:: .params.min_bucket_size(bytes)

   :param bytes: Receives or supplies the minimal allocation size a bucket may
      serve.
   :type bytes: ``size_t``

   **Access:** read-write. (write is only available through defaults)
   **Defaults / Env:** supported.

   Controls the smallest chunk size kept in the pool, which in turn affects the
   number of buckets. Writes are validated for size correctness and disallowed
   after ``post_initialize``.

.. py:function:: .params.pool_trace(level)

   :param level: Receives or supplies the tracing level for the pool.
   :type level: ``int`` (``0`` disables tracing)

   **Access:** read-write. (write is only available through defaults)
   **Defaults / Env:** supported.

   Controls the disjoint pool's tracing features. ``0`` disables tracing.
   ``1`` records slab usage totals exposed through the ``.stats.curr_slabs_*``
   and ``.stats.max_slabs_*`` nodes. ``2`` additionally tracks allocation and
   free counters and prints a usage summary when the pool is destroyed. Values
   greater than ``2`` also emit debug logs for every allocation and free.
   Tracing must be activated before ``post_initialize``; attempting to change it
   later fails with ``UMF_RESULT_ERROR_NOT_SUPPORTED``.

.. py:function:: .stats.used_memory(bytes)

   Available under ``umf.pool.by_handle.disjoint`` and
   ``umf.pool.by_name.disjoint``. Provide the pool selector as the first wildcard
   argument.

   :param bytes: Receives the amount of memory that is presently allocated by
      the pool's clients.
   :type bytes: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Reports the memory currently in use across all slabs by active allocations.
   Available even when ``pool_trace`` is disabled.

.. py:function:: .stats.reserved_memory(bytes)

   :param bytes: Receives the total number of bytes reserved in slabs that the
      pool owns.
   :type bytes: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Returns the total slab capacity reserved by the pool, including cached free
   space. Available even when ``pool_trace`` is disabled.

.. py:function:: .stats.alloc_num(count)

   :param count: Receives the number of allocations the pool has issued.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` set to ``2`` or higher. Counts every
   allocation handed out by the pool since it was created.

.. py:function:: .stats.alloc_pool_num(count)

   :param count: Receives the number of allocations served directly from cached
      slabs.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` set to ``2`` or higher. Counts
   allocations served from cached slabs without visiting the provider.

.. py:function:: .stats.free_num(count)

   :param count: Receives the total number of frees processed by the pool.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` set to ``2`` or higher. Tracks the
   number of frees observed by the pool since its creation.

.. py:function:: .stats.curr_slabs_in_use(count)

   :param count: Receives the current number of slabs actively serving
      allocations.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` of at least ``1``. Returns the number of
   slabs that currently have live allocations.

.. py:function:: .stats.curr_slabs_in_pool(count)

   :param count: Receives how many slabs are cached and ready for reuse.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` of at least ``1``. Reports the slabs
   retained in the pool for future reuse.

.. py:function:: .stats.max_slabs_in_use(count)

   :param count: Receives the historical maximum of simultaneously used slabs.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` of at least ``1``. Provides the peak
   number of slabs that were in use at the same time.

.. py:function:: .stats.max_slabs_in_pool(count)

   :param count: Receives the largest number of slabs retained in the cache.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` of at least ``1``. Returns the highest
   number of slabs ever retained in the cache simultaneously.

.. py:function:: .buckets.count(count)

   :param count: Receives the number of distinct bucket sizes.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Returns the total number of buckets in the pool.

.. py:function:: .buckets.{id}.size(bytes)

   ``{id}`` denotes a bucket index of type ``size_t``. Valid indices range from
   ``0`` to ``.buckets.count - 1``.

   :param bytes: Receives the allocation size that the bucket serves.
   :type bytes: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Reports the allocation size serviced by the selected bucket. This value is
   available even when tracing is disabled.

.. py:function:: .buckets.{id}.stats.alloc_num(count)

   ``{id}`` denotes a bucket index of type ``size_t``. Valid indices range from
   ``0`` to ``.buckets.count - 1``.

   :param count: Receives the number of allocations performed by this bucket.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` set to ``2`` or higher. Counts every
   allocation that passed through the specified bucket.

.. py:function:: .buckets.{id}.stats.alloc_pool_num(count)

   ``{id}`` denotes a bucket index of type ``size_t``. Valid indices range from
   ``0`` to ``.buckets.count - 1``.

   :param count: Receives the number of allocations satisfied from cached slabs
      in this bucket.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` set to ``2`` or higher. Counts how many
   allocations were served entirely from the bucket's cached slabs.

.. py:function:: .buckets.{id}.stats.free_num(count)

   ``{id}`` denotes a bucket index of type ``size_t``. Valid indices range from
   ``0`` to ``.buckets.count - 1``.

   :param count: Receives the number of frees recorded for this bucket.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` set to ``2`` or higher. Tracks the
   number of frees observed for the bucket.

.. py:function:: .buckets.{id}.stats.curr_slabs_in_use(count)

   ``{id}`` denotes a bucket index of type ``size_t``. Valid indices range from
   ``0`` to ``.buckets.count - 1``.

   :param count: Receives how many slabs for this bucket currently serve
      allocations.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` of at least ``1``. Returns the current
   slab utilization for the bucket.

.. py:function:: .buckets.{id}.stats.curr_slabs_in_pool(count)

   Available through ``umf.pool.by_handle.disjoint`` and
   ``umf.pool.by_name.disjoint``. Provide the pool selector and bucket index as
   the first two wildcard arguments. ``{id}`` denotes a bucket index of type
   ``size_t``. Valid indices range from ``0`` to ``.buckets.count - 1``.

   :param count: Receives the number of slabs cached and immediately available
      for this bucket.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` of at least ``1``. Reports cached slabs
   that the bucket can reuse without a provider call.

.. py:function:: .buckets.{id}.stats.max_slabs_in_use(count)

   ``{id}`` denotes a bucket index of type ``size_t``. Valid indices range from
   ``0`` to ``.buckets.count - 1``.

   :param count: Receives the peak number of slabs in use for this bucket.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` of at least ``1``. Provides the
   historical maximum of slabs simultaneously in use for the bucket.

.. py:function:: .buckets.{id}.stats.max_slabs_in_pool(count)

   ``{id}`` denotes a bucket index of type ``size_t``. Valid indices range from
   ``0`` to ``.buckets.count - 1``.

   :param count: Receives the largest number of slabs retained in the bucket's
      cache.
   :type count: ``size_t``

   **Access:** read-only.
   **Defaults / Env:** not supported.

   Requires tracing with ``pool_trace`` of at least ``1``. Returns the maximum
   number of slabs cached for later use by the bucket.


Scalable pool (``scalable``)
------------------------------

The scalable pool currently exposes only the common statistics nodes.

Jemalloc pool (``jemalloc``)
--------------------------------

The jemalloc-backed pool currently exposes only the common statistics nodes.

================================================
Adding CTL support to custom providers and pools
================================================

The :file:`examples/ctl/custom_ctl.c` source demonstrates how a minimal
provider can expose configuration entries, statistics and runnables through the
CTL API. To add similar support to your own provider or pool you must implement
an ``ext_ctl`` callback – parse incoming CTL paths and handle
``CTL_QUERY_READ``, ``CTL_QUERY_WRITE`` and ``CTL_QUERY_RUNNABLE`` requests.
The callback receives a ``umf_ctl_query_source_t`` indicating whether the
query came from the application or a configuration source.  Programmatic
calls pass typed binary data, while configuration sources deliver strings
that must be parsed.  Wildcards (``{}``) may appear in paths and are supplied
as additional arguments.

During initialization UMF will execute ``post_initialize`` on the callback after
applying any queued defaults, allowing the provider or pool to finalize its
state before it is used by the application.  The example converts wildcarded
paths into ``printf``-style format strings with ``%s`` and uses ``vsnprintf`` to
resolve the extra arguments.  It also shows a helper that accepts integers from
either source, printing the final values from ``post_initialize``.

Building and running the example:

.. code-block:: bash

   cmake -B build
   cmake --build build
   ./build/examples/umf_example_ctl

An optional modulus can be supplied via the environment:

.. code-block:: bash

   UMF_CONF="umf.provider.default.ctl.m=10" ./build/examples/umf_example_ctl
