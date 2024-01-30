Glossary
==========================================================

.. _glossary-homogeneous-memory-system:

Homogeneous Memory System  
  A system that operates on a single type of memory implemented using a single 
  technology.

.. _glossary-heterogeneous-memory-system:

Heterogeneous Memory System 
  A system that operates on multiple types of memories, possibly implemented 
  using different technologies, often managed by different entities.

.. _glossary-memory-tiering:

Memory Tiering
  An organization of different types of memory storage within a system, each 
  having distinct characteristics, performance, and cost attributes. These 
  memory tiers are typically organized in a hierarchy, with faster, more 
  expensive memory located closer to the processor and slower, less expensive 
  memory located further away.

.. _glossary-memory-access-initiator:

Memory Access Initiator 
  A component in a computer system that initiates or requests access to the 
  computer's memory subsystem. This could be a CPU, GPU, or other I/O and cache 
  devices.

.. _glossary-memory-target:

Memory Target 
  Any part of the memory subsystem that can handle memory access requests. This 
  could be the OS-accessible main memory (RAM), video memory that resides on 
  the graphics cards, memory caches, storage, external memory devices connected 
  using CXL.mem protocol, etc.

.. _glossary-memory-page:

Memory Page 
  A fixed-length contiguous block of virtual memory, described by a single 
  entry in the page table. It is the smallest unit of data for memory 
  management in a virtual memory operating system.

.. _glossary-enlightened-application:

Enlightened Application 
  An application that explicitly manages data allocation distribution among 
  different types of memory and handles data migration between them. 

.. _glossary-unenlightened-application:

Unenlightened Application 
  An application that relies on the underlying infrastructure (OS, frameworks, 
  libraries) that offers various memory tiering and migration solutions without 
  any code modifications.

.. _glossary-memory-pool:

Memory Pool 
  A memory management technique used in computer programming and software 
  development, where relatively large blocks of memory are preallocated using 
  memory provider and then passed to a pool allocator for fine-grain 
  management. The pool allocator could divide these blocks into smaller chunks 
  and use them for application allocations depending on its needs. Typically 
  pool allocators focus on the low fragmentation and constant allocation time, 
  so they are used to optimize memory allocation and deallocation in scenarios 
  where efficiency and performance are critical.

.. _glossary-pool-allocator:

Pool Allocator 
  A memory allocator type used to efficiently manage memory pools. Among the 
  existing ones are jemalloc or oneTBB's Scalable Memory Allocator.

.. _glossary-memory-provider:

Memory Provider 
  A software component responsible for supplying memory or managing memory 
  targets. A single memory provider can efficiently manage the memory 
  operations for one or multiple devices within the system or other memory 
  sources like file-backed or user-provided memory. Memory providers are 
  responsible for coarse-grain allocations and management of memory pages.

.. _glossary-hbm:

High Bandwidth Memory (HBM)
  A high-speed computer memory. It is used in conjunction with high-performance 
  graphics accelerators, network devices, and high-performance data centers, as 
  on-package cache in CPUs, FPGAs, supercomputers, etc.

.. _glossary-cxl:

Compute Express Link (`CXL`_)
  An open standard for high-speed, high-capacity central processing unit 
  (CPU)-to-device and CPU-to-memory connections, designed for high-performance 
  data center computers. CXL is built on the serial PCI Express (PCIe) physical 
  and electrical interface and includes PCIe-based block input/output protocol 
  (CXL.io), cache-coherent protocols for accessing system memory (CXL.cache), 
  and device memory (CXL.mem).

.. _glossary-tbb:

oneAPI Threading Building Blocks (`oneTBB`_)
  A C++ template library developed by Intel for parallel programming on 
  multi-core processors. TBB broke down the computation into tasks that can run 
  in parallel. The library manages and schedules threads to execute these tasks.

.. _glossary-jemalloc:

jemalloc 
  A general-purpose malloc implementation that emphasizes fragmentation 
  avoidance and scalable concurrency support. It provides introspection, memory 
  management, and tuning features functionalities. `Jemalloc`_ uses separate 
  pools (“arenas”) for each CPU which avoids lock contention problems in 
  multithreading applications and makes them scale linearly with the number of 
  threads.

.. _glossary-usm:

Unified Shared Memory (USM) 
  A programming model which provides a single memory address space that is 
  shared between CPUs, GPUs, and possibly other accelerators. It simplifies 
  memory management by transparently handling data migration between the CPU 
  and the accelerator device as needed.

.. _CXL: https://www.computeexpresslink.org/
.. _oneTBB: https://oneapi-src.github.io/oneTBB/
.. _Jemalloc: https://jemalloc.net/
