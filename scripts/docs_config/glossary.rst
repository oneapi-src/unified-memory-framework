Glossary
==========================================================

Homogeneous Memory
  A collection of memory composed of a single memory type, managed by a singular 
  driver using a uniform approach.

Heterogeneous Memory
  A set of memory composed of multiple types of memory technologies, each 
  requiring distinct handling approaches often managed by separate drivers.

Memory Tiering
  An organization and hierarchy of different types of memory storage within a 
  system, with each type of memory having distinct characteristics, performance, 
  and cost attributes. These memory tiers are typically organized in a 
  hierarchy, with faster, more expensive memory located closer to the processor 
  and slower, less expensive memory located further away.

Memory Access Initiator 
  A component in a computer system that initiates or requests access to the 
  computer's memory subsystem. This could be a CPU, GPU, or other I/O and cache 
  devices.

Memory Target 
  Any part of the memory subsystem that can handle memory access requests. This 
  could be the OS memory (RAM), video memory that resides on the graphics 
  cards, memory caches, storage, external memory devices connected using 
  CXL.mem protocol, etc.

Memory Page 
  A fixed-length contiguous block of virtual memory, described by a single 
  entry in the page table. It is the smallest unit of data for memory 
  management in a virtual memory operating system.

Enlightened Application 
  An application that explicitly manages data allocation distribution among 
  memory tiers and further data migration. 

Unenlightened Application 
  An application that coexists with the underlying infrastructure (OS, 
  frameworks, libraries) that offers various memory tiering and migration 
  solutions without any code modifications.

Memory Pool 
  A memory management technique used in computer programming and software 
  development, where fixed-size blocks of memory are preallocated using one or 
  more memory providers and then divided into smaller, fixed-size blocks or 
  chunks. These smaller blocks are then allocated and deallocated by a pool 
  allocator depending on the needs of the program or application. Thanks to 
  low fragmentation and constant allocation time, memory pools are used to 
  optimize memory allocation and deallocation in scenarios where efficiency 
  and performance are critical.

Pool Allocator 
  A memory allocator type used to efficiently manage memory pools. 

Memory Provider 
  A software component responsible for supplying memory or managing memory 
  targets. A single memory provider kind can efficiently manage the memory 
  operations for one or multiple devices within the system or other memory 
  sources like file-backed or user-provided memory.

High Bandwidth Memory (HBM) 
  A high-speed computer memory. It is used in conjunction with high-performance 
  graphics accelerators, network devices, and high-performance data centers, as 
  on-package cache on-package RAM in CPUs, FPGAs, supercomputers, etc.

Compute Express Link (CXL_) 
  An open standard for high-speed, high-capacity central processing unit 
  (CPU)-to-device and CPU-to-memory connections, designed for high-performance 
  data center computers. CXL is built on the serial PCI Express (PCIe) physical 
  and electrical interface and includes PCIe-based block input/output protocol 
  (CXL.io), cache-coherent protocols for accessing system memory (CXL.cache), 
  and device memory (CXL.mem).

oneAPI Threading Building Blocks (oneTBB_)
  A C++ template library developed by Intel for parallel programming on 
  multi-core processors. TBB broke down the computation into tasks that can run 
  in parallel. The library manages and schedules threads to execute these tasks.

jemalloc 
  A general-purpose malloc implementation that emphasizes fragmentation 
  avoidance and scalable concurrency support. It provides introspection, memory 
  management, and tuning features functionalities. Jemalloc_ uses separate pools 
  (“arenas”) for each CPU which avoids lock contention problems in 
  multithreading applications and makes them scale linearly with the number of 
  threads.

Unified Shared Memory (USM) 
  A programming model which provides a single memory address space that is 
  shared between CPUs, GPUs, and possibly other accelerators. It simplifies 
  memory management by transparently handling data migration between the CPU 
  and the accelerator device as needed.

.. _CXL https://www.computeexpresslink.org/
.. _oneTBB https://oneapi-src.github.io/oneTBB/
.. _Jemalloc https://jemalloc.net/
