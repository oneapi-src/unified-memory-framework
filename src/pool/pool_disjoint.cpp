// Copyright (C) 2023-2025 Intel Corporation
// Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <cassert>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <limits>
#include <list>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// TODO: replace with logger?
#include <iostream>

#include "provider/provider_tracking.h"

#include "../cpp_helpers.hpp"
#include "pool_disjoint.h"
#include "umf.h"
#include "utils_log.h"
#include "utils_math.h"
#include "utils_sanitizers.h"

// Temporary solution for disabling memory poisoning. This is needed because
// AddressSanitizer does not support memory poisoning for GPU allocations.
// More info: https://github.com/oneapi-src/unified-memory-framework/issues/634
#ifndef POISON_MEMORY
#define POISON_MEMORY 0
#endif

static inline void annotate_memory_inaccessible([[maybe_unused]] void *ptr,
                                                [[maybe_unused]] size_t size) {
#if (POISON_MEMORY != 0)
    utils_annotate_memory_inaccessible(ptr, size);
#endif
}

static inline void annotate_memory_undefined([[maybe_unused]] void *ptr,
                                             [[maybe_unused]] size_t size) {
#if (POISON_MEMORY != 0)
    utils_annotate_memory_undefined(ptr, size);
#endif
}

typedef struct umf_disjoint_pool_shared_limits_t {
    size_t MaxSize;
    std::atomic<size_t> TotalSize;
} umf_disjoint_pool_shared_limits_t;

// Configuration of Disjoint Pool
typedef struct umf_disjoint_pool_params_t {
    // Minimum allocation size that will be requested from the memory provider.
    size_t SlabMinSize;

    // Allocations up to this limit will be subject to chunking/pooling
    size_t MaxPoolableSize;

    // When pooling, each bucket will hold a max of 'Capacity' unfreed slabs
    size_t Capacity;

    // Holds the minimum bucket size valid for allocation of a memory type.
    // This value must be a power of 2.
    size_t MinBucketSize;

    // Holds size of the pool managed by the allocator.
    size_t CurPoolSize;

    // Whether to print pool usage statistics
    int PoolTrace;

    // Memory limits that can be shared between multitple pool instances,
    // i.e. if multiple pools use the same SharedLimits sum of those pools'
    // sizes cannot exceed MaxSize.
    umf_disjoint_pool_shared_limits_handle_t SharedLimits;

    // Name used in traces
    char *Name;
} umf_disjoint_pool_params_t;

class DisjointPool {
  public:
    class AllocImpl;
    using Config = umf_disjoint_pool_params_t;

    umf_result_t initialize(umf_memory_provider_handle_t provider,
                            umf_disjoint_pool_params_handle_t parameters);
    void *malloc(size_t size);
    void *calloc(size_t, size_t);
    void *realloc(void *, size_t);
    void *aligned_malloc(size_t size, size_t alignment);
    size_t malloc_usable_size(void *);
    umf_result_t free(void *ptr);
    umf_result_t get_last_allocation_error();

    DisjointPool();
    ~DisjointPool();

  private:
    std::unique_ptr<AllocImpl> impl;
};

umf_disjoint_pool_shared_limits_t *
umfDisjointPoolSharedLimitsCreate(size_t MaxSize) {
    return new umf_disjoint_pool_shared_limits_t{MaxSize, 0};
}

void umfDisjointPoolSharedLimitsDestroy(
    umf_disjoint_pool_shared_limits_handle_t hSharedLimits) {
    delete hSharedLimits;
}

umf_result_t
umfDisjointPoolParamsCreate(umf_disjoint_pool_params_handle_t *hParams) {
    static const char *DEFAULT_NAME = "disjoint_pool";

    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    umf_disjoint_pool_params_handle_t params = new umf_disjoint_pool_params_t{};
    if (params == nullptr) {
        LOG_ERR("cannot allocate memory for disjoint pool params");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    params->SlabMinSize = 0;
    params->MaxPoolableSize = 0;
    params->Capacity = 0;
    params->MinBucketSize = UMF_DISJOINT_POOL_MIN_BUCKET_DEFAULT_SIZE;
    params->CurPoolSize = 0;
    params->PoolTrace = 0;
    params->SharedLimits = nullptr;
    params->Name = nullptr;

    umf_result_t ret = umfDisjointPoolParamsSetName(params, DEFAULT_NAME);
    if (ret != UMF_RESULT_SUCCESS) {
        delete params;
        return ret;
    }

    *hParams = params;

    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsDestroy(umf_disjoint_pool_params_handle_t hParams) {
    if (hParams) {
        delete[] hParams->Name;
        delete hParams;
    }

    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetSlabMinSize(umf_disjoint_pool_params_handle_t hParams,
                                    size_t slabMinSize) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->SlabMinSize = slabMinSize;
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfDisjointPoolParamsSetMaxPoolableSize(
    umf_disjoint_pool_params_handle_t hParams, size_t maxPoolableSize) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->MaxPoolableSize = maxPoolableSize;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetCapacity(umf_disjoint_pool_params_handle_t hParams,
                                 size_t maxCapacity) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->Capacity = maxCapacity;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetMinBucketSize(umf_disjoint_pool_params_handle_t hParams,
                                      size_t minBucketSize) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    // minBucketSize parameter must be a power of 2 and greater than 0.
    if (minBucketSize == 0 || (minBucketSize & (minBucketSize - 1))) {
        LOG_ERR("minBucketSize must be a power of 2 and greater than 0");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->MinBucketSize = minBucketSize;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetTrace(umf_disjoint_pool_params_handle_t hParams,
                              int poolTrace) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->PoolTrace = poolTrace;
    return UMF_RESULT_SUCCESS;
}

umf_result_t umfDisjointPoolParamsSetSharedLimits(
    umf_disjoint_pool_params_handle_t hParams,
    umf_disjoint_pool_shared_limits_handle_t hSharedLimits) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    hParams->SharedLimits = hSharedLimits;
    return UMF_RESULT_SUCCESS;
}

umf_result_t
umfDisjointPoolParamsSetName(umf_disjoint_pool_params_handle_t hParams,
                             const char *name) {
    if (!hParams) {
        LOG_ERR("disjoint pool params handle is NULL");
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    char *newName = new char[std::strlen(name) + 1];
    if (newName == nullptr) {
        LOG_ERR("cannot allocate memory for disjoint pool name");
        return UMF_RESULT_ERROR_OUT_OF_HOST_MEMORY;
    }

    delete[] hParams->Name;
    hParams->Name = newName;
    std::strcpy(hParams->Name, name);

    return UMF_RESULT_SUCCESS;
}

// Allocations are a minimum of 4KB/64KB/2MB even when a smaller size is
// requested. The implementation distinguishes between allocations of size
// ChunkCutOff = (minimum-alloc-size / 2) and those that are larger.
// Allocation requests smaller than ChunkCutoff use chunks taken from a single
// coarse-grain allocation. Thus, for example, for a 64KB minimum allocation
// size, and 8-byte allocations, only 1 in ~8000 requests results in a new
// coarse-grain allocation. Freeing results only in a chunk of a larger
// allocation to be marked as available and no real return to the system. An
// allocation is returned to the system only when all chunks in the larger
// allocation are freed by the program. Allocations larger than ChunkCutOff use
// a separate coarse-grain allocation for each request. These are subject to
// "pooling". That is, when such an allocation is freed by the program it is
// retained in a pool. The pool is available for future allocations, which means
// there are fewer actual coarse-grain allocations/deallocations.

// The largest size which is allocated via the allocator.
// Allocations with size > CutOff bypass the pool and
// go directly to the provider.
static constexpr size_t CutOff = (size_t)1 << 31; // 2GB

// Aligns the pointer down to the specified alignment
// (e.g. returns 8 for Size = 13, Alignment = 8)
static void *AlignPtrDown(void *Ptr, const size_t Alignment) {
    return reinterpret_cast<void *>((reinterpret_cast<size_t>(Ptr)) &
                                    (~(Alignment - 1)));
}

// Aligns the pointer up to the specified alignment
// (e.g. returns 16 for Size = 13, Alignment = 8)
static void *AlignPtrUp(void *Ptr, const size_t Alignment) {
    void *AlignedPtr = AlignPtrDown(Ptr, Alignment);
    // Special case when the pointer is already aligned
    if (Ptr == AlignedPtr) {
        return Ptr;
    }
    return static_cast<char *>(AlignedPtr) + Alignment;
}

// Aligns the value up to the specified alignment
// (e.g. returns 16 for Size = 13, Alignment = 8)
static size_t AlignUp(size_t Val, size_t Alignment) {
    assert(Alignment > 0);
    return (Val + Alignment - 1) & (~(Alignment - 1));
}

typedef struct MemoryProviderError {
    umf_result_t code;
} MemoryProviderError_t;

class Bucket;

// Represents the allocated memory block of size 'SlabMinSize'
// Internally, it splits the memory block into chunks. The number of
// chunks depends of the size of a Bucket which created the Slab.
// Note: Bucket's methods are responsible for thread safety of Slab access,
// so no locking happens here.
class Slab {

    // Pointer to the allocated memory of SlabMinSize bytes
    void *MemPtr;

    // Represents the current state of each chunk:
    // if the bit is set then the chunk is allocated
    // the chunk is free for allocation otherwise
    std::vector<bool> Chunks;

    // Total number of allocated chunks at the moment.
    size_t NumAllocated = 0;

    // The bucket which the slab belongs to
    Bucket &bucket;

    using ListIter = std::list<std::unique_ptr<Slab>>::iterator;

    // Store iterator to the corresponding node in avail/unavail list
    // to achieve O(1) removal
    ListIter SlabListIter;

    // Hints where to start search for free chunk in a slab
    size_t FirstFreeChunkIdx = 0;

    // Return the index of the first available chunk, SIZE_MAX otherwise
    size_t FindFirstAvailableChunkIdx() const;

    // Register/Unregister the slab in the global slab address map.
    void regSlab(Slab &);
    void unregSlab(Slab &);
    static void regSlabByAddr(void *, Slab &);
    static void unregSlabByAddr(void *, Slab &);

  public:
    Slab(Bucket &);
    ~Slab();

    void setIterator(ListIter It) { SlabListIter = It; }
    ListIter getIterator() const { return SlabListIter; }

    size_t getNumAllocated() const { return NumAllocated; }

    // Get pointer to allocation that is one piece of this slab.
    void *getChunk();

    // Get pointer to allocation that is this entire slab.
    void *getSlab();

    void *getPtr() const { return MemPtr; }
    void *getEnd() const;

    size_t getChunkSize() const;
    size_t getNumChunks() const { return Chunks.size(); }

    bool hasAvail();

    Bucket &getBucket();
    const Bucket &getBucket() const;

    void freeChunk(void *Ptr);
};

class Bucket {
    const size_t Size;

    // List of slabs which have at least 1 available chunk.
    std::list<std::unique_ptr<Slab>> AvailableSlabs;

    // List of slabs with 0 available chunk.
    std::list<std::unique_ptr<Slab>> UnavailableSlabs;

    // Protects the bucket and all the corresponding slabs
    std::mutex BucketLock;

    // Reference to the allocator context, used access memory allocation
    // routines, slab map and etc.
    DisjointPool::AllocImpl &OwnAllocCtx;

    // For buckets used in chunked mode, a counter of slabs in the pool.
    // For allocations that use an entire slab each, the entries in the Available
    // list are entries in the pool.Each slab is available for a new
    // allocation.The size of the Available list is the size of the pool.
    // For allocations that use slabs in chunked mode, slabs will be in the
    // Available list if any one or more of their chunks is free.The entire slab
    // is not necessarily free, just some chunks in the slab are free. To
    // implement pooling we will allow one slab in the Available list to be
    // entirely empty. Normally such a slab would have been freed. But
    // now we don't, and treat this slab as "in the pool".
    // When a slab becomes entirely free we have to decide whether to return it
    // to the provider or keep it allocated. A simple check for size of the
    // Available list is not sufficient to check whether any slab has been
    // pooled yet. We would have to traverse the entire Available list and check
    // if any of them is entirely free. Instead we keep a counter of entirely
    // empty slabs within the Available list to speed up the process of checking
    // if a slab in this bucket is already pooled.
    size_t chunkedSlabsInPool;

    // Statistics
    size_t allocPoolCount;
    size_t freeCount;
    size_t currSlabsInUse;
    size_t currSlabsInPool;
    size_t maxSlabsInPool;

  public:
    // Statistics
    size_t allocCount;
    size_t maxSlabsInUse;

    Bucket(size_t Sz, DisjointPool::AllocImpl &AllocCtx)
        : Size{Sz}, OwnAllocCtx{AllocCtx}, chunkedSlabsInPool(0),
          allocPoolCount(0), freeCount(0), currSlabsInUse(0),
          currSlabsInPool(0), maxSlabsInPool(0), allocCount(0),
          maxSlabsInUse(0) {}

    // Get pointer to allocation that is one piece of an available slab in this
    // bucket.
    void *getChunk(bool &FromPool);

    // Get pointer to allocation that is a full slab in this bucket.
    void *getSlab(bool &FromPool);

    // Return the allocation size of this bucket.
    size_t getSize() const { return Size; }

    // Free an allocation that is one piece of a slab in this bucket.
    void freeChunk(void *Ptr, Slab &Slab, bool &ToPool);

    // Free an allocation that is a full slab in this bucket.
    void freeSlab(Slab &Slab, bool &ToPool);

    umf_memory_provider_handle_t getMemHandle();

    DisjointPool::AllocImpl &getAllocCtx() { return OwnAllocCtx; }

    // Check whether an allocation to be freed can be placed in the pool.
    bool CanPool(bool &ToPool);

    // The minimum allocation size for any slab.
    size_t SlabMinSize();

    // The allocation size for a slab in this bucket.
    size_t SlabAllocSize();

    // The minimum size of a chunk from this bucket's slabs.
    size_t ChunkCutOff();

    // The number of slabs in this bucket that can be in the pool.
    size_t Capacity();

    // The maximum allocation size subject to pooling.
    size_t MaxPoolableSize();

    // Update allocation count
    void countAlloc(bool FromPool);

    // Update free count
    void countFree();

    // Update statistics of Available/Unavailable
    void updateStats(int InUse, int InPool);

    // Print bucket statistics
    void printStats(bool &TitlePrinted, const std::string &Label);

  private:
    void onFreeChunk(Slab &, bool &ToPool);

    // Update statistics of pool usage, and indicate that an allocation was made
    // from the pool.
    void decrementPool(bool &FromPool);

    // Get a slab to be used for chunked allocations.
    decltype(AvailableSlabs.begin()) getAvailSlab(bool &FromPool);

    // Get a slab that will be used as a whole for a single allocation.
    decltype(AvailableSlabs.begin()) getAvailFullSlab(bool &FromPool);
};

class DisjointPool::AllocImpl {
    // It's important for the map to be destroyed last after buckets and their
    // slabs This is because slab's destructor removes the object from the map.
    std::unordered_multimap<void *, Slab &> KnownSlabs;
    std::shared_timed_mutex KnownSlabsMapLock;

    // Handle to the memory provider
    umf_memory_provider_handle_t MemHandle;

    // Store as unique_ptrs since Bucket is not Movable(because of std::mutex)
    std::vector<std::unique_ptr<Bucket>> Buckets;

    // Configuration for this instance
    umf_disjoint_pool_params_t params;

    umf_disjoint_pool_shared_limits_t DefaultSharedLimits = {
        (std::numeric_limits<size_t>::max)(), 0};

    // Used in algorithm for finding buckets
    std::size_t MinBucketSizeExp;

    // Coarse-grain allocation min alignment
    size_t ProviderMinPageSize;

  public:
    AllocImpl(umf_memory_provider_handle_t hProvider,
              umf_disjoint_pool_params_handle_t params)
        : MemHandle{hProvider}, params(*params) {

        VALGRIND_DO_CREATE_MEMPOOL(this, 0, 0);

        // deep copy of the Name
        this->params.Name = new char[std::strlen(params->Name) + 1];
        std::strcpy(this->params.Name, params->Name);

        // Generate buckets sized such as: 64, 96, 128, 192, ..., CutOff.
        // Powers of 2 and the value halfway between the powers of 2.
        auto Size1 = this->params.MinBucketSize;
        // MinBucketSize cannot be larger than CutOff.
        Size1 = std::min(Size1, CutOff);
        // Buckets sized smaller than the bucket default size- 8 aren't needed.
        Size1 = std::max(Size1, UMF_DISJOINT_POOL_MIN_BUCKET_DEFAULT_SIZE);
        // Calculate the exponent for MinBucketSize used for finding buckets.
        MinBucketSizeExp = (size_t)log2Utils(Size1);
        auto Size2 = Size1 + Size1 / 2;
        for (; Size2 < CutOff; Size1 *= 2, Size2 *= 2) {
            Buckets.push_back(std::make_unique<Bucket>(Size1, *this));
            Buckets.push_back(std::make_unique<Bucket>(Size2, *this));
        }
        Buckets.push_back(std::make_unique<Bucket>(CutOff, *this));

        auto ret = umfMemoryProviderGetMinPageSize(hProvider, nullptr,
                                                   &ProviderMinPageSize);
        if (ret != UMF_RESULT_SUCCESS) {
            ProviderMinPageSize = 0;
        }
    }

    ~AllocImpl() {
        VALGRIND_DO_DESTROY_MEMPOOL(this);
        delete[] this->params.Name;
    }

    void *allocate(size_t Size, size_t Alignment, bool &FromPool);
    void *allocate(size_t Size, bool &FromPool);
    void deallocate(void *Ptr, bool &ToPool);

    umf_memory_provider_handle_t getMemHandle() { return MemHandle; }

    std::shared_timed_mutex &getKnownSlabsMapLock() {
        return KnownSlabsMapLock;
    }
    std::unordered_multimap<void *, Slab &> &getKnownSlabs() {
        return KnownSlabs;
    }

    size_t SlabMinSize() { return params.SlabMinSize; };

    umf_disjoint_pool_params_t &getParams() { return params; }

    umf_disjoint_pool_shared_limits_t *getLimits() {
        if (params.SharedLimits) {
            return params.SharedLimits;
        } else {
            return &DefaultSharedLimits;
        }
    };

    void printStats(bool &TitlePrinted, size_t &HighBucketSize,
                    size_t &HighPeakSlabsInUse, const std::string &Label);

  private:
    Bucket &findBucket(size_t Size);
    std::size_t sizeToIdx(size_t Size);
};

static void *memoryProviderAlloc(umf_memory_provider_handle_t hProvider,
                                 size_t size, size_t alignment = 0) {
    void *ptr;
    auto ret = umfMemoryProviderAlloc(hProvider, size, alignment, &ptr);
    if (ret != UMF_RESULT_SUCCESS) {
        throw MemoryProviderError{ret};
    }
    annotate_memory_inaccessible(ptr, size);
    return ptr;
}

static void memoryProviderFree(umf_memory_provider_handle_t hProvider,
                               void *ptr) {
    size_t size = 0;

    if (ptr) {
        umf_alloc_info_t allocInfo = {NULL, 0, NULL};
        umf_result_t umf_result = umfMemoryTrackerGetAllocInfo(ptr, &allocInfo);
        if (umf_result == UMF_RESULT_SUCCESS) {
            size = allocInfo.baseSize;
        }
    }

    auto ret = umfMemoryProviderFree(hProvider, ptr, size);
    if (ret != UMF_RESULT_SUCCESS) {
        throw MemoryProviderError{ret};
    }
}

bool operator==(const Slab &Lhs, const Slab &Rhs) {
    return Lhs.getPtr() == Rhs.getPtr();
}

std::ostream &operator<<(std::ostream &Os, const Slab &Slab) {
    Os << "Slab<" << Slab.getPtr() << ", " << Slab.getEnd() << ", "
       << Slab.getBucket().getSize() << ">";
    return Os;
}

Slab::Slab(Bucket &Bkt)
    : // In case bucket size is not a multiple of SlabMinSize, we would have
      // some padding at the end of the slab.
      Chunks(Bkt.SlabMinSize() / Bkt.getSize()), NumAllocated{0},
      bucket(Bkt), SlabListIter{}, FirstFreeChunkIdx{0} {
    auto SlabSize = Bkt.SlabAllocSize();
    MemPtr = memoryProviderAlloc(Bkt.getMemHandle(), SlabSize);
    regSlab(*this);
}

Slab::~Slab() {
    try {
        unregSlab(*this);
    } catch (std::exception &e) {
        LOG_ERR("DisjointPool: unexpected error: %s", e.what());
    }

    try {
        memoryProviderFree(bucket.getMemHandle(), MemPtr);
    } catch (MemoryProviderError &e) {
        LOG_ERR("DisjointPool: error from memory provider: %d", e.code);

        if (e.code == UMF_RESULT_ERROR_MEMORY_PROVIDER_SPECIFIC) {
            const char *message = "";
            int error = 0;

            try {
                umfMemoryProviderGetLastNativeError(
                    umfGetLastFailedMemoryProvider(), &message, &error);
                LOG_ERR("Native error msg: %s, native error code: %d", message,
                        error);
            } catch (...) {
                // ignore any additional errors from logger
            }
        }
    }
}

// Return the index of the first available chunk, SIZE_MAX otherwise
size_t Slab::FindFirstAvailableChunkIdx() const {
    // Use the first free chunk index as a hint for the search.
    auto It = std::find_if(Chunks.begin() + FirstFreeChunkIdx, Chunks.end(),
                           [](auto x) { return !x; });
    if (It != Chunks.end()) {
        return It - Chunks.begin();
    }

    return std::numeric_limits<size_t>::max();
}

void *Slab::getChunk() {
    // assert(NumAllocated != Chunks.size());

    const size_t ChunkIdx = FindFirstAvailableChunkIdx();
    // Free chunk must exist, otherwise we would have allocated another slab
    assert(ChunkIdx != (std::numeric_limits<size_t>::max()));

    void *const FreeChunk =
        (static_cast<uint8_t *>(getPtr())) + ChunkIdx * getChunkSize();
    Chunks[ChunkIdx] = true;
    NumAllocated += 1;

    // Use the found index as the next hint
    FirstFreeChunkIdx = ChunkIdx;

    return FreeChunk;
}

void *Slab::getSlab() { return getPtr(); }

Bucket &Slab::getBucket() { return bucket; }
const Bucket &Slab::getBucket() const { return bucket; }

size_t Slab::getChunkSize() const { return bucket.getSize(); }

void Slab::regSlabByAddr(void *Addr, Slab &Slab) {
    auto &Lock = Slab.getBucket().getAllocCtx().getKnownSlabsMapLock();
    auto &Map = Slab.getBucket().getAllocCtx().getKnownSlabs();

    std::lock_guard<std::shared_timed_mutex> Lg(Lock);
    Map.insert({Addr, Slab});
}

void Slab::unregSlabByAddr(void *Addr, Slab &Slab) {
    auto &Lock = Slab.getBucket().getAllocCtx().getKnownSlabsMapLock();
    auto &Map = Slab.getBucket().getAllocCtx().getKnownSlabs();

    std::lock_guard<std::shared_timed_mutex> Lg(Lock);

    auto Slabs = Map.equal_range(Addr);
    // At least the must get the current slab from the map.
    assert(Slabs.first != Slabs.second && "Slab is not found");

    for (auto It = Slabs.first; It != Slabs.second; ++It) {
        if (It->second == Slab) {
            Map.erase(It);
            return;
        }
    }

    assert(false && "Slab is not found");
}

void Slab::regSlab(Slab &Slab) {
    void *StartAddr = AlignPtrDown(Slab.getPtr(), bucket.SlabMinSize());
    void *EndAddr = static_cast<char *>(StartAddr) + bucket.SlabMinSize();

    regSlabByAddr(StartAddr, Slab);
    regSlabByAddr(EndAddr, Slab);
}

void Slab::unregSlab(Slab &Slab) {
    void *StartAddr = AlignPtrDown(Slab.getPtr(), bucket.SlabMinSize());
    void *EndAddr = static_cast<char *>(StartAddr) + bucket.SlabMinSize();

    unregSlabByAddr(StartAddr, Slab);
    unregSlabByAddr(EndAddr, Slab);
}

void Slab::freeChunk(void *Ptr) {
    // This method should be called through bucket(since we might remove the slab
    // as a result), therefore all locks are done on that level.

    // Make sure that we're in the right slab
    assert(Ptr >= getPtr() && Ptr < getEnd());

    // Even if the pointer p was previously aligned, it's still inside the
    // corresponding chunk, so we get the correct index here.
    auto ChunkIdx = (static_cast<char *>(Ptr) - static_cast<char *>(MemPtr)) /
                    getChunkSize();

    // Make sure that the chunk was allocated
    assert(Chunks[ChunkIdx] && "double free detected");

    Chunks[ChunkIdx] = false;
    NumAllocated -= 1;

    if (ChunkIdx < FirstFreeChunkIdx) {
        FirstFreeChunkIdx = ChunkIdx;
    }
}

void *Slab::getEnd() const {
    return static_cast<char *>(getPtr()) + bucket.SlabMinSize();
}

bool Slab::hasAvail() { return NumAllocated != getNumChunks(); }

// If a slab was available in the pool then note that the current pooled
// size has reduced by the size of a slab in this bucket.
void Bucket::decrementPool(bool &FromPool) {
    FromPool = true;
    updateStats(1, -1);
    OwnAllocCtx.getLimits()->TotalSize -= SlabAllocSize();
}

auto Bucket::getAvailFullSlab(bool &FromPool)
    -> decltype(AvailableSlabs.begin()) {
    // Return a slab that will be used for a single allocation.
    if (AvailableSlabs.size() == 0) {
        auto It = AvailableSlabs.insert(AvailableSlabs.begin(),
                                        std::make_unique<Slab>(*this));
        (*It)->setIterator(It);
        FromPool = false;
        updateStats(1, 0);
    } else {
        decrementPool(FromPool);
    }

    return AvailableSlabs.begin();
}

void *Bucket::getSlab(bool &FromPool) {
    std::lock_guard<std::mutex> Lg(BucketLock);

    auto SlabIt = getAvailFullSlab(FromPool);
    auto *FreeSlab = (*SlabIt)->getSlab();
    auto It =
        UnavailableSlabs.insert(UnavailableSlabs.begin(), std::move(*SlabIt));
    AvailableSlabs.erase(SlabIt);
    (*It)->setIterator(It);
    return FreeSlab;
}

void Bucket::freeSlab(Slab &Slab, bool &ToPool) {
    std::lock_guard<std::mutex> Lg(BucketLock);
    auto SlabIter = Slab.getIterator();
    assert(SlabIter != UnavailableSlabs.end());
    if (CanPool(ToPool)) {
        auto It =
            AvailableSlabs.insert(AvailableSlabs.begin(), std::move(*SlabIter));
        UnavailableSlabs.erase(SlabIter);
        (*It)->setIterator(It);
    } else {
        UnavailableSlabs.erase(SlabIter);
    }
}

auto Bucket::getAvailSlab(bool &FromPool) -> decltype(AvailableSlabs.begin()) {

    if (AvailableSlabs.size() == 0) {
        auto It = AvailableSlabs.insert(AvailableSlabs.begin(),
                                        std::make_unique<Slab>(*this));
        (*It)->setIterator(It);

        updateStats(1, 0);
        FromPool = false;
    } else {
        if ((*(AvailableSlabs.begin()))->getNumAllocated() == 0) {
            // If this was an empty slab, it was in the pool.
            // Now it is no longer in the pool, so update count.
            --chunkedSlabsInPool;
            decrementPool(FromPool);
        } else {
            // Allocation from existing slab is treated as from pool for statistics.
            FromPool = true;
        }
    }

    return AvailableSlabs.begin();
}

void *Bucket::getChunk(bool &FromPool) {
    std::lock_guard<std::mutex> Lg(BucketLock);

    auto SlabIt = getAvailSlab(FromPool);
    auto *FreeChunk = (*SlabIt)->getChunk();

    // If the slab is full, move it to unavailable slabs and update its iterator
    if (!((*SlabIt)->hasAvail())) {
        auto It = UnavailableSlabs.insert(UnavailableSlabs.begin(),
                                          std::move(*SlabIt));
        AvailableSlabs.erase(SlabIt);
        (*It)->setIterator(It);
    }

    return FreeChunk;
}

void Bucket::freeChunk(void *Ptr, Slab &Slab, bool &ToPool) {
    std::lock_guard<std::mutex> Lg(BucketLock);

    Slab.freeChunk(Ptr);

    onFreeChunk(Slab, ToPool);
}

// The lock must be acquired before calling this method
void Bucket::onFreeChunk(Slab &Slab, bool &ToPool) {
    ToPool = true;

    // In case if the slab was previously full and now has 1 available
    // chunk, it should be moved to the list of available slabs
    if (Slab.getNumAllocated() == (Slab.getNumChunks() - 1)) {
        auto SlabIter = Slab.getIterator();
        assert(SlabIter != UnavailableSlabs.end());

        auto It =
            AvailableSlabs.insert(AvailableSlabs.begin(), std::move(*SlabIter));
        UnavailableSlabs.erase(SlabIter);

        (*It)->setIterator(It);
    }

    // Check if slab is empty, and pool it if we can.
    if (Slab.getNumAllocated() == 0) {
        // The slab is now empty.
        // If pool has capacity then put the slab in the pool.
        // The ToPool parameter indicates whether the Slab will be put in the
        // pool or freed.
        if (!CanPool(ToPool)) {
            // Note: since the slab is stored as unique_ptr, just remove it from
            // the list to destroy the object.
            auto It = Slab.getIterator();
            assert(It != AvailableSlabs.end());
            AvailableSlabs.erase(It);
        }
    }
}

bool Bucket::CanPool(bool &ToPool) {
    size_t NewFreeSlabsInBucket;
    // Check if this bucket is used in chunked form or as full slabs.
    bool chunkedBucket = getSize() <= ChunkCutOff();
    if (chunkedBucket) {
        NewFreeSlabsInBucket = chunkedSlabsInPool + 1;
    } else {
        NewFreeSlabsInBucket = AvailableSlabs.size() + 1;
    }
    if (Capacity() >= NewFreeSlabsInBucket) {
        size_t PoolSize = OwnAllocCtx.getLimits()->TotalSize;
        while (true) {
            size_t NewPoolSize = PoolSize + SlabAllocSize();

            if (OwnAllocCtx.getLimits()->MaxSize < NewPoolSize) {
                break;
            }

            if (OwnAllocCtx.getLimits()->TotalSize.compare_exchange_strong(
                    PoolSize, NewPoolSize)) {
                if (chunkedBucket) {
                    ++chunkedSlabsInPool;
                }

                updateStats(-1, 1);
                ToPool = true;
                return true;
            }
        }
    }

    updateStats(-1, 0);
    ToPool = false;
    return false;
}

umf_memory_provider_handle_t Bucket::getMemHandle() {
    return OwnAllocCtx.getMemHandle();
}

size_t Bucket::SlabMinSize() { return OwnAllocCtx.getParams().SlabMinSize; }

size_t Bucket::SlabAllocSize() { return std::max(getSize(), SlabMinSize()); }

size_t Bucket::Capacity() {
    // For buckets used in chunked mode, just one slab in pool is sufficient.
    // For larger buckets, the capacity could be more and is adjustable.
    if (getSize() <= ChunkCutOff()) {
        return 1;
    } else {
        return OwnAllocCtx.getParams().Capacity;
    }
}

size_t Bucket::MaxPoolableSize() {
    return OwnAllocCtx.getParams().MaxPoolableSize;
}

size_t Bucket::ChunkCutOff() { return SlabMinSize() / 2; }

void Bucket::countAlloc(bool FromPool) {
    ++allocCount;
    if (FromPool) {
        ++allocPoolCount;
    }
}

void Bucket::countFree() { ++freeCount; }

void Bucket::updateStats(int InUse, int InPool) {
    if (OwnAllocCtx.getParams().PoolTrace == 0) {
        return;
    }
    currSlabsInUse += InUse;
    maxSlabsInUse = std::max(currSlabsInUse, maxSlabsInUse);
    currSlabsInPool += InPool;
    maxSlabsInPool = std::max(currSlabsInPool, maxSlabsInPool);
    // Increment or decrement current pool sizes based on whether
    // slab was added to or removed from pool.
    OwnAllocCtx.getParams().CurPoolSize += InPool * SlabAllocSize();
}

void Bucket::printStats(bool &TitlePrinted, const std::string &Label) {
    if (allocCount) {
        if (!TitlePrinted) {
            std::cout << Label << " memory statistics\n";
            std::cout << std::setw(14) << "Bucket Size" << std::setw(12)
                      << "Allocs" << std::setw(12) << "Frees" << std::setw(18)
                      << "Allocs from Pool" << std::setw(20)
                      << "Peak Slabs in Use" << std::setw(21)
                      << "Peak Slabs in Pool" << std::endl;
            TitlePrinted = true;
        }
        std::cout << std::setw(14) << getSize() << std::setw(12) << allocCount
                  << std::setw(12) << freeCount << std::setw(18)
                  << allocPoolCount << std::setw(20) << maxSlabsInUse
                  << std::setw(21) << maxSlabsInPool << std::endl;
    }
}

void *DisjointPool::AllocImpl::allocate(size_t Size, bool &FromPool) try {
    void *Ptr;

    if (Size == 0) {
        return nullptr;
    }

    FromPool = false;
    if (Size > getParams().MaxPoolableSize) {
        Ptr = memoryProviderAlloc(getMemHandle(), Size);
        annotate_memory_undefined(Ptr, Size);
        return Ptr;
    }

    auto &Bucket = findBucket(Size);

    if (Size > Bucket.ChunkCutOff()) {
        Ptr = Bucket.getSlab(FromPool);
    } else {
        Ptr = Bucket.getChunk(FromPool);
    }

    if (getParams().PoolTrace > 1) {
        Bucket.countAlloc(FromPool);
    }

    VALGRIND_DO_MEMPOOL_ALLOC(this, Ptr, Size);
    annotate_memory_undefined(Ptr, Bucket.getSize());

    return Ptr;
} catch (MemoryProviderError &e) {
    umf::getPoolLastStatusRef<DisjointPool>() = e.code;
    return nullptr;
}

void *DisjointPool::AllocImpl::allocate(size_t Size, size_t Alignment,
                                        bool &FromPool) try {
    void *Ptr;

    if (Size == 0) {
        return nullptr;
    }

    if (Alignment <= 1) {
        return allocate(Size, FromPool);
    }

    size_t AlignedSize;
    if (Alignment <= ProviderMinPageSize) {
        // This allocation will be served from a Bucket which size is multiple
        // of Alignment and Slab address is aligned to ProviderMinPageSize
        // so the address will be properly aligned.
        AlignedSize = (Size > 1) ? AlignUp(Size, Alignment) : Alignment;
    } else {
        // Slabs are only aligned to ProviderMinPageSize, we need to compensate
        // for that in case the allocation is within pooling limit.
        // TODO: consider creating properly-aligned Slabs on demand
        AlignedSize = Size + Alignment - 1;
    }

    // Check if requested allocation size is within pooling limit.
    // If not, just request aligned pointer from the system.
    FromPool = false;
    if (AlignedSize > getParams().MaxPoolableSize) {
        Ptr = memoryProviderAlloc(getMemHandle(), Size, Alignment);
        annotate_memory_undefined(Ptr, Size);
        return Ptr;
    }

    auto &Bucket = findBucket(AlignedSize);

    if (AlignedSize > Bucket.ChunkCutOff()) {
        Ptr = Bucket.getSlab(FromPool);
    } else {
        Ptr = Bucket.getChunk(FromPool);
    }

    if (getParams().PoolTrace > 1) {
        Bucket.countAlloc(FromPool);
    }

    VALGRIND_DO_MEMPOOL_ALLOC(this, AlignPtrUp(Ptr, Alignment), Size);
    annotate_memory_undefined(AlignPtrUp(Ptr, Alignment), Size);
    return AlignPtrUp(Ptr, Alignment);
} catch (MemoryProviderError &e) {
    umf::getPoolLastStatusRef<DisjointPool>() = e.code;
    return nullptr;
}

std::size_t DisjointPool::AllocImpl::sizeToIdx(size_t Size) {
    assert(Size <= CutOff && "Unexpected size");
    assert(Size > 0 && "Unexpected size");

    size_t MinBucketSize = (size_t)1 << MinBucketSizeExp;
    if (Size < MinBucketSize) {
        return 0;
    }

    // Get the position of the leftmost set bit.
    size_t position = getLeftmostSetBitPos(Size);

    auto isPowerOf2 = 0 == (Size & (Size - 1));
    auto largerThanHalfwayBetweenPowersOf2 =
        !isPowerOf2 && bool((Size - 1) & (uint64_t(1) << (position - 1)));
    auto index = (position - MinBucketSizeExp) * 2 + (int)(!isPowerOf2) +
                 (int)largerThanHalfwayBetweenPowersOf2;

    return index;
}

Bucket &DisjointPool::AllocImpl::findBucket(size_t Size) {
    auto calculatedIdx = sizeToIdx(Size);
    assert((*(Buckets[calculatedIdx])).getSize() >= Size);
    if (calculatedIdx > 0) {
        assert((*(Buckets[calculatedIdx - 1])).getSize() < Size);
    }

    return *(Buckets[calculatedIdx]);
}

void DisjointPool::AllocImpl::deallocate(void *Ptr, bool &ToPool) {
    auto *SlabPtr = AlignPtrDown(Ptr, SlabMinSize());

    // Lock the map on read
    std::shared_lock<std::shared_timed_mutex> Lk(getKnownSlabsMapLock());

    ToPool = false;
    auto Slabs = getKnownSlabs().equal_range(SlabPtr);
    if (Slabs.first == Slabs.second) {
        Lk.unlock();
        memoryProviderFree(getMemHandle(), Ptr);
        return;
    }

    for (auto It = Slabs.first; It != Slabs.second; ++It) {
        // The slab object won't be deleted until it's removed from the map which is
        // protected by the lock, so it's safe to access it here.
        auto &Slab = It->second;
        if (Ptr >= Slab.getPtr() && Ptr < Slab.getEnd()) {
            // Unlock the map before freeing the chunk, it may be locked on write
            // there
            Lk.unlock();
            auto &Bucket = Slab.getBucket();

            if (getParams().PoolTrace > 1) {
                Bucket.countFree();
            }

            VALGRIND_DO_MEMPOOL_FREE(this, Ptr);
            annotate_memory_inaccessible(Ptr, Bucket.getSize());
            if (Bucket.getSize() <= Bucket.ChunkCutOff()) {
                Bucket.freeChunk(Ptr, Slab, ToPool);
            } else {
                Bucket.freeSlab(Slab, ToPool);
            }

            return;
        }
    }

    Lk.unlock();
    // There is a rare case when we have a pointer from system allocation next
    // to some slab with an entry in the map. So we find a slab
    // but the range checks fail.
    memoryProviderFree(getMemHandle(), Ptr);
}

void DisjointPool::AllocImpl::printStats(bool &TitlePrinted,
                                         size_t &HighBucketSize,
                                         size_t &HighPeakSlabsInUse,
                                         const std::string &MTName) {
    HighBucketSize = 0;
    HighPeakSlabsInUse = 0;
    for (auto &B : Buckets) {
        (*B).printStats(TitlePrinted, MTName);
        HighPeakSlabsInUse = std::max((*B).maxSlabsInUse, HighPeakSlabsInUse);
        if ((*B).allocCount) {
            HighBucketSize = std::max((*B).SlabAllocSize(), HighBucketSize);
        }
    }
}

umf_result_t
DisjointPool::initialize(umf_memory_provider_handle_t provider,
                         umf_disjoint_pool_params_handle_t parameters) {
    if (!provider) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }
    // MinBucketSize parameter must be a power of 2 for bucket sizes
    // to generate correctly.
    if (!parameters->MinBucketSize ||
        !((parameters->MinBucketSize & (parameters->MinBucketSize - 1)) == 0)) {
        return UMF_RESULT_ERROR_INVALID_ARGUMENT;
    }

    impl = std::make_unique<AllocImpl>(provider, parameters);
    return UMF_RESULT_SUCCESS;
}

void *DisjointPool::malloc(size_t size) { // For full-slab allocations indicates
                                          // whether slab is from Pool.
    bool FromPool;
    auto Ptr = impl->allocate(size, FromPool);

    if (impl->getParams().PoolTrace > 2) {
        auto MT = impl->getParams().Name;
        std::cout << "Allocated " << std::setw(8) << size << " " << MT
                  << " bytes from " << (FromPool ? "Pool" : "Provider") << " ->"
                  << Ptr << std::endl;
    }
    return Ptr;
}

void *DisjointPool::calloc(size_t, size_t) {
    // Not supported
    umf::getPoolLastStatusRef<DisjointPool>() = UMF_RESULT_ERROR_NOT_SUPPORTED;
    return NULL;
}

void *DisjointPool::realloc(void *, size_t) {
    // Not supported
    umf::getPoolLastStatusRef<DisjointPool>() = UMF_RESULT_ERROR_NOT_SUPPORTED;
    return NULL;
}

void *DisjointPool::aligned_malloc(size_t size, size_t alignment) {
    bool FromPool;
    auto Ptr = impl->allocate(size, alignment, FromPool);

    if (impl->getParams().PoolTrace > 2) {
        auto MT = impl->getParams().Name;
        std::cout << "Allocated " << std::setw(8) << size << " " << MT
                  << " bytes aligned at " << alignment << " from "
                  << (FromPool ? "Pool" : "Provider") << " ->" << Ptr
                  << std::endl;
    }
    return Ptr;
}

size_t DisjointPool::malloc_usable_size(void *) {
    // Not supported
    return 0;
}

umf_result_t DisjointPool::free(void *ptr) try {
    bool ToPool;
    impl->deallocate(ptr, ToPool);

    if (impl->getParams().PoolTrace > 2) {
        auto MT = impl->getParams().Name;
        std::cout << "Freed " << MT << " " << ptr << " to "
                  << (ToPool ? "Pool" : "Provider")
                  << ", Current total pool size "
                  << impl->getLimits()->TotalSize.load()
                  << ", Current pool size for " << MT << " "
                  << impl->getParams().CurPoolSize << "\n";
    }
    return UMF_RESULT_SUCCESS;
} catch (MemoryProviderError &e) {
    return e.code;
}

umf_result_t DisjointPool::get_last_allocation_error() {
    return umf::getPoolLastStatusRef<DisjointPool>();
}

DisjointPool::DisjointPool() {}

// Define destructor for use with unique_ptr
DisjointPool::~DisjointPool() {
    bool TitlePrinted = false;
    size_t HighBucketSize;
    size_t HighPeakSlabsInUse;
    if (impl->getParams().PoolTrace > 1) {
        auto name = impl->getParams().Name;
        try { // cannot throw in destructor
            impl->printStats(TitlePrinted, HighBucketSize, HighPeakSlabsInUse,
                             name);
            if (TitlePrinted) {
                std::cout << "Current Pool Size "
                          << impl->getLimits()->TotalSize.load() << std::endl;
                std::cout << "Suggested Setting=;"
                          << std::string(1, (char)tolower(name[0]))
                          << std::string(name + 1) << ":" << HighBucketSize
                          << "," << HighPeakSlabsInUse << ",64K" << std::endl;
            }
        } catch (...) { // ignore exceptions
        }
    }
}

static umf_memory_pool_ops_t UMF_DISJOINT_POOL_OPS =
    umf::poolMakeCOps<DisjointPool, umf_disjoint_pool_params_t>();

umf_memory_pool_ops_t *umfDisjointPoolOps(void) {
    return &UMF_DISJOINT_POOL_OPS;
}
