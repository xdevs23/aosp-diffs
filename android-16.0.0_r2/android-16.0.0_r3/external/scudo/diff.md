```diff
diff --git a/Android.bp b/Android.bp
index ce57fa5..073b6cc 100644
--- a/Android.bp
+++ b/Android.bp
@@ -258,6 +258,9 @@ cc_defaults {
         "-Wno-unreachable-code-loop-increment",
         "-DSCUDO_DEBUG=1",
         "-DSCUDO_NO_TEST_MAIN",
+        // Fortify might interfere with the expectations of the Scudo tests,
+        // so disable fortify.
+        "-U_FORTIFY_SOURCE",
     ],
     target: {
         bionic: {
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be..cfa5095 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -5,4 +5,3 @@ clang_format = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/standalone/allocator_config.def b/standalone/allocator_config.def
index 43893e9..84fcec0 100644
--- a/standalone/allocator_config.def
+++ b/standalone/allocator_config.def
@@ -81,6 +81,10 @@ PRIMARY_REQUIRED(const s32, MaxReleaseToOsIntervalMs)
 
 // PRIMARY_OPTIONAL(TYPE, NAME, DEFAULT)
 //
+
+// Enables/disables primary block caching. Batch class still caches.
+PRIMARY_OPTIONAL(const bool, EnableBlockCache, true)
+
 // The scale of a compact pointer. E.g., Ptr = Base + (CompactPtr << Scale).
 PRIMARY_OPTIONAL(const uptr, CompactPtrScale, SCUDO_MIN_ALIGNMENT_LOG)
 
diff --git a/standalone/combined.h b/standalone/combined.h
index 5deb8c9..4365564 100644
--- a/standalone/combined.h
+++ b/standalone/combined.h
@@ -15,7 +15,6 @@
 #include "common.h"
 #include "flags.h"
 #include "flags_parser.h"
-#include "local_cache.h"
 #include "mem_map.h"
 #include "memtag.h"
 #include "mutex.h"
@@ -23,6 +22,7 @@
 #include "quarantine.h"
 #include "report.h"
 #include "secondary.h"
+#include "size_class_allocator.h"
 #include "stack_depot.h"
 #include "string_utils.h"
 #include "tsd.h"
@@ -54,7 +54,7 @@ public:
       typename AllocatorConfig::template PrimaryT<PrimaryConfig<Config>>;
   using SecondaryT =
       typename AllocatorConfig::template SecondaryT<SecondaryConfig<Config>>;
-  using CacheT = typename PrimaryT::CacheT;
+  using SizeClassAllocatorT = typename PrimaryT::SizeClassAllocatorT;
   typedef Allocator<Config, PostInitCallback> ThisT;
   typedef typename AllocatorConfig::template TSDRegistryT<ThisT> TSDRegistryT;
 
@@ -63,8 +63,9 @@ public:
   }
 
   struct QuarantineCallback {
-    explicit QuarantineCallback(ThisT &Instance, CacheT &LocalCache)
-        : Allocator(Instance), Cache(LocalCache) {}
+    explicit QuarantineCallback(ThisT &Instance,
+                                SizeClassAllocatorT &SizeClassAllocator)
+        : Allocator(Instance), SizeClassAllocator(SizeClassAllocator) {}
 
     // Chunk recycling function, returns a quarantined chunk to the backend,
     // first making sure it hasn't been tampered with.
@@ -80,7 +81,7 @@ public:
       if (allocatorSupportsMemoryTagging<AllocatorConfig>())
         Ptr = untagPointer(Ptr);
       void *BlockBegin = Allocator::getBlockBegin(Ptr, &Header);
-      Cache.deallocate(Header.ClassId, BlockBegin);
+      SizeClassAllocator.deallocate(Header.ClassId, BlockBegin);
     }
 
     // We take a shortcut when allocating a quarantine batch by working with the
@@ -89,7 +90,7 @@ public:
     void *allocate(UNUSED uptr Size) {
       const uptr QuarantineClassId = SizeClassMap::getClassIdBySize(
           sizeof(QuarantineBatch) + Chunk::getHeaderSize());
-      void *Ptr = Cache.allocate(QuarantineClassId);
+      void *Ptr = SizeClassAllocator.allocate(QuarantineClassId);
       // Quarantine batch allocation failure is fatal.
       if (UNLIKELY(!Ptr))
         reportOutOfMemory(SizeClassMap::getSizeByClassId(QuarantineClassId));
@@ -126,14 +127,15 @@ public:
 
       Header.State = Chunk::State::Available;
       Chunk::storeHeader(Allocator.Cookie, Ptr, &Header);
-      Cache.deallocate(QuarantineClassId,
-                       reinterpret_cast<void *>(reinterpret_cast<uptr>(Ptr) -
-                                                Chunk::getHeaderSize()));
+      SizeClassAllocator.deallocate(
+          QuarantineClassId,
+          reinterpret_cast<void *>(reinterpret_cast<uptr>(Ptr) -
+                                   Chunk::getHeaderSize()));
     }
 
   private:
     ThisT &Allocator;
-    CacheT &Cache;
+    SizeClassAllocatorT &SizeClassAllocator;
   };
 
   typedef GlobalQuarantine<QuarantineCallback, void> QuarantineT;
@@ -263,7 +265,9 @@ public:
   QuarantineT *getQuarantine() { return &Quarantine; }
 
   // The Cache must be provided zero-initialized.
-  void initCache(CacheT *Cache) { Cache->init(&Stats, &Primary); }
+  void initAllocator(SizeClassAllocatorT *SizeClassAllocator) {
+    SizeClassAllocator->init(&Stats, &Primary);
+  }
 
   // Release the resources used by a TSD, which involves:
   // - draining the local quarantine cache to the global quarantine;
@@ -273,15 +277,16 @@ public:
   void commitBack(TSD<ThisT> *TSD) {
     TSD->assertLocked(/*BypassCheck=*/true);
     Quarantine.drain(&TSD->getQuarantineCache(),
-                     QuarantineCallback(*this, TSD->getCache()));
-    TSD->getCache().destroy(&Stats);
+                     QuarantineCallback(*this, TSD->getSizeClassAllocator()));
+    TSD->getSizeClassAllocator().destroy(&Stats);
   }
 
   void drainCache(TSD<ThisT> *TSD) {
     TSD->assertLocked(/*BypassCheck=*/true);
-    Quarantine.drainAndRecycle(&TSD->getQuarantineCache(),
-                               QuarantineCallback(*this, TSD->getCache()));
-    TSD->getCache().drain();
+    Quarantine.drainAndRecycle(
+        &TSD->getQuarantineCache(),
+        QuarantineCallback(*this, TSD->getSizeClassAllocator()));
+    TSD->getSizeClassAllocator().drain();
   }
   void drainCaches() { TSDRegistry.drainCaches(this); }
 
@@ -390,13 +395,13 @@ public:
       ClassId = SizeClassMap::getClassIdBySize(NeededSize);
       DCHECK_NE(ClassId, 0U);
       typename TSDRegistryT::ScopedTSD TSD(TSDRegistry);
-      Block = TSD->getCache().allocate(ClassId);
+      Block = TSD->getSizeClassAllocator().allocate(ClassId);
       // If the allocation failed, retry in each successively larger class until
       // it fits. If it fails to fit in the largest class, fallback to the
       // Secondary.
       if (UNLIKELY(!Block)) {
         while (ClassId < SizeClassMap::LargestClassId && !Block)
-          Block = TSD->getCache().allocate(++ClassId);
+          Block = TSD->getSizeClassAllocator().allocate(++ClassId);
         if (!Block)
           ClassId = 0;
       }
@@ -1280,7 +1285,8 @@ private:
         bool CacheDrained;
         {
           typename TSDRegistryT::ScopedTSD TSD(TSDRegistry);
-          CacheDrained = TSD->getCache().deallocate(ClassId, BlockBegin);
+          CacheDrained =
+              TSD->getSizeClassAllocator().deallocate(ClassId, BlockBegin);
         }
         // When we have drained some blocks back to the Primary from TSD, that
         // implies that we may have the chance to release some pages as well.
@@ -1296,7 +1302,8 @@ private:
         retagBlock(Options, TaggedPtr, Ptr, Header, Size, false);
       typename TSDRegistryT::ScopedTSD TSD(TSDRegistry);
       Quarantine.put(&TSD->getQuarantineCache(),
-                     QuarantineCallback(*this, TSD->getCache()), Ptr, Size);
+                     QuarantineCallback(*this, TSD->getSizeClassAllocator()),
+                     Ptr, Size);
     }
   }
 
diff --git a/standalone/primary32.h b/standalone/primary32.h
index 596c48f..0932d47 100644
--- a/standalone/primary32.h
+++ b/standalone/primary32.h
@@ -13,10 +13,10 @@
 #include "bytemap.h"
 #include "common.h"
 #include "list.h"
-#include "local_cache.h"
 #include "options.h"
 #include "release.h"
 #include "report.h"
+#include "size_class_allocator.h"
 #include "stats.h"
 #include "string_utils.h"
 #include "thread_annotations.h"
@@ -52,7 +52,10 @@ public:
   static_assert((1UL << Config::getRegionSizeLog()) >= SizeClassMap::MaxSize,
                 "");
   typedef SizeClassAllocator32<Config> ThisT;
-  typedef SizeClassAllocatorLocalCache<ThisT> CacheT;
+  using SizeClassAllocatorT =
+      typename Conditional<Config::getEnableBlockCache(),
+                           SizeClassAllocatorLocalCache<ThisT>,
+                           SizeClassAllocatorNoCache<ThisT>>::type;
   typedef TransferBatch<ThisT> TransferBatchT;
   typedef BatchGroup<ThisT> BatchGroupT;
 
@@ -191,17 +194,19 @@ public:
     return BlockSize > PageSize;
   }
 
-  u16 popBlocks(CacheT *C, uptr ClassId, CompactPtrT *ToArray,
-                const u16 MaxBlockCount) {
+  u16 popBlocks(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                CompactPtrT *ToArray, const u16 MaxBlockCount) {
     DCHECK_LT(ClassId, NumClasses);
     SizeClassInfo *Sci = getSizeClassInfo(ClassId);
     ScopedLock L(Sci->Mutex);
 
-    u16 PopCount = popBlocksImpl(C, ClassId, Sci, ToArray, MaxBlockCount);
+    u16 PopCount =
+        popBlocksImpl(SizeClassAllocator, ClassId, Sci, ToArray, MaxBlockCount);
     if (UNLIKELY(PopCount == 0)) {
-      if (UNLIKELY(!populateFreeList(C, ClassId, Sci)))
+      if (UNLIKELY(!populateFreeList(SizeClassAllocator, ClassId, Sci)))
         return 0U;
-      PopCount = popBlocksImpl(C, ClassId, Sci, ToArray, MaxBlockCount);
+      PopCount = popBlocksImpl(SizeClassAllocator, ClassId, Sci, ToArray,
+                               MaxBlockCount);
       DCHECK_NE(PopCount, 0U);
     }
 
@@ -209,7 +214,8 @@ public:
   }
 
   // Push the array of free blocks to the designated batch group.
-  void pushBlocks(CacheT *C, uptr ClassId, CompactPtrT *Array, u32 Size) {
+  void pushBlocks(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                  CompactPtrT *Array, u32 Size) {
     DCHECK_LT(ClassId, NumClasses);
     DCHECK_GT(Size, 0);
 
@@ -240,7 +246,7 @@ public:
     }
 
     ScopedLock L(Sci->Mutex);
-    pushBlocksImpl(C, ClassId, Sci, Array, Size, SameGroup);
+    pushBlocksImpl(SizeClassAllocator, ClassId, Sci, Array, Size, SameGroup);
   }
 
   void disable() NO_THREAD_SAFETY_ANALYSIS {
@@ -529,8 +535,8 @@ private:
       // memory group here.
       BG->CompactPtrGroupBase = 0;
       BG->BytesInBGAtLastCheckpoint = 0;
-      BG->MaxCachedPerBatch =
-          CacheT::getMaxCached(getSizeByClassId(SizeClassMap::BatchClassId));
+      BG->MaxCachedPerBatch = SizeClassAllocatorT::getMaxCached(
+          getSizeByClassId(SizeClassMap::BatchClassId));
 
       Sci->FreeListInfo.BlockList.push_front(BG);
     }
@@ -597,18 +603,18 @@ private:
   // same group then we will skip checking the group id of each block.
   //
   // The region mutex needs to be held while calling this method.
-  void pushBlocksImpl(CacheT *C, uptr ClassId, SizeClassInfo *Sci,
-                      CompactPtrT *Array, u32 Size, bool SameGroup = false)
-      REQUIRES(Sci->Mutex) {
+  void pushBlocksImpl(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                      SizeClassInfo *Sci, CompactPtrT *Array, u32 Size,
+                      bool SameGroup = false) REQUIRES(Sci->Mutex) {
     DCHECK_NE(ClassId, SizeClassMap::BatchClassId);
     DCHECK_GT(Size, 0U);
 
     auto CreateGroup = [&](uptr CompactPtrGroupBase) {
-      BatchGroupT *BG =
-          reinterpret_cast<BatchGroupT *>(C->getBatchClassBlock());
+      BatchGroupT *BG = reinterpret_cast<BatchGroupT *>(
+          SizeClassAllocator->getBatchClassBlock());
       BG->Batches.clear();
-      TransferBatchT *TB =
-          reinterpret_cast<TransferBatchT *>(C->getBatchClassBlock());
+      TransferBatchT *TB = reinterpret_cast<TransferBatchT *>(
+          SizeClassAllocator->getBatchClassBlock());
       TB->clear();
 
       BG->CompactPtrGroupBase = CompactPtrGroupBase;
@@ -629,8 +635,8 @@ private:
         u16 UnusedSlots =
             static_cast<u16>(BG->MaxCachedPerBatch - CurBatch->getCount());
         if (UnusedSlots == 0) {
-          CurBatch =
-              reinterpret_cast<TransferBatchT *>(C->getBatchClassBlock());
+          CurBatch = reinterpret_cast<TransferBatchT *>(
+              SizeClassAllocator->getBatchClassBlock());
           CurBatch->clear();
           Batches.push_front(CurBatch);
           UnusedSlots = BG->MaxCachedPerBatch;
@@ -704,9 +710,9 @@ private:
     InsertBlocks(Cur, Array + Size - Count, Count);
   }
 
-  u16 popBlocksImpl(CacheT *C, uptr ClassId, SizeClassInfo *Sci,
-                    CompactPtrT *ToArray, const u16 MaxBlockCount)
-      REQUIRES(Sci->Mutex) {
+  u16 popBlocksImpl(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                    SizeClassInfo *Sci, CompactPtrT *ToArray,
+                    const u16 MaxBlockCount) REQUIRES(Sci->Mutex) {
     if (Sci->FreeListInfo.BlockList.empty())
       return 0U;
 
@@ -730,11 +736,11 @@ private:
     // So far, instead of always filling the blocks to `MaxBlockCount`, we only
     // examine single `TransferBatch` to minimize the time spent on the primary
     // allocator. Besides, the sizes of `TransferBatch` and
-    // `CacheT::getMaxCached()` may also impact the time spent on accessing the
-    // primary allocator.
+    // `SizeClassAllocatorT::getMaxCached()` may also impact the time spent on
+    // accessing the primary allocator.
     // TODO(chiahungduan): Evaluate if we want to always prepare `MaxBlockCount`
     // blocks and/or adjust the size of `TransferBatch` according to
-    // `CacheT::getMaxCached()`.
+    // `SizeClassAllocatorT::getMaxCached()`.
     TransferBatchT *B = Batches.front();
     DCHECK_NE(B, nullptr);
     DCHECK_GT(B->getCount(), 0U);
@@ -754,7 +760,7 @@ private:
       // deallocate. Read the comment in `pushBatchClassBlocks()` for more
       // details.
       if (ClassId != SizeClassMap::BatchClassId)
-        C->deallocate(SizeClassMap::BatchClassId, B);
+        SizeClassAllocator->deallocate(SizeClassMap::BatchClassId, B);
 
       if (Batches.empty()) {
         BatchGroupT *BG = Sci->FreeListInfo.BlockList.front();
@@ -766,7 +772,7 @@ private:
         // Which means, once we pop the last TransferBatch, the block is
         // implicitly deallocated.
         if (ClassId != SizeClassMap::BatchClassId)
-          C->deallocate(SizeClassMap::BatchClassId, BG);
+          SizeClassAllocator->deallocate(SizeClassMap::BatchClassId, BG);
       }
     }
 
@@ -774,7 +780,8 @@ private:
     return PopCount;
   }
 
-  NOINLINE bool populateFreeList(CacheT *C, uptr ClassId, SizeClassInfo *Sci)
+  NOINLINE bool populateFreeList(SizeClassAllocatorT *SizeClassAllocator,
+                                 uptr ClassId, SizeClassInfo *Sci)
       REQUIRES(Sci->Mutex) {
     uptr Region;
     uptr Offset;
@@ -791,13 +798,13 @@ private:
       Region = allocateRegion(Sci, ClassId);
       if (UNLIKELY(!Region))
         return false;
-      C->getStats().add(StatMapped, RegionSize);
+      SizeClassAllocator->getStats().add(StatMapped, RegionSize);
       Sci->CurrentRegion = Region;
       Offset = 0;
     }
 
     const uptr Size = getSizeByClassId(ClassId);
-    const u16 MaxCount = CacheT::getMaxCached(Size);
+    const u16 MaxCount = SizeClassAllocatorT::getMaxCached(Size);
     DCHECK_GT(MaxCount, 0U);
     // The maximum number of blocks we should carve in the region is dictated
     // by the maximum number of batches we want to fill, and the amount of
@@ -827,7 +834,8 @@ private:
       for (u32 I = 1; I < NumberOfBlocks; I++) {
         if (UNLIKELY(compactPtrGroupBase(ShuffleArray[I]) != CurGroup)) {
           shuffle(ShuffleArray + I - N, N, &Sci->RandState);
-          pushBlocksImpl(C, ClassId, Sci, ShuffleArray + I - N, N,
+          pushBlocksImpl(SizeClassAllocator, ClassId, Sci, ShuffleArray + I - N,
+                         N,
                          /*SameGroup=*/true);
           N = 1;
           CurGroup = compactPtrGroupBase(ShuffleArray[I]);
@@ -837,7 +845,8 @@ private:
       }
 
       shuffle(ShuffleArray + NumberOfBlocks - N, N, &Sci->RandState);
-      pushBlocksImpl(C, ClassId, Sci, &ShuffleArray[NumberOfBlocks - N], N,
+      pushBlocksImpl(SizeClassAllocator, ClassId, Sci,
+                     &ShuffleArray[NumberOfBlocks - N], N,
                      /*SameGroup=*/true);
     } else {
       pushBatchClassBlocks(Sci, ShuffleArray, NumberOfBlocks);
@@ -850,7 +859,7 @@ private:
     Sci->FreeListInfo.PushedBlocks -= NumberOfBlocks;
 
     const uptr AllocatedUser = Size * NumberOfBlocks;
-    C->getStats().add(StatFree, AllocatedUser);
+    SizeClassAllocator->getStats().add(StatFree, AllocatedUser);
     DCHECK_LE(Sci->CurrentRegionAllocated + AllocatedUser, RegionSize);
     // If there is not enough room in the region currently associated to fit
     // more blocks, we deassociate the region by resetting CurrentRegion and
diff --git a/standalone/primary64.h b/standalone/primary64.h
index e7da849..25ee999 100644
--- a/standalone/primary64.h
+++ b/standalone/primary64.h
@@ -14,11 +14,11 @@
 #include "common.h"
 #include "condition_variable.h"
 #include "list.h"
-#include "local_cache.h"
 #include "mem_map.h"
 #include "memtag.h"
 #include "options.h"
 #include "release.h"
+#include "size_class_allocator.h"
 #include "stats.h"
 #include "string_utils.h"
 #include "thread_annotations.h"
@@ -57,9 +57,12 @@ public:
                 "Group size shouldn't be greater than the region size");
   static const uptr GroupScale = GroupSizeLog - CompactPtrScale;
   typedef SizeClassAllocator64<Config> ThisT;
-  typedef SizeClassAllocatorLocalCache<ThisT> CacheT;
   typedef TransferBatch<ThisT> TransferBatchT;
   typedef BatchGroup<ThisT> BatchGroupT;
+  using SizeClassAllocatorT =
+      typename Conditional<Config::getEnableBlockCache(),
+                           SizeClassAllocatorLocalCache<ThisT>,
+                           SizeClassAllocatorNoCache<ThisT>>::type;
 
   // BachClass is used to store internal metadata so it needs to be at least as
   // large as the largest data structure.
@@ -215,15 +218,16 @@ public:
     DCHECK_EQ(BlocksInUse, BatchClassUsedInFreeLists);
   }
 
-  u16 popBlocks(CacheT *C, uptr ClassId, CompactPtrT *ToArray,
-                const u16 MaxBlockCount) {
+  u16 popBlocks(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                CompactPtrT *ToArray, const u16 MaxBlockCount) {
     DCHECK_LT(ClassId, NumClasses);
     RegionInfo *Region = getRegionInfo(ClassId);
     u16 PopCount = 0;
 
     {
       ScopedLock L(Region->FLLock);
-      PopCount = popBlocksImpl(C, ClassId, Region, ToArray, MaxBlockCount);
+      PopCount = popBlocksImpl(SizeClassAllocator, ClassId, Region, ToArray,
+                               MaxBlockCount);
       if (PopCount != 0U)
         return PopCount;
     }
@@ -231,8 +235,8 @@ public:
     bool ReportRegionExhausted = false;
 
     if (conditionVariableEnabled()) {
-      PopCount = popBlocksWithCV(C, ClassId, Region, ToArray, MaxBlockCount,
-                                 ReportRegionExhausted);
+      PopCount = popBlocksWithCV(SizeClassAllocator, ClassId, Region, ToArray,
+                                 MaxBlockCount, ReportRegionExhausted);
     } else {
       while (true) {
         // When two threads compete for `Region->MMLock`, we only want one of
@@ -241,15 +245,16 @@ public:
         ScopedLock ML(Region->MMLock);
         {
           ScopedLock FL(Region->FLLock);
-          PopCount = popBlocksImpl(C, ClassId, Region, ToArray, MaxBlockCount);
+          PopCount = popBlocksImpl(SizeClassAllocator, ClassId, Region, ToArray,
+                                   MaxBlockCount);
           if (PopCount != 0U)
             return PopCount;
         }
 
         const bool RegionIsExhausted = Region->Exhausted;
         if (!RegionIsExhausted) {
-          PopCount = populateFreeListAndPopBlocks(C, ClassId, Region, ToArray,
-                                                  MaxBlockCount);
+          PopCount = populateFreeListAndPopBlocks(
+              SizeClassAllocator, ClassId, Region, ToArray, MaxBlockCount);
         }
         ReportRegionExhausted = !RegionIsExhausted && Region->Exhausted;
         break;
@@ -270,7 +275,8 @@ public:
   }
 
   // Push the array of free blocks to the designated batch group.
-  void pushBlocks(CacheT *C, uptr ClassId, CompactPtrT *Array, u32 Size) {
+  void pushBlocks(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                  CompactPtrT *Array, u32 Size) {
     DCHECK_LT(ClassId, NumClasses);
     DCHECK_GT(Size, 0);
 
@@ -305,7 +311,8 @@ public:
 
     {
       ScopedLock L(Region->FLLock);
-      pushBlocksImpl(C, ClassId, Region, Array, Size, SameGroup);
+      pushBlocksImpl(SizeClassAllocator, ClassId, Region, Array, Size,
+                     SameGroup);
       if (conditionVariableEnabled())
         Region->FLLockCV.notifyAll(Region->FLLock);
     }
@@ -697,8 +704,8 @@ private:
       // memory group here.
       BG->CompactPtrGroupBase = 0;
       BG->BytesInBGAtLastCheckpoint = 0;
-      BG->MaxCachedPerBatch =
-          CacheT::getMaxCached(getSizeByClassId(SizeClassMap::BatchClassId));
+      BG->MaxCachedPerBatch = SizeClassAllocatorT::getMaxCached(
+          getSizeByClassId(SizeClassMap::BatchClassId));
 
       Region->FreeListInfo.BlockList.push_front(BG);
     }
@@ -764,18 +771,18 @@ private:
   // that we can get better performance of maintaining sorted property.
   // Use `SameGroup=true` to indicate that all blocks in the array are from the
   // same group then we will skip checking the group id of each block.
-  void pushBlocksImpl(CacheT *C, uptr ClassId, RegionInfo *Region,
-                      CompactPtrT *Array, u32 Size, bool SameGroup = false)
-      REQUIRES(Region->FLLock) {
+  void pushBlocksImpl(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                      RegionInfo *Region, CompactPtrT *Array, u32 Size,
+                      bool SameGroup = false) REQUIRES(Region->FLLock) {
     DCHECK_NE(ClassId, SizeClassMap::BatchClassId);
     DCHECK_GT(Size, 0U);
 
     auto CreateGroup = [&](uptr CompactPtrGroupBase) {
-      BatchGroupT *BG =
-          reinterpret_cast<BatchGroupT *>(C->getBatchClassBlock());
+      BatchGroupT *BG = reinterpret_cast<BatchGroupT *>(
+          SizeClassAllocator->getBatchClassBlock());
       BG->Batches.clear();
-      TransferBatchT *TB =
-          reinterpret_cast<TransferBatchT *>(C->getBatchClassBlock());
+      TransferBatchT *TB = reinterpret_cast<TransferBatchT *>(
+          SizeClassAllocator->getBatchClassBlock());
       TB->clear();
 
       BG->CompactPtrGroupBase = CompactPtrGroupBase;
@@ -796,8 +803,8 @@ private:
         u16 UnusedSlots =
             static_cast<u16>(BG->MaxCachedPerBatch - CurBatch->getCount());
         if (UnusedSlots == 0) {
-          CurBatch =
-              reinterpret_cast<TransferBatchT *>(C->getBatchClassBlock());
+          CurBatch = reinterpret_cast<TransferBatchT *>(
+              SizeClassAllocator->getBatchClassBlock());
           CurBatch->clear();
           Batches.push_front(CurBatch);
           UnusedSlots = BG->MaxCachedPerBatch;
@@ -871,9 +878,9 @@ private:
     InsertBlocks(Cur, Array + Size - Count, Count);
   }
 
-  u16 popBlocksWithCV(CacheT *C, uptr ClassId, RegionInfo *Region,
-                      CompactPtrT *ToArray, const u16 MaxBlockCount,
-                      bool &ReportRegionExhausted) {
+  u16 popBlocksWithCV(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                      RegionInfo *Region, CompactPtrT *ToArray,
+                      const u16 MaxBlockCount, bool &ReportRegionExhausted) {
     u16 PopCount = 0;
 
     while (true) {
@@ -895,8 +902,8 @@ private:
 
         const bool RegionIsExhausted = Region->Exhausted;
         if (!RegionIsExhausted) {
-          PopCount = populateFreeListAndPopBlocks(C, ClassId, Region, ToArray,
-                                                  MaxBlockCount);
+          PopCount = populateFreeListAndPopBlocks(
+              SizeClassAllocator, ClassId, Region, ToArray, MaxBlockCount);
         }
         ReportRegionExhausted = !RegionIsExhausted && Region->Exhausted;
 
@@ -924,7 +931,8 @@ private:
       // blocks were used up right after the refillment. Therefore, we have to
       // check if someone is still populating the freelist.
       ScopedLock FL(Region->FLLock);
-      PopCount = popBlocksImpl(C, ClassId, Region, ToArray, MaxBlockCount);
+      PopCount = popBlocksImpl(SizeClassAllocator, ClassId, Region, ToArray,
+                               MaxBlockCount);
       if (PopCount != 0U)
         break;
 
@@ -938,7 +946,8 @@ private:
       // `pushBatchClassBlocks()` and `mergeGroupsToReleaseBack()`.
       Region->FLLockCV.wait(Region->FLLock);
 
-      PopCount = popBlocksImpl(C, ClassId, Region, ToArray, MaxBlockCount);
+      PopCount = popBlocksImpl(SizeClassAllocator, ClassId, Region, ToArray,
+                               MaxBlockCount);
       if (PopCount != 0U)
         break;
     }
@@ -946,9 +955,9 @@ private:
     return PopCount;
   }
 
-  u16 popBlocksImpl(CacheT *C, uptr ClassId, RegionInfo *Region,
-                    CompactPtrT *ToArray, const u16 MaxBlockCount)
-      REQUIRES(Region->FLLock) {
+  u16 popBlocksImpl(SizeClassAllocatorT *SizeClassAllocator, uptr ClassId,
+                    RegionInfo *Region, CompactPtrT *ToArray,
+                    const u16 MaxBlockCount) REQUIRES(Region->FLLock) {
     if (Region->FreeListInfo.BlockList.empty())
       return 0U;
 
@@ -972,11 +981,11 @@ private:
     // So far, instead of always filling blocks to `MaxBlockCount`, we only
     // examine single `TransferBatch` to minimize the time spent in the primary
     // allocator. Besides, the sizes of `TransferBatch` and
-    // `CacheT::getMaxCached()` may also impact the time spent on accessing the
-    // primary allocator.
+    // `SizeClassAllocatorT::getMaxCached()` may also impact the time spent on
+    // accessing the primary allocator.
     // TODO(chiahungduan): Evaluate if we want to always prepare `MaxBlockCount`
     // blocks and/or adjust the size of `TransferBatch` according to
-    // `CacheT::getMaxCached()`.
+    // `SizeClassAllocatorT::getMaxCached()`.
     TransferBatchT *B = Batches.front();
     DCHECK_NE(B, nullptr);
     DCHECK_GT(B->getCount(), 0U);
@@ -996,7 +1005,7 @@ private:
       // deallocate. Read the comment in `pushBatchClassBlocks()` for more
       // details.
       if (ClassId != SizeClassMap::BatchClassId)
-        C->deallocate(SizeClassMap::BatchClassId, B);
+        SizeClassAllocator->deallocate(SizeClassMap::BatchClassId, B);
 
       if (Batches.empty()) {
         BatchGroupT *BG = Region->FreeListInfo.BlockList.front();
@@ -1008,7 +1017,7 @@ private:
         // Which means, once we pop the last TransferBatch, the block is
         // implicitly deallocated.
         if (ClassId != SizeClassMap::BatchClassId)
-          C->deallocate(SizeClassMap::BatchClassId, BG);
+          SizeClassAllocator->deallocate(SizeClassMap::BatchClassId, BG);
       }
     }
 
@@ -1017,11 +1026,10 @@ private:
     return PopCount;
   }
 
-  NOINLINE u16 populateFreeListAndPopBlocks(CacheT *C, uptr ClassId,
-                                            RegionInfo *Region,
-                                            CompactPtrT *ToArray,
-                                            const u16 MaxBlockCount)
-      REQUIRES(Region->MMLock) EXCLUDES(Region->FLLock) {
+  NOINLINE u16 populateFreeListAndPopBlocks(
+      SizeClassAllocatorT *SizeClassAllocator, uptr ClassId, RegionInfo *Region,
+      CompactPtrT *ToArray, const u16 MaxBlockCount) REQUIRES(Region->MMLock)
+      EXCLUDES(Region->FLLock) {
     if (!Config::getEnableContiguousRegions() &&
         !Region->MemMapInfo.MemMap.isAllocated()) {
       ReservedMemoryT ReservedMemory;
@@ -1040,7 +1048,7 @@ private:
 
     DCHECK(Region->MemMapInfo.MemMap.isAllocated());
     const uptr Size = getSizeByClassId(ClassId);
-    const u16 MaxCount = CacheT::getMaxCached(Size);
+    const u16 MaxCount = SizeClassAllocatorT::getMaxCached(Size);
     const uptr RegionBeg = Region->RegionBeg;
     const uptr MappedUser = Region->MemMapInfo.MappedUser;
     const uptr TotalUserBytes =
@@ -1064,7 +1072,7 @@ private:
         return 0U;
       }
       Region->MemMapInfo.MappedUser += MapSize;
-      C->getStats().add(StatMapped, MapSize);
+      SizeClassAllocator->getStats().add(StatMapped, MapSize);
     }
 
     const u32 NumberOfBlocks =
@@ -1092,7 +1100,8 @@ private:
       for (u32 I = 1; I < NumberOfBlocks; I++) {
         if (UNLIKELY(compactPtrGroup(ShuffleArray[I]) != CurGroup)) {
           shuffle(ShuffleArray + I - N, N, &Region->RandState);
-          pushBlocksImpl(C, ClassId, Region, ShuffleArray + I - N, N,
+          pushBlocksImpl(SizeClassAllocator, ClassId, Region,
+                         ShuffleArray + I - N, N,
                          /*SameGroup=*/true);
           N = 1;
           CurGroup = compactPtrGroup(ShuffleArray[I]);
@@ -1102,14 +1111,15 @@ private:
       }
 
       shuffle(ShuffleArray + NumberOfBlocks - N, N, &Region->RandState);
-      pushBlocksImpl(C, ClassId, Region, &ShuffleArray[NumberOfBlocks - N], N,
+      pushBlocksImpl(SizeClassAllocator, ClassId, Region,
+                     &ShuffleArray[NumberOfBlocks - N], N,
                      /*SameGroup=*/true);
     } else {
       pushBatchClassBlocks(Region, ShuffleArray, NumberOfBlocks);
     }
 
-    const u16 PopCount =
-        popBlocksImpl(C, ClassId, Region, ToArray, MaxBlockCount);
+    const u16 PopCount = popBlocksImpl(SizeClassAllocator, ClassId, Region,
+                                       ToArray, MaxBlockCount);
     DCHECK_NE(PopCount, 0U);
 
     // Note that `PushedBlocks` and `PoppedBlocks` are supposed to only record
@@ -1119,7 +1129,7 @@ private:
     Region->FreeListInfo.PushedBlocks -= NumberOfBlocks;
 
     const uptr AllocatedUser = Size * NumberOfBlocks;
-    C->getStats().add(StatFree, AllocatedUser);
+    SizeClassAllocator->getStats().add(StatFree, AllocatedUser);
     Region->MemMapInfo.AllocatedUser += AllocatedUser;
 
     return PopCount;
diff --git a/standalone/secondary.h b/standalone/secondary.h
index f3f91c4..286e5d3 100644
--- a/standalone/secondary.h
+++ b/standalone/secondary.h
@@ -206,11 +206,13 @@ public:
     computePercentage(SuccessfulRetrieves, CallsToRetrieve, &Integral,
                       &Fractional);
     const s32 Interval = atomic_load_relaxed(&ReleaseToOsIntervalMs);
-    Str->append(
-        "Stats: MapAllocatorCache: EntriesCount: %zu, "
-        "MaxEntriesCount: %u, MaxEntrySize: %zu, ReleaseToOsIntervalMs = %d\n",
-        LRUEntries.size(), atomic_load_relaxed(&MaxEntriesCount),
-        atomic_load_relaxed(&MaxEntrySize), Interval >= 0 ? Interval : -1);
+    Str->append("Stats: MapAllocatorCache: EntriesCount: %zu, "
+                "MaxEntriesCount: %u, MaxEntrySize: %zu, ReleaseToOsSkips: "
+                "%zu, ReleaseToOsIntervalMs = %d\n",
+                LRUEntries.size(), atomic_load_relaxed(&MaxEntriesCount),
+                atomic_load_relaxed(&MaxEntrySize),
+                atomic_load_relaxed(&ReleaseToOsSkips),
+                Interval >= 0 ? Interval : -1);
     Str->append("Stats: CacheRetrievalStats: SuccessRate: %u/%u "
                 "(%zu.%02zu%%)\n",
                 SuccessfulRetrieves, CallsToRetrieve, Integral, Fractional);
@@ -343,8 +345,15 @@ public:
       unmapCallBack(EvictMemMap);
 
     if (Interval >= 0) {
-      // TODO: Add ReleaseToOS logic to LRU algorithm
-      releaseOlderThan(Time - static_cast<u64>(Interval) * 1000000);
+      // It is very likely that multiple threads trying to do a release at the
+      // same time will not actually release any extra elements. Therefore,
+      // let any other thread continue, skipping the release.
+      if (Mutex.tryLock()) {
+        // TODO: Add ReleaseToOS logic to LRU algorithm
+        releaseOlderThan(Time - static_cast<u64>(Interval) * 1000000);
+        Mutex.unlock();
+      } else
+        atomic_fetch_add(&ReleaseToOsSkips, 1U, memory_order_relaxed);
     }
   }
 
@@ -488,7 +497,12 @@ public:
     return true;
   }
 
-  void releaseToOS() { releaseOlderThan(UINT64_MAX); }
+  void releaseToOS() EXCLUDES(Mutex) {
+    // Since this is a request to release everything, always wait for the
+    // lock so that we guarantee all entries are released after this call.
+    ScopedLock L(Mutex);
+    releaseOlderThan(UINT64_MAX);
+  }
 
   void disableMemoryTagging() EXCLUDES(Mutex) {
     ScopedLock L(Mutex);
@@ -554,8 +568,7 @@ private:
     Entry.Time = 0;
   }
 
-  void releaseOlderThan(u64 Time) EXCLUDES(Mutex) {
-    ScopedLock L(Mutex);
+  void releaseOlderThan(u64 Time) REQUIRES(Mutex) {
     if (!LRUEntries.size() || OldestTime == 0 || OldestTime > Time)
       return;
     OldestTime = 0;
@@ -573,6 +586,7 @@ private:
   atomic_s32 ReleaseToOsIntervalMs = {};
   u32 CallsToRetrieve GUARDED_BY(Mutex) = 0;
   u32 SuccessfulRetrieves GUARDED_BY(Mutex) = 0;
+  atomic_uptr ReleaseToOsSkips = {};
 
   CachedBlock Entries[Config::getEntriesArraySize()] GUARDED_BY(Mutex) = {};
   NonZeroLengthArray<CachedBlock, Config::getQuarantineSize()>
diff --git a/standalone/local_cache.h b/standalone/size_class_allocator.h
similarity index 53%
rename from standalone/local_cache.h
rename to standalone/size_class_allocator.h
index 46d6aff..7c7d630 100644
--- a/standalone/local_cache.h
+++ b/standalone/size_class_allocator.h
@@ -1,4 +1,4 @@
-//===-- local_cache.h -------------------------------------------*- C++ -*-===//
+//===-- size_class_allocator.h ----------------------------------*- C++ -*-===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,8 +6,8 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef SCUDO_LOCAL_CACHE_H_
-#define SCUDO_LOCAL_CACHE_H_
+#ifndef SCUDO_SIZE_CLASS_ALLOCATOR_H_
+#define SCUDO_SIZE_CLASS_ALLOCATOR_H_
 
 #include "internal_defs.h"
 #include "list.h"
@@ -28,7 +28,7 @@ template <class SizeClassAllocator> struct SizeClassAllocatorLocalCache {
     if (LIKELY(S))
       S->link(&Stats);
     Allocator = A;
-    initCache();
+    initAllocator();
   }
 
   void destroy(GlobalStats *S) {
@@ -112,7 +112,7 @@ template <class SizeClassAllocator> struct SizeClassAllocatorLocalCache {
 
       EmptyCache = false;
       // The size of BatchClass is set to 0 intentionally. See the comment in
-      // initCache() for more details.
+      // initAllocator() for more details.
       const uptr ClassSize = I == BatchClassId
                                  ? SizeClassAllocator::getSizeByClassId(I)
                                  : PerClassArray[I].ClassSize;
@@ -146,7 +146,7 @@ private:
   LocalStats Stats;
   SizeClassAllocator *Allocator = nullptr;
 
-  NOINLINE void initCache() {
+  NOINLINE void initAllocator() {
     for (uptr I = 0; I < NumClasses; I++) {
       PerClass *P = &PerClassArray[I];
       const uptr Size = SizeClassAllocator::getSizeByClassId(I);
@@ -161,11 +161,6 @@ private:
     }
   }
 
-  void destroyBatch(uptr ClassId, void *B) {
-    if (ClassId != BatchClassId)
-      deallocate(BatchClassId, B);
-  }
-
   NOINLINE bool refill(PerClass *C, uptr ClassId, u16 MaxRefill) {
     const u16 NumBlocksRefilled =
         Allocator->popBlocks(this, ClassId, C->Chunks, MaxRefill);
@@ -184,6 +179,148 @@ private:
   }
 };
 
+template <class SizeClassAllocator> struct SizeClassAllocatorNoCache {
+  typedef typename SizeClassAllocator::SizeClassMap SizeClassMap;
+  typedef typename SizeClassAllocator::CompactPtrT CompactPtrT;
+
+  void init(GlobalStats *S, SizeClassAllocator *A) {
+    Stats.init();
+    if (LIKELY(S))
+      S->link(&Stats);
+    Allocator = A;
+    initAllocator();
+  }
+
+  void destroy(GlobalStats *S) {
+    if (LIKELY(S))
+      S->unlink(&Stats);
+  }
+
+  void *allocate(uptr ClassId) {
+    CompactPtrT CompactPtr;
+    uptr NumBlocksPopped = Allocator->popBlocks(this, ClassId, &CompactPtr, 1U);
+    if (NumBlocksPopped == 0)
+      return nullptr;
+    DCHECK_EQ(NumBlocksPopped, 1U);
+    const PerClass *C = &PerClassArray[ClassId];
+    Stats.add(StatAllocated, C->ClassSize);
+    Stats.sub(StatFree, C->ClassSize);
+    return Allocator->decompactPtr(ClassId, CompactPtr);
+  }
+
+  bool deallocate(uptr ClassId, void *P) {
+    CHECK_LT(ClassId, NumClasses);
+
+    if (ClassId == BatchClassId)
+      return deallocateBatchClassBlock(P);
+
+    CompactPtrT CompactPtr =
+        Allocator->compactPtr(ClassId, reinterpret_cast<uptr>(P));
+    Allocator->pushBlocks(this, ClassId, &CompactPtr, 1U);
+    PerClass *C = &PerClassArray[ClassId];
+    Stats.sub(StatAllocated, C->ClassSize);
+    Stats.add(StatFree, C->ClassSize);
+
+    // The following adopts the same strategy of allocator draining as used
+    // in SizeClassAllocatorLocalCache so that use the same hint when doing
+    // a page release.
+    ++C->Count;
+    const bool SuggestDraining = C->Count >= C->MaxCount;
+    if (SuggestDraining)
+      C->Count = 0;
+    return SuggestDraining;
+  }
+
+  void *getBatchClassBlock() {
+    PerClass *C = &PerClassArray[BatchClassId];
+    if (C->Count == 0) {
+      const u16 NumBlocksRefilled = Allocator->popBlocks(
+          this, BatchClassId, BatchClassStorage, C->MaxCount);
+      if (NumBlocksRefilled == 0)
+        reportOutOfMemory(SizeClassAllocator::getSizeByClassId(BatchClassId));
+      DCHECK_LE(NumBlocksRefilled, SizeClassMap::MaxNumCachedHint);
+      C->Count = NumBlocksRefilled;
+    }
+
+    const uptr ClassSize = C->ClassSize;
+    CompactPtrT CompactP = BatchClassStorage[--C->Count];
+    Stats.add(StatAllocated, ClassSize);
+    Stats.sub(StatFree, ClassSize);
+
+    return Allocator->decompactPtr(BatchClassId, CompactP);
+  }
+
+  LocalStats &getStats() { return Stats; }
+
+  void getStats(ScopedString *Str) { Str->append("    No block is cached.\n"); }
+
+  bool isEmpty() const {
+    const PerClass *C = &PerClassArray[BatchClassId];
+    return C->Count == 0;
+  }
+  void drain() {
+    PerClass *C = &PerClassArray[BatchClassId];
+    if (C->Count > 0) {
+      Allocator->pushBlocks(this, BatchClassId, BatchClassStorage, C->Count);
+      C->Count = 0;
+    }
+  }
+
+  static u16 getMaxCached(uptr Size) {
+    return Min(SizeClassMap::MaxNumCachedHint,
+               SizeClassMap::getMaxCachedHint(Size));
+  }
+
+private:
+  static const uptr NumClasses = SizeClassMap::NumClasses;
+  static const uptr BatchClassId = SizeClassMap::BatchClassId;
+  struct alignas(SCUDO_CACHE_LINE_SIZE) PerClass {
+    u16 Count = 0;
+    u16 MaxCount;
+    // Note: ClassSize is zero for the transfer batch.
+    uptr ClassSize;
+  };
+  PerClass PerClassArray[NumClasses] = {};
+  // Popping BatchClass blocks requires taking a certain amount of blocks at
+  // once. This restriction comes from how we manage the storing of BatchClass
+  // in the primary allocator. See more details in `popBlocksImpl` in the
+  // primary allocator.
+  CompactPtrT BatchClassStorage[SizeClassMap::MaxNumCachedHint] = {};
+  LocalStats Stats;
+  SizeClassAllocator *Allocator = nullptr;
+
+  bool deallocateBatchClassBlock(void *P) {
+    PerClass *C = &PerClassArray[BatchClassId];
+    // Drain all the blocks.
+    if (C->Count >= C->MaxCount) {
+      Allocator->pushBlocks(this, BatchClassId, BatchClassStorage, C->Count);
+      C->Count = 0;
+    }
+    BatchClassStorage[C->Count++] =
+        Allocator->compactPtr(BatchClassId, reinterpret_cast<uptr>(P));
+
+    // Currently, BatchClass doesn't support page releasing, so we always return
+    // false.
+    return false;
+  }
+
+  NOINLINE void initAllocator() {
+    for (uptr I = 0; I < NumClasses; I++) {
+      PerClass *P = &PerClassArray[I];
+      const uptr Size = SizeClassAllocator::getSizeByClassId(I);
+      if (I != BatchClassId) {
+        P->ClassSize = Size;
+        P->MaxCount = static_cast<u16>(2 * getMaxCached(Size));
+      } else {
+        // ClassSize in this struct is only used for malloc/free stats, which
+        // should only track user allocations, not internal movements.
+        P->ClassSize = 0;
+        P->MaxCount = SizeClassMap::MaxNumCachedHint;
+      }
+    }
+  }
+};
+
 } // namespace scudo
 
-#endif // SCUDO_LOCAL_CACHE_H_
+#endif // SCUDO_SIZE_CLASS_ALLOCATOR_H_
diff --git a/standalone/tests/combined_test.cpp b/standalone/tests/combined_test.cpp
index 9d665ef..7e8d5b4 100644
--- a/standalone/tests/combined_test.cpp
+++ b/standalone/tests/combined_test.cpp
@@ -212,6 +212,47 @@ struct TestConditionVariableConfig {
   };
   template <typename Config> using SecondaryT = scudo::MapAllocator<Config>;
 };
+
+struct TestNoCacheConfig {
+  static const bool MaySupportMemoryTagging = true;
+  template <class A>
+  using TSDRegistryT =
+      scudo::TSDRegistrySharedT<A, 8U, 4U>; // Shared, max 8 TSDs.
+
+  struct Primary {
+    using SizeClassMap = scudo::AndroidSizeClassMap;
+#if SCUDO_CAN_USE_PRIMARY64
+    static const scudo::uptr RegionSizeLog = 28U;
+    typedef scudo::u32 CompactPtrT;
+    static const scudo::uptr CompactPtrScale = SCUDO_MIN_ALIGNMENT_LOG;
+    static const scudo::uptr GroupSizeLog = 20U;
+    static const bool EnableRandomOffset = true;
+    static const scudo::uptr MapSizeIncrement = 1UL << 18;
+#else
+    static const scudo::uptr RegionSizeLog = 18U;
+    static const scudo::uptr GroupSizeLog = 18U;
+    typedef scudo::uptr CompactPtrT;
+#endif
+    static const bool EnableBlockCache = false;
+    static const scudo::s32 MinReleaseToOsIntervalMs = 1000;
+    static const scudo::s32 MaxReleaseToOsIntervalMs = 1000;
+  };
+
+#if SCUDO_CAN_USE_PRIMARY64
+  template <typename Config>
+  using PrimaryT = scudo::SizeClassAllocator64<Config>;
+#else
+  template <typename Config>
+  using PrimaryT = scudo::SizeClassAllocator32<Config>;
+#endif
+
+  struct Secondary {
+    template <typename Config>
+    using CacheT = scudo::MapAllocatorNoCache<Config>;
+  };
+  template <typename Config> using SecondaryT = scudo::MapAllocator<Config>;
+};
+
 } // namespace scudo
 
 #if SCUDO_FUCHSIA
@@ -221,7 +262,8 @@ struct TestConditionVariableConfig {
 #define SCUDO_TYPED_TEST_ALL_TYPES(FIXTURE, NAME)                              \
   SCUDO_TYPED_TEST_TYPE(FIXTURE, NAME, DefaultConfig)                          \
   SCUDO_TYPED_TEST_TYPE(FIXTURE, NAME, AndroidConfig)                          \
-  SCUDO_TYPED_TEST_TYPE(FIXTURE, NAME, TestConditionVariableConfig)
+  SCUDO_TYPED_TEST_TYPE(FIXTURE, NAME, TestConditionVariableConfig)            \
+  SCUDO_TYPED_TEST_TYPE(FIXTURE, NAME, TestNoCacheConfig)
 #endif
 
 #define SCUDO_TYPED_TEST_TYPE(FIXTURE, NAME, TYPE)                             \
@@ -597,7 +639,7 @@ SCUDO_TYPED_TEST(ScudoCombinedTest, Stats) {
   EXPECT_NE(Stats.find("Stats: Quarantine"), std::string::npos);
 }
 
-SCUDO_TYPED_TEST_SKIP_THREAD_SAFETY(ScudoCombinedTest, CacheDrain) {
+SCUDO_TYPED_TEST_SKIP_THREAD_SAFETY(ScudoCombinedTest, Drain) {
   using AllocatorT = typename BaseT::AllocatorT;
   auto *Allocator = this->Allocator.get();
 
@@ -612,9 +654,9 @@ SCUDO_TYPED_TEST_SKIP_THREAD_SAFETY(ScudoCombinedTest, CacheDrain) {
 
   typename AllocatorT::TSDRegistryT::ScopedTSD TSD(
       *Allocator->getTSDRegistry());
-  EXPECT_TRUE(!TSD->getCache().isEmpty());
-  TSD->getCache().drain();
-  EXPECT_TRUE(TSD->getCache().isEmpty());
+  EXPECT_TRUE(!TSD->getSizeClassAllocator().isEmpty());
+  TSD->getSizeClassAllocator().drain();
+  EXPECT_TRUE(TSD->getSizeClassAllocator().isEmpty());
 }
 
 SCUDO_TYPED_TEST_SKIP_THREAD_SAFETY(ScudoCombinedTest, ForceCacheDrain) {
@@ -635,7 +677,7 @@ SCUDO_TYPED_TEST_SKIP_THREAD_SAFETY(ScudoCombinedTest, ForceCacheDrain) {
 
   typename AllocatorT::TSDRegistryT::ScopedTSD TSD(
       *Allocator->getTSDRegistry());
-  EXPECT_TRUE(TSD->getCache().isEmpty());
+  EXPECT_TRUE(TSD->getSizeClassAllocator().isEmpty());
   EXPECT_EQ(TSD->getQuarantineCache().getSize(), 0U);
   EXPECT_TRUE(Allocator->getQuarantine()->isEmpty());
 }
@@ -1027,7 +1069,7 @@ TEST(ScudoCombinedTest, BasicTrustyConfig) {
   bool UnlockRequired;
   typename AllocatorT::TSDRegistryT::ScopedTSD TSD(
       *Allocator->getTSDRegistry());
-  TSD->getCache().drain();
+  TSD->getSizeClassAllocator().drain();
 
   Allocator->releaseToOS(scudo::ReleaseToOS::Force);
 }
diff --git a/standalone/tests/primary_test.cpp b/standalone/tests/primary_test.cpp
index 0636fe7..7dc38c2 100644
--- a/standalone/tests/primary_test.cpp
+++ b/standalone/tests/primary_test.cpp
@@ -211,8 +211,8 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, BasicPrimary) {
   using Primary = TestAllocator<TypeParam, scudo::DefaultSizeClassMap>;
   std::unique_ptr<Primary> Allocator(new Primary);
   Allocator->init(/*ReleaseToOsInterval=*/-1);
-  typename Primary::CacheT Cache;
-  Cache.init(nullptr, Allocator.get());
+  typename Primary::SizeClassAllocatorT SizeClassAllocator;
+  SizeClassAllocator.init(nullptr, Allocator.get());
   const scudo::uptr NumberOfAllocations = 32U;
   for (scudo::uptr I = 0; I <= 16U; I++) {
     const scudo::uptr Size = 1UL << I;
@@ -221,14 +221,14 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, BasicPrimary) {
     const scudo::uptr ClassId = Primary::SizeClassMap::getClassIdBySize(Size);
     void *Pointers[NumberOfAllocations];
     for (scudo::uptr J = 0; J < NumberOfAllocations; J++) {
-      void *P = Cache.allocate(ClassId);
+      void *P = SizeClassAllocator.allocate(ClassId);
       memset(P, 'B', Size);
       Pointers[J] = P;
     }
     for (scudo::uptr J = 0; J < NumberOfAllocations; J++)
-      Cache.deallocate(ClassId, Pointers[J]);
+      SizeClassAllocator.deallocate(ClassId, Pointers[J]);
   }
-  Cache.destroy(nullptr);
+  SizeClassAllocator.destroy(nullptr);
   Allocator->releaseToOS(scudo::ReleaseToOS::Force);
   scudo::ScopedString Str;
   Allocator->getStats(&Str);
@@ -261,19 +261,20 @@ TEST(ScudoPrimaryTest, Primary64OOM) {
       scudo::SizeClassAllocator64<scudo::PrimaryConfig<SmallRegionsConfig>>;
   Primary Allocator;
   Allocator.init(/*ReleaseToOsInterval=*/-1);
-  typename Primary::CacheT Cache;
+  typename Primary::SizeClassAllocatorT SizeClassAllocator;
   scudo::GlobalStats Stats;
   Stats.init();
-  Cache.init(&Stats, &Allocator);
+  SizeClassAllocator.init(&Stats, &Allocator);
   bool AllocationFailed = false;
   std::vector<void *> Blocks;
   const scudo::uptr ClassId = Primary::SizeClassMap::LargestClassId;
   const scudo::uptr Size = Primary::getSizeByClassId(ClassId);
-  const scudo::u16 MaxCachedBlockCount = Primary::CacheT::getMaxCached(Size);
+  const scudo::u16 MaxCachedBlockCount =
+      Primary::SizeClassAllocatorT::getMaxCached(Size);
 
   for (scudo::uptr I = 0; I < 10000U; I++) {
     for (scudo::uptr J = 0; J < MaxCachedBlockCount; ++J) {
-      void *Ptr = Cache.allocate(ClassId);
+      void *Ptr = SizeClassAllocator.allocate(ClassId);
       if (Ptr == nullptr) {
         AllocationFailed = true;
         break;
@@ -284,9 +285,9 @@ TEST(ScudoPrimaryTest, Primary64OOM) {
   }
 
   for (auto *Ptr : Blocks)
-    Cache.deallocate(ClassId, Ptr);
+    SizeClassAllocator.deallocate(ClassId, Ptr);
 
-  Cache.destroy(nullptr);
+  SizeClassAllocator.destroy(nullptr);
   Allocator.releaseToOS(scudo::ReleaseToOS::Force);
   scudo::ScopedString Str;
   Allocator.getStats(&Str);
@@ -299,14 +300,14 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, PrimaryIterate) {
   using Primary = TestAllocator<TypeParam, scudo::DefaultSizeClassMap>;
   std::unique_ptr<Primary> Allocator(new Primary);
   Allocator->init(/*ReleaseToOsInterval=*/-1);
-  typename Primary::CacheT Cache;
-  Cache.init(nullptr, Allocator.get());
+  typename Primary::SizeClassAllocatorT SizeClassAllocator;
+  SizeClassAllocator.init(nullptr, Allocator.get());
   std::vector<std::pair<scudo::uptr, void *>> V;
   for (scudo::uptr I = 0; I < 64U; I++) {
     const scudo::uptr Size =
         static_cast<scudo::uptr>(std::rand()) % Primary::SizeClassMap::MaxSize;
     const scudo::uptr ClassId = Primary::SizeClassMap::getClassIdBySize(Size);
-    void *P = Cache.allocate(ClassId);
+    void *P = SizeClassAllocator.allocate(ClassId);
     V.push_back(std::make_pair(ClassId, P));
   }
   scudo::uptr Found = 0;
@@ -322,10 +323,10 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, PrimaryIterate) {
   EXPECT_EQ(Found, V.size());
   while (!V.empty()) {
     auto Pair = V.back();
-    Cache.deallocate(Pair.first, Pair.second);
+    SizeClassAllocator.deallocate(Pair.first, Pair.second);
     V.pop_back();
   }
-  Cache.destroy(nullptr);
+  SizeClassAllocator.destroy(nullptr);
   Allocator->releaseToOS(scudo::ReleaseToOS::Force);
   scudo::ScopedString Str;
   Allocator->getStats(&Str);
@@ -342,8 +343,9 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, PrimaryThreaded) {
   std::thread Threads[32];
   for (scudo::uptr I = 0; I < ARRAY_SIZE(Threads); I++) {
     Threads[I] = std::thread([&]() {
-      static thread_local typename Primary::CacheT Cache;
-      Cache.init(nullptr, Allocator.get());
+      static thread_local
+          typename Primary::SizeClassAllocatorT SizeClassAllocator;
+      SizeClassAllocator.init(nullptr, Allocator.get());
       std::vector<std::pair<scudo::uptr, void *>> V;
       {
         std::unique_lock<std::mutex> Lock(Mutex);
@@ -355,7 +357,7 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, PrimaryThreaded) {
                                  Primary::SizeClassMap::MaxSize / 4;
         const scudo::uptr ClassId =
             Primary::SizeClassMap::getClassIdBySize(Size);
-        void *P = Cache.allocate(ClassId);
+        void *P = SizeClassAllocator.allocate(ClassId);
         if (P)
           V.push_back(std::make_pair(ClassId, P));
       }
@@ -365,14 +367,14 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, PrimaryThreaded) {
 
       while (!V.empty()) {
         auto Pair = V.back();
-        Cache.deallocate(Pair.first, Pair.second);
+        SizeClassAllocator.deallocate(Pair.first, Pair.second);
         V.pop_back();
         // This increases the chance of having non-full TransferBatches and it
         // will jump into the code path of merging TransferBatches.
         if (std::rand() % 8 == 0)
-          Cache.drain();
+          SizeClassAllocator.drain();
       }
-      Cache.destroy(nullptr);
+      SizeClassAllocator.destroy(nullptr);
     });
   }
   {
@@ -397,15 +399,15 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, ReleaseToOS) {
   using Primary = TestAllocator<TypeParam, scudo::DefaultSizeClassMap>;
   std::unique_ptr<Primary> Allocator(new Primary);
   Allocator->init(/*ReleaseToOsInterval=*/-1);
-  typename Primary::CacheT Cache;
-  Cache.init(nullptr, Allocator.get());
+  typename Primary::SizeClassAllocatorT SizeClassAllocator;
+  SizeClassAllocator.init(nullptr, Allocator.get());
   const scudo::uptr Size = scudo::getPageSizeCached() * 2;
   EXPECT_TRUE(Primary::canAllocate(Size));
   const scudo::uptr ClassId = Primary::SizeClassMap::getClassIdBySize(Size);
-  void *P = Cache.allocate(ClassId);
+  void *P = SizeClassAllocator.allocate(ClassId);
   EXPECT_NE(P, nullptr);
-  Cache.deallocate(ClassId, P);
-  Cache.destroy(nullptr);
+  SizeClassAllocator.deallocate(ClassId, P);
+  SizeClassAllocator.destroy(nullptr);
   EXPECT_GT(Allocator->releaseToOS(scudo::ReleaseToOS::ForceAll), 0U);
 }
 
@@ -413,8 +415,8 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, MemoryGroup) {
   using Primary = TestAllocator<TypeParam, scudo::DefaultSizeClassMap>;
   std::unique_ptr<Primary> Allocator(new Primary);
   Allocator->init(/*ReleaseToOsInterval=*/-1);
-  typename Primary::CacheT Cache;
-  Cache.init(nullptr, Allocator.get());
+  typename Primary::SizeClassAllocatorT SizeClassAllocator;
+  SizeClassAllocator.init(nullptr, Allocator.get());
   const scudo::uptr Size = 32U;
   const scudo::uptr ClassId = Primary::SizeClassMap::getClassIdBySize(Size);
 
@@ -434,27 +436,31 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, MemoryGroup) {
   std::mt19937 R;
 
   for (scudo::uptr I = 0; I < PeakNumberOfAllocations; ++I)
-    Blocks.push_back(reinterpret_cast<scudo::uptr>(Cache.allocate(ClassId)));
+    Blocks.push_back(
+        reinterpret_cast<scudo::uptr>(SizeClassAllocator.allocate(ClassId)));
 
   std::shuffle(Blocks.begin(), Blocks.end(), R);
 
   // Release all the allocated blocks, including those held by local cache.
   while (!Blocks.empty()) {
-    Cache.deallocate(ClassId, reinterpret_cast<void *>(Blocks.back()));
+    SizeClassAllocator.deallocate(ClassId,
+                                  reinterpret_cast<void *>(Blocks.back()));
     Blocks.pop_back();
   }
-  Cache.drain();
+  SizeClassAllocator.drain();
 
   for (scudo::uptr I = 0; I < FinalNumberOfAllocations; ++I)
-    Blocks.push_back(reinterpret_cast<scudo::uptr>(Cache.allocate(ClassId)));
+    Blocks.push_back(
+        reinterpret_cast<scudo::uptr>(SizeClassAllocator.allocate(ClassId)));
 
   EXPECT_LE(*std::max_element(Blocks.begin(), Blocks.end()) -
                 *std::min_element(Blocks.begin(), Blocks.end()),
             GroupSizeMem * 2);
 
   while (!Blocks.empty()) {
-    Cache.deallocate(ClassId, reinterpret_cast<void *>(Blocks.back()));
+    SizeClassAllocator.deallocate(ClassId,
+                                  reinterpret_cast<void *>(Blocks.back()));
     Blocks.pop_back();
   }
-  Cache.drain();
+  SizeClassAllocator.drain();
 }
diff --git a/standalone/tests/tsd_test.cpp b/standalone/tests/tsd_test.cpp
index 851ac46..ad50ab3 100644
--- a/standalone/tests/tsd_test.cpp
+++ b/standalone/tests/tsd_test.cpp
@@ -26,7 +26,7 @@ template <class Config> class MockAllocator {
 public:
   using ThisT = MockAllocator<Config>;
   using TSDRegistryT = typename Config::template TSDRegistryT<ThisT>;
-  using CacheT = struct MockCache {
+  using SizeClassAllocatorT = struct MockSizeClassAllocator {
     volatile scudo::uptr Canary;
   };
   using QuarantineCacheT = struct MockQuarantine {};
@@ -38,7 +38,9 @@ public:
   }
 
   void unmapTestOnly() { TSDRegistry.unmapTestOnly(this); }
-  void initCache(CacheT *Cache) { *Cache = {}; }
+  void initAllocator(SizeClassAllocatorT *SizeClassAllocator) {
+    *SizeClassAllocator = {};
+  }
   void commitBack(UNUSED scudo::TSD<MockAllocator> *TSD) {}
   TSDRegistryT *getTSDRegistry() { return &TSDRegistry; }
   void callPostInitCallback() {}
@@ -103,14 +105,15 @@ static void testRegistry() NO_THREAD_SAFETY_ANALYSIS {
 
   {
     typename AllocatorT::TSDRegistryT::ScopedTSD TSD(*Registry);
-    EXPECT_EQ(TSD->getCache().Canary, 0U);
+    EXPECT_EQ(TSD->getSizeClassAllocator().Canary, 0U);
   }
 
   Registry->initThreadMaybe(Allocator.get(), /*MinimalInit=*/false);
   {
     typename AllocatorT::TSDRegistryT::ScopedTSD TSD(*Registry);
-    EXPECT_EQ(TSD->getCache().Canary, 0U);
-    memset(&TSD->getCache(), 0x42, sizeof(TSD->getCache()));
+    EXPECT_EQ(TSD->getSizeClassAllocator().Canary, 0U);
+    memset(&TSD->getSizeClassAllocator(), 0x42,
+           sizeof(TSD->getSizeClassAllocator()));
   }
 }
 
@@ -126,10 +129,10 @@ static std::mutex Mutex;
 static std::condition_variable Cv;
 static bool Ready;
 
-// Accessing `TSD->getCache()` requires `TSD::Mutex` which isn't easy to test
-// using thread-safety analysis. Alternatively, we verify the thread safety
-// through a runtime check in ScopedTSD and mark the test body with
-// NO_THREAD_SAFETY_ANALYSIS.
+// Accessing `TSD->getSizeClassAllocator()` requires `TSD::Mutex` which isn't
+// easy to test using thread-safety analysis. Alternatively, we verify the
+// thread safety through a runtime check in ScopedTSD and mark the test body
+// with NO_THREAD_SAFETY_ANALYSIS.
 template <typename AllocatorT>
 static void stressCache(AllocatorT *Allocator) NO_THREAD_SAFETY_ANALYSIS {
   auto Registry = Allocator->getTSDRegistry();
@@ -144,15 +147,15 @@ static void stressCache(AllocatorT *Allocator) NO_THREAD_SAFETY_ANALYSIS {
   // same for a shared TSD.
   if (std::is_same<typename AllocatorT::TSDRegistryT,
                    scudo::TSDRegistryExT<AllocatorT>>()) {
-    EXPECT_EQ(TSD->getCache().Canary, 0U);
+    EXPECT_EQ(TSD->getSizeClassAllocator().Canary, 0U);
   }
   // Transform the thread id to a uptr to use it as canary.
   const scudo::uptr Canary = static_cast<scudo::uptr>(
       std::hash<std::thread::id>{}(std::this_thread::get_id()));
-  TSD->getCache().Canary = Canary;
+  TSD->getSizeClassAllocator().Canary = Canary;
   // Loop a few times to make sure that a concurrent thread isn't modifying it.
   for (scudo::uptr I = 0; I < 4096U; I++)
-    EXPECT_EQ(TSD->getCache().Canary, Canary);
+    EXPECT_EQ(TSD->getSizeClassAllocator().Canary, Canary);
 }
 
 template <class AllocatorT> static void testRegistryThreaded() {
diff --git a/standalone/tsd.h b/standalone/tsd.h
index 72773f2..9303f57 100644
--- a/standalone/tsd.h
+++ b/standalone/tsd.h
@@ -31,7 +31,7 @@ template <class Allocator> struct alignas(SCUDO_CACHE_LINE_SIZE) TSD {
   void init(Allocator *Instance) NO_THREAD_SAFETY_ANALYSIS {
     DCHECK_EQ(DestructorIterations, 0U);
     DCHECK(isAligned(reinterpret_cast<uptr>(this), alignof(ThisT)));
-    Instance->initCache(&Cache);
+    Instance->initAllocator(&SizeClassAllocator);
     DestructorIterations = PTHREAD_DESTRUCTOR_ITERATIONS;
   }
 
@@ -72,7 +72,10 @@ template <class Allocator> struct alignas(SCUDO_CACHE_LINE_SIZE) TSD {
   // TODO(chiahungduan): Ideally, we want to do `Mutex.assertHeld` but acquiring
   // TSD doesn't always require holding the lock. Add this assertion while the
   // lock is always acquired.
-  typename Allocator::CacheT &getCache() REQUIRES(Mutex) { return Cache; }
+  typename Allocator::SizeClassAllocatorT &getSizeClassAllocator()
+      REQUIRES(Mutex) {
+    return SizeClassAllocator;
+  }
   typename Allocator::QuarantineCacheT &getQuarantineCache() REQUIRES(Mutex) {
     return QuarantineCache;
   }
@@ -81,7 +84,7 @@ private:
   HybridMutex Mutex;
   atomic_uptr Precedence = {};
 
-  typename Allocator::CacheT Cache GUARDED_BY(Mutex);
+  typename Allocator::SizeClassAllocatorT SizeClassAllocator GUARDED_BY(Mutex);
   typename Allocator::QuarantineCacheT QuarantineCache GUARDED_BY(Mutex);
 };
 
diff --git a/standalone/tsd_shared.h b/standalone/tsd_shared.h
index dade16d..8b570a7 100644
--- a/standalone/tsd_shared.h
+++ b/standalone/tsd_shared.h
@@ -127,7 +127,7 @@ struct TSDRegistrySharedT {
       // analyzer.
       TSDs[I].assertLocked(/*BypassCheck=*/true);
       Str->append("  Shared TSD[%zu]:\n", I);
-      TSDs[I].getCache().getStats(Str);
+      TSDs[I].getSizeClassAllocator().getStats(Str);
       TSDs[I].unlock();
     }
   }
diff --git a/standalone/type_traits.h b/standalone/type_traits.h
index 16ed5a0..1c36a83 100644
--- a/standalone/type_traits.h
+++ b/standalone/type_traits.h
@@ -42,6 +42,14 @@ template <typename T> struct isPointer<T *> {
   static constexpr bool value = true;
 };
 
+template <bool Cond, typename L, typename R> struct Conditional {
+  using type = L;
+};
+
+template <typename L, typename R> struct Conditional<false, L, R> {
+  using type = R;
+};
+
 } // namespace scudo
 
 #endif // SCUDO_TYPE_TRAITS_H_
```

