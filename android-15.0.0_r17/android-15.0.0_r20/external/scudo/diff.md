```diff
diff --git a/Android.bp b/Android.bp
index 6236b5e..ce57fa5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -389,3 +389,9 @@ cc_test {
         "scudo_unit_tests_default",
     ],
 }
+
+dirgroup {
+    name: "trusty_dirgroup_external_scudo",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/standalone/combined.h b/standalone/combined.h
index a5f1bc3..5deb8c9 100644
--- a/standalone/combined.h
+++ b/standalone/combined.h
@@ -785,6 +785,9 @@ public:
   // A corrupted chunk will not be reported as owned, which is WAI.
   bool isOwned(const void *Ptr) {
     initThreadMaybe();
+    // If the allocation is not owned, the tags could be wrong.
+    ScopedDisableMemoryTagChecks x(
+        useMemoryTagging<AllocatorConfig>(Primary.Options.load()));
 #ifdef GWP_ASAN_HOOKS
     if (GuardedAlloc.pointerIsMine(Ptr))
       return true;
@@ -1252,22 +1255,26 @@ private:
     else
       Header->State = Chunk::State::Quarantined;
 
-    void *BlockBegin;
-    if (LIKELY(!useMemoryTagging<AllocatorConfig>(Options))) {
+    if (LIKELY(!useMemoryTagging<AllocatorConfig>(Options)))
       Header->OriginOrWasZeroed = 0U;
-      if (BypassQuarantine && allocatorSupportsMemoryTagging<AllocatorConfig>())
-        Ptr = untagPointer(Ptr);
-      BlockBegin = getBlockBegin(Ptr, Header);
-    } else {
+    else {
       Header->OriginOrWasZeroed =
           Header->ClassId && !TSDRegistry.getDisableMemInit();
-      BlockBegin =
-          retagBlock(Options, TaggedPtr, Ptr, Header, Size, BypassQuarantine);
     }
 
     Chunk::storeHeader(Cookie, Ptr, Header);
 
     if (BypassQuarantine) {
+      void *BlockBegin;
+      if (LIKELY(!useMemoryTagging<AllocatorConfig>(Options))) {
+        // Must do this after storeHeader because loadHeader uses a tagged ptr.
+        if (allocatorSupportsMemoryTagging<AllocatorConfig>())
+          Ptr = untagPointer(Ptr);
+        BlockBegin = getBlockBegin(Ptr, Header);
+      } else {
+        BlockBegin = retagBlock(Options, TaggedPtr, Ptr, Header, Size, true);
+      }
+
       const uptr ClassId = Header->ClassId;
       if (LIKELY(ClassId)) {
         bool CacheDrained;
@@ -1285,6 +1292,8 @@ private:
         Secondary.deallocate(Options, BlockBegin);
       }
     } else {
+      if (UNLIKELY(useMemoryTagging<AllocatorConfig>(Options)))
+        retagBlock(Options, TaggedPtr, Ptr, Header, Size, false);
       typename TSDRegistryT::ScopedTSD TSD(TSDRegistry);
       Quarantine.put(&TSD->getQuarantineCache(),
                      QuarantineCallback(*this, TSD->getCache()), Ptr, Size);
diff --git a/standalone/list.h b/standalone/list.h
index 6b952a6..c6bd32a 100644
--- a/standalone/list.h
+++ b/standalone/list.h
@@ -61,10 +61,11 @@ public:
   using LinkTy = decltype(T::Next);
 
   LinkOp() = default;
-  LinkOp(T *BaseT, uptr BaseSize) : Base(BaseT), Size(BaseSize) {}
+  // TODO: Check if the `BaseSize` can fit in `Size`.
+  LinkOp(T *BaseT, uptr BaseSize)
+      : Base(BaseT), Size(static_cast<LinkTy>(BaseSize)) {}
   void init(T *LinkBase, uptr BaseSize) {
     Base = LinkBase;
-    // TODO: Check if the `BaseSize` can fit in `Size`.
     Size = static_cast<LinkTy>(BaseSize);
   }
   T *getBase() const { return Base; }
diff --git a/standalone/memtag.h b/standalone/memtag.h
index 1f6983e..83ebe67 100644
--- a/standalone/memtag.h
+++ b/standalone/memtag.h
@@ -122,9 +122,12 @@ inline NORETURN void enableSystemMemoryTaggingTestOnly() {
 
 class ScopedDisableMemoryTagChecks {
   uptr PrevTCO;
+  bool active;
 
 public:
-  ScopedDisableMemoryTagChecks() {
+  ScopedDisableMemoryTagChecks(bool cond = true) : active(cond) {
+    if (!active)
+      return;
     __asm__ __volatile__(
         R"(
         .arch_extension memtag
@@ -135,6 +138,8 @@ public:
   }
 
   ~ScopedDisableMemoryTagChecks() {
+    if (!active)
+      return;
     __asm__ __volatile__(
         R"(
         .arch_extension memtag
@@ -269,7 +274,7 @@ inline NORETURN void enableSystemMemoryTaggingTestOnly() {
 }
 
 struct ScopedDisableMemoryTagChecks {
-  ScopedDisableMemoryTagChecks() {}
+  ScopedDisableMemoryTagChecks(UNUSED bool cond = true) {}
 };
 
 inline NORETURN uptr selectRandomTag(uptr Ptr, uptr ExcludeMask) {
diff --git a/standalone/primary64.h b/standalone/primary64.h
index a387647..e382e01 100644
--- a/standalone/primary64.h
+++ b/standalone/primary64.h
@@ -532,6 +532,11 @@ private:
     uptr BytesInFreeListAtLastCheckpoint;
     uptr RangesReleased;
     uptr LastReleasedBytes;
+    // The minimum size of pushed blocks to trigger page release.
+    uptr TryReleaseThreshold;
+    // The number of bytes not triggering `releaseToOSMaybe()` because of
+    // the length of release interval.
+    uptr PendingPushedBytesDelta;
     u64 LastReleaseAtNs;
   };
 
@@ -560,8 +565,6 @@ private:
     u32 RandState GUARDED_BY(MMLock) = 0;
     BlocksInfo FreeListInfo GUARDED_BY(FLLock);
     PagesInfo MemMapInfo GUARDED_BY(MMLock);
-    // The minimum size of pushed blocks to trigger page release.
-    uptr TryReleaseThreshold GUARDED_BY(MMLock) = 0;
     ReleaseToOsInfo ReleaseInfo GUARDED_BY(MMLock) = {};
     bool Exhausted GUARDED_BY(MMLock) = false;
     bool isPopulatingFreeList GUARDED_BY(FLLock) = false;
@@ -610,9 +613,8 @@ private:
     return BlockSize < PageSize / 16U;
   }
 
-  ALWAYS_INLINE static bool isLargeBlock(uptr BlockSize) {
-    const uptr PageSize = getPageSizeCached();
-    return BlockSize > PageSize;
+  ALWAYS_INLINE uptr getMinReleaseAttemptSize(uptr BlockSize) {
+    return roundUp(BlockSize, getPageSizeCached());
   }
 
   ALWAYS_INLINE void initRegion(RegionInfo *Region, uptr ClassId,
@@ -631,12 +633,16 @@ private:
           (getRandomModN(&Region->RandState, 16) + 1) * PageSize;
     }
 
+    const uptr BlockSize = getSizeByClassId(ClassId);
     // Releasing small blocks is expensive, set a higher threshold to avoid
     // frequent page releases.
-    if (isSmallBlock(getSizeByClassId(ClassId)))
-      Region->TryReleaseThreshold = PageSize * SmallerBlockReleasePageDelta;
-    else
-      Region->TryReleaseThreshold = PageSize;
+    if (isSmallBlock(BlockSize)) {
+      Region->ReleaseInfo.TryReleaseThreshold =
+          PageSize * SmallerBlockReleasePageDelta;
+    } else {
+      Region->ReleaseInfo.TryReleaseThreshold =
+          getMinReleaseAttemptSize(BlockSize);
+    }
   }
 
   void pushBatchClassBlocks(RegionInfo *Region, CompactPtrT *Array, u32 Size)
@@ -1245,6 +1251,7 @@ private:
     uptr BytesInFreeList;
     const uptr AllocatedUserEnd =
         Region->MemMapInfo.AllocatedUser + Region->RegionBeg;
+    uptr RegionPushedBytesDelta = 0;
     SinglyLinkedList<BatchGroupT> GroupsToRelease;
 
     {
@@ -1267,6 +1274,12 @@ private:
         return 0;
       }
 
+      // Given that we will unlock the freelist for block operations, cache the
+      // value here so that when we are adapting the `TryReleaseThreshold`
+      // later, we are using the right metric.
+      RegionPushedBytesDelta =
+          BytesInFreeList - Region->ReleaseInfo.BytesInFreeListAtLastCheckpoint;
+
       // ==================================================================== //
       // 2. Determine which groups can release the pages. Use a heuristic to
       //    gather groups that are candidates for doing a release.
@@ -1310,12 +1323,45 @@ private:
     auto SkipRegion = [](UNUSED uptr RegionIndex) { return false; };
     releaseFreeMemoryToOS(Context, Recorder, SkipRegion);
     if (Recorder.getReleasedRangesCount() > 0) {
+      // This is the case that we didn't hit the release threshold but it has
+      // been past a certain period of time. Thus we try to release some pages
+      // and if it does release some additional pages, it's hint that we are
+      // able to lower the threshold. Currently, this case happens when the
+      // `RegionPushedBytesDelta` is over half of the `TryReleaseThreshold`. As
+      // a result, we shrink the threshold to half accordingly.
+      // TODO(chiahungduan): Apply the same adjustment strategy to small blocks.
+      if (!isSmallBlock(BlockSize)) {
+        if (RegionPushedBytesDelta < Region->ReleaseInfo.TryReleaseThreshold &&
+            Recorder.getReleasedBytes() >
+                Region->ReleaseInfo.LastReleasedBytes +
+                    getMinReleaseAttemptSize(BlockSize)) {
+          Region->ReleaseInfo.TryReleaseThreshold =
+              Max(Region->ReleaseInfo.TryReleaseThreshold / 2,
+                  getMinReleaseAttemptSize(BlockSize));
+        }
+      }
+
       Region->ReleaseInfo.BytesInFreeListAtLastCheckpoint = BytesInFreeList;
       Region->ReleaseInfo.RangesReleased += Recorder.getReleasedRangesCount();
       Region->ReleaseInfo.LastReleasedBytes = Recorder.getReleasedBytes();
     }
     Region->ReleaseInfo.LastReleaseAtNs = getMonotonicTimeFast();
 
+    if (Region->ReleaseInfo.PendingPushedBytesDelta > 0) {
+      // Instead of increasing the threshold by the amount of
+      // `PendingPushedBytesDelta`, we only increase half of the amount so that
+      // it won't be a leap (which may lead to higher memory pressure) because
+      // of certain memory usage bursts which don't happen frequently.
+      Region->ReleaseInfo.TryReleaseThreshold +=
+          Region->ReleaseInfo.PendingPushedBytesDelta / 2;
+      // This is another guard of avoiding the growth of threshold indefinitely.
+      // Note that we may consider to make this configurable if we have a better
+      // way to model this.
+      Region->ReleaseInfo.TryReleaseThreshold = Min<uptr>(
+          Region->ReleaseInfo.TryReleaseThreshold, (1UL << GroupSizeLog) / 2);
+      Region->ReleaseInfo.PendingPushedBytesDelta = 0;
+    }
+
     // ====================================================================== //
     // 5. Merge the `GroupsToRelease` back to the freelist.
     // ====================================================================== //
@@ -1329,8 +1375,6 @@ private:
       REQUIRES(Region->MMLock, Region->FLLock) {
     DCHECK_GE(Region->FreeListInfo.PoppedBlocks,
               Region->FreeListInfo.PushedBlocks);
-    const uptr PageSize = getPageSizeCached();
-
     // Always update `BytesInFreeListAtLastCheckpoint` with the smallest value
     // so that we won't underestimate the releasable pages. For example, the
     // following is the region usage,
@@ -1354,34 +1398,44 @@ private:
 
     const uptr RegionPushedBytesDelta =
         BytesInFreeList - Region->ReleaseInfo.BytesInFreeListAtLastCheckpoint;
-    if (RegionPushedBytesDelta < PageSize)
-      return false;
-
-    // Releasing smaller blocks is expensive, so we want to make sure that a
-    // significant amount of bytes are free, and that there has been a good
-    // amount of batches pushed to the freelist before attempting to release.
-    if (isSmallBlock(BlockSize) && ReleaseType == ReleaseToOS::Normal)
-      if (RegionPushedBytesDelta < Region->TryReleaseThreshold)
-        return false;
 
     if (ReleaseType == ReleaseToOS::Normal) {
-      const s32 IntervalMs = atomic_load_relaxed(&ReleaseToOsIntervalMs);
+      if (RegionPushedBytesDelta < Region->ReleaseInfo.TryReleaseThreshold / 2)
+        return false;
+
+      const s64 IntervalMs = atomic_load_relaxed(&ReleaseToOsIntervalMs);
       if (IntervalMs < 0)
         return false;
 
-      // The constant 8 here is selected from profiling some apps and the number
-      // of unreleased pages in the large size classes is around 16 pages or
-      // more. Choose half of it as a heuristic and which also avoids page
-      // release every time for every pushBlocks() attempt by large blocks.
-      const bool ByPassReleaseInterval =
-          isLargeBlock(BlockSize) && RegionPushedBytesDelta > 8 * PageSize;
-      if (!ByPassReleaseInterval) {
-        if (Region->ReleaseInfo.LastReleaseAtNs +
-                static_cast<u64>(IntervalMs) * 1000000 >
-            getMonotonicTimeFast()) {
-          // Memory was returned recently.
+      const u64 IntervalNs = static_cast<u64>(IntervalMs) * 1000000;
+      const u64 CurTimeNs = getMonotonicTimeFast();
+      const u64 DiffSinceLastReleaseNs =
+          CurTimeNs - Region->ReleaseInfo.LastReleaseAtNs;
+
+      // At here, `RegionPushedBytesDelta` is more than half of
+      // `TryReleaseThreshold`. If the last release happened 2 release interval
+      // before, we will still try to see if there's any chance to release some
+      // memory even it doesn't exceed the threshold.
+      if (RegionPushedBytesDelta < Region->ReleaseInfo.TryReleaseThreshold) {
+        // We want the threshold to have a shorter response time to the variant
+        // memory usage patterns. According to data collected during experiments
+        // (which were done with 1, 2, 4, 8 intervals), `2` strikes the better
+        // balance between the memory usage and number of page release attempts.
+        if (DiffSinceLastReleaseNs < 2 * IntervalNs)
           return false;
-        }
+      } else if (DiffSinceLastReleaseNs < IntervalNs) {
+        // In this case, we are over the threshold but we just did some page
+        // release in the same release interval. This is a hint that we may want
+        // a higher threshold so that we can release more memory at once.
+        // `TryReleaseThreshold` will be adjusted according to how many bytes
+        // are not released, i.e., the `PendingPushedBytesdelta` here.
+        // TODO(chiahungduan): Apply the same adjustment strategy to small
+        // blocks.
+        if (!isSmallBlock(BlockSize))
+          Region->ReleaseInfo.PendingPushedBytesDelta = RegionPushedBytesDelta;
+
+        // Memory was returned recently.
+        return false;
       }
     } // if (ReleaseType == ReleaseToOS::Normal)
 
@@ -1397,10 +1451,10 @@ private:
     SinglyLinkedList<BatchGroupT> GroupsToRelease;
 
     // We are examining each group and will take the minimum distance to the
-    // release threshold as the next Region::TryReleaseThreshold(). Note that if
-    // the size of free blocks has reached the release threshold, the distance
-    // to the next release will be PageSize * SmallerBlockReleasePageDelta. See
-    // the comment on `SmallerBlockReleasePageDelta` for more details.
+    // release threshold as the next `TryReleaseThreshold`. Note that if the
+    // size of free blocks has reached the release threshold, the distance to
+    // the next release will be PageSize * SmallerBlockReleasePageDelta. See the
+    // comment on `SmallerBlockReleasePageDelta` for more details.
     uptr MinDistToThreshold = GroupSize;
 
     for (BatchGroupT *BG = Region->FreeListInfo.BlockList.front(),
@@ -1438,6 +1492,11 @@ private:
       }
 
       const uptr PushedBytesDelta = BytesInBG - BG->BytesInBGAtLastCheckpoint;
+      if (PushedBytesDelta < getMinReleaseAttemptSize(BlockSize)) {
+        Prev = BG;
+        BG = BG->Next;
+        continue;
+      }
 
       // Given the randomness property, we try to release the pages only if the
       // bytes used by free blocks exceed certain proportion of group size. Note
@@ -1548,7 +1607,7 @@ private:
       // back to normal.
       if (MinDistToThreshold == GroupSize)
         MinDistToThreshold = PageSize * SmallerBlockReleasePageDelta;
-      Region->TryReleaseThreshold = MinDistToThreshold;
+      Region->ReleaseInfo.TryReleaseThreshold = MinDistToThreshold;
     }
 
     return GroupsToRelease;
diff --git a/standalone/secondary.h b/standalone/secondary.h
index 2fae29e..25b8235 100644
--- a/standalone/secondary.h
+++ b/standalone/secondary.h
@@ -71,7 +71,8 @@ namespace {
 
 struct CachedBlock {
   static constexpr u16 CacheIndexMax = UINT16_MAX;
-  static constexpr u16 InvalidEntry = CacheIndexMax;
+  static constexpr u16 EndOfListVal = CacheIndexMax;
+
   // We allow a certain amount of fragmentation and part of the fragmented bytes
   // will be released by `releaseAndZeroPagesToOS()`. This increases the chance
   // of cache hit rate and reduces the overhead to the RSS at the same time. See
@@ -206,17 +207,16 @@ public:
                       &Fractional);
     const s32 Interval = atomic_load_relaxed(&ReleaseToOsIntervalMs);
     Str->append(
-        "Stats: MapAllocatorCache: EntriesCount: %d, "
+        "Stats: MapAllocatorCache: EntriesCount: %zu, "
         "MaxEntriesCount: %u, MaxEntrySize: %zu, ReleaseToOsIntervalMs = %d\n",
-        EntriesCount, atomic_load_relaxed(&MaxEntriesCount),
+        LRUEntries.size(), atomic_load_relaxed(&MaxEntriesCount),
         atomic_load_relaxed(&MaxEntrySize), Interval >= 0 ? Interval : -1);
     Str->append("Stats: CacheRetrievalStats: SuccessRate: %u/%u "
                 "(%zu.%02zu%%)\n",
                 SuccessfulRetrieves, CallsToRetrieve, Integral, Fractional);
     Str->append("Cache Entry Info (Most Recent -> Least Recent):\n");
 
-    for (u32 I = LRUHead; I != CachedBlock::InvalidEntry; I = Entries[I].Next) {
-      CachedBlock &Entry = Entries[I];
+    for (CachedBlock &Entry : LRUEntries) {
       Str->append("  StartBlockAddress: 0x%zx, EndBlockAddress: 0x%zx, "
                   "BlockSize: %zu %s\n",
                   Entry.CommitBase, Entry.CommitBase + Entry.CommitSize,
@@ -234,7 +234,7 @@ public:
                 "Cache entry array is too large to be indexed.");
 
   void init(s32 ReleaseToOsInterval) NO_THREAD_SAFETY_ANALYSIS {
-    DCHECK_EQ(EntriesCount, 0U);
+    DCHECK_EQ(LRUEntries.size(), 0U);
     setOption(Option::MaxCacheEntriesCount,
               static_cast<sptr>(Config::getDefaultMaxEntriesCount()));
     setOption(Option::MaxCacheEntrySize,
@@ -244,17 +244,13 @@ public:
       ReleaseToOsInterval = Config::getDefaultReleaseToOsIntervalMs();
     setOption(Option::ReleaseInterval, static_cast<sptr>(ReleaseToOsInterval));
 
-    // The cache is initially empty
-    LRUHead = CachedBlock::InvalidEntry;
-    LRUTail = CachedBlock::InvalidEntry;
-
-    // Available entries will be retrieved starting from the beginning of the
-    // Entries array
-    AvailableHead = 0;
-    for (u32 I = 0; I < Config::getEntriesArraySize() - 1; I++)
-      Entries[I].Next = static_cast<u16>(I + 1);
+    LRUEntries.clear();
+    LRUEntries.init(Entries, sizeof(Entries));
 
-    Entries[Config::getEntriesArraySize() - 1].Next = CachedBlock::InvalidEntry;
+    AvailEntries.clear();
+    AvailEntries.init(Entries, sizeof(Entries));
+    for (u32 I = 0; I < Config::getEntriesArraySize(); I++)
+      AvailEntries.push_back(&Entries[I]);
   }
 
   void store(const Options &Options, uptr CommitBase, uptr CommitSize,
@@ -326,11 +322,15 @@ public:
         Entry = PrevEntry;
       }
 
-      // All excess entries are evicted from the cache
-      while (needToEvict()) {
+      // All excess entries are evicted from the cache. Note that when
+      // `MaxEntriesCount` is zero, cache storing shouldn't happen and it's
+      // guarded by the `DCHECK(canCache(CommitSize))` above. As a result, we
+      // won't try to pop `LRUEntries` when it's empty.
+      while (LRUEntries.size() >= atomic_load_relaxed(&MaxEntriesCount)) {
         // Save MemMaps of evicted entries to perform unmap outside of lock
-        EvictionMemMaps.push_back(Entries[LRUTail].MemMap);
-        remove(LRUTail);
+        CachedBlock *Entry = LRUEntries.back();
+        EvictionMemMaps.push_back(Entry->MemMap);
+        remove(Entry);
       }
 
       insert(Entry);
@@ -360,9 +360,9 @@ public:
     {
       ScopedLock L(Mutex);
       CallsToRetrieve++;
-      if (EntriesCount == 0)
+      if (LRUEntries.size() == 0)
         return {};
-      u16 RetrievedIndex = CachedBlock::InvalidEntry;
+      CachedBlock *RetrievedEntry = nullptr;
       uptr MinDiff = UINTPTR_MAX;
 
       //  Since allocation sizes don't always match cached memory chunk sizes
@@ -382,10 +382,9 @@ public:
       //  well as the header metadata. If EntryHeaderPos - CommitBase exceeds
       //  MaxAllowedFragmentedPages * PageSize, the cached memory chunk is
       //  not considered valid for retrieval.
-      for (u16 I = LRUHead; I != CachedBlock::InvalidEntry;
-           I = Entries[I].Next) {
-        const uptr CommitBase = Entries[I].CommitBase;
-        const uptr CommitSize = Entries[I].CommitSize;
+      for (CachedBlock &Entry : LRUEntries) {
+        const uptr CommitBase = Entry.CommitBase;
+        const uptr CommitSize = Entry.CommitSize;
         const uptr AllocPos =
             roundDown(CommitBase + CommitSize - Size, Alignment);
         const uptr HeaderPos = AllocPos - HeadersSize;
@@ -408,7 +407,7 @@ public:
           continue;
 
         MinDiff = Diff;
-        RetrievedIndex = I;
+        RetrievedEntry = &Entry;
         EntryHeaderPos = HeaderPos;
 
         // Immediately use a cached block if its size is close enough to the
@@ -418,9 +417,10 @@ public:
         if (Diff <= OptimalFitThesholdBytes)
           break;
       }
-      if (RetrievedIndex != CachedBlock::InvalidEntry) {
-        Entry = Entries[RetrievedIndex];
-        remove(RetrievedIndex);
+
+      if (RetrievedEntry != nullptr) {
+        Entry = *RetrievedEntry;
+        remove(RetrievedEntry);
         SuccessfulRetrieves++;
       }
     }
@@ -499,10 +499,8 @@ public:
         Quarantine[I].invalidate();
       }
     }
-    for (u32 I = LRUHead; I != CachedBlock::InvalidEntry; I = Entries[I].Next) {
-      Entries[I].MemMap.setMemoryPermission(Entries[I].CommitBase,
-                                            Entries[I].CommitSize, 0);
-    }
+    for (CachedBlock &Entry : LRUEntries)
+      Entry.MemMap.setMemoryPermission(Entry.CommitBase, Entry.CommitSize, 0);
     QuarantinePos = -1U;
   }
 
@@ -513,64 +511,19 @@ public:
   void unmapTestOnly() { empty(); }
 
 private:
-  bool needToEvict() REQUIRES(Mutex) {
-    return (EntriesCount >= atomic_load_relaxed(&MaxEntriesCount));
-  }
-
   void insert(const CachedBlock &Entry) REQUIRES(Mutex) {
-    DCHECK_LT(EntriesCount, atomic_load_relaxed(&MaxEntriesCount));
-
-    // Cache should be populated with valid entries when not empty
-    DCHECK_NE(AvailableHead, CachedBlock::InvalidEntry);
-
-    u32 FreeIndex = AvailableHead;
-    AvailableHead = Entries[AvailableHead].Next;
-
-    if (EntriesCount == 0) {
-      LRUTail = static_cast<u16>(FreeIndex);
-    } else {
-      // Check list order
-      if (EntriesCount > 1)
-        DCHECK_GE(Entries[LRUHead].Time, Entries[Entries[LRUHead].Next].Time);
-      Entries[LRUHead].Prev = static_cast<u16>(FreeIndex);
-    }
+    CachedBlock *AvailEntry = AvailEntries.front();
+    AvailEntries.pop_front();
 
-    Entries[FreeIndex] = Entry;
-    Entries[FreeIndex].Next = LRUHead;
-    Entries[FreeIndex].Prev = CachedBlock::InvalidEntry;
-    LRUHead = static_cast<u16>(FreeIndex);
-    EntriesCount++;
-
-    // Availability stack should not have available entries when all entries
-    // are in use
-    if (EntriesCount == Config::getEntriesArraySize())
-      DCHECK_EQ(AvailableHead, CachedBlock::InvalidEntry);
+    *AvailEntry = Entry;
+    LRUEntries.push_front(AvailEntry);
   }
 
-  void remove(uptr I) REQUIRES(Mutex) {
-    DCHECK(Entries[I].isValid());
-
-    Entries[I].invalidate();
-
-    if (I == LRUHead)
-      LRUHead = Entries[I].Next;
-    else
-      Entries[Entries[I].Prev].Next = Entries[I].Next;
-
-    if (I == LRUTail)
-      LRUTail = Entries[I].Prev;
-    else
-      Entries[Entries[I].Next].Prev = Entries[I].Prev;
-
-    Entries[I].Next = AvailableHead;
-    AvailableHead = static_cast<u16>(I);
-    EntriesCount--;
-
-    // Cache should not have valid entries when not empty
-    if (EntriesCount == 0) {
-      DCHECK_EQ(LRUHead, CachedBlock::InvalidEntry);
-      DCHECK_EQ(LRUTail, CachedBlock::InvalidEntry);
-    }
+  void remove(CachedBlock *Entry) REQUIRES(Mutex) {
+    DCHECK(Entry->isValid());
+    LRUEntries.remove(Entry);
+    Entry->invalidate();
+    AvailEntries.push_front(Entry);
   }
 
   void empty() {
@@ -578,14 +531,10 @@ private:
     uptr N = 0;
     {
       ScopedLock L(Mutex);
-      for (uptr I = 0; I < Config::getEntriesArraySize(); I++) {
-        if (!Entries[I].isValid())
-          continue;
-        MapInfo[N] = Entries[I].MemMap;
-        remove(I);
-        N++;
-      }
-      EntriesCount = 0;
+
+      for (CachedBlock &Entry : LRUEntries)
+        MapInfo[N++] = Entry.MemMap;
+      LRUEntries.clear();
     }
     for (uptr I = 0; I < N; I++) {
       MemMapT &MemMap = MapInfo[I];
@@ -607,7 +556,7 @@ private:
 
   void releaseOlderThan(u64 Time) EXCLUDES(Mutex) {
     ScopedLock L(Mutex);
-    if (!EntriesCount || OldestTime == 0 || OldestTime > Time)
+    if (!LRUEntries.size() || OldestTime == 0 || OldestTime > Time)
       return;
     OldestTime = 0;
     for (uptr I = 0; I < Config::getQuarantineSize(); I++)
@@ -617,7 +566,6 @@ private:
   }
 
   HybridMutex Mutex;
-  u32 EntriesCount GUARDED_BY(Mutex) = 0;
   u32 QuarantinePos GUARDED_BY(Mutex) = 0;
   atomic_u32 MaxEntriesCount = {};
   atomic_uptr MaxEntrySize = {};
@@ -630,12 +578,10 @@ private:
   NonZeroLengthArray<CachedBlock, Config::getQuarantineSize()>
       Quarantine GUARDED_BY(Mutex) = {};
 
-  // The LRUHead of the cache is the most recently used cache entry
-  u16 LRUHead GUARDED_BY(Mutex) = 0;
-  // The LRUTail of the cache is the least recently used cache entry
-  u16 LRUTail GUARDED_BY(Mutex) = 0;
-  // The AvailableHead is the top of the stack of available entries
-  u16 AvailableHead GUARDED_BY(Mutex) = 0;
+  // Cached blocks stored in LRU order
+  DoublyLinkedList<CachedBlock> LRUEntries GUARDED_BY(Mutex);
+  // The unused Entries
+  SinglyLinkedList<CachedBlock> AvailEntries GUARDED_BY(Mutex);
 };
 
 template <typename Config> class MapAllocator {
diff --git a/standalone/tests/combined_test.cpp b/standalone/tests/combined_test.cpp
index 16b19e8..ff98eb3 100644
--- a/standalone/tests/combined_test.cpp
+++ b/standalone/tests/combined_test.cpp
@@ -534,6 +534,27 @@ SCUDO_TYPED_TEST(ScudoCombinedDeathTest, UseAfterFree) {
   }
 }
 
+SCUDO_TYPED_TEST(ScudoCombinedDeathTest, DoubleFreeFromPrimary) {
+  auto *Allocator = this->Allocator.get();
+
+  for (scudo::uptr SizeLog = 0U; SizeLog <= 20U; SizeLog++) {
+    const scudo::uptr Size = 1U << SizeLog;
+    if (!isPrimaryAllocation<TestAllocator<TypeParam>>(Size, 0))
+      break;
+
+    // Verify that a double free results in a chunk state error.
+    EXPECT_DEATH(
+        {
+          // Allocate from primary
+          void *P = Allocator->allocate(Size, Origin);
+          ASSERT_TRUE(P != nullptr);
+          Allocator->deallocate(P, Origin);
+          Allocator->deallocate(P, Origin);
+        },
+        "invalid chunk state");
+  }
+}
+
 SCUDO_TYPED_TEST(ScudoCombinedDeathTest, DisableMemoryTagging) {
   auto *Allocator = this->Allocator.get();
 
diff --git a/standalone/tests/memtag_test.cpp b/standalone/tests/memtag_test.cpp
index 1fae651..09093e1 100644
--- a/standalone/tests/memtag_test.cpp
+++ b/standalone/tests/memtag_test.cpp
@@ -19,7 +19,7 @@ namespace scudo {
 
 TEST(MemtagBasicDeathTest, Unsupported) {
   if (archSupportsMemoryTagging())
-    TEST_SKIP("Memory tagging is not supported");
+    TEST_SKIP("Memory tagging is not unsupported");
   // Skip when running with HWASan.
   if (&__hwasan_init != 0)
     TEST_SKIP("Incompatible with HWASan");
```

