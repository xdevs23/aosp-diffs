```diff
diff --git a/OWNERS b/OWNERS
index 4f31bde..0d1ae30 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 cferris@google.com
 enh@google.com
 chiahungduan@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/config/custom_scudo_config.h b/config/custom_scudo_config.h
index b1b1d9a..6f8589b 100644
--- a/config/custom_scudo_config.h
+++ b/config/custom_scudo_config.h
@@ -124,6 +124,10 @@ struct HostConfig {
       static const s32 DefaultReleaseToOsIntervalMs = 10000;
     };
     template <typename Config> using CacheT = MapAllocatorCache<Config>;
+#if !defined(__LP64__)
+    // Do not use guard pages on 32 bit due to limited VA space.
+    static const bool EnableGuardPages = false;
+#endif
   };
 
   template <typename Config> using SecondaryT = MapAllocator<Config>;
@@ -173,6 +177,10 @@ struct AndroidNormalConfig {
       static const s32 DefaultReleaseToOsIntervalMs = 0;
     };
     template <typename Config> using CacheT = MapAllocatorCache<Config>;
+#if !defined(__LP64__)
+    // Do not use guard pages on 32 bit due to limited VA space.
+    static const bool EnableGuardPages = false;
+#endif
   };
 
   template <typename Config> using SecondaryT = MapAllocator<Config>;
@@ -213,6 +221,10 @@ struct AndroidLowMemoryConfig {
   struct Secondary {
     // TODO(cferris): After secondary caching tuned, re-add a cache config.
     template <typename Config> using CacheT = MapAllocatorNoCache<Config>;
+#if !defined(__LP64__)
+    // Do not use guard pages on 32 bit due to limited VA space.
+    static const bool EnableGuardPages = false;
+#endif
   };
 
   template <typename Config> using SecondaryT = MapAllocator<Config>;
diff --git a/standalone/allocator_config.def b/standalone/allocator_config.def
index ce37b1c..43893e9 100644
--- a/standalone/allocator_config.def
+++ b/standalone/allocator_config.def
@@ -31,6 +31,9 @@
 #ifndef SECONDARY_REQUIRED_TEMPLATE_TYPE
 #define SECONDARY_REQUIRED_TEMPLATE_TYPE(...)
 #endif
+#ifndef SECONDARY_OPTIONAL
+#define SECONDARY_OPTIONAL(...)
+#endif
 #ifndef SECONDARY_CACHE_OPTIONAL
 #define SECONDARY_CACHE_OPTIONAL(...)
 #endif
@@ -109,6 +112,11 @@ PRIMARY_OPTIONAL_TYPE(CompactPtrT, uptr)
 // Defines the type of Secondary Cache to use.
 SECONDARY_REQUIRED_TEMPLATE_TYPE(CacheT)
 
+// SECONDARY_OPTIONAL(TYPE, NAME, DEFAULT)
+//
+// Add one guard page at the front and back for each allocation.
+SECONDARY_OPTIONAL(const bool, EnableGuardPages, true)
+
 // SECONDARY_CACHE_OPTIONAL(TYPE, NAME, DEFAULT)
 //
 // Defines the type of cache used by the Secondary. Some additional
@@ -122,6 +130,7 @@ SECONDARY_CACHE_OPTIONAL(const s32, MaxReleaseToOsIntervalMs, INT32_MAX)
 SECONDARY_CACHE_OPTIONAL(const s32, DefaultReleaseToOsIntervalMs, INT32_MIN)
 
 #undef SECONDARY_CACHE_OPTIONAL
+#undef SECONDARY_OPTIONAL
 #undef SECONDARY_REQUIRED_TEMPLATE_TYPE
 #undef PRIMARY_OPTIONAL_TYPE
 #undef PRIMARY_OPTIONAL
diff --git a/standalone/allocator_config_wrapper.h b/standalone/allocator_config_wrapper.h
index 5477236..ac639ee 100644
--- a/standalone/allocator_config_wrapper.h
+++ b/standalone/allocator_config_wrapper.h
@@ -12,35 +12,7 @@
 #include "condition_variable.h"
 #include "internal_defs.h"
 #include "secondary.h"
-
-namespace {
-
-template <typename T> struct removeConst {
-  using type = T;
-};
-template <typename T> struct removeConst<const T> {
-  using type = T;
-};
-
-// This is only used for SFINAE when detecting if a type is defined.
-template <typename T> struct voidAdaptor {
-  using type = void;
-};
-
-// This is used for detecting the case that defines the flag with wrong type and
-// it'll be viewed as undefined optional flag.
-template <typename L, typename R> struct assertSameType {
-  template <typename, typename> struct isSame {
-    static constexpr bool value = false;
-  };
-  template <typename T> struct isSame<T, T> {
-    static constexpr bool value = true;
-  };
-  static_assert(isSame<L, R>::value, "Flag type mismatches");
-  using type = R;
-};
-
-} // namespace
+#include "type_traits.h"
 
 namespace scudo {
 
@@ -123,6 +95,13 @@ template <typename AllocatorConfig> struct SecondaryConfig {
 #define SECONDARY_REQUIRED_TEMPLATE_TYPE(NAME)                                 \
   template <typename T>                                                        \
   using NAME = typename AllocatorConfig::Secondary::template NAME<T>;
+
+#define SECONDARY_OPTIONAL(TYPE, NAME, DEFAULT)                                \
+  OPTIONAL_TEMPLATE(TYPE, NAME, DEFAULT, NAME)                                 \
+  static constexpr removeConst<TYPE>::type get##NAME() {                       \
+    return NAME##State<typename AllocatorConfig::Secondary>::getValue();       \
+  }
+
 #include "allocator_config.def"
 
   struct CacheConfig {
diff --git a/standalone/chunk.h b/standalone/chunk.h
index 9228df0..a1b8e72 100644
--- a/standalone/chunk.h
+++ b/standalone/chunk.h
@@ -125,7 +125,7 @@ inline void loadHeader(u32 Cookie, const void *Ptr,
   *NewUnpackedHeader = bit_cast<UnpackedHeader>(NewPackedHeader);
   if (UNLIKELY(NewUnpackedHeader->Checksum !=
                computeHeaderChecksum(Cookie, Ptr, NewUnpackedHeader)))
-    reportHeaderCorruption(const_cast<void *>(Ptr));
+    reportHeaderCorruption(NewUnpackedHeader, const_cast<void *>(Ptr));
 }
 
 inline bool isValid(u32 Cookie, const void *Ptr,
diff --git a/standalone/list.h b/standalone/list.h
index c6bd32a..e0b8278 100644
--- a/standalone/list.h
+++ b/standalone/list.h
@@ -10,17 +10,7 @@
 #define SCUDO_LIST_H_
 
 #include "internal_defs.h"
-
-// TODO: Move the helpers to a header.
-namespace {
-template <typename T> struct isPointer {
-  static constexpr bool value = false;
-};
-
-template <typename T> struct isPointer<T *> {
-  static constexpr bool value = true;
-};
-} // namespace
+#include "type_traits.h"
 
 namespace scudo {
 
@@ -58,10 +48,11 @@ public:
 
 template <class T> class LinkOp<T, /*LinkWithPtr=*/false> {
 public:
-  using LinkTy = decltype(T::Next);
+  using LinkTy = typename assertSameType<
+      typename removeConst<decltype(T::Next)>::type,
+      typename removeConst<decltype(T::EndOfListVal)>::type>::type;
 
   LinkOp() = default;
-  // TODO: Check if the `BaseSize` can fit in `Size`.
   LinkOp(T *BaseT, uptr BaseSize)
       : Base(BaseT), Size(static_cast<LinkTy>(BaseSize)) {}
   void init(T *LinkBase, uptr BaseSize) {
@@ -80,11 +71,12 @@ public:
   }
   // Set `X->Next` to `Next`.
   void setNext(T *X, T *Next) const {
-    // TODO: Check if the offset fits in the size of `LinkTy`.
-    if (Next == nullptr)
+    if (Next == nullptr) {
       X->Next = getEndOfListVal();
-    else
+    } else {
+      assertElementInRange(Next);
       X->Next = static_cast<LinkTy>(Next - Base);
+    }
   }
 
   T *getPrev(T *X) const {
@@ -96,17 +88,22 @@ public:
   }
   // Set `X->Prev` to `Prev`.
   void setPrev(T *X, T *Prev) const {
-    DCHECK_LT(reinterpret_cast<uptr>(Prev),
-              reinterpret_cast<uptr>(Base + Size));
-    if (Prev == nullptr)
+    if (Prev == nullptr) {
       X->Prev = getEndOfListVal();
-    else
+    } else {
+      assertElementInRange(Prev);
       X->Prev = static_cast<LinkTy>(Prev - Base);
+    }
   }
 
-  // TODO: `LinkTy` should be the same as decltype(T::EndOfListVal).
   LinkTy getEndOfListVal() const { return T::EndOfListVal; }
 
+private:
+  void assertElementInRange(T *X) const {
+    DCHECK_GE(reinterpret_cast<uptr>(X), reinterpret_cast<uptr>(Base));
+    DCHECK_LE(static_cast<LinkTy>(X - Base), Size);
+  }
+
 protected:
   T *Base = nullptr;
   LinkTy Size = 0;
diff --git a/standalone/primary32.h b/standalone/primary32.h
index 654b129..596c48f 100644
--- a/standalone/primary32.h
+++ b/standalone/primary32.h
@@ -387,7 +387,7 @@ private:
 
   struct ReleaseToOsInfo {
     uptr BytesInFreeListAtLastCheckpoint;
-    uptr RangesReleased;
+    uptr NumReleasesAttempted;
     uptr LastReleasedBytes;
     u64 LastReleaseAtNs;
   };
@@ -880,14 +880,14 @@ private:
           BytesInFreeList - Sci->ReleaseInfo.BytesInFreeListAtLastCheckpoint;
     }
     const uptr AvailableChunks = Sci->AllocatedUser / BlockSize;
-    Str->append("  %02zu (%6zu): mapped: %6zuK popped: %7zu pushed: %7zu "
-                "inuse: %6zu avail: %6zu releases: %6zu last released: %6zuK "
-                "latest pushed bytes: %6zuK\n",
-                ClassId, getSizeByClassId(ClassId), Sci->AllocatedUser >> 10,
-                Sci->FreeListInfo.PoppedBlocks, Sci->FreeListInfo.PushedBlocks,
-                InUse, AvailableChunks, Sci->ReleaseInfo.RangesReleased,
-                Sci->ReleaseInfo.LastReleasedBytes >> 10,
-                PushedBytesDelta >> 10);
+    Str->append(
+        "  %02zu (%6zu): mapped: %6zuK popped: %7zu pushed: %7zu "
+        "inuse: %6zu avail: %6zu releases attempted: %6zu last released: %6zuK "
+        "latest pushed bytes: %6zuK\n",
+        ClassId, getSizeByClassId(ClassId), Sci->AllocatedUser >> 10,
+        Sci->FreeListInfo.PoppedBlocks, Sci->FreeListInfo.PushedBlocks, InUse,
+        AvailableChunks, Sci->ReleaseInfo.NumReleasesAttempted,
+        Sci->ReleaseInfo.LastReleasedBytes >> 10, PushedBytesDelta >> 10);
   }
 
   void getSizeClassFragmentationInfo(SizeClassInfo *Sci, uptr ClassId,
@@ -972,6 +972,10 @@ private:
     const uptr Base = First * RegionSize;
     const uptr NumberOfRegions = Last - First + 1U;
 
+    // The following steps contribute to the majority time spent in page
+    // releasing thus we increment the counter here.
+    ++Sci->ReleaseInfo.NumReleasesAttempted;
+
     // ==================================================================== //
     // 2. Mark the free blocks and we can tell which pages are in-use by
     //    querying `PageReleaseContext`.
@@ -991,9 +995,8 @@ private:
     };
     releaseFreeMemoryToOS(Context, Recorder, SkipRegion);
 
-    if (Recorder.getReleasedRangesCount() > 0) {
+    if (Recorder.getReleasedBytes() > 0) {
       Sci->ReleaseInfo.BytesInFreeListAtLastCheckpoint = BytesInFreeList;
-      Sci->ReleaseInfo.RangesReleased += Recorder.getReleasedRangesCount();
       Sci->ReleaseInfo.LastReleasedBytes = Recorder.getReleasedBytes();
       TotalReleasedBytes += Sci->ReleaseInfo.LastReleasedBytes;
     }
diff --git a/standalone/primary64.h b/standalone/primary64.h
index e382e01..e7da849 100644
--- a/standalone/primary64.h
+++ b/standalone/primary64.h
@@ -530,7 +530,7 @@ private:
 
   struct ReleaseToOsInfo {
     uptr BytesInFreeListAtLastCheckpoint;
-    uptr RangesReleased;
+    uptr NumReleasesAttempted;
     uptr LastReleasedBytes;
     // The minimum size of pushed blocks to trigger page release.
     uptr TryReleaseThreshold;
@@ -1141,17 +1141,18 @@ private:
           BytesInFreeList - Region->ReleaseInfo.BytesInFreeListAtLastCheckpoint;
     }
     const uptr TotalChunks = Region->MemMapInfo.AllocatedUser / BlockSize;
-    Str->append(
-        "%s %02zu (%6zu): mapped: %6zuK popped: %7zu pushed: %7zu "
-        "inuse: %6zu total: %6zu releases: %6zu last "
-        "released: %6zuK latest pushed bytes: %6zuK region: 0x%zx (0x%zx)\n",
-        Region->Exhausted ? "E" : " ", ClassId, getSizeByClassId(ClassId),
-        Region->MemMapInfo.MappedUser >> 10, Region->FreeListInfo.PoppedBlocks,
-        Region->FreeListInfo.PushedBlocks, InUseBlocks, TotalChunks,
-        Region->ReleaseInfo.RangesReleased,
-        Region->ReleaseInfo.LastReleasedBytes >> 10,
-        RegionPushedBytesDelta >> 10, Region->RegionBeg,
-        getRegionBaseByClassId(ClassId));
+    Str->append("%s %02zu (%6zu): mapped: %6zuK popped: %7zu pushed: %7zu "
+                "inuse: %6zu total: %6zu releases attempted: %6zu last "
+                "released: %6zuK latest pushed bytes: %6zuK region: 0x%zx "
+                "(0x%zx)\n",
+                Region->Exhausted ? "E" : " ", ClassId,
+                getSizeByClassId(ClassId), Region->MemMapInfo.MappedUser >> 10,
+                Region->FreeListInfo.PoppedBlocks,
+                Region->FreeListInfo.PushedBlocks, InUseBlocks, TotalChunks,
+                Region->ReleaseInfo.NumReleasesAttempted,
+                Region->ReleaseInfo.LastReleasedBytes >> 10,
+                RegionPushedBytesDelta >> 10, Region->RegionBeg,
+                getRegionBaseByClassId(ClassId));
   }
 
   void getRegionFragmentationInfo(RegionInfo *Region, uptr ClassId,
@@ -1296,6 +1297,10 @@ private:
         return 0;
     }
 
+    // The following steps contribute to the majority time spent in page
+    // releasing thus we increment the counter here.
+    ++Region->ReleaseInfo.NumReleasesAttempted;
+
     // Note that we have extracted the `GroupsToRelease` from region freelist.
     // It's safe to let pushBlocks()/popBlocks() access the remaining region
     // freelist. In the steps 3 and 4, we will temporarily release the FLLock
@@ -1322,7 +1327,7 @@ private:
                                             Context.getReleaseOffset());
     auto SkipRegion = [](UNUSED uptr RegionIndex) { return false; };
     releaseFreeMemoryToOS(Context, Recorder, SkipRegion);
-    if (Recorder.getReleasedRangesCount() > 0) {
+    if (Recorder.getReleasedBytes() > 0) {
       // This is the case that we didn't hit the release threshold but it has
       // been past a certain period of time. Thus we try to release some pages
       // and if it does release some additional pages, it's hint that we are
@@ -1342,7 +1347,6 @@ private:
       }
 
       Region->ReleaseInfo.BytesInFreeListAtLastCheckpoint = BytesInFreeList;
-      Region->ReleaseInfo.RangesReleased += Recorder.getReleasedRangesCount();
       Region->ReleaseInfo.LastReleasedBytes = Recorder.getReleasedBytes();
     }
     Region->ReleaseInfo.LastReleaseAtNs = getMonotonicTimeFast();
diff --git a/standalone/release.h b/standalone/release.h
index 6353daf..7a4912e 100644
--- a/standalone/release.h
+++ b/standalone/release.h
@@ -22,8 +22,6 @@ public:
   RegionReleaseRecorder(MemMapT *RegionMemMap, uptr Base, uptr Offset = 0)
       : RegionMemMap(RegionMemMap), Base(Base), Offset(Offset) {}
 
-  uptr getReleasedRangesCount() const { return ReleasedRangesCount; }
-
   uptr getReleasedBytes() const { return ReleasedBytes; }
 
   uptr getBase() const { return Base; }
@@ -33,12 +31,10 @@ public:
   void releasePageRangeToOS(uptr From, uptr To) {
     const uptr Size = To - From;
     RegionMemMap->releasePagesToOS(getBase() + Offset + From, Size);
-    ReleasedRangesCount++;
     ReleasedBytes += Size;
   }
 
 private:
-  uptr ReleasedRangesCount = 0;
   uptr ReleasedBytes = 0;
   MemMapT *RegionMemMap = nullptr;
   uptr Base = 0;
@@ -52,8 +48,6 @@ public:
   ReleaseRecorder(uptr Base, uptr Offset = 0, MapPlatformData *Data = nullptr)
       : Base(Base), Offset(Offset), Data(Data) {}
 
-  uptr getReleasedRangesCount() const { return ReleasedRangesCount; }
-
   uptr getReleasedBytes() const { return ReleasedBytes; }
 
   uptr getBase() const { return Base; }
@@ -62,12 +56,10 @@ public:
   void releasePageRangeToOS(uptr From, uptr To) {
     const uptr Size = To - From;
     releasePagesToOS(Base, From + Offset, Size, Data);
-    ReleasedRangesCount++;
     ReleasedBytes += Size;
   }
 
 private:
-  uptr ReleasedRangesCount = 0;
   uptr ReleasedBytes = 0;
   // The starting address to release. Note that we may want to combine (Base +
   // Offset) as a new Base. However, the Base is retrieved from
diff --git a/standalone/report.cpp b/standalone/report.cpp
index 9cef0ad..14a4066 100644
--- a/standalone/report.cpp
+++ b/standalone/report.cpp
@@ -9,6 +9,7 @@
 #include "report.h"
 
 #include "atomic_helpers.h"
+#include "chunk.h"
 #include "string_utils.h"
 
 #include <stdarg.h>
@@ -65,9 +66,18 @@ void NORETURN reportInvalidFlag(const char *FlagType, const char *Value) {
 
 // The checksum of a chunk header is invalid. This could be caused by an
 // {over,under}write of the header, a pointer that is not an actual chunk.
-void NORETURN reportHeaderCorruption(void *Ptr) {
-  ScopedErrorReport Report;
-  Report.append("corrupted chunk header at address %p\n", Ptr);
+void NORETURN reportHeaderCorruption(void *Header, void *Ptr) {
+  ScopedErrorReport Report;
+  Report.append("corrupted chunk header at address %p", Ptr);
+  if (*static_cast<Chunk::PackedHeader *>(Header) == 0U) {
+    // Header all zero, which could indicate that this might be a pointer that
+    // has been double freed but the memory has been released to the kernel.
+    Report.append(": chunk header is zero and might indicate memory corruption "
+                  "or a double free\n",
+                  Ptr);
+  } else {
+    Report.append(": most likely due to memory corruption\n", Ptr);
+  }
 }
 
 // The allocator was compiled with parameters that conflict with field size
diff --git a/standalone/report.h b/standalone/report.h
index a510fda..c0214b5 100644
--- a/standalone/report.h
+++ b/standalone/report.h
@@ -12,7 +12,6 @@
 #include "internal_defs.h"
 
 namespace scudo {
-
 // Reports are *fatal* unless stated otherwise.
 
 // Generic error, adds newline to end of message.
@@ -25,7 +24,7 @@ void NORETURN reportRawError(const char *Message);
 void NORETURN reportInvalidFlag(const char *FlagType, const char *Value);
 
 // Chunk header related errors.
-void NORETURN reportHeaderCorruption(void *Ptr);
+void NORETURN reportHeaderCorruption(void *Header, void *Ptr);
 
 // Sanity checks related error.
 void NORETURN reportSanityCheckError(const char *Field);
diff --git a/standalone/secondary.h b/standalone/secondary.h
index 25b8235..f3f91c4 100644
--- a/standalone/secondary.h
+++ b/standalone/secondary.h
@@ -614,6 +614,12 @@ public:
     return getBlockEnd(Ptr) - reinterpret_cast<uptr>(Ptr);
   }
 
+  static uptr getGuardPageSize() {
+    if (Config::getEnableGuardPages())
+      return getPageSizeCached();
+    return 0U;
+  }
+
   static constexpr uptr getHeadersSize() {
     return Chunk::getHeaderSize() + LargeBlock::getHeaderSize();
   }
@@ -763,11 +769,11 @@ void *MapAllocator<Config>::allocate(const Options &Options, uptr Size,
 
   uptr RoundedSize =
       roundUp(roundUp(Size, Alignment) + getHeadersSize(), PageSize);
-  if (Alignment > PageSize)
+  if (UNLIKELY(Alignment > PageSize))
     RoundedSize += Alignment - PageSize;
 
   ReservedMemoryT ReservedMemory;
-  const uptr MapSize = RoundedSize + 2 * PageSize;
+  const uptr MapSize = RoundedSize + 2 * getGuardPageSize();
   if (UNLIKELY(!ReservedMemory.create(/*Addr=*/0U, MapSize, nullptr,
                                       MAP_ALLOWNOMEM))) {
     return nullptr;
@@ -777,7 +783,7 @@ void *MapAllocator<Config>::allocate(const Options &Options, uptr Size,
   MemMapT MemMap = ReservedMemory.dispatch(ReservedMemory.getBase(),
                                            ReservedMemory.getCapacity());
   uptr MapBase = MemMap.getBase();
-  uptr CommitBase = MapBase + PageSize;
+  uptr CommitBase = MapBase + getGuardPageSize();
   uptr MapEnd = MapBase + MapSize;
 
   // In the unlikely event of alignments larger than a page, adjust the amount
@@ -786,25 +792,30 @@ void *MapAllocator<Config>::allocate(const Options &Options, uptr Size,
     // For alignments greater than or equal to a page, the user pointer (eg:
     // the pointer that is returned by the C or C++ allocation APIs) ends up
     // on a page boundary , and our headers will live in the preceding page.
-    CommitBase = roundUp(MapBase + PageSize + 1, Alignment) - PageSize;
-    const uptr NewMapBase = CommitBase - PageSize;
-    DCHECK_GE(NewMapBase, MapBase);
+    CommitBase =
+        roundUp(MapBase + getGuardPageSize() + 1, Alignment) - PageSize;
     // We only trim the extra memory on 32-bit platforms: 64-bit platforms
     // are less constrained memory wise, and that saves us two syscalls.
-    if (SCUDO_WORDSIZE == 32U && NewMapBase != MapBase) {
-      MemMap.unmap(MapBase, NewMapBase - MapBase);
-      MapBase = NewMapBase;
-    }
-    const uptr NewMapEnd =
-        CommitBase + PageSize + roundUp(Size, PageSize) + PageSize;
-    DCHECK_LE(NewMapEnd, MapEnd);
-    if (SCUDO_WORDSIZE == 32U && NewMapEnd != MapEnd) {
-      MemMap.unmap(NewMapEnd, MapEnd - NewMapEnd);
-      MapEnd = NewMapEnd;
+    if (SCUDO_WORDSIZE == 32U) {
+      const uptr NewMapBase = CommitBase - getGuardPageSize();
+      DCHECK_GE(NewMapBase, MapBase);
+      if (NewMapBase != MapBase) {
+        MemMap.unmap(MapBase, NewMapBase - MapBase);
+        MapBase = NewMapBase;
+      }
+      // CommitBase is past the first guard page, but this computation needs
+      // to include a page where the header lives.
+      const uptr NewMapEnd =
+          CommitBase + PageSize + roundUp(Size, PageSize) + getGuardPageSize();
+      DCHECK_LE(NewMapEnd, MapEnd);
+      if (NewMapEnd != MapEnd) {
+        MemMap.unmap(NewMapEnd, MapEnd - NewMapEnd);
+        MapEnd = NewMapEnd;
+      }
     }
   }
 
-  const uptr CommitSize = MapEnd - PageSize - CommitBase;
+  const uptr CommitSize = MapEnd - getGuardPageSize() - CommitBase;
   const uptr AllocPos = roundDown(CommitBase + CommitSize - Size, Alignment);
   if (!mapSecondary<Config>(Options, CommitBase, CommitSize, AllocPos, 0,
                             MemMap)) {
@@ -812,6 +823,8 @@ void *MapAllocator<Config>::allocate(const Options &Options, uptr Size,
     return nullptr;
   }
   const uptr HeaderPos = AllocPos - getHeadersSize();
+  // Make sure that the header is not in the guard page or before the base.
+  DCHECK_GE(HeaderPos, MapBase + getGuardPageSize());
   LargeBlock::Header *H = reinterpret_cast<LargeBlock::Header *>(
       LargeBlock::addHeaderTag<Config>(HeaderPos));
   if (useMemoryTagging<Config>(Options))
diff --git a/standalone/tests/combined_test.cpp b/standalone/tests/combined_test.cpp
index ff98eb3..9d665ef 100644
--- a/standalone/tests/combined_test.cpp
+++ b/standalone/tests/combined_test.cpp
@@ -54,16 +54,18 @@ void checkMemoryTaggingMaybe(AllocatorT *Allocator, void *P, scudo::uptr Size,
                              scudo::uptr Alignment) {
   const scudo::uptr MinAlignment = 1UL << SCUDO_MIN_ALIGNMENT_LOG;
   Size = scudo::roundUp(Size, MinAlignment);
-  if (Allocator->useMemoryTaggingTestOnly())
+  if (Allocator->useMemoryTaggingTestOnly()) {
     EXPECT_DEATH(
         {
           disableDebuggerdMaybe();
           reinterpret_cast<char *>(P)[-1] = 'A';
         },
         "");
+  }
   if (isPrimaryAllocation<AllocatorT>(Size, Alignment)
           ? Allocator->useMemoryTaggingTestOnly()
-          : Alignment == MinAlignment) {
+          : Alignment == MinAlignment &&
+                AllocatorT::SecondaryT::getGuardPageSize() > 0) {
     EXPECT_DEATH(
         {
           disableDebuggerdMaybe();
diff --git a/standalone/tests/report_test.cpp b/standalone/tests/report_test.cpp
index 6c46243..514837d 100644
--- a/standalone/tests/report_test.cpp
+++ b/standalone/tests/report_test.cpp
@@ -8,6 +8,7 @@
 
 #include "tests/scudo_unit_test.h"
 
+#include "chunk.h"
 #include "report.h"
 
 TEST(ScudoReportDeathTest, Check) {
@@ -20,9 +21,11 @@ TEST(ScudoReportDeathTest, Check) {
 TEST(ScudoReportDeathTest, Generic) {
   // Potentially unused if EXPECT_DEATH isn't defined.
   UNUSED void *P = reinterpret_cast<void *>(0x42424242U);
+  UNUSED scudo::Chunk::PackedHeader Header = {};
   EXPECT_DEATH(scudo::reportError("TEST123"), "Scudo ERROR.*TEST123");
   EXPECT_DEATH(scudo::reportInvalidFlag("ABC", "DEF"), "Scudo ERROR.*ABC.*DEF");
-  EXPECT_DEATH(scudo::reportHeaderCorruption(P), "Scudo ERROR.*42424242");
+  EXPECT_DEATH(scudo::reportHeaderCorruption(&Header, P),
+               "Scudo ERROR.*42424242");
   EXPECT_DEATH(scudo::reportSanityCheckError("XYZ"), "Scudo ERROR.*XYZ");
   EXPECT_DEATH(scudo::reportAlignmentTooBig(123, 456), "Scudo ERROR.*123.*456");
   EXPECT_DEATH(scudo::reportAllocationSizeTooBig(123, 456, 789),
@@ -54,6 +57,19 @@ TEST(ScudoReportDeathTest, CSpecific) {
                "Scudo ERROR.*123.*456");
 }
 
+TEST(ScudoReportDeathTest, HeaderCorruption) {
+  UNUSED void *P = reinterpret_cast<void *>(0x42424242U);
+  UNUSED scudo::Chunk::PackedHeader Header = {};
+  EXPECT_DEATH(scudo::reportHeaderCorruption(&Header, P),
+               "Scudo ERROR.*corrupted chunk header at address 0x.*42424242: "
+               "chunk header is zero and might indicate memory "
+               "corruption or a double free");
+  Header = 10U;
+  EXPECT_DEATH(scudo::reportHeaderCorruption(&Header, P),
+               "Scudo ERROR.*corrupted chunk header at address 0x.*42424242: "
+               "most likely due to memory corruption");
+}
+
 #if SCUDO_LINUX || SCUDO_TRUSTY || SCUDO_ANDROID
 #include "report_linux.h"
 
diff --git a/standalone/tests/scudo_unit_test.h b/standalone/tests/scudo_unit_test.h
index f8b658c..27c0e59 100644
--- a/standalone/tests/scudo_unit_test.h
+++ b/standalone/tests/scudo_unit_test.h
@@ -12,6 +12,7 @@
 #include <zxtest/zxtest.h>
 using Test = ::zxtest::Test;
 #define TEST_SKIP(message) ZXTEST_SKIP(message)
+#define TEST_HAS_FAILURE true
 #else
 #include "gtest/gtest.h"
 using Test = ::testing::Test;
@@ -19,6 +20,7 @@ using Test = ::testing::Test;
   do {                                                                         \
     GTEST_SKIP() << message;                                                   \
   } while (0)
+#define TEST_HAS_FAILURE Test::HasFailure()
 #endif
 
 // If EXPECT_DEATH isn't defined, make it a no-op.
diff --git a/standalone/tests/secondary_test.cpp b/standalone/tests/secondary_test.cpp
index 3638f1c..d8a7f6b 100644
--- a/standalone/tests/secondary_test.cpp
+++ b/standalone/tests/secondary_test.cpp
@@ -13,15 +13,19 @@
 #include "allocator_config_wrapper.h"
 #include "secondary.h"
 
+#include <string.h>
+
 #include <algorithm>
 #include <condition_variable>
 #include <memory>
 #include <mutex>
 #include <random>
-#include <stdio.h>
 #include <thread>
 #include <vector>
 
+// Get this once to use through-out the tests.
+const scudo::uptr PageSize = scudo::getPageSizeCached();
+
 template <typename Config> static scudo::Options getOptionsForConfig() {
   if (!Config::getMaySupportMemoryTagging() ||
       !scudo::archSupportsMemoryTagging() ||
@@ -32,60 +36,39 @@ template <typename Config> static scudo::Options getOptionsForConfig() {
   return AO.load();
 }
 
-template <typename Config> static void testSecondaryBasic(void) {
-  using SecondaryT = scudo::MapAllocator<scudo::SecondaryConfig<Config>>;
-  scudo::Options Options =
-      getOptionsForConfig<scudo::SecondaryConfig<Config>>();
+template <class Config> struct AllocatorInfoType {
+  std::unique_ptr<scudo::MapAllocator<scudo::SecondaryConfig<Config>>>
+      Allocator;
+  scudo::GlobalStats GlobalStats;
+  scudo::Options Options;
+
+  AllocatorInfoType(scudo::s32 ReleaseToOsInterval) {
+    using SecondaryT = scudo::MapAllocator<scudo::SecondaryConfig<Config>>;
+    Options = getOptionsForConfig<scudo::SecondaryConfig<Config>>();
+    GlobalStats.init();
+    Allocator.reset(new SecondaryT);
+    Allocator->init(&GlobalStats, ReleaseToOsInterval);
+  }
 
-  scudo::GlobalStats S;
-  S.init();
-  std::unique_ptr<SecondaryT> L(new SecondaryT);
-  L->init(&S);
-  const scudo::uptr Size = 1U << 16;
-  void *P = L->allocate(Options, Size);
-  EXPECT_NE(P, nullptr);
-  memset(P, 'A', Size);
-  EXPECT_GE(SecondaryT::getBlockSize(P), Size);
-  L->deallocate(Options, P);
+  AllocatorInfoType() : AllocatorInfoType(-1) {}
 
-  // If the Secondary can't cache that pointer, it will be unmapped.
-  if (!L->canCache(Size)) {
-    EXPECT_DEATH(
-        {
-          // Repeat few time to avoid missing crash if it's mmaped by unrelated
-          // code.
-          for (int i = 0; i < 10; ++i) {
-            P = L->allocate(Options, Size);
-            L->deallocate(Options, P);
-            memset(P, 'A', Size);
-          }
-        },
-        "");
-  }
+  ~AllocatorInfoType() {
+    if (Allocator == nullptr) {
+      return;
+    }
 
-  const scudo::uptr Align = 1U << 16;
-  P = L->allocate(Options, Size + Align, Align);
-  EXPECT_NE(P, nullptr);
-  void *AlignedP = reinterpret_cast<void *>(
-      scudo::roundUp(reinterpret_cast<scudo::uptr>(P), Align));
-  memset(AlignedP, 'A', Size);
-  L->deallocate(Options, P);
+    if (TEST_HAS_FAILURE) {
+      // Print all of the stats if the test fails.
+      scudo::ScopedString Str;
+      Allocator->getStats(&Str);
+      Str.output();
+    }
 
-  std::vector<void *> V;
-  for (scudo::uptr I = 0; I < 32U; I++)
-    V.push_back(L->allocate(Options, Size));
-  std::shuffle(V.begin(), V.end(), std::mt19937(std::random_device()()));
-  while (!V.empty()) {
-    L->deallocate(Options, V.back());
-    V.pop_back();
+    Allocator->unmapTestOnly();
   }
-  scudo::ScopedString Str;
-  L->getStats(&Str);
-  Str.output();
-  L->unmapTestOnly();
-}
+};
 
-struct NoCacheConfig {
+struct TestNoCacheConfig {
   static const bool MaySupportMemoryTagging = false;
   template <typename> using TSDRegistryT = void;
   template <typename> using PrimaryT = void;
@@ -97,7 +80,20 @@ struct NoCacheConfig {
   };
 };
 
-struct TestConfig {
+struct TestNoCacheNoGuardPageConfig {
+  static const bool MaySupportMemoryTagging = false;
+  template <typename> using TSDRegistryT = void;
+  template <typename> using PrimaryT = void;
+  template <typename Config> using SecondaryT = scudo::MapAllocator<Config>;
+
+  struct Secondary {
+    template <typename Config>
+    using CacheT = scudo::MapAllocatorNoCache<Config>;
+    static const bool EnableGuardPages = false;
+  };
+};
+
+struct TestCacheConfig {
   static const bool MaySupportMemoryTagging = false;
   template <typename> using TSDRegistryT = void;
   template <typename> using PrimaryT = void;
@@ -117,30 +113,85 @@ struct TestConfig {
   };
 };
 
-TEST(ScudoSecondaryTest, SecondaryBasic) {
-  testSecondaryBasic<NoCacheConfig>();
-  testSecondaryBasic<scudo::DefaultConfig>();
-  testSecondaryBasic<TestConfig>();
-}
+struct TestCacheNoGuardPageConfig {
+  static const bool MaySupportMemoryTagging = false;
+  template <typename> using TSDRegistryT = void;
+  template <typename> using PrimaryT = void;
+  template <typename> using SecondaryT = void;
 
-struct MapAllocatorTest : public Test {
-  using Config = scudo::DefaultConfig;
-  using LargeAllocator = scudo::MapAllocator<scudo::SecondaryConfig<Config>>;
+  struct Secondary {
+    struct Cache {
+      static const scudo::u32 EntriesArraySize = 128U;
+      static const scudo::u32 QuarantineSize = 0U;
+      static const scudo::u32 DefaultMaxEntriesCount = 64U;
+      static const scudo::uptr DefaultMaxEntrySize = 1UL << 20;
+      static const scudo::s32 MinReleaseToOsIntervalMs = INT32_MIN;
+      static const scudo::s32 MaxReleaseToOsIntervalMs = INT32_MAX;
+    };
 
-  void SetUp() override { Allocator->init(nullptr); }
+    template <typename Config> using CacheT = scudo::MapAllocatorCache<Config>;
+    static const bool EnableGuardPages = false;
+  };
+};
 
-  void TearDown() override { Allocator->unmapTestOnly(); }
+template <typename Config> static void testBasic() {
+  using SecondaryT = scudo::MapAllocator<scudo::SecondaryConfig<Config>>;
+  AllocatorInfoType<Config> Info;
 
-  std::unique_ptr<LargeAllocator> Allocator =
-      std::make_unique<LargeAllocator>();
-  scudo::Options Options =
-      getOptionsForConfig<scudo::SecondaryConfig<Config>>();
-};
+  const scudo::uptr Size = 1U << 16;
+  void *P = Info.Allocator->allocate(Info.Options, Size);
+  EXPECT_NE(P, nullptr);
+  memset(P, 'A', Size);
+  EXPECT_GE(SecondaryT::getBlockSize(P), Size);
+  Info.Allocator->deallocate(Info.Options, P);
+
+  // If the Secondary can't cache that pointer, it will be unmapped.
+  if (!Info.Allocator->canCache(Size)) {
+    EXPECT_DEATH(
+        {
+          // Repeat few time to avoid missing crash if it's mmaped by unrelated
+          // code.
+          for (int i = 0; i < 10; ++i) {
+            P = Info.Allocator->allocate(Info.Options, Size);
+            Info.Allocator->deallocate(Info.Options, P);
+            memset(P, 'A', Size);
+          }
+        },
+        "");
+  }
+
+  const scudo::uptr Align = 1U << 16;
+  P = Info.Allocator->allocate(Info.Options, Size + Align, Align);
+  EXPECT_NE(P, nullptr);
+  void *AlignedP = reinterpret_cast<void *>(
+      scudo::roundUp(reinterpret_cast<scudo::uptr>(P), Align));
+  memset(AlignedP, 'A', Size);
+  Info.Allocator->deallocate(Info.Options, P);
+
+  std::vector<void *> V;
+  for (scudo::uptr I = 0; I < 32U; I++)
+    V.push_back(Info.Allocator->allocate(Info.Options, Size));
+  std::shuffle(V.begin(), V.end(), std::mt19937(std::random_device()()));
+  while (!V.empty()) {
+    Info.Allocator->deallocate(Info.Options, V.back());
+    V.pop_back();
+  }
+}
+
+TEST(ScudoSecondaryTest, Basic) {
+  testBasic<TestNoCacheConfig>();
+  testBasic<TestNoCacheNoGuardPageConfig>();
+  testBasic<TestCacheConfig>();
+  testBasic<TestCacheNoGuardPageConfig>();
+  testBasic<scudo::DefaultConfig>();
+}
 
 // This exercises a variety of combinations of size and alignment for the
 // MapAllocator. The size computation done here mimic the ones done by the
 // combined allocator.
-TEST_F(MapAllocatorTest, SecondaryCombinations) {
+template <typename Config> void testAllocatorCombinations() {
+  AllocatorInfoType<Config> Info;
+
   constexpr scudo::uptr MinAlign = FIRST_32_SECOND_64(8, 16);
   constexpr scudo::uptr HeaderSize = scudo::roundUp(8, MinAlign);
   for (scudo::uptr SizeLog = 0; SizeLog <= 20; SizeLog++) {
@@ -154,106 +205,81 @@ TEST_F(MapAllocatorTest, SecondaryCombinations) {
             static_cast<scudo::uptr>((1LL << SizeLog) + Delta), MinAlign);
         const scudo::uptr Size =
             HeaderSize + UserSize + (Align > MinAlign ? Align - HeaderSize : 0);
-        void *P = Allocator->allocate(Options, Size, Align);
+        void *P = Info.Allocator->allocate(Info.Options, Size, Align);
         EXPECT_NE(P, nullptr);
         void *AlignedP = reinterpret_cast<void *>(
             scudo::roundUp(reinterpret_cast<scudo::uptr>(P), Align));
         memset(AlignedP, 0xff, UserSize);
-        Allocator->deallocate(Options, P);
+        Info.Allocator->deallocate(Info.Options, P);
       }
     }
   }
-  scudo::ScopedString Str;
-  Allocator->getStats(&Str);
-  Str.output();
 }
 
-TEST_F(MapAllocatorTest, SecondaryIterate) {
+TEST(ScudoSecondaryTest, AllocatorCombinations) {
+  testAllocatorCombinations<TestNoCacheConfig>();
+  testAllocatorCombinations<TestNoCacheNoGuardPageConfig>();
+}
+
+template <typename Config> void testAllocatorIterate() {
+  AllocatorInfoType<Config> Info;
+
   std::vector<void *> V;
-  const scudo::uptr PageSize = scudo::getPageSizeCached();
   for (scudo::uptr I = 0; I < 32U; I++)
-    V.push_back(Allocator->allocate(
-        Options, (static_cast<scudo::uptr>(std::rand()) % 16U) * PageSize));
+    V.push_back(Info.Allocator->allocate(
+        Info.Options,
+        (static_cast<scudo::uptr>(std::rand()) % 16U) * PageSize));
   auto Lambda = [&V](scudo::uptr Block) {
     EXPECT_NE(std::find(V.begin(), V.end(), reinterpret_cast<void *>(Block)),
               V.end());
   };
-  Allocator->disable();
-  Allocator->iterateOverBlocks(Lambda);
-  Allocator->enable();
+  Info.Allocator->disable();
+  Info.Allocator->iterateOverBlocks(Lambda);
+  Info.Allocator->enable();
   while (!V.empty()) {
-    Allocator->deallocate(Options, V.back());
+    Info.Allocator->deallocate(Info.Options, V.back());
     V.pop_back();
   }
-  scudo::ScopedString Str;
-  Allocator->getStats(&Str);
-  Str.output();
 }
 
-TEST_F(MapAllocatorTest, SecondaryCacheOptions) {
-  if (!Allocator->canCache(0U))
-    TEST_SKIP("Secondary Cache disabled");
-
-  // Attempt to set a maximum number of entries higher than the array size.
-  EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4096U));
-
-  // Attempt to set an invalid (negative) number of entries
-  EXPECT_FALSE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, -1));
-
-  // Various valid combinations.
-  EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4U));
-  EXPECT_TRUE(
-      Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 20));
-  EXPECT_TRUE(Allocator->canCache(1UL << 18));
-  EXPECT_TRUE(
-      Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 17));
-  EXPECT_FALSE(Allocator->canCache(1UL << 18));
-  EXPECT_TRUE(Allocator->canCache(1UL << 16));
-  EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 0U));
-  EXPECT_FALSE(Allocator->canCache(1UL << 16));
-  EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4U));
-  EXPECT_TRUE(
-      Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 20));
-  EXPECT_TRUE(Allocator->canCache(1UL << 16));
+TEST(ScudoSecondaryTest, AllocatorIterate) {
+  testAllocatorIterate<TestNoCacheConfig>();
+  testAllocatorIterate<TestNoCacheNoGuardPageConfig>();
 }
 
-struct MapAllocatorWithReleaseTest : public MapAllocatorTest {
-  void SetUp() override { Allocator->init(nullptr, /*ReleaseToOsInterval=*/0); }
-
-  void performAllocations() {
-    std::vector<void *> V;
-    const scudo::uptr PageSize = scudo::getPageSizeCached();
-    {
-      std::unique_lock<std::mutex> Lock(Mutex);
-      while (!Ready)
-        Cv.wait(Lock);
-    }
-    for (scudo::uptr I = 0; I < 128U; I++) {
-      // Deallocate 75% of the blocks.
-      const bool Deallocate = (std::rand() & 3) != 0;
-      void *P = Allocator->allocate(
-          Options, (static_cast<scudo::uptr>(std::rand()) % 16U) * PageSize);
-      if (Deallocate)
-        Allocator->deallocate(Options, P);
-      else
-        V.push_back(P);
-    }
-    while (!V.empty()) {
-      Allocator->deallocate(Options, V.back());
-      V.pop_back();
-    }
-  }
+template <typename Config> void testAllocatorWithReleaseThreadsRace() {
+  AllocatorInfoType<Config> Info(/*ReleaseToOsInterval=*/0);
 
   std::mutex Mutex;
   std::condition_variable Cv;
   bool Ready = false;
-};
 
-TEST_F(MapAllocatorWithReleaseTest, SecondaryThreadsRace) {
   std::thread Threads[16];
   for (scudo::uptr I = 0; I < ARRAY_SIZE(Threads); I++)
-    Threads[I] =
-        std::thread(&MapAllocatorWithReleaseTest::performAllocations, this);
+    Threads[I] = std::thread([&Mutex, &Cv, &Ready, &Info]() {
+      std::vector<void *> V;
+      {
+        std::unique_lock<std::mutex> Lock(Mutex);
+        while (!Ready)
+          Cv.wait(Lock);
+      }
+      for (scudo::uptr I = 0; I < 128U; I++) {
+        // Deallocate 75% of the blocks.
+        const bool Deallocate = (std::rand() & 3) != 0;
+        void *P = Info.Allocator->allocate(
+            Info.Options,
+            (static_cast<scudo::uptr>(std::rand()) % 16U) * PageSize);
+        if (Deallocate)
+          Info.Allocator->deallocate(Info.Options, P);
+        else
+          V.push_back(P);
+      }
+      while (!V.empty()) {
+        Info.Allocator->deallocate(Info.Options, V.back());
+        V.pop_back();
+      }
+    });
+
   {
     std::unique_lock<std::mutex> Lock(Mutex);
     Ready = true;
@@ -261,36 +287,101 @@ TEST_F(MapAllocatorWithReleaseTest, SecondaryThreadsRace) {
   }
   for (auto &T : Threads)
     T.join();
-  scudo::ScopedString Str;
-  Allocator->getStats(&Str);
-  Str.output();
 }
 
-struct MapAllocatorCacheTest : public Test {
-  static constexpr scudo::u32 UnmappedMarker = 0xDEADBEEF;
+TEST(ScudoSecondaryTest, AllocatorWithReleaseThreadsRace) {
+  testAllocatorWithReleaseThreadsRace<TestNoCacheConfig>();
+  testAllocatorWithReleaseThreadsRace<TestNoCacheNoGuardPageConfig>();
+}
+
+template <typename Config>
+void testGetMappedSize(scudo::uptr Size, scudo::uptr *mapped,
+                       scudo::uptr *guard_page_size) {
+  AllocatorInfoType<Config> Info;
 
-  static void testUnmapCallback(scudo::MemMapT &MemMap) {
+  scudo::uptr Stats[scudo::StatCount] = {};
+  Info.GlobalStats.get(Stats);
+  *mapped = Stats[scudo::StatMapped];
+  Stats[scudo::StatMapped] = 0;
+
+  // Make sure the allocation is aligned to a page boundary so that the checks
+  // in the tests can avoid problems due to allocations having different
+  // alignments.
+  void *Ptr = Info.Allocator->allocate(Info.Options, Size, PageSize);
+  EXPECT_NE(Ptr, nullptr);
+
+  Info.GlobalStats.get(Stats);
+  EXPECT_GE(Stats[scudo::StatMapped], *mapped);
+  *mapped = Stats[scudo::StatMapped] - *mapped;
+
+  Info.Allocator->deallocate(Info.Options, Ptr);
+
+  *guard_page_size = Info.Allocator->getGuardPageSize();
+}
+
+TEST(ScudoSecondaryTest, VerifyGuardPageOption) {
+  static scudo::uptr AllocSize = 1000 * PageSize;
+
+  // Verify that a config with guard pages enabled:
+  //  - Non-zero sized guard page
+  //  - Mapped in at least the size of the allocation plus 2 * guard page size
+  scudo::uptr guard_mapped = 0;
+  scudo::uptr guard_page_size = 0;
+  testGetMappedSize<TestNoCacheConfig>(AllocSize, &guard_mapped,
+                                       &guard_page_size);
+  EXPECT_GT(guard_page_size, 0U);
+  EXPECT_GE(guard_mapped, AllocSize + 2 * guard_page_size);
+
+  // Verify that a config with guard pages disabled:
+  //  - Zero sized guard page
+  //  - The total mapped in is greater than the allocation size
+  scudo::uptr no_guard_mapped = 0;
+  scudo::uptr no_guard_page_size = 0;
+  testGetMappedSize<TestNoCacheNoGuardPageConfig>(AllocSize, &no_guard_mapped,
+                                                  &no_guard_page_size);
+  EXPECT_EQ(no_guard_page_size, 0U);
+  EXPECT_GE(no_guard_mapped, AllocSize);
+
+  // Verify that a guard page config mapped in at least twice the size of
+  // their guard page when compared to a no guard page config.
+  EXPECT_GE(guard_mapped, no_guard_mapped + guard_page_size * 2);
+}
+
+// Value written to cache entries that are unmapped.
+static scudo::u32 UnmappedMarker = 0xDEADBEEF;
+
+template <class Config> struct CacheInfoType {
+  static void addMarkerToMapCallback(scudo::MemMapT &MemMap) {
+    // When a cache entry is unmaped, don't unmap it write a special marker
+    // to indicate the cache entry was released. The real unmap will happen
+    // in the destructor. It is assumed that all of these maps will be in
+    // the MemMaps vector.
     scudo::u32 *Ptr = reinterpret_cast<scudo::u32 *>(MemMap.getBase());
     *Ptr = UnmappedMarker;
   }
 
-  using SecondaryConfig = scudo::SecondaryConfig<TestConfig>;
+  using SecondaryConfig = scudo::SecondaryConfig<TestCacheConfig>;
   using CacheConfig = SecondaryConfig::CacheConfig;
-  using CacheT = scudo::MapAllocatorCache<CacheConfig, testUnmapCallback>;
-
+  using CacheT = scudo::MapAllocatorCache<CacheConfig, addMarkerToMapCallback>;
+  scudo::Options Options = getOptionsForConfig<SecondaryConfig>();
   std::unique_ptr<CacheT> Cache = std::make_unique<CacheT>();
-
-  const scudo::uptr PageSize = scudo::getPageSizeCached();
+  std::vector<scudo::MemMapT> MemMaps;
   // The current test allocation size is set to the maximum
   // cache entry size
   static constexpr scudo::uptr TestAllocSize =
       CacheConfig::getDefaultMaxEntrySize();
 
-  scudo::Options Options = getOptionsForConfig<SecondaryConfig>();
+  CacheInfoType() { Cache->init(/*ReleaseToOsInterval=*/-1); }
 
-  void SetUp() override { Cache->init(/*ReleaseToOsInterval=*/-1); }
+  ~CacheInfoType() {
+    if (Cache == nullptr) {
+      return;
+    }
 
-  void TearDown() override { Cache->unmapTestOnly(); }
+    // Clean up MemMaps
+    for (auto &MemMap : MemMaps)
+      MemMap.unmap();
+  }
 
   scudo::MemMapT allocate(scudo::uptr Size) {
     scudo::uptr MapSize = scudo::roundUp(Size, PageSize);
@@ -304,8 +395,7 @@ struct MapAllocatorCacheTest : public Test {
     return MemMap;
   }
 
-  void fillCacheWithSameSizeBlocks(std::vector<scudo::MemMapT> &MemMaps,
-                                   scudo::uptr NumEntries, scudo::uptr Size) {
+  void fillCacheWithSameSizeBlocks(scudo::uptr NumEntries, scudo::uptr Size) {
     for (scudo::uptr I = 0; I < NumEntries; I++) {
       MemMaps.emplace_back(allocate(Size));
       auto &MemMap = MemMaps[I];
@@ -315,58 +405,60 @@ struct MapAllocatorCacheTest : public Test {
   }
 };
 
-TEST_F(MapAllocatorCacheTest, CacheOrder) {
-  std::vector<scudo::MemMapT> MemMaps;
-  Cache->setOption(scudo::Option::MaxCacheEntriesCount,
-                   CacheConfig::getEntriesArraySize());
+TEST(ScudoSecondaryTest, AllocatorCacheEntryOrder) {
+  CacheInfoType<TestCacheConfig> Info;
+  using CacheConfig = CacheInfoType<TestCacheConfig>::CacheConfig;
 
-  fillCacheWithSameSizeBlocks(MemMaps, CacheConfig::getEntriesArraySize(),
-                              TestAllocSize);
+  Info.Cache->setOption(scudo::Option::MaxCacheEntriesCount,
+                        CacheConfig::getEntriesArraySize());
+
+  Info.fillCacheWithSameSizeBlocks(CacheConfig::getEntriesArraySize(),
+                                   Info.TestAllocSize);
 
   // Retrieval order should be the inverse of insertion order
   for (scudo::uptr I = CacheConfig::getEntriesArraySize(); I > 0; I--) {
     scudo::uptr EntryHeaderPos;
-    scudo::CachedBlock Entry =
-        Cache->retrieve(0, TestAllocSize, PageSize, 0, EntryHeaderPos);
-    EXPECT_EQ(Entry.MemMap.getBase(), MemMaps[I - 1].getBase());
+    scudo::CachedBlock Entry = Info.Cache->retrieve(
+        0, Info.TestAllocSize, PageSize, 0, EntryHeaderPos);
+    EXPECT_EQ(Entry.MemMap.getBase(), Info.MemMaps[I - 1].getBase());
   }
-
-  // Clean up MemMaps
-  for (auto &MemMap : MemMaps)
-    MemMap.unmap();
 }
 
-TEST_F(MapAllocatorCacheTest, PartialChunkHeuristicRetrievalTest) {
+TEST(ScudoSecondaryTest, AllocatorCachePartialChunkHeuristicRetrievalTest) {
+  CacheInfoType<TestCacheConfig> Info;
+
   const scudo::uptr FragmentedPages =
       1 + scudo::CachedBlock::MaxReleasedCachePages;
   scudo::uptr EntryHeaderPos;
   scudo::CachedBlock Entry;
-  scudo::MemMapT MemMap = allocate(PageSize + FragmentedPages * PageSize);
-  Cache->store(Options, MemMap.getBase(), MemMap.getCapacity(),
-               MemMap.getBase(), MemMap);
+  scudo::MemMapT MemMap = Info.allocate(PageSize + FragmentedPages * PageSize);
+  Info.Cache->store(Info.Options, MemMap.getBase(), MemMap.getCapacity(),
+                    MemMap.getBase(), MemMap);
 
   // FragmentedPages > MaxAllowedFragmentedPages so PageSize
   // cannot be retrieved from the cache
-  Entry = Cache->retrieve(/*MaxAllowedFragmentedPages=*/0, PageSize, PageSize,
-                          0, EntryHeaderPos);
+  Entry = Info.Cache->retrieve(/*MaxAllowedFragmentedPages=*/0, PageSize,
+                               PageSize, 0, EntryHeaderPos);
   EXPECT_FALSE(Entry.isValid());
 
   // FragmentedPages == MaxAllowedFragmentedPages so PageSize
   // can be retrieved from the cache
-  Entry =
-      Cache->retrieve(FragmentedPages, PageSize, PageSize, 0, EntryHeaderPos);
+  Entry = Info.Cache->retrieve(FragmentedPages, PageSize, PageSize, 0,
+                               EntryHeaderPos);
   EXPECT_TRUE(Entry.isValid());
 
   MemMap.unmap();
 }
 
-TEST_F(MapAllocatorCacheTest, MemoryLeakTest) {
-  std::vector<scudo::MemMapT> MemMaps;
+TEST(ScudoSecondaryTest, AllocatorCacheMemoryLeakTest) {
+  CacheInfoType<TestCacheConfig> Info;
+  using CacheConfig = CacheInfoType<TestCacheConfig>::CacheConfig;
+
   // Fill the cache above MaxEntriesCount to force an eviction
   // The first cache entry should be evicted (because it is the oldest)
   // due to the maximum number of entries being reached
-  fillCacheWithSameSizeBlocks(
-      MemMaps, CacheConfig::getDefaultMaxEntriesCount() + 1, TestAllocSize);
+  Info.fillCacheWithSameSizeBlocks(CacheConfig::getDefaultMaxEntriesCount() + 1,
+                                   Info.TestAllocSize);
 
   std::vector<scudo::CachedBlock> RetrievedEntries;
 
@@ -374,16 +466,40 @@ TEST_F(MapAllocatorCacheTest, MemoryLeakTest) {
   // inserted into the cache
   for (scudo::uptr I = CacheConfig::getDefaultMaxEntriesCount(); I > 0; I--) {
     scudo::uptr EntryHeaderPos;
-    RetrievedEntries.push_back(
-        Cache->retrieve(0, TestAllocSize, PageSize, 0, EntryHeaderPos));
-    EXPECT_EQ(MemMaps[I].getBase(), RetrievedEntries.back().MemMap.getBase());
+    RetrievedEntries.push_back(Info.Cache->retrieve(
+        0, Info.TestAllocSize, PageSize, 0, EntryHeaderPos));
+    EXPECT_EQ(Info.MemMaps[I].getBase(),
+              RetrievedEntries.back().MemMap.getBase());
   }
 
   // Evicted entry should be marked due to unmap callback
-  EXPECT_EQ(*reinterpret_cast<scudo::u32 *>(MemMaps[0].getBase()),
+  EXPECT_EQ(*reinterpret_cast<scudo::u32 *>(Info.MemMaps[0].getBase()),
             UnmappedMarker);
+}
+
+TEST(ScudoSecondaryTest, AllocatorCacheOptions) {
+  CacheInfoType<TestCacheConfig> Info;
 
-  // Clean up MemMaps
-  for (auto &MemMap : MemMaps)
-    MemMap.unmap();
+  // Attempt to set a maximum number of entries higher than the array size.
+  EXPECT_TRUE(
+      Info.Cache->setOption(scudo::Option::MaxCacheEntriesCount, 4096U));
+
+  // Attempt to set an invalid (negative) number of entries
+  EXPECT_FALSE(Info.Cache->setOption(scudo::Option::MaxCacheEntriesCount, -1));
+
+  // Various valid combinations.
+  EXPECT_TRUE(Info.Cache->setOption(scudo::Option::MaxCacheEntriesCount, 4U));
+  EXPECT_TRUE(
+      Info.Cache->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 20));
+  EXPECT_TRUE(Info.Cache->canCache(1UL << 18));
+  EXPECT_TRUE(
+      Info.Cache->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 17));
+  EXPECT_FALSE(Info.Cache->canCache(1UL << 18));
+  EXPECT_TRUE(Info.Cache->canCache(1UL << 16));
+  EXPECT_TRUE(Info.Cache->setOption(scudo::Option::MaxCacheEntriesCount, 0U));
+  EXPECT_FALSE(Info.Cache->canCache(1UL << 16));
+  EXPECT_TRUE(Info.Cache->setOption(scudo::Option::MaxCacheEntriesCount, 4U));
+  EXPECT_TRUE(
+      Info.Cache->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 20));
+  EXPECT_TRUE(Info.Cache->canCache(1UL << 16));
 }
diff --git a/standalone/type_traits.h b/standalone/type_traits.h
new file mode 100644
index 0000000..16ed5a0
--- /dev/null
+++ b/standalone/type_traits.h
@@ -0,0 +1,47 @@
+//===-- type_traits.h -------------------------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef SCUDO_TYPE_TRAITS_H_
+#define SCUDO_TYPE_TRAITS_H_
+
+namespace scudo {
+
+template <typename T> struct removeConst {
+  using type = T;
+};
+template <typename T> struct removeConst<const T> {
+  using type = T;
+};
+
+// This is only used for SFINAE when detecting if a type is defined.
+template <typename T> struct voidAdaptor {
+  using type = void;
+};
+
+template <typename L, typename R> struct assertSameType {
+  template <typename, typename> struct isSame {
+    static constexpr bool value = false;
+  };
+  template <typename T> struct isSame<T, T> {
+    static constexpr bool value = true;
+  };
+  static_assert(isSame<L, R>::value, "Type mismatches");
+  using type = R;
+};
+
+template <typename T> struct isPointer {
+  static constexpr bool value = false;
+};
+
+template <typename T> struct isPointer<T *> {
+  static constexpr bool value = true;
+};
+
+} // namespace scudo
+
+#endif // SCUDO_TYPE_TRAITS_H_
```

