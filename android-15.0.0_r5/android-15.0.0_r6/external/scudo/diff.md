```diff
diff --git a/Android.bp b/Android.bp
index 7dd3eca..6236b5e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -84,9 +84,29 @@ cc_defaults {
     },
 }
 
+cc_defaults {
+    name: "scudo_warning_defaults",
+    cflags: [
+        "-Wall",
+        "-Wextra",
+        "-Wunused",
+        "-Wno-unused-result",
+        "-Wconversion",
+
+        "-Werror=pointer-to-int-cast",
+        "-Werror=int-to-pointer-cast",
+        "-Werror=thread-safety",
+        "-Werror=type-limits",
+        "-Werror",
+    ],
+}
+
 cc_defaults {
     name: "libscudo_defaults",
-    defaults: ["scudo_config_defaults"],
+    defaults: [
+        "scudo_config_defaults",
+        "scudo_warning_defaults",
+    ],
     native_coverage: false,
     ramdisk_available: true,
     vendor_ramdisk_available: true,
@@ -102,18 +122,6 @@ cc_defaults {
         "-fno-rtti",
         // This option speeds up alloc/free code paths by about 5% to 7%.
         "-fno-stack-protector",
-
-        "-Wall",
-        "-Wextra",
-        "-Wunused",
-        "-Wno-unused-result",
-        "-Wconversion",
-
-        "-Werror=pointer-to-int-cast",
-        "-Werror=int-to-pointer-cast",
-        "-Werror=thread-safety",
-        "-Werror=type-limits",
-        "-Werror",
     ],
     cppflags: [
         "-nostdinc++",
@@ -200,12 +208,12 @@ cc_library {
     name: "libscudo",
     defaults: ["libscudo_defaults"],
     visibility: [
-      "//bionic:__subpackages__",
-      "//build/kati:__subpackages__",
-      "//frameworks/libs/native_bridge_support/android_api/libc:__subpackages__",
-      "//external/ninja:__subpackages__",
-      "//external/stg:__subpackages__",
-      "//system/core/debuggerd:__subpackages__",
+        "//bionic:__subpackages__",
+        "//build/kati:__subpackages__",
+        "//frameworks/libs/native_bridge_support/android_api/libc:__subpackages__",
+        "//external/ninja:__subpackages__",
+        "//external/stg:__subpackages__",
+        "//system/core/debuggerd:__subpackages__",
     ],
     shared: {
         enabled: false,
@@ -226,13 +234,16 @@ cc_library_static {
     name: "libscudo_for_testing",
     defaults: ["libscudo_defaults"],
     cflags: [
-        "-DSCUDO_DEBUG",
+        "-DSCUDO_DEBUG=1",
     ],
 }
 
 cc_defaults {
     name: "scudo_unit_tests_default",
-    defaults: ["scudo_config_defaults"],
+    defaults: [
+        "scudo_config_defaults",
+        "scudo_warning_defaults",
+    ],
     isolated: true,
     static_libs: ["libscudo_for_testing"],
     include_dirs: [
@@ -240,13 +251,12 @@ cc_defaults {
         "external/scudo/standalone/include",
     ],
     cflags: [
-        "-Wconversion",
         // In memtag_test.cpp, some tests are disabled by GTEST_SKIP() so that
         // they won't be run. However, for those disabled tests, it may contain
         // unreachable code paths which will mislead some compiler checks. Given
         // this flag won't be impacted too much, disable it only in the test.
         "-Wno-unreachable-code-loop-increment",
-        "-DSCUDO_DEBUG",
+        "-DSCUDO_DEBUG=1",
         "-DSCUDO_NO_TEST_MAIN",
     ],
     target: {
@@ -321,7 +331,7 @@ cc_fuzz {
     ],
     srcs: ["standalone/fuzz/get_error_info_fuzzer.cpp"],
     fuzz_config: {
-        componentid: 87896
+        componentid: 87896,
     },
 }
 
diff --git a/config/custom_scudo_config.h b/config/custom_scudo_config.h
index 8fe8cbc..b1b1d9a 100644
--- a/config/custom_scudo_config.h
+++ b/config/custom_scudo_config.h
@@ -220,6 +220,13 @@ struct AndroidLowMemoryConfig {
 
 #if defined(__ANDROID__)
 
+#include <unistd.h>
+
+#if defined(PAGE_SIZE)
+// This is to guarantee that the getPageSizeCached() function is constexpr.
+static_assert(getPageSizeCached() != 0, "getPageSizeCached() is zero");
+#endif
+
 #if defined(SCUDO_LOW_MEMORY)
 typedef AndroidLowMemoryConfig Config;
 #else
diff --git a/standalone/allocator_common.h b/standalone/allocator_common.h
index 2b77516..0169601 100644
--- a/standalone/allocator_common.h
+++ b/standalone/allocator_common.h
@@ -75,16 +75,13 @@ template <class SizeClassAllocator> struct BatchGroup {
   BatchGroup *Next;
   // The compact base address of each group
   uptr CompactPtrGroupBase;
-  // Cache value of SizeClassAllocatorLocalCache::getMaxCached()
-  u16 MaxCachedPerBatch;
-  // Number of blocks pushed into this group. This is an increment-only
-  // counter.
-  uptr PushedBlocks;
   // This is used to track how many bytes are not in-use since last time we
   // tried to release pages.
   uptr BytesInBGAtLastCheckpoint;
   // Blocks are managed by TransferBatch in a list.
   SinglyLinkedList<TransferBatch<SizeClassAllocator>> Batches;
+  // Cache value of SizeClassAllocatorLocalCache::getMaxCached()
+  u16 MaxCachedPerBatch;
 };
 
 } // namespace scudo
diff --git a/standalone/allocator_config.def b/standalone/allocator_config.def
index dcd130a..ce37b1c 100644
--- a/standalone/allocator_config.def
+++ b/standalone/allocator_config.def
@@ -56,16 +56,8 @@ BASE_OPTIONAL(const bool, MaySupportMemoryTagging, false)
 // SizeClassMap to use with the Primary.
 PRIMARY_REQUIRED_TYPE(SizeClassMap)
 
-// Defines the type and scale of a compact pointer. A compact pointer can
-// be understood as the offset of a pointer within the region it belongs
-// to, in increments of a power-of-2 scale. See `CompactPtrScale` also.
-PRIMARY_REQUIRED_TYPE(CompactPtrT)
-
 // PRIMARY_REQUIRED(TYPE, NAME)
 //
-// The scale of a compact pointer. E.g., Ptr = Base + (CompactPtr << Scale).
-PRIMARY_REQUIRED(const uptr, CompactPtrScale)
-
 // Log2 of the size of a size class region, as used by the Primary.
 PRIMARY_REQUIRED(const uptr, RegionSizeLog)
 
@@ -86,6 +78,9 @@ PRIMARY_REQUIRED(const s32, MaxReleaseToOsIntervalMs)
 
 // PRIMARY_OPTIONAL(TYPE, NAME, DEFAULT)
 //
+// The scale of a compact pointer. E.g., Ptr = Base + (CompactPtr << Scale).
+PRIMARY_OPTIONAL(const uptr, CompactPtrScale, SCUDO_MIN_ALIGNMENT_LOG)
+
 // Indicates support for offsetting the start of a region by a random number of
 // pages. This is only used if `EnableContiguousRegions` is enabled.
 PRIMARY_OPTIONAL(const bool, EnableRandomOffset, false)
@@ -104,6 +99,11 @@ PRIMARY_OPTIONAL(const bool, EnableContiguousRegions, true)
 // guarantee a performance benefit.
 PRIMARY_OPTIONAL_TYPE(ConditionVariableT, ConditionVariableDummy)
 
+// Defines the type and scale of a compact pointer. A compact pointer can
+// be understood as the offset of a pointer within the region it belongs
+// to, in increments of a power-of-2 scale. See `CompactPtrScale` also.
+PRIMARY_OPTIONAL_TYPE(CompactPtrT, uptr)
+
 // SECONDARY_REQUIRED_TEMPLATE_TYPE(NAME)
 //
 // Defines the type of Secondary Cache to use.
diff --git a/standalone/benchmarks/malloc_benchmark.cpp b/standalone/benchmarks/malloc_benchmark.cpp
deleted file mode 100644
index 4fb05b7..0000000
--- a/standalone/benchmarks/malloc_benchmark.cpp
+++ /dev/null
@@ -1,105 +0,0 @@
-//===-- malloc_benchmark.cpp ------------------------------------*- C++ -*-===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "allocator_config.h"
-#include "combined.h"
-#include "common.h"
-
-#include "benchmark/benchmark.h"
-
-#include <memory>
-#include <vector>
-
-void *CurrentAllocator;
-template <typename Config> void PostInitCallback() {
-  reinterpret_cast<scudo::Allocator<Config> *>(CurrentAllocator)->initGwpAsan();
-}
-
-template <typename Config> static void BM_malloc_free(benchmark::State &State) {
-  using AllocatorT = scudo::Allocator<Config, PostInitCallback<Config>>;
-  auto Deleter = [](AllocatorT *A) {
-    A->unmapTestOnly();
-    delete A;
-  };
-  std::unique_ptr<AllocatorT, decltype(Deleter)> Allocator(new AllocatorT,
-                                                           Deleter);
-  CurrentAllocator = Allocator.get();
-
-  const size_t NBytes = State.range(0);
-  size_t PageSize = scudo::getPageSizeCached();
-
-  for (auto _ : State) {
-    void *Ptr = Allocator->allocate(NBytes, scudo::Chunk::Origin::Malloc);
-    auto *Data = reinterpret_cast<uint8_t *>(Ptr);
-    for (size_t I = 0; I < NBytes; I += PageSize)
-      Data[I] = 1;
-    benchmark::DoNotOptimize(Ptr);
-    Allocator->deallocate(Ptr, scudo::Chunk::Origin::Malloc);
-  }
-
-  State.SetBytesProcessed(uint64_t(State.iterations()) * uint64_t(NBytes));
-}
-
-static const size_t MinSize = 8;
-static const size_t MaxSize = 128 * 1024;
-
-// FIXME: Add DefaultConfig here once we can tear down the exclusive TSD
-// cleanly.
-BENCHMARK_TEMPLATE(BM_malloc_free, scudo::AndroidConfig)
-    ->Range(MinSize, MaxSize);
-#if SCUDO_CAN_USE_PRIMARY64
-BENCHMARK_TEMPLATE(BM_malloc_free, scudo::FuchsiaConfig)
-    ->Range(MinSize, MaxSize);
-#endif
-
-template <typename Config>
-static void BM_malloc_free_loop(benchmark::State &State) {
-  using AllocatorT = scudo::Allocator<Config, PostInitCallback<Config>>;
-  auto Deleter = [](AllocatorT *A) {
-    A->unmapTestOnly();
-    delete A;
-  };
-  std::unique_ptr<AllocatorT, decltype(Deleter)> Allocator(new AllocatorT,
-                                                           Deleter);
-  CurrentAllocator = Allocator.get();
-
-  const size_t NumIters = State.range(0);
-  size_t PageSize = scudo::getPageSizeCached();
-  std::vector<void *> Ptrs(NumIters);
-
-  for (auto _ : State) {
-    size_t SizeLog2 = 0;
-    for (void *&Ptr : Ptrs) {
-      Ptr = Allocator->allocate(1 << SizeLog2, scudo::Chunk::Origin::Malloc);
-      auto *Data = reinterpret_cast<uint8_t *>(Ptr);
-      for (size_t I = 0; I < 1 << SizeLog2; I += PageSize)
-        Data[I] = 1;
-      benchmark::DoNotOptimize(Ptr);
-      SizeLog2 = (SizeLog2 + 1) % 16;
-    }
-    for (void *&Ptr : Ptrs)
-      Allocator->deallocate(Ptr, scudo::Chunk::Origin::Malloc);
-  }
-
-  State.SetBytesProcessed(uint64_t(State.iterations()) * uint64_t(NumIters) *
-                          8192);
-}
-
-static const size_t MinIters = 8;
-static const size_t MaxIters = 32 * 1024;
-
-// FIXME: Add DefaultConfig here once we can tear down the exclusive TSD
-// cleanly.
-BENCHMARK_TEMPLATE(BM_malloc_free_loop, scudo::AndroidConfig)
-    ->Range(MinIters, MaxIters);
-#if SCUDO_CAN_USE_PRIMARY64
-BENCHMARK_TEMPLATE(BM_malloc_free_loop, scudo::FuchsiaConfig)
-    ->Range(MinIters, MaxIters);
-#endif
-
-BENCHMARK_MAIN();
diff --git a/standalone/combined.h b/standalone/combined.h
index f9ed365..a5f1bc3 100644
--- a/standalone/combined.h
+++ b/standalone/combined.h
@@ -140,6 +140,9 @@ public:
   typedef typename QuarantineT::CacheT QuarantineCacheT;
 
   void init() {
+    // Make sure that the page size is initialized if it's not a constant.
+    CHECK_NE(getPageSizeCached(), 0U);
+
     performSanityChecks();
 
     // Check if hardware CRC32 is supported in the binary and by the platform,
@@ -549,6 +552,19 @@ public:
     // header to reflect the size change.
     if (reinterpret_cast<uptr>(OldTaggedPtr) + NewSize <= BlockEnd) {
       if (NewSize > OldSize || (OldSize - NewSize) < getPageSizeCached()) {
+        // If we have reduced the size, set the extra bytes to the fill value
+        // so that we are ready to grow it again in the future.
+        if (NewSize < OldSize) {
+          const FillContentsMode FillContents =
+              TSDRegistry.getDisableMemInit() ? NoFill
+                                              : Options.getFillContentsMode();
+          if (FillContents != NoFill) {
+            memset(reinterpret_cast<char *>(OldTaggedPtr) + NewSize,
+                   FillContents == ZeroFill ? 0 : PatternFillByte,
+                   OldSize - NewSize);
+          }
+        }
+
         Header.SizeOrUnusedBytes =
             (ClassId ? NewSize
                      : BlockEnd -
@@ -1693,14 +1709,12 @@ private:
       return;
     // N.B. because RawStackDepotMap is part of RawRingBufferMap, the order
     // is very important.
-    RB->RawStackDepotMap.unmap(RB->RawStackDepotMap.getBase(),
-                               RB->RawStackDepotMap.getCapacity());
+    RB->RawStackDepotMap.unmap();
     // Note that the `RB->RawRingBufferMap` is stored on the pages managed by
     // itself. Take over the ownership before calling unmap() so that any
     // operation along with unmap() won't touch inaccessible pages.
     MemMapT RawRingBufferMap = RB->RawRingBufferMap;
-    RawRingBufferMap.unmap(RawRingBufferMap.getBase(),
-                           RawRingBufferMap.getCapacity());
+    RawRingBufferMap.unmap();
     atomic_store(&RingBufferAddress, 0, memory_order_release);
   }
 
diff --git a/standalone/common.cpp b/standalone/common.cpp
index 06e9306..80134c3 100644
--- a/standalone/common.cpp
+++ b/standalone/common.cpp
@@ -12,13 +12,21 @@
 
 namespace scudo {
 
-uptr PageSizeCached;
+#if !defined(SCUDO_PAGE_SIZE)
+uptr PageSizeCached = 0;
+uptr PageSizeLogCached = 0;
+
+// Must be defined in platform specific code.
 uptr getPageSize();
 
+// This must be called in the init path or there could be a race if multiple
+// threads try to set the cached values.
 uptr getPageSizeSlow() {
   PageSizeCached = getPageSize();
   CHECK_NE(PageSizeCached, 0);
+  PageSizeLogCached = getLog2(PageSizeCached);
   return PageSizeCached;
 }
+#endif
 
 } // namespace scudo
diff --git a/standalone/common.h b/standalone/common.h
index 151fbd3..e5dfda2 100644
--- a/standalone/common.h
+++ b/standalone/common.h
@@ -133,18 +133,40 @@ inline void computePercentage(uptr Numerator, uptr Denominator, uptr *Integral,
 
 // Platform specific functions.
 
+#if defined(SCUDO_PAGE_SIZE)
+
+inline constexpr uptr getPageSizeCached() { return SCUDO_PAGE_SIZE; }
+
+inline constexpr uptr getPageSizeSlow() { return getPageSizeCached(); }
+
+inline constexpr uptr getPageSizeLogCached() {
+  return static_cast<uptr>(__builtin_ctzl(SCUDO_PAGE_SIZE));
+}
+
+#else
+
 extern uptr PageSizeCached;
+extern uptr PageSizeLogCached;
+
 uptr getPageSizeSlow();
+
 inline uptr getPageSizeCached() {
-#if SCUDO_ANDROID && defined(PAGE_SIZE)
-  // Most Android builds have a build-time constant page size.
-  return PAGE_SIZE;
-#endif
   if (LIKELY(PageSizeCached))
     return PageSizeCached;
   return getPageSizeSlow();
 }
 
+inline uptr getPageSizeLogCached() {
+  if (LIKELY(PageSizeLogCached))
+    return PageSizeLogCached;
+  // PageSizeLogCached and PageSizeCached are both set in getPageSizeSlow()
+  getPageSizeSlow();
+  DCHECK_NE(PageSizeLogCached, 0);
+  return PageSizeLogCached;
+}
+
+#endif
+
 // Returns 0 if the number of CPUs could not be determined.
 u32 getNumberOfCPUs();
 
diff --git a/standalone/linux.cpp b/standalone/linux.cpp
index 2746951..6cc8e0c 100644
--- a/standalone/linux.cpp
+++ b/standalone/linux.cpp
@@ -40,7 +40,10 @@
 
 namespace scudo {
 
+#if !defined(SCUDO_PAGE_SIZE)
+// This function is only used when page size is not hard-coded.
 uptr getPageSize() { return static_cast<uptr>(sysconf(_SC_PAGESIZE)); }
+#endif
 
 void NORETURN die() { abort(); }
 
diff --git a/standalone/list.h b/standalone/list.h
index 0137667..6b952a6 100644
--- a/standalone/list.h
+++ b/standalone/list.h
@@ -11,17 +11,113 @@
 
 #include "internal_defs.h"
 
+// TODO: Move the helpers to a header.
+namespace {
+template <typename T> struct isPointer {
+  static constexpr bool value = false;
+};
+
+template <typename T> struct isPointer<T *> {
+  static constexpr bool value = true;
+};
+} // namespace
+
 namespace scudo {
 
 // Intrusive POD singly and doubly linked list.
 // An object with all zero fields should represent a valid empty list. clear()
 // should be called on all non-zero-initialized objects before using.
+//
+// The intrusive list requires the member `Next` (and `Prev` if doubly linked
+// list)` defined in the node type. The type of `Next`/`Prev` can be a pointer
+// or an index to an array. For example, if the storage of the nodes is an
+// array, instead of using a pointer type, linking with an index type can save
+// some space.
+//
+// There are two things to be noticed while using an index type,
+//   1. Call init() to set up the base address of the array.
+//   2. Define `EndOfListVal` as the nil of the list.
+
+template <class T, bool LinkWithPtr = isPointer<decltype(T::Next)>::value>
+class LinkOp {
+public:
+  LinkOp() = default;
+  LinkOp(UNUSED T *BaseT, UNUSED uptr BaseSize) {}
+  void init(UNUSED T *LinkBase, UNUSED uptr Size) {}
+  T *getBase() const { return nullptr; }
+  uptr getSize() const { return 0; }
+
+  T *getNext(T *X) const { return X->Next; }
+  void setNext(T *X, T *Next) const { X->Next = Next; }
+
+  T *getPrev(T *X) const { return X->Prev; }
+  void setPrev(T *X, T *Prev) const { X->Prev = Prev; }
+
+  T *getEndOfListVal() const { return nullptr; }
+};
+
+template <class T> class LinkOp<T, /*LinkWithPtr=*/false> {
+public:
+  using LinkTy = decltype(T::Next);
+
+  LinkOp() = default;
+  LinkOp(T *BaseT, uptr BaseSize) : Base(BaseT), Size(BaseSize) {}
+  void init(T *LinkBase, uptr BaseSize) {
+    Base = LinkBase;
+    // TODO: Check if the `BaseSize` can fit in `Size`.
+    Size = static_cast<LinkTy>(BaseSize);
+  }
+  T *getBase() const { return Base; }
+  LinkTy getSize() const { return Size; }
+
+  T *getNext(T *X) const {
+    DCHECK_NE(getBase(), nullptr);
+    if (X->Next == getEndOfListVal())
+      return nullptr;
+    DCHECK_LT(X->Next, Size);
+    return &Base[X->Next];
+  }
+  // Set `X->Next` to `Next`.
+  void setNext(T *X, T *Next) const {
+    // TODO: Check if the offset fits in the size of `LinkTy`.
+    if (Next == nullptr)
+      X->Next = getEndOfListVal();
+    else
+      X->Next = static_cast<LinkTy>(Next - Base);
+  }
 
-template <class T> class IteratorBase {
+  T *getPrev(T *X) const {
+    DCHECK_NE(getBase(), nullptr);
+    if (X->Prev == getEndOfListVal())
+      return nullptr;
+    DCHECK_LT(X->Prev, Size);
+    return &Base[X->Prev];
+  }
+  // Set `X->Prev` to `Prev`.
+  void setPrev(T *X, T *Prev) const {
+    DCHECK_LT(reinterpret_cast<uptr>(Prev),
+              reinterpret_cast<uptr>(Base + Size));
+    if (Prev == nullptr)
+      X->Prev = getEndOfListVal();
+    else
+      X->Prev = static_cast<LinkTy>(Prev - Base);
+  }
+
+  // TODO: `LinkTy` should be the same as decltype(T::EndOfListVal).
+  LinkTy getEndOfListVal() const { return T::EndOfListVal; }
+
+protected:
+  T *Base = nullptr;
+  LinkTy Size = 0;
+};
+
+template <class T> class IteratorBase : public LinkOp<T> {
 public:
-  explicit IteratorBase(T *CurrentT) : Current(CurrentT) {}
+  IteratorBase(const LinkOp<T> &Link, T *CurrentT)
+      : LinkOp<T>(Link), Current(CurrentT) {}
+
   IteratorBase &operator++() {
-    Current = Current->Next;
+    Current = this->getNext(Current);
     return *this;
   }
   bool operator!=(IteratorBase Other) const { return Current != Other.Current; }
@@ -31,7 +127,10 @@ private:
   T *Current;
 };
 
-template <class T> struct IntrusiveList {
+template <class T> struct IntrusiveList : public LinkOp<T> {
+  IntrusiveList() = default;
+  void init(T *Base, uptr BaseSize) { LinkOp<T>::init(Base, BaseSize); }
+
   bool empty() const { return Size == 0; }
   uptr size() const { return Size; }
 
@@ -48,11 +147,21 @@ template <class T> struct IntrusiveList {
   typedef IteratorBase<T> Iterator;
   typedef IteratorBase<const T> ConstIterator;
 
-  Iterator begin() { return Iterator(First); }
-  Iterator end() { return Iterator(nullptr); }
+  Iterator begin() {
+    return Iterator(LinkOp<T>(this->getBase(), this->getSize()), First);
+  }
+  Iterator end() {
+    return Iterator(LinkOp<T>(this->getBase(), this->getSize()), nullptr);
+  }
 
-  ConstIterator begin() const { return ConstIterator(First); }
-  ConstIterator end() const { return ConstIterator(nullptr); }
+  ConstIterator begin() const {
+    return ConstIterator(LinkOp<const T>(this->getBase(), this->getSize()),
+                         First);
+  }
+  ConstIterator end() const {
+    return ConstIterator(LinkOp<const T>(this->getBase(), this->getSize()),
+                         nullptr);
+  }
 
   void checkConsistency() const;
 
@@ -68,13 +177,13 @@ template <class T> void IntrusiveList<T>::checkConsistency() const {
     CHECK_EQ(Last, nullptr);
   } else {
     uptr Count = 0;
-    for (T *I = First;; I = I->Next) {
+    for (T *I = First;; I = this->getNext(I)) {
       Count++;
       if (I == Last)
         break;
     }
     CHECK_EQ(this->size(), Count);
-    CHECK_EQ(Last->Next, nullptr);
+    CHECK_EQ(this->getNext(Last), nullptr);
   }
 }
 
@@ -83,13 +192,16 @@ template <class T> struct SinglyLinkedList : public IntrusiveList<T> {
   using IntrusiveList<T>::Last;
   using IntrusiveList<T>::Size;
   using IntrusiveList<T>::empty;
+  using IntrusiveList<T>::setNext;
+  using IntrusiveList<T>::getNext;
+  using IntrusiveList<T>::getEndOfListVal;
 
   void push_back(T *X) {
-    X->Next = nullptr;
+    setNext(X, nullptr);
     if (empty())
       First = X;
     else
-      Last->Next = X;
+      setNext(Last, X);
     Last = X;
     Size++;
   }
@@ -97,14 +209,14 @@ template <class T> struct SinglyLinkedList : public IntrusiveList<T> {
   void push_front(T *X) {
     if (empty())
       Last = X;
-    X->Next = First;
+    setNext(X, First);
     First = X;
     Size++;
   }
 
   void pop_front() {
     DCHECK(!empty());
-    First = First->Next;
+    First = getNext(First);
     if (!First)
       Last = nullptr;
     Size--;
@@ -115,8 +227,8 @@ template <class T> struct SinglyLinkedList : public IntrusiveList<T> {
     DCHECK(!empty());
     DCHECK_NE(Prev, nullptr);
     DCHECK_NE(X, nullptr);
-    X->Next = Prev->Next;
-    Prev->Next = X;
+    setNext(X, getNext(Prev));
+    setNext(Prev, X);
     if (Last == Prev)
       Last = X;
     ++Size;
@@ -126,8 +238,8 @@ template <class T> struct SinglyLinkedList : public IntrusiveList<T> {
     DCHECK(!empty());
     DCHECK_NE(Prev, nullptr);
     DCHECK_NE(X, nullptr);
-    DCHECK_EQ(Prev->Next, X);
-    Prev->Next = X->Next;
+    DCHECK_EQ(getNext(Prev), X);
+    setNext(Prev, getNext(X));
     if (Last == X)
       Last = Prev;
     Size--;
@@ -140,7 +252,7 @@ template <class T> struct SinglyLinkedList : public IntrusiveList<T> {
     if (empty()) {
       *this = *L;
     } else {
-      Last->Next = L->First;
+      setNext(Last, L->First);
       Last = L->Last;
       Size += L->size();
     }
@@ -153,16 +265,21 @@ template <class T> struct DoublyLinkedList : IntrusiveList<T> {
   using IntrusiveList<T>::Last;
   using IntrusiveList<T>::Size;
   using IntrusiveList<T>::empty;
+  using IntrusiveList<T>::setNext;
+  using IntrusiveList<T>::getNext;
+  using IntrusiveList<T>::setPrev;
+  using IntrusiveList<T>::getPrev;
+  using IntrusiveList<T>::getEndOfListVal;
 
   void push_front(T *X) {
-    X->Prev = nullptr;
+    setPrev(X, nullptr);
     if (empty()) {
       Last = X;
     } else {
-      DCHECK_EQ(First->Prev, nullptr);
-      First->Prev = X;
+      DCHECK_EQ(getPrev(First), nullptr);
+      setPrev(First, X);
     }
-    X->Next = First;
+    setNext(X, First);
     First = X;
     Size++;
   }
@@ -171,37 +288,37 @@ template <class T> struct DoublyLinkedList : IntrusiveList<T> {
   void insert(T *X, T *Y) {
     if (Y == First)
       return push_front(X);
-    T *Prev = Y->Prev;
+    T *Prev = getPrev(Y);
     // This is a hard CHECK to ensure consistency in the event of an intentional
     // corruption of Y->Prev, to prevent a potential write-{4,8}.
-    CHECK_EQ(Prev->Next, Y);
-    Prev->Next = X;
-    X->Prev = Prev;
-    X->Next = Y;
-    Y->Prev = X;
+    CHECK_EQ(getNext(Prev), Y);
+    setNext(Prev, X);
+    setPrev(X, Prev);
+    setNext(X, Y);
+    setPrev(Y, X);
     Size++;
   }
 
   void push_back(T *X) {
-    X->Next = nullptr;
+    setNext(X, nullptr);
     if (empty()) {
       First = X;
     } else {
-      DCHECK_EQ(Last->Next, nullptr);
-      Last->Next = X;
+      DCHECK_EQ(getNext(Last), nullptr);
+      setNext(Last, X);
     }
-    X->Prev = Last;
+    setPrev(X, Last);
     Last = X;
     Size++;
   }
 
   void pop_front() {
     DCHECK(!empty());
-    First = First->Next;
+    First = getNext(First);
     if (!First)
       Last = nullptr;
     else
-      First->Prev = nullptr;
+      setPrev(First, nullptr);
     Size--;
   }
 
@@ -209,15 +326,15 @@ template <class T> struct DoublyLinkedList : IntrusiveList<T> {
   // catch potential corruption attempts, that could yield a mirrored
   // write-{4,8} primitive. nullptr checks are deemed less vital.
   void remove(T *X) {
-    T *Prev = X->Prev;
-    T *Next = X->Next;
+    T *Prev = getPrev(X);
+    T *Next = getNext(X);
     if (Prev) {
-      CHECK_EQ(Prev->Next, X);
-      Prev->Next = Next;
+      CHECK_EQ(getNext(Prev), X);
+      setNext(Prev, Next);
     }
     if (Next) {
-      CHECK_EQ(Next->Prev, X);
-      Next->Prev = Prev;
+      CHECK_EQ(getPrev(Next), X);
+      setPrev(Next, Prev);
     }
     if (First == X) {
       DCHECK_EQ(Prev, nullptr);
diff --git a/standalone/mem_map_base.h b/standalone/mem_map_base.h
index 99ab0cb..dbf4ec3 100644
--- a/standalone/mem_map_base.h
+++ b/standalone/mem_map_base.h
@@ -35,6 +35,8 @@ public:
     DCHECK((Addr == getBase()) || (Addr + Size == getBase() + getCapacity()));
     invokeImpl(&Derived::unmapImpl, Addr, Size);
   }
+  // A default implementation to unmap all pages.
+  void unmap() { unmap(getBase(), getCapacity()); }
 
   // This is used to remap a mapped range (either from map() or dispatched from
   // ReservedMemory). For example, we have reserved several pages and then we
diff --git a/standalone/mem_map_fuchsia.cpp b/standalone/mem_map_fuchsia.cpp
index fc793ab..9d6df2b 100644
--- a/standalone/mem_map_fuchsia.cpp
+++ b/standalone/mem_map_fuchsia.cpp
@@ -91,12 +91,15 @@ static bool IsNoMemError(zx_status_t Status) {
   return Status == ZX_ERR_NO_MEMORY || Status == ZX_ERR_NO_RESOURCES;
 }
 
+// Note: this constructor is only called by ReservedMemoryFuchsia::dispatch.
 MemMapFuchsia::MemMapFuchsia(uptr Base, uptr Capacity)
     : MapAddr(Base), WindowBase(Base), WindowSize(Capacity) {
   // Create the VMO.
   zx_status_t Status = _zx_vmo_create(Capacity, 0, &Vmo);
   if (UNLIKELY(Status != ZX_OK))
     dieOnError(Status, "zx_vmo_create", Capacity);
+
+  setVmoName(Vmo, "scudo:dispatched");
 }
 
 bool MemMapFuchsia::mapImpl(UNUSED uptr Addr, uptr Size, const char *Name,
diff --git a/standalone/platform.h b/standalone/platform.h
index 5af1275..3f017fa 100644
--- a/standalone/platform.h
+++ b/standalone/platform.h
@@ -21,6 +21,11 @@
 // See https://android.googlesource.com/platform/bionic/+/master/docs/defines.md
 #if defined(__BIONIC__)
 #define SCUDO_ANDROID 1
+// Transitive includes of unistd.h will get PAGE_SIZE if it is defined.
+#include <unistd.h>
+#if defined(PAGE_SIZE)
+#define SCUDO_PAGE_SIZE PAGE_SIZE
+#endif
 #else
 #define SCUDO_ANDROID 0
 #endif
diff --git a/standalone/primary32.h b/standalone/primary32.h
index ebfb8df..654b129 100644
--- a/standalone/primary32.h
+++ b/standalone/primary32.h
@@ -56,12 +56,9 @@ public:
   typedef TransferBatch<ThisT> TransferBatchT;
   typedef BatchGroup<ThisT> BatchGroupT;
 
-  static_assert(sizeof(BatchGroupT) <= sizeof(TransferBatchT),
-                "BatchGroupT uses the same class size as TransferBatchT");
-
   static uptr getSizeByClassId(uptr ClassId) {
     return (ClassId == SizeClassMap::BatchClassId)
-               ? sizeof(TransferBatchT)
+               ? Max(sizeof(BatchGroupT), sizeof(TransferBatchT))
                : SizeClassMap::getSizeByClassId(ClassId);
   }
 
@@ -332,6 +329,12 @@ public:
     }
   }
 
+  void getMemoryGroupFragmentationInfo(ScopedString *Str) {
+    // Each region is also a memory group because region size is the same as
+    // group size.
+    getFragmentationInfo(Str);
+  }
+
   bool setOption(Option O, sptr Value) {
     if (O == Option::ReleaseInterval) {
       const s32 Interval = Max(
@@ -525,9 +528,6 @@ private:
       // BatchClass hasn't enabled memory group. Use `0` to indicate there's no
       // memory group here.
       BG->CompactPtrGroupBase = 0;
-      // `BG` is also the block of BatchClassId. Note that this is different
-      // from `CreateGroup` in `pushBlocksImpl`
-      BG->PushedBlocks = 1;
       BG->BytesInBGAtLastCheckpoint = 0;
       BG->MaxCachedPerBatch =
           CacheT::getMaxCached(getSizeByClassId(SizeClassMap::BatchClassId));
@@ -552,9 +552,6 @@ private:
       TB->add(
           compactPtr(SizeClassMap::BatchClassId, reinterpret_cast<uptr>(BG)));
       --Size;
-      DCHECK_EQ(BG->PushedBlocks, 1U);
-      // `TB` is also the block of BatchClassId.
-      BG->PushedBlocks += 1;
       BG->Batches.push_front(TB);
     }
 
@@ -581,8 +578,6 @@ private:
       CurBatch->appendFromArray(&Array[I], AppendSize);
       I += AppendSize;
     }
-
-    BG->PushedBlocks += Size;
   }
   // Push the blocks to their batch group. The layout will be like,
   //
@@ -618,7 +613,6 @@ private:
 
       BG->CompactPtrGroupBase = CompactPtrGroupBase;
       BG->Batches.push_front(TB);
-      BG->PushedBlocks = 0;
       BG->BytesInBGAtLastCheckpoint = 0;
       BG->MaxCachedPerBatch = TransferBatchT::MaxNumCached;
 
@@ -646,8 +640,6 @@ private:
         CurBatch->appendFromArray(&Array[I], AppendSize);
         I += AppendSize;
       }
-
-      BG->PushedBlocks += Size;
     };
 
     Sci->FreeListInfo.PushedBlocks += Size;
@@ -940,7 +932,7 @@ private:
 
     uptr Integral;
     uptr Fractional;
-    computePercentage(BlockSize * InUseBlocks, InUsePages * PageSize, &Integral,
+    computePercentage(BlockSize * InUseBlocks, InUseBytes, &Integral,
                       &Fractional);
     Str->append("  %02zu (%6zu): inuse/total blocks: %6zu/%6zu inuse/total "
                 "pages: %6zu/%6zu inuse bytes: %6zuK util: %3zu.%02zu%%\n",
diff --git a/standalone/primary64.h b/standalone/primary64.h
index 8a583ba..a387647 100644
--- a/standalone/primary64.h
+++ b/standalone/primary64.h
@@ -61,12 +61,12 @@ public:
   typedef TransferBatch<ThisT> TransferBatchT;
   typedef BatchGroup<ThisT> BatchGroupT;
 
-  static_assert(sizeof(BatchGroupT) <= sizeof(TransferBatchT),
-                "BatchGroupT uses the same class size as TransferBatchT");
-
+  // BachClass is used to store internal metadata so it needs to be at least as
+  // large as the largest data structure.
   static uptr getSizeByClassId(uptr ClassId) {
     return (ClassId == SizeClassMap::BatchClassId)
-               ? roundUp(sizeof(TransferBatchT), 1U << CompactPtrScale)
+               ? roundUp(Max(sizeof(TransferBatchT), sizeof(BatchGroupT)),
+                         1U << CompactPtrScale)
                : SizeClassMap::getSizeByClassId(ClassId);
   }
 
@@ -160,7 +160,7 @@ public:
         ScopedLock ML(Region->MMLock);
         MemMapT MemMap = Region->MemMapInfo.MemMap;
         if (MemMap.isAllocated())
-          MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+          MemMap.unmap();
       }
       *Region = {};
     }
@@ -236,7 +236,7 @@ public:
     } else {
       while (true) {
         // When two threads compete for `Region->MMLock`, we only want one of
-        // them to call populateFreeListAndPopBatch(). To avoid both of them
+        // them to call populateFreeListAndPopBlocks(). To avoid both of them
         // doing that, always check the freelist before mapping new pages.
         ScopedLock ML(Region->MMLock);
         {
@@ -395,6 +395,18 @@ public:
     }
   }
 
+  void getMemoryGroupFragmentationInfo(ScopedString *Str) {
+    Str->append(
+        "Fragmentation Stats: SizeClassAllocator64: page size = %zu bytes\n",
+        getPageSizeCached());
+
+    for (uptr I = 1; I < NumClasses; I++) {
+      RegionInfo *Region = getRegionInfo(I);
+      ScopedLock L(Region->MMLock);
+      getMemoryGroupFragmentationInfoInRegion(Region, I, Str);
+    }
+  }
+
   bool setOption(Option O, sptr Value) {
     if (O == Option::ReleaseInterval) {
       const s32 Interval = Max(
@@ -678,9 +690,6 @@ private:
       // BatchClass hasn't enabled memory group. Use `0` to indicate there's no
       // memory group here.
       BG->CompactPtrGroupBase = 0;
-      // `BG` is also the block of BatchClassId. Note that this is different
-      // from `CreateGroup` in `pushBlocksImpl`
-      BG->PushedBlocks = 1;
       BG->BytesInBGAtLastCheckpoint = 0;
       BG->MaxCachedPerBatch =
           CacheT::getMaxCached(getSizeByClassId(SizeClassMap::BatchClassId));
@@ -705,9 +714,6 @@ private:
       TB->add(
           compactPtr(SizeClassMap::BatchClassId, reinterpret_cast<uptr>(BG)));
       --Size;
-      DCHECK_EQ(BG->PushedBlocks, 1U);
-      // `TB` is also the block of BatchClassId.
-      BG->PushedBlocks += 1;
       BG->Batches.push_front(TB);
     }
 
@@ -734,8 +740,6 @@ private:
       CurBatch->appendFromArray(&Array[I], AppendSize);
       I += AppendSize;
     }
-
-    BG->PushedBlocks += Size;
   }
 
   // Push the blocks to their batch group. The layout will be like,
@@ -770,7 +774,6 @@ private:
 
       BG->CompactPtrGroupBase = CompactPtrGroupBase;
       BG->Batches.push_front(TB);
-      BG->PushedBlocks = 0;
       BG->BytesInBGAtLastCheckpoint = 0;
       BG->MaxCachedPerBatch = TransferBatchT::MaxNumCached;
 
@@ -798,8 +801,6 @@ private:
         CurBatch->appendFromArray(&Array[I], AppendSize);
         I += AppendSize;
       }
-
-      BG->PushedBlocks += Size;
     };
 
     Region->FreeListInfo.PushedBlocks += Size;
@@ -872,7 +873,7 @@ private:
     while (true) {
       // We only expect one thread doing the freelist refillment and other
       // threads will be waiting for either the completion of the
-      // `populateFreeListAndPopBatch()` or `pushBlocks()` called by other
+      // `populateFreeListAndPopBlocks()` or `pushBlocks()` called by other
       // threads.
       bool PopulateFreeList = false;
       {
@@ -910,7 +911,7 @@ private:
       // At here, there are two preconditions to be met before waiting,
       //   1. The freelist is empty.
       //   2. Region->isPopulatingFreeList == true, i.e, someone is still doing
-      //   `populateFreeListAndPopBatch()`.
+      //   `populateFreeListAndPopBlocks()`.
       //
       // Note that it has the chance that freelist is empty but
       // Region->isPopulatingFreeList == false because all the new populated
@@ -926,8 +927,8 @@ private:
 
       // Now the freelist is empty and someone's doing the refillment. We will
       // wait until anyone refills the freelist or someone finishes doing
-      // `populateFreeListAndPopBatch()`. The refillment can be done by
-      // `populateFreeListAndPopBatch()`, `pushBlocks()`,
+      // `populateFreeListAndPopBlocks()`. The refillment can be done by
+      // `populateFreeListAndPopBlocks()`, `pushBlocks()`,
       // `pushBatchClassBlocks()` and `mergeGroupsToReleaseBack()`.
       Region->FLLockCV.wait(Region->FLLock);
 
@@ -1107,8 +1108,8 @@ private:
 
     // Note that `PushedBlocks` and `PoppedBlocks` are supposed to only record
     // the requests from `PushBlocks` and `PopBatch` which are external
-    // interfaces. `populateFreeListAndPopBatch` is the internal interface so we
-    // should set the values back to avoid incorrectly setting the stats.
+    // interfaces. `populateFreeListAndPopBlocks` is the internal interface so
+    // we should set the values back to avoid incorrectly setting the stats.
     Region->FreeListInfo.PushedBlocks -= NumberOfBlocks;
 
     const uptr AllocatedUser = Size * NumberOfBlocks;
@@ -1185,7 +1186,7 @@ private:
 
     uptr Integral;
     uptr Fractional;
-    computePercentage(BlockSize * InUseBlocks, InUsePages * PageSize, &Integral,
+    computePercentage(BlockSize * InUseBlocks, InUseBytes, &Integral,
                       &Fractional);
     Str->append("  %02zu (%6zu): inuse/total blocks: %6zu/%6zu inuse/total "
                 "pages: %6zu/%6zu inuse bytes: %6zuK util: %3zu.%02zu%%\n",
@@ -1193,6 +1194,50 @@ private:
                 AllocatedPagesCount, InUseBytes >> 10, Integral, Fractional);
   }
 
+  void getMemoryGroupFragmentationInfoInRegion(RegionInfo *Region, uptr ClassId,
+                                               ScopedString *Str)
+      REQUIRES(Region->MMLock) EXCLUDES(Region->FLLock) {
+    const uptr BlockSize = getSizeByClassId(ClassId);
+    const uptr AllocatedUserEnd =
+        Region->MemMapInfo.AllocatedUser + Region->RegionBeg;
+
+    SinglyLinkedList<BatchGroupT> GroupsToRelease;
+    {
+      ScopedLock L(Region->FLLock);
+      GroupsToRelease = Region->FreeListInfo.BlockList;
+      Region->FreeListInfo.BlockList.clear();
+    }
+
+    constexpr uptr GroupSize = (1UL << GroupSizeLog);
+    constexpr uptr MaxNumGroups = RegionSize / GroupSize;
+
+    MemoryGroupFragmentationRecorder<GroupSize, MaxNumGroups> Recorder;
+    if (!GroupsToRelease.empty()) {
+      PageReleaseContext Context =
+          markFreeBlocks(Region, BlockSize, AllocatedUserEnd,
+                         getCompactPtrBaseByClassId(ClassId), GroupsToRelease);
+      auto SkipRegion = [](UNUSED uptr RegionIndex) { return false; };
+      releaseFreeMemoryToOS(Context, Recorder, SkipRegion);
+
+      mergeGroupsToReleaseBack(Region, GroupsToRelease);
+    }
+
+    Str->append("MemoryGroupFragmentationInfo in Region %zu (%zu)\n", ClassId,
+                BlockSize);
+
+    const uptr MaxNumGroupsInUse =
+        roundUp(Region->MemMapInfo.AllocatedUser, GroupSize) / GroupSize;
+    for (uptr I = 0; I < MaxNumGroupsInUse; ++I) {
+      uptr Integral;
+      uptr Fractional;
+      computePercentage(Recorder.NumPagesInOneGroup -
+                            Recorder.getNumFreePages(I),
+                        Recorder.NumPagesInOneGroup, &Integral, &Fractional);
+      Str->append("MemoryGroup #%zu (0x%zx): util: %3zu.%02zu%%\n", I,
+                  Region->RegionBeg + I * GroupSize, Integral, Fractional);
+    }
+  }
+
   NOINLINE uptr releaseToOSMaybe(RegionInfo *Region, uptr ClassId,
                                  ReleaseToOS ReleaseType = ReleaseToOS::Normal)
       REQUIRES(Region->MMLock) EXCLUDES(Region->FLLock) {
@@ -1633,7 +1678,6 @@ private:
       GroupsToRelease.pop_front();
 
       if (BG->CompactPtrGroupBase == Cur->CompactPtrGroupBase) {
-        BG->PushedBlocks += Cur->PushedBlocks;
         // We have updated `BatchGroup::BytesInBGAtLastCheckpoint` while
         // collecting the `GroupsToRelease`.
         BG->BytesInBGAtLastCheckpoint = Cur->BytesInBGAtLastCheckpoint;
diff --git a/standalone/release.h b/standalone/release.h
index b6f76a4..6353daf 100644
--- a/standalone/release.h
+++ b/standalone/release.h
@@ -88,13 +88,29 @@ public:
 
   void releasePageRangeToOS(uptr From, uptr To) {
     DCHECK_EQ((To - From) % getPageSizeCached(), 0U);
-    ReleasedPagesCount += (To - From) / getPageSizeCached();
+    ReleasedPagesCount += (To - From) >> getPageSizeLogCached();
   }
 
 private:
   uptr ReleasedPagesCount = 0;
 };
 
+template <uptr GroupSize, uptr NumGroups>
+class MemoryGroupFragmentationRecorder {
+public:
+  const uptr NumPagesInOneGroup = GroupSize / getPageSizeCached();
+
+  void releasePageRangeToOS(uptr From, uptr To) {
+    for (uptr I = From / getPageSizeCached(); I < To / getPageSizeCached(); ++I)
+      ++FreePagesCount[I / NumPagesInOneGroup];
+  }
+
+  uptr getNumFreePages(uptr GroupId) { return FreePagesCount[GroupId]; }
+
+private:
+  uptr FreePagesCount[NumGroups] = {};
+};
+
 // A buffer pool which holds a fixed number of static buffers of `uptr` elements
 // for fast buffer allocation. If the request size is greater than
 // `StaticBufferNumElements` or if all the static buffers are in use, it'll
@@ -158,7 +174,7 @@ public:
       DCHECK_EQ((Mask & (static_cast<uptr>(1) << Buf.BufferIndex)), 0U);
       Mask |= static_cast<uptr>(1) << Buf.BufferIndex;
     } else {
-      Buf.MemMap.unmap(Buf.MemMap.getBase(), Buf.MemMap.getCapacity());
+      Buf.MemMap.unmap();
     }
   }
 
@@ -348,7 +364,7 @@ private:
 template <class ReleaseRecorderT> class FreePagesRangeTracker {
 public:
   explicit FreePagesRangeTracker(ReleaseRecorderT &Recorder)
-      : Recorder(Recorder), PageSizeLog(getLog2(getPageSizeCached())) {}
+      : Recorder(Recorder) {}
 
   void processNextPage(bool Released) {
     if (Released) {
@@ -372,6 +388,7 @@ public:
 private:
   void closeOpenedRange() {
     if (InRange) {
+      const uptr PageSizeLog = getPageSizeLogCached();
       Recorder.releasePageRangeToOS((CurrentRangeStatePage << PageSizeLog),
                                     (CurrentPage << PageSizeLog));
       InRange = false;
@@ -379,7 +396,6 @@ private:
   }
 
   ReleaseRecorderT &Recorder;
-  const uptr PageSizeLog;
   bool InRange = false;
   uptr CurrentPage = 0;
   uptr CurrentRangeStatePage = 0;
@@ -389,7 +405,7 @@ struct PageReleaseContext {
   PageReleaseContext(uptr BlockSize, uptr NumberOfRegions, uptr ReleaseSize,
                      uptr ReleaseOffset = 0)
       : BlockSize(BlockSize), NumberOfRegions(NumberOfRegions) {
-    PageSize = getPageSizeCached();
+    const uptr PageSize = getPageSizeCached();
     if (BlockSize <= PageSize) {
       if (PageSize % BlockSize == 0) {
         // Same number of chunks per page, no cross overs.
@@ -408,7 +424,7 @@ struct PageReleaseContext {
         SameBlockCountPerPage = false;
       }
     } else {
-      if (BlockSize % PageSize == 0) {
+      if ((BlockSize & (PageSize - 1)) == 0) {
         // One chunk covers multiple pages, no cross overs.
         FullPagesBlockCountMax = 1;
         SameBlockCountPerPage = true;
@@ -427,8 +443,8 @@ struct PageReleaseContext {
     if (NumberOfRegions != 1)
       DCHECK_EQ(ReleaseOffset, 0U);
 
-    PagesCount = roundUp(ReleaseSize, PageSize) / PageSize;
-    PageSizeLog = getLog2(PageSize);
+    const uptr PageSizeLog = getPageSizeLogCached();
+    PagesCount = roundUp(ReleaseSize, PageSize) >> PageSizeLog;
     ReleasePageOffset = ReleaseOffset >> PageSizeLog;
   }
 
@@ -451,6 +467,7 @@ struct PageReleaseContext {
   // RegionSize, it's not necessary to be aligned with page size.
   bool markRangeAsAllCounted(uptr From, uptr To, uptr Base,
                              const uptr RegionIndex, const uptr RegionSize) {
+    const uptr PageSize = getPageSizeCached();
     DCHECK_LT(From, To);
     DCHECK_LE(To, Base + RegionSize);
     DCHECK_EQ(From % PageSize, 0U);
@@ -544,6 +561,7 @@ struct PageReleaseContext {
     if (!ensurePageMapAllocated())
       return false;
 
+    const uptr PageSize = getPageSizeCached();
     if (MayContainLastBlockInRegion) {
       const uptr LastBlockInRegion =
           ((RegionSize / BlockSize) - 1U) * BlockSize;
@@ -605,17 +623,19 @@ struct PageReleaseContext {
     return true;
   }
 
-  uptr getPageIndex(uptr P) { return (P >> PageSizeLog) - ReleasePageOffset; }
-  uptr getReleaseOffset() { return ReleasePageOffset << PageSizeLog; }
+  uptr getPageIndex(uptr P) {
+    return (P >> getPageSizeLogCached()) - ReleasePageOffset;
+  }
+  uptr getReleaseOffset() {
+    return ReleasePageOffset << getPageSizeLogCached();
+  }
 
   uptr BlockSize;
   uptr NumberOfRegions;
   // For partial region marking, some pages in front are not needed to be
   // counted.
   uptr ReleasePageOffset;
-  uptr PageSize;
   uptr PagesCount;
-  uptr PageSizeLog;
   uptr FullPagesBlockCountMax;
   bool SameBlockCountPerPage;
   RegionPageMap PageMap;
@@ -628,7 +648,7 @@ template <class ReleaseRecorderT, typename SkipRegionT>
 NOINLINE void
 releaseFreeMemoryToOS(PageReleaseContext &Context,
                       ReleaseRecorderT &Recorder, SkipRegionT SkipRegion) {
-  const uptr PageSize = Context.PageSize;
+  const uptr PageSize = getPageSizeCached();
   const uptr BlockSize = Context.BlockSize;
   const uptr PagesCount = Context.PagesCount;
   const uptr NumberOfRegions = Context.NumberOfRegions;
@@ -671,7 +691,7 @@ releaseFreeMemoryToOS(PageReleaseContext &Context,
       uptr PrevPageBoundary = 0;
       uptr CurrentBoundary = 0;
       if (ReleasePageOffset > 0) {
-        PrevPageBoundary = ReleasePageOffset * PageSize;
+        PrevPageBoundary = ReleasePageOffset << getPageSizeLogCached();
         CurrentBoundary = roundUpSlow(PrevPageBoundary, BlockSize);
       }
       for (uptr J = 0; J < PagesCount; J++) {
diff --git a/standalone/secondary.h b/standalone/secondary.h
index d8c9f5b..2fae29e 100644
--- a/standalone/secondary.h
+++ b/standalone/secondary.h
@@ -19,6 +19,7 @@
 #include "stats.h"
 #include "string_utils.h"
 #include "thread_annotations.h"
+#include "vector.h"
 
 namespace scudo {
 
@@ -64,21 +65,32 @@ template <typename Config> static Header *getHeader(const void *Ptr) {
 
 } // namespace LargeBlock
 
-static inline void unmap(LargeBlock::Header *H) {
-  // Note that the `H->MapMap` is stored on the pages managed by itself. Take
-  // over the ownership before unmap() so that any operation along with unmap()
-  // won't touch inaccessible pages.
-  MemMapT MemMap = H->MemMap;
-  MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
-}
+static inline void unmap(MemMapT &MemMap) { MemMap.unmap(); }
 
 namespace {
+
 struct CachedBlock {
+  static constexpr u16 CacheIndexMax = UINT16_MAX;
+  static constexpr u16 InvalidEntry = CacheIndexMax;
+  // We allow a certain amount of fragmentation and part of the fragmented bytes
+  // will be released by `releaseAndZeroPagesToOS()`. This increases the chance
+  // of cache hit rate and reduces the overhead to the RSS at the same time. See
+  // more details in the `MapAllocatorCache::retrieve()` section.
+  //
+  // We arrived at this default value after noticing that mapping in larger
+  // memory regions performs better than releasing memory and forcing a cache
+  // hit. According to the data, it suggests that beyond 4 pages, the release
+  // execution time is longer than the map execution time. In this way,
+  // the default is dependent on the platform.
+  static constexpr uptr MaxReleasedCachePages = 4U;
+
   uptr CommitBase = 0;
   uptr CommitSize = 0;
   uptr BlockBegin = 0;
   MemMapT MemMap = {};
   u64 Time = 0;
+  u16 Next = 0;
+  u16 Prev = 0;
 
   bool isValid() { return CommitBase != 0; }
 
@@ -89,12 +101,19 @@ struct CachedBlock {
 template <typename Config> class MapAllocatorNoCache {
 public:
   void init(UNUSED s32 ReleaseToOsInterval) {}
-  bool retrieve(UNUSED Options Options, UNUSED uptr Size, UNUSED uptr Alignment,
-                UNUSED uptr HeadersSize, UNUSED LargeBlock::Header **H,
-                UNUSED bool *Zeroed) {
-    return false;
+  CachedBlock retrieve(UNUSED uptr MaxAllowedFragmentedBytes, UNUSED uptr Size,
+                       UNUSED uptr Alignment, UNUSED uptr HeadersSize,
+                       UNUSED uptr &EntryHeaderPos) {
+    return {};
   }
-  void store(UNUSED Options Options, LargeBlock::Header *H) { unmap(H); }
+  void store(UNUSED Options Options, UNUSED uptr CommitBase,
+             UNUSED uptr CommitSize, UNUSED uptr BlockBegin,
+             UNUSED MemMapT MemMap) {
+    // This should never be called since canCache always returns false.
+    UNREACHABLE(
+        "It is not valid to call store on MapAllocatorNoCache objects.");
+  }
+
   bool canCache(UNUSED uptr Size) { return false; }
   void disable() {}
   void enable() {}
@@ -114,7 +133,7 @@ public:
   }
 };
 
-static const uptr MaxUnusedCachePages = 4U;
+static const uptr MaxUnreleasedCachePages = 4U;
 
 template <typename Config>
 bool mapSecondary(const Options &Options, uptr CommitBase, uptr CommitSize,
@@ -144,9 +163,11 @@ bool mapSecondary(const Options &Options, uptr CommitBase, uptr CommitSize,
     }
   }
 
-  const uptr MaxUnusedCacheBytes = MaxUnusedCachePages * PageSize;
-  if (useMemoryTagging<Config>(Options) && CommitSize > MaxUnusedCacheBytes) {
-    const uptr UntaggedPos = Max(AllocPos, CommitBase + MaxUnusedCacheBytes);
+  const uptr MaxUnreleasedCacheBytes = MaxUnreleasedCachePages * PageSize;
+  if (useMemoryTagging<Config>(Options) &&
+      CommitSize > MaxUnreleasedCacheBytes) {
+    const uptr UntaggedPos =
+        Max(AllocPos, CommitBase + MaxUnreleasedCacheBytes);
     return MemMap.remap(CommitBase, UntaggedPos - CommitBase, "scudo:secondary",
                         MAP_MEMTAG | Flags) &&
            MemMap.remap(UntaggedPos, CommitBase + CommitSize - UntaggedPos,
@@ -171,7 +192,11 @@ public:
   T &operator[](uptr UNUSED Idx) { UNREACHABLE("Unsupported!"); }
 };
 
-template <typename Config> class MapAllocatorCache {
+// The default unmap callback is simply scudo::unmap.
+// In testing, a different unmap callback is used to
+// record information about unmaps in the cache
+template <typename Config, void (*unmapCallBack)(MemMapT &) = unmap>
+class MapAllocatorCache {
 public:
   void getStats(ScopedString *Str) {
     ScopedLock L(Mutex);
@@ -188,10 +213,11 @@ public:
     Str->append("Stats: CacheRetrievalStats: SuccessRate: %u/%u "
                 "(%zu.%02zu%%)\n",
                 SuccessfulRetrieves, CallsToRetrieve, Integral, Fractional);
-    for (CachedBlock Entry : Entries) {
-      if (!Entry.isValid())
-        continue;
-      Str->append("StartBlockAddress: 0x%zx, EndBlockAddress: 0x%zx, "
+    Str->append("Cache Entry Info (Most Recent -> Least Recent):\n");
+
+    for (u32 I = LRUHead; I != CachedBlock::InvalidEntry; I = Entries[I].Next) {
+      CachedBlock &Entry = Entries[I];
+      Str->append("  StartBlockAddress: 0x%zx, EndBlockAddress: 0x%zx, "
                   "BlockSize: %zu %s\n",
                   Entry.CommitBase, Entry.CommitBase + Entry.CommitSize,
                   Entry.CommitSize, Entry.Time == 0 ? "[R]" : "");
@@ -202,6 +228,10 @@ public:
   static_assert(Config::getDefaultMaxEntriesCount() <=
                     Config::getEntriesArraySize(),
                 "");
+  // Ensure the cache entry array size fits in the LRU list Next and Prev
+  // index fields
+  static_assert(Config::getEntriesArraySize() <= CachedBlock::CacheIndexMax,
+                "Cache entry array is too large to be indexed.");
 
   void init(s32 ReleaseToOsInterval) NO_THREAD_SAFETY_ANALYSIS {
     DCHECK_EQ(EntriesCount, 0U);
@@ -213,23 +243,34 @@ public:
     if (Config::getDefaultReleaseToOsIntervalMs() != INT32_MIN)
       ReleaseToOsInterval = Config::getDefaultReleaseToOsIntervalMs();
     setOption(Option::ReleaseInterval, static_cast<sptr>(ReleaseToOsInterval));
+
+    // The cache is initially empty
+    LRUHead = CachedBlock::InvalidEntry;
+    LRUTail = CachedBlock::InvalidEntry;
+
+    // Available entries will be retrieved starting from the beginning of the
+    // Entries array
+    AvailableHead = 0;
+    for (u32 I = 0; I < Config::getEntriesArraySize() - 1; I++)
+      Entries[I].Next = static_cast<u16>(I + 1);
+
+    Entries[Config::getEntriesArraySize() - 1].Next = CachedBlock::InvalidEntry;
   }
 
-  void store(const Options &Options, LargeBlock::Header *H) EXCLUDES(Mutex) {
-    if (!canCache(H->CommitSize))
-      return unmap(H);
+  void store(const Options &Options, uptr CommitBase, uptr CommitSize,
+             uptr BlockBegin, MemMapT MemMap) EXCLUDES(Mutex) {
+    DCHECK(canCache(CommitSize));
 
-    bool EntryCached = false;
-    bool EmptyCache = false;
     const s32 Interval = atomic_load_relaxed(&ReleaseToOsIntervalMs);
-    const u64 Time = getMonotonicTimeFast();
-    const u32 MaxCount = atomic_load_relaxed(&MaxEntriesCount);
+    u64 Time;
     CachedBlock Entry;
-    Entry.CommitBase = H->CommitBase;
-    Entry.CommitSize = H->CommitSize;
-    Entry.BlockBegin = reinterpret_cast<uptr>(H + 1);
-    Entry.MemMap = H->MemMap;
-    Entry.Time = Time;
+
+    Entry.CommitBase = CommitBase;
+    Entry.CommitSize = CommitSize;
+    Entry.BlockBegin = BlockBegin;
+    Entry.MemMap = MemMap;
+    Entry.Time = UINT64_MAX;
+
     if (useMemoryTagging<Config>(Options)) {
       if (Interval == 0 && !SCUDO_FUCHSIA) {
         // Release the memory and make it inaccessible at the same time by
@@ -243,17 +284,32 @@ public:
         Entry.MemMap.setMemoryPermission(Entry.CommitBase, Entry.CommitSize,
                                          MAP_NOACCESS);
       }
-    } else if (Interval == 0) {
-      Entry.MemMap.releaseAndZeroPagesToOS(Entry.CommitBase, Entry.CommitSize);
-      Entry.Time = 0;
     }
+
+    // Usually only one entry will be evicted from the cache.
+    // Only in the rare event that the cache shrinks in real-time
+    // due to a decrease in the configurable value MaxEntriesCount
+    // will more than one cache entry be evicted.
+    // The vector is used to save the MemMaps of evicted entries so
+    // that the unmap call can be performed outside the lock
+    Vector<MemMapT, 1U> EvictionMemMaps;
+
     do {
       ScopedLock L(Mutex);
+
+      // Time must be computed under the lock to ensure
+      // that the LRU cache remains sorted with respect to
+      // time in a multithreaded environment
+      Time = getMonotonicTimeFast();
+      if (Entry.Time != 0)
+        Entry.Time = Time;
+
       if (useMemoryTagging<Config>(Options) && QuarantinePos == -1U) {
         // If we get here then memory tagging was disabled in between when we
         // read Options and when we locked Mutex. We can't insert our entry into
         // the quarantine or the cache because the permissions would be wrong so
         // just unmap it.
+        unmapCallBack(Entry.MemMap);
         break;
       }
       if (Config::getQuarantineSize() && useMemoryTagging<Config>(Options)) {
@@ -269,112 +325,138 @@ public:
           OldestTime = Entry.Time;
         Entry = PrevEntry;
       }
-      if (EntriesCount >= MaxCount) {
-        if (IsFullEvents++ == 4U)
-          EmptyCache = true;
-      } else {
-        for (u32 I = 0; I < MaxCount; I++) {
-          if (Entries[I].isValid())
-            continue;
-          if (I != 0)
-            Entries[I] = Entries[0];
-          Entries[0] = Entry;
-          EntriesCount++;
-          if (OldestTime == 0)
-            OldestTime = Entry.Time;
-          EntryCached = true;
-          break;
-        }
+
+      // All excess entries are evicted from the cache
+      while (needToEvict()) {
+        // Save MemMaps of evicted entries to perform unmap outside of lock
+        EvictionMemMaps.push_back(Entries[LRUTail].MemMap);
+        remove(LRUTail);
       }
+
+      insert(Entry);
+
+      if (OldestTime == 0)
+        OldestTime = Entry.Time;
     } while (0);
-    if (EmptyCache)
-      empty();
-    else if (Interval >= 0)
+
+    for (MemMapT &EvictMemMap : EvictionMemMaps)
+      unmapCallBack(EvictMemMap);
+
+    if (Interval >= 0) {
+      // TODO: Add ReleaseToOS logic to LRU algorithm
       releaseOlderThan(Time - static_cast<u64>(Interval) * 1000000);
-    if (!EntryCached)
-      Entry.MemMap.unmap(Entry.MemMap.getBase(), Entry.MemMap.getCapacity());
+    }
   }
 
-  bool retrieve(Options Options, uptr Size, uptr Alignment, uptr HeadersSize,
-                LargeBlock::Header **H, bool *Zeroed) EXCLUDES(Mutex) {
+  CachedBlock retrieve(uptr MaxAllowedFragmentedPages, uptr Size,
+                       uptr Alignment, uptr HeadersSize, uptr &EntryHeaderPos)
+      EXCLUDES(Mutex) {
     const uptr PageSize = getPageSizeCached();
-    const u32 MaxCount = atomic_load_relaxed(&MaxEntriesCount);
     // 10% of the requested size proved to be the optimal choice for
     // retrieving cached blocks after testing several options.
     constexpr u32 FragmentedBytesDivisor = 10;
-    bool Found = false;
     CachedBlock Entry;
-    uptr EntryHeaderPos = 0;
+    EntryHeaderPos = 0;
     {
       ScopedLock L(Mutex);
       CallsToRetrieve++;
       if (EntriesCount == 0)
-        return false;
-      u32 OptimalFitIndex = 0;
+        return {};
+      u16 RetrievedIndex = CachedBlock::InvalidEntry;
       uptr MinDiff = UINTPTR_MAX;
-      for (u32 I = 0; I < MaxCount; I++) {
-        if (!Entries[I].isValid())
-          continue;
+
+      //  Since allocation sizes don't always match cached memory chunk sizes
+      //  we allow some memory to be unused (called fragmented bytes). The
+      //  amount of unused bytes is exactly EntryHeaderPos - CommitBase.
+      //
+      //        CommitBase                CommitBase + CommitSize
+      //          V                              V
+      //      +---+------------+-----------------+---+
+      //      |   |            |                 |   |
+      //      +---+------------+-----------------+---+
+      //      ^                ^                     ^
+      //    Guard         EntryHeaderPos          Guard-page-end
+      //    page-begin
+      //
+      //  [EntryHeaderPos, CommitBase + CommitSize) contains the user data as
+      //  well as the header metadata. If EntryHeaderPos - CommitBase exceeds
+      //  MaxAllowedFragmentedPages * PageSize, the cached memory chunk is
+      //  not considered valid for retrieval.
+      for (u16 I = LRUHead; I != CachedBlock::InvalidEntry;
+           I = Entries[I].Next) {
         const uptr CommitBase = Entries[I].CommitBase;
         const uptr CommitSize = Entries[I].CommitSize;
         const uptr AllocPos =
             roundDown(CommitBase + CommitSize - Size, Alignment);
         const uptr HeaderPos = AllocPos - HeadersSize;
+        const uptr MaxAllowedFragmentedBytes =
+            MaxAllowedFragmentedPages * PageSize;
         if (HeaderPos > CommitBase + CommitSize)
           continue;
+        // TODO: Remove AllocPos > CommitBase + MaxAllowedFragmentedBytes
+        // and replace with Diff > MaxAllowedFragmentedBytes
         if (HeaderPos < CommitBase ||
-            AllocPos > CommitBase + PageSize * MaxUnusedCachePages) {
+            AllocPos > CommitBase + MaxAllowedFragmentedBytes) {
           continue;
         }
-        Found = true;
-        const uptr Diff = HeaderPos - CommitBase;
-        // immediately use a cached block if it's size is close enough to the
-        // requested size.
-        const uptr MaxAllowedFragmentedBytes =
-            (CommitBase + CommitSize - HeaderPos) / FragmentedBytesDivisor;
-        if (Diff <= MaxAllowedFragmentedBytes) {
-          OptimalFitIndex = I;
-          EntryHeaderPos = HeaderPos;
-          break;
-        }
-        // keep track of the smallest cached block
+
+        const uptr Diff = roundDown(HeaderPos, PageSize) - CommitBase;
+
+        // Keep track of the smallest cached block
         // that is greater than (AllocSize + HeaderSize)
-        if (Diff > MinDiff)
+        if (Diff >= MinDiff)
           continue;
-        OptimalFitIndex = I;
+
         MinDiff = Diff;
+        RetrievedIndex = I;
         EntryHeaderPos = HeaderPos;
+
+        // Immediately use a cached block if its size is close enough to the
+        // requested size
+        const uptr OptimalFitThesholdBytes =
+            (CommitBase + CommitSize - HeaderPos) / FragmentedBytesDivisor;
+        if (Diff <= OptimalFitThesholdBytes)
+          break;
       }
-      if (Found) {
-        Entry = Entries[OptimalFitIndex];
-        Entries[OptimalFitIndex].invalidate();
-        EntriesCount--;
+      if (RetrievedIndex != CachedBlock::InvalidEntry) {
+        Entry = Entries[RetrievedIndex];
+        remove(RetrievedIndex);
         SuccessfulRetrieves++;
       }
     }
-    if (!Found)
-      return false;
 
-    *H = reinterpret_cast<LargeBlock::Header *>(
-        LargeBlock::addHeaderTag<Config>(EntryHeaderPos));
-    *Zeroed = Entry.Time == 0;
-    if (useMemoryTagging<Config>(Options))
-      Entry.MemMap.setMemoryPermission(Entry.CommitBase, Entry.CommitSize, 0);
-    uptr NewBlockBegin = reinterpret_cast<uptr>(*H + 1);
-    if (useMemoryTagging<Config>(Options)) {
-      if (*Zeroed) {
-        storeTags(LargeBlock::addHeaderTag<Config>(Entry.CommitBase),
-                  NewBlockBegin);
-      } else if (Entry.BlockBegin < NewBlockBegin) {
-        storeTags(Entry.BlockBegin, NewBlockBegin);
-      } else {
-        storeTags(untagPointer(NewBlockBegin), untagPointer(Entry.BlockBegin));
+    //  The difference between the retrieved memory chunk and the request
+    //  size is at most MaxAllowedFragmentedPages
+    //
+    // +- MaxAllowedFragmentedPages * PageSize -+
+    // +--------------------------+-------------+
+    // |                          |             |
+    // +--------------------------+-------------+
+    //  \ Bytes to be released   /        ^
+    //                                    |
+    //                           (may or may not be committed)
+    //
+    //   The maximum number of bytes released to the OS is capped by
+    //   MaxReleasedCachePages
+    //
+    //   TODO : Consider making MaxReleasedCachePages configurable since
+    //   the release to OS API can vary across systems.
+    if (Entry.Time != 0) {
+      const uptr FragmentedBytes =
+          roundDown(EntryHeaderPos, PageSize) - Entry.CommitBase;
+      const uptr MaxUnreleasedCacheBytes = MaxUnreleasedCachePages * PageSize;
+      if (FragmentedBytes > MaxUnreleasedCacheBytes) {
+        const uptr MaxReleasedCacheBytes =
+            CachedBlock::MaxReleasedCachePages * PageSize;
+        uptr BytesToRelease =
+            roundUp(Min<uptr>(MaxReleasedCacheBytes,
+                              FragmentedBytes - MaxUnreleasedCacheBytes),
+                    PageSize);
+        Entry.MemMap.releaseAndZeroPagesToOS(Entry.CommitBase, BytesToRelease);
       }
     }
-    (*H)->CommitBase = Entry.CommitBase;
-    (*H)->CommitSize = Entry.CommitSize;
-    (*H)->MemMap = Entry.MemMap;
-    return true;
+
+    return Entry;
   }
 
   bool canCache(uptr Size) {
@@ -391,10 +473,11 @@ public:
       return true;
     }
     if (O == Option::MaxCacheEntriesCount) {
-      const u32 MaxCount = static_cast<u32>(Value);
-      if (MaxCount > Config::getEntriesArraySize())
+      if (Value < 0)
         return false;
-      atomic_store_relaxed(&MaxEntriesCount, MaxCount);
+      atomic_store_relaxed(
+          &MaxEntriesCount,
+          Min<u32>(static_cast<u32>(Value), Config::getEntriesArraySize()));
       return true;
     }
     if (O == Option::MaxCacheEntrySize) {
@@ -412,16 +495,13 @@ public:
     for (u32 I = 0; I != Config::getQuarantineSize(); ++I) {
       if (Quarantine[I].isValid()) {
         MemMapT &MemMap = Quarantine[I].MemMap;
-        MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+        unmapCallBack(MemMap);
         Quarantine[I].invalidate();
       }
     }
-    const u32 MaxCount = atomic_load_relaxed(&MaxEntriesCount);
-    for (u32 I = 0; I < MaxCount; I++) {
-      if (Entries[I].isValid()) {
-        Entries[I].MemMap.setMemoryPermission(Entries[I].CommitBase,
-                                              Entries[I].CommitSize, 0);
-      }
+    for (u32 I = LRUHead; I != CachedBlock::InvalidEntry; I = Entries[I].Next) {
+      Entries[I].MemMap.setMemoryPermission(Entries[I].CommitBase,
+                                            Entries[I].CommitSize, 0);
     }
     QuarantinePos = -1U;
   }
@@ -433,6 +513,66 @@ public:
   void unmapTestOnly() { empty(); }
 
 private:
+  bool needToEvict() REQUIRES(Mutex) {
+    return (EntriesCount >= atomic_load_relaxed(&MaxEntriesCount));
+  }
+
+  void insert(const CachedBlock &Entry) REQUIRES(Mutex) {
+    DCHECK_LT(EntriesCount, atomic_load_relaxed(&MaxEntriesCount));
+
+    // Cache should be populated with valid entries when not empty
+    DCHECK_NE(AvailableHead, CachedBlock::InvalidEntry);
+
+    u32 FreeIndex = AvailableHead;
+    AvailableHead = Entries[AvailableHead].Next;
+
+    if (EntriesCount == 0) {
+      LRUTail = static_cast<u16>(FreeIndex);
+    } else {
+      // Check list order
+      if (EntriesCount > 1)
+        DCHECK_GE(Entries[LRUHead].Time, Entries[Entries[LRUHead].Next].Time);
+      Entries[LRUHead].Prev = static_cast<u16>(FreeIndex);
+    }
+
+    Entries[FreeIndex] = Entry;
+    Entries[FreeIndex].Next = LRUHead;
+    Entries[FreeIndex].Prev = CachedBlock::InvalidEntry;
+    LRUHead = static_cast<u16>(FreeIndex);
+    EntriesCount++;
+
+    // Availability stack should not have available entries when all entries
+    // are in use
+    if (EntriesCount == Config::getEntriesArraySize())
+      DCHECK_EQ(AvailableHead, CachedBlock::InvalidEntry);
+  }
+
+  void remove(uptr I) REQUIRES(Mutex) {
+    DCHECK(Entries[I].isValid());
+
+    Entries[I].invalidate();
+
+    if (I == LRUHead)
+      LRUHead = Entries[I].Next;
+    else
+      Entries[Entries[I].Prev].Next = Entries[I].Next;
+
+    if (I == LRUTail)
+      LRUTail = Entries[I].Prev;
+    else
+      Entries[Entries[I].Next].Prev = Entries[I].Prev;
+
+    Entries[I].Next = AvailableHead;
+    AvailableHead = static_cast<u16>(I);
+    EntriesCount--;
+
+    // Cache should not have valid entries when not empty
+    if (EntriesCount == 0) {
+      DCHECK_EQ(LRUHead, CachedBlock::InvalidEntry);
+      DCHECK_EQ(LRUTail, CachedBlock::InvalidEntry);
+    }
+  }
+
   void empty() {
     MemMapT MapInfo[Config::getEntriesArraySize()];
     uptr N = 0;
@@ -442,15 +582,14 @@ private:
         if (!Entries[I].isValid())
           continue;
         MapInfo[N] = Entries[I].MemMap;
-        Entries[I].invalidate();
+        remove(I);
         N++;
       }
       EntriesCount = 0;
-      IsFullEvents = 0;
     }
     for (uptr I = 0; I < N; I++) {
       MemMapT &MemMap = MapInfo[I];
-      MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+      unmapCallBack(MemMap);
     }
   }
 
@@ -483,7 +622,6 @@ private:
   atomic_u32 MaxEntriesCount = {};
   atomic_uptr MaxEntrySize = {};
   u64 OldestTime GUARDED_BY(Mutex) = 0;
-  u32 IsFullEvents GUARDED_BY(Mutex) = 0;
   atomic_s32 ReleaseToOsIntervalMs = {};
   u32 CallsToRetrieve GUARDED_BY(Mutex) = 0;
   u32 SuccessfulRetrieves GUARDED_BY(Mutex) = 0;
@@ -491,6 +629,13 @@ private:
   CachedBlock Entries[Config::getEntriesArraySize()] GUARDED_BY(Mutex) = {};
   NonZeroLengthArray<CachedBlock, Config::getQuarantineSize()>
       Quarantine GUARDED_BY(Mutex) = {};
+
+  // The LRUHead of the cache is the most recently used cache entry
+  u16 LRUHead GUARDED_BY(Mutex) = 0;
+  // The LRUTail of the cache is the least recently used cache entry
+  u16 LRUTail GUARDED_BY(Mutex) = 0;
+  // The AvailableHead is the top of the stack of available entries
+  u16 AvailableHead GUARDED_BY(Mutex) = 0;
 };
 
 template <typename Config> class MapAllocator {
@@ -511,6 +656,9 @@ public:
 
   void deallocate(const Options &Options, void *Ptr);
 
+  void *tryAllocateFromCache(const Options &Options, uptr Size, uptr Alignment,
+                             uptr *BlockEndPtr, FillContentsMode FillContents);
+
   static uptr getBlockEnd(void *Ptr) {
     auto *B = LargeBlock::getHeader<Config>(Ptr);
     return B->CommitBase + B->CommitSize;
@@ -571,6 +719,71 @@ private:
   LocalStats Stats GUARDED_BY(Mutex);
 };
 
+template <typename Config>
+void *
+MapAllocator<Config>::tryAllocateFromCache(const Options &Options, uptr Size,
+                                           uptr Alignment, uptr *BlockEndPtr,
+                                           FillContentsMode FillContents) {
+  CachedBlock Entry;
+  uptr EntryHeaderPos;
+  uptr MaxAllowedFragmentedPages = MaxUnreleasedCachePages;
+
+  if (LIKELY(!useMemoryTagging<Config>(Options))) {
+    MaxAllowedFragmentedPages += CachedBlock::MaxReleasedCachePages;
+  } else {
+    // TODO: Enable MaxReleasedCachePages may result in pages for an entry being
+    // partially released and it erases the tag of those pages as well. To
+    // support this feature for MTE, we need to tag those pages again.
+    DCHECK_EQ(MaxAllowedFragmentedPages, MaxUnreleasedCachePages);
+  }
+
+  Entry = Cache.retrieve(MaxAllowedFragmentedPages, Size, Alignment,
+                         getHeadersSize(), EntryHeaderPos);
+  if (!Entry.isValid())
+    return nullptr;
+
+  LargeBlock::Header *H = reinterpret_cast<LargeBlock::Header *>(
+      LargeBlock::addHeaderTag<Config>(EntryHeaderPos));
+  bool Zeroed = Entry.Time == 0;
+  if (useMemoryTagging<Config>(Options)) {
+    uptr NewBlockBegin = reinterpret_cast<uptr>(H + 1);
+    Entry.MemMap.setMemoryPermission(Entry.CommitBase, Entry.CommitSize, 0);
+    if (Zeroed) {
+      storeTags(LargeBlock::addHeaderTag<Config>(Entry.CommitBase),
+                NewBlockBegin);
+    } else if (Entry.BlockBegin < NewBlockBegin) {
+      storeTags(Entry.BlockBegin, NewBlockBegin);
+    } else {
+      storeTags(untagPointer(NewBlockBegin), untagPointer(Entry.BlockBegin));
+    }
+  }
+
+  H->CommitBase = Entry.CommitBase;
+  H->CommitSize = Entry.CommitSize;
+  H->MemMap = Entry.MemMap;
+
+  const uptr BlockEnd = H->CommitBase + H->CommitSize;
+  if (BlockEndPtr)
+    *BlockEndPtr = BlockEnd;
+  uptr HInt = reinterpret_cast<uptr>(H);
+  if (allocatorSupportsMemoryTagging<Config>())
+    HInt = untagPointer(HInt);
+  const uptr PtrInt = HInt + LargeBlock::getHeaderSize();
+  void *Ptr = reinterpret_cast<void *>(PtrInt);
+  if (FillContents && !Zeroed)
+    memset(Ptr, FillContents == ZeroFill ? 0 : PatternFillByte,
+           BlockEnd - PtrInt);
+  {
+    ScopedLock L(Mutex);
+    InUseBlocks.push_back(H);
+    AllocatedBytes += H->CommitSize;
+    FragmentedBytes += H->MemMap.getCapacity() - H->CommitSize;
+    NumberOfAllocs++;
+    Stats.add(StatAllocated, H->CommitSize);
+    Stats.add(StatMapped, H->MemMap.getCapacity());
+  }
+  return Ptr;
+}
 // As with the Primary, the size passed to this function includes any desired
 // alignment, so that the frontend can align the user allocation. The hint
 // parameter allows us to unmap spurious memory when dealing with larger
@@ -596,32 +809,10 @@ void *MapAllocator<Config>::allocate(const Options &Options, uptr Size,
   const uptr MinNeededSizeForCache = roundUp(Size + getHeadersSize(), PageSize);
 
   if (Alignment < PageSize && Cache.canCache(MinNeededSizeForCache)) {
-    LargeBlock::Header *H;
-    bool Zeroed;
-    if (Cache.retrieve(Options, Size, Alignment, getHeadersSize(), &H,
-                       &Zeroed)) {
-      const uptr BlockEnd = H->CommitBase + H->CommitSize;
-      if (BlockEndPtr)
-        *BlockEndPtr = BlockEnd;
-      uptr HInt = reinterpret_cast<uptr>(H);
-      if (allocatorSupportsMemoryTagging<Config>())
-        HInt = untagPointer(HInt);
-      const uptr PtrInt = HInt + LargeBlock::getHeaderSize();
-      void *Ptr = reinterpret_cast<void *>(PtrInt);
-      if (FillContents && !Zeroed)
-        memset(Ptr, FillContents == ZeroFill ? 0 : PatternFillByte,
-               BlockEnd - PtrInt);
-      {
-        ScopedLock L(Mutex);
-        InUseBlocks.push_back(H);
-        AllocatedBytes += H->CommitSize;
-        FragmentedBytes += H->MemMap.getCapacity() - H->CommitSize;
-        NumberOfAllocs++;
-        Stats.add(StatAllocated, H->CommitSize);
-        Stats.add(StatMapped, H->MemMap.getCapacity());
-      }
+    void *Ptr = tryAllocateFromCache(Options, Size, Alignment, BlockEndPtr,
+                                     FillContents);
+    if (Ptr != nullptr)
       return Ptr;
-    }
   }
 
   uptr RoundedSize =
@@ -646,9 +837,9 @@ void *MapAllocator<Config>::allocate(const Options &Options, uptr Size,
   // In the unlikely event of alignments larger than a page, adjust the amount
   // of memory we want to commit, and trim the extra memory.
   if (UNLIKELY(Alignment >= PageSize)) {
-    // For alignments greater than or equal to a page, the user pointer (eg: the
-    // pointer that is returned by the C or C++ allocation APIs) ends up on a
-    // page boundary , and our headers will live in the preceding page.
+    // For alignments greater than or equal to a page, the user pointer (eg:
+    // the pointer that is returned by the C or C++ allocation APIs) ends up
+    // on a page boundary , and our headers will live in the preceding page.
     CommitBase = roundUp(MapBase + PageSize + 1, Alignment) - PageSize;
     const uptr NewMapBase = CommitBase - PageSize;
     DCHECK_GE(NewMapBase, MapBase);
@@ -671,7 +862,7 @@ void *MapAllocator<Config>::allocate(const Options &Options, uptr Size,
   const uptr AllocPos = roundDown(CommitBase + CommitSize - Size, Alignment);
   if (!mapSecondary<Config>(Options, CommitBase, CommitSize, AllocPos, 0,
                             MemMap)) {
-    MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+    unmap(MemMap);
     return nullptr;
   }
   const uptr HeaderPos = AllocPos - getHeadersSize();
@@ -713,7 +904,17 @@ void MapAllocator<Config>::deallocate(const Options &Options, void *Ptr)
     Stats.sub(StatAllocated, CommitSize);
     Stats.sub(StatMapped, H->MemMap.getCapacity());
   }
-  Cache.store(Options, H);
+
+  if (Cache.canCache(H->CommitSize)) {
+    Cache.store(Options, H->CommitBase, H->CommitSize,
+                reinterpret_cast<uptr>(H + 1), H->MemMap);
+  } else {
+    // Note that the `H->MemMap` is stored on the pages managed by itself. Take
+    // over the ownership before unmap() so that any operation along with
+    // unmap() won't touch inaccessible pages.
+    MemMapT MemMap = H->MemMap;
+    unmap(MemMap);
+  }
 }
 
 template <typename Config>
diff --git a/standalone/string_utils.h b/standalone/string_utils.h
index 6e00b63..cf61e15 100644
--- a/standalone/string_utils.h
+++ b/standalone/string_utils.h
@@ -40,7 +40,7 @@ private:
   void appendString(int Width, int MaxChars, const char *S);
   void appendPointer(u64 ptr_value);
 
-  Vector<char> String;
+  Vector<char, 256> String;
 };
 
 void Printf(const char *Format, ...) FORMAT(1, 2);
diff --git a/standalone/tests/combined_test.cpp b/standalone/tests/combined_test.cpp
index 1a36155..16b19e8 100644
--- a/standalone/tests/combined_test.cpp
+++ b/standalone/tests/combined_test.cpp
@@ -447,19 +447,32 @@ SCUDO_TYPED_TEST(ScudoCombinedDeathTest, ReallocateSame) {
   // returns the same chunk. This requires that all the sizes we iterate on use
   // the same block size, but that should be the case for MaxSize - 64 with our
   // default class size maps.
-  constexpr scudo::uptr ReallocSize =
+  constexpr scudo::uptr InitialSize =
       TypeParam::Primary::SizeClassMap::MaxSize - 64;
-  void *P = Allocator->allocate(ReallocSize, Origin);
   const char Marker = 'A';
-  memset(P, Marker, ReallocSize);
+  Allocator->setFillContents(scudo::PatternOrZeroFill);
+
+  void *P = Allocator->allocate(InitialSize, Origin);
+  scudo::uptr CurrentSize = InitialSize;
   for (scudo::sptr Delta = -32; Delta < 32; Delta += 8) {
+    memset(P, Marker, CurrentSize);
     const scudo::uptr NewSize =
-        static_cast<scudo::uptr>(static_cast<scudo::sptr>(ReallocSize) + Delta);
+        static_cast<scudo::uptr>(static_cast<scudo::sptr>(InitialSize) + Delta);
     void *NewP = Allocator->reallocate(P, NewSize);
     EXPECT_EQ(NewP, P);
-    for (scudo::uptr I = 0; I < ReallocSize - 32; I++)
+
+    // Verify that existing contents have been preserved.
+    for (scudo::uptr I = 0; I < scudo::Min(CurrentSize, NewSize); I++)
       EXPECT_EQ((reinterpret_cast<char *>(NewP))[I], Marker);
+
+    // Verify that new bytes are set according to FillContentsMode.
+    for (scudo::uptr I = CurrentSize; I < NewSize; I++) {
+      unsigned char V = (reinterpret_cast<unsigned char *>(NewP))[I];
+      EXPECT_TRUE(V == scudo::PatternFillByte || V == 0);
+    }
+
     checkMemoryTaggingMaybe(Allocator, NewP, NewSize, 0);
+    CurrentSize = NewSize;
   }
   Allocator->deallocate(P, Origin);
 }
diff --git a/standalone/tests/common_test.cpp b/standalone/tests/common_test.cpp
index fff7c66..e6ddbb0 100644
--- a/standalone/tests/common_test.cpp
+++ b/standalone/tests/common_test.cpp
@@ -50,7 +50,7 @@ TEST(ScudoCommonTest, SKIP_ON_FUCHSIA(ResidentMemorySize)) {
   memset(P, 1, Size);
   EXPECT_GT(getResidentMemorySize(), OnStart + Size - Threshold);
 
-  MemMap.unmap(MemMap.getBase(), Size);
+  MemMap.unmap();
 }
 
 TEST(ScudoCommonTest, Zeros) {
@@ -69,7 +69,7 @@ TEST(ScudoCommonTest, Zeros) {
   MemMap.releasePagesToOS(MemMap.getBase(), Size);
   EXPECT_EQ(std::count(P, P + N, 0), N);
 
-  MemMap.unmap(MemMap.getBase(), Size);
+  MemMap.unmap();
 }
 
 } // namespace scudo
diff --git a/standalone/tests/list_test.cpp b/standalone/tests/list_test.cpp
index 140ca02..688cbbe 100644
--- a/standalone/tests/list_test.cpp
+++ b/standalone/tests/list_test.cpp
@@ -10,25 +10,22 @@
 
 #include "list.h"
 
-struct ListItem {
-  ListItem *Next;
-  ListItem *Prev;
-};
+#include <array>
 
-static ListItem Items[6];
-static ListItem *X = &Items[0];
-static ListItem *Y = &Items[1];
-static ListItem *Z = &Items[2];
-static ListItem *A = &Items[3];
-static ListItem *B = &Items[4];
-static ListItem *C = &Items[5];
+struct ListItemLinkedWithPtr {
+  ListItemLinkedWithPtr *Next;
+  ListItemLinkedWithPtr *Prev;
+};
 
-typedef scudo::SinglyLinkedList<ListItem> SLList;
-typedef scudo::DoublyLinkedList<ListItem> DLList;
+struct ListItemLinkedWithIndex {
+  scudo::uptr Next;
+  scudo::uptr Prev;
+  static constexpr scudo::uptr EndOfListVal = 1ULL << 30;
+};
 
-template <typename ListT>
-static void setList(ListT *L, ListItem *I1 = nullptr, ListItem *I2 = nullptr,
-                    ListItem *I3 = nullptr) {
+template <typename ListT, typename ListItemTy>
+static void setList(ListT *L, ListItemTy *I1 = nullptr,
+                    ListItemTy *I2 = nullptr, ListItemTy *I3 = nullptr) {
   L->clear();
   if (I1)
     L->push_back(I1);
@@ -38,10 +35,10 @@ static void setList(ListT *L, ListItem *I1 = nullptr, ListItem *I2 = nullptr,
     L->push_back(I3);
 }
 
-template <typename ListT>
-static void checkList(ListT *L, ListItem *I1, ListItem *I2 = nullptr,
-                      ListItem *I3 = nullptr, ListItem *I4 = nullptr,
-                      ListItem *I5 = nullptr, ListItem *I6 = nullptr) {
+template <typename ListT, typename ListItemTy>
+static void checkList(ListT *L, ListItemTy *I1, ListItemTy *I2 = nullptr,
+                      ListItemTy *I3 = nullptr, ListItemTy *I4 = nullptr,
+                      ListItemTy *I5 = nullptr, ListItemTy *I6 = nullptr) {
   if (I1) {
     EXPECT_EQ(L->front(), I1);
     L->pop_front();
@@ -69,9 +66,16 @@ static void checkList(ListT *L, ListItem *I1, ListItem *I2 = nullptr,
   EXPECT_TRUE(L->empty());
 }
 
-template <typename ListT> static void testListCommon(void) {
-  ListT L;
+template <template <typename> class ListTy, typename ListItemTy>
+static void testListCommon(void) {
+  ListItemTy Items[3];
+  ListItemTy *X = &Items[0];
+  ListItemTy *Y = &Items[1];
+  ListItemTy *Z = &Items[2];
+
+  ListTy<ListItemTy> L;
   L.clear();
+  L.init(Items, sizeof(Items));
 
   EXPECT_EQ(L.size(), 0U);
   L.push_back(X);
@@ -123,16 +127,40 @@ template <typename ListT> static void testListCommon(void) {
   L.pop_front();
   EXPECT_TRUE(L.empty());
   L.checkConsistency();
+
+  L.push_back(X);
+  L.push_back(Y);
+  L.push_back(Z);
+
+  // Verify the iterator
+  std::array<ListItemTy *, 3> visitOrder{X, Y, Z};
+  auto Iter = visitOrder.begin();
+  for (const auto &Item : L) {
+    EXPECT_EQ(&Item, *Iter);
+    ++Iter;
+  }
 }
 
 TEST(ScudoListTest, LinkedListCommon) {
-  testListCommon<SLList>();
-  testListCommon<DLList>();
+  testListCommon<scudo::SinglyLinkedList, ListItemLinkedWithPtr>();
+  testListCommon<scudo::SinglyLinkedList, ListItemLinkedWithIndex>();
+  testListCommon<scudo::DoublyLinkedList, ListItemLinkedWithPtr>();
+  testListCommon<scudo::DoublyLinkedList, ListItemLinkedWithIndex>();
 }
 
-TEST(ScudoListTest, SinglyLinkedList) {
-  SLList L;
+template <template <typename> class ListTy, typename ListItemTy>
+static void testSinglyLinkedList() {
+  ListItemTy Items[6];
+  ListItemTy *X = &Items[0];
+  ListItemTy *Y = &Items[1];
+  ListItemTy *Z = &Items[2];
+  ListItemTy *A = &Items[3];
+  ListItemTy *B = &Items[4];
+  ListItemTy *C = &Items[5];
+
+  ListTy<ListItemTy> L;
   L.clear();
+  L.init(Items, sizeof(Items));
 
   L.push_back(X);
   L.push_back(Y);
@@ -150,9 +178,11 @@ TEST(ScudoListTest, SinglyLinkedList) {
   L.pop_front();
   EXPECT_TRUE(L.empty());
 
-  SLList L1, L2;
+  ListTy<ListItemTy> L1, L2;
   L1.clear();
   L2.clear();
+  L1.init(Items, sizeof(Items));
+  L2.init(Items, sizeof(Items));
 
   L1.append_back(&L2);
   EXPECT_TRUE(L1.empty());
@@ -180,9 +210,21 @@ TEST(ScudoListTest, SinglyLinkedList) {
   EXPECT_EQ(L1.size(), 1U);
 }
 
-TEST(ScudoListTest, DoublyLinkedList) {
-  DLList L;
+TEST(ScudoListTest, SinglyLinkedList) {
+  testSinglyLinkedList<scudo::SinglyLinkedList, ListItemLinkedWithPtr>();
+  testSinglyLinkedList<scudo::SinglyLinkedList, ListItemLinkedWithIndex>();
+}
+
+template <template <typename> class ListTy, typename ListItemTy>
+static void testDoublyLinkedList() {
+  ListItemTy Items[3];
+  ListItemTy *X = &Items[0];
+  ListItemTy *Y = &Items[1];
+  ListItemTy *Z = &Items[2];
+
+  ListTy<ListItemTy> L;
   L.clear();
+  L.init(Items, sizeof(Items));
 
   L.push_back(X);
   L.push_back(Y);
@@ -214,3 +256,8 @@ TEST(ScudoListTest, DoublyLinkedList) {
   L.pop_front();
   EXPECT_TRUE(L.empty());
 }
+
+TEST(ScudoListTest, DoublyLinkedList) {
+  testDoublyLinkedList<scudo::DoublyLinkedList, ListItemLinkedWithPtr>();
+  testDoublyLinkedList<scudo::DoublyLinkedList, ListItemLinkedWithIndex>();
+}
diff --git a/standalone/tests/map_test.cpp b/standalone/tests/map_test.cpp
index 06a56f8..cc7d3ee 100644
--- a/standalone/tests/map_test.cpp
+++ b/standalone/tests/map_test.cpp
@@ -46,7 +46,7 @@ TEST(ScudoMapDeathTest, MapUnmap) {
           scudo::uptr P = MemMap.getBase();
           if (P == 0U)
             continue;
-          MemMap.unmap(MemMap.getBase(), Size);
+          MemMap.unmap();
           memset(reinterpret_cast<void *>(P), 0xbb, Size);
         }
       },
@@ -68,7 +68,7 @@ TEST(ScudoMapDeathTest, MapWithGuardUnmap) {
   ASSERT_TRUE(MemMap.remap(Q, Size, MappingName));
   memset(reinterpret_cast<void *>(Q), 0xaa, Size);
   EXPECT_DEATH(memset(reinterpret_cast<void *>(Q), 0xaa, Size + 1), "");
-  MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+  MemMap.unmap();
 }
 
 TEST(ScudoMapTest, MapGrowUnmap) {
@@ -87,5 +87,5 @@ TEST(ScudoMapTest, MapGrowUnmap) {
   Q += PageSize;
   ASSERT_TRUE(MemMap.remap(Q, PageSize, MappingName));
   memset(reinterpret_cast<void *>(Q), 0xbb, PageSize);
-  MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+  MemMap.unmap();
 }
diff --git a/standalone/tests/memtag_test.cpp b/standalone/tests/memtag_test.cpp
index 37a1885..1fae651 100644
--- a/standalone/tests/memtag_test.cpp
+++ b/standalone/tests/memtag_test.cpp
@@ -19,10 +19,10 @@ namespace scudo {
 
 TEST(MemtagBasicDeathTest, Unsupported) {
   if (archSupportsMemoryTagging())
-    GTEST_SKIP();
+    TEST_SKIP("Memory tagging is not supported");
   // Skip when running with HWASan.
   if (&__hwasan_init != 0)
-    GTEST_SKIP();
+    TEST_SKIP("Incompatible with HWASan");
 
   EXPECT_DEATH(archMemoryTagGranuleSize(), "not supported");
   EXPECT_DEATH(untagPointer((uptr)0), "not supported");
@@ -48,7 +48,7 @@ class MemtagTest : public Test {
 protected:
   void SetUp() override {
     if (!archSupportsMemoryTagging() || !systemDetectsMemoryTagFaultsTestOnly())
-      GTEST_SKIP() << "Memory tagging is not supported";
+      TEST_SKIP("Memory tagging is not supported");
 
     BufferSize = getPageSizeCached();
     ASSERT_FALSE(MemMap.isAllocated());
@@ -63,7 +63,7 @@ protected:
   void TearDown() override {
     if (Buffer) {
       ASSERT_TRUE(MemMap.isAllocated());
-      MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+      MemMap.unmap();
     }
   }
 
diff --git a/standalone/tests/primary_test.cpp b/standalone/tests/primary_test.cpp
index 1cf3bb5..0636fe7 100644
--- a/standalone/tests/primary_test.cpp
+++ b/standalone/tests/primary_test.cpp
@@ -386,6 +386,7 @@ SCUDO_TYPED_TEST(ScudoPrimaryTest, PrimaryThreaded) {
   scudo::ScopedString Str;
   Allocator->getStats(&Str);
   Allocator->getFragmentationInfo(&Str);
+  Allocator->getMemoryGroupFragmentationInfo(&Str);
   Str.output();
 }
 
diff --git a/standalone/tests/scudo_unit_test.h b/standalone/tests/scudo_unit_test.h
index 4283416..f8b658c 100644
--- a/standalone/tests/scudo_unit_test.h
+++ b/standalone/tests/scudo_unit_test.h
@@ -11,9 +11,14 @@
 #if SCUDO_FUCHSIA
 #include <zxtest/zxtest.h>
 using Test = ::zxtest::Test;
+#define TEST_SKIP(message) ZXTEST_SKIP(message)
 #else
 #include "gtest/gtest.h"
 using Test = ::testing::Test;
+#define TEST_SKIP(message)                                                     \
+  do {                                                                         \
+    GTEST_SKIP() << message;                                                   \
+  } while (0)
 #endif
 
 // If EXPECT_DEATH isn't defined, make it a no-op.
diff --git a/standalone/tests/secondary_test.cpp b/standalone/tests/secondary_test.cpp
index 8f0250e..3638f1c 100644
--- a/standalone/tests/secondary_test.cpp
+++ b/standalone/tests/secondary_test.cpp
@@ -190,29 +190,31 @@ TEST_F(MapAllocatorTest, SecondaryIterate) {
   Str.output();
 }
 
-TEST_F(MapAllocatorTest, SecondaryOptions) {
+TEST_F(MapAllocatorTest, SecondaryCacheOptions) {
+  if (!Allocator->canCache(0U))
+    TEST_SKIP("Secondary Cache disabled");
+
   // Attempt to set a maximum number of entries higher than the array size.
-  EXPECT_FALSE(
-      Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4096U));
-  // A negative number will be cast to a scudo::u32, and fail.
+  EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4096U));
+
+  // Attempt to set an invalid (negative) number of entries
   EXPECT_FALSE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, -1));
-  if (Allocator->canCache(0U)) {
-    // Various valid combinations.
-    EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4U));
-    EXPECT_TRUE(
-        Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 20));
-    EXPECT_TRUE(Allocator->canCache(1UL << 18));
-    EXPECT_TRUE(
-        Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 17));
-    EXPECT_FALSE(Allocator->canCache(1UL << 18));
-    EXPECT_TRUE(Allocator->canCache(1UL << 16));
-    EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 0U));
-    EXPECT_FALSE(Allocator->canCache(1UL << 16));
-    EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4U));
-    EXPECT_TRUE(
-        Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 20));
-    EXPECT_TRUE(Allocator->canCache(1UL << 16));
-  }
+
+  // Various valid combinations.
+  EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4U));
+  EXPECT_TRUE(
+      Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 20));
+  EXPECT_TRUE(Allocator->canCache(1UL << 18));
+  EXPECT_TRUE(
+      Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 17));
+  EXPECT_FALSE(Allocator->canCache(1UL << 18));
+  EXPECT_TRUE(Allocator->canCache(1UL << 16));
+  EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 0U));
+  EXPECT_FALSE(Allocator->canCache(1UL << 16));
+  EXPECT_TRUE(Allocator->setOption(scudo::Option::MaxCacheEntriesCount, 4U));
+  EXPECT_TRUE(
+      Allocator->setOption(scudo::Option::MaxCacheEntrySize, 1UL << 20));
+  EXPECT_TRUE(Allocator->canCache(1UL << 16));
 }
 
 struct MapAllocatorWithReleaseTest : public MapAllocatorTest {
@@ -263,3 +265,125 @@ TEST_F(MapAllocatorWithReleaseTest, SecondaryThreadsRace) {
   Allocator->getStats(&Str);
   Str.output();
 }
+
+struct MapAllocatorCacheTest : public Test {
+  static constexpr scudo::u32 UnmappedMarker = 0xDEADBEEF;
+
+  static void testUnmapCallback(scudo::MemMapT &MemMap) {
+    scudo::u32 *Ptr = reinterpret_cast<scudo::u32 *>(MemMap.getBase());
+    *Ptr = UnmappedMarker;
+  }
+
+  using SecondaryConfig = scudo::SecondaryConfig<TestConfig>;
+  using CacheConfig = SecondaryConfig::CacheConfig;
+  using CacheT = scudo::MapAllocatorCache<CacheConfig, testUnmapCallback>;
+
+  std::unique_ptr<CacheT> Cache = std::make_unique<CacheT>();
+
+  const scudo::uptr PageSize = scudo::getPageSizeCached();
+  // The current test allocation size is set to the maximum
+  // cache entry size
+  static constexpr scudo::uptr TestAllocSize =
+      CacheConfig::getDefaultMaxEntrySize();
+
+  scudo::Options Options = getOptionsForConfig<SecondaryConfig>();
+
+  void SetUp() override { Cache->init(/*ReleaseToOsInterval=*/-1); }
+
+  void TearDown() override { Cache->unmapTestOnly(); }
+
+  scudo::MemMapT allocate(scudo::uptr Size) {
+    scudo::uptr MapSize = scudo::roundUp(Size, PageSize);
+    scudo::ReservedMemoryT ReservedMemory;
+    CHECK(ReservedMemory.create(0U, MapSize, nullptr, MAP_ALLOWNOMEM));
+
+    scudo::MemMapT MemMap = ReservedMemory.dispatch(
+        ReservedMemory.getBase(), ReservedMemory.getCapacity());
+    MemMap.remap(MemMap.getBase(), MemMap.getCapacity(), "scudo:test",
+                 MAP_RESIZABLE | MAP_ALLOWNOMEM);
+    return MemMap;
+  }
+
+  void fillCacheWithSameSizeBlocks(std::vector<scudo::MemMapT> &MemMaps,
+                                   scudo::uptr NumEntries, scudo::uptr Size) {
+    for (scudo::uptr I = 0; I < NumEntries; I++) {
+      MemMaps.emplace_back(allocate(Size));
+      auto &MemMap = MemMaps[I];
+      Cache->store(Options, MemMap.getBase(), MemMap.getCapacity(),
+                   MemMap.getBase(), MemMap);
+    }
+  }
+};
+
+TEST_F(MapAllocatorCacheTest, CacheOrder) {
+  std::vector<scudo::MemMapT> MemMaps;
+  Cache->setOption(scudo::Option::MaxCacheEntriesCount,
+                   CacheConfig::getEntriesArraySize());
+
+  fillCacheWithSameSizeBlocks(MemMaps, CacheConfig::getEntriesArraySize(),
+                              TestAllocSize);
+
+  // Retrieval order should be the inverse of insertion order
+  for (scudo::uptr I = CacheConfig::getEntriesArraySize(); I > 0; I--) {
+    scudo::uptr EntryHeaderPos;
+    scudo::CachedBlock Entry =
+        Cache->retrieve(0, TestAllocSize, PageSize, 0, EntryHeaderPos);
+    EXPECT_EQ(Entry.MemMap.getBase(), MemMaps[I - 1].getBase());
+  }
+
+  // Clean up MemMaps
+  for (auto &MemMap : MemMaps)
+    MemMap.unmap();
+}
+
+TEST_F(MapAllocatorCacheTest, PartialChunkHeuristicRetrievalTest) {
+  const scudo::uptr FragmentedPages =
+      1 + scudo::CachedBlock::MaxReleasedCachePages;
+  scudo::uptr EntryHeaderPos;
+  scudo::CachedBlock Entry;
+  scudo::MemMapT MemMap = allocate(PageSize + FragmentedPages * PageSize);
+  Cache->store(Options, MemMap.getBase(), MemMap.getCapacity(),
+               MemMap.getBase(), MemMap);
+
+  // FragmentedPages > MaxAllowedFragmentedPages so PageSize
+  // cannot be retrieved from the cache
+  Entry = Cache->retrieve(/*MaxAllowedFragmentedPages=*/0, PageSize, PageSize,
+                          0, EntryHeaderPos);
+  EXPECT_FALSE(Entry.isValid());
+
+  // FragmentedPages == MaxAllowedFragmentedPages so PageSize
+  // can be retrieved from the cache
+  Entry =
+      Cache->retrieve(FragmentedPages, PageSize, PageSize, 0, EntryHeaderPos);
+  EXPECT_TRUE(Entry.isValid());
+
+  MemMap.unmap();
+}
+
+TEST_F(MapAllocatorCacheTest, MemoryLeakTest) {
+  std::vector<scudo::MemMapT> MemMaps;
+  // Fill the cache above MaxEntriesCount to force an eviction
+  // The first cache entry should be evicted (because it is the oldest)
+  // due to the maximum number of entries being reached
+  fillCacheWithSameSizeBlocks(
+      MemMaps, CacheConfig::getDefaultMaxEntriesCount() + 1, TestAllocSize);
+
+  std::vector<scudo::CachedBlock> RetrievedEntries;
+
+  // First MemMap should be evicted from cache because it was the first
+  // inserted into the cache
+  for (scudo::uptr I = CacheConfig::getDefaultMaxEntriesCount(); I > 0; I--) {
+    scudo::uptr EntryHeaderPos;
+    RetrievedEntries.push_back(
+        Cache->retrieve(0, TestAllocSize, PageSize, 0, EntryHeaderPos));
+    EXPECT_EQ(MemMaps[I].getBase(), RetrievedEntries.back().MemMap.getBase());
+  }
+
+  // Evicted entry should be marked due to unmap callback
+  EXPECT_EQ(*reinterpret_cast<scudo::u32 *>(MemMaps[0].getBase()),
+            UnmappedMarker);
+
+  // Clean up MemMaps
+  for (auto &MemMap : MemMaps)
+    MemMap.unmap();
+}
diff --git a/standalone/tests/strings_test.cpp b/standalone/tests/strings_test.cpp
index abb8180..f81e503 100644
--- a/standalone/tests/strings_test.cpp
+++ b/standalone/tests/strings_test.cpp
@@ -145,9 +145,9 @@ TEST(ScudoStringsTest, CapacityIncreaseFails) {
   scudo::MemMapT MemMap;
   if (MemMap.map(/*Addr=*/0U, scudo::getPageSizeCached(), "scudo:test",
                  MAP_ALLOWNOMEM)) {
-    MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+    MemMap.unmap();
     setrlimit(RLIMIT_AS, &Limit);
-    GTEST_SKIP() << "Limiting address space does not prevent mmap.";
+    TEST_SKIP("Limiting address space does not prevent mmap.");
   }
 
   // Test requires that the default length is at least 6 characters.
diff --git a/standalone/tests/timing_test.cpp b/standalone/tests/timing_test.cpp
index 09a6c31..a762aee 100644
--- a/standalone/tests/timing_test.cpp
+++ b/standalone/tests/timing_test.cpp
@@ -10,6 +10,7 @@
 
 #include "timing.h"
 
+#include <cstdlib>
 #include <string>
 
 class ScudoTimingTest : public Test {
@@ -33,41 +34,36 @@ public:
 
   void printAllTimersStats() { Manager.printAll(); }
 
+  void getAllTimersStats(scudo::ScopedString &Str) { Manager.getAll(Str); }
+
   scudo::TimingManager &getTimingManager() { return Manager; }
 
+  void testCallTimers() {
+    scudo::ScopedTimer Outer(getTimingManager(), "Level1");
+    {
+      scudo::ScopedTimer Inner1(getTimingManager(), Outer, "Level2");
+      { scudo::ScopedTimer Inner2(getTimingManager(), Inner1, "Level3"); }
+    }
+  }
+
 private:
   scudo::TimingManager Manager;
 };
 
-// Given that the output of statistics of timers are dumped through
-// `scudo::Printf` which is platform dependent, so we don't have a reliable way
-// to catch the output and verify the details. Now we only verify the number of
-// invocations on linux.
 TEST_F(ScudoTimingTest, SimpleTimer) {
-#if SCUDO_LINUX
-  testing::internal::LogToStderr();
-  testing::internal::CaptureStderr();
-#endif
-
   testIgnoredTimer();
   testChainedCalls();
-  printAllTimersStats();
+  scudo::ScopedString Str;
+  getAllTimersStats(Str);
 
-#if SCUDO_LINUX
-  std::string output = testing::internal::GetCapturedStderr();
-  EXPECT_TRUE(output.find("testIgnoredTimer (1)") == std::string::npos);
-  EXPECT_TRUE(output.find("testChainedCalls (1)") != std::string::npos);
-  EXPECT_TRUE(output.find("testFunc2 (1)") != std::string::npos);
-  EXPECT_TRUE(output.find("testFunc1 (1)") != std::string::npos);
-#endif
+  std::string Output(Str.data());
+  EXPECT_TRUE(Output.find("testIgnoredTimer (1)") == std::string::npos);
+  EXPECT_TRUE(Output.find("testChainedCalls (1)") != std::string::npos);
+  EXPECT_TRUE(Output.find("testFunc2 (1)") != std::string::npos);
+  EXPECT_TRUE(Output.find("testFunc1 (1)") != std::string::npos);
 }
 
 TEST_F(ScudoTimingTest, NestedTimer) {
-#if SCUDO_LINUX
-  testing::internal::LogToStderr();
-  testing::internal::CaptureStderr();
-#endif
-
   {
     scudo::ScopedTimer Outer(getTimingManager(), "Outer");
     {
@@ -75,12 +71,191 @@ TEST_F(ScudoTimingTest, NestedTimer) {
       { scudo::ScopedTimer Inner2(getTimingManager(), Inner1, "Inner2"); }
     }
   }
-  printAllTimersStats();
+  scudo::ScopedString Str;
+  getAllTimersStats(Str);
+
+  std::string Output(Str.data());
+  EXPECT_TRUE(Output.find("Outer (1)") != std::string::npos);
+  EXPECT_TRUE(Output.find("Inner1 (1)") != std::string::npos);
+  EXPECT_TRUE(Output.find("Inner2 (1)") != std::string::npos);
+}
+
+TEST_F(ScudoTimingTest, VerifyChainedTimerCalculations) {
+  {
+    scudo::ScopedTimer Outer(getTimingManager(), "Level1");
+    sleep(1);
+    {
+      scudo::ScopedTimer Inner1(getTimingManager(), Outer, "Level2");
+      sleep(2);
+      {
+        scudo::ScopedTimer Inner2(getTimingManager(), Inner1, "Level3");
+        sleep(3);
+      }
+    }
+  }
+  scudo::ScopedString Str;
+  getAllTimersStats(Str);
+  std::string Output(Str.data());
+
+  // Get the individual timer values for the average and maximum, then
+  // verify that the timer values are being calculated properly.
+  Output = Output.substr(Output.find('\n') + 1);
+  char *end;
+  unsigned long long Level1AvgNs = std::strtoull(Output.c_str(), &end, 10);
+  ASSERT_TRUE(end != nullptr);
+  unsigned long long Level1MaxNs = std::strtoull(&end[6], &end, 10);
+  ASSERT_TRUE(end != nullptr);
+  EXPECT_EQ(Level1AvgNs, Level1MaxNs);
+
+  Output = Output.substr(Output.find('\n') + 1);
+  unsigned long long Level2AvgNs = std::strtoull(Output.c_str(), &end, 10);
+  ASSERT_TRUE(end != nullptr);
+  unsigned long long Level2MaxNs = std::strtoull(&end[6], &end, 10);
+  ASSERT_TRUE(end != nullptr);
+  EXPECT_EQ(Level2AvgNs, Level2MaxNs);
+
+  Output = Output.substr(Output.find('\n') + 1);
+  unsigned long long Level3AvgNs = std::strtoull(Output.c_str(), &end, 10);
+  ASSERT_TRUE(end != nullptr);
+  unsigned long long Level3MaxNs = std::strtoull(&end[6], &end, 10);
+  ASSERT_TRUE(end != nullptr);
+  EXPECT_EQ(Level3AvgNs, Level3MaxNs);
+
+  EXPECT_GT(Level1AvgNs, Level2AvgNs);
+  EXPECT_GT(Level2AvgNs, Level3AvgNs);
+
+  // The time for the first timer needs to be at least six seconds.
+  EXPECT_GT(Level1AvgNs, 6000000000U);
+  // The time for the second timer needs to be at least five seconds.
+  EXPECT_GT(Level2AvgNs, 5000000000U);
+  // The time for the third timer needs to be at least three seconds.
+  EXPECT_GT(Level3AvgNs, 3000000000U);
+  // The time between the first and second timer needs to be at least one
+  // second.
+  EXPECT_GT(Level1AvgNs - Level2AvgNs, 1000000000U);
+  // The time between the second and third timer needs to be at least two
+  // second.
+  EXPECT_GT(Level2AvgNs - Level3AvgNs, 2000000000U);
+}
+
+TEST_F(ScudoTimingTest, VerifyMax) {
+  for (size_t i = 0; i < 3; i++) {
+    scudo::ScopedTimer Outer(getTimingManager(), "Level1");
+    sleep(1);
+  }
+  scudo::ScopedString Str;
+  getAllTimersStats(Str);
+  std::string Output(Str.data());
+
+  Output = Output.substr(Output.find('\n') + 1);
+  char *end;
+  unsigned long long AvgNs = std::strtoull(Output.c_str(), &end, 10);
+  ASSERT_TRUE(end != nullptr);
+  unsigned long long MaxNs = std::strtoull(&end[6], &end, 10);
+  ASSERT_TRUE(end != nullptr);
+
+  EXPECT_GE(MaxNs, AvgNs);
+}
+
+TEST_F(ScudoTimingTest, VerifyMultipleTimerCalls) {
+  for (size_t i = 0; i < 5; i++)
+    testCallTimers();
+
+  scudo::ScopedString Str;
+  getAllTimersStats(Str);
+  std::string Output(Str.data());
+  EXPECT_TRUE(Output.find("Level1 (5)") != std::string::npos);
+  EXPECT_TRUE(Output.find("Level2 (5)") != std::string::npos);
+  EXPECT_TRUE(Output.find("Level3 (5)") != std::string::npos);
+}
+
+TEST_F(ScudoTimingTest, VerifyHeader) {
+  { scudo::ScopedTimer Outer(getTimingManager(), "Timer"); }
+  scudo::ScopedString Str;
+  getAllTimersStats(Str);
+
+  std::string Output(Str.data());
+  std::string Header(Output.substr(0, Output.find('\n')));
+  EXPECT_EQ(Header, "-- Average Operation Time -- -- Maximum Operation Time -- "
+                    "-- Name (# of Calls) --");
+}
+
+TEST_F(ScudoTimingTest, VerifyTimerFormat) {
+  testCallTimers();
+  scudo::ScopedString Str;
+  getAllTimersStats(Str);
+  std::string Output(Str.data());
+
+  // Check the top level line, should look similar to:
+  //          11718.0(ns)                    11718(ns)            Level1 (1)
+  Output = Output.substr(Output.find('\n') + 1);
+
+  // Verify that the Average Operation Time is in the correct location.
+  EXPECT_EQ(".0(ns) ", Output.substr(14, 7));
+
+  // Verify that the Maximum Operation Time is in the correct location.
+  EXPECT_EQ("(ns) ", Output.substr(45, 5));
+
+  // Verify that the first timer name is in the correct location.
+  EXPECT_EQ("Level1 (1)\n", Output.substr(61, 11));
+
+  // Check a chained timer, should look similar to:
+  //           5331.0(ns)                     5331(ns)              Level2 (1)
+  Output = Output.substr(Output.find('\n') + 1);
+
+  // Verify that the Average Operation Time is in the correct location.
+  EXPECT_EQ(".0(ns) ", Output.substr(14, 7));
+
+  // Verify that the Maximum Operation Time is in the correct location.
+  EXPECT_EQ("(ns) ", Output.substr(45, 5));
+
+  // Verify that the first timer name is in the correct location.
+  EXPECT_EQ("  Level2 (1)\n", Output.substr(61, 13));
+
+  // Check a secondary chained timer, should look similar to:
+  //            814.0(ns)                      814(ns)                Level3 (1)
+  Output = Output.substr(Output.find('\n') + 1);
+
+  // Verify that the Average Operation Time is in the correct location.
+  EXPECT_EQ(".0(ns) ", Output.substr(14, 7));
+
+  // Verify that the Maximum Operation Time is in the correct location.
+  EXPECT_EQ("(ns) ", Output.substr(45, 5));
+
+  // Verify that the first timer name is in the correct location.
+  EXPECT_EQ("    Level3 (1)\n", Output.substr(61, 15));
+}
 
 #if SCUDO_LINUX
-  std::string output = testing::internal::GetCapturedStderr();
-  EXPECT_TRUE(output.find("Outer (1)") != std::string::npos);
-  EXPECT_TRUE(output.find("Inner1 (1)") != std::string::npos);
-  EXPECT_TRUE(output.find("Inner2 (1)") != std::string::npos);
+TEST_F(ScudoTimingTest, VerifyPrintMatchesGet) {
+  testing::internal::LogToStderr();
+  testing::internal::CaptureStderr();
+  testCallTimers();
+
+  { scudo::ScopedTimer Outer(getTimingManager(), "Timer"); }
+  printAllTimersStats();
+  std::string PrintOutput = testing::internal::GetCapturedStderr();
+  EXPECT_TRUE(PrintOutput.size() != 0);
+
+  scudo::ScopedString Str;
+  getAllTimersStats(Str);
+  std::string GetOutput(Str.data());
+  EXPECT_TRUE(GetOutput.size() != 0);
+
+  EXPECT_EQ(PrintOutput, GetOutput);
+}
 #endif
+
+#if SCUDO_LINUX
+TEST_F(ScudoTimingTest, VerifyReporting) {
+  testing::internal::LogToStderr();
+  testing::internal::CaptureStderr();
+  // Every 100 calls generates a report, but run a few extra to verify the
+  // report happened at call 100.
+  for (size_t i = 0; i < 110; i++)
+    scudo::ScopedTimer Outer(getTimingManager(), "VerifyReportTimer");
+
+  std::string Output = testing::internal::GetCapturedStderr();
+  EXPECT_TRUE(Output.find("VerifyReportTimer (100)") != std::string::npos);
 }
+#endif
diff --git a/standalone/tests/vector_test.cpp b/standalone/tests/vector_test.cpp
index b612676..cec8f46 100644
--- a/standalone/tests/vector_test.cpp
+++ b/standalone/tests/vector_test.cpp
@@ -11,7 +11,7 @@
 #include "vector.h"
 
 TEST(ScudoVectorTest, Basic) {
-  scudo::Vector<int> V;
+  scudo::Vector<int, 64U> V;
   EXPECT_EQ(V.size(), 0U);
   V.push_back(42);
   EXPECT_EQ(V.size(), 1U);
@@ -23,7 +23,7 @@ TEST(ScudoVectorTest, Basic) {
 }
 
 TEST(ScudoVectorTest, Stride) {
-  scudo::Vector<scudo::uptr> V;
+  scudo::Vector<scudo::uptr, 32U> V;
   for (scudo::uptr I = 0; I < 1000; I++) {
     V.push_back(I);
     EXPECT_EQ(V.size(), I + 1U);
@@ -34,7 +34,7 @@ TEST(ScudoVectorTest, Stride) {
 }
 
 TEST(ScudoVectorTest, ResizeReduction) {
-  scudo::Vector<int> V;
+  scudo::Vector<int, 64U> V;
   V.push_back(0);
   V.push_back(0);
   EXPECT_EQ(V.size(), 2U);
@@ -48,7 +48,7 @@ TEST(ScudoVectorTest, ResizeReduction) {
 
 // Verify that if the reallocate fails, nothing new is added.
 TEST(ScudoVectorTest, ReallocateFails) {
-  scudo::Vector<char> V;
+  scudo::Vector<char, 256U> V;
   scudo::uptr capacity = V.capacity();
 
   // Get the current address space size.
@@ -62,9 +62,9 @@ TEST(ScudoVectorTest, ReallocateFails) {
   scudo::MemMapT MemMap;
   if (MemMap.map(/*Addr=*/0U, scudo::getPageSizeCached(), "scudo:test",
                  MAP_ALLOWNOMEM)) {
-    MemMap.unmap(MemMap.getBase(), MemMap.getCapacity());
+    MemMap.unmap();
     setrlimit(RLIMIT_AS, &Limit);
-    GTEST_SKIP() << "Limiting address space does not prevent mmap.";
+    TEST_SKIP("Limiting address space does not prevent mmap.");
   }
 
   V.resize(capacity);
diff --git a/standalone/timing.h b/standalone/timing.h
index 84caa79..938b205 100644
--- a/standalone/timing.h
+++ b/standalone/timing.h
@@ -14,6 +14,10 @@
 #include "string_utils.h"
 #include "thread_annotations.h"
 
+#ifndef __STDC_FORMAT_MACROS
+// Ensure PRId64 macro is available
+#define __STDC_FORMAT_MACROS 1
+#endif
 #include <inttypes.h>
 #include <string.h>
 
@@ -104,6 +108,7 @@ public:
     strncpy(Timers[NumAllocatedTimers].Name, Name, MaxLenOfTimerName);
     TimerRecords[NumAllocatedTimers].AccumulatedTime = 0;
     TimerRecords[NumAllocatedTimers].Occurrence = 0;
+    TimerRecords[NumAllocatedTimers].MaxTime = 0;
     return Timer(*this, NumAllocatedTimers++);
   }
 
@@ -140,36 +145,47 @@ public:
 
     const u32 HandleId = T.HandleId;
     CHECK_LT(HandleId, MaxNumberOfTimers);
-    TimerRecords[HandleId].AccumulatedTime += T.getAccumulatedTime();
+    u64 AccTime = T.getAccumulatedTime();
+    TimerRecords[HandleId].AccumulatedTime += AccTime;
+    if (AccTime > TimerRecords[HandleId].MaxTime) {
+      TimerRecords[HandleId].MaxTime = AccTime;
+    }
     ++TimerRecords[HandleId].Occurrence;
     ++NumEventsReported;
-    if (NumEventsReported % PrintingInterval == 0)
-      printAllImpl();
+    if (NumEventsReported % PrintingInterval == 0) {
+      ScopedString Str;
+      getAllImpl(Str);
+      Str.output();
+    }
   }
 
   void printAll() EXCLUDES(Mutex) {
+    ScopedString Str;
+    getAll(Str);
+    Str.output();
+  }
+
+  void getAll(ScopedString &Str) EXCLUDES(Mutex) {
     ScopedLock L(Mutex);
-    printAllImpl();
+    getAllImpl(Str);
   }
 
 private:
-  void printAllImpl() REQUIRES(Mutex) {
-    static char NameHeader[] = "-- Name (# of Calls) --";
+  void getAllImpl(ScopedString &Str) REQUIRES(Mutex) {
     static char AvgHeader[] = "-- Average Operation Time --";
-    ScopedString Str;
-    Str.append("%-15s %-15s\n", AvgHeader, NameHeader);
+    static char MaxHeader[] = "-- Maximum Operation Time --";
+    static char NameHeader[] = "-- Name (# of Calls) --";
+    Str.append("%-15s %-15s %-15s\n", AvgHeader, MaxHeader, NameHeader);
 
     for (u32 I = 0; I < NumAllocatedTimers; ++I) {
       if (Timers[I].Nesting != MaxNumberOfTimers)
         continue;
-      printImpl(Str, I);
+      getImpl(Str, I);
     }
-
-    Str.output();
   }
 
-  void printImpl(ScopedString &Str, const u32 HandleId,
-                 const u32 ExtraIndent = 0) REQUIRES(Mutex) {
+  void getImpl(ScopedString &Str, const u32 HandleId, const u32 ExtraIndent = 0)
+      REQUIRES(Mutex) {
     const u64 AccumulatedTime = TimerRecords[HandleId].AccumulatedTime;
     const u64 Occurrence = TimerRecords[HandleId].Occurrence;
     const u64 Integral = Occurrence == 0 ? 0 : AccumulatedTime / Occurrence;
@@ -179,15 +195,20 @@ private:
         Occurrence == 0 ? 0
                         : ((AccumulatedTime % Occurrence) * 10) / Occurrence;
 
-    Str.append("%14" PRId64 ".%" PRId64 "(ns) %-11s", Integral, Fraction, " ");
+    // Average time.
+    Str.append("%14" PRId64 ".%" PRId64 "(ns) %-8s", Integral, Fraction, " ");
+
+    // Maximum time.
+    Str.append("%16" PRId64 "(ns) %-11s", TimerRecords[HandleId].MaxTime, " ");
 
+    // Name and num occurrences.
     for (u32 I = 0; I < ExtraIndent; ++I)
       Str.append("%s", "  ");
     Str.append("%s (%" PRId64 ")\n", Timers[HandleId].Name, Occurrence);
 
     for (u32 I = 0; I < NumAllocatedTimers; ++I)
       if (Timers[I].Nesting == HandleId)
-        printImpl(Str, I, ExtraIndent + 1);
+        getImpl(Str, I, ExtraIndent + 1);
   }
 
   // Instead of maintaining pages for timer registration, a static buffer is
@@ -199,6 +220,7 @@ private:
   struct Record {
     u64 AccumulatedTime = 0;
     u64 Occurrence = 0;
+    u64 MaxTime = 0;
   };
 
   struct TimerInfo {
diff --git a/standalone/vector.h b/standalone/vector.h
index ca10cc2..0d059ba 100644
--- a/standalone/vector.h
+++ b/standalone/vector.h
@@ -21,7 +21,7 @@ namespace scudo {
 // implementation supports only POD types.
 //
 // NOTE: This class is not meant to be used directly, use Vector<T> instead.
-template <typename T> class VectorNoCtor {
+template <typename T, size_t StaticNumEntries> class VectorNoCtor {
 public:
   T &operator[](uptr I) {
     DCHECK_LT(I, Size);
@@ -86,8 +86,7 @@ protected:
   }
   void destroy() {
     if (Data != &LocalData[0])
-      ExternalBuffer.unmap(ExternalBuffer.getBase(),
-                           ExternalBuffer.getCapacity());
+      ExternalBuffer.unmap();
   }
 
 private:
@@ -116,18 +115,21 @@ private:
   uptr CapacityBytes = 0;
   uptr Size = 0;
 
-  T LocalData[256 / sizeof(T)] = {};
+  T LocalData[StaticNumEntries] = {};
   MemMapT ExternalBuffer;
 };
 
-template <typename T> class Vector : public VectorNoCtor<T> {
+template <typename T, size_t StaticNumEntries>
+class Vector : public VectorNoCtor<T, StaticNumEntries> {
 public:
-  constexpr Vector() { VectorNoCtor<T>::init(); }
+  static_assert(StaticNumEntries > 0U,
+                "Vector must have a non-zero number of static entries.");
+  constexpr Vector() { VectorNoCtor<T, StaticNumEntries>::init(); }
   explicit Vector(uptr Count) {
-    VectorNoCtor<T>::init(Count);
+    VectorNoCtor<T, StaticNumEntries>::init(Count);
     this->resize(Count);
   }
-  ~Vector() { VectorNoCtor<T>::destroy(); }
+  ~Vector() { VectorNoCtor<T, StaticNumEntries>::destroy(); }
   // Disallow copies and moves.
   Vector(const Vector &) = delete;
   Vector &operator=(const Vector &) = delete;
```

