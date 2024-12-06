```diff
diff --git a/Android.bp b/Android.bp
index a2924bd..55e812a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -107,6 +107,7 @@ cc_library_static {
     ],
     srcs: [
         "gwp_asan/common.cpp",
+        "gwp_asan/crash_handler.cpp", // for __gwp_asan_error_is_mine in libc().
         "gwp_asan/guarded_pool_allocator.cpp",
         "gwp_asan/platform_specific/common_posix.cpp",
         "gwp_asan/platform_specific/guarded_pool_allocator_posix.cpp",
diff --git a/gwp_asan/definitions.h b/gwp_asan/definitions.h
index bec0290..c6785d4 100644
--- a/gwp_asan/definitions.h
+++ b/gwp_asan/definitions.h
@@ -12,7 +12,8 @@
 #define GWP_ASAN_TLS_INITIAL_EXEC                                              \
   __thread __attribute__((tls_model("initial-exec")))
 
-#define GWP_ASAN_UNLIKELY(X) __builtin_expect(!!(X), 0)
+#define GWP_ASAN_LIKELY(EXPR) __builtin_expect((bool)(EXPR), true)
+#define GWP_ASAN_UNLIKELY(EXPR) __builtin_expect((bool)(EXPR), false)
 #define GWP_ASAN_ALWAYS_INLINE inline __attribute__((always_inline))
 
 #define GWP_ASAN_WEAK __attribute__((weak))
diff --git a/gwp_asan/guarded_pool_allocator.cpp b/gwp_asan/guarded_pool_allocator.cpp
index 5f41e1e..a5f1ecd 100644
--- a/gwp_asan/guarded_pool_allocator.cpp
+++ b/gwp_asan/guarded_pool_allocator.cpp
@@ -52,12 +52,12 @@ void GuardedPoolAllocator::init(const options::Options &Opts) {
       Opts.MaxSimultaneousAllocations == 0)
     return;
 
-  Check(Opts.SampleRate >= 0, "GWP-ASan Error: SampleRate is < 0.");
-  Check(Opts.SampleRate < (1 << 30), "GWP-ASan Error: SampleRate is >= 2^30.");
-  Check(Opts.MaxSimultaneousAllocations >= 0,
+  check(Opts.SampleRate >= 0, "GWP-ASan Error: SampleRate is < 0.");
+  check(Opts.SampleRate < (1 << 30), "GWP-ASan Error: SampleRate is >= 2^30.");
+  check(Opts.MaxSimultaneousAllocations >= 0,
         "GWP-ASan Error: MaxSimultaneousAllocations is < 0.");
 
-  Check(SingletonPtr == nullptr,
+  check(SingletonPtr == nullptr,
         "There's already a live GuardedPoolAllocator!");
   SingletonPtr = this;
   Backtrace = Opts.Backtrace;
diff --git a/gwp_asan/platform_specific/guarded_pool_allocator_fuchsia.cpp b/gwp_asan/platform_specific/guarded_pool_allocator_fuchsia.cpp
index ca5231a..5d5c729 100644
--- a/gwp_asan/platform_specific/guarded_pool_allocator_fuchsia.cpp
+++ b/gwp_asan/platform_specific/guarded_pool_allocator_fuchsia.cpp
@@ -24,13 +24,13 @@ void *GuardedPoolAllocator::map(size_t Size, const char *Name) const {
   assert((Size % State.PageSize) == 0);
   zx_handle_t Vmo;
   zx_status_t Status = _zx_vmo_create(Size, 0, &Vmo);
-  Check(Status == ZX_OK, "Failed to create Vmo");
+  checkWithErrorCode(Status == ZX_OK, "Failed to create Vmo", Status);
   _zx_object_set_property(Vmo, ZX_PROP_NAME, Name, strlen(Name));
   zx_vaddr_t Addr;
   Status = _zx_vmar_map(_zx_vmar_root_self(),
                         ZX_VM_PERM_READ | ZX_VM_PERM_WRITE | ZX_VM_ALLOW_FAULTS,
                         0, Vmo, 0, Size, &Addr);
-  Check(Status == ZX_OK, "Vmo mapping failed");
+  checkWithErrorCode(Status == ZX_OK, "Vmo mapping failed", Status);
   _zx_handle_close(Vmo);
   return reinterpret_cast<void *>(Addr);
 }
@@ -40,7 +40,7 @@ void GuardedPoolAllocator::unmap(void *Ptr, size_t Size) const {
   assert((Size % State.PageSize) == 0);
   zx_status_t Status = _zx_vmar_unmap(_zx_vmar_root_self(),
                                       reinterpret_cast<zx_vaddr_t>(Ptr), Size);
-  Check(Status == ZX_OK, "Vmo unmapping failed");
+  checkWithErrorCode(Status == ZX_OK, "Vmo unmapping failed", Status);
 }
 
 void *GuardedPoolAllocator::reserveGuardedPool(size_t Size) {
@@ -50,7 +50,8 @@ void *GuardedPoolAllocator::reserveGuardedPool(size_t Size) {
       _zx_vmar_root_self(),
       ZX_VM_CAN_MAP_READ | ZX_VM_CAN_MAP_WRITE | ZX_VM_CAN_MAP_SPECIFIC, 0,
       Size, &GuardedPagePoolPlatformData.Vmar, &Addr);
-  Check(Status == ZX_OK, "Failed to reserve guarded pool allocator memory");
+  checkWithErrorCode(Status == ZX_OK,
+                     "Failed to reserve guarded pool allocator memory", Status);
   _zx_object_set_property(GuardedPagePoolPlatformData.Vmar, ZX_PROP_NAME,
                           kGwpAsanGuardPageName, strlen(kGwpAsanGuardPageName));
   return reinterpret_cast<void *>(Addr);
@@ -59,8 +60,10 @@ void *GuardedPoolAllocator::reserveGuardedPool(size_t Size) {
 void GuardedPoolAllocator::unreserveGuardedPool() {
   const zx_handle_t Vmar = GuardedPagePoolPlatformData.Vmar;
   assert(Vmar != ZX_HANDLE_INVALID && Vmar != _zx_vmar_root_self());
-  Check(_zx_vmar_destroy(Vmar) == ZX_OK, "Failed to destroy a vmar");
-  Check(_zx_handle_close(Vmar) == ZX_OK, "Failed to close a vmar");
+  zx_status_t Status = _zx_vmar_destroy(Vmar);
+  checkWithErrorCode(Status == ZX_OK, "Failed to destroy a vmar", Status);
+  Status = _zx_handle_close(Vmar);
+  checkWithErrorCode(Status == ZX_OK, "Failed to close a vmar", Status);
   GuardedPagePoolPlatformData.Vmar = ZX_HANDLE_INVALID;
 }
 
@@ -69,7 +72,7 @@ void GuardedPoolAllocator::allocateInGuardedPool(void *Ptr, size_t Size) const {
   assert((Size % State.PageSize) == 0);
   zx_handle_t Vmo;
   zx_status_t Status = _zx_vmo_create(Size, 0, &Vmo);
-  Check(Status == ZX_OK, "Failed to create vmo");
+  checkWithErrorCode(Status == ZX_OK, "Failed to create vmo", Status);
   _zx_object_set_property(Vmo, ZX_PROP_NAME, kGwpAsanAliveSlotName,
                           strlen(kGwpAsanAliveSlotName));
   const zx_handle_t Vmar = GuardedPagePoolPlatformData.Vmar;
@@ -81,7 +84,7 @@ void GuardedPoolAllocator::allocateInGuardedPool(void *Ptr, size_t Size) const {
                         ZX_VM_PERM_READ | ZX_VM_PERM_WRITE |
                             ZX_VM_ALLOW_FAULTS | ZX_VM_SPECIFIC,
                         Offset, Vmo, 0, Size, &P);
-  Check(Status == ZX_OK, "Vmo mapping failed");
+  checkWithErrorCode(Status == ZX_OK, "Vmo mapping failed", Status);
   _zx_handle_close(Vmo);
 }
 
@@ -93,7 +96,7 @@ void GuardedPoolAllocator::deallocateInGuardedPool(void *Ptr,
   assert(Vmar != ZX_HANDLE_INVALID && Vmar != _zx_vmar_root_self());
   const zx_status_t Status =
       _zx_vmar_unmap(Vmar, reinterpret_cast<zx_vaddr_t>(Ptr), Size);
-  Check(Status == ZX_OK, "Vmar unmapping failed");
+  checkWithErrorCode(Status == ZX_OK, "Vmar unmapping failed", Status);
 }
 
 size_t GuardedPoolAllocator::getPlatformPageSize() {
diff --git a/gwp_asan/platform_specific/guarded_pool_allocator_posix.cpp b/gwp_asan/platform_specific/guarded_pool_allocator_posix.cpp
index c036ebe..7b2e199 100644
--- a/gwp_asan/platform_specific/guarded_pool_allocator_posix.cpp
+++ b/gwp_asan/platform_specific/guarded_pool_allocator_posix.cpp
@@ -12,6 +12,7 @@
 #include "gwp_asan/utilities.h"
 
 #include <assert.h>
+#include <errno.h>
 #include <pthread.h>
 #include <stdint.h>
 #include <stdlib.h>
@@ -46,7 +47,8 @@ void *GuardedPoolAllocator::map(size_t Size, const char *Name) const {
   assert((Size % State.PageSize) == 0);
   void *Ptr = mmap(nullptr, Size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
-  Check(Ptr != MAP_FAILED, "Failed to map guarded pool allocator memory");
+  checkWithErrorCode(Ptr != MAP_FAILED,
+                     "Failed to map guarded pool allocator memory", errno);
   MaybeSetMappingName(Ptr, Size, Name);
   return Ptr;
 }
@@ -54,15 +56,16 @@ void *GuardedPoolAllocator::map(size_t Size, const char *Name) const {
 void GuardedPoolAllocator::unmap(void *Ptr, size_t Size) const {
   assert((reinterpret_cast<uintptr_t>(Ptr) % State.PageSize) == 0);
   assert((Size % State.PageSize) == 0);
-  Check(munmap(Ptr, Size) == 0,
-        "Failed to unmap guarded pool allocator memory.");
+  checkWithErrorCode(munmap(Ptr, Size) == 0,
+                     "Failed to unmap guarded pool allocator memory.", errno);
 }
 
 void *GuardedPoolAllocator::reserveGuardedPool(size_t Size) {
   assert((Size % State.PageSize) == 0);
   void *Ptr =
       mmap(nullptr, Size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
-  Check(Ptr != MAP_FAILED, "Failed to reserve guarded pool allocator memory");
+  checkWithErrorCode(Ptr != MAP_FAILED,
+                     "Failed to reserve guarded pool allocator memory", errno);
   MaybeSetMappingName(Ptr, Size, kGwpAsanGuardPageName);
   return Ptr;
 }
@@ -75,8 +78,9 @@ void GuardedPoolAllocator::unreserveGuardedPool() {
 void GuardedPoolAllocator::allocateInGuardedPool(void *Ptr, size_t Size) const {
   assert((reinterpret_cast<uintptr_t>(Ptr) % State.PageSize) == 0);
   assert((Size % State.PageSize) == 0);
-  Check(mprotect(Ptr, Size, PROT_READ | PROT_WRITE) == 0,
-        "Failed to allocate in guarded pool allocator memory");
+  checkWithErrorCode(mprotect(Ptr, Size, PROT_READ | PROT_WRITE) == 0,
+                     "Failed to allocate in guarded pool allocator memory",
+                     errno);
   MaybeSetMappingName(Ptr, Size, kGwpAsanAliveSlotName);
 }
 
@@ -87,9 +91,10 @@ void GuardedPoolAllocator::deallocateInGuardedPool(void *Ptr,
   // mmap() a PROT_NONE page over the address to release it to the system, if
   // we used mprotect() here the system would count pages in the quarantine
   // against the RSS.
-  Check(mmap(Ptr, Size, PROT_NONE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1,
-             0) != MAP_FAILED,
-        "Failed to deallocate in guarded pool allocator memory");
+  checkWithErrorCode(
+      mmap(Ptr, Size, PROT_NONE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1,
+           0) != MAP_FAILED,
+      "Failed to deallocate in guarded pool allocator memory", errno);
   MaybeSetMappingName(Ptr, Size, kGwpAsanGuardPageName);
 }
 
diff --git a/gwp_asan/platform_specific/utilities_fuchsia.cpp b/gwp_asan/platform_specific/utilities_fuchsia.cpp
index bc9d3a4..fecf94b 100644
--- a/gwp_asan/platform_specific/utilities_fuchsia.cpp
+++ b/gwp_asan/platform_specific/utilities_fuchsia.cpp
@@ -8,12 +8,25 @@
 
 #include "gwp_asan/utilities.h"
 
+#include <alloca.h>
+#include <stdio.h>
 #include <string.h>
 #include <zircon/sanitizer.h>
+#include <zircon/status.h>
 
 namespace gwp_asan {
 void die(const char *Message) {
   __sanitizer_log_write(Message, strlen(Message));
   __builtin_trap();
 }
+
+void dieWithErrorCode(const char *Message, int64_t ErrorCode) {
+  const char *error_str =
+      _zx_status_get_string(static_cast<zx_status_t>(ErrorCode));
+  size_t buffer_size = strlen(Message) + 32 + strlen(error_str);
+  char *buffer = static_cast<char *>(alloca(buffer_size));
+  snprintf(buffer, buffer_size, "%s (Error Code: %s)", Message, error_str);
+  __sanitizer_log_write(buffer, strlen(buffer));
+  __builtin_trap();
+}
 } // namespace gwp_asan
diff --git a/gwp_asan/platform_specific/utilities_posix.cpp b/gwp_asan/platform_specific/utilities_posix.cpp
index 7357963..7501980 100644
--- a/gwp_asan/platform_specific/utilities_posix.cpp
+++ b/gwp_asan/platform_specific/utilities_posix.cpp
@@ -6,7 +6,11 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include <alloca.h>
 #include <features.h> // IWYU pragma: keep (for __BIONIC__ macro)
+#include <inttypes.h>
+#include <stdint.h>
+#include <string.h>
 
 #ifdef __BIONIC__
 #include "gwp_asan/definitions.h"
@@ -27,4 +31,21 @@ void die(const char *Message) {
   __builtin_trap();
 #endif // __BIONIC__
 }
+
+void dieWithErrorCode(const char *Message, int64_t ErrorCode) {
+#ifdef __BIONIC__
+  if (&android_set_abort_message == nullptr)
+    abort();
+
+  size_t buffer_size = strlen(Message) + 48;
+  char *buffer = static_cast<char *>(alloca(buffer_size));
+  snprintf(buffer, buffer_size, "%s (Error Code: %" PRId64 ")", Message,
+           ErrorCode);
+  android_set_abort_message(buffer);
+  abort();
+#else  // __BIONIC__
+  fprintf(stderr, "%s (Error Code: %" PRId64 ")", Message, ErrorCode);
+  __builtin_trap();
+#endif // __BIONIC__
+}
 } // namespace gwp_asan
diff --git a/gwp_asan/tests/utilities.cpp b/gwp_asan/tests/utilities.cpp
new file mode 100644
index 0000000..09a54e5
--- /dev/null
+++ b/gwp_asan/tests/utilities.cpp
@@ -0,0 +1,24 @@
+//===-- utilities.cpp -------------------------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "gwp_asan/utilities.h"
+#include "gwp_asan/tests/harness.h"
+
+using gwp_asan::check;
+using gwp_asan::checkWithErrorCode;
+
+TEST(UtilitiesDeathTest, CheckPrintsAsExpected) {
+  EXPECT_DEATH({ check(false, "Hello world"); }, "Hello world");
+  check(true, "Should not crash");
+  EXPECT_DEATH(
+      { checkWithErrorCode(false, "Hello world", 1337); },
+      "Hello world \\(Error Code: 1337\\)");
+  EXPECT_DEATH(
+      { checkWithErrorCode(false, "Hello world", -1337); },
+      "Hello world \\(Error Code: -1337\\)");
+}
diff --git a/gwp_asan/utilities.h b/gwp_asan/utilities.h
index d8bc0e4..02f450a 100644
--- a/gwp_asan/utilities.h
+++ b/gwp_asan/utilities.h
@@ -12,17 +12,28 @@
 #include "gwp_asan/definitions.h"
 
 #include <stddef.h>
+#include <stdint.h>
 
 namespace gwp_asan {
 // Terminates in a platform-specific way with `Message`.
 void die(const char *Message);
+void dieWithErrorCode(const char *Message, int64_t ErrorCode);
 
 // Checks that `Condition` is true, otherwise dies with `Message`.
-GWP_ASAN_ALWAYS_INLINE void Check(bool Condition, const char *Message) {
-  if (Condition)
+GWP_ASAN_ALWAYS_INLINE void check(bool Condition, const char *Message) {
+  if (GWP_ASAN_LIKELY(Condition))
     return;
   die(Message);
 }
+
+// Checks that `Condition` is true, otherwise dies with `Message` (including
+// errno at the end).
+GWP_ASAN_ALWAYS_INLINE void
+checkWithErrorCode(bool Condition, const char *Message, int64_t ErrorCode) {
+  if (GWP_ASAN_LIKELY(Condition))
+    return;
+  dieWithErrorCode(Message, ErrorCode);
+}
 } // namespace gwp_asan
 
 #endif // GWP_ASAN_UTILITIES_H_
```

