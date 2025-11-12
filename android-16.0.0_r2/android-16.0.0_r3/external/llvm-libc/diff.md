```diff
diff --git a/Android.bp b/Android.bp
index 3192b79..fbedc15 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,4 +1,6 @@
-// https://ci.android.com/builds/latest/branches/aosp-build-tools/targets/linux/view/soong_build.html
+// Use this command to manually trigger a run if you don't want to wait a week:
+// $ /google/bin/releases/copybara/public/copybara/copybara service trigger /google/src/head/depot/google3/wireless/android/android_native_team/copy.bara.sky default
+// (See go/copybara-service-commands#trigger for more.)
 
 cc_defaults {
     name: "llvmlibc_defaults",
@@ -11,14 +13,6 @@ cc_defaults {
         // Necessary to build.
         "-DLIBC_NAMESPACE=llvmlibc",
     ],
-    arch: {
-        // TODO: https://github.com/llvm/llvm-project/issues/93738
-        // llvm-libc does not (yet) support --target=armv7a-linux -mthumb
-        // Build in ARM mode, but perhaps revisit this in the future.
-        arm: {
-            instruction_set: "arm",
-        },
-    },
 }
 
 cc_library_static {
@@ -31,7 +25,21 @@ cc_library_static {
         "external/llvm-libc",
     ],
     srcs: [
+        "src/inttypes/imaxabs.cpp",
+        "src/inttypes/imaxdiv.cpp",
+        "src/search/lfind.cpp",
+        "src/search/lsearch.cpp",
+        "src/search/insque.cpp",
+        "src/search/remque.cpp",
+        "src/stdlib/abs.cpp",
         "src/stdlib/bsearch.cpp",
+        "src/stdlib/div.cpp",
+        "src/stdlib/labs.cpp",
+        "src/stdlib/ldiv.cpp",
+        "src/stdlib/llabs.cpp",
+        "src/stdlib/lldiv.cpp",
+        "src/stdlib/qsort.cpp",
+        "src/stdlib/qsort_r.cpp",
         "src/string/memchr.cpp",
         "src/string/memrchr.cpp",
         "src/string/strchr.cpp",
@@ -40,12 +48,12 @@ cc_library_static {
         "src/string/strlcpy.cpp",
         "src/string/strnlen.cpp",
         "src/string/strrchr.cpp",
+        "src/wchar/wcschr.cpp",
     ],
     cppflags: [
         // Necessary for non-namespaced exports.
         "-DLIBC_COPT_PUBLIC_PACKAGING",
-        // TODO: remove when https://github.com/llvm/llvm-project/pull/116686 is
-        // integrated.
+        // See https://github.com/llvm/llvm-project/pull/116686.
         "-DLLVM_LIBC_FUNCTION_ATTR=__attribute__((visibility(\"default\")))",
     ],
     // No C++ runtime.
@@ -128,7 +136,19 @@ cc_test {
     name: "llvmlibc_tests",
     defaults: ["llvmlibc_test_defaults"],
     srcs: [
+        "test/src/inttypes/imaxabs_test.cpp",
+        "test/src/inttypes/imaxdiv_test.cpp",
+        "test/src/search/lfind_test.cpp",
+        "test/src/search/lsearch_test.cpp",
+        "test/src/search/insque_test.cpp",
+        "test/src/stdlib/abs_test.cpp",
         "test/src/stdlib/bsearch_test.cpp",
+        "test/src/stdlib/div_test.cpp",
+        "test/src/stdlib/labs_test.cpp",
+        "test/src/stdlib/ldiv_test.cpp",
+        "test/src/stdlib/llabs_test.cpp",
+        "test/src/stdlib/lldiv_test.cpp",
+        "test/src/stdlib/qsort_r_test.cpp",
         "test/src/string/memchr_test.cpp",
         "test/src/string/memrchr_test.cpp",
         "test/src/string/strchr_test.cpp",
@@ -137,6 +157,7 @@ cc_test {
         "test/src/string/strlcpy_test.cpp",
         "test/src/string/strnlen_test.cpp",
         "test/src/string/strrchr_test.cpp",
+        "test/src/wchar/wcschr_test.cpp",
     ],
     arch: {
         arm64: {
diff --git a/hdr/offsetof_macros.h b/hdr/offsetof_macros.h
new file mode 100644
index 0000000..42e853f
--- /dev/null
+++ b/hdr/offsetof_macros.h
@@ -0,0 +1,23 @@
+//===-- Definition of macros for offsetof ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_HDR_OFFSETOF_MACROS_H
+#define LLVM_LIBC_HDR_OFFSETOF_MACROS_H
+
+#ifdef LIBC_FULL_BUILD
+
+#include "include/llvm-libc-macros/offsetof-macro.h"
+
+#else // Overlay mode
+
+#define __need_offsetof
+#include <stddef.h>
+
+#endif // LLVM_LIBC_FULL_BUILD
+
+#endif // LLVM_LIBC_HDR_OFFSETOF_MACROS_H
diff --git a/hdr/stdlib_overlay.h b/hdr/stdlib_overlay.h
index f095caf..53c32ec 100644
--- a/hdr/stdlib_overlay.h
+++ b/hdr/stdlib_overlay.h
@@ -19,6 +19,11 @@
 // functions, causing external alias errors.  They are guarded by
 // `__USE_FORTIFY_LEVEL`, which will be temporarily disabled.
 
+#ifdef _FORTIFY_SOURCE
+#define LIBC_OLD_FORTIFY_SOURCE _FORTIFY_SOURCE
+#undef _FORTIFY_SOURCE
+#endif
+
 #ifdef __USE_FORTIFY_LEVEL
 #define LIBC_OLD_USE_FORTIFY_LEVEL __USE_FORTIFY_LEVEL
 #undef __USE_FORTIFY_LEVEL
@@ -27,6 +32,11 @@
 
 #include <stdlib.h>
 
+#ifdef LIBC_OLD_FORTIFY_SOURCE
+#define _FORTIFY_SOURCE LIBC_OLD_FORTIFY_SOURCE
+#undef LIBC_OLD_FORTIFY_SOURCE
+#endif
+
 #ifdef LIBC_OLD_USE_FORTIFY_LEVEL
 #undef __USE_FORTIFY_LEVEL
 #define __USE_FORTIFY_LEVEL LIBC_OLD_USE_FORTIFY_LEVEL
diff --git a/hdr/types/ACTION.h b/hdr/types/ACTION.h
new file mode 100644
index 0000000..0b63521
--- /dev/null
+++ b/hdr/types/ACTION.h
@@ -0,0 +1,22 @@
+//===-- Proxy header for ACTION -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_HDR_TYPES_ACTION_H
+#define LLVM_LIBC_HDR_TYPES_ACTION_H
+
+#ifdef LIBC_FULL_BUILD
+
+#include "include/llvm-libc-types/ACTION.h"
+
+#else // Overlay mode
+
+#include <search.h>
+
+#endif // LLVM_LIBC_FULL_BUILD
+
+#endif // LLVM_LIBC_HDR_TYPES_ACTION_H
diff --git a/hdr/types/ENTRY.h b/hdr/types/ENTRY.h
new file mode 100644
index 0000000..5f4aee4
--- /dev/null
+++ b/hdr/types/ENTRY.h
@@ -0,0 +1,22 @@
+//===-- Proxy header for ENTRY --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_HDR_TYPES_ENTRY_H
+#define LLVM_LIBC_HDR_TYPES_ENTRY_H
+
+#ifdef LIBC_FULL_BUILD
+
+#include "include/llvm-libc-types/ENTRY.h"
+
+#else // Overlay mode
+
+#include <search.h>
+
+#endif // LLVM_LIBC_FULL_BUILD
+
+#endif // LLVM_LIBC_HDR_TYPES_ENTRY_H
diff --git a/hdr/types/struct_itimerval.h b/hdr/types/struct_itimerval.h
new file mode 100644
index 0000000..b228167
--- /dev/null
+++ b/hdr/types/struct_itimerval.h
@@ -0,0 +1,21 @@
+//===-- Proxy for struct itimerval ----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+#ifndef LLVM_LIBC_HDR_TYPES_STRUCT_ITIMERVAL_H
+#define LLVM_LIBC_HDR_TYPES_STRUCT_ITIMERVAL_H
+
+#ifdef LIBC_FULL_BUILD
+
+#include "include/llvm-libc-types/struct_itimerval.h"
+
+#else
+
+#include <sys/time.h>
+
+#endif // LIBC_FULL_BUILD
+
+#endif // LLVM_LIBC_HDR_TYPES_STRUCT_ITIMERVAL_H
diff --git a/include/llvm-libc-macros/baremetal/time-macros.h b/include/llvm-libc-macros/baremetal/time-macros.h
new file mode 100644
index 0000000..3537376
--- /dev/null
+++ b/include/llvm-libc-macros/baremetal/time-macros.h
@@ -0,0 +1,26 @@
+//===-- Definition of macros from time.h ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_MACROS_BAREMETAL_TIME_MACROS_H
+#define LLVM_LIBC_MACROS_BAREMETAL_TIME_MACROS_H
+
+#ifdef __CLK_TCK
+#define CLOCKS_PER_SEC __CLK_TCK
+#else
+#if defined(__arm__) || defined(_M_ARM) || defined(__aarch64__) ||             \
+    defined(__arm64__) || defined(_M_ARM64)
+// This default implementation of this function shall use semihosting
+// Semihosting measures time in centiseconds
+// https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst#sys-clock-0x10
+#define CLOCKS_PER_SEC 100
+#else
+#define CLOCKS_PER_SEC 1000000
+#endif
+#endif
+
+#endif // LLVM_LIBC_MACROS_BAREMETAL_TIME_MACROS_H
diff --git a/include/llvm-libc-macros/time-macros.h b/include/llvm-libc-macros/time-macros.h
index 445d8b3..30e0a31 100644
--- a/include/llvm-libc-macros/time-macros.h
+++ b/include/llvm-libc-macros/time-macros.h
@@ -5,8 +5,14 @@
 #include "gpu/time-macros.h"
 #elif defined(__linux__)
 #include "linux/time-macros.h"
+#elif defined(__ELF__)
+#include "baremetal/time-macros.h"
+#else
+#define CLOCKS_PER_SEC 1000000
 #endif
 
+#define CLK_TCK CLOCKS_PER_SEC
+
 #define TIME_UTC 1
 #define TIME_MONOTONIC 2
 #define TIME_ACTIVE 3
diff --git a/include/llvm-libc-types/EFI_ALLOCATE_TYPE.h b/include/llvm-libc-types/EFI_ALLOCATE_TYPE.h
deleted file mode 100644
index 90f2396..0000000
--- a/include/llvm-libc-types/EFI_ALLOCATE_TYPE.h
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Definition of EFI_ALLOCATE_TYPE type ------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_ALLOCATE_TYPE_H
-#define LLVM_LIBC_TYPES_EFI_ALLOCATE_TYPE_H
-
-typedef enum {
-  AllocateAnyPages,
-  AllocateMaxAddress,
-  AllocateAddress,
-  MaxAllocateType
-} EFI_ALLOCATE_TYPE;
-
-#endif // LLVM_LIBC_TYPES_EFI_ALLOCATE_TYPE_H
diff --git a/include/llvm-libc-types/EFI_BOOT_SERVICES.h b/include/llvm-libc-types/EFI_BOOT_SERVICES.h
deleted file mode 100644
index 8b7a6aa..0000000
--- a/include/llvm-libc-types/EFI_BOOT_SERVICES.h
+++ /dev/null
@@ -1,250 +0,0 @@
-//===-- Definition of EFI_BOOT_SERVICES type ------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_BOOT_SERVICES_H
-#define LLVM_LIBC_TYPES_EFI_BOOT_SERVICES_H
-
-#include "../llvm-libc-macros/EFIAPI-macros.h"
-#include "EFI_ALLOCATE_TYPE.h"
-#include "EFI_DEVICE_PATH_PROTOCOL.h"
-#include "EFI_EVENT.h"
-#include "EFI_GUID.h"
-#include "EFI_INTERFACE_TYPE.h"
-#include "EFI_LOCATE_SEARCH_TYPE.h"
-#include "EFI_MEMORY_DESCRIPTOR.h"
-#include "EFI_MEMORY_TYPE.h"
-#include "EFI_OPEN_PROTOCOL_INFORMATION_ENTRY.h"
-#include "EFI_PHYSICAL_ADDRESS.h"
-#include "EFI_STATUS.h"
-#include "EFI_TABLE_HEADER.h"
-#include "EFI_TIMER_DELAY.h"
-#include "EFI_TPL.h"
-#include "char16_t.h"
-#include "size_t.h"
-
-#define EFI_BOOT_SERVICES_SIGNATURE 0x56524553544f4f42
-#define EFI_BOOT_SERVICES_REVISION EFI_SPECIFICATION_VERSION
-
-typedef EFI_TPL(EFIAPI *EFI_RAISE_TPL)(EFI_TPL NewTpl);
-typedef void(EFIAPI *EFI_RESTORE_TPL)(EFI_TPL OldTpl);
-
-typedef EFI_STATUS(EFIAPI *EFI_ALLOCATE_PAGES)(EFI_ALLOCATE_TYPE Type,
-                                               EFI_MEMORY_TYPE MemoryType,
-                                               size_t Pages,
-                                               EFI_PHYSICAL_ADDRESS *Memory);
-typedef EFI_STATUS(EFIAPI *EFI_FREE_PAGES)(EFI_PHYSICAL_ADDRESS Memory,
-                                           size_t Pages);
-typedef EFI_STATUS(EFIAPI *EFI_GET_MEMORY_MAP)(size_t *MemoryMapSize,
-                                               EFI_MEMORY_DESCRIPTOR *MemoryMap,
-                                               size_t *MapKey,
-                                               size_t *DescriptorSize,
-                                               uint32_t *DescriptorVersion);
-
-typedef EFI_STATUS(EFIAPI *EFI_ALLOCATE_POOL)(EFI_MEMORY_TYPE PoolType,
-                                              size_t Size, void **Buffer);
-typedef EFI_STATUS(EFIAPI *EFI_FREE_POOL)(void *Buffer);
-
-typedef void(EFIAPI *EFI_EVENT_NOTIFY)(EFI_EVENT Event, void *Context);
-
-typedef EFI_STATUS(EFIAPI *EFI_CREATE_EVENT)(uint32_t Type, EFI_TPL NotifyTpl,
-                                             EFI_EVENT_NOTIFY NotifyFunction,
-                                             void *NotifyContext,
-                                             EFI_EVENT *Event);
-typedef EFI_STATUS(EFIAPI *EFI_SET_TIMER)(EFI_EVENT Event, EFI_TIMER_DELAY Type,
-                                          uint64_t TriggerTime);
-typedef EFI_STATUS(EFIAPI *EFI_WAIT_FOR_EVENT)(size_t NumberOfEvents,
-                                               EFI_EVENT *Event, size_t *Index);
-typedef EFI_STATUS(EFIAPI *EFI_SIGNAL_EVENT)(EFI_EVENT Event);
-typedef EFI_STATUS(EFIAPI *EFI_CLOSE_EVENT)(EFI_EVENT Event);
-typedef EFI_STATUS(EFIAPI *EFI_CHECK_EVENT)(EFI_EVENT Event);
-
-typedef EFI_STATUS(EFIAPI *EFI_INSTALL_PROTOCOL_INTERFACE)(
-    EFI_HANDLE *Handle, EFI_GUID *Protocol, EFI_INTERFACE_TYPE InterfaceType,
-    void *Interface);
-typedef EFI_STATUS(EFIAPI *EFI_REINSTALL_PROTOCOL_INTERFACE)(
-    EFI_HANDLE Handle, EFI_GUID *Protocol, void *OldInterface,
-    void *NewInterface);
-typedef EFI_STATUS(EFIAPI *EFI_UNINSTALL_PROTOCOL_INTERFACE)(EFI_HANDLE Handle,
-                                                             EFI_GUID *Protocol,
-                                                             void *Interface);
-
-typedef EFI_STATUS(EFIAPI *EFI_HANDLE_PROTOCOL)(EFI_HANDLE Handle,
-                                                EFI_GUID *Protocol,
-                                                void **Interface);
-typedef EFI_STATUS(EFIAPI *EFI_REGISTER_PROTOCOL_NOTIFY)(EFI_GUID *Protocol,
-                                                         EFI_EVENT Event,
-                                                         void **Registration);
-
-typedef EFI_STATUS(EFIAPI *EFI_LOCATE_HANDLE)(EFI_LOCATE_SEARCH_TYPE SearchType,
-                                              EFI_GUID *Protocol,
-                                              void *SearchKey,
-                                              size_t *BufferSize,
-                                              EFI_HANDLE *Buffer);
-typedef EFI_STATUS(EFIAPI *EFI_LOCATE_DEVICE_PATH)(
-    EFI_GUID *Protocol, EFI_DEVICE_PATH_PROTOCOL **DevicePath,
-    EFI_HANDLE *Device);
-
-typedef EFI_STATUS(EFIAPI *EFI_INSTALL_CONFIGURATION_TABLE)(EFI_GUID *Guid,
-                                                            void *Table);
-typedef EFI_STATUS(EFIAPI *EFI_IMAGE_UNLOAD)(EFI_HANDLE ImageHandle);
-typedef EFI_STATUS(EFIAPI *EFI_IMAGE_START)(EFI_HANDLE ImageHandle,
-                                            size_t *ExitDataSize,
-                                            char16_t **ExitData);
-
-typedef EFI_STATUS(EFIAPI *EFI_EXIT)(EFI_HANDLE ImageHandle,
-                                     EFI_STATUS ExitStatus, size_t ExitDataSize,
-                                     char16_t *ExitData);
-typedef EFI_STATUS(EFIAPI *EFI_EXIT_BOOT_SERVICES)(EFI_HANDLE ImageHandle,
-                                                   size_t MapKey);
-typedef EFI_STATUS(EFIAPI *EFI_GET_NEXT_MONOTONIC_COUNT)(uint64_t *Count);
-typedef EFI_STATUS(EFIAPI *EFI_STALL)(size_t Microseconds);
-typedef EFI_STATUS(EFIAPI *EFI_SET_WATCHDOG_TIMER)(size_t Timeout,
-                                                   uint64_t WatchdogCode,
-                                                   size_t DataSize,
-                                                   char16_t *WatchdogData);
-
-typedef EFI_STATUS(EFIAPI *EFI_CONNECT_CONTROLLER)(
-    EFI_HANDLE ControllerHandle, EFI_HANDLE *DriverImageHandle,
-    EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath, bool Recursive);
-
-typedef EFI_STATUS(EFIAPI *EFI_DISCONNECT_CONTROLLER)(
-    EFI_HANDLE ControllerHandle, EFI_HANDLE DriverImageHandle,
-    EFI_HANDLE ChildHandle);
-
-typedef EFI_STATUS(EFIAPI *EFI_OPEN_PROTOCOL)(
-    EFI_HANDLE Handle, EFI_GUID *Protocol, void **Interface,
-    EFI_HANDLE AgentHandle, EFI_HANDLE ControllerHandle, uint32_t Attributes);
-
-typedef EFI_STATUS(EFIAPI *EFI_CLOSE_PROTOCOL)(EFI_HANDLE Handle,
-                                               EFI_GUID *Protocol,
-                                               EFI_HANDLE AgentHandle,
-                                               EFI_HANDLE ControllerHandle);
-
-typedef EFI_STATUS(EFIAPI *EFI_OPEN_PROTOCOL_INFORMATION)(
-    EFI_HANDLE Handle, EFI_GUID *Protocol,
-    EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer, size_t *EntryCount);
-
-typedef EFI_STATUS(EFIAPI *EFI_PROTOCOLS_PER_HANDLE)(
-    EFI_HANDLE Handle, EFI_GUID ***ProtocolBuffer, size_t *ProtocolBufferCount);
-
-typedef EFI_STATUS(EFIAPI *EFI_LOCATE_HANDLE_BUFFER)(
-    EFI_LOCATE_SEARCH_TYPE SearchType, EFI_GUID *Protocol, void *SearchKey,
-    size_t *NoHandles, EFI_HANDLE **Buffer);
-
-typedef EFI_STATUS(EFIAPI *EFI_LOCATE_PROTOCOL)(EFI_GUID *Protocol,
-                                                void *Registration,
-                                                void **Interface);
-
-typedef EFI_STATUS(EFIAPI *EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES)(
-    EFI_HANDLE Handle, ...);
-typedef EFI_STATUS(EFIAPI *EFI_CALCULATE_CRC32)(void *Data, size_t DataSize,
-                                                uint32_t *Crc32);
-
-typedef void(EFIAPI *EFI_COPY_MEM)(void *Destination, void *Source,
-                                   size_t Length);
-typedef void(EFIAPI *EFI_SET_MEM)(void *Buffer, size_t Size, uint8_t Value);
-
-typedef EFI_STATUS(EFIAPI *EFI_CREATE_EVENT_EX)(
-    uint32_t Type, EFI_TPL NotifyTpl, EFI_EVENT_NOTIFY NotifyFunction,
-    const void *NotifyContext, const EFI_GUID *EventGroup, EFI_EVENT *Event);
-
-typedef struct {
-  EFI_TABLE_HEADER Hdr;
-
-  //
-  // Task Priority Services
-  //
-  EFI_RAISE_TPL RaiseTPL;     // EFI 1.0+
-  EFI_RESTORE_TPL RestoreTPL; // EFI 1.0+
-
-  //
-  // Memory Services
-  //
-  EFI_ALLOCATE_PAGES AllocatePages; // EFI 1.0+
-  EFI_FREE_PAGES FreePages;         // EFI 1.0+
-  EFI_GET_MEMORY_MAP GetMemoryMap;  // EFI 1.0+
-  EFI_ALLOCATE_POOL AllocatePool;   // EFI 1.0+
-  EFI_FREE_POOL FreePool;           // EFI 1.0+
-
-  //
-  // Event & Timer Services
-  //
-  EFI_CREATE_EVENT CreateEvent;    // EFI 1.0+
-  EFI_SET_TIMER SetTimer;          // EFI 1.0+
-  EFI_WAIT_FOR_EVENT WaitForEvent; // EFI 1.0+
-  EFI_SIGNAL_EVENT SignalEvent;    // EFI 1.0+
-  EFI_CLOSE_EVENT CloseEvent;      // EFI 1.0+
-  EFI_CHECK_EVENT CheckEvent;      // EFI 1.0+
-
-  //
-  // Protocol Handler Services
-  //
-  EFI_INSTALL_PROTOCOL_INTERFACE InstallProtocolInterface;     // EFI 1.0+
-  EFI_REINSTALL_PROTOCOL_INTERFACE ReinstallProtocolInterface; // EFI 1.0+
-  EFI_UNINSTALL_PROTOCOL_INTERFACE UninstallProtocolInterface; // EFI 1.0+
-  EFI_HANDLE_PROTOCOL HandleProtocol;                          // EFI 1.0+
-  void *Reserved;                                              // EFI 1.0+
-  EFI_REGISTER_PROTOCOL_NOTIFY RegisterProtocolNotify;         // EFI 1.0+
-  EFI_LOCATE_HANDLE LocateHandle;                              // EFI 1.+
-  EFI_LOCATE_DEVICE_PATH LocateDevicePath;                     // EFI 1.0+
-  EFI_INSTALL_CONFIGURATION_TABLE InstallConfigurationTable;   // EFI 1.0+
-
-  //
-  // Image Services
-  //
-  EFI_IMAGE_UNLOAD LoadImage;              // EFI 1.0+
-  EFI_IMAGE_START StartImage;              // EFI 1.0+
-  EFI_EXIT Exit;                           // EFI 1.0+
-  EFI_IMAGE_UNLOAD UnloadImage;            // EFI 1.0+
-  EFI_EXIT_BOOT_SERVICES ExitBootServices; // EFI 1.0+
-
-  //
-  // Miscellaneous Services
-  //
-  EFI_GET_NEXT_MONOTONIC_COUNT GetNextMonotonicCount; // EFI 1.0+
-  EFI_STALL Stall;                                    // EFI 1.0+
-  EFI_SET_WATCHDOG_TIMER SetWatchdogTimer;            // EFI 1.0+
-
-  //
-  // DriverSupport Services
-  //
-  EFI_CONNECT_CONTROLLER ConnectController;       // EFI 1.1
-  EFI_DISCONNECT_CONTROLLER DisconnectController; // EFI 1.1+
-
-  //
-  // Open and Close Protocol Services
-  //
-  EFI_OPEN_PROTOCOL OpenProtocol;                        // EFI 1.1+
-  EFI_CLOSE_PROTOCOL CloseProtocol;                      // EFI 1.1+
-  EFI_OPEN_PROTOCOL_INFORMATION OpenProtocolInformation; // EFI 1.1+
-
-  //
-  // Library Services
-  //
-  EFI_PROTOCOLS_PER_HANDLE ProtocolsPerHandle; // EFI 1.1+
-  EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer; // EFI 1.1+
-  EFI_LOCATE_PROTOCOL LocateProtocol;          // EFI 1.1+
-  EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES
-  InstallMultipleProtocolInterfaces; // EFI 1.1+
-  EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES
-  UninstallMultipleProtocolInterfaces; // EFI 1.1+*
-
-  //
-  // 32-bit CRC Services
-  //
-  EFI_CALCULATE_CRC32 CalculateCrc32; // EFI 1.1+
-
-  //
-  // Miscellaneous Services
-  //
-  EFI_COPY_MEM CopyMem;              // EFI 1.1+
-  EFI_SET_MEM SetMem;                // EFI 1.1+
-  EFI_CREATE_EVENT_EX CreateEventEx; // UEFI 2.0+
-} EFI_BOOT_SERVICES;
-
-#endif // LLVM_LIBC_TYPES_EFI_BOOT_SERVICES_H
diff --git a/include/llvm-libc-types/EFI_CAPSULE.h b/include/llvm-libc-types/EFI_CAPSULE.h
deleted file mode 100644
index c7440c9..0000000
--- a/include/llvm-libc-types/EFI_CAPSULE.h
+++ /dev/null
@@ -1,26 +0,0 @@
-//===-- Definition of EFI_CAPSULE type ------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_CAPSULE_H
-#define LLVM_LIBC_TYPES_EFI_CAPSULE_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-#include "EFI_GUID.h"
-
-typedef struct {
-  EFI_GUID CapsuleGuid;
-  uint32_t HeaderSize;
-  uint32_t Flags;
-  uint32_t CapsuleImageSize;
-} EFI_CAPSULE_HEADER;
-
-#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET 0x00010000
-#define CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE 0x00020000
-#define CAPSULE_FLAGS_INITIATE_RESET 0x00040000
-
-#endif // LLVM_LIBC_TYPES_EFI_CAPSULE_H
diff --git a/include/llvm-libc-types/EFI_CONFIGURATION_TABLE.h b/include/llvm-libc-types/EFI_CONFIGURATION_TABLE.h
deleted file mode 100644
index 56cd3e4..0000000
--- a/include/llvm-libc-types/EFI_CONFIGURATION_TABLE.h
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Definition of EFI_CONFIGURATION_TABLE type ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===---------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_CONFIGURATION_TABLE_H
-#define LLVM_LIBC_TYPES_EFI_CONFIGURATION_TABLE_H
-
-#include "EFI_GUID.h"
-
-typedef struct {
-  EFI_GUID VendorGuid;
-  void *VendorTable;
-} EFI_CONFIGURATION_TABLE;
-
-#endif // LLVM_LIBC_TYPES_EFI_CONFIGURATION_TABLE_H
diff --git a/include/llvm-libc-types/EFI_DEVICE_PATH_PROTOCOL.h b/include/llvm-libc-types/EFI_DEVICE_PATH_PROTOCOL.h
deleted file mode 100644
index f6a0b2e..0000000
--- a/include/llvm-libc-types/EFI_DEVICE_PATH_PROTOCOL.h
+++ /dev/null
@@ -1,23 +0,0 @@
-//===-- Definition of EFI_DEVICE_PATH_PROTOCOL type -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_DEVICE_PATH_PROTOCOL_H
-#define LLVM_LIBC_TYPES_EFI_DEVICE_PATH_PROTOCOL_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-
-#define EFI_DEVICE_PATH_PROTOCOL_GUID                                          \
-  {0x09576e91, 0x6d3f, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}
-
-typedef struct _EFI_DEVICE_PATH_PROTOCOL {
-  uint8_t Type;
-  uint8_t SubType;
-  uint8_t Length[2];
-} EFI_DEVICE_PATH_PROTOCOL;
-
-#endif // LLVM_LIBC_TYPES_EFI_DEVICE_PATH_PROTOCOL_H
diff --git a/include/llvm-libc-types/EFI_EVENT.h b/include/llvm-libc-types/EFI_EVENT.h
deleted file mode 100644
index 938856b..0000000
--- a/include/llvm-libc-types/EFI_EVENT.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of EFI_EVENT type --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_EVENT_H
-#define LLVM_LIBC_TYPES_EFI_EVENT_H
-
-typedef void *EFI_EVENT;
-
-#define EVT_TIMER 0x80000000
-#define EVT_RUNTIME 0x40000000
-#define EVT_NOTIFY_WAIT 0x00000100
-#define EVT_NOTIFY_SIGNAL 0x00000200
-#define EVT_SIGNAL_EXIT_BOOT_SERVICES 0x00000201
-#define EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE 0x60000202
-
-#endif // LLVM_LIBC_TYPES_EFI_EVENT_H
diff --git a/include/llvm-libc-types/EFI_GUID.h b/include/llvm-libc-types/EFI_GUID.h
deleted file mode 100644
index b353000..0000000
--- a/include/llvm-libc-types/EFI_GUID.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of EFI_GUID type -----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_GUID_H
-#define LLVM_LIBC_TYPES_EFI_GUID_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-
-typedef struct {
-  uint32_t Data1;
-  uint16_t Data2;
-  uint16_t Data3;
-  uint8_t Data4[8];
-} EFI_GUID;
-
-#endif // LLVM_LIBC_TYPES_EFI_GUID_H
diff --git a/include/llvm-libc-types/EFI_HANDLE.h b/include/llvm-libc-types/EFI_HANDLE.h
deleted file mode 100644
index d4376dd..0000000
--- a/include/llvm-libc-types/EFI_HANDLE.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of EFI_HANDLE type ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_HANDLE_H
-#define LLVM_LIBC_TYPES_EFI_HANDLE_H
-
-typedef void *EFI_HANDLE;
-
-#endif // LLVM_LIBC_TYPES_EFI_HANDLE_H
diff --git a/include/llvm-libc-types/EFI_LOCATE_SEARCH_TYPE.h b/include/llvm-libc-types/EFI_LOCATE_SEARCH_TYPE.h
deleted file mode 100644
index 3a8fd7b..0000000
--- a/include/llvm-libc-types/EFI_LOCATE_SEARCH_TYPE.h
+++ /dev/null
@@ -1,18 +0,0 @@
-//===-- Definition of EFI_LOCATE_SEARCH_TYPE type -------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_LOCATE_SEARCH_TYPE_H
-#define LLVM_LIBC_TYPES_EFI_LOCATE_SEARCH_TYPE_H
-
-typedef enum {
-  AllHandles,
-  ByRegisterNotify,
-  ByProtocol,
-} EFI_LOCATE_SEARCH_TYPE;
-
-#endif // LLVM_LIBC_TYPES_EFI_LOCATE_SEARCH_TYPE_H
diff --git a/include/llvm-libc-types/EFI_MEMORY_DESCRIPTOR.h b/include/llvm-libc-types/EFI_MEMORY_DESCRIPTOR.h
deleted file mode 100644
index 72d0579..0000000
--- a/include/llvm-libc-types/EFI_MEMORY_DESCRIPTOR.h
+++ /dev/null
@@ -1,43 +0,0 @@
-//===-- Definition of EFI_MEMORY_DESCRIPTOR type --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_MEMORY_DESCRIPTOR_H
-#define LLVM_LIBC_TYPES_EFI_MEMORY_DESCRIPTOR_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-#include "EFI_PHYSICAL_ADDRESS.h"
-#include "EFI_VIRTUAL_ADDRESS.h"
-
-#define EFI_MEMORY_DESCRIPTOR_VERSION 1
-
-#define EFI_MEMORY_UC 0x0000000000000001
-#define EFI_MEMORY_WC 0x0000000000000002
-#define EFI_MEMORY_WT 0x0000000000000004
-#define EFI_MEMORY_WB 0x0000000000000008
-#define EFI_MEMORY_UCE 0x0000000000000010
-#define EFI_MEMORY_WP 0x0000000000001000
-#define EFI_MEMORY_RP 0x0000000000002000
-#define EFI_MEMORY_XP 0x0000000000004000
-#define EFI_MEMORY_NV 0x0000000000008000
-#define EFI_MEMORY_MORE_RELIABLE 0x0000000000010000
-#define EFI_MEMORY_RO 0x0000000000020000
-#define EFI_MEMORY_SP 0x0000000000040000
-#define EFI_MEMORY_CPU_CRYPTO 0x0000000000080000
-#define EFI_MEMORY_RUNTIME 0x8000000000000000
-#define EFI_MEMORY_ISA_VALID 0x4000000000000000
-#define EFI_MEMORY_ISA_MASK 0x0FFFF00000000000
-
-typedef struct {
-  uint32_t Type;
-  EFI_PHYSICAL_ADDRESS PhysicalStart;
-  EFI_VIRTUAL_ADDRESS VirtualStart;
-  uint64_t NumberOfPages;
-  uint64_t Attribute;
-} EFI_MEMORY_DESCRIPTOR;
-
-#endif // LLVM_LIBC_TYPES_EFI_MEMORY_DESCRIPTOR_H
diff --git a/include/llvm-libc-types/EFI_MEMORY_TYPE.h b/include/llvm-libc-types/EFI_MEMORY_TYPE.h
deleted file mode 100644
index c8921cd..0000000
--- a/include/llvm-libc-types/EFI_MEMORY_TYPE.h
+++ /dev/null
@@ -1,32 +0,0 @@
-//===-- Definition of EFI_MEMORY_TYPE type --------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_MEMORY_TYPE_H
-#define LLVM_LIBC_TYPES_EFI_MEMORY_TYPE_H
-
-typedef enum {
-  EfiReservedMemoryType,
-  EfiLoaderCode,
-  EfiLoaderData,
-  EfiBootServicesCode,
-  EfiBootServicesData,
-  EfiRuntimeServicesCode,
-  EfiRuntimeServicesData,
-  EfiConventionalMemory,
-  EfiUnusableMemory,
-  EfiACPIReclaimMemory,
-  EfiACPIMemoryNVS,
-  EfiMemoryMappedIO,
-  EfiMemoryMappedIOPortSpace,
-  EfiPalCode,
-  EfiPersistentMemory,
-  EfiUnacceptedMemoryType,
-  EfiMaxMemoryType
-} EFI_MEMORY_TYPE;
-
-#endif // LLVM_LIBC_TYPES_EFI_MEMORY_TYPE_H
diff --git a/include/llvm-libc-types/EFI_OPEN_PROTOCOL_INFORMATION_ENTRY.h b/include/llvm-libc-types/EFI_OPEN_PROTOCOL_INFORMATION_ENTRY.h
deleted file mode 100644
index de0c59c..0000000
--- a/include/llvm-libc-types/EFI_OPEN_PROTOCOL_INFORMATION_ENTRY.h
+++ /dev/null
@@ -1,22 +0,0 @@
-//===-- Definition of EFI_OPEN_PROTOCOL_INFORMATION_ENTRY type ------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY_H
-#define LLVM_LIBC_TYPES_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-#include "EFI_HANDLE.h"
-
-typedef struct {
-  EFI_HANDLE AgentHandle;
-  EFI_HANDLE ControllerHandle;
-  uint32_t Attributes;
-  uint32_t OpenCount;
-} EFI_OPEN_PROTOCOL_INFORMATION_ENTRY;
-
-#endif // LLVM_LIBC_TYPES_EFI_OPEN_PROTOCOL_INFORMATION_ENTRY_H
diff --git a/include/llvm-libc-types/EFI_PHYSICAL_ADDRESS.h b/include/llvm-libc-types/EFI_PHYSICAL_ADDRESS.h
deleted file mode 100644
index 8880ee6..0000000
--- a/include/llvm-libc-types/EFI_PHYSICAL_ADDRESS.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of EFI_PHYSICAL_ADDRESS type ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_PHYSICAL_ADDRESS_H
-#define LLVM_LIBC_TYPES_EFI_PHYSICAL_ADDRESS_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-
-typedef uint64_t EFI_PHYSICAL_ADDRESS;
-
-#endif // LLVM_LIBC_TYPES_EFI_PHYSICAL_ADDRESS_H
diff --git a/include/llvm-libc-types/EFI_RUNTIME_SERVICES.h b/include/llvm-libc-types/EFI_RUNTIME_SERVICES.h
deleted file mode 100644
index 8913118..0000000
--- a/include/llvm-libc-types/EFI_RUNTIME_SERVICES.h
+++ /dev/null
@@ -1,137 +0,0 @@
-//===-- Definition of EFI_RUNTIME_SERVICES type ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_RUNTIME_SERVICES_H
-#define LLVM_LIBC_TYPES_EFI_RUNTIME_SERVICES_H
-
-#include "../llvm-libc-macros/EFIAPI-macros.h"
-#include "../llvm-libc-macros/stdint-macros.h"
-#include "EFI_CAPSULE.h"
-#include "EFI_MEMORY_DESCRIPTOR.h"
-#include "EFI_PHYSICAL_ADDRESS.h"
-#include "EFI_STATUS.h"
-#include "EFI_TABLE_HEADER.h"
-#include "EFI_TIME.h"
-#include "char16_t.h"
-#include "size_t.h"
-
-#define EFI_RUNTIME_SERVICES_SIGNATURE 0x56524553544e5552
-#define EFI_RUNTIME_SERVICES_REVISION EFI_SPECIFICATION_VERSION
-
-#define EFI_VARIABLE_NON_VOLATILE 0x00000001
-#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
-#define EFI_VARIABLE_RUNTIME_ACCESS 0x00000004
-#define EFI_VARIABLE_HARDWARE_ERROR_RECORD 0x00000008
-// This attribute is identified by the mnemonic 'HR' elsewhere
-// in this specification.
-#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS 0x00000010
-// NOTE: EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS is deprecated
-// and should be considered reserved.
-#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
-#define EFI_VARIABLE_APPEND_WRITE 0x00000040
-#define EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS 0x00000080
-
-typedef enum {
-  EfiResetCold,
-  EfiResetWarm,
-  EfiResetShutdown,
-  EfiResetPlatformSpecific,
-} EFI_RESET_TYPE;
-
-#define EFI_VARIABLE_AUTHENTICATION_3_CERT_ID_SHA256 1
-
-typedef struct {
-  uint8_t Type;
-  uint32_t IdSize;
-  // Value is defined as:
-  // uint8_t Id[IdSize];
-} EFI_VARIABLE_AUTHENTICATION_3_CERT_ID;
-
-typedef EFI_STATUS(EFIAPI *EFI_GET_TIME)(EFI_TIME *Time,
-                                         EFI_TIME_CAPABILITIES *Capabilities);
-typedef EFI_STATUS(EFIAPI *EFI_SET_TIME)(EFI_TIME *Time);
-typedef EFI_STATUS(EFIAPI *EFI_GET_WAKEUP_TIME)(bool *Enabled, bool *Pending,
-                                                EFI_TIME *Time);
-typedef EFI_STATUS(EFIAPI *EFI_SET_WAKEUP_TIME)(bool *Enabled, EFI_TIME *Time);
-
-typedef EFI_STATUS(EFIAPI *EFI_SET_VIRTUAL_ADDRESS_MAP)(
-    size_t MemoryMapSize, size_t DescriptorSize, uint32_t DescriptorVersion,
-    EFI_MEMORY_DESCRIPTOR *VirtualMap);
-typedef EFI_STATUS(EFIAPI *EFI_CONVERT_POINTER)(size_t DebugDisposition,
-                                                void **Address);
-
-typedef EFI_STATUS(EFIAPI *EFI_GET_VARIABLE)(char16_t *VariableName,
-                                             EFI_GUID *VendorGuid,
-                                             uint32_t *Attributes,
-                                             size_t *DataSize, void *Data);
-typedef EFI_STATUS(EFIAPI *EFI_GET_NEXT_VARIABLE_NAME)(size_t *VariableNameSize,
-                                                       char16_t *VariableName,
-                                                       EFI_GUID *VendorGuid);
-typedef EFI_STATUS(EFIAPI *EFI_SET_VARIABLE)(char16_t *VariableName,
-                                             EFI_GUID *VendorGuid,
-                                             uint32_t Attributes,
-                                             size_t DataSize, void *Data);
-
-typedef EFI_STATUS(EFIAPI *EFI_GET_NEXT_HIGH_MONO_COUNT)(uint32_t *HighCount);
-typedef void(EFIAPI *EFI_RESET_SYSTEM)(EFI_RESET_TYPE ResetType,
-                                       EFI_STATUS ResetStatus, size_t DataSize,
-                                       void *ResetData);
-
-typedef EFI_STATUS(EFIAPI *EFI_UPDATE_CAPSULE)(
-    EFI_CAPSULE_HEADER **CapsuleHeaderArray, size_t CapsuleCount,
-    EFI_PHYSICAL_ADDRESS ScatterGatherList);
-typedef EFI_STATUS(EFIAPI *EFI_QUERY_CAPSULE_CAPABILITIES)(
-    EFI_CAPSULE_HEADER **CapsuleHeaderArray, size_t CapsuleCount,
-    uint64_t *MaximumCapsuleSize, EFI_RESET_TYPE ResetType);
-
-typedef EFI_STATUS(EFIAPI *EFI_QUERY_VARIABLE_INFO)(
-    uint32_t Attributes, uint64_t *MaximumVariableStorageSize,
-    uint64_t *RemainingVariableStorageSize, uint64_t *MaximumVariableSize);
-
-typedef struct {
-  EFI_TABLE_HEADER Hdr;
-
-  ///
-  /// Time Services
-  EFI_GET_TIME GetTime;
-  EFI_SET_TIME SetTime;
-  EFI_GET_WAKEUP_TIME GetWakeupTime;
-  EFI_SET_WAKEUP_TIME SetWakeupTime;
-
-  //
-  // Virtual Memory Services
-  //
-  EFI_SET_VIRTUAL_ADDRESS_MAP SetVirtualAddressMap;
-  EFI_CONVERT_POINTER ConvertPointer;
-
-  //
-  // Variable Services
-  //
-  EFI_GET_VARIABLE GetVariable;
-  EFI_GET_NEXT_VARIABLE_NAME GetNextVariableName;
-  EFI_SET_VARIABLE SetVariable;
-
-  //
-  // Miscellaneous Services
-  //
-  EFI_GET_NEXT_HIGH_MONO_COUNT GetNextHighMonotonicCount;
-  EFI_RESET_SYSTEM ResetSystem;
-
-  //
-  // UEFI 2.0 Capsule Services
-  //
-  EFI_UPDATE_CAPSULE UpdateCapsule;
-  EFI_QUERY_CAPSULE_CAPABILITIES QueryCapsuleCapabilities;
-
-  //
-  // Miscellaneous UEFI 2.0 Service
-  //
-  EFI_QUERY_VARIABLE_INFO QueryVariableInfo;
-} EFI_RUNTIME_SERVICES;
-
-#endif // LLVM_LIBC_TYPES_EFI_RUNTIME_SERVICES_H
diff --git a/include/llvm-libc-types/EFI_SIMPLE_TEXT_INPUT_PROTOCOL.h b/include/llvm-libc-types/EFI_SIMPLE_TEXT_INPUT_PROTOCOL.h
deleted file mode 100644
index a6dc095..0000000
--- a/include/llvm-libc-types/EFI_SIMPLE_TEXT_INPUT_PROTOCOL.h
+++ /dev/null
@@ -1,39 +0,0 @@
-//===-- Definition of EFI_SIMPLE_TEXT_INPUT_PROTOCOL type -----------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_SIMPLE_TEXT_INPUT_PROTOCOL_H
-#define LLVM_LIBC_TYPES_EFI_SIMPLE_TEXT_INPUT_PROTOCOL_H
-
-#include "../llvm-libc-macros/EFIAPI-macros.h"
-#include "../llvm-libc-macros/stdint-macros.h"
-#include "EFI_EVENT.h"
-#include "EFI_STATUS.h"
-#include "char16_t.h"
-
-#define EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID                                    \
-  {0x387477c1, 0x69c7, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}
-
-typedef struct {
-  uint16_t ScanCode;
-  char16_t UnicodeChar;
-} EFI_INPUT_KEY;
-
-struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
-
-typedef EFI_STATUS(EFIAPI *EFI_INPUT_RESET)(
-    struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, bool ExtendedVerification);
-typedef EFI_STATUS(EFIAPI *EFI_INPUT_READ_KEY)(
-    struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, EFI_INPUT_KEY *Key);
-
-typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
-  EFI_INPUT_RESET Reset;
-  EFI_INPUT_READ_KEY ReadKeyStroke;
-  EFI_EVENT WaitForKey;
-} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
-
-#endif // LLVM_LIBC_TYPES_EFI_SIMPLE_TEXT_INPUT_PROTOCOL_H
diff --git a/include/llvm-libc-types/EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.h b/include/llvm-libc-types/EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.h
deleted file mode 100644
index b5014c4..0000000
--- a/include/llvm-libc-types/EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.h
+++ /dev/null
@@ -1,64 +0,0 @@
-//===-- Definition of EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL type ----------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_H
-#define LLVM_LIBC_TYPES_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-#include "EFI_STATUS.h"
-#include "size_t.h"
-
-#define EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID                                   \
-  {0x387477c2, 0x69c7, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}
-
-struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
-
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_RESET)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, bool ExtendedVerification);
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_STRING)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, const char16_t *String);
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_TEST_STRING)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, const char16_t *String);
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_QUERY_MODE)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, size_t ModeNumber,
-    size_t *Columns, size_t *Rows);
-
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_SET_MODE)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, size_t ModeNumber);
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_SET_ATTRIBUTE)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, size_t Attribute);
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_CLEAR_SCREEN)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This);
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_SET_CURSOR_POSITION)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, size_t Column, size_t Row);
-typedef EFI_STATUS(EFIAPI *EFI_TEXT_ENABLE_CURSOR)(
-    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, bool Visible);
-
-typedef struct {
-  int32_t MaxMode;
-  int32_t Mode;
-  int32_t Attribute;
-  int32_t CursorColumn;
-  int32_t CursorRow;
-  bool CursorVisible;
-} SIMPLE_TEXT_OUTPUT_MODE;
-
-typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
-  EFI_TEXT_RESET Reset;
-  EFI_TEXT_STRING OutputString;
-  EFI_TEXT_TEST_STRING TestString;
-  EFI_TEXT_QUERY_MODE QueryMode;
-  EFI_TEXT_SET_MODE SetMode;
-  EFI_TEXT_SET_ATTRIBUTE SetAttribute;
-  EFI_TEXT_CLEAR_SCREEN ClearScreen;
-  EFI_TEXT_SET_CURSOR_POSITION SetCursorPosition;
-  EFI_TEXT_ENABLE_CURSOR EnableCursor;
-  SIMPLE_TEXT_OUTPUT_MODE *Mode;
-} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
-
-#endif // LLVM_LIBC_TYPES_EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_H
diff --git a/include/llvm-libc-types/EFI_STATUS.h b/include/llvm-libc-types/EFI_STATUS.h
deleted file mode 100644
index f7fa6e5..0000000
--- a/include/llvm-libc-types/EFI_STATUS.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of EFI_STATUS type ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_STATUS_H
-#define LLVM_LIBC_TYPES_EFI_STATUS_H
-
-#include "size_t.h"
-
-typedef size_t EFI_STATUS;
-
-#endif // LLVM_LIBC_TYPES_EFI_STATUS_H
diff --git a/include/llvm-libc-types/EFI_SYSTEM_TABLE.h b/include/llvm-libc-types/EFI_SYSTEM_TABLE.h
deleted file mode 100644
index 290067a..0000000
--- a/include/llvm-libc-types/EFI_SYSTEM_TABLE.h
+++ /dev/null
@@ -1,65 +0,0 @@
-//===-- Definition of EFI_SYSTEM_TABLE type -------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===---------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_SYSTEM_TABLE_H
-#define LLVM_LIBC_TYPES_EFI_SYSTEM_TABLE_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-#include "EFI_BOOT_SERVICES.h"
-#include "EFI_CONFIGURATION_TABLE.h"
-#include "EFI_HANDLE.h"
-#include "EFI_RUNTIME_SERVICES.h"
-#include "EFI_SIMPLE_TEXT_INPUT_PROTOCOL.h"
-#include "EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.h"
-#include "EFI_STATUS.h"
-#include "EFI_TABLE_HEADER.h"
-
-#include "char16_t.h"
-#include "size_t.h"
-
-#define EFI_SYSTEM_TABLE_SIGNATURE 0x5453595320494249
-#define EFI_2_100_SYSTEM_TABLE_REVISION ((2 << 16) | (100))
-#define EFI_2_90_SYSTEM_TABLE_REVISION ((2 << 16) | (90))
-#define EFI_2_80_SYSTEM_TABLE_REVISION ((2 << 16) | (80))
-#define EFI_2_70_SYSTEM_TABLE_REVISION ((2 << 16) | (70))
-#define EFI_2_60_SYSTEM_TABLE_REVISION ((2 << 16) | (60))
-#define EFI_2_50_SYSTEM_TABLE_REVISION ((2 << 16) | (50))
-#define EFI_2_40_SYSTEM_TABLE_REVISION ((2 << 16) | (40))
-#define EFI_2_31_SYSTEM_TABLE_REVISION ((2 << 16) | (31))
-#define EFI_2_30_SYSTEM_TABLE_REVISION ((2 << 16) | (30))
-#define EFI_2_20_SYSTEM_TABLE_REVISION ((2 << 16) | (20))
-#define EFI_2_10_SYSTEM_TABLE_REVISION ((2 << 16) | (10))
-#define EFI_2_00_SYSTEM_TABLE_REVISION ((2 << 16) | (00))
-#define EFI_1_10_SYSTEM_TABLE_REVISION ((1 << 16) | (10))
-#define EFI_1_02_SYSTEM_TABLE_REVISION ((1 << 16) | (02))
-#define EFI_SPECIFICATION_VERSION EFI_SYSTEM_TABLE_REVISION
-#define EFI_SYSTEM_TABLE_REVISION EFI_2_100_SYSTEM_TABLE_REVISION
-
-typedef struct {
-  EFI_TABLE_HEADER Hdr;
-
-  char16_t *FirmwareVendor;
-  uint32_t FirmwareRevision;
-
-  EFI_HANDLE ConsoleInHandle;
-  EFI_SIMPLE_TEXT_INPUT_PROTOCOL *ConIn;
-
-  EFI_HANDLE ConsoleOutHandle;
-  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
-
-  EFI_HANDLE StandardErrorHandle;
-  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
-
-  EFI_RUNTIME_SERVICES *RuntimeServices;
-  EFI_BOOT_SERVICES *BootServices;
-
-  size_t NumberOfTableEntries;
-  EFI_CONFIGURATION_TABLE *ConfigurationTable;
-} EFI_SYSTEM_TABLE;
-
-#endif // LLVM_LIBC_TYPES_EFI_SYSTEM_TABLE_H
diff --git a/include/llvm-libc-types/EFI_TABLE_HEADER.h b/include/llvm-libc-types/EFI_TABLE_HEADER.h
deleted file mode 100644
index 293968e..0000000
--- a/include/llvm-libc-types/EFI_TABLE_HEADER.h
+++ /dev/null
@@ -1,22 +0,0 @@
-//===-- Definition of EFI_TABLE_HEADER type -------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===---------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_TABLE_HEADER_H
-#define LLVM_LIBC_TYPES_EFI_TABLE_HEADER_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-
-typedef struct {
-  uint64_t Signature;
-  uint32_t Revision;
-  uint32_t HeaderSize;
-  uint32_t CRC32;
-  uint32_t Reserved;
-} EFI_TABLE_HEADER;
-
-#endif // LLVM_LIBC_TYPES_EFI_TABLE_HEADER_H
diff --git a/include/llvm-libc-types/EFI_TIME.h b/include/llvm-libc-types/EFI_TIME.h
deleted file mode 100644
index b0e38b9..0000000
--- a/include/llvm-libc-types/EFI_TIME.h
+++ /dev/null
@@ -1,37 +0,0 @@
-//===-- Definition of EFI_TIME type ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_TIME_H
-#define LLVM_LIBC_TYPES_EFI_TIME_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-
-typedef struct {
-  uint16_t Year;  // 1900 - 9999
-  uint8_t Month;  // 1 - 12
-  uint8_t Day;    // 1 - 31
-  uint8_t Hour;   // 0 - 23
-  uint8_t Minute; // 0 - 59
-  uint8_t Second; // 0 - 59
-  uint8_t Pad1;
-  uint32_t Nanosecond; // 0 - 999,999,999
-  int16_t TimeZone;    // --1440 to 1440 or 2047
-} EFI_TIME;
-
-#define EFI_TIME_ADJUST_DAYLIGHT 0x01
-#define EFI_TIME_IN_DAYLIGHT 0x02
-
-#define EFI_UNSPECIFIED_TIMEZONE 0x07FF
-
-typedef struct {
-  uint32_t Resolution;
-  uint32_t Accuracy;
-  bool SetsToZero;
-} EFI_TIME_CAPABILITIES;
-
-#endif // LLVM_LIBC_TYPES_EFI_TIME_H
diff --git a/include/llvm-libc-types/EFI_TPL.h b/include/llvm-libc-types/EFI_TPL.h
deleted file mode 100644
index 8361ccf..0000000
--- a/include/llvm-libc-types/EFI_TPL.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of EFI_TPL type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_TPL_H
-#define LLVM_LIBC_TYPES_EFI_TPL_H
-
-#include "size_t.h"
-
-typedef size_t EFI_TPL;
-
-#define TPL_APPLICATION 4
-#define TPL_CALLBACK 8
-#define TPL_NOTIFY 16
-#define TPL_HIGH_LEVEL 31
-
-#endif // LLVM_LIBC_TYPES_EFI_TPL_H
diff --git a/include/llvm-libc-types/EFI_VIRTUAL_ADDRESS.h b/include/llvm-libc-types/EFI_VIRTUAL_ADDRESS.h
deleted file mode 100644
index 46cbec7..0000000
--- a/include/llvm-libc-types/EFI_VIRTUAL_ADDRESS.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of EFI_VIRTUAL_ADDRESS type ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_EFI_VIRTUAL_ADDRESS_H
-#define LLVM_LIBC_TYPES_EFI_VIRTUAL_ADDRESS_H
-
-#include "../llvm-libc-macros/stdint-macros.h"
-
-typedef uint64_t EFI_VIRTUAL_ADDRESS;
-
-#endif // LLVM_LIBC_TYPES_EFI_VIRTUAL_ADDRESS_H
diff --git a/include/llvm-libc-types/__atexithandler_t.h b/include/llvm-libc-types/__atexithandler_t.h
deleted file mode 100644
index 01aed67..0000000
--- a/include/llvm-libc-types/__atexithandler_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __atexithandler_t ------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___ATEXITHANDLER_T_H
-#define LLVM_LIBC_TYPES___ATEXITHANDLER_T_H
-
-typedef void (*__atexithandler_t)(void);
-
-#endif // LLVM_LIBC_TYPES___ATEXITHANDLER_T_H
diff --git a/include/llvm-libc-types/__atfork_callback_t.h b/include/llvm-libc-types/__atfork_callback_t.h
deleted file mode 100644
index ae2d0ca..0000000
--- a/include/llvm-libc-types/__atfork_callback_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __atfork_callback_t ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___ATFORK_CALLBACK_T_H
-#define LLVM_LIBC_TYPES___ATFORK_CALLBACK_T_H
-
-typedef void (*__atfork_callback_t)(void);
-
-#endif // LLVM_LIBC_TYPES___ATFORK_CALLBACK_T_H
diff --git a/include/llvm-libc-types/__bsearchcompare_t.h b/include/llvm-libc-types/__bsearchcompare_t.h
deleted file mode 100644
index 0b1987b..0000000
--- a/include/llvm-libc-types/__bsearchcompare_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __bsearchcompare_t -----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___BSEARCHCOMPARE_T_H
-#define LLVM_LIBC_TYPES___BSEARCHCOMPARE_T_H
-
-typedef int (*__bsearchcompare_t)(const void *, const void *);
-
-#endif // LLVM_LIBC_TYPES___BSEARCHCOMPARE_T_H
diff --git a/include/llvm-libc-types/__call_once_func_t.h b/include/llvm-libc-types/__call_once_func_t.h
deleted file mode 100644
index 6d278da..0000000
--- a/include/llvm-libc-types/__call_once_func_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of __call_once_func_t type -----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___CALL_ONCE_FUNC_T_H
-#define LLVM_LIBC_TYPES___CALL_ONCE_FUNC_T_H
-
-typedef void (*__call_once_func_t)(void);
-
-#endif // LLVM_LIBC_TYPES___CALL_ONCE_FUNC_T_H
diff --git a/include/llvm-libc-types/__dl_iterate_phdr_callback_t.h b/include/llvm-libc-types/__dl_iterate_phdr_callback_t.h
deleted file mode 100644
index 52078da..0000000
--- a/include/llvm-libc-types/__dl_iterate_phdr_callback_t.h
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Definition of type __dl_iterate_phdr_callback_t ------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===---------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___DL_ITERATE_PHDR_CALLBACK_T_H
-#define LLVM_LIBC_TYPES___DL_ITERATE_PHDR_CALLBACK_T_H
-
-#include "size_t.h"
-
-struct dl_phdr_info;
-
-typedef int (*__dl_iterate_phdr_callback_t)(struct dl_phdr_info *, size_t,
-                                            void *);
-
-#endif // LLVM_LIBC_TYPES___DL_ITERATE_PHDR_CALLBACK_T_H
diff --git a/include/llvm-libc-types/__exec_argv_t.h b/include/llvm-libc-types/__exec_argv_t.h
deleted file mode 100644
index 4eff583..0000000
--- a/include/llvm-libc-types/__exec_argv_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __exec_argv_t ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___EXEC_ARGV_T_H
-#define LLVM_LIBC_TYPES___EXEC_ARGV_T_H
-
-typedef char *const __exec_argv_t[];
-
-#endif // LLVM_LIBC_TYPES___EXEC_ARGV_T_H
diff --git a/include/llvm-libc-types/__exec_envp_t.h b/include/llvm-libc-types/__exec_envp_t.h
deleted file mode 100644
index 89e0275..0000000
--- a/include/llvm-libc-types/__exec_envp_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __exec_envp_t ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___EXEC_ENVP_T_H
-#define LLVM_LIBC_TYPES___EXEC_ENVP_T_H
-
-typedef char *const __exec_envp_t[];
-
-#endif // LLVM_LIBC_TYPES___EXEC_ENVP_T_H
diff --git a/include/llvm-libc-types/__futex_word.h b/include/llvm-libc-types/__futex_word.h
deleted file mode 100644
index 04023c7..0000000
--- a/include/llvm-libc-types/__futex_word.h
+++ /dev/null
@@ -1,20 +0,0 @@
-//===-- Definition of type which can represent a futex word ---------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___FUTEX_WORD_H
-#define LLVM_LIBC_TYPES___FUTEX_WORD_H
-
-typedef struct {
-  // Futex word should be aligned appropriately to allow target atomic
-  // instructions. This declaration mimics the internal setup.
-  _Alignas(sizeof(__UINT32_TYPE__) > _Alignof(__UINT32_TYPE__)
-               ? sizeof(__UINT32_TYPE__)
-               : _Alignof(__UINT32_TYPE__)) __UINT32_TYPE__ __word;
-} __futex_word;
-
-#endif // LLVM_LIBC_TYPES___FUTEX_WORD_H
diff --git a/include/llvm-libc-types/__getoptargv_t.h b/include/llvm-libc-types/__getoptargv_t.h
deleted file mode 100644
index c26b9e9..0000000
--- a/include/llvm-libc-types/__getoptargv_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __getoptargv_t ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___GETOPTARGV_T_H
-#define LLVM_LIBC_TYPES___GETOPTARGV_T_H
-
-typedef char *const __getoptargv_t[];
-
-#endif // LLVM_LIBC_TYPES___GETOPTARGV_T_H
diff --git a/include/llvm-libc-types/__lsearchcompare_t.h b/include/llvm-libc-types/__lsearchcompare_t.h
deleted file mode 100644
index 08dc2db..0000000
--- a/include/llvm-libc-types/__lsearchcompare_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __lsearchcompare_t -----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___LSEARCHCOMPARE_T_H
-#define LLVM_LIBC_TYPES___LSEARCHCOMPARE_T_H
-
-typedef int (*__lsearchcompare_t)(const void *, const void *);
-
-#endif // LLVM_LIBC_TYPES___LSEARCHCOMPARE_T_H
diff --git a/include/llvm-libc-types/__mutex_type.h b/include/llvm-libc-types/__mutex_type.h
deleted file mode 100644
index 8355616..0000000
--- a/include/llvm-libc-types/__mutex_type.h
+++ /dev/null
@@ -1,29 +0,0 @@
-//===-- Definition of a common mutex type ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___MUTEX_TYPE_H
-#define LLVM_LIBC_TYPES___MUTEX_TYPE_H
-
-#include "__futex_word.h"
-
-typedef struct {
-  unsigned char __timed;
-  unsigned char __recursive;
-  unsigned char __robust;
-
-  void *__owner;
-  unsigned long long __lock_count;
-
-#ifdef __linux__
-  __futex_word __ftxw;
-#else
-#error "Mutex type not defined for the target platform."
-#endif
-} __mutex_type;
-
-#endif // LLVM_LIBC_TYPES___MUTEX_TYPE_H
diff --git a/include/llvm-libc-types/__pthread_once_func_t.h b/include/llvm-libc-types/__pthread_once_func_t.h
deleted file mode 100644
index 7575029..0000000
--- a/include/llvm-libc-types/__pthread_once_func_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of __pthread_once_func_t type --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___PTHREAD_ONCE_FUNC_T_H
-#define LLVM_LIBC_TYPES___PTHREAD_ONCE_FUNC_T_H
-
-typedef void (*__pthread_once_func_t)(void);
-
-#endif // LLVM_LIBC_TYPES___PTHREAD_ONCE_FUNC_T_H
diff --git a/include/llvm-libc-types/__pthread_start_t.h b/include/llvm-libc-types/__pthread_start_t.h
deleted file mode 100644
index 6b7ae40..0000000
--- a/include/llvm-libc-types/__pthread_start_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of __pthread_start_t type ------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___PTHREAD_START_T_H
-#define LLVM_LIBC_TYPES___PTHREAD_START_T_H
-
-typedef void *(*__pthread_start_t)(void *);
-
-#endif // LLVM_LIBC_TYPES___PTHREAD_START_T_H
diff --git a/include/llvm-libc-types/__pthread_tss_dtor_t.h b/include/llvm-libc-types/__pthread_tss_dtor_t.h
deleted file mode 100644
index c67b604..0000000
--- a/include/llvm-libc-types/__pthread_tss_dtor_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of the type __pthread_tss_dtor_t -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___PTHREAD_TSS_DTOR_T_H
-#define LLVM_LIBC_TYPES___PTHREAD_TSS_DTOR_T_H
-
-typedef void (*__pthread_tss_dtor_t)(void *);
-
-#endif // LLVM_LIBC_TYPES___PTHREAD_TSS_DTOR_T_H
diff --git a/include/llvm-libc-types/__qsortcompare_t.h b/include/llvm-libc-types/__qsortcompare_t.h
deleted file mode 100644
index 48fc9cc..0000000
--- a/include/llvm-libc-types/__qsortcompare_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __qsortcompare_t -------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___QSORTCOMPARE_T_H
-#define LLVM_LIBC_TYPES___QSORTCOMPARE_T_H
-
-typedef int (*__qsortcompare_t)(const void *, const void *);
-
-#endif // LLVM_LIBC_TYPES___QSORTCOMPARE_T_H
diff --git a/include/llvm-libc-types/__qsortrcompare_t.h b/include/llvm-libc-types/__qsortrcompare_t.h
deleted file mode 100644
index f6b0588..0000000
--- a/include/llvm-libc-types/__qsortrcompare_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type __qsortrcompare_t ------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___QSORTRCOMPARE_T_H
-#define LLVM_LIBC_TYPES___QSORTRCOMPARE_T_H
-
-typedef int (*__qsortrcompare_t)(const void *, const void *, void *);
-
-#endif // LLVM_LIBC_TYPES___QSORTRCOMPARE_T_H
diff --git a/include/llvm-libc-types/__thread_type.h b/include/llvm-libc-types/__thread_type.h
deleted file mode 100644
index 645573f..0000000
--- a/include/llvm-libc-types/__thread_type.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of thrd_t type -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES___THREAD_TYPE_H
-#define LLVM_LIBC_TYPES___THREAD_TYPE_H
-
-typedef struct {
-  void *__attrib;
-} __thread_type;
-
-#endif // LLVM_LIBC_TYPES___THREAD_TYPE_H
diff --git a/include/llvm-libc-types/blkcnt_t.h b/include/llvm-libc-types/blkcnt_t.h
deleted file mode 100644
index 9dea8f0..0000000
--- a/include/llvm-libc-types/blkcnt_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of blkcnt_t type ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_BLKCNT_T_H
-#define LLVM_LIBC_TYPES_BLKCNT_T_H
-
-typedef __INTPTR_TYPE__ blkcnt_t;
-
-#endif // LLVM_LIBC_TYPES_BLKCNT_T_H
diff --git a/include/llvm-libc-types/blksize_t.h b/include/llvm-libc-types/blksize_t.h
deleted file mode 100644
index 7caa970..0000000
--- a/include/llvm-libc-types/blksize_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of blksize_t type --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_BLKSIZE_T_H
-#define LLVM_LIBC_TYPES_BLKSIZE_T_H
-
-typedef __INTPTR_TYPE__ blksize_t;
-
-#endif // LLVM_LIBC_TYPES_BLKSIZE_T_H
diff --git a/include/llvm-libc-types/char16_t.h b/include/llvm-libc-types/char16_t.h
deleted file mode 100644
index 1f5847a..0000000
--- a/include/llvm-libc-types/char16_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of char16_t type ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_CHAR16_T_H
-#define LLVM_LIBC_TYPES_CHAR16_T_H
-
-#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
-#include "../llvm-libc-macros/stdint-macros.h"
-typedef uint_least16_t char16_t;
-#endif
-
-#endif // LLVM_LIBC_TYPES_CHAR16_T_H
diff --git a/include/llvm-libc-types/char32_t.h b/include/llvm-libc-types/char32_t.h
deleted file mode 100644
index 20b72dc..0000000
--- a/include/llvm-libc-types/char32_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of char32_t type ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_CHAR32_T_H
-#define LLVM_LIBC_TYPES_CHAR32_T_H
-
-#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
-#include "../llvm-libc-macros/stdint-macros.h"
-typedef uint_least32_t char32_t;
-#endif
-
-#endif // LLVM_LIBC_TYPES_CHAR32_T_H
diff --git a/include/llvm-libc-types/char8_t.h b/include/llvm-libc-types/char8_t.h
deleted file mode 100644
index ddadab1..0000000
--- a/include/llvm-libc-types/char8_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of char8_t type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_CHAR8_T_H
-#define LLVM_LIBC_TYPES_CHAR8_T_H
-
-#if !defined(__cplusplus) && defined(__STDC_VERSION__) &&                      \
-    __STDC_VERSION__ >= 202311L
-typedef unsigned char char8_t;
-#endif
-
-#endif // LLVM_LIBC_TYPES_CHAR8_T_H
diff --git a/include/llvm-libc-types/clock_t.h b/include/llvm-libc-types/clock_t.h
deleted file mode 100644
index 8759ee9..0000000
--- a/include/llvm-libc-types/clock_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of clock_t type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_CLOCK_T_H
-#define LLVM_LIBC_TYPES_CLOCK_T_H
-
-typedef long clock_t;
-
-#endif // LLVM_LIBC_TYPES_CLOCK_T_H
diff --git a/include/llvm-libc-types/clockid_t.h b/include/llvm-libc-types/clockid_t.h
deleted file mode 100644
index 4b05959..0000000
--- a/include/llvm-libc-types/clockid_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of the type clockid_t ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_CLOCKID_T_H
-#define LLVM_LIBC_TYPES_CLOCKID_T_H
-
-typedef int clockid_t;
-
-#endif // LLVM_LIBC_TYPES_CLOCKID_T_H
diff --git a/include/llvm-libc-types/cookie_io_functions_t.h b/include/llvm-libc-types/cookie_io_functions_t.h
deleted file mode 100644
index d1eea8f..0000000
--- a/include/llvm-libc-types/cookie_io_functions_t.h
+++ /dev/null
@@ -1,28 +0,0 @@
-//===-- Definition of type cookie_io_functions_t --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_COOKIE_IO_FUNCTIONS_T_H
-#define LLVM_LIBC_TYPES_COOKIE_IO_FUNCTIONS_T_H
-
-#include "off64_t.h"
-#include "size_t.h"
-#include "ssize_t.h"
-
-typedef ssize_t cookie_read_function_t(void *, char *, size_t);
-typedef ssize_t cookie_write_function_t(void *, const char *, size_t);
-typedef int cookie_seek_function_t(void *, off64_t *, int);
-typedef int cookie_close_function_t(void *);
-
-typedef struct {
-  cookie_read_function_t *read;
-  cookie_write_function_t *write;
-  cookie_seek_function_t *seek;
-  cookie_close_function_t *close;
-} cookie_io_functions_t;
-
-#endif // LLVM_LIBC_TYPES_COOKIE_IO_FUNCTIONS_T_H
diff --git a/include/llvm-libc-types/cpu_set_t.h b/include/llvm-libc-types/cpu_set_t.h
deleted file mode 100644
index 8c6859d..0000000
--- a/include/llvm-libc-types/cpu_set_t.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of a cpu_set_t type ------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_CPU_SET_T_H
-#define LLVM_LIBC_TYPES_CPU_SET_T_H
-
-#define __CPU_SETSIZE 1024
-#define __NCPUBITS (8 * sizeof(unsigned long))
-
-typedef struct {
-  // If a processor with more than 1024 CPUs is to be supported in future,
-  // we need to adjust the size of this array.
-  unsigned long __mask[128 / sizeof(unsigned long)];
-} cpu_set_t;
-
-#endif // LLVM_LIBC_TYPES_CPU_SET_T_H
diff --git a/include/llvm-libc-types/dev_t.h b/include/llvm-libc-types/dev_t.h
deleted file mode 100644
index 3181e34..0000000
--- a/include/llvm-libc-types/dev_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of dev_t type ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_DEV_T_H
-#define LLVM_LIBC_TYPES_DEV_T_H
-
-typedef __UINT64_TYPE__ dev_t;
-
-#endif // LLVM_LIBC_TYPES_DEV_T_H
diff --git a/include/llvm-libc-types/div_t.h b/include/llvm-libc-types/div_t.h
deleted file mode 100644
index 450603d..0000000
--- a/include/llvm-libc-types/div_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of type div_t ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_DIV_T_H
-#define LLVM_LIBC_TYPES_DIV_T_H
-
-typedef struct {
-  int quot;
-  int rem;
-} div_t;
-
-#endif // LLVM_LIBC_TYPES_DIV_T_H
diff --git a/include/llvm-libc-types/double_t.h b/include/llvm-libc-types/double_t.h
deleted file mode 100644
index c4ad08a..0000000
--- a/include/llvm-libc-types/double_t.h
+++ /dev/null
@@ -1,24 +0,0 @@
-//===-- Definition of double_t type ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_DOUBLE_T_H
-#define LLVM_LIBC_TYPES_DOUBLE_T_H
-
-#if !defined(__FLT_EVAL_METHOD__) || __FLT_EVAL_METHOD__ == 0
-#define __LLVM_LIBC_DOUBLE_T double
-#elif __FLT_EVAL_METHOD__ == 1
-#define __LLVM_LIBC_DOUBLE_T double
-#elif __FLT_EVAL_METHOD__ == 2
-#define __LLVM_LIBC_DOUBLE_T long double
-#else
-#error "Unsupported __FLT_EVAL_METHOD__ value."
-#endif
-
-typedef __LLVM_LIBC_DOUBLE_T double_t;
-
-#endif // LLVM_LIBC_TYPES_DOUBLE_T_H
diff --git a/include/llvm-libc-types/fd_set.h b/include/llvm-libc-types/fd_set.h
deleted file mode 100644
index 52b7161..0000000
--- a/include/llvm-libc-types/fd_set.h
+++ /dev/null
@@ -1,18 +0,0 @@
-//===-- Definition of fd_set type -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_FD_SET_H
-#define LLVM_LIBC_TYPES_FD_SET_H
-
-#include "../llvm-libc-macros/sys-select-macros.h" // __FD_SET_WORD_TYPE, __FD_SET_ARRAYSIZE
-
-typedef struct {
-  __FD_SET_WORD_TYPE __set[__FD_SET_ARRAYSIZE];
-} fd_set;
-
-#endif // LLVM_LIBC_TYPES_FD_SET_H
diff --git a/include/llvm-libc-types/fenv_t.h b/include/llvm-libc-types/fenv_t.h
deleted file mode 100644
index c83f238..0000000
--- a/include/llvm-libc-types/fenv_t.h
+++ /dev/null
@@ -1,36 +0,0 @@
-//===-- Definition of type fenv_t -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_FENV_T_H
-#define LLVM_LIBC_TYPES_FENV_T_H
-
-#ifdef __aarch64__
-typedef struct {
-  unsigned char __control_word[4];
-  unsigned char __status_word[4];
-} fenv_t;
-#elif defined(__x86_64__)
-typedef struct {
-  unsigned char __x86_status[28];
-  unsigned char __mxcsr[4];
-} fenv_t;
-#elif defined(__arm__) || defined(_M_ARM)
-typedef struct {
-  unsigned int __fpscr;
-} fenv_t;
-#elif defined(__riscv)
-typedef unsigned int fenv_t;
-#elif defined(__AMDGPU__) || defined(__NVPTX__)
-typedef struct {
-  unsigned int __fpc;
-} fenv_t;
-#else
-#error "fenv_t not defined for your platform"
-#endif
-
-#endif // LLVM_LIBC_TYPES_FENV_T_H
diff --git a/include/llvm-libc-types/fexcept_t.h b/include/llvm-libc-types/fexcept_t.h
deleted file mode 100644
index 5aa09fb..0000000
--- a/include/llvm-libc-types/fexcept_t.h
+++ /dev/null
@@ -1,18 +0,0 @@
-//===-- Definition of fexcept_t type --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_FEXCEPT_T_H
-#define LLVM_LIBC_TYPES_FEXCEPT_T_H
-
-#if defined(__x86_64__) || defined(__i386__)
-typedef unsigned short int fexcept_t;
-#else
-typedef unsigned int fexcept_t;
-#endif
-
-#endif // LLVM_LIBC_TYPES_FEXCEPT_T_H
diff --git a/include/llvm-libc-types/float_t.h b/include/llvm-libc-types/float_t.h
deleted file mode 100644
index 5027249..0000000
--- a/include/llvm-libc-types/float_t.h
+++ /dev/null
@@ -1,24 +0,0 @@
-//===-- Definition of float_t type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_FLOAT_T_H
-#define LLVM_LIBC_TYPES_FLOAT_T_H
-
-#if !defined(__FLT_EVAL_METHOD__) || __FLT_EVAL_METHOD__ == 0
-#define __LLVM_LIBC_FLOAT_T float
-#elif __FLT_EVAL_METHOD__ == 1
-#define __LLVM_LIBC_FLOAT_T double
-#elif __FLT_EVAL_METHOD__ == 2
-#define __LLVM_LIBC_FLOAT_T long double
-#else
-#error "Unsupported __FLT_EVAL_METHOD__ value."
-#endif
-
-typedef __LLVM_LIBC_FLOAT_T float_t;
-
-#endif // LLVM_LIBC_TYPES_FLOAT_T_H
diff --git a/include/llvm-libc-types/fsblkcnt_t.h b/include/llvm-libc-types/fsblkcnt_t.h
deleted file mode 100644
index 8c7d330..0000000
--- a/include/llvm-libc-types/fsblkcnt_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of fsblkcnt_t type -------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_FSBLKCNT_T_H
-#define LLVM_LIBC_TYPES_FSBLKCNT_T_H
-
-typedef __UINT64_TYPE__ fsblkcnt_t;
-
-#endif // LLVM_LIBC_TYPES_FSBLKCNT_T_H
diff --git a/include/llvm-libc-types/fsfilcnt_t.h b/include/llvm-libc-types/fsfilcnt_t.h
deleted file mode 100644
index 1269783..0000000
--- a/include/llvm-libc-types/fsfilcnt_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of fsfilcnt_t type -------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_FSFILCNT_T_H
-#define LLVM_LIBC_TYPES_FSFILCNT_T_H
-
-typedef __UINT64_TYPE__ fsfilcnt_t;
-
-#endif // LLVM_LIBC_TYPES_FSFILCNT_T_H
diff --git a/include/llvm-libc-types/gid_t.h b/include/llvm-libc-types/gid_t.h
deleted file mode 100644
index cfe36ce..0000000
--- a/include/llvm-libc-types/gid_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of gid_t type ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_GID_T_H
-#define LLVM_LIBC_TYPES_GID_T_H
-
-typedef __UINT32_TYPE__ gid_t;
-
-#endif // LLVM_LIBC_TYPES_GID_T_H
diff --git a/include/llvm-libc-types/imaxdiv_t.h b/include/llvm-libc-types/imaxdiv_t.h
deleted file mode 100644
index 5062b64..0000000
--- a/include/llvm-libc-types/imaxdiv_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of type imaxdiv_t --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef __LLVM_LIBC_TYPES_IMAXDIV_T_H__
-#define __LLVM_LIBC_TYPES_IMAXDIV_T_H__
-
-typedef struct {
-  intmax_t quot;
-  intmax_t rem;
-} imaxdiv_t;
-
-#endif // __LLVM_LIBC_TYPES_IMAXDIV_T_H__
diff --git a/include/llvm-libc-types/ino_t.h b/include/llvm-libc-types/ino_t.h
deleted file mode 100644
index 148bd67..0000000
--- a/include/llvm-libc-types/ino_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of ino_t type ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_INO_T_H
-#define LLVM_LIBC_TYPES_INO_T_H
-
-typedef __UINTPTR_TYPE__ ino_t;
-
-#endif // LLVM_LIBC_TYPES_INO_T_H
diff --git a/include/llvm-libc-types/jmp_buf.h b/include/llvm-libc-types/jmp_buf.h
deleted file mode 100644
index f246e64..0000000
--- a/include/llvm-libc-types/jmp_buf.h
+++ /dev/null
@@ -1,57 +0,0 @@
-//===-- Definition of type jmp_buf ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_JMP_BUF_H
-#define LLVM_LIBC_TYPES_JMP_BUF_H
-
-typedef struct {
-#ifdef __x86_64__
-  __UINT64_TYPE__ rbx;
-  __UINT64_TYPE__ rbp;
-  __UINT64_TYPE__ r12;
-  __UINT64_TYPE__ r13;
-  __UINT64_TYPE__ r14;
-  __UINT64_TYPE__ r15;
-  __UINTPTR_TYPE__ rsp;
-  __UINTPTR_TYPE__ rip;
-#elif defined(__i386__)
-  long ebx;
-  long esi;
-  long edi;
-  long ebp;
-  long esp;
-  long eip;
-#elif defined(__riscv)
-  /* Program counter.  */
-  long int __pc;
-  /* Callee-saved registers.  */
-  long int __regs[12];
-  /* Stack pointer.  */
-  long int __sp;
-  /* Callee-saved floating point registers.  */
-#if __riscv_float_abi_double
-  double __fpregs[12];
-#elif defined(__riscv_float_abi_single)
-#error "__jmp_buf not available for your target architecture."
-#endif
-#elif defined(__arm__)
-  // r4, r5, r6, r7, r8, r9, r10, r11, r12, lr
-  long opaque[10];
-#elif defined(__aarch64__)
-  long opaque[14]; // x19-x29, lr, sp, optional x18
-#if __ARM_FP
-  long fopaque[8]; // d8-d15
-#endif
-#else
-#error "__jmp_buf not available for your target architecture."
-#endif
-} __jmp_buf;
-
-typedef __jmp_buf jmp_buf[1];
-
-#endif // LLVM_LIBC_TYPES_JMP_BUF_H
diff --git a/include/llvm-libc-types/ldiv_t.h b/include/llvm-libc-types/ldiv_t.h
deleted file mode 100644
index 5c64ec1..0000000
--- a/include/llvm-libc-types/ldiv_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of type ldiv_t -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_LDIV_T_H
-#define LLVM_LIBC_TYPES_LDIV_T_H
-
-typedef struct {
-  long quot;
-  long rem;
-} ldiv_t;
-
-#endif // LLVM_LIBC_TYPES_LDIV_T_H
diff --git a/include/llvm-libc-types/lldiv_t.h b/include/llvm-libc-types/lldiv_t.h
deleted file mode 100644
index 5b8dcbe..0000000
--- a/include/llvm-libc-types/lldiv_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of type lldiv_t ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_LLDIV_T_H
-#define LLVM_LIBC_TYPES_LLDIV_T_H
-
-typedef struct {
-  long long quot;
-  long long rem;
-} lldiv_t;
-
-#endif // LLVM_LIBC_TYPES_LLDIV_T_H
diff --git a/include/llvm-libc-types/locale_t.h b/include/llvm-libc-types/locale_t.h
deleted file mode 100644
index 6d78300..0000000
--- a/include/llvm-libc-types/locale_t.h
+++ /dev/null
@@ -1,22 +0,0 @@
-//===-- Definition of type locale_t ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_LOCALE_T_H
-#define LLVM_LIBC_TYPES_LOCALE_T_H
-
-#define NUM_LOCALE_CATEGORIES 6
-
-struct __locale_data;
-
-struct __locale_t {
-  struct __locale_data *data[NUM_LOCALE_CATEGORIES];
-};
-
-typedef struct __locale_t *locale_t;
-
-#endif // LLVM_LIBC_TYPES_LOCALE_T_H
diff --git a/include/llvm-libc-types/mbstate_t.h b/include/llvm-libc-types/mbstate_t.h
deleted file mode 100644
index 540d509..0000000
--- a/include/llvm-libc-types/mbstate_t.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of mbstate_t type --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_MBSTATE_T_H
-#define LLVM_LIBC_TYPES_MBSTATE_T_H
-
-// TODO: Complete this once we implement functions that operate on this type.
-typedef struct {
-} mbstate_t;
-
-#endif // LLVM_LIBC_TYPES_MBSTATE_T_H
diff --git a/include/llvm-libc-types/mode_t.h b/include/llvm-libc-types/mode_t.h
deleted file mode 100644
index fe09060..0000000
--- a/include/llvm-libc-types/mode_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of mode_t type -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_MODE_T_H
-#define LLVM_LIBC_TYPES_MODE_T_H
-
-typedef unsigned mode_t;
-
-#endif // LLVM_LIBC_TYPES_MODE_T_H
diff --git a/include/llvm-libc-types/mtx_t.h b/include/llvm-libc-types/mtx_t.h
deleted file mode 100644
index 56e41bd..0000000
--- a/include/llvm-libc-types/mtx_t.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of mtx_t type ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_MTX_T_H
-#define LLVM_LIBC_TYPES_MTX_T_H
-
-#include "__mutex_type.h"
-
-typedef __mutex_type mtx_t;
-
-#endif // LLVM_LIBC_TYPES_MTX_T_H
diff --git a/include/llvm-libc-types/nfds_t.h b/include/llvm-libc-types/nfds_t.h
deleted file mode 100644
index c0abcce..0000000
--- a/include/llvm-libc-types/nfds_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type nfds_t -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_NFDS_T_H
-#define LLVM_LIBC_TYPES_NFDS_T_H
-
-typedef unsigned int nfds_t;
-
-#endif // LLVM_LIBC_TYPES_NFDS_T_H
diff --git a/include/llvm-libc-types/nlink_t.h b/include/llvm-libc-types/nlink_t.h
deleted file mode 100644
index 7e0016a..0000000
--- a/include/llvm-libc-types/nlink_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of nlink_t type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_NLINK_T_H
-#define LLVM_LIBC_TYPES_NLINK_T_H
-
-typedef __UINTPTR_TYPE__ nlink_t;
-
-#endif // LLVM_LIBC_TYPES_NLINK_T_H
diff --git a/include/llvm-libc-types/off64_t.h b/include/llvm-libc-types/off64_t.h
deleted file mode 100644
index 669698a..0000000
--- a/include/llvm-libc-types/off64_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of off64_t type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_OFF64_T_H
-#define LLVM_LIBC_TYPES_OFF64_T_H
-
-typedef __INT64_TYPE__ off64_t;
-
-#endif // LLVM_LIBC_TYPES_OFF64_T_H
diff --git a/include/llvm-libc-types/off_t.h b/include/llvm-libc-types/off_t.h
deleted file mode 100644
index 63224b6..0000000
--- a/include/llvm-libc-types/off_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of off_t type ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_OFF_T_H
-#define LLVM_LIBC_TYPES_OFF_T_H
-
-typedef __INT64_TYPE__ off_t;
-
-#endif // LLVM_LIBC_TYPES_OFF_T_H
diff --git a/include/llvm-libc-types/once_flag.h b/include/llvm-libc-types/once_flag.h
deleted file mode 100644
index b3b7e0d..0000000
--- a/include/llvm-libc-types/once_flag.h
+++ /dev/null
@@ -1,20 +0,0 @@
-//===-- Definition of once_flag type --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_ONCE_FLAG_H
-#define LLVM_LIBC_TYPES_ONCE_FLAG_H
-
-#include "__futex_word.h"
-
-#ifdef __linux__
-typedef __futex_word once_flag;
-#else
-#error "Once flag type not defined for the target platform."
-#endif
-
-#endif // LLVM_LIBC_TYPES_ONCE_FLAG_H
diff --git a/include/llvm-libc-types/pid_t.h b/include/llvm-libc-types/pid_t.h
deleted file mode 100644
index 0397bd2..0000000
--- a/include/llvm-libc-types/pid_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of pid_t type ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PID_T_H
-#define LLVM_LIBC_TYPES_PID_T_H
-
-typedef __INT32_TYPE__ pid_t;
-
-#endif // LLVM_LIBC_TYPES_PID_T_H
diff --git a/include/llvm-libc-types/posix_spawn_file_actions_t.h b/include/llvm-libc-types/posix_spawn_file_actions_t.h
deleted file mode 100644
index 3062da3..0000000
--- a/include/llvm-libc-types/posix_spawn_file_actions_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of type posix_spawn_file_actions_t ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_POSIX_SPAWN_FILE_ACTIONS_T_H
-#define LLVM_LIBC_TYPES_POSIX_SPAWN_FILE_ACTIONS_T_H
-
-typedef struct {
-  void *__front;
-  void *__back;
-} posix_spawn_file_actions_t;
-
-#endif // LLVM_LIBC_TYPES_POSIX_SPAWN_FILE_ACTIONS_T_H
diff --git a/include/llvm-libc-types/posix_spawnattr_t.h b/include/llvm-libc-types/posix_spawnattr_t.h
deleted file mode 100644
index 47cadc7..0000000
--- a/include/llvm-libc-types/posix_spawnattr_t.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of type posix_spawn_file_actions_t ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_POSIX_SPAWNATTR_T_H
-#define LLVM_LIBC_TYPES_POSIX_SPAWNATTR_T_H
-
-typedef struct {
-  // This data structure will be populated as required.
-} posix_spawnattr_t;
-
-#endif // LLVM_LIBC_TYPES_POSIX_SPAWNATTR_T_H
diff --git a/include/llvm-libc-types/pthread_attr_t.h b/include/llvm-libc-types/pthread_attr_t.h
deleted file mode 100644
index e686ac9..0000000
--- a/include/llvm-libc-types/pthread_attr_t.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of pthread_attr_t type ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PTHREAD_ATTR_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_ATTR_T_H
-
-#include "size_t.h"
-
-typedef struct {
-  int __detachstate;
-  void *__stack;
-  size_t __stacksize;
-  size_t __guardsize;
-} pthread_attr_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_ATTR_T_H
diff --git a/include/llvm-libc-types/pthread_condattr_t.h b/include/llvm-libc-types/pthread_condattr_t.h
deleted file mode 100644
index b91fc29..0000000
--- a/include/llvm-libc-types/pthread_condattr_t.h
+++ /dev/null
@@ -1,18 +0,0 @@
-//===-- Definition of pthread_condattr_t type -----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-#ifndef LLVM_LIBC_TYPES_PTHREAD_CONDATTR_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_CONDATTR_T_H
-
-#include "clockid_t.h"
-
-typedef struct {
-  clockid_t clock;
-  int pshared;
-} pthread_condattr_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_CONDATTR_T_H
diff --git a/include/llvm-libc-types/pthread_key_t.h b/include/llvm-libc-types/pthread_key_t.h
deleted file mode 100644
index e73c7e2..0000000
--- a/include/llvm-libc-types/pthread_key_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of the type pthread_key_t ------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PTHREAD_KEY_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_KEY_T_H
-
-typedef unsigned int pthread_key_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_KEY_T_H
diff --git a/include/llvm-libc-types/pthread_mutex_t.h b/include/llvm-libc-types/pthread_mutex_t.h
deleted file mode 100644
index 1535cba..0000000
--- a/include/llvm-libc-types/pthread_mutex_t.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of pthread_mutex_t type --------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PTHREAD_MUTEX_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_MUTEX_T_H
-
-#include "__mutex_type.h"
-
-typedef __mutex_type pthread_mutex_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_MUTEX_T_H
diff --git a/include/llvm-libc-types/pthread_mutexattr_t.h b/include/llvm-libc-types/pthread_mutexattr_t.h
deleted file mode 100644
index 8f159a6..0000000
--- a/include/llvm-libc-types/pthread_mutexattr_t.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of pthread_mutexattr_t type ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PTHREAD_MUTEXATTR_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_MUTEXATTR_T_H
-
-// pthread_mutexattr_t is a collection bit mapped flags. The mapping is internal
-// detail of the libc implementation.
-typedef unsigned int pthread_mutexattr_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_MUTEXATTR_T_H
diff --git a/include/llvm-libc-types/pthread_once_t.h b/include/llvm-libc-types/pthread_once_t.h
deleted file mode 100644
index 12a8150..0000000
--- a/include/llvm-libc-types/pthread_once_t.h
+++ /dev/null
@@ -1,20 +0,0 @@
-//===-- Definition of pthread_once_t type ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PTHREAD_ONCE_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_ONCE_T_H
-
-#include "__futex_word.h"
-
-#ifdef __linux__
-typedef __futex_word pthread_once_t;
-#else
-#error "Once flag type not defined for the target platform."
-#endif
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_ONCE_T_H
diff --git a/include/llvm-libc-types/pthread_rwlock_t.h b/include/llvm-libc-types/pthread_rwlock_t.h
deleted file mode 100644
index 4a7c6c7..0000000
--- a/include/llvm-libc-types/pthread_rwlock_t.h
+++ /dev/null
@@ -1,26 +0,0 @@
-//===-- Definition of pthread_mutex_t type --------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PTHREAD_RWLOCK_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_RWLOCK_T_H
-
-#include "__futex_word.h"
-#include "pid_t.h"
-typedef struct {
-  unsigned __is_pshared : 1;
-  unsigned __preference : 1;
-  int __state;
-  pid_t __writer_tid;
-  __futex_word __wait_queue_mutex;
-  __futex_word __pending_readers;
-  __futex_word __pending_writers;
-  __futex_word __reader_serialization;
-  __futex_word __writer_serialization;
-} pthread_rwlock_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_RWLOCK_T_H
diff --git a/include/llvm-libc-types/pthread_rwlockattr_t.h b/include/llvm-libc-types/pthread_rwlockattr_t.h
deleted file mode 100644
index 397c844..0000000
--- a/include/llvm-libc-types/pthread_rwlockattr_t.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of pthread_rwlockattr_t type ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-#ifndef LLVM_LIBC_TYPES_PTHREAD_RWLOCKATTR_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_RWLOCKATTR_T_H
-
-typedef struct {
-  int pshared;
-  int pref;
-} pthread_rwlockattr_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_RWLOCKATTR_T_H
diff --git a/include/llvm-libc-types/pthread_spinlock_t.h b/include/llvm-libc-types/pthread_spinlock_t.h
deleted file mode 100644
index afb4fe9..0000000
--- a/include/llvm-libc-types/pthread_spinlock_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of pthread_spinlock_t type -----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PTHREAD_SPINLOCK_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_SPINLOCK_T_H
-#include "pid_t.h"
-typedef struct {
-  unsigned char __lockword;
-  pid_t __owner;
-} pthread_spinlock_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_SPINLOCK_T_H
diff --git a/include/llvm-libc-types/pthread_t.h b/include/llvm-libc-types/pthread_t.h
deleted file mode 100644
index f64887b..0000000
--- a/include/llvm-libc-types/pthread_t.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of pthread_t type --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_PTHREAD_T_H
-#define LLVM_LIBC_TYPES_PTHREAD_T_H
-
-#include "__thread_type.h"
-
-typedef __thread_type pthread_t;
-
-#endif // LLVM_LIBC_TYPES_PTHREAD_T_H
diff --git a/include/llvm-libc-types/rlim_t.h b/include/llvm-libc-types/rlim_t.h
deleted file mode 100644
index 016ec7b..0000000
--- a/include/llvm-libc-types/rlim_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of type rlim_t -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_RLIM_T_H
-#define LLVM_LIBC_TYPES_RLIM_T_H
-
-typedef __UINT64_TYPE__ rlim_t;
-
-#endif // LLVM_LIBC_TYPES_RLIM_T_H
diff --git a/include/llvm-libc-types/sa_family_t.h b/include/llvm-libc-types/sa_family_t.h
deleted file mode 100644
index 0a010b6..0000000
--- a/include/llvm-libc-types/sa_family_t.h
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Definition of sa_family_t type ------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SA_FAMILY_T_H
-#define LLVM_LIBC_TYPES_SA_FAMILY_T_H
-
-// The posix standard only says of sa_family_t that it must be unsigned. The
-// linux man page for "address_families" lists approximately 32 different
-// address families, meaning that a short 16 bit number will have plenty of
-// space for all of them.
-
-typedef unsigned short sa_family_t;
-
-#endif // LLVM_LIBC_TYPES_SA_FAMILY_T_H
diff --git a/include/llvm-libc-types/sig_atomic_t.h b/include/llvm-libc-types/sig_atomic_t.h
deleted file mode 100644
index 2ef3758..0000000
--- a/include/llvm-libc-types/sig_atomic_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of sig_atomic_t type -----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SIG_ATOMIC_T_H
-#define LLVM_LIBC_TYPES_SIG_ATOMIC_T_H
-
-typedef int sig_atomic_t;
-
-#endif // LLVM_LIBC_TYPES_SIG_ATOMIC_T_H
diff --git a/include/llvm-libc-types/sighandler_t.h b/include/llvm-libc-types/sighandler_t.h
deleted file mode 100644
index f39ab04..0000000
--- a/include/llvm-libc-types/sighandler_t.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of sighandler_t ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SIGHANDLER_T_H
-#define LLVM_LIBC_TYPES_SIGHANDLER_T_H
-
-#ifdef __linux__
-// For compatibility with glibc.
-typedef void (*sighandler_t)(int);
-#endif
-
-#endif // LLVM_LIBC_TYPES_SIGHANDLER_T_H
diff --git a/include/llvm-libc-types/siginfo_t.h b/include/llvm-libc-types/siginfo_t.h
deleted file mode 100644
index 20fdd46..0000000
--- a/include/llvm-libc-types/siginfo_t.h
+++ /dev/null
@@ -1,109 +0,0 @@
-//===-- Definition of siginfo_t type --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SIGINFO_T_H
-#define LLVM_LIBC_TYPES_SIGINFO_T_H
-
-#include "clock_t.h"
-#include "pid_t.h"
-#include "uid_t.h"
-#include "union_sigval.h"
-
-#define SI_MAX_SIZE 128
-
-typedef struct {
-  int si_signo; /* Signal number.  */
-  int si_errno; /* If non-zero, an errno value associated with
-                   this signal, as defined in <errno.h>.  */
-  int si_code;  /* Signal code.  */
-  union {
-    int _si_pad[SI_MAX_SIZE / sizeof(int)];
-
-    /* kill() */
-    struct {
-      pid_t si_pid; /* sender's pid */
-      uid_t si_uid; /* sender's uid */
-    } _kill;
-
-    /* POSIX.1b timers */
-    struct {
-      int si_tid;             /* timer id */
-      int _overrun;           /* overrun count */
-      union sigval si_sigval; /* same as below */
-    } _timer;
-
-    /* POSIX.1b signals */
-    struct {
-      pid_t si_pid; /* sender's pid */
-      uid_t si_uid; /* sender's uid */
-      union sigval si_sigval;
-    } _rt;
-
-    /* SIGCHLD */
-    struct {
-      pid_t si_pid;  /* which child */
-      uid_t si_uid;  /* sender's uid */
-      int si_status; /* exit code */
-      clock_t si_utime;
-      clock_t si_stime;
-    } _sigchld;
-
-    /* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
-    struct {
-      void *si_addr;         /* faulting insn/memory ref. */
-      short int si_addr_lsb; /* Valid LSB of the reported address.  */
-      union {
-        /* used when si_code=SEGV_BNDERR */
-        struct {
-          void *_lower;
-          void *_upper;
-        } _addr_bnd;
-        /* used when si_code=SEGV_PKUERR */
-        __UINT32_TYPE__ _pkey;
-      } _bounds;
-    } _sigfault;
-
-    /* SIGPOLL */
-    struct {
-      long int si_band; /* POLL_IN, POLL_OUT, POLL_MSG */
-      int si_fd;
-    } _sigpoll;
-
-    /* SIGSYS */
-    struct {
-      void *_call_addr;   /* calling user insn */
-      int _syscall;       /* triggering system call number */
-      unsigned int _arch; /* AUDIT_ARCH_* of syscall */
-    } _sigsys;
-  } _sifields;
-} siginfo_t;
-
-#undef SI_MAX_SIZE
-
-#define si_pid _sifields._kill.si_pid
-#define si_uid _sifields._kill.si_uid
-#define si_timerid _sifields._timer.si_tid
-#define si_overrun _sifields._timer.si_overrun
-#define si_status _sifields._sigchld.si_status
-#define si_utime _sifields._sigchld.si_utime
-#define si_stime _sifields._sigchld.si_stime
-#define si_value _sifields._rt.si_sigval
-#define si_int _sifields._rt.si_sigval.sival_int
-#define si_ptr _sifields._rt.si_sigval.sival_ptr
-#define si_addr _sifields._sigfault.si_addr
-#define si_addr_lsb _sifields._sigfault.si_addr_lsb
-#define si_lower _sifields._sigfault._bounds._addr_bnd._lower
-#define si_upper _sifields._sigfault._bounds._addr_bnd._upper
-#define si_pkey _sifields._sigfault._bounds._pkey
-#define si_band _sifields._sigpoll.si_band
-#define si_fd _sifields._sigpoll.si_fd
-#define si_call_addr _sifields._sigsys._call_addr
-#define si_syscall _sifields._sigsys._syscall
-#define si_arch _sifields._sigsys._arch
-
-#endif // LLVM_LIBC_TYPES_SIGINFO_T_H
diff --git a/include/llvm-libc-types/sigset_t.h b/include/llvm-libc-types/sigset_t.h
deleted file mode 100644
index 8c4d3b4..0000000
--- a/include/llvm-libc-types/sigset_t.h
+++ /dev/null
@@ -1,20 +0,0 @@
-//===-- Definition of sigset_t type ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SIGSET_T_H
-#define LLVM_LIBC_TYPES_SIGSET_T_H
-
-#include "../llvm-libc-macros/signal-macros.h" // __NSIGSET_WORDS
-
-// This definition can be adjusted/specialized for different targets and
-// platforms as necessary. This definition works for Linux on most targets.
-typedef struct {
-  unsigned long __signals[__NSIGSET_WORDS];
-} sigset_t;
-
-#endif // LLVM_LIBC_TYPES_SIGSET_T_H
diff --git a/include/llvm-libc-types/socklen_t.h b/include/llvm-libc-types/socklen_t.h
deleted file mode 100644
index 5357747..0000000
--- a/include/llvm-libc-types/socklen_t.h
+++ /dev/null
@@ -1,18 +0,0 @@
-//===-- Definition of socklen_t type ------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SOCKLEN_T_H
-#define LLVM_LIBC_TYPES_SOCKLEN_T_H
-
-// The posix standard only says of socklen_t that it must be an integer type of
-// width of at least 32 bits. The long type is defined as being at least 32
-// bits, so an unsigned long should be fine.
-
-typedef unsigned long socklen_t;
-
-#endif // LLVM_LIBC_TYPES_SOCKLEN_T_H
diff --git a/include/llvm-libc-types/speed_t.h b/include/llvm-libc-types/speed_t.h
deleted file mode 100644
index 9875d3b..0000000
--- a/include/llvm-libc-types/speed_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of speed_t type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SPEED_T_H
-#define LLVM_LIBC_TYPES_SPEED_T_H
-
-typedef unsigned int speed_t;
-
-#endif // LLVM_LIBC_TYPES_SPEED_T_H
diff --git a/include/llvm-libc-types/ssize_t.h b/include/llvm-libc-types/ssize_t.h
deleted file mode 100644
index 41e4b6d..0000000
--- a/include/llvm-libc-types/ssize_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of ssize_t type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SSIZE_T_H
-#define LLVM_LIBC_TYPES_SSIZE_T_H
-
-typedef __INT64_TYPE__ ssize_t;
-
-#endif // LLVM_LIBC_TYPES_SSIZE_T_H
diff --git a/include/llvm-libc-types/stack_t.h b/include/llvm-libc-types/stack_t.h
deleted file mode 100644
index 92d0305..0000000
--- a/include/llvm-libc-types/stack_t.h
+++ /dev/null
@@ -1,22 +0,0 @@
-//===-- Definition of stack_t type ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STACK_T_H
-#define LLVM_LIBC_TYPES_STACK_T_H
-
-#include "size_t.h"
-
-typedef struct {
-  // The order of the fields declared here should match the kernel definition
-  // of stack_t in order for the SYS_sigaltstack syscall to work correctly.
-  void *ss_sp;
-  int ss_flags;
-  size_t ss_size;
-} stack_t;
-
-#endif // LLVM_LIBC_TYPES_STACK_T_H
diff --git a/include/llvm-libc-types/stdfix-types.h b/include/llvm-libc-types/stdfix-types.h
deleted file mode 100644
index 542d45e..0000000
--- a/include/llvm-libc-types/stdfix-types.h
+++ /dev/null
@@ -1,25 +0,0 @@
-//===-- Definition of stdfix integer types --------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STDFIX_TYPES_H
-#define LLVM_LIBC_TYPES_STDFIX_TYPES_H
-
-typedef signed char int_hr_t;
-typedef signed short int int_r_t;
-typedef signed int int_lr_t;
-typedef signed short int_hk_t;
-typedef signed int int_k_t;
-typedef signed long long int_lk_t;
-typedef unsigned char uint_uhr_t;
-typedef unsigned short int uint_ur_t;
-typedef unsigned int uint_ulr_t;
-typedef unsigned short int uint_uhk_t;
-typedef unsigned int uint_uk_t;
-typedef unsigned long long uint_ulk_t;
-
-#endif // LLVM_LIBC_TYPES_STDFIX_TYPES_H
diff --git a/include/llvm-libc-types/struct_dirent.h b/include/llvm-libc-types/struct_dirent.h
deleted file mode 100644
index f950869..0000000
--- a/include/llvm-libc-types/struct_dirent.h
+++ /dev/null
@@ -1,29 +0,0 @@
-//===-- Definition of type struct dirent ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_DIRENT_H
-#define LLVM_LIBC_TYPES_STRUCT_DIRENT_H
-
-#include "ino_t.h"
-#include "off_t.h"
-
-struct dirent {
-  ino_t d_ino;
-#ifdef __linux__
-  off_t d_off;
-  unsigned short d_reclen;
-#endif
-  unsigned char d_type;
-  // The user code should use strlen to determine actual the size of d_name.
-  // Likewise, it is incorrect and prohibited by the POSIX standard to detemine
-  // the size of struct dirent type using sizeof. The size should be got using
-  // a different method, for example, from the d_reclen field on Linux.
-  char d_name[1];
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_DIRENT_H
diff --git a/include/llvm-libc-types/struct_dl_phdr_info.h b/include/llvm-libc-types/struct_dl_phdr_info.h
deleted file mode 100644
index 2b9a5d2..0000000
--- a/include/llvm-libc-types/struct_dl_phdr_info.h
+++ /dev/null
@@ -1,30 +0,0 @@
-//===-- Definition of type struct dl_phdr_info ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===---------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_DL_PHDR_INFO_H
-#define LLVM_LIBC_TYPES_STRUCT_DL_PHDR_INFO_H
-
-#include "../llvm-libc-macros/link-macros.h"
-#include "size_t.h"
-#include <elf.h>
-#include <stdint.h>
-
-struct dl_phdr_info {
-  ElfW(Addr) dlpi_addr;
-  const char *dlpi_name;
-  const ElfW(Phdr) * dlpi_phdr;
-  ElfW(Half) dlpi_phnum;
-
-  uint64_t dlpi_adds;
-  uint64_t dlpi_subs;
-
-  size_t dlpi_tls_modid;
-  void *dlpi_tls_data;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_DL_PHDR_INFO_H
diff --git a/include/llvm-libc-types/struct_epoll_data.h b/include/llvm-libc-types/struct_epoll_data.h
deleted file mode 100644
index 7200276..0000000
--- a/include/llvm-libc-types/struct_epoll_data.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of epoll_data type -------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_EPOLL_DATA_H
-#define LLVM_LIBC_TYPES_STRUCT_EPOLL_DATA_H
-
-union epoll_data {
-  void *ptr;
-  int fd;
-  __UINT32_TYPE__ u32;
-  __UINT64_TYPE__ u64;
-};
-
-typedef union epoll_data epoll_data_t;
-
-#endif // LLVM_LIBC_TYPES_STRUCT_EPOLL_DATA_H
diff --git a/include/llvm-libc-types/struct_epoll_event.h b/include/llvm-libc-types/struct_epoll_event.h
deleted file mode 100644
index f95fd1a..0000000
--- a/include/llvm-libc-types/struct_epoll_event.h
+++ /dev/null
@@ -1,23 +0,0 @@
-//===-- Definition of epoll_event type ------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_EPOLL_EVENT_H
-#define LLVM_LIBC_TYPES_STRUCT_EPOLL_EVENT_H
-
-#include "struct_epoll_data.h"
-
-typedef struct
-#ifdef __x86_64__
-    [[gnu::packed]] // Necessary for compatibility.
-#endif
-    epoll_event {
-  __UINT32_TYPE__ events;
-  epoll_data_t data;
-} epoll_event;
-
-#endif // LLVM_LIBC_TYPES_STRUCT_EPOLL_EVENT_H
diff --git a/include/llvm-libc-types/struct_f_owner_ex.h b/include/llvm-libc-types/struct_f_owner_ex.h
deleted file mode 100644
index 87d4b89..0000000
--- a/include/llvm-libc-types/struct_f_owner_ex.h
+++ /dev/null
@@ -1,25 +0,0 @@
-//===-- Definition of type struct f_owner_ex ------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_F_OWNER_EX_H
-#define LLVM_LIBC_TYPES_STRUCT_F_OWNER_EX_H
-
-#include "pid_t.h"
-
-enum pid_type {
-  F_OWNER_TID = 0,
-  F_OWNER_PID,
-  F_OWNER_PGRP,
-};
-
-struct f_owner_ex {
-  enum pid_type type;
-  pid_t pid;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_F_OWNER_EX_H
diff --git a/include/llvm-libc-types/struct_flock.h b/include/llvm-libc-types/struct_flock.h
deleted file mode 100644
index d4bde09..0000000
--- a/include/llvm-libc-types/struct_flock.h
+++ /dev/null
@@ -1,25 +0,0 @@
-//===-- Definition of type struct flock64 ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_FLOCK_H
-#define LLVM_LIBC_TYPES_STRUCT_FLOCK_H
-
-#include "off_t.h"
-#include "pid_t.h"
-
-#include <stdint.h>
-
-struct flock {
-  int16_t l_type;
-  int16_t l_whence;
-  off_t l_start;
-  off_t l_len;
-  pid_t l_pid;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_FLOCK_H
diff --git a/include/llvm-libc-types/struct_flock64.h b/include/llvm-libc-types/struct_flock64.h
deleted file mode 100644
index 8e485d7..0000000
--- a/include/llvm-libc-types/struct_flock64.h
+++ /dev/null
@@ -1,25 +0,0 @@
-//===-- Definition of type struct flock64 ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_FLOCK64_H
-#define LLVM_LIBC_TYPES_STRUCT_FLOCK64_H
-
-#include "off64_t.h"
-#include "pid_t.h"
-
-#include <stdint.h>
-
-struct flock64 {
-  int16_t l_type;
-  int16_t l_whence;
-  off64_t l_start;
-  off64_t l_len;
-  pid_t l_pid;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_FLOCK64_H
diff --git a/include/llvm-libc-types/struct_hsearch_data.h b/include/llvm-libc-types/struct_hsearch_data.h
deleted file mode 100644
index cdb1d0c..0000000
--- a/include/llvm-libc-types/struct_hsearch_data.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of type struct hsearch_data ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_HSEARCH_DATA_H
-#define LLVM_LIBC_TYPES_STRUCT_HSEARCH_DATA_H
-
-struct hsearch_data {
-  void *__opaque;
-  unsigned int __unused[2];
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_HSEARCH_DATA_H
diff --git a/include/llvm-libc-types/struct_iovec.h b/include/llvm-libc-types/struct_iovec.h
deleted file mode 100644
index db2ca64..0000000
--- a/include/llvm-libc-types/struct_iovec.h
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Definition of struct iovec ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_IOVEC_H
-#define LLVM_LIBC_TYPES_STRUCT_IOVEC_H
-
-#include "size_t.h"
-
-struct iovec {
-  void *iov_base;
-  size_t iov_len;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_IOVEC_H
diff --git a/include/llvm-libc-types/struct_lconv.h b/include/llvm-libc-types/struct_lconv.h
deleted file mode 100644
index 9d69f05..0000000
--- a/include/llvm-libc-types/struct_lconv.h
+++ /dev/null
@@ -1,39 +0,0 @@
-//===-- Definition of type lconv ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_LCONV_H
-#define LLVM_LIBC_TYPES_LCONV_H
-
-struct lconv {
-  char *decimal_point;
-  char *thousands_sep;
-  char *grouping;
-  char *mon_decimal_point;
-  char *mon_thousands_sep;
-  char *mon_grouping;
-  char *positive_sign;
-  char *negative_sign;
-  char *currency_symbol;
-  char frac_digits;
-  char p_cs_precedes;
-  char n_cs_precedes;
-  char p_sep_by_space;
-  char n_sep_by_space;
-  char p_sign_posn;
-  char n_sign_posn;
-  char *int_curr_symbol;
-  char int_frac_digits;
-  char int_p_cs_precedes;
-  char int_n_cs_precedes;
-  char int_p_sep_by_space;
-  char int_n_sep_by_space;
-  char int_p_sign_posn;
-  char int_n_sign_posn;
-};
-
-#endif // LLVM_LIBC_TYPES_LCONV_H
diff --git a/include/llvm-libc-types/struct_msghdr.h b/include/llvm-libc-types/struct_msghdr.h
deleted file mode 100644
index 7933de1..0000000
--- a/include/llvm-libc-types/struct_msghdr.h
+++ /dev/null
@@ -1,26 +0,0 @@
-//===-- Definition of struct msghdr ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_MSGHDR_H
-#define LLVM_LIBC_TYPES_STRUCT_MSGHDR_H
-
-#include "size_t.h"
-#include "socklen_t.h"
-#include "struct_iovec.h"
-
-struct msghdr {
-  void *msg_name;        /* Optional address */
-  socklen_t msg_namelen; /* Size of address */
-  struct iovec *msg_iov; /* Scatter/gather array */
-  size_t msg_iovlen;     /* # elements in msg_iov */
-  void *msg_control;     /* Ancillary data, see below */
-  size_t msg_controllen; /* Ancillary data buffer len */
-  int msg_flags;         /* Flags (unused) */
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_MSGHDR_H
diff --git a/include/llvm-libc-types/struct_pollfd.h b/include/llvm-libc-types/struct_pollfd.h
deleted file mode 100644
index 80abc8e..0000000
--- a/include/llvm-libc-types/struct_pollfd.h
+++ /dev/null
@@ -1,18 +0,0 @@
-//===-- Definition of type struct pollfd ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_POLLFD_H
-#define LLVM_LIBC_TYPES_STRUCT_POLLFD_H
-
-struct pollfd {
-  int fd;
-  short events;
-  short revents;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_POLLFD_H
diff --git a/include/llvm-libc-types/struct_rlimit.h b/include/llvm-libc-types/struct_rlimit.h
deleted file mode 100644
index 15d8c0e..0000000
--- a/include/llvm-libc-types/struct_rlimit.h
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Definition of type struct rlimit ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_RLIMIT_H
-#define LLVM_LIBC_TYPES_STRUCT_RLIMIT_H
-
-#include "rlim_t.h"
-
-struct rlimit {
-  rlim_t rlim_cur;
-  rlim_t rlim_max;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_RLIMIT_H
diff --git a/include/llvm-libc-types/struct_rusage.h b/include/llvm-libc-types/struct_rusage.h
deleted file mode 100644
index 59fe9f7..0000000
--- a/include/llvm-libc-types/struct_rusage.h
+++ /dev/null
@@ -1,37 +0,0 @@
-//===-- Definition of type struct rusage ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_RUSAGE_H
-#define LLVM_LIBC_TYPES_STRUCT_RUSAGE_H
-
-#include "struct_timeval.h"
-
-struct rusage {
-  struct timeval ru_utime;
-  struct timeval ru_stime;
-#ifdef __linux__
-  // Following fields are linux extensions as expected by the
-  // linux syscalls.
-  long ru_maxrss;   // Maximum resident set size
-  long ru_ixrss;    // Integral shared memory size
-  long ru_idrss;    // Integral unshared data size
-  long ru_isrss;    // Integral unshared stack size
-  long ru_minflt;   // Page reclaims
-  long ru_majflt;   // Page faults
-  long ru_nswap;    // Swaps
-  long ru_inblock;  // Block input operations
-  long ru_oublock;  // Block output operations
-  long ru_msgsnd;   // Messages sent
-  long ru_msgrcv;   // Messages received
-  long ru_nsignals; // Signals received
-  long ru_nvcsw;    // Voluntary context switches
-  long ru_nivcsw;   // Involuntary context switches
-#endif
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_RUSAGE_H
diff --git a/include/llvm-libc-types/struct_sched_param.h b/include/llvm-libc-types/struct_sched_param.h
deleted file mode 100644
index e44a00b..0000000
--- a/include/llvm-libc-types/struct_sched_param.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of type struct sched_param -----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_SCHED_PARAM_H
-#define LLVM_LIBC_TYPES_STRUCT_SCHED_PARAM_H
-
-#include "pid_t.h"
-#include "struct_timespec.h"
-#include "time_t.h"
-
-struct sched_param {
-  // Process or thread execution scheduling priority.
-  int sched_priority;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_SCHED_PARAM_H
diff --git a/include/llvm-libc-types/struct_sigaction.h b/include/llvm-libc-types/struct_sigaction.h
deleted file mode 100644
index 907418b..0000000
--- a/include/llvm-libc-types/struct_sigaction.h
+++ /dev/null
@@ -1,28 +0,0 @@
-//===-- Definition of struct __sigaction ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_SIGACTION_H
-#define LLVM_LIBC_TYPES_STRUCT_SIGACTION_H
-
-#include "siginfo_t.h"
-#include "sigset_t.h"
-
-struct sigaction {
-  union {
-    void (*sa_handler)(int);
-    void (*sa_sigaction)(int, siginfo_t *, void *);
-  };
-  sigset_t sa_mask;
-  int sa_flags;
-#ifdef __linux__
-  // This field is present on linux for most targets.
-  void (*sa_restorer)(void);
-#endif
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_SIGACTION_H
diff --git a/include/llvm-libc-types/struct_sockaddr.h b/include/llvm-libc-types/struct_sockaddr.h
deleted file mode 100644
index b7579e9..0000000
--- a/include/llvm-libc-types/struct_sockaddr.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of struct sockaddr -------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_SOCKADDR_H
-#define LLVM_LIBC_TYPES_STRUCT_SOCKADDR_H
-
-#include "sa_family_t.h"
-
-struct sockaddr {
-  sa_family_t sa_family;
-  // sa_data is a variable length array. It is provided with a length of one
-  // here as a placeholder.
-  char sa_data[1];
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_SOCKADDR_H
diff --git a/include/llvm-libc-types/struct_sockaddr_un.h b/include/llvm-libc-types/struct_sockaddr_un.h
deleted file mode 100644
index 5ed31a4..0000000
--- a/include/llvm-libc-types/struct_sockaddr_un.h
+++ /dev/null
@@ -1,22 +0,0 @@
-//===-- Definition of struct sockaddr_un ----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_SOCKADDR_UN_H
-#define LLVM_LIBC_TYPES_STRUCT_SOCKADDR_UN_H
-
-#include "sa_family_t.h"
-
-// This is the sockaddr specialization for AF_UNIX or AF_LOCAL sockets, as
-// defined by posix.
-
-struct sockaddr_un {
-  sa_family_t sun_family; /* AF_UNIX */
-  char sun_path[108];     /* Pathname */
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_SOCKADDR_UN_H
diff --git a/include/llvm-libc-types/struct_stat.h b/include/llvm-libc-types/struct_stat.h
deleted file mode 100644
index 4026679..0000000
--- a/include/llvm-libc-types/struct_stat.h
+++ /dev/null
@@ -1,39 +0,0 @@
-//===-- Definition of struct stat -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_STAT_H
-#define LLVM_LIBC_TYPES_STRUCT_STAT_H
-
-#include "blkcnt_t.h"
-#include "blksize_t.h"
-#include "dev_t.h"
-#include "gid_t.h"
-#include "ino_t.h"
-#include "mode_t.h"
-#include "nlink_t.h"
-#include "off_t.h"
-#include "struct_timespec.h"
-#include "uid_t.h"
-
-struct stat {
-  dev_t st_dev;
-  ino_t st_ino;
-  mode_t st_mode;
-  nlink_t st_nlink;
-  uid_t st_uid;
-  gid_t st_gid;
-  dev_t st_rdev;
-  off_t st_size;
-  struct timespec st_atim;
-  struct timespec st_mtim;
-  struct timespec st_ctim;
-  blksize_t st_blksize;
-  blkcnt_t st_blocks;
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_STAT_H
diff --git a/include/llvm-libc-types/struct_statvfs.h b/include/llvm-libc-types/struct_statvfs.h
deleted file mode 100644
index 9c649af..0000000
--- a/include/llvm-libc-types/struct_statvfs.h
+++ /dev/null
@@ -1,29 +0,0 @@
-//===-- Definition of type struct statvfs ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_STATVFS_H
-#define LLVM_LIBC_TYPES_STRUCT_STATVFS_H
-
-#include "fsblkcnt_t.h"
-#include "fsfilcnt_t.h"
-
-struct statvfs {
-  unsigned long f_bsize;   /* Filesystem block size */
-  unsigned long f_frsize;  /* Fragment size */
-  fsblkcnt_t f_blocks;     /* Size of fs in f_frsize units */
-  fsblkcnt_t f_bfree;      /* Number of free blocks */
-  fsblkcnt_t f_bavail;     /* Number of free blocks for unprivileged users */
-  fsfilcnt_t f_files;      /* Number of inodes */
-  fsfilcnt_t f_ffree;      /* Number of free inodes */
-  fsfilcnt_t f_favail;     /* Number of free inodes for unprivileged users */
-  unsigned long f_fsid;    /* Filesystem ID */
-  unsigned long f_flag;    /* Mount flags */
-  unsigned long f_namemax; /* Maximum filename length */
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_STATVFS_H
diff --git a/include/llvm-libc-types/struct_termios.h b/include/llvm-libc-types/struct_termios.h
deleted file mode 100644
index e3c5f28..0000000
--- a/include/llvm-libc-types/struct_termios.h
+++ /dev/null
@@ -1,32 +0,0 @@
-//===-- Definition of struct termios --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef __LLVM_LIBC_TYPES_STRUCT_TERMIOS_H__
-#define __LLVM_LIBC_TYPES_STRUCT_TERMIOS_H__
-
-#include "cc_t.h"
-#include "speed_t.h"
-#include "tcflag_t.h"
-
-struct termios {
-  tcflag_t c_iflag; // Input mode flags
-  tcflag_t c_oflag; // Output mode flags
-  tcflag_t c_cflag; // Control mode flags
-  tcflag_t c_lflag; // Local mode flags
-#ifdef __linux__
-  cc_t c_line; // Line discipline
-#endif         // __linux__
-  // NCCS is defined in llvm-libc-macros/termios-macros.h.
-  cc_t c_cc[NCCS]; // Control characters
-#ifdef __linux__
-  speed_t c_ispeed; // Input speed
-  speed_t c_ospeed; // output speed
-#endif              // __linux__
-};
-
-#endif // __LLVM_LIBC_TYPES_STRUCT_TERMIOS_H__
diff --git a/include/llvm-libc-types/struct_timespec.h b/include/llvm-libc-types/struct_timespec.h
deleted file mode 100644
index 28b5a57..0000000
--- a/include/llvm-libc-types/struct_timespec.h
+++ /dev/null
@@ -1,20 +0,0 @@
-//===-- Definition of struct timespec -------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_TIMESPEC_H
-#define LLVM_LIBC_TYPES_STRUCT_TIMESPEC_H
-
-#include "time_t.h"
-
-struct timespec {
-  time_t tv_sec; /* Seconds.  */
-  /* TODO: BIG_ENDIAN may require padding. */
-  long tv_nsec; /* Nanoseconds.  */
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_TIMESPEC_H
diff --git a/include/llvm-libc-types/struct_timeval.h b/include/llvm-libc-types/struct_timeval.h
deleted file mode 100644
index 9595d85..0000000
--- a/include/llvm-libc-types/struct_timeval.h
+++ /dev/null
@@ -1,20 +0,0 @@
-//===-- Definition of struct timeval -------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_TIMEVAL_H
-#define LLVM_LIBC_TYPES_STRUCT_TIMEVAL_H
-
-#include "suseconds_t.h"
-#include "time_t.h"
-
-struct timeval {
-  time_t tv_sec;       // Seconds
-  suseconds_t tv_usec; // Micro seconds
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_TIMEVAL_H
diff --git a/include/llvm-libc-types/struct_tm.h b/include/llvm-libc-types/struct_tm.h
deleted file mode 100644
index 2ec74ec..0000000
--- a/include/llvm-libc-types/struct_tm.h
+++ /dev/null
@@ -1,25 +0,0 @@
-//===-- Definition of struct tm -------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_TM_H
-#define LLVM_LIBC_TYPES_STRUCT_TM_H
-
-struct tm {
-  int tm_sec;   // seconds after the minute
-  int tm_min;   // minutes after the hour
-  int tm_hour;  // hours since midnight
-  int tm_mday;  // day of the month
-  int tm_mon;   // months since January
-  int tm_year;  // years since 1900
-  int tm_wday;  // days since Sunday
-  int tm_yday;  // days since January
-  int tm_isdst; // Daylight Saving Time flag
-  // TODO: add tm_gmtoff and tm_zone? (posix extensions)
-};
-
-#endif // LLVM_LIBC_TYPES_STRUCT_TM_H
diff --git a/include/llvm-libc-types/struct_utsname.h b/include/llvm-libc-types/struct_utsname.h
deleted file mode 100644
index e474171..0000000
--- a/include/llvm-libc-types/struct_utsname.h
+++ /dev/null
@@ -1,34 +0,0 @@
-//===-- Definition of struct utsname --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_STRUCT_UTSNAME_H
-#define LLVM_LIBC_TYPES_STRUCT_UTSNAME_H
-
-#if defined(__linux__)
-#define __UTS_NAME_LENGTH 65
-#elif defined(__APPLE__)
-#define __UTS_NAME_LENGTH 256
-#else
-// Arbitray default. Should be specialized for each platform.
-#define __UTS_NAME_LENGTH 1024
-#endif
-
-struct utsname {
-  char sysname[__UTS_NAME_LENGTH];
-  char nodename[__UTS_NAME_LENGTH];
-  char release[__UTS_NAME_LENGTH];
-  char version[__UTS_NAME_LENGTH];
-  char machine[__UTS_NAME_LENGTH];
-#ifdef __linux__
-  char domainname[__UTS_NAME_LENGTH];
-#endif
-};
-
-#undef __UTS_NAME_LENGTH
-
-#endif // LLVM_LIBC_TYPES_STRUCT_UTSNAME_H
diff --git a/include/llvm-libc-types/suseconds_t.h b/include/llvm-libc-types/suseconds_t.h
deleted file mode 100644
index 32ecc9f..0000000
--- a/include/llvm-libc-types/suseconds_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of suseconds_t type ------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_SUSECONDS_T_H
-#define LLVM_LIBC_TYPES_SUSECONDS_T_H
-
-typedef __INT32_TYPE__ suseconds_t;
-
-#endif // LLVM_LIBC_TYPES_SUSECONDS_T_H
diff --git a/include/llvm-libc-types/tcflag_t.h b/include/llvm-libc-types/tcflag_t.h
deleted file mode 100644
index 2978487..0000000
--- a/include/llvm-libc-types/tcflag_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of tcflag_t type ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_TCFLAG_T_H
-#define LLVM_LIBC_TYPES_TCFLAG_T_H
-
-typedef unsigned int tcflag_t;
-
-#endif // LLVM_LIBC_TYPES_TCFLAG_T_H
diff --git a/include/llvm-libc-types/test_rpc_opcodes_t.h b/include/llvm-libc-types/test_rpc_opcodes_t.h
deleted file mode 100644
index 7129768..0000000
--- a/include/llvm-libc-types/test_rpc_opcodes_t.h
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Definition of RPC opcodes used for internal tests -----------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_TEST_RPC_OPCODES_T_H
-#define LLVM_LIBC_TYPES_TEST_RPC_OPCODES_T_H
-
-// We consider the first 32768 opcodes as reserved for libc purposes. We allow
-// extensions to use any other number without conflicting with anything else.
-typedef enum : unsigned short {
-  RPC_TEST_NOOP = 1 << 15,
-  RPC_TEST_INCREMENT,
-  RPC_TEST_INTERFACE,
-  RPC_TEST_STREAM,
-} rpc_test_opcode_t;
-
-#endif // LLVM_LIBC_TYPES_TEST_RPC_OPCODES_T_H
diff --git a/include/llvm-libc-types/thrd_start_t.h b/include/llvm-libc-types/thrd_start_t.h
deleted file mode 100644
index 1fb21bc..0000000
--- a/include/llvm-libc-types/thrd_start_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of thrd_start_t type -----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_THRD_START_T_H
-#define LLVM_LIBC_TYPES_THRD_START_T_H
-
-typedef int (*thrd_start_t)(void *);
-
-#endif // LLVM_LIBC_TYPES_THRD_START_T_H
diff --git a/include/llvm-libc-types/thrd_t.h b/include/llvm-libc-types/thrd_t.h
deleted file mode 100644
index d5f3106..0000000
--- a/include/llvm-libc-types/thrd_t.h
+++ /dev/null
@@ -1,16 +0,0 @@
-//===-- Definition of thrd_t type -----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_THRD_T_H
-#define LLVM_LIBC_TYPES_THRD_T_H
-
-#include "__thread_type.h"
-
-typedef __thread_type thrd_t;
-
-#endif // LLVM_LIBC_TYPES_THRD_T_H
diff --git a/include/llvm-libc-types/time_t.h b/include/llvm-libc-types/time_t.h
deleted file mode 100644
index 76920dc..0000000
--- a/include/llvm-libc-types/time_t.h
+++ /dev/null
@@ -1,18 +0,0 @@
-//===-- Definition of the type time_t, for use during the libc build ------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_TIME_T_H
-#define LLVM_LIBC_TYPES_TIME_T_H
-
-#ifdef LIBC_TYPES_TIME_T_IS_32_BIT
-#include "time_t_32.h"
-#else
-#include "time_t_64.h"
-#endif
-
-#endif // LLVM_LIBC_TYPES_TIME_T_H
diff --git a/include/llvm-libc-types/time_t_32.h b/include/llvm-libc-types/time_t_32.h
deleted file mode 100644
index 2c415f6..0000000
--- a/include/llvm-libc-types/time_t_32.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of the type time_t -------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_TIME_T_32_H
-#define LLVM_LIBC_TYPES_TIME_T_32_H
-
-typedef __INT32_TYPE__ time_t;
-
-#endif // LLVM_LIBC_TYPES_TIME_T_32_H
diff --git a/include/llvm-libc-types/time_t_64.h b/include/llvm-libc-types/time_t_64.h
deleted file mode 100644
index 8f7fd32..0000000
--- a/include/llvm-libc-types/time_t_64.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of the type time_t -------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_TIME_T_64_H
-#define LLVM_LIBC_TYPES_TIME_T_64_H
-
-typedef __INT64_TYPE__ time_t;
-
-#endif // LLVM_LIBC_TYPES_TIME_T_64_H
diff --git a/include/llvm-libc-types/tss_dtor_t.h b/include/llvm-libc-types/tss_dtor_t.h
deleted file mode 100644
index c54b34e..0000000
--- a/include/llvm-libc-types/tss_dtor_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of the type tss_dtor_t ---------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_TSS_DTOR_T_H
-#define LLVM_LIBC_TYPES_TSS_DTOR_T_H
-
-typedef void (*tss_dtor_t)(void *);
-
-#endif // LLVM_LIBC_TYPES_TSS_DTOR_T_H
diff --git a/include/llvm-libc-types/tss_t.h b/include/llvm-libc-types/tss_t.h
deleted file mode 100644
index 92bc7ef..0000000
--- a/include/llvm-libc-types/tss_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of the type tss_t --------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_TSS_T_H
-#define LLVM_LIBC_TYPES_TSS_T_H
-
-typedef unsigned int tss_t;
-
-#endif // LLVM_LIBC_TYPES_TSS_T_H
diff --git a/include/llvm-libc-types/uid_t.h b/include/llvm-libc-types/uid_t.h
deleted file mode 100644
index 4f6c647..0000000
--- a/include/llvm-libc-types/uid_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of uid_t type ------------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_UID_T_H
-#define LLVM_LIBC_TYPES_UID_T_H
-
-typedef __UINT32_TYPE__ uid_t;
-
-#endif // LLVM_LIBC_TYPES_UID_T_H
diff --git a/include/llvm-libc-types/union_sigval.h b/include/llvm-libc-types/union_sigval.h
deleted file mode 100644
index 5f83cd2..0000000
--- a/include/llvm-libc-types/union_sigval.h
+++ /dev/null
@@ -1,17 +0,0 @@
-//===-- Definition of type union sigval -----------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_UNION_SIGVAL_H
-#define LLVM_LIBC_TYPES_UNION_SIGVAL_H
-
-union sigval {
-  int sival_int;
-  void *sival_ptr;
-};
-
-#endif // LLVM_LIBC_TYPES_UNION_SIGVAL_H
diff --git a/include/llvm-libc-types/wchar_t.h b/include/llvm-libc-types/wchar_t.h
deleted file mode 100644
index bf2633a..0000000
--- a/include/llvm-libc-types/wchar_t.h
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Definition of wchar_t types ---------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_WCHAR_T_H
-#define LLVM_LIBC_TYPES_WCHAR_T_H
-
-// wchar_t is a fundamental type in C++.
-#ifndef __cplusplus
-
-typedef __WCHAR_TYPE__ wchar_t;
-
-#endif
-
-#endif // LLVM_LIBC_TYPES_WCHAR_T_H
diff --git a/include/llvm-libc-types/wint_t.h b/include/llvm-libc-types/wint_t.h
deleted file mode 100644
index a53c6e3..0000000
--- a/include/llvm-libc-types/wint_t.h
+++ /dev/null
@@ -1,14 +0,0 @@
-//===-- Definition of wint_t types ----------------------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_TYPES_WINT_T_H
-#define LLVM_LIBC_TYPES_WINT_T_H
-
-typedef __WINT_TYPE__ wint_t;
-
-#endif // LLVM_LIBC_TYPES_WINT_T_H
diff --git a/libc/shared/rpc.h b/libc/shared/rpc.h
index dd46d5d..7295efd 100644
--- a/libc/shared/rpc.h
+++ b/libc/shared/rpc.h
@@ -275,7 +275,7 @@ template <bool Invert> struct Process {
   }
 };
 
-/// Invokes a function accross every active buffer across the total lane size.
+/// Invokes a function across every active buffer across the total lane size.
 template <typename F>
 RPC_ATTRS static void invoke_rpc(F &&fn, uint32_t lane_size, uint64_t lane_mask,
                                  Buffer *slot) {
@@ -375,8 +375,8 @@ struct Server {
                                          uint32_t start = 0);
   RPC_ATTRS Port open(uint32_t lane_size);
 
-  RPC_ATTRS static uint64_t allocation_size(uint32_t lane_size,
-                                            uint32_t port_count) {
+  RPC_ATTRS static constexpr uint64_t allocation_size(uint32_t lane_size,
+                                                      uint32_t port_count) {
     return Process<true>::allocation_size(port_count, lane_size);
   }
 
diff --git a/src/__support/CPP/atomic.h b/src/__support/CPP/atomic.h
index 287dcac..2f00b3e 100644
--- a/src/__support/CPP/atomic.h
+++ b/src/__support/CPP/atomic.h
@@ -40,6 +40,28 @@ enum class MemoryScope : int {
 #endif
 };
 
+namespace impl {
+LIBC_INLINE constexpr int order(MemoryOrder mem_ord) {
+  return static_cast<int>(mem_ord);
+}
+
+LIBC_INLINE constexpr int scope(MemoryScope mem_scope) {
+  return static_cast<int>(mem_scope);
+}
+
+template <class T> LIBC_INLINE T *addressof(T &ref) {
+  return __builtin_addressof(ref);
+}
+
+LIBC_INLINE constexpr int infer_failure_order(MemoryOrder mem_ord) {
+  if (mem_ord == MemoryOrder::RELEASE)
+    return order(MemoryOrder::RELAXED);
+  if (mem_ord == MemoryOrder::ACQ_REL)
+    return order(MemoryOrder::ACQUIRE);
+  return order(mem_ord);
+}
+} // namespace impl
+
 template <typename T> struct Atomic {
   static_assert(is_trivially_copyable_v<T> && is_copy_constructible_v<T> &&
                     is_move_constructible_v<T> && is_copy_assignable_v<T> &&
@@ -54,15 +76,6 @@ template <typename T> struct Atomic {
 
 private:
   // type conversion helper to avoid long c++ style casts
-  LIBC_INLINE static int order(MemoryOrder mem_ord) {
-    return static_cast<int>(mem_ord);
-  }
-
-  LIBC_INLINE static int scope(MemoryScope mem_scope) {
-    return static_cast<int>(mem_scope);
-  }
-
-  LIBC_INLINE static T *addressof(T &ref) { return __builtin_addressof(ref); }
 
   // Require types that are 1, 2, 4, 8, or 16 bytes in length to be aligned to
   // at least their size to be potentially used lock-free.
@@ -84,7 +97,7 @@ public:
 
   LIBC_INLINE constexpr Atomic() = default;
 
-  // Intializes the value without using atomic operations.
+  // Initializes the value without using atomic operations.
   LIBC_INLINE constexpr Atomic(value_type v) : val(v) {}
 
   LIBC_INLINE Atomic(const Atomic &) = delete;
@@ -98,10 +111,11 @@ public:
        [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
     T res;
 #if __has_builtin(__scoped_atomic_load)
-    __scoped_atomic_load(addressof(val), addressof(res), order(mem_ord),
-                         scope(mem_scope));
+    __scoped_atomic_load(impl::addressof(val), impl::addressof(res),
+                         impl::order(mem_ord), impl::scope(mem_scope));
 #else
-    __atomic_load(addressof(val), addressof(res), order(mem_ord));
+    __atomic_load(impl::addressof(val), impl::addressof(res),
+                  impl::order(mem_ord));
 #endif
     return res;
   }
@@ -116,10 +130,11 @@ public:
   store(T rhs, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
         [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
 #if __has_builtin(__scoped_atomic_store)
-    __scoped_atomic_store(addressof(val), addressof(rhs), order(mem_ord),
-                          scope(mem_scope));
+    __scoped_atomic_store(impl::addressof(val), impl::addressof(rhs),
+                          impl::order(mem_ord), impl::scope(mem_scope));
 #else
-    __atomic_store(addressof(val), addressof(rhs), order(mem_ord));
+    __atomic_store(impl::addressof(val), impl::addressof(rhs),
+                   impl::order(mem_ord));
 #endif
   }
 
@@ -127,9 +142,10 @@ public:
   LIBC_INLINE bool compare_exchange_strong(
       T &expected, T desired, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
       [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
-    return __atomic_compare_exchange(addressof(val), addressof(expected),
-                                     addressof(desired), false, order(mem_ord),
-                                     order(mem_ord));
+    return __atomic_compare_exchange(
+        impl::addressof(val), impl::addressof(expected),
+        impl::addressof(desired), false, impl::order(mem_ord),
+        impl::infer_failure_order(mem_ord));
   }
 
   // Atomic compare exchange (separate success and failure memory orders)
@@ -138,17 +154,19 @@ public:
       MemoryOrder failure_order,
       [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
     return __atomic_compare_exchange(
-        addressof(val), addressof(expected), addressof(desired), false,
-        order(success_order), order(failure_order));
+        impl::addressof(val), impl::addressof(expected),
+        impl::addressof(desired), false, impl::order(success_order),
+        impl::order(failure_order));
   }
 
   // Atomic compare exchange (weak version)
   LIBC_INLINE bool compare_exchange_weak(
       T &expected, T desired, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
       [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
-    return __atomic_compare_exchange(addressof(val), addressof(expected),
-                                     addressof(desired), true, order(mem_ord),
-                                     order(mem_ord));
+    return __atomic_compare_exchange(
+        impl::addressof(val), impl::addressof(expected),
+        impl::addressof(desired), true, impl::order(mem_ord),
+        impl::infer_failure_order(mem_ord));
   }
 
   // Atomic compare exchange (weak version with separate success and failure
@@ -158,8 +176,9 @@ public:
       MemoryOrder failure_order,
       [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
     return __atomic_compare_exchange(
-        addressof(val), addressof(expected), addressof(desired), true,
-        order(success_order), order(failure_order));
+        impl::addressof(val), impl::addressof(expected),
+        impl::addressof(desired), true, impl::order(success_order),
+        impl::order(failure_order));
   }
 
   LIBC_INLINE T
@@ -167,11 +186,12 @@ public:
            [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
     T ret;
 #if __has_builtin(__scoped_atomic_exchange)
-    __scoped_atomic_exchange(addressof(val), addressof(desired), addressof(ret),
-                             order(mem_ord), scope(mem_scope));
+    __scoped_atomic_exchange(impl::addressof(val), impl::addressof(desired),
+                             impl::addressof(ret), impl::order(mem_ord),
+                             impl::scope(mem_scope));
 #else
-    __atomic_exchange(addressof(val), addressof(desired), addressof(ret),
-                      order(mem_ord));
+    __atomic_exchange(impl::addressof(val), impl::addressof(desired),
+                      impl::addressof(ret), impl::order(mem_ord));
 #endif
     return ret;
   }
@@ -181,10 +201,12 @@ public:
             [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
     static_assert(cpp::is_integral_v<T>, "T must be an integral type.");
 #if __has_builtin(__scoped_atomic_fetch_add)
-    return __scoped_atomic_fetch_add(addressof(val), increment, order(mem_ord),
-                                     scope(mem_scope));
+    return __scoped_atomic_fetch_add(impl::addressof(val), increment,
+                                     impl::order(mem_ord),
+                                     impl::scope(mem_scope));
 #else
-    return __atomic_fetch_add(addressof(val), increment, order(mem_ord));
+    return __atomic_fetch_add(impl::addressof(val), increment,
+                              impl::order(mem_ord));
 #endif
   }
 
@@ -193,10 +215,11 @@ public:
            [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
     static_assert(cpp::is_integral_v<T>, "T must be an integral type.");
 #if __has_builtin(__scoped_atomic_fetch_or)
-    return __scoped_atomic_fetch_or(addressof(val), mask, order(mem_ord),
-                                    scope(mem_scope));
+    return __scoped_atomic_fetch_or(impl::addressof(val), mask,
+                                    impl::order(mem_ord),
+                                    impl::scope(mem_scope));
 #else
-    return __atomic_fetch_or(addressof(val), mask, order(mem_ord));
+    return __atomic_fetch_or(impl::addressof(val), mask, impl::order(mem_ord));
 #endif
   }
 
@@ -205,10 +228,11 @@ public:
             [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
     static_assert(cpp::is_integral_v<T>, "T must be an integral type.");
 #if __has_builtin(__scoped_atomic_fetch_and)
-    return __scoped_atomic_fetch_and(addressof(val), mask, order(mem_ord),
-                                     scope(mem_scope));
+    return __scoped_atomic_fetch_and(impl::addressof(val), mask,
+                                     impl::order(mem_ord),
+                                     impl::scope(mem_scope));
 #else
-    return __atomic_fetch_and(addressof(val), mask, order(mem_ord));
+    return __atomic_fetch_and(impl::addressof(val), mask, impl::order(mem_ord));
 #endif
   }
 
@@ -217,10 +241,12 @@ public:
             [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) {
     static_assert(cpp::is_integral_v<T>, "T must be an integral type.");
 #if __has_builtin(__scoped_atomic_fetch_sub)
-    return __scoped_atomic_fetch_sub(addressof(val), decrement, order(mem_ord),
-                                     scope(mem_scope));
+    return __scoped_atomic_fetch_sub(impl::addressof(val), decrement,
+                                     impl::order(mem_ord),
+                                     impl::scope(mem_scope));
 #else
-    return __atomic_fetch_sub(addressof(val), decrement, order(mem_ord));
+    return __atomic_fetch_sub(impl::addressof(val), decrement,
+                              impl::order(mem_ord));
 #endif
   }
 
@@ -229,6 +255,149 @@ public:
   LIBC_INLINE void set(T rhs) { val = rhs; }
 };
 
+template <typename T> struct AtomicRef {
+  static_assert(is_trivially_copyable_v<T> && is_copy_constructible_v<T> &&
+                    is_move_constructible_v<T> && is_copy_assignable_v<T> &&
+                    is_move_assignable_v<T>,
+                "AtomicRef<T> requires T to be trivially copyable, copy "
+                "constructible, move constructible, copy assignable, "
+                "and move assignable.");
+
+  static_assert(cpp::has_unique_object_representations_v<T>,
+                "AtomicRef<T> only supports types with unique object "
+                "representations.");
+
+private:
+  T *ptr;
+
+public:
+  // Constructor from T reference
+  LIBC_INLINE explicit constexpr AtomicRef(T &obj) : ptr(&obj) {}
+
+  // Non-standard Implicit conversion from T*
+  LIBC_INLINE constexpr AtomicRef(T *obj) : ptr(obj) {}
+
+  LIBC_INLINE AtomicRef(const AtomicRef &) = default;
+  LIBC_INLINE AtomicRef &operator=(const AtomicRef &) = default;
+
+  // Atomic load
+  LIBC_INLINE operator T() const { return load(); }
+
+  LIBC_INLINE T
+  load(MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
+       [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+    T res;
+#if __has_builtin(__scoped_atomic_load)
+    __scoped_atomic_load(ptr, &res, impl::order(mem_ord),
+                         impl::scope(mem_scope));
+#else
+    __atomic_load(ptr, &res, impl::order(mem_ord));
+#endif
+    return res;
+  }
+
+  // Atomic store
+  LIBC_INLINE T operator=(T rhs) const {
+    store(rhs);
+    return rhs;
+  }
+
+  LIBC_INLINE void
+  store(T rhs, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
+        [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+#if __has_builtin(__scoped_atomic_store)
+    __scoped_atomic_store(ptr, &rhs, impl::order(mem_ord),
+                          impl::scope(mem_scope));
+#else
+    __atomic_store(ptr, &rhs, impl::order(mem_ord));
+#endif
+  }
+
+  // Atomic compare exchange (strong)
+  LIBC_INLINE bool compare_exchange_strong(
+      T &expected, T desired, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
+      [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+    return __atomic_compare_exchange(ptr, &expected, &desired, false,
+                                     impl::order(mem_ord),
+                                     impl::infer_failure_order(mem_ord));
+  }
+
+  // Atomic compare exchange (strong, separate success/failure memory orders)
+  LIBC_INLINE bool compare_exchange_strong(
+      T &expected, T desired, MemoryOrder success_order,
+      MemoryOrder failure_order,
+      [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+    return __atomic_compare_exchange(ptr, &expected, &desired, false,
+                                     impl::order(success_order),
+                                     impl::order(failure_order));
+  }
+
+  // Atomic exchange
+  LIBC_INLINE T
+  exchange(T desired, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
+           [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+    T ret;
+#if __has_builtin(__scoped_atomic_exchange)
+    __scoped_atomic_exchange(ptr, &desired, &ret, impl::order(mem_ord),
+                             impl::scope(mem_scope));
+#else
+    __atomic_exchange(ptr, &desired, &ret, impl::order(mem_ord));
+#endif
+    return ret;
+  }
+
+  LIBC_INLINE T fetch_add(
+      T increment, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
+      [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+    static_assert(cpp::is_integral_v<T>, "T must be an integral type.");
+#if __has_builtin(__scoped_atomic_fetch_add)
+    return __scoped_atomic_fetch_add(ptr, increment, impl::order(mem_ord),
+                                     impl::scope(mem_scope));
+#else
+    return __atomic_fetch_add(ptr, increment, impl::order(mem_ord));
+#endif
+  }
+
+  LIBC_INLINE T
+  fetch_or(T mask, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
+           [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+    static_assert(cpp::is_integral_v<T>, "T must be an integral type.");
+#if __has_builtin(__scoped_atomic_fetch_or)
+    return __scoped_atomic_fetch_or(ptr, mask, impl::order(mem_ord),
+                                    impl::scope(mem_scope));
+#else
+    return __atomic_fetch_or(ptr, mask, impl::order(mem_ord));
+#endif
+  }
+
+  LIBC_INLINE T fetch_and(
+      T mask, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
+      [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+    static_assert(cpp::is_integral_v<T>, "T must be an integral type.");
+#if __has_builtin(__scoped_atomic_fetch_and)
+    return __scoped_atomic_fetch_and(ptr, mask, impl::order(mem_ord),
+                                     impl::scope(mem_scope));
+#else
+    return __atomic_fetch_and(ptr, mask, impl::order(mem_ord));
+#endif
+  }
+
+  LIBC_INLINE T fetch_sub(
+      T decrement, MemoryOrder mem_ord = MemoryOrder::SEQ_CST,
+      [[maybe_unused]] MemoryScope mem_scope = MemoryScope::DEVICE) const {
+    static_assert(cpp::is_integral_v<T>, "T must be an integral type.");
+#if __has_builtin(__scoped_atomic_fetch_sub)
+    return __scoped_atomic_fetch_sub(ptr, decrement, impl::order(mem_ord),
+                                     impl::scope(mem_scope));
+#else
+    return __atomic_fetch_sub(ptr, decrement, impl::order(mem_ord));
+#endif
+  }
+};
+
+// Permit CTAD when generating an atomic reference.
+template <typename T> AtomicRef(T &) -> AtomicRef<T>;
+
 // Issue a thread fence with the given memory ordering.
 LIBC_INLINE void atomic_thread_fence(
     MemoryOrder mem_ord,
@@ -254,7 +423,6 @@ LIBC_INLINE void atomic_signal_fence([[maybe_unused]] MemoryOrder mem_ord) {
   asm volatile("" ::: "memory");
 #endif
 }
-
 } // namespace cpp
 } // namespace LIBC_NAMESPACE_DECL
 
diff --git a/src/__support/CPP/type_traits/is_signed.h b/src/__support/CPP/type_traits/is_signed.h
index 3f56fb3..2ddb43a 100644
--- a/src/__support/CPP/type_traits/is_signed.h
+++ b/src/__support/CPP/type_traits/is_signed.h
@@ -8,20 +8,43 @@
 #ifndef LLVM_LIBC_SRC___SUPPORT_CPP_TYPE_TRAITS_IS_SIGNED_H
 #define LLVM_LIBC_SRC___SUPPORT_CPP_TYPE_TRAITS_IS_SIGNED_H
 
+#include "include/llvm-libc-macros/stdfix-macros.h"
 #include "src/__support/CPP/type_traits/bool_constant.h"
 #include "src/__support/CPP/type_traits/is_arithmetic.h"
+#include "src/__support/CPP/type_traits/is_same.h"
+#include "src/__support/CPP/type_traits/remove_cv.h"
 #include "src/__support/macros/attributes.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 namespace cpp {
 
-// is_signed
+#ifndef LIBC_COMPILER_HAS_FIXED_POINT
 template <typename T>
 struct is_signed : bool_constant<(is_arithmetic_v<T> && (T(-1) < T(0)))> {
   LIBC_INLINE constexpr operator bool() const { return is_signed::value; }
   LIBC_INLINE constexpr bool operator()() const { return is_signed::value; }
 };
+#else
+template <typename T> struct is_signed {
+private:
+  template <typename Head, typename... Args>
+  LIBC_INLINE static constexpr bool __is_unqualified_any_of() {
+    return (... || is_same_v<remove_cv_t<Head>, Args>);
+  }
+
+public:
+  LIBC_INLINE_VAR static constexpr bool value =
+      (is_arithmetic_v<T> && (T(-1) < T(0))) ||
+      __is_unqualified_any_of<T, short fract, fract, long fract, short accum,
+                              accum, long accum, short sat fract, sat fract,
+                              long sat fract, short sat accum, sat accum,
+                              long sat accum>();
+  LIBC_INLINE constexpr operator bool() const { return is_signed::value; }
+  LIBC_INLINE constexpr bool operator()() const { return is_signed::value; }
+};
+#endif // LIBC_COMPILER_HAS_FIXED_POINT
+
 template <typename T>
 LIBC_INLINE_VAR constexpr bool is_signed_v = is_signed<T>::value;
 
diff --git a/src/__support/CPP/type_traits/is_unsigned.h b/src/__support/CPP/type_traits/is_unsigned.h
index eed519b..3ae6337 100644
--- a/src/__support/CPP/type_traits/is_unsigned.h
+++ b/src/__support/CPP/type_traits/is_unsigned.h
@@ -8,20 +8,45 @@
 #ifndef LLVM_LIBC_SRC___SUPPORT_CPP_TYPE_TRAITS_IS_UNSIGNED_H
 #define LLVM_LIBC_SRC___SUPPORT_CPP_TYPE_TRAITS_IS_UNSIGNED_H
 
+#include "include/llvm-libc-macros/stdfix-macros.h"
 #include "src/__support/CPP/type_traits/bool_constant.h"
 #include "src/__support/CPP/type_traits/is_arithmetic.h"
+#include "src/__support/CPP/type_traits/is_same.h"
+#include "src/__support/CPP/type_traits/remove_cv.h"
 #include "src/__support/macros/attributes.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 namespace cpp {
 
-// is_unsigned
+#ifndef LIBC_COMPILER_HAS_FIXED_POINT
 template <typename T>
 struct is_unsigned : bool_constant<(is_arithmetic_v<T> && (T(-1) > T(0)))> {
   LIBC_INLINE constexpr operator bool() const { return is_unsigned::value; }
   LIBC_INLINE constexpr bool operator()() const { return is_unsigned::value; }
 };
+#else
+template <typename T> struct is_unsigned {
+private:
+  template <typename Head, typename... Args>
+  LIBC_INLINE static constexpr bool __is_unqualified_any_of() {
+    return (... || is_same_v<remove_cv_t<Head>, Args>);
+  }
+
+public:
+  LIBC_INLINE_VAR static constexpr bool value =
+      (is_arithmetic_v<T> && (T(-1) > T(0))) ||
+      __is_unqualified_any_of<T, unsigned short fract, unsigned fract,
+                              unsigned long fract, unsigned short accum,
+                              unsigned accum, unsigned long accum,
+                              unsigned short sat fract, unsigned sat fract,
+                              unsigned long sat fract, unsigned short sat accum,
+                              unsigned sat accum, unsigned long sat accum>();
+  LIBC_INLINE constexpr operator bool() const { return is_unsigned::value; }
+  LIBC_INLINE constexpr bool operator()() const { return is_unsigned::value; }
+};
+#endif // LIBC_COMPILER_HAS_FIXED_POINT
+
 template <typename T>
 LIBC_INLINE_VAR constexpr bool is_unsigned_v = is_unsigned<T>::value;
 
diff --git a/src/__support/FPUtil/FEnvImpl.h b/src/__support/FPUtil/FEnvImpl.h
index 1c5a110..4c8f34a 100644
--- a/src/__support/FPUtil/FEnvImpl.h
+++ b/src/__support/FPUtil/FEnvImpl.h
@@ -17,7 +17,7 @@
 #include "src/__support/macros/properties/architectures.h"
 #include "src/errno/libc_errno.h"
 
-#if defined(LIBC_TARGET_ARCH_IS_AARCH64)
+#if defined(LIBC_TARGET_ARCH_IS_AARCH64) && defined(__ARM_FP)
 #if defined(__APPLE__)
 #include "aarch64/fenv_darwin_impl.h"
 #else
diff --git a/src/__support/FPUtil/FPBits.h b/src/__support/FPUtil/FPBits.h
index bee8d0a..4fa3bc3 100644
--- a/src/__support/FPUtil/FPBits.h
+++ b/src/__support/FPUtil/FPBits.h
@@ -757,7 +757,7 @@ public:
       result.set_significand(number);
       result.set_biased_exponent(static_cast<StorageType>(ep + 1));
     } else {
-      result.set_significand(number >> -ep);
+      result.set_significand(number >> static_cast<unsigned>(-ep));
     }
     return RetT(result.uintval());
   }
diff --git a/src/__support/FPUtil/Hypot.h b/src/__support/FPUtil/Hypot.h
index 6aa8084..94da259 100644
--- a/src/__support/FPUtil/Hypot.h
+++ b/src/__support/FPUtil/Hypot.h
@@ -30,7 +30,7 @@ LIBC_INLINE T find_leading_one(T mant, int &shift_length) {
   if (mant > 0) {
     shift_length = (sizeof(mant) * 8) - 1 - cpp::countl_zero(mant);
   }
-  return T(1) << shift_length;
+  return static_cast<T>((T(1) << shift_length));
 }
 
 } // namespace internal
@@ -207,8 +207,10 @@ LIBC_INLINE T hypot(T x, T y) {
 
   for (StorageType current_bit = leading_one >> 1; current_bit;
        current_bit >>= 1) {
-    r = (r << 1) + ((tail_bits & current_bit) ? 1 : 0);
-    StorageType tmp = (y_new << 1) + current_bit; // 2*y_new(n - 1) + 2^(-n)
+    r = static_cast<StorageType>((r << 1)) +
+        ((tail_bits & current_bit) ? 1 : 0);
+    StorageType tmp = static_cast<StorageType>((y_new << 1)) +
+                      current_bit; // 2*y_new(n - 1) + 2^(-n)
     if (r >= tmp) {
       r -= tmp;
       y_new += current_bit;
diff --git a/src/__support/FPUtil/aarch64/sqrt.h b/src/__support/FPUtil/aarch64/sqrt.h
index b69267f..4eb576b 100644
--- a/src/__support/FPUtil/aarch64/sqrt.h
+++ b/src/__support/FPUtil/aarch64/sqrt.h
@@ -12,6 +12,7 @@
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
 #include "src/__support/macros/properties/architectures.h"
+#include "src/__support/macros/properties/cpu_features.h"
 
 #if !defined(LIBC_TARGET_ARCH_IS_AARCH64)
 #error "Invalid include"
@@ -22,17 +23,21 @@
 namespace LIBC_NAMESPACE_DECL {
 namespace fputil {
 
+#ifdef LIBC_TARGET_CPU_HAS_FPU_FLOAT
 template <> LIBC_INLINE float sqrt<float>(float x) {
   float y;
-  __asm__ __volatile__("fsqrt %s0, %s1\n\t" : "=w"(y) : "w"(x));
+  asm("fsqrt %s0, %s1\n\t" : "=w"(y) : "w"(x));
   return y;
 }
+#endif // LIBC_TARGET_CPU_HAS_FPU_FLOAT
 
+#ifdef LIBC_TARGET_CPU_HAS_FPU_DOUBLE
 template <> LIBC_INLINE double sqrt<double>(double x) {
   double y;
-  __asm__ __volatile__("fsqrt %d0, %d1\n\t" : "=w"(y) : "w"(x));
+  asm("fsqrt %d0, %d1\n\t" : "=w"(y) : "w"(x));
   return y;
 }
+#endif // LIBC_TARGET_CPU_HAS_FPU_DOUBLE
 
 } // namespace fputil
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/__support/FPUtil/arm/sqrt.h b/src/__support/FPUtil/arm/sqrt.h
new file mode 100644
index 0000000..e6cb58c
--- /dev/null
+++ b/src/__support/FPUtil/arm/sqrt.h
@@ -0,0 +1,45 @@
+//===-- Square root of IEEE 754 floating point numbers ----------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC___SUPPORT_FPUTIL_ARM_SQRT_H
+#define LLVM_LIBC_SRC___SUPPORT_FPUTIL_ARM_SQRT_H
+
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/architectures.h"
+#include "src/__support/macros/properties/cpu_features.h"
+
+#if !defined(LIBC_TARGET_ARCH_IS_ARM)
+#error "Invalid include"
+#endif
+
+#include "src/__support/FPUtil/generic/sqrt.h"
+
+namespace LIBC_NAMESPACE_DECL {
+namespace fputil {
+
+#ifdef LIBC_TARGET_CPU_HAS_FPU_FLOAT
+template <> LIBC_INLINE float sqrt<float>(float x) {
+  float y;
+  asm("vsqrt %0, %1\n\t" : "=w"(y) : "w"(x));
+  return y;
+}
+#endif // LIBC_TARGET_CPU_HAS_FPU_FLOAT
+
+#ifdef LIBC_TARGET_CPU_HAS_FPU_DOUBLE
+template <> LIBC_INLINE double sqrt<double>(double x) {
+  double y;
+  asm("vsqrt %0, %1\n\t" : "=w"(y) : "w"(x));
+  return y;
+}
+#endif // LIBC_TARGET_CPU_HAS_FPU_DOUBLE
+
+} // namespace fputil
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC___SUPPORT_FPUTIL_ARM_SQRT_H
diff --git a/src/__support/FPUtil/cast.h b/src/__support/FPUtil/cast.h
index 126f385..7578bb4 100644
--- a/src/__support/FPUtil/cast.h
+++ b/src/__support/FPUtil/cast.h
@@ -18,6 +18,9 @@
 
 namespace LIBC_NAMESPACE::fputil {
 
+// TODO: Add optimization for known good targets with fast
+// float to float16 conversion:
+// https://github.com/llvm/llvm-project/issues/133517
 template <typename OutType, typename InType>
 LIBC_INLINE constexpr cpp::enable_if_t<cpp::is_floating_point_v<OutType> &&
                                            cpp::is_floating_point_v<InType>,
diff --git a/src/__support/FPUtil/dyadic_float.h b/src/__support/FPUtil/dyadic_float.h
index 5ef35de..6c3e152 100644
--- a/src/__support/FPUtil/dyadic_float.h
+++ b/src/__support/FPUtil/dyadic_float.h
@@ -104,7 +104,7 @@ template <size_t Bits> struct DyadicFloat {
     normalize();
   }
 
-  LIBC_INLINE constexpr DyadicFloat(Sign s, int e, MantissaType m)
+  LIBC_INLINE constexpr DyadicFloat(Sign s, int e, const MantissaType &m)
       : sign(s), exponent(e), mantissa(m) {
     normalize();
   }
@@ -175,7 +175,7 @@ template <size_t Bits> struct DyadicFloat {
   LIBC_INLINE constexpr cpp::enable_if_t<
       cpp::is_floating_point_v<T> && (FPBits<T>::FRACTION_LEN < Bits), T>
   generic_as() const {
-    using FPBits = FPBits<float16>;
+    using FPBits = FPBits<T>;
     using StorageType = typename FPBits::StorageType;
 
     constexpr int EXTRA_FRACTION_LEN = Bits - 1 - FPBits::FRACTION_LEN;
@@ -335,7 +335,7 @@ template <size_t Bits> struct DyadicFloat {
                  .get_val();
 
     MantissaType round_mask =
-        shift > MantissaType::BITS ? 0 : MantissaType(1) << (shift - 1);
+        shift - 1 >= MantissaType::BITS ? 0 : MantissaType(1) << (shift - 1);
     MantissaType sticky_mask = round_mask - MantissaType(1);
 
     bool round_bit = !(mantissa & round_mask).is_zero();
@@ -434,7 +434,12 @@ template <size_t Bits> struct DyadicFloat {
     if (exponent > 0) {
       new_mant <<= exponent;
     } else {
-      new_mant >>= (-exponent);
+      // Cast the exponent to size_t before negating it, rather than after,
+      // to avoid undefined behavior negating INT_MIN as an integer (although
+      // exponents coming in to this function _shouldn't_ be that large). The
+      // result should always end up as a positive size_t.
+      size_t shift = -static_cast<size_t>(exponent);
+      new_mant >>= shift;
     }
 
     if (sign.is_neg()) {
diff --git a/src/__support/FPUtil/nearest_integer.h b/src/__support/FPUtil/nearest_integer.h
index 5d0dedd..768f134 100644
--- a/src/__support/FPUtil/nearest_integer.h
+++ b/src/__support/FPUtil/nearest_integer.h
@@ -16,7 +16,7 @@
 
 #if (defined(LIBC_TARGET_ARCH_IS_X86_64) && defined(LIBC_TARGET_CPU_HAS_SSE4_2))
 #include "x86_64/nearest_integer.h"
-#elif defined(LIBC_TARGET_ARCH_IS_AARCH64)
+#elif (defined(LIBC_TARGET_ARCH_IS_AARCH64) && defined(__ARM_FP))
 #include "aarch64/nearest_integer.h"
 #elif defined(LIBC_TARGET_ARCH_IS_GPU)
 
diff --git a/src/__support/FPUtil/riscv/sqrt.h b/src/__support/FPUtil/riscv/sqrt.h
index 0363822..8cff03a 100644
--- a/src/__support/FPUtil/riscv/sqrt.h
+++ b/src/__support/FPUtil/riscv/sqrt.h
@@ -12,6 +12,7 @@
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
 #include "src/__support/macros/properties/architectures.h"
+#include "src/__support/macros/properties/cpu_features.h"
 
 #if !defined(LIBC_TARGET_ARCH_IS_ANY_RISCV)
 #error "Invalid include"
@@ -22,21 +23,21 @@
 namespace LIBC_NAMESPACE_DECL {
 namespace fputil {
 
-#ifdef __riscv_flen
+#ifdef LIBC_TARGET_CPU_HAS_FPU_FLOAT
 template <> LIBC_INLINE float sqrt<float>(float x) {
   float result;
-  __asm__ __volatile__("fsqrt.s %0, %1\n\t" : "=f"(result) : "f"(x));
+  asm("fsqrt.s %0, %1\n\t" : "=f"(result) : "f"(x));
   return result;
 }
+#endif // LIBC_TARGET_CPU_HAS_FPU_FLOAT
 
-#if __riscv_flen >= 64
+#ifdef LIBC_TARGET_CPU_HAS_FPU_DOUBLE
 template <> LIBC_INLINE double sqrt<double>(double x) {
   double result;
-  __asm__ __volatile__("fsqrt.d %0, %1\n\t" : "=f"(result) : "f"(x));
+  asm("fsqrt.d %0, %1\n\t" : "=f"(result) : "f"(x));
   return result;
 }
-#endif // __riscv_flen >= 64
-#endif // __riscv_flen
+#endif // LIBC_TARGET_CPU_HAS_FPU_FLOAT
 
 } // namespace fputil
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/__support/FPUtil/sqrt.h b/src/__support/FPUtil/sqrt.h
index eb86ddf..d4ed744 100644
--- a/src/__support/FPUtil/sqrt.h
+++ b/src/__support/FPUtil/sqrt.h
@@ -12,14 +12,54 @@
 #include "src/__support/macros/properties/architectures.h"
 #include "src/__support/macros/properties/cpu_features.h"
 
-#if defined(LIBC_TARGET_ARCH_IS_X86_64) && defined(LIBC_TARGET_CPU_HAS_SSE2)
+#include "src/__support/FPUtil/generic/sqrt.h"
+
+// Generic instruction specializations with __builtin_elementwise_sqrt.
+#if defined(LIBC_TARGET_CPU_HAS_FPU_FLOAT) ||                                  \
+    defined(LIBC_TARGET_CPU_HAS_FPU_DOUBLE)
+
+#if __has_builtin(__builtin_elementwise_sqrt)
+
+namespace LIBC_NAMESPACE_DECL {
+namespace fputil {
+
+#ifdef LIBC_TARGET_CPU_HAS_FPU_FLOAT
+template <> LIBC_INLINE float sqrt<float>(float x) {
+  return __builtin_elementwise_sqrt(x);
+}
+#endif // LIBC_TARGET_CPU_HAS_FPU_FLOAT
+
+#ifdef LIBC_TARGET_CPU_HAS_FPU_DOUBLE
+template <> LIBC_INLINE double sqrt<double>(double x) {
+  return __builtin_elementwise_sqrt(x);
+}
+#endif // LIBC_TARGET_CPU_HAS_FPU_DOUBLE
+
+// Use 80-bit long double instruction on x86.
+// https://godbolt.org/z/oWEaj6hxK
+#ifdef LIBC_TYPES_LONG_DOUBLE_IS_X86_FLOAT80
+template <> LIBC_INLINE long double sqrt<long double>(long double x) {
+  return __builtin_elementwise_sqrt(x);
+}
+#endif // LIBC_TYPES_LONG_DOUBLE_IS_X86_FLOAT80
+
+} // namespace fputil
+} // namespace LIBC_NAMESPACE_DECL
+
+#else // __builtin_elementwise_sqrt
+// Use inline assembly when __builtin_elementwise_sqrt is not available.
+#if defined(LIBC_TARGET_CPU_HAS_SSE2)
 #include "x86_64/sqrt.h"
-#elif defined(LIBC_TARGET_ARCH_IS_AARCH64)
+#elif defined(LIBC_TARGET_ARCH_IS_AARCH64) && defined(__ARM_FP)
 #include "aarch64/sqrt.h"
+#elif defined(LIBC_TARGET_ARCH_IS_ARM)
+#include "arm/sqrt.h"
 #elif defined(LIBC_TARGET_ARCH_IS_ANY_RISCV)
 #include "riscv/sqrt.h"
-#else
-#include "generic/sqrt.h"
+#endif // Target specific header of inline asm.
+
+#endif // __builtin_elementwise_sqrt
+
+#endif // LIBC_TARGET_CPU_HAS_FPU_FLOAT or DOUBLE
 
-#endif
 #endif // LLVM_LIBC_SRC___SUPPORT_FPUTIL_SQRT_H
diff --git a/src/__support/GPU/allocator.cpp b/src/__support/GPU/allocator.cpp
index ac335a1..135ced3 100644
--- a/src/__support/GPU/allocator.cpp
+++ b/src/__support/GPU/allocator.cpp
@@ -5,17 +5,49 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 //
 //===----------------------------------------------------------------------===//
+//
+// This file implements a parallel allocator intended for use on a GPU device.
+// The core algorithm is slab allocator using a random walk over a bitfield for
+// maximum parallel progress. Slab handling is done by a wait-free reference
+// counted guard. The first use of a slab will create it from system memory for
+// re-use. The last use will invalidate it and free the memory.
+//
+//===----------------------------------------------------------------------===//
 
 #include "allocator.h"
 
+#include "src/__support/CPP/atomic.h"
+#include "src/__support/CPP/bit.h"
+#include "src/__support/CPP/new.h"
 #include "src/__support/GPU/utils.h"
 #include "src/__support/RPC/rpc_client.h"
-#include "src/__support/macros/config.h"
+#include "src/__support/threads/sleep.h"
 
 namespace LIBC_NAMESPACE_DECL {
-namespace {
 
-void *rpc_allocate(uint64_t size) {
+constexpr static uint64_t MAX_SIZE = /* 64 GiB */ 64ull * 1024 * 1024 * 1024;
+constexpr static uint64_t SLAB_SIZE = /* 2 MiB */ 2ull * 1024 * 1024;
+constexpr static uint64_t ARRAY_SIZE = MAX_SIZE / SLAB_SIZE;
+constexpr static uint64_t SLAB_ALIGNMENT = SLAB_SIZE - 1;
+constexpr static uint32_t BITS_IN_WORD = sizeof(uint32_t) * 8;
+constexpr static uint32_t MIN_SIZE = 16;
+constexpr static uint32_t MIN_ALIGNMENT = MIN_SIZE - 1;
+
+// A sentinel used to indicate an invalid but non-null pointer value.
+constexpr static uint64_t SENTINEL = cpp::numeric_limits<uint64_t>::max();
+
+// The number of times we will try starting on a single index before skipping
+// past it.
+constexpr static uint32_t MAX_TRIES = 512;
+
+static_assert(!(ARRAY_SIZE & (ARRAY_SIZE - 1)), "Must be a power of two");
+
+namespace impl {
+// Allocates more memory from the system through the RPC interface. All
+// allocations from the system MUST be aligned on a 2MiB barrier. The default
+// HSA allocator has this behavior for any allocation >= 2MiB and the CUDA
+// driver provides an alignment field for virtual memory allocations.
+static void *rpc_allocate(uint64_t size) {
   void *ptr = nullptr;
   rpc::Client::Port port = rpc::client.open<LIBC_MALLOC>();
   port.send_and_recv(
@@ -27,7 +59,8 @@ void *rpc_allocate(uint64_t size) {
   return ptr;
 }
 
-void rpc_free(void *ptr) {
+// Deallocates the associated system memory.
+static void rpc_free(void *ptr) {
   rpc::Client::Port port = rpc::client.open<LIBC_FREE>();
   port.send([=](rpc::Buffer *buffer, uint32_t) {
     buffer->data[0] = reinterpret_cast<uintptr_t>(ptr);
@@ -35,13 +68,463 @@ void rpc_free(void *ptr) {
   port.close();
 }
 
-} // namespace
+// Convert a potentially disjoint bitmask into an increasing integer per-lane
+// for use with indexing between gpu lanes.
+static inline uint32_t lane_count(uint64_t lane_mask) {
+  return cpp::popcount(lane_mask & ((uint64_t(1) << gpu::get_lane_id()) - 1));
+}
+
+// Obtain an initial value to seed a random number generator. We use the rounded
+// multiples of the golden ratio from xorshift* as additional spreading.
+static inline uint32_t entropy() {
+  return (static_cast<uint32_t>(gpu::processor_clock()) ^
+          (gpu::get_thread_id_x() * 0x632be59b) ^
+          (gpu::get_block_id_x() * 0x85157af5)) *
+         0x9e3779bb;
+}
+
+// Generate a random number and update the state using the xorshift32* PRNG.
+static inline uint32_t xorshift32(uint32_t &state) {
+  state ^= state << 13;
+  state ^= state >> 17;
+  state ^= state << 5;
+  return state * 0x9e3779bb;
+}
+
+// Final stage of murmurhash used to get a unique index for the global array
+static inline uint32_t hash(uint32_t x) {
+  x ^= x >> 16;
+  x *= 0x85ebca6b;
+  x ^= x >> 13;
+  x *= 0xc2b2ae35;
+  x ^= x >> 16;
+  return x;
+}
+
+// Rounds the input value to the closest permitted chunk size. Here we accept
+// the sum of the closest three powers of two. For a 2MiB slab size this is 48
+// different chunk sizes. This gives us average internal fragmentation of 87.5%.
+static inline uint32_t get_chunk_size(uint32_t x) {
+  uint32_t y = x < MIN_SIZE ? MIN_SIZE : x;
+  uint32_t pow2 = BITS_IN_WORD - cpp::countl_zero(y - 1);
+
+  uint32_t s0 = 0b0100 << (pow2 - 3);
+  uint32_t s1 = 0b0110 << (pow2 - 3);
+  uint32_t s2 = 0b0111 << (pow2 - 3);
+  uint32_t s3 = 0b1000 << (pow2 - 3);
+
+  if (s0 > y)
+    return (s0 + MIN_ALIGNMENT) & ~MIN_ALIGNMENT;
+  if (s1 > y)
+    return (s1 + MIN_ALIGNMENT) & ~MIN_ALIGNMENT;
+  if (s2 > y)
+    return (s2 + MIN_ALIGNMENT) & ~MIN_ALIGNMENT;
+  return (s3 + MIN_ALIGNMENT) & ~MIN_ALIGNMENT;
+}
+
+// Rounds to the nearest power of two.
+template <uint32_t N, typename T>
+static inline constexpr T round_up(const T x) {
+  static_assert(((N - 1) & N) == 0, "N must be a power of two");
+  return (x + N) & ~(N - 1);
+}
+
+} // namespace impl
+
+/// A slab allocator used to hand out identically sized slabs of memory.
+/// Allocation is done through random walks of a bitfield until a free bit is
+/// encountered. This reduces contention and is highly parallel on a GPU.
+///
+/// 0       4           8       16                 ...                     2 MiB
+/// ┌────────┬──────────┬────────┬──────────────────┬──────────────────────────┐
+/// │ chunk  │  index   │  pad   │    bitfield[]    │         memory[]         │
+/// └────────┴──────────┴────────┴──────────────────┴──────────────────────────┘
+///
+/// The size of the bitfield is the slab size divided by the chunk size divided
+/// by the number of bits per word. We pad the interface to ensure 16 byte
+/// alignment and to indicate that if the pointer is not aligned by 2MiB it
+/// belongs to a slab rather than the global allocator.
+struct Slab {
+  // Header metadata for the slab, aligned to the minimum alignment.
+  struct alignas(MIN_SIZE) Header {
+    uint32_t chunk_size;
+    uint32_t global_index;
+  };
+
+  // Initialize the slab with its chunk size and index in the global table for
+  // use when freeing.
+  Slab(uint32_t chunk_size, uint32_t global_index) {
+    Header *header = reinterpret_cast<Header *>(memory);
+    header->chunk_size = chunk_size;
+    header->global_index = global_index;
+
+    // This memset is expensive and likely not necessary for the current 'kfd'
+    // driver. Until zeroed pages are exposed by the API we must be careful.
+    __builtin_memset(get_bitfield(), 0, bitfield_bytes(chunk_size));
+  }
+
+  // Get the number of chunks that can theoretically fit inside this slab.
+  constexpr static uint32_t num_chunks(uint32_t chunk_size) {
+    return SLAB_SIZE / chunk_size;
+  }
+
+  // Get the number of bytes needed to contain the bitfield bits.
+  constexpr static uint32_t bitfield_bytes(uint32_t chunk_size) {
+    return ((num_chunks(chunk_size) + BITS_IN_WORD - 1) / BITS_IN_WORD) * 8;
+  }
+
+  // The actual amount of memory available excluding the bitfield and metadata.
+  constexpr static uint32_t available_bytes(uint32_t chunk_size) {
+    return SLAB_SIZE - bitfield_bytes(chunk_size) - sizeof(Header);
+  }
+
+  // The number of chunks that can be stored in this slab.
+  constexpr static uint32_t available_chunks(uint32_t chunk_size) {
+    return available_bytes(chunk_size) / chunk_size;
+  }
+
+  // The length in bits of the bitfield.
+  constexpr static uint32_t usable_bits(uint32_t chunk_size) {
+    return available_bytes(chunk_size) / chunk_size;
+  }
+
+  // Get the location in the memory where we will store the chunk size.
+  uint32_t get_chunk_size() const {
+    return reinterpret_cast<const Header *>(memory)->chunk_size;
+  }
+
+  // Get the location in the memory where we will store the global index.
+  uint32_t get_global_index() const {
+    return reinterpret_cast<const Header *>(memory)->global_index;
+  }
+
+  // Get a pointer to where the bitfield is located in the memory.
+  uint32_t *get_bitfield() {
+    return reinterpret_cast<uint32_t *>(memory + sizeof(Header));
+  }
+
+  // Get a pointer to where the actual memory to be allocated lives.
+  uint8_t *get_memory(uint32_t chunk_size) {
+    return reinterpret_cast<uint8_t *>(get_bitfield()) +
+           bitfield_bytes(chunk_size);
+  }
+
+  // Get a pointer to the actual memory given an index into the bitfield.
+  void *ptr_from_index(uint32_t index, uint32_t chunk_size) {
+    return get_memory(chunk_size) + index * chunk_size;
+  }
+
+  // Convert a pointer back into its bitfield index using its offset.
+  uint32_t index_from_ptr(void *ptr, uint32_t chunk_size) {
+    return static_cast<uint32_t>(reinterpret_cast<uint8_t *>(ptr) -
+                                 get_memory(chunk_size)) /
+           chunk_size;
+  }
+
+  // Randomly walks the bitfield until it finds a free bit. Allocations attempt
+  // to put lanes right next to each other for better caching and convergence.
+  void *allocate(uint64_t lane_mask, uint64_t uniform) {
+    uint32_t chunk_size = get_chunk_size();
+    uint32_t state = impl::entropy();
+
+    // The uniform mask represents which lanes contain a uniform target pointer.
+    // We attempt to place these next to each other.
+    void *result = nullptr;
+    for (uint64_t mask = lane_mask; mask;
+         mask = gpu::ballot(lane_mask, !result)) {
+      if (result)
+        continue;
+
+      uint32_t start = gpu::broadcast_value(lane_mask, impl::xorshift32(state));
+
+      uint32_t id = impl::lane_count(uniform & mask);
+      uint32_t index = (start + id) % usable_bits(chunk_size);
+      uint32_t slot = index / BITS_IN_WORD;
+      uint32_t bit = index % BITS_IN_WORD;
+
+      // Get the mask of bits destined for the same slot and coalesce it.
+      uint64_t match = uniform & gpu::match_any(mask, slot);
+      uint32_t length = cpp::popcount(match);
+      uint32_t bitmask = static_cast<uint32_t>((uint64_t(1) << length) - 1)
+                         << bit;
+
+      uint32_t before = 0;
+      if (gpu::get_lane_id() == static_cast<uint32_t>(cpp::countr_zero(match)))
+        before = cpp::AtomicRef(get_bitfield()[slot])
+                     .fetch_or(bitmask, cpp::MemoryOrder::RELAXED);
+      before = gpu::shuffle(mask, cpp::countr_zero(match), before);
+      if (~before & (1 << bit))
+        result = ptr_from_index(index, chunk_size);
+      else
+        sleep_briefly();
+    }
+
+    cpp::atomic_thread_fence(cpp::MemoryOrder::ACQUIRE);
+    return result;
+  }
+
+  // Deallocates memory by resetting its corresponding bit in the bitfield.
+  void deallocate(void *ptr) {
+    uint32_t chunk_size = get_chunk_size();
+    uint32_t index = index_from_ptr(ptr, chunk_size);
+    uint32_t slot = index / BITS_IN_WORD;
+    uint32_t bit = index % BITS_IN_WORD;
+
+    cpp::atomic_thread_fence(cpp::MemoryOrder::RELEASE);
+    cpp::AtomicRef(get_bitfield()[slot])
+        .fetch_and(~(1u << bit), cpp::MemoryOrder::RELAXED);
+  }
+
+  // The actual memory the slab will manage. All offsets are calculated at
+  // runtime with the chunk size to keep the interface convergent when a warp or
+  // wavefront is handling multiple sizes at once.
+  uint8_t memory[SLAB_SIZE];
+};
+
+/// A wait-free guard around a pointer resource to be created dynamically if
+/// space is available and freed once there are no more users.
+template <typename T> struct GuardPtr {
+private:
+  struct RefCounter {
+    // Indicates that the object is in its deallocation phase and thus invalid.
+    static constexpr uint64_t INVALID = uint64_t(1) << 63;
+
+    // If a read preempts an unlock call we indicate this so the following
+    // unlock call can swap out the helped bit and maintain exclusive ownership.
+    static constexpr uint64_t HELPED = uint64_t(1) << 62;
+
+    // Resets the reference counter, cannot be reset to zero safely.
+    void reset(uint32_t n, uint64_t &count) {
+      counter.store(n, cpp::MemoryOrder::RELAXED);
+      count = n;
+    }
+
+    // Acquire a slot in the reference counter if it is not invalid.
+    bool acquire(uint32_t n, uint64_t &count) {
+      count = counter.fetch_add(n, cpp::MemoryOrder::RELAXED) + n;
+      return (count & INVALID) == 0;
+    }
+
+    // Release a slot in the reference counter. This function should only be
+    // called following a valid acquire call.
+    bool release(uint32_t n) {
+      // If this thread caused the counter to reach zero we try to invalidate it
+      // and obtain exclusive rights to deconstruct it. If the CAS failed either
+      // another thread resurrected the counter and we quit, or a parallel read
+      // helped us invalidating it. For the latter, claim that flag and return.
+      if (counter.fetch_sub(n, cpp::MemoryOrder::RELAXED) == n) {
+        uint64_t expected = 0;
+        if (counter.compare_exchange_strong(expected, INVALID,
+                                            cpp::MemoryOrder::RELAXED,
+                                            cpp::MemoryOrder::RELAXED))
+          return true;
+        else if ((expected & HELPED) &&
+                 (counter.exchange(INVALID, cpp::MemoryOrder::RELAXED) &
+                  HELPED))
+          return true;
+      }
+      return false;
+    }
+
+    // Returns the current reference count, potentially helping a releasing
+    // thread.
+    uint64_t read() {
+      auto val = counter.load(cpp::MemoryOrder::RELAXED);
+      if (val == 0 && counter.compare_exchange_strong(
+                          val, INVALID | HELPED, cpp::MemoryOrder::RELAXED))
+        return 0;
+      return (val & INVALID) ? 0 : val;
+    }
+
+    cpp::Atomic<uint64_t> counter{0};
+  };
+
+  cpp::Atomic<T *> ptr{nullptr};
+  RefCounter ref{};
+
+  // Should be called be a single lane for each different pointer.
+  template <typename... Args>
+  T *try_lock_impl(uint32_t n, uint64_t &count, Args &&...args) {
+    T *expected = ptr.load(cpp::MemoryOrder::RELAXED);
+    if (!expected &&
+        ptr.compare_exchange_strong(expected, reinterpret_cast<T *>(SENTINEL),
+                                    cpp::MemoryOrder::RELAXED,
+                                    cpp::MemoryOrder::RELAXED)) {
+      count = cpp::numeric_limits<uint64_t>::max();
+      void *raw = impl::rpc_allocate(sizeof(T));
+      if (!raw)
+        return nullptr;
+      T *mem = new (raw) T(cpp::forward<Args>(args)...);
+
+      cpp::atomic_thread_fence(cpp::MemoryOrder::RELEASE);
+      ptr.store(mem, cpp::MemoryOrder::RELAXED);
+      cpp::atomic_thread_fence(cpp::MemoryOrder::ACQUIRE);
+      if (!ref.acquire(n, count))
+        ref.reset(n, count);
+      return mem;
+    }
+
+    if (!expected || expected == reinterpret_cast<T *>(SENTINEL))
+      return nullptr;
+
+    if (!ref.acquire(n, count))
+      return nullptr;
+
+    cpp::atomic_thread_fence(cpp::MemoryOrder::ACQUIRE);
+    return ptr.load(cpp::MemoryOrder::RELAXED);
+  }
+
+public:
+  // Attempt to lock access to the pointer, potentially creating it if empty.
+  // The uniform mask represents which lanes share the same pointer. For each
+  // uniform value we elect a leader to handle it on behalf of the other lanes.
+  template <typename... Args>
+  T *try_lock(uint64_t lane_mask, uint64_t uniform, uint64_t &count,
+              Args &&...args) {
+    count = 0;
+    T *result = nullptr;
+    if (gpu::get_lane_id() == uint32_t(cpp::countr_zero(uniform)))
+      result = try_lock_impl(cpp::popcount(uniform), count,
+                             cpp::forward<Args>(args)...);
+    result = gpu::shuffle(lane_mask, cpp::countr_zero(uniform), result);
+    count = gpu::shuffle(lane_mask, cpp::countr_zero(uniform), count);
+
+    if (!result)
+      return nullptr;
+
+    if (count != cpp::numeric_limits<uint64_t>::max())
+      count = count - cpp::popcount(uniform) + impl::lane_count(uniform) + 1;
+
+    return result;
+  }
+
+  // Release the associated lock on the pointer, potentially destroying it.
+  void unlock(uint64_t lane_mask, uint64_t mask) {
+    cpp::atomic_thread_fence(cpp::MemoryOrder::RELEASE);
+    if (gpu::get_lane_id() == uint32_t(cpp::countr_zero(mask)) &&
+        ref.release(cpp::popcount(mask))) {
+      T *p = ptr.load(cpp::MemoryOrder::RELAXED);
+      p->~T();
+      impl::rpc_free(p);
+      cpp::atomic_thread_fence(cpp::MemoryOrder::RELEASE);
+      ptr.store(nullptr, cpp::MemoryOrder::RELAXED);
+    }
+    gpu::sync_lane(lane_mask);
+  }
+
+  // Get the current value of the reference counter.
+  uint64_t use_count() { return ref.read(); }
+};
+
+// The global array used to search for a valid slab to allocate from.
+static GuardPtr<Slab> slots[ARRAY_SIZE] = {};
+
+// Tries to find a slab in the table that can support the given chunk size.
+static Slab *find_slab(uint32_t chunk_size) {
+  // We start at a hashed value to spread out different chunk sizes.
+  uint32_t start = impl::hash(chunk_size);
+  uint64_t lane_mask = gpu::get_lane_mask();
+  uint64_t uniform = gpu::match_any(lane_mask, chunk_size);
+
+  Slab *result = nullptr;
+  uint32_t nudge = 0;
+  for (uint64_t mask = lane_mask; mask;
+       mask = gpu::ballot(lane_mask, !result), ++nudge) {
+    uint32_t index = cpp::numeric_limits<uint32_t>::max();
+    for (uint32_t offset = nudge / MAX_TRIES;
+         gpu::ballot(lane_mask, index == cpp::numeric_limits<uint32_t>::max());
+         offset += cpp::popcount(uniform & lane_mask)) {
+      uint32_t candidate =
+          (start + offset + impl::lane_count(uniform & lane_mask)) % ARRAY_SIZE;
+      uint64_t available =
+          gpu::ballot(lane_mask, slots[candidate].use_count() <
+                                     Slab::available_chunks(chunk_size));
+      uint32_t new_index = gpu::shuffle(
+          lane_mask, cpp::countr_zero(available & uniform), candidate);
+
+      // Each uniform group will use the first empty slot they find.
+      if ((index == cpp::numeric_limits<uint32_t>::max() &&
+           (available & uniform)))
+        index = new_index;
+
+      // Guaruntees that this loop will eventuall exit if there is no space.
+      if (offset >= ARRAY_SIZE) {
+        result = reinterpret_cast<Slab *>(SENTINEL);
+        index = 0;
+      }
+    }
+
+    // Try to claim a slot for the found slot.
+    if (!result) {
+      uint64_t reserved = 0;
+      Slab *slab = slots[index].try_lock(lane_mask & mask, uniform & mask,
+                                         reserved, chunk_size, index);
+      // If we find a slab with a matching chunk size then we store the result.
+      // Otherwise, we need to free the claimed lock and continue. In the case
+      // of out-of-memory we return a sentinel value.
+      if (slab && reserved <= Slab::available_chunks(chunk_size) &&
+          slab->get_chunk_size() == chunk_size) {
+        result = slab;
+      } else if (slab && (reserved > Slab::available_chunks(chunk_size) ||
+                          slab->get_chunk_size() != chunk_size)) {
+        if (slab->get_chunk_size() != chunk_size)
+          start = index + 1;
+        slots[index].unlock(gpu::get_lane_mask(),
+                            gpu::get_lane_mask() & uniform);
+      } else if (!slab && reserved == cpp::numeric_limits<uint64_t>::max()) {
+        result = reinterpret_cast<Slab *>(SENTINEL);
+      } else {
+        sleep_briefly();
+      }
+    }
+  }
+  return result;
+}
+
+// Release the lock associated with a given slab.
+static void release_slab(Slab *slab) {
+  uint32_t index = slab->get_global_index();
+  uint64_t lane_mask = gpu::get_lane_mask();
+  uint64_t uniform = gpu::match_any(lane_mask, index);
+  slots[index].unlock(lane_mask, uniform);
+}
 
 namespace gpu {
 
-void *allocate(uint64_t size) { return rpc_allocate(size); }
+void *allocate(uint64_t size) {
+  if (!size)
+    return nullptr;
+
+  // Allocations requiring a full slab or more go directly to memory.
+  if (size >= SLAB_SIZE / 2)
+    return impl::rpc_allocate(impl::round_up<SLAB_SIZE>(size));
+
+  // Try to find a slab for the rounded up chunk size and allocate from it.
+  uint32_t chunk_size = impl::get_chunk_size(static_cast<uint32_t>(size));
+  Slab *slab = find_slab(chunk_size);
+  if (!slab || slab == reinterpret_cast<Slab *>(SENTINEL))
+    return nullptr;
+
+  uint64_t lane_mask = gpu::get_lane_mask();
+  uint64_t uniform = gpu::match_any(lane_mask, slab->get_global_index());
+  void *ptr = slab->allocate(lane_mask, uniform);
+  return ptr;
+}
+
+void deallocate(void *ptr) {
+  if (!ptr)
+    return;
 
-void deallocate(void *ptr) { rpc_free(ptr); }
+  // All non-slab allocations will be aligned on a 2MiB boundary.
+  if ((reinterpret_cast<uintptr_t>(ptr) & SLAB_ALIGNMENT) == 0)
+    return impl::rpc_free(ptr);
+
+  // The original slab pointer is the 2MiB boundary using the given pointer.
+  Slab *slab = reinterpret_cast<Slab *>(
+      (reinterpret_cast<uintptr_t>(ptr) & ~SLAB_ALIGNMENT));
+  slab->deallocate(ptr);
+  release_slab(slab);
+}
 
 } // namespace gpu
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/__support/GPU/utils.h b/src/__support/GPU/utils.h
index 0fd3a64..1b3e6ed 100644
--- a/src/__support/GPU/utils.h
+++ b/src/__support/GPU/utils.h
@@ -92,6 +92,18 @@ LIBC_INLINE uint32_t shuffle(uint64_t lane_mask, uint32_t idx, uint32_t x,
   return __gpu_shuffle_idx_u32(lane_mask, idx, x, width);
 }
 
+LIBC_INLINE uint64_t shuffle(uint64_t lane_mask, uint32_t idx, uint64_t x,
+                             uint32_t width = __gpu_num_lanes()) {
+  return __gpu_shuffle_idx_u64(lane_mask, idx, x, width);
+}
+
+template <typename T>
+LIBC_INLINE T *shuffle(uint64_t lane_mask, uint32_t idx, T *x,
+                       uint32_t width = __gpu_num_lanes()) {
+  return reinterpret_cast<T *>(__gpu_shuffle_idx_u64(
+      lane_mask, idx, reinterpret_cast<uintptr_t>(x), width));
+}
+
 LIBC_INLINE uint64_t match_any(uint64_t lane_mask, uint32_t x) {
   return __gpu_match_any_u32(lane_mask, x);
 }
diff --git a/src/__support/HashTable/table.h b/src/__support/HashTable/table.h
index d50a948..13badb9 100644
--- a/src/__support/HashTable/table.h
+++ b/src/__support/HashTable/table.h
@@ -9,7 +9,7 @@
 #ifndef LLVM_LIBC_SRC___SUPPORT_HASHTABLE_TABLE_H
 #define LLVM_LIBC_SRC___SUPPORT_HASHTABLE_TABLE_H
 
-#include "include/llvm-libc-types/ENTRY.h"
+#include "hdr/types/ENTRY.h"
 #include "src/__support/CPP/bit.h" // bit_ceil
 #include "src/__support/CPP/new.h"
 #include "src/__support/HashTable/bitmask.h"
diff --git a/src/__support/OSUtil/darwin/arm/syscall.h b/src/__support/OSUtil/darwin/aarch64/syscall.h
similarity index 100%
rename from src/__support/OSUtil/darwin/arm/syscall.h
rename to src/__support/OSUtil/darwin/aarch64/syscall.h
diff --git a/src/__support/OSUtil/darwin/syscall.h b/src/__support/OSUtil/darwin/syscall.h
index eab9636..463407d 100644
--- a/src/__support/OSUtil/darwin/syscall.h
+++ b/src/__support/OSUtil/darwin/syscall.h
@@ -15,7 +15,7 @@
 #include "src/__support/macros/properties/architectures.h"
 
 #ifdef LIBC_TARGET_ARCH_IS_ANY_ARM
-#include "arm/syscall.h"
+#include "aarch64/syscall.h"
 #else
 #error "Unsupported architecture"
 #endif
diff --git a/src/__support/OSUtil/uefi/error.h b/src/__support/OSUtil/uefi/error.h
new file mode 100644
index 0000000..9fdc569
--- /dev/null
+++ b/src/__support/OSUtil/uefi/error.h
@@ -0,0 +1,104 @@
+//===----------- UEFI implementation of error utils --------------*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC___SUPPORT_OSUTIL_UEFI_ERROR_H
+#define LLVM_LIBC_SRC___SUPPORT_OSUTIL_UEFI_ERROR_H
+
+#include "hdr/errno_macros.h"
+#include "include/llvm-libc-types/EFI_STATUS.h"
+#include "src/__support/CPP/array.h"
+#include "src/__support/CPP/limits.h"
+#include "src/__support/macros/attributes.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+static constexpr int EFI_ERROR_MAX_BIT = cpp::numeric_limits<EFI_STATUS>::max();
+
+static constexpr int EFI_ENCODE_ERROR(int value) {
+  return EFI_ERROR_MAX_BIT | (EFI_ERROR_MAX_BIT >> 2) | (value);
+}
+
+static constexpr int EFI_ENCODE_WARNING(int value) {
+  return (EFI_ERROR_MAX_BIT >> 2) | (value);
+}
+
+struct UefiStatusErrnoEntry {
+  EFI_STATUS status;
+  int errno_value;
+};
+
+static constexpr cpp::array<UefiStatusErrnoEntry, 43> UEFI_STATUS_ERRNO_MAP = {{
+    {EFI_SUCCESS, 0},
+    {EFI_ENCODE_ERROR(EFI_LOAD_ERROR), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_INVALID_PARAMETER), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_BAD_BUFFER_SIZE), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_NOT_READY), EBUSY},
+    {EFI_ENCODE_ERROR(EFI_DEVICE_ERROR), EIO},
+    {EFI_ENCODE_ERROR(EFI_WRITE_PROTECTED), EPERM},
+    {EFI_ENCODE_ERROR(EFI_OUT_OF_RESOURCES), ENOMEM},
+    {EFI_ENCODE_ERROR(EFI_VOLUME_CORRUPTED), EROFS},
+    {EFI_ENCODE_ERROR(EFI_VOLUME_FULL), ENOSPC},
+    {EFI_ENCODE_ERROR(EFI_NO_MEDIA), ENODEV},
+    {EFI_ENCODE_ERROR(EFI_MEDIA_CHANGED), ENXIO},
+    {EFI_ENCODE_ERROR(EFI_NOT_FOUND), ENOENT},
+    {EFI_ENCODE_ERROR(EFI_ACCESS_DENIED), EACCES},
+    {EFI_ENCODE_ERROR(EFI_NO_RESPONSE), EBUSY},
+    {EFI_ENCODE_ERROR(EFI_NO_MAPPING), ENODEV},
+    {EFI_ENCODE_ERROR(EFI_TIMEOUT), EBUSY},
+    {EFI_ENCODE_ERROR(EFI_NOT_STARTED), EAGAIN},
+    {EFI_ENCODE_ERROR(EFI_ALREADY_STARTED), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_ABORTED), EFAULT},
+    {EFI_ENCODE_ERROR(EFI_ICMP_ERROR), EIO},
+    {EFI_ENCODE_ERROR(EFI_TFTP_ERROR), EIO},
+    {EFI_ENCODE_ERROR(EFI_PROTOCOL_ERROR), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_INCOMPATIBLE_VERSION), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_SECURITY_VIOLATION), EPERM},
+    {EFI_ENCODE_ERROR(EFI_CRC_ERROR), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_END_OF_MEDIA), EPIPE},
+    {EFI_ENCODE_ERROR(EFI_END_OF_FILE), EPIPE},
+    {EFI_ENCODE_ERROR(EFI_INVALID_LANGUAGE), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_COMPROMISED_DATA), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_IP_ADDRESS_CONFLICT), EINVAL},
+    {EFI_ENCODE_ERROR(EFI_HTTP_ERROR), EIO},
+    {EFI_ENCODE_WARNING(EFI_WARN_UNKNOWN_GLYPH), EINVAL},
+    {EFI_ENCODE_WARNING(EFI_WARN_DELETE_FAILURE), EROFS},
+    {EFI_ENCODE_WARNING(EFI_WARN_WRITE_FAILURE), EROFS},
+    {EFI_ENCODE_WARNING(EFI_WARN_BUFFER_TOO_SMALL), E2BIG},
+    {EFI_ENCODE_WARNING(EFI_WARN_STALE_DATA), EINVAL},
+    {EFI_ENCODE_WARNING(EFI_WARN_FILE_SYSTEM), EROFS},
+    {EFI_ENCODE_WARNING(EFI_WARN_RESET_REQUIRED), EINTR},
+}};
+
+LIBC_INLINE int uefi_status_to_errno(EFI_STATUS status) {
+  for (auto it = UEFI_STATUS_ERRNO_MAP.begin();
+       it != UEFI_STATUS_ERRNO_MAP.end(); it++) {
+    const struct UefiStatusErrnoEntry entry = *it;
+    if (entry.status == status)
+      return entry.errno_value;
+  }
+
+  // Unknown type
+  return EINVAL;
+}
+
+LIBC_INLINE EFI_STATUS errno_to_uefi_status(int errno_value) {
+  for (auto it = UEFI_STATUS_ERRNO_MAP.begin();
+       it != UEFI_STATUS_ERRNO_MAP.end(); it++) {
+    const struct UefiStatusErrnoEntry entry = *it;
+    if (entry.errno_value == errno_value)
+      return entry.status;
+  }
+
+  // Unknown type
+  return EFI_INVALID_PARAMETER;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC___SUPPORT_OSUTIL_UEFI_ERROR_H
diff --git a/src/__support/OSUtil/uefi/exit.cpp b/src/__support/OSUtil/uefi/exit.cpp
index 432f69a..e734983 100644
--- a/src/__support/OSUtil/uefi/exit.cpp
+++ b/src/__support/OSUtil/uefi/exit.cpp
@@ -7,14 +7,16 @@
 //===-----------------------------------------------------------------===//
 
 #include "src/__support/OSUtil/exit.h"
-#include "include/Uefi.h"
+#include "config/uefi.h"
+#include "include/llvm-libc-types/EFI_SYSTEM_TABLE.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 namespace internal {
 
 [[noreturn]] void exit(int status) {
-  efi_system_table->BootServices->Exit(efi_image_handle, status, 0, nullptr);
+  app.system_table->BootServices->Exit(__llvm_libc_efi_image_handle, status, 0,
+                                       nullptr);
   __builtin_unreachable();
 }
 
diff --git a/src/__support/OSUtil/uefi/io.cpp b/src/__support/OSUtil/uefi/io.cpp
index 756c5aa..e1e50fb 100644
--- a/src/__support/OSUtil/uefi/io.cpp
+++ b/src/__support/OSUtil/uefi/io.cpp
@@ -8,19 +8,24 @@
 
 #include "io.h"
 
+#include "Uefi.h"
+#include "config/app.h"
 #include "src/__support/CPP/string_view.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-ssize_t read_from_stdin(char *buf, size_t size) { return 0; }
+ssize_t read_from_stdin([[gnu::unused]] char *buf,
+                        [[gnu::unused]] size_t size) {
+  return 0;
+}
 
 void write_to_stdout(cpp::string_view msg) {
   // TODO: use mbstowcs once implemented
   for (size_t i = 0; i < msg.size(); i++) {
     char16_t e[2] = {msg[i], 0};
-    efi_system_table->ConOut->OutputString(
-        efi_system_table->ConOut, reinterpret_cast<const char16_t *>(&e));
+    app.system_table->ConOut->OutputString(
+        app.system_table->ConOut, reinterpret_cast<const char16_t *>(&e));
   }
 }
 
@@ -28,8 +33,8 @@ void write_to_stderr(cpp::string_view msg) {
   // TODO: use mbstowcs once implemented
   for (size_t i = 0; i < msg.size(); i++) {
     char16_t e[2] = {msg[i], 0};
-    efi_system_table->StdErr->OutputString(
-        efi_system_table->StdErr, reinterpret_cast<const char16_t *>(&e));
+    app.system_table->StdErr->OutputString(
+        app.system_table->StdErr, reinterpret_cast<const char16_t *>(&e));
   }
 }
 
diff --git a/src/__support/common.h b/src/__support/common.h
index 42e8a79..15209b7 100644
--- a/src/__support/common.h
+++ b/src/__support/common.h
@@ -37,17 +37,27 @@
 
 #define LLVM_LIBC_ATTR(name) EXPAND_THEN_SECOND(LLVM_LIBC_FUNCTION_ATTR_##name)
 
-// MacOS needs to be excluded because it does not support aliasing.
-#if defined(LIBC_COPT_PUBLIC_PACKAGING) && (!defined(__APPLE__))
+// At the moment, [[gnu::alias()]] is not supported on MacOS, and it is needed
+// to cleanly export and alias the C++ symbol `LIBC_NAMESPACE::func` with the C
+// symbol `func`.  So for public packaging on MacOS, we will only export the C
+// symbol.  Moreover, a C symbol `func` in macOS is mangled as `_func`.
+#if defined(LIBC_COPT_PUBLIC_PACKAGING)
+#ifndef __APPLE__
 #define LLVM_LIBC_FUNCTION_IMPL(type, name, arglist)                           \
   LLVM_LIBC_ATTR(name)                                                         \
   LLVM_LIBC_FUNCTION_ATTR decltype(LIBC_NAMESPACE::name)                       \
       __##name##_impl__ __asm__(#name);                                        \
   decltype(LIBC_NAMESPACE::name) name [[gnu::alias(#name)]];                   \
   type __##name##_impl__ arglist
-#else
+#else // __APPLE__
+#define LLVM_LIBC_FUNCTION_IMPL(type, name, arglist)                           \
+  LLVM_LIBC_ATTR(name)                                                         \
+  LLVM_LIBC_FUNCTION_ATTR decltype(LIBC_NAMESPACE::name) name asm("_" #name);  \
+  type name arglist
+#endif // __APPLE__
+#else  // LIBC_COPT_PUBLIC_PACKAGING
 #define LLVM_LIBC_FUNCTION_IMPL(type, name, arglist) type name arglist
-#endif
+#endif // LIBC_COPT_PUBLIC_PACKAGING
 
 // This extra layer of macro allows `name` to be a macro to rename a function.
 #define LLVM_LIBC_FUNCTION(type, name, arglist)                                \
diff --git a/src/__support/fixed_point/fx_bits.h b/src/__support/fixed_point/fx_bits.h
index b05f46b..00c6119 100644
--- a/src/__support/fixed_point/fx_bits.h
+++ b/src/__support/fixed_point/fx_bits.h
@@ -15,6 +15,7 @@
 #include "src/__support/CPP/type_traits.h"
 #include "src/__support/macros/attributes.h"   // LIBC_INLINE
 #include "src/__support/macros/config.h"       // LIBC_NAMESPACE_DECL
+#include "src/__support/macros/null_check.h"   // LIBC_CRASH_ON_VALUE
 #include "src/__support/macros/optimization.h" // LIBC_UNLIKELY
 #include "src/__support/math_extras.h"
 
@@ -201,6 +202,28 @@ bitsfx(T f) {
   return cpp::bit_cast<XType, T>(f);
 }
 
+// divide the two fixed-point types and return an integer result
+template <typename T, typename XType>
+LIBC_INLINE constexpr cpp::enable_if_t<cpp::is_fixed_point_v<T>, XType>
+idiv(T x, T y) {
+  using FXBits = FXBits<T>;
+  using FXRep = FXRep<T>;
+  using CompType = typename FXRep::CompType;
+
+  // If the value of the second operand of the / operator is zero, the
+  // behavior is undefined. Ref: ISO/IEC TR 18037:2008(E) p.g. 16
+  LIBC_CRASH_ON_VALUE(y, FXRep::ZERO());
+
+  CompType x_comp = static_cast<CompType>(FXBits(x).get_bits());
+  CompType y_comp = static_cast<CompType>(FXBits(y).get_bits());
+
+  // If an integer result of one of these functions overflows, the behavior is
+  // undefined. Ref: ISO/IEC TR 18037:2008(E) p.g. 16
+  CompType result = x_comp / y_comp;
+
+  return static_cast<XType>(result);
+}
+
 } // namespace fixed_point
 } // namespace LIBC_NAMESPACE_DECL
 
diff --git a/src/__support/float_to_string.h b/src/__support/float_to_string.h
index 4b03eaf..d88bf84 100644
--- a/src/__support/float_to_string.h
+++ b/src/__support/float_to_string.h
@@ -491,7 +491,7 @@ public:
 
   LIBC_INLINE constexpr BlockInt get_negative_block(int block_index) {
     if (exponent < 0) {
-      const int32_t idx = -exponent / IDX_SIZE;
+      const int32_t idx = -exponent / static_cast<int32_t>(IDX_SIZE);
 
       UInt<MID_INT_SIZE> val;
 
@@ -579,7 +579,7 @@ public:
 
     return num_requested_digits > -exponent;
 #else
-    const int32_t idx = -exponent / IDX_SIZE;
+    const int32_t idx = -exponent / static_cast<int32_t>(IDX_SIZE);
     const size_t p =
         POW10_OFFSET_2[idx] + negative_block_index - MIN_BLOCK_2[idx];
     // If the remaining digits are all 0, then this is the lowest block.
@@ -601,7 +601,7 @@ public:
     }
     return 0;
 #else
-    return MIN_BLOCK_2[-exponent / IDX_SIZE];
+    return MIN_BLOCK_2[-exponent / static_cast<int32_t>(IDX_SIZE)];
 #endif
   }
 };
diff --git a/src/__support/libc_assert.h b/src/__support/libc_assert.h
index 3db179f..ada1795 100644
--- a/src/__support/libc_assert.h
+++ b/src/__support/libc_assert.h
@@ -9,7 +9,6 @@
 #ifndef LLVM_LIBC_SRC___SUPPORT_LIBC_ASSERT_H
 #define LLVM_LIBC_SRC___SUPPORT_LIBC_ASSERT_H
 
-#include "src/__support/macros/config.h"
 #if defined(LIBC_COPT_USE_C_ASSERT) || !defined(LIBC_FULL_BUILD)
 
 // The build is configured to just use the public <assert.h> API
@@ -25,6 +24,7 @@
 #include "src/__support/OSUtil/io.h"
 #include "src/__support/integer_to_string.h"
 #include "src/__support/macros/attributes.h"   // For LIBC_INLINE
+#include "src/__support/macros/config.h"
 #include "src/__support/macros/optimization.h" // For LIBC_UNLIKELY
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/__support/macros/null_check.h b/src/__support/macros/null_check.h
index eda19f8..abf65c5 100644
--- a/src/__support/macros/null_check.h
+++ b/src/__support/macros/null_check.h
@@ -19,10 +19,19 @@
     if (LIBC_UNLIKELY((ptr) == nullptr))                                       \
       __builtin_trap();                                                        \
   } while (0)
+#define LIBC_CRASH_ON_VALUE(var, value)                                        \
+  do {                                                                         \
+    if (LIBC_UNLIKELY((var) == (value)))                                       \
+      __builtin_trap();                                                        \
+  } while (0)
+
 #else
 #define LIBC_CRASH_ON_NULLPTR(ptr)                                             \
   do {                                                                         \
   } while (0)
+#define LIBC_CRASH_ON_VALUE(var, value)                                        \
+  do {                                                                         \
+  } while (0)
 #endif
 
 #endif // LLVM_LIBC_SRC___SUPPORT_MACROS_NULL_CHECK_H
diff --git a/src/__support/macros/properties/cpu_features.h b/src/__support/macros/properties/cpu_features.h
index 1714775..3677e1f 100644
--- a/src/__support/macros/properties/cpu_features.h
+++ b/src/__support/macros/properties/cpu_features.h
@@ -20,6 +20,8 @@
 
 #if defined(__SSE2__)
 #define LIBC_TARGET_CPU_HAS_SSE2
+#define LIBC_TARGET_CPU_HAS_FPU_FLOAT
+#define LIBC_TARGET_CPU_HAS_FPU_DOUBLE
 #endif
 
 #if defined(__SSE4_2__)
@@ -42,24 +44,55 @@
 #define LIBC_TARGET_CPU_HAS_AVX512BW
 #endif
 
+#if defined(__ARM_FP)
+#if (__ARM_FP & 0x2)
+#define LIBC_TARGET_CPU_HAS_ARM_FPU_HALF
+#define LIBC_TARGET_CPU_HAS_FPU_HALF
+#endif // LIBC_TARGET_CPU_HAS_ARM_FPU_HALF
+#if (__ARM_FP & 0x4)
+#define LIBC_TARGET_CPU_HAS_ARM_FPU_FLOAT
+#define LIBC_TARGET_CPU_HAS_FPU_FLOAT
+#endif // LIBC_TARGET_CPU_HAS_ARM_FPU_FLOAT
+#if (__ARM_FP & 0x8)
+#define LIBC_TARGET_CPU_HAS_ARM_FPU_DOUBLE
+#define LIBC_TARGET_CPU_HAS_FPU_DOUBLE
+#endif // LIBC_TARGET_CPU_HAS_ARM_FPU_DOUBLE
+#endif // __ARM_FP
+
+#if defined(__riscv_flen)
+// https://github.com/riscv-non-isa/riscv-c-api-doc/blob/main/src/c-api.adoc
+#if (__riscv_flen & 0x10)
+#define LIBC_TARGET_CPU_HAS_RISCV_FPU_HALF
+#define LIBC_TARGET_CPU_HAS_FPU_HALF
+#endif // LIBC_TARGET_CPU_HAS_RISCV_FPU_HALF
+#if (__riscv_flen & 0x20)
+#define LIBC_TARGET_CPU_HAS_RISCV_FPU_FLOAT
+#define LIBC_TARGET_CPU_HAS_FPU_FLOAT
+#endif // LIBC_TARGET_CPU_HAS_RISCV_FPU_FLOAT
+#if (__riscv_flen & 0x40)
+#define LIBC_TARGET_CPU_HAS_RISCV_FPU_DOUBLE
+#define LIBC_TARGET_CPU_HAS_FPU_DOUBLE
+#endif // LIBC_TARGET_CPU_HAS_RISCV_FPU_DOUBLE
+#endif // __riscv_flen
+
+#if defined(__NVPTX__) || defined(__AMDGPU__)
+#define LIBC_TARGET_CPU_HAS_FPU_FLOAT
+#define LIBC_TARGET_CPU_HAS_FPU_DOUBLE
+#endif
+
 #if defined(__ARM_FEATURE_FMA) || (defined(__AVX2__) && defined(__FMA__)) ||   \
     defined(__NVPTX__) || defined(__AMDGPU__) || defined(__LIBC_RISCV_USE_FMA)
 #define LIBC_TARGET_CPU_HAS_FMA
 // Provide a more fine-grained control of FMA instruction for ARM targets.
-#if defined(__ARM_FP)
-#if (__ARM_FP & 0x2)
+#if defined(LIBC_TARGET_CPU_HAS_FPU_HALF)
 #define LIBC_TARGET_CPU_HAS_FMA_HALF
 #endif // LIBC_TARGET_CPU_HAS_FMA_HALF
-#if (__ARM_FP & 0x4)
+#if defined(LIBC_TARGET_CPU_HAS_FPU_FLOAT)
 #define LIBC_TARGET_CPU_HAS_FMA_FLOAT
 #endif // LIBC_TARGET_CPU_HAS_FMA_FLOAT
-#if (__ARM_FP & 0x8)
+#if defined(LIBC_TARGET_CPU_HAS_FPU_DOUBLE)
 #define LIBC_TARGET_CPU_HAS_FMA_DOUBLE
 #endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
-#else
-#define LIBC_TARGET_CPU_HAS_FMA_FLOAT
-#define LIBC_TARGET_CPU_HAS_FMA_DOUBLE
-#endif
 #endif
 
 #if defined(LIBC_TARGET_ARCH_IS_AARCH64) ||                                    \
diff --git a/src/__support/str_to_float.h b/src/__support/str_to_float.h
index 48c8830..0748e1c 100644
--- a/src/__support/str_to_float.h
+++ b/src/__support/str_to_float.h
@@ -15,6 +15,7 @@
 #ifndef LLVM_LIBC_SRC___SUPPORT_STR_TO_FLOAT_H
 #define LLVM_LIBC_SRC___SUPPORT_STR_TO_FLOAT_H
 
+#include "hdr/errno_macros.h" // For ERANGE
 #include "src/__support/CPP/bit.h"
 #include "src/__support/CPP/limits.h"
 #include "src/__support/CPP/optional.h"
@@ -31,7 +32,6 @@
 #include "src/__support/str_to_integer.h"
 #include "src/__support/str_to_num_result.h"
 #include "src/__support/uint128.h"
-#include "src/errno/libc_errno.h" // For ERANGE
 
 #include <stdint.h>
 
diff --git a/src/__support/str_to_integer.h b/src/__support/str_to_integer.h
index 9212ad2..76a99a8 100644
--- a/src/__support/str_to_integer.h
+++ b/src/__support/str_to_integer.h
@@ -15,6 +15,7 @@
 #ifndef LLVM_LIBC_SRC___SUPPORT_STR_TO_INTEGER_H
 #define LLVM_LIBC_SRC___SUPPORT_STR_TO_INTEGER_H
 
+#include "hdr/errno_macros.h" // For ERANGE
 #include "src/__support/CPP/limits.h"
 #include "src/__support/CPP/type_traits.h"
 #include "src/__support/CPP/type_traits/make_unsigned.h"
@@ -24,7 +25,6 @@
 #include "src/__support/macros/config.h"
 #include "src/__support/str_to_num_result.h"
 #include "src/__support/uint128.h"
-#include "src/errno/libc_errno.h" // For ERANGE
 
 namespace LIBC_NAMESPACE_DECL {
 namespace internal {
diff --git a/src/math/acoshf16.h b/src/math/acoshf16.h
new file mode 100644
index 0000000..f471ecf
--- /dev/null
+++ b/src/math/acoshf16.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for acoshf16 ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_ACOSHF16_H
+#define LLVM_LIBC_SRC_MATH_ACOSHF16_H
+
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+float16 acoshf16(float16 x);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_ACOSHF16_H
diff --git a/src/math/acospif16.h b/src/math/acospif16.h
new file mode 100644
index 0000000..e94a35b
--- /dev/null
+++ b/src/math/acospif16.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for acospif16 ---------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_ACOSPIF16_H
+#define LLVM_LIBC_SRC_MATH_ACOSPIF16_H
+
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+float16 acospif16(float16 x);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_ACOSPIF16_H
diff --git a/src/math/amdgpu/asin.cpp b/src/math/amdgpu/asin.cpp
deleted file mode 100644
index a79641e..0000000
--- a/src/math/amdgpu/asin.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU asin function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/asin.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, asin, (double x)) { return __ocml_asin_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/asinf.cpp b/src/math/amdgpu/asinf.cpp
deleted file mode 100644
index e70944a..0000000
--- a/src/math/amdgpu/asinf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the asinf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/asinf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, asinf, (float x)) { return __ocml_asin_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/asinh.cpp b/src/math/amdgpu/asinh.cpp
deleted file mode 100644
index 6423685..0000000
--- a/src/math/amdgpu/asinh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU asinh function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/asinh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, asinh, (double x)) { return __ocml_asinh_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/asinhf.cpp b/src/math/amdgpu/asinhf.cpp
deleted file mode 100644
index bafa77f..0000000
--- a/src/math/amdgpu/asinhf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the asinhf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/asinhf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, asinhf, (float x)) { return __ocml_asinh_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/atan.cpp b/src/math/amdgpu/atan.cpp
deleted file mode 100644
index 49941e9..0000000
--- a/src/math/amdgpu/atan.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU atan function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atan.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, atan, (double x)) { return __ocml_atan_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/atanf.cpp b/src/math/amdgpu/atanf.cpp
deleted file mode 100644
index ab1837d..0000000
--- a/src/math/amdgpu/atanf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the atanf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atanf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, atanf, (float x)) { return __ocml_atan_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/atanh.cpp b/src/math/amdgpu/atanh.cpp
deleted file mode 100644
index 091c155..0000000
--- a/src/math/amdgpu/atanh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU atanh function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atanh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, atanh, (double x)) { return __ocml_atanh_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/atanhf.cpp b/src/math/amdgpu/atanhf.cpp
deleted file mode 100644
index fa9cf39..0000000
--- a/src/math/amdgpu/atanhf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the atanhf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atanhf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, atanhf, (float x)) { return __ocml_atanh_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/cos.cpp b/src/math/amdgpu/cos.cpp
deleted file mode 100644
index a4d4c94..0000000
--- a/src/math/amdgpu/cos.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the cos function for GPU ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/cos.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, cos, (double x)) { return __ocml_cos_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/cosf.cpp b/src/math/amdgpu/cosf.cpp
deleted file mode 100644
index 99ec118..0000000
--- a/src/math/amdgpu/cosf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the cosf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/cosf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, cosf, (float x)) { return __ocml_cos_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/cosh.cpp b/src/math/amdgpu/cosh.cpp
deleted file mode 100644
index d94d7af..0000000
--- a/src/math/amdgpu/cosh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the cosh function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/cosh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, cosh, (double x)) { return __ocml_cosh_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/coshf.cpp b/src/math/amdgpu/coshf.cpp
deleted file mode 100644
index 5b641be..0000000
--- a/src/math/amdgpu/coshf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the coshf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/coshf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, coshf, (float x)) { return __ocml_cosh_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/declarations.h b/src/math/amdgpu/declarations.h
deleted file mode 100644
index 88e2201..0000000
--- a/src/math/amdgpu/declarations.h
+++ /dev/null
@@ -1,91 +0,0 @@
-//===-- AMDGPU specific declarations for math support ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_SRC_MATH_AMDGPU_DECLARATIONS_H
-#define LLVM_LIBC_SRC_MATH_AMDGPU_DECLARATIONS_H
-
-#include "platform.h"
-
-#include "src/__support/GPU/utils.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-extern "C" {
-float __ocml_acos_f32(float);
-double __ocml_acos_f64(double);
-float __ocml_acosh_f32(float);
-double __ocml_acosh_f64(double);
-float __ocml_asin_f32(float);
-double __ocml_asin_f64(double);
-float __ocml_asinh_f32(float);
-double __ocml_asinh_f64(double);
-float __ocml_atan_f32(float);
-double __ocml_atan_f64(double);
-float __ocml_atan2_f32(float, float);
-double __ocml_atan2_f64(double, double);
-float __ocml_atanh_f32(float);
-double __ocml_atanh_f64(double);
-float __ocml_cos_f32(float);
-double __ocml_cos_f64(double);
-float __ocml_cosh_f32(float);
-double __ocml_cosh_f64(double);
-float __ocml_erf_f32(float);
-double __ocml_erf_f64(double);
-float __ocml_exp_f32(float);
-double __ocml_exp_f64(double);
-float __ocml_exp2_f32(float);
-double __ocml_exp2_f64(double);
-float __ocml_exp10_f32(float);
-double __ocml_exp10_f64(double);
-double __ocml_exp2_f64(double);
-float __ocml_expm1_f32(float);
-double __ocml_expm1_f64(double);
-float __ocml_fdim_f32(float, float);
-double __ocml_fdim_f64(double, double);
-float __ocml_hypot_f32(float, float);
-double __ocml_hypot_f64(double, double);
-int __ocml_ilogb_f64(double);
-int __ocml_ilogb_f32(float);
-float __ocml_ldexp_f32(float, int);
-double __ocml_ldexp_f64(double, int);
-float __ocml_log10_f32(float);
-double __ocml_log10_f64(double);
-float __ocml_log1p_f32(float);
-double __ocml_log1p_f64(double);
-float __ocml_log2_f32(float);
-double __ocml_log2_f64(double);
-float __ocml_log_f32(float);
-double __ocml_log_f64(double);
-float __ocml_nextafter_f32(float, float);
-double __ocml_nextafter_f64(double, double);
-float __ocml_pow_f32(float, float);
-double __ocml_pow_f64(double, double);
-float __ocml_pown_f32(float, int);
-double __ocml_pown_f64(double, int);
-float __ocml_sin_f32(float);
-double __ocml_sin_f64(double);
-float __ocml_sincos_f32(float, float *);
-double __ocml_sincos_f64(double, double *);
-float __ocml_sinh_f32(float);
-double __ocml_sinh_f64(double);
-float __ocml_tan_f32(float);
-double __ocml_tan_f64(double);
-float __ocml_tanh_f32(float);
-double __ocml_tanh_f64(double);
-float __ocml_remquo_f32(float, float, gpu::Private<int> *);
-double __ocml_remquo_f64(double, double, gpu::Private<int> *);
-double __ocml_tgamma_f64(double);
-float __ocml_tgamma_f32(float);
-double __ocml_lgamma_f64(double);
-double __ocml_lgamma_r_f64(double, gpu::Private<int> *);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
-
-#endif // LLVM_LIBC_SRC_MATH_AMDGPU_DECLARATIONS_H
diff --git a/src/math/amdgpu/erf.cpp b/src/math/amdgpu/erf.cpp
deleted file mode 100644
index 07ae268..0000000
--- a/src/math/amdgpu/erf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU erf function ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/erf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, erf, (double x)) { return __ocml_erf_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/erff.cpp b/src/math/amdgpu/erff.cpp
deleted file mode 100644
index a4b7b27..0000000
--- a/src/math/amdgpu/erff.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU erff function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/erff.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, erff, (float x)) { return __ocml_erf_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/exp.cpp b/src/math/amdgpu/exp.cpp
deleted file mode 100644
index dae79be..0000000
--- a/src/math/amdgpu/exp.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU exp function ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, exp, (double x)) { return __ocml_exp_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/exp10.cpp b/src/math/amdgpu/exp10.cpp
deleted file mode 100644
index f13d218..0000000
--- a/src/math/amdgpu/exp10.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU exp10 function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp10.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, exp10, (double x)) { return __ocml_exp10_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/exp10f.cpp b/src/math/amdgpu/exp10f.cpp
deleted file mode 100644
index 883e734..0000000
--- a/src/math/amdgpu/exp10f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the exp10f function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp10f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, exp10f, (float x)) { return __ocml_exp10_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/exp2.cpp b/src/math/amdgpu/exp2.cpp
deleted file mode 100644
index fb336cf..0000000
--- a/src/math/amdgpu/exp2.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU exp2 function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp2.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, exp2, (double x)) { return __ocml_exp2_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/exp2f.cpp b/src/math/amdgpu/exp2f.cpp
deleted file mode 100644
index 77b4a9c..0000000
--- a/src/math/amdgpu/exp2f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the exp2f function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp2f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, exp2f, (float x)) { return __ocml_exp2_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/expf.cpp b/src/math/amdgpu/expf.cpp
deleted file mode 100644
index 6c44aad..0000000
--- a/src/math/amdgpu/expf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the expf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/expf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, expf, (float x)) { return __ocml_exp_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/expm1.cpp b/src/math/amdgpu/expm1.cpp
deleted file mode 100644
index df3643f..0000000
--- a/src/math/amdgpu/expm1.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU expm1 function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/expm1.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, expm1, (double x)) { return __ocml_expm1_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/expm1f.cpp b/src/math/amdgpu/expm1f.cpp
deleted file mode 100644
index 2409997..0000000
--- a/src/math/amdgpu/expm1f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the expm1f function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/expm1f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, expm1f, (float x)) { return __ocml_expm1_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/frexp.cpp b/src/math/amdgpu/frexp.cpp
index 00e5187..4ae2b00 100644
--- a/src/math/amdgpu/frexp.cpp
+++ b/src/math/amdgpu/frexp.cpp
@@ -9,7 +9,6 @@
 #include "src/math/frexp.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/frexpf.cpp b/src/math/amdgpu/frexpf.cpp
index 2799e54..fd53f65 100644
--- a/src/math/amdgpu/frexpf.cpp
+++ b/src/math/amdgpu/frexpf.cpp
@@ -9,7 +9,6 @@
 #include "src/math/frexpf.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/hypot.cpp b/src/math/amdgpu/hypot.cpp
deleted file mode 100644
index dcf1152..0000000
--- a/src/math/amdgpu/hypot.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the hypot function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/hypot.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, hypot, (double x, double y)) {
-  return __ocml_hypot_f64(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/hypotf.cpp b/src/math/amdgpu/hypotf.cpp
deleted file mode 100644
index 68ec659..0000000
--- a/src/math/amdgpu/hypotf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the hypotf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/hypotf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, hypotf, (float x, float y)) {
-  return __ocml_hypot_f32(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/ilogb.cpp b/src/math/amdgpu/ilogb.cpp
deleted file mode 100644
index 37f24df..0000000
--- a/src/math/amdgpu/ilogb.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the ilogb function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/ilogb.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(int, ilogb, (double x)) { return __ocml_ilogb_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/ilogbf.cpp b/src/math/amdgpu/ilogbf.cpp
deleted file mode 100644
index 56e74e1..0000000
--- a/src/math/amdgpu/ilogbf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the ilogbf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/ilogbf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(int, ilogbf, (float x)) { return __ocml_ilogb_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/ldexp.cpp b/src/math/amdgpu/ldexp.cpp
index 393eabb..5b786a9 100644
--- a/src/math/amdgpu/ldexp.cpp
+++ b/src/math/amdgpu/ldexp.cpp
@@ -9,7 +9,6 @@
 #include "src/math/ldexp.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/ldexpf.cpp b/src/math/amdgpu/ldexpf.cpp
index 970603d..d3aa77f 100644
--- a/src/math/amdgpu/ldexpf.cpp
+++ b/src/math/amdgpu/ldexpf.cpp
@@ -9,7 +9,6 @@
 #include "src/math/ldexpf.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/lgamma.cpp b/src/math/amdgpu/lgamma.cpp
index acff4c7..9666927 100644
--- a/src/math/amdgpu/lgamma.cpp
+++ b/src/math/amdgpu/lgamma.cpp
@@ -9,11 +9,11 @@
 #include "src/math/lgamma.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, lgamma, (double x)) { return __ocml_lgamma_f64(x); }
+// TODO: Implement this.
+LLVM_LIBC_FUNCTION(double, lgamma, (double)) { return 0.0; }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/lgamma_r.cpp b/src/math/amdgpu/lgamma_r.cpp
index 0a79988..8b69ca3 100644
--- a/src/math/amdgpu/lgamma_r.cpp
+++ b/src/math/amdgpu/lgamma_r.cpp
@@ -9,16 +9,13 @@
 #include "src/math/lgamma_r.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, lgamma_r, (double x, int *signp)) {
-  int tmp = *signp;
-  double r = __ocml_lgamma_r_f64(x, (gpu::Private<int> *)&tmp);
-  *signp = tmp;
-  return r;
+LLVM_LIBC_FUNCTION(double, lgamma_r, (double, int *signp)) {
+  *signp = 0;
+  return 0;
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/llrint.cpp b/src/math/amdgpu/llrint.cpp
index 21129fe..6e0f57a 100644
--- a/src/math/amdgpu/llrint.cpp
+++ b/src/math/amdgpu/llrint.cpp
@@ -9,7 +9,6 @@
 #include "src/math/llrint.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/llrintf.cpp b/src/math/amdgpu/llrintf.cpp
index a6f9f43..d8de23f 100644
--- a/src/math/amdgpu/llrintf.cpp
+++ b/src/math/amdgpu/llrintf.cpp
@@ -9,7 +9,6 @@
 #include "src/math/llrintf.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/log.cpp b/src/math/amdgpu/log.cpp
deleted file mode 100644
index bd01adf..0000000
--- a/src/math/amdgpu/log.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log function ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, log, (double x)) { return __ocml_log_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/log10.cpp b/src/math/amdgpu/log10.cpp
deleted file mode 100644
index 75957c9..0000000
--- a/src/math/amdgpu/log10.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log10 function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log10.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, log10, (double x)) { return __ocml_log10_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/log10f.cpp b/src/math/amdgpu/log10f.cpp
deleted file mode 100644
index 9c12d6b..0000000
--- a/src/math/amdgpu/log10f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log10f function -------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log10f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, log10f, (float x)) { return __ocml_log10_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/log1p.cpp b/src/math/amdgpu/log1p.cpp
deleted file mode 100644
index fc27519..0000000
--- a/src/math/amdgpu/log1p.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log1p function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log1p.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, log1p, (double x)) { return __ocml_log1p_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/log1pf.cpp b/src/math/amdgpu/log1pf.cpp
deleted file mode 100644
index b2d26fb..0000000
--- a/src/math/amdgpu/log1pf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log1pf function -------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log1pf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, log1pf, (float x)) { return __ocml_log1p_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/log2.cpp b/src/math/amdgpu/log2.cpp
deleted file mode 100644
index 73f34b6..0000000
--- a/src/math/amdgpu/log2.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log2 function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log2.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, log2, (double x)) { return __ocml_log2_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/log2f.cpp b/src/math/amdgpu/log2f.cpp
deleted file mode 100644
index 3b62eda..0000000
--- a/src/math/amdgpu/log2f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log2f function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log2f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, log2f, (float x)) { return __ocml_log2_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/logbf.cpp b/src/math/amdgpu/logbf.cpp
deleted file mode 100644
index bc7c462..0000000
--- a/src/math/amdgpu/logbf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU logbf function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/logbf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, logbf, (float x)) { return __ocml_logb_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/logf.cpp b/src/math/amdgpu/logf.cpp
deleted file mode 100644
index 1792567..0000000
--- a/src/math/amdgpu/logf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU logf function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/logf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, logf, (float x)) { return __ocml_log_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/lrint.cpp b/src/math/amdgpu/lrint.cpp
index 715b552..5ba70ec 100644
--- a/src/math/amdgpu/lrint.cpp
+++ b/src/math/amdgpu/lrint.cpp
@@ -9,7 +9,6 @@
 #include "src/math/lrint.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/lrintf.cpp b/src/math/amdgpu/lrintf.cpp
index 3870638..1c985b0 100644
--- a/src/math/amdgpu/lrintf.cpp
+++ b/src/math/amdgpu/lrintf.cpp
@@ -9,7 +9,6 @@
 #include "src/math/lrintf.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/nextafter.cpp b/src/math/amdgpu/nextafter.cpp
deleted file mode 100644
index 226b8a5..0000000
--- a/src/math/amdgpu/nextafter.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the nextafter function for GPU ------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/nextafter.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, nextafter, (double x, double y)) {
-  return __ocml_nextafter_f64(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/nextafterf.cpp b/src/math/amdgpu/nextafterf.cpp
deleted file mode 100644
index 7bed2c1..0000000
--- a/src/math/amdgpu/nextafterf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the nextafterf function for GPU -----------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/nextafterf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, nextafterf, (float x, float y)) {
-  return __ocml_nextafter_f32(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/platform.h b/src/math/amdgpu/platform.h
deleted file mode 100644
index 472a983..0000000
--- a/src/math/amdgpu/platform.h
+++ /dev/null
@@ -1,55 +0,0 @@
-//===-- AMDGPU specific platform definitions for math support -------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_SRC_MATH_AMDGPU_PLATFORM_H
-#define LLVM_LIBC_SRC_MATH_AMDGPU_PLATFORM_H
-
-#include "src/__support/macros/attributes.h"
-#include "src/__support/macros/config.h"
-
-#include <stdint.h>
-
-namespace LIBC_NAMESPACE_DECL {
-
-// The ROCm device library uses control globals to alter codegen for the
-// different targets. To avoid needing to link them in manually we simply
-// define them here.
-extern "C" {
-
-// Disable unsafe math optimizations in the implementation.
-extern const LIBC_INLINE_VAR uint8_t __oclc_unsafe_math_opt = 0;
-
-// Disable denormalization at zero optimizations in the implementation.
-extern const LIBC_INLINE_VAR uint8_t __oclc_daz_opt = 0;
-
-// Disable rounding optimizations for 32-bit square roots.
-extern const LIBC_INLINE_VAR uint8_t __oclc_correctly_rounded_sqrt32 = 1;
-
-// Disable finite math optimizations.
-extern const LIBC_INLINE_VAR uint8_t __oclc_finite_only_opt = 0;
-
-// Set the ISA value to a high enough value that the ROCm device library math
-// functions will assume we have fast FMA operations among other features. This
-// is determined to be safe on all targets by looking at the source code.
-// https://github.com/ROCm/ROCm-Device-Libs/blob/amd-stg-open/ocml/src/opts.h
-extern const LIBC_INLINE_VAR uint32_t __oclc_ISA_version = 9000;
-}
-
-// These aliases cause clang to emit the control constants with ODR linkage.
-// This allows us to link against the symbols without preventing them from being
-// optimized out or causing symbol collisions.
-[[gnu::alias("__oclc_unsafe_math_opt")]] const uint8_t __oclc_unsafe_math_opt__;
-[[gnu::alias("__oclc_daz_opt")]] const uint8_t __oclc_daz_opt__;
-[[gnu::alias("__oclc_correctly_rounded_sqrt32")]] const uint8_t
-    __oclc_correctly_rounded_sqrt32__;
-[[gnu::alias("__oclc_finite_only_opt")]] const uint8_t __oclc_finite_only_opt__;
-[[gnu::alias("__oclc_ISA_version")]] const uint32_t __oclc_ISA_version__;
-
-} // namespace LIBC_NAMESPACE_DECL
-
-#endif // LLVM_LIBC_SRC_MATH_AMDGPU_PLATFORM_H
diff --git a/src/math/amdgpu/powf.cpp b/src/math/amdgpu/powf.cpp
deleted file mode 100644
index 6931934..0000000
--- a/src/math/amdgpu/powf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the powf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/powf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, powf, (float x, float y)) {
-  return __ocml_pow_f32(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/powi.cpp b/src/math/amdgpu/powi.cpp
deleted file mode 100644
index 6b31b47..0000000
--- a/src/math/amdgpu/powi.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the powi function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/powi.h"
-#include "src/__support/common.h"
-#include "src/__support/macros/config.h"
-
-#include "declarations.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, powi, (double x, int y)) {
-  return __ocml_pown_f64(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/powif.cpp b/src/math/amdgpu/powif.cpp
deleted file mode 100644
index 94f8a91..0000000
--- a/src/math/amdgpu/powif.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the powi function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/powif.h"
-#include "src/__support/common.h"
-#include "src/__support/macros/config.h"
-
-#include "declarations.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, powif, (float x, int y)) {
-  return __ocml_pown_f32(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/remquof.cpp b/src/math/amdgpu/remquof.cpp
deleted file mode 100644
index 854d3bf..0000000
--- a/src/math/amdgpu/remquof.cpp
+++ /dev/null
@@ -1,24 +0,0 @@
-//===-- Implementation of the GPU remquof function ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/remquof.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, remquof, (float x, float y, int *quo)) {
-  int tmp;
-  float r = __ocml_remquo_f32(x, y, (gpu::Private<int> *)&tmp);
-  *quo = tmp;
-  return r;
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/scalbn.cpp b/src/math/amdgpu/scalbn.cpp
index 05bbbc6..3c3c19e 100644
--- a/src/math/amdgpu/scalbn.cpp
+++ b/src/math/amdgpu/scalbn.cpp
@@ -9,7 +9,6 @@
 #include "src/math/scalbn.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/scalbnf.cpp b/src/math/amdgpu/scalbnf.cpp
index f0e9e47..c348aa7 100644
--- a/src/math/amdgpu/scalbnf.cpp
+++ b/src/math/amdgpu/scalbnf.cpp
@@ -9,7 +9,6 @@
 #include "src/math/scalbnf.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/amdgpu/sin.cpp b/src/math/amdgpu/sin.cpp
deleted file mode 100644
index f3d88af..0000000
--- a/src/math/amdgpu/sin.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the sin function for GPU ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sin.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, sin, (double x)) { return __ocml_sin_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/sincos.cpp b/src/math/amdgpu/sincos.cpp
deleted file mode 100644
index 304ac0c..0000000
--- a/src/math/amdgpu/sincos.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the sincos function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sincos.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(void, sincos, (double x, double *sinptr, double *cosptr)) {
-  *sinptr = __ocml_sincos_f64(x, cosptr);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/sincosf.cpp b/src/math/amdgpu/sincosf.cpp
deleted file mode 100644
index 1c4e9c6..0000000
--- a/src/math/amdgpu/sincosf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the sincosf function for GPU --------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sincosf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(void, sincosf, (float x, float *sinptr, float *cosptr)) {
-  *sinptr = __ocml_sincos_f32(x, cosptr);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/sinf.cpp b/src/math/amdgpu/sinf.cpp
deleted file mode 100644
index c6d64a6..0000000
--- a/src/math/amdgpu/sinf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the sinf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sinf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, sinf, (float x)) { return __ocml_sin_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/sinh.cpp b/src/math/amdgpu/sinh.cpp
deleted file mode 100644
index 26314f4..0000000
--- a/src/math/amdgpu/sinh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the sinh function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sinh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, sinh, (double x)) { return __ocml_sinh_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/sinhf.cpp b/src/math/amdgpu/sinhf.cpp
deleted file mode 100644
index a4eb8e1..0000000
--- a/src/math/amdgpu/sinhf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the sinhf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sinhf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, sinhf, (float x)) { return __ocml_sinh_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/tan.cpp b/src/math/amdgpu/tan.cpp
deleted file mode 100644
index c946dc2..0000000
--- a/src/math/amdgpu/tan.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the tan function for GPU ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/tan.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, tan, (double x)) { return __ocml_tan_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/tanf.cpp b/src/math/amdgpu/tanf.cpp
deleted file mode 100644
index 8c93fc4..0000000
--- a/src/math/amdgpu/tanf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the tanf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/tanf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, tanf, (float x)) { return __ocml_tan_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/tanh.cpp b/src/math/amdgpu/tanh.cpp
deleted file mode 100644
index 834353e..0000000
--- a/src/math/amdgpu/tanh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the tanh function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/tanh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, tanh, (double x)) { return __ocml_tanh_f64(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/tanhf.cpp b/src/math/amdgpu/tanhf.cpp
deleted file mode 100644
index 5029596..0000000
--- a/src/math/amdgpu/tanhf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the tanhf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/tanhf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, tanhf, (float x)) { return __ocml_tanh_f32(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/tgamma.cpp b/src/math/amdgpu/tgamma.cpp
index 485a6a3..0dfb0fd 100644
--- a/src/math/amdgpu/tgamma.cpp
+++ b/src/math/amdgpu/tgamma.cpp
@@ -9,11 +9,10 @@
 #include "src/math/tgamma.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, tgamma, (double x)) { return __ocml_tgamma_f64(x); }
+LLVM_LIBC_FUNCTION(double, tgamma, (double)) { return 0.0; }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/tgammaf.cpp b/src/math/amdgpu/tgammaf.cpp
index e48a486..9dd17ab 100644
--- a/src/math/amdgpu/tgammaf.cpp
+++ b/src/math/amdgpu/tgammaf.cpp
@@ -9,11 +9,10 @@
 #include "src/math/tgammaf.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(float, tgammaf, (float x)) { return __ocml_tgamma_f32(x); }
+LLVM_LIBC_FUNCTION(float, tgammaf, (float)) { return 0.0f; }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/asinhf16.h b/src/math/asinhf16.h
new file mode 100644
index 0000000..bb40e20
--- /dev/null
+++ b/src/math/asinhf16.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for asinhf16 ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_ASINHF16_H
+#define LLVM_LIBC_SRC_MATH_ASINHF16_H
+
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+float16 asinhf16(float16 x);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_ASINHF16_H
diff --git a/src/math/atan2f128.h b/src/math/atan2f128.h
new file mode 100644
index 0000000..26f7ec6
--- /dev/null
+++ b/src/math/atan2f128.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for atan2f128 ---------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_ATAN2F128_H
+#define LLVM_LIBC_SRC_MATH_ATAN2F128_H
+
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+float128 atan2f128(float128 x, float128 y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_ATAN2F128_H
diff --git a/src/math/atanf16.h b/src/math/atanf16.h
new file mode 100644
index 0000000..96ae35c
--- /dev/null
+++ b/src/math/atanf16.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for atanf16 -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_ATANF16_H
+#define LLVM_LIBC_SRC_MATH_ATANF16_H
+
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+float16 atanf16(float16 x);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_ATANF16_H
diff --git a/src/math/atanhf16.h b/src/math/atanhf16.h
new file mode 100644
index 0000000..9fbb262
--- /dev/null
+++ b/src/math/atanhf16.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for atanhf16 ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_ATANHF16_H
+#define LLVM_LIBC_SRC_MATH_ATANHF16_H
+
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+float16 atanhf16(float16 x);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_ATANHF16_H
diff --git a/src/math/fmaf16.h b/src/math/fmaf16.h
new file mode 100644
index 0000000..1c4d468
--- /dev/null
+++ b/src/math/fmaf16.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for fmaf16 ------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_FMAF16_H
+#define LLVM_LIBC_SRC_MATH_FMAF16_H
+
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+float16 fmaf16(float16 x, float16 y, float16 z);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_FMAF16_H
diff --git a/src/math/generic/acos.cpp b/src/math/generic/acos.cpp
new file mode 100644
index 0000000..c14721f
--- /dev/null
+++ b/src/math/generic/acos.cpp
@@ -0,0 +1,278 @@
+//===-- Double-precision acos function ------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/acos.h"
+#include "asin_utils.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/PolyEval.h"
+#include "src/__support/FPUtil/double_double.h"
+#include "src/__support/FPUtil/dyadic_float.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/sqrt.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/optimization.h"            // LIBC_UNLIKELY
+#include "src/__support/macros/properties/cpu_features.h" // LIBC_TARGET_CPU_HAS_FMA
+
+namespace LIBC_NAMESPACE_DECL {
+
+using DoubleDouble = fputil::DoubleDouble;
+using Float128 = fputil::DyadicFloat<128>;
+
+LLVM_LIBC_FUNCTION(double, acos, (double x)) {
+  using FPBits = fputil::FPBits<double>;
+
+  FPBits xbits(x);
+  int x_exp = xbits.get_biased_exponent();
+
+  // |x| < 0.5.
+  if (x_exp < FPBits::EXP_BIAS - 1) {
+    // |x| < 2^-55.
+    if (LIBC_UNLIKELY(x_exp < FPBits::EXP_BIAS - 55)) {
+      // When |x| < 2^-55, acos(x) = pi/2
+#if defined(LIBC_MATH_HAS_SKIP_ACCURATE_PASS)
+      return PI_OVER_TWO.hi;
+#else
+      // Force the evaluation and prevent constant propagation so that it
+      // is rounded correctly for FE_UPWARD rounding mode.
+      return (xbits.abs().get_val() + 0x1.0p-160) + PI_OVER_TWO.hi;
+#endif // LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+    }
+
+#ifdef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+    // acos(x) = pi/2 - asin(x)
+    //         = pi/2 - x * P(x^2)
+    double p = asin_eval(x * x);
+    return PI_OVER_TWO.hi + fputil::multiply_add(-x, p, PI_OVER_TWO.lo);
+#else
+    unsigned idx;
+    DoubleDouble x_sq = fputil::exact_mult(x, x);
+    double err = xbits.abs().get_val() * 0x1.0p-51;
+    // Polynomial approximation:
+    //   p ~ asin(x)/x
+    DoubleDouble p = asin_eval(x_sq, idx, err);
+    // asin(x) ~ x * p
+    DoubleDouble r0 = fputil::exact_mult(x, p.hi);
+    // acos(x) = pi/2 - asin(x)
+    //         ~ pi/2 - x * p
+    //         = pi/2 - x * (p.hi + p.lo)
+    double r_hi = fputil::multiply_add(-x, p.hi, PI_OVER_TWO.hi);
+    // Use Dekker's 2SUM algorithm to compute the lower part.
+    double r_lo = ((PI_OVER_TWO.hi - r_hi) - r0.hi) - r0.lo;
+    r_lo = fputil::multiply_add(-x, p.lo, r_lo + PI_OVER_TWO.lo);
+
+    // Ziv's accuracy test.
+
+    double r_upper = r_hi + (r_lo + err);
+    double r_lower = r_hi + (r_lo - err);
+
+    if (LIBC_LIKELY(r_upper == r_lower))
+      return r_upper;
+
+    // Ziv's accuracy test failed, perform 128-bit calculation.
+
+    // Recalculate mod 1/64.
+    idx = static_cast<unsigned>(fputil::nearest_integer(x_sq.hi * 0x1.0p6));
+
+    // Get x^2 - idx/64 exactly.  When FMA is available, double-double
+    // multiplication will be correct for all rounding modes.  Otherwise we use
+    // Float128 directly.
+    Float128 x_f128(x);
+
+#ifdef LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+    // u = x^2 - idx/64
+    Float128 u_hi(
+        fputil::multiply_add(static_cast<double>(idx), -0x1.0p-6, x_sq.hi));
+    Float128 u = fputil::quick_add(u_hi, Float128(x_sq.lo));
+#else
+    Float128 x_sq_f128 = fputil::quick_mul(x_f128, x_f128);
+    Float128 u = fputil::quick_add(
+        x_sq_f128, Float128(static_cast<double>(idx) * (-0x1.0p-6)));
+#endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+
+    Float128 p_f128 = asin_eval(u, idx);
+    // Flip the sign of x_f128 to perform subtraction.
+    x_f128.sign = x_f128.sign.negate();
+    Float128 r =
+        fputil::quick_add(PI_OVER_TWO_F128, fputil::quick_mul(x_f128, p_f128));
+
+    return static_cast<double>(r);
+#endif // LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+  }
+  // |x| >= 0.5
+
+  double x_abs = xbits.abs().get_val();
+
+  // Maintaining the sign:
+  constexpr double SIGN[2] = {1.0, -1.0};
+  double x_sign = SIGN[xbits.is_neg()];
+  // |x| >= 1
+  if (LIBC_UNLIKELY(x_exp >= FPBits::EXP_BIAS)) {
+    // x = +-1, asin(x) = +- pi/2
+    if (x_abs == 1.0) {
+      // x = 1, acos(x) = 0,
+      // x = -1, acos(x) = pi
+      return x == 1.0 ? 0.0 : fputil::multiply_add(-x_sign, PI.hi, PI.lo);
+    }
+    // |x| > 1, return NaN.
+    if (xbits.is_quiet_nan())
+      return x;
+
+    // Set domain error for non-NaN input.
+    if (!xbits.is_nan())
+      fputil::set_errno_if_required(EDOM);
+
+    fputil::raise_except_if_required(FE_INVALID);
+    return FPBits::quiet_nan().get_val();
+  }
+
+  // When |x| >= 0.5, we perform range reduction as follow:
+  //
+  // When 0.5 <= x < 1, let:
+  //   y = acos(x)
+  // We will use the double angle formula:
+  //   cos(2y) = 1 - 2 sin^2(y)
+  // and the complement angle identity:
+  //   x = cos(y) = 1 - 2 sin^2 (y/2)
+  // So:
+  //   sin(y/2) = sqrt( (1 - x)/2 )
+  // And hence:
+  //   y/2 = asin( sqrt( (1 - x)/2 ) )
+  // Equivalently:
+  //   acos(x) = y = 2 * asin( sqrt( (1 - x)/2 ) )
+  // Let u = (1 - x)/2, then:
+  //   acos(x) = 2 * asin( sqrt(u) )
+  // Moreover, since 0.5 <= x < 1:
+  //   0 < u <= 1/4, and 0 < sqrt(u) <= 0.5,
+  // And hence we can reuse the same polynomial approximation of asin(x) when
+  // |x| <= 0.5:
+  //   acos(x) ~ 2 * sqrt(u) * P(u).
+  //
+  // When -1 < x <= -0.5, we reduce to the previous case using the formula:
+  //   acos(x) = pi - acos(-x)
+  //           = pi - 2 * asin ( sqrt( (1 + x)/2 ) )
+  //           ~ pi - 2 * sqrt(u) * P(u),
+  // where u = (1 - |x|)/2.
+
+  // u = (1 - |x|)/2
+  double u = fputil::multiply_add(x_abs, -0.5, 0.5);
+  // v_hi + v_lo ~ sqrt(u).
+  // Let:
+  //   h = u - v_hi^2 = (sqrt(u) - v_hi) * (sqrt(u) + v_hi)
+  // Then:
+  //   sqrt(u) = v_hi + h / (sqrt(u) + v_hi)
+  //            ~ v_hi + h / (2 * v_hi)
+  // So we can use:
+  //   v_lo = h / (2 * v_hi).
+  double v_hi = fputil::sqrt<double>(u);
+
+#ifdef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+  constexpr DoubleDouble CONST_TERM[2] = {{0.0, 0.0}, PI};
+  DoubleDouble const_term = CONST_TERM[xbits.is_neg()];
+
+  double p = asin_eval(u);
+  double scale = x_sign * 2.0 * v_hi;
+  double r = const_term.hi + fputil::multiply_add(scale, p, const_term.lo);
+  return r;
+#else
+
+#ifdef LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+  double h = fputil::multiply_add(v_hi, -v_hi, u);
+#else
+  DoubleDouble v_hi_sq = fputil::exact_mult(v_hi, v_hi);
+  double h = (u - v_hi_sq.hi) - v_hi_sq.lo;
+#endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+
+  // Scale v_lo and v_hi by 2 from the formula:
+  //   vh = v_hi * 2
+  //   vl = 2*v_lo = h / v_hi.
+  double vh = v_hi * 2.0;
+  double vl = h / v_hi;
+
+  // Polynomial approximation:
+  //   p ~ asin(sqrt(u))/sqrt(u)
+  unsigned idx;
+  double err = vh * 0x1.0p-51;
+
+  DoubleDouble p = asin_eval(DoubleDouble{0.0, u}, idx, err);
+
+  // Perform computations in double-double arithmetic:
+  //   asin(x) = pi/2 - (v_hi + v_lo) * (ASIN_COEFFS[idx][0] + p)
+  DoubleDouble r0 = fputil::quick_mult(DoubleDouble{vl, vh}, p);
+
+  double r_hi, r_lo;
+  if (xbits.is_pos()) {
+    r_hi = r0.hi;
+    r_lo = r0.lo;
+  } else {
+    DoubleDouble r = fputil::exact_add(PI.hi, -r0.hi);
+    r_hi = r.hi;
+    r_lo = (PI.lo - r0.lo) + r.lo;
+  }
+
+  // Ziv's accuracy test.
+
+  double r_upper = r_hi + (r_lo + err);
+  double r_lower = r_hi + (r_lo - err);
+
+  if (LIBC_LIKELY(r_upper == r_lower))
+    return r_upper;
+
+  // Ziv's accuracy test failed, we redo the computations in Float128.
+  // Recalculate mod 1/64.
+  idx = static_cast<unsigned>(fputil::nearest_integer(u * 0x1.0p6));
+
+  // After the first step of Newton-Raphson approximating v = sqrt(u), we have
+  // that:
+  //   sqrt(u) = v_hi + h / (sqrt(u) + v_hi)
+  //      v_lo = h / (2 * v_hi)
+  // With error:
+  //   sqrt(u) - (v_hi + v_lo) = h * ( 1/(sqrt(u) + v_hi) - 1/(2*v_hi) )
+  //                           = -h^2 / (2*v * (sqrt(u) + v)^2).
+  // Since:
+  //   (sqrt(u) + v_hi)^2 ~ (2sqrt(u))^2 = 4u,
+  // we can add another correction term to (v_hi + v_lo) that is:
+  //   v_ll = -h^2 / (2*v_hi * 4u)
+  //        = -v_lo * (h / 4u)
+  //        = -vl * (h / 8u),
+  // making the errors:
+  //   sqrt(u) - (v_hi + v_lo + v_ll) = O(h^3)
+  // well beyond 128-bit precision needed.
+
+  // Get the rounding error of vl = 2 * v_lo ~ h / vh
+  // Get full product of vh * vl
+#ifdef LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+  double vl_lo = fputil::multiply_add(-v_hi, vl, h) / v_hi;
+#else
+  DoubleDouble vh_vl = fputil::exact_mult(v_hi, vl);
+  double vl_lo = ((h - vh_vl.hi) - vh_vl.lo) / v_hi;
+#endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+  // vll = 2*v_ll = -vl * (h / (4u)).
+  double t = h * (-0.25) / u;
+  double vll = fputil::multiply_add(vl, t, vl_lo);
+  // m_v = -(v_hi + v_lo + v_ll).
+  Float128 m_v = fputil::quick_add(
+      Float128(vh), fputil::quick_add(Float128(vl), Float128(vll)));
+  m_v.sign = xbits.sign();
+
+  // Perform computations in Float128:
+  //   acos(x) = (v_hi + v_lo + vll) * P(u)         , when 0.5 <= x < 1,
+  //           = pi - (v_hi + v_lo + vll) * P(u)    , when -1 < x <= -0.5.
+  Float128 y_f128(fputil::multiply_add(static_cast<double>(idx), -0x1.0p-6, u));
+
+  Float128 p_f128 = asin_eval(y_f128, idx);
+  Float128 r_f128 = fputil::quick_mul(m_v, p_f128);
+
+  if (xbits.is_neg())
+    r_f128 = fputil::quick_add(PI_F128, r_f128);
+
+  return static_cast<double>(r_f128);
+#endif // LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/acosf.cpp b/src/math/generic/acosf.cpp
index 509a5eb..8dd6de2 100644
--- a/src/math/generic/acosf.cpp
+++ b/src/math/generic/acosf.cpp
@@ -84,10 +84,17 @@ LLVM_LIBC_FUNCTION(float, acosf, (float x)) {
                           0x1.921fb6p+1f)
                     : /* x == 1.0f */ 0.0f;
 
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+
+    // |x| <= +/-inf
     if (x_abs <= 0x7f80'0000U) {
       fputil::set_errno_if_required(EDOM);
       fputil::raise_except_if_required(FE_INVALID);
     }
+
     return x + FPBits::quiet_nan().get_val();
   }
 
diff --git a/src/math/generic/acoshf16.cpp b/src/math/generic/acoshf16.cpp
new file mode 100644
index 0000000..44783a8
--- /dev/null
+++ b/src/math/generic/acoshf16.cpp
@@ -0,0 +1,110 @@
+//===-- Half-precision acosh(x) function ----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/acoshf16.h"
+#include "explogxf.h"
+#include "hdr/errno_macros.h"
+#include "hdr/fenv_macros.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/PolyEval.h"
+#include "src/__support/FPUtil/cast.h"
+#include "src/__support/FPUtil/except_value_utils.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/sqrt.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/optimization.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+static constexpr size_t N_EXCEPTS = 2;
+static constexpr fputil::ExceptValues<float16, N_EXCEPTS> ACOSHF16_EXCEPTS{{
+    // (input, RZ output, RU offset, RD offset, RN offset)
+    // x = 0x1.6dcp+1, acoshf16(x) = 0x1.b6p+0 (RZ)
+    {0x41B7, 0x3ED8, 1, 0, 0},
+    // x = 0x1.39p+0, acoshf16(x) = 0x1.4f8p-1 (RZ)
+    {0x3CE4, 0x393E, 1, 0, 1},
+}};
+
+LLVM_LIBC_FUNCTION(float16, acoshf16, (float16 x)) {
+  using FPBits = fputil::FPBits<float16>;
+  FPBits xbits(x);
+  uint16_t x_u = xbits.uintval();
+
+  // Check for NaN input first.
+  if (LIBC_UNLIKELY(xbits.is_inf_or_nan())) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+    if (xbits.is_neg()) {
+      fputil::set_errno_if_required(EDOM);
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+    return x;
+  }
+
+  // Domain error for inputs less than 1.0.
+  if (LIBC_UNLIKELY(x <= 1.0f)) {
+    if (x == 1.0f)
+      return FPBits::zero().get_val();
+    fputil::set_errno_if_required(EDOM);
+    fputil::raise_except_if_required(FE_INVALID);
+    return FPBits::quiet_nan().get_val();
+  }
+
+  if (auto r = ACOSHF16_EXCEPTS.lookup(xbits.uintval());
+      LIBC_UNLIKELY(r.has_value()))
+    return r.value();
+
+  float xf = x;
+  // High-precision polynomial approximation for inputs close to 1.0
+  // ([1, 1.25)).
+  //
+  // Brief derivation:
+  // 1. Expand acosh(1 + delta) using Taylor series around delta=0:
+  //    acosh(1 + delta) ≈ sqrt(2 * delta) * [1 - delta/12 + 3*delta^2/160
+  //                     - 5*delta^3/896 + 35*delta^4/18432 + ...]
+  // 2. Truncate the series to fit accurately for delta in [0, 0.25].
+  // 3. Polynomial coefficients (from sollya) used here are:
+  //    P(delta) ≈ 1 - 0x1.555556p-4 * delta + 0x1.333334p-6 * delta^2
+  //               - 0x1.6db6dcp-8 * delta^3 + 0x1.f1c71cp-10 * delta^4
+  // 4. The Sollya commands used to generate these coefficients were:
+  //      > display = hexadecimal;
+  //      > round(1/12, SG, RN);
+  //      > round(3/160, SG, RN);
+  //      > round(5/896, SG, RN);
+  //      > round(35/18432, SG, RN);
+  //      With hexadecimal display mode enabled, the outputs were:
+  //      0x1.555556p-4
+  //      0x1.333334p-6
+  //      0x1.6db6dcp-8
+  //      0x1.f1c71cp-10
+  // 5. The maximum absolute error, estimated using:
+  //      dirtyinfnorm(acosh(1 + x) - sqrt(2*x) * P(x), [0, 0.25])
+  //    is:
+  //      0x1.d84281p-22
+  if (LIBC_UNLIKELY(x_u < 0x3D00U)) {
+    float delta = xf - 1.0f;
+    float sqrt_2_delta = fputil::sqrt<float>(2.0 * delta);
+    float pe = fputil::polyeval(delta, 0x1p+0f, -0x1.555556p-4f, 0x1.333334p-6f,
+                                -0x1.6db6dcp-8f, 0x1.f1c71cp-10f);
+    float approx = sqrt_2_delta * pe;
+    return fputil::cast<float16>(approx);
+  }
+
+  // acosh(x) = log(x + sqrt(x^2 - 1))
+  float sqrt_term = fputil::sqrt<float>(fputil::multiply_add(xf, xf, -1.0f));
+  float result = static_cast<float>(log_eval(xf + sqrt_term));
+
+  return fputil::cast<float16>(result);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/acospif16.cpp b/src/math/generic/acospif16.cpp
new file mode 100644
index 0000000..bfdf169
--- /dev/null
+++ b/src/math/generic/acospif16.cpp
@@ -0,0 +1,134 @@
+//===-- Half-precision acospi function ------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/acospif16.h"
+#include "hdr/errno_macros.h"
+#include "hdr/fenv_macros.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/PolyEval.h"
+#include "src/__support/FPUtil/cast.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/sqrt.h"
+#include "src/__support/macros/optimization.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(float16, acospif16, (float16 x)) {
+  using FPBits = fputil::FPBits<float16>;
+  FPBits xbits(x);
+
+  uint16_t x_u = xbits.uintval();
+  uint16_t x_abs = x_u & 0x7fff;
+  uint16_t x_sign = x_u >> 15;
+
+  // |x| > 0x1p0, |x| > 1, or x is NaN.
+  if (LIBC_UNLIKELY(x_abs > 0x3c00)) {
+    // acospif16(NaN) = NaN
+    if (xbits.is_nan()) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+
+      return x;
+    }
+
+    // 1 < |x| <= +inf
+    fputil::raise_except_if_required(FE_INVALID);
+    fputil::set_errno_if_required(EDOM);
+
+    return FPBits::quiet_nan().get_val();
+  }
+
+  // |x| == 0x1p0, x is 1 or -1
+  // if x is (-)1, return 1
+  // if x is (+)1, return 0
+  if (LIBC_UNLIKELY(x_abs == 0x3c00))
+    return fputil::cast<float16>(x_sign ? 1.0f : 0.0f);
+
+  float xf = x;
+  float xsq = xf * xf;
+
+  // Degree-6 minimax polynomial coefficients of asin(x) generated by Sollya
+  // with: > P = fpminimax(asin(x)/(pi * x), [|0, 2, 4, 6, 8|], [|SG...|], [0,
+  // 0.5]);
+  constexpr float POLY_COEFFS[5] = {0x1.45f308p-2f, 0x1.b2900cp-5f,
+                                    0x1.897e36p-6f, 0x1.9efafcp-7f,
+                                    0x1.06d884p-6f};
+  // |x| <= 0x1p-1, |x| <= 0.5
+  if (x_abs <= 0x3800) {
+    // if x is 0, return 0.5
+    if (LIBC_UNLIKELY(x_abs == 0))
+      return fputil::cast<float16>(0.5f);
+
+    // Note that: acos(x) = pi/2 + asin(-x) = pi/2 - asin(x), then
+    //            acospi(x) = 0.5 - asin(x)/pi
+    float interm =
+        fputil::polyeval(xsq, POLY_COEFFS[0], POLY_COEFFS[1], POLY_COEFFS[2],
+                         POLY_COEFFS[3], POLY_COEFFS[4]);
+
+    return fputil::cast<float16>(fputil::multiply_add(-xf, interm, 0.5f));
+  }
+
+  // When |x| > 0.5, assume that 0.5 < |x| <= 1
+  //
+  // Step-by-step range-reduction proof:
+  // 1:  Let y = asin(x), such that, x = sin(y)
+  // 2:  From complimentary angle identity:
+  //       x = sin(y) = cos(pi/2 - y)
+  // 3:  Let z = pi/2 - y, such that x = cos(z)
+  // 4:  From double angle formula; cos(2A) = 1 - 2 * sin^2(A):
+  //       z = 2A, z/2 = A
+  //       cos(z) = 1 - 2 * sin^2(z/2)
+  // 5:  Make sin(z/2) subject of the formula:
+  //       sin(z/2) = sqrt((1 - cos(z))/2)
+  // 6:  Recall [3]; x = cos(z). Therefore:
+  //       sin(z/2) = sqrt((1 - x)/2)
+  // 7:  Let u = (1 - x)/2
+  // 8:  Therefore:
+  //       asin(sqrt(u)) = z/2
+  //       2 * asin(sqrt(u)) = z
+  // 9:  Recall [3]; z = pi/2 - y. Therefore:
+  //       y = pi/2 - z
+  //       y = pi/2 - 2 * asin(sqrt(u))
+  // 10: Recall [1], y = asin(x). Therefore:
+  //       asin(x) = pi/2 - 2 * asin(sqrt(u))
+  // 11: Recall that: acos(x) = pi/2 + asin(-x) = pi/2 - asin(x)
+  //     Therefore:
+  //       acos(x) = pi/2 - (pi/2 - 2 * asin(sqrt(u)))
+  //       acos(x) = 2 * asin(sqrt(u))
+  //       acospi(x) = 2 * (asin(sqrt(u)) / pi)
+  //
+  // THE RANGE REDUCTION, HOW?
+  // 12: Recall [7], u = (1 - x)/2
+  // 13: Since 0.5 < x <= 1, therefore:
+  //       0 <= u <= 0.25 and 0 <= sqrt(u) <= 0.5
+  //
+  // Hence, we can reuse the same [0, 0.5] domain polynomial approximation for
+  // Step [11] as `sqrt(u)` is in range.
+  // When -1 < x <= -0.5, the identity:
+  //       acos(x) = pi - acos(-x)
+  //       acospi(x) = 1 - acos(-x)/pi
+  // allows us to compute for the negative x value (lhs)
+  // with a positive x value instead (rhs).
+
+  float xf_abs = (xf < 0 ? -xf : xf);
+  float u = fputil::multiply_add(-0.5f, xf_abs, 0.5f);
+  float sqrt_u = fputil::sqrt<float>(u);
+
+  float asin_sqrt_u =
+      sqrt_u * fputil::polyeval(u, POLY_COEFFS[0], POLY_COEFFS[1],
+                                POLY_COEFFS[2], POLY_COEFFS[3], POLY_COEFFS[4]);
+
+  // Same as acos(x), but devided the expression with pi
+  return fputil::cast<float16>(
+      x_sign ? fputil::multiply_add(-2.0f, asin_sqrt_u, 1.0f)
+             : 2.0f * asin_sqrt_u);
+}
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/asin.cpp b/src/math/generic/asin.cpp
new file mode 100644
index 0000000..ad77683
--- /dev/null
+++ b/src/math/generic/asin.cpp
@@ -0,0 +1,288 @@
+//===-- Double-precision asin function ------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/asin.h"
+#include "asin_utils.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/PolyEval.h"
+#include "src/__support/FPUtil/double_double.h"
+#include "src/__support/FPUtil/dyadic_float.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/sqrt.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/optimization.h"            // LIBC_UNLIKELY
+#include "src/__support/macros/properties/cpu_features.h" // LIBC_TARGET_CPU_HAS_FMA
+
+namespace LIBC_NAMESPACE_DECL {
+
+using DoubleDouble = fputil::DoubleDouble;
+using Float128 = fputil::DyadicFloat<128>;
+
+LLVM_LIBC_FUNCTION(double, asin, (double x)) {
+  using FPBits = fputil::FPBits<double>;
+
+  FPBits xbits(x);
+  int x_exp = xbits.get_biased_exponent();
+
+  // |x| < 0.5.
+  if (x_exp < FPBits::EXP_BIAS - 1) {
+    // |x| < 2^-26.
+    if (LIBC_UNLIKELY(x_exp < FPBits::EXP_BIAS - 26)) {
+      // When |x| < 2^-26, the relative error of the approximation asin(x) ~ x
+      // is:
+      //   |asin(x) - x| / |asin(x)| < |x^3| / (6|x|)
+      //                             = x^2 / 6
+      //                             < 2^-54
+      //                             < epsilon(1)/2.
+      // So the correctly rounded values of asin(x) are:
+      //   = x + sign(x)*eps(x) if rounding mode = FE_TOWARDZERO,
+      //                        or (rounding mode = FE_UPWARD and x is
+      //                        negative),
+      //   = x otherwise.
+      // To simplify the rounding decision and make it more efficient, we use
+      //   fma(x, 2^-54, x) instead.
+      // Note: to use the formula x + 2^-54*x to decide the correct rounding, we
+      // do need fma(x, 2^-54, x) to prevent underflow caused by 2^-54*x when
+      // |x| < 2^-1022. For targets without FMA instructions, when x is close to
+      // denormal range, we normalize x,
+#if defined(LIBC_MATH_HAS_SKIP_ACCURATE_PASS)
+      return x;
+#elif defined(LIBC_TARGET_CPU_HAS_FMA_DOUBLE)
+      return fputil::multiply_add(x, 0x1.0p-54, x);
+#else
+      if (xbits.abs().uintval() == 0)
+        return x;
+      // Get sign(x) * min_normal.
+      FPBits eps_bits = FPBits::min_normal();
+      eps_bits.set_sign(xbits.sign());
+      double eps = eps_bits.get_val();
+      double normalize_const = (x_exp == 0) ? eps : 0.0;
+      double scaled_normal =
+          fputil::multiply_add(x + normalize_const, 0x1.0p54, eps);
+      return fputil::multiply_add(scaled_normal, 0x1.0p-54, -normalize_const);
+#endif // LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+    }
+
+#ifdef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+    return x * asin_eval(x * x);
+#else
+    unsigned idx;
+    DoubleDouble x_sq = fputil::exact_mult(x, x);
+    double err = xbits.abs().get_val() * 0x1.0p-51;
+    // Polynomial approximation:
+    //   p ~ asin(x)/x
+
+    DoubleDouble p = asin_eval(x_sq, idx, err);
+    // asin(x) ~ x * (ASIN_COEFFS[idx][0] + p)
+    DoubleDouble r0 = fputil::exact_mult(x, p.hi);
+    double r_lo = fputil::multiply_add(x, p.lo, r0.lo);
+
+    // Ziv's accuracy test.
+
+    double r_upper = r0.hi + (r_lo + err);
+    double r_lower = r0.hi + (r_lo - err);
+
+    if (LIBC_LIKELY(r_upper == r_lower))
+      return r_upper;
+
+    // Ziv's accuracy test failed, perform 128-bit calculation.
+
+    // Recalculate mod 1/64.
+    idx = static_cast<unsigned>(fputil::nearest_integer(x_sq.hi * 0x1.0p6));
+
+    // Get x^2 - idx/64 exactly.  When FMA is available, double-double
+    // multiplication will be correct for all rounding modes.  Otherwise we use
+    // Float128 directly.
+    Float128 x_f128(x);
+
+#ifdef LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+    // u = x^2 - idx/64
+    Float128 u_hi(
+        fputil::multiply_add(static_cast<double>(idx), -0x1.0p-6, x_sq.hi));
+    Float128 u = fputil::quick_add(u_hi, Float128(x_sq.lo));
+#else
+    Float128 x_sq_f128 = fputil::quick_mul(x_f128, x_f128);
+    Float128 u = fputil::quick_add(
+        x_sq_f128, Float128(static_cast<double>(idx) * (-0x1.0p-6)));
+#endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+
+    Float128 p_f128 = asin_eval(u, idx);
+    Float128 r = fputil::quick_mul(x_f128, p_f128);
+
+    return static_cast<double>(r);
+#endif // LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+  }
+  // |x| >= 0.5
+
+  double x_abs = xbits.abs().get_val();
+
+  // Maintaining the sign:
+  constexpr double SIGN[2] = {1.0, -1.0};
+  double x_sign = SIGN[xbits.is_neg()];
+
+  // |x| >= 1
+  if (LIBC_UNLIKELY(x_exp >= FPBits::EXP_BIAS)) {
+    // x = +-1, asin(x) = +- pi/2
+    if (x_abs == 1.0) {
+      // return +- pi/2
+      return fputil::multiply_add(x_sign, PI_OVER_TWO.hi,
+                                  x_sign * PI_OVER_TWO.lo);
+    }
+    // |x| > 1, return NaN.
+    if (xbits.is_quiet_nan())
+      return x;
+
+    // Set domain error for non-NaN input.
+    if (!xbits.is_nan())
+      fputil::set_errno_if_required(EDOM);
+
+    fputil::raise_except_if_required(FE_INVALID);
+    return FPBits::quiet_nan().get_val();
+  }
+
+  // When |x| >= 0.5, we perform range reduction as follow:
+  //
+  // Assume further that 0.5 <= x < 1, and let:
+  //   y = asin(x)
+  // We will use the double angle formula:
+  //   cos(2y) = 1 - 2 sin^2(y)
+  // and the complement angle identity:
+  //   x = sin(y) = cos(pi/2 - y)
+  //              = 1 - 2 sin^2 (pi/4 - y/2)
+  // So:
+  //   sin(pi/4 - y/2) = sqrt( (1 - x)/2 )
+  // And hence:
+  //   pi/4 - y/2 = asin( sqrt( (1 - x)/2 ) )
+  // Equivalently:
+  //   asin(x) = y = pi/2 - 2 * asin( sqrt( (1 - x)/2 ) )
+  // Let u = (1 - x)/2, then:
+  //   asin(x) = pi/2 - 2 * asin( sqrt(u) )
+  // Moreover, since 0.5 <= x < 1:
+  //   0 < u <= 1/4, and 0 < sqrt(u) <= 0.5,
+  // And hence we can reuse the same polynomial approximation of asin(x) when
+  // |x| <= 0.5:
+  //   asin(x) ~ pi/2 - 2 * sqrt(u) * P(u),
+
+  // u = (1 - |x|)/2
+  double u = fputil::multiply_add(x_abs, -0.5, 0.5);
+  // v_hi + v_lo ~ sqrt(u).
+  // Let:
+  //   h = u - v_hi^2 = (sqrt(u) - v_hi) * (sqrt(u) + v_hi)
+  // Then:
+  //   sqrt(u) = v_hi + h / (sqrt(u) + v_hi)
+  //           ~ v_hi + h / (2 * v_hi)
+  // So we can use:
+  //   v_lo = h / (2 * v_hi).
+  // Then,
+  //   asin(x) ~ pi/2 - 2*(v_hi + v_lo) * P(u)
+  double v_hi = fputil::sqrt<double>(u);
+
+#ifdef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+  double p = asin_eval(u);
+  double r = x_sign * fputil::multiply_add(-2.0 * v_hi, p, PI_OVER_TWO.hi);
+  return r;
+#else
+
+#ifdef LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+  double h = fputil::multiply_add(v_hi, -v_hi, u);
+#else
+  DoubleDouble v_hi_sq = fputil::exact_mult(v_hi, v_hi);
+  double h = (u - v_hi_sq.hi) - v_hi_sq.lo;
+#endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+
+  // Scale v_lo and v_hi by 2 from the formula:
+  //   vh = v_hi * 2
+  //   vl = 2*v_lo = h / v_hi.
+  double vh = v_hi * 2.0;
+  double vl = h / v_hi;
+
+  // Polynomial approximation:
+  //   p ~ asin(sqrt(u))/sqrt(u)
+  unsigned idx;
+  double err = vh * 0x1.0p-51;
+
+  DoubleDouble p = asin_eval(DoubleDouble{0.0, u}, idx, err);
+
+  // Perform computations in double-double arithmetic:
+  //   asin(x) = pi/2 - (v_hi + v_lo) * (ASIN_COEFFS[idx][0] + p)
+  DoubleDouble r0 = fputil::quick_mult(DoubleDouble{vl, vh}, p);
+  DoubleDouble r = fputil::exact_add(PI_OVER_TWO.hi, -r0.hi);
+
+  double r_lo = PI_OVER_TWO.lo - r0.lo + r.lo;
+
+  // Ziv's accuracy test.
+
+#ifdef LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+  double r_upper = fputil::multiply_add(
+      r.hi, x_sign, fputil::multiply_add(r_lo, x_sign, err));
+  double r_lower = fputil::multiply_add(
+      r.hi, x_sign, fputil::multiply_add(r_lo, x_sign, -err));
+#else
+  r_lo *= x_sign;
+  r.hi *= x_sign;
+  double r_upper = r.hi + (r_lo + err);
+  double r_lower = r.hi + (r_lo - err);
+#endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+
+  if (LIBC_LIKELY(r_upper == r_lower))
+    return r_upper;
+
+  // Ziv's accuracy test failed, we redo the computations in Float128.
+  // Recalculate mod 1/64.
+  idx = static_cast<unsigned>(fputil::nearest_integer(u * 0x1.0p6));
+
+  // After the first step of Newton-Raphson approximating v = sqrt(u), we have
+  // that:
+  //   sqrt(u) = v_hi + h / (sqrt(u) + v_hi)
+  //      v_lo = h / (2 * v_hi)
+  // With error:
+  //   sqrt(u) - (v_hi + v_lo) = h * ( 1/(sqrt(u) + v_hi) - 1/(2*v_hi) )
+  //                           = -h^2 / (2*v * (sqrt(u) + v)^2).
+  // Since:
+  //   (sqrt(u) + v_hi)^2 ~ (2sqrt(u))^2 = 4u,
+  // we can add another correction term to (v_hi + v_lo) that is:
+  //   v_ll = -h^2 / (2*v_hi * 4u)
+  //        = -v_lo * (h / 4u)
+  //        = -vl * (h / 8u),
+  // making the errors:
+  //   sqrt(u) - (v_hi + v_lo + v_ll) = O(h^3)
+  // well beyond 128-bit precision needed.
+
+  // Get the rounding error of vl = 2 * v_lo ~ h / vh
+  // Get full product of vh * vl
+#ifdef LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+  double vl_lo = fputil::multiply_add(-v_hi, vl, h) / v_hi;
+#else
+  DoubleDouble vh_vl = fputil::exact_mult(v_hi, vl);
+  double vl_lo = ((h - vh_vl.hi) - vh_vl.lo) / v_hi;
+#endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+  // vll = 2*v_ll = -vl * (h / (4u)).
+  double t = h * (-0.25) / u;
+  double vll = fputil::multiply_add(vl, t, vl_lo);
+  // m_v = -(v_hi + v_lo + v_ll).
+  Float128 m_v = fputil::quick_add(
+      Float128(vh), fputil::quick_add(Float128(vl), Float128(vll)));
+  m_v.sign = Sign::NEG;
+
+  // Perform computations in Float128:
+  //   asin(x) = pi/2 - (v_hi + v_lo + vll) * P(u).
+  Float128 y_f128(fputil::multiply_add(static_cast<double>(idx), -0x1.0p-6, u));
+
+  Float128 p_f128 = asin_eval(y_f128, idx);
+  Float128 r0_f128 = fputil::quick_mul(m_v, p_f128);
+  Float128 r_f128 = fputil::quick_add(PI_OVER_TWO_F128, r0_f128);
+
+  if (xbits.is_neg())
+    r_f128.sign = Sign::NEG;
+
+  return static_cast<double>(r_f128);
+#endif // LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/asin_utils.h b/src/math/generic/asin_utils.h
new file mode 100644
index 0000000..44913d5
--- /dev/null
+++ b/src/math/generic/asin_utils.h
@@ -0,0 +1,574 @@
+//===-- Collection of utils for asin/acos -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_GENERIC_ASIN_UTILS_H
+#define LLVM_LIBC_SRC_MATH_GENERIC_ASIN_UTILS_H
+
+#include "src/__support/FPUtil/PolyEval.h"
+#include "src/__support/FPUtil/double_double.h"
+#include "src/__support/FPUtil/dyadic_float.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/nearest_integer.h"
+#include "src/__support/integer_literals.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/optimization.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+namespace {
+
+using DoubleDouble = fputil::DoubleDouble;
+using Float128 = fputil::DyadicFloat<128>;
+
+constexpr DoubleDouble PI = {0x1.1a62633145c07p-53, 0x1.921fb54442d18p1};
+
+constexpr DoubleDouble PI_OVER_TWO = {0x1.1a62633145c07p-54,
+                                      0x1.921fb54442d18p0};
+
+#ifdef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+
+// When correct rounding is not needed, we use a degree-22 minimax polynomial to
+// approximate asin(x)/x on [0, 0.5] using Sollya with:
+// > P = fpminimax(asin(x)/x, [|0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22|],
+//                 [|1, D...|], [0, 0.5]);
+// > dirtyinfnorm(asin(x)/x - P, [0, 0.5]);
+// 0x1.1a71ef0a0f26a9fb7ed7e41dee788b13d1770db3dp-52
+
+constexpr double ASIN_COEFFS[12] = {
+    0x1.0000000000000p0,  0x1.5555555556dcfp-3,  0x1.3333333082e11p-4,
+    0x1.6db6dd14099edp-5, 0x1.f1c69b35bf81fp-6,  0x1.6e97194225a67p-6,
+    0x1.1babddb82ce12p-6, 0x1.d55bd078600d6p-7,  0x1.33328959e63d6p-7,
+    0x1.2b5993bda1d9bp-6, -0x1.806aff270bf25p-7, 0x1.02614e5ed3936p-5,
+};
+
+LIBC_INLINE double asin_eval(double u) {
+  double u2 = u * u;
+  double c0 = fputil::multiply_add(u, ASIN_COEFFS[1], ASIN_COEFFS[0]);
+  double c1 = fputil::multiply_add(u, ASIN_COEFFS[3], ASIN_COEFFS[2]);
+  double c2 = fputil::multiply_add(u, ASIN_COEFFS[5], ASIN_COEFFS[4]);
+  double c3 = fputil::multiply_add(u, ASIN_COEFFS[7], ASIN_COEFFS[6]);
+  double c4 = fputil::multiply_add(u, ASIN_COEFFS[9], ASIN_COEFFS[8]);
+  double c5 = fputil::multiply_add(u, ASIN_COEFFS[11], ASIN_COEFFS[10]);
+
+  double u4 = u2 * u2;
+  double d0 = fputil::multiply_add(u2, c1, c0);
+  double d1 = fputil::multiply_add(u2, c3, c2);
+  double d2 = fputil::multiply_add(u2, c5, c4);
+
+  return fputil::polyeval(u4, d0, d1, d2);
+}
+
+#else
+
+// The Taylor expansion of asin(x) around 0 is:
+//   asin(x) = x + x^3/6 + 3x^5/40 + ...
+//           ~ x * P(x^2).
+// Let u = x^2, then P(x^2) = P(u), and |x| = sqrt(u).  Note that when
+// |x| <= 0.5, we have |u| <= 0.25.
+// We approximate P(u) by breaking it down by performing range reduction mod
+//   2^-5 = 1/32.
+// So for:
+//   k = round(u * 32),
+//   y = u - k/32,
+// we have that:
+//   x = sqrt(u) = sqrt(k/32 + y),
+//   |y| <= 2^-5 = 1/32,
+// and:
+//   P(u) = P(k/32 + y) = Q_k(y).
+// Hence :
+//   asin(x) = sqrt(k/32 + y) * Q_k(y),
+// Or equivalently:
+//   Q_k(y) = asin(sqrt(k/32 + y)) / sqrt(k/32 + y).
+// We generate the coefficients of Q_k by Sollya as following:
+// > procedure ASIN_APPROX(N, Deg) {
+//     abs_error = 0;
+//     rel_error = 0;
+//     deg = [||];
+//     for i from 2 to Deg do deg = deg :. i;
+//     for i from 1 to N/4 do {
+//       F = asin(sqrt(i/N + x))/sqrt(i/N + x);
+//       T = taylor(F, 1, 0);
+//       T_DD = roundcoefficients(T, [|DD...|]);
+//       I = [-1/(2*N), 1/(2*N)];
+//       Q = fpminimax(F, deg, [|D...|], I, T_DD);
+//       abs_err = dirtyinfnorm(F - Q, I);
+//       rel_err = dirtyinfnorm((F - Q)/x^2, I);
+//       if (abs_err > abs_error) then abs_error = abs_err;
+//       if (rel_err > rel_error) then rel_error = rel_err;
+//       d0 = D(coeff(Q, 0));
+//       d1 = coeff(Q, 0) - d0;
+//       write("{", d0, ", ", d1);
+//       d0 = D(coeff(Q, 1)); d1 = coeff(Q, 1) - d0;  write(", ", d0, ", ", d1);
+//       for j from 2 to Deg do {
+//         write(", ", coeff(Q, j));
+//       };
+//       print("},");
+//     };
+//     print("Absolute Errors:", D(abs_error));
+//     print("Relative Errors:", D(rel_error));
+//  };
+// > ASIN_APPROX(32, 9);
+// Absolute Errors: 0x1.69837b5183654p-72
+// Relative Errors: 0x1.4d7f82835bf64p-55
+
+// For k = 0, we use the degree-18 Taylor polynomial of asin(x)/x:
+//
+// > P = 1 + x^2 * DD(1/6) + x^4 * D(3/40) + x^6 * D(5/112) + x^8 * D(35/1152) +
+//       x^10 * D(63/2816) + x^12 * D(231/13312) + x^14 * D(143/10240) +
+//       x^16 * D(6435/557056) + x^18 * D(12155/1245184);
+// > dirtyinfnorm(asin(x)/x - P, [-1/64, 1/64]);
+// 0x1.999075402cafp-83
+
+constexpr double ASIN_COEFFS[9][12] = {
+    {1.0, 0.0, 0x1.5555555555555p-3, 0x1.5555555555555p-57,
+     0x1.3333333333333p-4, 0x1.6db6db6db6db7p-5, 0x1.f1c71c71c71c7p-6,
+     0x1.6e8ba2e8ba2e9p-6, 0x1.1c4ec4ec4ec4fp-6, 0x1.c99999999999ap-7,
+     0x1.7a87878787878p-7, 0x1.3fde50d79435ep-7},
+    {0x1.015a397cf0f1cp0, -0x1.eebd6ccfe3ee3p-55, 0x1.5f3581be7b08bp-3,
+     -0x1.5df80d0e7237dp-57, 0x1.4519ddf1ae53p-4, 0x1.8eb4b6eeb1696p-5,
+     0x1.17bc85420fec8p-5, 0x1.a8e39b5dcad81p-6, 0x1.53f8df127539bp-6,
+     0x1.1a485a0b0130ap-6, 0x1.e20e6e493002p-7, 0x1.a466a7030f4c9p-7},
+    {0x1.02be9ce0b87cdp0, 0x1.e5d09da2e0f04p-56, 0x1.69ab5325bc359p-3,
+     -0x1.92f480cfede2dp-57, 0x1.58a4c3097aab1p-4, 0x1.b3db36068dd8p-5,
+     0x1.3b9482184625p-5, 0x1.eedc823765d21p-6, 0x1.98e35d756be6bp-6,
+     0x1.5ea4f1b32731ap-6, 0x1.355115764148ep-6, 0x1.16a5853847c91p-6},
+    {0x1.042dc6a65ffbfp0, -0x1.c7ea28dce95d1p-55, 0x1.74c4bd7412f9dp-3,
+     0x1.447024c0a3c87p-58, 0x1.6e09c6d2b72b9p-4, 0x1.ddd9dcdae5315p-5,
+     0x1.656f1f64058b8p-5, 0x1.21a42e4437101p-5, 0x1.eed0350b7edb2p-6,
+     0x1.b6bc877e58c52p-6, 0x1.903a0872eb2a4p-6, 0x1.74da839ddd6d8p-6},
+    {0x1.05a8621feb16bp0, -0x1.e5b33b1407c5fp-56, 0x1.809186c2e57ddp-3,
+     -0x1.3dcb4d6069407p-60, 0x1.8587d99442dc5p-4, 0x1.06c23d1e75be3p-4,
+     0x1.969024051c67dp-5, 0x1.54e4f934aacfdp-5, 0x1.2d60a732dbc9cp-5,
+     0x1.149f0c046eac7p-5, 0x1.053a56dba1fbap-5, 0x1.f7face3343992p-6},
+    {0x1.072f2b6f1e601p0, -0x1.2dcbb0541997p-54, 0x1.8d2397127aebap-3,
+     0x1.ead0c497955fbp-57, 0x1.9f68df88da518p-4, 0x1.21ee26a5900d7p-4,
+     0x1.d08e7081b53a9p-5, 0x1.938dd661713f7p-5, 0x1.71b9f299b72e6p-5,
+     0x1.5fbc7d2450527p-5, 0x1.58573247ec325p-5, 0x1.585a174a6a4cep-5},
+    {0x1.08c2f1d638e4cp0, 0x1.b47c159534a3dp-56, 0x1.9a8f592078624p-3,
+     -0x1.ea339145b65cdp-57, 0x1.bc04165b57aabp-4, 0x1.410df5f58441dp-4,
+     0x1.0ab6bdf5f8f7p-4, 0x1.e0b92eea1fce1p-5, 0x1.c9094e443a971p-5,
+     0x1.c34651d64bc74p-5, 0x1.caa008d1af08p-5, 0x1.dc165bc0c4fc5p-5},
+    {0x1.0a649a73e61f2p0, 0x1.74ac0d817e9c7p-55, 0x1.a8ec30dc9389p-3,
+     -0x1.8ab1c0eef300cp-59, 0x1.dbc11ea95061bp-4, 0x1.64e371d661328p-4,
+     0x1.33e0023b3d895p-4, 0x1.2042269c243cep-4, 0x1.1cce74bda223p-4,
+     0x1.244d425572ce9p-4, 0x1.34d475c7f1e3ep-4, 0x1.4d4e653082ad3p-4},
+    {0x1.0c152382d7366p0, -0x1.ee6913347c2a6p-54, 0x1.b8550d62bfb6dp-3,
+     -0x1.d10aec3f116d5p-57, 0x1.ff1bde0fa3cap-4, 0x1.8e5f3ab69f6a4p-4,
+     0x1.656be8b6527cep-4, 0x1.5c39755dc041ap-4, 0x1.661e6ebd40599p-4,
+     0x1.7ea3dddee2a4fp-4, 0x1.a4f439abb4869p-4, 0x1.d9181c0fda658p-4},
+};
+
+// We calculate the lower part of the approximation P(u).
+LIBC_INLINE DoubleDouble asin_eval(const DoubleDouble &u, unsigned &idx,
+                                   double &err) {
+  using fputil::multiply_add;
+  // k = round(u * 32).
+  double k = fputil::nearest_integer(u.hi * 0x1.0p5);
+  idx = static_cast<unsigned>(k);
+  // y = u - k/32.
+  double y_hi = multiply_add(k, -0x1.0p-5, u.hi); // Exact
+  DoubleDouble y = fputil::exact_add(y_hi, u.lo);
+  double y2 = y.hi * y.hi;
+  // Add double-double errors in addition to the relative errors from y2.
+  err = fputil::multiply_add(err, y2, 0x1.0p-102);
+  DoubleDouble c0 = fputil::quick_mult(
+      y, DoubleDouble{ASIN_COEFFS[idx][3], ASIN_COEFFS[idx][2]});
+  double c1 = multiply_add(y.hi, ASIN_COEFFS[idx][5], ASIN_COEFFS[idx][4]);
+  double c2 = multiply_add(y.hi, ASIN_COEFFS[idx][7], ASIN_COEFFS[idx][6]);
+  double c3 = multiply_add(y.hi, ASIN_COEFFS[idx][9], ASIN_COEFFS[idx][8]);
+  double c4 = multiply_add(y.hi, ASIN_COEFFS[idx][11], ASIN_COEFFS[idx][10]);
+
+  double y4 = y2 * y2;
+  double d0 = multiply_add(y2, c2, c1);
+  double d1 = multiply_add(y2, c4, c3);
+
+  DoubleDouble r = fputil::exact_add(ASIN_COEFFS[idx][0], c0.hi);
+
+  double e1 = multiply_add(y4, d1, d0);
+
+  r.lo = multiply_add(y2, e1, ASIN_COEFFS[idx][1] + c0.lo + r.lo);
+
+  return r;
+}
+
+// Follow the discussion above, we generate the coefficients of Q_k by Sollya as
+// following:
+// > procedure PRINTF128(a) {
+//   write("{");
+//   if (a < 0)
+//     then write("Sign::NEG, ") else write("Sign::POS, ");
+//   a_exp = floor(log2(a)) + 1;
+//   write((a + 2 ^ a_exp) * 2 ^ -128);
+//   print("},");
+// };
+// > verbosity = 0;
+// > procedure ASIN_APPROX(N, Deg) {
+//     abs_error = 0;
+//     rel_error = 0;
+//     for i from 1 to N / 4 do {
+//       Q = fpminimax(asin(sqrt(i / N + x)) / sqrt(i / N + x), Deg,
+//                     [| 128... | ], [ -1 / (2 * N), 1 / (2 * N) ]);
+//       abs_err = dirtyinfnorm(asin(sqrt(i / N + x)) - sqrt(i / N + x) * Q,
+//                              [ -1 / (2 * N), 1 / (2 * N) ]);
+//       rel_err = dirtyinfnorm(asin(sqrt(i / N + x)) / sqrt(i / N + x) - Q,
+//                              [ -1 / (2 * N), 1 / (2 * N) ]);
+//       if (abs_err > abs_error) then abs_error = abs_err;
+//       if (rel_err > rel_error) then rel_error = rel_err;
+//       write("{");
+//       for j from 0 to Deg do PRINTF128(coeff(Q, j));
+//       print("},");
+//     };
+//     print("Absolute Errors:", abs_error);
+//     print("Relative Errors:", rel_error);
+//   };
+// > ASIN_APPROX(64, 15);
+// ...
+// Absolute Errors: 0x1.0b3...p-129
+// Relative Errors: 0x1.1db...p-128
+//
+// For k = 0, we use Taylor polynomial of asin(x)/x around x = 0.
+//   asin(x)/x ~ 1 + x^2/6 + (3 x^4)/40 + (5 x^6)/112 + (35 x^8)/1152 +
+//               + (63 x^10)/2816 + (231 x^12)/13312 + (143 x^14)/10240 +
+//               + (6435 x^16)/557056 + (12155 x^18)/1245184 +
+//               + (46189 x^20)/5505024 + (88179 x^22)/12058624 +
+//               + (676039 x^24)/104857600 + (1300075 x^26)/226492416 +
+//               + (5014575 x^28)/973078528 + (9694845 x^30)/2080374784.
+
+constexpr Float128 ASIN_COEFFS_F128[17][16] = {
+    {
+        {Sign::POS, -127, 0x80000000'00000000'00000000'00000000_u128},
+        {Sign::POS, -130, 0xaaaaaaaa'aaaaaaaa'aaaaaaaa'aaaaaaab_u128},
+        {Sign::POS, -131, 0x99999999'99999999'99999999'9999999a_u128},
+        {Sign::POS, -132, 0xb6db6db6'db6db6db'6db6db6d'b6db6db7_u128},
+        {Sign::POS, -133, 0xf8e38e38'e38e38e3'8e38e38e'38e38e39_u128},
+        {Sign::POS, -133, 0xb745d174'5d1745d1'745d1745'd1745d17_u128},
+        {Sign::POS, -133, 0x8e276276'27627627'62762762'76276276_u128},
+        {Sign::POS, -134, 0xe4cccccc'cccccccc'cccccccc'cccccccd_u128},
+        {Sign::POS, -134, 0xbd43c3c3'c3c3c3c3'c3c3c3c3'c3c3c3c4_u128},
+        {Sign::POS, -134, 0x9fef286b'ca1af286'bca1af28'6bca1af3_u128},
+        {Sign::POS, -134, 0x89779e79'e79e79e7'9e79e79e'79e79e7a_u128},
+        {Sign::POS, -135, 0xef9de9bd'37a6f4de'9bd37a6f'4de9bd38_u128},
+        {Sign::POS, -135, 0xd3431eb8'51eb851e'b851eb85'1eb851ec_u128},
+        {Sign::POS, -135, 0xbc16ed09'7b425ed0'97b425ed'097b425f_u128},
+        {Sign::POS, -135, 0xa8dd1846'9ee58469'ee58469e'e58469ee_u128},
+        {Sign::POS, -135, 0x98b41def'7bdef7bd'ef7bdef7'bdef7bdf_u128},
+    },
+    {
+        {Sign::POS, -127, 0x8055f060'94f0f05f'3ac3b927'50a701d9_u128},
+        {Sign::POS, -130, 0xad19c2ea'e3dd2429'8d04f71d'b965ee1b_u128},
+        {Sign::POS, -131, 0x9dfa882b'7b31af17'f9f19d33'0c45d24b_u128},
+        {Sign::POS, -132, 0xbedd3b58'c9e605ef'1404e1f0'4ba57940_u128},
+        {Sign::POS, -132, 0x83df2581'cb4fea82'b406f201'2fde6d5c_u128},
+        {Sign::POS, -133, 0xc534fe61'9b82dd16'ed5d8a43'f7710526_u128},
+        {Sign::POS, -133, 0x9b56fa62'88295ddf'ce8425fe'a04d733e_u128},
+        {Sign::POS, -134, 0xfdeddb19'4a030da7'27158080'd24caf46_u128},
+        {Sign::POS, -134, 0xd55827db'ff416ea8'042c4d8c'07cddeeb_u128},
+        {Sign::POS, -134, 0xb71d73a9'f2ba0688'5eaeeae9'413a0f5f_u128},
+        {Sign::POS, -134, 0x9fde87e2'ace91274'38f82666'd619c1ba_u128},
+        {Sign::POS, -134, 0x8d876557'5e4626a1'1b621336'93587847_u128},
+        {Sign::POS, -135, 0xfd801840'c8710595'6880fe13'a9657f8f_u128},
+        {Sign::POS, -135, 0xe54245a9'4c8c2ebb'30488494'64b0e34d_u128},
+        {Sign::POS, -135, 0xd11eb46f'4095a661'8890d123'15c96482_u128},
+        {Sign::POS, -135, 0xc01a4201'467fbc0b'960618d5'ec2adaa8_u128},
+    },
+    {
+        {Sign::POS, -127, 0x80ad1cbe'7878de11'4293301c'11ce9d49_u128},
+        {Sign::POS, -130, 0xaf9ac0df'3d845544'0fe5e31b'9051d03e_u128},
+        {Sign::POS, -131, 0xa28ceef8'd7297e05'f94773ad'f4a695c6_u128},
+        {Sign::POS, -132, 0xc75a5b77'58b4b11d'396c68ad'6733022b_u128},
+        {Sign::POS, -132, 0x8bde42a1'084a6674'50c5bceb'005d4b62_u128},
+        {Sign::POS, -133, 0xd471cdae'e2f35a96'bd4bc513'e0ccdf2c_u128},
+        {Sign::POS, -133, 0xa9fc6fd5'd204a4e3'e609940c'6b991b67_u128},
+        {Sign::POS, -133, 0x8d242d97'ba12b492'e25c7e7c'0c3fcf60_u128},
+        {Sign::POS, -134, 0xf0f1ba74'b149afc3'2f0bbab5'a20c6199_u128},
+        {Sign::POS, -134, 0xd21b42fb'd8e9098d'19612692'9a043332_u128},
+        {Sign::POS, -134, 0xba5e5492'7896a3e7'193a74d5'78631587_u128},
+        {Sign::POS, -134, 0xa7a17ae7'fc707f45'910e7a5d'c95251f4_u128},
+        {Sign::POS, -134, 0x98889a6a'b0370464'50c950d3'61d79ed7_u128},
+        {Sign::POS, -134, 0x8c29330e'4318fd29'25c5b528'84e39e7c_u128},
+        {Sign::POS, -134, 0x81e7bf48'b25bc7c0'b9204a4f'd4f5fa8b_u128},
+        {Sign::POS, -135, 0xf2801b09'11bf0768'773996dd'5224d852_u128},
+    },
+    {
+        {Sign::POS, -127, 0x81058e3e'f82ba622'ab81cd63'e1a91d57_u128},
+        {Sign::POS, -130, 0xb22e7055'c80dd354'8a2f2e8e'860d3f33_u128},
+        {Sign::POS, -131, 0xa753ce1a'7e3d1f57'247b37e6'03f93624_u128},
+        {Sign::POS, -132, 0xd05c5604'8eca8d18'dcdd76b7'f4b1f185_u128},
+        {Sign::POS, -132, 0x947cdd5e'f1d64df0'84f78df1'e2ecb854_u128},
+        {Sign::POS, -133, 0xe5218370'2ebbf6e8'3727a755'57843b93_u128},
+        {Sign::POS, -133, 0xba482553'383b92eb'186f78f1'8c35d6af_u128},
+        {Sign::POS, -133, 0x9d2b034a'7266c6a1'54b78a98'1a547429_u128},
+        {Sign::POS, -133, 0x8852f723'feea6046'e125f5a9'64e168e6_u128},
+        {Sign::POS, -134, 0xf19c9891'6c896c99'732052fe'5c54e992_u128},
+        {Sign::POS, -134, 0xd9cc81a5'c5ddf0f0'd651011e'a8ecd936_u128},
+        {Sign::POS, -134, 0xc7173169'dcb6095f'a6160847'b595aaff_u128},
+        {Sign::POS, -134, 0xb81cd3f6'4a422ebe'07aeb734'e4dcf3a1_u128},
+        {Sign::POS, -134, 0xabf01b1c'd15932aa'698d4382'512318a9_u128},
+        {Sign::POS, -134, 0xa1f1cf1b'd889a1ac'7120ca2f'bbbc1745_u128},
+        {Sign::POS, -134, 0x99a1b838'e38fbf11'429a4350'76b7d191_u128},
+    },
+    {
+        {Sign::POS, -127, 0x815f4e70'5c3e68f2'e84ed170'78211dfd_u128},
+        {Sign::POS, -130, 0xb4d5a992'de1ac4da'16fe6024'3a6cc371_u128},
+        {Sign::POS, -131, 0xac526184'bd558c65'66642dce'edc4b04a_u128},
+        {Sign::POS, -132, 0xd9ed9b03'46ec0bab'429ea221'4774bbc1_u128},
+        {Sign::POS, -132, 0x9dca410c'1efaeb74'87956685'dd5fe848_u128},
+        {Sign::POS, -133, 0xf76e411b'a926fc02'7f942265'9c39a882_u128},
+        {Sign::POS, -133, 0xcc71b004'eeb60c0f'1d387f76'44b46bf8_u128},
+        {Sign::POS, -133, 0xaf527a40'6f1084fb'5019904e'd12d384d_u128},
+        {Sign::POS, -133, 0x9a9304b0'd8a9de19'e1803691'269be22c_u128},
+        {Sign::POS, -133, 0x8b3d37c0'dbde09ef'342ddf4f'e80dd3fb_u128},
+        {Sign::POS, -134, 0xff2e9111'3a961c78'92297bab'cc257804_u128},
+        {Sign::POS, -134, 0xed1fb643'f2ca31c1'b0a1553a'e077285a_u128},
+        {Sign::POS, -134, 0xdeeb0f5e'81ad5e30'78d79ae3'83be1c18_u128},
+        {Sign::POS, -134, 0xd3a13ba6'8ce9abfc'a66eb1fd'c0c760fd_u128},
+        {Sign::POS, -134, 0xcaa8c381'd44bb44f'0ab25126'9a5fae10_u128},
+        {Sign::POS, -134, 0xc36fb2c4'244401cf'10dd8a39'78ccbf7f_u128},
+    },
+    {
+        {Sign::POS, -127, 0x81ba6750'6064f4dd'08015b7c'713688f0_u128},
+        {Sign::POS, -130, 0xb791524b'd975fdd1'584037b7'103b42ca_u128},
+        {Sign::POS, -131, 0xb18c26c5'3ced9856'db5bc672'cc95a64f_u128},
+        {Sign::POS, -132, 0xe4199ce5'd25be89b'4a0ad208'da77022d_u128},
+        {Sign::POS, -132, 0xa7d77999'0f80e3e9'7e97e9d1'0e337550_u128},
+        {Sign::POS, -132, 0x85c3e039'8959c95b'e6e1e87f'7e6636b1_u128},
+        {Sign::POS, -133, 0xe0b90ecd'95f7e6eb'a675bae0'628bd214_u128},
+        {Sign::POS, -133, 0xc3edb6b4'ed0a684c'c7a3ee4d'f1dcd3f9_u128},
+        {Sign::POS, -133, 0xafa274d2'e66e1f61'9e8ab3c7'7221214e_u128},
+        {Sign::POS, -133, 0xa0dd903d'e110b71a'8a1fc9df'cc080308_u128},
+        {Sign::POS, -133, 0x95e2f38c'60441961'72b90625'e3a37573_u128},
+        {Sign::POS, -133, 0x8d9fe38f'2c705139'029f857c'9f628b2b_u128},
+        {Sign::POS, -133, 0x8762410a'4967a974'6b609e83'7c025a39_u128},
+        {Sign::POS, -133, 0x82b220be'd9ec0e5a'9ce9af7c'c65c94b9_u128},
+        {Sign::POS, -134, 0xfe866073'2312c056'4265d82a'3afea10c_u128},
+        {Sign::POS, -134, 0xf99b667c'5f8ef6a6'11fafa4d'5c76ebb3_u128},
+    },
+    {
+        {Sign::POS, -127, 0x8216e353'2ffdf638'15d72316'a2f327f2_u128},
+        {Sign::POS, -130, 0xba625eba'097ce944'7024c0a3'c873729b_u128},
+        {Sign::POS, -131, 0xb704e369'5b95ce44'cde30106'90e92cc3_u128},
+        {Sign::POS, -132, 0xeeecee6d'7298b8a3'075da5d7'456bdcde_u128},
+        {Sign::POS, -132, 0xb2b78fb1'fcfdc273'1d1ac11c'e29c16f1_u128},
+        {Sign::POS, -132, 0x90d21722'148fdaf5'0d566a01'0bb8784b_u128},
+        {Sign::POS, -133, 0xf7681c54'9771ebb6'17686858'eb5e1caf_u128},
+        {Sign::POS, -133, 0xdb5e45c0'52ec0c1c'ff28765e'd4c44bfb_u128},
+        {Sign::POS, -133, 0xc7ff0dd7'a34ee29b'7cb689af'fe887bf5_u128},
+        {Sign::POS, -133, 0xba4e6f37'a98a3e3f'f1175427'20f45c82_u128},
+        {Sign::POS, -133, 0xb08f6e11'688e4174'b3d48abe'c0a6d5cd_u128},
+        {Sign::POS, -133, 0xa9af6a33'14aabe45'26da1218'05bbb52e_u128},
+        {Sign::POS, -133, 0xa4fd22fa'1b4f0d7f'1456af96'cbd0cde6_u128},
+        {Sign::POS, -133, 0xa20229b4'7e9c2e39'22c49987'66a05c5a_u128},
+        {Sign::POS, -133, 0xa0775ca8'4409c735'351d01f1'34467927_u128},
+        {Sign::POS, -133, 0xa010d2d9'08428a53'53603f20'66c8b8ba_u128},
+    },
+    {
+        {Sign::POS, -127, 0x8274cd6a'f25e642d'0b1a02fb'03f53f3e_u128},
+        {Sign::POS, -130, 0xbd49d2c8'b9005b2a'ee795b17'92181a48_u128},
+        {Sign::POS, -131, 0xbcc0ac23'98e00fd7'c40811f5'486aca6a_u128},
+        {Sign::POS, -132, 0xfa756493'b381b917'6cdea268'e44dd2fd_u128},
+        {Sign::POS, -132, 0xbe7fce1e'462b43c6'0537d6f7'138c87ac_u128},
+        {Sign::POS, -132, 0x9d00958b'edc83095'b4cc907c'a92c30f1_u128},
+        {Sign::POS, -132, 0x886a2440'ed93d825'333c19c2'6de36d73_u128},
+        {Sign::POS, -133, 0xf616ebc0'4f576462'd9312544'e8fbe0fd_u128},
+        {Sign::POS, -133, 0xe43f4c9d'ebb5d685'00903a00'7bd6ad39_u128},
+        {Sign::POS, -133, 0xd8516eab'32337672'569b4e19'a44e795c_u128},
+        {Sign::POS, -133, 0xd091fa04'954666ee'cc4da283'82e977c0_u128},
+        {Sign::POS, -133, 0xcbf13442'c4c0f859'0449c2c4'2fc046fe_u128},
+        {Sign::POS, -133, 0xc9c1d1b4'dea4c76c'd101e562'dc3af77f_u128},
+        {Sign::POS, -133, 0xc9924d2a'b8ec37d9'80af1780'0fb63e4e_u128},
+        {Sign::POS, -133, 0xcb24b252'1ff37e4a'41f35260'2b9ace95_u128},
+        {Sign::POS, -133, 0xce2d87ac'194a6304'1658ed0e'4cdb8161_u128},
+    },
+    {
+        {Sign::POS, -127, 0x82d4310f'f58b570d'266275fc'1d085c87_u128},
+        {Sign::POS, -130, 0xc048c361'72bee7b0'8d2ca7e5'afe4f335_u128},
+        {Sign::POS, -131, 0xc2c3ecca'216e290e'b99c5c53'5d48595a_u128},
+        {Sign::POS, -131, 0x83611e8f'3adf2217'be3c342a'dfb1c562_u128},
+        {Sign::POS, -132, 0xcb481202'8b0ba9aa'e586f73d'faea68e4_u128},
+        {Sign::POS, -132, 0xaa727c9a'4caba65d'c8dc13ef'8bed52e4_u128},
+        {Sign::POS, -132, 0x96b05462'efac126e'db6871d0'0be1eff9_u128},
+        {Sign::POS, -132, 0x8a4f8752'9b3c9232'63eb1596'a2c83eb4_u128},
+        {Sign::POS, -132, 0x828be6f4'1b14e6e6'8efc1012'2afe425a_u128},
+        {Sign::POS, -133, 0xfbd2f055'9d699ea9'b572008e'1fb08088_u128},
+        {Sign::POS, -133, 0xf71b3c70'dc4610e6'bc1e581c'817b88bd_u128},
+        {Sign::POS, -133, 0xf5e8ebf6'3b0aef3f'97ba4c8f'e49b6f0a_u128},
+        {Sign::POS, -133, 0xf7986238'1eb8bd7a'73577ed0'c05e4abf_u128},
+        {Sign::POS, -133, 0xfbc3832a'a903cd65'a46ee523'f342c621_u128},
+        {Sign::POS, -132, 0x811ea5f3'7409245e'1777fdd1'59b29f80_u128},
+        {Sign::POS, -132, 0x85619588'b83c90ef'67740d6a'd2f372a8_u128},
+    },
+    {
+        {Sign::POS, -127, 0x83351a49'8764656f'e1774024'a5e751a6_u128},
+        {Sign::POS, -130, 0xc36057da'23d39c2b'336474e0'3a893914_u128},
+        {Sign::POS, -131, 0xc913714c'a46cc0bf'3bdd68ba'53a309d4_u128},
+        {Sign::POS, -131, 0x89f2254d'f1469d60'e1324bac'95db6742_u128},
+        {Sign::POS, -132, 0xd92b27f6'38df6911'5842365c'c120cc63_u128},
+        {Sign::POS, -132, 0xb94ff079'7848d391'486efffa'a6fbc37f_u128},
+        {Sign::POS, -132, 0xa6c03919'862e8437'70f86a73'43da3a6e_u128},
+        {Sign::POS, -132, 0x9bcb70c9'a378e97f'a59f25f3'ba202e33_u128},
+        {Sign::POS, -132, 0x95b103b0'62aa9f64'ee2d6146'76020bc5_u128},
+        {Sign::POS, -132, 0x92fa4a1c'7d7fd161'8f25aa4e'f65ca52f_u128},
+        {Sign::POS, -132, 0x92d387a2'c5dd771d'4015ca29'e3eda1d9_u128},
+        {Sign::POS, -132, 0x94c13c5c'997615c3'8a2f63c8'c314226f_u128},
+        {Sign::POS, -132, 0x987b8c8f'5e9e7a5f'e8497909'd60d1194_u128},
+        {Sign::POS, -132, 0x9ddb0978'da99e6ad'83d5eca2'9d079ef7_u128},
+        {Sign::POS, -132, 0xa4d9aeee'4b512ed4'5ec95cd1'37ce3f22_u128},
+        {Sign::POS, -132, 0xad602af3'1e14d681'8a267da2'57c030de_u128},
+    },
+    {
+        {Sign::POS, -127, 0x839795b7'8f3005a4'689f57cc'd201f7dc_u128},
+        {Sign::POS, -130, 0xc691cb89'3d75d3d5'a1892f2a'bf54ec45_u128},
+        {Sign::POS, -131, 0xcfb46fc4'6d28c32c'9ae5ad3d'a7749dc8_u128},
+        {Sign::POS, -131, 0x90f71352'c806c830'20edb8b2'7594386b_u128},
+        {Sign::POS, -132, 0xe8473840'd511dc77'd63def5d'7f4de9c0_u128},
+        {Sign::POS, -132, 0xc9c6eb30'aaf2b63d'ec20f671'8689534a_u128},
+        {Sign::POS, -132, 0xb8dcfa84'eb6cab93'3023ddcc'b8f68a2f_u128},
+        {Sign::POS, -132, 0xafde4094'c1a14390'9609a3ea'847225a9_u128},
+        {Sign::POS, -132, 0xac1254e7'5852a836'b2aca5e5'0cfc484f_u128},
+        {Sign::POS, -132, 0xac0d3ffa'd6171016'b1a12557'858663c1_u128},
+        {Sign::POS, -132, 0xaf0877f9'0ca5c52f'fc54b5af'b5cbc350_u128},
+        {Sign::POS, -132, 0xb498574f'af349a2b'f391ff83'b3570919_u128},
+        {Sign::POS, -132, 0xbc87c7bb'34182440'280647cd'976affb0_u128},
+        {Sign::POS, -132, 0xc6c5688f'58a42593'4569de36'0855c393_u128},
+        {Sign::POS, -132, 0xd368b088'5bb9496a'dd7c92df'8798aaf7_u128},
+        {Sign::POS, -132, 0xe272168a'c8dbe668'381542bf'fc24c266_u128},
+    },
+    {
+        {Sign::POS, -127, 0x83fbb09c'fbb0ebf4'208c9037'70373f79_u128},
+        {Sign::POS, -130, 0xc9de6f84'8e652b0b'3b2a2bb9'f7ce3de8_u128},
+        {Sign::POS, -131, 0xd6ac93c7'6e215233'f184fdcc'e5872970_u128},
+        {Sign::POS, -131, 0x987a35b9'87c02522'1927dee9'70fc6b18_u128},
+        {Sign::POS, -132, 0xf8be450d'266409a9'2e534ffd'905f4424_u128},
+        {Sign::POS, -132, 0xdc0c36d7'34415e3b'c5121c4d'4e28c17d_u128},
+        {Sign::POS, -132, 0xcd551b98'81d982a8'1399d9ba'ddf55821_u128},
+        {Sign::POS, -132, 0xc6f91e3f'428d6be3'646f3147'20445145_u128},
+        {Sign::POS, -132, 0xc64f100c'85e1e8f1'6f501d1e'2155f872_u128},
+        {Sign::POS, -132, 0xc9fe25ae'295f1f24'5924cf9a'036a31f2_u128},
+        {Sign::POS, -132, 0xd157410e'fcc10fbb'fceb318a'b4990bd7_u128},
+        {Sign::POS, -132, 0xdc0aeb56'ca679f92'3b3c44d8'99b1add7_u128},
+        {Sign::POS, -132, 0xea05b383'bc339550'e5c5c34b'bfa416a1_u128},
+        {Sign::POS, -132, 0xfb5e3897'5a5c8f62'280a90dc'9ebe9107_u128},
+        {Sign::POS, -131, 0x88301d81'b38f225d'2226ab7e'df342d90_u128},
+        {Sign::POS, -131, 0x949e3465'e4a8aef7'46311182'5fc3fde8_u128},
+    },
+    {
+        {Sign::POS, -127, 0x846178eb'1c7260da'3e0aca9a'51e68d84_u128},
+        {Sign::POS, -130, 0xcd47ac90'3c311c2b'98dd7493'4656d210_u128},
+        {Sign::POS, -131, 0xde020b2d'abd5628c'b88634e5'73f312fc_u128},
+        {Sign::POS, -131, 0xa086fafa'c220fb73'9939cae3'2d69683f_u128},
+        {Sign::POS, -131, 0x855b5efa'f6963d73'e4664cb1'd43f03a9_u128},
+        {Sign::POS, -132, 0xf05c9774'fe0de25c'ccf1c1df'd2ed9941_u128},
+        {Sign::POS, -132, 0xe484a941'19639229'f06ae955'f8edc7d1_u128},
+        {Sign::POS, -132, 0xe1a32bb2'52ca122c'bf2f0904'cfc476cb_u128},
+        {Sign::POS, -132, 0xe528e091'7bb8a01a'9218ce3e'1e85af60_u128},
+        {Sign::POS, -132, 0xeddd556a'faa2d46f'e91c61fa'adf12aec_u128},
+        {Sign::POS, -132, 0xfb390fa3'15e9d55f'5683c0c4'c7719f81_u128},
+        {Sign::POS, -131, 0x868e5fa4'15597c8f'7c42a262'8f2d6332_u128},
+        {Sign::POS, -131, 0x91d79767'a3d037f9'cd84ead5'c0714310_u128},
+        {Sign::POS, -131, 0x9fa6a035'915bc052'377a8abb'faf4e3c6_u128},
+        {Sign::POS, -131, 0xb04edefd'6ac2a93e'ec33e6f6'3d53e7c2_u128},
+        {Sign::POS, -131, 0xc416980d'dc5c186b'7bdcded6'97ea5844_u128},
+    },
+    {
+        {Sign::POS, -127, 0x84c8fd4d'ffdf9fc6'bdd7ebca'88183d7b_u128},
+        {Sign::POS, -130, 0xd0cf0544'11dbf845'cb6eeae5'bc980e2f_u128},
+        {Sign::POS, -131, 0xe5bb9480'7ce0eaca'74300a46'8398e944_u128},
+        {Sign::POS, -131, 0xa92a18f8'd611860b'5f2ef8c6'8e8ca002_u128},
+        {Sign::POS, -131, 0x8f2e1684'17eb4e6c'1ec44b9b'e4b1c3e5_u128},
+        {Sign::POS, -131, 0x837f1764'0ee8f416'8694b4a1'c647af0c_u128},
+        {Sign::POS, -132, 0xfed7e2a9'05a5190e'b7d70a61'a24ad801_u128},
+        {Sign::POS, -131, 0x803f29ff'dc6fd2bc'3c3c4b50'a9dc860c_u128},
+        {Sign::POS, -131, 0x84c61e09'b8aa35e4'96239f9c'b1d00b3c_u128},
+        {Sign::POS, -131, 0x8c7ed311'f77980d6'842ddf90'6a68a0bc_u128},
+        {Sign::POS, -131, 0x9746077b'd397c2d1'038a4744'a76f5fb5_u128},
+        {Sign::POS, -131, 0xa5341277'c4185ace'54f26328'322158e8_u128},
+        {Sign::POS, -131, 0xb68d78f5'0972f6de'9189aa23'd3ecefc2_u128},
+        {Sign::POS, -131, 0xcbbcefc2'15bade4e'f1d36947'c8b6e460_u128},
+        {Sign::POS, -131, 0xe564a459'c851390d'd45a4748'f29f182b_u128},
+        {Sign::POS, -130, 0x820ea28b'c89662c3'2a64ccdc'efb2b259_u128},
+    },
+    {
+        {Sign::POS, -127, 0x85324d39'f30f9174'ac0d817e'9c744b0b_u128},
+        {Sign::POS, -130, 0xd476186e'49c47f3a'a71f8886'7f9f21c4_u128},
+        {Sign::POS, -131, 0xede08f54'a830e87b'07881700'65e57b6c_u128},
+        {Sign::POS, -131, 0xb271b8eb'309963ee'89187c73'0b92f7d5_u128},
+        {Sign::POS, -131, 0x99f0011d'95d3a6dd'282bd00a'db808151_u128},
+        {Sign::POS, -131, 0x9021134e'02b479e7'3aabf9bb'b7ab6cf3_u128},
+        {Sign::POS, -131, 0x8e673bf2'f11db54a'909c4c72'6389499f_u128},
+        {Sign::POS, -131, 0x9226a371'88dd55f7'bfe21777'4a42a7ae_u128},
+        {Sign::POS, -131, 0x9a4d78fc'9df79d9a'44609c02'a625808a_u128},
+        {Sign::POS, -131, 0xa68335fb'41d2d91c'e7bbd2a3'31a1d17b_u128},
+        {Sign::POS, -131, 0xb6d89c39'28d0cb26'809d4df6'e55cba1a_u128},
+        {Sign::POS, -131, 0xcba71468'9177fc2d'7f23df2f'37226488_u128},
+        {Sign::POS, -131, 0xe5846de8'44833ae9'34416c87'0315eb9e_u128},
+        {Sign::POS, -130, 0x82a07032'64e6226b'200d94a1'66fc7951_u128},
+        {Sign::POS, -130, 0x9602695c'b6fa8886'68ca0cba'b59ea683_u128},
+        {Sign::POS, -130, 0xad7d185a'ab3d14dd'd908a7b1'c57352bb_u128},
+    },
+    {
+        {Sign::POS, -127, 0x859d78fa'4405d8fa'287dbc69'95d0975e_u128},
+        {Sign::POS, -130, 0xd83ea3bc'131d6baa'67c51d88'4c4dae01_u128},
+        {Sign::POS, -131, 0xf6790edb'df07342b'aad85870'167af128_u128},
+        {Sign::POS, -131, 0xbc6daa33'12be0f85'bc7fa753'52b10a83_u128},
+        {Sign::POS, -131, 0xa5bd41bc'9c986b13'1af2542e'92aacb59_u128},
+        {Sign::POS, -131, 0x9e4358bc'24e04364'b4539b76'e444b790_u128},
+        {Sign::POS, -131, 0x9f7fc21b'dca1f2b5'f3f6d44b'c5a37626_u128},
+        {Sign::POS, -131, 0xa6fd793c'0b9c44c1'30a518cc'66b5e511_u128},
+        {Sign::POS, -131, 0xb3dccfac'cd1592b3'bcd6b7c0'9749993d_u128},
+        {Sign::POS, -131, 0xc6056c3a'4a5f329a'48f1429d'27f930fc_u128},
+        {Sign::POS, -131, 0xddd9e529'858a4502'6e7f3d1c'1e7dcb89_u128},
+        {Sign::POS, -131, 0xfc1bccee'dc8d2567'1721c468'6f7f53ec_u128},
+        {Sign::POS, -130, 0x90f2bb21'5cdbe7e2'f9ef8e12'059cc66a_u128},
+        {Sign::POS, -130, 0xa857d5df'5b4da940'15ce4e95'7201fc79_u128},
+        {Sign::POS, -130, 0xc54119c0'10c02bf4'd87ece17'1ef85c5f_u128},
+        {Sign::POS, -130, 0xe8c50ebc'880356de'2c1f4c42'9ee9748f_u128},
+    },
+    {
+        {Sign::POS, -127, 0x860a91c1'6b9b2c23'2dd99707'ab3d688b_u128},
+        {Sign::POS, -130, 0xdc2a86b1'5fdb645d'ea2781dd'25555f49_u128},
+        {Sign::POS, -131, 0xff8def07'd1e514d7'b2e8ebb6'5c3afe5e_u128},
+        {Sign::POS, -131, 0xc72f9d5b'4fb559e3'20db92e3'a5ae3f73_u128},
+        {Sign::POS, -131, 0xb2b5f45b'1d26f4dd'0b210309'fb68914f_u128},
+        {Sign::POS, -131, 0xae1cbaae'c7b55465'4da858f5'47e62a37_u128},
+        {Sign::POS, -131, 0xb30f3998'10202a0d'a52ec085'a7d63289_u128},
+        {Sign::POS, -131, 0xbf51f27f'b7aff89d'dc24e2aa'208d2054_u128},
+        {Sign::POS, -131, 0xd250735e'87d0b527'6f99bcc9'bd6fc717_u128},
+        {Sign::POS, -131, 0xec543ec2'bddb2efb'36d9ce81'a7c84336_u128},
+        {Sign::POS, -130, 0x871f73e3'298ef45c'eed83998'2bc731b9_u128},
+        {Sign::POS, -130, 0x9cbb5447'af8574f1'21fa4cda'93d82b7e_u128},
+        {Sign::POS, -130, 0xb7f5a6c0'430a347f'11b22cde'91de0885_u128},
+        {Sign::POS, -130, 0xda153cc4'14abdb96'840df7c2'3299fec0_u128},
+        {Sign::POS, -129, 0x826c129b'3e4a2612'b2cd11f1'4d2ba60c_u128},
+        {Sign::POS, -129, 0x9d19c289'fc0e8aa4'f351418b'b760ce90_u128},
+    },
+};
+
+constexpr Float128 PI_OVER_TWO_F128 = {
+    Sign::POS, -127, 0xc90fdaa2'2168c234'c4c6628b'80dc1cd1_u128};
+
+constexpr Float128 PI_F128 = {Sign::POS, -126,
+                              0xc90fdaa2'2168c234'c4c6628b'80dc1cd1_u128};
+
+LIBC_INLINE Float128 asin_eval(const Float128 &u, unsigned idx) {
+  return fputil::polyeval(u, ASIN_COEFFS_F128[idx][0], ASIN_COEFFS_F128[idx][1],
+                          ASIN_COEFFS_F128[idx][2], ASIN_COEFFS_F128[idx][3],
+                          ASIN_COEFFS_F128[idx][4], ASIN_COEFFS_F128[idx][5],
+                          ASIN_COEFFS_F128[idx][6], ASIN_COEFFS_F128[idx][7],
+                          ASIN_COEFFS_F128[idx][8], ASIN_COEFFS_F128[idx][9],
+                          ASIN_COEFFS_F128[idx][10], ASIN_COEFFS_F128[idx][11],
+                          ASIN_COEFFS_F128[idx][12], ASIN_COEFFS_F128[idx][13],
+                          ASIN_COEFFS_F128[idx][14], ASIN_COEFFS_F128[idx][15]);
+}
+
+#endif // LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+
+} // anonymous namespace
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_GENERIC_ASIN_UTILS_H
diff --git a/src/math/generic/asinf.cpp b/src/math/generic/asinf.cpp
index da85441..12383bf 100644
--- a/src/math/generic/asinf.cpp
+++ b/src/math/generic/asinf.cpp
@@ -108,10 +108,16 @@ LLVM_LIBC_FUNCTION(float, asinf, (float x)) {
 
   // |x| > 1, return NaNs.
   if (LIBC_UNLIKELY(x_abs > 0x3f80'0000U)) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+
     if (x_abs <= 0x7f80'0000U) {
       fputil::set_errno_if_required(EDOM);
       fputil::raise_except_if_required(FE_INVALID);
     }
+
     return FPBits::quiet_nan().get_val();
   }
 
diff --git a/src/math/generic/asinhf.cpp b/src/math/generic/asinhf.cpp
index 37b87a8..0bb7065 100644
--- a/src/math/generic/asinhf.cpp
+++ b/src/math/generic/asinhf.cpp
@@ -61,8 +61,14 @@ LLVM_LIBC_FUNCTION(float, asinhf, (float x)) {
   };
 
   if (LIBC_UNLIKELY(x_abs >= 0x4bdd'65a5U)) {
-    if (LIBC_UNLIKELY(xbits.is_inf_or_nan()))
+    if (LIBC_UNLIKELY(xbits.is_inf_or_nan())) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits_t::quiet_nan().get_val();
+      }
+
       return x;
+    }
 
     // Exceptional cases when x > 2^24.
     switch (x_abs) {
diff --git a/src/math/generic/asinhf16.cpp b/src/math/generic/asinhf16.cpp
new file mode 100644
index 0000000..7878632
--- /dev/null
+++ b/src/math/generic/asinhf16.cpp
@@ -0,0 +1,107 @@
+//===-- Half-precision asinh(x) function ----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/asinhf16.h"
+#include "explogxf.h"
+#include "hdr/fenv_macros.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/PolyEval.h"
+#include "src/__support/FPUtil/cast.h"
+#include "src/__support/FPUtil/except_value_utils.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/rounding_mode.h"
+#include "src/__support/FPUtil/sqrt.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/optimization.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+#ifndef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+static constexpr size_t N_EXCEPTS = 8;
+
+static constexpr fputil::ExceptValues<float16, N_EXCEPTS> ASINHF16_EXCEPTS{{
+    // (input, RZ output, RU offset, RD offset, RN offset)
+
+    // x = 0x1.da4p-2, asinhf16(x) = 0x1.ca8p-2 (RZ)
+    {0x3769, 0x372a, 1, 0, 1},
+    // x = 0x1.d6cp-1, asinhf16(x) = 0x1.a58p-1 (RZ)
+    {0x3b5b, 0x3a96, 1, 0, 0},
+    // x = 0x1.c7cp+3, asinhf16(x) = 0x1.accp+1 (RZ)
+    {0x4b1f, 0x42b3, 1, 0, 0},
+    // x = 0x1.26cp+4, asinhf16(x) = 0x1.cd8p+1 (RZ)
+    {0x4c9b, 0x4336, 1, 0, 1},
+    // x = -0x1.da4p-2, asinhf16(x) = -0x1.ca8p-2 (RZ)
+    {0xb769, 0xb72a, 0, 1, 1},
+    // x = -0x1.d6cp-1, asinhf16(x) = -0x1.a58p-1 (RZ)
+    {0xbb5b, 0xba96, 0, 1, 0},
+    // x = -0x1.c7cp+3, asinhf16(x) = -0x1.accp+1 (RZ)
+    {0xcb1f, 0xc2b3, 0, 1, 0},
+    // x = -0x1.26cp+4, asinhf16(x) = -0x1.cd8p+1 (RZ)
+    {0xcc9b, 0xc336, 0, 1, 1},
+}};
+#endif // !LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+
+LLVM_LIBC_FUNCTION(float16, asinhf16, (float16 x)) {
+  using FPBits = fputil::FPBits<float16>;
+  FPBits xbits(x);
+
+  uint16_t x_u = xbits.uintval();
+  uint16_t x_abs = x_u & 0x7fff;
+
+  if (LIBC_UNLIKELY(xbits.is_inf_or_nan())) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+
+    return x;
+  }
+
+#ifndef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+  // Handle exceptional values
+  if (auto r = ASINHF16_EXCEPTS.lookup(x_u); LIBC_UNLIKELY(r.has_value()))
+    return r.value();
+#endif // !LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+
+  float xf = x;
+  const float SIGN[2] = {1.0f, -1.0f};
+  float x_sign = SIGN[x_u >> 15];
+
+  // |x| <= 0.25
+  if (LIBC_UNLIKELY(x_abs <= 0x3400)) {
+    // when |x| < 0x1.718p-5, asinhf16(x) = x. Adjust by 1 ULP for certain
+    // rounding types.
+    if (LIBC_UNLIKELY(x_abs < 0x29c6)) {
+      int rounding = fputil::quick_get_round();
+      if ((rounding == FE_UPWARD || rounding == FE_TOWARDZERO) && xf < 0)
+        return fputil::cast<float16>(xf + 0x1p-24f);
+      if ((rounding == FE_DOWNWARD || rounding == FE_TOWARDZERO) && xf > 0)
+        return fputil::cast<float16>(xf - 0x1p-24f);
+      return fputil::cast<float16>(xf);
+    }
+
+    float x_sq = xf * xf;
+    // Generated by Sollya with:
+    // > P = fpminimax(asinh(x)/x, [|0, 2, 4, 6, 8|], [|SG...|], [0, 2^-2]);
+    // The last coefficient 0x1.bd114ep-6f has been changed to 0x1.bd114ep-5f
+    // for better accuracy.
+    float p = fputil::polyeval(x_sq, 1.0f, -0x1.555552p-3f, 0x1.332f6ap-4f,
+                               -0x1.6c53dep-5f, 0x1.bd114ep-5f);
+
+    return fputil::cast<float16>(xf * p);
+  }
+
+  // General case: asinh(x) = ln(x + sqrt(x^2 + 1))
+  float sqrt_term = fputil::sqrt<float>(fputil::multiply_add(xf, xf, 1.0f));
+  return fputil::cast<float16>(
+      x_sign * log_eval(fputil::multiply_add(xf, x_sign, sqrt_term)));
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/atan2.cpp b/src/math/generic/atan2.cpp
index 8adfe33..aa770de 100644
--- a/src/math/generic/atan2.cpp
+++ b/src/math/generic/atan2.cpp
@@ -8,6 +8,7 @@
 
 #include "src/math/atan2.h"
 #include "atan_utils.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
 #include "src/__support/FPUtil/FPBits.h"
 #include "src/__support/FPUtil/double_double.h"
 #include "src/__support/FPUtil/multiply_add.h"
@@ -111,8 +112,11 @@ LLVM_LIBC_FUNCTION(double, atan2, (double y, double x)) {
   // Check for exceptional cases, whether inputs are 0, inf, nan, or close to
   // overflow, or close to underflow.
   if (LIBC_UNLIKELY(max_exp > 0x7ffU - 128U || min_exp < 128U)) {
-    if (x_bits.is_nan() || y_bits.is_nan())
+    if (x_bits.is_nan() || y_bits.is_nan()) {
+      if (x_bits.is_signaling_nan() || y_bits.is_signaling_nan())
+        fputil::raise_except_if_required(FE_INVALID);
       return FPBits::quiet_nan().get_val();
+    }
     unsigned x_except = x == 0.0 ? 0 : (FPBits(x_abs).is_inf() ? 2 : 1);
     unsigned y_except = y == 0.0 ? 0 : (FPBits(y_abs).is_inf() ? 2 : 1);
 
diff --git a/src/math/generic/atan2f.cpp b/src/math/generic/atan2f.cpp
index 726cae9..c04b0eb 100644
--- a/src/math/generic/atan2f.cpp
+++ b/src/math/generic/atan2f.cpp
@@ -7,7 +7,9 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/math/atan2f.h"
+#include "hdr/fenv_macros.h"
 #include "inv_trigf_utils.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
 #include "src/__support/FPUtil/FPBits.h"
 #include "src/__support/FPUtil/PolyEval.h"
 #include "src/__support/FPUtil/double_double.h"
@@ -264,8 +266,11 @@ LLVM_LIBC_FUNCTION(float, atan2f, (float y, float x)) {
   double den_d = static_cast<double>(den_f);
 
   if (LIBC_UNLIKELY(max_abs >= 0x7f80'0000U || num_d == 0.0)) {
-    if (x_bits.is_nan() || y_bits.is_nan())
+    if (x_bits.is_nan() || y_bits.is_nan()) {
+      if (x_bits.is_signaling_nan() || y_bits.is_signaling_nan())
+        fputil::raise_except_if_required(FE_INVALID);
       return FPBits::quiet_nan().get_val();
+    }
     double x_d = static_cast<double>(x);
     double y_d = static_cast<double>(y);
     size_t x_except = (x_d == 0.0) ? 0 : (x_abs == 0x7f80'0000 ? 2 : 1);
diff --git a/src/math/generic/atan2f128.cpp b/src/math/generic/atan2f128.cpp
new file mode 100644
index 0000000..a3aba0b
--- /dev/null
+++ b/src/math/generic/atan2f128.cpp
@@ -0,0 +1,203 @@
+//===-- Quad-precision atan2 function -------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/atan2f128.h"
+#include "atan_utils.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/dyadic_float.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/nearest_integer.h"
+#include "src/__support/integer_literals.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/optimization.h" // LIBC_UNLIKELY
+#include "src/__support/macros/properties/types.h"
+#include "src/__support/uint128.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+namespace {
+
+using Float128 = fputil::DyadicFloat<128>;
+
+static constexpr Float128 ZERO = {Sign::POS, 0, 0_u128};
+static constexpr Float128 MZERO = {Sign::NEG, 0, 0_u128};
+static constexpr Float128 PI = {Sign::POS, -126,
+                                0xc90fdaa2'2168c234'c4c6628b'80dc1cd1_u128};
+static constexpr Float128 MPI = {Sign::NEG, -126,
+                                 0xc90fdaa2'2168c234'c4c6628b'80dc1cd1_u128};
+static constexpr Float128 PI_OVER_2 = {
+    Sign::POS, -127, 0xc90fdaa2'2168c234'c4c6628b'80dc1cd1_u128};
+static constexpr Float128 MPI_OVER_2 = {
+    Sign::NEG, -127, 0xc90fdaa2'2168c234'c4c6628b'80dc1cd1_u128};
+static constexpr Float128 PI_OVER_4 = {
+    Sign::POS, -128, 0xc90fdaa2'2168c234'c4c6628b'80dc1cd1_u128};
+static constexpr Float128 THREE_PI_OVER_4 = {
+    Sign::POS, -128, 0x96cbe3f9'990e91a7'9394c9e8'a0a5159d_u128};
+
+// Adjustment for constant term:
+//   CONST_ADJ[x_sign][y_sign][recip]
+static constexpr Float128 CONST_ADJ[2][2][2] = {
+    {{ZERO, MPI_OVER_2}, {MZERO, MPI_OVER_2}},
+    {{MPI, PI_OVER_2}, {MPI, PI_OVER_2}}};
+
+} // anonymous namespace
+
+// There are several range reduction steps we can take for atan2(y, x) as
+// follow:
+
+// * Range reduction 1: signness
+// atan2(y, x) will return a number between -PI and PI representing the angle
+// forming by the 0x axis and the vector (x, y) on the 0xy-plane.
+// In particular, we have that:
+//   atan2(y, x) = atan( y/x )         if x >= 0 and y >= 0 (I-quadrant)
+//               = pi + atan( y/x )    if x < 0 and y >= 0  (II-quadrant)
+//               = -pi + atan( y/x )   if x < 0 and y < 0   (III-quadrant)
+//               = atan( y/x )         if x >= 0 and y < 0  (IV-quadrant)
+// Since atan function is odd, we can use the formula:
+//   atan(-u) = -atan(u)
+// to adjust the above conditions a bit further:
+//   atan2(y, x) = atan( |y|/|x| )         if x >= 0 and y >= 0 (I-quadrant)
+//               = pi - atan( |y|/|x| )    if x < 0 and y >= 0  (II-quadrant)
+//               = -pi + atan( |y|/|x| )   if x < 0 and y < 0   (III-quadrant)
+//               = -atan( |y|/|x| )        if x >= 0 and y < 0  (IV-quadrant)
+// Which can be simplified to:
+//   atan2(y, x) = sign(y) * atan( |y|/|x| )             if x >= 0
+//               = sign(y) * (pi - atan( |y|/|x| ))      if x < 0
+
+// * Range reduction 2: reciprocal
+// Now that the argument inside atan is positive, we can use the formula:
+//   atan(1/x) = pi/2 - atan(x)
+// to make the argument inside atan <= 1 as follow:
+//   atan2(y, x) = sign(y) * atan( |y|/|x|)            if 0 <= |y| <= x
+//               = sign(y) * (pi/2 - atan( |x|/|y| )   if 0 <= x < |y|
+//               = sign(y) * (pi - atan( |y|/|x| ))    if 0 <= |y| <= -x
+//               = sign(y) * (pi/2 + atan( |x|/|y| ))  if 0 <= -x < |y|
+
+// * Range reduction 3: look up table.
+// After the previous two range reduction steps, we reduce the problem to
+// compute atan(u) with 0 <= u <= 1, or to be precise:
+//   atan( n / d ) where n = min(|x|, |y|) and d = max(|x|, |y|).
+// An accurate polynomial approximation for the whole [0, 1] input range will
+// require a very large degree.  To make it more efficient, we reduce the input
+// range further by finding an integer idx such that:
+//   | n/d - idx/64 | <= 1/128.
+// In particular,
+//   idx := round(2^6 * n/d)
+// Then for the fast pass, we find a polynomial approximation for:
+//   atan( n/d ) ~ atan( idx/64 ) + (n/d - idx/64) * Q(n/d - idx/64)
+// For the accurate pass, we use the addition formula:
+//   atan( n/d ) - atan( idx/64 ) = atan( (n/d - idx/64)/(1 + (n*idx)/(64*d)) )
+//                                = atan( (n - d*(idx/64))/(d + n*(idx/64)) )
+// And for the fast pass, we use degree-13 minimax polynomial to compute the
+// RHS:
+//   atan(u) ~ P(u) = u - c_3 * u^3 + c_5 * u^5 - c_7 * u^7 + c_9 *u^9 -
+//                    - c_11 * u^11 + c_13 * u^13
+// with absolute errors bounded by:
+//   |atan(u) - P(u)| < 2^-121
+// and relative errors bounded by:
+//   |(atan(u) - P(u)) / P(u)| < 2^-114.
+
+LLVM_LIBC_FUNCTION(float128, atan2f128, (float128 y, float128 x)) {
+  using FPBits = fputil::FPBits<float128>;
+  using Float128 = fputil::DyadicFloat<128>;
+
+  FPBits x_bits(x), y_bits(y);
+  bool x_sign = x_bits.sign().is_neg();
+  bool y_sign = y_bits.sign().is_neg();
+  x_bits = x_bits.abs();
+  y_bits = y_bits.abs();
+  UInt128 x_abs = x_bits.uintval();
+  UInt128 y_abs = y_bits.uintval();
+  bool recip = x_abs < y_abs;
+  UInt128 min_abs = recip ? x_abs : y_abs;
+  UInt128 max_abs = !recip ? x_abs : y_abs;
+  unsigned min_exp = static_cast<unsigned>(min_abs >> FPBits::FRACTION_LEN);
+  unsigned max_exp = static_cast<unsigned>(max_abs >> FPBits::FRACTION_LEN);
+
+  Float128 num(FPBits(min_abs).get_val());
+  Float128 den(FPBits(max_abs).get_val());
+
+  // Check for exceptional cases, whether inputs are 0, inf, nan, or close to
+  // overflow, or close to underflow.
+  if (LIBC_UNLIKELY(max_exp >= 0x7fffU || min_exp == 0U)) {
+    if (x_bits.is_nan() || y_bits.is_nan())
+      return FPBits::quiet_nan().get_val();
+    unsigned x_except = x == 0 ? 0 : (FPBits(x_abs).is_inf() ? 2 : 1);
+    unsigned y_except = y == 0 ? 0 : (FPBits(y_abs).is_inf() ? 2 : 1);
+
+    // Exceptional cases:
+    //   EXCEPT[y_except][x_except][x_is_neg]
+    // with x_except & y_except:
+    //   0: zero
+    //   1: finite, non-zero
+    //   2: infinity
+    constexpr Float128 EXCEPTS[3][3][2] = {
+        {{ZERO, PI}, {ZERO, PI}, {ZERO, PI}},
+        {{PI_OVER_2, PI_OVER_2}, {ZERO, ZERO}, {ZERO, PI}},
+        {{PI_OVER_2, PI_OVER_2},
+         {PI_OVER_2, PI_OVER_2},
+         {PI_OVER_4, THREE_PI_OVER_4}},
+    };
+
+    if ((x_except != 1) || (y_except != 1)) {
+      Float128 r = EXCEPTS[y_except][x_except][x_sign];
+      if (y_sign)
+        r.sign = r.sign.negate();
+      return static_cast<float128>(r);
+    }
+  }
+
+  bool final_sign = ((x_sign != y_sign) != recip);
+  Float128 const_term = CONST_ADJ[x_sign][y_sign][recip];
+  int exp_diff = den.exponent - num.exponent;
+  // We have the following bound for normalized n and d:
+  //   2^(-exp_diff - 1) < n/d < 2^(-exp_diff + 1).
+  if (LIBC_UNLIKELY(exp_diff > FPBits::FRACTION_LEN + 2)) {
+    if (final_sign)
+      const_term.sign = const_term.sign.negate();
+    return static_cast<float128>(const_term);
+  }
+
+  // Take 24 leading bits of num and den to convert to float for fast division.
+  // We also multiply the numerator by 64 using integer addition directly to the
+  // exponent field.
+  float num_f =
+      cpp::bit_cast<float>(static_cast<uint32_t>(num.mantissa >> 104) +
+                           (6U << fputil::FPBits<float>::FRACTION_LEN));
+  float den_f = cpp::bit_cast<float>(
+      static_cast<uint32_t>(den.mantissa >> 104) +
+      (static_cast<uint32_t>(exp_diff) << fputil::FPBits<float>::FRACTION_LEN));
+
+  float k = fputil::nearest_integer(num_f / den_f);
+  unsigned idx = static_cast<unsigned>(k);
+
+  // k_f128 = idx / 64
+  Float128 k_f128(Sign::POS, -6, Float128::MantissaType(idx));
+
+  // Range reduction:
+  // atan(n/d) - atan(k) = atan((n/d - k/64) / (1 + (n/d) * (k/64)))
+  //                     = atan((n - d * k/64)) / (d + n * k/64))
+  // num_f128 = n - d * k/64
+  Float128 num_f128 = fputil::multiply_add(den, -k_f128, num);
+  // den_f128 = d + n * k/64
+  Float128 den_f128 = fputil::multiply_add(num, k_f128, den);
+
+  // q = (n - d * k) / (d + n * k)
+  Float128 q = fputil::quick_mul(num_f128, fputil::approx_reciprocal(den_f128));
+  // p ~ atan(q)
+  Float128 p = atan_eval(q);
+
+  Float128 r =
+      fputil::quick_add(const_term, fputil::quick_add(ATAN_I_F128[idx], p));
+  if (final_sign)
+    r.sign = r.sign.negate();
+
+  return static_cast<float128>(r);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/atan_utils.h b/src/math/generic/atan_utils.h
index 3331843..24c7271 100644
--- a/src/math/generic/atan_utils.h
+++ b/src/math/generic/atan_utils.h
@@ -9,8 +9,11 @@
 #ifndef LLVM_LIBC_SRC_MATH_GENERIC_ATAN_UTILS_H
 #define LLVM_LIBC_SRC_MATH_GENERIC_ATAN_UTILS_H
 
+#include "src/__support/FPUtil/PolyEval.h"
 #include "src/__support/FPUtil/double_double.h"
+#include "src/__support/FPUtil/dyadic_float.h"
 #include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/integer_literals.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
@@ -18,6 +21,7 @@ namespace LIBC_NAMESPACE_DECL {
 namespace {
 
 using DoubleDouble = fputil::DoubleDouble;
+using Float128 = fputil::DyadicFloat<128>;
 
 // atan(i/64) with i = 0..64, generated by Sollya with:
 // > for i from 0 to 64 do {
@@ -25,7 +29,7 @@ using DoubleDouble = fputil::DoubleDouble;
 //     b = round(atan(i/64) - a, D, RN);
 //     print("{", b, ",", a, "},");
 //   };
-constexpr fputil::DoubleDouble ATAN_I[65] = {
+constexpr DoubleDouble ATAN_I[65] = {
     {0.0, 0.0},
     {-0x1.220c39d4dff5p-61, 0x1.fff555bbb729bp-7},
     {-0x1.5ec431444912cp-60, 0x1.ffd55bba97625p-6},
@@ -106,7 +110,7 @@ constexpr fputil::DoubleDouble ATAN_I[65] = {
 //        + x_lo * (1 - x_hi^2 + x_hi^4)
 // Since p.lo is ~ x^3/3, the relative error from rounding is bounded by:
 //   |(atan(x) - P(x))/atan(x)| < ulp(x^2) <= 2^(-14-52) = 2^-66.
-DoubleDouble atan_eval(const DoubleDouble &x) {
+[[maybe_unused]] DoubleDouble atan_eval(const DoubleDouble &x) {
   DoubleDouble p;
   p.hi = x.hi;
   double x_hi_sq = x.hi * x.hi;
@@ -130,6 +134,106 @@ DoubleDouble atan_eval(const DoubleDouble &x) {
   return p;
 }
 
+// Float128 versions.
+// atan(i/64) with i = 0..64, generated by Sollya with:
+// > for i from 1 to 64 do {
+//     a = round(atan(i/64), 128, RN);
+//     ll = ceil(log2(a));
+//     b = 2^ll + a;
+//     print("{Sign::POS, ", 2^(ll - 128), ",", b, "},");
+// };
+constexpr Float128 ATAN_I_F128[65] = {
+    {Sign::POS, 0, 0_u128},
+    {Sign::POS, -134, 0xfffaaadd'db94d5bb'e78c5640'15f76048_u128},
+    {Sign::POS, -133, 0xffeaaddd'4bb12542'779d776d'da8c6214_u128},
+    {Sign::POS, -132, 0xbfdc0c21'86d14fcf'220e10d6'1df56ec7_u128},
+    {Sign::POS, -132, 0xffaaddb9'67ef4e36'cb2792dc'0e2e0d51_u128},
+    {Sign::POS, -131, 0x9facf873'e2aceb58'99c50bbf'08e6cdf6_u128},
+    {Sign::POS, -131, 0xbf70c130'17887460'93567e78'4cf83676_u128},
+    {Sign::POS, -131, 0xdf1cf5f3'783e1bef'71e5340b'30e5d9ef_u128},
+    {Sign::POS, -131, 0xfeadd4d5'617b6e32'c897989f'3e888ef8_u128},
+    {Sign::POS, -130, 0x8f0fd7d8'21b93725'bd375929'83a0af9a_u128},
+    {Sign::POS, -130, 0x9eb77746'331362c3'47619d25'0360fe85_u128},
+    {Sign::POS, -130, 0xae4c08f1'f6134efa'b54d3fef'0c2de994_u128},
+    {Sign::POS, -130, 0xbdcbda5e'72d81134'7b0b4f88'1c9c7488_u128},
+    {Sign::POS, -130, 0xcd35474b'643130e7'b00f3da1'a46eeb3b_u128},
+    {Sign::POS, -130, 0xdc86ba94'93051022'f621a5c1'cb552f03_u128},
+    {Sign::POS, -130, 0xebbeaef9'02b9b38c'91a2a68b'2fbd78e8_u128},
+    {Sign::POS, -130, 0xfadbafc9'6406eb15'6dc79ef5'f7a217e6_u128},
+    {Sign::POS, -129, 0x84ee2cbe'c31b12c5'c8e72197'0cabd3a3_u128},
+    {Sign::POS, -129, 0x8c5fad18'5f8bc130'ca4748b1'bf88298d_u128},
+    {Sign::POS, -129, 0x93c1b902'bf7a2df1'06459240'6fe1447a_u128},
+    {Sign::POS, -129, 0x9b13b9b8'3f5e5e69'c5abb498'd27af328_u128},
+    {Sign::POS, -129, 0xa25521b6'15784d45'43787549'88b8d9e3_u128},
+    {Sign::POS, -129, 0xa9856cca'8e6a4eda'99b7f77b'f7d9e8c1_u128},
+    {Sign::POS, -129, 0xb0a42018'4e7f0cb1'b51d51dc'200a0fc3_u128},
+    {Sign::POS, -129, 0xb7b0ca0f'26f78473'8aa32122'dcfe4483_u128},
+    {Sign::POS, -129, 0xbeab025b'1d9fbad3'910b8564'93411026_u128},
+    {Sign::POS, -129, 0xc59269ca'50d92b6d'a1746e91'f50a28de_u128},
+    {Sign::POS, -129, 0xcc66aa2a'6b58c33c'd9311fa1'4ed9b7c4_u128},
+    {Sign::POS, -129, 0xd327761e'611fe5b6'427c95e9'001e7136_u128},
+    {Sign::POS, -129, 0xd9d488ed'32e3635c'30f6394a'0806345d_u128},
+    {Sign::POS, -129, 0xe06da64a'764f7c67'c631ed96'798cb804_u128},
+    {Sign::POS, -129, 0xe6f29a19'609a84ba'60b77ce1'ca6dc2c8_u128},
+    {Sign::POS, -129, 0xed63382b'0dda7b45'6fe445ec'bc3a8d03_u128},
+    {Sign::POS, -129, 0xf3bf5bf8'bad1a21c'a7b837e6'86adf3fa_u128},
+    {Sign::POS, -129, 0xfa06e85a'a0a0be5c'66d23c7d'5dc8ecc2_u128},
+    {Sign::POS, -128, 0x801ce39e'0d205c99'a6d6c6c5'4d938596_u128},
+    {Sign::POS, -128, 0x832bf4a6'd9867e2a'4b6a09cb'61a515c1_u128},
+    {Sign::POS, -128, 0x8630a2da'da1ed065'd3e84ed5'013ca37e_u128},
+    {Sign::POS, -128, 0x892aecdf'de9547b5'094478fc'472b4afc_u128},
+    {Sign::POS, -128, 0x8c1ad445'f3e09b8c'439d8018'60205921_u128},
+    {Sign::POS, -128, 0x8f005d5e'f7f59f9b'5c835e16'65c43748_u128},
+    {Sign::POS, -128, 0x91db8f16'64f350e2'10e4f9c1'126e0220_u128},
+    {Sign::POS, -128, 0x94ac72c9'847186f6'18c4f393'f78a32f9_u128},
+    {Sign::POS, -128, 0x97731420'365e538b'abd3fe19'f1aeb6b3_u128},
+    {Sign::POS, -128, 0x9a2f80e6'71bdda20'4226f8e2'204ff3bd_u128},
+    {Sign::POS, -128, 0x9ce1c8e6'a0b8cdb9'f799c4e8'174cf11c_u128},
+    {Sign::POS, -128, 0x9f89fdc4'f4b7a1ec'f8b49264'4f0701e0_u128},
+    {Sign::POS, -128, 0xa22832db'cadaae08'92fe9c08'637af0e6_u128},
+    {Sign::POS, -128, 0xa4bc7d19'34f70924'19a87f2a'457dac9f_u128},
+    {Sign::POS, -128, 0xa746f2dd'b7602294'67b7d66f'2d74e019_u128},
+    {Sign::POS, -128, 0xa9c7abdc'4830f5c8'916a84b5'be7933f6_u128},
+    {Sign::POS, -128, 0xac3ec0fb'997dd6a1'a36273a5'6afa8ef4_u128},
+    {Sign::POS, -128, 0xaeac4c38'b4d8c080'14725e2f'3e52070a_u128},
+    {Sign::POS, -128, 0xb110688a'ebdc6f6a'43d65788'b9f6a7b5_u128},
+    {Sign::POS, -128, 0xb36b31c9'1f043691'59014174'4462f93a_u128},
+    {Sign::POS, -128, 0xb5bcc490'59ecc4af'f8f3cee7'5e3907d5_u128},
+    {Sign::POS, -128, 0xb8053e2b'c2319e73'cb2da552'10a4443d_u128},
+    {Sign::POS, -128, 0xba44bc7d'd470782f'654c2cb1'0942e386_u128},
+    {Sign::POS, -128, 0xbc7b5dea'e98af280'd4113006'e80fb290_u128},
+    {Sign::POS, -128, 0xbea94144'fd049aac'1043c5e7'55282e7d_u128},
+    {Sign::POS, -128, 0xc0ce85b8'ac526640'89dd62c4'6e92fa25_u128},
+    {Sign::POS, -128, 0xc2eb4abb'661628b5'b373fe45'c61bb9fb_u128},
+    {Sign::POS, -128, 0xc4ffaffa'bf8fbd54'8cb43d10'bc9e0221_u128},
+    {Sign::POS, -128, 0xc70bd54c'e602ee13'e7d54fbd'09f2be38_u128},
+    {Sign::POS, -128, 0xc90fdaa2'2168c234'c4c6628b'80dc1cd1_u128},
+};
+
+// Degree-13 minimax polynomial generated by Sollya with:
+// > P = fpminimax(atan(x), [|1, 3, 5, 7, 9, 11, 13|], [|1, 128...|],
+//                 [0, 2^-7]);
+// > dirtyinfnorm(atan(x) - P, [0, 2^-7]);
+// 0x1.26016ad97f323875760f869684c0898d7b7bb8bep-122
+constexpr Float128 ATAN_POLY_F128[] = {
+    {Sign::NEG, -129, 0xaaaaaaaa'aaaaaaaa'aaaaaaa6'003c5d1d_u128},
+    {Sign::POS, -130, 0xcccccccc'cccccccc'cca00232'8776b063_u128},
+    {Sign::NEG, -130, 0x92492492'49249201'27f5268a'cb24aec0_u128},
+    {Sign::POS, -131, 0xe38e38e3'8dce3d96'626a1643'f8eb68f3_u128},
+    {Sign::NEG, -131, 0xba2e8b7a'ea4ad00f'005a35c7'6ef609b1_u128},
+    {Sign::POS, -131, 0x9d82765e'd22a7d92'ac09c405'c0a69214_u128},
+};
+
+// Approximate atan for |x| <= 2^-7.
+[[maybe_unused]] Float128 atan_eval(const Float128 &x) {
+  Float128 x_sq = fputil::quick_mul(x, x);
+  Float128 x3 = fputil::quick_mul(x, x_sq);
+  Float128 p = fputil::polyeval(x_sq, ATAN_POLY_F128[0], ATAN_POLY_F128[1],
+                                ATAN_POLY_F128[2], ATAN_POLY_F128[3],
+                                ATAN_POLY_F128[4], ATAN_POLY_F128[5]);
+  return fputil::multiply_add(x3, p, x);
+}
+
 } // anonymous namespace
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/atanf16.cpp b/src/math/generic/atanf16.cpp
new file mode 100644
index 0000000..9b6ec65
--- /dev/null
+++ b/src/math/generic/atanf16.cpp
@@ -0,0 +1,107 @@
+//===-- Half-precision atanf16(x) function --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/atanf16.h"
+#include "hdr/errno_macros.h"
+#include "hdr/fenv_macros.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/PolyEval.h"
+#include "src/__support/FPUtil/cast.h"
+#include "src/__support/FPUtil/except_value_utils.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/sqrt.h"
+#include "src/__support/macros/optimization.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+// Generated by Solly using the following command:
+// > round(pi/2, SG, RN);
+static constexpr float PI_2 = 0x1.921fb6p0;
+
+#ifndef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+static constexpr size_t N_EXCEPTS = 6;
+
+static constexpr fputil::ExceptValues<float16, N_EXCEPTS> ATANF16_EXCEPTS{{
+    // (input, RZ output, RU offset, RD offset, RN offset)
+    {0x2745, 0x2744, 1, 0, 1},
+    {0x3099, 0x3090, 1, 0, 1},
+    {0x3c6c, 0x3aae, 1, 0, 1},
+    {0x466e, 0x3daa, 1, 0, 1},
+    {0x48ae, 0x3ddb, 1, 0, 0},
+    {0x5619, 0x3e3d, 1, 0, 1},
+}};
+#endif // !LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+
+LLVM_LIBC_FUNCTION(float16, atanf16, (float16 x)) {
+  using FPBits = fputil::FPBits<float16>;
+  FPBits xbits(x);
+
+  uint16_t x_u = xbits.uintval();
+  uint16_t x_abs = x_u & 0x7fff;
+  bool x_sign = x_u >> 15;
+  float sign = (x_sign ? -1.0 : 1.0);
+
+  // |x| >= +/-inf
+  if (LIBC_UNLIKELY(x_abs >= 0x7c00)) {
+    if (xbits.is_nan()) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+      return x;
+    }
+
+    // atanf16(+/-inf) = +/-pi/2
+    return fputil::cast<float16>(sign * PI_2);
+  }
+
+  float xf = x;
+  float xsq = xf * xf;
+#ifndef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
+  // Handle exceptional values
+  if (auto r = ATANF16_EXCEPTS.lookup_odd(x_abs, x_sign);
+      LIBC_UNLIKELY(r.has_value()))
+    return r.value();
+#endif
+
+  // |x| <= 0x1p0, |x| <= 1
+  if (x_abs <= 0x3c00) {
+    // atanf16(+/-0) = +/-0
+    if (LIBC_UNLIKELY(x_abs == 0))
+      return x;
+
+    // Degree-14 minimax odd polynomial of atan(x) generated by Sollya with:
+    // > P = fpminimax(atan(x)/x, [|0, 2, 4, 6, 8, 10, 12, 14|], [|SG...|],
+    // [0, 1]);
+    float result = fputil::polyeval(
+        xsq, 0x1.fffffcp-1f, -0x1.55519ep-2f, 0x1.98f6a8p-3f, -0x1.1f0a92p-3f,
+        0x1.95b654p-4f, -0x1.e65492p-5f, 0x1.8c0c36p-6f, -0x1.32316ep-8f);
+    return fputil::cast<float16>(xf * result);
+  }
+
+  // If |x| > 1
+  // y = atan(x) = sign(x) * atan(|x|)
+  // atan(|x|) = pi/2 - atan(1/|x|)
+  // Recall, 1/|x| < 1
+  float x_inv_sq = 1.0f / xsq;
+  float x_inv = fputil::sqrt<float>(x_inv_sq);
+
+  // Degree-14 minimax odd polynomial of atan(x) generated by Sollya with:
+  // > P = fpminimax(atan(x)/x, [|0, 2, 4, 6, 8, 10, 12, 14|], [|SG...|],
+  // [0, 1]);
+  float interm =
+      fputil::polyeval(x_inv_sq, 0x1.fffffcp-1f, -0x1.55519ep-2f,
+                       0x1.98f6a8p-3f, -0x1.1f0a92p-3f, 0x1.95b654p-4f,
+                       -0x1.e65492p-5f, 0x1.8c0c36p-6f, -0x1.32316ep-8f);
+
+  return fputil::cast<float16>(sign *
+                               fputil::multiply_add(x_inv, -interm, PI_2));
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/atanhf.cpp b/src/math/generic/atanhf.cpp
index a2051bd..2149314 100644
--- a/src/math/generic/atanhf.cpp
+++ b/src/math/generic/atanhf.cpp
@@ -24,6 +24,10 @@ LLVM_LIBC_FUNCTION(float, atanhf, (float x)) {
   // |x| >= 1.0
   if (LIBC_UNLIKELY(x_abs >= 0x3F80'0000U)) {
     if (xbits.is_nan()) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
       return x;
     }
     // |x| == 1.0
diff --git a/src/math/generic/atanhf16.cpp b/src/math/generic/atanhf16.cpp
new file mode 100644
index 0000000..57885ac
--- /dev/null
+++ b/src/math/generic/atanhf16.cpp
@@ -0,0 +1,98 @@
+//===-- Half-precision atanh(x) function ----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/atanhf16.h"
+#include "explogxf.h"
+#include "hdr/errno_macros.h"
+#include "hdr/fenv_macros.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/PolyEval.h"
+#include "src/__support/FPUtil/cast.h"
+#include "src/__support/FPUtil/except_value_utils.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/optimization.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+static constexpr size_t N_EXCEPTS = 1;
+static constexpr fputil::ExceptValues<float16, N_EXCEPTS> ATANHF16_EXCEPTS{{
+    // (input, RZ output, RU offset, RD offset, RN offset)
+    // x = 0x1.a5cp-4, atanhf16(x) = 0x1.a74p-4 (RZ)
+    {0x2E97, 0x2E9D, 1, 0, 0},
+}};
+
+LLVM_LIBC_FUNCTION(float16, atanhf16, (float16 x)) {
+  using FPBits = fputil::FPBits<float16>;
+
+  FPBits xbits(x);
+  Sign sign = xbits.sign();
+  uint16_t x_abs = xbits.abs().uintval();
+
+  // |x| >= 1
+  if (LIBC_UNLIKELY(x_abs >= 0x3c00U)) {
+    if (xbits.is_nan()) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+      return x;
+    }
+
+    // |x| == 1.0
+    if (x_abs == 0x3c00U) {
+      fputil::set_errno_if_required(ERANGE);
+      fputil::raise_except_if_required(FE_DIVBYZERO);
+      return FPBits::inf(sign).get_val();
+    }
+    // |x| > 1.0
+    fputil::set_errno_if_required(EDOM);
+    fputil::raise_except_if_required(FE_INVALID);
+    return FPBits::quiet_nan().get_val();
+  }
+
+  if (auto r = ATANHF16_EXCEPTS.lookup(xbits.uintval());
+      LIBC_UNLIKELY(r.has_value()))
+    return r.value();
+
+  // For |x| less than approximately 0.24
+  if (LIBC_UNLIKELY(x_abs <= 0x33f3U)) {
+    // atanh(+/-0) = +/-0
+    if (LIBC_UNLIKELY(x_abs == 0U))
+      return x;
+    // The Taylor expansion of atanh(x) is:
+    //    atanh(x) = x + x^3/3 + x^5/5 + x^7/7 + x^9/9 + x^11/11
+    //             = x * [1 + x^2/3 + x^4/5 + x^6/7 + x^8/9 + x^10/11]
+    // When |x| < 2^-5 (0x0800U), this can be approximated by:
+    //    atanh(x) ≈ x + (1/3)*x^3
+    if (LIBC_UNLIKELY(x_abs < 0x0800U)) {
+      float xf = x;
+      return fputil::cast<float16>(xf + 0x1.555556p-2f * xf * xf * xf);
+    }
+
+    // For 2^-5 <= |x| <= 0x1.fccp-3 (~0.24):
+    //   Let t = x^2.
+    //   Define P(t) ≈ (1/3)*t + (1/5)*t^2 + (1/7)*t^3 + (1/9)*t^4 + (1/11)*t^5.
+    // Coefficients (from Sollya, RN, hexadecimal):
+    //  1/3 = 0x1.555556p-2, 1/5 = 0x1.99999ap-3, 1/7 = 0x1.24924ap-3,
+    //  1/9 = 0x1.c71c72p-4, 1/11 = 0x1.745d18p-4
+    // Thus, atanh(x) ≈ x * (1 + P(x^2)).
+    float xf = x;
+    float x2 = xf * xf;
+    float pe = fputil::polyeval(x2, 0.0f, 0x1.555556p-2f, 0x1.99999ap-3f,
+                                0x1.24924ap-3f, 0x1.c71c72p-4f, 0x1.745d18p-4f);
+    return fputil::cast<float16>(fputil::multiply_add(xf, pe, xf));
+  }
+
+  float xf = x;
+  return fputil::cast<float16>(0.5 * log_eval_f((xf + 1.0f) / (xf - 1.0f)));
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/common_constants.cpp b/src/math/generic/common_constants.cpp
index 3088ef9..b2c1293 100644
--- a/src/math/generic/common_constants.cpp
+++ b/src/math/generic/common_constants.cpp
@@ -13,6 +13,45 @@
 
 namespace LIBC_NAMESPACE_DECL {
 
+// Lookup table for logf(f) = logf(1 + n*2^(-7)) where n = 0..127,
+// computed and stored as float precision constants.
+// Generated by Sollya with the following commands:
+//   display = hexadecimal;
+//   for n from 0 to 127 do { print(single(1 / (1 + n / 128.0))); };
+const float ONE_OVER_F_FLOAT[128] = {
+    0x1p0f,         0x1.fc07fp-1f,  0x1.f81f82p-1f, 0x1.f4465ap-1f,
+    0x1.f07c2p-1f,  0x1.ecc07cp-1f, 0x1.e9131ap-1f, 0x1.e573acp-1f,
+    0x1.e1e1e2p-1f, 0x1.de5d6ep-1f, 0x1.dae608p-1f, 0x1.d77b66p-1f,
+    0x1.d41d42p-1f, 0x1.d0cb58p-1f, 0x1.cd8568p-1f, 0x1.ca4b3p-1f,
+    0x1.c71c72p-1f, 0x1.c3f8fp-1f,  0x1.c0e07p-1f,  0x1.bdd2b8p-1f,
+    0x1.bacf92p-1f, 0x1.b7d6c4p-1f, 0x1.b4e81cp-1f, 0x1.b20364p-1f,
+    0x1.af286cp-1f, 0x1.ac5702p-1f, 0x1.a98ef6p-1f, 0x1.a6d01ap-1f,
+    0x1.a41a42p-1f, 0x1.a16d4p-1f,  0x1.9ec8eap-1f, 0x1.9c2d14p-1f,
+    0x1.99999ap-1f, 0x1.970e5p-1f,  0x1.948b1p-1f,  0x1.920fb4p-1f,
+    0x1.8f9c18p-1f, 0x1.8d3018p-1f, 0x1.8acb9p-1f,  0x1.886e6p-1f,
+    0x1.861862p-1f, 0x1.83c978p-1f, 0x1.818182p-1f, 0x1.7f406p-1f,
+    0x1.7d05f4p-1f, 0x1.7ad22p-1f,  0x1.78a4c8p-1f, 0x1.767dcep-1f,
+    0x1.745d18p-1f, 0x1.724288p-1f, 0x1.702e06p-1f, 0x1.6e1f76p-1f,
+    0x1.6c16c2p-1f, 0x1.6a13cep-1f, 0x1.681682p-1f, 0x1.661ec6p-1f,
+    0x1.642c86p-1f, 0x1.623fa8p-1f, 0x1.605816p-1f, 0x1.5e75bcp-1f,
+    0x1.5c9882p-1f, 0x1.5ac056p-1f, 0x1.58ed24p-1f, 0x1.571ed4p-1f,
+    0x1.555556p-1f, 0x1.539094p-1f, 0x1.51d07ep-1f, 0x1.501502p-1f,
+    0x1.4e5e0ap-1f, 0x1.4cab88p-1f, 0x1.4afd6ap-1f, 0x1.49539ep-1f,
+    0x1.47ae14p-1f, 0x1.460cbcp-1f, 0x1.446f86p-1f, 0x1.42d662p-1f,
+    0x1.414142p-1f, 0x1.3fb014p-1f, 0x1.3e22ccp-1f, 0x1.3c995ap-1f,
+    0x1.3b13b2p-1f, 0x1.3991c2p-1f, 0x1.381382p-1f, 0x1.3698ep-1f,
+    0x1.3521dp-1f,  0x1.33ae46p-1f, 0x1.323e34p-1f, 0x1.30d19p-1f,
+    0x1.2f684cp-1f, 0x1.2e025cp-1f, 0x1.2c9fb4p-1f, 0x1.2b404ap-1f,
+    0x1.29e412p-1f, 0x1.288b02p-1f, 0x1.27350cp-1f, 0x1.25e228p-1f,
+    0x1.24924ap-1f, 0x1.234568p-1f, 0x1.21fb78p-1f, 0x1.20b47p-1f,
+    0x1.1f7048p-1f, 0x1.1e2ef4p-1f, 0x1.1cf06ap-1f, 0x1.1bb4a4p-1f,
+    0x1.1a7b96p-1f, 0x1.194538p-1f, 0x1.181182p-1f, 0x1.16e068p-1f,
+    0x1.15b1e6p-1f, 0x1.1485fp-1f,  0x1.135c82p-1f, 0x1.12358ep-1f,
+    0x1.111112p-1f, 0x1.0fef02p-1f, 0x1.0ecf56p-1f, 0x1.0db20ap-1f,
+    0x1.0c9714p-1f, 0x1.0b7e6ep-1f, 0x1.0a681p-1f,  0x1.0953f4p-1f,
+    0x1.08421p-1f,  0x1.07326p-1f,  0x1.0624dep-1f, 0x1.05198p-1f,
+    0x1.041042p-1f, 0x1.03091cp-1f, 0x1.020408p-1f, 0x1.010102p-1f};
+
 // Lookup table for (1/f) where f = 1 + n*2^(-7), n = 0..127.
 const double ONE_OVER_F[128] = {
     0x1.0000000000000p+0, 0x1.fc07f01fc07f0p-1, 0x1.f81f81f81f820p-1,
@@ -59,6 +98,45 @@ const double ONE_OVER_F[128] = {
     0x1.05197f7d73404p-1, 0x1.0410410410410p-1, 0x1.03091b51f5e1ap-1,
     0x1.0204081020408p-1, 0x1.0101010101010p-1};
 
+// Lookup table for log(f) = log(1 + n*2^(-7)) where n = 0..127,
+// computed and stored as float precision constants.
+// Generated by Sollya with the following commands:
+//   display = hexadecimal;
+//   for n from 0 to 127 do { print(single(log(1 + n / 128.0))); };
+const float LOG_F_FLOAT[128] = {
+    0.0f,           0x1.fe02a6p-8f, 0x1.fc0a8cp-7f, 0x1.7b91bp-6f,
+    0x1.f829bp-6f,  0x1.39e87cp-5f, 0x1.77459p-5f,  0x1.b42dd8p-5f,
+    0x1.f0a30cp-5f, 0x1.16536ep-4f, 0x1.341d7ap-4f, 0x1.51b074p-4f,
+    0x1.6f0d28p-4f, 0x1.8c345ep-4f, 0x1.a926d4p-4f, 0x1.c5e548p-4f,
+    0x1.e27076p-4f, 0x1.fec914p-4f, 0x1.0d77e8p-3f, 0x1.1b72aep-3f,
+    0x1.29553p-3f,  0x1.371fc2p-3f, 0x1.44d2b6p-3f, 0x1.526e5ep-3f,
+    0x1.5ff308p-3f, 0x1.6d60fep-3f, 0x1.7ab89p-3f,  0x1.87fa06p-3f,
+    0x1.9525aap-3f, 0x1.a23bc2p-3f, 0x1.af3c94p-3f, 0x1.bc2868p-3f,
+    0x1.c8ff7cp-3f, 0x1.d5c216p-3f, 0x1.e27076p-3f, 0x1.ef0adcp-3f,
+    0x1.fb9186p-3f, 0x1.04025ap-2f, 0x1.0a324ep-2f, 0x1.1058cp-2f,
+    0x1.1675cap-2f, 0x1.1c898cp-2f, 0x1.22942p-2f,  0x1.2895a2p-2f,
+    0x1.2e8e2cp-2f, 0x1.347ddap-2f, 0x1.3a64c6p-2f, 0x1.404308p-2f,
+    0x1.4618bcp-2f, 0x1.4be5fap-2f, 0x1.51aad8p-2f, 0x1.576772p-2f,
+    0x1.5d1bdcp-2f, 0x1.62c83p-2f,  0x1.686c82p-2f, 0x1.6e08eap-2f,
+    0x1.739d8p-2f,  0x1.792a56p-2f, 0x1.7eaf84p-2f, 0x1.842d1ep-2f,
+    0x1.89a338p-2f, 0x1.8f11e8p-2f, 0x1.947942p-2f, 0x1.99d958p-2f,
+    0x1.9f323ep-2f, 0x1.a4840ap-2f, 0x1.a9cecap-2f, 0x1.af1294p-2f,
+    0x1.b44f78p-2f, 0x1.b9858ap-2f, 0x1.beb4dap-2f, 0x1.c3dd7ap-2f,
+    0x1.c8ff7cp-2f, 0x1.ce1afp-2f,  0x1.d32fe8p-2f, 0x1.d83e72p-2f,
+    0x1.dd46ap-2f,  0x1.e24882p-2f, 0x1.e74426p-2f, 0x1.ec399ep-2f,
+    0x1.f128f6p-2f, 0x1.f6124p-2f,  0x1.faf588p-2f, 0x1.ffd2ep-2f,
+    0x1.02552ap-1f, 0x1.04bdfap-1f, 0x1.0723e6p-1f, 0x1.0986f4p-1f,
+    0x1.0be72ep-1f, 0x1.0e4498p-1f, 0x1.109f3ap-1f, 0x1.12f71ap-1f,
+    0x1.154c3ep-1f, 0x1.179eacp-1f, 0x1.19ee6cp-1f, 0x1.1c3b82p-1f,
+    0x1.1e85f6p-1f, 0x1.20cdcep-1f, 0x1.23130ep-1f, 0x1.2555bcp-1f,
+    0x1.2795e2p-1f, 0x1.29d38p-1f,  0x1.2c0e9ep-1f, 0x1.2e4744p-1f,
+    0x1.307d74p-1f, 0x1.32b134p-1f, 0x1.34e28ap-1f, 0x1.37117cp-1f,
+    0x1.393e0ep-1f, 0x1.3b6844p-1f, 0x1.3d9026p-1f, 0x1.3fb5b8p-1f,
+    0x1.41d8fep-1f, 0x1.43f9fep-1f, 0x1.4618bcp-1f, 0x1.48353ep-1f,
+    0x1.4a4f86p-1f, 0x1.4c679ap-1f, 0x1.4e7d82p-1f, 0x1.50913cp-1f,
+    0x1.52a2d2p-1f, 0x1.54b246p-1f, 0x1.56bf9ep-1f, 0x1.58cadcp-1f,
+    0x1.5ad404p-1f, 0x1.5cdb1ep-1f, 0x1.5ee02ap-1f, 0x1.60e33p-1f};
+
 // Lookup table for log(f) = log(1 + n*2^(-7)) where n = 0..127.
 const double LOG_F[128] = {
     0x0.0000000000000p+0, 0x1.fe02a6b106788p-8, 0x1.fc0a8b0fc03e3p-7,
diff --git a/src/math/generic/common_constants.h b/src/math/generic/common_constants.h
index dc1a90c..e65f002 100644
--- a/src/math/generic/common_constants.h
+++ b/src/math/generic/common_constants.h
@@ -15,9 +15,17 @@
 
 namespace LIBC_NAMESPACE_DECL {
 
+// Lookup table for (1/f) where f = 1 + n*2^(-7), n = 0..127,
+// computed and stored as float precision constants.
+extern const float ONE_OVER_F_FLOAT[128];
+
 // Lookup table for (1/f) where f = 1 + n*2^(-7), n = 0..127.
 extern const double ONE_OVER_F[128];
 
+// Lookup table for log(f) = log(1 + n*2^(-7)) where n = 0..127,
+// computed and stored as float precision constants.
+extern const float LOG_F_FLOAT[128];
+
 // Lookup table for log(f) = log(1 + n*2^(-7)) where n = 0..127.
 extern const double LOG_F[128];
 
diff --git a/src/math/generic/cos.cpp b/src/math/generic/cos.cpp
index b60082b..5da0f86 100644
--- a/src/math/generic/cos.cpp
+++ b/src/math/generic/cos.cpp
@@ -65,7 +65,11 @@ LLVM_LIBC_FUNCTION(double, cos, (double x)) {
   } else {
     // Inf or NaN
     if (LIBC_UNLIKELY(x_e > 2 * FPBits::EXP_BIAS)) {
-      // sin(+-Inf) = NaN
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+      // cos(+-Inf) = NaN
       if (xbits.get_mantissa() == 0) {
         fputil::set_errno_if_required(EDOM);
         fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/cosf.cpp b/src/math/generic/cosf.cpp
index 6ea24f9..7cdae09 100644
--- a/src/math/generic/cosf.cpp
+++ b/src/math/generic/cosf.cpp
@@ -117,6 +117,11 @@ LLVM_LIBC_FUNCTION(float, cosf, (float x)) {
 
   // x is inf or nan.
   if (LIBC_UNLIKELY(x_abs >= 0x7f80'0000U)) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+
     if (x_abs == 0x7f80'0000U) {
       fputil::set_errno_if_required(EDOM);
       fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/cosf16.cpp b/src/math/generic/cosf16.cpp
index 4d42db9..99bb03e 100644
--- a/src/math/generic/cosf16.cpp
+++ b/src/math/generic/cosf16.cpp
@@ -67,6 +67,11 @@ LLVM_LIBC_FUNCTION(float16, cosf16, (float16 x)) {
 
   // cos(+/-inf) = NaN, and cos(NaN) = NaN
   if (xbits.is_inf_or_nan()) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+
     if (xbits.is_inf()) {
       fputil::set_errno_if_required(EDOM);
       fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/coshf16.cpp b/src/math/generic/coshf16.cpp
index 6668e77..689d16a 100644
--- a/src/math/generic/coshf16.cpp
+++ b/src/math/generic/coshf16.cpp
@@ -42,7 +42,7 @@ static constexpr fputil::ExceptValues<float16, 9> COSHF16_EXCEPTS_POS = {{
     {0x497cU, 0x7715U, 1U, 0U, 1U},
 }};
 
-static constexpr fputil::ExceptValues<float16, 4> COSHF16_EXCEPTS_NEG = {{
+static constexpr fputil::ExceptValues<float16, 6> COSHF16_EXCEPTS_NEG = {{
     // x = -0x1.6ap-5, coshf16(x) = 0x1p+0 (RZ)
     {0xa9a8U, 0x3c00U, 1U, 0U, 1U},
     // x = -0x1.b6p+0, coshf16(x) = 0x1.6d8p+1 (RZ)
@@ -51,6 +51,10 @@ static constexpr fputil::ExceptValues<float16, 4> COSHF16_EXCEPTS_NEG = {{
     {0xc4a2U, 0x526dU, 1U, 0U, 0U},
     // x = -0x1.5fp+3, coshf16(x) = 0x1.c54p+14 (RZ)
     {0xc97cU, 0x7715U, 1U, 0U, 1U},
+    // x = -0x1.8c4p+0, coshf16(x) = 0x1.3a8p+1 (RZ)
+    {0xbe31U, 0x40eaU, 1U, 0U, 0U},
+    // x = -0x1.994p+0, coshf16(x) = 0x1.498p+1 (RZ)
+    {0xbe65U, 0x4126U, 1U, 0U, 0U},
 }};
 #endif // !LIBC_MATH_HAS_SKIP_ACCURATE_PASS
 
diff --git a/src/math/generic/cospif.cpp b/src/math/generic/cospif.cpp
index 29566f4..5b6880f 100644
--- a/src/math/generic/cospif.cpp
+++ b/src/math/generic/cospif.cpp
@@ -66,6 +66,11 @@ LLVM_LIBC_FUNCTION(float, cospif, (float x)) {
 
     // x is inf or nan.
     if (LIBC_UNLIKELY(x_abs >= 0x7f80'0000U)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+
       if (x_abs == 0x7f80'0000U) {
         fputil::set_errno_if_required(EDOM);
         fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/cospif16.cpp b/src/math/generic/cospif16.cpp
index ee74bdb..9dc2592 100644
--- a/src/math/generic/cospif16.cpp
+++ b/src/math/generic/cospif16.cpp
@@ -54,6 +54,10 @@ LLVM_LIBC_FUNCTION(float16, cospif16, (float16 x)) {
 
     // Check for NaN or infintiy values
     if (LIBC_UNLIKELY(x_abs >= 0x7c00)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
       // If value is equal to infinity
       if (x_abs == 0x7c00) {
         fputil::set_errno_if_required(EDOM);
diff --git a/src/math/generic/erff.cpp b/src/math/generic/erff.cpp
index 016afe4..44607a5 100644
--- a/src/math/generic/erff.cpp
+++ b/src/math/generic/erff.cpp
@@ -135,6 +135,10 @@ LLVM_LIBC_FUNCTION(float, erff, (float x)) {
     int sign = xbits.is_neg() ? 1 : 0;
 
     if (LIBC_UNLIKELY(x_abs >= 0x7f80'0000U)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
       return (x_abs > 0x7f80'0000) ? x : ONE[sign];
     }
 
diff --git a/src/math/generic/exp_utils.cpp b/src/math/generic/exp_utils.cpp
deleted file mode 100644
index cc21637..0000000
--- a/src/math/generic/exp_utils.cpp
+++ /dev/null
@@ -1,128 +0,0 @@
-//===-- Implemention of exp and friends' utils ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "exp_utils.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-const Exp2fDataTable exp2f_data = {
-    // :tab[i] = uint(2^(i/N)) - (i << 52-BITS)
-    //    used for computing 2^(k/N) for an int |k| < 150 N as
-    //    double(tab[k%N] + (k << 52-BITS))
-    {
-// tab
-#if N == 8
-        0x3ff0000000000000,
-        0x3fef72b83c7d517b,
-        0x3fef06fe0a31b715,
-        0x3feebfdad5362a27,
-        0x3feea09e667f3bcd,
-        0x3feeace5422aa0db,
-        0x3feee89f995ad3ad,
-        0x3fef5818dcfba487,
-#elif N == 16
-        0x3ff0000000000000,
-        0x3fefb5586cf9890f,
-        0x3fef72b83c7d517b,
-        0x3fef387a6e756238,
-        0x3fef06fe0a31b715,
-        0x3feedea64c123422,
-        0x3feebfdad5362a27,
-        0x3feeab07dd485429,
-        0x3feea09e667f3bcd,
-        0x3feea11473eb0187,
-        0x3feeace5422aa0db,
-        0x3feec49182a3f090,
-        0x3feee89f995ad3ad,
-        0x3fef199bdd85529c,
-        0x3fef5818dcfba487,
-        0x3fefa4afa2a490da,
-#elif N == 32
-        0x3ff0000000000000, 0x3fefd9b0d3158574, 0x3fefb5586cf9890f,
-        0x3fef9301d0125b51, 0x3fef72b83c7d517b, 0x3fef54873168b9aa,
-        0x3fef387a6e756238, 0x3fef1e9df51fdee1, 0x3fef06fe0a31b715,
-        0x3feef1a7373aa9cb, 0x3feedea64c123422, 0x3feece086061892d,
-        0x3feebfdad5362a27, 0x3feeb42b569d4f82, 0x3feeab07dd485429,
-        0x3feea47eb03a5585, 0x3feea09e667f3bcd, 0x3fee9f75e8ec5f74,
-        0x3feea11473eb0187, 0x3feea589994cce13, 0x3feeace5422aa0db,
-        0x3feeb737b0cdc5e5, 0x3feec49182a3f090, 0x3feed503b23e255d,
-        0x3feee89f995ad3ad, 0x3feeff76f2fb5e47, 0x3fef199bdd85529c,
-        0x3fef3720dcef9069, 0x3fef5818dcfba487, 0x3fef7c97337b9b5f,
-        0x3fefa4afa2a490da, 0x3fefd0765b6e4540,
-#elif N == 64
-        0x3ff0000000000000, 0x3fefec9a3e778061, 0x3fefd9b0d3158574,
-        0x3fefc74518759bc8, 0x3fefb5586cf9890f, 0x3fefa3ec32d3d1a2,
-        0x3fef9301d0125b51, 0x3fef829aaea92de0, 0x3fef72b83c7d517b,
-        0x3fef635beb6fcb75, 0x3fef54873168b9aa, 0x3fef463b88628cd6,
-        0x3fef387a6e756238, 0x3fef2b4565e27cdd, 0x3fef1e9df51fdee1,
-        0x3fef1285a6e4030b, 0x3fef06fe0a31b715, 0x3feefc08b26416ff,
-        0x3feef1a7373aa9cb, 0x3feee7db34e59ff7, 0x3feedea64c123422,
-        0x3feed60a21f72e2a, 0x3feece086061892d, 0x3feec6a2b5c13cd0,
-        0x3feebfdad5362a27, 0x3feeb9b2769d2ca7, 0x3feeb42b569d4f82,
-        0x3feeaf4736b527da, 0x3feeab07dd485429, 0x3feea76f15ad2148,
-        0x3feea47eb03a5585, 0x3feea23882552225, 0x3feea09e667f3bcd,
-        0x3fee9fb23c651a2f, 0x3fee9f75e8ec5f74, 0x3fee9feb564267c9,
-        0x3feea11473eb0187, 0x3feea2f336cf4e62, 0x3feea589994cce13,
-        0x3feea8d99b4492ed, 0x3feeace5422aa0db, 0x3feeb1ae99157736,
-        0x3feeb737b0cdc5e5, 0x3feebd829fde4e50, 0x3feec49182a3f090,
-        0x3feecc667b5de565, 0x3feed503b23e255d, 0x3feede6b5579fdbf,
-        0x3feee89f995ad3ad, 0x3feef3a2b84f15fb, 0x3feeff76f2fb5e47,
-        0x3fef0c1e904bc1d2, 0x3fef199bdd85529c, 0x3fef27f12e57d14b,
-        0x3fef3720dcef9069, 0x3fef472d4a07897c, 0x3fef5818dcfba487,
-        0x3fef69e603db3285, 0x3fef7c97337b9b5f, 0x3fef902ee78b3ff6,
-        0x3fefa4afa2a490da, 0x3fefba1bee615a27, 0x3fefd0765b6e4540,
-        0x3fefe7c1819e90d8,
-#endif
-    },
-    as_double(0x4338000000000000) / N, // shift_scaled
-    {
-// poly
-#if N == 8
-        as_double(0x3fac6a00335106e2),
-        as_double(0x3fcec0c313449f55),
-        as_double(0x3fe62e431111f69f),
-#elif N == 16
-        as_double(0x3fac6ac6aa313963),
-        as_double(0x3fcebfff4532d9ba),
-        as_double(0x3fe62e43001bc49f),
-#elif N == 32
-        as_double(0x3fac6af84b912394),
-        as_double(0x3fcebfce50fac4f3),
-        as_double(0x3fe62e42ff0c52d6),
-#elif N == 64
-        as_double(0x3fac6b04b4221b2a),
-        as_double(0x3fcebfc213e184d7),
-        as_double(0x3fe62e42fefb5b7f),
-#endif
-    },
-    as_double(0x4338000000000000),     // shift
-    as_double(0x3ff71547652b82fe) * N, // invln2_scaled
-    {
-// poly_scaled
-#if N == 8
-        as_double(0x3fac6a00335106e2) / N / N / N,
-        as_double(0x3fcec0c313449f55) / N / N,
-        as_double(0x3fe62e431111f69f) / N,
-#elif N == 16
-        as_double(0x3fac6ac6aa313963) / N / N / N,
-        as_double(0x3fcebfff4532d9ba) / N / N,
-        as_double(0x3fe62e43001bc49f) / N,
-#elif N == 32
-        as_double(0x3fac6af84b912394) / N / N / N,
-        as_double(0x3fcebfce50fac4f3) / N / N,
-        as_double(0x3fe62e42ff0c52d6) / N,
-#elif N == 64
-        as_double(0x3fac6b04b4221b2a) / N / N / N,
-        as_double(0x3fcebfc213e184d7) / N / N,
-        as_double(0x3fe62e42fefb5b7f) / N,
-#endif
-    },
-};
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/exp_utils.h b/src/math/generic/exp_utils.h
deleted file mode 100644
index dca9eb7..0000000
--- a/src/math/generic/exp_utils.h
+++ /dev/null
@@ -1,34 +0,0 @@
-//===-- Collection of utils for exp and friends -----------------*- C++ -*-===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_SRC_MATH_GENERIC_EXP_UTILS_H
-#define LLVM_LIBC_SRC_MATH_GENERIC_EXP_UTILS_H
-
-#include "src/__support/macros/config.h"
-#include <stdint.h>
-
-#define EXP2F_TABLE_BITS 5
-#define EXP2F_POLY_ORDER 3
-#define N (1 << EXP2F_TABLE_BITS)
-
-namespace LIBC_NAMESPACE_DECL {
-
-struct Exp2fDataTable {
-  uint64_t tab[1 << EXP2F_TABLE_BITS];
-  double shift_scaled;
-  double poly[EXP2F_POLY_ORDER];
-  double shift;
-  double invln2_scaled;
-  double poly_scaled[EXP2F_POLY_ORDER];
-};
-
-extern const Exp2fDataTable exp2f_data;
-
-} // namespace LIBC_NAMESPACE_DECL
-
-#endif // LLVM_LIBC_SRC_MATH_GENERIC_EXP_UTILS_H
diff --git a/src/math/generic/explogxf.h b/src/math/generic/explogxf.h
index e79aa13..212ede4 100644
--- a/src/math/generic/explogxf.h
+++ b/src/math/generic/explogxf.h
@@ -297,6 +297,49 @@ LIBC_INLINE static double log2_eval(double x) {
   return result;
 }
 
+// x should be positive, normal finite value
+// TODO: Simplify range reduction and polynomial degree for float16.
+//       See issue #137190.
+LIBC_INLINE static float log_eval_f(float x) {
+  // For x = 2^ex * (1 + mx), logf(x) = ex * logf(2) + logf(1 + mx).
+  using FPBits = fputil::FPBits<float>;
+  FPBits xbits(x);
+
+  float ex = static_cast<float>(xbits.get_exponent());
+  // p1 is the leading 7 bits of mx, i.e.
+  // p1 * 2^(-7) <= m_x < (p1 + 1) * 2^(-7).
+  int p1 = static_cast<int>(xbits.get_mantissa() >> (FPBits::FRACTION_LEN - 7));
+
+  // Set bits to (1 + (mx - p1*2^(-7)))
+  xbits.set_uintval(xbits.uintval() & (FPBits::FRACTION_MASK >> 7));
+  xbits.set_biased_exponent(FPBits::EXP_BIAS);
+  // dx = (mx - p1*2^(-7)) / (1 + p1*2^(-7)).
+  float dx = (xbits.get_val() - 1.0f) * ONE_OVER_F_FLOAT[p1];
+
+  // Minimax polynomial for log(1 + dx), generated using Sollya:
+  //   > P = fpminimax(log(1 + x)/x, 6, [|SG...|], [0, 2^-7]);
+  //   > Q = (P - 1) / x;
+  //   > for i from 0 to degree(Q) do print(coeff(Q, i));
+  constexpr float COEFFS[6] = {-0x1p-1f,       0x1.555556p-2f,  -0x1.00022ep-2f,
+                               0x1.9ea056p-3f, -0x1.e50324p-2f, 0x1.c018fp3f};
+
+  float dx2 = dx * dx;
+
+  float c1 = fputil::multiply_add(dx, COEFFS[1], COEFFS[0]);
+  float c2 = fputil::multiply_add(dx, COEFFS[3], COEFFS[2]);
+  float c3 = fputil::multiply_add(dx, COEFFS[5], COEFFS[4]);
+
+  float p = fputil::polyeval(dx2, dx, c1, c2, c3);
+
+  // Generated by Sollya with the following commands:
+  //   > display = hexadecimal;
+  //   > round(log(2), SG, RN);
+  constexpr float LOGF_2 = 0x1.62e43p-1f;
+
+  float result = fputil::multiply_add(ex, LOGF_2, LOG_F_FLOAT[p1] + p);
+  return result;
+}
+
 // x should be positive, normal finite value
 LIBC_INLINE static double log_eval(double x) {
   // For x = 2^ex * (1 + mx)
diff --git a/src/math/generic/expm1f.cpp b/src/math/generic/expm1f.cpp
index 1e44e94..b2967e2 100644
--- a/src/math/generic/expm1f.cpp
+++ b/src/math/generic/expm1f.cpp
@@ -30,6 +30,7 @@ LLVM_LIBC_FUNCTION(float, expm1f, (float x)) {
   uint32_t x_u = xbits.uintval();
   uint32_t x_abs = x_u & 0x7fff'ffffU;
 
+#ifndef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
   // Exceptional value
   if (LIBC_UNLIKELY(x_u == 0x3e35'bec5U)) { // x = 0x1.6b7d8ap-3f
     int round_mode = fputil::quick_get_round();
@@ -37,7 +38,6 @@ LLVM_LIBC_FUNCTION(float, expm1f, (float x)) {
       return 0x1.8dbe64p-3f;
     return 0x1.8dbe62p-3f;
   }
-
 #if !defined(LIBC_TARGET_CPU_HAS_FMA_DOUBLE)
   if (LIBC_UNLIKELY(x_u == 0xbdc1'c6cbU)) { // x = -0x1.838d96p-4f
     int round_mode = fputil::quick_get_round();
@@ -46,6 +46,7 @@ LLVM_LIBC_FUNCTION(float, expm1f, (float x)) {
     return -0x1.71c882p-4f;
   }
 #endif // LIBC_TARGET_CPU_HAS_FMA_DOUBLE
+#endif // !LIBC_MATH_HAS_SKIP_ACCURATE_PASS
 
   // When |x| > 25*log(2), or nan
   if (LIBC_UNLIKELY(x_abs >= 0x418a'a123U)) {
diff --git a/src/math/amdgpu/atan2.cpp b/src/math/generic/fmaf16.cpp
similarity index 64%
rename from src/math/amdgpu/atan2.cpp
rename to src/math/generic/fmaf16.cpp
index f590750..4f712f5 100644
--- a/src/math/amdgpu/atan2.cpp
+++ b/src/math/generic/fmaf16.cpp
@@ -1,4 +1,4 @@
-//===-- Implementation of the GPU atan2 function --------------------------===//
+//===-- Implementation of fmaf16 function ---------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,16 +6,15 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/atan2.h"
+#include "src/math/fmaf16.h"
+#include "src/__support/FPUtil/FMA.h"
 #include "src/__support/common.h"
-
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, atan2, (double x, double y)) {
-  return __ocml_atan2_f64(x, y);
+LLVM_LIBC_FUNCTION(float16, fmaf16, (float16 x, float16 y, float16 z)) {
+  return fputil::fma<float16>(x, y, z);
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/hypotf16.cpp b/src/math/generic/hypotf16.cpp
new file mode 100644
index 0000000..d782c26
--- /dev/null
+++ b/src/math/generic/hypotf16.cpp
@@ -0,0 +1,92 @@
+//===-- Implementation of hypotf16 function -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/hypotf16.h"
+#include "src/__support/FPUtil/FEnvImpl.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/cast.h"
+#include "src/__support/FPUtil/multiply_add.h"
+#include "src/__support/FPUtil/sqrt.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/optimization.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+// For targets where conversion from float to float16 has to be
+// emulated, fputil::hypot<float16> is faster
+LLVM_LIBC_FUNCTION(float16, hypotf16, (float16 x, float16 y)) {
+  using FloatBits = fputil::FPBits<float>;
+  using FPBits = fputil::FPBits<float16>;
+
+  FPBits x_abs = FPBits(x).abs();
+  FPBits y_abs = FPBits(y).abs();
+
+  bool x_abs_larger = x_abs.uintval() >= y_abs.uintval();
+
+  FPBits a_bits = x_abs_larger ? x_abs : y_abs;
+  FPBits b_bits = x_abs_larger ? y_abs : x_abs;
+
+  uint16_t a_u = a_bits.uintval();
+  uint16_t b_u = b_bits.uintval();
+
+  // Note: replacing `a_u >= FPBits::EXP_MASK` with `a_bits.is_inf_or_nan()`
+  // generates extra exponent bit masking instructions on x86-64.
+  if (LIBC_UNLIKELY(a_u >= FPBits::EXP_MASK)) {
+    // x or y is inf or nan
+    if (a_bits.is_signaling_nan() || b_bits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+    if (a_bits.is_inf() || b_bits.is_inf())
+      return FPBits::inf().get_val();
+    return a_bits.get_val();
+  }
+
+  // TODO: Investigate why replacing the return line below with:
+  //   return x_bits.get_val() + y_bits.get_val();
+  // fails the hypotf16 smoke tests.
+  if (LIBC_UNLIKELY(a_u - b_u >=
+                    static_cast<uint16_t>((FPBits::FRACTION_LEN + 2)
+                                          << FPBits::FRACTION_LEN)))
+    return a_bits.get_val() + b_bits.get_val();
+
+  float af = fputil::cast<float>(a_bits.get_val());
+  float bf = fputil::cast<float>(b_bits.get_val());
+
+  // These squares are exact.
+  float a_sq = af * af;
+  float sum_sq = fputil::multiply_add(bf, bf, a_sq);
+
+  FloatBits result(fputil::sqrt<float>(sum_sq));
+  uint32_t r_u = result.uintval();
+
+  // If any of the sticky bits of the result are non-zero, except the LSB, then
+  // the rounded result is correct.
+  if (LIBC_UNLIKELY(((r_u + 1) & 0x0000'0FFE) == 0)) {
+    float r_d = result.get_val();
+
+    // Perform rounding correction.
+    float sum_sq_lo = fputil::multiply_add(bf, bf, a_sq - sum_sq);
+    float err = sum_sq_lo - fputil::multiply_add(r_d, r_d, -sum_sq);
+
+    if (err > 0) {
+      r_u |= 1;
+    } else if ((err < 0) && (r_u & 1) == 0) {
+      r_u -= 1;
+    } else if ((r_u & 0x0000'1FFF) == 0) {
+      // The rounded result is exact.
+      fputil::clear_except_if_required(FE_INEXACT);
+    }
+    return fputil::cast<float16>(FloatBits(r_u).get_val());
+  }
+
+  return fputil::cast<float16>(result.get_val());
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/generic/log1p.cpp b/src/math/generic/log1p.cpp
index 058409f..09f465a 100644
--- a/src/math/generic/log1p.cpp
+++ b/src/math/generic/log1p.cpp
@@ -910,7 +910,12 @@ LLVM_LIBC_FUNCTION(double, log1p, (double x)) {
           return FPBits_t::quiet_nan().get_val();
         }
         // x is +Inf or NaN
-        return x;
+        if (xbits.is_inf() && xbits.is_pos())
+          return x;
+
+        if (xbits.is_signaling_nan())
+          fputil::raise_except_if_required(FE_INVALID);
+        return FPBits_t::quiet_nan().get_val();
       }
       x_dd.hi = x;
     } else {
diff --git a/src/math/generic/logf.cpp b/src/math/generic/logf.cpp
index 032d658..e8d2ba2 100644
--- a/src/math/generic/logf.cpp
+++ b/src/math/generic/logf.cpp
@@ -132,6 +132,11 @@ LLVM_LIBC_FUNCTION(float, logf, (float x)) {
         return FPBits::quiet_nan().get_val();
       }
       // x is +inf or nan
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+
       return x;
     }
   }
diff --git a/src/math/generic/pow.cpp b/src/math/generic/pow.cpp
index 8a12934..43e99a7 100644
--- a/src/math/generic/pow.cpp
+++ b/src/math/generic/pow.cpp
@@ -217,6 +217,11 @@ LLVM_LIBC_FUNCTION(double, pow, (double x, double y)) {
   uint64_t sign = 0;
 
   ///////// BEGIN - Check exceptional cases ////////////////////////////////////
+  // If x or y is signaling NaN
+  if (x_abs.is_signaling_nan() || y_abs.is_signaling_nan()) {
+    fputil::raise_except_if_required(FE_INVALID);
+    return FPBits::quiet_nan().get_val();
+  }
 
   // The double precision number that is closest to 1 is (1 - 2^-53), which has
   //   log2(1 - 2^-53) ~ -1.715...p-53.
diff --git a/src/math/generic/powf.cpp b/src/math/generic/powf.cpp
index 2d7deca..dfdfd5d 100644
--- a/src/math/generic/powf.cpp
+++ b/src/math/generic/powf.cpp
@@ -664,6 +664,12 @@ LLVM_LIBC_FUNCTION(float, powf, (float x, float y)) {
   //   |y * log2(x)| = 0 or > 151.
   // Hence x^y will either overflow or underflow if x is not zero.
   if (LIBC_UNLIKELY((y_abs & 0x0007'ffff) == 0) || (y_abs > 0x4f170000)) {
+    // y is signaling NaN
+    if (xbits.is_signaling_nan() || ybits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FloatBits::quiet_nan().get_val();
+    }
+
     // Exceptional exponents.
     if (y == 0.0f)
       return 1.0f;
@@ -736,8 +742,8 @@ LLVM_LIBC_FUNCTION(float, powf, (float x, float y)) {
         }
       }
       if (y_abs > 0x4f17'0000) {
+        // if y is NaN
         if (y_abs > 0x7f80'0000) {
-          // y is NaN
           if (x_u == 0x3f80'0000) { // x = 1.0f
             // pow(1, NaN) = 1
             return 1.0f;
@@ -759,6 +765,12 @@ LLVM_LIBC_FUNCTION(float, powf, (float x, float y)) {
   // y is finite and non-zero.
   if (LIBC_UNLIKELY(((x_u & 0x801f'ffffU) == 0) || x_u >= 0x7f80'0000U ||
                     x_u < 0x0080'0000U)) {
+    // if x is signaling NaN
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FloatBits::quiet_nan().get_val();
+    }
+
     switch (x_u) {
     case 0x3f80'0000: // x = 1.0f
       return 1.0f;
diff --git a/src/math/generic/sin.cpp b/src/math/generic/sin.cpp
index 4a58dcf..a614427 100644
--- a/src/math/generic/sin.cpp
+++ b/src/math/generic/sin.cpp
@@ -77,6 +77,11 @@ LLVM_LIBC_FUNCTION(double, sin, (double x)) {
     // Inf or NaN
     if (LIBC_UNLIKELY(x_e > 2 * FPBits::EXP_BIAS)) {
       // sin(+-Inf) = NaN
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+
       if (xbits.get_mantissa() == 0) {
         fputil::set_errno_if_required(EDOM);
         fputil::raise_except_if_required(FE_INVALID);
@@ -158,7 +163,7 @@ LLVM_LIBC_FUNCTION(double, sin, (double x)) {
   Float128 sin_k_f128 = get_sin_k(k);
   Float128 cos_k_f128 = get_sin_k(k + 64);
 
-  // sin(x) = sin((k * pi/128 + u)
+  // sin(x) = sin(k * pi/128 + u)
   //        = sin(u) * cos(k*pi/128) + cos(u) * sin(k*pi/128)
   Float128 r = fputil::quick_add(fputil::quick_mul(sin_k_f128, cos_u),
                                  fputil::quick_mul(cos_k_f128, sin_u));
diff --git a/src/math/generic/sincos.cpp b/src/math/generic/sincos.cpp
index 0ac2f7f..08c8a82 100644
--- a/src/math/generic/sincos.cpp
+++ b/src/math/generic/sincos.cpp
@@ -85,6 +85,12 @@ LLVM_LIBC_FUNCTION(void, sincos, (double x, double *sin_x, double *cos_x)) {
   } else {
     // Inf or NaN
     if (LIBC_UNLIKELY(x_e > 2 * FPBits::EXP_BIAS)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        *sin_x = *cos_x = FPBits::quiet_nan().get_val();
+        return;
+      }
+
       // sin(+-Inf) = NaN
       if (xbits.get_mantissa() == 0) {
         fputil::set_errno_if_required(EDOM);
diff --git a/src/math/generic/sincosf.cpp b/src/math/generic/sincosf.cpp
index 623ef63..9c7bf18 100644
--- a/src/math/generic/sincosf.cpp
+++ b/src/math/generic/sincosf.cpp
@@ -145,6 +145,12 @@ LLVM_LIBC_FUNCTION(void, sincosf, (float x, float *sinp, float *cosp)) {
 
   // x is inf or nan.
   if (LIBC_UNLIKELY(x_abs >= 0x7f80'0000U)) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      *sinp = *cosp = FPBits::quiet_nan().get_val();
+      return;
+    }
+
     if (x_abs == 0x7f80'0000U) {
       fputil::set_errno_if_required(EDOM);
       fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/sinf.cpp b/src/math/generic/sinf.cpp
index d27ce84..38ea56f 100644
--- a/src/math/generic/sinf.cpp
+++ b/src/math/generic/sinf.cpp
@@ -136,6 +136,11 @@ LLVM_LIBC_FUNCTION(float, sinf, (float x)) {
 #endif // !LIBC_MATH_HAS_SKIP_ACCURATE_PASS
 
   if (LIBC_UNLIKELY(x_abs >= 0x7f80'0000U)) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+
     if (x_abs == 0x7f80'0000U) {
       fputil::set_errno_if_required(EDOM);
       fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/sinf16.cpp b/src/math/generic/sinf16.cpp
index 85e55a6..28debbd 100644
--- a/src/math/generic/sinf16.cpp
+++ b/src/math/generic/sinf16.cpp
@@ -87,6 +87,11 @@ LLVM_LIBC_FUNCTION(float16, sinf16, (float16 x)) {
   }
 
   if (xbits.is_inf_or_nan()) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
+
     if (xbits.is_inf()) {
       fputil::set_errno_if_required(EDOM);
       fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/sinhf16.cpp b/src/math/generic/sinhf16.cpp
index 680e1cc..b426ea7 100644
--- a/src/math/generic/sinhf16.cpp
+++ b/src/math/generic/sinhf16.cpp
@@ -21,7 +21,7 @@
 namespace LIBC_NAMESPACE_DECL {
 
 #ifndef LIBC_MATH_HAS_SKIP_ACCURATE_PASS
-static constexpr fputil::ExceptValues<float16, 16> SINHF16_EXCEPTS_POS = {{
+static constexpr fputil::ExceptValues<float16, 17> SINHF16_EXCEPTS_POS = {{
     // x = 0x1.714p-5, sinhf16(x) = 0x1.714p-5 (RZ)
     {0x29c5U, 0x29c5U, 1U, 0U, 1U},
     // x = 0x1.25p-4, sinhf16(x) = 0x1.25p-4 (RZ)
@@ -54,9 +54,11 @@ static constexpr fputil::ExceptValues<float16, 16> SINHF16_EXCEPTS_POS = {{
     {0x4629U, 0x5b65U, 1U, 0U, 1U},
     // x = 0x1.5fp+3, sinhf16(x) = 0x1.c54p+14 (RZ)
     {0x497cU, 0x7715U, 1U, 0U, 1U},
+    // x = 0x1.3c8p+1, sinhf16(x) = 0x1.78ap+2 (RZ)
+    {0x40f2U, 0x45e2U, 1U, 0U, 1U},
 }};
 
-static constexpr fputil::ExceptValues<float16, 12> SINHF16_EXCEPTS_NEG = {{
+static constexpr fputil::ExceptValues<float16, 13> SINHF16_EXCEPTS_NEG = {{
     // x = -0x1.714p-5, sinhf16(x) = -0x1.714p-5 (RZ)
     {0xa9c5U, 0xa9c5U, 0U, 1U, 1U},
     // x = -0x1.25p-4, sinhf16(x) = -0x1.25p-4 (RZ)
@@ -81,6 +83,8 @@ static constexpr fputil::ExceptValues<float16, 12> SINHF16_EXCEPTS_NEG = {{
     {0xc629U, 0xdb65U, 0U, 1U, 1U},
     // x = -0x1.5fp+3, sinhf16(x) = -0x1.c54p+14 (RZ)
     {0xc97cU, 0xf715U, 0U, 1U, 1U},
+    // x = -0x1.3c8p+1, sinhf16(x) = -0x1.78ap+2 (RZ)
+    {0xc0f2U, 0xc5e2U, 0U, 1U, 1U},
 }};
 #endif // !LIBC_MATH_HAS_SKIP_ACCURATE_PASS
 
diff --git a/src/math/generic/sinpif.cpp b/src/math/generic/sinpif.cpp
index f572ded..492689d 100644
--- a/src/math/generic/sinpif.cpp
+++ b/src/math/generic/sinpif.cpp
@@ -83,6 +83,11 @@ LLVM_LIBC_FUNCTION(float, sinpif, (float x)) {
 
     // check for NaN values
     if (LIBC_UNLIKELY(x_abs >= 0x7f80'0000U)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+
       if (x_abs == 0x7f80'0000U) {
         fputil::set_errno_if_required(EDOM);
         fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/sinpif16.cpp b/src/math/generic/sinpif16.cpp
index 51ea595..68af484 100644
--- a/src/math/generic/sinpif16.cpp
+++ b/src/math/generic/sinpif16.cpp
@@ -50,6 +50,10 @@ LLVM_LIBC_FUNCTION(float16, sinpif16, (float16 x)) {
   if (LIBC_UNLIKELY(x_abs >= 0x6400)) {
     // Check for NaN or infinity values
     if (LIBC_UNLIKELY(x_abs >= 0x7c00)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
       // If value is equal to infinity
       if (x_abs == 0x7c00) {
         fputil::set_errno_if_required(EDOM);
diff --git a/src/math/generic/tan.cpp b/src/math/generic/tan.cpp
index a899a21..89b812c 100644
--- a/src/math/generic/tan.cpp
+++ b/src/math/generic/tan.cpp
@@ -163,6 +163,10 @@ LLVM_LIBC_FUNCTION(double, tan, (double x)) {
   } else {
     // Inf or NaN
     if (LIBC_UNLIKELY(x_e > 2 * FPBits::EXP_BIAS)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
       // tan(+-Inf) = NaN
       if (xbits.get_mantissa() == 0) {
         fputil::set_errno_if_required(EDOM);
diff --git a/src/math/generic/tanf.cpp b/src/math/generic/tanf.cpp
index a15aa97..ca5e35d 100644
--- a/src/math/generic/tanf.cpp
+++ b/src/math/generic/tanf.cpp
@@ -113,6 +113,11 @@ LLVM_LIBC_FUNCTION(float, tanf, (float x)) {
   if (LIBC_UNLIKELY(x_abs > 0x4d56'd354U)) {
     // Inf or NaN
     if (LIBC_UNLIKELY(x_abs >= 0x7f80'0000U)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+
       if (x_abs == 0x7f80'0000U) {
         fputil::set_errno_if_required(EDOM);
         fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/generic/tanf16.cpp b/src/math/generic/tanf16.cpp
index 97d201b..229f4a3 100644
--- a/src/math/generic/tanf16.cpp
+++ b/src/math/generic/tanf16.cpp
@@ -84,6 +84,10 @@ LLVM_LIBC_FUNCTION(float16, tanf16, (float16 x)) {
 
   // tan(+/-inf) = NaN, and tan(NaN) = NaN
   if (LIBC_UNLIKELY(x_abs >= 0x7c00)) {
+    if (xbits.is_signaling_nan()) {
+      fputil::raise_except_if_required(FE_INVALID);
+      return FPBits::quiet_nan().get_val();
+    }
     // x = +/-inf
     if (x_abs == 0x7c00) {
       fputil::set_errno_if_required(EDOM);
diff --git a/src/math/generic/tanpif16.cpp b/src/math/generic/tanpif16.cpp
index 71cf25c..792d405 100644
--- a/src/math/generic/tanpif16.cpp
+++ b/src/math/generic/tanpif16.cpp
@@ -63,6 +63,11 @@ LLVM_LIBC_FUNCTION(float16, tanpif16, (float16 x)) {
   if (LIBC_UNLIKELY(x_abs >= 0x6400)) {
     // Check for NaN or infinity values
     if (LIBC_UNLIKELY(x_abs >= 0x7c00)) {
+      if (xbits.is_signaling_nan()) {
+        fputil::raise_except_if_required(FE_INVALID);
+        return FPBits::quiet_nan().get_val();
+      }
+      // is inf
       if (x_abs == 0x7c00) {
         fputil::set_errno_if_required(EDOM);
         fputil::raise_except_if_required(FE_INVALID);
diff --git a/src/math/hypotf16.h b/src/math/hypotf16.h
new file mode 100644
index 0000000..2d37c61
--- /dev/null
+++ b/src/math/hypotf16.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for hypotf16 ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_HYPOTF16_H
+#define LLVM_LIBC_SRC_MATH_HYPOTF16_H
+
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+float16 hypotf16(float16 x, float16 y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_MATH_HYPOTF16_H
diff --git a/src/math/nvptx/acos.cpp b/src/math/nvptx/acos.cpp
deleted file mode 100644
index 7049f9f..0000000
--- a/src/math/nvptx/acos.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU acos function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/acos.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, acos, (double x)) { return __nv_acos(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/acosf.cpp b/src/math/nvptx/acosf.cpp
deleted file mode 100644
index cf70a0f..0000000
--- a/src/math/nvptx/acosf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the acosf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/acosf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, acosf, (float x)) { return __nv_acosf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/acosh.cpp b/src/math/nvptx/acosh.cpp
deleted file mode 100644
index 2628aa9..0000000
--- a/src/math/nvptx/acosh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU acosh function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/acosh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, acosh, (double x)) { return __nv_acosh(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/acoshf.cpp b/src/math/nvptx/acoshf.cpp
deleted file mode 100644
index b8f57fd..0000000
--- a/src/math/nvptx/acoshf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the acoshf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/acoshf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, acoshf, (float x)) { return __nv_acoshf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/asin.cpp b/src/math/nvptx/asin.cpp
deleted file mode 100644
index 417b67a..0000000
--- a/src/math/nvptx/asin.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU asin function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/asin.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, asin, (double x)) { return __nv_asin(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/asinf.cpp b/src/math/nvptx/asinf.cpp
deleted file mode 100644
index ea819bd..0000000
--- a/src/math/nvptx/asinf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the asinf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/asinf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, asinf, (float x)) { return __nv_asinf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/asinh.cpp b/src/math/nvptx/asinh.cpp
deleted file mode 100644
index 49dcd22..0000000
--- a/src/math/nvptx/asinh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU asinh function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/asinh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, asinh, (double x)) { return __nv_asinh(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/asinhf.cpp b/src/math/nvptx/asinhf.cpp
deleted file mode 100644
index af8afe7..0000000
--- a/src/math/nvptx/asinhf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the asinhf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/asinhf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, asinhf, (float x)) { return __nv_asinhf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/atan.cpp b/src/math/nvptx/atan.cpp
deleted file mode 100644
index e94ef57..0000000
--- a/src/math/nvptx/atan.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU atan function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atan.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, atan, (double x)) { return __nv_atan(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/atan2.cpp b/src/math/nvptx/atan2.cpp
deleted file mode 100644
index d12c4cb..0000000
--- a/src/math/nvptx/atan2.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the GPU atan2 function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atan2.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, atan2, (double x, double y)) {
-  return __nv_atan2(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/atan2f.cpp b/src/math/nvptx/atan2f.cpp
deleted file mode 100644
index f39f322..0000000
--- a/src/math/nvptx/atan2f.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the GPU atan2f function -------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atan2f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, atan2f, (float x, float y)) {
-  return __nv_atan2f(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/atanf.cpp b/src/math/nvptx/atanf.cpp
deleted file mode 100644
index f66ade7..0000000
--- a/src/math/nvptx/atanf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the atanf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atanf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, atanf, (float x)) { return __nv_atanf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/atanh.cpp b/src/math/nvptx/atanh.cpp
deleted file mode 100644
index a206d51..0000000
--- a/src/math/nvptx/atanh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU atanh function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atanh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, atanh, (double x)) { return __nv_atanh(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/atanhf.cpp b/src/math/nvptx/atanhf.cpp
deleted file mode 100644
index 06f6883..0000000
--- a/src/math/nvptx/atanhf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the atanhf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/atanhf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, atanhf, (float x)) { return __nv_atanhf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/cos.cpp b/src/math/nvptx/cos.cpp
deleted file mode 100644
index 873fd50..0000000
--- a/src/math/nvptx/cos.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the cos function for GPU ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/cos.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, cos, (double x)) { return __nv_cos(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/cosf.cpp b/src/math/nvptx/cosf.cpp
deleted file mode 100644
index 82b3bb7..0000000
--- a/src/math/nvptx/cosf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the cosf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/cosf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, cosf, (float x)) { return __nv_cosf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/cosh.cpp b/src/math/nvptx/cosh.cpp
deleted file mode 100644
index 434e8c5..0000000
--- a/src/math/nvptx/cosh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the cosh function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/cosh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, cosh, (double x)) { return __nv_cosh(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/coshf.cpp b/src/math/nvptx/coshf.cpp
deleted file mode 100644
index 87d6b16..0000000
--- a/src/math/nvptx/coshf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the coshf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/coshf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, coshf, (float x)) { return __nv_coshf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/declarations.h b/src/math/nvptx/declarations.h
deleted file mode 100644
index 6f0bcfe..0000000
--- a/src/math/nvptx/declarations.h
+++ /dev/null
@@ -1,94 +0,0 @@
-//===-- NVPTX specific declarations for math support ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_SRC_MATH_NVPTX_DECLARATIONS_H
-#define LLVM_LIBC_SRC_MATH_NVPTX_DECLARATIONS_H
-
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-extern "C" {
-double __nv_acos(double);
-float __nv_acosf(float);
-double __nv_acosh(double);
-float __nv_acoshf(float);
-double __nv_asin(double);
-float __nv_asinf(float);
-double __nv_asinh(double);
-float __nv_asinhf(float);
-double __nv_atan(double);
-float __nv_atanf(float);
-double __nv_atan2(double, double);
-float __nv_atan2f(float, float);
-double __nv_atanh(double);
-float __nv_atanhf(float);
-double __nv_cos(double);
-float __nv_cosf(float);
-double __nv_cosh(double);
-float __nv_coshf(float);
-double __nv_erf(double);
-float __nv_erff(float);
-double __nv_exp(double);
-float __nv_expf(float);
-double __nv_exp2(double);
-float __nv_exp2f(float);
-double __nv_exp10(double);
-float __nv_exp10f(float);
-double __nv_expm1(double);
-float __nv_expm1f(float);
-double __nv_fdim(double, double);
-float __nv_fdimf(float, float);
-double __nv_hypot(double, double);
-float __nv_hypotf(float, float);
-int __nv_ilogb(double);
-int __nv_ilogbf(float);
-double __nv_ldexp(double, int);
-float __nv_ldexpf(float, int);
-long long __nv_llrint(double);
-long long __nv_llrintf(float);
-long __nv_lrint(double);
-long __nv_lrintf(float);
-double __nv_log10(double);
-float __nv_log10f(float);
-double __nv_log1p(double);
-float __nv_log1pf(float);
-double __nv_log2(double);
-float __nv_log2f(float);
-double __nv_log(double);
-float __nv_logf(float);
-double __nv_nextafter(double, double);
-float __nv_nextafterf(float, float);
-double __nv_pow(double, double);
-float __nv_powf(float, float);
-double __nv_powi(double, int);
-float __nv_powif(float, int);
-double __nv_sin(double);
-float __nv_sinf(float);
-void __nv_sincos(double, double *, double *);
-void __nv_sincosf(float, float *, float *);
-double __nv_sinh(double);
-float __nv_sinhf(float);
-double __nv_tan(double);
-float __nv_tanf(float);
-double __nv_tanh(double);
-float __nv_tanhf(float);
-double __nv_frexp(double, int *);
-float __nv_frexpf(float, int *);
-double __nv_scalbn(double, int);
-float __nv_scalbnf(float, int);
-double __nv_remquo(double, double, int *);
-float __nv_remquof(float, float, int *);
-double __nv_tgamma(double);
-float __nv_tgammaf(float);
-float __nv_lgamma(double);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
-
-#endif // LLVM_LIBC_SRC_MATH_NVPTX_DECLARATIONS_H
diff --git a/src/math/nvptx/erf.cpp b/src/math/nvptx/erf.cpp
deleted file mode 100644
index c7ca7d4..0000000
--- a/src/math/nvptx/erf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU erf function ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/erf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, erf, (double x)) { return __nv_erf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/erff.cpp b/src/math/nvptx/erff.cpp
deleted file mode 100644
index 1c64e07..0000000
--- a/src/math/nvptx/erff.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU erff function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/erff.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, erff, (float x)) { return __nv_erff(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/exp.cpp b/src/math/nvptx/exp.cpp
deleted file mode 100644
index dcbadcf..0000000
--- a/src/math/nvptx/exp.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU exp function ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, exp, (double x)) { return __nv_exp(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/exp10.cpp b/src/math/nvptx/exp10.cpp
deleted file mode 100644
index 0972a3c..0000000
--- a/src/math/nvptx/exp10.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU exp10 function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp10.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, exp10, (double x)) { return __nv_exp10(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/exp10f.cpp b/src/math/nvptx/exp10f.cpp
deleted file mode 100644
index 0709771..0000000
--- a/src/math/nvptx/exp10f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the exp10f function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp10f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, exp10f, (float x)) { return __nv_exp10f(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/exp2.cpp b/src/math/nvptx/exp2.cpp
deleted file mode 100644
index 3465e5b..0000000
--- a/src/math/nvptx/exp2.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU exp2 function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp2.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, exp2, (double x)) { return __nv_exp2(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/exp2f.cpp b/src/math/nvptx/exp2f.cpp
deleted file mode 100644
index 0525764..0000000
--- a/src/math/nvptx/exp2f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the exp2f function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/exp2f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, exp2f, (float x)) { return __nv_exp2f(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/expf.cpp b/src/math/nvptx/expf.cpp
deleted file mode 100644
index 2b802e5..0000000
--- a/src/math/nvptx/expf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the expf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/expf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, expf, (float x)) { return __nv_expf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/expm1.cpp b/src/math/nvptx/expm1.cpp
deleted file mode 100644
index 91845cf..0000000
--- a/src/math/nvptx/expm1.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU expm1 function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/expm1.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, expm1, (double x)) { return __nv_expm1(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/expm1f.cpp b/src/math/nvptx/expm1f.cpp
deleted file mode 100644
index 31e67af..0000000
--- a/src/math/nvptx/expm1f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the expm1f function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/expm1f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, expm1f, (float x)) { return __nv_expm1f(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/fdim.cpp b/src/math/nvptx/fdim.cpp
deleted file mode 100644
index edf4009..0000000
--- a/src/math/nvptx/fdim.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the fdim function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/fdim.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, fdim, (double x, double y)) {
-  return __nv_fdim(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/fdimf.cpp b/src/math/nvptx/fdimf.cpp
deleted file mode 100644
index 017143a..0000000
--- a/src/math/nvptx/fdimf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the fdimf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/fdimf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, fdimf, (float x, float y)) {
-  return __nv_fdimf(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/frexp.cpp b/src/math/nvptx/frexp.cpp
deleted file mode 100644
index edba8d7..0000000
--- a/src/math/nvptx/frexp.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the frexp function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/frexp.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, frexp, (double x, int *p)) {
-  return __nv_frexp(x, p);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/frexpf.cpp b/src/math/nvptx/frexpf.cpp
deleted file mode 100644
index 0461941..0000000
--- a/src/math/nvptx/frexpf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the frexpf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/frexpf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, frexpf, (float x, int *p)) {
-  return __nv_frexpf(x, p);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/hypot.cpp b/src/math/nvptx/hypot.cpp
deleted file mode 100644
index a7bacd6..0000000
--- a/src/math/nvptx/hypot.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the hypot function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/hypot.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, hypot, (double x, double y)) {
-  return __nv_hypot(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/hypotf.cpp b/src/math/nvptx/hypotf.cpp
deleted file mode 100644
index 49e85a1..0000000
--- a/src/math/nvptx/hypotf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the hypotf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/hypotf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, hypotf, (float x, float y)) {
-  return __nv_hypotf(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/ilogb.cpp b/src/math/nvptx/ilogb.cpp
deleted file mode 100644
index 3d552c2..0000000
--- a/src/math/nvptx/ilogb.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the ilogb function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/ilogb.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(int, ilogb, (double x)) { return __nv_ilogb(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/ilogbf.cpp b/src/math/nvptx/ilogbf.cpp
deleted file mode 100644
index a78926f..0000000
--- a/src/math/nvptx/ilogbf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the ilogbf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/ilogbf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(int, ilogbf, (float x)) { return __nv_ilogbf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/ldexp.cpp b/src/math/nvptx/ldexp.cpp
deleted file mode 100644
index 0adc7c3..0000000
--- a/src/math/nvptx/ldexp.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the ldexp function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/ldexp.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, ldexp, (double x, int y)) {
-  return __nv_ldexp(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/ldexpf.cpp b/src/math/nvptx/ldexpf.cpp
deleted file mode 100644
index eb7dd42..0000000
--- a/src/math/nvptx/ldexpf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the ldexpf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/ldexpf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, ldexpf, (float x, int y)) {
-  return __nv_ldexpf(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/lgamma.cpp b/src/math/nvptx/lgamma.cpp
index 0447a97..0dc3111 100644
--- a/src/math/nvptx/lgamma.cpp
+++ b/src/math/nvptx/lgamma.cpp
@@ -9,11 +9,10 @@
 #include "src/math/lgamma.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, lgamma, (double x)) { return __nv_lgamma(x); }
+LLVM_LIBC_FUNCTION(double, lgamma, (double)) { return 0.0; }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/lgamma_r.cpp b/src/math/nvptx/lgamma_r.cpp
index 85f66c8..92018da 100644
--- a/src/math/nvptx/lgamma_r.cpp
+++ b/src/math/nvptx/lgamma_r.cpp
@@ -9,15 +9,13 @@
 #include "src/math/lgamma_r.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, lgamma_r, (double x, int *signp)) {
-  double result = __nv_lgamma(x);
-  *signp = (result < 0.0) ? -1 : 1;
-  return result;
+LLVM_LIBC_FUNCTION(double, lgamma_r, (double, int *signp)) {
+  *signp = 0.0;
+  return 0.0;
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/llrint.cpp b/src/math/nvptx/llrint.cpp
index 21129fe..6e0f57a 100644
--- a/src/math/nvptx/llrint.cpp
+++ b/src/math/nvptx/llrint.cpp
@@ -9,7 +9,6 @@
 #include "src/math/llrint.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/nvptx/llrintf.cpp b/src/math/nvptx/llrintf.cpp
index a6f9f43..d8de23f 100644
--- a/src/math/nvptx/llrintf.cpp
+++ b/src/math/nvptx/llrintf.cpp
@@ -9,7 +9,6 @@
 #include "src/math/llrintf.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/nvptx/log.cpp b/src/math/nvptx/log.cpp
deleted file mode 100644
index fd556ac..0000000
--- a/src/math/nvptx/log.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log function ----------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, log, (double x)) { return __nv_log(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/log10.cpp b/src/math/nvptx/log10.cpp
deleted file mode 100644
index fbbf214..0000000
--- a/src/math/nvptx/log10.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log10 function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log10.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, log10, (double x)) { return __nv_log10(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/log10f.cpp b/src/math/nvptx/log10f.cpp
deleted file mode 100644
index c2f24df..0000000
--- a/src/math/nvptx/log10f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log10f function -------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log10f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, log10f, (float x)) { return __nv_log10f(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/log1p.cpp b/src/math/nvptx/log1p.cpp
deleted file mode 100644
index 2ffd0fe..0000000
--- a/src/math/nvptx/log1p.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log1p function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log1p.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, log1p, (double x)) { return __nv_log1p(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/log1pf.cpp b/src/math/nvptx/log1pf.cpp
deleted file mode 100644
index 2de4f27..0000000
--- a/src/math/nvptx/log1pf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log1pf function -------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log1pf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, log1pf, (float x)) { return __nv_log1pf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/log2.cpp b/src/math/nvptx/log2.cpp
deleted file mode 100644
index 54e2da0..0000000
--- a/src/math/nvptx/log2.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log2 function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log2.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, log2, (double x)) { return __nv_log2(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/log2f.cpp b/src/math/nvptx/log2f.cpp
deleted file mode 100644
index c2a6054..0000000
--- a/src/math/nvptx/log2f.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU log2f function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/log2f.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, log2f, (float x)) { return __nv_log2f(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/logb.cpp b/src/math/nvptx/logb.cpp
deleted file mode 100644
index f6998bd..0000000
--- a/src/math/nvptx/logb.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU logb function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/logb.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, logb, (double x)) { return __nv_logb(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/logbf.cpp b/src/math/nvptx/logbf.cpp
deleted file mode 100644
index f72c04f..0000000
--- a/src/math/nvptx/logbf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU logbf function --------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/logbf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, logbf, (float x)) { return __nv_logbf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/logf.cpp b/src/math/nvptx/logf.cpp
deleted file mode 100644
index 1a5bc1e..0000000
--- a/src/math/nvptx/logf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the GPU logf function ---------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/logf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, logf, (float x)) { return __nv_logf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/lrint.cpp b/src/math/nvptx/lrint.cpp
index 715b552..5ba70ec 100644
--- a/src/math/nvptx/lrint.cpp
+++ b/src/math/nvptx/lrint.cpp
@@ -9,7 +9,6 @@
 #include "src/math/lrint.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/math/nvptx/lrintf.cpp b/src/math/nvptx/lrintf.cpp
deleted file mode 100644
index 3ed05f6..0000000
--- a/src/math/nvptx/lrintf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the lrintf function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/lrintf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(long, lrintf, (float x)) { return __nv_lrintf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/nextafter.cpp b/src/math/nvptx/nextafter.cpp
deleted file mode 100644
index 3dc9100..0000000
--- a/src/math/nvptx/nextafter.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the nextafter function for GPU ------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/nextafter.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, nextafter, (double x, double y)) {
-  return __nv_nextafter(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/nextafterf.cpp b/src/math/nvptx/nextafterf.cpp
deleted file mode 100644
index 162b85e..0000000
--- a/src/math/nvptx/nextafterf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the nextafterf function for GPU -----------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/nextafterf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, nextafterf, (float x, float y)) {
-  return __nv_nextafterf(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/nvptx.h b/src/math/nvptx/nvptx.h
deleted file mode 100644
index 2035b76..0000000
--- a/src/math/nvptx/nvptx.h
+++ /dev/null
@@ -1,103 +0,0 @@
-//===-- NVPTX specific definitions for math support -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#ifndef LLVM_LIBC_SRC_MATH_NVPTX_NVPTX_H
-#define LLVM_LIBC_SRC_MATH_NVPTX_NVPTX_H
-
-#include "declarations.h"
-
-#include "src/__support/macros/attributes.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-namespace internal {
-LIBC_INLINE double acos(double x) { return __nv_acos(x); }
-LIBC_INLINE float acosf(float x) { return __nv_acosf(x); }
-LIBC_INLINE double acosh(double x) { return __nv_acosh(x); }
-LIBC_INLINE float acoshf(float x) { return __nv_acoshf(x); }
-LIBC_INLINE double asin(double x) { return __nv_asin(x); }
-LIBC_INLINE float asinf(float x) { return __nv_asinf(x); }
-LIBC_INLINE double asinh(double x) { return __nv_asinh(x); }
-LIBC_INLINE float asinhf(float x) { return __nv_asinhf(x); }
-LIBC_INLINE double atan2(double x, double y) { return __nv_atan2(x, y); }
-LIBC_INLINE float atan2f(float x, float y) { return __nv_atan2f(x, y); }
-LIBC_INLINE double atan(double x) { return __nv_atan(x); }
-LIBC_INLINE float atanf(float x) { return __nv_atanf(x); }
-LIBC_INLINE double atanh(double x) { return __nv_atanh(x); }
-LIBC_INLINE float atanhf(float x) { return __nv_atanhf(x); }
-LIBC_INLINE double cos(double x) { return __nv_cos(x); }
-LIBC_INLINE float cosf(float x) { return __nv_cosf(x); }
-LIBC_INLINE double cosh(double x) { return __nv_cosh(x); }
-LIBC_INLINE float coshf(float x) { return __nv_coshf(x); }
-LIBC_INLINE double erf(double x) { return __nv_erf(x); }
-LIBC_INLINE float erff(float x) { return __nv_erff(x); }
-LIBC_INLINE double exp(double x) { return __nv_exp(x); }
-LIBC_INLINE float expf(float x) { return __nv_expf(x); }
-LIBC_INLINE double exp2(double x) { return __nv_exp2(x); }
-LIBC_INLINE float exp2f(float x) { return __nv_exp2f(x); }
-LIBC_INLINE double exp10(double x) { return __nv_exp10(x); }
-LIBC_INLINE float exp10f(float x) { return __nv_exp10f(x); }
-LIBC_INLINE double expm1(double x) { return __nv_expm1(x); }
-LIBC_INLINE float expm1f(float x) { return __nv_expm1f(x); }
-LIBC_INLINE double fdim(double x, double y) { return __nv_fdim(x, y); }
-LIBC_INLINE float fdimf(float x, float y) { return __nv_fdimf(x, y); }
-LIBC_INLINE double hypot(double x, double y) { return __nv_hypot(x, y); }
-LIBC_INLINE float hypotf(float x, float y) { return __nv_hypotf(x, y); }
-LIBC_INLINE int ilogb(double x) { return __nv_ilogb(x); }
-LIBC_INLINE int ilogbf(float x) { return __nv_ilogbf(x); }
-LIBC_INLINE double ldexp(double x, int i) { return __nv_ldexp(x, i); }
-LIBC_INLINE float ldexpf(float x, int i) { return __nv_ldexpf(x, i); }
-LIBC_INLINE long long llrint(double x) { return __nv_llrint(x); }
-LIBC_INLINE long long llrintf(float x) { return __nv_llrintf(x); }
-LIBC_INLINE double log10(double x) { return __nv_log10(x); }
-LIBC_INLINE float log10f(float x) { return __nv_log10f(x); }
-LIBC_INLINE double log1p(double x) { return __nv_log1p(x); }
-LIBC_INLINE float log1pf(float x) { return __nv_log1pf(x); }
-LIBC_INLINE double log2(double x) { return __nv_log2(x); }
-LIBC_INLINE float log2f(float x) { return __nv_log2f(x); }
-LIBC_INLINE double log(double x) { return __nv_log(x); }
-LIBC_INLINE float logf(float x) { return __nv_logf(x); }
-LIBC_INLINE long lrint(double x) { return __nv_lrint(x); }
-LIBC_INLINE long lrintf(float x) { return __nv_lrintf(x); }
-LIBC_INLINE double nextafter(double x, double y) {
-  return __nv_nextafter(x, y);
-}
-LIBC_INLINE float nextafterf(float x, float y) { return __nv_nextafterf(x, y); }
-LIBC_INLINE double pow(double x, double y) { return __nv_pow(x, y); }
-LIBC_INLINE float powf(float x, float y) { return __nv_powf(x, y); }
-LIBC_INLINE double sin(double x) { return __nv_sin(x); }
-LIBC_INLINE float sinf(float x) { return __nv_sinf(x); }
-LIBC_INLINE void sincos(double x, double *sinptr, double *cosptr) {
-  return __nv_sincos(x, sinptr, cosptr);
-}
-LIBC_INLINE void sincosf(float x, float *sinptr, float *cosptr) {
-  return __nv_sincosf(x, sinptr, cosptr);
-}
-LIBC_INLINE double sinh(double x) { return __nv_sinh(x); }
-LIBC_INLINE float sinhf(float x) { return __nv_sinhf(x); }
-LIBC_INLINE double tan(double x) { return __nv_tan(x); }
-LIBC_INLINE float tanf(float x) { return __nv_tanf(x); }
-LIBC_INLINE double tanh(double x) { return __nv_tanh(x); }
-LIBC_INLINE float tanhf(float x) { return __nv_tanhf(x); }
-LIBC_INLINE double scalbn(double x, int i) { return __nv_scalbn(x, i); }
-LIBC_INLINE float scalbnf(float x, int i) { return __nv_scalbnf(x, i); }
-LIBC_INLINE double frexp(double x, int *i) { return __nv_frexp(x, i); }
-LIBC_INLINE float frexpf(float x, int *i) { return __nv_frexpf(x, i); }
-LIBC_INLINE double remquo(double x, double y, int *i) {
-  return __nv_remquo(x, y, i);
-}
-LIBC_INLINE float remquof(float x, float y, int *i) {
-  return __nv_remquof(x, y, i);
-}
-LIBC_INLINE double tgamma(double x) { return __nv_tgamma(x); }
-LIBC_INLINE float tgammaf(float x) { return __nv_tgammaf(x); }
-
-} // namespace internal
-} // namespace LIBC_NAMESPACE_DECL
-
-#endif // LLVM_LIBC_SRC_MATH_NVPTX_NVPTX_H
diff --git a/src/math/nvptx/powf.cpp b/src/math/nvptx/powf.cpp
deleted file mode 100644
index 9c577c7..0000000
--- a/src/math/nvptx/powf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the powf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/powf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, powf, (float x, float y)) { return __nv_powf(x, y); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/powi.cpp b/src/math/nvptx/powi.cpp
deleted file mode 100644
index 16214bd..0000000
--- a/src/math/nvptx/powi.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the powi function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/powi.h"
-#include "src/__support/common.h"
-#include "src/__support/macros/config.h"
-
-#include "declarations.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, powi, (double x, int y)) { return __nv_powi(x, y); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/powif.cpp b/src/math/nvptx/powif.cpp
deleted file mode 100644
index 5d26fdc..0000000
--- a/src/math/nvptx/powif.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the powif function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/powif.h"
-#include "src/__support/common.h"
-#include "src/__support/macros/config.h"
-
-#include "declarations.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, powif, (float x, int y)) { return __nv_powif(x, y); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/remquo.cpp b/src/math/nvptx/remquo.cpp
deleted file mode 100644
index aae1831..0000000
--- a/src/math/nvptx/remquo.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the GPU remquo function -------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/remquo.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, remquo, (double x, double y, int *quo)) {
-  return __nv_remquo(x, y, quo);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/remquof.cpp b/src/math/nvptx/remquof.cpp
deleted file mode 100644
index d7ce3c0..0000000
--- a/src/math/nvptx/remquof.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the GPU remquof function ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/remquof.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, remquof, (float x, float y, int *quo)) {
-  return __nv_remquof(x, y, quo);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/scalbn.cpp b/src/math/nvptx/scalbn.cpp
deleted file mode 100644
index ecadc34..0000000
--- a/src/math/nvptx/scalbn.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the GPU scalbn function -------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/scalbn.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, scalbn, (double x, int y)) {
-  return __nv_scalbn(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/scalbnf.cpp b/src/math/nvptx/scalbnf.cpp
deleted file mode 100644
index 35ff699..0000000
--- a/src/math/nvptx/scalbnf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the GPU scalbnf function ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/scalbnf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, scalbnf, (float x, int y)) {
-  return __nv_scalbnf(x, y);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/sin.cpp b/src/math/nvptx/sin.cpp
deleted file mode 100644
index 0e86f9c..0000000
--- a/src/math/nvptx/sin.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the sin function for GPU ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sin.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, sin, (double x)) { return __nv_sin(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/sincos.cpp b/src/math/nvptx/sincos.cpp
deleted file mode 100644
index 5a77234..0000000
--- a/src/math/nvptx/sincos.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the sincos function for GPU ---------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sincos.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(void, sincos, (double x, double *sinptr, double *cosptr)) {
-  return __nv_sincos(x, sinptr, cosptr);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/sincosf.cpp b/src/math/nvptx/sincosf.cpp
deleted file mode 100644
index e4039ad..0000000
--- a/src/math/nvptx/sincosf.cpp
+++ /dev/null
@@ -1,21 +0,0 @@
-//===-- Implementation of the sincosf function for GPU --------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sincosf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(void, sincosf, (float x, float *sinptr, float *cosptr)) {
-  return __nv_sincosf(x, sinptr, cosptr);
-}
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/sinf.cpp b/src/math/nvptx/sinf.cpp
deleted file mode 100644
index 14e722f..0000000
--- a/src/math/nvptx/sinf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the sinf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sinf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, sinf, (float x)) { return __nv_sinf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/sinh.cpp b/src/math/nvptx/sinh.cpp
deleted file mode 100644
index 701811d..0000000
--- a/src/math/nvptx/sinh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the sinh function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sinh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, sinh, (double x)) { return __nv_sinh(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/sinhf.cpp b/src/math/nvptx/sinhf.cpp
deleted file mode 100644
index 2c6ac21..0000000
--- a/src/math/nvptx/sinhf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the sinhf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/sinhf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, sinhf, (float x)) { return __nv_sinhf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/tan.cpp b/src/math/nvptx/tan.cpp
deleted file mode 100644
index 2d3f1fe..0000000
--- a/src/math/nvptx/tan.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the tan function for GPU ------------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/tan.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, tan, (double x)) { return __nv_tan(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/tanf.cpp b/src/math/nvptx/tanf.cpp
deleted file mode 100644
index bdf51d9..0000000
--- a/src/math/nvptx/tanf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the tanf function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/tanf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, tanf, (float x)) { return __nv_tanf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/tanh.cpp b/src/math/nvptx/tanh.cpp
deleted file mode 100644
index 8255889..0000000
--- a/src/math/nvptx/tanh.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the tanh function for GPU -----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/tanh.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(double, tanh, (double x)) { return __nv_tanh(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/tanhf.cpp b/src/math/nvptx/tanhf.cpp
deleted file mode 100644
index a22524a..0000000
--- a/src/math/nvptx/tanhf.cpp
+++ /dev/null
@@ -1,19 +0,0 @@
-//===-- Implementation of the tanhf function for GPU ----------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/math/tanhf.h"
-#include "src/__support/common.h"
-
-#include "declarations.h"
-#include "src/__support/macros/config.h"
-
-namespace LIBC_NAMESPACE_DECL {
-
-LLVM_LIBC_FUNCTION(float, tanhf, (float x)) { return __nv_tanhf(x); }
-
-} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/tgamma.cpp b/src/math/nvptx/tgamma.cpp
index 29f0334..0dfb0fd 100644
--- a/src/math/nvptx/tgamma.cpp
+++ b/src/math/nvptx/tgamma.cpp
@@ -9,11 +9,10 @@
 #include "src/math/tgamma.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, tgamma, (double x)) { return __nv_tgamma(x); }
+LLVM_LIBC_FUNCTION(double, tgamma, (double)) { return 0.0; }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/nvptx/tgammaf.cpp b/src/math/nvptx/tgammaf.cpp
index d7de80b..bb77cf5 100644
--- a/src/math/nvptx/tgammaf.cpp
+++ b/src/math/nvptx/tgammaf.cpp
@@ -9,11 +9,10 @@
 #include "src/math/tgammaf.h"
 #include "src/__support/common.h"
 
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(float, tgammaf, (float x)) { return __nv_tgammaf(x); }
+LLVM_LIBC_FUNCTION(float, tgammaf, (float)) { return 0.0; }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/poll/linux/poll.cpp b/src/poll/linux/poll.cpp
index d7c1958..f82fcbc 100644
--- a/src/poll/linux/poll.cpp
+++ b/src/poll/linux/poll.cpp
@@ -23,9 +23,9 @@ namespace LIBC_NAMESPACE_DECL {
 LLVM_LIBC_FUNCTION(int, poll, (pollfd * fds, nfds_t nfds, int timeout)) {
   int ret = 0;
 
-#ifdef SYS_poll
+#if defined(SYS_poll)
   ret = LIBC_NAMESPACE::syscall_impl<int>(SYS_poll, fds, nfds, timeout);
-#elif defined(SYS_ppoll)
+#else // no SYS_poll
   timespec ts, *tsp;
   if (timeout >= 0) {
     ts.tv_sec = timeout / 1000;
@@ -34,12 +34,16 @@ LLVM_LIBC_FUNCTION(int, poll, (pollfd * fds, nfds_t nfds, int timeout)) {
   } else {
     tsp = nullptr;
   }
+#if defined(SYS_ppoll)
   ret =
       LIBC_NAMESPACE::syscall_impl<int>(SYS_ppoll, fds, nfds, tsp, nullptr, 0);
+#elif defined(SYS_ppoll_time64)
+  ret = LIBC_NAMESPACE::syscall_impl<int>(SYS_ppoll_time64, fds, nfds, tsp,
+                                          nullptr, 0);
 #else
-// TODO: https://github.com/llvm/llvm-project/issues/125940
-#error "SYS_ppoll_time64?"
-#endif
+#error "poll, ppoll, ppoll_time64 syscalls not available."
+#endif // defined(SYS_ppoll) || defined(SYS_ppoll_time64)
+#endif // defined(SYS_poll)
 
   if (ret < 0) {
     libc_errno = -ret;
diff --git a/src/search/hsearch.h b/src/search/hsearch.h
index 4d03985..820ebde 100644
--- a/src/search/hsearch.h
+++ b/src/search/hsearch.h
@@ -9,8 +9,9 @@
 #ifndef LLVM_LIBC_SRC_SEARCH_HSEARCH_H
 #define LLVM_LIBC_SRC_SEARCH_HSEARCH_H
 
+#include "hdr/types/ACTION.h"
+#include "hdr/types/ENTRY.h"
 #include "src/__support/macros/config.h"
-#include <search.h> // ENTRY, ACTION
 
 namespace LIBC_NAMESPACE_DECL {
 ENTRY *hsearch(ENTRY item, ACTION action);
diff --git a/src/search/hsearch_r.h b/src/search/hsearch_r.h
index 6e95110..98f956f 100644
--- a/src/search/hsearch_r.h
+++ b/src/search/hsearch_r.h
@@ -9,8 +9,10 @@
 #ifndef LLVM_LIBC_SRC_SEARCH_HSEARCH_R_H
 #define LLVM_LIBC_SRC_SEARCH_HSEARCH_R_H
 
+#include "hdr/types/ACTION.h"
+#include "hdr/types/ENTRY.h"
 #include "src/__support/macros/config.h"
-#include <search.h> // ENTRY, ACTION
+#include <search.h> // hsearch_data
 
 namespace LIBC_NAMESPACE_DECL {
 int hsearch_r(ENTRY item, ACTION action, ENTRY **retval,
diff --git a/src/setjmp/aarch64/sigsetjmp.cpp b/src/setjmp/aarch64/sigsetjmp.cpp
new file mode 100644
index 0000000..734591b
--- /dev/null
+++ b/src/setjmp/aarch64/sigsetjmp.cpp
@@ -0,0 +1,36 @@
+//===-- Implementation of sigsetjmp ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/setjmp/sigsetjmp.h"
+#include "hdr/offsetof_macros.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/setjmp/setjmp_impl.h"
+#include "src/setjmp/sigsetjmp_epilogue.h"
+
+namespace LIBC_NAMESPACE_DECL {
+[[gnu::naked]]
+LLVM_LIBC_FUNCTION(int, sigsetjmp, (sigjmp_buf, int)) {
+  asm(R"(
+      cbz w1, %c[setjmp]
+
+      str x30, [x0, %c[retaddr]]
+      str x19, [x0, %c[extra]]
+      mov x19, x0
+      bl %c[setjmp]
+
+      mov w1, w0
+      mov x0, x19
+      ldr x30, [x0, %c[retaddr]]
+      ldr x19, [x0, %c[extra]]
+      b %c[epilogue])" ::[retaddr] "i"(offsetof(__jmp_buf, sig_retaddr)),
+      [extra] "i"(offsetof(__jmp_buf, sig_extra)), [setjmp] "i"(setjmp),
+      [epilogue] "i"(sigsetjmp_epilogue)
+      : "x0", "x1", "x19", "x30");
+}
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/setjmp/linux/sigsetjmp_epilogue.cpp b/src/setjmp/linux/sigsetjmp_epilogue.cpp
new file mode 100644
index 0000000..4718623
--- /dev/null
+++ b/src/setjmp/linux/sigsetjmp_epilogue.cpp
@@ -0,0 +1,25 @@
+//===-- Implementation of sigsetjmp_epilogue ------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/setjmp/sigsetjmp_epilogue.h"
+#include "src/__support/OSUtil/syscall.h"
+#include "src/__support/common.h"
+#include <sys/syscall.h> // For syscall numbers.
+
+namespace LIBC_NAMESPACE_DECL {
+[[gnu::returns_twice]] int sigsetjmp_epilogue(jmp_buf buffer, int retval) {
+  // If set is NULL, then the signal mask is unchanged (i.e., how is
+  // ignored), but the current value of the signal mask is nevertheless
+  // returned in oldset (if it is not NULL).
+  syscall_impl<long>(SYS_rt_sigprocmask, SIG_SETMASK,
+                     /* set= */ retval ? &buffer->sigmask : nullptr,
+                     /* old_set= */ retval ? nullptr : &buffer->sigmask,
+                     sizeof(sigset_t));
+  return retval;
+}
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/setjmp/riscv/sigsetjmp.cpp b/src/setjmp/riscv/sigsetjmp.cpp
new file mode 100644
index 0000000..2c6d442
--- /dev/null
+++ b/src/setjmp/riscv/sigsetjmp.cpp
@@ -0,0 +1,49 @@
+//===-- Implementation of sigsetjmp ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/setjmp/sigsetjmp.h"
+#include "hdr/offsetof_macros.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/setjmp/setjmp_impl.h"
+#include "src/setjmp/sigsetjmp_epilogue.h"
+
+#if __riscv_xlen == 64
+#define STORE(A, B, C) "sd " #A ", %c[" #B "](" #C ")\n\t"
+#define LOAD(A, B, C) "ld " #A ", %c[" #B "](" #C ")\n\t"
+#elif __riscv_xlen == 32
+#define STORE(A, B, C) "sw " #A ", %c[" #B "](" #C ")\n\t"
+#define LOAD(A, B, C) "lw " #A ", %c[" #B "](" #C ")\n\t"
+#else
+#error "Unsupported RISC-V architecture"
+#endif
+
+namespace LIBC_NAMESPACE_DECL {
+[[gnu::naked]]
+LLVM_LIBC_FUNCTION(int, sigsetjmp, (sigjmp_buf, int)) {
+  // clang-format off
+  asm("beqz a1, .Lnosave\n\t"
+      STORE(ra, retaddr, a0)
+      STORE(s0, extra, a0)
+      "mv s0, a0\n\t"
+      "call %c[setjmp]\n\t"
+      "mv a1, a0\n\t"
+      "mv a0, s0\n\t"
+      LOAD(s0, extra, a0)
+      LOAD(ra, retaddr, a0)
+      "tail %c[epilogue]\n"
+".Lnosave:\n\t"
+      "tail %c[setjmp]"
+      // clang-format on
+      ::[retaddr] "i"(offsetof(__jmp_buf, sig_retaddr)),
+      [extra] "i"(offsetof(__jmp_buf, sig_extra)), [setjmp] "i"(setjmp),
+      [epilogue] "i"(sigsetjmp_epilogue)
+      : "a0", "a1", "s0");
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/setjmp/setjmp_impl.h b/src/setjmp/setjmp_impl.h
index 669f720..c89d6bc 100644
--- a/src/setjmp/setjmp_impl.h
+++ b/src/setjmp/setjmp_impl.h
@@ -29,7 +29,8 @@ namespace LIBC_NAMESPACE_DECL {
 #ifdef LIBC_COMPILER_IS_GCC
 [[gnu::nothrow]]
 #endif
-__attribute__((returns_twice)) int setjmp(jmp_buf buf);
+[[gnu::returns_twice]] int
+setjmp(jmp_buf buf);
 
 } // namespace LIBC_NAMESPACE_DECL
 
diff --git a/src/setjmp/siglongjmp.cpp b/src/setjmp/siglongjmp.cpp
new file mode 100644
index 0000000..e372a6f
--- /dev/null
+++ b/src/setjmp/siglongjmp.cpp
@@ -0,0 +1,23 @@
+//===-- Implementation of siglongjmp --------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/setjmp/siglongjmp.h"
+#include "src/__support/common.h"
+#include "src/setjmp/longjmp.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+// siglongjmp is the same as longjmp. The additional recovery work is done in
+// the epilogue of the sigsetjmp function.
+// TODO: move this inside the TU of longjmp and making it an alias after
+//       sigsetjmp is implemented for all architectures.
+LLVM_LIBC_FUNCTION(void, siglongjmp, (jmp_buf buf, int val)) {
+  return LIBC_NAMESPACE::longjmp(buf, val);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/setjmp/siglongjmp.h b/src/setjmp/siglongjmp.h
new file mode 100644
index 0000000..ea5bbb9
--- /dev/null
+++ b/src/setjmp/siglongjmp.h
@@ -0,0 +1,25 @@
+//===-- Implementation header for siglongjmp --------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_SETJMP_SIGLONGJMP_H
+#define LLVM_LIBC_SRC_SETJMP_SIGLONGJMP_H
+
+#include "hdr/types/jmp_buf.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/compiler.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+#ifdef LIBC_COMPILER_IS_GCC
+[[gnu::nothrow]]
+#endif
+void siglongjmp(jmp_buf buf, int val);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_SETJMP_SIGLONGJMP_H
diff --git a/src/setjmp/sigsetjmp.h b/src/setjmp/sigsetjmp.h
new file mode 100644
index 0000000..ef060c8
--- /dev/null
+++ b/src/setjmp/sigsetjmp.h
@@ -0,0 +1,26 @@
+//===-- Implementation header for sigsetjmp ---------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_SETJMP_SIGSETJMP_H
+#define LLVM_LIBC_SRC_SETJMP_SIGSETJMP_H
+
+#include "hdr/types/jmp_buf.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/properties/compiler.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+#ifdef LIBC_COMPILER_IS_GCC
+[[gnu::nothrow]]
+#endif
+[[gnu::returns_twice]] int
+sigsetjmp(sigjmp_buf buf, int savesigs);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_SETJMP_SIGSETJMP_H
diff --git a/src/setjmp/sigsetjmp_epilogue.h b/src/setjmp/sigsetjmp_epilogue.h
new file mode 100644
index 0000000..88702b7
--- /dev/null
+++ b/src/setjmp/sigsetjmp_epilogue.h
@@ -0,0 +1,19 @@
+//===-- Implementation header for sigsetjmp epilogue ------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_SETJMP_SIGSETJMP_EPILOGUE_H
+#define LLVM_LIBC_SRC_SETJMP_SIGSETJMP_EPILOGUE_H
+
+#include "hdr/types/jmp_buf.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE_DECL {
+[[gnu::returns_twice]] int sigsetjmp_epilogue(jmp_buf buffer, int retval);
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_SETJMP_SIGSETJMP_EPILOGUE_H
diff --git a/src/setjmp/x86_64/setjmp.cpp b/src/setjmp/x86_64/setjmp.cpp
index 5ac10fa..66d1316 100644
--- a/src/setjmp/x86_64/setjmp.cpp
+++ b/src/setjmp/x86_64/setjmp.cpp
@@ -6,7 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "include/llvm-libc-macros/offsetof-macro.h"
+// We use naked functions to avoid compiler-generated prologue and epilogue.
+// Despite GCC documentation listing this as an unsupported case for extended
+// asm, the generated code is not wrong as we only pass in constant operands
+// to extended asm.
+// See https://github.com/llvm/llvm-project/issues/137055 for related remarks.
+
+#include "hdr/offsetof_macros.h"
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
 #include "src/setjmp/setjmp_impl.h"
diff --git a/src/setjmp/x86_64/sigsetjmp.cpp b/src/setjmp/x86_64/sigsetjmp.cpp
new file mode 100644
index 0000000..4c97a01
--- /dev/null
+++ b/src/setjmp/x86_64/sigsetjmp.cpp
@@ -0,0 +1,68 @@
+//===-- Implementation of sigsetjmp ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/setjmp/sigsetjmp.h"
+#include "hdr/offsetof_macros.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/setjmp/setjmp_impl.h"
+#include "src/setjmp/sigsetjmp_epilogue.h"
+
+#if !defined(LIBC_TARGET_ARCH_IS_X86)
+#error "Invalid file include"
+#endif
+namespace LIBC_NAMESPACE_DECL {
+#ifdef __i386__
+[[gnu::naked]]
+LLVM_LIBC_FUNCTION(int, sigsetjmp, (sigjmp_buf buf)) {
+  asm(R"(
+      mov 8(%%esp), %%ecx
+      jecxz .Lnosave
+
+      mov 4(%%esp), %%eax
+      pop %c[retaddr](%%eax)
+      mov %%ebx, %c[extra](%%eax)
+      mov %%eax, %%ebx
+      call %P[setjmp]
+      push %c[retaddr](%%ebx)
+      mov %%ebx,4(%%esp)
+      mov %%eax,8(%%esp)
+      mov %c[extra](%%ebx), %%ebx
+      jmp %P[epilogue]
+      
+.Lnosave:
+      jmp %P[setjmp])" ::[retaddr] "i"(offsetof(__jmp_buf, sig_retaddr)),
+      [extra] "i"(offsetof(__jmp_buf, sig_extra)), [setjmp] "X"(setjmp),
+      [epilogue] "X"(sigsetjmp_epilogue)
+      : "eax", "ebx", "ecx");
+}
+#endif
+[[gnu::naked]]
+LLVM_LIBC_FUNCTION(int, sigsetjmp, (sigjmp_buf, int)) {
+  asm(R"(
+      test %%esi, %%esi
+      jz .Lnosave
+
+      pop %c[retaddr](%%rdi)
+      mov %%rbx, %c[extra](%%rdi)
+      mov %%rdi, %%rbx
+      call %P[setjmp]
+      push %c[retaddr](%%rbx)
+      mov %%rbx, %%rdi
+      mov %%eax, %%esi
+      mov %c[extra](%%rdi), %%rbx
+      jmp %P[epilogue]
+      
+.Lnosave:
+      jmp %P[setjmp])" ::[retaddr] "i"(offsetof(__jmp_buf, sig_retaddr)),
+      [extra] "i"(offsetof(__jmp_buf, sig_extra)), [setjmp] "X"(setjmp),
+      [epilogue] "X"(sigsetjmp_epilogue)
+      : "rax", "rbx");
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivk.cpp b/src/stdfix/idivk.cpp
new file mode 100644
index 0000000..d1d758d
--- /dev/null
+++ b/src/stdfix/idivk.cpp
@@ -0,0 +1,21 @@
+//===-- Implementation of idivk function  ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "idivk.h"
+#include "include/llvm-libc-macros/stdfix-macros.h" // accum
+#include "src/__support/common.h"                   // LLVM_LIBC_FUNCTION
+#include "src/__support/fixed_point/fx_bits.h"      // fixed_point
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(int, idivk, (accum x, accum y)) {
+  return fixed_point::idiv<accum, int>(x, y);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivk.h b/src/stdfix/idivk.h
new file mode 100644
index 0000000..a84bd0d
--- /dev/null
+++ b/src/stdfix/idivk.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for idivk ------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDFIX_IDIVK_H
+#define LLVM_LIBC_SRC_STDFIX_IDIVK_H
+
+#include "include/llvm-libc-macros/stdfix-macros.h" // accum
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+int idivk(accum x, accum y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDFIX_IDIVK_H
diff --git a/src/stdfix/idivlk.cpp b/src/stdfix/idivlk.cpp
new file mode 100644
index 0000000..36e1df6
--- /dev/null
+++ b/src/stdfix/idivlk.cpp
@@ -0,0 +1,21 @@
+//===-- Implementation of idivlk function  --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "idivlk.h"
+#include "include/llvm-libc-macros/stdfix-macros.h" // long accum
+#include "src/__support/common.h"                   // LLVM_LIBC_FUNCTION
+#include "src/__support/fixed_point/fx_bits.h"      // fixed_point
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(long int, idivlk, (long accum x, long accum y)) {
+  return fixed_point::idiv<long accum, long int>(x, y);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivlk.h b/src/stdfix/idivlk.h
new file mode 100644
index 0000000..274a61a
--- /dev/null
+++ b/src/stdfix/idivlk.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for idivlk -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDFIX_IDIVLK_H
+#define LLVM_LIBC_SRC_STDFIX_IDIVLK_H
+
+#include "include/llvm-libc-macros/stdfix-macros.h" // long accum
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+long int idivlk(long accum x, long accum y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDFIX_IDIVLK_H
diff --git a/src/stdfix/idivlr.cpp b/src/stdfix/idivlr.cpp
new file mode 100644
index 0000000..1c9d62d
--- /dev/null
+++ b/src/stdfix/idivlr.cpp
@@ -0,0 +1,21 @@
+//===-- Implementation of idivlr function  --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "idivlr.h"
+#include "include/llvm-libc-macros/stdfix-macros.h" // long fract
+#include "src/__support/common.h"                   // LLVM_LIBC_FUNCTION
+#include "src/__support/fixed_point/fx_bits.h"      // fixed_point
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(long int, idivlr, (long fract x, long fract y)) {
+  return fixed_point::idiv<long fract, long int>(x, y);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivlr.h b/src/stdfix/idivlr.h
new file mode 100644
index 0000000..de36035
--- /dev/null
+++ b/src/stdfix/idivlr.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for idivlr -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDFIX_IDIVLR_H
+#define LLVM_LIBC_SRC_STDFIX_IDIVLR_H
+
+#include "include/llvm-libc-macros/stdfix-macros.h" // long fract
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+long int idivlr(long fract x, long fract y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDFIX_IDIVLR_H
diff --git a/src/stdfix/idivr.cpp b/src/stdfix/idivr.cpp
new file mode 100644
index 0000000..80dd1b2
--- /dev/null
+++ b/src/stdfix/idivr.cpp
@@ -0,0 +1,21 @@
+//===-- Implementation of idivr function  ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "idivr.h"
+#include "include/llvm-libc-macros/stdfix-macros.h" // fract
+#include "src/__support/common.h"                   // LLVM_LIBC_FUNCTION
+#include "src/__support/fixed_point/fx_bits.h"      // fixed_point
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(int, idivr, (fract x, fract y)) {
+  return fixed_point::idiv<fract, int>(x, y);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivr.h b/src/stdfix/idivr.h
new file mode 100644
index 0000000..f3a95e2
--- /dev/null
+++ b/src/stdfix/idivr.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for idivr ------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDFIX_IDIVR_H
+#define LLVM_LIBC_SRC_STDFIX_IDIVR_H
+
+#include "include/llvm-libc-macros/stdfix-macros.h" // fract
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+int idivr(fract x, fract y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDFIX_IDIVR_H
diff --git a/src/stdfix/idivuk.cpp b/src/stdfix/idivuk.cpp
new file mode 100644
index 0000000..27bf8ed
--- /dev/null
+++ b/src/stdfix/idivuk.cpp
@@ -0,0 +1,21 @@
+//===-- Implementation of idivuk function  --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "idivuk.h"
+#include "include/llvm-libc-macros/stdfix-macros.h" // unsigned accum
+#include "src/__support/common.h"                   // LLVM_LIBC_FUNCTION
+#include "src/__support/fixed_point/fx_bits.h"      // fixed_point
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(unsigned int, idivuk, (unsigned accum x, unsigned accum y)) {
+  return fixed_point::idiv<unsigned accum, unsigned int>(x, y);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivuk.h b/src/stdfix/idivuk.h
new file mode 100644
index 0000000..a8dce0a
--- /dev/null
+++ b/src/stdfix/idivuk.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for idivuk ------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDFIX_IDIVUK_H
+#define LLVM_LIBC_SRC_STDFIX_IDIVUK_H
+
+#include "include/llvm-libc-macros/stdfix-macros.h" // unsigned accum
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+unsigned int idivuk(unsigned accum x, unsigned accum y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDFIX_IDIVUK_H
diff --git a/src/stdfix/idivulk.cpp b/src/stdfix/idivulk.cpp
new file mode 100644
index 0000000..8b4e63c
--- /dev/null
+++ b/src/stdfix/idivulk.cpp
@@ -0,0 +1,22 @@
+//===-- Implementation of idivulk function  -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "idivulk.h"
+#include "include/llvm-libc-macros/stdfix-macros.h" // unsigned long accum
+#include "src/__support/common.h"                   // LLVM_LIBC_FUNCTION
+#include "src/__support/fixed_point/fx_bits.h"      // fixed_point
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(unsigned long int, idivulk,
+                   (unsigned long accum x, unsigned long accum y)) {
+  return fixed_point::idiv<unsigned long accum, unsigned long int>(x, y);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivulk.h b/src/stdfix/idivulk.h
new file mode 100644
index 0000000..b463e76
--- /dev/null
+++ b/src/stdfix/idivulk.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for idivlk -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDFIX_IDIVULK_H
+#define LLVM_LIBC_SRC_STDFIX_IDIVULK_H
+
+#include "include/llvm-libc-macros/stdfix-macros.h" // unsigned long accum
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+unsigned long int idivulk(unsigned long accum x, unsigned long accum y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDFIX_IDIVULK_H
diff --git a/src/stdfix/idivulr.cpp b/src/stdfix/idivulr.cpp
new file mode 100644
index 0000000..6e6a780
--- /dev/null
+++ b/src/stdfix/idivulr.cpp
@@ -0,0 +1,22 @@
+//===-- Implementation of idivulr function --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "idivulr.h"
+#include "include/llvm-libc-macros/stdfix-macros.h" // unsigned long fract
+#include "src/__support/common.h"                   // LLVM_LIBC_FUNCTION
+#include "src/__support/fixed_point/fx_bits.h"      // fixed_point
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(unsigned long int, idivulr,
+                   (unsigned long fract x, unsigned long fract y)) {
+  return fixed_point::idiv<unsigned long fract, unsigned long int>(x, y);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivulr.h b/src/stdfix/idivulr.h
new file mode 100644
index 0000000..c2f6a19
--- /dev/null
+++ b/src/stdfix/idivulr.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for idivulr ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDFIX_IDIVULR_H
+#define LLVM_LIBC_SRC_STDFIX_IDIVULR_H
+
+#include "include/llvm-libc-macros/stdfix-macros.h" // unsigned long fract
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+unsigned long int idivulr(unsigned long fract x, unsigned long fract y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDFIX_IDIVULR_H
diff --git a/src/stdfix/idivur.cpp b/src/stdfix/idivur.cpp
new file mode 100644
index 0000000..319817b
--- /dev/null
+++ b/src/stdfix/idivur.cpp
@@ -0,0 +1,21 @@
+//===-- Implementation of idivur function  --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "idivur.h"
+#include "include/llvm-libc-macros/stdfix-macros.h" // unsigned fract
+#include "src/__support/common.h"                   // LLVM_LIBC_FUNCTION
+#include "src/__support/fixed_point/fx_bits.h"      // fixed_point
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(unsigned int, idivur, (unsigned fract x, unsigned fract y)) {
+  return fixed_point::idiv<unsigned fract, unsigned int>(x, y);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdfix/idivur.h b/src/stdfix/idivur.h
new file mode 100644
index 0000000..f69db20
--- /dev/null
+++ b/src/stdfix/idivur.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for idivur -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDFIX_IDIVUR_H
+#define LLVM_LIBC_SRC_STDFIX_IDIVUR_H
+
+#include "include/llvm-libc-macros/stdfix-macros.h" // unsigned fract
+#include "src/__support/macros/config.h"            // LIBC_NAMESPACE_DECL
+
+namespace LIBC_NAMESPACE_DECL {
+
+unsigned int idivur(unsigned fract x, unsigned fract y);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDFIX_IDIVUR_H
diff --git a/src/stdio/gpu/clearerr.cpp b/src/stdio/gpu/clearerr.cpp
index 4d843e4..5a0ca52 100644
--- a/src/stdio/gpu/clearerr.cpp
+++ b/src/stdio/gpu/clearerr.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/clearerr.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fclose.cpp b/src/stdio/gpu/fclose.cpp
index 847d6b8..1e00515 100644
--- a/src/stdio/gpu/fclose.cpp
+++ b/src/stdio/gpu/fclose.cpp
@@ -7,11 +7,11 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fclose.h"
-#include "src/__support/macros/config.h"
-#include "src/stdio/gpu/file.h"
 
 #include "hdr/stdio_macros.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
+#include "src/stdio/gpu/file.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/feof.cpp b/src/stdio/gpu/feof.cpp
index a15e487..3ae308b 100644
--- a/src/stdio/gpu/feof.cpp
+++ b/src/stdio/gpu/feof.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/feof.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/ferror.cpp b/src/stdio/gpu/ferror.cpp
index 8273820..64d62e7 100644
--- a/src/stdio/gpu/ferror.cpp
+++ b/src/stdio/gpu/ferror.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/ferror.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fflush.cpp b/src/stdio/gpu/fflush.cpp
index 5a5137b..0b6ef92 100644
--- a/src/stdio/gpu/fflush.cpp
+++ b/src/stdio/gpu/fflush.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fflush.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fgetc.cpp b/src/stdio/gpu/fgetc.cpp
index cb42f31..aaeb159 100644
--- a/src/stdio/gpu/fgetc.cpp
+++ b/src/stdio/gpu/fgetc.cpp
@@ -7,11 +7,11 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fgetc.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/stdio_macros.h" // for EOF.
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fgets.cpp b/src/stdio/gpu/fgets.cpp
index d90b7aa..5447e86 100644
--- a/src/stdio/gpu/fgets.cpp
+++ b/src/stdio/gpu/fgets.cpp
@@ -7,14 +7,13 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fgets.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
-#include "src/stdio/feof.h"
-#include "src/stdio/ferror.h"
 
+#include "file.h"
 #include "hdr/stdio_macros.h" // for EOF.
 #include "hdr/types/FILE.h"
-#include <stddef.h>
+#include "src/__support/common.h"
+
+#include <stdint.h>
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/file.h b/src/stdio/gpu/file.h
index 437ee99..102c6c6 100644
--- a/src/stdio/gpu/file.h
+++ b/src/stdio/gpu/file.h
@@ -6,12 +6,11 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/__support/RPC/rpc_client.h"
-#include "src/__support/macros/config.h"
-#include "src/string/string_utils.h"
-
 #include "hdr/stdio_macros.h" // For stdin/out/err
 #include "hdr/types/FILE.h"
+#include "src/__support/RPC/rpc_client.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/attributes.h"
 
 namespace LIBC_NAMESPACE_DECL {
 namespace file {
diff --git a/src/stdio/gpu/fopen.cpp b/src/stdio/gpu/fopen.cpp
index 18dd719..eee3eda 100644
--- a/src/stdio/gpu/fopen.cpp
+++ b/src/stdio/gpu/fopen.cpp
@@ -7,11 +7,12 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fopen.h"
-#include "src/__support/CPP/string_view.h"
-#include "src/__support/macros/config.h"
-#include "src/stdio/gpu/file.h"
 
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
+#include "src/stdio/gpu/file.h"
+#include "src/string/memory_utils/inline_memcpy.h"
+#include "src/string/string_utils.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fprintf.cpp b/src/stdio/gpu/fprintf.cpp
index 46196d7..5b8f01d 100644
--- a/src/stdio/gpu/fprintf.cpp
+++ b/src/stdio/gpu/fprintf.cpp
@@ -11,6 +11,7 @@
 #include "hdr/types/FILE.h"
 #include "src/__support/CPP/string_view.h"
 #include "src/__support/arg_list.h"
+#include "src/__support/common.h"
 #include "src/errno/libc_errno.h"
 #include "src/stdio/gpu/vfprintf_utils.h"
 
diff --git a/src/stdio/gpu/fputc.cpp b/src/stdio/gpu/fputc.cpp
index ad2db03..8a8959b 100644
--- a/src/stdio/gpu/fputc.cpp
+++ b/src/stdio/gpu/fputc.cpp
@@ -7,11 +7,11 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fputc.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/stdio_macros.h" // for EOF.
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fputs.cpp b/src/stdio/gpu/fputs.cpp
index 7a08244..780a40d 100644
--- a/src/stdio/gpu/fputs.cpp
+++ b/src/stdio/gpu/fputs.cpp
@@ -7,13 +7,12 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fputs.h"
-#include "src/__support/CPP/string_view.h"
-#include "src/__support/macros/config.h"
-#include "src/errno/libc_errno.h"
-#include "src/stdio/gpu/file.h"
 
 #include "hdr/stdio_macros.h" // for EOF.
 #include "hdr/types/FILE.h"
+#include "src/__support/CPP/string_view.h"
+#include "src/__support/common.h"
+#include "src/stdio/gpu/file.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fread.cpp b/src/stdio/gpu/fread.cpp
index 57fa5b6..5619b54 100644
--- a/src/stdio/gpu/fread.cpp
+++ b/src/stdio/gpu/fread.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fread.h"
-#include "src/__support/macros/config.h"
-#include "src/stdio/gpu/file.h"
 
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
+#include "src/stdio/gpu/file.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fseek.cpp b/src/stdio/gpu/fseek.cpp
index 5ada5de..468d65f 100644
--- a/src/stdio/gpu/fseek.cpp
+++ b/src/stdio/gpu/fseek.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fseek.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/ftell.cpp b/src/stdio/gpu/ftell.cpp
index 04bb0dd..7ee33d7 100644
--- a/src/stdio/gpu/ftell.cpp
+++ b/src/stdio/gpu/ftell.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/ftell.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/fwrite.cpp b/src/stdio/gpu/fwrite.cpp
index 6c54869..73c2651 100644
--- a/src/stdio/gpu/fwrite.cpp
+++ b/src/stdio/gpu/fwrite.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/fwrite.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/getc.cpp b/src/stdio/gpu/getc.cpp
index 9c32974..6dfb5ce 100644
--- a/src/stdio/gpu/getc.cpp
+++ b/src/stdio/gpu/getc.cpp
@@ -7,11 +7,11 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/getc.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/stdio_macros.h" // for EOF.
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/getchar.cpp b/src/stdio/gpu/getchar.cpp
index d99b97b..7bf561f 100644
--- a/src/stdio/gpu/getchar.cpp
+++ b/src/stdio/gpu/getchar.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/getchar.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/stdio_macros.h" // for EOF and stdin.
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/printf.cpp b/src/stdio/gpu/printf.cpp
index be1885f..53fe69d 100644
--- a/src/stdio/gpu/printf.cpp
+++ b/src/stdio/gpu/printf.cpp
@@ -10,6 +10,7 @@
 
 #include "src/__support/CPP/string_view.h"
 #include "src/__support/arg_list.h"
+#include "src/__support/common.h"
 #include "src/errno/libc_errno.h"
 #include "src/stdio/gpu/vfprintf_utils.h"
 
diff --git a/src/stdio/gpu/putc.cpp b/src/stdio/gpu/putc.cpp
index f8ae98d..da80d6c 100644
--- a/src/stdio/gpu/putc.cpp
+++ b/src/stdio/gpu/putc.cpp
@@ -7,11 +7,11 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/putc.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/stdio_macros.h" // for EOF.
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/putchar.cpp b/src/stdio/gpu/putchar.cpp
index c49b02e..da2d0a8 100644
--- a/src/stdio/gpu/putchar.cpp
+++ b/src/stdio/gpu/putchar.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/putchar.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/stdio_macros.h" // for EOF and stdout.
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/puts.cpp b/src/stdio/gpu/puts.cpp
index fc252ab..9b4ae66 100644
--- a/src/stdio/gpu/puts.cpp
+++ b/src/stdio/gpu/puts.cpp
@@ -7,19 +7,18 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/puts.h"
-#include "src/__support/CPP/string_view.h"
-#include "src/__support/macros/config.h"
-#include "src/errno/libc_errno.h"
-#include "src/stdio/gpu/file.h"
 
 #include "hdr/stdio_macros.h" // for EOF and stdout.
+#include "src/__support/CPP/string_view.h"
+#include "src/__support/common.h"
+#include "src/stdio/gpu/file.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(int, puts, (const char *__restrict str)) {
   cpp::string_view str_view(str);
-  auto written = file::write_impl<LIBC_WRITE_TO_STDOUT_NEWLINE>(stdout, str,
-                                                               str_view.size());
+  auto written = file::write_impl<LIBC_WRITE_TO_STDOUT_NEWLINE>(
+      stdout, str, str_view.size());
   if (written != str_view.size() + 1)
     return EOF;
   return 0;
diff --git a/src/stdio/gpu/remove.cpp b/src/stdio/gpu/remove.cpp
index 4bfb5d3..3cd7274 100644
--- a/src/stdio/gpu/remove.cpp
+++ b/src/stdio/gpu/remove.cpp
@@ -7,10 +7,11 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/remove.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
+#include "src/string/string_utils.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/rename.cpp b/src/stdio/gpu/rename.cpp
index 589bf24..d7c71fc 100644
--- a/src/stdio/gpu/rename.cpp
+++ b/src/stdio/gpu/rename.cpp
@@ -7,11 +7,11 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/rename.h"
-#include "src/__support/CPP/string_view.h"
-#include "src/__support/macros/config.h"
-#include "src/stdio/gpu/file.h"
 
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
+#include "src/stdio/gpu/file.h"
+#include "src/string/string_utils.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/stderr.cpp b/src/stdio/gpu/stderr.cpp
index efbc3b4..d0fa1ae 100644
--- a/src/stdio/gpu/stderr.cpp
+++ b/src/stdio/gpu/stderr.cpp
@@ -7,7 +7,7 @@
 //===----------------------------------------------------------------------===//
 
 #include "hdr/types/FILE.h"
-#include "src/__support/macros/config.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 static struct {
diff --git a/src/stdio/gpu/stdin.cpp b/src/stdio/gpu/stdin.cpp
index 66618fd..fef4c3e 100644
--- a/src/stdio/gpu/stdin.cpp
+++ b/src/stdio/gpu/stdin.cpp
@@ -7,7 +7,7 @@
 //===----------------------------------------------------------------------===//
 
 #include "hdr/types/FILE.h"
-#include "src/__support/macros/config.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 static struct {
diff --git a/src/stdio/gpu/stdout.cpp b/src/stdio/gpu/stdout.cpp
index e3869f9..e458dcc 100644
--- a/src/stdio/gpu/stdout.cpp
+++ b/src/stdio/gpu/stdout.cpp
@@ -7,7 +7,7 @@
 //===----------------------------------------------------------------------===//
 
 #include "hdr/types/FILE.h"
-#include "src/__support/macros/config.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 static struct {
diff --git a/src/stdio/gpu/ungetc.cpp b/src/stdio/gpu/ungetc.cpp
index fd1db46..fadd1d7 100644
--- a/src/stdio/gpu/ungetc.cpp
+++ b/src/stdio/gpu/ungetc.cpp
@@ -7,10 +7,10 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/ungetc.h"
-#include "file.h"
-#include "src/__support/macros/config.h"
 
+#include "file.h"
 #include "hdr/types/FILE.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
diff --git a/src/stdio/gpu/vfprintf.cpp b/src/stdio/gpu/vfprintf.cpp
index c92685f..16a5ed4 100644
--- a/src/stdio/gpu/vfprintf.cpp
+++ b/src/stdio/gpu/vfprintf.cpp
@@ -11,7 +11,7 @@
 #include "hdr/types/FILE.h"
 #include "src/__support/CPP/string_view.h"
 #include "src/__support/arg_list.h"
-#include "src/errno/libc_errno.h"
+#include "src/__support/common.h"
 #include "src/stdio/gpu/vfprintf_utils.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/stdio/gpu/vfprintf_utils.h b/src/stdio/gpu/vfprintf_utils.h
index df157d3..6df4648 100644
--- a/src/stdio/gpu/vfprintf_utils.h
+++ b/src/stdio/gpu/vfprintf_utils.h
@@ -10,7 +10,6 @@
 #include "src/__support/GPU/utils.h"
 #include "src/__support/RPC/rpc_client.h"
 #include "src/__support/arg_list.h"
-#include "src/__support/macros/config.h"
 #include "src/stdio/gpu/file.h"
 #include "src/string/string_utils.h"
 
diff --git a/src/stdio/gpu/vprintf.cpp b/src/stdio/gpu/vprintf.cpp
index 54012f3..65f5dbf 100644
--- a/src/stdio/gpu/vprintf.cpp
+++ b/src/stdio/gpu/vprintf.cpp
@@ -10,7 +10,7 @@
 
 #include "src/__support/CPP/string_view.h"
 #include "src/__support/arg_list.h"
-#include "src/errno/libc_errno.h"
+#include "src/__support/common.h"
 #include "src/stdio/gpu/vfprintf_utils.h"
 
 namespace LIBC_NAMESPACE_DECL {
diff --git a/src/stdio/printf_core/core_structs.h b/src/stdio/printf_core/core_structs.h
index 4c3b81f..e27f77b 100644
--- a/src/stdio/printf_core/core_structs.h
+++ b/src/stdio/printf_core/core_structs.h
@@ -55,8 +55,13 @@ struct FormatSection {
   int min_width = 0;
   int precision = -1;
 
-  // Needs to be large enough to hold a long double.
+  // Needs to be large enough to hold a long double. Special case handling for
+  // the PowerPC double double type because it has no FPBits interface.
+#ifdef LIBC_TYPES_LONG_DOUBLE_IS_DOUBLE_DOUBLE
+  UInt128 conv_val_raw;
+#else
   fputil::FPBits<long double>::StorageType conv_val_raw;
+#endif // LIBC_TYPES_LONG_DOUBLE_IS_DOUBLE_DOUBLE
   void *conv_val_ptr;
 
   char conv_name;
diff --git a/src/stdio/printf_core/float_dec_converter.h b/src/stdio/printf_core/float_dec_converter.h
index ee55498..ed004f9 100644
--- a/src/stdio/printf_core/float_dec_converter.h
+++ b/src/stdio/printf_core/float_dec_converter.h
@@ -186,13 +186,12 @@ template <WriteMode write_mode> class FloatWriter {
     if (total_digits_written < digits_before_decimal &&
         total_digits_written + buffered_digits >= digits_before_decimal &&
         has_decimal_point) {
+      // digits_to_write > 0 guaranteed by outer if
       size_t digits_to_write = digits_before_decimal - total_digits_written;
-      if (digits_to_write > 0) {
-        // Write the digits before the decimal point.
-        RET_IF_RESULT_NEGATIVE(writer->write({block_buffer, digits_to_write}));
-      }
+      // Write the digits before the decimal point.
+      RET_IF_RESULT_NEGATIVE(writer->write({block_buffer, digits_to_write}));
       RET_IF_RESULT_NEGATIVE(writer->write(DECIMAL_POINT));
-      if (buffered_digits - digits_to_write > 0) {
+      if (buffered_digits > digits_to_write) {
         // Write the digits after the decimal point.
         RET_IF_RESULT_NEGATIVE(
             writer->write({block_buffer + digits_to_write,
@@ -217,12 +216,11 @@ template <WriteMode write_mode> class FloatWriter {
         total_digits_written + BLOCK_SIZE * max_block_count >=
             digits_before_decimal &&
         has_decimal_point) {
+      // digits_to_write > 0 guaranteed by outer if
       size_t digits_to_write = digits_before_decimal - total_digits_written;
-      if (digits_to_write > 0) {
-        RET_IF_RESULT_NEGATIVE(writer->write(MAX_BLOCK_DIGIT, digits_to_write));
-      }
+      RET_IF_RESULT_NEGATIVE(writer->write(MAX_BLOCK_DIGIT, digits_to_write));
       RET_IF_RESULT_NEGATIVE(writer->write(DECIMAL_POINT));
-      if ((BLOCK_SIZE * max_block_count) - digits_to_write > 0) {
+      if ((BLOCK_SIZE * max_block_count) > digits_to_write) {
         RET_IF_RESULT_NEGATIVE(writer->write(
             MAX_BLOCK_DIGIT, (BLOCK_SIZE * max_block_count) - digits_to_write));
       }
diff --git a/src/math/amdgpu/remquo.cpp b/src/stdlib/memalignment.cpp
similarity index 56%
rename from src/math/amdgpu/remquo.cpp
rename to src/stdlib/memalignment.cpp
index 42c908e..f06e7bf 100644
--- a/src/math/amdgpu/remquo.cpp
+++ b/src/stdlib/memalignment.cpp
@@ -1,4 +1,4 @@
-//===-- Implementation of the GPU remquo function -------------------------===//
+//===-- Implementation for memalignment -------------------------*- C++ -*-===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,19 +6,20 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/remquo.h"
+#include "src/stdlib/memalignment.h"
+#include "src/__support/CPP/bit.h"
 #include "src/__support/common.h"
-
-#include "declarations.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, remquo, (double x, double y, int *quo)) {
-  int tmp;
-  double r = __ocml_remquo_f64(x, y, (gpu::Private<int> *)&tmp);
-  *quo = tmp;
-  return r;
+LLVM_LIBC_FUNCTION(size_t, memalignment, (const void *p)) {
+  if (p == nullptr)
+    return 0;
+
+  uintptr_t addr = reinterpret_cast<uintptr_t>(p);
+
+  return size_t(1) << cpp::countr_zero(addr);
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/stdlib/memalignment.h b/src/stdlib/memalignment.h
new file mode 100644
index 0000000..b7c7430
--- /dev/null
+++ b/src/stdlib/memalignment.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for memalignment ------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDLIB_MEM_ALIGNMENT_H
+#define LLVM_LIBC_SRC_STDLIB_MEM_ALIGNMENT_H
+
+#include "hdr/types/size_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+size_t memalignment(const void *p);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_STDLIB_LDIV_H
diff --git a/src/stdlib/qsort_r.h b/src/stdlib/qsort_r.h
index 51a459c..b0d8c57 100644
--- a/src/stdlib/qsort_r.h
+++ b/src/stdlib/qsort_r.h
@@ -14,10 +14,9 @@
 
 namespace LIBC_NAMESPACE_DECL {
 
-// This qsort_r uses the glibc argument ordering instead of the BSD argument
-// ordering (which puts arg before the function pointer). Putting arg after the
-// function pointer more closely matches the ordering for qsort_s, which is the
-// standardized equivalent of qsort_r.
+// This qsort_r uses the POSIX 1003.1-2024 argument ordering instead of the
+// historical BSD argument ordering (which put arg before the function pointer).
+// https://www.austingroupbugs.net/view.php?id=900
 
 void qsort_r(void *array, size_t array_size, size_t elem_size,
              int (*compare)(const void *, const void *, void *), void *arg);
diff --git a/src/string/memccpy.cpp b/src/string/memccpy.cpp
index ae90cf9..d5654fc 100644
--- a/src/string/memccpy.cpp
+++ b/src/string/memccpy.cpp
@@ -10,6 +10,7 @@
 
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include <stddef.h> // For size_t.
 
 namespace LIBC_NAMESPACE_DECL {
@@ -17,6 +18,10 @@ namespace LIBC_NAMESPACE_DECL {
 LLVM_LIBC_FUNCTION(void *, memccpy,
                    (void *__restrict dest, const void *__restrict src, int c,
                     size_t count)) {
+  if (count) {
+    LIBC_CRASH_ON_NULLPTR(dest);
+    LIBC_CRASH_ON_NULLPTR(src);
+  }
   unsigned char end = static_cast<unsigned char>(c);
   const unsigned char *uc_src = static_cast<const unsigned char *>(src);
   unsigned char *uc_dest = static_cast<unsigned char *>(dest);
diff --git a/src/string/memchr.cpp b/src/string/memchr.cpp
index ba52f14..ccdc262 100644
--- a/src/string/memchr.cpp
+++ b/src/string/memchr.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/memchr.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/string_utils.h"
 
 #include "src/__support/common.h"
@@ -17,6 +18,8 @@ namespace LIBC_NAMESPACE_DECL {
 
 // TODO: Look at performance benefits of comparing words.
 LLVM_LIBC_FUNCTION(void *, memchr, (const void *src, int c, size_t n)) {
+  if (n)
+    LIBC_CRASH_ON_NULLPTR(src);
   return internal::find_first_character(
       reinterpret_cast<const unsigned char *>(src),
       static_cast<unsigned char>(c), n);
diff --git a/src/string/memcmp.cpp b/src/string/memcmp.cpp
index 68996fb..d2f67f0 100644
--- a/src/string/memcmp.cpp
+++ b/src/string/memcmp.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/memcmp.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_memcmp.h"
 
 #include <stddef.h> // size_t
@@ -16,6 +17,10 @@ namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(int, memcmp,
                    (const void *lhs, const void *rhs, size_t count)) {
+  if (count) {
+    LIBC_CRASH_ON_NULLPTR(lhs);
+    LIBC_CRASH_ON_NULLPTR(rhs);
+  }
   return inline_memcmp(lhs, rhs, count);
 }
 
diff --git a/src/string/memcpy.cpp b/src/string/memcpy.cpp
index 0eb7f2c..4d4ff4d 100644
--- a/src/string/memcpy.cpp
+++ b/src/string/memcpy.cpp
@@ -9,6 +9,7 @@
 #include "src/string/memcpy.h"
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_memcpy.h"
 
 namespace LIBC_NAMESPACE_DECL {
@@ -16,6 +17,10 @@ namespace LIBC_NAMESPACE_DECL {
 LLVM_LIBC_FUNCTION(void *, memcpy,
                    (void *__restrict dst, const void *__restrict src,
                     size_t size)) {
+  if (size) {
+    LIBC_CRASH_ON_NULLPTR(dst);
+    LIBC_CRASH_ON_NULLPTR(src);
+  }
   inline_memcpy(dst, src, size);
   return dst;
 }
diff --git a/src/string/memmove.cpp b/src/string/memmove.cpp
index 26a8c41..04ed51b 100644
--- a/src/string/memmove.cpp
+++ b/src/string/memmove.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/memmove.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_memcpy.h"
 #include "src/string/memory_utils/inline_memmove.h"
 #include <stddef.h> // size_t
@@ -16,6 +17,10 @@ namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(void *, memmove,
                    (void *dst, const void *src, size_t count)) {
+  if (count) {
+    LIBC_CRASH_ON_NULLPTR(dst);
+    LIBC_CRASH_ON_NULLPTR(src);
+  }
   // Memmove may handle some small sizes as efficiently as inline_memcpy.
   // For these sizes we may not do is_disjoint check.
   // This both avoids additional code for the most frequent smaller sizes
diff --git a/src/string/memory_utils/aarch64/inline_bcmp.h b/src/string/memory_utils/aarch64/inline_bcmp.h
index e41ac20..66d2437 100644
--- a/src/string/memory_utils/aarch64/inline_bcmp.h
+++ b/src/string/memory_utils/aarch64/inline_bcmp.h
@@ -19,9 +19,43 @@
 
 namespace LIBC_NAMESPACE_DECL {
 
-[[maybe_unused]] LIBC_INLINE BcmpReturnType inline_bcmp_aarch64(CPtr p1,
-                                                                CPtr p2,
-                                                                size_t count) {
+[[maybe_unused]] LIBC_INLINE BcmpReturnType
+inline_bcmp_aarch64_no_fp(CPtr p1, CPtr p2, size_t count) {
+  if (LIBC_LIKELY(count < 16)) {
+    switch (count) {
+    case 0:
+      return BcmpReturnType::zero();
+    case 1:
+      return generic::Bcmp<uint8_t>::block(p1, p2);
+    case 2:
+      return generic::Bcmp<uint16_t>::block(p1, p2);
+    case 3:
+      return generic::Bcmp<uint16_t>::head_tail(p1, p2, count);
+    case 4:
+      return generic::Bcmp<uint32_t>::block(p1, p2);
+    case 5:
+    case 6:
+    case 7:
+      return generic::Bcmp<uint32_t>::head_tail(p1, p2, count);
+    case 8:
+      return generic::Bcmp<uint64_t>::block(p1, p2);
+    case 9:
+    case 10:
+    case 11:
+    case 12:
+    case 13:
+    case 14:
+    case 15:
+      return generic::Bcmp<uint64_t>::head_tail(p1, p2, count);
+    }
+  }
+
+  return generic::Bcmp<uint64_t>::loop_and_tail_align_above(256, p1, p2, count);
+}
+
+#ifdef __ARM_NEON
+[[maybe_unused]] LIBC_INLINE BcmpReturnType
+inline_bcmp_aarch64_with_fp(CPtr p1, CPtr p2, size_t count) {
   if (LIBC_LIKELY(count <= 32)) {
     if (LIBC_UNLIKELY(count >= 16)) {
       return aarch64::Bcmp<16>::head_tail(p1, p2, count);
@@ -65,6 +99,16 @@ namespace LIBC_NAMESPACE_DECL {
   }
   return aarch64::Bcmp<32>::loop_and_tail(p1, p2, count);
 }
+#endif
+
+[[gnu::flatten]] LIBC_INLINE BcmpReturnType
+inline_bcmp_aarch64_dispatch(CPtr p1, CPtr p2, size_t count) {
+#if defined(__ARM_NEON)
+  return inline_bcmp_aarch64_with_fp(p1, p2, count);
+#else
+  return inline_bcmp_aarch64_no_fp(p1, p2, count);
+#endif
+}
 
 } // namespace LIBC_NAMESPACE_DECL
 
diff --git a/src/string/memory_utils/aarch64/inline_memcmp.h b/src/string/memory_utils/aarch64/inline_memcmp.h
index 35ca077..380ebb4 100644
--- a/src/string/memory_utils/aarch64/inline_memcmp.h
+++ b/src/string/memory_utils/aarch64/inline_memcmp.h
@@ -17,17 +17,40 @@
 namespace LIBC_NAMESPACE_DECL {
 
 [[maybe_unused]] LIBC_INLINE MemcmpReturnType
-inline_memcmp_generic_gt16(CPtr p1, CPtr p2, size_t count) {
-  if (LIBC_UNLIKELY(count >= 384)) {
-    if (auto value = generic::Memcmp<uint8x16_t>::block(p1, p2))
-      return value;
-    align_to_next_boundary<16, Arg::P1>(p1, p2, count);
-  }
-  return generic::Memcmp<uint8x16_t>::loop_and_tail(p1, p2, count);
+inline_memcmp_aarch64_no_fp(CPtr p1, CPtr p2, size_t count) {
+  if (count == 0)
+    return MemcmpReturnType::zero();
+  if (count == 1)
+    return generic::Memcmp<uint8_t>::block(p1, p2);
+  if (count == 2)
+    return generic::Memcmp<uint16_t>::block(p1, p2);
+  if (count == 3)
+    return generic::MemcmpSequence<uint16_t, uint8_t>::block(p1, p2);
+  if (count <= 8)
+    return generic::Memcmp<uint32_t>::head_tail(p1, p2, count);
+  if (count <= 16)
+    return generic::Memcmp<uint64_t>::head_tail(p1, p2, count);
+
+  return generic::Memcmp<uint64_t>::loop_and_tail_align_above(384, p1, p2,
+                                                              count);
 }
 
+#if defined(__ARM_NEON)
 [[maybe_unused]] LIBC_INLINE MemcmpReturnType
-inline_memcmp_aarch64_neon_gt16(CPtr p1, CPtr p2, size_t count) {
+inline_memcmp_aarch64_with_fp(CPtr p1, CPtr p2, size_t count) {
+  if (count == 0)
+    return MemcmpReturnType::zero();
+  if (count == 1)
+    return generic::Memcmp<uint8_t>::block(p1, p2);
+  if (count == 2)
+    return generic::Memcmp<uint16_t>::block(p1, p2);
+  if (count == 3)
+    return generic::MemcmpSequence<uint16_t, uint8_t>::block(p1, p2);
+  if (count <= 8)
+    return generic::Memcmp<uint32_t>::head_tail(p1, p2, count);
+  if (count <= 16)
+    return generic::Memcmp<uint64_t>::head_tail(p1, p2, count);
+
   if (LIBC_UNLIKELY(count >= 128)) { // [128, ∞]
     if (auto value = generic::Memcmp<uint8x16_t>::block(p1, p2))
       return value;
@@ -46,25 +69,15 @@ inline_memcmp_aarch64_neon_gt16(CPtr p1, CPtr p2, size_t count) {
   return generic::Memcmp<uint8x16_t>::loop_and_tail(p1 + 32, p2 + 32,
                                                     count - 32);
 }
+#endif
 
-LIBC_INLINE MemcmpReturnType inline_memcmp_aarch64(CPtr p1, CPtr p2,
-                                                   size_t count) {
-  if (count == 0)
-    return MemcmpReturnType::zero();
-  if (count == 1)
-    return generic::Memcmp<uint8_t>::block(p1, p2);
-  if (count == 2)
-    return generic::Memcmp<uint16_t>::block(p1, p2);
-  if (count == 3)
-    return generic::MemcmpSequence<uint16_t, uint8_t>::block(p1, p2);
-  if (count <= 8)
-    return generic::Memcmp<uint32_t>::head_tail(p1, p2, count);
-  if (count <= 16)
-    return generic::Memcmp<uint64_t>::head_tail(p1, p2, count);
-  if constexpr (aarch64::kNeon)
-    return inline_memcmp_aarch64_neon_gt16(p1, p2, count);
-  else
-    return inline_memcmp_generic_gt16(p1, p2, count);
+[[gnu::flatten]] LIBC_INLINE MemcmpReturnType
+inline_memcmp_aarch64_dispatch(CPtr p1, CPtr p2, size_t count) {
+#if defined(__ARM_NEON)
+  return inline_memcmp_aarch64_with_fp(p1, p2, count);
+#else
+  return inline_memcmp_aarch64_no_fp(p1, p2, count);
+#endif
 }
 } // namespace LIBC_NAMESPACE_DECL
 
diff --git a/src/string/memory_utils/aarch64/inline_memmove.h b/src/string/memory_utils/aarch64/inline_memmove.h
index 2b23803..d8d2769 100644
--- a/src/string/memory_utils/aarch64/inline_memmove.h
+++ b/src/string/memory_utils/aarch64/inline_memmove.h
@@ -8,8 +8,7 @@
 #ifndef LIBC_SRC_STRING_MEMORY_UTILS_AARCH64_INLINE_MEMMOVE_H
 #define LIBC_SRC_STRING_MEMORY_UTILS_AARCH64_INLINE_MEMMOVE_H
 
-#include "src/__support/macros/attributes.h"    // LIBC_INLINE
-#include "src/string/memory_utils/op_aarch64.h" // aarch64::kNeon
+#include "src/__support/macros/attributes.h" // LIBC_INLINE
 #include "src/string/memory_utils/op_builtin.h"
 #include "src/string/memory_utils/op_generic.h"
 #include "src/string/memory_utils/utils.h"
@@ -19,7 +18,6 @@
 namespace LIBC_NAMESPACE_DECL {
 
 LIBC_INLINE void inline_memmove_aarch64(Ptr dst, CPtr src, size_t count) {
-  static_assert(aarch64::kNeon, "aarch64 supports vector types");
   using uint128_t = generic_v128;
   using uint256_t = generic_v256;
   using uint512_t = generic_v512;
diff --git a/src/string/memory_utils/aarch64/inline_memset.h b/src/string/memory_utils/aarch64/inline_memset.h
index efcbfd0..1b4b871 100644
--- a/src/string/memory_utils/aarch64/inline_memset.h
+++ b/src/string/memory_utils/aarch64/inline_memset.h
@@ -18,12 +18,12 @@
 
 namespace LIBC_NAMESPACE_DECL {
 
+using uint128_t = generic_v128;
+using uint256_t = generic_v256;
+using uint512_t = generic_v512;
+
 [[maybe_unused]] LIBC_INLINE static void
-inline_memset_aarch64(Ptr dst, uint8_t value, size_t count) {
-  static_assert(aarch64::kNeon, "aarch64 supports vector types");
-  using uint128_t = generic_v128;
-  using uint256_t = generic_v256;
-  using uint512_t = generic_v512;
+inline_memset_aarch64_no_fp(Ptr dst, uint8_t value, size_t count) {
   if (count == 0)
     return;
   if (count <= 3) {
@@ -46,15 +46,57 @@ inline_memset_aarch64(Ptr dst, uint8_t value, size_t count) {
     generic::Memset<uint256_t>::tail(dst, value, count);
     return;
   }
+
+  generic::Memset<uint128_t>::block(dst, value);
+  align_to_next_boundary<16>(dst, count);
+  return generic::Memset<uint512_t>::loop_and_tail(dst, value, count);
+}
+
+#if defined(__ARM_NEON)
+[[maybe_unused]] LIBC_INLINE static void
+inline_memset_aarch64_with_fp(Ptr dst, uint8_t value, size_t count) {
+  if (count == 0)
+    return;
+  if (count <= 3) {
+    generic::Memset<uint8_t>::block(dst, value);
+    if (count > 1)
+      generic::Memset<uint16_t>::tail(dst, value, count);
+    return;
+  }
+  if (count <= 8)
+    return generic::Memset<uint32_t>::head_tail(dst, value, count);
+  if (count <= 16)
+    return generic::Memset<uint64_t>::head_tail(dst, value, count);
+  if (count <= 32)
+    return generic::Memset<uint128_t>::head_tail(dst, value, count);
+  if (count <= (32 + 64)) {
+    generic::Memset<uint256_t>::block(dst, value);
+    if (count <= 64)
+      return generic::Memset<uint256_t>::tail(dst, value, count);
+    generic::Memset<uint256_t>::block(dst + 32, value);
+    generic::Memset<uint256_t>::tail(dst, value, count);
+    return;
+  }
+
   if (count >= 448 && value == 0 && aarch64::neon::hasZva()) {
     generic::Memset<uint512_t>::block(dst, 0);
     align_to_next_boundary<64>(dst, count);
     return aarch64::neon::BzeroCacheLine::loop_and_tail(dst, 0, count);
-  } else {
-    generic::Memset<uint128_t>::block(dst, value);
-    align_to_next_boundary<16>(dst, count);
-    return generic::Memset<uint512_t>::loop_and_tail(dst, value, count);
   }
+
+  generic::Memset<uint128_t>::block(dst, value);
+  align_to_next_boundary<16>(dst, count);
+  return generic::Memset<uint512_t>::loop_and_tail(dst, value, count);
+}
+#endif
+
+[[gnu::flatten]] [[maybe_unused]] LIBC_INLINE static void
+inline_memset_aarch64_dispatch(Ptr dst, uint8_t value, size_t count) {
+#if defined(__ARM_NEON)
+  return inline_memset_aarch64_with_fp(dst, value, count);
+#else
+  return inline_memset_aarch64_no_fp(dst, value, count);
+#endif
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/string/memory_utils/inline_bcmp.h b/src/string/memory_utils/inline_bcmp.h
index 3c1dc80..955d764 100644
--- a/src/string/memory_utils/inline_bcmp.h
+++ b/src/string/memory_utils/inline_bcmp.h
@@ -21,7 +21,7 @@
 #define LIBC_SRC_STRING_MEMORY_UTILS_BCMP inline_bcmp_x86
 #elif defined(LIBC_TARGET_ARCH_IS_AARCH64)
 #include "src/string/memory_utils/aarch64/inline_bcmp.h"
-#define LIBC_SRC_STRING_MEMORY_UTILS_BCMP inline_bcmp_aarch64
+#define LIBC_SRC_STRING_MEMORY_UTILS_BCMP inline_bcmp_aarch64_dispatch
 #elif defined(LIBC_TARGET_ARCH_IS_ANY_RISCV)
 #include "src/string/memory_utils/riscv/inline_bcmp.h"
 #define LIBC_SRC_STRING_MEMORY_UTILS_BCMP inline_bcmp_riscv
diff --git a/src/string/memory_utils/inline_memcmp.h b/src/string/memory_utils/inline_memcmp.h
index a2ca9af..85a614b 100644
--- a/src/string/memory_utils/inline_memcmp.h
+++ b/src/string/memory_utils/inline_memcmp.h
@@ -20,7 +20,7 @@
 #define LIBC_SRC_STRING_MEMORY_UTILS_MEMCMP inline_memcmp_x86
 #elif defined(LIBC_TARGET_ARCH_IS_AARCH64)
 #include "src/string/memory_utils/aarch64/inline_memcmp.h"
-#define LIBC_SRC_STRING_MEMORY_UTILS_MEMCMP inline_memcmp_aarch64
+#define LIBC_SRC_STRING_MEMORY_UTILS_MEMCMP inline_memcmp_aarch64_dispatch
 #elif defined(LIBC_TARGET_ARCH_IS_ANY_RISCV)
 #include "src/string/memory_utils/riscv/inline_memcmp.h"
 #define LIBC_SRC_STRING_MEMORY_UTILS_MEMCMP inline_memcmp_riscv
diff --git a/src/string/memory_utils/inline_memset.h b/src/string/memory_utils/inline_memset.h
index aed3707..fd9c29e 100644
--- a/src/string/memory_utils/inline_memset.h
+++ b/src/string/memory_utils/inline_memset.h
@@ -20,7 +20,7 @@
 #define LIBC_SRC_STRING_MEMORY_UTILS_MEMSET inline_memset_x86
 #elif defined(LIBC_TARGET_ARCH_IS_AARCH64)
 #include "src/string/memory_utils/aarch64/inline_memset.h"
-#define LIBC_SRC_STRING_MEMORY_UTILS_MEMSET inline_memset_aarch64
+#define LIBC_SRC_STRING_MEMORY_UTILS_MEMSET inline_memset_aarch64_dispatch
 #elif defined(LIBC_TARGET_ARCH_IS_ANY_RISCV)
 #include "src/string/memory_utils/riscv/inline_memset.h"
 #define LIBC_SRC_STRING_MEMORY_UTILS_MEMSET inline_memset_riscv
diff --git a/src/string/memory_utils/op_aarch64.h b/src/string/memory_utils/op_aarch64.h
index 868c644..e552601 100644
--- a/src/string/memory_utils/op_aarch64.h
+++ b/src/string/memory_utils/op_aarch64.h
@@ -25,7 +25,6 @@
 
 #ifdef __ARM_NEON
 #include <arm_neon.h>
-#endif //__ARM_NEON
 
 namespace LIBC_NAMESPACE_DECL {
 namespace aarch64 {
@@ -176,6 +175,8 @@ template <size_t Size> struct Bcmp {
 } // namespace aarch64
 } // namespace LIBC_NAMESPACE_DECL
 
+#endif //__ARM_NEON
+
 namespace LIBC_NAMESPACE_DECL {
 namespace generic {
 
@@ -225,6 +226,8 @@ LIBC_INLINE MemcmpReturnType cmp<uint64_t>(CPtr p1, CPtr p2, size_t offset) {
   return MemcmpReturnType::zero();
 }
 
+#if defined(__ARM_NEON)
+
 ///////////////////////////////////////////////////////////////////////////////
 // Specializations for uint8x16_t
 template <> struct is_vector<uint8x16_t> : cpp::true_type {};
@@ -269,6 +272,9 @@ LIBC_INLINE MemcmpReturnType cmp<uint8x16x2_t>(CPtr p1, CPtr p2,
   }
   return MemcmpReturnType::zero();
 }
+
+#endif // __ARM_NEON
+
 } // namespace generic
 } // namespace LIBC_NAMESPACE_DECL
 
diff --git a/src/string/mempcpy.cpp b/src/string/mempcpy.cpp
index 09392ce..b6a9721 100644
--- a/src/string/mempcpy.cpp
+++ b/src/string/mempcpy.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/mempcpy.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_memcpy.h"
 
 #include "src/__support/common.h"
@@ -18,6 +19,10 @@ namespace LIBC_NAMESPACE_DECL {
 LLVM_LIBC_FUNCTION(void *, mempcpy,
                    (void *__restrict dst, const void *__restrict src,
                     size_t count)) {
+  if (count) {
+    LIBC_CRASH_ON_NULLPTR(dst);
+    LIBC_CRASH_ON_NULLPTR(src);
+  }
   inline_memcpy(dst, src, count);
   return reinterpret_cast<char *>(dst) + count;
 }
diff --git a/src/string/memrchr.cpp b/src/string/memrchr.cpp
index d665e22..d5c843c 100644
--- a/src/string/memrchr.cpp
+++ b/src/string/memrchr.cpp
@@ -9,11 +9,16 @@
 #include "src/string/memrchr.h"
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include <stddef.h>
 
 namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(void *, memrchr, (const void *src, int c, size_t n)) {
+
+  if (n)
+    LIBC_CRASH_ON_NULLPTR(src);
+
   const unsigned char *str = reinterpret_cast<const unsigned char *>(src);
   const unsigned char ch = static_cast<unsigned char>(c);
   for (; n != 0; --n) {
diff --git a/src/string/memset.cpp b/src/string/memset.cpp
index c2868af..a0b96b3 100644
--- a/src/string/memset.cpp
+++ b/src/string/memset.cpp
@@ -9,11 +9,15 @@
 #include "src/string/memset.h"
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_memset.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(void *, memset, (void *dst, int value, size_t count)) {
+  if (count)
+    LIBC_CRASH_ON_NULLPTR(dst);
+
   inline_memset(dst, static_cast<uint8_t>(value), count);
   return dst;
 }
diff --git a/src/string/stpncpy.cpp b/src/string/stpncpy.cpp
index d2a6e04..47bf4c6 100644
--- a/src/string/stpncpy.cpp
+++ b/src/string/stpncpy.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/stpncpy.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_bzero.h"
 
 #include "src/__support/common.h"
@@ -17,6 +18,10 @@ namespace LIBC_NAMESPACE_DECL {
 LLVM_LIBC_FUNCTION(char *, stpncpy,
                    (char *__restrict dest, const char *__restrict src,
                     size_t n)) {
+  if (n) {
+    LIBC_CRASH_ON_NULLPTR(dest);
+    LIBC_CRASH_ON_NULLPTR(src);
+  }
   size_t i;
   // Copy up until \0 is found.
   for (i = 0; i < n && src[i] != '\0'; ++i)
diff --git a/src/string/strcasestr.cpp b/src/string/strcasestr.cpp
index 1da1e3f..de8e4be 100644
--- a/src/string/strcasestr.cpp
+++ b/src/string/strcasestr.cpp
@@ -11,6 +11,7 @@
 #include "src/__support/common.h"
 #include "src/__support/ctype_utils.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_strstr.h"
 
 namespace LIBC_NAMESPACE_DECL {
@@ -23,6 +24,9 @@ LLVM_LIBC_FUNCTION(char *, strcasestr,
     return LIBC_NAMESPACE::internal::tolower(a) -
            LIBC_NAMESPACE::internal::tolower(b);
   };
+
+  LIBC_CRASH_ON_NULLPTR(haystack);
+  LIBC_CRASH_ON_NULLPTR(needle);
   return inline_strstr(haystack, needle, case_cmp);
 }
 
diff --git a/src/string/strcat.cpp b/src/string/strcat.cpp
index 0eb189c..6a6f068 100644
--- a/src/string/strcat.cpp
+++ b/src/string/strcat.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/strcat.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/strcpy.h"
 #include "src/string/string_utils.h"
 
@@ -17,6 +18,8 @@ namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(char *, strcat,
                    (char *__restrict dest, const char *__restrict src)) {
+  LIBC_CRASH_ON_NULLPTR(dest);
+  LIBC_CRASH_ON_NULLPTR(src);
   size_t dest_length = internal::string_length(dest);
   size_t src_length = internal::string_length(src);
   LIBC_NAMESPACE::strcpy(dest + dest_length, src);
diff --git a/src/string/strcoll.cpp b/src/string/strcoll.cpp
index eeb2c79..aa08f71 100644
--- a/src/string/strcoll.cpp
+++ b/src/string/strcoll.cpp
@@ -10,11 +10,14 @@
 
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
 // TODO: Add support for locales.
 LLVM_LIBC_FUNCTION(int, strcoll, (const char *left, const char *right)) {
+  LIBC_CRASH_ON_NULLPTR(left);
+  LIBC_CRASH_ON_NULLPTR(right);
   for (; *left && *left == *right; ++left, ++right)
     ;
   return static_cast<int>(*left) - static_cast<int>(*right);
diff --git a/src/string/strcoll_l.cpp b/src/string/strcoll_l.cpp
index f664a3c..e820efa 100644
--- a/src/string/strcoll_l.cpp
+++ b/src/string/strcoll_l.cpp
@@ -10,12 +10,15 @@
 
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
 // TODO: Add support for locales.
 LLVM_LIBC_FUNCTION(int, strcoll_l,
                    (const char *left, const char *right, locale_t)) {
+  LIBC_CRASH_ON_NULLPTR(left);
+  LIBC_CRASH_ON_NULLPTR(right);
   for (; *left && *left == *right; ++left, ++right)
     ;
   return static_cast<int>(*left) - static_cast<int>(*right);
diff --git a/src/string/strcpy.cpp b/src/string/strcpy.cpp
index 60b73ab..2013593 100644
--- a/src/string/strcpy.cpp
+++ b/src/string/strcpy.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/strcpy.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_memcpy.h"
 #include "src/string/string_utils.h"
 
@@ -17,6 +18,7 @@ namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(char *, strcpy,
                    (char *__restrict dest, const char *__restrict src)) {
+  LIBC_CRASH_ON_NULLPTR(dest);
   size_t size = internal::string_length(src) + 1;
   inline_memcpy(dest, src, size);
   return dest;
diff --git a/src/string/string_utils.h b/src/string/string_utils.h
index e4659f6..dcbfc75 100644
--- a/src/string/string_utils.h
+++ b/src/string/string_utils.h
@@ -14,19 +14,19 @@
 #ifndef LLVM_LIBC_SRC_STRING_STRING_UTILS_H
 #define LLVM_LIBC_SRC_STRING_STRING_UTILS_H
 
+#include "hdr/limits_macros.h"
 #include "hdr/types/size_t.h"
 #include "src/__support/CPP/bitset.h"
 #include "src/__support/CPP/type_traits.h" // cpp::is_same_v
 #include "src/__support/macros/config.h"
 #include "src/__support/macros/optimization.h" // LIBC_UNLIKELY
-#include "src/string/memory_utils/inline_bzero.h"
-#include "src/string/memory_utils/inline_memcpy.h"
 
 namespace LIBC_NAMESPACE_DECL {
 namespace internal {
 
 template <typename Word> LIBC_INLINE constexpr Word repeat_byte(Word byte) {
-  constexpr size_t BITS_IN_BYTE = 8;
+  static_assert(CHAR_BIT == 8, "repeat_byte assumes a byte is 8 bits.");
+  constexpr size_t BITS_IN_BYTE = CHAR_BIT;
   constexpr size_t BYTE_MASK = 0xff;
   Word result = 0;
   byte = byte & BYTE_MASK;
@@ -189,8 +189,7 @@ LIBC_INLINE char *string_token(char *__restrict src,
   if (LIBC_UNLIKELY(src == nullptr && ((src = *saveptr) == nullptr)))
     return nullptr;
 
-  static_assert(sizeof(char) == sizeof(cpp::byte),
-                "bitset of 256 assumes char is 8 bits");
+  static_assert(CHAR_BIT == 8, "bitset of 256 assumes char is 8 bits");
   cpp::bitset<256> delimiter_set;
   for (; *delimiter_string != '\0'; ++delimiter_string)
     delimiter_set.set(static_cast<size_t>(*delimiter_string));
@@ -220,7 +219,7 @@ LIBC_INLINE size_t strlcpy(char *__restrict dst, const char *__restrict src,
   if (!size)
     return len;
   size_t n = len < size - 1 ? len : size - 1;
-  inline_memcpy(dst, src, n);
+  __builtin_memcpy(dst, src, n);
   dst[n] = '\0';
   return len;
 }
diff --git a/src/string/strlen.cpp b/src/string/strlen.cpp
index ff7ab14..234edb8 100644
--- a/src/string/strlen.cpp
+++ b/src/string/strlen.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/strlen.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/string_utils.h"
 
 #include "src/__support/common.h"
@@ -17,6 +18,7 @@ namespace LIBC_NAMESPACE_DECL {
 // TODO: investigate the performance of this function.
 // There might be potential for compiler optimization.
 LLVM_LIBC_FUNCTION(size_t, strlen, (const char *src)) {
+  LIBC_CRASH_ON_NULLPTR(src);
   return internal::string_length(src);
 }
 
diff --git a/src/string/strncat.cpp b/src/string/strncat.cpp
index 221881f..4926b7d 100644
--- a/src/string/strncat.cpp
+++ b/src/string/strncat.cpp
@@ -8,6 +8,7 @@
 
 #include "src/string/strncat.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/string_utils.h"
 #include "src/string/strncpy.h"
 
@@ -18,6 +19,10 @@ namespace LIBC_NAMESPACE_DECL {
 LLVM_LIBC_FUNCTION(char *, strncat,
                    (char *__restrict dest, const char *__restrict src,
                     size_t count)) {
+  if (count) {
+    LIBC_CRASH_ON_NULLPTR(dest);
+    LIBC_CRASH_ON_NULLPTR(src);
+  }
   size_t src_length = internal::string_length(src);
   size_t copy_amount = src_length > count ? count : src_length;
   size_t dest_length = internal::string_length(dest);
diff --git a/src/string/strncmp.cpp b/src/string/strncmp.cpp
index 16d4601..f21fd76 100644
--- a/src/string/strncmp.cpp
+++ b/src/string/strncmp.cpp
@@ -10,6 +10,7 @@
 
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_strcmp.h"
 
 #include <stddef.h>
@@ -18,6 +19,10 @@ namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(int, strncmp,
                    (const char *left, const char *right, size_t n)) {
+  if (n) {
+    LIBC_CRASH_ON_NULLPTR(left);
+    LIBC_CRASH_ON_NULLPTR(right);
+  }
   auto comp = [](char l, char r) -> int { return l - r; };
   return inline_strncmp(left, right, n, comp);
 }
diff --git a/src/string/strncpy.cpp b/src/string/strncpy.cpp
index 4976ad9..e271009 100644
--- a/src/string/strncpy.cpp
+++ b/src/string/strncpy.cpp
@@ -10,6 +10,7 @@
 
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include <stddef.h> // For size_t.
 
 namespace LIBC_NAMESPACE_DECL {
@@ -17,6 +18,10 @@ namespace LIBC_NAMESPACE_DECL {
 LLVM_LIBC_FUNCTION(char *, strncpy,
                    (char *__restrict dest, const char *__restrict src,
                     size_t n)) {
+  if (n) {
+    LIBC_CRASH_ON_NULLPTR(dest);
+    LIBC_CRASH_ON_NULLPTR(src);
+  }
   size_t i = 0;
   // Copy up until \0 is found.
   for (; i < n && src[i] != '\0'; ++i)
diff --git a/src/string/strsep.cpp b/src/string/strsep.cpp
index 4c27512..41874b6 100644
--- a/src/string/strsep.cpp
+++ b/src/string/strsep.cpp
@@ -9,14 +9,19 @@
 #include "src/string/strsep.h"
 
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/string_utils.h"
 
+#include "src/__support/common.h"
+
 namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(char *, strsep,
                    (char **__restrict stringp, const char *__restrict delim)) {
+  LIBC_CRASH_ON_NULLPTR(stringp);
   if (!*stringp)
     return nullptr;
+  LIBC_CRASH_ON_NULLPTR(delim);
   return internal::string_token<false>(*stringp, delim, stringp);
 }
 
diff --git a/src/string/strspn.cpp b/src/string/strspn.cpp
index 66bb399..b205bed 100644
--- a/src/string/strspn.cpp
+++ b/src/string/strspn.cpp
@@ -11,11 +11,14 @@
 #include "src/__support/CPP/bitset.h"
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include <stddef.h>
 
 namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(size_t, strspn, (const char *src, const char *segment)) {
+  LIBC_CRASH_ON_NULLPTR(src);
+  LIBC_CRASH_ON_NULLPTR(segment);
   const char *initial = src;
   cpp::bitset<256> bitset;
 
diff --git a/src/string/strstr.cpp b/src/string/strstr.cpp
index 5132f06..44797ef 100644
--- a/src/string/strstr.cpp
+++ b/src/string/strstr.cpp
@@ -10,6 +10,7 @@
 
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/memory_utils/inline_strstr.h"
 
 namespace LIBC_NAMESPACE_DECL {
@@ -18,6 +19,8 @@ namespace LIBC_NAMESPACE_DECL {
 // improved upon using well known string matching algorithms.
 LLVM_LIBC_FUNCTION(char *, strstr, (const char *haystack, const char *needle)) {
   auto comp = [](char l, char r) -> int { return l - r; };
+  LIBC_CRASH_ON_NULLPTR(haystack);
+  LIBC_CRASH_ON_NULLPTR(needle);
   return inline_strstr(haystack, needle, comp);
 }
 
diff --git a/src/strings/rindex.cpp b/src/strings/rindex.cpp
index 1242e0f..2540222 100644
--- a/src/strings/rindex.cpp
+++ b/src/strings/rindex.cpp
@@ -10,11 +10,13 @@
 
 #include "src/__support/common.h"
 #include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
 #include "src/string/string_utils.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(char *, rindex, (const char *src, int c)) {
+  LIBC_CRASH_ON_NULLPTR(src);
   return internal::strrchr_implementation(src, c);
 }
 
diff --git a/src/sys/stat/linux/chmod.cpp b/src/sys/stat/linux/chmod.cpp
index 57d5bae..1b787e4 100644
--- a/src/sys/stat/linux/chmod.cpp
+++ b/src/sys/stat/linux/chmod.cpp
@@ -23,12 +23,12 @@ namespace LIBC_NAMESPACE_DECL {
 LLVM_LIBC_FUNCTION(int, chmod, (const char *path, mode_t mode)) {
 #ifdef SYS_chmod
   int ret = LIBC_NAMESPACE::syscall_impl<int>(SYS_chmod, path, mode);
-#elif defined(SYS_fchmodat2)
-  int ret = LIBC_NAMESPACE::syscall_impl<int>(SYS_fchmodat2, AT_FDCWD, path,
-                                              mode, 0, AT_SYMLINK_NOFOLLOW);
 #elif defined(SYS_fchmodat)
   int ret =
       LIBC_NAMESPACE::syscall_impl<int>(SYS_fchmodat, AT_FDCWD, path, mode, 0);
+#elif defined(SYS_fchmodat2)
+  int ret = LIBC_NAMESPACE::syscall_impl<int>(SYS_fchmodat2, AT_FDCWD, path,
+                                              mode, 0, AT_SYMLINK_NOFOLLOW);
 #else
 #error "chmod, fchmodat and fchmodat2 syscalls not available."
 #endif
diff --git a/src/sys/time/getitimer.h b/src/sys/time/getitimer.h
new file mode 100644
index 0000000..e19dfd1
--- /dev/null
+++ b/src/sys/time/getitimer.h
@@ -0,0 +1,19 @@
+//===-- Implementation header for getitimer -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_SYS_TIME_GETITIMER_H
+#define LLVM_LIBC_SRC_SYS_TIME_GETITIMER_H
+
+#include "hdr/types/struct_itimerval.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+int getitimer(int which, struct itimerval *curr_value);
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_SYS_TIME_GETITIMER_H
diff --git a/src/sys/time/linux/getitimer.cpp b/src/sys/time/linux/getitimer.cpp
new file mode 100644
index 0000000..fec06aa
--- /dev/null
+++ b/src/sys/time/linux/getitimer.cpp
@@ -0,0 +1,43 @@
+//===-- Implementation file for getitimer ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/sys/time/getitimer.h"
+#include "hdr/types/struct_itimerval.h"
+#include "src/__support/OSUtil/syscall.h"
+#include "src/__support/common.h"
+#include "src/errno/libc_errno.h"
+#include <sys/syscall.h>
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(int, getitimer, (int which, struct itimerval *curr_value)) {
+  long ret = 0;
+  if constexpr (sizeof(time_t) > sizeof(long)) {
+    // There is no SYS_getitimer_time64 call, so we can't use time_t directly.
+    long curr_value32[4];
+    ret =
+        LIBC_NAMESPACE::syscall_impl<long>(SYS_getitimer, which, curr_value32);
+    if (!ret) {
+      curr_value->it_interval.tv_sec = curr_value32[0];
+      curr_value->it_interval.tv_usec = curr_value32[1];
+      curr_value->it_value.tv_sec = curr_value32[2];
+      curr_value->it_value.tv_usec = curr_value32[3];
+    }
+  } else {
+    ret = LIBC_NAMESPACE::syscall_impl<long>(SYS_getitimer, which, curr_value);
+  }
+
+  // On failure, return -1 and set errno.
+  if (ret < 0) {
+    libc_errno = static_cast<int>(-ret);
+    return -1;
+  }
+  return 0;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/sys/time/linux/setitimer.cpp b/src/sys/time/linux/setitimer.cpp
new file mode 100644
index 0000000..def04a4
--- /dev/null
+++ b/src/sys/time/linux/setitimer.cpp
@@ -0,0 +1,52 @@
+//===-- Implementation file for setitimer ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+#include "src/sys/time/setitimer.h"
+#include "hdr/types/struct_itimerval.h"
+#include "src/__support/OSUtil/syscall.h"
+#include "src/__support/common.h"
+#include "src/errno/libc_errno.h"
+#include <sys/syscall.h>
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(int, setitimer,
+                   (int which, const struct itimerval *new_value,
+                    struct itimerval *old_value)) {
+  long ret = 0;
+  if constexpr (sizeof(time_t) > sizeof(long)) {
+    // There is no SYS_setitimer_time64 call, so we can't use time_t directly,
+    // and need to convert it to long first.
+    long new_value32[4] = {static_cast<long>(new_value->it_interval.tv_sec),
+                           new_value->it_interval.tv_usec,
+                           static_cast<long>(new_value->it_value.tv_sec),
+                           new_value->it_value.tv_usec};
+    long old_value32[4];
+
+    ret = LIBC_NAMESPACE::syscall_impl<long>(SYS_setitimer, which, new_value32,
+                                             old_value32);
+
+    if (!ret && old_value) {
+      old_value->it_interval.tv_sec = old_value32[0];
+      old_value->it_interval.tv_usec = old_value32[1];
+      old_value->it_value.tv_sec = old_value32[2];
+      old_value->it_value.tv_usec = old_value32[3];
+    }
+  } else {
+    ret = LIBC_NAMESPACE::syscall_impl<long>(SYS_setitimer, which, new_value,
+                                             old_value);
+  }
+
+  // On failure, return -1 and set errno.
+  if (ret < 0) {
+    libc_errno = static_cast<int>(-ret);
+    return -1;
+  }
+  return 0;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/sys/time/linux/utimes.cpp b/src/sys/time/linux/utimes.cpp
new file mode 100644
index 0000000..76b6993
--- /dev/null
+++ b/src/sys/time/linux/utimes.cpp
@@ -0,0 +1,84 @@
+//===-- Linux implementation of utimes ------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/sys/time/utimes.h"
+
+#include "hdr/fcntl_macros.h"
+#include "hdr/types/struct_timespec.h"
+#include "hdr/types/struct_timeval.h"
+
+#include "src/__support/OSUtil/syscall.h"
+#include "src/__support/common.h"
+
+#include "src/errno/libc_errno.h"
+
+#include <sys/syscall.h>
+
+namespace LIBC_NAMESPACE_DECL {
+
+#ifdef SYS_utimes
+constexpr auto UTIMES_SYSCALL_ID = SYS_utimes;
+#elif defined(SYS_utimensat)
+constexpr auto UTIMES_SYSCALL_ID = SYS_utimensat;
+#elif defined(SYS_utimensat_time64)
+constexpr auto UTIMES_SYSCALL_ID = SYS_utimensat_time64;
+#else
+#error "utimes, utimensat, utimensat_time64,  syscalls not available."
+#endif
+
+LLVM_LIBC_FUNCTION(int, utimes,
+                   (const char *path, const struct timeval times[2])) {
+  int ret;
+
+#ifdef SYS_utimes
+  // No need to define a timespec struct, use the syscall directly.
+  ret = LIBC_NAMESPACE::syscall_impl<int>(UTIMES_SYSCALL_ID, path, times);
+#elif defined(SYS_utimensat) || defined(SYS_utimensat_time64)
+  // the utimensat syscall requires a timespec struct, not timeval.
+  struct timespec ts[2];
+  struct timespec *ts_ptr = nullptr; // default value if times is nullptr
+
+  // convert the microsec values in timeval struct times
+  // to nanosecond values in timespec struct ts
+  if (times != nullptr) {
+
+    // ensure consistent values
+    if ((times[0].tv_usec < 0 || times[1].tv_usec < 0) ||
+        (times[0].tv_usec >= 1000000 || times[1].tv_usec >= 1000000)) {
+      libc_errno = EINVAL;
+      return -1;
+    }
+
+    // set seconds in ts
+    ts[0].tv_sec = times[0].tv_sec;
+    ts[1].tv_sec = times[1].tv_sec;
+
+    // convert u-seconds to nanoseconds
+    ts[0].tv_nsec = times[0].tv_usec * 1000;
+    ts[1].tv_nsec = times[1].tv_usec * 1000;
+
+    ts_ptr = ts;
+  }
+
+  // If times was nullptr, ts_ptr remains nullptr, which utimensat interprets
+  // as setting times to the current time.
+
+  // utimensat syscall.
+  // flags=0 means don't follow symlinks (like utimes)
+  ret = LIBC_NAMESPACE::syscall_impl<int>(UTIMES_SYSCALL_ID, AT_FDCWD, path,
+                                          ts_ptr, 0);
+#endif // SYS_utimensat
+
+  if (ret < 0) {
+    libc_errno = -ret;
+    return -1;
+  }
+
+  return 0;
+}
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/sys/time/setitimer.h b/src/sys/time/setitimer.h
new file mode 100644
index 0000000..9daf8a7
--- /dev/null
+++ b/src/sys/time/setitimer.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for setitimer -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_SYS_TIME_SETITIMER_H
+#define LLVM_LIBC_SRC_SYS_TIME_SETITIMER_H
+
+#include "hdr/types/struct_itimerval.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+int setitimer(int which, const struct itimerval *new_value,
+              struct itimerval *old_value);
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_SYS_TIME_SETITIMER_H
diff --git a/src/math/amdgpu/logb.cpp b/src/sys/time/utimes.h
similarity index 61%
rename from src/math/amdgpu/logb.cpp
rename to src/sys/time/utimes.h
index 4b68e28..6e19e41 100644
--- a/src/math/amdgpu/logb.cpp
+++ b/src/sys/time/utimes.h
@@ -1,4 +1,4 @@
-//===-- Implementation of the GPU logb function ---------------------------===//
+//===-- Implementation header for utimes ----------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,14 +6,16 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/logb.h"
-#include "src/__support/common.h"
+#ifndef LLVM_LIBC_SRC_SYS_TIME_UTIMES_H
+#define LLVM_LIBC_SRC_SYS_TIME_UTIMES_H
 
-#include "declarations.h"
+#include "hdr/types/struct_timeval.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, logb, (double x)) { return __ocml_logb_f64(x); }
+int utimes(const char *path, const struct timeval times[2]);
 
 } // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_SYS_TIME_UTIMES_H
diff --git a/src/time/mktime.cpp b/src/time/mktime.cpp
index fc05ff2..8165239 100644
--- a/src/time/mktime.cpp
+++ b/src/time/mktime.cpp
@@ -15,13 +15,17 @@
 namespace LIBC_NAMESPACE_DECL {
 
 LLVM_LIBC_FUNCTION(time_t, mktime, (struct tm * tm_out)) {
-  int64_t seconds = time_utils::mktime_internal(tm_out);
+  auto mktime_result = time_utils::mktime_internal(tm_out);
+  if (!mktime_result)
+    return time_utils::out_of_range();
+
+  time_t seconds = *mktime_result;
 
   // Update the tm structure's year, month, day, etc. from seconds.
   if (time_utils::update_from_seconds(seconds, tm_out) < 0)
     return time_utils::out_of_range();
 
-  return static_cast<time_t>(seconds);
+  return seconds;
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/time/time_utils.cpp b/src/time/time_utils.cpp
index 3ccb2dd..1c519c3 100644
--- a/src/time/time_utils.cpp
+++ b/src/time/time_utils.cpp
@@ -18,7 +18,7 @@ namespace LIBC_NAMESPACE_DECL {
 namespace time_utils {
 
 // TODO: clean this up in a followup patch
-int64_t mktime_internal(const tm *tm_out) {
+cpp::optional<time_t> mktime_internal(const tm *tm_out) {
   // Unlike most C Library functions, mktime doesn't just die on bad input.
   // TODO(rtenneti); Handle leap seconds.
   int64_t tm_year_from_base = tm_out->tm_year + time_constants::TIME_YEAR_BASE;
@@ -27,20 +27,20 @@ int64_t mktime_internal(const tm *tm_out) {
   if (sizeof(time_t) == 4 &&
       tm_year_from_base >= time_constants::END_OF32_BIT_EPOCH_YEAR) {
     if (tm_year_from_base > time_constants::END_OF32_BIT_EPOCH_YEAR)
-      return time_utils::out_of_range();
+      return cpp::nullopt;
     if (tm_out->tm_mon > 0)
-      return time_utils::out_of_range();
+      return cpp::nullopt;
     if (tm_out->tm_mday > 19)
-      return time_utils::out_of_range();
+      return cpp::nullopt;
     else if (tm_out->tm_mday == 19) {
       if (tm_out->tm_hour > 3)
-        return time_utils::out_of_range();
+        return cpp::nullopt;
       else if (tm_out->tm_hour == 3) {
         if (tm_out->tm_min > 14)
-          return time_utils::out_of_range();
+          return cpp::nullopt;
         else if (tm_out->tm_min == 14) {
           if (tm_out->tm_sec > 7)
-            return time_utils::out_of_range();
+            return cpp::nullopt;
         }
       }
     }
@@ -102,10 +102,10 @@ int64_t mktime_internal(const tm *tm_out) {
 
   // TODO: https://github.com/llvm/llvm-project/issues/121962
   // Need to handle timezone and update of tm_isdst.
-  int64_t seconds = tm_out->tm_sec +
-                    tm_out->tm_min * time_constants::SECONDS_PER_MIN +
-                    tm_out->tm_hour * time_constants::SECONDS_PER_HOUR +
-                    total_days * time_constants::SECONDS_PER_DAY;
+  time_t seconds = static_cast<time_t>(
+      tm_out->tm_sec + tm_out->tm_min * time_constants::SECONDS_PER_MIN +
+      tm_out->tm_hour * time_constants::SECONDS_PER_HOUR +
+      total_days * time_constants::SECONDS_PER_DAY);
   return seconds;
 }
 
@@ -136,7 +136,7 @@ static int64_t computeRemainingYears(int64_t daysPerYears,
 //
 // Compute the number of months from the remaining days. Finally, adjust years
 // to be 1900 and months to be from January.
-int64_t update_from_seconds(int64_t total_seconds, tm *tm) {
+int64_t update_from_seconds(time_t total_seconds, tm *tm) {
   // Days in month starting from March in the year 2000.
   static const char daysInMonth[] = {31 /* Mar */, 30, 31, 30, 31, 31,
                                      30,           31, 30, 31, 31, 29};
@@ -152,8 +152,7 @@ int64_t update_from_seconds(int64_t total_seconds, tm *tm) {
           : INT_MAX * static_cast<int64_t>(
                           time_constants::NUMBER_OF_SECONDS_IN_LEAP_YEAR);
 
-  time_t ts = static_cast<time_t>(total_seconds);
-  if (ts < time_min || ts > time_max)
+  if (total_seconds < time_min || total_seconds > time_max)
     return time_utils::out_of_range();
 
   int64_t seconds =
diff --git a/src/time/time_utils.h b/src/time/time_utils.h
index 68eaac8..bbbb1c0 100644
--- a/src/time/time_utils.h
+++ b/src/time/time_utils.h
@@ -26,11 +26,11 @@ namespace time_utils {
 
 // calculates the seconds from the epoch for tm_in. Does not update the struct,
 // you must call update_from_seconds for that.
-int64_t mktime_internal(const tm *tm_out);
+cpp::optional<time_t> mktime_internal(const tm *tm_out);
 
 // Update the "tm" structure's year, month, etc. members from seconds.
 // "total_seconds" is the number of seconds since January 1st, 1970.
-int64_t update_from_seconds(int64_t total_seconds, tm *tm);
+int64_t update_from_seconds(time_t total_seconds, tm *tm);
 
 // TODO(michaelrj): move these functions to use ErrorOr instead of setting
 // errno. They always accompany a specific return value so we only need the one
@@ -84,7 +84,7 @@ LIBC_INLINE char *asctime(const tm *timeptr, char *buffer,
 }
 
 LIBC_INLINE tm *gmtime_internal(const time_t *timer, tm *result) {
-  int64_t seconds = *timer;
+  time_t seconds = *timer;
   // Update the tm structure's year, month, day, etc. from seconds.
   if (update_from_seconds(seconds, result) < 0) {
     out_of_range();
@@ -329,7 +329,8 @@ public:
   }
 
   LIBC_INLINE time_t get_epoch() const {
-    return static_cast<time_t>(mktime_internal(timeptr));
+    auto seconds = mktime_internal(timeptr);
+    return seconds ? *seconds : time_utils::out_of_range();
   }
 
   // returns the timezone offset in microwave time:
diff --git a/src/wchar/wcscat.cpp b/src/wchar/wcscat.cpp
new file mode 100644
index 0000000..50d90c0
--- /dev/null
+++ b/src/wchar/wcscat.cpp
@@ -0,0 +1,29 @@
+//===-- Implementation of wcscat ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcscat.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/string/string_utils.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(wchar_t *, wcscat,
+                   (wchar_t *__restrict s1, const wchar_t *__restrict s2)) {
+  size_t size_1 = internal::string_length(s1);
+  size_t i = 0;
+  for (; s2[i] != L'\0'; i++)
+    s1[size_1 + i] = s2[i];
+  s1[size_1 + i] = L'\0';
+  return s1;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/acosh.cpp b/src/wchar/wcscat.h
similarity index 59%
rename from src/math/amdgpu/acosh.cpp
rename to src/wchar/wcscat.h
index 15c9734..b0b4455 100644
--- a/src/math/amdgpu/acosh.cpp
+++ b/src/wchar/wcscat.h
@@ -1,4 +1,4 @@
-//===-- Implementation of the GPU acosh function --------------------------===//
+//===-- Implementation header for wcscat ----------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,14 +6,16 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/acosh.h"
-#include "src/__support/common.h"
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSCAT_H
+#define LLVM_LIBC_SRC_WCHAR_WCSCAT_H
 
-#include "declarations.h"
+#include "hdr/types/wchar_t.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, acosh, (double x)) { return __ocml_acosh_f64(x); }
+wchar_t *wcscat(wchar_t *__restrict s1, const wchar_t *__restrict s2);
 
 } // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSCAT_H
diff --git a/src/math/amdgpu/atan2f.cpp b/src/wchar/wcschr.cpp
similarity index 61%
rename from src/math/amdgpu/atan2f.cpp
rename to src/wchar/wcschr.cpp
index 736c77d..defc2ce 100644
--- a/src/math/amdgpu/atan2f.cpp
+++ b/src/wchar/wcschr.cpp
@@ -1,4 +1,4 @@
-//===-- Implementation of the GPU atan2f function -------------------------===//
+//===-- Implementation of wcschr ------------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,16 +6,20 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/atan2f.h"
-#include "src/__support/common.h"
+#include "src/wchar/wcschr.h"
 
-#include "declarations.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(float, atan2f, (float x, float y)) {
-  return __ocml_atan2_f32(x, y);
+LLVM_LIBC_FUNCTION(const wchar_t *, wcschr, (const wchar_t *s, wchar_t c)) {
+  for (; *s && *s != c; ++s)
+    ;
+  if (*s == c)
+    return s;
+  return nullptr;
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/acoshf.cpp b/src/wchar/wcschr.h
similarity index 61%
rename from src/math/amdgpu/acoshf.cpp
rename to src/wchar/wcschr.h
index 79e71b0..70bf283 100644
--- a/src/math/amdgpu/acoshf.cpp
+++ b/src/wchar/wcschr.h
@@ -1,4 +1,4 @@
-//===-- Implementation of the acoshf function for GPU ---------------------===//
+//===-- Implementation header for wcschr ----------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,14 +6,16 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/acoshf.h"
-#include "src/__support/common.h"
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSCHR_H
+#define LLVM_LIBC_SRC_WCHAR_WCSCHR_H
 
-#include "declarations.h"
+#include "hdr/types/wchar_t.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(float, acoshf, (float x)) { return __ocml_acosh_f32(x); }
+const wchar_t *wcschr(const wchar_t *s, wchar_t c);
 
 } // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSCHR_H
diff --git a/src/wchar/wcscmp.cpp b/src/wchar/wcscmp.cpp
new file mode 100644
index 0000000..f285efd
--- /dev/null
+++ b/src/wchar/wcscmp.cpp
@@ -0,0 +1,30 @@
+//===-- Implementation of wcscmp ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcscmp.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/null_check.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(int, wcscmp, (const wchar_t *left, const wchar_t *right)) {
+  LIBC_CRASH_ON_NULLPTR(left);
+  LIBC_CRASH_ON_NULLPTR(right);
+
+  auto comp = [](wchar_t l, wchar_t r) -> int { return l - r; };
+
+  for (; *left && !comp(*left, *right); ++left, ++right)
+    ;
+
+  return comp(*left, *right);
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wcscmp.h b/src/wchar/wcscmp.h
new file mode 100644
index 0000000..af82d06
--- /dev/null
+++ b/src/wchar/wcscmp.h
@@ -0,0 +1,22 @@
+//===-- Implementation header for wcscmp ----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSCMP_H
+#define LLVM_LIBC_SRC_WCHAR_WCSCMP_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+int wcscmp(const wchar_t *left, const wchar_t *right);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSCMP_H
diff --git a/src/wchar/wcscpy.cpp b/src/wchar/wcscpy.cpp
new file mode 100644
index 0000000..dc46b97
--- /dev/null
+++ b/src/wchar/wcscpy.cpp
@@ -0,0 +1,27 @@
+//===-- Implementation of wcscpy ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcscpy.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/string/memory_utils/inline_memcpy.h"
+#include "src/string/string_utils.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(wchar_t *, wcscpy,
+                   (wchar_t *__restrict s1, const wchar_t *__restrict s2)) {
+  size_t size = internal::string_length(s2) + 1;
+  inline_memcpy(s1, s2, size * sizeof(wchar_t));
+  return s1;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wcscpy.h b/src/wchar/wcscpy.h
new file mode 100644
index 0000000..c3f0e5f
--- /dev/null
+++ b/src/wchar/wcscpy.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for wcscpy ----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSCPY_H
+#define LLVM_LIBC_SRC_WCHAR_WCSCPY_H
+
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+wchar_t *wcscpy(wchar_t *__restrict s1, const wchar_t *__restrict s2);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSCPY_H
diff --git a/src/wchar/wcsncat.cpp b/src/wchar/wcsncat.cpp
new file mode 100644
index 0000000..62595b4
--- /dev/null
+++ b/src/wchar/wcsncat.cpp
@@ -0,0 +1,31 @@
+//===-- Implementation of wcsncat -----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcsncat.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/string/string_utils.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(wchar_t *, wcsncat,
+                   (wchar_t *__restrict s1, const wchar_t *__restrict s2,
+                    size_t n)) {
+  size_t size = internal::string_length(s1);
+  size_t i = 0;
+  for (; s2[i] && i < n; ++i)
+    s1[size + i] = s2[i];
+  // Appending null character to the end of the result.
+  s1[size + i] = L'\0';
+  return s1;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wcsncat.h b/src/wchar/wcsncat.h
new file mode 100644
index 0000000..978645e
--- /dev/null
+++ b/src/wchar/wcsncat.h
@@ -0,0 +1,23 @@
+//===-- Implementation header for wcsncat ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSNCAT_H
+#define LLVM_LIBC_SRC_WCHAR_WCSNCAT_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+wchar_t *wcsncat(wchar_t *__restrict s1, const wchar_t *__restrict s2,
+                 size_t n);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSNCAT_H
diff --git a/src/wchar/wcsncmp.cpp b/src/wchar/wcsncmp.cpp
new file mode 100644
index 0000000..f2e052b
--- /dev/null
+++ b/src/wchar/wcsncmp.cpp
@@ -0,0 +1,37 @@
+//===-- Implementation of wcsncmp -----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcsncmp.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/null_check.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(int, wcsncmp,
+                   (const wchar_t *left, const wchar_t *right, size_t n)) {
+  LIBC_CRASH_ON_NULLPTR(left);
+  LIBC_CRASH_ON_NULLPTR(right);
+
+  if (n == 0)
+    return 0;
+
+  auto comp = [](wchar_t l, wchar_t r) -> int { return l - r; };
+
+  for (; n > 1; --n, ++left, ++right) {
+    wchar_t lc = *left;
+    if (!comp(lc, '\0') || comp(lc, *right))
+      break;
+  }
+  return comp(*reinterpret_cast<const wchar_t *>(left),
+              *reinterpret_cast<const wchar_t *>(right));
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wcsncmp.h b/src/wchar/wcsncmp.h
new file mode 100644
index 0000000..0b4187e
--- /dev/null
+++ b/src/wchar/wcsncmp.h
@@ -0,0 +1,22 @@
+//===-- Implementation header for wcsncmp ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSNCMP_H
+#define LLVM_LIBC_SRC_WCHAR_WCSNCMP_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+int wcsncmp(const wchar_t *left, const wchar_t *right, size_t n);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSNCMP_H
diff --git a/src/wchar/wcsncpy.cpp b/src/wchar/wcsncpy.cpp
new file mode 100644
index 0000000..e7ae9a4
--- /dev/null
+++ b/src/wchar/wcsncpy.cpp
@@ -0,0 +1,33 @@
+//===-- Implementation of wcsncpy -----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcsncpy.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/string/memory_utils/inline_memcpy.h"
+#include "src/string/string_utils.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(wchar_t *, wcsncpy,
+                   (wchar_t *__restrict s1, const wchar_t *__restrict s2,
+                    size_t n)) {
+  size_t i = 0;
+  // Copy up until \0 is found.
+  for (; i < n && s2[i] != L'\0'; ++i)
+    s1[i] = s2[i];
+  // When s2 is shorter than n, append \0.
+  for (; i < n; ++i)
+    s1[i] = L'\0';
+  return s1;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wcsncpy.h b/src/wchar/wcsncpy.h
new file mode 100644
index 0000000..06c23f2
--- /dev/null
+++ b/src/wchar/wcsncpy.h
@@ -0,0 +1,23 @@
+//===-- Implementation header for wcsncpy ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSNCPY_H
+#define LLVM_LIBC_SRC_WCHAR_WCSNCPY_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+wchar_t *wcsncpy(wchar_t *__restrict s1, const wchar_t *__restrict s2,
+                 size_t n);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSNCPY_H
diff --git a/src/wchar/wcspbrk.cpp b/src/wchar/wcspbrk.cpp
new file mode 100644
index 0000000..a00ba99
--- /dev/null
+++ b/src/wchar/wcspbrk.cpp
@@ -0,0 +1,38 @@
+//===-- Implementation of wcspbrk -----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcspbrk.h"
+
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/null_check.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+bool contains_char(const wchar_t *str, wchar_t target) {
+  for (; *str != L'\0'; str++)
+    if (*str == target)
+      return true;
+
+  return false;
+}
+
+LLVM_LIBC_FUNCTION(const wchar_t *, wcspbrk,
+                   (const wchar_t *src, const wchar_t *breakset)) {
+  LIBC_CRASH_ON_NULLPTR(src);
+  LIBC_CRASH_ON_NULLPTR(breakset);
+
+  // currently O(n * m), can be further optimized to O(n + m) with a hash set
+  for (int src_idx = 0; src[src_idx] != 0; src_idx++)
+    if (contains_char(breakset, src[src_idx]))
+      return src + src_idx;
+
+  return nullptr;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wcspbrk.h b/src/wchar/wcspbrk.h
new file mode 100644
index 0000000..531651b
--- /dev/null
+++ b/src/wchar/wcspbrk.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for wcspbrk ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSPBRK_H
+#define LLVM_LIBC_SRC_WCHAR_WCSPBRK_H
+
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+const wchar_t *wcspbrk(const wchar_t *src, const wchar_t *breakset);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSPBRK_H
diff --git a/src/wchar/wcsrchr.cpp b/src/wchar/wcsrchr.cpp
new file mode 100644
index 0000000..bb4e373
--- /dev/null
+++ b/src/wchar/wcsrchr.cpp
@@ -0,0 +1,31 @@
+//===-- Implementation of wcsrchr -----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcsrchr.h"
+
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(const wchar_t *, wcsrchr, (const wchar_t *s, wchar_t c)) {
+  LIBC_CRASH_ON_NULLPTR(s);
+
+  const wchar_t *last_occurrence = nullptr;
+  while (true) {
+    if (*s == c)
+      last_occurrence = s;
+    if (*s == L'\0')
+      return last_occurrence;
+    ++s;
+  }
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/acos.cpp b/src/wchar/wcsrchr.h
similarity index 61%
rename from src/math/amdgpu/acos.cpp
rename to src/wchar/wcsrchr.h
index de870f2..5e9d8c3 100644
--- a/src/math/amdgpu/acos.cpp
+++ b/src/wchar/wcsrchr.h
@@ -1,4 +1,4 @@
-//===-- Implementation of the GPU acos function ---------------------------===//
+//===-- Implementation header for wcsrchr ---------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,14 +6,16 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/acos.h"
-#include "src/__support/common.h"
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSRCHR_H
+#define LLVM_LIBC_SRC_WCHAR_WCSRCHR_H
 
-#include "declarations.h"
+#include "hdr/types/wchar_t.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, acos, (double x)) { return __ocml_acos_f64(x); }
+const wchar_t *wcsrchr(const wchar_t *s, wchar_t c);
 
 } // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSRCHR_H
diff --git a/src/wchar/wcsspn.cpp b/src/wchar/wcsspn.cpp
new file mode 100644
index 0000000..23de381
--- /dev/null
+++ b/src/wchar/wcsspn.cpp
@@ -0,0 +1,34 @@
+//===-- Implementation of wcsspn ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcsspn.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+bool check(wchar_t c, const wchar_t *s2) {
+  for (int n = 0; s2[n]; ++n) {
+    if (s2[n] == c)
+      return true;
+  }
+  return false;
+}
+LLVM_LIBC_FUNCTION(size_t, wcsspn, (const wchar_t *s1, const wchar_t *s2)) {
+  size_t i = 0;
+  for (; s1[i]; ++i) {
+    if (!check(s1[i], s2))
+      return i;
+  }
+  return i;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wcsspn.h b/src/wchar/wcsspn.h
new file mode 100644
index 0000000..6dbe65d
--- /dev/null
+++ b/src/wchar/wcsspn.h
@@ -0,0 +1,22 @@
+//===-- Implementation header for wcsspn ----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSSPN_H
+#define LLVM_LIBC_SRC_WCHAR_WCSSPN_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+size_t wcsspn(const wchar_t *s1, const wchar_t *s2);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSCHR_H
diff --git a/src/wchar/wcsstr.cpp b/src/wchar/wcsstr.cpp
new file mode 100644
index 0000000..961835a
--- /dev/null
+++ b/src/wchar/wcsstr.cpp
@@ -0,0 +1,38 @@
+//===-- Implementation of wcsstr ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcsstr.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/string/string_utils.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(const wchar_t *, wcsstr,
+                   (const wchar_t *s1, const wchar_t *s2)) {
+  size_t s1_len = internal::string_length(s1);
+  size_t s2_len = internal::string_length(s2);
+  if (s2_len == 0)
+    return s1;
+  if (s2_len > s1_len)
+    return nullptr;
+  for (size_t i = 0; i <= (s1_len - s2_len); ++i) {
+    size_t j = 0;
+    // j will increment until the characters don't match or end of string.
+    for (; j < s2_len && s1[i + j] == s2[j]; ++j)
+      ;
+    if (j == s2_len)
+      return (s1 + i);
+  }
+  return nullptr;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/math/amdgpu/acosf.cpp b/src/wchar/wcsstr.h
similarity index 60%
rename from src/math/amdgpu/acosf.cpp
rename to src/wchar/wcsstr.h
index 0a72a70..af054d8 100644
--- a/src/math/amdgpu/acosf.cpp
+++ b/src/wchar/wcsstr.h
@@ -1,4 +1,4 @@
-//===-- Implementation of the acosf function for GPU ----------------------===//
+//===-- Implementation header for wcsstr ----------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,14 +6,16 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/acosf.h"
-#include "src/__support/common.h"
+#ifndef LLVM_LIBC_SRC_WCHAR_WCSSTR_H
+#define LLVM_LIBC_SRC_WCHAR_WCSSTR_H
 
-#include "declarations.h"
+#include "hdr/types/wchar_t.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(float, acosf, (float x)) { return __ocml_acos_f32(x); }
+const wchar_t *wcsstr(const wchar_t *s1, const wchar_t *s2);
 
 } // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WCSSTR_H
diff --git a/src/math/amdgpu/fdimf.cpp b/src/wchar/wmemchr.cpp
similarity index 55%
rename from src/math/amdgpu/fdimf.cpp
rename to src/wchar/wmemchr.cpp
index ed3855e..8a1cd6c 100644
--- a/src/math/amdgpu/fdimf.cpp
+++ b/src/wchar/wmemchr.cpp
@@ -1,4 +1,4 @@
-//===-- Implementation of the fdimf function for GPU ----------------------===//
+//===-- Implementation of wmemchr -----------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,16 +6,22 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/fdimf.h"
-#include "src/__support/common.h"
+#include "src/wchar/wmemchr.h"
 
-#include "declarations.h"
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
 #include "src/__support/macros/config.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(float, fdimf, (float x, float y)) {
-  return __ocml_fdim_f32(x, y);
+LLVM_LIBC_FUNCTION(const wchar_t *, wmemchr,
+                   (const wchar_t *s, wchar_t c, size_t n)) {
+  size_t i = 0;
+  for (; i < n; ++i)
+    if (s[i] == c)
+      return (s + i);
+  return nullptr;
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wmemchr.h b/src/wchar/wmemchr.h
new file mode 100644
index 0000000..5541290
--- /dev/null
+++ b/src/wchar/wmemchr.h
@@ -0,0 +1,22 @@
+//===-- Implementation header for wmemchr ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WMEMCHR_H
+#define LLVM_LIBC_SRC_WCHAR_WMEMCHR_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+const wchar_t *wmemchr(const wchar_t *s, wchar_t c, size_t n);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WMEMCHR_H
diff --git a/src/wchar/wmemcmp.cpp b/src/wchar/wmemcmp.cpp
new file mode 100644
index 0000000..374f3d5
--- /dev/null
+++ b/src/wchar/wmemcmp.cpp
@@ -0,0 +1,31 @@
+//===-- Implementation of wmemcmp -----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wmemcmp.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/__support/macros/null_check.h" // LIBC_CRASH_ON_NULLPTR
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(int, wmemcmp,
+                   (const wchar_t *s1, const wchar_t *s2, size_t n)) {
+  LIBC_CRASH_ON_NULLPTR(s1);
+  LIBC_CRASH_ON_NULLPTR(s2);
+  for (size_t i = 0; i < n; ++i) {
+    if (s1[i] != s2[i])
+      return (int)(s1[i] - s2[i]);
+  }
+  // If it reaches the end, all n values must be the same.
+  return 0;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wmemcmp.h b/src/wchar/wmemcmp.h
new file mode 100644
index 0000000..51f5fbb
--- /dev/null
+++ b/src/wchar/wmemcmp.h
@@ -0,0 +1,22 @@
+//===-- Implementation header for wmemcmp ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WMEMCMP_H
+#define LLVM_LIBC_SRC_WCHAR_WMEMCMP_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+int wmemcmp(const wchar_t *s1, const wchar_t *s2, size_t n);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WMEMCMP_H
diff --git a/src/wchar/wmemcpy.cpp b/src/wchar/wmemcpy.cpp
new file mode 100644
index 0000000..56708d6
--- /dev/null
+++ b/src/wchar/wmemcpy.cpp
@@ -0,0 +1,26 @@
+//===-- Implementation of wmemcpy -----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wmemcpy.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/__support/macros/config.h"
+#include "src/string/memory_utils/inline_memcpy.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(wchar_t *, wmemcpy,
+                   (wchar_t *__restrict s1, const wchar_t *__restrict s2,
+                    size_t n)) {
+  inline_memcpy(s1, s2, n * sizeof(wchar_t));
+  return s1;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wmemcpy.h b/src/wchar/wmemcpy.h
new file mode 100644
index 0000000..c5a11a5
--- /dev/null
+++ b/src/wchar/wmemcpy.h
@@ -0,0 +1,23 @@
+//===-- Implementation header for wmemcpy ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WMEMCPY_H
+#define LLVM_LIBC_SRC_WCHAR_WMEMCPY_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+wchar_t *wmemcpy(wchar_t *__restrict s1, const wchar_t *__restrict s2,
+                 size_t n);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WMEMCPY_H
diff --git a/src/wchar/wmempcpy.cpp b/src/wchar/wmempcpy.cpp
new file mode 100644
index 0000000..d8b89c0
--- /dev/null
+++ b/src/wchar/wmempcpy.cpp
@@ -0,0 +1,25 @@
+//===-- Implementation of wmempcpy ----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wmempcpy.h"
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
+#include "src/string/memory_utils/inline_memcpy.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+LLVM_LIBC_FUNCTION(wchar_t *, wmempcpy,
+                   (wchar_t *__restrict to, const wchar_t *__restrict from,
+                    size_t size)) {
+  inline_memcpy(to, from, size * sizeof(wchar_t));
+  return reinterpret_cast<wchar_t *>(to) + size;
+}
+
+} // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wmempcpy.h b/src/wchar/wmempcpy.h
new file mode 100644
index 0000000..580674b
--- /dev/null
+++ b/src/wchar/wmempcpy.h
@@ -0,0 +1,23 @@
+//===-- Implementation header for wmempcpy---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WMEMPCPY_H
+#define LLVM_LIBC_SRC_WCHAR_WMEMPCPY_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+wchar_t *wmempcpy(wchar_t *__restrict from, const wchar_t *__restrict s2,
+                  size_t n);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WMEMPCPY_H
diff --git a/src/math/amdgpu/fdim.cpp b/src/wchar/wmemset.cpp
similarity index 58%
rename from src/math/amdgpu/fdim.cpp
rename to src/wchar/wmemset.cpp
index 8ade0b2..7c99f5c 100644
--- a/src/math/amdgpu/fdim.cpp
+++ b/src/wchar/wmemset.cpp
@@ -1,4 +1,4 @@
-//===-- Implementation of the fdim function for GPU -----------------------===//
+//===-- Implementation of wmemset -----------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,16 +6,19 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/math/fdim.h"
-#include "src/__support/common.h"
+#include "src/wchar/wmemset.h"
 
-#include "declarations.h"
-#include "src/__support/macros/config.h"
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/common.h"
 
 namespace LIBC_NAMESPACE_DECL {
 
-LLVM_LIBC_FUNCTION(double, fdim, (double x, double y)) {
-  return __ocml_fdim_f64(x, y);
+LLVM_LIBC_FUNCTION(wchar_t *, wmemset, (wchar_t * s, wchar_t c, size_t n)) {
+  for (size_t i = 0; i < n; i++)
+    s[i] = c;
+
+  return s;
 }
 
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/src/wchar/wmemset.h b/src/wchar/wmemset.h
new file mode 100644
index 0000000..075a561
--- /dev/null
+++ b/src/wchar/wmemset.h
@@ -0,0 +1,23 @@
+//===-- Implementation header for wmemset
+//----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_WCHAR_WMEMSET_H
+#define LLVM_LIBC_SRC_WCHAR_WMEMSET_H
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/__support/macros/config.h"
+
+namespace LIBC_NAMESPACE_DECL {
+
+wchar_t *wmemset(wchar_t *s, wchar_t c, size_t n);
+
+} // namespace LIBC_NAMESPACE_DECL
+
+#endif // LLVM_LIBC_SRC_WCHAR_WMEMSET_H
diff --git a/test/UnitTest/ZxTest.h b/test/UnitTest/ZxTest.h
index 0881902..ac616db 100644
--- a/test/UnitTest/ZxTest.h
+++ b/test/UnitTest/ZxTest.h
@@ -14,14 +14,6 @@
 
 #define WITH_SIGNAL(X) #X
 
-// These macros are used in string unittests.
-#define ASSERT_ERRNO_EQ(VAL)                                                   \
-  ASSERT_EQ(VAL, static_cast<int>(LIBC_NAMESPACE::libc_errno))
-#define ASSERT_ERRNO_SUCCESS()                                                 \
-  ASSERT_EQ(0, static_cast<int>(LIBC_NAMESPACE::libc_errno))
-#define ASSERT_ERRNO_FAILURE()                                                 \
-  ASSERT_NE(0, static_cast<int>(LIBC_NAMESPACE::libc_errno))
-
 #ifndef EXPECT_DEATH
 // Since zxtest has ASSERT_DEATH but not EXPECT_DEATH, wrap calling it
 // in a lambda returning void to swallow any early returns so that this
diff --git a/test/integration/src/__support/GPU/match.cpp b/test/integration/src/__support/GPU/match.cpp
index 0eadb13..2d314c2 100644
--- a/test/integration/src/__support/GPU/match.cpp
+++ b/test/integration/src/__support/GPU/match.cpp
@@ -14,6 +14,8 @@ using namespace LIBC_NAMESPACE;
 
 // Test to ensure that match any / match all work.
 static void test_match() {
+  // FIXME: Disable on older SMs as they hang for some reason.
+#if !defined(__CUDA_ARCH__) || __CUDA_ARCH__ >= 700
   uint64_t mask = gpu::get_lane_mask();
   EXPECT_EQ(1ull << gpu::get_lane_id(),
             gpu::match_any(mask, gpu::get_lane_id()));
@@ -23,6 +25,7 @@ static void test_match() {
   EXPECT_EQ(expected, gpu::match_any(mask, gpu::get_lane_id() < 16));
   EXPECT_EQ(mask, gpu::match_all(mask, 1));
   EXPECT_EQ(0ull, gpu::match_all(mask, gpu::get_lane_id()));
+#endif
 }
 
 TEST_MAIN(int argc, char **argv, char **envp) {
diff --git a/test/integration/src/stdlib/gpu/malloc.cpp b/test/integration/src/stdlib/gpu/malloc.cpp
new file mode 100644
index 0000000..7880206
--- /dev/null
+++ b/test/integration/src/stdlib/gpu/malloc.cpp
@@ -0,0 +1,40 @@
+//===-- Test for parallel GPU malloc interface ----------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "test/IntegrationTest/test.h"
+
+#include "src/__support/GPU/utils.h"
+#include "src/stdlib/free.h"
+#include "src/stdlib/malloc.h"
+
+using namespace LIBC_NAMESPACE;
+
+TEST_MAIN(int, char **, char **) {
+  int *convergent = reinterpret_cast<int *>(LIBC_NAMESPACE::malloc(16));
+  EXPECT_NE(convergent, nullptr);
+  *convergent = 1;
+  EXPECT_EQ(*convergent, 1);
+  LIBC_NAMESPACE::free(convergent);
+
+  int *divergent = reinterpret_cast<int *>(
+      LIBC_NAMESPACE::malloc((gpu::get_thread_id() + 1) * 16));
+  EXPECT_NE(divergent, nullptr);
+  *divergent = 1;
+  EXPECT_EQ(*divergent, 1);
+  LIBC_NAMESPACE::free(divergent);
+
+  if (gpu::get_lane_id() & 1) {
+    int *masked = reinterpret_cast<int *>(
+        LIBC_NAMESPACE::malloc((gpu::get_thread_id() + 1) * 16));
+    EXPECT_NE(masked, nullptr);
+    *masked = 1;
+    EXPECT_EQ(*masked, 1);
+    LIBC_NAMESPACE::free(masked);
+  }
+  return 0;
+}
diff --git a/test/integration/src/stdlib/gpu/malloc_stress.cpp b/test/integration/src/stdlib/gpu/malloc_stress.cpp
new file mode 100644
index 0000000..77479f8
--- /dev/null
+++ b/test/integration/src/stdlib/gpu/malloc_stress.cpp
@@ -0,0 +1,38 @@
+//===-- Test for parallel GPU malloc interface ----------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "test/IntegrationTest/test.h"
+
+#include "src/__support/GPU/utils.h"
+#include "src/stdlib/free.h"
+#include "src/stdlib/malloc.h"
+
+using namespace LIBC_NAMESPACE;
+
+static inline void use(uint8_t *ptr, uint32_t size) {
+  EXPECT_NE(ptr, nullptr);
+  for (int i = 0; i < size; ++i)
+    ptr[i] = uint8_t(i + gpu::get_thread_id());
+
+  // Try to detect if some other thread manages to clobber our memory.
+  for (int i = 0; i < size; ++i)
+    EXPECT_EQ(ptr[i], uint8_t(i + gpu::get_thread_id()));
+}
+
+TEST_MAIN(int, char **, char **) {
+  void *ptrs[256];
+  for (int i = 0; i < 256; ++i)
+    ptrs[i] = malloc(gpu::get_lane_id() % 2 ? 16 : 32);
+
+  for (int i = 0; i < 256; ++i)
+    use(reinterpret_cast<uint8_t *>(ptrs[i]), gpu::get_lane_id() % 2 ? 16 : 32);
+
+  for (int i = 0; i < 256; ++i)
+    free(ptrs[i]);
+  return 0;
+}
diff --git a/test/integration/startup/gpu/rpc_stream_test.cpp b/test/integration/startup/gpu/rpc_stream_test.cpp
index aba5b0b..3e81328 100644
--- a/test/integration/startup/gpu/rpc_stream_test.cpp
+++ b/test/integration/startup/gpu/rpc_stream_test.cpp
@@ -12,6 +12,7 @@
 #include "src/__support/integer_to_string.h"
 #include "src/string/memory_utils/inline_memcmp.h"
 #include "src/string/memory_utils/inline_memcpy.h"
+#include "src/string/memory_utils/inline_memset.h"
 #include "src/string/string_utils.h"
 #include "test/IntegrationTest/test.h"
 
diff --git a/include/llvm-libc-types/cc_t.h b/test/integration/startup/uefi/main_without_args.cpp
similarity index 62%
rename from include/llvm-libc-types/cc_t.h
rename to test/integration/startup/uefi/main_without_args.cpp
index 40d99ad..9bc3546 100644
--- a/include/llvm-libc-types/cc_t.h
+++ b/test/integration/startup/uefi/main_without_args.cpp
@@ -1,4 +1,4 @@
-//===-- Definition of cc_t type -------------------------------------------===//
+//===-- Loader test for main without args ---------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,9 +6,6 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef LLVM_LIBC_TYPES_CC_T_H
-#define LLVM_LIBC_TYPES_CC_T_H
+#include "test/IntegrationTest/test.h"
 
-typedef unsigned char cc_t;
-
-#endif // LLVM_LIBC_TYPES_CC_T_H
+TEST_MAIN() { return 0; }
diff --git a/test/src/__support/CPP/atomic_test.cpp b/test/src/__support/CPP/atomic_test.cpp
index 5c3f60e..7b2a929 100644
--- a/test/src/__support/CPP/atomic_test.cpp
+++ b/test/src/__support/CPP/atomic_test.cpp
@@ -50,3 +50,18 @@ TEST(LlvmLibcAtomicTest, TrivialCompositeData) {
   ASSERT_EQ(old.a, 'a');
   ASSERT_EQ(old.b, 'b');
 }
+
+TEST(LlvmLibcAtomicTest, AtomicRefTest) {
+  int val = 123;
+  LIBC_NAMESPACE::cpp::AtomicRef aint(val);
+  ASSERT_EQ(aint.load(LIBC_NAMESPACE::cpp::MemoryOrder::RELAXED), 123);
+  ASSERT_EQ(aint.fetch_add(1, LIBC_NAMESPACE::cpp::MemoryOrder::RELAXED), 123);
+  aint = 1234;
+  ASSERT_EQ(aint.load(LIBC_NAMESPACE::cpp::MemoryOrder::RELAXED), 1234);
+
+  // Test the implicit construction from pointer.
+  auto fn = [](LIBC_NAMESPACE::cpp::AtomicRef<int> aint) -> int {
+    return aint.load(LIBC_NAMESPACE::cpp::MemoryOrder::RELAXED);
+  };
+  ASSERT_EQ(fn(&val), 1234);
+}
diff --git a/test/src/__support/CPP/type_traits_test.cpp b/test/src/__support/CPP/type_traits_test.cpp
index 4b3e48c..3a607ec 100644
--- a/test/src/__support/CPP/type_traits_test.cpp
+++ b/test/src/__support/CPP/type_traits_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "include/llvm-libc-macros/stdfix-macros.h"
 #include "src/__support/CPP/type_traits.h"
 #include "src/__support/macros/config.h"
 #include "test/UnitTest/Test.h"
@@ -409,7 +410,37 @@ TEST(LlvmLibcTypeTraitsTest, is_object) {
 
 // TODO is_scalar
 
-// TODO is_signed
+TEST(LlvmLibcTypeTraitsTest, is_signed) {
+  EXPECT_TRUE((is_signed_v<int>));
+  EXPECT_TRUE((is_signed_v<long>));
+  EXPECT_TRUE((is_signed_v<long long>));
+  EXPECT_FALSE((is_signed_v<unsigned int>));
+  EXPECT_FALSE((is_signed_v<unsigned long>));
+  EXPECT_FALSE((is_signed_v<unsigned long long>));
+  EXPECT_TRUE((is_signed_v<float>));
+  EXPECT_TRUE((is_signed_v<double>));
+  EXPECT_TRUE((is_signed_v<long double>));
+
+#ifdef LIBC_COMPILER_HAS_FIXED_POINT
+  // for fixed point types
+  EXPECT_TRUE((is_signed_v<fract>));
+  EXPECT_FALSE((is_signed_v<unsigned fract>));
+  EXPECT_TRUE((is_signed_v<accum>));
+  EXPECT_FALSE((is_signed_v<unsigned accum>));
+  EXPECT_TRUE((is_signed_v<sat fract>));
+  EXPECT_FALSE((is_signed_v<unsigned sat fract>));
+  EXPECT_TRUE((is_signed_v<sat accum>));
+  EXPECT_FALSE((is_signed_v<unsigned sat accum>));
+  EXPECT_TRUE((is_signed_v<short fract>));
+  EXPECT_FALSE((is_signed_v<unsigned short fract>));
+  EXPECT_TRUE((is_signed_v<short accum>));
+  EXPECT_FALSE((is_signed_v<unsigned short accum>));
+  EXPECT_TRUE((is_signed_v<long fract>));
+  EXPECT_FALSE((is_signed_v<unsigned long fract>));
+  EXPECT_TRUE((is_signed_v<long accum>));
+  EXPECT_FALSE((is_signed_v<unsigned long accum>));
+#endif
+}
 
 // TODO is_trivially_constructible
 
@@ -419,7 +450,37 @@ TEST(LlvmLibcTypeTraitsTest, is_object) {
 
 // TODO is_union
 
-// TODO is_unsigned
+TEST(LlvmLibcTypeTraitsTest, is_unsigned) {
+  EXPECT_FALSE((is_unsigned_v<int>));
+  EXPECT_FALSE((is_unsigned_v<long>));
+  EXPECT_FALSE((is_unsigned_v<long long>));
+  EXPECT_TRUE((is_unsigned_v<unsigned int>));
+  EXPECT_TRUE((is_unsigned_v<unsigned long>));
+  EXPECT_TRUE((is_unsigned_v<unsigned long long>));
+  EXPECT_FALSE((is_unsigned_v<float>));
+  EXPECT_FALSE((is_unsigned_v<double>));
+  EXPECT_FALSE((is_unsigned_v<long double>));
+
+#ifdef LIBC_COMPILER_HAS_FIXED_POINT
+  // for fixed point types
+  EXPECT_FALSE((is_unsigned_v<fract>));
+  EXPECT_TRUE((is_unsigned_v<unsigned fract>));
+  EXPECT_FALSE((is_unsigned_v<accum>));
+  EXPECT_TRUE((is_unsigned_v<unsigned accum>));
+  EXPECT_FALSE((is_unsigned_v<sat fract>));
+  EXPECT_TRUE((is_unsigned_v<unsigned sat fract>));
+  EXPECT_FALSE((is_unsigned_v<sat accum>));
+  EXPECT_TRUE((is_unsigned_v<unsigned sat accum>));
+  EXPECT_FALSE((is_unsigned_v<short fract>));
+  EXPECT_TRUE((is_unsigned_v<unsigned short fract>));
+  EXPECT_FALSE((is_unsigned_v<short accum>));
+  EXPECT_TRUE((is_unsigned_v<unsigned short accum>));
+  EXPECT_FALSE((is_unsigned_v<long fract>));
+  EXPECT_TRUE((is_unsigned_v<unsigned long fract>));
+  EXPECT_FALSE((is_unsigned_v<long accum>));
+  EXPECT_TRUE((is_unsigned_v<unsigned long accum>));
+#endif
+}
 
 // TODO is_void
 
diff --git a/test/src/__support/freelist_heap_test.cpp b/test/src/__support/freelist_heap_test.cpp
index 0623272..93e2361 100644
--- a/test/src/__support/freelist_heap_test.cpp
+++ b/test/src/__support/freelist_heap_test.cpp
@@ -13,6 +13,15 @@
 #include "src/string/memcpy.h"
 #include "test/UnitTest/Test.h"
 
+asm(R"(
+.globl _end, __llvm_libc_heap_limit
+
+.bss
+_end:
+  .fill 1024
+__llvm_libc_heap_limit:
+)");
+
 using LIBC_NAMESPACE::Block;
 using LIBC_NAMESPACE::freelist_heap;
 using LIBC_NAMESPACE::FreeListHeap;
diff --git a/test/src/__support/str_to_float_comparison_test.cpp b/test/src/__support/str_to_float_comparison_test.cpp
index 61bfc3c..6e89ce2 100644
--- a/test/src/__support/str_to_float_comparison_test.cpp
+++ b/test/src/__support/str_to_float_comparison_test.cpp
@@ -6,16 +6,18 @@
 //
 //===----------------------------------------------------------------------===//
 
-// #include "src/__support/str_float_conv_utils.h"
-
-#include <stdlib.h> // For string to float functions
-
-// #include "src/__support/FPUtil/FPBits.h"
-
-#include <cstdint>
-#include <fstream>
-#include <iostream>
-#include <string>
+#include "src/__support/CPP/bit.h"
+#include "src/stdio/fclose.h"
+#include "src/stdio/fgets.h"
+#include "src/stdio/fopen.h"
+#include "src/stdio/printf.h"
+#include "src/stdlib/getenv.h"
+#include "src/stdlib/strtod.h"
+#include "src/stdlib/strtof.h"
+#include "src/string/strdup.h"
+#include "src/string/strtok.h"
+#include "test/UnitTest/Test.h"
+#include <stdint.h>
 
 // The intent of this test is to read in files in the format used in this test
 // dataset: https://github.com/nigeltao/parse-number-fxx-test-data
@@ -32,6 +34,19 @@
 // ./libc_str_to_float_comparison_test <path/to/dataset/repo>/data/*
 // It will take a few seconds to run.
 
+struct ParseResult {
+  uint32_t totalFails;
+  uint32_t totalBitDiffs;
+  uint32_t detailedBitDiffs[4];
+  uint32_t total;
+};
+
+enum class ParseStatus : uint8_t {
+  SUCCESS,
+  FILE_ERROR,
+  PARSE_ERROR,
+};
+
 static inline uint32_t hexCharToU32(char in) {
   return in > '9' ? in + 10 - 'A' : in - '0';
 }
@@ -54,120 +69,168 @@ static inline uint64_t fastHexToU64(const char *inStr) {
   return result;
 }
 
-int checkFile(char *inputFileName, int *totalFails, int *totalBitDiffs,
-              int *detailedBitDiffs, int *total) {
-  int32_t curFails = 0;    // Only counts actual failures, not bitdiffs.
-  int32_t curBitDiffs = 0; // A bitdiff is when the expected result and actual
-                           // result are off by +/- 1 bit.
-  std::string line;
-  std::string num;
+static void parseLine(const char *line, ParseResult &parseResult,
+                      int32_t &curFails, int32_t &curBitDiffs) {
 
-  std::ifstream fileStream(inputFileName, std::ifstream::in);
+  if (line[0] == '#')
+    return;
 
-  if (!fileStream.is_open()) {
-    std::cout << "file '" << inputFileName << "' failed to open. Exiting.\n";
-    return 1;
-  }
-  while (getline(fileStream, line)) {
-    if (line[0] == '#') {
-      continue;
-    }
-    *total = *total + 1;
-    uint32_t expectedFloatRaw;
-    uint64_t expectedDoubleRaw;
+  parseResult.total += 1;
+  uint32_t expectedFloatRaw;
+  uint64_t expectedDoubleRaw;
 
-    expectedFloatRaw = fastHexToU32(line.c_str() + 5);
-    expectedDoubleRaw = fastHexToU64(line.c_str() + 14);
-    num = line.substr(31);
+  expectedFloatRaw = fastHexToU32(line + 5);
+  expectedDoubleRaw = fastHexToU64(line + 14);
 
-    float floatResult = strtof(num.c_str(), nullptr);
+  const char *num = line + 31;
 
-    double doubleResult = strtod(num.c_str(), nullptr);
+  float floatResult = LIBC_NAMESPACE::strtof(num, nullptr);
 
-    uint32_t floatRaw = *(uint32_t *)(&floatResult);
+  double doubleResult = LIBC_NAMESPACE::strtod(num, nullptr);
 
-    uint64_t doubleRaw = *(uint64_t *)(&doubleResult);
+  uint32_t floatRaw = LIBC_NAMESPACE::cpp::bit_cast<uint32_t>(floatResult);
 
-    if (!(expectedFloatRaw == floatRaw)) {
-      if (expectedFloatRaw == floatRaw + 1 ||
-          expectedFloatRaw == floatRaw - 1) {
-        curBitDiffs++;
-        if (expectedFloatRaw == floatRaw + 1) {
-          detailedBitDiffs[0] = detailedBitDiffs[0] + 1; // float low
-        } else {
-          detailedBitDiffs[1] = detailedBitDiffs[1] + 1; // float high
-        }
+  uint64_t doubleRaw = LIBC_NAMESPACE::cpp::bit_cast<uint64_t>(doubleResult);
+
+  if (!(expectedFloatRaw == floatRaw)) {
+    if (expectedFloatRaw == floatRaw + 1 || expectedFloatRaw == floatRaw - 1) {
+      curBitDiffs++;
+      if (expectedFloatRaw == floatRaw + 1) {
+        parseResult.detailedBitDiffs[0] =
+            parseResult.detailedBitDiffs[0] + 1; // float low
       } else {
-        curFails++;
-      }
-      if (curFails + curBitDiffs < 10) {
-        std::cout << "Float fail for '" << num << "'. Expected " << std::hex
-                  << expectedFloatRaw << " but got " << floatRaw << "\n"
-                  << std::dec;
+        parseResult.detailedBitDiffs[1] =
+            parseResult.detailedBitDiffs[1] + 1; // float high
       }
+    } else {
+      curFails++;
     }
+    if (curFails + curBitDiffs < 10) {
+      LIBC_NAMESPACE::printf("Float fail for '%s'. Expected %x but got %x\n",
+                             num, expectedFloatRaw, floatRaw);
+    }
+  }
 
-    if (!(expectedDoubleRaw == doubleRaw)) {
-      if (expectedDoubleRaw == doubleRaw + 1 ||
-          expectedDoubleRaw == doubleRaw - 1) {
-        curBitDiffs++;
-        if (expectedDoubleRaw == doubleRaw + 1) {
-          detailedBitDiffs[2] = detailedBitDiffs[2] + 1; // double low
-        } else {
-          detailedBitDiffs[3] = detailedBitDiffs[3] + 1; // double high
-        }
+  if (!(expectedDoubleRaw == doubleRaw)) {
+    if (expectedDoubleRaw == doubleRaw + 1 ||
+        expectedDoubleRaw == doubleRaw - 1) {
+      curBitDiffs++;
+      if (expectedDoubleRaw == doubleRaw + 1) {
+        parseResult.detailedBitDiffs[2] =
+            parseResult.detailedBitDiffs[2] + 1; // double low
       } else {
-        curFails++;
-      }
-      if (curFails + curBitDiffs < 10) {
-        std::cout << "Double fail for '" << num << "'. Expected " << std::hex
-                  << expectedDoubleRaw << " but got " << doubleRaw << "\n"
-                  << std::dec;
+        parseResult.detailedBitDiffs[3] =
+            parseResult.detailedBitDiffs[3] + 1; // double high
       }
+    } else {
+      curFails++;
+    }
+    if (curFails + curBitDiffs < 10) {
+      LIBC_NAMESPACE::printf("Double fail for '%s'. Expected %lx but got %lx\n",
+                             num, expectedDoubleRaw, doubleRaw);
     }
   }
+}
 
-  fileStream.close();
+ParseStatus checkBuffer(ParseResult &parseResult) {
+  constexpr const char *LINES[] = {
+      "3C00 3F800000 3FF0000000000000 1",
+      "3D00 3FA00000 3FF4000000000000 1.25",
+      "3D9A 3FB33333 3FF6666666666666 1.4",
+      "57B7 42F6E979 405EDD2F1A9FBE77 123.456",
+      "622A 44454000 4088A80000000000 789",
+      "7C00 7F800000 7FF0000000000000 123.456e789"};
+
+  int32_t curFails = 0;    // Only counts actual failures, not bitdiffs.
+  int32_t curBitDiffs = 0; // A bitdiff is when the expected result and actual
+  // result are off by +/- 1 bit.
+
+  for (uint8_t i = 0; i < sizeof(LINES) / sizeof(LINES[0]); i++) {
+    parseLine(LINES[i], parseResult, curFails, curBitDiffs);
+  }
 
-  *totalBitDiffs += curBitDiffs;
-  *totalFails += curFails;
+  parseResult.totalBitDiffs += curBitDiffs;
+  parseResult.totalFails += curFails;
 
   if (curFails > 1 || curBitDiffs > 1) {
-    return 2;
+    return ParseStatus::PARSE_ERROR;
   }
-  return 0;
+  return ParseStatus::SUCCESS;
 }
 
-int main(int argc, char *argv[]) {
-  int result = 0;
-  int fails = 0;
+ParseStatus checkFile(char *inputFileName, ParseResult &parseResult) {
+  int32_t curFails = 0;    // Only counts actual failures, not bitdiffs.
+  int32_t curBitDiffs = 0; // A bitdiff is when the expected result and actual
+  // result are off by +/- 1 bit.
+  char line[1000];
+
+  auto *fileHandle = LIBC_NAMESPACE::fopen(inputFileName, "r");
+
+  if (!fileHandle) {
+    LIBC_NAMESPACE::printf("file '%s' failed to open. Exiting.\n",
+                           inputFileName);
+    return ParseStatus::FILE_ERROR;
+  }
+
+  while (LIBC_NAMESPACE::fgets(line, sizeof(line), fileHandle)) {
+    parseLine(line, parseResult, curFails, curBitDiffs);
+  }
+
+  LIBC_NAMESPACE::fclose(fileHandle);
+
+  parseResult.totalBitDiffs += curBitDiffs;
+  parseResult.totalFails += curFails;
+
+  if (curFails > 1 || curBitDiffs > 1) {
+    return ParseStatus::PARSE_ERROR;
+  }
+  return ParseStatus::SUCCESS;
+}
+
+ParseStatus updateStatus(ParseStatus parse_status, ParseStatus cur_status) {
+  if (cur_status == ParseStatus::FILE_ERROR) {
+    parse_status = ParseStatus::FILE_ERROR;
+  } else if (cur_status == ParseStatus::PARSE_ERROR) {
+    parse_status = ParseStatus::PARSE_ERROR;
+  }
+  return parse_status;
+}
+
+TEST(LlvmLibcStrToFloatComparisonTest, CheckFloats) {
+  ParseStatus parseStatus = ParseStatus::SUCCESS;
 
   // Bitdiffs are cases where the expected result and actual result only differ
   // by +/- the least significant bit. They are tracked separately from larger
   // failures since a bitdiff is most likely the result of a rounding error, and
   // splitting them off makes them easier to track down.
-  int bitdiffs = 0;
-  int detailedBitDiffs[4] = {0, 0, 0, 0};
-
-  int total = 0;
-  for (int i = 1; i < argc; i++) {
-    std::cout << "Starting file " << argv[i] << "\n";
-    int curResult =
-        checkFile(argv[i], &fails, &bitdiffs, detailedBitDiffs, &total);
-    if (curResult == 1) {
-      result = 1;
-      break;
-    } else if (curResult == 2) {
-      result = 2;
+
+  ParseResult parseResult = {
+      .totalFails = 0,
+      .totalBitDiffs = 0,
+      .detailedBitDiffs = {0, 0, 0, 0},
+      .total = 0,
+  };
+
+  char *files = LIBC_NAMESPACE::getenv("FILES");
+
+  if (files == nullptr) {
+    ParseStatus cur_status = checkBuffer(parseResult);
+    parseStatus = updateStatus(parseStatus, cur_status);
+  } else {
+    files = LIBC_NAMESPACE::strdup(files);
+    for (char *file = LIBC_NAMESPACE::strtok(files, ","); file != nullptr;
+         file = LIBC_NAMESPACE::strtok(nullptr, ",")) {
+      ParseStatus cur_status = checkFile(file, parseResult);
+      parseStatus = updateStatus(parseStatus, cur_status);
     }
   }
-  std::cout << "Results:\n"
-            << "Total significant failed conversions: " << fails << "\n"
-            << "Total conversions off by +/- 1 bit: " << bitdiffs << "\n"
-            << "\t" << detailedBitDiffs[0] << "\tfloat low\n"
-            << "\t" << detailedBitDiffs[1] << "\tfloat high\n"
-            << "\t" << detailedBitDiffs[2] << "\tdouble low\n"
-            << "\t" << detailedBitDiffs[3] << "\tdouble high\n"
-            << "Total lines: " << total << "\n";
-  return result;
+
+  EXPECT_EQ(parseStatus, ParseStatus::SUCCESS);
+  EXPECT_EQ(parseResult.totalFails, 0u);
+  EXPECT_EQ(parseResult.totalBitDiffs, 0u);
+  EXPECT_EQ(parseResult.detailedBitDiffs[0], 0u); // float low
+  EXPECT_EQ(parseResult.detailedBitDiffs[1], 0u); // float high
+  EXPECT_EQ(parseResult.detailedBitDiffs[2], 0u); // double low
+  EXPECT_EQ(parseResult.detailedBitDiffs[3], 0u); // double high
+  LIBC_NAMESPACE::printf("Total lines: %d\n", parseResult.total);
 }
diff --git a/test/src/math/FmaTest.h b/test/src/math/FmaTest.h
index 0114333..5c5419c 100644
--- a/test/src/math/FmaTest.h
+++ b/test/src/math/FmaTest.h
@@ -58,8 +58,9 @@ public:
 
   void test_subnormal_range(FmaFunc func) {
     constexpr InStorageType COUNT = 100'001;
-    constexpr InStorageType STEP =
+    constexpr InStorageType RAW_STEP =
         (IN_MAX_SUBNORMAL_U - IN_MIN_SUBNORMAL_U) / COUNT;
+    constexpr InStorageType STEP = (RAW_STEP == 0 ? 1 : RAW_STEP);
     LIBC_NAMESPACE::srand(1);
     for (InStorageType v = IN_MIN_SUBNORMAL_U, w = IN_MAX_SUBNORMAL_U;
          v <= IN_MAX_SUBNORMAL_U && w >= IN_MIN_SUBNORMAL_U;
@@ -75,7 +76,9 @@ public:
 
   void test_normal_range(FmaFunc func) {
     constexpr InStorageType COUNT = 100'001;
-    constexpr InStorageType STEP = (IN_MAX_NORMAL_U - IN_MIN_NORMAL_U) / COUNT;
+    constexpr InStorageType RAW_STEP =
+        (IN_MAX_NORMAL_U - IN_MIN_NORMAL_U) / COUNT;
+    constexpr InStorageType STEP = (RAW_STEP == 0 ? 1 : RAW_STEP);
     LIBC_NAMESPACE::srand(1);
     for (InStorageType v = IN_MIN_NORMAL_U, w = IN_MAX_NORMAL_U;
          v <= IN_MAX_NORMAL_U && w >= IN_MIN_NORMAL_U; v += STEP, w -= STEP) {
diff --git a/test/src/math/HypotTest.h b/test/src/math/HypotTest.h
index fd0c1b3..dc73581 100644
--- a/test/src/math/HypotTest.h
+++ b/test/src/math/HypotTest.h
@@ -73,7 +73,7 @@ public:
     constexpr StorageType COUNT = 10'001;
     for (unsigned scale = 0; scale < 4; ++scale) {
       StorageType max_value = MAX_SUBNORMAL << scale;
-      StorageType step = (max_value - MIN_SUBNORMAL) / COUNT;
+      StorageType step = (max_value - MIN_SUBNORMAL) / COUNT + 1;
       for (int signs = 0; signs < 4; ++signs) {
         for (StorageType v = MIN_SUBNORMAL, w = max_value;
              v <= max_value && w >= MIN_SUBNORMAL; v += step, w -= step) {
diff --git a/test/src/math/acos_test.cpp b/test/src/math/acos_test.cpp
new file mode 100644
index 0000000..1404887
--- /dev/null
+++ b/test/src/math/acos_test.cpp
@@ -0,0 +1,82 @@
+//===-- Unittests for acos ------------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/acos.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+
+using LlvmLibcAcosTest = LIBC_NAMESPACE::testing::FPTest<double>;
+
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+using LIBC_NAMESPACE::testing::tlog;
+
+TEST_F(LlvmLibcAcosTest, InDoubleRange) {
+  constexpr uint64_t COUNT = 123'451;
+  uint64_t START = FPBits(0x1.0p-60).uintval();
+  uint64_t STOP = FPBits(1.0).uintval();
+  uint64_t STEP = (STOP - START) / COUNT;
+
+  auto test = [&](mpfr::RoundingMode rounding_mode) {
+    mpfr::ForceRoundingMode __r(rounding_mode);
+    if (!__r.success)
+      return;
+
+    uint64_t fails = 0;
+    uint64_t count = 0;
+    uint64_t cc = 0;
+    double mx = 0.0, mr = 0.0;
+    double tol = 0.5;
+
+    for (uint64_t i = 0, v = START; i <= COUNT; ++i, v += STEP) {
+      double x = FPBits(v).get_val();
+      if (FPBits(v).is_inf_or_nan())
+        continue;
+      double result = LIBC_NAMESPACE::acos(x);
+      ++cc;
+      if (FPBits(result).is_inf_or_nan())
+        continue;
+
+      ++count;
+
+      if (!TEST_MPFR_MATCH_ROUNDING_SILENTLY(mpfr::Operation::Acos, x, result,
+                                             0.5, rounding_mode)) {
+        ++fails;
+        while (!TEST_MPFR_MATCH_ROUNDING_SILENTLY(mpfr::Operation::Acos, x,
+                                                  result, tol, rounding_mode)) {
+          mx = x;
+          mr = result;
+
+          if (tol > 1000.0)
+            break;
+
+          tol *= 2.0;
+        }
+      }
+    }
+    if (fails) {
+      tlog << " Acos failed: " << fails << "/" << count << "/" << cc
+           << " tests.\n";
+      tlog << "   Max ULPs is at most: " << static_cast<uint64_t>(tol) << ".\n";
+      EXPECT_MPFR_MATCH(mpfr::Operation::Acos, mx, mr, 0.5, rounding_mode);
+    }
+  };
+
+  tlog << " Test Rounding To Nearest...\n";
+  test(mpfr::RoundingMode::Nearest);
+
+  tlog << " Test Rounding Downward...\n";
+  test(mpfr::RoundingMode::Downward);
+
+  tlog << " Test Rounding Upward...\n";
+  test(mpfr::RoundingMode::Upward);
+
+  tlog << " Test Rounding Toward Zero...\n";
+  test(mpfr::RoundingMode::TowardZero);
+}
diff --git a/test/src/math/acoshf16_test.cpp b/test/src/math/acoshf16_test.cpp
new file mode 100644
index 0000000..7348018
--- /dev/null
+++ b/test/src/math/acoshf16_test.cpp
@@ -0,0 +1,28 @@
+//===-- Unittests for acoshf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/errno/libc_errno.h"
+#include "src/math/acoshf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+#include <stdint.h>
+
+using LlvmLibcAcoshf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+static constexpr uint16_t START = 0x3c00U;
+static constexpr uint16_t STOP = 0x7c00;
+
+TEST_F(LlvmLibcAcoshf16Test, PositiveRange) {
+  for (uint16_t v = START; v <= STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Acosh, x,
+                                   LIBC_NAMESPACE::acoshf16(x), 0.5);
+  }
+}
diff --git a/test/src/math/acospif16_test.cpp b/test/src/math/acospif16_test.cpp
new file mode 100644
index 0000000..1dd951f
--- /dev/null
+++ b/test/src/math/acospif16_test.cpp
@@ -0,0 +1,42 @@
+//===-- Exhaustive test for acospif16 -------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/acospif16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+
+using LlvmLibcAcospif16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+// Range: [0, Inf]
+static constexpr uint16_t POS_START = 0x0000U;
+static constexpr uint16_t POS_STOP = 0x7c00U;
+
+// Range: [-Inf, 0]
+static constexpr uint16_t NEG_START = 0x8000U;
+static constexpr uint16_t NEG_STOP = 0xfc00U;
+
+TEST_F(LlvmLibcAcospif16Test, PositiveRange) {
+  for (uint16_t v = POS_START; v <= POS_STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Acospi, x,
+                                   LIBC_NAMESPACE::acospif16(x), 0.5);
+  }
+}
+
+TEST_F(LlvmLibcAcospif16Test, NegativeRange) {
+  for (uint16_t v = NEG_START; v <= NEG_STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Acospi, x,
+                                   LIBC_NAMESPACE::acospif16(x), 0.5);
+  }
+}
diff --git a/test/src/math/asin_test.cpp b/test/src/math/asin_test.cpp
new file mode 100644
index 0000000..385e341
--- /dev/null
+++ b/test/src/math/asin_test.cpp
@@ -0,0 +1,83 @@
+//===-- Unittests for asin ------------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/asin.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+
+using LlvmLibcAsinTest = LIBC_NAMESPACE::testing::FPTest<double>;
+
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+using LIBC_NAMESPACE::testing::tlog;
+
+TEST_F(LlvmLibcAsinTest, InDoubleRange) {
+  constexpr uint64_t COUNT = 123'451;
+  uint64_t START = FPBits(0x1.0p-60).uintval();
+  uint64_t STOP = FPBits(1.0).uintval();
+  uint64_t STEP = (STOP - START) / COUNT;
+
+  auto test = [&](mpfr::RoundingMode rounding_mode) {
+    mpfr::ForceRoundingMode __r(rounding_mode);
+    if (!__r.success)
+      return;
+
+    uint64_t fails = 0;
+    uint64_t count = 0;
+    uint64_t cc = 0;
+    double mx = 0.0, mr = 0.0;
+    double tol = 0.5;
+
+    for (uint64_t i = 0, v = START; i <= COUNT; ++i, v += STEP) {
+      double x = FPBits(v).get_val();
+      if (FPBits(v).is_nan() || FPBits(v).is_inf())
+        continue;
+      LIBC_NAMESPACE::libc_errno = 0;
+      double result = LIBC_NAMESPACE::asin(x);
+      ++cc;
+      if (FPBits(result).is_nan() || FPBits(result).is_inf())
+        continue;
+
+      ++count;
+
+      if (!TEST_MPFR_MATCH_ROUNDING_SILENTLY(mpfr::Operation::Asin, x, result,
+                                             0.5, rounding_mode)) {
+        ++fails;
+        while (!TEST_MPFR_MATCH_ROUNDING_SILENTLY(mpfr::Operation::Asin, x,
+                                                  result, tol, rounding_mode)) {
+          mx = x;
+          mr = result;
+
+          if (tol > 1000.0)
+            break;
+
+          tol *= 2.0;
+        }
+      }
+    }
+    if (fails) {
+      tlog << " Asin failed: " << fails << "/" << count << "/" << cc
+           << " tests.\n";
+      tlog << "   Max ULPs is at most: " << static_cast<uint64_t>(tol) << ".\n";
+      EXPECT_MPFR_MATCH(mpfr::Operation::Asin, mx, mr, 0.5, rounding_mode);
+    }
+  };
+
+  tlog << " Test Rounding To Nearest...\n";
+  test(mpfr::RoundingMode::Nearest);
+
+  tlog << " Test Rounding Downward...\n";
+  test(mpfr::RoundingMode::Downward);
+
+  tlog << " Test Rounding Upward...\n";
+  test(mpfr::RoundingMode::Upward);
+
+  tlog << " Test Rounding Toward Zero...\n";
+  test(mpfr::RoundingMode::TowardZero);
+}
diff --git a/test/src/math/asinhf16_test.cpp b/test/src/math/asinhf16_test.cpp
new file mode 100644
index 0000000..929d137
--- /dev/null
+++ b/test/src/math/asinhf16_test.cpp
@@ -0,0 +1,42 @@
+//===-- Exhaustive test for asinhf16 --------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/asinhf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+
+using LlvmLibcAsinhf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+// Range: [0, Inf]
+static constexpr uint16_t POS_START = 0x0000U;
+static constexpr uint16_t POS_STOP = 0x7c00U;
+
+// Range: [-Inf, 0]
+static constexpr uint16_t NEG_START = 0x8000U;
+static constexpr uint16_t NEG_STOP = 0xfc00U;
+
+TEST_F(LlvmLibcAsinhf16Test, PositiveRange) {
+  for (uint16_t v = POS_START; v <= POS_STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Asinh, x,
+                                   LIBC_NAMESPACE::asinhf16(x), 0.5);
+  }
+}
+
+TEST_F(LlvmLibcAsinhf16Test, NegativeRange) {
+  for (uint16_t v = NEG_START; v <= NEG_STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Asinh, x,
+                                   LIBC_NAMESPACE::asinhf16(x), 0.5);
+  }
+}
diff --git a/test/src/math/atan2f128_test.cpp b/test/src/math/atan2f128_test.cpp
new file mode 100644
index 0000000..0bfec1b
--- /dev/null
+++ b/test/src/math/atan2f128_test.cpp
@@ -0,0 +1,101 @@
+//===-- Unittests for atan2f128 -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/atan2f128.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+
+using LlvmLibcAtan2f128Test = LIBC_NAMESPACE::testing::FPTest<float128>;
+using LIBC_NAMESPACE::testing::tlog;
+
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+TEST_F(LlvmLibcAtan2f128Test, InQuadRange) {
+  constexpr StorageType X_COUNT = 123;
+  constexpr StorageType X_START =
+      FPBits(static_cast<float128>(0.25q)).uintval();
+  constexpr StorageType X_STOP = FPBits(static_cast<float128>(4.0q)).uintval();
+  constexpr StorageType X_STEP = (X_STOP - X_START) / X_COUNT;
+
+  constexpr StorageType Y_COUNT = 137;
+  constexpr StorageType Y_START =
+      FPBits(static_cast<float128>(0.25q)).uintval();
+  constexpr StorageType Y_STOP = FPBits(static_cast<float128>(4.0q)).uintval();
+  constexpr StorageType Y_STEP = (Y_STOP - Y_START) / Y_COUNT;
+
+  auto test = [&](mpfr::RoundingMode rounding_mode) {
+    mpfr::ForceRoundingMode __r(rounding_mode);
+    if (!__r.success)
+      return;
+
+    uint64_t fails = 0;
+    uint64_t finite_count = 0;
+    uint64_t total_count = 0;
+    float128 failed_x = 0.0, failed_y = 0.0, failed_r = 0.0;
+    double tol = 0.5;
+
+    for (StorageType i = 0, v = X_START; i <= X_COUNT; ++i, v += X_STEP) {
+      float128 x = FPBits(v).get_val();
+      if (FPBits(x).is_inf_or_nan() || x < 0.0q)
+        continue;
+
+      for (StorageType j = 0, w = Y_START; j <= Y_COUNT; ++j, w += Y_STEP) {
+        float128 y = FPBits(w).get_val();
+        if (FPBits(y).is_inf_or_nan())
+          continue;
+
+        float128 result = LIBC_NAMESPACE::atan2f128(x, y);
+        ++total_count;
+        if (FPBits(result).is_inf_or_nan())
+          continue;
+
+        ++finite_count;
+        mpfr::BinaryInput<float128> inputs{x, y};
+
+        if (!TEST_MPFR_MATCH_ROUNDING_SILENTLY(mpfr::Operation::Atan2, inputs,
+                                               result, 2.0, rounding_mode)) {
+          ++fails;
+          while (!TEST_MPFR_MATCH_ROUNDING_SILENTLY(
+              mpfr::Operation::Atan2, inputs, result, tol, rounding_mode)) {
+            failed_x = x;
+            failed_y = y;
+            failed_r = result;
+
+            if (tol > 1000.0)
+              break;
+
+            tol *= 2.0;
+          }
+        }
+      }
+    }
+    if (fails || (finite_count < total_count)) {
+      tlog << " Atan2 failed: " << fails << "/" << finite_count << "/"
+           << total_count << " tests.\n"
+           << "   Max ULPs is at most: " << static_cast<uint64_t>(tol) << ".\n";
+    }
+    if (fails) {
+      mpfr::BinaryInput<float128> inputs{failed_x, failed_y};
+      EXPECT_MPFR_MATCH(mpfr::Operation::Atan2, inputs, failed_r, 0.5,
+                        rounding_mode);
+    }
+  };
+
+  tlog << " Test Rounding To Nearest...\n";
+  test(mpfr::RoundingMode::Nearest);
+
+  tlog << " Test Rounding Downward...\n";
+  test(mpfr::RoundingMode::Downward);
+
+  tlog << " Test Rounding Upward...\n";
+  test(mpfr::RoundingMode::Upward);
+
+  tlog << " Test Rounding Toward Zero...\n";
+  test(mpfr::RoundingMode::TowardZero);
+}
diff --git a/test/src/math/atanf16_test.cpp b/test/src/math/atanf16_test.cpp
new file mode 100644
index 0000000..fa383e7
--- /dev/null
+++ b/test/src/math/atanf16_test.cpp
@@ -0,0 +1,40 @@
+//===-- Exhaustive test for atanf16 ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/atanf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+
+using LlvmLibcAtanf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+// Range: [0, Inf]
+static constexpr uint16_t POS_START = 0x0000U;
+static constexpr uint16_t POS_STOP = 0x7c00U;
+
+// Range: [-Inf, 0]
+static constexpr uint16_t NEG_START = 0x8000U;
+static constexpr uint16_t NEG_STOP = 0xfc00U;
+
+TEST_F(LlvmLibcAtanf16Test, PositiveRange) {
+  for (uint16_t v = POS_START; v <= POS_STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Atan, x,
+                                   LIBC_NAMESPACE::atanf16(x), 0.5);
+  }
+}
+
+TEST_F(LlvmLibcAtanf16Test, NegativeRange) {
+  for (uint16_t v = NEG_START; v <= NEG_STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Atan, x,
+                                   LIBC_NAMESPACE::atanf16(x), 0.5);
+  }
+}
diff --git a/test/src/math/atanhf16_test.cpp b/test/src/math/atanhf16_test.cpp
new file mode 100644
index 0000000..e35cc77
--- /dev/null
+++ b/test/src/math/atanhf16_test.cpp
@@ -0,0 +1,40 @@
+//===-- Unittests for atanhf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/atanhf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+#include <stdint.h>
+
+using LlvmLibcAtanhf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+// Range for positive numbers: [0, +Inf]
+static constexpr uint16_t POS_START = 0x0000U;
+static constexpr uint16_t POS_STOP = 0x7C00U;
+
+// Range for negative numbers: [-Inf, 0]
+static constexpr uint16_t NEG_START = 0x8000U;
+static constexpr uint16_t NEG_STOP = 0xFC00U;
+
+TEST_F(LlvmLibcAtanhf16Test, PositiveRange) {
+  for (uint16_t v = POS_START; v <= POS_STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Atanh, x,
+                                   LIBC_NAMESPACE::atanhf16(x), 0.5);
+  }
+}
+
+TEST_F(LlvmLibcAtanhf16Test, NegativeRange) {
+  for (uint16_t v = NEG_START; v <= NEG_STOP; ++v) {
+    float16 x = FPBits(v).get_val();
+    EXPECT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Atanh, x,
+                                   LIBC_NAMESPACE::atanhf16(x), 0.5);
+  }
+}
diff --git a/test/src/math/exhaustive/hypotf16_test.cpp b/test/src/math/exhaustive/hypotf16_test.cpp
new file mode 100644
index 0000000..f79041e
--- /dev/null
+++ b/test/src/math/exhaustive/hypotf16_test.cpp
@@ -0,0 +1,67 @@
+//===-- Exhaustive test for hypotf16 --------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "exhaustive_test.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/Hypot.h"
+#include "src/math/hypotf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+struct Hypotf16Checker : public virtual LIBC_NAMESPACE::testing::Test {
+  using FloatType = float16;
+  using FPBits = LIBC_NAMESPACE::fputil::FPBits<float16>;
+  using StorageType = typename FPBits::StorageType;
+
+  uint64_t check(uint16_t x_start, uint16_t x_stop, uint16_t y_start,
+                 uint16_t y_stop, mpfr::RoundingMode rounding) {
+    mpfr::ForceRoundingMode r(rounding);
+    if (!r.success)
+      return true;
+    uint16_t xbits = x_start;
+    uint64_t failed = 0;
+    do {
+      float16 x = FPBits(xbits).get_val();
+      uint16_t ybits = xbits;
+      do {
+        float16 y = FPBits(ybits).get_val();
+        bool correct = TEST_FP_EQ(LIBC_NAMESPACE::fputil::hypot<float16>(x, y),
+                                  LIBC_NAMESPACE::hypotf16(x, y));
+        // Using MPFR will be much slower.
+        // mpfr::BinaryInput<float16> input{x, y};
+        // bool correct = TEST_MPFR_MATCH_ROUNDING_SILENTLY(
+        //  mpfr::Operation::Hypot, input, LIBC_NAMESPACE::hypotf16(x, y),
+        // 0.5,
+        //  rounding);
+        failed += (!correct);
+      } while (ybits++ < y_stop);
+    } while (xbits++ < x_stop);
+    return failed;
+  }
+};
+
+using LlvmLibcHypotf16ExhaustiveTest =
+    LlvmLibcExhaustiveMathTest<Hypotf16Checker, 1 << 2>;
+
+// Range of both inputs: [0, inf]
+static constexpr uint16_t POS_START = 0x0000U;
+static constexpr uint16_t POS_STOP = 0x7C00U;
+
+TEST_F(LlvmLibcHypotf16ExhaustiveTest, PositiveRange) {
+  test_full_range_all_roundings(POS_START, POS_STOP, POS_START, POS_STOP);
+}
+
+// Range of both inputs: [-0, -inf]
+static constexpr uint16_t NEG_START = 0x8000U;
+static constexpr uint16_t NEG_STOP = 0xFC00U;
+
+TEST_F(LlvmLibcHypotf16ExhaustiveTest, NegativeRange) {
+  test_full_range_all_roundings(NEG_START, NEG_STOP, NEG_START, NEG_STOP);
+}
diff --git a/test/src/math/exhaustive/hypotf_test.cpp b/test/src/math/exhaustive/hypotf_test.cpp
index 04da55d..695a2fb 100644
--- a/test/src/math/exhaustive/hypotf_test.cpp
+++ b/test/src/math/exhaustive/hypotf_test.cpp
@@ -21,7 +21,7 @@ struct HypotfChecker : public virtual LIBC_NAMESPACE::testing::Test {
   using StorageType = typename FPBits::StorageType;
 
   uint64_t check(uint32_t start, uint32_t stop, mpfr::RoundingMode rounding) {
-    // Range of the second input: [2^37, 2^48).
+    // Range of the second input: [2^37, 2^48].
     constexpr uint32_t Y_START = (37U + 127U) << 23;
     constexpr uint32_t Y_STOP = (48U + 127U) << 23;
 
@@ -49,11 +49,15 @@ struct HypotfChecker : public virtual LIBC_NAMESPACE::testing::Test {
   }
 };
 
-using LlvmLibcHypotfExhaustiveTest = LlvmLibcExhaustiveMathTest<HypotfChecker>;
+using LlvmLibcHypotfExhaustiveTest =
+    LlvmLibcExhaustiveMathTest<HypotfChecker, /*Increment=*/1>;
 
-// Range of the first input: [2^23, 2^24);
+// Range of the first input: [2^23, 2^24];
 static constexpr uint32_t START = (23U + 127U) << 23;
-static constexpr uint32_t STOP = ((23U + 127U) << 23) + 1;
+// static constexpr uint32_t STOP = (24U + 127U) << 23;
+// Use a smaller range for automated tests, since the full range takes too long
+// and should only be run manually.
+static constexpr uint32_t STOP = ((23U + 127U) << 23) + 1024U;
 
 TEST_F(LlvmLibcHypotfExhaustiveTest, PositiveRange) {
   test_full_range_all_roundings(START, STOP);
diff --git a/test/src/math/exp10m1f_test.cpp b/test/src/math/exp10m1f_test.cpp
index cc96032..aee2733 100644
--- a/test/src/math/exp10m1f_test.cpp
+++ b/test/src/math/exp10m1f_test.cpp
@@ -80,7 +80,7 @@ TEST_F(LlvmLibcExp10m1fTest, InFloatRange) {
   constexpr uint32_t STEP = UINT32_MAX / COUNT;
   for (uint32_t i = 0, v = 0; i <= COUNT; ++i, v += STEP) {
     float x = FPBits(v).get_val();
-    if (isnan(x) || isinf(x))
+    if (FPBits(v).is_inf_or_nan())
       continue;
     LIBC_NAMESPACE::libc_errno = 0;
     float result = LIBC_NAMESPACE::exp10m1f(x);
@@ -89,7 +89,7 @@ TEST_F(LlvmLibcExp10m1fTest, InFloatRange) {
     // in the single-precision floating point range, then ignore comparing with
     // MPFR result as MPFR can still produce valid results because of its
     // wider precision.
-    if (isnan(result) || isinf(result) || LIBC_NAMESPACE::libc_errno != 0)
+    if (FPBits(result).is_inf_or_nan() || LIBC_NAMESPACE::libc_errno != 0)
       continue;
     ASSERT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Exp10m1, x,
                                    LIBC_NAMESPACE::exp10m1f(x), 0.5);
diff --git a/include/llvm-libc-types/DIR.h b/test/src/math/fmaf16_test.cpp
similarity index 63%
rename from include/llvm-libc-types/DIR.h
rename to test/src/math/fmaf16_test.cpp
index 855446d..233d3a7 100644
--- a/include/llvm-libc-types/DIR.h
+++ b/test/src/math/fmaf16_test.cpp
@@ -1,4 +1,4 @@
-//===-- Definition of the type DIR ----------------------------------------===//
+//===-- Unittests for fmaf16 ----------------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,9 +6,8 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef LLVM_LIBC_TYPES_DIR_H
-#define LLVM_LIBC_TYPES_DIR_H
+#include "FmaTest.h"
 
-typedef struct DIR DIR;
+#include "src/math/fmaf16.h"
 
-#endif // LLVM_LIBC_TYPES_DIR_H
+LIST_FMA_TESTS(float16, LIBC_NAMESPACE::fmaf16)
diff --git a/test/src/math/hypotf16_test.cpp b/test/src/math/hypotf16_test.cpp
new file mode 100644
index 0000000..37d5747
--- /dev/null
+++ b/test/src/math/hypotf16_test.cpp
@@ -0,0 +1,21 @@
+//===-- Unittests for hypotf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "HypotTest.h"
+
+#include "src/math/hypotf16.h"
+
+using LlvmLibcHypotf16Test = HypotTestTemplate<float16>;
+
+TEST_F(LlvmLibcHypotf16Test, SubnormalRange) {
+  test_subnormal_range(&LIBC_NAMESPACE::hypotf16);
+}
+
+TEST_F(LlvmLibcHypotf16Test, NormalRange) {
+  test_normal_range(&LIBC_NAMESPACE::hypotf16);
+}
diff --git a/test/src/math/performance_testing/BinaryOpSingleOutputPerf.h b/test/src/math/performance_testing/BinaryOpSingleOutputPerf.h
deleted file mode 100644
index 98a1813..0000000
--- a/test/src/math/performance_testing/BinaryOpSingleOutputPerf.h
+++ /dev/null
@@ -1,148 +0,0 @@
-//===-- Common utility class for differential analysis --------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/__support/CPP/algorithm.h"
-#include "src/__support/FPUtil/FPBits.h"
-#include "src/__support/macros/config.h"
-#include "test/src/math/performance_testing/Timer.h"
-
-#include <cstddef>
-#include <fstream>
-
-namespace LIBC_NAMESPACE_DECL {
-namespace testing {
-template <typename OutputType, typename InputType>
-class BinaryOpSingleOutputPerf {
-  using FPBits = fputil::FPBits<OutputType>;
-  using StorageType = typename FPBits::StorageType;
-  static constexpr StorageType UIntMax =
-      cpp::numeric_limits<StorageType>::max();
-
-public:
-  typedef OutputType Func(InputType, InputType);
-
-  static void run_perf_in_range(Func myFunc, Func otherFunc,
-                                StorageType startingBit, StorageType endingBit,
-                                size_t N, size_t rounds, std::ofstream &log) {
-    if (sizeof(StorageType) <= sizeof(size_t))
-      N = cpp::min(N, static_cast<size_t>(endingBit - startingBit));
-
-    auto runner = [=](Func func) {
-      [[maybe_unused]] volatile OutputType result;
-      if (endingBit < startingBit) {
-        return;
-      }
-
-      StorageType step = (endingBit - startingBit) / N;
-      for (size_t i = 0; i < rounds; i++) {
-        for (StorageType bitsX = startingBit, bitsY = endingBit;;
-             bitsX += step, bitsY -= step) {
-          InputType x = FPBits(bitsX).get_val();
-          InputType y = FPBits(bitsY).get_val();
-          result = func(x, y);
-          if (endingBit - bitsX < step) {
-            break;
-          }
-        }
-      }
-    };
-
-    Timer timer;
-    timer.start();
-    runner(myFunc);
-    timer.stop();
-
-    double my_average = static_cast<double>(timer.nanoseconds()) / N / rounds;
-    log << "-- My function --\n";
-    log << "     Total time      : " << timer.nanoseconds() << " ns \n";
-    log << "     Average runtime : " << my_average << " ns/op \n";
-    log << "     Ops per second  : "
-        << static_cast<uint64_t>(1'000'000'000.0 / my_average) << " op/s \n";
-
-    timer.start();
-    runner(otherFunc);
-    timer.stop();
-
-    double other_average =
-        static_cast<double>(timer.nanoseconds()) / N / rounds;
-    log << "-- Other function --\n";
-    log << "     Total time      : " << timer.nanoseconds() << " ns \n";
-    log << "     Average runtime : " << other_average << " ns/op \n";
-    log << "     Ops per second  : "
-        << static_cast<uint64_t>(1'000'000'000.0 / other_average) << " op/s \n";
-
-    log << "-- Average runtime ratio --\n";
-    log << "     Mine / Other's  : " << my_average / other_average << " \n";
-  }
-
-  static void run_perf(Func myFunc, Func otherFunc, int rounds,
-                       const char *logFile) {
-    std::ofstream log(logFile);
-    log << " Performance tests with inputs in denormal range:\n";
-    run_perf_in_range(myFunc, otherFunc, /* startingBit= */ StorageType(0),
-                      /* endingBit= */ FPBits::max_subnormal().uintval(),
-                      1'000'001, rounds, log);
-    log << "\n Performance tests with inputs in normal range:\n";
-    run_perf_in_range(myFunc, otherFunc,
-                      /* startingBit= */ FPBits::min_normal().uintval(),
-                      /* endingBit= */ FPBits::max_normal().uintval(),
-                      1'000'001, rounds, log);
-    log << "\n Performance tests with inputs in normal range with exponents "
-           "close to each other:\n";
-    run_perf_in_range(
-        myFunc, otherFunc,
-        /* startingBit= */ FPBits(OutputType(0x1.0p-10)).uintval(),
-        /* endingBit= */ FPBits(OutputType(0x1.0p+10)).uintval(), 1'000'001,
-        rounds, log);
-  }
-
-  static void run_diff(Func myFunc, Func otherFunc, const char *logFile) {
-    uint64_t diffCount = 0;
-    std::ofstream log(logFile);
-    log << " Diff tests with inputs in denormal range:\n";
-    diffCount += run_diff_in_range(
-        myFunc, otherFunc, /* startingBit= */ StorageType(0),
-        /* endingBit= */ FPBits::max_subnormal().uintval(), 1'000'001, log);
-    log << "\n Diff tests with inputs in normal range:\n";
-    diffCount += run_diff_in_range(
-        myFunc, otherFunc,
-        /* startingBit= */ FPBits::min_normal().uintval(),
-        /* endingBit= */ FPBits::max_normal().uintval(), 100'000'001, log);
-    log << "\n Diff tests with inputs in normal range with exponents "
-           "close to each other:\n";
-    diffCount += run_diff_in_range(
-        myFunc, otherFunc,
-        /* startingBit= */ FPBits(OutputType(0x1.0p-10)).uintval(),
-        /* endingBit= */ FPBits(OutputType(0x1.0p+10)).uintval(), 10'000'001,
-        log);
-
-    log << "Total number of differing results: " << diffCount << '\n';
-  }
-};
-
-} // namespace testing
-} // namespace LIBC_NAMESPACE_DECL
-
-#define BINARY_OP_SINGLE_OUTPUT_PERF(OutputType, InputType, myFunc, otherFunc, \
-                                     filename)                                 \
-  int main() {                                                                 \
-    LIBC_NAMESPACE::testing::BinaryOpSingleOutputPerf<                         \
-        OutputType, InputType>::run_perf(&myFunc, &otherFunc, 1, filename);    \
-    return 0;                                                                  \
-  }
-
-#define BINARY_OP_SINGLE_OUTPUT_PERF_EX(OutputType, InputType, myFunc,         \
-                                        otherFunc, rounds, filename)           \
-  {                                                                            \
-    LIBC_NAMESPACE::testing::BinaryOpSingleOutputPerf<                         \
-        OutputType, InputType>::run_perf(&myFunc, &otherFunc, rounds,          \
-                                         filename);                            \
-    LIBC_NAMESPACE::testing::BinaryOpSingleOutputPerf<                         \
-        OutputType, InputType>::run_perf(&myFunc, &otherFunc, rounds,          \
-                                         filename);                            \
-  }
diff --git a/test/src/math/performance_testing/PerfTest.h b/test/src/math/performance_testing/PerfTest.h
new file mode 100644
index 0000000..3cc6b24
--- /dev/null
+++ b/test/src/math/performance_testing/PerfTest.h
@@ -0,0 +1,159 @@
+//===-- Common utility class for differential analysis --------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/CPP/algorithm.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/macros/config.h"
+#include "test/src/math/performance_testing/Timer.h"
+
+#include <cstddef>
+#include <fstream>
+
+namespace LIBC_NAMESPACE_DECL {
+namespace testing {
+template <typename OutputType, typename InputType> class PerfTest {
+  using FPBits = fputil::FPBits<OutputType>;
+  using StorageType = typename FPBits::StorageType;
+  static constexpr StorageType U_INT_MAX =
+      cpp::numeric_limits<StorageType>::max();
+
+public:
+  using BinaryFuncPtr = OutputType (*)(InputType, InputType);
+  using UnaryFuncPtr = OutputType (*)(InputType);
+
+  template <bool binary, typename Func>
+  static void run_perf_in_range(Func FuncA, Func FuncB, StorageType startingBit,
+                                StorageType endingBit, size_t N, size_t rounds,
+                                const char *name_a, const char *name_b,
+                                std::ofstream &log) {
+    if (sizeof(StorageType) <= sizeof(size_t))
+      N = cpp::min(N, static_cast<size_t>(endingBit - startingBit));
+
+    auto runner = [=](Func func) {
+      [[maybe_unused]] volatile OutputType result;
+      if (endingBit < startingBit) {
+        return;
+      }
+
+      StorageType step = (endingBit - startingBit) / N;
+      if (step == 0)
+        step = 1;
+      for (size_t i = 0; i < rounds; i++) {
+        for (StorageType bits_x = startingBit, bits_y = endingBit;;
+             bits_x += step, bits_y -= step) {
+          InputType x = FPBits(bits_x).get_val();
+          if constexpr (binary) {
+            InputType y = FPBits(bits_y).get_val();
+            result = func(x, y);
+          } else {
+            result = func(x);
+          }
+          if (endingBit - bits_x < step) {
+            break;
+          }
+        }
+      }
+    };
+
+    Timer timer;
+    timer.start();
+    runner(FuncA);
+    timer.stop();
+
+    double a_average = static_cast<double>(timer.nanoseconds()) / N / rounds;
+    log << "-- Function A: " << name_a << " --\n";
+    log << "     Total time      : " << timer.nanoseconds() << " ns \n";
+    log << "     Average runtime : " << a_average << " ns/op \n";
+    log << "     Ops per second  : "
+        << static_cast<uint64_t>(1'000'000'000.0 / a_average) << " op/s \n";
+
+    timer.start();
+    runner(FuncB);
+    timer.stop();
+
+    double b_average = static_cast<double>(timer.nanoseconds()) / N / rounds;
+    log << "-- Function B: " << name_b << " --\n";
+    log << "     Total time      : " << timer.nanoseconds() << " ns \n";
+    log << "     Average runtime : " << b_average << " ns/op \n";
+    log << "     Ops per second  : "
+        << static_cast<uint64_t>(1'000'000'000.0 / b_average) << " op/s \n";
+
+    log << "-- Average ops per second ratio --\n";
+    log << "     A / B  : " << b_average / a_average << " \n";
+  }
+
+  template <bool binary, typename Func>
+  static void run_perf(Func FuncA, Func FuncB, int rounds, const char *name_a,
+                       const char *name_b, const char *logFile) {
+    std::ofstream log(logFile);
+    log << " Performance tests with inputs in denormal range:\n";
+    run_perf_in_range<binary>(
+        FuncA, FuncB, /* startingBit= */ StorageType(0),
+        /* endingBit= */ FPBits::max_subnormal().uintval(), 1'000'001, rounds,
+        name_a, name_b, log);
+    log << "\n Performance tests with inputs in normal range:\n";
+    run_perf_in_range<binary>(FuncA, FuncB,
+                              /* startingBit= */ FPBits::min_normal().uintval(),
+                              /* endingBit= */ FPBits::max_normal().uintval(),
+                              1'000'001, rounds, name_a, name_b, log);
+    log << "\n Performance tests with inputs in normal range with exponents "
+           "close to each other:\n";
+    run_perf_in_range<binary>(
+        FuncA, FuncB,
+        /* startingBit= */ FPBits(OutputType(0x1.0p-10)).uintval(),
+        /* endingBit= */ FPBits(OutputType(0x1.0p+10)).uintval(), 1'000'001,
+        rounds, name_a, name_b, log);
+  }
+};
+
+} // namespace testing
+} // namespace LIBC_NAMESPACE_DECL
+
+#define BINARY_INPUT_SINGLE_OUTPUT_PERF(OutputType, InputType, FuncA, FuncB,   \
+                                        filename)                              \
+  {                                                                            \
+    using TargetFuncPtr =                                                      \
+        typename LIBC_NAMESPACE::testing::PerfTest<OutputType,                 \
+                                                   InputType>::BinaryFuncPtr;  \
+    LIBC_NAMESPACE::testing::PerfTest<OutputType, InputType>::run_perf<true>(  \
+        static_cast<TargetFuncPtr>(&FuncA),                                    \
+        static_cast<TargetFuncPtr>(&FuncB), 1, #FuncA, #FuncB, filename);      \
+    return 0;                                                                  \
+  }
+
+#define BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(OutputType, InputType, FuncA,       \
+                                           FuncB, rounds, filename)            \
+  {                                                                            \
+    using TargetFuncPtr =                                                      \
+        typename LIBC_NAMESPACE::testing::PerfTest<OutputType,                 \
+                                                   InputType>::BinaryFuncPtr;  \
+    LIBC_NAMESPACE::testing::PerfTest<OutputType, InputType>::run_perf<true>(  \
+        static_cast<TargetFuncPtr>(&FuncA),                                    \
+        static_cast<TargetFuncPtr>(&FuncB), rounds, #FuncA, #FuncB, filename); \
+    return 0;                                                                  \
+  }
+
+#define SINGLE_INPUT_SINGLE_OUTPUT_PERF(T, FuncA, FuncB, filename)             \
+  {                                                                            \
+    using TargetFuncPtr =                                                      \
+        typename LIBC_NAMESPACE::testing::PerfTest<T, T>::UnaryFuncPtr;        \
+    LIBC_NAMESPACE::testing::PerfTest<T, T>::run_perf<false>(                  \
+        static_cast<TargetFuncPtr>(&FuncA),                                    \
+        static_cast<TargetFuncPtr>(&FuncB), 1, #FuncA, #FuncB, filename);      \
+    return 0;                                                                  \
+  }
+
+#define SINGLE_INPUT_SINGLE_OUTPUT_PERF_EX(T, FuncA, FuncB, rounds, filename)  \
+  {                                                                            \
+    using TargetFuncPtr =                                                      \
+        typename LIBC_NAMESPACE::testing::PerfTest<T, T>::UnaryFuncPtr;        \
+    LIBC_NAMESPACE::testing::PerfTest<T, T>::run_perf<false>(                  \
+        static_cast<TargetFuncPtr>(&FuncA),                                    \
+        static_cast<TargetFuncPtr>(&FuncB), rounds, #FuncA, #FuncB, filename); \
+    return 0;                                                                  \
+  }
diff --git a/test/src/math/performance_testing/SingleInputSingleOutputPerf.h b/test/src/math/performance_testing/SingleInputSingleOutputPerf.h
deleted file mode 100644
index efad125..0000000
--- a/test/src/math/performance_testing/SingleInputSingleOutputPerf.h
+++ /dev/null
@@ -1,105 +0,0 @@
-//===-- Common utility class for differential analysis --------------------===//
-//
-// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
-// See https://llvm.org/LICENSE.txt for license information.
-// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
-//
-//===----------------------------------------------------------------------===//
-
-#include "src/__support/CPP/algorithm.h"
-#include "src/__support/FPUtil/FPBits.h"
-#include "src/__support/macros/config.h"
-#include "test/src/math/performance_testing/Timer.h"
-
-#include <fstream>
-
-namespace LIBC_NAMESPACE_DECL {
-namespace testing {
-
-template <typename T> class SingleInputSingleOutputPerf {
-  using FPBits = fputil::FPBits<T>;
-  using StorageType = typename FPBits::StorageType;
-  static constexpr StorageType UIntMax =
-      cpp::numeric_limits<StorageType>::max();
-
-public:
-  typedef T Func(T);
-
-  static void runPerfInRange(Func myFunc, Func otherFunc,
-                             StorageType startingBit, StorageType endingBit,
-                             size_t rounds, std::ofstream &log) {
-    size_t n = 10'010'001;
-    if (sizeof(StorageType) <= sizeof(size_t))
-      n = cpp::min(n, static_cast<size_t>(endingBit - startingBit));
-
-    auto runner = [=](Func func) {
-      StorageType step = (endingBit - startingBit) / n;
-      if (step == 0)
-        step = 1;
-      [[maybe_unused]] volatile T result;
-      for (size_t i = 0; i < rounds; i++) {
-        for (StorageType bits = startingBit; bits < endingBit; bits += step) {
-          T x = FPBits(bits).get_val();
-          result = func(x);
-        }
-      }
-    };
-
-    Timer timer;
-    timer.start();
-    runner(myFunc);
-    timer.stop();
-
-    double myAverage = static_cast<double>(timer.nanoseconds()) / n / rounds;
-    log << "-- My function --\n";
-    log << "     Total time      : " << timer.nanoseconds() << " ns \n";
-    log << "     Average runtime : " << myAverage << " ns/op \n";
-    log << "     Ops per second  : "
-        << static_cast<uint64_t>(1'000'000'000.0 / myAverage) << " op/s \n";
-
-    timer.start();
-    runner(otherFunc);
-    timer.stop();
-
-    double otherAverage = static_cast<double>(timer.nanoseconds()) / n / rounds;
-    log << "-- Other function --\n";
-    log << "     Total time      : " << timer.nanoseconds() << " ns \n";
-    log << "     Average runtime : " << otherAverage << " ns/op \n";
-    log << "     Ops per second  : "
-        << static_cast<uint64_t>(1'000'000'000.0 / otherAverage) << " op/s \n";
-
-    log << "-- Average runtime ratio --\n";
-    log << "     Mine / Other's  : " << myAverage / otherAverage << " \n";
-  }
-
-  static void runPerf(Func myFunc, Func otherFunc, size_t rounds,
-                      const char *logFile) {
-    std::ofstream log(logFile);
-    log << " Performance tests with inputs in denormal range:\n";
-    runPerfInRange(myFunc, otherFunc, /* startingBit= */ StorageType(0),
-                   /* endingBit= */ FPBits::max_subnormal().uintval(), rounds,
-                   log);
-    log << "\n Performance tests with inputs in normal range:\n";
-    runPerfInRange(myFunc, otherFunc,
-                   /* startingBit= */ FPBits::min_normal().uintval(),
-                   /* endingBit= */ FPBits::max_normal().uintval(), rounds,
-                   log);
-  }
-};
-
-} // namespace testing
-} // namespace LIBC_NAMESPACE_DECL
-
-#define SINGLE_INPUT_SINGLE_OUTPUT_PERF(T, myFunc, otherFunc, filename)        \
-  int main() {                                                                 \
-    LIBC_NAMESPACE::testing::SingleInputSingleOutputPerf<T>::runPerf(          \
-        &myFunc, &otherFunc, 1, filename);                                     \
-    return 0;                                                                  \
-  }
-
-#define SINGLE_INPUT_SINGLE_OUTPUT_PERF_EX(T, myFunc, otherFunc, rounds,       \
-                                           filename)                           \
-  {                                                                            \
-    LIBC_NAMESPACE::testing::SingleInputSingleOutputPerf<T>::runPerf(          \
-        &myFunc, &otherFunc, rounds, filename);                                \
-  }
diff --git a/test/src/math/performance_testing/ceilf_perf.cpp b/test/src/math/performance_testing/ceilf_perf.cpp
index 04e96f6..37c5d31 100644
--- a/test/src/math/performance_testing/ceilf_perf.cpp
+++ b/test/src/math/performance_testing/ceilf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/ceilf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::ceilf, ::ceilf,
-                                "ceilf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::ceilf, ::ceilf,
+                                  "ceilf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/cosf_perf.cpp b/test/src/math/performance_testing/cosf_perf.cpp
index 1501b8b..b189c55 100644
--- a/test/src/math/performance_testing/cosf_perf.cpp
+++ b/test/src/math/performance_testing/cosf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/cosf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::cosf, ::cosf,
-                                "cosf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::cosf, ::cosf,
+                                  "cosf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/exp10f16_perf.cpp b/test/src/math/performance_testing/exp10f16_perf.cpp
index b9e76d4..8d7bb7b 100644
--- a/test/src/math/performance_testing/exp10f16_perf.cpp
+++ b/test/src/math/performance_testing/exp10f16_perf.cpp
@@ -6,8 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/exp10f16.h"
 
 // LLVM libc might be the only libc implementation with support for float16 math
diff --git a/test/src/math/performance_testing/exp2f16_perf.cpp b/test/src/math/performance_testing/exp2f16_perf.cpp
index aa58de2..c564fa1 100644
--- a/test/src/math/performance_testing/exp2f16_perf.cpp
+++ b/test/src/math/performance_testing/exp2f16_perf.cpp
@@ -6,8 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/exp2f16.h"
 
 // LLVM libc might be the only libc implementation with support for float16 math
diff --git a/test/src/math/performance_testing/exp2f_perf.cpp b/test/src/math/performance_testing/exp2f_perf.cpp
index 19a70ac..fa5a6ad 100644
--- a/test/src/math/performance_testing/exp2f_perf.cpp
+++ b/test/src/math/performance_testing/exp2f_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/exp2f.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::exp2f, ::exp2f,
-                                "exp2f_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::exp2f, ::exp2f,
+                                  "exp2f_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/expf16_perf.cpp b/test/src/math/performance_testing/expf16_perf.cpp
index bc9d9f0..7fe567c 100644
--- a/test/src/math/performance_testing/expf16_perf.cpp
+++ b/test/src/math/performance_testing/expf16_perf.cpp
@@ -6,8 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/expf16.h"
 
 // LLVM libc might be the only libc implementation with support for float16 math
diff --git a/test/src/math/performance_testing/expf_perf.cpp b/test/src/math/performance_testing/expf_perf.cpp
index 4b74351..33306d1 100644
--- a/test/src/math/performance_testing/expf_perf.cpp
+++ b/test/src/math/performance_testing/expf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/expf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::expf, ::expf,
-                                "expf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::expf, ::expf,
+                                  "expf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/expm1f_perf.cpp b/test/src/math/performance_testing/expm1f_perf.cpp
index 128ab35..a64f303 100644
--- a/test/src/math/performance_testing/expm1f_perf.cpp
+++ b/test/src/math/performance_testing/expm1f_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/expm1f.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::expm1f, ::expm1f,
-                                "expm1f_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::expm1f, ::expm1f,
+                                  "expm1f_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/fabsf_perf.cpp b/test/src/math/performance_testing/fabsf_perf.cpp
index b6c6add..7a8bd16 100644
--- a/test/src/math/performance_testing/fabsf_perf.cpp
+++ b/test/src/math/performance_testing/fabsf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/fabsf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::fabsf, ::fabsf,
-                                "fabsf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::fabsf, ::fabsf,
+                                  "fabsf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/floorf_perf.cpp b/test/src/math/performance_testing/floorf_perf.cpp
index 0f1087b..85fa739 100644
--- a/test/src/math/performance_testing/floorf_perf.cpp
+++ b/test/src/math/performance_testing/floorf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/floorf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::floorf, ::floorf,
-                                "floorf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::floorf, ::floorf,
+                                  "floorf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/fmod_perf.cpp b/test/src/math/performance_testing/fmod_perf.cpp
index 75a4242..a99a61f 100644
--- a/test/src/math/performance_testing/fmod_perf.cpp
+++ b/test/src/math/performance_testing/fmod_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/fmod.h"
 
 #include <math.h>
 
-BINARY_OP_SINGLE_OUTPUT_PERF(double, double, LIBC_NAMESPACE::fmod, ::fmod,
-                             "fmod_perf.log")
+int main() {
+  BINARY_INPUT_SINGLE_OUTPUT_PERF(double, double, LIBC_NAMESPACE::fmod, ::fmod,
+                                  "fmod_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/fmodf128_perf.cpp b/test/src/math/performance_testing/fmodf128_perf.cpp
index 8165e92..9321268 100644
--- a/test/src/math/performance_testing/fmodf128_perf.cpp
+++ b/test/src/math/performance_testing/fmodf128_perf.cpp
@@ -6,11 +6,14 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputDiff.h"
-
+#include "PerfTest.h"
+#include "src/__support/macros/properties/types.h"
 #include "src/math/fmodf128.h"
 
 #include <math.h>
 
-BINARY_OP_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::fmodf128, ::fmodf128,
-                             "fmodf128_perf.log")
+int main() {
+  BINARY_INPUT_SINGLE_OUTPUT_PERF(float128, float128, LIBC_NAMESPACE::fmodf128,
+                                  ::fmodf128, "fmodf128_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/fmodf16_perf.cpp b/test/src/math/performance_testing/fmodf16_perf.cpp
index 062bc2d..f7c492c 100644
--- a/test/src/math/performance_testing/fmodf16_perf.cpp
+++ b/test/src/math/performance_testing/fmodf16_perf.cpp
@@ -6,7 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
+#include "PerfTest.h"
 
 #include "src/__support/FPUtil/generic/FMod.h"
 #include "src/__support/macros/properties/types.h"
@@ -16,12 +16,12 @@
 #define FMOD_FUNC(U) (LIBC_NAMESPACE::fputil::generic::FMod<float16, U>::eval)
 
 int main() {
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float16, float16, FMOD_FUNC(uint16_t),
-                                  FMOD_FUNC(uint32_t), 5000,
-                                  "fmodf16_u16_vs_u32_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float16, float16, FMOD_FUNC(uint16_t),
+                                     FMOD_FUNC(uint32_t), 5000,
+                                     "fmodf16_u16_vs_u32_perf.log")
 
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float16, float16, FMOD_FUNC(uint16_t),
-                                  FMOD_FUNC(uint64_t), 5000,
-                                  "fmodf16_u16_vs_u64_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float16, float16, FMOD_FUNC(uint16_t),
+                                     FMOD_FUNC(uint64_t), 5000,
+                                     "fmodf16_u16_vs_u64_perf.log")
   return 0;
 }
diff --git a/test/src/math/performance_testing/fmodf_perf.cpp b/test/src/math/performance_testing/fmodf_perf.cpp
index b4f37ef..27cc7ed 100644
--- a/test/src/math/performance_testing/fmodf_perf.cpp
+++ b/test/src/math/performance_testing/fmodf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/fmodf.h"
 
 #include <math.h>
 
-BINARY_OP_SINGLE_OUTPUT_PERF(float, float, LIBC_NAMESPACE::fmodf, ::fmodf,
-                             "fmodf_perf.log")
+int main() {
+  BINARY_INPUT_SINGLE_OUTPUT_PERF(float, float, LIBC_NAMESPACE::fmodf, ::fmodf,
+                                  "fmodf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/fmodl_perf.cpp b/test/src/math/performance_testing/fmodl_perf.cpp
index aefdf2d..bb5a1d8 100644
--- a/test/src/math/performance_testing/fmodl_perf.cpp
+++ b/test/src/math/performance_testing/fmodl_perf.cpp
@@ -6,11 +6,14 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputDiff.h"
-
+#include "PerfTest.h"
 #include "src/math/fmodl.h"
 
 #include <math.h>
 
-BINARY_OP_SINGLE_OUTPUT_PERF(long double, LIBC_NAMESPACE::fmodl, ::fmodl,
-                             "fmodl_perf.log")
+int main() {
+  BINARY_INPUT_SINGLE_OUTPUT_PERF(long double, long double,
+                                  LIBC_NAMESPACE::fmodl, ::fmodl,
+                                  "fmodl_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/fmul_perf.cpp b/test/src/math/performance_testing/fmul_perf.cpp
index f15cfaf..0a8dcfe 100644
--- a/test/src/math/performance_testing/fmul_perf.cpp
+++ b/test/src/math/performance_testing/fmul_perf.cpp
@@ -6,7 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
+#include "PerfTest.h"
 #include "src/__support/FPUtil/generic/mul.h"
 #include "src/math/fmul.h"
 
@@ -17,8 +17,8 @@ float fmul_placeholder_binary(double x, double y) {
 }
 
 int main() {
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, double, LIBC_NAMESPACE::fmul,
-                                  fmul_placeholder_binary, DOUBLE_ROUNDS,
-                                  "fmul_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float, double, LIBC_NAMESPACE::fmul,
+                                     fmul_placeholder_binary, DOUBLE_ROUNDS,
+                                     "fmul_perf.log")
   return 0;
 }
diff --git a/test/src/math/performance_testing/fmull_perf.cpp b/test/src/math/performance_testing/fmull_perf.cpp
index 058e102..16ea375 100644
--- a/test/src/math/performance_testing/fmull_perf.cpp
+++ b/test/src/math/performance_testing/fmull_perf.cpp
@@ -6,7 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
+#include "PerfTest.h"
 #include "src/math/fmull.h"
 
 static constexpr size_t LONG_DOUBLE_ROUNDS = 40;
@@ -16,8 +16,8 @@ float fmull_placeholder_binary(long double x, long double y) {
 }
 
 int main() {
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, long double, LIBC_NAMESPACE::fmull,
-                                  fmull_placeholder_binary, LONG_DOUBLE_ROUNDS,
-                                  "fmull_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float, long double, LIBC_NAMESPACE::fmull,
+                                     fmull_placeholder_binary,
+                                     LONG_DOUBLE_ROUNDS, "fmull_perf.log")
   return 0;
 }
diff --git a/test/src/math/performance_testing/hypot_perf.cpp b/test/src/math/performance_testing/hypot_perf.cpp
index 04a493f..f7a3107 100644
--- a/test/src/math/performance_testing/hypot_perf.cpp
+++ b/test/src/math/performance_testing/hypot_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/hypot.h"
 
 #include <math.h>
 
-BINARY_OP_SINGLE_OUTPUT_PERF(double, double, LIBC_NAMESPACE::hypot, ::hypot,
-                             "hypot_perf.log")
+int main() {
+  BINARY_INPUT_SINGLE_OUTPUT_PERF(double, double, LIBC_NAMESPACE::hypot,
+                                  ::hypot, "hypot_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/hypotf16_perf.cpp b/test/src/math/performance_testing/hypotf16_perf.cpp
new file mode 100644
index 0000000..883331a
--- /dev/null
+++ b/test/src/math/performance_testing/hypotf16_perf.cpp
@@ -0,0 +1,19 @@
+//===-- Differential test for hypotf16 ------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "PerfTest.h"
+
+#include "src/__support/FPUtil/Hypot.h"
+#include "src/math/hypotf16.h"
+
+int main() {
+  BINARY_INPUT_SINGLE_OUTPUT_PERF(float16, float16, LIBC_NAMESPACE::hypotf16,
+                                  LIBC_NAMESPACE::fputil::hypot<float16>,
+                                  "hypotf16_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/hypotf_perf.cpp b/test/src/math/performance_testing/hypotf_perf.cpp
index 8a42f79..00f2233 100644
--- a/test/src/math/performance_testing/hypotf_perf.cpp
+++ b/test/src/math/performance_testing/hypotf_perf.cpp
@@ -6,11 +6,14 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
+#include "PerfTest.h"
 
 #include "src/math/hypotf.h"
 
 #include <math.h>
 
-BINARY_OP_SINGLE_OUTPUT_PERF(float, float, LIBC_NAMESPACE::hypotf, ::hypotf,
-                             "hypotf_perf.log")
+int main() {
+  BINARY_INPUT_SINGLE_OUTPUT_PERF(float, float, LIBC_NAMESPACE::hypotf,
+                                  ::hypotf, "hypotf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/log10f_perf.cpp b/test/src/math/performance_testing/log10f_perf.cpp
index 32a31b9..87e191e 100644
--- a/test/src/math/performance_testing/log10f_perf.cpp
+++ b/test/src/math/performance_testing/log10f_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/log10f.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::log10f, ::log10f,
-                                "log10f_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::log10f, ::log10f,
+                                  "log10f_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/log1pf_perf.cpp b/test/src/math/performance_testing/log1pf_perf.cpp
index 18c1684..2484b03 100644
--- a/test/src/math/performance_testing/log1pf_perf.cpp
+++ b/test/src/math/performance_testing/log1pf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/log1pf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::log1pf, ::log1pf,
-                                "log1pf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::log1pf, ::log1pf,
+                                  "log1pf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/log2f_perf.cpp b/test/src/math/performance_testing/log2f_perf.cpp
index c4c4dbf..9d0e6e5 100644
--- a/test/src/math/performance_testing/log2f_perf.cpp
+++ b/test/src/math/performance_testing/log2f_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/log2f.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::log2f, ::log2f,
-                                "log2f_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::log2f, ::log2f,
+                                  "log2f_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/logbf_perf.cpp b/test/src/math/performance_testing/logbf_perf.cpp
index eefd64b..b5e6d1f 100644
--- a/test/src/math/performance_testing/logbf_perf.cpp
+++ b/test/src/math/performance_testing/logbf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/logbf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::logbf, ::logbf,
-                                "logbf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::logbf, ::logbf,
+                                  "logbf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/logf_perf.cpp b/test/src/math/performance_testing/logf_perf.cpp
index 53f4f50..b078d9f 100644
--- a/test/src/math/performance_testing/logf_perf.cpp
+++ b/test/src/math/performance_testing/logf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/logf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::logf, ::logf,
-                                "logf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::logf, ::logf,
+                                  "logf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/max_min_funcs_perf.cpp b/test/src/math/performance_testing/max_min_funcs_perf.cpp
index b77268d..7bf9a86 100644
--- a/test/src/math/performance_testing/max_min_funcs_perf.cpp
+++ b/test/src/math/performance_testing/max_min_funcs_perf.cpp
@@ -6,7 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
+#include "PerfTest.h"
 #include "src/math/fmaxf.h"
 #include "src/math/fmaxf16.h"
 #include "src/math/fmaximum_numf.h"
@@ -35,41 +35,40 @@ float16 placeholder_binaryf16(float16 x, float16 y) { return x; }
 float placeholder_binaryf(float x, float y) { return x; }
 
 int main() {
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float16, float16, LIBC_NAMESPACE::fmaxf16,
-                                  placeholder_binaryf16, FLOAT16_ROUNDS,
-                                  "fmaxf16_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float16, float16, LIBC_NAMESPACE::fminf16,
-                                  placeholder_binaryf16, FLOAT16_ROUNDS,
-                                  "fminf16_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float16, float16, LIBC_NAMESPACE::fmaximumf16,
-                                  placeholder_binaryf16, FLOAT16_ROUNDS,
-                                  "fmaximumf16_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float16, float16, LIBC_NAMESPACE::fminimumf16,
-                                  placeholder_binaryf16, FLOAT16_ROUNDS,
-                                  "fminimumf16_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float16, float16, LIBC_NAMESPACE::fmaxf16,
+                                     placeholder_binaryf16, FLOAT16_ROUNDS,
+                                     "fmaxf16_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float16, float16, LIBC_NAMESPACE::fminf16,
+                                     placeholder_binaryf16, FLOAT16_ROUNDS,
+                                     "fminf16_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(
+      float16, float16, LIBC_NAMESPACE::fmaximumf16, placeholder_binaryf16,
+      FLOAT16_ROUNDS, "fmaximumf16_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(
+      float16, float16, LIBC_NAMESPACE::fminimumf16, placeholder_binaryf16,
+      FLOAT16_ROUNDS, "fminimumf16_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(
       float16, float16, LIBC_NAMESPACE::fmaximum_numf16, placeholder_binaryf16,
       FLOAT16_ROUNDS, "fmaximum_numf16_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(
       float16, float16, LIBC_NAMESPACE::fminimum_numf16, placeholder_binaryf16,
       FLOAT16_ROUNDS, "fminimum_numf16_perf.log")
 
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fmaxf, ::fmaxf,
-                                  FLOAT_ROUNDS, "fmaxf_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fminf, ::fminf,
-                                  FLOAT_ROUNDS, "fminf_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fmaximumf,
-                                  placeholder_binaryf, FLOAT_ROUNDS,
-                                  "fmaximumf_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fminimumf,
-                                  placeholder_binaryf, FLOAT_ROUNDS,
-                                  "fminimumf_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fmaximum_numf,
-                                  placeholder_binaryf, FLOAT_ROUNDS,
-                                  "fmaximum_numf_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fminimum_numf,
-                                  placeholder_binaryf, FLOAT_ROUNDS,
-                                  "fminimum_numf_perf.log")
-
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fmaxf,
+                                     ::fmaxf, FLOAT_ROUNDS, "fmaxf_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fminf,
+                                     ::fminf, FLOAT_ROUNDS, "fminf_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fmaximumf,
+                                     placeholder_binaryf, FLOAT_ROUNDS,
+                                     "fmaximumf_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::fminimumf,
+                                     placeholder_binaryf, FLOAT_ROUNDS,
+                                     "fminimumf_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(
+      float, float, LIBC_NAMESPACE::fmaximum_numf, placeholder_binaryf,
+      FLOAT_ROUNDS, "fmaximum_numf_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(
+      float, float, LIBC_NAMESPACE::fminimum_numf, placeholder_binaryf,
+      FLOAT_ROUNDS, "fminimum_numf_perf.log")
   return 0;
 }
diff --git a/test/src/math/performance_testing/misc_basic_ops_perf.cpp b/test/src/math/performance_testing/misc_basic_ops_perf.cpp
index 9a4522c..6f7864e 100644
--- a/test/src/math/performance_testing/misc_basic_ops_perf.cpp
+++ b/test/src/math/performance_testing/misc_basic_ops_perf.cpp
@@ -6,8 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "BinaryOpSingleOutputPerf.h"
-#include "SingleInputSingleOutputPerf.h"
+#include "PerfTest.h"
 #include "src/math/copysignf.h"
 #include "src/math/copysignf16.h"
 #include "src/math/fabsf.h"
@@ -28,14 +27,15 @@ int main() {
   SINGLE_INPUT_SINGLE_OUTPUT_PERF_EX(float16, LIBC_NAMESPACE::fabsf16,
                                      placeholder_unaryf16, FLOAT16_ROUNDS,
                                      "fabsf16_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float16, float16, LIBC_NAMESPACE::copysignf16,
-                                  placeholder_binaryf16, FLOAT16_ROUNDS,
-                                  "copysignf16_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(
+      float16, float16, LIBC_NAMESPACE::copysignf16, placeholder_binaryf16,
+      FLOAT16_ROUNDS, "copysignf16_perf.log")
 
   SINGLE_INPUT_SINGLE_OUTPUT_PERF_EX(float, LIBC_NAMESPACE::fabsf, fabsf,
                                      FLOAT_ROUNDS, "fabsf_perf.log")
-  BINARY_OP_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::copysignf,
-                                  copysignf, FLOAT_ROUNDS, "copysignf_perf.log")
+  BINARY_INPUT_SINGLE_OUTPUT_PERF_EX(float, float, LIBC_NAMESPACE::copysignf,
+                                     copysignf, FLOAT_ROUNDS,
+                                     "copysignf_perf.log")
 
   return 0;
 }
diff --git a/test/src/math/performance_testing/nearbyintf_perf.cpp b/test/src/math/performance_testing/nearbyintf_perf.cpp
index ae708dd..3fa844d 100644
--- a/test/src/math/performance_testing/nearbyintf_perf.cpp
+++ b/test/src/math/performance_testing/nearbyintf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/nearbyintf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::nearbyintf, ::nearbyintf,
-                                "nearbyintf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::nearbyintf,
+                                  ::nearbyintf, "nearbyintf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/nearest_integer_funcs_perf.cpp b/test/src/math/performance_testing/nearest_integer_funcs_perf.cpp
index b7bd663..fa5f80f 100644
--- a/test/src/math/performance_testing/nearest_integer_funcs_perf.cpp
+++ b/test/src/math/performance_testing/nearest_integer_funcs_perf.cpp
@@ -40,7 +40,8 @@ public:
   static void run_perf_in_range(Func my_func, Func other_func,
                                 StorageType starting_bit,
                                 StorageType ending_bit, StorageType step,
-                                size_t rounds, std::ofstream &log) {
+                                size_t rounds, const char *name_a,
+                                const char *name_b, std::ofstream &log) {
     auto runner = [=](Func func) {
       [[maybe_unused]] volatile T result;
       for (size_t i = 0; i < rounds; i++) {
@@ -60,7 +61,7 @@ public:
     size_t number_of_runs = (ending_bit - starting_bit) / step + 1;
     double my_average =
         static_cast<double>(timer.nanoseconds()) / number_of_runs / rounds;
-    log << "-- My function --\n";
+    log << "-- Function A: " << name_a << " --\n";
     log << "     Total time      : " << timer.nanoseconds() << " ns \n";
     log << "     Average runtime : " << my_average << " ns/op \n";
     log << "     Ops per second  : "
@@ -72,17 +73,18 @@ public:
 
     double other_average =
         static_cast<double>(timer.nanoseconds()) / number_of_runs / rounds;
-    log << "-- Other function --\n";
+    log << "-- Function B: " << name_b << " --\n";
     log << "     Total time      : " << timer.nanoseconds() << " ns \n";
     log << "     Average runtime : " << other_average << " ns/op \n";
     log << "     Ops per second  : "
         << static_cast<uint64_t>(1'000'000'000.0 / other_average) << " op/s \n";
 
-    log << "-- Average runtime ratio --\n";
-    log << "     Mine / Other's  : " << my_average / other_average << " \n";
+    log << "-- Average ops per second ratio --\n";
+    log << "     A / B  : " << other_average / my_average << " \n";
   }
 
   static void run_perf(Func my_func, Func other_func, size_t rounds,
+                       const char *name_a, const char *name_b,
                        const char *log_file) {
     std::ofstream log(log_file);
     log << "Performance tests with inputs in normal integral range:\n";
@@ -93,14 +95,14 @@ public:
         StorageType((FPBits::EXP_BIAS + FPBits::FRACTION_LEN - 1)
                     << FPBits::SIG_LEN),
         /*step=*/StorageType(1 << FPBits::SIG_LEN),
-        rounds * FPBits::EXP_BIAS * FPBits::EXP_BIAS * 2, log);
+        rounds * FPBits::EXP_BIAS * FPBits::EXP_BIAS * 2, name_a, name_b, log);
     log << "\n Performance tests with inputs in low integral range:\n";
     run_perf_in_range(
         my_func, other_func,
         /*starting_bit=*/StorageType(1 << FPBits::SIG_LEN),
         /*ending_bit=*/StorageType((FPBits::EXP_BIAS - 1) << FPBits::SIG_LEN),
         /*step_bit=*/StorageType(1 << FPBits::SIG_LEN),
-        rounds * FPBits::EXP_BIAS * FPBits::EXP_BIAS * 2, log);
+        rounds * FPBits::EXP_BIAS * FPBits::EXP_BIAS * 2, name_a, name_b, log);
     log << "\n Performance tests with inputs in high integral range:\n";
     run_perf_in_range(
         my_func, other_func,
@@ -110,7 +112,7 @@ public:
         /*ending_bit=*/
         StorageType(FPBits::MAX_BIASED_EXPONENT << FPBits::SIG_LEN),
         /*step=*/StorageType(1 << FPBits::SIG_LEN),
-        rounds * FPBits::EXP_BIAS * FPBits::EXP_BIAS * 2, log);
+        rounds * FPBits::EXP_BIAS * FPBits::EXP_BIAS * 2, name_a, name_b, log);
     log << "\n Performance tests with inputs in normal fractional range:\n";
     run_perf_in_range(
         my_func, other_func,
@@ -118,11 +120,11 @@ public:
         StorageType(((FPBits::EXP_BIAS + 1) << FPBits::SIG_LEN) + 1),
         /*ending_bit=*/
         StorageType(((FPBits::EXP_BIAS + 2) << FPBits::SIG_LEN) - 1),
-        /*step=*/StorageType(1), rounds * 2, log);
+        /*step=*/StorageType(1), rounds * 2, name_a, name_b, log);
     log << "\n Performance tests with inputs in subnormal fractional range:\n";
     run_perf_in_range(my_func, other_func, /*starting_bit=*/StorageType(1),
                       /*ending_bit=*/StorageType(FPBits::SIG_MASK),
-                      /*step=*/StorageType(1), rounds, log);
+                      /*step=*/StorageType(1), rounds, name_a, name_b, log);
   }
 };
 
@@ -131,9 +133,7 @@ public:
 #define NEAREST_INTEGER_PERF(T, my_func, other_func, rounds, filename)         \
   {                                                                            \
     LIBC_NAMESPACE::testing::NearestIntegerPerf<T>::run_perf(                  \
-        &my_func, &other_func, rounds, filename);                              \
-    LIBC_NAMESPACE::testing::NearestIntegerPerf<T>::run_perf(                  \
-        &my_func, &other_func, rounds, filename);                              \
+        &my_func, &other_func, rounds, #my_func, #other_func, filename);       \
   }
 
 static constexpr size_t FLOAT16_ROUNDS = 20'000;
diff --git a/test/src/math/performance_testing/rintf_perf.cpp b/test/src/math/performance_testing/rintf_perf.cpp
index 6347ac9..f54b19c 100644
--- a/test/src/math/performance_testing/rintf_perf.cpp
+++ b/test/src/math/performance_testing/rintf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/rintf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::rintf, ::rintf,
-                                "rintf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::rintf, ::rintf,
+                                  "rintf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/roundf_perf.cpp b/test/src/math/performance_testing/roundf_perf.cpp
index 36becac..fb2a630 100644
--- a/test/src/math/performance_testing/roundf_perf.cpp
+++ b/test/src/math/performance_testing/roundf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/roundf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::roundf, ::roundf,
-                                "roundf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::roundf, ::roundf,
+                                  "roundf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/sinf_perf.cpp b/test/src/math/performance_testing/sinf_perf.cpp
index 43ba60e..e12a4b1 100644
--- a/test/src/math/performance_testing/sinf_perf.cpp
+++ b/test/src/math/performance_testing/sinf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/sinf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::sinf, ::sinf,
-                                "sinf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::sinf, ::sinf,
+                                  "sinf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/sqrtf128_perf.cpp b/test/src/math/performance_testing/sqrtf128_perf.cpp
index bc04e69..e6a30af 100644
--- a/test/src/math/performance_testing/sqrtf128_perf.cpp
+++ b/test/src/math/performance_testing/sqrtf128_perf.cpp
@@ -7,8 +7,7 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/__support/FPUtil/sqrt.h"
 #include "src/math/sqrtf128.h"
 
@@ -16,5 +15,8 @@ float128 sqrtf128_placeholder(float128 x) {
   return LIBC_NAMESPACE::fputil::sqrt<float128>(x);
 }
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float128, LIBC_NAMESPACE::sqrtf128,
-                                ::sqrtf128_placeholder, "sqrtf128_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float128, LIBC_NAMESPACE::sqrtf128,
+                                  ::sqrtf128_placeholder, "sqrtf128_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/sqrtf_perf.cpp b/test/src/math/performance_testing/sqrtf_perf.cpp
index 7132551..a244e3c 100644
--- a/test/src/math/performance_testing/sqrtf_perf.cpp
+++ b/test/src/math/performance_testing/sqrtf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/sqrtf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::sqrtf, ::sqrtf,
-                                "sqrtf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::sqrtf, ::sqrtf,
+                                  "sqrtf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/performance_testing/truncf_perf.cpp b/test/src/math/performance_testing/truncf_perf.cpp
index ff74c6b..11c7d23 100644
--- a/test/src/math/performance_testing/truncf_perf.cpp
+++ b/test/src/math/performance_testing/truncf_perf.cpp
@@ -6,11 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "SingleInputSingleOutputPerf.h"
-
+#include "PerfTest.h"
 #include "src/math/truncf.h"
 
 #include <math.h>
 
-SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::truncf, ::truncf,
-                                "truncf_perf.log")
+int main() {
+  SINGLE_INPUT_SINGLE_OUTPUT_PERF(float, LIBC_NAMESPACE::truncf, ::truncf,
+                                  "truncf_perf.log")
+  return 0;
+}
diff --git a/test/src/math/smoke/FmaTest.h b/test/src/math/smoke/FmaTest.h
index 4109342..5d344d9 100644
--- a/test/src/math/smoke/FmaTest.h
+++ b/test/src/math/smoke/FmaTest.h
@@ -9,9 +9,7 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_FMATEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_FMATEST_H
 
-#include "src/__support/CPP/type_traits.h"
 #include "src/__support/FPUtil/cast.h"
-#include "src/__support/macros/properties/types.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
@@ -90,14 +88,8 @@ public:
     // Test overflow.
     OutType z = out.max_normal;
     InType in_z = LIBC_NAMESPACE::fputil::cast<InType>(out.max_normal);
-#if defined(LIBC_TYPES_HAS_FLOAT16) && !defined(__LIBC_USE_FLOAT16_CONVERSION)
-    // Rounding modes other than the default might not be usable with float16.
-    if constexpr (LIBC_NAMESPACE::cpp::is_same_v<OutType, float16>)
-      EXPECT_FP_EQ(OutType(0.75) * z, func(InType(1.75), in_z, -in_z));
-    else
-#endif
-      EXPECT_FP_EQ_ALL_ROUNDING(OutType(0.75) * z,
-                                func(InType(1.75), in_z, -in_z));
+    EXPECT_FP_EQ_ALL_ROUNDING(OutType(0.75) * z,
+                              func(InType(1.75), in_z, -in_z));
 
     // Exact cancellation.
     EXPECT_FP_EQ_ROUNDING_NEAREST(
diff --git a/test/src/math/smoke/acos_test.cpp b/test/src/math/smoke/acos_test.cpp
new file mode 100644
index 0000000..3a59bce
--- /dev/null
+++ b/test/src/math/smoke/acos_test.cpp
@@ -0,0 +1,64 @@
+//===-- Unittests for acos ------------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/fenv_macros.h"
+#include "src/errno/libc_errno.h"
+#include "src/math/acos.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcAcosTest = LIBC_NAMESPACE::testing::FPTest<double>;
+
+TEST_F(LlvmLibcAcosTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::acos(sNaN),
+                                           FE_INVALID);
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::acos(aNaN));
+  EXPECT_FP_EQ(0x1.921fb54442d18p0, LIBC_NAMESPACE::acos(zero));
+  EXPECT_FP_EQ(0x1.921fb54442d18p0, LIBC_NAMESPACE::acos(neg_zero));
+
+  LIBC_NAMESPACE::libc_errno = 0;
+  EXPECT_FP_EQ_WITH_EXCEPTION_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::acos(inf),
+                                           FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+  EXPECT_FP_EQ_WITH_EXCEPTION_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::acos(neg_inf),
+                                           FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+  EXPECT_FP_EQ_WITH_EXCEPTION_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::acos(2.0),
+                                           FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+  EXPECT_FP_EQ_WITH_EXCEPTION_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::acos(-2.0),
+                                           FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+  EXPECT_FP_EQ(zero, LIBC_NAMESPACE::acos(1.0));
+  EXPECT_FP_EQ(0x1.921fb54442d18p1, LIBC_NAMESPACE::acos(-1.0));
+  EXPECT_FP_EQ(0x1.921fb54442d18p0, LIBC_NAMESPACE::acos(0x1.0p-54));
+}
+
+#ifdef LIBC_TEST_FTZ_DAZ
+
+using namespace LIBC_NAMESPACE::testing;
+
+TEST_F(LlvmLibcAcosTest, FTZMode) {
+  ModifyMXCSR mxcsr(FTZ);
+
+  EXPECT_FP_EQ(0x1.921fb54442d18p0, LIBC_NAMESPACE::acos(min_denormal));
+}
+
+TEST_F(LlvmLibcAcosTest, DAZMode) {
+  ModifyMXCSR mxcsr(DAZ);
+
+  EXPECT_FP_EQ(0x1.921fb54442d18p0, LIBC_NAMESPACE::acos(min_denormal));
+}
+
+TEST_F(LlvmLibcAcosTest, FTZDAZMode) {
+  ModifyMXCSR mxcsr(FTZ | DAZ);
+
+  EXPECT_FP_EQ(0x1.921fb54442d18p0, LIBC_NAMESPACE::acos(min_denormal));
+}
+
+#endif
diff --git a/test/src/math/smoke/acosf_test.cpp b/test/src/math/smoke/acosf_test.cpp
index e5d56c7..74f68e0 100644
--- a/test/src/math/smoke/acosf_test.cpp
+++ b/test/src/math/smoke/acosf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcAcosfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcAcosfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::acosf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::acosf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/acoshf16_test.cpp b/test/src/math/smoke/acoshf16_test.cpp
new file mode 100644
index 0000000..7681c2a
--- /dev/null
+++ b/test/src/math/smoke/acoshf16_test.cpp
@@ -0,0 +1,70 @@
+//===-- Unittests for acoshf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/FPUtil/cast.h"
+#include "src/errno/libc_errno.h"
+#include "src/math/acoshf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcAcoshf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+
+TEST_F(LlvmLibcAcoshf16Test, SpecialNumbers) {
+  LIBC_NAMESPACE::libc_errno = 0;
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acoshf16(aNaN));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::acoshf16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::acoshf16(zero), FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acoshf16(neg_zero));
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::acoshf16(neg_zero),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ(inf, LIBC_NAMESPACE::acoshf16(inf));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acoshf16(neg_inf));
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::acoshf16(neg_inf),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ(zero, LIBC_NAMESPACE::acoshf16(
+                         LIBC_NAMESPACE::fputil::cast<float16>(1.0)));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acoshf16(
+                         LIBC_NAMESPACE::fputil::cast<float16>(0.5)));
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(
+      aNaN,
+      LIBC_NAMESPACE::acoshf16(LIBC_NAMESPACE::fputil::cast<float16>(-1.0)),
+      FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(
+      aNaN,
+      LIBC_NAMESPACE::acoshf16(LIBC_NAMESPACE::fputil::cast<float16>(-2.0)),
+      FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(
+      aNaN,
+      LIBC_NAMESPACE::acoshf16(LIBC_NAMESPACE::fputil::cast<float16>(-3.0)),
+      FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+}
diff --git a/test/src/math/smoke/acoshf_test.cpp b/test/src/math/smoke/acoshf_test.cpp
index c4e8825..c5ba880 100644
--- a/test/src/math/smoke/acoshf_test.cpp
+++ b/test/src/math/smoke/acoshf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcAcoshfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcAcoshfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::acoshf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::acoshf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/acospif16_test.cpp b/test/src/math/smoke/acospif16_test.cpp
new file mode 100644
index 0000000..66b9470
--- /dev/null
+++ b/test/src/math/smoke/acospif16_test.cpp
@@ -0,0 +1,38 @@
+//===-- Unittests for acospif16 -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/errno/libc_errno.h"
+#include "src/math/acospif16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcAcospif16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+TEST_F(LlvmLibcAcospif16Test, SpecialNumbers) {
+  LIBC_NAMESPACE::libc_errno = 0;
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acospif16(aNaN));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::acospif16(sNaN),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(zero, LIBC_NAMESPACE::acospif16(1.0f));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acospif16(inf));
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acospif16(neg_inf));
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acospif16(2.0f));
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::acospif16(-2.0f));
+  EXPECT_MATH_ERRNO(EDOM);
+}
diff --git a/test/src/math/smoke/asin_test.cpp b/test/src/math/smoke/asin_test.cpp
new file mode 100644
index 0000000..fdd1ba1
--- /dev/null
+++ b/test/src/math/smoke/asin_test.cpp
@@ -0,0 +1,56 @@
+//===-- Unittests for asin ------------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/fenv_macros.h"
+#include "src/math/asin.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcAsinTest = LIBC_NAMESPACE::testing::FPTest<double>;
+
+TEST_F(LlvmLibcAsinTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::asin(sNaN),
+                                           FE_INVALID);
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::asin(aNaN));
+  EXPECT_FP_EQ_ALL_ROUNDING(zero, LIBC_NAMESPACE::asin(zero));
+  EXPECT_FP_EQ_ALL_ROUNDING(neg_zero, LIBC_NAMESPACE::asin(neg_zero));
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::asin(inf));
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::asin(neg_inf));
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::asin(2.0));
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::asin(-2.0));
+  EXPECT_FP_EQ(0x1.921fb54442d18p0, LIBC_NAMESPACE::asin(1.0));
+  EXPECT_FP_EQ(-0x1.921fb54442d18p0, LIBC_NAMESPACE::asin(-1.0));
+}
+
+#ifdef LIBC_TEST_FTZ_DAZ
+
+using namespace LIBC_NAMESPACE::testing;
+
+// With FTZ/DAZ flags are set, when the inputs are denormal, the output bit
+// pattern might not be exactly 0, but they should all be equal to 0 as floating
+// points.
+
+TEST_F(LlvmLibcAsinTest, FTZMode) {
+  ModifyMXCSR mxcsr(FTZ);
+
+  EXPECT_TRUE(zero == LIBC_NAMESPACE::asin(min_denormal));
+}
+
+TEST_F(LlvmLibcAsinTest, DAZMode) {
+  ModifyMXCSR mxcsr(DAZ);
+
+  EXPECT_TRUE(zero == LIBC_NAMESPACE::asin(min_denormal));
+}
+
+TEST_F(LlvmLibcAsinTest, FTZDAZMode) {
+  ModifyMXCSR mxcsr(FTZ | DAZ);
+
+  EXPECT_TRUE(zero == LIBC_NAMESPACE::asin(min_denormal));
+}
+
+#endif
diff --git a/test/src/math/smoke/asinf_test.cpp b/test/src/math/smoke/asinf_test.cpp
index ce1576e..d817d2b 100644
--- a/test/src/math/smoke/asinf_test.cpp
+++ b/test/src/math/smoke/asinf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcAsinfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcAsinfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::asinf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::asinf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/asinhf16_test.cpp b/test/src/math/smoke/asinhf16_test.cpp
new file mode 100644
index 0000000..dcaab21
--- /dev/null
+++ b/test/src/math/smoke/asinhf16_test.cpp
@@ -0,0 +1,35 @@
+//===-- Unittests for asinhf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/errno/libc_errno.h"
+#include "src/math/asinhf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcAsinhf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+
+TEST_F(LlvmLibcAsinhf16Test, SpecialNumbers) {
+  LIBC_NAMESPACE::libc_errno = 0;
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::asinhf16(aNaN));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::asinhf16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(zero, LIBC_NAMESPACE::asinhf16(zero));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(neg_zero, LIBC_NAMESPACE::asinhf16(neg_zero));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(inf, LIBC_NAMESPACE::asinhf16(inf));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(neg_inf, LIBC_NAMESPACE::asinhf16(neg_inf));
+  EXPECT_MATH_ERRNO(0);
+}
diff --git a/test/src/math/smoke/asinhf_test.cpp b/test/src/math/smoke/asinhf_test.cpp
index 5b83ce6..4a8743c 100644
--- a/test/src/math/smoke/asinhf_test.cpp
+++ b/test/src/math/smoke/asinhf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcAsinhfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcAsinhfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::asinhf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::asinhf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/atan2_test.cpp b/test/src/math/smoke/atan2_test.cpp
index 1606c3f..a79845f 100644
--- a/test/src/math/smoke/atan2_test.cpp
+++ b/test/src/math/smoke/atan2_test.cpp
@@ -13,6 +13,18 @@
 using LlvmLibcAtan2Test = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcAtan2Test, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atan2(sNaN, sNaN),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atan2(sNaN, 1.0),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atan2(1.0, sNaN),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::atan2(aNaN, zero));
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::atan2(1.0, aNaN));
   EXPECT_FP_EQ_ALL_ROUNDING(0.0, LIBC_NAMESPACE::atan2(zero, zero));
diff --git a/test/src/math/smoke/atan2f128_test.cpp b/test/src/math/smoke/atan2f128_test.cpp
new file mode 100644
index 0000000..9d539f8
--- /dev/null
+++ b/test/src/math/smoke/atan2f128_test.cpp
@@ -0,0 +1,28 @@
+//===-- Unittests for atan2f128 -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/atan2f128.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcAtan2f128Test = LIBC_NAMESPACE::testing::FPTest<float128>;
+
+TEST_F(LlvmLibcAtan2f128Test, SpecialNumbers) {
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::atan2f128(aNaN, zero));
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::atan2f128(1.0, aNaN));
+  EXPECT_FP_EQ_ALL_ROUNDING(zero, LIBC_NAMESPACE::atan2f128(zero, zero));
+  EXPECT_FP_EQ_ALL_ROUNDING(neg_zero,
+                            LIBC_NAMESPACE::atan2f128(neg_zero, zero));
+  EXPECT_FP_EQ_ALL_ROUNDING(zero, LIBC_NAMESPACE::atan2f128(1.0, inf));
+  EXPECT_FP_EQ_ALL_ROUNDING(neg_zero, LIBC_NAMESPACE::atan2f128(-1.0, inf));
+
+  float128 x = 0x1.ffffffffffffffffffffffffffe7p1q;
+  float128 y = 0x1.fffffffffffffffffffffffffff2p1q;
+  float128 r = 0x1.921fb54442d18469898cc51701b3p-1q;
+  EXPECT_FP_EQ(r, LIBC_NAMESPACE::atan2f128(x, y));
+}
diff --git a/test/src/math/smoke/atan2f_test.cpp b/test/src/math/smoke/atan2f_test.cpp
index 94ec18d..1fbcfbe 100644
--- a/test/src/math/smoke/atan2f_test.cpp
+++ b/test/src/math/smoke/atan2f_test.cpp
@@ -18,6 +18,18 @@ using LlvmLibcAtan2fTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcAtan2fTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atan2f(sNaN, sNaN),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atan2f(sNaN, 1.0f),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atan2f(1.0f, sNaN),
+                              FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   // TODO: Strengthen errno,exception checks and remove these assert macros
   // after new matchers/test fixtures are added see:
   // https://github.com/llvm/llvm-project/issues/90653.
diff --git a/test/src/math/smoke/atan_test.cpp b/test/src/math/smoke/atan_test.cpp
index b83f315..6576db9 100644
--- a/test/src/math/smoke/atan_test.cpp
+++ b/test/src/math/smoke/atan_test.cpp
@@ -13,10 +13,10 @@
 using LlvmLibcAtanTest = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcAtanTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atan(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::atan(aNaN));
-  // atan(sNaN) = aNaN.
-  EXPECT_EQ(FPBits(aNaN).uintval(),
-            FPBits(LIBC_NAMESPACE::atan(sNaN)).uintval());
   EXPECT_FP_EQ_ALL_ROUNDING(zero, LIBC_NAMESPACE::atan(zero));
   EXPECT_FP_EQ_ALL_ROUNDING(neg_zero, LIBC_NAMESPACE::atan(neg_zero));
   // atan(+-Inf) = +- pi/2.
diff --git a/test/src/math/smoke/atanf16_test.cpp b/test/src/math/smoke/atanf16_test.cpp
new file mode 100644
index 0000000..af50287
--- /dev/null
+++ b/test/src/math/smoke/atanf16_test.cpp
@@ -0,0 +1,35 @@
+//===-- Unittests for atanf16 ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception.
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/errno/libc_errno.h"
+#include "src/math/atanf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcAtanf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+
+TEST_F(LlvmLibcAtanf16Test, SpecialNumbers) {
+  LIBC_NAMESPACE::libc_errno = 0;
+  EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::atanf16(aNaN));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atanf16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(zero, LIBC_NAMESPACE::atanf16(zero));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(neg_zero, LIBC_NAMESPACE::atanf16(neg_zero));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(0x1.92p0, LIBC_NAMESPACE::atanf16(inf));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ(-0x1.92p0, LIBC_NAMESPACE::atanf16(neg_inf));
+  EXPECT_MATH_ERRNO(0);
+}
diff --git a/test/src/math/smoke/atanf_test.cpp b/test/src/math/smoke/atanf_test.cpp
index 346b8e8..7d09a28 100644
--- a/test/src/math/smoke/atanf_test.cpp
+++ b/test/src/math/smoke/atanf_test.cpp
@@ -19,6 +19,8 @@ using LlvmLibcAtanfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 
 TEST_F(LlvmLibcAtanfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atanf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
 
   // TODO: Strengthen errno,exception checks and remove these assert macros
   // after new matchers/test fixtures are added
diff --git a/test/src/math/smoke/atanhf16_test.cpp b/test/src/math/smoke/atanhf16_test.cpp
new file mode 100644
index 0000000..81df6da
--- /dev/null
+++ b/test/src/math/smoke/atanhf16_test.cpp
@@ -0,0 +1,60 @@
+//===-- Unittests for atanhf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/FPUtil/cast.h"
+#include "src/errno/libc_errno.h"
+#include "src/math/atanhf16.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcAtanhf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
+
+TEST_F(LlvmLibcAtanhf16Test, SpecialNumbers) {
+  LIBC_NAMESPACE::libc_errno = 0;
+  EXPECT_FP_EQ_WITH_EXCEPTION_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::atanhf16(sNaN),
+                                           FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::atanhf16(aNaN));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_ALL_ROUNDING(zero, LIBC_NAMESPACE::atanhf16(zero));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_ALL_ROUNDING(neg_zero, LIBC_NAMESPACE::atanhf16(neg_zero));
+  EXPECT_MATH_ERRNO(0);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(
+      inf,
+      LIBC_NAMESPACE::atanhf16(LIBC_NAMESPACE::fputil::cast<float16>(1.0f)),
+      FE_DIVBYZERO);
+  EXPECT_MATH_ERRNO(ERANGE);
+
+  EXPECT_FP_EQ_WITH_EXCEPTION(
+      neg_inf,
+      LIBC_NAMESPACE::atanhf16(LIBC_NAMESPACE::fputil::cast<float16>(-1.0f)),
+      FE_DIVBYZERO);
+  EXPECT_MATH_ERRNO(ERANGE);
+
+  EXPECT_FP_IS_NAN_WITH_EXCEPTION(
+      LIBC_NAMESPACE::atanhf16(LIBC_NAMESPACE::fputil::cast<float16>(2.0f)),
+      FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_IS_NAN_WITH_EXCEPTION(
+      LIBC_NAMESPACE::atanhf16(LIBC_NAMESPACE::fputil::cast<float16>(-2.0f)),
+      FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::atanhf16(inf), FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+
+  EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::atanhf16(neg_inf),
+                                  FE_INVALID);
+  EXPECT_MATH_ERRNO(EDOM);
+}
diff --git a/test/src/math/smoke/atanhf_test.cpp b/test/src/math/smoke/atanhf_test.cpp
index 8300b47..73a5b81 100644
--- a/test/src/math/smoke/atanhf_test.cpp
+++ b/test/src/math/smoke/atanhf_test.cpp
@@ -21,7 +21,8 @@ using LlvmLibcAtanhfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 
 TEST_F(LlvmLibcAtanhfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
-
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::atanhf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
   // TODO: Strengthen errno,exception checks and remove these assert macros
   // after new matchers/test fixtures are added, see:
   // https://github.com/llvm/llvm-project/issues/90653
diff --git a/test/src/math/smoke/cbrt_test.cpp b/test/src/math/smoke/cbrt_test.cpp
index 092e6dd..9218f0f 100644
--- a/test/src/math/smoke/cbrt_test.cpp
+++ b/test/src/math/smoke/cbrt_test.cpp
@@ -15,6 +15,9 @@ using LlvmLibcCbrtTest = LIBC_NAMESPACE::testing::FPTest<double>;
 using LIBC_NAMESPACE::testing::tlog;
 
 TEST_F(LlvmLibcCbrtTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::cbrt(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::cbrt(aNaN));
   EXPECT_FP_EQ_ALL_ROUNDING(inf, LIBC_NAMESPACE::cbrt(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(neg_inf, LIBC_NAMESPACE::cbrt(neg_inf));
diff --git a/test/src/math/smoke/cbrtf_test.cpp b/test/src/math/smoke/cbrtf_test.cpp
index 202a5ce..5dcdf61 100644
--- a/test/src/math/smoke/cbrtf_test.cpp
+++ b/test/src/math/smoke/cbrtf_test.cpp
@@ -15,6 +15,9 @@ using LlvmLibcCbrtfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 using LIBC_NAMESPACE::testing::tlog;
 
 TEST_F(LlvmLibcCbrtfTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::cbrtf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::cbrtf(aNaN));
   EXPECT_FP_EQ_ALL_ROUNDING(inf, LIBC_NAMESPACE::cbrtf(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(neg_inf, LIBC_NAMESPACE::cbrtf(neg_inf));
diff --git a/test/src/math/smoke/cos_test.cpp b/test/src/math/smoke/cos_test.cpp
index 88d8ead..427d2c4 100644
--- a/test/src/math/smoke/cos_test.cpp
+++ b/test/src/math/smoke/cos_test.cpp
@@ -15,6 +15,9 @@ using LlvmLibcCosTest = LIBC_NAMESPACE::testing::FPTest<double>;
 using LIBC_NAMESPACE::testing::tlog;
 
 TEST_F(LlvmLibcCosTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::cos(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::cos(aNaN));
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::cos(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::cos(neg_inf));
diff --git a/test/src/math/smoke/cosf16_test.cpp b/test/src/math/smoke/cosf16_test.cpp
index 9a51d10..2638551 100644
--- a/test/src/math/smoke/cosf16_test.cpp
+++ b/test/src/math/smoke/cosf16_test.cpp
@@ -16,6 +16,9 @@ using LlvmLibcCosf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
 TEST_F(LlvmLibcCosf16Test, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::cosf16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::cosf16(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/cosf_test.cpp b/test/src/math/smoke/cosf_test.cpp
index 2e261f9..9977358 100644
--- a/test/src/math/smoke/cosf_test.cpp
+++ b/test/src/math/smoke/cosf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcCosfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcCosfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::cosf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::cosf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/coshf_test.cpp b/test/src/math/smoke/coshf_test.cpp
index fd1556b..1611ea1 100644
--- a/test/src/math/smoke/coshf_test.cpp
+++ b/test/src/math/smoke/coshf_test.cpp
@@ -21,6 +21,9 @@ using LlvmLibcCoshfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcCoshfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::coshf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::coshf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/cospif16_test.cpp b/test/src/math/smoke/cospif16_test.cpp
index 135267a..edd8ed9 100644
--- a/test/src/math/smoke/cospif16_test.cpp
+++ b/test/src/math/smoke/cospif16_test.cpp
@@ -17,6 +17,9 @@ using LlvmLibcCospif16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
 TEST_F(LlvmLibcCospif16Test, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::cospif16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::cospif16(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/cospif_test.cpp b/test/src/math/smoke/cospif_test.cpp
index bf6d86b..2015389 100644
--- a/test/src/math/smoke/cospif_test.cpp
+++ b/test/src/math/smoke/cospif_test.cpp
@@ -17,6 +17,9 @@ using LlvmLibcCospifTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcCospifTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::cospif(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::cospif(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/erff_test.cpp b/test/src/math/smoke/erff_test.cpp
index 7d2c101..a9f4994 100644
--- a/test/src/math/smoke/erff_test.cpp
+++ b/test/src/math/smoke/erff_test.cpp
@@ -17,6 +17,9 @@
 using LlvmLibcErffTest = LIBC_NAMESPACE::testing::FPTest<float>;
 
 TEST_F(LlvmLibcErffTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::erff(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::erff(aNaN));
   EXPECT_FP_EQ_ALL_ROUNDING(1.0f, LIBC_NAMESPACE::erff(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(-1.0f, LIBC_NAMESPACE::erff(neg_inf));
diff --git a/test/src/math/smoke/exp10_test.cpp b/test/src/math/smoke/exp10_test.cpp
index ca9fc35..baf8a76 100644
--- a/test/src/math/smoke/exp10_test.cpp
+++ b/test/src/math/smoke/exp10_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcExp10Test = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcExp10Test, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::exp10(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::exp10(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::exp10(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(zero, LIBC_NAMESPACE::exp10(neg_inf));
diff --git a/test/src/math/smoke/exp10f_test.cpp b/test/src/math/smoke/exp10f_test.cpp
index bcbfc96..bf39e2c 100644
--- a/test/src/math/smoke/exp10f_test.cpp
+++ b/test/src/math/smoke/exp10f_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcExp10fTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcExp10fTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::exp10f(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::exp10f(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/exp10m1f_test.cpp b/test/src/math/smoke/exp10m1f_test.cpp
index 9c65a38..2c2cfdb 100644
--- a/test/src/math/smoke/exp10m1f_test.cpp
+++ b/test/src/math/smoke/exp10m1f_test.cpp
@@ -16,6 +16,9 @@ using LlvmLibcExp10m1fTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcExp10m1fTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::exp10m1f(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_EQ(FPBits(aNaN).uintval(),
             FPBits(LIBC_NAMESPACE::exp10m1f(aNaN)).uintval());
   EXPECT_EQ(FPBits(neg_aNaN).uintval(),
diff --git a/test/src/math/smoke/exp2_test.cpp b/test/src/math/smoke/exp2_test.cpp
index d97a384..9ab9129 100644
--- a/test/src/math/smoke/exp2_test.cpp
+++ b/test/src/math/smoke/exp2_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcExp2Test = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcExp2Test, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::exp2(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::exp2(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::exp2(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(zero, LIBC_NAMESPACE::exp2(neg_inf));
diff --git a/test/src/math/smoke/exp2f_test.cpp b/test/src/math/smoke/exp2f_test.cpp
index d9cdecb..a928389 100644
--- a/test/src/math/smoke/exp2f_test.cpp
+++ b/test/src/math/smoke/exp2f_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcExp2fTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcExp2fTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::exp2f(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::exp2f(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/exp2m1f_test.cpp b/test/src/math/smoke/exp2m1f_test.cpp
index 4657d08..99bdf00 100644
--- a/test/src/math/smoke/exp2m1f_test.cpp
+++ b/test/src/math/smoke/exp2m1f_test.cpp
@@ -18,6 +18,9 @@ using LIBC_NAMESPACE::fputil::testing::RoundingMode;
 TEST_F(LlvmLibcExp2m1fTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::exp2m1f(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::exp2m1f(aNaN));
   EXPECT_FP_EQ_ALL_ROUNDING(inf, LIBC_NAMESPACE::exp2m1f(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(-1.0f, LIBC_NAMESPACE::exp2m1f(neg_inf));
diff --git a/test/src/math/smoke/exp_test.cpp b/test/src/math/smoke/exp_test.cpp
index d2467ff..f862430 100644
--- a/test/src/math/smoke/exp_test.cpp
+++ b/test/src/math/smoke/exp_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcExpTest = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcExpTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::exp(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::exp(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::exp(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(zero, LIBC_NAMESPACE::exp(neg_inf));
diff --git a/test/src/math/smoke/expf_test.cpp b/test/src/math/smoke/expf_test.cpp
index 11181ed..eee8304 100644
--- a/test/src/math/smoke/expf_test.cpp
+++ b/test/src/math/smoke/expf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcExpfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcExpfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::expf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::expf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/expm1_test.cpp b/test/src/math/smoke/expm1_test.cpp
index cebd2d7..bc71c53 100644
--- a/test/src/math/smoke/expm1_test.cpp
+++ b/test/src/math/smoke/expm1_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcExpm1Test = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcExpm1Test, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::expm1(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::expm1(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::expm1(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(-1.0, LIBC_NAMESPACE::expm1(neg_inf));
diff --git a/test/src/math/smoke/expm1f_test.cpp b/test/src/math/smoke/expm1f_test.cpp
index f4138aa..dfb474d 100644
--- a/test/src/math/smoke/expm1f_test.cpp
+++ b/test/src/math/smoke/expm1f_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcExpm1fTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcExpm1fTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::expm1f(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::expm1f(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/include/llvm-libc-types/FILE.h b/test/src/math/smoke/fmaf16_test.cpp
similarity index 62%
rename from include/llvm-libc-types/FILE.h
rename to test/src/math/smoke/fmaf16_test.cpp
index f1d2e4f..233d3a7 100644
--- a/include/llvm-libc-types/FILE.h
+++ b/test/src/math/smoke/fmaf16_test.cpp
@@ -1,4 +1,4 @@
-//===-- Definition of the type FILE ---------------------------------------===//
+//===-- Unittests for fmaf16 ----------------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,9 +6,8 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef LLVM_LIBC_TYPES_FILE_H
-#define LLVM_LIBC_TYPES_FILE_H
+#include "FmaTest.h"
 
-typedef struct FILE FILE;
+#include "src/math/fmaf16.h"
 
-#endif // LLVM_LIBC_TYPES_FILE_H
+LIST_FMA_TESTS(float16, LIBC_NAMESPACE::fmaf16)
diff --git a/include/llvm-libc-types/cnd_t.h b/test/src/math/smoke/hypotf16_test.cpp
similarity index 52%
rename from include/llvm-libc-types/cnd_t.h
rename to test/src/math/smoke/hypotf16_test.cpp
index 77ec583..b48b093 100644
--- a/include/llvm-libc-types/cnd_t.h
+++ b/test/src/math/smoke/hypotf16_test.cpp
@@ -1,4 +1,4 @@
-//===-- Definition of cnd_t type ------------------------------------------===//
+//===-- Unittests for hypotf16 --------------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,15 +6,12 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef LLVM_LIBC_TYPES_CND_T_H
-#define LLVM_LIBC_TYPES_CND_T_H
+#include "HypotTest.h"
 
-#include "__futex_word.h"
+#include "src/math/hypotf16.h"
 
-typedef struct {
-  void *__qfront;
-  void *__qback;
-  __futex_word __qmtx;
-} cnd_t;
+using LlvmLibcHypotf16Test = HypotTestTemplate<float16>;
 
-#endif // LLVM_LIBC_TYPES_CND_T_H
+TEST_F(LlvmLibcHypotf16Test, SpecialNumbers) {
+  test_special_numbers(&LIBC_NAMESPACE::hypotf16);
+}
diff --git a/test/src/math/smoke/log10_test.cpp b/test/src/math/smoke/log10_test.cpp
index 9f159f2..ff73850 100644
--- a/test/src/math/smoke/log10_test.cpp
+++ b/test/src/math/smoke/log10_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcLog10Test = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcLog10Test, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::log10(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::log10(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::log10(inf));
   EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::log10(neg_inf), FE_INVALID);
diff --git a/test/src/math/smoke/log10f_test.cpp b/test/src/math/smoke/log10f_test.cpp
index 4e3bf65..a638221 100644
--- a/test/src/math/smoke/log10f_test.cpp
+++ b/test/src/math/smoke/log10f_test.cpp
@@ -17,6 +17,9 @@
 using LlvmLibcLog10fTest = LIBC_NAMESPACE::testing::FPTest<float>;
 
 TEST_F(LlvmLibcLog10fTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::log10f(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::log10f(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::log10f(inf));
   EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::log10f(neg_inf), FE_INVALID);
diff --git a/test/src/math/smoke/log1p_test.cpp b/test/src/math/smoke/log1p_test.cpp
index b98c0f2..631c24b 100644
--- a/test/src/math/smoke/log1p_test.cpp
+++ b/test/src/math/smoke/log1p_test.cpp
@@ -16,6 +16,9 @@
 using LlvmLibcLog1pTest = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcLog1pTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::log1p(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::log1p(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::log1p(inf));
   EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::log1p(neg_inf), FE_INVALID);
diff --git a/test/src/math/smoke/log1pf_test.cpp b/test/src/math/smoke/log1pf_test.cpp
index 1b0a1d5..bd828ad 100644
--- a/test/src/math/smoke/log1pf_test.cpp
+++ b/test/src/math/smoke/log1pf_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcLog1pfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 
 TEST_F(LlvmLibcLog1pfTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::log1pf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::log1pf(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::log1pf(inf));
   EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::log1pf(neg_inf), FE_INVALID);
diff --git a/test/src/math/smoke/log2_test.cpp b/test/src/math/smoke/log2_test.cpp
index 1570d60..9993d44 100644
--- a/test/src/math/smoke/log2_test.cpp
+++ b/test/src/math/smoke/log2_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcLog2Test = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcLog2Test, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::log2(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::log2(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::log2(inf));
   EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::log2(neg_inf), FE_INVALID);
diff --git a/test/src/math/smoke/log2f_test.cpp b/test/src/math/smoke/log2f_test.cpp
index 67b2c5b..8648b75 100644
--- a/test/src/math/smoke/log2f_test.cpp
+++ b/test/src/math/smoke/log2f_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcLog2fTest = LIBC_NAMESPACE::testing::FPTest<float>;
 
 TEST_F(LlvmLibcLog2fTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::log2f(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::log2f(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::log2f(inf));
   EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::log2f(neg_inf), FE_INVALID);
diff --git a/test/src/math/smoke/log_test.cpp b/test/src/math/smoke/log_test.cpp
index 20b974d..d31eb0c 100644
--- a/test/src/math/smoke/log_test.cpp
+++ b/test/src/math/smoke/log_test.cpp
@@ -18,6 +18,9 @@
 using LlvmLibcLogTest = LIBC_NAMESPACE::testing::FPTest<double>;
 
 TEST_F(LlvmLibcLogTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::log(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::log(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::log(inf));
   EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::log(neg_inf), FE_INVALID);
diff --git a/test/src/math/smoke/logf_test.cpp b/test/src/math/smoke/logf_test.cpp
index 1a3102a..faba50e 100644
--- a/test/src/math/smoke/logf_test.cpp
+++ b/test/src/math/smoke/logf_test.cpp
@@ -17,6 +17,9 @@
 using LlvmLibcLogfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 
 TEST_F(LlvmLibcLogfTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::logf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::logf(aNaN));
   EXPECT_FP_EQ(inf, LIBC_NAMESPACE::logf(inf));
   EXPECT_FP_IS_NAN_WITH_EXCEPTION(LIBC_NAMESPACE::logf(neg_inf), FE_INVALID);
diff --git a/test/src/math/smoke/nan_test.cpp b/test/src/math/smoke/nan_test.cpp
index e45e2e6..e8376c0 100644
--- a/test/src/math/smoke/nan_test.cpp
+++ b/test/src/math/smoke/nan_test.cpp
@@ -46,6 +46,6 @@ TEST_F(LlvmLibcNanTest, RandomString) {
 
 #if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
 TEST_F(LlvmLibcNanTest, InvalidInput) {
-  EXPECT_DEATH([] { LIBC_NAMESPACE::nan(nullptr); });
+  EXPECT_DEATH([] { LIBC_NAMESPACE::nan(nullptr); }, WITH_SIGNAL(-1));
 }
 #endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/math/smoke/nanf128_test.cpp b/test/src/math/smoke/nanf128_test.cpp
index aa59b79..a63ce88 100644
--- a/test/src/math/smoke/nanf128_test.cpp
+++ b/test/src/math/smoke/nanf128_test.cpp
@@ -57,6 +57,6 @@ TEST_F(LlvmLibcNanf128Test, RandomString) {
 
 #if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
 TEST_F(LlvmLibcNanf128Test, InvalidInput) {
-  EXPECT_DEATH([] { LIBC_NAMESPACE::nanf128(nullptr); });
+  EXPECT_DEATH([] { LIBC_NAMESPACE::nanf128(nullptr); }, WITH_SIGNAL(-1));
 }
 #endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/math/smoke/nanf16_test.cpp b/test/src/math/smoke/nanf16_test.cpp
index 04a8c7b..694470b 100644
--- a/test/src/math/smoke/nanf16_test.cpp
+++ b/test/src/math/smoke/nanf16_test.cpp
@@ -45,6 +45,6 @@ TEST_F(LlvmLibcNanf16Test, RandomString) {
 
 #if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
 TEST_F(LlvmLibcNanf16Test, InvalidInput) {
-  EXPECT_DEATH([] { LIBC_NAMESPACE::nanf16(nullptr); });
+  EXPECT_DEATH([] { LIBC_NAMESPACE::nanf16(nullptr); }, WITH_SIGNAL(-1));
 }
 #endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/math/smoke/nanf_test.cpp b/test/src/math/smoke/nanf_test.cpp
index 40e90c4..cb57f65 100644
--- a/test/src/math/smoke/nanf_test.cpp
+++ b/test/src/math/smoke/nanf_test.cpp
@@ -45,6 +45,6 @@ TEST_F(LlvmLibcNanfTest, RandomString) {
 
 #if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
 TEST_F(LlvmLibcNanfTest, InvalidInput) {
-  EXPECT_DEATH([] { LIBC_NAMESPACE::nanf(nullptr); });
+  EXPECT_DEATH([] { LIBC_NAMESPACE::nanf(nullptr); }, WITH_SIGNAL(-1));
 }
 #endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/math/smoke/nanl_test.cpp b/test/src/math/smoke/nanl_test.cpp
index dea969f..3bcb914 100644
--- a/test/src/math/smoke/nanl_test.cpp
+++ b/test/src/math/smoke/nanl_test.cpp
@@ -73,6 +73,6 @@ TEST_F(LlvmLibcNanlTest, RandomString) {
 
 #if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
 TEST_F(LlvmLibcNanlTest, InvalidInput) {
-  EXPECT_DEATH([] { LIBC_NAMESPACE::nanl(nullptr); });
+  EXPECT_DEATH([] { LIBC_NAMESPACE::nanl(nullptr); }, WITH_SIGNAL(-1));
 }
 #endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/math/smoke/pow_test.cpp b/test/src/math/smoke/pow_test.cpp
index f9db7f1..b27134a 100644
--- a/test/src/math/smoke/pow_test.cpp
+++ b/test/src/math/smoke/pow_test.cpp
@@ -29,7 +29,33 @@ TEST_F(LlvmLibcPowTest, SpecialNumbers) {
     if (!__r.success)
       continue;
 
+    // pow( sNaN, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(sNaN, sNaN),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(
+        aNaN, LIBC_NAMESPACE::pow(sNaN, NEG_ODD_INTEGER), FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(
+        aNaN, LIBC_NAMESPACE::pow(sNaN, NEG_EVEN_INTEGER), FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(
+        aNaN, LIBC_NAMESPACE::pow(sNaN, POS_ODD_INTEGER), FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(
+        aNaN, LIBC_NAMESPACE::pow(sNaN, POS_EVEN_INTEGER), FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(sNaN, ONE_HALF),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(sNaN, zero),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(sNaN, neg_zero),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(sNaN, inf),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(sNaN, neg_inf),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(sNaN, aNaN),
+                                FE_INVALID);
+
     // pow( 0.0, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(zero, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ_WITH_EXCEPTION(inf, LIBC_NAMESPACE::pow(zero, NEG_ODD_INTEGER),
                                 FE_DIVBYZERO);
     EXPECT_FP_EQ_WITH_EXCEPTION(
@@ -48,6 +74,8 @@ TEST_F(LlvmLibcPowTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::pow(zero, aNaN));
 
     // pow( -0.0, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(neg_zero, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ_WITH_EXCEPTION(
         neg_inf, LIBC_NAMESPACE::pow(neg_zero, NEG_ODD_INTEGER), FE_DIVBYZERO);
     EXPECT_FP_EQ_WITH_EXCEPTION(
@@ -66,6 +94,8 @@ TEST_F(LlvmLibcPowTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::pow(neg_zero, aNaN));
 
     // pow( 1.0, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(1.0, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(1.0, zero));
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(1.0, neg_zero));
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(1.0, 1.0));
@@ -80,7 +110,9 @@ TEST_F(LlvmLibcPowTest, SpecialNumbers) {
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(1.0, neg_inf));
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(1.0, aNaN));
 
-    // pow( 1.0, exponent )
+    // pow( -1.0, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(-1.0, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(-1.0, zero));
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(-1.0, neg_zero));
     EXPECT_FP_EQ(-1.0, LIBC_NAMESPACE::pow(-1.0, 1.0));
@@ -98,6 +130,8 @@ TEST_F(LlvmLibcPowTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::pow(-1.0, aNaN));
 
     // pow( inf, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(inf, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(inf, zero));
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(inf, neg_zero));
     EXPECT_FP_EQ(inf, LIBC_NAMESPACE::pow(inf, 1.0));
@@ -114,6 +148,8 @@ TEST_F(LlvmLibcPowTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::pow(inf, aNaN));
 
     // pow( -inf, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(neg_inf, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(neg_inf, zero));
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(neg_inf, neg_zero));
     EXPECT_FP_EQ(neg_inf, LIBC_NAMESPACE::pow(neg_inf, 1.0));
@@ -130,6 +166,8 @@ TEST_F(LlvmLibcPowTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::pow(neg_inf, aNaN));
 
     // pow ( aNaN, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::pow(aNaN, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(aNaN, zero));
     EXPECT_FP_EQ(1.0, LIBC_NAMESPACE::pow(aNaN, neg_zero));
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::pow(aNaN, 1.0));
diff --git a/test/src/math/smoke/powf_test.cpp b/test/src/math/smoke/powf_test.cpp
index 9cc95ce..0d1a650 100644
--- a/test/src/math/smoke/powf_test.cpp
+++ b/test/src/math/smoke/powf_test.cpp
@@ -32,7 +32,33 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     if (!__r.success)
       continue;
 
+    // pow( sNaN, exponent)
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(sNaN, sNaN),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(
+        aNaN, LIBC_NAMESPACE::powf(sNaN, neg_odd_integer), FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(
+        aNaN, LIBC_NAMESPACE::powf(sNaN, neg_even_integer), FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(
+        aNaN, LIBC_NAMESPACE::powf(sNaN, pos_odd_integer), FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(
+        aNaN, LIBC_NAMESPACE::powf(sNaN, pos_even_integer), FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(sNaN, one_half),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(sNaN, zero),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(sNaN, neg_zero),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(sNaN, inf),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(sNaN, neg_inf),
+                                FE_INVALID);
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(sNaN, aNaN),
+                                FE_INVALID);
+
     // pow( 0.0f, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(zero, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ_WITH_EXCEPTION(
         inf, LIBC_NAMESPACE::powf(zero, neg_odd_integer), FE_DIVBYZERO);
     EXPECT_FP_EQ_WITH_EXCEPTION(
@@ -51,6 +77,8 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::powf(zero, aNaN));
 
     // pow( -0.0f, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(neg_zero, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ_WITH_EXCEPTION(
         neg_inf, LIBC_NAMESPACE::powf(neg_zero, neg_odd_integer), FE_DIVBYZERO);
     EXPECT_FP_EQ_WITH_EXCEPTION(
@@ -69,6 +97,8 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::powf(neg_zero, aNaN));
 
     // pow( 1.0f, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(1.0f, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(1.0f, zero));
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(1.0f, neg_zero));
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(1.0f, 1.0f));
@@ -83,7 +113,9 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(1.0f, neg_inf));
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(1.0f, aNaN));
 
-    // pow( 1.0f, exponent )
+    // pow( -1.0f, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(-1.0f, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(-1.0f, zero));
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(-1.0f, neg_zero));
     EXPECT_FP_EQ(-1.0f, LIBC_NAMESPACE::powf(-1.0f, 1.0f));
@@ -101,6 +133,8 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::powf(-1.0f, aNaN));
 
     // pow( inf, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(inf, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(inf, zero));
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(inf, neg_zero));
     EXPECT_FP_EQ(inf, LIBC_NAMESPACE::powf(inf, 1.0f));
@@ -117,6 +151,8 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::powf(inf, aNaN));
 
     // pow( -inf, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(neg_inf, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(neg_inf, zero));
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(neg_inf, neg_zero));
     EXPECT_FP_EQ(neg_inf, LIBC_NAMESPACE::powf(neg_inf, 1.0f));
@@ -133,6 +169,8 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::powf(neg_inf, aNaN));
 
     // pow ( aNaN, exponent )
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(aNaN, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(aNaN, zero));
     EXPECT_FP_EQ(1.0f, LIBC_NAMESPACE::powf(aNaN, neg_zero));
     EXPECT_FP_IS_NAN(LIBC_NAMESPACE::powf(aNaN, 1.0f));
@@ -160,6 +198,8 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     EXPECT_FP_EQ(zero, LIBC_NAMESPACE::powf(-1.1f, neg_inf));
 
     // Exact powers of 2:
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(2.0f, sNaN),
+                                FE_INVALID);
     EXPECT_FP_EQ(0x1.0p15f, LIBC_NAMESPACE::powf(2.0f, 15.0f));
     EXPECT_FP_EQ(0x1.0p126f, LIBC_NAMESPACE::powf(2.0f, 126.0f));
     EXPECT_FP_EQ(0x1.0p-45f, LIBC_NAMESPACE::powf(2.0f, -45.0f));
@@ -178,6 +218,8 @@ TEST_F(LlvmLibcPowfTest, SpecialNumbers) {
     EXPECT_FP_EQ(100000000.0f, LIBC_NAMESPACE::powf(10.0f, 8.0f));
     EXPECT_FP_EQ(1000000000.0f, LIBC_NAMESPACE::powf(10.0f, 9.0f));
     EXPECT_FP_EQ(10000000000.0f, LIBC_NAMESPACE::powf(10.0f, 10.0f));
+    EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::powf(10.0f, sNaN),
+                                FE_INVALID);
 
     // Overflow / Underflow:
     if (ROUNDING_MODES[i] != RoundingMode::Downward &&
diff --git a/test/src/math/smoke/sin_test.cpp b/test/src/math/smoke/sin_test.cpp
index 7dd1b7f..da6d71b 100644
--- a/test/src/math/smoke/sin_test.cpp
+++ b/test/src/math/smoke/sin_test.cpp
@@ -15,6 +15,9 @@ using LlvmLibcSinTest = LIBC_NAMESPACE::testing::FPTest<double>;
 using LIBC_NAMESPACE::testing::tlog;
 
 TEST_F(LlvmLibcSinTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::sin(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::sin(aNaN));
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::sin(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::sin(neg_inf));
diff --git a/test/src/math/smoke/sincos_test.cpp b/test/src/math/smoke/sincos_test.cpp
index 371c0ad..8bc584d 100644
--- a/test/src/math/smoke/sincos_test.cpp
+++ b/test/src/math/smoke/sincos_test.cpp
@@ -15,6 +15,11 @@ using LlvmLibcSincosTest = LIBC_NAMESPACE::testing::FPTest<double>;
 TEST_F(LlvmLibcSincosTest, SpecialNumbers) {
   double sin_x, cos_x;
 
+  LIBC_NAMESPACE::sincos(sNaN, &sin_x, &cos_x);
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, cos_x);
+  EXPECT_FP_EQ_ALL_ROUNDING(aNaN, sin_x);
+  EXPECT_MATH_ERRNO(0);
+
   LIBC_NAMESPACE::sincos(aNaN, &sin_x, &cos_x);
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, cos_x);
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, sin_x);
diff --git a/test/src/math/smoke/sincosf_test.cpp b/test/src/math/smoke/sincosf_test.cpp
index e6896ca..5f66868 100644
--- a/test/src/math/smoke/sincosf_test.cpp
+++ b/test/src/math/smoke/sincosf_test.cpp
@@ -21,6 +21,11 @@ TEST_F(LlvmLibcSinCosfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
   float sin, cos;
 
+  LIBC_NAMESPACE::sincosf(sNaN, &sin, &cos);
+  EXPECT_FP_EQ(aNaN, cos);
+  EXPECT_FP_EQ(aNaN, sin);
+  EXPECT_MATH_ERRNO(0);
+
   LIBC_NAMESPACE::sincosf(aNaN, &sin, &cos);
   EXPECT_FP_EQ(aNaN, cos);
   EXPECT_FP_EQ(aNaN, sin);
diff --git a/test/src/math/smoke/sinf16_test.cpp b/test/src/math/smoke/sinf16_test.cpp
index 2966c3c..a0e7a7b 100644
--- a/test/src/math/smoke/sinf16_test.cpp
+++ b/test/src/math/smoke/sinf16_test.cpp
@@ -16,6 +16,9 @@ using LlvmLibcSinf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
 TEST_F(LlvmLibcSinf16Test, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::sinf16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::sinf16(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/sinf_test.cpp b/test/src/math/smoke/sinf_test.cpp
index 776c66d..de504b4 100644
--- a/test/src/math/smoke/sinf_test.cpp
+++ b/test/src/math/smoke/sinf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcSinfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcSinfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::sinf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::sinf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/sinhf_test.cpp b/test/src/math/smoke/sinhf_test.cpp
index 3cc0656..e22cfc7 100644
--- a/test/src/math/smoke/sinhf_test.cpp
+++ b/test/src/math/smoke/sinhf_test.cpp
@@ -21,6 +21,9 @@ using LlvmLibcSinhfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcSinhfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::sinhf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::sinhf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/sinpif16_test.cpp b/test/src/math/smoke/sinpif16_test.cpp
index a79fd52..b2db6fb 100644
--- a/test/src/math/smoke/sinpif16_test.cpp
+++ b/test/src/math/smoke/sinpif16_test.cpp
@@ -17,6 +17,9 @@ using LlvmLibcSinpif16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
 TEST_F(LlvmLibcSinpif16Test, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::sinpif16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::sinpif16(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/sinpif_test.cpp b/test/src/math/smoke/sinpif_test.cpp
index 11bda0b..1ba5c1d 100644
--- a/test/src/math/smoke/sinpif_test.cpp
+++ b/test/src/math/smoke/sinpif_test.cpp
@@ -17,6 +17,9 @@ using LlvmLibcSinpifTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcSinpifTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::sinpif(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::sinpif(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/tan_test.cpp b/test/src/math/smoke/tan_test.cpp
index aa5c23d..6538990 100644
--- a/test/src/math/smoke/tan_test.cpp
+++ b/test/src/math/smoke/tan_test.cpp
@@ -15,6 +15,9 @@ using LlvmLibcTanTest = LIBC_NAMESPACE::testing::FPTest<double>;
 using LIBC_NAMESPACE::testing::tlog;
 
 TEST_F(LlvmLibcTanTest, SpecialNumbers) {
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::tan(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::tan(aNaN));
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::tan(inf));
   EXPECT_FP_EQ_ALL_ROUNDING(aNaN, LIBC_NAMESPACE::tan(neg_inf));
diff --git a/test/src/math/smoke/tanf16_test.cpp b/test/src/math/smoke/tanf16_test.cpp
index 39d1182..f65b9fc 100644
--- a/test/src/math/smoke/tanf16_test.cpp
+++ b/test/src/math/smoke/tanf16_test.cpp
@@ -17,6 +17,9 @@ using LlvmLibcTanf16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
 TEST_F(LlvmLibcTanf16Test, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::tanf16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::tanf16(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/tanf_test.cpp b/test/src/math/smoke/tanf_test.cpp
index 93fbfde..178e906 100644
--- a/test/src/math/smoke/tanf_test.cpp
+++ b/test/src/math/smoke/tanf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcTanfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcTanfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::tanf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::tanf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/tanhf_test.cpp b/test/src/math/smoke/tanhf_test.cpp
index 3b7faa8..c09761e 100644
--- a/test/src/math/smoke/tanhf_test.cpp
+++ b/test/src/math/smoke/tanhf_test.cpp
@@ -20,6 +20,9 @@ using LlvmLibcTanhfTest = LIBC_NAMESPACE::testing::FPTest<float>;
 TEST_F(LlvmLibcTanhfTest, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::tanhf(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::tanhf(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/math/smoke/tanpif16_test.cpp b/test/src/math/smoke/tanpif16_test.cpp
index a378cfb..74797d1 100644
--- a/test/src/math/smoke/tanpif16_test.cpp
+++ b/test/src/math/smoke/tanpif16_test.cpp
@@ -16,6 +16,9 @@ using LlvmLibcTanpif16Test = LIBC_NAMESPACE::testing::FPTest<float16>;
 TEST_F(LlvmLibcTanpif16Test, SpecialNumbers) {
   LIBC_NAMESPACE::libc_errno = 0;
 
+  EXPECT_FP_EQ_WITH_EXCEPTION(aNaN, LIBC_NAMESPACE::tanpif16(sNaN), FE_INVALID);
+  EXPECT_MATH_ERRNO(0);
+
   EXPECT_FP_EQ(aNaN, LIBC_NAMESPACE::tanpif16(aNaN));
   EXPECT_MATH_ERRNO(0);
 
diff --git a/test/src/search/lfind_test.cpp b/test/src/search/lfind_test.cpp
index 00384f7..21f810a 100644
--- a/test/src/search/lfind_test.cpp
+++ b/test/src/search/lfind_test.cpp
@@ -9,10 +9,14 @@
 #include "src/search/lfind.h"
 #include "test/UnitTest/Test.h"
 
+namespace {
+
 int compar(const void *a, const void *b) {
   return *reinterpret_cast<const int *>(a) != *reinterpret_cast<const int *>(b);
 }
 
+} // namespace
+
 TEST(LlvmLibcLfindTest, SearchHead) {
   int list[3] = {1, 2, 3};
   size_t len = 3;
diff --git a/test/src/search/lsearch_test.cpp b/test/src/search/lsearch_test.cpp
index 9e58b87..864e3ec 100644
--- a/test/src/search/lsearch_test.cpp
+++ b/test/src/search/lsearch_test.cpp
@@ -9,10 +9,14 @@
 #include "src/search/lsearch.h"
 #include "test/UnitTest/Test.h"
 
+namespace {
+
 int compar(const void *a, const void *b) {
   return *reinterpret_cast<const int *>(a) != *reinterpret_cast<const int *>(b);
 }
 
+} // namespace
+
 TEST(LlvmLibcLsearchTest, SearchHead) {
   int list[3] = {1, 2, 3};
   size_t len = 3;
diff --git a/test/src/setjmp/sigsetjmp_test.cpp b/test/src/setjmp/sigsetjmp_test.cpp
new file mode 100644
index 0000000..cf8d2f2
--- /dev/null
+++ b/test/src/setjmp/sigsetjmp_test.cpp
@@ -0,0 +1,88 @@
+//===-- Unittests for sigsetjmp and siglongjmp ----------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/setjmp/siglongjmp.h"
+#include "src/setjmp/sigsetjmp.h"
+#include "src/signal/sigprocmask.h"
+#include "src/string/memcmp.h"
+#include "src/string/memset.h"
+#include "test/UnitTest/Test.h"
+
+constexpr int MAX_LOOP = 123;
+int longjmp_called = 0;
+
+void jump_back(jmp_buf buf, int n) {
+  longjmp_called++;
+  LIBC_NAMESPACE::siglongjmp(buf, n); // Will return |n| out of setjmp
+}
+
+TEST(LlvmLibcSetJmpTest, SigSetAndJumpBackSaveSigs) {
+  jmp_buf buf;
+  longjmp_called = 0;
+  volatile int n = 0;
+  sigset_t old;
+  sigset_t mask_all;
+  sigset_t recovered;
+  LIBC_NAMESPACE::memset(&mask_all, 0xFF, sizeof(mask_all));
+  LIBC_NAMESPACE::memset(&old, 0, sizeof(old));
+  LIBC_NAMESPACE::memset(&recovered, 0, sizeof(recovered));
+  LIBC_NAMESPACE::sigprocmask(0, nullptr, &old);
+  if (LIBC_NAMESPACE::sigsetjmp(buf, 1) <= MAX_LOOP) {
+    LIBC_NAMESPACE::sigprocmask(0, nullptr, &recovered);
+    ASSERT_EQ(0, LIBC_NAMESPACE::memcmp(&old, &recovered, sizeof(old)));
+    n = n + 1;
+    LIBC_NAMESPACE::sigprocmask(SIG_BLOCK, &mask_all, nullptr);
+    jump_back(buf, n);
+  }
+  ASSERT_EQ(longjmp_called, n);
+  ASSERT_EQ(n, MAX_LOOP + 1);
+}
+
+TEST(LlvmLibcSetJmpTest, SigSetAndJumpBackValOneSaveSigs) {
+  jmp_buf buf;
+  longjmp_called = 0;
+  sigset_t old;
+  sigset_t mask_all;
+  sigset_t recovered;
+  LIBC_NAMESPACE::memset(&mask_all, 0xFF, sizeof(mask_all));
+  LIBC_NAMESPACE::memset(&old, 0, sizeof(old));
+  LIBC_NAMESPACE::memset(&recovered, 0, sizeof(recovered));
+  LIBC_NAMESPACE::sigprocmask(0, nullptr, &old);
+  int val = LIBC_NAMESPACE::sigsetjmp(buf, 1);
+  if (val == 0) {
+    LIBC_NAMESPACE::sigprocmask(SIG_BLOCK, &mask_all, nullptr);
+    jump_back(buf, val);
+  }
+  LIBC_NAMESPACE::sigprocmask(0, nullptr, &recovered);
+  ASSERT_EQ(0, LIBC_NAMESPACE::memcmp(&old, &recovered, sizeof(old)));
+  ASSERT_EQ(longjmp_called, 1);
+  ASSERT_EQ(val, 1);
+}
+
+TEST(LlvmLibcSetJmpTest, SigSetAndJumpBackNoSaveSigs) {
+  jmp_buf buf;
+  longjmp_called = 0;
+  volatile int n = 0;
+  if (LIBC_NAMESPACE::sigsetjmp(buf, 0) <= MAX_LOOP) {
+    n = n + 1;
+    jump_back(buf, n);
+  }
+  ASSERT_EQ(longjmp_called, n);
+  ASSERT_EQ(n, MAX_LOOP + 1);
+}
+
+TEST(LlvmLibcSetJmpTest, SigSetAndJumpBackValOneNoSaveSigs) {
+  jmp_buf buf;
+  longjmp_called = 0;
+  int val = LIBC_NAMESPACE::sigsetjmp(buf, 0);
+  if (val == 0) {
+    jump_back(buf, val);
+  }
+  ASSERT_EQ(longjmp_called, 1);
+  ASSERT_EQ(val, 1);
+}
diff --git a/test/src/stdfix/IdivTest.h b/test/src/stdfix/IdivTest.h
new file mode 100644
index 0000000..0e9cc40
--- /dev/null
+++ b/test/src/stdfix/IdivTest.h
@@ -0,0 +1,91 @@
+//===-- Utility class to test idivfx functions ------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "test/UnitTest/Test.h"
+
+#include "src/__support/fixed_point/fx_rep.h"
+#include "src/__support/macros/sanitizer.h"
+
+#include "hdr/signal_macros.h"
+
+template <typename T, typename XType>
+class IdivTest : public LIBC_NAMESPACE::testing::Test {
+
+  using FXRep = LIBC_NAMESPACE::fixed_point::FXRep<T>;
+
+  static constexpr T zero = FXRep::ZERO();
+  static constexpr T max = FXRep::MAX();
+  static constexpr T min = FXRep::MIN();
+  static constexpr T one_half = FXRep::ONE_HALF();
+  static constexpr T one_fourth = FXRep::ONE_FOURTH();
+
+public:
+  typedef XType (*IdivFunc)(T, T);
+
+  void testSpecialNumbers(IdivFunc func) {
+    constexpr bool is_signed = (FXRep::SIGN_LEN > 0);
+    constexpr bool has_integral = (FXRep::INTEGRAL_LEN > 0);
+
+    EXPECT_EQ(func(one_half, one_fourth), static_cast<XType>(2));
+    EXPECT_EQ(func(one_half, one_half), static_cast<XType>(1));
+    EXPECT_EQ(func(one_fourth, one_half), static_cast<XType>(0));
+    EXPECT_EQ(func(0.75, 0.25), static_cast<XType>(3));
+    EXPECT_EQ(func(0.625, 0.125), static_cast<XType>(5));
+
+    if constexpr (is_signed) {
+      EXPECT_EQ(func(min, one_half), static_cast<XType>(min) * 2);
+    } else {
+      EXPECT_EQ(func(min, one_half), static_cast<XType>(0));
+    }
+
+    if constexpr (has_integral && min <= 7 && max >= 5) {
+      EXPECT_EQ(func(6.9, 4.2), static_cast<XType>(1));
+      EXPECT_EQ(func(4.2, 6.9), static_cast<XType>(0));
+      EXPECT_EQ(func(4.5, 2.2), static_cast<XType>(2));
+      EXPECT_EQ(func(2.2, 1.1), static_cast<XType>(2));
+      EXPECT_EQ(func(2.25, 1.0), static_cast<XType>(2));
+      EXPECT_EQ(func(2.25, 3.0), static_cast<XType>(0));
+
+      if constexpr (is_signed) {
+        EXPECT_EQ(func(4.2, -6.9), static_cast<XType>(0));
+        EXPECT_EQ(func(-6.9, 4.2), static_cast<XType>(-1));
+        EXPECT_EQ(func(-2.5, 1.25), static_cast<XType>(-2));
+        EXPECT_EQ(func(-2.25, 1.0), static_cast<XType>(-2));
+        EXPECT_EQ(func(2.25, -3.0), static_cast<XType>(0));
+      }
+    }
+  }
+
+  void testInvalidNumbers(IdivFunc func) {
+    constexpr bool has_integral = (FXRep::INTEGRAL_LEN > 0);
+
+    EXPECT_DEATH([func] { func(0.5, 0.0); }, WITH_SIGNAL(-1));
+    if constexpr (has_integral) {
+      EXPECT_DEATH([func] { func(2.5, 0.0); }, WITH_SIGNAL(-1));
+    }
+  }
+};
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+#define LIST_IDIV_TESTS(Name, T, XType, func)                                  \
+  using LlvmLibcIdiv##Name##Test = IdivTest<T, XType>;                         \
+  TEST_F(LlvmLibcIdiv##Name##Test, InvalidNumbers) {                           \
+    testInvalidNumbers(&func);                                                 \
+  }                                                                            \
+  TEST_F(LlvmLibcIdiv##Name##Test, SpecialNumbers) {                           \
+    testSpecialNumbers(&func);                                                 \
+  }                                                                            \
+  static_assert(true, "Require semicolon.")
+#else
+#define LIST_IDIV_TESTS(Name, T, XType, func)                                  \
+  using LlvmLibcIdiv##Name##Test = IdivTest<T, XType>;                         \
+  TEST_F(LlvmLibcIdiv##Name##Test, SpecialNumbers) {                           \
+    testSpecialNumbers(&func);                                                 \
+  }                                                                            \
+  static_assert(true, "Require semicolon.")
+#endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/include/llvm-libc-types/ACTION.h b/test/src/stdfix/idivk_test.cpp
similarity index 62%
rename from include/llvm-libc-types/ACTION.h
rename to test/src/stdfix/idivk_test.cpp
index 1ddce20..b10a43e 100644
--- a/include/llvm-libc-types/ACTION.h
+++ b/test/src/stdfix/idivk_test.cpp
@@ -1,4 +1,4 @@
-//===-- Definition of ACTION type -----------------------------------------===//
+//===-- Unittests for idivk -----------------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,9 +6,9 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef LLVM_LIBC_TYPES_ACTION_H
-#define LLVM_LIBC_TYPES_ACTION_H
+#include "IdivTest.h"
 
-typedef enum { FIND, ENTER } ACTION;
+#include "llvm-libc-macros/stdfix-macros.h" // accum
+#include "src/stdfix/idivk.h"
 
-#endif // LLVM_LIBC_TYPES_ACTION_H
+LIST_IDIV_TESTS(k, accum, int, LIBC_NAMESPACE::idivk);
diff --git a/test/src/stdfix/idivlk_test.cpp b/test/src/stdfix/idivlk_test.cpp
new file mode 100644
index 0000000..dcd4ccb
--- /dev/null
+++ b/test/src/stdfix/idivlk_test.cpp
@@ -0,0 +1,14 @@
+//===-- Unittests for idivlk ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "IdivTest.h"
+
+#include "llvm-libc-macros/stdfix-macros.h" // long accum
+#include "src/stdfix/idivlk.h"
+
+LIST_IDIV_TESTS(lk, long accum, long int, LIBC_NAMESPACE::idivlk);
diff --git a/test/src/stdfix/idivlr_test.cpp b/test/src/stdfix/idivlr_test.cpp
new file mode 100644
index 0000000..0fdb1e3
--- /dev/null
+++ b/test/src/stdfix/idivlr_test.cpp
@@ -0,0 +1,14 @@
+//===-- Unittests for idivlr ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "IdivTest.h"
+
+#include "llvm-libc-macros/stdfix-macros.h" // long fract
+#include "src/stdfix/idivlr.h"
+
+LIST_IDIV_TESTS(lr, long fract, long int, LIBC_NAMESPACE::idivlr);
diff --git a/include/llvm-libc-types/ENTRY.h b/test/src/stdfix/idivr_test.cpp
similarity index 57%
rename from include/llvm-libc-types/ENTRY.h
rename to test/src/stdfix/idivr_test.cpp
index ccbd777..82bec5c 100644
--- a/include/llvm-libc-types/ENTRY.h
+++ b/test/src/stdfix/idivr_test.cpp
@@ -1,4 +1,4 @@
-//===-- Definition of ENTRY type ------------------------------------------===//
+//===-- Unittests for idivr -----------------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,12 +6,9 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef LLVM_LIBC_TYPES_ENTRY_H
-#define LLVM_LIBC_TYPES_ENTRY_H
+#include "IdivTest.h"
 
-typedef struct {
-  char *key;
-  void *data;
-} ENTRY;
+#include "llvm-libc-macros/stdfix-macros.h" // fract
+#include "src/stdfix/idivr.h"
 
-#endif // LLVM_LIBC_TYPES_ENTRY_H
+LIST_IDIV_TESTS(r, fract, int, LIBC_NAMESPACE::idivr);
diff --git a/test/src/stdfix/idivuk_test.cpp b/test/src/stdfix/idivuk_test.cpp
new file mode 100644
index 0000000..2bfd93d
--- /dev/null
+++ b/test/src/stdfix/idivuk_test.cpp
@@ -0,0 +1,14 @@
+//===-- Unittests for idivuk ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "IdivTest.h"
+
+#include "llvm-libc-macros/stdfix-macros.h" // unsigned accum
+#include "src/stdfix/idivuk.h"
+
+LIST_IDIV_TESTS(uk, unsigned accum, unsigned int, LIBC_NAMESPACE::idivuk);
diff --git a/include/llvm-libc-types/EFI_TIMER_DELAY.h b/test/src/stdfix/idivulk_test.cpp
similarity index 51%
rename from include/llvm-libc-types/EFI_TIMER_DELAY.h
rename to test/src/stdfix/idivulk_test.cpp
index 2a6872c..31eb961 100644
--- a/include/llvm-libc-types/EFI_TIMER_DELAY.h
+++ b/test/src/stdfix/idivulk_test.cpp
@@ -1,4 +1,4 @@
-//===-- Definition of EFI_TIMER_DELAY type --------------------------------===//
+//===-- Unittests for idivulk ---------------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,13 +6,10 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef LLVM_LIBC_TYPES_EFI_TIMER_DELAY_H
-#define LLVM_LIBC_TYPES_EFI_TIMER_DELAY_H
+#include "IdivTest.h"
 
-typedef enum {
-  TimerCancel,
-  TimerPeriodic,
-  TimerRelative,
-} EFI_TIMER_DELAY;
+#include "llvm-libc-macros/stdfix-macros.h" // unsigned long accum
+#include "src/stdfix/idivulk.h"
 
-#endif // LLVM_LIBC_TYPES_EFI_TIMER_DELAY_H
+LIST_IDIV_TESTS(ulk, unsigned long accum, unsigned long int,
+                LIBC_NAMESPACE::idivulk);
diff --git a/include/llvm-libc-types/EFI_INTERFACE_TYPE.h b/test/src/stdfix/idivulr_test.cpp
similarity index 51%
rename from include/llvm-libc-types/EFI_INTERFACE_TYPE.h
rename to test/src/stdfix/idivulr_test.cpp
index d463c53..6f43df1 100644
--- a/include/llvm-libc-types/EFI_INTERFACE_TYPE.h
+++ b/test/src/stdfix/idivulr_test.cpp
@@ -1,4 +1,4 @@
-//===-- Definition of EFI_INTERFACE_TYPE type -----------------------------===//
+//===-- Unittests for idivulr ---------------------------------------------===//
 //
 // Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 // See https://llvm.org/LICENSE.txt for license information.
@@ -6,11 +6,10 @@
 //
 //===----------------------------------------------------------------------===//
 
-#ifndef LLVM_LIBC_TYPES_EFI_INTERFACE_TYPE_H
-#define LLVM_LIBC_TYPES_EFI_INTERFACE_TYPE_H
+#include "IdivTest.h"
 
-typedef enum {
-  EFI_NATIVE_INTERFACE,
-} EFI_INTERFACE_TYPE;
+#include "llvm-libc-macros/stdfix-macros.h" // unsigned long fract
+#include "src/stdfix/idivulr.h"
 
-#endif // LLVM_LIBC_TYPES_EFI_INTERFACE_TYPE_H
+LIST_IDIV_TESTS(ulr, unsigned long fract, unsigned long int,
+                LIBC_NAMESPACE::idivulr);
diff --git a/test/src/stdfix/idivur_test.cpp b/test/src/stdfix/idivur_test.cpp
new file mode 100644
index 0000000..c2d2f9c
--- /dev/null
+++ b/test/src/stdfix/idivur_test.cpp
@@ -0,0 +1,14 @@
+//===-- Unittests for idivur ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "IdivTest.h"
+
+#include "llvm-libc-macros/stdfix-macros.h" // unsigned fract
+#include "src/stdfix/idivur.h"
+
+LIST_IDIV_TESTS(ur, unsigned fract, unsigned int, LIBC_NAMESPACE::idivur);
diff --git a/test/src/stdlib/malloc_test.cpp b/test/src/stdlib/malloc_test.cpp
index d9023cf..a8b32b7 100644
--- a/test/src/stdlib/malloc_test.cpp
+++ b/test/src/stdlib/malloc_test.cpp
@@ -17,3 +17,15 @@ TEST(LlvmLibcMallocTest, Allocate) {
   EXPECT_EQ(*ptr, 1);
   LIBC_NAMESPACE::free(ptr);
 }
+
+TEST(LlvmLibcMallocTest, Nullptr) {
+  int *ptr = reinterpret_cast<int *>(LIBC_NAMESPACE::malloc(0));
+  EXPECT_EQ(reinterpret_cast<void *>(ptr), static_cast<void *>(nullptr));
+  LIBC_NAMESPACE::free(ptr);
+}
+
+TEST(LlvmLibcMallocTest, LargeAllocation) {
+  int *ptr = reinterpret_cast<int *>(LIBC_NAMESPACE::malloc(2ul * 1024 * 1024));
+  EXPECT_NE(reinterpret_cast<void *>(ptr), static_cast<void *>(nullptr));
+  LIBC_NAMESPACE::free(ptr);
+}
diff --git a/test/src/stdlib/memalignment_test.cpp b/test/src/stdlib/memalignment_test.cpp
new file mode 100644
index 0000000..2ca1b79
--- /dev/null
+++ b/test/src/stdlib/memalignment_test.cpp
@@ -0,0 +1,59 @@
+//===-- Unittests for memalignment ----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/stdlib/memalignment.h"
+#include "test/UnitTest/Test.h"
+
+#include <stdint.h>
+
+TEST(LlvmLibcMemAlignmentTest, NullPointer) {
+  void *ptr = nullptr;
+  EXPECT_EQ(LIBC_NAMESPACE::memalignment(ptr), static_cast<size_t>(0));
+}
+
+TEST(LlvmLibcMemAlignmentTest, SpecificAlignment) {
+
+  // These addresses have known alignment patterns - if we can construct them
+  uintptr_t addr_align2 = 0x2;   // 2-byte aligned
+  uintptr_t addr_align4 = 0x4;   // 4-byte aligned
+  uintptr_t addr_align8 = 0x8;   // 8-byte aligned
+  uintptr_t addr_align16 = 0x10; // 16-byte aligned
+  uintptr_t addr_align32 = 0x20; // 32-byte aligned
+
+  void *ptr_align2 = reinterpret_cast<void *>(addr_align2);
+  void *ptr_align4 = reinterpret_cast<void *>(addr_align4);
+  void *ptr_align8 = reinterpret_cast<void *>(addr_align8);
+  void *ptr_align16 = reinterpret_cast<void *>(addr_align16);
+  void *ptr_align32 = reinterpret_cast<void *>(addr_align32);
+
+  EXPECT_EQ(LIBC_NAMESPACE::memalignment(ptr_align2), static_cast<size_t>(2));
+  EXPECT_EQ(LIBC_NAMESPACE::memalignment(ptr_align4), static_cast<size_t>(4));
+  EXPECT_EQ(LIBC_NAMESPACE::memalignment(ptr_align8), static_cast<size_t>(8));
+  EXPECT_EQ(LIBC_NAMESPACE::memalignment(ptr_align16), static_cast<size_t>(16));
+  EXPECT_EQ(LIBC_NAMESPACE::memalignment(ptr_align32), static_cast<size_t>(32));
+
+  uintptr_t addr_complex = 0x1234560; // 16-byte aligned (ends in 0)
+  void *ptr_complex = reinterpret_cast<void *>(addr_complex);
+  EXPECT_EQ(LIBC_NAMESPACE::memalignment(ptr_complex), static_cast<size_t>(32));
+}
+
+TEST(LlvmLibcMemAlignmentTest, AlignasSpecifiedAlignment) {
+  alignas(16) static int aligned_16;
+  alignas(32) static int aligned_32;
+  alignas(64) static int aligned_64;
+  alignas(128) static int aligned_128;
+  alignas(256) static int aligned_256;
+
+  EXPECT_GE(LIBC_NAMESPACE::memalignment(&aligned_16), static_cast<size_t>(16));
+  EXPECT_GE(LIBC_NAMESPACE::memalignment(&aligned_32), static_cast<size_t>(32));
+  EXPECT_GE(LIBC_NAMESPACE::memalignment(&aligned_64), static_cast<size_t>(64));
+  EXPECT_GE(LIBC_NAMESPACE::memalignment(&aligned_128),
+            static_cast<size_t>(128));
+  EXPECT_GE(LIBC_NAMESPACE::memalignment(&aligned_256),
+            static_cast<size_t>(256));
+}
diff --git a/test/src/string/memchr_test.cpp b/test/src/string/memchr_test.cpp
index 3439582..1455183 100644
--- a/test/src/string/memchr_test.cpp
+++ b/test/src/string/memchr_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/string/memchr.h"
 #include "test/UnitTest/Test.h"
 #include <stddef.h>
@@ -120,3 +121,12 @@ TEST(LlvmLibcMemChrTest, SignedCharacterFound) {
   // Should find the first character 'c'.
   ASSERT_EQ(actual[0], c);
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcMemChrTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::memchr(nullptr, 1, 1); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/string/memcmp_test.cpp b/test/src/string/memcmp_test.cpp
index 9f85a6d..3dfbced 100644
--- a/test/src/string/memcmp_test.cpp
+++ b/test/src/string/memcmp_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "memory_utils/memory_check_utils.h"
 #include "src/__support/macros/config.h"
 #include "src/string/memcmp.h"
@@ -65,4 +66,13 @@ TEST(LlvmLibcMemcmpTest, SizeSweep) {
   }
 }
 
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcMemcmpTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::memcmp(nullptr, nullptr, 1); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/test/src/string/memcpy_test.cpp b/test/src/string/memcpy_test.cpp
index ce267d1..8c43ac8 100644
--- a/test/src/string/memcpy_test.cpp
+++ b/test/src/string/memcpy_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "memory_utils/memory_check_utils.h"
 #include "src/__support/macros/config.h"
 #include "src/__support/macros/properties/os.h" // LIBC_TARGET_OS_IS_LINUX
@@ -72,4 +73,12 @@ TEST(LlvmLibcMemcpyTest, CheckAccess) {
 
 #endif // !defined(LIBC_FULL_BUILD) && defined(LIBC_TARGET_OS_IS_LINUX)
 
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcMemcpyTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::memcpy(nullptr, nullptr, 1); },
+               WITH_SIGNAL(-1));
+}
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/test/src/string/memmove_test.cpp b/test/src/string/memmove_test.cpp
index 1e225e5..0d47655 100644
--- a/test/src/string/memmove_test.cpp
+++ b/test/src/string/memmove_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/__support/macros/config.h"
 #include "src/string/memmove.h"
 
@@ -103,4 +104,13 @@ TEST(LlvmLibcMemmoveTest, SizeSweep) {
     }
 }
 
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcMemmoveTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::memmove(nullptr, nullptr, 2); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // LIBC_TARGET_OS_IS_LINUX
+
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/test/src/string/mempcpy_test.cpp b/test/src/string/mempcpy_test.cpp
index 877ee81..24482a8 100644
--- a/test/src/string/mempcpy_test.cpp
+++ b/test/src/string/mempcpy_test.cpp
@@ -5,7 +5,7 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 //
 //===----------------------------------------------------------------------===//
-
+#include "hdr/signal_macros.h"
 #include "src/string/mempcpy.h"
 #include "test/UnitTest/Test.h"
 
@@ -26,3 +26,12 @@ TEST(LlvmLibcMempcpyTest, ZeroCount) {
   void *result = LIBC_NAMESPACE::mempcpy(dest, src, 0);
   ASSERT_EQ(static_cast<char *>(result), dest + 0);
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcMempcpyTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::mempcpy(nullptr, nullptr, 1); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/string/memrchr_test.cpp b/test/src/string/memrchr_test.cpp
index 421cb9b..c73a479 100644
--- a/test/src/string/memrchr_test.cpp
+++ b/test/src/string/memrchr_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/string/memrchr.h"
 #include "test/UnitTest/Test.h"
 #include <stddef.h>
@@ -112,3 +113,12 @@ TEST(LlvmLibcMemRChrTest, ZeroLengthShouldReturnNullptr) {
   // This will iterate over exactly zero characters, so should return nullptr.
   ASSERT_STREQ(call_memrchr(src, 'd', 0), nullptr);
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcMemRChrTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::memrchr(nullptr, 'd', 1); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/string/memset_test.cpp b/test/src/string/memset_test.cpp
index 46d6ce7..9562d2d 100644
--- a/test/src/string/memset_test.cpp
+++ b/test/src/string/memset_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "memory_utils/memory_check_utils.h"
 #include "src/__support/macros/config.h"
 #include "src/__support/macros/properties/os.h" // LIBC_TARGET_OS_IS_LINUX
@@ -59,4 +60,13 @@ TEST(LlvmLibcMemsetTest, CheckAccess) {
 
 #endif // !defined(LIBC_FULL_BUILD) && defined(LIBC_TARGET_OS_IS_LINUX)
 
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcMemsetTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::memset(nullptr, 0, 1); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
 } // namespace LIBC_NAMESPACE_DECL
diff --git a/test/src/string/stpncpy_test.cpp b/test/src/string/stpncpy_test.cpp
index 247fa92..f5c61e2 100644
--- a/test/src/string/stpncpy_test.cpp
+++ b/test/src/string/stpncpy_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/__support/CPP/span.h"
 #include "src/string/stpncpy.h"
 #include "test/UnitTest/Test.h"
@@ -71,3 +72,12 @@ TEST_F(LlvmLibcStpncpyTest, CopyTwoWithNull) {
   const char expected[] = {'x', '\0'};
   check_stpncpy(dst, src, 2, expected, 1);
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST_F(LlvmLibcStpncpyTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::stpncpy(nullptr, nullptr, 1); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/string/strcat_test.cpp b/test/src/string/strcat_test.cpp
index e4f6c1e..20f8d11 100644
--- a/test/src/string/strcat_test.cpp
+++ b/test/src/string/strcat_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/string/strcat.h"
 #include "test/UnitTest/Test.h"
 
@@ -35,3 +36,12 @@ TEST(LlvmLibcStrCatTest, NonEmptyDest) {
   ASSERT_STREQ(dest, result);
   ASSERT_STREQ(dest, "xyzabc");
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcStrCatTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::strcat(nullptr, nullptr); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/string/strcoll_test.cpp b/test/src/string/strcoll_test.cpp
index a10f98f..268e232 100644
--- a/test/src/string/strcoll_test.cpp
+++ b/test/src/string/strcoll_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/string/strcoll.h"
 #include "test/UnitTest/Test.h"
 
@@ -28,3 +29,12 @@ TEST(LlvmLibcStrcollTest, SimpleTest) {
   result = LIBC_NAMESPACE::strcoll(s3, s1);
   ASSERT_GT(result, 0);
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcStrcollTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::strcoll(nullptr, nullptr); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/string/strcpy_test.cpp b/test/src/string/strcpy_test.cpp
index 1a1227a..ead60be 100644
--- a/test/src/string/strcpy_test.cpp
+++ b/test/src/string/strcpy_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/string/strcpy.h"
 #include "test/UnitTest/Test.h"
 
@@ -42,3 +43,12 @@ TEST(LlvmLibcStrCpyTest, OffsetDest) {
   ASSERT_STREQ(dest + 3, result);
   ASSERT_STREQ(dest, "xyzabc");
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcStrCpyTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::strcpy(nullptr, nullptr); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/string/strlcpy_test.cpp b/test/src/string/strlcpy_test.cpp
index 0914257..b42954c 100644
--- a/test/src/string/strlcpy_test.cpp
+++ b/test/src/string/strlcpy_test.cpp
@@ -14,8 +14,8 @@ TEST(LlvmLibcStrlcpyTest, TooBig) {
   char buf[2];
   EXPECT_EQ(LIBC_NAMESPACE::strlcpy(buf, str, 2), size_t(3));
   EXPECT_STREQ(buf, "a");
-
-  EXPECT_EQ(LIBC_NAMESPACE::strlcpy(nullptr, str, 0), size_t(3));
+  char dst[] = "";
+  EXPECT_EQ(LIBC_NAMESPACE::strlcpy(dst, str, 0), size_t(3));
 }
 
 TEST(LlvmLibcStrlcpyTest, Smaller) {
diff --git a/test/src/string/strsep_test.cpp b/test/src/string/strsep_test.cpp
index 0daa29f..6f02ce3 100644
--- a/test/src/string/strsep_test.cpp
+++ b/test/src/string/strsep_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/string/strsep.h"
 #include "test/UnitTest/Test.h"
 
@@ -51,3 +52,12 @@ TEST(LlvmLibcStrsepTest, DelimitersShouldNotBeIncludedInToken) {
     ASSERT_STREQ(LIBC_NAMESPACE::strsep(&string, "_:"), expected[i]);
   }
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcStrsepTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::strsep(nullptr, nullptr); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/string/strspn_test.cpp b/test/src/string/strspn_test.cpp
index cdd12af..adf9a45 100644
--- a/test/src/string/strspn_test.cpp
+++ b/test/src/string/strspn_test.cpp
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "hdr/signal_macros.h"
 #include "src/string/strspn.h"
 
 #include "test/UnitTest/Test.h"
@@ -83,3 +84,12 @@ TEST(LlvmLibcStrSpnTest, DuplicatedCharactersToBeSearchedForShouldStillMatch) {
   EXPECT_EQ(LIBC_NAMESPACE::strspn("aaa", "aa"), size_t{3});
   EXPECT_EQ(LIBC_NAMESPACE::strspn("aaaa", "aa"), size_t{4});
 }
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+
+TEST(LlvmLibcStrSpnTest, CrashOnNullPtr) {
+  ASSERT_DEATH([]() { LIBC_NAMESPACE::strspn(nullptr, nullptr); },
+               WITH_SIGNAL(-1));
+}
+
+#endif // defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
diff --git a/test/src/sys/auxv/linux/getauxval_test.cpp b/test/src/sys/auxv/linux/getauxval_test.cpp
index 8811fd8..b8728b7 100644
--- a/test/src/sys/auxv/linux/getauxval_test.cpp
+++ b/test/src/sys/auxv/linux/getauxval_test.cpp
@@ -5,16 +5,18 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 //
 //===----------------------------------------------------------------------===//
-#include "src/errno/libc_errno.h"
+
 #include "src/sys/auxv/getauxval.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 #include <src/string/strstr.h>
 #include <sys/auxv.h>
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcGetauxvalTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcGetauxvalTest, Basic) {
+TEST_F(LlvmLibcGetauxvalTest, Basic) {
   EXPECT_THAT(LIBC_NAMESPACE::getauxval(AT_PAGESZ),
               returns(GT(0ul)).with_errno(EQ(0)));
   const char *filename;
diff --git a/test/src/sys/epoll/linux/epoll_create1_test.cpp b/test/src/sys/epoll/linux/epoll_create1_test.cpp
index 4059afe..3fd6298 100644
--- a/test/src/sys/epoll/linux/epoll_create1_test.cpp
+++ b/test/src/sys/epoll/linux/epoll_create1_test.cpp
@@ -6,15 +6,16 @@
 //
 //===----------------------------------------------------------------------===//
 #include "hdr/sys_epoll_macros.h"
-#include "src/errno/libc_errno.h"
 #include "src/sys/epoll/epoll_create1.h"
 #include "src/unistd/close.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcEpollCreate1Test = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcEpollCreate1Test, Basic) {
+TEST_F(LlvmLibcEpollCreate1Test, Basic) {
   int fd = LIBC_NAMESPACE::epoll_create1(0);
   ASSERT_GT(fd, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -22,7 +23,7 @@ TEST(LlvmLibcEpollCreate1Test, Basic) {
   ASSERT_THAT(LIBC_NAMESPACE::close(fd), Succeeds());
 }
 
-TEST(LlvmLibcEpollCreate1Test, CloseOnExecute) {
+TEST_F(LlvmLibcEpollCreate1Test, CloseOnExecute) {
   int fd = LIBC_NAMESPACE::epoll_create1(EPOLL_CLOEXEC);
   ASSERT_GT(fd, 0);
   ASSERT_ERRNO_SUCCESS();
diff --git a/test/src/sys/epoll/linux/epoll_create_test.cpp b/test/src/sys/epoll/linux/epoll_create_test.cpp
index 9c4bad1..06c17c6 100644
--- a/test/src/sys/epoll/linux/epoll_create_test.cpp
+++ b/test/src/sys/epoll/linux/epoll_create_test.cpp
@@ -5,16 +5,17 @@
 // SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 //
 //===----------------------------------------------------------------------===//
-#include "src/errno/libc_errno.h"
 #include "src/sys/epoll/epoll_create.h"
 #include "src/unistd/close.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 #include <sys/syscall.h> // For syscall numbers.
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcEpollCreateTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcEpollCreateTest, Basic) {
+TEST_F(LlvmLibcEpollCreateTest, Basic) {
   int fd = LIBC_NAMESPACE::epoll_create(1);
   ASSERT_GT(fd, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -23,7 +24,7 @@ TEST(LlvmLibcEpollCreateTest, Basic) {
 }
 
 #ifdef SYS_epoll_create
-TEST(LlvmLibcEpollCreateTest, Fails) {
+TEST_F(LlvmLibcEpollCreateTest, Fails) {
   ASSERT_THAT(LIBC_NAMESPACE::epoll_create(0), Fails(EINVAL));
 }
 #endif
diff --git a/test/src/sys/epoll/linux/epoll_ctl_test.cpp b/test/src/sys/epoll/linux/epoll_ctl_test.cpp
index fa2d358..bfbf9c0 100644
--- a/test/src/sys/epoll/linux/epoll_ctl_test.cpp
+++ b/test/src/sys/epoll/linux/epoll_ctl_test.cpp
@@ -8,17 +8,18 @@
 
 #include "hdr/sys_epoll_macros.h"
 #include "hdr/types/struct_epoll_event.h"
-#include "src/errno/libc_errno.h"
 #include "src/sys/epoll/epoll_create1.h"
 #include "src/sys/epoll/epoll_ctl.h"
 #include "src/unistd/close.h"
 #include "src/unistd/pipe.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcEpollCtlTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcEpollCtlTest, Basic) {
+TEST_F(LlvmLibcEpollCtlTest, Basic) {
   int epfd = LIBC_NAMESPACE::epoll_create1(0);
   ASSERT_GT(epfd, 0);
   ASSERT_ERRNO_SUCCESS();
diff --git a/test/src/sys/epoll/linux/epoll_pwait2_test.cpp b/test/src/sys/epoll/linux/epoll_pwait2_test.cpp
index 2f4c985..6da070e 100644
--- a/test/src/sys/epoll/linux/epoll_pwait2_test.cpp
+++ b/test/src/sys/epoll/linux/epoll_pwait2_test.cpp
@@ -8,18 +8,19 @@
 #include "hdr/sys_epoll_macros.h"
 #include "hdr/types/struct_epoll_event.h"
 #include "hdr/types/struct_timespec.h"
-#include "src/errno/libc_errno.h"
 #include "src/sys/epoll/epoll_create1.h"
 #include "src/sys/epoll/epoll_ctl.h"
 #include "src/sys/epoll/epoll_pwait2.h"
 #include "src/unistd/close.h"
 #include "src/unistd/pipe.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcEpollPwaitTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcEpollPwaitTest, Basic) {
+TEST_F(LlvmLibcEpollPwaitTest, Basic) {
   int epfd = LIBC_NAMESPACE::epoll_create1(0);
   ASSERT_GT(epfd, 0);
   ASSERT_ERRNO_SUCCESS();
diff --git a/test/src/sys/epoll/linux/epoll_pwait_test.cpp b/test/src/sys/epoll/linux/epoll_pwait_test.cpp
index 8e14aea..3b93617 100644
--- a/test/src/sys/epoll/linux/epoll_pwait_test.cpp
+++ b/test/src/sys/epoll/linux/epoll_pwait_test.cpp
@@ -7,19 +7,19 @@
 //===----------------------------------------------------------------------===//
 #include "hdr/sys_epoll_macros.h"
 #include "hdr/types/struct_epoll_event.h"
-#include "src/errno/libc_errno.h"
 #include "src/sys/epoll/epoll_create1.h"
 #include "src/sys/epoll/epoll_ctl.h"
 #include "src/sys/epoll/epoll_pwait.h"
 #include "src/unistd/close.h"
 #include "src/unistd/pipe.h"
-
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcEpollPwaitTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcEpollPwaitTest, Basic) {
+TEST_F(LlvmLibcEpollPwaitTest, Basic) {
   int epfd = LIBC_NAMESPACE::epoll_create1(0);
   ASSERT_GT(epfd, 0);
   ASSERT_ERRNO_SUCCESS();
diff --git a/test/src/sys/epoll/linux/epoll_wait_test.cpp b/test/src/sys/epoll/linux/epoll_wait_test.cpp
index f9e855a..7457ef2 100644
--- a/test/src/sys/epoll/linux/epoll_wait_test.cpp
+++ b/test/src/sys/epoll/linux/epoll_wait_test.cpp
@@ -7,18 +7,19 @@
 //===----------------------------------------------------------------------===//
 #include "hdr/sys_epoll_macros.h"
 #include "hdr/types/struct_epoll_event.h"
-#include "src/errno/libc_errno.h"
 #include "src/sys/epoll/epoll_create1.h"
 #include "src/sys/epoll/epoll_ctl.h"
 #include "src/sys/epoll/epoll_wait.h"
 #include "src/unistd/close.h"
 #include "src/unistd/pipe.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcEpollWaitTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcEpollWaitTest, Basic) {
+TEST_F(LlvmLibcEpollWaitTest, Basic) {
   int epfd = LIBC_NAMESPACE::epoll_create1(0);
   ASSERT_GT(epfd, 0);
   ASSERT_ERRNO_SUCCESS();
diff --git a/test/src/sys/mman/linux/madvise_test.cpp b/test/src/sys/mman/linux/madvise_test.cpp
index 6768d11..6671050 100644
--- a/test/src/sys/mman/linux/madvise_test.cpp
+++ b/test/src/sys/mman/linux/madvise_test.cpp
@@ -6,10 +6,10 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/sys/mman/madvise.h"
 #include "src/sys/mman/mmap.h"
 #include "src/sys/mman/munmap.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -17,10 +17,10 @@
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using LlvmLibcMadviseTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcMadviseTest, NoError) {
+TEST_F(LlvmLibcMadviseTest, NoError) {
   size_t alloc_size = 128;
-  LIBC_NAMESPACE::libc_errno = 0;
   void *addr = LIBC_NAMESPACE::mmap(nullptr, alloc_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -37,8 +37,7 @@ TEST(LlvmLibcMadviseTest, NoError) {
   EXPECT_THAT(LIBC_NAMESPACE::munmap(addr, alloc_size), Succeeds());
 }
 
-TEST(LlvmLibcMadviseTest, Error_BadPtr) {
-  LIBC_NAMESPACE::libc_errno = 0;
+TEST_F(LlvmLibcMadviseTest, Error_BadPtr) {
   EXPECT_THAT(LIBC_NAMESPACE::madvise(nullptr, 8, MADV_SEQUENTIAL),
               Fails(ENOMEM));
 }
diff --git a/test/src/sys/mman/linux/mincore_test.cpp b/test/src/sys/mman/linux/mincore_test.cpp
index e49e300..ade620b 100644
--- a/test/src/sys/mman/linux/mincore_test.cpp
+++ b/test/src/sys/mman/linux/mincore_test.cpp
@@ -7,7 +7,6 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/__support/OSUtil/syscall.h" // For internal syscall function.
-#include "src/errno/libc_errno.h"
 #include "src/sys/mman/madvise.h"
 #include "src/sys/mman/mincore.h"
 #include "src/sys/mman/mlock.h"
@@ -15,6 +14,7 @@
 #include "src/sys/mman/munlock.h"
 #include "src/sys/mman/munmap.h"
 #include "src/unistd/sysconf.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -24,64 +24,60 @@
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using LlvmLibcMincoreTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcMincoreTest, UnMappedMemory) {
-  LIBC_NAMESPACE::libc_errno = 0;
+TEST_F(LlvmLibcMincoreTest, UnMappedMemory) {
   unsigned char vec;
   int res = LIBC_NAMESPACE::mincore(nullptr, 1, &vec);
   EXPECT_THAT(res, Fails(ENOMEM, -1));
 }
 
-TEST(LlvmLibcMincoreTest, UnalignedAddr) {
+TEST_F(LlvmLibcMincoreTest, UnalignedAddr) {
   unsigned long page_size = LIBC_NAMESPACE::sysconf(_SC_PAGESIZE);
   void *addr = LIBC_NAMESPACE::mmap(nullptr, page_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   EXPECT_NE(addr, MAP_FAILED);
   EXPECT_EQ(reinterpret_cast<unsigned long>(addr) % page_size, 0ul);
-  LIBC_NAMESPACE::libc_errno = 0;
   int res = LIBC_NAMESPACE::mincore(static_cast<char *>(addr) + 1, 1, nullptr);
   EXPECT_THAT(res, Fails(EINVAL, -1));
   EXPECT_THAT(LIBC_NAMESPACE::munmap(addr, page_size), Succeeds());
 }
 
-TEST(LlvmLibcMincoreTest, InvalidVec) {
+TEST_F(LlvmLibcMincoreTest, InvalidVec) {
   unsigned long page_size = LIBC_NAMESPACE::sysconf(_SC_PAGESIZE);
   void *addr = LIBC_NAMESPACE::mmap(nullptr, 4 * page_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   EXPECT_NE(addr, MAP_FAILED);
   EXPECT_EQ(reinterpret_cast<unsigned long>(addr) % page_size, 0ul);
-  LIBC_NAMESPACE::libc_errno = 0;
   int res = LIBC_NAMESPACE::mincore(addr, 1, nullptr);
   EXPECT_THAT(res, Fails(EFAULT, -1));
 }
 
-TEST(LlvmLibcMincoreTest, NoError) {
+TEST_F(LlvmLibcMincoreTest, NoError) {
   unsigned long page_size = LIBC_NAMESPACE::sysconf(_SC_PAGESIZE);
   void *addr = LIBC_NAMESPACE::mmap(nullptr, page_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   EXPECT_NE(addr, MAP_FAILED);
   EXPECT_EQ(reinterpret_cast<unsigned long>(addr) % page_size, 0ul);
   unsigned char vec;
-  LIBC_NAMESPACE::libc_errno = 0;
   int res = LIBC_NAMESPACE::mincore(addr, 1, &vec);
   EXPECT_THAT(res, Succeeds());
   EXPECT_THAT(LIBC_NAMESPACE::munmap(addr, page_size), Succeeds());
 }
 
-TEST(LlvmLibcMincoreTest, NegativeLength) {
+TEST_F(LlvmLibcMincoreTest, NegativeLength) {
   unsigned long page_size = LIBC_NAMESPACE::sysconf(_SC_PAGESIZE);
   void *addr = LIBC_NAMESPACE::mmap(nullptr, page_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   EXPECT_NE(addr, MAP_FAILED);
   EXPECT_EQ(reinterpret_cast<unsigned long>(addr) % page_size, 0ul);
   unsigned char vec;
-  LIBC_NAMESPACE::libc_errno = 0;
   int res = LIBC_NAMESPACE::mincore(addr, -1, &vec);
   EXPECT_THAT(res, Fails(ENOMEM, -1));
   EXPECT_THAT(LIBC_NAMESPACE::munmap(addr, page_size), Succeeds());
 }
 
-TEST(LlvmLibcMincoreTest, PageOut) {
+TEST_F(LlvmLibcMincoreTest, PageOut) {
   unsigned long page_size = LIBC_NAMESPACE::sysconf(_SC_PAGESIZE);
   unsigned char vec;
   void *addr = LIBC_NAMESPACE::mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
@@ -101,11 +97,9 @@ TEST(LlvmLibcMincoreTest, PageOut) {
 
   // page out the memory
   {
-    LIBC_NAMESPACE::libc_errno = 0;
     EXPECT_THAT(LIBC_NAMESPACE::madvise(addr, page_size, MADV_DONTNEED),
                 Succeeds());
 
-    LIBC_NAMESPACE::libc_errno = 0;
     int res = LIBC_NAMESPACE::mincore(addr, page_size, &vec);
     EXPECT_EQ(vec & 1u, 0u);
     EXPECT_THAT(res, Succeeds());
diff --git a/test/src/sys/mman/linux/mlock_test.cpp b/test/src/sys/mman/linux/mlock_test.cpp
index 48cde13..88abaca 100644
--- a/test/src/sys/mman/linux/mlock_test.cpp
+++ b/test/src/sys/mman/linux/mlock_test.cpp
@@ -19,6 +19,7 @@
 #include "src/sys/mman/munmap.h"
 #include "src/sys/resource/getrlimit.h"
 #include "src/unistd/sysconf.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -29,6 +30,7 @@
 #include <unistd.h>
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcMlockTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
 struct PageHolder {
   size_t size;
@@ -72,12 +74,12 @@ static bool is_permitted_size(size_t size) {
          get_capacity(CAP_IPC_LOCK);
 }
 
-TEST(LlvmLibcMlockTest, UnMappedMemory) {
+TEST_F(LlvmLibcMlockTest, UnMappedMemory) {
   EXPECT_THAT(LIBC_NAMESPACE::mlock(nullptr, 1024), Fails(ENOMEM));
   EXPECT_THAT(LIBC_NAMESPACE::munlock(nullptr, 1024), Fails(ENOMEM));
 }
 
-TEST(LlvmLibcMlockTest, Overflow) {
+TEST_F(LlvmLibcMlockTest, Overflow) {
   PageHolder holder;
   EXPECT_TRUE(holder.is_valid());
   size_t negative_size = -holder.size;
@@ -89,7 +91,7 @@ TEST(LlvmLibcMlockTest, Overflow) {
 }
 
 #ifdef SYS_mlock2
-TEST(LlvmLibcMlockTest, MLock2) {
+TEST_F(LlvmLibcMlockTest, MLock2) {
   PageHolder holder;
   EXPECT_TRUE(holder.is_valid());
   EXPECT_THAT(LIBC_NAMESPACE::madvise(holder.addr, holder.size, MADV_DONTNEED),
@@ -115,9 +117,8 @@ TEST(LlvmLibcMlockTest, MLock2) {
 }
 #endif
 
-TEST(LlvmLibcMlockTest, InvalidFlag) {
+TEST_F(LlvmLibcMlockTest, InvalidFlag) {
   size_t alloc_size = 128; // page size
-  LIBC_NAMESPACE::libc_errno = 0;
   void *addr = LIBC_NAMESPACE::mmap(nullptr, alloc_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -139,7 +140,7 @@ TEST(LlvmLibcMlockTest, InvalidFlag) {
   LIBC_NAMESPACE::munmap(addr, alloc_size);
 }
 
-TEST(LlvmLibcMlockTest, MLockAll) {
+TEST_F(LlvmLibcMlockTest, MLockAll) {
   {
     PageHolder holder;
     EXPECT_TRUE(holder.is_valid());
diff --git a/test/src/sys/mman/linux/mmap_test.cpp b/test/src/sys/mman/linux/mmap_test.cpp
index dcbc758..1541576 100644
--- a/test/src/sys/mman/linux/mmap_test.cpp
+++ b/test/src/sys/mman/linux/mmap_test.cpp
@@ -6,9 +6,9 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/sys/mman/mmap.h"
 #include "src/sys/mman/munmap.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -16,10 +16,10 @@
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using LlvmLibcMMapTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcMMapTest, NoError) {
+TEST_F(LlvmLibcMMapTest, NoError) {
   size_t alloc_size = 128;
-  LIBC_NAMESPACE::libc_errno = 0;
   void *addr = LIBC_NAMESPACE::mmap(nullptr, alloc_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -33,8 +33,7 @@ TEST(LlvmLibcMMapTest, NoError) {
   EXPECT_THAT(LIBC_NAMESPACE::munmap(addr, alloc_size), Succeeds());
 }
 
-TEST(LlvmLibcMMapTest, Error_InvalidSize) {
-  LIBC_NAMESPACE::libc_errno = 0;
+TEST_F(LlvmLibcMMapTest, Error_InvalidSize) {
   void *addr = LIBC_NAMESPACE::mmap(nullptr, 0, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   EXPECT_THAT(addr, Fails(EINVAL, MAP_FAILED));
diff --git a/test/src/sys/mman/linux/mprotect_test.cpp b/test/src/sys/mman/linux/mprotect_test.cpp
index 46e449e..c1278a1 100644
--- a/test/src/sys/mman/linux/mprotect_test.cpp
+++ b/test/src/sys/mman/linux/mprotect_test.cpp
@@ -6,10 +6,10 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/sys/mman/mmap.h"
 #include "src/sys/mman/mprotect.h"
 #include "src/sys/mman/munmap.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -18,10 +18,10 @@
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using LlvmLibcMProtectTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcMProtectTest, NoError) {
+TEST_F(LlvmLibcMProtectTest, NoError) {
   size_t alloc_size = 128;
-  LIBC_NAMESPACE::libc_errno = 0;
   void *addr = LIBC_NAMESPACE::mmap(nullptr, alloc_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -47,7 +47,7 @@ TEST(LlvmLibcMProtectTest, NoError) {
 // This test is disabled currently due to flakeyness. It will be re-enabled once
 // it is less flakey.
 /*
-TEST(LlvmLibcMProtectTest, Error_InvalidWrite) {
+TEST_F(LlvmLibcMProtectTest, Error_InvalidWrite) {
   // attempting to write to a read-only protected part of memory should cause a
   // segfault.
   EXPECT_DEATH(
diff --git a/test/src/sys/mman/linux/mremap_test.cpp b/test/src/sys/mman/linux/mremap_test.cpp
index 12e4485..5ff774d 100644
--- a/test/src/sys/mman/linux/mremap_test.cpp
+++ b/test/src/sys/mman/linux/mremap_test.cpp
@@ -6,10 +6,10 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/sys/mman/mmap.h"
 #include "src/sys/mman/mremap.h"
 #include "src/sys/mman/munmap.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -17,11 +17,11 @@
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using LlvmLibcMremapTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcMremapTest, NoError) {
+TEST_F(LlvmLibcMremapTest, NoError) {
   size_t initial_size = 128;
   size_t new_size = 256;
-  LIBC_NAMESPACE::libc_errno = 0;
 
   // Allocate memory using mmap.
   void *addr =
@@ -47,9 +47,8 @@ TEST(LlvmLibcMremapTest, NoError) {
   EXPECT_THAT(LIBC_NAMESPACE::munmap(new_addr, new_size), Succeeds());
 }
 
-TEST(LlvmLibcMremapTest, Error_InvalidSize) {
+TEST_F(LlvmLibcMremapTest, Error_InvalidSize) {
   size_t initial_size = 128;
-  LIBC_NAMESPACE::libc_errno = 0;
 
   // Allocate memory using mmap.
   void *addr =
diff --git a/test/src/sys/mman/linux/msync_test.cpp b/test/src/sys/mman/linux/msync_test.cpp
index 65eedb2..b4eedb3 100644
--- a/test/src/sys/mman/linux/msync_test.cpp
+++ b/test/src/sys/mman/linux/msync_test.cpp
@@ -6,17 +6,18 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/sys/mman/mlock.h"
 #include "src/sys/mman/mmap.h"
 #include "src/sys/mman/msync.h"
 #include "src/sys/mman/munlock.h"
 #include "src/sys/mman/munmap.h"
 #include "src/unistd/sysconf.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcMsyncTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
 struct PageHolder {
   size_t size;
@@ -36,12 +37,12 @@ struct PageHolder {
   bool is_valid() { return addr != MAP_FAILED; }
 };
 
-TEST(LlvmLibcMsyncTest, UnMappedMemory) {
+TEST_F(LlvmLibcMsyncTest, UnMappedMemory) {
   EXPECT_THAT(LIBC_NAMESPACE::msync(nullptr, 1024, MS_SYNC), Fails(ENOMEM));
   EXPECT_THAT(LIBC_NAMESPACE::msync(nullptr, 1024, MS_ASYNC), Fails(ENOMEM));
 }
 
-TEST(LlvmLibcMsyncTest, LockedPage) {
+TEST_F(LlvmLibcMsyncTest, LockedPage) {
   PageHolder page;
   ASSERT_TRUE(page.is_valid());
   ASSERT_THAT(LIBC_NAMESPACE::mlock(page.addr, page.size), Succeeds());
@@ -52,14 +53,14 @@ TEST(LlvmLibcMsyncTest, LockedPage) {
   EXPECT_THAT(LIBC_NAMESPACE::msync(page.addr, page.size, MS_SYNC), Succeeds());
 }
 
-TEST(LlvmLibcMsyncTest, UnalignedAddress) {
+TEST_F(LlvmLibcMsyncTest, UnalignedAddress) {
   PageHolder page;
   ASSERT_TRUE(page.is_valid());
   EXPECT_THAT(LIBC_NAMESPACE::msync(&page[1], page.size - 1, MS_SYNC),
               Fails(EINVAL));
 }
 
-TEST(LlvmLibcMsyncTest, InvalidFlag) {
+TEST_F(LlvmLibcMsyncTest, InvalidFlag) {
   PageHolder page;
   ASSERT_TRUE(page.is_valid());
   EXPECT_THAT(LIBC_NAMESPACE::msync(page.addr, page.size, MS_SYNC | MS_ASYNC),
diff --git a/test/src/sys/mman/linux/posix_madvise_test.cpp b/test/src/sys/mman/linux/posix_madvise_test.cpp
index ee6489c..7fe2718 100644
--- a/test/src/sys/mman/linux/posix_madvise_test.cpp
+++ b/test/src/sys/mman/linux/posix_madvise_test.cpp
@@ -6,10 +6,10 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/sys/mman/mmap.h"
 #include "src/sys/mman/munmap.h"
 #include "src/sys/mman/posix_madvise.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -17,10 +17,10 @@
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using LlvmLibcPosixMadviseTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcPosixMadviseTest, NoError) {
+TEST_F(LlvmLibcPosixMadviseTest, NoError) {
   size_t alloc_size = 128;
-  LIBC_NAMESPACE::libc_errno = 0;
   void *addr = LIBC_NAMESPACE::mmap(nullptr, alloc_size, PROT_READ,
                                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -37,8 +37,7 @@ TEST(LlvmLibcPosixMadviseTest, NoError) {
   EXPECT_THAT(LIBC_NAMESPACE::munmap(addr, alloc_size), Succeeds());
 }
 
-TEST(LlvmLibcPosixMadviseTest, Error_BadPtr) {
-  LIBC_NAMESPACE::libc_errno = 0;
+TEST_F(LlvmLibcPosixMadviseTest, Error_BadPtr) {
   // posix_madvise is a no-op on DONTNEED, so it shouldn't fail even with the
   // nullptr.
   EXPECT_EQ(LIBC_NAMESPACE::posix_madvise(nullptr, 8, POSIX_MADV_DONTNEED), 0);
diff --git a/test/src/sys/mman/linux/remap_file_pages_test.cpp b/test/src/sys/mman/linux/remap_file_pages_test.cpp
index ebc5c89..851e4f7 100644
--- a/test/src/sys/mman/linux/remap_file_pages_test.cpp
+++ b/test/src/sys/mman/linux/remap_file_pages_test.cpp
@@ -6,13 +6,13 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/mman/mmap.h"
 #include "src/sys/mman/munmap.h"
 #include "src/sys/mman/remap_file_pages.h"
 #include "src/unistd/close.h"
 #include "src/unistd/sysconf.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -21,8 +21,9 @@
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using LlvmLibcRemapFilePagesTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcRemapFilePagesTest, NoError) {
+TEST_F(LlvmLibcRemapFilePagesTest, NoError) {
   size_t page_size = LIBC_NAMESPACE::sysconf(_SC_PAGE_SIZE);
   ASSERT_GT(page_size, size_t(0));
 
@@ -34,7 +35,6 @@ TEST(LlvmLibcRemapFilePagesTest, NoError) {
 
   // First, allocate some memory using mmap
   size_t alloc_size = 2 * page_size;
-  LIBC_NAMESPACE::libc_errno = 0;
   void *addr = LIBC_NAMESPACE::mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, fd, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -44,15 +44,12 @@ TEST(LlvmLibcRemapFilePagesTest, NoError) {
   EXPECT_THAT(LIBC_NAMESPACE::remap_file_pages(addr, page_size, 0, 1, 0),
               Succeeds());
 
-  // Reset error number for the new function
-  LIBC_NAMESPACE::libc_errno = 0;
-
   // Clean up
   EXPECT_THAT(LIBC_NAMESPACE::munmap(addr, alloc_size), Succeeds());
   EXPECT_THAT(LIBC_NAMESPACE::close(fd), Succeeds());
 }
 
-TEST(LlvmLibcRemapFilePagesTest, ErrorInvalidFlags) {
+TEST_F(LlvmLibcRemapFilePagesTest, ErrorInvalidFlags) {
   size_t page_size = LIBC_NAMESPACE::sysconf(_SC_PAGE_SIZE);
   ASSERT_GT(page_size, size_t(0));
 
@@ -64,7 +61,6 @@ TEST(LlvmLibcRemapFilePagesTest, ErrorInvalidFlags) {
 
   // First, allocate some memory using mmap
   size_t alloc_size = 2 * page_size;
-  LIBC_NAMESPACE::libc_errno = 0;
   void *addr = LIBC_NAMESPACE::mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, fd, 0);
   ASSERT_ERRNO_SUCCESS();
@@ -80,7 +76,7 @@ TEST(LlvmLibcRemapFilePagesTest, ErrorInvalidFlags) {
   EXPECT_THAT(LIBC_NAMESPACE::close(fd), Succeeds());
 }
 
-TEST(LlvmLibcRemapFilePagesTest, ErrorInvalidAddress) {
+TEST_F(LlvmLibcRemapFilePagesTest, ErrorInvalidAddress) {
   size_t page_size = LIBC_NAMESPACE::sysconf(_SC_PAGESIZE);
   ASSERT_GT(page_size, size_t(0));
 
diff --git a/test/src/sys/mman/linux/shm_test.cpp b/test/src/sys/mman/linux/shm_test.cpp
index 7f4be18..ae555fa 100644
--- a/test/src/sys/mman/linux/shm_test.cpp
+++ b/test/src/sys/mman/linux/shm_test.cpp
@@ -15,15 +15,17 @@
 #include "src/sys/mman/shm_unlink.h"
 #include "src/unistd/close.h"
 #include "src/unistd/ftruncate.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 #include <sys/syscall.h>
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcShmTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 // since shm_open/shm_unlink are wrappers around open/unlink, we only focus on
 // testing basic cases and name conversions.
 
-TEST(LlvmLibcShmTest, Basic) {
+TEST_F(LlvmLibcShmTest, Basic) {
   const char *name = "/test_shm_open";
   int fd;
   ASSERT_THAT(fd = LIBC_NAMESPACE::shm_open(name, O_CREAT | O_RDWR, 0666),
@@ -57,7 +59,7 @@ TEST(LlvmLibcShmTest, Basic) {
   ASSERT_THAT(LIBC_NAMESPACE::shm_unlink(name), Succeeds());
 }
 
-TEST(LlvmLibcShmTest, NameConversion) {
+TEST_F(LlvmLibcShmTest, NameConversion) {
   const char *name = "////test_shm_open";
   int fd;
   ASSERT_THAT(fd = LIBC_NAMESPACE::shm_open(name, O_CREAT | O_RDWR, 0666),
diff --git a/test/src/sys/prctl/linux/prctl_test.cpp b/test/src/sys/prctl/linux/prctl_test.cpp
index 987c35d..374c905 100644
--- a/test/src/sys/prctl/linux/prctl_test.cpp
+++ b/test/src/sys/prctl/linux/prctl_test.cpp
@@ -6,15 +6,16 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/sys/prctl/prctl.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include <sys/prctl.h>
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using LlvmLibcSysPrctlTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcSysPrctlTest, GetSetName) {
+TEST_F(LlvmLibcSysPrctlTest, GetSetName) {
   char name[17];
   unsigned long name_addr = 0;
   ASSERT_THAT(LIBC_NAMESPACE::prctl(PR_GET_NAME, name_addr, 0, 0, 0),
@@ -30,10 +31,9 @@ TEST(LlvmLibcSysPrctlTest, GetSetName) {
   ASSERT_STREQ(name, "libc-test");
 }
 
-TEST(LlvmLibcSysPrctlTest, GetTHPDisable) {
+TEST_F(LlvmLibcSysPrctlTest, GetTHPDisable) {
   // Manually check errno since the return value logic here is not
   // covered in ErrnoSetterMatcher.
-  LIBC_NAMESPACE::libc_errno = 0;
   int ret = LIBC_NAMESPACE::prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0);
   ASSERT_ERRNO_SUCCESS();
   // PR_GET_THP_DISABLE return (as the function result) the current
diff --git a/test/src/sys/random/linux/getrandom_test.cpp b/test/src/sys/random/linux/getrandom_test.cpp
index eb5b23c..70ecfbf 100644
--- a/test/src/sys/random/linux/getrandom_test.cpp
+++ b/test/src/sys/random/linux/getrandom_test.cpp
@@ -7,28 +7,26 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/__support/CPP/array.h"
-#include "src/errno/libc_errno.h"
 #include "src/math/fabs.h"
 #include "src/sys/random/getrandom.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
-TEST(LlvmLibcGetRandomTest, InvalidFlag) {
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcGetRandomTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
+
+TEST_F(LlvmLibcGetRandomTest, InvalidFlag) {
   LIBC_NAMESPACE::cpp::array<char, 10> buffer;
-  LIBC_NAMESPACE::libc_errno = 0;
-  ASSERT_THAT(
-      LIBC_NAMESPACE::getrandom(buffer.data(), buffer.size(), -1),
-      LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails<ssize_t>(EINVAL));
+  ASSERT_THAT(LIBC_NAMESPACE::getrandom(buffer.data(), buffer.size(), -1),
+              Fails(EINVAL));
 }
 
-TEST(LlvmLibcGetRandomTest, InvalidBuffer) {
-  LIBC_NAMESPACE::libc_errno = 0;
-  ASSERT_THAT(
-      LIBC_NAMESPACE::getrandom(nullptr, 65536, 0),
-      LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails<ssize_t>(EFAULT));
+TEST_F(LlvmLibcGetRandomTest, InvalidBuffer) {
+  ASSERT_THAT(LIBC_NAMESPACE::getrandom(nullptr, 65536, 0), Fails(EFAULT));
 }
 
-TEST(LlvmLibcGetRandomTest, ReturnsSize) {
+TEST_F(LlvmLibcGetRandomTest, ReturnsSize) {
   LIBC_NAMESPACE::cpp::array<char, 10> buffer;
   for (size_t i = 0; i < buffer.size(); ++i) {
     // Without GRND_RANDOM set this should never fail.
@@ -37,7 +35,7 @@ TEST(LlvmLibcGetRandomTest, ReturnsSize) {
   }
 }
 
-TEST(LlvmLibcGetRandomTest, CheckValue) {
+TEST_F(LlvmLibcGetRandomTest, CheckValue) {
   // Probability of picking one particular value amongst 256 possibilities a
   // hundred times in a row is (1/256)^100 = 1.49969681e-241.
   LIBC_NAMESPACE::cpp::array<char, 100> buffer;
diff --git a/test/src/sys/resource/getrlimit_setrlimit_test.cpp b/test/src/sys/resource/getrlimit_setrlimit_test.cpp
index 62d21c3..d6e1490 100644
--- a/test/src/sys/resource/getrlimit_setrlimit_test.cpp
+++ b/test/src/sys/resource/getrlimit_setrlimit_test.cpp
@@ -7,29 +7,28 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/__support/CPP/string_view.h"
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/resource/getrlimit.h"
 #include "src/sys/resource/setrlimit.h"
 #include "src/unistd/close.h"
 #include "src/unistd/unlink.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include <sys/resource.h>
 #include <sys/stat.h>
 
-TEST(LlvmLibcResourceLimitsTest, SetNoFileLimit) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcResourceLimitsTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
+TEST_F(LlvmLibcResourceLimitsTest, SetNoFileLimit) {
   // The test strategy is to first create initialize two file descriptors
   // successfully. Next, close the files and set the file descriptor limit
   // to 4. This will allow us to open one of those file but not the other.
 
   constexpr const char *TEST_FILE1 = "testdata/resource_limits1.test";
   constexpr const char *TEST_FILE2 = "testdata/resource_limits2.test";
-  LIBC_NAMESPACE::libc_errno = 0;
 
   int fd1 = LIBC_NAMESPACE::open(TEST_FILE1, O_CREAT | O_WRONLY, S_IRWXU);
   ASSERT_GT(fd1, 0);
@@ -54,7 +53,6 @@ TEST(LlvmLibcResourceLimitsTest, SetNoFileLimit) {
   ASSERT_LT(fd2, 0);
   ASSERT_ERRNO_FAILURE();
 
-  LIBC_NAMESPACE::libc_errno = 0;
   ASSERT_THAT(LIBC_NAMESPACE::close(fd1), Succeeds(0));
 
   fd2 = LIBC_NAMESPACE::open(TEST_FILE2, O_RDONLY);
@@ -64,7 +62,6 @@ TEST(LlvmLibcResourceLimitsTest, SetNoFileLimit) {
   ASSERT_LT(fd1, 0);
   ASSERT_ERRNO_FAILURE();
 
-  LIBC_NAMESPACE::libc_errno = 0;
   ASSERT_THAT(LIBC_NAMESPACE::close(fd2), Succeeds(0));
 
   ASSERT_THAT(LIBC_NAMESPACE::unlink(TEST_FILE1), Succeeds(0));
diff --git a/test/src/sys/select/select_failure_test.cpp b/test/src/sys/select/select_failure_test.cpp
index a4990bf..c5a7ad7 100644
--- a/test/src/sys/select/select_failure_test.cpp
+++ b/test/src/sys/select/select_failure_test.cpp
@@ -8,6 +8,7 @@
 
 #include "src/sys/select/select.h"
 #include "src/unistd/read.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
@@ -15,8 +16,9 @@
 #include <unistd.h>
 
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+using LlvmLibcSelectTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcSelectTest, SelectInvalidFD) {
+TEST_F(LlvmLibcSelectTest, SelectInvalidFD) {
   fd_set set;
   FD_ZERO(&set);
   struct timeval timeout {
diff --git a/test/src/sys/select/select_ui_test.cpp b/test/src/sys/select/select_ui_test.cpp
index a158cab..f2e1786 100644
--- a/test/src/sys/select/select_ui_test.cpp
+++ b/test/src/sys/select/select_ui_test.cpp
@@ -6,19 +6,22 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/sys/select/select.h"
 #include "src/unistd/read.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
+#include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include <sys/select.h>
 #include <unistd.h>
 
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcSelectTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
+
 // This test is not be run automatically as part of the libc testsuite.
 // Instead, one has to run it manually and press a key on the keyboard
 // to make the test succeed.
-TEST(LlvmLibcSelectTest, ReadStdinAfterSelect) {
-  LIBC_NAMESPACE::libc_errno = 0;
+TEST_F(LlvmLibcSelectTest, ReadStdinAfterSelect) {
   constexpr int STDIN_FD = 0;
   fd_set set;
   FD_ZERO(&set);
@@ -32,19 +35,20 @@ TEST(LlvmLibcSelectTest, ReadStdinAfterSelect) {
 
   // Zero timeout means we don't wait for input. So, select should return
   // immediately.
-  int count =
-      LIBC_NAMESPACE::select(STDIN_FD + 1, &set, nullptr, nullptr, &zero);
+  ASSERT_THAT(
+      LIBC_NAMESPACE::select(STDIN_FD + 1, &set, nullptr, nullptr, &zero),
+      Succeeds(0));
   // The set should indicate that stdin is NOT ready for reading.
   ASSERT_EQ(0, FD_ISSET(STDIN_FD, &set));
 
   FD_SET(STDIN_FD, &set);
   // Wait for an hour and give the user a chance to hit a key.
-  count = LIBC_NAMESPACE::select(STDIN_FD + 1, &set, nullptr, nullptr, &hr);
-  ASSERT_EQ(count, 1);
+  ASSERT_THAT(LIBC_NAMESPACE::select(STDIN_FD + 1, &set, nullptr, nullptr, &hr),
+              Succeeds(1));
   // The set should indicate that stdin is ready for reading.
   ASSERT_EQ(1, FD_ISSET(STDIN_FD, &set));
 
   // Verify that atleast one character can be read.
   char c;
-  ASSERT_EQ(LIBC_NAMESPACE::read(STDIN_FD, &c, 1), ssize_t(1));
+  ASSERT_THAT(LIBC_NAMESPACE::read(STDIN_FD, &c, 1), Succeeds(ssize_t(1)));
 }
diff --git a/test/src/sys/sendfile/sendfile_test.cpp b/test/src/sys/sendfile/sendfile_test.cpp
index a658212..4e789ba 100644
--- a/test/src/sys/sendfile/sendfile_test.cpp
+++ b/test/src/sys/sendfile/sendfile_test.cpp
@@ -7,25 +7,24 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/__support/CPP/string_view.h"
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/sendfile/sendfile.h"
 #include "src/unistd/close.h"
 #include "src/unistd/read.h"
 #include "src/unistd/unlink.h"
 #include "src/unistd/write.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include "hdr/fcntl_macros.h"
 #include <sys/stat.h>
 
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcSendfileTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 namespace cpp = LIBC_NAMESPACE::cpp;
 
-TEST(LlvmLibcSendfileTest, CreateAndTransfer) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
-
+TEST_F(LlvmLibcSendfileTest, CreateAndTransfer) {
   // The test strategy is to
   //   1. Create a temporary file with known data.
   //   2. Use sendfile to copy it to another file.
@@ -35,7 +34,6 @@ TEST(LlvmLibcSendfileTest, CreateAndTransfer) {
   constexpr const char *OUT_FILE = "testdata/sendfile_out.test";
   const char IN_DATA[] = "sendfile test";
   constexpr ssize_t IN_SIZE = ssize_t(sizeof(IN_DATA));
-  LIBC_NAMESPACE::libc_errno = 0;
 
   int in_fd = LIBC_NAMESPACE::open(IN_FILE, O_CREAT | O_WRONLY, S_IRWXU);
   ASSERT_GT(in_fd, 0);
diff --git a/test/src/sys/stat/chmod_test.cpp b/test/src/sys/stat/chmod_test.cpp
index 83ab0f4..fbdb1fb 100644
--- a/test/src/sys/stat/chmod_test.cpp
+++ b/test/src/sys/stat/chmod_test.cpp
@@ -6,21 +6,21 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/stat/chmod.h"
 #include "src/unistd/close.h"
 #include "src/unistd/write.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include "hdr/fcntl_macros.h"
 #include <sys/stat.h>
 
-TEST(LlvmLibcChmodTest, ChangeAndOpen) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcChmodTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
+TEST_F(LlvmLibcChmodTest, ChangeAndOpen) {
   // The test file is initially writable. We open it for writing and ensure
   // that it indeed can be opened for writing. Next, we close the file and
   // make it readonly using chmod. We test that chmod actually succeeded by
@@ -28,7 +28,6 @@ TEST(LlvmLibcChmodTest, ChangeAndOpen) {
   constexpr const char *TEST_FILE = "testdata/chmod.test";
   const char WRITE_DATA[] = "test data";
   constexpr ssize_t WRITE_SIZE = ssize_t(sizeof(WRITE_DATA));
-  LIBC_NAMESPACE::libc_errno = 0;
 
   int fd = LIBC_NAMESPACE::open(TEST_FILE, O_APPEND | O_WRONLY);
   ASSERT_GT(fd, 0);
@@ -46,7 +45,6 @@ TEST(LlvmLibcChmodTest, ChangeAndOpen) {
   // Opening for writing should fail.
   EXPECT_EQ(LIBC_NAMESPACE::open(TEST_FILE, O_APPEND | O_WRONLY), -1);
   ASSERT_ERRNO_FAILURE();
-  LIBC_NAMESPACE::libc_errno = 0;
   // But opening for reading should succeed.
   fd = LIBC_NAMESPACE::open(TEST_FILE, O_APPEND | O_RDONLY);
   EXPECT_GT(fd, 0);
@@ -56,10 +54,7 @@ TEST(LlvmLibcChmodTest, ChangeAndOpen) {
   EXPECT_THAT(LIBC_NAMESPACE::chmod(TEST_FILE, S_IRWXU), Succeeds(0));
 }
 
-TEST(LlvmLibcChmodTest, NonExistentFile) {
-  LIBC_NAMESPACE::libc_errno = 0;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+TEST_F(LlvmLibcChmodTest, NonExistentFile) {
   ASSERT_THAT(LIBC_NAMESPACE::chmod("non-existent-file", S_IRUSR),
               Fails(ENOENT));
-  LIBC_NAMESPACE::libc_errno = 0;
 }
diff --git a/test/src/sys/stat/fchmod_test.cpp b/test/src/sys/stat/fchmod_test.cpp
index 03eb79d..eff6924 100644
--- a/test/src/sys/stat/fchmod_test.cpp
+++ b/test/src/sys/stat/fchmod_test.cpp
@@ -6,21 +6,21 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/stat/fchmod.h"
 #include "src/unistd/close.h"
 #include "src/unistd/write.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include "hdr/fcntl_macros.h"
 #include <sys/stat.h>
 
-TEST(LlvmLibcChmodTest, ChangeAndOpen) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcFchmodTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
+TEST_F(LlvmLibcFchmodTest, ChangeAndOpen) {
   // The test file is initially writable. We open it for writing and ensure
   // that it indeed can be opened for writing. Next, we close the file and
   // make it readonly using chmod. We test that chmod actually succeeded by
@@ -28,7 +28,6 @@ TEST(LlvmLibcChmodTest, ChangeAndOpen) {
   constexpr const char *TEST_FILE = "testdata/fchmod.test";
   const char WRITE_DATA[] = "test data";
   constexpr ssize_t WRITE_SIZE = ssize_t(sizeof(WRITE_DATA));
-  LIBC_NAMESPACE::libc_errno = 0;
 
   int fd = LIBC_NAMESPACE::open(TEST_FILE, O_APPEND | O_WRONLY);
   ASSERT_GT(fd, 0);
@@ -46,7 +45,6 @@ TEST(LlvmLibcChmodTest, ChangeAndOpen) {
   // Opening for writing should fail.
   EXPECT_EQ(LIBC_NAMESPACE::open(TEST_FILE, O_APPEND | O_WRONLY), -1);
   ASSERT_ERRNO_FAILURE();
-  LIBC_NAMESPACE::libc_errno = 0;
   // But opening for reading should succeed.
   fd = LIBC_NAMESPACE::open(TEST_FILE, O_APPEND | O_RDONLY);
   EXPECT_GT(fd, 0);
@@ -56,9 +54,7 @@ TEST(LlvmLibcChmodTest, ChangeAndOpen) {
   EXPECT_THAT(LIBC_NAMESPACE::close(fd), Succeeds(0));
 }
 
-TEST(LlvmLibcChmodTest, NonExistentFile) {
-  LIBC_NAMESPACE::libc_errno = 0;
+TEST_F(LlvmLibcFchmodTest, NonExistentFile) {
   ASSERT_EQ(LIBC_NAMESPACE::fchmod(-1, S_IRUSR), -1);
   ASSERT_ERRNO_FAILURE();
-  LIBC_NAMESPACE::libc_errno = 0;
 }
diff --git a/test/src/sys/stat/fchmodat_test.cpp b/test/src/sys/stat/fchmodat_test.cpp
index 09970b6..c8b2631 100644
--- a/test/src/sys/stat/fchmodat_test.cpp
+++ b/test/src/sys/stat/fchmodat_test.cpp
@@ -6,21 +6,21 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/stat/fchmodat.h"
 #include "src/unistd/close.h"
 #include "src/unistd/write.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include "hdr/fcntl_macros.h"
 #include <sys/stat.h>
 
-TEST(LlvmLibcFchmodatTest, ChangeAndOpen) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcFchmodatTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
+TEST_F(LlvmLibcFchmodatTest, ChangeAndOpen) {
   // The test file is initially writable. We open it for writing and ensure
   // that it indeed can be opened for writing. Next, we close the file and
   // make it readonly using chmod. We test that chmod actually succeeded by
@@ -30,7 +30,6 @@ TEST(LlvmLibcFchmodatTest, ChangeAndOpen) {
   constexpr const char *TEST_FILE_BASENAME = "fchmodat.test";
   const char WRITE_DATA[] = "fchmodat test";
   constexpr ssize_t WRITE_SIZE = ssize_t(sizeof(WRITE_DATA));
-  LIBC_NAMESPACE::libc_errno = 0;
 
   int fd = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_WRONLY, S_IRWXU);
   ASSERT_GT(fd, 0);
@@ -49,7 +48,6 @@ TEST(LlvmLibcFchmodatTest, ChangeAndOpen) {
   // Opening for writing should fail.
   EXPECT_EQ(LIBC_NAMESPACE::open(TEST_FILE, O_APPEND | O_WRONLY), -1);
   ASSERT_ERRNO_FAILURE();
-  LIBC_NAMESPACE::libc_errno = 0;
   // But opening for reading should succeed.
   fd = LIBC_NAMESPACE::open(TEST_FILE, O_APPEND | O_RDONLY);
   EXPECT_GT(fd, 0);
@@ -62,11 +60,8 @@ TEST(LlvmLibcFchmodatTest, ChangeAndOpen) {
   EXPECT_THAT(LIBC_NAMESPACE::close(dirfd), Succeeds(0));
 }
 
-TEST(LlvmLibcFchmodatTest, NonExistentFile) {
-  LIBC_NAMESPACE::libc_errno = 0;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+TEST_F(LlvmLibcFchmodatTest, NonExistentFile) {
   ASSERT_THAT(
       LIBC_NAMESPACE::fchmodat(AT_FDCWD, "non-existent-file", S_IRUSR, 0),
       Fails(ENOENT));
-  LIBC_NAMESPACE::libc_errno = 0;
 }
diff --git a/test/src/sys/stat/fstat_test.cpp b/test/src/sys/stat/fstat_test.cpp
index 34c675d..3a0fb69 100644
--- a/test/src/sys/stat/fstat_test.cpp
+++ b/test/src/sys/stat/fstat_test.cpp
@@ -6,27 +6,26 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/stat/fstat.h"
 #include "src/unistd/close.h"
 #include "src/unistd/unlink.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include "hdr/fcntl_macros.h"
 #include <sys/stat.h>
 
-TEST(LlvmLibcFStatTest, CreatAndReadMode) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcFStatTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
+TEST_F(LlvmLibcFStatTest, CreatAndReadMode) {
   // The test file is initially writable. We open it for writing and ensure
   // that it indeed can be opened for writing. Next, we close the file and
   // make it readonly using chmod. We test that chmod actually succeeded by
   // trying to open the file for writing and failing.
   constexpr const char *TEST_FILE = "testdata/fstat.test";
-  LIBC_NAMESPACE::libc_errno = 0;
 
   int fd = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_WRONLY, S_IRWXU);
   ASSERT_GT(fd, 0);
@@ -41,10 +40,7 @@ TEST(LlvmLibcFStatTest, CreatAndReadMode) {
   ASSERT_THAT(LIBC_NAMESPACE::unlink(TEST_FILE), Succeeds(0));
 }
 
-TEST(LlvmLibcFStatTest, NonExistentFile) {
-  LIBC_NAMESPACE::libc_errno = 0;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+TEST_F(LlvmLibcFStatTest, NonExistentFile) {
   struct stat statbuf;
   ASSERT_THAT(LIBC_NAMESPACE::fstat(-1, &statbuf), Fails(EBADF));
-  LIBC_NAMESPACE::libc_errno = 0;
 }
diff --git a/test/src/sys/stat/lstat_test.cpp b/test/src/sys/stat/lstat_test.cpp
index a723d5a..1da19c9 100644
--- a/test/src/sys/stat/lstat_test.cpp
+++ b/test/src/sys/stat/lstat_test.cpp
@@ -6,27 +6,26 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/stat/lstat.h"
 #include "src/unistd/close.h"
 #include "src/unistd/unlink.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include "hdr/fcntl_macros.h"
 #include <sys/stat.h>
 
-TEST(LlvmLibcLStatTest, CreatAndReadMode) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcLStatTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
+TEST_F(LlvmLibcLStatTest, CreatAndReadMode) {
   // The test file is initially writable. We open it for writing and ensure
   // that it indeed can be opened for writing. Next, we close the file and
   // make it readonly using chmod. We test that chmod actually succeeded by
   // trying to open the file for writing and failing.
   constexpr const char *TEST_FILE = "testdata/lstat.test";
-  LIBC_NAMESPACE::libc_errno = 0;
 
   int fd = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_WRONLY, S_IRWXU);
   ASSERT_GT(fd, 0);
@@ -41,11 +40,8 @@ TEST(LlvmLibcLStatTest, CreatAndReadMode) {
   ASSERT_THAT(LIBC_NAMESPACE::unlink(TEST_FILE), Succeeds(0));
 }
 
-TEST(LlvmLibcLStatTest, NonExistentFile) {
-  LIBC_NAMESPACE::libc_errno = 0;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+TEST_F(LlvmLibcLStatTest, NonExistentFile) {
   struct stat statbuf;
   ASSERT_THAT(LIBC_NAMESPACE::lstat("non-existent-file", &statbuf),
               Fails(ENOENT));
-  LIBC_NAMESPACE::libc_errno = 0;
 }
diff --git a/test/src/sys/stat/mkdirat_test.cpp b/test/src/sys/stat/mkdirat_test.cpp
index 85e013d..fd32a44 100644
--- a/test/src/sys/stat/mkdirat_test.cpp
+++ b/test/src/sys/stat/mkdirat_test.cpp
@@ -8,13 +8,16 @@
 
 #include "src/sys/stat/mkdirat.h"
 #include "src/unistd/rmdir.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include "hdr/fcntl_macros.h"
 
-TEST(LlvmLibcMkdiratTest, CreateAndRemove) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcMkdiratTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
+
+TEST_F(LlvmLibcMkdiratTest, CreateAndRemove) {
   constexpr const char *FILENAME = "testdata/mkdirat.testdir";
   auto TEST_DIR = libc_make_test_file_path(FILENAME);
   ASSERT_THAT(LIBC_NAMESPACE::mkdirat(AT_FDCWD, TEST_DIR, S_IRWXU),
@@ -22,8 +25,7 @@ TEST(LlvmLibcMkdiratTest, CreateAndRemove) {
   ASSERT_THAT(LIBC_NAMESPACE::rmdir(TEST_DIR), Succeeds(0));
 }
 
-TEST(LlvmLibcMkdiratTest, BadPath) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+TEST_F(LlvmLibcMkdiratTest, BadPath) {
   ASSERT_THAT(
       LIBC_NAMESPACE::mkdirat(AT_FDCWD, "non-existent-dir/test", S_IRWXU),
       Fails(ENOENT));
diff --git a/test/src/sys/stat/stat_test.cpp b/test/src/sys/stat/stat_test.cpp
index 0ddd8ba..88ef37e 100644
--- a/test/src/sys/stat/stat_test.cpp
+++ b/test/src/sys/stat/stat_test.cpp
@@ -6,27 +6,26 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/stat/stat.h"
 #include "src/unistd/close.h"
 #include "src/unistd/unlink.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include "hdr/fcntl_macros.h"
 #include <sys/stat.h>
 
-TEST(LlvmLibcStatTest, CreatAndReadMode) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcStatTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
+TEST_F(LlvmLibcStatTest, CreatAndReadMode) {
   // The test file is initially writable. We open it for writing and ensure
   // that it indeed can be opened for writing. Next, we close the file and
   // make it readonly using chmod. We test that chmod actually succeeded by
   // trying to open the file for writing and failing.
   constexpr const char *TEST_FILE = "testdata/stat.test";
-  LIBC_NAMESPACE::libc_errno = 0;
 
   int fd = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_WRONLY, S_IRWXU);
   ASSERT_GT(fd, 0);
@@ -41,11 +40,8 @@ TEST(LlvmLibcStatTest, CreatAndReadMode) {
   ASSERT_THAT(LIBC_NAMESPACE::unlink(TEST_FILE), Succeeds(0));
 }
 
-TEST(LlvmLibcStatTest, NonExistentFile) {
-  LIBC_NAMESPACE::libc_errno = 0;
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+TEST_F(LlvmLibcStatTest, NonExistentFile) {
   struct stat statbuf;
   ASSERT_THAT(LIBC_NAMESPACE::stat("non-existent-file", &statbuf),
               Fails(ENOENT));
-  LIBC_NAMESPACE::libc_errno = 0;
 }
diff --git a/test/src/sys/statvfs/linux/fstatvfs_test.cpp b/test/src/sys/statvfs/linux/fstatvfs_test.cpp
index f4d71e9..455a826 100644
--- a/test/src/sys/statvfs/linux/fstatvfs_test.cpp
+++ b/test/src/sys/statvfs/linux/fstatvfs_test.cpp
@@ -8,17 +8,20 @@
 
 #include "hdr/fcntl_macros.h"
 #include "src/__support/macros/config.h"
+#include "src/errno/libc_errno.h"
 #include "src/fcntl/open.h"
 #include "src/sys/stat/mkdirat.h"
 #include "src/sys/statvfs/fstatvfs.h"
 #include "src/unistd/close.h"
 #include "src/unistd/rmdir.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcSysFStatvfsTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcSysFStatvfsTest, FStatvfsBasic) {
+TEST_F(LlvmLibcSysFStatvfsTest, FStatvfsBasic) {
   struct statvfs buf;
 
   int fd = LIBC_NAMESPACE::open("/", O_PATH);
@@ -30,7 +33,7 @@ TEST(LlvmLibcSysFStatvfsTest, FStatvfsBasic) {
   ASSERT_THAT(LIBC_NAMESPACE::close(fd), Succeeds(0));
 }
 
-TEST(LlvmLibcSysFStatvfsTest, FStatvfsInvalidPath) {
+TEST_F(LlvmLibcSysFStatvfsTest, FStatvfsInvalidPath) {
   struct statvfs buf;
 
   constexpr const char *FILENAME = "fstatvfs.testdir";
diff --git a/test/src/sys/statvfs/linux/statvfs_test.cpp b/test/src/sys/statvfs/linux/statvfs_test.cpp
index 32f8120..f356bb3 100644
--- a/test/src/sys/statvfs/linux/statvfs_test.cpp
+++ b/test/src/sys/statvfs/linux/statvfs_test.cpp
@@ -12,18 +12,20 @@
 #include "src/sys/stat/mkdirat.h"
 #include "src/sys/statvfs/statvfs.h"
 #include "src/unistd/rmdir.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcSysStatvfsTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
 
-TEST(LlvmLibcSysStatvfsTest, StatvfsBasic) {
+TEST_F(LlvmLibcSysStatvfsTest, StatvfsBasic) {
   struct statvfs buf;
   // The root of the file directory must always exist
   ASSERT_THAT(LIBC_NAMESPACE::statvfs("/", &buf), Succeeds());
 }
 
-TEST(LlvmLibcSysStatvfsTest, StatvfsInvalidPath) {
+TEST_F(LlvmLibcSysStatvfsTest, StatvfsInvalidPath) {
   struct statvfs buf;
 
   ASSERT_THAT(LIBC_NAMESPACE::statvfs("", &buf), Fails(ENOENT));
diff --git a/test/src/sys/time/getitimer_test.cpp b/test/src/sys/time/getitimer_test.cpp
new file mode 100644
index 0000000..c1d6f72
--- /dev/null
+++ b/test/src/sys/time/getitimer_test.cpp
@@ -0,0 +1,41 @@
+//===-- Unittests for getitimer -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM
+// Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/struct_itimerval.h"
+#include "src/sys/time/getitimer.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
+#include "test/UnitTest/ErrnoSetterMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcSysTimeGetitimerTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
+
+TEST_F(LlvmLibcSysTimeGetitimerTest, SmokeTest) {
+  struct itimerval timer;
+  timer.it_value.tv_sec = -1;
+  timer.it_value.tv_usec = -1;
+  timer.it_interval.tv_sec = -1;
+  timer.it_interval.tv_usec = -1;
+
+  ASSERT_THAT(LIBC_NAMESPACE::getitimer(0, &timer),
+              returns(EQ(0)).with_errno(EQ(0)));
+
+  ASSERT_TRUE(timer.it_value.tv_sec == 0);
+  ASSERT_TRUE(timer.it_value.tv_usec == 0);
+  ASSERT_TRUE(timer.it_interval.tv_sec == 0);
+  ASSERT_TRUE(timer.it_interval.tv_usec == 0);
+}
+
+TEST_F(LlvmLibcSysTimeGetitimerTest, InvalidRetTest) {
+  struct itimerval timer;
+
+  // out of range timer type (which)
+  ASSERT_THAT(LIBC_NAMESPACE::getitimer(99, &timer),
+              returns(NE(0)).with_errno(NE(0)));
+}
diff --git a/test/src/sys/time/setitimer_test.cpp b/test/src/sys/time/setitimer_test.cpp
new file mode 100644
index 0000000..16d33fd
--- /dev/null
+++ b/test/src/sys/time/setitimer_test.cpp
@@ -0,0 +1,57 @@
+//===-- Unittests for setitimer -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM
+// Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/struct_itimerval.h"
+#include "hdr/types/struct_sigaction.h"
+#include "src/signal/sigaction.h"
+#include "src/signal/sigemptyset.h"
+#include "src/sys/time/setitimer.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
+#include "test/UnitTest/ErrnoSetterMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcSysTimeSetitimerTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
+
+static bool timer_fired(false);
+
+extern "C" void handle_sigalrm(int) { timer_fired = true; }
+
+TEST_F(LlvmLibcSysTimeSetitimerTest, SmokeTest) {
+  LIBC_NAMESPACE::libc_errno = 0;
+  struct sigaction sa;
+  sa.sa_handler = handle_sigalrm;
+  LIBC_NAMESPACE::sigemptyset(&sa.sa_mask);
+  sa.sa_flags = 0;
+  LIBC_NAMESPACE::sigaction(SIGALRM, &sa, nullptr);
+
+  struct itimerval timer;
+  timer.it_value.tv_sec = 0;
+  timer.it_value.tv_usec = 200000;
+  timer.it_interval.tv_sec = 0;
+  timer.it_interval.tv_usec = 0; // One-shot timer
+
+  ASSERT_THAT(LIBC_NAMESPACE::setitimer(0, &timer, nullptr),
+              returns(EQ(0)).with_errno(EQ(0)));
+
+  while (true) {
+    if (timer_fired)
+      break;
+  }
+
+  ASSERT_TRUE(timer_fired);
+}
+
+TEST_F(LlvmLibcSysTimeSetitimerTest, InvalidRetTest) {
+  struct itimerval timer;
+
+  // out of range timer type (which)
+  ASSERT_THAT(LIBC_NAMESPACE::setitimer(99, &timer, nullptr),
+              returns(NE(0)).with_errno(NE(0)));
+}
diff --git a/test/src/sys/time/utimes_test.cpp b/test/src/sys/time/utimes_test.cpp
new file mode 100644
index 0000000..36c1e8b
--- /dev/null
+++ b/test/src/sys/time/utimes_test.cpp
@@ -0,0 +1,97 @@
+//===-- Unittests for utimes ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/fcntl_macros.h"
+#include "hdr/sys_stat_macros.h"
+#include "hdr/types/struct_timeval.h"
+#include "src/fcntl/open.h"
+#include "src/stdio/remove.h"
+#include "src/sys/stat/stat.h"
+#include "src/sys/time/utimes.h"
+#include "src/unistd/close.h"
+
+#include "test/UnitTest/ErrnoCheckingTest.h"
+#include "test/UnitTest/ErrnoSetterMatcher.h"
+#include "test/UnitTest/Test.h"
+
+using LlvmLibcUtimesTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
+
+// SUCCESS: Takes a file and successfully updates
+// its last access and modified times.
+TEST_F(LlvmLibcUtimesTest, ChangeTimesSpecific) {
+  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+
+  constexpr const char *FILE_PATH = "utimes_pass.test";
+  auto TEST_FILE = libc_make_test_file_path(FILE_PATH);
+  int fd = LIBC_NAMESPACE::open(TEST_FILE, O_WRONLY | O_CREAT, S_IRWXU);
+  ASSERT_ERRNO_SUCCESS();
+  ASSERT_GT(fd, 0);
+  ASSERT_THAT(LIBC_NAMESPACE::close(fd), Succeeds(0));
+
+  // make a dummy timeval struct
+  struct timeval times[2];
+  times[0].tv_sec = 54321;
+  times[0].tv_usec = 12345;
+  times[1].tv_sec = 43210;
+  times[1].tv_usec = 23456;
+
+  // ensure utimes succeeds
+  ASSERT_THAT(LIBC_NAMESPACE::utimes(TEST_FILE, times), Succeeds(0));
+
+  // verify the times values against stat of the TEST_FILE
+  struct stat statbuf;
+  ASSERT_EQ(LIBC_NAMESPACE::stat(TEST_FILE, &statbuf), 0);
+
+  // seconds
+  ASSERT_EQ(statbuf.st_atim.tv_sec, times[0].tv_sec);
+  ASSERT_EQ(statbuf.st_mtim.tv_sec, times[1].tv_sec);
+
+  // microseconds
+  ASSERT_EQ(statbuf.st_atim.tv_nsec,
+            static_cast<long>(times[0].tv_usec * 1000));
+  ASSERT_EQ(statbuf.st_mtim.tv_nsec,
+            static_cast<long>(times[1].tv_usec * 1000));
+
+  ASSERT_THAT(LIBC_NAMESPACE::remove(TEST_FILE), Succeeds(0));
+}
+
+// FAILURE: Invalid values in the timeval struct
+// to check that utimes rejects it.
+TEST_F(LlvmLibcUtimesTest, InvalidMicroseconds) {
+  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+
+  constexpr const char *FILE_PATH = "utimes_fail.test";
+  auto TEST_FILE = libc_make_test_file_path(FILE_PATH);
+  int fd = LIBC_NAMESPACE::open(TEST_FILE, O_WRONLY | O_CREAT, S_IRWXU);
+  ASSERT_GT(fd, 0);
+  ASSERT_THAT(LIBC_NAMESPACE::close(fd), Succeeds(0));
+
+  // make a dummy timeval struct
+  // populated with bad usec values
+  struct timeval times[2];
+  times[0].tv_sec = 54321;
+  times[0].tv_usec = 4567;
+  times[1].tv_sec = 43210;
+  times[1].tv_usec = 1000000; // invalid
+
+  // ensure utimes fails
+  ASSERT_THAT(LIBC_NAMESPACE::utimes(TEST_FILE, times), Fails(EINVAL));
+
+  // check for failure on
+  // the other possible bad values
+
+  times[0].tv_sec = 54321;
+  times[0].tv_usec = -4567; // invalid
+  times[1].tv_sec = 43210;
+  times[1].tv_usec = 1000;
+
+  // ensure utimes fails once more
+  ASSERT_THAT(LIBC_NAMESPACE::utimes(TEST_FILE, times), Fails(EINVAL));
+  ASSERT_THAT(LIBC_NAMESPACE::remove(TEST_FILE), Succeeds(0));
+}
diff --git a/test/src/sys/wait/wait4_test.cpp b/test/src/sys/wait/wait4_test.cpp
index c408004..c9875c3 100644
--- a/test/src/sys/wait/wait4_test.cpp
+++ b/test/src/sys/wait/wait4_test.cpp
@@ -7,16 +7,19 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/sys/wait/wait4.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include <sys/wait.h>
 
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcWait4Test = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
+
 // The test here is a simpl test for WNOHANG functionality. For a more
 // involved test, look at fork_test.
 
-TEST(LlvmLibcwait4Test, NoHangTest) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+TEST_F(LlvmLibcWait4Test, NoHangTest) {
   int status;
   ASSERT_THAT(LIBC_NAMESPACE::wait4(-1, &status, WNOHANG, nullptr),
               Fails(ECHILD));
diff --git a/test/src/sys/wait/waitpid_test.cpp b/test/src/sys/wait/waitpid_test.cpp
index fb456bf..c15f26f 100644
--- a/test/src/sys/wait/waitpid_test.cpp
+++ b/test/src/sys/wait/waitpid_test.cpp
@@ -7,16 +7,19 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/sys/wait/waitpid.h"
+#include "test/UnitTest/ErrnoCheckingTest.h"
 #include "test/UnitTest/ErrnoSetterMatcher.h"
 #include "test/UnitTest/Test.h"
 
 #include <sys/wait.h>
 
+using namespace LIBC_NAMESPACE::testing::ErrnoSetterMatcher;
+using LlvmLibcWaitPidTest = LIBC_NAMESPACE::testing::ErrnoCheckingTest;
+
 // The test here is a simpl test for WNOHANG functionality. For a more
 // involved test, look at fork_test.
 
-TEST(LlvmLibcWaitPidTest, NoHangTest) {
-  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
+TEST_F(LlvmLibcWaitPidTest, NoHangTest) {
   int status;
   ASSERT_THAT(LIBC_NAMESPACE::waitpid(-1, &status, WNOHANG), Fails(ECHILD));
 }
diff --git a/test/src/time/ctime_test.cpp b/test/src/time/ctime_test.cpp
index 7ec71bb..6f1168f 100644
--- a/test/src/time/ctime_test.cpp
+++ b/test/src/time/ctime_test.cpp
@@ -11,10 +11,10 @@
 #include "test/UnitTest/Test.h"
 #include "test/src/time/TmHelper.h"
 
-TEST(LlvmLibcCtime, NULL) {
+TEST(LlvmLibcCtime, nullptr) {
   char *result;
-  result = LIBC_NAMESPACE::ctime(NULL);
-  ASSERT_STREQ(NULL, result);
+  result = LIBC_NAMESPACE::ctime(nullptr);
+  ASSERT_STREQ(nullptr, result);
 }
 
 TEST(LlvmLibcCtime, ValidUnixTimestamp0) {
@@ -38,5 +38,5 @@ TEST(LlvmLibcCtime, InvalidArgument) {
   char *result;
   t = 2147483648;
   result = LIBC_NAMESPACE::ctime(&t);
-  ASSERT_STREQ(NULL, result);
+  ASSERT_STREQ(nullptr, result);
 }
diff --git a/test/src/time/mktime_test.cpp b/test/src/time/mktime_test.cpp
index fe1116f..1dfdd73 100644
--- a/test/src/time/mktime_test.cpp
+++ b/test/src/time/mktime_test.cpp
@@ -18,6 +18,10 @@ using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Fails;
 using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
 using LIBC_NAMESPACE::time_constants::Month;
 
+#ifndef EOVERFLOW
+#define EOVERFLOW 0
+#endif
+
 static inline constexpr int tm_year(int year) {
   return year - LIBC_NAMESPACE::time_constants::TIME_YEAR_BASE;
 }
diff --git a/test/src/wchar/wcscat_test.cpp b/test/src/wchar/wcscat_test.cpp
new file mode 100644
index 0000000..e91f796
--- /dev/null
+++ b/test/src/wchar/wcscat_test.cpp
@@ -0,0 +1,47 @@
+//===-- Unittests for wcscat ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcscat.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSCatTest, EmptyDest) {
+  // Dest should be fully replaced with src.
+  wchar_t dest[4] = {L'\0'};
+  const wchar_t *src = L"abc";
+  LIBC_NAMESPACE::wcscat(dest, src);
+  ASSERT_TRUE(dest[0] == L'a');
+  ASSERT_TRUE(dest[1] == L'b');
+  ASSERT_TRUE(dest[2] == L'c');
+  ASSERT_TRUE(dest[3] == L'\0');
+}
+
+TEST(LlvmLibcWCSCatTest, NonEmptyDest) {
+  // Src should be appended on to dest.
+  wchar_t dest[7] = {L'x', L'y', L'z', L'\0'};
+  const wchar_t *src = L"abc";
+  LIBC_NAMESPACE::wcscat(dest, src);
+  ASSERT_TRUE(dest[0] == L'x');
+  ASSERT_TRUE(dest[1] == L'y');
+  ASSERT_TRUE(dest[2] == L'z');
+  ASSERT_TRUE(dest[3] == L'a');
+  ASSERT_TRUE(dest[4] == L'b');
+  ASSERT_TRUE(dest[5] == L'c');
+  ASSERT_TRUE(dest[6] == L'\0');
+}
+
+TEST(LlvmLibcWCSCatTest, EmptySrc) {
+  // Dest should remain intact.
+  wchar_t dest[4] = {L'x', L'y', L'z', L'\0'};
+  const wchar_t *src = L"";
+  LIBC_NAMESPACE::wcscat(dest, src);
+  ASSERT_TRUE(dest[0] == L'x');
+  ASSERT_TRUE(dest[1] == L'y');
+  ASSERT_TRUE(dest[2] == L'z');
+  ASSERT_TRUE(dest[3] == L'\0');
+}
diff --git a/test/src/wchar/wcschr_test.cpp b/test/src/wchar/wcschr_test.cpp
new file mode 100644
index 0000000..b494f3d
--- /dev/null
+++ b/test/src/wchar/wcschr_test.cpp
@@ -0,0 +1,61 @@
+//===-- Unittests for wcschr ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcschr.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSChrTest, FindsFirstCharacter) {
+  // Should return pointer to original string since 'a' is the first character.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(src, L'a'), src);
+}
+
+TEST(LlvmLibcWCSChrTest, FindsMiddleCharacter) {
+  // Should return pointer to 'c'.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(src, L'c'), (src + 2));
+}
+
+TEST(LlvmLibcWCSChrTest, FindsLastCharacterThatIsNotNullTerminator) {
+  // Should return pointer to 'e'.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(src, L'e'), (src + 4));
+}
+
+TEST(LlvmLibcWCSChrTest, FindsNullTerminator) {
+  // Should return pointer to null terminator.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(src, L'\0'), (src + 5));
+}
+
+TEST(LlvmLibcWCSChrTest, CharacterNotWithinStringShouldReturnNullptr) {
+  // Since 'z' is not within the string, should return nullptr.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(src, L'z'), nullptr);
+}
+
+TEST(LlvmLibcWCSChrTest, ShouldFindFirstOfDuplicates) {
+  // Should return pointer to the first '1'.
+  const wchar_t *src = L"abc1def1ghi";
+  ASSERT_EQ((int)(LIBC_NAMESPACE::wcschr(src, L'1') - src), 3);
+
+  // Should return original string since 'X' is the first character.
+  const wchar_t *dups = L"XXXXX";
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(dups, L'X'), dups);
+}
+
+TEST(LlvmLibcWCSChrTest, EmptyStringShouldOnlyMatchNullTerminator) {
+  // Null terminator should match
+  const wchar_t *src = L"";
+  ASSERT_EQ(src, LIBC_NAMESPACE::wcschr(src, L'\0'));
+  // All other characters should not match
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(src, L'Z'), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(src, L'3'), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wcschr(src, L'*'), nullptr);
+}
diff --git a/test/src/wchar/wcscmp_test.cpp b/test/src/wchar/wcscmp_test.cpp
new file mode 100644
index 0000000..6572aad
--- /dev/null
+++ b/test/src/wchar/wcscmp_test.cpp
@@ -0,0 +1,97 @@
+//===-- Unittests for wcscmp ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcscmp.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWcscmpTest, EmptyStringsShouldReturnZero) {
+  const wchar_t *s1 = L"";
+  const wchar_t *s2 = L"";
+  int result = LIBC_NAMESPACE::wcscmp(s1, s2);
+  ASSERT_EQ(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcscmp(s2, s1);
+  ASSERT_EQ(result, 0);
+}
+
+TEST(LlvmLibcWcscmpTest, EmptyStringShouldNotEqualNonEmptyString) {
+  const wchar_t *empty = L"";
+  const wchar_t *s2 = L"abc";
+  int result = LIBC_NAMESPACE::wcscmp(empty, s2);
+  ASSERT_LT(result, 0);
+
+  // Similar case if empty string is second argument.
+  const wchar_t *s3 = L"123";
+  result = LIBC_NAMESPACE::wcscmp(s3, empty);
+  ASSERT_GT(result, 0);
+}
+
+TEST(LlvmLibcWcscmpTest, EqualStringsShouldReturnZero) {
+  const wchar_t *s1 = L"abc";
+  const wchar_t *s2 = L"abc";
+  int result = LIBC_NAMESPACE::wcscmp(s1, s2);
+  ASSERT_EQ(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcscmp(s2, s1);
+  ASSERT_EQ(result, 0);
+}
+
+TEST(LlvmLibcWcscmpTest, ShouldReturnResultOfFirstDifference) {
+  const wchar_t *s1 = L"___B42__";
+  const wchar_t *s2 = L"___C55__";
+  int result = LIBC_NAMESPACE::wcscmp(s1, s2);
+  ASSERT_LT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcscmp(s2, s1);
+  ASSERT_GT(result, 0);
+}
+
+TEST(LlvmLibcWcscmpTest, CapitalizedLetterShouldNotBeEqual) {
+  const wchar_t *s1 = L"abcd";
+  const wchar_t *s2 = L"abCd";
+  int result = LIBC_NAMESPACE::wcscmp(s1, s2);
+  ASSERT_GT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcscmp(s2, s1);
+  ASSERT_LT(result, 0);
+}
+
+TEST(LlvmLibcWcscmpTest, UnequalLengthStringsShouldNotReturnZero) {
+  const wchar_t *s1 = L"abc";
+  const wchar_t *s2 = L"abcd";
+  int result = LIBC_NAMESPACE::wcscmp(s1, s2);
+  ASSERT_LT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcscmp(s2, s1);
+  ASSERT_GT(result, 0);
+}
+
+TEST(LlvmLibcWcscmpTest, StringArgumentSwapChangesSign) {
+  const wchar_t *a = L"a";
+  const wchar_t *b = L"b";
+  int result = LIBC_NAMESPACE::wcscmp(b, a);
+  ASSERT_GT(result, 0);
+
+  result = LIBC_NAMESPACE::wcscmp(a, b);
+  ASSERT_LT(result, 0);
+}
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+TEST(LlvmLibcWcscmpTest, NullptrCrash) {
+  // Passing in a nullptr should crash the program.
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wcscmp(L"aaaaaaaaaaaaaa", nullptr); },
+               WITH_SIGNAL(-1));
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wcscmp(nullptr, L"aaaaaaaaaaaaaa"); },
+               WITH_SIGNAL(-1));
+}
+#endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/wchar/wcscpy_test.cpp b/test/src/wchar/wcscpy_test.cpp
new file mode 100644
index 0000000..7b71b2b
--- /dev/null
+++ b/test/src/wchar/wcscpy_test.cpp
@@ -0,0 +1,48 @@
+//===-- Unittests for wcscpy ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcscpy.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSCpyTest, EmptySrc) {
+  // Empty src should lead to empty destination.
+  wchar_t dest[4] = {L'a', L'b', L'c', L'\0'};
+  const wchar_t *src = L"";
+  LIBC_NAMESPACE::wcscpy(dest, src);
+  ASSERT_TRUE(dest[0] == src[0]);
+  ASSERT_TRUE(dest[0] == L'\0');
+}
+
+TEST(LlvmLibcWCSCpyTest, EmptyDest) {
+  // Empty dest should result in src
+  const wchar_t *src = L"abc";
+  wchar_t dest[4];
+  LIBC_NAMESPACE::wcscpy(dest, src);
+  ASSERT_TRUE(dest[0] == L'a');
+  ASSERT_TRUE(dest[1] == L'b');
+  ASSERT_TRUE(dest[2] == L'c');
+  ASSERT_TRUE(dest[3] == L'\0');
+}
+
+TEST(LlvmLibcWCSCpyTest, OffsetDest) {
+  // Offsetting should result in a concatenation.
+  const wchar_t *src = L"abc";
+  wchar_t dest[7];
+  dest[0] = L'x';
+  dest[1] = L'y';
+  dest[2] = L'z';
+  LIBC_NAMESPACE::wcscpy(dest + 3, src);
+  ASSERT_TRUE(dest[0] == L'x');
+  ASSERT_TRUE(dest[1] == L'y');
+  ASSERT_TRUE(dest[2] == L'z');
+  ASSERT_TRUE(dest[3] == src[0]);
+  ASSERT_TRUE(dest[4] == src[1]);
+  ASSERT_TRUE(dest[5] == src[2]);
+  ASSERT_TRUE(dest[6] == src[3]);
+}
diff --git a/test/src/wchar/wcsncat_test.cpp b/test/src/wchar/wcsncat_test.cpp
new file mode 100644
index 0000000..47359f8
--- /dev/null
+++ b/test/src/wchar/wcsncat_test.cpp
@@ -0,0 +1,82 @@
+//===-- Unittests for wcscat ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcsncat.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSNCatTest, EmptyDest) {
+  wchar_t dest[4] = {L'\0'};
+  const wchar_t *src = L"abc";
+
+  // Start by copying nothing
+  LIBC_NAMESPACE::wcsncat(dest, src, 0);
+  ASSERT_TRUE(dest[0] == L'\0');
+
+  // Copying part of it.
+  LIBC_NAMESPACE::wcsncat(dest, src, 1);
+  ASSERT_TRUE(dest[0] == L'a');
+  ASSERT_TRUE(dest[1] == L'\0');
+
+  // Resetting for the last test.
+  dest[0] = '\0';
+
+  // Copying all of it.
+  LIBC_NAMESPACE::wcsncat(dest, src, 3);
+  ASSERT_TRUE(dest[0] == L'a');
+  ASSERT_TRUE(dest[1] == L'b');
+  ASSERT_TRUE(dest[2] == L'c');
+  ASSERT_TRUE(dest[3] == L'\0');
+}
+
+TEST(LlvmLibcWCSNCatTest, NonEmptyDest) {
+  wchar_t dest[7] = {L'x', L'y', L'z', L'\0'};
+  const wchar_t *src = L"abc";
+
+  // Adding on only part of the string
+  LIBC_NAMESPACE::wcsncat(dest, src, 1);
+  ASSERT_TRUE(dest[0] == L'x');
+  ASSERT_TRUE(dest[1] == L'y');
+  ASSERT_TRUE(dest[2] == L'z');
+  ASSERT_TRUE(dest[3] == L'a');
+  ASSERT_TRUE(dest[4] == L'\0');
+
+  // Copying more without resetting
+  LIBC_NAMESPACE::wcsncat(dest, src, 2);
+  ASSERT_TRUE(dest[0] == L'x');
+  ASSERT_TRUE(dest[1] == L'y');
+  ASSERT_TRUE(dest[2] == L'z');
+  ASSERT_TRUE(dest[3] == L'a');
+  ASSERT_TRUE(dest[4] == L'a');
+  ASSERT_TRUE(dest[5] == L'b');
+  ASSERT_TRUE(dest[6] == L'\0');
+
+  // Setting end marker to make sure it overwrites properly.
+  dest[3] = L'\0';
+
+  // Copying all of it.
+  LIBC_NAMESPACE::wcsncat(dest, src, 3);
+  ASSERT_TRUE(dest[0] == L'x');
+  ASSERT_TRUE(dest[1] == L'y');
+  ASSERT_TRUE(dest[2] == L'z');
+  ASSERT_TRUE(dest[3] == L'a');
+  ASSERT_TRUE(dest[4] == L'b');
+  ASSERT_TRUE(dest[5] == L'c');
+  ASSERT_TRUE(dest[6] == L'\0');
+
+  // Check that copying still works when count > src length.
+  dest[0] = L'\0';
+  // And that it doesn't write beyond what is necessary.
+  dest[4] = L'Z';
+  LIBC_NAMESPACE::wcsncat(dest, src, 4);
+  ASSERT_TRUE(dest[0] == L'a');
+  ASSERT_TRUE(dest[1] == L'b');
+  ASSERT_TRUE(dest[2] == L'c');
+  ASSERT_TRUE(dest[3] == L'\0');
+  ASSERT_TRUE(dest[4] == L'Z');
+}
diff --git a/test/src/wchar/wcsncmp_test.cpp b/test/src/wchar/wcsncmp_test.cpp
new file mode 100644
index 0000000..28bbb52
--- /dev/null
+++ b/test/src/wchar/wcsncmp_test.cpp
@@ -0,0 +1,169 @@
+//===-- Unittests for wcsncmp ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wcsncmp.h"
+#include "test/UnitTest/Test.h"
+
+// This group is just copies of the wcscmp tests, since all the same cases still
+// need to be tested.
+
+TEST(LlvmLibcWcsncmpTest, EmptyStringsShouldReturnZeroWithSufficientLength) {
+  const wchar_t *s1 = L"";
+  const wchar_t *s2 = L"";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 1);
+  ASSERT_EQ(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 1);
+  ASSERT_EQ(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest,
+     EmptyStringShouldNotEqualNonEmptyStringWithSufficientLength) {
+  const wchar_t *empty = L"";
+  const wchar_t *s2 = L"abc";
+  int result = LIBC_NAMESPACE::wcsncmp(empty, s2, 3);
+  ASSERT_LT(result, 0);
+
+  // Similar case if empty string is second argument.
+  const wchar_t *s3 = L"123";
+  result = LIBC_NAMESPACE::wcsncmp(s3, empty, 3);
+  ASSERT_GT(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest, EqualStringsShouldReturnZeroWithSufficientLength) {
+  const wchar_t *s1 = L"abc";
+  const wchar_t *s2 = L"abc";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 3);
+  ASSERT_EQ(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 3);
+  ASSERT_EQ(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest,
+     ShouldReturnResultOfFirstDifferenceWithSufficientLength) {
+  const wchar_t *s1 = L"___B42__";
+  const wchar_t *s2 = L"___C55__";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 8);
+  ASSERT_LT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 8);
+  ASSERT_GT(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest,
+     CapitalizedLetterShouldNotBeEqualWithSufficientLength) {
+  const wchar_t *s1 = L"abcd";
+  const wchar_t *s2 = L"abCd";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 4);
+  ASSERT_GT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 4);
+  ASSERT_LT(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest,
+     UnequalLengthStringsShouldNotReturnZeroWithSufficientLength) {
+  const wchar_t *s1 = L"abc";
+  const wchar_t *s2 = L"abcd";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 4);
+  ASSERT_LT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 4);
+  ASSERT_GT(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest, StringArgumentSwapChangesSignWithSufficientLength) {
+  const wchar_t *a = L"a";
+  const wchar_t *b = L"b";
+  int result = LIBC_NAMESPACE::wcsncmp(b, a, 1);
+  ASSERT_GT(result, 0);
+
+  result = LIBC_NAMESPACE::wcsncmp(a, b, 1);
+  ASSERT_LT(result, 0);
+}
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+TEST(LlvmLibcWcsncmpTest, NullptrCrash) {
+  // Passing in a nullptr should crash the program.
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wcsncmp(L"aaaaaaaaaaaaaa", nullptr, 3); },
+               WITH_SIGNAL(-1));
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wcsncmp(nullptr, L"aaaaaaaaaaaaaa", 3); },
+               WITH_SIGNAL(-1));
+}
+#endif // LIBC_HAS_ADDRESS_SANITIZER
+
+// This group is actually testing wcsncmp functionality
+
+TEST(LlvmLibcWcsncmpTest, NonEqualStringsEqualWithLengthZero) {
+  const wchar_t *s1 = L"abc";
+  const wchar_t *s2 = L"def";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 0);
+  ASSERT_EQ(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 0);
+  ASSERT_EQ(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest, NonEqualStringsNotEqualWithLengthOne) {
+  const wchar_t *s1 = L"abc";
+  const wchar_t *s2 = L"def";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 1);
+  ASSERT_LT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 1);
+  ASSERT_GT(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest, NonEqualStringsEqualWithShorterLength) {
+  const wchar_t *s1 = L"___B42__";
+  const wchar_t *s2 = L"___C55__";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 3);
+  ASSERT_EQ(result, 0);
+
+  // This should return 'B' - 'C' = -1.
+  result = LIBC_NAMESPACE::wcsncmp(s1, s2, 4);
+  ASSERT_LT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 3);
+  ASSERT_EQ(result, 0);
+
+  // This should return 'C' - 'B' = 1.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 4);
+  ASSERT_GT(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest, StringComparisonEndsOnNullByteEvenWithLongerLength) {
+  const wchar_t *s1 = L"abc\0def";
+  const wchar_t *s2 = L"abc\0abc";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 7);
+  ASSERT_EQ(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 7);
+  ASSERT_EQ(result, 0);
+}
+
+TEST(LlvmLibcWcsncmpTest, Case) {
+  const wchar_t *s1 = L"aB";
+  const wchar_t *s2 = L"ab";
+  int result = LIBC_NAMESPACE::wcsncmp(s1, s2, 2);
+  ASSERT_LT(result, 0);
+
+  // Verify operands reversed.
+  result = LIBC_NAMESPACE::wcsncmp(s2, s1, 2);
+  ASSERT_GT(result, 0);
+}
diff --git a/test/src/wchar/wcsncpy_test.cpp b/test/src/wchar/wcsncpy_test.cpp
new file mode 100644
index 0000000..9b5ffbe
--- /dev/null
+++ b/test/src/wchar/wcsncpy_test.cpp
@@ -0,0 +1,66 @@
+//===-- Unittests for wcsncpy ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcsncpy.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSNCpyTest, CopyZero) {
+  // Dest should remain unchanged.
+  wchar_t dest[3] = {L'a', L'b', L'\0'};
+  const wchar_t *src = L"x";
+  LIBC_NAMESPACE::wcsncpy(dest, src, 0);
+  ASSERT_TRUE(dest[0] == L'a');
+  ASSERT_TRUE(dest[1] == L'b');
+  ASSERT_TRUE(dest[2] == L'\0');
+}
+
+TEST(LlvmLibcWCSNCpyTest, CopyFullIntoEmpty) {
+  // Dest should be the exact same as src.
+  wchar_t dest[15];
+  const wchar_t *src = L"aaaaabbbbccccc";
+  LIBC_NAMESPACE::wcsncpy(dest, src, 15);
+  for (int i = 0; i < 15; i++)
+    ASSERT_TRUE(dest[i] == src[i]);
+}
+
+TEST(LlvmLibcWCSNCpyTest, CopyPartial) {
+  // First two characters of dest should be the first two characters of src.
+  wchar_t dest[] = {L'a', L'b', L'c', L'd', L'\0'};
+  const wchar_t *src = L"1234";
+  LIBC_NAMESPACE::wcsncpy(dest, src, 2);
+  ASSERT_TRUE(dest[0] == L'1');
+  ASSERT_TRUE(dest[1] == L'2');
+  ASSERT_TRUE(dest[2] == L'c');
+  ASSERT_TRUE(dest[3] == L'd');
+  ASSERT_TRUE(dest[4] == L'\0');
+}
+
+TEST(LlvmLibcWCSNCpyTest, CopyNullTerminator) {
+  // Null terminator should copy into dest.
+  wchar_t dest[] = {L'a', L'b', L'c', L'd', L'\0'};
+  const wchar_t src[] = {L'\0', L'y'};
+  LIBC_NAMESPACE::wcsncpy(dest, src, 1);
+  ASSERT_TRUE(dest[0] == L'\0');
+  ASSERT_TRUE(dest[1] == L'b');
+  ASSERT_TRUE(dest[2] == L'c');
+  ASSERT_TRUE(dest[3] == L'd');
+  ASSERT_TRUE(dest[4] == L'\0');
+}
+
+TEST(LlvmLibcWCSNCpyTest, CopyPastSrc) {
+  // Copying past src should fill with null terminator.
+  wchar_t dest[] = {L'a', L'b', L'c', L'd', L'\0'};
+  const wchar_t src[] = {L'x', L'\0'};
+  LIBC_NAMESPACE::wcsncpy(dest, src, 4);
+  ASSERT_TRUE(dest[0] == L'x');
+  ASSERT_TRUE(dest[1] == L'\0');
+  ASSERT_TRUE(dest[2] == L'\0');
+  ASSERT_TRUE(dest[3] == L'\0');
+  ASSERT_TRUE(dest[4] == L'\0');
+}
diff --git a/test/src/wchar/wcspbrk_test.cpp b/test/src/wchar/wcspbrk_test.cpp
new file mode 100644
index 0000000..bca9bff
--- /dev/null
+++ b/test/src/wchar/wcspbrk_test.cpp
@@ -0,0 +1,72 @@
+//===-- Unittests for wcspbrk ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcspbrk.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSPBrkTest, EmptyStringShouldReturnNullptr) {
+  // The search should not include the null terminator.
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(L"", L""), nullptr);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(L"_", L""), nullptr);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(L"", L"_"), nullptr);
+}
+
+TEST(LlvmLibcWCSPBrkTest, ShouldNotFindAnythingAfterNullTerminator) {
+  const wchar_t src[4] = {'a', 'b', '\0', 'c'};
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"c"), nullptr);
+}
+
+TEST(LlvmLibcWCSPBrkTest, ShouldReturnNullptrIfNoCharactersFound) {
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(L"12345", L"abcdef"), nullptr);
+}
+
+TEST(LlvmLibcWCSPBrkTest, FindsFirstCharacter) {
+  const wchar_t *src = L"12345";
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"1"), src);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"-1"), src);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"1_"), src);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"f1_"), src);
+}
+
+TEST(LlvmLibcWCSPBrkTest, FindsMiddleCharacter) {
+  const wchar_t *src = L"12345";
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"3"), src + 2);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"?3"), src + 2);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"3F"), src + 2);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"z3_"), src + 2);
+}
+
+TEST(LlvmLibcWCSPBrkTest, FindsLastCharacter) {
+  const wchar_t *src = L"12345";
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"5"), src + 4);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"r5"), src + 4);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"59"), src + 4);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"n5_"), src + 4);
+}
+
+TEST(LlvmLibcWCSPBrkTest, FindsFirstOfRepeated) {
+  const wchar_t *src = L"A,B,C,D";
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L","), src + 1);
+}
+
+TEST(LlvmLibcWCSPBrkTest, FindsFirstInBreakset) {
+  const wchar_t *src = L"12345";
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"34"), src + 2);
+  EXPECT_EQ(LIBC_NAMESPACE::wcspbrk(src, L"43"), src + 2);
+}
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+TEST(LlvmLibcWCSPBrkTest, NullptrCrash) {
+  // Passing in a nullptr should crash the program.
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wcspbrk(L"aaaaaaaaaaaaaa", nullptr); },
+               WITH_SIGNAL(-1));
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wcspbrk(nullptr, L"aaaaaaaaaaaaaa"); },
+               WITH_SIGNAL(-1));
+}
+#endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/wchar/wcsrchr_test.cpp b/test/src/wchar/wcsrchr_test.cpp
new file mode 100644
index 0000000..707dfb6
--- /dev/null
+++ b/test/src/wchar/wcsrchr_test.cpp
@@ -0,0 +1,68 @@
+//===-- Unittests for wcsrchr ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcsrchr.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSRChrTest, FindsFirstCharacter) {
+  // Should return pointer to original string since 'a' is the first character.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(src, L'a'), src);
+}
+
+TEST(LlvmLibcWCSRChrTest, FindsMiddleCharacter) {
+  // Should return pointer to 'c'.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(src, L'c'), (src + 2));
+}
+
+TEST(LlvmLibcWCSRChrTest, FindsLastCharacterThatIsNotNullTerminator) {
+  // Should return pointer to 'e'.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(src, L'e'), (src + 4));
+}
+
+TEST(LlvmLibcWCSRChrTest, FindsNullTerminator) {
+  // Should return pointer to null terminator.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(src, L'\0'), (src + 5));
+}
+
+TEST(LlvmLibcWCSRChrTest, CharacterNotWithinStringShouldReturnNullptr) {
+  // Since 'z' is not within the string, should return nullptr.
+  const wchar_t *src = L"abcde";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(src, L'z'), nullptr);
+}
+
+TEST(LlvmLibcWCSRChrTest, ShouldFindLastOfDuplicates) {
+  // Should return pointer to the last '1'.
+  const wchar_t *src = L"abc1def1ghi";
+  ASSERT_EQ((int)(LIBC_NAMESPACE::wcsrchr(src, L'1') - src), 7);
+
+  // Should return pointer to the last 'X'
+  const wchar_t *dups = L"XXXXX";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(dups, L'X'), dups + 4);
+}
+
+TEST(LlvmLibcWCSRChrTest, EmptyStringShouldOnlyMatchNullTerminator) {
+  // Null terminator should match
+  const wchar_t *src = L"";
+  ASSERT_EQ(src, LIBC_NAMESPACE::wcsrchr(src, L'\0'));
+  // All other characters should not match
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(src, L'Z'), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(src, L'3'), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wcsrchr(src, L'*'), nullptr);
+}
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+TEST(LlvmLibcWCSRChrTest, NullptrCrash) {
+  // Passing in a nullptr should crash the program.
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wcsrchr(nullptr, L'a'); }, WITH_SIGNAL(-1));
+}
+#endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/wchar/wcsspn_test.cpp b/test/src/wchar/wcsspn_test.cpp
new file mode 100644
index 0000000..fbcc35f
--- /dev/null
+++ b/test/src/wchar/wcsspn_test.cpp
@@ -0,0 +1,86 @@
+//===-- Unittests for wcsspn ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcsspn.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSSpnTest, EmptyStringShouldReturnZeroLengthSpan) {
+  // The search should not include the null terminator.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"", L""), size_t{0});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"_", L""), size_t{0});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"", L"_"), size_t{0});
+}
+
+TEST(LlvmLibcWCSSpnTest, ShouldNotSpanAnythingAfterNullTerminator) {
+  const wchar_t src[4] = {'a', 'b', '\0', 'c'};
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"ab"), size_t{2});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"c"), size_t{0});
+
+  // Same goes for the segment to be searched for.
+  const wchar_t segment[4] = {'1', '2', '\0', '3'};
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"123", segment), size_t{2});
+}
+
+TEST(LlvmLibcWCSSpnTest, SpanEachIndividualCharacter) {
+  const wchar_t *src = L"12345";
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"1"), size_t{1});
+  // Since '1' is not within the segment, the span
+  // size should remain zero.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"2"), size_t{0});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"3"), size_t{0});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"4"), size_t{0});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"5"), size_t{0});
+}
+
+TEST(LlvmLibcWCSSpnTest, UnmatchedCharacterShouldNotBeCountedInSpan) {
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"a", L"b"), size_t{0});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"abcdef", L"1"), size_t{0});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"123", L"4"), size_t{0});
+}
+
+TEST(LlvmLibcWCSSpnTest, SequentialCharactersShouldSpan) {
+  const wchar_t *src = L"abcde";
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"a"), size_t{1});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"ab"), size_t{2});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"abc"), size_t{3});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"abcd"), size_t{4});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"abcde"), size_t{5});
+  // Same thing for when the roles are reversed.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"abcde", src), size_t{5});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"abcd", src), size_t{4});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"abc", src), size_t{3});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"ab", src), size_t{2});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"a", src), size_t{1});
+}
+
+TEST(LlvmLibcWCSSpnTest, NonSequentialCharactersShouldNotSpan) {
+  const wchar_t *src = L"123456789";
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"_1_abc_2_def_3_"), size_t{3});
+  // Only spans 4 since '5' is not within the span.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(src, L"67__34abc12"), size_t{4});
+}
+
+TEST(LlvmLibcWCSSpnTest, ReverseCharacters) {
+  // Since these are still sequential, this should span.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"12345", L"54321"), size_t{5});
+  // Does not span any since '1' is not within the span.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"12345", L"432"), size_t{0});
+  // Only spans 1 since '2' is not within the span.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"12345", L"51"), size_t{1});
+}
+
+TEST(LlvmLibcWCSSpnTest, DuplicatedCharactersToBeSearchedForShouldStillMatch) {
+  // Only a single character, so only spans 1.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"a", L"aa"), size_t{1});
+  // This should count once for each 'a' in the source string.
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"aa", L"aa"), size_t{2});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"aaa", L"aa"), size_t{3});
+  EXPECT_EQ(LIBC_NAMESPACE::wcsspn(L"aaaa", L"aa"), size_t{4});
+}
diff --git a/test/src/wchar/wcsstr_test.cpp b/test/src/wchar/wcsstr_test.cpp
new file mode 100644
index 0000000..c1448bb
--- /dev/null
+++ b/test/src/wchar/wcsstr_test.cpp
@@ -0,0 +1,113 @@
+//===-- Unittests for wcsstr ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wcsstr.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWCSStrTest, NeedleNotInHaystack) {
+  // Should return nullptr if string is not found.
+  const wchar_t *haystack = L"12345";
+  const wchar_t *needle = L"a";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), nullptr);
+}
+
+TEST(LlvmLibcWCSStrTest, NeedleIsEmptyString) {
+  // Should return pointer to first character if needle is empty.
+  const wchar_t *haystack = L"12345";
+  const wchar_t *needle = L"";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), haystack);
+}
+
+TEST(LlvmLibcWCSStrTest, HaystackIsEmptyString) {
+  // Should return nullptr since haystack is empty.
+  const wchar_t *needle = L"12345";
+  const wchar_t *haystack = L"";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), nullptr);
+}
+
+TEST(LlvmLibcWCSStrTest, HaystackAndNeedleAreEmptyStrings) {
+  // Should point to haystack since needle is empty.
+  const wchar_t *needle = L"";
+  const wchar_t *haystack = L"";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), haystack);
+}
+
+TEST(LlvmLibcWCSStrTest, HaystackAndNeedleAreSingleCharacters) {
+  const wchar_t *haystack = L"a";
+  // Should point to haystack.
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"a"), haystack);
+  // Should return nullptr.
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"b"), nullptr);
+}
+
+TEST(LlvmLibcWCSStrTest, NeedleEqualToHaystack) {
+  const wchar_t *haystack = L"12345";
+  // Should point to haystack.
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"12345"), haystack);
+}
+
+TEST(LlvmLibcWCSStrTest, NeedleLargerThanHaystack) {
+  const wchar_t *haystack = L"123";
+  // Should return nullptr.
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"12345"), nullptr);
+}
+
+TEST(LlvmLibcWCSStrTest, NeedleAtBeginning) {
+  const wchar_t *haystack = L"12345";
+  const wchar_t *needle = L"12";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), haystack);
+}
+
+TEST(LlvmLibcWCSStrTest, NeedleInMiddle) {
+  const wchar_t *haystack = L"abcdefghi";
+  const wchar_t *needle = L"def";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), haystack + 3);
+}
+
+TEST(LlvmLibcWCSStrTest, NeedleDirectlyBeforeNullTerminator) {
+  const wchar_t *haystack = L"abcdefghi";
+  const wchar_t *needle = L"ghi";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), haystack + 6);
+}
+
+TEST(LlvmLibcWCSStrTest, NeedlePastNullTerminator) {
+  const wchar_t haystack[5] = {L'1', L'2', L'\0', L'3', L'4'};
+  // Shouldn't find anything after the null terminator.
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, /*needle=*/L"3"), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, /*needle=*/L"4"), nullptr);
+}
+
+TEST(LlvmLibcWCSStrTest, PartialNeedle) {
+  const wchar_t *haystack = L"la_ap_lap";
+  const wchar_t *needle = L"lap";
+  // Shouldn't find la or ap.
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), haystack + 6);
+}
+
+TEST(LlvmLibcWCSStrTest, MisspelledNeedle) {
+  const wchar_t *haystack = L"atalloftwocities...wait, tale";
+  const wchar_t *needle = L"tale";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), haystack + 25);
+}
+
+TEST(LlvmLibcWCSStrTest, AnagramNeedle) {
+  const wchar_t *haystack = L"dgo_ogd_god_odg_gdo_dog";
+  const wchar_t *needle = L"dog";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, needle), haystack + 20);
+}
+
+TEST(LlvmLibcWCSStrTest, MorphedNeedle) {
+  // Changes a single letter in the needle to mismatch with the haystack.
+  const wchar_t *haystack = L"once upon a time";
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"time"), haystack + 12);
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"lime"), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"tome"), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"tire"), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wcsstr(haystack, L"timo"), nullptr);
+}
diff --git a/test/src/wchar/wmemchr_test.cpp b/test/src/wchar/wmemchr_test.cpp
new file mode 100644
index 0000000..6b25bd8
--- /dev/null
+++ b/test/src/wchar/wmemchr_test.cpp
@@ -0,0 +1,92 @@
+//===-- Unittests for wmemchr ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wmemchr.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWMemChrTest, FindsCharacterAfterNullTerminator) {
+  // wmemchr should continue searching after a null terminator.
+  const size_t size = 5;
+  const wchar_t src[size] = {L'a', L'\0', L'b', L'c', L'\0'};
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'b', size), (src + 2));
+}
+
+TEST(LlvmLibcWMemChrTest, FindsCharacterInNonNullTerminatedCollection) {
+  const size_t size = 3;
+  const wchar_t src[size] = {L'a', L'b', L'c'};
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'b', size), (src + 1));
+}
+
+TEST(LlvmLibcWMemChrTest, FindsFirstCharacter) {
+  const size_t size = 6;
+  const wchar_t *src = L"abcde";
+  // Should return original array since 'a' is the first character.
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'a', size), (src));
+}
+
+TEST(LlvmLibcWMemChrTest, FindsMiddleCharacter) {
+  const size_t size = 6;
+  const wchar_t *src = L"abcde";
+  // Should return characters after and including 'c'.
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'c', size), (src + 2));
+}
+
+TEST(LlvmLibcWMemChrTest, FindsLastCharacterThatIsNotNullTerminator) {
+  const size_t size = 6;
+  const wchar_t *src = L"abcde";
+  // Should return 'e' and null terminator.
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'e', size), (src + 4));
+}
+
+TEST(LlvmLibcWMemChrTest, FindsNullTerminator) {
+  const size_t size = 6;
+  const wchar_t *src = L"abcde";
+  // Should return null terminator.
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'\0', size), (src + 5));
+}
+
+TEST(LlvmLibcWMemChrTest, CharacterNotWithinStringShouldReturnNullptr) {
+  const size_t size = 6;
+  const wchar_t *src = L"abcde";
+  // Should return nullptr.
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'z', size), nullptr);
+}
+
+TEST(LlvmLibcWMemChrTest, CharacterNotWithinSizeShouldReturnNullptr) {
+  const size_t size = 3;
+  const wchar_t *src = L"abcde";
+  // Should return nullptr.
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'd', size), nullptr);
+}
+
+TEST(LlvmLibcWMemChrTest, TheSourceShouldNotChange) {
+  const size_t size = 3;
+  const wchar_t *src = L"ab";
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'a', size), src);
+  ASSERT_TRUE(src[0] == L'a');
+  ASSERT_TRUE(src[1] == L'b');
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'c', size), nullptr);
+  ASSERT_TRUE(src[0] == L'a');
+  ASSERT_TRUE(src[1] == L'b');
+}
+
+TEST(LlvmLibcWMemChrTest, EmptyStringShouldOnlyMatchNullTerminator) {
+  const size_t size = 1;
+  const wchar_t *src = L"";
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'\0', size), src);
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'c', size), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'1', size), nullptr);
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'?', size), nullptr);
+}
+
+TEST(LlvmLibcWMemChrTest, SingleRepeatedCharacterShouldReturnFirst) {
+  const size_t size = 6;
+  const wchar_t *src = L"XXXXX";
+  ASSERT_EQ(LIBC_NAMESPACE::wmemchr(src, L'X', size), src);
+}
diff --git a/test/src/wchar/wmemcmp_test.cpp b/test/src/wchar/wmemcmp_test.cpp
new file mode 100644
index 0000000..5b07ca7
--- /dev/null
+++ b/test/src/wchar/wmemcmp_test.cpp
@@ -0,0 +1,78 @@
+//===-- Unittests for wmemcmp ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wmemcmp.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWMemcmpTest, CmpZeroByte) {
+  // Comparing zero bytes should result in 0.
+  const wchar_t *lhs = L"ab";
+  const wchar_t *rhs = L"yz";
+  EXPECT_EQ(LIBC_NAMESPACE::wmemcmp(lhs, rhs, 0), 0);
+}
+
+TEST(LlvmLibcWMemcmpTest, LhsRhsAreTheSame) {
+  // Comparing strings of equal value should result in 0.
+  const wchar_t *lhs = L"ab";
+  const wchar_t *rhs = L"ab";
+  EXPECT_EQ(LIBC_NAMESPACE::wmemcmp(lhs, rhs, 2), 0);
+}
+
+TEST(LlvmLibcWMemcmpTest, LhsBeforeRhsLexically) {
+  // z after b, should result in a value less than 0.
+  const wchar_t *lhs = L"ab";
+  const wchar_t *rhs = L"az";
+  EXPECT_LT(LIBC_NAMESPACE::wmemcmp(lhs, rhs, 2), 0);
+}
+
+TEST(LlvmLibcWMemcmpTest, LhsAfterRhsLexically) {
+  // z after b, should result in a value greater than 0.
+  const wchar_t *lhs = L"az";
+  const wchar_t *rhs = L"ab";
+  EXPECT_GT(LIBC_NAMESPACE::wmemcmp(lhs, rhs, 2), 0);
+}
+
+TEST(LlvmLibcWMemcmpTest, CompareToEmpty) {
+  // lhs is nonempty, should result in a value greater than 0.
+  const wchar_t *lhs = L"az";
+  const wchar_t *rhs = L"";
+  EXPECT_GT(LIBC_NAMESPACE::wmemcmp(lhs, rhs, 1), 0);
+}
+
+TEST(LlvmLibcWMemcmpTest, LhsAfterRhsLexicallyLong) {
+  // b after a, should result in a value greater than 0.
+  const wchar_t *lhs = L"aaaaaaaaaaaaab";
+  const wchar_t *rhs = L"aaaaaaaaaaaaaa";
+  EXPECT_GT(LIBC_NAMESPACE::wmemcmp(lhs, rhs, 15), 0);
+}
+
+TEST(LlvmLibcWMemcmpTest, RhsAfterLhsLexicallyLong) {
+  // b after a, should result in a value less than 0.
+  const wchar_t *lhs = L"aaaaaaaaaaaaaa";
+  const wchar_t *rhs = L"aaaaaaaaaaaaab";
+  EXPECT_LT(LIBC_NAMESPACE::wmemcmp(lhs, rhs, 15), 0);
+}
+
+TEST(LlvmLibcWMemcmpTest, LhsRhsAreTheSameLong) {
+  // Comparing strings of equal value should result in 0.
+  const wchar_t *lhs = L"aaaaaaaaaaaaaa";
+  const wchar_t *rhs = L"aaaaaaaaaaaaaa";
+  EXPECT_EQ(LIBC_NAMESPACE::wmemcmp(lhs, rhs, 15), 0);
+}
+
+#if defined(LIBC_ADD_NULL_CHECKS) && !defined(LIBC_HAS_SANITIZER)
+TEST(LlvmLibcWMemcmpTest, NullptrCrash) {
+  // Passing in a nullptr should crash the program.
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wmemcmp(L"aaaaaaaaaaaaaa", nullptr, 15); },
+               WITH_SIGNAL(-1));
+  EXPECT_DEATH([] { LIBC_NAMESPACE::wmemcmp(nullptr, L"aaaaaaaaaaaaaa", 15); },
+               WITH_SIGNAL(-1));
+}
+#endif // LIBC_HAS_ADDRESS_SANITIZER
diff --git a/test/src/wchar/wmemcpy_test.cpp b/test/src/wchar/wmemcpy_test.cpp
new file mode 100644
index 0000000..5533eef
--- /dev/null
+++ b/test/src/wchar/wmemcpy_test.cpp
@@ -0,0 +1,61 @@
+//===-- Unittests for wmemcpy ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wmemcpy.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWMemcpyTest, CopyIntoEmpty) {
+  wchar_t dest[10] = {};
+  const wchar_t *src = L"abcde";
+  LIBC_NAMESPACE::wmemcpy(dest, src, 6);
+  ASSERT_TRUE(src[0] == dest[0]);
+  ASSERT_TRUE(src[1] == dest[1]);
+  ASSERT_TRUE(src[2] == dest[2]);
+  ASSERT_TRUE(src[3] == dest[3]);
+  ASSERT_TRUE(src[4] == dest[4]);
+  ASSERT_TRUE(src[5] == dest[5]);
+}
+
+TEST(LlvmLibcWMemcpyTest, CopyFullString) {
+  // After copying, strings should be the same.
+  wchar_t dest[10] = {};
+  const wchar_t *src = L"abcde";
+  LIBC_NAMESPACE::wmemcpy(dest, src, 6);
+  ASSERT_TRUE(src[0] == dest[0]);
+  ASSERT_TRUE(src[1] == dest[1]);
+  ASSERT_TRUE(src[2] == dest[2]);
+  ASSERT_TRUE(src[3] == dest[3]);
+  ASSERT_TRUE(src[4] == dest[4]);
+  ASSERT_TRUE(src[5] == dest[5]);
+}
+
+TEST(LlvmLibcWMemcpyTest, CopyPartialString) {
+  // After copying, only first two characters should be the same.
+  wchar_t dest[10] = {};
+  const wchar_t *src = L"abcde";
+  LIBC_NAMESPACE::wmemcpy(dest, src, 2);
+  ASSERT_TRUE(src[0] == dest[0]);
+  ASSERT_TRUE(src[1] == dest[1]);
+  ASSERT_TRUE(src[2] != dest[2]);
+  ASSERT_TRUE(src[3] != dest[3]);
+  ASSERT_TRUE(src[4] != dest[4]);
+}
+
+TEST(LlvmLibcWMemcpyTest, CopyZeroCharacters) {
+  // Copying 0 characters should not change the string
+  wchar_t dest[10] = {L'1', L'2', L'3', L'4', L'5', L'\0'};
+  const wchar_t *src = L"abcde";
+  LIBC_NAMESPACE::wmemcpy(dest, src, 0);
+  ASSERT_TRUE(L'1' == dest[0]);
+  ASSERT_TRUE(L'2' == dest[1]);
+  ASSERT_TRUE(L'3' == dest[2]);
+  ASSERT_TRUE(L'4' == dest[3]);
+  ASSERT_TRUE(L'5' == dest[4]);
+}
diff --git a/test/src/wchar/wmempcpy_test.cpp b/test/src/wchar/wmempcpy_test.cpp
new file mode 100644
index 0000000..000e4b3
--- /dev/null
+++ b/test/src/wchar/wmempcpy_test.cpp
@@ -0,0 +1,50 @@
+//===-- Unittests for wmempcpy --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/wchar/wmempcpy.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWMempcpyTest, Simple) {
+  const wchar_t *src = L"12345";
+  wchar_t dest[10] = {};
+  void *result = LIBC_NAMESPACE::wmempcpy(dest, src, 6);
+  ASSERT_EQ(static_cast<wchar_t *>(result), dest + 6);
+
+  ASSERT_TRUE(dest[0] == src[0]);
+  ASSERT_TRUE(dest[1] == src[1]);
+  ASSERT_TRUE(dest[2] == src[2]);
+  ASSERT_TRUE(dest[3] == src[3]);
+  ASSERT_TRUE(dest[4] == src[4]);
+  ASSERT_TRUE(dest[5] == src[5]);
+}
+
+TEST(LlvmLibcWmempcpyTest, ZeroCount) {
+  const wchar_t *src = L"12345";
+  wchar_t dest[5] = {};
+  void *result = LIBC_NAMESPACE::wmempcpy(dest, src, 0);
+  ASSERT_EQ(static_cast<wchar_t *>(result), dest);
+
+  ASSERT_TRUE(dest[0] == 0);
+  ASSERT_TRUE(dest[1] == 0);
+  ASSERT_TRUE(dest[2] == 0);
+  ASSERT_TRUE(dest[3] == 0);
+  ASSERT_TRUE(dest[4] == 0);
+}
+
+TEST(LlvmLibcWMempcpyTest, BoundaryCheck) {
+  const wchar_t *src = L"12345";
+  wchar_t dest[4] = {};
+  void *result = LIBC_NAMESPACE::wmempcpy(dest + 1, src + 1, 2);
+
+  ASSERT_TRUE(dest[0] == 0);
+  ASSERT_TRUE(dest[1] == src[1]);
+  ASSERT_TRUE(dest[2] == src[2]);
+  ASSERT_TRUE(dest[3] == 0);
+
+  ASSERT_EQ(static_cast<wchar_t *>(result), dest + 3);
+}
diff --git a/test/src/wchar/wmemset_test.cpp b/test/src/wchar/wmemset_test.cpp
new file mode 100644
index 0000000..30e5458
--- /dev/null
+++ b/test/src/wchar/wmemset_test.cpp
@@ -0,0 +1,88 @@
+//===-- Unittests for wmemset ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "hdr/types/size_t.h"
+#include "hdr/types/wchar_t.h"
+#include "src/wchar/wmemset.h"
+#include "test/UnitTest/Test.h"
+
+TEST(LlvmLibcWMemsetTest, SmallStringBoundCheck) {
+  wchar_t str[5];
+  for (int i = 0; i < 5; i++)
+    str[i] = 'A';
+
+  wchar_t *output = LIBC_NAMESPACE::wmemset(str + 1, 'B', 3);
+
+  EXPECT_EQ(output, str + 1);
+
+  // EXPECT_TRUE being used since there isn't currently support for printing
+  // wide chars in the future, it would be preferred to switch these to
+  // EXPECT_EQ
+  EXPECT_TRUE(str[0] == (wchar_t)'A');
+  EXPECT_TRUE(str[1] == (wchar_t)'B');
+  EXPECT_TRUE(str[2] == (wchar_t)'B');
+  EXPECT_TRUE(str[3] == (wchar_t)'B');
+  EXPECT_TRUE(str[4] == (wchar_t)'A');
+}
+
+TEST(LlvmLibcWMemsetTest, LargeStringBoundCheck) {
+  constexpr int str_size = 1000;
+  wchar_t str[str_size];
+  for (int i = 0; i < str_size; i++)
+    str[i] = 'A';
+
+  wchar_t *output = LIBC_NAMESPACE::wmemset(str + 1, 'B', str_size - 2);
+
+  EXPECT_EQ(output, str + 1);
+
+  EXPECT_TRUE(str[0] == (wchar_t)'A');
+  for (int i = 1; i < str_size - 1; i++)
+    EXPECT_TRUE(str[i] == (wchar_t)'B');
+
+  EXPECT_TRUE(str[str_size - 1] == (wchar_t)'A');
+}
+
+TEST(LlvmLibcWMemsetTest, WCharSizeSmallString) {
+  // ensure we can handle full range of widechars
+  wchar_t str[5];
+  const wchar_t target = WCHAR_MAX;
+
+  for (int i = 0; i < 5; i++)
+    str[i] = 'A';
+
+  wchar_t *output = LIBC_NAMESPACE::wmemset(str + 1, target, 3);
+
+  EXPECT_EQ(output, str + 1);
+
+  EXPECT_TRUE(str[0] == (wchar_t)'A');
+  EXPECT_TRUE(str[1] == target);
+  EXPECT_TRUE(str[2] == target);
+  EXPECT_TRUE(str[3] == target);
+  EXPECT_TRUE(str[4] == (wchar_t)'A');
+}
+
+TEST(LlvmLibcWMemsetTest, WCharSizeLargeString) {
+  // ensure we can handle full range of widechars
+  constexpr int str_size = 1000;
+  wchar_t str[str_size];
+
+  const wchar_t target = WCHAR_MAX;
+
+  for (int i = 0; i < str_size; i++)
+    str[i] = 'A';
+
+  wchar_t *output = LIBC_NAMESPACE::wmemset(str + 1, target, str_size - 2);
+
+  EXPECT_EQ(output, str + 1);
+
+  EXPECT_TRUE(str[0] == (wchar_t)'A');
+  for (int i = 1; i < str_size - 1; i++)
+    EXPECT_TRUE(str[i] == target);
+
+  EXPECT_TRUE(str[str_size - 1] == (wchar_t)'A');
+}
```

