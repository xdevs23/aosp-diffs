```diff
diff --git a/METADATA b/METADATA
deleted file mode 100644
index d97975ca3..000000000
--- a/METADATA
+++ /dev/null
@@ -1,3 +0,0 @@
-third_party {
-  license_type: NOTICE
-}
diff --git a/OWNERS b/OWNERS
index 3818b1d54..1859b9e84 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,3 +5,5 @@ chiahungduan@google.com
 danalbert@google.com
 rprichard@google.com
 yabinc@google.com
+
+per-file docs/mte.md=eugenis@google.com,fmayer@google.com,pcc@google.com
diff --git a/docs/mte.md b/docs/mte.md
new file mode 100644
index 000000000..3034cc73e
--- /dev/null
+++ b/docs/mte.md
@@ -0,0 +1,244 @@
+# Arm Memory Tagging Extension (MTE) implementation
+
+AOSP supports Arm MTE to detect invalid memory accesses. The implementation is
+spread across multiple components, both within and out of the AOSP tree. This
+document gives an overview and pointers about how the various MTE features are
+implemented.
+
+For documentation of the behavior rather than the implementation, see the
+[SAC page on MTE] instead. For MTE for apps, see the [NDK page on MTE].
+
+The relevant components are:
+
+* [LLVM Project] (out of AOSP tree)
+    * Stack tagging instrumentation pass
+    * Scudo memory allocator
+* bionic
+    * libc
+    * dynamic loader
+* Zygote
+* debuggerd
+* [NDK]
+
+## MTE enablement
+
+The way MTE is requested and enabled differs between native binaries and Java
+apps. This is necessarily so, because Java apps get forked from the Zygote,
+while native executables get inintialized by the linker.
+
+### Native binaries
+
+Both AOSP and the NDK allow you to compile C/C++ code that use MTE to detect
+memory safety issues. The [NDK legacy cmake toolchain] and the
+[NDK new cmake toolchain] both support "memtag" as an argument for
+`ANDROID_SANITIZE`. NDK make has no specific support for MTE, but the
+relevant flags can be passed directly as `CFLAGS` and `LDFLAGS`.
+
+For the OS itself, [Soong] supports "memtag_[heap|stack|globals]" as
+`SANITIZE_TARGET  and as `sanitize:` attribute in Android.bp files;
+[Android make] supports the same environment variables as Soong. This passes
+the appropriate flags to the clang driver for both compile and link steps.
+
+#### Linker
+
+* For **dynamic executables** LLD has support to
+  [add appropriate dynamic sections] as defined in the [ELF standard]
+* For **static executables** and as a fallback for older devices, LLD
+  also supports [adding the Android-specific ELF note]
+
+Both of the above are controlled by the linker flag `--android-memtag-mode`
+which is [passed in by the clang driver] if
+`-fsanitize=memtag-[stack|heap|globals]` is [passed in].
+`-fsanitize=memtag` [enables all three] (even for API levels that don't
+implement the runtime for globals, which means builds from old versions
+of clang may no work with newer platform versions that support globals).
+`-fsanitize-memtag-mode` allows to choose between ASYNC and SYNC.
+
+This information can be queried using `llvm-readelf --memtag`.
+
+This information is [picked up by libc init] to decide whether to enable MTE.
+`-fsanitize-heap` controls both whether scudo tags allocations, and whether
+tag checking is enabled.
+
+#### Runtime environment (dynamic loader, libc)
+
+There are two different initialization sequences for libc, both of which end up
+calling `__libc_init_mte`.
+
+N.B. the linker has its own copy of libc, which is used when executing these
+functions. That is why we have to use `__libc_shared_globals` to communicate
+with the libc of the process we are starting.
+
+* **static executables** `__libc_init` is called from `crtbegin.c`, which calls
+                         `__libc_init_mte`
+* **dynamic executables** the linker calls `__libc_init_mte`
+
+`__libc_init_mte` figures out the appropriate MTE level that is requested by
+the process, calls `prctl` to request this from the kernel, and stores data in
+`__libc_shared_globals` which gets picked up later to enable MTE in scudo.
+
+It also does work related to stack tagging and permissive mode, which will be
+detailed later.
+
+### Apps
+
+Apps can request MTE be enabled for their process via the manifest attribute
+`android:memtagMode`. This gets interpreted by Zygote, which always runs with
+`ASYNC` MTE enabled, because MTE for a process can only be disabled after
+it has been initialized (see [Native binaries](#native-binaries)), not enabled.
+
+[decideTaggingLevel] in the Zygote figures out whether to enable MTE for
+an app, and stores it in the `runtimeFlags`, which get picked up by
+[SpecializeCommon] after forking from the Zygote.
+
+## MTE implementation
+
+### Heap Tagging
+
+Heap tagging is implemented in the scudo allocator. On `malloc` and `free`,
+scudo will update the memory's tags to prevent use-after-free and buffer
+overflows.
+
+[scudo's memtag.h] contains helper functions to deal with MTE tag management,
+which are used in [combined.h] and [secondary.h].
+
+
+### Stack Tagging
+
+Stack tagging requires instrumenting function bodies. It is implemented as
+an instrumentation pass in LLVM called [AArch64StackTagging], which sets
+the tags according to the lifetime of stack objects.
+
+The instrumentation pass also supports recording stack history, consisting of:
+
+* PC
+* Frame pointer
+* Base tag
+
+This can be used to reconstruct which stack object was referred to in an
+invalid access. The logic to reconstruct this can be found in the
+[stack script].
+
+
+Stack tagging is enabled in one of two circumstances:
+* at process startup, if the main binary or any of its dependencies are
+  compiled with `memtag-stack`
+* library compiled with `memtag-stack` is `dlopen`ed later, either directly or
+  as a dependency of a `dlopen`ed library. In this case, the
+  [__pthread_internal_remap_stack_with_mte] function is used (called from
+  `memtag_stack_dlopen_callback`). Because `dlopen`
+  is handled by the linker, we have to [store a function pointer] to the
+  process's version of the function in `__libc_shared_globals`.
+
+Enabling stack MTE consists of two operations:
+* Remapping the stacks as `PROT_MTE`
+* Allocating a stack history buffer.
+
+The first operation is only necessary when the process is running with MTE
+enabled. The second operation is also necessary when the process is not running
+with MTE enabled, because the writes to the stack history buffer are
+unconditional.
+
+libc keeps track of this through two globals:
+
+* `__libc_memtag_stack`:  whether stack MTE is enabled on the process, i.e.
+  whether the stack pages are mapped with PROT\_MTE. This is always false if
+  MTE is disabled for the process (i.e. `libc_globals.memtag` is false).
+* `__libc_memtag_stack_abi`: whether the process contains any code that was
+  compiled with memtag-stack. This is true even if the process does not have
+  MTE enabled.
+
+### Globals Tagging
+
+TODO(fmayer): write once submitted
+
+### Crash reporting
+
+For MTE crashes, debuggerd serializes special information into the Tombstone
+proto:
+
+* Tags around fault address
+* Scudo allocation history
+
+This is done in [tombstone\_proto.cpp]. The information is converted to a text
+proto in [tombstone\_proto\_to\_text.cpp].
+
+## Bootloader control
+
+The bootloader API allows userspace to enable MTE on devices that do not ship
+with MTE enabled by default.
+
+See [SAC MTE bootloader support] for the API definition. In AOSP, this API is
+implemented in [system/extras/mtectrl]. mtectrl.rc handles the property
+changes and invokes mtectrl to update the misc partition to communicate
+with the bootloader.
+
+There is also an [API in Device Policy Manager] that allows the device admin
+to enable or disable MTE under certain circumstances.
+
+The device can opt in or out of these APIs by a set of system properties:
+
+* `ro.arm64.memtag.bootctl_supported`: the system property API is supported,
+  and an option is displayed in Developer Options.
+* `ro.arm64.memtag.bootctl_settings_toggle`: an option is displayed in the
+  normal settings. This requires `ro.arm64.memtag.bootctl_supported` to be
+  true. This implies `ro.arm64.memtag.bootctl_device_policy_manager`, if it
+  is not explicitely set.
+* `ro.arm64.memtag.bootctl_device_policy_manager`: the Device Policy Manager
+  API is supported.
+
+## Permissive MTE
+
+Permissive MTE refers to a mode which, instead of crashing the process on an
+MTE fault, records a tombstone but then continues execution of the process.
+An important caveat is that system calls with invalid pointers (where the
+pointer tag does not match the memory tag) still return an error code.
+
+This mode is only available for system services, not apps. It is implemented
+in the [debugger\_signal\_handler] by disabling MTE for the faulting thread.
+Optionally, the user can ask for MTE to be re-enabled after some time.
+This is achieved by arming a timer that calls [enable_mte_signal_handler]
+upon expiry.
+
+## MTE Mode Upgrade
+
+When a system service [crashes in ASYNC mode], we set an impossible signal
+as an exit code (because that signal is always gracefully handled by libc),
+and [in init] we set `BIONIC_MEMTAG_UPGRADE_SECS`, which gets handled by
+[libc startup].
+
+[SpecializeCommon]: https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/jni/com_android_internal_os_Zygote.cpp?q=f:frameworks%2Fbase%2Fcore%2Fjni%2Fcom_android_internal_os_Zygote.cpp%20%22%20mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL,%22&ss=android%2Fplatform%2Fsuperproject%2Fmain
+[LLVM Project]: https://github.com/llvm/llvm-project/
+[NDK]: https://android.googlesource.com/platform/ndk/
+[NDK legacy cmake toolchain]: https://android.googlesource.com/platform/ndk/+/refs/heads/main/build/cmake/android-legacy.toolchain.cmake#490
+[NDK new cmake toolchain]: https://android.googlesource.com/platform/ndk/+/refs/heads/main/build/cmake/flags.cmake#56
+[Soong]: https://cs.android.com/android/platform/superproject/main/+/main:build/soong/cc/sanitize.go?q=sanitize.go&ss=android%2Fplatform%2Fsuperproject%2Fmain
+[decideTaggingLevel]: https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/com/android/internal/os/Zygote.java?q=symbol:decideTaggingLevel
+[picked up by libc init]: https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/bionic/libc_init_mte.cpp?q=symbol:__get_tagging_level%20f:bionic
+[enables all three]: https://github.com/llvm/llvm-project/blob/e732d1ce86783b1d7fe30645fcb30434109505b9/clang/include/clang/Basic/Sanitizers.def#L62
+[passed in]: https://github.com/llvm/llvm-project/blob/ff2e619dfcd77328812a42d2ba2b11c3ff96f410/clang/lib/Driver/SanitizerArgs.cpp#L719
+[passed in by the clang driver]: https://github.com/llvm/llvm-project/blob/ff2e619dfcd77328812a42d2ba2b11c3ff96f410/clang/lib/Driver/ToolChains/CommonArgs.cpp#L1595
+[adding the Android-specific ELF note]: https://github.com/llvm/llvm-project/blob/435cb0dc5eca08cdd8d9ed0d887fa1693cc2bf33/lld/ELF/Driver.cpp#L1258
+[ELF standard]: https://github.com/ARM-software/abi-aa/blob/main/memtagabielf64/memtagabielf64.rst#6dynamic-section
+[add appropriate dynamic sections]: https://github.com/llvm/llvm-project/blob/7022498ac2f236e411e8a0f9a48669e754000a4b/lld/ELF/SyntheticSections.cpp#L1473
+[storeTags]: https://cs.android.com/android/platform/superproject/main/+/main:external/scudo/standalone/memtag.h?q=f:scudo%20f:memtag.h%20function:storeTags
+[SAC page on MTE]: https://source.android.com/docs/security/test/memory-safety/arm-mte
+[NDK page on MTE]: https://developer.android.com/ndk/guides/arm-mte
+[AArch64StackTagging]: https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/AArch64StackTagging.cpp
+[scudo's memtag.h]: https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/scudo/standalone/memtag.h
+[combined.h]: https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/scudo/standalone/combined.h
+[secondary.h]: https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/scudo/standalone/secondary.h
+[__pthread_internal_remap_stack_with_mte]: https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/bionic/pthread_internal.cpp?q=__pthread_internal_remap_stack_with_mte
+[stack script]: https://cs.android.com/android/platform/superproject/main/+/main:development/scripts/stack?q=stack
+[Android make]: https://cs.android.com/android/platform/superproject/main/+/main:build/make/core/config_sanitizers.mk
+[store a function pointer]: https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/bionic/libc_init_dynamic.cpp;l=168?q=memtag_stack_dlopen_callback
+[tombstone\_proto.cpp]: https://cs.android.com/android/platform/superproject/main/+/main:system/core/debuggerd/libdebuggerd/tombstone_proto.cpp?q=tombstone_proto.cpp
+[tombstone\_proto\_to\_text.cpp]: https://cs.android.com/android/platform/superproject/main/+/main:system/core/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
+[SAC MTE bootloader support]: https://source.android.com/docs/security/test/memory-safety/bootloader-support
+[system/extras/mtectrl]: https://cs.android.com/android/platform/superproject/main/+/main:system/extras/mtectrl/
+[API in Device Policy Manager]: https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/android/app/admin/DevicePolicyManager.java?q=symbol:setMtePolicy%20f:DevicePolicyManager.java
+[debuggerd\_signal_handler]: https://cs.android.com/android/platform/superproject/main/+/main:system/core/debuggerd/handler/debuggerd_handler.cpp?q=f:debuggerd_handler.cpp%20symbol:debuggerd_signal_handler
+[enable_mte_signal_handler]: https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/bionic/libc_init_mte.cpp?q=symbol:__enable_mte_signal_handler
+[in init]: https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/service.cpp?q=f:system%2Fcore%2Finit%2Fservice.cpp%20should_upgrade_mte
+[crashes in ASYNC mode]: https://cs.android.com/android/platform/superproject/main/+/main:system/core/debuggerd/handler/debuggerd_handler.cpp;l=799?q=BIONIC_SIGNAL_ART_PROFILER
+[libc startup]: https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/bionic/libc_init_mte.cpp?q=BIONIC_MEMTAG_UPGRADE_SECS
diff --git a/docs/status.md b/docs/status.md
index 94784de9d..e7111d964 100644
--- a/docs/status.md
+++ b/docs/status.md
@@ -62,6 +62,7 @@ Current libc symbols: https://android.googlesource.com/platform/bionic/+/main/li
 New libc functions in API level 36:
   * `qsort_r`, `sig2str`/`str2sig` (POSIX Issue 8 additions).
   * GNU/BSD extension `lchmod`.
+  * GNU extensions `pthread_getaffinity_np`/`pthread_setaffinity_np`.
   * New system call wrapper: `mseal` (`<sys/mman.h>`).
 
 New libc functions in V (API level 35):
diff --git a/libc/Android.bp b/libc/Android.bp
index eeea72807..c34023c37 100644
--- a/libc/Android.bp
+++ b/libc/Android.bp
@@ -264,6 +264,7 @@ cc_library_static {
     name: "libc_init_static",
     defaults: ["libc_defaults"],
     srcs: [
+        "bionic/libc_init_mte.cpp",
         "bionic/libc_init_static.cpp",
         ":elf_note_sources",
     ],
@@ -353,7 +354,6 @@ cc_library_static {
         "-Wno-unused-parameter",
         "-include netbsd-compat.h",
         "-Wframe-larger-than=66000",
-        "-include private/bsd_sys_param.h",
     ],
 
     local_include_dirs: [
@@ -418,20 +418,6 @@ cc_library_static {
         "upstream-freebsd/lib/libc/string/wmemmove.c",
         "upstream-freebsd/lib/libc/string/wmemset.c",
     ],
-    arch: {
-        x86: {
-            exclude_srcs: [
-                "upstream-freebsd/lib/libc/string/wcschr.c",
-                "upstream-freebsd/lib/libc/string/wcscmp.c",
-                "upstream-freebsd/lib/libc/string/wcslen.c",
-                "upstream-freebsd/lib/libc/string/wcsrchr.c",
-                "upstream-freebsd/lib/libc/string/wmemcmp.c",
-                "upstream-freebsd/lib/libc/string/wcscat.c",
-                "upstream-freebsd/lib/libc/string/wcscpy.c",
-                "upstream-freebsd/lib/libc/string/wmemcmp.c",
-            ],
-        },
-    },
 
     cflags: [
         "-Wno-sign-compare",
@@ -485,7 +471,6 @@ cc_library_static {
         "upstream-netbsd/lib/libc/regex/regerror.c",
         "upstream-netbsd/lib/libc/regex/regexec.c",
         "upstream-netbsd/lib/libc/regex/regfree.c",
-        "upstream-netbsd/lib/libc/stdlib/bsearch.c",
         "upstream-netbsd/lib/libc/stdlib/drand48.c",
         "upstream-netbsd/lib/libc/stdlib/erand48.c",
         "upstream-netbsd/lib/libc/stdlib/jrand48.c",
@@ -638,10 +623,7 @@ cc_library_static {
         arm: {
             srcs: [
                 "upstream-openbsd/lib/libc/string/memchr.c",
-                "upstream-openbsd/lib/libc/string/memrchr.c",
                 "upstream-openbsd/lib/libc/string/stpncpy.c",
-                "upstream-openbsd/lib/libc/string/strlcat.c",
-                "upstream-openbsd/lib/libc/string/strlcpy.c",
                 "upstream-openbsd/lib/libc/string/strncat.c",
                 "upstream-openbsd/lib/libc/string/strncmp.c",
                 "upstream-openbsd/lib/libc/string/strncpy.c",
@@ -651,18 +633,13 @@ cc_library_static {
             srcs: [
                 "upstream-openbsd/lib/libc/string/strcat.c",
                 "upstream-openbsd/lib/libc/string/stpncpy.c",
-                "upstream-openbsd/lib/libc/string/strlcat.c",
-                "upstream-openbsd/lib/libc/string/strlcpy.c",
                 "upstream-openbsd/lib/libc/string/strncat.c",
                 "upstream-openbsd/lib/libc/string/strncpy.c",
             ],
         },
         riscv64: {
             srcs: [
-                "upstream-openbsd/lib/libc/string/memrchr.c",
                 "upstream-openbsd/lib/libc/string/stpncpy.c",
-                "upstream-openbsd/lib/libc/string/strlcat.c",
-                "upstream-openbsd/lib/libc/string/strlcpy.c",
             ],
         },
         x86: {
@@ -672,10 +649,7 @@ cc_library_static {
         },
         x86_64: {
             srcs: [
-                "upstream-openbsd/lib/libc/string/memchr.c",
-                "upstream-openbsd/lib/libc/string/memrchr.c",
-                "upstream-openbsd/lib/libc/string/strlcat.c",
-                "upstream-openbsd/lib/libc/string/strlcpy.c",
+                // x86_64 has custom/llvm-libc implementations of all of these.
             ],
         },
     },
@@ -955,6 +929,7 @@ cc_library_static {
         "bionic/pthread_detach.cpp",
         "bionic/pthread_equal.cpp",
         "bionic/pthread_exit.cpp",
+        "bionic/pthread_getaffinity.cpp",
         "bionic/pthread_getcpuclockid.cpp",
         "bionic/pthread_getschedparam.cpp",
         "bionic/pthread_gettid_np.cpp",
@@ -968,6 +943,7 @@ cc_library_static {
         "bionic/pthread_sigqueue.cpp",
         "bionic/pthread_self.cpp",
         "bionic/pthread_setname_np.cpp",
+        "bionic/pthread_setaffinity.cpp",
         "bionic/pthread_setschedparam.cpp",
         "bionic/pthread_spinlock.cpp",
         "bionic/ptrace.cpp",
@@ -1183,7 +1159,6 @@ cc_library_static {
 
                 "arch-x86/string/sse2-memchr-atom.S",
                 "arch-x86/string/sse2-memmove-slm.S",
-                "arch-x86/string/sse2-memrchr-atom.S",
                 "arch-x86/string/sse2-memset-slm.S",
                 "arch-x86/string/sse2-stpcpy-slm.S",
                 "arch-x86/string/sse2-stpncpy-slm.S",
@@ -1193,24 +1168,14 @@ cc_library_static {
                 "arch-x86/string/sse2-strncpy-slm.S",
                 "arch-x86/string/sse2-strnlen-atom.S",
                 "arch-x86/string/sse2-strrchr-atom.S",
-                "arch-x86/string/sse2-wcschr-atom.S",
-                "arch-x86/string/sse2-wcsrchr-atom.S",
-                "arch-x86/string/sse2-wcslen-atom.S",
-                "arch-x86/string/sse2-wcscmp-atom.S",
 
                 "arch-x86/string/ssse3-memcmp-atom.S",
                 "arch-x86/string/ssse3-strcat-atom.S",
                 "arch-x86/string/ssse3-strcmp-atom.S",
-                "arch-x86/string/ssse3-strlcat-atom.S",
-                "arch-x86/string/ssse3-strlcpy-atom.S",
                 "arch-x86/string/ssse3-strncat-atom.S",
                 "arch-x86/string/ssse3-strncmp-atom.S",
-                "arch-x86/string/ssse3-wcscat-atom.S",
-                "arch-x86/string/ssse3-wcscpy-atom.S",
-                "arch-x86/string/ssse3-wmemcmp-atom.S",
 
                 "arch-x86/string/sse4-memcmp-slm.S",
-                "arch-x86/string/sse4-wmemcmp-slm.S",
 
                 "bionic/strchrnul.cpp",
             ],
@@ -1237,11 +1202,6 @@ cc_library_static {
                 "arch-x86_64/string/sse4-memcmp-slm.S",
                 "arch-x86_64/string/ssse3-strcmp-slm.S",
                 "arch-x86_64/string/ssse3-strncmp-slm.S",
-
-                "bionic/strchr.cpp",
-                "bionic/strchrnul.cpp",
-                "bionic/strnlen.cpp",
-                "bionic/strrchr.cpp",
             ],
         },
     },
@@ -1260,6 +1220,7 @@ cc_library_static {
     generated_headers: ["generated_android_ids"],
 
     whole_static_libs: [
+        "//external/llvm-libc:llvmlibc",
         "libsystemproperties",
     ],
 
@@ -1512,6 +1473,7 @@ filegroup {
     srcs: [
         "arch-common/bionic/crtbegin_so.c",
         "arch-common/bionic/crtbrand.S",
+        "bionic/android_mallopt.cpp",
         "bionic/gwp_asan_wrappers.cpp",
         "bionic/heap_tagging.cpp",
         "bionic/icu.cpp",
@@ -1530,6 +1492,7 @@ filegroup {
 filegroup {
     name: "libc_sources_static",
     srcs: [
+        "bionic/android_mallopt.cpp",
         "bionic/gwp_asan_wrappers.cpp",
         "bionic/heap_tagging.cpp",
         "bionic/icu_static.cpp",
@@ -1696,8 +1659,14 @@ cc_library {
     },
     native_bridge_supported: false,
     // It is never correct to depend on this directly. This is only
-    // needed for the runtime apex, and in base_system.mk.
-    visibility: ["//bionic/apex"],
+    // needed for the runtime apex, and in base_system.mk, and system_image_defaults
+    // which is default module for soong-defined system image.
+    visibility: [
+        "//bionic/apex",
+        "//build/make/target/product/generic",
+        //TODO(b/381985636) : Remove visibility to Soong-defined GSI once resolved
+        "//build/make/target/product/gsi",
+    ],
 }
 
 genrule {
@@ -1783,6 +1752,7 @@ cc_library_headers {
     name: "libc_uapi_headers",
     visibility: [
         "//external/musl",
+        "//external/rust/crates/v4l2r/android",
     ],
     llndk: {
         llndk_headers: true,
@@ -2018,15 +1988,6 @@ cc_defaults {
 cc_defaults {
     name: "crt_so_defaults",
     defaults: ["crt_defaults"],
-
-    arch: {
-        x86: {
-            cflags: ["-fPIC"],
-        },
-        x86_64: {
-            cflags: ["-fPIC"],
-        },
-    },
     stl: "none",
 }
 
@@ -2166,6 +2127,7 @@ cc_library_static {
 //     async_safe_fatal_va_list
 cc_library_static {
     name: "librust_baremetal",
+    defaults: ["cc_baremetal_defaults"],
     header_libs: ["libc_headers"],
     include_dirs: [
         "bionic/libc/async_safe/include",
@@ -2192,6 +2154,7 @@ cc_library_static {
         },
     },
     whole_static_libs: [
+        "//external/llvm-libc:llvmlibc",
         "libarm-optimized-routines-mem",
         "libc_netbsd",
     ],
diff --git a/libc/NOTICE b/libc/NOTICE
index 1a84d3ca7..bca4891ed 100644
--- a/libc/NOTICE
+++ b/libc/NOTICE
@@ -3585,22 +3585,6 @@ SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
 -------------------------------------------------------------------
 
-Copyright (c) 2007 Todd C. Miller <millert@openbsd.org>
-
-Permission to use, copy, modify, and distribute this software for any
-purpose with or without fee is hereby granted, provided that the above
-copyright notice and this permission notice appear in all copies.
-
-THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
-WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
-MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
-ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
-WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
-ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
-OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
-
--------------------------------------------------------------------
-
 Copyright (c) 2007-2008  Michael G Schwern
 
 This software originally derived from Paul Sheer's pivotal_gmtime_r.c.
@@ -3862,36 +3846,6 @@ SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
-Copyright (c) 2011 Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-
--------------------------------------------------------------------
-
 Copyright (c) 2011 Martin Pieuchot <mpi@openbsd.org>
 
 Permission to use, copy, modify, and distribute this software for any
@@ -3937,36 +3891,6 @@ SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 -------------------------------------------------------------------
 
-Copyright (c) 2011, 2012, 2013 Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-
--------------------------------------------------------------------
-
 Copyright (c) 2011, Intel Corporation
 All rights reserved.
 
diff --git a/libc/arch-common/bionic/crt_pad_segment.S b/libc/arch-common/bionic/crt_pad_segment.S
index 86c730d9e..2fbe0b905 100644
--- a/libc/arch-common/bionic/crt_pad_segment.S
+++ b/libc/arch-common/bionic/crt_pad_segment.S
@@ -26,6 +26,12 @@
  * SUCH DAMAGE.
  */
 
+#if defined(__aarch64__)
+#include <private/bionic_asm_arm64.h>
+
+__bionic_asm_custom_note_gnu_section()
+#endif
+
 #include <private/bionic_asm_note.h>
 
   .section ".note.android.pad_segment", "a", %note
diff --git a/libc/arch-x86/dynamic_function_dispatch.cpp b/libc/arch-x86/dynamic_function_dispatch.cpp
index 98d7ec2a2..240fcdf52 100644
--- a/libc/arch-x86/dynamic_function_dispatch.cpp
+++ b/libc/arch-x86/dynamic_function_dispatch.cpp
@@ -38,14 +38,4 @@ DEFINE_IFUNC_FOR(memcmp) {
 }
 MEMCMP_SHIM()
 
-typedef int wmemcmp_func_t(const wchar_t*, const wchar_t*, size_t);
-DEFINE_IFUNC_FOR(wmemcmp) {
-  __builtin_cpu_init();
-  if (__builtin_cpu_supports("sse4.1")) RETURN_FUNC(wmemcmp_func_t, wmemcmp_sse4);
-  RETURN_FUNC(wmemcmp_func_t, wmemcmp_atom);
-}
-DEFINE_STATIC_SHIM(int wmemcmp(const wchar_t* lhs, const wchar_t* rhs, size_t n) {
-  FORWARD(wmemcmp)(lhs, rhs, n);
-})
-
 }  // extern "C"
diff --git a/libc/arch-x86/string/sse2-memrchr-atom.S b/libc/arch-x86/string/sse2-memrchr-atom.S
deleted file mode 100644
index 1aa1a1a40..000000000
--- a/libc/arch-x86/string/sse2-memrchr-atom.S
+++ /dev/null
@@ -1,778 +0,0 @@
-/*
-Copyright (c) 2011, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef L
-# define L(label)	.L##label
-#endif
-
-#ifndef cfi_startproc
-# define cfi_startproc	.cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc	.cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name,  @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name,	.-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG) pushl REG; CFI_PUSH (REG)
-#define POP(REG) popl REG; CFI_POP (REG)
-
-#define PARMS  4
-#define STR1  PARMS
-#define STR2  STR1+4
-#define LEN   STR2+4
-
-	.text
-ENTRY (memrchr)
-	mov	STR1(%esp), %ecx
-	movd	STR2(%esp), %xmm1
-	mov	LEN(%esp), %edx
-
-	test	%edx, %edx
-	jz	L(return_null)
-	sub	$16, %edx
-	jbe	L(length_less16)
-
-	punpcklbw %xmm1, %xmm1
-	add	%edx, %ecx
-	punpcklbw %xmm1, %xmm1
-
-	movdqu	(%ecx), %xmm0
-	pshufd	$0, %xmm1, %xmm1
-	pcmpeqb	%xmm1, %xmm0
-
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(exit_dispatch)
-
-	sub	$64, %ecx
-	mov	%ecx, %eax
-	and	$15, %eax
-	jz	L(loop_prolog)
-
-	add	$16, %ecx
-	add	$16, %edx
-	and	$-16, %ecx
-	sub	%eax, %edx
-
-	.p2align 4
-/* Loop start on aligned string.  */
-L(loop_prolog):
-	sub	$64, %edx
-	jbe	L(exit_loop)
-
-	movdqa	48(%ecx), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(matches48)
-
-	movdqa	32(%ecx), %xmm2
-	pcmpeqb	%xmm1, %xmm2
-	pmovmskb %xmm2, %eax
-	test	%eax, %eax
-	jnz	L(matches32)
-
-	movdqa	16(%ecx), %xmm3
-	pcmpeqb	%xmm1, %xmm3
-	pmovmskb %xmm3, %eax
-	test	%eax, %eax
-	jnz	L(matches16)
-
-	movdqa	(%ecx), %xmm4
-	pcmpeqb	%xmm1, %xmm4
-	pmovmskb %xmm4, %eax
-	test	%eax, %eax
-	jnz	L(exit_dispatch)
-
-	sub	$64, %ecx
-	sub	$64, %edx
-	jbe	L(exit_loop)
-
-	movdqa	48(%ecx), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(matches48)
-
-	movdqa	32(%ecx), %xmm2
-	pcmpeqb	%xmm1, %xmm2
-	pmovmskb %xmm2, %eax
-	test	%eax, %eax
-	jnz	L(matches32)
-
-	movdqa	16(%ecx), %xmm3
-	pcmpeqb	%xmm1, %xmm3
-	pmovmskb %xmm3, %eax
-	test	%eax, %eax
-	jnz	L(matches16)
-
-	movdqa	(%ecx), %xmm3
-	pcmpeqb	%xmm1, %xmm3
-	pmovmskb %xmm3, %eax
-	test	%eax, %eax
-	jnz	L(exit_dispatch)
-
-	mov	%ecx, %eax
-	and	$63, %eax
-	test	%eax, %eax
-	jz	L(align64_loop)
-
-	add	$64, %ecx
-	add	$64, %edx
-	and	$-64, %ecx
-	sub	%eax, %edx
-
-	.p2align 4
-L(align64_loop):
-	sub	$64, %ecx
-	sub	$64, %edx
-	jbe	L(exit_loop)
-
-	movdqa	(%ecx), %xmm0
-	movdqa	16(%ecx), %xmm2
-	movdqa	32(%ecx), %xmm3
-	movdqa	48(%ecx), %xmm4
-
-	pcmpeqb	%xmm1, %xmm0
-	pcmpeqb	%xmm1, %xmm2
-	pcmpeqb	%xmm1, %xmm3
-	pcmpeqb	%xmm1, %xmm4
-
-	pmaxub	%xmm3, %xmm0
-	pmaxub	%xmm4, %xmm2
-	pmaxub	%xmm0, %xmm2
-	pmovmskb %xmm2, %eax
-
-	test	%eax, %eax
-	jz	L(align64_loop)
-
-	pmovmskb %xmm4, %eax
-	test	%eax, %eax
-	jnz	L(matches48)
-
-	pmovmskb %xmm3, %eax
-	test	%eax, %eax
-	jnz	L(matches32)
-
-	movdqa	16(%ecx), %xmm2
-
-	pcmpeqb	%xmm1, %xmm2
-	pcmpeqb	(%ecx), %xmm1
-
-	pmovmskb %xmm2, %eax
-	test	%eax, %eax
-	jnz	L(matches16)
-
-	pmovmskb %xmm1, %eax
-	test	%ah, %ah
-	jnz	L(exit_dispatch_high)
-	mov	%al, %dl
-	and	$15 << 4, %dl
-	jnz	L(exit_dispatch_8)
-	test	$0x08, %al
-	jnz	L(exit_4)
-	test	$0x04, %al
-	jnz	L(exit_3)
-	test	$0x02, %al
-	jnz	L(exit_2)
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(exit_loop):
-	add	$64, %edx
-	cmp	$32, %edx
-	jbe	L(exit_loop_32)
-
-	movdqa	48(%ecx), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(matches48)
-
-	movdqa	32(%ecx), %xmm2
-	pcmpeqb	%xmm1, %xmm2
-	pmovmskb %xmm2, %eax
-	test	%eax, %eax
-	jnz	L(matches32)
-
-	movdqa	16(%ecx), %xmm3
-	pcmpeqb	%xmm1, %xmm3
-	pmovmskb %xmm3, %eax
-	test	%eax, %eax
-	jnz	L(matches16_1)
-	cmp	$48, %edx
-	jbe	L(return_null)
-
-	pcmpeqb	(%ecx), %xmm1
-	pmovmskb %xmm1, %eax
-	test	%eax, %eax
-	jnz	L(matches0_1)
-	xor	%eax, %eax
-	ret
-
-	.p2align 4
-L(exit_loop_32):
-	movdqa	48(%ecx), %xmm0
-	pcmpeqb	%xmm1, %xmm0
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(matches48_1)
-	cmp	$16, %edx
-	jbe	L(return_null)
-
-	pcmpeqb	32(%ecx), %xmm1
-	pmovmskb %xmm1, %eax
-	test	%eax, %eax
-	jnz	L(matches32_1)
-	xor	%eax, %eax
-	ret
-
-	.p2align 4
-L(matches16):
-	lea	16(%ecx), %ecx
-	test	%ah, %ah
-	jnz	L(exit_dispatch_high)
-	mov	%al, %dl
-	and	$15 << 4, %dl
-	jnz	L(exit_dispatch_8)
-	test	$0x08, %al
-	jnz	L(exit_4)
-	test	$0x04, %al
-	jnz	L(exit_3)
-	test	$0x02, %al
-	jnz	L(exit_2)
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(matches32):
-	lea	32(%ecx), %ecx
-	test	%ah, %ah
-	jnz	L(exit_dispatch_high)
-	mov	%al, %dl
-	and	$15 << 4, %dl
-	jnz	L(exit_dispatch_8)
-	test	$0x08, %al
-	jnz	L(exit_4)
-	test	$0x04, %al
-	jnz	L(exit_3)
-	test	$0x02, %al
-	jnz	L(exit_2)
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(matches48):
-	lea	48(%ecx), %ecx
-
-	.p2align 4
-L(exit_dispatch):
-	test	%ah, %ah
-	jnz	L(exit_dispatch_high)
-	mov	%al, %dl
-	and	$15 << 4, %dl
-	jnz	L(exit_dispatch_8)
-	test	$0x08, %al
-	jnz	L(exit_4)
-	test	$0x04, %al
-	jnz	L(exit_3)
-	test	$0x02, %al
-	jnz	L(exit_2)
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(exit_dispatch_8):
-	test	$0x80, %al
-	jnz	L(exit_8)
-	test	$0x40, %al
-	jnz	L(exit_7)
-	test	$0x20, %al
-	jnz	L(exit_6)
-	lea	4(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_dispatch_high):
-	mov	%ah, %dh
-	and	$15 << 4, %dh
-	jnz	L(exit_dispatch_high_8)
-	test	$0x08, %ah
-	jnz	L(exit_12)
-	test	$0x04, %ah
-	jnz	L(exit_11)
-	test	$0x02, %ah
-	jnz	L(exit_10)
-	lea	8(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_dispatch_high_8):
-	test	$0x80, %ah
-	jnz	L(exit_16)
-	test	$0x40, %ah
-	jnz	L(exit_15)
-	test	$0x20, %ah
-	jnz	L(exit_14)
-	lea	12(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_2):
-	lea	1(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_3):
-	lea	2(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_4):
-	lea	3(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_6):
-	lea	5(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_7):
-	lea	6(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_8):
-	lea	7(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_10):
-	lea	9(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_11):
-	lea	10(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_12):
-	lea	11(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_14):
-	lea	13(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_15):
-	lea	14(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_16):
-	lea	15(%ecx), %eax
-	ret
-
-	.p2align 4
-L(matches0_1):
-	lea	-64(%edx), %edx
-
-	test	%ah, %ah
-	jnz	L(exit_dispatch_1_high)
-	mov	%al, %ah
-	and	$15 << 4, %ah
-	jnz	L(exit_dispatch_1_8)
-	test	$0x08, %al
-	jnz	L(exit_1_4)
-	test	$0x04, %al
-	jnz	L(exit_1_3)
-	test	$0x02, %al
-	jnz	L(exit_1_2)
-
-	add	$0, %edx
-	jl	L(return_null)
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(matches16_1):
-	lea	-48(%edx), %edx
-	lea	16(%ecx), %ecx
-
-	test	%ah, %ah
-	jnz	L(exit_dispatch_1_high)
-	mov	%al, %ah
-	and	$15 << 4, %ah
-	jnz	L(exit_dispatch_1_8)
-	test	$0x08, %al
-	jnz	L(exit_1_4)
-	test	$0x04, %al
-	jnz	L(exit_1_3)
-	test	$0x02, %al
-	jnz	L(exit_1_2)
-
-	add	$0, %edx
-	jl	L(return_null)
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(matches32_1):
-	lea	-32(%edx), %edx
-	lea	32(%ecx), %ecx
-
-	test	%ah, %ah
-	jnz	L(exit_dispatch_1_high)
-	mov	%al, %ah
-	and	$15 << 4, %ah
-	jnz	L(exit_dispatch_1_8)
-	test	$0x08, %al
-	jnz	L(exit_1_4)
-	test	$0x04, %al
-	jnz	L(exit_1_3)
-	test	$0x02, %al
-	jnz	L(exit_1_2)
-
-	add	$0, %edx
-	jl	L(return_null)
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(matches48_1):
-	lea	-16(%edx), %edx
-	lea	48(%ecx), %ecx
-
-	.p2align 4
-L(exit_dispatch_1):
-	test	%ah, %ah
-	jnz	L(exit_dispatch_1_high)
-	mov	%al, %ah
-	and	$15 << 4, %ah
-	jnz	L(exit_dispatch_1_8)
-	test	$0x08, %al
-	jnz	L(exit_1_4)
-	test	$0x04, %al
-	jnz	L(exit_1_3)
-	test	$0x02, %al
-	jnz	L(exit_1_2)
-
-	add	$0, %edx
-	jl	L(return_null)
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(exit_dispatch_1_8):
-	test	$0x80, %al
-	jnz	L(exit_1_8)
-	test	$0x40, %al
-	jnz	L(exit_1_7)
-	test	$0x20, %al
-	jnz	L(exit_1_6)
-
-	add	$4, %edx
-	jl	L(return_null)
-	lea	4(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_dispatch_1_high):
-	mov	%ah, %al
-	and	$15 << 4, %al
-	jnz	L(exit_dispatch_1_high_8)
-	test	$0x08, %ah
-	jnz	L(exit_1_12)
-	test	$0x04, %ah
-	jnz	L(exit_1_11)
-	test	$0x02, %ah
-	jnz	L(exit_1_10)
-
-	add	$8, %edx
-	jl	L(return_null)
-	lea	8(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_dispatch_1_high_8):
-	test	$0x80, %ah
-	jnz	L(exit_1_16)
-	test	$0x40, %ah
-	jnz	L(exit_1_15)
-	test	$0x20, %ah
-	jnz	L(exit_1_14)
-
-	add	$12, %edx
-	jl	L(return_null)
-	lea	12(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_2):
-	add	$1, %edx
-	jl	L(return_null)
-	lea	1(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_3):
-	add	$2, %edx
-	jl	L(return_null)
-	lea	2(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_4):
-	add	$3, %edx
-	jl	L(return_null)
-	lea	3(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_6):
-	add	$5, %edx
-	jl	L(return_null)
-	lea	5(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_7):
-	add	$6, %edx
-	jl	L(return_null)
-	lea	6(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_8):
-	add	$7, %edx
-	jl	L(return_null)
-	lea	7(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_10):
-	add	$9, %edx
-	jl	L(return_null)
-	lea	9(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_11):
-	add	$10, %edx
-	jl	L(return_null)
-	lea	10(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_12):
-	add	$11, %edx
-	jl	L(return_null)
-	lea	11(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_14):
-	add	$13, %edx
-	jl	L(return_null)
-	lea	13(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_15):
-	add	$14, %edx
-	jl	L(return_null)
-	lea	14(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit_1_16):
-	add	$15, %edx
-	jl	L(return_null)
-	lea	15(%ecx), %eax
-	ret
-
-	.p2align 4
-L(return_null):
-	xor	%eax, %eax
-	ret
-
-	.p2align 4
-L(length_less16_offset0):
-	mov	%dl, %cl
-	pcmpeqb	(%eax), %xmm1
-
-	mov	$1, %edx
-	sal	%cl, %edx
-	sub	$1, %edx
-
-	mov	%eax, %ecx
-	pmovmskb %xmm1, %eax
-
-	and	%edx, %eax
-	test	%eax, %eax
-	jnz	L(exit_dispatch)
-
-	xor	%eax, %eax
-	ret
-
-	.p2align 4
-L(length_less16):
-	punpcklbw %xmm1, %xmm1
-	add	$16, %edx
-	punpcklbw %xmm1, %xmm1
-
-	mov	%ecx, %eax
-	pshufd	$0, %xmm1, %xmm1
-
-	and	$15, %ecx
-	jz	L(length_less16_offset0)
-
-	PUSH	(%edi)
-
-	mov	%cl, %dh
-	add	%dl, %dh
-	and	$-16, %eax
-
-	sub	$16, %dh
-	ja	L(length_less16_part2)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edi
-
-	sar	%cl, %edi
-	add	%ecx, %eax
-	mov	%dl, %cl
-
-	mov	$1, %edx
-	sal	%cl, %edx
-	sub	$1, %edx
-
-	and	%edx, %edi
-	test	%edi, %edi
-	jz	L(ret_null)
-
-	bsr	%edi, %edi
-	add	%edi, %eax
-	POP	(%edi)
-	ret
-
-	CFI_PUSH     (%edi)
-
-	.p2align 4
-L(length_less16_part2):
-	movdqa	16(%eax), %xmm2
-	pcmpeqb	%xmm1, %xmm2
-	pmovmskb %xmm2, %edi
-
-	mov	%cl, %ch
-
-	mov	%dh, %cl
-	mov	$1, %edx
-	sal	%cl, %edx
-	sub	$1, %edx
-
-	and	%edx, %edi
-
-	test	%edi, %edi
-	jnz	L(length_less16_part2_return)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edi
-
-	mov	%ch, %cl
-	sar	%cl, %edi
-	test	%edi, %edi
-	jz	L(ret_null)
-
-	bsr	%edi, %edi
-	add	%edi, %eax
-	xor	%ch, %ch
-	add	%ecx, %eax
-	POP	(%edi)
-	ret
-
-	CFI_PUSH     (%edi)
-
-	.p2align 4
-L(length_less16_part2_return):
-	bsr	%edi, %edi
-	lea	16(%eax, %edi), %eax
-	POP	(%edi)
-	ret
-
-	CFI_PUSH     (%edi)
-
-	.p2align 4
-L(ret_null):
-	xor	%eax, %eax
-	POP	(%edi)
-	ret
-
-END (memrchr)
diff --git a/libc/arch-x86/string/sse2-wcschr-atom.S b/libc/arch-x86/string/sse2-wcschr-atom.S
deleted file mode 100644
index 729302bcd..000000000
--- a/libc/arch-x86/string/sse2-wcschr-atom.S
+++ /dev/null
@@ -1,267 +0,0 @@
-/*
-Copyright (c) 2011 Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef L
-# define L(label)	.L##label
-#endif
-
-#ifndef cfi_startproc
-# define cfi_startproc	.cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc	.cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name,  @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name,	.-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG)	pushl REG; CFI_PUSH (REG)
-#define POP(REG)	popl REG; CFI_POP (REG)
-
-#define PARMS	4
-
-
-#define STR1  PARMS
-#define STR2  STR1+4
-
-	.text
-ENTRY (wcschr)
-
-	mov	STR1(%esp), %ecx
-	movd	STR2(%esp), %xmm1
-
-	mov	%ecx, %eax
-	punpckldq %xmm1, %xmm1
-	pxor	%xmm2, %xmm2
-	punpckldq %xmm1, %xmm1
-
-	and	$63, %eax
-	cmp	$48, %eax
-	ja	L(cross_cache)
-
-	movdqu	(%ecx), %xmm0
-	pcmpeqd	%xmm0, %xmm2
-	pcmpeqd	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	or	%eax, %edx
-	jnz	L(matches)
-	and	$-16, %ecx
-	jmp	L(loop)
-
-	.p2align 4
-L(cross_cache):
-	PUSH	(%edi)
-	mov	%ecx, %edi
-	mov	%eax, %ecx
-	and	$-16, %edi
-	and	$15, %ecx
-	movdqa	(%edi), %xmm0
-	pcmpeqd	%xmm0, %xmm2
-	pcmpeqd	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-
-	sarl	%cl, %edx
-	sarl	%cl, %eax
-	test	%eax, %eax
-	jz	L(unaligned_no_match)
-
-	add	%edi, %ecx
-	POP	(%edi)
-
-	test	%edx, %edx
-	jz	L(match_case1)
-	test	%al, %al
-	jz	L(match_higth_case2)
-	test	$15, %al
-	jnz	L(match_case2_4)
-	test	$15, %dl
-	jnz	L(return_null)
-	lea	4(%ecx), %eax
-	ret
-
-	CFI_PUSH (%edi)
-
-	.p2align 4
-L(unaligned_no_match):
-	mov	%edi, %ecx
-	POP	(%edi)
-
-	test	%edx, %edx
-	jnz	L(return_null)
-
-	pxor	%xmm2, %xmm2
-
-/* Loop start on aligned string.  */
-	.p2align 4
-L(loop):
-	add	$16, %ecx
-	movdqa	(%ecx), %xmm0
-	pcmpeqd	%xmm0, %xmm2
-	pcmpeqd	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	or	%eax, %edx
-	jnz	L(matches)
-	add	$16, %ecx
-
-	movdqa	(%ecx), %xmm0
-	pcmpeqd	%xmm0, %xmm2
-	pcmpeqd	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	or	%eax, %edx
-	jnz	L(matches)
-	add	$16, %ecx
-
-	movdqa	(%ecx), %xmm0
-	pcmpeqd	%xmm0, %xmm2
-	pcmpeqd	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	or	%eax, %edx
-	jnz	L(matches)
-	add	$16, %ecx
-
-	movdqa	(%ecx), %xmm0
-	pcmpeqd	%xmm0, %xmm2
-	pcmpeqd	%xmm1, %xmm0
-	pmovmskb %xmm2, %edx
-	pmovmskb %xmm0, %eax
-	or	%eax, %edx
-	jz	L(loop)
-
-	.p2align 4
-L(matches):
-	pmovmskb %xmm2, %edx
-	test	%eax, %eax
-	jz	L(return_null)
-	test	%edx, %edx
-	jz	L(match_case1)
-
-	.p2align 4
-L(match_case2):
-	test	%al, %al
-	jz	L(match_higth_case2)
-	test	$15, %al
-	jnz	L(match_case2_4)
-	test	$15, %dl
-	jnz	L(return_null)
-	lea	4(%ecx), %eax
-	ret
-
-	.p2align 4
-L(match_case2_4):
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(match_higth_case2):
-	test	%dl, %dl
-	jnz	L(return_null)
-	test	$15, %ah
-	jnz	L(match_case2_12)
-	test	$15, %dh
-	jnz	L(return_null)
-	lea	12(%ecx), %eax
-	ret
-
-	.p2align 4
-L(match_case2_12):
-	lea	8(%ecx), %eax
-	ret
-
-	.p2align 4
-L(match_case1):
-	test	%al, %al
-	jz	L(match_higth_case1)
-
-	test	$0x01, %al
-	jnz	L(exit0)
-	lea	4(%ecx), %eax
-	ret
-
-	.p2align 4
-L(match_higth_case1):
-	test	$0x01, %ah
-	jnz	L(exit3)
-	lea	12(%ecx), %eax
-	ret
-
-	.p2align 4
-L(exit0):
-	mov	%ecx, %eax
-	ret
-
-	.p2align 4
-L(exit3):
-	lea	8(%ecx), %eax
-	ret
-
-	.p2align 4
-L(return_null):
-	xor	%eax, %eax
-	ret
-
-END (wcschr)
diff --git a/libc/arch-x86/string/sse2-wcscmp-atom.S b/libc/arch-x86/string/sse2-wcscmp-atom.S
deleted file mode 100644
index 8867d28ae..000000000
--- a/libc/arch-x86/string/sse2-wcscmp-atom.S
+++ /dev/null
@@ -1,1062 +0,0 @@
-/*
-Copyright (c) 2011 Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef L
-# define L(label)	.L##label
-#endif
-
-#ifndef cfi_startproc
-# define cfi_startproc	.cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc	.cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name, @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name, .-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG) pushl REG; CFI_PUSH (REG)
-#define POP(REG) popl REG; CFI_POP (REG)
-
-#define ENTRANCE PUSH(%esi); PUSH(%edi)
-#define RETURN  POP(%edi); POP(%esi); ret; CFI_PUSH(%esi); CFI_PUSH(%edi);
-#define PARMS  4
-#define STR1  PARMS
-#define STR2  STR1+4
-
-	.text
-ENTRY (wcscmp)
-/*
-	* This implementation uses SSE to compare up to 16 bytes at a time.
-*/
-	mov	STR1(%esp), %edx
-	mov	STR2(%esp), %eax
-
-	mov	(%eax), %ecx
-	cmp	%ecx, (%edx)
-	jne	L(neq)
-	test	%ecx, %ecx
-	jz	L(eq)
-
-	mov	4(%eax), %ecx
-	cmp	%ecx, 4(%edx)
-	jne	L(neq)
-	test	%ecx, %ecx
-	jz	L(eq)
-
-	mov	8(%eax), %ecx
-	cmp	%ecx, 8(%edx)
-	jne	L(neq)
-	test	%ecx, %ecx
-	jz	L(eq)
-
-	mov	12(%eax), %ecx
-	cmp	%ecx, 12(%edx)
-	jne	L(neq)
-	test	%ecx, %ecx
-	jz	L(eq)
-
-	ENTRANCE
-	add	$16, %eax
-	add	$16, %edx
-
-	mov	%eax, %esi
-	mov	%edx, %edi
-	pxor	%xmm0, %xmm0		/* clear %xmm0 for null char checks */
-	mov	%al, %ch
-	mov	%dl, %cl
-	and	$63, %eax		/* esi alignment in cache line */
-	and	$63, %edx		/* edi alignment in cache line */
-	and	$15, %cl
-	jz	L(continue_00)
-	cmp	$16, %edx
-	jb	L(continue_0)
-	cmp	$32, %edx
-	jb	L(continue_16)
-	cmp	$48, %edx
-	jb	L(continue_32)
-
-L(continue_48):
-	and	$15, %ch
-	jz	L(continue_48_00)
-	cmp	$16, %eax
-	jb	L(continue_0_48)
-	cmp	$32, %eax
-	jb	L(continue_16_48)
-	cmp	$48, %eax
-	jb	L(continue_32_48)
-
-	.p2align 4
-L(continue_48_48):
-	mov	(%esi), %ecx
-	cmp	%ecx, (%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	4(%esi), %ecx
-	cmp	%ecx, 4(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	8(%esi), %ecx
-	cmp	%ecx, 8(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	12(%esi), %ecx
-	cmp	%ecx, 12(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	movdqu	16(%edi), %xmm1
-	movdqu	16(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	movdqu	32(%edi), %xmm1
-	movdqu	32(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	movdqu	48(%edi), %xmm1
-	movdqu	48(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_48)
-
-	add	$64, %esi
-	add	$64, %edi
-	jmp	L(continue_48_48)
-
-L(continue_0):
-	and	$15, %ch
-	jz	L(continue_0_00)
-	cmp	$16, %eax
-	jb	L(continue_0_0)
-	cmp	$32, %eax
-	jb	L(continue_0_16)
-	cmp	$48, %eax
-	jb	L(continue_0_32)
-
-	.p2align 4
-L(continue_0_48):
-	mov	(%esi), %ecx
-	cmp	%ecx, (%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	4(%esi), %ecx
-	cmp	%ecx, 4(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	8(%esi), %ecx
-	cmp	%ecx, 8(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	12(%esi), %ecx
-	cmp	%ecx, 12(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	movdqu	16(%edi), %xmm1
-	movdqu	16(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	movdqu	32(%edi), %xmm1
-	movdqu	32(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	mov	48(%esi), %ecx
-	cmp	%ecx, 48(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	52(%esi), %ecx
-	cmp	%ecx, 52(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	56(%esi), %ecx
-	cmp	%ecx, 56(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	60(%esi), %ecx
-	cmp	%ecx, 60(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	add	$64, %esi
-	add	$64, %edi
-	jmp	L(continue_0_48)
-
-	.p2align 4
-L(continue_00):
-	and	$15, %ch
-	jz	L(continue_00_00)
-	cmp	$16, %eax
-	jb	L(continue_00_0)
-	cmp	$32, %eax
-	jb	L(continue_00_16)
-	cmp	$48, %eax
-	jb	L(continue_00_32)
-
-	.p2align 4
-L(continue_00_48):
-	pcmpeqd	(%edi), %xmm0
-	mov	(%edi), %eax
-	pmovmskb %xmm0, %ecx
-	test	%ecx, %ecx
-	jnz	L(less4_double_words1)
-
-	cmp	(%esi), %eax
-	jne	L(nequal)
-
-	mov	4(%edi), %eax
-	cmp	4(%esi), %eax
-	jne	L(nequal)
-
-	mov	8(%edi), %eax
-	cmp	8(%esi), %eax
-	jne	L(nequal)
-
-	mov	12(%edi), %eax
-	cmp	12(%esi), %eax
-	jne	L(nequal)
-
-	movdqu	16(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	16(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	movdqu	32(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	32(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	movdqu	48(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	48(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_48)
-
-	add	$64, %esi
-	add	$64, %edi
-	jmp	L(continue_00_48)
-
-	.p2align 4
-L(continue_32):
-	and	$15, %ch
-	jz	L(continue_32_00)
-	cmp	$16, %eax
-	jb	L(continue_0_32)
-	cmp	$32, %eax
-	jb	L(continue_16_32)
-	cmp	$48, %eax
-	jb	L(continue_32_32)
-
-	.p2align 4
-L(continue_32_48):
-	mov	(%esi), %ecx
-	cmp	%ecx, (%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	4(%esi), %ecx
-	cmp	%ecx, 4(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	8(%esi), %ecx
-	cmp	%ecx, 8(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	12(%esi), %ecx
-	cmp	%ecx, 12(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	16(%esi), %ecx
-	cmp	%ecx, 16(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	20(%esi), %ecx
-	cmp	%ecx, 20(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	24(%esi), %ecx
-	cmp	%ecx, 24(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	28(%esi), %ecx
-	cmp	%ecx, 28(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	movdqu	32(%edi), %xmm1
-	movdqu	32(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	movdqu	48(%edi), %xmm1
-	movdqu	48(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_48)
-
-	add	$64, %esi
-	add	$64, %edi
-	jmp	L(continue_32_48)
-
-	.p2align 4
-L(continue_16):
-	and	$15, %ch
-	jz	L(continue_16_00)
-	cmp	$16, %eax
-	jb	L(continue_0_16)
-	cmp	$32, %eax
-	jb	L(continue_16_16)
-	cmp	$48, %eax
-	jb	L(continue_16_32)
-
-	.p2align 4
-L(continue_16_48):
-	mov	(%esi), %ecx
-	cmp	%ecx, (%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	4(%esi), %ecx
-	cmp	%ecx, 4(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	8(%esi), %ecx
-	cmp	%ecx, 8(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	12(%esi), %ecx
-	cmp	%ecx, 12(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	movdqu	16(%edi), %xmm1
-	movdqu	16(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	mov	32(%esi), %ecx
-	cmp	%ecx, 32(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	36(%esi), %ecx
-	cmp	%ecx, 36(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	40(%esi), %ecx
-	cmp	%ecx, 40(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	44(%esi), %ecx
-	cmp	%ecx, 44(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	movdqu	48(%edi), %xmm1
-	movdqu	48(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_48)
-
-	add	$64, %esi
-	add	$64, %edi
-	jmp	L(continue_16_48)
-
-	.p2align 4
-L(continue_00_00):
-	movdqa	(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	movdqa	16(%edi), %xmm3
-	pcmpeqd	%xmm3, %xmm0		/* Any null double_word? */
-	pcmpeqd	16(%esi), %xmm3		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm3		/* packed sub of comparison results*/
-	pmovmskb %xmm3, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	movdqa	32(%edi), %xmm5
-	pcmpeqd	%xmm5, %xmm0		/* Any null double_word? */
-	pcmpeqd	32(%esi), %xmm5		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm5		/* packed sub of comparison results*/
-	pmovmskb %xmm5, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	movdqa	48(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	48(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_48)
-
-	add	$64, %esi
-	add	$64, %edi
-	jmp	L(continue_00_00)
-
-	.p2align 4
-L(continue_00_32):
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	add	$16, %esi
-	add	$16, %edi
-	jmp	L(continue_00_48)
-
-	.p2align 4
-L(continue_00_16):
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	movdqu	16(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	16(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	add	$32, %esi
-	add	$32, %edi
-	jmp	L(continue_00_48)
-
-	.p2align 4
-L(continue_00_0):
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	movdqu	16(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	16(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	movdqu	32(%esi), %xmm2
-	pcmpeqd	%xmm2, %xmm0		/* Any null double_word? */
-	pcmpeqd	32(%edi), %xmm2		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm2		/* packed sub of comparison results*/
-	pmovmskb %xmm2, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	add	$48, %esi
-	add	$48, %edi
-	jmp	L(continue_00_48)
-
-	.p2align 4
-L(continue_48_00):
-	pcmpeqd	(%esi), %xmm0
-	mov	(%edi), %eax
-	pmovmskb %xmm0, %ecx
-	test	%ecx, %ecx
-	jnz	L(less4_double_words1)
-
-	cmp	(%esi), %eax
-	jne	L(nequal)
-
-	mov	4(%edi), %eax
-	cmp	4(%esi), %eax
-	jne	L(nequal)
-
-	mov	8(%edi), %eax
-	cmp	8(%esi), %eax
-	jne	L(nequal)
-
-	mov	12(%edi), %eax
-	cmp	12(%esi), %eax
-	jne	L(nequal)
-
-	movdqu	16(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	16(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	movdqu	32(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	32(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	movdqu	48(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	48(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_48)
-
-	add	$64, %esi
-	add	$64, %edi
-	jmp	L(continue_48_00)
-
-	.p2align 4
-L(continue_32_00):
-	movdqu	(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	add	$16, %esi
-	add	$16, %edi
-	jmp	L(continue_48_00)
-
-	.p2align 4
-L(continue_16_00):
-	movdqu	(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	movdqu	16(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	16(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	add	$32, %esi
-	add	$32, %edi
-	jmp	L(continue_48_00)
-
-	.p2align 4
-L(continue_0_00):
-	movdqu	(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	movdqu	16(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	16(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	movdqu	32(%edi), %xmm1
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	32(%esi), %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	add	$48, %esi
-	add	$48, %edi
-	jmp	L(continue_48_00)
-
-	.p2align 4
-L(continue_32_32):
-	movdqu	(%edi), %xmm1
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	add	$16, %esi
-	add	$16, %edi
-	jmp	L(continue_48_48)
-
-	.p2align 4
-L(continue_16_16):
-	movdqu	(%edi), %xmm1
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	movdqu	16(%edi), %xmm3
-	movdqu	16(%esi), %xmm4
-	pcmpeqd	%xmm3, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm4, %xmm3		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm3		/* packed sub of comparison results*/
-	pmovmskb %xmm3, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	add	$32, %esi
-	add	$32, %edi
-	jmp	L(continue_48_48)
-
-	.p2align 4
-L(continue_0_0):
-	movdqu	(%edi), %xmm1
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	movdqu	16(%edi), %xmm3
-	movdqu	16(%esi), %xmm4
-	pcmpeqd	%xmm3, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm4, %xmm3		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm3		/* packed sub of comparison results*/
-	pmovmskb %xmm3, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	movdqu	32(%edi), %xmm1
-	movdqu	32(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_32)
-
-	add	$48, %esi
-	add	$48, %edi
-	jmp	L(continue_48_48)
-
-	.p2align 4
-L(continue_0_16):
-	movdqu	(%edi), %xmm1
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	movdqu	16(%edi), %xmm1
-	movdqu	16(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words_16)
-
-	add	$32, %esi
-	add	$32, %edi
-	jmp	L(continue_32_48)
-
-	.p2align 4
-L(continue_0_32):
-	movdqu	(%edi), %xmm1
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	add	$16, %esi
-	add	$16, %edi
-	jmp	L(continue_16_48)
-
-	.p2align 4
-L(continue_16_32):
-	movdqu	(%edi), %xmm1
-	movdqu	(%esi), %xmm2
-	pcmpeqd	%xmm1, %xmm0		/* Any null double_word? */
-	pcmpeqd	%xmm2, %xmm1		/* compare first 4 double_words for equality */
-	psubb	%xmm0, %xmm1		/* packed sub of comparison results*/
-	pmovmskb %xmm1, %edx
-	sub	$0xffff, %edx		/* if first 4 double_words are same, edx == 0xffff */
-	jnz	L(less4_double_words)
-
-	add	$16, %esi
-	add	$16, %edi
-	jmp	L(continue_32_48)
-
-	.p2align 4
-L(less4_double_words1):
-	cmp	(%esi), %eax
-	jne	L(nequal)
-	test	%eax, %eax
-	jz	L(equal)
-
-	mov	4(%esi), %ecx
-	cmp	%ecx, 4(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	8(%esi), %ecx
-	cmp	%ecx, 8(%edi)
-	jne	L(nequal)
-	test	%ecx, %ecx
-	jz	L(equal)
-
-	mov	12(%esi), %ecx
-	cmp	%ecx, 12(%edi)
-	jne	L(nequal)
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(less4_double_words):
-	xor	%eax, %eax
-	test	%dl, %dl
-	jz	L(next_two_double_words)
-	and	$15, %dl
-	jz	L(second_double_word)
-	mov	(%esi), %ecx
-	cmp	%ecx, (%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(second_double_word):
-	mov	4(%esi), %ecx
-	cmp	%ecx, 4(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(next_two_double_words):
-	and	$15, %dh
-	jz	L(fourth_double_word)
-	mov	8(%esi), %ecx
-	cmp	%ecx, 8(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(fourth_double_word):
-	mov	12(%esi), %ecx
-	cmp	%ecx, 12(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(less4_double_words_16):
-	xor	%eax, %eax
-	test	%dl, %dl
-	jz	L(next_two_double_words_16)
-	and	$15, %dl
-	jz	L(second_double_word_16)
-	mov	16(%esi), %ecx
-	cmp	%ecx, 16(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(second_double_word_16):
-	mov	20(%esi), %ecx
-	cmp	%ecx, 20(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(next_two_double_words_16):
-	and	$15, %dh
-	jz	L(fourth_double_word_16)
-	mov	24(%esi), %ecx
-	cmp	%ecx, 24(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(fourth_double_word_16):
-	mov	28(%esi), %ecx
-	cmp	%ecx, 28(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(less4_double_words_32):
-	xor	%eax, %eax
-	test	%dl, %dl
-	jz	L(next_two_double_words_32)
-	and	$15, %dl
-	jz	L(second_double_word_32)
-	mov	32(%esi), %ecx
-	cmp	%ecx, 32(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(second_double_word_32):
-	mov	36(%esi), %ecx
-	cmp	%ecx, 36(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(next_two_double_words_32):
-	and	$15, %dh
-	jz	L(fourth_double_word_32)
-	mov	40(%esi), %ecx
-	cmp	%ecx, 40(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(fourth_double_word_32):
-	mov	44(%esi), %ecx
-	cmp	%ecx, 44(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(less4_double_words_48):
-	xor	%eax, %eax
-	test	%dl, %dl
-	jz	L(next_two_double_words_48)
-	and	$15, %dl
-	jz	L(second_double_word_48)
-	mov	48(%esi), %ecx
-	cmp	%ecx, 48(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(second_double_word_48):
-	mov	52(%esi), %ecx
-	cmp	%ecx, 52(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(next_two_double_words_48):
-	and	$15, %dh
-	jz	L(fourth_double_word_48)
-	mov	56(%esi), %ecx
-	cmp	%ecx, 56(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(fourth_double_word_48):
-	mov	60(%esi), %ecx
-	cmp	%ecx, 60(%edi)
-	jne	L(nequal)
-	RETURN
-
-	.p2align 4
-L(nequal):
-	mov	$1, %eax
-	jg	L(return)
-	neg	%eax
-	RETURN
-
-	.p2align 4
-L(return):
-	RETURN
-
-	.p2align 4
-L(equal):
-	xorl	%eax, %eax
-	RETURN
-
-	CFI_POP (%edi)
-	CFI_POP (%esi)
-
-	.p2align 4
-L(neq):
-	mov	$1, %eax
-	jg	L(neq_bigger)
-	neg	%eax
-
-L(neq_bigger):
-	ret
-
-	.p2align 4
-L(eq):
-	xorl	%eax, %eax
-	ret
-
-END (wcscmp)
-
diff --git a/libc/arch-x86/string/sse2-wcslen-atom.S b/libc/arch-x86/string/sse2-wcslen-atom.S
deleted file mode 100644
index 2f10db450..000000000
--- a/libc/arch-x86/string/sse2-wcslen-atom.S
+++ /dev/null
@@ -1,306 +0,0 @@
-/*
-Copyright (c) 2011 Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef USE_AS_WCSCAT
-
-# ifndef L
-#  define L(label)	.L##label
-# endif
-
-# ifndef cfi_startproc
-#  define cfi_startproc	.cfi_startproc
-# endif
-
-# ifndef cfi_endproc
-#  define cfi_endproc	.cfi_endproc
-# endif
-
-# ifndef ENTRY
-#  define ENTRY(name)	\
-	.type name,  @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-# endif
-
-# ifndef END
-#  define END(name)	\
-	cfi_endproc;	\
-	.size name, .-name
-# endif
-
-# define PARMS	4
-# define STR	PARMS
-# define RETURN ret
-
-	.text
-ENTRY (wcslen)
-	mov	STR(%esp), %edx
-#endif
-	cmpl	$0, (%edx)
-	jz	L(exit_tail0)
-	cmpl	$0, 4(%edx)
-	jz	L(exit_tail1)
-	cmpl	$0, 8(%edx)
-	jz	L(exit_tail2)
-	cmpl	$0, 12(%edx)
-	jz	L(exit_tail3)
-	cmpl	$0, 16(%edx)
-	jz	L(exit_tail4)
-	cmpl	$0, 20(%edx)
-	jz	L(exit_tail5)
-	cmpl	$0, 24(%edx)
-	jz	L(exit_tail6)
-	cmpl	$0, 28(%edx)
-	jz	L(exit_tail7)
-
-	pxor	%xmm0, %xmm0
-
-	lea	32(%edx), %eax
-	lea	-16(%eax), %ecx
-	and	$-16, %eax
-
-	pcmpeqd	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	pxor	%xmm1, %xmm1
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	pxor	%xmm2, %xmm2
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	pxor	%xmm3, %xmm3
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	and	$-0x40, %eax
-
-	.p2align 4
-L(aligned_64_loop):
-	movaps	(%eax), %xmm0
-	movaps	16(%eax), %xmm1
-	movaps	32(%eax), %xmm2
-	movaps	48(%eax), %xmm6
-
-	pminub	%xmm1, %xmm0
-	pminub	%xmm6, %xmm2
-	pminub	%xmm0, %xmm2
-	pcmpeqd	%xmm3, %xmm2
-	pmovmskb %xmm2, %edx
-	lea	64(%eax), %eax
-	test	%edx, %edx
-	jz	L(aligned_64_loop)
-
-	pcmpeqd	-64(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	48(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	%xmm1, %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	-32(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqd	%xmm6, %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	jmp	L(aligned_64_loop)
-
-	.p2align 4
-L(exit):
-	sub	%ecx, %eax
-	shr	$2, %eax
-	test	%dl, %dl
-	jz	L(exit_high)
-
-	mov	%dl, %cl
-	and	$15, %cl
-	jz	L(exit_1)
-	RETURN
-
-	.p2align 4
-L(exit_high):
-	mov	%dh, %ch
-	and	$15, %ch
-	jz	L(exit_3)
-	add	$2, %eax
-	RETURN
-
-	.p2align 4
-L(exit_1):
-	add	$1, %eax
-	RETURN
-
-	.p2align 4
-L(exit_3):
-	add	$3, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail0):
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail1):
-	mov	$1, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail2):
-	mov	$2, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail3):
-	mov	$3, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail4):
-	mov	$4, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail5):
-	mov	$5, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail6):
-	mov	$6, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail7):
-	mov	$7, %eax
-#ifndef USE_AS_WCSCAT
-	RETURN
-
-END (wcslen)
-#endif
diff --git a/libc/arch-x86/string/sse2-wcsrchr-atom.S b/libc/arch-x86/string/sse2-wcsrchr-atom.S
deleted file mode 100644
index 1a55df24a..000000000
--- a/libc/arch-x86/string/sse2-wcsrchr-atom.S
+++ /dev/null
@@ -1,402 +0,0 @@
-/*
-Copyright (c) 2011 Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef L
-# define L(label)	.L##label
-#endif
-
-#ifndef cfi_startproc
-# define cfi_startproc	.cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc	.cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name, @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name, .-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG)	pushl REG;	CFI_PUSH (REG)
-#define POP(REG)	popl REG;	CFI_POP (REG)
-
-#define PARMS  8
-#define ENTRANCE PUSH(%edi);
-#define RETURN  POP(%edi);	ret;	CFI_PUSH(%edi);
-
-#define STR1  PARMS
-#define STR2  STR1+4
-
-	.text
-ENTRY (wcsrchr)
-
-	ENTRANCE
-	mov	STR1(%esp), %ecx
-	movd	STR2(%esp), %xmm1
-
-	mov	%ecx, %edi
-	punpckldq %xmm1, %xmm1
-	pxor	%xmm2, %xmm2
-	punpckldq %xmm1, %xmm1
-
-/* ECX has OFFSET. */
-	and	$63, %ecx
-	cmp	$48, %ecx
-	ja	L(crosscache)
-
-/* unaligned string. */
-	movdqu	(%edi), %xmm0
-	pcmpeqd	%xmm0, %xmm2
-	pcmpeqd	%xmm1, %xmm0
-/* Find where NULL is.  */
-	pmovmskb %xmm2, %ecx
-/* Check if there is a match.  */
-	pmovmskb %xmm0, %eax
-	add	$16, %edi
-
-	test	%eax, %eax
-	jnz	L(unaligned_match1)
-
-	test	%ecx, %ecx
-	jnz	L(return_null)
-
-	and	$-16, %edi
-
-	PUSH	(%esi)
-
-	xor	%edx, %edx
-	jmp	L(loop)
-
-	CFI_POP	(%esi)
-
-	.p2align 4
-L(unaligned_match1):
-	test	%ecx, %ecx
-	jnz	L(prolog_find_zero_1)
-
-	PUSH	(%esi)
-
-/* Save current match */
-	mov	%eax, %edx
-	mov	%edi, %esi
-	and	$-16, %edi
-	jmp	L(loop)
-
-	CFI_POP	(%esi)
-
-	.p2align 4
-L(crosscache):
-/* Hancle unaligned string.  */
-	and	$15, %ecx
-	and	$-16, %edi
-	pxor	%xmm3, %xmm3
-	movdqa	(%edi), %xmm0
-	pcmpeqd	%xmm0, %xmm3
-	pcmpeqd	%xmm1, %xmm0
-/* Find where NULL is.  */
-	pmovmskb %xmm3, %edx
-/* Check if there is a match.  */
-	pmovmskb %xmm0, %eax
-/* Remove the leading bytes.  */
-	shr	%cl, %edx
-	shr	%cl, %eax
-	add	$16, %edi
-
-	test	%eax, %eax
-	jnz	L(unaligned_match)
-
-	test	%edx, %edx
-	jnz	L(return_null)
-
-	PUSH	(%esi)
-
-	xor	%edx, %edx
-	jmp	L(loop)
-
-	CFI_POP	(%esi)
-
-	.p2align 4
-L(unaligned_match):
-	test	%edx, %edx
-	jnz	L(prolog_find_zero)
-
-	PUSH	(%esi)
-
-	mov	%eax, %edx
-	lea	(%edi, %ecx), %esi
-
-/* Loop start on aligned string.  */
-	.p2align 4
-L(loop):
-	movdqa	(%edi), %xmm0
-	pcmpeqd	%xmm0, %xmm2
-	add	$16, %edi
-	pcmpeqd	%xmm1, %xmm0
-	pmovmskb %xmm2, %ecx
-	pmovmskb %xmm0, %eax
-	or	%eax, %ecx
-	jnz	L(matches)
-
-	movdqa	(%edi), %xmm3
-	pcmpeqd	%xmm3, %xmm2
-	add	$16, %edi
-	pcmpeqd	%xmm1, %xmm3
-	pmovmskb %xmm2, %ecx
-	pmovmskb %xmm3, %eax
-	or	%eax, %ecx
-	jnz	L(matches)
-
-	movdqa	(%edi), %xmm4
-	pcmpeqd	%xmm4, %xmm2
-	add	$16, %edi
-	pcmpeqd	%xmm1, %xmm4
-	pmovmskb %xmm2, %ecx
-	pmovmskb %xmm4, %eax
-	or	%eax, %ecx
-	jnz	L(matches)
-
-	movdqa	(%edi), %xmm5
-	pcmpeqd	%xmm5, %xmm2
-	add	$16, %edi
-	pcmpeqd	%xmm1, %xmm5
-	pmovmskb %xmm2, %ecx
-	pmovmskb %xmm5, %eax
-	or	%eax, %ecx
-	jz	L(loop)
-
-	.p2align 4
-L(matches):
-	test	%eax, %eax
-	jnz	L(match)
-L(return_value):
-	test	%edx, %edx
-	jz	L(return_null_1)
-	mov	%edx, %eax
-	mov	%esi, %edi
-
-	POP	(%esi)
-
-	test	%ah, %ah
-	jnz	L(match_third_or_fourth_wchar)
-	test	$15 << 4, %al
-	jnz	L(match_second_wchar)
-	lea	-16(%edi), %eax
-	RETURN
-
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(return_null_1):
-	POP	(%esi)
-
-	xor	%eax, %eax
-	RETURN
-
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(match):
-	pmovmskb %xmm2, %ecx
-	test	%ecx, %ecx
-	jnz	L(find_zero)
-/* save match info */
-	mov	%eax, %edx
-	mov	%edi, %esi
-	jmp	L(loop)
-
-	.p2align 4
-L(find_zero):
-	test	%cl, %cl
-	jz	L(find_zero_in_third_or_fourth_wchar)
-	test	$15, %cl
-	jz	L(find_zero_in_second_wchar)
-	and	$1, %eax
-	jz	L(return_value)
-
-	POP	(%esi)
-
-	lea	-16(%edi), %eax
-	RETURN
-
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(find_zero_in_second_wchar):
-	and	$(1 << 5) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%esi)
-
-	test	$15 << 4, %al
-	jnz	L(match_second_wchar)
-	lea	-16(%edi), %eax
-	RETURN
-
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(find_zero_in_third_or_fourth_wchar):
-	test	$15, %ch
-	jz	L(find_zero_in_fourth_wchar)
-	and	$(1 << 9) - 1, %eax
-	jz	L(return_value)
-
-	POP	(%esi)
-
-	test	%ah, %ah
-	jnz	L(match_third_wchar)
-	test	$15 << 4, %al
-	jnz	L(match_second_wchar)
-	lea	-16(%edi), %eax
-	RETURN
-
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(find_zero_in_fourth_wchar):
-
-	POP	(%esi)
-
-	test	%ah, %ah
-	jnz	L(match_third_or_fourth_wchar)
-	test	$15 << 4, %al
-	jnz	L(match_second_wchar)
-	lea	-16(%edi), %eax
-	RETURN
-
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(match_second_wchar):
-	lea	-12(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_third_or_fourth_wchar):
-	test	$15 << 4, %ah
-	jnz	L(match_fourth_wchar)
-	lea	-8(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_third_wchar):
-	lea	-8(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(match_fourth_wchar):
-	lea	-4(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(return_null):
-	xor	%eax, %eax
-	RETURN
-
-	.p2align 4
-L(prolog_find_zero):
-	add	%ecx, %edi
-	mov     %edx, %ecx
-L(prolog_find_zero_1):
-	test	%cl, %cl
-	jz	L(prolog_find_zero_in_third_or_fourth_wchar)
-	test	$15, %cl
-	jz	L(prolog_find_zero_in_second_wchar)
-	and	$1, %eax
-	jz	L(return_null)
-
-	lea	-16(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(prolog_find_zero_in_second_wchar):
-	and	$(1 << 5) - 1, %eax
-	jz	L(return_null)
-
-	test	$15 << 4, %al
-	jnz	L(match_second_wchar)
-	lea	-16(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(prolog_find_zero_in_third_or_fourth_wchar):
-	test	$15, %ch
-	jz	L(prolog_find_zero_in_fourth_wchar)
-	and	$(1 << 9) - 1, %eax
-	jz	L(return_null)
-
-	test	%ah, %ah
-	jnz	L(match_third_wchar)
-	test	$15 << 4, %al
-	jnz	L(match_second_wchar)
-	lea	-16(%edi), %eax
-	RETURN
-
-	.p2align 4
-L(prolog_find_zero_in_fourth_wchar):
-	test	%ah, %ah
-	jnz	L(match_third_or_fourth_wchar)
-	test	$15 << 4, %al
-	jnz	L(match_second_wchar)
-	lea	-16(%edi), %eax
-	RETURN
-
-END (wcsrchr)
diff --git a/libc/arch-x86/string/sse4-wmemcmp-slm.S b/libc/arch-x86/string/sse4-wmemcmp-slm.S
deleted file mode 100644
index 2bf92f57e..000000000
--- a/libc/arch-x86/string/sse4-wmemcmp-slm.S
+++ /dev/null
@@ -1,33 +0,0 @@
-/*
-Copyright (c) 2014, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#define USE_AS_WMEMCMP
-#define MEMCMP wmemcmp_sse4
-#include "sse4-memcmp-slm.S"
diff --git a/libc/arch-x86/string/ssse3-strlcat-atom.S b/libc/arch-x86/string/ssse3-strlcat-atom.S
deleted file mode 100644
index daaf254d2..000000000
--- a/libc/arch-x86/string/ssse3-strlcat-atom.S
+++ /dev/null
@@ -1,1225 +0,0 @@
-/*
-Copyright (c) 2011, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-/* Optimized strlcat with SSSE3 */
-
-#ifndef cfi_startproc
-# define cfi_startproc	.cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc	.cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name,  @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name, .-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG)	pushl	REG;	CFI_PUSH (REG)
-#define POP(REG)	popl	REG;	CFI_POP (REG)
-#define L(label)	.L##Prolog_##label
-
-#define DST	4
-#define SRC	DST+8
-#define LEN	SRC+4
-
-	.text
-ENTRY (strlcat)
-	mov	DST(%esp), %edx
-	PUSH	(%ebx)
-	mov	LEN(%esp), %ebx
-	sub	$4, %ebx
-	jbe	L(len_less4_prolog)
-
-#define RETURN	jmp	L(StrcpyStep)
-#define edi	ebx
-
-#define USE_AS_STRNLEN
-#define USE_AS_STRCAT
-#define USE_AS_STRLCAT
-
-#include "sse2-strlen-atom.S"
-
-	.p2align 4
-L(StrcpyStep):
-
-#undef edi
-#undef L
-#define L(label) .L##label
-#undef RETURN
-#define RETURN	POP (%ebx); ret; CFI_PUSH (%ebx);
-#define RETURN1	POP (%edi); POP (%ebx); ret; CFI_PUSH (%ebx); CFI_PUSH (%edi)
-
-        movl	SRC(%esp), %ecx
-	movl	LEN(%esp), %ebx
-
-	cmp	%eax, %ebx
-	je	L(CalculateLengthOfSrcProlog)
-	sub	%eax, %ebx
-
-	test	%ebx, %ebx
-	jz	L(CalculateLengthOfSrcProlog)
-
-	mov	DST + 4(%esp), %edx
-
-	PUSH	(%edi)
-	add	%eax, %edx
-	mov	%ecx, %edi
-	sub	%eax, %edi
-
-	cmp	$8, %ebx
-	jbe	L(StrncpyExit8Bytes)
-
-	cmpb	$0, (%ecx)
-	jz	L(Exit1)
-	cmpb	$0, 1(%ecx)
-	jz	L(Exit2)
-	cmpb	$0, 2(%ecx)
-	jz	L(Exit3)
-	cmpb	$0, 3(%ecx)
-	jz	L(Exit4)
-	cmpb	$0, 4(%ecx)
-	jz	L(Exit5)
-	cmpb	$0, 5(%ecx)
-	jz	L(Exit6)
-	cmpb	$0, 6(%ecx)
-	jz	L(Exit7)
-	cmpb	$0, 7(%ecx)
-	jz	L(Exit8)
-	cmp	$16, %ebx
-	jb	L(StrncpyExit15Bytes)
-	cmpb	$0, 8(%ecx)
-	jz	L(Exit9)
-	cmpb	$0, 9(%ecx)
-	jz	L(Exit10)
-	cmpb	$0, 10(%ecx)
-	jz	L(Exit11)
-	cmpb	$0, 11(%ecx)
-	jz	L(Exit12)
-	cmpb	$0, 12(%ecx)
-	jz	L(Exit13)
-	cmpb	$0, 13(%ecx)
-	jz	L(Exit14)
-	cmpb	$0, 14(%ecx)
-	jz	L(Exit15)
-	cmpb	$0, 15(%ecx)
-	jz	L(Exit16)
-	cmp	$16, %ebx
-	je	L(StrlcpyExit16)
-
-#define USE_AS_STRNCPY
-#include "ssse3-strcpy-atom.S"
-
-	.p2align 4
-L(CopyFrom1To16Bytes):
-	add	%esi, %edx
-	add	%esi, %ecx
-
-	POP	(%esi)
-	test	%al, %al
-	jz	L(ExitHigh8)
-
-L(CopyFrom1To16BytesLess8):
-	mov	%al, %ah
-	and	$15, %ah
-	jz	L(ExitHigh4)
-
-	test	$0x01, %al
-	jnz	L(Exit1)
-	test	$0x02, %al
-	jnz	L(Exit2)
-	test	$0x04, %al
-	jnz	L(Exit3)
-L(Exit4):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-
-	lea	3(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(ExitHigh4):
-	test	$0x10, %al
-	jnz	L(Exit5)
-	test	$0x20, %al
-	jnz	L(Exit6)
-	test	$0x40, %al
-	jnz	L(Exit7)
-L(Exit8):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-
-	lea	7(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(ExitHigh8):
-	mov	%ah, %al
-	and	$15, %al
-	jz	L(ExitHigh12)
-
-	test	$0x01, %ah
-	jnz	L(Exit9)
-	test	$0x02, %ah
-	jnz	L(Exit10)
-	test	$0x04, %ah
-	jnz	L(Exit11)
-L(Exit12):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	8(%ecx), %eax
-	movl	%eax, 8(%edx)
-
-	lea	11(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(ExitHigh12):
-	test	$0x10, %ah
-	jnz	L(Exit13)
-	test	$0x20, %ah
-	jnz	L(Exit14)
-	test	$0x40, %ah
-	jnz	L(Exit15)
-L(Exit16):
-	movlpd	(%ecx), %xmm0
-	movlpd	8(%ecx), %xmm1
-	movlpd	%xmm0, (%edx)
-	movlpd	%xmm1, 8(%edx)
-
-	lea	15(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	CFI_PUSH(%esi)
-
-	.p2align 4
-L(CopyFrom1To16BytesCase2):
-	add	$16, %ebx
-	add	%esi, %ecx
-	add	%esi, %edx
-
-	POP	(%esi)
-
-	test	%al, %al
-	jz	L(ExitHighCase2)
-
-	cmp	$8, %ebx
-	ja	L(CopyFrom1To16BytesLess8)
-
-	test	$0x01, %al
-	jnz	L(Exit1)
-	cmp	$1, %ebx
-	je	L(StrlcpyExit1)
-	test	$0x02, %al
-	jnz	L(Exit2)
-	cmp	$2, %ebx
-	je	L(StrlcpyExit2)
-	test	$0x04, %al
-	jnz	L(Exit3)
-	cmp	$3, %ebx
-	je	L(StrlcpyExit3)
-	test	$0x08, %al
-	jnz	L(Exit4)
-	cmp	$4, %ebx
-	je	L(StrlcpyExit4)
-	test	$0x10, %al
-	jnz	L(Exit5)
-	cmp	$5, %ebx
-	je	L(StrlcpyExit5)
-	test	$0x20, %al
-	jnz	L(Exit6)
-	cmp	$6, %ebx
-	je	L(StrlcpyExit6)
-	test	$0x40, %al
-	jnz	L(Exit7)
-	cmp	$7, %ebx
-	je	L(StrlcpyExit7)
-	test	$0x80, %al
-	jnz	L(Exit8)
-	jmp	L(StrlcpyExit8)
-
-	.p2align 4
-L(ExitHighCase2):
-	cmp	$8, %ebx
-	jbe	L(CopyFrom1To16BytesLess8Case3)
-
-	test	$0x01, %ah
-	jnz	L(Exit9)
-	cmp	$9, %ebx
-	je	L(StrlcpyExit9)
-	test	$0x02, %ah
-	jnz	L(Exit10)
-	cmp	$10, %ebx
-	je	L(StrlcpyExit10)
-	test	$0x04, %ah
-	jnz	L(Exit11)
-	cmp	$11, %ebx
-	je	L(StrlcpyExit11)
-	test	$0x8, %ah
-	jnz	L(Exit12)
-	cmp	$12, %ebx
-	je	L(StrlcpyExit12)
-	test	$0x10, %ah
-	jnz	L(Exit13)
-	cmp	$13, %ebx
-	je	L(StrlcpyExit13)
-	test	$0x20, %ah
-	jnz	L(Exit14)
-	cmp	$14, %ebx
-	je	L(StrlcpyExit14)
-	test	$0x40, %ah
-	jnz	L(Exit15)
-	cmp	$15, %ebx
-	je	L(StrlcpyExit15)
-	test	$0x80, %ah
-	jnz	L(Exit16)
-	jmp	L(StrlcpyExit16)
-
-	CFI_PUSH(%esi)
-
-	.p2align 4
-L(CopyFrom1To16BytesCase2OrCase3):
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16BytesCase2)
-
-	.p2align 4
-L(CopyFrom1To16BytesCase3):
-	add	$16, %ebx
-	add	%esi, %edx
-	add	%esi, %ecx
-
-	POP	(%esi)
-
-	cmp	$8, %ebx
-	ja	L(ExitHigh8Case3)
-
-L(CopyFrom1To16BytesLess8Case3):
-	cmp	$4, %ebx
-	ja	L(ExitHigh4Case3)
-
-	cmp	$1, %ebx
-	je	L(StrlcpyExit1)
-	cmp	$2, %ebx
-	je	L(StrlcpyExit2)
-	cmp	$3, %ebx
-	je	L(StrlcpyExit3)
-L(StrlcpyExit4):
-	movb	%bh, 3(%edx)
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movb	2(%ecx), %al
-	movb	%al, 2(%edx)
-
-	lea	4(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(ExitHigh4Case3):
-	cmp	$5, %ebx
-	je	L(StrlcpyExit5)
-	cmp	$6, %ebx
-	je	L(StrlcpyExit6)
-	cmp	$7, %ebx
-	je	L(StrlcpyExit7)
-L(StrlcpyExit8):
-	movb	%bh, 7(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	3(%ecx), %eax
-	movl	%eax, 3(%edx)
-
-	lea	8(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(ExitHigh8Case3):
-	cmp	$12, %ebx
-	ja	L(ExitHigh12Case3)
-
-	cmp	$9, %ebx
-	je	L(StrlcpyExit9)
-	cmp	$10, %ebx
-	je	L(StrlcpyExit10)
-	cmp	$11, %ebx
-	je	L(StrlcpyExit11)
-L(StrlcpyExit12):
-	movb	%bh, 11(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	7(%ecx), %eax
-	movl	%eax, 7(%edx)
-
-	lea	12(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(ExitHigh12Case3):
-	cmp	$13, %ebx
-	je	L(StrlcpyExit13)
-	cmp	$14, %ebx
-	je	L(StrlcpyExit14)
-	cmp	$15, %ebx
-	je	L(StrlcpyExit15)
-L(StrlcpyExit16):
-	movb	%bh, 15(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	7(%ecx), %xmm0
-	movlpd	%xmm0, 7(%edx)
-
-	lea	16(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(StrlcpyExit1):
-	movb	%bh, (%edx)
-
-	lea	1(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit1):
-	movb	(%ecx), %al
-	movb	%al, (%edx)
-
-	mov	%ecx, %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit2):
-	movb	%bh, 1(%edx)
-	movb	(%ecx), %al
-	movb	%al, (%edx)
-
-	lea	2(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit2):
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movl	%edi, %eax
-
-	lea	1(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit3):
-	movb	%bh, 2(%edx)
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-
-	lea	3(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit3):
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movb	2(%ecx), %al
-	movb	%al, 2(%edx)
-
-	lea	2(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit5):
-	movb	%bh, 4(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	%edi, %eax
-
-	lea	5(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit5):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movb	4(%ecx), %al
-	movb	%al, 4(%edx)
-
-	lea	4(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit6):
-	movb	%bh, 5(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movb	4(%ecx), %al
-	movb	%al, 4(%edx)
-
-	lea	6(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit6):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movw	4(%ecx), %ax
-	movw	%ax, 4(%edx)
-
-	lea	5(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit7):
-	movb	%bh, 6(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movw	4(%ecx), %ax
-	movw	%ax, 4(%edx)
-
-	lea	7(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit7):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	3(%ecx), %eax
-	movl	%eax, 3(%edx)
-
-	lea	6(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit9):
-	movb	%bh, 8(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-
-	lea	9(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit9):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movb	8(%ecx), %al
-	movb	%al, 8(%edx)
-
-	lea	8(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit10):
-	movb	%bh, 9(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movb	8(%ecx), %al
-	movb	%al, 8(%edx)
-
-	lea	10(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit10):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movw	8(%ecx), %ax
-	movw	%ax, 8(%edx)
-
-	lea	9(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit11):
-	movb	%bh, 10(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movw	8(%ecx), %ax
-	movw	%ax, 8(%edx)
-
-	lea	11(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit11):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	7(%ecx), %eax
-	movl	%eax, 7(%edx)
-
-	lea	10(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit13):
-	movb	%bh, 12(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	8(%ecx), %eax
-	movl	%eax, 8(%edx)
-
-	lea	13(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit13):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	5(%ecx), %xmm0
-	movlpd	%xmm0, 5(%edx)
-
-	lea	12(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit14):
-	movb	%bh, 13(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	5(%ecx), %xmm0
-	movlpd	%xmm0, 5(%edx)
-
-	lea	14(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit14):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	6(%ecx), %xmm0
-	movlpd	%xmm0, 6(%edx)
-
-	lea	13(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit15):
-	movb	%bh, 14(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	6(%ecx), %xmm0
-	movlpd	%xmm0, 6(%edx)
-
-	lea	15(%ecx), %edx
-	mov	%edi, %ecx
-	POP	(%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit15):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	7(%ecx), %xmm0
-	movlpd	%xmm0, 7(%edx)
-
-	lea	14(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrncpyExit15Bytes):
-	cmp	$12, %ebx
-	ja	L(StrncpyExit15Bytes1)
-
-	cmpb	$0, 8(%ecx)
-	jz	L(Exit9)
-	cmp	$9, %ebx
-	je	L(StrlcpyExit9)
-
-	cmpb	$0, 9(%ecx)
-	jz	L(Exit10)
-	cmp	$10, %ebx
-	je	L(StrlcpyExit10)
-
-	cmpb	$0, 10(%ecx)
-	jz	L(Exit11)
-	cmp	$11, %ebx
-	je	L(StrlcpyExit11)
-
-	cmpb	$0, 11(%ecx)
-	jz	L(Exit12)
-	jmp	L(StrlcpyExit12)
-
-	.p2align 4
-L(StrncpyExit15Bytes1):
-	cmpb	$0, 8(%ecx)
-	jz	L(Exit9)
-	cmpb	$0, 9(%ecx)
-	jz	L(Exit10)
-	cmpb	$0, 10(%ecx)
-	jz	L(Exit11)
-	cmpb	$0, 11(%ecx)
-	jz	L(Exit12)
-
-	cmpb	$0, 12(%ecx)
-	jz	L(Exit13)
-	cmp	$13, %ebx
-	je	L(StrlcpyExit13)
-
-	cmpb	$0, 13(%ecx)
-	jz	L(Exit14)
-	cmp	$14, %ebx
-	je	L(StrlcpyExit14)
-
-	cmpb	$0, 14(%ecx)
-	jz	L(Exit15)
-	jmp	L(StrlcpyExit15)
-
-	.p2align 4
-L(StrncpyExit8Bytes):
-	cmp	$4, %ebx
-	ja	L(StrncpyExit8Bytes1)
-
-	cmpb	$0, (%ecx)
-	jz	L(Exit1)
-	cmp	$1, %ebx
-	je	L(StrlcpyExit1)
-
-	cmpb	$0, 1(%ecx)
-	jz	L(Exit2)
-	cmp	$2, %ebx
-	je	L(StrlcpyExit2)
-
-	cmpb	$0, 2(%ecx)
-	jz	L(Exit3)
-	cmp	$3, %ebx
-	je	L(StrlcpyExit3)
-
-	cmpb	$0, 3(%ecx)
-	jz	L(Exit4)
-	jmp	L(StrlcpyExit4)
-
-	.p2align 4
-L(StrncpyExit8Bytes1):
-	cmpb	$0, (%ecx)
-	jz	L(Exit1)
-	cmpb	$0, 1(%ecx)
-	jz	L(Exit2)
-	cmpb	$0, 2(%ecx)
-	jz	L(Exit3)
-	cmpb	$0, 3(%ecx)
-	jz	L(Exit4)
-
-	cmpb	$0, 4(%ecx)
-	jz	L(Exit5)
-	cmp	$5, %ebx
-	je	L(StrlcpyExit5)
-
-	cmpb	$0, 5(%ecx)
-	jz	L(Exit6)
-	cmp	$6, %ebx
-	je	L(StrlcpyExit6)
-
-	cmpb	$0, 6(%ecx)
-	jz	L(Exit7)
-	cmp	$7, %ebx
-	je	L(StrlcpyExit7)
-
-	cmpb	$0, 7(%ecx)
-	jz	L(Exit8)
-	jmp	L(StrlcpyExit8)
-
-	CFI_POP	(%edi)
-
-
-	.p2align 4
-L(Prolog_return_start_len):
-	movl	LEN(%esp), %ebx
-        movl	SRC(%esp), %ecx
-L(CalculateLengthOfSrcProlog):
-	mov	%ecx, %edx
-	sub	%ebx, %ecx
-
-	.p2align 4
-L(CalculateLengthOfSrc):
-	cmpb	$0, (%edx)
-	jz	L(exit_tail0)
-	cmpb	$0, 1(%edx)
-	jz	L(exit_tail1)
-	cmpb	$0, 2(%edx)
-	jz	L(exit_tail2)
-	cmpb	$0, 3(%edx)
-	jz	L(exit_tail3)
-
-	cmpb	$0, 4(%edx)
-	jz	L(exit_tail4)
-	cmpb	$0, 5(%edx)
-	jz	L(exit_tail5)
-	cmpb	$0, 6(%edx)
-	jz	L(exit_tail6)
-	cmpb	$0, 7(%edx)
-	jz	L(exit_tail7)
-
-	cmpb	$0, 8(%edx)
-	jz	L(exit_tail8)
-	cmpb	$0, 9(%edx)
-	jz	L(exit_tail9)
-	cmpb	$0, 10(%edx)
-	jz	L(exit_tail10)
-	cmpb	$0, 11(%edx)
-	jz	L(exit_tail11)
-
-	cmpb	$0, 12(%edx)
-	jz	L(exit_tail12)
-	cmpb	$0, 13(%edx)
-	jz	L(exit_tail13)
-	cmpb	$0, 14(%edx)
-	jz	L(exit_tail14)
-	cmpb	$0, 15(%edx)
-	jz	L(exit_tail15)
-
-	pxor	%xmm0, %xmm0
-	lea	16(%edx), %eax
-	add	$16, %ecx
-	and	$-16, %eax
-
-	pcmpeqb	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	pxor	%xmm1, %xmm1
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	pxor	%xmm2, %xmm2
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	pxor	%xmm3, %xmm3
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	and	$-0x40, %eax
-
-	.p2align 4
-L(aligned_64_loop):
-	movaps	(%eax), %xmm0
-	movaps	16(%eax), %xmm1
-	movaps	32(%eax), %xmm2
-	movaps	48(%eax), %xmm6
-	pminub	%xmm1, %xmm0
-	pminub	%xmm6, %xmm2
-	pminub	%xmm0, %xmm2
-	pcmpeqb	%xmm3, %xmm2
-	pmovmskb %xmm2, %edx
-	lea	64(%eax), %eax
-	test	%edx, %edx
-	jz	L(aligned_64_loop)
-
-	pcmpeqb	-64(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	48(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	%xmm1, %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	-32(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	%xmm6, %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-
-	.p2align 4
-L(exit):
-	sub	%ecx, %eax
-	test	%dl, %dl
-	jz	L(exit_more_8)
-
-	mov	%dl, %cl
-	and	$15, %cl
-	jz	L(exit_more_4)
-	test	$0x01, %dl
-	jnz	L(exit_0)
-	test	$0x02, %dl
-	jnz	L(exit_1)
-	test	$0x04, %dl
-	jnz	L(exit_2)
-	add	$3, %eax
-	RETURN
-
-	.p2align 4
-L(exit_more_4):
-	test	$0x10, %dl
-	jnz	L(exit_4)
-	test	$0x20, %dl
-	jnz	L(exit_5)
-	test	$0x40, %dl
-	jnz	L(exit_6)
-	add	$7, %eax
-	RETURN
-
-	.p2align 4
-L(exit_more_8):
-	mov	%dh, %ch
-	and	$15, %ch
-	jz	L(exit_more_12)
-	test	$0x01, %dh
-	jnz	L(exit_8)
-	test	$0x02, %dh
-	jnz	L(exit_9)
-	test	$0x04, %dh
-	jnz	L(exit_10)
-	add	$11, %eax
-	RETURN
-
-	.p2align 4
-L(exit_more_12):
-	test	$0x10, %dh
-	jnz	L(exit_12)
-	test	$0x20, %dh
-	jnz	L(exit_13)
-	test	$0x40, %dh
-	jnz	L(exit_14)
-	add	$15, %eax
-L(exit_0):
-	RETURN
-
-	.p2align 4
-L(exit_1):
-	add	$1, %eax
-	RETURN
-
-L(exit_2):
-	add	$2, %eax
-	RETURN
-
-L(exit_3):
-	add	$3, %eax
-	RETURN
-
-L(exit_4):
-	add	$4, %eax
-	RETURN
-
-L(exit_5):
-	add	$5, %eax
-	RETURN
-
-L(exit_6):
-	add	$6, %eax
-	RETURN
-
-L(exit_7):
-	add	$7, %eax
-	RETURN
-
-L(exit_8):
-	add	$8, %eax
-	RETURN
-
-L(exit_9):
-	add	$9, %eax
-	RETURN
-
-L(exit_10):
-	add	$10, %eax
-	RETURN
-
-L(exit_11):
-	add	$11, %eax
-	RETURN
-
-L(exit_12):
-	add	$12, %eax
-	RETURN
-
-L(exit_13):
-	add	$13, %eax
-	RETURN
-
-L(exit_14):
-	add	$14, %eax
-	RETURN
-
-L(exit_15):
-	add	$15, %eax
-	RETURN
-
-L(exit_tail0):
-	mov	%edx, %eax
-	sub	%ecx, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail1):
-	lea	1(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail2):
-	lea	2(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail3):
-	lea	3(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail4):
-	lea	4(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail5):
-	lea	5(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail6):
-	lea	6(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail7):
-	lea	7(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail8):
-	lea	8(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail9):
-	lea	9(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail10):
-	lea	10(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail11):
-	lea	11(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail12):
-	lea	12(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail13):
-	lea	13(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail14):
-	lea	14(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail15):
-	lea	15(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-END (strlcat)
diff --git a/libc/arch-x86/string/ssse3-strlcpy-atom.S b/libc/arch-x86/string/ssse3-strlcpy-atom.S
deleted file mode 100644
index cdb17cc53..000000000
--- a/libc/arch-x86/string/ssse3-strlcpy-atom.S
+++ /dev/null
@@ -1,1403 +0,0 @@
-/*
-Copyright (c) 2011, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#define USE_AS_STRNCPY
-#define STRCPY strlcpy
-#define STRLEN strlcpy
-#define USE_AS_STRLCPY
-#include "ssse3-strcpy-atom.S"
-
-	.p2align 4
-L(CopyFrom1To16Bytes):
-	add	%esi, %edx
-	add	%esi, %ecx
-
-	POP	(%esi)
-	test	%al, %al
-	jz	L(ExitHigh8)
-
-L(CopyFrom1To16BytesLess8):
-	mov	%al, %ah
-	and	$15, %ah
-	jz	L(ExitHigh4)
-
-	test	$0x01, %al
-	jnz	L(Exit1)
-	test	$0x02, %al
-	jnz	L(Exit2)
-	test	$0x04, %al
-	jnz	L(Exit3)
-L(Exit4):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-
-	lea	3(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(ExitHigh4):
-	test	$0x10, %al
-	jnz	L(Exit5)
-	test	$0x20, %al
-	jnz	L(Exit6)
-	test	$0x40, %al
-	jnz	L(Exit7)
-L(Exit8):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-
-	lea	7(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(ExitHigh8):
-	mov	%ah, %al
-	and	$15, %al
-	jz	L(ExitHigh12)
-
-	test	$0x01, %ah
-	jnz	L(Exit9)
-	test	$0x02, %ah
-	jnz	L(Exit10)
-	test	$0x04, %ah
-	jnz	L(Exit11)
-L(Exit12):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	8(%ecx), %eax
-	movl	%eax, 8(%edx)
-
-	lea	11(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(ExitHigh12):
-	test	$0x10, %ah
-	jnz	L(Exit13)
-	test	$0x20, %ah
-	jnz	L(Exit14)
-	test	$0x40, %ah
-	jnz	L(Exit15)
-L(Exit16):
-	movlpd	(%ecx), %xmm0
-	movlpd	8(%ecx), %xmm1
-	movlpd	%xmm0, (%edx)
-	movlpd	%xmm1, 8(%edx)
-
-	lea	15(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	CFI_PUSH(%esi)
-
-	.p2align 4
-L(CopyFrom1To16BytesCase2):
-	add	$16, %ebx
-	add	%esi, %ecx
-        add     %esi, %edx
-
-	POP	(%esi)
-
-        test    %al, %al
-        jz      L(ExitHighCase2)
-
-        cmp     $8, %ebx
-        ja      L(CopyFrom1To16BytesLess8)
-
-	test	$0x01, %al
-	jnz	L(Exit1)
-	cmp	$1, %ebx
-	je	L(StrlcpyExit1)
-	test	$0x02, %al
-	jnz	L(Exit2)
-	cmp	$2, %ebx
-	je	L(StrlcpyExit2)
-	test	$0x04, %al
-	jnz	L(Exit3)
-	cmp	$3, %ebx
-	je	L(StrlcpyExit3)
-	test	$0x08, %al
-	jnz	L(Exit4)
-	cmp	$4, %ebx
-	je	L(StrlcpyExit4)
-	test	$0x10, %al
-	jnz	L(Exit5)
-	cmp	$5, %ebx
-	je	L(StrlcpyExit5)
-	test	$0x20, %al
-	jnz	L(Exit6)
-	cmp	$6, %ebx
-	je	L(StrlcpyExit6)
-	test	$0x40, %al
-	jnz	L(Exit7)
-	cmp	$7, %ebx
-	je	L(StrlcpyExit7)
-	test	$0x80, %al
-	jnz	L(Exit8)
-	jmp	L(StrlcpyExit8)
-
-	.p2align 4
-L(ExitHighCase2):
-        cmp     $8, %ebx
-        jbe      L(CopyFrom1To16BytesLess8Case3)
-
-	test	$0x01, %ah
-	jnz	L(Exit9)
-	cmp	$9, %ebx
-	je	L(StrlcpyExit9)
-	test	$0x02, %ah
-	jnz	L(Exit10)
-	cmp	$10, %ebx
-	je	L(StrlcpyExit10)
-	test	$0x04, %ah
-	jnz	L(Exit11)
-	cmp	$11, %ebx
-	je	L(StrlcpyExit11)
-	test	$0x8, %ah
-	jnz	L(Exit12)
-	cmp	$12, %ebx
-	je	L(StrlcpyExit12)
-	test	$0x10, %ah
-	jnz	L(Exit13)
-	cmp	$13, %ebx
-	je	L(StrlcpyExit13)
-	test	$0x20, %ah
-	jnz	L(Exit14)
-	cmp	$14, %ebx
-	je	L(StrlcpyExit14)
-	test	$0x40, %ah
-	jnz	L(Exit15)
-	cmp	$15, %ebx
-	je	L(StrlcpyExit15)
-	test	$0x80, %ah
-	jnz	L(Exit16)
-	jmp	L(StrlcpyExit16)
-
-	CFI_PUSH(%esi)
-
-	.p2align 4
-L(CopyFrom1To16BytesCase2OrCase3):
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16BytesCase2)
-
-	.p2align 4
-L(CopyFrom1To16BytesCase3):
-	add	$16, %ebx
-	add	%esi, %edx
-	add	%esi, %ecx
-
-	POP	(%esi)
-
-	cmp	$8, %ebx
-	ja	L(ExitHigh8Case3)
-
-L(CopyFrom1To16BytesLess8Case3):
-	cmp	$4, %ebx
-	ja	L(ExitHigh4Case3)
-
-	cmp	$1, %ebx
-	je	L(StrlcpyExit1)
-	cmp	$2, %ebx
-	je	L(StrlcpyExit2)
-	cmp	$3, %ebx
-	je	L(StrlcpyExit3)
-L(StrlcpyExit4):
-	movb	%bh, 3(%edx)
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movb	2(%ecx), %al
-	movb	%al, 2(%edx)
-
-	lea	4(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(ExitHigh4Case3):
-	cmp	$5, %ebx
-	je	L(StrlcpyExit5)
-	cmp	$6, %ebx
-	je	L(StrlcpyExit6)
-	cmp	$7, %ebx
-	je	L(StrlcpyExit7)
-L(StrlcpyExit8):
-	movb	%bh, 7(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	3(%ecx), %eax
-	movl	%eax, 3(%edx)
-
-	lea	8(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(ExitHigh8Case3):
-	cmp	$12, %ebx
-	ja	L(ExitHigh12Case3)
-
-	cmp	$9, %ebx
-	je	L(StrlcpyExit9)
-	cmp	$10, %ebx
-	je	L(StrlcpyExit10)
-	cmp	$11, %ebx
-	je	L(StrlcpyExit11)
-L(StrlcpyExit12):
-	movb	%bh, 11(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	7(%ecx), %eax
-	movl	%eax, 7(%edx)
-
-	lea	12(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(ExitHigh12Case3):
-	cmp	$13, %ebx
-	je	L(StrlcpyExit13)
-	cmp	$14, %ebx
-	je	L(StrlcpyExit14)
-	cmp	$15, %ebx
-	je	L(StrlcpyExit15)
-L(StrlcpyExit16):
-	movb	%bh, 15(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	7(%ecx), %xmm0
-	movlpd	%xmm0, 7(%edx)
-
-	lea	16(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(StrlcpyExit1):
-	movb	%bh, (%edx)
-
-	lea	1(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit1):
-	movb	(%ecx), %al
-	movb	%al, (%edx)
-
-	mov	%ecx, %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit2):
-	movb	%bh, 1(%edx)
-	movb	(%ecx), %al
-	movb	%al, (%edx)
-
-	lea	2(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit2):
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movl	%edi, %eax
-
-	lea	1(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit3):
-	movb	%bh, 2(%edx)
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-
-	lea	3(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit3):
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movb	2(%ecx), %al
-	movb	%al, 2(%edx)
-
-	lea	2(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit5):
-	movb	%bh, 4(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	%edi, %eax
-
-	lea	5(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit5):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movb	4(%ecx), %al
-	movb	%al, 4(%edx)
-
-	lea	4(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit6):
-	movb	%bh, 5(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movb	4(%ecx), %al
-	movb	%al, 4(%edx)
-
-	lea	6(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit6):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movw	4(%ecx), %ax
-	movw	%ax, 4(%edx)
-
-	lea	5(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit7):
-	movb	%bh, 6(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movw	4(%ecx), %ax
-	movw	%ax, 4(%edx)
-
-	lea	7(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit7):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	3(%ecx), %eax
-	movl	%eax, 3(%edx)
-
-	lea	6(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit9):
-	movb	%bh, 8(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-
-	lea	9(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit9):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movb	8(%ecx), %al
-	movb	%al, 8(%edx)
-
-	lea	8(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit10):
-	movb	%bh, 9(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movb	8(%ecx), %al
-	movb	%al, 8(%edx)
-
-	lea	10(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit10):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movw	8(%ecx), %ax
-	movw	%ax, 8(%edx)
-
-	lea	9(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit11):
-	movb	%bh, 10(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movw	8(%ecx), %ax
-	movw	%ax, 8(%edx)
-
-	lea	11(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit11):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	7(%ecx), %eax
-	movl	%eax, 7(%edx)
-
-	lea	10(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit13):
-	movb	%bh, 12(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	8(%ecx), %eax
-	movl	%eax, 8(%edx)
-
-	lea	13(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit13):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	5(%ecx), %xmm0
-	movlpd	%xmm0, 5(%edx)
-
-	lea	12(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit14):
-	movb	%bh, 13(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	5(%ecx), %xmm0
-	movlpd	%xmm0, 5(%edx)
-
-	lea	14(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit14):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	6(%ecx), %xmm0
-	movlpd	%xmm0, 6(%edx)
-
-	lea	13(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-	.p2align 4
-L(StrlcpyExit15):
-	movb	%bh, 14(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	6(%ecx), %xmm0
-	movlpd	%xmm0, 6(%edx)
-
-	lea	15(%ecx), %edx
-	mov	%edi, %ecx
-        POP     (%edi)
-	jmp	L(CalculateLengthOfSrc)
-        CFI_PUSH     (%edi)
-
-	.p2align 4
-L(Exit15):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	7(%ecx), %xmm0
-	movlpd	%xmm0, 7(%edx)
-
-	lea	14(%ecx), %eax
-	sub	%edi, %eax
-	RETURN1
-
-        CFI_POP (%edi)
-
-	.p2align 4
-L(StrlcpyExit0):
-	movl	$0, %eax
-	RETURN
-
-	.p2align 4
-L(StrncpyExit15Bytes):
-	cmp	$12, %ebx
-	ja	L(StrncpyExit15Bytes1)
-
-	cmpb	$0, 8(%ecx)
-	jz	L(ExitTail9)
-	cmp	$9, %ebx
-	je	L(StrlcpyExitTail9)
-
-	cmpb	$0, 9(%ecx)
-	jz	L(ExitTail10)
-	cmp	$10, %ebx
-	je	L(StrlcpyExitTail10)
-
-	cmpb	$0, 10(%ecx)
-	jz	L(ExitTail11)
-	cmp	$11, %ebx
-	je	L(StrlcpyExitTail11)
-
-	cmpb	$0, 11(%ecx)
-	jz	L(ExitTail12)
-
-	movb	%bh, 11(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	7(%ecx), %eax
-	movl	%eax, 7(%edx)
-
-	lea	12(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(StrncpyExit15Bytes1):
-	cmpb	$0, 8(%ecx)
-	jz	L(ExitTail9)
-	cmpb	$0, 9(%ecx)
-	jz	L(ExitTail10)
-	cmpb	$0, 10(%ecx)
-	jz	L(ExitTail11)
-	cmpb	$0, 11(%ecx)
-	jz	L(ExitTail12)
-
-	cmpb	$0, 12(%ecx)
-	jz	L(ExitTail13)
-	cmp	$13, %ebx
-	je	L(StrlcpyExitTail13)
-
-	cmpb	$0, 13(%ecx)
-	jz	L(ExitTail14)
-	cmp	$14, %ebx
-	je	L(StrlcpyExitTail14)
-
-	cmpb	$0, 14(%ecx)
-	jz	L(ExitTail15)
-
-	movb	%bh, 14(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	6(%ecx), %xmm0
-	movlpd	%xmm0, 6(%edx)
-
-	lea	15(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(StrncpyExit8Bytes):
-	cmp	$4, %ebx
-	ja	L(StrncpyExit8Bytes1)
-
-	test	%ebx, %ebx
-	jz	L(StrlcpyExitTail0)
-
-	cmpb	$0, (%ecx)
-	jz	L(ExitTail1)
-	cmp	$1, %ebx
-	je	L(StrlcpyExitTail1)
-
-	cmpb	$0, 1(%ecx)
-	jz	L(ExitTail2)
-	cmp	$2, %ebx
-	je	L(StrlcpyExitTail2)
-
-	cmpb	$0, 2(%ecx)
-	jz	L(ExitTail3)
-	cmp	$3, %ebx
-	je	L(StrlcpyExitTail3)
-
-	cmpb	$0, 3(%ecx)
-	jz	L(ExitTail4)
-
-	movb	%bh, 3(%edx)
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movb	2(%ecx), %al
-	movb	%al, 2(%edx)
-
-	lea	4(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(StrncpyExit8Bytes1):
-	cmpb	$0, (%ecx)
-	jz	L(ExitTail1)
-	cmpb	$0, 1(%ecx)
-	jz	L(ExitTail2)
-	cmpb	$0, 2(%ecx)
-	jz	L(ExitTail3)
-	cmpb	$0, 3(%ecx)
-	jz	L(ExitTail4)
-
-	cmpb	$0, 4(%ecx)
-	jz	L(ExitTail5)
-	cmp	$5, %ebx
-	je	L(StrlcpyExitTail5)
-
-	cmpb	$0, 5(%ecx)
-	jz	L(ExitTail6)
-	cmp	$6, %ebx
-	je	L(StrlcpyExitTail6)
-
-	cmpb	$0, 6(%ecx)
-	jz	L(ExitTail7)
-	cmp	$7, %ebx
-	je	L(StrlcpyExitTail7)
-
-	cmpb	$0, 7(%ecx)
-	jz	L(ExitTail8)
-
-	movb	%bh, 7(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	3(%ecx), %eax
-	movl	%eax, 3(%edx)
-
-	lea	8(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(StrlcpyExitTail0):
-	mov	%ecx, %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(StrlcpyExitTail1):
-	movb	%bh, (%edx)
-
-	lea	1(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail1):
-	movb	(%ecx), %al
-	movb	%al, (%edx)
-
-	mov	$0, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail2):
-	movb	%bh, 1(%edx)
-	movb	(%ecx), %al
-	movb	%al, (%edx)
-
-	lea	2(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail2):
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movl	%edx, %eax
-
-	mov	$1, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail3):
-	movb	%bh, 2(%edx)
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-
-	lea	3(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail3):
-	movw	(%ecx), %ax
-	movw	%ax, (%edx)
-	movb	2(%ecx), %al
-	movb	%al, 2(%edx)
-
-	mov	$2, %eax
-	RETURN
-
-	.p2align 4
-L(ExitTail4):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-
-	mov	$3, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail5):
-	movb	%bh, 4(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	%edx, %eax
-
-	lea	5(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail5):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movb	4(%ecx), %al
-	movb	%al, 4(%edx)
-
-	mov	$4, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail6):
-	movb	%bh, 5(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movb	4(%ecx), %al
-	movb	%al, 4(%edx)
-
-	lea	6(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail6):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movw	4(%ecx), %ax
-	movw	%ax, 4(%edx)
-
-	mov	$5, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail7):
-	movb	%bh, 6(%edx)
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movw	4(%ecx), %ax
-	movw	%ax, 4(%edx)
-
-	lea	7(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail7):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	3(%ecx), %eax
-	movl	%eax, 3(%edx)
-
-	mov	$6, %eax
-	RETURN
-
-	.p2align 4
-L(ExitTail8):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-
-	mov	$7, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail9):
-	movb	%bh, 8(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-
-	lea	9(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail9):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movb	8(%ecx), %al
-	movb	%al, 8(%edx)
-
-	mov	$8, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail10):
-	movb	%bh, 9(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movb	8(%ecx), %al
-	movb	%al, 8(%edx)
-
-	lea	10(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail10):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movw	8(%ecx), %ax
-	movw	%ax, 8(%edx)
-
-	mov	$9, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail11):
-	movb	%bh, 10(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movw	8(%ecx), %ax
-	movw	%ax, 8(%edx)
-
-	lea	11(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail11):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	7(%ecx), %eax
-	movl	%eax, 7(%edx)
-
-	mov	$10, %eax
-	RETURN
-
-	.p2align 4
-L(ExitTail12):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	8(%ecx), %eax
-	movl	%eax, 8(%edx)
-
-	mov	$11, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail13):
-	movb	%bh, 12(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	8(%ecx), %eax
-	movl	%eax, 8(%edx)
-
-	lea	13(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail13):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	5(%ecx), %xmm0
-	movlpd	%xmm0, 5(%edx)
-
-	mov	$12, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail14):
-	movb	%bh, 13(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	5(%ecx), %xmm0
-	movlpd	%xmm0, 5(%edx)
-
-	lea	14(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail14):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	6(%ecx), %xmm0
-	movlpd	%xmm0, 6(%edx)
-
-	mov	$13, %eax
-	RETURN
-
-	.p2align 4
-L(ExitTail15):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	7(%ecx), %xmm0
-	movlpd	%xmm0, 7(%edx)
-
-	mov	$14, %eax
-	RETURN
-
-	.p2align 4
-L(StrlcpyExitTail16):
-	movb	%bh, 15(%edx)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movlpd	7(%ecx), %xmm0
-	movlpd	%xmm0, 7(%edx)
-
-	lea	16(%ecx), %edx
-	jmp	L(CalculateLengthOfSrc)
-
-	.p2align 4
-L(ExitTail16):
-	movlpd	(%ecx), %xmm0
-	movlpd	8(%ecx), %xmm1
-	movlpd	%xmm0, (%edx)
-	movlpd	%xmm1, 8(%edx)
-
-	mov	$15, %eax
-	RETURN
-
-	.p2align 4
-L(CalculateLengthOfSrc):
-	xor	%eax, %eax
-	cmpb	$0, (%edx)
-	jz	L(exit_tail0)
-	cmpb	$0, 1(%edx)
-	jz	L(exit_tail1)
-	cmpb	$0, 2(%edx)
-	jz	L(exit_tail2)
-	cmpb	$0, 3(%edx)
-	jz	L(exit_tail3)
-
-	cmpb	$0, 4(%edx)
-	jz	L(exit_tail4)
-	cmpb	$0, 5(%edx)
-	jz	L(exit_tail5)
-	cmpb	$0, 6(%edx)
-	jz	L(exit_tail6)
-	cmpb	$0, 7(%edx)
-	jz	L(exit_tail7)
-
-	cmpb	$0, 8(%edx)
-	jz	L(exit_tail8)
-	cmpb	$0, 9(%edx)
-	jz	L(exit_tail9)
-	cmpb	$0, 10(%edx)
-	jz	L(exit_tail10)
-	cmpb	$0, 11(%edx)
-	jz	L(exit_tail11)
-
-	cmpb	$0, 12(%edx)
-	jz	L(exit_tail12)
-	cmpb	$0, 13(%edx)
-	jz	L(exit_tail13)
-	cmpb	$0, 14(%edx)
-	jz	L(exit_tail14)
-	cmpb	$0, 15(%edx)
-	jz	L(exit_tail15)
-
-	pxor	%xmm0, %xmm0
-	lea	16(%edx), %eax
-	add	$16, %ecx
-	and	$-16, %eax
-
-	pcmpeqb	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	pxor	%xmm1, %xmm1
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	pxor	%xmm2, %xmm2
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	pxor	%xmm3, %xmm3
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm0
-	pmovmskb %xmm0, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm1
-	pmovmskb %xmm1, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm2
-	pmovmskb %xmm2, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	16(%eax), %eax
-	test	%edx, %edx
-	jnz	L(exit)
-
-	and	$-0x40, %eax
-
-	.p2align 4
-L(aligned_64_loop):
-	movaps	(%eax), %xmm0
-	movaps	16(%eax), %xmm1
-	movaps	32(%eax), %xmm2
-	movaps	48(%eax), %xmm6
-	pminub	%xmm1, %xmm0
-	pminub	%xmm6, %xmm2
-	pminub	%xmm0, %xmm2
-	pcmpeqb	%xmm3, %xmm2
-	pmovmskb %xmm2, %edx
-	lea	64(%eax), %eax
-	test	%edx, %edx
-	jz	L(aligned_64_loop)
-
-	pcmpeqb	-64(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	48(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	%xmm1, %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	-32(%eax), %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-	test	%edx, %edx
-	jnz	L(exit)
-
-	pcmpeqb	%xmm6, %xmm3
-	pmovmskb %xmm3, %edx
-	lea	-16(%ecx), %ecx
-
-	.p2align 4
-L(exit):
-	sub	%ecx, %eax
-	test	%dl, %dl
-	jz	L(exit_more_8)
-
-	mov	%dl, %cl
-	and	$15, %cl
-	jz	L(exit_more_4)
-	test	$0x01, %dl
-	jnz	L(exit_0)
-	test	$0x02, %dl
-	jnz	L(exit_1)
-	test	$0x04, %dl
-	jnz	L(exit_2)
-	add	$3, %eax
-	RETURN
-
-	.p2align 4
-L(exit_more_4):
-	test	$0x10, %dl
-	jnz	L(exit_4)
-	test	$0x20, %dl
-	jnz	L(exit_5)
-	test	$0x40, %dl
-	jnz	L(exit_6)
-	add	$7, %eax
-	RETURN
-
-	.p2align 4
-L(exit_more_8):
-	mov	%dh, %ch
-	and	$15, %ch
-	jz	L(exit_more_12)
-	test	$0x01, %dh
-	jnz	L(exit_8)
-	test	$0x02, %dh
-	jnz	L(exit_9)
-	test	$0x04, %dh
-	jnz	L(exit_10)
-	add	$11, %eax
-	RETURN
-
-	.p2align 4
-L(exit_more_12):
-	test	$0x10, %dh
-	jnz	L(exit_12)
-	test	$0x20, %dh
-	jnz	L(exit_13)
-	test	$0x40, %dh
-	jnz	L(exit_14)
-	add	$15, %eax
-L(exit_0):
-	RETURN
-
-	.p2align 4
-L(exit_1):
-	add	$1, %eax
-	RETURN
-
-L(exit_2):
-	add	$2, %eax
-	RETURN
-
-L(exit_3):
-	add	$3, %eax
-	RETURN
-
-L(exit_4):
-	add	$4, %eax
-	RETURN
-
-L(exit_5):
-	add	$5, %eax
-	RETURN
-
-L(exit_6):
-	add	$6, %eax
-	RETURN
-
-L(exit_7):
-	add	$7, %eax
-	RETURN
-
-L(exit_8):
-	add	$8, %eax
-	RETURN
-
-L(exit_9):
-	add	$9, %eax
-	RETURN
-
-L(exit_10):
-	add	$10, %eax
-	RETURN
-
-L(exit_11):
-	add	$11, %eax
-	RETURN
-
-L(exit_12):
-	add	$12, %eax
-	RETURN
-
-L(exit_13):
-	add	$13, %eax
-	RETURN
-
-L(exit_14):
-	add	$14, %eax
-	RETURN
-
-L(exit_15):
-	add	$15, %eax
-	RETURN
-
-L(exit_tail0):
-	mov	%edx, %eax
-	sub	%ecx, %eax
-	RETURN
-
-	.p2align 4
-L(exit_tail1):
-	lea	1(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail2):
-	lea	2(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail3):
-	lea	3(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail4):
-	lea	4(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail5):
-	lea	5(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail6):
-	lea	6(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail7):
-	lea	7(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail8):
-	lea	8(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail9):
-	lea	9(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail10):
-	lea	10(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail11):
-	lea	11(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail12):
-	lea	12(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail13):
-	lea	13(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail14):
-	lea	14(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-L(exit_tail15):
-	lea	15(%edx), %eax
-	sub	%ecx, %eax
-	RETURN
-
-END (STRCPY)
-
diff --git a/libc/arch-x86/string/ssse3-wcscat-atom.S b/libc/arch-x86/string/ssse3-wcscat-atom.S
deleted file mode 100644
index 8a389a378..000000000
--- a/libc/arch-x86/string/ssse3-wcscat-atom.S
+++ /dev/null
@@ -1,114 +0,0 @@
-/*
-Copyright (c) 2011 Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef L
-# define L(label)	.L##label
-#endif
-
-#ifndef cfi_startproc
-# define cfi_startproc                  .cfi_startproc
-#endif
-
-#ifndef cfi_endproc
-# define cfi_endproc                    .cfi_endproc
-#endif
-
-#ifndef cfi_rel_offset
-# define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-#endif
-
-#ifndef cfi_restore
-# define cfi_restore(reg)	.cfi_restore reg
-#endif
-
-#ifndef cfi_adjust_cfa_offset
-# define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-#endif
-
-#ifndef ENTRY
-# define ENTRY(name)	\
-	.type name,  @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-#endif
-
-#ifndef END
-# define END(name)	\
-	cfi_endproc;	\
-	.size name, .-name
-#endif
-
-#define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-#define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-#define PUSH(REG)	pushl REG;	CFI_PUSH (REG)
-#define POP(REG)	popl REG;	CFI_POP (REG)
-
-#define PARMS  4
-#define STR1  PARMS+4
-#define STR2  STR1+4
-
-#define USE_AS_WCSCAT
-
-.text
-ENTRY (wcscat)
-	PUSH    (%edi)
-	mov	STR1(%esp), %edi
-	mov	%edi, %edx
-
-#define RETURN  jmp L(WcscpyAtom)
-#include "sse2-wcslen-atom.S"
-
-L(WcscpyAtom):
-	shl	$2, %eax
-	mov	STR2(%esp), %ecx
-	lea	(%edi, %eax), %edx
-
-	cmpl	$0, (%ecx)
-	jz	L(Exit4)
-	cmpl	$0, 4(%ecx)
-	jz	L(Exit8)
-	cmpl	$0, 8(%ecx)
-	jz	L(Exit12)
-	cmpl	$0, 12(%ecx)
-	jz	L(Exit16)
-
-#undef RETURN
-#define RETURN  POP(%edi);	ret;	CFI_PUSH(%edi)
-#include "ssse3-wcscpy-atom.S"
-
-END (wcscat)
diff --git a/libc/arch-x86/string/ssse3-wcscpy-atom.S b/libc/arch-x86/string/ssse3-wcscpy-atom.S
deleted file mode 100644
index 27cb61e7b..000000000
--- a/libc/arch-x86/string/ssse3-wcscpy-atom.S
+++ /dev/null
@@ -1,652 +0,0 @@
-/*
-Copyright (c) 2011, Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#ifndef USE_AS_WCSCAT
-
-# ifndef L
-#  define L(label)	.L##label
-# endif
-
-# ifndef cfi_startproc
-#  define cfi_startproc	.cfi_startproc
-# endif
-
-# ifndef cfi_endproc
-#  define cfi_endproc	.cfi_endproc
-# endif
-
-# ifndef cfi_rel_offset
-#  define cfi_rel_offset(reg, off)	.cfi_rel_offset reg, off
-# endif
-
-# ifndef cfi_restore
-#  define cfi_restore(reg)	.cfi_restore reg
-# endif
-
-# ifndef cfi_adjust_cfa_offset
-#  define cfi_adjust_cfa_offset(off)	.cfi_adjust_cfa_offset off
-# endif
-
-# ifndef ENTRY
-#  define ENTRY(name)	\
-	.type name, @function;	\
-	.globl name;	\
-	.p2align 4;	\
-name:	\
-	cfi_startproc
-# endif
-
-# ifndef END
-#  define END(name)	\
-	cfi_endproc;	\
-	.size name, .-name
-# endif
-
-# define CFI_PUSH(REG)	\
-	cfi_adjust_cfa_offset (4);	\
-	cfi_rel_offset (REG, 0)
-
-# define CFI_POP(REG)	\
-	cfi_adjust_cfa_offset (-4);	\
-	cfi_restore (REG)
-
-# define PUSH(REG)	pushl REG; CFI_PUSH (REG)
-# define POP(REG)	popl REG; CFI_POP (REG)
-
-# define PARMS	4
-# define RETURN	POP (%edi); ret; CFI_PUSH (%edi)
-
-# define STR1	PARMS
-# define STR2	STR1+4
-# define LEN	STR2+4
-
-.text
-ENTRY (wcscpy)
-	mov	STR1(%esp), %edx
-	mov	STR2(%esp), %ecx
-
-	cmpl	$0, (%ecx)
-	jz	L(ExitTail4)
-	cmpl	$0, 4(%ecx)
-	jz	L(ExitTail8)
-	cmpl	$0, 8(%ecx)
-	jz	L(ExitTail12)
-	cmpl	$0, 12(%ecx)
-	jz	L(ExitTail16)
-
-	PUSH	(%edi)
-	mov	%edx, %edi
-#endif
-	PUSH	(%esi)
-	lea	16(%ecx), %esi
-
-	and	$-16, %esi
-
-	pxor	%xmm0, %xmm0
-	pcmpeqd	(%esi), %xmm0
-	movdqu	(%ecx), %xmm1
-	movdqu	%xmm1, (%edx)
-
-	pmovmskb %xmm0, %eax
-	sub	%ecx, %esi
-
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	mov	%edx, %eax
-	lea	16(%edx), %edx
-	and	$-16, %edx
-	sub	%edx, %eax
-
-	sub	%eax, %ecx
-	mov	%ecx, %eax
-	and	$0xf, %eax
-	mov	$0, %esi
-
-	jz	L(Align16Both)
-	cmp	$4, %eax
-	je	L(Shl4)
-	cmp	$8, %eax
-	je	L(Shl8)
-	jmp	L(Shl12)
-
-L(Align16Both):
-	movaps	(%ecx), %xmm1
-	movaps	16(%ecx), %xmm2
-	movaps	%xmm1, (%edx)
-	pcmpeqd	%xmm2, %xmm0
-	pmovmskb %xmm0, %eax
-	lea	16(%esi), %esi
-
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	movaps	16(%ecx, %esi), %xmm3
-	movaps	%xmm2, (%edx, %esi)
-	pcmpeqd	%xmm3, %xmm0
-	pmovmskb %xmm0, %eax
-	lea	16(%esi), %esi
-
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	movaps	16(%ecx, %esi), %xmm4
-	movaps	%xmm3, (%edx, %esi)
-	pcmpeqd	%xmm4, %xmm0
-	pmovmskb %xmm0, %eax
-	lea	16(%esi), %esi
-
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	movaps	16(%ecx, %esi), %xmm1
-	movaps	%xmm4, (%edx, %esi)
-	pcmpeqd	%xmm1, %xmm0
-	pmovmskb %xmm0, %eax
-	lea	16(%esi), %esi
-
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	movaps	16(%ecx, %esi), %xmm2
-	movaps	%xmm1, (%edx, %esi)
-	pcmpeqd	%xmm2, %xmm0
-	pmovmskb %xmm0, %eax
-	lea	16(%esi), %esi
-
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	movaps	16(%ecx, %esi), %xmm3
-	movaps	%xmm2, (%edx, %esi)
-	pcmpeqd	%xmm3, %xmm0
-	pmovmskb %xmm0, %eax
-	lea	16(%esi), %esi
-
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	movaps	%xmm3, (%edx, %esi)
-	mov	%ecx, %eax
-	lea	16(%ecx, %esi), %ecx
-	and	$-0x40, %ecx
-	sub	%ecx, %eax
-	sub	%eax, %edx
-
-	mov	$-0x40, %esi
-
-L(Aligned64Loop):
-	movaps	(%ecx), %xmm2
-	movaps	32(%ecx), %xmm3
-	movaps	%xmm2, %xmm4
-	movaps	16(%ecx), %xmm5
-	movaps	%xmm3, %xmm6
-	movaps	48(%ecx), %xmm7
-	pminub	%xmm5, %xmm2
-	pminub	%xmm7, %xmm3
-	pminub	%xmm2, %xmm3
-	lea	64(%edx), %edx
-	pcmpeqd	%xmm0, %xmm3
-	lea	64(%ecx), %ecx
-	pmovmskb %xmm3, %eax
-
-	test	%eax, %eax
-	jnz	L(Aligned64Leave)
-	movaps	%xmm4, -64(%edx)
-	movaps	%xmm5, -48(%edx)
-	movaps	%xmm6, -32(%edx)
-	movaps	%xmm7, -16(%edx)
-	jmp	L(Aligned64Loop)
-
-L(Aligned64Leave):
-	pcmpeqd	%xmm4, %xmm0
-	pmovmskb %xmm0, %eax
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	pcmpeqd	%xmm5, %xmm0
-	pmovmskb %xmm0, %eax
-	movaps	%xmm4, -64(%edx)
-	lea	16(%esi), %esi
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	pcmpeqd	%xmm6, %xmm0
-	pmovmskb %xmm0, %eax
-	movaps	%xmm5, -48(%edx)
-	lea	16(%esi), %esi
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	movaps	%xmm6, -32(%edx)
-	pcmpeqd	%xmm7, %xmm0
-	pmovmskb %xmm0, %eax
-	lea	16(%esi), %esi
-	test	%eax, %eax
-	jnz	L(CopyFrom1To16Bytes)
-
-	mov	$-0x40, %esi
-	movaps	%xmm7, -16(%edx)
-	jmp	L(Aligned64Loop)
-
-	.p2align 4
-L(Shl4):
-	movaps	-4(%ecx), %xmm1
-	movaps	12(%ecx), %xmm2
-L(Shl4Start):
-	pcmpeqd	%xmm2, %xmm0
-	pmovmskb %xmm0, %eax
-	movaps	%xmm2, %xmm3
-
-	test	%eax, %eax
-	jnz	L(Shl4LoopExit)
-
-	palignr	$4, %xmm1, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	28(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-	movaps	%xmm2, %xmm1
-
-	test	%eax, %eax
-	jnz	L(Shl4LoopExit)
-
-	palignr	$4, %xmm3, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	28(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-	movaps	%xmm2, %xmm3
-
-	test	%eax, %eax
-	jnz	L(Shl4LoopExit)
-
-	palignr	$4, %xmm1, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	28(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-
-	test	%eax, %eax
-	jnz	L(Shl4LoopExit)
-
-	palignr	$4, %xmm3, %xmm2
-	movaps	%xmm2, (%edx)
-	lea	28(%ecx), %ecx
-	lea	16(%edx), %edx
-
-	mov	%ecx, %eax
-	and	$-0x40, %ecx
-	sub	%ecx, %eax
-	lea	-12(%ecx), %ecx
-	sub	%eax, %edx
-
-	movaps	-4(%ecx), %xmm1
-
-L(Shl4LoopStart):
-	movaps	12(%ecx), %xmm2
-	movaps	28(%ecx), %xmm3
-	movaps	%xmm3, %xmm6
-	movaps	44(%ecx), %xmm4
-	movaps	%xmm4, %xmm7
-	movaps	60(%ecx), %xmm5
-	pminub	%xmm2, %xmm6
-	pminub	%xmm5, %xmm7
-	pminub	%xmm6, %xmm7
-	pcmpeqd	%xmm0, %xmm7
-	pmovmskb %xmm7, %eax
-	movaps	%xmm5, %xmm7
-	palignr	$4, %xmm4, %xmm5
-	palignr	$4, %xmm3, %xmm4
-	test	%eax, %eax
-	jnz	L(Shl4Start)
-
-	palignr	$4, %xmm2, %xmm3
-	lea	64(%ecx), %ecx
-	palignr	$4, %xmm1, %xmm2
-	movaps	%xmm7, %xmm1
-	movaps	%xmm5, 48(%edx)
-	movaps	%xmm4, 32(%edx)
-	movaps	%xmm3, 16(%edx)
-	movaps	%xmm2, (%edx)
-	lea	64(%edx), %edx
-	jmp	L(Shl4LoopStart)
-
-L(Shl4LoopExit):
-	movlpd	(%ecx), %xmm0
-	movl	8(%ecx), %esi
-	movlpd	%xmm0, (%edx)
-	movl	%esi, 8(%edx)
-	POP	(%esi)
-	add	$12, %edx
-	add	$12, %ecx
-	test	%al, %al
-	jz	L(ExitHigh)
-	test	$0x01, %al
-	jnz	L(Exit4)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	%edi, %eax
-	RETURN
-
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(Shl8):
-	movaps	-8(%ecx), %xmm1
-	movaps	8(%ecx), %xmm2
-L(Shl8Start):
-	pcmpeqd	%xmm2, %xmm0
-	pmovmskb %xmm0, %eax
-	movaps	%xmm2, %xmm3
-
-	test	%eax, %eax
-	jnz	L(Shl8LoopExit)
-
-	palignr	$8, %xmm1, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	24(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-	movaps	%xmm2, %xmm1
-
-	test	%eax, %eax
-	jnz	L(Shl8LoopExit)
-
-	palignr	$8, %xmm3, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	24(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-	movaps	%xmm2, %xmm3
-
-	test	%eax, %eax
-	jnz	L(Shl8LoopExit)
-
-	palignr	$8, %xmm1, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	24(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-
-	test	%eax, %eax
-	jnz	L(Shl8LoopExit)
-
-	palignr	$8, %xmm3, %xmm2
-	movaps	%xmm2, (%edx)
-	lea	24(%ecx), %ecx
-	lea	16(%edx), %edx
-
-	mov	%ecx, %eax
-	and	$-0x40, %ecx
-	sub	%ecx, %eax
-	lea	-8(%ecx), %ecx
-	sub	%eax, %edx
-
-	movaps	-8(%ecx), %xmm1
-
-L(Shl8LoopStart):
-	movaps	8(%ecx), %xmm2
-	movaps	24(%ecx), %xmm3
-	movaps	%xmm3, %xmm6
-	movaps	40(%ecx), %xmm4
-	movaps	%xmm4, %xmm7
-	movaps	56(%ecx), %xmm5
-	pminub	%xmm2, %xmm6
-	pminub	%xmm5, %xmm7
-	pminub	%xmm6, %xmm7
-	pcmpeqd	%xmm0, %xmm7
-	pmovmskb %xmm7, %eax
-	movaps	%xmm5, %xmm7
-	palignr	$8, %xmm4, %xmm5
-	palignr	$8, %xmm3, %xmm4
-	test	%eax, %eax
-	jnz	L(Shl8Start)
-
-	palignr	$8, %xmm2, %xmm3
-	lea	64(%ecx), %ecx
-	palignr	$8, %xmm1, %xmm2
-	movaps	%xmm7, %xmm1
-	movaps	%xmm5, 48(%edx)
-	movaps	%xmm4, 32(%edx)
-	movaps	%xmm3, 16(%edx)
-	movaps	%xmm2, (%edx)
-	lea	64(%edx), %edx
-	jmp	L(Shl8LoopStart)
-
-L(Shl8LoopExit):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	POP	(%esi)
-	add	$8, %edx
-	add	$8, %ecx
-	test	%al, %al
-	jz	L(ExitHigh)
-	test	$0x01, %al
-	jnz	L(Exit4)
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	%edi, %eax
-	RETURN
-
-	CFI_PUSH	(%esi)
-
-	.p2align 4
-L(Shl12):
-	movaps	-12(%ecx), %xmm1
-	movaps	4(%ecx), %xmm2
-L(Shl12Start):
-	pcmpeqd	%xmm2, %xmm0
-	pmovmskb %xmm0, %eax
-	movaps	%xmm2, %xmm3
-
-	test	%eax, %eax
-	jnz	L(Shl12LoopExit)
-
-	palignr	$12, %xmm1, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	20(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-	movaps	%xmm2, %xmm1
-
-	test	%eax, %eax
-	jnz	L(Shl12LoopExit)
-
-	palignr	$12, %xmm3, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	20(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-	movaps	%xmm2, %xmm3
-
-	test	%eax, %eax
-	jnz	L(Shl12LoopExit)
-
-	palignr	$12, %xmm1, %xmm2
-	movaps	%xmm2, (%edx)
-	movaps	20(%ecx), %xmm2
-
-	pcmpeqd	%xmm2, %xmm0
-	lea	16(%edx), %edx
-	pmovmskb %xmm0, %eax
-	lea	16(%ecx), %ecx
-
-	test	%eax, %eax
-	jnz	L(Shl12LoopExit)
-
-	palignr	$12, %xmm3, %xmm2
-	movaps	%xmm2, (%edx)
-	lea	20(%ecx), %ecx
-	lea	16(%edx), %edx
-
-	mov	%ecx, %eax
-	and	$-0x40, %ecx
-	sub	%ecx, %eax
-	lea	-4(%ecx), %ecx
-	sub	%eax, %edx
-
-	movaps	-12(%ecx), %xmm1
-
-L(Shl12LoopStart):
-	movaps	4(%ecx), %xmm2
-	movaps	20(%ecx), %xmm3
-	movaps	%xmm3, %xmm6
-	movaps	36(%ecx), %xmm4
-	movaps	%xmm4, %xmm7
-	movaps	52(%ecx), %xmm5
-	pminub	%xmm2, %xmm6
-	pminub	%xmm5, %xmm7
-	pminub	%xmm6, %xmm7
-	pcmpeqd	%xmm0, %xmm7
-	pmovmskb %xmm7, %eax
-	movaps	%xmm5, %xmm7
-	palignr	$12, %xmm4, %xmm5
-	palignr	$12, %xmm3, %xmm4
-	test	%eax, %eax
-	jnz	L(Shl12Start)
-
-	palignr	$12, %xmm2, %xmm3
-	lea	64(%ecx), %ecx
-	palignr	$12, %xmm1, %xmm2
-	movaps	%xmm7, %xmm1
-	movaps	%xmm5, 48(%edx)
-	movaps	%xmm4, 32(%edx)
-	movaps	%xmm3, 16(%edx)
-	movaps	%xmm2, (%edx)
-	lea	64(%edx), %edx
-	jmp	L(Shl12LoopStart)
-
-L(Shl12LoopExit):
-	movl	(%ecx), %esi
-	movl	%esi, (%edx)
-	mov	$4, %esi
-
-	.p2align 4
-L(CopyFrom1To16Bytes):
-	add	%esi, %edx
-	add	%esi, %ecx
-
-	POP	(%esi)
-	test	%al, %al
-	jz	L(ExitHigh)
-	test	$0x01, %al
-	jnz	L(Exit4)
-L(Exit8):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	%edi, %eax
-	RETURN
-
-	.p2align 4
-L(ExitHigh):
-	test	$0x01, %ah
-	jnz	L(Exit12)
-L(Exit16):
-	movdqu	(%ecx), %xmm0
-	movdqu	%xmm0, (%edx)
-	movl	%edi, %eax
-	RETURN
-
-	.p2align 4
-L(Exit4):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	%edi, %eax
-	RETURN
-
-	.p2align 4
-L(Exit12):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	8(%ecx), %eax
-	movl	%eax, 8(%edx)
-	movl	%edi, %eax
-	RETURN
-
-CFI_POP	(%edi)
-
-	.p2align 4
-L(ExitTail4):
-	movl	(%ecx), %eax
-	movl	%eax, (%edx)
-	movl	%edx, %eax
-	ret
-
-	.p2align 4
-L(ExitTail8):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	%edx, %eax
-	ret
-
-	.p2align 4
-L(ExitTail12):
-	movlpd	(%ecx), %xmm0
-	movlpd	%xmm0, (%edx)
-	movl	8(%ecx), %eax
-	movl	%eax, 8(%edx)
-	movl	%edx, %eax
-	ret
-
-	.p2align 4
-L(ExitTail16):
-	movdqu	(%ecx), %xmm0
-	movdqu	%xmm0, (%edx)
-	movl	%edx, %eax
-	ret
-
-#ifndef USE_AS_WCSCAT
-END (wcscpy)
-#endif
diff --git a/libc/arch-x86/string/ssse3-wmemcmp-atom.S b/libc/arch-x86/string/ssse3-wmemcmp-atom.S
deleted file mode 100644
index a81b78bca..000000000
--- a/libc/arch-x86/string/ssse3-wmemcmp-atom.S
+++ /dev/null
@@ -1,35 +0,0 @@
-/*
-Copyright (c) 2011, 2012, 2013 Intel Corporation
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions are met:
-
-    * Redistributions of source code must retain the above copyright notice,
-    * this list of conditions and the following disclaimer.
-
-    * Redistributions in binary form must reproduce the above copyright notice,
-    * this list of conditions and the following disclaimer in the documentation
-    * and/or other materials provided with the distribution.
-
-    * Neither the name of Intel Corporation nor the names of its contributors
-    * may be used to endorse or promote products derived from this software
-    * without specific prior written permission.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
-ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
-ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-*/
-
-#define MEMCMP  wmemcmp_atom
-
-#define USE_WCHAR
-#define USE_AS_WMEMCMP 1
-#include "ssse3-memcmp-atom.S"
diff --git a/libc/bionic/__libc_init_main_thread.cpp b/libc/bionic/__libc_init_main_thread.cpp
index 1b539f274..0d557f128 100644
--- a/libc/bionic/__libc_init_main_thread.cpp
+++ b/libc/bionic/__libc_init_main_thread.cpp
@@ -44,7 +44,7 @@ extern "C" int __set_tid_address(int* tid_address);
 // Declared in "private/bionic_ssp.h".
 uintptr_t __stack_chk_guard = 0;
 
-static pthread_internal_t main_thread;
+BIONIC_USED_BEFORE_LINKER_RELOCATES static pthread_internal_t main_thread;
 
 // Setup for the main thread. For dynamic executables, this is called by the
 // linker _before_ libc is mapped in memory. This means that all writes to
diff --git a/libc/bionic/android_mallopt.cpp b/libc/bionic/android_mallopt.cpp
new file mode 100644
index 000000000..79e407237
--- /dev/null
+++ b/libc/bionic/android_mallopt.cpp
@@ -0,0 +1,146 @@
+/*
+ * Copyright (C) 2009 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <errno.h>
+#include <stdatomic.h>
+
+#include <platform/bionic/malloc.h>
+#include <private/bionic_globals.h>
+
+#include "gwp_asan_wrappers.h"
+#include "malloc_limit.h"
+
+#if !defined(LIBC_STATIC)
+#include <stdio.h>
+
+#include <private/bionic_defs.h>
+
+#include "malloc_heapprofd.h"
+
+extern bool gZygoteChild;
+extern _Atomic bool gZygoteChildProfileable;
+
+bool WriteMallocLeakInfo(FILE* fp);
+bool GetMallocLeakInfo(android_mallopt_leak_info_t* leak_info);
+bool FreeMallocLeakInfo(android_mallopt_leak_info_t* leak_info);
+#endif
+
+// =============================================================================
+// Platform-internal mallopt variant.
+// =============================================================================
+#if !defined(LIBC_STATIC)
+__BIONIC_WEAK_FOR_NATIVE_BRIDGE
+#endif
+extern "C" bool android_mallopt(int opcode, void* arg, size_t arg_size) {
+  // Functionality available in both static and dynamic libc.
+  if (opcode == M_GET_DECAY_TIME_ENABLED) {
+    if (arg == nullptr || arg_size != sizeof(bool)) {
+      errno = EINVAL;
+      return false;
+    }
+    *reinterpret_cast<bool*>(arg) = atomic_load(&__libc_globals->decay_time_enabled);
+    return true;
+  }
+  if (opcode == M_INITIALIZE_GWP_ASAN) {
+    if (arg == nullptr || arg_size != sizeof(android_mallopt_gwp_asan_options_t)) {
+      errno = EINVAL;
+      return false;
+    }
+
+    return EnableGwpAsan(*reinterpret_cast<android_mallopt_gwp_asan_options_t*>(arg));
+  }
+  if (opcode == M_MEMTAG_STACK_IS_ON) {
+    if (arg == nullptr || arg_size != sizeof(bool)) {
+      errno = EINVAL;
+      return false;
+    }
+    *reinterpret_cast<bool*>(arg) = atomic_load(&__libc_memtag_stack);
+    return true;
+  }
+  if (opcode == M_SET_ALLOCATION_LIMIT_BYTES) {
+    return LimitEnable(arg, arg_size);
+  }
+
+#if defined(LIBC_STATIC)
+  errno = ENOTSUP;
+  return false;
+#else
+  if (opcode == M_SET_ZYGOTE_CHILD) {
+    if (arg != nullptr || arg_size != 0) {
+      errno = EINVAL;
+      return false;
+    }
+    gZygoteChild = true;
+    return true;
+  }
+  if (opcode == M_INIT_ZYGOTE_CHILD_PROFILING) {
+    if (arg != nullptr || arg_size != 0) {
+      errno = EINVAL;
+      return false;
+    }
+    atomic_store_explicit(&gZygoteChildProfileable, true, memory_order_release);
+    // Also check if heapprofd should start profiling from app startup.
+    HeapprofdInitZygoteChildProfiling();
+    return true;
+  }
+  if (opcode == M_GET_PROCESS_PROFILEABLE) {
+    if (arg == nullptr || arg_size != sizeof(bool)) {
+      errno = EINVAL;
+      return false;
+    }
+    // Native processes are considered profileable. Zygote children are considered
+    // profileable only when appropriately tagged.
+    *reinterpret_cast<bool*>(arg) =
+        !gZygoteChild || atomic_load_explicit(&gZygoteChildProfileable, memory_order_acquire);
+    return true;
+  }
+  if (opcode == M_WRITE_MALLOC_LEAK_INFO_TO_FILE) {
+    if (arg == nullptr || arg_size != sizeof(FILE*)) {
+      errno = EINVAL;
+      return false;
+    }
+    return WriteMallocLeakInfo(reinterpret_cast<FILE*>(arg));
+  }
+  if (opcode == M_GET_MALLOC_LEAK_INFO) {
+    if (arg == nullptr || arg_size != sizeof(android_mallopt_leak_info_t)) {
+      errno = EINVAL;
+      return false;
+    }
+    return GetMallocLeakInfo(reinterpret_cast<android_mallopt_leak_info_t*>(arg));
+  }
+  if (opcode == M_FREE_MALLOC_LEAK_INFO) {
+    if (arg == nullptr || arg_size != sizeof(android_mallopt_leak_info_t)) {
+      errno = EINVAL;
+      return false;
+    }
+    return FreeMallocLeakInfo(reinterpret_cast<android_mallopt_leak_info_t*>(arg));
+  }
+  // Try heapprofd's mallopt, as it handles options not covered here.
+  return HeapprofdMallopt(opcode, arg, arg_size);
+#endif
+}
diff --git a/libc/bionic/bionic_call_ifunc_resolver.cpp b/libc/bionic/bionic_call_ifunc_resolver.cpp
index e44d998ae..d5a812c94 100644
--- a/libc/bionic/bionic_call_ifunc_resolver.cpp
+++ b/libc/bionic/bionic_call_ifunc_resolver.cpp
@@ -31,6 +31,7 @@
 #include <sys/hwprobe.h>
 #include <sys/ifunc.h>
 
+#include "bionic/macros.h"
 #include "private/bionic_auxv.h"
 
 // This code is called in the linker before it has been relocated, so minimize calls into other
@@ -40,8 +41,8 @@
 ElfW(Addr) __bionic_call_ifunc_resolver(ElfW(Addr) resolver_addr) {
 #if defined(__aarch64__)
   typedef ElfW(Addr) (*ifunc_resolver_t)(uint64_t, __ifunc_arg_t*);
-  static __ifunc_arg_t arg;
-  static bool initialized = false;
+  BIONIC_USED_BEFORE_LINKER_RELOCATES static __ifunc_arg_t arg;
+  BIONIC_USED_BEFORE_LINKER_RELOCATES static bool initialized = false;
   if (!initialized) {
     initialized = true;
     arg._size = sizeof(__ifunc_arg_t);
diff --git a/libc/bionic/elf_note.cpp b/libc/bionic/elf_note.cpp
index d5cd5de44..9cc6b2159 100644
--- a/libc/bionic/elf_note.cpp
+++ b/libc/bionic/elf_note.cpp
@@ -38,31 +38,34 @@ bool __get_elf_note(unsigned note_type, const char* note_name, const ElfW(Addr)
     return false;
   }
 
+  size_t note_name_len = strlen(note_name) + 1;
+
   ElfW(Addr) p = note_addr;
   ElfW(Addr) note_end = p + phdr_note->p_memsz;
-
   while (p + sizeof(ElfW(Nhdr)) <= note_end) {
+    // Parse the note and check it's structurally valid.
     const ElfW(Nhdr)* note = reinterpret_cast<const ElfW(Nhdr)*>(p);
     p += sizeof(ElfW(Nhdr));
     const char* name = reinterpret_cast<const char*>(p);
-    p += align_up(note->n_namesz, 4);
-    const char* desc = reinterpret_cast<const char*>(p);
-    p += align_up(note->n_descsz, 4);
-    if (p > note_end) {
-      break;
+    if (__builtin_add_overflow(p, align_up(note->n_namesz, 4), &p)) {
+      return false;
     }
-    if (note->n_type != note_type) {
-      continue;
+    const char* desc = reinterpret_cast<const char*>(p);
+    if (__builtin_add_overflow(p, align_up(note->n_descsz, 4), &p)) {
+      return false;
     }
-    size_t note_name_len = strlen(note_name) + 1;
-    if (note->n_namesz != note_name_len || strncmp(note_name, name, note_name_len) != 0) {
-      break;
+    if (p > note_end) {
+      return false;
     }
 
-    *note_hdr = note;
-    *note_desc = desc;
-
-    return true;
+    // Is this the note we're looking for?
+    if (note->n_type == note_type &&
+        note->n_namesz == note_name_len &&
+        strncmp(note_name, name, note_name_len) == 0) {
+      *note_hdr = note;
+      *note_desc = desc;
+      return true;
+    }
   }
   return false;
 }
diff --git a/libc/bionic/fts.c b/libc/bionic/fts.c
index 128726768..c36835e3c 100644
--- a/libc/bionic/fts.c
+++ b/libc/bionic/fts.c
@@ -29,7 +29,6 @@
  * SUCH DAMAGE.
  */
 
-#include <sys/param.h>	/* ALIGN */
 #include <sys/stat.h>
 
 #include <dirent.h>
@@ -37,6 +36,7 @@
 #include <fcntl.h>
 #include <fts.h>
 #include <limits.h>
+#include <stdalign.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
@@ -912,10 +912,14 @@ fts_alloc(FTS *sp, const char *name, size_t namelen)
 	 * be careful that the stat structure is reasonably aligned.  Since the
 	 * fts_name field is declared to be of size 1, the fts_name pointer is
 	 * namelen + 2 before the first possible address of the stat structure.
+	 *
+	 * We can't use the same trick FreeBSD uses here because our fts_name
+	 * is a char[1] rather than a char*. This is also the reason we don't
+	 * need to say `namelen + 1`. We just assume the worst alignment.
 	 */
 	len = sizeof(FTSENT) + namelen;
 	if (!ISSET(FTS_NOSTAT))
-		len += sizeof(struct stat) + ALIGNBYTES;
+		len += alignof(struct stat) + sizeof(struct stat);
 	if ((p = calloc(1, len)) == NULL)
 		return (NULL);
 
@@ -923,7 +927,7 @@ fts_alloc(FTS *sp, const char *name, size_t namelen)
 	p->fts_namelen = namelen;
 	p->fts_instr = FTS_NOINSTR;
 	if (!ISSET(FTS_NOSTAT))
-		p->fts_statp = (struct stat *)ALIGN(p->fts_name + namelen + 2);
+		p->fts_statp = (struct stat *)__builtin_align_up(p->fts_name + namelen + 2, alignof(struct stat));
 	memcpy(p->fts_name, name, namelen);
 
 	return (p);
diff --git a/libc/bionic/libc_init_mte.cpp b/libc/bionic/libc_init_mte.cpp
new file mode 100644
index 000000000..3c8ef7da6
--- /dev/null
+++ b/libc/bionic/libc_init_mte.cpp
@@ -0,0 +1,325 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <android/api-level.h>
+#include <elf.h>
+#include <errno.h>
+#include <malloc.h>
+#include <signal.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <sys/auxv.h>
+#include <sys/mman.h>
+
+#include "async_safe/log.h"
+#include "heap_tagging.h"
+#include "libc_init_common.h"
+#include "platform/bionic/macros.h"
+#include "platform/bionic/mte.h"
+#include "platform/bionic/page.h"
+#include "platform/bionic/reserved_signals.h"
+#include "private/KernelArgumentBlock.h"
+#include "private/bionic_asm.h"
+#include "private/bionic_asm_note.h"
+#include "private/bionic_call_ifunc_resolver.h"
+#include "private/bionic_elf_tls.h"
+#include "private/bionic_globals.h"
+#include "private/bionic_tls.h"
+#include "private/elf_note.h"
+#include "pthread_internal.h"
+#include "sys/system_properties.h"
+#include "sysprop_helpers.h"
+
+#ifdef __aarch64__
+extern "C" const char* __gnu_basename(const char* path);
+
+static HeapTaggingLevel __get_memtag_level_from_note(const ElfW(Phdr) * phdr_start, size_t phdr_ct,
+                                                     const ElfW(Addr) load_bias, bool* stack) {
+  const ElfW(Nhdr) * note;
+  const char* desc;
+  if (!__find_elf_note(NT_ANDROID_TYPE_MEMTAG, "Android", phdr_start, phdr_ct, &note, &desc,
+                       load_bias)) {
+    return M_HEAP_TAGGING_LEVEL_TBI;
+  }
+
+  // Previously (in Android 12), if the note was != 4 bytes, we check-failed
+  // here. Let's be more permissive to allow future expansion.
+  if (note->n_descsz < 4) {
+    async_safe_fatal("unrecognized android.memtag note: n_descsz = %d, expected >= 4",
+                     note->n_descsz);
+  }
+
+  // `desc` is always aligned due to ELF requirements, enforced in __find_elf_note().
+  ElfW(Word) note_val = *reinterpret_cast<const ElfW(Word)*>(desc);
+  *stack = (note_val & NT_MEMTAG_STACK) != 0;
+
+  // Warning: In Android 12, any value outside of bits [0..3] resulted in a check-fail.
+  if (!(note_val & (NT_MEMTAG_HEAP | NT_MEMTAG_STACK))) {
+    async_safe_format_log(ANDROID_LOG_INFO, "libc",
+                          "unrecognised memtag note_val did not specificy heap or stack: %u",
+                          note_val);
+    return M_HEAP_TAGGING_LEVEL_TBI;
+  }
+
+  unsigned mode = note_val & NT_MEMTAG_LEVEL_MASK;
+  switch (mode) {
+    case NT_MEMTAG_LEVEL_NONE:
+      // Note, previously (in Android 12), NT_MEMTAG_LEVEL_NONE was
+      // NT_MEMTAG_LEVEL_DEFAULT, which implied SYNC mode. This was never used
+      // by anyone, but we note it (heh) here for posterity, in case the zero
+      // level becomes meaningful, and binaries with this note can be executed
+      // on Android 12 devices.
+      return M_HEAP_TAGGING_LEVEL_TBI;
+    case NT_MEMTAG_LEVEL_ASYNC:
+      return M_HEAP_TAGGING_LEVEL_ASYNC;
+    case NT_MEMTAG_LEVEL_SYNC:
+    default:
+      // We allow future extensions to specify mode 3 (currently unused), with
+      // the idea that it might be used for ASYMM mode or something else. On
+      // this version of Android, it falls back to SYNC mode.
+      return M_HEAP_TAGGING_LEVEL_SYNC;
+  }
+}
+
+// Returns true if there's an environment setting (either sysprop or env var)
+// that should overwrite the ELF note, and places the equivalent heap tagging
+// level into *level.
+static bool get_environment_memtag_setting(HeapTaggingLevel* level) {
+  static const char kMemtagPrognameSyspropPrefix[] = "arm64.memtag.process.";
+  static const char kMemtagGlobalSysprop[] = "persist.arm64.memtag.default";
+  static const char kMemtagOverrideSyspropPrefix[] =
+      "persist.device_config.memory_safety_native.mode_override.process.";
+
+  const char* progname = __libc_shared_globals()->init_progname;
+  if (progname == nullptr) return false;
+
+  const char* basename = __gnu_basename(progname);
+
+  char options_str[PROP_VALUE_MAX];
+  char sysprop_name[512];
+  async_safe_format_buffer(sysprop_name, sizeof(sysprop_name), "%s%s", kMemtagPrognameSyspropPrefix,
+                           basename);
+  char remote_sysprop_name[512];
+  async_safe_format_buffer(remote_sysprop_name, sizeof(remote_sysprop_name), "%s%s",
+                           kMemtagOverrideSyspropPrefix, basename);
+  const char* sys_prop_names[] = {sysprop_name, remote_sysprop_name, kMemtagGlobalSysprop};
+
+  if (!get_config_from_env_or_sysprops("MEMTAG_OPTIONS", sys_prop_names, arraysize(sys_prop_names),
+                                       options_str, sizeof(options_str))) {
+    return false;
+  }
+
+  if (strcmp("sync", options_str) == 0) {
+    *level = M_HEAP_TAGGING_LEVEL_SYNC;
+  } else if (strcmp("async", options_str) == 0) {
+    *level = M_HEAP_TAGGING_LEVEL_ASYNC;
+  } else if (strcmp("off", options_str) == 0) {
+    *level = M_HEAP_TAGGING_LEVEL_TBI;
+  } else {
+    async_safe_format_log(
+        ANDROID_LOG_ERROR, "libc",
+        "unrecognized memtag level: \"%s\" (options are \"sync\", \"async\", or \"off\").",
+        options_str);
+    return false;
+  }
+
+  return true;
+}
+
+// Returns the initial heap tagging level. Note: This function will never return
+// M_HEAP_TAGGING_LEVEL_NONE, if MTE isn't enabled for this process we enable
+// M_HEAP_TAGGING_LEVEL_TBI.
+static HeapTaggingLevel __get_tagging_level(const memtag_dynamic_entries_t* memtag_dynamic_entries,
+                                            const void* phdr_start, size_t phdr_ct,
+                                            uintptr_t load_bias, bool* stack) {
+  HeapTaggingLevel level = M_HEAP_TAGGING_LEVEL_TBI;
+
+  // If the dynamic entries exist, use those. Otherwise, fall back to the old
+  // Android note, which is still used for fully static executables. When
+  // -fsanitize=memtag* is used in newer toolchains, currently both the dynamic
+  // entries and the old note are created, but we'd expect to move to just the
+  // dynamic entries for dynamically linked executables in the future. In
+  // addition, there's still some cleanup of the build system (that uses a
+  // manually-constructed note) needed. For more information about the dynamic
+  // entries, see:
+  // https://github.com/ARM-software/abi-aa/blob/main/memtagabielf64/memtagabielf64.rst#dynamic-section
+  if (memtag_dynamic_entries && memtag_dynamic_entries->has_memtag_mode) {
+    switch (memtag_dynamic_entries->memtag_mode) {
+      case 0:
+        level = M_HEAP_TAGGING_LEVEL_SYNC;
+        break;
+      case 1:
+        level = M_HEAP_TAGGING_LEVEL_ASYNC;
+        break;
+      default:
+        async_safe_format_log(ANDROID_LOG_INFO, "libc",
+                              "unrecognised DT_AARCH64_MEMTAG_MODE value: %u",
+                              memtag_dynamic_entries->memtag_mode);
+    }
+    *stack = memtag_dynamic_entries->memtag_stack;
+  } else {
+    level = __get_memtag_level_from_note(reinterpret_cast<const ElfW(Phdr)*>(phdr_start), phdr_ct,
+                                         load_bias, stack);
+  }
+
+  // We can't short-circuit the environment override, as `stack` is still inherited from the
+  // binary's settings.
+  get_environment_memtag_setting(&level);
+  return level;
+}
+
+static void __enable_mte_signal_handler(int, siginfo_t* info, void*) {
+  if (info->si_code != SI_TIMER) {
+    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "Got BIONIC_ENABLE_MTE not from SI_TIMER");
+    return;
+  }
+  int tagged_addr_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
+  if (tagged_addr_ctrl < 0) {
+    async_safe_fatal("failed to PR_GET_TAGGED_ADDR_CTRL: %m");
+  }
+  if ((tagged_addr_ctrl & PR_MTE_TCF_MASK) != PR_MTE_TCF_NONE) {
+    return;
+  }
+  async_safe_format_log(ANDROID_LOG_INFO, "libc",
+                        "Re-enabling MTE, value: %x (tagged_addr_ctrl %lu)",
+                        info->si_value.sival_int, info->si_value.sival_int & PR_MTE_TCF_MASK);
+  tagged_addr_ctrl =
+      (tagged_addr_ctrl & ~PR_MTE_TCF_MASK) | (info->si_value.sival_int & PR_MTE_TCF_MASK);
+  if (prctl(PR_SET_TAGGED_ADDR_CTRL, tagged_addr_ctrl, 0, 0, 0) < 0) {
+    async_safe_fatal("failed to PR_SET_TAGGED_ADDR_CTRL %d: %m", tagged_addr_ctrl);
+  }
+}
+
+static int64_t __get_memtag_upgrade_secs() {
+  char* env = getenv("BIONIC_MEMTAG_UPGRADE_SECS");
+  if (!env) return 0;
+  int64_t timed_upgrade = 0;
+  static const char kAppProcessName[] = "app_process64";
+  const char* progname = __libc_shared_globals()->init_progname;
+  progname = progname ? __gnu_basename(progname) : nullptr;
+  // disable timed upgrade for zygote, as the thread spawned will violate the requirement
+  // that it be single-threaded.
+  if (!progname || strncmp(progname, kAppProcessName, sizeof(kAppProcessName)) != 0) {
+    char* endptr;
+    timed_upgrade = strtoll(env, &endptr, 10);
+    if (*endptr != '\0' || timed_upgrade < 0) {
+      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
+                            "Invalid value for BIONIC_MEMTAG_UPGRADE_SECS: %s", env);
+      timed_upgrade = 0;
+    }
+  }
+  // Make sure that this does not get passed to potential processes inheriting
+  // this environment.
+  unsetenv("BIONIC_MEMTAG_UPGRADE_SECS");
+  return timed_upgrade;
+}
+
+// Figure out the desired memory tagging mode (sync/async, heap/globals/stack) for this executable.
+// This function is called from the linker before the main executable is relocated.
+__attribute__((no_sanitize("hwaddress", "memtag"))) void __libc_init_mte(
+    const memtag_dynamic_entries_t* memtag_dynamic_entries, const void* phdr_start, size_t phdr_ct,
+    uintptr_t load_bias) {
+  bool memtag_stack = false;
+  HeapTaggingLevel level =
+      __get_tagging_level(memtag_dynamic_entries, phdr_start, phdr_ct, load_bias, &memtag_stack);
+  if (memtag_stack) __libc_shared_globals()->initial_memtag_stack_abi = true;
+
+  if (int64_t timed_upgrade = __get_memtag_upgrade_secs()) {
+    if (level == M_HEAP_TAGGING_LEVEL_ASYNC) {
+      async_safe_format_log(ANDROID_LOG_INFO, "libc",
+                            "Attempting timed MTE upgrade from async to sync.");
+      __libc_shared_globals()->heap_tagging_upgrade_timer_sec = timed_upgrade;
+      level = M_HEAP_TAGGING_LEVEL_SYNC;
+    } else if (level != M_HEAP_TAGGING_LEVEL_SYNC) {
+      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
+                            "Requested timed MTE upgrade from invalid %s to sync. Ignoring.",
+                            DescribeTaggingLevel(level));
+    }
+  }
+  if (level == M_HEAP_TAGGING_LEVEL_SYNC || level == M_HEAP_TAGGING_LEVEL_ASYNC) {
+    unsigned long prctl_arg = PR_TAGGED_ADDR_ENABLE | PR_MTE_TAG_SET_NONZERO;
+    prctl_arg |= (level == M_HEAP_TAGGING_LEVEL_SYNC) ? PR_MTE_TCF_SYNC : PR_MTE_TCF_ASYNC;
+
+    // When entering ASYNC mode, specify that we want to allow upgrading to SYNC by OR'ing in the
+    // SYNC flag. But if the kernel doesn't support specifying multiple TCF modes, fall back to
+    // specifying a single mode.
+    if (prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_arg | PR_MTE_TCF_SYNC, 0, 0, 0) == 0 ||
+        prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_arg, 0, 0, 0) == 0) {
+      __libc_shared_globals()->initial_heap_tagging_level = level;
+
+      struct sigaction action = {};
+      action.sa_flags = SA_SIGINFO | SA_RESTART;
+      action.sa_sigaction = __enable_mte_signal_handler;
+      sigaction(BIONIC_ENABLE_MTE, &action, nullptr);
+      return;
+    }
+  }
+
+  // MTE was either not enabled, or wasn't supported on this device. Try and use
+  // TBI.
+  if (prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) == 0) {
+    __libc_shared_globals()->initial_heap_tagging_level = M_HEAP_TAGGING_LEVEL_TBI;
+  }
+  // We did not enable MTE, so we do not need to arm the upgrade timer.
+  __libc_shared_globals()->heap_tagging_upgrade_timer_sec = 0;
+}
+
+// Figure out whether we need to map the stack as PROT_MTE.
+// For dynamic executables, this has to be called after loading all
+// DT_NEEDED libraries, in case one of them needs stack MTE.
+__attribute__((no_sanitize("hwaddress", "memtag"))) void __libc_init_mte_stack(void* stack_top) {
+  if (!__libc_shared_globals()->initial_memtag_stack_abi) {
+    return;
+  }
+
+  // Even if the device doesn't support MTE, we have to allocate stack
+  // history buffers for code compiled for stack MTE. That is because the
+  // codegen expects a buffer to be present in TLS_SLOT_STACK_MTE either
+  // way.
+  __get_bionic_tcb()->tls_slot(TLS_SLOT_STACK_MTE) = __allocate_stack_mte_ringbuffer(0, nullptr);
+
+  if (__libc_mte_enabled()) {
+    __libc_shared_globals()->initial_memtag_stack = true;
+    void* pg_start = reinterpret_cast<void*>(page_start(reinterpret_cast<uintptr_t>(stack_top)));
+    if (mprotect(pg_start, page_size(), PROT_READ | PROT_WRITE | PROT_MTE | PROT_GROWSDOWN)) {
+      async_safe_fatal("error: failed to set PROT_MTE on main thread stack: %m");
+    }
+  }
+}
+
+#else   // __aarch64__
+void __libc_init_mte(const memtag_dynamic_entries_t*, const void*, size_t, uintptr_t) {}
+void __libc_init_mte_stack(void*) {}
+#endif  // __aarch64__
+
+bool __libc_mte_enabled() {
+  HeapTaggingLevel lvl = __libc_shared_globals()->initial_heap_tagging_level;
+  return lvl == M_HEAP_TAGGING_LEVEL_SYNC || lvl == M_HEAP_TAGGING_LEVEL_ASYNC;
+}
diff --git a/libc/bionic/libc_init_static.cpp b/libc/bionic/libc_init_static.cpp
index 7c461139a..cd963754a 100644
--- a/libc/bionic/libc_init_static.cpp
+++ b/libc/bionic/libc_init_static.cpp
@@ -157,260 +157,6 @@ static void layout_static_tls(KernelArgumentBlock& args) {
 
   layout.finish_layout();
 }
-
-#ifdef __aarch64__
-static HeapTaggingLevel __get_memtag_level_from_note(const ElfW(Phdr) * phdr_start, size_t phdr_ct,
-                                                     const ElfW(Addr) load_bias, bool* stack) {
-  const ElfW(Nhdr) * note;
-  const char* desc;
-  if (!__find_elf_note(NT_ANDROID_TYPE_MEMTAG, "Android", phdr_start, phdr_ct, &note, &desc,
-                       load_bias)) {
-    return M_HEAP_TAGGING_LEVEL_TBI;
-  }
-
-  // Previously (in Android 12), if the note was != 4 bytes, we check-failed
-  // here. Let's be more permissive to allow future expansion.
-  if (note->n_descsz < 4) {
-    async_safe_fatal("unrecognized android.memtag note: n_descsz = %d, expected >= 4",
-                     note->n_descsz);
-  }
-
-  // `desc` is always aligned due to ELF requirements, enforced in __find_elf_note().
-  ElfW(Word) note_val = *reinterpret_cast<const ElfW(Word)*>(desc);
-  *stack = (note_val & NT_MEMTAG_STACK) != 0;
-
-  // Warning: In Android 12, any value outside of bits [0..3] resulted in a check-fail.
-  if (!(note_val & (NT_MEMTAG_HEAP | NT_MEMTAG_STACK))) {
-    async_safe_format_log(ANDROID_LOG_INFO, "libc",
-                          "unrecognised memtag note_val did not specificy heap or stack: %u",
-                          note_val);
-    return M_HEAP_TAGGING_LEVEL_TBI;
-  }
-
-  unsigned mode = note_val & NT_MEMTAG_LEVEL_MASK;
-  switch (mode) {
-    case NT_MEMTAG_LEVEL_NONE:
-      // Note, previously (in Android 12), NT_MEMTAG_LEVEL_NONE was
-      // NT_MEMTAG_LEVEL_DEFAULT, which implied SYNC mode. This was never used
-      // by anyone, but we note it (heh) here for posterity, in case the zero
-      // level becomes meaningful, and binaries with this note can be executed
-      // on Android 12 devices.
-      return M_HEAP_TAGGING_LEVEL_TBI;
-    case NT_MEMTAG_LEVEL_ASYNC:
-      return M_HEAP_TAGGING_LEVEL_ASYNC;
-    case NT_MEMTAG_LEVEL_SYNC:
-    default:
-      // We allow future extensions to specify mode 3 (currently unused), with
-      // the idea that it might be used for ASYMM mode or something else. On
-      // this version of Android, it falls back to SYNC mode.
-      return M_HEAP_TAGGING_LEVEL_SYNC;
-  }
-}
-
-// Returns true if there's an environment setting (either sysprop or env var)
-// that should overwrite the ELF note, and places the equivalent heap tagging
-// level into *level.
-static bool get_environment_memtag_setting(HeapTaggingLevel* level) {
-  static const char kMemtagPrognameSyspropPrefix[] = "arm64.memtag.process.";
-  static const char kMemtagGlobalSysprop[] = "persist.arm64.memtag.default";
-  static const char kMemtagOverrideSyspropPrefix[] =
-      "persist.device_config.memory_safety_native.mode_override.process.";
-
-  const char* progname = __libc_shared_globals()->init_progname;
-  if (progname == nullptr) return false;
-
-  const char* basename = __gnu_basename(progname);
-
-  char options_str[PROP_VALUE_MAX];
-  char sysprop_name[512];
-  async_safe_format_buffer(sysprop_name, sizeof(sysprop_name), "%s%s", kMemtagPrognameSyspropPrefix,
-                           basename);
-  char remote_sysprop_name[512];
-  async_safe_format_buffer(remote_sysprop_name, sizeof(remote_sysprop_name), "%s%s",
-                           kMemtagOverrideSyspropPrefix, basename);
-  const char* sys_prop_names[] = {sysprop_name, remote_sysprop_name, kMemtagGlobalSysprop};
-
-  if (!get_config_from_env_or_sysprops("MEMTAG_OPTIONS", sys_prop_names, arraysize(sys_prop_names),
-                                       options_str, sizeof(options_str))) {
-    return false;
-  }
-
-  if (strcmp("sync", options_str) == 0) {
-    *level = M_HEAP_TAGGING_LEVEL_SYNC;
-  } else if (strcmp("async", options_str) == 0) {
-    *level = M_HEAP_TAGGING_LEVEL_ASYNC;
-  } else if (strcmp("off", options_str) == 0) {
-    *level = M_HEAP_TAGGING_LEVEL_TBI;
-  } else {
-    async_safe_format_log(
-        ANDROID_LOG_ERROR, "libc",
-        "unrecognized memtag level: \"%s\" (options are \"sync\", \"async\", or \"off\").",
-        options_str);
-    return false;
-  }
-
-  return true;
-}
-
-// Returns the initial heap tagging level. Note: This function will never return
-// M_HEAP_TAGGING_LEVEL_NONE, if MTE isn't enabled for this process we enable
-// M_HEAP_TAGGING_LEVEL_TBI.
-static HeapTaggingLevel __get_tagging_level(const memtag_dynamic_entries_t* memtag_dynamic_entries,
-                                            const void* phdr_start, size_t phdr_ct,
-                                            uintptr_t load_bias, bool* stack) {
-  HeapTaggingLevel level = M_HEAP_TAGGING_LEVEL_TBI;
-
-  // If the dynamic entries exist, use those. Otherwise, fall back to the old
-  // Android note, which is still used for fully static executables. When
-  // -fsanitize=memtag* is used in newer toolchains, currently both the dynamic
-  // entries and the old note are created, but we'd expect to move to just the
-  // dynamic entries for dynamically linked executables in the future. In
-  // addition, there's still some cleanup of the build system (that uses a
-  // manually-constructed note) needed. For more information about the dynamic
-  // entries, see:
-  // https://github.com/ARM-software/abi-aa/blob/main/memtagabielf64/memtagabielf64.rst#dynamic-section
-  if (memtag_dynamic_entries && memtag_dynamic_entries->has_memtag_mode) {
-    switch (memtag_dynamic_entries->memtag_mode) {
-      case 0:
-        level = M_HEAP_TAGGING_LEVEL_SYNC;
-        break;
-      case 1:
-        level = M_HEAP_TAGGING_LEVEL_ASYNC;
-        break;
-      default:
-        async_safe_format_log(ANDROID_LOG_INFO, "libc",
-                              "unrecognised DT_AARCH64_MEMTAG_MODE value: %u",
-                              memtag_dynamic_entries->memtag_mode);
-    }
-    *stack = memtag_dynamic_entries->memtag_stack;
-  } else {
-    level = __get_memtag_level_from_note(reinterpret_cast<const ElfW(Phdr)*>(phdr_start), phdr_ct,
-                                         load_bias, stack);
-  }
-
-  // We can't short-circuit the environment override, as `stack` is still inherited from the
-  // binary's settings.
-  get_environment_memtag_setting(&level);
-  return level;
-}
-
-static void __enable_mte_signal_handler(int, siginfo_t* info, void*) {
-  if (info->si_code != SI_TIMER) {
-    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "Got BIONIC_ENABLE_MTE not from SI_TIMER");
-    return;
-  }
-  int tagged_addr_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
-  if (tagged_addr_ctrl < 0) {
-    async_safe_fatal("failed to PR_GET_TAGGED_ADDR_CTRL: %m");
-  }
-  if ((tagged_addr_ctrl & PR_MTE_TCF_MASK) != PR_MTE_TCF_NONE) {
-    return;
-  }
-  async_safe_format_log(ANDROID_LOG_INFO, "libc",
-                        "Re-enabling MTE, value: %x (tagged_addr_ctrl %lu)",
-                        info->si_value.sival_int, info->si_value.sival_int & PR_MTE_TCF_MASK);
-  tagged_addr_ctrl =
-      (tagged_addr_ctrl & ~PR_MTE_TCF_MASK) | (info->si_value.sival_int & PR_MTE_TCF_MASK);
-  if (prctl(PR_SET_TAGGED_ADDR_CTRL, tagged_addr_ctrl, 0, 0, 0) < 0) {
-    async_safe_fatal("failed to PR_SET_TAGGED_ADDR_CTRL %d: %m", tagged_addr_ctrl);
-  }
-}
-
-static int64_t __get_memtag_upgrade_secs() {
-  char* env = getenv("BIONIC_MEMTAG_UPGRADE_SECS");
-  if (!env) return 0;
-  int64_t timed_upgrade = 0;
-  static const char kAppProcessName[] = "app_process64";
-  const char* progname = __libc_shared_globals()->init_progname;
-  progname = progname ? __gnu_basename(progname) : nullptr;
-  // disable timed upgrade for zygote, as the thread spawned will violate the requirement
-  // that it be single-threaded.
-  if (!progname || strncmp(progname, kAppProcessName, sizeof(kAppProcessName)) != 0) {
-    char* endptr;
-    timed_upgrade = strtoll(env, &endptr, 10);
-    if (*endptr != '\0' || timed_upgrade < 0) {
-      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
-                            "Invalid value for BIONIC_MEMTAG_UPGRADE_SECS: %s", env);
-      timed_upgrade = 0;
-    }
-  }
-  // Make sure that this does not get passed to potential processes inheriting
-  // this environment.
-  unsetenv("BIONIC_MEMTAG_UPGRADE_SECS");
-  return timed_upgrade;
-}
-
-// Figure out the desired memory tagging mode (sync/async, heap/globals/stack) for this executable.
-// This function is called from the linker before the main executable is relocated.
-__attribute__((no_sanitize("hwaddress", "memtag"))) void __libc_init_mte(
-    const memtag_dynamic_entries_t* memtag_dynamic_entries, const void* phdr_start, size_t phdr_ct,
-    uintptr_t load_bias, void* stack_top) {
-  bool memtag_stack = false;
-  HeapTaggingLevel level =
-      __get_tagging_level(memtag_dynamic_entries, phdr_start, phdr_ct, load_bias, &memtag_stack);
-  // initial_memtag_stack is used by the linker (in linker.cpp) to communicate than any library
-  // linked by this executable enables memtag-stack.
-  // memtag_stack is also set for static executables if they request memtag stack via the note,
-  // in which case it will differ from initial_memtag_stack.
-  if (__libc_shared_globals()->initial_memtag_stack || memtag_stack) {
-    memtag_stack = true;
-    __libc_shared_globals()->initial_memtag_stack_abi = true;
-    __get_bionic_tcb()->tls_slot(TLS_SLOT_STACK_MTE) = __allocate_stack_mte_ringbuffer(0, nullptr);
-  }
-  if (int64_t timed_upgrade = __get_memtag_upgrade_secs()) {
-    if (level == M_HEAP_TAGGING_LEVEL_ASYNC) {
-      async_safe_format_log(ANDROID_LOG_INFO, "libc",
-                            "Attempting timed MTE upgrade from async to sync.");
-      __libc_shared_globals()->heap_tagging_upgrade_timer_sec = timed_upgrade;
-      level = M_HEAP_TAGGING_LEVEL_SYNC;
-    } else if (level != M_HEAP_TAGGING_LEVEL_SYNC) {
-      async_safe_format_log(
-          ANDROID_LOG_ERROR, "libc",
-          "Requested timed MTE upgrade from invalid %s to sync. Ignoring.",
-          DescribeTaggingLevel(level));
-    }
-  }
-  if (level == M_HEAP_TAGGING_LEVEL_SYNC || level == M_HEAP_TAGGING_LEVEL_ASYNC) {
-    unsigned long prctl_arg = PR_TAGGED_ADDR_ENABLE | PR_MTE_TAG_SET_NONZERO;
-    prctl_arg |= (level == M_HEAP_TAGGING_LEVEL_SYNC) ? PR_MTE_TCF_SYNC : PR_MTE_TCF_ASYNC;
-
-    // When entering ASYNC mode, specify that we want to allow upgrading to SYNC by OR'ing in the
-    // SYNC flag. But if the kernel doesn't support specifying multiple TCF modes, fall back to
-    // specifying a single mode.
-    if (prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_arg | PR_MTE_TCF_SYNC, 0, 0, 0) == 0 ||
-        prctl(PR_SET_TAGGED_ADDR_CTRL, prctl_arg, 0, 0, 0) == 0) {
-      __libc_shared_globals()->initial_heap_tagging_level = level;
-      __libc_shared_globals()->initial_memtag_stack = memtag_stack;
-
-      if (memtag_stack) {
-        void* pg_start =
-            reinterpret_cast<void*>(page_start(reinterpret_cast<uintptr_t>(stack_top)));
-        if (mprotect(pg_start, page_size(), PROT_READ | PROT_WRITE | PROT_MTE | PROT_GROWSDOWN)) {
-          async_safe_fatal("error: failed to set PROT_MTE on main thread stack: %m");
-        }
-      }
-      struct sigaction action = {};
-      action.sa_flags = SA_SIGINFO | SA_RESTART;
-      action.sa_sigaction = __enable_mte_signal_handler;
-      sigaction(BIONIC_ENABLE_MTE, &action, nullptr);
-      return;
-    }
-  }
-
-  // MTE was either not enabled, or wasn't supported on this device. Try and use
-  // TBI.
-  if (prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) == 0) {
-    __libc_shared_globals()->initial_heap_tagging_level = M_HEAP_TAGGING_LEVEL_TBI;
-  }
-  // We did not enable MTE, so we do not need to arm the upgrade timer.
-  __libc_shared_globals()->heap_tagging_upgrade_timer_sec = 0;
-  // We also didn't enable memtag_stack.
-  __libc_shared_globals()->initial_memtag_stack = false;
-}
-#else   // __aarch64__
-void __libc_init_mte(const memtag_dynamic_entries_t*, const void*, size_t, uintptr_t, void*) {}
-#endif  // __aarch64__
-
 void __libc_init_profiling_handlers() {
   // The dynamic variant of this function is more interesting, but this
   // at least ensures that static binaries aren't killed by the kernel's
@@ -436,7 +182,8 @@ __attribute__((no_sanitize("memtag"))) __noreturn static void __real_libc_init(
   __libc_init_common();
   __libc_init_mte(/*memtag_dynamic_entries=*/nullptr,
                   reinterpret_cast<ElfW(Phdr)*>(getauxval(AT_PHDR)), getauxval(AT_PHNUM),
-                  /*load_bias = */ 0, /*stack_top = */ raw_args);
+                  /*load_bias = */ 0);
+  __libc_init_mte_stack(/*stack_top = */ raw_args);
   __libc_init_scudo();
   __libc_init_profiling_handlers();
   __libc_init_fork_handler();
@@ -508,6 +255,6 @@ extern "C" void android_set_application_target_sdk_version(int target) {
 // compiled with -ffreestanding to avoid implicit string.h function calls. (It shouldn't strictly
 // be necessary, though.)
 __LIBC_HIDDEN__ libc_shared_globals* __libc_shared_globals() {
-  static libc_shared_globals globals;
+  BIONIC_USED_BEFORE_LINKER_RELOCATES static libc_shared_globals globals;
   return &globals;
 }
diff --git a/libc/bionic/malloc_common.cpp b/libc/bionic/malloc_common.cpp
index 596a1fc82..441d88482 100644
--- a/libc/bionic/malloc_common.cpp
+++ b/libc/bionic/malloc_common.cpp
@@ -332,44 +332,6 @@ extern "C" int __sanitizer_malloc_info(int, FILE*) {
 #endif
 // =============================================================================
 
-// =============================================================================
-// Platform-internal mallopt variant.
-// =============================================================================
-#if defined(LIBC_STATIC)
-extern "C" bool android_mallopt(int opcode, void* arg, size_t arg_size) {
-  if (opcode == M_SET_ALLOCATION_LIMIT_BYTES) {
-    return LimitEnable(arg, arg_size);
-  }
-  if (opcode == M_INITIALIZE_GWP_ASAN) {
-    if (arg == nullptr || arg_size != sizeof(android_mallopt_gwp_asan_options_t)) {
-      errno = EINVAL;
-      return false;
-    }
-
-    return EnableGwpAsan(*reinterpret_cast<android_mallopt_gwp_asan_options_t*>(arg));
-  }
-  if (opcode == M_MEMTAG_STACK_IS_ON) {
-    if (arg == nullptr || arg_size != sizeof(bool)) {
-      errno = EINVAL;
-      return false;
-    }
-    *reinterpret_cast<bool*>(arg) = atomic_load(&__libc_memtag_stack);
-    return true;
-  }
-  if (opcode == M_GET_DECAY_TIME_ENABLED) {
-    if (arg == nullptr || arg_size != sizeof(bool)) {
-      errno = EINVAL;
-      return false;
-    }
-    *reinterpret_cast<bool*>(arg) = atomic_load(&__libc_globals->decay_time_enabled);
-    return true;
-  }
-  errno = ENOTSUP;
-  return false;
-}
-#endif
-// =============================================================================
-
 static constexpr MallocDispatch __libc_malloc_default_dispatch __attribute__((unused)) = {
   Malloc(calloc),
   Malloc(free),
diff --git a/libc/bionic/malloc_common_dynamic.cpp b/libc/bionic/malloc_common_dynamic.cpp
index 6db625128..7b6d7d49c 100644
--- a/libc/bionic/malloc_common_dynamic.cpp
+++ b/libc/bionic/malloc_common_dynamic.cpp
@@ -80,7 +80,7 @@ pthread_mutex_t gGlobalsMutateLock = PTHREAD_MUTEX_INITIALIZER;
 
 _Atomic bool gGlobalsMutating = false;
 
-static bool gZygoteChild = false;
+bool gZygoteChild = false;
 
 // In a Zygote child process, this is set to true if profiling of this process
 // is allowed. Note that this is set at a later time than gZygoteChild. The
@@ -89,7 +89,7 @@ static bool gZygoteChild = false;
 // domains if applicable). These two flags are read by the
 // BIONIC_SIGNAL_PROFILER handler, which does nothing if the process is not
 // profileable.
-static _Atomic bool gZygoteChildProfileable = false;
+_Atomic bool gZygoteChildProfileable = false;
 
 // =============================================================================
 
@@ -471,93 +471,6 @@ extern "C" ssize_t malloc_backtrace(void* pointer, uintptr_t* frames, size_t fra
 }
 // =============================================================================
 
-// =============================================================================
-// Platform-internal mallopt variant.
-// =============================================================================
-__BIONIC_WEAK_FOR_NATIVE_BRIDGE
-extern "C" bool android_mallopt(int opcode, void* arg, size_t arg_size) {
-  if (opcode == M_SET_ZYGOTE_CHILD) {
-    if (arg != nullptr || arg_size != 0) {
-      errno = EINVAL;
-      return false;
-    }
-    gZygoteChild = true;
-    return true;
-  }
-  if (opcode == M_INIT_ZYGOTE_CHILD_PROFILING) {
-    if (arg != nullptr || arg_size != 0) {
-      errno = EINVAL;
-      return false;
-    }
-    atomic_store_explicit(&gZygoteChildProfileable, true, memory_order_release);
-    // Also check if heapprofd should start profiling from app startup.
-    HeapprofdInitZygoteChildProfiling();
-    return true;
-  }
-  if (opcode == M_GET_PROCESS_PROFILEABLE) {
-    if (arg == nullptr || arg_size != sizeof(bool)) {
-      errno = EINVAL;
-      return false;
-    }
-    // Native processes are considered profileable. Zygote children are considered
-    // profileable only when appropriately tagged.
-    *reinterpret_cast<bool*>(arg) =
-        !gZygoteChild || atomic_load_explicit(&gZygoteChildProfileable, memory_order_acquire);
-    return true;
-  }
-  if (opcode == M_SET_ALLOCATION_LIMIT_BYTES) {
-    return LimitEnable(arg, arg_size);
-  }
-  if (opcode == M_WRITE_MALLOC_LEAK_INFO_TO_FILE) {
-    if (arg == nullptr || arg_size != sizeof(FILE*)) {
-      errno = EINVAL;
-      return false;
-    }
-    return WriteMallocLeakInfo(reinterpret_cast<FILE*>(arg));
-  }
-  if (opcode == M_GET_MALLOC_LEAK_INFO) {
-    if (arg == nullptr || arg_size != sizeof(android_mallopt_leak_info_t)) {
-      errno = EINVAL;
-      return false;
-    }
-    return GetMallocLeakInfo(reinterpret_cast<android_mallopt_leak_info_t*>(arg));
-  }
-  if (opcode == M_FREE_MALLOC_LEAK_INFO) {
-    if (arg == nullptr || arg_size != sizeof(android_mallopt_leak_info_t)) {
-      errno = EINVAL;
-      return false;
-    }
-    return FreeMallocLeakInfo(reinterpret_cast<android_mallopt_leak_info_t*>(arg));
-  }
-  if (opcode == M_INITIALIZE_GWP_ASAN) {
-    if (arg == nullptr || arg_size != sizeof(android_mallopt_gwp_asan_options_t)) {
-      errno = EINVAL;
-      return false;
-    }
-
-    return EnableGwpAsan(*reinterpret_cast<android_mallopt_gwp_asan_options_t*>(arg));
-  }
-  if (opcode == M_MEMTAG_STACK_IS_ON) {
-    if (arg == nullptr || arg_size != sizeof(bool)) {
-      errno = EINVAL;
-      return false;
-    }
-    *reinterpret_cast<bool*>(arg) = atomic_load(&__libc_memtag_stack);
-    return true;
-  }
-  if (opcode == M_GET_DECAY_TIME_ENABLED) {
-    if (arg == nullptr || arg_size != sizeof(bool)) {
-      errno = EINVAL;
-      return false;
-    }
-    *reinterpret_cast<bool*>(arg) = atomic_load(&__libc_globals->decay_time_enabled);
-    return true;
-  }
-  // Try heapprofd's mallopt, as it handles options not covered here.
-  return HeapprofdMallopt(opcode, arg, arg_size);
-}
-// =============================================================================
-
 #if !defined(__LP64__) && defined(__arm__)
 // =============================================================================
 // Old platform only functions that some old 32 bit apps are still using.
diff --git a/libc/bionic/posix_timers.cpp b/libc/bionic/posix_timers.cpp
index 65749a42a..9516059e8 100644
--- a/libc/bionic/posix_timers.cpp
+++ b/libc/bionic/posix_timers.cpp
@@ -141,7 +141,7 @@ int timer_create(clockid_t clock_id, sigevent* evp, timer_t* timer_id) {
   // Otherwise, this must be SIGEV_THREAD timer...
   timer->callback = evp->sigev_notify_function;
   timer->callback_argument = evp->sigev_value;
-  atomic_init(&timer->deleted, false);
+  atomic_store_explicit(&timer->deleted, false, memory_order_relaxed);
 
   // Check arguments that the kernel doesn't care about but we do.
   if (timer->callback == nullptr) {
diff --git a/libc/bionic/pthread_barrier.cpp b/libc/bionic/pthread_barrier.cpp
index 1618222a1..ff048a616 100644
--- a/libc/bionic/pthread_barrier.cpp
+++ b/libc/bionic/pthread_barrier.cpp
@@ -95,8 +95,8 @@ int pthread_barrier_init(pthread_barrier_t* barrier_interface, const pthread_bar
     return EINVAL;
   }
   barrier->init_count = count;
-  atomic_init(&barrier->state, WAIT);
-  atomic_init(&barrier->wait_count, 0);
+  atomic_store_explicit(&barrier->state, WAIT, memory_order_relaxed);
+  atomic_store_explicit(&barrier->wait_count, 0, memory_order_relaxed);
   barrier->pshared = false;
   if (attr != nullptr && (*attr & 1)) {
     barrier->pshared = true;
diff --git a/libc/bionic/pthread_cond.cpp b/libc/bionic/pthread_cond.cpp
index f444676c7..197fd19ac 100644
--- a/libc/bionic/pthread_cond.cpp
+++ b/libc/bionic/pthread_cond.cpp
@@ -140,10 +140,10 @@ int pthread_cond_init(pthread_cond_t* cond_interface, const pthread_condattr_t*
   if (attr != nullptr) {
     init_state = (*attr & COND_FLAGS_MASK);
   }
-  atomic_init(&cond->state, init_state);
+  atomic_store_explicit(&cond->state, init_state, memory_order_relaxed);
 
 #if defined(__LP64__)
-  atomic_init(&cond->waiters, 0);
+  atomic_store_explicit(&cond->waiters, 0, memory_order_relaxed);
 #endif
 
   return 0;
diff --git a/libc/bionic/pthread_create.cpp b/libc/bionic/pthread_create.cpp
index ba20c5181..3fa8ee683 100644
--- a/libc/bionic/pthread_create.cpp
+++ b/libc/bionic/pthread_create.cpp
@@ -159,11 +159,11 @@ void __init_additional_stacks(pthread_internal_t* thread) {
 int __init_thread(pthread_internal_t* thread) {
   thread->cleanup_stack = nullptr;
 
-  if (__predict_true((thread->attr.flags & PTHREAD_ATTR_FLAG_DETACHED) == 0)) {
-    atomic_init(&thread->join_state, THREAD_NOT_JOINED);
-  } else {
-    atomic_init(&thread->join_state, THREAD_DETACHED);
+  ThreadJoinState state = THREAD_NOT_JOINED;
+  if (__predict_false((thread->attr.flags & PTHREAD_ATTR_FLAG_DETACHED) != 0)) {
+    state = THREAD_DETACHED;
   }
+  atomic_store_explicit(&thread->join_state, state, memory_order_relaxed);
 
   // Set the scheduling policy/priority of the thread if necessary.
   bool need_set = true;
@@ -351,15 +351,20 @@ void __set_stack_and_tls_vma_name(bool is_main_thread) {
 
 extern "C" int __rt_sigprocmask(int, const sigset64_t*, sigset64_t*, size_t);
 
-__attribute__((no_sanitize("hwaddress")))
+__attribute__((no_sanitize("hwaddress", "memtag")))
 #if defined(__aarch64__)
 // This function doesn't return, but it does appear in stack traces. Avoid using return PAC in this
 // function because we may end up resetting IA, which may confuse unwinders due to mismatching keys.
 __attribute__((target("branch-protection=bti")))
 #endif
-static int __pthread_start(void* arg) {
+static int
+__pthread_start(void* arg) {
   pthread_internal_t* thread = reinterpret_cast<pthread_internal_t*>(arg);
-
+#if defined(__aarch64__)
+  if (thread->should_allocate_stack_mte_ringbuffer) {
+    thread->bionic_tcb->tls_slot(TLS_SLOT_STACK_MTE) = __allocate_stack_mte_ringbuffer(0, thread);
+  }
+#endif
   __hwasan_thread_enter();
 
   // Wait for our creating thread to release us. This lets it have time to
@@ -450,9 +455,9 @@ int pthread_create(pthread_t* thread_out, pthread_attr_t const* attr,
 // This has to be done under g_thread_creation_lock or g_thread_list_lock to avoid racing with
 // __pthread_internal_remap_stack_with_mte.
 #ifdef __aarch64__
-  if (__libc_memtag_stack_abi) {
-    tcb->tls_slot(TLS_SLOT_STACK_MTE) = __allocate_stack_mte_ringbuffer(0, thread);
-  }
+  thread->should_allocate_stack_mte_ringbuffer = __libc_memtag_stack_abi;
+#else
+  thread->should_allocate_stack_mte_ringbuffer = false;
 #endif
 
   sigset64_t block_all_mask;
diff --git a/libc/bionic/pthread_exit.cpp b/libc/bionic/pthread_exit.cpp
index 0181abac9..27d05c206 100644
--- a/libc/bionic/pthread_exit.cpp
+++ b/libc/bionic/pthread_exit.cpp
@@ -33,10 +33,11 @@
 #include <string.h>
 #include <sys/mman.h>
 
-#include "private/bionic_constants.h"
-#include "private/bionic_defs.h"
+#include "platform/bionic/mte.h"
 #include "private/ScopedRWLock.h"
 #include "private/ScopedSignalBlocker.h"
+#include "private/bionic_constants.h"
+#include "private/bionic_defs.h"
 #include "pthread_internal.h"
 
 extern "C" __noreturn void _exit_with_stack_teardown(void*, size_t);
@@ -67,7 +68,7 @@ void __pthread_cleanup_pop(__pthread_cleanup_t* c, int execute) {
 }
 
 __BIONIC_WEAK_FOR_NATIVE_BRIDGE
-void pthread_exit(void* return_value) {
+__attribute__((no_sanitize("memtag"))) void pthread_exit(void* return_value) {
   // Call dtors for thread_local objects first.
   __cxa_thread_finalize();
 
@@ -138,6 +139,13 @@ void pthread_exit(void* return_value) {
   __notify_thread_exit_callbacks();
   __hwasan_thread_exit();
 
+#if defined(__aarch64__)
+  if (void* stack_mte_tls = thread->bionic_tcb->tls_slot(TLS_SLOT_STACK_MTE)) {
+    stack_mte_free_ringbuffer(reinterpret_cast<uintptr_t>(stack_mte_tls));
+  }
+#endif
+  // Everything below this line needs to be no_sanitize("memtag").
+
   if (old_state == THREAD_DETACHED && thread->mmap_size != 0) {
     // We need to free mapped space for detached threads when they exit.
     // That's not something we can do in C.
diff --git a/libc/bionic/pthread_getaffinity.cpp b/libc/bionic/pthread_getaffinity.cpp
new file mode 100644
index 000000000..9ce436ccf
--- /dev/null
+++ b/libc/bionic/pthread_getaffinity.cpp
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <errno.h>
+
+#include "private/ErrnoRestorer.h"
+#include "pthread_internal.h"
+
+int pthread_getaffinity_np(pthread_t t, size_t cpu_set_size, cpu_set_t* cpu_set) {
+  ErrnoRestorer errno_restorer;
+
+  pid_t tid = __pthread_internal_gettid(t, "pthread_getaffinity_np");
+  if (tid == -1) return ESRCH;
+
+  if (sched_getaffinity(tid, cpu_set_size, cpu_set) == -1) return errno;
+  return 0;
+}
diff --git a/libc/bionic/pthread_internal.cpp b/libc/bionic/pthread_internal.cpp
index 14cc7da48..4f2ad0cfe 100644
--- a/libc/bionic/pthread_internal.cpp
+++ b/libc/bionic/pthread_internal.cpp
@@ -34,6 +34,7 @@
 #include <string.h>
 #include <sys/mman.h>
 #include <sys/prctl.h>
+#include <sys/types.h>
 
 #include <async_safe/log.h>
 #include <bionic/mte.h>
@@ -76,15 +77,6 @@ void __pthread_internal_remove(pthread_internal_t* thread) {
 }
 
 static void __pthread_internal_free(pthread_internal_t* thread) {
-#ifdef __aarch64__
-  if (void* stack_mte_tls = thread->bionic_tcb->tls_slot(TLS_SLOT_STACK_MTE)) {
-    size_t size =
-        stack_mte_ringbuffer_size_from_pointer(reinterpret_cast<uintptr_t>(stack_mte_tls));
-    void* ptr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(stack_mte_tls) &
-                                        ((1ULL << 56ULL) - 1ULL));
-    munmap(ptr, size);
-  }
-#endif
   if (thread->mmap_size != 0) {
     // Free mapped space, including thread stack and pthread_internal_t.
     munmap(thread->mmap_base, thread->mmap_size);
@@ -216,7 +208,10 @@ bool __pthread_internal_remap_stack_with_mte() {
   __libc_memtag_stack_abi = true;
 
   for (pthread_internal_t* t = g_thread_list; t != nullptr; t = t->next) {
-    if (t->terminating) continue;
+    // should_allocate_stack_mte_ringbuffer indicates the thread is already
+    // aware that this process requires stack MTE, and will allocate the
+    // ring buffer in __pthread_start.
+    if (t->terminating || t->should_allocate_stack_mte_ringbuffer) continue;
     t->bionic_tcb->tls_slot(TLS_SLOT_STACK_MTE) =
         __allocate_stack_mte_ringbuffer(0, t->is_main() ? nullptr : t);
   }
@@ -264,8 +259,7 @@ bool android_run_on_all_threads(bool (*func)(void*), void* arg) {
   g_func = func;
   g_arg = arg;
 
-  static _Atomic(bool) g_retval;
-  atomic_init(&g_retval, true);
+  static _Atomic(bool) g_retval(true);
 
   auto handler = [](int, siginfo_t*, void*) {
     ErrnoRestorer restorer;
diff --git a/libc/bionic/pthread_internal.h b/libc/bionic/pthread_internal.h
index 5db42ab48..cbaa9a6a9 100644
--- a/libc/bionic/pthread_internal.h
+++ b/libc/bionic/pthread_internal.h
@@ -181,6 +181,7 @@ class pthread_internal_t {
 
   bionic_tcb* bionic_tcb;
   char stack_mte_ringbuffer_vma_name_buffer[32];
+  bool should_allocate_stack_mte_ringbuffer;
 
   bool is_main() { return start_routine == nullptr; }
 };
diff --git a/libc/bionic/pthread_mutex.cpp b/libc/bionic/pthread_mutex.cpp
index 0a452e982..c99717a3f 100644
--- a/libc/bionic/pthread_mutex.cpp
+++ b/libc/bionic/pthread_mutex.cpp
@@ -509,8 +509,8 @@ int pthread_mutex_init(pthread_mutex_t* mutex_interface, const pthread_mutexattr
     memset(mutex, 0, sizeof(pthread_mutex_internal_t));
 
     if (__predict_true(attr == nullptr)) {
-        atomic_init(&mutex->state, MUTEX_TYPE_BITS_NORMAL);
-        return 0;
+      atomic_store_explicit(&mutex->state, MUTEX_TYPE_BITS_NORMAL, memory_order_relaxed);
+      return 0;
     }
 
     uint16_t state = 0;
@@ -543,13 +543,13 @@ int pthread_mutex_init(pthread_mutex_t* mutex_interface, const pthread_mutexattr
         }
         mutex->pi_mutex_id = id;
 #endif
-        atomic_init(&mutex->state, PI_MUTEX_STATE);
+        atomic_store_explicit(&mutex->state, PI_MUTEX_STATE, memory_order_relaxed);
         PIMutex& pi_mutex = mutex->ToPIMutex();
         pi_mutex.type = *attr & MUTEXATTR_TYPE_MASK;
         pi_mutex.shared = (*attr & MUTEXATTR_SHARED_MASK) != 0;
     } else {
-        atomic_init(&mutex->state, state);
-        atomic_init(&mutex->owner_tid, 0);
+      atomic_store_explicit(&mutex->state, state, memory_order_relaxed);
+      atomic_store_explicit(&mutex->owner_tid, 0, memory_order_relaxed);
     }
     return 0;
 }
diff --git a/libc/bionic/pthread_rwlock.cpp b/libc/bionic/pthread_rwlock.cpp
index 6f3c6feb8..92134b48d 100644
--- a/libc/bionic/pthread_rwlock.cpp
+++ b/libc/bionic/pthread_rwlock.cpp
@@ -247,7 +247,7 @@ int pthread_rwlock_init(pthread_rwlock_t* rwlock_interface, const pthread_rwlock
     }
   }
 
-  atomic_init(&rwlock->state, 0);
+  atomic_store_explicit(&rwlock->state, 0, memory_order_relaxed);
   rwlock->pending_lock.init(rwlock->pshared);
   return 0;
 }
diff --git a/libc/bionic/pthread_setaffinity.cpp b/libc/bionic/pthread_setaffinity.cpp
new file mode 100644
index 000000000..6db418e7f
--- /dev/null
+++ b/libc/bionic/pthread_setaffinity.cpp
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <errno.h>
+
+#include "private/ErrnoRestorer.h"
+#include "pthread_internal.h"
+
+int pthread_setaffinity_np(pthread_t t, size_t cpu_set_size, const cpu_set_t* cpu_set) {
+  ErrnoRestorer errno_restorer;
+
+  pid_t tid = __pthread_internal_gettid(t, "pthread_setaffinity_np");
+  if (tid == -1) return ESRCH;
+
+  if (sched_setaffinity(tid, cpu_set_size, cpu_set) == -1) return errno;
+  return 0;
+}
diff --git a/libc/bionic/semaphore.cpp b/libc/bionic/semaphore.cpp
index 33552a90b..2c9b745c9 100644
--- a/libc/bionic/semaphore.cpp
+++ b/libc/bionic/semaphore.cpp
@@ -113,7 +113,7 @@ int sem_init(sem_t* sem, int pshared, unsigned int value) {
   }
 
   atomic_uint* sem_count_ptr = SEM_TO_ATOMIC_POINTER(sem);
-  atomic_init(sem_count_ptr, count);
+  atomic_store_explicit(sem_count_ptr, count, memory_order_relaxed);
   return 0;
 }
 
diff --git a/libc/bionic/stdlib_l.cpp b/libc/bionic/stdlib_l.cpp
index a636d08d7..58a907970 100644
--- a/libc/bionic/stdlib_l.cpp
+++ b/libc/bionic/stdlib_l.cpp
@@ -26,17 +26,11 @@
  * SUCH DAMAGE.
  */
 
+#define __BIONIC_STDLIB_INLINE /* Out of line. */
 #include <stdlib.h>
-#include <xlocale.h>
-
-double strtod_l(const char* s, char** end_ptr, locale_t) {
-  return strtod(s, end_ptr);
-}
-
-float strtof_l(const char* s, char** end_ptr, locale_t) {
-  return strtof(s, end_ptr);
-}
+#include <bits/stdlib_inlines.h>
 
+// strtold_l was introduced in API level 21, so it isn't polyfilled any more.
 long double strtold_l(const char* s, char** end_ptr, locale_t) {
   return strtold(s, end_ptr);
 }
diff --git a/libc/dns/net/gethnamaddr.c b/libc/dns/net/gethnamaddr.c
index add124f52..1ffabfa9d 100644
--- a/libc/dns/net/gethnamaddr.c
+++ b/libc/dns/net/gethnamaddr.c
@@ -495,7 +495,7 @@ no_recovery:
 	*he = NO_RECOVERY;
 	return NULL;
 success:
-	bp = (char *)ALIGN(bp);
+	bp = __builtin_align_up(bp, sizeof(uintptr_t));
 	n = (int)(ap - aliases);
 	qlen = (n + 1) * sizeof(*hent->h_aliases);
 	if ((size_t)(ep - bp) < qlen)
@@ -616,7 +616,7 @@ android_read_hostent(FILE* proxy, struct hostent* hp, char* hbuf, size_t hbuflen
 	}
 
 	// Fix alignment after variable-length data.
-	ptr = (char*)ALIGN(ptr);
+	ptr = __builtin_align_up(ptr, sizeof(uintptr_t));
 
 	int aliases_len = ((int)(aliases - aliases_ptrs) + 1) * sizeof(*hp->h_aliases);
 	if (ptr + aliases_len > hbuf_end) {
@@ -653,7 +653,7 @@ android_read_hostent(FILE* proxy, struct hostent* hp, char* hbuf, size_t hbuflen
 	}
 
 	// Fix alignment after variable-length data.
-	ptr = (char*)ALIGN(ptr);
+	ptr = __builtin_align_up(ptr, sizeof(uintptr_t));
 
 	int addrs_len = ((int)(addr_p - addr_ptrs) + 1) * sizeof(*hp->h_addr_list);
 	if (ptr + addrs_len > hbuf_end) {
diff --git a/libc/dns/net/sethostent.c b/libc/dns/net/sethostent.c
index 5c4bdb5ab..8ea4315ac 100644
--- a/libc/dns/net/sethostent.c
+++ b/libc/dns/net/sethostent.c
@@ -198,7 +198,7 @@ _hf_gethtbyname2(const char *name, int af, struct getnamaddr *info)
 				HENT_SCOPY(aliases[anum], hp->h_aliases[anum],
 				    ptr, len);
 			}
-			ptr = (void *)ALIGN(ptr);
+			ptr = __builtin_align_up(ptr, sizeof(uintptr_t));
 			if ((size_t)(ptr - buf) >= info->buflen)
 				goto nospc;
 		}
diff --git a/libc/execinfo/include/execinfo.h b/libc/execinfo/include/execinfo.h
index e092c002f..c8f9e216d 100644
--- a/libc/execinfo/include/execinfo.h
+++ b/libc/execinfo/include/execinfo.h
@@ -30,8 +30,10 @@
 
 /*
  * This file is exported as part of libexecinfo for use with musl, which doesn't
- * define __INTRODUCED_IN.  Stub it out.
+ * define __INTRODUCED_IN or __BIONIC_AVAILABILITY_GUARD.  Stub them out.
  */
 #define __INTRODUCED_IN(x)
+#define __BIONIC_AVAILABILITY_GUARD(x) 1
 #include <bionic/execinfo.h>
+#undef __BIONIC_AVAILABILITY_GUARD
 #undef __INTRODUCED_IN
diff --git a/libc/include/android/api-level.h b/libc/include/android/api-level.h
index 1bde3a598..c9536c165 100644
--- a/libc/include/android/api-level.h
+++ b/libc/include/android/api-level.h
@@ -189,7 +189,11 @@ __BEGIN_DECLS
  *
  * Available since API level 24.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int android_get_application_target_sdk_version() __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 #if __ANDROID_API__ < 29
 
diff --git a/libc/include/android/crash_detail.h b/libc/include/android/crash_detail.h
index 946a3abc7..fd1312a1f 100644
--- a/libc/include/android/crash_detail.h
+++ b/libc/include/android/crash_detail.h
@@ -33,9 +33,10 @@
  * @brief Attach extra information to android crashes.
  */
 
-#include <stddef.h>
 #include <sys/cdefs.h>
 
+#include <stddef.h>
+
 __BEGIN_DECLS
 
 typedef struct crash_detail_t crash_detail_t;
@@ -79,6 +80,8 @@ typedef struct crash_detail_t crash_detail_t;
  *
  * \return a handle to the extra crash detail.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 crash_detail_t* _Nullable android_crash_detail_register(
     const void* _Nonnull name, size_t name_size, const void* _Nullable data, size_t data_size) __INTRODUCED_IN(35);
 
@@ -122,5 +125,7 @@ void android_crash_detail_replace_data(crash_detail_t* _Nonnull crash_detail, co
  * \param name_size number of bytes of the buffer pointed to by name
  */
 void android_crash_detail_replace_name(crash_detail_t* _Nonnull crash_detail, const void* _Nonnull name, size_t name_size) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 
 __END_DECLS
diff --git a/libc/include/android/dlext.h b/libc/include/android/dlext.h
index 842ceeaee..d8d2752ec 100644
--- a/libc/include/android/dlext.h
+++ b/libc/include/android/dlext.h
@@ -16,10 +16,11 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <stdbool.h>
 #include <stddef.h>
 #include <stdint.h>
-#include <sys/cdefs.h>
 #include <sys/types.h>  /* for off64_t */
 
 /**
diff --git a/libc/include/android/fdsan.h b/libc/include/android/fdsan.h
index 4540498d8..a04fc7e38 100644
--- a/libc/include/android/fdsan.h
+++ b/libc/include/android/fdsan.h
@@ -28,9 +28,10 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <stdbool.h>
 #include <stdint.h>
-#include <sys/cdefs.h>
 
 __BEGIN_DECLS
 
@@ -134,6 +135,8 @@ enum android_fdsan_owner_type {
 /*
  * Create an owner tag with the specified type and least significant 56 bits of tag.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(29)
 uint64_t android_fdsan_create_owner_tag(enum android_fdsan_owner_type type, uint64_t tag) __INTRODUCED_IN(29) __attribute__((__weak__));
 
 /*
@@ -168,6 +171,8 @@ const char* _Nonnull android_fdsan_get_tag_type(uint64_t tag) __INTRODUCED_IN(29
  * Get an owner tag's value, with the type masked off.
  */
 uint64_t android_fdsan_get_tag_value(uint64_t tag) __INTRODUCED_IN(29);
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
+
 
 enum android_fdsan_error_level {
   // No errors.
@@ -186,6 +191,8 @@ enum android_fdsan_error_level {
 /*
  * Get the error level.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(29)
 enum android_fdsan_error_level android_fdsan_get_error_level() __INTRODUCED_IN(29) __attribute__((__weak__));
 
 /*
@@ -203,9 +210,15 @@ enum android_fdsan_error_level android_fdsan_get_error_level() __INTRODUCED_IN(2
  * (e.g. postfork).
  */
 enum android_fdsan_error_level android_fdsan_set_error_level(enum android_fdsan_error_level new_level) __INTRODUCED_IN(29) __attribute__((__weak__));
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
+
 
 /*
  * Set the error level to the global setting if available, or a default value.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 enum android_fdsan_error_level android_fdsan_set_error_level_from_property(enum android_fdsan_error_level default_level) __INTRODUCED_IN(30) __attribute__((__weak__));
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 __END_DECLS
diff --git a/libc/include/android/legacy_stdlib_inlines.h b/libc/include/android/legacy_stdlib_inlines.h
index a5a07ef4b..d228e671c 100644
--- a/libc/include/android/legacy_stdlib_inlines.h
+++ b/libc/include/android/legacy_stdlib_inlines.h
@@ -30,22 +30,9 @@
 
 #include <sys/cdefs.h>
 
-
 #if __ANDROID_API__ < 26
 
-#include <stdlib.h>
-#include <xlocale.h>
-
-__BEGIN_DECLS
-
-static __inline double strtod_l(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, locale_t _Nonnull __l) {
-  return strtod(__s, __end_ptr);
-}
-
-static __inline float strtof_l(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, locale_t _Nonnull __l) {
-  return strtof(__s, __end_ptr);
-}
-
-__END_DECLS
+#define __BIONIC_THREADS_INLINE static __inline
+#include <bits/stdlib_inlines.h>
 
 #endif
diff --git a/libc/include/android/set_abort_message.h b/libc/include/android/set_abort_message.h
index a77805700..6ad567862 100644
--- a/libc/include/android/set_abort_message.h
+++ b/libc/include/android/set_abort_message.h
@@ -33,10 +33,11 @@
  * @brief The android_set_abort_message() function.
  */
 
+#include <sys/cdefs.h>
+
 #include <stddef.h>
 #include <stdint.h>
 #include <string.h>
-#include <sys/cdefs.h>
 
 __BEGIN_DECLS
 
diff --git a/libc/include/android/versioning.h b/libc/include/android/versioning.h
index fe9264dbf..1cf6e5107 100644
--- a/libc/include/android/versioning.h
+++ b/libc/include/android/versioning.h
@@ -32,6 +32,11 @@
 // load even on systems too old to contain the API, but calls must be guarded
 // with `__builtin_available(android api_level, *)` to avoid segfaults.
 #define __BIONIC_AVAILABILITY(__what, ...) __attribute__((__availability__(android,__what __VA_OPT__(,) __VA_ARGS__)))
+
+// When the caller is using weak API references, we should expose the decls for
+// APIs which are not available in the caller's minSdkVersion, otherwise there's
+// no way to take advantage of the weak references.
+#define __BIONIC_AVAILABILITY_GUARD(api_level) 1
 #else
 // The 'strict' flag is required for NDK clients where the code was not written
 // to handle the case where the API was available at build-time but not at
@@ -40,9 +45,25 @@
 // compile in this mode (or worse, if the build doesn't use
 // -Werror=unguarded-availability, it would build but crash at runtime).
 #define __BIONIC_AVAILABILITY(__what, ...) __attribute__((__availability__(android,strict,__what __VA_OPT__(,) __VA_ARGS__)))
+
+// When the caller is using strict API references, we hide APIs which are not
+// available in the caller's minSdkVersion. This is a bionic-only deviation in
+// behavior from the rest of the NDK headers, but it's necessary to maintain
+// source compatibility with 3p libraries that either can't correctly detect API
+// availability (either incorrectly detecting as always-available or as
+// never-available, but neither is true), or define their own polyfills which
+// conflict with our declarations.
+//
+// https://github.com/android/ndk/issues/2081
+#define __BIONIC_AVAILABILITY_GUARD(api_level) (__ANDROID_MIN_SDK_VERSION__ >= (api_level))
 #endif
 
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wc23-extensions"
+// Passing no argument for the '...' parameter of a variadic macro is a C23 extension
 #define __INTRODUCED_IN(api_level) __BIONIC_AVAILABILITY(introduced=api_level)
+#pragma clang diagnostic pop
+
 #define __DEPRECATED_IN(api_level, msg) __BIONIC_AVAILABILITY(deprecated=api_level, message=msg)
 #define __REMOVED_IN(api_level, msg) __BIONIC_AVAILABILITY(obsoleted=api_level, message=msg)
 
@@ -59,9 +80,3 @@
 #define __INTRODUCED_IN_32(api_level)
 #define __INTRODUCED_IN_64(api_level) __BIONIC_AVAILABILITY(introduced=api_level)
 #endif
-
-// Vendor modules do not follow SDK versioning. Ignore NDK guards for vendor modules.
-#if defined(__ANDROID_VENDOR__)
-#undef __BIONIC_AVAILABILITY
-#define __BIONIC_AVAILABILITY(api_level, ...)
-#endif // defined(__ANDROID_VENDOR__)
diff --git a/libc/include/arpa/ftp.h b/libc/include/arpa/ftp.h
index 081c037ec..fecbf7f83 100644
--- a/libc/include/arpa/ftp.h
+++ b/libc/include/arpa/ftp.h
@@ -34,6 +34,8 @@
 #ifndef _ARPA_FTP_H_
 #define	_ARPA_FTP_H_
 
+#include <sys/cdefs.h>
+
 /* Definitions for FTP; see RFC-765. */
 
 /*
diff --git a/libc/include/arpa/inet.h b/libc/include/arpa/inet.h
index f00f2c13c..ce9dd93dc 100644
--- a/libc/include/arpa/inet.h
+++ b/libc/include/arpa/inet.h
@@ -29,9 +29,10 @@
 #ifndef _ARPA_INET_H_
 #define _ARPA_INET_H_
 
+#include <sys/cdefs.h>
+
 #include <netinet/in.h>
 #include <stdint.h>
-#include <sys/cdefs.h>
 #include <sys/types.h>
 
 __BEGIN_DECLS
diff --git a/libc/include/arpa/nameser.h b/libc/include/arpa/nameser.h
index 97109eebb..3e0025e73 100644
--- a/libc/include/arpa/nameser.h
+++ b/libc/include/arpa/nameser.h
@@ -55,9 +55,10 @@
 
 #define BIND_4_COMPAT
 
-#include <sys/types.h>
 #include <sys/cdefs.h>
 
+#include <sys/types.h>
+
 /*
  * Revision information.  This is the release date in YYYYMMDD format.
  * It can change every day so the right thing to do with it is use it
@@ -547,6 +548,8 @@ __BEGIN_DECLS
 #define ns_sprintrrf __ns_sprintrrf
 #endif
 
+
+#if __BIONIC_AVAILABILITY_GUARD(22)
 int ns_msg_getflag(ns_msg __handle, int __flag) __INTRODUCED_IN(22);
 uint16_t ns_get16(const u_char* _Nonnull __src) __INTRODUCED_IN(22);
 uint32_t ns_get32(const u_char* _Nonnull __src) __INTRODUCED_IN(22);
@@ -570,6 +573,8 @@ void ns_name_rollback(const u_char* _Nonnull __src, const u_char* _Nullable * _N
 
 int ns_makecanon(const char* _Nonnull __src, char* _Nonnull __dst, size_t __dst_size) __INTRODUCED_IN(22);
 int ns_samename(const char* _Nonnull __lhs, const char* _Nonnull __rhs) __INTRODUCED_IN(22);
+#endif /* __BIONIC_AVAILABILITY_GUARD(22) */
+
 
 __END_DECLS
 
diff --git a/libc/include/arpa/nameser_compat.h b/libc/include/arpa/nameser_compat.h
index e4e933507..027e5ca2e 100644
--- a/libc/include/arpa/nameser_compat.h
+++ b/libc/include/arpa/nameser_compat.h
@@ -40,9 +40,10 @@
 #ifndef _ARPA_NAMESER_COMPAT_
 #define	_ARPA_NAMESER_COMPAT_
 
-#include <endian.h>
 #include <sys/cdefs.h>
 
+#include <endian.h>
+
 #define	__BIND		19950621	/* (DEAD) interface version stamp. */
 
 /*
diff --git a/libc/include/arpa/telnet.h b/libc/include/arpa/telnet.h
index 758e9b834..30d8f210f 100644
--- a/libc/include/arpa/telnet.h
+++ b/libc/include/arpa/telnet.h
@@ -33,6 +33,8 @@
 #ifndef _ARPA_TELNET_H_
 #define	_ARPA_TELNET_H_
 
+#include <sys/cdefs.h>
+
 /*
  * Definitions for the TELNET protocol.
  */
diff --git a/libc/include/bits/bionic_multibyte_result.h b/libc/include/bits/bionic_multibyte_result.h
index 0d5cf21d1..930e67cb3 100644
--- a/libc/include/bits/bionic_multibyte_result.h
+++ b/libc/include/bits/bionic_multibyte_result.h
@@ -34,9 +34,10 @@
  * conversion APIs defined by C.
  */
 
-#include <stddef.h>
 #include <sys/cdefs.h>
 
+#include <stddef.h>
+
 __BEGIN_DECLS
 
 /**
diff --git a/libc/include/bits/fortify/poll.h b/libc/include/bits/fortify/poll.h
index f2e27d796..1b4a5bf8b 100644
--- a/libc/include/bits/fortify/poll.h
+++ b/libc/include/bits/fortify/poll.h
@@ -30,9 +30,17 @@
 #error "Never include this file directly; instead, include <poll.h>"
 #endif
 
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int __poll_chk(struct pollfd* _Nullable, nfds_t, int, size_t) __INTRODUCED_IN(23);
 int __ppoll_chk(struct pollfd* _Nullable, nfds_t, const struct timespec* _Nullable, const sigset_t* _Nullable, size_t) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int __ppoll64_chk(struct pollfd* _Nullable, nfds_t, const struct timespec* _Nullable, const sigset64_t* _Nullable, size_t) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 #if defined(__BIONIC_FORTIFY)
 #define __bos_fd_count_trivially_safe(bos_val, fds, fd_count)              \
diff --git a/libc/include/bits/fortify/socket.h b/libc/include/bits/fortify/socket.h
index 1c3605b20..bd626f9f6 100644
--- a/libc/include/bits/fortify/socket.h
+++ b/libc/include/bits/fortify/socket.h
@@ -30,7 +30,11 @@
 #error "Never include this file directly; instead, include <sys/socket.h>"
 #endif
 
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 ssize_t __sendto_chk(int, const void* _Nonnull, size_t, size_t, int, const struct sockaddr* _Nullable, socklen_t) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 ssize_t __recvfrom_chk(int, void* _Nullable, size_t, size_t, int, struct sockaddr* _Nullable, socklen_t* _Nullable);
 
 #if defined(__BIONIC_FORTIFY)
diff --git a/libc/include/bits/fortify/stdio.h b/libc/include/bits/fortify/stdio.h
index e4607e003..f9faeba87 100644
--- a/libc/include/bits/fortify/stdio.h
+++ b/libc/include/bits/fortify/stdio.h
@@ -31,8 +31,12 @@
 #endif
 
 char* _Nullable __fgets_chk(char* _Nonnull, int, FILE* _Nonnull, size_t);
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 size_t __fread_chk(void* _Nonnull, size_t, size_t, FILE* _Nonnull, size_t) __INTRODUCED_IN(24);
 size_t __fwrite_chk(const void* _Nonnull, size_t, size_t, FILE* _Nonnull, size_t) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 #if defined(__BIONIC_FORTIFY) && !defined(__BIONIC_NO_STDIO_FORTIFY)
 
diff --git a/libc/include/bits/fortify/string.h b/libc/include/bits/fortify/string.h
index 4d32b041e..6f0ee4ae7 100644
--- a/libc/include/bits/fortify/string.h
+++ b/libc/include/bits/fortify/string.h
@@ -30,8 +30,12 @@
 #error "Never include this file directly; instead, include <string.h>"
 #endif
 
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void* _Nullable __memchr_chk(const void* _Nonnull, int, size_t, size_t) __INTRODUCED_IN(23);
 void* _Nullable __memrchr_chk(const void* _Nonnull, int, size_t, size_t) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 char* _Nonnull __stpncpy_chk2(char* _Nonnull, const char* _Nonnull, size_t, size_t, size_t);
 char* _Nonnull __strncpy_chk2(char* _Nonnull, const char* _Nonnull, size_t, size_t, size_t);
 size_t __strlcpy_chk(char* _Nonnull, const char* _Nonnull, size_t, size_t);
@@ -220,8 +224,13 @@ size_t strlcat(char* _Nonnull const dst __pass_object_size, const char* _Nonnull
 }
 
 #if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
-__BIONIC_FORTIFY_INLINE
-size_t strlen(const char* _Nonnull const s __pass_object_size0) __overloadable {
+/*
+ * Clang, when parsing C, can fold strlen to a constant without LLVM's help.
+ * This doesn't apply to overloads of strlen, so write this differently. We
+ * can't use `__pass_object_size0` here, but that's fine: it doesn't help much
+ * on __always_inline functions.
+ */
+extern __always_inline __inline__ __attribute__((gnu_inline)) size_t strlen(const char* _Nonnull s) {
     return __strlen_chk(s, __bos0(s));
 }
 #endif
diff --git a/libc/include/bits/fortify/unistd.h b/libc/include/bits/fortify/unistd.h
index 7eda1a6d8..9acb94239 100644
--- a/libc/include/bits/fortify/unistd.h
+++ b/libc/include/bits/fortify/unistd.h
@@ -29,24 +29,52 @@
 #error "Never include this file directly; instead, include <unistd.h>"
 #endif
 
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 char* _Nullable __getcwd_chk(char* _Nullable, size_t, size_t) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t __pread_chk(int, void* _Nonnull, size_t, off_t, size_t) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 ssize_t __pread_real(int, void* _Nonnull, size_t, off_t) __RENAME(pread);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t __pread64_chk(int, void* _Nonnull, size_t, off64_t, size_t) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 ssize_t __pread64_real(int, void* _Nonnull, size_t, off64_t) __RENAME(pread64);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t __pwrite_chk(int, const void* _Nonnull, size_t, off_t, size_t) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 ssize_t __pwrite_real(int, const void* _Nonnull, size_t, off_t) __RENAME(pwrite);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t __pwrite64_chk(int, const void* _Nonnull, size_t, off64_t, size_t) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 ssize_t __pwrite64_real(int, const void* _Nonnull, size_t, off64_t) __RENAME(pwrite64);
 
 ssize_t __read_chk(int, void* __BIONIC_COMPLICATED_NULLNESS, size_t, size_t);
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t __write_chk(int, const void* __BIONIC_COMPLICATED_NULLNESS, size_t, size_t) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t __readlink_chk(const char* _Nonnull, char* _Nonnull, size_t, size_t) __INTRODUCED_IN(23);
 ssize_t __readlinkat_chk(int dirfd, const char* _Nonnull, char* _Nonnull, size_t, size_t) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 #if defined(__BIONIC_FORTIFY)
 
diff --git a/libc/include/bits/getentropy.h b/libc/include/bits/getentropy.h
index 98d88799b..c878470cd 100644
--- a/libc/include/bits/getentropy.h
+++ b/libc/include/bits/getentropy.h
@@ -48,6 +48,10 @@ __BEGIN_DECLS
  *
  * See also arc4random_buf() which is available in all API levels.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 __nodiscard int getentropy(void* _Nonnull __buffer, size_t __buffer_size) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 __END_DECLS
diff --git a/libc/include/bits/glibc-syscalls.h b/libc/include/bits/glibc-syscalls.h
index 7b171e8dc..8c5a91d3f 100644
--- a/libc/include/bits/glibc-syscalls.h
+++ b/libc/include/bits/glibc-syscalls.h
@@ -36,9 +36,6 @@
 #if defined(__NR_arch_prctl)
   #define SYS_arch_prctl __NR_arch_prctl
 #endif
-#if defined(__NR_arch_specific_syscall)
-  #define SYS_arch_specific_syscall __NR_arch_specific_syscall
-#endif
 #if defined(__NR_arm_fadvise64_64)
   #define SYS_arm_fadvise64_64 __NR_arm_fadvise64_64
 #endif
@@ -1272,9 +1269,6 @@
 #if defined(__NR_syscall)
   #define SYS_syscall __NR_syscall
 #endif
-#if defined(__NR_syscalls)
-  #define SYS_syscalls __NR_syscalls
-#endif
 #if defined(__NR_sysfs)
   #define SYS_sysfs __NR_sysfs
 #endif
@@ -1371,6 +1365,9 @@
 #if defined(__NR_unshare)
   #define SYS_unshare __NR_unshare
 #endif
+#if defined(__NR_uretprobe)
+  #define SYS_uretprobe __NR_uretprobe
+#endif
 #if defined(__NR_uselib)
   #define SYS_uselib __NR_uselib
 #endif
diff --git a/libc/include/bits/lockf.h b/libc/include/bits/lockf.h
index 195b34ac8..8f922b9c7 100644
--- a/libc/include/bits/lockf.h
+++ b/libc/include/bits/lockf.h
@@ -56,6 +56,8 @@ __BEGIN_DECLS
  *
  * See also flock().
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int lockf(int __fd, int __op, off_t __length) __RENAME_IF_FILE_OFFSET64(lockf64) __INTRODUCED_IN(24);
 
 /**
@@ -63,5 +65,7 @@ int lockf(int __fd, int __op, off_t __length) __RENAME_IF_FILE_OFFSET64(lockf64)
  * even from a 32-bit process without `_FILE_OFFSET_BITS=64`.
  */
 int lockf64(int __fd, int __op, off64_t __length) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 __END_DECLS
diff --git a/libc/include/bits/seek_constants.h b/libc/include/bits/seek_constants.h
index bfc02a821..a4fffb28d 100644
--- a/libc/include/bits/seek_constants.h
+++ b/libc/include/bits/seek_constants.h
@@ -33,6 +33,8 @@
  * @brief The `SEEK_` constants.
  */
 
+#include <sys/cdefs.h>
+
 /** Seek to an absolute offset. */
 #define SEEK_SET 0
 /** Seek relative to the current offset. */
diff --git a/libc/include/bits/stdatomic.h b/libc/include/bits/stdatomic.h
index c74eafdec..ebdc9e5b6 100644
--- a/libc/include/bits/stdatomic.h
+++ b/libc/include/bits/stdatomic.h
@@ -134,6 +134,8 @@ typedef enum {
 	memory_order_seq_cst = __ATOMIC_SEQ_CST
 } memory_order;
 
+#define kill_dependency(y) (y)
+
 /*
  * 7.17.4 Fences.
  */
diff --git a/libc/include/bits/stdlib_inlines.h b/libc/include/bits/stdlib_inlines.h
new file mode 100644
index 000000000..fffca1973
--- /dev/null
+++ b/libc/include/bits/stdlib_inlines.h
@@ -0,0 +1,48 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#pragma once
+
+#include <xlocale.h>
+#include <sys/cdefs.h>
+
+#if !defined(__BIONIC_STDLIB_INLINE)
+#define __BIONIC_STDLIB_INLINE static __inline
+#endif
+
+__BEGIN_DECLS
+
+__BIONIC_STDLIB_INLINE double strtod_l(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, locale_t _Nonnull __l) {
+  return strtod(__s, __end_ptr);
+}
+
+__BIONIC_STDLIB_INLINE float strtof_l(const char* _Nonnull __s, char* _Nullable * _Nullable __end_ptr, locale_t _Nonnull __l) {
+  return strtof(__s, __end_ptr);
+}
+
+__END_DECLS
diff --git a/libc/include/bits/strcasecmp.h b/libc/include/bits/strcasecmp.h
index be910ad00..d76cec9cb 100644
--- a/libc/include/bits/strcasecmp.h
+++ b/libc/include/bits/strcasecmp.h
@@ -51,7 +51,11 @@ int strcasecmp(const char* _Nonnull __s1, const char* _Nonnull __s2) __attribute
 /**
  * Like strcasecmp() but taking a `locale_t`.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int strcasecmp_l(const char* _Nonnull __s1, const char* _Nonnull __s2, locale_t _Nonnull __l) __attribute_pure__ __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * [strncasecmp(3)](https://man7.org/linux/man-pages/man3/strncasecmp.3.html) compares the first
@@ -66,6 +70,10 @@ int strncasecmp(const char* _Nonnull __s1, const char* _Nonnull __s2, size_t __n
 /**
  * Like strncasecmp() but taking a `locale_t`.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int strncasecmp_l(const char* _Nonnull __s1, const char* _Nonnull __s2, size_t __n, locale_t _Nonnull __l) __attribute_pure__ __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 __END_DECLS
diff --git a/libc/include/bits/swab.h b/libc/include/bits/swab.h
index 9591c2ede..da2865a32 100644
--- a/libc/include/bits/swab.h
+++ b/libc/include/bits/swab.h
@@ -28,8 +28,9 @@
 
 #pragma once
 
-#include <stdint.h>
 #include <sys/cdefs.h>
+
+#include <stdint.h>
 #include <sys/types.h>
 
 #if !defined(__BIONIC_SWAB_INLINE)
diff --git a/libc/include/bits/termios_inlines.h b/libc/include/bits/termios_inlines.h
index a884b595f..bb04e4dbc 100644
--- a/libc/include/bits/termios_inlines.h
+++ b/libc/include/bits/termios_inlines.h
@@ -29,8 +29,9 @@
 #ifndef _BITS_TERMIOS_INLINES_H_
 #define _BITS_TERMIOS_INLINES_H_
 
-#include <errno.h>
 #include <sys/cdefs.h>
+
+#include <errno.h>
 #include <sys/ioctl.h>
 #include <sys/types.h>
 
diff --git a/libc/include/bits/termios_winsize_inlines.h b/libc/include/bits/termios_winsize_inlines.h
index ae246e401..86777b015 100644
--- a/libc/include/bits/termios_winsize_inlines.h
+++ b/libc/include/bits/termios_winsize_inlines.h
@@ -28,8 +28,9 @@
 
 #pragma once
 
-#include <errno.h>
 #include <sys/cdefs.h>
+
+#include <errno.h>
 #include <sys/ioctl.h>
 #include <sys/types.h>
 
diff --git a/libc/include/bits/threads_inlines.h b/libc/include/bits/threads_inlines.h
index 05b785a81..ab294c171 100644
--- a/libc/include/bits/threads_inlines.h
+++ b/libc/include/bits/threads_inlines.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <threads.h>
 
 #include <errno.h>
diff --git a/libc/include/bits/wctype.h b/libc/include/bits/wctype.h
index 13a42544e..d0cffec2c 100644
--- a/libc/include/bits/wctype.h
+++ b/libc/include/bits/wctype.h
@@ -58,8 +58,12 @@ wctype_t wctype(const char* _Nonnull __name);
 int iswctype(wint_t __wc, wctype_t __type);
 
 typedef const void* wctrans_t;
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 wint_t towctrans(wint_t __wc, wctrans_t _Nonnull __transform) __INTRODUCED_IN(26);
 wctrans_t _Nullable wctrans(const char* _Nonnull __name) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 __END_DECLS
 
diff --git a/libc/include/complex.h b/libc/include/complex.h
index f205abdba..11158622c 100644
--- a/libc/include/complex.h
+++ b/libc/include/complex.h
@@ -53,76 +53,190 @@ __BEGIN_DECLS
 
 /* 7.3.5 Trigonometric functions */
 /* 7.3.5.1 The cacos functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex cacos(double complex __z) __INTRODUCED_IN(23);
 float complex cacosf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex cacosl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.5.2 The casin functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex casin(double complex __z) __INTRODUCED_IN(23);
 float complex casinf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex casinl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.5.1 The catan functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex catan(double complex __z) __INTRODUCED_IN(23);
 float complex catanf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex catanl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.5.1 The ccos functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex ccos(double complex __z) __INTRODUCED_IN(23);
 float complex ccosf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex ccosl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.5.1 The csin functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex csin(double complex __z) __INTRODUCED_IN(23);
 float complex csinf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex csinl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.5.1 The ctan functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex ctan(double complex __z) __INTRODUCED_IN(23);
 float complex ctanf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex ctanl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 /* 7.3.6 Hyperbolic functions */
 /* 7.3.6.1 The cacosh functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex cacosh(double complex __z) __INTRODUCED_IN(23);
 float complex cacoshf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex cacoshl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.6.2 The casinh functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex casinh(double complex __z) __INTRODUCED_IN(23);
 float complex casinhf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex casinhl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.6.3 The catanh functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex catanh(double complex __z) __INTRODUCED_IN(23);
 float complex catanhf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex catanhl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.6.4 The ccosh functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex ccosh(double complex __z) __INTRODUCED_IN(23);
 float complex ccoshf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex ccoshl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.6.5 The csinh functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex csinh(double complex __z) __INTRODUCED_IN(23);
 float complex csinhf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex csinhl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.6.6 The ctanh functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex ctanh(double complex __z) __INTRODUCED_IN(23);
 float complex ctanhf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex ctanhl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 /* 7.3.7 Exponential and logarithmic functions */
 /* 7.3.7.1 The cexp functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex cexp(double complex __z) __INTRODUCED_IN(23);
 float complex cexpf(float complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 long double complex cexpl(long double complex __z) __INTRODUCED_IN(26);
 /* 7.3.7.2 The clog functions */
 double complex clog(double complex __z) __INTRODUCED_IN(26);
 float complex clogf(float complex __z) __INTRODUCED_IN(26);
 long double complex clogl(long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 /* 7.3.8 Power and absolute-value functions */
 /* 7.3.8.1 The cabs functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double cabs(double complex __z) __INTRODUCED_IN(23);
 float cabsf(float complex __z) __INTRODUCED_IN(23);
 long double cabsl(long double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 /* 7.3.8.2 The cpow functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 double complex cpow(double complex __x, double complex __z) __INTRODUCED_IN(26);
 float complex cpowf(float complex __x, float complex __z) __INTRODUCED_IN(26);
 long double complex cpowl(long double complex __x, long double complex __z) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 /* 7.3.8.3 The csqrt functions */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 double complex csqrt(double complex __z) __INTRODUCED_IN(23);
 float complex csqrtf(float complex __z) __INTRODUCED_IN(23);
 long double complex csqrtl(long double complex __z) __INTRODUCED_IN(23);
@@ -148,6 +262,8 @@ long double complex cprojl(long double complex __z) __INTRODUCED_IN(23);
 double creal(double complex __z) __INTRODUCED_IN(23);
 float crealf(float complex __z) __INTRODUCED_IN(23);
 long double creall(long double complex __z) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 __END_DECLS
 
diff --git a/libc/include/ctype.h b/libc/include/ctype.h
index cb926a4fc..dc3f673b6 100644
--- a/libc/include/ctype.h
+++ b/libc/include/ctype.h
@@ -95,7 +95,7 @@ __BIONIC_CTYPE_INLINE int _toupper(int __ch) {
 
 /** Internal implementation detail. Do not use. */
 __attribute__((__no_sanitize__("unsigned-integer-overflow")))
-static inline int __bionic_ctype_in_range(unsigned __lo, int __ch, unsigned __hi) {
+__BIONIC_CTYPE_INLINE int __bionic_ctype_in_range(unsigned __lo, int __ch, unsigned __hi) {
   return (__BIONIC_CAST(static_cast, unsigned, __ch) - __lo) < (__hi - __lo + 1);
 }
 
diff --git a/libc/include/dirent.h b/libc/include/dirent.h
index 5333d78c5..8058cfb08 100644
--- a/libc/include/dirent.h
+++ b/libc/include/dirent.h
@@ -33,8 +33,9 @@
  * @brief Directory entry iteration.
  */
 
-#include <stdint.h>
 #include <sys/cdefs.h>
+
+#include <stdint.h>
 #include <sys/types.h>
 
 __BEGIN_DECLS
@@ -149,6 +150,8 @@ void rewinddir(DIR* _Nonnull __dir);
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void seekdir(DIR* _Nonnull __dir, long __location) __INTRODUCED_IN(23);
 
 /**
@@ -161,6 +164,8 @@ void seekdir(DIR* _Nonnull __dir, long __location) __INTRODUCED_IN(23);
  * Available since API level 23.
  */
 long telldir(DIR* _Nonnull __dir) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * [dirfd(3)](https://man7.org/linux/man-pages/man3/dirfd.3.html)
@@ -221,6 +226,8 @@ int scandir64(const char* _Nonnull __path, struct dirent64* _Nonnull * _Nonnull
  *
  * Available since API level 24.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int scandirat64(int __dir_fd, const char* _Nonnull __path, struct dirent64* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent64* _Nonnull), int (* _Nullable __comparator)(const struct dirent64* _Nonnull * _Nonnull, const struct dirent64* _Nonnull * _Nonnull)) __INTRODUCED_IN(24);
 
 /**
@@ -237,6 +244,8 @@ int scandirat64(int __dir_fd, const char* _Nonnull __path, struct dirent64* _Non
  * Available since API level 24.
  */
 int scandirat(int __dir_fd, const char* _Nonnull __path, struct dirent* _Nonnull * _Nonnull * _Nonnull __name_list, int (* _Nullable __filter)(const struct dirent* _Nonnull), int (* _Nullable __comparator)(const struct dirent* _Nonnull * _Nonnull, const struct dirent* _Nonnull * _Nonnull)) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 #endif
 
diff --git a/libc/include/dlfcn.h b/libc/include/dlfcn.h
index 071d50aef..81045fd71 100644
--- a/libc/include/dlfcn.h
+++ b/libc/include/dlfcn.h
@@ -28,9 +28,21 @@
 
 #pragma once
 
-#include <stdint.h>
 #include <sys/cdefs.h>
 
+#include <stdint.h>
+
+/**
+ * @addtogroup libdl Dynamic Linker
+ * @{
+ */
+
+/**
+ * \file
+ * Standard dynamic library support.
+ * See also the Android-specific functionality in `<android/dlext.h>`.
+ */
+
 __BEGIN_DECLS
 
 /**
@@ -51,6 +63,8 @@ typedef struct {
  * [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html)
  * loads the given shared library.
  *
+ * See also android_dlopen_ext().
+ *
  * Returns a pointer to an opaque handle for use with other <dlfcn.h> functions
  * on success, and returns NULL on failure, in which case dlerror() can be used
  * to retrieve the specific error.
@@ -116,7 +130,11 @@ void* _Nullable dlsym(void* __BIONIC_COMPLICATED_NULLNESS __handle, const char*
  * Returns the address of the symbol on success, and returns NULL on failure,
  * in which case dlerror() can be used to retrieve the specific error.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 void* _Nullable dlvsym(void* __BIONIC_COMPLICATED_NULLNESS __handle, const char* _Nullable __symbol, const char* _Nullable __version) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 /**
  * [dladdr(3)](https://man7.org/linux/man-pages/man3/dladdr.3.html)
@@ -186,3 +204,5 @@ int dladdr(const void* _Nonnull __addr, Dl_info* _Nonnull __info);
 #endif
 
 __END_DECLS
+
+/** @} */
diff --git a/libc/include/err.h b/libc/include/err.h
index d8122d7d8..4a1841ba2 100644
--- a/libc/include/err.h
+++ b/libc/include/err.h
@@ -36,8 +36,9 @@
  * @brief BSD error reporting functions. See `<error.h>` for the GNU equivalent.
  */
 
-#include <stdarg.h>
 #include <sys/cdefs.h>
+
+#include <stdarg.h>
 #include <sys/types.h>
 
 __BEGIN_DECLS
diff --git a/libc/include/error.h b/libc/include/error.h
index cb867cd5f..a9bdc2461 100644
--- a/libc/include/error.h
+++ b/libc/include/error.h
@@ -44,6 +44,8 @@ __BEGIN_DECLS
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 extern void (* _Nullable error_print_progname)(void) __INTRODUCED_IN(23);
 
 /**
@@ -81,5 +83,7 @@ void error(int __status, int __errno, const char* _Nonnull __fmt, ...) __printfl
  * Available since API level 23.
  */
 void error_at_line(int __status, int __errno, const char* _Nonnull __filename, unsigned int __line_number, const char* _Nonnull __fmt, ...) __printflike(5, 6) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 __END_DECLS
diff --git a/libc/include/execinfo.h b/libc/include/execinfo.h
index 88f4ae79d..84b637cd9 100644
--- a/libc/include/execinfo.h
+++ b/libc/include/execinfo.h
@@ -47,6 +47,8 @@ __BEGIN_DECLS
  *
  * Available since API level 33.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(33)
 int backtrace(void* _Nonnull * _Nonnull buffer, int size) __INTRODUCED_IN(33);
 
 /**
@@ -70,5 +72,7 @@ char* _Nullable * _Nullable backtrace_symbols(void* _Nonnull const* _Nonnull buf
  * Available since API level 33.
  */
 void backtrace_symbols_fd(void* _Nonnull const* _Nonnull buffer, int size, int fd) __INTRODUCED_IN(33);
+#endif /* __BIONIC_AVAILABILITY_GUARD(33) */
+
 
 __END_DECLS
diff --git a/libc/include/fcntl.h b/libc/include/fcntl.h
index 1e9a285eb..2bd1fc66b 100644
--- a/libc/include/fcntl.h
+++ b/libc/include/fcntl.h
@@ -227,7 +227,11 @@ ssize_t readahead(int __fd, off64_t __offset, size_t __length);
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int sync_file_range(int __fd, off64_t __offset, off64_t __length, unsigned int __flags) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 #endif
 
diff --git a/libc/include/glob.h b/libc/include/glob.h
index 2c2b8d136..ccdf2e92a 100644
--- a/libc/include/glob.h
+++ b/libc/include/glob.h
@@ -92,8 +92,12 @@ typedef struct {
 
 __BEGIN_DECLS
 
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int glob(const char* _Nonnull __pattern, int __flags, int (* _Nullable __error_callback)(const char* _Nonnull __failure_path, int __failure_errno), glob_t* _Nonnull __result_ptr) __INTRODUCED_IN(28);
 void globfree(glob_t* _Nonnull __result_ptr) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 __END_DECLS
 
diff --git a/libc/include/grp.h b/libc/include/grp.h
index 2451db52d..a48c04677 100644
--- a/libc/include/grp.h
+++ b/libc/include/grp.h
@@ -51,12 +51,20 @@ struct group* _Nullable getgrgid(gid_t __gid);
 struct group* _Nullable getgrnam(const char* _Nonnull __name);
 
 /* Note: Android has thousands and thousands of ids to iterate through. */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 struct group* _Nullable getgrent(void) __INTRODUCED_IN(26);
 
 void setgrent(void) __INTRODUCED_IN(26);
 void endgrent(void) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int getgrgid_r(gid_t __gid, struct group* __BIONIC_COMPLICATED_NULLNESS __group, char* _Nonnull __buf, size_t __n, struct group* _Nullable * _Nonnull __result) __INTRODUCED_IN(24);
 int getgrnam_r(const char* _Nonnull __name, struct group* __BIONIC_COMPLICATED_NULLNESS __group, char* _Nonnull __buf, size_t __n, struct group* _Nullable *_Nonnull __result) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 int getgrouplist(const char* _Nonnull __user, gid_t __group, gid_t* __BIONIC_COMPLICATED_NULLNESS __groups, int* _Nonnull __group_count);
 int initgroups(const char* _Nonnull __user, gid_t __group);
 
diff --git a/libc/include/iconv.h b/libc/include/iconv.h
index 9da46b4ef..35328ee9b 100644
--- a/libc/include/iconv.h
+++ b/libc/include/iconv.h
@@ -60,6 +60,8 @@ typedef struct __iconv_t* iconv_t;
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 iconv_t _Nonnull iconv_open(const char* _Nonnull __dst_encoding, const char* _Nonnull __src_encoding) __INTRODUCED_IN(28);
 
 /**
@@ -82,5 +84,7 @@ size_t iconv(iconv_t _Nonnull __converter, char* _Nullable * _Nullable __src_buf
  * Available since API level 28.
  */
 int iconv_close(iconv_t _Nonnull __converter) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 __END_DECLS
diff --git a/libc/include/ifaddrs.h b/libc/include/ifaddrs.h
index c4d0e1065..87d29471b 100644
--- a/libc/include/ifaddrs.h
+++ b/libc/include/ifaddrs.h
@@ -80,6 +80,8 @@ struct ifaddrs {
  *
  * Available since API level 24.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int getifaddrs(struct ifaddrs* _Nullable * _Nonnull __list_ptr) __INTRODUCED_IN(24);
 
 /**
@@ -89,5 +91,7 @@ int getifaddrs(struct ifaddrs* _Nullable * _Nonnull __list_ptr) __INTRODUCED_IN(
  * Available since API level 24.
  */
 void freeifaddrs(struct ifaddrs* _Nullable __ptr) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 __END_DECLS
diff --git a/libc/include/inttypes.h b/libc/include/inttypes.h
index 9fcd9f344..790030e97 100644
--- a/libc/include/inttypes.h
+++ b/libc/include/inttypes.h
@@ -19,8 +19,8 @@
 #ifndef	_INTTYPES_H_
 #define	_INTTYPES_H_
 
-#include <stdint.h>
 #include <sys/cdefs.h>
+#include <stdint.h>
 
 #ifdef __LP64__
 #define __PRI_64_prefix  "l"
diff --git a/libc/include/langinfo.h b/libc/include/langinfo.h
index 2b43892eb..b9d695c25 100644
--- a/libc/include/langinfo.h
+++ b/libc/include/langinfo.h
@@ -92,8 +92,12 @@ __BEGIN_DECLS
 #define NOEXPR 54
 #define CRNCYSTR 55
 
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 char* _Nonnull nl_langinfo(nl_item __item) __INTRODUCED_IN(26);
 char* _Nonnull nl_langinfo_l(nl_item __item, locale_t _Nonnull __l) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 __END_DECLS
 
diff --git a/libc/include/limits.h b/libc/include/limits.h
index e1f566c83..5e9ce591f 100644
--- a/libc/include/limits.h
+++ b/libc/include/limits.h
@@ -1,6 +1,3 @@
-/*	$OpenBSD: limits.h,v 1.13 2005/12/31 19:29:38 millert Exp $	*/
-/*	$NetBSD: limits.h,v 1.7 1994/10/26 00:56:00 cgd Exp $	*/
-
 /*
  * Copyright (c) 1988 The Regents of the University of California.
  * All rights reserved.
@@ -32,108 +29,101 @@
  *	@(#)limits.h	5.9 (Berkeley) 4/3/91
  */
 
-#ifndef _LIMITS_H_
-#define _LIMITS_H_
+#pragma once
+
+/**
+ * @file limits.h
+ * @brief Constants relating to implementation limits.
+ *
+ * This file is included via `#include_next` from the clang header of the same
+ * name that provides all the limits that the compiler is responsible for,
+ * primarily those relating to integer types defined by the C standard.
+ * This file defines the additional limits defined by POSIX.
+ */
+
+/*
+ * The Android build system has bionic _before_ the clang headers,
+ * so although the claim above that clang does an `#include_next`
+ * of this file is true for the NDK, it's not true for the OS,
+ * and we need to paper over that difference here until/unless
+ * the OS build changes.
+ */
+#if __has_include_next(<limits.h>)
+#include_next <limits.h>
+#endif
 
 #include <sys/cdefs.h>
 
 /* Historically bionic exposed the content of <float.h> from <limits.h> and <sys/limits.h> too. */
 #include <float.h>
 
+/* Many of the POSIX limits come from the kernel. */
 #include <linux/limits.h>
 
-#define PASS_MAX		128	/* _PASSWORD_LEN from <pwd.h> */
-
-#define NL_ARGMAX		9
-#define NL_LANGMAX		14
-#define NL_MSGMAX		32767
-#define NL_NMAX			1
-#define NL_SETMAX		255
-#define NL_TEXTMAX		255
-
-#define TMP_MAX                 308915776
-
-/* TODO: get all these from the compiler's <limits.h>? */
-
-#define CHAR_BIT 8
-#ifdef __LP64__
-# define LONG_BIT 64
-#else
-# define LONG_BIT 32
-#endif
-#define WORD_BIT 32
-
-#define	SCHAR_MAX	0x7f		/* max value for a signed char */
-#define SCHAR_MIN	(-0x7f-1)	/* min value for a signed char */
-
-#define	UCHAR_MAX	0xffU		/* max value for an unsigned char */
-#ifdef __CHAR_UNSIGNED__
-# define CHAR_MIN	0		/* min value for a char */
-# define CHAR_MAX	0xff		/* max value for a char */
-#else
-# define CHAR_MAX	0x7f
-# define CHAR_MIN	(-0x7f-1)
-#endif
-
-#define	USHRT_MAX	0xffffU		/* max value for an unsigned short */
-#define	SHRT_MAX	0x7fff		/* max value for a short */
-#define SHRT_MIN        (-0x7fff-1)     /* min value for a short */
-
-#define	UINT_MAX	0xffffffffU	/* max value for an unsigned int */
-#define	INT_MAX		0x7fffffff	/* max value for an int */
-#define	INT_MIN		(-0x7fffffff-1)	/* min value for an int */
-
-#ifdef __LP64__
-# define ULONG_MAX	0xffffffffffffffffUL     /* max value for unsigned long */
-# define LONG_MAX	0x7fffffffffffffffL      /* max value for a signed long */
-# define LONG_MIN	(-0x7fffffffffffffffL-1) /* min value for a signed long */
-#else
-# define ULONG_MAX	0xffffffffUL	/* max value for an unsigned long */
-# define LONG_MAX	0x7fffffffL	/* max value for a long */
-# define LONG_MIN	(-0x7fffffffL-1)/* min value for a long */
-#endif
-
-# define ULLONG_MAX	0xffffffffffffffffULL     /* max value for unsigned long long */
-# define LLONG_MAX	0x7fffffffffffffffLL      /* max value for a signed long long */
-# define LLONG_MIN	(-0x7fffffffffffffffLL-1) /* min value for a signed long long */
-
-/* GLibc compatibility definitions.
-   Note that these are defined by GCC's <limits.h>
-   only when __GNU_LIBRARY__ is defined, i.e. when
-   targetting GLibc. */
+/*
+ * bionic always exposed these alternative names,
+ * but clang's <limits.h> considers them GNU extensions,
+ * and may or may not have defined them.
+ */
 #ifndef LONG_LONG_MIN
-#define LONG_LONG_MIN  LLONG_MIN
+/** Non-portable synonym; use LLONG_MIN directly instead. */
+#define LONG_LONG_MIN LLONG_MIN
 #endif
-
 #ifndef LONG_LONG_MAX
-#define LONG_LONG_MAX  LLONG_MAX
+/** Non-portable synonym; use LLONG_MAX directly instead. */
+#define LONG_LONG_MAX LLONG_MAX
 #endif
-
 #ifndef ULONG_LONG_MAX
-#define ULONG_LONG_MAX  ULLONG_MAX
+/** Non-portable synonym; use ULLONG_MAX directly instead. */
+#define ULONG_LONG_MAX ULLONG_MAX
 #endif
 
-#if defined(__USE_BSD) || defined(__BIONIC__) /* Historically bionic exposed these. */
-# define UID_MAX	UINT_MAX	/* max value for a uid_t */
-# define GID_MAX	UINT_MAX	/* max value for a gid_t */
-#if defined(__LP64__)
-#define SIZE_T_MAX ULONG_MAX
+/** Maximum number of positional arguments in a printf()/scanf() format string. */
+#define NL_ARGMAX 9
+/** Maximum number of bytes in a $LANG name. */
+#define NL_LANGMAX 14
+/** Irrelevant with Android's <nl_types.h>. */
+#define NL_MSGMAX 32767
+/** Obsolete; removed from POSIX. */
+#define NL_NMAX 1
+/** Irrelevant with Android's <nl_types.h>. */
+#define NL_SETMAX 255
+/** Irrelevant with Android's <nl_types.h>. */
+#define NL_TEXTMAX 255
+
+/** Obsolete; removed from POSIX. */
+#define PASS_MAX 128
+/** Obsolete; removed from POSIX. */
+#define TMP_MAX 308915776
+
+/** Number of bits in a `long` (POSIX). */
+#if __LP64__
+#define LONG_BIT 64
 #else
-#define SIZE_T_MAX UINT_MAX
-#endif
+#define LONG_BIT 32
 #endif
+/** Number of bits in a "word" of `int` (POSIX). */
+#define WORD_BIT 32
 
-#if defined(__LP64__)
+/** Maximum value of a uid_t. */
+#define UID_MAX UINT_MAX
+/** Maximum value of a gid_t. */
+#define GID_MAX UINT_MAX
+/** Maximum value of a size_t. */
+#define SIZE_T_MAX ULONG_MAX
+/** Maximum value of a ssize_t. */
 #define SSIZE_MAX LONG_MAX
-#else
-#define SSIZE_MAX INT_MAX
-#endif
 
+/** Maximum number of bytes in a multibyte character. */
 #define MB_LEN_MAX 4
 
+/** Default process priority. */
 #define NZERO 20
 
+/** Maximum number of struct iovec that can be passed in a single readv()/writev(). */
 #define IOV_MAX 1024
+
+/** Maximum value for a semaphore. */
 #define SEM_VALUE_MAX 0x3fffffff
 
 /** Do not use: prefer getline() or asprintf() rather than hard-coding an arbitrary size. */
@@ -142,12 +132,17 @@
 /* POSIX says these belong in <unistd.h> but BSD has some in <limits.h>. */
 #include <bits/posix_limits.h>
 
+/** Maximum length of a hostname returned by gethostname(). */
 #define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
+
+/** Maximum length of a login name. */
 #define LOGIN_NAME_MAX 256
+
+/** Maximum length of terminal device name. */
 #define TTY_NAME_MAX 32
 
-/* >= _POSIX_THREAD_DESTRUCTOR_ITERATIONS */
-#define PTHREAD_DESTRUCTOR_ITERATIONS 4
+/** Maximum number of attempts to destroy thread-specific data when a thread exits. */
+#define PTHREAD_DESTRUCTOR_ITERATIONS _POSIX_THREAD_DESTRUCTOR_ITERATIONS
 
 /**
  * The number of calls to pthread_key_create() without intervening calls to
@@ -156,7 +151,5 @@
  */
 #define PTHREAD_KEYS_MAX 128
 
-/** bionic has no specific limit on the number of threads. */
+/** bionic has no fixed limit on the number of threads. */
 #undef PTHREAD_THREADS_MAX
-
-#endif /* !_LIMITS_H_ */
diff --git a/libc/include/link.h b/libc/include/link.h
index 216502ee7..331070e41 100644
--- a/libc/include/link.h
+++ b/libc/include/link.h
@@ -33,8 +33,9 @@
  * @brief Extra dynamic linker functionality (see also <dlfcn.h>).
  */
 
-#include <stdint.h>
 #include <sys/cdefs.h>
+
+#include <stdint.h>
 #include <sys/types.h>
 
 #include <elf.h>
diff --git a/libc/include/malloc.h b/libc/include/malloc.h
index 2fa4b496d..ac2746714 100644
--- a/libc/include/malloc.h
+++ b/libc/include/malloc.h
@@ -89,9 +89,9 @@ __nodiscard void* _Nullable realloc(void* _Nullable __ptr, size_t __byte_count)
  */
 #if __ANDROID_API__ >= 29
 __nodiscard void* _Nullable reallocarray(void* _Nullable __ptr, size_t __item_count, size_t __item_size) __BIONIC_ALLOC_SIZE(2, 3) __INTRODUCED_IN(29);
-#else
+#elif defined(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)
 #include <errno.h>
-static __inline __nodiscard void* _Nullable reallocarray(void* _Nullable __ptr, size_t __item_count, size_t __item_size) {
+static __inline __nodiscard void* _Nullable reallocarray(void* _Nullable __ptr, size_t __item_count, size_t __item_size) __BIONIC_ALLOC_SIZE(2, 3) {
   size_t __new_size;
   if (__builtin_mul_overflow(__item_count, __item_size, &__new_size)) {
     errno = ENOMEM;
@@ -195,7 +195,11 @@ struct mallinfo2 mallinfo2(void) __RENAME(mallinfo);
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int malloc_info(int __must_be_zero, FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * mallopt() option to set the decay time. Valid values are -1, 0 and 1.
@@ -368,7 +372,11 @@ enum HeapTaggingLevel {
  *
  * Available since API level 26.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int mallopt(int __option, int __value) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 /**
  * [__malloc_hook(3)](https://man7.org/linux/man-pages/man3/__malloc_hook.3.html)
@@ -379,6 +387,8 @@ int mallopt(int __option, int __value) __INTRODUCED_IN(26);
  *
  * See also: [extra documentation](https://android.googlesource.com/platform/bionic/+/main/libc/malloc_hooks/README.md)
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 extern void* _Nonnull (*volatile _Nonnull __malloc_hook)(size_t __byte_count, const void* _Nonnull __caller) __INTRODUCED_IN(28);
 
 /**
@@ -413,5 +423,7 @@ extern void (*volatile _Nonnull __free_hook)(void* _Nullable __ptr, const void*
  * See also: [extra documentation](https://android.googlesource.com/platform/bionic/+/main/libc/malloc_hooks/README.md)
  */
 extern void* _Nonnull (*volatile _Nonnull __memalign_hook)(size_t __alignment, size_t __byte_count, const void* _Nonnull __caller) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 __END_DECLS
diff --git a/libc/include/math.h b/libc/include/math.h
index 343ab987f..59161bf0e 100644
--- a/libc/include/math.h
+++ b/libc/include/math.h
@@ -350,7 +350,11 @@ int isnanf(float __x) __attribute_const__;
 double gamma_r(double __x, int* _Nonnull __sign);
 double lgamma_r(double __x, int* _Nonnull __sign);
 double significand(double __x);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 long double lgammal_r(long double __x, int* _Nonnull __sign) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 long double significandl(long double __x);
 float dremf(float __x, float __y);
 int finitef(float __x) __attribute_const__;
diff --git a/libc/include/mntent.h b/libc/include/mntent.h
index 9a3183802..4c0360226 100644
--- a/libc/include/mntent.h
+++ b/libc/include/mntent.h
@@ -29,8 +29,9 @@
 #ifndef _MNTENT_H_
 #define _MNTENT_H_
 
-#include <stdio.h>
 #include <sys/cdefs.h>
+
+#include <stdio.h>
 #include <paths.h>  /* for _PATH_MOUNTED */
 
 #define MOUNTED _PATH_MOUNTED
@@ -61,7 +62,11 @@ int endmntent(FILE* _Nullable __fp);
 struct mntent* _Nullable getmntent(FILE* _Nonnull __fp);
 struct mntent* _Nullable getmntent_r(FILE* _Nonnull __fp, struct mntent* _Nonnull __entry, char* _Nonnull __buf, int __size);
 FILE* _Nullable setmntent(const char* _Nonnull __filename, const char* _Nonnull __type);
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 char* _Nullable hasmntopt(const struct mntent* _Nonnull __entry, const char* _Nonnull __option) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 __END_DECLS
 
diff --git a/libc/include/net/if.h b/libc/include/net/if.h
index 79b41956b..50bc74c8b 100644
--- a/libc/include/net/if.h
+++ b/libc/include/net/if.h
@@ -29,9 +29,10 @@
 #ifndef _NET_IF_H_
 #define _NET_IF_H_
 
+#include <sys/cdefs.h>
+
 #include <sys/socket.h>
 #include <linux/if.h>
-#include <sys/cdefs.h>
 
 #ifndef IF_NAMESIZE
 #define IF_NAMESIZE IFNAMSIZ
@@ -46,8 +47,12 @@ struct if_nameindex {
 
 char* _Nullable if_indextoname(unsigned __index, char* _Nonnull __buf);
 unsigned if_nametoindex(const char* _Nonnull __name);
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 struct if_nameindex* _Nullable if_nameindex(void) __INTRODUCED_IN(24);
 void if_freenameindex(struct if_nameindex* _Nullable __ptr) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 __END_DECLS
 
diff --git a/libc/include/netdb.h b/libc/include/netdb.h
index 88214d589..04aaf5cfd 100644
--- a/libc/include/netdb.h
+++ b/libc/include/netdb.h
@@ -212,28 +212,52 @@ int* _Nonnull __get_h_errno(void);
 void herror(const char* _Nonnull __s);
 const char* _Nonnull hstrerror(int __error);
 struct hostent* _Nullable gethostbyaddr(const void* _Nonnull __addr, socklen_t __length, int __type);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int gethostbyaddr_r(const void* _Nonnull __addr, socklen_t __length, int __type, struct hostent* _Nonnull __ret, char* _Nonnull __buf, size_t __buf_size, struct hostent* _Nullable * _Nonnull __result, int* _Nonnull __h_errno_ptr) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 struct hostent* _Nullable gethostbyname(const char* _Nonnull __name);
 int gethostbyname_r(const char* _Nonnull __name, struct hostent* _Nonnull __ret, char* _Nonnull __buf, size_t __buf_size, struct hostent* _Nullable * _Nonnull __result, int* _Nonnull __h_errno_ptr);
 struct hostent* _Nullable gethostbyname2(const char* _Nonnull __name, int __af);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int gethostbyname2_r(const char* _Nonnull __name, int __af, struct hostent* _Nonnull __ret, char* _Nonnull __buf, size_t __buf_size, struct hostent* _Nullable * _Nonnull __result, int* _Nonnull __h_errno_ptr) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 void endhostent(void) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 struct hostent* _Nullable gethostent(void);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 void sethostent(int __stay_open) __INTRODUCED_IN(28);
 
 /* These functions are obsolete. None of these functions return anything but nullptr. */
 void endnetent(void) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 struct netent* _Nullable getnetbyaddr(uint32_t __net, int __type);
 struct netent* _Nullable getnetbyname(const char* _Nonnull __name);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 struct netent* _Nullable getnetent(void) __INTRODUCED_IN(28);
 void setnetent(int __stay_open) __INTRODUCED_IN(28);
 
 /* None of these functions return anything but nullptr. */
 void endprotoent(void) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 struct protoent* _Nullable getprotobyname(const char* _Nonnull __name);
 struct protoent* _Nullable getprotobynumber(int __proto);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 struct protoent* _Nullable getprotoent(void) __INTRODUCED_IN(28);
 void setprotoent(int __stay_open) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 /* These functions return entries from a built-in database. */
 void endservent(void);
diff --git a/libc/include/netinet/icmp6.h b/libc/include/netinet/icmp6.h
index 2b237a87e..ebd9f6ca7 100644
--- a/libc/include/netinet/icmp6.h
+++ b/libc/include/netinet/icmp6.h
@@ -65,9 +65,10 @@
 #ifndef _NETINET_ICMP6_H_
 #define _NETINET_ICMP6_H_
 
-#include <netinet/in.h> /* android-added: glibc source compatibility. */
 #include <sys/cdefs.h>
 
+#include <netinet/in.h> /* android-added: glibc source compatibility. */
+
 #define ICMPV6_PLD_MAXLEN	1232	/* IPV6_MMTU - sizeof(struct ip6_hdr)
 					   - sizeof(struct icmp6_hdr) */
 
diff --git a/libc/include/netinet/in.h b/libc/include/netinet/in.h
index 163e614d9..d4ce30271 100644
--- a/libc/include/netinet/in.h
+++ b/libc/include/netinet/in.h
@@ -28,9 +28,10 @@
 
 #pragma once
 
+#include <sys/cdefs.h>
+
 #include <endian.h>
 #include <netinet/in6.h>
-#include <sys/cdefs.h>
 #include <sys/socket.h>
 
 #include <linux/in.h>
diff --git a/libc/include/nl_types.h b/libc/include/nl_types.h
index 6c9935dbc..172d80d91 100644
--- a/libc/include/nl_types.h
+++ b/libc/include/nl_types.h
@@ -62,6 +62,8 @@ typedef int nl_item;
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 nl_catd _Nonnull catopen(const char* _Nonnull __name, int __flag) __INTRODUCED_IN(26);
 
 /**
@@ -80,5 +82,7 @@ char* _Nonnull catgets(nl_catd _Nonnull __catalog, int __set_number, int __msg_n
  * On Android, this always returns -1 with `errno` set to `EBADF`.
  */
 int catclose(nl_catd _Nonnull __catalog) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 __END_DECLS
diff --git a/libc/include/poll.h b/libc/include/poll.h
index 0dda3da08..e57f81275 100644
--- a/libc/include/poll.h
+++ b/libc/include/poll.h
@@ -64,7 +64,11 @@ int ppoll(struct pollfd* _Nullable __fds, nfds_t __count, const struct timespec*
 /**
  * Like ppoll() but allows setting a signal mask with RT signals even from a 32-bit process.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int ppoll64(struct pollfd* _Nullable  __fds, nfds_t __count, const struct timespec* _Nullable __timeout, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 #if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
 #define _POLL_H_
diff --git a/libc/include/pthread.h b/libc/include/pthread.h
index d718b401b..cdf1b8c6c 100644
--- a/libc/include/pthread.h
+++ b/libc/include/pthread.h
@@ -33,11 +33,12 @@
  * @brief POSIX threads.
  */
 
+#include <sys/cdefs.h>
+
 #include <limits.h>
 #include <bits/page_size.h>
 #include <bits/pthread_types.h>
 #include <sched.h>
-#include <sys/cdefs.h>
 #include <sys/types.h>
 #include <time.h>
 
@@ -98,7 +99,11 @@ int pthread_atfork(void (* _Nullable __prepare)(void), void (* _Nullable __paren
 int pthread_attr_destroy(pthread_attr_t* _Nonnull __attr);
 int pthread_attr_getdetachstate(const pthread_attr_t* _Nonnull __attr, int* _Nonnull __state);
 int pthread_attr_getguardsize(const pthread_attr_t* _Nonnull __attr, size_t* _Nonnull __size);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_attr_getinheritsched(const pthread_attr_t* _Nonnull __attr, int* _Nonnull __flag) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int pthread_attr_getschedparam(const pthread_attr_t* _Nonnull __attr, struct sched_param* _Nonnull __param);
 int pthread_attr_getschedpolicy(const pthread_attr_t* _Nonnull __attr, int* _Nonnull __policy);
 int pthread_attr_getscope(const pthread_attr_t* _Nonnull __attr, int* _Nonnull __scope);
@@ -107,7 +112,11 @@ int pthread_attr_getstacksize(const pthread_attr_t* _Nonnull __attr, size_t* _No
 int pthread_attr_init(pthread_attr_t* _Nonnull __attr);
 int pthread_attr_setdetachstate(pthread_attr_t* _Nonnull __attr, int __state);
 int pthread_attr_setguardsize(pthread_attr_t* _Nonnull __attr, size_t __size);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_attr_setinheritsched(pthread_attr_t* _Nonnull __attr, int __flag) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int pthread_attr_setschedparam(pthread_attr_t* _Nonnull __attr, const struct sched_param* _Nonnull __param);
 int pthread_attr_setschedpolicy(pthread_attr_t* _Nonnull __attr, int __policy);
 int pthread_attr_setscope(pthread_attr_t* _Nonnull __attr, int __scope);
@@ -122,8 +131,12 @@ int pthread_condattr_setclock(pthread_condattr_t* _Nonnull __attr, clockid_t __c
 int pthread_condattr_setpshared(pthread_condattr_t* _Nonnull __attr, int __shared);
 
 int pthread_cond_broadcast(pthread_cond_t* _Nonnull __cond);
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 int pthread_cond_clockwait(pthread_cond_t* _Nonnull __cond, pthread_mutex_t* _Nonnull __mutex, clockid_t __clock,
                            const struct timespec* _Nullable __timeout) __INTRODUCED_IN(30);
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 int pthread_cond_destroy(pthread_cond_t* _Nonnull __cond);
 int pthread_cond_init(pthread_cond_t* _Nonnull __cond, const pthread_condattr_t* _Nullable __attr);
 int pthread_cond_signal(pthread_cond_t* _Nonnull __cond);
@@ -138,8 +151,12 @@ int pthread_cond_timedwait(pthread_cond_t* _Nonnull __cond, pthread_mutex_t* _No
  * Note that pthread_cond_clockwait() allows specifying an arbitrary clock and has superseded this
  * function.
  */
+
+#if (!defined(__LP64__)) || (defined(__LP64__) && __ANDROID_API__ >= 28)
 int pthread_cond_timedwait_monotonic_np(pthread_cond_t* _Nonnull __cond, pthread_mutex_t* _Nonnull __mutex,
                                         const struct timespec* _Nullable __timeout) __INTRODUCED_IN_64(28);
+#endif /* (!defined(__LP64__)) || (defined(__LP64__) && __ANDROID_API__ >= 28) */
+
 int pthread_cond_wait(pthread_cond_t* _Nonnull __cond, pthread_mutex_t* _Nonnull __mutex);
 
 int pthread_create(pthread_t* _Nonnull __pthread_ptr, pthread_attr_t const* _Nullable __attr, void* _Nullable (* _Nonnull __start_routine)(void* _Nullable), void* _Nullable);
@@ -187,14 +204,26 @@ int pthread_key_delete(pthread_key_t __key);
 int pthread_mutexattr_destroy(pthread_mutexattr_t* _Nonnull __attr);
 int pthread_mutexattr_getpshared(const pthread_mutexattr_t* _Nonnull __attr, int* _Nonnull __shared);
 int pthread_mutexattr_gettype(const pthread_mutexattr_t* _Nonnull __attr, int* _Nonnull __type);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_mutexattr_getprotocol(const pthread_mutexattr_t* _Nonnull __attr, int* _Nonnull __protocol) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int pthread_mutexattr_init(pthread_mutexattr_t* _Nonnull __attr);
 int pthread_mutexattr_setpshared(pthread_mutexattr_t* _Nonnull __attr, int __shared);
 int pthread_mutexattr_settype(pthread_mutexattr_t* _Nonnull __attr, int __type);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_mutexattr_setprotocol(pthread_mutexattr_t* _Nonnull __attr, int __protocol) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
 
+
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 int pthread_mutex_clocklock(pthread_mutex_t* _Nonnull __mutex, clockid_t __clock,
                             const struct timespec* _Nullable __abstime) __INTRODUCED_IN(30);
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 int pthread_mutex_destroy(pthread_mutex_t* _Nonnull __mutex);
 int pthread_mutex_init(pthread_mutex_t* _Nonnull __mutex, const pthread_mutexattr_t* _Nullable __attr);
 int pthread_mutex_lock(pthread_mutex_t* _Nonnull __mutex);
@@ -209,8 +238,12 @@ int pthread_mutex_timedlock(pthread_mutex_t* _Nonnull __mutex, const struct time
  * Note that pthread_mutex_clocklock() allows specifying an arbitrary clock and has superseded this
  * function.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_mutex_timedlock_monotonic_np(pthread_mutex_t* _Nonnull __mutex, const struct timespec* _Nullable __timeout)
     __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int pthread_mutex_trylock(pthread_mutex_t* _Nonnull __mutex);
 int pthread_mutex_unlock(pthread_mutex_t* _Nonnull __mutex);
 
@@ -220,30 +253,48 @@ int pthread_rwlockattr_init(pthread_rwlockattr_t* _Nonnull __attr);
 int pthread_rwlockattr_destroy(pthread_rwlockattr_t* _Nonnull __attr);
 int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t* _Nonnull __attr, int* _Nonnull __shared);
 int pthread_rwlockattr_setpshared(pthread_rwlockattr_t* _Nonnull __attr, int __shared);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int pthread_rwlockattr_getkind_np(const pthread_rwlockattr_t* _Nonnull __attr, int* _Nonnull __kind)
   __INTRODUCED_IN(23);
 int pthread_rwlockattr_setkind_np(pthread_rwlockattr_t* _Nonnull __attr, int __kind) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 int pthread_rwlock_clockrdlock(pthread_rwlock_t* _Nonnull __rwlock, clockid_t __clock,
                                const struct timespec* _Nullable __timeout) __INTRODUCED_IN(30);
 int pthread_rwlock_clockwrlock(pthread_rwlock_t* _Nonnull __rwlock, clockid_t __clock,
                                const struct timespec* _Nullable __timeout) __INTRODUCED_IN(30);
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 int pthread_rwlock_destroy(pthread_rwlock_t* _Nonnull __rwlock);
 int pthread_rwlock_init(pthread_rwlock_t* _Nonnull __rwlock, const pthread_rwlockattr_t* _Nullable __attr);
 int pthread_rwlock_rdlock(pthread_rwlock_t* _Nonnull __rwlock);
 int pthread_rwlock_timedrdlock(pthread_rwlock_t* _Nonnull __rwlock, const struct timespec* _Nullable __timeout);
 /* See the comment on pthread_mutex_timedlock_monotonic_np for usage of this function. */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_rwlock_timedrdlock_monotonic_np(pthread_rwlock_t* _Nonnull __rwlock,
                                             const struct timespec* _Nullable __timeout) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int pthread_rwlock_timedwrlock(pthread_rwlock_t* _Nonnull __rwlock, const struct timespec* _Nullable __timeout);
 /* See the comment on pthread_mutex_timedlock_monotonic_np for usage of this function. */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_rwlock_timedwrlock_monotonic_np(pthread_rwlock_t* _Nonnull __rwlock,
                                             const struct timespec* _Nullable __timeout) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int pthread_rwlock_tryrdlock(pthread_rwlock_t* _Nonnull __rwlock);
 int pthread_rwlock_trywrlock(pthread_rwlock_t* _Nonnull __rwlock);
 int pthread_rwlock_unlock(pthread_rwlock_t* _Nonnull __rwlock);
 int pthread_rwlock_wrlock(pthread_rwlock_t* _Nonnull __rwlock);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int pthread_barrierattr_init(pthread_barrierattr_t* _Nonnull __attr) __INTRODUCED_IN(24);
 int pthread_barrierattr_destroy(pthread_barrierattr_t* _Nonnull __attr) __INTRODUCED_IN(24);
 int pthread_barrierattr_getpshared(const pthread_barrierattr_t* _Nonnull __attr, int* _Nonnull __shared) __INTRODUCED_IN(24);
@@ -258,15 +309,64 @@ int pthread_spin_init(pthread_spinlock_t* _Nonnull __spinlock, int __shared) __I
 int pthread_spin_lock(pthread_spinlock_t* _Nonnull __spinlock) __INTRODUCED_IN(24);
 int pthread_spin_trylock(pthread_spinlock_t* _Nonnull __spinlock) __INTRODUCED_IN(24);
 int pthread_spin_unlock(pthread_spinlock_t* _Nonnull __spinlock) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 pthread_t pthread_self(void) __attribute_const__;
 
-#if defined(__USE_GNU)
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(26)
+/**
+ * [pthread_getname_np(3)](https://man7.org/linux/man-pages/man3/pthread_getname_np.3.html)
+ * gets the name of the given thread.
+ * Names are at most 16 bytes (including '\0').
+ *
+ * Returns 0 on success and returns an error number on failure.
+ *
+ * Available since API level 26.
+ */
 int pthread_getname_np(pthread_t __pthread, char* _Nonnull __buf, size_t __n) __INTRODUCED_IN(26);
 #endif
-/* TODO: this should be __USE_GNU too. */
+
+/**
+ * [pthread_setname_np(3)](https://man7.org/linux/man-pages/man3/pthread_setname_np.3.html)
+ * sets the name of the given thread.
+ * Names are at most 16 bytes (including '\0').
+ * Truncation must be done by the caller;
+ * calls with longer names will fail with ERANGE.
+ *
+ * Returns 0 on success and returns an error number on failure.
+ *
+ * This should only have been available under _GNU_SOURCE,
+ * but is always available on Android by historical accident.
+ */
 int pthread_setname_np(pthread_t __pthread, const char* _Nonnull __name);
 
+/**
+ * [pthread_getaffinity_np(3)](https://man7.org/linux/man-pages/man3/pthread_getaffinity_np.3.html)
+ * gets the CPU affinity mask for the given thread.
+ *
+ * Returns 0 on success and returns an error number on failure.
+ *
+ * Available since API level 36.
+ * See sched_getaffinity() and pthread_gettid_np() for greater portability.
+ */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(36)
+int pthread_getaffinity_np(pthread_t __pthread, size_t __cpu_set_size, cpu_set_t* __cpu_set) __INTRODUCED_IN(36);
+#endif
+
+/**
+ * [pthread_setaffinity_np(3)](https://man7.org/linux/man-pages/man3/pthread_setaffinity_np.3.html)
+ * sets the CPU affinity mask for the given thread.
+ *
+ * Returns 0 on success and returns an error number on failure.
+ *
+ * Available since API level 36.
+ * See sched_getaffinity() and pthread_gettid_np() for greater portability.
+ */
+#if defined(__USE_GNU) && __BIONIC_AVAILABILITY_GUARD(36)
+int pthread_setaffinity_np(pthread_t __pthread, size_t __cpu_set_size, const cpu_set_t* __cpu_set) __INTRODUCED_IN(36);
+#endif
+
 /**
  * [pthread_setschedparam(3)](https://man7.org/linux/man-pages/man3/pthread_setschedparam.3.html)
  * sets the scheduler policy and parameters of the given thread.
@@ -301,7 +401,11 @@ int pthread_getschedparam(pthread_t __pthread, int* _Nonnull __policy, struct sc
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_setschedprio(pthread_t __pthread, int __priority) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 int pthread_setspecific(pthread_key_t __key, const void* _Nullable __value);
 
diff --git a/libc/include/pty.h b/libc/include/pty.h
index 1cfb77238..92d7fbb82 100644
--- a/libc/include/pty.h
+++ b/libc/include/pty.h
@@ -49,6 +49,8 @@ __BEGIN_DECLS
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int openpty(int* _Nonnull __pty_fd, int* _Nonnull __tty_fd, char* _Nullable __tty_name, const struct termios* _Nullable __termios_ptr, const struct winsize* _Nullable __winsize_ptr) __INTRODUCED_IN(23);
 
 /**
@@ -61,5 +63,7 @@ int openpty(int* _Nonnull __pty_fd, int* _Nonnull __tty_fd, char* _Nullable __tt
  * Available since API level 23.
  */
 int forkpty(int* _Nonnull __parent_pty_fd, char* _Nullable __child_tty_name, const struct termios* _Nullable __termios_ptr, const struct winsize* _Nullable __winsize_ptr) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 __END_DECLS
diff --git a/libc/include/pwd.h b/libc/include/pwd.h
index 2b17fbfb2..09592bcc2 100644
--- a/libc/include/pwd.h
+++ b/libc/include/pwd.h
@@ -84,10 +84,14 @@ struct passwd* _Nullable getpwnam(const char* _Nonnull __name);
 struct passwd* _Nullable getpwuid(uid_t __uid);
 
 /* Note: Android has thousands and thousands of ids to iterate through */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 struct passwd* _Nullable getpwent(void) __INTRODUCED_IN(26);
 
 void setpwent(void) __INTRODUCED_IN(26);
 void endpwent(void) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 int getpwnam_r(const char* _Nonnull __name, struct passwd* _Nonnull __pwd, char* _Nonnull __buf, size_t __n, struct passwd* _Nullable * _Nonnull __result);
 int getpwuid_r(uid_t __uid, struct passwd* _Nonnull __pwd, char* _Nonnull __buf, size_t __n, struct passwd* _Nullable * _Nonnull __result);
diff --git a/libc/include/resolv.h b/libc/include/resolv.h
index f25484a8d..c49cefc5f 100644
--- a/libc/include/resolv.h
+++ b/libc/include/resolv.h
@@ -29,9 +29,10 @@
 #ifndef _RESOLV_H_
 #define _RESOLV_H_
 
+#include <sys/cdefs.h>
+
 #include <sys/param.h>
 #include <sys/types.h>
-#include <sys/cdefs.h>
 #include <sys/socket.h>
 #include <stdio.h>
 #include <arpa/nameser.h>
@@ -60,7 +61,11 @@ int res_query(const char* _Nonnull __name, int __class, int __type, u_char* _Non
 int res_search(const char* _Nonnull __name, int __class, int __type, u_char* _Nonnull __answer, int __answer_size);
 
 #define res_randomid __res_randomid
+
+#if __BIONIC_AVAILABILITY_GUARD(29)
 u_int __res_randomid(void) __INTRODUCED_IN(29);
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
+
 
 __END_DECLS
 
diff --git a/libc/include/sched.h b/libc/include/sched.h
index e8f773672..7a2dcade8 100644
--- a/libc/include/sched.h
+++ b/libc/include/sched.h
@@ -33,9 +33,10 @@
  * @brief Thread execution scheduling.
  */
 
+#include <sys/cdefs.h>
+
 #include <bits/timespec.h>
 #include <linux/sched.h>
-#include <sys/cdefs.h>
 
 __BEGIN_DECLS
 
diff --git a/libc/include/search.h b/libc/include/search.h
index 85e31ee4c..2f43d91f2 100644
--- a/libc/include/search.h
+++ b/libc/include/search.h
@@ -85,6 +85,8 @@ void remque(void* _Nonnull __element);
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int hcreate(size_t __n) __INTRODUCED_IN(28);
 
 /**
@@ -109,6 +111,8 @@ void hdestroy(void) __INTRODUCED_IN(28);
  * Available since API level 28.
  */
 ENTRY* _Nullable hsearch(ENTRY __entry, ACTION __action) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 #if defined(__USE_BSD) || defined(__USE_GNU)
 
@@ -120,6 +124,8 @@ ENTRY* _Nullable hsearch(ENTRY __entry, ACTION __action) __INTRODUCED_IN(28);
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int hcreate_r(size_t __n, struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);
 
 /**
@@ -140,6 +146,8 @@ void hdestroy_r(struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);
  * Available since API level 28.
  */
 int hsearch_r(ENTRY __entry, ACTION __action, ENTRY* _Nullable * _Nonnull __result, struct hsearch_data* _Nonnull __table) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 #endif
 
diff --git a/libc/include/semaphore.h b/libc/include/semaphore.h
index 6ad9ea3ad..9c4702db6 100644
--- a/libc/include/semaphore.h
+++ b/libc/include/semaphore.h
@@ -45,7 +45,11 @@ typedef struct {
 
 #define SEM_FAILED __BIONIC_CAST(reinterpret_cast, sem_t*, 0)
 
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 int sem_clockwait(sem_t* _Nonnull __sem, clockid_t __clock, const struct timespec* _Nonnull __ts) __INTRODUCED_IN(30);
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 int sem_destroy(sem_t* _Nonnull __sem);
 int sem_getvalue(sem_t* _Nonnull __sem, int* _Nonnull __value);
 int sem_init(sem_t* _Nonnull __sem, int __shared, unsigned int __value);
@@ -59,7 +63,11 @@ int sem_timedwait(sem_t* _Nonnull __sem, const struct timespec* _Nonnull __ts);
  * Note that sem_clockwait() allows specifying an arbitrary clock and has superseded this
  * function.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sem_timedwait_monotonic_np(sem_t* _Nonnull __sem, const struct timespec* _Nonnull __ts) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int sem_trywait(sem_t* _Nonnull __sem);
 int sem_wait(sem_t* _Nonnull __sem);
 
diff --git a/libc/include/signal.h b/libc/include/signal.h
index 893fa9d4f..38dcbde3f 100644
--- a/libc/include/signal.h
+++ b/libc/include/signal.h
@@ -60,31 +60,73 @@ extern const char* _Nonnull const sys_signame[_NSIG]; /* BSD compatibility. */
 #define si_timerid si_tid /* glibc compatibility. */
 
 int sigaction(int __signal, const struct sigaction* _Nullable __new_action, struct sigaction* _Nullable __old_action);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigaction64(int __signal, const struct sigaction64* _Nullable __new_action, struct sigaction64* _Nullable __old_action) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 int siginterrupt(int __signal, int __flag);
 
 sighandler_t _Nonnull signal(int __signal, sighandler_t _Nullable __handler);
 int sigaddset(sigset_t* _Nonnull __set, int __signal);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigaddset64(sigset64_t* _Nonnull __set, int __signal) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int sigdelset(sigset_t* _Nonnull __set, int __signal);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigdelset64(sigset64_t* _Nonnull __set, int __signal) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int sigemptyset(sigset_t* _Nonnull __set);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigemptyset64(sigset64_t* _Nonnull __set) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int sigfillset(sigset_t* _Nonnull __set);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigfillset64(sigset64_t* _Nonnull __set) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int sigismember(const sigset_t* _Nonnull __set, int __signal);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigismember64(const sigset64_t* _Nonnull __set, int __signal) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 int sigpending(sigset_t* _Nonnull __set);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigpending64(sigset64_t* _Nonnull __set) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int sigprocmask(int __how, const sigset_t* _Nullable __new_set, sigset_t* _Nullable __old_set);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigprocmask64(int __how, const sigset64_t* _Nullable __new_set, sigset64_t* _Nullable __old_set) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int sigsuspend(const sigset_t* _Nonnull __mask);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigsuspend64(const sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 int sigwait(const sigset_t* _Nonnull __set, int* _Nonnull __signal);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigwait64(const sigset64_t* _Nonnull __set, int* _Nonnull __signal) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
+
 
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int sighold(int __signal)
   __attribute__((__deprecated__("use sigprocmask() or pthread_sigmask() instead")))
   __INTRODUCED_IN(26);
@@ -97,6 +139,8 @@ int sigrelse(int __signal)
   __INTRODUCED_IN(26);
 sighandler_t _Nonnull sigset(int __signal, sighandler_t _Nullable __handler)
   __attribute__((__deprecated__("use sigaction() instead"))) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 int raise(int __signal);
 int kill(pid_t __pid, int __signal);
@@ -110,17 +154,41 @@ void psignal(int __signal, const char* _Nullable __msg);
 
 int pthread_kill(pthread_t __pthread, int __signal);
 #if defined(__USE_GNU)
+
+#if __BIONIC_AVAILABILITY_GUARD(29)
 int pthread_sigqueue(pthread_t __pthread, int __signal, const union sigval __value) __INTRODUCED_IN(29);
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
+
 #endif
 
 int pthread_sigmask(int __how, const sigset_t* _Nullable __new_set, sigset_t* _Nullable __old_set);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pthread_sigmask64(int __how, const sigset64_t* _Nullable __new_set, sigset64_t* _Nullable __old_set) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
+
 
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int sigqueue(pid_t __pid, int __signal, const union sigval __value) __INTRODUCED_IN(23);
 int sigtimedwait(const sigset_t* _Nonnull __set, siginfo_t* _Nullable __info, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigtimedwait64(const sigset64_t* _Nonnull __set, siginfo_t* _Nullable __info, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int sigwaitinfo(const sigset_t* _Nonnull __set, siginfo_t* _Nullable __info) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int sigwaitinfo64(const sigset64_t* _Nonnull __set, siginfo_t* _Nullable __info) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 /**
  * Buffer size suitable for any call to sig2str().
@@ -137,6 +205,8 @@ int sigwaitinfo64(const sigset64_t* _Nonnull __set, siginfo_t* _Nullable __info)
  *
  * Available since API level 36.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(36)
 int sig2str(int __signal, char* _Nonnull __buf) __INTRODUCED_IN(36);
 
 /**
@@ -149,6 +219,8 @@ int sig2str(int __signal, char* _Nonnull __buf) __INTRODUCED_IN(36);
  * Available since API level 36.
  */
 int str2sig(const char* _Nonnull __name, int* _Nonnull __signal) __INTRODUCED_IN(36);
+#endif /* __BIONIC_AVAILABILITY_GUARD(36) */
+
 
 __END_DECLS
 
diff --git a/libc/include/spawn.h b/libc/include/spawn.h
index f36623953..b1057541e 100644
--- a/libc/include/spawn.h
+++ b/libc/include/spawn.h
@@ -55,6 +55,8 @@ __BEGIN_DECLS
 typedef struct __posix_spawnattr* posix_spawnattr_t;
 typedef struct __posix_spawn_file_actions* posix_spawn_file_actions_t;
 
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int posix_spawn(pid_t* _Nullable __pid, const char* _Nonnull __path, const posix_spawn_file_actions_t _Nullable * _Nullable __actions, const posix_spawnattr_t _Nullable * _Nullable __attr, char* const _Nullable __argv[_Nullable], char* const _Nullable __env[_Nullable]) __INTRODUCED_IN(28);
 int posix_spawnp(pid_t* _Nullable __pid, const char* _Nonnull __file, const posix_spawn_file_actions_t _Nullable * _Nullable __actions, const posix_spawnattr_t _Nullable * _Nullable __attr, char* const _Nullable __argv[_Nullable], char* const _Nullable __env[_Nullable]) __INTRODUCED_IN(28);
 
@@ -89,9 +91,15 @@ int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t _Nonnull * _Nonn
 int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd, const char* _Nonnull __path, int __flags, mode_t __mode) __INTRODUCED_IN(28);
 int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd) __INTRODUCED_IN(28);
 int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd, int __new_fd) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
+
+#if __BIONIC_AVAILABILITY_GUARD(34)
 int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, const char* _Nonnull __path) __INTRODUCED_IN(34);
 int posix_spawn_file_actions_addfchdir_np(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd) __INTRODUCED_IN(34);
+#endif /* __BIONIC_AVAILABILITY_GUARD(34) */
+
 
 __END_DECLS
 
diff --git a/libc/include/stdint.h b/libc/include/stdint.h
index 322a81ce1..772fe8b60 100644
--- a/libc/include/stdint.h
+++ b/libc/include/stdint.h
@@ -29,9 +29,10 @@
 #ifndef _STDINT_H
 #define _STDINT_H
 
+#include <sys/cdefs.h>
+
 #include <bits/wchar_limits.h>
 #include <stddef.h>
-#include <sys/cdefs.h>
 
 typedef signed char __int8_t;
 typedef unsigned char __uint8_t;
diff --git a/libc/include/stdio.h b/libc/include/stdio.h
index d24f6affa..2c2dc0173 100644
--- a/libc/include/stdio.h
+++ b/libc/include/stdio.h
@@ -196,7 +196,11 @@ int renameat(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 int renameat2(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path, unsigned __flags) __INTRODUCED_IN(30);
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 
 #endif
 
@@ -205,17 +209,25 @@ __nodiscard long ftell(FILE* _Nonnull __fp);
 
 /* See https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md */
 #if defined(__USE_FILE_OFFSET64)
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int fgetpos(FILE* _Nonnull __fp, fpos_t* _Nonnull __pos) __RENAME(fgetpos64) __INTRODUCED_IN(24);
 int fsetpos(FILE* _Nonnull __fp, const fpos_t* _Nonnull __pos) __RENAME(fsetpos64) __INTRODUCED_IN(24);
 int fseeko(FILE* _Nonnull __fp, off_t __offset, int __whence) __RENAME(fseeko64) __INTRODUCED_IN(24);
 __nodiscard off_t ftello(FILE* _Nonnull __fp) __RENAME(ftello64) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 #  if defined(__USE_BSD)
 /* If __read_fn and __write_fn are both nullptr, it will cause EINVAL */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard FILE* _Nullable funopen(const void* _Nullable __cookie,
               int (* __BIONIC_COMPLICATED_NULLNESS __read_fn)(void* _Nonnull, char* _Nonnull, int),
               int (* __BIONIC_COMPLICATED_NULLNESS __write_fn)(void* _Nonnull, const char* _Nonnull, int),
               fpos_t (* _Nullable __seek_fn)(void* _Nonnull, fpos_t, int),
               int (* _Nullable __close_fn)(void* _Nonnull)) __RENAME(funopen64) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 #  endif
 #else
 int fgetpos(FILE* _Nonnull __fp, fpos_t* _Nonnull __pos);
@@ -231,25 +243,45 @@ __nodiscard FILE* _Nullable funopen(const void* _Nullable __cookie,
               int (* _Nullable __close_fn)(void* _Nonnull));
 #  endif
 #endif
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int fgetpos64(FILE* _Nonnull __fp, fpos64_t* _Nonnull __pos) __INTRODUCED_IN(24);
 int fsetpos64(FILE* _Nonnull __fp, const fpos64_t* _Nonnull __pos) __INTRODUCED_IN(24);
 int fseeko64(FILE* _Nonnull __fp, off64_t __offset, int __whence) __INTRODUCED_IN(24);
 __nodiscard off64_t ftello64(FILE* _Nonnull __fp) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 #if defined(__USE_BSD)
 /* If __read_fn and __write_fn are both nullptr, it will cause EINVAL */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard FILE* _Nullable funopen64(const void* _Nullable __cookie,
                 int (* __BIONIC_COMPLICATED_NULLNESS __read_fn)(void* _Nonnull, char* _Nonnull, int),
                 int (* __BIONIC_COMPLICATED_NULLNESS __write_fn)(void* _Nonnull, const char* _Nonnull, int),
                 fpos64_t (* _Nullable __seek_fn)(void* _Nonnull, fpos64_t, int),
                 int (* _Nullable __close_fn)(void* _Nonnull)) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 #endif
 
 __nodiscard FILE* _Nullable fopen(const char* _Nonnull __path, const char* _Nonnull __mode);
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard FILE* _Nullable fopen64(const char* _Nonnull __path, const char* _Nonnull __mode) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 FILE* _Nullable freopen(const char* _Nullable __path, const char* _Nonnull __mode, FILE* _Nonnull __fp);
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 FILE* _Nullable freopen64(const char* _Nullable __path, const char* _Nonnull __mode, FILE* _Nonnull __fp) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 __nodiscard FILE* _Nullable tmpfile(void);
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard FILE* _Nullable tmpfile64(void) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 int snprintf(char* __BIONIC_COMPLICATED_NULLNESS __buf, size_t __size, const char* _Nonnull __fmt, ...) __printflike(3, 4);
 int vfscanf(FILE* _Nonnull __fp, const char* _Nonnull __fmt, va_list __args) __scanflike(2, 0);
@@ -258,7 +290,11 @@ int vsnprintf(char* __BIONIC_COMPLICATED_NULLNESS __buf, size_t __size, const ch
 int vsscanf(const char* _Nonnull __s, const char* _Nonnull __fmt, va_list __args) __scanflike(2, 0);
 
 #define L_ctermid 1024 /* size for ctermid() */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 char* _Nonnull ctermid(char* _Nullable __buf) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 __nodiscard FILE* _Nullable fdopen(int __fd, const char* _Nonnull __mode);
 __nodiscard int fileno(FILE* _Nonnull __fp);
@@ -272,8 +308,12 @@ __nodiscard int getchar_unlocked(void);
 int putc_unlocked(int __ch, FILE* _Nonnull __fp);
 int putchar_unlocked(int __ch);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 __nodiscard FILE* _Nullable fmemopen(void* _Nullable __buf, size_t __size, const char* _Nonnull __mode) __INTRODUCED_IN(23);
 __nodiscard FILE* _Nullable open_memstream(char* _Nonnull * _Nonnull __ptr, size_t* _Nonnull __size_ptr) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 #if defined(__USE_BSD) || defined(__BIONIC__) /* Historically bionic exposed these. */
 int  asprintf(char* _Nullable * _Nonnull __s_ptr, const char* _Nonnull __fmt, ...) __printflike(2, 3);
@@ -282,25 +322,41 @@ int fpurge(FILE* _Nonnull __fp);
 void setbuffer(FILE* _Nonnull __fp, char* _Nullable __buf, int __size);
 int setlinebuf(FILE* _Nonnull __fp);
 int vasprintf(char* _Nullable * _Nonnull __s_ptr, const char* _Nonnull __fmt, va_list __args) __printflike(2, 0);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void clearerr_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 __nodiscard int feof_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 __nodiscard int ferror_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 __nodiscard int fileno_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 #define fropen(cookie, fn) funopen(cookie, fn, 0, 0, 0)
 #define fwopen(cookie, fn) funopen(cookie, 0, fn, 0, 0)
 #endif
 
 #if defined(__USE_BSD)
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int fflush_unlocked(FILE* _Nullable __fp) __INTRODUCED_IN(28);
 __nodiscard int fgetc_unlocked(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 int fputc_unlocked(int __ch, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 size_t fread_unlocked(void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 size_t fwrite_unlocked(const void* _Nonnull __buf, size_t __size, size_t __count, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 #endif
 
 #if defined(__USE_GNU)
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int fputs_unlocked(const char* _Nonnull __s, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
 char* _Nullable fgets_unlocked(char* _Nonnull __buf, int __size, FILE* _Nonnull __fp) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 #endif
 
 #if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
diff --git a/libc/include/stdio_ext.h b/libc/include/stdio_ext.h
index d426a4a23..9ff07da61 100644
--- a/libc/include/stdio_ext.h
+++ b/libc/include/stdio_ext.h
@@ -44,6 +44,8 @@ __BEGIN_DECLS
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 size_t __fbufsize(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
 
 /**
@@ -53,6 +55,8 @@ size_t __fbufsize(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
  * Available since API level 23.
  */
 int __freadable(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * [__freading(3)](https://man7.org/linux/man-pages/man3/__freading.3.html) returns non-zero if
@@ -60,7 +64,11 @@ int __freadable(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int __freading(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 /**
  * [__fwritable(3)](https://man7.org/linux/man-pages/man3/__fwritable.3.html) returns non-zero if
@@ -68,7 +76,11 @@ int __freading(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int __fwritable(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * [__fwriting(3)](https://man7.org/linux/man-pages/man3/__fwriting.3.html) returns non-zero if
@@ -76,7 +88,11 @@ int __fwritable(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int __fwriting(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 /**
  * [__flbf(3)](https://man7.org/linux/man-pages/man3/__flbf.3.html) returns non-zero if
@@ -84,7 +100,11 @@ int __fwriting(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int __flbf(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * [__fpurge(3)](https://man7.org/linux/man-pages/man3/__fpurge.3.html) discards the contents of
@@ -98,7 +118,11 @@ void __fpurge(FILE* _Nonnull __fp) __RENAME(fpurge);
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 size_t __fpending(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * __freadahead(3) returns the number of bytes in the input buffer.
@@ -106,7 +130,11 @@ size_t __fpending(FILE* _Nonnull __fp) __INTRODUCED_IN(23);
  *
  * Available since API level 34.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(34)
 size_t __freadahead(FILE* _Nonnull __fp) __INTRODUCED_IN(34);
+#endif /* __BIONIC_AVAILABILITY_GUARD(34) */
+
 
 /**
  * [_flushlbf(3)](https://man7.org/linux/man-pages/man3/_flushlbf.3.html) flushes all
@@ -114,7 +142,11 @@ size_t __freadahead(FILE* _Nonnull __fp) __INTRODUCED_IN(34);
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void _flushlbf(void) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * `__fseterr` sets the
@@ -122,7 +154,11 @@ void _flushlbf(void) __INTRODUCED_IN(23);
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 void __fseterr(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 /** __fsetlocking() constant to query locking type. */
 #define FSETLOCKING_QUERY 0
@@ -139,6 +175,10 @@ void __fseterr(FILE* _Nonnull __fp) __INTRODUCED_IN(28);
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int __fsetlocking(FILE* _Nonnull __fp, int __type) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 __END_DECLS
diff --git a/libc/include/stdlib.h b/libc/include/stdlib.h
index 076a9788d..7081d7ccb 100644
--- a/libc/include/stdlib.h
+++ b/libc/include/stdlib.h
@@ -29,11 +29,12 @@
 #ifndef _STDLIB_H
 #define _STDLIB_H
 
+#include <sys/cdefs.h>
+
 #include <alloca.h>
 #include <bits/wait.h>
 #include <malloc.h>
 #include <stddef.h>
-#include <sys/cdefs.h>
 #include <xlocale.h>
 
 __BEGIN_DECLS
@@ -59,13 +60,21 @@ int clearenv(void);
 char* _Nullable mkdtemp(char* _Nonnull __template);
 char* _Nullable mktemp(char* _Nonnull __template) __attribute__((__deprecated__("mktemp is unsafe, use mkstemp or tmpfile instead")));
 
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int mkostemp64(char* _Nonnull __template, int __flags) __INTRODUCED_IN(23);
 int mkostemp(char* _Nonnull __template, int __flags) __INTRODUCED_IN(23);
 int mkostemps64(char* _Nonnull __template, int __suffix_length, int __flags) __INTRODUCED_IN(23);
 int mkostemps(char* _Nonnull __template, int __suffix_length, int __flags) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 int mkstemp64(char* _Nonnull __template);
 int mkstemp(char* _Nonnull __template);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int mkstemps64(char* _Nonnull __template, int __flags) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 int mkstemps(char* _Nonnull __template, int __flags);
 
 int posix_memalign(void* _Nullable * _Nullable __memptr, size_t __alignment, size_t __size);
@@ -79,7 +88,11 @@ int posix_memalign(void* _Nullable * _Nullable __memptr, size_t __alignment, siz
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 __nodiscard void* _Nullable aligned_alloc(size_t __alignment, size_t __size) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 __nodiscard char* _Nullable realpath(const char* _Nonnull __path, char* _Nullable __resolved);
 
@@ -122,7 +135,11 @@ void qsort(void* _Nullable __array, size_t __n, size_t __size, int (* _Nonnull _
  *
  * Available since API level 36.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(36)
 void qsort_r(void* _Nullable __array, size_t __n, size_t __size, int (* _Nonnull __comparator)(const void* _Nullable __lhs, const void* _Nullable __rhs, void* _Nullable __context), void* _Nullable __context) __INTRODUCED_IN(36);
+#endif /* __BIONIC_AVAILABILITY_GUARD(36) */
+
 
 uint32_t arc4random(void);
 uint32_t arc4random_uniform(uint32_t __upper_bound);
@@ -135,7 +152,11 @@ int rand_r(unsigned int* _Nonnull __seed_ptr);
 double drand48(void);
 double erand48(unsigned short __xsubi[_Nonnull 3]);
 long jrand48(unsigned short __xsubi[_Nonnull 3]);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void lcong48(unsigned short __param[_Nonnull 7]) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 long lrand48(void);
 long mrand48(void);
 long nrand48(unsigned short __xsubi[_Nonnull 3]);
@@ -151,7 +172,11 @@ char* _Nullable ptsname(int __fd);
 int ptsname_r(int __fd, char* _Nonnull __buf, size_t __n);
 int unlockpt(int __fd);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int getsubopt(char* _Nonnull * _Nonnull __option, char* _Nonnull const* _Nonnull __tokens, char* _Nullable * _Nonnull __value_ptr) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 typedef struct {
   int quot;
@@ -181,13 +206,21 @@ lldiv_t lldiv(long long __numerator, long long __denominator) __attribute_const_
  *
  * Returns the number of samples written to `__averages` (at most 3), and returns -1 on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(29)
 int getloadavg(double __averages[_Nonnull], int __n) __INTRODUCED_IN(29);
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
+
 
 /* BSD compatibility. */
 const char* _Nullable getprogname(void);
 void setprogname(const char* _Nonnull __name);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int mblen(const char* _Nullable __s, size_t __n) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 size_t mbstowcs(wchar_t* _Nullable __dst, const char* _Nullable __src, size_t __n);
 int mbtowc(wchar_t* _Nullable __wc_ptr, const char*  _Nullable __s, size_t __n);
 int wctomb(char* _Nullable __dst, wchar_t __wc);
diff --git a/libc/include/string.h b/libc/include/string.h
index 7c1c3be0e..79aac91b2 100644
--- a/libc/include/string.h
+++ b/libc/include/string.h
@@ -52,7 +52,11 @@ void* _Nullable memrchr(const void* _Nonnull __s, int __ch, size_t __n) __attrib
 int memcmp(const void* _Nonnull __lhs, const void* _Nonnull __rhs, size_t __n) __attribute_pure__;
 void* _Nonnull memcpy(void* _Nonnull, const void* _Nonnull, size_t);
 #if defined(__USE_GNU)
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 void* _Nonnull mempcpy(void* _Nonnull __dst, const void* _Nonnull __src, size_t __n) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 #endif
 void* _Nonnull memmove(void* _Nonnull __dst, const void* _Nonnull __src, size_t __n);
 
@@ -71,7 +75,11 @@ void* _Nonnull memset(void* _Nonnull __dst, int __ch, size_t __n);
  *
  * Returns `dst`.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(34)
 void* _Nonnull memset_explicit(void* _Nonnull __dst, int __ch, size_t __n) __INTRODUCED_IN(34);
+#endif /* __BIONIC_AVAILABILITY_GUARD(34) */
+
 
 void* _Nullable memmem(const void* _Nonnull __haystack, size_t __haystack_size, const void* _Nonnull __needle, size_t __needle_size) __attribute_pure__;
 
@@ -79,10 +87,18 @@ char* _Nullable strchr(const char* _Nonnull __s, int __ch) __attribute_pure__;
 char* _Nullable __strchr_chk(const char* _Nonnull __s, int __ch, size_t __n);
 #if defined(__USE_GNU)
 #if defined(__cplusplus)
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 extern "C++" char* _Nonnull strchrnul(char* _Nonnull __s, int __ch) __RENAME(strchrnul) __attribute_pure__ __INTRODUCED_IN(24);
 extern "C++" const char* _Nonnull strchrnul(const char* _Nonnull __s, int __ch) __RENAME(strchrnul) __attribute_pure__ __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 #else
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 char* _Nonnull strchrnul(const char* _Nonnull __s, int __ch) __attribute_pure__ __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 #endif
 #endif
 
@@ -156,7 +172,11 @@ int strerror_r(int __errno_value, char* _Nonnull __buf, size_t __n);
  * Available since API level 35.
  */
 #if defined(__USE_GNU)
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 const char* _Nullable strerrorname_np(int __errno_value) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 #endif
 
 /**
@@ -199,10 +219,18 @@ size_t strxfrm_l(char* __BIONIC_COMPLICATED_NULLNESS __dst, const char* _Nonnull
  * It doesn't modify its argument, and in C++ it's const-correct.
  */
 #if defined(__cplusplus)
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 extern "C++" char* _Nonnull basename(char* _Nullable __path) __RENAME(__gnu_basename) __INTRODUCED_IN(23);
 extern "C++" const char* _Nonnull basename(const char* _Nonnull __path) __RENAME(__gnu_basename) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 #else
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 char* _Nonnull basename(const char* _Nonnull __path) __RENAME(__gnu_basename) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 #endif
 #endif
 
diff --git a/libc/include/strings.h b/libc/include/strings.h
index d203bd2e4..7543edca5 100644
--- a/libc/include/strings.h
+++ b/libc/include/strings.h
@@ -43,8 +43,9 @@
  * @brief Extra string functions.
  */
 
-#include <sys/types.h>
 #include <sys/cdefs.h>
+
+#include <sys/types.h>
 #include <xlocale.h>
 
 #include <bits/strcasecmp.h>
diff --git a/libc/include/sys/cachectl.h b/libc/include/sys/cachectl.h
index b5fabe397..d06d6832f 100644
--- a/libc/include/sys/cachectl.h
+++ b/libc/include/sys/cachectl.h
@@ -48,7 +48,7 @@ __BEGIN_DECLS
 
 /**
  * __riscv_flush_icache(2) flushes the instruction cache for the given range of addresses.
- * The address range is currently (Linux 6.4) ignored, so both pointers may be null.
+ * The address range is currently (Linux 6.12) ignored, so both pointers may be null.
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
diff --git a/libc/include/sys/epoll.h b/libc/include/sys/epoll.h
index a5e3c144a..bec7c6417 100644
--- a/libc/include/sys/epoll.h
+++ b/libc/include/sys/epoll.h
@@ -88,13 +88,19 @@ int epoll_pwait(int __epoll_fd, struct epoll_event* _Nonnull __events, int __eve
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int epoll_pwait64(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, int __timeout_ms, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 /**
  * Like epoll_pwait() but with a `struct timespec` timeout, for nanosecond resolution.
  *
  * Available since API level 35.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 int epoll_pwait2(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, const struct timespec* _Nullable __timeout, const sigset_t* _Nullable __mask) __INTRODUCED_IN(35);
 
 /**
@@ -103,5 +109,7 @@ int epoll_pwait2(int __epoll_fd, struct epoll_event* _Nonnull __events, int __ev
  * Available since API level 35.
  */
 int epoll_pwait2_64(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, const struct timespec* _Nullable __timeout, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/mman.h b/libc/include/sys/mman.h
index 1a0e7f696..38cbf2fb7 100644
--- a/libc/include/sys/mman.h
+++ b/libc/include/sys/mman.h
@@ -133,7 +133,11 @@ int mlock(const void* _Nonnull __addr, size_t __size);
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 int mlock2(const void* _Nonnull __addr, size_t __size, int __flags) __INTRODUCED_IN(30);
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 
 /**
  * [munlock(2)](https://man7.org/linux/man-pages/man2/munlock.2.html)
@@ -171,7 +175,11 @@ int madvise(void* _Nonnull __addr, size_t __size, int __advice);
  *
  * Returns the number of bytes advised on success, and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(31)
 ssize_t process_madvise(int __pid_fd, const struct iovec* _Nonnull __iov, size_t __count, int __advice, unsigned __flags) __INTRODUCED_IN(31);
+#endif /* __BIONIC_AVAILABILITY_GUARD(31) */
+
 
 #if defined(__USE_GNU)
 
@@ -183,7 +191,11 @@ ssize_t process_madvise(int __pid_fd, const struct iovec* _Nonnull __iov, size_t
  *
  * Returns an fd on success, and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 int memfd_create(const char* _Nonnull __name, unsigned __flags) __INTRODUCED_IN(30);
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 
 #endif
 
@@ -220,7 +232,11 @@ int memfd_create(const char* _Nonnull __name, unsigned __flags) __INTRODUCED_IN(
  *
  * Returns 0 on success, and returns a positive error number on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int posix_madvise(void* _Nonnull __addr, size_t __size, int __advice) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * [mseal(2)](https://man7.org/linux/man-pages/man2/mseal.2.html)
@@ -232,6 +248,10 @@ int posix_madvise(void* _Nonnull __addr, size_t __size, int __advice) __INTRODUC
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(36)
 int mseal(void* _Nonnull __addr, size_t __size, unsigned long __flags) __INTRODUCED_IN(36);
+#endif /* __BIONIC_AVAILABILITY_GUARD(36) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/msg.h b/libc/include/sys/msg.h
index 26071b180..8b619be24 100644
--- a/libc/include/sys/msg.h
+++ b/libc/include/sys/msg.h
@@ -46,6 +46,8 @@ typedef __kernel_ulong_t msgqnum_t;
 typedef __kernel_ulong_t msglen_t;
 
 /** Not useful on Android; disallowed by SELinux. */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int msgctl(int __msg_id, int __op, struct msqid_ds* _Nullable __buf) __INTRODUCED_IN(26);
 /** Not useful on Android; disallowed by SELinux. */
 int msgget(key_t __key, int __flags) __INTRODUCED_IN(26);
@@ -53,5 +55,7 @@ int msgget(key_t __key, int __flags) __INTRODUCED_IN(26);
 ssize_t msgrcv(int __msg_id, void* _Nonnull __msgbuf_ptr, size_t __size, long __type, int __flags) __INTRODUCED_IN(26);
 /** Not useful on Android; disallowed by SELinux. */
 int msgsnd(int __msg_id, const void* _Nonnull __msgbuf_ptr, size_t __size, int __flags) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/param.h b/libc/include/sys/param.h
index 1c991aefc..99b6a0733 100644
--- a/libc/include/sys/param.h
+++ b/libc/include/sys/param.h
@@ -33,10 +33,11 @@
  * @brief Various macros.
  */
 
+#include <sys/cdefs.h>
+
 #include <endian.h>
 #include <limits.h>
 #include <linux/param.h>
-#include <sys/cdefs.h>
 
 /** The unit of `st_blocks` in `struct stat`. */
 #define DEV_BSIZE 512
diff --git a/libc/include/sys/pidfd.h b/libc/include/sys/pidfd.h
index 30455bb70..aaf49c997 100644
--- a/libc/include/sys/pidfd.h
+++ b/libc/include/sys/pidfd.h
@@ -49,6 +49,8 @@ __BEGIN_DECLS
  *
  * Available since API level 31.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(31)
 int pidfd_open(pid_t __pid, unsigned int __flags) __INTRODUCED_IN(31);
 
 /**
@@ -72,5 +74,7 @@ int pidfd_getfd(int __pidfd, int __targetfd, unsigned int __flags) __INTRODUCED_
  * Available since API level 31.
  */
 int pidfd_send_signal(int __pidfd, int __sig, siginfo_t * _Nullable __info, unsigned int __flags) __INTRODUCED_IN(31);
+#endif /* __BIONIC_AVAILABILITY_GUARD(31) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/quota.h b/libc/include/sys/quota.h
index 6e32705ba..af09674dd 100644
--- a/libc/include/sys/quota.h
+++ b/libc/include/sys/quota.h
@@ -51,6 +51,10 @@ __BEGIN_DECLS
  *
  * Available since API level 26.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int quotactl(int __op, const char* _Nullable __special, int __id, char* __BIONIC_COMPLICATED_NULLNESS __addr) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/random.h b/libc/include/sys/random.h
index b4a9993db..23d2c3aba 100644
--- a/libc/include/sys/random.h
+++ b/libc/include/sys/random.h
@@ -52,6 +52,10 @@ __BEGIN_DECLS
  *
  * See also arc4random_buf() which is available in all API levels.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 __nodiscard ssize_t getrandom(void* _Nonnull __buffer, size_t __buffer_size, unsigned int __flags) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/resource.h b/libc/include/sys/resource.h
index 6743343a8..05ef2c26e 100644
--- a/libc/include/sys/resource.h
+++ b/libc/include/sys/resource.h
@@ -54,7 +54,11 @@ int setpriority(int __which, id_t __who, int __priority);
 
 int getrusage(int __who, struct rusage* _Nonnull __usage);
 
+
+#if (!defined(__LP64__) && __ANDROID_API__ >= 24) || (defined(__LP64__))
 int prlimit(pid_t __pid, int __resource, const struct rlimit* _Nullable __new_limit, struct rlimit* _Nullable __old_limit) __INTRODUCED_IN_32(24) __INTRODUCED_IN_64(21);
+#endif /* (!defined(__LP64__) && __ANDROID_API__ >= 24) || (defined(__LP64__)) */
+
 int prlimit64(pid_t __pid, int __resource, const struct rlimit64* _Nullable __new_limit, struct rlimit64* _Nullable __old_limit);
 
 __END_DECLS
diff --git a/libc/include/sys/select.h b/libc/include/sys/select.h
index d5b34952a..a7227b071 100644
--- a/libc/include/sys/select.h
+++ b/libc/include/sys/select.h
@@ -119,6 +119,10 @@ int pselect(int __max_fd_plus_one, fd_set* _Nullable __read_fds, fd_set* _Nullab
  *
  * Available since API level 28.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int pselect64(int __max_fd_plus_one, fd_set* _Nullable __read_fds, fd_set* _Nullable __write_fds, fd_set* _Nullable __exception_fds, const struct timespec* _Nullable __timeout, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/sem.h b/libc/include/sys/sem.h
index 568228207..72f567e2b 100644
--- a/libc/include/sys/sem.h
+++ b/libc/include/sys/sem.h
@@ -51,12 +51,20 @@ union semun {
   void* _Nullable __pad;
 };
 
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int semctl(int __sem_id, int __sem_num, int __op, ...) __INTRODUCED_IN(26);
 int semget(key_t __key, int __sem_count, int __flags) __INTRODUCED_IN(26);
 int semop(int __sem_id, struct sembuf* _Nonnull __ops, size_t __op_count) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 #if defined(__USE_GNU)
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int semtimedop(int __sem_id, struct sembuf* _Nonnull __ops, size_t __op_count, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 #endif
 
 __END_DECLS
diff --git a/libc/include/sys/shm.h b/libc/include/sys/shm.h
index 8ab3d9ab9..a96078138 100644
--- a/libc/include/sys/shm.h
+++ b/libc/include/sys/shm.h
@@ -48,6 +48,8 @@ __BEGIN_DECLS
 typedef unsigned long shmatt_t;
 
 /** Not useful on Android; disallowed by SELinux. */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 void* _Nonnull shmat(int __shm_id, const void* _Nullable __addr, int __flags) __INTRODUCED_IN(26);
 /** Not useful on Android; disallowed by SELinux. */
 int shmctl(int __shm_id, int __op, struct shmid_ds* _Nullable __buf) __INTRODUCED_IN(26);
@@ -55,5 +57,7 @@ int shmctl(int __shm_id, int __op, struct shmid_ds* _Nullable __buf) __INTRODUCE
 int shmdt(const void* _Nonnull __addr) __INTRODUCED_IN(26);
 /** Not useful on Android; disallowed by SELinux. */
 int shmget(key_t __key, size_t __size, int __flags) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/signalfd.h b/libc/include/sys/signalfd.h
index 5568b7dfd..eaea525e9 100644
--- a/libc/include/sys/signalfd.h
+++ b/libc/include/sys/signalfd.h
@@ -51,6 +51,10 @@ int signalfd(int __fd, const sigset_t* _Nonnull __mask, int __flags);
 /**
  * Like signalfd() but allows setting a signal mask with RT signals even from a 32-bit process.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int signalfd64(int __fd, const sigset64_t* _Nonnull __mask, int __flags) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/stat.h b/libc/include/sys/stat.h
index 2633b69ac..0b4b248c1 100644
--- a/libc/include/sys/stat.h
+++ b/libc/include/sys/stat.h
@@ -33,9 +33,10 @@
  * @brief File status.
  */
 
+#include <sys/cdefs.h>
+
 #include <bits/timespec.h>
 #include <linux/stat.h>
-#include <sys/cdefs.h>
 #include <sys/types.h>
 
 __BEGIN_DECLS
@@ -176,7 +177,11 @@ int fchmodat(int __dir_fd, const char* _Nonnull __path, mode_t __mode, int __fla
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(36)
 int lchmod(const char* _Nonnull __path, mode_t __mode) __INTRODUCED_IN(36);
+#endif /* __BIONIC_AVAILABILITY_GUARD(36) */
+
 
 /**
  * [mkdir(2)](https://man7.org/linux/man-pages/man2/mkdir.2.html)
@@ -280,7 +285,11 @@ int mkfifo(const char* _Nonnull __path, mode_t __mode);
  *
  * Returns 0 on success and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int mkfifoat(int __dir_fd, const char* _Nonnull __path, mode_t __mode) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * Used in the tv_nsec field of an argument to utimensat()/futimens()
@@ -331,7 +340,11 @@ int futimens(int __fd, const struct timespec __times[_Nullable 2]);
  *
  * Available since API level 30.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(30)
 int statx(int __dir_fd, const char* _Nullable __path, int __flags, unsigned __mask, struct statx* _Nonnull __buf) __INTRODUCED_IN(30);
+#endif /* __BIONIC_AVAILABILITY_GUARD(30) */
+
 #endif
 
 __END_DECLS
diff --git a/libc/include/sys/statvfs.h b/libc/include/sys/statvfs.h
index 2feca81e7..860824bd4 100644
--- a/libc/include/sys/statvfs.h
+++ b/libc/include/sys/statvfs.h
@@ -21,8 +21,9 @@
  * @brief Filesystem statistics.
  */
 
-#include <stdint.h>
 #include <sys/cdefs.h>
+
+#include <stdint.h>
 #include <sys/types.h>
 
 __BEGIN_DECLS
diff --git a/libc/include/sys/syscall.h b/libc/include/sys/syscall.h
index a49323d15..9341ffb2f 100644
--- a/libc/include/sys/syscall.h
+++ b/libc/include/sys/syscall.h
@@ -29,9 +29,10 @@
 #ifndef _SYS_SYSCALL_H_
 #define _SYS_SYSCALL_H_
 
+#include <sys/cdefs.h>
+
 #include <asm/unistd.h> /* Linux kernel __NR_* names. */
 #include <bits/glibc-syscalls.h> /* glibc-compatible SYS_* aliases. */
-#include <sys/cdefs.h>
 
 /* The syscall function itself is declared in <unistd.h>, not here. */
 
diff --git a/libc/include/sys/sysinfo.h b/libc/include/sys/sysinfo.h
index 5956febb9..ed6a0078e 100644
--- a/libc/include/sys/sysinfo.h
+++ b/libc/include/sys/sysinfo.h
@@ -53,6 +53,8 @@ int sysinfo(struct sysinfo* _Nonnull __info);
  *
  * See also sysconf().
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int get_nprocs_conf(void) __INTRODUCED_IN(23);
 
 /**
@@ -84,5 +86,7 @@ long get_phys_pages(void) __INTRODUCED_IN(23);
  * See also sysconf().
  */
 long get_avphys_pages(void) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/system_properties.h b/libc/include/sys/system_properties.h
index e8b6e345d..1303079f0 100644
--- a/libc/include/sys/system_properties.h
+++ b/libc/include/sys/system_properties.h
@@ -71,9 +71,13 @@ const prop_info* _Nullable __system_property_find(const char* _Nonnull __name);
  *
  * Available since API level 26.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 void __system_property_read_callback(const prop_info* _Nonnull __pi,
     void (* _Nonnull __callback)(void* _Nullable __cookie, const char* _Nonnull __name, const char* _Nonnull __value, uint32_t __serial),
     void* _Nullable __cookie) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 /**
  * Passes a `prop_info` for each system property to the provided
@@ -101,8 +105,12 @@ int __system_property_foreach(void (* _Nonnull __callback)(const prop_info* _Non
  * Available since API level 26.
  */
 struct timespec;
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 bool __system_property_wait(const prop_info* _Nullable __pi, uint32_t __old_serial, uint32_t* _Nonnull __new_serial_ptr, const struct timespec* _Nullable __relative_timeout)
     __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 /**
  * Deprecated: there's no limit on the length of a property name since
@@ -233,7 +241,11 @@ int __system_property_update(prop_info* _Nonnull __pi, const char* _Nonnull __va
  *
  * Available since API level 35.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 int __system_properties_zygote_reload(void) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 
 /**
  * Deprecated: previously for testing, but now that SystemProperties is its own
diff --git a/libc/include/sys/thread_properties.h b/libc/include/sys/thread_properties.h
index efd212a78..b6214ee68 100644
--- a/libc/include/sys/thread_properties.h
+++ b/libc/include/sys/thread_properties.h
@@ -50,6 +50,8 @@ __BEGIN_DECLS
  *
  * Available since API level 31.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(31)
 void __libc_get_static_tls_bounds(void* _Nonnull * _Nonnull __static_tls_begin,
                                   void* _Nonnull * _Nonnull __static_tls_end) __INTRODUCED_IN(31);
 
@@ -93,5 +95,7 @@ void __libc_register_dynamic_tls_listeners(
                           void* _Nonnull __dynamic_tls_end),
     void (* _Nonnull __on_destruction)(void* _Nonnull __dynamic_tls_begin,
                              void* _Nonnull __dynamic_tls_end)) __INTRODUCED_IN(31);
+#endif /* __BIONIC_AVAILABILITY_GUARD(31) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/time.h b/libc/include/sys/time.h
index 6ba7a37dc..d12c30643 100644
--- a/libc/include/sys/time.h
+++ b/libc/include/sys/time.h
@@ -47,8 +47,12 @@ int setitimer(int __which, const struct itimerval* _Nonnull __new_value, struct
 int utimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2]);
 
 #if defined(__USE_BSD)
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int futimes(int __fd, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
 int lutimes(const char* _Nonnull __path, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 #endif
 
 #if defined(__USE_GNU)
@@ -65,7 +69,11 @@ int lutimes(const char* _Nonnull __path, const struct timeval __times[_Nullable
  *
  * Available since API level 26.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int futimesat(int __dir_fd, const char* __BIONIC_COMPLICATED_NULLNESS __path, const struct timeval __times[_Nullable 2]) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 #endif
 
 #define timerclear(a)   \
diff --git a/libc/include/sys/timerfd.h b/libc/include/sys/timerfd.h
index bfa9a558d..f7f1ffa42 100644
--- a/libc/include/sys/timerfd.h
+++ b/libc/include/sys/timerfd.h
@@ -33,10 +33,11 @@
  * @brief Timer file descriptors.
  */
 
+#include <sys/cdefs.h>
+
 #include <fcntl.h>
 #include <linux/timerfd.h>
 #include <time.h>
-#include <sys/cdefs.h>
 #include <sys/types.h>
 
 __BEGIN_DECLS
diff --git a/libc/include/sys/timex.h b/libc/include/sys/timex.h
index 828eb470e..6fb58e41b 100644
--- a/libc/include/sys/timex.h
+++ b/libc/include/sys/timex.h
@@ -46,6 +46,8 @@ __BEGIN_DECLS
  *
  * Available since API level 24.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 int adjtimex(struct timex* _Nonnull __buf) __INTRODUCED_IN(24);
 
 /**
@@ -56,5 +58,7 @@ int adjtimex(struct timex* _Nonnull __buf) __INTRODUCED_IN(24);
  * Available since API level 24.
  */
 int clock_adjtime(clockid_t __clock, struct timex* _Nonnull __tx) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 __END_DECLS
diff --git a/libc/include/sys/types.h b/libc/include/sys/types.h
index 4622a4eeb..0446260f2 100644
--- a/libc/include/sys/types.h
+++ b/libc/include/sys/types.h
@@ -29,9 +29,10 @@
 #ifndef _SYS_TYPES_H_
 #define _SYS_TYPES_H_
 
+#include <sys/cdefs.h>
+
 #include <stddef.h>
 #include <stdint.h>
-#include <sys/cdefs.h>
 
 #include <linux/types.h>
 #include <linux/posix_types.h>
diff --git a/libc/include/sys/uio.h b/libc/include/sys/uio.h
index d3e656197..eff3b1473 100644
--- a/libc/include/sys/uio.h
+++ b/libc/include/sys/uio.h
@@ -69,6 +69,8 @@ ssize_t writev(int __fd, const struct iovec* _Nonnull __iov, int __count);
  *
  * Available since API level 24.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(24)
 ssize_t preadv(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset) __RENAME_IF_FILE_OFFSET64(preadv64) __INTRODUCED_IN(24);
 
 /**
@@ -96,6 +98,8 @@ ssize_t preadv64(int __fd, const struct iovec* _Nonnull __iov, int __count, off6
  * Available since API level 24.
  */
 ssize_t pwritev64(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset) __INTRODUCED_IN(24);
+#endif /* __BIONIC_AVAILABILITY_GUARD(24) */
+
 
 /**
  * [preadv2(2)](https://man7.org/linux/man-pages/man2/preadv2.2.html) reads
@@ -107,6 +111,8 @@ ssize_t pwritev64(int __fd, const struct iovec* _Nonnull __iov, int __count, off
  *
  * Available since API level 33.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(33)
 ssize_t preadv2(int __fd, const struct iovec* _Nonnull __iov, int __count, off_t __offset, int __flags) __RENAME_IF_FILE_OFFSET64(preadv64v2) __INTRODUCED_IN(33);
 
 /**
@@ -134,6 +140,8 @@ ssize_t preadv64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, of
  * Available since API level 33.
  */
 ssize_t pwritev64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, off64_t __offset, int __flags) __INTRODUCED_IN(33);
+#endif /* __BIONIC_AVAILABILITY_GUARD(33) */
+
 
 /**
  * [process_vm_readv(2)](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
@@ -144,6 +152,8 @@ ssize_t pwritev64v2(int __fd, const struct iovec* _Nonnull __iov, int __count, o
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 ssize_t process_vm_readv(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __local_iov, unsigned long __local_iov_count, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __remote_iov, unsigned long __remote_iov_count, unsigned long __flags) __INTRODUCED_IN(23);
 
 /**
@@ -156,6 +166,8 @@ ssize_t process_vm_readv(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_N
  * Available since API level 23.
  */
 ssize_t process_vm_writev(pid_t __pid, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __local_iov, unsigned long __local_iov_count, const struct iovec* __BIONIC_COMPLICATED_NULLNESS __remote_iov, unsigned long __remote_iov_count, unsigned long __flags) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 #endif
 
diff --git a/libc/include/sys/un.h b/libc/include/sys/un.h
index 83c1d1744..c2bfcb060 100644
--- a/libc/include/sys/un.h
+++ b/libc/include/sys/un.h
@@ -33,9 +33,10 @@
  * @brief Unix domain sockets.
  */
 
+#include <sys/cdefs.h>
+
 #include <bits/sa_family_t.h>
 #include <linux/un.h>
-#include <sys/cdefs.h>
 
 #if defined(__USE_BSD) || defined(__USE_GNU)
 #include <string.h>
diff --git a/libc/include/sys/vfs.h b/libc/include/sys/vfs.h
index 1a640baee..5d078bee6 100644
--- a/libc/include/sys/vfs.h
+++ b/libc/include/sys/vfs.h
@@ -29,8 +29,9 @@
 #ifndef _SYS_VFS_H_
 #define _SYS_VFS_H_
 
-#include <stdint.h>
 #include <sys/cdefs.h>
+
+#include <stdint.h>
 #include <sys/types.h>
 
 __BEGIN_DECLS
diff --git a/libc/include/sys/wait.h b/libc/include/sys/wait.h
index 520836604..632aa43e6 100644
--- a/libc/include/sys/wait.h
+++ b/libc/include/sys/wait.h
@@ -28,8 +28,9 @@
 
 #pragma once
 
-#include <bits/wait.h>
 #include <sys/cdefs.h>
+
+#include <bits/wait.h>
 #include <sys/types.h>
 #include <sys/resource.h>
 #include <linux/wait.h>
diff --git a/libc/include/sys/xattr.h b/libc/include/sys/xattr.h
index 38c11e27a..ebe4eb86b 100644
--- a/libc/include/sys/xattr.h
+++ b/libc/include/sys/xattr.h
@@ -33,8 +33,9 @@
  * @brief Extended attribute functions.
  */
 
-#include <linux/xattr.h>
 #include <sys/cdefs.h>
+
+#include <linux/xattr.h>
 #include <sys/types.h>
 
 __BEGIN_DECLS
diff --git a/libc/include/syslog.h b/libc/include/syslog.h
index 33979f0b1..7a594f125 100644
--- a/libc/include/syslog.h
+++ b/libc/include/syslog.h
@@ -56,8 +56,9 @@
 
 #pragma once
 
-#include <stdio.h>
 #include <sys/cdefs.h>
+
+#include <stdio.h>
 #include <stdarg.h>
 
 __BEGIN_DECLS
diff --git a/libc/include/time.h b/libc/include/time.h
index e9d656994..6c9b761bc 100644
--- a/libc/include/time.h
+++ b/libc/include/time.h
@@ -166,7 +166,11 @@ time_t mktime(struct tm* _Nonnull __tm);
  *
  * Available since API level 35.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 time_t mktime_z(timezone_t _Nonnull __tz, struct tm* _Nonnull __tm) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 
 /**
  * [localtime(3)](https://man7.org/linux/man-pages/man3/localtime.3p.html) converts
@@ -200,7 +204,11 @@ struct tm* _Nullable localtime_r(const time_t* _Nonnull __t, struct tm* _Nonnull
  *
  * Available since API level 35.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 struct tm* _Nullable localtime_rz(timezone_t _Nonnull __tz, const time_t* _Nonnull __t, struct tm* _Nonnull __tm) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 
 /**
  * Inverse of localtime().
@@ -314,6 +322,8 @@ void tzset(void);
  *
  * Available since API level 35.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 timezone_t _Nullable tzalloc(const char* _Nullable __id) __INTRODUCED_IN(35);
 
 /**
@@ -326,6 +336,8 @@ timezone_t _Nullable tzalloc(const char* _Nullable __id) __INTRODUCED_IN(35);
  * Available since API level 35.
  */
 void tzfree(timezone_t _Nullable __tz) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 
 /**
  * [clock(3)](https://man7.org/linux/man-pages/man3/clock.3.html)
@@ -345,7 +357,11 @@ clock_t clock(void);
  *
  * Returns 0 on success, and returns -1 and returns an error number on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int clock_getcpuclockid(pid_t __pid, clockid_t* _Nonnull __clock) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 /**
  * [clock_getres(2)](https://man7.org/linux/man-pages/man2/clock_getres.2.html)
@@ -459,7 +475,11 @@ int timer_getoverrun(timer_t _Nonnull __timer);
  * Available since API level 29 for TIME_UTC; other bases arrived later.
  * Code for Android should prefer clock_gettime().
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(29)
 int timespec_get(struct timespec* _Nonnull __ts, int __base) __INTRODUCED_IN(29);
+#endif /* __BIONIC_AVAILABILITY_GUARD(29) */
+
 
 /**
  * timespec_getres(3) is equivalent to clock_getres() for the clock corresponding to the given base.
@@ -469,6 +489,10 @@ int timespec_get(struct timespec* _Nonnull __ts, int __base) __INTRODUCED_IN(29)
  * Available since API level 35.
  * Code for Android should prefer clock_gettime().
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 int timespec_getres(struct timespec* _Nonnull __ts, int __base) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 
 __END_DECLS
diff --git a/libc/include/uchar.h b/libc/include/uchar.h
index 55a36e72c..94efb2d3e 100644
--- a/libc/include/uchar.h
+++ b/libc/include/uchar.h
@@ -33,9 +33,10 @@
  * @brief Unicode functions.
  */
 
-#include <stddef.h>
 #include <sys/cdefs.h>
 
+#include <stddef.h>
+
 #include <bits/bionic_multibyte_result.h>
 #include <bits/mbstate_t.h>
 
diff --git a/libc/include/unistd.h b/libc/include/unistd.h
index e1c268fa7..e623339d3 100644
--- a/libc/include/unistd.h
+++ b/libc/include/unistd.h
@@ -28,8 +28,9 @@
 
 #pragma once
 
-#include <stddef.h>
 #include <sys/cdefs.h>
+
+#include <stddef.h>
 #include <sys/types.h>
 #include <sys/select.h>
 
@@ -100,7 +101,11 @@ pid_t fork(void);
  *
  * Available since API level 35.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(35)
 pid_t _Fork(void) __INTRODUCED_IN(35);
+#endif /* __BIONIC_AVAILABILITY_GUARD(35) */
+
 
 /**
  * [vfork(2)](https://man7.org/linux/man-pages/man2/vfork.2.html) creates a new
@@ -145,7 +150,11 @@ int execl(const char* _Nonnull __path, const char* _Nullable __arg0, ...) __attr
 int execlp(const char* _Nonnull __file, const char* _Nullable __arg0, ...) __attribute__((__sentinel__));
 int execle(const char* _Nonnull __path, const char* _Nullable __arg0, ... /*,  char* const* __envp */)
     __attribute__((__sentinel__(1)));
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int fexecve(int __fd, char* _Nullable const* _Nullable __argv, char* _Nullable const* _Nullable __envp) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 int nice(int __incr);
 
@@ -246,7 +255,11 @@ int setgroups(size_t __size, const gid_t* _Nullable __list);
 int getresuid(uid_t* _Nonnull __ruid, uid_t* _Nonnull __euid, uid_t* _Nonnull __suid);
 int getresgid(gid_t* _Nonnull __rgid, gid_t* _Nonnull __egid, gid_t* _Nonnull __sgid);
 char* _Nullable getlogin(void);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int getlogin_r(char* _Nonnull __buffer, size_t __buffer_size) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 
 long fpathconf(int __fd, int __name);
 long pathconf(const char* _Nonnull __path, int __name);
@@ -257,8 +270,29 @@ int link(const char* _Nonnull __old_path, const char* _Nonnull __new_path);
 int linkat(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path, int __flags);
 int unlink(const char* _Nonnull __path);
 int unlinkat(int __dirfd, const char* _Nonnull __path, int __flags);
+
+/**
+ * [chdir(2)](https://man7.org/linux/man-pages/man2/chdir.2.html) changes
+ * the current working directory to the given path.
+ *
+ * This function affects all threads in the process, so is generally a bad idea
+ * on Android where most code will be running in a multi-threaded context.
+ *
+ * Returns 0 on success, and returns -1 and sets `errno` on failure.
+ */
 int chdir(const char* _Nonnull __path);
+
+/**
+ * [fchdir(2)](https://man7.org/linux/man-pages/man2/chdir.2.html) changes
+ * the current working directory to the given fd.
+ *
+ * This function affects all threads in the process, so is generally a bad idea
+ * on Android where most code will be running in a multi-threaded context.
+ *
+ * Returns 0 on success, and returns -1 and sets `errno` on failure.
+ */
 int fchdir(int __fd);
+
 int rmdir(const char* _Nonnull __path);
 int pipe(int __fds[_Nonnull 2]);
 #if defined(__USE_GNU)
@@ -277,7 +311,11 @@ char* _Nullable getcwd(char* _Nullable __buf, size_t __size);
 
 void sync(void);
 #if defined(__USE_GNU)
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 int syncfs(int __fd) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 #endif
 
 int close(int __fd);
@@ -339,7 +377,11 @@ unsigned int sleep(unsigned int __seconds);
 int usleep(useconds_t __microseconds);
 
 int gethostname(char* _Nonnull _buf, size_t __buf_size);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int sethostname(const char* _Nonnull __name, size_t __n) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 int brk(void* _Nonnull __addr);
 void* _Nullable sbrk(ptrdiff_t __increment);
@@ -382,8 +424,12 @@ int tcsetpgrp(int __fd, pid_t __pid);
     } while (_rc == -1 && errno == EINTR); \
     _rc; })
 
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 int getdomainname(char* _Nonnull __buf, size_t __buf_size) __INTRODUCED_IN(26);
 int setdomainname(const char* _Nonnull __name, size_t __n) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 /**
  * [copy_file_range(2)](https://man7.org/linux/man-pages/man2/copy_file_range.2.html) copies
@@ -394,7 +440,11 @@ int setdomainname(const char* _Nonnull __name, size_t __n) __INTRODUCED_IN(26);
  * Returns the number of bytes copied on success, and returns -1 and sets
  * `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(34)
 ssize_t copy_file_range(int __fd_in, off64_t* _Nullable __off_in, int __fd_out, off64_t* _Nullable __off_out, size_t __length, unsigned int __flags) __INTRODUCED_IN(34);
+#endif /* __BIONIC_AVAILABILITY_GUARD(34) */
+
 
 #if __ANDROID_API__ >= 28
 void swab(const void* _Nonnull __src, void* _Nonnull __dst, ssize_t __byte_count) __INTRODUCED_IN(28);
@@ -414,7 +464,11 @@ void swab(const void* _Nonnull __src, void* _Nonnull __dst, ssize_t __byte_count
  *
  * Returns 0 on success, and returns -1 and sets `errno` on failure.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(34)
 int close_range(unsigned int __min_fd, unsigned int __max_fd, int __flags) __INTRODUCED_IN(34);
+#endif /* __BIONIC_AVAILABILITY_GUARD(34) */
+
 
 #if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
 #define _UNISTD_H_
diff --git a/libc/include/utmp.h b/libc/include/utmp.h
index d249f8af8..1674491ae 100644
--- a/libc/include/utmp.h
+++ b/libc/include/utmp.h
@@ -131,6 +131,10 @@ void endutent(void);
  *
  * Available since API level 23.
  */
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int login_tty(int __fd) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 
 __END_DECLS
diff --git a/libc/include/wchar.h b/libc/include/wchar.h
index e86f94deb..56594dc38 100644
--- a/libc/include/wchar.h
+++ b/libc/include/wchar.h
@@ -75,7 +75,11 @@ wchar_t* _Nonnull wcpcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src)
 wchar_t* _Nonnull wcpncpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
 size_t wcrtomb(char* _Nullable __buf, wchar_t __wc, mbstate_t* _Nullable __ps);
 int wcscasecmp(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int wcscasecmp_l(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, locale_t _Nonnull __l) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 wchar_t* _Nonnull wcscat(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src);
 wchar_t* _Nullable wcschr(const wchar_t * _Nonnull __s, wchar_t __wc);
 int wcscmp(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs);
@@ -83,10 +87,18 @@ int wcscoll(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs);
 wchar_t* _Nonnull wcscpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src);
 size_t wcscspn(const wchar_t* _Nonnull __s, const wchar_t* _Nonnull __accept);
 size_t wcsftime(wchar_t* _Nonnull __buf, size_t __n, const wchar_t* _Nullable __fmt, const struct tm* _Nonnull __tm);
+
+#if __BIONIC_AVAILABILITY_GUARD(28)
 size_t wcsftime_l(wchar_t* _Nonnull __buf, size_t __n, const wchar_t* _Nullable __fmt, const struct tm* _Nonnull __tm, locale_t _Nonnull __l) __INTRODUCED_IN(28);
+#endif /* __BIONIC_AVAILABILITY_GUARD(28) */
+
 size_t wcslen(const wchar_t* _Nonnull __s);
 int wcsncasecmp(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, size_t __n);
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 int wcsncasecmp_l(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, size_t __n, locale_t _Nonnull __l) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 wchar_t* _Nonnull wcsncat(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
 int wcsncmp(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, size_t __n);
 wchar_t* _Nonnull wcsncpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
@@ -117,7 +129,11 @@ wchar_t* _Nullable wmemchr(const wchar_t* _Nonnull __src, wchar_t __wc, size_t _
 int wmemcmp(const wchar_t* _Nullable __lhs, const wchar_t* _Nullable __rhs, size_t __n);
 wchar_t* _Nonnull wmemcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
 #if defined(__USE_GNU)
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 wchar_t* _Nonnull wmempcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 #endif
 wchar_t* _Nonnull wmemmove(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
 wchar_t* _Nonnull wmemset(wchar_t* _Nonnull __dst, wchar_t __wc, size_t __n);
@@ -133,7 +149,11 @@ size_t wcsxfrm_l(wchar_t* __BIONIC_COMPLICATED_NULLNESS __dst, const wchar_t* _N
 size_t wcslcat(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
 size_t wcslcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(23)
 FILE* _Nullable open_wmemstream(wchar_t* _Nonnull * _Nonnull __ptr, size_t* _Nonnull  __size_ptr) __INTRODUCED_IN(23);
+#endif /* __BIONIC_AVAILABILITY_GUARD(23) */
+
 wchar_t* _Nullable wcsdup(const wchar_t* _Nonnull __s);
 size_t wcsnlen(const wchar_t* _Nonnull __s, size_t __n);
 
diff --git a/libc/include/wctype.h b/libc/include/wctype.h
index 4f6f81f3a..30ec04f42 100644
--- a/libc/include/wctype.h
+++ b/libc/include/wctype.h
@@ -29,8 +29,9 @@
 #ifndef _WCTYPE_H_
 #define _WCTYPE_H_
 
-#include <bits/wctype.h>
 #include <sys/cdefs.h>
+
+#include <bits/wctype.h>
 #include <xlocale.h>
 
 __BEGIN_DECLS
@@ -51,8 +52,12 @@ int iswxdigit_l(wint_t __wc, locale_t _Nonnull __l);
 wint_t towlower_l(wint_t __wc, locale_t _Nonnull __l);
 wint_t towupper_l(wint_t __wc, locale_t _Nonnull __l);
 
+
+#if __BIONIC_AVAILABILITY_GUARD(26)
 wint_t towctrans_l(wint_t __wc, wctrans_t _Nonnull __transform, locale_t _Nonnull __l) __INTRODUCED_IN(26);
 wctrans_t _Nonnull wctrans_l(const char* _Nonnull __name, locale_t _Nonnull __l) __INTRODUCED_IN(26);
+#endif /* __BIONIC_AVAILABILITY_GUARD(26) */
+
 
 wctype_t wctype_l(const char* _Nonnull __name, locale_t _Nonnull __l);
 int iswctype_l(wint_t __wc, wctype_t __transform, locale_t _Nonnull __l);
diff --git a/libc/kernel/android/scsi/scsi/scsi_proto.h b/libc/kernel/android/scsi/scsi/scsi_proto.h
index d873fad68..754e12a44 100644
--- a/libc/kernel/android/scsi/scsi/scsi_proto.h
+++ b/libc/kernel/android/scsi/scsi/scsi_proto.h
@@ -109,6 +109,7 @@
 #define WRITE_SAME_16 0x93
 #define ZBC_OUT 0x94
 #define ZBC_IN 0x95
+#define WRITE_ATOMIC_16 0x9c
 #define SERVICE_ACTION_BIDIRECTIONAL 0x9d
 #define SERVICE_ACTION_IN_16 0x9e
 #define SERVICE_ACTION_OUT_16 0x9f
diff --git a/libc/kernel/tools/cpp.py b/libc/kernel/tools/cpp.py
index 08b786ac5..df508060d 100755
--- a/libc/kernel/tools/cpp.py
+++ b/libc/kernel/tools/cpp.py
@@ -1430,7 +1430,7 @@ class BlockList(object):
                         state = VAR_DECL
                     elif state == NORMAL and token_id in ['struct', 'typedef',
                                                           'enum', 'union',
-                                                          '__extension__']:
+                                                          '__extension__', '=']:
                         state = OTHER_DECL
                         state_token = token_id
                     elif block.tokens[i].kind == TokenKind.IDENTIFIER:
@@ -2057,7 +2057,7 @@ struct something {
   struct timeval val2;
 };
 """
-        self.assertEqual(self.parse(text, {"remove": True}), expected)
+        self.assertEqual(self.parse(text, {"remove": None}), expected)
 
     def test_remove_struct_from_end(self):
         text = """\
@@ -2076,7 +2076,7 @@ struct something {
   struct timeval val2;
 };
 """
-        self.assertEqual(self.parse(text, {"remove": True}), expected)
+        self.assertEqual(self.parse(text, {"remove": None}), expected)
 
     def test_remove_minimal_struct(self):
         text = """\
@@ -2084,7 +2084,7 @@ struct remove {
 };
 """
         expected = "";
-        self.assertEqual(self.parse(text, {"remove": True}), expected)
+        self.assertEqual(self.parse(text, {"remove": None}), expected)
 
     def test_remove_struct_with_struct_fields(self):
         text = """\
@@ -2104,7 +2104,7 @@ struct something {
   struct remove val2;
 };
 """
-        self.assertEqual(self.parse(text, {"remove": True}), expected)
+        self.assertEqual(self.parse(text, {"remove": None}), expected)
 
     def test_remove_consecutive_structs(self):
         text = """\
@@ -2136,7 +2136,7 @@ struct keep2 {
   struct timeval val2;
 };
 """
-        self.assertEqual(self.parse(text, {"remove1": True, "remove2": True}), expected)
+        self.assertEqual(self.parse(text, {"remove1": None, "remove2": None}), expected)
 
     def test_remove_multiple_structs(self):
         text = """\
@@ -2169,7 +2169,7 @@ struct keep3 {
   int val;
 };
 """
-        self.assertEqual(self.parse(text, {"remove1": True, "remove2": True}), expected)
+        self.assertEqual(self.parse(text, {"remove1": None, "remove2": None}), expected)
 
     def test_remove_struct_with_inline_structs(self):
         text = """\
@@ -2194,7 +2194,7 @@ struct something {
   struct timeval val2;
 };
 """
-        self.assertEqual(self.parse(text, {"remove": True}), expected)
+        self.assertEqual(self.parse(text, {"remove": None}), expected)
 
     def test_remove_struct_across_blocks(self):
         text = """\
@@ -2219,7 +2219,7 @@ struct something {
   struct timeval val2;
 };
 """
-        self.assertEqual(self.parse(text, {"remove": True}), expected)
+        self.assertEqual(self.parse(text, {"remove": None}), expected)
 
     def test_remove_struct_across_blocks_multiple_structs(self):
         text = """\
@@ -2246,7 +2246,7 @@ struct something {
   struct timeval val2;
 };
 """
-        self.assertEqual(self.parse(text, {"remove1": True, "remove2": True}), expected)
+        self.assertEqual(self.parse(text, {"remove1": None, "remove2": None}), expected)
 
     def test_remove_multiple_struct_and_add_includes(self):
         text = """\
@@ -2263,7 +2263,7 @@ struct remove2 {
 #include <bits/remove1.h>
 #include <bits/remove2.h>
 """
-        self.assertEqual(self.parse(text, {"remove1": False, "remove2": False}), expected)
+        self.assertEqual(self.parse(text, {"remove1": "bits/remove1.h", "remove2": "bits/remove2.h"}), expected)
 
 
 class FullPathTest(unittest.TestCase):
@@ -2580,6 +2580,71 @@ struct fields {
   struct timeval timeval;
   struct itimerval itimerval;
 };
+#include <linux/time.h>
+"""
+        self.assertEqual(self.parse(text), expected)
+
+    def test_var_definition(self):
+        # If we're definining the whole thing, it's probably worth keeping.
+        text = """\
+static const char *kString = "hello world";
+static const int kInteger = 42;
+"""
+        expected = """\
+static const char * kString = "hello world";
+static const int kInteger = 42;
+"""
+        self.assertEqual(self.parse(text), expected)
+
+    def test_struct_array_definition(self):
+        text = """\
+struct descriptor {
+  int args;
+  int size;
+};
+static const struct descriptor[] = {
+  {0, 0},
+  {1, 12},
+  {0, 42},
+};
+"""
+        expected = """\
+struct descriptor {
+  int args;
+  int size;
+};
+static const struct descriptor[] = {
+ {
+    0, 0
+  }
+ , {
+    1, 12
+  }
+ , {
+    0, 42
+  }
+ ,
+};
+"""
+        self.assertEqual(self.parse(text), expected)
+
+    def test_array_definition(self):
+        text = """\
+static const char *arr[] = {
+  "foo",
+  "bar",
+  "baz",
+};
+
+static int another_arr[5] = { 1, 2, 3, 4, 5};
+"""
+        expected = """\
+static const char * arr[] = {
+  "foo", "bar", "baz",
+};
+static int another_arr[5] = {
+  1, 2, 3, 4, 5
+};
 """
         self.assertEqual(self.parse(text), expected)
 
diff --git a/libc/kernel/tools/defaults.py b/libc/kernel/tools/defaults.py
index 06afb25d6..2994e5e29 100644
--- a/libc/kernel/tools/defaults.py
+++ b/libc/kernel/tools/defaults.py
@@ -25,6 +25,23 @@ kernel_known_macros = {
     # Otherwise, there will be two struct timeval definitions when
     # __kernel_old_timeval is renamed to timeval.
     "__kernel_old_timeval": "1",
+    # Drop the custom byte swap functions and just use the clang builtins.
+    # https://github.com/android/ndk/issues/2107
+    "__arch_swab16": kCppUndefinedMacro,
+    "__arch_swab16p": kCppUndefinedMacro,
+    "__arch_swab16s": kCppUndefinedMacro,
+    "__arch_swab32": kCppUndefinedMacro,
+    "__arch_swab32p": kCppUndefinedMacro,
+    "__arch_swab32s": kCppUndefinedMacro,
+    "__arch_swab64": kCppUndefinedMacro,
+    "__arch_swab64p": kCppUndefinedMacro,
+    "__arch_swab64s": kCppUndefinedMacro,
+    "__arch_swahb32": kCppUndefinedMacro,
+    "__arch_swahb32p": kCppUndefinedMacro,
+    "__arch_swahb32s": kCppUndefinedMacro,
+    "__arch_swahw32": kCppUndefinedMacro,
+    "__arch_swahw32p": kCppUndefinedMacro,
+    "__arch_swahw32s": kCppUndefinedMacro,
     }
 
 # This is the set of known kernel data structures we want to remove from
diff --git a/libc/kernel/tools/update_all.py b/libc/kernel/tools/update_all.py
index ae89a80f9..331a95796 100755
--- a/libc/kernel/tools/update_all.py
+++ b/libc/kernel/tools/update_all.py
@@ -88,15 +88,8 @@ def GenerateGlibcSyscallsHeader(updater):
     # Collect the set of all syscalls for all architectures.
     syscalls = set()
     pattern = re.compile(r'^\s*#\s*define\s*__NR_([a-z_]\S+)')
-    for unistd_h in ['kernel/uapi/asm-generic/unistd.h',
-                     'kernel/uapi/asm-arm/asm/unistd.h',
-                     'kernel/uapi/asm-arm/asm/unistd-eabi.h',
-                     'kernel/uapi/asm-arm/asm/unistd-oabi.h',
-                     'kernel/uapi/asm-riscv/asm/unistd.h',
-                     'kernel/uapi/asm-x86/asm/unistd_32.h',
-                     'kernel/uapi/asm-x86/asm/unistd_64.h',
-                     'kernel/uapi/asm-x86/asm/unistd_x32.h']:
-        for line in open(os.path.join(libc_root, unistd_h)):
+    for unistd_h in glob.glob('%s/kernel/uapi/asm-*/asm/unistd*.h' % libc_root):
+        for line in open(unistd_h):
             m = re.search(pattern, line)
             if m:
                 nr_name = m.group(1)
diff --git a/libc/kernel/uapi/asm-arm64/asm/unistd.h b/libc/kernel/uapi/asm-arm64/asm/unistd.h
index 7457ebca6..178578fdf 100644
--- a/libc/kernel/uapi/asm-arm64/asm/unistd.h
+++ b/libc/kernel/uapi/asm-arm64/asm/unistd.h
@@ -4,10 +4,4 @@
  * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
  * for more information.
  */
-#define __ARCH_WANT_RENAMEAT
-#define __ARCH_WANT_NEW_STAT
-#define __ARCH_WANT_SET_GET_RLIMIT
-#define __ARCH_WANT_TIME32_SYSCALLS
-#define __ARCH_WANT_SYS_CLONE3
-#define __ARCH_WANT_MEMFD_SECRET
-#include <asm-generic/unistd.h>
+#include <asm/unistd_64.h>
diff --git a/libc/kernel/uapi/asm-arm64/asm/unistd_64.h b/libc/kernel/uapi/asm-arm64/asm/unistd_64.h
new file mode 100644
index 000000000..0a0a1c04f
--- /dev/null
+++ b/libc/kernel/uapi/asm-arm64/asm/unistd_64.h
@@ -0,0 +1,327 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_ASM_UNISTD_64_H
+#define _UAPI_ASM_UNISTD_64_H
+#define __NR_io_setup 0
+#define __NR_io_destroy 1
+#define __NR_io_submit 2
+#define __NR_io_cancel 3
+#define __NR_io_getevents 4
+#define __NR_setxattr 5
+#define __NR_lsetxattr 6
+#define __NR_fsetxattr 7
+#define __NR_getxattr 8
+#define __NR_lgetxattr 9
+#define __NR_fgetxattr 10
+#define __NR_listxattr 11
+#define __NR_llistxattr 12
+#define __NR_flistxattr 13
+#define __NR_removexattr 14
+#define __NR_lremovexattr 15
+#define __NR_fremovexattr 16
+#define __NR_getcwd 17
+#define __NR_lookup_dcookie 18
+#define __NR_eventfd2 19
+#define __NR_epoll_create1 20
+#define __NR_epoll_ctl 21
+#define __NR_epoll_pwait 22
+#define __NR_dup 23
+#define __NR_dup3 24
+#define __NR_fcntl 25
+#define __NR_inotify_init1 26
+#define __NR_inotify_add_watch 27
+#define __NR_inotify_rm_watch 28
+#define __NR_ioctl 29
+#define __NR_ioprio_set 30
+#define __NR_ioprio_get 31
+#define __NR_flock 32
+#define __NR_mknodat 33
+#define __NR_mkdirat 34
+#define __NR_unlinkat 35
+#define __NR_symlinkat 36
+#define __NR_linkat 37
+#define __NR_renameat 38
+#define __NR_umount2 39
+#define __NR_mount 40
+#define __NR_pivot_root 41
+#define __NR_nfsservctl 42
+#define __NR_statfs 43
+#define __NR_fstatfs 44
+#define __NR_truncate 45
+#define __NR_ftruncate 46
+#define __NR_fallocate 47
+#define __NR_faccessat 48
+#define __NR_chdir 49
+#define __NR_fchdir 50
+#define __NR_chroot 51
+#define __NR_fchmod 52
+#define __NR_fchmodat 53
+#define __NR_fchownat 54
+#define __NR_fchown 55
+#define __NR_openat 56
+#define __NR_close 57
+#define __NR_vhangup 58
+#define __NR_pipe2 59
+#define __NR_quotactl 60
+#define __NR_getdents64 61
+#define __NR_lseek 62
+#define __NR_read 63
+#define __NR_write 64
+#define __NR_readv 65
+#define __NR_writev 66
+#define __NR_pread64 67
+#define __NR_pwrite64 68
+#define __NR_preadv 69
+#define __NR_pwritev 70
+#define __NR_sendfile 71
+#define __NR_pselect6 72
+#define __NR_ppoll 73
+#define __NR_signalfd4 74
+#define __NR_vmsplice 75
+#define __NR_splice 76
+#define __NR_tee 77
+#define __NR_readlinkat 78
+#define __NR_newfstatat 79
+#define __NR_fstat 80
+#define __NR_sync 81
+#define __NR_fsync 82
+#define __NR_fdatasync 83
+#define __NR_sync_file_range 84
+#define __NR_timerfd_create 85
+#define __NR_timerfd_settime 86
+#define __NR_timerfd_gettime 87
+#define __NR_utimensat 88
+#define __NR_acct 89
+#define __NR_capget 90
+#define __NR_capset 91
+#define __NR_personality 92
+#define __NR_exit 93
+#define __NR_exit_group 94
+#define __NR_waitid 95
+#define __NR_set_tid_address 96
+#define __NR_unshare 97
+#define __NR_futex 98
+#define __NR_set_robust_list 99
+#define __NR_get_robust_list 100
+#define __NR_nanosleep 101
+#define __NR_getitimer 102
+#define __NR_setitimer 103
+#define __NR_kexec_load 104
+#define __NR_init_module 105
+#define __NR_delete_module 106
+#define __NR_timer_create 107
+#define __NR_timer_gettime 108
+#define __NR_timer_getoverrun 109
+#define __NR_timer_settime 110
+#define __NR_timer_delete 111
+#define __NR_clock_settime 112
+#define __NR_clock_gettime 113
+#define __NR_clock_getres 114
+#define __NR_clock_nanosleep 115
+#define __NR_syslog 116
+#define __NR_ptrace 117
+#define __NR_sched_setparam 118
+#define __NR_sched_setscheduler 119
+#define __NR_sched_getscheduler 120
+#define __NR_sched_getparam 121
+#define __NR_sched_setaffinity 122
+#define __NR_sched_getaffinity 123
+#define __NR_sched_yield 124
+#define __NR_sched_get_priority_max 125
+#define __NR_sched_get_priority_min 126
+#define __NR_sched_rr_get_interval 127
+#define __NR_restart_syscall 128
+#define __NR_kill 129
+#define __NR_tkill 130
+#define __NR_tgkill 131
+#define __NR_sigaltstack 132
+#define __NR_rt_sigsuspend 133
+#define __NR_rt_sigaction 134
+#define __NR_rt_sigprocmask 135
+#define __NR_rt_sigpending 136
+#define __NR_rt_sigtimedwait 137
+#define __NR_rt_sigqueueinfo 138
+#define __NR_rt_sigreturn 139
+#define __NR_setpriority 140
+#define __NR_getpriority 141
+#define __NR_reboot 142
+#define __NR_setregid 143
+#define __NR_setgid 144
+#define __NR_setreuid 145
+#define __NR_setuid 146
+#define __NR_setresuid 147
+#define __NR_getresuid 148
+#define __NR_setresgid 149
+#define __NR_getresgid 150
+#define __NR_setfsuid 151
+#define __NR_setfsgid 152
+#define __NR_times 153
+#define __NR_setpgid 154
+#define __NR_getpgid 155
+#define __NR_getsid 156
+#define __NR_setsid 157
+#define __NR_getgroups 158
+#define __NR_setgroups 159
+#define __NR_uname 160
+#define __NR_sethostname 161
+#define __NR_setdomainname 162
+#define __NR_getrlimit 163
+#define __NR_setrlimit 164
+#define __NR_getrusage 165
+#define __NR_umask 166
+#define __NR_prctl 167
+#define __NR_getcpu 168
+#define __NR_gettimeofday 169
+#define __NR_settimeofday 170
+#define __NR_adjtimex 171
+#define __NR_getpid 172
+#define __NR_getppid 173
+#define __NR_getuid 174
+#define __NR_geteuid 175
+#define __NR_getgid 176
+#define __NR_getegid 177
+#define __NR_gettid 178
+#define __NR_sysinfo 179
+#define __NR_mq_open 180
+#define __NR_mq_unlink 181
+#define __NR_mq_timedsend 182
+#define __NR_mq_timedreceive 183
+#define __NR_mq_notify 184
+#define __NR_mq_getsetattr 185
+#define __NR_msgget 186
+#define __NR_msgctl 187
+#define __NR_msgrcv 188
+#define __NR_msgsnd 189
+#define __NR_semget 190
+#define __NR_semctl 191
+#define __NR_semtimedop 192
+#define __NR_semop 193
+#define __NR_shmget 194
+#define __NR_shmctl 195
+#define __NR_shmat 196
+#define __NR_shmdt 197
+#define __NR_socket 198
+#define __NR_socketpair 199
+#define __NR_bind 200
+#define __NR_listen 201
+#define __NR_accept 202
+#define __NR_connect 203
+#define __NR_getsockname 204
+#define __NR_getpeername 205
+#define __NR_sendto 206
+#define __NR_recvfrom 207
+#define __NR_setsockopt 208
+#define __NR_getsockopt 209
+#define __NR_shutdown 210
+#define __NR_sendmsg 211
+#define __NR_recvmsg 212
+#define __NR_readahead 213
+#define __NR_brk 214
+#define __NR_munmap 215
+#define __NR_mremap 216
+#define __NR_add_key 217
+#define __NR_request_key 218
+#define __NR_keyctl 219
+#define __NR_clone 220
+#define __NR_execve 221
+#define __NR_mmap 222
+#define __NR_fadvise64 223
+#define __NR_swapon 224
+#define __NR_swapoff 225
+#define __NR_mprotect 226
+#define __NR_msync 227
+#define __NR_mlock 228
+#define __NR_munlock 229
+#define __NR_mlockall 230
+#define __NR_munlockall 231
+#define __NR_mincore 232
+#define __NR_madvise 233
+#define __NR_remap_file_pages 234
+#define __NR_mbind 235
+#define __NR_get_mempolicy 236
+#define __NR_set_mempolicy 237
+#define __NR_migrate_pages 238
+#define __NR_move_pages 239
+#define __NR_rt_tgsigqueueinfo 240
+#define __NR_perf_event_open 241
+#define __NR_accept4 242
+#define __NR_recvmmsg 243
+#define __NR_wait4 260
+#define __NR_prlimit64 261
+#define __NR_fanotify_init 262
+#define __NR_fanotify_mark 263
+#define __NR_name_to_handle_at 264
+#define __NR_open_by_handle_at 265
+#define __NR_clock_adjtime 266
+#define __NR_syncfs 267
+#define __NR_setns 268
+#define __NR_sendmmsg 269
+#define __NR_process_vm_readv 270
+#define __NR_process_vm_writev 271
+#define __NR_kcmp 272
+#define __NR_finit_module 273
+#define __NR_sched_setattr 274
+#define __NR_sched_getattr 275
+#define __NR_renameat2 276
+#define __NR_seccomp 277
+#define __NR_getrandom 278
+#define __NR_memfd_create 279
+#define __NR_bpf 280
+#define __NR_execveat 281
+#define __NR_userfaultfd 282
+#define __NR_membarrier 283
+#define __NR_mlock2 284
+#define __NR_copy_file_range 285
+#define __NR_preadv2 286
+#define __NR_pwritev2 287
+#define __NR_pkey_mprotect 288
+#define __NR_pkey_alloc 289
+#define __NR_pkey_free 290
+#define __NR_statx 291
+#define __NR_io_pgetevents 292
+#define __NR_rseq 293
+#define __NR_kexec_file_load 294
+#define __NR_pidfd_send_signal 424
+#define __NR_io_uring_setup 425
+#define __NR_io_uring_enter 426
+#define __NR_io_uring_register 427
+#define __NR_open_tree 428
+#define __NR_move_mount 429
+#define __NR_fsopen 430
+#define __NR_fsconfig 431
+#define __NR_fsmount 432
+#define __NR_fspick 433
+#define __NR_pidfd_open 434
+#define __NR_clone3 435
+#define __NR_close_range 436
+#define __NR_openat2 437
+#define __NR_pidfd_getfd 438
+#define __NR_faccessat2 439
+#define __NR_process_madvise 440
+#define __NR_epoll_pwait2 441
+#define __NR_mount_setattr 442
+#define __NR_quotactl_fd 443
+#define __NR_landlock_create_ruleset 444
+#define __NR_landlock_add_rule 445
+#define __NR_landlock_restrict_self 446
+#define __NR_memfd_secret 447
+#define __NR_process_mrelease 448
+#define __NR_futex_waitv 449
+#define __NR_set_mempolicy_home_node 450
+#define __NR_cachestat 451
+#define __NR_fchmodat2 452
+#define __NR_map_shadow_stack 453
+#define __NR_futex_wake 454
+#define __NR_futex_wait 455
+#define __NR_futex_requeue 456
+#define __NR_statmount 457
+#define __NR_listmount 458
+#define __NR_lsm_get_self_attr 459
+#define __NR_lsm_set_self_attr 460
+#define __NR_lsm_list_modules 461
+#define __NR_mseal 462
+#endif
diff --git a/libc/kernel/uapi/asm-generic/unistd.h b/libc/kernel/uapi/asm-generic/unistd.h
index 7eaa89a51..652e7a2d0 100644
--- a/libc/kernel/uapi/asm-generic/unistd.h
+++ b/libc/kernel/uapi/asm-generic/unistd.h
@@ -381,9 +381,7 @@
 #define __NR_fsmount 432
 #define __NR_fspick 433
 #define __NR_pidfd_open 434
-#ifdef __ARCH_WANT_SYS_CLONE3
 #define __NR_clone3 435
-#endif
 #define __NR_close_range 436
 #define __NR_openat2 437
 #define __NR_pidfd_getfd 438
diff --git a/libc/kernel/uapi/asm-riscv/asm/hwprobe.h b/libc/kernel/uapi/asm-riscv/asm/hwprobe.h
index 3f30c889d..2e5f9a421 100644
--- a/libc/kernel/uapi/asm-riscv/asm/hwprobe.h
+++ b/libc/kernel/uapi/asm-riscv/asm/hwprobe.h
@@ -54,6 +54,18 @@ struct riscv_hwprobe {
 #define RISCV_HWPROBE_EXT_ZACAS (1ULL << 34)
 #define RISCV_HWPROBE_EXT_ZICOND (1ULL << 35)
 #define RISCV_HWPROBE_EXT_ZIHINTPAUSE (1ULL << 36)
+#define RISCV_HWPROBE_EXT_ZVE32X (1ULL << 37)
+#define RISCV_HWPROBE_EXT_ZVE32F (1ULL << 38)
+#define RISCV_HWPROBE_EXT_ZVE64X (1ULL << 39)
+#define RISCV_HWPROBE_EXT_ZVE64F (1ULL << 40)
+#define RISCV_HWPROBE_EXT_ZVE64D (1ULL << 41)
+#define RISCV_HWPROBE_EXT_ZIMOP (1ULL << 42)
+#define RISCV_HWPROBE_EXT_ZCA (1ULL << 43)
+#define RISCV_HWPROBE_EXT_ZCB (1ULL << 44)
+#define RISCV_HWPROBE_EXT_ZCD (1ULL << 45)
+#define RISCV_HWPROBE_EXT_ZCF (1ULL << 46)
+#define RISCV_HWPROBE_EXT_ZCMOP (1ULL << 47)
+#define RISCV_HWPROBE_EXT_ZAWRS (1ULL << 48)
 #define RISCV_HWPROBE_KEY_CPUPERF_0 5
 #define RISCV_HWPROBE_MISALIGNED_UNKNOWN (0 << 0)
 #define RISCV_HWPROBE_MISALIGNED_EMULATED (1 << 0)
@@ -62,5 +74,13 @@ struct riscv_hwprobe {
 #define RISCV_HWPROBE_MISALIGNED_UNSUPPORTED (4 << 0)
 #define RISCV_HWPROBE_MISALIGNED_MASK (7 << 0)
 #define RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE 6
+#define RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS 7
+#define RISCV_HWPROBE_KEY_TIME_CSR_FREQ 8
+#define RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF 9
+#define RISCV_HWPROBE_MISALIGNED_SCALAR_UNKNOWN 0
+#define RISCV_HWPROBE_MISALIGNED_SCALAR_EMULATED 1
+#define RISCV_HWPROBE_MISALIGNED_SCALAR_SLOW 2
+#define RISCV_HWPROBE_MISALIGNED_SCALAR_FAST 3
+#define RISCV_HWPROBE_MISALIGNED_SCALAR_UNSUPPORTED 4
 #define RISCV_HWPROBE_WHICH_CPUS (1 << 0)
 #endif
diff --git a/libc/kernel/uapi/asm-riscv/asm/kvm.h b/libc/kernel/uapi/asm-riscv/asm/kvm.h
index 12d8f614f..51f497747 100644
--- a/libc/kernel/uapi/asm-riscv/asm/kvm.h
+++ b/libc/kernel/uapi/asm-riscv/asm/kvm.h
@@ -128,6 +128,13 @@ enum KVM_RISCV_ISA_EXT_ID {
   KVM_RISCV_ISA_EXT_ZTSO,
   KVM_RISCV_ISA_EXT_ZACAS,
   KVM_RISCV_ISA_EXT_SSCOFPMF,
+  KVM_RISCV_ISA_EXT_ZIMOP,
+  KVM_RISCV_ISA_EXT_ZCA,
+  KVM_RISCV_ISA_EXT_ZCB,
+  KVM_RISCV_ISA_EXT_ZCD,
+  KVM_RISCV_ISA_EXT_ZCF,
+  KVM_RISCV_ISA_EXT_ZCMOP,
+  KVM_RISCV_ISA_EXT_ZAWRS,
   KVM_RISCV_ISA_EXT_MAX,
 };
 enum KVM_RISCV_SBI_EXT_ID {
diff --git a/libc/kernel/uapi/asm-riscv/asm/unistd.h b/libc/kernel/uapi/asm-riscv/asm/unistd.h
index 0c58887d9..f395f716b 100644
--- a/libc/kernel/uapi/asm-riscv/asm/unistd.h
+++ b/libc/kernel/uapi/asm-riscv/asm/unistd.h
@@ -4,18 +4,9 @@
  * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
  * for more information.
  */
-#if defined(__LP64__) && !defined(__SYSCALL_COMPAT)
-#define __ARCH_WANT_NEW_STAT
-#define __ARCH_WANT_SET_GET_RLIMIT
+#include <asm/bitsperlong.h>
+#if __BITS_PER_LONG == 64
+#include <asm/unistd_64.h>
+#else
+#include <asm/unistd_32.h>
 #endif
-#define __ARCH_WANT_SYS_CLONE3
-#define __ARCH_WANT_MEMFD_SECRET
-#include <asm-generic/unistd.h>
-#ifndef __NR_riscv_flush_icache
-#define __NR_riscv_flush_icache (__NR_arch_specific_syscall + 15)
-#endif
-__SYSCALL(__NR_riscv_flush_icache, sys_riscv_flush_icache)
-#ifndef __NR_riscv_hwprobe
-#define __NR_riscv_hwprobe (__NR_arch_specific_syscall + 14)
-#endif
-__SYSCALL(__NR_riscv_hwprobe, sys_riscv_hwprobe)
diff --git a/libc/kernel/uapi/asm-riscv/asm/unistd_32.h b/libc/kernel/uapi/asm-riscv/asm/unistd_32.h
new file mode 100644
index 000000000..864a55691
--- /dev/null
+++ b/libc/kernel/uapi/asm-riscv/asm/unistd_32.h
@@ -0,0 +1,318 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_ASM_UNISTD_32_H
+#define _UAPI_ASM_UNISTD_32_H
+#define __NR_io_setup 0
+#define __NR_io_destroy 1
+#define __NR_io_submit 2
+#define __NR_io_cancel 3
+#define __NR_setxattr 5
+#define __NR_lsetxattr 6
+#define __NR_fsetxattr 7
+#define __NR_getxattr 8
+#define __NR_lgetxattr 9
+#define __NR_fgetxattr 10
+#define __NR_listxattr 11
+#define __NR_llistxattr 12
+#define __NR_flistxattr 13
+#define __NR_removexattr 14
+#define __NR_lremovexattr 15
+#define __NR_fremovexattr 16
+#define __NR_getcwd 17
+#define __NR_lookup_dcookie 18
+#define __NR_eventfd2 19
+#define __NR_epoll_create1 20
+#define __NR_epoll_ctl 21
+#define __NR_epoll_pwait 22
+#define __NR_dup 23
+#define __NR_dup3 24
+#define __NR_fcntl64 25
+#define __NR_inotify_init1 26
+#define __NR_inotify_add_watch 27
+#define __NR_inotify_rm_watch 28
+#define __NR_ioctl 29
+#define __NR_ioprio_set 30
+#define __NR_ioprio_get 31
+#define __NR_flock 32
+#define __NR_mknodat 33
+#define __NR_mkdirat 34
+#define __NR_unlinkat 35
+#define __NR_symlinkat 36
+#define __NR_linkat 37
+#define __NR_umount2 39
+#define __NR_mount 40
+#define __NR_pivot_root 41
+#define __NR_nfsservctl 42
+#define __NR_statfs64 43
+#define __NR_fstatfs64 44
+#define __NR_truncate64 45
+#define __NR_ftruncate64 46
+#define __NR_fallocate 47
+#define __NR_faccessat 48
+#define __NR_chdir 49
+#define __NR_fchdir 50
+#define __NR_chroot 51
+#define __NR_fchmod 52
+#define __NR_fchmodat 53
+#define __NR_fchownat 54
+#define __NR_fchown 55
+#define __NR_openat 56
+#define __NR_close 57
+#define __NR_vhangup 58
+#define __NR_pipe2 59
+#define __NR_quotactl 60
+#define __NR_getdents64 61
+#define __NR_llseek 62
+#define __NR_read 63
+#define __NR_write 64
+#define __NR_readv 65
+#define __NR_writev 66
+#define __NR_pread64 67
+#define __NR_pwrite64 68
+#define __NR_preadv 69
+#define __NR_pwritev 70
+#define __NR_sendfile64 71
+#define __NR_signalfd4 74
+#define __NR_vmsplice 75
+#define __NR_splice 76
+#define __NR_tee 77
+#define __NR_readlinkat 78
+#define __NR_sync 81
+#define __NR_fsync 82
+#define __NR_fdatasync 83
+#define __NR_sync_file_range 84
+#define __NR_timerfd_create 85
+#define __NR_acct 89
+#define __NR_capget 90
+#define __NR_capset 91
+#define __NR_personality 92
+#define __NR_exit 93
+#define __NR_exit_group 94
+#define __NR_waitid 95
+#define __NR_set_tid_address 96
+#define __NR_unshare 97
+#define __NR_set_robust_list 99
+#define __NR_get_robust_list 100
+#define __NR_getitimer 102
+#define __NR_setitimer 103
+#define __NR_kexec_load 104
+#define __NR_init_module 105
+#define __NR_delete_module 106
+#define __NR_timer_create 107
+#define __NR_timer_getoverrun 109
+#define __NR_timer_delete 111
+#define __NR_syslog 116
+#define __NR_ptrace 117
+#define __NR_sched_setparam 118
+#define __NR_sched_setscheduler 119
+#define __NR_sched_getscheduler 120
+#define __NR_sched_getparam 121
+#define __NR_sched_setaffinity 122
+#define __NR_sched_getaffinity 123
+#define __NR_sched_yield 124
+#define __NR_sched_get_priority_max 125
+#define __NR_sched_get_priority_min 126
+#define __NR_restart_syscall 128
+#define __NR_kill 129
+#define __NR_tkill 130
+#define __NR_tgkill 131
+#define __NR_sigaltstack 132
+#define __NR_rt_sigsuspend 133
+#define __NR_rt_sigaction 134
+#define __NR_rt_sigprocmask 135
+#define __NR_rt_sigpending 136
+#define __NR_rt_sigqueueinfo 138
+#define __NR_rt_sigreturn 139
+#define __NR_setpriority 140
+#define __NR_getpriority 141
+#define __NR_reboot 142
+#define __NR_setregid 143
+#define __NR_setgid 144
+#define __NR_setreuid 145
+#define __NR_setuid 146
+#define __NR_setresuid 147
+#define __NR_getresuid 148
+#define __NR_setresgid 149
+#define __NR_getresgid 150
+#define __NR_setfsuid 151
+#define __NR_setfsgid 152
+#define __NR_times 153
+#define __NR_setpgid 154
+#define __NR_getpgid 155
+#define __NR_getsid 156
+#define __NR_setsid 157
+#define __NR_getgroups 158
+#define __NR_setgroups 159
+#define __NR_uname 160
+#define __NR_sethostname 161
+#define __NR_setdomainname 162
+#define __NR_getrusage 165
+#define __NR_umask 166
+#define __NR_prctl 167
+#define __NR_getcpu 168
+#define __NR_getpid 172
+#define __NR_getppid 173
+#define __NR_getuid 174
+#define __NR_geteuid 175
+#define __NR_getgid 176
+#define __NR_getegid 177
+#define __NR_gettid 178
+#define __NR_sysinfo 179
+#define __NR_mq_open 180
+#define __NR_mq_unlink 181
+#define __NR_mq_notify 184
+#define __NR_mq_getsetattr 185
+#define __NR_msgget 186
+#define __NR_msgctl 187
+#define __NR_msgrcv 188
+#define __NR_msgsnd 189
+#define __NR_semget 190
+#define __NR_semctl 191
+#define __NR_semop 193
+#define __NR_shmget 194
+#define __NR_shmctl 195
+#define __NR_shmat 196
+#define __NR_shmdt 197
+#define __NR_socket 198
+#define __NR_socketpair 199
+#define __NR_bind 200
+#define __NR_listen 201
+#define __NR_accept 202
+#define __NR_connect 203
+#define __NR_getsockname 204
+#define __NR_getpeername 205
+#define __NR_sendto 206
+#define __NR_recvfrom 207
+#define __NR_setsockopt 208
+#define __NR_getsockopt 209
+#define __NR_shutdown 210
+#define __NR_sendmsg 211
+#define __NR_recvmsg 212
+#define __NR_readahead 213
+#define __NR_brk 214
+#define __NR_munmap 215
+#define __NR_mremap 216
+#define __NR_add_key 217
+#define __NR_request_key 218
+#define __NR_keyctl 219
+#define __NR_clone 220
+#define __NR_execve 221
+#define __NR_mmap2 222
+#define __NR_fadvise64_64 223
+#define __NR_swapon 224
+#define __NR_swapoff 225
+#define __NR_mprotect 226
+#define __NR_msync 227
+#define __NR_mlock 228
+#define __NR_munlock 229
+#define __NR_mlockall 230
+#define __NR_munlockall 231
+#define __NR_mincore 232
+#define __NR_madvise 233
+#define __NR_remap_file_pages 234
+#define __NR_mbind 235
+#define __NR_get_mempolicy 236
+#define __NR_set_mempolicy 237
+#define __NR_migrate_pages 238
+#define __NR_move_pages 239
+#define __NR_rt_tgsigqueueinfo 240
+#define __NR_perf_event_open 241
+#define __NR_accept4 242
+#define __NR_riscv_hwprobe 258
+#define __NR_riscv_flush_icache 259
+#define __NR_prlimit64 261
+#define __NR_fanotify_init 262
+#define __NR_fanotify_mark 263
+#define __NR_name_to_handle_at 264
+#define __NR_open_by_handle_at 265
+#define __NR_syncfs 267
+#define __NR_setns 268
+#define __NR_sendmmsg 269
+#define __NR_process_vm_readv 270
+#define __NR_process_vm_writev 271
+#define __NR_kcmp 272
+#define __NR_finit_module 273
+#define __NR_sched_setattr 274
+#define __NR_sched_getattr 275
+#define __NR_renameat2 276
+#define __NR_seccomp 277
+#define __NR_getrandom 278
+#define __NR_memfd_create 279
+#define __NR_bpf 280
+#define __NR_execveat 281
+#define __NR_userfaultfd 282
+#define __NR_membarrier 283
+#define __NR_mlock2 284
+#define __NR_copy_file_range 285
+#define __NR_preadv2 286
+#define __NR_pwritev2 287
+#define __NR_pkey_mprotect 288
+#define __NR_pkey_alloc 289
+#define __NR_pkey_free 290
+#define __NR_statx 291
+#define __NR_rseq 293
+#define __NR_kexec_file_load 294
+#define __NR_clock_gettime64 403
+#define __NR_clock_settime64 404
+#define __NR_clock_adjtime64 405
+#define __NR_clock_getres_time64 406
+#define __NR_clock_nanosleep_time64 407
+#define __NR_timer_gettime64 408
+#define __NR_timer_settime64 409
+#define __NR_timerfd_gettime64 410
+#define __NR_timerfd_settime64 411
+#define __NR_utimensat_time64 412
+#define __NR_pselect6_time64 413
+#define __NR_ppoll_time64 414
+#define __NR_io_pgetevents_time64 416
+#define __NR_recvmmsg_time64 417
+#define __NR_mq_timedsend_time64 418
+#define __NR_mq_timedreceive_time64 419
+#define __NR_semtimedop_time64 420
+#define __NR_rt_sigtimedwait_time64 421
+#define __NR_futex_time64 422
+#define __NR_sched_rr_get_interval_time64 423
+#define __NR_pidfd_send_signal 424
+#define __NR_io_uring_setup 425
+#define __NR_io_uring_enter 426
+#define __NR_io_uring_register 427
+#define __NR_open_tree 428
+#define __NR_move_mount 429
+#define __NR_fsopen 430
+#define __NR_fsconfig 431
+#define __NR_fsmount 432
+#define __NR_fspick 433
+#define __NR_pidfd_open 434
+#define __NR_clone3 435
+#define __NR_close_range 436
+#define __NR_openat2 437
+#define __NR_pidfd_getfd 438
+#define __NR_faccessat2 439
+#define __NR_process_madvise 440
+#define __NR_epoll_pwait2 441
+#define __NR_mount_setattr 442
+#define __NR_quotactl_fd 443
+#define __NR_landlock_create_ruleset 444
+#define __NR_landlock_add_rule 445
+#define __NR_landlock_restrict_self 446
+#define __NR_memfd_secret 447
+#define __NR_process_mrelease 448
+#define __NR_futex_waitv 449
+#define __NR_set_mempolicy_home_node 450
+#define __NR_cachestat 451
+#define __NR_fchmodat2 452
+#define __NR_map_shadow_stack 453
+#define __NR_futex_wake 454
+#define __NR_futex_wait 455
+#define __NR_futex_requeue 456
+#define __NR_statmount 457
+#define __NR_listmount 458
+#define __NR_lsm_get_self_attr 459
+#define __NR_lsm_set_self_attr 460
+#define __NR_lsm_list_modules 461
+#define __NR_mseal 462
+#endif
diff --git a/libc/kernel/uapi/asm-riscv/asm/unistd_64.h b/libc/kernel/uapi/asm-riscv/asm/unistd_64.h
new file mode 100644
index 000000000..f15b65bdb
--- /dev/null
+++ b/libc/kernel/uapi/asm-riscv/asm/unistd_64.h
@@ -0,0 +1,328 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_ASM_UNISTD_64_H
+#define _UAPI_ASM_UNISTD_64_H
+#define __NR_io_setup 0
+#define __NR_io_destroy 1
+#define __NR_io_submit 2
+#define __NR_io_cancel 3
+#define __NR_io_getevents 4
+#define __NR_setxattr 5
+#define __NR_lsetxattr 6
+#define __NR_fsetxattr 7
+#define __NR_getxattr 8
+#define __NR_lgetxattr 9
+#define __NR_fgetxattr 10
+#define __NR_listxattr 11
+#define __NR_llistxattr 12
+#define __NR_flistxattr 13
+#define __NR_removexattr 14
+#define __NR_lremovexattr 15
+#define __NR_fremovexattr 16
+#define __NR_getcwd 17
+#define __NR_lookup_dcookie 18
+#define __NR_eventfd2 19
+#define __NR_epoll_create1 20
+#define __NR_epoll_ctl 21
+#define __NR_epoll_pwait 22
+#define __NR_dup 23
+#define __NR_dup3 24
+#define __NR_fcntl 25
+#define __NR_inotify_init1 26
+#define __NR_inotify_add_watch 27
+#define __NR_inotify_rm_watch 28
+#define __NR_ioctl 29
+#define __NR_ioprio_set 30
+#define __NR_ioprio_get 31
+#define __NR_flock 32
+#define __NR_mknodat 33
+#define __NR_mkdirat 34
+#define __NR_unlinkat 35
+#define __NR_symlinkat 36
+#define __NR_linkat 37
+#define __NR_umount2 39
+#define __NR_mount 40
+#define __NR_pivot_root 41
+#define __NR_nfsservctl 42
+#define __NR_statfs 43
+#define __NR_fstatfs 44
+#define __NR_truncate 45
+#define __NR_ftruncate 46
+#define __NR_fallocate 47
+#define __NR_faccessat 48
+#define __NR_chdir 49
+#define __NR_fchdir 50
+#define __NR_chroot 51
+#define __NR_fchmod 52
+#define __NR_fchmodat 53
+#define __NR_fchownat 54
+#define __NR_fchown 55
+#define __NR_openat 56
+#define __NR_close 57
+#define __NR_vhangup 58
+#define __NR_pipe2 59
+#define __NR_quotactl 60
+#define __NR_getdents64 61
+#define __NR_lseek 62
+#define __NR_read 63
+#define __NR_write 64
+#define __NR_readv 65
+#define __NR_writev 66
+#define __NR_pread64 67
+#define __NR_pwrite64 68
+#define __NR_preadv 69
+#define __NR_pwritev 70
+#define __NR_sendfile 71
+#define __NR_pselect6 72
+#define __NR_ppoll 73
+#define __NR_signalfd4 74
+#define __NR_vmsplice 75
+#define __NR_splice 76
+#define __NR_tee 77
+#define __NR_readlinkat 78
+#define __NR_newfstatat 79
+#define __NR_fstat 80
+#define __NR_sync 81
+#define __NR_fsync 82
+#define __NR_fdatasync 83
+#define __NR_sync_file_range 84
+#define __NR_timerfd_create 85
+#define __NR_timerfd_settime 86
+#define __NR_timerfd_gettime 87
+#define __NR_utimensat 88
+#define __NR_acct 89
+#define __NR_capget 90
+#define __NR_capset 91
+#define __NR_personality 92
+#define __NR_exit 93
+#define __NR_exit_group 94
+#define __NR_waitid 95
+#define __NR_set_tid_address 96
+#define __NR_unshare 97
+#define __NR_futex 98
+#define __NR_set_robust_list 99
+#define __NR_get_robust_list 100
+#define __NR_nanosleep 101
+#define __NR_getitimer 102
+#define __NR_setitimer 103
+#define __NR_kexec_load 104
+#define __NR_init_module 105
+#define __NR_delete_module 106
+#define __NR_timer_create 107
+#define __NR_timer_gettime 108
+#define __NR_timer_getoverrun 109
+#define __NR_timer_settime 110
+#define __NR_timer_delete 111
+#define __NR_clock_settime 112
+#define __NR_clock_gettime 113
+#define __NR_clock_getres 114
+#define __NR_clock_nanosleep 115
+#define __NR_syslog 116
+#define __NR_ptrace 117
+#define __NR_sched_setparam 118
+#define __NR_sched_setscheduler 119
+#define __NR_sched_getscheduler 120
+#define __NR_sched_getparam 121
+#define __NR_sched_setaffinity 122
+#define __NR_sched_getaffinity 123
+#define __NR_sched_yield 124
+#define __NR_sched_get_priority_max 125
+#define __NR_sched_get_priority_min 126
+#define __NR_sched_rr_get_interval 127
+#define __NR_restart_syscall 128
+#define __NR_kill 129
+#define __NR_tkill 130
+#define __NR_tgkill 131
+#define __NR_sigaltstack 132
+#define __NR_rt_sigsuspend 133
+#define __NR_rt_sigaction 134
+#define __NR_rt_sigprocmask 135
+#define __NR_rt_sigpending 136
+#define __NR_rt_sigtimedwait 137
+#define __NR_rt_sigqueueinfo 138
+#define __NR_rt_sigreturn 139
+#define __NR_setpriority 140
+#define __NR_getpriority 141
+#define __NR_reboot 142
+#define __NR_setregid 143
+#define __NR_setgid 144
+#define __NR_setreuid 145
+#define __NR_setuid 146
+#define __NR_setresuid 147
+#define __NR_getresuid 148
+#define __NR_setresgid 149
+#define __NR_getresgid 150
+#define __NR_setfsuid 151
+#define __NR_setfsgid 152
+#define __NR_times 153
+#define __NR_setpgid 154
+#define __NR_getpgid 155
+#define __NR_getsid 156
+#define __NR_setsid 157
+#define __NR_getgroups 158
+#define __NR_setgroups 159
+#define __NR_uname 160
+#define __NR_sethostname 161
+#define __NR_setdomainname 162
+#define __NR_getrlimit 163
+#define __NR_setrlimit 164
+#define __NR_getrusage 165
+#define __NR_umask 166
+#define __NR_prctl 167
+#define __NR_getcpu 168
+#define __NR_gettimeofday 169
+#define __NR_settimeofday 170
+#define __NR_adjtimex 171
+#define __NR_getpid 172
+#define __NR_getppid 173
+#define __NR_getuid 174
+#define __NR_geteuid 175
+#define __NR_getgid 176
+#define __NR_getegid 177
+#define __NR_gettid 178
+#define __NR_sysinfo 179
+#define __NR_mq_open 180
+#define __NR_mq_unlink 181
+#define __NR_mq_timedsend 182
+#define __NR_mq_timedreceive 183
+#define __NR_mq_notify 184
+#define __NR_mq_getsetattr 185
+#define __NR_msgget 186
+#define __NR_msgctl 187
+#define __NR_msgrcv 188
+#define __NR_msgsnd 189
+#define __NR_semget 190
+#define __NR_semctl 191
+#define __NR_semtimedop 192
+#define __NR_semop 193
+#define __NR_shmget 194
+#define __NR_shmctl 195
+#define __NR_shmat 196
+#define __NR_shmdt 197
+#define __NR_socket 198
+#define __NR_socketpair 199
+#define __NR_bind 200
+#define __NR_listen 201
+#define __NR_accept 202
+#define __NR_connect 203
+#define __NR_getsockname 204
+#define __NR_getpeername 205
+#define __NR_sendto 206
+#define __NR_recvfrom 207
+#define __NR_setsockopt 208
+#define __NR_getsockopt 209
+#define __NR_shutdown 210
+#define __NR_sendmsg 211
+#define __NR_recvmsg 212
+#define __NR_readahead 213
+#define __NR_brk 214
+#define __NR_munmap 215
+#define __NR_mremap 216
+#define __NR_add_key 217
+#define __NR_request_key 218
+#define __NR_keyctl 219
+#define __NR_clone 220
+#define __NR_execve 221
+#define __NR_mmap 222
+#define __NR_fadvise64 223
+#define __NR_swapon 224
+#define __NR_swapoff 225
+#define __NR_mprotect 226
+#define __NR_msync 227
+#define __NR_mlock 228
+#define __NR_munlock 229
+#define __NR_mlockall 230
+#define __NR_munlockall 231
+#define __NR_mincore 232
+#define __NR_madvise 233
+#define __NR_remap_file_pages 234
+#define __NR_mbind 235
+#define __NR_get_mempolicy 236
+#define __NR_set_mempolicy 237
+#define __NR_migrate_pages 238
+#define __NR_move_pages 239
+#define __NR_rt_tgsigqueueinfo 240
+#define __NR_perf_event_open 241
+#define __NR_accept4 242
+#define __NR_recvmmsg 243
+#define __NR_riscv_hwprobe 258
+#define __NR_riscv_flush_icache 259
+#define __NR_wait4 260
+#define __NR_prlimit64 261
+#define __NR_fanotify_init 262
+#define __NR_fanotify_mark 263
+#define __NR_name_to_handle_at 264
+#define __NR_open_by_handle_at 265
+#define __NR_clock_adjtime 266
+#define __NR_syncfs 267
+#define __NR_setns 268
+#define __NR_sendmmsg 269
+#define __NR_process_vm_readv 270
+#define __NR_process_vm_writev 271
+#define __NR_kcmp 272
+#define __NR_finit_module 273
+#define __NR_sched_setattr 274
+#define __NR_sched_getattr 275
+#define __NR_renameat2 276
+#define __NR_seccomp 277
+#define __NR_getrandom 278
+#define __NR_memfd_create 279
+#define __NR_bpf 280
+#define __NR_execveat 281
+#define __NR_userfaultfd 282
+#define __NR_membarrier 283
+#define __NR_mlock2 284
+#define __NR_copy_file_range 285
+#define __NR_preadv2 286
+#define __NR_pwritev2 287
+#define __NR_pkey_mprotect 288
+#define __NR_pkey_alloc 289
+#define __NR_pkey_free 290
+#define __NR_statx 291
+#define __NR_io_pgetevents 292
+#define __NR_rseq 293
+#define __NR_kexec_file_load 294
+#define __NR_pidfd_send_signal 424
+#define __NR_io_uring_setup 425
+#define __NR_io_uring_enter 426
+#define __NR_io_uring_register 427
+#define __NR_open_tree 428
+#define __NR_move_mount 429
+#define __NR_fsopen 430
+#define __NR_fsconfig 431
+#define __NR_fsmount 432
+#define __NR_fspick 433
+#define __NR_pidfd_open 434
+#define __NR_clone3 435
+#define __NR_close_range 436
+#define __NR_openat2 437
+#define __NR_pidfd_getfd 438
+#define __NR_faccessat2 439
+#define __NR_process_madvise 440
+#define __NR_epoll_pwait2 441
+#define __NR_mount_setattr 442
+#define __NR_quotactl_fd 443
+#define __NR_landlock_create_ruleset 444
+#define __NR_landlock_add_rule 445
+#define __NR_landlock_restrict_self 446
+#define __NR_memfd_secret 447
+#define __NR_process_mrelease 448
+#define __NR_futex_waitv 449
+#define __NR_set_mempolicy_home_node 450
+#define __NR_cachestat 451
+#define __NR_fchmodat2 452
+#define __NR_map_shadow_stack 453
+#define __NR_futex_wake 454
+#define __NR_futex_wait 455
+#define __NR_futex_requeue 456
+#define __NR_statmount 457
+#define __NR_listmount 458
+#define __NR_lsm_get_self_attr 459
+#define __NR_lsm_set_self_attr 460
+#define __NR_lsm_list_modules 461
+#define __NR_mseal 462
+#endif
diff --git a/libc/kernel/uapi/asm-x86/asm/kvm.h b/libc/kernel/uapi/asm-x86/asm/kvm.h
index 17b1c5dce..cd647b6d8 100644
--- a/libc/kernel/uapi/asm-x86/asm/kvm.h
+++ b/libc/kernel/uapi/asm-x86/asm/kvm.h
@@ -94,6 +94,7 @@ struct kvm_ioapic_state {
 #define KVM_NR_IRQCHIPS 3
 #define KVM_RUN_X86_SMM (1 << 0)
 #define KVM_RUN_X86_BUS_LOCK (1 << 1)
+#define KVM_RUN_X86_GUEST_MODE (1 << 2)
 struct kvm_regs {
   __u64 rax, rbx, rcx, rdx;
   __u64 rsi, rdi, rsp, rbp;
@@ -532,6 +533,9 @@ enum sev_cmd_id {
   KVM_SEV_GET_ATTESTATION_REPORT,
   KVM_SEV_SEND_CANCEL,
   KVM_SEV_INIT2,
+  KVM_SEV_SNP_LAUNCH_START = 100,
+  KVM_SEV_SNP_LAUNCH_UPDATE,
+  KVM_SEV_SNP_LAUNCH_FINISH,
   KVM_SEV_NR_MAX,
 };
 struct kvm_sev_cmd {
@@ -644,6 +648,42 @@ struct kvm_sev_receive_update_data {
   __u32 trans_len;
   __u32 pad2;
 };
+struct kvm_sev_snp_launch_start {
+  __u64 policy;
+  __u8 gosvw[16];
+  __u16 flags;
+  __u8 pad0[6];
+  __u64 pad1[4];
+};
+#define KVM_SEV_SNP_PAGE_TYPE_NORMAL 0x1
+#define KVM_SEV_SNP_PAGE_TYPE_ZERO 0x3
+#define KVM_SEV_SNP_PAGE_TYPE_UNMEASURED 0x4
+#define KVM_SEV_SNP_PAGE_TYPE_SECRETS 0x5
+#define KVM_SEV_SNP_PAGE_TYPE_CPUID 0x6
+struct kvm_sev_snp_launch_update {
+  __u64 gfn_start;
+  __u64 uaddr;
+  __u64 len;
+  __u8 type;
+  __u8 pad0;
+  __u16 flags;
+  __u32 pad1;
+  __u64 pad2[4];
+};
+#define KVM_SEV_SNP_ID_BLOCK_SIZE 96
+#define KVM_SEV_SNP_ID_AUTH_SIZE 4096
+#define KVM_SEV_SNP_FINISH_DATA_SIZE 32
+struct kvm_sev_snp_launch_finish {
+  __u64 id_block_uaddr;
+  __u64 id_auth_uaddr;
+  __u8 id_block_en;
+  __u8 auth_key_en;
+  __u8 vcek_disabled;
+  __u8 host_data[KVM_SEV_SNP_FINISH_DATA_SIZE];
+  __u8 pad0[3];
+  __u16 flags;
+  __u64 pad1[4];
+};
 #define KVM_X2APIC_API_USE_32BIT_IDS (1ULL << 0)
 #define KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK (1ULL << 1)
 struct kvm_hyperv_eventfd {
@@ -667,4 +707,5 @@ struct kvm_hyperv_eventfd {
 #define KVM_X86_SW_PROTECTED_VM 1
 #define KVM_X86_SEV_VM 2
 #define KVM_X86_SEV_ES_VM 3
+#define KVM_X86_SNP_VM 4
 #endif
diff --git a/libc/kernel/uapi/asm-x86/asm/svm.h b/libc/kernel/uapi/asm-x86/asm/svm.h
index ffbf0b3fc..4f165faec 100644
--- a/libc/kernel/uapi/asm-x86/asm/svm.h
+++ b/libc/kernel/uapi/asm-x86/asm/svm.h
@@ -117,6 +117,7 @@
 #define SVM_VMGEXIT_AP_CREATE_ON_INIT 0
 #define SVM_VMGEXIT_AP_CREATE 1
 #define SVM_VMGEXIT_AP_DESTROY 2
+#define SVM_VMGEXIT_SNP_RUN_VMPL 0x80000018
 #define SVM_VMGEXIT_HV_FEATURES 0x8000fffd
 #define SVM_VMGEXIT_TERM_REQUEST 0x8000fffe
 #define SVM_VMGEXIT_TERM_REASON(reason_set,reason_code) (((((u64) reason_set) & 0xf)) | ((((u64) reason_code) & 0xff) << 4))
diff --git a/libc/kernel/uapi/asm-x86/asm/unistd_64.h b/libc/kernel/uapi/asm-x86/asm/unistd_64.h
index 5dd666ca2..d5408a33c 100644
--- a/libc/kernel/uapi/asm-x86/asm/unistd_64.h
+++ b/libc/kernel/uapi/asm-x86/asm/unistd_64.h
@@ -341,6 +341,7 @@
 #define __NR_statx 332
 #define __NR_io_pgetevents 333
 #define __NR_rseq 334
+#define __NR_uretprobe 335
 #define __NR_pidfd_send_signal 424
 #define __NR_io_uring_setup 425
 #define __NR_io_uring_enter 426
diff --git a/libc/kernel/uapi/asm-x86/asm/unistd_x32.h b/libc/kernel/uapi/asm-x86/asm/unistd_x32.h
index a2ff6f441..fdcf7e6bd 100644
--- a/libc/kernel/uapi/asm-x86/asm/unistd_x32.h
+++ b/libc/kernel/uapi/asm-x86/asm/unistd_x32.h
@@ -294,6 +294,7 @@
 #define __NR_statx (__X32_SYSCALL_BIT + 332)
 #define __NR_io_pgetevents (__X32_SYSCALL_BIT + 333)
 #define __NR_rseq (__X32_SYSCALL_BIT + 334)
+#define __NR_uretprobe (__X32_SYSCALL_BIT + 335)
 #define __NR_pidfd_send_signal (__X32_SYSCALL_BIT + 424)
 #define __NR_io_uring_setup (__X32_SYSCALL_BIT + 425)
 #define __NR_io_uring_enter (__X32_SYSCALL_BIT + 426)
diff --git a/libc/kernel/uapi/drm/amdgpu_drm.h b/libc/kernel/uapi/drm/amdgpu_drm.h
index 0ad0bc249..7bbd5de4f 100644
--- a/libc/kernel/uapi/drm/amdgpu_drm.h
+++ b/libc/kernel/uapi/drm/amdgpu_drm.h
@@ -65,6 +65,7 @@ extern "C" {
 #define AMDGPU_GEM_CREATE_COHERENT (1 << 13)
 #define AMDGPU_GEM_CREATE_UNCACHED (1 << 14)
 #define AMDGPU_GEM_CREATE_EXT_COHERENT (1 << 15)
+#define AMDGPU_GEM_CREATE_GFX12_DCC (1 << 16)
 struct drm_amdgpu_gem_create_in {
   __u64 bo_size;
   __u64 alignment;
@@ -216,6 +217,14 @@ struct drm_amdgpu_gem_userptr {
 #define AMDGPU_TILING_DCC_INDEPENDENT_128B_MASK 0x1
 #define AMDGPU_TILING_SCANOUT_SHIFT 63
 #define AMDGPU_TILING_SCANOUT_MASK 0x1
+#define AMDGPU_TILING_GFX12_SWIZZLE_MODE_SHIFT 0
+#define AMDGPU_TILING_GFX12_SWIZZLE_MODE_MASK 0x7
+#define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_SHIFT 3
+#define AMDGPU_TILING_GFX12_DCC_MAX_COMPRESSED_BLOCK_MASK 0x3
+#define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_SHIFT 5
+#define AMDGPU_TILING_GFX12_DCC_NUMBER_TYPE_MASK 0x7
+#define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_SHIFT 8
+#define AMDGPU_TILING_GFX12_DCC_DATA_FORMAT_MASK 0x3f
 #define AMDGPU_TILING_SET(field,value) (((__u64) (value) & AMDGPU_TILING_ ##field ##_MASK) << AMDGPU_TILING_ ##field ##_SHIFT)
 #define AMDGPU_TILING_GET(value,field) (((__u64) (value) >> AMDGPU_TILING_ ##field ##_SHIFT) & AMDGPU_TILING_ ##field ##_MASK)
 #define AMDGPU_GEM_METADATA_OP_SET_METADATA 1
@@ -744,6 +753,10 @@ struct drm_amdgpu_info_gpuvm_fault {
 #define AMDGPU_FAMILY_GC_10_3_6 149
 #define AMDGPU_FAMILY_GC_10_3_7 151
 #define AMDGPU_FAMILY_GC_11_5_0 150
+#define AMDGPU_FAMILY_GC_12_0_0 152
+struct drm_color_ctm_3x4 {
+  __u64 matrix[12];
+};
 #ifdef __cplusplus
 }
 #endif
diff --git a/libc/kernel/uapi/drm/drm_fourcc.h b/libc/kernel/uapi/drm/drm_fourcc.h
index 6fd2eb87e..4902d6c4e 100644
--- a/libc/kernel/uapi/drm/drm_fourcc.h
+++ b/libc/kernel/uapi/drm/drm_fourcc.h
@@ -255,12 +255,17 @@ extern "C" {
 #define AMD_FMT_MOD_TILE_VER_GFX10 2
 #define AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS 3
 #define AMD_FMT_MOD_TILE_VER_GFX11 4
+#define AMD_FMT_MOD_TILE_VER_GFX12 5
 #define AMD_FMT_MOD_TILE_GFX9_64K_S 9
 #define AMD_FMT_MOD_TILE_GFX9_64K_D 10
 #define AMD_FMT_MOD_TILE_GFX9_64K_S_X 25
 #define AMD_FMT_MOD_TILE_GFX9_64K_D_X 26
 #define AMD_FMT_MOD_TILE_GFX9_64K_R_X 27
 #define AMD_FMT_MOD_TILE_GFX11_256K_R_X 31
+#define AMD_FMT_MOD_TILE_GFX12_256B_2D 1
+#define AMD_FMT_MOD_TILE_GFX12_4K_2D 2
+#define AMD_FMT_MOD_TILE_GFX12_64K_2D 3
+#define AMD_FMT_MOD_TILE_GFX12_256K_2D 4
 #define AMD_FMT_MOD_DCC_BLOCK_64B 0
 #define AMD_FMT_MOD_DCC_BLOCK_128B 1
 #define AMD_FMT_MOD_DCC_BLOCK_256B 2
diff --git a/libc/kernel/uapi/drm/drm_mode.h b/libc/kernel/uapi/drm/drm_mode.h
index 8fccdaf15..06c91c53c 100644
--- a/libc/kernel/uapi/drm/drm_mode.h
+++ b/libc/kernel/uapi/drm/drm_mode.h
@@ -357,9 +357,6 @@ struct drm_mode_crtc_lut {
 struct drm_color_ctm {
   __u64 matrix[9];
 };
-struct drm_color_ctm_3x4 {
-  __u64 matrix[12];
-};
 struct drm_color_lut {
   __u16 red;
   __u16 green;
diff --git a/libc/kernel/uapi/drm/i915_drm.h b/libc/kernel/uapi/drm/i915_drm.h
index 13eda7c2e..b43d8df5d 100644
--- a/libc/kernel/uapi/drm/i915_drm.h
+++ b/libc/kernel/uapi/drm/i915_drm.h
@@ -745,6 +745,7 @@ struct drm_i915_gem_context_param {
 #define I915_CONTEXT_PARAM_RINGSIZE 0xc
 #define I915_CONTEXT_PARAM_PROTECTED_CONTENT 0xd
 #define I915_CONTEXT_PARAM_LOW_LATENCY 0xe
+#define I915_CONTEXT_PARAM_CONTEXT_IMAGE 0xf
   __u64 value;
 };
 struct drm_i915_gem_context_param_sseu {
@@ -799,6 +800,14 @@ struct i915_context_param_engines {
 } __attribute__((packed));
 #define I915_DEFINE_CONTEXT_PARAM_ENGINES(name__,N__) struct { __u64 extensions; struct i915_engine_class_instance engines[N__]; \
 } __attribute__((packed)) name__
+struct i915_gem_context_param_context_image {
+  struct i915_engine_class_instance engine;
+  __u32 flags;
+#define I915_CONTEXT_IMAGE_FLAG_ENGINE_INDEX (1u << 0)
+  __u32 size;
+  __u32 mbz;
+  __u64 image;
+} __attribute__((packed));
 struct drm_i915_gem_context_create_ext_setparam {
   struct i915_user_extension base;
   struct drm_i915_gem_context_param param;
diff --git a/libc/kernel/uapi/drm/ivpu_accel.h b/libc/kernel/uapi/drm/ivpu_accel.h
index fcbf6f7fb..960bd43a7 100644
--- a/libc/kernel/uapi/drm/ivpu_accel.h
+++ b/libc/kernel/uapi/drm/ivpu_accel.h
@@ -18,12 +18,20 @@ extern "C" {
 #define DRM_IVPU_BO_INFO 0x03
 #define DRM_IVPU_SUBMIT 0x05
 #define DRM_IVPU_BO_WAIT 0x06
+#define DRM_IVPU_METRIC_STREAMER_START 0x07
+#define DRM_IVPU_METRIC_STREAMER_STOP 0x08
+#define DRM_IVPU_METRIC_STREAMER_GET_DATA 0x09
+#define DRM_IVPU_METRIC_STREAMER_GET_INFO 0x0a
 #define DRM_IOCTL_IVPU_GET_PARAM DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_GET_PARAM, struct drm_ivpu_param)
 #define DRM_IOCTL_IVPU_SET_PARAM DRM_IOW(DRM_COMMAND_BASE + DRM_IVPU_SET_PARAM, struct drm_ivpu_param)
 #define DRM_IOCTL_IVPU_BO_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_BO_CREATE, struct drm_ivpu_bo_create)
 #define DRM_IOCTL_IVPU_BO_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_BO_INFO, struct drm_ivpu_bo_info)
 #define DRM_IOCTL_IVPU_SUBMIT DRM_IOW(DRM_COMMAND_BASE + DRM_IVPU_SUBMIT, struct drm_ivpu_submit)
 #define DRM_IOCTL_IVPU_BO_WAIT DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_BO_WAIT, struct drm_ivpu_bo_wait)
+#define DRM_IOCTL_IVPU_METRIC_STREAMER_START DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_START, struct drm_ivpu_metric_streamer_start)
+#define DRM_IOCTL_IVPU_METRIC_STREAMER_STOP DRM_IOW(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_STOP, struct drm_ivpu_metric_streamer_stop)
+#define DRM_IOCTL_IVPU_METRIC_STREAMER_GET_DATA DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_GET_DATA, struct drm_ivpu_metric_streamer_get_data)
+#define DRM_IOCTL_IVPU_METRIC_STREAMER_GET_INFO DRM_IOWR(DRM_COMMAND_BASE + DRM_IVPU_METRIC_STREAMER_GET_INFO, struct drm_ivpu_metric_streamer_get_data)
 #define DRM_IVPU_PARAM_DEVICE_ID 0
 #define DRM_IVPU_PARAM_DEVICE_REVISION 1
 #define DRM_IVPU_PARAM_PLATFORM_TYPE 2
@@ -96,6 +104,22 @@ struct drm_ivpu_bo_wait {
   __u32 job_status;
   __u32 pad;
 };
+struct drm_ivpu_metric_streamer_start {
+  __u64 metric_group_mask;
+  __u64 sampling_period_ns;
+  __u32 read_period_samples;
+  __u32 sample_size;
+  __u32 max_data_size;
+};
+struct drm_ivpu_metric_streamer_get_data {
+  __u64 metric_group_mask;
+  __u64 buffer_ptr;
+  __u64 buffer_size;
+  __u64 data_size;
+};
+struct drm_ivpu_metric_streamer_stop {
+  __u64 metric_group_mask;
+};
 #ifdef __cplusplus
 }
 #endif
diff --git a/libc/kernel/uapi/drm/msm_drm.h b/libc/kernel/uapi/drm/msm_drm.h
index 4d837440b..7ec5ed2a3 100644
--- a/libc/kernel/uapi/drm/msm_drm.h
+++ b/libc/kernel/uapi/drm/msm_drm.h
@@ -37,6 +37,7 @@ struct drm_msm_timespec {
 #define MSM_PARAM_VA_START 0x0e
 #define MSM_PARAM_VA_SIZE 0x0f
 #define MSM_PARAM_HIGHEST_BANK_BIT 0x10
+#define MSM_PARAM_RAYTRACING 0x11
 #define MSM_PARAM_NR_RINGS MSM_PARAM_PRIORITIES
 struct drm_msm_param {
   __u32 pipe;
diff --git a/libc/kernel/uapi/drm/v3d_drm.h b/libc/kernel/uapi/drm/v3d_drm.h
index 4000fd3e6..b7aca21d1 100644
--- a/libc/kernel/uapi/drm/v3d_drm.h
+++ b/libc/kernel/uapi/drm/v3d_drm.h
@@ -22,6 +22,7 @@ extern "C" {
 #define DRM_V3D_PERFMON_DESTROY 0x09
 #define DRM_V3D_PERFMON_GET_VALUES 0x0a
 #define DRM_V3D_SUBMIT_CPU 0x0b
+#define DRM_V3D_PERFMON_GET_COUNTER 0x0c
 #define DRM_IOCTL_V3D_SUBMIT_CL DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_SUBMIT_CL, struct drm_v3d_submit_cl)
 #define DRM_IOCTL_V3D_WAIT_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_WAIT_BO, struct drm_v3d_wait_bo)
 #define DRM_IOCTL_V3D_CREATE_BO DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_CREATE_BO, struct drm_v3d_create_bo)
@@ -34,6 +35,7 @@ extern "C" {
 #define DRM_IOCTL_V3D_PERFMON_DESTROY DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_PERFMON_DESTROY, struct drm_v3d_perfmon_destroy)
 #define DRM_IOCTL_V3D_PERFMON_GET_VALUES DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_PERFMON_GET_VALUES, struct drm_v3d_perfmon_get_values)
 #define DRM_IOCTL_V3D_SUBMIT_CPU DRM_IOW(DRM_COMMAND_BASE + DRM_V3D_SUBMIT_CPU, struct drm_v3d_submit_cpu)
+#define DRM_IOCTL_V3D_PERFMON_GET_COUNTER DRM_IOWR(DRM_COMMAND_BASE + DRM_V3D_PERFMON_GET_COUNTER, struct drm_v3d_perfmon_get_counter)
 #define DRM_V3D_SUBMIT_CL_FLUSH_CACHE 0x01
 #define DRM_V3D_SUBMIT_EXTENSION 0x02
 struct drm_v3d_extension {
@@ -119,6 +121,7 @@ enum drm_v3d_param {
   DRM_V3D_PARAM_SUPPORTS_PERFMON,
   DRM_V3D_PARAM_SUPPORTS_MULTISYNC_EXT,
   DRM_V3D_PARAM_SUPPORTS_CPU_QUEUE,
+  DRM_V3D_PARAM_MAX_PERF_COUNTERS,
 };
 struct drm_v3d_get_param {
   __u32 param;
@@ -324,6 +327,16 @@ struct drm_v3d_perfmon_get_values {
   __u32 pad;
   __u64 values_ptr;
 };
+#define DRM_V3D_PERFCNT_MAX_NAME 64
+#define DRM_V3D_PERFCNT_MAX_CATEGORY 32
+#define DRM_V3D_PERFCNT_MAX_DESCRIPTION 256
+struct drm_v3d_perfmon_get_counter {
+  __u8 counter;
+  __u8 name[DRM_V3D_PERFCNT_MAX_NAME];
+  __u8 category[DRM_V3D_PERFCNT_MAX_CATEGORY];
+  __u8 description[DRM_V3D_PERFCNT_MAX_DESCRIPTION];
+  __u8 reserved[7];
+};
 #ifdef __cplusplus
 }
 #endif
diff --git a/libc/kernel/uapi/drm/xe_drm.h b/libc/kernel/uapi/drm/xe_drm.h
index d1b6dad75..a034b2921 100644
--- a/libc/kernel/uapi/drm/xe_drm.h
+++ b/libc/kernel/uapi/drm/xe_drm.h
@@ -21,6 +21,7 @@ extern "C" {
 #define DRM_XE_EXEC_QUEUE_GET_PROPERTY 0x08
 #define DRM_XE_EXEC 0x09
 #define DRM_XE_WAIT_USER_FENCE 0x0a
+#define DRM_XE_OBSERVATION 0x0b
 #define DRM_IOCTL_XE_DEVICE_QUERY DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_DEVICE_QUERY, struct drm_xe_device_query)
 #define DRM_IOCTL_XE_GEM_CREATE DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_GEM_CREATE, struct drm_xe_gem_create)
 #define DRM_IOCTL_XE_GEM_MMAP_OFFSET DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_GEM_MMAP_OFFSET, struct drm_xe_gem_mmap_offset)
@@ -32,6 +33,7 @@ extern "C" {
 #define DRM_IOCTL_XE_EXEC_QUEUE_GET_PROPERTY DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_EXEC_QUEUE_GET_PROPERTY, struct drm_xe_exec_queue_get_property)
 #define DRM_IOCTL_XE_EXEC DRM_IOW(DRM_COMMAND_BASE + DRM_XE_EXEC, struct drm_xe_exec)
 #define DRM_IOCTL_XE_WAIT_USER_FENCE DRM_IOWR(DRM_COMMAND_BASE + DRM_XE_WAIT_USER_FENCE, struct drm_xe_wait_user_fence)
+#define DRM_IOCTL_XE_OBSERVATION DRM_IOW(DRM_COMMAND_BASE + DRM_XE_OBSERVATION, struct drm_xe_observation_param)
 struct drm_xe_user_extension {
   __u64 next_extension;
   __u32 name;
@@ -120,6 +122,7 @@ struct drm_xe_query_topology_mask {
   __u16 gt_id;
 #define DRM_XE_TOPO_DSS_GEOMETRY 1
 #define DRM_XE_TOPO_DSS_COMPUTE 2
+#define DRM_XE_TOPO_L3_BANK 3
 #define DRM_XE_TOPO_EU_PER_DSS 4
   __u16 type;
   __u32 num_bytes;
@@ -155,6 +158,7 @@ struct drm_xe_device_query {
 #define DRM_XE_DEVICE_QUERY_GT_TOPOLOGY 5
 #define DRM_XE_DEVICE_QUERY_ENGINE_CYCLES 6
 #define DRM_XE_DEVICE_QUERY_UC_FW_VERSION 7
+#define DRM_XE_DEVICE_QUERY_OA_UNITS 8
   __u32 query;
   __u32 size;
   __u64 data;
@@ -309,6 +313,92 @@ struct drm_xe_wait_user_fence {
   __u32 pad2;
   __u64 reserved[2];
 };
+enum drm_xe_observation_type {
+  DRM_XE_OBSERVATION_TYPE_OA,
+};
+enum drm_xe_observation_op {
+  DRM_XE_OBSERVATION_OP_STREAM_OPEN,
+  DRM_XE_OBSERVATION_OP_ADD_CONFIG,
+  DRM_XE_OBSERVATION_OP_REMOVE_CONFIG,
+};
+struct drm_xe_observation_param {
+  __u64 extensions;
+  __u64 observation_type;
+  __u64 observation_op;
+  __u64 param;
+};
+enum drm_xe_observation_ioctls {
+  DRM_XE_OBSERVATION_IOCTL_ENABLE = _IO('i', 0x0),
+  DRM_XE_OBSERVATION_IOCTL_DISABLE = _IO('i', 0x1),
+  DRM_XE_OBSERVATION_IOCTL_CONFIG = _IO('i', 0x2),
+  DRM_XE_OBSERVATION_IOCTL_STATUS = _IO('i', 0x3),
+  DRM_XE_OBSERVATION_IOCTL_INFO = _IO('i', 0x4),
+};
+enum drm_xe_oa_unit_type {
+  DRM_XE_OA_UNIT_TYPE_OAG,
+  DRM_XE_OA_UNIT_TYPE_OAM,
+};
+struct drm_xe_oa_unit {
+  __u64 extensions;
+  __u32 oa_unit_id;
+  __u32 oa_unit_type;
+  __u64 capabilities;
+#define DRM_XE_OA_CAPS_BASE (1 << 0)
+  __u64 oa_timestamp_freq;
+  __u64 reserved[4];
+  __u64 num_engines;
+  struct drm_xe_engine_class_instance eci[];
+};
+struct drm_xe_query_oa_units {
+  __u64 extensions;
+  __u32 num_oa_units;
+  __u32 pad;
+  __u64 oa_units[];
+};
+enum drm_xe_oa_format_type {
+  DRM_XE_OA_FMT_TYPE_OAG,
+  DRM_XE_OA_FMT_TYPE_OAR,
+  DRM_XE_OA_FMT_TYPE_OAM,
+  DRM_XE_OA_FMT_TYPE_OAC,
+  DRM_XE_OA_FMT_TYPE_OAM_MPEC,
+  DRM_XE_OA_FMT_TYPE_PEC,
+};
+enum drm_xe_oa_property_id {
+#define DRM_XE_OA_EXTENSION_SET_PROPERTY 0
+  DRM_XE_OA_PROPERTY_OA_UNIT_ID = 1,
+  DRM_XE_OA_PROPERTY_SAMPLE_OA,
+  DRM_XE_OA_PROPERTY_OA_METRIC_SET,
+  DRM_XE_OA_PROPERTY_OA_FORMAT,
+#define DRM_XE_OA_FORMAT_MASK_FMT_TYPE (0xffu << 0)
+#define DRM_XE_OA_FORMAT_MASK_COUNTER_SEL (0xffu << 8)
+#define DRM_XE_OA_FORMAT_MASK_COUNTER_SIZE (0xffu << 16)
+#define DRM_XE_OA_FORMAT_MASK_BC_REPORT (0xffu << 24)
+  DRM_XE_OA_PROPERTY_OA_PERIOD_EXPONENT,
+  DRM_XE_OA_PROPERTY_OA_DISABLED,
+  DRM_XE_OA_PROPERTY_EXEC_QUEUE_ID,
+  DRM_XE_OA_PROPERTY_OA_ENGINE_INSTANCE,
+  DRM_XE_OA_PROPERTY_NO_PREEMPT,
+};
+struct drm_xe_oa_config {
+  __u64 extensions;
+  char uuid[36];
+  __u32 n_regs;
+  __u64 regs_ptr;
+};
+struct drm_xe_oa_stream_status {
+  __u64 extensions;
+  __u64 oa_status;
+#define DRM_XE_OASTATUS_MMIO_TRG_Q_FULL (1 << 3)
+#define DRM_XE_OASTATUS_COUNTER_OVERFLOW (1 << 2)
+#define DRM_XE_OASTATUS_BUFFER_OVERFLOW (1 << 1)
+#define DRM_XE_OASTATUS_REPORT_LOST (1 << 0)
+  __u64 reserved[3];
+};
+struct drm_xe_oa_stream_info {
+  __u64 extensions;
+  __u64 oa_buf_size;
+  __u64 reserved[3];
+};
 #ifdef __cplusplus
 }
 #endif
diff --git a/libc/kernel/uapi/linux/bpf.h b/libc/kernel/uapi/linux/bpf.h
index c73292052..8d648164c 100644
--- a/libc/kernel/uapi/linux/bpf.h
+++ b/libc/kernel/uapi/linux/bpf.h
@@ -367,6 +367,7 @@ enum {
 #define BPF_F_QUERY_EFFECTIVE (1U << 0)
 #define BPF_F_TEST_RUN_ON_CPU (1U << 0)
 #define BPF_F_TEST_XDP_LIVE_FRAMES (1U << 1)
+#define BPF_F_TEST_SKB_CHECKSUM_COMPLETE (1U << 2)
 enum bpf_stats_type {
   BPF_STATS_RUN_TIME = 0,
 };
@@ -773,8 +774,11 @@ enum {
 #define __bpf_md_ptr(type,name) union { type name; __u64 : 64; \
 } __attribute__((aligned(8)))
 enum {
-  BPF_SKB_TSTAMP_UNSPEC,
-  BPF_SKB_TSTAMP_DELIVERY_MONO,
+  BPF_SKB_TSTAMP_UNSPEC = 0,
+  BPF_SKB_TSTAMP_DELIVERY_MONO = 1,
+  BPF_SKB_CLOCK_REALTIME = 0,
+  BPF_SKB_CLOCK_MONOTONIC = 1,
+  BPF_SKB_CLOCK_TAI = 2,
 };
 struct __sk_buff {
   __u32 len;
diff --git a/libc/kernel/uapi/linux/btrfs_tree.h b/libc/kernel/uapi/linux/btrfs_tree.h
index ea33eee48..88f44d9dc 100644
--- a/libc/kernel/uapi/linux/btrfs_tree.h
+++ b/libc/kernel/uapi/linux/btrfs_tree.h
@@ -279,18 +279,8 @@ struct btrfs_raid_stride {
   __le64 devid;
   __le64 physical;
 } __attribute__((__packed__));
-#define BTRFS_STRIPE_RAID0 1
-#define BTRFS_STRIPE_RAID1 2
-#define BTRFS_STRIPE_DUP 3
-#define BTRFS_STRIPE_RAID10 4
-#define BTRFS_STRIPE_RAID5 5
-#define BTRFS_STRIPE_RAID6 6
-#define BTRFS_STRIPE_RAID1C3 7
-#define BTRFS_STRIPE_RAID1C4 8
 struct btrfs_stripe_extent {
-  __u8 encoding;
-  __u8 reserved[7];
-  struct btrfs_raid_stride strides[];
+  __DECLARE_FLEX_ARRAY(struct btrfs_raid_stride, strides);
 } __attribute__((__packed__));
 #define BTRFS_HEADER_FLAG_WRITTEN (1ULL << 0)
 #define BTRFS_HEADER_FLAG_RELOC (1ULL << 1)
@@ -300,6 +290,9 @@ struct btrfs_stripe_extent {
 #define BTRFS_SUPER_FLAG_METADUMP_V2 (1ULL << 34)
 #define BTRFS_SUPER_FLAG_CHANGING_FSID (1ULL << 35)
 #define BTRFS_SUPER_FLAG_CHANGING_FSID_V2 (1ULL << 36)
+#define BTRFS_SUPER_FLAG_CHANGING_BG_TREE (1ULL << 38)
+#define BTRFS_SUPER_FLAG_CHANGING_DATA_CSUM (1ULL << 39)
+#define BTRFS_SUPER_FLAG_CHANGING_META_CSUM (1ULL << 40)
 struct btrfs_extent_item {
   __le64 refs;
   __le64 generation;
diff --git a/libc/kernel/uapi/linux/dlm.h b/libc/kernel/uapi/linux/dlm.h
index 3c73908fa..1344f9b71 100644
--- a/libc/kernel/uapi/linux/dlm.h
+++ b/libc/kernel/uapi/linux/dlm.h
@@ -20,4 +20,5 @@ struct dlm_lksb {
 };
 #define DLM_LSFL_TIMEWARN 0x00000002
 #define DLM_LSFL_NEWEXCL 0x00000008
+#define __DLM_LSFL_RESERVED0 0x00000010
 #endif
diff --git a/libc/kernel/uapi/linux/dma-heap.h b/libc/kernel/uapi/linux/dma-heap.h
index 467e336a7..ac86b5923 100644
--- a/libc/kernel/uapi/linux/dma-heap.h
+++ b/libc/kernel/uapi/linux/dma-heap.h
@@ -9,7 +9,7 @@
 #include <linux/ioctl.h>
 #include <linux/types.h>
 #define DMA_HEAP_VALID_FD_FLAGS (O_CLOEXEC | O_ACCMODE)
-#define DMA_HEAP_VALID_HEAP_FLAGS (0)
+#define DMA_HEAP_VALID_HEAP_FLAGS (0ULL)
 struct dma_heap_allocation_data {
   __u64 len;
   __u32 fd;
diff --git a/libc/kernel/uapi/linux/ethtool.h b/libc/kernel/uapi/linux/ethtool.h
index 334c788d0..e213ba1b8 100644
--- a/libc/kernel/uapi/linux/ethtool.h
+++ b/libc/kernel/uapi/linux/ethtool.h
@@ -270,6 +270,56 @@ enum ethtool_module_power_mode {
   ETHTOOL_MODULE_POWER_MODE_LOW = 1,
   ETHTOOL_MODULE_POWER_MODE_HIGH,
 };
+enum ethtool_c33_pse_ext_state {
+  ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION = 1,
+  ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID,
+  ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE,
+  ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED,
+  ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM,
+  ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED,
+  ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE,
+  ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE,
+  ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED,
+};
+enum ethtool_c33_pse_ext_substate_mr_mps_valid {
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_DETECTED_UNDERLOAD = 1,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_CONNECTION_OPEN,
+};
+enum ethtool_c33_pse_ext_substate_error_condition {
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT = 1,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP,
+};
+enum ethtool_c33_pse_ext_substate_mr_pse_enable {
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE = 1,
+};
+enum ethtool_c33_pse_ext_substate_option_detect_ted {
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS = 1,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR,
+};
+enum ethtool_c33_pse_ext_substate_option_vport_lim {
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE = 1,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION,
+};
+enum ethtool_c33_pse_ext_substate_ovld_detected {
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD = 1,
+};
+enum ethtool_c33_pse_ext_substate_power_not_available {
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED = 1,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT,
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT,
+};
+enum ethtool_c33_pse_ext_substate_short_detected {
+  ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION = 1,
+};
 enum ethtool_pse_types {
   ETHTOOL_PSE_UNKNOWN = 1 << 0,
   ETHTOOL_PSE_PODL = 1 << 1,
@@ -311,6 +361,12 @@ enum ethtool_mm_verify_status {
   ETHTOOL_MM_VERIFY_STATUS_FAILED,
   ETHTOOL_MM_VERIFY_STATUS_DISABLED,
 };
+enum ethtool_module_fw_flash_status {
+  ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED = 1,
+  ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS,
+  ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED,
+  ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR,
+};
 struct ethtool_gstrings {
   __u32 cmd;
   __u32 string_set;
@@ -749,6 +805,7 @@ enum ethtool_link_mode_bit_indices {
   ETHTOOL_LINK_MODE_10baseT1S_Full_BIT = 99,
   ETHTOOL_LINK_MODE_10baseT1S_Half_BIT = 100,
   ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT = 101,
+  ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT = 102,
   __ETHTOOL_LINK_MODE_MASK_NBITS
 };
 #define __ETHTOOL_LINK_MODE_LEGACY_MASK(base_name) (1UL << (ETHTOOL_LINK_MODE_ ##base_name ##_BIT))
diff --git a/libc/kernel/uapi/linux/ethtool_netlink.h b/libc/kernel/uapi/linux/ethtool_netlink.h
index 6757ef550..ac6391a0b 100644
--- a/libc/kernel/uapi/linux/ethtool_netlink.h
+++ b/libc/kernel/uapi/linux/ethtool_netlink.h
@@ -52,6 +52,7 @@ enum {
   ETHTOOL_MSG_PLCA_GET_STATUS,
   ETHTOOL_MSG_MM_GET,
   ETHTOOL_MSG_MM_SET,
+  ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
   __ETHTOOL_MSG_USER_CNT,
   ETHTOOL_MSG_USER_MAX = __ETHTOOL_MSG_USER_CNT - 1
 };
@@ -100,6 +101,7 @@ enum {
   ETHTOOL_MSG_PLCA_NTF,
   ETHTOOL_MSG_MM_GET_REPLY,
   ETHTOOL_MSG_MM_NTF,
+  ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
   __ETHTOOL_MSG_KERNEL_CNT,
   ETHTOOL_MSG_KERNEL_MAX = __ETHTOOL_MSG_KERNEL_CNT - 1
 };
@@ -316,9 +318,25 @@ enum {
   ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES,
   ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES,
   ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS,
+  ETHTOOL_A_COALESCE_RX_PROFILE,
+  ETHTOOL_A_COALESCE_TX_PROFILE,
   __ETHTOOL_A_COALESCE_CNT,
   ETHTOOL_A_COALESCE_MAX = (__ETHTOOL_A_COALESCE_CNT - 1)
 };
+enum {
+  ETHTOOL_A_PROFILE_UNSPEC,
+  ETHTOOL_A_PROFILE_IRQ_MODERATION,
+  __ETHTOOL_A_PROFILE_CNT,
+  ETHTOOL_A_PROFILE_MAX = (__ETHTOOL_A_PROFILE_CNT - 1)
+};
+enum {
+  ETHTOOL_A_IRQ_MODERATION_UNSPEC,
+  ETHTOOL_A_IRQ_MODERATION_USEC,
+  ETHTOOL_A_IRQ_MODERATION_PKTS,
+  ETHTOOL_A_IRQ_MODERATION_COMPS,
+  __ETHTOOL_A_IRQ_MODERATION_CNT,
+  ETHTOOL_A_IRQ_MODERATION_MAX = (__ETHTOOL_A_IRQ_MODERATION_CNT - 1)
+};
 enum {
   ETHTOOL_A_PAUSE_UNSPEC,
   ETHTOOL_A_PAUSE_HEADER,
@@ -634,6 +652,11 @@ enum {
   __ETHTOOL_A_MODULE_CNT,
   ETHTOOL_A_MODULE_MAX = (__ETHTOOL_A_MODULE_CNT - 1)
 };
+enum {
+  ETHTOOL_A_C33_PSE_PW_LIMIT_UNSPEC,
+  ETHTOOL_A_C33_PSE_PW_LIMIT_MIN,
+  ETHTOOL_A_C33_PSE_PW_LIMIT_MAX,
+};
 enum {
   ETHTOOL_A_PSE_UNSPEC,
   ETHTOOL_A_PSE_HEADER,
@@ -643,6 +666,12 @@ enum {
   ETHTOOL_A_C33_PSE_ADMIN_STATE,
   ETHTOOL_A_C33_PSE_ADMIN_CONTROL,
   ETHTOOL_A_C33_PSE_PW_D_STATUS,
+  ETHTOOL_A_C33_PSE_PW_CLASS,
+  ETHTOOL_A_C33_PSE_ACTUAL_PW,
+  ETHTOOL_A_C33_PSE_EXT_STATE,
+  ETHTOOL_A_C33_PSE_EXT_SUBSTATE,
+  ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,
+  ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES,
   __ETHTOOL_A_PSE_CNT,
   ETHTOOL_A_PSE_MAX = (__ETHTOOL_A_PSE_CNT - 1)
 };
@@ -699,6 +728,18 @@ enum {
   __ETHTOOL_A_MM_CNT,
   ETHTOOL_A_MM_MAX = (__ETHTOOL_A_MM_CNT - 1)
 };
+enum {
+  ETHTOOL_A_MODULE_FW_FLASH_UNSPEC,
+  ETHTOOL_A_MODULE_FW_FLASH_HEADER,
+  ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,
+  ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,
+  ETHTOOL_A_MODULE_FW_FLASH_STATUS,
+  ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG,
+  ETHTOOL_A_MODULE_FW_FLASH_DONE,
+  ETHTOOL_A_MODULE_FW_FLASH_TOTAL,
+  __ETHTOOL_A_MODULE_FW_FLASH_CNT,
+  ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
+};
 #define ETHTOOL_GENL_NAME "ethtool"
 #define ETHTOOL_GENL_VERSION 1
 #define ETHTOOL_MCGRP_MONITOR_NAME "monitor"
diff --git a/libc/kernel/uapi/linux/fs.h b/libc/kernel/uapi/linux/fs.h
index 38a2d9e0a..adab56f86 100644
--- a/libc/kernel/uapi/linux/fs.h
+++ b/libc/kernel/uapi/linux/fs.h
@@ -194,8 +194,10 @@ typedef int __bitwise __kernel_rwf_t;
 #define RWF_NOWAIT (( __kernel_rwf_t) 0x00000008)
 #define RWF_APPEND (( __kernel_rwf_t) 0x00000010)
 #define RWF_NOAPPEND (( __kernel_rwf_t) 0x00000020)
-#define RWF_SUPPORTED (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | RWF_NOAPPEND)
-#define PAGEMAP_SCAN _IOWR('f', 16, struct pm_scan_arg)
+#define RWF_ATOMIC (( __kernel_rwf_t) 0x00000040)
+#define RWF_SUPPORTED (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | RWF_NOAPPEND | RWF_ATOMIC)
+#define PROCFS_IOCTL_MAGIC 'f'
+#define PAGEMAP_SCAN _IOWR(PROCFS_IOCTL_MAGIC, 16, struct pm_scan_arg)
 #define PAGE_IS_WPALLOWED (1 << 0)
 #define PAGE_IS_WRITTEN (1 << 1)
 #define PAGE_IS_FILE (1 << 2)
@@ -225,4 +227,30 @@ struct pm_scan_arg {
   __u64 category_anyof_mask;
   __u64 return_mask;
 };
+#define PROCMAP_QUERY _IOWR(PROCFS_IOCTL_MAGIC, 17, struct procmap_query)
+enum procmap_query_flags {
+  PROCMAP_QUERY_VMA_READABLE = 0x01,
+  PROCMAP_QUERY_VMA_WRITABLE = 0x02,
+  PROCMAP_QUERY_VMA_EXECUTABLE = 0x04,
+  PROCMAP_QUERY_VMA_SHARED = 0x08,
+  PROCMAP_QUERY_COVERING_OR_NEXT_VMA = 0x10,
+  PROCMAP_QUERY_FILE_BACKED_VMA = 0x20,
+};
+struct procmap_query {
+  __u64 size;
+  __u64 query_flags;
+  __u64 query_addr;
+  __u64 vma_start;
+  __u64 vma_end;
+  __u64 vma_flags;
+  __u64 vma_page_size;
+  __u64 vma_offset;
+  __u64 inode;
+  __u32 dev_major;
+  __u32 dev_minor;
+  __u32 vma_name_size;
+  __u32 build_id_size;
+  __u64 vma_name_addr;
+  __u64 build_id_addr;
+};
 #endif
diff --git a/libc/kernel/uapi/linux/if_xdp.h b/libc/kernel/uapi/linux/if_xdp.h
index b7eec87cb..7201e06a8 100644
--- a/libc/kernel/uapi/linux/if_xdp.h
+++ b/libc/kernel/uapi/linux/if_xdp.h
@@ -14,6 +14,7 @@
 #define XDP_USE_SG (1 << 4)
 #define XDP_UMEM_UNALIGNED_CHUNK_FLAG (1 << 0)
 #define XDP_UMEM_TX_SW_CSUM (1 << 1)
+#define XDP_UMEM_TX_METADATA_LEN (1 << 2)
 struct sockaddr_xdp {
   __u16 sxdp_family;
   __u16 sxdp_flags;
diff --git a/libc/kernel/uapi/linux/iio/buffer.h b/libc/kernel/uapi/linux/iio/buffer.h
index 45c6f65ba..7e03a8cf5 100644
--- a/libc/kernel/uapi/linux/iio/buffer.h
+++ b/libc/kernel/uapi/linux/iio/buffer.h
@@ -6,5 +6,16 @@
  */
 #ifndef _UAPI_IIO_BUFFER_H_
 #define _UAPI_IIO_BUFFER_H_
+#include <linux/types.h>
+#define IIO_BUFFER_DMABUF_CYCLIC (1 << 0)
+#define IIO_BUFFER_DMABUF_SUPPORTED_FLAGS 0x00000001
+struct iio_dmabuf {
+  __u32 fd;
+  __u32 flags;
+  __u64 bytes_used;
+};
 #define IIO_BUFFER_GET_FD_IOCTL _IOWR('i', 0x91, int)
+#define IIO_BUFFER_DMABUF_ATTACH_IOCTL _IOW('i', 0x92, int)
+#define IIO_BUFFER_DMABUF_DETACH_IOCTL _IOW('i', 0x93, int)
+#define IIO_BUFFER_DMABUF_ENQUEUE_IOCTL _IOW('i', 0x94, struct iio_dmabuf)
 #endif
diff --git a/libc/kernel/uapi/linux/in.h b/libc/kernel/uapi/linux/in.h
index 44efdd830..97bf4930c 100644
--- a/libc/kernel/uapi/linux/in.h
+++ b/libc/kernel/uapi/linux/in.h
@@ -69,6 +69,8 @@ enum {
 #define IPPROTO_ETHERNET IPPROTO_ETHERNET
   IPPROTO_RAW = 255,
 #define IPPROTO_RAW IPPROTO_RAW
+  IPPROTO_SMC = 256,
+#define IPPROTO_SMC IPPROTO_SMC
   IPPROTO_MPTCP = 262,
 #define IPPROTO_MPTCP IPPROTO_MPTCP
   IPPROTO_MAX
diff --git a/libc/kernel/uapi/linux/io_uring.h b/libc/kernel/uapi/linux/io_uring.h
index 5505963bc..6b4f2ea9b 100644
--- a/libc/kernel/uapi/linux/io_uring.h
+++ b/libc/kernel/uapi/linux/io_uring.h
@@ -176,6 +176,8 @@ enum io_uring_op {
   IORING_OP_FUTEX_WAITV,
   IORING_OP_FIXED_FD_INSTALL,
   IORING_OP_FTRUNCATE,
+  IORING_OP_BIND,
+  IORING_OP_LISTEN,
   IORING_OP_LAST,
 };
 #define IORING_URING_CMD_FIXED (1U << 0)
diff --git a/libc/kernel/uapi/linux/iommufd.h b/libc/kernel/uapi/linux/iommufd.h
index 257062881..6f663b410 100644
--- a/libc/kernel/uapi/linux/iommufd.h
+++ b/libc/kernel/uapi/linux/iommufd.h
@@ -12,19 +12,20 @@
 enum {
   IOMMUFD_CMD_BASE = 0x80,
   IOMMUFD_CMD_DESTROY = IOMMUFD_CMD_BASE,
-  IOMMUFD_CMD_IOAS_ALLOC,
-  IOMMUFD_CMD_IOAS_ALLOW_IOVAS,
-  IOMMUFD_CMD_IOAS_COPY,
-  IOMMUFD_CMD_IOAS_IOVA_RANGES,
-  IOMMUFD_CMD_IOAS_MAP,
-  IOMMUFD_CMD_IOAS_UNMAP,
-  IOMMUFD_CMD_OPTION,
-  IOMMUFD_CMD_VFIO_IOAS,
-  IOMMUFD_CMD_HWPT_ALLOC,
-  IOMMUFD_CMD_GET_HW_INFO,
-  IOMMUFD_CMD_HWPT_SET_DIRTY_TRACKING,
-  IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP,
-  IOMMUFD_CMD_HWPT_INVALIDATE,
+  IOMMUFD_CMD_IOAS_ALLOC = 0x81,
+  IOMMUFD_CMD_IOAS_ALLOW_IOVAS = 0x82,
+  IOMMUFD_CMD_IOAS_COPY = 0x83,
+  IOMMUFD_CMD_IOAS_IOVA_RANGES = 0x84,
+  IOMMUFD_CMD_IOAS_MAP = 0x85,
+  IOMMUFD_CMD_IOAS_UNMAP = 0x86,
+  IOMMUFD_CMD_OPTION = 0x87,
+  IOMMUFD_CMD_VFIO_IOAS = 0x88,
+  IOMMUFD_CMD_HWPT_ALLOC = 0x89,
+  IOMMUFD_CMD_GET_HW_INFO = 0x8a,
+  IOMMUFD_CMD_HWPT_SET_DIRTY_TRACKING = 0x8b,
+  IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP = 0x8c,
+  IOMMUFD_CMD_HWPT_INVALIDATE = 0x8d,
+  IOMMUFD_CMD_FAULT_QUEUE_ALLOC = 0x8e,
 };
 struct iommu_destroy {
   __u32 size;
@@ -122,6 +123,7 @@ struct iommu_vfio_ioas {
 enum iommufd_hwpt_alloc_flags {
   IOMMU_HWPT_ALLOC_NEST_PARENT = 1 << 0,
   IOMMU_HWPT_ALLOC_DIRTY_TRACKING = 1 << 1,
+  IOMMU_HWPT_FAULT_ID_VALID = 1 << 2,
 };
 enum iommu_hwpt_vtd_s1_flags {
   IOMMU_VTD_S1_SRE = 1 << 0,
@@ -135,8 +137,8 @@ struct iommu_hwpt_vtd_s1 {
   __u32 __reserved;
 };
 enum iommu_hwpt_data_type {
-  IOMMU_HWPT_DATA_NONE,
-  IOMMU_HWPT_DATA_VTD_S1,
+  IOMMU_HWPT_DATA_NONE = 0,
+  IOMMU_HWPT_DATA_VTD_S1 = 1,
 };
 struct iommu_hwpt_alloc {
   __u32 size;
@@ -148,6 +150,8 @@ struct iommu_hwpt_alloc {
   __u32 data_type;
   __u32 data_len;
   __aligned_u64 data_uptr;
+  __u32 fault_id;
+  __u32 __reserved2;
 };
 #define IOMMU_HWPT_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_ALLOC)
 enum iommu_hw_info_vtd_flags {
@@ -160,8 +164,8 @@ struct iommu_hw_info_vtd {
   __aligned_u64 ecap_reg;
 };
 enum iommu_hw_info_type {
-  IOMMU_HW_INFO_TYPE_NONE,
-  IOMMU_HW_INFO_TYPE_INTEL_VTD,
+  IOMMU_HW_INFO_TYPE_NONE = 0,
+  IOMMU_HW_INFO_TYPE_INTEL_VTD = 1,
 };
 enum iommufd_hw_capabilities {
   IOMMU_HW_CAP_DIRTY_TRACKING = 1 << 0,
@@ -202,7 +206,7 @@ struct iommu_hwpt_get_dirty_bitmap {
 };
 #define IOMMU_HWPT_GET_DIRTY_BITMAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP)
 enum iommu_hwpt_invalidate_data_type {
-  IOMMU_HWPT_INVALIDATE_DATA_VTD_S1,
+  IOMMU_HWPT_INVALIDATE_DATA_VTD_S1 = 0,
 };
 enum iommu_hwpt_vtd_s1_invalidate_flags {
   IOMMU_VTD_INV_FLAGS_LEAF = 1 << 0,
@@ -223,4 +227,39 @@ struct iommu_hwpt_invalidate {
   __u32 __reserved;
 };
 #define IOMMU_HWPT_INVALIDATE _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_INVALIDATE)
+enum iommu_hwpt_pgfault_flags {
+  IOMMU_PGFAULT_FLAGS_PASID_VALID = (1 << 0),
+  IOMMU_PGFAULT_FLAGS_LAST_PAGE = (1 << 1),
+};
+enum iommu_hwpt_pgfault_perm {
+  IOMMU_PGFAULT_PERM_READ = (1 << 0),
+  IOMMU_PGFAULT_PERM_WRITE = (1 << 1),
+  IOMMU_PGFAULT_PERM_EXEC = (1 << 2),
+  IOMMU_PGFAULT_PERM_PRIV = (1 << 3),
+};
+struct iommu_hwpt_pgfault {
+  __u32 flags;
+  __u32 dev_id;
+  __u32 pasid;
+  __u32 grpid;
+  __u32 perm;
+  __u64 addr;
+  __u32 length;
+  __u32 cookie;
+};
+enum iommufd_page_response_code {
+  IOMMUFD_PAGE_RESP_SUCCESS = 0,
+  IOMMUFD_PAGE_RESP_INVALID = 1,
+};
+struct iommu_hwpt_page_response {
+  __u32 cookie;
+  __u32 code;
+};
+struct iommu_fault_alloc {
+  __u32 size;
+  __u32 flags;
+  __u32 out_fault_id;
+  __u32 out_fault_fd;
+};
+#define IOMMU_FAULT_QUEUE_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_FAULT_QUEUE_ALLOC)
 #endif
diff --git a/libc/kernel/uapi/linux/kfd_ioctl.h b/libc/kernel/uapi/linux/kfd_ioctl.h
index 62c9872b0..193dd8e6d 100644
--- a/libc/kernel/uapi/linux/kfd_ioctl.h
+++ b/libc/kernel/uapi/linux/kfd_ioctl.h
@@ -9,7 +9,7 @@
 #include <drm/drm.h>
 #include <linux/ioctl.h>
 #define KFD_IOCTL_MAJOR_VERSION 1
-#define KFD_IOCTL_MINOR_VERSION 15
+#define KFD_IOCTL_MINOR_VERSION 16
 struct kfd_ioctl_get_version_args {
   __u32 major_version;
   __u32 minor_version;
@@ -269,6 +269,7 @@ struct kfd_ioctl_acquire_vm_args {
 #define KFD_IOC_ALLOC_MEM_FLAGS_COHERENT (1 << 26)
 #define KFD_IOC_ALLOC_MEM_FLAGS_UNCACHED (1 << 25)
 #define KFD_IOC_ALLOC_MEM_FLAGS_EXT_COHERENT (1 << 24)
+#define KFD_IOC_ALLOC_MEM_FLAGS_CONTIGUOUS (1 << 23)
 struct kfd_ioctl_alloc_memory_of_gpu_args {
   __u64 va_addr;
   __u64 size;
@@ -465,6 +466,7 @@ enum kfd_dbg_trap_address_watch_mode {
 };
 enum kfd_dbg_trap_flags {
   KFD_DBG_TRAP_FLAG_SINGLE_MEM_OP = 1,
+  KFD_DBG_TRAP_FLAG_SINGLE_ALU_OP = 2,
 };
 enum kfd_dbg_trap_exception_code {
   EC_NONE = 0,
diff --git a/libc/kernel/uapi/linux/kfd_sysfs.h b/libc/kernel/uapi/linux/kfd_sysfs.h
index e538cf264..7771582ce 100644
--- a/libc/kernel/uapi/linux/kfd_sysfs.h
+++ b/libc/kernel/uapi/linux/kfd_sysfs.h
@@ -35,7 +35,8 @@
 #define HSA_CAP_SVMAPI_SUPPORTED 0x08000000
 #define HSA_CAP_FLAGS_COHERENTHOSTACCESS 0x10000000
 #define HSA_CAP_TRAP_DEBUG_FIRMWARE_SUPPORTED 0x20000000
-#define HSA_CAP_RESERVED 0xe00f8000
+#define HSA_CAP_TRAP_DEBUG_PRECISE_ALU_OPERATIONS_SUPPORTED 0x40000000
+#define HSA_CAP_RESERVED 0x800f8000
 #define HSA_DBG_WATCH_ADDR_MASK_LO_BIT_MASK 0x0000000f
 #define HSA_DBG_WATCH_ADDR_MASK_LO_BIT_SHIFT 0
 #define HSA_DBG_WATCH_ADDR_MASK_HI_BIT_MASK 0x000003f0
diff --git a/libc/kernel/uapi/linux/kvm.h b/libc/kernel/uapi/linux/kvm.h
index ffaf5e65f..297a09d85 100644
--- a/libc/kernel/uapi/linux/kvm.h
+++ b/libc/kernel/uapi/linux/kvm.h
@@ -149,9 +149,10 @@ struct kvm_xen_exit {
 #define KVM_INTERNAL_ERROR_DELIVERY_EV 3
 #define KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON 4
 #define KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES (1ULL << 0)
+#define HINT_UNSAFE_IN_KVM(_symbol) _symbol
 struct kvm_run {
   __u8 request_interrupt_window;
-  __u8 immediate_exit;
+  __u8 HINT_UNSAFE_IN_KVM(immediate_exit);
   __u8 padding1[6];
   __u32 exit_reason;
   __u8 ready_for_interrupt_injection;
@@ -719,6 +720,9 @@ struct kvm_enable_cap {
 #define KVM_CAP_MEMORY_ATTRIBUTES 233
 #define KVM_CAP_GUEST_MEMFD 234
 #define KVM_CAP_VM_TYPES 235
+#define KVM_CAP_PRE_FAULT_MEMORY 236
+#define KVM_CAP_X86_APIC_BUS_CYCLES_NS 237
+#define KVM_CAP_X86_GUEST_MODE 238
 struct kvm_irq_routing_irqchip {
   __u32 irqchip;
   __u32 pin;
@@ -1109,4 +1113,11 @@ struct kvm_create_guest_memfd {
   __u64 flags;
   __u64 reserved[6];
 };
+#define KVM_PRE_FAULT_MEMORY _IOWR(KVMIO, 0xd5, struct kvm_pre_fault_memory)
+struct kvm_pre_fault_memory {
+  __u64 gpa;
+  __u64 size;
+  __u64 flags;
+  __u64 padding[5];
+};
 #endif
diff --git a/libc/kernel/uapi/linux/media/raspberrypi/pisp_be_config.h b/libc/kernel/uapi/linux/media/raspberrypi/pisp_be_config.h
new file mode 100644
index 000000000..2e981ad33
--- /dev/null
+++ b/libc/kernel/uapi/linux/media/raspberrypi/pisp_be_config.h
@@ -0,0 +1,418 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_PISP_BE_CONFIG_H_
+#define _UAPI_PISP_BE_CONFIG_H_
+#include <linux/types.h>
+#include "pisp_common.h"
+#define PISP_BACK_END_INPUT_ALIGN 4u
+#define PISP_BACK_END_COMPRESSED_ALIGN 8u
+#define PISP_BACK_END_OUTPUT_MIN_ALIGN 16u
+#define PISP_BACK_END_OUTPUT_MAX_ALIGN 64u
+#define PISP_BACK_END_MIN_TILE_WIDTH 16u
+#define PISP_BACK_END_MIN_TILE_HEIGHT 16u
+#define PISP_BACK_END_NUM_OUTPUTS 2
+#define PISP_BACK_END_HOG_OUTPUT 1
+#define PISP_BACK_END_NUM_TILES 64
+enum pisp_be_bayer_enable {
+  PISP_BE_BAYER_ENABLE_INPUT = 0x000001,
+  PISP_BE_BAYER_ENABLE_DECOMPRESS = 0x000002,
+  PISP_BE_BAYER_ENABLE_DPC = 0x000004,
+  PISP_BE_BAYER_ENABLE_GEQ = 0x000008,
+  PISP_BE_BAYER_ENABLE_TDN_INPUT = 0x000010,
+  PISP_BE_BAYER_ENABLE_TDN_DECOMPRESS = 0x000020,
+  PISP_BE_BAYER_ENABLE_TDN = 0x000040,
+  PISP_BE_BAYER_ENABLE_TDN_COMPRESS = 0x000080,
+  PISP_BE_BAYER_ENABLE_TDN_OUTPUT = 0x000100,
+  PISP_BE_BAYER_ENABLE_SDN = 0x000200,
+  PISP_BE_BAYER_ENABLE_BLC = 0x000400,
+  PISP_BE_BAYER_ENABLE_STITCH_INPUT = 0x000800,
+  PISP_BE_BAYER_ENABLE_STITCH_DECOMPRESS = 0x001000,
+  PISP_BE_BAYER_ENABLE_STITCH = 0x002000,
+  PISP_BE_BAYER_ENABLE_STITCH_COMPRESS = 0x004000,
+  PISP_BE_BAYER_ENABLE_STITCH_OUTPUT = 0x008000,
+  PISP_BE_BAYER_ENABLE_WBG = 0x010000,
+  PISP_BE_BAYER_ENABLE_CDN = 0x020000,
+  PISP_BE_BAYER_ENABLE_LSC = 0x040000,
+  PISP_BE_BAYER_ENABLE_TONEMAP = 0x080000,
+  PISP_BE_BAYER_ENABLE_CAC = 0x100000,
+  PISP_BE_BAYER_ENABLE_DEBIN = 0x200000,
+  PISP_BE_BAYER_ENABLE_DEMOSAIC = 0x400000,
+};
+enum pisp_be_rgb_enable {
+  PISP_BE_RGB_ENABLE_INPUT = 0x000001,
+  PISP_BE_RGB_ENABLE_CCM = 0x000002,
+  PISP_BE_RGB_ENABLE_SAT_CONTROL = 0x000004,
+  PISP_BE_RGB_ENABLE_YCBCR = 0x000008,
+  PISP_BE_RGB_ENABLE_FALSE_COLOUR = 0x000010,
+  PISP_BE_RGB_ENABLE_SHARPEN = 0x000020,
+  PISP_BE_RGB_ENABLE_YCBCR_INVERSE = 0x000080,
+  PISP_BE_RGB_ENABLE_GAMMA = 0x000100,
+  PISP_BE_RGB_ENABLE_CSC0 = 0x000200,
+  PISP_BE_RGB_ENABLE_CSC1 = 0x000400,
+  PISP_BE_RGB_ENABLE_DOWNSCALE0 = 0x001000,
+  PISP_BE_RGB_ENABLE_DOWNSCALE1 = 0x002000,
+  PISP_BE_RGB_ENABLE_RESAMPLE0 = 0x008000,
+  PISP_BE_RGB_ENABLE_RESAMPLE1 = 0x010000,
+  PISP_BE_RGB_ENABLE_OUTPUT0 = 0x040000,
+  PISP_BE_RGB_ENABLE_OUTPUT1 = 0x080000,
+  PISP_BE_RGB_ENABLE_HOG = 0x200000
+};
+#define PISP_BE_RGB_ENABLE_CSC(i) (PISP_BE_RGB_ENABLE_CSC0 << (i))
+#define PISP_BE_RGB_ENABLE_DOWNSCALE(i) (PISP_BE_RGB_ENABLE_DOWNSCALE0 << (i))
+#define PISP_BE_RGB_ENABLE_RESAMPLE(i) (PISP_BE_RGB_ENABLE_RESAMPLE0 << (i))
+#define PISP_BE_RGB_ENABLE_OUTPUT(i) (PISP_BE_RGB_ENABLE_OUTPUT0 << (i))
+enum pisp_be_dirty {
+  PISP_BE_DIRTY_GLOBAL = 0x0001,
+  PISP_BE_DIRTY_SH_FC_COMBINE = 0x0002,
+  PISP_BE_DIRTY_CROP = 0x0004
+};
+struct pisp_be_global_config {
+  __u32 bayer_enables;
+  __u32 rgb_enables;
+  __u8 bayer_order;
+  __u8 pad[3];
+} __attribute__((packed));
+struct pisp_be_input_buffer_config {
+  __u32 addr[3][2];
+} __attribute__((packed));
+struct pisp_be_dpc_config {
+  __u8 coeff_level;
+  __u8 coeff_range;
+  __u8 pad;
+#define PISP_BE_DPC_FLAG_FOLDBACK 1
+  __u8 flags;
+} __attribute__((packed));
+struct pisp_be_geq_config {
+  __u16 offset;
+#define PISP_BE_GEQ_SHARPER (1U << 15)
+#define PISP_BE_GEQ_SLOPE ((1 << 10) - 1)
+  __u16 slope_sharper;
+  __u16 min;
+  __u16 max;
+} __attribute__((packed));
+struct pisp_be_tdn_input_buffer_config {
+  __u32 addr[2];
+} __attribute__((packed));
+struct pisp_be_tdn_config {
+  __u16 black_level;
+  __u16 ratio;
+  __u16 noise_constant;
+  __u16 noise_slope;
+  __u16 threshold;
+  __u8 reset;
+  __u8 pad;
+} __attribute__((packed));
+struct pisp_be_tdn_output_buffer_config {
+  __u32 addr[2];
+} __attribute__((packed));
+struct pisp_be_sdn_config {
+  __u16 black_level;
+  __u8 leakage;
+  __u8 pad;
+  __u16 noise_constant;
+  __u16 noise_slope;
+  __u16 noise_constant2;
+  __u16 noise_slope2;
+} __attribute__((packed));
+struct pisp_be_stitch_input_buffer_config {
+  __u32 addr[2];
+} __attribute__((packed));
+#define PISP_BE_STITCH_STREAMING_LONG 0x8000
+#define PISP_BE_STITCH_EXPOSURE_RATIO_MASK 0x7fff
+struct pisp_be_stitch_config {
+  __u16 threshold_lo;
+  __u8 threshold_diff_power;
+  __u8 pad;
+  __u16 exposure_ratio;
+  __u8 motion_threshold_256;
+  __u8 motion_threshold_recip;
+} __attribute__((packed));
+struct pisp_be_stitch_output_buffer_config {
+  __u32 addr[2];
+} __attribute__((packed));
+struct pisp_be_cdn_config {
+  __u16 thresh;
+  __u8 iir_strength;
+  __u8 g_adjust;
+} __attribute__((packed));
+#define PISP_BE_LSC_LOG_GRID_SIZE 5
+#define PISP_BE_LSC_GRID_SIZE (1 << PISP_BE_LSC_LOG_GRID_SIZE)
+#define PISP_BE_LSC_STEP_PRECISION 18
+struct pisp_be_lsc_config {
+  __u16 grid_step_x;
+  __u16 grid_step_y;
+#define PISP_BE_LSC_LUT_SIZE (PISP_BE_LSC_GRID_SIZE + 1)
+  __u32 lut_packed[PISP_BE_LSC_LUT_SIZE][PISP_BE_LSC_LUT_SIZE];
+} __attribute__((packed));
+struct pisp_be_lsc_extra {
+  __u16 offset_x;
+  __u16 offset_y;
+} __attribute__((packed));
+#define PISP_BE_CAC_LOG_GRID_SIZE 3
+#define PISP_BE_CAC_GRID_SIZE (1 << PISP_BE_CAC_LOG_GRID_SIZE)
+#define PISP_BE_CAC_STEP_PRECISION 20
+struct pisp_be_cac_config {
+  __u16 grid_step_x;
+  __u16 grid_step_y;
+#define PISP_BE_CAC_LUT_SIZE (PISP_BE_CAC_GRID_SIZE + 1)
+  __s8 lut[PISP_BE_CAC_LUT_SIZE][PISP_BE_CAC_LUT_SIZE][2][2];
+} __attribute__((packed));
+struct pisp_be_cac_extra {
+  __u16 offset_x;
+  __u16 offset_y;
+} __attribute__((packed));
+#define PISP_BE_DEBIN_NUM_COEFFS 4
+struct pisp_be_debin_config {
+  __s8 coeffs[PISP_BE_DEBIN_NUM_COEFFS];
+  __s8 h_enable;
+  __s8 v_enable;
+  __s8 pad[2];
+} __attribute__((packed));
+#define PISP_BE_TONEMAP_LUT_SIZE 64
+struct pisp_be_tonemap_config {
+  __u16 detail_constant;
+  __u16 detail_slope;
+  __u16 iir_strength;
+  __u16 strength;
+  __u32 lut[PISP_BE_TONEMAP_LUT_SIZE];
+} __attribute__((packed));
+struct pisp_be_demosaic_config {
+  __u8 sharper;
+  __u8 fc_mode;
+  __u8 pad[2];
+} __attribute__((packed));
+struct pisp_be_ccm_config {
+  __s16 coeffs[9];
+  __u8 pad[2];
+  __s32 offsets[3];
+} __attribute__((packed));
+struct pisp_be_sat_control_config {
+  __u8 shift_r;
+  __u8 shift_g;
+  __u8 shift_b;
+  __u8 pad;
+} __attribute__((packed));
+struct pisp_be_false_colour_config {
+  __u8 distance;
+  __u8 pad[3];
+} __attribute__((packed));
+#define PISP_BE_SHARPEN_SIZE 5
+#define PISP_BE_SHARPEN_FUNC_NUM_POINTS 9
+struct pisp_be_sharpen_config {
+  __s8 kernel0[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+  __s8 pad0[3];
+  __s8 kernel1[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+  __s8 pad1[3];
+  __s8 kernel2[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+  __s8 pad2[3];
+  __s8 kernel3[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+  __s8 pad3[3];
+  __s8 kernel4[PISP_BE_SHARPEN_SIZE * PISP_BE_SHARPEN_SIZE];
+  __s8 pad4[3];
+  __u16 threshold_offset0;
+  __u16 threshold_slope0;
+  __u16 scale0;
+  __u16 pad5;
+  __u16 threshold_offset1;
+  __u16 threshold_slope1;
+  __u16 scale1;
+  __u16 pad6;
+  __u16 threshold_offset2;
+  __u16 threshold_slope2;
+  __u16 scale2;
+  __u16 pad7;
+  __u16 threshold_offset3;
+  __u16 threshold_slope3;
+  __u16 scale3;
+  __u16 pad8;
+  __u16 threshold_offset4;
+  __u16 threshold_slope4;
+  __u16 scale4;
+  __u16 pad9;
+  __u16 positive_strength;
+  __u16 positive_pre_limit;
+  __u16 positive_func[PISP_BE_SHARPEN_FUNC_NUM_POINTS];
+  __u16 positive_limit;
+  __u16 negative_strength;
+  __u16 negative_pre_limit;
+  __u16 negative_func[PISP_BE_SHARPEN_FUNC_NUM_POINTS];
+  __u16 negative_limit;
+  __u8 enables;
+  __u8 white;
+  __u8 black;
+  __u8 grey;
+} __attribute__((packed));
+struct pisp_be_sh_fc_combine_config {
+  __u8 y_factor;
+  __u8 c1_factor;
+  __u8 c2_factor;
+  __u8 pad;
+} __attribute__((packed));
+#define PISP_BE_GAMMA_LUT_SIZE 64
+struct pisp_be_gamma_config {
+  __u32 lut[PISP_BE_GAMMA_LUT_SIZE];
+} __attribute__((packed));
+struct pisp_be_crop_config {
+  __u16 offset_x, offset_y;
+  __u16 width, height;
+} __attribute__((packed));
+#define PISP_BE_RESAMPLE_FILTER_SIZE 96
+struct pisp_be_resample_config {
+  __u16 scale_factor_h, scale_factor_v;
+  __s16 coef[PISP_BE_RESAMPLE_FILTER_SIZE];
+} __attribute__((packed));
+struct pisp_be_resample_extra {
+  __u16 scaled_width;
+  __u16 scaled_height;
+  __s16 initial_phase_h[3];
+  __s16 initial_phase_v[3];
+} __attribute__((packed));
+struct pisp_be_downscale_config {
+  __u16 scale_factor_h;
+  __u16 scale_factor_v;
+  __u16 scale_recip_h;
+  __u16 scale_recip_v;
+} __attribute__((packed));
+struct pisp_be_downscale_extra {
+  __u16 scaled_width;
+  __u16 scaled_height;
+} __attribute__((packed));
+struct pisp_be_hog_config {
+  __u8 compute_signed;
+  __u8 channel_mix[3];
+  __u32 stride;
+} __attribute__((packed));
+struct pisp_be_axi_config {
+  __u8 r_qos;
+  __u8 r_cache_prot;
+  __u8 w_qos;
+  __u8 w_cache_prot;
+} __attribute__((packed));
+enum pisp_be_transform {
+  PISP_BE_TRANSFORM_NONE = 0x0,
+  PISP_BE_TRANSFORM_HFLIP = 0x1,
+  PISP_BE_TRANSFORM_VFLIP = 0x2,
+  PISP_BE_TRANSFORM_ROT180 = (PISP_BE_TRANSFORM_HFLIP | PISP_BE_TRANSFORM_VFLIP)
+};
+struct pisp_be_output_format_config {
+  struct pisp_image_format_config image;
+  __u8 transform;
+  __u8 pad[3];
+  __u16 lo;
+  __u16 hi;
+  __u16 lo2;
+  __u16 hi2;
+} __attribute__((packed));
+struct pisp_be_output_buffer_config {
+  __u32 addr[3][2];
+} __attribute__((packed));
+struct pisp_be_hog_buffer_config {
+  __u32 addr[2];
+} __attribute__((packed));
+struct pisp_be_config {
+  struct pisp_be_input_buffer_config input_buffer;
+  struct pisp_be_tdn_input_buffer_config tdn_input_buffer;
+  struct pisp_be_stitch_input_buffer_config stitch_input_buffer;
+  struct pisp_be_tdn_output_buffer_config tdn_output_buffer;
+  struct pisp_be_stitch_output_buffer_config stitch_output_buffer;
+  struct pisp_be_output_buffer_config output_buffer[PISP_BACK_END_NUM_OUTPUTS];
+  struct pisp_be_hog_buffer_config hog_buffer;
+  struct pisp_be_global_config global;
+  struct pisp_image_format_config input_format;
+  struct pisp_decompress_config decompress;
+  struct pisp_be_dpc_config dpc;
+  struct pisp_be_geq_config geq;
+  struct pisp_image_format_config tdn_input_format;
+  struct pisp_decompress_config tdn_decompress;
+  struct pisp_be_tdn_config tdn;
+  struct pisp_compress_config tdn_compress;
+  struct pisp_image_format_config tdn_output_format;
+  struct pisp_be_sdn_config sdn;
+  struct pisp_bla_config blc;
+  struct pisp_compress_config stitch_compress;
+  struct pisp_image_format_config stitch_output_format;
+  struct pisp_image_format_config stitch_input_format;
+  struct pisp_decompress_config stitch_decompress;
+  struct pisp_be_stitch_config stitch;
+  struct pisp_be_lsc_config lsc;
+  struct pisp_wbg_config wbg;
+  struct pisp_be_cdn_config cdn;
+  struct pisp_be_cac_config cac;
+  struct pisp_be_debin_config debin;
+  struct pisp_be_tonemap_config tonemap;
+  struct pisp_be_demosaic_config demosaic;
+  struct pisp_be_ccm_config ccm;
+  struct pisp_be_sat_control_config sat_control;
+  struct pisp_be_ccm_config ycbcr;
+  struct pisp_be_sharpen_config sharpen;
+  struct pisp_be_false_colour_config false_colour;
+  struct pisp_be_sh_fc_combine_config sh_fc_combine;
+  struct pisp_be_ccm_config ycbcr_inverse;
+  struct pisp_be_gamma_config gamma;
+  struct pisp_be_ccm_config csc[PISP_BACK_END_NUM_OUTPUTS];
+  struct pisp_be_downscale_config downscale[PISP_BACK_END_NUM_OUTPUTS];
+  struct pisp_be_resample_config resample[PISP_BACK_END_NUM_OUTPUTS];
+  struct pisp_be_output_format_config output_format[PISP_BACK_END_NUM_OUTPUTS];
+  struct pisp_be_hog_config hog;
+  struct pisp_be_axi_config axi;
+  struct pisp_be_lsc_extra lsc_extra;
+  struct pisp_be_cac_extra cac_extra;
+  struct pisp_be_downscale_extra downscale_extra[PISP_BACK_END_NUM_OUTPUTS];
+  struct pisp_be_resample_extra resample_extra[PISP_BACK_END_NUM_OUTPUTS];
+  struct pisp_be_crop_config crop;
+  struct pisp_image_format_config hog_format;
+  __u32 dirty_flags_bayer;
+  __u32 dirty_flags_rgb;
+  __u32 dirty_flags_extra;
+} __attribute__((packed));
+enum pisp_tile_edge {
+  PISP_LEFT_EDGE = (1 << 0),
+  PISP_RIGHT_EDGE = (1 << 1),
+  PISP_TOP_EDGE = (1 << 2),
+  PISP_BOTTOM_EDGE = (1 << 3)
+};
+struct pisp_tile {
+  __u8 edge;
+  __u8 pad0[3];
+  __u32 input_addr_offset;
+  __u32 input_addr_offset2;
+  __u16 input_offset_x;
+  __u16 input_offset_y;
+  __u16 input_width;
+  __u16 input_height;
+  __u32 tdn_input_addr_offset;
+  __u32 tdn_output_addr_offset;
+  __u32 stitch_input_addr_offset;
+  __u32 stitch_output_addr_offset;
+  __u32 lsc_grid_offset_x;
+  __u32 lsc_grid_offset_y;
+  __u32 cac_grid_offset_x;
+  __u32 cac_grid_offset_y;
+  __u16 crop_x_start[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 crop_x_end[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 crop_y_start[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 crop_y_end[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 downscale_phase_x[3 * PISP_BACK_END_NUM_OUTPUTS];
+  __u16 downscale_phase_y[3 * PISP_BACK_END_NUM_OUTPUTS];
+  __u16 resample_in_width[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 resample_in_height[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 resample_phase_x[3 * PISP_BACK_END_NUM_OUTPUTS];
+  __u16 resample_phase_y[3 * PISP_BACK_END_NUM_OUTPUTS];
+  __u16 output_offset_x[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 output_offset_y[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 output_width[PISP_BACK_END_NUM_OUTPUTS];
+  __u16 output_height[PISP_BACK_END_NUM_OUTPUTS];
+  __u32 output_addr_offset[PISP_BACK_END_NUM_OUTPUTS];
+  __u32 output_addr_offset2[PISP_BACK_END_NUM_OUTPUTS];
+  __u32 output_hog_addr_offset;
+} __attribute__((packed));
+struct pisp_be_tiles_config {
+  struct pisp_be_config config;
+  struct pisp_tile tiles[PISP_BACK_END_NUM_TILES];
+  __u32 num_tiles;
+} __attribute__((packed));
+#endif
diff --git a/libc/kernel/uapi/linux/media/raspberrypi/pisp_common.h b/libc/kernel/uapi/linux/media/raspberrypi/pisp_common.h
new file mode 100644
index 000000000..0e0b23f61
--- /dev/null
+++ b/libc/kernel/uapi/linux/media/raspberrypi/pisp_common.h
@@ -0,0 +1,119 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef _UAPI_PISP_COMMON_H_
+#define _UAPI_PISP_COMMON_H_
+#include <linux/types.h>
+struct pisp_image_format_config {
+  __u16 width;
+  __u16 height;
+  __u32 format;
+  __s32 stride;
+  __s32 stride2;
+} __attribute__((packed));
+enum pisp_bayer_order {
+  PISP_BAYER_ORDER_RGGB = 0,
+  PISP_BAYER_ORDER_GBRG = 1,
+  PISP_BAYER_ORDER_BGGR = 2,
+  PISP_BAYER_ORDER_GRBG = 3,
+  PISP_BAYER_ORDER_GREYSCALE = 128
+};
+enum pisp_image_format {
+  PISP_IMAGE_FORMAT_BPS_8 = 0x00000000,
+  PISP_IMAGE_FORMAT_BPS_10 = 0x00000001,
+  PISP_IMAGE_FORMAT_BPS_12 = 0x00000002,
+  PISP_IMAGE_FORMAT_BPS_16 = 0x00000003,
+  PISP_IMAGE_FORMAT_BPS_MASK = 0x00000003,
+  PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED = 0x00000000,
+  PISP_IMAGE_FORMAT_PLANARITY_SEMI_PLANAR = 0x00000010,
+  PISP_IMAGE_FORMAT_PLANARITY_PLANAR = 0x00000020,
+  PISP_IMAGE_FORMAT_PLANARITY_MASK = 0x00000030,
+  PISP_IMAGE_FORMAT_SAMPLING_444 = 0x00000000,
+  PISP_IMAGE_FORMAT_SAMPLING_422 = 0x00000100,
+  PISP_IMAGE_FORMAT_SAMPLING_420 = 0x00000200,
+  PISP_IMAGE_FORMAT_SAMPLING_MASK = 0x00000300,
+  PISP_IMAGE_FORMAT_ORDER_NORMAL = 0x00000000,
+  PISP_IMAGE_FORMAT_ORDER_SWAPPED = 0x00001000,
+  PISP_IMAGE_FORMAT_SHIFT_0 = 0x00000000,
+  PISP_IMAGE_FORMAT_SHIFT_1 = 0x00010000,
+  PISP_IMAGE_FORMAT_SHIFT_2 = 0x00020000,
+  PISP_IMAGE_FORMAT_SHIFT_3 = 0x00030000,
+  PISP_IMAGE_FORMAT_SHIFT_4 = 0x00040000,
+  PISP_IMAGE_FORMAT_SHIFT_5 = 0x00050000,
+  PISP_IMAGE_FORMAT_SHIFT_6 = 0x00060000,
+  PISP_IMAGE_FORMAT_SHIFT_7 = 0x00070000,
+  PISP_IMAGE_FORMAT_SHIFT_8 = 0x00080000,
+  PISP_IMAGE_FORMAT_SHIFT_MASK = 0x000f0000,
+  PISP_IMAGE_FORMAT_BPP_32 = 0x00100000,
+  PISP_IMAGE_FORMAT_UNCOMPRESSED = 0x00000000,
+  PISP_IMAGE_FORMAT_COMPRESSION_MODE_1 = 0x01000000,
+  PISP_IMAGE_FORMAT_COMPRESSION_MODE_2 = 0x02000000,
+  PISP_IMAGE_FORMAT_COMPRESSION_MODE_3 = 0x03000000,
+  PISP_IMAGE_FORMAT_COMPRESSION_MASK = 0x03000000,
+  PISP_IMAGE_FORMAT_HOG_SIGNED = 0x04000000,
+  PISP_IMAGE_FORMAT_HOG_UNSIGNED = 0x08000000,
+  PISP_IMAGE_FORMAT_INTEGRAL_IMAGE = 0x10000000,
+  PISP_IMAGE_FORMAT_WALLPAPER_ROLL = 0x20000000,
+  PISP_IMAGE_FORMAT_THREE_CHANNEL = 0x40000000,
+  PISP_IMAGE_FORMAT_SINGLE_16 = PISP_IMAGE_FORMAT_BPS_16,
+  PISP_IMAGE_FORMAT_THREE_16 = PISP_IMAGE_FORMAT_BPS_16 | PISP_IMAGE_FORMAT_THREE_CHANNEL
+};
+#define PISP_IMAGE_FORMAT_BPS_8(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_8)
+#define PISP_IMAGE_FORMAT_BPS_10(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_10)
+#define PISP_IMAGE_FORMAT_BPS_12(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_12)
+#define PISP_IMAGE_FORMAT_BPS_16(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) == PISP_IMAGE_FORMAT_BPS_16)
+#define PISP_IMAGE_FORMAT_BPS(fmt) (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) ? 8 + (2 << (((fmt) & PISP_IMAGE_FORMAT_BPS_MASK) - 1)) : 8)
+#define PISP_IMAGE_FORMAT_SHIFT(fmt) (((fmt) & PISP_IMAGE_FORMAT_SHIFT_MASK) / PISP_IMAGE_FORMAT_SHIFT_1)
+#define PISP_IMAGE_FORMAT_THREE_CHANNEL(fmt) ((fmt) & PISP_IMAGE_FORMAT_THREE_CHANNEL)
+#define PISP_IMAGE_FORMAT_SINGLE_CHANNEL(fmt) (! ((fmt) & PISP_IMAGE_FORMAT_THREE_CHANNEL))
+#define PISP_IMAGE_FORMAT_COMPRESSED(fmt) (((fmt) & PISP_IMAGE_FORMAT_COMPRESSION_MASK) != PISP_IMAGE_FORMAT_UNCOMPRESSED)
+#define PISP_IMAGE_FORMAT_SAMPLING_444(fmt) (((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) == PISP_IMAGE_FORMAT_SAMPLING_444)
+#define PISP_IMAGE_FORMAT_SAMPLING_422(fmt) (((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) == PISP_IMAGE_FORMAT_SAMPLING_422)
+#define PISP_IMAGE_FORMAT_SAMPLING_420(fmt) (((fmt) & PISP_IMAGE_FORMAT_SAMPLING_MASK) == PISP_IMAGE_FORMAT_SAMPLING_420)
+#define PISP_IMAGE_FORMAT_ORDER_NORMAL(fmt) (! ((fmt) & PISP_IMAGE_FORMAT_ORDER_SWAPPED))
+#define PISP_IMAGE_FORMAT_ORDER_SWAPPED(fmt) ((fmt) & PISP_IMAGE_FORMAT_ORDER_SWAPPED)
+#define PISP_IMAGE_FORMAT_INTERLEAVED(fmt) (((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) == PISP_IMAGE_FORMAT_PLANARITY_INTERLEAVED)
+#define PISP_IMAGE_FORMAT_SEMIPLANAR(fmt) (((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) == PISP_IMAGE_FORMAT_PLANARITY_SEMI_PLANAR)
+#define PISP_IMAGE_FORMAT_PLANAR(fmt) (((fmt) & PISP_IMAGE_FORMAT_PLANARITY_MASK) == PISP_IMAGE_FORMAT_PLANARITY_PLANAR)
+#define PISP_IMAGE_FORMAT_WALLPAPER(fmt) ((fmt) & PISP_IMAGE_FORMAT_WALLPAPER_ROLL)
+#define PISP_IMAGE_FORMAT_BPP_32(fmt) ((fmt) & PISP_IMAGE_FORMAT_BPP_32)
+#define PISP_IMAGE_FORMAT_HOG(fmt) ((fmt) & (PISP_IMAGE_FORMAT_HOG_SIGNED | PISP_IMAGE_FORMAT_HOG_UNSIGNED))
+#define PISP_WALLPAPER_WIDTH 128
+struct pisp_bla_config {
+  __u16 black_level_r;
+  __u16 black_level_gr;
+  __u16 black_level_gb;
+  __u16 black_level_b;
+  __u16 output_black_level;
+  __u8 pad[2];
+} __attribute__((packed));
+struct pisp_wbg_config {
+  __u16 gain_r;
+  __u16 gain_g;
+  __u16 gain_b;
+  __u8 pad[2];
+} __attribute__((packed));
+struct pisp_compress_config {
+  __u16 offset;
+  __u8 pad;
+  __u8 mode;
+} __attribute__((packed));
+struct pisp_decompress_config {
+  __u16 offset;
+  __u8 pad;
+  __u8 mode;
+} __attribute__((packed));
+enum pisp_axi_flags {
+  PISP_AXI_FLAG_ALIGN = 128,
+  PISP_AXI_FLAG_PAD = 64,
+  PISP_AXI_FLAG_PANIC = 32,
+};
+struct pisp_axi_config {
+  __u8 maxlen_flags;
+  __u8 cache_prot;
+  __u16 qos;
+} __attribute__((packed));
+#endif
diff --git a/libc/kernel/uapi/linux/mman.h b/libc/kernel/uapi/linux/mman.h
index cf1e978e8..f50b51c91 100644
--- a/libc/kernel/uapi/linux/mman.h
+++ b/libc/kernel/uapi/linux/mman.h
@@ -18,6 +18,7 @@
 #define MAP_SHARED 0x01
 #define MAP_PRIVATE 0x02
 #define MAP_SHARED_VALIDATE 0x03
+#define MAP_DROPPABLE 0x08
 #define MAP_HUGE_SHIFT HUGETLB_FLAG_ENCODE_SHIFT
 #define MAP_HUGE_MASK HUGETLB_FLAG_ENCODE_MASK
 #define MAP_HUGE_16KB HUGETLB_FLAG_ENCODE_16KB
diff --git a/libc/kernel/uapi/linux/mount.h b/libc/kernel/uapi/linux/mount.h
index 1166a7a3b..c4278b532 100644
--- a/libc/kernel/uapi/linux/mount.h
+++ b/libc/kernel/uapi/linux/mount.h
@@ -90,7 +90,7 @@ struct mount_attr {
 #define MOUNT_ATTR_SIZE_VER0 32
 struct statmount {
   __u32 size;
-  __u32 __spare1;
+  __u32 mnt_opts;
   __u64 mask;
   __u32 sb_dev_major;
   __u32 sb_dev_minor;
@@ -108,7 +108,8 @@ struct statmount {
   __u64 propagate_from;
   __u32 mnt_root;
   __u32 mnt_point;
-  __u64 __spare2[50];
+  __u64 mnt_ns_id;
+  __u64 __spare2[49];
   char str[];
 };
 struct mnt_id_req {
@@ -116,13 +117,18 @@ struct mnt_id_req {
   __u32 spare;
   __u64 mnt_id;
   __u64 param;
+  __u64 mnt_ns_id;
 };
 #define MNT_ID_REQ_SIZE_VER0 24
+#define MNT_ID_REQ_SIZE_VER1 32
 #define STATMOUNT_SB_BASIC 0x00000001U
 #define STATMOUNT_MNT_BASIC 0x00000002U
 #define STATMOUNT_PROPAGATE_FROM 0x00000004U
 #define STATMOUNT_MNT_ROOT 0x00000008U
 #define STATMOUNT_MNT_POINT 0x00000010U
 #define STATMOUNT_FS_TYPE 0x00000020U
+#define STATMOUNT_MNT_NS_ID 0x00000040U
+#define STATMOUNT_MNT_OPTS 0x00000080U
 #define LSMT_ROOT 0xffffffffffffffff
+#define LISTMOUNT_REVERSE (1 << 0)
 #endif
diff --git a/libc/kernel/uapi/linux/netfilter/nf_tables.h b/libc/kernel/uapi/linux/netfilter/nf_tables.h
index 792214735..bfc6e25b0 100644
--- a/libc/kernel/uapi/linux/netfilter/nf_tables.h
+++ b/libc/kernel/uapi/linux/netfilter/nf_tables.h
@@ -695,7 +695,7 @@ enum nft_secmark_attributes {
   __NFTA_SECMARK_MAX,
 };
 #define NFTA_SECMARK_MAX (__NFTA_SECMARK_MAX - 1)
-#define NFT_SECMARK_CTX_MAXLEN 256
+#define NFT_SECMARK_CTX_MAXLEN 4096
 enum nft_reject_types {
   NFT_REJECT_ICMP_UNREACH,
   NFT_REJECT_TCP_RST,
diff --git a/libc/kernel/uapi/linux/nfs4.h b/libc/kernel/uapi/linux/nfs4.h
index 21f1103d9..6512901e8 100644
--- a/libc/kernel/uapi/linux/nfs4.h
+++ b/libc/kernel/uapi/linux/nfs4.h
@@ -34,6 +34,7 @@
 #define NFS4_OPEN_RESULT_CONFIRM 0x0002
 #define NFS4_OPEN_RESULT_LOCKTYPE_POSIX 0x0004
 #define NFS4_OPEN_RESULT_PRESERVE_UNLINKED 0x0008
+#define NFS4_OPEN_RESULT_NO_OPEN_STATEID 0x0010
 #define NFS4_OPEN_RESULT_MAY_NOTIFY_LOCK 0x0020
 #define NFS4_SHARE_ACCESS_MASK 0x000F
 #define NFS4_SHARE_ACCESS_READ 0x0001
@@ -52,6 +53,8 @@
 #define NFS4_SHARE_WHEN_MASK 0xF0000
 #define NFS4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL 0x10000
 #define NFS4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED 0x20000
+#define NFS4_SHARE_WANT_DELEG_TIMESTAMPS 0x100000
+#define NFS4_SHARE_WANT_OPEN_XOR_DELEGATION 0x200000
 #define NFS4_CDFC4_FORE 0x1
 #define NFS4_CDFC4_BACK 0x2
 #define NFS4_CDFC4_BOTH 0x3
diff --git a/libc/kernel/uapi/linux/nfsd_netlink.h b/libc/kernel/uapi/linux/nfsd_netlink.h
index 45cb50467..bd3f02c0d 100644
--- a/libc/kernel/uapi/linux/nfsd_netlink.h
+++ b/libc/kernel/uapi/linux/nfsd_netlink.h
@@ -57,6 +57,12 @@ enum {
   __NFSD_A_SERVER_SOCK_MAX,
   NFSD_A_SERVER_SOCK_MAX = (__NFSD_A_SERVER_SOCK_MAX - 1)
 };
+enum {
+  NFSD_A_POOL_MODE_MODE = 1,
+  NFSD_A_POOL_MODE_NPOOLS,
+  __NFSD_A_POOL_MODE_MAX,
+  NFSD_A_POOL_MODE_MAX = (__NFSD_A_POOL_MODE_MAX - 1)
+};
 enum {
   NFSD_CMD_RPC_STATUS_GET = 1,
   NFSD_CMD_THREADS_SET,
@@ -65,6 +71,8 @@ enum {
   NFSD_CMD_VERSION_GET,
   NFSD_CMD_LISTENER_SET,
   NFSD_CMD_LISTENER_GET,
+  NFSD_CMD_POOL_MODE_SET,
+  NFSD_CMD_POOL_MODE_GET,
   __NFSD_CMD_MAX,
   NFSD_CMD_MAX = (__NFSD_CMD_MAX - 1)
 };
diff --git a/libc/kernel/uapi/linux/nl80211.h b/libc/kernel/uapi/linux/nl80211.h
index 98180c2ce..1bad2f2a9 100644
--- a/libc/kernel/uapi/linux/nl80211.h
+++ b/libc/kernel/uapi/linux/nl80211.h
@@ -528,6 +528,8 @@ enum nl80211_attrs {
   NL80211_ATTR_MLO_TTLM_DLINK,
   NL80211_ATTR_MLO_TTLM_ULINK,
   NL80211_ATTR_ASSOC_SPP_AMSDU,
+  NL80211_ATTR_WIPHY_RADIOS,
+  NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS,
   __NL80211_ATTR_AFTER_LAST,
   NUM_NL80211_ATTR = __NL80211_ATTR_AFTER_LAST,
   NL80211_ATTR_MAX = __NL80211_ATTR_AFTER_LAST - 1
@@ -878,6 +880,7 @@ enum nl80211_frequency_attr {
   NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT,
   NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT,
   NL80211_FREQUENCY_ATTR_CAN_MONITOR,
+  NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP,
   __NL80211_FREQUENCY_ATTR_AFTER_LAST,
   NL80211_FREQUENCY_ATTR_MAX = __NL80211_FREQUENCY_ATTR_AFTER_LAST - 1
 };
@@ -955,6 +958,7 @@ enum nl80211_reg_rule_flags {
   NL80211_RRF_DFS_CONCURRENT = 1 << 21,
   NL80211_RRF_NO_6GHZ_VLP_CLIENT = 1 << 22,
   NL80211_RRF_NO_6GHZ_AFC_CLIENT = 1 << 23,
+  NL80211_RRF_ALLOW_6GHZ_VLP_AP = 1 << 24,
 };
 #define NL80211_RRF_PASSIVE_SCAN NL80211_RRF_NO_IR
 #define NL80211_RRF_NO_IBSS NL80211_RRF_NO_IR
@@ -1973,4 +1977,19 @@ enum nl80211_ap_settings_flags {
   NL80211_AP_SETTINGS_EXTERNAL_AUTH_SUPPORT = 1 << 0,
   NL80211_AP_SETTINGS_SA_QUERY_OFFLOAD_SUPPORT = 1 << 1,
 };
+enum nl80211_wiphy_radio_attrs {
+  __NL80211_WIPHY_RADIO_ATTR_INVALID,
+  NL80211_WIPHY_RADIO_ATTR_INDEX,
+  NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE,
+  NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION,
+  __NL80211_WIPHY_RADIO_ATTR_LAST,
+  NL80211_WIPHY_RADIO_ATTR_MAX = __NL80211_WIPHY_RADIO_ATTR_LAST - 1,
+};
+enum nl80211_wiphy_radio_freq_range {
+  __NL80211_WIPHY_RADIO_FREQ_ATTR_INVALID,
+  NL80211_WIPHY_RADIO_FREQ_ATTR_START,
+  NL80211_WIPHY_RADIO_FREQ_ATTR_END,
+  __NL80211_WIPHY_RADIO_FREQ_ATTR_LAST,
+  NL80211_WIPHY_RADIO_FREQ_ATTR_MAX = __NL80211_WIPHY_RADIO_FREQ_ATTR_LAST - 1,
+};
 #endif
diff --git a/libc/kernel/uapi/linux/nsfs.h b/libc/kernel/uapi/linux/nsfs.h
index 61a5797e8..c8f22089d 100644
--- a/libc/kernel/uapi/linux/nsfs.h
+++ b/libc/kernel/uapi/linux/nsfs.h
@@ -7,9 +7,15 @@
 #ifndef __LINUX_NSFS_H
 #define __LINUX_NSFS_H
 #include <linux/ioctl.h>
+#include <linux/types.h>
 #define NSIO 0xb7
 #define NS_GET_USERNS _IO(NSIO, 0x1)
 #define NS_GET_PARENT _IO(NSIO, 0x2)
 #define NS_GET_NSTYPE _IO(NSIO, 0x3)
 #define NS_GET_OWNER_UID _IO(NSIO, 0x4)
+#define NS_GET_MNTNS_ID _IOR(NSIO, 0x5, __u64)
+#define NS_GET_PID_FROM_PIDNS _IOR(NSIO, 0x6, int)
+#define NS_GET_TGID_FROM_PIDNS _IOR(NSIO, 0x7, int)
+#define NS_GET_PID_IN_PIDNS _IOR(NSIO, 0x8, int)
+#define NS_GET_TGID_IN_PIDNS _IOR(NSIO, 0x9, int)
 #endif
diff --git a/libc/kernel/uapi/linux/openvswitch.h b/libc/kernel/uapi/linux/openvswitch.h
index d45f4fad4..98c803787 100644
--- a/libc/kernel/uapi/linux/openvswitch.h
+++ b/libc/kernel/uapi/linux/openvswitch.h
@@ -429,6 +429,13 @@ enum ovs_check_pkt_len_attr {
   __OVS_CHECK_PKT_LEN_ATTR_MAX,
 };
 #define OVS_CHECK_PKT_LEN_ATTR_MAX (__OVS_CHECK_PKT_LEN_ATTR_MAX - 1)
+#define OVS_PSAMPLE_COOKIE_MAX_SIZE 16
+enum ovs_psample_attr {
+  OVS_PSAMPLE_ATTR_GROUP = 1,
+  OVS_PSAMPLE_ATTR_COOKIE,
+  __OVS_PSAMPLE_ATTR_MAX
+};
+#define OVS_PSAMPLE_ATTR_MAX (__OVS_PSAMPLE_ATTR_MAX - 1)
 enum ovs_action_attr {
   OVS_ACTION_ATTR_UNSPEC,
   OVS_ACTION_ATTR_OUTPUT,
@@ -455,6 +462,7 @@ enum ovs_action_attr {
   OVS_ACTION_ATTR_ADD_MPLS,
   OVS_ACTION_ATTR_DEC_TTL,
   OVS_ACTION_ATTR_DROP,
+  OVS_ACTION_ATTR_PSAMPLE,
   __OVS_ACTION_ATTR_MAX,
 };
 #define OVS_ACTION_ATTR_MAX (__OVS_ACTION_ATTR_MAX - 1)
diff --git a/libc/kernel/uapi/linux/perf_event.h b/libc/kernel/uapi/linux/perf_event.h
index 16a1a2e3d..ec9b856bb 100644
--- a/libc/kernel/uapi/linux/perf_event.h
+++ b/libc/kernel/uapi/linux/perf_event.h
@@ -460,6 +460,8 @@ union perf_mem_data_src {
 #define PERF_MEM_LVLNUM_L2 0x02
 #define PERF_MEM_LVLNUM_L3 0x03
 #define PERF_MEM_LVLNUM_L4 0x04
+#define PERF_MEM_LVLNUM_L2_MHB 0x05
+#define PERF_MEM_LVLNUM_MSC 0x06
 #define PERF_MEM_LVLNUM_UNC 0x08
 #define PERF_MEM_LVLNUM_CXL 0x09
 #define PERF_MEM_LVLNUM_IO 0x0a
diff --git a/libc/kernel/uapi/linux/pidfd.h b/libc/kernel/uapi/linux/pidfd.h
index 082b4a05e..9068727ff 100644
--- a/libc/kernel/uapi/linux/pidfd.h
+++ b/libc/kernel/uapi/linux/pidfd.h
@@ -8,9 +8,21 @@
 #define _UAPI_LINUX_PIDFD_H
 #include <linux/types.h>
 #include <linux/fcntl.h>
+#include <linux/ioctl.h>
 #define PIDFD_NONBLOCK O_NONBLOCK
 #define PIDFD_THREAD O_EXCL
 #define PIDFD_SIGNAL_THREAD (1UL << 0)
 #define PIDFD_SIGNAL_THREAD_GROUP (1UL << 1)
 #define PIDFD_SIGNAL_PROCESS_GROUP (1UL << 2)
+#define PIDFS_IOCTL_MAGIC 0xFF
+#define PIDFD_GET_CGROUP_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 1)
+#define PIDFD_GET_IPC_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 2)
+#define PIDFD_GET_MNT_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 3)
+#define PIDFD_GET_NET_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 4)
+#define PIDFD_GET_PID_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 5)
+#define PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 6)
+#define PIDFD_GET_TIME_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 7)
+#define PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 8)
+#define PIDFD_GET_USER_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 9)
+#define PIDFD_GET_UTS_NAMESPACE _IO(PIDFS_IOCTL_MAGIC, 10)
 #endif
diff --git a/libc/kernel/uapi/linux/pkt_cls.h b/libc/kernel/uapi/linux/pkt_cls.h
index 6b5143c26..bdca5532c 100644
--- a/libc/kernel/uapi/linux/pkt_cls.h
+++ b/libc/kernel/uapi/linux/pkt_cls.h
@@ -419,6 +419,8 @@ enum {
   TCA_FLOWER_KEY_CFM,
   TCA_FLOWER_KEY_SPI,
   TCA_FLOWER_KEY_SPI_MASK,
+  TCA_FLOWER_KEY_ENC_FLAGS,
+  TCA_FLOWER_KEY_ENC_FLAGS_MASK,
   __TCA_FLOWER_MAX,
 };
 #define TCA_FLOWER_MAX (__TCA_FLOWER_MAX - 1)
@@ -497,7 +499,13 @@ enum {
 enum {
   TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT = (1 << 0),
   TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST = (1 << 1),
+  TCA_FLOWER_KEY_FLAGS_TUNNEL_CSUM = (1 << 2),
+  TCA_FLOWER_KEY_FLAGS_TUNNEL_DONT_FRAGMENT = (1 << 3),
+  TCA_FLOWER_KEY_FLAGS_TUNNEL_OAM = (1 << 4),
+  TCA_FLOWER_KEY_FLAGS_TUNNEL_CRIT_OPT = (1 << 5),
+  __TCA_FLOWER_KEY_FLAGS_MAX,
 };
+#define TCA_FLOWER_KEY_FLAGS_MAX (__TCA_FLOWER_KEY_FLAGS_MAX - 1)
 enum {
   TCA_FLOWER_KEY_CFM_OPT_UNSPEC,
   TCA_FLOWER_KEY_CFM_MD_LEVEL,
diff --git a/libc/kernel/uapi/linux/psample.h b/libc/kernel/uapi/linux/psample.h
index c82e76e35..f9f979c00 100644
--- a/libc/kernel/uapi/linux/psample.h
+++ b/libc/kernel/uapi/linux/psample.h
@@ -22,6 +22,8 @@ enum {
   PSAMPLE_ATTR_LATENCY,
   PSAMPLE_ATTR_TIMESTAMP,
   PSAMPLE_ATTR_PROTO,
+  PSAMPLE_ATTR_USER_COOKIE,
+  PSAMPLE_ATTR_SAMPLE_PROBABILITY,
   __PSAMPLE_ATTR_MAX
 };
 enum psample_command {
diff --git a/libc/kernel/uapi/linux/psp-sev.h b/libc/kernel/uapi/linux/psp-sev.h
index 82fcbf1ff..7274081af 100644
--- a/libc/kernel/uapi/linux/psp-sev.h
+++ b/libc/kernel/uapi/linux/psp-sev.h
@@ -20,6 +20,7 @@ enum {
   SNP_PLATFORM_STATUS,
   SNP_COMMIT,
   SNP_SET_CONFIG,
+  SNP_VLEK_LOAD,
   SEV_MAX,
 };
 typedef enum {
@@ -28,6 +29,7 @@ typedef enum {
   SEV_RET_INVALID_PLATFORM_STATE,
   SEV_RET_INVALID_GUEST_STATE,
   SEV_RET_INAVLID_CONFIG,
+  SEV_RET_INVALID_CONFIG = SEV_RET_INAVLID_CONFIG,
   SEV_RET_INVALID_LEN,
   SEV_RET_ALREADY_OWNED,
   SEV_RET_INVALID_CERTIFICATE,
@@ -113,6 +115,15 @@ struct sev_user_data_snp_config {
   __u32 rsvd : 30;
   __u8 rsvd1[52];
 } __attribute__((__packed__));
+struct sev_user_data_snp_vlek_load {
+  __u32 len;
+  __u8 vlek_wrapped_version;
+  __u8 rsvd[3];
+  __u64 vlek_wrapped_address;
+} __attribute__((__packed__));
+struct sev_user_data_snp_wrapped_vlek_hashstick {
+  __u8 data[432];
+} __attribute__((__packed__));
 struct sev_issue_cmd {
   __u32 cmd;
   __u64 data;
diff --git a/libc/kernel/uapi/linux/random.h b/libc/kernel/uapi/linux/random.h
index d1fd9984e..64f62d930 100644
--- a/libc/kernel/uapi/linux/random.h
+++ b/libc/kernel/uapi/linux/random.h
@@ -24,4 +24,10 @@ struct rand_pool_info {
 #define GRND_NONBLOCK 0x0001
 #define GRND_RANDOM 0x0002
 #define GRND_INSECURE 0x0004
+struct vgetrandom_opaque_params {
+  __u32 size_of_opaque_state;
+  __u32 mmap_prot;
+  __u32 mmap_flags;
+  __u32 reserved[13];
+};
 #endif
diff --git a/libc/kernel/uapi/linux/sev-guest.h b/libc/kernel/uapi/linux/sev-guest.h
index a822bedff..a72264128 100644
--- a/libc/kernel/uapi/linux/sev-guest.h
+++ b/libc/kernel/uapi/linux/sev-guest.h
@@ -51,6 +51,8 @@ struct snp_ext_report_req {
 #define SNP_GUEST_FW_ERR_MASK GENMASK_ULL(31, 0)
 #define SNP_GUEST_VMM_ERR_SHIFT 32
 #define SNP_GUEST_VMM_ERR(x) (((u64) x) << SNP_GUEST_VMM_ERR_SHIFT)
+#define SNP_GUEST_FW_ERR(x) ((x) & SNP_GUEST_FW_ERR_MASK)
+#define SNP_GUEST_ERR(vmm_err,fw_err) (SNP_GUEST_VMM_ERR(vmm_err) | SNP_GUEST_FW_ERR(fw_err))
 #define SNP_GUEST_VMM_ERR_INVALID_LEN 1
 #define SNP_GUEST_VMM_ERR_BUSY 2
 #endif
diff --git a/libc/kernel/uapi/linux/stat.h b/libc/kernel/uapi/linux/stat.h
index ff98fd2d9..aae9ed4f5 100644
--- a/libc/kernel/uapi/linux/stat.h
+++ b/libc/kernel/uapi/linux/stat.h
@@ -69,7 +69,11 @@ struct statx {
   __u32 stx_dio_mem_align;
   __u32 stx_dio_offset_align;
   __u64 stx_subvol;
-  __u64 __spare3[11];
+  __u32 stx_atomic_write_unit_min;
+  __u32 stx_atomic_write_unit_max;
+  __u32 stx_atomic_write_segments_max;
+  __u32 __spare1[1];
+  __u64 __spare3[9];
 };
 #define STATX_TYPE 0x00000001U
 #define STATX_MODE 0x00000002U
@@ -88,6 +92,7 @@ struct statx {
 #define STATX_DIOALIGN 0x00002000U
 #define STATX_MNT_ID_UNIQUE 0x00004000U
 #define STATX_SUBVOL 0x00008000U
+#define STATX_WRITE_ATOMIC 0x00010000U
 #define STATX__RESERVED 0x80000000U
 #define STATX_ALL 0x00000fffU
 #define STATX_ATTR_COMPRESSED 0x00000004
@@ -99,4 +104,5 @@ struct statx {
 #define STATX_ATTR_MOUNT_ROOT 0x00002000
 #define STATX_ATTR_VERITY 0x00100000
 #define STATX_ATTR_DAX 0x00200000
+#define STATX_ATTR_WRITE_ATOMIC 0x00400000
 #endif
diff --git a/libc/kernel/uapi/linux/swab.h b/libc/kernel/uapi/linux/swab.h
index 6225a7604..5d240e1b8 100644
--- a/libc/kernel/uapi/linux/swab.h
+++ b/libc/kernel/uapi/linux/swab.h
@@ -15,29 +15,14 @@
 #define ___constant_swab64(x) ((__u64) ((((__u64) (x) & (__u64) 0x00000000000000ffULL) << 56) | (((__u64) (x) & (__u64) 0x000000000000ff00ULL) << 40) | (((__u64) (x) & (__u64) 0x0000000000ff0000ULL) << 24) | (((__u64) (x) & (__u64) 0x00000000ff000000ULL) << 8) | (((__u64) (x) & (__u64) 0x000000ff00000000ULL) >> 8) | (((__u64) (x) & (__u64) 0x0000ff0000000000ULL) >> 24) | (((__u64) (x) & (__u64) 0x00ff000000000000ULL) >> 40) | (((__u64) (x) & (__u64) 0xff00000000000000ULL) >> 56)))
 #define ___constant_swahw32(x) ((__u32) ((((__u32) (x) & (__u32) 0x0000ffffUL) << 16) | (((__u32) (x) & (__u32) 0xffff0000UL) >> 16)))
 #define ___constant_swahb32(x) ((__u32) ((((__u32) (x) & (__u32) 0x00ff00ffUL) << 8) | (((__u32) (x) & (__u32) 0xff00ff00UL) >> 8)))
-#ifdef __arch_swab16
-#else
-#endif
-#ifdef __arch_swab32
-#else
-#endif
-#ifdef __arch_swab64
-#elif defined(__SWAB_64_THRU_32__)
+#ifdef __SWAB_64_THRU_32__
 #else
 #endif
 static inline __attribute__((__const__)) __u32 __fswahw32(__u32 val) {
-#ifdef __arch_swahw32
-  return __arch_swahw32(val);
-#else
   return ___constant_swahw32(val);
-#endif
 }
 static inline __attribute__((__const__)) __u32 __fswahb32(__u32 val) {
-#ifdef __arch_swahb32
-  return __arch_swahb32(val);
-#else
   return ___constant_swahb32(val);
-#endif
 }
 #define __swab16(x) (__u16) __builtin_bswap16((__u16) (x))
 #define __swab32(x) (__u32) __builtin_bswap32((__u32) (x))
@@ -48,73 +33,33 @@ static inline __attribute__((__const__)) __u32 __fswahb32(__u32 val) {
 #define __swahw32(x) (__builtin_constant_p((__u32) (x)) ? ___constant_swahw32(x) : __fswahw32(x))
 #define __swahb32(x) (__builtin_constant_p((__u32) (x)) ? ___constant_swahb32(x) : __fswahb32(x))
 static __always_inline __u16 __swab16p(const __u16 * p) {
-#ifdef __arch_swab16p
-  return __arch_swab16p(p);
-#else
   return __swab16(* p);
-#endif
 }
 static __always_inline __u32 __swab32p(const __u32 * p) {
-#ifdef __arch_swab32p
-  return __arch_swab32p(p);
-#else
   return __swab32(* p);
-#endif
 }
 static __always_inline __u64 __swab64p(const __u64 * p) {
-#ifdef __arch_swab64p
-  return __arch_swab64p(p);
-#else
   return __swab64(* p);
-#endif
 }
 static inline __u32 __swahw32p(const __u32 * p) {
-#ifdef __arch_swahw32p
-  return __arch_swahw32p(p);
-#else
   return __swahw32(* p);
-#endif
 }
 static inline __u32 __swahb32p(const __u32 * p) {
-#ifdef __arch_swahb32p
-  return __arch_swahb32p(p);
-#else
   return __swahb32(* p);
-#endif
 }
 static inline void __swab16s(__u16 * p) {
-#ifdef __arch_swab16s
-  __arch_swab16s(p);
-#else
   * p = __swab16p(p);
-#endif
 }
 static __always_inline void __swab32s(__u32 * p) {
-#ifdef __arch_swab32s
-  __arch_swab32s(p);
-#else
   * p = __swab32p(p);
-#endif
 }
 static __always_inline void __swab64s(__u64 * p) {
-#ifdef __arch_swab64s
-  __arch_swab64s(p);
-#else
   * p = __swab64p(p);
-#endif
 }
 static inline void __swahw32s(__u32 * p) {
-#ifdef __arch_swahw32s
-  __arch_swahw32s(p);
-#else
   * p = __swahw32p(p);
-#endif
 }
 static inline void __swahb32s(__u32 * p) {
-#ifdef __arch_swahb32s
-  __arch_swahb32s(p);
-#else
   * p = __swahb32p(p);
-#endif
 }
 #endif
diff --git a/libc/kernel/uapi/linux/tcp_metrics.h b/libc/kernel/uapi/linux/tcp_metrics.h
index 931f50c04..46ca1410c 100644
--- a/libc/kernel/uapi/linux/tcp_metrics.h
+++ b/libc/kernel/uapi/linux/tcp_metrics.h
@@ -4,8 +4,8 @@
  * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
  * for more information.
  */
-#ifndef _LINUX_TCP_METRICS_H
-#define _LINUX_TCP_METRICS_H
+#ifndef _UAPI_LINUX_TCP_METRICS_H
+#define _UAPI_LINUX_TCP_METRICS_H
 #include <linux/types.h>
 #define TCP_METRICS_GENL_NAME "tcp_metrics"
 #define TCP_METRICS_GENL_VERSION 0x1
@@ -20,6 +20,17 @@ enum tcp_metric_index {
   __TCP_METRIC_MAX,
 };
 #define TCP_METRIC_MAX (__TCP_METRIC_MAX - 1)
+enum {
+  TCP_METRICS_A_METRICS_RTT = 1,
+  TCP_METRICS_A_METRICS_RTTVAR,
+  TCP_METRICS_A_METRICS_SSTHRESH,
+  TCP_METRICS_A_METRICS_CWND,
+  TCP_METRICS_A_METRICS_REODERING,
+  TCP_METRICS_A_METRICS_RTT_US,
+  TCP_METRICS_A_METRICS_RTTVAR_US,
+  __TCP_METRICS_A_METRICS_MAX
+};
+#define TCP_METRICS_A_METRICS_MAX (__TCP_METRICS_A_METRICS_MAX - 1)
 enum {
   TCP_METRICS_ATTR_UNSPEC,
   TCP_METRICS_ATTR_ADDR_IPV4,
diff --git a/libc/kernel/uapi/linux/um_timetravel.h b/libc/kernel/uapi/linux/um_timetravel.h
index 87060171c..49eeb28ea 100644
--- a/libc/kernel/uapi/linux/um_timetravel.h
+++ b/libc/kernel/uapi/linux/um_timetravel.h
@@ -12,6 +12,15 @@ struct um_timetravel_msg {
   __u32 seq;
   __u64 time;
 };
+#define UM_TIMETRAVEL_MAX_FDS 2
+enum um_timetravel_shared_mem_fds {
+  UM_TIMETRAVEL_SHARED_MEMFD,
+  UM_TIMETRAVEL_SHARED_LOGFD,
+  UM_TIMETRAVEL_SHARED_MAX_FDS,
+};
+enum um_timetravel_start_ack {
+  UM_TIMETRAVEL_START_ACK_ID = 0xffff,
+};
 enum um_timetravel_ops {
   UM_TIMETRAVEL_ACK = 0,
   UM_TIMETRAVEL_START = 1,
@@ -22,5 +31,36 @@ enum um_timetravel_ops {
   UM_TIMETRAVEL_RUN = 6,
   UM_TIMETRAVEL_FREE_UNTIL = 7,
   UM_TIMETRAVEL_GET_TOD = 8,
+  UM_TIMETRAVEL_BROADCAST = 9,
+};
+#define UM_TIMETRAVEL_SCHEDSHM_VERSION 2
+enum um_timetravel_schedshm_cap {
+  UM_TIMETRAVEL_SCHEDSHM_CAP_TIME_SHARE = 0x1,
+};
+enum um_timetravel_schedshm_flags {
+  UM_TIMETRAVEL_SCHEDSHM_FLAGS_REQ_RUN = 0x1,
+};
+union um_timetravel_schedshm_client {
+  struct {
+    __u32 capa;
+    __u32 flags;
+    __u64 req_time;
+    __u64 name;
+  };
+  char reserve[128];
+};
+struct um_timetravel_schedshm {
+  union {
+    struct {
+      __u32 version;
+      __u32 len;
+      __u64 free_until;
+      __u64 current_time;
+      __u16 running_id;
+      __u16 max_clients;
+    };
+    char hdr[4096];
+  };
+  union um_timetravel_schedshm_client clients[];
 };
 #endif
diff --git a/libc/kernel/uapi/linux/v4l2-controls.h b/libc/kernel/uapi/linux/v4l2-controls.h
index 23158dcbc..f6ef26cd5 100644
--- a/libc/kernel/uapi/linux/v4l2-controls.h
+++ b/libc/kernel/uapi/linux/v4l2-controls.h
@@ -714,6 +714,7 @@ enum v4l2_mpeg_video_av1_level {
   V4L2_MPEG_VIDEO_AV1_LEVEL_7_2 = 22,
   V4L2_MPEG_VIDEO_AV1_LEVEL_7_3 = 23
 };
+#define V4L2_CID_MPEG_VIDEO_AVERAGE_QP (V4L2_CID_CODEC_BASE + 657)
 #define V4L2_CID_CODEC_CX2341X_BASE (V4L2_CTRL_CLASS_CODEC | 0x1000)
 #define V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER_MODE (V4L2_CID_CODEC_CX2341X_BASE + 0)
 enum v4l2_mpeg_cx2341x_video_spatial_filter_mode {
diff --git a/libc/kernel/uapi/linux/version.h b/libc/kernel/uapi/linux/version.h
index 7faa30f13..0cc45cfe9 100644
--- a/libc/kernel/uapi/linux/version.h
+++ b/libc/kernel/uapi/linux/version.h
@@ -4,8 +4,8 @@
  * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
  * for more information.
  */
-#define LINUX_VERSION_CODE 395776
+#define LINUX_VERSION_CODE 396032
 #define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
 #define LINUX_VERSION_MAJOR 6
-#define LINUX_VERSION_PATCHLEVEL 10
+#define LINUX_VERSION_PATCHLEVEL 11
 #define LINUX_VERSION_SUBLEVEL 0
diff --git a/libc/kernel/uapi/linux/videodev2.h b/libc/kernel/uapi/linux/videodev2.h
index 390594970..fb69a8aab 100644
--- a/libc/kernel/uapi/linux/videodev2.h
+++ b/libc/kernel/uapi/linux/videodev2.h
@@ -236,6 +236,8 @@ struct v4l2_pix_format {
 #define V4L2_PIX_FMT_RGBA1010102 v4l2_fourcc('R', 'A', '3', '0')
 #define V4L2_PIX_FMT_ARGB2101010 v4l2_fourcc('A', 'R', '3', '0')
 #define V4L2_PIX_FMT_BGR48_12 v4l2_fourcc('B', '3', '1', '2')
+#define V4L2_PIX_FMT_BGR48 v4l2_fourcc('B', 'G', 'R', '6')
+#define V4L2_PIX_FMT_RGB48 v4l2_fourcc('R', 'G', 'B', '6')
 #define V4L2_PIX_FMT_ABGR64_12 v4l2_fourcc('B', '4', '1', '2')
 #define V4L2_PIX_FMT_GREY v4l2_fourcc('G', 'R', 'E', 'Y')
 #define V4L2_PIX_FMT_Y4 v4l2_fourcc('Y', '0', '4', ' ')
@@ -425,6 +427,16 @@ struct v4l2_pix_format {
 #define V4L2_PIX_FMT_IPU3_SGBRG10 v4l2_fourcc('i', 'p', '3', 'g')
 #define V4L2_PIX_FMT_IPU3_SGRBG10 v4l2_fourcc('i', 'p', '3', 'G')
 #define V4L2_PIX_FMT_IPU3_SRGGB10 v4l2_fourcc('i', 'p', '3', 'r')
+#define V4L2_PIX_FMT_PISP_COMP1_RGGB v4l2_fourcc('P', 'C', '1', 'R')
+#define V4L2_PIX_FMT_PISP_COMP1_GRBG v4l2_fourcc('P', 'C', '1', 'G')
+#define V4L2_PIX_FMT_PISP_COMP1_GBRG v4l2_fourcc('P', 'C', '1', 'g')
+#define V4L2_PIX_FMT_PISP_COMP1_BGGR v4l2_fourcc('P', 'C', '1', 'B')
+#define V4L2_PIX_FMT_PISP_COMP1_MONO v4l2_fourcc('P', 'C', '1', 'M')
+#define V4L2_PIX_FMT_PISP_COMP2_RGGB v4l2_fourcc('P', 'C', '2', 'R')
+#define V4L2_PIX_FMT_PISP_COMP2_GRBG v4l2_fourcc('P', 'C', '2', 'G')
+#define V4L2_PIX_FMT_PISP_COMP2_GBRG v4l2_fourcc('P', 'C', '2', 'g')
+#define V4L2_PIX_FMT_PISP_COMP2_BGGR v4l2_fourcc('P', 'C', '2', 'B')
+#define V4L2_PIX_FMT_PISP_COMP2_MONO v4l2_fourcc('P', 'C', '2', 'M')
 #define V4L2_SDR_FMT_CU8 v4l2_fourcc('C', 'U', '0', '8')
 #define V4L2_SDR_FMT_CU16LE v4l2_fourcc('C', 'U', '1', '6')
 #define V4L2_SDR_FMT_CS8 v4l2_fourcc('C', 'S', '0', '8')
@@ -444,6 +456,7 @@ struct v4l2_pix_format {
 #define V4L2_META_FMT_VIVID v4l2_fourcc('V', 'I', 'V', 'D')
 #define V4L2_META_FMT_RK_ISP1_PARAMS v4l2_fourcc('R', 'K', '1', 'P')
 #define V4L2_META_FMT_RK_ISP1_STAT_3A v4l2_fourcc('R', 'K', '1', 'S')
+#define V4L2_META_FMT_RPI_BE_CFG v4l2_fourcc('R', 'P', 'B', 'C')
 #define V4L2_PIX_FMT_PRIV_MAGIC 0xfeedcafe
 #define V4L2_PIX_FMT_FLAG_PREMUL_ALPHA 0x00000001
 #define V4L2_PIX_FMT_FLAG_SET_CSC 0x00000002
diff --git a/libc/kernel/uapi/linux/xfrm.h b/libc/kernel/uapi/linux/xfrm.h
index b8e79e804..9509efe02 100644
--- a/libc/kernel/uapi/linux/xfrm.h
+++ b/libc/kernel/uapi/linux/xfrm.h
@@ -260,6 +260,7 @@ enum xfrm_attr_type_t {
   XFRMA_IF_ID,
   XFRMA_MTIMER_THRESH,
   XFRMA_SA_DIR,
+  XFRMA_NAT_KEEPALIVE_INTERVAL,
   __XFRMA_MAX
 #define XFRMA_OUTPUT_MARK XFRMA_SET_MARK
 #define XFRMA_MAX (__XFRMA_MAX - 1)
diff --git a/libc/kernel/uapi/linux/zorro_ids.h b/libc/kernel/uapi/linux/zorro_ids.h
index f47c89947..05239cd24 100644
--- a/libc/kernel/uapi/linux/zorro_ids.h
+++ b/libc/kernel/uapi/linux/zorro_ids.h
@@ -354,6 +354,8 @@
 #define ZORRO_MANUF_VMC 0x1389
 #define ZORRO_PROD_VMC_ISDN_BLASTER_Z2 ZORRO_ID(VMC, 0x01, 0)
 #define ZORRO_PROD_VMC_HYPERCOM_4 ZORRO_ID(VMC, 0x02, 0)
+#define ZORRO_MANUF_CSLAB 0x1400
+#define ZORRO_PROD_CSLAB_WARP_1260 ZORRO_ID(CSLAB, 0x65, 0)
 #define ZORRO_MANUF_INFORMATION 0x157C
 #define ZORRO_PROD_INFORMATION_ISDN_ENGINE_I ZORRO_ID(INFORMATION, 0x64, 0)
 #define ZORRO_MANUF_VORTEX 0x2017
diff --git a/libc/kernel/uapi/misc/mrvl_cn10k_dpi.h b/libc/kernel/uapi/misc/mrvl_cn10k_dpi.h
new file mode 100644
index 000000000..7d8671f74
--- /dev/null
+++ b/libc/kernel/uapi/misc/mrvl_cn10k_dpi.h
@@ -0,0 +1,26 @@
+/*
+ * This file is auto-generated. Modifications will be lost.
+ *
+ * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
+ * for more information.
+ */
+#ifndef __MRVL_CN10K_DPI_H__
+#define __MRVL_CN10K_DPI_H__
+#include <linux/types.h>
+#define DPI_MAX_ENGINES 6
+struct dpi_mps_mrrs_cfg {
+  __u16 max_read_req_sz;
+  __u16 max_payload_sz;
+  __u16 port;
+  __u16 reserved;
+};
+struct dpi_engine_cfg {
+  __u64 fifo_mask;
+  __u16 molr[DPI_MAX_ENGINES];
+  __u16 update_molr;
+  __u16 reserved;
+};
+#define DPI_MAGIC_NUM 0xB8
+#define DPI_MPS_MRRS_CFG _IOW(DPI_MAGIC_NUM, 1, struct dpi_mps_mrrs_cfg)
+#define DPI_ENGINE_CFG _IOW(DPI_MAGIC_NUM, 2, struct dpi_engine_cfg)
+#endif
diff --git a/libc/kernel/uapi/rdma/bnxt_re-abi.h b/libc/kernel/uapi/rdma/bnxt_re-abi.h
index 3dceafd8f..50f8b8a8c 100644
--- a/libc/kernel/uapi/rdma/bnxt_re-abi.h
+++ b/libc/kernel/uapi/rdma/bnxt_re-abi.h
@@ -18,7 +18,7 @@ enum {
   BNXT_RE_UCNTX_CMASK_WC_DPI_ENABLED = 0x04ULL,
   BNXT_RE_UCNTX_CMASK_DBR_PACING_ENABLED = 0x08ULL,
   BNXT_RE_UCNTX_CMASK_POW2_DISABLED = 0x10ULL,
-  BNXT_RE_COMP_MASK_UCNTX_HW_RETX_ENABLED = 0x40,
+  BNXT_RE_UCNTX_CMASK_MSN_TABLE_ENABLED = 0x40,
 };
 enum bnxt_re_wqe_mode {
   BNXT_QPLIB_WQE_MODE_STATIC = 0x00,
diff --git a/libc/kernel/uapi/rdma/ib_user_ioctl_cmds.h b/libc/kernel/uapi/rdma/ib_user_ioctl_cmds.h
index d774fba7e..5f5c4262b 100644
--- a/libc/kernel/uapi/rdma/ib_user_ioctl_cmds.h
+++ b/libc/kernel/uapi/rdma/ib_user_ioctl_cmds.h
@@ -8,8 +8,6 @@
 #define IB_USER_IOCTL_CMDS_H
 #define UVERBS_ID_NS_MASK 0xF000
 #define UVERBS_ID_NS_SHIFT 12
-#define UVERBS_UDATA_DRIVER_DATA_NS 1
-#define UVERBS_UDATA_DRIVER_DATA_FLAG (1UL << UVERBS_ID_NS_SHIFT)
 enum uverbs_default_objects {
   UVERBS_OBJECT_DEVICE,
   UVERBS_OBJECT_PD,
@@ -30,8 +28,10 @@ enum uverbs_default_objects {
   UVERBS_OBJECT_ASYNC_EVENT,
 };
 enum {
-  UVERBS_ATTR_UHW_IN = UVERBS_UDATA_DRIVER_DATA_FLAG,
+  UVERBS_ID_DRIVER_NS = 1UL << UVERBS_ID_NS_SHIFT,
+  UVERBS_ATTR_UHW_IN = UVERBS_ID_DRIVER_NS,
   UVERBS_ATTR_UHW_OUT,
+  UVERBS_ID_DRIVER_NS_WITH_UHW,
 };
 enum uverbs_methods_device {
   UVERBS_METHOD_INVOKE_WRITE,
diff --git a/libc/kernel/uapi/rdma/mana-abi.h b/libc/kernel/uapi/rdma/mana-abi.h
index 734717596..02bb06145 100644
--- a/libc/kernel/uapi/rdma/mana-abi.h
+++ b/libc/kernel/uapi/rdma/mana-abi.h
@@ -33,6 +33,13 @@ struct mana_ib_create_qp_resp {
   __u32 tx_vp_offset;
   __u32 reserved;
 };
+struct mana_ib_create_rc_qp {
+  __aligned_u64 queue_buf[4];
+  __u32 queue_size[4];
+};
+struct mana_ib_create_rc_qp_resp {
+  __u32 queue_id[4];
+};
 struct mana_ib_create_wq {
   __aligned_u64 wq_buf_addr;
   __u32 wq_buf_size;
diff --git a/libc/kernel/uapi/rdma/mlx5_user_ioctl_cmds.h b/libc/kernel/uapi/rdma/mlx5_user_ioctl_cmds.h
index 69d525065..ebafb00fd 100644
--- a/libc/kernel/uapi/rdma/mlx5_user_ioctl_cmds.h
+++ b/libc/kernel/uapi/rdma/mlx5_user_ioctl_cmds.h
@@ -201,6 +201,9 @@ enum mlx5_ib_steering_anchor_methods {
 enum mlx5_ib_device_query_context_attrs {
   MLX5_IB_ATTR_QUERY_CONTEXT_RESP_UCTX = (1U << UVERBS_ID_NS_SHIFT),
 };
+enum mlx5_ib_create_cq_attrs {
+  MLX5_IB_ATTR_CREATE_CQ_UAR_INDEX = UVERBS_ID_DRIVER_NS_WITH_UHW,
+};
 #define MLX5_IB_DW_MATCH_PARAM 0xA0
 struct mlx5_ib_match_params {
   __u32 match_params[MLX5_IB_DW_MATCH_PARAM];
diff --git a/libc/kernel/uapi/rdma/rdma_netlink.h b/libc/kernel/uapi/rdma/rdma_netlink.h
index 912a3c0d4..ac027ac76 100644
--- a/libc/kernel/uapi/rdma/rdma_netlink.h
+++ b/libc/kernel/uapi/rdma/rdma_netlink.h
@@ -199,6 +199,8 @@ enum rdma_nldev_command {
   RDMA_NLDEV_CMD_RES_SRQ_GET,
   RDMA_NLDEV_CMD_STAT_GET_STATUS,
   RDMA_NLDEV_CMD_RES_SRQ_GET_RAW,
+  RDMA_NLDEV_CMD_NEWDEV,
+  RDMA_NLDEV_CMD_DELDEV,
   RDMA_NLDEV_NUM_OPS
 };
 enum rdma_nldev_print_type {
@@ -306,6 +308,9 @@ enum rdma_nldev_attr {
   RDMA_NLDEV_SYS_ATTR_PRIVILEGED_QKEY_MODE,
   RDMA_NLDEV_ATTR_DRIVER_DETAILS,
   RDMA_NLDEV_ATTR_RES_SUBTYPE,
+  RDMA_NLDEV_ATTR_DEV_TYPE,
+  RDMA_NLDEV_ATTR_PARENT_NAME,
+  RDMA_NLDEV_ATTR_NAME_ASSIGN_TYPE,
   RDMA_NLDEV_ATTR_MAX
 };
 enum rdma_nl_counter_mode {
@@ -318,4 +323,11 @@ enum rdma_nl_counter_mask {
   RDMA_COUNTER_MASK_QP_TYPE = 1,
   RDMA_COUNTER_MASK_PID = 1 << 1,
 };
+enum rdma_nl_dev_type {
+  RDMA_DEVICE_TYPE_SMI = 1,
+};
+enum rdma_nl_name_assign_type {
+  RDMA_NAME_ASSIGN_TYPE_UNKNOWN = 0,
+  RDMA_NAME_ASSIGN_TYPE_USER = 1,
+};
 #endif
diff --git a/libc/kernel/uapi/scsi/scsi_bsg_mpi3mr.h b/libc/kernel/uapi/scsi/scsi_bsg_mpi3mr.h
index d98e8fa48..fe3094e02 100644
--- a/libc/kernel/uapi/scsi/scsi_bsg_mpi3mr.h
+++ b/libc/kernel/uapi/scsi/scsi_bsg_mpi3mr.h
@@ -144,7 +144,7 @@ struct mpi3mr_hdb_entry {
 };
 struct mpi3mr_bsg_in_hdb_status {
   __u8 num_hdb_types;
-  __u8 rsvd1;
+  __u8 element_trigger_format;
   __u16 rsvd2;
   __u32 rsvd3;
   struct mpi3mr_hdb_entry entry[1];
diff --git a/libc/kernel/uapi/sound/asequencer.h b/libc/kernel/uapi/sound/asequencer.h
index 79185285f..a3826a585 100644
--- a/libc/kernel/uapi/sound/asequencer.h
+++ b/libc/kernel/uapi/sound/asequencer.h
@@ -7,7 +7,7 @@
 #ifndef _UAPI__SOUND_ASEQUENCER_H
 #define _UAPI__SOUND_ASEQUENCER_H
 #include <sound/asound.h>
-#define SNDRV_SEQ_VERSION SNDRV_PROTOCOL_VERSION(1, 0, 3)
+#define SNDRV_SEQ_VERSION SNDRV_PROTOCOL_VERSION(1, 0, 4)
 #define SNDRV_SEQ_EVENT_SYSTEM 0
 #define SNDRV_SEQ_EVENT_RESULT 1
 #define SNDRV_SEQ_EVENT_NOTE 5
@@ -343,7 +343,8 @@ struct snd_seq_queue_tempo {
   int ppq;
   unsigned int skew_value;
   unsigned int skew_base;
-  char reserved[24];
+  unsigned short tempo_base;
+  char reserved[22];
 };
 #define SNDRV_SEQ_TIMER_ALSA 0
 #define SNDRV_SEQ_TIMER_MIDI_CLOCK 1
diff --git a/libc/kernel/uapi/sound/asound.h b/libc/kernel/uapi/sound/asound.h
index b608ed51f..cfe9f669a 100644
--- a/libc/kernel/uapi/sound/asound.h
+++ b/libc/kernel/uapi/sound/asound.h
@@ -92,7 +92,7 @@ struct snd_hwdep_dsp_image {
 #define SNDRV_HWDEP_IOCTL_INFO _IOR('H', 0x01, struct snd_hwdep_info)
 #define SNDRV_HWDEP_IOCTL_DSP_STATUS _IOR('H', 0x02, struct snd_hwdep_dsp_status)
 #define SNDRV_HWDEP_IOCTL_DSP_LOAD _IOW('H', 0x03, struct snd_hwdep_dsp_image)
-#define SNDRV_PCM_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 17)
+#define SNDRV_PCM_VERSION SNDRV_PROTOCOL_VERSION(2, 0, 18)
 typedef unsigned long snd_pcm_uframes_t;
 typedef signed long snd_pcm_sframes_t;
 enum {
@@ -263,7 +263,7 @@ union snd_pcm_sync_id {
   unsigned char id[16];
   unsigned short id16[8];
   unsigned int id32[4];
-};
+} __attribute__((deprecated));
 struct snd_pcm_info {
   unsigned int device;
   unsigned int subdevice;
@@ -276,7 +276,7 @@ struct snd_pcm_info {
   int dev_subclass;
   unsigned int subdevices_count;
   unsigned int subdevices_avail;
-  union snd_pcm_sync_id sync;
+  unsigned char pad1[16];
   unsigned char reserved[64];
 };
 typedef int snd_pcm_hw_param_t;
@@ -324,7 +324,8 @@ struct snd_pcm_hw_params {
   unsigned int rate_num;
   unsigned int rate_den;
   snd_pcm_uframes_t fifo_size;
-  unsigned char reserved[64];
+  unsigned char sync[16];
+  unsigned char reserved[48];
 };
 enum {
   SNDRV_PCM_TSTAMP_NONE = 0,
diff --git a/libc/kernel/uapi/sound/sof/abi.h b/libc/kernel/uapi/sound/sof/abi.h
index fe1fe47a0..ed6613195 100644
--- a/libc/kernel/uapi/sound/sof/abi.h
+++ b/libc/kernel/uapi/sound/sof/abi.h
@@ -9,7 +9,7 @@
 #include <linux/types.h>
 #define SOF_ABI_MAJOR 3
 #define SOF_ABI_MINOR 23
-#define SOF_ABI_PATCH 0
+#define SOF_ABI_PATCH 1
 #define SOF_ABI_MAJOR_SHIFT 24
 #define SOF_ABI_MAJOR_MASK 0xff
 #define SOF_ABI_MINOR_SHIFT 12
diff --git a/libc/libc.map.txt b/libc/libc.map.txt
index 0d2e42fcc..86dcc3975 100644
--- a/libc/libc.map.txt
+++ b/libc/libc.map.txt
@@ -591,7 +591,6 @@ LIBC {
     killpg;
     klogctl;
     labs;
-    lchmod; # introduced=36
     lchown;
     lcong48; # introduced=23
     ldexp;
@@ -671,7 +670,6 @@ LIBC {
     mprotect;
     mrand48;
     mremap;
-    mseal; # introduced=36
     msync;
     munlock;
     munlockall;
@@ -846,7 +844,6 @@ LIBC {
     pwrite;
     pwrite64;
     qsort;
-    qsort_r; # introduced=36
     quick_exit;
     raise;
     rand;
@@ -955,7 +952,6 @@ LIBC {
     setvbuf;
     setxattr;
     shutdown;
-    sig2str; # introduced=36
     sigaction;
     sigaddset;
     sigaltstack;
@@ -998,7 +994,6 @@ LIBC {
     stdout; # var introduced=23
     stpcpy;
     stpncpy;
-    str2sig; # introduced=36
     strcasecmp;
     strcasecmp_l; # introduced=23
     strcasestr;
@@ -1613,6 +1608,17 @@ LIBC_V { # introduced=35
     __system_properties_zygote_reload; # apex
 } LIBC_U;
 
+LIBC_36 { # introduced=36
+  global:
+    lchmod;
+    mseal;
+    pthread_getaffinity_np;
+    pthread_setaffinity_np;
+    qsort_r;
+    sig2str;
+    str2sig;
+} LIBC_V;
+
 LIBC_PRIVATE {
   global:
     __accept4; # arm x86
diff --git a/libc/malloc_debug/Android.bp b/libc/malloc_debug/Android.bp
index 3828c2802..5d61801ff 100644
--- a/libc/malloc_debug/Android.bp
+++ b/libc/malloc_debug/Android.bp
@@ -79,6 +79,10 @@ cc_library {
         "libmemunreachable",
     ],
 
+    whole_static_libs: [
+        "libmemory_trace",
+    ],
+
     shared_libs: [
         "libunwindstack",
     ],
diff --git a/libc/malloc_debug/Nanotime.h b/libc/malloc_debug/Nanotime.h
new file mode 100644
index 000000000..d7c3f6036
--- /dev/null
+++ b/libc/malloc_debug/Nanotime.h
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2012 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#pragma once
+
+#include <stdint.h>
+#include <time.h>
+
+static inline __always_inline uint64_t Nanotime() {
+  struct timespec t = {};
+  clock_gettime(CLOCK_MONOTONIC, &t);
+  return static_cast<uint64_t>(t.tv_sec) * 1000000000LL + t.tv_nsec;
+}
diff --git a/libc/malloc_debug/RecordData.cpp b/libc/malloc_debug/RecordData.cpp
index 79e051b00..1641732cb 100644
--- a/libc/malloc_debug/RecordData.cpp
+++ b/libc/malloc_debug/RecordData.cpp
@@ -39,72 +39,19 @@
 #include <mutex>
 
 #include <android-base/stringprintf.h>
+#include <memory_trace/MemoryTrace.h>
 
 #include "Config.h"
 #include "DebugData.h"
+#include "Nanotime.h"
 #include "RecordData.h"
 #include "debug_disable.h"
 #include "debug_log.h"
 
-RecordEntry::RecordEntry() : tid_(gettid()) {
-}
-
-bool ThreadCompleteEntry::Write(int fd) const {
-  return dprintf(fd, "%d: thread_done 0x0\n", tid_) > 0;
-}
-
-AllocEntry::AllocEntry(void* pointer, uint64_t start_ns, uint64_t end_ns)
-    : pointer_(pointer), start_ns_(start_ns), end_ns_(end_ns) {}
-
-MallocEntry::MallocEntry(void* pointer, size_t size, uint64_t start_ns, uint64_t end_ns)
-    : AllocEntry(pointer, start_ns, end_ns), size_(size) {}
-
-bool MallocEntry::Write(int fd) const {
-  return dprintf(fd, "%d: malloc %p %zu %" PRIu64 " %" PRIu64 "\n", tid_, pointer_, size_,
-                 start_ns_, end_ns_) > 0;
-}
-
-FreeEntry::FreeEntry(void* pointer, uint64_t start_ns, uint64_t end_ns)
-    : AllocEntry(pointer, start_ns, end_ns) {}
-
-bool FreeEntry::Write(int fd) const {
-  return dprintf(fd, "%d: free %p %" PRIu64 " %" PRIu64 "\n", tid_, pointer_, start_ns_, end_ns_) >
-         0;
-}
-
-CallocEntry::CallocEntry(void* pointer, size_t nmemb, size_t size, uint64_t start_ns,
-                         uint64_t end_ns)
-    : MallocEntry(pointer, size, start_ns, end_ns), nmemb_(nmemb) {}
-
-bool CallocEntry::Write(int fd) const {
-  return dprintf(fd, "%d: calloc %p %zu %zu %" PRIu64 " %" PRIu64 "\n", tid_, pointer_, nmemb_,
-                 size_, start_ns_, end_ns_) > 0;
-}
-
-ReallocEntry::ReallocEntry(void* pointer, size_t size, void* old_pointer, uint64_t start_ns,
-                           uint64_t end_ns)
-    : MallocEntry(pointer, size, start_ns, end_ns), old_pointer_(old_pointer) {}
-
-bool ReallocEntry::Write(int fd) const {
-  return dprintf(fd, "%d: realloc %p %p %zu %" PRIu64 " %" PRIu64 "\n", tid_, pointer_,
-                 old_pointer_, size_, start_ns_, end_ns_) > 0;
-}
-
-// aligned_alloc, posix_memalign, memalign, pvalloc, valloc all recorded with this class.
-MemalignEntry::MemalignEntry(void* pointer, size_t size, size_t alignment, uint64_t start_ns,
-                             uint64_t end_ns)
-    : MallocEntry(pointer, size, start_ns, end_ns), alignment_(alignment) {}
-
-bool MemalignEntry::Write(int fd) const {
-  return dprintf(fd, "%d: memalign %p %zu %zu %" PRIu64 " %" PRIu64 "\n", tid_, pointer_,
-                 alignment_, size_, start_ns_, end_ns_) > 0;
-}
-
 struct ThreadData {
-  ThreadData(RecordData* record_data, ThreadCompleteEntry* entry)
-      : record_data(record_data), entry(entry) {}
-  RecordData* record_data;
-  ThreadCompleteEntry* entry;
+  ThreadData(RecordData* record_data) : record_data(record_data) {}
+
+  RecordData* record_data = nullptr;
   size_t count = 0;
 };
 
@@ -117,7 +64,8 @@ static void ThreadKeyDelete(void* data) {
   if (thread_data->count == 4) {
     ScopedDisableDebugCalls disable;
 
-    thread_data->record_data->AddEntryOnly(thread_data->entry);
+    thread_data->record_data->AddEntryOnly(memory_trace::Entry{
+        .tid = gettid(), .type = memory_trace::THREAD_DONE, .end_ns = Nanotime()});
     delete thread_data;
   } else {
     pthread_setspecific(thread_data->record_data->key(), data);
@@ -159,7 +107,7 @@ void RecordData::WriteEntries(const std::string& file) {
   }
 
   for (size_t i = 0; i < cur_index_; i++) {
-    if (!entries_[i]->Write(dump_fd)) {
+    if (!memory_trace::WriteEntryToFd(dump_fd, entries_[i])) {
       error_log("Failed to write record alloc information: %s", strerror(errno));
       break;
     }
@@ -201,23 +149,23 @@ RecordData::~RecordData() {
   pthread_key_delete(key_);
 }
 
-void RecordData::AddEntryOnly(const RecordEntry* entry) {
+void RecordData::AddEntryOnly(const memory_trace::Entry& entry) {
   std::lock_guard<std::mutex> entries_lock(entries_lock_);
   if (cur_index_ == entries_.size()) {
     // Maxed out, throw the entry away.
     return;
   }
 
-  entries_[cur_index_++].reset(entry);
+  entries_[cur_index_++] = entry;
   if (cur_index_ == entries_.size()) {
     info_log("Maximum number of records added, all new operations will be dropped.");
   }
 }
 
-void RecordData::AddEntry(const RecordEntry* entry) {
+void RecordData::AddEntry(const memory_trace::Entry& entry) {
   void* data = pthread_getspecific(key_);
   if (data == nullptr) {
-    ThreadData* thread_data = new ThreadData(this, new ThreadCompleteEntry());
+    ThreadData* thread_data = new ThreadData(this);
     pthread_setspecific(key_, thread_data);
   }
 
diff --git a/libc/malloc_debug/RecordData.h b/libc/malloc_debug/RecordData.h
index 7efa1f7b3..f4b0d82ca 100644
--- a/libc/malloc_debug/RecordData.h
+++ b/libc/malloc_debug/RecordData.h
@@ -39,117 +39,9 @@
 #include <string>
 #include <vector>
 
+#include <memory_trace/MemoryTrace.h>
 #include <platform/bionic/macros.h>
 
-class RecordEntry {
- public:
-  RecordEntry();
-  virtual ~RecordEntry() = default;
-
-  virtual bool Write(int fd) const = 0;
-
- protected:
-  pid_t tid_;
-
- private:
-  BIONIC_DISALLOW_COPY_AND_ASSIGN(RecordEntry);
-};
-
-class ThreadCompleteEntry : public RecordEntry {
- public:
-  ThreadCompleteEntry() = default;
-  virtual ~ThreadCompleteEntry() = default;
-
-  bool Write(int fd) const override;
-
- private:
-  BIONIC_DISALLOW_COPY_AND_ASSIGN(ThreadCompleteEntry);
-};
-
-class AllocEntry : public RecordEntry {
- public:
-  explicit AllocEntry(void* pointer, uint64_t st, uint64_t et);
-  virtual ~AllocEntry() = default;
-
- protected:
-  void* pointer_;
-
-  // The start/end time of this operation.
-  uint64_t start_ns_;
-  uint64_t end_ns_;
-
- private:
-  BIONIC_DISALLOW_COPY_AND_ASSIGN(AllocEntry);
-};
-
-class MallocEntry : public AllocEntry {
- public:
-  MallocEntry(void* pointer, size_t size, uint64_t st, uint64_t et);
-  virtual ~MallocEntry() = default;
-
-  bool Write(int fd) const override;
-
- protected:
-  size_t size_;
-
- private:
-  BIONIC_DISALLOW_COPY_AND_ASSIGN(MallocEntry);
-};
-
-class FreeEntry : public AllocEntry {
- public:
-  explicit FreeEntry(void* pointer, uint64_t st, uint64_t et);
-  virtual ~FreeEntry() = default;
-
-  bool Write(int fd) const override;
-
- private:
-  BIONIC_DISALLOW_COPY_AND_ASSIGN(FreeEntry);
-};
-
-class CallocEntry : public MallocEntry {
- public:
-  CallocEntry(void* pointer, size_t nmemb, size_t size, uint64_t st, uint64_t et);
-  virtual ~CallocEntry() = default;
-
-  bool Write(int fd) const override;
-
- protected:
-  size_t nmemb_;
-
- private:
-  BIONIC_DISALLOW_COPY_AND_ASSIGN(CallocEntry);
-};
-
-class ReallocEntry : public MallocEntry {
- public:
-  ReallocEntry(void* pointer, size_t size, void* old_pointer, uint64_t st, uint64_t et);
-  virtual ~ReallocEntry() = default;
-
-  bool Write(int fd) const override;
-
- protected:
-  void* old_pointer_;
-
- private:
-  BIONIC_DISALLOW_COPY_AND_ASSIGN(ReallocEntry);
-};
-
-// aligned_alloc, posix_memalign, memalign, pvalloc, valloc all recorded with this class.
-class MemalignEntry : public MallocEntry {
- public:
-  MemalignEntry(void* pointer, size_t size, size_t alignment, uint64_t st, uint64_t et);
-  virtual ~MemalignEntry() = default;
-
-  bool Write(int fd) const override;
-
- protected:
-  size_t alignment_;
-
- private:
-  BIONIC_DISALLOW_COPY_AND_ASSIGN(MemalignEntry);
-};
-
 class Config;
 
 class RecordData {
@@ -159,8 +51,8 @@ class RecordData {
 
   bool Initialize(const Config& config);
 
-  void AddEntry(const RecordEntry* entry);
-  void AddEntryOnly(const RecordEntry* entry);
+  void AddEntry(const memory_trace::Entry& entry);
+  void AddEntryOnly(const memory_trace::Entry& entry);
 
   const std::string& file() { return file_; }
   pthread_key_t key() { return key_; }
@@ -176,7 +68,7 @@ class RecordData {
 
   std::mutex entries_lock_;
   pthread_key_t key_;
-  std::vector<std::unique_ptr<const RecordEntry>> entries_;
+  std::vector<memory_trace::Entry> entries_;
   size_t cur_index_;
   std::string file_;
 
diff --git a/libc/malloc_debug/malloc_debug.cpp b/libc/malloc_debug/malloc_debug.cpp
index 374385252..c183897b7 100644
--- a/libc/malloc_debug/malloc_debug.cpp
+++ b/libc/malloc_debug/malloc_debug.cpp
@@ -54,6 +54,7 @@
 #include "Config.h"
 #include "DebugData.h"
 #include "LogAllocatorStats.h"
+#include "Nanotime.h"
 #include "Unreachable.h"
 #include "UnwindBacktrace.h"
 #include "backtrace.h"
@@ -70,12 +71,6 @@ bool* g_zygote_child;
 
 const MallocDispatch* g_dispatch;
 
-static inline __always_inline uint64_t Nanotime() {
-  struct timespec t = {};
-  clock_gettime(CLOCK_MONOTONIC, &t);
-  return static_cast<uint64_t>(t.tv_sec) * 1000000000LL + t.tv_nsec;
-}
-
 namespace {
 // A TimedResult contains the result of from malloc end_ns al. functions and the
 // start/end timestamps.
@@ -598,8 +593,13 @@ void* debug_malloc(size_t size) {
   TimedResult result = InternalMalloc(size);
 
   if (g_debug->config().options() & RECORD_ALLOCS) {
-    g_debug->record->AddEntry(new MallocEntry(result.getValue<void*>(), size,
-                                              result.GetStartTimeNS(), result.GetEndTimeNS()));
+    g_debug->record->AddEntry(
+        memory_trace::Entry{.tid = gettid(),
+                            .type = memory_trace::MALLOC,
+                            .ptr = reinterpret_cast<uint64_t>(result.getValue<void*>()),
+                            .size = size,
+                            .start_ns = result.GetStartTimeNS(),
+                            .end_ns = result.GetEndTimeNS()});
   }
 
   return result.getValue<void*>();
@@ -687,8 +687,11 @@ void debug_free(void* pointer) {
   TimedResult result = InternalFree(pointer);
 
   if (g_debug->config().options() & RECORD_ALLOCS) {
-    g_debug->record->AddEntry(
-        new FreeEntry(pointer, result.GetStartTimeNS(), result.GetEndTimeNS()));
+    g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
+                                                  .type = memory_trace::FREE,
+                                                  .ptr = reinterpret_cast<uint64_t>(pointer),
+                                                  .start_ns = result.GetStartTimeNS(),
+                                                  .end_ns = result.GetEndTimeNS()});
   }
 }
 
@@ -771,8 +774,13 @@ void* debug_memalign(size_t alignment, size_t bytes) {
     }
 
     if (g_debug->config().options() & RECORD_ALLOCS) {
-      g_debug->record->AddEntry(new MemalignEntry(pointer, bytes, alignment,
-                                                  result.GetStartTimeNS(), result.GetEndTimeNS()));
+      g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
+                                                    .type = memory_trace::MEMALIGN,
+                                                    .ptr = reinterpret_cast<uint64_t>(pointer),
+                                                    .size = bytes,
+                                                    .u.align = alignment,
+                                                    .start_ns = result.GetStartTimeNS(),
+                                                    .end_ns = result.GetEndTimeNS()});
     }
   }
 
@@ -791,11 +799,16 @@ void* debug_realloc(void* pointer, size_t bytes) {
 
   if (pointer == nullptr) {
     TimedResult result = InternalMalloc(bytes);
+    pointer = result.getValue<void*>();
     if (g_debug->config().options() & RECORD_ALLOCS) {
-      g_debug->record->AddEntry(new ReallocEntry(result.getValue<void*>(), bytes, nullptr,
-                                                 result.GetStartTimeNS(), result.GetEndTimeNS()));
+      g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
+                                                    .type = memory_trace::REALLOC,
+                                                    .ptr = reinterpret_cast<uint64_t>(pointer),
+                                                    .size = bytes,
+                                                    .u.old_ptr = 0,
+                                                    .start_ns = result.GetStartTimeNS(),
+                                                    .end_ns = result.GetEndTimeNS()});
     }
-    pointer = result.getValue<void*>();
     return pointer;
   }
 
@@ -807,8 +820,14 @@ void* debug_realloc(void* pointer, size_t bytes) {
     TimedResult result = InternalFree(pointer);
 
     if (g_debug->config().options() & RECORD_ALLOCS) {
-      g_debug->record->AddEntry(new ReallocEntry(nullptr, bytes, pointer, result.GetStartTimeNS(),
-                                                 result.GetEndTimeNS()));
+      g_debug->record->AddEntry(
+          memory_trace::Entry{.tid = gettid(),
+                              .type = memory_trace::REALLOC,
+                              .ptr = 0,
+                              .size = 0,
+                              .u.old_ptr = reinterpret_cast<uint64_t>(pointer),
+                              .start_ns = result.GetStartTimeNS(),
+                              .end_ns = result.GetEndTimeNS()});
     }
 
     return nullptr;
@@ -905,8 +924,13 @@ void* debug_realloc(void* pointer, size_t bytes) {
   }
 
   if (g_debug->config().options() & RECORD_ALLOCS) {
-    g_debug->record->AddEntry(new ReallocEntry(new_pointer, bytes, pointer, result.GetStartTimeNS(),
-                                               result.GetEndTimeNS()));
+    g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
+                                                  .type = memory_trace::REALLOC,
+                                                  .ptr = reinterpret_cast<uint64_t>(new_pointer),
+                                                  .size = bytes,
+                                                  .u.old_ptr = reinterpret_cast<uint64_t>(pointer),
+                                                  .start_ns = result.GetStartTimeNS(),
+                                                  .end_ns = result.GetEndTimeNS()});
   }
 
   return new_pointer;
@@ -962,8 +986,13 @@ void* debug_calloc(size_t nmemb, size_t bytes) {
   }
 
   if (g_debug->config().options() & RECORD_ALLOCS) {
-    g_debug->record->AddEntry(
-        new CallocEntry(pointer, nmemb, bytes, result.GetStartTimeNS(), result.GetEndTimeNS()));
+    g_debug->record->AddEntry(memory_trace::Entry{.tid = gettid(),
+                                                  .type = memory_trace::CALLOC,
+                                                  .ptr = reinterpret_cast<uint64_t>(pointer),
+                                                  .size = bytes,
+                                                  .u.n_elements = nmemb,
+                                                  .start_ns = result.GetStartTimeNS(),
+                                                  .end_ns = result.GetEndTimeNS()});
   }
 
   if (pointer != nullptr && g_debug->TrackPointers()) {
diff --git a/libc/platform/bionic/macros.h b/libc/platform/bionic/macros.h
index 93268c147..b2d6f9649 100644
--- a/libc/platform/bionic/macros.h
+++ b/libc/platform/bionic/macros.h
@@ -97,3 +97,26 @@ template <typename T>
 static inline T* _Nonnull untag_address(T* _Nonnull p) {
   return reinterpret_cast<T*>(untag_address(reinterpret_cast<uintptr_t>(p)));
 }
+
+// MTE globals protects internal and external global variables. One of the main
+// things that MTE globals does is force all global variable accesses to go
+// through the GOT. In the linker though, some global variables are accessed (or
+// address-taken) prior to relocations being processed. Because relocations
+// haven't run yet, the GOT entry hasn't been populated, and this leads to
+// crashes. Thus, any globals used by the linker prior to relocation should be
+// annotated with this attribute, which suppresses tagging of this global
+// variable, restoring the pc-relative address computation.
+//
+// A way to find global variables that need this attribute is to build the
+// linker/libc with `SANITIZE_TARGET=memtag_globals`, push them onto a device
+// (it doesn't have to be MTE capable), and then run an executable using
+// LD_LIBRARY_PATH and using the linker in interpreter mode (e.g.
+// `LD_LIBRARY_PATH=/data/tmp/ /data/tmp/linker64 /data/tmp/my_binary`). A
+// good heuristic is that the global variable is in a file that should be
+// compiled with `-ffreestanding` (but there are global variables there that
+// don't need this attribute).
+#if __has_feature(memtag_globals)
+#define BIONIC_USED_BEFORE_LINKER_RELOCATES __attribute__((no_sanitize("memtag")))
+#else  // __has_feature(memtag_globals)
+#define BIONIC_USED_BEFORE_LINKER_RELOCATES
+#endif  // __has_feature(memtag_globals)
diff --git a/libc/platform/bionic/mte.h b/libc/platform/bionic/mte.h
index 98b3d275f..610cb45d0 100644
--- a/libc/platform/bionic/mte.h
+++ b/libc/platform/bionic/mte.h
@@ -28,6 +28,7 @@
 
 #pragma once
 
+#include <stddef.h>
 #include <sys/auxv.h>
 #include <sys/mman.h>
 #include <sys/prctl.h>
@@ -49,6 +50,36 @@ inline bool mte_supported() {
   return supported;
 }
 
+inline void* get_tagged_address(const void* ptr) {
+#if defined(__aarch64__)
+  if (mte_supported()) {
+    __asm__ __volatile__(".arch_extension mte; ldg %0, [%0]" : "+r"(ptr));
+  }
+#endif  // aarch64
+  return const_cast<void*>(ptr);
+}
+
+// Inserts a random tag tag to `ptr`, using any of the set lower 16 bits in
+// `mask` to exclude the corresponding tag from being generated. Note: This does
+// not tag memory. This generates a pointer to be used with set_memory_tag.
+inline void* insert_random_tag(const void* ptr, __attribute__((unused)) uint64_t mask = 0) {
+#if defined(__aarch64__)
+  if (mte_supported() && ptr) {
+    __asm__ __volatile__(".arch_extension mte; irg %0, %0, %1" : "+r"(ptr) : "r"(mask));
+  }
+#endif  // aarch64
+  return const_cast<void*>(ptr);
+}
+
+// Stores the address tag in `ptr` to memory, at `ptr`.
+inline void set_memory_tag(__attribute__((unused)) void* ptr) {
+#if defined(__aarch64__)
+  if (mte_supported()) {
+    __asm__ __volatile__(".arch_extension mte; stg %0, [%0]" : "+r"(ptr));
+  }
+#endif  // aarch64
+}
+
 #ifdef __aarch64__
 class ScopedDisableMTE {
   size_t prev_tco_;
@@ -86,6 +117,12 @@ inline uintptr_t stack_mte_ringbuffer_size_add_to_pointer(uintptr_t ptr, uintptr
   return ptr | ((1ULL << size_cls) << 56ULL);
 }
 
+inline void stack_mte_free_ringbuffer(uintptr_t stack_mte_tls) {
+  size_t size = stack_mte_ringbuffer_size_from_pointer(stack_mte_tls);
+  void* ptr = reinterpret_cast<void*>(stack_mte_tls & ((1ULL << 56ULL) - 1ULL));
+  munmap(ptr, size);
+}
+
 inline void* stack_mte_ringbuffer_allocate(size_t n, const char* name) {
   if (n > 7) return nullptr;
   // Allocation needs to be aligned to 2*size to make the fancy code-gen work.
diff --git a/libc/private/bionic_asm_arm.h b/libc/private/bionic_asm_arm.h
index d8381d32b..9ca5f387d 100644
--- a/libc/private/bionic_asm_arm.h
+++ b/libc/private/bionic_asm_arm.h
@@ -37,7 +37,7 @@
 
 #pragma once
 
-#define __bionic_asm_align 0
+#define __bionic_asm_align 64
 
 #undef __bionic_asm_custom_entry
 #undef __bionic_asm_custom_end
diff --git a/libc/private/bionic_asm_arm64.h b/libc/private/bionic_asm_arm64.h
index ffc718144..1e907a14b 100644
--- a/libc/private/bionic_asm_arm64.h
+++ b/libc/private/bionic_asm_arm64.h
@@ -37,7 +37,7 @@
 
 #pragma once
 
-#define __bionic_asm_align 16
+#define __bionic_asm_align 64
 
 #undef __bionic_asm_function_type
 #define __bionic_asm_function_type %function
diff --git a/libc/private/bionic_constants.h b/libc/private/bionic_constants.h
index 6274fe284..ce484d823 100644
--- a/libc/private/bionic_constants.h
+++ b/libc/private/bionic_constants.h
@@ -16,6 +16,7 @@
 
 #pragma once
 
+#define US_PER_S 1'000'000LL
 #define NS_PER_S 1'000'000'000LL
 
 // Size of the shadow call stack. This can be small because these stacks only
diff --git a/libc/private/bionic_globals.h b/libc/private/bionic_globals.h
index a1bebdaad..cd6dca977 100644
--- a/libc/private/bionic_globals.h
+++ b/libc/private/bionic_globals.h
@@ -157,6 +157,10 @@ struct libc_shared_globals {
 };
 
 __LIBC_HIDDEN__ libc_shared_globals* __libc_shared_globals();
+__LIBC_HIDDEN__ bool __libc_mte_enabled();
+__LIBC_HIDDEN__ void __libc_init_mte(const memtag_dynamic_entries_t*, const void*, size_t,
+                                     uintptr_t);
+__LIBC_HIDDEN__ void __libc_init_mte_stack(void*);
 __LIBC_HIDDEN__ void __libc_init_fdsan();
 __LIBC_HIDDEN__ void __libc_init_fdtrack();
 __LIBC_HIDDEN__ void __libc_init_profiling_handlers();
diff --git a/libc/private/bionic_lock.h b/libc/private/bionic_lock.h
index 8ed49394b..d0c6d5e22 100644
--- a/libc/private/bionic_lock.h
+++ b/libc/private/bionic_lock.h
@@ -46,7 +46,7 @@ class Lock {
 
  public:
   void init(bool process_shared) {
-    atomic_init(&state, Unlocked);
+    atomic_store_explicit(&state, Unlocked, memory_order_relaxed);
     this->process_shared = process_shared;
   }
 
diff --git a/libc/private/bionic_time_conversions.h b/libc/private/bionic_time_conversions.h
index c6b3c7825..ce7de0dfc 100644
--- a/libc/private/bionic_time_conversions.h
+++ b/libc/private/bionic_time_conversions.h
@@ -26,8 +26,7 @@
  * SUCH DAMAGE.
  */
 
-#ifndef _BIONIC_TIME_CONVERSIONS_H
-#define _BIONIC_TIME_CONVERSIONS_H
+#pragma once
 
 #include <errno.h>
 #include <time.h>
@@ -35,20 +34,21 @@
 
 #include "private/bionic_constants.h"
 
-__BEGIN_DECLS
+bool timespec_from_timeval(timespec& ts, const timeval& tv);
+void timespec_from_ms(timespec& ts, const int ms);
 
-__LIBC_HIDDEN__ bool timespec_from_timeval(timespec& ts, const timeval& tv);
-__LIBC_HIDDEN__ void timespec_from_ms(timespec& ts, const int ms);
+void timeval_from_timespec(timeval& tv, const timespec& ts);
 
-__LIBC_HIDDEN__ void timeval_from_timespec(timeval& tv, const timespec& ts);
+void monotonic_time_from_realtime_time(timespec& monotonic_time, const timespec& realtime_time);
+void realtime_time_from_monotonic_time(timespec& realtime_time, const timespec& monotonic_time);
 
-__LIBC_HIDDEN__ void monotonic_time_from_realtime_time(timespec& monotonic_time,
-                                                       const timespec& realtime_time);
-
-__LIBC_HIDDEN__ void realtime_time_from_monotonic_time(timespec& realtime_time,
-                                                       const timespec& monotonic_time);
+static inline int64_t to_ns(const timespec& ts) {
+  return ts.tv_sec * NS_PER_S + ts.tv_nsec;
+}
 
-__END_DECLS
+static inline int64_t to_us(const timeval& tv) {
+  return tv.tv_sec * US_PER_S + tv.tv_usec;
+}
 
 static inline int check_timespec(const timespec* ts, bool null_allowed) {
   if (null_allowed && ts == nullptr) {
@@ -76,5 +76,3 @@ static inline void absolute_timespec_from_timespec(timespec& abs_ts, const times
   }
 }
 #endif
-
-#endif
diff --git a/libc/stdio/stdio.cpp b/libc/stdio/stdio.cpp
index 37b9665ff..a5f2f81f4 100644
--- a/libc/stdio/stdio.cpp
+++ b/libc/stdio/stdio.cpp
@@ -58,8 +58,6 @@
 #include "private/bionic_fortify.h"
 #include "private/thread_private.h"
 
-#include "private/bsd_sys_param.h" // For ALIGN/ALIGNBYTES.
-
 #define	NDYNAMIC 10		/* add ten more whenever necessary */
 
 #define PRINTF_IMPL(expr) \
@@ -135,12 +133,14 @@ class ScopedFileLock {
 };
 
 static glue* moreglue(int n) {
-  char* data = new char[sizeof(glue) + ALIGNBYTES + n * sizeof(FILE) + n * sizeof(__sfileext)];
+  char* data = new char[sizeof(glue) +
+                        alignof(FILE) + n * sizeof(FILE) +
+                        alignof(__sfileext) + n * sizeof(__sfileext)];
   if (data == nullptr) return nullptr;
 
   glue* g = reinterpret_cast<glue*>(data);
-  FILE* p = reinterpret_cast<FILE*>(ALIGN(data + sizeof(*g)));
-  __sfileext* pext = reinterpret_cast<__sfileext*>(ALIGN(data + sizeof(*g)) + n * sizeof(FILE));
+  FILE* p = reinterpret_cast<FILE*>(__builtin_align_up(g + 1, alignof(FILE)));
+  __sfileext* pext = reinterpret_cast<__sfileext*>(__builtin_align_up(p + n, alignof(__sfileext)));
   g->next = nullptr;
   g->niobs = n;
   g->iobs = p;
diff --git a/libc/system_properties/include/system_properties/prop_area.h b/libc/system_properties/include/system_properties/prop_area.h
index 187ff75fe..089cf5274 100644
--- a/libc/system_properties/include/system_properties/prop_area.h
+++ b/libc/system_properties/include/system_properties/prop_area.h
@@ -102,7 +102,7 @@ class prop_area {
   }
 
   prop_area(const uint32_t magic, const uint32_t version) : magic_(magic), version_(version) {
-    atomic_init(&serial_, 0u);
+    atomic_store_explicit(&serial_, 0u, memory_order_relaxed);
     memset(reserved_, 0, sizeof(reserved_));
     // Allocate enough space for the root node.
     bytes_used_ = sizeof(prop_trie_node);
diff --git a/libc/system_properties/prop_info.cpp b/libc/system_properties/prop_info.cpp
index c3bf17756..499b36a9b 100644
--- a/libc/system_properties/prop_info.cpp
+++ b/libc/system_properties/prop_info.cpp
@@ -38,7 +38,7 @@ static_assert(sizeof(kLongLegacyError) < prop_info::kLongLegacyErrorBufferSize,
 prop_info::prop_info(const char* name, uint32_t namelen, const char* value, uint32_t valuelen) {
   memcpy(this->name, name, namelen);
   this->name[namelen] = '\0';
-  atomic_init(&this->serial, valuelen << 24);
+  atomic_store_explicit(&this->serial, valuelen << 24, memory_order_relaxed);
   memcpy(this->value, value, valuelen);
   this->value[valuelen] = '\0';
 }
@@ -48,7 +48,7 @@ prop_info::prop_info(const char* name, uint32_t namelen, uint32_t long_offset) {
   this->name[namelen] = '\0';
 
   auto error_value_len = sizeof(kLongLegacyError) - 1;
-  atomic_init(&this->serial, error_value_len << 24 | kLongFlag);
+  atomic_store_explicit(&this->serial, error_value_len << 24 | kLongFlag, memory_order_relaxed);
   memcpy(this->long_property.error_message, kLongLegacyError, sizeof(kLongLegacyError));
 
   this->long_property.offset = long_offset;
diff --git a/libc/upstream-netbsd/lib/libc/stdlib/bsearch.c b/libc/upstream-netbsd/lib/libc/stdlib/bsearch.c
deleted file mode 100644
index e48fe85e7..000000000
--- a/libc/upstream-netbsd/lib/libc/stdlib/bsearch.c
+++ /dev/null
@@ -1,85 +0,0 @@
-/*	$NetBSD: bsearch.c,v 1.16 2022/05/31 08:43:14 andvar Exp $	*/
-
-/*
- * Copyright (c) 1990, 1993
- *	The Regents of the University of California.  All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- * 1. Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- * 2. Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in the
- *    documentation and/or other materials provided with the distribution.
- * 3. Neither the name of the University nor the names of its contributors
- *    may be used to endorse or promote products derived from this software
- *    without specific prior written permission.
- *
- * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
- * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
- * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
- * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
- * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
- * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
- * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
- * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
- * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
- * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <sys/cdefs.h>
-#if defined(LIBC_SCCS) && !defined(lint)
-#if 0
-static char sccsid[] = "@(#)bsearch.c	8.1 (Berkeley) 6/4/93";
-#else
-__RCSID("$NetBSD: bsearch.c,v 1.16 2022/05/31 08:43:14 andvar Exp $");
-#endif
-#endif /* LIBC_SCCS and not lint */
-
-#include <assert.h>
-#include <errno.h>
-#include <stdlib.h>
-
-/*
- * Perform a binary search.
- *
- * The code below is a bit sneaky.  After a comparison fails, we
- * divide the work in half by moving either left or right. If lim
- * is odd, moving left simply involves halving lim: e.g., when lim
- * is 5 we look at item 2, so we change lim to 2 so that we will
- * look at items 0 & 1.  If lim is even, the same applies.  If lim
- * is odd, moving right again involves halving lim, this time moving
- * the base up one item past p: e.g., when lim is 5 we change base
- * to item 3 and make lim 2 so that we will look at items 3 and 4.
- * If lim is even, however, we have to shrink it by one before
- * halving: e.g., when lim is 4, we still looked at item 2, so we
- * have to make lim 3, then halve, obtaining 1, so that we will only
- * look at item 3.
- */
-void *
-bsearch(const void *key, const void *base0, size_t nmemb, size_t size,
-    int (*compar)(const void *, const void *))
-{
-	const char *base = base0;
-	size_t lim;
-	int cmp;
-	const void *p;
-
-	_DIAGASSERT(key != NULL);
-	_DIAGASSERT(base0 != NULL || nmemb == 0);
-	_DIAGASSERT(compar != NULL);
-
-	for (lim = nmemb; lim != 0; lim >>= 1) {
-		p = base + (lim >> 1) * size;
-		cmp = (*compar)(key, p);
-		if (cmp == 0)
-			return __UNCONST(p);
-		if (cmp > 0) {	/* key > p: move right */
-			base = (const char *)p + size;
-			lim--;
-		}		/* else move left */
-	}
-	return (NULL);
-}
diff --git a/libc/upstream-openbsd/android/include/openbsd-compat.h b/libc/upstream-openbsd/android/include/openbsd-compat.h
index cbc52b539..ac6840ac9 100644
--- a/libc/upstream-openbsd/android/include/openbsd-compat.h
+++ b/libc/upstream-openbsd/android/include/openbsd-compat.h
@@ -25,8 +25,6 @@
 
 #include <sys/random.h> // For getentropy.
 
-#include "private/bsd_sys_param.h"
-
 #define __BEGIN_HIDDEN_DECLS _Pragma("GCC visibility push(hidden)")
 #define __END_HIDDEN_DECLS _Pragma("GCC visibility pop")
 
diff --git a/libc/upstream-openbsd/lib/libc/string/memrchr.c b/libc/upstream-openbsd/lib/libc/string/memrchr.c
deleted file mode 100644
index e123bc173..000000000
--- a/libc/upstream-openbsd/lib/libc/string/memrchr.c
+++ /dev/null
@@ -1,39 +0,0 @@
-/*	$OpenBSD: memrchr.c,v 1.4 2019/01/25 00:19:25 millert Exp $	*/
-
-/*
- * Copyright (c) 2007 Todd C. Miller <millert@openbsd.org>
- *
- * Permission to use, copy, modify, and distribute this software for any
- * purpose with or without fee is hereby granted, provided that the above
- * copyright notice and this permission notice appear in all copies.
- *
- * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
- * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
- * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
- * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
- * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
- * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
- * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
- */
-
-#include <string.h>
-
-/*
- * Reverse memchr()
- * Find the last occurrence of 'c' in the buffer 's' of size 'n'.
- */
-void *
-memrchr(const void *s, int c, size_t n)
-{
-	const unsigned char *cp;
-
-	if (n != 0) {
-		cp = (unsigned char *)s + n;
-		do {
-			if (*(--cp) == (unsigned char)c)
-				return((void *)cp);
-		} while (--n != 0);
-	}
-	return(NULL);
-}
-DEF_WEAK(memrchr);
diff --git a/libc/upstream-openbsd/lib/libc/string/strlcat.c b/libc/upstream-openbsd/lib/libc/string/strlcat.c
deleted file mode 100644
index aa3db7ab3..000000000
--- a/libc/upstream-openbsd/lib/libc/string/strlcat.c
+++ /dev/null
@@ -1,56 +0,0 @@
-/*	$OpenBSD: strlcat.c,v 1.19 2019/01/25 00:19:25 millert Exp $	*/
-
-/*
- * Copyright (c) 1998, 2015 Todd C. Miller <millert@openbsd.org>
- *
- * Permission to use, copy, modify, and distribute this software for any
- * purpose with or without fee is hereby granted, provided that the above
- * copyright notice and this permission notice appear in all copies.
- *
- * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
- * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
- * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
- * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
- * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
- * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
- * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
- */
-
-#include <sys/types.h>
-#include <string.h>
-
-/*
- * Appends src to string dst of size dsize (unlike strncat, dsize is the
- * full size of dst, not space left).  At most dsize-1 characters
- * will be copied.  Always NUL terminates (unless dsize <= strlen(dst)).
- * Returns strlen(src) + MIN(dsize, strlen(initial dst)).
- * If retval >= dsize, truncation occurred.
- */
-size_t
-strlcat(char *dst, const char *src, size_t dsize)
-{
-	const char *odst = dst;
-	const char *osrc = src;
-	size_t n = dsize;
-	size_t dlen;
-
-	/* Find the end of dst and adjust bytes left but don't go past end. */
-	while (n-- != 0 && *dst != '\0')
-		dst++;
-	dlen = dst - odst;
-	n = dsize - dlen;
-
-	if (n-- == 0)
-		return(dlen + strlen(src));
-	while (*src != '\0') {
-		if (n != 0) {
-			*dst++ = *src;
-			n--;
-		}
-		src++;
-	}
-	*dst = '\0';
-
-	return(dlen + (src - osrc));	/* count does not include NUL */
-}
-DEF_WEAK(strlcat);
diff --git a/libc/upstream-openbsd/lib/libc/string/strlcpy.c b/libc/upstream-openbsd/lib/libc/string/strlcpy.c
deleted file mode 100644
index 7e3b9aef6..000000000
--- a/libc/upstream-openbsd/lib/libc/string/strlcpy.c
+++ /dev/null
@@ -1,51 +0,0 @@
-/*	$OpenBSD: strlcpy.c,v 1.16 2019/01/25 00:19:25 millert Exp $	*/
-
-/*
- * Copyright (c) 1998, 2015 Todd C. Miller <millert@openbsd.org>
- *
- * Permission to use, copy, modify, and distribute this software for any
- * purpose with or without fee is hereby granted, provided that the above
- * copyright notice and this permission notice appear in all copies.
- *
- * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
- * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
- * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
- * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
- * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
- * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
- * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
- */
-
-#include <sys/types.h>
-#include <string.h>
-
-/*
- * Copy string src to buffer dst of size dsize.  At most dsize-1
- * chars will be copied.  Always NUL terminates (unless dsize == 0).
- * Returns strlen(src); if retval >= dsize, truncation occurred.
- */
-size_t
-strlcpy(char *dst, const char *src, size_t dsize)
-{
-	const char *osrc = src;
-	size_t nleft = dsize;
-
-	/* Copy as many bytes as will fit. */
-	if (nleft != 0) {
-		while (--nleft != 0) {
-			if ((*dst++ = *src++) == '\0')
-				break;
-		}
-	}
-
-	/* Not enough room in dst, add NUL and traverse rest of src. */
-	if (nleft == 0) {
-		if (dsize != 0)
-			*dst = '\0';		/* NUL-terminate dst */
-		while (*src++)
-			;
-	}
-
-	return(src - osrc - 1);	/* count does not include NUL */
-}
-DEF_WEAK(strlcpy);
diff --git a/libdl/libdl_android.cpp b/libdl/libdl_android.cpp
index 47a164abb..f0959ebf9 100644
--- a/libdl/libdl_android.cpp
+++ b/libdl/libdl_android.cpp
@@ -59,6 +59,9 @@ void __loader_android_dlwarning(void* obj, void (*f)(void*, const char*));
 __attribute__((__weak__, visibility("default")))
 struct android_namespace_t* __loader_android_get_exported_namespace(const char* name);
 
+__attribute__((__weak__, visibility("default"))) void __loader_android_set_16kb_appcompat_mode(
+    bool enable_app_compat);
+
 // Proxy calls to bionic loader
 __attribute__((__weak__))
 void android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size) {
@@ -115,4 +118,8 @@ struct android_namespace_t* android_get_exported_namespace(const char* name) {
   return __loader_android_get_exported_namespace(name);
 }
 
+__attribute__((__weak__)) void android_set_16kb_appcompat_mode(bool enable_app_compat) {
+  __loader_android_set_16kb_appcompat_mode(enable_app_compat);
+}
+
 } // extern "C"
diff --git a/libdl/libdl_android.map.txt b/libdl/libdl_android.map.txt
index 7afcd9c6f..efbc841fc 100644
--- a/libdl/libdl_android.map.txt
+++ b/libdl/libdl_android.map.txt
@@ -24,6 +24,7 @@ LIBDL_ANDROID {
     android_init_anonymous_namespace; # apex
     android_link_namespaces; # apex
     android_set_application_target_sdk_version; # apex
+    android_set_16kb_appcompat_mode; #apex
   local:
     *;
 };
diff --git a/linker/Android.bp b/linker/Android.bp
index 563cf3d17..4863b9207 100644
--- a/linker/Android.bp
+++ b/linker/Android.bp
@@ -108,6 +108,12 @@ cc_defaults {
 
     // We need to access Bionic private headers in the linker.
     include_dirs: ["bionic/libc"],
+
+    sanitize: {
+        // Supporting memtag_globals in the linker would be tricky,
+        // because it relocates itself very early.
+        memtag_globals: false,
+    },
 }
 
 // ========================================================
@@ -184,6 +190,7 @@ filegroup {
         "linker_mapped_file_fragment.cpp",
         "linker_note_gnu_property.cpp",
         "linker_phdr.cpp",
+        "linker_phdr_16kib_compat.cpp",
         "linker_relocate.cpp",
         "linker_sdk_versions.cpp",
         "linker_soinfo.cpp",
@@ -493,6 +500,7 @@ cc_test {
         "linker_mapped_file_fragment.cpp",
         "linker_sdk_versions.cpp",
         "linker_dlwarning.cpp",
+        "linker_phdr_16kib_compat.cpp"
     ],
 
     static_libs: [
diff --git a/linker/dlfcn.cpp b/linker/dlfcn.cpp
index fee19f4a9..f811d6d17 100644
--- a/linker/dlfcn.cpp
+++ b/linker/dlfcn.cpp
@@ -89,6 +89,7 @@ void* __loader_dlvsym(void* handle,
                       const void* caller_addr) __LINKER_PUBLIC__;
 void __loader_add_thread_local_dtor(void* dso_handle) __LINKER_PUBLIC__;
 void __loader_remove_thread_local_dtor(void* dso_handle) __LINKER_PUBLIC__;
+void __loader_android_set_16kb_appcompat_mode(bool enable_app_compat) __LINKER_PUBLIC__;
 libc_shared_globals* __loader_shared_globals() __LINKER_PUBLIC__;
 #if defined(__arm__)
 _Unwind_Ptr __loader_dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) __LINKER_PUBLIC__;
@@ -301,6 +302,11 @@ void __loader_remove_thread_local_dtor(void* dso_handle) {
   decrement_dso_handle_reference_counter(dso_handle);
 }
 
+void __loader_android_set_16kb_appcompat_mode(bool enable_app_compat) {
+  ScopedPthreadMutexLocker locker(&g_dl_mutex);
+  set_16kb_appcompat_mode(enable_app_compat);
+}
+
 libc_shared_globals* __loader_shared_globals() {
   return __libc_shared_globals();
 }
@@ -331,6 +337,7 @@ soinfo* get_libdl_info(const soinfo& linker_si) {
     __libdl_info->gnu_bloom_filter_ = linker_si.gnu_bloom_filter_;
     __libdl_info->gnu_bucket_ = linker_si.gnu_bucket_;
     __libdl_info->gnu_chain_ = linker_si.gnu_chain_;
+    __libdl_info->memtag_dynamic_entries_ = linker_si.memtag_dynamic_entries_;
 
     __libdl_info->ref_count_ = 1;
     __libdl_info->strtab_size_ = linker_si.strtab_size_;
diff --git a/linker/ld_android.cpp b/linker/ld_android.cpp
index 1c031066e..c938a16ef 100644
--- a/linker/ld_android.cpp
+++ b/linker/ld_android.cpp
@@ -55,6 +55,7 @@ __strong_alias(__loader_dlvsym, __internal_linker_error);
 __strong_alias(__loader_add_thread_local_dtor, __internal_linker_error);
 __strong_alias(__loader_remove_thread_local_dtor, __internal_linker_error);
 __strong_alias(__loader_shared_globals, __internal_linker_error);
+__strong_alias(__loader_android_set_16kb_appcompat_mode, __internal_linker_error);
 #if defined(__arm__)
 __strong_alias(__loader_dl_unwind_find_exidx, __internal_linker_error);
 #endif
diff --git a/linker/linker.arm.map b/linker/linker.arm.map
index b805cd654..edfa24928 100644
--- a/linker/linker.arm.map
+++ b/linker/linker.arm.map
@@ -25,6 +25,7 @@
     __loader_shared_globals;
     rtld_db_dlactivity;
     __loader_android_handle_signal;
+    __loader_android_set_16kb_appcompat_mode;
   local:
     *;
 };
diff --git a/linker/linker.cpp b/linker/linker.cpp
index bcc25000f..8f7891558 100644
--- a/linker/linker.cpp
+++ b/linker/linker.cpp
@@ -51,6 +51,7 @@
 #include <android-base/scopeguard.h>
 #include <async_safe/log.h>
 #include <bionic/pthread_internal.h>
+#include <platform/bionic/mte.h>
 
 // Private C library headers.
 
@@ -640,6 +641,11 @@ class LoadTask {
     si_->set_gap_start(elf_reader.gap_start());
     si_->set_gap_size(elf_reader.gap_size());
     si_->set_should_pad_segments(elf_reader.should_pad_segments());
+    si_->set_should_use_16kib_app_compat(elf_reader.should_use_16kib_app_compat());
+    if (si_->should_use_16kib_app_compat()) {
+      si_->set_compat_relro_start(elf_reader.compat_relro_start());
+      si_->set_compat_relro_size(elf_reader.compat_relro_size());
+    }
 
     return true;
   }
@@ -1692,16 +1698,24 @@ bool find_libraries(android_namespace_t* ns,
     }
   }
 
+  // The WebView loader uses RELRO sharing in order to promote page sharing of the large RELRO
+  // segment, as it's full of C++ vtables. Because MTE globals, by default, applies random tags to
+  // each global variable, the RELRO segment is polluted and unique for each process. In order to
+  // allow sharing, but still provide some protection, we use deterministic global tagging schemes
+  // for DSOs that are loaded through android_dlopen_ext, such as those loaded by WebView.
+  bool dlext_use_relro =
+      extinfo && extinfo->flags & (ANDROID_DLEXT_WRITE_RELRO | ANDROID_DLEXT_USE_RELRO);
+
   // Step 3: pre-link all DT_NEEDED libraries in breadth first order.
   bool any_memtag_stack = false;
   for (auto&& task : load_tasks) {
     soinfo* si = task->get_soinfo();
-    if (!si->is_linked() && !si->prelink_image()) {
+    if (!si->is_linked() && !si->prelink_image(dlext_use_relro)) {
       return false;
     }
     // si->memtag_stack() needs to be called after si->prelink_image() which populates
     // the dynamic section.
-    if (si->has_min_version(7) && si->memtag_stack()) {
+    if (si->memtag_stack()) {
       any_memtag_stack = true;
       LD_LOG(kLogDlopen,
              "... load_library requesting stack MTE for: realpath=\"%s\", soname=\"%s\"",
@@ -1715,7 +1729,7 @@ bool find_libraries(android_namespace_t* ns,
     } else {
       // find_library is used by the initial linking step, so we communicate that we
       // want memtag_stack enabled to __libc_init_mte.
-      __libc_shared_globals()->initial_memtag_stack = true;
+      __libc_shared_globals()->initial_memtag_stack_abi = true;
     }
   }
 
@@ -2356,7 +2370,7 @@ bool do_dlsym(void* handle,
         void* tls_block = get_tls_block_for_this_thread(tls_module, /*should_alloc=*/true);
         *symbol = static_cast<char*>(tls_block) + sym->st_value;
       } else {
-        *symbol = reinterpret_cast<void*>(found->resolve_symbol_address(sym));
+        *symbol = get_tagged_address(reinterpret_cast<void*>(found->resolve_symbol_address(sym)));
       }
       failure_guard.Disable();
       LD_LOG(kLogDlsym,
@@ -2786,15 +2800,25 @@ bool soinfo::lookup_version_info(const VersionTracker& version_tracker, ElfW(Wor
   return true;
 }
 
-static void apply_relr_reloc(ElfW(Addr) offset, ElfW(Addr) load_bias) {
-  ElfW(Addr) address = offset + load_bias;
-  *reinterpret_cast<ElfW(Addr)*>(address) += load_bias;
+static void apply_relr_reloc(ElfW(Addr) offset, ElfW(Addr) load_bias, bool has_memtag_globals) {
+  ElfW(Addr) destination = offset + load_bias;
+  if (!has_memtag_globals) {
+    *reinterpret_cast<ElfW(Addr)*>(destination) += load_bias;
+    return;
+  }
+
+  ElfW(Addr)* tagged_destination =
+      reinterpret_cast<ElfW(Addr)*>(get_tagged_address(reinterpret_cast<void*>(destination)));
+  ElfW(Addr) tagged_value = reinterpret_cast<ElfW(Addr)>(
+      get_tagged_address(reinterpret_cast<void*>(*tagged_destination + load_bias)));
+  *tagged_destination = tagged_value;
 }
 
 // Process relocations in SHT_RELR section (experimental).
 // Details of the encoding are described in this post:
 //   https://groups.google.com/d/msg/generic-abi/bX460iggiKg/Pi9aSwwABgAJ
-bool relocate_relr(const ElfW(Relr)* begin, const ElfW(Relr)* end, ElfW(Addr) load_bias) {
+bool relocate_relr(const ElfW(Relr) * begin, const ElfW(Relr) * end, ElfW(Addr) load_bias,
+                   bool has_memtag_globals) {
   constexpr size_t wordsize = sizeof(ElfW(Addr));
 
   ElfW(Addr) base = 0;
@@ -2805,7 +2829,7 @@ bool relocate_relr(const ElfW(Relr)* begin, const ElfW(Relr)* end, ElfW(Addr) lo
     if ((entry&1) == 0) {
       // Even entry: encodes the offset for next relocation.
       offset = static_cast<ElfW(Addr)>(entry);
-      apply_relr_reloc(offset, load_bias);
+      apply_relr_reloc(offset, load_bias, has_memtag_globals);
       // Set base offset for subsequent bitmap entries.
       base = offset + wordsize;
       continue;
@@ -2816,7 +2840,7 @@ bool relocate_relr(const ElfW(Relr)* begin, const ElfW(Relr)* end, ElfW(Addr) lo
     while (entry != 0) {
       entry >>= 1;
       if ((entry&1) != 0) {
-        apply_relr_reloc(offset, load_bias);
+        apply_relr_reloc(offset, load_bias, has_memtag_globals);
       }
       offset += wordsize;
     }
@@ -2831,7 +2855,7 @@ bool relocate_relr(const ElfW(Relr)* begin, const ElfW(Relr)* end, ElfW(Addr) lo
 // An empty list of soinfos
 static soinfo_list_t g_empty_list;
 
-bool soinfo::prelink_image() {
+bool soinfo::prelink_image(bool dlext_use_relro) {
   if (flags_ & FLAG_PRELINKED) return true;
   /* Extract dynamic section */
   ElfW(Word) dynamic_flags = 0;
@@ -3320,6 +3344,18 @@ bool soinfo::prelink_image() {
   // it each time we look up a symbol with a version.
   if (!validate_verdef_section(this)) return false;
 
+  // MTE globals requires remapping data segments with PROT_MTE as anonymous mappings, because file
+  // based mappings may not be backed by tag-capable memory (see "MAP_ANONYMOUS" on
+  // https://www.kernel.org/doc/html/latest/arch/arm64/memory-tagging-extension.html). This is only
+  // done if the binary has MTE globals (evidenced by the dynamic table entries), as it destroys
+  // page sharing. It's also only done on devices that support MTE, because the act of remapping
+  // pages is unnecessary on non-MTE devices (where we might still run MTE-globals enabled code).
+  if (should_tag_memtag_globals() &&
+      remap_memtag_globals_segments(phdr, phnum, base) == 0) {
+    tag_globals(dlext_use_relro);
+    protect_memtag_globals_ro_segments(phdr, phnum, base);
+  }
+
   flags_ |= FLAG_PRELINKED;
   return true;
 }
@@ -3361,7 +3397,8 @@ bool soinfo::link_image(const SymbolLookupList& lookup_list, soinfo* local_group
                               "\"%s\" has text relocations",
                               get_realpath());
     add_dlwarning(get_realpath(), "text relocations");
-    if (phdr_table_unprotect_segments(phdr, phnum, load_bias, should_pad_segments_) < 0) {
+    if (phdr_table_unprotect_segments(phdr, phnum, load_bias, should_pad_segments_,
+                                      should_use_16kib_app_compat_) < 0) {
       DL_ERR("can't unprotect loadable segments for \"%s\": %m", get_realpath());
       return false;
     }
@@ -3377,7 +3414,8 @@ bool soinfo::link_image(const SymbolLookupList& lookup_list, soinfo* local_group
 #if !defined(__LP64__)
   if (has_text_relocations) {
     // All relocations are done, we can protect our segments back to read-only.
-    if (phdr_table_protect_segments(phdr, phnum, load_bias, should_pad_segments_) < 0) {
+    if (phdr_table_protect_segments(phdr, phnum, load_bias, should_pad_segments_,
+                                    should_use_16kib_app_compat_) < 0) {
       DL_ERR("can't protect segments for \"%s\": %m", get_realpath());
       return false;
     }
@@ -3390,6 +3428,13 @@ bool soinfo::link_image(const SymbolLookupList& lookup_list, soinfo* local_group
     return false;
   }
 
+  if (should_tag_memtag_globals()) {
+    std::list<std::string>* vma_names_ptr = vma_names();
+    // should_tag_memtag_globals -> __aarch64__ -> vma_names() != nullptr
+    CHECK(vma_names_ptr);
+    name_memtag_globals_segments(phdr, phnum, base, get_realpath(), vma_names_ptr);
+  }
+
   /* Handle serializing/sharing the RELRO segment */
   if (extinfo && (extinfo->flags & ANDROID_DLEXT_WRITE_RELRO)) {
     if (phdr_table_serialize_gnu_relro(phdr, phnum, load_bias,
@@ -3412,13 +3457,70 @@ bool soinfo::link_image(const SymbolLookupList& lookup_list, soinfo* local_group
 }
 
 bool soinfo::protect_relro() {
-  if (phdr_table_protect_gnu_relro(phdr, phnum, load_bias, should_pad_segments_) < 0) {
-    DL_ERR("can't enable GNU RELRO protection for \"%s\": %m", get_realpath());
-    return false;
+  if (should_use_16kib_app_compat_) {
+    if (phdr_table_protect_gnu_relro_16kib_compat(compat_relro_start_, compat_relro_size_) < 0) {
+      DL_ERR("can't enable COMPAT GNU RELRO protection for \"%s\": %s", get_realpath(),
+             strerror(errno));
+      return false;
+    }
+  } else {
+    if (phdr_table_protect_gnu_relro(phdr, phnum, load_bias, should_pad_segments_,
+                                     should_use_16kib_app_compat_) < 0) {
+      DL_ERR("can't enable GNU RELRO protection for \"%s\": %m", get_realpath());
+      return false;
+    }
   }
   return true;
 }
 
+// https://github.com/ARM-software/abi-aa/blob/main/memtagabielf64/memtagabielf64.rst#global-variable-tagging
+void soinfo::tag_globals(bool dlext_use_relro) {
+  if (is_linked()) return;
+  if (flags_ & FLAG_GLOBALS_TAGGED) return;
+  flags_ |= FLAG_GLOBALS_TAGGED;
+
+  constexpr size_t kTagGranuleSize = 16;
+  const uint8_t* descriptor_stream = reinterpret_cast<const uint8_t*>(memtag_globals());
+
+  if (memtag_globalssz() == 0) {
+    DL_ERR("Invalid memtag descriptor pool size: %zu", memtag_globalssz());
+  }
+
+  uint64_t addr = load_bias;
+  uleb128_decoder decoder(descriptor_stream, memtag_globalssz());
+  // Don't ever generate tag zero, to easily distinguish between tagged and
+  // untagged globals in register/tag dumps.
+  uint64_t last_tag_mask = 1;
+  uint64_t last_tag = 1;
+  constexpr uint64_t kDistanceReservedBits = 3;
+
+  while (decoder.has_bytes()) {
+    uint64_t value = decoder.pop_front();
+    uint64_t distance = (value >> kDistanceReservedBits) * kTagGranuleSize;
+    uint64_t ngranules = value & ((1 << kDistanceReservedBits) - 1);
+    if (ngranules == 0) {
+      ngranules = decoder.pop_front() + 1;
+    }
+
+    addr += distance;
+    void* tagged_addr;
+    if (dlext_use_relro) {
+      tagged_addr = reinterpret_cast<void*>(addr | (last_tag++ << 56));
+      if (last_tag > (1 << kTagGranuleSize)) last_tag = 1;
+    } else {
+      tagged_addr = insert_random_tag(reinterpret_cast<void*>(addr), last_tag_mask);
+      uint64_t tag = (reinterpret_cast<uint64_t>(tagged_addr) >> 56) & 0x0f;
+      last_tag_mask = 1 | (1 << tag);
+    }
+
+    for (size_t k = 0; k < ngranules; k++) {
+      auto* granule = static_cast<uint8_t*>(tagged_addr) + k * kTagGranuleSize;
+      set_memory_tag(static_cast<void*>(granule));
+    }
+    addr += ngranules * kTagGranuleSize;
+  }
+}
+
 static std::vector<android_namespace_t*> init_default_namespace_no_config(bool is_asan, bool is_hwasan) {
   g_default_namespace.set_isolated(false);
   auto default_ld_paths = is_asan ? kAsanDefaultLdPaths : (
diff --git a/linker/linker.generic.map b/linker/linker.generic.map
index 4d7f2363d..2beae65ea 100644
--- a/linker/linker.generic.map
+++ b/linker/linker.generic.map
@@ -24,6 +24,7 @@
     __loader_shared_globals;
     rtld_db_dlactivity;
     __loader_android_handle_signal;
+    __loader_android_set_16kb_appcompat_mode;
   local:
     *;
 };
diff --git a/linker/linker.h b/linker/linker.h
index ac2222d47..7afa0d730 100644
--- a/linker/linker.h
+++ b/linker/linker.h
@@ -108,6 +108,9 @@ int get_application_target_sdk_version();
 
 bool get_transparent_hugepages_supported();
 
+void set_16kb_appcompat_mode(bool enable_app_compat);
+bool get_16kb_appcompat_mode();
+
 enum {
   /* A regular namespace is the namespace with a custom search path that does
    * not impose any restrictions on the location of native libraries.
@@ -179,7 +182,8 @@ struct address_space_params {
 int get_application_target_sdk_version();
 ElfW(Versym) find_verdef_version_index(const soinfo* si, const version_info* vi);
 bool validate_verdef_section(const soinfo* si);
-bool relocate_relr(const ElfW(Relr)* begin, const ElfW(Relr)* end, ElfW(Addr) load_bias);
+bool relocate_relr(const ElfW(Relr) * begin, const ElfW(Relr) * end, ElfW(Addr) load_bias,
+                   bool has_memtag_globals);
 
 struct platform_properties {
 #if defined(__aarch64__)
diff --git a/linker/linker_main.cpp b/linker/linker_main.cpp
index 6ccd75b40..f65f82d5b 100644
--- a/linker/linker_main.cpp
+++ b/linker/linker_main.cpp
@@ -46,6 +46,7 @@
 #include "linker_tls.h"
 #include "linker_utils.h"
 
+#include "platform/bionic/macros.h"
 #include "private/KernelArgumentBlock.h"
 #include "private/bionic_call_ifunc_resolver.h"
 #include "private/bionic_globals.h"
@@ -71,7 +72,9 @@ static void get_elf_base_from_phdr(const ElfW(Phdr)* phdr_table, size_t phdr_cou
 static void set_bss_vma_name(soinfo* si);
 
 void __libc_init_mte(const memtag_dynamic_entries_t* memtag_dynamic_entries, const void* phdr_start,
-                     size_t phdr_count, uintptr_t load_bias, void* stack_top);
+                     size_t phdr_count, uintptr_t load_bias);
+
+void __libc_init_mte_stack(void* stack_top);
 
 static void __linker_cannot_link(const char* argv0) {
   __linker_error("CANNOT LINK EXECUTABLE \"%s\": %s", argv0, linker_get_error_buffer());
@@ -365,13 +368,16 @@ static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load
   init_link_map_head(*solinker);
 
 #if defined(__aarch64__)
+  __libc_init_mte(somain->memtag_dynamic_entries(), somain->phdr, somain->phnum, somain->load_bias);
+
   if (exe_to_load == nullptr) {
     // Kernel does not add PROT_BTI to executable pages of the loaded ELF.
     // Apply appropriate protections here if it is needed.
     auto note_gnu_property = GnuPropertySection(somain);
     if (note_gnu_property.IsBTICompatible() &&
-        (phdr_table_protect_segments(somain->phdr, somain->phnum, somain->load_bias,
-                                     somain->should_pad_segments(), &note_gnu_property) < 0)) {
+        (phdr_table_protect_segments(
+             somain->phdr, somain->phnum, somain->load_bias, somain->should_pad_segments(),
+             somain->should_use_16kib_app_compat(), &note_gnu_property) < 0)) {
       __linker_error("error: can't protect segments for \"%s\": %m", exe_info.path.c_str());
     }
   }
@@ -464,8 +470,7 @@ static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load
 #if defined(__aarch64__)
   // This has to happen after the find_libraries, which will have collected any possible
   // libraries that request memtag_stack in the dynamic section.
-  __libc_init_mte(somain->memtag_dynamic_entries(), somain->phdr, somain->phnum, somain->load_bias,
-                  args.argv);
+  __libc_init_mte_stack(args.argv);
 #endif
 
   linker_finalize_static_tls();
@@ -624,8 +629,13 @@ static void relocate_linker() {
     // Apply RELR relocations first so that the GOT is initialized for ifunc
     // resolvers.
     if (relr && relrsz) {
+      // Nothing has tagged the memtag globals here, so it is pointless either
+      // way to handle them, the tags will be zero anyway.
+      // That is moot though, because the linker does not use memtag_globals
+      // in the first place.
       relocate_relr(reinterpret_cast<ElfW(Relr*)>(ehdr + relr),
-                    reinterpret_cast<ElfW(Relr*)>(ehdr + relr + relrsz), ehdr);
+                    reinterpret_cast<ElfW(Relr*)>(ehdr + relr + relrsz), ehdr,
+                    /*has_memtag_globals=*/ false);
     }
     if (pltrel && pltrelsz) {
       call_ifunc_resolvers_for_section(reinterpret_cast<RelType*>(ehdr + pltrel),
@@ -645,6 +655,16 @@ static void linker_memclr(void* dst, size_t cnt) {
   }
 }
 
+// Remapping MTE globals segments happens before the linker relocates itself, and so can't use
+// memcpy() from string.h. This function is compiled with -ffreestanding.
+void linker_memcpy(void* dst, const void* src, size_t n) {
+  char* dst_bytes = reinterpret_cast<char*>(dst);
+  const char* src_bytes = reinterpret_cast<const char*>(src);
+  for (size_t i = 0; i < n; ++i) {
+    dst_bytes[i] = src_bytes[i];
+  }
+}
+
 // Detect an attempt to run the linker on itself. e.g.:
 //   /system/bin/linker64 /system/bin/linker64
 // Use priority-1 to run this constructor before other constructors.
@@ -722,6 +742,8 @@ extern "C" ElfW(Addr) __linker_init(void* raw_args) {
   tmp_linker_so.set_linker_flag();
 
   if (!tmp_linker_so.prelink_image()) __linker_cannot_link(args.argv[0]);
+  // There is special logic in soinfo::relocate to avoid duplicating the
+  // relocations we did in relocate_linker().
   if (!tmp_linker_so.link_image(SymbolLookupList(&tmp_linker_so), &tmp_linker_so, nullptr, nullptr)) __linker_cannot_link(args.argv[0]);
 
   return __linker_init_post_relocation(args, tmp_linker_so);
diff --git a/linker/linker_main.h b/linker/linker_main.h
index 724f43c14..ffbcf0f73 100644
--- a/linker/linker_main.h
+++ b/linker/linker_main.h
@@ -70,3 +70,5 @@ bool solist_remove_soinfo(soinfo* si);
 soinfo* solist_get_head();
 soinfo* solist_get_somain();
 soinfo* solist_get_vdso();
+
+void linker_memcpy(void* dst, const void* src, size_t n);
diff --git a/linker/linker_phdr.cpp b/linker/linker_phdr.cpp
index b7db4cd62..e5369ac61 100644
--- a/linker/linker_phdr.cpp
+++ b/linker/linker_phdr.cpp
@@ -37,9 +37,12 @@
 #include <unistd.h>
 
 #include "linker.h"
+#include "linker_debug.h"
 #include "linker_dlwarning.h"
 #include "linker_globals.h"
-#include "linker_debug.h"
+#include "linker_logger.h"
+#include "linker_main.h"
+#include "linker_soinfo.h"
 #include "linker_utils.h"
 
 #include "private/bionic_asm_note.h"
@@ -47,6 +50,7 @@
 #include "private/elf_note.h"
 
 #include <android-base/file.h>
+#include <android-base/properties.h>
 
 static int GetTargetElfMachine() {
 #if defined(__arm__)
@@ -139,11 +143,6 @@ static int GetTargetElfMachine() {
 
  **/
 
-#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
-#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
-                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
-                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
-
 static const size_t kPageSize = page_size();
 
 /*
@@ -182,6 +181,15 @@ bool ElfReader::Read(const char* name, int fd, off64_t file_offset, off64_t file
     did_read_ = true;
   }
 
+  if (kPageSize == 0x4000 && phdr_table_get_minimum_alignment(phdr_table_, phdr_num_) == 0x1000) {
+    // This prop needs to be read on 16KiB devices for each ELF where min_palign is 4KiB.
+    // It cannot be cached since the developer may toggle app compat on/off.
+    // This check will be removed once app compat is made the default on 16KiB devices.
+    should_use_16kib_app_compat_ =
+        ::android::base::GetBoolProperty("bionic.linker.16kb.app_compat.enabled", false) ||
+        get_16kb_appcompat_mode();
+  }
+
   return did_read_;
 }
 
@@ -197,8 +205,9 @@ bool ElfReader::Load(address_space_params* address_space) {
 #if defined(__aarch64__)
     // For Armv8.5-A loaded executable segments may require PROT_BTI.
     if (note_gnu_property_.IsBTICompatible()) {
-      did_load_ = (phdr_table_protect_segments(phdr_table_, phdr_num_, load_bias_,
-                                               should_pad_segments_, &note_gnu_property_) == 0);
+      did_load_ =
+          (phdr_table_protect_segments(phdr_table_, phdr_num_, load_bias_, should_pad_segments_,
+                                       should_use_16kib_app_compat_, &note_gnu_property_) == 0);
     }
 #endif
   }
@@ -690,6 +699,13 @@ bool ElfReader::ReserveAddressSpace(address_space_params* address_space) {
     return false;
   }
 
+  if (should_use_16kib_app_compat_) {
+    // Reserve additional space for aligning the permission boundary in compat loading
+    // Up to kPageSize-kCompatPageSize additional space is needed, but reservation
+    // is done with mmap which gives kPageSize multiple-sized reservations.
+    load_size_ += kPageSize;
+  }
+
   uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);
   void* start;
 
@@ -725,13 +741,21 @@ bool ElfReader::ReserveAddressSpace(address_space_params* address_space) {
 
   load_start_ = start;
   load_bias_ = reinterpret_cast<uint8_t*>(start) - addr;
+
+  if (should_use_16kib_app_compat_) {
+    // In compat mode make the initial mapping RW since the ELF contents will be read
+    // into it; instead of mapped over it.
+    mprotect(reinterpret_cast<void*>(start), load_size_, PROT_READ | PROT_WRITE);
+  }
+
   return true;
 }
 
 /*
- * Returns true if the kernel supports page size migration, else false.
+ * Returns true if the kernel supports page size migration for this process.
  */
 bool page_size_migration_supported() {
+#if defined(__LP64__)
   static bool pgsize_migration_enabled = []() {
     std::string enabled;
     if (!android::base::ReadFileToString("/sys/kernel/mm/pgsize_migration/enabled", &enabled)) {
@@ -740,6 +764,9 @@ bool page_size_migration_supported() {
     return enabled.find("1") != std::string::npos;
   }();
   return pgsize_migration_enabled;
+#else
+  return false;
+#endif
 }
 
 // Find the ELF note of type NT_ANDROID_TYPE_PAD_SEGMENT and check that the desc value is 1.
@@ -808,8 +835,15 @@ bool ElfReader::ReadPadSegmentNote() {
 }
 
 static inline void _extend_load_segment_vma(const ElfW(Phdr)* phdr_table, size_t phdr_count,
-                                             size_t phdr_idx, ElfW(Addr)* p_memsz,
-                                             ElfW(Addr)* p_filesz, bool should_pad_segments) {
+                                            size_t phdr_idx, ElfW(Addr)* p_memsz,
+                                            ElfW(Addr)* p_filesz, bool should_pad_segments,
+                                            bool should_use_16kib_app_compat) {
+  // NOTE: Segment extension is only applicable where the ELF's max-page-size > runtime page size;
+  // to save kernel VMA slab memory. 16KiB compat mode is the exact opposite scenario.
+  if (should_use_16kib_app_compat) {
+    return;
+  }
+
   const ElfW(Phdr)* phdr = &phdr_table[phdr_idx];
   const ElfW(Phdr)* next = nullptr;
   size_t next_idx = phdr_idx + 1;
@@ -879,6 +913,13 @@ bool ElfReader::MapSegment(size_t seg_idx, size_t len) {
 }
 
 void ElfReader::ZeroFillSegment(const ElfW(Phdr)* phdr) {
+  // NOTE: In 16KiB app compat mode, the ELF mapping is anonymous, meaning that
+  // RW segments are COW-ed from the kernel's zero page. So there is no need to
+  // explicitly zero-fill until the last page's limit.
+  if (should_use_16kib_app_compat_) {
+    return;
+  }
+
   ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
   uint64_t unextended_seg_file_end = seg_start + phdr->p_filesz;
 
@@ -898,6 +939,12 @@ void ElfReader::ZeroFillSegment(const ElfW(Phdr)* phdr) {
 }
 
 void ElfReader::DropPaddingPages(const ElfW(Phdr)* phdr, uint64_t seg_file_end) {
+  // NOTE: Padding pages are only applicable where the ELF's max-page-size > runtime page size;
+  // 16KiB compat mode is the exact opposite scenario.
+  if (should_use_16kib_app_compat_) {
+    return;
+  }
+
   ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
   uint64_t unextended_seg_file_end = seg_start + phdr->p_filesz;
 
@@ -926,6 +973,12 @@ void ElfReader::DropPaddingPages(const ElfW(Phdr)* phdr, uint64_t seg_file_end)
 
 bool ElfReader::MapBssSection(const ElfW(Phdr)* phdr, ElfW(Addr) seg_page_end,
                               ElfW(Addr) seg_file_end) {
+  // NOTE: We do not need to handle .bss in 16KiB compat mode since the mapping
+  // reservation is anonymous and RW to begin with.
+  if (should_use_16kib_app_compat_) {
+    return true;
+  }
+
   // seg_file_end is now the first page address after the file content.
   seg_file_end = page_end(seg_file_end);
 
@@ -952,15 +1005,27 @@ bool ElfReader::MapBssSection(const ElfW(Phdr)* phdr, ElfW(Addr) seg_page_end,
 }
 
 bool ElfReader::LoadSegments() {
+  // NOTE: The compat(legacy) page size (4096) must be used when aligning
+  // the 4KiB segments for loading in compat mode. The larger 16KiB page size
+  // will lead to overwriting adjacent segments since the ELF's segment(s)
+  // are not 16KiB aligned.
+  size_t seg_align = should_use_16kib_app_compat_ ? kCompatPageSize : kPageSize;
+
   size_t min_palign = phdr_table_get_minimum_alignment(phdr_table_, phdr_num_);
-  // Only enforce this on 16 KB systems. Apps may rely on undefined behavior
-  // here on 4 KB systems, which is the norm before this change is introduced.
-  if (kPageSize >= 16384 && min_palign < kPageSize) {
+  // Only enforce this on 16 KB systems with app compat disabled.
+  // Apps may rely on undefined behavior here on 4 KB systems,
+  // which is the norm before this change is introduced
+  if (kPageSize >= 16384 && min_palign < kPageSize && !should_use_16kib_app_compat_) {
     DL_ERR("\"%s\" program alignment (%zu) cannot be smaller than system page size (%zu)",
            name_.c_str(), min_palign, kPageSize);
     return false;
   }
 
+  if (!Setup16KiBAppCompat()) {
+    DL_ERR("\"%s\" failed to setup 16KiB App Compat", name_.c_str());
+    return false;
+  }
+
   for (size_t i = 0; i < phdr_num_; ++i) {
     const ElfW(Phdr)* phdr = &phdr_table_[i];
 
@@ -970,13 +1035,14 @@ bool ElfReader::LoadSegments() {
 
     ElfW(Addr) p_memsz = phdr->p_memsz;
     ElfW(Addr) p_filesz = phdr->p_filesz;
-    _extend_load_segment_vma(phdr_table_, phdr_num_, i, &p_memsz, &p_filesz, should_pad_segments_);
+    _extend_load_segment_vma(phdr_table_, phdr_num_, i, &p_memsz, &p_filesz, should_pad_segments_,
+                             should_use_16kib_app_compat_);
 
     // Segment addresses in memory.
     ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
     ElfW(Addr) seg_end = seg_start + p_memsz;
 
-    ElfW(Addr) seg_page_end = page_end(seg_end);
+    ElfW(Addr) seg_page_end = align_up(seg_end, seg_align);
 
     ElfW(Addr) seg_file_end = seg_start + p_filesz;
 
@@ -984,7 +1050,7 @@ bool ElfReader::LoadSegments() {
     ElfW(Addr) file_start = phdr->p_offset;
     ElfW(Addr) file_end = file_start + p_filesz;
 
-    ElfW(Addr) file_page_start = page_start(file_start);
+    ElfW(Addr) file_page_start = align_down(file_start, seg_align);
     ElfW(Addr) file_length = file_end - file_page_start;
 
     if (file_size_ <= 0) {
@@ -1017,8 +1083,14 @@ bool ElfReader::LoadSegments() {
       }
 
       // Pass the file_length, since it may have been extended by _extend_load_segment_vma().
-      if (!MapSegment(i, file_length)) {
-        return false;
+      if (should_use_16kib_app_compat_) {
+        if (!CompatMapSegment(i, file_length)) {
+          return false;
+        }
+      } else {
+        if (!MapSegment(i, file_length)) {
+          return false;
+        }
       }
     }
 
@@ -1039,7 +1111,7 @@ bool ElfReader::LoadSegments() {
  */
 static int _phdr_table_set_load_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                      ElfW(Addr) load_bias, int extra_prot_flags,
-                                     bool should_pad_segments) {
+                                     bool should_pad_segments, bool should_use_16kib_app_compat) {
   for (size_t i = 0; i < phdr_count; ++i) {
     const ElfW(Phdr)* phdr = &phdr_table[i];
 
@@ -1049,7 +1121,8 @@ static int _phdr_table_set_load_prot(const ElfW(Phdr)* phdr_table, size_t phdr_c
 
     ElfW(Addr) p_memsz = phdr->p_memsz;
     ElfW(Addr) p_filesz = phdr->p_filesz;
-    _extend_load_segment_vma(phdr_table, phdr_count, i, &p_memsz, &p_filesz, should_pad_segments);
+    _extend_load_segment_vma(phdr_table, phdr_count, i, &p_memsz, &p_filesz, should_pad_segments,
+                             should_use_16kib_app_compat);
 
     ElfW(Addr) seg_page_start = page_start(phdr->p_vaddr + load_bias);
     ElfW(Addr) seg_page_end = page_end(phdr->p_vaddr + p_memsz + load_bias);
@@ -1088,12 +1161,14 @@ static int _phdr_table_set_load_prot(const ElfW(Phdr)* phdr_table, size_t phdr_c
  *   phdr_count  -> number of entries in tables
  *   load_bias   -> load bias
  *   should_pad_segments -> Are segments extended to avoid gaps in the memory map
+ *   should_use_16kib_app_compat -> Is the ELF being loaded in 16KiB app compat mode.
  *   prop        -> GnuPropertySection or nullptr
  * Return:
  *   0 on success, -1 on failure (error code in errno).
  */
 int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                 ElfW(Addr) load_bias, bool should_pad_segments,
+                                bool should_use_16kib_app_compat,
                                 const GnuPropertySection* prop __unused) {
   int prot = 0;
 #if defined(__aarch64__)
@@ -1101,7 +1176,127 @@ int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
     prot |= PROT_BTI;
   }
 #endif
-  return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, prot, should_pad_segments);
+  return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, prot, should_pad_segments,
+                                   should_use_16kib_app_compat);
+}
+
+static bool segment_needs_memtag_globals_remapping(const ElfW(Phdr) * phdr) {
+  // For now, MTE globals is only supported on writeable data segments.
+  return phdr->p_type == PT_LOAD && !(phdr->p_flags & PF_X) && (phdr->p_flags & PF_W);
+}
+
+/* When MTE globals are requested by the binary, and when the hardware supports
+ * it, remap the executable's PT_LOAD data pages to have PROT_MTE.
+ *
+ * Returns 0 on success, -1 on failure (error code in errno).
+ */
+int remap_memtag_globals_segments(const ElfW(Phdr) * phdr_table __unused,
+                                  size_t phdr_count __unused, ElfW(Addr) load_bias __unused) {
+#if defined(__aarch64__)
+  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_table + phdr_count; phdr++) {
+    if (!segment_needs_memtag_globals_remapping(phdr)) {
+      continue;
+    }
+
+    uintptr_t seg_page_start = page_start(phdr->p_vaddr) + load_bias;
+    uintptr_t seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
+    size_t seg_page_aligned_size = seg_page_end - seg_page_start;
+
+    int prot = PFLAGS_TO_PROT(phdr->p_flags);
+    // For anonymous private mappings, it may be possible to simply mprotect()
+    // the PROT_MTE flag over the top. For file-based mappings, this will fail,
+    // and we'll need to fall back. We also allow PROT_WRITE here to allow
+    // writing memory tags (in `soinfo::tag_globals()`), and set these sections
+    // back to read-only after tags are applied (similar to RELRO).
+    prot |= PROT_MTE;
+    if (mprotect(reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size,
+                 prot | PROT_WRITE) == 0) {
+      continue;
+    }
+
+    void* mapping_copy = mmap(nullptr, seg_page_aligned_size, PROT_READ | PROT_WRITE,
+                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
+    linker_memcpy(mapping_copy, reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size);
+
+    void* seg_addr = mmap(reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size,
+                          prot | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
+    if (seg_addr == MAP_FAILED) return -1;
+
+    linker_memcpy(seg_addr, mapping_copy, seg_page_aligned_size);
+    munmap(mapping_copy, seg_page_aligned_size);
+  }
+#endif  // defined(__aarch64__)
+  return 0;
+}
+
+void protect_memtag_globals_ro_segments(const ElfW(Phdr) * phdr_table __unused,
+                                        size_t phdr_count __unused, ElfW(Addr) load_bias __unused) {
+#if defined(__aarch64__)
+  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_table + phdr_count; phdr++) {
+    int prot = PFLAGS_TO_PROT(phdr->p_flags);
+    if (!segment_needs_memtag_globals_remapping(phdr) || (prot & PROT_WRITE)) {
+      continue;
+    }
+
+    prot |= PROT_MTE;
+
+    uintptr_t seg_page_start = page_start(phdr->p_vaddr) + load_bias;
+    uintptr_t seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
+    size_t seg_page_aligned_size = seg_page_end - seg_page_start;
+    mprotect(reinterpret_cast<void*>(seg_page_start), seg_page_aligned_size, prot);
+  }
+#endif  // defined(__aarch64__)
+}
+
+void name_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
+                                  ElfW(Addr) load_bias, const char* soname,
+                                  std::list<std::string>* vma_names) {
+  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_table + phdr_count; phdr++) {
+    if (!segment_needs_memtag_globals_remapping(phdr)) {
+      continue;
+    }
+
+    uintptr_t seg_page_start = page_start(phdr->p_vaddr) + load_bias;
+    uintptr_t seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
+    size_t seg_page_aligned_size = seg_page_end - seg_page_start;
+
+    // For file-based mappings that we're now forcing to be anonymous mappings, set the VMA name to
+    // make debugging easier.
+    // Once we are targeting only devices that run kernel 5.10 or newer (and thus include
+    // https://android-review.git.corp.google.com/c/kernel/common/+/1934723 which causes the
+    // VMA_ANON_NAME to be copied into the kernel), we can get rid of the storage here.
+    // For now, that is not the case:
+    // https://source.android.com/docs/core/architecture/kernel/android-common#compatibility-matrix
+    constexpr int kVmaNameLimit = 80;
+    std::string& vma_name = vma_names->emplace_back(kVmaNameLimit, '\0');
+    int full_vma_length =
+        async_safe_format_buffer(vma_name.data(), kVmaNameLimit, "mt:%s+%" PRIxPTR, soname,
+                                 page_start(phdr->p_vaddr)) +
+        /* include the null terminator */ 1;
+    // There's an upper limit of 80 characters, including the null terminator, in the anonymous VMA
+    // name. If we run over that limit, we end up truncating the segment offset and parts of the
+    // DSO's name, starting on the right hand side of the basename. Because the basename is the most
+    // important thing, chop off the soname from the left hand side first.
+    //
+    // Example (with '#' as the null terminator):
+    //   - "mt:/data/nativetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so+e000#"
+    //     is a `full_vma_length` == 86.
+    //
+    // We need to left-truncate (86 - 80) 6 characters from the soname, plus the
+    // `vma_truncation_prefix`, so 9 characters total.
+    if (full_vma_length > kVmaNameLimit) {
+      const char vma_truncation_prefix[] = "...";
+      int soname_truncated_bytes =
+          full_vma_length - kVmaNameLimit + sizeof(vma_truncation_prefix) - 1;
+      async_safe_format_buffer(vma_name.data(), kVmaNameLimit, "mt:%s%s+%" PRIxPTR,
+                               vma_truncation_prefix, soname + soname_truncated_bytes,
+                               page_start(phdr->p_vaddr));
+    }
+    if (prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<void*>(seg_page_start),
+              seg_page_aligned_size, vma_name.data()) != 0) {
+      DL_WARN("Failed to rename memtag global segment: %m");
+    }
+  }
 }
 
 /* Change the protection of all loaded segments in memory to writable.
@@ -1118,20 +1313,22 @@ int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
  *   phdr_count  -> number of entries in tables
  *   load_bias   -> load bias
  *   should_pad_segments -> Are segments extended to avoid gaps in the memory map
+ *   should_use_16kib_app_compat -> Is the ELF being loaded in 16KiB app compat mode.
  * Return:
  *   0 on success, -1 on failure (error code in errno).
  */
-int phdr_table_unprotect_segments(const ElfW(Phdr)* phdr_table,
-                                  size_t phdr_count, ElfW(Addr) load_bias,
-                                  bool should_pad_segments) {
+int phdr_table_unprotect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
+                                  ElfW(Addr) load_bias, bool should_pad_segments,
+                                  bool should_use_16kib_app_compat) {
   return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, PROT_WRITE,
-                                   should_pad_segments);
+                                   should_pad_segments, should_use_16kib_app_compat);
 }
 
 static inline void _extend_gnu_relro_prot_end(const ElfW(Phdr)* relro_phdr,
                                               const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                               ElfW(Addr) load_bias, ElfW(Addr)* seg_page_end,
-                                              bool should_pad_segments) {
+                                              bool should_pad_segments,
+                                              bool should_use_16kib_app_compat) {
   // Find the index and phdr of the LOAD containing the GNU_RELRO segment
   for (size_t index = 0; index < phdr_count; ++index) {
     const ElfW(Phdr)* phdr = &phdr_table[index];
@@ -1179,7 +1376,7 @@ static inline void _extend_gnu_relro_prot_end(const ElfW(Phdr)* relro_phdr,
       // mprotect will only RO protect a part of the extended RW LOAD segment, which
       // will leave an extra split RW VMA (the gap).
       _extend_load_segment_vma(phdr_table, phdr_count, index, &p_memsz, &p_filesz,
-                               should_pad_segments);
+                               should_pad_segments, should_use_16kib_app_compat);
 
       *seg_page_end = page_end(phdr->p_vaddr + p_memsz + load_bias);
       return;
@@ -1192,7 +1389,8 @@ static inline void _extend_gnu_relro_prot_end(const ElfW(Phdr)* relro_phdr,
  */
 static int _phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                           ElfW(Addr) load_bias, int prot_flags,
-                                          bool should_pad_segments) {
+                                          bool should_pad_segments,
+                                          bool should_use_16kib_app_compat) {
   const ElfW(Phdr)* phdr = phdr_table;
   const ElfW(Phdr)* phdr_limit = phdr + phdr_count;
 
@@ -1220,7 +1418,7 @@ static int _phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t p
     ElfW(Addr) seg_page_start = page_start(phdr->p_vaddr) + load_bias;
     ElfW(Addr) seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz) + load_bias;
     _extend_gnu_relro_prot_end(phdr, phdr_table, phdr_count, load_bias, &seg_page_end,
-                               should_pad_segments);
+                               should_pad_segments, should_use_16kib_app_compat);
 
     int ret = mprotect(reinterpret_cast<void*>(seg_page_start),
                        seg_page_end - seg_page_start,
@@ -1246,13 +1444,29 @@ static int _phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t p
  *   phdr_count  -> number of entries in tables
  *   load_bias   -> load bias
  *   should_pad_segments -> Were segments extended to avoid gaps in the memory map
+ *   should_use_16kib_app_compat -> Is the ELF being loaded in 16KiB app compat mode.
  * Return:
  *   0 on success, -1 on failure (error code in errno).
  */
 int phdr_table_protect_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count,
-                                 ElfW(Addr) load_bias, bool should_pad_segments) {
+                                 ElfW(Addr) load_bias, bool should_pad_segments,
+                                 bool should_use_16kib_app_compat) {
   return _phdr_table_set_gnu_relro_prot(phdr_table, phdr_count, load_bias, PROT_READ,
-                                        should_pad_segments);
+                                        should_pad_segments, should_use_16kib_app_compat);
+}
+
+/*
+ * Apply RX protection to the compat relro region of the ELF being loaded in
+ * 16KiB compat mode.
+ *
+ * Input:
+ *   start  -> start address of the compat relro region.
+ *   size   -> size of the compat relro region in bytes.
+ * Return:
+ *   0 on success, -1 on failure (error code in errno).
+ */
+int phdr_table_protect_gnu_relro_16kib_compat(ElfW(Addr) start, ElfW(Addr) size) {
+  return mprotect(reinterpret_cast<void*>(start), size, PROT_READ | PROT_EXEC);
 }
 
 /* Serialize the GNU relro segments to the given file descriptor. This can be
diff --git a/linker/linker_phdr.h b/linker/linker_phdr.h
index 1d6bbe3ff..e15ece419 100644
--- a/linker/linker_phdr.h
+++ b/linker/linker_phdr.h
@@ -39,6 +39,15 @@
 #include "linker_mapped_file_fragment.h"
 #include "linker_note_gnu_property.h"
 
+#include <list>
+
+#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
+#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
+                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
+                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
+
+static constexpr size_t kCompatPageSize = 0x1000;
+
 class ElfReader {
  public:
   ElfReader();
@@ -59,6 +68,9 @@ class ElfReader {
   bool is_mapped_by_caller() const { return mapped_by_caller_; }
   ElfW(Addr) entry_point() const { return header_.e_entry + load_bias_; }
   bool should_pad_segments() const { return should_pad_segments_; }
+  bool should_use_16kib_app_compat() const { return should_use_16kib_app_compat_; }
+  ElfW(Addr) compat_relro_start() const { return compat_relro_start_; }
+  ElfW(Addr) compat_relro_size() const { return compat_relro_size_; }
 
  private:
   [[nodiscard]] bool ReadElfHeader();
@@ -69,10 +81,14 @@ class ElfReader {
   [[nodiscard]] bool ReadPadSegmentNote();
   [[nodiscard]] bool ReserveAddressSpace(address_space_params* address_space);
   [[nodiscard]] bool MapSegment(size_t seg_idx, size_t len);
+  [[nodiscard]] bool CompatMapSegment(size_t seg_idx, size_t len);
   void ZeroFillSegment(const ElfW(Phdr)* phdr);
   void DropPaddingPages(const ElfW(Phdr)* phdr, uint64_t seg_file_end);
   [[nodiscard]] bool MapBssSection(const ElfW(Phdr)* phdr, ElfW(Addr) seg_page_end,
                                    ElfW(Addr) seg_file_end);
+  [[nodiscard]] bool IsEligibleFor16KiBAppCompat(ElfW(Addr)* vaddr);
+  [[nodiscard]] bool HasAtMostOneRelroSegment(const ElfW(Phdr)** relro_phdr);
+  [[nodiscard]] bool Setup16KiBAppCompat();
   [[nodiscard]] bool LoadSegments();
   [[nodiscard]] bool FindPhdr();
   [[nodiscard]] bool FindGnuPropertySection();
@@ -123,6 +139,13 @@ class ElfReader {
   // Pad gaps between segments when memory mapping?
   bool should_pad_segments_ = false;
 
+  // Use app compat mode when loading 4KiB max-page-size ELFs on 16KiB page-size devices?
+  bool should_use_16kib_app_compat_ = false;
+
+  // RELRO region for 16KiB compat loading
+  ElfW(Addr) compat_relro_start_ = 0;
+  ElfW(Addr) compat_relro_size_ = 0;
+
   // Only used by AArch64 at the moment.
   GnuPropertySection note_gnu_property_ __unused;
 };
@@ -135,13 +158,18 @@ size_t phdr_table_get_minimum_alignment(const ElfW(Phdr)* phdr_table, size_t phd
 
 int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                 ElfW(Addr) load_bias, bool should_pad_segments,
+                                bool should_use_16kib_app_compat,
                                 const GnuPropertySection* prop = nullptr);
 
 int phdr_table_unprotect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
-                                  ElfW(Addr) load_bias, bool should_pad_segments);
+                                  ElfW(Addr) load_bias, bool should_pad_segments,
+                                  bool should_use_16kib_app_compat);
 
 int phdr_table_protect_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count,
-                                 ElfW(Addr) load_bias, bool should_pad_segments);
+                                 ElfW(Addr) load_bias, bool should_pad_segments,
+                                 bool should_use_16kib_app_compat);
+
+int phdr_table_protect_gnu_relro_16kib_compat(ElfW(Addr) start, ElfW(Addr) size);
 
 int phdr_table_serialize_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias, int fd, size_t* file_offset);
@@ -162,3 +190,13 @@ const char* phdr_table_get_interpreter_name(const ElfW(Phdr)* phdr_table, size_t
                                             ElfW(Addr) load_bias);
 
 bool page_size_migration_supported();
+
+int remap_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
+                                  ElfW(Addr) load_bias);
+
+void protect_memtag_globals_ro_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
+                                        ElfW(Addr) load_bias);
+
+void name_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
+                                  ElfW(Addr) load_bias, const char* soname,
+                                  std::list<std::string>* vma_names);
diff --git a/linker/linker_phdr_16kib_compat.cpp b/linker/linker_phdr_16kib_compat.cpp
new file mode 100644
index 000000000..bad20baef
--- /dev/null
+++ b/linker/linker_phdr_16kib_compat.cpp
@@ -0,0 +1,247 @@
+/*
+ * Copyright (C) 2012 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include "linker_phdr.h"
+
+#include <linux/prctl.h>
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <unistd.h>
+
+#include "linker_debug.h"
+#include "linker_dlwarning.h"
+#include "linker_globals.h"
+
+#include "platform/bionic/macros.h"
+#include "platform/bionic/page.h"
+
+#include <string>
+
+static bool g_enable_16kb_app_compat;
+
+static inline bool segment_contains_prefix(const ElfW(Phdr)* segment, const ElfW(Phdr)* prefix) {
+  return segment && prefix && segment->p_vaddr == prefix->p_vaddr;
+}
+
+void set_16kb_appcompat_mode(bool enable_app_compat) {
+  g_enable_16kb_app_compat = enable_app_compat;
+}
+
+bool get_16kb_appcompat_mode() {
+  return g_enable_16kb_app_compat;
+}
+
+/*
+ * Returns true if the ELF contains at most 1 RELRO segment; and populates @relro_phdr
+ * with the relro phdr or nullptr if none.
+ *
+ * Returns false if more than 1 RELRO segments are found.
+ */
+bool ElfReader::HasAtMostOneRelroSegment(const ElfW(Phdr)** relro_phdr) {
+  const ElfW(Phdr)* relro = nullptr;
+  for (size_t i = 0; i < phdr_num_; ++i) {
+    const ElfW(Phdr)* phdr = &phdr_table_[i];
+
+    if (phdr->p_type != PT_GNU_RELRO) {
+      continue;
+    }
+
+    if (relro == nullptr) {
+      relro = phdr;
+    } else {
+      return false;
+    }
+  }
+
+  *relro_phdr = relro;
+
+  return true;
+}
+
+/*
+ * In 16KiB compatibility mode ELFs with the following segment layout
+ * can be loaded successfully:
+ *
+ *         ┌────────────┬─────────────────────────┬────────────┐
+ *         │            │                         │            │
+ *         │  (RO|RX)*  │   (RW - RELRO prefix)?  │    (RW)*   │
+ *         │            │                         │            │
+ *         └────────────┴─────────────────────────┴────────────┘
+ *
+ * In other words, compatible layouts have:
+ *         - zero or more RO or RX segments;
+ *         - followed by zero or one RELRO prefix;
+ *         - followed by zero or more RW segments (this can include the RW
+ *           suffix from the segment containing the RELRO prefix, if any)
+ *
+ * In 16KiB compat mode, after relocation, the ELF is layout in virtual
+ * memory is as shown below:
+ *         ┌──────────────────────────────────────┬────────────┐
+ *         │                                      │            │
+ *         │                (RX)?                 │    (RW)?   │
+ *         │                                      │            │
+ *         └──────────────────────────────────────┴────────────┘
+ *
+ * In compat mode:
+ *         - the RO and RX segments along with the RELRO prefix are protected
+ *           as RX;
+ *         - and the RW segments along with RW suffix from the relro segment,
+ *           if any; are RW protected.
+ *
+ * This allows for the single RX|RW permission boundary to be aligned with
+ * a 16KiB page boundary; since a single page cannot share multiple
+ * permissions.
+ *
+ * IsEligibleFor16KiBAppCompat() identifies compatible ELFs and populates @vaddr
+ * with the boundary between RX|RW portions.
+ *
+ * Returns true if the ELF can be loaded in compat mode, else false.
+ */
+bool ElfReader::IsEligibleFor16KiBAppCompat(ElfW(Addr)* vaddr) {
+  const ElfW(Phdr)* relro_phdr = nullptr;
+  if (!HasAtMostOneRelroSegment(&relro_phdr)) {
+    DL_WARN("\"%s\": Compat loading failed: Multiple RELRO segments found", name_.c_str());
+    return false;
+  }
+
+  const ElfW(Phdr)* last_rw = nullptr;
+  const ElfW(Phdr)* first_rw = nullptr;
+
+  for (size_t i = 0; i < phdr_num_; ++i) {
+    const ElfW(Phdr)* curr = &phdr_table_[i];
+    const ElfW(Phdr)* prev = (i > 0) ? &phdr_table_[i - 1] : nullptr;
+
+    if (curr->p_type != PT_LOAD) {
+      continue;
+    }
+
+    int prot = PFLAGS_TO_PROT(curr->p_flags);
+
+    if ((prot & PROT_WRITE) && (prot & PROT_READ)) {
+      if (!first_rw) {
+        first_rw = curr;
+      }
+
+      if (last_rw && last_rw != prev) {
+        DL_WARN("\"%s\": Compat loading failed: ELF contains multiple non-adjacent RW segments",
+                name_.c_str());
+        return false;
+      }
+
+      last_rw = curr;
+    }
+  }
+
+  if (!relro_phdr) {
+    *vaddr = align_down(first_rw->p_vaddr, kCompatPageSize);
+    return true;
+  }
+
+  // The RELRO segment is present, it must be the prefix of the first RW segment.
+  if (!segment_contains_prefix(first_rw, relro_phdr)) {
+    DL_WARN("\"%s\": Compat loading failed: RELRO is not in the first RW segment",
+            name_.c_str());
+    return false;
+  }
+
+  uint64_t end;
+  if (__builtin_add_overflow(relro_phdr->p_vaddr, relro_phdr->p_memsz, &end)) {
+    DL_WARN("\"%s\": Compat loading failed: relro vaddr + memsz overflowed", name_.c_str());
+    return false;
+  }
+
+  *vaddr = align_up(end, kCompatPageSize);
+  return true;
+}
+
+/*
+ * Returns the offset/shift needed to align @vaddr to a page boundary.
+ */
+static inline ElfW(Addr) perm_boundary_offset(const ElfW(Addr) addr) {
+  ElfW(Addr) offset = page_offset(addr);
+
+  return offset ? page_size() - offset : 0;
+}
+
+bool ElfReader::Setup16KiBAppCompat() {
+  if (!should_use_16kib_app_compat_) {
+    return true;
+  }
+
+  ElfW(Addr) rx_rw_boundary;  // Permission bounadry for compat mode
+  if (!IsEligibleFor16KiBAppCompat(&rx_rw_boundary)) {
+    return false;
+  }
+
+  // Adjust the load_bias to position the RX|RW boundary on a page boundary
+  load_bias_ += perm_boundary_offset(rx_rw_boundary);
+
+  // RW region (.data, .bss ...)
+  ElfW(Addr) rw_start = load_bias_ + rx_rw_boundary;
+  ElfW(Addr) rw_size = load_size_ - (rw_start - reinterpret_cast<ElfW(Addr)>(load_start_));
+
+  CHECK(rw_start % getpagesize() == 0);
+  CHECK(rw_size % getpagesize() == 0);
+
+  // Compat RELRO (RX) region (.text, .data.relro, ...)
+  compat_relro_start_ = reinterpret_cast<ElfW(Addr)>(load_start_);
+  compat_relro_size_ = load_size_ - rw_size;
+
+  // Label the ELF VMA, since compat mode uses anonymous mappings.
+  std::string compat_name = name_ + " (compat loaded)";
+  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, load_start_, load_size_, compat_name.c_str());
+
+  return true;
+}
+
+bool ElfReader::CompatMapSegment(size_t seg_idx, size_t len) {
+  const ElfW(Phdr)* phdr = &phdr_table_[seg_idx];
+
+  // NOTE: The compat(legacy) page size (4096) must be used when aligning
+  // the 4KiB segments for loading (reading). The larger 16KiB page size
+  // will lead to overwriting adjacent segments since the ELF's segment(s)
+  // are not 16KiB aligned.
+
+  void* start = reinterpret_cast<void*>(align_down(phdr->p_vaddr + load_bias_, kCompatPageSize));
+
+  // The ELF could be being loaded directly from a zipped APK,
+  // the zip offset must be added to find the segment offset.
+  const ElfW(Addr) offset = file_offset_ + align_down(phdr->p_offset, kCompatPageSize);
+
+  CHECK(should_use_16kib_app_compat_);
+
+  // Since the 4KiB max-page-size ELF is not properly aligned, loading it by
+  // directly mmapping the ELF file is not feasible.
+  // Instead, read the ELF contents into the anonymous RW mapping.
+  if (TEMP_FAILURE_RETRY(pread64(fd_, start, len, offset)) == -1) {
+    DL_ERR("Compat loading: \"%s\" failed to read LOAD segment %zu: %m", name_.c_str(), seg_idx);
+    return false;
+  }
+
+  return true;
+}
diff --git a/linker/linker_relocate.cpp b/linker/linker_relocate.cpp
index bcb1efc1f..bbf83590b 100644
--- a/linker/linker_relocate.cpp
+++ b/linker/linker_relocate.cpp
@@ -44,6 +44,8 @@
 #include "linker_soinfo.h"
 #include "private/bionic_globals.h"
 
+#include <platform/bionic/mte.h>
+
 static bool is_tls_reloc(ElfW(Word) type) {
   switch (type) {
     case R_GENERIC_TLS_DTPMOD:
@@ -163,7 +165,8 @@ __attribute__((always_inline))
 static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
   constexpr bool IsGeneral = Mode == RelocMode::General;
 
-  void* const rel_target = reinterpret_cast<void*>(reloc.r_offset + relocator.si->load_bias);
+  void* const rel_target = reinterpret_cast<void*>(
+      relocator.si->apply_memtag_if_mte_globals(reloc.r_offset + relocator.si->load_bias));
   const uint32_t r_type = ELFW(R_TYPE)(reloc.r_info);
   const uint32_t r_sym = ELFW(R_SYM)(reloc.r_info);
 
@@ -188,8 +191,8 @@ static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
   auto protect_segments = [&]() {
     // Make .text executable.
     if (phdr_table_protect_segments(relocator.si->phdr, relocator.si->phnum,
-                                    relocator.si->load_bias,
-                                    relocator.si->should_pad_segments()) < 0) {
+                                    relocator.si->load_bias, relocator.si->should_pad_segments(),
+                                    relocator.si->should_use_16kib_app_compat()) < 0) {
       DL_ERR("can't protect segments for \"%s\": %m", relocator.si->get_realpath());
       return false;
     }
@@ -198,8 +201,8 @@ static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
   auto unprotect_segments = [&]() {
     // Make .text writable.
     if (phdr_table_unprotect_segments(relocator.si->phdr, relocator.si->phnum,
-                                      relocator.si->load_bias,
-                                      relocator.si->should_pad_segments()) < 0) {
+                                      relocator.si->load_bias, relocator.si->should_pad_segments(),
+                                      relocator.si->should_use_16kib_app_compat()) < 0) {
       DL_ERR("can't unprotect loadable segments for \"%s\": %m",
              relocator.si->get_realpath());
       return false;
@@ -316,6 +319,7 @@ static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
     // common in non-platform binaries.
     if (r_type == R_GENERIC_ABSOLUTE) {
       count_relocation_if<IsGeneral>(kRelocAbsolute);
+      if (found_in) sym_addr = found_in->apply_memtag_if_mte_globals(sym_addr);
       const ElfW(Addr) result = sym_addr + get_addend_rel();
       LD_DEBUG(reloc && IsGeneral, "RELO ABSOLUTE %16p <- %16p %s",
                rel_target, reinterpret_cast<void*>(result), sym_name);
@@ -326,6 +330,7 @@ static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
       // document (IHI0044F) specifies that R_ARM_GLOB_DAT has an addend, but Bionic isn't adding
       // it.
       count_relocation_if<IsGeneral>(kRelocAbsolute);
+      if (found_in) sym_addr = found_in->apply_memtag_if_mte_globals(sym_addr);
       const ElfW(Addr) result = sym_addr + get_addend_norel();
       LD_DEBUG(reloc && IsGeneral, "RELO GLOB_DAT %16p <- %16p %s",
                rel_target, reinterpret_cast<void*>(result), sym_name);
@@ -335,7 +340,18 @@ static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
       // In practice, r_sym is always zero, but if it weren't, the linker would still look up the
       // referenced symbol (and abort if the symbol isn't found), even though it isn't used.
       count_relocation_if<IsGeneral>(kRelocRelative);
-      const ElfW(Addr) result = relocator.si->load_bias + get_addend_rel();
+      ElfW(Addr) result = relocator.si->load_bias + get_addend_rel();
+      // MTE globals reuses the place bits for additional tag-derivation metadata for
+      // R_AARCH64_RELATIVE relocations, which makes it incompatible with
+      // `-Wl,--apply-dynamic-relocs`. This is enforced by lld, however there's nothing stopping
+      // Android binaries (particularly prebuilts) from building with this linker flag if they're
+      // not built with MTE globals. Thus, don't use the new relocation semantics if this DSO
+      // doesn't have MTE globals.
+      if (relocator.si->should_tag_memtag_globals()) {
+        int64_t* place = static_cast<int64_t*>(rel_target);
+        int64_t offset = *place;
+        result = relocator.si->apply_memtag_if_mte_globals(result + offset) - offset;
+      }
       LD_DEBUG(reloc && IsGeneral, "RELO RELATIVE %16p <- %16p",
                rel_target, reinterpret_cast<void*>(result));
       *static_cast<ElfW(Addr)*>(rel_target) = result;
@@ -600,7 +616,7 @@ bool soinfo::relocate(const SymbolLookupList& lookup_list) {
     LD_DEBUG(reloc, "[ relocating %s relr ]", get_realpath());
     const ElfW(Relr)* begin = relr_;
     const ElfW(Relr)* end = relr_ + relr_count_;
-    if (!relocate_relr(begin, end, load_bias)) {
+    if (!relocate_relr(begin, end, load_bias, should_tag_memtag_globals())) {
       return false;
     }
   }
diff --git a/linker/linker_sleb128.h b/linker/linker_sleb128.h
index 6bb31997d..f48fda8c9 100644
--- a/linker/linker_sleb128.h
+++ b/linker/linker_sleb128.h
@@ -69,3 +69,32 @@ class sleb128_decoder {
   const uint8_t* current_;
   const uint8_t* const end_;
 };
+
+class uleb128_decoder {
+ public:
+  uleb128_decoder(const uint8_t* buffer, size_t count) : current_(buffer), end_(buffer + count) {}
+
+  uint64_t pop_front() {
+    uint64_t value = 0;
+
+    size_t shift = 0;
+    uint8_t byte;
+
+    do {
+      if (current_ >= end_) {
+        async_safe_fatal("uleb128_decoder ran out of bounds");
+      }
+      byte = *current_++;
+      value |= (static_cast<size_t>(byte & 127) << shift);
+      shift += 7;
+    } while (byte & 128);
+
+    return value;
+  }
+
+  bool has_bytes() { return current_ < end_; }
+
+ private:
+  const uint8_t* current_;
+  const uint8_t* const end_;
+};
diff --git a/linker/linker_soinfo.cpp b/linker/linker_soinfo.cpp
index 0549d36ef..176c13334 100644
--- a/linker/linker_soinfo.cpp
+++ b/linker/linker_soinfo.cpp
@@ -44,6 +44,8 @@
 #include "linker_logger.h"
 #include "linker_relocate.h"
 #include "linker_utils.h"
+#include "platform/bionic/mte.h"
+#include "private/bionic_globals.h"
 
 SymbolLookupList::SymbolLookupList(soinfo* si)
     : sole_lib_(si->get_lookup_lib()), begin_(&sole_lib_), end_(&sole_lib_ + 1) {
@@ -304,6 +306,12 @@ const ElfW(Sym)* soinfo::find_symbol_by_name(SymbolName& symbol_name,
   return is_gnu_hash() ? gnu_lookup(symbol_name, vi) : elf_lookup(symbol_name, vi);
 }
 
+ElfW(Addr) soinfo::apply_memtag_if_mte_globals(ElfW(Addr) sym_addr) const {
+  if (!should_tag_memtag_globals()) return sym_addr;
+  if (sym_addr == 0) return sym_addr;  // Handle undefined weak symbols.
+  return reinterpret_cast<ElfW(Addr)>(get_tagged_address(reinterpret_cast<void*>(sym_addr)));
+}
+
 const ElfW(Sym)* soinfo::gnu_lookup(SymbolName& symbol_name, const version_info* vi) const {
   const uint32_t hash = symbol_name.gnu_hash();
 
diff --git a/linker/linker_soinfo.h b/linker/linker_soinfo.h
index 9a13af2a6..4d0267643 100644
--- a/linker/linker_soinfo.h
+++ b/linker/linker_soinfo.h
@@ -30,6 +30,7 @@
 
 #include <link.h>
 
+#include <list>
 #include <memory>
 #include <string>
 #include <vector>
@@ -66,6 +67,7 @@
                                          // soinfo is executed and this flag is
                                          // unset.
 #define FLAG_PRELINKED        0x00000400 // prelink_image has successfully processed this soinfo
+#define FLAG_GLOBALS_TAGGED   0x00000800 // globals have been tagged by MTE.
 #define FLAG_NEW_SOINFO       0x40000000 // new soinfo format
 
 #define SOINFO_VERSION 6
@@ -252,11 +254,14 @@ struct soinfo {
   void call_constructors();
   void call_destructors();
   void call_pre_init_constructors();
-  bool prelink_image();
+  bool prelink_image(bool deterministic_memtag_globals = false);
   bool link_image(const SymbolLookupList& lookup_list, soinfo* local_group_root,
                   const android_dlextinfo* extinfo, size_t* relro_fd_offset);
   bool protect_relro();
 
+  void tag_globals(bool deterministic_memtag_globals);
+  ElfW(Addr) apply_memtag_if_mte_globals(ElfW(Addr) sym_addr) const;
+
   void add_child(soinfo* child);
   void remove_all_links();
 
@@ -293,6 +298,9 @@ struct soinfo {
 #if defined(__work_around_b_24465209__)
     return (flags_ & FLAG_NEW_SOINFO) != 0 && version_ >= min_version;
 #else
+    // If you make this return non-true in the case where
+    // __work_around_b_24465209__ is not defined, you will have to change
+    // memtag_dynamic_entries() and vma_names().
     return true;
 #endif
   }
@@ -354,20 +362,66 @@ struct soinfo {
   size_t get_gap_size() const;
 
   const memtag_dynamic_entries_t* memtag_dynamic_entries() const {
-    CHECK(has_min_version(7));
+#ifdef __aarch64__
+#ifdef __work_around_b_24465209__
+#error "Assuming aarch64 does not use versioned soinfo."
+#endif
     return &memtag_dynamic_entries_;
+#endif
+    return nullptr;
+  }
+  void* memtag_globals() const {
+    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
+    return entries ? entries->memtag_globals : nullptr;
+  }
+  size_t memtag_globalssz() const {
+    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
+    return entries ? entries->memtag_globalssz : 0U;
+  }
+  bool has_memtag_mode() const {
+    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
+    return entries ? entries->has_memtag_mode : false;
+  }
+  unsigned memtag_mode() const {
+    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
+    return entries ? entries->memtag_mode : 0U;
+  }
+  bool memtag_heap() const {
+    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
+    return entries ? entries->memtag_heap : false;
+  }
+  bool memtag_stack() const {
+    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
+    return entries ? entries->memtag_stack : false;
   }
-  void* memtag_globals() const { return memtag_dynamic_entries()->memtag_globals; }
-  size_t memtag_globalssz() const { return memtag_dynamic_entries()->memtag_globalssz; }
-  bool has_memtag_mode() const { return memtag_dynamic_entries()->has_memtag_mode; }
-  unsigned memtag_mode() const { return memtag_dynamic_entries()->memtag_mode; }
-  bool memtag_heap() const { return memtag_dynamic_entries()->memtag_heap; }
-  bool memtag_stack() const { return memtag_dynamic_entries()->memtag_stack; }
 
   void set_should_pad_segments(bool should_pad_segments) {
    should_pad_segments_ = should_pad_segments;
   }
   bool should_pad_segments() const { return should_pad_segments_; }
+  bool should_tag_memtag_globals() const {
+    return !is_linker() && memtag_globals() && memtag_globalssz() > 0 && __libc_mte_enabled();
+  }
+  std::list<std::string>* vma_names() {
+#ifdef __aarch64__
+#ifdef __work_around_b_24465209__
+#error "Assuming aarch64 does not use versioned soinfo."
+#endif
+    return &vma_names_;
+#endif
+    return nullptr;
+};
+
+  void set_should_use_16kib_app_compat(bool should_use_16kib_app_compat) {
+    should_use_16kib_app_compat_ = should_use_16kib_app_compat;
+  }
+  bool should_use_16kib_app_compat() const { return should_use_16kib_app_compat_; }
+
+  void set_compat_relro_start(ElfW(Addr) start) { compat_relro_start_ = start; }
+  ElfW(Addr) compat_relro_start() const { return compat_relro_start_; }
+
+  void set_compat_relro_size(ElfW(Addr) size) { compat_relro_size_ = size; }
+  ElfW(Addr) compat_relro_size() const { return compat_relro_start_; }
 
  private:
   bool is_image_linked() const;
@@ -450,11 +504,19 @@ struct soinfo {
   ElfW(Addr) gap_start_;
   size_t gap_size_;
 
-  // version >= 7
+  // __aarch64__ only, which does not use versioning.
   memtag_dynamic_entries_t memtag_dynamic_entries_;
+  std::list<std::string> vma_names_;
 
   // Pad gaps between segments when memory mapping?
   bool should_pad_segments_ = false;
+
+  // Use app compat mode when loading 4KiB max-page-size ELFs on 16KiB page-size devices?
+  bool should_use_16kib_app_compat_ = false;
+
+  // RELRO region for 16KiB compat loading
+  ElfW(Addr) compat_relro_start_ = 0;
+  ElfW(Addr) compat_relro_size_ = 0;
 };
 
 // This function is used by dlvsym() to calculate hash of sym_ver
diff --git a/tests/Android.bp b/tests/Android.bp
index 6aecb405a..a97f5a824 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -389,7 +389,9 @@ cc_test_library {
         "bug_26110743_test.cpp",
         "byteswap_test.cpp",
         "complex_test.cpp",
-        "cpu_target_features_test.cpp",
+        // Disabled while investigating
+        // b/378304366, b/375525252
+        // "cpu_target_features_test.cpp",
         "ctype_test.cpp",
         "dirent_test.cpp",
         "elf_test.cpp",
@@ -428,6 +430,7 @@ cc_test_library {
         "malloc_test.cpp",
         "math_test.cpp",
         "membarrier_test.cpp",
+        "memtag_globals_test.cpp",
         "memtag_stack_test.cpp",
         "mntent_test.cpp",
         "mte_test.cpp",
@@ -746,6 +749,40 @@ cc_test_library {
     },
 }
 
+cc_defaults {
+    name: "bionic_fortify_c_tests_defaults",
+    defaults: [
+        "bionic_clang_fortify_tests_w_flags",
+        "bionic_tests_defaults",
+    ],
+    cflags: [
+        "-U_FORTIFY_SOURCE",
+        // -fbuiltin is required here to counteract -fno-builtin from
+        // `bionic_tests_defaults`. With `-fno-builtin`, Clang won't
+        // const-evaluate calls to `strlen`, which is tested for here.
+        "-fbuiltin",
+    ],
+    srcs: [
+        "clang_fortify_c_only_tests.c",
+    ],
+    tidy: false,
+    shared: {
+        enabled: false,
+    },
+}
+
+cc_test_library {
+    name: "libfortify1-c-tests-clang",
+    defaults: ["bionic_fortify_c_tests_defaults"],
+    cflags: ["-D_FORTIFY_SOURCE=1"],
+}
+
+cc_test_library {
+    name: "libfortify2-c-tests-clang",
+    defaults: ["bionic_fortify_c_tests_defaults"],
+    cflags: ["-D_FORTIFY_SOURCE=2"],
+}
+
 // -----------------------------------------------------------------------------
 // Library of all tests (excluding the dynamic linker tests).
 // -----------------------------------------------------------------------------
@@ -757,8 +794,10 @@ cc_test_library {
         "libBionicStandardTests",
         "libBionicElfTlsTests",
         "libBionicFramePointerTests",
+        "libfortify1-c-tests-clang",
         "libfortify1-tests-clang",
         "libfortify1-new-tests-clang",
+        "libfortify2-c-tests-clang",
         "libfortify2-tests-clang",
         "libfortify2-new-tests-clang",
     ],
@@ -779,6 +818,7 @@ cc_test_library {
         "dlfcn_test.cpp",
         "execinfo_test.cpp",
         "link_test.cpp",
+        "page_size_16kib_compat_test.cpp",
         "pthread_dlfcn_test.cpp",
     ],
     static_libs: [
@@ -787,6 +827,7 @@ cc_test_library {
     ],
     include_dirs: [
         "bionic/libc",
+        "bionic/tests/libs",
     ],
     shared: {
         enabled: false,
@@ -853,6 +894,11 @@ cc_defaults {
         "ld_preload_test_helper",
         "ld_preload_test_helper_lib1",
         "ld_preload_test_helper_lib2",
+        "memtag_globals_binary",
+        "memtag_globals_binary_static",
+        "memtag_globals_dso",
+        "mte_globals_relr_regression_test_b_314038442",
+        "mte_globals_relr_regression_test_b_314038442_mte",
         "ns_hidden_child_helper",
         "preinit_getauxval_test_helper",
         "preinit_syscall_test_helper",
@@ -934,6 +980,7 @@ cc_defaults {
         "libtest_dt_runpath_d",
         "libtest_dt_runpath_x",
         "libtest_dt_runpath_y",
+        "libtest_elf_max_page_size_4kib",
         "libtest_elftls_dynamic",
         "libtest_elftls_dynamic_filler_1",
         "libtest_elftls_dynamic_filler_2",
@@ -1159,6 +1206,35 @@ cc_test {
     test_suites: ["device-tests"],
 }
 
+cc_test {
+    name: "memtag_stack_abi_test",
+    enabled: false,
+    // This does not use bionic_tests_defaults because it is not supported on
+    // host.
+    arch: {
+        arm64: {
+            enabled: true,
+        },
+    },
+    // We don't use `sanitize:` so we generate the appropriate ELF note, but
+    // still support non-MTE devices.
+    // TODO(fmayer): also add a test that enables stack MTE for MTE devices,
+    // which would test for more bugs.
+    ldflags: ["-fsanitize=memtag-stack"],
+    // Turn off all other sanitizers from SANITIZE_TARGET.
+    sanitize: {
+        never: true,
+    },
+    shared_libs: [
+        "libbase",
+    ],
+    srcs: [
+        "memtag_stack_abi_test.cpp",
+    ],
+    header_libs: ["bionic_libc_platform_headers"],
+    test_suites: ["device-tests"],
+}
+
 cc_test {
     name: "bionic-stress-tests",
     defaults: [
@@ -1178,6 +1254,7 @@ cc_test {
 
     shared_libs: [
         "libbase",
+        "liblog",
     ],
 
     target: {
@@ -1247,6 +1324,11 @@ cc_test {
         "heap_tagging_static_disabled_helper",
         "heap_tagging_static_sync_helper",
         "heap_tagging_sync_helper",
+        "memtag_globals_binary",
+        "memtag_globals_binary_static",
+        "memtag_globals_dso",
+        "mte_globals_relr_regression_test_b_314038442",
+        "mte_globals_relr_regression_test_b_314038442_mte",
         "stack_tagging_helper",
         "stack_tagging_static_helper",
     ],
diff --git a/libc/private/bsd_sys_param.h b/tests/DoNotOptimize.h
similarity index 64%
rename from libc/private/bsd_sys_param.h
rename to tests/DoNotOptimize.h
index ab54aa032..711d339e8 100644
--- a/libc/private/bsd_sys_param.h
+++ b/tests/DoNotOptimize.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2014 The Android Open Source Project
+ * Copyright (C) 2012 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -16,8 +16,12 @@
 
 #pragma once
 
-#include <inttypes.h>
-
-/* OpenBSD has these in <sys/param.h>, but "ALIGN" isn't something we want to reserve. */
-#define ALIGNBYTES (sizeof(uintptr_t) - 1)
-#define ALIGN(p) ((__BIONIC_CAST(reinterpret_cast, uintptr_t, p) + ALIGNBYTES) & ~ALIGNBYTES)
+// From <benchmark/benchmark.h>.
+template <class Tp>
+static inline void DoNotOptimize(Tp const& value) {
+  asm volatile("" : : "r,m"(value) : "memory");
+}
+template <class Tp>
+static inline void DoNotOptimize(Tp& value) {
+  asm volatile("" : "+r,m"(value) : : "memory");
+}
diff --git a/tests/clang_fortify_c_only_tests.c b/tests/clang_fortify_c_only_tests.c
new file mode 100644
index 000000000..3bec848ac
--- /dev/null
+++ b/tests/clang_fortify_c_only_tests.c
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <string.h>
+
+// This is a test specifically of bionic's FORTIFY machinery. Other stdlibs need not apply.
+#ifdef __BIONIC__
+
+// Ensure that strlen can be evaluated at compile-time. Clang doesn't support
+// this in C++, but does in C.
+_Static_assert(strlen("foo") == 3, "");
+
+#endif  // __BIONIC__
diff --git a/tests/clang_fortify_tests.cpp b/tests/clang_fortify_tests.cpp
index f08fd1ff8..da7926d46 100644
--- a/tests/clang_fortify_tests.cpp
+++ b/tests/clang_fortify_tests.cpp
@@ -89,6 +89,10 @@
 #include <unistd.h>
 #include <wchar.h>
 
+#include <array>
+
+#include "DoNotOptimize.h"
+
 #ifndef COMPILATION_TESTS
 #include <android-base/silent_death_test.h>
 #include <gtest/gtest.h>
@@ -133,6 +137,24 @@ __attribute__((noreturn)) static void ExitAfter(Fn&& f) {
 
 const static int kBogusFD = -1;
 
+FORTIFY_TEST(strlen) {
+  auto run_strlen_with_contents = [&](std::array<char, 3> contents) {
+    // A lot of cruft is necessary to make this test DTRT. LLVM and Clang love to fold/optimize
+    // strlen calls, and that's the opposite of what we want to happen.
+
+    // Loop to convince LLVM that `contents` can never be known (since `xor volatile_value` can flip
+    // any bit in each elem of `contents`).
+    volatile char always_zero = 0;
+    for (char& c : contents) {
+      c ^= always_zero;
+    }
+    DoNotOptimize(strlen(&contents.front()));
+  };
+
+  EXPECT_NO_DEATH(run_strlen_with_contents({'f', 'o', '\0'}));
+  EXPECT_FORTIFY_DEATH(run_strlen_with_contents({'f', 'o', 'o'}));
+}
+
 FORTIFY_TEST(string) {
   char small_buffer[8] = {};
 
diff --git a/tests/complex_test.cpp b/tests/complex_test.cpp
index 8fdb2b2e1..ed0109a21 100644
--- a/tests/complex_test.cpp
+++ b/tests/complex_test.cpp
@@ -20,6 +20,9 @@
 #if !defined(__INTRODUCED_IN)
 #define __INTRODUCED_IN(x)
 #endif
+#if !defined(__BIONIC_AVAILABILITY_GUARD)
+#define __BIONIC_AVAILABILITY_GUARD(x) 1
+#endif
 
 // libc++ actively gets in the way of including <complex.h> from C++, so we
 // have to be naughty.
diff --git a/tests/cpu_target_features_test.cpp b/tests/cpu_target_features_test.cpp
index 3458bca9e..d77377251 100644
--- a/tests/cpu_target_features_test.cpp
+++ b/tests/cpu_target_features_test.cpp
@@ -54,15 +54,3 @@ TEST(cpu_target_features, has_expected_aarch64_compiler_values) {
   GTEST_SKIP() << "Not targeting an aarch64 architecture.";
 #endif
 }
-
-TEST(cpu_target_features, has_expected_arm_compiler_values) {
-#if defined(__arm__)
-  ExecTestHelper eth;
-  char* const argv[] = {nullptr};
-  const auto invocation = [&] { execvp("cpu-target-features", argv); };
-  eth.Run(invocation, 0, "(^|\n)__ARM_FEATURE_AES=1($|\n)");
-  eth.Run(invocation, 0, "(^|\n)__ARM_FEATURE_CRC32=1($|\n)");
-#else
-  GTEST_SKIP() << "Not targeting an arm architecture.";
-#endif
-}
diff --git a/tests/dlext_test.cpp b/tests/dlext_test.cpp
index 570da2a75..8b26cb0d4 100644
--- a/tests/dlext_test.cpp
+++ b/tests/dlext_test.cpp
@@ -21,6 +21,7 @@
 #include <errno.h>
 #include <fcntl.h>
 #include <inttypes.h>
+#include <link.h>
 #include <stdio.h>
 #include <string.h>
 #include <unistd.h>
@@ -40,11 +41,13 @@
 #include <procinfo/process_map.h>
 #include <ziparchive/zip_archive.h>
 
+#include "bionic/mte.h"
+#include "bionic/page.h"
 #include "core_shared_libs.h"
-#include "gtest_globals.h"
-#include "utils.h"
 #include "dlext_private.h"
 #include "dlfcn_symlink_support.h"
+#include "gtest_globals.h"
+#include "utils.h"
 
 #define ASSERT_DL_NOTNULL(ptr) \
     ASSERT_TRUE((ptr) != nullptr) << "dlerror: " << dlerror()
@@ -1958,6 +1961,14 @@ TEST(dlext, ns_allow_all_shared_libs) {
   dlclose(ns_a_handle3);
 }
 
+static inline int MapPflagsToProtFlags(uint32_t flags) {
+  int prot_flags = 0;
+  if (PF_X & flags) prot_flags |= PROT_EXEC;
+  if (PF_W & flags) prot_flags |= PROT_WRITE;
+  if (PF_R & flags) prot_flags |= PROT_READ;
+  return prot_flags;
+}
+
 TEST(dlext, ns_anonymous) {
   static const char* root_lib = "libnstest_root.so";
   std::string shared_libs = g_core_shared_libs + ":" + g_public_lib;
@@ -1999,30 +2010,45 @@ TEST(dlext, ns_anonymous) {
   typedef const char* (*fn_t)();
   fn_t ns_get_dlopened_string_private = reinterpret_cast<fn_t>(ns_get_dlopened_string_addr);
 
-  std::vector<map_record> maps;
-  Maps::parse_maps(&maps);
-
+  Dl_info private_library_info;
+  ASSERT_NE(dladdr(reinterpret_cast<void*>(ns_get_dlopened_string_addr), &private_library_info), 0)
+      << dlerror();
+  std::vector<map_record> maps_to_copy;
+  bool has_executable_segment = false;
   uintptr_t addr_start = 0;
   uintptr_t addr_end = 0;
-  bool has_executable_segment = false;
-  std::vector<map_record> maps_to_copy;
-
-  for (const auto& rec : maps) {
-    if (rec.pathname == private_library_absolute_path) {
-      if (addr_start == 0) {
-        addr_start = rec.addr_start;
-      }
-      addr_end = rec.addr_end;
-      has_executable_segment = has_executable_segment || (rec.perms & PROT_EXEC) != 0;
-
-      maps_to_copy.push_back(rec);
-    }
-  }
+  std::tuple dl_iterate_arg = {&private_library_info, &maps_to_copy, &has_executable_segment,
+                               &addr_start, &addr_end};
+  ASSERT_EQ(
+      1, dl_iterate_phdr(
+             [](dl_phdr_info* info, size_t /*size*/, void* data) -> int {
+               auto [private_library_info, maps_to_copy, has_executable_segment, addr_start,
+                     addr_end] = *reinterpret_cast<decltype(dl_iterate_arg)*>(data);
+               if (info->dlpi_addr != reinterpret_cast<ElfW(Addr)>(private_library_info->dli_fbase))
+                 return 0;
+
+               for (size_t i = 0; i < info->dlpi_phnum; ++i) {
+                 const ElfW(Phdr)* phdr = info->dlpi_phdr + i;
+                 if (phdr->p_type != PT_LOAD) continue;
+                 *has_executable_segment |= phdr->p_flags & PF_X;
+                 uintptr_t mapping_start = page_start(info->dlpi_addr + phdr->p_vaddr);
+                 uintptr_t mapping_end = page_end(info->dlpi_addr + phdr->p_vaddr + phdr->p_memsz);
+                 if (*addr_start == 0 || mapping_start < *addr_start) *addr_start = mapping_start;
+                 if (*addr_end == 0 || mapping_end > *addr_end) *addr_end = mapping_end;
+                 maps_to_copy->push_back({
+                     .addr_start = mapping_start,
+                     .addr_end = mapping_end,
+                     .perms = MapPflagsToProtFlags(phdr->p_flags),
+                 });
+               }
+               return 1;
+             },
+             &dl_iterate_arg));
 
   // Some validity checks.
+  ASSERT_NE(maps_to_copy.size(), 0u);
   ASSERT_TRUE(addr_start > 0);
   ASSERT_TRUE(addr_end > 0);
-  ASSERT_TRUE(maps_to_copy.size() > 0);
   ASSERT_TRUE(ns_get_dlopened_string_addr > addr_start);
   ASSERT_TRUE(ns_get_dlopened_string_addr < addr_end);
 
@@ -2052,19 +2078,26 @@ TEST(dlext, ns_anonymous) {
   ASSERT_EQ(ret, 0) << "Failed to stat library";
   size_t file_size = file_stat.st_size;
 
-  for (const auto& rec : maps_to_copy) {
-    uintptr_t offset = rec.addr_start - addr_start;
-    size_t size = rec.addr_end - rec.addr_start;
-    void* addr = reinterpret_cast<void*>(reserved_addr + offset);
-    void* map = mmap(addr, size, PROT_READ | PROT_WRITE,
-                     MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
-    ASSERT_TRUE(map != MAP_FAILED);
-    // Attempting the below memcpy from a portion of the map that is off the end of
-    // the backing file will cause the kernel to throw a SIGBUS
-    size_t _size = ::android::procinfo::MappedFileSize(rec.addr_start, rec.addr_end,
-                                                       rec.offset, file_size);
-    memcpy(map, reinterpret_cast<void*>(rec.addr_start), _size);
-    mprotect(map, size, rec.perms);
+  {
+    // Disable MTE while copying the PROT_MTE-protected global variables from
+    // the existing mappings. We don't really care about turning on PROT_MTE for
+    // the new copy of the mappings, as this isn't the behaviour under test and
+    // tags will be ignored. This only applies for MTE-enabled devices.
+    ScopedDisableMTE disable_mte_for_copying_global_variables;
+    for (const auto& rec : maps_to_copy) {
+      uintptr_t offset = rec.addr_start - addr_start;
+      size_t size = rec.addr_end - rec.addr_start;
+      void* addr = reinterpret_cast<void*>(reserved_addr + offset);
+      void* map =
+          mmap(addr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
+      ASSERT_TRUE(map != MAP_FAILED);
+      // Attempting the below memcpy from a portion of the map that is off the end of
+      // the backing file will cause the kernel to throw a SIGBUS
+      size_t _size =
+          ::android::procinfo::MappedFileSize(rec.addr_start, rec.addr_end, rec.offset, file_size);
+      memcpy(map, reinterpret_cast<void*>(rec.addr_start), _size);
+      mprotect(map, size, rec.perms);
+    }
   }
 
   // call the function copy
diff --git a/tests/fenv_test.cpp b/tests/fenv_test.cpp
index 9cf9d9893..bbf339f09 100644
--- a/tests/fenv_test.cpp
+++ b/tests/fenv_test.cpp
@@ -16,6 +16,7 @@
 
 #include <gtest/gtest.h>
 
+#include "DoNotOptimize.h"
 #include "utils.h"
 
 #include <fenv.h>
diff --git a/tests/grp_pwd_test.cpp b/tests/grp_pwd_test.cpp
index 7b7e0e506..3f93c8a93 100644
--- a/tests/grp_pwd_test.cpp
+++ b/tests/grp_pwd_test.cpp
@@ -480,6 +480,18 @@ static void expect_ids(T ids, bool is_group) {
       EXPECT_STREQ(getpwuid(AID_CROS_EC)->pw_name, "cros_ec");
     }
   }
+  // AID_MMD (1095) was added in API level 36, but "trunk stable" means
+  // that the 2024Q* builds are tested with the _previous_ release's CTS.
+  if (android::base::GetIntProperty("ro.build.version.sdk", 0) == 35) {
+#if !defined(AID_MMD)
+#define AID_MMD 1095
+#endif
+    ids.erase(AID_MMD);
+    expected_ids.erase(AID_MMD);
+    if (getpwuid(AID_MMD)) {
+      EXPECT_STREQ(getpwuid(AID_MMD)->pw_name, "mmd");
+    }
+  }
 
   EXPECT_EQ(expected_ids, ids) << return_differences();
 }
diff --git a/tests/headers/posix/stdatomic_h.c b/tests/headers/posix/stdatomic_h.c
new file mode 100644
index 000000000..05be859e9
--- /dev/null
+++ b/tests/headers/posix/stdatomic_h.c
@@ -0,0 +1,175 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <stdatomic.h>
+
+#include "header_checks.h"
+
+static void stdatomic_h() {
+  TYPE(atomic_flag);
+  TYPE(atomic_bool);
+  TYPE(atomic_char);
+  TYPE(atomic_schar);
+  TYPE(atomic_uchar);
+  TYPE(atomic_short);
+  TYPE(atomic_ushort);
+  TYPE(atomic_int);
+  TYPE(atomic_uint);
+  TYPE(atomic_long);
+  TYPE(atomic_ulong);
+  TYPE(atomic_llong);
+  TYPE(atomic_ullong);
+#if !defined(__GLIBC__)
+  TYPE(atomic_char16_t);
+  TYPE(atomic_char32_t);
+#endif
+  TYPE(atomic_wchar_t);
+  TYPE(atomic_int_least8_t);
+  TYPE(atomic_uint_least8_t);
+  TYPE(atomic_int_least16_t);
+  TYPE(atomic_uint_least16_t);
+  TYPE(atomic_int_least32_t);
+  TYPE(atomic_uint_least32_t);
+  TYPE(atomic_int_least64_t);
+  TYPE(atomic_uint_least64_t);
+  TYPE(atomic_int_fast8_t);
+  TYPE(atomic_uint_fast8_t);
+  TYPE(atomic_int_fast16_t);
+  TYPE(atomic_uint_fast16_t);
+  TYPE(atomic_int_fast32_t);
+  TYPE(atomic_uint_fast32_t);
+  TYPE(atomic_int_fast64_t);
+  TYPE(atomic_uint_fast64_t);
+  TYPE(atomic_intptr_t);
+  TYPE(atomic_uintptr_t);
+  TYPE(atomic_size_t);
+  TYPE(atomic_ptrdiff_t);
+  TYPE(atomic_intmax_t);
+  TYPE(atomic_uintmax_t);
+
+  memory_order m1 = memory_order_relaxed;
+  memory_order m2 = memory_order_consume;
+  memory_order m3 = memory_order_acquire;
+  memory_order m4 = memory_order_release;
+  memory_order m5 = memory_order_acq_rel;
+  memory_order m6 = memory_order_seq_cst;
+
+  MACRO(ATOMIC_BOOL_LOCK_FREE);
+  MACRO(ATOMIC_CHAR_LOCK_FREE);
+  MACRO(ATOMIC_CHAR16_T_LOCK_FREE);
+  MACRO(ATOMIC_CHAR32_T_LOCK_FREE);
+  MACRO(ATOMIC_WCHAR_T_LOCK_FREE);
+  MACRO(ATOMIC_SHORT_LOCK_FREE);
+  MACRO(ATOMIC_INT_LOCK_FREE);
+  MACRO(ATOMIC_LONG_LOCK_FREE);
+  MACRO(ATOMIC_LLONG_LOCK_FREE);
+  MACRO(ATOMIC_POINTER_LOCK_FREE);
+
+  atomic_flag f = ATOMIC_FLAG_INIT;
+  atomic_int i = ATOMIC_VAR_INIT(123);
+
+  // TODO: remove this #if after the next toolchain update (http://b/374104004).
+#if !defined(__GLIBC__)
+  i = kill_dependency(i);
+#endif
+
+#if !defined(atomic_compare_exchange_strong)
+#error atomic_compare_exchange_strong
+#endif
+#if !defined(atomic_compare_exchange_strong_explicit)
+#error atomic_compare_exchange_strong_explicit
+#endif
+#if !defined(atomic_compare_exchange_weak)
+#error atomic_compare_exchange_weak
+#endif
+#if !defined(atomic_compare_exchange_weak_explicit)
+#error atomic_compare_exchange_weak_explicit
+#endif
+#if !defined(atomic_exchange)
+#error atomic_exchange
+#endif
+#if !defined(atomic_exchange_explicit)
+#error atomic_exchange_explicit
+#endif
+#if !defined(atomic_fetch_add)
+#error atomic_fetch_add
+#endif
+#if !defined(atomic_fetch_add_explicit)
+#error atomic_fetch_add_explicit
+#endif
+#if !defined(atomic_fetch_and)
+#error atomic_fetch_and
+#endif
+#if !defined(atomic_fetch_and_explicit)
+#error atomic_fetch_and_explicit
+#endif
+#if !defined(atomic_fetch_or)
+#error atomic_fetch_or
+#endif
+#if !defined(atomic_fetch_or_explicit)
+#error atomic_fetch_or_explicit
+#endif
+#if !defined(atomic_fetch_sub)
+#error atomic_fetch_sub
+#endif
+#if !defined(atomic_fetch_sub_explicit)
+#error atomic_fetch_sub_explicit
+#endif
+#if !defined(atomic_fetch_xor)
+#error atomic_fetch_xor
+#endif
+#if !defined(atomic_fetch_xor_explicit)
+#error atomic_fetch_xor_explicit
+#endif
+#if !defined(atomic_init)
+#error atomic_init
+#endif
+#if !defined(atomic_is_lock_free)
+#error atomic_is_lock_free
+#endif
+#if !defined(atomic_load)
+#error atomic_load
+#endif
+#if !defined(atomic_load_explicit)
+#error atomic_load_explicit
+#endif
+#if !defined(atomic_store)
+#error atomic_store
+#endif
+#if !defined(atomic_store_explicit)
+#error atomic_store_explicit
+#endif
+
+  FUNCTION(atomic_flag_clear, void (*f)(volatile atomic_flag*));
+  FUNCTION(atomic_flag_clear_explicit, void (*f)(volatile atomic_flag*, memory_order));
+  FUNCTION(atomic_flag_test_and_set, bool (*f)(volatile atomic_flag*));
+  FUNCTION(atomic_flag_test_and_set_explicit, bool (*f)(volatile atomic_flag*, memory_order));
+
+  FUNCTION(atomic_signal_fence, void (*f)(memory_order));
+  FUNCTION(atomic_thread_fence, void (*f)(memory_order));
+}
diff --git a/tests/headers/posix/stdbool_h.c b/tests/headers/posix/stdbool_h.c
index f891a7334..830c33cea 100644
--- a/tests/headers/posix/stdbool_h.c
+++ b/tests/headers/posix/stdbool_h.c
@@ -31,10 +31,8 @@
 #include "header_checks.h"
 
 static void stdbool_h() {
-#if !defined(bool)
-#error bool
-#endif
-  MACRO_VALUE(true, 1);
-  MACRO_VALUE(false, 0);
+  TYPE(bool);
+  bool t = true;
+  bool f = false;
   MACRO_VALUE(__bool_true_false_are_defined, 1);
 }
diff --git a/tests/libs/Android.bp b/tests/libs/Android.bp
index 35f0f0c89..5b86e78bb 100644
--- a/tests/libs/Android.bp
+++ b/tests/libs/Android.bp
@@ -47,6 +47,16 @@ cc_defaults {
     },
 }
 
+// -----------------------------------------------------------------------------
+// Test library ELFs for linker page size related tests
+// -----------------------------------------------------------------------------
+cc_test_library {
+    name: "libtest_elf_max_page_size_4kib",
+    defaults: ["bionic_testlib_defaults"],
+    srcs: ["elf_max_page_size.c"],
+    ldflags: ["-z max-page-size=0x1000"],
+}
+
 // -----------------------------------------------------------------------------
 // Libraries and helper binaries for ELF TLS
 // -----------------------------------------------------------------------------
@@ -1893,3 +1903,89 @@ cc_genrule {
         " $(location soong_zip) -o $(out).unaligned -L 0 -C $(genDir)/zipdir -D $(genDir)/zipdir &&" +
         " $(location bionic_tests_zipalign) 16384 $(out).unaligned $(out)",
 }
+
+cc_defaults {
+    name: "memtag_globals_defaults",
+    defaults: [
+        "bionic_testlib_defaults",
+        "bionic_targets_only"
+    ],
+    cflags: [
+        "-Wno-array-bounds",
+        "-Wno-unused-variable",
+    ],
+    header_libs: ["bionic_libc_platform_headers"],
+    sanitize: {
+        hwaddress: false,
+        memtag_heap: true,
+        memtag_globals: true,
+        diag: {
+            memtag_heap: true,
+        }
+    },
+}
+
+cc_test_library {
+    name: "memtag_globals_dso",
+    defaults: [ "memtag_globals_defaults" ],
+    srcs: ["memtag_globals_dso.cpp"],
+}
+
+cc_test {
+    name: "memtag_globals_binary",
+    defaults: [ "memtag_globals_defaults" ],
+    srcs: ["memtag_globals_binary.cpp"],
+    shared_libs: [ "memtag_globals_dso" ],
+    // This binary is used in the bionic-unit-tests as a data dependency, and is
+    // in the same folder as memtag_globals_dso. But, the default cc_test rules
+    // make this binary (when just explicitly built and shoved in
+    // /data/nativetest64/) end up in a subfolder called
+    // 'memtag_globals_binary'. When this happens, the explicit build fails to
+    // find the DSO because the default rpath is just ${ORIGIN}, and because we
+    // want this to be usable both from bionic-unit-tests and explicit builds,
+    // let's just not put it in a subdirectory.
+    no_named_install_directory: true,
+}
+
+cc_test {
+    name: "memtag_globals_binary_static",
+    defaults: [ "memtag_globals_defaults" ],
+    srcs: ["memtag_globals_binary.cpp"],
+    static_libs: [ "memtag_globals_dso" ],
+    no_named_install_directory: true,
+    static_executable: true,
+}
+
+// This is a regression test for b/314038442, where binaries built *without* MTE
+// globals would have out-of-bounds RELR relocations, which where then `ldg`'d,
+// which resulted in linker crashes.
+cc_test {
+  name: "mte_globals_relr_regression_test_b_314038442",
+  defaults: [
+        "bionic_testlib_defaults",
+        "bionic_targets_only"
+    ],
+    cflags: [ "-Wno-array-bounds" ],
+    ldflags: [ "-Wl,--pack-dyn-relocs=relr" ],
+    srcs: ["mte_globals_relr_regression_test_b_314038442.cpp"],
+    no_named_install_directory: true,
+    sanitize: {
+        memtag_globals: false,
+    },
+}
+
+// Same test as above, but also for MTE globals, just for the sake of it.
+cc_test {
+  name: "mte_globals_relr_regression_test_b_314038442_mte",
+  defaults: [
+        "bionic_testlib_defaults",
+        "bionic_targets_only"
+    ],
+    cflags: [ "-Wno-array-bounds" ],
+    ldflags: [ "-Wl,--pack-dyn-relocs=relr" ],
+    srcs: ["mte_globals_relr_regression_test_b_314038442.cpp"],
+    no_named_install_directory: true,
+    sanitize: {
+      memtag_globals: true,
+    },
+}
diff --git a/tests/libs/elf_max_page_size.c b/tests/libs/elf_max_page_size.c
new file mode 100644
index 000000000..24c7e89a5
--- /dev/null
+++ b/tests/libs/elf_max_page_size.c
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include "elf_max_page_size.h"
+
+const int ro0 = RO0;
+const int ro1 = RO1;
+int rw0 = RW0;
+
+/* Force some padding alignment */
+int rw1 __attribute__((aligned(0x10000))) = RW1;
+
+int bss0, bss1;
+
+int* const prw0 = &rw0;
+
+int loader_test_func(void) {
+  rw0 += RW0_INCREMENT;
+  rw1 += RW1_INCREMENT;
+
+  bss0 += BSS0_INCREMENT;
+  bss1 += BSS1_INCREMENT;
+
+  return ro0 + ro1 + rw0 + rw1 + bss0 + bss1 + *prw0;
+}
diff --git a/tests/libs/elf_max_page_size.h b/tests/libs/elf_max_page_size.h
new file mode 100644
index 000000000..846a8b652
--- /dev/null
+++ b/tests/libs/elf_max_page_size.h
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#define RO0 23
+#define RO1 234
+#define RW0 2345
+#define RW1 23456
+#define BSS0 0
+#define BSS1 0
+
+#define RW0_INCREMENT 12
+#define RW1_INCREMENT 123
+#define BSS0_INCREMENT 1234
+#define BSS1_INCREMENT 12345
+
+#define TEST_RESULT_BASE (RO0 + RO1 + RW0 + RW1 + BSS0 + BSS1 + RW0)
+#define TEST_RESULT_INCREMENT \
+  (RW0_INCREMENT + RW1_INCREMENT + BSS0_INCREMENT + BSS1_INCREMENT + RW0_INCREMENT)
+
+typedef int (*loader_test_func_t)(void);
diff --git a/tests/libs/memtag_globals.h b/tests/libs/memtag_globals.h
new file mode 100644
index 000000000..a03abae5f
--- /dev/null
+++ b/tests/libs/memtag_globals.h
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <utility>
+#include <vector>
+
+void check_tagged(const void* a);
+void check_untagged(const void* a);
+void check_matching_tags(const void* a, const void* b);
+void check_eq(const void* a, const void* b);
+
+void dso_check_assertions(bool enforce_tagged);
+void dso_print_variables();
+
+void print_variable_address(const char* name, const void* ptr);
+void print_variables(const char* header,
+                     const std::vector<std::pair<const char*, const void*>>& tagged_variables,
+                     const std::vector<std::pair<const char*, const void*>>& untagged_variables);
diff --git a/tests/libs/memtag_globals_binary.cpp b/tests/libs/memtag_globals_binary.cpp
new file mode 100644
index 000000000..9248728a0
--- /dev/null
+++ b/tests/libs/memtag_globals_binary.cpp
@@ -0,0 +1,195 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <unistd.h>
+#include <string>
+#include <vector>
+
+#include "memtag_globals.h"
+
+// Adapted from the LLD test suite: lld/test/ELF/Inputs/aarch64-memtag-globals.s
+
+/// Global variables defined here, of various semantics.
+char global[30] = {};
+__attribute__((no_sanitize("memtag"))) int global_untagged = 0;
+const int const_global = 0;
+static const int hidden_const_global = 0;
+static char hidden_global[12] = {};
+__attribute__((visibility("hidden"))) int hidden_attr_global = 0;
+__attribute__((visibility("hidden"))) const int hidden_attr_const_global = 0;
+
+/// Should be untagged.
+__thread int tls_global;
+__thread static int hidden_tls_global;
+
+/// Tagged, from the other file.
+extern int global_extern;
+/// Untagged, from the other file.
+extern __attribute__((no_sanitize("memtag"))) int global_extern_untagged;
+/// Tagged here, but untagged in the definition found in the sister objfile
+/// (explicitly).
+extern int global_extern_untagged_definition_but_tagged_import;
+
+/// ABS64 relocations. Also, forces symtab entries for local and external
+/// globals.
+char* pointer_to_global = &global[0];
+char* pointer_inside_global = &global[17];
+char* pointer_to_global_end = &global[30];
+char* pointer_past_global_end = &global[48];
+int* pointer_to_global_untagged = &global_untagged;
+const int* pointer_to_const_global = &const_global;
+/// RELATIVE relocations.
+const int* pointer_to_hidden_const_global = &hidden_const_global;
+char* pointer_to_hidden_global = &hidden_global[0];
+int* pointer_to_hidden_attr_global = &hidden_attr_global;
+const int* pointer_to_hidden_attr_const_global = &hidden_attr_const_global;
+/// RELATIVE relocations with special AArch64 MemtagABI semantics, with the
+/// offset ('12' or '16') encoded in the place.
+char* pointer_to_hidden_global_end = &hidden_global[12];
+char* pointer_past_hidden_global_end = &hidden_global[16];
+/// ABS64 relocations.
+int* pointer_to_global_extern = &global_extern;
+int* pointer_to_global_extern_untagged = &global_extern_untagged;
+int* pointer_to_global_extern_untagged_definition_but_tagged_import =
+    &global_extern_untagged_definition_but_tagged_import;
+
+// Force materialization of these globals into the symtab.
+int* get_address_to_tls_global() {
+  return &tls_global;
+}
+int* get_address_to_hidden_tls_global() {
+  return &hidden_tls_global;
+}
+
+static const std::vector<std::pair<const char*, const void*>>& get_expected_tagged_vars() {
+  static std::vector<std::pair<const char*, const void*>> expected_tagged_vars = {
+      {"global", &global},
+      {"pointer_inside_global", pointer_inside_global},
+      {"pointer_to_global_end", pointer_to_global_end},
+      {"pointer_past_global_end", pointer_past_global_end},
+      {"hidden_global", &hidden_global},
+      {"hidden_attr_global", &hidden_attr_global},
+      {"global_extern", &global_extern},
+  };
+  return expected_tagged_vars;
+}
+
+static const std::vector<std::pair<const char*, const void*>>& get_expected_untagged_vars() {
+  static std::vector<std::pair<const char*, const void*>> expected_untagged_vars = {
+      {"global_extern_untagged", &global_extern_untagged},
+      {"global_extern_untagged_definition_but_tagged_import",
+       &global_extern_untagged_definition_but_tagged_import},
+      {"global_untagged", &global_untagged},
+      {"const_global", &const_global},
+      {"hidden_const_global", &hidden_const_global},
+      {"hidden_attr_const_global", &hidden_attr_const_global},
+      {"tls_global", &tls_global},
+      {"hidden_tls_global", &hidden_tls_global},
+  };
+  return expected_untagged_vars;
+}
+
+void exe_print_variables() {
+  print_variables("  Variables accessible from the binary:\n", get_expected_tagged_vars(),
+                  get_expected_untagged_vars());
+}
+
+// Dump the addresses of the global variables to stderr
+void dso_print();
+void dso_print_others();
+
+void exe_check_assertions(bool check_pointers_are_tagged) {
+  // Check that non-const variables are writeable.
+  *pointer_to_global = 0;
+  *pointer_inside_global = 0;
+  *(pointer_to_global_end - 1) = 0;
+  *pointer_to_global_untagged = 0;
+  *pointer_to_hidden_global = 0;
+  *pointer_to_hidden_attr_global = 0;
+  *(pointer_to_hidden_global_end - 1) = 0;
+  *pointer_to_global_extern = 0;
+  *pointer_to_global_extern_untagged = 0;
+  *pointer_to_global_extern_untagged_definition_but_tagged_import = 0;
+
+  if (check_pointers_are_tagged) {
+    for (const auto& [_, pointer] : get_expected_tagged_vars()) {
+      check_tagged(pointer);
+    }
+  }
+
+  for (const auto& [_, pointer] : get_expected_untagged_vars()) {
+    check_untagged(pointer);
+  }
+
+  check_matching_tags(pointer_to_global, pointer_inside_global);
+  check_matching_tags(pointer_to_global, pointer_to_global_end);
+  check_matching_tags(pointer_to_global, pointer_past_global_end);
+  check_eq(pointer_inside_global, pointer_to_global + 17);
+  check_eq(pointer_to_global_end, pointer_to_global + 30);
+  check_eq(pointer_past_global_end, pointer_to_global + 48);
+
+  check_matching_tags(pointer_to_hidden_global, pointer_to_hidden_global_end);
+  check_matching_tags(pointer_to_hidden_global, pointer_past_hidden_global_end);
+  check_eq(pointer_to_hidden_global_end, pointer_to_hidden_global + 12);
+  check_eq(pointer_past_hidden_global_end, pointer_to_hidden_global + 16);
+}
+
+void crash() {
+  *pointer_past_global_end = 0;
+}
+
+int main(int argc, char** argv) {
+  bool check_pointers_are_tagged = false;
+  // For an MTE-capable device, provide argv[1] == '1' to enable the assertions
+  // that pointers should be tagged.
+  if (argc >= 2 && argv[1][0] == '1') {
+    check_pointers_are_tagged = true;
+  }
+
+  char* heap_ptr = static_cast<char*>(malloc(1));
+  print_variable_address("heap address", heap_ptr);
+  *heap_ptr = 0;
+  if (check_pointers_are_tagged) check_tagged(heap_ptr);
+  free(heap_ptr);
+
+  exe_print_variables();
+  dso_print_variables();
+
+  exe_check_assertions(check_pointers_are_tagged);
+  dso_check_assertions(check_pointers_are_tagged);
+
+  printf("Assertions were passed. Now doing a global-buffer-overflow.\n");
+  fflush(stdout);
+  crash();
+  printf("global-buffer-overflow went uncaught.\n");
+  return 0;
+}
diff --git a/tests/libs/memtag_globals_dso.cpp b/tests/libs/memtag_globals_dso.cpp
new file mode 100644
index 000000000..9ed264e7f
--- /dev/null
+++ b/tests/libs/memtag_globals_dso.cpp
@@ -0,0 +1,165 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <vector>
+
+#include "memtag_globals.h"
+
+// Adapted from the LLD test suite: lld/test/ELF/Inputs/aarch64-memtag-globals.s
+
+int global_extern;
+static int global_extern_hidden;
+__attribute__((no_sanitize("memtag"))) int global_extern_untagged;
+__attribute__((no_sanitize("memtag"))) int global_extern_untagged_definition_but_tagged_import;
+
+void assertion_failure() {
+  exit(1);
+}
+
+void check_tagged(const void* a) {
+  uintptr_t a_uptr = reinterpret_cast<uintptr_t>(a);
+#if defined(__aarch64__)
+  if ((a_uptr >> 56) == 0) {
+    fprintf(stderr, "**********************************\n");
+    fprintf(stderr, "Failed assertion:\n");
+    fprintf(stderr, "  tag(0x%zx) != 0\n", a_uptr);
+    fprintf(stderr, "**********************************\n");
+
+    assertion_failure();
+  }
+#endif  // defined(__aarch64__)
+}
+
+void check_untagged(const void* a) {
+  uintptr_t a_uptr = reinterpret_cast<uintptr_t>(a);
+#if defined(__aarch64__)
+  if ((a_uptr >> 56) != 0) {
+    fprintf(stderr, "**********************************\n");
+    fprintf(stderr, "Failed assertion:\n");
+    fprintf(stderr, "  tag(0x%zx) == 0\n", a_uptr);
+    fprintf(stderr, "**********************************\n");
+
+    assertion_failure();
+  }
+#endif  // defined(__aarch64__)
+}
+
+void check_matching_tags(const void* a, const void* b) {
+  uintptr_t a_uptr = reinterpret_cast<uintptr_t>(a);
+  uintptr_t b_uptr = reinterpret_cast<uintptr_t>(b);
+#if defined(__aarch64__)
+  if (a_uptr >> 56 != b_uptr >> 56) {
+    fprintf(stderr, "**********************************\n");
+    fprintf(stderr, "Failed assertion:\n");
+    fprintf(stderr, "  tag(0x%zx) != tag(0x%zx)\n", a_uptr, b_uptr);
+    fprintf(stderr, "**********************************\n");
+
+    assertion_failure();
+  }
+#endif  // defined(__aarch64__)
+}
+
+void check_eq(const void* a, const void* b) {
+  if (a != b) {
+    fprintf(stderr, "**********************************\n");
+    fprintf(stderr, "Failed assertion:\n");
+    fprintf(stderr, "  %p != %p\n", a, b);
+    fprintf(stderr, "**********************************\n");
+
+    assertion_failure();
+  }
+}
+
+#define LONGEST_VARIABLE_NAME "51"
+void print_variable_address(const char* name, const void* ptr) {
+  printf("%" LONGEST_VARIABLE_NAME "s: %16p\n", name, ptr);
+}
+
+static const std::vector<std::pair<const char*, const void*>>& get_expected_tagged_vars() {
+  static std::vector<std::pair<const char*, const void*>> expected_tagged_vars = {
+      {"global_extern", &global_extern},
+      {"global_extern_hidden", &global_extern_hidden},
+  };
+  return expected_tagged_vars;
+}
+
+static const std::vector<std::pair<const char*, const void*>>& get_expected_untagged_vars() {
+  static std::vector<std::pair<const char*, const void*>> expected_untagged_vars = {
+      {"global_extern_untagged", &global_extern_untagged},
+      {"global_extern_untagged_definition_but_tagged_import",
+       &global_extern_untagged_definition_but_tagged_import},
+  };
+  return expected_untagged_vars;
+}
+
+void dso_print_variables() {
+  print_variables("  Variables declared in the DSO:\n", get_expected_tagged_vars(),
+                  get_expected_untagged_vars());
+}
+
+void print_variables(const char* header,
+                     const std::vector<std::pair<const char*, const void*>>& tagged_variables,
+                     const std::vector<std::pair<const char*, const void*>>& untagged_variables) {
+  printf("==========================================================\n");
+  printf("%s", header);
+  printf("==========================================================\n");
+  printf(" Variables expected to be tagged:\n");
+  printf("----------------------------------------------------------\n");
+  for (const auto& [name, pointer] : tagged_variables) {
+    print_variable_address(name, pointer);
+  }
+
+  printf("\n----------------------------------------------------------\n");
+  printf(" Variables expected to be untagged:\n");
+  printf("----------------------------------------------------------\n");
+  for (const auto& [name, pointer] : untagged_variables) {
+    print_variable_address(name, pointer);
+  }
+  printf("\n");
+}
+
+void dso_check_assertions(bool check_pointers_are_tagged) {
+  // Check that non-const variables are writeable.
+  global_extern = 0;
+  global_extern_hidden = 0;
+  global_extern_untagged = 0;
+  global_extern_untagged_definition_but_tagged_import = 0;
+
+  if (check_pointers_are_tagged) {
+    for (const auto& [_, pointer] : get_expected_tagged_vars()) {
+      check_tagged(pointer);
+    }
+  }
+
+  for (const auto& [_, pointer] : get_expected_untagged_vars()) {
+    check_untagged(pointer);
+  }
+}
diff --git a/tests/libs/mte_globals_relr_regression_test_b_314038442.cpp b/tests/libs/mte_globals_relr_regression_test_b_314038442.cpp
new file mode 100644
index 000000000..20bbba96b
--- /dev/null
+++ b/tests/libs/mte_globals_relr_regression_test_b_314038442.cpp
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <stdint.h>
+#include <stdio.h>
+
+static volatile char array[0x10000];
+volatile char* volatile oob_ptr = &array[0x111111111];
+
+unsigned char get_tag(__attribute__((unused)) volatile void* ptr) {
+#if defined(__aarch64__)
+  return static_cast<unsigned char>(reinterpret_cast<uintptr_t>(ptr) >> 56) & 0xf;
+#else   // !defined(__aarch64__)
+  return 0;
+#endif  // defined(__aarch64__)
+}
+
+int main() {
+  printf("Program loaded successfully. %p %p. ", array, oob_ptr);
+  if (get_tag(array) != get_tag(oob_ptr)) {
+    printf("Tags are mismatched!\n");
+    return 1;
+  }
+  if (get_tag(array) == 0) {
+    printf("Tags are zero!\n");
+  } else {
+    printf("Tags are non-zero\n");
+  }
+  return 0;
+}
diff --git a/tests/malloc_stress_test.cpp b/tests/malloc_stress_test.cpp
index b5b06abff..00f591952 100644
--- a/tests/malloc_stress_test.cpp
+++ b/tests/malloc_stress_test.cpp
@@ -27,10 +27,58 @@
 #include <thread>
 #include <vector>
 
-#include <android-base/strings.h>
 #if defined(__BIONIC__)
 #include <meminfo/procmeminfo.h>
 #include <procinfo/process_map.h>
+
+#include <log/log.h>
+#include <log/log_read.h>
+#endif
+
+#if defined(__BIONIC__)
+static void PrintLogStats(uint64_t& last_time) {
+  logger_list* logger =
+      android_logger_list_open(android_name_to_log_id("main"), ANDROID_LOG_NONBLOCK, 0, getpid());
+  if (logger == nullptr) {
+    printf("Failed to open log for main\n");
+    return;
+  }
+
+  uint64_t last_message_time = last_time;
+  while (true) {
+    log_msg entry;
+    ssize_t retval = android_logger_list_read(logger, &entry);
+    if (retval == 0) {
+      break;
+    }
+    if (retval < 0) {
+      if (retval == -EINTR) {
+        continue;
+      }
+      // EAGAIN means there is nothing left to read when ANDROID_LOG_NONBLOCK is set.
+      if (retval != -EAGAIN) {
+        printf("Failed to read log entry: %s\n", strerrordesc_np(retval));
+      }
+      break;
+    }
+    if (entry.msg() == nullptr) {
+      continue;
+    }
+    // Only print allocator tagged log entries.
+    std::string_view tag(entry.msg() + 1);
+    if (tag != "scudo" && tag != "jemalloc") {
+      continue;
+    }
+    if (entry.nsec() > last_time) {
+      printf("  %s\n", &tag.back() + 2);
+      // Only update the last time outside this loop just in case two or more
+      // messages have the same timestamp.
+      last_message_time = entry.nsec();
+    }
+  }
+  android_logger_list_close(logger);
+  last_time = last_message_time;
+}
 #endif
 
 TEST(malloc_stress, multiple_threads_forever) {
@@ -45,6 +93,8 @@ TEST(malloc_stress, multiple_threads_forever) {
 #endif
   uint64_t mallinfo_min = UINT64_MAX;
   uint64_t mallinfo_max = 0;
+
+  uint64_t last_message_time = 0;
   for (size_t i = 0; ; i++) {
     printf("Pass %zu\n", i);
 
@@ -74,8 +124,8 @@ TEST(malloc_stress, multiple_threads_forever) {
     uint64_t rss_bytes = 0;
     uint64_t vss_bytes = 0;
     for (auto& vma : maps) {
-      if (vma.name == "[anon:libc_malloc]" || android::base::StartsWith(vma.name, "[anon:scudo:") ||
-          android::base::StartsWith(vma.name, "[anon:GWP-ASan")) {
+      if (vma.name == "[anon:libc_malloc]" || vma.name.starts_with("[anon:scudo:") ||
+          vma.name.starts_with("[anon:GWP-ASan")) {
         android::meminfo::Vma update_vma(vma);
         ASSERT_TRUE(proc_mem.FillInVmaStats(update_vma));
         rss_bytes += update_vma.usage.rss;
@@ -112,5 +162,15 @@ TEST(malloc_stress, multiple_threads_forever) {
     printf("Allocated memory %zu %0.2fMB\n", mallinfo_bytes, mallinfo_bytes / (1024.0 * 1024.0));
     printf("  Min %" PRIu64 " %0.2fMB\n", mallinfo_min, mallinfo_min / (1024.0 * 1024.0));
     printf("  Max %" PRIu64 " %0.2fMB\n", mallinfo_max, mallinfo_max / (1024.0 * 1024.0));
+
+#if defined(__BIONIC__)
+    if (((i + 1) % 100) == 0) {
+      // Send native allocator stats to the log
+      mallopt(M_LOG_STATS, 0);
+
+      printf("Log stats:\n");
+      PrintLogStats(last_message_time);
+    }
+#endif
   }
 }
diff --git a/tests/malloc_test.cpp b/tests/malloc_test.cpp
index 813f348b0..3f1ba7959 100644
--- a/tests/malloc_test.cpp
+++ b/tests/malloc_test.cpp
@@ -47,6 +47,7 @@
 #include <android-base/file.h>
 #include <android-base/test_utils.h>
 
+#include "DoNotOptimize.h"
 #include "utils.h"
 
 #if defined(__BIONIC__)
diff --git a/tests/memtag_globals_test.cpp b/tests/memtag_globals_test.cpp
new file mode 100644
index 000000000..ff93e7b5d
--- /dev/null
+++ b/tests/memtag_globals_test.cpp
@@ -0,0 +1,113 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <gtest/gtest.h>
+
+#if defined(__BIONIC__)
+#include "gtest_globals.h"
+#include "utils.h"
+#endif  // defined(__BIONIC__)
+
+#include <android-base/test_utils.h>
+#include <sys/stat.h>
+#include <unistd.h>
+#include <string>
+#include <tuple>
+
+#include "platform/bionic/mte.h"
+
+class MemtagGlobalsTest : public testing::TestWithParam<bool> {};
+
+TEST_P(MemtagGlobalsTest, test) {
+  SKIP_WITH_HWASAN << "MTE globals tests are incompatible with HWASan";
+#if defined(__BIONIC__) && defined(__aarch64__)
+  std::string binary = GetTestLibRoot() + "/memtag_globals_binary";
+  bool is_static = MemtagGlobalsTest::GetParam();
+  if (is_static) {
+    binary += "_static";
+  }
+
+  chmod(binary.c_str(), 0755);
+  ExecTestHelper eth;
+  eth.SetArgs({binary.c_str(), nullptr});
+  eth.Run(
+      [&]() {
+        execve(binary.c_str(), eth.GetArgs(), eth.GetEnv());
+        GTEST_FAIL() << "Failed to execve: " << strerror(errno) << " " << binary.c_str();
+      },
+      // We catch the global-buffer-overflow and crash only when MTE globals is
+      // supported. Note that MTE globals is unsupported for fully static
+      // executables, but we should still make sure the binary passes its
+      // assertions, just that global variables won't be tagged.
+      (mte_supported() && !is_static) ? -SIGSEGV : 0, "Assertions were passed");
+#else
+  GTEST_SKIP() << "bionic/arm64 only";
+#endif
+}
+
+INSTANTIATE_TEST_SUITE_P(MemtagGlobalsTest, MemtagGlobalsTest, testing::Bool(),
+                         [](const ::testing::TestParamInfo<MemtagGlobalsTest::ParamType>& info) {
+                           if (info.param) return "MemtagGlobalsTest_static";
+                           return "MemtagGlobalsTest";
+                         });
+
+TEST(MemtagGlobalsTest, RelrRegressionTestForb314038442) {
+  SKIP_WITH_HWASAN << "MTE globals tests are incompatible with HWASan";
+#if defined(__BIONIC__) && defined(__aarch64__)
+  std::string binary = GetTestLibRoot() + "/mte_globals_relr_regression_test_b_314038442";
+  chmod(binary.c_str(), 0755);
+  ExecTestHelper eth;
+  eth.SetArgs({binary.c_str(), nullptr});
+  eth.Run(
+      [&]() {
+        execve(binary.c_str(), eth.GetArgs(), eth.GetEnv());
+        GTEST_FAIL() << "Failed to execve: " << strerror(errno) << " " << binary.c_str();
+      },
+      /* exit code */ 0, "Program loaded successfully.*Tags are zero!");
+#else
+  GTEST_SKIP() << "bionic/arm64 only";
+#endif
+}
+
+TEST(MemtagGlobalsTest, RelrRegressionTestForb314038442WithMteGlobals) {
+  if (!mte_supported()) GTEST_SKIP() << "Must have MTE support.";
+#if defined(__BIONIC__) && defined(__aarch64__)
+  std::string binary = GetTestLibRoot() + "/mte_globals_relr_regression_test_b_314038442_mte";
+  chmod(binary.c_str(), 0755);
+  ExecTestHelper eth;
+  eth.SetArgs({binary.c_str(), nullptr});
+  eth.Run(
+      [&]() {
+        execve(binary.c_str(), eth.GetArgs(), eth.GetEnv());
+        GTEST_FAIL() << "Failed to execve: " << strerror(errno) << " " << binary.c_str();
+      },
+      /* exit code */ 0, "Program loaded successfully.*Tags are non-zero");
+#else
+  GTEST_SKIP() << "bionic/arm64 only";
+#endif
+}
diff --git a/tests/memtag_stack_abi_test.cpp b/tests/memtag_stack_abi_test.cpp
new file mode 100644
index 000000000..4725c8dac
--- /dev/null
+++ b/tests/memtag_stack_abi_test.cpp
@@ -0,0 +1,102 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include <filesystem>
+#include <fstream>
+#include <iterator>
+#include <string>
+#include <thread>
+
+#include <dlfcn.h>
+#include <stdlib.h>
+
+#include <android-base/logging.h>
+#include <gtest/gtest.h>
+
+static size_t NumberBuffers() {
+  size_t bufs = 0;
+  std::ifstream file("/proc/self/maps");
+  CHECK(file.is_open());
+  std::string line;
+  while (std::getline(file, line)) {
+    if (line.find("stack_mte_ring") != std::string::npos) {
+      ++bufs;
+    }
+  }
+  return bufs;
+}
+
+static size_t NumberThreads() {
+  std::filesystem::directory_iterator di("/proc/self/task");
+  return std::distance(begin(di), end(di));
+}
+
+TEST(MemtagStackAbiTest, MainThread) {
+#if defined(__BIONIC__) && defined(__aarch64__)
+  ASSERT_EQ(NumberBuffers(), 1U);
+  ASSERT_EQ(NumberBuffers(), NumberThreads());
+#else
+  GTEST_SKIP() << "requires bionic arm64";
+#endif
+}
+
+TEST(MemtagStackAbiTest, JoinableThread) {
+#if defined(__BIONIC__) && defined(__aarch64__)
+  ASSERT_EQ(NumberBuffers(), 1U);
+  ASSERT_EQ(NumberBuffers(), NumberThreads());
+  std::thread th([] {
+    ASSERT_EQ(NumberBuffers(), 2U);
+    ASSERT_EQ(NumberBuffers(), NumberThreads());
+  });
+  th.join();
+  ASSERT_EQ(NumberBuffers(), 1U);
+  ASSERT_EQ(NumberBuffers(), NumberThreads());
+#else
+  GTEST_SKIP() << "requires bionic arm64";
+#endif
+}
+
+TEST(MemtagStackAbiTest, DetachedThread) {
+#if defined(__BIONIC__) && defined(__aarch64__)
+  ASSERT_EQ(NumberBuffers(), 1U);
+  ASSERT_EQ(NumberBuffers(), NumberThreads());
+  std::thread th([] {
+    ASSERT_EQ(NumberBuffers(), 2U);
+    ASSERT_EQ(NumberBuffers(), NumberThreads());
+  });
+  th.detach();
+  // Leave the thread some time to exit.
+  for (int i = 0; NumberBuffers() != 1 && i < 3; ++i) {
+    sleep(1);
+  }
+  ASSERT_EQ(NumberBuffers(), 1U);
+  ASSERT_EQ(NumberBuffers(), NumberThreads());
+#else
+  GTEST_SKIP() << "requires bionic arm64";
+#endif
+}
diff --git a/tests/page_size_16kib_compat_test.cpp b/tests/page_size_16kib_compat_test.cpp
new file mode 100644
index 000000000..a5d91b8c8
--- /dev/null
+++ b/tests/page_size_16kib_compat_test.cpp
@@ -0,0 +1,62 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include "page_size_compat_helpers.h"
+
+#include <android-base/properties.h>
+
+extern "C" void android_set_16kb_appcompat_mode(bool enable_app_compat);
+
+TEST(PageSize16KiBCompatTest, ElfAlignment4KiB_LoadElf) {
+  if (getpagesize() != 0x4000) {
+    GTEST_SKIP() << "This test is only applicable to 16kB page-size devices";
+  }
+
+  bool app_compat_enabled =
+      android::base::GetBoolProperty("bionic.linker.16kb.app_compat.enabled", false);
+  std::string lib = GetTestLibRoot() + "/libtest_elf_max_page_size_4kib.so";
+  void* handle = nullptr;
+
+  OpenTestLibrary(lib, !app_compat_enabled, &handle);
+
+  if (app_compat_enabled) CallTestFunction(handle);
+}
+
+TEST(PageSize16KiBCompatTest, ElfAlignment4KiB_LoadElf_perAppOption) {
+  if (getpagesize() != 0x4000) {
+    GTEST_SKIP() << "This test is only applicable to 16kB page-size devices";
+  }
+
+  android_set_16kb_appcompat_mode(true);
+  std::string lib = GetTestLibRoot() + "/libtest_elf_max_page_size_4kib.so";
+  void* handle = nullptr;
+
+  OpenTestLibrary(lib, false /*should_fail*/, &handle);
+  CallTestFunction(handle);
+  android_set_16kb_appcompat_mode(false);
+}
diff --git a/tests/page_size_compat_helpers.h b/tests/page_size_compat_helpers.h
new file mode 100644
index 000000000..2f0f1d0bb
--- /dev/null
+++ b/tests/page_size_compat_helpers.h
@@ -0,0 +1,75 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ * All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *  * Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *  * Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in
+ *    the documentation and/or other materials provided with the
+ *    distribution.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
+ * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
+ * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
+ * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
+ * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
+ * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
+ * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
+ * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
+ * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
+ * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
+ * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#pragma once
+
+#include "elf_max_page_size.h"
+#include "gtest_globals.h"
+
+#include <android-base/stringprintf.h>
+
+#include <string>
+
+#include <dlfcn.h>
+#include <gtest/gtest.h>
+#include <unistd.h>
+
+static inline void OpenTestLibrary(std::string lib, bool expect_fail, void** handle) {
+  void* _handle = dlopen(lib.c_str(), RTLD_NODELETE);
+  const char* dlopen_error = dlerror();
+
+  if (expect_fail) {
+    ASSERT_EQ(_handle, nullptr);
+
+    const std::string expected_error = android::base::StringPrintf(
+        "dlopen failed: \"%s\" program alignment (%d) cannot be smaller than system page size (%d)",
+        lib.c_str(), 4096, getpagesize());
+
+    ASSERT_EQ(expected_error, dlopen_error);
+  } else {
+    ASSERT_NE(_handle, nullptr) << "Failed to dlopen shared library \"" << lib
+                                << "\": " << dlopen_error;
+  }
+
+  *handle = _handle;
+}
+
+static inline void CallTestFunction(void* handle) {
+  loader_test_func_t loader_test_func = (loader_test_func_t)dlsym(handle, "loader_test_func");
+  const char* dlsym_error = dlerror();
+
+  ASSERT_EQ(dlsym_error, nullptr) << "Failed to locate symbol \"loader_test_func\": "
+                                  << dlsym_error;
+
+  int res = loader_test_func();
+  ASSERT_EQ(res, TEST_RESULT_BASE + TEST_RESULT_INCREMENT);
+
+  // Call loader_test_func() twice to ensure we can modify writeable data and bss data
+  res = loader_test_func();
+  ASSERT_EQ(res, TEST_RESULT_BASE + (2 * TEST_RESULT_INCREMENT));
+}
diff --git a/tests/prebuilt-elf-files/arm64/libtest_invalid-empty_shdr_table.so b/tests/prebuilt-elf-files/arm64/libtest_invalid-empty_shdr_table.so
index c8b543062..21a8f26fa 100755
Binary files a/tests/prebuilt-elf-files/arm64/libtest_invalid-empty_shdr_table.so and b/tests/prebuilt-elf-files/arm64/libtest_invalid-empty_shdr_table.so differ
diff --git a/tests/prebuilt-elf-files/arm64/libtest_invalid-local-tls.so b/tests/prebuilt-elf-files/arm64/libtest_invalid-local-tls.so
index 20c576525..c902bbe22 100755
Binary files a/tests/prebuilt-elf-files/arm64/libtest_invalid-local-tls.so and b/tests/prebuilt-elf-files/arm64/libtest_invalid-local-tls.so differ
diff --git a/tests/prebuilt-elf-files/arm64/libtest_invalid-unaligned_shdr_offset.so b/tests/prebuilt-elf-files/arm64/libtest_invalid-unaligned_shdr_offset.so
index 6e5a6e362..fb86bcacf 100755
Binary files a/tests/prebuilt-elf-files/arm64/libtest_invalid-unaligned_shdr_offset.so and b/tests/prebuilt-elf-files/arm64/libtest_invalid-unaligned_shdr_offset.so differ
diff --git a/tests/prebuilt-elf-files/arm64/libtest_invalid-zero_shdr_table_content.so b/tests/prebuilt-elf-files/arm64/libtest_invalid-zero_shdr_table_content.so
index 14b80b5aa..0416db2b6 100755
Binary files a/tests/prebuilt-elf-files/arm64/libtest_invalid-zero_shdr_table_content.so and b/tests/prebuilt-elf-files/arm64/libtest_invalid-zero_shdr_table_content.so differ
diff --git a/tests/prebuilt-elf-files/arm64/libtest_invalid-zero_shdr_table_offset.so b/tests/prebuilt-elf-files/arm64/libtest_invalid-zero_shdr_table_offset.so
index 0aaca72a8..90892a627 100755
Binary files a/tests/prebuilt-elf-files/arm64/libtest_invalid-zero_shdr_table_offset.so and b/tests/prebuilt-elf-files/arm64/libtest_invalid-zero_shdr_table_offset.so differ
diff --git a/tests/prebuilt-elf-files/gen-libtest_invalid-local-tls.sh b/tests/prebuilt-elf-files/gen-libtest_invalid-local-tls.sh
index 0f3e73628..98a2b0085 100755
--- a/tests/prebuilt-elf-files/gen-libtest_invalid-local-tls.sh
+++ b/tests/prebuilt-elf-files/gen-libtest_invalid-local-tls.sh
@@ -19,12 +19,18 @@ EOF
 build() {
   arch=$1
   target=$2
+
+  if [[ "$arch" == "arm64" || "$arch" == "x86_64" ]]; then
+    alignment="-Wl,-z,max-page-size=16384"
+  fi
+
   $NDK21E/toolchains/llvm/prebuilt/linux-x86_64/bin/clang -O2 --target=$target \
       -fpic -shared -o $arch/libtest_invalid-local-tls.so -fno-emulated-tls \
-      -fuse-ld=gold test.c test2.c
+      $alignment -fuse-ld=gold test.c test2.c
 }
 
 build arm armv7a-linux-androideabi29
 build arm64 aarch64-linux-android29
 build x86 i686-linux-android29
 build x86_64 x86_64-linux-android29
+
diff --git a/tests/prebuilt-elf-files/x86_64/libtest_invalid-empty_shdr_table.so b/tests/prebuilt-elf-files/x86_64/libtest_invalid-empty_shdr_table.so
index af1538dd6..00fefd42c 100755
Binary files a/tests/prebuilt-elf-files/x86_64/libtest_invalid-empty_shdr_table.so and b/tests/prebuilt-elf-files/x86_64/libtest_invalid-empty_shdr_table.so differ
diff --git a/tests/prebuilt-elf-files/x86_64/libtest_invalid-local-tls.so b/tests/prebuilt-elf-files/x86_64/libtest_invalid-local-tls.so
index 5b689ba17..31d2b37a9 100755
Binary files a/tests/prebuilt-elf-files/x86_64/libtest_invalid-local-tls.so and b/tests/prebuilt-elf-files/x86_64/libtest_invalid-local-tls.so differ
diff --git a/tests/prebuilt-elf-files/x86_64/libtest_invalid-unaligned_shdr_offset.so b/tests/prebuilt-elf-files/x86_64/libtest_invalid-unaligned_shdr_offset.so
index 87631af86..f9c310f4c 100755
Binary files a/tests/prebuilt-elf-files/x86_64/libtest_invalid-unaligned_shdr_offset.so and b/tests/prebuilt-elf-files/x86_64/libtest_invalid-unaligned_shdr_offset.so differ
diff --git a/tests/prebuilt-elf-files/x86_64/libtest_invalid-zero_shdr_table_content.so b/tests/prebuilt-elf-files/x86_64/libtest_invalid-zero_shdr_table_content.so
index 27d11387c..3d1f5d3c2 100755
Binary files a/tests/prebuilt-elf-files/x86_64/libtest_invalid-zero_shdr_table_content.so and b/tests/prebuilt-elf-files/x86_64/libtest_invalid-zero_shdr_table_content.so differ
diff --git a/tests/prebuilt-elf-files/x86_64/libtest_invalid-zero_shdr_table_offset.so b/tests/prebuilt-elf-files/x86_64/libtest_invalid-zero_shdr_table_offset.so
index 3e2c1d1d4..aeea1d28b 100755
Binary files a/tests/prebuilt-elf-files/x86_64/libtest_invalid-zero_shdr_table_offset.so and b/tests/prebuilt-elf-files/x86_64/libtest_invalid-zero_shdr_table_offset.so differ
diff --git a/tests/pthread_test.cpp b/tests/pthread_test.cpp
index 2bf755b44..5ce7d4d71 100644
--- a/tests/pthread_test.cpp
+++ b/tests/pthread_test.cpp
@@ -45,6 +45,7 @@
 #include <android-base/test_utils.h>
 
 #include "private/bionic_constants.h"
+#include "private/bionic_time_conversions.h"
 #include "SignalUtils.h"
 #include "utils.h"
 
@@ -2437,23 +2438,25 @@ static void pthread_mutex_timedlock_helper(clockid_t clock,
   ts.tv_sec = -1;
   ASSERT_EQ(ETIMEDOUT, lock_function(&m, &ts));
 
-  // check we wait long enough for the lock.
-  ASSERT_EQ(0, clock_gettime(clock, &ts));
-  const int64_t start_ns = ts.tv_sec * NS_PER_S + ts.tv_nsec;
+  // Check we wait long enough for the lock before timing out...
 
-  // add a second to get deadline.
+  // What time is it before we start?
+  ASSERT_EQ(0, clock_gettime(clock, &ts));
+  const int64_t start_ns = to_ns(ts);
+  // Add a second to get deadline, and wait until we time out.
   ts.tv_sec += 1;
-
   ASSERT_EQ(ETIMEDOUT, lock_function(&m, &ts));
 
+  // What time is it now we've timed out?
+  timespec ts2;
+  clock_gettime(clock, &ts2);
+  const int64_t end_ns = to_ns(ts2);
+
   // The timedlock must have waited at least 1 second before returning.
-  clock_gettime(clock, &ts);
-  const int64_t end_ns = ts.tv_sec * NS_PER_S + ts.tv_nsec;
-  ASSERT_GT(end_ns - start_ns, NS_PER_S);
+  ASSERT_GE(end_ns - start_ns, NS_PER_S);
 
   // If the mutex is unlocked, pthread_mutex_timedlock should succeed.
   ASSERT_EQ(0, pthread_mutex_unlock(&m));
-
   ASSERT_EQ(0, clock_gettime(clock, &ts));
   ts.tv_sec += 1;
   ASSERT_EQ(0, lock_function(&m, &ts));
@@ -2474,12 +2477,19 @@ TEST(pthread, pthread_mutex_timedlock_monotonic_np) {
 #endif  // __BIONIC__
 }
 
-TEST(pthread, pthread_mutex_clocklock) {
+TEST(pthread, pthread_mutex_clocklock_MONOTONIC) {
 #if defined(__BIONIC__)
   pthread_mutex_timedlock_helper(
       CLOCK_MONOTONIC, [](pthread_mutex_t* __mutex, const timespec* __timeout) {
         return pthread_mutex_clocklock(__mutex, CLOCK_MONOTONIC, __timeout);
       });
+#else   // __BIONIC__
+  GTEST_SKIP() << "pthread_mutex_clocklock not available";
+#endif  // __BIONIC__
+}
+
+TEST(pthread, pthread_mutex_clocklock_REALTIME) {
+#if defined(__BIONIC__)
   pthread_mutex_timedlock_helper(
       CLOCK_REALTIME, [](pthread_mutex_t* __mutex, const timespec* __timeout) {
         return pthread_mutex_clocklock(__mutex, CLOCK_REALTIME, __timeout);
@@ -3127,3 +3137,39 @@ TEST(pthread, run_on_all_threads) {
   GTEST_SKIP() << "bionic-only test";
 #endif
 }
+
+TEST(pthread, pthread_getaffinity_np_failure) {
+  // Trivial test of the errno-preserving/returning behavior.
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wnonnull"
+  errno = 0;
+  ASSERT_EQ(EINVAL, pthread_getaffinity_np(pthread_self(), 0, nullptr));
+  ASSERT_ERRNO(0);
+#pragma clang diagnostic pop
+}
+
+TEST(pthread, pthread_getaffinity) {
+  cpu_set_t set;
+  CPU_ZERO(&set);
+  ASSERT_EQ(0, pthread_getaffinity_np(pthread_self(), sizeof(set), &set));
+  ASSERT_GT(CPU_COUNT(&set), 0);
+}
+
+TEST(pthread, pthread_setaffinity_np_failure) {
+  // Trivial test of the errno-preserving/returning behavior.
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wnonnull"
+  errno = 0;
+  ASSERT_EQ(EINVAL, pthread_setaffinity_np(pthread_self(), 0, nullptr));
+  ASSERT_ERRNO(0);
+#pragma clang diagnostic pop
+}
+
+TEST(pthread, pthread_setaffinity) {
+  cpu_set_t set;
+  CPU_ZERO(&set);
+  ASSERT_EQ(0, pthread_getaffinity_np(pthread_self(), sizeof(set), &set));
+  // It's hard to make any more general claim than this,
+  // but it ought to be safe to ask for the same affinity you already have.
+  ASSERT_EQ(0, pthread_setaffinity_np(pthread_self(), sizeof(set), &set));
+}
diff --git a/tests/sched_test.cpp b/tests/sched_test.cpp
index 0231de443..448fae980 100644
--- a/tests/sched_test.cpp
+++ b/tests/sched_test.cpp
@@ -305,8 +305,35 @@ TEST(sched, sched_getscheduler_sched_setscheduler) {
 }
 
 TEST(sched, sched_getaffinity_failure) {
+  // Trivial test of the errno-preserving/returning behavior.
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wnonnull"
   ASSERT_EQ(-1, sched_getaffinity(getpid(), 0, nullptr));
+  ASSERT_ERRNO(EINVAL);
 #pragma clang diagnostic pop
 }
+
+TEST(pthread, sched_getaffinity) {
+  cpu_set_t set;
+  CPU_ZERO(&set);
+  ASSERT_EQ(0, sched_getaffinity(getpid(), sizeof(set), &set));
+  ASSERT_GT(CPU_COUNT(&set), 0);
+}
+
+TEST(sched, sched_setaffinity_failure) {
+  // Trivial test of the errno-preserving/returning behavior.
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wnonnull"
+  ASSERT_EQ(-1, sched_setaffinity(getpid(), 0, nullptr));
+  ASSERT_ERRNO(EINVAL);
+#pragma clang diagnostic pop
+}
+
+TEST(pthread, sched_setaffinity) {
+  cpu_set_t set;
+  CPU_ZERO(&set);
+  ASSERT_EQ(0, sched_getaffinity(getpid(), sizeof(set), &set));
+  // It's hard to make any more general claim than this,
+  // but it ought to be safe to ask for the same affinity you already have.
+  ASSERT_EQ(0, sched_setaffinity(getpid(), sizeof(set), &set));
+}
diff --git a/tests/stdatomic_test.cpp b/tests/stdatomic_test.cpp
index 1c51b118e..8a5408060 100644
--- a/tests/stdatomic_test.cpp
+++ b/tests/stdatomic_test.cpp
@@ -40,7 +40,7 @@ TEST(stdatomic, init) {
   atomic_int v = 123;
   ASSERT_EQ(123, atomic_load(&v));
 
-  atomic_init(&v, 456);
+  atomic_store_explicit(&v, 456, memory_order_relaxed);
   ASSERT_EQ(456, atomic_load(&v));
 
   atomic_flag f = ATOMIC_FLAG_INIT;
@@ -258,9 +258,9 @@ TEST(stdatomic, ordering) {
   // Run a memory ordering smoke test.
   void* result;
   three_atomics a;
-  atomic_init(&a.x, 0ul);
-  atomic_init(&a.y, 0ul);
-  atomic_init(&a.z, 0ul);
+  atomic_store_explicit(&a.x, 0ul, memory_order_relaxed);
+  atomic_store_explicit(&a.y, 0ul, memory_order_relaxed);
+  atomic_store_explicit(&a.z, 0ul, memory_order_relaxed);
   pthread_t t1,t2;
   ASSERT_EQ(0, pthread_create(&t1, nullptr, reader, &a));
   ASSERT_EQ(0, pthread_create(&t2, nullptr, writer, &a));
diff --git a/tests/string_test.cpp b/tests/string_test.cpp
index 6e1fcfc4d..502405f40 100644
--- a/tests/string_test.cpp
+++ b/tests/string_test.cpp
@@ -740,15 +740,11 @@ TEST(STRING_TEST, strncpy) {
     // Set the second half of ptr to the expected pattern in ptr2.
     memset(state.ptr + state.MAX_LEN, '\1', state.MAX_LEN);
     memcpy(state.ptr + state.MAX_LEN, state.ptr1, copy_len);
-    size_t expected_end;
     if (copy_len > ptr1_len) {
       memset(state.ptr + state.MAX_LEN + ptr1_len, '\0', copy_len - ptr1_len);
-      expected_end = ptr1_len;
-    } else {
-      expected_end = copy_len;
     }
 
-    ASSERT_EQ(state.ptr2 + expected_end, stpncpy(state.ptr2, state.ptr1, copy_len));
+    ASSERT_EQ(state.ptr2, strncpy(state.ptr2, state.ptr1, copy_len));
 
     // Verify ptr1 was not modified.
     ASSERT_EQ(0, memcmp(state.ptr1, state.ptr, state.MAX_LEN));
diff --git a/tests/struct_layout_test.cpp b/tests/struct_layout_test.cpp
index 1f04344cd..b9fd31507 100644
--- a/tests/struct_layout_test.cpp
+++ b/tests/struct_layout_test.cpp
@@ -30,7 +30,7 @@ void tests(CheckSize check_size, CheckOffset check_offset) {
 #define CHECK_OFFSET(name, field, offset) \
     check_offset(#name, #field, offsetof(name, field), offset);
 #ifdef __LP64__
-  CHECK_SIZE(pthread_internal_t, 816);
+  CHECK_SIZE(pthread_internal_t, 824);
   CHECK_OFFSET(pthread_internal_t, next, 0);
   CHECK_OFFSET(pthread_internal_t, prev, 8);
   CHECK_OFFSET(pthread_internal_t, tid, 16);
@@ -57,6 +57,7 @@ void tests(CheckSize check_size, CheckOffset check_offset) {
   CHECK_OFFSET(pthread_internal_t, errno_value, 768);
   CHECK_OFFSET(pthread_internal_t, bionic_tcb, 776);
   CHECK_OFFSET(pthread_internal_t, stack_mte_ringbuffer_vma_name_buffer, 784);
+  CHECK_OFFSET(pthread_internal_t, should_allocate_stack_mte_ringbuffer, 816);
   CHECK_SIZE(bionic_tls, 12200);
   CHECK_OFFSET(bionic_tls, key_data, 0);
   CHECK_OFFSET(bionic_tls, locale, 2080);
@@ -74,7 +75,7 @@ void tests(CheckSize check_size, CheckOffset check_offset) {
   CHECK_OFFSET(bionic_tls, bionic_systrace_disabled, 12193);
   CHECK_OFFSET(bionic_tls, padding, 12194);
 #else
-  CHECK_SIZE(pthread_internal_t, 704);
+  CHECK_SIZE(pthread_internal_t, 708);
   CHECK_OFFSET(pthread_internal_t, next, 0);
   CHECK_OFFSET(pthread_internal_t, prev, 4);
   CHECK_OFFSET(pthread_internal_t, tid, 8);
@@ -101,6 +102,7 @@ void tests(CheckSize check_size, CheckOffset check_offset) {
   CHECK_OFFSET(pthread_internal_t, errno_value, 664);
   CHECK_OFFSET(pthread_internal_t, bionic_tcb, 668);
   CHECK_OFFSET(pthread_internal_t, stack_mte_ringbuffer_vma_name_buffer, 672);
+  CHECK_OFFSET(pthread_internal_t, should_allocate_stack_mte_ringbuffer, 704);
   CHECK_SIZE(bionic_tls, 11080);
   CHECK_OFFSET(bionic_tls, key_data, 0);
   CHECK_OFFSET(bionic_tls, locale, 1040);
diff --git a/tests/sys_time_test.cpp b/tests/sys_time_test.cpp
index ff9271f8c..b0e52aac9 100644
--- a/tests/sys_time_test.cpp
+++ b/tests/sys_time_test.cpp
@@ -23,6 +23,7 @@
 
 #include <android-base/file.h>
 
+#include "private/bionic_time_conversions.h"
 #include "utils.h"
 
 // http://b/11383777
@@ -147,14 +148,6 @@ TEST(sys_time, gettimeofday) {
   ASSERT_EQ(0, syscall(__NR_gettimeofday, &tv2, nullptr));
 
   // What's the difference between the two?
-  tv2.tv_sec -= tv1.tv_sec;
-  tv2.tv_usec -= tv1.tv_usec;
-  if (tv2.tv_usec < 0) {
-    --tv2.tv_sec;
-    tv2.tv_usec += 1000000;
-  }
-
   // To try to avoid flakiness we'll accept answers within 10,000us (0.01s).
-  ASSERT_EQ(0, tv2.tv_sec);
-  ASSERT_LT(tv2.tv_usec, 10'000);
+  ASSERT_LT(to_us(tv2) - to_us(tv1), 10'000);
 }
diff --git a/tests/unistd_test.cpp b/tests/unistd_test.cpp
index 78b55c18b..9ad3b6dd4 100644
--- a/tests/unistd_test.cpp
+++ b/tests/unistd_test.cpp
@@ -16,6 +16,7 @@
 
 #include <gtest/gtest.h>
 
+#include "DoNotOptimize.h"
 #include "SignalUtils.h"
 #include "utils.h"
 
diff --git a/tests/utils.h b/tests/utils.h
index 3c83b734d..4740e59ef 100644
--- a/tests/utils.h
+++ b/tests/utils.h
@@ -295,16 +295,6 @@ class FdLeakChecker {
   size_t start_count_ = CountOpenFds();
 };
 
-// From <benchmark/benchmark.h>.
-template <class Tp>
-static inline void DoNotOptimize(Tp const& value) {
-  asm volatile("" : : "r,m"(value) : "memory");
-}
-template <class Tp>
-static inline void DoNotOptimize(Tp& value) {
-  asm volatile("" : "+r,m"(value) : : "memory");
-}
-
 static inline bool running_with_mte() {
 #ifdef __aarch64__
   int level = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
```

