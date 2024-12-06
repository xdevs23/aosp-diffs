```diff
diff --git a/Android.bp b/Android.bp
index bb10b56c..ab519d2b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -46,7 +46,10 @@ cc_defaults {
             enabled: false,
         },
         riscv64: {
-            enabled: false,
+            // TODO(b/123294366): disconnect guest arch from host arch!
+            cflags: [
+                "-DBERBERIS_GUEST_LP64=1",
+            ],
         },
         x86_64: {
             // TODO(b/123294366): disconnect guest arch from host arch!
@@ -77,19 +80,43 @@ cc_defaults {
     },
 }
 
+cc_defaults {
+    name: "berberis_all_hosts_defaults",
+    defaults: ["berberis_defaults"],
+    arch: {
+        arm64: {
+            enabled: true,
+            // TODO(b/123294366): disconnect guest arch from host arch!
+            cflags: [
+                "-DNATIVE_BRIDGE_GUEST_ARCH_RISCV64",
+                "-DBERBERIS_GUEST_LP64=1",
+            ],
+        },
+    },
+}
+
 cc_defaults {
     name: "berberis_defaults_64",
     defaults: ["berberis_defaults"],
     compile_multilib: "64",
 }
 
+cc_defaults {
+    name: "berberis_all_hosts_defaults_64",
+    defaults: ["berberis_all_hosts_defaults"],
+    compile_multilib: "64",
+}
+
 cc_defaults {
     name: "berberis_arm64_defaults",
     defaults: ["berberis_guest_agnostic_defaults"],
     compile_multilib: "64",
     arch: {
+        // TODO(b/123294366): disconnect guest arch from host arch!
         x86_64: {
-            // TODO(b/123294366): disconnect guest arch from host arch!
+            cflags: ["-DNATIVE_BRIDGE_GUEST_ARCH_ARM64"],
+        },
+        riscv64: {
             cflags: ["-DNATIVE_BRIDGE_GUEST_ARCH_ARM64"],
         },
     },
@@ -130,8 +157,10 @@ cc_library_shared {
         "libbase",
         "libberberis_assembler",
         "libberberis_base",
+        "libberberis_base_elf_backed_exec_region",
         "libberberis_instrument",
         "libberberis_intrinsics",
+        "libberberis_kernel_api_riscv64",
         "libberberis_runtime_primitives",
         "libberberis_tinyloader",
     ],
@@ -152,7 +181,6 @@ cc_library_shared {
                 "libberberis_guest_abi_riscv64",
                 "libberberis_heavy_optimizer_riscv64",
                 "libberberis_interpreter_riscv64",
-                "libberberis_kernel_api_riscv64",
                 "libberberis_lite_translator_riscv64_to_x86_64",
                 "libberberis_macro_assembler_riscv64_to_x86_64",
                 "libberberis_intrinsics_riscv64",
@@ -193,6 +221,7 @@ cc_test_host {
     static_libs: [
         "libberberis_assembler",
         "libberberis_base",
+        "libberberis_base_elf_backed_exec_region",
         "libberberis_intrinsics",
         "libberberis_instrument",
         "libberberis_runtime_primitives",
@@ -206,12 +235,18 @@ cc_test_host {
     whole_static_libs: [
         "libberberis_assembler_unit_tests",
         "libberberis_base_unit_tests",
+        "libberberis_base_elf_backed_exec_region_unit_tests",
         "libberberis_calling_conventions_unit_tests",
         "libberberis_intrinsics_unit_tests",
         "libberberis_tinyloader_unit_tests",
         "libberberis_runtime_primitives_unit_tests",
     ],
     arch: {
+        arm64: {
+            srcs: [
+                "base/raw_syscall_tests.cc",
+            ],
+        },
         x86: {
             srcs: [
                 "base/raw_syscall_tests.cc",
@@ -223,6 +258,9 @@ cc_test_host {
             ],
             static_libs: [
                 "libberberis_backend_riscv64_to_x86_64",
+                // Note: we don't even need to use anything from that library, just need to ensure it
+                // can be compiled successfully: all checks are done with static_asserts.
+                "libberberis_emulated_libvulkan_api_checker",
                 "libberberis_guest_abi_riscv64",
                 "libberberis_guest_os_primitives_riscv64",
                 "libberberis_guest_state_riscv64",
@@ -262,21 +300,15 @@ cc_test_host {
     },
 }
 
-// The following are the dependencies of `berberis_all` for `arm_to_x86`
-// Note: When the variables `BERBERIS_PRODUCT_PACKAGES` and
-//      `BERBERIS_DEV_PRODUCT_PACKAGES`, in `berberis_config.mk` are modified,
-//      please also change the `berberis_deps_defaults`.
 phony_rule_defaults {
-    name: "berberis_deps_defaults",
+    name: "berberis_all_deps_defaults",
     phony_deps: [
-        // BERBERIS_PRODUCT_PACKAGES
-        "libberberis_exec_region",
-        // BERBERIS_DEV_PRODUCT_PACKAGES
         "berberis_hello_world.native_bridge",
         "berberis_hello_world_static.native_bridge",
         "berberis_host_tests",
         "berberis_ndk_program_tests",
         "berberis_ndk_program_tests.native_bridge",
+        "berberis_perf_tests_static.native_bridge",
         "dwarf_reader",
         "libberberis_emulated_libcamera2ndk_api_checker",
         "nogrod_unit_tests",
@@ -284,16 +316,13 @@ phony_rule_defaults {
     ],
 }
 
-// Note: When the variables `BERBERIS_PRODUCT_PACKAGES_RISCV64_TO_X86_64` and
-//      `BERBERIS_DEV_PRODUCT_PACKAGES_RISCV64_TO_X86_64` in
-//      `berberis_config.mk` and the variables `NATIVE_BRIDGE_PRODUCT_PACKAGES`,
-//      `NATIVE_BRIDGE_ORIG_GUEST_LIBS`, `NATIVE_BRIDGE_MODIFIED_GUEST_LIBS`
-//      in `frameworks/libs/native_bridge_support/native_bridge_support.mk` are
-//      modified, please also change the `berberis_riscv64_to_x86_64_defaults`.
+// Note: Keep in sync with variables from `berberis_config.mk` and
+// `frameworks/libs/native_bridge_support/native_bridge_support.mk` indicated below.
 phony_rule_defaults {
-    name: "berberis_riscv64_to_x86_64_defaults",
+    name: "berberis_all_riscv64_to_x86_64_defaults",
     phony_deps: [
         // BERBERIS_PRODUCT_PACKAGES_RISCV64_TO_X86_64
+        "libberberis_exec_region",
         "libberberis_proxy_libEGL",
         "libberberis_proxy_libGLESv1_CM",
         "libberberis_proxy_libGLESv2",
@@ -358,7 +387,7 @@ phony_rule_defaults {
         "libnative_bridge_guest_libOpenSLES.native_bridge",
         "libnative_bridge_guest_libvulkan.native_bridge",
         "libnative_bridge_guest_libwebviewchromium_plat_support.native_bridge",
-        // BERBERIS_DEV_PRODUCT_PACKAGES_RISCV64_TO_X86_64
+        // Everything else.
         "berberis_guest_loader_riscv64_tests",
     ],
 }
@@ -388,8 +417,8 @@ berberis_phony_rule {
         translation_arch: {
             riscv64_to_x86_64: {
                 defaults: [
-                    "berberis_deps_defaults",
-                    "berberis_riscv64_to_x86_64_defaults",
+                    "berberis_all_deps_defaults",
+                    "berberis_all_riscv64_to_x86_64_defaults",
                 ],
                 enabled: true,
             },
diff --git a/README.md b/README.md
index f54367c4..6f529098 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,238 @@
-Berberis: dynamic binary translator to run Android apps
-with riscv64 native code on x86_64 devices or emulators.
+# Berberis
+
+Dynamic binary translator to run Android apps with riscv64 native code on x86_64 devices or emulators.
+
+Supported extensions include Zb* (bit manipulation) and most of Zv (vector). Some less commonly used vector instructions are not yet implemented, but Android CTS and some Android apps run with the current set of implemented instructions.
+
+Public mailing list: berberis-discuss@googlegroups.com
+
+## Getting Started
+
+Note: Googlers, read go/berberis and go/berberis-start first.
+
+### Build
+
+From your Android root checkout, run:
+
+```
+source build/envsetup.sh
+lunch sdk_phone64_x86_64_riscv64-trunk_staging-eng
+m berberis_all
+```
+
+For development, we recommend building all existing targets before uploading changes, since they are currently not always synchronized with `berberis_all`:
+
+```
+mmm frameworks/libs/binary_translation
+```
+
+### Run Hello World
+
+```
+out/host/linux-x86/bin/berberis_program_runner_riscv64 \
+out/target/product/emu64xr/testcases/berberis_hello_world_static.native_bridge/x86_64/berberis_hello_world_static
+```
+
+On success `Hello!` will be printed.
+
+### Run unit tests on host
+
+```
+m berberis_all berberis_run_host_tests
+```
+
+or
+
+```
+out/host/linux-x86/nativetest64/berberis_host_tests/berberis_host_tests
+```
+
+### Build and run emulator with Berberis support
+
+```
+m
+emulator -memory 4096 -writable-system -partition-size 65536 -qemu -cpu host &
+```
+
+### Run unit tests on device or emulator
+
+Note: Requires a running device or emulator with Berberis support.
+
+1. Sync tests to the device:
+
+```
+adb root
+adb sync data
+```
+
+2. Run guest loader tests:
+
+```
+adb shell /data/nativetest64/berberis_guest_loader_riscv64_tests/berberis_guest_loader_riscv64_tests
+```
+
+3. Run program tests:
+
+```
+adb shell /data/nativetest64/berberis_ndk_program_tests/berberis_ndk_program_tests
+```
+
+## Bionic unit tests
+
+Note: Requires a running device or emulator with Berberis support.
+
+1. Build Bionic unit tests:
+
+```
+m TARGET_PRODUCT=aosp_riscv64 bionic-unit-tests
+```
+
+2. Push tests to emulator or device:
+
+```
+adb push out/target/product/generic_riscv64/data/nativetest64/bionic-loader-test-libs /data/local/tmp
+adb push out/target/product/generic_riscv64/data/nativetest64/bionic-unit-tests /data/local/tmp
+```
+
+3. Run Bionic tests:
+
+```
+adb shell /system/bin/berberis_program_runner_riscv64 /data/local/tmp/bionic-unit-tests/bionic-unit-tests
+```
+
+## Development
+
+### Running Android Apps (APKs) on Berberis Emulator
+
+The steps for running Android apps on a Berberis emulator simply involve building and running the emulator (see instructions above), building your Android app, then installing it onto the emulator using `adb`.
+
+For example you can build then run the JNI test APK (see `tests/jni_tests/README.txt`) by running:
+
+```
+m TARGET_BUILD_VARIANT=userdebug TARGET_PRODUCT=aosp_riscv64 berberis_jni_tests
+```
+
+Install the app:
+
+```
+adb install out/target/product/generic_riscv64/testcases/berberis_jni_tests/riscv64/berberis_jni_tests.apk
+```
+
+Start the app:
+
+```
+adb shell am instrument -w com.berberis.jnitests/androidx.test.runner.AndroidJUnitRunner
+```
+
+Uninstall the app:
+
+```
+adb uninstall com.berberis.jnitests
+```
+
+## Debugging
+
+### Crash Reporting for Guest State
+
+When native code crashes a basic crash dump is written to `logcat` and a more detailed tombstone file is written to `/data/tombstones`. The tombstone file contains extra data about the crashed process. In particular, it contains stack traces for all the host threads and guest threads in the crashing process (not just the thread that caught the signal), a full memory map, and a list of all open file descriptors.
+
+To find the tombstone file, use `adb` to access the device or emulator (run `adb root` if you don't have permissions) and locate the file:
+
+```
+$ adb shell ls /data/tombstones/
+tombstone_00  tombstone_00.pb
+```
+`tombstone_00` is the output in human-readable text.
+
+Note: Guest thread information follows host thread information whenever it is available.
+
+Example tombstone output:
+
+```
+*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
+Build fingerprint: 'Android/sdk_phone64_x86_64_riscv64/emu64xr:VanillaIceCream/MAIN/eng.sijiec.20240510.182325:eng/test-keys'
+Revision: '0'
+ABI: 'x86_64'
+Guest architecture: 'riscv64'
+Timestamp: 2024-05-13 18:38:56.175592859+0000
+Process uptime: 3s
+Cmdline: com.berberis.jnitests
+pid: 2875, tid: 2896, name: roidJUnitRunner  >>> com.berberis.jnitests <<<
+uid: 10147
+signal 11 (SIGSEGV), code -6 (SI_TKILL), fault addr --------
+    rax 0000000000000000  rbx 00007445aebb0000  rcx 000074458c73df08  rdx 000000000000000b
+    r8  00007442f18487d0  r9  00007442f18487d0  r10 00007442ecc87770  r11 0000000000000206
+    r12 0000000000000000  r13 00000000002e4e64  r14 00007445aebaf020  r15 00007442ed113d10
+    rdi 0000000000000b3b  rsi 0000000000000b50
+    rbp 00000000aebaf401  rsp 00007442ed111948  rip 000074458c73df08
+
+7 total frames
+backtrace:
+      #00 pc 0000000000081f08  /apex/com.android.runtime/lib64/bionic/libc.so (syscall+24) (BuildId: 071397dbd1881d18b5bff5dbfbd86eb7)
+      #01 pc 00000000014cca92  /system/lib64/libberberis_riscv64.so (berberis::RunGuestSyscall(berberis::ThreadState*)+82) (BuildId: f3326eacda7666bc0e85d13ef7281630)
+      #02 pc 000000000037d955  /system/lib64/libberberis_riscv64.so (berberis::Decoder<berberis::SemanticsPlayer<berberis::Interpreter> >::DecodeSystem()+133) (BuildId: f3326eacda7666bc0e85d13ef7281630)
+      #03 pc 000000000037b4cf  /system/lib64/libberberis_riscv64.so (berberis::Decoder<berberis::SemanticsPlayer<berberis::Interpreter> >::DecodeBaseInstruction()+831) (BuildId: f3326eacda7666bc0e85d13ef7281630)
+      #04 pc 000000000037a9f4  /system/lib64/libberberis_riscv64.so (berberis::InterpretInsn(berberis::ThreadState*)+100) (BuildId: f3326eacda7666bc0e85d13ef7281630)
+      #05 pc 00000000002c7325  /system/lib64/libberberis_riscv64.so (berberis_entry_Interpret+21) (BuildId: f3326eacda7666bc0e85d13ef7281630)
+      #06 pc 114f9329b57c0dac  <unknown>
+
+memory near rbx:
+    00007445aebaffe0 0000000000000000 0000000000000000  ................
+    00007445aebafff0 0000000000000000 0000000000000000  ................
+    00007445aebb0000 0000000000000000 00007442ecdb2000  ......... ..Bt..
+    00007445aebb0010 0000000000125000 0000000000010000  .P..............
+    00007445aebb0020 0000000000125000 00007442eced6ff0  .P.......o..Bt..
+    00007445aebb0030 00007445aebae000 000074428dee7000  ....Et...p..Bt..
+    00007445aebb0040 000074428dee8000 00007445aebaf020  ....Bt.. ...Et..
+    00007445aebb0050 0000000000000000 0000000000000000  ................
+    00007445aebb0060 00007442e7d9b448 00007443b7836ce0  H...Bt...l..Ct..
+    00007445aebb0070 00007442ed111ab0 0000000000000000  ....Bt..........
+    00007445aebb0080 0000000000000000 0000000000000000  ................
+    00007445aebb0090 0000000000000000 0000000000000000  ................
+    00007445aebb00a0 0000000000000000 0000000000000000  ................
+    00007445aebb00b0 0000000000000000 0000000000000000  ................
+    00007445aebb00c0 0000000000000000 0000000000000000  ................
+    00007445aebb00d0 0000000000000000 0000000000000000  ................
+
+...snippet
+
+05-13 18:38:55.898  2875  2896 I TestRunner: finished: testGetVersion(com.berberis.jnitests.JniTests)
+05-13 18:38:55.900  2875  2896 I TestRunner: started: testRegisterNatives(com.berberis.jnitests.JniTests)
+--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---
+Guest thread information for tid: 2896
+    pc  00007442942e4e64  ra  00007442ecc88b08  sp  00007442eced6fc0  gp  000074428dee8000
+    tp  00007445aebae050  t0  0000000000000008  t1  00007442942ffb4c  t2  0000000000000000
+    t3  00007442942e4e60  t4  0000000000000000  t5  8d38b33c8bd53145  t6  736574696e6a2e73
+    s0  00007442eced6fe0  s1  000000000000002a  s2  0000000000000000  s3  0000000000000000
+    s4  0000000000000000  s5  0000000000000000  s6  0000000000000000  s7  0000000000000000
+    s8  0000000000000000  s9  0000000000000000  s10 0000000000000000  s11 0000000000000000
+    a0  0000000000000b3b  a1  0000000000000b50  a2  000000000000000b  a3  00007442ecc87770
+    a4  00007442f18487d0  a5  00007442f18487d0  a6  00007442f18487d0  a7  0000000000000083
+    vlenb 0000000000000000
+
+3 total frames
+backtrace:
+      #00 pc 000000000008de64  /system/lib64/riscv64/libc.so (tgkill+4) (BuildId: 7daa7d467f152da57592545534afd2ee)
+      #01 pc 0000000000001b04  /data/app/~~_CJlJwewmTxNSIr4kxVv7w==/com.berberis.jnitests-7MJzLGAPUFFAMt5wl-D-Hg==/base.apk!libberberis_jni_tests.so (offset 0x1000) ((anonymous namespace)::add42(_JNIEnv*, _jclass*, int)+18) (BuildId: 665cb51828ad4b5e3ddf149af15b31cc)
+      #02 pc 0000000000001004  /system/lib64/riscv64/libnative_bridge_vdso.so (BuildId: 3df95df99d97cad076b80c56aa20c552)
+
+memory near pc (/system/lib64/riscv64/libc.so):
+    00007442942e4e40 0000007308100893 01157363288578fd  ....s....x.(cs..
+    00007442942e4e50 b39540a005338082 0000001300000013  ..3..@..........
+    00007442942e4e60 0000007308300893 01157363288578fd  ..0.s....x.(cs..
+    00007442942e4e70 b39140a005338082 0000001300000013  ..3..@..........
+    00007442942e4e80 000000730d600893 01157363288578fd  ..`.s....x.(cs..
+    00007442942e4e90 b31540a005338082 0000001300000013  ..3..@..........
+    00007442942e4ea0 000000730dd00893 01157363288578fd  ....s....x.(cs..
+    00007442942e4eb0 b31140a005338082 0000001300000013  ..3..@..........
+    00007442942e4ec0 0000007307500893 01157363288578fd  ..P.s....x.(cs..
+    00007442942e4ed0 b1d540a005338082 0000001300000013  ..3..@..........
+    00007442942e4ee0 000000730a500893 01157363288578fd  ..P.s....x.(cs..
+    00007442942e4ef0 b1d140a005338082 0000001300000013  ..3..@..........
+    00007442942e4f00 0000007308d00893 01157363288578fd  ....s....x.(cs..
+    00007442942e4f10 b15540a005338082 0000001300000013  ..3..@U.........
+    00007442942e4f20 0000007308c00893 01157363288578fd  ....s....x.(cs..
+    00007442942e4f30 b15140a005338082 0000001300000013  ..3..@Q.........
+
+...snippet
+```
diff --git a/android_api/libvulkan/Android.bp b/android_api/libvulkan/Android.bp
index 657c0f6f..55dff3d2 100644
--- a/android_api/libvulkan/Android.bp
+++ b/android_api/libvulkan/Android.bp
@@ -43,3 +43,25 @@ cc_library_shared {
     },
     shared_libs: ["libvulkan"],
 }
+
+cc_library_static {
+    name: "libberberis_emulated_libvulkan_api_checker",
+    defaults: ["berberis_defaults_64"],
+    host_supported: true,
+    native_bridge_supported: true,
+    srcs: [":native_bridge_proxy_libvulkan_checker"],
+    header_libs: [
+        "hwvulkan_headers",
+        "libberberis_base_headers",
+        "vulkan_headers",
+    ],
+    arch: {
+        riscv64: {
+            enabled: true,
+            generated_headers: ["libberberis_android_api_libvulkan_vulkan_xml_headers_riscv64_to_x86_64"],
+        },
+        x86_64: {
+            generated_headers: ["libberberis_android_api_libvulkan_vulkan_xml_headers_riscv64_to_x86_64"],
+        },
+    },
+}
diff --git a/assembler/Android.bp b/assembler/Android.bp
index 24a4a70c..e0f38f50 100644
--- a/assembler/Android.bp
+++ b/assembler/Android.bp
@@ -18,9 +18,9 @@ package {
 }
 
 python_binary_host {
-    name: "gen_asm_x86",
-    main: "gen_asm_x86.py",
-    srcs: ["gen_asm_x86.py"],
+    name: "gen_asm",
+    main: "gen_asm.py",
+    srcs: ["gen_asm.py"],
     libs: ["asm_defs_lib"],
 }
 
@@ -29,7 +29,7 @@ python_binary_host {
     main: "gen_asm_tests_x86.py",
     srcs: [
         "gen_asm_tests_x86.py",
-        "gen_asm_x86.py",
+        "gen_asm.py",
     ],
     libs: ["asm_defs_lib"],
 }
@@ -39,6 +39,22 @@ python_library_host {
     srcs: ["asm_defs.py"],
 }
 
+filegroup {
+    name: "libberberis_assembler_gen_inputs_riscv32",
+    srcs: [
+        "instructions/insn_def_riscv.json",
+        "instructions/insn_def_rv32.json",
+    ],
+}
+
+filegroup {
+    name: "libberberis_assembler_gen_inputs_riscv64",
+    srcs: [
+        "instructions/insn_def_riscv.json",
+        "instructions/insn_def_rv64.json",
+    ],
+}
+
 filegroup {
     name: "libberberis_assembler_gen_inputs_x86_32",
     srcs: [
@@ -55,39 +71,65 @@ filegroup {
     ],
 }
 
+genrule {
+    name: "libberberis_assembler_gen_public_headers_riscv32",
+    out: [
+        "berberis/assembler/gen_assembler_common_riscv-inl.h",
+        "berberis/assembler/gen_assembler_rv32-inl.h",
+    ],
+    srcs: [":libberberis_assembler_gen_inputs_riscv32"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_assembler_gen_public_headers_riscv64",
+    out: [
+        "berberis/assembler/gen_assembler_common_riscv-inl.h",
+        "berberis/assembler/gen_assembler_rv64-inl.h",
+    ],
+    srcs: [":libberberis_assembler_gen_inputs_riscv64"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
+}
+
 genrule {
     name: "libberberis_assembler_gen_public_headers_x86_32",
     out: [
-        "berberis/assembler/gen_assembler_common_x86-inl.h",
+        "berberis/assembler/gen_assembler_x86_32_and_x86_64-inl.h",
         "berberis/assembler/gen_assembler_x86_32-inl.h",
     ],
     srcs: [":libberberis_assembler_gen_inputs_x86_32"],
-    tools: ["gen_asm_x86"],
-    cmd: "$(location gen_asm_x86) --binary-assembler $(out) $(in)",
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
 }
 
 genrule {
     name: "libberberis_assembler_gen_public_headers_x86_64",
     out: [
-        "berberis/assembler/gen_assembler_common_x86-inl.h",
+        "berberis/assembler/gen_assembler_x86_32_and_x86_64-inl.h",
         "berberis/assembler/gen_assembler_x86_64-inl.h",
     ],
     srcs: [":libberberis_assembler_gen_inputs_x86_64"],
-    tools: ["gen_asm_x86"],
-    cmd: "$(location gen_asm_x86) --binary-assembler $(out) $(in)",
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
 }
 
 cc_library_headers {
     name: "libberberis_assembler_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     header_libs: ["libberberis_base_headers"],
     export_header_lib_headers: ["libberberis_base_headers"],
     generated_headers: [
+        "libberberis_assembler_gen_public_headers_riscv32",
+        "libberberis_assembler_gen_public_headers_riscv64",
         "libberberis_assembler_gen_public_headers_x86_32",
         "libberberis_assembler_gen_public_headers_x86_64",
     ],
     export_generated_headers: [
+        "libberberis_assembler_gen_public_headers_riscv32",
+        "libberberis_assembler_gen_public_headers_riscv64",
         "libberberis_assembler_gen_public_headers_x86_32",
         "libberberis_assembler_gen_public_headers_x86_64",
     ],
@@ -131,6 +173,7 @@ cc_test_library {
     header_libs: ["berberis_test_utils_headers"],
     srcs: [
         "assembler_test.cc",
+        "immediates_test.cc",
         "machine_code_test.cc",
     ],
     generated_sources: ["libberberis_assembler_test_gen_sources"],
diff --git a/assembler/asm_defs.py b/assembler/asm_defs.py
index 2e0e4204..530b1d60 100644
--- a/assembler/asm_defs.py
+++ b/assembler/asm_defs.py
@@ -47,10 +47,10 @@ Each instruction is an object with following fields:
            and how it is treated by an instruction (used, defined,
            both used and defined)
   'asm' - which internal assembler's mnemonic is used
-  'opcodes' - optional flag for autogeneration: if opcode bytes are specified
-              then implementation would be automatically generated
-  'reg_to_rm' - optional flag to make RM field in ModRegRM byte destination
-                (most instructions with two registers use reg as destination)
+  'opcode' | 'opcodes' - optional flag for autogeneration:
+                         if opcode bytes are specified then implementation
+                         would be automatically generated
+  'type' - optional flag to specify extra information (encoded in the name).
   'mnemo' - how instruction shall be named in LIR dumps (ignored here)
 
 Memory operand for assembler instructions can be described as either opaque
@@ -73,10 +73,15 @@ argument's class.
 
 import copy
 import json
+import re
 
 
 def is_imm(arg_type):
-  return arg_type in ('Imm2', 'Imm8', 'Imm16', 'Imm32', 'Imm64')
+  return arg_type in (
+    'Imm2', 'Imm8', 'Imm16', 'Imm32', 'Imm64', # x86 immediates
+    'B-Imm', 'I-Imm', 'J-Imm', 'P-Imm', 'S-Imm', 'U-Imm', # Official RISC-V immediates
+    'Csr-Imm', 'Shift32-Imm', 'Shift64-Imm', # Extra RISC-V immediates
+  )
 
 
 def is_disp(arg_type):
@@ -84,15 +89,25 @@ def is_disp(arg_type):
 
 
 def is_mem_op(arg_type):
-  return arg_type in ('Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
-                      'MemX87', 'MemX8716', 'MemX8732', 'MemX8764', 'MemX8780',
-                      'VecMem32', 'VecMem64', 'VecMem128')
+  return arg_type in (
+    # Universal memory operands
+    'Mem', 'Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
+    # x86 memory operands
+    'MemX87', 'MemX8716', 'MemX8732', 'MemX8764', 'MemX8780', 'VecMem32', 'VecMem64', 'VecMem128')
 
 
 def is_cond(arg_type):
   return arg_type == 'Cond'
 
 
+def is_csr(arg_type):
+  return arg_type == 'CsrReg'
+
+
+def is_rm(arg_type):
+  return arg_type == 'Rm'
+
+
 def is_label(arg_type):
   return arg_type == 'Label'
 
@@ -107,6 +122,10 @@ def is_greg(arg_type):
                       'GeneralReg32', 'GeneralReg64')
 
 
+def is_freg(arg_type):
+  return arg_type == 'FpReg'
+
+
 def is_xreg(arg_type):
   return arg_type in ('XmmReg',
                       'VecReg64', 'VecReg128',
@@ -132,12 +151,16 @@ def get_mem_macro_name(insn, addr_mode = None):
     macro_name = macro_name[:-4]
   for arg in insn['args']:
     clazz = arg['class']
-    # Don't reflect FLAGS or Conditions or Labels in the name - we don't ever
+    # Don't reflect FLAGS/Conditions/Csrs/Labels in the name - we don't ever
     # have two different instructions where these cause the difference.
-    if clazz == 'FLAGS' or is_cond(clazz) or is_label(clazz):
+    if clazz == 'FLAGS' or is_cond(clazz) or is_label(clazz) or is_csr(clazz):
       pass
+    elif is_rm(clazz):
+      macro_name += 'Rm'
     elif is_x87reg(clazz) or is_greg(clazz) or is_implicit_reg(clazz):
       macro_name += 'Reg'
+    elif is_freg(clazz):
+      macro_name += 'FReg'
     elif is_xreg(clazz):
       macro_name += 'XReg'
     elif is_imm(clazz):
@@ -152,6 +175,11 @@ def get_mem_macro_name(insn, addr_mode = None):
   return macro_name
 
 
+def _get_cxx_name(name):
+  return ''.join(w if re.search('[A-Z]', w) else w.capitalize()
+                 for w in re.split('[-_. ]', name))
+
+
 def _expand_name(insn, stem, encoding = {}):
   # Make deep copy of the instruction to make sure consumers could treat them
   # as independent entities and add/remove marks freely.
@@ -159,7 +187,9 @@ def _expand_name(insn, stem, encoding = {}):
   # JSON never have "merged" objects thus having them in result violates
   # expectations.
   expanded_insn = copy.deepcopy(insn)
-  expanded_insn['asm'] = stem
+  # Native assembler name may include dots, spaces, etc. Keep it for text assembler.
+  expanded_insn["native-asm"] = stem
+  expanded_insn['asm'] = _get_cxx_name(stem)
   expanded_insn['name'] = get_mem_macro_name(expanded_insn)
   expanded_insn['mnemo'] = stem.upper()
   expanded_insn.update(encoding)
@@ -172,7 +202,8 @@ def _expand_insn_by_encodings(insns):
     if insn.get('encodings'):
       assert all((f not in insn) for f in ['stems', 'name', 'asm', 'mnemo'])
       # If we have encoding then we must have at least opcodes
-      assert all('opcodes' in encoding for _, encoding in insn['encodings'].items())
+      assert all('opcode' in encoding or 'opcodes' in encoding
+                  for _, encoding in insn['encodings'].items())
       expanded_insns.extend([_expand_name(insn, stem, encoding)
                             for stem, encoding in insn['encodings'].items()])
     elif insn.get('stems'):
diff --git a/assembler/assembler_test.cc b/assembler/assembler_test.cc
index 1f86404c..9ec9f91a 100644
--- a/assembler/assembler_test.cc
+++ b/assembler/assembler_test.cc
@@ -18,10 +18,14 @@
 
 #include <sys/mman.h>
 
+#include <cstring>
 #include <iterator>
 #include <string>
 
 #include "berberis/assembler/machine_code.h"
+#include "berberis/assembler/rv32e.h"
+#include "berberis/assembler/rv32i.h"
+#include "berberis/assembler/rv64i.h"
 #include "berberis/assembler/x86_32.h"
 #include "berberis/assembler/x86_64.h"
 #include "berberis/base/bit_util.h"
@@ -46,12 +50,13 @@ float FloatFunc(float f1, float f2) {
   return f1 - f2;
 }
 
-inline bool CompareCode(const uint8_t* code_template_begin,
-                        const uint8_t* code_template_end,
+template <typename ParcelInt>
+inline bool CompareCode(const ParcelInt* code_template_begin,
+                        const ParcelInt* code_template_end,
                         const MachineCode& code) {
-  if ((code_template_end - code_template_begin) != static_cast<intptr_t>(code.install_size())) {
+  if ((code_template_end - code_template_begin) * sizeof(ParcelInt) != code.install_size()) {
     ALOGE("Code size mismatch: %zd != %u",
-          code_template_end - code_template_begin,
+          (code_template_end - code_template_begin) * static_cast<unsigned>(sizeof(ParcelInt)),
           code.install_size());
     return false;
   }
@@ -69,13 +74,318 @@ inline bool CompareCode(const uint8_t* code_template_begin,
   return true;
 }
 
-#if defined(__i386__)
+namespace rv32 {
+
+bool AssemblerTest() {
+  MachineCode code;
+  Assembler assembler(&code);
+  Assembler::Label data_begin, data_end, label;
+  assembler.Bind(&data_begin);
+  // We test loads and stores twice to ensure that both positive and negative immediates are
+  // present both in auipc and in the follow-up load/store instructions.
+  assembler.Fld(Assembler::f1, data_end, Assembler::x2);
+  assembler.Flw(Assembler::f3, data_end, Assembler::x4);
+  assembler.Fsd(Assembler::f5, data_end, Assembler::x6);
+  assembler.Fsw(Assembler::f7, data_end, Assembler::x8);
+  assembler.Lb(Assembler::x9, data_end);
+  assembler.Lbu(Assembler::x10, data_end);
+  assembler.Lh(Assembler::x11, data_end);
+  assembler.Lhu(Assembler::x12, data_end);
+  assembler.Lw(Assembler::x13, data_end);
+  assembler.Sb(Assembler::x14, data_end, Assembler::x15);
+  assembler.Sh(Assembler::x16, data_end, Assembler::x17);
+  assembler.Sw(Assembler::x18, data_end, Assembler::x19);
+  assembler.Lla(Assembler::x20, data_end);
+  assembler.Bcc(Assembler::Condition::kEqual, Assembler::x1, Assembler::x2, label);
+  assembler.Bcc(Assembler::Condition::kNotEqual, Assembler::x3, Assembler::x4, label);
+  assembler.Bcc(Assembler::Condition::kLess, Assembler::x5, Assembler::x6, label);
+  assembler.Bcc(Assembler::Condition::kGreaterEqual, Assembler::x7, Assembler::x8, label);
+  assembler.Bcc(Assembler::Condition::kBelow, Assembler::x9, Assembler::x10, label);
+  assembler.Bcc(Assembler::Condition::kAboveEqual, Assembler::x11, Assembler::x12, label);
+  assembler.Jal(Assembler::x1, label);
+  assembler.Add(Assembler::x1, Assembler::x2, Assembler::x3);
+  assembler.Addi(Assembler::x1, Assembler::x2, 42);
+  assembler.Bind(&label);
+  // Jalr have two alternate forms.
+  assembler.Jalr(Assembler::x1, Assembler::x2, 42);
+  assembler.Jalr(Assembler::x3, {.base = Assembler::x4, .disp = 42});
+  assembler.Sw(Assembler::x1, {.base = Assembler::x2, .disp = 42});
+  assembler.Jal(Assembler::x2, label);
+  assembler.Beq(Assembler::x1, Assembler::x2, label);
+  assembler.Bne(Assembler::x3, Assembler::x4, label);
+  assembler.Blt(Assembler::x5, Assembler::x6, label);
+  assembler.Bge(Assembler::x7, Assembler::x8, label);
+  assembler.Bltu(Assembler::x9, Assembler::x10, label);
+  assembler.Bgeu(Assembler::x11, Assembler::x12, label);
+  assembler.Csrrc(Assembler::x1, Assembler::Csr::kVl, Assembler::x2);
+  assembler.Csrrs(Assembler::x3, Assembler::Csr::kVtype, Assembler::x4);
+  assembler.Csrrw(Assembler::x5, Assembler::Csr::kVlenb, Assembler::x6);
+  assembler.Slli(Assembler::x1, Assembler::x2, 3);
+  assembler.Srai(Assembler::x4, Assembler::x5, 6);
+  assembler.Srli(Assembler::x7, Assembler::x8, 9);
+  assembler.FcvtSW(Assembler::f1, Assembler::x2, Assembler::Rounding::kRmm);
+  assembler.FcvtSWu(Assembler::f3, Assembler::x4);
+  assembler.FcvtWS(Assembler::x1, Assembler::f2, Assembler::Rounding::kRmm);
+  assembler.FcvtWuS(Assembler::x3, Assembler::f4);
+  assembler.FsqrtS(Assembler::f1, Assembler::f2, Assembler::Rounding::kRmm);
+  assembler.FsqrtD(Assembler::f3, Assembler::f4);
+  assembler.PrefetchI({.base = Assembler::x1, .disp = 32});
+  assembler.PrefetchR({.base = Assembler::x2, .disp = 64});
+  assembler.PrefetchW({.base = Assembler::x3, .disp = 96});
+  // Move target position for more than 2048 bytes down to ensure auipc would use non-zero
+  // immediate.
+  for (size_t index = 120; index < 1200; ++index) {
+    assembler.TwoByte(uint16_t{0});
+  }
+  assembler.Fld(Assembler::f1, data_begin, Assembler::x2);
+  assembler.Flw(Assembler::f3, data_begin, Assembler::x4);
+  assembler.Fsd(Assembler::f5, data_begin, Assembler::x6);
+  assembler.Fsw(Assembler::f7, data_begin, Assembler::x8);
+  assembler.Lb(Assembler::x9, data_begin);
+  assembler.Lbu(Assembler::x10, data_begin);
+  assembler.Lh(Assembler::x11, data_begin);
+  assembler.Lhu(Assembler::x12, data_begin);
+  assembler.Lw(Assembler::x13, data_begin);
+  assembler.Sb(Assembler::x14, data_begin, Assembler::x15);
+  assembler.Sh(Assembler::x16, data_begin, Assembler::x17);
+  assembler.Sw(Assembler::x18, data_begin, Assembler::x19);
+  assembler.Lla(Assembler::x20, data_begin);
+  assembler.Bind(&data_end);
+  assembler.Finalize();
+
+  // clang-format off
+  static const uint16_t kCodeTemplate[] = {
+    0x1117, 0x0000,     // begin: auipc   x2, 4096
+    0x3087, 0x9c81,     //        fld     f1, -1592(x2)
+    0x1217, 0x0000,     //        auipc   x4, 4096
+    0x2187, 0x9c02,     //        flw     f3, -1600(x4)
+    0x1317, 0x0000,     //        auipc   x6, 4096
+    0x3c27, 0x9a53,     //        fsd     f5, -1608(x6)
+    0x1417, 0x0000,     //        auipc   x8, 4096
+    0x2827, 0x9a74,     //        fsw     f7, -1616(x8)
+    0x1497, 0x0000,     //        auipc   x9, 4096
+    0x8483, 0x9a84,     //        lb      x9, -1624(x9)
+    0x1517, 0x0000,     //        auipc   x10, 4096
+    0x4503, 0x9a05,     //        lbu     x10, -1632(x10)
+    0x1597, 0x0000,     //        auipc   x11, 4096
+    0x9583, 0x9985,     //        lh      x11, -1640(x11)
+    0x1617, 0x0000,     //        auipc   x12, 4096
+    0x5603, 0x9906,     //        lhu     x12, -1648(x12)
+    0x1697, 0x0000,     //        auipc   x13, 4096
+    0xa683, 0x9886,     //        lw      x13, -1656(x13)
+    0x1797, 0x0000,     //        auipc   x15, 4096
+    0x8023, 0x98e7,     //        sb      x14, -1664(x15)
+    0x1897, 0x0000,     //        auipc   x17, 4096
+    0x9c23, 0x9708,     //        sh      x16, -1672(x17)
+    0x1997, 0x0000,     //        auipc   x19, 4096
+    0xa823, 0x9729,     //        sw      x18, -1680(x19)
+    0x1a17, 0x0000,     //        auipc   x20, 4096
+    0x0a13, 0x968a,     //        addi    x20, x20, -1688
+    0x8263, 0x0220,     //        beq     x1, x2, label
+    0x9063, 0x0241,     //        bne     x3, x4, label
+    0xce63, 0x0062,     //        blt     x5, x6, label
+    0xdc63, 0x0083,     //        bge     x7, x8, label
+    0xea63, 0x00a4,     //        bltu    x9, x10, label
+    0xf863, 0x00c5,     //        bgeu    x11, x12, label
+    0x00ef, 0x00c0,     //        jal     x1, label
+    0x00b3, 0x0031,     //        add     x1, x2, x3
+    0x0093, 0x02a1,     //        addi    x1, x2, 42
+    0x00e7, 0x02a1,     // label: jalr    x1, x2, 42
+    0x01e7, 0x02a2,     //        jalr    x3, 42(x4)
+    0x2523, 0x0211,     //        sw      x1, 42(x2)
+    0xf16f, 0xff5f,     //        jal     x2, label
+    0x88e3, 0xfe20,     //        beq     x1, x2, label
+    0x96e3, 0xfe41,     //        bne     x3, x4, label
+    0xc4e3, 0xfe62,     //        blt     x5, x6, label
+    0xd2e3, 0xfe83,     //        bge     x7, x8, label
+    0xe0e3, 0xfea4,     //        bltu    x9, x10, label
+    0xfee3, 0xfcc5,     //        bgeu    x11, x12, label
+    0x30f3, 0xc201,     //        csrrc   x1, vl, x2
+    0x21f3, 0xc212,     //        csrrs   x3, vtype, x4
+    0x12f3, 0xc223,     //        csrrw   x5, vlenb, x6
+    0x1093, 0x0031,     //        slli    x1, x2, 3
+    0xd213, 0x4062,     //        srai    x4, x5, 6
+    0x5393, 0x0094,     //        srli    x7, x8, 9
+    0x40d3, 0xd001,     //        fcvt.s.w f1, x2, rmm
+    0x71d3, 0xd012,     //        fcvt.s.wu f3, x4
+    0x40d3, 0xc001,     //        fcvt.w.s x1, f2, rmm
+    0x71d3, 0xc012,     //        fcvt.wu.s x3, f4
+    0x40d3, 0x5801,     //        fsqrt.s f1, f2, rmm
+    0x71d3, 0x5a02,     //        fsqrt.d f3, f4
+    0xe013, 0x0200,     //        prefetch.i 32(x1)
+    0x6013, 0x0411,     //        prefetch.r 64(x2)
+    0xe013, 0x0631,     //        prefetch.w 96(x3)
+    [ 120 ... 1199 ] = 0,//       padding
+    0xf117, 0xffff,     //        auipc   x2, -4096
+    0x3087, 0x6a01,     //        fld     f1,1696(x2)
+    0xf217, 0xffff,     //        auipc   x4, -4096
+    0x2187, 0x6982,     //        flw     f3,1688(x4)
+    0xf317, 0xffff,     //        auipc   x6, -4096
+    0x3827, 0x6853,     //        fsd     f5,1680(x6)
+    0xf417, 0xffff,     //        auipc   x8, -4096
+    0x2427, 0x6874,     //        fsw     f7,1672(x8)
+    0xf497, 0xffff,     //        auipc   x9, -4096
+    0x8483, 0x6804,     //        lb      x9,1664(x9)
+    0xf517, 0xffff,     //        auipc   x10, -4096
+    0x4503, 0x6785,     //        lbu     x10,1656(x10)
+    0xf597, 0xffff,     //        auipc   x11, -4096
+    0x9583, 0x6705,     //        lh      x11,1648(x11)
+    0xf617, 0xffff,     //        auipc   x12, -4096
+    0x5603, 0x6686,     //        lhu     x12,1640(x12)
+    0xf697, 0xffff,     //        auipc   x13, -4096
+    0xa683, 0x6606,     //        lw      x13,1632(x13)
+    0xf797, 0xffff,     //        auipc   x15, -4096
+    0x8c23, 0x64e7,     //        sb      x14,1624(x15)
+    0xf897, 0xffff,     //        auipc   x17, -4096
+    0x9823, 0x6508,     //        sh      x16,1616(x17)
+    0xf997, 0xffff,     //        auipc   x19, -4096
+    0xa423, 0x6529,     //        sw      x18,1608(x19)
+    0xfa17, 0xffff,     //        auipc   x20, -4096
+    0x0a13, 0x640a,     //        addi    x20,x20,1600
+  };                    // end:
+  // clang-format on
+
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
+}
+
+}  // namespace rv32
+
+namespace rv64 {
+
+bool AssemblerTest() {
+  MachineCode code;
+  Assembler assembler(&code);
+  Assembler::Label data_begin, data_end;
+  assembler.Bind(&data_begin);
+  // We test loads and stores twice to ensure that both positive and negative immediates are
+  // present both in auipc and in the follow-up load/store instructions.
+  assembler.Ld(Assembler::x1, data_end);
+  assembler.Lwu(Assembler::x2, data_end);
+  assembler.Sd(Assembler::x3, data_end, Assembler::x4);
+  assembler.Bcc(Assembler::Condition::kAlways, Assembler::x1, Assembler::x2, 48);
+  assembler.Bcc(Assembler::Condition::kEqual, Assembler::x3, Assembler::x4, 44);
+  assembler.Bcc(Assembler::Condition::kNotEqual, Assembler::x5, Assembler::x6, 40);
+  assembler.Bcc(Assembler::Condition::kLess, Assembler::x7, Assembler::x8, 36);
+  assembler.Bcc(Assembler::Condition::kGreaterEqual, Assembler::x9, Assembler::x10, 32);
+  assembler.Bcc(Assembler::Condition::kBelow, Assembler::x11, Assembler::x12, 28);
+  assembler.Bcc(Assembler::Condition::kAboveEqual, Assembler::x13, Assembler::x14, 24);
+  assembler.Jal(Assembler::x1, 20);
+  assembler.Add(Assembler::x1, Assembler::x2, Assembler::x3);
+  assembler.Addw(Assembler::x1, Assembler::x2, Assembler::x3);
+  assembler.Addi(Assembler::x1, Assembler::x2, 42);
+  assembler.Addiw(Assembler::x1, Assembler::x2, 42);
+  // Jalr have two alternate forms.
+  assembler.Jalr(Assembler::x1, Assembler::x2, 42);
+  assembler.Jalr(Assembler::x3, {.base = Assembler::x4, .disp = 42});
+  assembler.Sw(Assembler::x1, {.base = Assembler::x2, .disp = 42});
+  assembler.Sd(Assembler::x3, {.base = Assembler::x4, .disp = 42});
+  assembler.Jal(Assembler::x2, -16);
+  assembler.Beq(Assembler::x1, Assembler::x2, -20);
+  assembler.Bne(Assembler::x3, Assembler::x4, -24);
+  assembler.Blt(Assembler::x5, Assembler::x6, -28);
+  assembler.Bge(Assembler::x7, Assembler::x8, -32);
+  assembler.Bltu(Assembler::x9, Assembler::x10, -36);
+  assembler.Bgeu(Assembler::x11, Assembler::x12, -40);
+  assembler.Bcc(Assembler::Condition::kAlways, Assembler::x13, Assembler::x14, -44);
+  assembler.Csrrc(Assembler::x1, Assembler::Csr::kVl, 2);
+  assembler.Csrrs(Assembler::x3, Assembler::Csr::kVtype, 4);
+  assembler.Csrrw(Assembler::x5, Assembler::Csr::kVlenb, 6);
+  assembler.Csrrci(Assembler::x7, Assembler::Csr::kVl, 8);
+  assembler.Csrrsi(Assembler::x9, Assembler::Csr::kVtype, 10);
+  assembler.Csrrwi(Assembler::x11, Assembler::Csr::kVlenb, 12);
+  assembler.Slliw(Assembler::x1, Assembler::x2, 3);
+  assembler.Sraiw(Assembler::x4, Assembler::x5, 6);
+  assembler.Srliw(Assembler::x7, Assembler::x8, 9);
+  assembler.FcvtDL(Assembler::f1, Assembler::x2, Assembler::Rounding::kRmm);
+  assembler.FcvtDLu(Assembler::f3, Assembler::x4);
+  assembler.FcvtLD(Assembler::x1, Assembler::f2, Assembler::Rounding::kRmm);
+  assembler.FcvtLuD(Assembler::x3, Assembler::f4);
+  assembler.FsqrtS(Assembler::f1, Assembler::f2, Assembler::Rounding::kRmm);
+  assembler.FsqrtD(Assembler::f3, Assembler::f4);
+  assembler.PrefetchI({.base = Assembler::x1, .disp = 32});
+  assembler.PrefetchR({.base = Assembler::x2, .disp = 64});
+  assembler.PrefetchW({.base = Assembler::x3, .disp = 96});
+  // Move target position for more than 2048 bytes down to ensure auipc would use non-zero
+  // immediate.
+  for (size_t index = 96; index < 1200; ++index) {
+    assembler.TwoByte(uint16_t{0});
+  }
+  assembler.Ld(Assembler::x1, data_begin);
+  assembler.Lwu(Assembler::x2, data_begin);
+  assembler.Sd(Assembler::x3, data_begin, Assembler::x4);
+  assembler.Bind(&data_end);
+  assembler.Finalize();
+
+  // clang-format off
+  static const uint16_t kCodeTemplate[] = {
+    0x1097, 0x0000,     // begin: auipc   x1, 4096
+    0xb083, 0x9780,     //        ld,     x1, -1672(x1)
+    0x1117, 0x0000,     //        auipc   x2, 4096
+    0x6103, 0x9701,     //        lwu     x2,-1680(x2)
+    0x1217, 0x0000,     //        auipc   x4, 4096
+    0x3423, 0x9632,     //        sd      x3,-1688(x4)
+    0x006f, 0x0300,     //        jal     x0, label
+    0x8663, 0x0241,     //        beq     x1, x2, label
+    0x9463, 0x0262,     //        bne     x3, x4, label
+    0xc263, 0x0283,     //        blt     x5, x6, label
+    0xd063, 0x02a4,     //        bge     x7, x8, label
+    0xee63, 0x00c5,     //        bltu    x9, x10, label
+    0xfc63, 0x00e6,     //        bgeu    x11, x12, label
+    0x00ef, 0x0140,     //        jal     x1, label
+    0x00b3, 0x0031,     //        add     x1, x2, x3
+    0x00bb, 0x0031,     //        addw    x1, x2, x3
+    0x0093, 0x02a1,     //        addi    x1, x2, 42
+    0x009b, 0x02a1,     //        addiw   x1, x2, 42
+    0x00e7, 0x02a1,     // label: jalr    x1, x2, 42
+    0x01e7, 0x02a2,     //        jalr    x3, 42(x4)
+    0x2523, 0x0211,     //        sw      x1, 42(x2)
+    0x3523, 0x0232,     //        sd      x3, 42(x4)
+    0xf16f, 0xff1f,     //        jal     x2, label
+    0x86e3, 0xfe20,     //        beq     x1, x2, label
+    0x94e3, 0xfe41,     //        bne     x3, x4, label
+    0xc2e3, 0xfe62,     //        blt     x5, x6, label
+    0xd0e3, 0xfe83,     //        bge     x7, x8, label
+    0xeee3, 0xfca4,     //        bltu    x9, x10, label
+    0xfce3, 0xfcc5,     //        bgeu    x11, x12, label
+    0xf06f, 0xfd5f,     //        jal     x0, label
+    0x70f3, 0xc201,     //        csrrc   x1, vl, 2
+    0x61f3, 0xc212,     //        csrrs   x3, vtype, 4
+    0x52f3, 0xc223,     //        csrrw   x5, vlenb, 6
+    0x73f3, 0xc204,     //        csrrci  x7, vl, 8
+    0x64f3, 0xc215,     //        csrrsi  x9, vtype, 10
+    0x55f3, 0xc226,     //        csrrwi  x11, vlenb, 12
+    0x109b, 0x0031,     //        slliw   x1, x2, 3
+    0xd21b, 0x4062,     //        sraiw   x4, x5, 6
+    0x539b, 0x0094,     //        srliw   x7, x8, 9
+    0x40d3, 0xd221,     //        fcvt.d.l f1, x2, rmm
+    0x71d3, 0xd232,     //        fcvt.d.lu f3, x4
+    0x40d3, 0xc221,     //        fcvt.l.d x1, f2, rmm
+    0x71d3, 0xc232,     //        fcvt.lu.d x3, f4
+    0x40d3, 0x5801,     //        fsqrt.s f1, f2, rmm
+    0x71d3, 0x5a02,     //        fsqrt.d f3, f4
+    0xe013, 0x0200,     //        prefetch.i 32(x1)
+    0x6013, 0x0411,     //        prefetch.r 64(x2)
+    0xe013, 0x0631,     //        prefetch.w 96(x3)
+    [ 96 ... 1199 ] = 0,//        padding
+    0xf097, 0xffff,     //        auipc   x1, -4096
+    0xb083, 0x6a00,     //        ld      x1, 1696(x1)
+    0xf117, 0xffff,     //        auipc   x2, -4096
+    0x6103, 0x6981,     //        lwu     x2, 1688(x2)
+    0xf217, 0xffff,     //        auipc   x4, -4096
+    0x3823, 0x6832,     //        sd      x3, 1680(x4)
+  };                    // end:
+  // clang-format on
+
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
+}
+
+}  // namespace rv64
 
 namespace x86_32 {
 
 bool AssemblerTest() {
   MachineCode code;
-  CodeEmitter assembler(&code);
+  Assembler assembler(&code);
   assembler.Movl(Assembler::eax, {.base = Assembler::esp, .disp = 4});
   assembler.CmpXchgl({.base = Assembler::esp, .disp = 4}, Assembler::eax);
   assembler.Subl(Assembler::esp, 16);
@@ -92,7 +402,7 @@ bool AssemblerTest() {
   assembler.Finalize();
 
   // clang-format off
-  static const uint8_t code_template[] = {
+  static const uint8_t kCodeTemplate[] = {
     0x8b, 0x44, 0x24, 0x04,                    // mov     0x4(%esp),%eax
     0x0f, 0xb1, 0x44, 0x24, 0x04,              // cmpxchg 0x4(%esp),%eax
     0x83, 0xec, 0x10,                          // sub     $16, %esp
@@ -109,25 +419,49 @@ bool AssemblerTest() {
   };
   // clang-format on
 
-  if (sizeof(code_template) != code.install_size()) {
-    ALOGE("Code size mismatch: %zu != %u", sizeof(code_template), code.install_size());
-    return false;
-  }
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
+}
 
-  if (memcmp(code_template, code.AddrAs<uint8_t>(0), code.install_size()) != 0) {
-    ALOGE("Code mismatch");
-    MachineCode code2;
-    code2.Add(code_template);
-    std::string code_str1, code_str2;
-    code.AsString(&code_str1);
-    code2.AsString(&code_str2);
-    ALOGE("assembler generated\n%s\nshall be\n%s", code_str1.c_str(), code_str2.c_str());
-    return false;
-  }
+}  // namespace x86_32
 
-  return true;
+namespace x86_64 {
+
+bool AssemblerTest() {
+  MachineCode code;
+  Assembler assembler(&code);
+  assembler.Movq(Assembler::rax, Assembler::rdi);
+  assembler.Subq(Assembler::rsp, 16);
+  assembler.Movq({.base = Assembler::rsp}, Assembler::rax);
+  assembler.Movq({.base = Assembler::rsp, .disp = 8}, Assembler::rax);
+  assembler.Movl({.base = Assembler::rax, .disp = 16}, 239);
+  assembler.Movq(Assembler::r11, {.base = Assembler::rsp});
+  assembler.Addq(Assembler::rsp, 16);
+  assembler.Ret();
+  assembler.Finalize();
+
+  // clang-format off
+  static const uint8_t kCodeTemplate[] = {
+    0x48, 0x89, 0xf8,               // mov %rdi, %rax
+    0x48, 0x83, 0xec, 0x10,         // sub $0x10, %rsp
+    0x48, 0x89, 0x04, 0x24,         // mov rax, (%rsp)
+    0x48, 0x89, 0x44, 0x24, 0x08,   // mov rax, 8(%rsp)
+    0xc7, 0x40, 0x10, 0xef, 0x00,   // movl $239, 0x10(%rax)
+    0x00, 0x00,
+    0x4c, 0x8b, 0x1c, 0x24,         // mov (%rsp), r11
+    0x48, 0x83, 0xc4, 0x10,         // add $0x10, %rsp
+    0xc3                            // ret
+  };
+  // clang-format on
+
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
 }
 
+}  // namespace x86_64
+
+#if defined(__i386__)
+
+namespace x86_32 {
+
 bool LabelTest() {
   MachineCode code;
   CodeEmitter as(&code);
@@ -386,51 +720,6 @@ bool ReadGlobalTest() {
 
 namespace x86_64 {
 
-bool AssemblerTest() {
-  MachineCode code;
-  CodeEmitter assembler(&code);
-  assembler.Movq(Assembler::rax, Assembler::rdi);
-  assembler.Subq(Assembler::rsp, 16);
-  assembler.Movq({.base = Assembler::rsp}, Assembler::rax);
-  assembler.Movq({.base = Assembler::rsp, .disp = 8}, Assembler::rax);
-  assembler.Movl({.base = Assembler::rax, .disp = 16}, 239);
-  assembler.Movq(Assembler::r11, {.base = Assembler::rsp});
-  assembler.Addq(Assembler::rsp, 16);
-  assembler.Ret();
-  assembler.Finalize();
-
-  // clang-format off
-  static const uint8_t code_template[] = {
-    0x48, 0x89, 0xf8,               // mov %rdi, %rax
-    0x48, 0x83, 0xec, 0x10,         // sub $0x10, %rsp
-    0x48, 0x89, 0x04, 0x24,         // mov rax, (%rsp)
-    0x48, 0x89, 0x44, 0x24, 0x08,   // mov rax, 8(%rsp)
-    0xc7, 0x40, 0x10, 0xef, 0x00,   // movl $239, 0x10(%rax)
-    0x00, 0x00,
-    0x4c, 0x8b, 0x1c, 0x24,         // mov (%rsp), r11
-    0x48, 0x83, 0xc4, 0x10,         // add $0x10, %rsp
-    0xc3                            // ret
-  };
-  // clang-format on
-
-  if (sizeof(code_template) != code.install_size()) {
-    ALOGE("Code size mismatch: %zu != %u", sizeof(code_template), code.install_size());
-    return false;
-  }
-
-  if (memcmp(code_template, code.AddrAs<uint8_t>(0), code.install_size()) != 0) {
-    ALOGE("Code mismatch");
-    MachineCode code2;
-    code2.Add(code_template);
-    std::string code_str1, code_str2;
-    code.AsString(&code_str1);
-    code2.AsString(&code_str2);
-    ALOGE("assembler generated\n%s\nshall be\n%s", code_str1.c_str(), code_str2.c_str());
-    return false;
-  }
-  return true;
-}
-
 bool LabelTest() {
   MachineCode code;
   CodeEmitter as(&code);
@@ -873,7 +1162,7 @@ bool MixedAssembler() {
   as64.Finalize();
 
   // clang-format off
-  static const uint8_t code_template[] = {
+  static const uint8_t kCodeTemplate[] = {
     0xe9, 0x08, 0x00, 0x00, 0x00,              // jmp lbl32
     0x90,                                      // xchg %eax, %eax == nop
     0xe9, 0x07, 0x00, 0x00, 0x00,              // jmp lbl64
@@ -884,15 +1173,18 @@ bool MixedAssembler() {
   };
   // clang-format on
 
-  return CompareCode(std::begin(code_template), std::end(code_template), code);
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
 }
 #endif
 
 }  // namespace berberis
 
 TEST(Assembler, AssemblerTest) {
-#if defined(__i386__)
+  EXPECT_TRUE(berberis::rv32::AssemblerTest());
+  EXPECT_TRUE(berberis::rv64::AssemblerTest());
   EXPECT_TRUE(berberis::x86_32::AssemblerTest());
+  EXPECT_TRUE(berberis::x86_64::AssemblerTest());
+#if defined(__i386__)
   EXPECT_TRUE(berberis::x86_32::LabelTest());
   EXPECT_TRUE(berberis::x86_32::CondTest1());
   EXPECT_TRUE(berberis::x86_32::CondTest2());
@@ -903,10 +1195,7 @@ TEST(Assembler, AssemblerTest) {
   EXPECT_TRUE(berberis::x86_32::XmmTest());
   EXPECT_TRUE(berberis::x86_32::BsrTest());
   EXPECT_TRUE(berberis::x86_32::ReadGlobalTest());
-  EXPECT_TRUE(berberis::ExhaustiveTest());
-  EXPECT_TRUE(berberis::MixedAssembler());
 #elif defined(__amd64__)
-  EXPECT_TRUE(berberis::x86_64::AssemblerTest());
   EXPECT_TRUE(berberis::x86_64::LabelTest());
   EXPECT_TRUE(berberis::x86_64::CondTest1());
   EXPECT_TRUE(berberis::x86_64::CondTest2());
@@ -921,7 +1210,7 @@ TEST(Assembler, AssemblerTest) {
   EXPECT_TRUE(berberis::x86_64::ShrdlRexTest());
   EXPECT_TRUE(berberis::x86_64::ReadGlobalTest());
   EXPECT_TRUE(berberis::x86_64::MemShiftTest());
+#endif
   EXPECT_TRUE(berberis::ExhaustiveTest());
   EXPECT_TRUE(berberis::MixedAssembler());
-#endif
 }
diff --git a/assembler/gen_asm_x86.py b/assembler/gen_asm.py
similarity index 78%
rename from assembler/gen_asm_x86.py
rename to assembler/gen_asm.py
index ff50c0d0..67412a86 100644
--- a/assembler/gen_asm_x86.py
+++ b/assembler/gen_asm.py
@@ -26,20 +26,34 @@ import sys
 INDENT = '  '
 
 _imm_types = {
+    # x86 immediates
     'Imm2': 'int8_t',
     'Imm8': 'int8_t',
     'Imm16': 'int16_t',
     'Imm32': 'int32_t',
-    'Imm64': 'int64_t'
+    'Imm64': 'int64_t',
+    # Official RISC-V immediates
+    'B-Imm': 'BImmediate',
+    'I-Imm': 'IImmediate',
+    'J-Imm': 'JImmediate',
+    'P-Imm': 'PImmediate',
+    'S-Imm': 'SImmediate',
+    'U-Imm': 'UImmediate',
+    # Extra RISC-V immediates
+    'Csr-Imm' : 'CsrImmediate',
+    'Shift32-Imm': 'Shift32Immediate',
+    'Shift64-Imm': 'Shift64Immediate'
 }
 
 
-def _get_arg_type_name(arg):
+def _get_arg_type_name(arg, insn_type):
   cls = arg.get('class')
   if asm_defs.is_x87reg(cls):
     return 'X87Register'
   if asm_defs.is_greg(cls):
     return 'Register'
+  if asm_defs.is_freg(cls):
+    return 'FpRegister'
   if asm_defs.is_xreg(cls):
     return 'XMMRegister'
   if asm_defs.is_imm(cls):
@@ -50,7 +64,13 @@ def _get_arg_type_name(arg):
     return 'const Label&'
   if asm_defs.is_cond(cls):
     return 'Condition'
+  if asm_defs.is_csr(cls):
+    return 'Csr'
+  if asm_defs.is_rm(cls):
+    return 'Rounding'
   if asm_defs.is_mem_op(cls):
+    if insn_type is not None and insn_type.endswith('-type'):
+      return 'const Operand<Register, %sImmediate>&' % insn_type[:-5]
     return 'const Operand&'
   raise Exception('class %s is not supported' % (cls))
 
@@ -65,13 +85,16 @@ def _get_immediate_type(insn):
   return imm_type
 
 
-def _get_params(insn):
+def _get_params(insn, filter=None):
   result = []
   arg_count = 0
   for arg in insn.get('args'):
     if asm_defs.is_implicit_reg(arg.get('class')):
       continue
-    result.append("%s arg%d" % (_get_arg_type_name(arg), arg_count))
+    if filter is not None and filter(arg):
+      continue
+    result.append("%s arg%d" % (
+      _get_arg_type_name(arg, insn.get('type', None)), arg_count))
     arg_count += 1
   return ', '.join(result)
 
@@ -90,7 +113,7 @@ def _get_template_name(insn):
       for param in name.split('<',1)[1][:-1].split(',')), name.split('<')[0]
 
 
-def _gen_generic_functions_h(f, insns, binary_assembler):
+def _gen_generic_functions_h(f, insns, binary_assembler, arch):
   template_names = set()
   for insn in insns:
     template, name = _get_template_name(insn)
@@ -109,7 +132,7 @@ def _gen_generic_functions_h(f, insns, binary_assembler):
       # full description of template function.
       template_name = str({
           'name': name,
-          'params': _get_params(insn)
+          'params': params
       })
       if template_name in template_names:
         continue
@@ -121,24 +144,51 @@ def _gen_generic_functions_h(f, insns, binary_assembler):
     # Text assembled passes "real" work down to GNU as, this works fine with
     # just a simple generic implementation.
     if binary_assembler:
+      if 'opcode' in insn:
+        assert '' not in insn
+        insn['opcodes'] = [insn['opcode']]
       if 'opcodes' in insn:
+        opcodes = []
+        for opcode in insn['opcodes']:
+          if re.match('^[0-9a-fA-F]{2}$', opcode):
+            opcodes.append('uint8_t{0x%s}' % opcode)
+          elif re.match('^[0-9a-fA-F]{4}$', opcode):
+            opcodes.append('uint16_t{0x%s}' % opcode)
+          elif re.match('^[0-9a-fA-F]{8}$', opcode):
+            opcodes.append('uint32_t{0x%s}' % opcode)
+          elif re.match('^[0-9a-fA-F]{4}_[0-9a-fA-F]{4}$', opcode):
+            opcodes.append('uint32_t{0x%s}' % re.sub('_', '\'', opcode))
+          elif re.match('^[0-7]$', opcode):
+            opcodes.append('uint8_t{%s}' % opcode)
+          else:
+            assert False
+        insn['processed_opcodes'] = opcodes
         print('void %s(%s) {' % (name, params), file=f)
-        _gen_emit_shortcut(f, insn, insns)
-        _gen_emit_instruction(f, insn)
+        if 'x86' in arch:
+          _gen_emit_shortcut(f, insn, insns)
+        _gen_emit_instruction(f, insn, arch)
         print('}', file=f)
         # If we have a memory operand (there may be at most one) then we also
         # have a special x86-64 exclusive form which accepts Label (it can be
         # emulated on x86-32, too, if needed).
-        if 'const Operand&' in params:
+        if 'const Operand&' in params and 'x86' in arch:
           print("", file=f)
           print('void %s(%s) {' % (
               name, params.replace('const Operand&', 'const LabelOperand')), file=f)
           _gen_emit_shortcut(f, insn, insns)
-          _gen_emit_instruction(f, insn, rip_operand=True)
+          _gen_emit_instruction(f, insn, arch, rip_operand=True)
+          print('}\n', file=f)
+        if 'Rounding' in params:
+          print("", file=f)
+          print('void %s(%s) {' % (
+              name, _get_params(insn, lambda arg: arg.get('class', '') == 'Rm')), file=f)
+          _gen_emit_instruction(f, insn, arch, dyn_rm=True)
           print('}\n', file=f)
       else:
         print('void %s(%s);' % (name, params), file=f)
-      if imm_type is not None:
+      # If immediate type is integer then we want to prevent automatic
+      # conversions from integers of larger sizes.
+      if imm_type is not None and "int" in imm_type:
         if template:
           print(template[:-1] + ", typename ImmType>", file=f)
         else:
@@ -152,17 +202,19 @@ def _gen_generic_functions_h(f, insns, binary_assembler):
       if 'feature' in insn:
         print('  SetRequiredFeature%s();' % insn['feature'], file=f)
       print('  Instruction(%s);' % ', '.join(
-          ['"%s"' % name] + list(_gen_instruction_args(insn))), file=f)
+          ['"%s"' % insn.get('native-asm', name)] +
+          list(_gen_instruction_args(insn, arch))), file=f)
       print('}', file=f)
 
 
-def _gen_instruction_args(insn):
+def _gen_instruction_args(insn, arch):
   arg_count = 0
   for arg in insn.get('args'):
     if asm_defs.is_implicit_reg(arg.get('class')):
       continue
-    if _get_arg_type_name(arg) == 'Register':
-      yield 'typename Assembler::%s(arg%d)' % (
+    if (_get_arg_type_name(arg, insn.get('type', None)) == 'Register'
+        and 'x86' in arch):
+      yield 'typename DerivedAssemblerType::%s(arg%d)' % (
           _ARGUMENT_FORMATS_TO_SIZES[arg['class']], arg_count)
     else:
       yield 'arg%d' % arg_count
@@ -229,7 +281,7 @@ def _gen_emit_shortcut_accumulator_imm8(f, insn, insns):
                           maybe_8bit_imm_args):
       continue
     print('  if (IsInRange<int8_t>(arg0)) {', file=f)
-    print(('    return %s(Assembler::Accumulator(), '
+    print(('    return %s(DerivedAssemblerType::Accumulator(), '
                  'static_cast<int8_t>(arg0));') % (
                      maybe_imm8_insn['asm'],), file=f)
     print('  }', file=f)
@@ -269,7 +321,7 @@ def _gen_emit_shortcut_accumulator(f, insn, insns):
       continue
     # Now call that version if register is an Accumulator.
     arg_count = len(_get_params(insn).split(','))
-    print('  if (Assembler::IsAccumulator(arg0)) {', file=f)
+    print('  if (DerivedAssemblerType::IsAccumulator(arg0)) {', file=f)
     print('  return %s(%s);' % (
       maybe_accumulator_insn['asm'],
       ', '.join('arg%d' % n for n in range(1, arg_count))), file=f)
@@ -313,6 +365,7 @@ _ARGUMENT_FORMATS_TO_SIZES = {
   'Imm16': '',
   'Imm32': '',
   'Imm64': '',
+  'Mem': 'MemoryDefaultBit',
   'Mem8' : 'Memory8Bit',
   'Mem16' : 'Memory16Bit',
   'Mem32' : 'Memory32Bit',
@@ -340,46 +393,32 @@ _ARGUMENT_FORMATS_TO_SIZES = {
 # e.g. VectorMemory32Bit becomes VectorLabel32Bit.
 #
 # Note: on x86-32 that mode can also be emulated using regular instruction form, if needed.
-def _gen_emit_instruction(f, insn, rip_operand=False):
+def _gen_emit_instruction(f, insn, arch, rip_operand=False, dyn_rm=False):
   result = []
   arg_count = 0
   for arg in insn['args']:
     if asm_defs.is_implicit_reg(arg['class']):
       continue
-    result.append('%s(arg%d)' % (_ARGUMENT_FORMATS_TO_SIZES[arg['class']], arg_count))
+    # Note: in RISC-V there is never any ambiguity about whether full register or its part is used.
+    # Instead size of operand is always encoded in the name, e.g. addw vs add or fadd.s vs fadd.d
+    if arch in ['common_riscv', 'rv32', 'rv64']:
+      if dyn_rm and arg['class'] == 'Rm':
+        result.append('Rounding::kDyn')
+      else:
+        result.append('arg%d' % arg_count)
+    else:
+      result.append('%s(arg%d)' % (_ARGUMENT_FORMATS_TO_SIZES[arg['class']], arg_count))
     arg_count += 1
-  if insn.get('reg_to_rm', False):
-    result[0], result[1] = result[1], result[0]
-  if insn.get('rm_to_vex', False):
-    result[0], result[1] = result[1], result[0]
-  if insn.get('vex_imm_rm_to_reg', False):
-    result[0], result[1], result[2], result[3] = result[0], result[3], result[1], result[2]
-  if insn.get('vex_rm_imm_to_reg', False):
-    result[0], result[1], result[2], result[3] = result[0], result[2], result[1], result[3]
   # If we want %rip--operand then we need to replace 'Memory' with 'Labal'
   if rip_operand:
     result = [arg.replace('Memory', 'Label') for arg in result]
-  # If vex operand is one of first 8 registers and rm operand is not then swapping these two
-  # operands produces more compact encoding.
-  # This only works with commutative instructions from first opcode map.
-  if ((insn.get('is_optimizable_using_commutation', False) and
-    # Note: we may only swap arguments if they have the same type.
-    # E.g. if one is memory and the other is register then we couldn't swap them.
-    result[0].split('(')[0] == result[2].split('(')[0])):
-    assert insn.get('vex_rm_to_reg', False)
-    print('  if (Assembler::IsSwapProfitable(%s, %s)) {' % (result[2], result[1]), file=f)
-    print('    return EmitInstruction<Opcodes<%s>>(%s);' % (
-        ', '.join('0x%02x' % int(opcode, 16) for opcode in insn['opcodes']),
-        ', '.join(result)), file=f)
-    print('  }', file=f)
-  if insn.get('vex_rm_to_reg', False):
-    result[0], result[1], result[2] = result[0], result[2], result[1]
-  print('  EmitInstruction<Opcodes<%s>>(%s);' % (
-      ', '.join('0x%02x' % int(opcode, 16) for opcode in insn['opcodes']),
+  print('  Emit%sInstruction<%s>(%s);' % (
+      asm_defs._get_cxx_name(insn.get('type', '')),
+      ', '.join(insn['processed_opcodes']),
       ', '.join(result)), file=f)
 
 
-def _gen_memory_function_specializations_h(f, insns):
+def _gen_memory_function_specializations_h(f, insns, arch):
   for insn in insns:
     # Only build additional definitions needed for memory access in LIR if there
     # are memory arguments and instruction is intended for use in LIR
@@ -413,7 +452,7 @@ def _gen_memory_function_specializations_h(f, insns):
           outgoing_args.append('{%s}' % (
               ', '.join(['.%s = %s' % (pair[1], pair[2]) for pair in mem_args])))
         else:
-          incoming_args.append('%s %s' % (_get_arg_type_name(arg), arg_name))
+          incoming_args.append('%s %s' % (_get_arg_type_name(arg, None), arg_name))
           outgoing_args.append(arg_name)
       if template:
         print(template, file=f)
@@ -429,9 +468,9 @@ def _is_for_asm(insn):
 
 
 def _load_asm_defs(asm_def):
-  _, insns = asm_defs.load_asm_defs(asm_def)
+  arch, insns = asm_defs.load_asm_defs(asm_def)
   # Filter out explicitly disabled instructions.
-  return [i for i in insns if _is_for_asm(i)]
+  return arch, [i for i in insns if _is_for_asm(i)]
 
 
 def main(argv):
@@ -457,11 +496,11 @@ def main(argv):
     assert False, 'unknown option %s' % (mode)
 
   for out_filename, input_filename in filename_pairs:
-    loaded_defs = _load_asm_defs(input_filename)
+    arch, loaded_defs = _load_asm_defs(input_filename)
     with open(out_filename, 'w') as out_file:
-      _gen_generic_functions_h(out_file, loaded_defs, binary_assembler)
-      if binary_assembler:
-        _gen_memory_function_specializations_h(out_file, loaded_defs)
+      _gen_generic_functions_h(out_file, loaded_defs, binary_assembler, arch)
+      if binary_assembler and arch is not None and 'x86' in arch:
+        _gen_memory_function_specializations_h(out_file, loaded_defs, arch)
 
 if __name__ == '__main__':
   sys.exit(main(sys.argv))
diff --git a/assembler/gen_asm_tests_x86.py b/assembler/gen_asm_tests_x86.py
index f6ba4386..827649a7 100644
--- a/assembler/gen_asm_tests_x86.py
+++ b/assembler/gen_asm_tests_x86.py
@@ -19,7 +19,7 @@ import itertools
 import json
 import sys
 
-import gen_asm_x86
+import gen_asm
 
 
 # Enable to avoid cycles.  Only use one register combo for tests.
@@ -40,8 +40,8 @@ def main(argv):
     with open(arc_assembler_file_name, 'w') as arc_assembler_file:
       pass
     return 0
-  common_defs = gen_asm_x86._load_asm_defs(argv[3])
-  arch_defs = gen_asm_x86._load_asm_defs(argv[4])
+  _, common_defs = gen_asm._load_asm_defs(argv[3])
+  _, arch_defs = gen_asm._load_asm_defs(argv[4])
 
   fast_mode = globals()["fast_mode"]
   if len(argv) > 5 and argv[5] == '--fast':
@@ -151,7 +151,7 @@ sample_arc_arguments = {
              'Assembler::Condition::kBelow', 'Assembler::Condition::kAboveEqual',
              'Assembler::Condition::kEqual', 'Assembler::Condition::kNotEqual',
              'Assembler::Condition::kBelowEqual', 'Assembler::Condition::kAbove',
-             'Assembler::Condition::kNegative', 'Assembler::Condition::kPositive',
+             'Assembler::Condition::kNegative', 'Assembler::Condition::kPositiveOrZero',
              'Assembler::Condition::kParityEven', 'Assembler::Condition::kParityOdd',
              'Assembler::Condition::kLess', 'Assembler::Condition::kGreaterEqual',
              'Assembler::Condition::kLessEqual', 'Assembler::Condition::kGreater'),
@@ -249,7 +249,7 @@ def _update_arguments(x86_64):
             for index in sample_att_arguments[addr]
             for scale in ('', ',2', ',4', ',8')
             if index not in ('%ESP', '%RSP')]
-  for mem_arg in ('Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
+  for mem_arg in ('Mem', 'Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
                   'MemX87', 'MemX8716', 'MemX8732', 'MemX8764', 'MemX8780',
                   'VecMem32', 'VecMem64', 'VecMem128'):
     sample_att_arguments[mem_arg] = tuple(addrs)
@@ -275,7 +275,7 @@ def _update_arguments(x86_64):
             for index in sample_arc_arguments[addr]
             for scale in ('One', 'Two', 'Four', 'Eight')
             if 'Assembler::esp' not in index and 'Assembler::rsp' not in index]
-  for mem_arg in ('Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
+  for mem_arg in ('Mem', 'Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
                   'MemX87', 'MemX8716', 'MemX8732', 'MemX8764', 'MemX8780',
                   'VecMem32', 'VecMem64', 'VecMem128'):
     sample_arc_arguments[mem_arg] = tuple(addrs)
@@ -391,8 +391,8 @@ def _gen_att_instruction_variants(
         else:
           insn_args = ('%E' + insn_args[0][2:],) + insn_args[1:]
     if insn_name[0:4] == 'LOCK':
-     # TODO(b/161986409): replace '\n' with ' ' when clang would be fixed.
-     fixed_name = '%s\n%s' % (insn_name[0:4], insn_name[4:])
+      # TODO(b/161986409): replace '\n' with ' ' when clang would be fixed.
+      fixed_name = '%s\n%s' % (insn_name[0:4], insn_name[4:])
     fixed_name = {
       # GNU disassembler accepts these instructions, but not Clang assembler.
       'FNDISI': '.byte 0xdb, 0xe1',
diff --git a/assembler/immediates_test.cc b/assembler/immediates_test.cc
new file mode 100644
index 00000000..228dcb1a
--- /dev/null
+++ b/assembler/immediates_test.cc
@@ -0,0 +1,987 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "gtest/gtest.h"
+
+#include <array>
+#include <optional>
+#include <tuple>
+
+#include "berberis/assembler/rv32.h"
+#include "berberis/assembler/rv64.h"
+
+namespace berberis {
+
+namespace {
+
+class Riscv64ImmediatesTest : public ::testing::Test {
+ public:
+  Riscv64ImmediatesTest() {}
+
+  template <typename ImmediateType,
+            std::optional<ImmediateType> (*make_immediate_i8)(int8_t),
+            std::optional<ImmediateType> (*make_immediate_u8)(uint8_t),
+            std::optional<ImmediateType> (*make_immediate_i16)(int16_t),
+            std::optional<ImmediateType> (*make_immediate_u16)(uint16_t),
+            std::optional<ImmediateType> (*make_immediate_i32)(int32_t),
+            std::optional<ImmediateType> (*make_immediate_u32)(uint32_t),
+            std::optional<ImmediateType> (*make_immediate_i64)(int64_t),
+            std::optional<ImmediateType> (*make_immediate_u64)(uint64_t),
+            size_t size>
+  void TestConversion(std::array<std::tuple<uint32_t, std::optional<uint32_t>>, size> test_cases) {
+    for (const auto& test_case : test_cases) {
+      int32_t source = static_cast<int32_t>(std::get<0>(test_case));
+      std::optional<uint32_t> expected_result = std::get<1>(test_case);
+      auto CheckConversion =
+          [&source, &expected_result]<typename IntType,
+                                      std::optional<ImmediateType> (*make_immediate)(IntType)>() {
+            IntType typed_source = static_cast<IntType>(source);
+            // If source is not representable as IntType, then conversion check doesn't make sense.
+            // E.e. if our test is trying to encode 0x100 which, when converted to int8_t becomes 0,
+            // then, if immediate actually accepts 0x100 expected_result would be encoding 0x100 but
+            // result would encode 0 which is correct, but different from expected_result !
+            if (static_cast<int32_t>(typed_source) != source ||
+                (!std::is_signed_v<IntType> && source < 0)) {
+              return;
+            }
+            std::optional<ImmediateType> result = make_immediate(source);
+            EXPECT_EQ(result.has_value(), expected_result.has_value());
+            if (result.has_value()) {
+              if constexpr (std::is_same_v<ImmediateType, riscv::CsrImmediate> ||
+                            std::is_same_v<ImmediateType, riscv::Shift32Immediate> ||
+                            std::is_same_v<ImmediateType, riscv::Shift64Immediate> ||
+                            (std::is_same_v<IntType, int16_t> &&
+                             !std::is_same_v<ImmediateType, riscv::JImmediate> &&
+                             !std::is_same_v<ImmediateType, riscv::UImmediate>) ||
+                            (std::is_same_v<IntType, int32_t> ||
+                             std::is_same_v<IntType, int64_t>)) {
+                CHECK_EQ(typed_source, static_cast<IntType>(*result));
+              }
+              uint32_t raw_immediate_value = result->EncodedValue();
+              // RISC-V I-ImmediateType and S-Immediate support the same set of values and could be
+              // converted from one to another, but other types of immediates are unique.
+              if constexpr (std::is_same_v<ImmediateType, rv64::Assembler::Immediate>) {
+                EXPECT_EQ(ImmediateType(rv64::Assembler::SImmediate(typed_source)), *result);
+              } else if constexpr (std::is_same_v<ImmediateType, rv64::Assembler::SImmediate>) {
+                EXPECT_EQ(ImmediateType(rv64::Assembler::Immediate(typed_source)), *result);
+              }
+              EXPECT_EQ(raw_immediate_value, *expected_result);
+              ImmediateType result = ImmediateType(source);
+              raw_immediate_value = result.EncodedValue();
+              EXPECT_EQ(raw_immediate_value, *expected_result);
+            }
+          };
+      CheckConversion.template operator()<int8_t, make_immediate_i8>();
+      CheckConversion.template operator()<uint8_t, make_immediate_u8>();
+      CheckConversion.template operator()<int16_t, make_immediate_i16>();
+      CheckConversion.template operator()<uint16_t, make_immediate_u16>();
+      CheckConversion.template operator()<int32_t, make_immediate_i32>();
+      CheckConversion.template operator()<uint32_t, make_immediate_u32>();
+      CheckConversion.template operator()<int64_t, make_immediate_i64>();
+      CheckConversion.template operator()<uint64_t, make_immediate_u64>();
+    }
+  }
+};
+
+TEST_F(Riscv64ImmediatesTest, TestBImmediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::BImmediate,
+                 riscv::MakeBImmediate,
+                 riscv::MakeBImmediate,
+                 riscv::MakeBImmediate,
+                 riscv::MakeBImmediate,
+                 riscv::MakeBImmediate,
+                 riscv::MakeBImmediate,
+                 riscv::MakeBImmediate,
+                 riscv::MakeBImmediate>(std::array{
+      T{0b00000000000000000000'0'000000'0000'0, 0b0'000000'00000'00000'000'0000'0'0000000},
+      //  31              12  11 10   5 4  1 0   31 30  25 24 20 19 15     11 8 7 6     0
+      T{0b00000000000000000000'0'000000'0000'1, {}},
+      T{0b00000000000000000000'0'000000'0001'0, 0b0'000000'00000'00000'000'0001'0'0000000},
+      T{0b00000000000000000000'0'000000'0010'0, 0b0'000000'00000'00000'000'0010'0'0000000},
+      T{0b00000000000000000000'0'000000'0100'0, 0b0'000000'00000'00000'000'0100'0'0000000},
+      T{0b00000000000000000000'0'000000'1000'0, 0b0'000000'00000'00000'000'1000'0'0000000},
+      T{0b00000000000000000000'0'000001'0000'0, 0b0'000001'00000'00000'000'0000'0'0000000},
+      T{0b00000000000000000000'0'000010'0000'0, 0b0'000010'00000'00000'000'0000'0'0000000},
+      T{0b00000000000000000000'0'000100'0000'0, 0b0'000100'00000'00000'000'0000'0'0000000},
+      T{0b00000000000000000000'0'001000'0000'0, 0b0'001000'00000'00000'000'0000'0'0000000},
+      T{0b00000000000000000000'0'010000'0000'0, 0b0'010000'00000'00000'000'0000'0'0000000},
+      T{0b00000000000000000000'0'100000'0000'0, 0b0'100000'00000'00000'000'0000'0'0000000},
+      T{0b00000000000000000000'1'000000'0000'0, 0b0'000000'00000'00000'000'0000'1'0000000},
+      T{0b00000000000000000001'0'000000'0000'0, {}},
+      T{0b00000000000000000010'0'000000'0000'0, {}},
+      T{0b00000000000000000100'0'000000'0000'0, {}},
+      T{0b00000000000000001000'0'000000'0000'0, {}},
+      T{0b00000000000000010000'0'000000'0000'0, {}},
+      T{0b00000000000000100000'0'000000'0000'0, {}},
+      T{0b00000000000001000000'0'000000'0000'0, {}},
+      T{0b00000000000010000000'0'000000'0000'0, {}},
+      T{0b00000000000100000000'0'000000'0000'0, {}},
+      T{0b00000000001000000000'0'000000'0000'0, {}},
+      T{0b00000000010000000000'0'000000'0000'0, {}},
+      T{0b00000000100000000000'0'000000'0000'0, {}},
+      T{0b00000001000000000000'0'000000'0000'0, {}},
+      T{0b00000010000000000000'0'000000'0000'0, {}},
+      T{0b00000100000000000000'0'000000'0000'0, {}},
+      T{0b00001000000000000000'0'000000'0000'0, {}},
+      T{0b00010000000000000000'0'000000'0000'0, {}},
+      T{0b00100000000000000000'0'000000'0000'0, {}},
+      T{0b01000000000000000000'0'000000'0000'0, {}},
+      T{0b10000000000000000000'0'000000'0000'0, {}},
+      //  31              12  11 10   5 4  1 0     31 30  25 24 20 19 15     11 8 7 6     0
+      T{0b11111111111111111111'1'111111'1111'1, {}},
+      T{0b11111111111111111111'1'111111'1111'0, 0b1'111111'00000'00000'000'1111'1'0000000},
+      T{0b11111111111111111111'1'111111'1110'0, 0b1'111111'00000'00000'000'1110'1'0000000},
+      T{0b11111111111111111111'1'111111'1100'0, 0b1'111111'00000'00000'000'1100'1'0000000},
+      T{0b11111111111111111111'1'111111'1000'0, 0b1'111111'00000'00000'000'1000'1'0000000},
+      T{0b11111111111111111111'1'111111'0000'0, 0b1'111111'00000'00000'000'0000'1'0000000},
+      T{0b11111111111111111111'1'111110'0000'0, 0b1'111110'00000'00000'000'0000'1'0000000},
+      T{0b11111111111111111111'1'111100'0000'0, 0b1'111100'00000'00000'000'0000'1'0000000},
+      T{0b11111111111111111111'1'111000'0000'0, 0b1'111000'00000'00000'000'0000'1'0000000},
+      T{0b11111111111111111111'1'110000'0000'0, 0b1'110000'00000'00000'000'0000'1'0000000},
+      T{0b11111111111111111111'1'100000'0000'0, 0b1'100000'00000'00000'000'0000'1'0000000},
+      T{0b11111111111111111111'1'000000'0000'0, 0b1'000000'00000'00000'000'0000'1'0000000},
+      T{0b11111111111111111111'0'000000'0000'0, 0b1'000000'00000'00000'000'0000'0'0000000},
+      T{0b11111111111111111110'0'000000'0000'0, {}},
+      T{0b11111111111111111100'0'000000'0000'0, {}},
+      T{0b11111111111111111000'0'000000'0000'0, {}},
+      T{0b11111111111111110000'0'000000'0000'0, {}},
+      T{0b11111111111111100000'0'000000'0000'0, {}},
+      T{0b11111111111111000000'0'000000'0000'0, {}},
+      T{0b11111111111110000000'0'000000'0000'0, {}},
+      T{0b11111111111100000000'0'000000'0000'0, {}},
+      T{0b11111111111000000000'0'000000'0000'0, {}},
+      T{0b11111111110000000000'0'000000'0000'0, {}},
+      T{0b11111111100000000000'0'000000'0000'0, {}},
+      T{0b11111111000000000000'0'000000'0000'0, {}},
+      T{0b11111110000000000000'0'000000'0000'0, {}},
+      T{0b11111100000000000000'0'000000'0000'0, {}},
+      T{0b11111000000000000000'0'000000'0000'0, {}},
+      T{0b11110000000000000000'0'000000'0000'0, {}},
+      T{0b11100000000000000000'0'000000'0000'0, {}},
+      T{0b11000000000000000000'0'000000'0000'0, {}},
+      T{0b10000000000000000000'0'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestCsrImmediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::CsrImmediate,
+                 riscv::MakeCsrImmediate,
+                 riscv::MakeCsrImmediate,
+                 riscv::MakeCsrImmediate,
+                 riscv::MakeCsrImmediate,
+                 riscv::MakeCsrImmediate,
+                 riscv::MakeCsrImmediate,
+                 riscv::MakeCsrImmediate,
+                 riscv::MakeCsrImmediate>(std::array{
+      T{0b000000000000000000000'000000'0000'0, 0b0'00000000000'00000'000'00000'0000000},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b000000000000000000000'000000'0000'1, 0b0'00000000000'00001'000'00000'0000000},
+      T{0b000000000000000000000'000000'0001'0, 0b0'00000000000'00010'000'00000'0000000},
+      T{0b000000000000000000000'000000'0010'0, 0b0'00000000000'00100'000'00000'0000000},
+      T{0b000000000000000000000'000000'0100'0, 0b0'00000000000'01000'000'00000'0000000},
+      T{0b000000000000000000000'000000'1000'0, 0b0'00000000000'10000'000'00000'0000000},
+      T{0b000000000000000000000'000001'0000'0, {}},
+      T{0b000000000000000000000'000010'0000'0, {}},
+      T{0b000000000000000000000'000100'0000'0, {}},
+      T{0b000000000000000000000'001000'0000'0, {}},
+      T{0b000000000000000000000'010000'0000'0, {}},
+      T{0b000000000000000000000'100000'0000'0, {}},
+      T{0b000000000000000000001'000000'0000'0, {}},
+      T{0b000000000000000000010'000000'0000'0, {}},
+      T{0b000000000000000000100'000000'0000'0, {}},
+      T{0b000000000000000001000'000000'0000'0, {}},
+      T{0b000000000000000010000'000000'0000'0, {}},
+      T{0b000000000000000100000'000000'0000'0, {}},
+      T{0b000000000000001000000'000000'0000'0, {}},
+      T{0b000000000000010000000'000000'0000'0, {}},
+      T{0b000000000000100000000'000000'0000'0, {}},
+      T{0b000000000001000000000'000000'0000'0, {}},
+      T{0b000000000010000000000'000000'0000'0, {}},
+      T{0b000000000100000000000'000000'0000'0, {}},
+      T{0b000000001000000000000'000000'0000'0, {}},
+      T{0b000000010000000000000'000000'0000'0, {}},
+      T{0b000000100000000000000'000000'0000'0, {}},
+      T{0b000001000000000000000'000000'0000'0, {}},
+      T{0b000010000000000000000'000000'0000'0, {}},
+      T{0b000100000000000000000'000000'0000'0, {}},
+      T{0b001000000000000000000'000000'0000'0, {}},
+      T{0b010000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b111111111111111111111'111111'1111'1, {}},
+      T{0b111111111111111111111'111111'1111'0, {}},
+      T{0b111111111111111111111'111111'1110'0, {}},
+      T{0b111111111111111111111'111111'1100'0, {}},
+      T{0b111111111111111111111'111111'1000'0, {}},
+      T{0b111111111111111111111'111111'0000'0, {}},
+      T{0b111111111111111111111'111110'0000'0, {}},
+      T{0b111111111111111111111'111100'0000'0, {}},
+      T{0b111111111111111111111'111000'0000'0, {}},
+      T{0b111111111111111111111'110000'0000'0, {}},
+      T{0b111111111111111111111'100000'0000'0, {}},
+      T{0b111111111111111111111'000000'0000'0, {}},
+      T{0b111111111111111111110'000000'0000'0, {}},
+      T{0b111111111111111111100'000000'0000'0, {}},
+      T{0b111111111111111111000'000000'0000'0, {}},
+      T{0b111111111111111110000'000000'0000'0, {}},
+      T{0b111111111111111100000'000000'0000'0, {}},
+      T{0b111111111111111000000'000000'0000'0, {}},
+      T{0b111111111111110000000'000000'0000'0, {}},
+      T{0b111111111111100000000'000000'0000'0, {}},
+      T{0b111111111111000000000'000000'0000'0, {}},
+      T{0b111111111110000000000'000000'0000'0, {}},
+      T{0b111111111100000000000'000000'0000'0, {}},
+      T{0b111111111000000000000'000000'0000'0, {}},
+      T{0b111111110000000000000'000000'0000'0, {}},
+      T{0b111111100000000000000'000000'0000'0, {}},
+      T{0b111111000000000000000'000000'0000'0, {}},
+      T{0b111110000000000000000'000000'0000'0, {}},
+      T{0b111100000000000000000'000000'0000'0, {}},
+      T{0b111000000000000000000'000000'0000'0, {}},
+      T{0b110000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestIImmediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::Immediate,
+                 riscv::MakeImmediate,
+                 riscv::MakeImmediate,
+                 riscv::MakeImmediate,
+                 riscv::MakeImmediate,
+                 riscv::MakeImmediate,
+                 riscv::MakeImmediate,
+                 riscv::MakeImmediate,
+                 riscv::MakeImmediate>(std::array{
+      T{0b000000000000000000000'000000'0000'0, 0b0'00000000000'00000'000'00000'0000000},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b000000000000000000000'000000'0000'1, 0b0'00000000001'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0001'0, 0b0'00000000010'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0010'0, 0b0'00000000100'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0100'0, 0b0'00000001000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'1000'0, 0b0'00000010000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000001'0000'0, 0b0'00000100000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000010'0000'0, 0b0'00001000000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000100'0000'0, 0b0'00010000000'00000'000'00000'0000000},
+      T{0b000000000000000000000'001000'0000'0, 0b0'00100000000'00000'000'00000'0000000},
+      T{0b000000000000000000000'010000'0000'0, 0b0'01000000000'00000'000'00000'0000000},
+      T{0b000000000000000000000'100000'0000'0, 0b0'10000000000'00000'000'00000'0000000},
+      T{0b000000000000000000001'000000'0000'0, {}},
+      T{0b000000000000000000010'000000'0000'0, {}},
+      T{0b000000000000000000100'000000'0000'0, {}},
+      T{0b000000000000000001000'000000'0000'0, {}},
+      T{0b000000000000000010000'000000'0000'0, {}},
+      T{0b000000000000000100000'000000'0000'0, {}},
+      T{0b000000000000001000000'000000'0000'0, {}},
+      T{0b000000000000010000000'000000'0000'0, {}},
+      T{0b000000000000100000000'000000'0000'0, {}},
+      T{0b000000000001000000000'000000'0000'0, {}},
+      T{0b000000000010000000000'000000'0000'0, {}},
+      T{0b000000000100000000000'000000'0000'0, {}},
+      T{0b000000001000000000000'000000'0000'0, {}},
+      T{0b000000010000000000000'000000'0000'0, {}},
+      T{0b000000100000000000000'000000'0000'0, {}},
+      T{0b000001000000000000000'000000'0000'0, {}},
+      T{0b000010000000000000000'000000'0000'0, {}},
+      T{0b000100000000000000000'000000'0000'0, {}},
+      T{0b001000000000000000000'000000'0000'0, {}},
+      T{0b010000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b111111111111111111111'111111'1111'1, 0b1'11111111111'00000'000'00000'0000000},
+      T{0b111111111111111111111'111111'1111'0, 0b1'11111111110'00000'000'00000'0000000},
+      T{0b111111111111111111111'111111'1110'0, 0b1'11111111100'00000'000'00000'0000000},
+      T{0b111111111111111111111'111111'1100'0, 0b1'11111111000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111111'1000'0, 0b1'11111110000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111111'0000'0, 0b1'11111100000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111110'0000'0, 0b1'11111000000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111100'0000'0, 0b1'11110000000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111000'0000'0, 0b1'11100000000'00000'000'00000'0000000},
+      T{0b111111111111111111111'110000'0000'0, 0b1'11000000000'00000'000'00000'0000000},
+      T{0b111111111111111111111'100000'0000'0, 0b1'10000000000'00000'000'00000'0000000},
+      T{0b111111111111111111111'000000'0000'0, 0b1'00000000000'00000'000'00000'0000000},
+      T{0b111111111111111111110'000000'0000'0, {}},
+      T{0b111111111111111111100'000000'0000'0, {}},
+      T{0b111111111111111111000'000000'0000'0, {}},
+      T{0b111111111111111110000'000000'0000'0, {}},
+      T{0b111111111111111100000'000000'0000'0, {}},
+      T{0b111111111111111000000'000000'0000'0, {}},
+      T{0b111111111111110000000'000000'0000'0, {}},
+      T{0b111111111111100000000'000000'0000'0, {}},
+      T{0b111111111111000000000'000000'0000'0, {}},
+      T{0b111111111110000000000'000000'0000'0, {}},
+      T{0b111111111100000000000'000000'0000'0, {}},
+      T{0b111111111000000000000'000000'0000'0, {}},
+      T{0b111111110000000000000'000000'0000'0, {}},
+      T{0b111111100000000000000'000000'0000'0, {}},
+      T{0b111111000000000000000'000000'0000'0, {}},
+      T{0b111110000000000000000'000000'0000'0, {}},
+      T{0b111100000000000000000'000000'0000'0, {}},
+      T{0b111000000000000000000'000000'0000'0, {}},
+      T{0b110000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestJImmediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::JImmediate,
+                 riscv::MakeJImmediate,
+                 riscv::MakeJImmediate,
+                 riscv::MakeJImmediate,
+                 riscv::MakeJImmediate,
+                 riscv::MakeJImmediate,
+                 riscv::MakeJImmediate,
+                 riscv::MakeJImmediate,
+                 riscv::MakeJImmediate>(std::array{
+      T{0b000000000000'00000000'0'0000000000'0, 0b0'0000000000'0'00000'000'0000'0'0000000},
+      //  31        20 19   12 11 10   5 4  1 0   31 30     21 20 19 15     11 8 7 6     0
+      T{0b000000000000'00000000'0'000000'0000'1, {}},
+      T{0b000000000000'00000000'0'000000'0001'0, 0b0'0000000001'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'000000'0010'0, 0b0'0000000010'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'000000'0100'0, 0b0'0000000100'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'000000'1000'0, 0b0'0000001000'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'000001'0000'0, 0b0'0000010000'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'000010'0000'0, 0b0'0000100000'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'000100'0000'0, 0b0'0001000000'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'001000'0000'0, 0b0'0010000000'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'010000'0000'0, 0b0'0100000000'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'0'100000'0000'0, 0b0'1000000000'0'00000'000'0000'0'0000000},
+      T{0b000000000000'00000000'1'000000'0000'0, 0b0'0000000000'1'00000'000'0000'0'0000000},
+      T{0b000000000000'00000001'0'000000'0000'0, 0b0'0000000000'0'00000'001'0000'0'0000000},
+      T{0b000000000000'00000010'0'000000'0000'0, 0b0'0000000000'0'00000'010'0000'0'0000000},
+      T{0b000000000000'00000100'0'000000'0000'0, 0b0'0000000000'0'00000'100'0000'0'0000000},
+      T{0b000000000000'00001000'0'000000'0000'0, 0b0'0000000000'0'00001'000'0000'0'0000000},
+      T{0b000000000000'00010000'0'000000'0000'0, 0b0'0000000000'0'00010'000'0000'0'0000000},
+      T{0b000000000000'00100000'0'000000'0000'0, 0b0'0000000000'0'00100'000'0000'0'0000000},
+      T{0b000000000000'01000000'0'000000'0000'0, 0b0'0000000000'0'01000'000'0000'0'0000000},
+      T{0b000000000000'10000000'0'000000'0000'0, 0b0'0000000000'0'10000'000'0000'0'0000000},
+      T{0b000000000001'00000000'0'000000'0000'0, {}},
+      T{0b000000000010'00000000'0'000000'0000'0, {}},
+      T{0b000000000100'00000000'0'000000'0000'0, {}},
+      T{0b000000001000'00000000'0'000000'0000'0, {}},
+      T{0b000000010000'00000000'0'000000'0000'0, {}},
+      T{0b000000100000'00000000'0'000000'0000'0, {}},
+      T{0b000001000000'00000000'0'000000'0000'0, {}},
+      T{0b000010000000'00000000'0'000000'0000'0, {}},
+      T{0b000100000000'00000000'0'000000'0000'0, {}},
+      T{0b001000000000'00000000'0'000000'0000'0, {}},
+      T{0b010000000000'00000000'0'000000'0000'0, {}},
+      T{0b100000000000'00000000'0'000000'0000'0, {}},
+      //  31        20 19   12 11 10   5 4  1 0   31 30     21 20 19 15     11 8 7 6     0
+      T{0b111111111111'11111111'1'111111'1111'1, {}},
+      T{0b111111111111'11111111'1'111111'1111'0, 0b1'1111111111'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'111111'1110'0, 0b1'1111111110'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'111111'1100'0, 0b1'1111111100'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'111111'1000'0, 0b1'1111111000'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'111111'0000'0, 0b1'1111110000'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'111110'0000'0, 0b1'1111100000'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'111100'0000'0, 0b1'1111000000'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'111000'0000'0, 0b1'1110000000'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'110000'0000'0, 0b1'1100000000'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'100000'0000'0, 0b1'1000000000'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'1'000000'0000'0, 0b1'0000000000'1'11111'111'0000'0'0000000},
+      T{0b111111111111'11111111'0'000000'0000'0, 0b1'0000000000'0'11111'111'0000'0'0000000},
+      T{0b111111111111'11111110'0'000000'0000'0, 0b1'0000000000'0'11111'110'0000'0'0000000},
+      T{0b111111111111'11111100'0'000000'0000'0, 0b1'0000000000'0'11111'100'0000'0'0000000},
+      T{0b111111111111'11111000'0'000000'0000'0, 0b1'0000000000'0'11111'000'0000'0'0000000},
+      T{0b111111111111'11110000'0'000000'0000'0, 0b1'0000000000'0'11110'000'0000'0'0000000},
+      T{0b111111111111'11100000'0'000000'0000'0, 0b1'0000000000'0'11100'000'0000'0'0000000},
+      T{0b111111111111'11000000'0'000000'0000'0, 0b1'0000000000'0'11000'000'0000'0'0000000},
+      T{0b111111111111'10000000'0'000000'0000'0, 0b1'0000000000'0'10000'000'0000'0'0000000},
+      T{0b111111111111'00000000'0'000000'0000'0, 0b1'0000000000'0'00000'000'0000'0'0000000},
+      T{0b111111111110'00000000'0'000000'0000'0, {}},
+      T{0b111111111100'00000000'0'000000'0000'0, {}},
+      T{0b111111111000'00000000'0'000000'0000'0, {}},
+      T{0b111111110000'00000000'0'000000'0000'0, {}},
+      T{0b111111100000'00000000'0'000000'0000'0, {}},
+      T{0b111111000000'00000000'0'000000'0000'0, {}},
+      T{0b111110000000'00000000'0'000000'0000'0, {}},
+      T{0b111100000000'00000000'0'000000'0000'0, {}},
+      T{0b111000000000'00000000'0'000000'0000'0, {}},
+      T{0b110000000000'00000000'0'000000'0000'0, {}},
+      T{0b100000000000'00000000'0'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestPImmediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::PImmediate,
+                 riscv::MakePImmediate,
+                 riscv::MakePImmediate,
+                 riscv::MakePImmediate,
+                 riscv::MakePImmediate,
+                 riscv::MakePImmediate,
+                 riscv::MakePImmediate,
+                 riscv::MakePImmediate,
+                 riscv::MakePImmediate>(std::array{
+      T{0b000000000000000000000'000000'0000'0, 0b0'000000'00000'00000'000'00000'0000000},
+      //  31                 11 10   5 4  1 0   31 30  25 24 20 19 15     11  7 6     0
+      T{0b000000000000000000000'000000'0000'1, {}},
+      T{0b000000000000000000000'000000'0001'0, {}},
+      T{0b000000000000000000000'000000'0010'0, {}},
+      T{0b000000000000000000000'000000'0100'0, {}},
+      T{0b000000000000000000000'000000'1000'0, {}},
+      T{0b000000000000000000000'000001'0000'0, 0b0'000001'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000010'0000'0, 0b0'000010'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000100'0000'0, 0b0'000100'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'001000'0000'0, 0b0'001000'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'010000'0000'0, 0b0'010000'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'100000'0000'0, 0b0'100000'00000'00000'000'00000'0000000},
+      T{0b000000000000000000001'000000'0000'0, {}},
+      T{0b000000000000000000010'000000'0000'0, {}},
+      T{0b000000000000000000100'000000'0000'0, {}},
+      T{0b000000000000000001000'000000'0000'0, {}},
+      T{0b000000000000000010000'000000'0000'0, {}},
+      T{0b000000000000000100000'000000'0000'0, {}},
+      T{0b000000000000001000000'000000'0000'0, {}},
+      T{0b000000000000010000000'000000'0000'0, {}},
+      T{0b000000000000100000000'000000'0000'0, {}},
+      T{0b000000000001000000000'000000'0000'0, {}},
+      T{0b000000000010000000000'000000'0000'0, {}},
+      T{0b000000000100000000000'000000'0000'0, {}},
+      T{0b000000001000000000000'000000'0000'0, {}},
+      T{0b000000010000000000000'000000'0000'0, {}},
+      T{0b000000100000000000000'000000'0000'0, {}},
+      T{0b000001000000000000000'000000'0000'0, {}},
+      T{0b000010000000000000000'000000'0000'0, {}},
+      T{0b000100000000000000000'000000'0000'0, {}},
+      T{0b001000000000000000000'000000'0000'0, {}},
+      T{0b010000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+      //  31                 11 10   5 4  1 0   31 30  25 24 20 19 15     11  7 6     0
+      T{0b111111111111111111111'111111'1111'1, {}},
+      T{0b111111111111111111111'111111'1111'0, {}},
+      T{0b111111111111111111111'111111'1110'0, {}},
+      T{0b111111111111111111111'111111'1100'0, {}},
+      T{0b111111111111111111111'111111'1000'0, {}},
+      T{0b111111111111111111111'111111'0000'0, 0b1'111111'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111110'0000'0, 0b1'111110'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111100'0000'0, 0b1'111100'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111000'0000'0, 0b1'111000'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'110000'0000'0, 0b1'110000'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'100000'0000'0, 0b1'100000'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'000000'0000'0, 0b1'000000'00000'00000'000'00000'0000000},
+      T{0b111111111111111111110'000000'0000'0, {}},
+      T{0b111111111111111111100'000000'0000'0, {}},
+      T{0b111111111111111111000'000000'0000'0, {}},
+      T{0b111111111111111110000'000000'0000'0, {}},
+      T{0b111111111111111100000'000000'0000'0, {}},
+      T{0b111111111111111000000'000000'0000'0, {}},
+      T{0b111111111111110000000'000000'0000'0, {}},
+      T{0b111111111111100000000'000000'0000'0, {}},
+      T{0b111111111111000000000'000000'0000'0, {}},
+      T{0b111111111110000000000'000000'0000'0, {}},
+      T{0b111111111100000000000'000000'0000'0, {}},
+      T{0b111111111000000000000'000000'0000'0, {}},
+      T{0b111111110000000000000'000000'0000'0, {}},
+      T{0b111111100000000000000'000000'0000'0, {}},
+      T{0b111111000000000000000'000000'0000'0, {}},
+      T{0b111110000000000000000'000000'0000'0, {}},
+      T{0b111100000000000000000'000000'0000'0, {}},
+      T{0b111000000000000000000'000000'0000'0, {}},
+      T{0b110000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestShiftImmediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<rv32::Assembler::ShiftImmediate,
+                 rv32::Assembler::MakeShiftImmediate,
+                 rv32::Assembler::MakeShiftImmediate,
+                 rv32::Assembler::MakeShiftImmediate,
+                 rv32::Assembler::MakeShiftImmediate,
+                 rv32::Assembler::MakeShiftImmediate,
+                 rv32::Assembler::MakeShiftImmediate,
+                 rv32::Assembler::MakeShiftImmediate,
+                 rv32::Assembler::MakeShiftImmediate>(std::array{
+      T{0b000000000000000000000'000000'0000'0, 0b0'00000000000'00000'000'00000'0000000},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b000000000000000000000'000000'0000'1, 0b0'00000000001'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0001'0, 0b0'00000000010'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0010'0, 0b0'00000000100'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0100'0, 0b0'00000001000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'1000'0, 0b0'00000010000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000001'0000'0, {}},
+      T{0b000000000000000000000'000010'0000'0, {}},
+      T{0b000000000000000000000'000100'0000'0, {}},
+      T{0b000000000000000000000'001000'0000'0, {}},
+      T{0b000000000000000000000'010000'0000'0, {}},
+      T{0b000000000000000000000'100000'0000'0, {}},
+      T{0b000000000000000000001'000000'0000'0, {}},
+      T{0b000000000000000000010'000000'0000'0, {}},
+      T{0b000000000000000000100'000000'0000'0, {}},
+      T{0b000000000000000001000'000000'0000'0, {}},
+      T{0b000000000000000010000'000000'0000'0, {}},
+      T{0b000000000000000100000'000000'0000'0, {}},
+      T{0b000000000000001000000'000000'0000'0, {}},
+      T{0b000000000000010000000'000000'0000'0, {}},
+      T{0b000000000000100000000'000000'0000'0, {}},
+      T{0b000000000001000000000'000000'0000'0, {}},
+      T{0b000000000010000000000'000000'0000'0, {}},
+      T{0b000000000100000000000'000000'0000'0, {}},
+      T{0b000000001000000000000'000000'0000'0, {}},
+      T{0b000000010000000000000'000000'0000'0, {}},
+      T{0b000000100000000000000'000000'0000'0, {}},
+      T{0b000001000000000000000'000000'0000'0, {}},
+      T{0b000010000000000000000'000000'0000'0, {}},
+      T{0b000100000000000000000'000000'0000'0, {}},
+      T{0b001000000000000000000'000000'0000'0, {}},
+      T{0b010000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b111111111111111111111'111111'1111'1, {}},
+      T{0b111111111111111111111'111111'1111'0, {}},
+      T{0b111111111111111111111'111111'1110'0, {}},
+      T{0b111111111111111111111'111111'1100'0, {}},
+      T{0b111111111111111111111'111111'1000'0, {}},
+      T{0b111111111111111111111'111111'0000'0, {}},
+      T{0b111111111111111111111'111110'0000'0, {}},
+      T{0b111111111111111111111'111100'0000'0, {}},
+      T{0b111111111111111111111'111000'0000'0, {}},
+      T{0b111111111111111111111'110000'0000'0, {}},
+      T{0b111111111111111111111'100000'0000'0, {}},
+      T{0b111111111111111111111'000000'0000'0, {}},
+      T{0b111111111111111111110'000000'0000'0, {}},
+      T{0b111111111111111111100'000000'0000'0, {}},
+      T{0b111111111111111111000'000000'0000'0, {}},
+      T{0b111111111111111110000'000000'0000'0, {}},
+      T{0b111111111111111100000'000000'0000'0, {}},
+      T{0b111111111111111000000'000000'0000'0, {}},
+      T{0b111111111111110000000'000000'0000'0, {}},
+      T{0b111111111111100000000'000000'0000'0, {}},
+      T{0b111111111111000000000'000000'0000'0, {}},
+      T{0b111111111110000000000'000000'0000'0, {}},
+      T{0b111111111100000000000'000000'0000'0, {}},
+      T{0b111111111000000000000'000000'0000'0, {}},
+      T{0b111111110000000000000'000000'0000'0, {}},
+      T{0b111111100000000000000'000000'0000'0, {}},
+      T{0b111111000000000000000'000000'0000'0, {}},
+      T{0b111110000000000000000'000000'0000'0, {}},
+      T{0b111100000000000000000'000000'0000'0, {}},
+      T{0b111000000000000000000'000000'0000'0, {}},
+      T{0b110000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+  });
+  TestConversion<rv64::Assembler::ShiftImmediate,
+                 rv64::Assembler::MakeShiftImmediate,
+                 rv64::Assembler::MakeShiftImmediate,
+                 rv64::Assembler::MakeShiftImmediate,
+                 rv64::Assembler::MakeShiftImmediate,
+                 rv64::Assembler::MakeShiftImmediate,
+                 rv64::Assembler::MakeShiftImmediate,
+                 rv64::Assembler::MakeShiftImmediate,
+                 rv64::Assembler::MakeShiftImmediate>(std::array{
+      T{0b000000000000000000000'000000'0000'0, 0b0'00000000000'00000'000'00000'0000000},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b000000000000000000000'000000'0000'1, 0b0'00000000001'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0001'0, 0b0'00000000010'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0010'0, 0b0'00000000100'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0100'0, 0b0'00000001000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'1000'0, 0b0'00000010000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000001'0000'0, 0b0'00000100000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000010'0000'0, {}},
+      T{0b000000000000000000000'000100'0000'0, {}},
+      T{0b000000000000000000000'001000'0000'0, {}},
+      T{0b000000000000000000000'010000'0000'0, {}},
+      T{0b000000000000000000000'100000'0000'0, {}},
+      T{0b000000000000000000001'000000'0000'0, {}},
+      T{0b000000000000000000010'000000'0000'0, {}},
+      T{0b000000000000000000100'000000'0000'0, {}},
+      T{0b000000000000000001000'000000'0000'0, {}},
+      T{0b000000000000000010000'000000'0000'0, {}},
+      T{0b000000000000000100000'000000'0000'0, {}},
+      T{0b000000000000001000000'000000'0000'0, {}},
+      T{0b000000000000010000000'000000'0000'0, {}},
+      T{0b000000000000100000000'000000'0000'0, {}},
+      T{0b000000000001000000000'000000'0000'0, {}},
+      T{0b000000000010000000000'000000'0000'0, {}},
+      T{0b000000000100000000000'000000'0000'0, {}},
+      T{0b000000001000000000000'000000'0000'0, {}},
+      T{0b000000010000000000000'000000'0000'0, {}},
+      T{0b000000100000000000000'000000'0000'0, {}},
+      T{0b000001000000000000000'000000'0000'0, {}},
+      T{0b000010000000000000000'000000'0000'0, {}},
+      T{0b000100000000000000000'000000'0000'0, {}},
+      T{0b001000000000000000000'000000'0000'0, {}},
+      T{0b010000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b111111111111111111111'111111'1111'1, {}},
+      T{0b111111111111111111111'111111'1111'0, {}},
+      T{0b111111111111111111111'111111'1110'0, {}},
+      T{0b111111111111111111111'111111'1100'0, {}},
+      T{0b111111111111111111111'111111'1000'0, {}},
+      T{0b111111111111111111111'111111'0000'0, {}},
+      T{0b111111111111111111111'111110'0000'0, {}},
+      T{0b111111111111111111111'111100'0000'0, {}},
+      T{0b111111111111111111111'111000'0000'0, {}},
+      T{0b111111111111111111111'110000'0000'0, {}},
+      T{0b111111111111111111111'100000'0000'0, {}},
+      T{0b111111111111111111111'000000'0000'0, {}},
+      T{0b111111111111111111110'000000'0000'0, {}},
+      T{0b111111111111111111100'000000'0000'0, {}},
+      T{0b111111111111111111000'000000'0000'0, {}},
+      T{0b111111111111111110000'000000'0000'0, {}},
+      T{0b111111111111111100000'000000'0000'0, {}},
+      T{0b111111111111111000000'000000'0000'0, {}},
+      T{0b111111111111110000000'000000'0000'0, {}},
+      T{0b111111111111100000000'000000'0000'0, {}},
+      T{0b111111111111000000000'000000'0000'0, {}},
+      T{0b111111111110000000000'000000'0000'0, {}},
+      T{0b111111111100000000000'000000'0000'0, {}},
+      T{0b111111111000000000000'000000'0000'0, {}},
+      T{0b111111110000000000000'000000'0000'0, {}},
+      T{0b111111100000000000000'000000'0000'0, {}},
+      T{0b111111000000000000000'000000'0000'0, {}},
+      T{0b111110000000000000000'000000'0000'0, {}},
+      T{0b111100000000000000000'000000'0000'0, {}},
+      T{0b111000000000000000000'000000'0000'0, {}},
+      T{0b110000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestShift32Immediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::Shift32Immediate,
+                 riscv::MakeShift32Immediate,
+                 riscv::MakeShift32Immediate,
+                 riscv::MakeShift32Immediate,
+                 riscv::MakeShift32Immediate,
+                 riscv::MakeShift32Immediate,
+                 riscv::MakeShift32Immediate,
+                 riscv::MakeShift32Immediate,
+                 riscv::MakeShift32Immediate>(std::array{
+      T{0b000000000000000000000'000000'0000'0, 0b0'00000000000'00000'000'00000'0000000},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b000000000000000000000'000000'0000'1, 0b0'00000000001'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0001'0, 0b0'00000000010'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0010'0, 0b0'00000000100'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0100'0, 0b0'00000001000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'1000'0, 0b0'00000010000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000001'0000'0, {}},
+      T{0b000000000000000000000'000010'0000'0, {}},
+      T{0b000000000000000000000'000100'0000'0, {}},
+      T{0b000000000000000000000'001000'0000'0, {}},
+      T{0b000000000000000000000'010000'0000'0, {}},
+      T{0b000000000000000000000'100000'0000'0, {}},
+      T{0b000000000000000000001'000000'0000'0, {}},
+      T{0b000000000000000000010'000000'0000'0, {}},
+      T{0b000000000000000000100'000000'0000'0, {}},
+      T{0b000000000000000001000'000000'0000'0, {}},
+      T{0b000000000000000010000'000000'0000'0, {}},
+      T{0b000000000000000100000'000000'0000'0, {}},
+      T{0b000000000000001000000'000000'0000'0, {}},
+      T{0b000000000000010000000'000000'0000'0, {}},
+      T{0b000000000000100000000'000000'0000'0, {}},
+      T{0b000000000001000000000'000000'0000'0, {}},
+      T{0b000000000010000000000'000000'0000'0, {}},
+      T{0b000000000100000000000'000000'0000'0, {}},
+      T{0b000000001000000000000'000000'0000'0, {}},
+      T{0b000000010000000000000'000000'0000'0, {}},
+      T{0b000000100000000000000'000000'0000'0, {}},
+      T{0b000001000000000000000'000000'0000'0, {}},
+      T{0b000010000000000000000'000000'0000'0, {}},
+      T{0b000100000000000000000'000000'0000'0, {}},
+      T{0b001000000000000000000'000000'0000'0, {}},
+      T{0b010000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b111111111111111111111'111111'1111'1, {}},
+      T{0b111111111111111111111'111111'1111'0, {}},
+      T{0b111111111111111111111'111111'1110'0, {}},
+      T{0b111111111111111111111'111111'1100'0, {}},
+      T{0b111111111111111111111'111111'1000'0, {}},
+      T{0b111111111111111111111'111111'0000'0, {}},
+      T{0b111111111111111111111'111110'0000'0, {}},
+      T{0b111111111111111111111'111100'0000'0, {}},
+      T{0b111111111111111111111'111000'0000'0, {}},
+      T{0b111111111111111111111'110000'0000'0, {}},
+      T{0b111111111111111111111'100000'0000'0, {}},
+      T{0b111111111111111111111'000000'0000'0, {}},
+      T{0b111111111111111111110'000000'0000'0, {}},
+      T{0b111111111111111111100'000000'0000'0, {}},
+      T{0b111111111111111111000'000000'0000'0, {}},
+      T{0b111111111111111110000'000000'0000'0, {}},
+      T{0b111111111111111100000'000000'0000'0, {}},
+      T{0b111111111111111000000'000000'0000'0, {}},
+      T{0b111111111111110000000'000000'0000'0, {}},
+      T{0b111111111111100000000'000000'0000'0, {}},
+      T{0b111111111111000000000'000000'0000'0, {}},
+      T{0b111111111110000000000'000000'0000'0, {}},
+      T{0b111111111100000000000'000000'0000'0, {}},
+      T{0b111111111000000000000'000000'0000'0, {}},
+      T{0b111111110000000000000'000000'0000'0, {}},
+      T{0b111111100000000000000'000000'0000'0, {}},
+      T{0b111111000000000000000'000000'0000'0, {}},
+      T{0b111110000000000000000'000000'0000'0, {}},
+      T{0b111100000000000000000'000000'0000'0, {}},
+      T{0b111000000000000000000'000000'0000'0, {}},
+      T{0b110000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestShift64Immediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::Shift64Immediate,
+                 riscv::MakeShift64Immediate,
+                 riscv::MakeShift64Immediate,
+                 riscv::MakeShift64Immediate,
+                 riscv::MakeShift64Immediate,
+                 riscv::MakeShift64Immediate,
+                 riscv::MakeShift64Immediate,
+                 riscv::MakeShift64Immediate,
+                 riscv::MakeShift64Immediate>(std::array{
+      T{0b000000000000000000000'000000'0000'0, 0b0'00000000000'00000'000'00000'0000000},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b000000000000000000000'000000'0000'1, 0b0'00000000001'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0001'0, 0b0'00000000010'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0010'0, 0b0'00000000100'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'0100'0, 0b0'00000001000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000000'1000'0, 0b0'00000010000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000001'0000'0, 0b0'00000100000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000010'0000'0, {}},
+      T{0b000000000000000000000'000100'0000'0, {}},
+      T{0b000000000000000000000'001000'0000'0, {}},
+      T{0b000000000000000000000'010000'0000'0, {}},
+      T{0b000000000000000000000'100000'0000'0, {}},
+      T{0b000000000000000000001'000000'0000'0, {}},
+      T{0b000000000000000000010'000000'0000'0, {}},
+      T{0b000000000000000000100'000000'0000'0, {}},
+      T{0b000000000000000001000'000000'0000'0, {}},
+      T{0b000000000000000010000'000000'0000'0, {}},
+      T{0b000000000000000100000'000000'0000'0, {}},
+      T{0b000000000000001000000'000000'0000'0, {}},
+      T{0b000000000000010000000'000000'0000'0, {}},
+      T{0b000000000000100000000'000000'0000'0, {}},
+      T{0b000000000001000000000'000000'0000'0, {}},
+      T{0b000000000010000000000'000000'0000'0, {}},
+      T{0b000000000100000000000'000000'0000'0, {}},
+      T{0b000000001000000000000'000000'0000'0, {}},
+      T{0b000000010000000000000'000000'0000'0, {}},
+      T{0b000000100000000000000'000000'0000'0, {}},
+      T{0b000001000000000000000'000000'0000'0, {}},
+      T{0b000010000000000000000'000000'0000'0, {}},
+      T{0b000100000000000000000'000000'0000'0, {}},
+      T{0b001000000000000000000'000000'0000'0, {}},
+      T{0b010000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+      //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
+      T{0b111111111111111111111'111111'1111'1, {}},
+      T{0b111111111111111111111'111111'1111'0, {}},
+      T{0b111111111111111111111'111111'1110'0, {}},
+      T{0b111111111111111111111'111111'1100'0, {}},
+      T{0b111111111111111111111'111111'1000'0, {}},
+      T{0b111111111111111111111'111111'0000'0, {}},
+      T{0b111111111111111111111'111110'0000'0, {}},
+      T{0b111111111111111111111'111100'0000'0, {}},
+      T{0b111111111111111111111'111000'0000'0, {}},
+      T{0b111111111111111111111'110000'0000'0, {}},
+      T{0b111111111111111111111'100000'0000'0, {}},
+      T{0b111111111111111111111'000000'0000'0, {}},
+      T{0b111111111111111111110'000000'0000'0, {}},
+      T{0b111111111111111111100'000000'0000'0, {}},
+      T{0b111111111111111111000'000000'0000'0, {}},
+      T{0b111111111111111110000'000000'0000'0, {}},
+      T{0b111111111111111100000'000000'0000'0, {}},
+      T{0b111111111111111000000'000000'0000'0, {}},
+      T{0b111111111111110000000'000000'0000'0, {}},
+      T{0b111111111111100000000'000000'0000'0, {}},
+      T{0b111111111111000000000'000000'0000'0, {}},
+      T{0b111111111110000000000'000000'0000'0, {}},
+      T{0b111111111100000000000'000000'0000'0, {}},
+      T{0b111111111000000000000'000000'0000'0, {}},
+      T{0b111111110000000000000'000000'0000'0, {}},
+      T{0b111111100000000000000'000000'0000'0, {}},
+      T{0b111111000000000000000'000000'0000'0, {}},
+      T{0b111110000000000000000'000000'0000'0, {}},
+      T{0b111100000000000000000'000000'0000'0, {}},
+      T{0b111000000000000000000'000000'0000'0, {}},
+      T{0b110000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestSImmediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::SImmediate,
+                 riscv::MakeSImmediate,
+                 riscv::MakeSImmediate,
+                 riscv::MakeSImmediate,
+                 riscv::MakeSImmediate,
+                 riscv::MakeSImmediate,
+                 riscv::MakeSImmediate,
+                 riscv::MakeSImmediate,
+                 riscv::MakeSImmediate>(std::array{
+      T{0b000000000000000000000'000000'0000'0, 0b0'000000'00000'00000'000'00000'0000000},
+      //  31                 11 10   5 4  1 0   31 30  25 24 20 19 15     11  7 6     0
+      T{0b000000000000000000000'000000'0000'1, 0b0'000000'00000'00000'000'00001'0000000},
+      T{0b000000000000000000000'000000'0001'0, 0b0'000000'00000'00000'000'00010'0000000},
+      T{0b000000000000000000000'000000'0010'0, 0b0'000000'00000'00000'000'00100'0000000},
+      T{0b000000000000000000000'000000'0100'0, 0b0'000000'00000'00000'000'01000'0000000},
+      T{0b000000000000000000000'000000'1000'0, 0b0'000000'00000'00000'000'10000'0000000},
+      T{0b000000000000000000000'000001'0000'0, 0b0'000001'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000010'0000'0, 0b0'000010'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'000100'0000'0, 0b0'000100'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'001000'0000'0, 0b0'001000'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'010000'0000'0, 0b0'010000'00000'00000'000'00000'0000000},
+      T{0b000000000000000000000'100000'0000'0, 0b0'100000'00000'00000'000'00000'0000000},
+      T{0b000000000000000000001'000000'0000'0, {}},
+      T{0b000000000000000000010'000000'0000'0, {}},
+      T{0b000000000000000000100'000000'0000'0, {}},
+      T{0b000000000000000001000'000000'0000'0, {}},
+      T{0b000000000000000010000'000000'0000'0, {}},
+      T{0b000000000000000100000'000000'0000'0, {}},
+      T{0b000000000000001000000'000000'0000'0, {}},
+      T{0b000000000000010000000'000000'0000'0, {}},
+      T{0b000000000000100000000'000000'0000'0, {}},
+      T{0b000000000001000000000'000000'0000'0, {}},
+      T{0b000000000010000000000'000000'0000'0, {}},
+      T{0b000000000100000000000'000000'0000'0, {}},
+      T{0b000000001000000000000'000000'0000'0, {}},
+      T{0b000000010000000000000'000000'0000'0, {}},
+      T{0b000000100000000000000'000000'0000'0, {}},
+      T{0b000001000000000000000'000000'0000'0, {}},
+      T{0b000010000000000000000'000000'0000'0, {}},
+      T{0b000100000000000000000'000000'0000'0, {}},
+      T{0b001000000000000000000'000000'0000'0, {}},
+      T{0b010000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+      //  31                 11 10   5 4  1 0   31 30  25 24 20 19 15     11  7 6     0
+      T{0b111111111111111111111'111111'1111'1, 0b1'111111'00000'00000'000'11111'0000000},
+      T{0b111111111111111111111'111111'1111'0, 0b1'111111'00000'00000'000'11110'0000000},
+      T{0b111111111111111111111'111111'1110'0, 0b1'111111'00000'00000'000'11100'0000000},
+      T{0b111111111111111111111'111111'1100'0, 0b1'111111'00000'00000'000'11000'0000000},
+      T{0b111111111111111111111'111111'1000'0, 0b1'111111'00000'00000'000'10000'0000000},
+      T{0b111111111111111111111'111111'0000'0, 0b1'111111'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111110'0000'0, 0b1'111110'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111100'0000'0, 0b1'111100'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'111000'0000'0, 0b1'111000'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'110000'0000'0, 0b1'110000'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'100000'0000'0, 0b1'100000'00000'00000'000'00000'0000000},
+      T{0b111111111111111111111'000000'0000'0, 0b1'000000'00000'00000'000'00000'0000000},
+      T{0b111111111111111111110'000000'0000'0, {}},
+      T{0b111111111111111111100'000000'0000'0, {}},
+      T{0b111111111111111111000'000000'0000'0, {}},
+      T{0b111111111111111110000'000000'0000'0, {}},
+      T{0b111111111111111100000'000000'0000'0, {}},
+      T{0b111111111111111000000'000000'0000'0, {}},
+      T{0b111111111111110000000'000000'0000'0, {}},
+      T{0b111111111111100000000'000000'0000'0, {}},
+      T{0b111111111111000000000'000000'0000'0, {}},
+      T{0b111111111110000000000'000000'0000'0, {}},
+      T{0b111111111100000000000'000000'0000'0, {}},
+      T{0b111111111000000000000'000000'0000'0, {}},
+      T{0b111111110000000000000'000000'0000'0, {}},
+      T{0b111111100000000000000'000000'0000'0, {}},
+      T{0b111111000000000000000'000000'0000'0, {}},
+      T{0b111110000000000000000'000000'0000'0, {}},
+      T{0b111100000000000000000'000000'0000'0, {}},
+      T{0b111000000000000000000'000000'0000'0, {}},
+      T{0b110000000000000000000'000000'0000'0, {}},
+      T{0b100000000000000000000'000000'0000'0, {}},
+  });
+}
+
+TEST_F(Riscv64ImmediatesTest, TestUImmediate) {
+  using T = std::tuple<uint32_t, std::optional<uint32_t>>;
+  TestConversion<riscv::UImmediate,
+                 riscv::MakeUImmediate,
+                 riscv::MakeUImmediate,
+                 riscv::MakeUImmediate,
+                 riscv::MakeUImmediate,
+                 riscv::MakeUImmediate,
+                 riscv::MakeUImmediate,
+                 riscv::MakeUImmediate,
+                 riscv::MakeUImmediate>(std::array{
+      T{0b0'00000000000'00000000'000000000000, 0b00000000000000000000'00000'0000000},
+      // 31 30       20 19    12 11         0    31                12 11  7 6     0
+      T{0b0'00000000000'00000000'000000000001, {}},
+      T{0b0'00000000000'00000000'000000000010, {}},
+      T{0b0'00000000000'00000000'000000000100, {}},
+      T{0b0'00000000000'00000000'000000001000, {}},
+      T{0b0'00000000000'00000000'000000010000, {}},
+      T{0b0'00000000000'00000000'000000100000, {}},
+      T{0b0'00000000000'00000000'000001000000, {}},
+      T{0b0'00000000000'00000000'000010000000, {}},
+      T{0b0'00000000000'00000000'000100000000, {}},
+      T{0b0'00000000000'00000000'001000000000, {}},
+      T{0b0'00000000000'00000000'010000000000, {}},
+      T{0b0'00000000000'00000000'100000000000, {}},
+      T{0b0'00000000000'00000001'000000000000, 0b00000000000000000001'00000'0000000},
+      T{0b0'00000000000'00000010'000000000000, 0b00000000000000000010'00000'0000000},
+      T{0b0'00000000000'00000100'000000000000, 0b00000000000000000100'00000'0000000},
+      T{0b0'00000000000'00001000'000000000000, 0b00000000000000001000'00000'0000000},
+      T{0b0'00000000000'00010000'000000000000, 0b00000000000000010000'00000'0000000},
+      T{0b0'00000000000'00100000'000000000000, 0b00000000000000100000'00000'0000000},
+      T{0b0'00000000000'01000000'000000000000, 0b00000000000001000000'00000'0000000},
+      T{0b0'00000000000'10000000'000000000000, 0b00000000000010000000'00000'0000000},
+      T{0b0'00000000001'00000000'000000000000, 0b00000000000100000000'00000'0000000},
+      T{0b0'00000000010'00000000'000000000000, 0b00000000001000000000'00000'0000000},
+      T{0b0'00000000100'00000000'000000000000, 0b00000000010000000000'00000'0000000},
+      T{0b0'00000001000'00000000'000000000000, 0b00000000100000000000'00000'0000000},
+      T{0b0'00000010000'00000000'000000000000, 0b00000001000000000000'00000'0000000},
+      T{0b0'00000100000'00000000'000000000000, 0b00000010000000000000'00000'0000000},
+      T{0b0'00001000000'00000000'000000000000, 0b00000100000000000000'00000'0000000},
+      T{0b0'00010000000'00000000'000000000000, 0b00001000000000000000'00000'0000000},
+      T{0b0'00100000000'00000000'000000000000, 0b00010000000000000000'00000'0000000},
+      T{0b0'01000000000'00000000'000000000000, 0b00100000000000000000'00000'0000000},
+      T{0b0'10000000000'00000000'000000000000, 0b01000000000000000000'00000'0000000},
+      // 31 30       20 19    12 11         0    31                12 11  7 6     0
+      T{0b1'11111111111'11111111'111111111111, {}},
+      T{0b1'11111111111'11111111'111111111110, {}},
+      T{0b1'11111111111'11111111'111111111100, {}},
+      T{0b1'11111111111'11111111'111111111000, {}},
+      T{0b1'11111111111'11111111'111111110000, {}},
+      T{0b1'11111111111'11111111'111111100000, {}},
+      T{0b1'11111111111'11111111'111111000000, {}},
+      T{0b1'11111111111'11111111'111110000000, {}},
+      T{0b1'11111111111'11111111'111100000000, {}},
+      T{0b1'11111111111'11111111'111000000000, {}},
+      T{0b1'11111111111'11111111'110000000000, {}},
+      T{0b1'11111111111'11111111'100000000000, {}},
+      T{0b1'11111111111'11111111'000000000000, 0b11111111111111111111'00000'0000000},
+      T{0b1'11111111111'11111110'000000000000, 0b11111111111111111110'00000'0000000},
+      T{0b1'11111111111'11111100'000000000000, 0b11111111111111111100'00000'0000000},
+      T{0b1'11111111111'11111000'000000000000, 0b11111111111111111000'00000'0000000},
+      T{0b1'11111111111'11110000'000000000000, 0b11111111111111110000'00000'0000000},
+      T{0b1'11111111111'11100000'000000000000, 0b11111111111111100000'00000'0000000},
+      T{0b1'11111111111'11000000'000000000000, 0b11111111111111000000'00000'0000000},
+      T{0b1'11111111111'10000000'000000000000, 0b11111111111110000000'00000'0000000},
+      T{0b1'11111111111'00000000'000000000000, 0b11111111111100000000'00000'0000000},
+      T{0b1'11111111110'00000000'000000000000, 0b11111111111000000000'00000'0000000},
+      T{0b1'11111111100'00000000'000000000000, 0b11111111110000000000'00000'0000000},
+      T{0b1'11111111000'00000000'000000000000, 0b11111111100000000000'00000'0000000},
+      T{0b1'11111110000'00000000'000000000000, 0b11111111000000000000'00000'0000000},
+      T{0b1'11111100000'00000000'000000000000, 0b11111110000000000000'00000'0000000},
+      T{0b1'11111000000'00000000'000000000000, 0b11111100000000000000'00000'0000000},
+      T{0b1'11110000000'00000000'000000000000, 0b11111000000000000000'00000'0000000},
+      T{0b1'11100000000'00000000'000000000000, 0b11110000000000000000'00000'0000000},
+      T{0b1'11000000000'00000000'000000000000, 0b11100000000000000000'00000'0000000},
+      T{0b1'10000000000'00000000'000000000000, 0b11000000000000000000'00000'0000000},
+      T{0b1'00000000000'00000000'000000000000, 0b10000000000000000000'00000'0000000},
+  });
+}
+
+}  // namespace
+
+}  // namespace berberis
diff --git a/assembler/include/berberis/assembler/common.h b/assembler/include/berberis/assembler/common.h
index 59030685..91a09039 100644
--- a/assembler/include/berberis/assembler/common.h
+++ b/assembler/include/berberis/assembler/common.h
@@ -120,6 +120,8 @@ class AssemblerBase {
 
   // These are 'static' relocations, resolved when code is finalized.
   // We also have 'dynamic' relocations, resolved when code is installed.
+  // TODO(b/232598137): rename Jump to something more appropriate since we are supporting
+  // memory-accessing instructions, not just jumps.
   struct Jump {
     const Label* label;
     // Position of field to store offset.  Note: unless it's recovery label precomputed
@@ -140,6 +142,17 @@ class AssemblerBase {
   DISALLOW_IMPLICIT_CONSTRUCTORS(AssemblerBase);
 };
 
+// Return the reverse condition. On all architectures that we may care about (AArch32/AArch64,
+// RISC-V and x86) this can be achieved with a simple bitflop of the lowest bit.
+// We may need a specialization of that function for more exotic architectures.
+template <typename Condition>
+inline constexpr Condition ToReverseCond(Condition cond) {
+  CHECK(cond != Condition::kInvalidCondition);
+  // Condition has a nice property that given a condition, you can get
+  // its reverse condition by flipping the least significant bit.
+  return Condition(static_cast<int>(cond) ^ 1);
+}
+
 }  // namespace berberis
 
 #endif  // BERBERIS_ASSEMBLER_COMMON_H_
diff --git a/assembler/include/berberis/assembler/riscv.h b/assembler/include/berberis/assembler/riscv.h
new file mode 100644
index 00000000..3771246c
--- /dev/null
+++ b/assembler/include/berberis/assembler/riscv.h
@@ -0,0 +1,1231 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef BERBERIS_ASSEMBLER_COMMON_RISCV_H_
+#define BERBERIS_ASSEMBLER_COMMON_RISCV_H_
+
+#include <cstddef>  // std::size_t
+#include <cstdint>
+#include <type_traits>  // std::enable_if, std::is_integral
+
+#include "berberis/assembler/common.h"
+#include "berberis/base/bit_util.h"
+#include "berberis/base/checks.h"
+
+namespace berberis {
+
+namespace rv32e {
+
+class Assembler;
+
+}  // namespace rv32e
+
+namespace rv32i {
+
+class Assembler;
+
+}  // namespace rv32i
+
+namespace rv64i {
+
+class Assembler;
+
+}  // namespace rv64i
+
+// riscv::Assembler includes implementation of most Risc V assembler instructions.
+//
+// RV32 and RV64 assemblers are nearly identical, but difference lies in handling
+// of some instructions: RV32 uses certain encodings differently to handle compressed
+// instructions, while RV64 adds some extra instructions to handle 32bit quantities
+// (*not* 64bit quantities as the name implies, instead there are width-native instructions
+// and extra 32bit ones for RV64).
+//
+// To handle that difference efficiently riscv::Assembler is CRTP class: it's parameterized
+// by its own descendant and pull certain functions from its implementation.
+
+namespace riscv {
+
+template <typename DerivedAssemblerType>
+class Assembler;
+
+enum class Condition {
+  kInvalidCondition = -1,
+
+  kEqual = 0,
+  kNotEqual = 1,
+  kLess = 4,
+  kGreaterEqual = 5,
+  kBelow = 6,
+  kAboveEqual = 7,
+  kAlways = 8,
+  kNever = 9,
+
+  // aka...
+  kCarry = kBelow,
+  kNotCarry = kAboveEqual,
+  kZero = kEqual,
+  kNotZero = kNotEqual
+};
+
+enum class Csr {
+  kFFlags = 0b00'00'0000'0001,
+  kFrm = 0b00'00'0000'0010,
+  kFCsr = 0b00'00'0000'0011,
+  kVstart = 0b00'00'0000'1000,
+  kVxsat = 0b00'00'0000'1001,
+  kVxrm = 0b00'00'0000'1010,
+  kVcsr = 0b00'00'0000'1111,
+  kCycle = 0b11'00'0000'0000,
+  kVl = 0b11'00'0010'0000,
+  kVtype = 0b11'00'0010'0001,
+  kVlenb = 0b11'00'0010'0010,
+};
+
+enum class Rounding { kRne = 0, kRtz = 1, kRdn = 2, kRup = 3, kRmm = 4, kDyn = 7 };
+
+// Immediates are kept in a form ready to be used with emitter.
+class BImmediate;
+class CsrImmediate;
+class IImmediate;
+using Immediate = IImmediate;
+class JImmediate;
+// In RISC V manual shifts are described as using I-format with complex restrictions for which
+// immediates are accepted and allowed (with parts of what manual classifies as “immediate” used
+// to determine the actual instruction used and rules which differ between RV32 and RV64!).
+//
+// Instead of doing special handling for the instructions in python scripts we just reclassify
+// these parts of immediate as “opcode” and reclassify these instructions as “Shift32-type” and
+// “Shift64-type”.
+//
+// This also means that the same instructions for RV32 and RV64 would have different types, but
+// since we don't have a goal to make RV32 a strict subset of RV64 that's acceptable.
+//
+// In addition we provide aliases in RV32 and RV64 assemblers to make sure users of assembler may
+// still use ShiftImmediate and MakeShiftImmediate for native width without thinking about
+// details of implementation.
+class Shift32Immediate;
+class Shift64Immediate;
+class PImmediate;
+class SImmediate;
+class UImmediate;
+
+// Don't use templates here to enable implicit conversions.
+#define BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate)    \
+  constexpr std::optional<Immediate> MakeImmediate(int8_t value);   \
+  constexpr std::optional<Immediate> MakeImmediate(uint8_t value);  \
+  constexpr std::optional<Immediate> MakeImmediate(int16_t value);  \
+  constexpr std::optional<Immediate> MakeImmediate(uint16_t value); \
+  constexpr std::optional<Immediate> MakeImmediate(int32_t value);  \
+  constexpr std::optional<Immediate> MakeImmediate(uint32_t value); \
+  constexpr std::optional<Immediate> MakeImmediate(int64_t value);  \
+  constexpr std::optional<Immediate> MakeImmediate(uint64_t value)
+BERBERIS_DEFINE_MAKE_IMMEDIATE(BImmediate, MakeBImmediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(CsrImmediate, MakeCsrImmediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(IImmediate, MakeImmediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(IImmediate, MakeIImmediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(JImmediate, MakeJImmediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(PImmediate, MakePImmediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(Shift32Immediate, MakeShift32Immediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(Shift64Immediate, MakeShift64Immediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(SImmediate, MakeSImmediate);
+BERBERIS_DEFINE_MAKE_IMMEDIATE(UImmediate, MakeUImmediate);
+#undef BERBERIS_DEFINE_MAKE_IMMEDIATE
+
+// RawImmediate is used to bypass checks in constructor. It's not supposed to be used directly.
+class RawImmediate {
+ private:
+  friend class BImmediate;
+  friend class CsrImmediate;
+  friend class IImmediate;
+  friend class JImmediate;
+  friend class Shift32Immediate;
+  friend class Shift64Immediate;
+  friend class PImmediate;
+  friend class SImmediate;
+  friend class UImmediate;
+  template <typename DerivedAssemblerType>
+  friend class Assembler;
+
+  constexpr RawImmediate(int32_t value) : value_(value) {}
+  int32_t value_;
+};
+
+#define BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, IntType)  \
+  constexpr Immediate(IntType value) : Immediate(MakeRaw(value)) { \
+    CHECK(AccetableValue(value));                                  \
+  }
+#define BERBERIS_DEFINE_IMMEDIATE(Immediate, MakeImmediate, kMaskValue, ...)                     \
+  class Immediate {                                                                              \
+   public:                                                                                       \
+    static constexpr int32_t kMask = static_cast<int32_t>(kMaskValue);                           \
+                                                                                                 \
+    BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, int8_t)                                     \
+    BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, uint8_t)                                    \
+    BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, int16_t)                                    \
+    BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, uint16_t)                                   \
+    BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, int32_t)                                    \
+    BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, uint32_t)                                   \
+    BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, int64_t)                                    \
+    BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR(Immediate, uint64_t)                                   \
+                                                                                                 \
+    constexpr Immediate() : value_(0) {}                                                         \
+                                                                                                 \
+    constexpr int32_t EncodedValue() {                                                           \
+      return value_;                                                                             \
+    }                                                                                            \
+                                                                                                 \
+    friend bool operator==(Immediate const&, Immediate const&) = default;                        \
+                                                                                                 \
+    template <typename DerivedAssemblerType>                                                     \
+    friend class Assembler;                                                                      \
+    friend constexpr std::optional<Immediate> MakeImmediate(int8_t value);                       \
+    friend constexpr std::optional<Immediate> MakeImmediate(uint8_t value);                      \
+    friend constexpr std::optional<Immediate> MakeImmediate(int16_t value);                      \
+    friend constexpr std::optional<Immediate> MakeImmediate(uint16_t value);                     \
+    friend constexpr std::optional<Immediate> MakeImmediate(int32_t value);                      \
+    friend constexpr std::optional<Immediate> MakeImmediate(uint32_t value);                     \
+    friend constexpr std::optional<Immediate> MakeImmediate(int64_t value);                      \
+    friend constexpr std::optional<Immediate> MakeImmediate(uint64_t value);                     \
+    __VA_ARGS__                                                                                  \
+                                                                                                 \
+   private:                                                                                      \
+    constexpr Immediate(RawImmediate raw) : value_(raw.value_) {}                                \
+    /* Return true if value would fit into immediate. */                                         \
+    template <typename IntType>                                                                  \
+    static constexpr bool AccetableValue(IntType value);                                         \
+    /* Make RawImmediate from immediate value. */                                                \
+    /* Note: value is not checked for correctness! Public interface is MakeImmediate factory. */ \
+    template <typename IntType>                                                                  \
+    static constexpr RawImmediate MakeRaw(IntType value);                                        \
+                                                                                                 \
+    int32_t value_;                                                                              \
+  }
+BERBERIS_DEFINE_IMMEDIATE(
+    BImmediate,
+    MakeBImmediate,
+    0xfe00'0f80,
+    explicit constexpr operator int16_t() const {
+      return ((value_ >> 7) & 0x001e) | ((value_ >> 20) & 0xf7e0) |
+             ((value_ << 4) & 0x0800);
+    }
+    explicit constexpr operator int32_t() const {
+      return ((value_ >> 7) & 0x0000'001e) | ((value_ >> 20) & 0xffff'f7e0) |
+             ((value_ << 4) & 0x0000'0800);
+    }
+    explicit constexpr operator int64_t() const {
+      return ((value_ >> 7) & 0x0000'0000'0000'001e) | ((value_ >> 20) & 0xffff'ffff'ffff'f7e0) |
+             ((value_ << 4) & 0x0000'0000'0000'0800);
+    });
+BERBERIS_DEFINE_IMMEDIATE(
+    CsrImmediate,
+    MakeCsrImmediate,
+    0x000f'8000,
+    explicit constexpr operator int8_t() const { return value_ >> 15; }
+    explicit constexpr operator uint8_t() const { return value_ >> 15; }
+    explicit constexpr operator int16_t() const { return value_ >> 15; }
+    explicit constexpr operator uint16_t() const { return value_ >> 15; }
+    explicit constexpr operator int32_t() const { return value_ >> 15; }
+    explicit constexpr operator uint32_t() const { return value_ >> 15; }
+    explicit constexpr operator int64_t() const { return value_ >> 15;}
+    explicit constexpr operator uint64_t() const { return value_ >> 15; });
+BERBERIS_DEFINE_IMMEDIATE(
+    IImmediate, MakeIImmediate, 0xfff0'0000, constexpr IImmediate(SImmediate s_imm);
+
+    explicit constexpr operator int16_t() const { return value_ >> 20; }
+    explicit constexpr operator int32_t() const { return value_ >> 20; }
+    explicit constexpr operator int64_t() const { return value_ >> 20; }
+
+    friend SImmediate;);
+BERBERIS_DEFINE_IMMEDIATE(
+    JImmediate,
+    MakeJImmediate,
+    0xffff'f000,
+    explicit constexpr operator int32_t() const {
+      return ((value_ >> 20) & 0xfff0'07fe) | ((value_ >> 9) & 0x0000'0800) |
+             (value_ & 0x000f'f000);
+    }
+    explicit constexpr operator int64_t() const {
+      return ((value_ >> 20) & 0xffff'ffff'fff0'07fe) | ((value_ >> 9) & 0x0000'0000'0000'0800) |
+             (value_ & 0x0000'0000'000f'f000);
+    });
+BERBERIS_DEFINE_IMMEDIATE(
+    PImmediate,
+    MakePImmediate,
+    0xfe00'0000,
+    explicit constexpr
+    operator int16_t() const { return value_ >> 20; }
+    explicit constexpr operator int32_t() const { return value_ >> 20; }
+    explicit constexpr operator int64_t() const { return value_ >> 20; });
+BERBERIS_DEFINE_IMMEDIATE(
+    Shift32Immediate,
+    MakeShift32Immediate,
+    0x01f0'0000,
+    explicit constexpr operator int8_t() const { return value_ >> 20; }
+    explicit constexpr operator uint8_t() const { return value_ >> 20; }
+    explicit constexpr operator int16_t() const { return value_ >> 20; }
+    explicit constexpr operator uint16_t() const { return value_ >> 20; }
+    explicit constexpr operator int32_t() const { return value_ >> 20; }
+    explicit constexpr operator uint32_t() const { return value_ >> 20; }
+    explicit constexpr operator int64_t() const { return value_ >> 20;}
+    explicit constexpr operator uint64_t() const { return value_ >> 20; });
+BERBERIS_DEFINE_IMMEDIATE(
+    Shift64Immediate,
+    MakeShift64Immediate,
+    0x03f0'0000,
+    explicit constexpr operator int8_t() const { return value_ >> 20; }
+    explicit constexpr operator uint8_t() const { return value_ >> 20; }
+    explicit constexpr operator int16_t() const { return value_ >> 20; }
+    explicit constexpr operator uint16_t() const { return value_ >> 20; }
+    explicit constexpr operator int32_t() const { return value_ >> 20; }
+    explicit constexpr operator uint32_t() const { return value_ >> 20; }
+    explicit constexpr operator int64_t() const { return value_ >> 20;}
+    explicit constexpr operator uint64_t() const { return value_ >> 20; });
+BERBERIS_DEFINE_IMMEDIATE(
+    SImmediate, MakeSImmediate, 0xfe00'0f80, constexpr SImmediate(Immediate imm);
+
+    explicit constexpr operator int16_t() const {
+      return ((value_ >> 7) & 0x0000'001f) | (value_ >> 20);
+    }
+    explicit constexpr operator int32_t() const {
+      return ((value_ >> 7) & 0x0000'001f) | (value_ >> 20);
+    }
+    explicit constexpr operator int64_t() const {
+      return ((value_ >> 7) & 0x0000'001f) | (value_ >> 20);
+    }
+
+    friend class IImmediate;);
+BERBERIS_DEFINE_IMMEDIATE(
+    UImmediate,
+    MakeUImmediate,
+    0xffff'f000,
+    explicit constexpr operator int32_t() const { return value_; }
+    explicit constexpr operator int64_t() const { return value_; });
+#undef BERBERIS_DEFINE_IMMEDIATE
+#undef BERBERIS_DEFINE_IMMEDIATE_CONSTRUCTOR
+
+constexpr IImmediate::IImmediate(SImmediate s_imm)
+    : value_((s_imm.value_ & 0xfe00'0000) | ((s_imm.value_ & 0x0000'0f80) << 13)) {}
+
+constexpr SImmediate::SImmediate(Immediate imm)
+    : value_((imm.value_ & 0xfe00'0000) | ((imm.value_ & 0x01f0'0000) >> 13)) {}
+
+#define BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, IntType) \
+  constexpr std::optional<Immediate> MakeImmediate(IntType value) {       \
+    if (!Immediate::AccetableValue(value)) {                              \
+      return std::nullopt;                                                \
+    }                                                                     \
+    return Immediate{Immediate::MakeRaw(value)};                          \
+  }
+#define BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(Immediate, MakeImmediate) \
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, int8_t)   \
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, uint8_t)  \
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, int16_t)  \
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, uint16_t) \
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, int32_t)  \
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, uint32_t) \
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, int64_t)  \
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate, uint64_t)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(BImmediate, MakeBImmediate)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(CsrImmediate, MakeCsrImmediate)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(IImmediate, MakeIImmediate)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(JImmediate, MakeJImmediate)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(PImmediate, MakePImmediate)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(Shift32Immediate, MakeShift32Immediate)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(Shift64Immediate, MakeShift64Immediate)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(SImmediate, MakeSImmediate)
+BERBERIS_DEFINE_MAKE_IMMEDIATE_SET(UImmediate, MakeUImmediate)
+#undef BERBERIS_DEFINE_MAKE_IMMEDIATE_SET
+#undef BERBERIS_DEFINE_MAKE_IMMEDIATE
+
+#define BERBERIS_DEFINE_MAKE_IMMEDIATE(IntType)                     \
+  constexpr std::optional<Immediate> MakeImmediate(IntType value) { \
+    return MakeIImmediate(value);                                   \
+  }
+BERBERIS_DEFINE_MAKE_IMMEDIATE(int8_t)
+BERBERIS_DEFINE_MAKE_IMMEDIATE(uint8_t)
+BERBERIS_DEFINE_MAKE_IMMEDIATE(int16_t)
+BERBERIS_DEFINE_MAKE_IMMEDIATE(uint16_t)
+BERBERIS_DEFINE_MAKE_IMMEDIATE(int32_t)
+BERBERIS_DEFINE_MAKE_IMMEDIATE(uint32_t)
+BERBERIS_DEFINE_MAKE_IMMEDIATE(int64_t)
+BERBERIS_DEFINE_MAKE_IMMEDIATE(uint64_t)
+#undef BERBERIS_DEFINE_MAKE_IMMEDIATE
+
+// Return true if value would fit into B-immediate.
+template <typename IntType>
+constexpr bool BImmediate::AccetableValue(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // B-immediate accepts 12 bits, but encodes signed even values, that's why we only may accept
+  // low 12 bits of any unsigned value.
+  // Encode mask as the largest accepted value plus one and cut it to IntType size.
+  constexpr uint64_t kUnsigned64bitInputMask = 0xffff'ffff'ffff'f001;
+  if constexpr (!std::is_signed_v<IntType>) {
+    constexpr IntType kUnsignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kUnsignedInputMask) == IntType{0};
+  } else {
+    // For signed values we also accept the same values as for unsigned case, but also accept
+    // value that have all bits in am kUnsignedInputMask set.
+    // B-immediate compresses these into one single sign bit, but lowest bit have to be zero.
+    constexpr IntType kSignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kSignedInputMask) == IntType{0} ||
+           static_cast<IntType>(value & kSignedInputMask) == (kSignedInputMask & ~int64_t{1});
+  }
+}
+
+// Return true if value would fit into Csr-immediate.
+template <typename IntType>
+constexpr bool CsrImmediate::AccetableValue(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Csr immediate is unsigned immediate with possible values between 0 and 31.
+  // If we make value unsigned negative numbers would become numbers >127 and would be rejected.
+  return std::make_unsigned_t<IntType>(value) < 32;
+}
+
+// Return true if value would fit into immediate.
+template <typename IntType>
+constexpr bool Immediate::AccetableValue(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // I-immediate accepts 12 bits, but encodes signed values, that's why we only may accept low
+  // 11 bits of any unsigned value.
+  // Encode mask as the largest accepted value plus one and cut it to IntType size.
+  constexpr uint64_t kUnsigned64bitInputMask = 0xffff'ffff'ffff'f800;
+  if constexpr (!std::is_signed_v<IntType>) {
+    constexpr IntType kUnsignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kUnsignedInputMask) == IntType{0};
+  } else {
+    // For signed values we accept the same values as for unsigned case, but also accept
+    // values that have all bits in kUnsignedInputMask set.
+    // I-immediate compresses these into one single sign bit.
+    constexpr IntType kSignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kSignedInputMask) == IntType{0} ||
+           static_cast<IntType>(value & kSignedInputMask) == kSignedInputMask;
+  }
+}
+
+// Return true if value would fit into J-immediate.
+template <typename IntType>
+constexpr bool JImmediate::AccetableValue(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // J-immediate accepts 20 bits, but encodes signed even values, that's why we only may accept
+  // bits from 1 to 19 of any unsigned value. Encode mask as the largest accepted value plus 1 and
+  // cut it to IntType size.
+  constexpr uint64_t kUnsigned64bitInputMask = 0xffff'ffff'fff0'0001;
+  if constexpr (!std::is_signed_v<IntType>) {
+    constexpr IntType kUnsignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kUnsignedInputMask) == IntType{0};
+  } else {
+    // For signed values we accept the same values as for unsigned case, but also accept
+    // value that have all bits in kUnsignedInputMask set except zero bit (which is zero).
+    // J-immediate compresses these into one single sign bit, but lowest bit have to be zero.
+    constexpr IntType kSignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kSignedInputMask) == IntType{0} ||
+           static_cast<IntType>(value & kSignedInputMask) == (kSignedInputMask & ~int64_t{1});
+  }
+}
+
+// Return true if value would fit into P-immediate.
+template <typename IntType>
+constexpr bool PImmediate::AccetableValue(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // P-immediate accepts 7 bits, but encodes only values divisible by 32, that's why we only may
+  // accept bits from 5 to 10 of any unsigned value. Encode mask as the largest accepted value
+  // plus 31 and cut it to IntType size.
+  constexpr uint64_t kUnsigned64bitInputMask = 0xffff'ffff'ffff'f81f;
+  if constexpr (!std::is_signed_v<IntType>) {
+    constexpr IntType kUnsignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kUnsignedInputMask) == IntType{0};
+  } else {
+    // For signed values we accept the same values as for unsigned case, but also accept
+    // value that have all bits in kUnsignedInputMask set except the lowest 5 bits (which are
+    // zero). P-immediate compresses these into one single sign bit, but lowest bits have to be
+    // zero.
+    constexpr IntType kSignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kSignedInputMask) == IntType{0} ||
+           static_cast<IntType>(value & kSignedInputMask) == (kSignedInputMask & ~int64_t{0x1f});
+  }
+}
+
+// Return true if value would fit into Shift32-immediate.
+template <typename IntType>
+constexpr bool Shift32Immediate::AccetableValue(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Shift32 immediate is unsigned immediate with possible values between 0 and 31.
+  // If we make value unsigned negative numbers would become numbers >127 and would be rejected.
+  return std::make_unsigned_t<IntType>(value) < 32;
+}
+
+// Return true if value would fit into Shift64-immediate.
+template <typename IntType>
+constexpr bool Shift64Immediate::AccetableValue(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Shift64 immediate is unsigned immediate with possible values between 0 and 63.
+  // If we make value unsigned negative numbers would become numbers >127 and would be rejected.
+  return std::make_unsigned_t<IntType>(value) < 64;
+}
+
+// Immediate (I-immediate in RISC V documentation) and S-Immediate are siblings: they encode
+// the same values but in a different way.
+// AccetableValue are the same for that reason, but MakeRaw are different.
+template <typename IntType>
+constexpr bool SImmediate::AccetableValue(IntType value) {
+  return Immediate::AccetableValue(value);
+}
+
+// Return true if value would fit into U-immediate.
+template <typename IntType>
+constexpr bool UImmediate::AccetableValue(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // U-immediate accepts 20 bits, but encodes only values divisible by 4096, that's why we only
+  // may accept bits from 12 to 30 of any unsigned value. Encode mask as the largest accepted
+  // value plus 4095 and cut it to IntType size.
+  constexpr uint64_t kUnsigned64bitInputMask = 0xffff'ffff'8000'0fff;
+  if constexpr (!std::is_signed_v<IntType>) {
+    constexpr IntType kUnsignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kUnsignedInputMask) == IntType{0};
+  } else {
+    // For signed values we accept the same values as for unsigned case, but also accept
+    // value that have all bits in kUnsignedInputMask set except lower 12 bits (which are zero).
+    // U-immediate compresses these into one single sign bit, but lowest bits have to be zero.
+    constexpr IntType kSignedInputMask = static_cast<IntType>(kUnsigned64bitInputMask);
+    return static_cast<IntType>(value & kSignedInputMask) == IntType{0} ||
+           static_cast<IntType>(value & kSignedInputMask) == (kSignedInputMask & ~int64_t{0xfff});
+  }
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeBImmediate factory.
+template <typename IntType>
+constexpr RawImmediate BImmediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Note: we have to convert type to int32_t before processing it! Otherwise we would produce
+  // incorrect value for negative inputs since one single input sign in the small immediate would
+  // turn into many bits in the insruction.
+  return (static_cast<int32_t>(value) & static_cast<int32_t>(0x8000'0000)) |
+         ((static_cast<int32_t>(value) & static_cast<int32_t>(0x0000'0800)) >> 4) |
+         ((static_cast<int32_t>(value) & static_cast<int32_t>(0x0000'001f)) << 7) |
+         ((static_cast<int32_t>(value) & static_cast<int32_t>(0x0000'07e0)) << 20);
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeImmediate factory.
+template <typename IntType>
+constexpr RawImmediate CsrImmediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Note: this is correct if input value is between 0 and 31, but that would be checked in
+  // MakeCsrImmediate.
+  return static_cast<int32_t>(value) << 15;
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeImmediate factory.
+template <typename IntType>
+constexpr RawImmediate Immediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  return static_cast<int32_t>(value) << 20;
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeJImmediate factory.
+template <typename IntType>
+constexpr RawImmediate JImmediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Note: we have to convert type to int32_t before processing it! Otherwise we would produce
+  // incorrect value for negative inputs since one single input sign in the small immediate would
+  // turn into many bits in the insruction.
+  return (static_cast<int32_t>(value) & static_cast<int32_t>(0x800f'f000)) |
+         ((static_cast<int32_t>(value) & static_cast<int32_t>(0x0000'0800)) << 9) |
+         ((static_cast<int32_t>(value) & static_cast<int32_t>(0x0000'07fe)) << 20);
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeImmediate factory.
+template <typename IntType>
+constexpr RawImmediate PImmediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Note: this is correct if input value is divisible by 32, but that would be checked in
+  // MakePImmediate.
+  return static_cast<int32_t>(value) << 20;
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeImmediate factory.
+template <typename IntType>
+constexpr RawImmediate Shift32Immediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Note: this is correct if input value is between 0 and 31, but that would be checked in
+  // MakeShift32Immediate.
+  return static_cast<int32_t>(value) << 20;
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeImmediate factory.
+template <typename IntType>
+constexpr RawImmediate Shift64Immediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Note: this is only correct if input value is between 0 and 63, but that would be checked in
+  // MakeShift64Immediate.
+  return static_cast<int32_t>(value) << 20;
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeSImmediate factory.
+template <typename IntType>
+constexpr RawImmediate SImmediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Here, because we are only using platforms with 32bit ints conversion to 32bit signed int may
+  // happen both before masking and after but we are doing it before for consistency.
+  return ((static_cast<int32_t>(value) & static_cast<int32_t>(0xffff'ffe0)) << 20) |
+         ((static_cast<int32_t>(value) & static_cast<int32_t>(0x0000'001f)) << 7);
+}
+
+// Make RawImmediate from immediate value.
+// Note: value is not checked for correctness here! Public interface is MakeImmediate factory.
+template <typename IntType>
+constexpr RawImmediate UImmediate::MakeRaw(IntType value) {
+  static_assert(std::is_integral_v<IntType>);
+  static_assert(sizeof(IntType) <= sizeof(uint64_t));
+  // Note: this is only correct if input value is between divisible by 4096 , but that would be
+  // checked in MakeUImmediate.
+  return static_cast<int32_t>(value);
+}
+
+template <typename DerivedAssemblerType>
+class Assembler : public AssemblerBase {
+ public:
+  explicit Assembler(MachineCode* code) : AssemblerBase(code) {}
+
+  using Condition = riscv::Condition;
+  using Csr = riscv::Csr;
+  using Rounding = riscv::Rounding;
+
+  class Register {
+   public:
+    constexpr bool operator==(const Register& reg) const { return num_ == reg.num_; }
+    constexpr bool operator!=(const Register& reg) const { return num_ != reg.num_; }
+    constexpr uint8_t GetPhysicalIndex() { return num_; }
+    friend constexpr uint8_t ValueForFmtSpec(Register value) { return value.num_; }
+    friend class Assembler<DerivedAssemblerType>;
+    friend class rv32e::Assembler;
+    friend class rv32i::Assembler;
+    friend class rv64i::Assembler;
+
+   private:
+    explicit constexpr Register(uint8_t num) : num_(num) {}
+    uint8_t num_;
+  };
+
+  // Note: register x0, technically, can be specified in assembler even if it doesn't exist
+  // as separate hardware register. It even have alias “zero” even in clang assembler.
+  static constexpr Register x0{0};
+  static constexpr Register x1{1};
+  static constexpr Register x2{2};
+  static constexpr Register x3{3};
+  static constexpr Register x4{4};
+  static constexpr Register x5{5};
+  static constexpr Register x6{6};
+  static constexpr Register x7{7};
+  static constexpr Register x8{8};
+  static constexpr Register x9{9};
+  static constexpr Register x10{10};
+  static constexpr Register x11{11};
+  static constexpr Register x12{12};
+  static constexpr Register x13{13};
+  static constexpr Register x14{14};
+  static constexpr Register x15{15};
+  static constexpr Register x16{16};
+  static constexpr Register x17{17};
+  static constexpr Register x18{18};
+  static constexpr Register x19{19};
+  static constexpr Register x20{20};
+  static constexpr Register x21{21};
+  static constexpr Register x22{22};
+  static constexpr Register x23{23};
+  static constexpr Register x24{24};
+  static constexpr Register x25{25};
+  static constexpr Register x26{26};
+  static constexpr Register x27{27};
+  static constexpr Register x28{28};
+  static constexpr Register x29{29};
+  static constexpr Register x30{30};
+  static constexpr Register x31{31};
+
+  // Aliases
+  static constexpr Register no_register{0x80};
+  static constexpr Register zero{0};
+
+  class FpRegister {
+   public:
+    constexpr bool operator==(const FpRegister& reg) const { return num_ == reg.num_; }
+    constexpr bool operator!=(const FpRegister& reg) const { return num_ != reg.num_; }
+    constexpr uint8_t GetPhysicalIndex() { return num_; }
+    friend constexpr uint8_t ValueForFmtSpec(FpRegister value) { return value.num_; }
+    friend class Assembler<DerivedAssemblerType>;
+
+   private:
+    explicit constexpr FpRegister(uint8_t num) : num_(num) {}
+    uint8_t num_;
+  };
+
+  static constexpr FpRegister f0{0};
+  static constexpr FpRegister f1{1};
+  static constexpr FpRegister f2{2};
+  static constexpr FpRegister f3{3};
+  static constexpr FpRegister f4{4};
+  static constexpr FpRegister f5{5};
+  static constexpr FpRegister f6{6};
+  static constexpr FpRegister f7{7};
+  static constexpr FpRegister f8{8};
+  static constexpr FpRegister f9{9};
+  static constexpr FpRegister f10{10};
+  static constexpr FpRegister f11{11};
+  static constexpr FpRegister f12{12};
+  static constexpr FpRegister f13{13};
+  static constexpr FpRegister f14{14};
+  static constexpr FpRegister f15{15};
+  static constexpr FpRegister f16{16};
+  static constexpr FpRegister f17{17};
+  static constexpr FpRegister f18{18};
+  static constexpr FpRegister f19{19};
+  static constexpr FpRegister f20{20};
+  static constexpr FpRegister f21{21};
+  static constexpr FpRegister f22{22};
+  static constexpr FpRegister f23{23};
+  static constexpr FpRegister f24{24};
+  static constexpr FpRegister f25{25};
+  static constexpr FpRegister f26{26};
+  static constexpr FpRegister f27{27};
+  static constexpr FpRegister f28{28};
+  static constexpr FpRegister f29{29};
+  static constexpr FpRegister f30{30};
+  static constexpr FpRegister f31{31};
+
+  // ABI
+  static constexpr FpRegister ft0{0};
+  static constexpr FpRegister ft1{1};
+  static constexpr FpRegister ft2{2};
+  static constexpr FpRegister ft3{3};
+  static constexpr FpRegister ft4{4};
+  static constexpr FpRegister ft5{5};
+  static constexpr FpRegister ft6{6};
+  static constexpr FpRegister ft7{7};
+  static constexpr FpRegister fs0{8};
+  static constexpr FpRegister fs1{9};
+  static constexpr FpRegister fa0{10};
+  static constexpr FpRegister fa1{11};
+  static constexpr FpRegister fa2{12};
+  static constexpr FpRegister fa3{13};
+  static constexpr FpRegister fa4{14};
+  static constexpr FpRegister fa5{15};
+  static constexpr FpRegister fa6{16};
+  static constexpr FpRegister fa7{17};
+  static constexpr FpRegister fs2{18};
+  static constexpr FpRegister fs3{19};
+  static constexpr FpRegister fs4{20};
+  static constexpr FpRegister fs5{21};
+  static constexpr FpRegister fs6{22};
+  static constexpr FpRegister fs7{23};
+  static constexpr FpRegister fs8{24};
+  static constexpr FpRegister fs9{25};
+  static constexpr FpRegister fs10{26};
+  static constexpr FpRegister fs11{27};
+  static constexpr FpRegister ft8{28};
+  static constexpr FpRegister ft9{29};
+  static constexpr FpRegister ft10{30};
+  static constexpr FpRegister ft11{31};
+
+  template <typename RegisterType, typename ImmediateType>
+  struct Operand {
+    RegisterType base{0};
+    ImmediateType disp = 0;
+  };
+
+  using BImmediate = riscv::BImmediate;
+  using CsrImmediate = riscv::CsrImmediate;
+  using IImmediate = riscv::IImmediate;
+  using Immediate = riscv::Immediate;
+  using JImmediate = riscv::JImmediate;
+  using Shift32Immediate = riscv::Shift32Immediate;
+  using Shift64Immediate = riscv::Shift64Immediate;
+  using PImmediate = riscv::PImmediate;
+  using SImmediate = riscv::SImmediate;
+  using UImmediate = riscv::UImmediate;
+
+  // Don't use templates here to enable implicit conversions.
+#define BERBERIS_DEFINE_MAKE_IMMEDIATE(Immediate, MakeImmediate)            \
+  static constexpr std::optional<Immediate> MakeImmediate(int8_t value) {   \
+    return riscv::MakeImmediate(value);                                     \
+  }                                                                         \
+  static constexpr std::optional<Immediate> MakeImmediate(uint8_t value) {  \
+    return riscv::MakeImmediate(value);                                     \
+  }                                                                         \
+  static constexpr std::optional<Immediate> MakeImmediate(int16_t value) {  \
+    return riscv::MakeImmediate(value);                                     \
+  }                                                                         \
+  static constexpr std::optional<Immediate> MakeImmediate(uint16_t value) { \
+    return riscv::MakeImmediate(value);                                     \
+  }                                                                         \
+  static constexpr std::optional<Immediate> MakeImmediate(int32_t value) {  \
+    return riscv::MakeImmediate(value);                                     \
+  }                                                                         \
+  static constexpr std::optional<Immediate> MakeImmediate(uint32_t value) { \
+    return riscv::MakeImmediate(value);                                     \
+  }                                                                         \
+  static constexpr std::optional<Immediate> MakeImmediate(int64_t value) {  \
+    return riscv::MakeImmediate(value);                                     \
+  }                                                                         \
+  static constexpr std::optional<Immediate> MakeImmediate(uint64_t value) { \
+    return riscv::MakeImmediate(value);                                     \
+  }
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(BImmediate, MakeBImmediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(CsrImmediate, MakeCsrImmediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(IImmediate, MakeImmediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(IImmediate, MakeIImmediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(JImmediate, MakeJImmediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(PImmediate, MakePImmediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Shift32Immediate, MakeShift32Immediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(Shift64Immediate, MakeShift64Immediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(SImmediate, MakeSImmediate)
+  BERBERIS_DEFINE_MAKE_IMMEDIATE(UImmediate, MakeUImmediate)
+#undef BERBERIS_DEFINE_MAKE_IMMEDIATE
+
+  // Macro operations.
+  void Finalize() { ResolveJumps(); }
+
+  void ResolveJumps();
+
+  // Instructions.
+#include "berberis/assembler/gen_assembler_common_riscv-inl.h"  // NOLINT generated file!
+
+ protected:
+  // Information about operands.
+  template <typename OperandType, typename = void>
+  class OperandInfo;
+
+  // Wrapped operand with information of where in the encoded instruction should it be placed.
+  template <typename OperandMarker, typename RegisterType>
+  struct RegisterOperand {
+    constexpr int32_t EncodeImmediate() {
+      return value.GetPhysicalIndex()
+             << OperandInfo<RegisterOperand<OperandMarker, RegisterType>>::kOffset;
+    }
+
+    RegisterType value;
+  };
+
+  struct ConditionOperand {
+    constexpr int32_t EncodeImmediate() {
+      return static_cast<int32_t>(value) << OperandInfo<ConditionOperand>::kOffset;
+    }
+
+    Condition value;
+  };
+
+  struct RoundingOperand {
+    constexpr int32_t EncodeImmediate() {
+      return static_cast<int32_t>(value) << OperandInfo<RoundingOperand>::kOffset;
+    }
+
+    Rounding value;
+  };
+
+  // Operand class  markers. Note, these classes shouldn't ever be instantiated, they are just
+  // used to carry information about operands.
+  class RdMarker;
+  class Rs1Marker;
+  class Rs2Marker;
+  class Rs3Marker;
+
+  template <typename RegisterType>
+  class OperandInfo<RegisterOperand<RdMarker, RegisterType>> {
+   public:
+    static constexpr bool IsImmediate = false;
+    static constexpr uint8_t kOffset = 7;
+    static constexpr uint32_t kMask = 0x0000'0f80;
+  };
+
+  template <>
+  class OperandInfo<ConditionOperand> {
+   public:
+    static constexpr bool IsImmediate = false;
+    static constexpr uint8_t kOffset = 12;
+    static constexpr uint32_t kMask = 0x0000'7000;
+  };
+
+  template <>
+  class OperandInfo<RoundingOperand> {
+   public:
+    static constexpr bool IsImmediate = false;
+    static constexpr uint8_t kOffset = 12;
+    static constexpr uint32_t kMask = 0x0000'7000;
+  };
+
+  template <typename RegisterType>
+  class OperandInfo<RegisterOperand<Rs1Marker, RegisterType>> {
+   public:
+    static constexpr bool IsImmediate = false;
+    static constexpr uint8_t kOffset = 15;
+    static constexpr uint32_t kMask = 0x000f'8000;
+  };
+
+  template <typename RegisterType>
+  class OperandInfo<RegisterOperand<Rs2Marker, RegisterType>> {
+   public:
+    static constexpr bool IsImmediate = false;
+    static constexpr uint8_t kOffset = 20;
+    static constexpr uint32_t kMask = 0x01f0'0000;
+  };
+
+  template <typename RegisterType>
+  class OperandInfo<RegisterOperand<Rs3Marker, RegisterType>> {
+   public:
+    static constexpr bool IsImmediate = false;
+    static constexpr uint8_t kOffset = 27;
+    static constexpr uint32_t kMask = 0xf800'0000;
+  };
+
+  template <typename Immediate>
+  class OperandInfo<Immediate, std::enable_if_t<sizeof(Immediate::kMask) != 0>> {
+   public:
+    static constexpr bool IsImmediate = true;
+    static constexpr uint8_t kOffset = 0;
+    static constexpr uint32_t kMask = Immediate::kMask;
+  };
+
+  template <typename RegisterType>
+  RegisterOperand<RdMarker, RegisterType> Rd(RegisterType value) {
+    return {value};
+  }
+
+  ConditionOperand Cond(Condition value) { return {value}; }
+
+  RoundingOperand Rm(Rounding value) { return {value}; }
+
+  template <typename RegisterType>
+  RegisterOperand<Rs1Marker, RegisterType> Rs1(RegisterType value) {
+    return {value};
+  }
+
+  template <typename RegisterType>
+  RegisterOperand<Rs2Marker, RegisterType> Rs2(RegisterType value) {
+    return {value};
+  }
+
+  template <typename RegisterType>
+  RegisterOperand<Rs3Marker, RegisterType> Rs3(RegisterType value) {
+    return {value};
+  }
+
+  template <uint32_t kOpcode, uint32_t kOpcodeMask, typename... ArgumentsTypes>
+  void EmitInstruction(ArgumentsTypes... arguments) {
+    // All uncompressed instructions in RISC-V have two lowest bit set and we don't handle
+    // compressed instructions here.
+    static_assert((kOpcode & 0b11) == 0b11);
+    // Instruction shouldn't have any bits set outside of its opcode mask.
+    static_assert((kOpcode & ~kOpcodeMask) == 0);
+    // Places for all operands in the opcode should not intersect with opcode.
+    static_assert((((kOpcodeMask & OperandInfo<ArgumentsTypes>::kMask) == 0) && ...));
+    Emit32((kOpcode | ... | [](auto argument) {
+      if constexpr (OperandInfo<decltype(argument)>::IsImmediate) {
+        return argument.EncodedValue();
+      } else {
+        return argument.EncodeImmediate();
+      }
+    }(arguments)));
+  }
+
+  template <uint32_t kOpcode,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename ImmediateType>
+  void EmitBTypeInstruction(ArgumentsType0&& argument0,
+                            ArgumentsType1&& argument1,
+                            ImmediateType&& immediate) {
+    return EmitInstruction<kOpcode, 0x0000'707f>(Rs1(argument0), Rs2(argument1), immediate);
+  }
+
+  template <uint32_t kOpcode, typename ArgumentsType0, typename OperandType>
+  void EmitITypeInstruction(ArgumentsType0&& argument0, OperandType&& operand) {
+    return EmitInstruction<kOpcode, 0x0000'707f>(Rd(argument0), Rs1(operand.base), operand.disp);
+  }
+
+  // Csr instructions are described as I-type instructions in RISC-V manual, but unlike most
+  // I-type instructions they use IImmediate to encode Csr register number and it comes as second
+  // argument, not third. In addition Csr value is defined as unsigned and not as signed which
+  // means certain Csr values (e.g. kVlenb) wouldn't be accepted as IImmediate!
+  template <uint32_t kOpcode, typename ArgumentsType0>
+  void EmitITypeInstruction(ArgumentsType0&& argument0, Csr csr, Register argument1) {
+    return EmitInstruction<kOpcode, 0x0000'707f>(
+        Rd(argument0),
+        IImmediate{riscv::RawImmediate{static_cast<int32_t>(csr) << 20}},
+        Rs1(argument1));
+  }
+
+  template <uint32_t kOpcode, typename ArgumentsType0>
+  void EmitITypeInstruction(ArgumentsType0&& argument0, Csr csr, CsrImmediate immediate) {
+    return EmitInstruction<kOpcode, 0x0000'707f>(
+        Rd(argument0), IImmediate{riscv::RawImmediate{static_cast<int32_t>(csr) << 20}}, immediate);
+  }
+
+  template <uint32_t kOpcode,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename ImmediateType>
+  void EmitITypeInstruction(ArgumentsType0&& argument0,
+                            ArgumentsType1&& argument1,
+                            ImmediateType&& immediate) {
+    // Some I-type instructions use immediate as opcode extension. In that case different,
+    // smaller, immediate with smaller mask is used. 0xfff0'707f &
+    // ~std::decay_t<ImmediateType>::kMask turns these bits that are not used as immediate into
+    // parts of opcode. For full I-immediate it produces 0x0000'707f, same as with I-type memory
+    // operand.
+    return EmitInstruction<kOpcode, 0xfff0'707f & ~std::decay_t<ImmediateType>::kMask>(
+        Rd(argument0), Rs1(argument1), immediate);
+  }
+
+  template <uint32_t kOpcode, typename ArgumentsType0, typename ImmediateType>
+  void EmitJTypeInstruction(ArgumentsType0&& argument0, ImmediateType&& immediate) {
+    return EmitInstruction<kOpcode, 0x0000'007f>(Rd(argument0), immediate);
+  }
+
+  template <uint32_t kOpcode, typename OperandType>
+  void EmitPTypeInstruction(OperandType&& operand) {
+    return EmitInstruction<kOpcode, 0x01f0'7fff>(Rs1(operand.base), operand.disp);
+  }
+
+  template <uint32_t kOpcode, typename ArgumentsType0, typename ArgumentsType1>
+  void EmitRTypeInstruction(ArgumentsType0&& argument0,
+                            ArgumentsType1&& argument1,
+                            Rounding argument2) {
+    return EmitInstruction<kOpcode, 0xfff0'007f>(Rd(argument0), Rs1(argument1), Rm(argument2));
+  }
+
+  template <uint32_t kOpcode,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename ArgumentsType2>
+  void EmitRTypeInstruction(ArgumentsType0&& argument0,
+                            ArgumentsType1&& argument1,
+                            ArgumentsType2&& argument2) {
+    return EmitInstruction<kOpcode, 0xfe00'707f>(Rd(argument0), Rs1(argument1), Rs2(argument2));
+  }
+
+  template <uint32_t kOpcode, typename ArgumentsType0, typename OperandType>
+  void EmitSTypeInstruction(ArgumentsType0&& argument0, OperandType&& operand) {
+    return EmitInstruction<kOpcode, 0x0000'707f>(Rs2(argument0), Rs1(operand.base), operand.disp);
+  }
+
+  template <uint32_t kOpcode, typename ArgumentsType0, typename ImmediateType>
+  void EmitUTypeInstruction(ArgumentsType0&& argument0, ImmediateType&& immediate) {
+    return EmitInstruction<kOpcode, 0x0000'007f>(Rd(argument0), immediate);
+  }
+
+ private:
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+};
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bcc(Condition cc,
+                                                 Register argument1,
+                                                 Register argument2,
+                                                 const Label& label) {
+  if (cc == Condition::kAlways) {
+    Jal(zero, label);
+    return;
+  } else if (cc == Condition::kNever) {
+    return;
+  }
+  CHECK_EQ(0, static_cast<uint8_t>(cc) & 0xf8);
+  jumps_.push_back(Jump{&label, pc(), false});
+  EmitInstruction<0x0000'0063, 0x0000'007f>(Cond(cc), Rs1(argument1), Rs2(argument2));
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bcc(Condition cc,
+                                                 Register argument1,
+                                                 Register argument2,
+                                                 BImmediate immediate) {
+  if (cc == Condition::kAlways) {
+    int32_t encoded_immediate_value = immediate.EncodedValue();
+    // Maybe better to provide an official interface to convert BImmediate into JImmediate?
+    // Most CPUs have uncoditional jump with longer range than condtional one (8086, ARM, RISC-V)
+    // or the same one (modern x86), thus such conversion is natural.
+    JImmediate jimmediate =
+        riscv::RawImmediate{((encoded_immediate_value >> 19) & 0x000f'f000) |
+                            ((encoded_immediate_value << 13) & 0x01f0'0000) |
+                            (encoded_immediate_value & static_cast<int32_t>(0xfe00'0000))};
+    Jal(zero, jimmediate);
+    return;
+  } else if (cc == Condition::kNever) {
+    return;
+  }
+  CHECK_EQ(0, static_cast<uint8_t>(cc) & 0xf8);
+  EmitInstruction<0x0000'0063, 0x0000'007f>(Cond(cc), Rs1(argument1), Rs2(argument2), immediate);
+}
+
+#define BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Name, TargetRegister, InstructionType, Opcode) \
+  template <typename DerivedAssemblerType>                                                       \
+  inline void Assembler<DerivedAssemblerType>::Name(                                             \
+      TargetRegister arg0, const Label& label, Register arg2) {                                  \
+    CHECK_NE(arg2, x0);                                                                          \
+    jumps_.push_back(Jump{&label, pc(), false});                                                 \
+    /* First issue auipc to load top 20 bits of difference between pc and target address */      \
+    EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg2, UImmediate{0});                            \
+    /* The low 12 bite of difference will be encoded in the memory accessing instruction */      \
+    Emit##InstructionType##TypeInstruction<uint32_t{Opcode}>(                                    \
+        arg0, Operand<Register, InstructionType##Immediate>{.base = arg2});                      \
+  }
+BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Fld, FpRegister, I, 0x0000'3007)
+BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Flw, FpRegister, I, 0x0000'2007)
+BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Fsd, FpRegister, S, 0x0000'3027)
+BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Fsw, FpRegister, S, 0x0000'2027)
+BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Sb, Register, S, 0x0000'0023)
+BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Sh, Register, S, 0x0000'1023)
+BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Sw, Register, S, 0x0000'2023)
+#undef BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION
+
+#define BERBERIS_DEFINE_LOAD_INSTRUCTION(Name, Opcode)                                         \
+  template <typename DerivedAssemblerType>                                                     \
+  inline void Assembler<DerivedAssemblerType>::Name(Register arg0, const Label& label) {       \
+    CHECK_NE(arg0, x0);                                                                        \
+    jumps_.push_back(Jump{&label, pc(), false});                                               \
+    /* First issue auipc to load top 20 bits of difference between pc and target address */    \
+    EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg0, UImmediate{0});                          \
+    /* The low 12 bite of difference will be encoded in the memory accessing instruction */    \
+    EmitITypeInstruction<uint32_t{Opcode}>(arg0, Operand<Register, IImmediate>{.base = arg0}); \
+  }
+BERBERIS_DEFINE_LOAD_INSTRUCTION(Lb, 0x0000'0003)
+BERBERIS_DEFINE_LOAD_INSTRUCTION(Lbu, 0x0000'4003)
+BERBERIS_DEFINE_LOAD_INSTRUCTION(Lh, 0x0000'1003)
+BERBERIS_DEFINE_LOAD_INSTRUCTION(Lhu, 0x0000'5003)
+BERBERIS_DEFINE_LOAD_INSTRUCTION(Lw, 0x0000'2003)
+#undef BERBERIS_DEFINE_LOAD_INSTRUCTION
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Lla(Register arg0, const Label& label) {
+  CHECK_NE(arg0, x0);
+  jumps_.push_back(Jump{&label, pc(), false});
+  // First issue auipc to load top 20 bits of difference between pc and target address
+  EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg0, UImmediate{0});
+  // The low 12 bite of difference will be added with addi instruction
+  EmitITypeInstruction<uint32_t{0x0000'0013}>(arg0, arg0, IImmediate{0});
+}
+
+#define BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Name, Opcode)          \
+  template <typename DerivedAssemblerType>                             \
+  inline void Assembler<DerivedAssemblerType>::Name(                   \
+      Register arg0, Register arg1, const Label& label) {              \
+    jumps_.push_back(Jump{&label, pc(), false});                       \
+    EmitBTypeInstruction<uint32_t{Opcode}>(arg0, arg1, BImmediate{0}); \
+  }
+BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Beq, 0x0000'0063)
+BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Bge, 0x0000'5063)
+BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Bgeu, 0x0000'7063)
+BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Blt, 0x0000'4063)
+BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Bltu, 0x0000'6063)
+BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Bne, 0x0000'1063)
+#undef BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Jal(Register argument0, const Label& label) {
+  jumps_.push_back(Jump{&label, pc(), false});
+  EmitInstruction<0x0000'006f, 0x0000'007f>(Rd(argument0));
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
+  for (const auto& jump : jumps_) {
+    const Label* label = jump.label;
+    uint32_t pc = jump.pc;
+    CHECK(label->IsBound());
+    if (jump.is_recovery) {
+      // Add pc -> label correspondence to recovery map.
+      AddRelocation(0, RelocationType::RelocRecoveryPoint, pc, label->position());
+    } else {
+      int32_t offset = label->position() - pc;
+      auto ProcessLabel =
+          [this, pc, offset]<typename ImmediateType,
+                             std::optional<ImmediateType> (*MakeImmediate)(int32_t)>() {
+            auto encoded_immediate = MakeImmediate(offset);
+            if (!encoded_immediate.has_value()) {
+              // UImmediate means we are dealing with auipc here, means we may accept any
+              // ±2GB offset, but need to look at the next instruction to do that.
+              if constexpr (std::is_same_v<ImmediateType, UImmediate>) {
+                // Bottom immediate is decoded with a 12 → 32 bit sign-extended.
+                // Compensate that by adding sign-bit of bottom to top.
+                // Make calculation as unsigned types to ensure we wouldn't hit any UB here.
+                int32_t top = (static_cast<uint32_t>(offset) +
+                               ((static_cast<uint32_t>(offset) & (1U << 11)) * 2)) &
+                              0xffff'f000U;
+                struct {
+                  int32_t data : 12;
+                } bottom = {offset};
+                *AddrAs<int32_t>(pc) |= UImmediate{top}.EncodedValue();
+                *AddrAs<int32_t>(pc + 4) |= (*AddrAs<int32_t>(pc + 4) & 32)
+                                                ? SImmediate{bottom.data}.EncodedValue()
+                                                : IImmediate{bottom.data}.EncodedValue();
+                return true;
+              }
+              return false;
+            }
+            *AddrAs<int32_t>(pc) |= encoded_immediate->EncodedValue();
+            return true;
+          };
+      // Check the instruction type:
+      //   AUIPC uses UImmediate, Jal uses JImmediate, while Bcc uses BImmediate.
+      bool RelocationInRange;
+      if (*AddrAs<int32_t>(pc) & 16) {
+        RelocationInRange = ProcessLabel.template operator()<UImmediate, MakeUImmediate>();
+      } else if (*AddrAs<int32_t>(pc) & 4) {
+        RelocationInRange = ProcessLabel.template operator()<JImmediate, MakeJImmediate>();
+      } else {
+        RelocationInRange = ProcessLabel.template operator()<BImmediate, MakeBImmediate>();
+      }
+      // Maybe need to propagate error to caller?
+      CHECK(RelocationInRange);
+    }
+  }
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Mv(Register dest, Register src) {
+  Addi(dest, src, 0);
+}
+
+}  // namespace riscv
+
+}  // namespace berberis
+
+#endif  // BERBERIS_ASSEMBLER_COMMON_X86_H_
diff --git a/assembler/include/berberis/assembler/rv32.h b/assembler/include/berberis/assembler/rv32.h
new file mode 100644
index 00000000..be8af904
--- /dev/null
+++ b/assembler/include/berberis/assembler/rv32.h
@@ -0,0 +1,68 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// Assembler to produce RV32 instructions (no ABI version). Somewhat influenced by V8 assembler.
+
+#ifndef BERBERIS_ASSEMBLER_RV32_H_
+#define BERBERIS_ASSEMBLER_RV32_H_
+
+#include <type_traits>  // std::is_same
+
+#include "berberis/assembler/riscv.h"
+
+namespace berberis::rv32 {
+
+class Assembler : public riscv::Assembler<Assembler> {
+ public:
+  using BaseAssembler = riscv::Assembler<Assembler>;
+  using FinalAssembler = Assembler;
+
+  explicit Assembler(MachineCode* code) : BaseAssembler(code) {}
+
+  using ShiftImmediate = BaseAssembler::Shift32Immediate;
+
+  // Don't use templates here to enable implicit conversions.
+#define BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(IntType)                                \
+  static constexpr std::optional<ShiftImmediate> MakeShiftImmediate(IntType value) { \
+    return BaseAssembler::MakeShift32Immediate(value);                               \
+  }
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(int8_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(uint8_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(int16_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(uint16_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(int32_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(uint32_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(int64_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(uint64_t)
+#undef BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE
+
+  friend BaseAssembler;
+
+// Instructions.
+#include "berberis/assembler/gen_assembler_rv32-inl.h"  // NOLINT generated file!
+
+ private:
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+  friend BaseAssembler;
+};
+
+}  // namespace berberis::rv32
+
+#endif  // BERBERIS_ASSEMBLER_RV32_H_
diff --git a/assembler/include/berberis/assembler/rv32e.h b/assembler/include/berberis/assembler/rv32e.h
new file mode 100644
index 00000000..da000079
--- /dev/null
+++ b/assembler/include/berberis/assembler/rv32e.h
@@ -0,0 +1,81 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// Assembler to produce RV32 instructions (EABI version). Somewhat influenced by V8 assembler.
+
+#ifndef BERBERIS_ASSEMBLER_RV32E_H_
+#define BERBERIS_ASSEMBLER_RV32E_H_
+
+#include <type_traits>  // std::is_same
+
+#include "berberis/assembler/rv32.h"
+
+namespace berberis::rv32e {
+
+class Assembler : public ::berberis::rv32::Assembler {
+ public:
+  using BaseAssembler = riscv::Assembler<::berberis::rv32::Assembler>;
+  using FinalAssembler = berberis::rv32::Assembler;
+
+  explicit Assembler(MachineCode* code) : berberis::rv32::Assembler(code) {}
+
+  // Registers available used on “small” CPUs (with 16 general purpose registers) and “big” CPUs (32
+  // general purpose registers).
+  static constexpr Register ra{1};
+  static constexpr Register sp{2};
+  static constexpr Register gp{3};
+  static constexpr Register tp{4};
+  static constexpr Register t0{5};
+  static constexpr Register s3{6};
+  static constexpr Register s4{7};
+  static constexpr Register s0{8};
+  static constexpr Register s1{9};
+  static constexpr Register a0{10};
+  static constexpr Register a1{11};
+  static constexpr Register a2{12};
+  static constexpr Register a3{13};
+  static constexpr Register s2{14};
+  static constexpr Register t1{15};
+
+  // Register only available on “big” CPUs (with 32 gneral purpose registers).
+  static constexpr Register s5{16};
+  static constexpr Register s6{17};
+  static constexpr Register s7{18};
+  static constexpr Register s8{19};
+  static constexpr Register s9{20};
+  static constexpr Register s10{21};
+  static constexpr Register s11{22};
+  static constexpr Register s12{23};
+  static constexpr Register s13{24};
+  static constexpr Register s14{25};
+  static constexpr Register s15{26};
+  static constexpr Register s16{27};
+  static constexpr Register s17{28};
+  static constexpr Register s18{29};
+  static constexpr Register s19{30};
+  static constexpr Register s20{31};
+
+ private:
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+};
+
+}  // namespace berberis::rv32e
+
+#endif  // BERBERIS_ASSEMBLER_RV32E_H_
diff --git a/assembler/include/berberis/assembler/rv32i.h b/assembler/include/berberis/assembler/rv32i.h
new file mode 100644
index 00000000..e671aee5
--- /dev/null
+++ b/assembler/include/berberis/assembler/rv32i.h
@@ -0,0 +1,81 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// Assembler to produce RV32 instructions (UABI version). Somewhat influenced by V8 assembler.
+
+#ifndef BERBERIS_ASSEMBLER_RV32I_H_
+#define BERBERIS_ASSEMBLER_RV32I_H_
+
+#include <type_traits>  // std::is_same
+
+#include "berberis/assembler/rv32.h"
+
+namespace berberis {
+
+namespace rv32i {
+
+class Assembler : public ::berberis::rv32::Assembler {
+ public:
+  using BaseAssembler = riscv::Assembler<::berberis::rv32::Assembler>;
+  using FinalAssembler = ::berberis::rv32::Assembler;
+
+  explicit Assembler(MachineCode* code) : berberis::rv32::Assembler(code) {}
+
+  static constexpr Register ra{1};
+  static constexpr Register sp{2};
+  static constexpr Register gp{3};
+  static constexpr Register tp{4};
+  static constexpr Register t0{5};
+  static constexpr Register t1{6};
+  static constexpr Register t2{7};
+  static constexpr Register s0{8};
+  static constexpr Register s1{9};
+  static constexpr Register a0{10};
+  static constexpr Register a1{11};
+  static constexpr Register a2{12};
+  static constexpr Register a3{13};
+  static constexpr Register a4{14};
+  static constexpr Register a5{15};
+  static constexpr Register a6{16};
+  static constexpr Register a7{17};
+  static constexpr Register s2{18};
+  static constexpr Register s3{19};
+  static constexpr Register s4{20};
+  static constexpr Register s5{21};
+  static constexpr Register s6{22};
+  static constexpr Register s7{23};
+  static constexpr Register s8{24};
+  static constexpr Register s9{25};
+  static constexpr Register s10{26};
+  static constexpr Register s11{27};
+  static constexpr Register t3{28};
+  static constexpr Register t4{29};
+  static constexpr Register t5{30};
+  static constexpr Register t6{31};
+
+ private:
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+};
+
+}  // namespace rv32i
+
+}  // namespace berberis
+
+#endif  // BERBERIS_ASSEMBLER_RV32I_H_
diff --git a/assembler/include/berberis/assembler/rv64.h b/assembler/include/berberis/assembler/rv64.h
new file mode 100644
index 00000000..e702adea
--- /dev/null
+++ b/assembler/include/berberis/assembler/rv64.h
@@ -0,0 +1,91 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// Assembler to produce RV64 instructions (no ABI version). Somewhat influenced by V8 assembler.
+
+#ifndef BERBERIS_ASSEMBLER_RV64_H_
+#define BERBERIS_ASSEMBLER_RV64_H_
+
+#include <type_traits>  // std::is_same
+
+#include "berberis/assembler/riscv.h"
+
+namespace berberis::rv64 {
+
+class Assembler : public riscv::Assembler<Assembler> {
+ public:
+  using BaseAssembler = riscv::Assembler<Assembler>;
+  using FinalAssembler = Assembler;
+
+  explicit Assembler(MachineCode* code) : BaseAssembler(code) {}
+
+  using ShiftImmediate = BaseAssembler::Shift64Immediate;
+
+  // Don't use templates here to enable implicit conversions.
+#define BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(IntType)                                \
+  static constexpr std::optional<ShiftImmediate> MakeShiftImmediate(IntType value) { \
+    return BaseAssembler::MakeShift64Immediate(value);                               \
+  }
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(int8_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(uint8_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(int16_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(uint16_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(int32_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(uint32_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(int64_t)
+  BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE(uint64_t)
+#undef BERBERIS_DEFINE_MAKE_SHIFT_IMMEDIATE
+
+  friend BaseAssembler;
+
+// Instructions.
+#include "berberis/assembler/gen_assembler_rv64-inl.h"  // NOLINT generated file!
+
+ private:
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+};
+
+inline void Assembler::Ld(Register arg0, const Label& label) {
+  jumps_.push_back(Jump{&label, pc(), false});
+  // First issue auipc to load top 20 bits of difference between pc and target address
+  EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg0, UImmediate{0});
+  // The low 12 bite of difference will be encoded in the Ld instruction
+  EmitITypeInstruction<uint32_t{0x0000'3003}>(arg0, Operand<Register, IImmediate>{.base = arg0});
+}
+
+inline void Assembler::Lwu(Register arg0, const Label& label) {
+  jumps_.push_back(Jump{&label, pc(), false});
+  // First issue auipc to load top 20 bits of difference between pc and target address
+  EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg0, UImmediate{0});
+  // The low 12 bite of difference will be encoded in the Lwu instruction
+  EmitITypeInstruction<uint32_t{0x0000'6003}>(arg0, Operand<Register, IImmediate>{.base = arg0});
+}
+
+inline void Assembler::Sd(Register arg0, const Label& label, Register arg2) {
+  jumps_.push_back(Jump{&label, pc(), false});
+  // First issue auipc to load top 20 bits of difference between pc and target address
+  EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg2, UImmediate{0});
+  // The low 12 bite of difference will be encoded in the Sd instruction
+  EmitSTypeInstruction<uint32_t{0x0000'3023}>(arg0, Operand<Register, SImmediate>{.base = arg2});
+}
+
+}  // namespace berberis::rv64
+
+#endif  // BERBERIS_ASSEMBLER_RV64_H_
diff --git a/assembler/include/berberis/assembler/rv64i.h b/assembler/include/berberis/assembler/rv64i.h
new file mode 100644
index 00000000..99815f54
--- /dev/null
+++ b/assembler/include/berberis/assembler/rv64i.h
@@ -0,0 +1,80 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// Assembler to produce RV64 instructions (UABI version). Somewhat influenced by V8 assembler.
+
+#ifndef BERBERIS_ASSEMBLER_RV64I_H_
+#define BERBERIS_ASSEMBLER_RV64I_H_
+
+#include <type_traits>  // std::is_same
+
+#include "berberis/assembler/rv64.h"
+
+namespace berberis {
+
+namespace rv64i {
+
+class Assembler : public ::berberis::rv64::Assembler {
+ public:
+  using BaseAssembler = riscv::Assembler<::berberis::rv64::Assembler>;
+  using FinalAssembler = ::berberis::rv64::Assembler;
+
+  explicit Assembler(MachineCode* code) : berberis::rv64::Assembler(code) {}
+
+  static constexpr Register ra{1};
+  static constexpr Register sp{2};
+  static constexpr Register gp{3};
+  static constexpr Register tp{4};
+  static constexpr Register t0{5};
+  static constexpr Register t1{6};
+  static constexpr Register t2{7};
+  static constexpr Register s0{8};
+  static constexpr Register s1{9};
+  static constexpr Register a0{10};
+  static constexpr Register a1{11};
+  static constexpr Register a2{12};
+  static constexpr Register a3{13};
+  static constexpr Register a4{14};
+  static constexpr Register a5{15};
+  static constexpr Register a6{16};
+  static constexpr Register a7{17};
+  static constexpr Register s2{18};
+  static constexpr Register s3{19};
+  static constexpr Register s4{20};
+  static constexpr Register s5{21};
+  static constexpr Register s6{22};
+  static constexpr Register s7{23};
+  static constexpr Register s8{24};
+  static constexpr Register s9{25};
+  static constexpr Register s10{26};
+  static constexpr Register s11{27};
+  static constexpr Register t3{28};
+  static constexpr Register t4{29};
+  static constexpr Register t5{30};
+  static constexpr Register t6{31};
+
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+};
+
+}  // namespace rv64i
+
+}  // namespace berberis
+
+#endif  // BERBERIS_ASSEMBLER_RV64I_H_
diff --git a/assembler/include/berberis/assembler/x86_32.h b/assembler/include/berberis/assembler/x86_32.h
index cde5c682..bd88a2b6 100644
--- a/assembler/include/berberis/assembler/x86_32.h
+++ b/assembler/include/berberis/assembler/x86_32.h
@@ -21,16 +21,18 @@
 
 #include <type_traits>  // std::is_same
 
-#include "berberis/assembler/common_x86.h"
-#include "berberis/base/macros.h"  // DISALLOW_IMPLICIT_CONSTRUCTORS
+#include "berberis/assembler/x86_32_and_x86_64.h"
 
 namespace berberis {
 
 namespace x86_32 {
 
-class Assembler : public AssemblerX86<Assembler> {
+class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
  public:
-  explicit Assembler(MachineCode* code) : AssemblerX86(code) {}
+  using BaseAssembler = x86_32_and_x86_64::Assembler<Assembler>;
+  using FinalAssembler = Assembler;
+
+  explicit Assembler(MachineCode* code) : BaseAssembler(code) {}
 
   static constexpr Register no_register{0x80};
   static constexpr Register eax{0};
@@ -61,91 +63,92 @@ class Assembler : public AssemblerX86<Assembler> {
 #include "berberis/assembler/gen_assembler_x86_32-inl.h"  // NOLINT generated file!
 
   // Unhide Decl(Mem) hidden by Decl(Reg).
-  using AssemblerX86::Decl;
+  using BaseAssembler::Decl;
 
   // Unhide Decw(Mem) hidden by Decw(Reg).
-  using AssemblerX86::Decw;
+  using BaseAssembler::Decw;
 
   // Unhide Incl(Mem) hidden by Incl(Reg).
-  using AssemblerX86::Incl;
+  using BaseAssembler::Incl;
 
   // Unhide Incw(Mem) hidden by Incw(Reg).
-  using AssemblerX86::Incw;
+  using BaseAssembler::Incw;
 
   // Unhide Movb(Reg, Reg) hidden by special versions below.
-  using AssemblerX86::Movb;
+  using BaseAssembler::Movb;
 
   // Movb in 32-bit mode has certain optimizations not available in x86-64 mode
   void Movb(Register dest, const Operand& src) {
     if (IsAccumulator(dest) && src.base == no_register && src.index == no_register) {
-      EmitInstruction<Opcodes<0xA0>>(src.disp);
+      EmitInstruction<0xA0>(src.disp);
     } else {
-      AssemblerX86::Movb(dest, src);
+      BaseAssembler::Movb(dest, src);
     }
   }
 
   void Movb(const Operand& dest, Register src) {
     if (dest.base == no_register && dest.index == no_register && IsAccumulator(src)) {
-      EmitInstruction<Opcodes<0xA2>>(dest.disp);
+      EmitInstruction<0xA2>(dest.disp);
     } else {
-      AssemblerX86::Movb(dest, src);
+      BaseAssembler::Movb(dest, src);
     }
   }
 
   // Unhide Movw(Reg, Reg) hidden by special versions below.
-  using AssemblerX86::Movw;
+  using BaseAssembler::Movw;
 
   // Movw in 32-bit mode has certain optimizations not available in x86-64 mode
   void Movw(Register dest, const Operand& src) {
     if (IsAccumulator(dest) && src.base == no_register && src.index == no_register) {
-      EmitInstruction<Opcodes<0x66, 0xA1>>(src.disp);
+      EmitInstruction<0x66, 0xA1>(src.disp);
     } else {
-      AssemblerX86::Movw(dest, src);
+      BaseAssembler::Movw(dest, src);
     }
   }
 
   void Movw(const Operand& dest, Register src) {
     if (dest.base == no_register && dest.index == no_register && IsAccumulator(src)) {
-      EmitInstruction<Opcodes<0x66, 0xA3>>(dest.disp);
+      EmitInstruction<0x66, 0xA3>(dest.disp);
     } else {
-      AssemblerX86::Movw(dest, src);
+      BaseAssembler::Movw(dest, src);
     }
   }
 
   // Unhide Movl(Reg, Reg) hidden by special versions below.
-  using AssemblerX86::Movl;
+  using BaseAssembler::Movl;
 
   // Movl in 32-bit mode has certain optimizations not available in x86-64 mode
   void Movl(Register dest, const Operand& src) {
     if (IsAccumulator(dest) && src.base == no_register && src.index == no_register) {
-      EmitInstruction<Opcodes<0xA1>>(src.disp);
+      EmitInstruction<0xA1>(src.disp);
     } else {
-      AssemblerX86::Movl(dest, src);
+      BaseAssembler::Movl(dest, src);
     }
   }
 
   void Movl(const Operand& dest, Register src) {
     if (dest.base == no_register && dest.index == no_register && IsAccumulator(src)) {
-      EmitInstruction<Opcodes<0xA3>>(dest.disp);
+      EmitInstruction<0xA3>(dest.disp);
     } else {
-      AssemblerX86::Movl(dest, src);
+      BaseAssembler::Movl(dest, src);
     }
   }
 
   // Unhide Vmov*(Mem, Reg) hidden by Vmov*(Reg, Reg).
-  using AssemblerX86::Vmovapd;
-  using AssemblerX86::Vmovaps;
-  using AssemblerX86::Vmovdqa;
-  using AssemblerX86::Vmovdqu;
-  using AssemblerX86::Vmovsd;
-  using AssemblerX86::Vmovss;
+  using BaseAssembler::Vmovapd;
+  using BaseAssembler::Vmovaps;
+  using BaseAssembler::Vmovdqa;
+  using BaseAssembler::Vmovdqu;
+  using BaseAssembler::Vmovq;
+  using BaseAssembler::Vmovsd;
+  using BaseAssembler::Vmovss;
 
   // TODO(b/127356868): decide what to do with these functions when cross-arch assembler is used.
 
 #ifdef __i386__
 
   // Unside Call(Reg), hidden by special version below.
-  using AssemblerX86::Call;
+  using BaseAssembler::Call;
 
   void Call(const void* target) {
     Emit8(0xe8);
@@ -156,7 +159,7 @@ class Assembler : public AssemblerX86<Assembler> {
   }
 
   // Unside Jcc(Label), hidden by special version below.
-  using AssemblerX86::Jcc;
+  using BaseAssembler::Jcc;
 
   // Make sure only type void* can be passed to function below, not Label* or any other type.
   template <typename T>
@@ -179,7 +182,7 @@ class Assembler : public AssemblerX86<Assembler> {
   }
 
   // Unside Jmp(Reg), hidden by special version below.
-  using AssemblerX86::Jmp;
+  using BaseAssembler::Jmp;
 
   // Make sure only type void* can be passed to function below, not Label* or any other type.
   template <typename T>
@@ -196,7 +199,12 @@ class Assembler : public AssemblerX86<Assembler> {
 #endif
 
  private:
-  DISALLOW_IMPLICIT_CONSTRUCTORS(Assembler);
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+  using DerivedAssemblerType = Assembler;
 
   static Register Accumulator() { return eax; }
   static bool IsAccumulator(Register reg) { return reg == eax; }
@@ -243,7 +251,7 @@ class Assembler : public AssemblerX86<Assembler> {
     constexpr auto vvvv_parameter = 2 - reg_is_opcode_extension - operands_count - labels_count;
     int vvvv = 0;
     if constexpr (registers_count > vvvv_parameter) {
-      vvvv = ArgumentByType<vvvv_parameter, IsRegister>(arguments...).num;
+      vvvv = ArgumentByType<vvvv_parameter, IsRegister>(arguments...).num_;
     }
     // Note that ¬R is always 1 in x86-32 mode but it's not set in JSON.
     // This means that 2nd byte of 3-byte vex is always the same in 32bit mode (but 3rd byte of
@@ -259,34 +267,34 @@ class Assembler : public AssemblerX86<Assembler> {
 
   template <typename ArgumentType>
   void EmitRegisterInOpcode(uint8_t opcode, ArgumentType argument) {
-    Emit8(opcode | argument.num);
+    Emit8(opcode | argument.num_);
   }
 
   template <typename ArgumentType1, typename ArgumentType2>
   void EmitModRM(ArgumentType1 argument1, ArgumentType2 argument2) {
-    Emit8(0xC0 | (argument1.num << 3) | argument2.num);
+    Emit8(0xC0 | (argument1.num_ << 3) | argument2.num_);
   }
 
   template <typename ArgumentType>
   void EmitModRM(uint8_t opcode_extension, ArgumentType argument) {
     CHECK_LE(opcode_extension, 7);
-    Emit8(0xC0 | (opcode_extension << 3) | argument.num);
+    Emit8(0xC0 | (opcode_extension << 3) | argument.num_);
   }
 
   template <typename ArgumentType>
   void EmitOperandOp(ArgumentType argument, Operand operand) {
-    EmitOperandOp(static_cast<int>(argument.num), operand);
+    EmitOperandOp(static_cast<int>(argument.num_), operand);
   }
 
   template <size_t kImmediatesSize, typename ArgumentType>
   void EmitRipOp(ArgumentType argument, const Label& label) {
-    EmitRipOp<kImmediatesSize>(static_cast<int>(argument.num), label);
+    EmitRipOp<kImmediatesSize>(static_cast<int>(argument.num_), label);
   }
 
   // Emit the ModR/M byte, and optionally the SIB byte and
   // 1- or 4-byte offset for a memory operand.  Also used to encode
   // a three-bit opcode extension into the ModR/M byte.
-  void EmitOperandOp(int number, const Operand& addr);
+  void EmitOperandOp(int num_ber, const Operand& addr);
   // Helper functions to handle various ModR/M and SIB combinations.
   // Should *only* be called from EmitOperandOp!
   void EmitIndexDispOperand(int reg, const Operand& addr);
@@ -294,9 +302,9 @@ class Assembler : public AssemblerX86<Assembler> {
   void EmitBaseIndexDispOperand(int base_modrm_and_sib, const Operand& addr);
   // Emit ModR/M for rip-addressig.
   template <size_t kImmediatesSize>
-  void EmitRipOp(int num, const Label& label);
+  void EmitRipOp(int num_, const Label& label);
 
-  friend AssemblerX86<Assembler>;
+  friend BaseAssembler;
 };
 
 // This function looks big, but when we are emitting Operand with fixed registers
@@ -304,12 +312,12 @@ class Assembler : public AssemblerX86<Assembler> {
 // makes effective size of that function very small.
 //
 // But for this to happen function have to be inline and in header.
-inline void Assembler::EmitOperandOp(int number, const Operand& addr) {
-  // Additional info (register number, etc) is limited to 3 bits.
-  CHECK_LE(unsigned(number), 7);
+inline void Assembler::EmitOperandOp(int num_ber, const Operand& addr) {
+  // Additional info (register num_ber, etc) is limited to 3 bits.
+  CHECK_LE(unsigned(num_ber), 7);
 
   // Reg field must be shifted by 3 bits.
-  int reg = number << 3;
+  int reg = num_ber << 3;
 
   // On x86 %esp cannot be index, only base.
   CHECK(addr.index != esp);
@@ -319,7 +327,7 @@ inline void Assembler::EmitOperandOp(int number, const Operand& addr) {
   if (addr.base != esp && addr.index == no_register) {
     // If we have base register then we could use the same logic as for other common cases.
     if (addr.base != no_register) {
-      EmitBaseIndexDispOperand<uint8_t, &Assembler::Emit8>(addr.base.num | reg, addr);
+      EmitBaseIndexDispOperand<uint8_t, &Assembler::Emit8>(addr.base.num_ | reg, addr);
     } else {
       Emit8(0x05 | reg);
       Emit32(addr.disp);
@@ -327,19 +335,19 @@ inline void Assembler::EmitOperandOp(int number, const Operand& addr) {
   } else if (addr.index == no_register) {
     // Note: when ModR/M and SIB are used "no index" is encoded as if %esp is used in place of
     // index (that's why %esp couldn't be used as index - see check above).
-    EmitBaseIndexDispOperand<int16_t, &Assembler::Emit16>(0x2004 | (addr.base.num << 8) | reg,
+    EmitBaseIndexDispOperand<int16_t, &Assembler::Emit16>(0x2004 | (addr.base.num_ << 8) | reg,
                                                           addr);
   } else if (addr.base == no_register) {
     EmitIndexDispOperand(reg, addr);
   } else {
     EmitBaseIndexDispOperand<int16_t, &Assembler::Emit16>(
-        0x04 | (addr.scale << 14) | (addr.index.num << 11) | (addr.base.num << 8) | reg, addr);
+        0x04 | (addr.scale << 14) | (addr.index.num_ << 11) | (addr.base.num_ << 8) | reg, addr);
   }
 }
 
 inline void Assembler::EmitIndexDispOperand(int reg, const Operand& addr) {
   // We only have index here, no base, use SIB but put %ebp in "base" field.
-  Emit16(0x0504 | (addr.scale << 14) | (addr.index.num << 11) | reg);
+  Emit16(0x0504 | (addr.scale << 14) | (addr.index.num_ << 11) | reg);
   Emit32(addr.disp);
 }
 
diff --git a/assembler/include/berberis/assembler/common_x86.h b/assembler/include/berberis/assembler/x86_32_and_x86_64.h
similarity index 58%
rename from assembler/include/berberis/assembler/common_x86.h
rename to assembler/include/berberis/assembler/x86_32_and_x86_64.h
index c67ce55a..81680482 100644
--- a/assembler/include/berberis/assembler/common_x86.h
+++ b/assembler/include/berberis/assembler/x86_32_and_x86_64.h
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_ASSEMBLER_COMMON_X86_H_
-#define BERBERIS_ASSEMBLER_COMMON_X86_H_
+#ifndef BERBERIS_ASSEMBLER_X86_32_AND_X86_64_H_
+#define BERBERIS_ASSEMBLER_X86_32_AND_X86_64_H_
 
 #include <cstddef>  // std::size_t
 #include <cstdint>
@@ -24,27 +24,40 @@
 #include "berberis/assembler/common.h"
 #include "berberis/base/bit_util.h"
 #include "berberis/base/checks.h"
-#include "berberis/base/macros.h"  // DISALLOW_IMPLICIT_CONSTRUCTORS
 
 namespace berberis {
 
-// AssemblerX86 includes implementation of most x86 assembler instructions.
+// Assembler includes implementation of most x86 assembler instructions.
 //
 // x86-32 and x86-64 assemblers are nearly identical, but difference lies in handling
 // of very low-level instruction details: almost all instructions on x86-64 could include
 // REX byte which is needed if new registers (%r8 to %r15 or %xmm8 to %xmm15) are used.
 //
-// To handle that difference efficiently AssemblerX86 is CRTP class: it's parameterized
+// To handle that difference efficiently Assembler is CRTP class: it's parameterized
 // by its own descendant and pull certain functions (e.g. GetHighBit or Rex8Size) from
 // its implementation.
 //
 // Certain functions are only implemented by its descendant (since there are instructions
 // which only exist in x86-32 mode and instructions which only exist in x86-64 mode).
 
-template <typename Assembler>
-class AssemblerX86 : public AssemblerBase {
+namespace x86_32 {
+
+class Assembler;
+
+}  // namespace x86_32
+
+namespace x86_64 {
+
+class Assembler;
+
+}  // namespace x86_64
+
+namespace x86_32_and_x86_64 {
+
+template <typename DerivedAssemblerType>
+class Assembler : public AssemblerBase {
  public:
-  explicit AssemblerX86(MachineCode* code) : AssemblerBase(code) {}
+  explicit Assembler(MachineCode* code) : AssemblerBase(code) {}
 
   enum class Condition {
     kInvalidCondition = -1,
@@ -58,7 +71,7 @@ class AssemblerX86 : public AssemblerBase {
     kBelowEqual = 6,
     kAbove = 7,
     kNegative = 8,
-    kPositive = 9,
+    kPositiveOrZero = 9,
     kParityEven = 10,
     kParityOdd = 11,
     kLess = 12,
@@ -74,33 +87,76 @@ class AssemblerX86 : public AssemblerBase {
     kZero = kEqual,
     kNotZero = kNotEqual,
     kSign = kNegative,
-    kNotSign = kPositive
+    kNotSign = kPositiveOrZero
   };
 
-  struct Register {
-    // Note: we couldn't make the following private because of peculiarities of C++ (see
-    // https://stackoverflow.com/questions/24527395/compiler-error-when-initializing-constexpr-static-class-member
-    // for explanation), but you are not supposed to access num or use GetHighBit() and GetLowBits()
-    // functions.  Treat that type as opaque cookie.
-
-    constexpr bool operator==(const Register& reg) const { return num == reg.num; }
-
-    constexpr bool operator!=(const Register& reg) const { return num != reg.num; }
+  friend constexpr const char* GetCondName(Condition cond) {
+    switch (cond) {
+      case Condition::kOverflow:
+        return "O";
+      case Condition::kNoOverflow:
+        return "NO";
+      case Condition::kBelow:
+        return "B";
+      case Condition::kAboveEqual:
+        return "AE";
+      case Condition::kEqual:
+        return "Z";
+      case Condition::kNotEqual:
+        return "NZ";
+      case Condition::kBelowEqual:
+        return "BE";
+      case Condition::kAbove:
+        return "A";
+      case Condition::kNegative:
+        return "N";
+      case Condition::kPositiveOrZero:
+        return "PL";
+      case Condition::kParityEven:
+        return "PE";
+      case Condition::kParityOdd:
+        return "PO";
+      case Condition::kLess:
+        return "LS";
+      case Condition::kGreaterEqual:
+        return "GE";
+      case Condition::kLessEqual:
+        return "LE";
+      case Condition::kGreater:
+        return "GT";
+      default:
+        return "??";
+    }
+  }
 
-    uint8_t num;
+  class Register {
+   public:
+    constexpr bool operator==(const Register& reg) const { return num_ == reg.num_; }
+    constexpr bool operator!=(const Register& reg) const { return num_ != reg.num_; }
+    constexpr uint8_t GetPhysicalIndex() { return num_; }
+    friend constexpr uint8_t ValueForFmtSpec(Register value) { return value.num_; }
+    friend class Assembler<DerivedAssemblerType>;
+    friend class x86_32::Assembler;
+    friend class x86_64::Assembler;
+
+   private:
+    explicit constexpr Register(uint8_t num) : num_(num) {}
+    uint8_t num_;
   };
 
-  struct X87Register {
-    // Note: we couldn't make the following private because of peculiarities of C++ (see
-    // https://stackoverflow.com/questions/24527395/compiler-error-when-initializing-constexpr-static-class-member
-    // for explanation), but you are not supposed to access num or use GetHighBit() and GetLowBits()
-    // functions.  Treat that type as opaque cookie.
-
-    constexpr bool operator==(const Register& reg) const { return num == reg.num; }
-
-    constexpr bool operator!=(const Register& reg) const { return num != reg.num; }
-
-    uint8_t num;
+  class X87Register {
+   public:
+    constexpr bool operator==(const Register& reg) const { return num_ == reg.num_; }
+    constexpr bool operator!=(const Register& reg) const { return num_ != reg.num_; }
+    constexpr uint8_t GetPhysicalIndex() { return num_; }
+    friend constexpr uint8_t ValueForFmtSpec(X87Register value) { return value.num_; }
+    friend class Assembler<DerivedAssemblerType>;
+    friend class x86_32::Assembler;
+    friend class x86_64::Assembler;
+
+   private:
+    explicit constexpr X87Register(uint8_t num) : num_(num) {}
+    uint8_t num_;
   };
 
   static constexpr X87Register st{0};
@@ -113,32 +169,36 @@ class AssemblerX86 : public AssemblerBase {
   static constexpr X87Register st6{6};
   static constexpr X87Register st7{7};
 
-  struct XMMRegister {
-    // Note: we couldn't make the following private because of peculiarities of C++ (see
-    // https://stackoverflow.com/questions/24527395/compiler-error-when-initializing-constexpr-static-class-member
-    // for explanation), but you are not supposed to access num or use GetHighBit() and GetLowBits()
-    // functions.  Treat that type as opaque cookie.
-
-    constexpr bool operator==(const XMMRegister& reg) const { return num == reg.num; }
-
-    constexpr bool operator!=(const XMMRegister& reg) const { return num != reg.num; }
-
-    uint8_t num;
+  class XMMRegister {
+   public:
+    constexpr bool operator==(const XMMRegister& reg) const { return num_ == reg.num_; }
+    constexpr bool operator!=(const XMMRegister& reg) const { return num_ != reg.num_; }
+    constexpr uint8_t GetPhysicalIndex() { return num_; }
+    friend constexpr uint8_t ValueForFmtSpec(XMMRegister value) { return value.num_; }
+    friend class Assembler<DerivedAssemblerType>;
+    friend class x86_32::Assembler;
+    friend class x86_64::Assembler;
+
+   private:
+    explicit constexpr XMMRegister(uint8_t num) : num_(num) {}
+    uint8_t num_;
   };
 
   enum ScaleFactor { kTimesOne = 0, kTimesTwo = 1, kTimesFour = 2, kTimesEight = 3 };
 
   struct Operand {
     constexpr uint8_t rex() const {
-      return Assembler::kIsX86_64 ? ((index.num & 0x08) >> 2) | ((base.num & 0x08) >> 3) : 0;
+      return DerivedAssemblerType::kIsX86_64
+                 ? ((index.num_ & 0x08) >> 2) | ((base.num_ & 0x08) >> 3)
+                 : 0;
     }
 
     constexpr bool RequiresRex() const {
-      return Assembler::kIsX86_64 ? ((index.num & 0x08) | (base.num & 0x08)) : false;
+      return DerivedAssemblerType::kIsX86_64 ? ((index.num_ & 0x08) | (base.num_ & 0x08)) : false;
     }
 
-    Register base = Assembler::no_register;
-    Register index = Assembler::no_register;
+    Register base = DerivedAssemblerType::no_register;
+    Register index = DerivedAssemblerType::no_register;
     ScaleFactor scale = kTimesOne;
     int32_t disp = 0;
   };
@@ -211,7 +271,7 @@ class AssemblerX86 : public AssemblerBase {
   }
 
 // Instructions.
-#include "berberis/assembler/gen_assembler_common_x86-inl.h"  // NOLINT generated file
+#include "berberis/assembler/gen_assembler_x86_32_and_x86_64-inl.h"  // NOLINT generated file
 
   // Flow control.
   void Jmp(int32_t offset) {
@@ -258,14 +318,14 @@ class AssemblerX86 : public AssemblerBase {
  protected:
   // Helper types to distinguish argument types.
   struct Register8Bit {
-    explicit constexpr Register8Bit(Register reg) : num(reg.num) {}
-    uint8_t num;
+    explicit constexpr Register8Bit(Register reg) : num_(reg.num_) {}
+    uint8_t num_;
   };
 
   struct Register32Bit {
-    explicit constexpr Register32Bit(Register reg) : num(reg.num) {}
-    explicit constexpr Register32Bit(XMMRegister reg) : num(reg.num) {}
-    uint8_t num;
+    explicit constexpr Register32Bit(Register reg) : num_(reg.num_) {}
+    explicit constexpr Register32Bit(XMMRegister reg) : num_(reg.num_) {}
+    uint8_t num_;
   };
 
   // 16-bit and 128-bit vector registers follow the same rules as 32-bit registers.
@@ -288,6 +348,9 @@ class AssemblerX86 : public AssemblerBase {
   // Only 64-bit memory is different.
   using Memory8Bit = Memory32Bit;
   using Memory16Bit = Memory32Bit;
+  // Some instructions have memory operand that have unspecified size (lea, prefetch, etc),
+  // they are encoded like Memory32Bit, anyway.
+  using MemoryDefaultBit = Memory32Bit;
   // X87 instructions always use the same encoding - even for 64-bit or 28-bytes
   // memory operands (like in fldenv/fnstenv)
   using MemoryX87 = Memory32Bit;
@@ -312,6 +375,9 @@ class AssemblerX86 : public AssemblerBase {
   // Only 64-bit memory is different.
   using Label8Bit = Label32Bit;
   using Label16Bit = Label32Bit;
+  // Some instructions have memory operand that have unspecified size (lea, prefetch, etc),
+  // they are encoded like Label32Bit, anyway.
+  using LabelDefaultBit = Label32Bit;
   // X87 instructions always use the same encoding - even for 64-bit or 28-bytes
   // memory operands (like in fldenv/fnstenv)
   using LabelX87 = Label32Bit;
@@ -338,18 +404,20 @@ class AssemblerX86 : public AssemblerBase {
 
   template <typename ArgumentType>
   struct IsRegister {
-    static constexpr bool value = Assembler::template IsRegister<ArgumentType>::value ||
+    static constexpr bool value = DerivedAssemblerType::template IsRegister<ArgumentType>::value ||
                                   std::is_same_v<ArgumentType, X87Register>;
   };
 
   template <typename ArgumentType>
   struct IsMemoryOperand {
-    static constexpr bool value = Assembler::template IsMemoryOperand<ArgumentType>::value;
+    static constexpr bool value =
+        DerivedAssemblerType::template IsMemoryOperand<ArgumentType>::value;
   };
 
   template <typename ArgumentType>
   struct IsLabelOperand {
-    static constexpr bool value = Assembler::template IsLabelOperand<ArgumentType>::value;
+    static constexpr bool value =
+        DerivedAssemblerType::template IsLabelOperand<ArgumentType>::value;
   };
 
   template <typename ArgumentType>
@@ -362,8 +430,8 @@ class AssemblerX86 : public AssemblerBase {
 
   // Count number of arguments selected by Predicate.
   template <template <typename> typename Predicate, typename... ArgumentTypes>
-  static constexpr std::size_t kCountArguments = ((Predicate<ArgumentTypes>::value ? 1 : 0) + ... +
-                                                  0);
+  static constexpr std::size_t kCountArguments =
+      ((Predicate<ArgumentTypes>::value ? 1 : 0) + ... + 0);
 
   // Extract arguments selected by Predicate.
   //
@@ -437,35 +505,6 @@ class AssemblerX86 : public AssemblerBase {
     return (ImmediateSize<ArgumentTypes>() + ... + 0);
   }
 
-  // Struct type to pass information about opcodes.
-  template <uint8_t... kOpcodes>
-  struct Opcodes {};
-
-  template <uint8_t... kOpcodes>
-  static constexpr size_t OpcodesCount(Opcodes<kOpcodes...>) {
-    return sizeof...(kOpcodes);
-  }
-
-  template <uint8_t kOpcode, uint8_t... kOpcodes>
-  static constexpr uint8_t FirstOpcode(Opcodes<kOpcode, kOpcodes...>) {
-    return kOpcode;
-  }
-
-  template <uint8_t kOpcode, uint8_t... kOpcodes>
-  static constexpr auto SkipFirstOpcodeFromType(Opcodes<kOpcode, kOpcodes...>) {
-    return Opcodes<kOpcodes...>{};
-  }
-
-  template <uint8_t kOpcode, uint8_t... kOpcodes>
-  auto EmitLegacyPrefixes(Opcodes<kOpcode, kOpcodes...> opcodes) {
-    if constexpr (IsLegacyPrefix(kOpcode)) {
-      Emit8(kOpcode);
-      return EmitLegacyPrefixes(Opcodes<kOpcodes...>{});
-    } else {
-      return opcodes;
-    }
-  }
-
   // Note: We may need separate x87 EmitInstruction if we would want to support
   // full set of x86 instructions.
   //
@@ -505,24 +544,36 @@ class AssemblerX86 : public AssemblerBase {
   // Note: if you change this function (or any of the helper functions) then remove --fast
   // option from ExhaustiveAssemblerTest to run full blackbox comparison to clang.
 
-  template <typename InstructionOpcodes, typename... ArgumentsTypes>
+  template <uint8_t... kOpcodes, typename... ArgumentsTypes>
   void EmitInstruction(ArgumentsTypes... arguments) {
-    auto opcodes_no_prefixes = EmitLegacyPrefixes(InstructionOpcodes{});
+    static constexpr auto kOpcodesArray = std::array{kOpcodes...};
+    static constexpr size_t kLegacyPrefixesCount = []() {
+      size_t legacy_prefixes_count = 0;
+      for (legacy_prefixes_count = 0; IsLegacyPrefix(kOpcodesArray[legacy_prefixes_count]);
+           ++legacy_prefixes_count) {
+      }
+      return legacy_prefixes_count;
+    }();
+    for (size_t legacy_prefixes_index = 0; legacy_prefixes_index < kLegacyPrefixesCount;
+         ++legacy_prefixes_index) {
+      Emit8(kOpcodesArray[legacy_prefixes_index]);
+    }
     // We don't yet support any XOP-encoded instructions, but they are 100% identical to vex ones,
     // except they are using 0x8F prefix, not 0xC4 prefix.
-    constexpr auto vex_xop = [&](auto opcodes) {
-      if constexpr (OpcodesCount(opcodes) < 3) {
+    constexpr auto kVexOrXop = []() {
+      if constexpr (std::size(kOpcodesArray) < kLegacyPrefixesCount + 3) {
         return false;
-      // Note that JSON files use AMD approach: bytes are specified as in AMD manual (only we are
-      // replacing ¬R/¬X/¬B and vvvv bits with zeros).
-      //
-      // In particular it means that vex-encoded instructions should be specified with 0xC4 even if
-      // they are always emitted with 0xC4-to-0xC5 folding.
-      } else if constexpr (FirstOpcode(opcodes) == 0xC4 || FirstOpcode(opcodes) == 0x8F) {
+        // Note that JSON files use AMD approach: bytes are specified as in AMD manual (only we are
+        // replacing ¬R/¬X/¬B and vvvv bits with zeros).
+        //
+        // In particular it means that vex-encoded instructions should be specified with 0xC4 even
+        // if they are always emitted with 0xC4-to-0xC5 folding.
+      } else if constexpr (kOpcodesArray[kLegacyPrefixesCount] == 0xC4 ||
+                           kOpcodesArray[kLegacyPrefixesCount] == 0x8F) {
         return true;
       }
       return false;
-    }(opcodes_no_prefixes);
+    }();
     constexpr auto conditions_count = kCountArguments<IsCondition, ArgumentsTypes...>;
     constexpr auto operands_count = kCountArguments<IsMemoryOperand, ArgumentsTypes...>;
     constexpr auto labels_count = kCountArguments<IsLabelOperand, ArgumentsTypes...>;
@@ -532,7 +583,7 @@ class AssemblerX86 : public AssemblerBase {
     constexpr auto reg_is_opcode_extension =
         (registers_count + operands_count > 0) &&
         (registers_count + operands_count + labels_count <
-         2 + vex_xop * (OpcodesCount(opcodes_no_prefixes) - 4));
+         2 + kVexOrXop * (std::size(kOpcodesArray) - kLegacyPrefixesCount - 4));
     static_assert((registers_count + operands_count + labels_count + conditions_count +
                    kCountArguments<IsImmediate, ArgumentsTypes...>) == sizeof...(ArgumentsTypes),
                   "Only registers (with specified size), Operands (with specified size), "
@@ -540,49 +591,46 @@ class AssemblerX86 : public AssemblerBase {
     static_assert(operands_count <= 1, "Only one operand is allowed in instruction.");
     static_assert(labels_count <= 1, "Only one label is allowed in instruction.");
     // 0x0f is an opcode extension, if it's not there then we only have one byte opcode.
-    auto opcodes_no_prefixes_no_opcode_extension = [&](auto opcodes) {
-      if constexpr (vex_xop) {
+    const size_t kPrefixesAndOpcodeExtensionsCount = []() {
+      if constexpr (kVexOrXop) {
         static_assert(conditions_count == 0,
                       "No conditionals are supported in vex/xop instructions.");
         static_assert((registers_count + operands_count + labels_count) <= 4,
                       "Up to four-arguments in vex/xop instructions are supported.");
-        constexpr auto vex_xop_byte1 = FirstOpcode(opcodes);
-        constexpr auto vex_xop_byte2 = FirstOpcode(SkipFirstOpcodeFromType(opcodes));
-        constexpr auto vex_xop_byte3 =
-            FirstOpcode(SkipFirstOpcodeFromType(SkipFirstOpcodeFromType(opcodes)));
-        static_cast<Assembler*>(this)
-            ->template EmitVex<vex_xop_byte1,
-                               vex_xop_byte2,
-                               vex_xop_byte3,
-                               reg_is_opcode_extension>(arguments...);
-        return SkipFirstOpcodeFromType(SkipFirstOpcodeFromType(SkipFirstOpcodeFromType(opcodes)));
+        return kLegacyPrefixesCount + 3;
       } else {
         static_assert(conditions_count <= 1, "Only one condition is allowed in instruction.");
         static_assert((registers_count + operands_count + labels_count) <= 2,
                       "Only two-arguments legacy instructions are supported.");
-        static_cast<Assembler*>(this)->EmitRex(arguments...);
-        if constexpr (FirstOpcode(opcodes) == 0x0F) {
-          Emit8(0x0F);
-          auto opcodes_no_prefixes_no_opcode_0x0F_extension = SkipFirstOpcodeFromType(opcodes);
-          if constexpr (FirstOpcode(opcodes_no_prefixes_no_opcode_0x0F_extension) == 0x38) {
-            Emit8(0x38);
-            return SkipFirstOpcodeFromType(opcodes_no_prefixes_no_opcode_0x0F_extension);
-          } else if constexpr (FirstOpcode(opcodes_no_prefixes_no_opcode_0x0F_extension) == 0x3A) {
-            Emit8(0x3A);
-            return SkipFirstOpcodeFromType(opcodes_no_prefixes_no_opcode_0x0F_extension);
-          } else {
-            return opcodes_no_prefixes_no_opcode_0x0F_extension;
+        if constexpr (kOpcodesArray[kLegacyPrefixesCount] == 0x0F) {
+          if constexpr (kOpcodesArray[kLegacyPrefixesCount + 1] == 0x38 ||
+                        kOpcodesArray[kLegacyPrefixesCount + 1] == 0x3A) {
+            return kLegacyPrefixesCount + 2;
           }
-        } else {
-          return opcodes;
+          return kLegacyPrefixesCount + 1;
         }
+        return kLegacyPrefixesCount;
       }
-    }(opcodes_no_prefixes);
+    }();
+    if constexpr (kVexOrXop) {
+      static_cast<DerivedAssemblerType*>(this)
+          ->template EmitVex<kOpcodesArray[kLegacyPrefixesCount],
+                             kOpcodesArray[kLegacyPrefixesCount + 1],
+                             kOpcodesArray[kLegacyPrefixesCount + 2],
+                             reg_is_opcode_extension>(arguments...);
+    } else {
+      static_cast<DerivedAssemblerType*>(this)->EmitRex(arguments...);
+      for (size_t extension_opcode_index = kLegacyPrefixesCount;
+           extension_opcode_index < kPrefixesAndOpcodeExtensionsCount;
+           ++extension_opcode_index) {
+        Emit8(kOpcodesArray[extension_opcode_index]);
+      }
+    }
     // These are older 8086 instructions which encode register number in the opcode itself.
     if constexpr (registers_count == 1 && operands_count == 0 && labels_count == 0 &&
-                  OpcodesCount(opcodes_no_prefixes_no_opcode_extension) == 1) {
-      static_cast<Assembler*>(this)->EmitRegisterInOpcode(
-          FirstOpcode(opcodes_no_prefixes_no_opcode_extension),
+                  std::size(kOpcodesArray) == kPrefixesAndOpcodeExtensionsCount + 1) {
+      static_cast<DerivedAssemblerType*>(this)->EmitRegisterInOpcode(
+          kOpcodesArray[kPrefixesAndOpcodeExtensionsCount],
           ArgumentByType<0, IsRegister>(arguments...));
       EmitImmediates(arguments...);
     } else {
@@ -590,54 +638,57 @@ class AssemblerX86 : public AssemblerBase {
       if constexpr (conditions_count == 1) {
         auto condition_code = static_cast<uint8_t>(ArgumentByType<0, IsCondition>(arguments...));
         CHECK_EQ(0, condition_code & 0xF0);
-        Emit8(FirstOpcode(opcodes_no_prefixes_no_opcode_extension) | condition_code);
+        Emit8(kOpcodesArray[kPrefixesAndOpcodeExtensionsCount] | condition_code);
       } else {
-        Emit8(FirstOpcode(opcodes_no_prefixes_no_opcode_extension));
+        Emit8(kOpcodesArray[kPrefixesAndOpcodeExtensionsCount]);
       }
-      auto extra_opcodes = SkipFirstOpcodeFromType(opcodes_no_prefixes_no_opcode_extension);
       if constexpr (reg_is_opcode_extension) {
         if constexpr (operands_count == 1) {
-          static_cast<Assembler*>(this)->EmitOperandOp(
-              static_cast<int>(FirstOpcode(extra_opcodes)),
+          static_cast<DerivedAssemblerType*>(this)->EmitOperandOp(
+              static_cast<int>(kOpcodesArray[kPrefixesAndOpcodeExtensionsCount + 1]),
               ArgumentByType<0, IsMemoryOperand>(arguments...).operand);
         } else if constexpr (labels_count == 1) {
-          static_cast<Assembler*>(this)->template EmitRipOp<ImmediatesSize<ArgumentsTypes...>()>(
-              static_cast<int>(FirstOpcode(extra_opcodes)),
-              ArgumentByType<0, IsLabelOperand>(arguments...).label);
+          static_cast<DerivedAssemblerType*>(this)
+              ->template EmitRipOp<ImmediatesSize<ArgumentsTypes...>()>(
+                  static_cast<int>(kOpcodesArray[kPrefixesAndOpcodeExtensionsCount + 1]),
+                  ArgumentByType<0, IsLabelOperand>(arguments...).label);
         } else {
-          static_cast<Assembler*>(this)->EmitModRM(this->FirstOpcode(extra_opcodes),
-                                                   ArgumentByType<0, IsRegister>(arguments...));
+          static_cast<DerivedAssemblerType*>(this)->EmitModRM(
+              kOpcodesArray[kPrefixesAndOpcodeExtensionsCount + 1],
+              ArgumentByType<0, IsRegister>(arguments...));
         }
       } else if constexpr (registers_count > 0) {
         if constexpr (operands_count == 1) {
-          static_cast<Assembler*>(this)->EmitOperandOp(
+          static_cast<DerivedAssemblerType*>(this)->EmitOperandOp(
               ArgumentByType<0, IsRegister>(arguments...),
               ArgumentByType<0, IsMemoryOperand>(arguments...).operand);
         } else if constexpr (labels_count == 1) {
-          static_cast<Assembler*>(this)->template EmitRipOp<ImmediatesSize<ArgumentsTypes...>()>(
-              ArgumentByType<0, IsRegister>(arguments...),
-              ArgumentByType<0, IsLabelOperand>(arguments...).label);
+          static_cast<DerivedAssemblerType*>(this)
+              ->template EmitRipOp<ImmediatesSize<ArgumentsTypes...>()>(
+                  ArgumentByType<0, IsRegister>(arguments...),
+                  ArgumentByType<0, IsLabelOperand>(arguments...).label);
         } else {
-          static_cast<Assembler*>(this)->EmitModRM(ArgumentByType<0, IsRegister>(arguments...),
-                                                   ArgumentByType<1, IsRegister>(arguments...));
+          static_cast<DerivedAssemblerType*>(this)->EmitModRM(
+              ArgumentByType<0, IsRegister>(arguments...),
+              ArgumentByType<1, IsRegister>(arguments...));
         }
       }
       // If reg is an opcode extension then we already used that element.
       if constexpr (reg_is_opcode_extension) {
-        static_assert(OpcodesCount(extra_opcodes) == 1);
-      } else if constexpr (OpcodesCount(extra_opcodes) > 0) {
+        static_assert(std::size(kOpcodesArray) == kPrefixesAndOpcodeExtensionsCount + 2);
+      } else if constexpr (std::size(kOpcodesArray) > kPrefixesAndOpcodeExtensionsCount + 1) {
         // Final opcode byte(s) - they are in the place where immediate is expected.
         // Cmpsps/Cmppd and 3DNow! instructions are using it.
-        static_assert(OpcodesCount(extra_opcodes) == 1);
-        Emit8(FirstOpcode(extra_opcodes));
+        static_assert(std::size(kOpcodesArray) == kPrefixesAndOpcodeExtensionsCount + 2);
+        Emit8(kOpcodesArray[kPrefixesAndOpcodeExtensionsCount + 1]);
       }
       if constexpr (registers_count + operands_count + labels_count == 4) {
         if constexpr (kCountArguments<IsImmediate, ArgumentsTypes...> == 1) {
-          Emit8((ArgumentByType<registers_count - 1, IsRegister>(arguments...).num << 4) |
+          Emit8((ArgumentByType<registers_count - 1, IsRegister>(arguments...).num_ << 4) |
                 ArgumentByType<0, IsImmediate>(arguments...));
         } else {
           static_assert(kCountArguments<IsImmediate, ArgumentsTypes...> == 0);
-          Emit8(ArgumentByType<registers_count - 1, IsRegister>(arguments...).num << 4);
+          Emit8(ArgumentByType<registers_count - 1, IsRegister>(arguments...).num_ << 4);
         }
       } else {
         EmitImmediates(arguments...);
@@ -645,63 +696,125 @@ class AssemblerX86 : public AssemblerBase {
     }
   }
 
-  void ResolveJumps();
+  // Normally instruction arguments come in the following order: vex, rm, reg, imm.
+  // But certain instructions can have swapped arguments in a different order.
+  // In addition to that we have special case where two arguments may need to be swapped
+  // to reduce encoding size.
+
+  template <uint8_t... kOpcodes,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename... ArgumentsTypes>
+  void EmitRegToRmInstruction(ArgumentsType0&& argument0,
+                              ArgumentsType1&& argument1,
+                              ArgumentsTypes&&... arguments) {
+    return EmitInstruction<kOpcodes...>(std::forward<ArgumentsType1>(argument1),
+                                        std::forward<ArgumentsType0>(argument0),
+                                        std::forward<ArgumentsTypes>(arguments)...);
+  }
 
- private:
-  DISALLOW_IMPLICIT_CONSTRUCTORS(AssemblerX86);
-};
+  template <uint8_t... kOpcodes,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename... ArgumentsTypes>
+  void EmitRmToVexInstruction(ArgumentsType0&& argument0,
+                              ArgumentsType1&& argument1,
+                              ArgumentsTypes&&... arguments) {
+    return EmitInstruction<kOpcodes...>(std::forward<ArgumentsType1>(argument1),
+                                        std::forward<ArgumentsType0>(argument0),
+                                        std::forward<ArgumentsTypes>(arguments)...);
+  }
 
-// Return the reverse condition.
-template <typename Condition>
-inline constexpr Condition ToReverseCond(Condition cond) {
-  CHECK(cond != Condition::kInvalidCondition);
-  // Condition has a nice property that given a condition, you can get
-  // its reverse condition by flipping the least significant bit.
-  return Condition(static_cast<int>(cond) ^ 1);
-}
+  // If vex operand is one of first 8 registers and rm operand is not then swapping these two
+  // operands produces more compact encoding.
+  // This only works with commutative instructions from first opcode map.
+  template <uint8_t... kOpcodes,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename ArgumentsType2,
+            typename... ArgumentsTypes>
+  void EmitOptimizableUsingCommutationInstruction(ArgumentsType0&& argument0,
+                                                  ArgumentsType1&& argument1,
+                                                  ArgumentsType2&& argument2,
+                                                  ArgumentsTypes&&... arguments) {
+    if constexpr (std::is_same_v<ArgumentsType2, ArgumentsType1>) {
+      if (DerivedAssemblerType::IsSwapProfitable(std::forward<ArgumentsType2>(argument2),
+                                                 std::forward<ArgumentsType1>(argument1))) {
+        return EmitInstruction<kOpcodes...>(std::forward<ArgumentsType0>(argument0),
+                                            std::forward<ArgumentsType1>(argument1),
+                                            std::forward<ArgumentsType2>(argument2),
+                                            std::forward<ArgumentsTypes>(arguments)...);
+      }
+    }
+    return EmitInstruction<kOpcodes...>(std::forward<ArgumentsType0>(argument0),
+                                        std::forward<ArgumentsType2>(argument2),
+                                        std::forward<ArgumentsType1>(argument1),
+                                        std::forward<ArgumentsTypes>(arguments)...);
+  }
 
-template <typename Condition>
-inline constexpr const char* GetCondName(Condition cond) {
-  switch (cond) {
-    case Condition::kOverflow:
-      return "O";
-    case Condition::kNoOverflow:
-      return "NO";
-    case Condition::kBelow:
-      return "B";
-    case Condition::kAboveEqual:
-      return "AE";
-    case Condition::kEqual:
-      return "Z";
-    case Condition::kNotEqual:
-      return "NZ";
-    case Condition::kBelowEqual:
-      return "BE";
-    case Condition::kAbove:
-      return "A";
-    case Condition::kNegative:
-      return "N";
-    case Condition::kPositive:
-      return "PL";
-    case Condition::kParityEven:
-      return "PE";
-    case Condition::kParityOdd:
-      return "PO";
-    case Condition::kLess:
-      return "LS";
-    case Condition::kGreaterEqual:
-      return "GE";
-    case Condition::kLessEqual:
-      return "LE";
-    case Condition::kGreater:
-      return "GT";
-    default:
-      return "??";
+  template <uint8_t... kOpcodes,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename ArgumentsType2,
+            typename ArgumentsType3,
+            typename... ArgumentsTypes>
+  void EmitVexImmRmToRegInstruction(ArgumentsType0&& argument0,
+                                    ArgumentsType1&& argument1,
+                                    ArgumentsType2&& argument2,
+                                    ArgumentsType3&& argument3,
+                                    ArgumentsTypes&&... arguments) {
+    return EmitInstruction<kOpcodes...>(std::forward<ArgumentsType0>(argument0),
+                                        std::forward<ArgumentsType3>(argument3),
+                                        std::forward<ArgumentsType1>(argument1),
+                                        std::forward<ArgumentsType2>(argument2),
+                                        std::forward<ArgumentsTypes>(arguments)...);
   }
-}
 
-template <typename Assembler>
-inline void AssemblerX86<Assembler>::Pmov(XMMRegister dest, XMMRegister src) {
+  template <uint8_t... kOpcodes,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename ArgumentsType2,
+            typename ArgumentsType3,
+            typename... ArgumentsTypes>
+  void EmitVexRmImmToRegInstruction(ArgumentsType0&& argument0,
+                                    ArgumentsType1&& argument1,
+                                    ArgumentsType2&& argument2,
+                                    ArgumentsType3&& argument3,
+                                    ArgumentsTypes&&... arguments) {
+    return EmitInstruction<kOpcodes...>(std::forward<ArgumentsType0>(argument0),
+                                        std::forward<ArgumentsType2>(argument2),
+                                        std::forward<ArgumentsType1>(argument1),
+                                        std::forward<ArgumentsType3>(argument3),
+                                        std::forward<ArgumentsTypes>(arguments)...);
+  }
+
+  template <uint8_t... kOpcodes,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename ArgumentsType2,
+            typename... ArgumentsTypes>
+  void EmitVexRmToRegInstruction(ArgumentsType0&& argument0,
+                                 ArgumentsType1&& argument1,
+                                 ArgumentsType2&& argument2,
+                                 ArgumentsTypes&&... arguments) {
+    return EmitInstruction<kOpcodes...>(std::forward<ArgumentsType0>(argument0),
+                                        std::forward<ArgumentsType2>(argument2),
+                                        std::forward<ArgumentsType1>(argument1),
+                                        std::forward<ArgumentsTypes>(arguments)...);
+  }
+
+  void ResolveJumps();
+
+ private:
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+};
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Pmov(XMMRegister dest, XMMRegister src) {
   // SSE does not have operations for register-to-register integer move and
   // Intel explicitly recommends to use pshufd instead on Pentium4:
   //   See https://software.intel.com/en-us/articles/
@@ -714,8 +827,8 @@ inline void AssemblerX86<Assembler>::Pmov(XMMRegister dest, XMMRegister src) {
   Movaps(dest, src);
 }
 
-template <typename Assembler>
-inline void AssemblerX86<Assembler>::Call(const Label& label) {
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Call(const Label& label) {
   if (label.IsBound()) {
     int32_t offset = label.position() - pc();
     Call(offset);
@@ -726,8 +839,8 @@ inline void AssemblerX86<Assembler>::Call(const Label& label) {
   }
 }
 
-template <typename Assembler>
-inline void AssemblerX86<Assembler>::Jcc(Condition cc, const Label& label) {
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Jcc(Condition cc, const Label& label) {
   if (cc == Condition::kAlways) {
     Jmp(label);
     return;
@@ -747,8 +860,8 @@ inline void AssemblerX86<Assembler>::Jcc(Condition cc, const Label& label) {
   }
 }
 
-template <typename Assembler>
-inline void AssemblerX86<Assembler>::Jmp(const Label& label) {
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Jmp(const Label& label) {
   // TODO(eaeltsin): may be remove IsBound case?
   // Then jmp by label will be of fixed size (5 bytes)
   if (label.IsBound()) {
@@ -761,8 +874,8 @@ inline void AssemblerX86<Assembler>::Jmp(const Label& label) {
   }
 }
 
-template <typename Assembler>
-inline void AssemblerX86<Assembler>::ResolveJumps() {
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
   for (const auto& jump : jumps_) {
     const Label* label = jump.label;
     uint32_t pc = jump.pc;
@@ -779,18 +892,20 @@ inline void AssemblerX86<Assembler>::ResolveJumps() {
 
 // Code size optimized instructions: they have different variants depending on registers used.
 
-template <typename Assembler>
-inline void AssemblerX86<Assembler>::Xchgl(Register dest, Register src) {
-  if (Assembler::IsAccumulator(src) || Assembler::IsAccumulator(dest)) {
-    Register other = Assembler::IsAccumulator(src) ? dest : src;
-    EmitInstruction<Opcodes<0x90>>(Register32Bit(other));
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Xchgl(Register dest, Register src) {
+  if (DerivedAssemblerType::IsAccumulator(src) || DerivedAssemblerType::IsAccumulator(dest)) {
+    Register other = DerivedAssemblerType::IsAccumulator(src) ? dest : src;
+    EmitInstruction<0x90>(Register32Bit(other));
   } else {
     // Clang 8 (after r330298) puts dest before src.  We are comparing output
     // to clang in exhaustive test thus we want to match clang behavior exactly.
-    EmitInstruction<Opcodes<0x87>>(Register32Bit(dest), Register32Bit(src));
+    EmitInstruction<0x87>(Register32Bit(dest), Register32Bit(src));
   }
 }
 
+}  // namespace x86_32_and_x86_64
+
 }  // namespace berberis
 
-#endif  // BERBERIS_ASSEMBLER_COMMON_X86_H_
+#endif  // BERBERIS_ASSEMBLER_X86_32_AND_X86_64_H_
diff --git a/assembler/include/berberis/assembler/x86_64.h b/assembler/include/berberis/assembler/x86_64.h
index c66cc1c7..64560698 100644
--- a/assembler/include/berberis/assembler/x86_64.h
+++ b/assembler/include/berberis/assembler/x86_64.h
@@ -21,9 +21,8 @@
 
 #include <type_traits>  // std::is_same
 
-#include "berberis/assembler/common_x86.h"
+#include "berberis/assembler/x86_32_and_x86_64.h"
 #include "berberis/base/logging.h"
-#include "berberis/base/macros.h"  // DISALLOW_IMPLICIT_CONSTRUCTORS
 
 namespace berberis {
 
@@ -31,9 +30,12 @@ class MachindeCode;
 
 namespace x86_64 {
 
-class Assembler : public AssemblerX86<Assembler> {
+class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
  public:
-  explicit Assembler(MachineCode* code) : AssemblerX86(code) {}
+  using BaseAssembler = x86_32_and_x86_64::Assembler<Assembler>;
+  using FinalAssembler = Assembler;
+
+  explicit Assembler(MachineCode* code) : BaseAssembler(code) {}
 
   static constexpr Register no_register{0x80};
   static constexpr Register rax{0};
@@ -86,31 +88,31 @@ class Assembler : public AssemblerX86<Assembler> {
   // the same.
 
   // Unhide Decl(Mem) hidden by Decl(Reg).
-  using AssemblerX86::Decl;
+  using BaseAssembler::Decl;
 
   // Unhide Decw(Mem) hidden by Decw(Reg).
-  using AssemblerX86::Decw;
+  using BaseAssembler::Decw;
 
   // Unhide Incl(Mem) hidden by Incl(Reg).
-  using AssemblerX86::Incl;
+  using BaseAssembler::Incl;
 
   // Unhide Incw(Mem) hidden by Incw(Reg).
-  using AssemblerX86::Incw;
+  using BaseAssembler::Incw;
 
   // Unhide Movq(Mem, XMMReg) and Movq(XMMReg, Mem) hidden by Movq(Reg, Imm) and many others.
-  using AssemblerX86::Movq;
+  using BaseAssembler::Movq;
 
   // Unhide Xchgl(Mem, Reg) hidden by modified version below.
-  using AssemblerX86::Xchgl;
+  using BaseAssembler::Xchgl;
 
   // Unhide Vmov*(Mem, Reg) hidden by Vmov*(Reg, Reg).
-  using AssemblerX86::Vmovapd;
-  using AssemblerX86::Vmovaps;
-  using AssemblerX86::Vmovdqa;
-  using AssemblerX86::Vmovdqu;
-  using AssemblerX86::Vmovq;
-  using AssemblerX86::Vmovsd;
-  using AssemblerX86::Vmovss;
+  using BaseAssembler::Vmovapd;
+  using BaseAssembler::Vmovaps;
+  using BaseAssembler::Vmovdqa;
+  using BaseAssembler::Vmovdqu;
+  using BaseAssembler::Vmovq;
+  using BaseAssembler::Vmovsd;
+  using BaseAssembler::Vmovss;
 
   void Xchgl(Register dest, Register src) {
     // In 32-bit mode "xchgl %eax, %eax" did nothing and was often reused as "nop".
@@ -122,7 +124,7 @@ class Assembler : public AssemblerX86<Assembler> {
     if (IsAccumulator(src) && IsAccumulator(dest)) {
       Emit16(0xc087);
     } else {
-      AssemblerX86::Xchgl(dest, src);
+      BaseAssembler::Xchgl(dest, src);
     }
   }
 
@@ -131,7 +133,7 @@ class Assembler : public AssemblerX86<Assembler> {
 #ifdef __amd64__
 
   // Unhide Call(Reg), hidden by special version below.
-  using AssemblerX86::Call;
+  using BaseAssembler::Call;
 
   void Call(const void* target) {
     // There are no call instruction with properties we need thus we emulate it.
@@ -147,7 +149,7 @@ class Assembler : public AssemblerX86<Assembler> {
   }
 
   // Unhide Jcc(Label), hidden by special version below.
-  using AssemblerX86::Jcc;
+  using BaseAssembler::Jcc;
 
   // Make sure only type void* can be passed to function below, not Label* or any other type.
   template <typename T>
@@ -175,7 +177,7 @@ class Assembler : public AssemblerX86<Assembler> {
   }
 
   // Unhide Jmp(Reg), hidden by special version below.
-  using AssemblerX86::Jmp;
+  using BaseAssembler::Jmp;
 
   // Make sure only type void* can be passed to function below, not Label* or any other type.
   template <typename T>
@@ -197,14 +199,19 @@ class Assembler : public AssemblerX86<Assembler> {
 #endif
 
  private:
-  DISALLOW_IMPLICIT_CONSTRUCTORS(Assembler);
+  Assembler() = delete;
+  Assembler(const Assembler&) = delete;
+  Assembler(Assembler&&) = delete;
+  void operator=(const Assembler&) = delete;
+  void operator=(Assembler&&) = delete;
+  using DerivedAssemblerType = Assembler;
 
   static Register Accumulator() { return rax; }
   static bool IsAccumulator(Register reg) { return reg == rax; }
 
   struct Register64Bit {
-    explicit constexpr Register64Bit(Register reg) : num(reg.num) {}
-    uint8_t num;
+    explicit constexpr Register64Bit(Register reg) : num_(reg.num_) {}
+    uint8_t num_;
   };
 
   struct Memory64Bit {
@@ -267,7 +274,7 @@ class Assembler : public AssemblerX86<Assembler> {
 
   template <uint8_t base_rex, typename ArgumentType>
   uint8_t Rex(ArgumentType argument) {
-    if (argument.num & 0b1000) {
+    if (argument.num_ & 0b1000) {
       // 64-bit argument requires REX.W bit
       if (std::is_same_v<ArgumentType, Register64Bit>) {
         return 0b0100'1000 | base_rex;
@@ -275,7 +282,7 @@ class Assembler : public AssemblerX86<Assembler> {
       return 0b0100'0000 | base_rex;
     }
     // 8-bit argument requires REX (even if without any bits).
-    if (std::is_same_v<ArgumentType, Register8Bit> && argument.num > 3) {
+    if (std::is_same_v<ArgumentType, Register8Bit> && argument.num_ > 3) {
       return 0b0100'0000;
     }
     if (std::is_same_v<ArgumentType, Register64Bit>) {
@@ -286,7 +293,7 @@ class Assembler : public AssemblerX86<Assembler> {
 
   uint8_t Rex(Operand operand) {
     // REX.B and REX.X always come from operand.
-    uint8_t rex = ((operand.base.num & 0b1000) >> 3) | ((operand.index.num & 0b1000) >> 2);
+    uint8_t rex = ((operand.base.num_ & 0b1000) >> 3) | ((operand.index.num_ & 0b1000) >> 2);
     if (rex) {
       // We actually need rex byte here.
       return 0b0100'0000 | rex;
@@ -306,7 +313,7 @@ class Assembler : public AssemblerX86<Assembler> {
   [[nodiscard]] static bool IsSwapProfitable(RegisterType rm_arg, RegisterType vex_arg) {
     // In 64bit mode we may use more compact encoding if operand encoded in rm is low register.
     // Return true if we may achieve that by swapping arguments.
-    return rm_arg.num >= 8 && vex_arg.num < 8;
+    return rm_arg.num_ >= 8 && vex_arg.num_ < 8;
   }
 
   template <uint8_t byte1,
@@ -321,26 +328,26 @@ class Assembler : public AssemblerX86<Assembler> {
     constexpr auto vvvv_parameter = 2 - reg_is_opcode_extension - operands_count - labels_count;
     int vvvv = 0;
     if constexpr (registers_count > vvvv_parameter) {
-      vvvv = ArgumentByType<vvvv_parameter, IsRegister>(arguments...).num;
+      vvvv = ArgumentByType<vvvv_parameter, IsRegister>(arguments...).num_;
     }
     auto vex2 = byte2 | 0b111'00000;
     if constexpr (operands_count == 1) {
       auto operand = ArgumentByType<0, IsMemoryOperand>(arguments...);
-      vex2 ^= (operand.operand.base.num & 0b1000) << 2;
-      vex2 ^= (operand.operand.index.num & 0b1000) << 3;
+      vex2 ^= (operand.operand.base.num_ & 0b1000) << 2;
+      vex2 ^= (operand.operand.index.num_ & 0b1000) << 3;
       if constexpr (!reg_is_opcode_extension) {
-        vex2 ^= (ArgumentByType<0, IsRegister>(arguments...).num & 0b1000) << 4;
+        vex2 ^= (ArgumentByType<0, IsRegister>(arguments...).num_ & 0b1000) << 4;
       }
     } else if constexpr (labels_count == 1) {
       if constexpr (!reg_is_opcode_extension) {
-        vex2 ^= (ArgumentByType<0, IsRegister>(arguments...).num & 0b1000) << 4;
+        vex2 ^= (ArgumentByType<0, IsRegister>(arguments...).num_ & 0b1000) << 4;
       }
     } else if constexpr (registers_count > 0) {
       if constexpr (reg_is_opcode_extension) {
-        vex2 ^= (ArgumentByType<0, IsRegister>(arguments...).num & 0b1000) << 2;
+        vex2 ^= (ArgumentByType<0, IsRegister>(arguments...).num_ & 0b1000) << 2;
       } else {
-        vex2 ^= (ArgumentByType<0, IsRegister>(arguments...).num & 0b1000) << 4;
-        vex2 ^= (ArgumentByType<1, IsRegister>(arguments...).num & 0b1000) << 2;
+        vex2 ^= (ArgumentByType<0, IsRegister>(arguments...).num_ & 0b1000) << 4;
+        vex2 ^= (ArgumentByType<1, IsRegister>(arguments...).num_ & 0b1000) << 2;
       }
     }
     if (byte1 == 0xC4 && (vex2 & 0b0'1'1'11111) == 0b0'1'1'00001 && (byte3 & 0b1'0000'0'00) == 0) {
@@ -354,34 +361,34 @@ class Assembler : public AssemblerX86<Assembler> {
 
   template <typename ArgumentType>
   void EmitRegisterInOpcode(uint8_t opcode, ArgumentType argument) {
-    Emit8(opcode | (argument.num & 0b111));
+    Emit8(opcode | (argument.num_ & 0b111));
   }
 
   template <typename ArgumentType1, typename ArgumentType2>
   void EmitModRM(ArgumentType1 argument1, ArgumentType2 argument2) {
-    Emit8(0xC0 | ((argument1.num & 0b111) << 3) | (argument2.num & 0b111));
+    Emit8(0xC0 | ((argument1.num_ & 0b111) << 3) | (argument2.num_ & 0b111));
   }
 
   template <typename ArgumentType>
   void EmitModRM(uint8_t opcode_extension, ArgumentType argument) {
     CHECK_LE(opcode_extension, 0b111);
-    Emit8(0xC0 | (opcode_extension << 3) | (argument.num & 0b111));
+    Emit8(0xC0 | (opcode_extension << 3) | (argument.num_ & 0b111));
   }
 
   template <typename ArgumentType>
   void EmitOperandOp(ArgumentType argument, Operand operand) {
-    EmitOperandOp(static_cast<int>(argument.num & 0b111), operand);
+    EmitOperandOp(static_cast<int>(argument.num_ & 0b111), operand);
   }
 
   template <size_t kImmediatesSize, typename ArgumentType>
   void EmitRipOp(ArgumentType argument, const Label& label) {
-    EmitRipOp<kImmediatesSize>(static_cast<int>(argument.num) & 0b111, label);
+    EmitRipOp<kImmediatesSize>(static_cast<int>(argument.num_) & 0b111, label);
   }
 
   // Emit the ModR/M byte, and optionally the SIB byte and
   // 1- or 4-byte offset for a memory operand.  Also used to encode
   // a three-bit opcode extension into the ModR/M byte.
-  void EmitOperandOp(int number, const Operand& addr);
+  void EmitOperandOp(int num_ber, const Operand& addr);
   // Helper functions to handle various ModR/M and SIB combinations.
   // Should *only* be called from EmitOperandOp!
   void EmitIndexDispOperand(int reg, const Operand& addr);
@@ -389,9 +396,9 @@ class Assembler : public AssemblerX86<Assembler> {
   void EmitBaseIndexDispOperand(int base_modrm_and_sib, const Operand& addr);
   // Emit ModR/M for rip-addressig.
   template <size_t kImmediatesSize>
-  void EmitRipOp(int num, const Label& label);
+  void EmitRipOp(int num_, const Label& label);
 
-  friend AssemblerX86<Assembler>;
+  friend BaseAssembler;
 };
 
 // This function looks big, but when we are emitting Operand with fixed registers
@@ -399,12 +406,12 @@ class Assembler : public AssemblerX86<Assembler> {
 // makes effective size of that function very small.
 //
 // But for this to happen function have to be inline and in header.
-inline void Assembler::EmitOperandOp(int number, const Operand& addr) {
-  // Additional info (register number, etc) is limited to 3 bits.
-  CHECK_LE(unsigned(number), 7);
+inline void Assembler::EmitOperandOp(int num_ber, const Operand& addr) {
+  // Additional info (register num_ber, etc) is limited to 3 bits.
+  CHECK_LE(unsigned(num_ber), 7);
 
   // Reg field must be shifted by 3 bits.
-  int reg = number << 3;
+  int reg = num_ber << 3;
 
   // On x86 %rsp cannot be index, only base.
   CHECK(addr.index != rsp);
@@ -414,7 +421,7 @@ inline void Assembler::EmitOperandOp(int number, const Operand& addr) {
   if (addr.base != rsp && addr.base != r12 && addr.index == no_register) {
     // If we have base register then we could use the same logic as for other common cases.
     if (addr.base != no_register) {
-      EmitBaseIndexDispOperand<uint8_t, &Assembler::Emit8>((addr.base.num & 7) | reg, addr);
+      EmitBaseIndexDispOperand<uint8_t, &Assembler::Emit8>((addr.base.num_ & 7) | reg, addr);
     } else {
       Emit16(0x2504 | reg);
       Emit32(addr.disp);
@@ -422,26 +429,27 @@ inline void Assembler::EmitOperandOp(int number, const Operand& addr) {
   } else if (addr.index == no_register) {
     // Note: when ModR/M and SIB are used "no index" is encoded as if %rsp is used in place of
     // index (that's why %rsp couldn't be used as index - see check above).
-    EmitBaseIndexDispOperand<int16_t, &Assembler::Emit16>(0x2004 | ((addr.base.num & 7) << 8) | reg,
-                                                          addr);
+    EmitBaseIndexDispOperand<int16_t, &Assembler::Emit16>(
+        0x2004 | ((addr.base.num_ & 7) << 8) | reg, addr);
   } else if (addr.base == no_register) {
     EmitIndexDispOperand(reg, addr);
   } else {
-    EmitBaseIndexDispOperand<int16_t, &Assembler::Emit16>(
-        0x04 | (addr.scale << 14) | ((addr.index.num & 7) << 11) | ((addr.base.num & 7) << 8) | reg,
-        addr);
+    EmitBaseIndexDispOperand<int16_t, &Assembler::Emit16>(0x04 | (addr.scale << 14) |
+                                                              ((addr.index.num_ & 7) << 11) |
+                                                              ((addr.base.num_ & 7) << 8) | reg,
+                                                          addr);
   }
 }
 
 inline void Assembler::EmitIndexDispOperand(int reg, const Operand& addr) {
   // We only have index here, no base, use SIB but put %rbp in "base" field.
-  Emit16(0x0504 | (addr.scale << 14) | ((addr.index.num & 7) << 11) | reg);
+  Emit16(0x0504 | (addr.scale << 14) | ((addr.index.num_ & 7) << 11) | reg);
   Emit32(addr.disp);
 }
 
 template <size_t kImmediatesSize>
-inline void Assembler::EmitRipOp(int num, const Label& label) {
-  Emit8(0x05 | (num << 3));
+inline void Assembler::EmitRipOp(int num_, const Label& label) {
+  Emit8(0x05 | (num_ << 3));
   jumps_.push_back(Jump{&label, pc(), false});
   Emit32(0xfffffffc - kImmediatesSize);
 }
@@ -468,64 +476,60 @@ inline void Assembler::Movq(Register dest, int64_t imm64) {
     Movl(dest, static_cast<uint32_t>(imm64));
   } else if (IsInRange<int32_t>(imm64)) {
     // Slightly longer encoding.
-    EmitInstruction<Opcodes<0xc7, 0x00>>(Register64Bit(dest), static_cast<int32_t>(imm64));
+    EmitInstruction<0xc7, 0x00>(Register64Bit(dest), static_cast<int32_t>(imm64));
   } else {
     // Longest encoding.
-    EmitInstruction<Opcodes<0xb8>>(Register64Bit(dest), imm64);
+    EmitInstruction<0xb8>(Register64Bit(dest), imm64);
   }
 }
 
 inline void Assembler::Vmovapd(XMMRegister arg0, XMMRegister arg1) {
-  if (arg0.num < 8 && arg1.num >= 8) {
-    return EmitInstruction<Opcodes<0xc4, 0x01, 0x01, 0x29>>(VectorRegister128Bit(arg1),
-                                                            VectorRegister128Bit(arg0));
+  if (arg0.num_ < 8 && arg1.num_ >= 8) {
+    return EmitInstruction<0xc4, 0x01, 0x01, 0x29>(VectorRegister128Bit(arg1),
+                                                   VectorRegister128Bit(arg0));
   }
-  EmitInstruction<Opcodes<0xc4, 0x01, 0x01, 0x28>>(VectorRegister128Bit(arg0),
-                                                   VectorRegister128Bit(arg1));
+  EmitInstruction<0xc4, 0x01, 0x01, 0x28>(VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
 }
 
 inline void Assembler::Vmovaps(XMMRegister arg0, XMMRegister arg1) {
-  if (arg0.num < 8 && arg1.num >= 8) {
-    return EmitInstruction<Opcodes<0xc4, 0x01, 0x00, 0x29>>(VectorRegister128Bit(arg1),
-                                                            VectorRegister128Bit(arg0));
+  if (arg0.num_ < 8 && arg1.num_ >= 8) {
+    return EmitInstruction<0xc4, 0x01, 0x00, 0x29>(VectorRegister128Bit(arg1),
+                                                   VectorRegister128Bit(arg0));
   }
-  EmitInstruction<Opcodes<0xc4, 0x01, 0x00, 0x28>>(VectorRegister128Bit(arg0),
-                                                   VectorRegister128Bit(arg1));
+  EmitInstruction<0xc4, 0x01, 0x00, 0x28>(VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
 }
 
 inline void Assembler::Vmovdqa(XMMRegister arg0, XMMRegister arg1) {
-  if (arg0.num < 8 && arg1.num >= 8) {
-    return EmitInstruction<Opcodes<0xc4, 0x01, 0x01, 0x7F>>(VectorRegister128Bit(arg1),
-                                                            VectorRegister128Bit(arg0));
+  if (arg0.num_ < 8 && arg1.num_ >= 8) {
+    return EmitInstruction<0xc4, 0x01, 0x01, 0x7F>(VectorRegister128Bit(arg1),
+                                                   VectorRegister128Bit(arg0));
   }
-  EmitInstruction<Opcodes<0xc4, 0x01, 0x01, 0x6F>>(VectorRegister128Bit(arg0),
-                                                   VectorRegister128Bit(arg1));
+  EmitInstruction<0xc4, 0x01, 0x01, 0x6F>(VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
 }
 
 inline void Assembler::Vmovdqu(XMMRegister arg0, XMMRegister arg1) {
-  if (arg0.num < 8 && arg1.num >= 8) {
-    return EmitInstruction<Opcodes<0xc4, 0x01, 0x02, 0x7F>>(VectorRegister128Bit(arg1),
-                                                            VectorRegister128Bit(arg0));
+  if (arg0.num_ < 8 && arg1.num_ >= 8) {
+    return EmitInstruction<0xc4, 0x01, 0x02, 0x7F>(VectorRegister128Bit(arg1),
+                                                   VectorRegister128Bit(arg0));
   }
-  EmitInstruction<Opcodes<0xc4, 0x01, 0x02, 0x6F>>(VectorRegister128Bit(arg0),
-                                                   VectorRegister128Bit(arg1));
+  EmitInstruction<0xc4, 0x01, 0x02, 0x6F>(VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
 }
 
 inline void Assembler::Vmovsd(XMMRegister arg0, XMMRegister arg1, XMMRegister arg2) {
-  if (arg0.num < 8 && arg2.num >= 8) {
-    return EmitInstruction<Opcodes<0xc4, 0x01, 0x03, 0x11>>(
+  if (arg0.num_ < 8 && arg2.num_ >= 8) {
+    return EmitInstruction<0xc4, 0x01, 0x03, 0x11>(
         VectorRegister128Bit(arg2), VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
   }
-  EmitInstruction<Opcodes<0xc4, 0x01, 0x03, 0x10>>(
+  EmitInstruction<0xc4, 0x01, 0x03, 0x10>(
       VectorRegister128Bit(arg0), VectorRegister128Bit(arg2), VectorRegister128Bit(arg1));
 }
 
 inline void Assembler::Vmovss(XMMRegister arg0, XMMRegister arg1, XMMRegister arg2) {
-  if (arg0.num < 8 && arg2.num >= 8) {
-    return EmitInstruction<Opcodes<0xc4, 0x01, 0x02, 0x11>>(
+  if (arg0.num_ < 8 && arg2.num_ >= 8) {
+    return EmitInstruction<0xc4, 0x01, 0x02, 0x11>(
         VectorRegister128Bit(arg2), VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
   }
-  EmitInstruction<Opcodes<0xc4, 0x01, 0x02, 0x10>>(
+  EmitInstruction<0xc4, 0x01, 0x02, 0x10>(
       VectorRegister128Bit(arg0), VectorRegister128Bit(arg2), VectorRegister128Bit(arg1));
 }
 
@@ -537,11 +541,11 @@ inline void Assembler::Xchgq(Register dest, Register src) {
     Emit8(0x90);
   } else if (IsAccumulator(src) || IsAccumulator(dest)) {
     Register other = IsAccumulator(src) ? dest : src;
-    EmitInstruction<Opcodes<0x90>>(Register64Bit(other));
+    EmitInstruction<0x90>(Register64Bit(other));
   } else {
   // Clang 8 (after r330298) puts dest before src.  We are comparing output
   // to clang in exhaustive test thus we want to match clang behavior exactly.
-    EmitInstruction<Opcodes<0x87>>(Register64Bit(dest), Register64Bit(src));
+  EmitInstruction<0x87>(Register64Bit(dest), Register64Bit(src));
   }
 }
 
diff --git a/assembler/instructions/insn_def_riscv.json b/assembler/instructions/insn_def_riscv.json
new file mode 100644
index 00000000..0fd186bf
--- /dev/null
+++ b/assembler/instructions/insn_def_riscv.json
@@ -0,0 +1,347 @@
+{
+  "License": [
+    "Copyright (C) 2024 The Android Open Source Project",
+    "",
+    "Licensed under the Apache License, Version 2.0 (the “License”);",
+    "you may not use this file except in compliance with the License.",
+    "You may obtain a copy of the License at",
+    "",
+    "     http://www.apache.org/licenses/LICENSE-2.0",
+    "",
+    "Unless required by applicable law or agreed to in writing, software",
+    "distributed under the License is distributed on an “AS IS” BASIS,",
+    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
+    "See the License for the specific language governing permissions and",
+    "limitations under the License."
+  ],
+  "arch": "common_riscv",
+  "insns": [
+    {
+      "encodings": {
+        "auipc": { "opcode": "0000_0017", "type": "U-Type" },
+        "lui": { "opcode": "0000_0017", "type": "U-Type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "U-Imm" }
+      ]
+    },
+    {
+      "encodings": {
+        "add": { "opcode": "0000_0033", "type": "R-type" },
+        "and": { "opcode": "0000_7033", "type": "R-type" },
+        "div": { "opcode": "0200_4033", "type": "R-type" },
+        "divu": { "opcode": "0200_5033", "type": "R-type" },
+        "mul": { "opcode": "0200_0033", "type": "R-type" },
+        "mulh": { "opcode": "0200_1033", "type": "R-type" },
+        "mulhsu": { "opcode": "0200_2033", "type": "R-type" },
+        "mulhu": { "opcode": "0200_3033", "type": "R-type" },
+        "or": { "opcode": "0000_6033", "type": "R-type" },
+        "rem": { "opcode": "0200_6033", "type": "R-type" },
+        "remu": { "opcode": "0200_7033", "type": "R-type" },
+        "sll": { "opcode": "0000_1033", "type": "R-type" },
+        "slt": { "opcode": "0000_2033", "type": "R-type" },
+        "sltu": { "opcode": "0000_3033", "type": "R-type" },
+        "sra": { "opcode": "4000_5033", "type": "R-type" },
+        "sraw": { "opcode": "4000_503b", "type": "R-type" },
+        "srl": { "opcode": "0000_5033", "type": "R-type" },
+        "srlw": { "opcode": "0000_503b", "type": "R-type" },
+        "sub": { "opcode": "4000_0033", "type": "R-type" },
+        "xor": { "opcode": "0000_4033", "type": "R-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "addi": { "opcode": "0000_0013", "type": "I-type" },
+        "andi": { "opcode": "0000_7013", "type": "I-type" },
+        "jalr": { "opcode": "0000_0067", "type": "I-type" },
+        "ori": { "opcode": "0000_6013", "type": "I-type" },
+        "slti": { "opcode": "0000_2013", "type": "I-type" },
+        "sltiu": { "opcode": "0000_3013", "type": "I-type" },
+        "xori": { "opcode": "0000_4013", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "I-Imm" }
+      ]
+    },
+    {
+      "stems": [ "bcc" ],
+      "args": [
+        { "class": "Cond" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "B-Imm" }
+      ]
+    },
+    {
+      "stems": [ "bcc" ],
+      "args": [
+        { "class": "Cond" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Label" }
+      ]
+    },
+    {
+      "encodings": {
+         "beq": { "opcode": "0000_0063", "type": "B-Type" },
+         "bge": { "opcode": "0000_5063", "type": "B-Type" },
+         "bgeu": { "opcode": "0000_7063", "type": "B-Type" },
+         "blt": { "opcode": "0000_4063", "type": "B-Type" },
+         "bltu": { "opcode": "0000_6063", "type": "B-Type" },
+         "bne": { "opcode": "0000_1063", "type": "B-Type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "B-Imm" }
+      ]
+    },
+    {
+      "stems": [ "beq", "bge", "bgeu", "blt", "bltu", "bne" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Label" }
+      ]
+    },
+    {
+      "encodings": {
+        "csrrc": { "opcode": "0000_3073", "type": "I-type" },
+        "csrrs": { "opcode": "0000_2073", "type": "I-type" },
+        "csrrw": { "opcode": "0000_1073", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "CsrReg", "usage": "use_def" },
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "csrrc": { "opcode": "0000_7073", "type": "I-type" },
+        "csrrci": { "opcode": "0000_7073", "type": "I-type" },
+        "csrrs": { "opcode": "0000_6073", "type": "I-type" },
+        "csrrsi": { "opcode": "0000_6073", "type": "I-type" },
+        "csrrw": { "opcode": "0000_5073", "type": "I-type" },
+        "csrrwi": { "opcode": "0000_5073", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "CsrReg", "usage": "use_def" },
+        { "class": "Csr-Imm" }
+      ]
+    },
+    {
+      "encodings": {
+        "fcvt.d.s": { "opcode": "4200_0053", "type": "R-type" },
+        "fcvt.s.d": { "opcode": "4010_0053", "type": "R-type" },
+        "fsqrt.s": { "opcode": "5800_0053", "type": "R-type" },
+        "fsqrt.d": { "opcode": "5a00_0053", "type": "R-type" }
+      },
+      "args": [
+        { "class": "FpReg", "usage": "def" },
+        { "class": "FpReg", "usage": "use" },
+        { "class": "Rm", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "fcvt.d.w": { "opcode": "d200_0053", "type": "R-type" },
+        "fcvt.d.wu": { "opcode": "d210_0053", "type": "R-type" },
+        "fcvt.s.w": { "opcode": "d000_0053", "type": "R-type" },
+        "fcvt.s.wu": { "opcode": "d010_0053", "type": "R-type" }
+      },
+      "args": [
+        { "class": "FpReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Rm", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "fcvt.w.d": { "opcode": "c200_0053", "type": "R-type" },
+        "fcvt.wu.d": { "opcode": "c210_0053", "type": "R-type" },
+        "fcvt.w.s": { "opcode": "c000_0053", "type": "R-type" },
+        "fcvt.wu.s": { "opcode": "c010_0053", "type": "R-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "FpReg", "usage": "use" },
+        { "class": "Rm", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "fld": { "opcode": "0000_3007", "type": "I-type" }
+      },
+      "args": [
+        { "class": "FpReg", "usage": "def" },
+        { "class": "Mem64", "usage": "use" }
+      ]
+    },
+    {
+      "stems": [ "fld", "flw" ],
+      "args": [
+        { "class": "FpReg", "usage": "def" },
+        { "class": "Label" },
+        { "class": "GeneralReg", "usage": "def" }
+      ]
+    },
+    {
+      "encodings": {
+        "flw": { "opcode": "0000_2007", "type": "I-type" }
+      },
+      "args": [
+        { "class": "FpReg", "usage": "def" },
+        { "class": "Mem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "fsd": { "opcode": "0000_3027", "type": "S-type" }
+      },
+      "args": [
+        { "class": "FpReg", "usage": "use" },
+        { "class": "Mem64", "usage": "def" }
+      ]
+    },
+    {
+      "stems": [ "fsd", "fsw" ],
+      "args": [
+        { "class": "FpReg", "usage": "use" },
+        { "class": "Label" },
+        { "class": "GeneralReg", "usage": "def" }
+      ]
+    },
+    {
+      "encodings": {
+        "fsw": { "opcode": "0000_2027", "type": "S-type" }
+      },
+      "args": [
+        { "class": "FpReg", "usage": "use" },
+        { "class": "Mem32", "usage": "def" }
+      ]
+    },
+    {
+      "encodings": {
+        "jal": { "opcode": "0000_006f", "type": "J-Type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "J-Imm" }
+      ]
+    },
+    {
+      "stems": [ "jal" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Label" }
+      ]
+    },
+    {
+      "encodings": {
+        "jalr": { "opcode": "0000_0067", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Mem", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "lb": { "opcode": "0000_0003", "type": "I-type" },
+        "lbu": { "opcode": "0000_4003", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Mem8", "usage": "use" }
+      ]
+    },
+    {
+      "stems": [ "lb", "lbu", "lh", "lhu", "lla", "lw" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Label" }
+      ]
+    },
+    {
+      "encodings": {
+        "lh": { "opcode": "0000_1003", "type": "I-type" },
+        "lhu": { "opcode": "0000_5003", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Mem16", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "lw": { "opcode": "0000_2003", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Mem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "prefetch.i": { "opcode": "0000_6013", "type": "P-type" },
+        "prefetch.r": { "opcode": "0010_6013", "type": "P-type" },
+        "prefetch.w": { "opcode": "0030_6013", "type": "P-type" }
+      },
+      "args": [
+        { "class": "Mem", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "sb": { "opcode": "0000_0023", "type": "S-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Mem8", "usage": "def" }
+      ]
+    },
+    {
+      "stems": [ "sb", "sh", "sw" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Label" },
+        { "class": "GeneralReg", "usage": "def" }
+      ]
+    },
+    {
+      "encodings": {
+        "sh": { "opcode": "0000_1023", "type": "S-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Mem16", "usage": "def" }
+      ]
+    },
+    {
+      "encodings": {
+        "sw": { "opcode": "0000_2023", "type": "S-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Mem32", "usage": "def" }
+      ]
+    },
+    {
+      "stems": [ "mv" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    }
+  ]
+}
diff --git a/assembler/instructions/insn_def_rv32.json b/assembler/instructions/insn_def_rv32.json
new file mode 100644
index 00000000..96a6cd5b
--- /dev/null
+++ b/assembler/instructions/insn_def_rv32.json
@@ -0,0 +1,32 @@
+{
+  "License": [
+    "Copyright (C) 2024 The Android Open Source Project",
+    "",
+    "Licensed under the Apache License, Version 2.0 (the “License”);",
+    "you may not use this file except in compliance with the License.",
+    "You may obtain a copy of the License at",
+    "",
+    "     http://www.apache.org/licenses/LICENSE-2.0",
+    "",
+    "Unless required by applicable law or agreed to in writing, software",
+    "distributed under the License is distributed on an “AS IS” BASIS,",
+    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
+    "See the License for the specific language governing permissions and",
+    "limitations under the License."
+  ],
+  "arch": "rv32",
+  "insns": [
+    {
+      "encodings": {
+        "slli": { "opcode": "0000_1013", "type": "I-type" },
+        "srai": { "opcode": "4000_5013", "type": "I-type" },
+        "srli": { "opcode": "0000_5013", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Shift32-Imm" }
+      ]
+    }
+  ]
+}
diff --git a/assembler/instructions/insn_def_rv64.json b/assembler/instructions/insn_def_rv64.json
new file mode 100644
index 00000000..fdee9578
--- /dev/null
+++ b/assembler/instructions/insn_def_rv64.json
@@ -0,0 +1,139 @@
+{
+  "License": [
+    "Copyright (C) 2024 The Android Open Source Project",
+    "",
+    "Licensed under the Apache License, Version 2.0 (the “License”);",
+    "you may not use this file except in compliance with the License.",
+    "You may obtain a copy of the License at",
+    "",
+    "     http://www.apache.org/licenses/LICENSE-2.0",
+    "",
+    "Unless required by applicable law or agreed to in writing, software",
+    "distributed under the License is distributed on an “AS IS” BASIS,",
+    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
+    "See the License for the specific language governing permissions and",
+    "limitations under the License."
+  ],
+  "arch": "rv64",
+  "insns": [
+    {
+      "encodings": {
+        "addw": { "opcode": "0000_003b", "type": "R-type" },
+        "divuw": { "opcode": "0200_503b", "type": "R-type" },
+        "divw": { "opcode": "0200_403b", "type": "R-type" },
+        "mulw": { "opcode": "0200_003b", "type": "R-type" },
+        "remuw": { "opcode": "0200_703b", "type": "R-type" },
+        "remw": { "opcode": "0200_603b", "type": "R-type" },
+        "sllw": { "opcode": "0000_103b", "type": "R-type" },
+        "subw": { "opcode": "4000_003b", "type": "R-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "addiw": { "opcode": "0000_001b", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "I-Imm" }
+      ]
+    },
+    {
+      "encodings": {
+        "fcvt.d.l": { "opcode": "d220_0053", "type": "R-type" },
+        "fcvt.d.lu": { "opcode": "d230_0053", "type": "R-type" },
+        "fcvt.s.l": { "opcode": "d020_0053", "type": "R-type" },
+        "fcvt.s.lu": { "opcode": "d030_0053", "type": "R-type" }
+      },
+      "args": [
+        { "class": "FpReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Rm", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "fcvt.l.d": { "opcode": "c220_0053", "type": "R-type" },
+        "fcvt.lu.d": { "opcode": "c230_0053", "type": "R-type" },
+        "fcvt.l.s": { "opcode": "c020_0053", "type": "R-type" },
+        "fcvt.lu.s": { "opcode": "c030_0053", "type": "R-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "FpReg", "usage": "use" },
+        { "class": "Rm", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "ld": { "opcode": "0000_3003", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Mem64", "usage": "use" }
+      ]
+    },
+    {
+      "stems": [ "ld", "lwu" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Label" }
+      ]
+    },
+    {
+      "encodings": {
+        "lwu": { "opcode": "0000_6003", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Mem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "slli": { "opcode": "0000_1013", "type": "I-type" },
+        "srai": { "opcode": "4000_5013", "type": "I-type" },
+        "srli": { "opcode": "0000_5013", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Shift64-Imm" }
+      ]
+    },
+    {
+      "encodings": {
+        "slliw": { "opcode": "0000_101b", "type": "I-type" },
+        "sraiw": { "opcode": "4000_501b", "type": "I-type" },
+        "srliw": { "opcode": "0000_501b", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Shift32-Imm" }
+      ]
+    },
+    {
+      "encodings": {
+        "sd": { "opcode": "0000_3023", "type": "S-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Mem64", "usage": "def" }
+      ]
+    },
+    {
+      "stems": [ "sd" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Label" },
+        { "class": "GeneralReg", "usage": "def" }
+      ]
+    }
+  ]
+}
diff --git a/assembler/instructions/insn_def_x86.json b/assembler/instructions/insn_def_x86.json
index f892b698..084cb8bd 100644
--- a/assembler/instructions/insn_def_x86.json
+++ b/assembler/instructions/insn_def_x86.json
@@ -31,8 +31,8 @@
     },
     {
       "encodings": {
-        "Adcb": { "opcodes": [ "12" ] },
-        "Sbbb": { "opcodes": [ "1A" ] }
+        "Adcb": { "opcode": "12" },
+        "Sbbb": { "opcode": "1A" }
       },
       "args": [
         { "class": "GeneralReg8", "usage": "use_def" },
@@ -42,8 +42,8 @@
     },
     {
       "encodings": {
-        "Adcb": { "opcodes": [ "10" ], "reg_to_rm": true },
-        "Sbbb": { "opcodes": [ "18" ], "reg_to_rm": true }
+        "Adcb": { "opcode": "10", "type": "reg_to_rm" },
+        "Sbbb": { "opcode": "18", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg8/Mem8", "usage": "use_def" },
@@ -53,8 +53,8 @@
     },
     {
       "encodings": {
-        "AdcbAccumulator": { "opcodes": [ "14" ] },
-        "SbbbAccumulator": { "opcodes": [ "1C" ] }
+        "AdcbAccumulator": { "opcode": "14" },
+        "SbbbAccumulator": { "opcode": "1C" }
       },
       "args": [
         { "class": "AL", "usage": "use_def" },
@@ -64,8 +64,8 @@
     },
     {
       "encodings": {
-        "Adcl": { "opcodes": [ "13" ] },
-        "Sbbl": { "opcodes": [ "1B" ] }
+        "Adcl": { "opcode": "13" },
+        "Sbbl": { "opcode": "1B" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "use_def" },
@@ -86,8 +86,8 @@
     },
     {
       "encodings": {
-        "Adcl": { "opcodes": [ "11" ], "reg_to_rm": true },
-        "Sbbl": { "opcodes": [ "19" ], "reg_to_rm": true }
+        "Adcl": { "opcode": "11", "type": "reg_to_rm" },
+        "Sbbl": { "opcode": "19", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use_def" },
@@ -97,8 +97,8 @@
     },
     {
       "encodings": {
-        "AdclAccumulator": { "opcodes": [ "15" ] },
-        "SbblAccumulator": { "opcodes": [ "1D" ] }
+        "AdclAccumulator": { "opcode": "15" },
+        "SbblAccumulator": { "opcode": "1D" }
       },
       "args": [
         { "class": "EAX", "usage": "use_def" },
@@ -143,8 +143,8 @@
     },
     {
       "encodings": {
-        "Adcw": { "opcodes": [ "66", "11" ], "reg_to_rm": true },
-        "Sbbw": { "opcodes": [ "66", "19" ], "reg_to_rm": true }
+        "Adcw": { "opcodes": [ "66", "11" ], "type": "reg_to_rm" },
+        "Sbbw": { "opcodes": [ "66", "19" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg16/Mem16", "usage": "use_def" },
@@ -197,11 +197,11 @@
     },
     {
       "encodings": {
-        "Addb": { "opcodes": [ "02" ] },
-        "Andb": { "opcodes": [ "22" ] },
-        "Orb": { "opcodes": [ "0A" ] },
-        "Subb": { "opcodes": [ "2A" ] },
-        "Xorb": { "opcodes": [ "32" ] }
+        "Addb": { "opcode": "02" },
+        "Andb": { "opcode": "22" },
+        "Orb": { "opcode": "0A" },
+        "Subb": { "opcode": "2A" },
+        "Xorb": { "opcode": "32" }
       },
       "args": [
         { "class": "GeneralReg8", "usage": "use_def" },
@@ -211,11 +211,11 @@
     },
     {
       "encodings": {
-        "Addb": { "opcodes": [ "00" ], "reg_to_rm": true },
-        "Andb": { "opcodes": [ "20" ], "reg_to_rm": true },
-        "Orb": { "opcodes": [ "08" ], "reg_to_rm": true },
-        "Subb": { "opcodes": [ "28" ], "reg_to_rm": true },
-        "Xorb": { "opcodes": [ "30" ], "reg_to_rm": true }
+        "Addb": { "opcode": "00", "type": "reg_to_rm" },
+        "Andb": { "opcode": "20", "type": "reg_to_rm" },
+        "Orb": { "opcode": "08", "type": "reg_to_rm" },
+        "Subb": { "opcode": "28", "type": "reg_to_rm" },
+        "Xorb": { "opcode": "30", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg8/Mem8", "usage": "use_def" },
@@ -225,11 +225,11 @@
     },
     {
       "encodings": {
-        "AddbAccumulator": { "opcodes": [ "04" ] },
-        "AndbAccumulator": { "opcodes": [ "24" ] },
-        "OrbAccumulator": { "opcodes": [ "0C" ] },
-        "SubbAccumulator": { "opcodes": [ "2C" ] },
-        "XorbAccumulator": { "opcodes": [ "34" ] }
+        "AddbAccumulator": { "opcode": "04" },
+        "AndbAccumulator": { "opcode": "24" },
+        "OrbAccumulator": { "opcode": "0C" },
+        "SubbAccumulator": { "opcode": "2C" },
+        "XorbAccumulator": { "opcode": "34" }
       },
       "args": [
         { "class": "AL", "usage": "use_def" },
@@ -239,14 +239,14 @@
     },
     {
       "encodings": {
-        "Addl": { "opcodes": [ "01" ], "reg_to_rm": true },
-        "Andl": { "opcodes": [ "21" ], "reg_to_rm": true },
-        "Btcl": { "opcodes": [ "0F", "BB" ], "reg_to_rm": true },
-        "Btrl": { "opcodes": [ "0F", "B3" ], "reg_to_rm": true },
-        "Btsl": { "opcodes": [ "0F", "AB" ], "reg_to_rm": true },
-        "Orl": { "opcodes": [ "09" ], "reg_to_rm": true },
-        "Subl": { "opcodes": [ "29" ], "reg_to_rm": true },
-        "Xorl": { "opcodes": [ "31" ], "reg_to_rm": true }
+        "Addl": { "opcode": "01", "type": "reg_to_rm" },
+        "Andl": { "opcode": "21", "type": "reg_to_rm" },
+        "Btcl": { "opcodes": [ "0F", "BB" ], "type": "reg_to_rm" },
+        "Btrl": { "opcodes": [ "0F", "B3" ], "type": "reg_to_rm" },
+        "Btsl": { "opcodes": [ "0F", "AB" ], "type": "reg_to_rm" },
+        "Orl": { "opcode": "09", "type": "reg_to_rm" },
+        "Subl": { "opcode": "29", "type": "reg_to_rm" },
+        "Xorl": { "opcode": "31", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use_def" },
@@ -256,11 +256,11 @@
     },
     {
       "encodings": {
-        "Addl": { "opcodes": [ "03" ] },
-        "Andl": { "opcodes": [ "23" ] },
-        "Orl": { "opcodes": [ "0B" ] },
-        "Subl": { "opcodes": [ "2B" ] },
-        "Xorl": { "opcodes": [ "33" ] }
+        "Addl": { "opcode": "03" },
+        "Andl": { "opcode": "23" },
+        "Orl": { "opcode": "0B" },
+        "Subl": { "opcode": "2B" },
+        "Xorl": { "opcode": "33" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "use_def" },
@@ -284,11 +284,11 @@
     },
     {
       "encodings": {
-        "AddlAccumulator": { "opcodes": [ "05" ] },
-        "AndlAccumulator": { "opcodes": [ "25" ] },
-        "OrlAccumulator": { "opcodes": [ "0D" ] },
-        "SublAccumulator": { "opcodes": [ "2D" ] },
-        "XorlAccumulator": { "opcodes": [ "35" ] }
+        "AddlAccumulator": { "opcode": "05" },
+        "AndlAccumulator": { "opcode": "25" },
+        "OrlAccumulator": { "opcode": "0D" },
+        "SublAccumulator": { "opcode": "2D" },
+        "XorlAccumulator": { "opcode": "35" }
       },
       "args": [
         { "class": "EAX", "usage": "use_def" },
@@ -478,14 +478,14 @@
     },
     {
       "encodings": {
-        "Addw": { "opcodes": [ "66", "01" ], "reg_to_rm": true },
-        "Andw": { "opcodes": [ "66", "21" ], "reg_to_rm": true },
-        "Btcw": { "opcodes": [ "66", "0F", "BB" ], "reg_to_rm": true },
-        "Btrw": { "opcodes": [ "66", "0F", "B3" ], "reg_to_rm": true },
-        "Btsw": { "opcodes": [ "66", "0F", "AB" ], "reg_to_rm": true },
-        "Orw": { "opcodes": [ "66", "09" ], "reg_to_rm": true },
-        "Subw": { "opcodes": [ "66", "29" ], "reg_to_rm": true },
-        "Xorw": { "opcodes": [ "66", "31" ], "reg_to_rm": true }
+        "Addw": { "opcodes": [ "66", "01" ], "type": "reg_to_rm" },
+        "Andw": { "opcodes": [ "66", "21" ], "type": "reg_to_rm" },
+        "Btcw": { "opcodes": [ "66", "0F", "BB" ], "type": "reg_to_rm" },
+        "Btrw": { "opcodes": [ "66", "0F", "B3" ], "type": "reg_to_rm" },
+        "Btsw": { "opcodes": [ "66", "0F", "AB" ], "type": "reg_to_rm" },
+        "Orw": { "opcodes": [ "66", "09" ], "type": "reg_to_rm" },
+        "Subw": { "opcodes": [ "66", "29" ], "type": "reg_to_rm" },
+        "Xorw": { "opcodes": [ "66", "31" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg16/Mem16", "usage": "use_def" },
@@ -556,7 +556,7 @@
     },
     {
       "encodings": {
-        "Andnl": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F2" ], "vex_rm_to_reg": true }
+        "Andnl": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F2" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "def" },
@@ -579,9 +579,9 @@
     },
     {
       "encodings": {
-        "Blsil": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F3", "3" ], "rm_to_vex": true },
-        "Blsmskl": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F3", "2" ], "rm_to_vex": true },
-        "Blsrl": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F3", "1" ], "rm_to_vex": true },
+        "Blsil": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F3", "3" ], "type": "rm_to_vex" },
+        "Blsmskl": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F3", "2" ], "type": "rm_to_vex" },
+        "Blsrl": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F3", "1" ], "type": "rm_to_vex" },
         "Bsfl": { "opcodes": [ "0F", "BC" ] },
         "Bsrl": { "opcodes": [ "0F", "BD" ] },
         "Lzcntl": { "feature": "LZCNT", "opcodes": [ "F3", "0F", "BD" ] },
@@ -618,9 +618,9 @@
     },
     {
       "encodings": {
-        "Btl": { "opcodes": [ "0F", "A3" ], "reg_to_rm": true },
-        "Cmpl": { "opcodes": [ "39" ], "reg_to_rm": true },
-        "Testl": { "opcodes": [ "85" ], "reg_to_rm": true }
+        "Btl": { "opcodes": [ "0F", "A3" ], "type": "reg_to_rm" },
+        "Cmpl": { "opcode": "39", "type": "reg_to_rm" },
+        "Testl": { "opcode": "85", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use" },
@@ -630,9 +630,9 @@
     },
     {
       "encodings": {
-        "Btw": { "opcodes": [ "66", "0F", "A3" ], "reg_to_rm": true },
-        "Cmpw": { "opcodes": [ "66", "39" ], "reg_to_rm": true },
-        "Testw": { "opcodes": [ "66", "85" ], "reg_to_rm": true }
+        "Btw": { "opcodes": [ "66", "0F", "A3" ], "type": "reg_to_rm" },
+        "Cmpw": { "opcodes": [ "66", "39" ], "type": "reg_to_rm" },
+        "Testw": { "opcodes": [ "66", "85" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg16/Mem16", "usage": "use" },
@@ -643,7 +643,7 @@
     {
       "encodings": {
         "Call": { "opcodes": [ "FF", "02" ] },
-        "Push": { "opcodes": [ "50" ] }
+        "Push": { "opcode": "50" }
       },
       "args": [
         { "class": "RSP", "usage": "use_def" },
@@ -669,8 +669,8 @@
     },
     {
       "encodings": {
-        "Cdq": { "opcodes": [ "99" ] },
-        "Cltd": { "opcodes": [ "99" ] }
+        "Cdq": { "opcode": "99" },
+        "Cltd": { "opcode": "99" }
       },
       "args": [
         { "class": "EAX", "usage": "use" },
@@ -679,9 +679,9 @@
     },
     {
       "encodings": {
-        "Clc": { "opcodes": [ "F8" ] },
-        "Cmc": { "opcodes": [ "F5" ] },
-        "Stc": { "opcodes": [ "F9" ] }
+        "Clc": { "opcode": "F8" },
+        "Cmc": { "opcode": "F5" },
+        "Stc": { "opcode": "F9" }
       },
       "args": [
         { "class": "FLAGS", "usage": "use_def" }
@@ -712,7 +712,7 @@
     {
       "encodings": {
         "CmpXchg8b": { "opcodes": [ "0F", "C7", "1" ] },
-        "LockCmpXchg8b": { "opcodes": [ "F0", "0F", "C7", "1" ] }
+        "Lock CmpXchg8b": { "opcodes": [ "F0", "0F", "C7", "1" ] }
       },
       "args": [
         { "class": "EAX", "usage": "use_def" },
@@ -725,7 +725,7 @@
     },
     {
       "encodings": {
-        "CmpXchgl": { "opcodes": [ "0F", "B1" ], "reg_to_rm": true }
+        "CmpXchgl": { "opcodes": [ "0F", "B1" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "EAX", "usage": "use_def" },
@@ -747,8 +747,8 @@
     },
     {
       "encodings": {
-        "Cmpb": { "opcodes": [ "38" ], "reg_to_rm": true },
-        "Testb": { "opcodes": [ "84" ], "reg_to_rm": true }
+        "Cmpb": { "opcode": "38", "type": "reg_to_rm" },
+        "Testb": { "opcode": "84", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg8/Mem8", "usage": "use" },
@@ -758,7 +758,7 @@
     },
     {
       "encodings": {
-        "Cmpb": { "opcodes": [ "3A" ] }
+        "Cmpb": { "opcode": "3A" }
       },
       "args": [
         { "class": "GeneralReg8", "usage": "use" },
@@ -768,8 +768,8 @@
     },
     {
       "encodings": {
-        "CmpbAccumulator": { "opcodes": [ "3C" ] },
-        "TestbAccumulator": { "opcodes": [ "A8" ] }
+        "CmpbAccumulator": { "opcode": "3C" },
+        "TestbAccumulator": { "opcode": "A8" }
       },
       "args": [
         { "class": "AL", "usage": "use" },
@@ -790,7 +790,7 @@
     },
     {
       "encodings": {
-        "Cmpl": { "opcodes": [ "3B" ] }
+        "Cmpl": { "opcode": "3B" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "use" },
@@ -800,8 +800,8 @@
     },
     {
       "encodings": {
-        "CmplAccumulator": { "opcodes": [ "3D" ] },
-        "TestlAccumulator": { "opcodes": [ "A9" ] }
+        "CmplAccumulator": { "opcode": "3D" },
+        "TestlAccumulator": { "opcode": "A9" }
       },
       "args": [
         { "class": "EAX", "usage": "use" },
@@ -957,8 +957,8 @@
     },
     {
       "encodings": {
-        "Cwde": { "opcodes": [ "98" ] },
-        "Cwtl": { "opcodes": [ "98" ] }
+        "Cwde": { "opcode": "98" },
+        "Cwtl": { "opcode": "98" }
       },
       "args": [
         { "class": "AX", "usage": "use" },
@@ -1223,14 +1223,14 @@
         "Fdecstp": { "opcodes": [ "D9", "F6" ] },
         "Fincstp": { "opcodes": [ "D9", "F7" ] },
         "Fnop": { "opcodes": [ "D9", "D0" ] },
-        "Fwait": { "opcodes": [ "9B" ] },
-        "Int3": { "opcodes": [ "CC" ] },
+        "Fwait": { "opcode": "9B" },
+        "Int3": { "opcode": "CC" },
         "Lfence": { "opcodes": [ "0F", "AE", "E8" ] },
         "Mfence": { "opcodes": [ "0F", "AE", "F0" ] },
         "Sfence": { "opcodes": [ "0F", "AE", "F8" ] },
-        "Nop": { "opcodes": [ "90" ] },
+        "Nop": { "opcode": "90" },
         "UD2": { "opcodes": [ "0F", "0B" ] },
-        "Wait": { "opcodes": [ "9B" ] }
+        "Wait": { "opcode": "9B" }
       },
       "args": []
     },
@@ -1503,7 +1503,7 @@
     },
     {
       "encodings": {
-        "Imull": { "opcodes": [ "69" ] }
+        "Imull": { "opcode": "69" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "def" },
@@ -1524,7 +1524,7 @@
     },
     {
       "encodings": {
-        "ImullImm8": { "opcodes": [ "6B" ] }
+        "ImullImm8": { "opcode": "6B" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "def" },
@@ -1601,7 +1601,7 @@
     },
     {
       "encodings": {
-        "Lahf": { "opcodes": [ "9F" ] }
+        "Lahf": { "opcode": "9F" }
       },
       "args": [
         { "class": "EAX", "usage": "use_def" },
@@ -1620,17 +1620,16 @@
     },
     {
       "encodings": {
-        "Leal": { "opcodes": [ "8D" ] },
-        "Movl": { "opcodes": [ "8B" ] }
+        "Leal": { "opcode": "8D" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "def" },
-        { "class": "Mem32", "usage": "use" }
+        { "class": "Mem", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "LockCmpXchgb": { "opcodes": [ "F0", "0F", "B0" ], "reg_to_rm": true }
+        "Lock CmpXchgb": { "opcodes": [ "F0", "0F", "B0" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "AL", "usage": "use_def" },
@@ -1641,7 +1640,7 @@
     },
     {
       "encodings": {
-        "LockCmpXchgl": { "opcodes": [ "F0", "0F", "B1" ], "reg_to_rm": true }
+        "Lock CmpXchgl": { "opcodes": [ "F0", "0F", "B1" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "EAX", "usage": "use_def" },
@@ -1652,7 +1651,7 @@
     },
     {
       "encodings": {
-        "LockCmpXchgw": { "opcodes": [ "F0", "66", "0F", "B1" ], "reg_to_rm": true }
+        "Lock CmpXchgw": { "opcodes": [ "F0", "66", "0F", "B1" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "AX", "usage": "use_def" },
@@ -1685,7 +1684,7 @@
     },
     {
       "encodings": {
-        "Movb": { "opcodes": [ "B0" ] }
+        "Movb": { "opcode": "B0" }
       },
       "args": [
         { "class": "GeneralReg8", "usage": "def" },
@@ -1694,7 +1693,7 @@
     },
     {
       "encodings": {
-        "Movb": { "opcodes": [ "8A" ] }
+        "Movb": { "opcode": "8A" }
       },
       "args": [
         { "class": "GeneralReg8", "usage": "def" },
@@ -1703,7 +1702,7 @@
     },
     {
       "encodings": {
-        "Movb": { "opcodes": [ "88" ], "reg_to_rm": true }
+        "Movb": { "opcode": "88", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg8/Mem8", "usage": "def" },
@@ -1721,8 +1720,8 @@
     },
     {
       "encodings": {
-        "Movd": { "opcodes": [ "66", "0F", "7E" ], "reg_to_rm": true },
-        "Vmovd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "7E" ], "reg_to_rm": true }
+        "Movd": { "opcodes": [ "66", "0F", "7E" ], "type": "reg_to_rm" },
+        "Vmovd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "7E" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "def" },
@@ -1813,7 +1812,16 @@
     },
     {
       "encodings": {
-        "Movl": { "opcodes": [ "B8" ] }
+        "Movl": { "opcode": "8B" }
+      },
+      "args": [
+        { "class": "GeneralReg32", "usage": "def" },
+        { "class": "Mem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Movl": { "opcode": "B8" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "def" },
@@ -1822,7 +1830,7 @@
     },
     {
       "encodings": {
-        "Movl": { "opcodes": [ "89" ], "reg_to_rm": true }
+        "Movl": { "opcode": "89", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "def" },
@@ -1950,7 +1958,7 @@
     },
     {
       "encodings": {
-        "Movw": { "opcodes": [ "66", "89" ], "reg_to_rm": true }
+        "Movw": { "opcodes": [ "66", "89" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg16/Mem16", "usage": "def" },
@@ -1968,9 +1976,9 @@
     },
     {
       "encodings": {
-        "Mulxl": { "feature": "BMI2", "opcodes": [ "C4", "02", "03", "F6" ], "vex_rm_to_reg": true },
-        "Pdepl": { "feature": "BMI2", "opcodes": [ "C4", "02", "03", "F5" ], "vex_rm_to_reg": true },
-        "Pextl": { "feature": "BMI2", "opcodes": [ "C4", "02", "02", "F5" ], "vex_rm_to_reg": true }
+        "Mulxl": { "feature": "BMI2", "opcodes": [ "C4", "02", "03", "F6" ], "type": "vex_rm_to_reg" },
+        "Pdepl": { "feature": "BMI2", "opcodes": [ "C4", "02", "03", "F5" ], "type": "vex_rm_to_reg" },
+        "Pextl": { "feature": "BMI2", "opcodes": [ "C4", "02", "02", "F5" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "use_def" },
@@ -2032,11 +2040,11 @@
     },
     {
       "encodings": {
-        "Pextrb": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "14" ], "reg_to_rm": true },
-        "Pextrd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "16" ], "reg_to_rm": true },
+        "Pextrb": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "14" ], "type": "reg_to_rm" },
+        "Pextrd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "16" ], "type": "reg_to_rm" },
         "Pextrw": { "opcodes": [ "66", "0F", "C5" ] },
-        "Vpextrb": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "14" ], "reg_to_rm": true },
-        "Vpextrd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "16" ], "reg_to_rm": true },
+        "Vpextrb": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "14" ], "type": "reg_to_rm" },
+        "Vpextrd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "16" ], "type": "reg_to_rm" },
         "Vpextrw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C5" ] }
       },
       "args": [
@@ -2081,7 +2089,7 @@
     },
     {
       "encodings": {
-        "Pop": { "opcodes": [ "58" ] }
+        "Pop": { "opcode": "58" }
       },
       "args": [
         { "class": "RSP", "usage": "use_def" },
@@ -2127,7 +2135,7 @@
     },
     {
       "encodings": {
-        "Push": { "opcodes": [ "68" ] }
+        "Push": { "opcode": "68" }
       },
       "args": [
         { "class": "RSP", "usage": "use_def" },
@@ -2136,7 +2144,7 @@
     },
     {
       "encodings": {
-        "PushImm8": { "opcodes": [ "6A" ] }
+        "PushImm8": { "opcode": "6A" }
       },
       "args": [
         { "class": "RSP", "usage": "use_def" },
@@ -2208,7 +2216,7 @@
     },
     {
       "encodings": {
-        "Ret": { "opcodes": [ "C3" ] }
+        "Ret": { "opcode": "C3" }
       },
       "args": [
         { "class": "RSP", "usage": "use_def" }
@@ -2288,7 +2296,7 @@
     },
     {
       "encodings": {
-        "Sahf": { "opcodes": [ "9E" ] }
+        "Sahf": { "opcode": "9E" }
       },
       "args": [
         { "class": "EAX", "usage": "use" },
@@ -2319,8 +2327,8 @@
     },
     {
       "encodings": {
-        "Shldl": { "opcodes": [ "0F", "A4" ], "reg_to_rm": true },
-        "Shrdl": { "opcodes": [ "0F", "AC" ], "reg_to_rm": true }
+        "Shldl": { "opcodes": [ "0F", "A4" ], "type": "reg_to_rm" },
+        "Shrdl": { "opcodes": [ "0F", "AC" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use_def" },
@@ -2331,8 +2339,8 @@
     },
     {
       "encodings": {
-        "ShldlByCl": { "opcodes": [ "0F", "A5" ], "reg_to_rm": true },
-        "ShrdlByCl": { "opcodes": [ "0F", "AD" ], "reg_to_rm": true }
+        "ShldlByCl": { "opcodes": [ "0F", "A5" ], "type": "reg_to_rm" },
+        "ShrdlByCl": { "opcodes": [ "0F", "AD" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use_def" },
@@ -2401,111 +2409,111 @@
     },
     {
       "encodings": {
-        "Vaddpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "58" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vaddps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "58" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vandpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "54" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vandps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "54" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpeqpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "00" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpeqps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "00" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmplepd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "02" ], "vex_rm_to_reg": true },
-        "Vcmpleps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "02" ], "vex_rm_to_reg": true },
-        "Vcmpltpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "01" ], "vex_rm_to_reg": true },
-        "Vcmpltps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "01" ], "vex_rm_to_reg": true },
-        "Vcmpneqpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "04" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpneqps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "04" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpnlepd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "06" ], "vex_rm_to_reg": true },
-        "Vcmpnleps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "06" ], "vex_rm_to_reg": true },
-        "Vcmpnltpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "05" ], "vex_rm_to_reg": true },
-        "Vcmpnltps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "05" ], "vex_rm_to_reg": true },
-        "Vcmpordpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "07" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpordps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "07" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpunordpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "03" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpunordps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "03" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vdivpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5E" ], "vex_rm_to_reg": true },
-        "Vdivps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5E" ], "vex_rm_to_reg": true },
-        "Vhaddpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "7C" ], "vex_rm_to_reg": true },
-        "Vhaddps": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "7C" ], "vex_rm_to_reg": true },
-        "Vmaxpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5F" ], "vex_rm_to_reg": true },
-        "Vmaxps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5F" ], "vex_rm_to_reg": true },
-        "Vminpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5D" ], "vex_rm_to_reg": true },
-        "Vminps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5D" ], "vex_rm_to_reg": true },
-        "Vmulpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "59" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vmulps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "59" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vorpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "56" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vorps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "56" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpackssdw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6B" ], "vex_rm_to_reg": true },
-        "Vpacksswb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "63" ], "vex_rm_to_reg": true },
-        "Vpackusdw": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "2B" ], "vex_rm_to_reg": true },
-        "Vpackuswb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "67" ], "vex_rm_to_reg": true },
-        "Vpaddb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FC" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpaddd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FE" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpaddq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D4" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpaddsb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EC" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpaddsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "ED" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpaddusb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DC" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpaddusw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DD" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpaddw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FD" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpand": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DB" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpandn": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DF" ], "vex_rm_to_reg": true },
-        "Vpavgb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E0" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpavgw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E3" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpcmpeqb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "74" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpcmpeqd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "76" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpcmpeqq": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "29" ], "vex_rm_to_reg": true },
-        "Vpcmpeqw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "75" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpcmpgtb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "64" ], "vex_rm_to_reg": true },
-        "Vpcmpgtd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "66" ], "vex_rm_to_reg": true },
-        "Vpcmpgtq": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "37" ], "vex_rm_to_reg": true },
-        "Vpcmpgtw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "65" ], "vex_rm_to_reg": true },
-        "Vpmaxsb": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3C" ], "vex_rm_to_reg": true },
-        "Vpmaxsd": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3D" ], "vex_rm_to_reg": true },
-        "Vpmaxsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EE" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpmaxub": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DE" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpmaxud": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3F" ], "vex_rm_to_reg": true },
-        "Vpmaxuw": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3E" ], "vex_rm_to_reg": true },
-        "Vpminsb": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "38" ], "vex_rm_to_reg": true },
-        "Vpminsd": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "39" ], "vex_rm_to_reg": true },
-        "Vpminsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EA" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpminub": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DA" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpminud": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3B" ], "vex_rm_to_reg": true },
-        "Vpminuw": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3A" ], "vex_rm_to_reg": true },
-        "Vpmulhrsw": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "0B" ], "vex_rm_to_reg": true },
-        "Vpmulhw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E5" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpmulld": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "40" ], "vex_rm_to_reg": true },
-        "Vpmullw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D5" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpmuludq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F4" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpor": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EB" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpsadbw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F6" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vpshufb": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "00" ], "vex_rm_to_reg": true },
-        "Vpslld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F2" ], "vex_rm_to_reg": true },
-        "Vpsllq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F3" ], "vex_rm_to_reg": true },
-        "Vpsllw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F1" ], "vex_rm_to_reg": true },
-        "Vpsrad": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E2" ], "vex_rm_to_reg": true },
-        "Vpsraw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E1" ], "vex_rm_to_reg": true },
-        "Vpsrld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D2" ], "vex_rm_to_reg": true },
-        "Vpsrlq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D3" ], "vex_rm_to_reg": true },
-        "Vpsrlw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D1" ], "vex_rm_to_reg": true },
-        "Vpsubb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F8" ], "vex_rm_to_reg": true },
-        "Vpsubd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FA" ], "vex_rm_to_reg": true },
-        "Vpsubq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FB" ], "vex_rm_to_reg": true },
-        "Vpsubsb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E8" ], "vex_rm_to_reg": true },
-        "Vpsubsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E9" ], "vex_rm_to_reg": true },
-        "Vpsubusb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D8" ], "vex_rm_to_reg": true },
-        "Vpsubusw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D9" ], "vex_rm_to_reg": true },
-        "Vpsubw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F9" ], "vex_rm_to_reg": true },
-        "Vpunpckhbw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "68" ], "vex_rm_to_reg": true },
-        "Vpunpckhdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6A" ], "vex_rm_to_reg": true },
-        "Vpunpckhqdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6D" ], "vex_rm_to_reg": true },
-        "Vpunpckhwd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "69" ], "vex_rm_to_reg": true },
-        "Vpunpcklbw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "60" ], "vex_rm_to_reg": true },
-        "Vpunpckldq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "62" ], "vex_rm_to_reg": true },
-        "Vpunpcklqdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6C" ], "vex_rm_to_reg": true },
-        "Vpunpcklwd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "61" ], "vex_rm_to_reg": true },
-        "Vpxor": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EF" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vsubpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5C" ], "vex_rm_to_reg": true },
-        "Vsubps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5C" ], "vex_rm_to_reg": true },
-        "Vxorpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "57" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vxorps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "57" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true }
+        "Vaddpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "58" ], "type": "optimizable_using_commutation" },
+        "Vaddps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "58" ], "type": "optimizable_using_commutation" },
+        "Vandpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "54" ], "type": "optimizable_using_commutation" },
+        "Vandps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "54" ], "type": "optimizable_using_commutation" },
+        "Vcmpeqpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "00" ], "type": "optimizable_using_commutation" },
+        "Vcmpeqps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "00" ], "type": "optimizable_using_commutation" },
+        "Vcmplepd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "02" ], "type": "vex_rm_to_reg" },
+        "Vcmpleps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "02" ], "type": "vex_rm_to_reg" },
+        "Vcmpltpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "01" ], "type": "vex_rm_to_reg" },
+        "Vcmpltps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "01" ], "type": "vex_rm_to_reg" },
+        "Vcmpneqpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "04" ], "type": "optimizable_using_commutation" },
+        "Vcmpneqps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "04" ], "type": "optimizable_using_commutation" },
+        "Vcmpnlepd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "06" ], "type": "vex_rm_to_reg" },
+        "Vcmpnleps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "06" ], "type": "vex_rm_to_reg" },
+        "Vcmpnltpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "05" ], "type": "vex_rm_to_reg" },
+        "Vcmpnltps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "05" ], "type": "vex_rm_to_reg" },
+        "Vcmpordpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "07" ], "type": "optimizable_using_commutation" },
+        "Vcmpordps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "07" ], "type": "optimizable_using_commutation" },
+        "Vcmpunordpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "03" ], "type": "optimizable_using_commutation" },
+        "Vcmpunordps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C2", "03" ], "type": "optimizable_using_commutation" },
+        "Vdivpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5E" ], "type": "vex_rm_to_reg" },
+        "Vdivps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5E" ], "type": "vex_rm_to_reg" },
+        "Vhaddpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "7C" ], "type": "vex_rm_to_reg" },
+        "Vhaddps": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "7C" ], "type": "vex_rm_to_reg" },
+        "Vmaxpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5F" ], "type": "vex_rm_to_reg" },
+        "Vmaxps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5F" ], "type": "vex_rm_to_reg" },
+        "Vminpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5D" ], "type": "vex_rm_to_reg" },
+        "Vminps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5D" ], "type": "vex_rm_to_reg" },
+        "Vmulpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "59" ], "type": "optimizable_using_commutation" },
+        "Vmulps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "59" ], "type": "optimizable_using_commutation" },
+        "Vorpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "56" ], "type": "optimizable_using_commutation" },
+        "Vorps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "56" ], "type": "optimizable_using_commutation" },
+        "Vpackssdw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6B" ], "type": "vex_rm_to_reg" },
+        "Vpacksswb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "63" ], "type": "vex_rm_to_reg" },
+        "Vpackusdw": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "2B" ], "type": "vex_rm_to_reg" },
+        "Vpackuswb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "67" ], "type": "vex_rm_to_reg" },
+        "Vpaddb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FC" ], "type": "optimizable_using_commutation" },
+        "Vpaddd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FE" ], "type": "optimizable_using_commutation" },
+        "Vpaddq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D4" ], "type": "optimizable_using_commutation" },
+        "Vpaddsb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EC" ], "type": "optimizable_using_commutation" },
+        "Vpaddsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "ED" ], "type": "optimizable_using_commutation" },
+        "Vpaddusb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DC" ], "type": "optimizable_using_commutation" },
+        "Vpaddusw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DD" ], "type": "optimizable_using_commutation" },
+        "Vpaddw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FD" ], "type": "optimizable_using_commutation" },
+        "Vpand": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DB" ], "type": "optimizable_using_commutation" },
+        "Vpandn": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DF" ], "type": "vex_rm_to_reg" },
+        "Vpavgb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E0" ], "type": "optimizable_using_commutation" },
+        "Vpavgw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E3" ], "type": "optimizable_using_commutation" },
+        "Vpcmpeqb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "74" ], "type": "optimizable_using_commutation" },
+        "Vpcmpeqd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "76" ], "type": "optimizable_using_commutation" },
+        "Vpcmpeqq": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "29" ], "type": "vex_rm_to_reg" },
+        "Vpcmpeqw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "75" ], "type": "optimizable_using_commutation" },
+        "Vpcmpgtb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "64" ], "type": "vex_rm_to_reg" },
+        "Vpcmpgtd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "66" ], "type": "vex_rm_to_reg" },
+        "Vpcmpgtq": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "37" ], "type": "vex_rm_to_reg" },
+        "Vpcmpgtw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "65" ], "type": "vex_rm_to_reg" },
+        "Vpmaxsb": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3C" ], "type": "vex_rm_to_reg" },
+        "Vpmaxsd": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3D" ], "type": "vex_rm_to_reg" },
+        "Vpmaxsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EE" ], "type": "optimizable_using_commutation" },
+        "Vpmaxub": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DE" ], "type": "optimizable_using_commutation" },
+        "Vpmaxud": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3F" ], "type": "vex_rm_to_reg" },
+        "Vpmaxuw": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3E" ], "type": "vex_rm_to_reg" },
+        "Vpminsb": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "38" ], "type": "vex_rm_to_reg" },
+        "Vpminsd": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "39" ], "type": "vex_rm_to_reg" },
+        "Vpminsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EA" ], "type": "optimizable_using_commutation" },
+        "Vpminub": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DA" ], "type": "optimizable_using_commutation" },
+        "Vpminud": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3B" ], "type": "vex_rm_to_reg" },
+        "Vpminuw": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3A" ], "type": "vex_rm_to_reg" },
+        "Vpmulhrsw": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "0B" ], "type": "vex_rm_to_reg" },
+        "Vpmulhw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E5" ], "type": "optimizable_using_commutation" },
+        "Vpmulld": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "40" ], "type": "vex_rm_to_reg" },
+        "Vpmullw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D5" ], "type": "optimizable_using_commutation" },
+        "Vpmuludq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F4" ], "type": "optimizable_using_commutation" },
+        "Vpor": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EB" ], "type": "optimizable_using_commutation" },
+        "Vpsadbw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F6" ], "type": "optimizable_using_commutation" },
+        "Vpshufb": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "00" ], "type": "vex_rm_to_reg" },
+        "Vpslld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F2" ], "type": "vex_rm_to_reg" },
+        "Vpsllq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F3" ], "type": "vex_rm_to_reg" },
+        "Vpsllw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F1" ], "type": "vex_rm_to_reg" },
+        "Vpsrad": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E2" ], "type": "vex_rm_to_reg" },
+        "Vpsraw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E1" ], "type": "vex_rm_to_reg" },
+        "Vpsrld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D2" ], "type": "vex_rm_to_reg" },
+        "Vpsrlq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D3" ], "type": "vex_rm_to_reg" },
+        "Vpsrlw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D1" ], "type": "vex_rm_to_reg" },
+        "Vpsubb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F8" ], "type": "vex_rm_to_reg" },
+        "Vpsubd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FA" ], "type": "vex_rm_to_reg" },
+        "Vpsubq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FB" ], "type": "vex_rm_to_reg" },
+        "Vpsubsb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E8" ], "type": "vex_rm_to_reg" },
+        "Vpsubsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E9" ], "type": "vex_rm_to_reg" },
+        "Vpsubusb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D8" ], "type": "vex_rm_to_reg" },
+        "Vpsubusw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D9" ], "type": "vex_rm_to_reg" },
+        "Vpsubw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F9" ], "type": "vex_rm_to_reg" },
+        "Vpunpckhbw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "68" ], "type": "vex_rm_to_reg" },
+        "Vpunpckhdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6A" ], "type": "vex_rm_to_reg" },
+        "Vpunpckhqdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6D" ], "type": "vex_rm_to_reg" },
+        "Vpunpckhwd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "69" ], "type": "vex_rm_to_reg" },
+        "Vpunpcklbw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "60" ], "type": "vex_rm_to_reg" },
+        "Vpunpckldq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "62" ], "type": "vex_rm_to_reg" },
+        "Vpunpcklqdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6C" ], "type": "vex_rm_to_reg" },
+        "Vpunpcklwd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "61" ], "type": "vex_rm_to_reg" },
+        "Vpxor": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EF" ], "type": "optimizable_using_commutation" },
+        "Vsubpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5C" ], "type": "vex_rm_to_reg" },
+        "Vsubps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5C" ], "type": "vex_rm_to_reg" },
+        "Vxorpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "57" ], "type": "optimizable_using_commutation" },
+        "Vxorps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "57" ], "type": "optimizable_using_commutation" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -2515,18 +2523,18 @@
     },
     {
       "encodings": {
-        "Vaddsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "58" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpeqsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "00" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmplesd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "02" ], "vex_rm_to_reg": true },
-        "Vcmpltsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "01" ], "vex_rm_to_reg": true },
-        "Vcmpneqsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "04" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpnlesd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "06" ], "vex_rm_to_reg": true },
-        "Vcmpnltsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "05" ], "vex_rm_to_reg": true },
-        "Vcmpordsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "07" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpunordsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "03" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vdivsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "5E" ], "vex_rm_to_reg": true },
-        "Vmulsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "59" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vsubsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "5C" ], "vex_rm_to_reg": true }
+        "Vaddsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "58" ], "type": "optimizable_using_commutation" },
+        "Vcmpeqsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "00" ], "type": "optimizable_using_commutation" },
+        "Vcmplesd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "02" ], "type": "vex_rm_to_reg" },
+        "Vcmpltsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "01" ], "type": "vex_rm_to_reg" },
+        "Vcmpneqsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "04" ], "type": "optimizable_using_commutation" },
+        "Vcmpnlesd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "06" ], "type": "vex_rm_to_reg" },
+        "Vcmpnltsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "05" ], "type": "vex_rm_to_reg" },
+        "Vcmpordsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "07" ], "type": "optimizable_using_commutation" },
+        "Vcmpunordsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "C2", "03" ], "type": "optimizable_using_commutation" },
+        "Vdivsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "5E" ], "type": "vex_rm_to_reg" },
+        "Vmulsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "59" ], "type": "optimizable_using_commutation" },
+        "Vsubsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "5C" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "FpReg64", "usage": "def" },
@@ -2536,18 +2544,18 @@
     },
     {
       "encodings": {
-        "Vaddss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "58" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpeqss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "00" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpless": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "02" ], "vex_rm_to_reg": true },
-        "Vcmpltss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "01" ], "vex_rm_to_reg": true },
-        "Vcmpneqss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "04" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpnless": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "06" ], "vex_rm_to_reg": true },
-        "Vcmpnltss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "05" ], "vex_rm_to_reg": true },
-        "Vcmpordss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "07" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vcmpunordss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "03" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vdivss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5E" ], "vex_rm_to_reg": true },
-        "Vmulss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "59" ], "is_optimizable_using_commutation": true, "vex_rm_to_reg": true },
-        "Vsubss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5C" ], "vex_rm_to_reg": true }
+        "Vaddss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "58" ], "type": "optimizable_using_commutation" },
+        "Vcmpeqss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "00" ], "type": "optimizable_using_commutation" },
+        "Vcmpless": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "02" ], "type": "vex_rm_to_reg" },
+        "Vcmpltss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "01" ], "type": "vex_rm_to_reg" },
+        "Vcmpneqss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "04" ], "type": "optimizable_using_commutation" },
+        "Vcmpnless": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "06" ], "type": "vex_rm_to_reg" },
+        "Vcmpnltss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "05" ], "type": "vex_rm_to_reg" },
+        "Vcmpordss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "07" ], "type": "optimizable_using_commutation" },
+        "Vcmpunordss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "C2", "03" ], "type": "optimizable_using_commutation" },
+        "Vdivss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5E" ], "type": "vex_rm_to_reg" },
+        "Vmulss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "59" ], "type": "optimizable_using_commutation" },
+        "Vsubss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5C" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "FpReg32", "usage": "def" },
@@ -2557,7 +2565,7 @@
     },
     {
       "encodings": {
-        "Vcvtsd2ss": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "5A" ], "vex_rm_to_reg": true }
+        "Vcvtsd2ss": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "5A" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "FpReg32", "usage": "def" },
@@ -2567,7 +2575,7 @@
     },
     {
       "encodings": {
-        "Vcvtsi2sdl": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "2A" ], "vex_rm_to_reg": true }
+        "Vcvtsi2sdl": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "2A" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "FpReg64", "usage": "def" },
@@ -2577,7 +2585,7 @@
     },
     {
       "encodings": {
-        "Vcvtsi2ssl": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "2A" ], "vex_rm_to_reg": true }
+        "Vcvtsi2ssl": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "2A" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "FpReg32", "usage": "def" },
@@ -2587,7 +2595,7 @@
     },
     {
       "encodings": {
-        "Vcvtss2sd": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5A" ], "vex_rm_to_reg": true }
+        "Vcvtss2sd": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5A" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "FpReg64", "usage": "def" },
@@ -2597,42 +2605,42 @@
     },
     {
       "encodings": {
-        "Vfmadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "98" ], "vex_rm_to_reg": true },
-        "Vfmadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "98" ], "vex_rm_to_reg": true },
-        "Vfmadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A8" ], "vex_rm_to_reg": true },
-        "Vfmadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A8" ], "vex_rm_to_reg": true },
-        "Vfmadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B8" ], "vex_rm_to_reg": true },
-        "Vfmadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B8" ], "vex_rm_to_reg": true },
-        "Vfmaddsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "96" ], "vex_rm_to_reg": true },
-        "Vfmaddsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "96" ], "vex_rm_to_reg": true },
-        "Vfmaddsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A6" ], "vex_rm_to_reg": true },
-        "Vfmaddsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A6" ], "vex_rm_to_reg": true },
-        "Vfmaddsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B6" ], "vex_rm_to_reg": true },
-        "Vfmaddsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B6" ], "vex_rm_to_reg": true },
-        "Vfmsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9A" ], "vex_rm_to_reg": true },
-        "Vfmsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9A" ], "vex_rm_to_reg": true },
-        "Vfmsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AA" ], "vex_rm_to_reg": true },
-        "Vfmsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AA" ], "vex_rm_to_reg": true },
-        "Vfmsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BA" ], "vex_rm_to_reg": true },
-        "Vfmsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BA" ], "vex_rm_to_reg": true },
-        "Vfmsubadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "97" ], "vex_rm_to_reg": true },
-        "Vfmsubadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "97" ], "vex_rm_to_reg": true },
-        "Vfmsubadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A7" ], "vex_rm_to_reg": true },
-        "Vfmsubadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A7" ], "vex_rm_to_reg": true },
-        "Vfmsubadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B7" ], "vex_rm_to_reg": true },
-        "Vfmsubadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B7" ], "vex_rm_to_reg": true },
-        "Vfnmadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9C" ], "vex_rm_to_reg": true },
-        "Vfnmadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9C" ], "vex_rm_to_reg": true },
-        "Vfnmadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AC" ], "vex_rm_to_reg": true },
-        "Vfnmadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AC" ], "vex_rm_to_reg": true },
-        "Vfnmadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BC" ], "vex_rm_to_reg": true },
-        "Vfnmadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BC" ], "vex_rm_to_reg": true },
-        "Vfnmsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9E" ], "vex_rm_to_reg": true },
-        "Vfnmsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9E" ], "vex_rm_to_reg": true },
-        "Vfnmsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AE" ], "vex_rm_to_reg": true },
-        "Vfnmsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AE" ], "vex_rm_to_reg": true },
-        "Vfnmsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BE" ], "vex_rm_to_reg": true },
-        "Vfnmsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BE" ], "vex_rm_to_reg": true }
+        "Vfmadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "98" ], "type": "vex_rm_to_reg" },
+        "Vfmadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "98" ], "type": "vex_rm_to_reg" },
+        "Vfmadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B8" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "96" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "96" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B6" ], "type": "vex_rm_to_reg" },
+        "Vfmsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9A" ], "type": "vex_rm_to_reg" },
+        "Vfmsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9A" ], "type": "vex_rm_to_reg" },
+        "Vfmsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BA" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "97" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "97" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A7" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A7" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B7" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B7" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9C" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9C" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AC" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AC" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BC" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BC" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9E" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9E" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AE" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AE" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BE" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BE" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "VecReg128", "usage": "use_def" },
@@ -2642,18 +2650,18 @@
     },
     {
       "encodings": {
-        "Vfmadd132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "99" ], "vex_rm_to_reg": true },
-        "Vfmadd213sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A9" ], "vex_rm_to_reg": true },
-        "Vfmadd231sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B9" ], "vex_rm_to_reg": true },
-        "Vfmsub132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9B" ], "vex_rm_to_reg": true },
-        "Vfmsub213sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AB" ], "vex_rm_to_reg": true },
-        "Vfmsub231sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BB" ], "vex_rm_to_reg": true },
-        "Vfnmadd132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9D" ], "vex_rm_to_reg": true },
-        "Vfnmadd213sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AD" ], "vex_rm_to_reg": true },
-        "Vfnmadd231sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BD" ], "vex_rm_to_reg": true },
-        "Vfnmsub132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9F" ], "vex_rm_to_reg": true },
-        "Vfnmsub213sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AF" ], "vex_rm_to_reg": true },
-        "Vfnmsub231sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BF" ], "vex_rm_to_reg": true }
+        "Vfmadd132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "99" ], "type": "vex_rm_to_reg" },
+        "Vfmadd213sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A9" ], "type": "vex_rm_to_reg" },
+        "Vfmadd231sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B9" ], "type": "vex_rm_to_reg" },
+        "Vfmsub132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9B" ], "type": "vex_rm_to_reg" },
+        "Vfmsub213sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AB" ], "type": "vex_rm_to_reg" },
+        "Vfmsub231sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BB" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9D" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd213sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AD" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd231sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BD" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9F" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub213sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AF" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub231sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BF" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "use_def" },
@@ -2663,18 +2671,18 @@
     },
     {
       "encodings": {
-        "Vfmadd132ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "99" ], "vex_rm_to_reg": true },
-        "Vfmadd213ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A9" ], "vex_rm_to_reg": true },
-        "Vfmadd231ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B9" ], "vex_rm_to_reg": true },
-        "Vfmsub132ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9B" ], "vex_rm_to_reg": true },
-        "Vfmsub213ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AB" ], "vex_rm_to_reg": true },
-        "Vfmsub231ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BB" ], "vex_rm_to_reg": true },
-        "Vfnmadd132ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9D" ], "vex_rm_to_reg": true },
-        "Vfnmadd213ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AD" ], "vex_rm_to_reg": true },
-        "Vfnmadd231ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BD" ], "vex_rm_to_reg": true },
-        "Vfnmsub132ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9F" ], "vex_rm_to_reg": true },
-        "Vfnmsub213ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AF" ], "vex_rm_to_reg": true },
-        "Vfnmsub231ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BF" ], "vex_rm_to_reg": true }
+        "Vfmadd132ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "99" ], "type": "vex_rm_to_reg" },
+        "Vfmadd213ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A9" ], "type": "vex_rm_to_reg" },
+        "Vfmadd231ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B9" ], "type": "vex_rm_to_reg" },
+        "Vfmsub132ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9B" ], "type": "vex_rm_to_reg" },
+        "Vfmsub213ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AB" ], "type": "vex_rm_to_reg" },
+        "Vfmsub231ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BB" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd132ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9D" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd213ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AD" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd231ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BD" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub132ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9F" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub213ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AF" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub231ss": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BF" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "use_def" },
@@ -2684,18 +2692,18 @@
     },
     {
       "encodings": {
-        "Vfmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "69" ], "vex_rm_imm_to_reg": true },
-        "Vfmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "68" ], "vex_rm_imm_to_reg": true },
-        "Vfmaddsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "5D" ], "vex_rm_imm_to_reg": true },
-        "Vfmaddsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "5C" ], "vex_rm_imm_to_reg": true },
-        "Vfmsubaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "5F" ], "vex_rm_imm_to_reg": true },
-        "Vfmsubaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "5E" ], "vex_rm_imm_to_reg": true },
-        "Vfmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6D" ], "vex_rm_imm_to_reg": true },
-        "Vfmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6C" ], "vex_rm_imm_to_reg": true },
-        "Vfnmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "79" ], "vex_rm_imm_to_reg": true },
-        "Vfnmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "78" ], "vex_rm_imm_to_reg": true },
-        "Vfnmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7D" ], "vex_rm_imm_to_reg": true },
-        "Vfnmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7C" ], "vex_rm_imm_to_reg": true }
+        "Vfmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "69" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "68" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmaddsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "5D" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmaddsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "5C" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "5F" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "5E" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6D" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6C" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "79" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "78" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7D" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7C" ], "type": "vex_rm_imm_to_reg" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -2706,18 +2714,18 @@
     },
     {
       "encodings": {
-        "Vfmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "69" ], "vex_imm_rm_to_reg": true },
-        "Vfmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "68" ], "vex_imm_rm_to_reg": true },
-        "Vfmaddsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "5D" ], "vex_imm_rm_to_reg": true },
-        "Vfmaddsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "5C" ], "vex_imm_rm_to_reg": true },
-        "Vfmsubaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "5F" ], "vex_imm_rm_to_reg": true },
-        "Vfmsubaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "5E" ], "vex_imm_rm_to_reg": true },
-        "Vfmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6D" ], "vex_imm_rm_to_reg": true },
-        "Vfmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6C" ], "vex_imm_rm_to_reg": true },
-        "Vfnmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "79" ], "vex_imm_rm_to_reg": true },
-        "Vfnmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "78" ], "vex_imm_rm_to_reg": true },
-        "Vfnmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7D" ], "vex_imm_rm_to_reg": true },
-        "Vfnmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7C" ], "vex_imm_rm_to_reg": true }
+        "Vfmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "69" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "68" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmaddsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "5D" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmaddsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "5C" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "5F" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "5E" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6D" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6C" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "79" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "78" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7D" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7C" ], "type": "vex_imm_rm_to_reg" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -2728,10 +2736,10 @@
     },
     {
       "encodings": {
-        "Vfmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6B" ], "vex_rm_imm_to_reg": true },
-        "Vfmsubsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6F" ], "vex_rm_imm_to_reg": true },
-        "Vfnmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7B" ], "vex_rm_imm_to_reg": true },
-        "Vfnmsubsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7F" ], "vex_rm_imm_to_reg": true }
+        "Vfmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6B" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6F" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7B" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmsubsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7F" ], "type": "vex_rm_imm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
@@ -2742,10 +2750,10 @@
     },
     {
       "encodings": {
-        "Vfmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6B" ], "vex_imm_rm_to_reg": true },
-        "Vfmsubsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6F" ], "vex_imm_rm_to_reg": true },
-        "Vfnmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7B" ], "vex_imm_rm_to_reg": true },
-        "Vfnmsubsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7F" ], "vex_imm_rm_to_reg": true }
+        "Vfmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6B" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6F" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7B" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmsubsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7F" ], "type": "vex_imm_rm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
@@ -2756,10 +2764,10 @@
     },
     {
       "encodings": {
-        "Vfmaddss": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6A" ], "vex_rm_imm_to_reg": true },
-        "Vfmsubss": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6E" ], "vex_rm_imm_to_reg": true },
-        "Vfnmaddss": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7A" ], "vex_rm_imm_to_reg": true },
-        "Vfnmsubss": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7E" ], "vex_rm_imm_to_reg": true }
+        "Vfmaddss": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6A" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubss": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6E" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmaddss": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7A" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmsubss": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "7E" ], "type": "vex_rm_imm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
@@ -2770,10 +2778,10 @@
     },
     {
       "encodings": {
-        "Vfmaddss": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6A" ], "vex_imm_rm_to_reg": true },
-        "Vfmsubss": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6E" ], "vex_imm_rm_to_reg": true },
-        "Vfnmaddss": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7A" ], "vex_imm_rm_to_reg": true },
-        "Vfnmsubss": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7E" ], "vex_imm_rm_to_reg": true }
+        "Vfmaddss": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6A" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubss": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "6E" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmaddss": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7A" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmsubss": { "feature": "FMA4", "opcodes": [ "C4", "03", "81", "7E" ], "type": "vex_imm_rm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
@@ -2804,8 +2812,8 @@
     },
     {
       "encodings": {
-        "Vmovhlps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "12" ], "vex_rm_to_reg": true },
-        "Vmovlhps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "16" ], "vex_rm_to_reg": true }
+        "Vmovhlps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "12" ], "type": "vex_rm_to_reg" },
+        "Vmovlhps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "16" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
@@ -2828,8 +2836,8 @@
     },
     {
       "encodings": {
-        "Vpermil2pd": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "49" ], "vex_imm_rm_to_reg": true },
-        "Vpermil2ps": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "48" ], "vex_imm_rm_to_reg": true }
+        "Vpermil2pd": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "49" ], "type": "vex_imm_rm_to_reg" },
+        "Vpermil2ps": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "48" ], "type": "vex_imm_rm_to_reg" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -2841,8 +2849,8 @@
     },
     {
       "encodings": {
-        "Vpermil2pd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "49" ], "vex_rm_imm_to_reg": true },
-        "Vpermil2ps": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "48" ], "vex_rm_imm_to_reg": true }
+        "Vpermil2pd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "49" ], "type": "vex_rm_imm_to_reg" },
+        "Vpermil2ps": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "48" ], "type": "vex_rm_imm_to_reg" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -2854,9 +2862,9 @@
     },
     {
       "encodings": {
-        "Vpinsrb": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "20" ], "vex_rm_to_reg": true },
-        "Vpinsrd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "22" ], "vex_rm_to_reg": true },
-        "Vpinsrw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C4" ], "vex_rm_to_reg": true }
+        "Vpinsrb": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "20" ], "type": "vex_rm_to_reg" },
+        "Vpinsrd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "22" ], "type": "vex_rm_to_reg" },
+        "Vpinsrw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C4" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "VecReg128", "usage": "use_def" },
@@ -2867,16 +2875,16 @@
     },
     {
       "encodings": {
-        "Vpslld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "72", "6" ], "rm_to_vex": true },
-        "Vpslldq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "73", "7" ], "rm_to_vex": true },
-        "Vpsllq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "73", "6" ], "rm_to_vex": true },
-        "Vpsllw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "71", "6" ], "rm_to_vex": true },
-        "Vpsrad": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "72", "4" ], "rm_to_vex": true },
-        "Vpsraw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "71", "4" ], "rm_to_vex": true },
-        "Vpsrld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "72", "2" ], "rm_to_vex": true },
-        "Vpsrldq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "73", "3" ], "rm_to_vex": true },
-        "Vpsrlq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "73", "2" ], "rm_to_vex": true },
-        "Vpsrlw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "71", "2" ], "rm_to_vex": true }
+        "Vpslld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "72", "6" ], "type": "rm_to_vex" },
+        "Vpslldq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "73", "7" ], "type": "rm_to_vex" },
+        "Vpsllq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "73", "6" ], "type": "rm_to_vex" },
+        "Vpsllw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "71", "6" ], "type": "rm_to_vex" },
+        "Vpsrad": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "72", "4" ], "type": "rm_to_vex" },
+        "Vpsraw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "71", "4" ], "type": "rm_to_vex" },
+        "Vpsrld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "72", "2" ], "type": "rm_to_vex" },
+        "Vpsrldq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "73", "3" ], "type": "rm_to_vex" },
+        "Vpsrlq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "73", "2" ], "type": "rm_to_vex" },
+        "Vpsrlw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "71", "2" ], "type": "rm_to_vex" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -2886,7 +2894,7 @@
     },
     {
       "encodings": {
-        "Vroundsd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "0B" ], "vex_rm_to_reg": true }
+        "Vroundsd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "0B" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "FpReg64", "usage": "def" },
@@ -2897,7 +2905,7 @@
     },
     {
       "encodings": {
-        "Vroundss": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "0A" ], "vex_rm_to_reg": true }
+        "Vroundss": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "0A" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "FpReg32", "usage": "def" },
@@ -2908,8 +2916,8 @@
     },
     {
       "encodings": {
-        "Vshufpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C6" ], "vex_rm_to_reg": true },
-        "Vshufps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C6" ], "vex_rm_to_reg": true }
+        "Vshufpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C6" ], "type": "vex_rm_to_reg" },
+        "Vshufps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C6" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -2927,7 +2935,7 @@
     },
     {
       "encodings": {
-        "Xchgl": { "opcodes": [ "87" ] }
+        "Xchgl": { "opcode": "87" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "use_def" },
diff --git a/assembler/instructions/insn_def_x86_32.json b/assembler/instructions/insn_def_x86_32.json
index 8d912978..e7efa194 100644
--- a/assembler/instructions/insn_def_x86_32.json
+++ b/assembler/instructions/insn_def_x86_32.json
@@ -27,8 +27,8 @@
     },
     {
       "encodings": {
-        "Decl": { "opcodes": [ "48" ] },
-        "Incl": { "opcodes": [ "40" ] }
+        "Decl": { "opcode": "48" },
+        "Incl": { "opcode": "40" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "use_def" },
@@ -93,8 +93,8 @@
     },
     {
       "encodings": {
-        "Vmovsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "10" ], "vex_rm_to_reg": true },
-        "Vmovss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "10" ], "vex_rm_to_reg": true }
+        "Vmovsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "10" ], "type": "vex_rm_to_reg" },
+        "Vmovss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "10" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
diff --git a/assembler/instructions/insn_def_x86_64.json b/assembler/instructions/insn_def_x86_64.json
index 2eeade98..aa3551ba 100644
--- a/assembler/instructions/insn_def_x86_64.json
+++ b/assembler/instructions/insn_def_x86_64.json
@@ -18,8 +18,8 @@
   "insns": [
     {
       "encodings": {
-        "Adcq": { "opcodes": [ "13" ] },
-        "Sbbq": { "opcodes": [ "1B" ] }
+        "Adcq": { "opcode": "13" },
+        "Sbbq": { "opcode": "1B" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "use_def" },
@@ -40,8 +40,8 @@
     },
     {
       "encodings": {
-        "Adcq": { "opcodes": [ "11" ], "reg_to_rm": true },
-        "Sbbq": { "opcodes": [ "19" ], "reg_to_rm": true }
+        "Adcq": { "opcode": "11", "type": "reg_to_rm" },
+        "Sbbq": { "opcode": "19", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64/Mem64", "usage": "use_def" },
@@ -75,14 +75,14 @@
     },
     {
       "encodings": {
-        "Addq": { "opcodes": [ "01" ], "reg_to_rm": true },
-        "Andq": { "opcodes": [ "21" ], "reg_to_rm": true },
-        "Btcq": { "opcodes": [ "0F", "BB" ], "reg_to_rm": true },
-        "Btrq": { "opcodes": [ "0F", "B3" ], "reg_to_rm": true },
-        "Btsq": { "opcodes": [ "0F", "AB" ], "reg_to_rm": true },
-        "Orq": { "opcodes": [ "09" ], "reg_to_rm": true },
-        "Subq": { "opcodes": [ "29" ], "reg_to_rm": true },
-        "Xorq": { "opcodes": [ "31" ], "reg_to_rm": true }
+        "Addq": { "opcode": "01", "type": "reg_to_rm" },
+        "Andq": { "opcode": "21", "type": "reg_to_rm" },
+        "Btcq": { "opcodes": [ "0F", "BB" ], "type": "reg_to_rm" },
+        "Btrq": { "opcodes": [ "0F", "B3" ], "type": "reg_to_rm" },
+        "Btsq": { "opcodes": [ "0F", "AB" ], "type": "reg_to_rm" },
+        "Orq": { "opcode": "09", "type": "reg_to_rm" },
+        "Subq": { "opcode": "29", "type": "reg_to_rm" },
+        "Xorq": { "opcode": "31", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64/Mem64", "usage": "use_def" },
@@ -92,11 +92,11 @@
     },
     {
       "encodings": {
-        "Addq": { "opcodes": [ "03" ] },
-        "Andq": { "opcodes": [ "23" ] },
-        "Orq": { "opcodes": [ "0B" ] },
-        "Subq": { "opcodes": [ "2B" ] },
-        "Xorq": { "opcodes": [ "33" ] }
+        "Addq": { "opcode": "03" },
+        "Andq": { "opcode": "23" },
+        "Orq": { "opcode": "0B" },
+        "Subq": { "opcode": "2B" },
+        "Xorq": { "opcode": "33" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "use_def" },
@@ -157,7 +157,7 @@
     },
     {
       "encodings": {
-        "Andnq": { "feature": "BMI", "opcodes": [ "C4", "02", "80", "F2" ], "vex_rm_to_reg": true }
+        "Andnq": { "feature": "BMI", "opcodes": [ "C4", "02", "80", "F2" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
@@ -180,9 +180,9 @@
     },
     {
       "encodings": {
-        "Blsiq": { "feature": "BMI", "opcodes": [ "C4", "02", "80", "F3", "3" ], "rm_to_vex": true },
-        "Blsmskq": { "feature": "BMI", "opcodes": [ "C4", "02", "80", "F3", "2" ], "rm_to_vex": true },
-        "Blsrq": { "feature": "BMI", "opcodes": [ "C4", "02", "80", "F3", "1" ], "rm_to_vex": true },
+        "Blsiq": { "feature": "BMI", "opcodes": [ "C4", "02", "80", "F3", "3" ], "type": "rm_to_vex" },
+        "Blsmskq": { "feature": "BMI", "opcodes": [ "C4", "02", "80", "F3", "2" ], "type": "rm_to_vex" },
+        "Blsrq": { "feature": "BMI", "opcodes": [ "C4", "02", "80", "F3", "1" ], "type": "rm_to_vex" },
         "Bsfq": { "opcodes": [ "0F", "BC" ] },
         "Bsrq": { "opcodes": [ "0F", "BD" ] },
         "Lzcntq": { "feature": "LZCNT", "opcodes": [ "F3", "0F", "BD" ] },
@@ -205,9 +205,9 @@
     },
     {
       "encodings": {
-        "Btq": { "opcodes": [ "0F", "A3" ], "reg_to_rm": true },
-        "Cmpq": { "opcodes": [ "39" ], "reg_to_rm": true },
-        "Testq": { "opcodes": [ "85" ], "reg_to_rm": true }
+        "Btq": { "opcodes": [ "0F", "A3" ], "type": "reg_to_rm" },
+        "Cmpq": { "opcode": "39", "type": "reg_to_rm" },
+        "Testq": { "opcode": "85", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64/Mem64", "usage": "use" },
@@ -248,7 +248,7 @@
     {
       "encodings": {
         "CmpXchg16b": { "opcodes": [ "0F", "C7", "1" ] },
-        "LockCmpXchg16b": { "opcodes": [ "F0", "0F", "C7", "1" ] }
+        "Lock CmpXchg16b": { "opcodes": [ "F0", "0F", "C7", "1" ] }
       },
       "args": [
         { "class": "RAX", "usage": "use_def" },
@@ -261,7 +261,7 @@
     },
     {
       "encodings": {
-        "CmpXchgq": { "opcodes": [ "0F", "B1" ], "reg_to_rm": true }
+        "CmpXchgq": { "opcodes": [ "0F", "B1" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "RAX", "usage": "use_def" },
@@ -283,7 +283,7 @@
     },
     {
       "encodings": {
-        "Cmpq": { "opcodes": [ "3B" ] }
+        "Cmpq": { "opcode": "3B" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "use" },
@@ -449,7 +449,7 @@
     },
     {
       "encodings": {
-        "Imulq": { "opcodes": [ "69" ] }
+        "Imulq": { "opcode": "69" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
@@ -470,7 +470,7 @@
     },
     {
       "encodings": {
-        "ImulqImm8": { "opcodes": [ "6B" ] }
+        "ImulqImm8": { "opcode": "6B" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
@@ -489,17 +489,16 @@
     },
     {
       "encodings": {
-        "Leaq": { "opcodes": [ "8D" ] },
-        "Movq": { "opcodes": [ "8B" ] }
+        "Leaq": { "opcode": "8D" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
-        { "class": "Mem64", "usage": "use" }
+        { "class": "Mem", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "LockCmpXchgq": { "opcodes": [ "F0", "0F", "B1" ], "reg_to_rm": true }
+        "Lock CmpXchgq": { "opcodes": [ "F0", "0F", "B1" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "RAX", "usage": "use_def" },
@@ -510,8 +509,8 @@
     },
     {
       "encodings": {
-        "Movq": { "opcodes": [ "66", "0F", "7E" ], "reg_to_rm": true },
-        "Vmovq": { "feature": "AVX", "opcodes": [ "C4", "01", "81", "7E" ], "reg_to_rm": true }
+        "Movq": { "opcodes": [ "66", "0F", "7E" ], "type": "reg_to_rm" },
+        "Vmovq": { "feature": "AVX", "opcodes": [ "C4", "01", "81", "7E" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
@@ -537,13 +536,22 @@
     },
     {
       "encodings": {
-        "Movq": { "opcodes": [ "89" ], "reg_to_rm": true }
+        "Movq": { "opcode": "89", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64/Mem64", "usage": "def" },
         { "class": "GeneralReg64", "usage": "use" }
       ]
     },
+    {
+      "encodings": {
+        "Movq": { "opcode": "8B" }
+      },
+      "args": [
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "Mem64", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "Movq": { "opcodes": [ "C7", "0" ] }
@@ -565,7 +573,7 @@
     },
     {
       "encodings": {
-        "Movsxlq": { "opcodes": [ "63" ] }
+        "Movsxlq": { "opcode": "63" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
@@ -584,9 +592,9 @@
     },
     {
       "encodings": {
-        "Mulxq": { "feature": "BMI2", "opcodes": [ "C4", "82", "83", "F6" ], "vex_rm_to_reg": true },
-        "Pdepq": { "feature": "BMI2", "opcodes": [ "C4", "82", "83", "F5" ], "vex_rm_to_reg": true },
-        "Pextq": { "feature": "BMI2", "opcodes": [ "C4", "82", "82", "F5" ], "vex_rm_to_reg": true }
+        "Mulxq": { "feature": "BMI2", "opcodes": [ "C4", "82", "83", "F6" ], "type": "vex_rm_to_reg" },
+        "Pdepq": { "feature": "BMI2", "opcodes": [ "C4", "82", "83", "F5" ], "type": "vex_rm_to_reg" },
+        "Pextq": { "feature": "BMI2", "opcodes": [ "C4", "82", "82", "F5" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "use_def" },
@@ -604,8 +612,8 @@
     },
     {
       "encodings": {
-        "Pextrq": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "16" ], "reg_to_rm": true },
-        "Vpextrq": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "16" ], "reg_to_rm": true }
+        "Pextrq": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "16" ], "type": "reg_to_rm" },
+        "Vpextrq": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "16" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
@@ -700,8 +708,8 @@
     },
     {
       "encodings": {
-        "Shldq": { "opcodes": [ "0F", "A4" ], "reg_to_rm": true },
-        "Shrdq": { "opcodes": [ "0F", "AC" ], "reg_to_rm": true }
+        "Shldq": { "opcodes": [ "0F", "A4" ], "type": "reg_to_rm" },
+        "Shrdq": { "opcodes": [ "0F", "AC" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64/Mem64", "usage": "use_def" },
@@ -712,8 +720,8 @@
     },
     {
       "encodings": {
-        "ShldqByCl": { "opcodes": [ "0F", "A5" ], "reg_to_rm": true },
-        "ShrdqByCl": { "opcodes": [ "0F", "AD" ], "reg_to_rm": true }
+        "ShldqByCl": { "opcodes": [ "0F", "A5" ], "type": "reg_to_rm" },
+        "ShrdqByCl": { "opcodes": [ "0F", "AD" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64/Mem64", "usage": "use_def" },
@@ -740,7 +748,7 @@
     },
     {
       "encodings": {
-        "Vpinsrq": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "22" ], "vex_rm_to_reg": true }
+        "Vpinsrq": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "22" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -758,7 +766,7 @@
     },
     {
       "encodings": {
-        "Xchgq": { "opcodes": [ "87" ] }
+        "Xchgq": { "opcode": "87" }
       },
       "args": [
         { "class": "GeneralReg64", "usage": "use_def" },
diff --git a/backend/common/machine_ir_debug.cc b/backend/common/machine_ir_debug.cc
index 448a2c34..a3036e03 100644
--- a/backend/common/machine_ir_debug.cc
+++ b/backend/common/machine_ir_debug.cc
@@ -19,6 +19,7 @@
 #include <string>
 
 #include "berberis/base/stringprintf.h"
+#include "berberis/guest_state/guest_addr.h"
 
 namespace berberis {
 
@@ -79,6 +80,14 @@ std::string MachineBasicBlock::GetDebugString() const {
   }
   out += "]\n";
 
+  if (guest_addr() != kNullGuestAddr) {
+    // Profile counter may exist only if guest-addr is set, so we print them together.
+    out += StringPrintf("    [GuestAddr=%p ProfCounter=", ToHostAddr<void>(guest_addr()));
+    out += profile_counter().has_value() ? StringPrintf("%" PRIu32 "]", profile_counter().value())
+                                         : "unknown]";
+    out += "\n";
+  }
+
   for (const auto* edge : in_edges()) {
     out += StringPrintf("    MachineEdge %d -> %d [\n", edge->src()->id(), edge->dst()->id());
     out += GetInsnListDebugString("      ", edge->insn_list());
diff --git a/backend/include/berberis/backend/common/machine_ir.h b/backend/include/berberis/backend/common/machine_ir.h
index 26839367..779ed4e9 100644
--- a/backend/include/berberis/backend/common/machine_ir.h
+++ b/backend/include/berberis/backend/common/machine_ir.h
@@ -23,6 +23,7 @@
 #include <cstddef>
 #include <cstdint>
 #include <limits>
+#include <optional>
 #include <string>
 
 #include "berberis/backend/code_emitter.h"
@@ -315,6 +316,8 @@ class MachineBasicBlock {
  public:
   MachineBasicBlock(Arena* arena, uint32_t id)
       : id_(id),
+        guest_addr_(kNullGuestAddr),
+        profile_counter_(0),
         insn_list_(arena),
         in_edges_(arena),
         out_edges_(arena),
@@ -324,6 +327,12 @@ class MachineBasicBlock {
 
   [[nodiscard]] uint32_t id() const { return id_; }
 
+  [[nodiscard]] GuestAddr guest_addr() const { return guest_addr_; }
+  void set_guest_addr(GuestAddr addr) { guest_addr_ = addr; }
+
+  [[nodiscard]] std::optional<uint32_t> profile_counter() const { return profile_counter_; }
+  void set_profile_counter(uint32_t counter) { profile_counter_ = counter; }
+
   [[nodiscard]] const MachineInsnList& insn_list() const { return insn_list_; }
   [[nodiscard]] MachineInsnList& insn_list() { return insn_list_; }
 
@@ -347,6 +356,8 @@ class MachineBasicBlock {
 
  private:
   const uint32_t id_;
+  GuestAddr guest_addr_;
+  std::optional<uint32_t> profile_counter_;
   MachineInsnList insn_list_;
   MachineEdgeVector in_edges_;
   MachineEdgeVector out_edges_;
diff --git a/backend/x86_64/machine_insn_intrinsics_tests.cc b/backend/x86_64/machine_insn_intrinsics_tests.cc
index 8e667156..5388c8b4 100644
--- a/backend/x86_64/machine_insn_intrinsics_tests.cc
+++ b/backend/x86_64/machine_insn_intrinsics_tests.cc
@@ -17,7 +17,7 @@
 #include "gtest/gtest.h"
 
 #include "berberis/backend/x86_64/machine_insn_intrinsics.h"
-#include "berberis/intrinsics/common_to_x86/intrinsics_bindings.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
 #include "berberis/intrinsics/intrinsics_args.h"
 
 namespace berberis {
diff --git a/backend/x86_64/reg_class_def.json b/backend/x86_64/reg_class_def.json
index bd29f71a..20deebc6 100644
--- a/backend/x86_64/reg_class_def.json
+++ b/backend/x86_64/reg_class_def.json
@@ -18,7 +18,12 @@
     {
       "name": "GeneralReg64",
       "size": 8,
+      "comment": ["Legacy registers (those other than r8-15) save a byte in ",
+	          "encoding, but RAX, RCX and RDX are often implicit operands"],
       "regs": [
+        "RDI",
+        "RSI",
+        "RBX",
         "R10",
         "R11",
         "R13",
@@ -27,33 +32,32 @@
         "R8",
         "R9",
         "RDX",
-        "RBX",
         "R12",
         "RCX",
-        "RAX",
-        "RSI",
-        "RDI"
+        "RAX"
       ]
     },
     {
       "name": "XmmReg",
       "size": 16,
+      "comment": ["XMM0-7 save a byte in encoding, but XMM0 can be ",
+	          "an implicit operand in some instructions"],
       "regs": [
-        "XMM15",
-        "XMM14",
-        "XMM13",
-        "XMM12",
-        "XMM11",
-        "XMM10",
-        "XMM9",
-        "XMM8",
-        "XMM7",
-        "XMM6",
-        "XMM5",
-        "XMM4",
-        "XMM3",
-        "XMM2",
         "XMM1",
+        "XMM2",
+        "XMM3",
+        "XMM4",
+        "XMM5",
+        "XMM6",
+        "XMM7",
+        "XMM8",
+        "XMM9",
+        "XMM10",
+        "XMM11",
+        "XMM12",
+        "XMM13",
+        "XMM14",
+        "XMM15",
         "XMM0"
       ]
     },
@@ -353,4 +357,4 @@
       ]
     }
   ]
-}
\ No newline at end of file
+}
diff --git a/base/Android.bp b/base/Android.bp
index 0f0733d2..7ba8a049 100644
--- a/base/Android.bp
+++ b/base/Android.bp
@@ -19,16 +19,34 @@ package {
 
 cc_library_headers {
     name: "libberberis_base_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
+    native_bridge_supported: true,
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: ["libbase_headers"],
     export_header_lib_headers: ["libbase_headers"],
+    arch: {
+        arm: {
+            enabled: true,
+        },
+        arm64: {
+            enabled: true,
+        },
+        riscv64: {
+            enabled: true,
+        },
+        x86: {
+            enabled: true,
+        },
+        x86_64: {
+            enabled: true,
+        },
+    },
 }
 
 cc_library_static {
     name: "libberberis_base",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     srcs: [
         "config_globals.cc",
@@ -37,6 +55,7 @@ cc_library_static {
         "exec_region_anonymous.cc",
         "format_buffer.cc",
         "large_mmap.cc",
+        "maps_snapshot.cc",
         "mapped_file_fragment.cc",
         "memfd_backed_mmap.cc",
         "mmap_posix.cc",
@@ -44,13 +63,28 @@ cc_library_static {
         "tracing.cc",
     ],
     arch: {
+        arm64: {
+            srcs: ["raw_syscall_arm64.S"],
+        },
         x86: {
             srcs: ["raw_syscall_x86_32.S"],
         },
         x86_64: {
             srcs: ["raw_syscall_x86_64.S"],
         },
+        riscv64: {
+            srcs: ["raw_syscall_riscv64.S"],
+        },
     },
+
+    header_libs: ["libberberis_base_headers"],
+    export_header_lib_headers: ["libberberis_base_headers"],
+}
+
+cc_library_static {
+    name: "libberberis_base_elf_backed_exec_region",
+    defaults: ["berberis_all_hosts_defaults"],
+    host_supported: true,
     target: {
         bionic: {
             srcs: ["exec_region_elf_backed.cc"],
@@ -61,6 +95,21 @@ cc_library_static {
     export_header_lib_headers: ["libberberis_base_headers"],
 }
 
+// ATTENTION: do not use it outside of static tests!
+cc_library_static {
+    name: "libberberis_base_elf_backed_exec_region_for_static_tests",
+    defaults: ["berberis_all_hosts_defaults"],
+    host_supported: true,
+    target: {
+        bionic: {
+            srcs: ["exec_region_elf_backed_for_static_tests.cc"],
+        },
+    },
+
+    header_libs: ["libberberis_base_headers"],
+    export_header_lib_headers: ["libberberis_base_headers"],
+}
+
 cc_test_library {
     name: "libberberis_base_unit_tests",
     defaults: ["berberis_test_library_defaults"],
@@ -75,10 +124,17 @@ cc_test_library {
         "format_buffer_test.cc",
         "lock_free_stack_test.cc",
         "large_mmap_test.cc",
+        "maps_snapshot_test.cc",
         "memfd_backed_mmap_test.cc",
         "mmap_pool_test.cc",
         "pointer_and_counter_test.cc",
     ],
+    header_libs: ["libberberis_base_headers"],
+}
+
+cc_test_library {
+    name: "libberberis_base_elf_backed_exec_region_unit_tests",
+    defaults: ["berberis_test_library_defaults"],
     target: {
         bionic: {
             srcs: ["exec_region_elf_backed_test.cc"],
diff --git a/kernel_api/include/berberis/kernel_api/tracing.h b/base/exec_region_elf_backed_for_static_tests.cc
similarity index 59%
rename from kernel_api/include/berberis/kernel_api/tracing.h
rename to base/exec_region_elf_backed_for_static_tests.cc
index b140b0d9..d4b64fbb 100644
--- a/kernel_api/include/berberis/kernel_api/tracing.h
+++ b/base/exec_region_elf_backed_for_static_tests.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2016 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,18 +14,17 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_KERNEL_API_TRACING_H_
-#define BERBERIS_KERNEL_API_TRACING_H_
+#include "berberis/base/exec_region_elf_backed.h"
+
+#include "berberis/base/exec_region_anonymous.h"
 
 namespace berberis {
 
-void __attribute__((__format__(printf, 1, 2))) KernelApiTrace(const char* format, ...);
+// For static executables we cannot use dlopen_ext.
+// Use anonymous factory instead. Please do not use
+// this outside of static tests.
+ExecRegion ExecRegionElfBackedFactory::Create(size_t size) {
+  return ExecRegionAnonymousFactory::Create(size);
+}
 
 }  // namespace berberis
-
-#define KAPI_TRACE(...)                      \
-  do {                                       \
-    ::berberis::KernelApiTrace(__VA_ARGS__); \
-  } while (0)
-
-#endif  // BERBERIS_KERNEL_API_TRACING_H_
diff --git a/base/include/berberis/base/bit_util.h b/base/include/berberis/base/bit_util.h
index eb9adf43..ff348c87 100644
--- a/base/include/berberis/base/bit_util.h
+++ b/base/include/berberis/base/bit_util.h
@@ -725,7 +725,7 @@ using RawInt8 = Raw<uint8_t>;
 using RawInt16 = Raw<uint16_t>;
 using RawInt32 = Raw<uint32_t>;
 using RawInt64 = Raw<uint64_t>;
-#if defined(__x86_64__)
+#if defined(__LP64__)
 using RawInt128 = Raw<unsigned __int128>;
 #endif
 
@@ -737,7 +737,7 @@ using SatInt32 = Saturating<int32_t>;
 using SatUInt32 = Saturating<uint32_t>;
 using SatInt64 = Saturating<int64_t>;
 using SatUInt64 = Saturating<uint64_t>;
-#if defined(__x86_64__)
+#if defined(__LP64__)
 using SatInt128 = Saturating<__int128>;
 using SatUInt128 = Saturating<unsigned __int128>;
 #endif
@@ -752,7 +752,7 @@ using Int64 = Wrapping<int64_t>;
 using UInt64 = Wrapping<uint64_t>;
 using IntPtr = Wrapping<intptr_t>;
 using UIntPtr = Wrapping<uintptr_t>;
-#if defined(__x86_64__)
+#if defined(__LP64__)
 using Int128 = Wrapping<__int128>;
 using UInt128 = Wrapping<unsigned __int128>;
 #endif
diff --git a/base/include/berberis/base/checks.h b/base/include/berberis/base/checks.h
index fd04febe..99fcfb00 100644
--- a/base/include/berberis/base/checks.h
+++ b/base/include/berberis/base/checks.h
@@ -20,6 +20,7 @@
 #include <array>
 #include <cinttypes>
 
+#include "berberis/base/config.h"
 #include "berberis/base/logging.h"
 
 // Helpers for building message format, without incurring any function calls when the condition
@@ -60,6 +61,10 @@ class FmtSpec {
   }
 };
 
+constexpr auto&& ValueForFmtSpec(auto&& value) {
+  return std::forward<decltype(value)>(value);
+}
+
 }  // namespace berberis
 
 #define BERBERIS_VALUE_STR_IMPL(v) #v
@@ -73,6 +78,11 @@ class FmtSpec {
 
 #define UNREACHABLE() FATAL("This code is (supposed to be) unreachable.")
 
+#define FATAL_UNIMPL_INSN_IF_NOT_BRINGUP()           \
+  if (!berberis::config::kInstructionsBringupMode) { \
+    FATAL("Unimplemented instruction!");             \
+  }
+
 #ifdef CHECK
 #undef CHECK
 #endif
@@ -80,16 +90,26 @@ class FmtSpec {
 
 // TODO(b/232598137): fix multiple evaluation of v1 and v2!
 // TODO(b/232598137): change message from '1 == 0' to 'x == y (1 == 0)'!
-#define BERBERIS_CHECK_OP(op, v1, v2)                                                    \
-  LOG_ALWAYS_FATAL_IF(                                                                   \
-      !((v1)op(v2)), /* // NOLINT */                                                     \
-      []() {                                                                             \
-        constexpr static auto __fmt = berberis::FmtSpec::Fmt(                            \
-            BERBERIS_CHECK_PREFIX, " " #op " ", berberis::FmtSpec::kValue<decltype(v1)>, \
-            berberis::FmtSpec::kValue<decltype(v2)>);                                    \
-        return __fmt.data();                                                             \
-      }(),                                                                               \
-      v1, v2)
+#define BERBERIS_CHECK_OP(op, v1, v2)                                                         \
+  LOG_ALWAYS_FATAL_IF(                                                                        \
+      !((v1)op(v2)), /* // NOLINT */                                                          \
+      []() {                                                                                  \
+        using ::berberis::ValueForFmtSpec;                                                    \
+        constexpr static auto __fmt =                                                         \
+            berberis::FmtSpec::Fmt(BERBERIS_CHECK_PREFIX,                                     \
+                                   " " #op " ",                                               \
+                                   berberis::FmtSpec::kValue<decltype(ValueForFmtSpec(v1))>,  \
+                                   berberis::FmtSpec::kValue<decltype(ValueForFmtSpec(v2))>); \
+        return __fmt.data();                                                                  \
+      }(),                                                                                    \
+      ({                                                                                      \
+        using ::berberis::ValueForFmtSpec;                                                    \
+        ValueForFmtSpec(v1);                                                                  \
+      }),                                                                                     \
+      ({                                                                                      \
+        using ::berberis::ValueForFmtSpec;                                                    \
+        ValueForFmtSpec(v2);                                                                  \
+      }))
 
 #ifdef CHECK_EQ
 #undef CHECK_EQ
diff --git a/base/include/berberis/base/config.h b/base/include/berberis/base/config.h
index bd0323fc..308c2e4a 100644
--- a/base/include/berberis/base/config.h
+++ b/base/include/berberis/base/config.h
@@ -59,6 +59,8 @@ inline constexpr uint32_t kScratchAreaSize = 32;
 inline constexpr uint32_t kScratchAreaAlign = 16;
 // Scratch area slot size if more than one scratch is needed.
 inline constexpr uint32_t kScratchAreaSlotSize = 8;
+// Flag for testing mode of unimplemented instructions.
+inline constexpr bool kInstructionsBringupMode = false;
 
 }  // namespace berberis::config
 
diff --git a/base/include/berberis/base/dependent_false.h b/base/include/berberis/base/dependent_false.h
index f01a48e0..83005ebc 100644
--- a/base/include/berberis/base/dependent_false.h
+++ b/base/include/berberis/base/dependent_false.h
@@ -24,9 +24,27 @@ namespace berberis {
 template <typename T>
 inline constexpr bool kDependentTypeFalse = false;
 
-template <auto T>
+template <auto A>
 inline constexpr bool kDependentValueFalse = false;
 
+template <typename T>
+class ImpossibleTypeConst {
+  static_assert(false);
+  static constexpr bool kValue = false;
+};
+
+template <typename T>
+inline constexpr bool kImpossibleTypeConst = ImpossibleTypeConst<T>::kValue;
+
+template <auto A>
+class ImpossibleValueConst {
+  static_assert(false);
+  static constexpr bool kValue = false;
+};
+
+template <auto A>
+inline constexpr bool kImpossibleValueConst = ImpossibleValueConst<A>::kValue;
+
 }  // namespace berberis
 
 #endif  // BERBERIS_BASE_DEPENDENT_FALSE_H_
diff --git a/base/include/berberis/base/maps_snapshot.h b/base/include/berberis/base/maps_snapshot.h
new file mode 100644
index 00000000..3b0d8fe7
--- /dev/null
+++ b/base/include/berberis/base/maps_snapshot.h
@@ -0,0 +1,61 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef BERBERIS_BASE_INCLUDE_BERBERIS_BASE_MAPS_SNAPSHOT_H_
+#define BERBERIS_BASE_INCLUDE_BERBERIS_BASE_MAPS_SNAPSHOT_H_
+
+#include <cstdint>
+#include <mutex>
+#include <optional>
+
+#include "berberis/base/arena_alloc.h"
+#include "berberis/base/arena_map.h"
+#include "berberis/base/arena_string.h"
+
+namespace berberis {
+
+// Stores snapshot mappings from /proc/self/maps for faster access.
+// Can contain stale records which is fine for profiling or heuristics,
+// but do NOT use it where reliable mapping information is required.
+// Call Update() to reread /proc/self/maps.
+// Thread-safe, doesn't use malloc.
+class MapsSnapshot {
+ public:
+  static MapsSnapshot* GetInstance();
+  void Update();
+  // It's important that we return const ArenaString, since arena isn't thread-safe, and we should
+  // NOT be triggering re-allocations from outside of this class.
+  std::optional<const ArenaString> FindMappedObjectName(uintptr_t addr);
+  void ClearForTesting() {
+    std::scoped_lock lock(mutex_);
+    maps_.clear();
+  };
+
+ private:
+  MapsSnapshot() : arena_(), mutex_(), maps_(&arena_) {};
+  struct Record {
+    uintptr_t start;
+    uintptr_t end;
+    ArenaString pathname;
+  };
+  Arena arena_;
+  std::mutex mutex_;
+  ArenaMap<uintptr_t, Record> maps_;
+};
+
+}  // namespace berberis
+
+#endif  // BERBERIS_BASE_INCLUDE_BERBERIS_BASE_MAPS_SNAPSHOT_H_
diff --git a/base/include/berberis/base/mmap.h b/base/include/berberis/base/mmap.h
index cfe690d0..df74c1a8 100644
--- a/base/include/berberis/base/mmap.h
+++ b/base/include/berberis/base/mmap.h
@@ -34,7 +34,17 @@ constexpr T AlignDownPageSize(T x) {
 
 template <typename T>
 constexpr T AlignUpPageSize(T x) {
-  return AlignUp(x, kPageSize);
+  static_assert(!std::is_signed_v<T>);
+  T result = AlignUp(x, kPageSize);
+  CHECK_GE(result, x);
+  return result;
+}
+
+template <typename T>
+constexpr bool AlignUpPageSizeOverflow(T x, T* result) {
+  static_assert(!std::is_signed_v<T>);
+  *result = AlignUp(x, kPageSize);
+  return *result < x;
 }
 
 template <typename T>
diff --git a/base/include/berberis/base/pointer_and_counter.h b/base/include/berberis/base/pointer_and_counter.h
index 4a8a1c50..44aeb94a 100644
--- a/base/include/berberis/base/pointer_and_counter.h
+++ b/base/include/berberis/base/pointer_and_counter.h
@@ -32,23 +32,23 @@ struct PointerAndCounter {
   //     [counter][pointer-without-align-bits]
   // bit: 63                                0
   static_assert(sizeof(T*) == 8, "wrong pointer size");
-  static const size_t kPointerBits = 48;
-  static const size_t kAlignBits = BitUtilLog2(kAlign);
+  static constexpr size_t kPointerBits = 48;
+  static constexpr size_t kAlignBits = BitUtilLog2(kAlign);
 #else
   // 32-bit pointers and size_t. KISS.
   //     [counter][pointer]
   // bit: 63   32  31    0
   static_assert(sizeof(T*) == 4, "wrong pointer size");
-  static const size_t kPointerBits = 32;
-  static const size_t kAlignBits = 0;
+  static constexpr size_t kPointerBits = 32;
+  static constexpr size_t kAlignBits = 0;
 #endif
 
-  static const size_t kRealPointerBits = kPointerBits - kAlignBits;
-  static const size_t kCounterBits = 64 - kRealPointerBits;
+  static constexpr size_t kRealPointerBits = kPointerBits - kAlignBits;
+  static constexpr size_t kCounterBits = 64 - kRealPointerBits;
 
-  static const uint64_t kRealPointerMask = uint64_t(-1) >> kCounterBits;
+  static constexpr uint64_t kRealPointerMask = uint64_t(-1) >> kCounterBits;
 
-  static const uint64_t kMaxCounter = uint64_t(1) << kCounterBits;
+  static constexpr uint64_t kMaxCounter = uint64_t(1) << kCounterBits;
 
   // ATTENTION: counter might get truncated!
   static uint64_t PackUnsafe(T* p, uint64_t cnt) {
diff --git a/base/maps_snapshot.cc b/base/maps_snapshot.cc
new file mode 100644
index 00000000..48218bf1
--- /dev/null
+++ b/base/maps_snapshot.cc
@@ -0,0 +1,80 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "berberis/base/maps_snapshot.h"
+
+#include <cstdint>
+#include <cstdio>
+#include <mutex>
+#include <optional>
+
+#include "berberis/base/arena_string.h"
+#include "berberis/base/tracing.h"
+
+namespace berberis {
+
+MapsSnapshot* MapsSnapshot::GetInstance() {
+  static MapsSnapshot g_maps_snapshot;
+  return &g_maps_snapshot;
+}
+
+void MapsSnapshot::Update() {
+  std::scoped_lock lock(mutex_);
+
+  FILE* maps_file = fopen("/proc/self/maps", "r");
+  if (!maps_file) {
+    TRACE("Error opening /proc/self/maps");
+    return;
+  }
+
+  maps_.clear();
+
+  char line[512], pathname[256];
+  uintptr_t start, end;
+  while (fgets(line, sizeof(line), maps_file)) {
+    // Maximum string size 255 so that we have space for the terminating '\0'.
+    int match_count = sscanf(
+        line, "%" SCNxPTR "-%" SCNxPTR " %*s %*lx %*x:%*x %*lu%*[ ]%255s", &start, &end, pathname);
+    if (match_count == 2 || match_count == 3) {
+      // If there is no pathname we still memorize the record, so that we can differentiate this
+      // case from missing mapping, e.g. when the snapshot is not up to date.
+      const char* recorded_pathname = (match_count == 3) ? pathname : "";
+      // Addresses go in the increasing order in /proc/self/maps, so we hint to add new records
+      // to the end of the map.
+      maps_.emplace_hint(
+          maps_.end(), start, Record{start, end, ArenaString{recorded_pathname, &arena_}});
+    }
+  }
+
+  fclose(maps_file);
+}
+
+std::optional<const ArenaString> MapsSnapshot::FindMappedObjectName(uintptr_t addr) {
+  std::scoped_lock lock(mutex_);
+  auto next_it = maps_.upper_bound(addr);
+  if (next_it == maps_.begin()) {
+    return std::nullopt;
+  }
+  auto& rec = std::prev(next_it)->second;
+  if (addr >= rec.start && addr < rec.end) {
+    // Make sure we return a copy since the storage may be
+    // invalidated as soon as we release the lock.
+    return rec.pathname;
+  }
+  return std::nullopt;
+}
+
+}  // namespace berberis
diff --git a/base/maps_snapshot_test.cc b/base/maps_snapshot_test.cc
new file mode 100644
index 00000000..1984bf86
--- /dev/null
+++ b/base/maps_snapshot_test.cc
@@ -0,0 +1,110 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "gtest/gtest.h"
+
+#include "sys/mman.h"
+
+#include <cstdint>
+#include <cstdio>
+#include <cstring>  // strncmp
+#include <memory>
+#include <string>
+#include <tuple>
+
+#include "berberis/base/maps_snapshot.h"
+
+namespace berberis {
+
+namespace {
+
+void Foo() {};
+
+TEST(MapsSnapshot, Basic) {
+  auto* maps_snapshot = MapsSnapshot::GetInstance();
+
+  maps_snapshot->ClearForTesting();
+
+  // No mappings can be found before snapshot is taken by Update().
+  auto no_mappings_result = maps_snapshot->FindMappedObjectName(reinterpret_cast<uintptr_t>(&Foo));
+  ASSERT_FALSE(no_mappings_result.has_value());
+
+  maps_snapshot->Update();
+
+  auto result = maps_snapshot->FindMappedObjectName(reinterpret_cast<uintptr_t>(&Foo));
+  ASSERT_TRUE(result.has_value());
+  ASSERT_FALSE(result.value().empty());
+}
+
+TEST(MapsSnapshot, AnonymousMapping) {
+  auto* maps_snapshot = MapsSnapshot::GetInstance();
+
+  void* addr = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
+  ASSERT_NE(addr, MAP_FAILED);
+  maps_snapshot->Update();
+  auto result = maps_snapshot->FindMappedObjectName(reinterpret_cast<uintptr_t>(addr));
+  munmap(addr, 4096);
+
+  ASSERT_TRUE(result.has_value());
+  ASSERT_TRUE(result.value().empty());
+}
+
+std::tuple<uintptr_t, std::string> GetAddressOfFirstMappingWithSubstring(std::string substr) {
+  std::unique_ptr<FILE, decltype(&fclose)> maps_file(fopen("/proc/self/maps", "r"), fclose);
+  if (maps_file == nullptr) {
+    ADD_FAILURE() << "Cannot open /proc/self/maps";
+    return {0, ""};
+  }
+
+  char line[512], pathname[256];
+  uintptr_t start;
+  while (fgets(line, sizeof(line), maps_file.get())) {
+    // Maximum string size 255 so that we have space for the terminating '\0'.
+    int match_count = sscanf(
+        line, "%" SCNxPTR "-%*" SCNxPTR " %*s %*lx %*x:%*x %*lu%*[ ]%255s", &start, pathname);
+    if (match_count == 2) {
+      std::string current_pathname(pathname);
+      if (current_pathname.find(substr) != current_pathname.npos) {
+        return {start, current_pathname};
+      }
+    }
+  }
+  ADD_FAILURE() << "Cannot find " << substr << " in /proc/self/maps";
+  return {0, ""};
+}
+
+TEST(MapsSnapshot, ExactFilenameMatch) {
+  auto* maps_snapshot = MapsSnapshot::GetInstance();
+
+  // Take some object that must be mapped already and is unlikely to be suddenly unmapped. "libc.so"
+  // may have a version suffix like "libc-2.19.so", which would make parsing too challenging for
+  // what this test requires. We don't want to search just for "libc" either since it's likely to
+  // match an unrelated library. "libc++.so" is taken from the local build
+  // (out/host/linux-x86/lib64/libc++.so) so we should be able to find it.
+  auto [addr, pathname] = GetAddressOfFirstMappingWithSubstring("libc++.so");
+  ASSERT_GT(addr, 0u);
+
+  maps_snapshot->Update();
+  auto result = maps_snapshot->FindMappedObjectName(reinterpret_cast<uintptr_t>(addr));
+
+  ASSERT_TRUE(result.has_value());
+  // MapsSnapshot only stores first 255 symbols plus terminating null.
+  ASSERT_TRUE(strncmp(result.value().c_str(), pathname.c_str(), 255) == 0);
+}
+
+}  // namespace
+
+}  // namespace berberis
diff --git a/base/raw_syscall_arm64.S b/base/raw_syscall_arm64.S
new file mode 100644
index 00000000..5f4380af
--- /dev/null
+++ b/base/raw_syscall_arm64.S
@@ -0,0 +1,37 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+  .globl berberis_RawSyscallImpl
+  .balign 16
+
+berberis_RawSyscallImpl:
+  // The aapcs64 ABI passes the first RawSyscallImpl param (the syscall number) in x0.
+  // The arm64 syscall ABI passes the syscall number in x8.
+
+  // Move the syscall number up.
+  mov x8, x0
+
+  // Shift the arguments down.
+  mov x0, x1
+  mov x1, x2
+  mov x2, x3
+  mov x3, x4
+  mov x4, x5
+  mov x5, x6
+
+  svc #0
+
+  ret
diff --git a/base/raw_syscall_riscv64.S b/base/raw_syscall_riscv64.S
new file mode 100644
index 00000000..b1bbb611
--- /dev/null
+++ b/base/raw_syscall_riscv64.S
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+  .globl berberis_RawSyscallImpl
+  .balign 16
+
+berberis_RawSyscallImpl:
+  // Move the syscall number up.
+  mv a7, a0
+
+  // Shuffle the arguments down.
+  mv a0, a1
+  mv a1, a2
+  mv a2, a3
+  mv a3, a4
+  mv a4, a5
+  mv a5, a6
+
+  ecall
+
+  ret
diff --git a/berberis_config.mk b/berberis_config.mk
index 511fd0a3..a479411b 100644
--- a/berberis_config.mk
+++ b/berberis_config.mk
@@ -15,21 +15,15 @@
 #
 
 # This file defines:
-#   BERBERIS_PRODUCT_PACKAGES - list of main product packages
-#   BERBERIS_DEV_PRODUCT_PACKAGES - list of development packages
+#   BERBERIS_PRODUCT_PACKAGES_RISCV64_TO_X86_64 - list of main product packages for riscv64 to
+#                                                 x86_64 translation.
 #
 
 include frameworks/libs/native_bridge_support/native_bridge_support.mk
 
-# Note: When modifying this variable, please also update the `phony_deps` of
-#       `berberis_deps_defaults` in frameworks/libs/binary_translation/Android.bp.
-BERBERIS_PRODUCT_PACKAGES := \
-    libberberis_exec_region
-
-# Note: When modifying this variable, please also update the `phony_deps` of
-#       `berberis_riscv64_to_x86_64_defaults` in
-#       frameworks/libs/binary_translation/Android.bp.
+# Note: Keep in sync with `berberis_all_riscv64_to_x86_64_defaults` in Android.bp.
 BERBERIS_PRODUCT_PACKAGES_RISCV64_TO_X86_64 := \
+    libberberis_exec_region \
     libberberis_proxy_libEGL \
     libberberis_proxy_libGLESv1_CM \
     libberberis_proxy_libGLESv2 \
@@ -59,26 +53,6 @@ BERBERIS_PRODUCT_PACKAGES_RISCV64_TO_X86_64 := \
 # when all its bits are ready for riscv64.
 BERBERIS_PRODUCT_PACKAGES_RISCV64_TO_X86_64 += $(NATIVE_BRIDGE_PRODUCT_PACKAGES_RISCV64_READY)
 
-# Note: When modifying this variable, please also update the `phony_deps` of
-#       `berberis_riscv64_to_x86_64_defaults` in
-#       frameworks/libs/binary_translation/Android.bp.
-BERBERIS_DEV_PRODUCT_PACKAGES := \
-    berberis_hello_world.native_bridge \
-    berberis_hello_world_static.native_bridge \
-    berberis_host_tests \
-    berberis_ndk_program_tests \
-    berberis_ndk_program_tests.native_bridge \
-    dwarf_reader \
-    libberberis_emulated_libcamera2ndk_api_checker \
-    nogrod_unit_tests \
-    gen_intrinsics_tests
-
-# Note: When modifying this variable, please also update the `phony_deps` of
-#       `berberis_riscv64_to_x86_64_defaults` in
-#       frameworks/libs/binary_translation/Android.bp.
-BERBERIS_DEV_PRODUCT_PACKAGES_RISCV64_TO_X86_64 := \
-    berberis_guest_loader_riscv64_tests
-
 BERBERIS_DISTRIBUTION_ARTIFACTS_RISCV64 := \
     system/bin/berberis_program_runner_binfmt_misc_riscv64 \
     system/bin/berberis_program_runner_riscv64 \
diff --git a/calling_conventions/Android.bp b/calling_conventions/Android.bp
index b2381bb8..a09c37df 100644
--- a/calling_conventions/Android.bp
+++ b/calling_conventions/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_calling_conventions_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: ["libberberis_base_headers"],
diff --git a/calling_conventions/calling_conventions_x86_64_test.cc b/calling_conventions/calling_conventions_x86_64_test.cc
index ed8f1083..69eb3517 100644
--- a/calling_conventions/calling_conventions_x86_64_test.cc
+++ b/calling_conventions/calling_conventions_x86_64_test.cc
@@ -27,72 +27,72 @@ TEST(CallingConventions_x86_64, Smoke) {
   ArgLocation loc;
 
   loc = conv.GetNextIntArgLoc(1, 1);
-  EXPECT_EQ(kArgLocationInt, loc.kind);
-  EXPECT_EQ(0u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationInt);
+  EXPECT_EQ(loc.offset, 0u);
 
   loc = conv.GetNextIntArgLoc(16, 16);
-  EXPECT_EQ(kArgLocationInt, loc.kind);
-  EXPECT_EQ(1u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationInt);
+  EXPECT_EQ(loc.offset, 1u);
 
   loc = conv.GetNextIntArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationInt, loc.kind);
-  EXPECT_EQ(3u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationInt);
+  EXPECT_EQ(loc.offset, 3u);
 
   loc = conv.GetNextIntArgLoc(16, 16);
-  EXPECT_EQ(kArgLocationInt, loc.kind);
-  EXPECT_EQ(4u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationInt);
+  EXPECT_EQ(loc.offset, 4u);
 
   loc = conv.GetNextIntArgLoc(1, 1);
-  EXPECT_EQ(kArgLocationStack, loc.kind);
-  EXPECT_EQ(0u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationStack);
+  EXPECT_EQ(loc.offset, 0u);
 
   loc = conv.GetNextIntArgLoc(1, 1);
-  EXPECT_EQ(kArgLocationStack, loc.kind);
-  EXPECT_EQ(8u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationStack);
+  EXPECT_EQ(loc.offset, 8u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(0u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 0u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(1u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 1u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(2u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 2u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(3u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 3u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(4u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 4u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(5u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 5u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(6u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 6u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(7u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 7u);
 
   loc = conv.GetNextFpArgLoc(8, 8);
-  EXPECT_EQ(kArgLocationStack, loc.kind);
-  EXPECT_EQ(16u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationStack);
+  EXPECT_EQ(loc.offset, 16u);
 
   loc = conv.GetIntResLoc(1);
-  EXPECT_EQ(kArgLocationIntOut, loc.kind);
-  EXPECT_EQ(0u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationIntOut);
+  EXPECT_EQ(loc.offset, 0u);
 
   loc = conv.GetFpResLoc(8);
-  EXPECT_EQ(kArgLocationSimd, loc.kind);
-  EXPECT_EQ(0u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationSimd);
+  EXPECT_EQ(loc.offset, 0u);
 }
 
 TEST(CallingConventions_x86_64, LastIntRegUsed) {
@@ -105,18 +105,18 @@ TEST(CallingConventions_x86_64, LastIntRegUsed) {
   conv.GetNextIntArgLoc(4, 4);
   conv.GetNextIntArgLoc(4, 4);
   loc = conv.GetNextIntArgLoc(4, 4);
-  EXPECT_EQ(kArgLocationInt, loc.kind);
-  EXPECT_EQ(4u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationInt);
+  EXPECT_EQ(loc.offset, 4u);
 
   // Add param that doesn't fit in the last reg.
   loc = conv.GetNextIntArgLoc(16, 16);
-  EXPECT_EQ(kArgLocationStack, loc.kind);
-  EXPECT_EQ(0u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationStack);
+  EXPECT_EQ(loc.offset, 0u);
 
   // Add param that fits in the last reg.
   loc = conv.GetNextIntArgLoc(4, 4);
-  EXPECT_EQ(kArgLocationInt, loc.kind);
-  EXPECT_EQ(5u, loc.offset);
+  EXPECT_EQ(loc.kind, kArgLocationInt);
+  EXPECT_EQ(loc.offset, 5u);
 }
 
 }  // namespace
diff --git a/code_gen_lib/Android.bp b/code_gen_lib/Android.bp
index 9782ae53..ca7587d4 100644
--- a/code_gen_lib/Android.bp
+++ b/code_gen_lib/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_code_gen_lib_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: [
diff --git a/decoder/Android.bp b/decoder/Android.bp
index 211f9680..a4235131 100644
--- a/decoder/Android.bp
+++ b/decoder/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_decoder_riscv64_headers",
-    defaults: ["berberis_defaults_64"],
+    defaults: ["berberis_all_hosts_defaults_64"],
     header_libs: ["libberberis_base_headers"],
     host_supported: true,
     export_include_dirs: ["include"],
diff --git a/decoder/include/berberis/decoder/riscv64/decoder.h b/decoder/include/berberis/decoder/riscv64/decoder.h
index 7c6aebcc..80fffa00 100644
--- a/decoder/include/berberis/decoder/riscv64/decoder.h
+++ b/decoder/include/berberis/decoder/riscv64/decoder.h
@@ -146,6 +146,10 @@ class Decoder {
 
   enum class OpSingleInputOpcode : uint16_t {
     kZexth = 0b0000'100'100,
+    kZextb,
+    kZextw,
+    kSextb,
+    kSexth,
   };
 
   enum class OpFpGpRegisterTargetNoRoundingOpcode : uint8_t {
@@ -312,9 +316,9 @@ class Decoder {
     kVfmsacvv = 0b101110,
     kVfnmsacvv = 0b101111,
     kVfwaddvv = 0b110000,
-    kVfwredusumvv = 0b110001,
+    kVfwredusumvs = 0b110001,
     kVfwsubvv = 0b110010,
-    kVfwredosumvv = 0b110011,
+    kVfwredosumvs = 0b110011,
     kVfwaddwv = 0b110100,
     kVfwsubwv = 0b110110,
     kVfwmulvv = 0b111000,
@@ -393,8 +397,8 @@ class Decoder {
     kVnsrawv = 0b101101,
     kVnclipuwv = 0b101110,
     kVnclipwv = 0b101111,
-    kVwredsumuvv = 0b110000,
-    kVwredsumvv = 0b110001,
+    kVwredsumuvs = 0b110000,
+    kVwredsumvs = 0b110001,
   };
 
   enum class VOpIVxOpcode : uint8_t {
@@ -590,6 +594,7 @@ class Decoder {
     kVsextvf4m = 0b00101,
     kVzextvf2m = 0b00110,
     kVsextvf2m = 0b00111,
+    kVbrev8v = 0b01000,
   };
 
   // Load/Store instruction include 3bit “width” field while all other floating-point instructions
@@ -1141,6 +1146,34 @@ class Decoder {
     uint8_t low_imm = GetBits<2, 5>();
     uint8_t high_imm = GetBits<12, 1>();
     uint8_t imm = (high_imm << 5) + low_imm;
+    uint8_t zc_high_opcode_bits = GetBits<10, 3>();
+    uint16_t zc_opcode{static_cast<uint16_t>(low_imm | (zc_high_opcode_bits << 5))};
+
+    std::optional<OpSingleInputOpcode> si_opcode;
+    switch (zc_opcode) {
+      case 0b111'11'010:
+        si_opcode = OpSingleInputOpcode::kZexth;
+        break;
+      case 0b111'11'000:
+        si_opcode = OpSingleInputOpcode::kZextb;
+        break;
+      case 0b111'11'100:
+        si_opcode = OpSingleInputOpcode::kZextw;
+        break;
+      case 0b111'11'001:
+        si_opcode = OpSingleInputOpcode::kSextb;
+        break;
+      case 0b111'11'011:
+        si_opcode = OpSingleInputOpcode::kSexth;
+        break;
+      default:
+        break;
+    }
+    if (si_opcode.has_value()) {
+      const OpSingleInputArgs args = {.opcode = si_opcode.value(), .dst = r, .src = r};
+      return insn_consumer_->OpSingleInput(args);
+    }
+
     switch (GetBits<10, 2>()) {
       case 0b00: {
         const ShiftImmArgs args = {
diff --git a/decoder/include/berberis/decoder/riscv64/semantics_player.h b/decoder/include/berberis/decoder/riscv64/semantics_player.h
index eedb6fdf..c9c53e42 100644
--- a/decoder/include/berberis/decoder/riscv64/semantics_player.h
+++ b/decoder/include/berberis/decoder/riscv64/semantics_player.h
@@ -30,9 +30,11 @@ class SemanticsPlayer {
   using CsrName = typename SemanticsListener::CsrName;
   using Decoder = Decoder<SemanticsPlayer>;
   using Register = typename SemanticsListener::Register;
+  static constexpr Register no_register = SemanticsListener::no_register;
   using Float32 = typename SemanticsListener::Float32;
   using Float64 = typename SemanticsListener::Float64;
   using FpRegister = typename SemanticsListener::FpRegister;
+  static constexpr FpRegister no_fp_register = SemanticsListener::no_fp_register;
 
   explicit SemanticsPlayer(SemanticsListener* listener) : listener_(listener) {}
 
@@ -41,7 +43,7 @@ class SemanticsPlayer {
   void Amo(const typename Decoder::AmoArgs& args) {
     Register arg1 = GetRegOrZero(args.src1);
     Register arg2 = GetRegOrZero(args.src2);
-    Register result;
+    Register result = no_register;
     switch (args.operand_type) {
       case Decoder::MemoryDataOperandType::k32bit:
         result = Amo<int32_t>(args.opcode, arg1, arg2, args.aq, args.rl);
@@ -100,7 +102,7 @@ class SemanticsPlayer {
         return listener_->template AmoMax<std::make_unsigned_t<IntType>, aq, rl>(arg1, arg2);
       default:
         Undefined();
-        return {};
+        return no_register;
     }
   }
 
@@ -211,7 +213,7 @@ class SemanticsPlayer {
                          int8_t src) {
     FpRegister arg = GetFRegAndUnboxNan<FLoatType>(src);
     Register frm = listener_->template GetCsr<CsrName::kFrm>();
-    Register result;
+    Register result = no_register;
     switch (dst_type) {
       case Decoder::FcvtOperandType::k32bitSigned:
         result = listener_->template FCvtFloatToInteger<int32_t, FLoatType>(rm, frm, arg);
@@ -249,7 +251,7 @@ class SemanticsPlayer {
                           int8_t src) {
     Register arg = GetRegOrZero(src);
     Register frm = listener_->template GetCsr<CsrName::kFrm>();
-    FpRegister result;
+    FpRegister result = no_fp_register;
     switch (src_type) {
       case Decoder::FcvtOperandType::k32bitSigned:
         result = listener_->template FCvtIntegerToFloat<FloatType, int32_t>(rm, frm, arg);
@@ -294,7 +296,7 @@ class SemanticsPlayer {
     FpRegister arg2 = GetFRegAndUnboxNan<FloatType>(src2);
     FpRegister arg3 = GetFRegAndUnboxNan<FloatType>(src3);
     Register frm = listener_->template GetCsr<CsrName::kFrm>();
-    FpRegister result;
+    FpRegister result = no_fp_register;
     switch (opcode) {
       case Decoder::FmaOpcode::kFmadd:
         result = listener_->template FMAdd<FloatType>(rm, frm, arg1, arg2, arg3);
@@ -328,7 +330,7 @@ class SemanticsPlayer {
   void Fence(const typename Decoder::FenceArgs& args) {
     listener_->Fence(args.opcode,
                      // args.src is currently unused - read below.
-                     Register{},
+                     no_register,
                      args.sw,
                      args.sr,
                      args.so,
@@ -480,10 +482,22 @@ class SemanticsPlayer {
 
   void OpSingleInput(const typename Decoder::OpSingleInputArgs& args) {
     Register arg = GetRegOrZero(args.src);
-    Register result;
+    Register result = no_register;
     switch (args.opcode) {
+      case Decoder::OpSingleInputOpcode::kZextb:
+        result = listener_->template Zext<uint8_t>(arg);
+        break;
       case Decoder::OpSingleInputOpcode::kZexth:
-        result = listener_->Zexth(arg);
+        result = listener_->template Zext<uint16_t>(arg);
+        break;
+      case Decoder::OpSingleInputOpcode::kZextw:
+        result = listener_->template Zext<uint32_t>(arg);
+        break;
+      case Decoder::OpSingleInputOpcode::kSextb:
+        result = listener_->template Sext<int8_t>(arg);
+        break;
+      case Decoder::OpSingleInputOpcode::kSexth:
+        result = listener_->template Sext<int16_t>(arg);
         break;
       default:
         Undefined();
@@ -508,7 +522,7 @@ class SemanticsPlayer {
     FpRegister arg1 = GetFRegAndUnboxNan<FloatType>(src1);
     FpRegister arg2 = GetFRegAndUnboxNan<FloatType>(src2);
     Register frm = listener_->template GetCsr<CsrName::kFrm>();
-    FpRegister result;
+    FpRegister result = no_fp_register;
     switch (opcode) {
       case Decoder::OpFpOpcode::kFAdd:
         result = listener_->template FAdd<FloatType>(rm, frm, arg1, arg2);
@@ -548,7 +562,7 @@ class SemanticsPlayer {
                                       int8_t src2) {
     FpRegister arg1 = GetFRegAndUnboxNan<FloatType>(src1);
     FpRegister arg2 = GetFRegAndUnboxNan<FloatType>(src2);
-    Register result;
+    Register result = no_register;
     switch (opcode) {
       case Decoder::OpFpGpRegisterTargetNoRoundingOpcode::kFle:
         result = listener_->template Fle<FloatType>(arg1, arg2);
@@ -583,7 +597,7 @@ class SemanticsPlayer {
       int8_t dst,
       int8_t src) {
     FpRegister arg = GetFRegAndUnboxNan<FloatType>(src);
-    Register result;
+    Register result = no_register;
     switch (opcode) {
       case Decoder::OpFpGpRegisterTargetSingleInputNoRoundingOpcode::kFclass:
         result = listener_->template FClass<FloatType>(arg);
@@ -610,9 +624,9 @@ class SemanticsPlayer {
                       int8_t dst,
                       int8_t src1,
                       int8_t src2) {
-    FpRegister arg1;
-    FpRegister arg2;
-    FpRegister result;
+    FpRegister arg1 = no_fp_register;
+    FpRegister arg2 = no_fp_register;
+    FpRegister result = no_fp_register;
     // The sign-injection instructions (FSGNJ, FSGNJN, FSGNJX) do not canonicalize NaNs;
     // they manipulate the underlying bit patterns directly.
     bool canonicalize_nan = true;
@@ -657,7 +671,7 @@ class SemanticsPlayer {
 
   void FmvFloatToInteger(const typename Decoder::FmvFloatToIntegerArgs& args) {
     FpRegister arg = GetFpReg(args.src);
-    Register result;
+    Register result = no_register;
     switch (args.operand_type) {
       case Decoder::FloatOperandType::kFloat:
         result = listener_->template FmvFloatToInteger<int32_t, Float32>(arg);
@@ -674,7 +688,7 @@ class SemanticsPlayer {
 
   void FmvIntegerToFloat(const typename Decoder::FmvIntegerToFloatArgs& args) {
     Register arg = GetRegOrZero(args.src);
-    FpRegister result;
+    FpRegister result = no_fp_register;
     switch (args.operand_type) {
       case Decoder::FloatOperandType::kFloat:
         result = listener_->template FmvIntegerToFloat<Float32, int32_t>(arg);
@@ -707,7 +721,7 @@ class SemanticsPlayer {
                        int8_t dst,
                        int8_t src) {
     FpRegister arg = GetFRegAndUnboxNan<FloatType>(src);
-    FpRegister result;
+    FpRegister result = no_fp_register;
     Register frm = listener_->template GetCsr<CsrName::kFrm>();
     switch (opcode) {
       case Decoder::OpFpSingleInputOpcode::kFSqrt:
@@ -736,7 +750,7 @@ class SemanticsPlayer {
                                  int8_t dst,
                                  int8_t src) {
     FpRegister arg = GetFRegAndUnboxNan<FloatType>(src);
-    FpRegister result;
+    FpRegister result = no_fp_register;
     switch (opcode) {
       case Decoder::OpFpSingleInputNoRoundingOpcode::kFmv:
         result = listener_->Fmv(arg);
@@ -768,7 +782,7 @@ class SemanticsPlayer {
                                        return listener_->Srai(arg, args.imm);
                                      default:
                                        Undefined();
-                                       return Register{};
+                                       return no_register;
                                    }
                                  },
                                  [&](const typename Decoder::ShiftImm32Args& args) {
@@ -802,7 +816,7 @@ class SemanticsPlayer {
                                        return listener_->Bseti(arg, args.shamt);
                                      default:
                                        Undefined();
-                                       return Register{};
+                                       return no_register;
                                    }
                                  },
                                  [&](const typename Decoder::BitmanipImm32Args& args) {
@@ -819,7 +833,7 @@ class SemanticsPlayer {
                                        return listener_->Slliuw(arg, args.shamt);
                                      default:
                                        Undefined();
-                                       return Register{};
+                                       return no_register;
                                    }
                                  }}(args);
     SetRegOrIgnore(args.dst, result);
@@ -1013,7 +1027,7 @@ class SemanticsPlayer {
   };
 
   std::tuple<bool, Register> GetCsr(CsrName csr) {
-    Register reg;
+    Register reg = no_register;
     GetCsrProcessor get_csr(reg, listener_);
     return {ProcessCsrNameAsTemplateParameter(csr, get_csr), reg};
   }
diff --git a/enable_riscv64_to_x86_64.mk b/enable_riscv64_to_x86_64.mk
index 0f079262..618537e4 100644
--- a/enable_riscv64_to_x86_64.mk
+++ b/enable_riscv64_to_x86_64.mk
@@ -14,16 +14,9 @@
 # limitations under the License.
 #
 
-# This file defines:
-#   BERBERIS_PRODUCT_PACKAGES - list of main product packages
-#   BERBERIS_DEV_PRODUCT_PACKAGES - list of development packages
-#
-
 include frameworks/libs/binary_translation/berberis_config.mk
 
-PRODUCT_PACKAGES += \
-    $(BERBERIS_PRODUCT_PACKAGES) \
-    $(BERBERIS_PRODUCT_PACKAGES_RISCV64_TO_X86_64)
+PRODUCT_PACKAGES += $(BERBERIS_PRODUCT_PACKAGES_RISCV64_TO_X86_64)
 
 # ATTENTION: we are overriding
 # PRODUCT_SYSTEM_PROPERTIES += ro.dalvik.vm.native.bridge?=0
diff --git a/exec_region/sections.ld b/exec_region/sections.ld
index 097003c2..49b02a1e 100644
--- a/exec_region/sections.ld
+++ b/exec_region/sections.ld
@@ -14,14 +14,20 @@
  * limitations under the License.
  */
 
+/*
+ * NOTE: Android supports both 4KiB and 16Kib page sizes.
+ *
+ * Use the larger page size (16384) for page alignment that
+ * works in both 4KiB and 16KiB devices.
+ */
 SECTIONS {
   . = SIZEOF_HEADERS;
   .text : {
     *(.text.*)
-    . = ALIGN(4096);
+    . = ALIGN(16384);
     exec_region_start = .;
     . += (512 * 1024);
-    . = ALIGN(4096);
+    . = ALIGN(16384);
     exec_region_end = .;
   }
   .plt : {
@@ -31,7 +37,7 @@ SECTIONS {
    * next PT_LOAD segment from mapping over .plt section removing
    * executable flag from .plt. See also http://b/254823538.
    */
-  . = ALIGN(4096);
+  . = ALIGN(16384);
   .fini_array : {
     *(.fini_array.*)
   }
@@ -51,5 +57,5 @@ SECTIONS {
    * GNU_RELRO segment from mprotecting writable flag away
    * from them. See also http://b/261807330.
    */
-  . = ALIGN(4096);
+  . = ALIGN(16384);
 }
diff --git a/guest_abi/Android.bp b/guest_abi/Android.bp
index 22aa6c3d..14fd6550 100644
--- a/guest_abi/Android.bp
+++ b/guest_abi/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_guest_abi_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: [
diff --git a/guest_loader/guest_loader_test.cc b/guest_loader/guest_loader_test.cc
index 3bb171b7..7d54f01b 100644
--- a/guest_loader/guest_loader_test.cc
+++ b/guest_loader/guest_loader_test.cc
@@ -35,19 +35,27 @@ TEST(guest_loader, smoke) {
 
   std::string error_msg;
   GuestLoader* loader = GuestLoader::StartAppProcessInNewThread(&error_msg);
-  ASSERT_NE(nullptr, loader) << error_msg;
+  ASSERT_NE(loader, nullptr) << error_msg;
 
   // Reset dlerror.
   loader->DlError();
-  ASSERT_EQ(nullptr, loader->DlError());
+  ASSERT_EQ(loader->DlError(), nullptr);
 
   Dl_info info;
-  ASSERT_EQ(0, loader->DlAddr(loader, &info));
-  ASSERT_EQ(nullptr, loader->DlError());  // dladdr doesn't set dlerror.
+  ASSERT_EQ(loader->DlAddr(loader, &info), 0);
+  ASSERT_EQ(loader->DlError(), nullptr);  // dladdr doesn't set dlerror.
 
   void* handle = loader->DlOpen("libc.so", RTLD_NOW);
-  ASSERT_NE(nullptr, handle) << loader->DlError();  // dlerror called only if assertion fails.
-  ASSERT_EQ(nullptr, loader->DlError());
+  ASSERT_NE(handle, nullptr) << loader->DlError();  // dlerror called only if assertion fails.
+  // Clear dlerror: successful dlopen(libc.so) might result in dlerror
+  // being set (because of failed dlsym("swift_demangle") during its
+  // initialization).
+  loader->DlError();
+
+  handle = loader->DlOpen("libdl.so", RTLD_NOW);
+  const char* dlerror = loader->DlError();
+  ASSERT_NE(handle, nullptr) << dlerror;
+  ASSERT_EQ(dlerror, nullptr) << dlerror;
 
   android_namespace_t* ns = loader->CreateNamespace("classloader-namespace",
                                                     nullptr,
@@ -55,10 +63,10 @@ TEST(guest_loader, smoke) {
                                                     kNamespaceTypeIsolated,
                                                     "/data:/mnt/expand",
                                                     nullptr);
-  ASSERT_NE(nullptr, ns) << loader->DlError();  // dlerror called only if assertion fails.
-  ASSERT_EQ(nullptr, loader->DlError());
+  ASSERT_NE(ns, nullptr) << loader->DlError();  // dlerror called only if assertion fails.
+  ASSERT_EQ(loader->DlError(), nullptr);
 }
 
 }  // namespace
 
-}  // namespace berberis
\ No newline at end of file
+}  // namespace berberis
diff --git a/guest_os_primitives/get_tls.h b/guest_os_primitives/get_tls.h
index 8eeb80b9..cb154291 100644
--- a/guest_os_primitives/get_tls.h
+++ b/guest_os_primitives/get_tls.h
@@ -33,10 +33,17 @@ namespace berberis {
     __asm__("mov %%fs:0, %0" : "=r"(__val)); \
     __val;                                   \
   })
+#elif defined(__riscv)
+#define GetTls()                        \
+  ({                                    \
+    void** __val;                       \
+    __asm__("mv %0, tp" : "=r"(__val)); \
+    __val;                              \
+  })
 #else
 #error unsupported architecture
 #endif
 
 }  // namespace berberis
 
-#endif  // BERBERIS_GUEST_OS_PRIMITIVES_GET_TLS_H_
\ No newline at end of file
+#endif  // BERBERIS_GUEST_OS_PRIMITIVES_GET_TLS_H_
diff --git a/guest_os_primitives/guest_signal_action.cc b/guest_os_primitives/guest_signal_action.cc
index 87f4616d..d5a7448f 100644
--- a/guest_os_primitives/guest_signal_action.cc
+++ b/guest_os_primitives/guest_signal_action.cc
@@ -63,6 +63,8 @@ void ConvertHostSigactionToGuest(const HostStructSigaction* host_sa, Guest_sigac
       if (memcmp(handler, "\x48\xc7\xc0\x0f\x00\x00\x00\x0f\x05", 9) != 0) {  // x86_64 sigreturn
         LOG_ALWAYS_FATAL("Unknown x86_64 sa_restorer in host sigaction!");
       }
+#elif defined(__riscv)
+      LOG_ALWAYS_FATAL("Unimplemented for riscv64");
 #else
 #error "Unknown host arch"
 #endif
diff --git a/guest_os_primitives/guest_signal_handling.cc b/guest_os_primitives/guest_signal_handling.cc
index 6739ea5f..0a800b61 100644
--- a/guest_os_primitives/guest_signal_handling.cc
+++ b/guest_os_primitives/guest_signal_handling.cc
@@ -78,6 +78,31 @@ const Guest_sigaction* FindSignalHandler(const GuestSignalActionsTable& signal_a
   return &signal_actions.at(signal - 1).GetClaimedGuestAction();
 }
 
+#if defined(__i386__)
+constexpr size_t kHostRegIP = REG_EIP;
+#elif defined(__x86_64__)
+constexpr size_t kHostRegIP = REG_RIP;
+#elif defined(__riscv)
+constexpr size_t kHostRegIP = REG_PC;
+#else
+#error "Unknown host arch"
+#endif
+uintptr_t GetHostRegIP(const ucontext_t* ucontext) {
+#if defined(__riscv)
+  return ucontext->uc_mcontext.__gregs[kHostRegIP];
+#else
+  return ucontext->uc_mcontext.gregs[kHostRegIP];
+#endif
+}
+
+void SetHostRegIP(ucontext* ucontext, uintptr_t addr) {
+#if defined(__riscv)
+  ucontext->uc_mcontext.__gregs[kHostRegIP] = addr;
+#else
+  ucontext->uc_mcontext.gregs[kHostRegIP] = addr;
+#endif
+}
+
 // Can be interrupted by another HandleHostSignal!
 void HandleHostSignal(int sig, siginfo_t* info, void* context) {
   TRACE("handle host signal %d", sig);
@@ -101,17 +126,9 @@ void HandleHostSignal(int sig, siginfo_t* info, void* context) {
     // We can't make signals pendings as we need to detach the thread!
     CHECK(!attached);
 
-#if defined(__i386__)
-    constexpr size_t kHostRegIP = REG_EIP;
-#elif defined(__x86_64__)
-    constexpr size_t kHostRegIP = REG_RIP;
-#else
-#error "Unknown host arch"
-#endif
-
     // Run recovery code to restore precise context and exit generated code.
     ucontext_t* ucontext = reinterpret_cast<ucontext_t*>(context);
-    uintptr_t addr = ucontext->uc_mcontext.gregs[kHostRegIP];
+    uintptr_t addr = GetHostRegIP(ucontext);
     uintptr_t recovery_addr = FindRecoveryCode(addr, thread->state());
 
     if (recovery_addr) {
@@ -127,7 +144,7 @@ void HandleHostSignal(int sig, siginfo_t* info, void* context) {
             "Imprecise context at recovery, only guest pc is in sync."
             " Other registers may be stale.");
       }
-      ucontext->uc_mcontext.gregs[kHostRegIP] = recovery_addr;
+      SetHostRegIP(ucontext, recovery_addr);
       TRACE("guest signal handler suspended, run recovery for host pc %p at host pc %p",
             reinterpret_cast<void*>(addr),
             reinterpret_cast<void*>(recovery_addr));
diff --git a/guest_os_primitives/guest_thread.cc b/guest_os_primitives/guest_thread.cc
index 1979a81b..ffa4f51b 100644
--- a/guest_os_primitives/guest_thread.cc
+++ b/guest_os_primitives/guest_thread.cc
@@ -224,10 +224,24 @@ bool GuestThread::AllocStack(void* stack, size_t stack_size, size_t guard_size)
     return true;
   }
 
-  guard_size_ = AlignUpPageSize(guard_size);
-  mmap_size_ = guard_size_ + AlignUpPageSize(stack_size);
+  if (AlignUpPageSizeOverflow(guard_size, &guard_size_)) {
+    return false;
+  }
+
+  size_t aligned_stack_size{};
+  if (AlignUpPageSizeOverflow(stack_size, &aligned_stack_size)) {
+    return false;
+  }
+
+  if (__builtin_add_overflow(aligned_stack_size, guard_size_, &mmap_size_)) {
+    return false;
+  }
   stack_size_ = mmap_size_;
 
+  if (stack_size_ == 0) {
+    return false;
+  }
+
   stack_ = Mmap(mmap_size_);
   if (stack_ == MAP_FAILED) {
     TRACE("failed to allocate stack!");
@@ -240,7 +254,12 @@ bool GuestThread::AllocStack(void* stack, size_t stack_size, size_t guard_size)
     return false;
   }
 
-  stack_top_ = ToGuestAddr(stack_) + stack_size_ - 16;
+  // `stack_size_ - 16` is guaranteed to not overflow since it is not 0 and
+  // aligned to the page size.
+  if (__builtin_add_overflow(ToGuestAddr(stack_), stack_size_ - 16, &stack_top_)) {
+    return false;
+  }
+
   return true;
 }
 
diff --git a/guest_os_primitives/guest_thread_clone.cc b/guest_os_primitives/guest_thread_clone.cc
index 31062464..8aa87acd 100644
--- a/guest_os_primitives/guest_thread_clone.cc
+++ b/guest_os_primitives/guest_thread_clone.cc
@@ -18,6 +18,8 @@
 #include <sched.h>
 #include <semaphore.h>
 
+#include <cstring>  // strerror
+
 #include "berberis/base/checks.h"
 #include "berberis/base/tracing.h"
 #include "berberis/guest_os_primitives/guest_signal.h"
@@ -51,6 +53,28 @@ struct GuestThreadCloneInfo {
   sem_t sem;
 };
 
+void SemPostOrDie(sem_t* sem) {
+  int error = sem_post(sem);
+  // sem_post works in two stages: it increments semaphore's value, and then calls FUTEX_WAKE.
+  // If FUTEX_WAIT sporadically returns inside sem_wait between sem_post stages then sem_wait
+  // may observe the updated value and successfully finish. If semaphore is destroyed upon
+  // sem_wait return (like in CloneGuestThread), sem_post's call to FUTEX_WAKE will fail with
+  // EINVAL.
+  // Note that sem_destroy itself may do nothing (bionic and glibc are like that), the actual
+  // destruction happens because we free up memory (e.g. stack frame) where sem_t is stored.
+  // More details at https://sourceware.org/bugzilla/show_bug.cgi?id=12674
+#if defined(__GLIBC__) && ((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 21)))
+  // GLibc before 2.21 may return EINVAL in the above situation. We ignore it since we cannot do
+  // anything about it, and it doesn't really break anything: we just acknowledge the fact that the
+  // semaphore can be destoyed already.
+  LOG_ALWAYS_FATAL_IF(error != 0 && error != EINVAL, "sem_post returned error=%s", strerror(errno));
+#else
+  // Bionic and recent GLibc ignore the error code returned
+  // from FUTEX_WAKE. So, they never return EINVAL.
+  LOG_ALWAYS_FATAL_IF(error != 0, "sem_post returned error=%s", strerror(errno));
+#endif
+}
+
 int RunClonedGuestThread(void* arg) {
   GuestThreadCloneInfo* info = static_cast<GuestThreadCloneInfo*>(arg);
   GuestThread* thread = info->thread;
@@ -70,7 +94,7 @@ int RunClonedGuestThread(void* arg) {
   // - search for child in thread table
   // - send child a signal
   // - dispose info
-  CHECK_EQ(0, sem_post(&info->sem));
+  SemPostOrDie(&info->sem);
   // TODO(b/77574158): Ensure caller has a chance to handle the notification.
   sched_yield();
 
@@ -152,7 +176,8 @@ pid_t CloneGuestThread(GuestThread* thread,
   SetPendingSignalsStatusAtomic(clone_thread_state, kPendingSignalsEnabled);
   SetResidence(clone_thread_state, kOutsideGeneratedCode);
 
-  sem_init(&info.sem, 0, 0);
+  int error = sem_init(&info.sem, 0, 0);
+  LOG_ALWAYS_FATAL_IF(error != 0, "sem_init returned error=%s", strerror(errno));
 
   // ATTENTION: Don't set new tls for the host - tls might be incompatible.
   // TODO(b/280551726): Consider forcing new host tls to 0.
diff --git a/guest_state/Android.bp b/guest_state/Android.bp
index cd637f28..f244a91b 100644
--- a/guest_state/Android.bp
+++ b/guest_state/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_guest_state_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: [
@@ -34,7 +34,7 @@ cc_library_headers {
 
 cc_defaults {
     name: "berberis_guest_state_headers_defaults",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     header_libs: [
         "libberberis_guest_state_headers",
@@ -78,7 +78,7 @@ cc_library_headers {
 cc_library_static {
     name: "libberberis_guest_state_riscv64",
     defaults: [
-        "berberis_defaults_64",
+        "berberis_all_hosts_defaults_64",
         "berberis_guest_state_defaults",
     ],
     srcs: [
diff --git a/guest_state/guest_state.cc b/guest_state/guest_state.cc
index f7505e94..8b949492 100644
--- a/guest_state/guest_state.cc
+++ b/guest_state/guest_state.cc
@@ -42,11 +42,21 @@ const uint32_t kHostArch = NATIVE_BRIDGE_ARCH_X86;
 const uint32_t kGuestArch = NATIVE_BRIDGE_ARCH_ARM64;
 const uint32_t kHostArch = NATIVE_BRIDGE_ARCH_X86_64;
 
+#elif defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64) && defined(__riscv)
+
+const uint32_t kGuestArch = NATIVE_BRIDGE_ARCH_ARM64;
+const uint32_t kHostArch = NATIVE_BRIDGE_ARCH_RISCV64;
+
 #elif defined(NATIVE_BRIDGE_GUEST_ARCH_RISCV64) && defined(__x86_64__)
 
 const uint32_t kGuestArch = NATIVE_BRIDGE_ARCH_RISCV64;
 const uint32_t kHostArch = NATIVE_BRIDGE_ARCH_X86_64;
 
+#elif defined(NATIVE_BRIDGE_GUEST_ARCH_RISCV64) && defined(__aarch64__)
+
+const uint32_t kGuestArch = NATIVE_BRIDGE_ARCH_RISCV64;
+const uint32_t kHostArch = NATIVE_BRIDGE_ARCH_ARM64;
+
 #else
 
 #error "Unknown guest/host arch combination"
diff --git a/heavy_optimizer/riscv64/call_intrinsic.h b/heavy_optimizer/riscv64/call_intrinsic.h
index 7212c628..e85c80a6 100644
--- a/heavy_optimizer/riscv64/call_intrinsic.h
+++ b/heavy_optimizer/riscv64/call_intrinsic.h
@@ -25,6 +25,7 @@
 #include "berberis/backend/x86_64/machine_ir_builder.h"
 #include "berberis/base/bit_util.h"
 #include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/simd_register.h"
 
 #include "simd_register.h"
 
diff --git a/heavy_optimizer/riscv64/frontend.h b/heavy_optimizer/riscv64/frontend.h
index 17de50c8..8e37fcb4 100644
--- a/heavy_optimizer/riscv64/frontend.h
+++ b/heavy_optimizer/riscv64/frontend.h
@@ -43,7 +43,9 @@ class HeavyOptimizerFrontend {
   using CsrName = berberis::CsrName;
   using Decoder = Decoder<SemanticsPlayer<HeavyOptimizerFrontend>>;
   using Register = MachineReg;
+  static constexpr Register no_register = MachineReg{};
   using FpRegister = SimdReg;
+  static constexpr SimdReg no_fp_register = SimdReg{};
   using Float32 = intrinsics::Float32;
   using Float64 = intrinsics::Float64;
 
diff --git a/heavy_optimizer/riscv64/inline_intrinsic.h b/heavy_optimizer/riscv64/inline_intrinsic.h
index f4664893..c7612550 100644
--- a/heavy_optimizer/riscv64/inline_intrinsic.h
+++ b/heavy_optimizer/riscv64/inline_intrinsic.h
@@ -32,7 +32,7 @@
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
 #include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/common_to_x86/intrinsics_bindings.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
 #include "berberis/intrinsics/intrinsics.h"
 #include "berberis/intrinsics/intrinsics_args.h"
 #include "berberis/intrinsics/intrinsics_process_bindings.h"
@@ -262,8 +262,6 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
                                                       ArgTypeForFriend... args);
 
   template <auto kFunc,
-            typename Assembler_common_x86,
-            typename Assembler_x86_64,
             typename MacroAssembler,
             typename Result,
             typename Callback,
@@ -272,15 +270,14 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
                                                       Result def_result,
                                                       Args&&... args);
 
-  template <
-      auto kIntrinsicTemplateName,
-      auto kMacroInstructionTemplateName,
-      auto kMnemo,
-      typename GetOpcode,
-      intrinsics::bindings::CPUIDRestriction kCPUIDRestrictionTemplateValue,
-      intrinsics::bindings::PreciseNanOperationsHandling kPreciseNanOperationsHandlingTemplateValue,
-      bool kSideEffectsTemplateValue,
-      typename... Types>
+  template <auto kIntrinsicTemplateName,
+            auto kMacroInstructionTemplateName,
+            auto kMnemo,
+            typename GetOpcode,
+            typename CPUIDRestrictionTemplateValue,
+            typename PreciseNanOperationsHandlingTemplateValue,
+            bool kSideEffectsTemplateValue,
+            typename... Types>
   friend class intrinsics::bindings::AsmCallInfo;
 
   TryBindingBasedInlineIntrinsicForHeavyOptimizer() = delete;
@@ -302,15 +299,11 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
         xmm_result_reg_{},
         flag_register_{flag_register},
         input_args_(std::tuple{args...}),
-        success_(
-            intrinsics::bindings::ProcessBindings<kFunction,
-                                                  AssemblerX86<x86_64::Assembler>,
-                                                  x86_64::Assembler,
-                                                  std::tuple<MacroAssembler<x86_64::Assembler>>,
-                                                  bool,
-                                                  TryBindingBasedInlineIntrinsicForHeavyOptimizer&>(
-                *this,
-                false)) {}
+        success_(intrinsics::bindings::ProcessBindings<
+                 kFunction,
+                 typename MacroAssembler<x86_64::Assembler>::MacroAssemblers,
+                 bool,
+                 TryBindingBasedInlineIntrinsicForHeavyOptimizer&>(*this, false)) {}
 
   operator bool() { return success_; }
 
@@ -330,29 +323,30 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
                              bool> = true>
   std::optional<bool> /*ProcessBindingsClient*/ operator()(AsmCallInfo asm_call_info) {
     static_assert(std::is_same_v<decltype(kFunction), typename AsmCallInfo::IntrinsicType>);
-    if constexpr (AsmCallInfo::kPreciseNanOperationsHandling !=
-                  intrinsics::bindings::kNoNansOperation) {
+    if constexpr (!std::is_same_v<typename AsmCallInfo::PreciseNanOperationsHandling,
+                                  intrinsics::bindings::NoNansOperation>) {
       return false;
     }
 
-    if constexpr (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasAVX) {
+    using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
+    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
       if (!host_platform::kHasAVX) {
         return false;
       }
-    } else if constexpr (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasBMI) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
       if (!host_platform::kHasBMI) {
         return false;
       }
-    } else if constexpr (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasLZCNT) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>) {
       if (!host_platform::kHasLZCNT) {
         return false;
       }
-    } else if constexpr (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasPOPCNT) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>) {
       if (!host_platform::kHasPOPCNT) {
         return false;
       }
-    } else if constexpr (AsmCallInfo::kCPUIDRestriction ==
-                         intrinsics::bindings::kNoCPUIDRestriction) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        intrinsics::bindings::NoCPUIDRestriction>) {
       // No restrictions. Do nothing.
     } else {
       static_assert(berberis::kDependentValueFalse<AsmCallInfo::kCPUIDRestriction>);
diff --git a/instrument/Android.bp b/instrument/Android.bp
index e206eaaa..c2d667c0 100644
--- a/instrument/Android.bp
+++ b/instrument/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_instrument_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: [
@@ -32,7 +32,7 @@ cc_library_headers {
 
 cc_library_static {
     name: "libberberis_instrument",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     srcs: ["instrument.cc"],
     header_libs: [
@@ -41,4 +41,4 @@ cc_library_static {
         "libberberis_instrument_headers",
     ],
     export_header_lib_headers: ["libberberis_instrument_headers"],
-}
\ No newline at end of file
+}
diff --git a/interpreter/Android.bp b/interpreter/Android.bp
index 2e8d5709..a51d4552 100644
--- a/interpreter/Android.bp
+++ b/interpreter/Android.bp
@@ -19,47 +19,59 @@ package {
 
 cc_library_headers {
     name: "libberberis_interpreter_riscv64_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
 }
 
 cc_library_static {
     name: "libberberis_interpreter_riscv64",
-    defaults: ["berberis_defaults_64"],
+    defaults: [
+        "berberis_all_hosts_defaults_64",
+        "berberis_memory_region_reservation_defaults",
+    ],
     host_supported: true,
-    cflags: ["-DBERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS"],
     header_libs: [
         "libberberis_base_headers",
         "libberberis_decoder_riscv64_headers",
         "libberberis_guest_state_riscv64_headers",
         "libberberis_interpreter_riscv64_headers",
-        "libberberis_intrinsics_riscv64_headers",
         "libberberis_kernel_api_headers",
         "libberberis_runtime_primitives_headers",
+        "libberberis_intrinsics_riscv64_headers",
     ],
     export_header_lib_headers: ["libberberis_interpreter_riscv64_headers"],
     arch: {
         x86_64: {
-            cflags: ["-mssse3"],
-            srcs: ["riscv64/faulty_memory_accesses_x86_64.cc"],
+            cflags: [
+                "-DBERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS",
+                "-mssse3",
+            ],
+            srcs: [
+                "riscv64/faulty_memory_accesses_x86_64.cc",
+                "riscv64/interpreter-VLoadIndexedArgs.cc",
+                "riscv64/interpreter-VLoadStrideArgs.cc",
+                "riscv64/interpreter-VLoadUnitStrideArgs.cc",
+                "riscv64/interpreter-VOpFVfArgs.cc",
+                "riscv64/interpreter-VOpFVvArgs.cc",
+                "riscv64/interpreter-VOpIViArgs.cc",
+                "riscv64/interpreter-VOpIVvArgs.cc",
+                "riscv64/interpreter-VOpIVxArgs.cc",
+                "riscv64/interpreter-VOpMVvArgs.cc",
+                "riscv64/interpreter-VOpMVxArgs.cc",
+                "riscv64/interpreter-VStoreIndexedArgs.cc",
+                "riscv64/interpreter-VStoreStrideArgs.cc",
+                "riscv64/interpreter-VStoreUnitStrideArgs.cc",
+            ],
+        },
+        arm64: {
+            srcs: [
+                "riscv64/faulty_memory_accesses_arm64.cc",
+            ],
         },
     },
     srcs: [
         "riscv64/interpreter-main.cc",
-        "riscv64/interpreter-VLoadIndexedArgs.cc",
-        "riscv64/interpreter-VLoadStrideArgs.cc",
-        "riscv64/interpreter-VLoadUnitStrideArgs.cc",
-        "riscv64/interpreter-VOpFVfArgs.cc",
-        "riscv64/interpreter-VOpFVvArgs.cc",
-        "riscv64/interpreter-VOpIViArgs.cc",
-        "riscv64/interpreter-VOpIVvArgs.cc",
-        "riscv64/interpreter-VOpIVxArgs.cc",
-        "riscv64/interpreter-VOpMVvArgs.cc",
-        "riscv64/interpreter-VOpMVxArgs.cc",
-        "riscv64/interpreter-VStoreIndexedArgs.cc",
-        "riscv64/interpreter-VStoreStrideArgs.cc",
-        "riscv64/interpreter-VStoreUnitStrideArgs.cc",
     ],
 }
 
@@ -80,3 +92,32 @@ cc_test_library {
         "libberberis_kernel_api_headers",
     ],
 }
+
+cc_test {
+    name: "berberis_interpreter_riscv64_to_arm64_insn_tests_static",
+    defaults: ["berberis_all_hosts_defaults_64"],
+    static_libs: [
+        "libbase",
+        "libberberis_base",
+        "libberberis_interpreter_riscv64",
+        "libberberis_kernel_api_riscv64",
+        "liblog",
+    ],
+    srcs: [
+        "riscv64/faulty_memory_accesses_test.cc",
+        "riscv64/interpreter_arm64_test.cc",
+    ],
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_guest_state_riscv64_headers",
+        "libberberis_interpreter_riscv64_headers",
+        "libberberis_runtime_primitives_headers",
+    ],
+    arch: {
+        x86_64: {
+            enabled: false,
+        },
+    },
+    static_executable: true,
+    host_supported: false,
+}
diff --git a/interpreter/riscv64/faulty_memory_accesses.h b/interpreter/faulty_memory_accesses.h
similarity index 100%
rename from interpreter/riscv64/faulty_memory_accesses.h
rename to interpreter/faulty_memory_accesses.h
diff --git a/interpreter/riscv64/faulty_memory_accesses_arm64.cc b/interpreter/riscv64/faulty_memory_accesses_arm64.cc
new file mode 100644
index 00000000..eff3b102
--- /dev/null
+++ b/interpreter/riscv64/faulty_memory_accesses_arm64.cc
@@ -0,0 +1,190 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "../faulty_memory_accesses.h"
+
+#include <cstdint>
+#include <utility>
+
+#include "berberis/base/checks.h"
+#include "berberis/runtime_primitives/recovery_code.h"
+
+namespace berberis {
+
+namespace {
+
+extern "C" FaultyLoadResult FaultyLoad8(const void*);
+extern "C" FaultyLoadResult FaultyLoad16(const void*);
+extern "C" FaultyLoadResult FaultyLoad32(const void*);
+extern "C" FaultyLoadResult FaultyLoad64(const void*);
+extern "C" char g_faulty_load_recovery;
+
+__asm__(
+    R"(
+   .globl FaultyLoad8
+   .balign 16
+FaultyLoad8:
+   ldrb w0, [x0]    // Load 1 byte from memory pointed to by x0 into w0 (lower 32 bits of x0)
+   mov w1, #0       // Move 0 into w1 (lower 32 bits of x1)
+   ret
+
+   .globl FaultyLoad16
+   .balign 16
+FaultyLoad16:
+   ldrh w0, [x0]    // Load 2 bytes (halfword) from memory pointed to by x0 into w0
+   mov w1, #0
+   ret
+
+   .globl FaultyLoad32
+   .balign 16
+FaultyLoad32:
+   ldr w0, [x0]     // Load 4 bytes (word) from memory pointed to by x0 into w0
+   mov w1, #0
+   ret
+
+   .globl FaultyLoad64
+   .balign 16
+FaultyLoad64:
+   ldr x0, [x0]     // Load 8 bytes (doubleword) from memory pointed to by x0 into x0
+   mov w1, #0
+   ret
+
+   .globl g_faulty_load_recovery
+g_faulty_load_recovery:
+   mov w1, #1
+   ret
+)");
+
+extern "C" bool FaultyStore8(void*, uint64_t);
+extern "C" bool FaultyStore16(void*, uint64_t);
+extern "C" bool FaultyStore32(void*, uint64_t);
+extern "C" bool FaultyStore64(void*, uint64_t);
+extern "C" char g_faulty_store_recovery;
+
+__asm__(
+    R"(
+   .globl FaultyStore8
+   .balign 16
+FaultyStore8:
+   strb w1, [x0]     // Store the lower 8 bits of w1 (from x1) into memory pointed to by x0
+   mov w0, #0         // Move 0 into w0 (lower 32 bits of x0)
+   ret
+
+   .globl FaultyStore16
+   .balign 16
+FaultyStore16:
+   strh w1, [x0]     // Store the lower 16 bits of w1 (from x1) into memory pointed to by x0
+   mov w0, #0
+   ret
+
+   .globl FaultyStore32
+   .balign 16
+FaultyStore32:
+   str w1, [x0]      // Store the lower 32 bits of w1 (from x1) into memory pointed to by x0
+   mov w0, #0
+   ret
+
+   .globl FaultyStore64
+   .balign 16
+FaultyStore64:
+   str x1, [x0]      // Store the 64 bits of x1 into memory pointed to by x0
+   mov w0, #0
+   ret
+
+   .globl g_faulty_store_recovery
+g_faulty_store_recovery:
+   mov w0, #1
+   ret
+)");
+
+template <typename FaultyAccessPointer>
+std::pair<uintptr_t, uintptr_t> MakePairAdapter(FaultyAccessPointer fault_addr,
+                                                void* recovery_addr) {
+  return {reinterpret_cast<uintptr_t>(fault_addr), reinterpret_cast<uintptr_t>(recovery_addr)};
+}
+
+}  // namespace
+
+FaultyLoadResult FaultyLoad(const void* addr, uint8_t data_bytes) {
+  CHECK_LE(data_bytes, 8);
+
+  FaultyLoadResult result;
+  switch (data_bytes) {
+    case 1:
+      result = FaultyLoad8(addr);
+      break;
+    case 2:
+      result = FaultyLoad16(addr);
+      break;
+    case 4:
+      result = FaultyLoad32(addr);
+      break;
+    case 8:
+      result = FaultyLoad64(addr);
+      break;
+    default:
+      LOG_ALWAYS_FATAL("Unexpected FaultyLoad access size");
+  }
+
+  return result;
+}
+
+bool FaultyStore(void* addr, uint8_t data_bytes, uint64_t value) {
+  CHECK_LE(data_bytes, 8);
+
+  bool is_fault;
+  switch (data_bytes) {
+    case 1:
+      is_fault = FaultyStore8(addr, value);
+      break;
+    case 2:
+      is_fault = FaultyStore16(addr, value);
+      break;
+    case 4:
+      is_fault = FaultyStore32(addr, value);
+      break;
+    case 8:
+      is_fault = FaultyStore64(addr, value);
+      break;
+    default:
+      LOG_ALWAYS_FATAL("Unexpected FaultyLoad access size");
+  }
+
+  return is_fault;
+}
+
+void AddFaultyMemoryAccessRecoveryCode() {
+  InitExtraRecoveryCodeUnsafe({
+      MakePairAdapter(&FaultyLoad8, &g_faulty_load_recovery),
+      MakePairAdapter(&FaultyLoad16, &g_faulty_load_recovery),
+      MakePairAdapter(&FaultyLoad32, &g_faulty_load_recovery),
+      MakePairAdapter(&FaultyLoad64, &g_faulty_load_recovery),
+  });
+}
+
+void* FindFaultyMemoryAccessRecoveryAddrForTesting(void* fault_addr) {
+  if (fault_addr == &FaultyLoad8 || fault_addr == &FaultyLoad16 || fault_addr == &FaultyLoad32 ||
+      fault_addr == &FaultyLoad64) {
+    return &g_faulty_load_recovery;
+  }
+  if (fault_addr == &FaultyStore8 || fault_addr == &FaultyStore16 || fault_addr == &FaultyStore32 ||
+      fault_addr == &FaultyStore64) {
+    return &g_faulty_store_recovery;
+  }
+  return nullptr;
+}
+
+}  // namespace berberis
diff --git a/interpreter/riscv64/faulty_memory_accesses_test.cc b/interpreter/riscv64/faulty_memory_accesses_test.cc
index 1cd26d82..def6523c 100644
--- a/interpreter/riscv64/faulty_memory_accesses_test.cc
+++ b/interpreter/riscv64/faulty_memory_accesses_test.cc
@@ -22,16 +22,18 @@
 
 #include "berberis/base/checks.h"
 
-#include "faulty_memory_accesses.h"
+#include "../faulty_memory_accesses.h"
 
 namespace berberis {
 
 namespace {
 
 #if defined(__i386__)
-constexpr size_t kRegIP = REG_EIP;
+#define IP_ACCESSOR(ucontext) ucontext->uc_mcontext.gregs[REG_EIP]
 #elif defined(__x86_64__)
-constexpr size_t kRegIP = REG_RIP;
+#define IP_ACCESSOR(ucontext) ucontext->uc_mcontext.gregs[REG_RIP]
+#elif defined(__aarch64__)
+#define IP_ACCESSOR(ucontext) ucontext->uc_mcontext.pc
 #else
 #error "Unsupported arch"
 #endif
@@ -39,10 +41,10 @@ constexpr size_t kRegIP = REG_RIP;
 void FaultHandler(int /* sig */, siginfo_t* /* info */, void* ctx) {
   ucontext_t* ucontext = reinterpret_cast<ucontext_t*>(ctx);
   static_assert(sizeof(void*) == sizeof(greg_t), "Unsupported type sizes");
-  void* fault_addr = reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[kRegIP]);
+  void* fault_addr = reinterpret_cast<void*>(IP_ACCESSOR(ucontext));
   void* recovery_addr = FindFaultyMemoryAccessRecoveryAddrForTesting(fault_addr);
   CHECK(recovery_addr);
-  ucontext->uc_mcontext.gregs[kRegIP] = reinterpret_cast<greg_t>(recovery_addr);
+  IP_ACCESSOR(ucontext) = reinterpret_cast<greg_t>(recovery_addr);
 }
 
 class ScopedFaultySigaction {
diff --git a/interpreter/riscv64/faulty_memory_accesses_x86_64.cc b/interpreter/riscv64/faulty_memory_accesses_x86_64.cc
index bbc324d7..e845a654 100644
--- a/interpreter/riscv64/faulty_memory_accesses_x86_64.cc
+++ b/interpreter/riscv64/faulty_memory_accesses_x86_64.cc
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#include "faulty_memory_accesses.h"
+#include "../faulty_memory_accesses.h"
 
 #include <cstdint>
 #include <utility>
diff --git a/interpreter/riscv64/interpreter-main.cc b/interpreter/riscv64/interpreter-main.cc
index 07834b5f..4ba8d31b 100644
--- a/interpreter/riscv64/interpreter-main.cc
+++ b/interpreter/riscv64/interpreter-main.cc
@@ -21,8 +21,12 @@
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/guest_state/guest_state.h"
 
-#include "faulty_memory_accesses.h"
+#include "../faulty_memory_accesses.h"
+#if defined(__x86_64__)
 #include "interpreter.h"
+#elif defined(__aarch64__)
+#include "interpreter_arm64.h"
+#endif
 
 namespace berberis {
 
diff --git a/interpreter/riscv64/interpreter.h b/interpreter/riscv64/interpreter.h
index e3f11502..aaad543b 100644
--- a/interpreter/riscv64/interpreter.h
+++ b/interpreter/riscv64/interpreter.h
@@ -31,7 +31,7 @@
 #include "berberis/intrinsics/guest_cpu_flags.h"  // ToHostRoundingMode
 #include "berberis/intrinsics/intrinsics.h"
 #include "berberis/intrinsics/intrinsics_float.h"
-#include "berberis/intrinsics/riscv64/vector_intrinsics.h"
+#include "berberis/intrinsics/riscv64_to_all/vector_intrinsics.h"
 #include "berberis/intrinsics/simd_register.h"
 #include "berberis/intrinsics/type_traits.h"
 #include "berberis/kernel_api/run_guest_syscall.h"
@@ -39,24 +39,17 @@
 #include "berberis/runtime_primitives/memory_region_reservation.h"
 #include "berberis/runtime_primitives/recovery_code.h"
 
-#include "faulty_memory_accesses.h"
 #include "regs.h"
 
+#include "../faulty_memory_accesses.h"
+
 namespace berberis {
 
 inline constexpr std::memory_order AqRlToStdMemoryOrder(bool aq, bool rl) {
   if (aq) {
-    if (rl) {
-      return std::memory_order_acq_rel;
-    } else {
-      return std::memory_order_acquire;
-    }
+    return rl ? std::memory_order_acq_rel : std::memory_order_acquire;
   } else {
-    if (rl) {
-      return std::memory_order_release;
-    } else {
-      return std::memory_order_relaxed;
-    }
+    return rl ? std::memory_order_release : std::memory_order_relaxed;
   }
 }
 
@@ -71,7 +64,9 @@ class Interpreter {
   using CsrName = berberis::CsrName;
   using Decoder = Decoder<SemanticsPlayer<Interpreter>>;
   using Register = uint64_t;
+  static constexpr Register no_register = 0;
   using FpRegister = uint64_t;
+  static constexpr FpRegister no_fp_register = 0;
   using Float32 = intrinsics::Float32;
   using Float64 = intrinsics::Float64;
 
@@ -610,7 +605,7 @@ class Interpreter {
   template <typename ElementType, typename VOpArgs, typename... ExtraArgs>
   void OpVector(const VOpArgs& args, Register vtype, ExtraArgs... extra_args) {
     auto vemul = Decoder::SignExtend<3>(vtype & 0b111);
-    vemul -= ((vtype >> 3) & 0b111);        // Divide by SEW.
+    vemul -= ((vtype >> 3) & 0b111);  // Divide by SEW.
     vemul +=
         static_cast<std::underlying_type_t<decltype(args.width)>>(args.width);  // Multiply by EEW.
     if (vemul < -3 || vemul > 3) [[unlikely]] {
@@ -1476,6 +1471,15 @@ class Interpreter {
   void OpVector(const Decoder::VOpFVvArgs& args) {
     using SignedType = Wrapping<std::make_signed_t<typename TypeTraits<ElementType>::Int>>;
     using UnsignedType = Wrapping<std::make_unsigned_t<typename TypeTraits<ElementType>::Int>>;
+    // Floating point IEEE 754 value -0.0 includes 1 top bit set and the other bits not set:
+    // https://en.wikipedia.org/wiki/Signed_zero#Representations This is the exact same
+    // representation minimum negative integer have in two's complement representation:
+    // https://en.wikipedia.org/wiki/Two%27s_complement#Most_negative_number
+    // Note: we pass filler elements as integers because `Float32`/`Float64` couldn't be template
+    // parameters.
+    constexpr SignedType kNegativeZero{std::numeric_limits<typename SignedType::BaseType>::min()};
+    // Floating point IEEE 754 value +0.0 includes only zero bits, same as integer zero.
+    constexpr SignedType kPositiveZero{};
     // We currently don't support Float16 operations, but conversion routines that deal with
     // double-width floats use these encodings to produce regular Float32 types.
     if constexpr (sizeof(ElementType) <= sizeof(Float32)) {
@@ -1562,6 +1566,27 @@ class Interpreter {
                                  vta,
                                  vma,
                                  kFrm>(args.dst, args.src1, args.src2);
+        case Decoder::VOpFVvOpcode::kVfwredusumvs:
+          // 14.3. Vector Single-Width Floating-Point Reduction Instructions:
+          // The additive identity is +0.0 when rounding down or -0.0 for all other rounding
+          // modes.
+          if (GetCsr<kFrm>() != FPFlags::RDN) {
+            return OpVectorvs<intrinsics::Vfredosumvs<ElementType, WideType<ElementType>>,
+                              ElementType,
+                              WideType<ElementType>,
+                              vlmul,
+                              vta,
+                              vma,
+                              kFrm>(args.dst, Vec<kNegativeZero>{args.src1}, args.src2);
+          } else {
+            return OpVectorvs<intrinsics::Vfredosumvs<ElementType, WideType<ElementType>>,
+                              ElementType,
+                              WideType<ElementType>,
+                              vlmul,
+                              vta,
+                              vma,
+                              kFrm>(args.dst, Vec<kPositiveZero>{args.src1}, args.src2);
+          }
         case Decoder::VOpFVvOpcode::kVfwsubvv:
           return OpVectorWidenvv<intrinsics::Vfwsubvv<ElementType>,
                                  ElementType,
@@ -1569,6 +1594,27 @@ class Interpreter {
                                  vta,
                                  vma,
                                  kFrm>(args.dst, args.src1, args.src2);
+        case Decoder::VOpFVvOpcode::kVfwredosumvs:
+          // 14.3. Vector Single-Width Floating-Point Reduction Instructions:
+          // The additive identity is +0.0 when rounding down or -0.0 for all other rounding
+          // modes.
+          if (GetCsr<kFrm>() != FPFlags::RDN) {
+            return OpVectorvs<intrinsics::Vfredosumvs<ElementType, WideType<ElementType>>,
+                              ElementType,
+                              WideType<ElementType>,
+                              vlmul,
+                              vta,
+                              vma,
+                              kFrm>(args.dst, Vec<kNegativeZero>{args.src1}, args.src2);
+          } else {
+            return OpVectorvs<intrinsics::Vfredosumvs<ElementType, WideType<ElementType>>,
+                              ElementType,
+                              WideType<ElementType>,
+                              vlmul,
+                              vta,
+                              vma,
+                              kFrm>(args.dst, Vec<kPositiveZero>{args.src1}, args.src2);
+          }
         case Decoder::VOpFVvOpcode::kVfwmulvv:
           return OpVectorWidenvv<intrinsics::Vfwmulvv<ElementType>,
                                  ElementType,
@@ -1703,15 +1749,6 @@ class Interpreter {
     // If our ElementType is Float16 then “straight” operations are unsupported and we whouldn't try
     // instantiate any functions since this would lead to compilke-time error.
     if constexpr (sizeof(ElementType) >= sizeof(Float32)) {
-      // Floating point IEEE 754 value -0.0 includes 1 top bit set and the other bits not set:
-      // https://en.wikipedia.org/wiki/Signed_zero#Representations This is the exact same
-      // representation minimum negative integer have in two's complement representation:
-      // https://en.wikipedia.org/wiki/Two%27s_complement#Most_negative_number
-      // Note: we pass filler elements as integers because `Float32`/`Float64` couldn't be template
-      // parameters.
-      constexpr SignedType kNegativeZero{std::numeric_limits<typename SignedType::BaseType>::min()};
-      // Floating point IEEE 754 value +0.0 includes only zero bits, same as integer zero.
-      constexpr SignedType kPositiveZero{};
       // Keep cases sorted in opcode order to match RISC-V V manual.
       switch (args.opcode) {
         case Decoder::VOpFVvOpcode::kVfredusumvs:
@@ -1992,6 +2029,12 @@ class Interpreter {
       case Decoder::VOpIViOpcode::kVrgathervi:
         return OpVectorGather<ElementType, vlmul, vta, vma>(
             args.dst, args.src, [&args](size_t /*index*/) { return ElementType{args.uimm}; });
+      case Decoder::VOpIViOpcode::kVadcvi:
+        return OpVectorvxm<intrinsics::Vadcvx<SignedType>,
+                           SignedType,
+                           NumberOfRegistersInvolved(vlmul),
+                           vta,
+                           vma>(args.dst, args.src, SignedType{args.imm});
       case Decoder::VOpIViOpcode::kVmseqvi:
         return OpVectorToMaskvx<intrinsics::Vseqvx<SignedType>, SignedType, vlmul, vma>(
             args.dst, args.src, SignedType{args.imm});
@@ -2147,6 +2190,18 @@ class Interpreter {
         return OpVectorGather<ElementType, vlmul, vta, vma>(
             args.dst, args.src1, [&indexes](size_t index) { return indexes[index]; });
       }
+      case Decoder::VOpIVvOpcode::kVadcvv:
+        return OpVectorvvm<intrinsics::Vadcvv<SignedType>,
+                           SignedType,
+                           NumberOfRegistersInvolved(vlmul),
+                           vta,
+                           vma>(args.dst, args.src1, args.src2);
+      case Decoder::VOpIVvOpcode::kVsbcvv:
+        return OpVectorvvm<intrinsics::Vsbcvv<SignedType>,
+                           SignedType,
+                           NumberOfRegistersInvolved(vlmul),
+                           vta,
+                           vma>(args.dst, args.src1, args.src2);
       case Decoder::VOpIVvOpcode::kVmseqvv:
         return OpVectorToMaskvv<intrinsics::Vseqvv<ElementType>, ElementType, vlmul, vma>(
             args.dst, args.src1, args.src2);
@@ -2259,6 +2314,20 @@ class Interpreter {
                                 vta,
                                 vma,
                                 kVxrm>(args.dst, args.src1, args.src2);
+      case Decoder::VOpIVvOpcode::kVwredsumuvs:
+        return OpVectorvs<intrinsics::Vredsumvs<UnsignedType, WideType<UnsignedType>>,
+                          UnsignedType,
+                          WideType<UnsignedType>,
+                          vlmul,
+                          vta,
+                          vma>(args.dst, Vec<UnsignedType{}>{args.src1}, args.src2);
+      case Decoder::VOpIVvOpcode::kVwredsumvs:
+        return OpVectorvs<intrinsics::Vredsumvs<SignedType, WideType<SignedType>>,
+                          SignedType,
+                          WideType<SignedType>,
+                          vlmul,
+                          vta,
+                          vma>(args.dst, Vec<SignedType{}>{args.src1}, args.src2);
       default:
         Undefined();
     }
@@ -2295,6 +2364,18 @@ class Interpreter {
             args.dst, args.src1, [&arg2](size_t /*index*/) {
               return MaybeTruncateTo<ElementType>(arg2);
             });
+      case Decoder::VOpIVxOpcode::kVadcvx:
+        return OpVectorvxm<intrinsics::Vadcvx<ElementType>,
+                           ElementType,
+                           NumberOfRegistersInvolved(vlmul),
+                           vta,
+                           vma>(args.dst, args.src1, MaybeTruncateTo<ElementType>(arg2));
+      case Decoder::VOpIVxOpcode::kVsbcvx:
+        return OpVectorvxm<intrinsics::Vsbcvx<ElementType>,
+                           ElementType,
+                           NumberOfRegistersInvolved(vlmul),
+                           vta,
+                           vma>(args.dst, args.src1, MaybeTruncateTo<ElementType>(arg2));
       case Decoder::VOpIVxOpcode::kVmseqvx:
         return OpVectorToMaskvx<intrinsics::Vseqvx<ElementType>, ElementType, vlmul, vma>(
             args.dst, args.src1, MaybeTruncateTo<ElementType>(arg2));
@@ -2579,6 +2660,10 @@ class Interpreter {
                                       vma>(args.dst, args.src1);
             }
             break;
+          case Decoder::VXUnary0Opcode::kVbrev8v:
+            return OpVectorv<intrinsics::Vbrev8v<ElementType>, ElementType, vlmul, vta, vma>(
+                args.dst, args.src1);
+            break;
           default:
             return Undefined();
         }
@@ -3318,9 +3403,23 @@ class Interpreter {
             auto vma,
             CsrName... kExtraCsrs,
             auto kDefaultElement>
+  void OpVectorvs(uint8_t dst, Vec<kDefaultElement> src1, uint8_t src2) {
+    return OpVectorvs<Intrinsic, ElementType, ElementType, vlmul, vta, vma, kExtraCsrs...>(
+        dst, src1, src2);
+  }
+
+  template <auto Intrinsic,
+            typename ElementType,
+            typename ResultType,
+            VectorRegisterGroupMultiplier vlmul,
+            TailProcessing vta,
+            auto vma,
+            CsrName... kExtraCsrs,
+            auto kDefaultElement>
   void OpVectorvs(uint8_t dst, Vec<kDefaultElement> src1, uint8_t src2) {
     return OpVectorvs<Intrinsic,
                       ElementType,
+                      ResultType,
                       NumberOfRegistersInvolved(vlmul),
                       vta,
                       vma,
@@ -3329,6 +3428,7 @@ class Interpreter {
 
   template <auto Intrinsic,
             typename ElementType,
+            typename ResultType,
             size_t kRegistersInvolved,
             TailProcessing vta,
             auto vma,
@@ -3349,7 +3449,7 @@ class Interpreter {
       return;
     }
     auto mask = GetMaskForVectorOperations<vma>();
-    ElementType init = SIMD128Register{state_->cpu.v[src2]}.Get<ElementType>(0);
+    ResultType init = SIMD128Register{state_->cpu.v[src2]}.Get<ResultType>(0);
     for (size_t index = 0; index < kRegistersInvolved; ++index) {
       init = std::get<0>(
           Intrinsic(GetCsr<kExtraCsrs>()...,
@@ -3358,7 +3458,7 @@ class Interpreter {
     }
     SIMD128Register result{state_->cpu.v[dst]};
     result.Set(init, 0);
-    result = std::get<0>(intrinsics::VectorMasking<ElementType, vta>(result, result, 0, 1));
+    result = std::get<0>(intrinsics::VectorMasking<ResultType, vta>(result, result, 0, 1));
     state_->cpu.v[dst] = result.Get<__uint128_t>();
   }
 
@@ -3606,6 +3706,95 @@ class Interpreter {
     }
   }
 
+  template <auto Intrinsic,
+            typename ElementType,
+            size_t kRegistersInvolved,
+            TailProcessing vta,
+            auto vma,
+            CsrName... kExtraCsrs>
+  void OpVectorvxm(uint8_t dst, uint8_t src1, ElementType arg2) {
+    // All args must be aligned at kRegistersInvolved amount. We'll merge them
+    // together and then do a combined check for all of them at once.
+    if (!IsAligned<kRegistersInvolved>(dst | src1)) {
+      return Undefined();
+    }
+
+    size_t vstart = GetCsr<CsrName::kVstart>();
+    size_t vl = GetCsr<CsrName::kVl>();
+    SetCsr<CsrName::kVstart>(0);
+    // When vstart >= vl, there are no body elements, and no elements are updated in any destination
+    // vector register group, including that no tail elements are updated with agnostic values.
+    if (vstart >= vl) [[unlikely]] {
+      return Undefined();
+    }
+
+    for (size_t index = 0; index < kRegistersInvolved; ++index) {
+      SIMD128Register arg1{state_->cpu.v[src1 + index]};
+      SIMD128Register arg3{};
+      if constexpr (!std::is_same_v<decltype(vma), intrinsics::NoInactiveProcessing>) {
+        if constexpr (vma == InactiveProcessing::kUndisturbed) {
+          arg3 = std::get<0>(
+              intrinsics::GetMaskVectorArgument<ElementType, vta, vma>(state_->cpu.v[0], index));
+        }
+      }
+
+      SIMD128Register result(state_->cpu.v[dst + index]);
+      result = VectorMasking<ElementType, vta, intrinsics::NoInactiveProcessing{}>(
+          result,
+          std::get<0>(Intrinsic(GetCsr<kExtraCsrs>()..., arg1, arg2, arg3)),
+          vstart,
+          vl,
+          index,
+          intrinsics::NoInactiveProcessing{});
+      state_->cpu.v[dst + index] = result.Get<__uint128_t>();
+    }
+  }
+
+  template <auto Intrinsic,
+            typename ElementType,
+            size_t kRegistersInvolved,
+            TailProcessing vta,
+            auto vma,
+            CsrName... kExtraCsrs>
+  void OpVectorvvm(uint8_t dst, uint8_t src1, uint8_t src2) {
+    // All args must be aligned at kRegistersInvolved amount. We'll merge them
+    // together and then do a combined check for all of them at once.
+    if (!IsAligned<kRegistersInvolved>(dst | src1 | src2)) {
+      return Undefined();
+    }
+
+    size_t vstart = GetCsr<CsrName::kVstart>();
+    size_t vl = GetCsr<CsrName::kVl>();
+    SetCsr<CsrName::kVstart>(0);
+    // When vstart >= vl, there are no body elements, and no elements are updated in any destination
+    // vector register group, including that no tail elements are updated with agnostic values.
+    if (vstart >= vl) [[unlikely]] {
+      return Undefined();
+    }
+
+    for (size_t index = 0; index < kRegistersInvolved; ++index) {
+      SIMD128Register arg1{state_->cpu.v[src1 + index]};
+      SIMD128Register arg2{state_->cpu.v[src2 + index]};
+      SIMD128Register arg3{};
+      if constexpr (!std::is_same_v<decltype(vma), intrinsics::NoInactiveProcessing>) {
+        if constexpr (vma == InactiveProcessing::kUndisturbed) {
+          arg3 = std::get<0>(
+              intrinsics::GetMaskVectorArgument<ElementType, vta, vma>(state_->cpu.v[0], index));
+        }
+      }
+
+      SIMD128Register result(state_->cpu.v[dst + index]);
+      result = VectorMasking<ElementType, vta, intrinsics::NoInactiveProcessing{}>(
+          result,
+          std::get<0>(Intrinsic(GetCsr<kExtraCsrs>()..., arg1, arg2, arg3)),
+          vstart,
+          vl,
+          index,
+          intrinsics::NoInactiveProcessing{});
+      state_->cpu.v[dst + index] = result.Get<__uint128_t>();
+    }
+  }
+
   template <auto Intrinsic,
             typename ElementType,
             VectorRegisterGroupMultiplier vlmul,
@@ -3968,11 +4157,18 @@ class Interpreter {
 
   template <typename ElementType, VectorRegisterGroupMultiplier vlmul, TailProcessing vta, auto vma>
   void OpVectorslidedown(uint8_t dst, uint8_t src, Register offset) {
-    return OpVectorslidedown<ElementType, NumberOfRegistersInvolved(vlmul), vta, vma>(
-        dst, src, offset);
+    return OpVectorslidedown<ElementType,
+                             NumberOfRegistersInvolved(vlmul),
+                             GetVlmax<ElementType, vlmul>(),
+                             vta,
+                             vma>(dst, src, offset);
   }
 
-  template <typename ElementType, size_t kRegistersInvolved, TailProcessing vta, auto vma>
+  template <typename ElementType,
+            size_t kRegistersInvolved,
+            size_t kVlmax,
+            TailProcessing vta,
+            auto vma>
   void OpVectorslidedown(uint8_t dst, uint8_t src, Register offset) {
     constexpr size_t kElementsPerRegister = 16 / sizeof(ElementType);
     if (!IsAligned<kRegistersInvolved>(dst | src)) {
@@ -3992,21 +4188,21 @@ class Interpreter {
       SIMD128Register result(state_->cpu.v[dst + index]);
 
       size_t first_arg_disp = index + offset / kElementsPerRegister;
-      SIMD128Register arg1 = (first_arg_disp >= kRegistersInvolved)
-                                 ? SIMD128Register{0}
-                                 : state_->cpu.v[src + first_arg_disp];
-      SIMD128Register arg2 = (first_arg_disp + 1 >= kRegistersInvolved)
-                                 ? SIMD128Register{0}
-                                 : state_->cpu.v[src + first_arg_disp + 1];
+      SIMD128Register arg1 = state_->cpu.v[src + first_arg_disp];
+      SIMD128Register arg2 = state_->cpu.v[src + first_arg_disp + 1];
+      SIMD128Register tunnel_shift_result;
+      // Elements coming from above vlmax are zeroes.
+      if (offset >= kVlmax) {
+        tunnel_shift_result = SIMD128Register{0};
+      } else {
+        tunnel_shift_result = std::get<0>(
+            intrinsics::VectorSlideDown<ElementType>(offset % kElementsPerRegister, arg1, arg2));
+        tunnel_shift_result =
+            VectorZeroFill<ElementType>(tunnel_shift_result, kVlmax - offset, kVlmax, index);
+      }
 
-      result =
-          VectorMasking<ElementType, vta, vma>(result,
-                                               std::get<0>(intrinsics::VectorSlideDown<ElementType>(
-                                                   offset % kElementsPerRegister, arg1, arg2)),
-                                               vstart,
-                                               vl,
-                                               index,
-                                               mask);
+      result = VectorMasking<ElementType, vta, vma>(
+          result, tunnel_shift_result, vstart, vl, index, mask);
       state_->cpu.v[dst + index] = result.Get<__uint128_t>();
     }
   }
@@ -4048,7 +4244,11 @@ class Interpreter {
     }
 
     // Slide all the elements by one.
-    OpVectorslidedown<ElementType, NumberOfRegistersInvolved(vlmul), vta, vma>(dst, src, 1);
+    OpVectorslidedown<ElementType,
+                      NumberOfRegistersInvolved(vlmul),
+                      GetVlmax<ElementType, vlmul>(),
+                      vta,
+                      vma>(dst, src, 1);
     if (exception_raised_) {
       return;
     }
@@ -4358,6 +4558,14 @@ class Interpreter {
         std::get<0>(intrinsics::MaskForRegisterInSequence<ElementType>(mask, index))));
   }
 
+  template <typename ElementType>
+  SIMD128Register VectorZeroFill(SIMD128Register src, size_t start, size_t end, size_t index) {
+    return VectorMasking<ElementType,
+                         TailProcessing::kUndisturbed,
+                         intrinsics::NoInactiveProcessing{}>(
+        src, SIMD128Register{0}, start, end, index, intrinsics::NoInactiveProcessing{});
+  }
+
   template <template <auto> typename ProcessType,
             auto kLambda =
                 [](auto packaged_value) {
diff --git a/interpreter/riscv64/interpreter_arm64.h b/interpreter/riscv64/interpreter_arm64.h
new file mode 100644
index 00000000..32cc56d9
--- /dev/null
+++ b/interpreter/riscv64/interpreter_arm64.h
@@ -0,0 +1,665 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file excenaupt in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "berberis/interpreter/riscv64/interpreter.h"
+
+#include <atomic>
+#include <cstdint>
+#include <cstdlib>
+
+#include "berberis/base/bit_util.h"
+#include "berberis/decoder/riscv64/decoder.h"
+#include "berberis/decoder/riscv64/semantics_player.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/intrinsics/riscv64_to_all/intrinsics.h"
+#include "berberis/kernel_api/run_guest_syscall.h"
+#include "berberis/runtime_primitives/memory_region_reservation.h"
+
+#include "regs.h"
+
+#include "../faulty_memory_accesses.h"
+
+namespace berberis {
+
+inline constexpr std::memory_order AqRlToStdMemoryOrder(bool aq, bool rl) {
+  if (aq) {
+    return rl ? std::memory_order_acq_rel : std::memory_order_acquire;
+  } else {
+    return rl ? std::memory_order_release : std::memory_order_relaxed;
+  }
+}
+
+class Interpreter {
+ public:
+  using CsrName = berberis::CsrName;
+  using Decoder = Decoder<SemanticsPlayer<Interpreter>>;
+  using Register = uint64_t;
+  static constexpr Register no_register = 0;
+  using FpRegister = uint64_t;
+  static constexpr FpRegister no_fp_register = 0;
+  using Float32 = float;
+  using Float64 = double;
+
+  explicit Interpreter(ThreadState* state)
+      : state_(state), branch_taken_(false), exception_raised_(false) {}
+
+  //
+  // Instruction implementations.
+  //
+
+  Register UpdateCsr(Decoder::CsrOpcode opcode, Register arg, Register csr) {
+    UNUSED(opcode, arg, csr);
+    Undefined();
+    return {};
+  }
+
+  Register UpdateCsr(Decoder::CsrImmOpcode opcode, uint8_t imm, Register csr) {
+    UNUSED(opcode, imm, csr);
+    Undefined();
+    return {};
+  }
+
+  void Fence(Decoder::FenceOpcode /*opcode*/,
+             Register /*src*/,
+             bool sw,
+             bool sr,
+             bool /*so*/,
+             bool /*si*/,
+             bool pw,
+             bool pr,
+             bool /*po*/,
+             bool /*pi*/) {
+    bool read_fence = sr | pr;
+    bool write_fence = sw | pw;
+    // "ish" is for inner shareable access, which is normally needed by userspace programs.
+    if (read_fence) {
+      if (write_fence) {
+        // This is equivalent to "fence rw,rw".
+        asm volatile("dmb ish" ::: "memory");
+      } else {
+        // "ishld" is equivalent to "fence r,rw", which is stronger than what we need here
+        // ("fence r,r"). However, it is the closet option that ARM offers.
+        asm volatile("dmb ishld" ::: "memory");
+      }
+    } else if (write_fence) {
+      // "st" is equivalent to "fence w,w".
+      asm volatile("dmb ishst" ::: "memory");
+    }
+    return;
+  }
+
+  template <typename IntType, bool aq, bool rl>
+  Register Lr(int64_t addr) {
+    // TODO(b/358214671): use more efficient way for MemoryRegionReservation.
+    static_assert(std::is_integral_v<IntType>, "Lr: IntType must be integral");
+    static_assert(std::is_signed_v<IntType>, "Lr: IntType must be signed");
+    CHECK(!exception_raised_);
+    // Address must be aligned on size of IntType.
+    CHECK((addr % sizeof(IntType)) == 0ULL);
+    return MemoryRegionReservation::Load<IntType>(&state_->cpu, addr, AqRlToStdMemoryOrder(aq, rl));
+  }
+
+  template <typename IntType, bool aq, bool rl>
+  Register Sc(int64_t addr, IntType val) {
+    // TODO(b/358214671): use more efficient way for MemoryRegionReservation.
+    static_assert(std::is_integral_v<IntType>, "Sc: IntType must be integral");
+    static_assert(std::is_signed_v<IntType>, "Sc: IntType must be signed");
+    CHECK(!exception_raised_);
+    // Address must be aligned on size of IntType.
+    CHECK((addr % sizeof(IntType)) == 0ULL);
+    return static_cast<Register>(MemoryRegionReservation::Store<IntType>(
+        &state_->cpu, addr, val, AqRlToStdMemoryOrder(aq, rl)));
+  }
+
+  Register Op(Decoder::OpOpcode opcode, Register arg1, Register arg2) {
+    switch (opcode) {
+      case Decoder::OpOpcode::kAdd:
+        return Int64(arg1) + Int64(arg2);
+      case Decoder::OpOpcode::kSub:
+        return Int64(arg1) - Int64(arg2);
+      case Decoder::OpOpcode::kAnd:
+        return Int64(arg1) & Int64(arg2);
+      case Decoder::OpOpcode::kOr:
+        return Int64(arg1) | Int64(arg2);
+      case Decoder::OpOpcode::kXor:
+        return Int64(arg1) ^ Int64(arg2);
+      case Decoder::OpOpcode::kSll:
+        return Int64(arg1) << Int64(arg2);
+      case Decoder::OpOpcode::kSrl:
+        return UInt64(arg1) >> Int64(arg2);
+      case Decoder::OpOpcode::kSra:
+        return Int64(arg1) >> Int64(arg2);
+      case Decoder::OpOpcode::kSlt:
+        return Int64(arg1) < Int64(arg2) ? 1 : 0;
+      case Decoder::OpOpcode::kSltu:
+        return UInt64(arg1) < UInt64(arg2) ? 1 : 0;
+      case Decoder::OpOpcode::kAndn:
+        return Int64(arg1) & (~Int64(arg2));
+      case Decoder::OpOpcode::kOrn:
+        return Int64(arg1) | (~Int64(arg2));
+      case Decoder::OpOpcode::kXnor:
+        return ~(Int64(arg1) ^ Int64(arg2));
+      default:
+        Undefined();
+        return {};
+    }
+  }
+
+  Register Op32(Decoder::Op32Opcode opcode, Register arg1, Register arg2) {
+    UNUSED(opcode, arg1, arg2);
+    Undefined();
+    return {};
+  }
+
+  Register Load(Decoder::LoadOperandType operand_type, Register arg, int16_t offset) {
+    void* ptr = ToHostAddr<void>(arg + offset);
+    switch (operand_type) {
+      case Decoder::LoadOperandType::k8bitUnsigned:
+        return Load<uint8_t>(ptr);
+      case Decoder::LoadOperandType::k16bitUnsigned:
+        return Load<uint16_t>(ptr);
+      case Decoder::LoadOperandType::k32bitUnsigned:
+        return Load<uint32_t>(ptr);
+      case Decoder::LoadOperandType::k64bit:
+        return Load<uint64_t>(ptr);
+      case Decoder::LoadOperandType::k8bitSigned:
+        return Load<int8_t>(ptr);
+      case Decoder::LoadOperandType::k16bitSigned:
+        return Load<int16_t>(ptr);
+      case Decoder::LoadOperandType::k32bitSigned:
+        return Load<int32_t>(ptr);
+      default:
+        Undefined();
+        return {};
+    }
+  }
+
+  template <typename DataType>
+  FpRegister LoadFp(Register arg, int16_t offset) {
+    UNUSED(arg, offset);
+    Undefined();
+    return {};
+  }
+
+  Register OpImm(Decoder::OpImmOpcode opcode, Register arg, int16_t imm) {
+    switch (opcode) {
+      case Decoder::OpImmOpcode::kAddi:
+        return arg + int64_t{imm};
+      case Decoder::OpImmOpcode::kSlti:
+        return bit_cast<int64_t>(arg) < int64_t{imm} ? 1 : 0;
+      case Decoder::OpImmOpcode::kSltiu:
+        return arg < bit_cast<uint64_t>(int64_t{imm}) ? 1 : 0;
+      case Decoder::OpImmOpcode::kXori:
+        return arg ^ int64_t { imm };
+      case Decoder::OpImmOpcode::kOri:
+        return arg | int64_t{imm};
+      case Decoder::OpImmOpcode::kAndi:
+        return arg & int64_t{imm};
+      default:
+        Undefined();
+        return {};
+    }
+  }
+
+  Register Lui(int32_t imm) { return int64_t{imm}; }
+
+  Register Auipc(int32_t imm) {
+    uint64_t pc = state_->cpu.insn_addr;
+    return pc + int64_t{imm};
+  }
+
+  Register OpImm32(Decoder::OpImm32Opcode opcode, Register arg, int16_t imm) {
+    UNUSED(opcode, arg, imm);
+    Undefined();
+    return {};
+  }
+
+  // TODO(b/232598137): rework ecall to not take parameters explicitly.
+  Register Ecall(Register /* syscall_nr */,
+                 Register /* arg0 */,
+                 Register /* arg1 */,
+                 Register /* arg2 */,
+                 Register /* arg3 */,
+                 Register /* arg4 */,
+                 Register /* arg5 */) {
+    CHECK(!exception_raised_);
+    RunGuestSyscall(state_);
+    return state_->cpu.x[A0];
+  }
+
+  Register Slli(Register arg, int8_t imm) { return arg << imm; }
+
+  Register Srli(Register arg, int8_t imm) { return arg >> imm; }
+
+  Register Srai(Register arg, int8_t imm) { return bit_cast<int64_t>(arg) >> imm; }
+
+  Register ShiftImm32(Decoder::ShiftImm32Opcode opcode, Register arg, uint16_t imm) {
+    UNUSED(opcode, arg, imm);
+    Undefined();
+    return {};
+  }
+
+  Register Rori(Register arg, int8_t shamt) {
+    CheckShamtIsValid(shamt);
+    return (((uint64_t(arg) >> shamt)) | (uint64_t(arg) << (64 - shamt)));
+  }
+
+  Register Roriw(Register arg, int8_t shamt) {
+    UNUSED(arg, shamt);
+    Undefined();
+    return {};
+  }
+
+  void Store(Decoder::MemoryDataOperandType operand_type,
+             Register arg,
+             int16_t offset,
+             Register data) {
+    void* ptr = ToHostAddr<void>(arg + offset);
+    switch (operand_type) {
+      case Decoder::MemoryDataOperandType::k8bit:
+        Store<uint8_t>(ptr, data);
+        break;
+      case Decoder::MemoryDataOperandType::k16bit:
+        Store<uint16_t>(ptr, data);
+        break;
+      case Decoder::MemoryDataOperandType::k32bit:
+        Store<uint32_t>(ptr, data);
+        break;
+      case Decoder::MemoryDataOperandType::k64bit:
+        Store<uint64_t>(ptr, data);
+        break;
+      default:
+        return Undefined();
+    }
+  }
+
+  template <typename DataType>
+  void StoreFp(Register arg, int16_t offset, FpRegister data) {
+    UNUSED(arg, offset, data);
+    Undefined();
+  }
+
+  void CompareAndBranch(Decoder::BranchOpcode opcode,
+                        Register arg1,
+                        Register arg2,
+                        int16_t offset) {
+    bool cond_value;
+    switch (opcode) {
+      case Decoder::BranchOpcode::kBeq:
+        cond_value = arg1 == arg2;
+        break;
+      case Decoder::BranchOpcode::kBne:
+        cond_value = arg1 != arg2;
+        break;
+      case Decoder::BranchOpcode::kBltu:
+        cond_value = arg1 < arg2;
+        break;
+      case Decoder::BranchOpcode::kBgeu:
+        cond_value = arg1 >= arg2;
+        break;
+      case Decoder::BranchOpcode::kBlt:
+        cond_value = bit_cast<int64_t>(arg1) < bit_cast<int64_t>(arg2);
+        break;
+      case Decoder::BranchOpcode::kBge:
+        cond_value = bit_cast<int64_t>(arg1) >= bit_cast<int64_t>(arg2);
+        break;
+      default:
+        return Undefined();
+    }
+
+    if (cond_value) {
+      Branch(offset);
+    }
+  }
+
+  void Branch(int32_t offset) {
+    CHECK(!exception_raised_);
+    state_->cpu.insn_addr += offset;
+    branch_taken_ = true;
+  }
+
+  void BranchRegister(Register base, int16_t offset) {
+    CHECK(!exception_raised_);
+    state_->cpu.insn_addr = (base + offset) & ~uint64_t{1};
+    branch_taken_ = true;
+  }
+
+  FpRegister Fmv(FpRegister arg) { return arg; }
+
+  //
+  // V extensions.
+  //
+
+  enum class TailProcessing {
+    kUndisturbed = 0,
+    kAgnostic = 1,
+  };
+
+  enum class InactiveProcessing {
+    kUndisturbed = 0,
+    kAgnostic = 1,
+  };
+
+  enum class VectorSelectElementWidth {
+    k8bit = 0b000,
+    k16bit = 0b001,
+    k32bit = 0b010,
+    k64bit = 0b011,
+    kMaxValue = 0b111,
+  };
+
+  enum class VectorRegisterGroupMultiplier {
+    k1register = 0b000,
+    k2registers = 0b001,
+    k4registers = 0b010,
+    k8registers = 0b011,
+    kEigthOfRegister = 0b101,
+    kQuarterOfRegister = 0b110,
+    kHalfOfRegister = 0b111,
+    kMaxValue = 0b111,
+  };
+
+  static constexpr size_t NumberOfRegistersInvolved(VectorRegisterGroupMultiplier vlmul) {
+    switch (vlmul) {
+      case VectorRegisterGroupMultiplier::k2registers:
+        return 2;
+      case VectorRegisterGroupMultiplier::k4registers:
+        return 4;
+      case VectorRegisterGroupMultiplier::k8registers:
+        return 8;
+      default:
+        return 1;
+    }
+  }
+
+  static constexpr size_t NumRegistersInvolvedForWideOperand(VectorRegisterGroupMultiplier vlmul) {
+    switch (vlmul) {
+      case VectorRegisterGroupMultiplier::k1register:
+        return 2;
+      case VectorRegisterGroupMultiplier::k2registers:
+        return 4;
+      case VectorRegisterGroupMultiplier::k4registers:
+        return 8;
+      default:
+        return 1;
+    }
+  }
+
+  template <typename ElementType, VectorRegisterGroupMultiplier vlmul>
+  static constexpr size_t GetVlmax() {
+    return 0;
+  }
+
+  template <typename VOpArgs, typename... ExtraArgs>
+  void OpVector(const VOpArgs& args, [[maybe_unused]] ExtraArgs... extra_args) {
+    UNUSED(args);
+    Undefined();
+  }
+
+  template <typename ElementType, typename VOpArgs, typename... ExtraArgs>
+  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
+    UNUSED(args, vtype);
+    Undefined();
+  }
+
+  template <typename ElementType, typename VOpArgs, typename... ExtraArgs>
+  void OpVector(const VOpArgs& args,
+                VectorRegisterGroupMultiplier vlmul,
+                Register vtype,
+                [[maybe_unused]] ExtraArgs... extra_args) {
+    UNUSED(args, vlmul, vtype);
+    Undefined();
+  }
+
+  template <typename ElementType,
+            VectorRegisterGroupMultiplier vlmul,
+            typename VOpArgs,
+            typename... ExtraArgs>
+  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
+    UNUSED(args, vtype);
+    Undefined();
+  }
+
+  template <typename ElementType,
+            VectorRegisterGroupMultiplier vlmul,
+            auto vma,
+            typename VOpArgs,
+            typename... ExtraArgs>
+  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
+    UNUSED(args, vtype);
+    Undefined();
+  }
+
+  template <typename ElementType,
+            size_t kSegmentSize,
+            VectorRegisterGroupMultiplier vlmul,
+            auto vma,
+            typename VOpArgs,
+            typename... ExtraArgs>
+  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
+    UNUSED(args, vtype);
+    Undefined();
+  }
+
+  template <size_t kSegmentSize,
+            typename IndexElementType,
+            size_t kIndexRegistersInvolved,
+            TailProcessing vta,
+            auto vma,
+            typename VOpArgs,
+            typename... ExtraArgs>
+  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
+    UNUSED(args, vtype);
+    Undefined();
+  }
+
+  template <typename DataElementType,
+            size_t kSegmentSize,
+            typename IndexElementType,
+            size_t kIndexRegistersInvolved,
+            TailProcessing vta,
+            auto vma,
+            typename VOpArgs,
+            typename... ExtraArgs>
+  void OpVector(const VOpArgs& args,
+                VectorRegisterGroupMultiplier vlmul,
+                [[maybe_unused]] ExtraArgs... extra_args) {
+    UNUSED(args, vlmul);
+    Undefined();
+  }
+
+  void Nop() {}
+
+  void Undefined() {
+    // If there is a guest handler registered for SIGILL we'll delay its processing until the next
+    // sync point (likely the main dispatching loop) due to enabled pending signals. Thus we must
+    // ensure that insn_addr isn't automatically advanced in FinalizeInsn.
+    exception_raised_ = true;
+    abort();
+  }
+
+  void Unimplemented() {
+    // TODO(b/265372622): Replace with fatal from logging.h.
+    abort();
+  }
+
+  //
+  // Guest state getters/setters.
+  //
+
+  Register GetReg(uint8_t reg) const {
+    CheckRegIsValid(reg);
+    return state_->cpu.x[reg];
+  }
+
+  void SetReg(uint8_t reg, Register value) {
+    if (exception_raised_) {
+      // Do not produce side effects.
+      return;
+    }
+    CheckRegIsValid(reg);
+    state_->cpu.x[reg] = value;
+  }
+
+  FpRegister GetFpReg(uint8_t reg) const {
+    CheckFpRegIsValid(reg);
+    return state_->cpu.f[reg];
+  }
+
+  template <typename FloatType>
+  FpRegister GetFRegAndUnboxNan(uint8_t reg);
+
+  template <typename FloatType>
+  void NanBoxAndSetFpReg(uint8_t reg, FpRegister value);
+
+  //
+  // Various helper methods.
+  //
+
+  template <CsrName kName>
+  [[nodiscard]] Register GetCsr() {
+    Undefined();
+    return {};
+  }
+
+  template <CsrName kName>
+  void SetCsr(Register arg) {
+    UNUSED(arg);
+    Undefined();
+  }
+
+  uint64_t GetImm(uint64_t imm) const { return imm; }
+
+  [[nodiscard]] Register Copy(Register value) const { return value; }
+
+  void FinalizeInsn(uint8_t insn_len) {
+    if (!branch_taken_ && !exception_raised_) {
+      state_->cpu.insn_addr += insn_len;
+    }
+  }
+
+  [[nodiscard]] GuestAddr GetInsnAddr() const { return state_->cpu.insn_addr; }
+
+#include "berberis/intrinsics/interpreter_intrinsics_hooks-inl.h"
+
+ private:
+  template <typename DataType>
+  Register Load(const void* ptr) {
+    static_assert(std::is_integral_v<DataType>);
+    CHECK(!exception_raised_);
+    FaultyLoadResult result = FaultyLoad(ptr, sizeof(DataType));
+    if (result.is_fault) {
+      exception_raised_ = true;
+      return {};
+    }
+    return static_cast<DataType>(result.value);
+  }
+
+  template <typename DataType>
+  void Store(void* ptr, uint64_t data) {
+    static_assert(std::is_integral_v<DataType>);
+    CHECK(!exception_raised_);
+    exception_raised_ = FaultyStore(ptr, sizeof(DataType), data);
+  }
+
+  void CheckShamtIsValid(int8_t shamt) const {
+    CHECK_GE(shamt, 0);
+    CHECK_LT(shamt, 64);
+  }
+
+  void CheckShamt32IsValid(int8_t shamt) const {
+    CHECK_GE(shamt, 0);
+    CHECK_LT(shamt, 32);
+  }
+
+  void CheckRegIsValid(uint8_t reg) const {
+    CHECK_GT(reg, 0u);
+    CHECK_LE(reg, std::size(state_->cpu.x));
+  }
+
+  void CheckFpRegIsValid(uint8_t reg) const { CHECK_LT(reg, std::size(state_->cpu.f)); }
+
+  ProcessState* state_;
+  bool branch_taken_;
+  bool exception_raised_;
+};
+
+template <>
+[[nodiscard]] Interpreter::FpRegister inline Interpreter::GetFRegAndUnboxNan<Interpreter::Float32>(
+    uint8_t reg) {
+  UNUSED(reg);
+  Interpreter::Undefined();
+  return {};
+}
+
+template <>
+[[nodiscard]] Interpreter::FpRegister inline Interpreter::GetFRegAndUnboxNan<Interpreter::Float64>(
+    uint8_t reg) {
+  UNUSED(reg);
+  Interpreter::Undefined();
+  return {};
+}
+
+template <>
+void inline Interpreter::NanBoxAndSetFpReg<Interpreter::Float32>(uint8_t reg, FpRegister value) {
+  if (exception_raised_) {
+    // Do not produce side effects.
+    return;
+  }
+  CheckFpRegIsValid(reg);
+  state_->cpu.f[reg] = NanBox<Float32>(value);
+}
+
+template <>
+void inline Interpreter::NanBoxAndSetFpReg<Interpreter::Float64>(uint8_t reg, FpRegister value) {
+  if (exception_raised_) {
+    // Do not produce side effects.
+    return;
+  }
+  CheckFpRegIsValid(reg);
+  state_->cpu.f[reg] = value;
+}
+
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadIndexedArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadStrideArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadUnitStrideArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpFVfArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpFVvArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIViArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIVvArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIVxArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpMVvArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpMVxArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreIndexedArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreStrideArgs& args);
+template <>
+extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreUnitStrideArgs& args);
+#endif
+
+}  // namespace berberis
diff --git a/interpreter/riscv64/interpreter_arm64_test.cc b/interpreter/riscv64/interpreter_arm64_test.cc
new file mode 100644
index 00000000..95d1cae5
--- /dev/null
+++ b/interpreter/riscv64/interpreter_arm64_test.cc
@@ -0,0 +1,501 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "gtest/gtest.h"
+
+#include <cstdint>
+#include <initializer_list>
+#include <tuple>
+
+#include "berberis/base/bit_util.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/guest_state/guest_state.h"
+#include "berberis/interpreter/riscv64/interpreter.h"
+#include "berberis/runtime_primitives/memory_region_reservation.h"
+
+namespace berberis {
+
+namespace {
+
+class Riscv64ToArm64InterpreterTest : public ::testing::Test {
+ public:
+  template <uint8_t kInsnSize = 4>
+  bool RunOneInstruction(ThreadState* state, GuestAddr stop_pc) {
+    InterpretInsn(state);
+    return state->cpu.insn_addr == stop_pc;
+  }
+
+  template <uint8_t kInsnSize = 4>
+  void RunInstruction(const uint32_t& insn_bytes) {
+    state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
+    InterpretInsn(&state_);
+  }
+
+  void TestOp(uint32_t insn_bytes,
+              // The tuple is [arg1, arg2, expected_result].
+              std::initializer_list<std::tuple<uint64_t, uint64_t, uint64_t>> args) {
+    for (auto arg : args) {
+      SetXReg<2>(state_.cpu, std::get<0>(arg));
+      SetXReg<3>(state_.cpu, std::get<1>(arg));
+      RunInstruction(insn_bytes);
+      EXPECT_EQ(GetXReg<1>(state_.cpu), std::get<2>(arg));
+    }
+  }
+
+  void TestOpImm(uint32_t insn_bytes,
+                 std::initializer_list<std::tuple<uint64_t, uint16_t, uint64_t>> args) {
+    for (auto [arg1, imm, expected_result] : args) {
+      CHECK_LE(imm, 63);
+      uint32_t insn_bytes_with_immediate = insn_bytes | imm << 20;
+      SetXReg<2>(state_.cpu, arg1);
+      RunInstruction(insn_bytes_with_immediate);
+      EXPECT_EQ(GetXReg<1>(state_.cpu), expected_result);
+    }
+  }
+
+  void TestAuipc(uint32_t insn_bytes, uint64_t expected_offset) {
+    RunInstruction(insn_bytes);
+    EXPECT_EQ(GetXReg<1>(state_.cpu), expected_offset + ToGuestAddr(&insn_bytes));
+  }
+
+  void TestLui(uint32_t insn_bytes, uint64_t expected_result) {
+    RunInstruction(insn_bytes);
+    EXPECT_EQ(GetXReg<1>(state_.cpu), expected_result);
+  }
+
+  void TestBranch(uint32_t insn_bytes,
+                  std::initializer_list<std::tuple<uint64_t, uint64_t, int8_t>> args) {
+    auto code_start = ToGuestAddr(&insn_bytes);
+    for (auto [arg1, arg2, expected_offset] : args) {
+      state_.cpu.insn_addr = code_start;
+      SetXReg<1>(state_.cpu, arg1);
+      SetXReg<2>(state_.cpu, arg2);
+      InterpretInsn(&state_);
+      EXPECT_EQ(state_.cpu.insn_addr, code_start + expected_offset);
+    }
+  }
+
+  void TestJumpAndLink(uint32_t insn_bytes, int8_t expected_offset) {
+    auto code_start = ToGuestAddr(&insn_bytes);
+    state_.cpu.insn_addr = code_start;
+    InterpretInsn(&state_);
+    EXPECT_EQ(state_.cpu.insn_addr, code_start + expected_offset);
+    EXPECT_EQ(GetXReg<1>(state_.cpu), code_start + 4);
+  }
+
+  void TestLoad(uint32_t insn_bytes, uint64_t expected_result) {
+    // Offset is always 8.
+    SetXReg<2>(state_.cpu, ToGuestAddr(bit_cast<uint8_t*>(&kDataToLoad) - 8));
+    RunInstruction(insn_bytes);
+    EXPECT_EQ(GetXReg<1>(state_.cpu), expected_result);
+  }
+
+  // kLinkRegisterOffsetIfUsed is size of instruction or 0 if instruction does not link register.
+  template <uint8_t kLinkRegisterOffsetIfUsed>
+  void TestJumpAndLinkRegister(uint32_t insn_bytes, uint64_t base_disp, int64_t expected_offset) {
+    auto code_start = ToGuestAddr(&insn_bytes);
+    state_.cpu.insn_addr = code_start;
+    SetXReg<1>(state_.cpu, 0);
+    SetXReg<2>(state_.cpu, code_start + base_disp);
+    InterpretInsn(&state_);
+    EXPECT_EQ(state_.cpu.insn_addr, code_start + expected_offset);
+    if constexpr (kLinkRegisterOffsetIfUsed == 0) {
+      EXPECT_EQ(GetXReg<1>(state_.cpu), 0UL);
+    } else {
+      EXPECT_EQ(GetXReg<1>(state_.cpu), code_start + kLinkRegisterOffsetIfUsed);
+    }
+  }
+
+  void TestStore(uint32_t insn_bytes, uint64_t expected_result) {
+    // Offset is always 8.
+    SetXReg<1>(state_.cpu, ToGuestAddr(bit_cast<uint8_t*>(&store_area_) - 8));
+    SetXReg<2>(state_.cpu, kDataToStore);
+    store_area_ = 0;
+    RunInstruction(insn_bytes);
+    EXPECT_EQ(store_area_, expected_result);
+  }
+
+  void TestAtomicLoad(uint32_t insn_bytes,
+                      const uint64_t* const data_to_load,
+                      uint64_t expected_result) {
+    state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
+    SetXReg<1>(state_.cpu, ToGuestAddr(data_to_load));
+    EXPECT_TRUE(RunOneInstruction(&state_, state_.cpu.insn_addr + 4));
+    EXPECT_EQ(GetXReg<2>(state_.cpu), expected_result);
+    EXPECT_EQ(state_.cpu.reservation_address, ToGuestAddr(data_to_load));
+    // We always reserve the full 64-bit range of the reservation address.
+    EXPECT_EQ(state_.cpu.reservation_value, *data_to_load);
+  }
+
+  template <typename T>
+  void TestAtomicStore(uint32_t insn_bytes, T expected_result) {
+    store_area_ = ~uint64_t{0};
+    state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
+    SetXReg<1>(state_.cpu, ToGuestAddr(&store_area_));
+    SetXReg<2>(state_.cpu, kDataToStore);
+    SetXReg<3>(state_.cpu, 0xdeadbeef);
+    state_.cpu.reservation_address = ToGuestAddr(&store_area_);
+    state_.cpu.reservation_value = store_area_;
+    MemoryRegionReservation::SetOwner(ToGuestAddr(&store_area_), &state_.cpu);
+    EXPECT_TRUE(RunOneInstruction(&state_, state_.cpu.insn_addr + 4));
+    EXPECT_EQ(static_cast<T>(store_area_), expected_result);
+    EXPECT_EQ(GetXReg<3>(state_.cpu), 0u);
+  }
+
+  void TestAtomicStoreNoLoadFailure(uint32_t insn_bytes) {
+    state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
+    SetXReg<1>(state_.cpu, ToGuestAddr(&store_area_));
+    SetXReg<2>(state_.cpu, kDataToStore);
+    SetXReg<3>(state_.cpu, 0xdeadbeef);
+    store_area_ = 0;
+    EXPECT_TRUE(RunOneInstruction(&state_, state_.cpu.insn_addr + 4));
+    EXPECT_EQ(store_area_, 0u);
+    EXPECT_EQ(GetXReg<3>(state_.cpu), 1u);
+  }
+
+  void TestAtomicStoreDifferentLoadFailure(uint32_t insn_bytes) {
+    state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
+    SetXReg<1>(state_.cpu, ToGuestAddr(&store_area_));
+    SetXReg<2>(state_.cpu, kDataToStore);
+    SetXReg<3>(state_.cpu, 0xdeadbeef);
+    state_.cpu.reservation_address = ToGuestAddr(&kDataToStore);
+    state_.cpu.reservation_value = 0;
+    MemoryRegionReservation::SetOwner(ToGuestAddr(&kDataToStore), &state_.cpu);
+    store_area_ = 0;
+    EXPECT_TRUE(RunOneInstruction(&state_, state_.cpu.insn_addr + 4));
+    EXPECT_EQ(store_area_, 0u);
+    EXPECT_EQ(GetXReg<3>(state_.cpu), 1u);
+  }
+
+  void TestAmo(uint32_t insn_bytes,
+               uint64_t arg1,
+               uint64_t arg2,
+               uint64_t expected_result,
+               uint64_t expected_memory) {
+    // Copy arg1 into store_area_
+    store_area_ = arg1;
+    SetXReg<2>(state_.cpu, ToGuestAddr(bit_cast<uint8_t*>(&store_area_)));
+    SetXReg<3>(state_.cpu, arg2);
+    RunInstruction(insn_bytes);
+    EXPECT_EQ(GetXReg<1>(state_.cpu), expected_result);
+    EXPECT_EQ(store_area_, expected_memory);
+  }
+
+  void TestAmo(uint32_t insn_bytes32, uint32_t insn_bytes64, uint64_t expected_memory) {
+    TestAmo(insn_bytes32,
+            0xffff'eeee'dddd'ccccULL,
+            0xaaaa'bbbb'cccc'ddddULL,
+            0xffff'ffff'dddd'ccccULL,
+            0xffff'eeee'0000'0000 | uint32_t(expected_memory));
+    TestAmo(insn_bytes64,
+            0xffff'eeee'dddd'ccccULL,
+            0xaaaa'bbbb'cccc'ddddULL,
+            0xffff'eeee'dddd'ccccULL,
+            expected_memory);
+  }
+
+ protected:
+  static constexpr uint64_t kDataToLoad{0xffffeeeeddddccccULL};
+  static constexpr uint64_t kDataToStore = kDataToLoad;
+  uint64_t store_area_;
+  ThreadState state_;
+};
+
+TEST_F(Riscv64ToArm64InterpreterTest, OpInstructions) {
+  // Add
+  TestOp(0x003100b3, {{19, 23, 42}});
+  // Sub
+  TestOp(0x403100b3, {{42, 23, 19}});
+  // And
+  TestOp(0x003170b3, {{0b0101, 0b0011, 0b0001}});
+  // Or
+  TestOp(0x003160b3, {{0b0101, 0b0011, 0b0111}});
+  // Xor
+  TestOp(0x003140b3, {{0b0101, 0b0011, 0b0110}});
+  // Sll
+  TestOp(0x003110b3, {{0b1010, 3, 0b1010'000}});
+  // Srl
+  TestOp(0x003150b3, {{0xf000'0000'0000'0000ULL, 12, 0x000f'0000'0000'0000ULL}});
+  // Sra
+  TestOp(0x403150b3, {{0xf000'0000'0000'0000ULL, 12, 0xffff'0000'0000'0000ULL}});
+  // Slt
+  TestOp(0x003120b3,
+         {
+             {19, 23, 1},
+             {23, 19, 0},
+             {~0ULL, 0, 1},
+         });
+  // Sltu
+  TestOp(0x003130b3,
+         {
+             {19, 23, 1},
+             {23, 19, 0},
+             {~0ULL, 0, 0},
+         });
+  // Andn
+  TestOp(0x403170b3, {{0b0101, 0b0011, 0b0100}});
+  // Orn
+  TestOp(0x403160b3, {{0b0101, 0b0011, 0xffff'ffff'ffff'fffd}});
+  // Xnor
+  TestOp(0x403140b3, {{0b0101, 0b0011, 0xffff'ffff'ffff'fff9}});
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, OpImmInstructions) {
+  // Addi
+  TestOpImm(0x00010093, {{19, 23, 42}});
+  // Slti
+  TestOpImm(0x00012093,
+            {
+                {19, 23, 1},
+                {23, 19, 0},
+                {~0ULL, 0, 1},
+            });
+  // Sltiu
+  TestOpImm(0x00013093,
+            {
+                {19, 23, 1},
+                {23, 19, 0},
+                {~0ULL, 0, 0},
+            });
+  // Xori
+  TestOpImm(0x00014093, {{0b0101, 0b0011, 0b0110}});
+  // Ori
+  TestOpImm(0x00016093, {{0b0101, 0b0011, 0b0111}});
+  // Andi
+  TestOpImm(0x00017093, {{0b0101, 0b0011, 0b0001}});
+  // Slli
+  TestOpImm(0x00011093, {{0b1010, 3, 0b1010'000}});
+  // Srli
+  TestOpImm(0x00015093, {{0xf000'0000'0000'0000ULL, 12, 0x000f'0000'0000'0000ULL}});
+  // Srai
+  TestOpImm(0x40015093, {{0xf000'0000'0000'0000ULL, 12, 0xffff'0000'0000'0000ULL}});
+  // Rori
+  TestOpImm(0x60015093, {{0xf000'0000'0000'000fULL, 4, 0xff00'0000'0000'0000ULL}});
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, UpperImmInstructions) {
+  // Auipc
+  TestAuipc(0xfedcb097, 0xffff'ffff'fedc'b000);
+  // Lui
+  TestLui(0xfedcb0b7, 0xffff'ffff'fedc'b000);
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, TestBranchInstructions) {
+  // Beq
+  TestBranch(0x00208463,
+             {
+                 {42, 42, 8},
+                 {41, 42, 4},
+                 {42, 41, 4},
+             });
+  // Bne
+  TestBranch(0x00209463,
+             {
+                 {42, 42, 4},
+                 {41, 42, 8},
+                 {42, 41, 8},
+             });
+  // Bltu
+  TestBranch(0x0020e463,
+             {
+                 {41, 42, 8},
+                 {42, 42, 4},
+                 {42, 41, 4},
+                 {0xf000'0000'0000'0000ULL, 42, 4},
+                 {42, 0xf000'0000'0000'0000ULL, 8},
+             });
+  // Bgeu
+  TestBranch(0x0020f463,
+             {
+                 {42, 41, 8},
+                 {42, 42, 8},
+                 {41, 42, 4},
+                 {0xf000'0000'0000'0000ULL, 42, 8},
+                 {42, 0xf000'0000'0000'0000ULL, 4},
+             });
+  // Blt
+  TestBranch(0x0020c463,
+             {
+                 {41, 42, 8},
+                 {42, 42, 4},
+                 {42, 41, 4},
+                 {0xf000'0000'0000'0000ULL, 42, 8},
+                 {42, 0xf000'0000'0000'0000ULL, 4},
+             });
+  // Bge
+  TestBranch(0x0020d463,
+             {
+                 {42, 41, 8},
+                 {42, 42, 8},
+                 {41, 42, 4},
+                 {0xf000'0000'0000'0000ULL, 42, 4},
+                 {42, 0xf000'0000'0000'0000ULL, 8},
+             });
+  // Beq with negative offset.
+  TestBranch(0xfe208ee3,
+             {
+                 {42, 42, -4},
+             });
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, JumpAndLinkInstructions) {
+  // Jal
+  TestJumpAndLink(0x008000ef, 8);
+  // Jal with negative offset.
+  TestJumpAndLink(0xffdff0ef, -4);
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, JumpAndLinkRegisterInstructions) {
+  // Jalr offset=4.
+  TestJumpAndLinkRegister<4>(0x004100e7, 38, 42);
+  // Jalr offset=-4.
+  TestJumpAndLinkRegister<4>(0xffc100e7, 42, 38);
+  // Jalr offset=5 - must properly align the target to even.
+  TestJumpAndLinkRegister<4>(0x005100e7, 38, 42);
+  // Jr offset=4.
+  TestJumpAndLinkRegister<0>(0x00410067, 38, 42);
+  // Jr offset=-4.
+  TestJumpAndLinkRegister<0>(0xffc10067, 42, 38);
+  // Jr offset=5 - must properly align the target to even.
+  TestJumpAndLinkRegister<0>(0x00510067, 38, 42);
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, LoadInstructions) {
+  // Offset is always 8.
+  // Lbu
+  TestLoad(0x00814083, kDataToLoad & 0xffULL);
+  // Lhu
+  TestLoad(0x00815083, kDataToLoad & 0xffffULL);
+  // Lwu
+  TestLoad(0x00816083, kDataToLoad & 0xffff'ffffULL);
+  // Ldu
+  TestLoad(0x00813083, kDataToLoad);
+  // Lb
+  TestLoad(0x00810083, int64_t{int8_t(kDataToLoad)});
+  // Lh
+  TestLoad(0x00811083, int64_t{int16_t(kDataToLoad)});
+  // Lw
+  TestLoad(0x00812083, int64_t{int32_t(kDataToLoad)});
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, StoreInstructions) {
+  // Offset is always 8.
+  // Sb
+  TestStore(0x00208423, kDataToStore & 0xffULL);
+  // Sh
+  TestStore(0x00209423, kDataToStore & 0xffffULL);
+  // Sw
+  TestStore(0x0020a423, kDataToStore & 0xffff'ffffULL);
+  // Sd
+  TestStore(0x0020b423, kDataToStore);
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, AtomicLoadInstructions) {
+  // Validate sign-extension of returned value.
+  const uint64_t kNegative32BitValue = 0x0000'0000'8000'0000ULL;
+  const uint64_t kSignExtendedNegative = 0xffff'ffff'8000'0000ULL;
+  const uint64_t kPositive32BitValue = 0xffff'ffff'0000'0000ULL;
+  const uint64_t kSignExtendedPositive = 0ULL;
+  static_assert(static_cast<int32_t>(kSignExtendedPositive) >= 0);
+  static_assert(static_cast<int32_t>(kSignExtendedNegative) < 0);
+
+  // Lrw - sign extends from 32 to 64.
+  TestAtomicLoad(0x1000a12f, &kPositive32BitValue, kSignExtendedPositive);
+  TestAtomicLoad(0x1000a12f, &kNegative32BitValue, kSignExtendedNegative);
+
+  // Lrd
+  TestAtomicLoad(0x1000b12f, &kDataToLoad, kDataToLoad);
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, AtomicStoreInstructions) {
+  // Scw
+  TestAtomicStore(0x1820a1af, static_cast<uint32_t>(kDataToStore));
+
+  // Scd
+  TestAtomicStore(0x1820b1af, kDataToStore);
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, AtomicStoreInstructionNoLoadFailure) {
+  // Scw
+  TestAtomicStoreNoLoadFailure(0x1820a1af);
+
+  // Scd
+  TestAtomicStoreNoLoadFailure(0x1820b1af);
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, AtomicStoreInstructionDifferentLoadFailure) {
+  // Scw
+  TestAtomicStoreDifferentLoadFailure(0x1820a1af);
+
+  // Scd
+  TestAtomicStoreDifferentLoadFailure(0x1820b1af);
+}
+
+TEST_F(Riscv64ToArm64InterpreterTest, AmoInstructions) {
+  // Verifying that all aq and rl combinations work for Amoswap, but only test relaxed one for most
+  // other instructions for brevity.
+
+  // AmoswaoW/AmoswaoD
+  TestAmo(0x083120af, 0x083130af, 0xaaaa'bbbb'cccc'ddddULL);
+
+  // AmoswapWAq/AmoswapDAq
+  TestAmo(0x0c3120af, 0x0c3130af, 0xaaaa'bbbb'cccc'ddddULL);
+
+  // AmoswapWRl/AmoswapDRl
+  TestAmo(0x0a3120af, 0x0a3130af, 0xaaaa'bbbb'cccc'ddddULL);
+
+  // AmoswapWAqrl/AmoswapDAqrl
+  TestAmo(0x0e3120af, 0x0e3130af, 0xaaaa'bbbb'cccc'ddddULL);
+
+  // AmoaddW/AmoaddD
+  TestAmo(0x003120af, 0x003130af, 0xaaaa'aaaa'aaaa'aaa9);
+
+  // AmoxorW/AmoxorD
+  TestAmo(0x203120af, 0x203130af, 0x5555'5555'1111'1111);
+
+  // AmoandW/AmoandD
+  TestAmo(0x603120af, 0x603130af, 0xaaaa'aaaa'cccc'cccc);
+
+  // AmoorW/AmoorD
+  TestAmo(0x403120af, 0x403130af, 0xffff'ffff'dddd'dddd);
+
+  // AmominW/AmominD
+  TestAmo(0x803120af, 0x803130af, 0xaaaa'bbbb'cccc'ddddULL);
+
+  // AmomaxW/AmomaxD
+  TestAmo(0xa03120af, 0xa03130af, 0xffff'eeee'dddd'ccccULL);
+
+  // AmominuW/AmominuD
+  TestAmo(0xc03120af, 0xc03130af, 0xaaaa'bbbb'cccc'ddddULL);
+
+  // AmomaxuW/AmomaxuD
+  TestAmo(0xe03120af, 0xe03130af, 0xffff'eeee'dddd'ccccULL);
+}
+
+// Corresponding to interpreter_test.cc
+
+TEST_F(Riscv64ToArm64InterpreterTest, FenceInstructions) {
+  // Fence
+  RunInstruction(0x0ff0000f);
+  // FenceTso
+  RunInstruction(0x8330000f);
+
+  // FenceI explicitly not supported.
+}
+
+}  // namespace
+
+}  // namespace berberis
diff --git a/interpreter/riscv64/interpreter_test.cc b/interpreter/riscv64/interpreter_test.cc
index ecc21dd2..100c72d2 100644
--- a/interpreter/riscv64/interpreter_test.cc
+++ b/interpreter/riscv64/interpreter_test.cc
@@ -38,7 +38,8 @@
 #include "berberis/intrinsics/simd_register.h"
 #include "berberis/intrinsics/vector_intrinsics.h"
 #include "berberis/runtime_primitives/memory_region_reservation.h"
-#include "faulty_memory_accesses.h"
+
+#include "../faulty_memory_accesses.h"
 
 namespace berberis {
 
@@ -1098,18 +1099,18 @@ class Riscv64InterpreterTest : public ::testing::Test {
   }
 
   void TestVectorFloatInstruction(uint32_t insn_bytes,
-                                  const uint32_t (&expected_result_int32)[8][4],
-                                  const uint64_t (&expected_result_int64)[8][2],
+                                  const UInt32x4Tuple (&expected_result_int32)[8],
+                                  const UInt64x2Tuple (&expected_result_int64)[8],
                                   const __v2du (&source)[16]) {
     TestVectorInstruction<TestVectorInstructionKind::kFloat, TestVectorInstructionMode::kDefault>(
         insn_bytes, source, expected_result_int32, expected_result_int64);
   }
 
   void TestVectorInstruction(uint32_t insn_bytes,
-                             const uint8_t (&expected_result_int8)[8][16],
-                             const uint16_t (&expected_result_int16)[8][8],
-                             const uint32_t (&expected_result_int32)[8][4],
-                             const uint64_t (&expected_result_int64)[8][2],
+                             const UInt8x16Tuple (&expected_result_int8)[8],
+                             const UInt16x8Tuple (&expected_result_int16)[8],
+                             const UInt32x4Tuple (&expected_result_int32)[8],
+                             const UInt64x2Tuple (&expected_result_int64)[8],
                              const __v2du (&source)[16]) {
     TestVectorInstruction<TestVectorInstructionKind::kInteger, TestVectorInstructionMode::kDefault>(
         insn_bytes,
@@ -1121,18 +1122,18 @@ class Riscv64InterpreterTest : public ::testing::Test {
   }
 
   void TestVectorMergeFloatInstruction(uint32_t insn_bytes,
-                                       const uint32_t (&expected_result_int32)[8][4],
-                                       const uint64_t (&expected_result_int64)[8][2],
+                                       const UInt32x4Tuple (&expected_result_int32)[8],
+                                       const UInt64x2Tuple (&expected_result_int64)[8],
                                        const __v2du (&source)[16]) {
     TestVectorInstruction<TestVectorInstructionKind::kFloat, TestVectorInstructionMode::kVMerge>(
         insn_bytes, source, expected_result_int32, expected_result_int64);
   }
 
   void TestVectorMergeInstruction(uint32_t insn_bytes,
-                                  const uint8_t (&expected_result_int8)[8][16],
-                                  const uint16_t (&expected_result_int16)[8][8],
-                                  const uint32_t (&expected_result_int32)[8][4],
-                                  const uint64_t (&expected_result_int64)[8][2],
+                                  const UInt8x16Tuple (&expected_result_int8)[8],
+                                  const UInt16x8Tuple (&expected_result_int16)[8],
+                                  const UInt32x4Tuple (&expected_result_int32)[8],
+                                  const UInt64x2Tuple (&expected_result_int64)[8],
                                   const __v2du (&source)[16]) {
     TestVectorInstruction<TestVectorInstructionKind::kInteger, TestVectorInstructionMode::kVMerge>(
         insn_bytes,
@@ -1144,7 +1145,7 @@ class Riscv64InterpreterTest : public ::testing::Test {
   }
 
   void TestWideningVectorFloatInstruction(uint32_t insn_bytes,
-                                          const uint64_t (&expected_result_int64)[8][2],
+                                          const UInt64x2Tuple (&expected_result_int64)[8],
                                           const __v2du (&source)[16],
                                           __m128i dst_result = kUndisturbedResult) {
     TestVectorInstructionInternal<TestVectorInstructionKind::kFloat,
@@ -1153,8 +1154,8 @@ class Riscv64InterpreterTest : public ::testing::Test {
   }
 
   void TestWideningVectorFloatInstruction(uint32_t insn_bytes,
-                                          const uint32_t (&expected_result_int32)[8][4],
-                                          const uint64_t (&expected_result_int64)[8][2],
+                                          const UInt32x4Tuple (&expected_result_int32)[8],
+                                          const UInt64x2Tuple (&expected_result_int64)[8],
                                           const __v2du (&source)[16]) {
     TestVectorInstruction<TestVectorInstructionKind::kFloat, TestVectorInstructionMode::kWidening>(
         insn_bytes, source, expected_result_int32, expected_result_int64);
@@ -1165,27 +1166,21 @@ class Riscv64InterpreterTest : public ::testing::Test {
 
   template <TestVectorInstructionKind kTestVectorInstructionKind,
             TestVectorInstructionMode kTestVectorInstructionMode,
-            typename... ElementType,
-            size_t... kResultsCount,
-            size_t... kElementCount>
-  void TestVectorInstruction(
-      uint32_t insn_bytes,
-      const __v2du (&source)[16],
-      const ElementType (&... expected_result)[kResultsCount][kElementCount]) {
+            typename... ExpectedResultType>
+  void TestVectorInstruction(uint32_t insn_bytes,
+                             const __v2du (&source)[16],
+                             const ExpectedResultType&... expected_result) {
     TestVectorInstructionInternal<kTestVectorInstructionKind, kTestVectorInstructionMode>(
         insn_bytes, kUndisturbedResult, source, expected_result...);
   }
 
   template <TestVectorInstructionKind kTestVectorInstructionKind,
             TestVectorInstructionMode kTestVectorInstructionMode,
-            typename... ElementType,
-            size_t... kResultsCount,
-            size_t... kElementCount>
-  void TestVectorInstructionInternal(
-      uint32_t insn_bytes,
-      __m128i dst_result,
-      const __v2du (&source)[16],
-      const ElementType (&... expected_result)[kResultsCount][kElementCount]) {
+            typename... ExpectedResultType>
+  void TestVectorInstructionInternal(uint32_t insn_bytes,
+                                     __m128i dst_result,
+                                     const __v2du (&source)[16],
+                                     const ExpectedResultType&... expected_result) {
     auto Verify = [this, &source, dst_result](uint32_t insn_bytes,
                                               uint8_t vsew,
                                               uint8_t vlmul_max,
@@ -1318,15 +1313,15 @@ class Riscv64InterpreterTest : public ::testing::Test {
     // Every insruction is tested with vm bit not set (and mask register used) and with vm bit
     // set (and mask register is not used).
     ((Verify(insn_bytes,
-             BitUtilLog2(sizeof(ElementType)) -
+             BitUtilLog2(sizeof(std::remove_cvref_t<decltype(std::get<0>(expected_result[0]))>)) -
                  (kTestVectorInstructionMode == TestVectorInstructionMode::kWidening),
              8,
              expected_result,
-             MaskForElem<ElementType>()),
+             MaskForElem<std::remove_cvref_t<decltype(std::get<0>(expected_result[0]))>>()),
       Verify((insn_bytes &
               ~(0x01f00000 * (kTestVectorInstructionMode == TestVectorInstructionMode::kVMerge))) |
                  (1 << 25),
-             BitUtilLog2(sizeof(ElementType)) -
+             BitUtilLog2(sizeof(std::remove_cvref_t<decltype(std::get<0>(expected_result[0]))>)) -
                  (kTestVectorInstructionMode == TestVectorInstructionMode::kWidening),
              8,
              expected_result,
@@ -1402,7 +1397,7 @@ class Riscv64InterpreterTest : public ::testing::Test {
   }
 
   void TestVectorMaskTargetInstruction(uint32_t insn_bytes,
-                                       const uint8_t (&expected_result_int8)[16],
+                                       const UInt8x16Tuple(&expected_result_int8),
                                        const uint64_t expected_result_int16,
                                        const uint32_t expected_result_int32,
                                        const uint16_t expected_result_int64,
@@ -1506,161 +1501,136 @@ class Riscv64InterpreterTest : public ::testing::Test {
      ...);
   }
 
-  void TestVXmXXsInstruction(uint32_t insn_bytes,
-                            const uint64_t (&expected_result_no_mask)[129],
-                            const uint64_t (&expected_result_with_mask)[129],
-                            const __v2du source) {
-    auto Verify = [this, &source](uint32_t insn_bytes,
-                                  const uint64_t (&expected_result)[129]) {
-      state_.cpu.v[0] = SIMD128Register{kMask}.Get<__uint128_t>();
-
-      auto [vlmax, vtype] = intrinsics::Vsetvl(~0ULL, 3);
-      state_.cpu.vtype = vtype;
-      state_.cpu.vstart = 0;
-      state_.cpu.v[16] = SIMD128Register{source}.Get<__uint128_t>();
-
-      for (uint8_t vl = 0; vl <= vlmax; ++vl) {
-        state_.cpu.vl = vl;
-        SetXReg<1>(state_.cpu, 0xaaaa'aaaa'aaaa'aaaa);
-
-        state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
-        EXPECT_TRUE(RunOneInstruction(&state_, state_.cpu.insn_addr + 4));
-        EXPECT_EQ(GetXReg<1>(state_.cpu), expected_result[vl]) << std::to_string(vl);
-      }
-    };
-
-    Verify(insn_bytes, expected_result_with_mask);
-    Verify(insn_bytes | (1 << 25), expected_result_no_mask);
-  }
-
-  void TestVectorReductionInstruction(uint32_t insn_bytes,
-                                      const uint32_t (&expected_result_vd0_int32)[8],
-                                      const uint64_t (&expected_result_vd0_int64)[8],
-                                      const uint32_t (&expected_result_vd0_with_mask_int32)[8],
-                                      const uint64_t (&expected_result_vd0_with_mask_int64)[8],
-                                      const __v2du (&source)[16]) {
-    TestVectorReductionInstruction(
-        insn_bytes,
-        source,
-        std::tuple<const uint32_t(&)[8], const uint32_t(&)[8]>{expected_result_vd0_int32,
-                                                               expected_result_vd0_with_mask_int32},
-        std::tuple<const uint64_t(&)[8], const uint64_t(&)[8]>{
-            expected_result_vd0_int64, expected_result_vd0_with_mask_int64});
-  }
-
-  void TestVectorReductionInstruction(uint32_t insn_bytes,
-                                      const uint8_t (&expected_result_vd0_int8)[8],
-                                      const uint16_t (&expected_result_vd0_int16)[8],
-                                      const uint32_t (&expected_result_vd0_int32)[8],
-                                      const uint64_t (&expected_result_vd0_int64)[8],
-                                      const uint8_t (&expected_result_vd0_with_mask_int8)[8],
-                                      const uint16_t (&expected_result_vd0_with_mask_int16)[8],
-                                      const uint32_t (&expected_result_vd0_with_mask_int32)[8],
-                                      const uint64_t (&expected_result_vd0_with_mask_int64)[8],
-                                      const __v2du (&source)[16]) {
-    TestVectorReductionInstruction(
-        insn_bytes,
-        source,
-        std::tuple<const uint8_t(&)[8], const uint8_t(&)[8]>{expected_result_vd0_int8,
-                                                             expected_result_vd0_with_mask_int8},
-        std::tuple<const uint16_t(&)[8], const uint16_t(&)[8]>{expected_result_vd0_int16,
-                                                               expected_result_vd0_with_mask_int16},
-        std::tuple<const uint32_t(&)[8], const uint32_t(&)[8]>{expected_result_vd0_int32,
-                                                               expected_result_vd0_with_mask_int32},
-        std::tuple<const uint64_t(&)[8], const uint64_t(&)[8]>{
-            expected_result_vd0_int64, expected_result_vd0_with_mask_int64});
-  }
+  void TestVectorCarryInstruction(uint32_t insn_bytes,
+                                  const UInt8x16Tuple (&expected_result_int8)[8],
+                                  const UInt16x8Tuple (&expected_result_int16)[8],
+                                  const UInt32x4Tuple (&expected_result_int32)[8],
+                                  const UInt64x2Tuple (&expected_result_int64)[8],
+                                  const __v2du (&source)[16]) {
+    auto Verify = [this, &source](uint32_t insn_bytes, uint8_t vsew, const auto& expected_result) {
+      __m128i dst_result = kUndisturbedResult;
 
-  template <typename... ExpectedResultType>
-  void TestVectorReductionInstruction(
-      uint32_t insn_bytes,
-      const __v2du (&source)[16],
-      std::tuple<const ExpectedResultType (&)[8],
-                 const ExpectedResultType (&)[8]>... expected_result) {
-    // Each expected_result input to this function is the vd[0] value of the reduction, for each
-    // of the possible vlmul, i.e. expected_result_vd0_int8[n] = vd[0], int8, no mask, vlmul=n.
-    //
-    // As vlmul=4 is reserved, expected_result_vd0_*[4] is ignored.
-    auto Verify = [this, &source](uint32_t insn_bytes,
-                                  uint8_t vsew,
-                                  uint8_t vlmul,
-                                  const auto& expected_result) {
-      // Mask register is, unconditionally, v0, and we need 8, 16, or 24 to handle full 8-registers
-      // inputs thus we use v8..v15 for destination and place sources into v16..v23 and v24..v31.
+      // Set mask register
       state_.cpu.v[0] = SIMD128Register{kMask}.Get<__uint128_t>();
+
+      // Set source registers
       for (size_t index = 0; index < std::size(source); ++index) {
         state_.cpu.v[16 + index] = SIMD128Register{source[index]}.Get<__uint128_t>();
       }
-      for (uint8_t vta = 0; vta < 2; ++vta) {
-        for (uint8_t vma = 0; vma < 2; ++vma) {
+
+      // Set x1 for vx instructions.
+      SetXReg<1>(state_.cpu, 0xaaaa'aaaa'aaaa'aaaa);
+
+      for (uint8_t vlmul = 0; vlmul < 8; ++vlmul) {
+        for (uint8_t vta = 0; vta < 2; ++vta) {
+          uint8_t vma = 0;
           auto [vlmax, vtype] =
               intrinsics::Vsetvl(~0ULL, (vma << 7) | (vta << 6) | (vsew << 3) | vlmul);
           // Incompatible vsew and vlmax. Skip it.
           if (vlmax == 0) {
             continue;
           }
+          uint8_t emul = vlmul & 0b111;
 
-          // Vector reduction instructions must always have a vstart=0.
-          state_.cpu.vstart = 0;
-          state_.cpu.vl = vlmax;
+          // To make tests quick enough we don't test vstart and vl change with small register
+          // sets. Only with vlmul == 2 (4 registers) we set vstart and vl to skip half of first
+          // register, last register and half of next-to last register.
+          // Don't use vlmul == 3 because that one may not be supported if instruction widens the
+          // result.
+          if (vlmul == 2) {
+            state_.cpu.vstart = vlmax / 8;
+            state_.cpu.vl = (vlmax * 5) / 8;
+          } else {
+            state_.cpu.vstart = 0;
+            state_.cpu.vl = vlmax;
+          }
           state_.cpu.vtype = vtype;
 
           // Set expected_result vector registers into 0b01010101… pattern.
           for (size_t index = 0; index < 8; ++index) {
-            state_.cpu.v[8 + index] = SIMD128Register{kUndisturbedResult}.Get<__uint128_t>();
+            state_.cpu.v[8 + index] = SIMD128Register{dst_result}.Get<__uint128_t>();
           }
 
           state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
           EXPECT_TRUE(RunOneInstruction(&state_, state_.cpu.insn_addr + 4));
 
-          // Reduction instructions are unique in that they produce a scalar
-          // output to a single vector register as opposed to a register group.
-          // This allows us to take some short-cuts when validating:
-          //
-          // - The mask setting is only useful during computation, as the body
-          // of the destination is always only element 0, which will always be
-          // written to, regardless of mask setting.
-          // - The tail is guaranteed to be 1..VLEN/SEW, so the vlmul setting
-          // does not affect the elements that the tail policy applies to in the
-          // destination register.
-
-          // Verify that the destination register holds the reduction in the
-          // first element and the tail policy applies to the remaining.
-          size_t vsew_bits = 8 << vsew;
-          __uint128_t expected_result_register =
-            SIMD128Register{vta ? kAgnosticResult : kUndisturbedResult}.Get<__uint128_t>();
-          expected_result_register = (expected_result_register >> vsew_bits) << vsew_bits;
-          expected_result_register |= expected_result;
-          EXPECT_EQ(state_.cpu.v[8], expected_result_register);
-
-          // Verify all non-destination registers are undisturbed.
-          for (size_t index = 1; index < 8; ++index) {
-            EXPECT_EQ(state_.cpu.v[8 + index], SIMD128Register{kUndisturbedResult}.Get<__uint128_t>());
+          if (emul < 4) {
+            for (size_t index = 0; index < 1 << emul; ++index) {
+              if (index == 0 && emul == 2) {
+                EXPECT_EQ(state_.cpu.v[8 + index],
+                          ((dst_result & kFractionMaskInt8[3]) |
+                           (SIMD128Register{expected_result[index]} & ~kFractionMaskInt8[3]))
+                              .template Get<__uint128_t>());
+              } else if (index == 2 && emul == 2) {
+                EXPECT_EQ(state_.cpu.v[8 + index],
+                          ((SIMD128Register{expected_result[index]} & kFractionMaskInt8[3]) |
+                           ((vta ? kAgnosticResult : dst_result) & ~kFractionMaskInt8[3]))
+                              .template Get<__uint128_t>());
+              } else if (index == 3 && emul == 2 && vta) {
+                EXPECT_EQ(state_.cpu.v[8 + index], SIMD128Register{kAgnosticResult});
+              } else if (index == 3 && emul == 2) {
+                EXPECT_EQ(state_.cpu.v[8 + index], SIMD128Register{dst_result});
+              } else {
+                EXPECT_EQ(state_.cpu.v[8 + index],
+                          (SIMD128Register{expected_result[index]}).template Get<__uint128_t>());
+              }
+            }
+          } else {
+            EXPECT_EQ(state_.cpu.v[8],
+                      ((SIMD128Register{expected_result[0]} & kFractionMaskInt8[emul - 4]) |
+                       ((vta ? kAgnosticResult : dst_result) & ~kFractionMaskInt8[emul - 4]))
+                          .template Get<__uint128_t>());
           }
 
-          // Every vector instruction must set vstart to 0, but shouldn't touch vl.
-          EXPECT_EQ(state_.cpu.vstart, 0);
-          EXPECT_EQ(state_.cpu.vl, vlmax);
+          if (emul == 2) {
+            // Every vector instruction must set vstart to 0, but shouldn't touch vl.
+            EXPECT_EQ(state_.cpu.vstart, 0);
+            EXPECT_EQ(state_.cpu.vl, (vlmax * 5) / 8);
+          }
         }
       }
     };
 
-    for (int vlmul = 0; vlmul < 8; vlmul++) {
-      ((Verify(insn_bytes,
-               BitUtilLog2(sizeof(ExpectedResultType)),
-               vlmul,
-               std::get<1>(expected_result)[vlmul]),
-        Verify(insn_bytes | (1 << 25),
-               BitUtilLog2(sizeof(ExpectedResultType)),
-               vlmul,
-               std::get<0>(expected_result)[vlmul])),
-       ...);
-    }
+    // Some instructions don't support use of mask register, but in these instructions bit
+    // #25 is set.  This function doesn't support these. Verify that vm bit is not set.
+    EXPECT_EQ(insn_bytes & (1 << 25), 0U);
+
+    Verify(insn_bytes, 0, expected_result_int8);
+    Verify(insn_bytes, 1, expected_result_int16);
+    Verify(insn_bytes, 2, expected_result_int32);
+    Verify(insn_bytes, 3, expected_result_int64);
+  }
+
+  void TestVXmXXsInstruction(uint32_t insn_bytes,
+                            const uint64_t (&expected_result_no_mask)[129],
+                            const uint64_t (&expected_result_with_mask)[129],
+                            const __v2du source) {
+    auto Verify = [this, &source](uint32_t insn_bytes,
+                                  const uint64_t (&expected_result)[129]) {
+      state_.cpu.v[0] = SIMD128Register{kMask}.Get<__uint128_t>();
+
+      auto [vlmax, vtype] = intrinsics::Vsetvl(~0ULL, 3);
+      state_.cpu.vtype = vtype;
+      state_.cpu.vstart = 0;
+      state_.cpu.v[16] = SIMD128Register{source}.Get<__uint128_t>();
+
+      for (uint8_t vl = 0; vl <= vlmax; ++vl) {
+        state_.cpu.vl = vl;
+        SetXReg<1>(state_.cpu, 0xaaaa'aaaa'aaaa'aaaa);
+
+        state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
+        EXPECT_TRUE(RunOneInstruction(&state_, state_.cpu.insn_addr + 4));
+        EXPECT_EQ(GetXReg<1>(state_.cpu), expected_result[vl]) << std::to_string(vl);
+      }
+    };
+
+    Verify(insn_bytes, expected_result_with_mask);
+    Verify(insn_bytes | (1 << 25), expected_result_no_mask);
   }
 
   void TestVectorFloatPermutationInstruction(uint32_t insn_bytes,
-                                             const uint32_t (&expected_result_int32)[8][4],
-                                             const uint64_t (&expected_result_int64)[8][2],
+                                             const UInt32x4Tuple (&expected_result_int32)[8],
+                                             const UInt64x2Tuple (&expected_result_int64)[8],
                                              const __v2du (&source)[16],
                                              uint8_t vlmul,
                                              uint64_t skip = 0,
@@ -1678,10 +1648,10 @@ class Riscv64InterpreterTest : public ::testing::Test {
   }
 
   void TestVectorPermutationInstruction(uint32_t insn_bytes,
-                                        const uint8_t (&expected_result_int8)[8][16],
-                                        const uint16_t (&expected_result_int16)[8][8],
-                                        const uint32_t (&expected_result_int32)[8][4],
-                                        const uint64_t (&expected_result_int64)[8][2],
+                                        const UInt8x16Tuple (&expected_result_int8)[8],
+                                        const UInt16x8Tuple (&expected_result_int16)[8],
+                                        const UInt32x4Tuple (&expected_result_int32)[8],
+                                        const UInt64x2Tuple (&expected_result_int64)[8],
                                         const __v2du (&source)[16],
                                         uint8_t vlmul,
                                         uint64_t regx1 = 0x0,
@@ -1714,18 +1684,16 @@ class Riscv64InterpreterTest : public ::testing::Test {
   // expected_result (that is, at vl-1) will be expected to be the same as
   // |regx1| when VL < VMAX and said element is active.
   template <TestVectorInstructionKind kTestVectorInstructionKind,
-            typename... ElementType,
-            size_t... kResultsCount,
-            size_t... kElementCount>
-  void TestVectorPermutationInstruction(
-      uint32_t insn_bytes,
-      const __v2du (&source)[16],
-      uint8_t vlmul,
-      uint64_t skip,
-      bool ignore_vma_for_last,
-      bool last_elem_is_reg1,
-      uint64_t regx1,
-      const ElementType (&... expected_result)[kResultsCount][kElementCount]) {
+            typename... ExpectedResultType,
+            size_t... kResultsCount>
+  void TestVectorPermutationInstruction(uint32_t insn_bytes,
+                                        const __v2du (&source)[16],
+                                        uint8_t vlmul,
+                                        uint64_t skip,
+                                        bool ignore_vma_for_last,
+                                        bool last_elem_is_reg1,
+                                        uint64_t regx1,
+                                        const ExpectedResultType&... expected_result) {
     auto Verify = [this, &source, vlmul, regx1, skip, ignore_vma_for_last, last_elem_is_reg1](
                       uint32_t insn_bytes,
                       uint8_t vsew,
@@ -1913,10 +1881,15 @@ class Riscv64InterpreterTest : public ::testing::Test {
     };
 
     // Test with and without masking enabled.
-    (Verify(
-         insn_bytes, BitUtilLog2(sizeof(ElementType)), expected_result, MaskForElem<ElementType>()),
+    (Verify(insn_bytes,
+            BitUtilLog2(sizeof(std::remove_cvref_t<decltype(std::get<0>(expected_result[0]))>)),
+            expected_result,
+            MaskForElem<std::remove_cvref_t<decltype(std::get<0>(expected_result[0]))>>()),
      ...);
-    (Verify(insn_bytes | (1 << 25), BitUtilLog2(sizeof(ElementType)), expected_result, kNoMask),
+    (Verify(insn_bytes | (1 << 25),
+            BitUtilLog2(sizeof(std::remove_cvref_t<decltype(std::get<0>(expected_result[0]))>)),
+            expected_result,
+            kNoMask),
      ...);
   }
 
@@ -7494,6 +7467,44 @@ TEST_F(Riscv64InterpreterTest, TestVfnmsub) {
                              kVectorCalculationsSource);
 }
 
+TEST_F(Riscv64InterpreterTest, TestVbrev8) {
+  TestVectorInstruction(
+      0x49842457,  // vbrev8.v v8, v24, v0.t
+      {{160, 15, 160, 15, 160, 15, 160, 15, 2, 2, 2, 2, 255, 255, 255, 255},
+       {136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136, 136},
+       {143, 255, 143, 255, 143, 255, 143, 255, 143, 255, 143, 255, 143, 255, 143, 255},
+       {6, 70, 38, 102, 150, 86, 54, 118, 142, 78, 46, 110, 30, 94, 62, 126},
+       {1, 65, 33, 97, 145, 81, 49, 113, 137, 73, 41, 105, 25, 89, 57, 121},
+       {5, 69, 37, 101, 149, 85, 53, 117, 141, 77, 45, 109, 29, 93, 61, 125},
+       {3, 67, 35, 99, 147, 83, 51, 115, 139, 75, 43, 107, 27, 91, 59, 123},
+       {7, 71, 39, 103, 151, 87, 55, 119, 143, 79, 47, 111, 31, 95, 63, 127}},
+      {{0x0fa0, 0x0fa0, 0x0fa0, 0x0fa0, 0x0202, 0x0202, 0xffff, 0xffff},
+       {0x8888, 0x8888, 0x8888, 0x8888, 0x8888, 0x8888, 0x8888, 0x8888},
+       {0xff8f, 0xff8f, 0xff8f, 0xff8f, 0xff8f, 0xff8f, 0xff8f, 0xff8f},
+       {0x4606, 0x6626, 0x5696, 0x7636, 0x4e8e, 0x6e2e, 0x5e1e, 0x7e3e},
+       {0x4101, 0x6121, 0x5191, 0x7131, 0x4989, 0x6929, 0x5919, 0x7939},
+       {0x4505, 0x6525, 0x5595, 0x7535, 0x4d8d, 0x6d2d, 0x5d1d, 0x7d3d},
+       {0x4303, 0x6323, 0x5393, 0x7333, 0x4b8b, 0x6b2b, 0x5b1b, 0x7b3b},
+       {0x4707, 0x6727, 0x5797, 0x7737, 0x4f8f, 0x6f2f, 0x5f1f, 0x7f3f}},
+      {{0x0fa0'0fa0, 0x0fa0'0fa0, 0x0202'0202, 0xffff'ffff},
+       {0x8888'8888, 0x8888'8888, 0x8888'8888, 0x8888'8888},
+       {0xff8f'ff8f, 0xff8f'ff8f, 0xff8f'ff8f, 0xff8f'ff8f},
+       {0x6626'4606, 0x7636'5696, 0x6e2e'4e8e, 0x7e3e'5e1e},
+       {0x6121'4101, 0x7131'5191, 0x6929'4989, 0x7939'5919},
+       {0x6525'4505, 0x7535'5595, 0x6d2d'4d8d, 0x7d3d'5d1d},
+       {0x6323'4303, 0x7333'5393, 0x6b2b'4b8b, 0x7b3b'5b1b},
+       {0x6727'4707, 0x7737'5797, 0x6f2f'4f8f, 0x7f3f'5f1f}},
+      {{0x0fa0'0fa0'0fa0'0fa0, 0xffff'ffff'0202'0202},
+       {0x8888'8888'8888'8888, 0x8888'8888'8888'8888},
+       {0xff8f'ff8f'ff8f'ff8f, 0xff8f'ff8f'ff8f'ff8f},
+       {0x7636'5696'6626'4606, 0x7e3e'5e1e'6e2e'4e8e},
+       {0x7131'5191'6121'4101, 0x7939'5919'6929'4989},
+       {0x7535'5595'6525'4505, 0x7d3d'5d1d'6d2d'4d8d},
+       {0x7333'5393'6323'4303, 0x7b3b'5b1b'6b2b'4b8b},
+       {0x7737'5797'6727'4707, 0x7f3f'5f1f'6f2f'4f8f}},
+      kVectorComparisonSource);
+}
+
 TEST_F(Riscv64InterpreterTest, TestVfmin) {
   TestVectorFloatInstruction(0x1100d457,  // vfmin.vf v8, v16, f1, v0.t
                              {{0xf005'f005, 0xf005'f005, 0x4040'4040, 0x40b4'0000},
@@ -7683,572 +7694,6 @@ TEST_F(Riscv64InterpreterTest, TestVfsgnj) {
                              kVectorCalculationsSource);
 }
 
-TEST_F(Riscv64InterpreterTest, TestVredsum) {
-  TestVectorReductionInstruction(
-      0x1882457,  // vredsum.vs v8,v24,v16,v0.t
-      // expected_result_vd0_int8
-      {242, 228, 200, 144, /* unused */ 0, 146, 44, 121},
-      // expected_result_vd0_int16
-      {0x0172, 0x82e4, 0x88c8, 0xa090, /* unused */ 0, 0x1300, 0xa904, 0xe119},
-      // expected_result_vd0_int32
-      {0xcb44'b932,
-       0x9407'71e4,
-       0xa70e'64c8,
-       0xd312'5090,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x1907'1300,
-       0xb713'ad09},
-      // expected_result_vd0_int64
-      {0xb32f'a926'9f1b'9511,
-       0x1f99'0d88'fb74'e962,
-       0xb92c'970e'74e8'52c4,
-       0xef4e'ad14'6aca'2888,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x2513'1f0e'1907'1300},
-      // expected_result_vd0_with_mask_int8
-      {39, 248, 142, 27, /* unused */ 0, 0, 154, 210},
-      // expected_result_vd0_with_mask_int16
-      {0x5f45, 0xc22f, 0x99d0, 0x98bf, /* unused */ 0, 0x1300, 0x1300, 0x4b15},
-      // expected_result_vd0_with_mask_int32
-      {0x2d38'1f29,
-       0x99a1'838a,
-       0x1989'ef5c,
-       0x9cf4'4aa1,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x1907'1300,
-       0x1907'1300},
-      // expected_result_vd0_with_mask_int64
-      {0x2513'1f0e'1907'1300,
-       0x917c'8370'7560'6751,
-       0x4e56'3842'222a'0c13,
-       0xc833'9e0e'73df'49b5,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x2513'1f0e'1907'1300},
-      kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVfredosum) {
-  TestVectorReductionInstruction(0xd881457,  // vfredosum.vs v8, v24, v16, v0.t
-                                             // expected_result_vd0_int32
-                                 {0x9e0c'9a8e,
-                                  0xbe2c'bace,
-                                  0xfe6c'fb4e,
-                                  0x7e6b'fc4d,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9604'9200,
-                                  0x9e0c'9a8e},
-                                 // expected_result_vd0_int64
-                                 {0x9e0c'9a09'9604'9200,
-                                  0xbe2c'ba29'b624'b220,
-                                  0xfe6c'fa69'f664'f260,
-                                  0x7eec'5def'0cee'0dee,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9e0c'9a09'9604'9200},
-                                 // expected_result_vd0_with_mask_int32
-                                 {0x9604'929d,
-                                  0xbe2c'ba29,
-                                  0xfe6c'fb4e,
-                                  0x7e6b'fa84,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9604'9200,
-                                  0x9604'9200},
-                                 // expected_result_vd0_with_mask_int64
-                                 {0x9e0c'9a09'9604'9200,
-                                  0xbe2c'ba29'b624'b220,
-                                  0xee7c'ea78'e674'e271,
-                                  0x6efc'4e0d'ee0d'ee0f,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9e0c'9a09'9604'9200},
-                                 kVectorCalculationsSource);
-}
-
-// Currently Vfredusum is implemented as Vfredosum (as explicitly permitted by RVV 1.0).
-// If we would implement some speedups which would change results then we may need to alter tests.
-TEST_F(Riscv64InterpreterTest, TestVfredusum) {
-  TestVectorReductionInstruction(0x5881457,  // vfredusum.vs v8, v24, v16, v0.t
-                                             // expected_result_vd0_int32
-                                 {0x9e0c'9a8e,
-                                  0xbe2c'bace,
-                                  0xfe6c'fb4e,
-                                  0x7e6b'fc4d,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9604'9200,
-                                  0x9e0c'9a8e},
-                                 // expected_result_vd0_int64
-                                 {0x9e0c'9a09'9604'9200,
-                                  0xbe2c'ba29'b624'b220,
-                                  0xfe6c'fa69'f664'f260,
-                                  0x7eec'5def'0cee'0dee,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9e0c'9a09'9604'9200},
-                                 // expected_result_vd0_with_mask_int32
-                                 {0x9604'929d,
-                                  0xbe2c'ba29,
-                                  0xfe6c'fb4e,
-                                  0x7e6b'fa84,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9604'9200,
-                                  0x9604'9200},
-                                 // expected_result_vd0_with_mask_int64
-                                 {0x9e0c'9a09'9604'9200,
-                                  0xbe2c'ba29'b624'b220,
-                                  0xee7c'ea78'e674'e271,
-                                  0x6efc'4e0d'ee0d'ee0f,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9e0c'9a09'9604'9200},
-                                 kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVredand) {
-  TestVectorReductionInstruction(
-      0x5882457,  // vredand.vs v8,v24,v16,v0.t
-      // expected_result_vd0_int8
-      {0, 0, 0, 0, /* unused */ 0, 0, 0, 0},
-      // expected_result_vd0_int16
-      {0x8000, 0x8000, 0x8000, 0x0000, /* unused */ 0, 0x8000, 0x8000, 0x8000},
-      // expected_result_vd0_int32
-      {0x8200'8000,
-       0x8200'8000,
-       0x8200'8000,
-       0x0200'0000,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8200'8000,
-       0x8200'8000},
-      // expected_result_vd0_int64
-      {0x8604'8000'8200'8000,
-       0x8604'8000'8200'8000,
-       0x8604'8000'8200'8000,
-       0x0604'0000'0200'0000,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8604'8000'8200'8000},
-      // expected_result_vd0_with_mask_int8
-      {0, 0, 0, 0, /* unused */ 0, 0, 0, 0},
-      // expected_result_vd0_with_mask_int16
-      {0x8000, 0x8000, 0x8000, 0x0000, /* unused */ 0, 0x8000, 0x8000, 0x8000},
-      // expected_result_vd0_with_mask_int32
-      {0x8200'8000,
-       0x8200'8000,
-       0x8200'8000,
-       0x0200'0000,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8200'8000,
-       0x8200'8000},
-      // expected_result_vd0_with_mask_int64
-      {0x8604'8000'8200'8000,
-       0x8604'8000'8200'8000,
-       0x8604'8000'8200'8000,
-       0x0604'0000'0200'0000,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8604'8000'8200'8000},
-      kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVredor) {
-  TestVectorReductionInstruction(
-      0x9882457,  // vredor.vs v8,v24,v16,v0.t
-      // expected_result_vd0_int8
-      {159, 191, 255, 255, /* unused */ 0, 146, 150, 159},
-      // expected_result_vd0_int16
-      {0x9f1d, 0xbf3d, 0xff7d, 0xfffd, /* unused */ 0, 0x9300, 0x9704, 0x9f0d},
-      // expected_result_vd0_int32
-      {0x9f1e'9b19,
-       0xbf3e'bb39,
-       0xff7e'fb79,
-       0xfffe'fbf9,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9706'9300,
-       0x9f0e'9b09},
-      // expected_result_vd0_int64
-      {0x9f1e'9f1d'9716'9311,
-       0xbf3e'bf3d'b736'b331,
-       0xff7e'ff7d'f776'f371,
-       0xfffe'fffd'f7f6'f3f1,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9f0e'9f0d'9706'9300},
-      // expected_result_vd0_with_mask_int8
-      {159, 191, 255, 255, /* unused */ 0, 0, 150, 158},
-      // expected_result_vd0_with_mask_int16
-      {0x9f1d, 0xbf3d, 0xff7d, 0xfffd, /* unused */ 0, 0x9300, 0x9300, 0x9f0d},
-      // expected_result_vd0_with_mask_int32
-      {0x9f1e'9b19,
-       0xbf3e'bb39,
-       0xff7e'fb79,
-       0xfffe'fbf9,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9706'9300,
-       0x9706'9300},
-      // expected_result_vd0_with_mask_int64
-      {0x9f0e'9f0d'9706'9300,
-       0xbf3e'bf3d'b736'b331,
-       0xff7e'ff7d'f776'f371,
-       0xfffe'fffd'f7f6'f3f1,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9f0e'9f0d'9706'9300},
-      kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVredxor) {
-  TestVectorReductionInstruction(
-      0xd882457,  // vredxor.vs v8,v24,v16,v0.t
-      // expected_result_vd0_int8
-      {0, 0, 0, 0, /* unused */ 0, 146, 0, 1},
-      // expected_result_vd0_int16
-      {0x8100, 0x8100, 0x8100, 0x8100, /* unused */ 0, 0x1300, 0x8504, 0x8101},
-      // expected_result_vd0_int32
-      {0x8302'8100,
-       0x8302'8100,
-       0x8302'8100,
-       0x8302'8100,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x1506'1300,
-       0x8b0a'8909},
-      // expected_result_vd0_int64
-      {0x9716'9515'9312'9111,
-       0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x190a'1f0d'1506'1300},
-      // expected_result_vd0_with_mask_int8
-      {143, 154, 150, 43, /* unused */ 0, 0, 146, 150},
-      // expected_result_vd0_with_mask_int16
-      {0x1f0d, 0xbd3d, 0x9514, 0x8d0d, /* unused */ 0, 0x1300, 0x1300, 0x1705},
-      // expected_result_vd0_with_mask_int32
-      {0x1d0e'1b09,
-       0x0d1e'0b18,
-       0xfb7a'f978,
-       0xab2a'a929,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x1506'1300,
-       0x1506'1300},
-      // expected_result_vd0_with_mask_int64
-      {0x190a'1f0d'1506'1300,
-       0x091a'0f1c'0516'0311,
-       0x293a'2f3c'2536'2331,
-       0x77f6'75f5'73f2'71f1,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x190a'1f0d'1506'1300},
-      kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVredminu) {
-  TestVectorReductionInstruction(
-      0x11882457,  // vredminu.vs v8,v24,v16,v0.t
-      // expected_result_vd0_int8
-      {0, 0, 0, 0, /* unused */ 0, 0, 0, 0},
-      // expected_result_vd0_int16
-      {0x8100, 0x8100, 0x8100, 0x0291, /* unused */ 0, 0x8100, 0x8100, 0x8100},
-      // expected_result_vd0_int32
-      {0x83028100,
-       0x83028100,
-       0x83028100,
-       0x06940291,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x83028100,
-       0x83028100},
-      // expected_result_vd0_int64
-      {0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x0e9c'0a98'0694'0291,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8706'8504'8302'8100},
-      // expected_result_vd0_with_mask_int8
-      {0, 0, 0, 0, /* unused */ 0, 0, 0, 0},
-      // expected_result_vd0_with_mask_int16
-      {0x8100, 0x8100, 0x8100, 0x0291, /* unused */ 0, 0x8100, 0x8100, 0x8100},
-      // expected_result_vd0_with_mask_int32
-      {0x8302'8100,
-       0x8302'8100,
-       0x8302'8100,
-       0x0e9c'0a98,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8302'8100,
-       0x8302'8100},
-      // expected_result_vd0_with_mask_int64
-      {0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x1e8c'1a89'1684'1280,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8706'8504'8302'8100},
-      kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVredmin) {
-  TestVectorReductionInstruction(
-      0x15882457,  // vredmin.vs v8,v24,v16,v0.t
-      // expected_result_vd0_int8
-      {130, 130, 130, 128, /* unused */ 0, 146, 146, 146},
-      // expected_result_vd0_int16
-      {0x8100, 0x8100, 0x8100, 0x8100, /* unused */ 0, 0x8100, 0x8100, 0x8100},
-      // expected_result_vd0_int32
-      {0x8302'8100,
-       0x8302'8100,
-       0x8302'8100,
-       0x8302'8100,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8302'8100,
-       0x8302'8100},
-      // expected_result_vd0_int64
-      {0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8706'8504'8302'8100},
-      // expected_result_vd0_with_mask_int8
-      {138, 138, 138, 128, /* unused */ 0, 0, 150, 150},
-      // expected_result_vd0_with_mask_int16
-      {0x8100, 0x8100, 0x8100, 0x8100, /* unused */ 0, 0x8100, 0x8100, 0x8100},
-      // expected_result_vd0_with_mask_int32
-      {0x8302'8100,
-       0x8302'8100,
-       0x8302'8100,
-       0x8302'8100,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8302'8100,
-       0x8302'8100},
-      // expected_result_vd0_with_mask_int64
-      {0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       0x8706'8504'8302'8100,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x8706'8504'8302'8100},
-      kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVfredmin) {
-  TestVectorReductionInstruction(0x15881457,  // vfredmin.vs v8, v24, v16, v0.t
-                                              // expected_result_vd0_int32
-                                 {0x9e0c'9a09,
-                                  0xbe2c'ba29,
-                                  0xfe6c'fa69,
-                                  0xfe6c'fa69,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9604'9200,
-                                  0x9e0c'9a09},
-                                 // expected_result_vd0_int64
-                                 {0x9e0c'9a09'9604'9200,
-                                  0xbe2c'ba29'b624'b220,
-                                  0xfe6c'fa69'f664'f260,
-                                  0xfe6c'fa69'f664'f260,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9e0c'9a09'9604'9200},
-                                 // expected_result_vd0_with_mask_int32
-                                 {0x9604'9200,
-                                  0xbe2c'ba29,
-                                  0xfe6c'fa69,
-                                  0xfe6c'fa69,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9604'9200,
-                                  0x9604'9200},
-                                 // expected_result_vd0_with_mask_int64
-                                 {0x9e0c'9a09'9604'9200,
-                                  0xbe2c'ba29'b624'b220,
-                                  0xee7c'ea78'e674'e271,
-                                  0xee7c'ea78'e674'e271,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x9e0c'9a09'9604'9200},
-                                 kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVredmaxu) {
-  TestVectorReductionInstruction(
-      0x19882457,  // vredmaxu.vs v8,v24,v16,v0.t
-      // expected_result_vd0_int8
-      {158, 190, 254, 254, /* unused */ 0, 146, 150, 158},
-      // expected_result_vd0_int16
-      {0x9e0c, 0xbe2c, 0xfe6c, 0xfe6c, /* unused */ 0, 0x9200, 0x9604, 0x9e0c},
-      // expected_result_vd0_int32
-      {0x9e0c'9a09,
-       0xbe2c'ba29,
-       0xfe6c'fa69,
-       0xfe6c'fa69,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9604'9200,
-       0x9e0c'9a09},
-      // expected_result_vd0_int64
-      {0x9e0c'9a09'9604'9200,
-       0xbe2c'ba29'b624'b220,
-       0xfe6c'fa69'f664'f260,
-       0xfe6c'fa69'f664'f260,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9e0c'9a09'9604'9200},
-      // expected_result_vd0_with_mask_int8
-      {158, 186, 254, 254, /* unused */ 0, 0, 150, 158},
-      // expected_result_vd0_with_mask_int16
-      {0x9e0c, 0xba29, 0xfe6c, 0xfe6c, /* unused */ 0, 0x9200, 0x9200, 0x9e0c},
-      // expected_result_vd0_with_mask_int32
-      {0x9604'9200,
-       0xbe2c'ba29,
-       0xfe6c'fa69,
-       0xfe6c'fa69,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9604'9200,
-       0x9604'9200},
-      // expected_result_vd0_with_mask_int64
-      {0x9e0c'9a09'9604'9200,
-       0xbe2c'ba29'b624'b220,
-       0xee7c'ea78'e674'e271,
-       0xee7c'ea78'e674'e271,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9e0c'9a09'9604'9200},
-      kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVredmax) {
-  TestVectorReductionInstruction(
-      0x1d882457,  // vredmax.vs v8,v24,v16,v0.t
-      // expected_result_vd0_int8
-      {28, 60, 124, 126, /* unused */ 0, 0, 4, 12},
-      // expected_result_vd0_int16
-      {0x9e0c, 0xbe2c, 0xfe6c, 0x7eec, /* unused */ 0, 0x9200, 0x9604, 0x9e0c},
-      // expected_result_vd0_int32
-      {0x9e0c'9a09,
-       0xbe2c'ba29,
-       0xfe6c'fa69,
-       0x7eec'7ae9,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9604'9200,
-       0x9e0c'9a09},
-      // expected_result_vd0_int64
-      {0x9e0c'9a09'9604'9200,
-       0xbe2c'ba29'b624'b220,
-       0xfe6c'fa69'f664'f260,
-       0x7eec'7ae9'76e4'72e0,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9e0c'9a09'9604'9200},
-      // expected_result_vd0_with_mask_int8
-      {24, 52, 124, 126, /* unused */ 0, 0, 4, 4},
-      // expected_result_vd0_with_mask_int16
-      {0x9e0c, 0xba29, 0xfe6c, 0x7ae9, /* unused */ 0, 0x9200, 0x9200, 0x9e0c},
-      // expected_result_vd0_with_mask_int32
-      {0x9604'9200,
-       0xbe2c'ba29,
-       0xfe6c'fa69,
-       0x7eec'7ae9,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9604'9200,
-       0x9604'9200},
-      // expected_result_vd0_with_mask_int64
-      {0x9e0c'9a09'9604'9200,
-       0xbe2c'ba29'b624'b220,
-       0xee7c'ea78'e674'e271,
-       0x6efc'6af8'66f4'62f1,
-       /* unused */ 0,
-       /* unused */ 0,
-       /* unused */ 0,
-       0x9e0c'9a09'9604'9200},
-      kVectorCalculationsSource);
-}
-
-TEST_F(Riscv64InterpreterTest, TestVfredmax) {
-  TestVectorReductionInstruction(0x1d881457,  // vfredmax.vs v8, v24, v16, v0.t
-                                              // expected_result_vd0_int32
-                                 {0x8302'8100,
-                                  0x8302'8100,
-                                  0x8302'8100,
-                                  0x7eec'7ae9,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x8302'8100,
-                                  0x8302'8100},
-                                 // expected_result_vd0_int64
-                                 {0x8706'8504'8302'8100,
-                                  0x8706'8504'8302'8100,
-                                  0x8706'8504'8302'8100,
-                                  0x7eec'7ae9'76e4'72e0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x8706'8504'8302'8100},
-                                 // expected_result_vd0_with_mask_int32
-                                 {0x8302'8100,
-                                  0x8302'8100,
-                                  0x8302'8100,
-                                  0x7eec'7ae9,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x8302'8100,
-                                  0x8302'8100},
-                                 // expected_result_vd0_with_mask_int64
-                                 {0x8706'8504'8302'8100,
-                                  0x8706'8504'8302'8100,
-                                  0x8706'8504'8302'8100,
-                                  0x6efc'6af8'66f4'62f1,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  /* unused */ 0,
-                                  0x8706'8504'8302'8100},
-                                 kVectorCalculationsSource);
-}
-
 // Note that the expected test outputs for v[f]merge.vXm are identical to those for v[f]mv.v.X.
 // This happens because v[f]merge.vXm is just a v[f]mv.v.X with mask (second operand is not used
 // by v[f]mv.v.X but the difference between v[f]merge.vXm and v[f]mv.v.X is captured in masking
@@ -8545,43 +7990,46 @@ TEST_F(Riscv64InterpreterTest, TestVslide1down) {
                                    /*last_elem_is_x1=*/true);
 
   // VLMUL = 5
-  TestVectorPermutationInstruction(0x3d80e457,  // vslide1down.vx v8, v24, x1, v0.t
-                                   {{2, 0xaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{0xaaaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{}, {}, {}, {}, {}, {}, {}, {}},
-                                   kVectorCalculationsSourceLegacy,
-                                   /*vlmul=*/5,
-                                   /*regx1=*/0xaaaa'aaaa'aaaa'aaaa,
-                                   /*skip=*/0,
-                                   /*ignore_vma_for_last=*/true,
-                                   /*last_elem_is_x1=*/true);
+  TestVectorPermutationInstruction(
+      0x3d80e457,  // vslide1down.vx v8, v24, x1, v0.t
+      {{2, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{0xaaaa, 0, 0, 0, 0, 0, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{}, {}, {}, {}, {}, {}, {}, {}},
+      {{}, {}, {}, {}, {}, {}, {}, {}},
+      kVectorCalculationsSourceLegacy,
+      /*vlmul=*/5,
+      /*regx1=*/0xaaaa'aaaa'aaaa'aaaa,
+      /*skip=*/0,
+      /*ignore_vma_for_last=*/true,
+      /*last_elem_is_x1=*/true);
 
   // VLMUL = 6
-  TestVectorPermutationInstruction(0x3d80e457,  // vslide1down.vx v8, v24, x1, v0.t
-                                   {{2, 4, 6, 0xaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{0x0604, 0xaaaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{0xaaaa'aaaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{}, {}, {}, {}, {}, {}, {}, {}},
-                                   kVectorCalculationsSourceLegacy,
-                                   /*vlmul=*/6,
-                                   /*regx1=*/0xaaaa'aaaa'aaaa'aaaa,
-                                   /*skip=*/0,
-                                   /*ignore_vma_for_last=*/true,
-                                   /*last_elem_is_x1=*/true);
+  TestVectorPermutationInstruction(
+      0x3d80e457,  // vslide1down.vx v8, v24, x1, v0.t
+      {{2, 4, 6, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{0x0604, 0xaaaa, 0, 0, 0, 0, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{0xaaaa'aaaa, 0, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{}, {}, {}, {}, {}, {}, {}, {}},
+      kVectorCalculationsSourceLegacy,
+      /*vlmul=*/6,
+      /*regx1=*/0xaaaa'aaaa'aaaa'aaaa,
+      /*skip=*/0,
+      /*ignore_vma_for_last=*/true,
+      /*last_elem_is_x1=*/true);
 
   // VLMUL = 7
-  TestVectorPermutationInstruction(0x3d80e457,  // vslide1down.vx v8, v24, x1, v0.t
-                                   {{2, 4, 6, 9, 10, 12, 14, 0xaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{0x0604, 0x0a09, 0x0e0c, 0xaaaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{0x0e0c'0a09, 0xaaaa'aaaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   {{0xaaaa'aaaa'aaaa'aaaa}, {}, {}, {}, {}, {}, {}, {}},
-                                   kVectorCalculationsSourceLegacy,
-                                   /*vlmul=*/7,
-                                   /*regx1=*/0xaaaa'aaaa'aaaa'aaaa,
-                                   /*skip=*/0,
-                                   /*ignore_vma_for_last=*/true,
-                                   /*last_elem_is_x1=*/true);
+  TestVectorPermutationInstruction(
+      0x3d80e457,  // vslide1down.vx v8, v24, x1, v0.t
+      {{2, 4, 6, 9, 10, 12, 14, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{0x0604, 0x0a09, 0x0e0c, 0xaaaa, 0, 0, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{0x0e0c'0a09, 0xaaaa'aaaa, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{0xaaaa'aaaa'aaaa'aaaa, 0}, {}, {}, {}, {}, {}, {}, {}},
+      kVectorCalculationsSourceLegacy,
+      /*vlmul=*/7,
+      /*regx1=*/0xaaaa'aaaa'aaaa'aaaa,
+      /*skip=*/0,
+      /*ignore_vma_for_last=*/true,
+      /*last_elem_is_x1=*/true);
 }
 
 TEST_F(Riscv64InterpreterTest, TestVfslide1up) {
@@ -8714,7 +8162,7 @@ TEST_F(Riscv64InterpreterTest, TestVfslide1down) {
 
   // VLMUL = 6
   TestVectorFloatPermutationInstruction(0x3d80d457,  // vfslide1down.vf v8, v24, f1, v0.t
-                                        {{0x40b4'0000}, {}, {}, {}, {}, {}, {}, {}},
+                                        {{0x40b4'0000, 0, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
                                         {{}, {}, {}, {}, {}, {}, {}, {}},
                                         kVectorCalculationsSource,
                                         /*vlmul=*/6,
@@ -8723,14 +8171,15 @@ TEST_F(Riscv64InterpreterTest, TestVfslide1down) {
                                         /*last_elem_is_f1=*/true);
 
   // VLMUL = 7
-  TestVectorFloatPermutationInstruction(0x3d80d457,  // vfslide1down.vf v8, v24, f1, v0.t
-                                        {{0x9e0c'9a09, 0x40b4'0000}, {}, {}, {}, {}, {}, {}, {}},
-                                        {{0x4016'8000'0000'0000}, {}, {}, {}, {}, {}, {}, {}},
-                                        kVectorCalculationsSource,
-                                        /*vlmul=*/7,
-                                        /*skip=*/0,
-                                        /*ignore_vma_for_last=*/true,
-                                        /*last_elem_is_f1=*/true);
+  TestVectorFloatPermutationInstruction(
+      0x3d80d457,  // vfslide1down.vf v8, v24, f1, v0.t
+      {{0x9e0c'9a09, 0x40b4'0000, 0, 0}, {}, {}, {}, {}, {}, {}, {}},
+      {{0x4016'8000'0000'0000, 0}, {}, {}, {}, {}, {}, {}, {}},
+      kVectorCalculationsSource,
+      /*vlmul=*/7,
+      /*skip=*/0,
+      /*ignore_vma_for_last=*/true,
+      /*last_elem_is_f1=*/true);
 }
 
 TEST_F(Riscv64InterpreterTest, TestVseXX) {
@@ -9612,6 +9061,189 @@ TEST_F(Riscv64InterpreterTest, TestVrgather) {
       kVectorCalculationsSource);
 }
 
+TEST_F(Riscv64InterpreterTest, TestVadc) {
+  TestVectorCarryInstruction(
+      0x410c0457,  //  vadc.vvm v8,v16,v24,v0
+      {{1, 19, 7, 26, 13, 32, 18, 38, 26, 11, 31, 17, 37, 24, 42, 30},
+       {49, 68, 54, 74, 61, 80, 67, 85, 74, 59, 79, 66, 84, 72, 90, 78},
+       {97, 115, 103, 121, 110, 128, 114, 134, 121, 108, 127, 113, 133, 119, 139, 126},
+       {145, 163, 151, 170, 157, 176, 162, 182, 170, 155, 175, 161, 181, 167, 187, 174},
+       {193, 211, 199, 217, 206, 224, 210, 230, 218, 204, 222, 210, 229, 216, 235, 221},
+       {241, 3, 247, 10, 253, 16, 3, 22, 9, 252, 15, 2, 21, 7, 27, 14},
+       {33, 52, 38, 58, 46, 64, 50, 70, 58, 44, 63, 49, 69, 55, 75, 61},
+       {81, 100, 87, 105, 94, 112, 99, 118, 105, 92, 110, 98, 116, 104, 123, 109}},
+      {{0x1301, 0x1906, 0x1f0e, 0x2513, 0x0b19, 0x111f, 0x1724, 0x1d2b},
+       {0x4331, 0x4936, 0x4f3e, 0x5542, 0x3b4a, 0x414f, 0x4754, 0x4d5b},
+       {0x7361, 0x7967, 0x7f6d, 0x8573, 0x6b79, 0x717f, 0x7785, 0x7d8a},
+       {0xa391, 0xa996, 0xaf9e, 0xb5a3, 0x9ba9, 0xa1af, 0xa7b4, 0xadbb},
+       {0xd3c1, 0xd9c6, 0xdfce, 0xe5d2, 0xcbda, 0xd1df, 0xd7e4, 0xddeb},
+       {0x03f0, 0x09f7, 0x0ffe, 0x1602, 0xfc0a, 0x020e, 0x0815, 0x0e1b},
+       {0x3421, 0x3a26, 0x402e, 0x4633, 0x2c39, 0x323f, 0x3844, 0x3e4b},
+       {0x6451, 0x6a56, 0x705e, 0x7662, 0x5c6a, 0x626e, 0x6875, 0x6e7b}},
+      {{0x1907'1301, 0x2513'1f0d, 0x111f'0b1a, 0x1d2b'1725},
+       {0x4937'4330, 0x5543'4f3e, 0x414f'3b49, 0x4d5b'4755},
+       {0x7967'7361, 0x8573'7f6d, 0x717f'6b7a, 0x7d8b'7784},
+       {0xa997'a391, 0xb5a3'af9e, 0xa1af'9ba9, 0xadbb'a7b5},
+       {0xd9c6'd3c1, 0xe5d2'dfce, 0xd1de'cbd9, 0xddea'd7e5},
+       {0x09f7'03f0, 0x1603'0ffe, 0x020e'fc0a, 0x0e1b'0814},
+       {0x3a27'3421, 0x4633'402d, 0x323f'2c3a, 0x3e4b'3845},
+       {0x6a57'6450, 0x7663'705e, 0x626f'5c69, 0x6e7b'6875}},
+      {{0x2513'1f0e'1907'1301, 0x1d2b'1725'111f'0b19},
+       {0x5543'4f3e'4937'4331, 0x4d5b'4755'414f'3b4a},
+       {0x8573'7f6e'7967'7360, 0x7d8b'7785'717f'6b7a},
+       {0xb5a3'af9e'a997'a390, 0xadbb'a7b5'a1af'9baa},
+       {0xe5d2'dfcd'd9c6'd3c1, 0xddea'd7e4'd1de'cbd9},
+       {0x1603'0ffe'09f7'03f1, 0x0e1b'0815'020e'fc09},
+       {0x4633'402e'3a27'3421, 0x3e4b'3845'323f'2c3a},
+       {0x7663'705e'6a57'6450, 0x6e7b'6875'626f'5c6a}},
+      kVectorCalculationsSource);
+
+  TestVectorCarryInstruction(
+      0x4100c457,  // vadc.vxm	v8,v16,x1,v0
+      {{171, 43, 173, 46, 174, 48, 176, 50, 179, 51, 181, 53, 183, 56, 184, 58},
+       {187, 60, 188, 62, 190, 64, 193, 65, 195, 67, 197, 70, 198, 72, 200, 74},
+       {203, 75, 205, 77, 207, 80, 208, 82, 210, 84, 213, 85, 215, 87, 217, 90},
+       {219, 91, 221, 94, 222, 96, 224, 98, 227, 99, 229, 101, 231, 103, 233, 106},
+       {235, 107, 237, 109, 239, 112, 240, 114, 243, 116, 244, 118, 247, 120, 249, 121},
+       {251, 123, 253, 126, 254, 128, 1, 130, 2, 132, 5, 134, 7, 135, 9, 138},
+       {11, 140, 12, 142, 15, 144, 16, 146, 19, 148, 21, 149, 23, 151, 25, 153},
+       {27, 156, 29, 157, 31, 160, 33, 162, 34, 164, 36, 166, 38, 168, 41, 169}},
+      {{0x2bab, 0x2dac, 0x2faf, 0x31b1, 0x33b2, 0x35b5, 0x37b6, 0x39b9},
+       {0x3bbb, 0x3dbc, 0x3fbf, 0x41c0, 0x43c3, 0x45c5, 0x47c6, 0x49c9},
+       {0x4bcb, 0x4dcd, 0x4fce, 0x51d1, 0x53d2, 0x55d5, 0x57d7, 0x59d8},
+       {0x5bdb, 0x5ddc, 0x5fdf, 0x61e1, 0x63e2, 0x65e5, 0x67e6, 0x69e9},
+       {0x6beb, 0x6dec, 0x6fef, 0x71f0, 0x73f3, 0x75f5, 0x77f6, 0x79f9},
+       {0x7bfa, 0x7dfd, 0x7fff, 0x8200, 0x8403, 0x8604, 0x8807, 0x8a09},
+       {0x8c0b, 0x8e0c, 0x900f, 0x9211, 0x9412, 0x9615, 0x9816, 0x9a19},
+       {0x9c1b, 0x9e1c, 0xa01f, 0xa220, 0xa423, 0xa624, 0xa827, 0xaa29}},
+      {{0x2dad'2bab, 0x31b1'2fae, 0x35b5'33b3, 0x39b9'37b7},
+       {0x3dbd'3bba, 0x41c1'3fbf, 0x45c5'43c2, 0x49c9'47c7},
+       {0x4dcd'4bcb, 0x51d1'4fce, 0x55d5'53d3, 0x59d9'57d6},
+       {0x5ddd'5bdb, 0x61e1'5fdf, 0x65e5'63e2, 0x69e9'67e7},
+       {0x6ded'6beb, 0x71f1'6fef, 0x75f5'73f2, 0x79f9'77f7},
+       {0x7dfd'7bfa, 0x8201'7fff, 0x8605'8403, 0x8a09'8806},
+       {0x8e0d'8c0b, 0x9211'900e, 0x9615'9413, 0x9a19'9817},
+       {0x9e1d'9c1a, 0xa221'a01f, 0xa625'a422, 0xaa29'a827}},
+      {{0x31b1'2faf'2dad'2bab, 0x39b9'37b7'35b5'33b2},
+       {0x41c1'3fbf'3dbd'3bbb, 0x49c9'47c7'45c5'43c3},
+       {0x51d1'4fcf'4dcd'4bca, 0x59d9'57d7'55d5'53d3},
+       {0x61e1'5fdf'5ddd'5bda, 0x69e9'67e7'65e5'63e3},
+       {0x71f1'6fef'6ded'6beb, 0x79f9'77f7'75f5'73f2},
+       {0x8201'7fff'7dfd'7bfb, 0x8a09'8807'8605'8402},
+       {0x9211'900f'8e0d'8c0b, 0x9a19'9817'9615'9413},
+       {0xa221'a01f'9e1d'9c1a, 0xaa29'a827'a625'a423}},
+      kVectorCalculationsSource);
+
+  TestVectorCarryInstruction(
+      0x4105b457,  // vadc.vim v8,v16,0xb,v0
+      {{12, 140, 14, 143, 15, 145, 17, 147, 20, 148, 22, 150, 24, 153, 25, 155},
+       {28, 157, 29, 159, 31, 161, 34, 162, 36, 164, 38, 167, 39, 169, 41, 171},
+       {44, 172, 46, 174, 48, 177, 49, 179, 51, 181, 54, 182, 56, 184, 58, 187},
+       {60, 188, 62, 191, 63, 193, 65, 195, 68, 196, 70, 198, 72, 200, 74, 203},
+       {76, 204, 78, 206, 80, 209, 81, 211, 84, 213, 85, 215, 88, 217, 90, 218},
+       {92, 220, 94, 223, 95, 225, 98, 227, 99, 229, 102, 231, 104, 232, 106, 235},
+       {108, 237, 109, 239, 112, 241, 113, 243, 116, 245, 118, 246, 120, 248, 122, 250},
+       {124, 253, 126, 254, 128, 1, 130, 3, 131, 5, 133, 7, 135, 9, 138, 10}},
+      {{0x810c, 0x830d, 0x8510, 0x8712, 0x8913, 0x8b16, 0x8d17, 0x8f1a},
+       {0x911c, 0x931d, 0x9520, 0x9721, 0x9924, 0x9b26, 0x9d27, 0x9f2a},
+       {0xa12c, 0xa32e, 0xa52f, 0xa732, 0xa933, 0xab36, 0xad38, 0xaf39},
+       {0xb13c, 0xb33d, 0xb540, 0xb742, 0xb943, 0xbb46, 0xbd47, 0xbf4a},
+       {0xc14c, 0xc34d, 0xc550, 0xc751, 0xc954, 0xcb56, 0xcd57, 0xcf5a},
+       {0xd15b, 0xd35e, 0xd560, 0xd761, 0xd964, 0xdb65, 0xdd68, 0xdf6a},
+       {0xe16c, 0xe36d, 0xe570, 0xe772, 0xe973, 0xeb76, 0xed77, 0xef7a},
+       {0xf17c, 0xf37d, 0xf580, 0xf781, 0xf984, 0xfb85, 0xfd88, 0xff8a}},
+      {{0x8302'810c, 0x8706'850f, 0x8b0a'8914, 0x8f0e'8d18},
+       {0x9312'911b, 0x9716'9520, 0x9b1a'9923, 0x9f1e'9d28},
+       {0xa322'a12c, 0xa726'a52f, 0xab2a'a934, 0xaf2e'ad37},
+       {0xb332'b13c, 0xb736'b540, 0xbb3a'b943, 0xbf3e'bd48},
+       {0xc342'c14c, 0xc746'c550, 0xcb4a'c953, 0xcf4e'cd58},
+       {0xd352'd15b, 0xd756'd560, 0xdb5a'd964, 0xdf5e'dd67},
+       {0xe362'e16c, 0xe766'e56f, 0xeb6a'e974, 0xef6e'ed78},
+       {0xf372'f17b, 0xf776'f580, 0xfb7a'f983, 0xff7e'fd88}},
+      {{0x8706'8504'8302'810c, 0x8f0e'8d0c'8b0a'8913},
+       {0x9716'9514'9312'911c, 0x9f1e'9d1c'9b1a'9924},
+       {0xa726'a524'a322'a12b, 0xaf2e'ad2c'ab2a'a934},
+       {0xb736'b534'b332'b13b, 0xbf3e'bd3c'bb3a'b944},
+       {0xc746'c544'c342'c14c, 0xcf4e'cd4c'cb4a'c953},
+       {0xd756'd554'd352'd15c, 0xdf5e'dd5c'db5a'd963},
+       {0xe766'e564'e362'e16c, 0xef6e'ed6c'eb6a'e974},
+       {0xf776'f574'f372'f17b, 0xff7e'fd7c'fb7a'f984}},
+      kVectorCalculationsSource);
+}
+
+TEST_F(Riscv64InterpreterTest, TestVsbc) {
+  TestVectorCarryInstruction(
+      0x490c0457,  // vsb.vvm	v8,v16,v24,v0
+      {{255, 17, 1, 18, 5, 20, 6, 22, 8, 249, 9, 251, 11, 252, 14, 254},
+       {15, 32, 18, 34, 21, 36, 21, 39, 24, 9, 25, 10, 28, 12, 30, 14},
+       {31, 49, 33, 51, 36, 52, 38, 54, 41, 24, 41, 27, 43, 29, 45, 30},
+       {47, 65, 49, 66, 53, 68, 54, 70, 56, 41, 57, 43, 59, 45, 61, 46},
+       {63, 81, 65, 83, 68, 84, 70, 86, 72, 56, 74, 58, 75, 60, 77, 63},
+       {79, 97, 81, 98, 85, 100, 85, 102, 89, 72, 89, 74, 91, 77, 93, 78},
+       {95, 112, 98, 114, 100, 116, 102, 118, 104, 88, 105, 91, 107, 93, 109, 95},
+       {111, 128, 113, 131, 116, 132, 117, 134, 121, 104, 122, 106, 124, 108, 125, 111}},
+      {{0x10ff, 0x1302, 0x1504, 0x1705, 0xf909, 0xfb09, 0xfd0c, 0xff0d},
+       {0x210f, 0x2312, 0x2514, 0x2716, 0x0918, 0x0b19, 0x0d1c, 0x0f1d},
+       {0x311f, 0x3321, 0x3525, 0x3725, 0x1929, 0x1b29, 0x1d2b, 0x1f2e},
+       {0x412f, 0x4332, 0x4534, 0x4735, 0x2939, 0x2b39, 0x2d3c, 0x2f3d},
+       {0x513f, 0x5342, 0x5544, 0x5746, 0x3948, 0x3b49, 0x3d4c, 0x3f4d},
+       {0x6150, 0x6351, 0x6554, 0x6756, 0x4958, 0x4b5a, 0x4d5b, 0x4f5d},
+       {0x715f, 0x7362, 0x7564, 0x7765, 0x5969, 0x5b69, 0x5d6c, 0x5f6d},
+       {0x816f, 0x8372, 0x8574, 0x8776, 0x6978, 0x6b7a, 0x6d7b, 0x6f7d}},
+      {{0x1302'10ff, 0x1706'1505, 0xfb09'f908, 0xff0d'fd0b},
+       {0x2312'2110, 0x2716'2514, 0x0b1a'0919, 0x0f1e'0d1b},
+       {0x3322'311f, 0x3726'3525, 0x1b2a'1928, 0x1f2e'1d2c},
+       {0x4332'412f, 0x4736'4534, 0x2b3a'2939, 0x2f3e'2d3b},
+       {0x5341'513f, 0x5745'5544, 0x3b49'3949, 0x3f4d'3d4b},
+       {0x6351'6150, 0x6755'6554, 0x4b59'4958, 0x4f5d'4d5c},
+       {0x7361'715f, 0x7765'7565, 0x5b69'5968, 0x5f6d'5d6b},
+       {0x8371'8170, 0x8775'8574, 0x6b79'6979, 0x6f7d'6d7b}},
+      {{0x1706'1505'1302'10ff, 0xff0d'fd0b'fb09'f909},
+       {0x2716'2515'2312'210f, 0x0f1e'0d1c'0b1a'0918},
+       {0x3726'3525'3322'3120, 0x1f2e'1d2c'1b2a'1928},
+       {0x4736'4535'4332'4130, 0x2f3e'2d3c'2b3a'2938},
+       {0x5745'5544'5341'513f, 0x3f4d'3d4b'3b49'3949},
+       {0x6755'6554'6351'614f, 0x4f5d'4d5b'4b59'4959},
+       {0x7765'7564'7361'715f, 0x5f6d'5d6b'5b69'5968},
+       {0x8775'8574'8371'8170, 0x6f7d'6d7b'6b79'6978}},
+      kVectorCalculationsSource);
+
+  TestVectorCarryInstruction(
+      0x4900c457,  // vsbc.vxm	v8,v16,x1,v0
+      {{169, 41, 167, 38, 166, 36, 164, 34, 161, 33, 159, 31, 157, 28, 156, 26},
+       {153, 24, 152, 22, 150, 20, 147, 19, 145, 17, 143, 14, 142, 12, 140, 10},
+       {137, 9, 135, 7, 133, 4, 132, 2, 130, 0, 127, 255, 125, 253, 123, 250},
+       {121, 249, 119, 246, 118, 244, 116, 242, 113, 241, 111, 239, 109, 237, 107, 234},
+       {105, 233, 103, 231, 101, 228, 100, 226, 97, 224, 96, 222, 93, 220, 91, 219},
+       {89, 217, 87, 214, 86, 212, 83, 210, 82, 208, 79, 206, 77, 205, 75, 202},
+       {73, 200, 72, 198, 69, 196, 68, 194, 65, 192, 63, 191, 61, 189, 59, 187},
+       {57, 184, 55, 183, 53, 180, 51, 178, 50, 176, 48, 174, 46, 172, 43, 171}},
+      {{0x29a9, 0x27a8, 0x25a5, 0x23a3, 0x21a2, 0x1f9f, 0x1d9e, 0x1b9b},
+       {0x1999, 0x1798, 0x1595, 0x1394, 0x1191, 0x0f8f, 0x0d8e, 0x0b8b},
+       {0x0989, 0x0787, 0x0586, 0x0383, 0x0182, 0xff7f, 0xfd7d, 0xfb7c},
+       {0xf979, 0xf778, 0xf575, 0xf373, 0xf172, 0xef6f, 0xed6e, 0xeb6b},
+       {0xe969, 0xe768, 0xe565, 0xe364, 0xe161, 0xdf5f, 0xdd5e, 0xdb5b},
+       {0xd95a, 0xd757, 0xd555, 0xd354, 0xd151, 0xcf50, 0xcd4d, 0xcb4b},
+       {0xc949, 0xc748, 0xc545, 0xc343, 0xc142, 0xbf3f, 0xbd3e, 0xbb3b},
+       {0xb939, 0xb738, 0xb535, 0xb334, 0xb131, 0xaf30, 0xad2d, 0xab2b}},
+      {{0x27a8'29a9, 0x23a4'25a6, 0x1fa0'21a1, 0x1b9c'1d9d},
+       {0x1798'199a, 0x1394'1595, 0x0f90'1192, 0x0b8c'0d8d},
+       {0x0788'0989, 0x0384'0586, 0xff80'0181, 0xfb7b'fd7e},
+       {0xf777'f979, 0xf373'f575, 0xef6f'f172, 0xeb6b'ed6d},
+       {0xe767'e969, 0xe363'e565, 0xdf5f'e162, 0xdb5b'dd5d},
+       {0xd757'd95a, 0xd353'd555, 0xcf4f'd151, 0xcb4b'cd4e},
+       {0xc747'c949, 0xc343'c546, 0xbf3f'c141, 0xbb3b'bd3d},
+       {0xb737'b93a, 0xb333'b535, 0xaf2f'b132, 0xab2b'ad2d}},
+      {{0x23a4'25a6'27a8'29a9, 0x1b9c'1d9e'1fa0'21a2},
+       {0x1394'1596'1798'1999, 0x0b8c'0d8e'0f90'1191},
+       {0x0384'0586'0788'098a, 0xfb7b'fd7d'ff80'0181},
+       {0xf373'f575'f777'f97a, 0xeb6b'ed6d'ef6f'f171},
+       {0xe363'e565'e767'e969, 0xdb5b'dd5d'df5f'e162},
+       {0xd353'd555'd757'd959, 0xcb4b'cd4d'cf4f'd152},
+       {0xc343'c545'c747'c949, 0xbb3b'bd3d'bf3f'c141},
+       {0xb333'b535'b737'b93a, 0xab2b'ad2d'af2f'b131}},
+      kVectorCalculationsSource);
+}
 }  // namespace
 
 }  // namespace berberis
diff --git a/interpreter/riscv64/regs.h b/interpreter/riscv64/regs.h
index ddd05935..3168b3a5 100644
--- a/interpreter/riscv64/regs.h
+++ b/interpreter/riscv64/regs.h
@@ -21,7 +21,9 @@
 #include <cstring>
 
 #include "berberis/base/bit_util.h"
+#if !defined(__aarch64__)
 #include "berberis/intrinsics/intrinsics_float.h"
+#endif
 
 namespace berberis {
 
@@ -43,6 +45,7 @@ inline auto IntegerToGPRReg(IntegerType arg)
   }
 }
 
+#if !defined(__aarch64__)
 template <typename FloatType>
 inline FloatType FPRegToFloat(uint64_t arg);
 
@@ -71,6 +74,7 @@ template <>
 inline uint64_t FloatToFPReg<intrinsics::Float64>(intrinsics::Float64 arg) {
   return bit_cast<uint64_t>(arg);
 }
+#endif
 
 }  // namespace berberis
 
diff --git a/intrinsics/Android.bp b/intrinsics/Android.bp
index 862817f1..ad8fbfe2 100644
--- a/intrinsics/Android.bp
+++ b/intrinsics/Android.bp
@@ -43,6 +43,22 @@ python_test_host {
     },
 }
 
+filegroup {
+    name: "libberberis_intrinsics_gen_inputs_riscv64_to_all",
+    srcs: ["riscv64_to_all/intrinsic_def.json"],
+}
+
+genrule {
+    name: "libberberis_text_assembler_gen_headers_riscv64",
+    out: [
+        "gen_text_assembler_common_riscv-inl.h",
+        "gen_text_assembler_riscv64-inl.h",
+    ],
+    srcs: [":libberberis_assembler_gen_inputs_riscv64"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --text-assembler $(out) $(in)",
+}
+
 genrule {
     name: "libberberis_text_assembler_gen_headers_x86_32",
     out: [
@@ -50,8 +66,8 @@ genrule {
         "gen_text_assembler_x86_32-inl.h",
     ],
     srcs: [":libberberis_assembler_gen_inputs_x86_32"],
-    tools: ["gen_asm_x86"],
-    cmd: "$(location gen_asm_x86) --text-assembler $(out) $(in)",
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --text-assembler $(out) $(in)",
 }
 
 genrule {
@@ -61,13 +77,8 @@ genrule {
         "gen_text_assembler_x86_64-inl.h",
     ],
     srcs: [":libberberis_assembler_gen_inputs_x86_64"],
-    tools: ["gen_asm_x86"],
-    cmd: "$(location gen_asm_x86) --text-assembler $(out) $(in)",
-}
-
-filegroup {
-    name: "libberberis_intrinsics_gen_inputs_riscv64_to_x86_64",
-    srcs: ["riscv64_to_x86_64/intrinsic_def.json"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --text-assembler $(out) $(in)",
 }
 
 filegroup {
@@ -87,7 +98,7 @@ filegroup {
 
 filegroup {
     name: "gen_text_asm_intrinsics_srcs",
-    srcs: ["common_to_x86/gen_text_asm_intrinsics.cc"],
+    srcs: ["gen_text_asm_intrinsics.cc"],
 }
 
 genrule {
@@ -102,7 +113,7 @@ genrule {
     name: "libberberis_macro_assembler_gen_intrinsics_headers_riscv64_to_x86_64",
     out: ["text_asm_intrinsics_process_bindings-inl.h"],
     srcs: [
-        ":libberberis_intrinsics_gen_inputs_riscv64_to_x86_64",
+        ":libberberis_intrinsics_gen_inputs_riscv64_to_all",
         ":libberberis_machine_ir_intrinsic_binding_riscv64_to_x86_64",
         ":libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64",
         ":libberberis_assembler_gen_inputs_x86_64",
@@ -121,7 +132,7 @@ genrule {
         "berberis/intrinsics/mock_semantics_listener_intrinsics_hooks-inl.h",
     ],
     srcs: [
-        ":libberberis_intrinsics_gen_inputs_riscv64_to_x86_64",
+        ":libberberis_intrinsics_gen_inputs_riscv64_to_all",
         ":libberberis_machine_ir_intrinsic_binding_riscv64_to_x86_64",
         ":libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64",
         ":libberberis_assembler_gen_inputs_x86_64",
@@ -134,8 +145,21 @@ genrule {
     name: "libberberis_macro_assembler_gen_headers_riscv64_to_x86_64",
     out: ["berberis/intrinsics/macro_assembler_interface-inl.h"],
     srcs: [":libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64"],
-    tools: ["gen_asm_x86"],
-    cmd: "$(location gen_asm_x86) --binary-assembler $(out) $(in)",
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_intrinsics_gen_public_headers_riscv64_to_arm64",
+    out: [
+        "berberis/intrinsics/intrinsics-inl.h",
+        "berberis/intrinsics/interpreter_intrinsics_hooks-inl.h",
+    ],
+    srcs: [
+        ":libberberis_intrinsics_gen_inputs_riscv64_to_all",
+    ],
+    tools: ["gen_intrinsics"],
+    cmd: "$(location gen_intrinsics) arm64 --public_headers $(out) $(in)",
 }
 
 // Note: the following two genrules and this host binary are working together.
@@ -203,6 +227,7 @@ cc_defaults {
             cflags: ["-O0"],
             srcs: [":gen_text_asm_intrinsics_srcs"],
             header_libs: [
+                "libberberis_assembler_headers", // Immediates.
                 "libberberis_base_headers",
                 "libberberis_runtime_primitives_headers",
             ],
@@ -220,7 +245,7 @@ cc_defaults {
 
 cc_library_headers {
     name: "libberberis_intrinsics_riscv64_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     header_libs: [
         "libberberis_base_headers",
@@ -232,7 +257,14 @@ cc_library_headers {
         "libberberis_intrinsics_headers",
         "libberberis_runtime_primitives_headers", // for platform.h
     ],
+    export_include_dirs: [
+        "riscv64_to_all/include",
+    ],
     arch: {
+        arm64: {
+            generated_headers: ["libberberis_intrinsics_gen_public_headers_riscv64_to_arm64"],
+            export_generated_headers: ["libberberis_intrinsics_gen_public_headers_riscv64_to_arm64"],
+        },
         x86_64: {
             generated_headers: [
                 "libberberis_intrinsics_gen_inline_headers_riscv64_to_x86_64",
@@ -244,7 +276,6 @@ cc_library_headers {
             ],
             export_include_dirs: [
                 "riscv64_to_x86_64/include",
-                "riscv64/include",
             ],
         },
     },
@@ -252,20 +283,26 @@ cc_library_headers {
 
 cc_library_headers {
     name: "libberberis_intrinsics_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
+    native_bridge_supported: true,
     export_include_dirs: ["include"],
     header_libs: ["libberberis_base_headers"],
     export_header_lib_headers: ["libberberis_base_headers"],
     arch: {
         x86: {
             export_include_dirs: [
-                "common_to_x86/include",
+                "all_to_x86_32_or_x86_64/include",
             ],
         },
         x86_64: {
             export_include_dirs: [
-                "common_to_x86/include",
+                "all_to_x86_32_or_x86_64/include",
+            ],
+        },
+        riscv64: {
+            export_include_dirs: [
+                "all_to_riscv64/include",
             ],
         },
     },
@@ -280,19 +317,55 @@ cc_library_static {
     export_header_lib_headers: ["libberberis_intrinsics_riscv64_headers"],
 }
 
+cc_library_headers {
+    name: "libberberis_macro_assembler_headers_all_to_riscv64",
+    defaults: ["berberis_defaults_64"],
+    host_supported: true,
+    export_include_dirs: [
+        "all_to_riscv64/include",
+        "include",
+    ],
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_intrinsics_headers",
+    ],
+    export_header_lib_headers: [
+        "libberberis_base_headers",
+        "libberberis_intrinsics_headers",
+    ],
+}
+
+cc_library_headers {
+    name: "libberberis_macro_assembler_headers_all_to_x86_64",
+    defaults: ["berberis_defaults_64"],
+    host_supported: true,
+    export_include_dirs: [
+        "all_to_x86_32_or_x86_64/include",
+        "include",
+    ],
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_intrinsics_headers",
+    ],
+    export_header_lib_headers: [
+        "libberberis_base_headers",
+        "libberberis_intrinsics_headers",
+    ],
+}
+
 cc_library_headers {
     name: "libberberis_macro_assembler_headers_riscv64_to_x86_64",
     defaults: ["berberis_defaults_64"],
     host_supported: true,
     export_include_dirs: [
+        "riscv64_to_all/include",
         "riscv64_to_x86_64/include",
-        "riscv64/include",
-        "common_to_x86/include",
         "include",
     ],
     header_libs: [
         "libberberis_base_headers",
         "libberberis_intrinsics_headers",
+        "libberberis_macro_assembler_headers_all_to_x86_64",
     ],
     export_header_lib_headers: [
         "libberberis_base_headers",
@@ -315,8 +388,8 @@ cc_library_static {
     defaults: ["berberis_defaults_64"],
     host_supported: true,
     srcs: [
-        "riscv64/intrinsics.cc",
-        "riscv64/vector_intrinsics.cc",
+        "riscv64_to_all/intrinsics.cc",
+        "riscv64_to_all/vector_intrinsics.cc",
     ],
     header_libs: [
         "libberberis_base_headers",
@@ -332,22 +405,22 @@ cc_test_library {
     name: "libberberis_intrinsics_unit_tests",
     defaults: ["berberis_defaults"],
     host_supported: true,
+    srcs: ["simd_register_test.cc"],
     arch: {
         x86: {
             srcs: [
-                "common_to_x86/intrinsics_float_test.cc",
-                "common_to_x86/simd_register_test.cc",
+                "all_to_x86_32_or_x86_64/intrinsics_float_test.cc",
             ],
         },
         x86_64: {
             cflags: ["-mssse3"],
             srcs: [
-                "common_to_x86/intrinsics_float_test.cc",
-                "common_to_x86_64/tuple_test.cc",
+                "all_to_x86_32_or_x86_64/intrinsics_float_test.cc",
+                "all_to_x86_64/tuple_test.cc",
                 // Note that these two tests technically should work on any platform that supports
                 // risv64 to something translation, but currently that's only x86-64.
-                "riscv64/intrinsics_test.cc",
-                "riscv64/vector_intrinsics_test.cc",
+                "riscv64_to_all/intrinsics_test.cc",
+                "riscv64_to_all/vector_intrinsics_test.cc",
             ],
         },
     },
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h
new file mode 100644
index 00000000..d6e9fc74
--- /dev/null
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h
@@ -0,0 +1,100 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef BERBERIS_INTRINSICS_COMMON_TO_RISCV_INTRINSICS_BINDINGS_H_
+#define BERBERIS_INTRINSICS_COMMON_TO_RISCV_INTRINSICS_BINDINGS_H_
+
+#include <cstdint>
+
+#include "berberis/assembler/riscv.h"
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
+#include "berberis/intrinsics/intrinsics_args.h"
+#include "berberis/intrinsics/type_traits.h"
+
+namespace berberis::intrinsics::bindings {
+
+class BImm {
+ public:
+  using Type = riscv::BImmediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+class CsrImm {
+ public:
+  using Type = riscv::CsrImmediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+class GeneralReg {
+ public:
+  using Type = uint64_t;
+  static constexpr bool kIsImmediate = false;
+  static constexpr bool kIsImplicitReg = false;
+  static constexpr char kAsRegister = 'r';
+  template <typename MachineInsnArch>
+  static constexpr auto kRegClass = MachineInsnArch::kGeneralReg;
+};
+
+class IImm {
+ public:
+  using Type = riscv::IImmediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+class JImm {
+ public:
+  using Type = riscv::JImmediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+class PImm {
+ public:
+  using Type = riscv::PImmediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+class SImm {
+ public:
+  using Type = riscv::SImmediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+class Shift32Imm {
+ public:
+  using Type = riscv::Shift32Immediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+class Shift64Imm {
+ public:
+  using Type = riscv::Shift64Immediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+class UImm {
+ public:
+  using Type = riscv::UImmediate;
+  static constexpr bool kIsImmediate = true;
+};
+
+// Tag classes. They are never instantioned, only used as tags to pass information about
+// bindings.
+class NoCPUIDRestriction;
+
+}  // namespace berberis::intrinsics::bindings
+
+#endif  // BERBERIS_INTRINSICS_COMMON_TO_RISCV_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h
new file mode 100644
index 00000000..9b1b01db
--- /dev/null
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h
@@ -0,0 +1,308 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef BERBERIS_INTRINSICS_ALL_TO_RISCV64_INTRINSICS_FLOAT_H_
+#define BERBERIS_INTRINSICS_ALL_TO_RISCV64_INTRINSICS_FLOAT_H_
+
+#include <cinttypes>
+#include <cmath>
+
+#include "berberis/base/bit_util.h"
+#include "berberis/base/logging.h"
+#include "berberis/intrinsics/common/intrinsics_float.h"  // Float32/Float64
+#include "berberis/intrinsics/guest_rounding_modes.h"     // FE_HOSTROUND/FE_TIESAWAY
+
+namespace berberis::intrinsics {
+
+#define MAKE_BINARY_OPERATOR(guest_name, operator_name, assignment_name)                         \
+                                                                                                 \
+  inline Float32 operator operator_name(const Float32& v1, const Float32& v2) {                  \
+    Float32 result;                                                                              \
+    asm("f" #guest_name ".s %0, %1, %2" : "=f"(result.value_) : "f"(v1.value_), "f"(v2.value_)); \
+    return result;                                                                               \
+  }                                                                                              \
+                                                                                                 \
+  inline Float32& operator assignment_name(Float32 & v1, const Float32 & v2) {                   \
+    asm("f" #guest_name ".s %0, %1, %2" : "=f"(v1.value_) : "f"(v1.value_), "f"(v2.value_));     \
+    return v1;                                                                                   \
+  }                                                                                              \
+                                                                                                 \
+  inline Float64 operator operator_name(const Float64& v1, const Float64& v2) {                  \
+    Float64 result;                                                                              \
+    asm("f" #guest_name ".d %0, %1, %2" : "=f"(result.value_) : "f"(v1.value_), "f"(v2.value_)); \
+    return result;                                                                               \
+  }                                                                                              \
+                                                                                                 \
+  inline Float64& operator assignment_name(Float64 & v1, const Float64 & v2) {                   \
+    asm("f" #guest_name ".d %0, %1, %2" : "=f"(v1.value_) : "f"(v1.value_), "f"(v2.value_));     \
+    return v1;                                                                                   \
+  }
+
+MAKE_BINARY_OPERATOR(add, +, +=)
+MAKE_BINARY_OPERATOR(sub, -, -=)
+MAKE_BINARY_OPERATOR(mul, *, *=)
+MAKE_BINARY_OPERATOR(div, /, /=)
+
+#undef MAKE_BINARY_OPERATOR
+
+inline bool operator<(const Float32& v1, const Float32& v2) {
+  bool result;
+  asm("flt.s %0, %1, %2" : "=r"(result) : "f"(v1.value_), "f"(v2.value_));
+  return result;
+}
+
+inline bool operator<(const Float64& v1, const Float64& v2) {
+  bool result;
+  asm("flt.d %0, %1, %2" : "=r"(result) : "f"(v1.value_), "f"(v2.value_));
+  return result;
+}
+
+inline bool operator>(const Float32& v1, const Float32& v2) {
+  bool result;
+  asm("flt.s %0, %1, %2" : "=r"(result) : "f"(v2.value_), "f"(v1.value_));
+  return result;
+}
+
+inline bool operator>(const Float64& v1, const Float64& v2) {
+  bool result;
+  asm("flt.d %0, %1, %2" : "=r"(result) : "f"(v2.value_), "f"(v1.value_));
+  return result;
+}
+
+inline bool operator<=(const Float32& v1, const Float32& v2) {
+  bool result;
+  asm("fle.s %0, %1, %2" : "=r"(result) : "f"(v1.value_), "f"(v2.value_));
+  return result;
+}
+
+inline bool operator<=(const Float64& v1, const Float64& v2) {
+  bool result;
+  asm("fle.d %0, %1, %2" : "=r"(result) : "f"(v1.value_), "f"(v2.value_));
+  return result;
+}
+
+inline bool operator>=(const Float32& v1, const Float32& v2) {
+  bool result;
+  asm("fle.s %0, %1, %2" : "=r"(result) : "f"(v2.value_), "f"(v1.value_));
+  return result;
+}
+
+inline bool operator>=(const Float64& v1, const Float64& v2) {
+  bool result;
+  asm("fle.d %0, %1, %2" : "=r"(result) : "f"(v2.value_), "f"(v1.value_));
+  return result;
+}
+
+inline bool operator==(const Float32& v1, const Float32& v2) {
+  bool result;
+  asm("feq.s %0, %1, %2" : "=r"(result) : "f"(v1.value_), "f"(v2.value_));
+  return result;
+}
+
+inline bool operator==(const Float64& v1, const Float64& v2) {
+  bool result;
+  asm("feq.d %0, %1, %2" : "=r"(result) : "f"(v1.value_), "f"(v2.value_));
+  return result;
+}
+
+inline bool operator!=(const Float32& v1, const Float32& v2) {
+  bool result;
+  asm("feq.s %0, %1, %2" : "=r"(result) : "f"(v1.value_), "f"(v2.value_));
+  return !result;
+}
+
+inline bool operator!=(const Float64& v1, const Float64& v2) {
+  bool result;
+  asm("feq.d %0, %1, %2" : "=r"(result) : "f"(v1.value_), "f"(v2.value_));
+  return !result;
+}
+
+// It's NOT safe to use ANY functions which return float or double.  That's because IA32 ABI uses
+// x87 stack to pass arguments (and does that even with -mfpmath=sse) and NaN float and
+// double values would be corrupted if pushed on it.
+
+inline Float32 Negative(const Float32& v) {
+  Float32 result;
+  asm("fneg.s %0, %1" : "=f"(result.value_) : "f"(v.value_));
+  return result;
+}
+
+inline Float64 Negative(const Float64& v) {
+  Float64 result;
+  asm("fneg.d %0, %1" : "=f"(result.value_) : "f"(v.value_));
+  return result;
+}
+
+inline Float32 FPRound(const Float32& value, uint32_t round_control) {
+  // RISC-V doesn't have any instructions that can be used used to implement FPRound efficiently
+  // because conversion to integer returns an actual int (int32_t or int64_t) and that fails for
+  // values that are larger than 1/ϵ – but all such values couldn't have fraction parts which means
+  // that we may return them unmodified and only deal with small values that fit into int32_t below.
+  Float32 result = value;
+  // First of all we need to obtain positive value.
+  Float32 positive_value;
+  asm("fabs.s %0, %1" : "=f"(positive_value.value_) : "f"(result.value_));
+  // Compare that positive value to 1/ϵ and return values that are not smaller unmodified.
+  // Note: that includes ±∞ and NaNs!
+  int64_t compare_result;
+  asm("flt.s %0, %1, %2"
+      : "=r"(compare_result)
+      : "f"(positive_value.value_), "f"(float{1 / std::numeric_limits<float>::epsilon()}));
+  if (compare_result == 0) [[unlikely]] {
+    return result;
+  }
+  // Note: here we are dealing only with “small” values that can fit into int32_t.
+  switch (round_control) {
+    case FE_HOSTROUND:
+      asm("fcvt.w.s %1, %2, dyn\n"
+          "fcvt.s.w %0, %1, dyn"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_TONEAREST:
+      asm("fcvt.w.s %1, %2, rne\n"
+          "fcvt.s.w %0, %1, rne"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_DOWNWARD:
+      asm("fcvt.w.s %1, %2, rdn\n"
+          "fcvt.s.w %0, %1, rdn"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_UPWARD:
+      asm("fcvt.w.s %1, %2, rup\n"
+          "fcvt.s.w %0, %1, rup"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_TOWARDZERO:
+      asm("fcvt.w.s %1, %2, rtz\n"
+          "fcvt.s.w %0, %1, rtz"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_TIESAWAY:
+      // Convert positive value to integer with rounding down.
+      asm("fcvt.w.s %0, %1, rup" : "=r"(compare_result) : "f"(positive_value.value_));
+      // Subtract ½ from the rounded avlue and compare to the previously calculated positive value.
+      // Note: here we don't have to deal with infinities, NaNs, values that are too large, etc,
+      // since they are all handled above before we reach that line.
+      //  But coding that in C++ gives compiler opportunity to use Zfa, if it's enabled.
+      if (positive_value.value_ ==
+          static_cast<float>(static_cast<float>(static_cast<int32_t>(compare_result)) - 0.5f)) {
+        // If they are equal then we already have the final result (but without correct sign bit).
+        // Thankfully RISC-V includes operation that can be used to pick sign from original value.
+        asm("fsgnj.s %0, %1, %2"
+            : "=f"(result.value_)
+            : "f"(positive_value.value_), "f"(result.value_));
+      } else {
+        // Otherwise we may now use conversion to nearest.
+        asm("fcvt.w.s %1, %2, rne\n"
+            "fcvt.s.w %0, %1, rne"
+            : "=f"(result.value_), "=r"(compare_result)
+            : "f"(result.value_));
+      }
+      break;
+    default:
+      FATAL("Unknown round_control in FPRound!");
+  }
+  return result;
+}
+
+inline Float64 FPRound(const Float64& value, uint32_t round_control) {
+  // RISC-V doesn't have any instructions that can be used used to implement FPRound efficiently
+  // because conversion to integer returns an actual int (int32_t or int64_t) and that fails for
+  // values that are larger than 1/ϵ – but all such values couldn't have fraction parts which means
+  // that we may return them unmodified and only deal with small values that fit into int64_t below.
+  Float64 result = value;
+  // First of all we need to obtain positive value.
+  Float64 positive_value;
+  asm("fabs.d %0, %1" : "=f"(positive_value.value_) : "f"(result.value_));
+  // Compare that positive value to 1/ϵ and return values that are not smaller unmodified.
+  // Note: that includes ±∞ and NaNs!
+  int64_t compare_result;
+  asm("flt.d %0, %1, %2"
+      : "=r"(compare_result)
+      : "f"(positive_value.value_), "f"(1 / std::numeric_limits<double>::epsilon()));
+  if (compare_result == 0) [[unlikely]] {
+    return result;
+  }
+  // Note: here we are dealing only with “small” values that can fit into int32_t.
+  switch (round_control) {
+    case FE_HOSTROUND:
+      asm("fcvt.l.d %1, %2, dyn\n"
+          "fcvt.d.l %0, %1, dyn"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_TONEAREST:
+      asm("fcvt.l.d %1, %2, rne\n"
+          "fcvt.d.l %0, %1, rne"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_DOWNWARD:
+      asm("fcvt.l.d %1, %2, rdn\n"
+          "fcvt.d.l %0, %1, rdn"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_UPWARD:
+      asm("fcvt.l.d %1, %2, rup\n"
+          "fcvt.d.l %0, %1, rup"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_TOWARDZERO:
+      asm("fcvt.l.d %1, %2, rtz\n"
+          "fcvt.d.l %0, %1, rtz"
+          : "=f"(result.value_), "=r"(compare_result)
+          : "f"(result.value_));
+      break;
+    case FE_TIESAWAY:
+      // Convert positive value to integer with rounding down.
+      asm("fcvt.l.d %0, %1, rup" : "=r"(compare_result) : "f"(positive_value.value_));
+      // Subtract ½ from the rounded avlue and compare to the previously calculated positive value.
+      // Note: here we don't have to deal with infinities, NaNs, values that are too large, etc,
+      // since they are all handled above before we reach that line.
+      //  But coding that in C++ gives compiler opportunity to use Zfa, if it's enabled.
+      if (positive_value.value_ == static_cast<double>(compare_result) - 0.5) {
+        // If they are equal then we already have the final result (but without correct sign bit).
+        // Thankfully RISC-V includes operation that can be used to pick sign from original value.
+        asm("fsgnj.d %0, %1, %2"
+            : "=f"(result.value_)
+            : "f"(positive_value.value_), "f"(result.value_));
+      } else {
+        // Otherwise we may now use conversion to nearest.
+        asm("fcvt.l.d %1, %2, rne\n"
+            "fcvt.d.l %0, %1, rne"
+            : "=f"(result.value_), "=r"(compare_result)
+            : "f"(result.value_));
+      }
+      break;
+    default:
+      FATAL("Unknown round_control in FPRound!");
+  }
+  return result;
+}
+
+#undef ROUND_FLOAT
+
+}  // namespace berberis::intrinsics
+
+#endif  // BERBERIS_INTRINSICS_ALL_TO_RISCV64_INTRINSICS_FLOAT_H_
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h
new file mode 100644
index 00000000..49e8a1e9
--- /dev/null
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h
@@ -0,0 +1,371 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef BERBERIS_INTRINSICS_COMMON_TO_RISCV_TEXT_ASSEMBLER_COMMON_H_
+#define BERBERIS_INTRINSICS_COMMON_TO_RISCV_TEXT_ASSEMBLER_COMMON_H_
+
+#include <array>
+#include <cstdint>
+#include <cstdio>
+#include <deque>
+#include <string>
+
+#include "berberis/assembler/riscv.h"
+#include "berberis/base/checks.h"
+#include "berberis/base/config.h"
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h"
+
+namespace berberis {
+
+namespace constants_pool {
+
+extern const intptr_t kBerberisMacroAssemblerConstantsRelocated;
+
+inline intptr_t GetOffset(intptr_t address) {
+  return address - constants_pool::kBerberisMacroAssemblerConstantsRelocated;
+}
+
+}  // namespace constants_pool
+
+namespace riscv {
+
+#define BERBERIS_DEFINE_TO_FAS_ARGUMENT(Immediate)                         \
+  template <typename MacroAssembler>                                       \
+  inline std::string ToGasArgument(Immediate immediate, MacroAssembler*) { \
+    return "$" + std::to_string(static_cast<int32_t>(immediate));          \
+  }
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(BImmediate)
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(CsrImmediate)
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(IImmediate)
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(JImmediate)
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(PImmediate)
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(Shift32Immediate)
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(Shift64Immediate)
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(SImmediate)
+BERBERIS_DEFINE_TO_FAS_ARGUMENT(UImmediate)
+#undef BERBERIS_DEFINE_TO_FAS_ARGUMENT
+
+template <typename MacroAssembler>
+inline std::string ToGasArgument(Rounding rm, MacroAssembler*) {
+  switch (rm) {
+    case Rounding::kRne:
+      return "rne";
+    case Rounding::kRtz:
+      return "rtz";
+    case Rounding::kRdn:
+      return "rdn";
+    case Rounding::kRup:
+      return "ruo";
+    case Rounding::kRmm:
+      return "rmm";
+    case Rounding::kDyn:
+      return "dyn";
+    default:
+      LOG_ALWAYS_FATAL("Unsupported rounding mode %d", rm);
+  }
+}
+
+template <typename DerivedAssemblerType>
+class TextAssembler {
+ public:
+  using Condition = riscv::Condition;
+  using Csr = riscv::Csr;
+  using Rounding = riscv::Rounding;
+
+  struct Label {
+    size_t id;
+    bool bound = false;
+
+    template <typename MacroAssembler>
+    friend std::string ToGasArgument(const Label& label, MacroAssembler*) {
+      return std::to_string(label.id) + (label.bound ? "b" : "f");
+    }
+  };
+
+  template <typename RegisterType, typename ImmediateType>
+  struct Operand;
+
+  class Register {
+   public:
+    constexpr Register() : arg_no_(kNoRegister) {}
+    constexpr Register(int arg_no) : arg_no_(arg_no) {}
+    int arg_no() const {
+      CHECK_NE(arg_no_, kNoRegister);
+      return arg_no_;
+    }
+
+    friend bool operator==(const Register&, const Register&) = default;
+
+    static constexpr int kNoRegister = -1;
+    static constexpr int kStackPointer = -2;
+    // Used in Operand to deal with references to scratch area.
+    static constexpr int kScratchPointer = -3;
+    static constexpr int kZeroRegister = -4;
+
+    template <typename MacroAssembler>
+    friend const std::string ToGasArgument(const Register& reg, MacroAssembler*) {
+      if (reg.arg_no_ == kZeroRegister) {
+        return "zero";
+      }
+
+      return '%' + std::to_string(reg.arg_no());
+    }
+
+   private:
+    template <typename RegisterType, typename ImmediateType>
+    friend struct Operand;
+
+    // Register number created during creation of assembler call.
+    // See arg['arm_register'] in _gen_c_intrinsic_body in gen_intrinsics.py
+    //
+    // Default value (-1) means it's not assigned yet (thus couldn't be used).
+    int arg_no_;
+  };
+
+  class FpRegister {
+   public:
+    constexpr FpRegister() : arg_no_(kNoRegister) {}
+    constexpr FpRegister(int arg_no) : arg_no_(arg_no) {}
+    int arg_no() const {
+      CHECK_NE(arg_no_, kNoRegister);
+      return arg_no_;
+    }
+
+    friend bool operator==(const FpRegister&, const FpRegister&) = default;
+
+    template <typename MacroAssembler>
+    friend const std::string ToGasArgument(const FpRegister& reg, MacroAssembler*) {
+      return '%' + std::to_string(reg.arg_no());
+    }
+
+   private:
+    // Register number created during creation of assembler call.
+    // See arg['arm_register'] in _gen_c_intrinsic_body in gen_intrinsics.py
+    //
+    // Default value (-1) means it's not assigned yet (thus couldn't be used).
+    static constexpr int kNoRegister = -1;
+    int arg_no_;
+  };
+
+  template <typename RegisterType, typename ImmediateType>
+  struct Operand {
+    RegisterType base{0};
+    ImmediateType disp = 0;
+
+    template <typename MacroAssembler>
+    friend const std::string ToGasArgument(const Operand& op, MacroAssembler* as) {
+      std::string result{};
+      result = '(' + ToGasArgument(op.base, as) + ')';
+      int32_t disp = static_cast<int32_t>(op.disp);
+      if (disp) {
+        result = ToGasArgument(disp, as) + result;
+      }
+      return result;
+    }
+  };
+
+  using BImmediate = riscv::BImmediate;
+  using CsrImmediate = riscv::CsrImmediate;
+  using IImmediate = riscv::IImmediate;
+  using Immediate = riscv::Immediate;
+  using JImmediate = riscv::JImmediate;
+  using Shift32Immediate = riscv::Shift32Immediate;
+  using Shift64Immediate = riscv::Shift64Immediate;
+  using PImmediate = riscv::PImmediate;
+  using SImmediate = riscv::SImmediate;
+  using UImmediate = riscv::UImmediate;
+
+  TextAssembler(int indent, FILE* out) : indent_(indent), out_(out) {}
+
+  // Verify CPU vendor and SSE restrictions.
+  template <typename CPUIDRestriction>
+  void CheckCPUIDRestriction() {}
+
+  // Translate CPU restrictions into string.
+  template <typename CPUIDRestriction>
+  static constexpr const char* kCPUIDRestrictionString =
+      DerivedAssemblerType::template CPUIDRestrictionToString<CPUIDRestriction>();
+
+  Register gpr_a{};
+  Register gpr_c{};
+  Register gpr_d{};
+  // Note: stack pointer is not reflected in list of arguments, intrinsics use
+  // it implicitly.
+  Register gpr_s{Register::kStackPointer};
+  // Used in Operand as pseudo-register to temporary operand.
+  Register gpr_scratch{Register::kScratchPointer};
+  // Intrinsics which use these constants receive it via additional parameter - and
+  // we need to know if it's needed or not.
+  Register gpr_macroassembler_constants{};
+  bool need_gpr_macroassembler_constants() const { return need_gpr_macroassembler_constants_; }
+
+  Register gpr_macroassembler_scratch{};
+  bool need_gpr_macroassembler_scratch() const { return need_gpr_macroassembler_scratch_; }
+  Register gpr_macroassembler_scratch2{};
+
+  Register zero{Register::kZeroRegister};
+
+  void Bind(Label* label) {
+    CHECK_EQ(label->bound, false);
+    fprintf(out_, "%*s\"%zd:\\n\"\n", indent_ + 2, "", label->id);
+    label->bound = true;
+  }
+
+  Label* MakeLabel() {
+    labels_allocated_.push_back({labels_allocated_.size()});
+    return &labels_allocated_.back();
+  }
+
+  template <typename... Args>
+  void Byte(Args... args) {
+    static_assert((std::is_same_v<Args, uint8_t> && ...));
+    bool print_kwd = true;
+    fprintf(out_, "%*s\"", indent_ + 2, "");
+    (fprintf(out_, "%s%" PRIu8, print_kwd ? print_kwd = false, ".byte " : ", ", args), ...);
+    fprintf(out_, "\\n\"\n");
+  }
+
+  template <typename... Args>
+  void TwoByte(Args... args) {
+    static_assert((std::is_same_v<Args, uint16_t> && ...));
+    bool print_kwd = true;
+    fprintf(out_, "%*s\"", indent_ + 2, "");
+    (fprintf(out_, "%s%" PRIu16, print_kwd ? print_kwd = false, ".2byte " : ", ", args), ...);
+    fprintf(out_, "\\n\"\n");
+  }
+
+  template <typename... Args>
+  void FourByte(Args... args) {
+    static_assert((std::is_same_v<Args, uint32_t> && ...));
+    bool print_kwd = true;
+    fprintf(out_, "%*s\"", indent_ + 2, "");
+    (fprintf(out_, "%s%" PRIu32, print_kwd ? print_kwd = false, ".4byte " : ", ", args), ...);
+    fprintf(out_, "\\n\"\n");
+  }
+
+  template <typename... Args>
+  void EigthByte(Args... args) {
+    static_assert((std::is_same_v<Args, uint64_t> && ...));
+    bool print_kwd = true;
+    fprintf(out_, "%*s\"", indent_ + 2, "");
+    (fprintf(out_, "%s%" PRIu64, print_kwd ? print_kwd = false, ".8byte " : ", ", args), ...);
+    fprintf(out_, "\\n\"\n");
+  }
+
+  void P2Align(uint32_t m) {
+    fprintf(out_, "%*s\".p2align %u\\n\"\n", indent_ + 2, "", m);
+  }
+
+// Instructions.
+#include "gen_text_assembler_common_riscv-inl.h"  // NOLINT generated file
+
+ protected:
+  template <typename CPUIDRestriction>
+  static constexpr const char* CPUIDRestrictionToString() {
+    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::NoCPUIDRestriction>) {
+      return nullptr;
+    } else {
+      static_assert(kDependentTypeFalse<CPUIDRestriction>);
+    }
+  }
+
+  bool need_gpr_macroassembler_constants_ = false;
+  bool need_gpr_macroassembler_scratch_ = false;
+
+  template <typename... Args>
+  void Instruction(const char* name, Condition cond, const Args&... args);
+
+  template <typename... Args>
+  void Instruction(const char* name, const Args&... args);
+
+  void EmitString() {}
+
+  void EmitString(const std::string& s) { fprintf(out_, "%s", s.c_str()); }
+
+  template <typename... Args>
+  void EmitString(const std::string& s, const Args&... args) {
+    fprintf(out_, "%s, ", s.c_str());
+    EmitString(args...);
+  }
+
+ protected:
+  int indent_;
+  FILE* out_;
+
+ private:
+  std::deque<Label> labels_allocated_;
+
+  TextAssembler() = delete;
+  TextAssembler(const TextAssembler&) = delete;
+  TextAssembler(TextAssembler&&) = delete;
+  void operator=(const TextAssembler&) = delete;
+  void operator=(TextAssembler&&) = delete;
+};
+
+template <typename Arg, typename MacroAssembler>
+inline std::string ToGasArgument(const Arg& arg, MacroAssembler*) {
+  return "$" + std::to_string(arg);
+}
+
+template <typename DerivedAssemblerType>
+template <typename... Args>
+inline void TextAssembler<DerivedAssemblerType>::Instruction(const char* name,
+                                                             Condition cond,
+                                                             const Args&... args) {
+  char name_with_condition[8] = {};
+  CHECK_EQ(strcmp(name, "Bcc"), 0);
+
+  switch (cond) {
+    case Condition::kEqual:
+      strcat(name_with_condition, "eq");
+      break;
+    case Condition::kNotEqual:
+      strcat(name_with_condition, "ne");
+      break;
+    case Condition::kLess:
+      strcat(name_with_condition, "lt");
+      break;
+    case Condition::kGreaterEqual:
+      strcat(name_with_condition, "ge");
+      break;
+    case Condition::kBelow:
+      strcat(name_with_condition, "ltu");
+      break;
+    case Condition::kAboveEqual:
+      strcat(name_with_condition, "geu");
+      break;
+    default:
+      LOG_ALWAYS_FATAL("Unsupported condition %d", cond);
+  }
+  Instruction(name_with_condition, args...);
+}
+
+template <typename DerivedAssemblerType>
+template <typename... Args>
+inline void TextAssembler<DerivedAssemblerType>::Instruction(const char* name,
+                                                             const Args&... args) {
+  int name_length = strlen(name);
+  fprintf(out_, "%*s\"%.*s ", indent_ + 2, "", name_length, name);
+  EmitString(ToGasArgument(args, this)...);
+  fprintf(out_, "\\n\"\n");
+}
+
+}  // namespace riscv
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_COMMON_TO_RISCV_TEXT_ASSEMBLER_COMMON_H_
diff --git a/kernel_api/riscv64/tracing.cc b/intrinsics/all_to_riscv64/include/berberis/intrinsics/macro_assembler-inl.h
similarity index 63%
rename from kernel_api/riscv64/tracing.cc
rename to intrinsics/all_to_riscv64/include/berberis/intrinsics/macro_assembler-inl.h
index 068f3e00..a1a77fa4 100644
--- a/kernel_api/riscv64/tracing.cc
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/macro_assembler-inl.h
@@ -14,21 +14,8 @@
  * limitations under the License.
  */
 
-#include "berberis/kernel_api/tracing.h"
-
-#include <cstdarg>
-
-#include "berberis/base/tracing.h"
-
-namespace berberis {
-
-void __attribute__((__format__(printf, 1, 2))) KernelApiTrace(const char* format, ...) {
-  if (Tracing::IsOn()) {
-    va_list ap;
-    va_start(ap, format);
-    Tracing::TraceV(format, ap);
-    va_end(ap);
-  }
-}
-
-}  // namespace berberis
+#ifndef DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
+#error This file is supposed to be included from berberis/intrinsics/macro_assembler-inl.h
+#else
+#undef DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
+#endif
diff --git a/intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/intrinsics_bindings.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
similarity index 51%
rename from intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/intrinsics_bindings.h
rename to intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
index 4caa2282..36124ace 100644
--- a/intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/intrinsics_bindings.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
@@ -14,14 +14,15 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_INTRINSICS_COMMON_TO_X86_INTRINSICS_BINDINGS_H_
-#define BERBERIS_INTRINSICS_COMMON_TO_X86_INTRINSICS_BINDINGS_H_
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_INTRINSICS_BINDINGS_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_INTRINSICS_BINDINGS_H_
 
 #include <xmmintrin.h>
 
 #include <cstdint>
 
 #include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
 #include "berberis/intrinsics/intrinsics_args.h"
 #include "berberis/intrinsics/type_traits.h"
 
@@ -207,15 +208,6 @@ class GeneralReg64 {
   static constexpr auto kRegClass = MachineInsnArch::kGeneralReg64;
 };
 
-class FLAGS {
- public:
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 0;
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kFLAGS;
-};
-
 class FpReg32 {
  public:
   using Type = __m128;
@@ -256,202 +248,73 @@ class XmmReg {
   static constexpr auto kRegClass = MachineInsnArch::kXmmReg;
 };
 
-class Mem8 {
- public:
-  using Type = uint8_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
-class Mem16 {
- public:
-  using Type = uint16_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
-class Mem32 {
- public:
-  using Type = uint32_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
-class Mem64 {
- public:
-  using Type = uint64_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
 class MemX87 {
  public:
   static constexpr bool kIsImmediate = false;
   static constexpr char kAsRegister = 'm';
 };
 
-// // Tag classes. They are never instantioned, only used as tags to pass information about
+// Tag classes. They are never instantioned, only used as tags to pass information about
 // bindings.
-class Def;
-class DefEarlyClobber;
-class Use;
-class UseDef;
-
-template <typename Tag, typename MachineRegKind>
-constexpr auto ToRegKind() {
-  if constexpr (std::is_same_v<Tag, Def>) {
-    return MachineRegKind::kDef;
-  } else if constexpr (std::is_same_v<Tag, DefEarlyClobber>) {
-    return MachineRegKind::kDefEarlyClobber;
-  } else if constexpr (std::is_same_v<Tag, Use>) {
-    return MachineRegKind::kUse;
-  } else if constexpr (std::is_same_v<Tag, UseDef>) {
-    return MachineRegKind::kUseDef;
-  } else {
-    static_assert(kDependentTypeFalse<Tag>);
-  }
-}
-
-template <typename Tag, typename MachineRegKind>
-inline constexpr auto kRegKind = ToRegKind<Tag, MachineRegKind>();
-
-enum CPUIDRestriction : int {
-  kNoCPUIDRestriction = 0,
-  kHas3DNOW,
-  kHas3DNOWP,
-  kHasADX,
-  kHasAES,
-  kHasAESAVX,
-  kHasAMXBF16,
-  kHasAMXFP16,
-  kHasAMXINT8,
-  kHasAMXTILE,
-  kHasAVX,
-  kHasAVX2,
-  kHasAVX5124FMAPS,
-  kHasAVX5124VNNIW,
-  kHasAVX512BF16,
-  kHasAVX512BITALG,
-  kHasAVX512BW,
-  kHasAVX512CD,
-  kHasAVX512DQ,
-  kHasAVX512ER,
-  kHasAVX512F,
-  kHasAVX512FP16,
-  kHasAVX512IFMA,
-  kHasAVX512PF,
-  kHasAVX512VBMI,
-  kHasAVX512VBMI2,
-  kHasAVX512VL,
-  kHasAVX512VNNI,
-  kHasAVX512VPOPCNTDQ,
-  kHasBMI,
-  kHasBMI2,
-  kHasCLMUL,
-  kHasCMOV,
-  kHasCMPXCHG16B,
-  kHasCMPXCHG8B,
-  kHasF16C,
-  kHasFMA,
-  kHasFMA4,
-  kHasFXSAVE,
-  kHasLZCNT,
-  // BMI2 is set and PDEP/PEXT are ok to use. See more here:
-  //   https://twitter.com/instlatx64/status/1322503571288559617
-  kHashPDEP,
-  kHasPOPCNT,
-  kHasRDSEED,
-  kHasSERIALIZE,
-  kHasSHA,
-  kHasSSE,
-  kHasSSE2,
-  kHasSSE3,
-  kHasSSE4_1,
-  kHasSSE4_2,
-  kHasSSE4a,
-  kHasSSSE3,
-  kHasTBM,
-  kHasVAES,
-  kHasX87,
-  kIsAuthenticAMD
-};
-
-enum PreciseNanOperationsHandling : int {
-  kNoNansOperation = 0,
-  kPreciseNanOperationsHandling,
-  kImpreciseNanOperationsHandling
-};
-
-template <auto kIntrinsicTemplateName,
-          auto kMacroInstructionTemplateName,
-          auto kMnemo,
-          typename GetOpcode,
-          CPUIDRestriction kCPUIDRestrictionTemplateValue,
-          PreciseNanOperationsHandling kPreciseNanOperationsHandlingTemplateValue,
-          bool kSideEffectsTemplateValue,
-          typename... Types>
-class AsmCallInfo;
-
-template <auto kIntrinsicTemplateName,
-          auto kMacroInstructionTemplateName,
-          auto kMnemo,
-          typename GetOpcode,
-          CPUIDRestriction kCPUIDRestrictionTemplateValue,
-          PreciseNanOperationsHandling kPreciseNanOperationsHandlingTemplateValue,
-          bool kSideEffectsTemplateValue,
-          typename... InputArgumentsTypes,
-          typename... OutputArgumentsTypes,
-          typename... BindingsTypes>
-class AsmCallInfo<kIntrinsicTemplateName,
-                  kMacroInstructionTemplateName,
-                  kMnemo,
-                  GetOpcode,
-                  kCPUIDRestrictionTemplateValue,
-                  kPreciseNanOperationsHandlingTemplateValue,
-                  kSideEffectsTemplateValue,
-                  std::tuple<InputArgumentsTypes...>,
-                  std::tuple<OutputArgumentsTypes...>,
-                  BindingsTypes...>
-    final {
- public:
-  static constexpr auto kIntrinsic = kIntrinsicTemplateName;
-  static constexpr auto kMacroInstruction = kMacroInstructionTemplateName;
-  // TODO(b/260725458): Use lambda template argument after C++20 becomes available.
-  template <typename Opcode>
-  static constexpr auto kOpcode = GetOpcode{}.template operator()<Opcode>();
-  static constexpr CPUIDRestriction kCPUIDRestriction = kCPUIDRestrictionTemplateValue;
-  static constexpr PreciseNanOperationsHandling kPreciseNanOperationsHandling =
-      kPreciseNanOperationsHandlingTemplateValue;
-  static constexpr bool kSideEffects = kSideEffectsTemplateValue;
-  static constexpr const char* InputArgumentsTypeNames[] = {
-      TypeTraits<InputArgumentsTypes>::kName...};
-  static constexpr const char* OutputArgumentsTypeNames[] = {
-      TypeTraits<OutputArgumentsTypes>::kName...};
-  template <typename Callback, typename... Args>
-  constexpr static void ProcessBindings(Callback&& callback, Args&&... args) {
-    (callback(ArgTraits<BindingsTypes>(), std::forward<Args>(args)...), ...);
-  }
-  template <typename Callback, typename... Args>
-  constexpr static auto MakeTuplefromBindings(Callback&& callback, Args&&... args) {
-    return std::tuple_cat(callback(ArgTraits<BindingsTypes>(), std::forward<Args>(args)...)...);
-  }
-  using InputArguments = std::tuple<InputArgumentsTypes...>;
-  using OutputArguments = std::tuple<OutputArgumentsTypes...>;
-  using Bindings = std::tuple<BindingsTypes...>;
-  using IntrinsicType = std::conditional_t<std::tuple_size_v<OutputArguments> == 0,
-                                           void (*)(InputArgumentsTypes...),
-                                           OutputArguments (*)(InputArgumentsTypes...)>;
-  template <template <typename, auto, auto, typename...> typename MachineInsnType,
-            template <typename...>
-            typename ConstructorArgs,
-            typename Opcode>
-  using MachineInsn = MachineInsnType<AsmCallInfo,
-                                      kMnemo,
-                                      kOpcode<Opcode>,
-                                      ConstructorArgs<BindingsTypes...>,
-                                      BindingsTypes...>;
-};
+class NoCPUIDRestriction;
+class Has3DNOW;
+class Has3DNOWP;
+class HasADX;
+class HasAES;
+class HasAESAVX;
+class HasAMXBF16;
+class HasAMXFP16;
+class HasAMXINT8;
+class HasAMXTILE;
+class HasAVX;
+class HasAVX2;
+class HasAVX5124FMAPS;
+class HasAVX5124VNNIW;
+class HasAVX512BF16;
+class HasAVX512BITALG;
+class HasAVX512BW;
+class HasAVX512CD;
+class HasAVX512DQ;
+class HasAVX512ER;
+class HasAVX512F;
+class HasAVX512FP16;
+class HasAVX512IFMA;
+class HasAVX512PF;
+class HasAVX512VBMI;
+class HasAVX512VBMI2;
+class HasAVX512VL;
+class HasAVX512VNNI;
+class HasAVX512VPOPCNTDQ;
+class HasBMI;
+class HasBMI2;
+class HasCLMUL;
+class HasCMOV;
+class HasCMPXCHG16B;
+class HasCMPXCHG8B;
+class HasF16C;
+class HasFMA;
+class HasFMA4;
+class HasFXSAVE;
+class HasLZCNT;
+// BMI2 is set and PDEP/PEXT are ok to use. See more here:
+//   https://twitter.com/instlatx64/status/1322503571288559617
+class HashPDEP;
+class HasPOPCNT;
+class HasRDSEED;
+class HasSERIALIZE;
+class HasSHA;
+class HasSSE;
+class HasSSE2;
+class HasSSE3;
+class HasSSE4_1;
+class HasSSE4_2;
+class HasSSE4a;
+class HasSSSE3;
+class HasTBM;
+class HasVAES;
+class HasX87;
+class IsAuthenticAMD;
 
 }  // namespace berberis::intrinsics::bindings
 
-#endif  // BERBERIS_INTRINSICS_COMMON_TO_X86_INTRINSICS_BINDINGS_H_
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/intrinsics_float.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h
similarity index 65%
rename from intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/intrinsics_float.h
rename to intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h
index 5fc3c4cc..f402cd9a 100644
--- a/intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/intrinsics_float.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-#ifndef COMMON_TO_X86_BERBERIS_INTRINSICS_INTRINSICS_FLOAT_H_
-#define COMMON_TO_X86_BERBERIS_INTRINSICS_INTRINSICS_FLOAT_H_
+#ifndef ALL_TO_X86_32_OR_x86_64_BERBERIS_INTRINSICS_INTRINSICS_FLOAT_H_
+#define ALL_TO_X86_32_OR_x86_64_BERBERIS_INTRINSICS_INTRINSICS_FLOAT_H_
 
 #include <cmath>
 
@@ -34,7 +34,7 @@ namespace berberis::intrinsics {
     return result;                                                                      \
   }                                                                                     \
                                                                                         \
-  inline Float32& operator assignment_name(Float32& v1, const Float32& v2) {            \
+  inline Float32& operator assignment_name(Float32 & v1, const Float32 & v2) {          \
     asm(#guest_name "ss %2,%0" : "=x"(v1.value_) : "0"(v1.value_), "x"(v2.value_));     \
     return v1;                                                                          \
   }                                                                                     \
@@ -45,7 +45,7 @@ namespace berberis::intrinsics {
     return result;                                                                      \
   }                                                                                     \
                                                                                         \
-  inline Float64& operator assignment_name(Float64& v1, const Float64& v2) {            \
+  inline Float64& operator assignment_name(Float64 & v1, const Float64 & v2) {          \
     asm(#guest_name "sd %2,%0" : "=x"(v1.value_) : "0"(v1.value_), "x"(v2.value_));     \
     return v1;                                                                          \
   }
@@ -132,27 +132,6 @@ inline bool operator!=(const Float64& v1, const Float64& v2) {
 // It's NOT safe to use ANY functions which return float or double.  That's because IA32 ABI uses
 // x87 stack to pass arguments (and does that even with -mfpmath=sse) and NaN float and
 // double values would be corrupted if pushed on it.
-//
-// It's safe to use builtins here if that file is compiled with -mfpmath=sse (clang does not have
-// such flag but uses SSE whenever possible, GCC needs both -msse2 and -mfpmath=sse) since builtins
-// DON'T use an official calling conventions but are instead embedded in the function - even if all
-// optimizations are disabled.
-
-inline Float32 CopySignBit(const Float32& v1, const Float32& v2) {
-  return Float32(__builtin_copysignf(v1.value_, v2.value_));
-}
-
-inline Float64 CopySignBit(const Float64& v1, const Float64& v2) {
-  return Float64(__builtin_copysign(v1.value_, v2.value_));
-}
-
-inline Float32 Absolute(const Float32& v) {
-  return Float32(__builtin_fabsf(v.value_));
-}
-
-inline Float64 Absolute(const Float64& v) {
-  return Float64(__builtin_fabs(v.value_));
-}
 
 inline Float32 Negative(const Float32& v) {
   // TODO(b/120563432): Simple -v.value_ doesn't work after a clang update.
@@ -170,22 +149,26 @@ inline Float64 Negative(const Float64& v) {
   return result;
 }
 
-inline FPInfo FPClassify(const Float32& v) {
-  return static_cast<FPInfo>(__builtin_fpclassify(static_cast<int>(FPInfo::kNaN),
-                                                  static_cast<int>(FPInfo::kInfinite),
-                                                  static_cast<int>(FPInfo::kNormal),
-                                                  static_cast<int>(FPInfo::kSubnormal),
-                                                  static_cast<int>(FPInfo::kZero),
-                                                  v.value_));
-}
-
-inline FPInfo FPClassify(const Float64& v) {
-  return static_cast<FPInfo>(__builtin_fpclassify(static_cast<int>(FPInfo::kNaN),
-                                                  static_cast<int>(FPInfo::kInfinite),
-                                                  static_cast<int>(FPInfo::kNormal),
-                                                  static_cast<int>(FPInfo::kSubnormal),
-                                                  static_cast<int>(FPInfo::kZero),
-                                                  v.value_));
+template <typename FloatType>
+inline WrappedFloatType<FloatType> FPRoundTiesAway(WrappedFloatType<FloatType> value) {
+  // Since x86 does not support this rounding mode exactly, we must manually handle the
+  // tie-aways (from ±x.5).
+  WrappedFloatType<FloatType> value_rounded_up = FPRound(value, FE_UPWARD);
+  // Check if value has fraction of exactly 0.5.
+  // Note that this check can produce spurious true and/or false results for numbers that are too
+  // large to have fraction parts. We don't care because for such numbers all three possible FPRound
+  // calls above and below produce the exact same result (which is the same as original value).
+  if (value == value_rounded_up - WrappedFloatType<FloatType>{0.5f}) {
+    if (SignBit(value)) {
+      // If value is negative then FE_TIESAWAY acts as FE_DOWNWARD.
+      return FPRound(value, FE_DOWNWARD);
+    } else {
+      // If value is negative then FE_TIESAWAY acts as FE_UPWARD.
+      return value_rounded_up;
+    }
+  }
+  // Otherwise FE_TIESAWAY acts as FE_TONEAREST.
+  return FPRound(value, FE_TONEAREST);
 }
 
 inline Float32 FPRound(const Float32& value, uint32_t round_control) {
@@ -207,12 +190,7 @@ inline Float32 FPRound(const Float32& value, uint32_t round_control) {
       asm("roundss $3,%1,%0" : "=x"(result.value_) : "x"(value.value_));
       break;
     case FE_TIESAWAY:
-      // TODO(b/146437763): Might fail if value doesn't have a floating part.
-      if (value == FPRound(value, FE_DOWNWARD) + Float32(0.5)) {
-        result = value > Float32(0.0) ? FPRound(value, FE_UPWARD) : FPRound(value, FE_DOWNWARD);
-      } else {
-        result = FPRound(value, FE_TONEAREST);
-      }
+      result = FPRoundTiesAway(value);
       break;
     default:
       LOG_ALWAYS_FATAL("Internal error: unknown round_control in FPRound!");
@@ -240,19 +218,7 @@ inline Float64 FPRound(const Float64& value, uint32_t round_control) {
       asm("roundsd $3,%1,%0" : "=x"(result.value_) : "x"(value.value_));
       break;
     case FE_TIESAWAY:
-      // Since x86 does not support this rounding mode exactly, we must manually handle the
-      // tie-aways (from (-)x.5)
-      if (value == FPRound(value, FE_DOWNWARD)) {
-        // Value is already an integer and can be returned as-is. Checking this first avoids dealing
-        // with numbers too large to be able to have a fractional part.
-        return value;
-      } else if (value == FPRound(value, FE_DOWNWARD) + Float64(0.5)) {
-        // Fraction part is exactly 1/2, in which case we need to tie-away
-        result = value > Float64(0.0) ? FPRound(value, FE_UPWARD) : FPRound(value, FE_DOWNWARD);
-      } else {
-        // Any other case can be handled by to-nearest rounding.
-        result = FPRound(value, FE_TONEAREST);
-      }
+      result = FPRoundTiesAway(value);
       break;
     default:
       LOG_ALWAYS_FATAL("Internal error: unknown round_control in FPRound!");
@@ -261,39 +227,6 @@ inline Float64 FPRound(const Float64& value, uint32_t round_control) {
   return result;
 }
 
-inline int IsNan(const Float32& v) {
-  return __builtin_isnan(v.value_);
-}
-
-inline int IsNan(const Float64& v) {
-  return __builtin_isnan(v.value_);
-}
-
-inline int SignBit(const Float32& v) {
-  return __builtin_signbitf(v.value_);
-}
-
-inline int SignBit(const Float64& v) {
-  return __builtin_signbit(v.value_);
-}
-
-inline Float32 Sqrt(const Float32& v) {
-  return Float32(__builtin_sqrtf(v.value_));
-}
-
-inline Float64 Sqrt(const Float64& v) {
-  return Float64(__builtin_sqrt(v.value_));
-}
-
-// x*y + z
-inline Float32 MulAdd(const Float32& v1, const Float32& v2, const Float32& v3) {
-  return Float32(fmaf(v1.value_, v2.value_, v3.value_));
-}
-
-inline Float64 MulAdd(const Float64& v1, const Float64& v2, const Float64& v3) {
-  return Float64(fma(v1.value_, v2.value_, v3.value_));
-}
-
 }  // namespace berberis::intrinsics
 
-#endif  // COMMON_TO_X86_BERBERIS_INTRINSICS_INTRINSICS_FLOAT_H_
+#endif  // ALL_TO_X86_32_OR_x86_64_BERBERIS_INTRINSICS_INTRINSICS_FLOAT_H_
diff --git a/intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/text_assembler_common.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
similarity index 68%
rename from intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/text_assembler_common.h
rename to intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
index 0bf1e4d2..9f317aeb 100644
--- a/intrinsics/common_to_x86/include/berberis/intrinsics/common_to_x86/text_assembler_common.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_INTRINSICS_COMMON_TO_X86_TEXT_ASSEMBLER_COMMON_H_
-#define BERBERIS_INTRINSICS_COMMON_TO_X86_TEXT_ASSEMBLER_COMMON_H_
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_TEXT_ASSEMBLER_COMMON_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_TEXT_ASSEMBLER_COMMON_H_
 
 #include <array>
 #include <cstdint>
@@ -25,18 +25,33 @@
 
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
-#include "berberis/base/macros.h"  // DISALLOW_IMPLICIT_CONSTRUCTORS
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
 
 namespace berberis {
 
 namespace constants_pool {
 
-int32_t GetOffset(int32_t address);
+// Note: kBerberisMacroAssemblerConstantsRelocated is the same as original,
+// unrelocated version in 32-bit world.  But in 64-bit world it's copy on the first 2GiB.
+//
+// Our builder could be built as 64-bit binary thus we must not mix them.
+//
+// Note: we have CHECK_*_LAYOUT tests in macro_assembler_common_x86.cc to make sure
+// offsets produced by 64-bit builder are usable in 32-bit libberberis.so
 
+extern const int32_t kBerberisMacroAssemblerConstantsRelocated;
+
+inline int32_t GetOffset(int32_t address) {
+  return address - constants_pool::kBerberisMacroAssemblerConstantsRelocated;
 }
 
-template <typename Assembler>
-class TextAssemblerX86 {
+}  // namespace constants_pool
+
+namespace x86_32_and_x86_64 {
+
+template <typename DerivedAssemblerType>
+class TextAssembler {
  public:
   // Condition class - 16 x86 conditions.
   enum class Condition {
@@ -49,7 +64,7 @@ class TextAssemblerX86 {
     kBelowEqual = 6,
     kAbove = 7,
     kNegative = 8,
-    kPositive = 9,
+    kPositiveOrZero = 9,
     kParityEven = 10,
     kParityOdd = 11,
     kLess = 12,
@@ -63,7 +78,7 @@ class TextAssemblerX86 {
     kZero = kEqual,
     kNotZero = kNotEqual,
     kSign = kNegative,
-    kNotSign = kPositive
+    kNotSign = kPositiveOrZero
   };
 
   enum ScaleFactor {
@@ -89,7 +104,6 @@ class TextAssemblerX86 {
 
   class Register {
    public:
-    constexpr Register() : arg_no_(kNoRegister) {}
     constexpr Register(int arg_no) : arg_no_(arg_no) {}
     int arg_no() const {
       CHECK_NE(arg_no_, kNoRegister);
@@ -116,7 +130,6 @@ class TextAssemblerX86 {
 
   class X87Register {
    public:
-    constexpr X87Register() : arg_no_(kNoRegister) {}
     constexpr X87Register(int arg_no) : arg_no_(arg_no) {}
     int arg_no() const {
       CHECK_NE(arg_no_, kNoRegister);
@@ -142,7 +155,6 @@ class TextAssemblerX86 {
 
   class XMMRegister {
    public:
-    constexpr XMMRegister() : arg_no_(kNoRegister) {}
     constexpr XMMRegister(int arg_no) : arg_no_(arg_no) {}
     int arg_no() const {
       CHECK_NE(arg_no_, kNoRegister);
@@ -167,8 +179,8 @@ class TextAssemblerX86 {
   };
 
   struct Operand {
-    Register base = Register{};
-    Register index = Register{};
+    Register base = Register{Register::kNoRegister};
+    Register index = Register{Register::kNoRegister};
     ScaleFactor scale = kTimesOne;
     int32_t disp = 0;
 
@@ -177,9 +189,11 @@ class TextAssemblerX86 {
       std::string result{};
       if (op.base.arg_no_ == Register::kNoRegister and op.index.arg_no_ == Register::kNoRegister) {
         as->need_gpr_macroassembler_constants_ = true;
-        result = std::to_string(constants_pool::GetOffset(op.disp)) + " + " +
-                 ToGasArgument(
-                     typename Assembler::RegisterDefaultBit(as->gpr_macroassembler_constants), as);
+        result =
+            std::to_string(constants_pool::GetOffset(op.disp)) + " + " +
+            ToGasArgument(
+                typename DerivedAssemblerType::RegisterDefaultBit(as->gpr_macroassembler_constants),
+                as);
       } else if (op.base.arg_no_ == Register::kScratchPointer) {
         CHECK(op.index.arg_no_ == Register::kNoRegister);
         // Only support two pointers to scratch area for now.
@@ -192,10 +206,11 @@ class TextAssemblerX86 {
         }
       } else {
         if (op.base.arg_no_ != Register::kNoRegister) {
-          result = ToGasArgument(typename Assembler::RegisterDefaultBit(op.base), as);
+          result = ToGasArgument(typename DerivedAssemblerType::RegisterDefaultBit(op.base), as);
         }
         if (op.index.arg_no_ != Register::kNoRegister) {
-          result += ',' + ToGasArgument(typename Assembler::RegisterDefaultBit(op.index), as) +
+          result += ',' +
+                    ToGasArgument(typename DerivedAssemblerType::RegisterDefaultBit(op.index), as) +
                     ',' + std::to_string(1 << op.scale);
         }
         result = '(' + result + ')';
@@ -207,11 +222,14 @@ class TextAssemblerX86 {
     }
   };
 
-  TextAssemblerX86(int indent, FILE* out) : indent_(indent), out_(out) {}
+  TextAssembler(int indent, FILE* out) : indent_(indent), out_(out) {}
 
-  Register gpr_a{};
-  Register gpr_c{};
-  Register gpr_d{};
+  // These start as Register::kNoRegister but can be changed if they are used as arguments to
+  // something else.
+  // If they are not coming as arguments then using them is compile-time error!
+  Register gpr_a{Register::kNoRegister};
+  Register gpr_c{Register::kNoRegister};
+  Register gpr_d{Register::kNoRegister};
   // Note: stack pointer is not reflected in list of arguments, intrinsics use
   // it implicitly.
   Register gpr_s{Register::kStackPointer};
@@ -222,12 +240,12 @@ class TextAssemblerX86 {
   // In x86-32 mode, on the other hand, we need complex dance to access it via GOT.
   // Intrinsics which use these constants receive it via additional parameter - and
   // we need to know if it's needed or not.
-  Register gpr_macroassembler_constants{};
+  Register gpr_macroassembler_constants{Register::kNoRegister};
   bool need_gpr_macroassembler_constants() const { return need_gpr_macroassembler_constants_; }
 
-  Register gpr_macroassembler_scratch{};
+  Register gpr_macroassembler_scratch{Register::kNoRegister};
   bool need_gpr_macroassembler_scratch() const { return need_gpr_macroassembler_scratch_; }
-  Register gpr_macroassembler_scratch2{};
+  Register gpr_macroassembler_scratch2{Register::kNoRegister};
 
   bool need_avx = false;
   bool need_bmi = false;
@@ -292,10 +310,80 @@ class TextAssemblerX86 {
     fprintf(out_, "%*s\".p2align %u\\n\"\n", indent_ + 2, "", m);
   }
 
+  // Verify CPU vendor and SSE restrictions.
+  template <typename CPUIDRestriction>
+  void CheckCPUIDRestriction() {
+    constexpr bool expect_bmi = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>;
+    constexpr bool expect_fma = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA>;
+    constexpr bool expect_fma4 = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA4>;
+    constexpr bool expect_lzcnt = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>;
+    constexpr bool expect_popcnt =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>;
+    constexpr bool expect_avx =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX> || expect_fma || expect_fma4;
+    constexpr bool expect_sse4_2 =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_2> || expect_avx;
+    constexpr bool expect_sse4_1 =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_1> || expect_sse4_2;
+    constexpr bool expect_ssse3 =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3> || expect_sse4_1;
+    constexpr bool expect_sse3 =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE3> || expect_ssse3;
+
+    CHECK_EQ(expect_avx, need_avx);
+    CHECK_EQ(expect_bmi, need_bmi);
+    CHECK_EQ(expect_fma, need_fma);
+    CHECK_EQ(expect_fma4, need_fma4);
+    CHECK_EQ(expect_lzcnt, need_lzcnt);
+    CHECK_EQ(expect_popcnt, need_popcnt);
+    CHECK_EQ(expect_sse3, need_sse3);
+    CHECK_EQ(expect_ssse3, need_ssse3);
+    CHECK_EQ(expect_sse4_1, need_sse4_1);
+    CHECK_EQ(expect_sse4_2, need_sse4_2);
+  }
+
+  // Translate CPU restrictions into string.
+  template <typename CPUIDRestriction>
+  static constexpr const char* kCPUIDRestrictionString =
+      DerivedAssemblerType::template CPUIDRestrictionToString<CPUIDRestriction>();
+
 // Instructions.
 #include "gen_text_assembler_common_x86-inl.h"  // NOLINT generated file
 
  protected:
+  template <typename CPUIDRestriction>
+  static constexpr const char* CPUIDRestrictionToString() {
+    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::NoCPUIDRestriction>) {
+      return nullptr;
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::IsAuthenticAMD>) {
+      return "host_platform::kIsAuthenticAMD";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
+      return "host_platform::kHasAVX";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
+      return "host_platform::kHasBMI";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA>) {
+      return "host_platform::kHasFMA";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA4>) {
+      return "host_platform::kHasFMA4";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>) {
+      return "host_platform::kHasLZCNT";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>) {
+      return "host_platform::kHasPOPCNT";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE3>) {
+      return "host_platform::kHasSSE3";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3>) {
+      return "host_platform::kHasSSSE3";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_1>) {
+      return "host_platform::kHasSSE4_1";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_2>) {
+      return "host_platform::kHasSSE4_2";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3>) {
+      return "host_platform::kHasSSSE3";
+    } else {
+      static_assert(kDependentTypeFalse<CPUIDRestriction>);
+    }
+  }
+
   bool need_gpr_macroassembler_constants_ = false;
   bool need_gpr_macroassembler_scratch_ = false;
 
@@ -405,7 +493,11 @@ class TextAssemblerX86 {
  private:
   std::deque<Label> labels_allocated_;
 
-  DISALLOW_IMPLICIT_CONSTRUCTORS(TextAssemblerX86);
+  TextAssembler() = delete;
+  TextAssembler(const TextAssembler&) = delete;
+  TextAssembler(TextAssembler&&) = delete;
+  void operator=(const TextAssembler&) = delete;
+  void operator=(TextAssembler&&) = delete;
 };
 
 template <typename Arg, typename MacroAssembler>
@@ -413,9 +505,11 @@ inline std::string ToGasArgument(const Arg& arg, MacroAssembler*) {
   return "$" + std::to_string(arg);
 }
 
-template <typename Assembler>
+template <typename DerivedAssemblerType>
 template <typename... Args>
-inline void TextAssemblerX86<Assembler>::Instruction(const char* name, Condition cond, const Args&... args) {
+inline void TextAssembler<DerivedAssemblerType>::Instruction(const char* name,
+                                                             Condition cond,
+                                                             const Args&... args) {
   char name_with_condition[8] = {};
   if (strcmp(name, "Cmovl") == 0 || strcmp(name, "Cmovq") == 0) {
     strcpy(name_with_condition, "Cmov");
@@ -453,7 +547,7 @@ inline void TextAssemblerX86<Assembler>::Instruction(const char* name, Condition
     case Condition::kNegative:
       strcat(name_with_condition, "s");
       break;
-    case Condition::kPositive:
+    case Condition::kPositiveOrZero:
       strcat(name_with_condition, "ns");
       break;
     case Condition::kParityEven:
@@ -478,9 +572,10 @@ inline void TextAssemblerX86<Assembler>::Instruction(const char* name, Condition
   Instruction(name_with_condition, args...);
 }
 
-template <typename Assembler>
+template <typename DerivedAssemblerType>
 template <typename... Args>
-inline void TextAssemblerX86<Assembler>::Instruction(const char* name, const Args&... args) {
+inline void TextAssembler<DerivedAssemblerType>::Instruction(const char* name,
+                                                             const Args&... args) {
   for (auto it : std::array<std::tuple<const char*, const char*>, 18>{
            {// Note: SSE doesn't include simple register-to-register move instruction.
             // You are supposed to use one of half-dozen variants depending on what you
@@ -526,6 +621,8 @@ inline void TextAssemblerX86<Assembler>::Instruction(const char* name, const Arg
   fprintf(out_, "\\n\"\n");
 }
 
+}  // namespace x86_32_and_x86_64
+
 }  // namespace berberis
 
-#endif  // BERBERIS_INTRINSICS_COMMON_TO_X86_TEXT_ASSEMBLER_COMMON_H_
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_TEXT_ASSEMBLER_COMMON_H_
diff --git a/intrinsics/common_to_x86/include/berberis/intrinsics/intrinsics_bindings.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/intrinsics_bindings.h
similarity index 91%
rename from intrinsics/common_to_x86/include/berberis/intrinsics/intrinsics_bindings.h
rename to intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/intrinsics_bindings.h
index 6acb8b0d..fe32c39e 100644
--- a/intrinsics/common_to_x86/include/berberis/intrinsics/intrinsics_bindings.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/intrinsics_bindings.h
@@ -17,6 +17,6 @@
 #ifndef BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
 #define BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
 
-#include "berberis/intrinsics/common_to_x86/intrinsics_bindings.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
 
 #endif  // BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/common_to_x86/include/berberis/intrinsics/macro_assembler-inl.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/macro_assembler-inl.h
similarity index 100%
rename from intrinsics/common_to_x86/include/berberis/intrinsics/macro_assembler-inl.h
rename to intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/macro_assembler-inl.h
diff --git a/intrinsics/common_to_x86/intrinsics_float_test.cc b/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float_test.cc
similarity index 99%
rename from intrinsics/common_to_x86/intrinsics_float_test.cc
rename to intrinsics/all_to_x86_32_or_x86_64/intrinsics_float_test.cc
index 18225d57..53a66485 100644
--- a/intrinsics/common_to_x86/intrinsics_float_test.cc
+++ b/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float_test.cc
@@ -20,8 +20,8 @@
 #include <utility>  // std::forward
 
 #include "berberis/base/bit_util.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h"
 #include "berberis/intrinsics/common/intrinsics_float.h"
-#include "berberis/intrinsics/common_to_x86/intrinsics_float.h"
 
 namespace berberis {
 
diff --git a/intrinsics/common_to_x86_64/tuple_test.cc b/intrinsics/all_to_x86_64/tuple_test.cc
similarity index 100%
rename from intrinsics/common_to_x86_64/tuple_test.cc
rename to intrinsics/all_to_x86_64/tuple_test.cc
diff --git a/intrinsics/gen_intrinsics.py b/intrinsics/gen_intrinsics.py
index 69b9a78d..55913a52 100755
--- a/intrinsics/gen_intrinsics.py
+++ b/intrinsics/gen_intrinsics.py
@@ -311,6 +311,15 @@ def _get_interpreter_hook_call_expr(name, intr, desc=None):
 def _get_interpreter_hook_return_stmt(name, intr, desc=None):
   return 'return ' + _get_interpreter_hook_call_expr(name, intr, desc) + ';'
 
+def _get_unused(intr):
+  call_expr = 'UNUSED(%s);' % ', '.join('arg%d' % (num) for num, _ in enumerate(intr['in']))
+  return call_expr
+
+def _get_placeholder_return_stmt(intr, f):
+  print(INDENT + _get_unused(intr), file=f)
+  outs = intr['out']
+  if outs:
+    print(INDENT + 'return {};', file=f)
 
 def _get_semantics_player_hook_raw_vector_body(name, intr, get_return_stmt):
   outs = intr['out']
@@ -324,7 +333,6 @@ def _get_semantics_player_hook_raw_vector_body(name, intr, get_return_stmt):
       yield 2 * INDENT + get_return_stmt(name, intr, desc)
   yield INDENT + 'default:'
   yield 2 * INDENT + 'LOG_ALWAYS_FATAL("Unsupported size");'
-  yield 2 * INDENT + 'return {};'
   yield '}'
 
 
@@ -372,7 +380,6 @@ def _get_semantics_player_hook_vector_body(name, intr, get_return_stmt):
         yield 2 * INDENT + get_return_stmt(name, intr, desc)
   yield INDENT + 'default:'
   yield 2 * INDENT + 'LOG_ALWAYS_FATAL("Unsupported format");'
-  yield 2 * INDENT + 'return {};'
   yield '}'
 
 
@@ -382,7 +389,7 @@ def _get_interpreter_hook_vector_body(name, intr):
       name, intr, _get_interpreter_hook_return_stmt)
 
 
-def _gen_interpreter_hook(f, name, intr):
+def _gen_interpreter_hook(f, name, intr, option):
   print('%s const {' % (_get_semantics_player_hook_proto(name, intr)), file=f)
 
   if _is_vector_class(intr):
@@ -398,7 +405,12 @@ def _gen_interpreter_hook(f, name, intr):
     lines = [INDENT + l for l in lines]
     print('\n'.join(lines), file=f)
   else:
-    print(INDENT + _get_interpreter_hook_return_stmt(name, intr), file=f)
+    # TODO(b/363057506): Add float support and clean up the logic here.
+    arm64_allowlist = ['AmoAdd', 'AmoAnd', 'AmoMax', 'AmoMin', 'AmoOr', 'AmoSwap', 'AmoXor']
+    if (option == 'arm64') and (name not in arm64_allowlist):
+      _get_placeholder_return_stmt(intr, f)
+    else:
+      print(INDENT + _get_interpreter_hook_return_stmt(name, intr), file=f)
 
   print('}\n', file=f)
 
@@ -677,10 +689,10 @@ def _gen_semantic_player_types(intrs):
       intr['sem-player-types'] = map
 
 
-def _gen_interpreter_intrinsics_hooks_impl_inl_h(f, intrs):
+def _gen_interpreter_intrinsics_hooks_impl_inl_h(f, intrs, option):
   print(AUTOGEN, file=f)
   for name, intr in intrs:
-    _gen_interpreter_hook(f, name, intr)
+    _gen_interpreter_hook(f, name, intr, option)
 
 
 def _gen_translator_intrinsics_hooks_impl_inl_h(f, intrs):
@@ -736,13 +748,11 @@ def _get_reg_operand_info(arg, info_prefix=None):
 
 def _gen_make_intrinsics(f, intrs, archs):
   print("""%s
-template <%s,
-          typename MacroAssembler,
+template <typename MacroAssembler,
           typename Callback,
           typename... Args>
-void ProcessAllBindings(Callback callback, Args&&... args) {""" % (
-    AUTOGEN,
-    ',\n          '.join(['typename Assembler_%s' % arch for arch in archs])),
+void ProcessAllBindings([[maybe_unused]] Callback callback,
+                        [[maybe_unused]] Args&&... args) {""" % AUTOGEN,
     file=f)
   for line in _gen_c_intrinsics_generator(
           intrs, _is_interpreter_compatible_assembler, False): # False for gen_builder
@@ -805,13 +815,11 @@ def _gen_process_bindings(f, intrs, archs):
   _gen_opcode_generators_f(f, intrs)
   print("""
 template <auto kFunc,
-          %s,
           typename MacroAssembler,
           typename Result,
           typename Callback,
           typename... Args>
-Result ProcessBindings(Callback callback, Result def_result, Args&&... args) {""" % (
-    ',\n          '.join(['typename Assembler_%s' % arch for arch in archs])),
+Result ProcessBindings(Callback callback, Result def_result, Args&&... args) {""",
     file=f)
   for line in _gen_c_intrinsics_generator(
           intrs, _is_translator_compatible_assembler, True): # True for gen_builder
@@ -906,16 +914,16 @@ def _gen_c_intrinsic(name,
   if not check_compatible_assembler(asm):
     return
 
-  cpuid_restriction = 'intrinsics::bindings::kNoCPUIDRestriction'
+  cpuid_restriction = 'intrinsics::bindings::NoCPUIDRestriction'
   if 'feature' in asm:
     if asm['feature'] == 'AuthenticAMD':
-      cpuid_restriction = 'intrinsics::bindings::kIsAuthenticAMD'
+      cpuid_restriction = 'intrinsics::bindings::IsAuthenticAMD'
     else:
-      cpuid_restriction = 'intrinsics::bindings::kHas%s' % asm['feature']
+      cpuid_restriction = 'intrinsics::bindings::Has%s' % asm['feature']
 
-  nan_restriction = 'intrinsics::bindings::kNoNansOperation'
+  nan_restriction = 'intrinsics::bindings::NoNansOperation'
   if 'nan' in asm:
-    nan_restriction = 'intrinsics::bindings::k%sNanOperationsHandling' % asm['nan']
+    nan_restriction = 'intrinsics::bindings::%sNanOperationsHandling' % asm['nan']
     template_arg = 'true' if asm['nan'] == "Precise" else "false"
     if '<' in name:
       template_pos = name.index('<')
@@ -1015,10 +1023,7 @@ def _get_asm_reference(asm):
   #     typename Assembler_common_x86::Register,
   #     typename Assembler_common_x86::Register)>(
   #       &Assembler_common_x86::Lzcntl)
-  if 'arch' in asm:
-    assembler = 'Assembler_%s' % asm['arch']
-  else:
-    assembler = 'std::tuple_element_t<%s, MacroAssembler>' % asm['macroassembler']
+  assembler = 'std::tuple_element_t<%s, MacroAssembler>' % asm['macroassembler']
   return 'static_cast<void (%s::*)(%s)>(%s&%s::%s%s)' % (
       assembler,
       _get_asm_type(asm, 'typename %s::' % assembler),
@@ -1044,7 +1049,7 @@ def _load_intrs_arch_def(intrs_defs):
   for intrs_def in intrs_defs:
     with open(intrs_def) as intrs:
       json_array = json.load(intrs)
-      while isinstance(json_array[0], str):
+      while isinstance(len(json_array) > 0 and json_array[0], str):
         json_array.pop(0)
       json_data.extend(json_array)
   return json_data
@@ -1052,12 +1057,8 @@ def _load_intrs_arch_def(intrs_defs):
 
 def _load_macro_def(intrs, arch_intrs, insns_def, macroassembler):
   arch, insns = asm_defs.load_asm_defs(insns_def)
-  if arch is not None:
-    for insn in insns:
-      insn['arch'] = arch
-  else:
-    for insn in insns:
-      insn['macroassembler'] = macroassembler
+  for insn in insns:
+    insn['macroassembler'] = macroassembler
   insns_map = dict((insn['name'], insn) for insn in insns)
   unprocessed_intrs = []
   for arch_intr in arch_intrs:
@@ -1070,13 +1071,13 @@ def _load_macro_def(intrs, arch_intrs, insns_def, macroassembler):
 
 
 def _is_interpreter_compatible_assembler(intr_asm):
-  if intr_asm.get('usage', '') == 'translate-only':
+  if intr_asm.get('usage', '') == 'inline-only':
     return False
   return True
 
 
 def _is_translator_compatible_assembler(intr_asm):
-  if intr_asm.get('usage', '') == 'interpret-only':
+  if intr_asm.get('usage', '') == 'no-inline':
     return False
   return True
 
@@ -1138,10 +1139,7 @@ def _open_asm_def_files(def_files, arch_def_files, asm_def_files, need_archs=Tru
   macro_assemblers = 0
   for macro_def in asm_def_files:
     arch, arch_intrs = _load_macro_def(expanded_intrs, arch_intrs, macro_def, macro_assemblers)
-    if arch is not None:
-      archs.append(arch)
-    else:
-      macro_assemblers += 1
+    macro_assemblers += 1
   # Make sure that all intrinsics were found during processing of arch_intrs.
   assert arch_intrs == []
   if need_archs:
@@ -1200,6 +1198,23 @@ def main(argv):
       pass
     return open(name, 'w')
 
+  # Temporary special case for riscv64 to arm64.
+  # TODO(b/362520361): generalize and combine with the below.
+  option = argv[1]
+  if option == 'arm64':
+    mode = argv[2]
+    out_files_end = 5
+    def_files_end = out_files_end
+    while argv[def_files_end].endswith('intrinsic_def.json'):
+      def_files_end += 1
+      if (def_files_end == len(argv)):
+        break
+    intrs = sorted(_load_intrs_def_files(argv[out_files_end:def_files_end]).items())
+    _gen_intrinsics_inl_h(open_out_file(argv[3]), intrs)
+    _gen_semantic_player_types(intrs)
+    _gen_interpreter_intrinsics_hooks_impl_inl_h(open_out_file(argv[4]), intrs, option)
+    return 0
+
   mode = argv[1]
   if mode in ('--text_asm_intrinsics_bindings', '--public_headers'):
     out_files_end = 3 if mode == '--text_asm_intrinsics_bindings' else 7
@@ -1220,7 +1235,7 @@ def main(argv):
       _gen_intrinsics_inl_h(open_out_file(argv[2]), intrs)
       _gen_process_bindings(open_out_file(argv[3]), expanded_intrs, archs)
       _gen_semantic_player_types(intrs)
-      _gen_interpreter_intrinsics_hooks_impl_inl_h(open_out_file(argv[4]), intrs)
+      _gen_interpreter_intrinsics_hooks_impl_inl_h(open_out_file(argv[4]), intrs, '')
       _gen_translator_intrinsics_hooks_impl_inl_h(
           open_out_file(argv[5]), intrs)
       _gen_mock_semantics_listener_intrinsics_hooks_impl_inl_h(
diff --git a/intrinsics/gen_intrinsics_test.py b/intrinsics/gen_intrinsics_test.py
index 25e90432..cd7c0070 100755
--- a/intrinsics/gen_intrinsics_test.py
+++ b/intrinsics/gen_intrinsics_test.py
@@ -201,7 +201,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return std::get<0>(intrinsics::Foo<128>(arg0, arg1));",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported size\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
   def test_get_interpreter_hook_vector_body_fp(self):
@@ -219,7 +218,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return std::get<0>(intrinsics::Foo<intrinsics::Float32, 4>(arg0, arg1));",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
 
@@ -242,7 +240,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return std::get<0>(intrinsics::Foo<uint64_t, 2>(arg0, arg1));",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
 
@@ -263,7 +260,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return std::get<0>(intrinsics::Foo<int32_t, 4>(arg0, arg1));",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
 
@@ -284,7 +280,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return std::get<0>(intrinsics::Foo<uint32_t, 4>(arg0, arg1));",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
 
@@ -303,7 +298,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return std::get<0>(intrinsics::Foo<uint32_t, 2>(arg0, arg1));",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
 
@@ -326,7 +320,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return intrinsics::Foo<int32_t, 1>(arg0, GPRRegToInteger<uint32_t>(arg1));",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
 
@@ -363,7 +356,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return CallIntrinsic<&intrinsics::Foo<128>, SimdRegister>(arg0, arg1);",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported size\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
 
@@ -386,7 +378,6 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    return CallIntrinsic<&intrinsics::Foo<int32_t, 1>, std::tuple<SimdRegister, Register>>(arg0, arg1);",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
-                              "    return {};",
                               "}")) # pyformat: disable
 
 if __name__ == "__main__":
diff --git a/intrinsics/common_to_x86/gen_text_asm_intrinsics.cc b/intrinsics/gen_text_asm_intrinsics.cc
similarity index 83%
rename from intrinsics/common_to_x86/gen_text_asm_intrinsics.cc
rename to intrinsics/gen_text_asm_intrinsics.cc
index 67816881..b03bf4da 100644
--- a/intrinsics/common_to_x86/gen_text_asm_intrinsics.cc
+++ b/intrinsics/gen_text_asm_intrinsics.cc
@@ -15,7 +15,6 @@
  */
 
 #include <stdio.h>
-#include <xmmintrin.h>
 
 #include <algorithm>
 #include <iterator>
@@ -28,9 +27,9 @@
 
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
-#include "berberis/intrinsics/common_to_x86/intrinsics_bindings.h"
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
+#include "berberis/intrinsics/common/intrinsics_float.h"
 #include "berberis/intrinsics/intrinsics_args.h"
-#include "berberis/intrinsics/intrinsics_float.h"
 #include "berberis/intrinsics/macro_assembler.h"
 #include "berberis/intrinsics/simd_register.h"
 #include "berberis/intrinsics/type_traits.h"
@@ -39,24 +38,6 @@
 
 namespace berberis {
 
-namespace constants_pool {
-
-// Note: kBerberisMacroAssemblerConstantsRelocated is the same as original,
-// unrelocated version in 32-bit world.  But in 64-bit world it's copy on the first 2GiB.
-//
-// Our builder could be built as 64-bit binary thus we must not mix them.
-//
-// Note: we have CHECK_*_LAYOUT tests in macro_assembler_common_x86.cc to make sure
-// offsets produced by 64-bit builder are usable in 32-bit libberberis.so
-
-extern const int32_t kBerberisMacroAssemblerConstantsRelocated;
-
-int32_t GetOffset(int32_t address) {
-  return address - constants_pool::kBerberisMacroAssemblerConstantsRelocated;
-}
-
-}  // namespace constants_pool
-
 template <typename AsmCallInfo>
 void GenerateOutputVariables(FILE* out, int indent);
 template <typename AsmCallInfo>
@@ -353,62 +334,7 @@ auto CallTextAssembler(FILE* out, int indent, int* register_numbers) {
                        }
                      })));
   // Verify CPU vendor and SSE restrictions.
-  bool expect_avx = false;
-  bool expect_bmi = false;
-  bool expect_fma = false;
-  bool expect_fma4 = false;
-  bool expect_lzcnt = false;
-  bool expect_popcnt = false;
-  bool expect_sse3 = false;
-  bool expect_ssse3 = false;
-  bool expect_sse4_1 = false;
-  bool expect_sse4_2 = false;
-  switch (AsmCallInfo::kCPUIDRestriction) {
-    case intrinsics::bindings::kHasBMI:
-      expect_bmi = true;
-      break;
-    case intrinsics::bindings::kHasLZCNT:
-      expect_lzcnt = true;
-      break;
-    case intrinsics::bindings::kHasPOPCNT:
-      expect_popcnt = true;
-      break;
-    case intrinsics::bindings::kHasFMA:
-    case intrinsics::bindings::kHasFMA4:
-      if (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasFMA) {
-        expect_fma = true;
-      } else {
-        expect_fma4 = true;
-      }
-      [[fallthrough]];
-    case intrinsics::bindings::kHasAVX:
-      expect_avx = true;
-      [[fallthrough]];
-    case intrinsics::bindings::kHasSSE4_2:
-      expect_sse4_2 = true;
-      [[fallthrough]];
-    case intrinsics::bindings::kHasSSE4_1:
-      expect_sse4_1 = true;
-      [[fallthrough]];
-    case intrinsics::bindings::kHasSSSE3:
-      expect_ssse3 = true;
-      [[fallthrough]];
-    case intrinsics::bindings::kHasSSE3:
-      expect_sse3 = true;
-      [[fallthrough]];
-    case intrinsics::bindings::kIsAuthenticAMD:
-    case intrinsics::bindings::kNoCPUIDRestriction:;  // Do nothing - make compiler happy.
-  }
-  CHECK_EQ(expect_avx, as.need_avx);
-  CHECK_EQ(expect_bmi, as.need_bmi);
-  CHECK_EQ(expect_fma, as.need_fma);
-  CHECK_EQ(expect_fma4, as.need_fma4);
-  CHECK_EQ(expect_lzcnt, as.need_lzcnt);
-  CHECK_EQ(expect_popcnt, as.need_popcnt);
-  CHECK_EQ(expect_sse3, as.need_sse3);
-  CHECK_EQ(expect_ssse3, as.need_ssse3);
-  CHECK_EQ(expect_sse4_1, as.need_sse4_1);
-  CHECK_EQ(expect_sse4_2, as.need_sse4_2);
+  as.CheckCPUIDRestriction<typename AsmCallInfo::CPUIDRestriction>();
   return std::tuple{as.need_gpr_macroassembler_scratch(), as.need_gpr_macroassembler_constants()};
 }
 
@@ -598,13 +524,15 @@ constexpr bool NeedOutputShadow(Arg arg) {
 #include "text_asm_intrinsics_process_bindings-inl.h"
 
 void GenerateTextAsmIntrinsics(FILE* out) {
-  intrinsics::bindings::CPUIDRestriction cpuid_restriction =
-      intrinsics::bindings::kNoCPUIDRestriction;
+  // Note: nullptr means "NoCPUIDRestriction", other values are only assigned in one place below
+  // since the code in this function mostly cares only about three cases:
+  //   • There are no CPU restrictions.
+  //   • There are CPU restrictions but they are the same as in previous case (which is error).
+  //   • There are new CPU restrictions.
+  const char* cpuid_restriction = nullptr /* NoCPUIDRestriction */;
   bool if_opened = false;
   std::string running_name;
-  ProcessAllBindings<TextAssemblerX86<TextAssembler>,
-                     TextAssembler,
-                     MacroAssembler<TextAssembler>::MacroAssemblers>(
+  ProcessAllBindings<MacroAssembler<TextAssembler>::MacroAssemblers>(
       [&running_name, &if_opened, &cpuid_restriction, out](auto&& asm_call_generator) {
         using AsmCallInfo = std::decay_t<decltype(asm_call_generator)>;
         std::string full_name = std::string(asm_call_generator.kIntrinsic,
@@ -621,9 +549,9 @@ void GenerateTextAsmIntrinsics(FILE* out) {
         }
         if (full_name != running_name) {
           if (if_opened) {
-            if (cpuid_restriction != intrinsics::bindings::kNoCPUIDRestriction) {
+            if (cpuid_restriction) {
               fprintf(out, "  } else {\n    return %s;\n", running_name.c_str());
-              cpuid_restriction = intrinsics::bindings::kNoCPUIDRestriction;
+              cpuid_restriction = nullptr /* NoCPUIDRestriction */;
             }
             if_opened = false;
             fprintf(out, "  }\n");
@@ -635,58 +563,23 @@ void GenerateTextAsmIntrinsics(FILE* out) {
           GenerateFunctionHeader<AsmCallInfo>(out, 0);
           running_name = full_name;
         }
-        if (asm_call_generator.kCPUIDRestriction != cpuid_restriction) {
-          if (asm_call_generator.kCPUIDRestriction == intrinsics::bindings::kNoCPUIDRestriction) {
+        using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
+        // Note: this series of "if constexpr" expressions is the only place where cpuid_restriction
+        // may get a concrete non-zero value;
+        if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::NoCPUIDRestriction>) {
+          if (cpuid_restriction) {
             fprintf(out, "  } else {\n");
+            cpuid_restriction = nullptr;
+          }
+        } else {
+          if (if_opened) {
+            fprintf(out, "  } else if (");
           } else {
-            if (if_opened) {
-              fprintf(out, "  } else if (");
-            } else {
-              fprintf(out, "  if (");
-              if_opened = true;
-            }
-            switch (asm_call_generator.kCPUIDRestriction) {
-              default:
-                // Unsupported CPUID value.
-                CHECK(false);
-              case intrinsics::bindings::kIsAuthenticAMD:
-                fprintf(out, "host_platform::kIsAuthenticAMD");
-                break;
-              case intrinsics::bindings::kHasAVX:
-                fprintf(out, "host_platform::kHasAVX");
-                break;
-              case intrinsics::bindings::kHasBMI:
-                fprintf(out, "host_platform::kHasBMI");
-                break;
-              case intrinsics::bindings::kHasFMA:
-                fprintf(out, "host_platform::kHasFMA");
-                break;
-              case intrinsics::bindings::kHasFMA4:
-                fprintf(out, "host_platform::kHasFMA4");
-                break;
-              case intrinsics::bindings::kHasLZCNT:
-                fprintf(out, "host_platform::kHasLZCNT");
-                break;
-              case intrinsics::bindings::kHasPOPCNT:
-                fprintf(out, "host_platform::kHasPOPCNT");
-                break;
-              case intrinsics::bindings::kHasSSE3:
-                fprintf(out, "host_platform::kHasSSE3");
-                break;
-              case intrinsics::bindings::kHasSSSE3:
-                fprintf(out, "host_platform::kHasSSSE3");
-                break;
-              case intrinsics::bindings::kHasSSE4_1:
-                fprintf(out, "host_platform::kHasSSE4_1");
-                break;
-              case intrinsics::bindings::kHasSSE4_2:
-                fprintf(out, "host_platform::kHasSSE4_2");
-                break;
-              case intrinsics::bindings::kNoCPUIDRestriction:;  // Do nothing - make compiler happy.
-            }
-            fprintf(out, ") {\n");
+            fprintf(out, "  if (");
+            if_opened = true;
           }
-          cpuid_restriction = asm_call_generator.kCPUIDRestriction;
+          cpuid_restriction = TextAssembler::kCPUIDRestrictionString<CPUIDRestriction>;
+          fprintf(out, "%s) {\n", cpuid_restriction);
         }
         GenerateFunctionBody<AsmCallInfo>(out, 2 + 2 * if_opened);
       });
@@ -694,7 +587,9 @@ void GenerateTextAsmIntrinsics(FILE* out) {
     fprintf(out, "  }\n");
   }
   // Final line of function.
-  fprintf(out, "};\n\n");
+  if (!running_name.empty()) {
+    fprintf(out, "};\n\n");
+  }
 }
 
 }  // namespace berberis
@@ -703,17 +598,35 @@ int main(int argc, char* argv[]) {
   FILE* out = argc > 1 ? fopen(argv[1], "w") : stdout;
   fprintf(out,
           R"STRING(
-// This file automatically generated by make_intrinsics.cc
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// This file automatically generated by gen_text_asm_intrinsics.cc
 // DO NOT EDIT!
 
 #ifndef %2$s_%3$s_INTRINSICS_INTRINSICS_H_
 #define %2$s_%3$s_INTRINSICS_INTRINSICS_H_
 
+#if defined(__i386__) || defined(__x86_64__)
 #include <xmmintrin.h>
+#endif
 
 #include "berberis/base/config.h"
 #include "berberis/runtime_primitives/platform.h"
-#include "%3$s/intrinsics/%1$s/intrinsics.h"
+#include "%3$s/intrinsics/%1$s_to_all/intrinsics.h"
 #include "%3$s/intrinsics/vector_intrinsics.h"
 
 namespace berberis::constants_pool {
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics.h b/intrinsics/include/berberis/intrinsics/common/intrinsics.h
index 2f57cd68..f6aa056d 100644
--- a/intrinsics/include/berberis/intrinsics/common/intrinsics.h
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics.h
@@ -20,14 +20,17 @@
 #include <cstdint>
 
 #include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/intrinsics_float.h"  // Float32/Float64/ProcessNans
+
+#if !defined(__aarch64__)
+#include "berberis/intrinsics/common/intrinsics_float.h"  // Float32/Float64
+#endif
 
 namespace berberis {
 
 class SIMD128Register;
 
 namespace intrinsics {
-
+#if !defined(__aarch64__)
 enum EnumFromTemplateType {
   kInt8T,
   kUInt8T,
@@ -73,7 +76,7 @@ constexpr EnumFromTemplateType TypeToEnumFromTemplateType() {
 
 template <typename Type>
 constexpr EnumFromTemplateType kEnumFromTemplateType = TypeToEnumFromTemplateType<Type>();
-
+#endif
 // A solution for the inability to call generic implementation from specialization.
 // Declaration:
 //   template <typename Type,
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h b/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h
new file mode 100644
index 00000000..4b82329d
--- /dev/null
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h
@@ -0,0 +1,175 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef BERBERIS_INTRINSICS_COMMON_INTRINSICS_BINDINGS_H_
+#define BERBERIS_INTRINSICS_COMMON_INTRINSICS_BINDINGS_H_
+
+#include <cstdint>
+
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/intrinsics_args.h"
+#include "berberis/intrinsics/type_traits.h"
+
+namespace berberis::intrinsics::bindings {
+
+class FLAGS {
+ public:
+  static constexpr bool kIsImmediate = false;
+  static constexpr bool kIsImplicitReg = true;
+  static constexpr char kAsRegister = 0;
+  template <typename MachineInsnArch>
+  static constexpr auto kRegClass = MachineInsnArch::kFLAGS;
+};
+
+class Mem8 {
+ public:
+  using Type = uint8_t;
+  static constexpr bool kIsImmediate = false;
+  static constexpr char kAsRegister = 'm';
+};
+
+class Mem16 {
+ public:
+  using Type = uint16_t;
+  static constexpr bool kIsImmediate = false;
+  static constexpr char kAsRegister = 'm';
+};
+
+class Mem32 {
+ public:
+  using Type = uint32_t;
+  static constexpr bool kIsImmediate = false;
+  static constexpr char kAsRegister = 'm';
+};
+
+class Mem64 {
+ public:
+  using Type = uint64_t;
+  static constexpr bool kIsImmediate = false;
+  static constexpr char kAsRegister = 'm';
+};
+
+// Tag classes. They are never instantioned, only used as tags to pass information about
+// bindings.
+class Def;
+class DefEarlyClobber;
+class Use;
+class UseDef;
+
+template <typename Tag, typename MachineRegKind>
+constexpr auto ToRegKind() {
+  if constexpr (std::is_same_v<Tag, Def>) {
+    return MachineRegKind::kDef;
+  } else if constexpr (std::is_same_v<Tag, DefEarlyClobber>) {
+    return MachineRegKind::kDefEarlyClobber;
+  } else if constexpr (std::is_same_v<Tag, Use>) {
+    return MachineRegKind::kUse;
+  } else if constexpr (std::is_same_v<Tag, UseDef>) {
+    return MachineRegKind::kUseDef;
+  } else {
+    static_assert(kDependentTypeFalse<Tag>);
+  }
+}
+
+template <typename Tag, typename MachineRegKind>
+inline constexpr auto kRegKind = ToRegKind<Tag, MachineRegKind>();
+
+// Tag classes. They are never instantioned, only used as tags to pass information about
+// bindings.
+class NoCPUIDRestriction;  // All CPUs have at least “no CPUID restriction” mode.
+
+// Tag classes. They are never instantioned, only used as tags to pass information about
+// bindings.
+class NoNansOperation;
+class PreciseNanOperationsHandling;
+class ImpreciseNanOperationsHandling;
+
+template <auto kIntrinsicTemplateName,
+          auto kMacroInstructionTemplateName,
+          auto kMnemo,
+          typename GetOpcode,
+          typename CPUIDRestrictionTemplateValue,
+          typename PreciseNanOperationsHandlingTemplateValue,
+          bool kSideEffectsTemplateValue,
+          typename... Types>
+class AsmCallInfo;
+
+template <auto kIntrinsicTemplateName,
+          auto kMacroInstructionTemplateName,
+          auto kMnemo,
+          typename GetOpcode,
+          typename CPUIDRestrictionTemplateValue,
+          typename PreciseNanOperationsHandlingTemplateValue,
+          bool kSideEffectsTemplateValue,
+          typename... InputArgumentsTypes,
+          typename... OutputArgumentsTypes,
+          typename... BindingsTypes>
+class AsmCallInfo<kIntrinsicTemplateName,
+                  kMacroInstructionTemplateName,
+                  kMnemo,
+                  GetOpcode,
+                  CPUIDRestrictionTemplateValue,
+                  PreciseNanOperationsHandlingTemplateValue,
+                  kSideEffectsTemplateValue,
+                  std::tuple<InputArgumentsTypes...>,
+                  std::tuple<OutputArgumentsTypes...>,
+                  BindingsTypes...>
+    final {
+ public:
+  static constexpr auto kIntrinsic = kIntrinsicTemplateName;
+  static constexpr auto kMacroInstruction = kMacroInstructionTemplateName;
+  // TODO(b/260725458): Use lambda template argument after C++20 becomes available.
+  template <typename Opcode>
+  static constexpr auto kOpcode = GetOpcode{}.template operator()<Opcode>();
+  using CPUIDRestriction = CPUIDRestrictionTemplateValue;
+  using PreciseNanOperationsHandling = PreciseNanOperationsHandlingTemplateValue;
+  static constexpr bool kSideEffects = kSideEffectsTemplateValue;
+  static constexpr const char* InputArgumentsTypeNames[] = {
+      TypeTraits<InputArgumentsTypes>::kName...};
+  static constexpr const char* OutputArgumentsTypeNames[] = {
+      TypeTraits<OutputArgumentsTypes>::kName...};
+  template <typename Callback, typename... Args>
+  constexpr static void ProcessBindings(Callback&& callback, Args&&... args) {
+    (callback(ArgTraits<BindingsTypes>(), std::forward<Args>(args)...), ...);
+  }
+  template <typename Callback, typename... Args>
+  constexpr static bool VerifyBindings(Callback&& callback, Args&&... args) {
+    return (callback(ArgTraits<BindingsTypes>(), std::forward<Args>(args)...) && ...);
+  }
+  template <typename Callback, typename... Args>
+  constexpr static auto MakeTuplefromBindings(Callback&& callback, Args&&... args) {
+    return std::tuple_cat(callback(ArgTraits<BindingsTypes>(), std::forward<Args>(args)...)...);
+  }
+  using InputArguments = std::tuple<InputArgumentsTypes...>;
+  using OutputArguments = std::tuple<OutputArgumentsTypes...>;
+  using Bindings = std::tuple<BindingsTypes...>;
+  using IntrinsicType = std::conditional_t<std::tuple_size_v<OutputArguments> == 0,
+                                           void (*)(InputArgumentsTypes...),
+                                           OutputArguments (*)(InputArgumentsTypes...)>;
+  template <template <typename, auto, auto, typename...> typename MachineInsnType,
+            template <typename...>
+            typename ConstructorArgs,
+            typename Opcode>
+  using MachineInsn = MachineInsnType<AsmCallInfo,
+                                      kMnemo,
+                                      kOpcode<Opcode>,
+                                      ConstructorArgs<BindingsTypes...>,
+                                      BindingsTypes...>;
+};
+
+}  // namespace berberis::intrinsics::bindings
+
+#endif  // BERBERIS_INTRINSICS_COMMON_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics_float.h b/intrinsics/include/berberis/intrinsics/common/intrinsics_float.h
index a227b6b4..db56e6d2 100644
--- a/intrinsics/include/berberis/intrinsics/common/intrinsics_float.h
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics_float.h
@@ -59,7 +59,7 @@ class WrappedFloatType {
   WrappedFloatType& operator=(WrappedFloatType&& other) noexcept = default;
   ~WrappedFloatType() = default;
   template <typename IntType,
-            typename = std::enable_if_t<std::is_integral_v<BaseType> &&
+            typename = std::enable_if_t<std::is_integral_v<IntType> &&
                                         sizeof(BaseType) == sizeof(IntType)>>
   [[nodiscard]] constexpr operator Raw<IntType>() const {
     // Can't use bit_cast here because of IA32 ABI!
@@ -73,6 +73,9 @@ class WrappedFloatType {
   explicit constexpr operator uint32_t() const { return value_; }
   explicit constexpr operator int64_t() const { return value_; }
   explicit constexpr operator uint64_t() const { return value_; }
+  explicit constexpr operator WrappedFloatType<_Float16>() const {
+    return WrappedFloatType<_Float16>(value_);
+  }
   explicit constexpr operator WrappedFloatType<float>() const {
     return WrappedFloatType<float>(value_);
   }
@@ -130,6 +133,81 @@ using Float16 = WrappedFloatType<_Float16>;
 using Float32 = WrappedFloatType<float>;
 using Float64 = WrappedFloatType<double>;
 
+// It's NOT safe to use ANY functions which return raw float or double.  That's because IA32 ABI
+// uses x87 stack to pass arguments (even with -mfpmath=sse) which clobbers NaN values.
+//
+// Builtins do NOT use the official calling conventions but are instead embedded in the function -
+// even if all optimizations are disabled. Therefore, it's safe to use builtins here if on x86 host
+// this file is compiled with SSE enforced for FP calculations, which is always the case for us.
+// Clang uses SSE whenever possible by default. For GCC we need to specify -msse2 and -mfpmath=sse.
+
+inline Float32 CopySignBit(const Float32& v1, const Float32& v2) {
+  return Float32(__builtin_copysignf(v1.value_, v2.value_));
+}
+
+inline Float64 CopySignBit(const Float64& v1, const Float64& v2) {
+  return Float64(__builtin_copysign(v1.value_, v2.value_));
+}
+
+inline Float32 Absolute(const Float32& v) {
+  return Float32(__builtin_fabsf(v.value_));
+}
+
+inline Float64 Absolute(const Float64& v) {
+  return Float64(__builtin_fabs(v.value_));
+}
+
+inline FPInfo FPClassify(const Float32& v) {
+  return static_cast<FPInfo>(__builtin_fpclassify(static_cast<int>(FPInfo::kNaN),
+                                                  static_cast<int>(FPInfo::kInfinite),
+                                                  static_cast<int>(FPInfo::kNormal),
+                                                  static_cast<int>(FPInfo::kSubnormal),
+                                                  static_cast<int>(FPInfo::kZero),
+                                                  v.value_));
+}
+
+inline FPInfo FPClassify(const Float64& v) {
+  return static_cast<FPInfo>(__builtin_fpclassify(static_cast<int>(FPInfo::kNaN),
+                                                  static_cast<int>(FPInfo::kInfinite),
+                                                  static_cast<int>(FPInfo::kNormal),
+                                                  static_cast<int>(FPInfo::kSubnormal),
+                                                  static_cast<int>(FPInfo::kZero),
+                                                  v.value_));
+}
+
+inline int IsNan(const Float32& v) {
+  return __builtin_isnan(v.value_);
+}
+
+inline int IsNan(const Float64& v) {
+  return __builtin_isnan(v.value_);
+}
+
+inline int SignBit(const Float32& v) {
+  return __builtin_signbitf(v.value_);
+}
+
+inline int SignBit(const Float64& v) {
+  return __builtin_signbit(v.value_);
+}
+
+inline Float32 Sqrt(const Float32& v) {
+  return Float32(__builtin_sqrtf(v.value_));
+}
+
+inline Float64 Sqrt(const Float64& v) {
+  return Float64(__builtin_sqrt(v.value_));
+}
+
+// x*y + z
+inline Float32 MulAdd(const Float32& v1, const Float32& v2, const Float32& v3) {
+  return Float32(fmaf(v1.value_, v2.value_, v3.value_));
+}
+
+inline Float64 MulAdd(const Float64& v1, const Float64& v2, const Float64& v3) {
+  return Float64(fma(v1.value_, v2.value_, v3.value_));
+}
+
 }  // namespace intrinsics
 
 }  // namespace berberis
diff --git a/intrinsics/include/berberis/intrinsics/intrinsics_bitmanip_impl.h b/intrinsics/include/berberis/intrinsics/intrinsics_bitmanip_impl.h
index 812001e9..b23bc395 100644
--- a/intrinsics/include/berberis/intrinsics/intrinsics_bitmanip_impl.h
+++ b/intrinsics/include/berberis/intrinsics/intrinsics_bitmanip_impl.h
@@ -33,6 +33,23 @@ inline std::tuple<int64_t> Cpop<int64_t, kUseCppImplementation>(int64_t src) {
   return {__builtin_popcountll(src)};
 }
 
+template <typename ElementType>
+std::tuple<ElementType> Brev8(ElementType arg) {
+  constexpr unsigned long ls1 = 0x5555'5555'5555'5555;
+  constexpr unsigned long rs1 = 0xAAAA'AAAA'AAAA'AAAA;
+  constexpr unsigned long ls2 = 0x3333'3333'3333'3333;
+  constexpr unsigned long rs2 = 0xCCCC'CCCC'CCCC'CCCC;
+  constexpr unsigned long ls4 = 0x0F0F'0F0F'0F0F'0F0F;
+  constexpr unsigned long rs4 = 0xF0F0'F0F0'F0F0'F0F0;
+  auto tmp_arg = static_cast<typename ElementType::BaseType>(arg);
+
+  tmp_arg = ((tmp_arg & ls1) << 1) | ((tmp_arg & rs1) >> 1);
+  tmp_arg = ((tmp_arg & ls2) << 2) | ((tmp_arg & rs2) >> 2);
+  tmp_arg = ((tmp_arg & ls4) << 4) | ((tmp_arg & rs4) >> 4);
+
+  return {ElementType{tmp_arg}};
+}
+
 }  // namespace berberis::intrinsics
 
 #endif  // BERBERIS_INTRINSICS_INTRINSICS_BITMANIP_IMPL_H_
diff --git a/intrinsics/include/berberis/intrinsics/intrinsics_process_bindings.h b/intrinsics/include/berberis/intrinsics/intrinsics_process_bindings.h
index cb855f57..4341f63d 100644
--- a/intrinsics/include/berberis/intrinsics/intrinsics_process_bindings.h
+++ b/intrinsics/include/berberis/intrinsics/intrinsics_process_bindings.h
@@ -17,8 +17,6 @@
 #ifndef BERBERIS_INTRINSICS_INTRINSICS_PROCESS_BINDINGS_H_
 #define BERBERIS_INTRINSICS_INTRINSICS_PROCESS_BINDINGS_H_
 
-#include <xmmintrin.h>
-
 #include <cstdint>
 
 #include "berberis/intrinsics/intrinsics_args.h"
diff --git a/intrinsics/include/berberis/intrinsics/simd_register.h b/intrinsics/include/berberis/intrinsics/simd_register.h
index bf77f217..8c0cdfb1 100644
--- a/intrinsics/include/berberis/intrinsics/simd_register.h
+++ b/intrinsics/include/berberis/intrinsics/simd_register.h
@@ -17,12 +17,9 @@
 #ifndef BERBERIS_INTRINSICS_SIMD_REGISTER_H_
 #define BERBERIS_INTRINSICS_SIMD_REGISTER_H_
 
-#if defined(__i386__) || defined(__x86_64__)
-#include "xmmintrin.h"
-#endif
-
-#include <stdint.h>
-#include <string.h>
+#include <cstdint>
+#include <cstring>
+#include <tuple>
 
 #include "berberis/base/bit_util.h"
 #include "berberis/intrinsics/common/intrinsics_float.h"
@@ -47,6 +44,27 @@ constexpr T SIMD128RegisterSet(SIMD128Register* reg, T elem, int index) = delete
 [[nodiscard]] constexpr SIMD128Register operator^(SIMD128Register lhs, SIMD128Register rhs);
 [[nodiscard]] constexpr SIMD128Register operator~(SIMD128Register lhs);
 
+#if defined(__GNUC__)
+using Int8x16 = char __attribute__((__vector_size__(16), may_alias));
+using UInt8x16 = unsigned char __attribute__((__vector_size__(16), may_alias));
+using Int16x8 = short __attribute__((__vector_size__(16), may_alias));
+using UInt16x8 = unsigned short __attribute__((__vector_size__(16), may_alias));
+using Int32x4 = int __attribute__((__vector_size__(16), may_alias));
+using UInt32x4 = unsigned int __attribute__((__vector_size__(16), may_alias));
+using UInt64x2 = unsigned long long __attribute__((__vector_size__(16), may_alias));
+using Float64x2 = double __attribute__((__vector_size__(16), may_alias));
+using Int64x2 = long long __attribute__((__vector_size__(16), __aligned__(16), may_alias));
+using Float32x4 = float __attribute__((__vector_size__(16), __aligned__(16), may_alias));
+
+using UInt8x16Tuple =
+    std::tuple<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
+               uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>;
+using UInt16x8Tuple =
+    std::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t>;
+using UInt32x4Tuple = std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>;
+using UInt64x2Tuple = std::tuple<uint64_t, uint64_t>;
+#endif
+
 class SIMD128Register {
  public:
   // TODO(b/260725458): use explicit(sizeof(T) == 16) instead of three constructors when C++20 would
@@ -58,28 +76,41 @@ class SIMD128Register {
   SIMD128Register() = default;
   SIMD128Register(const SIMD128Register&) = default;
   SIMD128Register(SIMD128Register&&) = default;
-#define SIMD_ARRAY_CONSTRUCTOR(Type, member, kSize)                \
-  constexpr SIMD128Register(const Type(&elem)[kSize]) : member{} { \
-    for (size_t index = 0; index < kSize; ++index) {               \
-      Set(elem[index], index);                                     \
-    }                                                              \
-  }
-  SIMD_ARRAY_CONSTRUCTOR(int8_t, int8, 16)
-  SIMD_ARRAY_CONSTRUCTOR(uint8_t, uint8, 16)
-  SIMD_ARRAY_CONSTRUCTOR(int16_t, int16, 8)
-  SIMD_ARRAY_CONSTRUCTOR(uint16_t, uint16, 8)
-  SIMD_ARRAY_CONSTRUCTOR(int32_t, int32, 4)
-  SIMD_ARRAY_CONSTRUCTOR(uint32_t, uint32, 4)
-  SIMD_ARRAY_CONSTRUCTOR(int64_t, int64, 2)
-  SIMD_ARRAY_CONSTRUCTOR(uint64_t, uint64, 2)
-#undef SIMD_ARRAY_CONSTRUCTOR
+
+  SIMD128Register(UInt8x16Tuple uint8x16_tuple) noexcept
+      : uint8{[&uint8x16_tuple] {
+          auto [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15] =
+              uint8x16_tuple;
+          uint8_t result[16] = {
+              x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15};
+          return std::bit_cast<Int8x16>(result);
+        }()} {}
+  SIMD128Register(UInt16x8Tuple uint16x8_tuple) noexcept
+      : uint8{[&uint16x8_tuple] {
+          auto [x0, x1, x2, x3, x4, x5, x6, x7] = uint16x8_tuple;
+          uint16_t result[8] = {x0, x1, x2, x3, x4, x5, x6, x7};
+          return std::bit_cast<Int16x8>(result);
+        }()} {}
+  SIMD128Register(UInt32x4Tuple uint32x4_tuple) noexcept
+      : uint8{[&uint32x4_tuple] {
+          auto [x0, x1, x2, x3] = uint32x4_tuple;
+          uint32_t result[4] = {x0, x1, x2, x3};
+          return std::bit_cast<Int32x4>(result);
+        }()} {}
+  SIMD128Register(UInt64x2Tuple uint64x2_tuple) noexcept
+      : uint8{[&uint64x2_tuple] {
+          auto [x0, x1] = uint64x2_tuple;
+          uint64_t result[2] = {x0, x1};
+          return std::bit_cast<Int64x2>(result);
+        }()} {}
+
   SIMD128Register& operator=(const SIMD128Register&) = default;
   SIMD128Register& operator=(SIMD128Register&&) = default;
   // Note that all other constructos are not constexpr because they not compatible with notion of
   // “active union member”.
   // Attribute gnu::may_alias prevents UB at runtime, but doesn't make it possible to make “active
   // union member” diffused in constexpr.
-#if defined(__x86_64__)
+#if defined(__LP64__)
   constexpr SIMD128Register(__int128_t elem) : int128{(elem)} {}
   constexpr SIMD128Register(Int128 elem) : int128{(elem.value)} {}
   constexpr SIMD128Register(SatInt128 elem) : int128{(elem.value)} {}
@@ -87,22 +118,33 @@ class SIMD128Register {
   constexpr SIMD128Register(UInt128 elem) : uint128{(elem.value)} {}
   constexpr SIMD128Register(SatUInt128 elem) : uint128{(elem.value)} {}
 #endif
-#if defined(__i386__) || defined(__x86_64__)
+#if defined(__GNUC__)
   // Note: we couldn't use elem's below to directly initialize SIMD128Register (even if it works
   // fine with __int128_t and __uint128_t), but Set works correctly if we pick correct “active
   // union member” first.
-  constexpr SIMD128Register(__v16qi elem) : int8{} { Set(elem); }
-  constexpr SIMD128Register(__v16qu elem) : uint8{} { Set(elem); }
-  constexpr SIMD128Register(__v8hi elem) : int16{} { Set(elem); }
-  constexpr SIMD128Register(__v8hu elem) : uint16{} { Set(elem); }
-  constexpr SIMD128Register(__v4si elem) : int32{} { Set(elem); }
-  constexpr SIMD128Register(__v4su elem) : uint32{} { Set(elem); }
-  constexpr SIMD128Register(__v2du elem) : uint64{} { Set(elem); }
-  constexpr SIMD128Register(__v2df elem) : float64{} { Set(elem); }
-  constexpr SIMD128Register(__m128i elem) : int64{} { Set(elem); }
-  constexpr SIMD128Register(__m128 elem) : float32{} { Set(elem); }
+  constexpr SIMD128Register(Int8x16 elem) : int8{} { Set(elem); }
+  constexpr SIMD128Register(UInt8x16 elem) : uint8{} { Set(elem); }
+  constexpr SIMD128Register(Int16x8 elem) : int16{} { Set(elem); }
+  constexpr SIMD128Register(UInt16x8 elem) : uint16{} { Set(elem); }
+  constexpr SIMD128Register(Int32x4 elem) : int32{} { Set(elem); }
+  constexpr SIMD128Register(UInt32x4 elem) : uint32{} { Set(elem); }
+  constexpr SIMD128Register(UInt64x2 elem) : uint64{} { Set(elem); }
+  constexpr SIMD128Register(Float64x2 elem) : float64{} { Set(elem); }
+  constexpr SIMD128Register(Int64x2 elem) : int64{} { Set(elem); }
+  constexpr SIMD128Register(Float32x4 elem) : float32{} { Set(elem); }
 #endif
 
+  // Generates optimal assembly for x86 and riscv.
+  template <typename T>
+  static bool compareVectors(T x, T y) {
+    T res = x == y;
+    bool result = true;
+    for (int i = 0; i < int{sizeof(SIMD128Register) / sizeof(T)}; ++i) {
+      result &= res[i];
+    }
+    return result;
+  }
+
   template <typename T>
   [[nodiscard]] constexpr auto Get(int index) const
       -> std::enable_if_t<sizeof(T) < 16, std::decay_t<T>> {
@@ -136,9 +178,7 @@ class SIMD128Register {
     // Note comparison of two vectors return vector of the same type. In such a case we need to
     // merge many bools that we got.
     if constexpr (sizeof(decltype(lhs == rhs.template Get<T>())) == sizeof(SIMD128Register)) {
-      // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
-      // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
-      return _mm_movemask_epi8(lhs == rhs.template Get<T>()) == 0xffff;
+      return compareVectors(lhs, rhs.template Get<T>());
     } else {
       return lhs == rhs.Get<T>();
     }
@@ -148,9 +188,7 @@ class SIMD128Register {
     // Note comparison of two vectors return vector of the same type. In such a case we need to
     // merge many bools that we got.
     if constexpr (sizeof(decltype(lhs != rhs.template Get<T>())) == sizeof(SIMD128Register)) {
-      // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
-      // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
-      return _mm_movemask_epi8(lhs == rhs.template Get<T>()) != 0xffff;
+      return !compareVectors(lhs, rhs.template Get<T>());
     } else {
       return lhs != rhs.Get<T>();
     }
@@ -162,7 +200,7 @@ class SIMD128Register {
     if constexpr (sizeof(decltype(lhs.template Get<T>() == rhs)) == sizeof(SIMD128Register)) {
       // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
       // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
-      return _mm_movemask_epi8(lhs.template Get<T>() == rhs) == 0xffff;
+      return compareVectors(lhs.template Get<T>(), rhs);
     } else {
       return lhs.Get<T>() == rhs;
     }
@@ -174,12 +212,12 @@ class SIMD128Register {
     if constexpr (sizeof(decltype(lhs.template Get<T>() == rhs)) == sizeof(SIMD128Register)) {
       // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
       // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
-      return _mm_movemask_epi8(lhs.template Get<T>() == rhs) != 0xffff;
+      return !compareVectors(lhs.template Get<T>(), rhs);
     } else {
       return lhs.Get<T>() != rhs;
     }
   }
-#if defined(__i386__) || defined(__x86_64__)
+#if defined(__GNUC__)
   friend constexpr bool operator==(SIMD128Register lhs, SIMD128Register rhs);
   friend constexpr bool operator!=(SIMD128Register lhs, SIMD128Register rhs);
   friend constexpr SIMD128Register operator&(SIMD128Register lhs, SIMD128Register rhs);
@@ -205,7 +243,7 @@ class SIMD128Register {
     [[gnu::vector_size(16), gnu::may_alias]] uint32_t uint32;
     [[gnu::vector_size(16), gnu::may_alias]] int64_t int64;
     [[gnu::vector_size(16), gnu::may_alias]] uint64_t uint64;
-#if defined(__x86_64__)
+#if defined(__LP64__)
     [[gnu::vector_size(16), gnu::may_alias]] __int128_t int128;
     [[gnu::vector_size(16), gnu::may_alias]] __uint128_t uint128;
 #endif
@@ -229,6 +267,8 @@ static_assert(sizeof(SIMD128Register) == 16, "Unexpected size of SIMD128Register
 static_assert(alignof(SIMD128Register) == 16, "Unexpected align of SIMD128Register");
 #elif defined(__x86_64__)
 static_assert(alignof(SIMD128Register) == 16, "Unexpected align of SIMD128Register");
+#elif defined(__riscv)
+static_assert(alignof(SIMD128Register) == 16, "Unexpected align of SIMD128Register");
 #else
 #error Unsupported architecture
 #endif
@@ -331,7 +371,7 @@ SIMD_128_SAFEINT_REGISTER_GETTER_SETTER(SatInt64, int64);
 SIMD_128_STDINT_REGISTER_GETTER_SETTER(uint64_t, uint64);
 SIMD_128_SAFEINT_REGISTER_GETTER_SETTER(UInt64, uint64);
 SIMD_128_SAFEINT_REGISTER_GETTER_SETTER(SatUInt64, uint64);
-#if defined(__x86_64__)
+#if defined(__LP64__)
 SIMD_128_STDINT_REGISTER_GETTER_SETTER(__int128_t, int128);
 SIMD_128_SAFEINT_REGISTER_GETTER_SETTER(RawInt128, uint128);
 SIMD_128_SAFEINT_REGISTER_GETTER_SETTER(Int128, int128);
@@ -340,17 +380,17 @@ SIMD_128_STDINT_REGISTER_GETTER_SETTER(__uint128_t, uint128);
 SIMD_128_SAFEINT_REGISTER_GETTER_SETTER(UInt128, uint128);
 SIMD_128_SAFEINT_REGISTER_GETTER_SETTER(SatUInt128, uint128);
 #endif
-#if defined(__i386__) || defined(__x86_64__)
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__v16qi, int8);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__v16qu, uint8);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__v8hi, int16);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__v8hu, uint16);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__v4si, int32);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__v4su, uint32);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__v2du, uint64);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__v2df, float64);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__m128i, int64);
-SIMD_128_FULL_REGISTER_GETTER_SETTER(__m128, float32);
+#if defined(__GNUC__)
+SIMD_128_FULL_REGISTER_GETTER_SETTER(Int8x16, int8);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(UInt8x16, uint8);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(Int16x8, int16);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(UInt16x8, uint16);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(Int32x4, int32);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(UInt32x4, uint32);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(UInt64x2, uint64);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(Float64x2, float64);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(Int64x2, int64);
+SIMD_128_FULL_REGISTER_GETTER_SETTER(Float32x4, float32);
 #endif
 SIMD_128_FLOAT_REGISTER_GETTER_SETTER(intrinsics::Float32, float, float32);
 SIMD_128_FLOAT_REGISTER_GETTER_SETTER(intrinsics::Float64, double, float64);
@@ -359,32 +399,32 @@ SIMD_128_FLOAT_REGISTER_GETTER_SETTER(intrinsics::Float64, double, float64);
 #undef SIMD_128_SAFEINT_REGISTER_GETTER_SETTER
 #undef SIMD_128_STDINT_REGISTER_GETTER_SETTER
 
-#if defined(__i386__) || defined(__x86_64__)
+#if defined(__GNUC__)
 [[nodiscard]] constexpr bool operator==(SIMD128Register lhs, SIMD128Register rhs) {
   // Note comparison of two vectors return vector of the same type. In such a case we need to
   // merge many bools that we got.
   // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
   // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
-  return _mm_movemask_epi8(lhs.Get<__m128i>() == rhs.Get<__m128i>()) == 0xffff;
+  return SIMD128Register::compareVectors(lhs.Get<Int64x2>(), rhs.Get<Int64x2>());
 }
 [[nodiscard]] constexpr bool operator!=(SIMD128Register lhs, SIMD128Register rhs) {
   // Note comparison of two vectors return vector of the same type. In such a case we need to
   // merge many bools that we got.
   // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
   // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
-  return _mm_movemask_epi8(lhs.Get<__m128i>() == rhs.Get<__m128i>()) != 0xffff;
+  return !SIMD128Register::compareVectors(lhs.Get<Int64x2>(), rhs.Get<Int64x2>());
 }
 [[nodiscard]] constexpr SIMD128Register operator&(SIMD128Register lhs, SIMD128Register rhs) {
-  return lhs.Get<__m128i>() & rhs.Get<__m128i>();
+  return lhs.Get<Int64x2>() & rhs.Get<Int64x2>();
 }
 [[nodiscard]] constexpr SIMD128Register operator|(SIMD128Register lhs, SIMD128Register rhs) {
-  return lhs.Get<__m128i>() | rhs.Get<__m128i>();
+  return lhs.Get<Int64x2>() | rhs.Get<Int64x2>();
 }
 [[nodiscard]] constexpr SIMD128Register operator^(SIMD128Register lhs, SIMD128Register rhs) {
-  return lhs.Get<__m128i>() ^ rhs.Get<__m128i>();
+  return lhs.Get<Int64x2>() ^ rhs.Get<Int64x2>();
 }
 [[nodiscard]] constexpr SIMD128Register operator~(SIMD128Register lhs) {
-  return ~lhs.Get<__m128i>();
+  return ~lhs.Get<Int64x2>();
 }
 #endif
 
diff --git a/intrinsics/include/berberis/intrinsics/type_traits.h b/intrinsics/include/berberis/intrinsics/type_traits.h
index b5ac41fb..5f4241f1 100644
--- a/intrinsics/include/berberis/intrinsics/type_traits.h
+++ b/intrinsics/include/berberis/intrinsics/type_traits.h
@@ -17,10 +17,6 @@
 #ifndef BERBERIS_INTRINSICS_TYPE_TRAITS_H_
 #define BERBERIS_INTRINSICS_TYPE_TRAITS_H_
 
-#if defined(__i386__) || defined(__x86_64__)
-#include <xmmintrin.h>
-#endif
-
 #include <cstdint>
 
 #include "berberis/intrinsics/common/intrinsics_float.h"
@@ -60,7 +56,7 @@ struct TypeTraits<uint32_t> {
 template <>
 struct TypeTraits<uint64_t> {
   using Narrow = uint32_t;
-#if defined(__x86_64__)
+#if defined(__LP64__)
   using Wide = __uint128_t;
 #endif
   using Float = intrinsics::Float64;
@@ -95,7 +91,7 @@ struct TypeTraits<int32_t> {
 template <>
 struct TypeTraits<int64_t> {
   using Narrow = int32_t;
-#if defined(__x86_64__)
+#if defined(__LP64__)
   using Wide = __int128_t;
 #endif
   using Float = intrinsics::Float64;
@@ -137,7 +133,7 @@ struct TypeTraits<intrinsics::Float64> {
   using Int = int64_t;
   using Raw = double;
   using Narrow = intrinsics::Float32;
-#if defined(__x86_64__)
+#if defined(__LP64__)
   static_assert(sizeof(long double) > sizeof(intrinsics::Float64));
   using Wide = long double;
 #endif
@@ -158,7 +154,7 @@ template <>
 struct TypeTraits<double> {
   using Int = int64_t;
   using Wrapped = intrinsics::Float64;
-#if defined(__x86_64__)
+#if defined(__LP64__)
   static_assert(sizeof(long double) > sizeof(intrinsics::Float64));
   using Wide = long double;
 #endif
@@ -169,13 +165,13 @@ struct TypeTraits<double> {
 
 template <>
 struct TypeTraits<SIMD128Register> {
-#if defined(__i386__) || defined(__x86_64__)
-  using Raw = __m128;
+#if defined(__GNUC__)
+  using Raw = Float32x4;
 #endif
   static constexpr char kName[] = "SIMD128Register";
 };
 
-#if defined(__x86_64__)
+#if defined(__LP64__)
 
 template <>
 struct TypeTraits<long double> {
@@ -199,16 +195,12 @@ struct TypeTraits<__uint128_t> {
 
 #endif
 
-#if defined(__i386__) || defined(__x86_64__)
-
 template <>
-struct TypeTraits<__m128> {
+struct TypeTraits<Float32x4> {
   static constexpr int kBits = 128;
   static constexpr char kName[] = "__m128";
 };
 
-#endif
-
 }  // namespace berberis
 
 #endif  // BERBERIS_INTRINSICS_TYPE_TRAITS_H_
diff --git a/intrinsics/riscv64/include/berberis/intrinsics/guest_cpu_flags.h b/intrinsics/riscv64_to_all/include/berberis/intrinsics/guest_cpu_flags.h
similarity index 100%
rename from intrinsics/riscv64/include/berberis/intrinsics/guest_cpu_flags.h
rename to intrinsics/riscv64_to_all/include/berberis/intrinsics/guest_cpu_flags.h
diff --git a/intrinsics/riscv64/include/berberis/intrinsics/riscv64/intrinsics.h b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/intrinsics.h
similarity index 80%
rename from intrinsics/riscv64/include/berberis/intrinsics/riscv64/intrinsics.h
rename to intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/intrinsics.h
index ad305983..f9565ebc 100644
--- a/intrinsics/riscv64/include/berberis/intrinsics/riscv64/intrinsics.h
+++ b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/intrinsics.h
@@ -14,27 +14,37 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_INTRINSICS_RISCV64_INTRINSICS_H_
-#define BERBERIS_INTRINSICS_RISCV64_INTRINSICS_H_
+#ifndef BERBERIS_INTRINSICS_RISCV64_TO_ALL_INTRINSICS_H_
+#define BERBERIS_INTRINSICS_RISCV64_TO_ALL_INTRINSICS_H_
 
+#include <cstdint>
 #include <limits>
 #include <tuple>
 #include <type_traits>
 
-#include "berberis/base/bit_util.h"
 #include "berberis/intrinsics/common/intrinsics.h"
+
+#if !defined(__aarch64__)
+#include "berberis/base/bit_util.h"
 #include "berberis/intrinsics/intrinsics_float.h"  // Float32/Float64/ProcessNans
 #include "berberis/intrinsics/type_traits.h"
+#endif
 
 namespace berberis::intrinsics {
 
+#if defined(__aarch64__)
+using Float64 = double;
+#endif
+
 #include "berberis/intrinsics/intrinsics-inl.h"  // NOLINT: generated file!
 
 }  // namespace berberis::intrinsics
 
 #include "berberis/intrinsics/intrinsics_atomics_impl.h"
+#if !defined(__aarch64__)
 #include "berberis/intrinsics/intrinsics_bitmanip_impl.h"
 #include "berberis/intrinsics/intrinsics_fixed_point_impl.h"
 #include "berberis/intrinsics/intrinsics_floating_point_impl.h"
+#endif
 
-#endif  // BERBERIS_INTRINSICS_RISCV64_INTRINSICS_H_
+#endif  // BERBERIS_INTRINSICS_RISCV64_TO_ALL_INTRINSICS_H_
diff --git a/intrinsics/riscv64/include/berberis/intrinsics/riscv64/vector_intrinsics.h b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
similarity index 97%
rename from intrinsics/riscv64/include/berberis/intrinsics/riscv64/vector_intrinsics.h
rename to intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
index 31dde0d8..b9cf29e3 100644
--- a/intrinsics/riscv64/include/berberis/intrinsics/riscv64/vector_intrinsics.h
+++ b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_INTRINSICS_RISCV64_VECTOR_INTRINSICS_H_
-#define BERBERIS_INTRINSICS_RISCV64_VECTOR_INTRINSICS_H_
+#ifndef BERBERIS_INTRINSICS_RISCV64_TO_ALL_VECTOR_INTRINSICS_H_
+#define BERBERIS_INTRINSICS_RISCV64_TO_ALL_VECTOR_INTRINSICS_H_
 
 #include <algorithm>
 #include <climits>  // CHAR_BIT
@@ -187,6 +187,15 @@ template <typename ElementType>
 }
 #endif
 
+// For instructions that operate on carry bits, expands single bit from mask register
+//     into vector argument
+template <typename ElementType, TailProcessing vta, auto vma>
+std::tuple<SIMD128Register> GetMaskVectorArgument(SIMD128Register mask, size_t index) {
+  using MaskType = std::conditional_t<sizeof(ElementType) == sizeof(Int8), UInt16, UInt8>;
+  auto register_mask = std::get<0>(MaskForRegisterInSequence<ElementType>(mask, index));
+  return BitMaskToSimdMaskForTests<ElementType>(Int64{MaskType{register_mask}});
+}
+
 template <typename ElementType>
 [[nodiscard]] inline ElementType VectorElement(SIMD128Register src, int index) {
   return src.Get<ElementType>(index);
@@ -425,7 +434,8 @@ template <typename ElementType, TailProcessing vta, InactiveProcessing vma, type
 template <typename ElementType, typename... ParameterType>
 inline constexpr bool kIsAllowedArgumentForVector =
     ((std::is_same_v<ParameterType, SIMD128Register> ||
-      std::is_same_v<ParameterType, ElementType>)&&...);
+      std::is_same_v<ParameterType, ElementType>) &&
+     ...);
 
 // TODO(b/260725458): Pass lambda as template argument after C++20 would become available.
 template <typename ElementType, typename Lambda, typename... ParameterType>
@@ -449,7 +459,11 @@ inline std::tuple<ResultType> VectorProcessingReduce(Lambda lambda,
   static_assert(kIsAllowedArgumentForVector<ElementType, ParameterType...>);
   constexpr size_t kElementsCount = sizeof(SIMD128Register) / sizeof(ElementType);
   for (size_t index = 0; index < kElementsCount; ++index) {
-    init = lambda(init, VectorElement<ElementType>(parameters, index)...);
+    if constexpr (std::is_same_v<ResultType, WideType<ElementType>>) {
+      init = lambda(init, Widen(VectorElement<ElementType>(parameters, index)...));
+    } else {
+      init = lambda(init, VectorElement<ElementType>(parameters, index)...);
+    }
   }
   return init;
 }
@@ -817,7 +831,7 @@ std::tuple<ElementType> WideMultiplySignedUnsigned(ElementType arg1, ElementType
   inline std::tuple<ResultType> Name(DEFINE_ARITHMETIC_PARAMETERS_OR_ARGUMENTS parameters) { \
     return VectorProcessingReduce<ElementType>(                                              \
         [DEFINE_ARITHMETIC_PARAMETERS_OR_ARGUMENTS capture](auto... args) {                  \
-          static_assert((std::is_same_v<decltype(args), ElementType> && ...));               \
+          static_assert((std::is_same_v<decltype(args), ResultType> && ...));                \
           arithmetic;                                                                        \
         },                                                                                   \
         DEFINE_ARITHMETIC_PARAMETERS_OR_ARGUMENTS arguments);                                \
@@ -937,6 +951,7 @@ std::tuple<ElementType> WideMultiplySignedUnsigned(ElementType arg1, ElementType
 
 DEFINE_1OP_ARITHMETIC_INTRINSIC_V(copy, auto [arg] = std::tuple{args...}; arg)
 DEFINE_1OP_ARITHMETIC_INTRINSIC_X(copy, auto [arg] = std::tuple{args...}; arg)
+DEFINE_1OP_ARITHMETIC_INTRINSIC_V(brev8, std::get<0>((Brev8(args...))))
 DEFINE_1OP_ARITHMETIC_INTRINSIC_V(frsqrt7, RSqrtEstimate(args...))
 DEFINE_1OP_ARITHMETIC_INTRINSIC_V(
     fclass,
@@ -1082,6 +1097,14 @@ DEFINE_2OP_ARITHMETIC_INTRINSIC_VX(fgt, auto [arg1, arg2] = std::tuple{args...};
 DEFINE_2OP_ARITHMETIC_INTRINSIC_VX(fge, auto [arg1, arg2] = std::tuple{args...};
                                    using IntType = typename TypeTraits<ElementType>::Int;
                                    (~IntType{0}) * IntType(std::get<0>(Fle(arg2, arg1))))
+DEFINE_3OP_ARITHMETIC_INTRINSIC_VX(adc, auto [arg1, arg2, arg3] = std::tuple{args...};
+                                   (arg2 + arg1 - arg3))
+DEFINE_3OP_ARITHMETIC_INTRINSIC_VV(adc, auto [arg1, arg2, arg3] = std::tuple{args...};
+                                   (arg2 + arg1 - arg3))
+DEFINE_3OP_ARITHMETIC_INTRINSIC_VX(sbc, auto [arg1, arg2, arg3] = std::tuple{args...};
+                                   (arg2 - arg1 + arg3))
+DEFINE_3OP_ARITHMETIC_INTRINSIC_VV(sbc, auto [arg1, arg2, arg3] = std::tuple{args...};
+                                   (arg2 - arg1 + arg3))
 DEFINE_2OP_ARITHMETIC_INTRINSIC_VV(
     seq,
     (~ElementType{0}) * ElementType{static_cast<typename ElementType::BaseType>((args == ...))})
@@ -1302,4 +1325,4 @@ DEFINE_2OP_1CSR_NARROW_ARITHMETIC_INTRINSIC_WX(
 
 }  // namespace berberis::intrinsics
 
-#endif  // BERBERIS_INTRINSICS_RISCV64_VECTOR_INTRINSICS_H_
+#endif  // BERBERIS_INTRINSICS_RISCV64_TO_ALL_VECTOR_INTRINSICS_H_
diff --git a/intrinsics/riscv64_to_x86_64/intrinsic_def.json b/intrinsics/riscv64_to_all/intrinsic_def.json
similarity index 99%
rename from intrinsics/riscv64_to_x86_64/intrinsic_def.json
rename to intrinsics/riscv64_to_all/intrinsic_def.json
index 9102efeb..6939f09d 100644
--- a/intrinsics/riscv64_to_x86_64/intrinsic_def.json
+++ b/intrinsics/riscv64_to_all/intrinsic_def.json
@@ -796,10 +796,11 @@
     "in": [ "uint8_t", "uint64_t", "uimm16" ],
     "out": [ "uint64_t", "uint64_t" ]
   },
-  "Zexth": {
-    "comment": "Zero-extend half word",
-    "class": "scalar",
-    "in": [ "int16_t" ],
-    "out": [ "int64_t" ]
+  "Zext": {
+    "comment": "Zero-extend to 64 bit",
+    "class": "template",
+    "variants": [ "uint8_t", "uint16_t", "uint32_t" ],
+    "in": [ "Type0" ],
+    "out": [ "uint64_t" ]
   }
 }
diff --git a/intrinsics/riscv64/intrinsics.cc b/intrinsics/riscv64_to_all/intrinsics.cc
similarity index 100%
rename from intrinsics/riscv64/intrinsics.cc
rename to intrinsics/riscv64_to_all/intrinsics.cc
diff --git a/intrinsics/riscv64/intrinsics_test.cc b/intrinsics/riscv64_to_all/intrinsics_test.cc
similarity index 100%
rename from intrinsics/riscv64/intrinsics_test.cc
rename to intrinsics/riscv64_to_all/intrinsics_test.cc
diff --git a/intrinsics/riscv64/vector_intrinsics.cc b/intrinsics/riscv64_to_all/vector_intrinsics.cc
similarity index 100%
rename from intrinsics/riscv64/vector_intrinsics.cc
rename to intrinsics/riscv64_to_all/vector_intrinsics.cc
diff --git a/intrinsics/riscv64/vector_intrinsics_test.cc b/intrinsics/riscv64_to_all/vector_intrinsics_test.cc
similarity index 86%
rename from intrinsics/riscv64/vector_intrinsics_test.cc
rename to intrinsics/riscv64_to_all/vector_intrinsics_test.cc
index 67386851..fecaa3fa 100644
--- a/intrinsics/riscv64/vector_intrinsics_test.cc
+++ b/intrinsics/riscv64_to_all/vector_intrinsics_test.cc
@@ -393,55 +393,53 @@ TEST(VectorIntrinsics, VlArgForVx) {
 }
 
 TEST(VectorIntrinsics, VmaskArgForVvv) {
-  auto Verify = []<typename ElementType>(
-                    auto Vaddvv,
-                    SIMD128Register arg2,
-                    [[gnu::vector_size(16),
-                      gnu::may_alias]] ElementType result_to_check_agnostic_agnostic,
-                    [[gnu::vector_size(16),
-                      gnu::may_alias]] ElementType result_to_check_agnostic_undisturbed,
-                    [[gnu::vector_size(16),
-                      gnu::may_alias]] ElementType result_to_check_undisturbed_agnostic,
-                    [[gnu::vector_size(16),
-                      gnu::may_alias]] ElementType result_to_check_undisturbed_undisturbed) {
-    constexpr size_t kHalfLen = sizeof(SIMD128Register) / sizeof(ElementType) / 2;
-    ASSERT_EQ(
-        (VectorMasking<Wrapping<ElementType>,
-                       TailProcessing::kAgnostic,
-                       InactiveProcessing::kAgnostic>(kUndisturbedResult,
-                                                      std::get<0>(Vaddvv(__m128i{-1, -1}, arg2)),
-                                                      0,
-                                                      kHalfLen,
-                                                      RawInt16{0xfdda})),
-        std::tuple{result_to_check_agnostic_agnostic});
-    ASSERT_EQ(
-        (VectorMasking<Wrapping<ElementType>,
-                       TailProcessing::kAgnostic,
-                       InactiveProcessing::kUndisturbed>(kUndisturbedResult,
-                                                         std::get<0>(Vaddvv(__m128i{-1, -1}, arg2)),
-                                                         0,
-                                                         kHalfLen,
-                                                         RawInt16{0xfdda})),
-        std::tuple{result_to_check_agnostic_undisturbed});
-    ASSERT_EQ(
-        (VectorMasking<Wrapping<ElementType>,
-                       TailProcessing::kUndisturbed,
-                       InactiveProcessing::kAgnostic>(kUndisturbedResult,
-                                                      std::get<0>(Vaddvv(__m128i{-1, -1}, arg2)),
-                                                      0,
-                                                      kHalfLen,
-                                                      RawInt16{0xfdda})),
-        std::tuple{result_to_check_undisturbed_agnostic});
-    ASSERT_EQ(
-        (VectorMasking<Wrapping<ElementType>,
-                       TailProcessing::kUndisturbed,
-                       InactiveProcessing::kUndisturbed>(kUndisturbedResult,
-                                                         std::get<0>(Vaddvv(__m128i{-1, -1}, arg2)),
-                                                         0,
-                                                         kHalfLen,
-                                                         RawInt16{0xfdda})),
-        std::tuple{result_to_check_undisturbed_undisturbed});
-  };
+  auto Verify =
+      []<typename ElementType>(
+          auto Vaddvv,
+          SIMD128Register arg2,
+          [[gnu::vector_size(16), gnu::may_alias]] ElementType result_to_check_agnostic_agnostic,
+          [[gnu::vector_size(16), gnu::may_alias]] ElementType result_to_check_agnostic_undisturbed,
+          [[gnu::vector_size(16), gnu::may_alias]] ElementType result_to_check_undisturbed_agnostic,
+          [[gnu::vector_size(16),
+            gnu::may_alias]] ElementType result_to_check_undisturbed_undisturbed) {
+        constexpr size_t kHalfLen = sizeof(SIMD128Register) / sizeof(ElementType) / 2;
+        ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
+                                 TailProcessing::kAgnostic,
+                                 InactiveProcessing::kAgnostic>(
+                      kUndisturbedResult,
+                      std::get<0>(Vaddvv(__m128i{-1, -1}, arg2)),
+                      0,
+                      kHalfLen,
+                      RawInt16{0xfdda})),
+                  std::tuple{result_to_check_agnostic_agnostic});
+        ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
+                                 TailProcessing::kAgnostic,
+                                 InactiveProcessing::kUndisturbed>(
+                      kUndisturbedResult,
+                      std::get<0>(Vaddvv(__m128i{-1, -1}, arg2)),
+                      0,
+                      kHalfLen,
+                      RawInt16{0xfdda})),
+                  std::tuple{result_to_check_agnostic_undisturbed});
+        ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
+                                 TailProcessing::kUndisturbed,
+                                 InactiveProcessing::kAgnostic>(
+                      kUndisturbedResult,
+                      std::get<0>(Vaddvv(__m128i{-1, -1}, arg2)),
+                      0,
+                      kHalfLen,
+                      RawInt16{0xfdda})),
+                  std::tuple{result_to_check_undisturbed_agnostic});
+        ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
+                                 TailProcessing::kUndisturbed,
+                                 InactiveProcessing::kUndisturbed>(
+                      kUndisturbedResult,
+                      std::get<0>(Vaddvv(__m128i{-1, -1}, arg2)),
+                      0,
+                      kHalfLen,
+                      RawInt16{0xfdda})),
+                  std::tuple{result_to_check_undisturbed_undisturbed});
+      };
   Verify(
       Vaddvv<UInt8>,
       __v16qu{0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1},
@@ -496,51 +494,51 @@ TEST(VectorIntrinsics, VmaskArgForVvv) {
 }
 
 TEST(VectorIntrinsics, VmaskArgForVvx) {
-  auto Verify = []<typename ElementType>(
-                    auto Vaddvx,
-                    SIMD128Register arg1,
-                    [[gnu::vector_size(16),
-                      gnu::may_alias]] ElementType result_to_check_agnostic_agnostic,
-                    [[gnu::vector_size(16),
-                      gnu::may_alias]] ElementType result_to_check_agnostic_undisturbed,
-                    [[gnu::vector_size(16),
-                      gnu::may_alias]] ElementType result_to_check_undisturbed_agnostic,
-                    [[gnu::vector_size(16),
-                      gnu::may_alias]] ElementType result_to_check_undisturbed_undisturbed) {
-    constexpr size_t kHalfLen = sizeof(SIMD128Register) / sizeof(ElementType) / 2;
-    ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
-                             TailProcessing::kAgnostic,
-                             InactiveProcessing::kAgnostic>(kUndisturbedResult,
-                                                            std::get<0>(Vaddvx(arg1, UInt8{1})),
-                                                            0,
-                                                            kHalfLen,
-                                                            RawInt16{0xfdda})),
-              std::tuple{result_to_check_agnostic_agnostic});
-    ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
-                             TailProcessing::kAgnostic,
-                             InactiveProcessing::kUndisturbed>(kUndisturbedResult,
-                                                               std::get<0>(Vaddvx(arg1, UInt8{1})),
-                                                               0,
-                                                               kHalfLen,
-                                                               RawInt16{0xfdda})),
-              std::tuple{result_to_check_agnostic_undisturbed});
-    ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
-                             TailProcessing::kUndisturbed,
-                             InactiveProcessing::kAgnostic>(kUndisturbedResult,
-                                                            std::get<0>(Vaddvx(arg1, UInt8{1})),
-                                                            0,
-                                                            kHalfLen,
-                                                            RawInt16{0xfdda})),
-              std::tuple{result_to_check_undisturbed_agnostic});
-    ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
-                             TailProcessing::kUndisturbed,
-                             InactiveProcessing::kUndisturbed>(kUndisturbedResult,
-                                                               std::get<0>(Vaddvx(arg1, UInt8{1})),
-                                                               0,
-                                                               kHalfLen,
-                                                               RawInt16{0xfdda})),
-              std::tuple{result_to_check_undisturbed_undisturbed});
-  };
+  auto Verify =
+      []<typename ElementType>(
+          auto Vaddvx,
+          SIMD128Register arg1,
+          [[gnu::vector_size(16), gnu::may_alias]] ElementType result_to_check_agnostic_agnostic,
+          [[gnu::vector_size(16), gnu::may_alias]] ElementType result_to_check_agnostic_undisturbed,
+          [[gnu::vector_size(16), gnu::may_alias]] ElementType result_to_check_undisturbed_agnostic,
+          [[gnu::vector_size(16),
+            gnu::may_alias]] ElementType result_to_check_undisturbed_undisturbed) {
+        constexpr size_t kHalfLen = sizeof(SIMD128Register) / sizeof(ElementType) / 2;
+        ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
+                                 TailProcessing::kAgnostic,
+                                 InactiveProcessing::kAgnostic>(kUndisturbedResult,
+                                                                std::get<0>(Vaddvx(arg1, UInt8{1})),
+                                                                0,
+                                                                kHalfLen,
+                                                                RawInt16{0xfdda})),
+                  std::tuple{result_to_check_agnostic_agnostic});
+        ASSERT_EQ(
+            (VectorMasking<Wrapping<ElementType>,
+                           TailProcessing::kAgnostic,
+                           InactiveProcessing::kUndisturbed>(kUndisturbedResult,
+                                                             std::get<0>(Vaddvx(arg1, UInt8{1})),
+                                                             0,
+                                                             kHalfLen,
+                                                             RawInt16{0xfdda})),
+            std::tuple{result_to_check_agnostic_undisturbed});
+        ASSERT_EQ((VectorMasking<Wrapping<ElementType>,
+                                 TailProcessing::kUndisturbed,
+                                 InactiveProcessing::kAgnostic>(kUndisturbedResult,
+                                                                std::get<0>(Vaddvx(arg1, UInt8{1})),
+                                                                0,
+                                                                kHalfLen,
+                                                                RawInt16{0xfdda})),
+                  std::tuple{result_to_check_undisturbed_agnostic});
+        ASSERT_EQ(
+            (VectorMasking<Wrapping<ElementType>,
+                           TailProcessing::kUndisturbed,
+                           InactiveProcessing::kUndisturbed>(kUndisturbedResult,
+                                                             std::get<0>(Vaddvx(arg1, UInt8{1})),
+                                                             0,
+                                                             kHalfLen,
+                                                             RawInt16{0xfdda})),
+            std::tuple{result_to_check_undisturbed_undisturbed});
+      };
   Verify(
       Vaddvx<UInt8>,
       __v16qu{254, 255, 254, 255, 254, 255, 254, 255, 254, 255, 254, 255, 254, 255, 254, 255},
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/intrinsics_float.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/intrinsics_float.h
index 05152748..7bcbdf20 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/intrinsics_float.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/intrinsics_float.h
@@ -21,8 +21,8 @@
 #include <limits>
 
 #include "berberis/base/bit_util.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h"
 #include "berberis/intrinsics/common/intrinsics_float.h"
-#include "berberis/intrinsics/common_to_x86/intrinsics_float.h"
 #include "berberis/intrinsics/guest_cpu_flags.h"       // ToHostRoundingMode
 #include "berberis/intrinsics/guest_rounding_modes.h"  // ScopedRoundingMode
 #include "berberis/intrinsics/type_traits.h"
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
index dc4b7809..3035ae0c 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
@@ -24,7 +24,10 @@
 #include <tuple>
 #include <utility>
 
-#include "berberis/intrinsics/intrinsics_float.h"
+// Don't include arch-dependent parts because macro-assembler doesn't depend on implementation of
+// Float32/Float64 types but can be compiled for different architecture (soong's host architecture,
+// not device architecture AKA berberis' host architecture).
+#include "berberis/intrinsics/common/intrinsics_float.h"
 #include "berberis/intrinsics/macro_assembler_constants_pool.h"
 
 namespace berberis {
@@ -32,7 +35,9 @@ namespace berberis {
 template <typename Assembler>
 class MacroAssembler : public Assembler {
  public:
-  using MacroAssemblers = std::tuple<MacroAssembler<Assembler>>;
+  using MacroAssemblers = std::tuple<MacroAssembler<Assembler>,
+                                     typename Assembler::BaseAssembler,
+                                     typename Assembler::FinalAssembler>;
 
   template <typename... Args>
   explicit MacroAssembler(Args&&... args) : Assembler(std::forward<Args>(args)...) {
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_constants_pool.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_constants_pool.h
index a7a20c95..57fcb4f4 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_constants_pool.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_constants_pool.h
@@ -19,13 +19,14 @@
 
 #include <cinttypes>
 
+#include "berberis/base/dependent_false.h"
 #include "berberis/intrinsics/common/intrinsics_float.h"
 
 namespace berberis::constants_pool {
 
 // Vector constants, that is: constants are repeated to fill 128bit SIMD register.
 template <auto Value>
-extern const int32_t kVectorConst;
+inline constexpr int32_t kVectorConst = kImpossibleValueConst<Value>;
 template <>
 extern const int32_t kVectorConst<int8_t{-128}>;
 template <>
@@ -47,6 +48,8 @@ extern const int32_t kVectorConst<int32_t{0x7fff'ffff}>;
 template <>
 extern const int32_t kVectorConst<int64_t{static_cast<int64_t>(-0x8000'0000'0000'0000)}>;
 template <>
+extern const int32_t kVectorConst<int64_t{0x3ff0'0000'0000'0000}>;
+template <>
 extern const int32_t kVectorConst<int64_t{0x7ff0'0000'0000'0000}>;
 template <>
 extern const int32_t kVectorConst<int64_t{0x7fff'ffff'ffff'ffff}>;
@@ -127,7 +130,7 @@ inline const int32_t& kVectorConst<int64_t{-1}> = kVectorConst<uint64_t{0xffff'f
 // 64 bit constants for use with arithmetic operations.
 // Used because only 32 bit immediates are supported on x86-64.
 template <auto Value>
-extern const int32_t kConst;
+inline constexpr int32_t kConst = kImpossibleValueConst<Value>;
 template <>
 extern const int32_t kConst<uint32_t{32}>;
 template <>
@@ -181,21 +184,21 @@ inline const int32_t& kConst<uint64_t{0xffff'ffff'ffff'ffff}> =
 // Constant suitable for NaN boxing of RISC-V 32bit float with PXor.
 // Note: technically we only need to Nan-box Float32 since we don't support Float16 yet.
 template <typename FloatType>
-extern const int32_t kNanBox;
+inline constexpr int32_t kNanBox = kImpossibleTypeConst<FloatType>;
 template <>
 inline const int32_t& kNanBox<intrinsics::Float32> = kVectorConst<uint64_t{0xffff'ffff'0000'0000}>;
 
 // Canonically Nan boxed canonical NaN.
 // Note: technically we only need to Nan-box Float32 since we don't support Float16 yet.
 template <typename FloatType>
-extern const int32_t kNanBoxedNans;
+inline constexpr int32_t kNanBoxedNans = kImpossibleTypeConst<FloatType>;
 template <>
 inline const int32_t& kNanBoxedNans<intrinsics::Float32> =
     kVectorConst<uint64_t{0xffff'ffff'7fc0'0000}>;
 
 // Canonical NaNs. Float32 and Float64 are supported.
 template <typename FloatType>
-extern const int32_t kCanonicalNans;
+inline constexpr int32_t kCanonicalNans = kImpossibleTypeConst<FloatType>;
 template <>
 inline const int32_t& kCanonicalNans<intrinsics::Float32> =
     kVectorConst<uint64_t{0x7fc0'0000'7fc0'0000}>;
@@ -205,7 +208,7 @@ inline const int32_t& kCanonicalNans<intrinsics::Float64> =
 
 // Helper constant for BsrToClz conversion. 63 for int32_t, 127 for int64_t.
 template <typename IntType>
-extern const int32_t kBsrToClz;
+inline constexpr int32_t kBsrToClz = kImpossibleTypeConst<IntType>;
 template <>
 inline const int32_t kBsrToClz<int32_t> = kConst<uint32_t{63}>;
 template <>
@@ -213,7 +216,7 @@ inline const int32_t kBsrToClz<int64_t> = kConst<uint64_t{127}>;
 
 // Helper constant for width of the type. 32 for int32_t, 64 for int64_t.
 template <typename IntType>
-extern const int32_t kWidthInBits;
+inline constexpr int32_t kWidthInBits = kImpossibleTypeConst<IntType>;
 template <>
 inline const int32_t kWidthInBits<int32_t> = kConst<uint32_t{32}>;
 template <>
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
index f3ddaea7..150e1a1b 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
@@ -131,6 +131,6 @@ template <typename ElementType,
 
 // Include host-agnostic code.
 
-#include "berberis/intrinsics/riscv64/vector_intrinsics.h"
+#include "berberis/intrinsics/riscv64_to_all/vector_intrinsics.h"
 
 #endif  // RISCV64_TO_X86_64_BERBERIS_INTRINSICS_VECTOR_INTRINSICS_H_
diff --git a/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json b/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
index e9e052b8..452d3657 100644
--- a/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
+++ b/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
@@ -309,35 +309,35 @@
   {
     "name": "FeGetExceptions",
     "insn": "MacroFeGetExceptionsTranslate",
-    "usage": "translate-only",
+    "usage": "inline-only",
     "in": [],
     "out": [ 1 ]
   },
   {
     "name": "FeSetExceptions",
     "insn": "MacroFeSetExceptionsTranslate",
-    "usage": "translate-only",
+    "usage": "inline-only",
     "in": [ 0 ],
     "out": []
   },
   {
     "name": "FeSetExceptionsAndRound",
     "insn": "MacroFeSetExceptionsAndRoundTranslate",
-    "usage": "translate-only",
+    "usage": "inline-only",
     "in": [ 0, 3 ],
     "out": []
   },
   {
     "name": "FeSetExceptionsImm",
     "insn": "MacroFeSetExceptionsImmTranslate",
-    "usage": "translate-only",
+    "usage": "inline-only",
     "in": [ 1 ],
     "out": []
   },
   {
     "name": "FeSetExceptionsAndRoundImm",
     "insn": "MacroFeSetExceptionsAndRoundImmTranslate",
-    "usage": "translate-only",
+    "usage": "inline-only",
     "in": [ 1 ],
     "out": []
   },
@@ -350,14 +350,14 @@
   {
     "name": "FeSetRoundImm",
     "insn": "MacroFeSetRound",
-    "usage": "interpret-only",
+    "usage": "no-inline",
     "in": [ 3 ],
     "out": []
   },
   {
     "name": "FeSetRoundImm",
     "insn": "MacroFeSetRoundImmTranslate",
-    "usage": "translate-only",
+    "usage": "inline-only",
     "in": [ 2 ],
     "out": []
   },
@@ -741,9 +741,21 @@
     "out": [ 0 ]
   },
   {
-    "name": "Zexth",
+    "name": "Zext<uint8_t>",
+    "insn": "MovzxbqRegReg",
+    "in": [ 1 ],
+    "out": [ 0 ]
+  },
+  {
+    "name": "Zext<uint16_t>",
     "insn": "MovzxwqRegReg",
     "in": [ 1 ],
     "out": [ 0 ]
+  },
+  {
+    "name": "Zext<uint32_t>",
+    "insn": "MovlRegReg",
+    "in": [ 1 ],
+    "out": [ 0 ]
   }
 ]
diff --git a/intrinsics/riscv64_to_x86_64/macro_assembler.cc b/intrinsics/riscv64_to_x86_64/macro_assembler.cc
index edbf615a..d2c3338b 100644
--- a/intrinsics/riscv64_to_x86_64/macro_assembler.cc
+++ b/intrinsics/riscv64_to_x86_64/macro_assembler.cc
@@ -20,6 +20,7 @@
 #include "berberis/base/bit_util.h"
 #include "berberis/base/mmap.h"
 #include "berberis/base/struct_check.h"
+#include "berberis/intrinsics/simd_register.h"
 
 #include "berberis/intrinsics/macro_assembler.h"
 
@@ -133,7 +134,7 @@ struct MacroAssemblerConstants {
   // This may be true for hardware implementation, but in software vid.v may be implemented with a
   // simple precomputed table which implementation of viota.m is much more tricky and slow.
   // Here are precomputed values for Vid.v
-  alignas(16) __m128i kVid64Bit[8] = {
+  alignas(16) Int64x2 kVid64Bit[8] = {
       {0, 1},
       {2, 3},
       {4, 5},
@@ -143,7 +144,7 @@ struct MacroAssemblerConstants {
       {12, 13},
       {14, 15},
   };
-  alignas(16) __v4si kVid32Bit[8] = {
+  alignas(16) Int32x4 kVid32Bit[8] = {
       {0, 1, 2, 3},
       {4, 5, 6, 7},
       {8, 9, 10, 11},
@@ -153,7 +154,7 @@ struct MacroAssemblerConstants {
       {24, 25, 26, 27},
       {28, 29, 30, 31},
   };
-  alignas(16) __v8hi kVid16Bit[8] = {
+  alignas(16) Int16x8 kVid16Bit[8] = {
       {0, 1, 2, 3, 4, 5, 6, 7},
       {8, 9, 10, 11, 12, 13, 14, 15},
       {16, 17, 18, 19, 20, 21, 22, 23},
@@ -163,7 +164,7 @@ struct MacroAssemblerConstants {
       {48, 49, 50, 51, 52, 53, 54, 55},
       {56, 57, 58, 59, 60, 61, 62, 63},
   };
-  alignas(16) __v16qi kVid8Bit[8] = {
+  alignas(16) Int8x16 kVid8Bit[8] = {
       {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
       {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
       {32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47},
diff --git a/intrinsics/riscv64_to_x86_64/text_assembler.h b/intrinsics/riscv64_to_x86_64/text_assembler.h
index c3de26ee..855b6092 100644
--- a/intrinsics/riscv64_to_x86_64/text_assembler.h
+++ b/intrinsics/riscv64_to_x86_64/text_assembler.h
@@ -19,19 +19,22 @@
 
 #include <stdio.h>
 
-#include "berberis/intrinsics/common_to_x86/text_assembler_common.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h"
 
 namespace berberis {
 
-class TextAssembler : public TextAssemblerX86<TextAssembler> {
+class TextAssembler : public x86_32_and_x86_64::TextAssembler<TextAssembler> {
  public:
-  TextAssembler(int indent, FILE* out) : TextAssemblerX86(indent, out) {}
+  using BaseAssembler = x86_32_and_x86_64::TextAssembler<TextAssembler>;
+  using FinalAssembler = TextAssembler;
+
+  TextAssembler(int indent, FILE* out) : BaseAssembler(indent, out) {}
 
 // Instructions.
 #include "gen_text_assembler_x86_64-inl.h"  // NOLINT generated file
 
   // Unhide Movq(Mem, XMMReg) and Movq(XMMReg, Mem) hidden by Movq(Reg, Imm) and many others.
-  using TextAssemblerX86::Movq;
+  using BaseAssembler::Movq;
 
   static constexpr char kArchName[] = "riscv64";
   static constexpr char kArchGuard[] = "RISCV64_TO_X86_64";
@@ -41,9 +44,14 @@ class TextAssembler : public TextAssemblerX86<TextAssembler> {
   using RegisterDefaultBit = RegisterTemplate<kRsp, 'q'>;
 
  private:
-  using Assembler = TextAssembler;
-  DISALLOW_IMPLICIT_CONSTRUCTORS(TextAssembler);
-  friend TextAssemblerX86;
+  TextAssembler() = delete;
+  TextAssembler(const TextAssembler&) = delete;
+  TextAssembler(TextAssembler&&) = delete;
+  void operator=(const TextAssembler&) = delete;
+  void operator=(TextAssembler&&) = delete;
+  using DerivedAssemblerType = TextAssembler;
+
+  friend BaseAssembler;
 };
 
 void MakeGetSetFPEnvironment(FILE* out) {
diff --git a/intrinsics/common_to_x86/simd_register_test.cc b/intrinsics/simd_register_test.cc
similarity index 81%
rename from intrinsics/common_to_x86/simd_register_test.cc
rename to intrinsics/simd_register_test.cc
index c95a69df..f556ad1d 100644
--- a/intrinsics/common_to_x86/simd_register_test.cc
+++ b/intrinsics/simd_register_test.cc
@@ -24,8 +24,8 @@ namespace berberis {
 
 namespace {
 
-constexpr __m128i kLhs = {0x5555'5555'5555'5555, 0x5555'5555'5555'5555};
-constexpr __m128i kRhs = {0x3333'3333'3333'3333, 0x3333'3333'3333'3333};
+constexpr Int64x2 kLhs = {0x5555'5555'5555'5555, 0x5555'5555'5555'5555};
+constexpr Int64x2 kRhs = {0x3333'3333'3333'3333, 0x3333'3333'3333'3333};
 
 TEST(SIMD_REGISTER, TestEq) {
   SIMD128Register lhs = kLhs;
@@ -45,27 +45,27 @@ TEST(SIMD_REGISTER, TestNe) {
 TEST(SIMD_REGISTER, TestAnd) {
   SIMD128Register lhs = kLhs;
   SIMD128Register rhs = kRhs;
-  SIMD128Register result = __m128i{0x1111'1111'1111'1111, 0x1111'1111'1111'1111};
+  SIMD128Register result = Int64x2{0x1111'1111'1111'1111, 0x1111'1111'1111'1111};
   ASSERT_EQ(lhs & rhs, result);
 }
 
 TEST(SIMD_REGISTER, TestNot) {
   SIMD128Register lhs = kLhs;
-  SIMD128Register result = __m128i{-0x5555'5555'5555'5556, -0x5555'5555'5555'5556};
+  SIMD128Register result = Int64x2{-0x5555'5555'5555'5556, -0x5555'5555'5555'5556};
   ASSERT_EQ(~lhs, result);
 }
 
 TEST(SIMD_REGISTER, TestOr) {
   SIMD128Register lhs = kLhs;
   SIMD128Register rhs = kRhs;
-  SIMD128Register result = __m128i{0x7777'7777'7777'7777, 0x7777'7777'7777'7777};
+  SIMD128Register result = Int64x2{0x7777'7777'7777'7777, 0x7777'7777'7777'7777};
   ASSERT_EQ(lhs | rhs, result);
 }
 
 TEST(SIMD_REGISTER, TestXor) {
   SIMD128Register lhs = kLhs;
   SIMD128Register rhs = kRhs;
-  SIMD128Register result = __m128i{0x6666'6666'6666'6666, 0x6666'6666'6666'6666};
+  SIMD128Register result = Int64x2{0x6666'6666'6666'6666, 0x6666'6666'6666'6666};
   ASSERT_EQ(lhs ^ rhs, result);
 }
 
diff --git a/kernel_api/Android.bp b/kernel_api/Android.bp
index a11d8972..75fd4fed 100644
--- a/kernel_api/Android.bp
+++ b/kernel_api/Android.bp
@@ -19,7 +19,10 @@ package {
 
 cc_library_headers {
     name: "libberberis_kernel_api_headers",
-    defaults: ["berberis_guest_agnostic_defaults"],
+    defaults: [
+        "berberis_all_hosts_defaults",
+        "berberis_guest_agnostic_defaults",
+    ],
     host_supported: true,
     export_include_dirs: ["include"],
 }
@@ -27,24 +30,64 @@ cc_library_headers {
 cc_library_static {
     name: "libberberis_kernel_api_common",
     defaults: [
+        "berberis_all_hosts_defaults",
         "berberis_guest_agnostic_defaults",
     ],
     host_supported: true,
+    // TODO(b/346604197): Use the same set of sources on arm64 as on other archs once
+    // runtime_primitives and guest_os_primitives are ported.
+    arch: {
+        arm64: {
+            srcs: [
+                "runtime_bridge_riscv64_to_arm64.cc",
+            ],
+        },
+        riscv64: {
+            srcs: [
+                "open_emulation.cc",
+                "runtime_bridge.cc",
+                "sigevent_emulation.cc",
+                "sys_mman_emulation.cc",
+                "sys_prctl_emulation.cc",
+            ],
+            header_libs: [
+                "libberberis_guest_os_primitives_headers",
+            ],
+        },
+        x86: {
+            srcs: [
+                "open_emulation.cc",
+                "runtime_bridge.cc",
+                "sigevent_emulation.cc",
+                "sys_mman_emulation.cc",
+                "sys_prctl_emulation.cc",
+            ],
+            header_libs: [
+                "libberberis_guest_os_primitives_headers",
+            ],
+        },
+        x86_64: {
+            srcs: [
+                "open_emulation.cc",
+                "runtime_bridge.cc",
+                "sigevent_emulation.cc",
+                "sys_mman_emulation.cc",
+                "sys_prctl_emulation.cc",
+            ],
+            header_libs: [
+                "libberberis_guest_os_primitives_headers",
+            ],
+        },
+    },
     srcs: [
         "exec_emulation.cc",
         "fcntl_emulation.cc",
         "main_executable_real_path_emulation.cc",
-        "open_emulation.cc",
-        "runtime_bridge.cc",
-        "sigevent_emulation.cc",
-        "sys_mman_emulation.cc",
-        "sys_prctl_emulation.cc",
         "sys_ptrace_emulation.cc",
         "unistd_emulation.cc",
     ],
     header_libs: [
         "libberberis_base_headers",
-        "libberberis_guest_os_primitives_headers",
         "libberberis_kernel_api_headers",
     ],
     export_header_lib_headers: ["libberberis_kernel_api_headers"],
@@ -53,23 +96,32 @@ cc_library_static {
 cc_library_static {
     name: "libberberis_kernel_api_riscv64",
     defaults: [
-        "berberis_defaults_64",
+        "berberis_all_hosts_defaults_64",
     ],
     host_supported: true,
+    // TODO(b/346604197): Use the same set of sources on arm64 as on other archs once
+    // runtime_primitives and guest_os_primitives are ported.
+    arch: {
+        x86_64: {
+            header_libs: [
+                "libberberis_guest_os_primitives_headers",
+            ],
+            srcs: [
+                "riscv64/open_emulation.cc",
+            ],
+        },
+    },
     whole_static_libs: [
         "libberberis_kernel_api_common",
     ],
     srcs: [
         "riscv64/epoll_emulation.cc",
-        "riscv64/open_emulation.cc",
         "riscv64/syscall_emulation_arch.cc",
         "riscv64/syscall_emulation.cc",
-        "riscv64/tracing.cc",
     ],
     local_include_dirs: ["riscv64"],
     header_libs: [
         "libberberis_base_headers",
-        "libberberis_guest_os_primitives_headers",
         "libberberis_guest_state_riscv64_headers",
         "libberberis_instrument_headers",
         "libberberis_kernel_api_headers",
diff --git a/kernel_api/exec_emulation.cc b/kernel_api/exec_emulation.cc
index 4789f36c..049d60f4 100644
--- a/kernel_api/exec_emulation.cc
+++ b/kernel_api/exec_emulation.cc
@@ -19,6 +19,7 @@
 #include <unistd.h>
 
 #include <cstring>
+#include <utility>
 
 #include "berberis/base/mmap.h"
 #include "berberis/base/strings.h"
@@ -27,6 +28,11 @@ namespace berberis {
 
 namespace {
 
+std::pair<const char*, size_t> GetGuestPlatformVarPrefixWithSize() {
+  static constexpr char kGuestPlatformVarPrefix[] = "BERBERIS_GUEST_";
+  return {kGuestPlatformVarPrefix, sizeof(kGuestPlatformVarPrefix) - 1};
+}
+
 bool IsPlatformVar(const char* s) {
   return StartsWith(s, "LD_CONFIG_FILE=") || StartsWith(s, "LD_LIBRARY_PATH=") ||
          StartsWith(s, "LD_DEBUG=") || StartsWith(s, "LD_PRELOAD=");
diff --git a/kernel_api/fcntl_emulation.cc b/kernel_api/fcntl_emulation.cc
index 6c74b49d..2a452757 100644
--- a/kernel_api/fcntl_emulation.cc
+++ b/kernel_api/fcntl_emulation.cc
@@ -33,8 +33,8 @@
 #include <cerrno>
 
 #include "berberis/base/checks.h"
+#include "berberis/base/tracing.h"
 #include "berberis/kernel_api/open_emulation.h"
-#include "berberis/kernel_api/tracing.h"
 
 static_assert(F_DUPFD == 0);
 static_assert(F_GETFD == 1);
@@ -110,6 +110,13 @@ void ConvertHostFlock64ToGuestFlock(const struct flock64* host, Guest_flock* gue
 namespace berberis {
 
 int GuestFcntl(int fd, int cmd, long arg_3) {
+  // TODO(b/346604197): Enable on arm64 once guest_os_primitives is ported.
+#ifdef __aarch64__
+  UNUSED(fd, cmd, arg_3);
+  TRACE("unimplemented GuestFcntl");
+  errno = ENOSYS;
+  return -1;
+#else
   auto [processed, result] = GuestFcntlArch(fd, cmd, arg_3);
   if (processed) {
     return result;
@@ -169,10 +176,11 @@ int GuestFcntl(int fd, int cmd, long arg_3) {
     case F_SETFL:
       return fcntl(fd, cmd, ToHostOpenFlags(arg_3));
     default:
-      KAPI_TRACE("Unknown fcntl command: %d", cmd);
+      TRACE("Unknown fcntl command: %d", cmd);
       errno = ENOSYS;
       return -1;
   }
+#endif
 }
 
 }  // namespace berberis
diff --git a/kernel_api/include/berberis/kernel_api/exec_emulation.h b/kernel_api/include/berberis/kernel_api/exec_emulation.h
index 893016f0..06a44e73 100644
--- a/kernel_api/include/berberis/kernel_api/exec_emulation.h
+++ b/kernel_api/include/berberis/kernel_api/exec_emulation.h
@@ -18,12 +18,9 @@
 #define BERBERIS_KERNEL_API_EXEC_EMULATION_H_
 
 #include <cstddef>
-#include <utility>
 
 namespace berberis {
 
-std::pair<const char*, size_t> GetGuestPlatformVarPrefixWithSize();
-
 char** DemangleGuestEnvp(char** dst, char** envp);
 
 int ExecveForGuest(const char* filename, char* const argv[], char* const envp[]);
diff --git a/kernel_api/include/berberis/kernel_api/syscall_emulation_common.h b/kernel_api/include/berberis/kernel_api/syscall_emulation_common.h
index ba2a8ca4..c7153cdc 100644
--- a/kernel_api/include/berberis/kernel_api/syscall_emulation_common.h
+++ b/kernel_api/include/berberis/kernel_api/syscall_emulation_common.h
@@ -26,13 +26,13 @@
 
 #include "berberis/base/bit_util.h"
 #include "berberis/base/macros.h"
+#include "berberis/base/tracing.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/kernel_api/exec_emulation.h"
 #include "berberis/kernel_api/fcntl_emulation.h"
 #include "berberis/kernel_api/open_emulation.h"
 #include "berberis/kernel_api/sys_prctl_emulation.h"
 #include "berberis/kernel_api/sys_ptrace_emulation.h"
-#include "berberis/kernel_api/tracing.h"
 #include "berberis/kernel_api/unistd_emulation.h"
 
 namespace berberis {
@@ -41,14 +41,22 @@ void ConvertHostStatToGuestArch(const struct stat& host_stat, GuestAddr guest_st
 
 inline long RunGuestSyscall___NR_clone3(long arg_1, long arg_2) {
   UNUSED(arg_1, arg_2);
-  KAPI_TRACE("unimplemented syscall __NR_clone3");
+  TRACE("unimplemented syscall __NR_clone3");
   errno = ENOSYS;
   return -1;
 }
 
 inline long RunGuestSyscall___NR_close(long arg_1) {
+  // TODO(b/346604197): Enable on arm64 once guest_os_primitives is ported.
+#ifdef __aarch64__
+  UNUSED(arg_1);
+  TRACE("unimplemented syscall __NR_close");
+  errno = ENOSYS;
+  return -1;
+#else
   CloseEmulatedProcSelfMapsFileDescriptor(arg_1);
   return syscall(__NR_close, arg_1);
+#endif
 }
 
 inline long RunGuestSyscall___NR_execve(long arg_1, long arg_2, long arg_3) {
@@ -59,11 +67,18 @@ inline long RunGuestSyscall___NR_execve(long arg_1, long arg_2, long arg_3) {
 
 inline long RunGuestSyscall___NR_faccessat(long arg_1, long arg_2, long arg_3) {
   // TODO(b/128614662): translate!
-  KAPI_TRACE("unimplemented syscall __NR_faccessat, running host syscall as is");
+  TRACE("unimplemented syscall __NR_faccessat, running host syscall as is");
   return syscall(__NR_faccessat, arg_1, arg_2, arg_3);
 }
 
 inline long RunGuestSyscall___NR_fstat(long arg_1, long arg_2) {
+  // TODO(b/346604197): Enable on arm64 once guest_os_primitives is ported.
+#ifdef __aarch64__
+  UNUSED(arg_1, arg_2);
+  TRACE("unimplemented syscall __NR_fstat");
+  errno = ENOSYS;
+  return -1;
+#else
   // We are including this structure from library headers (sys/stat.h) and assume
   // that it matches kernel's layout.
   // TODO(b/232598137): Add a check for this. It seems like this is an issue for 32-bit
@@ -72,8 +87,12 @@ inline long RunGuestSyscall___NR_fstat(long arg_1, long arg_2) {
   struct stat host_stat;
   long result;
   if (IsFileDescriptorEmulatedProcSelfMaps(arg_1)) {
-    KAPI_TRACE("Emulating fstat for /proc/self/maps");
-    result = syscall(__NR_stat, "/proc/self/maps", &host_stat);
+    TRACE("Emulating fstat for /proc/self/maps");
+#if defined(__LP64__)
+    result = syscall(__NR_newfstatat, AT_FDCWD, "/proc/self/maps", &host_stat, 0);
+#else
+    result = syscall(__NR_fstatat64, AT_FDCWD, "/proc/self/maps", &host_stat, 0);
+#endif
   } else {
     result = syscall(__NR_fstat, arg_1, &host_stat);
   }
@@ -81,17 +100,26 @@ inline long RunGuestSyscall___NR_fstat(long arg_1, long arg_2) {
     ConvertHostStatToGuestArch(host_stat, bit_cast<GuestAddr>(arg_2));
   }
   return result;
+#endif
 }
 
 inline long RunGuestSyscall___NR_fstatfs(long arg_1, long arg_2) {
+  // TODO(b/346604197): Enable on arm64 once guest_os_primitives is ported.
+#ifdef __aarch64__
+  UNUSED(arg_1, arg_2);
+  TRACE("unimplemented syscall __NR_fstatfs");
+  errno = ENOSYS;
+  return -1;
+#else
   if (IsFileDescriptorEmulatedProcSelfMaps(arg_1)) {
-    KAPI_TRACE("Emulating fstatfs for /proc/self/maps");
+    TRACE("Emulating fstatfs for /proc/self/maps");
     // arg_2 (struct statfs*) has kernel expected layout, which is different from
     // what libc may expect. E.g. this happens for 32-bit bionic where the library call
     // expects struct statfs64. Thus ensure we invoke syscall, not library call.
     return syscall(__NR_statfs, "/proc/self/maps", arg_2);
   }
   return syscall(__NR_fstatfs, arg_1, arg_2);
+#endif
 }
 
 inline long RunGuestSyscall___NR_fcntl(long arg_1, long arg_2, long arg_3) {
@@ -99,14 +127,30 @@ inline long RunGuestSyscall___NR_fcntl(long arg_1, long arg_2, long arg_3) {
 }
 
 inline long RunGuestSyscall___NR_openat(long arg_1, long arg_2, long arg_3, long arg_4) {
+  // TODO(b/346604197): Enable on arm64 once guest_os_primitives is ported.
+#ifdef __aarch64__
+  UNUSED(arg_1, arg_2, arg_3, arg_4);
+  TRACE("unimplemented syscall __NR_openat");
+  errno = ENOSYS;
+  return -1;
+#else
   return static_cast<long>(OpenatForGuest(static_cast<int>(arg_1),       // dirfd
                                           bit_cast<const char*>(arg_2),  // path
                                           static_cast<int>(arg_3),       // flags
                                           static_cast<mode_t>(arg_4)));  // mode
+#endif
 }
 
 inline long RunGuestSyscall___NR_prctl(long arg_1, long arg_2, long arg_3, long arg_4, long arg_5) {
+  // TODO(b/346604197): Enable on arm64 once guest_os_primitives is ported.
+#ifdef __aarch64__
+  UNUSED(arg_1, arg_2, arg_3, arg_4, arg_5);
+  TRACE("unimplemented syscall __NR_prctl");
+  errno = ENOSYS;
+  return -1;
+#else
   return PrctlForGuest(arg_1, arg_2, arg_3, arg_4, arg_5);
+#endif
 }
 
 inline long RunGuestSyscall___NR_ptrace(long arg_1, long arg_2, long arg_3, long arg_4) {
@@ -124,7 +168,7 @@ inline long RunGuestSyscall___NR_readlinkat(long arg_1, long arg_2, long arg_3,
 }
 
 inline long RunGuestSyscall___NR_rt_sigreturn(long) {
-  KAPI_TRACE("unsupported syscall __NR_rt_sigaction");
+  TRACE("unsupported syscall __NR_rt_sigaction");
   errno = ENOSYS;
   return -1;
 }
@@ -148,7 +192,7 @@ long RunUnknownGuestSyscall(long guest_nr,
                             long arg_5,
                             long arg_6) {
   UNUSED(arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
-  KAPI_TRACE("unknown syscall %ld", guest_nr);
+  TRACE("unknown syscall %ld", guest_nr);
   errno = ENOSYS;
   return -1;
 }
diff --git a/kernel_api/riscv64/epoll_emulation.cc b/kernel_api/riscv64/epoll_emulation.cc
index 134175ee..c9fda610 100644
--- a/kernel_api/riscv64/epoll_emulation.cc
+++ b/kernel_api/riscv64/epoll_emulation.cc
@@ -24,7 +24,7 @@
 #include <cstring>
 
 #include "berberis/base/bit_util.h"
-#include "berberis/kernel_api/tracing.h"
+#include "berberis/base/tracing.h"
 
 #include "guest_types.h"
 
@@ -83,7 +83,7 @@ long RunGuestSyscall___NR_epoll_pwait(long arg_1,
 }
 
 long RunGuestSyscall___NR_epoll_pwait2(long, long, long, long, long, long) {
-  KAPI_TRACE("unsupported syscall __NR_epoll_pwait2");
+  TRACE("unsupported syscall __NR_epoll_pwait2");
   errno = ENOSYS;
   return -1;
 }
diff --git a/kernel_api/riscv64/gen_syscall_emulation_riscv64_to_arm64-inl.h b/kernel_api/riscv64/gen_syscall_emulation_riscv64_to_arm64-inl.h
new file mode 100644
index 00000000..475bd144
--- /dev/null
+++ b/kernel_api/riscv64/gen_syscall_emulation_riscv64_to_arm64-inl.h
@@ -0,0 +1,768 @@
+// This file automatically generated by gen_kernel_syscalls_translation.py
+// DO NOT EDIT!
+
+long RunGuestSyscallImpl(long guest_nr,
+                         long arg_1,
+                         long arg_2,
+                         long arg_3,
+                         long arg_4,
+                         long arg_5,
+                         long arg_6) {
+  switch (guest_nr) {
+    case 202:  // __NR_accept
+      return syscall(202, arg_1, arg_2, arg_3);
+    case 242:  // __NR_accept4
+      return syscall(242, arg_1, arg_2, arg_3, arg_4);
+    case 89:  // __NR_acct
+      return syscall(89, arg_1);
+    case 217:  // __NR_add_key
+      return syscall(217, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 171:  // __NR_adjtimex
+      return syscall(171, arg_1);
+    case 200:  // __NR_bind
+      return syscall(200, arg_1, arg_2, arg_3);
+    case 280:  // __NR_bpf
+      return syscall(280, arg_1, arg_2, arg_3);
+    case 214:  // __NR_brk
+      return syscall(214, arg_1);
+    case 90:  // __NR_capget
+      return syscall(90, arg_1, arg_2);
+    case 91:  // __NR_capset
+      return syscall(91, arg_1, arg_2);
+    case 49:  // __NR_chdir
+      return syscall(49, arg_1);
+    case 51:  // __NR_chroot
+      return syscall(51, arg_1);
+    case 266:  // __NR_clock_adjtime
+      return syscall(266, arg_1, arg_2);
+    case 114:  // __NR_clock_getres
+      return syscall(114, arg_1, arg_2);
+    case 113:  // __NR_clock_gettime
+      return syscall(113, arg_1, arg_2);
+    case 115:  // __NR_clock_nanosleep
+      return syscall(115, arg_1, arg_2, arg_3, arg_4);
+    case 112:  // __NR_clock_settime
+      return syscall(112, arg_1, arg_2);
+    case 220:  // __NR_clone
+      // custom syscall
+      return RunGuestSyscall___NR_clone(arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 435:  // __NR_clone3
+      // custom syscall
+      return RunGuestSyscall___NR_clone3(arg_1, arg_2);
+    case 57:  // __NR_close
+      // /proc/self/maps emulation
+      return RunGuestSyscall___NR_close(arg_1);
+    case 436:  // __NR_close_range
+      return syscall(436, arg_1, arg_2, arg_3);
+    case 203:  // __NR_connect
+      return syscall(203, arg_1, arg_2, arg_3);
+    case 285:  // __NR_copy_file_range
+      return syscall(285, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 106:  // __NR_delete_module
+      return syscall(106, arg_1, arg_2);
+    case 23:  // __NR_dup
+      return syscall(23, arg_1);
+    case 24:  // __NR_dup3
+      return syscall(24, arg_1, arg_2, arg_3);
+    case 20:  // __NR_epoll_create1
+      return syscall(20, arg_1);
+    case 21:  // __NR_epoll_ctl
+      return syscall(21, arg_1, arg_2, arg_3, arg_4);
+    case 22:  // __NR_epoll_pwait
+      return syscall(22, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 441:  // __NR_epoll_pwait2
+      return syscall(441, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 19:  // __NR_eventfd2
+      return syscall(19, arg_1, arg_2);
+    case 221:  // __NR_execve
+      // custom syscall
+      return RunGuestSyscall___NR_execve(arg_1, arg_2, arg_3);
+    case 281:  // __NR_execveat
+      // custom syscall
+      return RunGuestSyscall___NR_execveat(arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 93:  // __NR_exit
+      // cleans guest thread
+      return RunGuestSyscall___NR_exit(arg_1);
+    case 94:  // __NR_exit_group
+      return syscall(94, arg_1);
+    case 48:  // __NR_faccessat
+      // follows symlinks
+      return RunGuestSyscall___NR_faccessat(arg_1, arg_2, arg_3);
+    case 439:  // __NR_faccessat2
+      return syscall(439, arg_1, arg_2, arg_3, arg_4);
+    case 223:  // __NR_fadvise64
+      return syscall(223, arg_1, arg_2, arg_3, arg_4);
+    case 47:  // __NR_fallocate
+      return syscall(47, arg_1, arg_2, arg_3, arg_4);
+    case 262:  // __NR_fanotify_init
+      // missing prototype
+      TRACE("unsupported syscall __NR_fanotify_init");
+      errno = ENOSYS;
+      return -1;
+    case 263:  // __NR_fanotify_mark
+      // missing prototype
+      TRACE("unsupported syscall __NR_fanotify_mark");
+      errno = ENOSYS;
+      return -1;
+    case 50:  // __NR_fchdir
+      return syscall(50, arg_1);
+    case 52:  // __NR_fchmod
+      return syscall(52, arg_1, arg_2);
+    case 53:  // __NR_fchmodat
+      return syscall(53, arg_1, arg_2, arg_3);
+    case 55:  // __NR_fchown
+      return syscall(55, arg_1, arg_2, arg_3);
+    case 54:  // __NR_fchownat
+      return syscall(54, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 25:  // __NR_fcntl
+      // custom syscall
+      return RunGuestSyscall___NR_fcntl(arg_1, arg_2, arg_3);
+    case 83:  // __NR_fdatasync
+      return syscall(83, arg_1);
+    case 10:  // __NR_fgetxattr
+      return syscall(10, arg_1, arg_2, arg_3, arg_4);
+    case 273:  // __NR_finit_module
+      return syscall(273, arg_1, arg_2, arg_3);
+    case 13:  // __NR_flistxattr
+      return syscall(13, arg_1, arg_2, arg_3);
+    case 32:  // __NR_flock
+      return syscall(32, arg_1, arg_2);
+    case 16:  // __NR_fremovexattr
+      return syscall(16, arg_1, arg_2);
+    case 431:  // __NR_fsconfig
+      return syscall(431, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 7:  // __NR_fsetxattr
+      return syscall(7, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 432:  // __NR_fsmount
+      return syscall(432, arg_1, arg_2, arg_3);
+    case 430:  // __NR_fsopen
+      return syscall(430, arg_1, arg_2);
+    case 433:  // __NR_fspick
+      return syscall(433, arg_1, arg_2, arg_3);
+    case 80:  // __NR_fstat
+      return syscall(80, arg_1, arg_2);
+    case 44:  // __NR_fstatfs
+      // /proc/self/maps emulation
+      return RunGuestSyscall___NR_fstatfs(arg_1, arg_2);
+    case 82:  // __NR_fsync
+      return syscall(82, arg_1);
+    case 46:  // __NR_ftruncate
+      return syscall(46, arg_1, arg_2);
+    case 98:  // __NR_futex
+      return syscall(98, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 449:  // __NR_futex_waitv
+      return syscall(449, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 236:  // __NR_get_mempolicy
+      // missing prototype
+      TRACE("unsupported syscall __NR_get_mempolicy");
+      errno = ENOSYS;
+      return -1;
+    case 100:  // __NR_get_robust_list
+      return syscall(100, arg_1, arg_2, arg_3);
+    case 168:  // __NR_getcpu
+      return syscall(168, arg_1, arg_2, arg_3);
+    case 17:  // __NR_getcwd
+      return syscall(17, arg_1, arg_2);
+    case 61:  // __NR_getdents64
+      return syscall(61, arg_1, arg_2, arg_3);
+    case 177:  // __NR_getegid
+      return syscall(177);
+    case 175:  // __NR_geteuid
+      return syscall(175);
+    case 176:  // __NR_getgid
+      return syscall(176);
+    case 158:  // __NR_getgroups
+      return syscall(158, arg_1, arg_2);
+    case 102:  // __NR_getitimer
+      return syscall(102, arg_1, arg_2);
+    case 205:  // __NR_getpeername
+      return syscall(205, arg_1, arg_2, arg_3);
+    case 155:  // __NR_getpgid
+      return syscall(155, arg_1);
+    case 172:  // __NR_getpid
+      return syscall(172);
+    case 173:  // __NR_getppid
+      return syscall(173);
+    case 141:  // __NR_getpriority
+      return syscall(141, arg_1, arg_2);
+    case 278:  // __NR_getrandom
+      return syscall(278, arg_1, arg_2, arg_3);
+    case 150:  // __NR_getresgid
+      return syscall(150, arg_1, arg_2, arg_3);
+    case 148:  // __NR_getresuid
+      return syscall(148, arg_1, arg_2, arg_3);
+    case 163:  // __NR_getrlimit
+      return syscall(163, arg_1, arg_2);
+    case 165:  // __NR_getrusage
+      return syscall(165, arg_1, arg_2);
+    case 156:  // __NR_getsid
+      return syscall(156, arg_1);
+    case 204:  // __NR_getsockname
+      return syscall(204, arg_1, arg_2, arg_3);
+    case 209:  // __NR_getsockopt
+      return syscall(209, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 178:  // __NR_gettid
+      return syscall(178);
+    case 169:  // __NR_gettimeofday
+      return syscall(169, arg_1, arg_2);
+    case 174:  // __NR_getuid
+      return syscall(174);
+    case 8:  // __NR_getxattr
+      return syscall(8, arg_1, arg_2, arg_3, arg_4);
+    case 105:  // __NR_init_module
+      return syscall(105, arg_1, arg_2, arg_3);
+    case 27:  // __NR_inotify_add_watch
+      return syscall(27, arg_1, arg_2, arg_3);
+    case 26:  // __NR_inotify_init1
+      return syscall(26, arg_1);
+    case 28:  // __NR_inotify_rm_watch
+      return syscall(28, arg_1, arg_2);
+    case 3:  // __NR_io_cancel
+      return syscall(3, arg_1, arg_2, arg_3);
+    case 1:  // __NR_io_destroy
+      return syscall(1, arg_1);
+    case 4:  // __NR_io_getevents
+      return syscall(4, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 292:  // __NR_io_pgetevents
+      return syscall(292, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 0:  // __NR_io_setup
+      return syscall(0, arg_1, arg_2);
+    case 2:  // __NR_io_submit
+      return syscall(2, arg_1, arg_2, arg_3);
+    case 426:  // __NR_io_uring_enter
+      return syscall(426, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 427:  // __NR_io_uring_register
+      return syscall(427, arg_1, arg_2, arg_3, arg_4);
+    case 425:  // __NR_io_uring_setup
+      return syscall(425, arg_1, arg_2);
+    case 29:  // __NR_ioctl
+      // custom syscall
+      return RunGuestSyscall___NR_ioctl(arg_1, arg_2, arg_3);
+    case 31:  // __NR_ioprio_get
+      return syscall(31, arg_1, arg_2);
+    case 30:  // __NR_ioprio_set
+      return syscall(30, arg_1, arg_2, arg_3);
+    case 272:  // __NR_kcmp
+      return syscall(272, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 294:  // __NR_kexec_file_load
+      // missing prototype
+      TRACE("unsupported syscall __NR_kexec_file_load");
+      errno = ENOSYS;
+      return -1;
+    case 104:  // __NR_kexec_load
+      // missing prototype
+      TRACE("unsupported syscall __NR_kexec_load");
+      errno = ENOSYS;
+      return -1;
+    case 219:  // __NR_keyctl
+      return syscall(219, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 129:  // __NR_kill
+      return syscall(129, arg_1, arg_2);
+    case 445:  // __NR_landlock_add_rule
+      // missing prototype
+      TRACE("unsupported syscall __NR_landlock_add_rule");
+      errno = ENOSYS;
+      return -1;
+    case 444:  // __NR_landlock_create_ruleset
+      // missing prototype
+      TRACE("unsupported syscall __NR_landlock_create_ruleset");
+      errno = ENOSYS;
+      return -1;
+    case 446:  // __NR_landlock_restrict_self
+      // missing prototype
+      TRACE("unsupported syscall __NR_landlock_restrict_self");
+      errno = ENOSYS;
+      return -1;
+    case 9:  // __NR_lgetxattr
+      return syscall(9, arg_1, arg_2, arg_3, arg_4);
+    case 37:  // __NR_linkat
+      return syscall(37, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 201:  // __NR_listen
+      return syscall(201, arg_1, arg_2);
+    case 11:  // __NR_listxattr
+      return syscall(11, arg_1, arg_2, arg_3);
+    case 12:  // __NR_llistxattr
+      return syscall(12, arg_1, arg_2, arg_3);
+    case 18:  // __NR_lookup_dcookie
+      return syscall(18, arg_1, arg_2, arg_3);
+    case 15:  // __NR_lremovexattr
+      return syscall(15, arg_1, arg_2);
+    case 62:  // __NR_lseek
+      return syscall(62, arg_1, arg_2, arg_3);
+    case 6:  // __NR_lsetxattr
+      return syscall(6, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 233:  // __NR_madvise
+      return syscall(233, arg_1, arg_2, arg_3);
+    case 235:  // __NR_mbind
+      // missing prototype
+      TRACE("unsupported syscall __NR_mbind");
+      errno = ENOSYS;
+      return -1;
+    case 283:  // __NR_membarrier
+      return syscall(283, arg_1, arg_2, arg_3);
+    case 279:  // __NR_memfd_create
+      return syscall(279, arg_1, arg_2);
+    case 447:  // __NR_memfd_secret
+      return syscall(447, arg_1);
+    case 238:  // __NR_migrate_pages
+      // missing prototype
+      TRACE("unsupported syscall __NR_migrate_pages");
+      errno = ENOSYS;
+      return -1;
+    case 232:  // __NR_mincore
+      return syscall(232, arg_1, arg_2, arg_3);
+    case 34:  // __NR_mkdirat
+      return syscall(34, arg_1, arg_2, arg_3);
+    case 33:  // __NR_mknodat
+      return syscall(33, arg_1, arg_2, arg_3, arg_4);
+    case 228:  // __NR_mlock
+      return syscall(228, arg_1, arg_2);
+    case 284:  // __NR_mlock2
+      return syscall(284, arg_1, arg_2, arg_3);
+    case 230:  // __NR_mlockall
+      return syscall(230, arg_1);
+    case 222:  // __NR_mmap
+      // changes memory protection
+      return RunGuestSyscall___NR_mmap(arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 40:  // __NR_mount
+      return syscall(40, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 442:  // __NR_mount_setattr
+      return syscall(442, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 429:  // __NR_move_mount
+      return syscall(429, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 239:  // __NR_move_pages
+      // missing prototype
+      TRACE("unsupported syscall __NR_move_pages");
+      errno = ENOSYS;
+      return -1;
+    case 226:  // __NR_mprotect
+      // changes memory protection
+      return RunGuestSyscall___NR_mprotect(arg_1, arg_2, arg_3);
+    case 185:  // __NR_mq_getsetattr
+      // missing prototype
+      TRACE("unsupported syscall __NR_mq_getsetattr");
+      errno = ENOSYS;
+      return -1;
+    case 184:  // __NR_mq_notify
+      // missing prototype
+      TRACE("unsupported syscall __NR_mq_notify");
+      errno = ENOSYS;
+      return -1;
+    case 180:  // __NR_mq_open
+      // missing prototype
+      TRACE("unsupported syscall __NR_mq_open");
+      errno = ENOSYS;
+      return -1;
+    case 183:  // __NR_mq_timedreceive
+      // missing prototype
+      TRACE("unsupported syscall __NR_mq_timedreceive");
+      errno = ENOSYS;
+      return -1;
+    case 182:  // __NR_mq_timedsend
+      // missing prototype
+      TRACE("unsupported syscall __NR_mq_timedsend");
+      errno = ENOSYS;
+      return -1;
+    case 181:  // __NR_mq_unlink
+      // missing prototype
+      TRACE("unsupported syscall __NR_mq_unlink");
+      errno = ENOSYS;
+      return -1;
+    case 216:  // __NR_mremap
+      // changes memory protection
+      return RunGuestSyscall___NR_mremap(arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 187:  // __NR_msgctl
+      // missing prototype
+      TRACE("unsupported syscall __NR_msgctl");
+      errno = ENOSYS;
+      return -1;
+    case 186:  // __NR_msgget
+      // missing prototype
+      TRACE("unsupported syscall __NR_msgget");
+      errno = ENOSYS;
+      return -1;
+    case 188:  // __NR_msgrcv
+      // missing prototype
+      TRACE("unsupported syscall __NR_msgrcv");
+      errno = ENOSYS;
+      return -1;
+    case 189:  // __NR_msgsnd
+      // missing prototype
+      TRACE("unsupported syscall __NR_msgsnd");
+      errno = ENOSYS;
+      return -1;
+    case 227:  // __NR_msync
+      return syscall(227, arg_1, arg_2, arg_3);
+    case 229:  // __NR_munlock
+      return syscall(229, arg_1, arg_2);
+    case 231:  // __NR_munlockall
+      return syscall(231);
+    case 215:  // __NR_munmap
+      // changes memory protection
+      return RunGuestSyscall___NR_munmap(arg_1, arg_2);
+    case 264:  // __NR_name_to_handle_at
+      // missing prototype
+      TRACE("unsupported syscall __NR_name_to_handle_at");
+      errno = ENOSYS;
+      return -1;
+    case 101:  // __NR_nanosleep
+      return syscall(101, arg_1, arg_2);
+    case 79:  // __NR_newfstatat
+      // follows symlinks
+      return RunGuestSyscall___NR_newfstatat(arg_1, arg_2, arg_3, arg_4);
+    case 42:  // __NR_nfsservctl
+      return syscall(42);
+    case 265:  // __NR_open_by_handle_at
+      // missing prototype
+      TRACE("unsupported syscall __NR_open_by_handle_at");
+      errno = ENOSYS;
+      return -1;
+    case 428:  // __NR_open_tree
+      return syscall(428, arg_1, arg_2, arg_3);
+    case 56:  // __NR_openat
+      // follows symlinks, open flags value mismatch
+      return RunGuestSyscall___NR_openat(arg_1, arg_2, arg_3, arg_4);
+    case 437:  // __NR_openat2
+      return syscall(437, arg_1, arg_2, arg_3, arg_4);
+    case 241:  // __NR_perf_event_open
+      return syscall(241, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 92:  // __NR_personality
+      return syscall(92, arg_1);
+    case 438:  // __NR_pidfd_getfd
+      return syscall(438, arg_1, arg_2, arg_3);
+    case 434:  // __NR_pidfd_open
+      return syscall(434, arg_1, arg_2);
+    case 424:  // __NR_pidfd_send_signal
+      return syscall(424, arg_1, arg_2, arg_3, arg_4);
+    case 59:  // __NR_pipe2
+      return syscall(59, arg_1, arg_2);
+    case 41:  // __NR_pivot_root
+      return syscall(41, arg_1, arg_2);
+    case 289:  // __NR_pkey_alloc
+      // missing prototype
+      TRACE("unsupported syscall __NR_pkey_alloc");
+      errno = ENOSYS;
+      return -1;
+    case 290:  // __NR_pkey_free
+      // missing prototype
+      TRACE("unsupported syscall __NR_pkey_free");
+      errno = ENOSYS;
+      return -1;
+    case 288:  // __NR_pkey_mprotect
+      // missing prototype
+      TRACE("unsupported syscall __NR_pkey_mprotect");
+      errno = ENOSYS;
+      return -1;
+    case 73:  // __NR_ppoll
+      return syscall(73, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 167:  // __NR_prctl
+      // custom syscall
+      return RunGuestSyscall___NR_prctl(arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 67:  // __NR_pread64
+      return syscall(67, arg_1, arg_2, arg_3, arg_4);
+    case 69:  // __NR_preadv
+      return syscall(69, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 286:  // __NR_preadv2
+      return syscall(286, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 261:  // __NR_prlimit64
+      return syscall(261, arg_1, arg_2, arg_3, arg_4);
+    case 440:  // __NR_process_madvise
+      return syscall(440, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 448:  // __NR_process_mrelease
+      return syscall(448, arg_1, arg_2);
+    case 270:  // __NR_process_vm_readv
+      return syscall(270, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 271:  // __NR_process_vm_writev
+      return syscall(271, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 72:  // __NR_pselect6
+      return syscall(72, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 117:  // __NR_ptrace
+      // custom syscall
+      return RunGuestSyscall___NR_ptrace(arg_1, arg_2, arg_3, arg_4);
+    case 68:  // __NR_pwrite64
+      return syscall(68, arg_1, arg_2, arg_3, arg_4);
+    case 70:  // __NR_pwritev
+      return syscall(70, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 287:  // __NR_pwritev2
+      return syscall(287, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 60:  // __NR_quotactl
+      return syscall(60, arg_1, arg_2, arg_3, arg_4);
+    case 443:  // __NR_quotactl_fd
+      return syscall(443, arg_1, arg_2, arg_3, arg_4);
+    case 63:  // __NR_read
+      return syscall(63, arg_1, arg_2, arg_3);
+    case 213:  // __NR_readahead
+      return syscall(213, arg_1, arg_2, arg_3);
+    case 78:  // __NR_readlinkat
+      // follows symlinks
+      return RunGuestSyscall___NR_readlinkat(arg_1, arg_2, arg_3, arg_4);
+    case 65:  // __NR_readv
+      return syscall(65, arg_1, arg_2, arg_3);
+    case 142:  // __NR_reboot
+      return syscall(142, arg_1, arg_2, arg_3, arg_4);
+    case 207:  // __NR_recvfrom
+      return syscall(207, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 243:  // __NR_recvmmsg
+      return syscall(243, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 212:  // __NR_recvmsg
+      return syscall(212, arg_1, arg_2, arg_3);
+    case 234:  // __NR_remap_file_pages
+      return syscall(234, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 14:  // __NR_removexattr
+      return syscall(14, arg_1, arg_2);
+    case 38:  // __NR_renameat
+      return syscall(38, arg_1, arg_2, arg_3, arg_4);
+    case 276:  // __NR_renameat2
+      return syscall(276, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 218:  // __NR_request_key
+      return syscall(218, arg_1, arg_2, arg_3, arg_4);
+    case 128:  // __NR_restart_syscall
+      return syscall(128);
+    case 259:  // __NR_riscv_flush_icache
+      // missing on arm64
+      return RunGuestSyscall___NR_riscv_flush_icache(arg_1, arg_2, arg_3);
+    case 258:  // __NR_riscv_hwprobe
+      // missing on arm64
+      return RunGuestSyscall___NR_riscv_hwprobe(arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 293:  // __NR_rseq
+      // missing prototype
+      TRACE("unsupported syscall __NR_rseq");
+      errno = ENOSYS;
+      return -1;
+    case 134:  // __NR_rt_sigaction
+      // changes signal action
+      return RunGuestSyscall___NR_rt_sigaction(arg_1, arg_2, arg_3, arg_4);
+    case 136:  // __NR_rt_sigpending
+      return syscall(136, arg_1, arg_2);
+    case 135:  // __NR_rt_sigprocmask
+      return syscall(135, arg_1, arg_2, arg_3, arg_4);
+    case 138:  // __NR_rt_sigqueueinfo
+      return syscall(138, arg_1, arg_2, arg_3);
+    case 139:  // __NR_rt_sigreturn
+      // should never be called from guest
+      return RunGuestSyscall___NR_rt_sigreturn(arg_1);
+    case 133:  // __NR_rt_sigsuspend
+      return syscall(133, arg_1, arg_2);
+    case 137:  // __NR_rt_sigtimedwait
+      return syscall(137, arg_1, arg_2, arg_3, arg_4);
+    case 240:  // __NR_rt_tgsigqueueinfo
+      return syscall(240, arg_1, arg_2, arg_3, arg_4);
+    case 125:  // __NR_sched_get_priority_max
+      return syscall(125, arg_1);
+    case 126:  // __NR_sched_get_priority_min
+      return syscall(126, arg_1);
+    case 123:  // __NR_sched_getaffinity
+      return syscall(123, arg_1, arg_2, arg_3);
+    case 275:  // __NR_sched_getattr
+      return syscall(275, arg_1, arg_2, arg_3, arg_4);
+    case 121:  // __NR_sched_getparam
+      return syscall(121, arg_1, arg_2);
+    case 120:  // __NR_sched_getscheduler
+      return syscall(120, arg_1);
+    case 127:  // __NR_sched_rr_get_interval
+      return syscall(127, arg_1, arg_2);
+    case 122:  // __NR_sched_setaffinity
+      return syscall(122, arg_1, arg_2, arg_3);
+    case 274:  // __NR_sched_setattr
+      return syscall(274, arg_1, arg_2, arg_3);
+    case 118:  // __NR_sched_setparam
+      return syscall(118, arg_1, arg_2);
+    case 119:  // __NR_sched_setscheduler
+      return syscall(119, arg_1, arg_2, arg_3);
+    case 124:  // __NR_sched_yield
+      return syscall(124);
+    case 277:  // __NR_seccomp
+      return syscall(277, arg_1, arg_2, arg_3);
+    case 191:  // __NR_semctl
+      // missing prototype
+      TRACE("unsupported syscall __NR_semctl");
+      errno = ENOSYS;
+      return -1;
+    case 190:  // __NR_semget
+      // missing prototype
+      TRACE("unsupported syscall __NR_semget");
+      errno = ENOSYS;
+      return -1;
+    case 193:  // __NR_semop
+      // missing prototype
+      TRACE("unsupported syscall __NR_semop");
+      errno = ENOSYS;
+      return -1;
+    case 192:  // __NR_semtimedop
+      // missing prototype
+      TRACE("unsupported syscall __NR_semtimedop");
+      errno = ENOSYS;
+      return -1;
+    case 71:  // __NR_sendfile
+      return syscall(71, arg_1, arg_2, arg_3, arg_4);
+    case 269:  // __NR_sendmmsg
+      return syscall(269, arg_1, arg_2, arg_3, arg_4);
+    case 211:  // __NR_sendmsg
+      return syscall(211, arg_1, arg_2, arg_3);
+    case 206:  // __NR_sendto
+      return syscall(206, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 237:  // __NR_set_mempolicy
+      // missing prototype
+      TRACE("unsupported syscall __NR_set_mempolicy");
+      errno = ENOSYS;
+      return -1;
+    case 450:  // __NR_set_mempolicy_home_node
+      // missing prototype
+      TRACE("unsupported syscall __NR_set_mempolicy_home_node");
+      errno = ENOSYS;
+      return -1;
+    case 99:  // __NR_set_robust_list
+      return syscall(99, arg_1, arg_2);
+    case 96:  // __NR_set_tid_address
+      return syscall(96, arg_1);
+    case 162:  // __NR_setdomainname
+      return syscall(162, arg_1, arg_2);
+    case 152:  // __NR_setfsgid
+      return syscall(152, arg_1);
+    case 151:  // __NR_setfsuid
+      return syscall(151, arg_1);
+    case 144:  // __NR_setgid
+      return syscall(144, arg_1);
+    case 159:  // __NR_setgroups
+      return syscall(159, arg_1, arg_2);
+    case 161:  // __NR_sethostname
+      return syscall(161, arg_1, arg_2);
+    case 103:  // __NR_setitimer
+      return syscall(103, arg_1, arg_2, arg_3);
+    case 268:  // __NR_setns
+      return syscall(268, arg_1, arg_2);
+    case 154:  // __NR_setpgid
+      return syscall(154, arg_1, arg_2);
+    case 140:  // __NR_setpriority
+      return syscall(140, arg_1, arg_2, arg_3);
+    case 143:  // __NR_setregid
+      return syscall(143, arg_1, arg_2);
+    case 149:  // __NR_setresgid
+      return syscall(149, arg_1, arg_2, arg_3);
+    case 147:  // __NR_setresuid
+      return syscall(147, arg_1, arg_2, arg_3);
+    case 145:  // __NR_setreuid
+      return syscall(145, arg_1, arg_2);
+    case 164:  // __NR_setrlimit
+      return syscall(164, arg_1, arg_2);
+    case 157:  // __NR_setsid
+      return syscall(157);
+    case 208:  // __NR_setsockopt
+      return syscall(208, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 170:  // __NR_settimeofday
+      return syscall(170, arg_1, arg_2);
+    case 146:  // __NR_setuid
+      return syscall(146, arg_1);
+    case 5:  // __NR_setxattr
+      return syscall(5, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 196:  // __NR_shmat
+      // missing prototype
+      TRACE("unsupported syscall __NR_shmat");
+      errno = ENOSYS;
+      return -1;
+    case 195:  // __NR_shmctl
+      // missing prototype
+      TRACE("unsupported syscall __NR_shmctl");
+      errno = ENOSYS;
+      return -1;
+    case 197:  // __NR_shmdt
+      // missing prototype
+      TRACE("unsupported syscall __NR_shmdt");
+      errno = ENOSYS;
+      return -1;
+    case 194:  // __NR_shmget
+      // missing prototype
+      TRACE("unsupported syscall __NR_shmget");
+      errno = ENOSYS;
+      return -1;
+    case 210:  // __NR_shutdown
+      return syscall(210, arg_1, arg_2);
+    case 132:  // __NR_sigaltstack
+      // changes signal stack
+      return RunGuestSyscall___NR_sigaltstack(arg_1, arg_2);
+    case 74:  // __NR_signalfd4
+      return syscall(74, arg_1, arg_2, arg_3, arg_4);
+    case 198:  // __NR_socket
+      return syscall(198, arg_1, arg_2, arg_3);
+    case 199:  // __NR_socketpair
+      return syscall(199, arg_1, arg_2, arg_3, arg_4);
+    case 76:  // __NR_splice
+      return syscall(76, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+    case 43:  // __NR_statfs
+      return syscall(43, arg_1, arg_2);
+    case 291:  // __NR_statx
+      // follows symlinks
+      return RunGuestSyscall___NR_statx(arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 225:  // __NR_swapoff
+      return syscall(225, arg_1);
+    case 224:  // __NR_swapon
+      return syscall(224, arg_1, arg_2);
+    case 36:  // __NR_symlinkat
+      return syscall(36, arg_1, arg_2, arg_3);
+    case 81:  // __NR_sync
+      return syscall(81);
+    case 84:  // __NR_sync_file_range
+      return syscall(84, arg_1, arg_2, arg_3, arg_4);
+    case 267:  // __NR_syncfs
+      return syscall(267, arg_1);
+    case 179:  // __NR_sysinfo
+      return syscall(179, arg_1);
+    case 116:  // __NR_syslog
+      return syscall(116, arg_1, arg_2, arg_3);
+    case 77:  // __NR_tee
+      return syscall(77, arg_1, arg_2, arg_3, arg_4);
+    case 131:  // __NR_tgkill
+      return syscall(131, arg_1, arg_2, arg_3);
+    case 107:  // __NR_timer_create
+      // incompatible prototype
+      return RunGuestSyscall___NR_timer_create(arg_1, arg_2, arg_3);
+    case 111:  // __NR_timer_delete
+      return syscall(111, arg_1);
+    case 109:  // __NR_timer_getoverrun
+      return syscall(109, arg_1);
+    case 108:  // __NR_timer_gettime
+      return syscall(108, arg_1, arg_2);
+    case 110:  // __NR_timer_settime
+      return syscall(110, arg_1, arg_2, arg_3, arg_4);
+    case 85:  // __NR_timerfd_create
+      return syscall(85, arg_1, arg_2);
+    case 87:  // __NR_timerfd_gettime
+      return syscall(87, arg_1, arg_2);
+    case 86:  // __NR_timerfd_settime
+      return syscall(86, arg_1, arg_2, arg_3, arg_4);
+    case 153:  // __NR_times
+      return syscall(153, arg_1);
+    case 130:  // __NR_tkill
+      return syscall(130, arg_1, arg_2);
+    case 45:  // __NR_truncate
+      return syscall(45, arg_1, arg_2);
+    case 166:  // __NR_umask
+      return syscall(166, arg_1);
+    case 39:  // __NR_umount2
+      return syscall(39, arg_1, arg_2);
+    case 160:  // __NR_uname
+      return syscall(160, arg_1);
+    case 35:  // __NR_unlinkat
+      return syscall(35, arg_1, arg_2, arg_3);
+    case 97:  // __NR_unshare
+      return syscall(97, arg_1);
+    case 282:  // __NR_userfaultfd
+      return syscall(282, arg_1);
+    case 88:  // __NR_utimensat
+      return syscall(88, arg_1, arg_2, arg_3, arg_4);
+    case 58:  // __NR_vhangup
+      return syscall(58);
+    case 75:  // __NR_vmsplice
+      return syscall(75, arg_1, arg_2, arg_3, arg_4);
+    case 260:  // __NR_wait4
+      return syscall(260, arg_1, arg_2, arg_3, arg_4);
+    case 95:  // __NR_waitid
+      return syscall(95, arg_1, arg_2, arg_3, arg_4, arg_5);
+    case 64:  // __NR_write
+      return syscall(64, arg_1, arg_2, arg_3);
+    case 66:  // __NR_writev
+      return syscall(66, arg_1, arg_2, arg_3);
+    default:
+      return RunUnknownGuestSyscall(guest_nr, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+  }
+}
diff --git a/kernel_api/riscv64/gen_syscall_emulation_riscv64_to_x86_64-inl.h b/kernel_api/riscv64/gen_syscall_emulation_riscv64_to_x86_64-inl.h
index 779284c8..3315fb3b 100644
--- a/kernel_api/riscv64/gen_syscall_emulation_riscv64_to_x86_64-inl.h
+++ b/kernel_api/riscv64/gen_syscall_emulation_riscv64_to_x86_64-inl.h
@@ -100,12 +100,12 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(285, arg_1, arg_2, arg_3, arg_4);
     case 262:  // __NR_fanotify_init
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_fanotify_init");
+      TRACE("unsupported syscall __NR_fanotify_init");
       errno = ENOSYS;
       return -1;
     case 263:  // __NR_fanotify_mark
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_fanotify_mark");
+      TRACE("unsupported syscall __NR_fanotify_mark");
       errno = ENOSYS;
       return -1;
     case 50:  // __NR_fchdir
@@ -159,7 +159,7 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(449, arg_1, arg_2, arg_3, arg_4, arg_5);
     case 236:  // __NR_get_mempolicy
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_get_mempolicy");
+      TRACE("unsupported syscall __NR_get_mempolicy");
       errno = ENOSYS;
       return -1;
     case 100:  // __NR_get_robust_list
@@ -251,12 +251,12 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(312, arg_1, arg_2, arg_3, arg_4, arg_5);
     case 294:  // __NR_kexec_file_load
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_kexec_file_load");
+      TRACE("unsupported syscall __NR_kexec_file_load");
       errno = ENOSYS;
       return -1;
     case 104:  // __NR_kexec_load
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_kexec_load");
+      TRACE("unsupported syscall __NR_kexec_load");
       errno = ENOSYS;
       return -1;
     case 219:  // __NR_keyctl
@@ -265,17 +265,17 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(62, arg_1, arg_2);
     case 445:  // __NR_landlock_add_rule
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_landlock_add_rule");
+      TRACE("unsupported syscall __NR_landlock_add_rule");
       errno = ENOSYS;
       return -1;
     case 444:  // __NR_landlock_create_ruleset
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_landlock_create_ruleset");
+      TRACE("unsupported syscall __NR_landlock_create_ruleset");
       errno = ENOSYS;
       return -1;
     case 446:  // __NR_landlock_restrict_self
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_landlock_restrict_self");
+      TRACE("unsupported syscall __NR_landlock_restrict_self");
       errno = ENOSYS;
       return -1;
     case 9:  // __NR_lgetxattr
@@ -300,7 +300,7 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(28, arg_1, arg_2, arg_3);
     case 235:  // __NR_mbind
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_mbind");
+      TRACE("unsupported syscall __NR_mbind");
       errno = ENOSYS;
       return -1;
     case 283:  // __NR_membarrier
@@ -311,7 +311,7 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(447, arg_1);
     case 238:  // __NR_migrate_pages
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_migrate_pages");
+      TRACE("unsupported syscall __NR_migrate_pages");
       errno = ENOSYS;
       return -1;
     case 232:  // __NR_mincore
@@ -337,7 +337,7 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(429, arg_1, arg_2, arg_3, arg_4, arg_5);
     case 239:  // __NR_move_pages
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_move_pages");
+      TRACE("unsupported syscall __NR_move_pages");
       errno = ENOSYS;
       return -1;
     case 226:  // __NR_mprotect
@@ -345,32 +345,32 @@ long RunGuestSyscallImpl(long guest_nr,
       return RunGuestSyscall___NR_mprotect(arg_1, arg_2, arg_3);
     case 185:  // __NR_mq_getsetattr
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_mq_getsetattr");
+      TRACE("unsupported syscall __NR_mq_getsetattr");
       errno = ENOSYS;
       return -1;
     case 184:  // __NR_mq_notify
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_mq_notify");
+      TRACE("unsupported syscall __NR_mq_notify");
       errno = ENOSYS;
       return -1;
     case 180:  // __NR_mq_open
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_mq_open");
+      TRACE("unsupported syscall __NR_mq_open");
       errno = ENOSYS;
       return -1;
     case 183:  // __NR_mq_timedreceive
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_mq_timedreceive");
+      TRACE("unsupported syscall __NR_mq_timedreceive");
       errno = ENOSYS;
       return -1;
     case 182:  // __NR_mq_timedsend
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_mq_timedsend");
+      TRACE("unsupported syscall __NR_mq_timedsend");
       errno = ENOSYS;
       return -1;
     case 181:  // __NR_mq_unlink
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_mq_unlink");
+      TRACE("unsupported syscall __NR_mq_unlink");
       errno = ENOSYS;
       return -1;
     case 216:  // __NR_mremap
@@ -378,22 +378,22 @@ long RunGuestSyscallImpl(long guest_nr,
       return RunGuestSyscall___NR_mremap(arg_1, arg_2, arg_3, arg_4, arg_5);
     case 187:  // __NR_msgctl
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_msgctl");
+      TRACE("unsupported syscall __NR_msgctl");
       errno = ENOSYS;
       return -1;
     case 186:  // __NR_msgget
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_msgget");
+      TRACE("unsupported syscall __NR_msgget");
       errno = ENOSYS;
       return -1;
     case 188:  // __NR_msgrcv
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_msgrcv");
+      TRACE("unsupported syscall __NR_msgrcv");
       errno = ENOSYS;
       return -1;
     case 189:  // __NR_msgsnd
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_msgsnd");
+      TRACE("unsupported syscall __NR_msgsnd");
       errno = ENOSYS;
       return -1;
     case 227:  // __NR_msync
@@ -407,7 +407,7 @@ long RunGuestSyscallImpl(long guest_nr,
       return RunGuestSyscall___NR_munmap(arg_1, arg_2);
     case 264:  // __NR_name_to_handle_at
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_name_to_handle_at");
+      TRACE("unsupported syscall __NR_name_to_handle_at");
       errno = ENOSYS;
       return -1;
     case 101:  // __NR_nanosleep
@@ -419,7 +419,7 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(180);
     case 265:  // __NR_open_by_handle_at
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_open_by_handle_at");
+      TRACE("unsupported syscall __NR_open_by_handle_at");
       errno = ENOSYS;
       return -1;
     case 428:  // __NR_open_tree
@@ -445,17 +445,17 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(155, arg_1, arg_2);
     case 289:  // __NR_pkey_alloc
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_pkey_alloc");
+      TRACE("unsupported syscall __NR_pkey_alloc");
       errno = ENOSYS;
       return -1;
     case 290:  // __NR_pkey_free
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_pkey_free");
+      TRACE("unsupported syscall __NR_pkey_free");
       errno = ENOSYS;
       return -1;
     case 288:  // __NR_pkey_mprotect
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_pkey_mprotect");
+      TRACE("unsupported syscall __NR_pkey_mprotect");
       errno = ENOSYS;
       return -1;
     case 73:  // __NR_ppoll
@@ -531,7 +531,7 @@ long RunGuestSyscallImpl(long guest_nr,
       return RunGuestSyscall___NR_riscv_hwprobe(arg_1, arg_2, arg_3, arg_4, arg_5);
     case 293:  // __NR_rseq
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_rseq");
+      TRACE("unsupported syscall __NR_rseq");
       errno = ENOSYS;
       return -1;
     case 134:  // __NR_rt_sigaction
@@ -580,22 +580,22 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(317, arg_1, arg_2, arg_3);
     case 191:  // __NR_semctl
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_semctl");
+      TRACE("unsupported syscall __NR_semctl");
       errno = ENOSYS;
       return -1;
     case 190:  // __NR_semget
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_semget");
+      TRACE("unsupported syscall __NR_semget");
       errno = ENOSYS;
       return -1;
     case 193:  // __NR_semop
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_semop");
+      TRACE("unsupported syscall __NR_semop");
       errno = ENOSYS;
       return -1;
     case 192:  // __NR_semtimedop
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_semtimedop");
+      TRACE("unsupported syscall __NR_semtimedop");
       errno = ENOSYS;
       return -1;
     case 71:  // __NR_sendfile
@@ -608,12 +608,12 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(44, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
     case 237:  // __NR_set_mempolicy
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_set_mempolicy");
+      TRACE("unsupported syscall __NR_set_mempolicy");
       errno = ENOSYS;
       return -1;
     case 450:  // __NR_set_mempolicy_home_node
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_set_mempolicy_home_node");
+      TRACE("unsupported syscall __NR_set_mempolicy_home_node");
       errno = ENOSYS;
       return -1;
     case 99:  // __NR_set_robust_list
@@ -662,22 +662,22 @@ long RunGuestSyscallImpl(long guest_nr,
       return syscall(188, arg_1, arg_2, arg_3, arg_4, arg_5);
     case 196:  // __NR_shmat
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_shmat");
+      TRACE("unsupported syscall __NR_shmat");
       errno = ENOSYS;
       return -1;
     case 195:  // __NR_shmctl
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_shmctl");
+      TRACE("unsupported syscall __NR_shmctl");
       errno = ENOSYS;
       return -1;
     case 197:  // __NR_shmdt
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_shmdt");
+      TRACE("unsupported syscall __NR_shmdt");
       errno = ENOSYS;
       return -1;
     case 194:  // __NR_shmget
       // missing prototype
-      KAPI_TRACE("unsupported syscall __NR_shmget");
+      TRACE("unsupported syscall __NR_shmget");
       errno = ENOSYS;
       return -1;
     case 210:  // __NR_shutdown
diff --git a/kernel_api/riscv64/open_emulation.cc b/kernel_api/riscv64/open_emulation.cc
index afd31019..d85852c2 100644
--- a/kernel_api/riscv64/open_emulation.cc
+++ b/kernel_api/riscv64/open_emulation.cc
@@ -23,14 +23,19 @@
 #include <sys/stat.h>
 #include <sys/types.h>
 
-#include "berberis/kernel_api/tracing.h"
-
-#define GUEST_O_LARGEFILE 00100000
+#include "berberis/base/tracing.h"
 
 namespace berberis {
 
-#if !defined(__i386__) && !defined(__x86_64__)
-#error Currently open flags conversion is only supported on x86
+#if !defined(__x86_64__)
+#error Currently open flags conversion is only supported on x86_64
+#endif
+
+// Glibc doesn't support O_LARGEFILE and defines it to 0. Here we need
+// kernel's definition for x86_64.
+#if (O_LARGEFILE == 0)
+#undef O_LARGEFILE
+#define O_LARGEFILE 00100000
 #endif
 
 // Glibc doesn't expose __O_SYNC
@@ -69,53 +74,38 @@ static_assert(O_DIRECT == 040000);
 static_assert(__O_SYNC == 04000000);
 static_assert(O_SYNC == (O_DSYNC | __O_SYNC));
 static_assert(O_PATH == 010000000);
+static_assert(O_LARGEFILE == 00100000);
 
 namespace {
 
-const int kCompatibleOpenFlags = O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND |
-                                 O_NONBLOCK | O_DSYNC | FASYNC | O_NOATIME | O_DIRECTORY |
-                                 O_NOFOLLOW | O_CLOEXEC | O_DIRECT | __O_SYNC | O_PATH;
+const int kCompatibleOpenFlags =
+    O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND | O_NONBLOCK | O_DSYNC | FASYNC |
+    O_NOATIME | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_DIRECT | __O_SYNC | O_PATH | O_LARGEFILE;
 
 }  // namespace
 
 const char* kGuestCpuinfoPath = "/system/etc/cpuinfo.riscv64.txt";
 
 int ToHostOpenFlags(int guest_flags) {
-  const int kIncompatibleGuestOpenFlags = GUEST_O_LARGEFILE;
-
-  int unknown_guest_flags = guest_flags & ~(kCompatibleOpenFlags | kIncompatibleGuestOpenFlags);
+  int unknown_guest_flags = guest_flags & ~kCompatibleOpenFlags;
   if (unknown_guest_flags) {
-    KAPI_TRACE("Unsupported guest open flags: original=0x%x unsupported=0x%x",
-               guest_flags,
-               unknown_guest_flags);
+    TRACE("Unrecognized guest open flags: original=0x%x unsupported=0x%x. Passing to host as is.",
+          guest_flags,
+          unknown_guest_flags);
   }
 
-  int host_flags = guest_flags & ~kIncompatibleGuestOpenFlags;
-
-  if (guest_flags & GUEST_O_LARGEFILE) {
-    host_flags |= O_LARGEFILE;
-  }
-
-  return host_flags;
+  return guest_flags;
 }
 
 int ToGuestOpenFlags(int host_flags) {
-  const int kIncompatibleHostOpenFlags = O_LARGEFILE;
-
-  int unknown_host_flags = host_flags & ~(kCompatibleOpenFlags | kIncompatibleHostOpenFlags);
+  int unknown_host_flags = host_flags & ~kCompatibleOpenFlags;
   if (unknown_host_flags) {
-    KAPI_TRACE("Unsupported host open flags: original=0x%x unsupported=0x%x",
-               host_flags,
-               unknown_host_flags);
+    TRACE("Unrecognized host open flags: original=0x%x unsupported=0x%x. Passing to guest as is.",
+          host_flags,
+          unknown_host_flags);
   }
 
-  int guest_flags = host_flags & ~kIncompatibleHostOpenFlags;
-
-  if (host_flags & O_LARGEFILE) {
-    guest_flags |= GUEST_O_LARGEFILE;
-  }
-
-  return guest_flags;
+  return host_flags;
 }
 
 }  // namespace berberis
diff --git a/kernel_api/riscv64/syscall_emulation.cc b/kernel_api/riscv64/syscall_emulation.cc
index 62c4e328..3319028c 100644
--- a/kernel_api/riscv64/syscall_emulation.cc
+++ b/kernel_api/riscv64/syscall_emulation.cc
@@ -26,15 +26,18 @@
 #include "berberis/base/macros.h"
 #include "berberis/base/scoped_errno.h"
 #include "berberis/base/tracing.h"
-#include "berberis/guest_os_primitives/scoped_pending_signals.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/guest_state/guest_state.h"
 #include "berberis/instrument/syscall.h"
 #include "berberis/kernel_api/main_executable_real_path_emulation.h"
 #include "berberis/kernel_api/runtime_bridge.h"
 #include "berberis/kernel_api/syscall_emulation_common.h"
-#include "berberis/kernel_api/tracing.h"
+
+// TODO(b/346604197): Enable on arm64 once these modules are ported.
+#ifdef __x86_64__
+#include "berberis/guest_os_primitives/scoped_pending_signals.h"
 #include "berberis/runtime_primitives/runtime_library.h"
+#endif
 
 #include "epoll_emulation.h"
 #include "guest_types.h"
@@ -82,19 +85,22 @@ void Hwprobe(Guest_riscv_hwprobe& pair) {
 
 long RunGuestSyscall___NR_execveat(long arg_1, long arg_2, long arg_3, long arg_4, long arg_5) {
   UNUSED(arg_1, arg_2, arg_3, arg_4, arg_5);
-  KAPI_TRACE("unimplemented syscall __NR_execveat");
+  TRACE("unimplemented syscall __NR_execveat");
   errno = ENOSYS;
   return -1;
 }
 
+// sys_fadvise64 has a different entry-point symbol name between riscv64 and x86_64.
+#ifdef __x86_64__
 long RunGuestSyscall___NR_fadvise64(long arg_1, long arg_2, long arg_3, long arg_4) {
   // on 64-bit architectures, sys_fadvise64 and sys_fadvise64_64 are equal.
   return syscall(__NR_fadvise64, arg_1, arg_2, arg_3, arg_4);
 }
+#endif
 
 long RunGuestSyscall___NR_ioctl(long arg_1, long arg_2, long arg_3) {
   // TODO(b/128614662): translate!
-  KAPI_TRACE("unimplemented ioctl 0x%lx, running host syscall as is", arg_2);
+  TRACE("unimplemented ioctl 0x%lx, running host syscall as is", arg_2);
   return syscall(__NR_ioctl, arg_1, arg_2, arg_3);
 }
 
@@ -134,6 +140,8 @@ long RunGuestSyscall___NR_riscv_hwprobe(long arg_1,
 }
 
 long RunGuestSyscall___NR_riscv_flush_icache(long arg_1, long arg_2, long arg_3) {
+// TODO(b/346604197): Enable on arm64 once runtime_primitives are ready.
+#ifdef __x86_64__
   static constexpr uint64_t kFlagsLocal = 1UL;
   static constexpr uint64_t kFlagsAll = kFlagsLocal;
 
@@ -150,20 +158,37 @@ long RunGuestSyscall___NR_riscv_flush_icache(long arg_1, long arg_2, long arg_3)
   TRACE("icache flush: [0x%lx, 0x%lx)", start, end);
   InvalidateGuestRange(start, end);
   return 0;
+#else
+  UNUSED(arg_1, arg_2, arg_3);
+  TRACE("unimplemented syscall __NR_riscv_flush_icache");
+  errno = ENOSYS;
+  return -1;
+#endif
 }
 
 // RunGuestSyscallImpl.
+#if defined(__aarch64__)
+#include "gen_syscall_emulation_riscv64_to_arm64-inl.h"
+#elif defined(__x86_64__)
 #include "gen_syscall_emulation_riscv64_to_x86_64-inl.h"
+#else
+#error "Unsupported host arch"
+#endif
 
 }  // namespace
 
 void RunGuestSyscall(ThreadState* state) {
+#ifdef __x86_64__
   // ATTENTION: run guest signal handlers instantly!
   // If signal arrives while in a syscall, syscall should immediately return with EINTR.
   // In this case pending signals are OK, as guest handlers will run on return from syscall.
   // BUT, if signal action has SA_RESTART, certain syscalls will restart instead of returning.
   // In this case, pending signals will never run...
   ScopedPendingSignalsDisabler scoped_pending_signals_disabler(state->thread);
+#else
+  // TODO(b/346604197): Enable on arm64 once guest_os_primitives is ported.
+  TRACE("ScopedPendingSignalsDisabler is not available on this arch");
+#endif
   ScopedErrno scoped_errno;
 
   long guest_nr = state->cpu.x[A7];
diff --git a/kernel_api/riscv64/syscall_emulation_arch.cc b/kernel_api/riscv64/syscall_emulation_arch.cc
index df2b565b..fc65337b 100644
--- a/kernel_api/riscv64/syscall_emulation_arch.cc
+++ b/kernel_api/riscv64/syscall_emulation_arch.cc
@@ -18,10 +18,8 @@
 
 #include <cstddef>
 #include <tuple>
-#include <utility>
 
 #include "berberis/guest_state/guest_addr.h"
-#include "berberis/kernel_api/exec_emulation.h"
 #include "berberis/kernel_api/fcntl_emulation.h"
 #include "berberis/kernel_api/sys_ptrace_emulation.h"
 
@@ -29,11 +27,6 @@
 
 namespace berberis {
 
-std::pair<const char*, size_t> GetGuestPlatformVarPrefixWithSize() {
-  static constexpr char kGuestPlatformVarPrefix[] = "BERBERIS_GUEST_";
-  return {kGuestPlatformVarPrefix, sizeof(kGuestPlatformVarPrefix) - 1};
-}
-
 std::tuple<bool, int> GuestFcntlArch(int, int, long) {
   return {false, -1};
 }
diff --git a/kernel_api/runtime_bridge_riscv64_to_arm64.cc b/kernel_api/runtime_bridge_riscv64_to_arm64.cc
new file mode 100644
index 00000000..f3b480ce
--- /dev/null
+++ b/kernel_api/runtime_bridge_riscv64_to_arm64.cc
@@ -0,0 +1,109 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "berberis/kernel_api/runtime_bridge.h"
+
+#include <cerrno>
+
+#include "berberis/base/macros.h"
+#include "berberis/base/tracing.h"
+
+namespace berberis {
+
+long RunGuestSyscall___NR_rt_sigaction(long sig_num_arg,
+                                       long act_arg,
+                                       long old_act_arg,
+                                       long sigset_size_arg) {
+  UNUSED(sig_num_arg, act_arg, old_act_arg, sigset_size_arg);
+  TRACE("unimplemented syscall __NR_rt_sigaction");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_sigaltstack(long stack, long old_stack) {
+  UNUSED(stack, old_stack);
+  TRACE("unimplemented syscall __NR_sigaltstack");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_timer_create(long arg_1, long arg_2, long arg_3) {
+  UNUSED(arg_1, arg_2, arg_3);
+  TRACE("unimplemented syscall __NR_timer_create");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_exit(long arg) {
+  UNUSED(arg);
+  TRACE("unimplemented syscall __NR_exit");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_clone(long arg_1, long arg_2, long arg_3, long arg_4, long arg_5) {
+  UNUSED(arg_1, arg_2, arg_3, arg_4, arg_5);
+  TRACE("unimplemented syscall __NR_clone");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_mmap(long arg_1,
+                               long arg_2,
+                               long arg_3,
+                               long arg_4,
+                               long arg_5,
+                               long arg_6) {
+  UNUSED(arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+  TRACE("unimplemented syscall __NR_mmap");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_mmap2(long arg_1,
+                                long arg_2,
+                                long arg_3,
+                                long arg_4,
+                                long arg_5,
+                                long arg_6) {
+  UNUSED(arg_1, arg_2, arg_3, arg_4, arg_5, arg_6);
+  TRACE("unimplemented syscall __NR_mmap2");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_munmap(long arg_1, long arg_2) {
+  UNUSED(arg_1, arg_2);
+  TRACE("unimplemented syscall __NR_munmap");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_mprotect(long arg_1, long arg_2, long arg_3) {
+  UNUSED(arg_1, arg_2, arg_3);
+  TRACE("unimplemented syscall __NR_mprotect");
+  errno = ENOSYS;
+  return -1;
+}
+
+long RunGuestSyscall___NR_mremap(long arg_1, long arg_2, long arg_3, long arg_4, long arg_5) {
+  UNUSED(arg_1, arg_2, arg_3, arg_4, arg_5);
+  TRACE("unimplemented syscall __NR_mremap");
+  errno = ENOSYS;
+  return -1;
+}
+
+}  // namespace berberis
diff --git a/kernel_api/sys_ptrace_emulation.cc b/kernel_api/sys_ptrace_emulation.cc
index d3c7b5d6..4832c7ec 100644
--- a/kernel_api/sys_ptrace_emulation.cc
+++ b/kernel_api/sys_ptrace_emulation.cc
@@ -24,7 +24,7 @@
 #include <cerrno>
 #include <cstring>
 
-#include "berberis/kernel_api/tracing.h"
+#include "berberis/base/tracing.h"
 
 namespace berberis {
 
@@ -68,11 +68,11 @@ int PtraceForGuest(int int_request, pid_t pid, void* addr, void* data) {
     case PTRACE_POKETEXT:
       return ptrace(request, pid, addr, data);
     case PTRACE_GETSIGINFO:
-      KAPI_TRACE("not implemented: ptrace(PTRACE_GETSIGINFO, ...)");
+      TRACE("not implemented: ptrace(PTRACE_GETSIGINFO, ...)");
       errno = EPERM;
       return -1;
     case PTRACE_GETREGSET:
-      KAPI_TRACE("not implemented: ptrace(PTRACE_GETREGSET, ...)");
+      TRACE("not implemented: ptrace(PTRACE_GETREGSET, ...)");
       if (data) {
         // Even in case of error, kernel sets iov_len to amount of data written.
         auto iov = reinterpret_cast<iovec*>(data);
@@ -83,11 +83,11 @@ int PtraceForGuest(int int_request, pid_t pid, void* addr, void* data) {
       }
       return -1;
     case PTRACE_SETREGSET:
-      KAPI_TRACE("not implemented: ptrace(PTRACE_SETREGSET, ...)");
+      TRACE("not implemented: ptrace(PTRACE_SETREGSET, ...)");
       errno = EINVAL;
       return -1;
     default:
-      KAPI_TRACE("not implemented: ptrace(0x%x, ...)", request);
+      TRACE("not implemented: ptrace(0x%x, ...)", request);
       errno = EPERM;
       return -1;
   }
diff --git a/kernel_api/tools/gen_kernel_syscalls_translation.py b/kernel_api/tools/gen_kernel_syscalls_translation.py
index bef712e8..a1a0488c 100755
--- a/kernel_api/tools/gen_kernel_syscalls_translation.py
+++ b/kernel_api/tools/gen_kernel_syscalls_translation.py
@@ -133,7 +133,7 @@ long RunGuestSyscallImpl(long guest_nr,
     params = _get_syscall_params(src_syscall, guest_api)
     if params is None:
       print('      // missing prototype')
-      print('      KAPI_TRACE("unsupported syscall %s");' % (name))
+      print('      TRACE("unsupported syscall %s");' % (name))
       print('      errno = ENOSYS;')
       print('      return -1;')
       continue
diff --git a/lite_translator/riscv64_to_x86_64/call_intrinsic.h b/lite_translator/riscv64_to_x86_64/call_intrinsic.h
index a2816010..75d4f453 100644
--- a/lite_translator/riscv64_to_x86_64/call_intrinsic.h
+++ b/lite_translator/riscv64_to_x86_64/call_intrinsic.h
@@ -53,7 +53,7 @@ inline constexpr auto kRegOffsetsOnStack = []() {
 
   int8_t stack_allocation_size = 0;
   for (auto reg : kCallerSavedRegs) {
-    regs_on_stack[reg.num] = stack_allocation_size;
+    regs_on_stack[reg.GetPhysicalIndex()] = stack_allocation_size;
     ++stack_allocation_size;
   }
   return regs_on_stack;
@@ -88,7 +88,7 @@ inline constexpr auto kSimdRegOffsetsOnStack = []() {
 
   int8_t stack_allocation_size = AlignUp(std::size(kCallerSavedRegs), 2);
   for (auto reg : kCallerSavedXMMRegs) {
-    simd_regs_on_stack[reg.num] = stack_allocation_size;
+    simd_regs_on_stack[reg.GetPhysicalIndex()] = stack_allocation_size;
     stack_allocation_size += 2;
   }
   return simd_regs_on_stack;
@@ -107,11 +107,11 @@ inline void PushCallerSaved(MacroAssembler<x86_64::Assembler>& as) {
   as.Subq(as.rsp, kSaveAreaSize * 8);
 
   for (auto reg : kCallerSavedRegs) {
-    as.Movq({.base = as.rsp, .disp = kRegOffsetsOnStack[reg.num] * 8}, reg);
+    as.Movq({.base = as.rsp, .disp = kRegOffsetsOnStack[reg.GetPhysicalIndex()] * 8}, reg);
   }
 
   for (auto reg : kCallerSavedXMMRegs) {
-    as.Movdqa({.base = as.rsp, .disp = kSimdRegOffsetsOnStack[reg.num] * 8}, reg);
+    as.Movdqa({.base = as.rsp, .disp = kSimdRegOffsetsOnStack[reg.GetPhysicalIndex()] * 8}, reg);
   }
 }
 
@@ -120,13 +120,14 @@ inline void PushCallerSaved(MacroAssembler<x86_64::Assembler>& as) {
 // kRegIsNotOnStack. These registers are skipped during restoration process.
 inline void PopCallerSaved(MacroAssembler<x86_64::Assembler>& as, const StoredRegsInfo regs_info) {
   for (auto reg : kCallerSavedRegs) {
-    if (regs_info.regs_on_stack[reg.num] != kRegIsNotOnStack) {
-      as.Movq(reg, {.base = as.rsp, .disp = regs_info.regs_on_stack[reg.num] * 8});
+    if (regs_info.regs_on_stack[reg.GetPhysicalIndex()] != kRegIsNotOnStack) {
+      as.Movq(reg, {.base = as.rsp, .disp = regs_info.regs_on_stack[reg.GetPhysicalIndex()] * 8});
     }
   }
   for (auto reg : kCallerSavedXMMRegs) {
-    if (regs_info.simd_regs_on_stack[reg.num] != kRegIsNotOnStack) {
-      as.Movdqa(reg, {.base = as.rsp, .disp = regs_info.simd_regs_on_stack[reg.num] * 8});
+    if (regs_info.simd_regs_on_stack[reg.GetPhysicalIndex()] != kRegIsNotOnStack) {
+      as.Movdqa(reg,
+                {.base = as.rsp, .disp = regs_info.simd_regs_on_stack[reg.GetPhysicalIndex()] * 8});
     }
   }
 
@@ -254,27 +255,27 @@ constexpr bool InitArgs(MacroAssembler&& as, bool has_avx, AssemblerArgType... a
     } else if constexpr (std::is_integral_v<IntrinsicType> &&
                          sizeof(IntrinsicType) <= sizeof(int32_t) &&
                          std::is_same_v<AssemblerType, Register>) {
-      if (kRegOffsetsOnStack[arg.value.num] == kRegIsNotOnStack) {
+      if (kRegOffsetsOnStack[arg.value.GetPhysicalIndex()] == kRegIsNotOnStack) {
         as.template Expand<int32_t, IntrinsicType>(kAbiArgs[gp_index++], arg.value);
       } else {
         as.template Expand<int32_t, IntrinsicType>(
             kAbiArgs[gp_index++],
-            {.base = Assembler::rsp, .disp = kRegOffsetsOnStack[arg.value.num] * 8});
+            {.base = Assembler::rsp, .disp = kRegOffsetsOnStack[arg.value.GetPhysicalIndex()] * 8});
       }
     } else if constexpr (std::is_integral_v<IntrinsicType> &&
                          sizeof(IntrinsicType) == sizeof(int64_t) &&
                          std::is_same_v<AssemblerType, Register>) {
-      if (kRegOffsetsOnStack[arg.value.num] == kRegIsNotOnStack) {
+      if (kRegOffsetsOnStack[arg.value.GetPhysicalIndex()] == kRegIsNotOnStack) {
         as.template Expand<int64_t, IntrinsicType>(kAbiArgs[gp_index++], arg.value);
       } else {
         as.template Expand<int64_t, IntrinsicType>(
             kAbiArgs[gp_index++],
-            {.base = Assembler::rsp, .disp = kRegOffsetsOnStack[arg.value.num] * 8});
+            {.base = Assembler::rsp, .disp = kRegOffsetsOnStack[arg.value.GetPhysicalIndex()] * 8});
       }
     } else if constexpr ((std::is_same_v<IntrinsicType, Float32> ||
                           std::is_same_v<IntrinsicType, Float64>)&&std::is_same_v<AssemblerType,
                                                                                   XMMRegister>) {
-      if (kSimdRegOffsetsOnStack[arg.value.num] == kRegIsNotOnStack) {
+      if (kSimdRegOffsetsOnStack[arg.value.GetPhysicalIndex()] == kRegIsNotOnStack) {
         if (has_avx) {
           as.template Vmovs<IntrinsicType>(
               kAbiSimdArgs[simd_index], kAbiSimdArgs[simd_index], arg.value);
@@ -286,11 +287,11 @@ constexpr bool InitArgs(MacroAssembler&& as, bool has_avx, AssemblerArgType... a
         if (has_avx) {
           as.template Vmovs<IntrinsicType>(
               kAbiSimdArgs[simd_index++],
-              {.base = as.rsp, .disp = kSimdRegOffsetsOnStack[arg.value.num] * 8});
+              {.base = as.rsp, .disp = kSimdRegOffsetsOnStack[arg.value.GetPhysicalIndex()] * 8});
         } else {
           as.template Movs<IntrinsicType>(
               kAbiSimdArgs[simd_index++],
-              {.base = as.rsp, .disp = kSimdRegOffsetsOnStack[arg.value.num] * 8});
+              {.base = as.rsp, .disp = kSimdRegOffsetsOnStack[arg.value.GetPhysicalIndex()] * 8});
         }
       }
     } else {
@@ -318,18 +319,18 @@ StoredRegsInfo ForwardResults(MacroAssembler<x86_64::Assembler>& as, AssemblerRe
   if constexpr (Assembler::kFormatIs<IntrinsicResType, std::tuple<int32_t>, std::tuple<uint32_t>> &&
                 std::is_same_v<AssemblerResType, Register>) {
     // Note: even unsigned 32-bit results are sign-extended to 64bit register on RV64.
-    regs_info.regs_on_stack[result.num] = kRegIsNotOnStack;
+    regs_info.regs_on_stack[result.GetPhysicalIndex()] = kRegIsNotOnStack;
     as.Expand<int64_t, int32_t>(result, Assembler::rax);
   } else if constexpr (Assembler::
                            kFormatIs<IntrinsicResType, std::tuple<int64_t>, std::tuple<uint64_t>> &&
                        std::is_same_v<AssemblerResType, Register>) {
-    regs_info.regs_on_stack[result.num] = kRegIsNotOnStack;
+    regs_info.regs_on_stack[result.GetPhysicalIndex()] = kRegIsNotOnStack;
     as.Mov<int64_t>(result, Assembler::rax);
   } else if constexpr (Assembler::
                            kFormatIs<IntrinsicResType, std::tuple<Float32>, std::tuple<Float64>> &&
                        std::is_same_v<AssemblerResType, XMMRegister>) {
     using ResType0 = std::tuple_element_t<0, IntrinsicResType>;
-    regs_info.simd_regs_on_stack[result.num] = kRegIsNotOnStack;
+    regs_info.simd_regs_on_stack[result.GetPhysicalIndex()] = kRegIsNotOnStack;
     if (host_platform::kHasAVX) {
       as.Vmovs<ResType0>(result, result, Assembler::xmm0);
     } else {
@@ -341,11 +342,11 @@ StoredRegsInfo ForwardResults(MacroAssembler<x86_64::Assembler>& as, AssemblerRe
     auto [result0, result1] = result;
     if constexpr (Assembler::kFormatIs<ResType0, int32_t, uint32_t> &&
                   std::is_same_v<std::tuple_element_t<0, AssemblerResType>, Register>) {
-      regs_info.regs_on_stack[result0.num] = kRegIsNotOnStack;
+      regs_info.regs_on_stack[result0.GetPhysicalIndex()] = kRegIsNotOnStack;
       as.Expand<int64_t, int32_t>(result0, Assembler::rax);
     } else if constexpr (Assembler::kFormatIs<ResType0, int64_t, uint64_t> &&
                          std::is_same_v<std::tuple_element_t<0, AssemblerResType>, Register>) {
-      regs_info.regs_on_stack[result0.num] = kRegIsNotOnStack;
+      regs_info.regs_on_stack[result0.GetPhysicalIndex()] = kRegIsNotOnStack;
       as.Mov<int64_t>(result0, Assembler::rax);
     } else {
       static_assert(kDependentTypeFalse<std::tuple<IntrinsicResType, AssemblerResType>>,
@@ -353,11 +354,11 @@ StoredRegsInfo ForwardResults(MacroAssembler<x86_64::Assembler>& as, AssemblerRe
     }
     if constexpr (Assembler::kFormatIs<ResType1, int32_t, uint32_t> &&
                   std::is_same_v<std::tuple_element_t<1, AssemblerResType>, Register>) {
-      regs_info.regs_on_stack[result1.num] = kRegIsNotOnStack;
+      regs_info.regs_on_stack[result1.GetPhysicalIndex()] = kRegIsNotOnStack;
       as.Expand<int64_t, int32_t>(result1, Assembler::rdx);
     } else if constexpr (Assembler::kFormatIs<ResType1, int64_t, uint64_t> &&
                          std::is_same_v<std::tuple_element_t<1, AssemblerResType>, Register>) {
-      regs_info.regs_on_stack[result1.num] = kRegIsNotOnStack;
+      regs_info.regs_on_stack[result1.GetPhysicalIndex()] = kRegIsNotOnStack;
       as.Mov<int64_t>(result1, Assembler::rdx);
     } else {
       static_assert(kDependentTypeFalse<std::tuple<IntrinsicResType, AssemblerResType>>,
@@ -377,10 +378,25 @@ StoredRegsInfo ForwardResults(MacroAssembler<x86_64::Assembler>& as, AssemblerRe
 
 template <typename IntrinsicResType, typename... IntrinsicArgType, typename... AssemblerArgType>
 void InitArgsVerify(AssemblerArgType...) {
+  constexpr auto MakeDummyAssemblerType = []<typename AssemblerType>() {
+    if constexpr (std::is_same_v<AssemblerType, x86_64::Assembler::Register>) {
+      // Note: we couldn't use no_register here, but any “real” register should work.
+      return x86_64::Assembler::rax;
+    } else if constexpr (std::is_same_v<AssemblerType, x86_64::Assembler::XMMRegister>) {
+      // Note: we couldn't use no_xmm_register here, but any “real” register should work.
+      return x86_64::Assembler::xmm0;
+    } else {
+      return AssemblerType{0};
+    }
+  };
   static_assert(InitArgs<IntrinsicResType, IntrinsicArgType...>(
-      ConstExprCheckAssembler(), true, AssemblerArgType{0}...));
+      ConstExprCheckAssembler(),
+      true,
+      MakeDummyAssemblerType.template operator()<AssemblerArgType>()...));
   static_assert(InitArgs<IntrinsicResType, IntrinsicArgType...>(
-      ConstExprCheckAssembler(), false, AssemblerArgType{0}...));
+      ConstExprCheckAssembler(),
+      false,
+      MakeDummyAssemblerType.template operator()<AssemblerArgType>()...));
 }
 
 template <typename AssemblerResType,
diff --git a/lite_translator/riscv64_to_x86_64/inline_intrinsic.h b/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
index fa930da1..04896728 100644
--- a/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
+++ b/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
@@ -201,8 +201,6 @@ class TryBindingBasedInlineIntrinsic {
                                  AssemblerResTypeForFriend result,
                                  AssemblerArgTypeForFriend... args);
   template <auto kFunc,
-            typename Assembler_common_x86,
-            typename Assembler_x86_64,
             typename MacroAssembler,
             typename Result,
             typename Callback,
@@ -210,15 +208,14 @@ class TryBindingBasedInlineIntrinsic {
   friend Result intrinsics::bindings::ProcessBindings(Callback callback,
                                                       Result def_result,
                                                       Args&&... args);
-  template <
-      auto kIntrinsicTemplateName,
-      auto kMacroInstructionTemplateName,
-      auto kMnemo,
-      typename GetOpcode,
-      intrinsics::bindings::CPUIDRestriction kCPUIDRestrictionTemplateValue,
-      intrinsics::bindings::PreciseNanOperationsHandling kPreciseNanOperationsHandlingTemplateValue,
-      bool kSideEffectsTemplateValue,
-      typename... Types>
+  template <auto kIntrinsicTemplateName,
+            auto kMacroInstructionTemplateName,
+            auto kMnemo,
+            typename GetOpcode,
+            typename kCPUIDRestrictionTemplateValue,
+            typename kPreciseNanOperationsHandlingTemplateValue,
+            bool kSideEffectsTemplateValue,
+            typename... Types>
   friend class intrinsics::bindings::AsmCallInfo;
 
   TryBindingBasedInlineIntrinsic() = delete;
@@ -237,38 +234,37 @@ class TryBindingBasedInlineIntrinsic {
         simd_reg_alloc_(simd_reg_alloc),
         result_{result},
         input_args_(std::tuple{args...}),
-        success_(
-            intrinsics::bindings::ProcessBindings<kFunction,
-                                                  AssemblerX86<x86_64::Assembler>,
-                                                  x86_64::Assembler,
-                                                  std::tuple<MacroAssembler<x86_64::Assembler>>,
-                                                  bool,
-                                                  TryBindingBasedInlineIntrinsic&>(*this, false)) {}
+        success_(intrinsics::bindings::ProcessBindings<
+                 kFunction,
+                 typename MacroAssembler<x86_64::Assembler>::MacroAssemblers,
+                 bool,
+                 TryBindingBasedInlineIntrinsic&>(*this, false)) {}
   operator bool() { return success_; }
 
   template <typename AsmCallInfo>
   std::optional<bool> /*ProcessBindingsClient*/ operator()(AsmCallInfo asm_call_info) {
     static_assert(std::is_same_v<decltype(kFunction), typename AsmCallInfo::IntrinsicType>);
-    static_assert(AsmCallInfo::kPreciseNanOperationsHandling ==
-                  intrinsics::bindings::kNoNansOperation);
-    if constexpr (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasAVX) {
+    static_assert(std::is_same_v<typename AsmCallInfo::PreciseNanOperationsHandling,
+                                 intrinsics::bindings::NoNansOperation>);
+    using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
+    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
       if (!host_platform::kHasAVX) {
         return false;
       }
-    } else if constexpr (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasBMI) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
       if (!host_platform::kHasBMI) {
         return false;
       }
-    } else if constexpr (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasLZCNT) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>) {
       if (!host_platform::kHasLZCNT) {
         return false;
       }
-    } else if constexpr (AsmCallInfo::kCPUIDRestriction == intrinsics::bindings::kHasPOPCNT) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>) {
       if (!host_platform::kHasPOPCNT) {
         return false;
       }
-    } else if constexpr (AsmCallInfo::kCPUIDRestriction ==
-                         intrinsics::bindings::kNoCPUIDRestriction) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        intrinsics::bindings::NoCPUIDRestriction>) {
       // No restrictions. Do nothing.
     } else {
       static_assert(kDependentValueFalse<AsmCallInfo::kCPUIDRestriction>);
@@ -285,14 +281,14 @@ class TryBindingBasedInlineIntrinsic {
       if constexpr (std::is_integral_v<ReturnType>) {
         if (result_reg_ != x86_64::Assembler::no_register) {
           Mov<ReturnType>(as_, result_, result_reg_);
-          CHECK_EQ(result_xmm_reg_.num, x86_64::Assembler::no_xmm_register.num);
+          CHECK_EQ(result_xmm_reg_, x86_64::Assembler::no_xmm_register);
         } else if (result_xmm_reg_ != x86_64::Assembler::no_xmm_register) {
           Mov<typename TypeTraits<ReturnType>::Float>(as_, result_, result_xmm_reg_);
-          CHECK_EQ(result_reg_.num, x86_64::Assembler::no_register.num);
+          CHECK_EQ(result_reg_, x86_64::Assembler::no_register);
         }
       } else {
-        CHECK_EQ(result_reg_.num, x86_64::Assembler::no_register.num);
-        CHECK_EQ(result_xmm_reg_.num, x86_64::Assembler::no_xmm_register.num);
+        CHECK_EQ(result_reg_, x86_64::Assembler::no_register);
+        CHECK_EQ(result_xmm_reg_, x86_64::Assembler::no_xmm_register);
       }
       if constexpr (std::is_integral_v<ReturnType> && sizeof(ReturnType) < sizeof(std::int32_t)) {
         // Don't handle these types just yet. We are not sure how to expand them and there
@@ -358,7 +354,7 @@ class TryBindingBasedInlineIntrinsic {
         if constexpr (RegisterClass::kAsRegister == 'x' && std::is_integral_v<Type>) {
           static_assert(std::is_integral_v<
                         std::tuple_element_t<arg_info.to, typename AsmCallInfo::OutputArguments>>);
-          CHECK_EQ(result_xmm_reg_.num, x86_64::Assembler::no_xmm_register.num);
+          CHECK_EQ(result_xmm_reg_, x86_64::Assembler::no_xmm_register);
           result_xmm_reg_ = reg_alloc();
           Mov<typename TypeTraits<int64_t>::Float>(
               as_, result_xmm_reg_, std::get<arg_info.from>(input_args_));
@@ -390,7 +386,7 @@ class TryBindingBasedInlineIntrinsic {
         static_assert(std::is_same_v<Usage, intrinsics::bindings::UseDef>);
         static_assert(RegisterClass::kIsImplicitReg);
         if constexpr (RegisterClass::kAsRegister == 'a') {
-          CHECK_EQ(result_reg_.num, x86_64::Assembler::no_register.num);
+          CHECK_EQ(result_reg_, x86_64::Assembler::no_register);
           Mov<Type>(as_, as_.rax, std::get<arg_info.from>(input_args_));
           result_reg_ = as_.rax;
           return std::tuple{};
@@ -402,17 +398,17 @@ class TryBindingBasedInlineIntrinsic {
         static_assert(std::is_same_v<Usage, intrinsics::bindings::Def> ||
                       std::is_same_v<Usage, intrinsics::bindings::DefEarlyClobber>);
         if constexpr (RegisterClass::kAsRegister == 'a') {
-          CHECK_EQ(result_reg_.num, x86_64::Assembler::no_register.num);
+          CHECK_EQ(result_reg_, x86_64::Assembler::no_register);
           result_reg_ = as_.rax;
           return std::tuple{};
         } else if constexpr (RegisterClass::kAsRegister == 'c') {
-          CHECK_EQ(result_reg_.num, x86_64::Assembler::no_register.num);
+          CHECK_EQ(result_reg_, x86_64::Assembler::no_register);
           result_reg_ = as_.rcx;
           return std::tuple{};
         } else {
           static_assert(!RegisterClass::kIsImplicitReg);
           if constexpr (RegisterClass::kAsRegister == 'x' && std::is_integral_v<Type>) {
-            CHECK_EQ(result_xmm_reg_.num, x86_64::Assembler::no_xmm_register.num);
+            CHECK_EQ(result_xmm_reg_, x86_64::Assembler::no_xmm_register);
             result_xmm_reg_ = reg_alloc();
             return std::tuple{result_xmm_reg_};
           } else {
diff --git a/lite_translator/riscv64_to_x86_64/lite_translator.cc b/lite_translator/riscv64_to_x86_64/lite_translator.cc
index 707bb30a..0a6ed2ec 100644
--- a/lite_translator/riscv64_to_x86_64/lite_translator.cc
+++ b/lite_translator/riscv64_to_x86_64/lite_translator.cc
@@ -126,7 +126,7 @@ Register LiteTranslator::Op(Decoder::OpOpcode opcode, Register arg1, Register ar
       break;
     default:
       Undefined();
-      return {};
+      return Assembler::no_register;
   }
   return res;
 }
@@ -168,7 +168,7 @@ Register LiteTranslator::Op32(Decoder::Op32Opcode opcode, Register arg1, Registe
       break;
     default:
       Undefined();
-      return {};
+      return Assembler::no_register;
   }
   return res;
 }
@@ -205,7 +205,7 @@ Register LiteTranslator::OpImm(Decoder::OpImmOpcode opcode, Register arg, int16_
       break;
     default:
       Undefined();
-      return {};
+      return Assembler::no_register;
   }
   return res;
 }
@@ -220,7 +220,7 @@ Register LiteTranslator::OpImm32(Decoder::OpImm32Opcode opcode, Register arg, in
       break;
     default:
       Undefined();
-      return {};
+      return Assembler::no_register;
   }
   return res;
 }
@@ -259,7 +259,7 @@ Register LiteTranslator::ShiftImm32(Decoder::ShiftImm32Opcode opcode, Register a
     as_.SarlByCl(res);
   } else {
     Undefined();
-    return {};
+    return Assembler::no_register;
   }
   as_.Movsxlq(res, res);
   return res;
@@ -397,7 +397,7 @@ Register LiteTranslator::Load(Decoder::LoadOperandType operand_type, Register ar
       break;
     default:
       Undefined();
-      return {};
+      return Assembler::no_register;
   }
 
   // TODO(b/144326673): Emit the recovery code at the end of the region so it doesn't interrupt
@@ -463,7 +463,7 @@ Register LiteTranslator::UpdateCsr(Decoder::CsrOpcode opcode, Register arg, Regi
       break;
     default:
       Undefined();
-      return {};
+      return Assembler::no_register;
   }
   return res;
 }
@@ -484,7 +484,7 @@ Register LiteTranslator::UpdateCsr(Decoder::CsrImmOpcode opcode, uint8_t imm, Re
       break;
     default:
       Undefined();
-      return {};
+      return Assembler::no_register;
   }
   return res;
 }
diff --git a/lite_translator/riscv64_to_x86_64/lite_translator.h b/lite_translator/riscv64_to_x86_64/lite_translator.h
index 58843a38..50407baa 100644
--- a/lite_translator/riscv64_to_x86_64/lite_translator.h
+++ b/lite_translator/riscv64_to_x86_64/lite_translator.h
@@ -51,9 +51,11 @@ class LiteTranslator {
   using CsrName = berberis::CsrName;
   using Decoder = Decoder<SemanticsPlayer<LiteTranslator>>;
   using Register = Assembler::Register;
+  static constexpr auto no_register = Assembler::no_register;
   // Note: on RISC-V architecture FP register and SIMD registers are disjoint, but on x86 they are
   // the same.
   using FpRegister = Assembler::XMMRegister;
+  static constexpr auto no_fp_register = Assembler::no_xmm_register;
   using SimdRegister = Assembler::XMMRegister;
   using Condition = Assembler::Condition;
   using Float32 = intrinsics::Float32;
@@ -105,7 +107,7 @@ class LiteTranslator {
                  Register arg5) {
     UNUSED(syscall_nr, arg0, arg1, arg2, arg3, arg4, arg5);
     Undefined();
-    return {};
+    return Assembler::no_register;
   }
 
   void Fence(Decoder::FenceOpcode /*opcode*/,
@@ -378,7 +380,7 @@ class LiteTranslator {
       return {alloc_result.value(), true};
     }
     success_ = false;
-    return {{}, false};
+    return {Assembler::no_register, false};
   }
 
   std::tuple<SimdRegister, bool> GetMappedFpRegOrMap(int reg) {
@@ -391,7 +393,7 @@ class LiteTranslator {
       return {alloc_result.value(), true};
     }
     success_ = false;
-    return {{}, false};
+    return {Assembler::no_xmm_register, false};
   }
 
   Register AllocTempReg() {
@@ -399,7 +401,7 @@ class LiteTranslator {
       return reg_option.value();
     }
     success_ = false;
-    return {};
+    return Assembler::no_register;
   };
 
   SimdRegister AllocTempSimdReg() {
@@ -407,19 +409,19 @@ class LiteTranslator {
       return reg_option.value();
     }
     success_ = false;
-    return {};
+    return Assembler::no_xmm_register;
   };
 
   template <typename IntType, bool aq, bool rl>
   Register Lr(Register /* addr */) {
     Undefined();
-    return {};
+    return Assembler::no_register;
   }
 
   template <typename IntType, bool aq, bool rl>
   Register Sc(Register /* addr */, Register /* data */) {
     Undefined();
-    return {};
+    return Assembler::no_register;
   }
 
  private:
@@ -436,18 +438,19 @@ class LiteTranslator {
       }
       call_intrinsic::CallIntrinsic<AssemblerResType>(as_, kFunction, args...);
     } else {
-      AssemblerResType result;
-      if constexpr (std::is_same_v<AssemblerResType, Register>) {
-        result = AllocTempReg();
-      } else if constexpr (std::is_same_v<AssemblerResType, std::tuple<Register, Register>>) {
-        result = std::tuple{AllocTempReg(), AllocTempReg()};
-      } else if constexpr (std::is_same_v<AssemblerResType, SimdRegister>) {
-        result = AllocTempSimdReg();
-      } else {
-        // This should not be reached by the compiler. If it is - there is a new result type that
-        // needs to be supported.
-        static_assert(kDependentTypeFalse<AssemblerResType>, "Unsupported result type");
-      }
+      AssemblerResType result = [this] {
+        if constexpr (std::is_same_v<AssemblerResType, Register>) {
+          return AllocTempReg();
+        } else if constexpr (std::is_same_v<AssemblerResType, std::tuple<Register, Register>>) {
+          return std::tuple{AllocTempReg(), AllocTempReg()};
+        } else if constexpr (std::is_same_v<AssemblerResType, SimdRegister>) {
+          return AllocTempSimdReg();
+        } else {
+          // This should not be reached by the compiler. If it is - there is a new result type that
+          // needs to be supported.
+          static_assert(kDependentTypeFalse<AssemblerResType>, "Unsupported result type");
+        }
+      }();
 
       if (inline_intrinsic::TryInlineIntrinsic<kFunction>(
               as_,
diff --git a/lite_translator/riscv64_to_x86_64/lite_translator_tests.cc b/lite_translator/riscv64_to_x86_64/lite_translator_tests.cc
index 4791ad2d..e2b9006c 100644
--- a/lite_translator/riscv64_to_x86_64/lite_translator_tests.cc
+++ b/lite_translator/riscv64_to_x86_64/lite_translator_tests.cc
@@ -84,7 +84,7 @@ TEST(Riscv64LiteTranslatorTest, GetFpReg) {
 TEST(Riscv64LiteTranslatorTest, NanBoxAndSetFpReg) {
   MachineCode machine_code;
   LiteTranslator translator(&machine_code, 0);
-  LiteTranslator::FpRegister reg;
+  LiteTranslator::FpRegister reg = x86_64::Assembler::xmm0;
   int32_t offset = offsetof(ThreadState, cpu.f) + 1 * sizeof(LiteTranslator::Float64);
   size_t store_insn_base = machine_code.install_size();
   translator.StoreFpReg(reg, offset);
@@ -112,7 +112,7 @@ TEST(Riscv64LiteTranslatorTest, NanBoxAndSetFpReg) {
 TEST(Riscv64LiteTranslatorTest, SetReg) {
   MachineCode machine_code;
   LiteTranslator translator(&machine_code, 0);
-  LiteTranslator::Register reg;
+  LiteTranslator::Register reg = x86_64::Assembler::rax;
   int32_t offset = offsetof(ThreadState, cpu.x[0]) + 1 * 8;
   size_t store_insn_base = machine_code.install_size();
   translator.as()->Movq({.base = translator.as()->rbp, .disp = offset}, reg);
diff --git a/program_runner/Android.bp b/program_runner/Android.bp
index 91995fbd..f9f93e88 100644
--- a/program_runner/Android.bp
+++ b/program_runner/Android.bp
@@ -46,14 +46,56 @@ cc_defaults {
     ],
 }
 
+cc_defaults {
+    name: "berberis_program_runner_arm64_defaults",
+    defaults: ["berberis_all_hosts_defaults_64"],
+    host_supported: true,
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_guest_state_headers",
+    ],
+    static_libs: [
+        "libberberis_base",
+        "libberberis_guest_state_riscv64",
+        "libberberis_interpreter_riscv64",
+        "libberberis_kernel_api_riscv64",
+        "libberberis_tinyloader",
+    ],
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    arch: {
+        x86_64: {
+            enabled: false,
+        },
+    },
+}
+
+filegroup {
+    name: "berberis_binfmt_misc_srcs",
+    srcs: ["main_binfmt_misc.cc"],
+}
+
+filegroup {
+    name: "berberis_program_runner_main_srcs",
+    srcs: ["main.cc"],
+}
+
 cc_binary {
     name: "berberis_program_runner_binfmt_misc_riscv64",
     defaults: ["berberis_program_runner_defaults"],
-    srcs: ["main_binfmt_misc.cc"],
+    srcs: [":berberis_binfmt_misc_srcs"],
 }
 
 cc_binary {
     name: "berberis_program_runner_riscv64",
     defaults: ["berberis_program_runner_defaults"],
-    srcs: ["main.cc"],
+    srcs: [":berberis_program_runner_main_srcs"],
+}
+
+cc_binary {
+    name: "berberis_program_runner_riscv64_to_arm64",
+    defaults: ["berberis_program_runner_arm64_defaults"],
+    srcs: [":berberis_program_runner_main_srcs"],
 }
diff --git a/program_runner/main.cc b/program_runner/main.cc
index 868d4bb8..b2249d19 100644
--- a/program_runner/main.cc
+++ b/program_runner/main.cc
@@ -21,15 +21,17 @@
 #include <cstdio>
 #include <cstring>
 #include <string>
-#include <tuple>
 
-#include "berberis/base/bit_util.h"
 #include "berberis/base/checks.h"
-#include "berberis/base/file.h"
-#include "berberis/guest_loader/guest_loader.h"
-#include "berberis/guest_state/guest_addr.h"
+
+#if defined(__i386__) || defined(__x86_64__)
 #include "berberis/program_runner/program_runner.h"
-#include "berberis/runtime/berberis.h"
+#elif defined(__aarch64__)
+#include "berberis/guest_state/guest_state.h"
+#include "berberis/interpreter/riscv64/interpreter.h"
+#include "berberis/tiny_loader/loaded_elf_file.h"
+#include "berberis/tiny_loader/tiny_loader.h"
+#endif
 
 // Program runner meant for testing and manual invocation.
 
@@ -39,39 +41,60 @@ namespace {
 
 void Usage(const char* argv_0) {
   printf(
-      "Usage: %s [-h] guest_executable [arg1 [arg2 ...]]\n"
-      "  -h             - print this message\n"
+      "Usage: %s [-h|?] [-l loader] [-s vdso] guest_executable [arg1 [arg2 ...]]\n"
+      "  -h, -?           - print this message\n"
+      "  -l loader        - path to guest loader\n"
+      "  -s vdso          - path to guest vdso\n"
       "  guest_executable - path to the guest executable\n",
       argv_0);
 }
 
 struct Options {
+  const char* guest_executable;
+  const char* loader_path;
+  const char* vdso_path;
   bool print_help_and_exit;
 };
 
 Options ParseArgs(int argc, char* argv[]) {
   CHECK_GE(argc, 1);
-
-  Options opts{};
-
-  while (true) {
-    int c = getopt(argc, argv, "+h:");
-    if (c < 0) {
+  static const Options kOptsError{.print_help_and_exit = true};
+  Options opts{
+      .guest_executable = nullptr,
+      .loader_path = nullptr,
+      .vdso_path = nullptr,
+      .print_help_and_exit = false,
+  };
+
+  int curr_arg = 1;
+  for (int curr_arg = 1; curr_arg < argc; ++curr_arg) {
+    if (argv[curr_arg][0] != '-') {
       break;
     }
-    switch (c) {
+    const char option = argv[curr_arg][1];
+    switch (option) {
+      case 's':
+      case 'l':
+        if (++curr_arg == argc) {
+          return kOptsError;
+        }
+        if (option == 's') {
+          opts.vdso_path = argv[curr_arg];
+        } else {
+          opts.loader_path = argv[curr_arg];
+        }
+        break;
       case 'h':
-        return Options{.print_help_and_exit = true};
+      case '?':
       default:
-        UNREACHABLE();
+        return kOptsError;
     }
   }
 
-  if (optind >= argc) {
-    return Options{.print_help_and_exit = true};
+  if (curr_arg >= argc) {
+    return kOptsError;
   }
 
-  opts.print_help_and_exit = false;
   return opts;
 }
 
@@ -79,7 +102,7 @@ Options ParseArgs(int argc, char* argv[]) {
 
 }  // namespace berberis
 
-int main(int argc, char* argv[], char* envp[]) {
+int main(int argc, char* argv[], [[maybe_unused]] char* envp[]) {
 #if defined(__GLIBC__)
   // Disable brk in glibc-malloc.
   //
@@ -98,6 +121,7 @@ int main(int argc, char* argv[], char* envp[]) {
   }
 
   std::string error_msg;
+#if defined(__i386__) || defined(__x86_64__) || defined(__riscv)
   if (!berberis::Run(
           // TODO(b/276787135): Make vdso and loader configurable via command line arguments.
           /* vdso_path */ nullptr,
@@ -109,6 +133,25 @@ int main(int argc, char* argv[], char* envp[]) {
     fprintf(stderr, "unable to start executable: %s\n", error_msg.c_str());
     return -1;
   }
+#elif defined(__aarch64__)
+  LoadedElfFile elf_file;
+  if (!TinyLoader::LoadFromFile(argv[optind], &elf_file, &error_msg)) {
+    fprintf(stderr, "unable to start load file: %s\n", error_msg.c_str());
+    return -1;
+  }
+  if (elf_file.e_type() != ET_EXEC) {
+    fprintf(stderr, "this is not a static executable file: %hu\n", elf_file.e_type());
+    return -1;
+  }
+
+  berberis::ThreadState state{};
+  state.cpu.insn_addr = berberis::ToGuestAddr(elf_file.entry_point());
+  while (true) {
+    InterpretInsn(&state);
+  }
+#else
+#error Unsupported platform
+#endif
 
   return 0;
 }
diff --git a/program_runner/main_binfmt_misc.cc b/program_runner/main_binfmt_misc.cc
index 0b0d691b..e5dac061 100644
--- a/program_runner/main_binfmt_misc.cc
+++ b/program_runner/main_binfmt_misc.cc
@@ -21,12 +21,11 @@
 
 // Basic program runner meant to be used by binfmt_misc utility.
 
-int main(int argc, const char* argv[], char* envp[]) {
+int main(int argc, const char* argv[], [[maybe_unused]] char* envp[]) {
   if (argc < 3) {
     printf("Usage: %s /full/path/to/program program [args...]", argv[0]);
     return 0;
   }
-
   std::string error_msg;
   if (!berberis::Run(
           /* vdso_path */ nullptr,
@@ -38,4 +37,4 @@ int main(int argc, const char* argv[], char* envp[]) {
     fprintf(stderr, "Error running %s: %s", argv[1], error_msg.c_str());
     return -1;
   }
-}
\ No newline at end of file
+}
diff --git a/runtime/Android.bp b/runtime/Android.bp
index 3a4d85df..c94e7905 100644
--- a/runtime/Android.bp
+++ b/runtime/Android.bp
@@ -31,8 +31,15 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "berberis_runtime_library_riscv64_srcs",
+    srcs: [
+        "runtime_library_riscv64.cc",
+    ],
+}
+
 cc_defaults {
-    name: "berberis_runtime_library_x86_64_defaults",
+    name: "berberis_runtime_library_defaults",
     arch: {
         x86_64: {
             srcs: [":berberis_runtime_library_x86_64_srcs"],
@@ -41,6 +48,13 @@ cc_defaults {
                 "libberberis_runtime_primitives_headers",
             ],
         },
+        riscv64: {
+            srcs: [":berberis_runtime_library_riscv64_srcs"],
+            header_libs: [
+                "libberberis_base_headers",
+                "libberberis_runtime_primitives_headers",
+            ],
+        },
     },
     // Targets using these defaults must provide the following guest-specific fields:
     // header_libs: ["libberberis_guest_state_<guest>_headers"],
@@ -51,7 +65,7 @@ cc_library_static {
     name: "libberberis_runtime_riscv64_to_x86_64",
     defaults: [
         "berberis_defaults_64",
-        "berberis_runtime_library_x86_64_defaults",
+        "berberis_runtime_library_defaults",
     ],
     host_supported: true,
     srcs: [
diff --git a/runtime/berberis.cc b/runtime/berberis.cc
index db47e8eb..fd17f31a 100644
--- a/runtime/berberis.cc
+++ b/runtime/berberis.cc
@@ -36,6 +36,7 @@ bool IsAddressGuestExecutable(GuestAddr pc) {
 
 bool InitBerberisUnsafe() {
   InitLargeMmap();
+  InitHostEntries();
   Tracing::Init();
   InitGuestThreadManager();
   InitGuestFunctionWrapper(&IsAddressGuestExecutable);
diff --git a/runtime/runtime_library_riscv64.cc b/runtime/runtime_library_riscv64.cc
new file mode 100644
index 00000000..5721e1d3
--- /dev/null
+++ b/runtime/runtime_library_riscv64.cc
@@ -0,0 +1,68 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "berberis/runtime_primitives/runtime_library.h"
+
+// TODO: b/352784623 - These need to be implemented by the time we activate
+// translation cache.
+
+namespace berberis {
+
+extern "C" {
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_RunGeneratedCode(ThreadState* state, HostCode code) {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Interpret() {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_ExitGeneratedCode() {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Stop() {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_NoExec() {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_NotTranslated() {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Translating() {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Invalidating() {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Wrapping() {
+  asm("unimp");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_HandleLightCounterThresholdReached() {
+  asm("unimp");
+}
+
+}  // extern "C"
+
+}  // namespace berberis
diff --git a/runtime_primitives/Android.bp b/runtime_primitives/Android.bp
index 5820a61f..38d5c006 100644
--- a/runtime_primitives/Android.bp
+++ b/runtime_primitives/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_runtime_primitives_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: [
@@ -36,12 +36,13 @@ cc_library_headers {
 
 cc_library_static {
     name: "libberberis_runtime_primitives",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     srcs: [
         "code_pool.cc",
         "crash_reporter.cc",
         "guest_function_wrapper_impl.cc",
+        "host_entries.cc",
         "host_function_wrapper_impl.cc",
         "known_guest_function_wrapper.cc",
         "platform.cc",
@@ -71,7 +72,7 @@ filegroup {
 
 cc_defaults {
     name: "berberis_memory_region_reservation_defaults",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     srcs: [":berberis_memory_region_reservation_srcs"],
     header_libs: [
diff --git a/runtime_primitives/host_entries.cc b/runtime_primitives/host_entries.cc
new file mode 100644
index 00000000..0cdd6d14
--- /dev/null
+++ b/runtime_primitives/host_entries.cc
@@ -0,0 +1,64 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "berberis/runtime_primitives/runtime_library.h"
+
+#if defined(__x86_64__)
+#include "berberis/assembler/machine_code.h"
+#include "berberis/assembler/x86_64.h"
+#include "berberis/runtime_primitives/code_pool.h"
+#endif
+
+namespace berberis {
+
+HostCode kEntryInterpret;
+HostCode kEntryExitGeneratedCode;
+HostCode kEntryStop;
+HostCode kEntryNoExec;
+HostCode kEntryNotTranslated;
+HostCode kEntryTranslating;
+HostCode kEntryInvalidating;
+HostCode kEntryWrapping;
+
+namespace {
+// This function installs a trampoline in the CodePool address space.
+// This needed to ensure that all entries in the translation cache
+// are always pointing to the memory allocated via CodePool.
+HostCode InstallEntryTrampoline(HostCode target_function_ptr) {
+#if defined(__x86_64__)
+  MachineCode mc;
+  x86_64::Assembler as(&mc);
+  as.Jmp(target_function_ptr);
+  as.Finalize();
+  return GetDefaultCodePoolInstance()->Add(&mc);
+#else
+  return target_function_ptr;
+#endif
+}
+}  // namespace
+
+void InitHostEntries() {
+  kEntryInterpret = InstallEntryTrampoline(AsHostCode(berberis_entry_Interpret));
+  kEntryExitGeneratedCode = InstallEntryTrampoline(AsHostCode(berberis_entry_ExitGeneratedCode));
+  kEntryStop = InstallEntryTrampoline(AsHostCode(berberis_entry_Stop));
+  kEntryNoExec = InstallEntryTrampoline(AsHostCode(berberis_entry_NoExec));
+  kEntryNotTranslated = InstallEntryTrampoline(AsHostCode(berberis_entry_NotTranslated));
+  kEntryTranslating = InstallEntryTrampoline(AsHostCode(berberis_entry_Translating));
+  kEntryInvalidating = InstallEntryTrampoline(AsHostCode(berberis_entry_Invalidating));
+  kEntryWrapping = InstallEntryTrampoline(AsHostCode(berberis_entry_Wrapping));
+}
+
+}  // namespace berberis
diff --git a/runtime_primitives/include/berberis/runtime_primitives/runtime_library.h b/runtime_primitives/include/berberis/runtime_primitives/runtime_library.h
index 389d9504..cb41c747 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/runtime_library.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/runtime_library.h
@@ -45,15 +45,17 @@ __attribute__((__visibility__("hidden"))) void berberis_HandleNoExec(ThreadState
 
 }  // extern "C"
 
-// Inline const since we cannot use constexpr because of reinterpret_cast.
-inline const auto kEntryInterpret = AsHostCode(berberis_entry_Interpret);
-inline const auto kEntryExitGeneratedCode = AsHostCode(berberis_entry_ExitGeneratedCode);
-inline const auto kEntryStop = AsHostCode(berberis_entry_Stop);
-inline const auto kEntryNoExec = AsHostCode(berberis_entry_NoExec);
-inline const auto kEntryNotTranslated = AsHostCode(berberis_entry_NotTranslated);
-inline const auto kEntryTranslating = AsHostCode(berberis_entry_Translating);
-inline const auto kEntryInvalidating = AsHostCode(berberis_entry_Invalidating);
-inline const auto kEntryWrapping = AsHostCode(berberis_entry_Wrapping);
+// These constants are initialized by InitHostEntries()
+extern HostCode kEntryInterpret;
+extern HostCode kEntryExitGeneratedCode;
+extern HostCode kEntryStop;
+extern HostCode kEntryNoExec;
+extern HostCode kEntryNotTranslated;
+extern HostCode kEntryTranslating;
+extern HostCode kEntryInvalidating;
+extern HostCode kEntryWrapping;
+
+void InitHostEntries();
 
 void InvalidateGuestRange(GuestAddr start, GuestAddr end);
 
diff --git a/runtime_primitives/include/berberis/runtime_primitives/table_of_tables.h b/runtime_primitives/include/berberis/runtime_primitives/table_of_tables.h
index 3c01294d..7eb9f63e 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/table_of_tables.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/table_of_tables.h
@@ -34,6 +34,7 @@ class TableOfTables {
  public:
   explicit TableOfTables(T default_value) : default_value_(default_value) {
     static_assert(sizeof(T) == sizeof(uintptr_t));
+    CHECK_NE(default_value, T{0});
     default_table_ = static_cast<decltype(default_table_)>(CreateMemfdBackedMapOrDie(
         GetOrAllocDefaultMemfdUnsafe(), kChildTableBytes, kMemfdRegionSize));
 
diff --git a/runtime_primitives/memory_region_reservation.cc b/runtime_primitives/memory_region_reservation.cc
index 66094a13..ad81d0fe 100644
--- a/runtime_primitives/memory_region_reservation.cc
+++ b/runtime_primitives/memory_region_reservation.cc
@@ -44,6 +44,8 @@ inline ReservationType MemoryRegionReservationLoadTemplate(GuestAddr addr,
         std::atomic_load_explicit(ToHostAddr<std::atomic<uint64_t>>(addr + 8), mem_order);
     return (high << 64) | low;
   } else if constexpr (sizeof(ReservationType) == 8) {
+    ReservationType reservation;
+#if defined(__i386__)
     // Starting from i486 all accesses for all instructions are atomic when they are used for
     // naturally-aligned variables of uint8_t, uint16_t and uint32_t types.  But situation is not so
     // straightforward when we are dealing with uint64_t.
@@ -71,8 +73,10 @@ inline ReservationType MemoryRegionReservationLoadTemplate(GuestAddr addr,
     // Not only is this slow, but this fails when we are accessing read-only memory!
     //
     // Use raw "movq" assembler instruction to circumvent that limitation of IA32 ABI.
-    ReservationType reservation;
     __asm__ __volatile__("movq (%1),%0" : "=x"(reservation) : "r"(addr));
+#else
+    reservation = std::atomic_load_explicit(ToHostAddr<std::atomic<uint64_t>>(addr), mem_order);
+#endif
     return reservation;
   } else {
     static_bad_size();
diff --git a/runtime_primitives/profiler_interface.cc b/runtime_primitives/profiler_interface.cc
index bb00d0ee..e2131c05 100644
--- a/runtime_primitives/profiler_interface.cc
+++ b/runtime_primitives/profiler_interface.cc
@@ -16,13 +16,19 @@
 
 #include "berberis/runtime_primitives/profiler_interface.h"
 
-#include <fcntl.h>
+#include <fcntl.h>   // open
+#include <unistd.h>  // write
+
+#include <array>
+#include <cstring>  // str*
 
 #include "berberis/base/config_globals.h"
 #include "berberis/base/format_buffer.h"
 #include "berberis/base/gettid.h"
+#include "berberis/base/maps_snapshot.h"
 #include "berberis/base/scoped_errno.h"
 #include "berberis/base/tracing.h"
+#include "berberis/guest_state/guest_addr.h"
 
 namespace berberis {
 
@@ -76,27 +82,71 @@ int ProfilerOpenLogFile() {
   return fd;
 }
 
+constexpr size_t kMaxMappedNameLen = 16;
+// Name c-string + terminating null + underscore.
+using MappedNameBuffer = std::array<char, kMaxMappedNameLen + 2>;
+
+// Malloc-free implementation.
+MappedNameBuffer ConstructMappedNameBuffer(GuestAddr guest_addr) {
+  MappedNameBuffer buf;
+  auto* maps_snapshot = MapsSnapshot::GetInstance();
+
+  auto mapped_name = maps_snapshot->FindMappedObjectName(guest_addr);
+  if (!mapped_name.has_value()) {
+    // If no mapping is found renew the snapshot and try again.
+    maps_snapshot->Update();
+    auto updated_mapped_name = maps_snapshot->FindMappedObjectName(guest_addr);
+    if (!updated_mapped_name.has_value()) {
+      TRACE("Guest addr %p not found in /proc/self/maps", ToHostAddr<void>(guest_addr));
+      buf[0] = '\0';
+      return buf;
+    }
+    mapped_name.emplace(std::move(updated_mapped_name.value()));
+  }
+
+  // We can use more clever logic here and try to extract the basename, but the parent directory
+  // name may also be interesting (e.g. <guest_arch>/libc.so) so we just take the last
+  // kMaxMappedNameLen symbols for simplicity until it's proven we need something more advanced.
+  // An added benefit of this approach is that symbols look well aligned in the profile.
+  auto& result = mapped_name.value();
+  size_t terminator_pos;
+  if (result.length() > kMaxMappedNameLen) {
+    // In this case it should be safe to call strcpy, but we still use strncpy to be extra careful.
+    strncpy(buf.data(), result.c_str() + result.length() - kMaxMappedNameLen, kMaxMappedNameLen);
+    terminator_pos = kMaxMappedNameLen;
+  } else {
+    strncpy(buf.data(), result.c_str(), kMaxMappedNameLen);
+    terminator_pos = result.length();
+  }
+  buf[terminator_pos] = '_';
+  buf[terminator_pos + 1] = '\0';
+
+  return buf;
+}
+
 }  // namespace
 
 void ProfilerLogGeneratedCode(const void* start,
                               size_t size,
                               GuestAddr guest_start,
                               size_t guest_size,
-                              const char* prefix) {
+                              const char* jit_suffix) {
   static int fd = ProfilerOpenLogFile();
   if (fd == -1) {
     return;
   }
 
-  char buf[80];
-  // start size name
-  // TODO(b232598137): make name useful
+  MappedNameBuffer mapped_name_buf = ConstructMappedNameBuffer(guest_start);
+
+  char buf[128];
+  // start size symbol-name
   size_t n = FormatBuffer(buf,
                           sizeof(buf),
-                          "%p 0x%zx %s_jit_0x%lx+%zu\n",
+                          "%p 0x%zx %s%s_0x%lx+%zu\n",
                           start,
                           size,
-                          prefix,
+                          mapped_name_buf.data(),
+                          jit_suffix,
                           guest_start,
                           guest_size);
   UNUSED(write(fd, buf, n));
diff --git a/test_utils/include/berberis/test_utils/insn_tests_riscv64-inl.h b/test_utils/include/berberis/test_utils/insn_tests_riscv64-inl.h
index d865ccfd..c8ab6104 100644
--- a/test_utils/include/berberis/test_utils/insn_tests_riscv64-inl.h
+++ b/test_utils/include/berberis/test_utils/insn_tests_riscv64-inl.h
@@ -191,6 +191,15 @@ class TESTSUITE : public ::testing::Test {
     }
   }
 
+  void TestCMiscAluSingleInput(uint16_t insn_bytes,
+                               std::initializer_list<std::tuple<uint64_t, uint64_t>> args) {
+    for (auto [arg1, expected_result] : args) {
+      SetXReg<8>(state_.cpu, arg1);
+      RunInstruction<2>(insn_bytes);
+      EXPECT_EQ(GetXReg<8>(state_.cpu), expected_result);
+    }
+  }
+
   void TestCMiscAluImm(uint16_t insn_bytes, uint64_t value, uint64_t expected_result) {
     SetXReg<9>(state_.cpu, value);
     RunInstruction<2>(insn_bytes);
@@ -1047,6 +1056,19 @@ TEST_F(TESTSUITE, CMiscAluInstructions) {
   TestCMiscAlu(0x9c25, {{19, 23, 42}});
 }
 
+TEST_F(TESTSUITE, CBitManipInstructions) {
+  // c.zext.h
+  TestCMiscAluSingleInput(0x9c69, {{0xffff'ffff'ffff'fffe, 0xfffe}});
+  // c.zext.w
+  TestCMiscAluSingleInput(0x9c71, {{0xffff'ffff'ffff'fffe, 0xffff'fffe}});
+  // c.zext.b
+  TestCMiscAluSingleInput(0x9c61, {{0xffff'ffff'ffff'fffe, 0xfe}});
+  // c.sext.b
+  TestCMiscAluSingleInput(0x9c65, {{0b1111'1110, 0xffff'ffff'ffff'fffe}});
+  // c.sext.h
+  TestCMiscAluSingleInput(0x9c6d, {{0b1111'1111'1111'1110, 0xffff'ffff'ffff'fffe}});
+}
+
 TEST_F(TESTSUITE, CMiscAluImm) {
   union {
     uint8_t uimm;
@@ -1448,6 +1470,10 @@ TEST_F(TESTSUITE, Op32Instructions) {
           {0xffff'ffff'8000'0000, 0xffff'ffff'8000'0001, 0xffff'ffff'8000'0000}});
   // Zext.h
   TestOp(0x080140bb, {{0xffff'ffff'ffff'fffeULL, 0, 0xfffe}});
+  // Zext.b
+  TestOp(0x0ff17093, {{0xffff'ffff'ffff'fffeULL, 0, 0xfe}});
+  // Zext.w
+  TestOp(0x080100bb, {{0xffff'ffff'ffff'fffeULL, 0, 0xffff'fffe}});
   // Rorw
   TestOp(0x603150bb, {{0x0000'0000'f000'000fULL, 4, 0xffff'ffff'ff00'0000}});
   TestOp(0x603150bb, {{0x0000'0000'f000'0000ULL, 4, 0x0000'0000'0f00'0000}});
@@ -1783,6 +1809,7 @@ TEST_F(TESTSUITE, StoreInstructions) {
   // Sd
   TestStore(0x0020b423, kDataToStore);
 }
+
 TEST_F(TESTSUITE, FmaInstructions) {
   // Fmadd.S
   TestFma(0x203170c3, {std::tuple{1.0f, 2.0f, 3.0f, 5.0f}});
diff --git a/tests/hello_world/Android.bp b/tests/hello_world/Android.bp
index 059f6994..bdd01aeb 100644
--- a/tests/hello_world/Android.bp
+++ b/tests/hello_world/Android.bp
@@ -63,3 +63,27 @@ cc_test {
     defaults: ["berberis_hello_world_arm64_nocrt_defaults"],
     static_executable: true,
 }
+
+cc_defaults {
+    name: "berberis_hello_world_riscv64_nocrt_defaults",
+    native_bridge_supported: true,
+    enabled: false,
+    arch: {
+        riscv64: {
+            enabled: true,
+            srcs: ["main_riscv64.S"],
+        },
+    },
+    nocrt: true,
+}
+
+cc_test {
+    name: "berberis_hello_world_riscv64_nocrt",
+    defaults: ["berberis_hello_world_riscv64_nocrt_defaults"],
+}
+
+cc_test {
+    name: "berberis_hello_world_riscv64_nocrt_static",
+    defaults: ["berberis_hello_world_riscv64_nocrt_defaults"],
+    static_executable: true,
+}
diff --git a/tests/hello_world/main_riscv64.S b/tests/hello_world/main_riscv64.S
new file mode 100644
index 00000000..75d39d24
--- /dev/null
+++ b/tests/hello_world/main_riscv64.S
@@ -0,0 +1,39 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+.section .text
+.globl _start
+_start:
+    // SYS_write
+    li a7, 64
+    // fd is stdout
+    li a0, 1
+    // pc-relative address of the string
+1:
+    auipc a1, %pcrel_hi(hello_string)
+    addi a1, a1, %pcrel_lo(1b)
+    // string size
+    li a2, 6
+    ecall
+
+    // SYS_exit
+    li a7, 93
+    // value to return from main
+    li a0, 0
+    ecall
+
+.section .rodata
+hello_string:
+   .asciz "Hello\n"
diff --git a/tests/inline_asm_tests/main_arm64.cc b/tests/inline_asm_tests/main_arm64.cc
index f3805319..0d40a634 100644
--- a/tests/inline_asm_tests/main_arm64.cc
+++ b/tests/inline_asm_tests/main_arm64.cc
@@ -1632,6 +1632,22 @@ TEST(Arm64InsnTest, RoundToIntNearestTiesAwayFp64) {
   ASSERT_EQ(AsmFrinta(0xBFDFFFFFFFFFFFFF), MakeUInt128(0x8000000000000000U, 0U));
 
   // A number too large to have fractional precision, should not change upon rounding with tie-away
+  ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(0.5 / std::numeric_limits<double>::epsilon())),
+            MakeUInt128(bit_cast<uint64_t>(0.5 / std::numeric_limits<double>::epsilon()), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(-0.5 / std::numeric_limits<double>::epsilon())),
+            MakeUInt128(bit_cast<uint64_t>(-0.5 / std::numeric_limits<double>::epsilon()), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(0.75 / std::numeric_limits<double>::epsilon())),
+            MakeUInt128(bit_cast<uint64_t>(0.75 / std::numeric_limits<double>::epsilon()), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(-0.75 / std::numeric_limits<double>::epsilon())),
+            MakeUInt128(bit_cast<uint64_t>(-0.75 / std::numeric_limits<double>::epsilon()), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(1.0 / std::numeric_limits<double>::epsilon())),
+            MakeUInt128(bit_cast<uint64_t>(1.0 / std::numeric_limits<double>::epsilon()), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(-1.0 / std::numeric_limits<double>::epsilon())),
+            MakeUInt128(bit_cast<uint64_t>(-1.0 / std::numeric_limits<double>::epsilon()), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(2.0 / std::numeric_limits<double>::epsilon())),
+            MakeUInt128(bit_cast<uint64_t>(2.0 / std::numeric_limits<double>::epsilon()), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(-2.0 / std::numeric_limits<double>::epsilon())),
+            MakeUInt128(bit_cast<uint64_t>(-2.0 / std::numeric_limits<double>::epsilon()), 0U));
   ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(1.0e100)), MakeUInt128(bit_cast<uint64_t>(1.0e100), 0U));
   ASSERT_EQ(AsmFrinta(bit_cast<uint64_t>(-1.0e100)), MakeUInt128(bit_cast<uint64_t>(-1.0e100), 0U));
 }
@@ -1665,6 +1681,34 @@ TEST(Arm64InsnTest, RoundToIntNearestTiesAwayFp32) {
 
   // -0.49999997019767761 -> -0.0 (should not "tie away" since -0.4999... != -0.5)
   ASSERT_EQ(AsmFrinta(0xbeffffff), MakeUInt128(0x80000000U, 0U));
+
+  // A number too large to have fractional precision, should not change upon rounding with tie-away
+  ASSERT_EQ(
+      AsmFrinta(bit_cast<uint32_t>(float{0.5 / std::numeric_limits<float>::epsilon()})),
+      MakeUInt128(bit_cast<uint32_t>(float{0.5 / std::numeric_limits<float>::epsilon()}), 0U));
+  ASSERT_EQ(
+      AsmFrinta(bit_cast<uint32_t>(float{-0.5 / std::numeric_limits<float>::epsilon()})),
+      MakeUInt128(bit_cast<uint32_t>(float{-0.5 / std::numeric_limits<float>::epsilon()}), 0U));
+  ASSERT_EQ(
+      AsmFrinta(bit_cast<uint32_t>(float{0.75 / std::numeric_limits<float>::epsilon()})),
+      MakeUInt128(bit_cast<uint32_t>(float{0.75 / std::numeric_limits<float>::epsilon()}), 0U));
+  ASSERT_EQ(
+      AsmFrinta(bit_cast<uint32_t>(float{-0.75 / std::numeric_limits<float>::epsilon()})),
+      MakeUInt128(bit_cast<uint32_t>(float{-0.75 / std::numeric_limits<float>::epsilon()}), 0U));
+  ASSERT_EQ(
+      AsmFrinta(bit_cast<uint32_t>(float{1.0 / std::numeric_limits<float>::epsilon()})),
+      MakeUInt128(bit_cast<uint32_t>(float{1.0 / std::numeric_limits<float>::epsilon()}), 0U));
+  ASSERT_EQ(
+      AsmFrinta(bit_cast<uint32_t>(float{-1.0 / std::numeric_limits<float>::epsilon()})),
+      MakeUInt128(bit_cast<uint32_t>(float{-1.0 / std::numeric_limits<float>::epsilon()}), 0U));
+  ASSERT_EQ(
+      AsmFrinta(bit_cast<uint32_t>(float{2.0 / std::numeric_limits<float>::epsilon()})),
+      MakeUInt128(bit_cast<uint32_t>(float{2.0 / std::numeric_limits<float>::epsilon()}), 0U));
+  ASSERT_EQ(
+      AsmFrinta(bit_cast<uint32_t>(float{-2.0 / std::numeric_limits<float>::epsilon()})),
+      MakeUInt128(bit_cast<uint32_t>(float{-2.0 / std::numeric_limits<float>::epsilon()}), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint32_t>(1.0e38f)), MakeUInt128(bit_cast<uint32_t>(1.0e38f), 0U));
+  ASSERT_EQ(AsmFrinta(bit_cast<uint32_t>(-1.0e38f)), MakeUInt128(bit_cast<uint32_t>(-1.0e38f), 0U));
 }
 
 TEST(Arm64InsnTest, RoundToIntDownwardFp64) {
@@ -4805,9 +4849,9 @@ TEST(Arm64InsnTest, Load2MultipleInt8x8) {
 }
 
 TEST(Arm64InsnTest, Load3MultipleInt8x8) {
-  static constexpr uint8_t mem[] = {0x32, 0x87, 0x67, 0x03, 0x80, 0x92, 0x52, 0x16,
-                                    0x79, 0x07, 0x57, 0x12, 0x04, 0x06, 0x12, 0x37,
-                                    0x59, 0x63, 0x27, 0x68, 0x56, 0x74, 0x84, 0x50};
+  static constexpr uint8_t mem[3 * 8] = {0x32, 0x87, 0x67, 0x03, 0x80, 0x92, 0x52, 0x16,
+                                         0x79, 0x07, 0x57, 0x12, 0x04, 0x06, 0x12, 0x37,
+                                         0x59, 0x63, 0x27, 0x68, 0x56, 0x74, 0x84, 0x50};
   __uint128_t res[3];
   asm("ld3 {v7.8b-v9.8b}, [%3]\n\t"
       "mov %0.16b, v7.16b\n\t"
@@ -4821,8 +4865,379 @@ TEST(Arm64InsnTest, Load3MultipleInt8x8) {
   ASSERT_EQ(res[2], MakeUInt128(0x5056631212799267ULL, 0U));
 }
 
+TEST(Arm64InsnTest, Store3MultipleInt8x8) {
+  static constexpr uint64_t arg[3] = {
+      0x7427370407520332ULL, 0x8468590657168087ULL, 0x5056631212799267ULL};
+  uint64_t res[3];
+  asm("mov v0.16b, %0.16b\n\t"
+      "mov v1.16b, %1.16b\n\t"
+      "mov v2.16b, %2.16b\n\t"
+      "st3 {v0.8b-v2.8b}, [%3]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "r"(res)
+      : "v0", "v1", "v2", "memory");
+  ASSERT_EQ(res[0], 0x1652928003678732ULL);
+  ASSERT_EQ(res[1], 0x3712060412570779ULL);
+  ASSERT_EQ(res[2], 0x5084745668276359ULL);
+}
+
+TEST(Arm64InsnTest, Load3MultipleInt8x16) {
+  static constexpr uint8_t mem[3 * 16] = {
+      0x69, 0x20, 0x35, 0x65, 0x63, 0x38, 0x44, 0x96, 0x25, 0x32, 0x83, 0x38,
+      0x52, 0x27, 0x99, 0x24, 0x59, 0x60, 0x97, 0x86, 0x59, 0x47, 0x23, 0x88,
+      0x91, 0x29, 0x63, 0x62, 0x59, 0x54, 0x32, 0x73, 0x45, 0x44, 0x37, 0x16,
+      0x33, 0x55, 0x77, 0x43, 0x29, 0x49, 0x99, 0x28, 0x81, 0x05, 0x57, 0x17};
+  __uint128_t res[3];
+  asm("ld3 {v7.16b-v9.16b}, [%3]\n\t"
+      "mov %0.16b, v7.16b\n\t"
+      "mov %1.16b, v8.16b\n\t"
+      "mov %2.16b, v9.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2])
+      : "r"(mem)
+      : "v7", "v8", "v9", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x4797245232446569ULL, 0x599433344326291ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x2386592783966320ULL, 0x5728295537735929ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x8859609938253835ULL, 0x1781497716455463ULL));
+}
+
+TEST(Arm64InsnTest, Store3MultipleInt8x16) {
+  static constexpr __uint128_t arg[3] = {MakeUInt128(0x4797245232446569ULL, 0x599433344326291ULL),
+                                         MakeUInt128(0x2386592783966320ULL, 0x5728295537735929ULL),
+                                         MakeUInt128(0x8859609938253835ULL, 0x1781497716455463ULL)};
+  __uint128_t res[3];
+  asm("mov v0.16b, %0.16b\n\t"
+      "mov v1.16b, %1.16b\n\t"
+      "mov v2.16b, %2.16b\n\t"
+      "st3 {v0.16b-v2.16b}, [%3]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "r"(res)
+      : "v0", "v1", "v2", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x2499275238833225ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475986976059ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x4377553316374445ULL, 0x1757058128994929ULL));
+}
+
+TEST(Arm64InsnTest, Load3MultipleInt16x4) {
+  static constexpr uint16_t mem[3 * 4] = {0x2069,
+                                          0x6535,
+                                          0x3863,
+                                          0x9644,
+                                          0x3225,
+                                          0x3883,
+                                          0x2752,
+                                          0x2499,
+                                          0x6059,
+                                          0x8697,
+                                          0x4759,
+                                          0x8823};
+  __uint128_t res[3];
+  asm("ld3 {v30.4h-v0.4h}, [%3]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2])
+      : "r"(mem)
+      : "v30", "v31", "v0", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x8697275296442069ULL, 0));
+  ASSERT_EQ(res[1], MakeUInt128(0x4759249932256535ULL, 0));
+  ASSERT_EQ(res[2], MakeUInt128(0x8823605938833863ULL, 0));
+}
+
+TEST(Arm64InsnTest, Store3MultipleInt16x4) {
+  static constexpr uint64_t arg[3] = {
+      0x8697275296442069ULL, 0x4759249932256535ULL, 0x8823605938833863ULL};
+  uint64_t res[3];
+  asm("mov v0.16b, %0.16b\n\t"
+      "mov v1.16b, %1.16b\n\t"
+      "mov v2.16b, %2.16b\n\t"
+      "st3 {v0.4h-v2.4h}, [%3]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "r"(res)
+      : "v0", "v1", "v2", "memory");
+  ASSERT_EQ(res[0], 0x9644386365352069ULL);
+  ASSERT_EQ(res[1], 0x2499275238833225ULL);
+  ASSERT_EQ(res[2], 0x8823475986976059ULL);
+}
+
+TEST(Arm64InsnTest, Load3MultipleInt16x8) {
+  static constexpr uint16_t mem[3 * 8] = {0x2069, 0x6535, 0x3863, 0x9644, 0x3225, 0x3883,
+                                          0x2752, 0x2499, 0x6059, 0x8697, 0x4759, 0x8823,
+                                          0x2991, 0x6263, 0x5459, 0x7332, 0x4445, 0x1637,
+                                          0x5533, 0x4377, 0x4929, 0x2899, 0x0581, 0x1757};
+  __uint128_t res[3];
+  asm("ld3 {v30.8h-v0.8h}, [%3]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2])
+      : "r"(mem)
+      : "v30", "v31", "v0", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x8697275296442069ULL, 0x2899553373322991ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x4759249932256535ULL, 0x581437744456263ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x8823605938833863ULL, 0x1757492916375459ULL));
+}
+
+TEST(Arm64InsnTest, Store3MultipleInt16x8) {
+  static constexpr __uint128_t arg[3] = {MakeUInt128(0x8697275296442069ULL, 0x2899553373322991ULL),
+                                         MakeUInt128(0x4759249932256535ULL, 0x581437744456263ULL),
+                                         MakeUInt128(0x8823605938833863ULL, 0x1757492916375459ULL)};
+  __uint128_t res[3];
+  asm("mov v0.16b, %0.16b\n\t"
+      "mov v1.16b, %1.16b\n\t"
+      "mov v2.16b, %2.16b\n\t"
+      "st3 {v0.8h-v2.8h}, [%3]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "r"(res)
+      : "v0", "v1", "v2", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x2499275238833225ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475986976059ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x4377553316374445ULL, 0x1757058128994929ULL));
+}
+
+TEST(Arm64InsnTest, Load3MultipleInt32x2) {
+  static constexpr uint32_t mem[3 * 2] = {
+      0x65352069, 0x96443863, 0x38833225, 0x24992752, 0x86976059, 0x88234759};
+  __uint128_t res[3];
+  asm("ld3 {v30.2s-v0.2s}, [%3]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2])
+      : "r"(mem)
+      : "v30", "v31", "v0", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x2499275265352069ULL, 0));
+  ASSERT_EQ(res[1], MakeUInt128(0x8697605996443863ULL, 0));
+  ASSERT_EQ(res[2], MakeUInt128(0x8823475938833225ULL, 0));
+}
+
+TEST(Arm64InsnTest, Store3MultipleInt32x2) {
+  static constexpr uint64_t arg[3] = {
+      0x2499275265352069ULL, 0x8697605996443863ULL, 0x8823475938833225ULL};
+  uint64_t res[3];
+  asm("mov v0.16b, %0.16b\n\t"
+      "mov v1.16b, %1.16b\n\t"
+      "mov v2.16b, %2.16b\n\t"
+      "st3 {v0.2s-v2.2s}, [%3]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "r"(res)
+      : "v0", "v1", "v2", "memory");
+  ASSERT_EQ(res[0], 0x9644386365352069ULL);
+  ASSERT_EQ(res[1], 0x2499275238833225ULL);
+  ASSERT_EQ(res[2], 0x8823475986976059ULL);
+}
+
+TEST(Arm64InsnTest, Load3MultipleInt32x4) {
+  static constexpr uint32_t mem[3 * 4] = {0x65352069,
+                                          0x96443863,
+                                          0x38833225,
+                                          0x24992752,
+                                          0x86976059,
+                                          0x88234759,
+                                          0x62632991,
+                                          0x73325459,
+                                          0x16374445,
+                                          0x43775533,
+                                          0x28994929,
+                                          0x17570581};
+  __uint128_t res[3];
+  asm("ld3 {v30.4s-v0.4s}, [%3]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2])
+      : "r"(mem)
+      : "v30", "v31", "v0", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x2499275265352069ULL, 0x4377553362632991ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8697605996443863ULL, 0x2899492973325459ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x8823475938833225ULL, 0x1757058116374445ULL));
+}
+
+TEST(Arm64InsnTest, Store3MultipleInt32x4) {
+  static constexpr __uint128_t arg[3] = {MakeUInt128(0x2499275265352069ULL, 0x4377553362632991ULL),
+                                         MakeUInt128(0x8697605996443863ULL, 0x2899492973325459ULL),
+                                         MakeUInt128(0x8823475938833225ULL, 0x1757058116374445ULL)};
+  __uint128_t res[3];
+  asm("mov v0.16b, %0.16b\n\t"
+      "mov v1.16b, %1.16b\n\t"
+      "mov v2.16b, %2.16b\n\t"
+      "st3 {v0.4s-v2.4s}, [%3]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "r"(res)
+      : "v0", "v1", "v2", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x2499275238833225ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475986976059ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x4377553316374445ULL, 0x1757058128994929ULL));
+}
+
+TEST(Arm64InsnTest, Load3MultipleInt64x2) {
+  static constexpr uint64_t mem[3 * 2] = {0x9644386365352069,
+                                          0x2499275238833225,
+                                          0x8823475986976059,
+                                          0x7332545962632991,
+                                          0x4377553316374445,
+                                          0x1757058128994929};
+  __uint128_t res[3];
+  asm("ld3 {v30.2d-v0.2d}, [%3]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2])
+      : "r"(mem)
+      : "v30", "v31", "v0", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x2499275238833225ULL, 0x4377553316374445ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x8823475986976059ULL, 0x1757058128994929ULL));
+}
+
+TEST(Arm64InsnTest, Store3MultipleInt64x2) {
+  static constexpr __uint128_t arg[3] = {MakeUInt128(0x9644386365352069ULL, 0x7332545962632991ULL),
+                                         MakeUInt128(0x2499275238833225ULL, 0x4377553316374445ULL),
+                                         MakeUInt128(0x8823475986976059ULL, 0x1757058128994929ULL)};
+  __uint128_t res[3];
+  asm("mov v0.16b, %0.16b\n\t"
+      "mov v1.16b, %1.16b\n\t"
+      "mov v2.16b, %2.16b\n\t"
+      "st3 {v0.2d-v2.2d}, [%3]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "r"(res)
+      : "v0", "v1", "v2", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x2499275238833225ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475986976059ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x4377553316374445ULL, 0x1757058128994929ULL));
+}
+
+TEST(Arm64InsnTest, Load4MultipleInt8x8) {
+  static constexpr uint8_t mem[4 * 8] = {0x69, 0x20, 0x35, 0x65, 0x63, 0x38, 0x44, 0x96,
+                                         0x25, 0x32, 0x83, 0x38, 0x52, 0x27, 0x99, 0x24,
+                                         0x59, 0x60, 0x97, 0x86, 0x59, 0x47, 0x23, 0x88,
+                                         0x91, 0x29, 0x63, 0x62, 0x59, 0x54, 0x32, 0x73};
+  __uint128_t res[4];
+  asm("ld4 {v7.8b-v10.8b}, [%4]\n\t"
+      "mov %0.16b, v7.16b\n\t"
+      "mov %1.16b, v8.16b\n\t"
+      "mov %2.16b, v9.16b\n\t"
+      "mov %3.16b, v10.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2]), "=w"(res[3])
+      : "r"(mem)
+      : "v7", "v8", "v9", "v10", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x5991595952256369ULL, 0));
+  ASSERT_EQ(res[1], MakeUInt128(0x5429476027323820ULL, 0));
+  ASSERT_EQ(res[2], MakeUInt128(0x3263239799834435ULL, 0));
+  ASSERT_EQ(res[3], MakeUInt128(0x7362888624389665ULL, 0));
+}
+
+TEST(Arm64InsnTest, Store4MultipleInt8x8) {
+  static constexpr uint64_t arg[4] = {
+      0x5991595952256369ULL, 0x5429476027323820ULL, 0x3263239799834435ULL, 0x7362888624389665ULL};
+  uint64_t res[4];
+  asm("mov v7.16b, %0.16b\n\t"
+      "mov v8.16b, %1.16b\n\t"
+      "mov v9.16b, %2.16b\n\t"
+      "mov v10.16b, %3.16b\n\t"
+      "st4 {v7.8b-v10.8b}, [%4]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "w"(arg[3]), "r"(res)
+      : "v7", "v8", "v9", "v10", "memory");
+  ASSERT_EQ(res[0], 0x9644386365352069ULL);
+  ASSERT_EQ(res[1], 0x2499275238833225ULL);
+  ASSERT_EQ(res[2], 0x8823475986976059ULL);
+  ASSERT_EQ(res[3], 0x7332545962632991ULL);
+}
+
+TEST(Arm64InsnTest, Load4MultipleInt8x16) {
+  static constexpr uint8_t mem[4 * 16] = {
+      0x69, 0x20, 0x35, 0x65, 0x63, 0x38, 0x44, 0x96, 0x25, 0x32, 0x83, 0x38, 0x52,
+      0x27, 0x99, 0x24, 0x59, 0x60, 0x97, 0x86, 0x59, 0x47, 0x23, 0x88, 0x91, 0x29,
+      0x63, 0x62, 0x59, 0x54, 0x32, 0x73, 0x45, 0x44, 0x37, 0x16, 0x33, 0x55, 0x77,
+      0x43, 0x29, 0x49, 0x99, 0x28, 0x81, 0x05, 0x57, 0x17, 0x81, 0x98, 0x78, 0x50,
+      0x68, 0x14, 0x62, 0x52, 0x32, 0x13, 0x47, 0x52, 0x37, 0x38, 0x11, 0x65};
+  __uint128_t res[4];
+  asm("ld4 {v7.16b-v10.16b}, [%4]\n\t"
+      "mov %0.16b, v7.16b\n\t"
+      "mov %1.16b, v8.16b\n\t"
+      "mov %2.16b, v9.16b\n\t"
+      "mov %3.16b, v10.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2]), "=w"(res[3])
+      : "r"(mem)
+      : "v7", "v8", "v9", "v10", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x5991595952256369ULL, 0x3732688181293345ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x5429476027323820ULL, 0x3813149805495544ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x3263239799834435ULL, 0x1147627857997737ULL));
+  ASSERT_EQ(res[3], MakeUInt128(0x7362888624389665ULL, 0x6552525017284316ULL));
+}
+
+TEST(Arm64InsnTest, Store4MultipleInt8x16) {
+  static constexpr __uint128_t arg[4] = {MakeUInt128(0x5991595952256369ULL, 0x3732688181293345ULL),
+                                         MakeUInt128(0x5429476027323820ULL, 0x3813149805495544ULL),
+                                         MakeUInt128(0x3263239799834435ULL, 0x1147627857997737ULL),
+                                         MakeUInt128(0x7362888624389665ULL, 0x6552525017284316ULL)};
+  __uint128_t res[4];
+  asm("mov v7.16b, %0.16b\n\t"
+      "mov v8.16b, %1.16b\n\t"
+      "mov v9.16b, %2.16b\n\t"
+      "mov v10.16b, %3.16b\n\t"
+      "st4 {v7.16b-v10.16b}, [%4]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "w"(arg[3]), "r"(res)
+      : "v7", "v8", "v9", "v10", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x2499275238833225ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475986976059ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x4377553316374445ULL, 0x1757058128994929ULL));
+  ASSERT_EQ(res[3], MakeUInt128(0x5262146850789881ULL, 0x6511383752471332ULL));
+}
+
+TEST(Arm64InsnTest, Load4MultipleInt16x4) {
+  static constexpr uint16_t mem[4 * 4] = {0x2069,
+                                          0x6535,
+                                          0x3863,
+                                          0x9644,
+                                          0x3225,
+                                          0x3883,
+                                          0x2752,
+                                          0x2499,
+                                          0x6059,
+                                          0x8697,
+                                          0x4759,
+                                          0x8823,
+                                          0x2991,
+                                          0x6263,
+                                          0x5459,
+                                          0x7332};
+  __uint128_t res[4];
+  asm("ld4 {v30.4h-v1.4h}, [%4]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b\n\t"
+      "mov %3.16b, v1.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2]), "=w"(res[3])
+      : "r"(mem)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x2991605932252069ULL, 0));
+  ASSERT_EQ(res[1], MakeUInt128(0x6263869738836535ULL, 0));
+  ASSERT_EQ(res[2], MakeUInt128(0x5459475927523863ULL, 0));
+  ASSERT_EQ(res[3], MakeUInt128(0x7332882324999644ULL, 0));
+}
+
+TEST(Arm64InsnTest, Store4MultipleInt16x4) {
+  static constexpr uint64_t arg[4] = {
+      0x2991605932252069ULL, 0x6263869738836535ULL, 0x5459475927523863ULL, 0x7332882324999644ULL};
+  uint64_t res[4];
+  asm("mov v30.16b, %0.16b\n\t"
+      "mov v31.16b, %1.16b\n\t"
+      "mov v0.16b, %2.16b\n\t"
+      "mov v1.16b, %3.16b\n\t"
+      "st4 {v30.4h-v1.4h}, [%4]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "w"(arg[3]), "r"(res)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], 0x9644386365352069ULL);
+  ASSERT_EQ(res[1], 0x2499275238833225ULL);
+  ASSERT_EQ(res[2], 0x8823475986976059ULL);
+  ASSERT_EQ(res[3], 0x7332545962632991ULL);
+}
+
 TEST(Arm64InsnTest, Load4MultipleInt16x8) {
-  static constexpr uint16_t mem[] = {
+  static constexpr uint16_t mem[4 * 8] = {
       0x2069, 0x6535, 0x3863, 0x9644, 0x3225, 0x3883, 0x2752, 0x2499, 0x6059, 0x8697, 0x4759,
       0x8823, 0x2991, 0x6263, 0x5459, 0x7332, 0x4445, 0x1637, 0x5533, 0x4377, 0x4929, 0x2899,
       0x0581, 0x1757, 0x9881, 0x5078, 0x1468, 0x5262, 0x1332, 0x5247, 0x3837, 0x6511};
@@ -4841,6 +5256,164 @@ TEST(Arm64InsnTest, Load4MultipleInt16x8) {
   ASSERT_EQ(res[3], MakeUInt128(0x7332882324999644ULL, 0x6511526217574377ULL));
 }
 
+TEST(Arm64InsnTest, Store4MultipleInt16x8) {
+  static constexpr __uint128_t arg[4] = {MakeUInt128(0x2991605932252069ULL, 0x1332988149294445ULL),
+                                         MakeUInt128(0x6263869738836535ULL, 0x5247507828991637ULL),
+                                         MakeUInt128(0x5459475927523863ULL, 0x3837146805815533ULL),
+                                         MakeUInt128(0x7332882324999644ULL, 0x6511526217574377ULL)};
+  __uint128_t res[4];
+  asm("mov v30.16b, %0.16b\n\t"
+      "mov v31.16b, %1.16b\n\t"
+      "mov v0.16b, %2.16b\n\t"
+      "mov v1.16b, %3.16b\n\t"
+      "st4 {v30.8h-v1.8h}, [%4]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "w"(arg[3]), "r"(res)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x2499275238833225ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475986976059ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x4377553316374445ULL, 0x1757058128994929ULL));
+  ASSERT_EQ(res[3], MakeUInt128(0x5262146850789881ULL, 0x6511383752471332ULL));
+}
+
+TEST(Arm64InsnTest, Load4MultipleInt32x2) {
+  static constexpr uint32_t mem[4 * 2] = {0x65352069,
+                                          0x96443863,
+                                          0x38833225,
+                                          0x24992752,
+                                          0x86976059,
+                                          0x88234759,
+                                          0x62632991,
+                                          0x73325459};
+  __uint128_t res[4];
+  asm("ld4 {v30.2s-v1.2s}, [%4]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b\n\t"
+      "mov %3.16b, v1.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2]), "=w"(res[3])
+      : "r"(mem)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x8697605965352069ULL, 0));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475996443863ULL, 0));
+  ASSERT_EQ(res[2], MakeUInt128(0x6263299138833225ULL, 0));
+  ASSERT_EQ(res[3], MakeUInt128(0x7332545924992752ULL, 0));
+}
+
+TEST(Arm64InsnTest, Store4MultipleInt32x2) {
+  static constexpr uint64_t arg[4] = {
+      0x8697605965352069ULL, 0x8823475996443863ULL, 0x6263299138833225ULL, 0x7332545924992752ULL};
+  uint64_t res[4];
+  asm("mov v30.16b, %0.16b\n\t"
+      "mov v31.16b, %1.16b\n\t"
+      "mov v0.16b, %2.16b\n\t"
+      "mov v1.16b, %3.16b\n\t"
+      "st4 {v30.2s-v1.2s}, [%4]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "w"(arg[3]), "r"(res)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], 0x9644386365352069ULL);
+  ASSERT_EQ(res[1], 0x2499275238833225ULL);
+  ASSERT_EQ(res[2], 0x8823475986976059ULL);
+  ASSERT_EQ(res[3], 0x7332545962632991ULL);
+}
+
+TEST(Arm64InsnTest, Load4MultipleInt32x4) {
+  static constexpr uint32_t mem[4 * 4] = {0x65352069,
+                                          0x96443863,
+                                          0x38833225,
+                                          0x24992752,
+                                          0x86976059,
+                                          0x88234759,
+                                          0x62632991,
+                                          0x73325459,
+                                          0x16374445,
+                                          0x43775533,
+                                          0x28994929,
+                                          0x17570581,
+                                          0x50789881,
+                                          0x52621468,
+                                          0x52471332,
+                                          0x65113837};
+  __uint128_t res[4];
+  asm("ld4 {v30.4s-v1.4s}, [%4]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b\n\t"
+      "mov %3.16b, v1.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2]), "=w"(res[3])
+      : "r"(mem)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x8697605965352069ULL, 0x5078988116374445ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475996443863ULL, 0x5262146843775533ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x6263299138833225ULL, 0x5247133228994929ULL));
+  ASSERT_EQ(res[3], MakeUInt128(0x7332545924992752ULL, 0x6511383717570581ULL));
+}
+
+TEST(Arm64InsnTest, Store4MultipleInt32x4) {
+  static constexpr __uint128_t arg[4] = {MakeUInt128(0x8697605965352069ULL, 0x5078988116374445ULL),
+                                         MakeUInt128(0x8823475996443863ULL, 0x5262146843775533ULL),
+                                         MakeUInt128(0x6263299138833225ULL, 0x5247133228994929ULL),
+                                         MakeUInt128(0x7332545924992752ULL, 0x6511383717570581ULL)};
+  __uint128_t res[4];
+  asm("mov v30.16b, %0.16b\n\t"
+      "mov v31.16b, %1.16b\n\t"
+      "mov v0.16b, %2.16b\n\t"
+      "mov v1.16b, %3.16b\n\t"
+      "st4 {v30.4s-v1.4s}, [%4]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "w"(arg[3]), "r"(res)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x2499275238833225ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475986976059ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x4377553316374445ULL, 0x1757058128994929ULL));
+  ASSERT_EQ(res[3], MakeUInt128(0x5262146850789881ULL, 0x6511383752471332ULL));
+}
+
+TEST(Arm64InsnTest, Load4MultipleInt64x2) {
+  static constexpr uint64_t mem[4 * 2] = {0x9644386365352069,
+                                          0x2499275238833225,
+                                          0x8823475986976059,
+                                          0x7332545962632991,
+                                          0x4377553316374445,
+                                          0x1757058128994929,
+                                          0x5262146850789881,
+                                          0x6511383752471332};
+  __uint128_t res[4];
+  asm("ld4 {v30.2d-v1.2d}, [%4]\n\t"
+      "mov %0.16b, v30.16b\n\t"
+      "mov %1.16b, v31.16b\n\t"
+      "mov %2.16b, v0.16b\n\t"
+      "mov %3.16b, v1.16b"
+      : "=w"(res[0]), "=w"(res[1]), "=w"(res[2]), "=w"(res[3])
+      : "r"(mem)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x4377553316374445ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x2499275238833225ULL, 0x1757058128994929ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x8823475986976059ULL, 0x5262146850789881ULL));
+  ASSERT_EQ(res[3], MakeUInt128(0x7332545962632991ULL, 0x6511383752471332ULL));
+}
+
+TEST(Arm64InsnTest, Store4MultipleInt64x2) {
+  static constexpr __uint128_t arg[4] = {MakeUInt128(0x9644386365352069ULL, 0x4377553316374445ULL),
+                                         MakeUInt128(0x2499275238833225ULL, 0x1757058128994929ULL),
+                                         MakeUInt128(0x8823475986976059ULL, 0x5262146850789881ULL),
+                                         MakeUInt128(0x7332545962632991ULL, 0x6511383752471332ULL)};
+  __uint128_t res[4];
+  asm("mov v30.16b, %0.16b\n\t"
+      "mov v31.16b, %1.16b\n\t"
+      "mov v0.16b, %2.16b\n\t"
+      "mov v1.16b, %3.16b\n\t"
+      "st4 {v30.2d-v1.2d}, [%4]"
+      :
+      : "w"(arg[0]), "w"(arg[1]), "w"(arg[2]), "w"(arg[3]), "r"(res)
+      : "v30", "v31", "v0", "v1", "memory");
+  ASSERT_EQ(res[0], MakeUInt128(0x9644386365352069ULL, 0x2499275238833225ULL));
+  ASSERT_EQ(res[1], MakeUInt128(0x8823475986976059ULL, 0x7332545962632991ULL));
+  ASSERT_EQ(res[2], MakeUInt128(0x4377553316374445ULL, 0x1757058128994929ULL));
+  ASSERT_EQ(res[3], MakeUInt128(0x5262146850789881ULL, 0x6511383752471332ULL));
+}
+
 TEST(Arm64InsnTest, Load1ReplicateInt8x8) {
   static constexpr uint8_t mem = 0x81U;
   __uint128_t res;
@@ -8364,8 +8937,22 @@ TEST(Arm64InsnTest, UnsignedDivide64) {
     asm("udiv %0, %1, %2" : "=r"(result) : "r"(num), "r"(den));
     return result;
   };
-  ASSERT_EQ(udiv64(0x8'0000'0000ULL, 2ULL), 0x4'0000'0000ULL) << "Division is 64-bit.";
-  ASSERT_EQ(udiv64(123ULL, 0ULL), 0ULL) << "Div by 0 results in 0.";
+  ASSERT_EQ(udiv64(0x8'0000'0000ULL, 2ULL), 0x4'0000'0000ULL) << "Division should be 64-bit.";
+  ASSERT_EQ(udiv64(123ULL, 0ULL), 0ULL) << "Div by 0 should result in 0.";
+}
+
+TEST(Arm64InsnTest, SignedDivide64) {
+  auto div64 = [](int64_t num, int64_t den) {
+    int64_t result;
+    asm("sdiv %0, %1, %2" : "=r"(result) : "r"(num), "r"(den));
+    return result;
+  };
+  ASSERT_EQ(div64(67802402LL, -1LL), -67802402LL)
+      << "Division by -1 should flip sign if dividend is not numeric_limits::min.";
+  ASSERT_EQ(div64(-531675317891LL, -1LL), 531675317891LL)
+      << "Division by -1 should flip sign if dividend is not numeric_limits::min.";
+  ASSERT_EQ(div64(std::numeric_limits<int64_t>::min(), -1LL), std::numeric_limits<int64_t>::min())
+      << "Div of numeric_limits::min by -1 should result in numeric_limits::min.";
 }
 
 TEST(Arm64InsnTest, AesEncode) {
diff --git a/tests/inline_asm_tests/main_riscv64.cc b/tests/inline_asm_tests/main_riscv64.cc
index 98fbe982..616d54d1 100644
--- a/tests/inline_asm_tests/main_riscv64.cc
+++ b/tests/inline_asm_tests/main_riscv64.cc
@@ -24,6 +24,8 @@
 #include <tuple>
 #include <utility>
 
+namespace berberis {
+
 namespace {
 
 template <typename T>
@@ -31,65 +33,69 @@ constexpr T BitUtilLog2(T x) {
   return __builtin_ctz(x);
 }
 
-using uint8_16_t = std::tuple<uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t,
-                              uint8_t>;
-using uint16_8_t =
+using UInt8x16Tuple = std::tuple<uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t,
+                                 uint8_t>;
+using UInt16x8Tuple =
     std::tuple<uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t>;
-using uint32_4_t = std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>;
-using uint64_2_t = std::tuple<uint64_t, uint64_t>;
+using UInt32x4Tuple = std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>;
+using UInt64x2Tuple = std::tuple<uint64_t, uint64_t>;
 
 enum PrintModeEndianess { kLittleEndian, kBigEndian };
 
 // A wrapper around __uint128 which can be constructed from a pair of uint64_t literals.
-class SIMD128 {
+class SIMD128Register {
  public:
-  SIMD128(){};
-
-  constexpr SIMD128(uint8_16_t u8) : uint8_{u8} {};
-  constexpr SIMD128(uint16_8_t u16) : uint16_{u16} {};
-  constexpr SIMD128(uint32_4_t u32) : uint32_{u32} {};
-  constexpr SIMD128(uint64_2_t u64) : uint64_{u64} {};
-  constexpr SIMD128(__int128_t i128) : i128_{i128} {};
-  constexpr SIMD128(uint8_t u128) : u128_{u128} {};
-  constexpr SIMD128(uint16_t u128) : u128_{u128} {};
-  constexpr SIMD128(uint32_t u128) : u128_{u128} {};
-  constexpr SIMD128(uint64_t u128) : u128_{u128} {};
-  constexpr SIMD128(__uint128_t u128) : u128_{u128} {};
+  SIMD128Register() {};
+
+  constexpr SIMD128Register(UInt8x16Tuple u8) : uint8_{u8} {};
+  constexpr SIMD128Register(UInt16x8Tuple u16) : uint16_{u16} {};
+  constexpr SIMD128Register(UInt32x4Tuple u32) : uint32_{u32} {};
+  constexpr SIMD128Register(UInt64x2Tuple u64) : uint64_{u64} {};
+  constexpr SIMD128Register(__int128_t i128) : i128_{i128} {};
+  constexpr SIMD128Register(uint8_t u128) : u128_{u128} {};
+  constexpr SIMD128Register(uint16_t u128) : u128_{u128} {};
+  constexpr SIMD128Register(uint32_t u128) : u128_{u128} {};
+  constexpr SIMD128Register(uint64_t u128) : u128_{u128} {};
+  constexpr SIMD128Register(__uint128_t u128) : u128_{u128} {};
 
   [[nodiscard]] constexpr __uint128_t Get() const { return u128_; }
 
-  constexpr SIMD128& operator=(const SIMD128& other) {
+  constexpr SIMD128Register& operator=(const SIMD128Register& other) {
     u128_ = other.u128_;
     return *this;
   };
-  constexpr SIMD128& operator|=(const SIMD128& other) {
+  constexpr SIMD128Register& operator&=(const SIMD128Register& other) {
+    u128_ &= other.u128_;
+    return *this;
+  }
+  constexpr SIMD128Register& operator|=(const SIMD128Register& other) {
     u128_ |= other.u128_;
     return *this;
   }
 
-  constexpr bool operator==(const SIMD128& other) const { return u128_ == other.u128_; }
-  constexpr bool operator!=(const SIMD128& other) const { return u128_ != other.u128_; }
-  constexpr SIMD128 operator>>(size_t shift_amount) const { return u128_ >> shift_amount; }
-  constexpr SIMD128 operator<<(size_t shift_amount) const { return u128_ << shift_amount; }
-  constexpr SIMD128 operator&(SIMD128 other) const { return u128_ & other.u128_; }
-  constexpr SIMD128 operator|(SIMD128 other) const { return u128_ | other.u128_; }
-  constexpr SIMD128 operator^(SIMD128 other) const { return u128_ ^ other.u128_; }
-  constexpr SIMD128 operator~() const { return ~u128_; }
-  friend std::ostream& operator<<(std::ostream& os, const SIMD128& simd);
+  constexpr bool operator==(const SIMD128Register& other) const { return u128_ == other.u128_; }
+  constexpr bool operator!=(const SIMD128Register& other) const { return u128_ != other.u128_; }
+  constexpr SIMD128Register operator>>(size_t shift_amount) const { return u128_ >> shift_amount; }
+  constexpr SIMD128Register operator<<(size_t shift_amount) const { return u128_ << shift_amount; }
+  constexpr SIMD128Register operator&(SIMD128Register other) const { return u128_ & other.u128_; }
+  constexpr SIMD128Register operator|(SIMD128Register other) const { return u128_ | other.u128_; }
+  constexpr SIMD128Register operator^(SIMD128Register other) const { return u128_ ^ other.u128_; }
+  constexpr SIMD128Register operator~() const { return ~u128_; }
+  friend std::ostream& operator<<(std::ostream& os, const SIMD128Register& simd);
 
   template <size_t N>
   std::ostream& Print(std::ostream& os) const {
@@ -124,26 +130,26 @@ class SIMD128 {
  private:
   union {
 #ifdef __GNUC__
-    [[gnu::may_alias]] uint8_16_t uint8_;
-    [[gnu::may_alias]] uint16_8_t uint16_;
-    [[gnu::may_alias]] uint32_4_t uint32_;
-    [[gnu::may_alias]] uint64_2_t uint64_;
+    [[gnu::may_alias]] UInt8x16Tuple uint8_;
+    [[gnu::may_alias]] UInt16x8Tuple uint16_;
+    [[gnu::may_alias]] UInt32x4Tuple uint32_;
+    [[gnu::may_alias]] UInt64x2Tuple uint64_;
     [[gnu::may_alias]] __int128_t i128_;
     [[gnu::may_alias]] __uint128_t u128_;
 #endif
   };
 
-  // Support for BIG_ENDIAN or LITTLE_ENDIAN printing of SIMD128 values. Change this value
+  // Support for BIG_ENDIAN or LITTLE_ENDIAN printing of SIMD128Register values. Change this value
   // if you want to see failure results in LITTLE_ENDIAN.
   static constexpr const PrintModeEndianess kSimd128PrintMode = kBigEndian;
 };
 
 // Helps produce easy to read output on failed tests.
-std::ostream& operator<<(std::ostream& os, const SIMD128& simd) {
+std::ostream& operator<<(std::ostream& os, const SIMD128Register& simd) {
   return simd.PrintEach(os, std::make_index_sequence<8>());
 }
 
-constexpr SIMD128 kVectorCalculationsSourceLegacy[16] = {
+const SIMD128Register kVectorCalculationsSourceLegacy[16] = {
     {{0x8706'8504'8302'8100, 0x8f0e'8d0c'8b0a'8908}},
     {{0x9716'9514'9312'9110, 0x9f1e'9d1c'9b1a'9918}},
     {{0xa726'a524'a322'a120, 0xaf2e'ad2c'ab2a'a928}},
@@ -163,7 +169,7 @@ constexpr SIMD128 kVectorCalculationsSourceLegacy[16] = {
     {{0xeeec'eae9'e6e4'e2e0, 0xfefc'faf8'f6f4'f2f1}},
 };
 
-constexpr SIMD128 kVectorCalculationsSource[16] = {
+const SIMD128Register kVectorCalculationsSource[16] = {
     {{0x8706'8504'8302'8100, 0x8f0e'8d0c'8b0a'8908}},
     {{0x9716'9514'9312'9110, 0x9f1e'9d1c'9b1a'9918}},
     {{0xa726'a524'a322'a120, 0xaf2e'ad2c'ab2a'a928}},
@@ -183,7 +189,7 @@ constexpr SIMD128 kVectorCalculationsSource[16] = {
     {{0x7eec'7ae9'76e4'72e0, 0x6efc'6af8'66f4'62f1}},
 };
 
-constexpr SIMD128 kVectorComparisonSource[16] = {
+const SIMD128Register kVectorComparisonSource[16] = {
     {{0xf005'f005'f005'f005, 0xffff'ffff'4040'4040}},
     {{0xffff'ffff'40b4'40b4, 0xffff'ffff'40b4'0000}},
     {{0x4016'4016'4016'4016, 0x4016'8000'0000'0000}},
@@ -213,9 +219,9 @@ inline constexpr uint64_t ROD = 0b11;
 }  // namespace VXRMFlags
 
 // Easily recognizable bit pattern for target register.
-constexpr SIMD128 kUndisturbedResult{{0x5555'5555'5555'5555, 0x5555'5555'5555'5555}};
+const SIMD128Register kUndisturbedResult{{0x5555'5555'5555'5555, 0x5555'5555'5555'5555}};
 
-SIMD128 GetAgnosticResult() {
+SIMD128Register GetAgnosticResult() {
   static const bool kRvvAgnosticIsUndisturbed = getenv("RVV_AGNOSTIC_IS_UNDISTURBED") != nullptr;
   if (kRvvAgnosticIsUndisturbed) {
     return kUndisturbedResult;
@@ -223,12 +229,12 @@ SIMD128 GetAgnosticResult() {
   return {{~uint64_t{0U}, ~uint64_t{0U}}};
 }
 
-const SIMD128 kAgnosticResult = GetAgnosticResult();
+const SIMD128Register kAgnosticResult = GetAgnosticResult();
 
 // Mask in form suitable for storing in v0 and use in v0.t form.
-static constexpr SIMD128 kMask{{0xd5ad'd6b5'ad6b'b5ad, 0x6af7'57bb'deed'7bb5}};
+const SIMD128Register kMask{{0xd5ad'd6b5'ad6b'b5ad, 0x6af7'57bb'deed'7bb5}};
 // Mask used with vsew = 0 (8bit) elements.
-static constexpr SIMD128 kMaskInt8[8] = {
+const SIMD128Register kMaskInt8[8] = {
     {{255, 0, 255, 255, 0, 255, 0, 255, 255, 0, 255, 0, 255, 255, 0, 255}},
     {{255, 255, 0, 255, 0, 255, 255, 0, 255, 0, 255, 255, 0, 255, 0, 255}},
     {{255, 0, 255, 0, 255, 255, 0, 255, 0, 255, 255, 0, 255, 0, 255, 255}},
@@ -239,7 +245,7 @@ static constexpr SIMD128 kMaskInt8[8] = {
     {{255, 255, 255, 0, 255, 255, 255, 255, 0, 255, 0, 255, 0, 255, 255, 0}},
 };
 // Mask used with vsew = 1 (16bit) elements.
-static constexpr SIMD128 kMaskInt16[8] = {
+const SIMD128Register kMaskInt16[8] = {
     {{0xffff, 0x0000, 0xffff, 0xffff, 0x0000, 0xffff, 0x0000, 0xffff}},
     {{0xffff, 0x0000, 0xffff, 0x0000, 0xffff, 0xffff, 0x0000, 0xffff}},
     {{0xffff, 0xffff, 0x0000, 0xffff, 0x0000, 0xffff, 0xffff, 0x0000}},
@@ -250,7 +256,7 @@ static constexpr SIMD128 kMaskInt16[8] = {
     {{0xffff, 0x0000, 0xffff, 0x0000, 0xffff, 0x0000, 0xffff, 0xffff}},
 };
 // Mask used with vsew = 2 (32bit) elements.
-static constexpr SIMD128 kMaskInt32[8] = {
+const SIMD128Register kMaskInt32[8] = {
     {{0xffff'ffff, 0x0000'0000, 0xffff'ffff, 0xffff'ffff}},
     {{0x0000'0000, 0xffff'ffff, 0x0000'0000, 0xffff'ffff}},
     {{0xffff'ffff, 0x0000'0000, 0xffff'ffff, 0x0000'0000}},
@@ -261,7 +267,7 @@ static constexpr SIMD128 kMaskInt32[8] = {
     {{0x0000'0000, 0xffff'ffff, 0x0000'0000, 0xffff'ffff}},
 };
 // Mask used with vsew = 3 (64bit) elements.
-static constexpr SIMD128 kMaskInt64[8] = {
+const SIMD128Register kMaskInt64[8] = {
     {{0xffff'ffff'ffff'ffff, 0x0000'0000'0000'0000}},
     {{0xffff'ffff'ffff'ffff, 0xffff'ffff'ffff'ffff}},
     {{0x0000'0000'0000'0000, 0xffff'ffff'ffff'ffff}},
@@ -272,7 +278,7 @@ static constexpr SIMD128 kMaskInt64[8] = {
     {{0x0000'0000'0000'0000, 0xffff'ffff'ffff'ffff}},
 };
 // To verify operations without masking.
-static constexpr SIMD128 kNoMask[8] = {
+const SIMD128Register kNoMask[8] = {
     {{0xffff'ffff'ffff'ffff, 0xffff'ffff'ffff'ffff}},
     {{0xffff'ffff'ffff'ffff, 0xffff'ffff'ffff'ffff}},
     {{0xffff'ffff'ffff'ffff, 0xffff'ffff'ffff'ffff}},
@@ -284,7 +290,7 @@ static constexpr SIMD128 kNoMask[8] = {
 };
 
 // Half of sub-register lmul.
-static constexpr SIMD128 kFractionMaskInt8[5] = {
+const SIMD128Register kFractionMaskInt8[5] = {
     {{255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},                // Half of 1/8 reg = 1/16
     {{255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},              // Half of 1/4 reg = 1/8
     {{255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},          // Half of 1/2 reg = 1/4
@@ -292,7 +298,7 @@ static constexpr SIMD128 kFractionMaskInt8[5] = {
     {{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}},  // Full reg
 };
 
-SIMD128 MakeBitmaskFromVl(size_t vl) {
+SIMD128Register MakeBitmaskFromVl(size_t vl) {
   if (vl == 128) {
     return {__uint128_t(0)};
   } else {
@@ -327,8 +333,8 @@ auto MaskForElemIfMasked() {
 using ExecInsnFunc = void (*)();
 
 void RunTwoVectorArgsOneRes(ExecInsnFunc exec_insn,
-                            const SIMD128* src,
-                            SIMD128* res,
+                            const SIMD128Register* src,
+                            SIMD128Register* res,
                             uint64_t vtype,
                             uint64_t vlmax) {
   uint64_t vstart, vl;
@@ -400,8 +406,8 @@ void RunTwoVectorArgsOneRes(ExecInsnFunc exec_insn,
 // scalar and float will be filled from scalar_src, and will use t0 and ft0,
 // respectively.
 void RunCommonVectorFunc(ExecInsnFunc exec_insn,
-                         const SIMD128* src,
-                         SIMD128* res,
+                         const SIMD128Register* src,
+                         SIMD128Register* res,
                          uint64_t* scalar_int_res,
                          uint64_t* scalar_float_res,
                          uint64_t scalar_src,
@@ -497,8 +503,8 @@ template <TestVectorInstructionKind kTestVectorInstructionKind,
           size_t... kResultsCount>
 void TestVectorInstructionInternal(ExecInsnFunc exec_insn,
                                    ExecInsnFunc exec_masked_insn,
-                                   const SIMD128 dst_result,
-                                   const SIMD128 (&source)[16],
+                                   const SIMD128Register dst_result,
+                                   const SIMD128Register (&source)[16],
                                    const ExpectedResultType (&... expected_result)[kResultsCount]) {
   auto Verify = [&source, dst_result](ExecInsnFunc exec_insn,
                                       uint8_t vsew,
@@ -557,7 +563,7 @@ void TestVectorInstructionInternal(ExecInsnFunc exec_insn,
             vl = vlmax;
           }
 
-          SIMD128 result[8];
+          SIMD128Register result[8];
           // Set expected_result vector registers into 0b01010101… pattern.
           // Set undisturbed result vector registers.
           std::fill_n(result, 8, dst_result);
@@ -566,7 +572,7 @@ void TestVectorInstructionInternal(ExecInsnFunc exec_insn,
               exec_insn, &source[0], &result[0], nullptr, nullptr, scalar_src, vstart, vtype, vl);
 
           // Values for inactive elements (i.e. corresponding mask bit is 0).
-          SIMD128 expected_inactive[8];
+          SIMD128Register expected_inactive[8];
           if constexpr (kTestVectorInstructionMode == TestVectorInstructionMode::kVMerge) {
             // vs2 is the start of the source vector register group.
             // Note: copy_n input/output args are backwards compared to fill_n below.
@@ -581,11 +587,13 @@ void TestVectorInstructionInternal(ExecInsnFunc exec_insn,
               if (index == 0 && emul == 2) {
                 EXPECT_EQ(result[index],
                           ((dst_result & kFractionMaskInt8[3]) |
-                           (SIMD128{expected_result[index]} & mask[index] & ~kFractionMaskInt8[3]) |
+                           (SIMD128Register{expected_result[index]} & mask[index] &
+                            ~kFractionMaskInt8[3]) |
                            (expected_inactive[index] & ~mask[index] & ~kFractionMaskInt8[3])));
               } else if (index == 2 && emul == 2) {
                 EXPECT_EQ(result[index],
-                          ((SIMD128{expected_result[index]} & mask[index] & kFractionMaskInt8[3]) |
+                          ((SIMD128Register{expected_result[index]} & mask[index] &
+                            kFractionMaskInt8[3]) |
                            (expected_inactive[index] & ~mask[index] & kFractionMaskInt8[3]) |
                            ((vta ? kAgnosticResult : dst_result) & ~kFractionMaskInt8[3])));
               } else if (index == 3 && emul == 2 && vta) {
@@ -594,15 +602,16 @@ void TestVectorInstructionInternal(ExecInsnFunc exec_insn,
                 EXPECT_EQ(result[index], dst_result);
               } else {
                 EXPECT_EQ(result[index],
-                          ((SIMD128{expected_result[index]} & mask[index]) |
+                          ((SIMD128Register{expected_result[index]} & mask[index]) |
                            ((expected_inactive[index] & ~mask[index]))));
               }
             }
           } else {
-            EXPECT_EQ(result[0],
-                      ((SIMD128{expected_result[0]} & mask[0] & kFractionMaskInt8[emul - 4]) |
-                       (expected_inactive[0] & ~mask[0] & kFractionMaskInt8[emul - 4]) |
-                       ((vta ? kAgnosticResult : dst_result) & ~kFractionMaskInt8[emul - 4])));
+            EXPECT_EQ(
+                result[0],
+                ((SIMD128Register{expected_result[0]} & mask[0] & kFractionMaskInt8[emul - 4]) |
+                 (expected_inactive[0] & ~mask[0] & kFractionMaskInt8[emul - 4]) |
+                 ((vta ? kAgnosticResult : dst_result) & ~kFractionMaskInt8[emul - 4])));
           }
         }
       }
@@ -628,7 +637,7 @@ template <TestVectorInstructionKind kTestVectorInstructionKind,
           size_t... kResultsCount>
 void TestVectorInstruction(ExecInsnFunc exec_insn,
                            ExecInsnFunc exec_masked_insn,
-                           const SIMD128 (&source)[16],
+                           const SIMD128Register (&source)[16],
                            const ExpectedResultType (&... expected_result)[kResultsCount]) {
   TestVectorInstructionInternal<kTestVectorInstructionKind, kTestVectorInstructionMode>(
       exec_insn, exec_masked_insn, kUndisturbedResult, source, expected_result...);
@@ -636,11 +645,11 @@ void TestVectorInstruction(ExecInsnFunc exec_insn,
 
 void TestVectorInstruction(ExecInsnFunc exec_insn,
                            ExecInsnFunc exec_masked_insn,
-                           const uint8_16_t (&expected_result_int8)[8],
-                           const uint16_8_t (&expected_result_int16)[8],
-                           const uint32_4_t (&expected_result_int32)[8],
-                           const uint64_2_t (&expected_result_int64)[8],
-                           const SIMD128 (&source)[16]) {
+                           const UInt8x16Tuple (&expected_result_int8)[8],
+                           const UInt16x8Tuple (&expected_result_int16)[8],
+                           const UInt32x4Tuple (&expected_result_int32)[8],
+                           const UInt64x2Tuple (&expected_result_int64)[8],
+                           const SIMD128Register (&source)[16]) {
   TestVectorInstruction<TestVectorInstructionKind::kInteger, TestVectorInstructionMode::kDefault>(
       exec_insn,
       exec_masked_insn,
@@ -653,19 +662,19 @@ void TestVectorInstruction(ExecInsnFunc exec_insn,
 
 void TestVectorFloatInstruction(ExecInsnFunc exec_insn,
                                 ExecInsnFunc exec_masked_insn,
-                                const uint32_4_t (&expected_result_int32)[8],
-                                const uint64_2_t (&expected_result_int64)[8],
-                                const SIMD128 (&source)[16]) {
+                                const UInt32x4Tuple (&expected_result_int32)[8],
+                                const UInt64x2Tuple (&expected_result_int64)[8],
+                                const SIMD128Register (&source)[16]) {
   TestVectorInstruction<TestVectorInstructionKind::kFloat, TestVectorInstructionMode::kDefault>(
       exec_insn, exec_masked_insn, source, expected_result_int32, expected_result_int64);
 }
 
 void TestNarrowingVectorInstruction(ExecInsnFunc exec_insn,
                                     ExecInsnFunc exec_masked_insn,
-                                    const uint8_16_t (&expected_result_int8)[4],
-                                    const uint16_8_t (&expected_result_int16)[4],
-                                    const uint32_4_t (&expected_result_int32)[4],
-                                    const SIMD128 (&source)[16]) {
+                                    const UInt8x16Tuple (&expected_result_int8)[4],
+                                    const UInt16x8Tuple (&expected_result_int16)[4],
+                                    const UInt32x4Tuple (&expected_result_int32)[4],
+                                    const SIMD128Register (&source)[16]) {
   TestVectorInstruction<TestVectorInstructionKind::kInteger, TestVectorInstructionMode::kNarrowing>(
       exec_insn,
       exec_masked_insn,
@@ -677,26 +686,26 @@ void TestNarrowingVectorInstruction(ExecInsnFunc exec_insn,
 
 void TestNarrowingVectorFloatInstruction(ExecInsnFunc exec_insn,
                                          ExecInsnFunc exec_masked_insn,
-                                         const uint32_4_t (&expected_result_int32)[4],
-                                         const SIMD128 (&source)[16]) {
+                                         const UInt32x4Tuple (&expected_result_int32)[4],
+                                         const SIMD128Register (&source)[16]) {
   TestVectorInstruction<TestVectorInstructionKind::kFloat, TestVectorInstructionMode::kNarrowing>(
       exec_insn, exec_masked_insn, source, expected_result_int32);
 }
 
 void TestNarrowingVectorFloatInstruction(ExecInsnFunc exec_insn,
                                          ExecInsnFunc exec_masked_insn,
-                                         const uint16_8_t (&expected_result_int16)[4],
-                                         const uint32_4_t (&expected_result_int32)[4],
-                                         const SIMD128 (&source)[16]) {
+                                         const UInt16x8Tuple (&expected_result_int16)[4],
+                                         const UInt32x4Tuple (&expected_result_int32)[4],
+                                         const SIMD128Register (&source)[16]) {
   TestVectorInstruction<TestVectorInstructionKind::kFloat, TestVectorInstructionMode::kNarrowing>(
       exec_insn, exec_masked_insn, source, expected_result_int16, expected_result_int32);
 }
 
 void TestWideningVectorFloatInstruction(ExecInsnFunc exec_insn,
                                         ExecInsnFunc exec_masked_insn,
-                                        const uint64_2_t (&expected_result_int64)[8],
-                                        const SIMD128 (&source)[16],
-                                        SIMD128 dst_result = kUndisturbedResult) {
+                                        const UInt64x2Tuple (&expected_result_int64)[8],
+                                        const SIMD128Register (&source)[16],
+                                        SIMD128Register dst_result = kUndisturbedResult) {
   TestVectorInstructionInternal<TestVectorInstructionKind::kFloat,
                                 TestVectorInstructionMode::kWidening>(
       exec_insn, exec_masked_insn, dst_result, source, expected_result_int64);
@@ -704,19 +713,19 @@ void TestWideningVectorFloatInstruction(ExecInsnFunc exec_insn,
 
 void TestWideningVectorFloatInstruction(ExecInsnFunc exec_insn,
                                         ExecInsnFunc exec_masked_insn,
-                                        const uint32_4_t (&expected_result_int32)[8],
-                                        const uint64_2_t (&expected_result_int64)[8],
-                                        const SIMD128 (&source)[16]) {
+                                        const UInt32x4Tuple (&expected_result_int32)[8],
+                                        const UInt64x2Tuple (&expected_result_int64)[8],
+                                        const SIMD128Register (&source)[16]) {
   TestVectorInstruction<TestVectorInstructionKind::kFloat, TestVectorInstructionMode::kWidening>(
       exec_insn, exec_masked_insn, source, expected_result_int32, expected_result_int64);
 }
 
 void TestWideningVectorInstruction(ExecInsnFunc exec_insn,
                                    ExecInsnFunc exec_masked_insn,
-                                   const uint16_8_t (&expected_result_int16)[8],
-                                   const uint32_4_t (&expected_result_int32)[8],
-                                   const uint64_2_t (&expected_result_int64)[8],
-                                   const SIMD128 (&source)[16]) {
+                                   const UInt16x8Tuple (&expected_result_int16)[8],
+                                   const UInt32x4Tuple (&expected_result_int32)[8],
+                                   const UInt64x2Tuple (&expected_result_int64)[8],
+                                   const SIMD128Register (&source)[16]) {
   TestVectorInstruction<TestVectorInstructionKind::kInteger, TestVectorInstructionMode::kWidening>(
       exec_insn,
       exec_masked_insn,
@@ -726,77 +735,87 @@ void TestWideningVectorInstruction(ExecInsnFunc exec_insn,
       expected_result_int64);
 }
 
-template <typename... ExpectedResultType>
+template <TestVectorInstructionMode kTestVectorInstructionMode, typename... ExpectedResultType>
 void TestVectorReductionInstruction(
     ExecInsnFunc exec_insn,
     ExecInsnFunc exec_masked_insn,
-    const SIMD128 (&source)[16],
+    const SIMD128Register (&source)[16],
     std::tuple<const ExpectedResultType (&)[8],
                const ExpectedResultType (&)[8]>... expected_result) {
   // Each expected_result input to this function is the vd[0] value of the reduction, for each
   // of the possible vlmul, i.e. expected_result_vd0_int8[n] = vd[0], int8, no mask, vlmul=n.
   //
   // As vlmul=4 is reserved, expected_result_vd0_*[4] is ignored.
-  auto Verify = [&source](ExecInsnFunc exec_insn,
-                          uint8_t vsew,
-                          uint8_t vlmul,
-                          const auto& expected_result) {
-    for (uint8_t vta = 0; vta < 2; ++vta) {
-      for (uint8_t vma = 0; vma < 2; ++vma) {
-        uint64_t vtype = (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
-        uint64_t vlmax = 0;
-        asm("vsetvl %0, zero, %1" : "=r"(vlmax) : "r"(vtype));
-        if (vlmax == 0) {
-          continue;
-        }
+  auto Verify =
+      [&source](ExecInsnFunc exec_insn, uint8_t vsew, uint8_t vlmul, const auto& expected_result) {
+        for (uint8_t vta = 0; vta < 2; ++vta) {
+          for (uint8_t vma = 0; vma < 2; ++vma) {
+            uint64_t vtype = (vma << 7) | (vta << 6) | (vsew << 3) | vlmul;
+            uint64_t vlmax = 0;
+            asm("vsetvl %0, zero, %1" : "=r"(vlmax) : "r"(vtype));
+            if (vlmax == 0) {
+              continue;
+            }
 
-        SIMD128 result[8];
-        // Set undisturbed result vector registers.
-        for (size_t index = 0; index < 8; ++index) {
-          result[index] = kUndisturbedResult;
-        }
+            SIMD128Register result[8];
+            // Set undisturbed result vector registers.
+            for (size_t index = 0; index < 8; ++index) {
+              result[index] = kUndisturbedResult;
+            }
 
-        // Exectations for reductions are for swapped source arguments.
-        SIMD128 two_sources[16]{};
-        memcpy(&two_sources[0], &source[8], sizeof(two_sources[0]) * 8);
-        memcpy(&two_sources[8], &source[0], sizeof(two_sources[0]) * 8);
-
-        RunTwoVectorArgsOneRes(exec_insn, &two_sources[0], &result[0], vtype, vlmax);
-
-        // Reduction instructions are unique in that they produce a scalar
-        // output to a single vector register as opposed to a register group.
-        // This allows us to take some short-cuts when validating:
-        //
-        // - The mask setting is only useful during computation, as the body
-        // of the destination is always only element 0, which will always be
-        // written to, regardless of mask setting.
-        // - The tail is guaranteed to be 1..VLEN/SEW, so the vlmul setting
-        // does not affect the elements that the tail policy applies to in the
-        // destination register.
-
-        // Verify that the destination register holds the reduction in the
-        // first element and the tail policy applies to the remaining.
-        SIMD128 expected_result_register = vta ? kAgnosticResult : kUndisturbedResult;
-        size_t vsew_bits = 8 << vsew;
-        expected_result_register = (expected_result_register >> vsew_bits) << vsew_bits;
-        expected_result_register |= SIMD128{expected_result};
-        EXPECT_EQ(result[0], expected_result_register) << " vtype=" << vtype;
-
-        // Verify all non-destination registers are undisturbed.
-        for (size_t index = 1; index < 8; ++index) {
-          EXPECT_EQ(result[index], kUndisturbedResult) << " vtype=" << vtype;
+            // Exectations for reductions are for swapped source arguments.
+            SIMD128Register two_sources[16]{};
+            memcpy(&two_sources[0], &source[8], sizeof(two_sources[0]) * 8);
+            memcpy(&two_sources[8], &source[0], sizeof(two_sources[0]) * 8);
+
+            RunTwoVectorArgsOneRes(exec_insn, &two_sources[0], &result[0], vtype, vlmax);
+
+            // Reduction instructions are unique in that they produce a scalar
+            // output to a single vector register as opposed to a register group.
+            // This allows us to take some short-cuts when validating:
+            //
+            // - The mask setting is only useful during computation, as the body
+            // of the destination is always only element 0, which will always be
+            // written to, regardless of mask setting.
+            // - The tail is guaranteed to be 1..VLEN/SEW, so the vlmul setting
+            // does not affect the elements that the tail policy applies to in the
+            // destination register.
+
+            // Verify that the destination register holds the reduction in the
+            // first element and the tail policy applies to the remaining.
+            SIMD128Register expected_result_register = vta ? kAgnosticResult : kUndisturbedResult;
+            size_t result_bits = 8 << vsew;
+            if constexpr (kTestVectorInstructionMode == TestVectorInstructionMode::kWidening) {
+              result_bits *= 2;
+            }
+            expected_result_register &= ~SIMD128Register{(__int128_t{1} << result_bits) - 1};
+            expected_result_register |= SIMD128Register{expected_result};
+            EXPECT_EQ(result[0], expected_result_register) << " vtype=" << vtype;
+
+            // Verify all non-destination registers are undisturbed.
+            for (size_t index = 1; index < 8; ++index) {
+              EXPECT_EQ(result[index], kUndisturbedResult)
+                  << " index=" << index << " vtype=" << vtype;
+            }
+          }
         }
-      }
+      };
+
+  auto GetVsew = [](size_t result_size) -> uint8_t {
+    size_t sew = result_size;
+    if constexpr (kTestVectorInstructionMode == TestVectorInstructionMode::kWidening) {
+      sew /= 2;
     }
+    return BitUtilLog2(sew);
   };
 
   for (int vlmul = 0; vlmul < 8; vlmul++) {
     ((Verify(exec_insn,
-             BitUtilLog2(sizeof(ExpectedResultType)),
+             GetVsew(sizeof(ExpectedResultType)),
              vlmul,
              std::get<0>(expected_result)[vlmul]),
       Verify(exec_masked_insn,
-             BitUtilLog2(sizeof(ExpectedResultType)),
+             GetVsew(sizeof(ExpectedResultType)),
              vlmul,
              std::get<1>(expected_result)[vlmul])),
      ...);
@@ -809,8 +828,8 @@ void TestVectorReductionInstruction(ExecInsnFunc exec_insn,
                                     const uint64_t (&expected_result_vd0_int64)[8],
                                     const uint32_t (&expected_result_vd0_with_mask_int32)[8],
                                     const uint64_t (&expected_result_vd0_with_mask_int64)[8],
-                                    const SIMD128 (&source)[16]) {
-  TestVectorReductionInstruction(
+                                    const SIMD128Register (&source)[16]) {
+  TestVectorReductionInstruction<TestVectorInstructionMode::kDefault>(
       exec_insn,
       exec_masked_insn,
       source,
@@ -830,8 +849,8 @@ void TestVectorReductionInstruction(ExecInsnFunc exec_insn,
                                     const uint16_t (&expected_result_vd0_with_mask_int16)[8],
                                     const uint32_t (&expected_result_vd0_with_mask_int32)[8],
                                     const uint64_t (&expected_result_vd0_with_mask_int64)[8],
-                                    const SIMD128 (&source)[16]) {
-  TestVectorReductionInstruction(
+                                    const SIMD128Register (&source)[16]) {
+  TestVectorReductionInstruction<TestVectorInstructionMode::kDefault>(
       exec_insn,
       exec_masked_insn,
       source,
@@ -845,9 +864,45 @@ void TestVectorReductionInstruction(ExecInsnFunc exec_insn,
                                                              expected_result_vd0_with_mask_int64});
 }
 
+void TestWideningVectorReductionInstruction(
+    ExecInsnFunc exec_insn,
+    ExecInsnFunc exec_masked_insn,
+    const uint64_t (&expected_result_vd0_int64)[8],
+    const uint64_t (&expected_result_vd0_with_mask_int64)[8],
+    const SIMD128Register (&source)[16]) {
+  TestVectorReductionInstruction<TestVectorInstructionMode::kWidening>(
+      exec_insn,
+      exec_masked_insn,
+      source,
+      std::tuple<const uint64_t(&)[8], const uint64_t(&)[8]>{expected_result_vd0_int64,
+                                                             expected_result_vd0_with_mask_int64});
+}
+
+void TestWideningVectorReductionInstruction(
+    ExecInsnFunc exec_insn,
+    ExecInsnFunc exec_masked_insn,
+    const uint16_t (&expected_result_vd0_int16)[8],
+    const uint32_t (&expected_result_vd0_int32)[8],
+    const uint64_t (&expected_result_vd0_int64)[8],
+    const uint16_t (&expected_result_vd0_with_mask_int16)[8],
+    const uint32_t (&expected_result_vd0_with_mask_int32)[8],
+    const uint64_t (&expected_result_vd0_with_mask_int64)[8],
+    const SIMD128Register (&source)[16]) {
+  TestVectorReductionInstruction<TestVectorInstructionMode::kWidening>(
+      exec_insn,
+      exec_masked_insn,
+      source,
+      std::tuple<const uint16_t(&)[8], const uint16_t(&)[8]>{expected_result_vd0_int16,
+                                                             expected_result_vd0_with_mask_int16},
+      std::tuple<const uint32_t(&)[8], const uint32_t(&)[8]>{expected_result_vd0_int32,
+                                                             expected_result_vd0_with_mask_int32},
+      std::tuple<const uint64_t(&)[8], const uint64_t(&)[8]>{expected_result_vd0_int64,
+                                                             expected_result_vd0_with_mask_int64});
+}
+
 template <bool kIsMasked, typename... ExpectedResultType, size_t... kResultsCount>
 void TestVectorIota(ExecInsnFunc exec_insn,
-                    const SIMD128 (&source)[16],
+                    const SIMD128Register (&source)[16],
                     const ExpectedResultType (&... expected_result)[kResultsCount]) {
   auto Verify = [&source](ExecInsnFunc exec_insn,
                           uint8_t vsew,
@@ -874,7 +929,7 @@ void TestVectorIota(ExecInsnFunc exec_insn,
               vlin = vl;
             }
 
-            SIMD128 result[8];
+            SIMD128Register result[8];
             // Set expected_result vector registers into 0b01010101… pattern.
             // Set undisturbed result vector registers.
             std::fill_n(result, 8, kUndisturbedResult);
@@ -882,7 +937,7 @@ void TestVectorIota(ExecInsnFunc exec_insn,
             RunCommonVectorFunc(
                 exec_insn, &source[0], &result[0], nullptr, nullptr, 0, 0, vtype, vlin);
 
-            SIMD128 expected_inactive[8];
+            SIMD128Register expected_inactive[8];
             std::fill_n(expected_inactive, 8, (vma ? kAgnosticResult : kUndisturbedResult));
 
             // vl of 0 should never change dst registers
@@ -896,7 +951,7 @@ void TestVectorIota(ExecInsnFunc exec_insn,
                   if (index == 2 && vlmul == 2) {
                     EXPECT_EQ(
                         result[index],
-                        ((SIMD128{expected_result[index]} & elem_mask[index] &
+                        ((SIMD128Register{expected_result[index]} & elem_mask[index] &
                           kFractionMaskInt8[3]) |
                          (expected_inactive[index] & ~elem_mask[index] & kFractionMaskInt8[3]) |
                          ((vta ? kAgnosticResult : kUndisturbedResult) & ~kFractionMaskInt8[3])));
@@ -904,7 +959,7 @@ void TestVectorIota(ExecInsnFunc exec_insn,
                     EXPECT_EQ(result[index], vta ? kAgnosticResult : kUndisturbedResult);
                   } else {
                     EXPECT_EQ(result[index],
-                              ((SIMD128{expected_result[index]} & elem_mask[index]) |
+                              ((SIMD128Register{expected_result[index]} & elem_mask[index]) |
                                (expected_inactive[index] & ~elem_mask[index])));
                   }
                 }
@@ -913,7 +968,8 @@ void TestVectorIota(ExecInsnFunc exec_insn,
               // vlmul >= 4 only uses 1 register
               EXPECT_EQ(
                   result[0],
-                  ((SIMD128{expected_result[0]} & elem_mask[0] & kFractionMaskInt8[vlmul - 4]) |
+                  ((SIMD128Register{expected_result[0]} & elem_mask[0] &
+                    kFractionMaskInt8[vlmul - 4]) |
                    (expected_inactive[0] & ~elem_mask[0] & kFractionMaskInt8[vlmul - 4]) |
                    ((vta ? kAgnosticResult : kUndisturbedResult) & ~kFractionMaskInt8[vlmul - 4])));
             }
@@ -932,11 +988,11 @@ void TestVectorIota(ExecInsnFunc exec_insn,
 
 template <bool kIsMasked>
 void TestVectorIota(ExecInsnFunc exec_insn,
-                    const uint8_16_t (&expected_result_int8)[8],
-                    const uint16_8_t (&expected_result_int16)[8],
-                    const uint32_4_t (&expected_result_int32)[8],
-                    const uint64_2_t (&expected_result_int64)[8],
-                    const SIMD128 (&source)[16]) {
+                    const UInt8x16Tuple (&expected_result_int8)[8],
+                    const UInt16x8Tuple (&expected_result_int16)[8],
+                    const UInt32x4Tuple (&expected_result_int32)[8],
+                    const UInt64x2Tuple (&expected_result_int64)[8],
+                    const SIMD128Register (&source)[16]) {
   TestVectorIota<kIsMasked>(exec_insn,
                             source,
                             expected_result_int8,
@@ -947,10 +1003,10 @@ void TestVectorIota(ExecInsnFunc exec_insn,
 
 void TestExtendingVectorInstruction(ExecInsnFunc exec_insn,
                                     ExecInsnFunc exec_masked_insn,
-                                    const uint16_8_t (&expected_result_int16)[8],
-                                    const uint32_4_t (&expected_result_int32)[8],
-                                    const uint64_2_t (&expected_result_int64)[8],
-                                    const SIMD128 (&source)[16],
+                                    const UInt16x8Tuple (&expected_result_int16)[8],
+                                    const UInt32x4Tuple (&expected_result_int32)[8],
+                                    const UInt64x2Tuple (&expected_result_int64)[8],
+                                    const SIMD128Register (&source)[16],
                                     const uint8_t factor) {
   auto Verify = [&source, &factor](ExecInsnFunc exec_insn,
                                    uint8_t vsew,
@@ -987,7 +1043,7 @@ void TestExtendingVectorInstruction(ExecInsnFunc exec_insn,
             vl = vlmax;
           }
 
-          SIMD128 result[8];
+          SIMD128Register result[8];
           // Set expected_result vector registers into 0b01010101… pattern.
           // Set undisturbed result vector registers.
           std::fill_n(result, 8, kUndisturbedResult);
@@ -997,22 +1053,22 @@ void TestExtendingVectorInstruction(ExecInsnFunc exec_insn,
 
           // Values for inactive elements (i.e. corresponding mask bit is 0).
           const size_t n = std::size(source) * 2;
-          SIMD128 expected_inactive[n];
+          SIMD128Register expected_inactive[n];
           // For most instructions, follow basic inactive processing rules based on vma flag.
           std::fill_n(expected_inactive, n, (vma ? kAgnosticResult : kUndisturbedResult));
 
           if (vlmul < 4) {
             for (size_t index = 0; index < 1 << vlmul; ++index) {
               if (index == 0 && vlmul == 2) {
-                EXPECT_EQ(
-                    result[index],
-                    (kUndisturbedResult & kFractionMaskInt8[3]) |
-                        (SIMD128{expected_result[index]} & mask[index] & ~kFractionMaskInt8[3]) |
-                        (expected_inactive[index] & ~mask[index] & ~kFractionMaskInt8[3]));
+                EXPECT_EQ(result[index],
+                          (kUndisturbedResult & kFractionMaskInt8[3]) |
+                              (SIMD128Register{expected_result[index]} & mask[index] &
+                               ~kFractionMaskInt8[3]) |
+                              (expected_inactive[index] & ~mask[index] & ~kFractionMaskInt8[3]));
               } else if (index == 2 && vlmul == 2) {
                 EXPECT_EQ(
                     result[index],
-                    (SIMD128{expected_result[index]} & mask[index] & kFractionMaskInt8[3]) |
+                    (SIMD128Register{expected_result[index]} & mask[index] & kFractionMaskInt8[3]) |
                         (expected_inactive[index] & ~mask[index] & kFractionMaskInt8[3]) |
                         ((vta ? kAgnosticResult : kUndisturbedResult) & ~kFractionMaskInt8[3]));
               } else if (index == 3 && vlmul == 2 && vta) {
@@ -1021,14 +1077,14 @@ void TestExtendingVectorInstruction(ExecInsnFunc exec_insn,
                 EXPECT_EQ(result[index], kUndisturbedResult);
               } else {
                 EXPECT_EQ(result[index],
-                          (SIMD128{expected_result[index]} & mask[index]) |
+                          (SIMD128Register{expected_result[index]} & mask[index]) |
                               (expected_inactive[index] & ~mask[index]));
               }
             }
           } else {
             EXPECT_EQ(
                 result[0],
-                (SIMD128{expected_result[0]} & mask[0] & kFractionMaskInt8[vlmul - 4]) |
+                (SIMD128Register{expected_result[0]} & mask[0] & kFractionMaskInt8[vlmul - 4]) |
                     (expected_inactive[0] & ~mask[0] & kFractionMaskInt8[vlmul - 4]) |
                     ((vta ? kAgnosticResult : kUndisturbedResult) & ~kFractionMaskInt8[vlmul - 4]));
           }
@@ -1067,7 +1123,7 @@ template <TestVectorInstructionKind kTestVectorInstructionKind,
 void TestVectorPermutationInstruction(
     ExecInsnFunc exec_insn,
     ExecInsnFunc exec_masked_insn,
-    const SIMD128 (&source)[16],
+    const SIMD128Register (&source)[16],
     uint8_t vlmul,
     uint64_t skip,
     bool ignore_vma_for_last,
@@ -1105,7 +1161,7 @@ void TestVectorPermutationInstruction(
     }
     // Values for which the mask is not applied due to being before the offset when doing
     // vslideup.
-    SIMD128 skip_mask[num_regs];
+    SIMD128Register skip_mask[num_regs];
     int64_t toskip = skip;
     for (size_t index = 0; index < num_regs && toskip > 0; ++index) {
       size_t skip_bits = toskip * kElementSize * 8;
@@ -1138,7 +1194,7 @@ void TestVectorPermutationInstruction(
           vl = vlmax;
         }
 
-        SIMD128 result[8];
+        SIMD128Register result[8];
         // Set expected_result vector registers into 0b01010101… pattern.
         // Set undisturbed result vector registers.
         std::fill_n(result, 8, kUndisturbedResult);
@@ -1149,7 +1205,7 @@ void TestVectorPermutationInstruction(
 
         const size_t n = std::size(source);
         // Values for inactive elements (i.e. corresponding mask bit is 0).
-        SIMD128 expected_inactive[n];
+        SIMD128Register expected_inactive[n];
         // For most instructions, follow basic inactive processing rules based on vma flag.
         std::fill_n(expected_inactive, n, (vma ? kAgnosticResult : kUndisturbedResult));
 
@@ -1164,9 +1220,9 @@ void TestVectorPermutationInstruction(
               (expected_inactive[last_reg] & ~mask_for_vl) | (kUndisturbedResult & mask_for_vl);
         }
 
-        SIMD128 expected_result[std::size(expected_result_raw)];
+        SIMD128Register expected_result[std::size(expected_result_raw)];
         for (size_t index = 0; index < std::size(expected_result_raw); ++index) {
-          expected_result[index] = SIMD128{expected_result_raw[index]};
+          expected_result[index] = SIMD128Register{expected_result_raw[index]};
         }
 
         if (vlmul == 2 && last_elem_is_reg1) {
@@ -1218,10 +1274,8 @@ void TestVectorPermutationInstruction(
                             (expected_inactive[index] & ~mask[index] & ~skip_mask[index] &
                              kFractionMaskInt8[3]) |
                             ((vta ? kAgnosticResult : kUndisturbedResult) & ~kFractionMaskInt8[3]));
-            } else if (index == 3 && vlmul == 2 && vta) {
-              EXPECT_EQ(result[index], kAgnosticResult);
             } else if (index == 3 && vlmul == 2) {
-              EXPECT_EQ(result[index], kUndisturbedResult);
+              EXPECT_EQ(result[index], vta ? kAgnosticResult : kUndisturbedResult);
             } else {
               EXPECT_EQ(result[index],
                         (expected_result[index] & (mask[index] | skip_mask[index])) |
@@ -1229,15 +1283,17 @@ void TestVectorPermutationInstruction(
             }
           }
         } else {
-          SIMD128 v8 = result[0];
-          SIMD128 affected_part{expected_result[0] &
-                                ((mask[0] & kFractionMaskInt8[vlmul - 4]) | skip_mask[0])};
-          SIMD128 masked_part{expected_inactive[0] & ~mask[0] & ~skip_mask[0] &
-                              kFractionMaskInt8[vlmul - 4]};
-          SIMD128 tail_part{(vta ? kAgnosticResult : kUndisturbedResult) &
-                            ~kFractionMaskInt8[vlmul - 4]};
-
-          EXPECT_EQ(v8, affected_part | masked_part | tail_part);
+          SIMD128Register affected_part{expected_result[0] &
+                                        ((mask[0] & kFractionMaskInt8[vlmul - 4]) | skip_mask[0])};
+          SIMD128Register masked_part{expected_inactive[0] & ~mask[0] & ~skip_mask[0] &
+                                      kFractionMaskInt8[vlmul - 4]};
+          SIMD128Register tail_part{(vta ? kAgnosticResult : kUndisturbedResult) &
+                                    ~kFractionMaskInt8[vlmul - 4]};
+
+          EXPECT_EQ(result[0], affected_part | masked_part | tail_part)
+              << "vlmul=" << uint32_t{vlmul} << " vsew=" << uint32_t{vsew}
+              << " vma=" << uint32_t{vma} << " vl=" << vl << " vstart=" << vstart
+              << " affected_part=" << affected_part;
         }
       }
     }
@@ -1258,11 +1314,11 @@ void TestVectorPermutationInstruction(
 
 void TestVectorPermutationInstruction(ExecInsnFunc exec_insn,
                                       ExecInsnFunc exec_masked_insn,
-                                      const uint8_16_t (&expected_result_int8)[8],
-                                      const uint16_8_t (&expected_result_int16)[8],
-                                      const uint32_4_t (&expected_result_int32)[8],
-                                      const uint64_2_t (&expected_result_int64)[8],
-                                      const SIMD128 (&source)[16],
+                                      const UInt8x16Tuple (&expected_result_int8)[8],
+                                      const UInt16x8Tuple (&expected_result_int16)[8],
+                                      const UInt32x4Tuple (&expected_result_int32)[8],
+                                      const UInt64x2Tuple (&expected_result_int64)[8],
+                                      const SIMD128Register (&source)[16],
                                       uint8_t vlmul,
                                       uint64_t regt0 = 0x0,
                                       uint64_t skip = 0,
@@ -1285,7 +1341,7 @@ void TestVectorPermutationInstruction(ExecInsnFunc exec_insn,
 template <typename... ExpectedResultType>
 void TestVectorMaskTargetInstruction(ExecInsnFunc exec_insn,
                                      ExecInsnFunc exec_masked_insn,
-                                     const SIMD128 (&source)[16],
+                                     const SIMD128Register (&source)[16],
                                      const ExpectedResultType(&... expected_result)) {
   auto Verify = [&source](
                     ExecInsnFunc exec_insn, uint8_t vsew, const auto& expected_result, auto mask) {
@@ -1324,7 +1380,7 @@ void TestVectorMaskTargetInstruction(ExecInsnFunc exec_insn,
             vl = vlmax;
           }
 
-          SIMD128 result[8];
+          SIMD128Register result[8];
           // Set expected_result vector registers into 0b01010101… pattern.
           // Set undisturbed result vector registers.
           std::fill_n(result, 8, kUndisturbedResult);
@@ -1332,23 +1388,23 @@ void TestVectorMaskTargetInstruction(ExecInsnFunc exec_insn,
           RunCommonVectorFunc(
               exec_insn, &source[0], &result[0], nullptr, nullptr, scalar_src, vstart, vtype, vl);
 
-          SIMD128 expected_result_in_register(expected_result);
-          if (vma == 0) {
-            expected_result_in_register =
-                (expected_result_in_register & mask) | (kUndisturbedResult & ~mask);
-          } else {
-            expected_result_in_register |= ~mask;
-          }
+          SIMD128Register expected_result_in_register(expected_result);
+          expected_result_in_register = (expected_result_in_register & mask) |
+                                        ((vma ? kAgnosticResult : kUndisturbedResult) & ~mask);
           // Mask registers are always processing tail like vta is set.
           if (vlmax != 128) {
-            expected_result_in_register |= MakeBitmaskFromVl(vl);
+            const SIMD128Register vl_mask = MakeBitmaskFromVl(vl);
+            expected_result_in_register =
+                (kAgnosticResult & vl_mask) | (expected_result_in_register & ~vl_mask);
           }
           if (vlmul == 2) {
-            const SIMD128 start_mask = MakeBitmaskFromVl(vstart);
+            const SIMD128Register start_mask = MakeBitmaskFromVl(vstart);
             expected_result_in_register =
                 (kUndisturbedResult & ~start_mask) | (expected_result_in_register & start_mask);
           }
-          EXPECT_EQ(result[0], expected_result_in_register);
+          EXPECT_EQ(result[0], expected_result_in_register)
+              << "vlmul=" << uint32_t{vlmul} << " vsew=" << uint32_t{vsew}
+              << " vma=" << uint32_t{vma} << " vl=" << vl << " vstart=" << vstart;
         }
       }
     }
@@ -1369,18 +1425,18 @@ void TestVectorMaskTargetInstruction(ExecInsnFunc exec_insn,
                                      ExecInsnFunc exec_masked_insn,
                                      const uint32_t expected_result_int32,
                                      const uint16_t expected_result_int64,
-                                     const SIMD128 (&source)[16]) {
+                                     const SIMD128Register (&source)[16]) {
   TestVectorMaskTargetInstruction(
       exec_insn, exec_masked_insn, source, expected_result_int32, expected_result_int64);
 }
 
 void TestVectorMaskTargetInstruction(ExecInsnFunc exec_insn,
                                      ExecInsnFunc exec_masked_insn,
-                                     const uint8_16_t expected_result_int8,
+                                     const UInt8x16Tuple expected_result_int8,
                                      const uint64_t expected_result_int16,
                                      const uint32_t expected_result_int32,
                                      const uint16_t expected_result_int64,
-                                     const SIMD128 (&source)[16]) {
+                                     const SIMD128Register (&source)[16]) {
   TestVectorMaskTargetInstruction(exec_insn,
                                   exec_masked_insn,
                                   source,
@@ -1455,6 +1511,104 @@ TEST(InlineAsmTestRiscv64, TestVredsum) {
       kVectorCalculationsSource);
 }
 
+DEFINE_TWO_ARG_ONE_RES_FUNCTION(Vwredsumu, vwredsumu.vs)
+
+TEST(InlineAsmTestRiscv64, TestVwredsumu) {
+  TestWideningVectorReductionInstruction(
+      ExecVwredsumu,
+      ExecMaskedVwredsumu,
+      // expected_result_vd0_int16
+      {0x85f2, 0x8ce4, 0xa0c8, 0xc090, /* unused */ 0, 0x8192, 0x822c, 0x8379},
+      // expected_result_vd0_int32
+      {0x8307'0172,
+       0x830c'82e4,
+       0x831a'88c8,
+       0x8322'a090,
+       /* unused */ 0,
+       0x8303'1300,
+       0x8303'a904,
+       0x8304'e119},
+      // expected_result_vd0_int64
+      {0x8706'8506'cb44'b932,
+       0x8706'8509'9407'71e4,
+       0x8706'8510'a70e'64c8,
+       0x8706'8514'd312'5090,
+       /* unused */ 0,
+       /* unused */ 0,
+       0x8706'8505'1907'1300,
+       0x8706'8505'b713'ad09},
+      // expected_result_vd0_with_mask_int16
+      {0x8427, 0x88f8, 0x948e, 0xab1b, /* unused */ 0, 0x8100, 0x819a, 0x82d2},
+      // expected_result_vd0_with_mask_int32
+      {0x8305'5f45,
+       0x8308'c22f,
+       0x8311'99d0,
+       0x8316'98bf,
+       /* unused */ 0,
+       0x8303'1300,
+       0x8303'1300,
+       0x8304'4b15},
+      // expected_result_vd0_with_mask_int64
+      {0x8706'8506'2d38'1f29,
+       0x8706'8507'99a1'838a,
+       0x8706'850c'1989'ef5c,
+       0x8706'850e'9cf4'4aa1,
+       /* unused */ 0,
+       /* unused */ 0,
+       0x8706'8505'1907'1300,
+       0x8706'8505'1907'1300},
+      kVectorCalculationsSource);
+}
+
+DEFINE_TWO_ARG_ONE_RES_FUNCTION(Vwredsum, vwredsum.vs)
+
+TEST(InlineAsmTestRiscv64, TestVwredsum) {
+  TestWideningVectorReductionInstruction(
+      ExecVwredsum,
+      ExecMaskedVwredsum,
+      // expected_result_vd0_int16
+      {0x7df2, 0x7ce4, 0x80c8, 0x8090, /* unused */ 0, 0x8092, 0x802c, 0x7f79},
+      // expected_result_vd0_int32
+      {0x82ff'0172,
+       0x82fc'82e4,
+       0x82fa'88c8,
+       0x8302'a090,
+       /* unused */ 0,
+       0x8302'1300,
+       0x8301'a904,
+       0x8300'e119},
+      // expected_result_vd0_int64
+      {0x8706'8502'cb44'b932,
+       0x8706'8501'9407'71e4,
+       0x8706'8500'a70e'64c8,
+       0x8706'8504'd312'5090,
+       /* unused */ 0,
+       /* unused */ 0,
+       0x8706'8504'1907'1300,
+       0x8706'8503'b713'ad09},
+      // expected_result_vd0_with_mask_int16
+      {0x7f27, 0x7df8, 0x818e, 0x811b, /* unused */ 0, 0x8100, 0x809a, 0x7fd2},
+      // expected_result_vd0_with_mask_int32
+      {0x8300'5f45,
+       0x82fe'c22f,
+       0x82fd'99d0,
+       0x8302'98bf,
+       /* unused */ 0,
+       0x8302'1300,
+       0x8302'1300,
+       0x8301'4b15},
+      // expected_result_vd0_with_mask_int64
+      {0x8706'8503'2d38'1f29,
+       0x8706'8502'99a1'838a,
+       0x8706'8502'1989'ef5c,
+       0x8706'8504'9cf4'4aa1,
+       /* unused */ 0,
+       /* unused */ 0,
+       0x8706'8504'1907'1300,
+       0x8706'8504'1907'1300},
+      kVectorCalculationsSource);
+}
+
 DEFINE_TWO_ARG_ONE_RES_FUNCTION(Vfredosum, vfredosum.vs)
 
 TEST(InlineAsmTestRiscv64, TestVfredosum) {
@@ -1545,6 +1699,62 @@ TEST(InlineAsmTestRiscv64, TestVfredusum) {
                                  kVectorCalculationsSource);
 }
 
+DEFINE_TWO_ARG_ONE_RES_FUNCTION(Vfwredusum, vfwredusum.vs)
+
+// We currently don't support half-precision (16-bit) floats, so only check 32-bit to 64-bit
+// widening.
+TEST(InlineAsmTestRiscv64, TestVfwredusum) {
+  TestWideningVectorReductionInstruction(ExecVfwredusum,
+                                         ExecMaskedVfwredusum,
+                                         // expected_result_vd0_int64
+                                         {0xbbc1'9351'b253'9156,
+                                          0xbfc5'9759'b65b'955e,
+                                          0xc7cd'9f69'be6b'9d6e,
+                                          0x47cd'7f89'9e8b'7d8d,
+                                          /* unused */ 0,
+                                          /* unused */ 0,
+                                          0xbac0'9240'0000'0000,
+                                          0xbbc1'9351'b240'0000},
+                                         // expected_result_vd0_with_mask_int64
+                                         {0xbac0'9253'9155'9042,
+                                          0xbfc5'9745'2017'9547,
+                                          0xc7cd'9f69'be6b'9d4f,
+                                          0x47cd'7f50'81d3'7d6f,
+                                          /* unused */ 0,
+                                          /* unused */ 0,
+                                          0xbac0'9240'0000'0000,
+                                          0xbac0'9240'0000'0000},
+                                         kVectorCalculationsSource);
+}
+
+DEFINE_TWO_ARG_ONE_RES_FUNCTION(Vfwredosum, vfwredosum.vs)
+
+// We currently don't support half-precision (16-bit) floats, so only check 32-bit to 64-bit
+// widening.
+TEST(InlineAsmTestRiscv64, TestVfwredosum) {
+  TestWideningVectorReductionInstruction(ExecVfwredosum,
+                                         ExecMaskedVfwredosum,
+                                         // expected_result_vd0_int64
+                                         {0xbbc1'9351'b253'9156,
+                                          0xbfc5'9759'b65b'955e,
+                                          0xc7cd'9f69'be6b'9d6e,
+                                          0x47cd'7f89'9e8b'7d8d,
+                                          /* unused */ 0,
+                                          /* unused */ 0,
+                                          0xbac0'9240'0000'0000,
+                                          0xbbc1'9351'b240'0000},
+                                         // expected_result_vd0_with_mask_int64
+                                         {0xbac0'9253'9155'9042,
+                                          0xbfc5'9745'2017'9547,
+                                          0xc7cd'9f69'be6b'9d4f,
+                                          0x47cd'7f50'81d3'7d6f,
+                                          /* unused */ 0,
+                                          /* unused */ 0,
+                                          0xbac0'9240'0000'0000,
+                                          0xbac0'9240'0000'0000},
+                                         kVectorCalculationsSource);
+}
+
 DEFINE_TWO_ARG_ONE_RES_FUNCTION(Vredand, vredand.vs)
 
 TEST(InlineAsmTestRiscv64, TestVredand) {
@@ -4162,8 +4372,6 @@ TEST(InlineAsmTestRiscv64, TestVmfeq) {
       ExecVmfeqvf, ExecMaskedVmfeqvf, 0x0000'0040, 0x0020, kVectorComparisonSource);
 }
 
-}  // namespace
-
 [[gnu::naked]] void ExecVaadduvv() {
   asm("vaaddu.vv  v8, v16, v24\n\t"
       "ret\n\t");
@@ -9185,6 +9393,7 @@ TEST(InlineAsmTestRiscv64, TestVslide1up) {
        {0xdedc'dad8'd6d4'd2d1, 0xeeec'eae9'e6e4'e2e0}},
       kVectorCalculationsSourceLegacy);
 }
+
 [[gnu::naked]] void ExecVsllvv() {
   asm("vsll.vv  v8, v16, v24\n\t"
       "ret\n\t");
@@ -10770,6 +10979,7 @@ TEST(InlineAsmTestRiscv64, TestVmulhsu) {
                         kVectorCalculationsSourceLegacy);
 }
 
+// TODO(b/301577077): Add vi tests with non-zero shift.
 [[gnu::naked]] void ExecVslidedownvi() {
   asm("vslidedown.vi  v8, v24, 0\n\t"
       "ret\n\t");
@@ -11237,7 +11447,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
   TestVectorPermutationInstruction(
       ExecVslidedownvx,
       ExecMaskedVslidedownvx,
-      {{2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
+      {{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
@@ -11245,7 +11455,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
-      {{0x0604, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
+      {{0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
@@ -11277,7 +11487,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
   TestVectorPermutationInstruction(
       ExecVslidedownvx,
       ExecMaskedVslidedownvx,
-      {{17, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
+      {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
@@ -11318,7 +11528,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
   TestVectorPermutationInstruction(
       ExecVslidedownvx,
       ExecMaskedVslidedownvx,
-      {{2, 4, 6, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
+      {{2, 4, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
@@ -11326,7 +11536,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
-      {{0x0604, 0x0a09, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
+      {{0x0604, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
@@ -11334,7 +11544,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000}},
-      {{0x0e0c'0a09, 0x0000'0000, 0x0000'0000, 0x0000'0000},
+      {{0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
@@ -11358,7 +11568,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
   TestVectorPermutationInstruction(
       ExecVslidedownvx,
       ExecMaskedVslidedownvx,
-      {{17, 18, 20, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
+      {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
@@ -11399,7 +11609,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
   TestVectorPermutationInstruction(
       ExecVslidedownvx,
       ExecMaskedVslidedownvx,
-      {{2, 4, 6, 9, 10, 12, 14, 17, 0, 0, 0, 0, 0, 0, 0, 0},
+      {{2, 4, 6, 9, 10, 12, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
@@ -11407,7 +11617,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
-      {{0x0604, 0x0a09, 0x0e0c, 0x1211, 0x0000, 0x0000, 0x0000, 0x0000},
+      {{0x0604, 0x0a09, 0x0e0c, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
@@ -11415,7 +11625,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
        {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000}},
-      {{0x0e0c'0a09, 0x1614'1211, 0x0000'0000, 0x0000'0000},
+      {{0x0e0c'0a09, 0x0000'0000, 0x0000'0000, 0x0000'0000},
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
@@ -11423,7 +11633,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000},
        {0x0000'0000, 0x0000'0000, 0x0000'0000, 0x0000'0000}},
-      {{0x1e1c'1a18'1614'1211, 0x0000'0000'0000'0000},
+      {{0x0000'0000'0000'0000, 0x0000'0000'0000'0000},
        {0x0000'0000'0000'0000, 0x0000'0000'0000'0000},
        {0x0000'0000'0000'0000, 0x0000'0000'0000'0000},
        {0x0000'0000'0000'0000, 0x0000'0000'0000'0000},
@@ -11439,7 +11649,7 @@ TEST(InlineAsmTestRiscv64, TestVslidedown) {
   TestVectorPermutationInstruction(
       ExecVslidedownvx,
       ExecMaskedVslidedownvx,
-      {{17, 18, 20, 22, 24, 26, 28, 30, 0, 0, 0, 0, 0, 0, 0, 0},
+      {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
@@ -12182,3 +12392,7 @@ TEST(InlineAsmTestRiscv64, TestVslideup) {
       /*regx1=*/8,
       /*skip=*/8);
 }
+
+}  // namespace
+
+}  // namespace berberis
diff --git a/tests/jni_tests/Android.bp b/tests/jni_tests/Android.bp
index d137d7b1..bafb9d7c 100644
--- a/tests/jni_tests/Android.bp
+++ b/tests/jni_tests/Android.bp
@@ -25,7 +25,7 @@ android_test {
         "androidx.test.ext.junit",
         "androidx.test.rules",
     ],
-    libs: ["android.test.runner"],
+    libs: ["android.test.runner.stubs"],
     jni_libs: ["libberberis_jni_tests"],
     sdk_version: "current",
 }
diff --git a/tests/ndk_program_tests/Android.bp b/tests/ndk_program_tests/Android.bp
index 36e95616..c7121cc0 100644
--- a/tests/ndk_program_tests/Android.bp
+++ b/tests/ndk_program_tests/Android.bp
@@ -76,6 +76,9 @@ cc_defaults {
     arch: {
         riscv64: {
             srcs: [":berberis_ndk_program_tests_riscv64_srcs"],
+            // Note: we don't even need to use anything from that library, just need to ensure it
+            // can be compiled successfully: all checks are done with static_asserts.
+            static_libs: ["libberberis_emulated_libvulkan_api_checker"],
         },
     },
     header_libs: ["libberberis_ndk_program_tests_headers"],
diff --git a/tiny_loader/Android.bp b/tiny_loader/Android.bp
index 07249b68..1ec3e096 100644
--- a/tiny_loader/Android.bp
+++ b/tiny_loader/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_tinyloader_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: ["libberberis_base_headers"],
@@ -28,7 +28,7 @@ cc_library_headers {
 
 cc_library_static {
     name: "libberberis_tinyloader",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     srcs: [
         "tiny_loader.cc",
```

