```diff
diff --git a/android_api/gen_proxy_libraries.py b/android_api/gen_proxy_libraries.py
index 9404013..9e11e3d 100755
--- a/android_api/gen_proxy_libraries.py
+++ b/android_api/gen_proxy_libraries.py
@@ -195,8 +195,8 @@ class ProxyGenerator:
                             '--host_arch',
                             host_json_suffix],
                            shell=False)
-    if p.wait() != 0:
-      raise Exception('Error while generating custom trampolines for %s' % library)
+      if p.wait() != 0:
+        raise Exception('Error while generating custom trampolines for %s' % library)
 
     print('Generating %s trampolines for %s, logs: %s' % (
         trampoline_suffix, library, tmp_output_trampolines[1]))
diff --git a/android_api/libc/Android.bp b/android_api/libc/Android.bp
index dfb223f..f1572f5 100644
--- a/android_api/libc/Android.bp
+++ b/android_api/libc/Android.bp
@@ -30,6 +30,7 @@ cc_library {
         // Definitions come from bionic/libc/Android.bp that force
         // the usage of the correct native allocator.
         "libc_native_allocator_defaults",
+        "keep_symbols",
     ],
     name: "libnative_bridge_guest_libc",
     overrides: ["libc"],
@@ -83,36 +84,16 @@ cc_library {
                 // For backwards-compatibility, some arm32 builtins are exported from libc.so.
                 static_libs: ["libclang_rt.builtins-exported"],
             },
-
-            // Arm 32 bit does not produce complete exidx unwind information
-            // so keep the .debug_frame which is relatively small and does
-            // include needed unwind information.
-            // See b/132992102 for details.
-            strip: {
-                keep_symbols_and_debug_frame: true,
-            },
         },
         arm64: {
             srcs: ["stubs_arm64.cpp"],
 
             version_script: ":libc.arm64.map",
-
-            // Leave the symbols in the shared library so that stack unwinders can produce
-            // meaningful name resolution.
-            strip: {
-                keep_symbols: true,
-            },
         },
         riscv64: {
             srcs: ["stubs_riscv64.cpp"],
 
             version_script: ":libc.riscv64.map",
-
-            // Leave the symbols in the shared library so that stack unwinders can produce
-            // meaningful name resolution.
-            strip: {
-                keep_symbols: true,
-            },
         },
     },
 
@@ -147,9 +128,9 @@ cc_library {
         never: true,
     },
 
-    // lld complains about duplicate symbols in libcrt and libgcc. Suppress the
-    // warning since this is intended right now.
-    // Bug: 117558759
+    // lld complains about duplicate symbols in libc because we are intercepting some symbols that
+    // are not marked as weak in bionic.
+    // TODO(b/349973092): remove workaround when all relevant symbols are properly marked.
     ldflags: ["-Wl,-z,muldefs"],
 }
 
diff --git a/android_api/libc/proxy/custom_trampolines_arm64_to_x86_64.json b/android_api/libc/proxy/custom_trampolines_arm64_to_x86_64.json
index 81ed1d6..503881a 100644
--- a/android_api/libc/proxy/custom_trampolines_arm64_to_x86_64.json
+++ b/android_api/libc/proxy/custom_trampolines_arm64_to_x86_64.json
@@ -161,6 +161,30 @@
       "is_compatible": true,
       "signature": "vp"
     },
+    "android_crash_detail_register": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "ppipi"
+    },
+    "android_crash_detail_unregister": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vp"
+    },
+    "android_crash_detail_replace_data": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vppi"
+    },
+    "android_crash_detail_replace_name": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vppi"
+    },
     "clock_gettime": {
       "call_method": "default",
       "comment": "clock_gettime uses call to vdso symbol to avoid doing syscall, this is why we want to proxy it to the host library",
diff --git a/android_api/libc/proxy/custom_trampolines_arm_to_x86.json b/android_api/libc/proxy/custom_trampolines_arm_to_x86.json
index 6d3d1bd..a2e2a97 100644
--- a/android_api/libc/proxy/custom_trampolines_arm_to_x86.json
+++ b/android_api/libc/proxy/custom_trampolines_arm_to_x86.json
@@ -161,6 +161,30 @@
       "is_compatible": true,
       "signature": "vp"
     },
+    "android_crash_detail_register": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "ppipi"
+    },
+    "android_crash_detail_unregister": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vp"
+    },
+    "android_crash_detail_replace_data": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vppi"
+    },
+    "android_crash_detail_replace_name": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vppi"
+    },
     "environ": {
       "call_method": "do_not_call",
       "header": "unitstd.h",
diff --git a/android_api/libc/proxy/custom_trampolines_riscv64_to_x86_64.json b/android_api/libc/proxy/custom_trampolines_riscv64_to_x86_64.json
index c177ad3..503881a 100644
--- a/android_api/libc/proxy/custom_trampolines_riscv64_to_x86_64.json
+++ b/android_api/libc/proxy/custom_trampolines_riscv64_to_x86_64.json
@@ -161,6 +161,30 @@
       "is_compatible": true,
       "signature": "vp"
     },
+    "android_crash_detail_register": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "ppipi"
+    },
+    "android_crash_detail_unregister": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vp"
+    },
+    "android_crash_detail_replace_data": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vppi"
+    },
+    "android_crash_detail_replace_name": {
+      "call_method": "default",
+      "header": "android/crash_detail.h",
+      "is_compatible": true,
+      "signature": "vppi"
+    },
     "clock_gettime": {
       "call_method": "default",
       "comment": "clock_gettime uses call to vdso symbol to avoid doing syscall, this is why we want to proxy it to the host library",
@@ -588,4 +612,4 @@
     }
   },
   "types": {}
-}
\ No newline at end of file
+}
diff --git a/android_api/libc/proxy/trampolines_arm64_to_x86_64-inl.h b/android_api/libc/proxy/trampolines_arm64_to_x86_64-inl.h
index 8b5ab35..aac6718 100644
--- a/android_api/libc/proxy/trampolines_arm64_to_x86_64-inl.h
+++ b/android_api/libc/proxy/trampolines_arm64_to_x86_64-inl.h
@@ -22,6 +22,10 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"__system_property_wait_any", GetTrampolineFunc<auto(uint32_t) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"_longjmp", GetTrampolineFunc<auto(void*, int32_t) -> void>(), reinterpret_cast<void*>(DoThunk__longjmp)},
 {"_setjmp", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(DoThunk__setjmp)},
+{"android_crash_detail_register", GetTrampolineFunc<auto(void*, int32_t, void*, int32_t) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_replace_data", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_replace_name", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_unregister", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"android_getaddrinfofornet", GetTrampolineFunc<auto(void*, void*, void*, uint32_t, uint32_t, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"android_getaddrinfofornetcontext", GetTrampolineFunc<auto(void*, void*, void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"android_mallopt", GetTrampolineFunc<auto(int32_t, void*, size_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libc/proxy/trampolines_arm_to_x86-inl.h b/android_api/libc/proxy/trampolines_arm_to_x86-inl.h
index 965b760..54f0d1f 100644
--- a/android_api/libc/proxy/trampolines_arm_to_x86-inl.h
+++ b/android_api/libc/proxy/trampolines_arm_to_x86-inl.h
@@ -22,6 +22,10 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"__system_property_wait_any", GetTrampolineFunc<auto(uint32_t) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"_longjmp", GetTrampolineFunc<auto(void*, int32_t) -> void>(), reinterpret_cast<void*>(DoThunk__longjmp)},
 {"_setjmp", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(DoThunk__setjmp)},
+{"android_crash_detail_register", GetTrampolineFunc<auto(void*, int32_t, void*, int32_t) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_replace_data", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_replace_name", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_unregister", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"android_getaddrinfofornet", GetTrampolineFunc<auto(void*, void*, void*, uint32_t, uint32_t, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"android_getaddrinfofornetcontext", GetTrampolineFunc<auto(void*, void*, void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"android_mallopt", GetTrampolineFunc<auto(int32_t, void*, size_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libc/proxy/trampolines_riscv64_to_x86_64-inl.h b/android_api/libc/proxy/trampolines_riscv64_to_x86_64-inl.h
index 8b5ab35..aac6718 100644
--- a/android_api/libc/proxy/trampolines_riscv64_to_x86_64-inl.h
+++ b/android_api/libc/proxy/trampolines_riscv64_to_x86_64-inl.h
@@ -22,6 +22,10 @@ const KnownTrampoline kKnownTrampolines[] = {
 {"__system_property_wait_any", GetTrampolineFunc<auto(uint32_t) -> uint32_t>(), reinterpret_cast<void*>(NULL)},
 {"_longjmp", GetTrampolineFunc<auto(void*, int32_t) -> void>(), reinterpret_cast<void*>(DoThunk__longjmp)},
 {"_setjmp", GetTrampolineFunc<auto(void*) -> int32_t>(), reinterpret_cast<void*>(DoThunk__setjmp)},
+{"android_crash_detail_register", GetTrampolineFunc<auto(void*, int32_t, void*, int32_t) -> void*>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_replace_data", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_replace_name", GetTrampolineFunc<auto(void*, void*, int32_t) -> void>(), reinterpret_cast<void*>(NULL)},
+{"android_crash_detail_unregister", GetTrampolineFunc<auto(void*) -> void>(), reinterpret_cast<void*>(NULL)},
 {"android_getaddrinfofornet", GetTrampolineFunc<auto(void*, void*, void*, uint32_t, uint32_t, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"android_getaddrinfofornetcontext", GetTrampolineFunc<auto(void*, void*, void*, void*, void*) -> int32_t>(), reinterpret_cast<void*>(NULL)},
 {"android_mallopt", GetTrampolineFunc<auto(int32_t, void*, size_t) -> int32_t>(), reinterpret_cast<void*>(NULL)},
diff --git a/android_api/libc/stubs_arm.cpp b/android_api/libc/stubs_arm.cpp
index 0720fc2..3939c9e 100644
--- a/android_api/libc/stubs_arm.cpp
+++ b/android_api/libc/stubs_arm.cpp
@@ -39,6 +39,10 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(__system_property_wait);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(__system_property_wait_any);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_longjmp);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_setjmp);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_register);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_replace_data);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_replace_name);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_unregister);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_getaddrinfofornet);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_getaddrinfofornetcontext);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_mallopt);
@@ -135,6 +139,10 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", __system_property_wait_any);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", _longjmp);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", _setjmp);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_register);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_replace_data);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_replace_name);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_unregister);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_getaddrinfofornet);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_getaddrinfofornetcontext);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_mallopt);
diff --git a/android_api/libc/stubs_arm64.cpp b/android_api/libc/stubs_arm64.cpp
index 88c3711..177b8ae 100644
--- a/android_api/libc/stubs_arm64.cpp
+++ b/android_api/libc/stubs_arm64.cpp
@@ -39,6 +39,10 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(__system_property_wait);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(__system_property_wait_any);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_longjmp);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_setjmp);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_register);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_replace_data);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_replace_name);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_unregister);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_getaddrinfofornet);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_getaddrinfofornetcontext);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_mallopt);
@@ -137,6 +141,10 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", __system_property_wait_any);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", _longjmp);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", _setjmp);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_register);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_replace_data);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_replace_name);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_unregister);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_getaddrinfofornet);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_getaddrinfofornetcontext);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_mallopt);
diff --git a/android_api/libc/stubs_riscv64.cpp b/android_api/libc/stubs_riscv64.cpp
index 88c3711..177b8ae 100644
--- a/android_api/libc/stubs_riscv64.cpp
+++ b/android_api/libc/stubs_riscv64.cpp
@@ -39,6 +39,10 @@ DEFINE_INTERCEPTABLE_STUB_FUNCTION(__system_property_wait);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(__system_property_wait_any);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_longjmp);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(_setjmp);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_register);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_replace_data);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_replace_name);
+DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_crash_detail_unregister);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_getaddrinfofornet);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_getaddrinfofornetcontext);
 DEFINE_INTERCEPTABLE_STUB_FUNCTION(android_mallopt);
@@ -137,6 +141,10 @@ static void __attribute__((constructor(0))) init_stub_library() {
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", __system_property_wait_any);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", _longjmp);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", _setjmp);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_register);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_replace_data);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_replace_name);
+  INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_crash_detail_unregister);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_getaddrinfofornet);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_getaddrinfofornetcontext);
   INIT_INTERCEPTABLE_STUB_FUNCTION("libc.so", android_mallopt);
diff --git a/android_api/libvulkan/Android.bp b/android_api/libvulkan/Android.bp
index fbdd5d7..5405da8 100644
--- a/android_api/libvulkan/Android.bp
+++ b/android_api/libvulkan/Android.bp
@@ -82,7 +82,7 @@ bootstrap_go_package {
 blueprint_go_binary {
     name: "gen_vulkan",
     srcs: ["proxy/gen_vulkan.go"],
-    testSrcs: ["gen_vulkan_test.go"],
+    testSrcs: ["proxy/gen_vulkan_test.go"],
     deps: ["vulkan_xml"],
 }
 
@@ -92,3 +92,10 @@ filegroup {
         "proxy/vulkan_trampolines.cc",
     ],
 }
+
+filegroup {
+    name: "native_bridge_proxy_libvulkan_checker",
+    srcs: [
+        "proxy/emulated_api_checker.cc",
+    ],
+}
diff --git a/android_api/libvulkan/proxy/cpp_types.go b/android_api/libvulkan/proxy/cpp_types.go
index 5130f96..c5aa3c8 100644
--- a/android_api/libvulkan/proxy/cpp_types.go
+++ b/android_api/libvulkan/proxy/cpp_types.go
@@ -116,6 +116,25 @@ const (
 	LastArch  = X86_64
 )
 
+func Define(arch Arch) string {
+	switch arch {
+	default:
+		panic(fmt.Sprintf("cpp_types: Unknown arch %d", arch))
+	case Arm:
+		return "defined(__arm__)"
+	case Arm64:
+		return "defined(__aarch64__)"
+	case Riscv32:
+		return "defined(__riscv) && (__riscv_xlen == 32)"
+	case Riscv64:
+		return "defined(__riscv) && (__riscv_xlen == 64)"
+	case X86:
+		return "defined(__i386__)"
+	case X86_64:
+		return "defined(__x86_64__)"
+	}
+}
+
 // The zero Kind is Invalid Kind.
 type Kind uint
 
diff --git a/android_api/libvulkan/proxy/emulated_api_checker.cc b/android_api/libvulkan/proxy/emulated_api_checker.cc
new file mode 100644
index 0000000..3c57d07
--- /dev/null
+++ b/android_api/libvulkan/proxy/emulated_api_checker.cc
@@ -0,0 +1,18 @@
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
+#define BERBERIS_LAYOUT_CHECK_ONLY
+#include "vulkan_xml.h"
diff --git a/android_api/libvulkan/proxy/gen_vulkan.go b/android_api/libvulkan/proxy/gen_vulkan.go
index 5bba43e..6b77f5e 100644
--- a/android_api/libvulkan/proxy/gen_vulkan.go
+++ b/android_api/libvulkan/proxy/gen_vulkan.go
@@ -177,6 +177,11 @@ func generateVulkanXML(sorted_type_names []string, types map[string]cpp_types.Ty
 		return err
 	}
 
+	_, err = fmt.Fprint(out_file, "#ifndef BERBERIS_LAYOUT_CHECK_ONLY\n")
+	if err != nil {
+		return err
+	}
+
 	err = printExtensionsMap(out_file, extensions)
 	if err != nil {
 		return err
@@ -200,15 +205,6 @@ func generateVulkanXML(sorted_type_names []string, types map[string]cpp_types.Ty
 	_, err = fmt.Fprint(out_file,
 		`
 
-namespace {
-
-`)
-
-	_, err = fmt.Fprint(out_file,
-		`
-
-}  // namespace
-
 // Note: we put all the conversion routines in the anonymous namespace to make sure we are not
 // generating dead code or referencing non-existing code: attempt to use static function which
 // is not defined is error and if function is unreferenced that causes error since we are compiling
@@ -252,8 +248,15 @@ void RunGuest_vkGetInstanceProcAddr(GuestAddr pc, GuestArgumentBuffer* buf);
 		return err
 	}
 
+	err = printGuestStructVerification(out_file, sorted_type_names, types, host_arch, guest_arch)
+	if err != nil {
+		return err
+	}
+
 	_, err = fmt.Fprintf(out_file,
-		`} // namespace
+		`#endif  // BERBERIS_LAYOUT_CHECK_ONLY
+
+} // namespace
 
 }  // namespace berberis
 
@@ -279,22 +282,17 @@ void RunGuest_vkGetInstanceProcAddr(GuestAddr pc, GuestArgumentBuffer* buf);
 		return err
 	}
 
-	err = printAliasVerification(out_file, sorted_type_names, types)
-	if err != nil {
-		return err
-	}
-
-	err = printEnumVerification(out_file, sorted_type_names, types)
+	err = printAliasVerification(out_file, sorted_type_names, types, host_arch, guest_arch)
 	if err != nil {
 		return err
 	}
 
-	err = printHostStructVerification(out_file, sorted_type_names, types)
+	err = printEnumVerification(out_file, sorted_type_names, types, host_arch, guest_arch)
 	if err != nil {
 		return err
 	}
 
-	err = printGuestStructVerification(out_file, sorted_type_names, types, host_arch, guest_arch)
+	err = printHostStructVerification(out_file, sorted_type_names, types, host_arch, guest_arch)
 	if err != nil {
 		return err
 	}
@@ -421,24 +419,40 @@ func printAliasTypes(w io.Writer, sorted_type_names []string, types map[string]c
 	return nil
 }
 
-func printAliasVerification(w io.Writer, sorted_type_names []string, types map[string]cpp_types.Type) error {
+func printAliasVerification(w io.Writer, sorted_type_names []string, types map[string]cpp_types.Type, host_arch, guest_arch cpp_types.Arch) error {
 	for _, name := range sorted_type_names {
 		typе := types[name]
 		if !vulkan_types.IsVulkanHandle(typе) && !vulkan_types.IsVulkanNondispatchableHandle(typе) && !isAlias(typе) {
 			continue
 		}
+		if isAliasOfOpaque(typе) {
+			continue
+		}
 		_, err := fmt.Fprintf(
 			w,
-			`#if !defined(BERBERIS_%s)
-CHECK_STRUCT_LAYOUT(berberis::%s, sizeof(::%s) * 8, alignof(::%s) * 8);
-#endif  /* BERBERIS_%s */
+			`#if %[7]s
+CHECK_STRUCT_LAYOUT(berberis::%[2]s, %[3]d, %[4]d);
+#if !defined(BERBERIS_%[1]s)
+CHECK_STRUCT_LAYOUT(::%[2]s, %[3]d, %[4]d);
+#endif  /* BERBERIS_%[1]s */
+#elif %[8]s
+CHECK_STRUCT_LAYOUT(berberis::%[2]s, %[5]d, %[6]d);
+#if !defined(BERBERIS_%[1]s)
+CHECK_STRUCT_LAYOUT(::%[2]s, %[5]d, %[6]d);
+#endif  /* BERBERIS_%[1]s */
+#else
+#error Unsupported architecture.
+#endif
 
 `,
 			toEnumNameWithSuffix(name, "NOVERIFY"),
 			name,
-			name,
-			name,
-			toEnumNameWithSuffix(name, "NOVERIFY"))
+			typе.Bits(host_arch),
+			typе.Align(host_arch),
+			typе.Bits(guest_arch),
+			typе.Align(guest_arch),
+			cpp_types.Define(host_arch),
+			cpp_types.Define(guest_arch))
 		if err != nil {
 			return err
 		}
@@ -498,7 +512,7 @@ func printEnums(w io.Writer, sorted_type_names []string, types map[string]cpp_ty
 	return nil
 }
 
-func printEnumVerification(w io.Writer, sorted_type_names []string, types map[string]cpp_types.Type) error {
+func printEnumVerification(w io.Writer, sorted_type_names []string, types map[string]cpp_types.Type, host_arch, guest_arch cpp_types.Arch) error {
 	for _, name := range sorted_type_names {
 		typе := types[name]
 		// Note: currently enums in vk.xml are architecture-agnostic. If some type is enum then it's always enum, on all
@@ -512,13 +526,30 @@ func printEnumVerification(w io.Writer, sorted_type_names []string, types map[st
 		}
 		_, err = fmt.Fprintf(
 			w,
-			`#if !defined(BERBERIS_%s)
-CHECK_STRUCT_LAYOUT(berberis::%s, sizeof(%s) * 8, alignof(%s) * 8);
+			`#if %[7]s
+CHECK_STRUCT_LAYOUT(berberis::%[2]s, %[3]d, %[4]d);
+#elif %[8]s
+CHECK_STRUCT_LAYOUT(berberis::%[2]s, %[5]d, %[6]d);
+#else
+#error Unsupported architecture.
+#endif
+#if !defined(BERBERIS_%[1]s)
+#if %[7]s
+CHECK_STRUCT_LAYOUT(::%[2]s, %[3]d, %[4]d);
+#elif %[8]s
+CHECK_STRUCT_LAYOUT(::%[2]s, %[5]d, %[6]d);
+#else
+#error Unsupported architecture.
+#endif
 `,
 			toEnumNameWithSuffix(name, "NOVERIFY"),
 			name,
-			name,
-			name)
+			typе.Bits(host_arch),
+			typе.Align(host_arch),
+			typе.Bits(guest_arch),
+			typе.Align(guest_arch),
+			cpp_types.Define(host_arch),
+			cpp_types.Define(guest_arch))
 		if err != nil {
 			return err
 		}
@@ -526,12 +557,10 @@ CHECK_STRUCT_LAYOUT(berberis::%s, sizeof(%s) * 8, alignof(%s) * 8);
 			field := typе.Field(i, cpp_types.FirstArch).(cpp_types.EnumFieldInfo)
 			_, err = fmt.Fprintf(
 				w,
-				`#if !defined(BERBERIS_%s_NOVERIFY)
-static_assert(std::int64_t(%s) == std::int64_t(berberis::BERBERIS_%s));
+				`#if !defined(BERBERIS_%[1]s_NOVERIFY)
+static_assert(std::int64_t(%[1]s) == std::int64_t(berberis::BERBERIS_%[1]s));
 #endif
 `,
-				field.Name(),
-				field.Name(),
 				field.Name())
 			if err != nil {
 				return err
@@ -539,17 +568,14 @@ static_assert(std::int64_t(%s) == std::int64_t(berberis::BERBERIS_%s));
 		}
 		_, err = fmt.Fprintf(
 			w,
-			`#if !defined(BERBERIS_%s_NOVERIFY)
-static_assert(std::int64_t(%s) == std::int64_t(berberis::BERBERIS_%s));
-#endif  /* BERBERIS_%s_NOVERIFY */
-#endif  /* BERBERIS_%s */
+			`#if !defined(BERBERIS_%[2]s_NOVERIFY)
+static_assert(std::int64_t(%[2]s) == std::int64_t(berberis::BERBERIS_%[2]s));
+#endif  /* BERBERIS_%[2]s_NOVERIFY */
+#endif  /* BERBERIS_%[1]s */
 
 `,
-			toEnumNameWithSuffix(name, "MAX_ENUM"),
-			toEnumNameWithSuffix(name, "MAX_ENUM"),
-			toEnumNameWithSuffix(name, "MAX_ENUM"),
-			toEnumNameWithSuffix(name, "MAX_ENUM"),
-			toEnumNameWithSuffix(name, "NOVERIFY"))
+			toEnumNameWithSuffix(name, "NOVERIFY"),
+			toEnumNameWithSuffix(name, "MAX_ENUM"))
 		if err != nil {
 			return err
 		}
@@ -3132,34 +3158,91 @@ func doesNeedHolder(typе cpp_types.Type, host_arch cpp_types.Arch, guest_arch c
 	return false
 }
 
-func printHostStructVerification(w io.Writer, sorted_type_names []string, types map[string]cpp_types.Type) error {
+func printHostStructVerification(w io.Writer, sorted_type_names []string, types map[string]cpp_types.Type, host_arch, guest_arch cpp_types.Arch) error {
 	for _, name := range sorted_type_names {
 		typе := types[name]
 		if !isStruct(typе) && !isUnion(typе) {
 			continue
 		}
+		fields_check_berberis_host := []string{}
+		fields_check_platform_host := []string{}
+		for i := uint(0); i < typе.NumField(host_arch); i++ {
+			field := typе.Field(i, host_arch)
+			var field_offset uint
+			if !isUnion(typе) {
+				field_offset = field.(cpp_types.StructFieldInfo).Offset()
+			} else {
+				field_offset = 0
+			}
+			fields_check_berberis_host = append(fields_check_berberis_host,
+				fmt.Sprintf("CHECK_FIELD_LAYOUT(berberis::%[1]s, %[2]s, %[3]d, %[4]d);",
+					name,
+					field.Name(),
+					field_offset,
+					field.Type().Bits(host_arch)))
+			fields_check_platform_host = append(fields_check_platform_host,
+				fmt.Sprintf("CHECK_FIELD_LAYOUT(::%[1]s, %[2]s, %[3]d, %[4]d);",
+					name,
+					field.Name(),
+					field_offset,
+					field.Type().Bits(host_arch)))
+		}
+		fields_check_berberis_guest := []string{}
+		fields_check_platform_guest := []string{}
+		for i := uint(0); i < typе.NumField(guest_arch); i++ {
+			field := typе.Field(i, guest_arch)
+			var field_offset uint
+			if !isUnion(typе) {
+				field_offset = field.(cpp_types.StructFieldInfo).Offset()
+			} else {
+				field_offset = 0
+			}
+			fields_check_berberis_guest = append(fields_check_berberis_guest,
+				fmt.Sprintf("CHECK_FIELD_LAYOUT(berberis::%[1]s, %[2]s, %[3]d, %[4]d);",
+					name,
+					field.Name(),
+					field_offset,
+					field.Type().Bits(guest_arch)))
+			fields_check_platform_guest = append(fields_check_platform_guest,
+				fmt.Sprintf("CHECK_FIELD_LAYOUT(::%[1]s, %[2]s, %[3]d, %[4]d);",
+					name,
+					field.Name(),
+					field_offset,
+					field.Type().Bits(guest_arch)))
+		}
 		_, err := fmt.Fprintf(
 			w,
-			`#if !defined(BERBERIS_%[1]s)
-CHECK_STRUCT_LAYOUT(berberis::%[2]s, sizeof(%[2]s) * 8, alignof(%[2]s) * 8);
+			`#if %[7]s
+CHECK_STRUCT_LAYOUT(berberis::%[2]s, %[3]d, %[4]d);
+%[9]s
+#if !defined(BERBERIS_%[1]s)
+CHECK_STRUCT_LAYOUT(::%[2]s, %[3]d, %[4]d);
+%[10]s
+#endif  /* BERBERIS_%[1]s */
+#elif %[8]s
+CHECK_STRUCT_LAYOUT(berberis::%[2]s, %[5]d, %[6]d);
+%[11]s
+#if !defined(BERBERIS_%[1]s)
+CHECK_STRUCT_LAYOUT(::%[2]s, %[5]d, %[6]d);
+%[12]s
+#endif  /* BERBERIS_%[1]s */
+#else
+#error Unsupported architecture.
+#endif
+
 `,
 			toEnumNameWithSuffix(name, "NOVERIFY"),
-			name)
-		if err != nil {
-			return err
-		}
-		for i := uint(0); i < typе.NumField(cpp_types.FirstArch); i++ {
-			field := typе.Field(i, cpp_types.FirstArch)
-			_, err = fmt.Fprintf(
-				w,
-				"CHECK_FIELD_LAYOUT(berberis::%[1]s, %[2]s, offsetof(::%[1]s, %[2]s) * 8, sizeof(std::declval<::%[1]s*>()->%[2]s) * 8);\n",
-				name,
-				field.Name())
-			if err != nil {
-				return err
-			}
-		}
-		_, err = fmt.Fprintf(w, "#endif  /* %s */\n\n", toEnumNameWithSuffix(name, "NOVERIFY"))
+			name,
+			typе.Bits(host_arch),
+			typе.Align(host_arch),
+			typе.Bits(guest_arch),
+			typе.Align(guest_arch),
+			cpp_types.Define(host_arch),
+			cpp_types.Define(guest_arch),
+			strings.Join(fields_check_berberis_host, "\n"),
+			strings.Join(fields_check_platform_host, "\n"),
+			strings.Join(fields_check_berberis_guest, "\n"),
+			strings.Join(fields_check_platform_guest, "\n"))
 		if err != nil {
 			return err
 		}
@@ -3793,6 +3876,10 @@ func isAliasOfEnum(typе cpp_types.Type) bool {
 	return cpp_types.IsKind(typе, []cpp_types.Kind{cpp_types.Alias, cpp_types.Enum})
 }
 
+func isAliasOfOpaque(typе cpp_types.Type) bool {
+	return cpp_types.IsKind(typе, []cpp_types.Kind{cpp_types.Alias, cpp_types.Opaque})
+}
+
 func isArray(typе cpp_types.Type) bool {
 	return cpp_types.IsKind(typе, []cpp_types.Kind{cpp_types.Array})
 }
diff --git a/android_api/libvulkan/proxy/vulkan_types.go b/android_api/libvulkan/proxy/vulkan_types.go
index a9f6379..d45bc56 100644
--- a/android_api/libvulkan/proxy/vulkan_types.go
+++ b/android_api/libvulkan/proxy/vulkan_types.go
@@ -35,7 +35,7 @@ var HANDLEType = cpp_types.AliasType(
 
 var HINSTANCEType = cpp_types.AliasType("HINSTANCE", HANDLEType)
 
-var HMONITORType = cpp_types.AliasType("HINSTANCE", HANDLEType)
+var HMONITORType = cpp_types.AliasType("HMONITOR", HANDLEType)
 
 var HWNDType = cpp_types.AliasType("HWND", HANDLEType)
 
diff --git a/android_api/libvulkan/proxy/vulkan_xml.h b/android_api/libvulkan/proxy/vulkan_xml.h
index 7c2589f..003dc73 100644
--- a/android_api/libvulkan/proxy/vulkan_xml.h
+++ b/android_api/libvulkan/proxy/vulkan_xml.h
@@ -23,6 +23,7 @@
 
 #include "berberis/base/bit_util.h"
 #include "berberis/base/struct_check.h"
+#ifndef BERBERIS_LAYOUT_CHECK_ONLY
 #include "berberis/guest_abi/function_wrappers.h"
 #include "berberis/guest_abi/guest_arguments.h"
 #include "berberis/guest_abi/guest_function_wrapper_signature.h"
@@ -36,6 +37,8 @@
 #include "berberis/runtime_primitives/runtime_library.h"
 
 #include "binary_search.h"
+#endif
+
 // Note: we only need these defines at the end of xvulkan_xml-inl.h and would like to not include it
 // prematurely but vulkan_xml_define.h couldn't be included from vulkan_xml-inl.h when these two
 // files are in different filegroups.
@@ -54,6 +57,8 @@ struct xcb_connection_t;
 
 namespace berberis {
 
+#ifndef BERBERIS_LAYOUT_CHECK_ONLY
+
 template <typename ResultType, typename... ArgumentType>
 inline ResultType (*WrapGuestFunctionIfNeeded(GuestType<ResultType (*)(ArgumentType...)> func,
                                               const char* name))(ArgumentType...) {
@@ -108,6 +113,7 @@ static GuestType<const void*> ConvertOptionalStructures(const void* head,
 static GuestType<void*> ConvertOptionalStructures(void* head,
                                                   std::unique_ptr<GuestHolderBase>& holder,
                                                   bool& out_of_memory);
+#endif  // BERBERIS_LAYOUT_CHECK_ONLY
 
 namespace {
 
diff --git a/android_api/libvulkan/proxy/vulkan_xml_define.h b/android_api/libvulkan/proxy/vulkan_xml_define.h
index 4b7d1eb..9ce08ff 100644
--- a/android_api/libvulkan/proxy/vulkan_xml_define.h
+++ b/android_api/libvulkan/proxy/vulkan_xml_define.h
@@ -44,8 +44,6 @@
 
 // DirectFB types: vulkan_directfb.h requires definitions of DirectFB types which are not available
 // on Android.
-#define BERBERIS_IDIRECT_NOVERIFY_FB 1
-#define BERBERIS_IDIRECT_FBSURFACE_NOVERIFY 1
 #define BERBERIS_VK_DIRECT_FBSURFACE_CREATE_FLAGS_NOVERIFY_EXT 1
 #define BERBERIS_VK_DIRECT_FBSURFACE_CREATE_INFO_NOVERIFY_EXT 1
 
diff --git a/native_bridge_support.mk b/native_bridge_support.mk
index 7e5d243..0a73245 100644
--- a/native_bridge_support.mk
+++ b/native_bridge_support.mk
@@ -28,8 +28,7 @@
 # NATIVE_BRIDGE_MODIFIED_GUEST_LIBS: List of modified guest libraries that require host counterpart.
 #
 
-# Note: When modifying this variable, please also update the `phony_deps` of
-#       `berberis_riscv64_to_x86_64_defaults` in
+# Note: keep in sync with `berberis_all_riscv64_to_x86_64_defaults` in
 #       frameworks/libs/binary_translation/Android.bp.
 NATIVE_BRIDGE_PRODUCT_PACKAGES := \
     libnative_bridge_vdso.native_bridge \
@@ -58,10 +57,9 @@ NATIVE_BRIDGE_PRODUCT_PACKAGES := \
 # libicui18n.bootstrap
 # libicuuc.bootstrap
 
-# Note: When modifying this variable, please also update the `phony_deps` of
-#       `berberis_riscv64_to_x86_64_defaults` in
-#       frameworks/libs/binary_translation/Android.bp.
 # Original guest libraries.
+# Note: keep in sync with `berberis_all_riscv64_to_x86_64_defaults` in
+#       frameworks/libs/binary_translation/Android.bp.
 NATIVE_BRIDGE_ORIG_GUEST_LIBS := \
     libandroidicu.bootstrap \
     libcompiler_rt \
@@ -79,10 +77,9 @@ NATIVE_BRIDGE_ORIG_GUEST_LIBS := \
     libutils \
     libz
 
-# Note: When modifying this variable, please also update the `phony_deps` of
-#       `berberis_riscv64_to_x86_64_defaults` in
-#       frameworks/libs/binary_translation/Android.bp.
 # These libraries need special support on the native bridge implementation side.
+# Note: keep in sync with `berberis_all_riscv64_to_x86_64_defaults` in
+#       frameworks/libs/binary_translation/Android.bp.
 NATIVE_BRIDGE_MODIFIED_GUEST_LIBS := \
     libaaudio \
     libamidi \
```

