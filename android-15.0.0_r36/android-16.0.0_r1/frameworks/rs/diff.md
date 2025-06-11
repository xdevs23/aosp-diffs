```diff
diff --git a/Android.bp b/Android.bp
index c24ed3c4..d28392e3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -14,6 +14,7 @@ cc_defaults {
         "-Werror",
         "-Wall",
         "-Wextra",
+        "-Wno-cast-function-type-mismatch",
         "-Wno-deprecated-declarations",
         "-Wno-unused-parameter",
         "-Wno-unused-variable",
@@ -88,7 +89,7 @@ cc_library_shared {
     },
 
     target: {
-        native_bridge : {
+        native_bridge: {
             header_libs: [
                 "libnativewindow_headers",
                 "media_ndk_headers",
diff --git a/cpp/Android.bp b/cpp/Android.bp
index 433c79fc..afe7f2ea 100644
--- a/cpp/Android.bp
+++ b/cpp/Android.bp
@@ -17,15 +17,15 @@ cc_library_static {
     ],
 
     cflags: [
-        "-Wall",
-        "-Werror",
         "-Wno-unused-parameter",
         "-DRS_COMPATIBILITY_LIB",
     ],
 
-
     sdk_version: "9",
-    shared_libs: ["libdl", "liblog"],
+    shared_libs: [
+        "libdl",
+        "liblog",
+    ],
     // Used in librsjni, which is built as NDK code => no ASan.
     sanitize: {
         never: true,
@@ -54,23 +54,17 @@ cc_defaults {
     ],
 
     cflags: [
-        "-Werror",
-        "-Wall",
-        "-Wextra",
-        "-Wno-deprecated-declarations",
         "-Wno-unused-parameter",
-        "-Wno-unused-variable",
     ],
-
     // We need to export not just rs/cpp but also rs.  This is because
     // RenderScript.h includes rsCppStructs.h, which includes rs/rsDefines.h.
     header_libs: [
         "jni_headers",
-        "rs-headers"
+        "rs-headers",
     ],
     export_header_lib_headers: [
         "jni_headers",
-        "rs-headers"
+        "rs-headers",
     ],
     export_include_dirs: ["."],
 
@@ -103,7 +97,10 @@ cc_library_static {
     name: "libRScpp_static",
     defaults: ["libRScpp-defaults"],
 
-    cflags: ["-DRS_COMPATIBILITY_LIB"],
+    cflags: [
+        "-Wno-unused-parameter",
+        "-DRS_COMPATIBILITY_LIB",
+    ],
 
     sdk_version: "9",
     whole_static_libs: ["libRSDispatch"],
diff --git a/cpu_ref/Android.bp b/cpu_ref/Android.bp
index 0d1e1790..6a02a64a 100644
--- a/cpu_ref/Android.bp
+++ b/cpu_ref/Android.bp
@@ -74,8 +74,12 @@ cc_library_shared {
         x86_64: {
             cflags: ["-DARCH_X86_HAVE_SSSE3"],
             srcs: ["rsCpuIntrinsics_x86.cpp"],
-	    avx2: {
-                cflags: ["-DARCH_X86_HAVE_AVX2", "-mavx2", "-mfma"],
+            avx2: {
+                cflags: [
+                    "-DARCH_X86_HAVE_AVX2",
+                    "-mavx2",
+                    "-mfma",
+                ],
             },
         },
         riscv64: {
@@ -102,11 +106,8 @@ cc_library_shared {
         "frameworks/compile/libbcc/include",
         "frameworks/rs",
     ],
-
     cflags: [
-        "-Werror",
-        "-Wall",
-        "-Wextra",
+        "-Wno-cast-function-type-mismatch",
         "-Wno-unused-parameter",
         "-Wno-unused-variable",
     ],
diff --git a/script_api/Android.bp b/script_api/Android.bp
index 8046bd0b..abddf9aa 100644
--- a/script_api/Android.bp
+++ b/script_api/Android.bp
@@ -17,11 +17,6 @@ cc_binary_host {
         "GenerateRSFunctionsList.cpp",
     ],
 
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
-
     sanitize: {
         never: true,
     },
diff --git a/support/jni/Android.bp b/support/jni/Android.bp
index 5a86d46e..21a3847f 100644
--- a/support/jni/Android.bp
+++ b/support/jni/Android.bp
@@ -20,9 +20,6 @@ cc_library_shared {
     ],
 
     cflags: [
-        "-Werror",
-        "-Wall",
-        "-Wextra",
         "-Wno-unused-parameter",
         "-DRS_COMPATIBILITY_LIB",
     ],
@@ -66,9 +63,6 @@ cc_library_shared {
     ],
 
     cflags: [
-        "-Werror",
-        "-Wall",
-        "-Wextra",
         "-Wno-unused-parameter",
         "-DRS_COMPATIBILITY_LIB",
     ],
diff --git a/tests/cpp_api/Android.bp b/tests/cpp_api/Android.bp
index 9c3632ac..dbb9b8b6 100644
--- a/tests/cpp_api/Android.bp
+++ b/tests/cpp_api/Android.bp
@@ -21,11 +21,5 @@ package {
 cc_defaults {
     name: "frameworks_rs_tests_cpp-api-defaults",
     shared_libs: ["liblog"],
-    cflags: [
-        "-Werror",
-        "-Wall",
-        "-Wextra",
-    ],
     header_libs: ["rs-headers"],
 }
-
diff --git a/toolkit/Android.bp b/toolkit/Android.bp
index 30bda04f..aa19676c 100644
--- a/toolkit/Android.bp
+++ b/toolkit/Android.bp
@@ -7,11 +7,11 @@ package {
 cc_binary {
     name: "renderscripttoolkittest",
     srcs: [
-        "TestTaskProcessor.cpp"
+        "TestTaskProcessor.cpp",
     ],
     shared_libs: [
-         "libbase",
-         "librenderscripttoolkit",
+        "libbase",
+        "librenderscripttoolkit",
     ],
 }
 
@@ -31,14 +31,14 @@ cc_library_shared {
         "Histogram.cpp",
         "Lut.cpp",
         "Lut3d.cpp",
-	"RenderScriptToolkit.cpp",
+        "RenderScriptToolkit.cpp",
         "Resize.cpp",
         "TaskProcessor.cpp",
         "Utils.cpp",
         "YuvToRgb.cpp",
     ],
 
-    static_libs: [ "cpufeatures" ],
+    static_libs: ["cpufeatures"],
 
     arch: {
         arm64: {
@@ -84,8 +84,12 @@ cc_library_shared {
         x86_64: {
             cflags: ["-DARCH_X86_HAVE_SSSE3"],
             srcs: ["x86.cpp"],
-        avx2: {
-                cflags: ["-DARCH_X86_HAVE_AVX2", "-mavx2", "-mfma"],
+            avx2: {
+                cflags: [
+                    "-DARCH_X86_HAVE_AVX2",
+                    "-mavx2",
+                    "-mfma",
+                ],
             },
         },
     },
@@ -93,8 +97,8 @@ cc_library_shared {
     shared_libs: [
         "libbase",
         "liblog",
-	"libnativehelper",
-	"libjnigraphics",
+        "libnativehelper",
+        "libjnigraphics",
     ],
     header_libs: [
         // TODO Once we compile in the .cpp files, check if any of these libraries are needed.
@@ -104,13 +108,8 @@ cc_library_shared {
 
     include_dirs: [
     ],
-
     cflags: [
         "-Wthread-safety",
-        "-Werror",
-        "-Wall",
-        "-Wextra",
         "-Wno-unused-parameter",
-        "-Wno-unused-variable",
     ],
 }
```

