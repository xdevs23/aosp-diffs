```diff
diff --git a/Android.bp b/Android.bp
index 0f8e4048..b6566cb6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -41,8 +41,22 @@ license {
     ],
 }
 
+cc_defaults {
+    name: "zstd_defaults",
+    arch: {
+        x86_64: {
+            cflags: ["-DZSTD_DISABLE_ASM"],
+        },
+    },
+    cflags: [
+        "-DZSTD_HAVE_WEAK_SYMBOLS=0",
+        "-DZSTD_TRACE=0",
+    ],
+}
+
 cc_library {
     name: "libzstd",
+    defaults: ["zstd_defaults"],
     min_sdk_version: "apex_inherit",
     apex_available: [
         "//apex_available:platform",
@@ -89,21 +103,24 @@ cc_library {
         },
     },
     srcs: ["lib/*/*.c"],
-    arch: {
-        x86_64: {
-            cflags: ["-DZSTD_DISABLE_ASM"],
-        },
-    },
-    cflags: [
-        "-DZSTD_HAVE_WEAK_SYMBOLS=0",
-        "-DZSTD_TRACE=0",
-    ],
     local_include_dirs: ["lib/common"],
     export_include_dirs: ["lib"],
 }
 
+cc_binary_host {
+    name: "zstd",
+    defaults: ["zstd_defaults"],
+    srcs: [
+        "programs/*.c",
+        // Rebuild the whole library as part of the binary to enable multithreading.
+        "lib/*/*.c",
+    ],
+    cflags: ["-DZSTD_MULTITHREAD=1"],
+}
+
 cc_defaults {
     name: "zstd_fuzz_defaults",
+    defaults: ["zstd_defaults"],
     static_libs: [
         "libzstd",
     ],
```

