```diff
diff --git a/Android.bp b/Android.bp
index 3ce7a9d..8a73b70 100644
--- a/Android.bp
+++ b/Android.bp
@@ -38,11 +38,16 @@ cc_library {
     ],
     // -D_32BIT_FIXED_POINT should be added to cflags for devices without a FPU
     // unit such as ARM Cortex-R series or external 32-bit DSPs.
-    cflags: ["-O2", "-Werror", "-Wall", "-Wextra"],
+    cflags: [
+        "-O2",
+        "-Werror",
+        "-Wall",
+        "-Wextra",
+    ],
     min_sdk_version: "Tiramisu",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
     visibility: [
         "//external/libldac/fuzzer",
@@ -65,11 +70,16 @@ cc_library {
     export_include_dirs: ["abr/inc"],
     srcs: ["abr/src/ldacBT_abr.c"],
     static_libs: ["libldacBT_enc"],
-    cflags: ["-O2", "-Werror", "-Wall", "-Wextra"],
+    cflags: [
+        "-O2",
+        "-Werror",
+        "-Wall",
+        "-Wextra",
+    ],
     min_sdk_version: "Tiramisu",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
     visibility: [
         "//packages/modules/Bluetooth:__subpackages__",
diff --git a/OWNERS b/OWNERS
index b77a7e3..38fff0d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 # This project does not need newer update?
 # Please update this list if you find better candidates.
 rtenneti@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

