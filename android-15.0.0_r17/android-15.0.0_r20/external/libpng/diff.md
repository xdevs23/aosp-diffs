```diff
diff --git a/Android.bp b/Android.bp
index da4b6c966..d565f7d6d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -61,10 +61,10 @@ cc_defaults {
             cflags: ["-O3"],
         },
         arm64: {
-            srcs: ["arm/*",],
+            srcs: ["arm/*"],
             cflags: ["-O3"],
             exclude_srcs: [
-                "arm/filter_neon.S"
+                "arm/filter_neon.S",
             ],
         },
         x86: {
@@ -113,7 +113,7 @@ cc_library {
     min_sdk_version: "apex_inherit",
     apex_available: [
         "com.android.mediaprovider",
-        "//apex_available:platform"
+        "//apex_available:platform",
     ],
 }
 
@@ -137,7 +137,10 @@ cc_test {
     gtest: false,
     srcs: ["pngtest.c"],
     name: "pngtest",
-    cflags: ["-Wall", "-Werror"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
     shared_libs: [
         "libpng",
         "libz",
@@ -146,7 +149,7 @@ cc_test {
 
 cc_fuzz {
     name: "libpng_read_fuzzer",
-    host_supported:true,
+    host_supported: true,
 
     static_libs: [
         "libpng",
diff --git a/OWNERS b/OWNERS
index 5366a9a7e..7529cb920 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1 @@
-# Default code reviewers picked from top 3 or more developers.
-# Please update this list if you find better candidates.
-scroggo@google.com
 include platform/system/core:/janitors/OWNERS
```

