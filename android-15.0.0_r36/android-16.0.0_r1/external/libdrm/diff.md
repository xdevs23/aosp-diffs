```diff
diff --git a/Android.bp b/Android.bp
index c38c56f8..149aed68 100644
--- a/Android.bp
+++ b/Android.bp
@@ -93,6 +93,7 @@ cc_library {
     host_supported: true,
     vendor_available: true,
     product_available: true,
+    min_sdk_version: "34",
     apex_available: [
         "//apex_available:platform",
         "//apex_available:anyapex",
@@ -106,7 +107,10 @@ cc_library {
         "generated_static_table_fourcc_h",
     ],
 
-    export_include_dirs: ["include/drm", "android"],
+    export_include_dirs: [
+        "include/drm",
+        "android",
+    ],
 
     cflags: [
         "-Wno-enum-conversion",
diff --git a/OWNERS b/OWNERS
index 7b4c82dc..3dd52ab3 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,4 @@
 adelva@google.com
 john.stultz@linaro.org
 seanpaul@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

