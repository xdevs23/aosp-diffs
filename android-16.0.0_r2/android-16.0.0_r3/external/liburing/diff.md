```diff
diff --git a/Android.bp b/Android.bp
index d032c66..d04849a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -31,7 +31,7 @@ cc_defaults {
         "-Werror",
         "-Wno-pointer-arith",
         "-Wno-unused-parameter",
-        "-D_GNU_SOURCE"
+        "-D_GNU_SOURCE",
     ],
     export_include_dirs: [
         "src/include",
@@ -53,6 +53,12 @@ cc_library_static {
     recovery_available: true,
     ramdisk_available: true,
     vendor_ramdisk_available: true,
+    vendor_available: true,
     host_supported: true,
     device_supported: true,
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.os.statsd",
+    ],
+    min_sdk_version: "apex_inherit",
 }
```

