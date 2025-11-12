```diff
diff --git a/Android.bp b/Android.bp
index 12cb910..041609f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -57,9 +57,29 @@ filegroup {
 cc_library_headers {
     name: "emboss_runtime_headers",
     cpp_std: "c++20",
-    vendor_available: true,
     export_include_dirs: [
         ".",
     ],
+    cmake_snapshot_supported: true,
     host_supported: true,
+    native_bridge_supported: true,
+    product_available: true,
+    recovery_available: true,
+    vendor_available: true,
+    vendor_ramdisk_available: true,
+
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+    min_sdk_version: "apex_inherit",
+
+    target: {
+        linux_bionic: {
+            enabled: true,
+        },
+        windows: {
+            enabled: true,
+        }
+    }
 }
```

