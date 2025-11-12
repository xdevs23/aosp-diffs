```diff
diff --git a/Android.bp b/Android.bp
index 7522edb..a764387 100644
--- a/Android.bp
+++ b/Android.bp
@@ -79,6 +79,22 @@ cc_library_static {
         "com.android.bt",
     ],
     min_sdk_version: "30",
+    cmake_snapshot_supported: true,
+    host_supported: true,
+    native_bridge_supported: true,
+    product_available: true,
+    recovery_available: true,
+    vendor_available: true,
+    vendor_ramdisk_available: true,
+
+    target: {
+        linux_bionic: {
+            enabled: true,
+        },
+        windows: {
+            enabled: true,
+        },
+    },
 }
 
 cc_library_static {
```

