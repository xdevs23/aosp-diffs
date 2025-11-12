```diff
diff --git a/Android.bp b/Android.bp
index 764a8c04..c86355c5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -53,7 +53,6 @@ rust_library {
     whole_static_libs: [
         "libcxxbridge05",
     ],
-    shared_libs: ["libc++"],
     host_supported: true,
     vendor_available: true,
     product_available: true,
@@ -62,6 +61,18 @@ rust_library {
         "//apex_available:platform",
     ],
     min_sdk_version: "29",
+    target: {
+        android: {
+            shared_libs: ["libc++"],
+        },
+        not_windows: {
+            shared_libs: ["libc++"],
+        },
+        windows: {
+            enabled: true,
+            static_libs: ["libc++_static"],
+        },
+    },
 }
 
 cc_library_static {
@@ -77,6 +88,11 @@ cc_library_static {
         "//apex_available:platform",
     ],
     min_sdk_version: "29",
+    target: {
+        windows: {
+            enabled: true,
+        },
+    },
 }
 
 cc_library_static {
```

