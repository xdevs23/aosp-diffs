```diff
diff --git a/Android.bp b/Android.bp
index 14e9e8f..fdf384c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -612,6 +612,12 @@ cc_library_static {
     vendor_available: true,
     product_available: true,
     min_sdk_version: "29",
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 cc_library_static {
@@ -628,4 +634,10 @@ cc_library_static {
     vendor_available: true,
     product_available: true,
     min_sdk_version: "29",
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
```

