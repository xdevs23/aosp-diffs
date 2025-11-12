```diff
diff --git a/Android.bp b/Android.bp
index 5dddd3b..c1dce7b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,6 +55,12 @@ cc_library {
     double_loadable: true,
     min_sdk_version: "29",
     host_supported: true,
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 // Header only lib to share type between HIDL and AIDL MQDescriptor
@@ -93,6 +99,12 @@ cc_library {
     product_available: true,
     min_sdk_version: "29",
     host_supported: true,
+
+    // b/336916369: This library gets linked into a rust rlib.  Disable LTO
+    // until cross-language lto is supported.
+    lto: {
+        never: true,
+    },
 }
 
 rust_bindgen {
```

