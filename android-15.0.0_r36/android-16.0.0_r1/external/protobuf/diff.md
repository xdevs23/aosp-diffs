```diff
diff --git a/Android.bp b/Android.bp
index e194951b0..c7d29331c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -248,6 +248,7 @@ cc_library {
     name: "libprotobuf-cpp-full",
     defaults: ["libprotobuf-cpp-full-defaults"],
     host_supported: true,
+    recovery_available: true,
     vendor_available: true,
     product_available: true,
     // TODO(b/153609531): remove when no longer needed.
@@ -277,7 +278,6 @@ cc_test_library {
     apex_available: [
         "//apex_available:platform",
         "com.android.os.statsd",
-        "test_com.android.os.statsd",
     ],
     min_sdk_version: "29",
 }
@@ -496,7 +496,7 @@ java_library_static {
 
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
     ],
 }
 
```

