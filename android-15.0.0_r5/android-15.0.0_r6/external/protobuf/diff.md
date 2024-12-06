```diff
diff --git a/Android.bp b/Android.bp
index 6200c48f2..269964747 100644
--- a/Android.bp
+++ b/Android.bp
@@ -108,6 +108,9 @@ cc_defaults {
         android: {
             shared_libs: ["liblog"],
         },
+        host: {
+            rtti: true,
+        },
 
         // This suffix for vendor and product must be updated
         // when a new version is imported.
@@ -389,8 +392,6 @@ cc_library {
             cflags: ["-UWIN32_LEAN_AND_MEAN"],
         },
     },
-
-    rtti: true,
 }
 
 // Android Protocol buffer compiler, aprotoc (host executable)
@@ -692,6 +693,7 @@ java_library {
     sdk_version: "core_current",
     installable: false,
     licenses: ["external_protobuf_libcore_private_stubs_license"],
+    is_stubs_module: true,
 }
 
 // Python library
@@ -753,6 +755,15 @@ filegroup {
     path: "src",
 }
 
+
+filegroup {
+    name: "libprotobuf-internal-any-proto",
+    srcs: [
+        "src/google/protobuf/any.proto",
+    ],
+    path: "src",
+}
+
 // Unit tests
 // =======================================================
 cc_defaults {
```

