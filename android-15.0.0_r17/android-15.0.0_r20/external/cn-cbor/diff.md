```diff
diff --git a/Android.bp b/Android.bp
index 5b1b789..72b9269 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,4 +1,3 @@
-
 package {
     default_applicable_licenses: ["external_cn-cbor_license"],
 }
@@ -30,31 +29,33 @@ license {
 }
 
 cc_library {
-  name: "libcn-cbor",
-  vendor_available: true,
-  srcs: [
-    "src/cn-cbor.c",
-    "src/cn-create.c",
-    "src/cn-encoder.c",
-    "src/cn-error.c",
-    "src/cn-get.c",
-  ],
-  local_include_dirs: [
-    "include",
-  ],
-  export_include_dirs: [
-    "include",
-  ],
-  unique_host_soname: true,
-  host_supported: true,
+    name: "libcn-cbor",
+    vendor_available: true,
+    srcs: [
+        "src/cn-cbor.c",
+        "src/cn-create.c",
+        "src/cn-encoder.c",
+        "src/cn-error.c",
+        "src/cn-get.c",
+    ],
+    local_include_dirs: [
+        "include",
+    ],
+    export_include_dirs: [
+        "include",
+    ],
+    unique_host_soname: true,
+    host_supported: true,
+    c_std: "gnu99",
 }
 
 cc_test {
-  name: "cn-cbor_test",
-  host_supported: true,
-  srcs: [
-    "test/cbor_test.c",
-  ],
-  shared_libs: [ "libcn-cbor", ],
-  gtest: false,
+    name: "cn-cbor_test",
+    host_supported: true,
+    srcs: [
+        "test/cbor_test.c",
+    ],
+    shared_libs: ["libcn-cbor"],
+    gtest: false,
+    c_std: "gnu99",
 }
```

