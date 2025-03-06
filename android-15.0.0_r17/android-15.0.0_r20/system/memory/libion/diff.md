```diff
diff --git a/Android.bp b/Android.bp
index e490e72..95b44ac 100644
--- a/Android.bp
+++ b/Android.bp
@@ -2,23 +2,11 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-cc_library {
-    name: "libion",
+cc_defaults {
+    name: "libion_defaults",
     vendor_available: true,
     product_available: true,
     recovery_available: true,
-    double_loadable: true,
-    srcs: ["ion.c"],
-    shared_libs: ["liblog"],
-    local_include_dirs: [
-        "include",
-        "kernel-headers",
-    ],
-    export_include_dirs: [
-        "include",
-        "kernel-headers",
-    ],
-    cflags: ["-Werror"],
     min_sdk_version: "29",
     apex_available: [
         "//apex_available:platform",
@@ -27,6 +15,27 @@ cc_library {
     ],
 }
 
+cc_library_headers {
+    name: "libion_headers",
+    defaults: ["libion_defaults"],
+    host_supported: true,
+    export_include_dirs: [
+        "include",
+        "kernel-headers",
+    ],
+}
+
+cc_library {
+    name: "libion",
+    defaults: ["libion_defaults"],
+    double_loadable: true,
+    srcs: ["ion.c"],
+    header_libs: ["libion_headers"],
+    export_header_lib_headers: ["libion_headers"],
+    shared_libs: ["liblog"],
+    cflags: ["-Werror"],
+}
+
 cc_binary {
     name: "iontest",
     srcs: ["ion_test.c"],
```

