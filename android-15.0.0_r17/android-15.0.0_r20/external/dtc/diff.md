```diff
diff --git a/Android.bp b/Android.bp
index f4b1d37..834851e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -100,6 +100,10 @@ cc_binary {
     name: "dtc_static",
     defaults: ["dtc_defaults"],
     static_executable: true,
+    // TODO(b/373646042): this is a workaround for failed link
+    sanitize: {
+        hwaddress: false,
+    },
     installable: false, // test only
 }
 
@@ -154,3 +158,9 @@ genrule {
         ")-Android-build;" +
         "sed s/@VCS_TAG@/$${version}/ $(in) > $(out)",
 }
+
+dirgroup {
+    name: "trusty_dirgroup_external_dtc",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/libfdt/Android.bp b/libfdt/Android.bp
index c30bfa5..32b3b39 100644
--- a/libfdt/Android.bp
+++ b/libfdt/Android.bp
@@ -4,9 +4,8 @@ package {
     default_applicable_licenses: ["external_dtc_libfdt_license"],
 }
 
-cc_library {
-    name: "libfdt",
-    host_supported: true,
+cc_defaults {
+    name: "libfdt_defaults",
     defaults: ["dtc_cflags_defaults"],
     srcs: [
         "fdt.c",
@@ -22,11 +21,24 @@ cc_library {
         "acpi.c",
     ],
     export_include_dirs: ["."],
+}
+
+cc_library {
+    name: "libfdt",
+    host_supported: true,
+    defaults: ["libfdt_defaults"],
     apex_available: [
         "//apex_available:platform",
         "com.android.virt",
     ],
+}
 
+cc_library {
+    name: "libfdt_baremetal",
+    defaults: [
+        "cc_baremetal_defaults",
+        "libfdt_defaults",
+    ],
     // b/336916369: This library gets linked into a rust rlib.  Disable LTO
     // until cross-language lto is supported.
     lto: {
```

