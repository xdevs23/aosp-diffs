```diff
diff --git a/Android.bp b/Android.bp
index c146039..6755295 100644
--- a/Android.bp
+++ b/Android.bp
@@ -3,6 +3,21 @@
 // because the changes will be overridden on upgrade.
 // Content before the first "rust_*" or "genrule" module is preserved.
 
+package {
+    default_applicable_licenses: ["external_rust_crates_configparser_license"],
+}
+
+license {
+    name: "external_rust_crates_configparser_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-MIT",
+    ],
+    license_text: [
+        "LICENSE",
+    ],
+}
+
 rust_library_host {
     name: "libconfigparser",
     crate_name: "configparser",
```

