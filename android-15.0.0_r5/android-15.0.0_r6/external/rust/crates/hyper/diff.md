```diff
diff --git a/Android.bp b/Android.bp
index 45e7681..dd5a133 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,14 +1,12 @@
 // This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
+// Do not modify this file because the changes will be overridden on upgrade.
 
 package {
-    default_applicable_licenses: ["external_rust_crates_libhyper_license"],
+    default_applicable_licenses: ["external_rust_crates_hyper_license"],
 }
 
 license {
-    name: "external_rust_crates_libhyper_license",
+    name: "external_rust_crates_hyper_license",
     visibility: [":__subpackages__"],
     license_kinds: ["SPDX-license-identifier-MIT"],
     license_text: ["LICENSE"],
```
