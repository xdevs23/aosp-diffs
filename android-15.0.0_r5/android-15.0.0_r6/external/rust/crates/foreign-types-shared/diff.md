```diff
diff --git a/Android.bp b/Android.bp
index 4b7333f..4a31531 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,44 +1,15 @@
 // This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
+// Do not modify this file because the changes will be overridden on upgrade.
 
 package {
-    default_applicable_licenses: [
-        "external_rust_crates_foreign-types-shared_license",
-    ],
+    default_applicable_licenses: ["external_rust_crates_foreign-types-shared_license"],
 }
 
-// Added automatically by a large-scale-change that took the approach of
-// 'apply every license found to every target'. While this makes sure we respect
-// every license restriction, it may not be entirely correct.
-//
-// e.g. GPL in an MIT project might only apply to the contrib/ directory.
-//
-// Please consider splitting the single license below into multiple licenses,
-// taking care not to lose any license_kind information, and overriding the
-// default license using the 'licenses: [...]' property on targets as needed.
-//
-// For unused files, consider creating a 'fileGroup' with "//visibility:private"
-// to attach the license to, and including a comment whether the files may be
-// used in the current project.
-//
-// large-scale-change included anything that looked like it might be a license
-// text as a license_text. e.g. LICENSE, NOTICE, COPYING etc.
-//
-// Please consider removing redundant or irrelevant files from 'license_text:'.
-// See: http://go/android-license-faq
 license {
     name: "external_rust_crates_foreign-types-shared_license",
     visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-Apache-2.0",
-        "SPDX-license-identifier-MIT",
-    ],
-    license_text: [
-        "LICENSE-APACHE",
-        "LICENSE-MIT",
-    ],
+    license_kinds: ["SPDX-license-identifier-Apache-2.0"],
+    license_text: ["LICENSE"],
 }
 
 rust_library_rlib {
@@ -51,8 +22,7 @@ rust_library_rlib {
     edition: "2015",
     apex_available: [
         "//apex_available:platform",
-        "com.android.compos",
-        "com.android.virt",
+        "//apex_available:anyapex",
     ],
     product_available: true,
     vendor_available: true,
diff --git a/cargo_embargo.json b/cargo_embargo.json
index 4747e56..c51e6b2 100644
--- a/cargo_embargo.json
+++ b/cargo_embargo.json
@@ -1,9 +1,4 @@
 {
-  "apex_available": [
-    "//apex_available:platform",
-    "com.android.compos",
-    "com.android.virt"
-  ],
   "package": {
     "foreign-types-shared": {
       "force_rlib": true
```

