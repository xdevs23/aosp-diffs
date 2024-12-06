```diff
diff --git a/3.2.23/Android.bp b/3.2.23/Android.bp
index 91af052..6ab69d2 100644
--- a/3.2.23/Android.bp
+++ b/3.2.23/Android.bp
@@ -7,35 +7,14 @@ package {
     default_applicable_licenses: ["external_rust_crates_clap_3.2.23_license"],
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
     name: "external_rust_crates_clap_3.2.23_license",
     visibility: [":__subpackages__"],
     license_kinds: [
         "SPDX-license-identifier-Apache-2.0",
-        "SPDX-license-identifier-MIT",
     ],
     license_text: [
-        "LICENSE-APACHE",
-        "LICENSE-MIT",
+        "LICENSE",
     ],
 }
 
diff --git a/Android.bp b/Android.bp
index d54646a..8d565b5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -7,35 +7,14 @@ package {
     default_applicable_licenses: ["external_rust_crates_clap_license"],
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
     name: "external_rust_crates_clap_license",
     visibility: [":__subpackages__"],
     license_kinds: [
         "SPDX-license-identifier-Apache-2.0",
-        "SPDX-license-identifier-MIT",
     ],
     license_text: [
-        "LICENSE-APACHE",
-        "LICENSE-MIT",
+        "LICENSE",
     ],
 }
 
```

