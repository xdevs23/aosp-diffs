```diff
diff --git a/Android.bp b/Android.bp
index 345d748..29867a9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,21 +1,16 @@
 // This file is generated by cargo_embargo.
-// Do not modify this file after the first "rust_*" or "genrule" module
-// because the changes will be overridden on upgrade.
-// Content before the first "rust_*" or "genrule" module is preserved.
+// Do not modify this file because the changes will be overridden on upgrade.
 
 package {
     default_applicable_licenses: ["external_rust_crates_bytemuck_license"],
+    default_team: "trendy_team_android_rust",
 }
 
 license {
     name: "external_rust_crates_bytemuck_license",
     visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-Apache-2.0",
-    ],
-    license_text: [
-        "LICENSE",
-    ],
+    license_kinds: ["SPDX-license-identifier-Apache-2.0"],
+    license_text: ["LICENSE"],
 }
 
 rust_test {
```

