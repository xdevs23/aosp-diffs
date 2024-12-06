```diff
diff --git a/Android.bp b/Android.bp
index 1218833..e7147ee 100644
--- a/Android.bp
+++ b/Android.bp
@@ -5,6 +5,18 @@
 
 package {
     default_team: "trendy_team_android_rust",
+    default_applicable_licenses: ["external_rust_crates_downcast_license"],
+}
+
+license {
+    name: "external_rust_crates_downcast_license",
+    visibility: [":__subpackages__"],
+    license_kinds: [
+        "SPDX-license-identifier-MIT",
+    ],
+    license_text: [
+        "LICENSE",
+    ],
 }
 
 rust_test {
```

