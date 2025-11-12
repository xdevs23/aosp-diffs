```diff
diff --git a/Android.bp b/Android.bp
index 332cf4f..9aee343 100644
--- a/Android.bp
+++ b/Android.bp
@@ -24,6 +24,7 @@ license {
     visibility: [":__subpackages__"],
     license_kinds: [
         "SPDX-license-identifier-Apache-2.0",
+        "SPDX-license-identifier-OFL",
     ],
     license_text: [
         "NOTICE",
@@ -33,15 +34,14 @@ license {
 filegroup {
     name: "recovery_roboto-fonts_dep",
     export_to_make_var: "recovery_roboto-fonts_dep",
-    srcs: [
-        "*.otf",
-        "*.ttf",
-    ],
+    srcs: [ "font/3.005/Roboto-Regular.ttf", ],
 }
 
-prebuilt_font {
+prebuilt_versioned_font {
     name: "Roboto-Regular.ttf",
-    src: "Roboto-Regular.ttf",
+    versionFlag: "RELEASE_PACKAGE_ROBOTO_FONT_VERSION",
+    defaultVersion: "3.005",
+
     // These symlinks are for backward compatibility.
     symlinks: [
         "DroidSans.ttf",
diff --git a/MODULE_LICENSE_OFL b/MODULE_LICENSE_OFL
new file mode 100644
index 0000000..e69de29
diff --git a/Roboto-Regular.ttf b/font/3.005/Roboto-Regular.ttf
similarity index 100%
rename from Roboto-Regular.ttf
rename to font/3.005/Roboto-Regular.ttf
diff --git a/font/3.011/Roboto-Regular.ttf b/font/3.011/Roboto-Regular.ttf
new file mode 100644
index 0000000..bad9f84
Binary files /dev/null and b/font/3.011/Roboto-Regular.ttf differ
```

