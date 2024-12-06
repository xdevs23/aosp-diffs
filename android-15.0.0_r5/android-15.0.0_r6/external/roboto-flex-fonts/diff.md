```diff
diff --git a/Android.bp b/Android.bp
index 30f0448..5e2c1bf 100644
--- a/Android.bp
+++ b/Android.bp
@@ -23,7 +23,7 @@ license {
     name: "external_roboto-flex-fonts_license",
     visibility: [":__subpackages__"],
     license_kinds: [
-        "SPDX-license-identifier-OFL",  // by exception only
+        "SPDX-license-identifier-OFL", // by exception only
     ],
     license_text: [
         "LICENSE",
@@ -34,3 +34,11 @@ prebuilt_font {
     name: "RobotoFlex-Regular.ttf",
     src: "RobotoFlex-Regular.ttf",
 }
+
+filegroup {
+    name: "RobotoFlex",
+    srcs: ["font_config.json"],
+    required: [
+        "RobotoFlex-Regular.ttf",
+    ],
+}
diff --git a/font_config.json b/font_config.json
new file mode 100644
index 0000000..7bec58c
--- /dev/null
+++ b/font_config.json
@@ -0,0 +1,14 @@
+[
+    {
+        "name": "roboto-flex",
+        "fonts": [
+            {
+                "file": "RobotoFlex-Regular.ttf",
+                "supportedAxes": "wght",
+                "axes": {
+                    "wdth": "100"
+                }
+            }
+        ]
+    }
+]
\ No newline at end of file
```

