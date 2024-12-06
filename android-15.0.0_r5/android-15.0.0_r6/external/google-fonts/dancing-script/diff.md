```diff
diff --git a/Android.bp b/Android.bp
index a4847b2..6f17c47 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,5 +55,13 @@ prebuilt_font {
 
 filegroup {
     name: "GoogleFontDancingScript",
-    srcs: [ "*.ttf" ],
+    srcs: ["*.ttf"],
+}
+
+filegroup {
+    name: "DancingScript",
+    srcs: ["font_config.json"],
+    required: [
+        "DancingScript-Regular.ttf",
+    ],
 }
diff --git a/font_config.json b/font_config.json
new file mode 100644
index 0000000..f4be9c5
--- /dev/null
+++ b/font_config.json
@@ -0,0 +1,11 @@
+[
+    {
+        "name": "cursive",
+        "fonts": [
+            {
+                "file": "DancingScript-Regular.ttf",
+                "supportedAxes": "wght"
+            }
+        ]
+    }
+]
\ No newline at end of file
```

