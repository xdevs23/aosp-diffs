```diff
diff --git a/Android.bp b/Android.bp
index 7bb241b..3f5db13 100644
--- a/Android.bp
+++ b/Android.bp
@@ -50,3 +50,11 @@ prebuilt_font {
     name: "CutiveMono.ttf",
     src: "CutiveMono.ttf",
 }
+
+filegroup {
+    name: "CutiveMono",
+    srcs: ["font_config.json"],
+    required: [
+        "CutiveMono.ttf",
+    ],
+}
diff --git a/font_config.json b/font_config.json
new file mode 100644
index 0000000..eb50c9d
--- /dev/null
+++ b/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "name": "serif-monospace",
+        "fonts": [
+            {
+                "file": "CutiveMono.ttf",
+                "postScriptName": "CutiveMono-Regular",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
```

