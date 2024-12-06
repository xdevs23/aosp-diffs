```diff
diff --git a/Android.bp b/Android.bp
index 4a1e4e2..408f468 100644
--- a/Android.bp
+++ b/Android.bp
@@ -33,3 +33,11 @@ prebuilt_font {
     name: "ComingSoon.ttf",
     src: "ComingSoon.ttf",
 }
+
+filegroup {
+    name: "ComingSoon",
+    srcs: ["font_config.json"],
+    required: [
+        "ComingSoon.ttf",
+    ],
+}
diff --git a/font_config.json b/font_config.json
new file mode 100644
index 0000000..fd207bc
--- /dev/null
+++ b/font_config.json
@@ -0,0 +1,13 @@
+[
+    {
+        "name": "casual",
+        "fonts": [
+            {
+                "file": "ComingSoon.ttf",
+                "postScriptName": "ComingSoon-Regular",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
```

