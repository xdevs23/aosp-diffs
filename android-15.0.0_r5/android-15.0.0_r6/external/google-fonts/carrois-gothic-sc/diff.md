```diff
diff --git a/Android.bp b/Android.bp
index 120b759..63894dd 100644
--- a/Android.bp
+++ b/Android.bp
@@ -52,3 +52,11 @@ prebuilt_font {
     name: "CarroisGothicSC-Regular.ttf",
     src: "CarroisGothicSC-Regular.ttf",
 }
+
+filegroup {
+    name: "CarroisGothicSC",
+    srcs: ["font_config.json"],
+    required: [
+        "CarroisGothicSC-Regular.ttf",
+    ],
+}
diff --git a/font_config.json b/font_config.json
new file mode 100644
index 0000000..2b2776f
--- /dev/null
+++ b/font_config.json
@@ -0,0 +1,12 @@
+[
+    {
+        "name": "sans-serif-smallcaps",
+        "fonts": [
+            {
+                "file": "CarroisGothicSC-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            }
+        ]
+    }
+]
\ No newline at end of file
```

