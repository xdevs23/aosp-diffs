```diff
diff --git a/Android.bp b/Android.bp
index 1a50325..27dc3d6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -77,3 +77,16 @@ prebuilt_font {
     name: "SourceSansPro-BoldItalic.ttf",
     src: "SourceSansPro-BoldItalic.ttf",
 }
+
+filegroup {
+    name: "SourceSansPro",
+    srcs: ["font_config.json"],
+    required: [
+        "SourceSansPro-Bold.ttf",
+        "SourceSansPro-Regular.ttf",
+        "SourceSansPro-SemiBold.ttf",
+        "SourceSansPro-SemiBoldItalic.ttf",
+        "SourceSansPro-Italic.ttf",
+        "SourceSansPro-BoldItalic.ttf",
+    ],
+}
diff --git a/font_config.json b/font_config.json
new file mode 100644
index 0000000..a3f3aee
--- /dev/null
+++ b/font_config.json
@@ -0,0 +1,37 @@
+[
+    {
+        "name": "source-sans-pro",
+        "fonts": [
+            {
+                "file": "SourceSansPro-Regular.ttf",
+                "weight": "400",
+                "style": "normal"
+            },
+            {
+                "file": "SourceSansPro-Italic.ttf",
+                "weight": "400",
+                "style": "italic"
+            },
+            {
+                "file": "SourceSansPro-SemiBold.ttf",
+                "weight": "600",
+                "style": "normal"
+            },
+            {
+                "file": "SourceSansPro-SemiBoldItalic.ttf",
+                "weight": "600",
+                "style": "italic"
+            },
+            {
+                "file": "SourceSansPro-Bold.ttf",
+                "weight": "700",
+                "style": "normal"
+            },
+            {
+                "file": "SourceSansPro-BoldItalic.ttf",
+                "weight": "700",
+                "style": "italic"
+            }
+        ]
+    }
+]
\ No newline at end of file
```

