```diff
diff --git a/Android.bp b/Android.bp
index ac3180e..332cf4f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -43,7 +43,10 @@ prebuilt_font {
     name: "Roboto-Regular.ttf",
     src: "Roboto-Regular.ttf",
     // These symlinks are for backward compatibility.
-    symlinks: ["DroidSans.ttf", "DroidSans-Bold.ttf"],
+    symlinks: [
+        "DroidSans.ttf",
+        "DroidSans-Bold.ttf",
+    ],
 }
 
 // This static version of fonts are for backward compatibility.
@@ -51,3 +54,11 @@ prebuilt_font {
     name: "RobotoStatic-Regular.ttf",
     src: "RobotoStatic-Regular.ttf",
 }
+
+filegroup {
+    name: "Roboto",
+    srcs: ["font_config.json"],
+    required: [
+        "Roboto-Regular.ttf",
+    ],
+}
diff --git a/font_config.json b/font_config.json
new file mode 100644
index 0000000..f080f8b
--- /dev/null
+++ b/font_config.json
@@ -0,0 +1,26 @@
+[
+    {
+        "name": "sans-serif",
+        "fonts": [
+            {
+                "file": "Roboto-Regular.ttf",
+                "supportedAxes": "wght,ital",
+                "axes": {
+                    "wdth": "100"
+                }
+            }
+        ]
+    },
+    {
+        "name": "sans-serif-condensed",
+        "fonts": [
+            {
+                "file": "Roboto-Regular.ttf",
+                "supportedAxes": "wght,ital",
+                "axes": {
+                    "wdth": "75"
+                }
+            }
+        ]
+    }
+]
\ No newline at end of file
```

