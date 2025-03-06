```diff
diff --git a/Android.bp b/Android.bp
index 0793e83..de3963b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -44,7 +44,10 @@ cc_library_static {
         "src/framing.c",
     ],
 
-    cflags: ["-Wall", "-Werror"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
 
     export_include_dirs: ["include"],
 
```

