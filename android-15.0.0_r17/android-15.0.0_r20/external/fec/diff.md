```diff
diff --git a/Android.bp b/Android.bp
index 3bbcc45..c6b34d5 100644
--- a/Android.bp
+++ b/Android.bp
@@ -48,7 +48,7 @@ cc_library {
     cflags: [
         "-Wall",
         "-Werror",
-        "-O3"
+        "-O3",
     ],
     export_include_dirs: ["."],
 
```

