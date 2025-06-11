```diff
diff --git a/Android.bp b/Android.bp
index ff2b82d..0ade0de 100644
--- a/Android.bp
+++ b/Android.bp
@@ -41,8 +41,8 @@ cc_defaults {
         "-DHAVE_PTHREAD",
         "-Wall",
         "-Werror",
-        "-Wno-implicit-fallthrough",
-        // gflags_completions.cc:326,327 have unannotated fall-through
+        "-Wno-cast-function-type-mismatch",
+        "-Wno-implicit-fallthrough", // gflags_completions.cc:326,327 have unannotated fall-through
     ],
     export_include_dirs: [
         "android",
```

