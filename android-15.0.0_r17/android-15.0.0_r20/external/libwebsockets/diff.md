```diff
diff --git a/Android.bp b/Android.bp
index dd36bfb9..2f5ea2ba 100644
--- a/Android.bp
+++ b/Android.bp
@@ -217,7 +217,6 @@ cc_library_static {
                 "-pthread",
                 "-Wno-unused-command-line-argument",
                 "-Wno-unused-parameter",
-                "-Wno-implicit-function-declaration",
             ],
         },
     },
```

