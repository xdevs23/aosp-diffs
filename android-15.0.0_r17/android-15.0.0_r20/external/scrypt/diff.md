```diff
diff --git a/sources.bp b/sources.bp
index 7c2df96..8a41c0a 100644
--- a/sources.bp
+++ b/sources.bp
@@ -27,7 +27,6 @@ cc_defaults {
         "-DUSE_OPENSSL_PBKDF2",
         "-Wall",
         "-Werror",
-        "-Wno-implicit-function-declaration",
         "-Wno-unused-variable",
     ],
 
```

