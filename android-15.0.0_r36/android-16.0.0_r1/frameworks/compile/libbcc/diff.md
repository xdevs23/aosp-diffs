```diff
diff --git a/lib/Android.bp b/lib/Android.bp
index 6ddc652..0df1c99 100644
--- a/lib/Android.bp
+++ b/lib/Android.bp
@@ -51,6 +51,9 @@ cc_library {
         "Source.cpp",
     ],
 
+    cflags: [
+        "-Wno-cast-function-type-mismatch",
+    ],
     shared_libs: ["libbcinfo"],
 
     header_libs: ["slang_headers"],
```

