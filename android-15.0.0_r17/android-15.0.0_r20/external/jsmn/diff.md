```diff
diff --git a/Android.bp b/Android.bp
index c1ce2b3..7febed1 100644
--- a/Android.bp
+++ b/Android.bp
@@ -48,7 +48,10 @@ cc_library_static {
     name: "libjsmn",
     vendor_available: true,
     srcs: ["jsmn.c"],
-    cflags: ["-Wall", "-Werror"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
     export_include_dirs: ["."],
     min_sdk_version: "apex_inherit",
     apex_available: [
```

