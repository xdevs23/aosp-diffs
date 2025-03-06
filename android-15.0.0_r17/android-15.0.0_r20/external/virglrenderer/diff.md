```diff
diff --git a/Android.bp b/Android.bp
index ace67054..1dc3035b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -61,6 +61,10 @@ cc_library_headers {
 cc_library {
     name: "libvirglrenderer",
     host_supported: true,
+
+    // This project's unreachable() macro conflicts with the C23 one.
+    c_std: "gnu17",
+
     cflags: [
         "-DHAVE_CONFIG_H",
         "-include prebuilt-intermediates/config.h",
```

