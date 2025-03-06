```diff
diff --git a/squashfs-tools/Android.bp b/squashfs-tools/Android.bp
index 95985fa..b6d1a82 100644
--- a/squashfs-tools/Android.bp
+++ b/squashfs-tools/Android.bp
@@ -26,6 +26,8 @@ package {
 cc_defaults {
     name: "squashfs-tools_defaults",
 
+    // Our old version of upstream doesn't build as C23.
+    c_std: "gnu17",
     cflags: [
         "-D_FILE_OFFSET_BITS=64",
         "-D_LARGEFILE_SOURCE",
```

