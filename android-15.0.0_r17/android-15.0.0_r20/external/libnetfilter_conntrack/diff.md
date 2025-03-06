```diff
diff --git a/Android.bp b/Android.bp
index 610796c..bb09f98 100644
--- a/Android.bp
+++ b/Android.bp
@@ -74,7 +74,7 @@ sub_srcs = [
 cc_library_shared {
     name: "libnetfilter_conntrack",
     export_include_dirs: ["include"],
-    vendor:true,
+    vendor: true,
     srcs: sub_srcs,
     cflags: [
         "-Wno-unused-parameter",
```

