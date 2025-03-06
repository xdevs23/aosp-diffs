```diff
diff --git a/Android.bp b/Android.bp
index 9803e87..a62bcb7 100644
--- a/Android.bp
+++ b/Android.bp
@@ -83,8 +83,8 @@ cc_library_static {
         "src/util-list.c",
         "src/utils.c",
     ],
+    c_std: "c11",
     cflags: [
-        "-std=c11",
         "-fno-strict-aliasing",
         "-fsanitize-undefined-trap-on-error",
         "-Wall",
@@ -96,12 +96,12 @@ cc_library_static {
         "-D_GNU_SOURCE",
     ],
     static_libs: [
-        "libxml2"
+        "libxml2",
     ],
     local_include_dirs: [
         "src",
         "config",
-        "config/libxkbcommon.so.0.0.0.p"
+        "config/libxkbcommon.so.0.0.0.p",
     ],
     export_include_dirs: ["include"],
     vendor_available: true,
```

