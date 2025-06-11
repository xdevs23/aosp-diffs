```diff
diff --git a/Android.bp b/Android.bp
index 1a45065..bc74482 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,4 +1,4 @@
-cc_library_shared {
+cc_library_static {
     name: "libfbjni",
     export_include_dirs: ["cxx"],
     srcs: [
@@ -7,7 +7,7 @@ cc_library_shared {
         "cxx/lyra/*.cpp",
     ],
     sdk_version: "current",
-    min_sdk_version: "33",
+    min_sdk_version: "apex_inherit",
     stl: "libc++_static",
     cflags: [
         "-fexceptions",
diff --git a/OWNERS b/OWNERS
index c956c29..a2a4268 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
-include platform/system/core:main:/janitors/OWNERS
\ No newline at end of file
+include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

