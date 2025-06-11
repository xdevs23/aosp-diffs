```diff
diff --git a/Android.bp b/Android.bp
index ae89cfe..dc944f3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -48,6 +48,7 @@ license {
 cc_library {
     name: "libepoxy",
     host_supported: true,
+    vendor_available: true,
     cflags: ["-Wno-unused-parameter"],
     local_include_dirs: [
         "prebuilt-intermediates",
@@ -55,7 +56,7 @@ cc_library {
     ],
     export_include_dirs: [
         "include",
-        "prebuilt-intermediates/include"
+        "prebuilt-intermediates/include",
     ],
     srcs: [
         "prebuilt-intermediates/src/egl_generated_dispatch.c",
@@ -63,6 +64,13 @@ cc_library {
         "src/dispatch_common.c",
         "src/dispatch_egl.c",
     ],
+    target: {
+        vendor: {
+            shared_libs: [
+                "libEGL",
+            ],
+        },
+    },
     apex_available: [
         "//apex_available:platform",
         "com.android.virt",
diff --git a/OWNERS b/OWNERS
index 0e7c54b..42cfa7d 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,4 @@ jemoreira@google.com
 malchev@google.com
 rammuthiah@google.com
 schuffelen@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

