```diff
diff --git a/Android.bp b/Android.bp
index 5c6cae0..ea3b60a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -39,15 +39,15 @@ genrule {
     name: "libva_gen_headers",
     srcs: [
         "configure.ac",
-        "va/va_version.h.in",
         "va/drm/va_drm.h",
+        "va/va_version.h.in",
     ],
     tools: [
         "libva_gen_version_script",
     ],
     out: [
-        "va/va_version.h",
         "va/va_drm.h",
+        "va/va_version.h",
     ],
     cmd: "$(location libva_gen_version_script) " +
         "$$(dirname $(location configure.ac)) " +
@@ -84,9 +84,9 @@ cc_library_shared {
     name: "libva",
 
     shared_libs: [
+        "libcutils",
         "libdl",
         "libdrm",
-        "libcutils",
         "liblog",
     ],
 
@@ -109,19 +109,19 @@ cc_library_shared {
     ],
 
     srcs: [
-        "va/va.c",
-        "va/va_trace.c",
-        "va/va_str.c",
         "va/drm/va_drm.c",
         "va/drm/va_drm_auth.c",
         "va/drm/va_drm_utils.c",
+        "va/va.c",
+        "va/va_str.c",
+        "va/va_trace.c",
     ],
 
     cflags: [
+        "-DLOG_TAG=\"libva\"",
+        "-DSYSCONFDIR=\"/vendor/etc\"",
         "-Werror",
         "-Winvalid-pch",
-        "-DSYSCONFDIR=\"/vendor/etc\"",
-        "-DLOG_TAG=\"libva\"",
     ],
 
     arch: {
@@ -139,9 +139,9 @@ cc_library_shared {
     name: "libva-android",
 
     shared_libs: [
-        "libva",
         "libdrm",
         "liblog",
+        "libva",
     ],
 
     local_include_dirs: [
@@ -164,9 +164,9 @@ cc_library_shared {
     ],
 
     cflags: [
+        "-DLOG_TAG=\"libva-android\"",
         "-Werror",
         "-Winvalid-pch",
-        "-DLOG_TAG=\"libva-android\"",
     ],
 
     vendor: true,
diff --git a/METADATA b/METADATA
index 3885cec..3275940 100644
--- a/METADATA
+++ b/METADATA
@@ -7,9 +7,9 @@ description: "Libva is an implementation for VA-API (Video Acceleration API)  VA
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 10
-    day: 14
+    year: 2025
+    month: 3
+    day: 10
   }
   identifier {
     type: "Git"
```

