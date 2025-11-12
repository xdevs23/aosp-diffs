```diff
diff --git a/Android.bp b/Android.bp
index 55f44f03..999e004f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -32,9 +32,9 @@ cc_defaults {
     cflags: [
         "-DPACKAGE_VERSION=\"" + v4l_utils_version + "\"",
         "-DNO_LIBV4L2",
-    ],
 
-    static_executable: true,
+        "-Wno-shift-overflow",
+    ],
 
     visibility: [
         // Only add dependencies that run in test images
@@ -45,9 +45,10 @@ cc_defaults {
 }
 
 cc_binary {
-    name: "v4l2-compliance",
+    name: "v4l2-compliance_static",
     defaults: ["v4l-utils.cc_defaults"],
     srcs: ["utils/v4l2-compliance/*.cpp"],
+    static_executable: true,
 }
 
 genrule {
@@ -66,6 +67,18 @@ cc_binary {
         "utils/v4l2-ctl/*.cpp",
         "utils/v4l2-ctl/*.c",
     ],
+    vendor: true,
+}
+
+cc_binary {
+    name: "v4l2-ctl_static",
+    defaults: ["v4l-utils.cc_defaults"],
+    generated_headers: ["media_bus_format_names_header"],
+    srcs: [
+        "utils/v4l2-ctl/*.cpp",
+        "utils/v4l2-ctl/*.c",
+    ],
+    static_executable: true,
 }
 
 genrule {
@@ -77,13 +90,14 @@ genrule {
 }
 
 cc_binary {
-    name: "media-ctl",
+    name: "media-ctl_static",
     defaults: ["v4l-utils.cc_defaults"],
     generated_headers: [
         "media_bus_format_codes_header",
         "media_bus_format_names_header",
     ],
     srcs: ["utils/media-ctl/*.c"],
+    static_executable: true,
 }
 
 // Following defines unused files that is under licenses that are different
```

