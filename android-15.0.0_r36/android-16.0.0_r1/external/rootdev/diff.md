```diff
diff --git a/Android.bp b/Android.bp
index d072361..3b6e4a3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -16,8 +16,6 @@ package {
     default_applicable_licenses: ["external_rootdev_license"],
 }
 
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
 license {
     name: "external_rootdev_license",
     visibility: [":__subpackages__"],
@@ -29,29 +27,20 @@ license {
     ],
 }
 
-rootdev_CFLAGS = [
-    "-D_BSD_SOURCE",
-    "-D_FILE_OFFSET_BITS=64",
-    "-D_LARGEFILE_SOURCE",
-    "-include sys/sysmacros.h",
-    "-Wall",
-    "-Werror",
-    "-Wno-deprecated-declarations",
-    "-Wno-sign-compare",
-]
-
-// Build the shared library.
-cc_library_shared {
-    name: "librootdev",
-    cflags: rootdev_CFLAGS,
-    srcs: ["rootdev.c"],
-    export_include_dirs: ["."],
-}
-
 // Build the command line tool.
 cc_binary {
     name: "rootdev",
-    cflags: rootdev_CFLAGS,
-    shared_libs: ["librootdev"],
-    srcs: ["main.c"],
+    cflags: [
+        "-D_BSD_SOURCE",
+        "-D_FILE_OFFSET_BITS=64",
+        "-include sys/sysmacros.h",
+        "-Wall",
+        "-Werror",
+        "-Wno-deprecated-declarations",
+        "-Wno-sign-compare",
+    ],
+    srcs: [
+        "main.c",
+        "rootdev.c",
+    ],
 }
diff --git a/OWNERS b/OWNERS
index 244c628..d9d2e31 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 # Default code reviewers picked from top 3 or more developers.
 # Please update this list if you find better candidates.
 enh@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

