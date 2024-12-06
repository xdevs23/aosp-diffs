```diff
diff --git a/Android.bp b/Android.bp
index 4170b93..d7b2204 100644
--- a/Android.bp
+++ b/Android.bp
@@ -56,9 +56,7 @@ cc_defaults {
     ],
 
     cflags: [
-        "-Wall",
         "-Wno-unused-parameter",
-        "-Werror",
         "-D__DISABLE_ASSERTS",
     ],
 
diff --git a/bcinfo/Android.bp b/bcinfo/Android.bp
index 936d6ae..8cfa8cb 100644
--- a/bcinfo/Android.bp
+++ b/bcinfo/Android.bp
@@ -41,10 +41,7 @@ cc_library_shared {
     ],
 
     cflags: [
-        "-Wall",
         "-Wno-unused-parameter",
-        "-Werror",
-
         "-D__DISABLE_ASSERTS",
     ],
 
@@ -68,7 +65,7 @@ cc_library_shared {
         "libLLVMBitReader_2_7",
         "libLLVMBitReader_3_0",
         "libLLVMBitWriter_3_2",
-	"libStripUnkAttr",
+        "libStripUnkAttr",
     ],
 
     target: {
diff --git a/bcinfo/Wrap/Android.bp b/bcinfo/Wrap/Android.bp
index f86684a..9b367b6 100644
--- a/bcinfo/Wrap/Android.bp
+++ b/bcinfo/Wrap/Android.bp
@@ -39,8 +39,6 @@ cc_library_static {
         "wrapper_output.cpp",
     ],
 
-    cflags: ["-Wall", "-Werror"],
-
     target: {
         host: {
             cflags: ["-D__HOST__"],
@@ -50,5 +48,8 @@ cc_library_static {
         },
     },
 
-    header_libs: ["libbcinfo-headers", "liblog_headers"],
+    header_libs: [
+        "libbcinfo-headers",
+        "liblog_headers",
+    ],
 }
```

