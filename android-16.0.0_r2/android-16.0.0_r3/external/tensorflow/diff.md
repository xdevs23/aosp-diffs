```diff
diff --git a/Android.bp b/Android.bp
index 414d7a84139..494af69bbc7 100644
--- a/Android.bp
+++ b/Android.bp
@@ -70,6 +70,19 @@ cc_library_headers {
     ],
 }
 
+TF_ABSL_LIBS = [
+    "absl_cleanup",
+    "absl_container_btree",
+    "absl_container_flat_hash_map",
+    "absl_container_flat_hash_set",
+    "absl_container_node_hash_map",
+    "absl_status",
+    "absl_status_statusor",
+    "absl_strings",
+    "absl_strings_cord",
+    "absl_time",
+]
+
 genrule {
     name: "libtflite_mutable_schema",
     tools: ["flatc"],
@@ -118,11 +131,10 @@ cc_library_static {
         "libneuralnetworks",
     ],
     static_libs: [
-        "libabsl",
         "libgtest_ndk_c++",
         "libgmock_ndk",
         "libtflite_static",
-    ],
+    ] + TF_ABSL_LIBS,
     header_libs: [
         "libeigen",
         "gemmlowp_headers",
@@ -171,13 +183,12 @@ cc_library_static {
     ],
     export_include_dirs: ["."],
     whole_static_libs: [
-        "libabsl",
         "libdoubleconversion",
         "libfft2d",
         "libruy_static",
         "libtextclassifier_hash_static",
         "tensorflow_core_proto_cpp_lite",
-    ],
+    ] + TF_ABSL_LIBS,
     header_libs: [
         "fp16_headers",
         "jni_headers",
```

