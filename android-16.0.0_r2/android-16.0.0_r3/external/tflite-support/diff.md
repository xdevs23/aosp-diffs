```diff
diff --git a/Android.bp b/Android.bp
index e5add5e..f6cb2fe 100644
--- a/Android.bp
+++ b/Android.bp
@@ -42,6 +42,15 @@ cc_defaults {
     ],
 }
 
+TFLITE_ABSL_LIBS = [
+    "absl_memory",
+    "absl_status",
+    "absl_strings",
+    "absl_flags_flag",
+    "absl_flags_parse",
+    "absl_container_node_hash_map",
+]
+
 cc_library_static {
     name: "tflite_support",
     sdk_version: "current",
@@ -72,9 +81,8 @@ cc_library_static {
         "flatbuffer_headers",
     ],
     static_libs: [
-        "libabsl",
         "libtflite_static",
-    ],
+    ] + TFLITE_ABSL_LIBS,
     apex_available: [
         "//apex_available:platform",
         "com.android.adservices",
@@ -125,10 +133,9 @@ cc_library_static {
     ],
     generated_headers: ["tflite_support_metadata_schema"],
     static_libs: [
-        "libabsl",
         "libtextclassifier_bert_tokenizer",
         "libtflite_static",
-    ],
+    ] + TFLITE_ABSL_LIBS,
     apex_available: [
         "//apex_available:platform",
         "com.android.adservices",
@@ -147,11 +154,10 @@ cc_test {
     sdk_version: "current",
     min_sdk_version: "30",
     static_libs: [
-        "libabsl",
         "libbase_ndk",
         "libgmock_ndk",
         "tflite_support_tokenizers",
-    ],
+    ] + TFLITE_ABSL_LIBS,
     header_libs: [
         // TODO (ag/17748161): Create target for just TFLite headers and use here.
         "tensorflow_headers",
@@ -180,13 +186,12 @@ cc_library_static {
     ],
     generated_headers: ["tflite_support_metadata_schema"],
     static_libs: [
-        "libabsl",
         "libtflite_static",
         "tflite_configuration_proto",
         "tflite_support_task_core_proto",
         "tflite_support_tokenizers",
         "tflite_support_metadata_extractor",
-    ],
+    ] + TFLITE_ABSL_LIBS,
     apex_available: [
         "//apex_available:platform",
         "com.android.adservices",
@@ -232,7 +237,6 @@ cc_library_shared {
         "libz",
     ],
     static_libs: [
-        "libabsl",
         "libprotobuf-cpp-lite-ndk",
         "libtextclassifier_bert_tokenizer",
         "libtflite_static",
@@ -243,7 +247,7 @@ cc_library_shared {
         "tflite_support_task_core",
         "tflite_support_task_core_proto",
         "tflite_support_tokenizers",
-    ],
+    ] + TFLITE_ABSL_LIBS,
     header_libs: [
         // TODO (ag/17748161): Create target for just TFLite headers and use here.
         "tensorflow_headers",
@@ -303,9 +307,8 @@ cc_library_static {
         "tflite_support_metadata_schema",
     ],
     static_libs: [
-        "libabsl",
         "tflite_support_libz",
-    ],
+    ] + TFLITE_ABSL_LIBS,
     apex_available: [
         "//apex_available:platform",
         "com.android.adservices",
@@ -331,10 +334,9 @@ cc_library_static {
         "tflite_support_metadata_schema",
     ],
     static_libs: [
-        "libabsl",
         "tflite_configuration_proto",
         "tflite_support_task_core_proto",
-    ],
+    ] + TFLITE_ABSL_LIBS,
     apex_available: [
         "//apex_available:platform",
         "com.android.adservices",
@@ -359,7 +361,6 @@ cc_test {
         "libz",
     ],
     static_libs: [
-        "libabsl",
         "libbase_ndk",
         "libgmock_ndk",
         "libprotobuf-cpp-lite-ndk",
@@ -372,7 +373,7 @@ cc_test {
         "tflite_support_task_core_proto",
         "tflite_support_task_core",
         "tflite_support_tokenizers",
-    ],
+    ] + TFLITE_ABSL_LIBS,
     header_libs: [
         // TODO (ag/17748161): Create target for just TFLite headers and use here.
         "tensorflow_headers",
diff --git a/OWNERS b/OWNERS
index 7a7c056..c161237 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
-fban@google.com
-luwa@google.com
\ No newline at end of file
+qiaoli@google.com
+mijiang@google.com
+xufan@google.com
\ No newline at end of file
```

