```diff
diff --git a/Android.bp b/Android.bp
index 6cb54a8..630bd26 100644
--- a/Android.bp
+++ b/Android.bp
@@ -72,7 +72,7 @@ cc_library_static {
         "flatbuffer_headers",
     ],
     static_libs: [
-        "libtextclassifier_abseil",
+        "libabsl",
         "libtflite_static",
     ],
     apex_available: [
@@ -125,8 +125,8 @@ cc_library_static {
     ],
     generated_headers: ["tflite_support_metadata_schema"],
     static_libs: [
+        "libabsl",
         "libtextclassifier_bert_tokenizer",
-        "libtextclassifier_abseil",
         "libtflite_static",
     ],
     apex_available: [
@@ -147,10 +147,10 @@ cc_test {
     sdk_version: "current",
     min_sdk_version: "30",
     static_libs: [
-        "tflite_support_tokenizers",
-        "libtextclassifier_abseil",
-        "libgmock_ndk",
+        "libabsl",
         "libbase_ndk",
+        "libgmock_ndk",
+        "tflite_support_tokenizers",
     ],
     header_libs: [
         // TODO (ag/17748161): Create target for just TFLite headers and use here.
@@ -180,7 +180,7 @@ cc_library_static {
     ],
     generated_headers: ["tflite_support_metadata_schema"],
     static_libs: [
-        "libtextclassifier_abseil",
+        "libabsl",
         "libtflite_static",
         "tflite_configuration_proto",
         "tflite_support_task_core_proto",
@@ -232,8 +232,8 @@ cc_library_shared {
         "libz",
     ],
     static_libs: [
+        "libabsl",
         "libprotobuf-cpp-lite-ndk",
-        "libtextclassifier_abseil",
         "libtextclassifier_bert_tokenizer",
         "libtflite_static",
         "tflite_configuration_proto",
@@ -306,7 +306,7 @@ cc_library_static {
         "tflite_support_metadata_schema",
     ],
     static_libs: [
-        "libtextclassifier_abseil",
+        "libabsl",
         "tflite_support_libz",
     ],
     apex_available: [
@@ -334,7 +334,7 @@ cc_library_static {
         "tflite_support_metadata_schema",
     ],
     static_libs: [
-        "libtextclassifier_abseil",
+        "libabsl",
         "tflite_configuration_proto",
         "tflite_support_task_core_proto",
     ],
@@ -362,18 +362,18 @@ cc_test {
         "libz",
     ],
     static_libs: [
+        "libabsl",
+        "libbase_ndk",
+        "libgmock_ndk",
         "libprotobuf-cpp-lite-ndk",
-        "libtextclassifier_abseil",
         "libtextclassifier_bert_tokenizer",
         "libtflite_static",
-        "libgmock_ndk",
-        "libbase_ndk",
         "tflite_configuration_proto",
         "tflite_support_classifiers",
         "tflite_support_libz",
         "tflite_support_metadata_extractor",
-        "tflite_support_task_core",
         "tflite_support_task_core_proto",
+        "tflite_support_task_core",
         "tflite_support_tokenizers",
     ],
     header_libs: [
diff --git a/tensorflow_lite_support/cc/text/tokenizers/tokenizer_utils.cc b/tensorflow_lite_support/cc/text/tokenizers/tokenizer_utils.cc
index 7e7eb69..e331234 100644
--- a/tensorflow_lite_support/cc/text/tokenizers/tokenizer_utils.cc
+++ b/tensorflow_lite_support/cc/text/tokenizers/tokenizer_utils.cc
@@ -16,6 +16,7 @@ limitations under the License.
 #include "tensorflow_lite_support/cc/text/tokenizers/tokenizer_utils.h"
 
 #include "absl/status/status.h"
+#include "absl/strings/str_cat.h"
 #include "tensorflow_lite_support/cc/common.h"
 #include "tensorflow_lite_support/cc/port/status_macros.h"
 #include "tensorflow_lite_support/cc/text/tokenizers/regex_tokenizer.h"
diff --git a/tensorflow_lite_support/metadata/cc/metadata_extractor.cc b/tensorflow_lite_support/metadata/cc/metadata_extractor.cc
index c2d85bc..d8cb2ae 100644
--- a/tensorflow_lite_support/metadata/cc/metadata_extractor.cc
+++ b/tensorflow_lite_support/metadata/cc/metadata_extractor.cc
@@ -19,6 +19,7 @@ limitations under the License.
 
 #include "absl/memory/memory.h"
 #include "absl/status/status.h"
+#include "absl/strings/str_cat.h"
 #include "absl/strings/str_format.h"
 #include "absl/strings/string_view.h"
 #include "flatbuffers/flatbuffers.h"
```

