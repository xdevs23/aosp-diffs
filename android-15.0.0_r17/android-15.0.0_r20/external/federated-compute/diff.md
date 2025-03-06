```diff
diff --git a/Android.bp b/Android.bp
index 3130368..2afe5a6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -50,6 +50,7 @@ java_library_static {
         "fcp/protos/ondevicepersonalization/task_assignments.proto",
         "fcp/protos/ondevicepersonalization/eligibility_spec.proto",
         "fcp/protos/ondevicepersonalization/exception_reporting.proto",
+        "fcp/protos/ondevicepersonalization/common.proto",
         "fcp/protos/federatedcompute/common.proto",
         "fcp/protos/plan.proto",
         "fcp/client/**/*.proto",
@@ -185,11 +186,12 @@ cc_test {
     ],
     static_libs: [
         "federated-compute-cc-proto-lite",
-        "libgmock",
+        "libabsl",
         "libbase_ndk",
-        "libprotobuf-cpp-lite-ndk",
+        "libc++fs", // used by filesystem
+        "libgmock",
         "liblog",
-        "tensorflow_abseil",
+        "libprotobuf-cpp-lite-ndk",
     ],
     whole_static_libs: [
         "libfederatedcompute",
diff --git a/fcp/protos/federatedcompute/common.proto b/fcp/protos/federatedcompute/common.proto
index 1cc8ae3..9862d53 100644
--- a/fcp/protos/federatedcompute/common.proto
+++ b/fcp/protos/federatedcompute/common.proto
@@ -356,18 +356,3 @@ enum Code {
   // HTTP Mapping: 500 Internal Server Error
   DATA_LOSS = 15;
 }
-
-// The upload instruction shared for use by the aggregate exception counts 
-// from the client and FL results.
-// Next id: 4
-message UploadInstruction {
-  // upload file path.
-  string upload_location = 1;
-
-  // extra head for uploading.
-  map<string, string> extra_request_headers = 2;
-
-  // The compression used for resource, or unset if the data is
-  // uncompressed.
-  google.internal.federatedcompute.v1.ResourceCompressionFormat compression_format = 3;
-}
diff --git a/fcp/protos/ondevicepersonalization/common.proto b/fcp/protos/ondevicepersonalization/common.proto
new file mode 100644
index 0000000..25dd32c
--- /dev/null
+++ b/fcp/protos/ondevicepersonalization/common.proto
@@ -0,0 +1,38 @@
+/**
+ * Copyright 2024 Google LLC
+ *
+ * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may
+ * not use this file except in compliance with the License. You may obtain a
+ * copy of the License at
+ *
+ * <p>http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * <p>Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+ * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+ * License for the specific language governing permissions and limitations under
+ * the License.
+ */
+syntax = "proto3";
+
+package google.ondevicepersonalization.federatedcompute.proto;
+
+import "fcp/protos/federatedcompute/common.proto";
+
+option java_package = "com.google.ondevicepersonalization.federatedcompute.proto";
+option java_multiple_files = true;
+
+// The upload instruction shared for use by the aggregate exception counts
+// from the client and FL results.
+// Next id: 4
+message UploadInstruction {
+  // upload file path.
+  string upload_location = 1;
+
+  // extra head for uploading.
+  map<string, string> extra_request_headers = 2;
+
+  // The compression used for resource, or unset if the data is
+  // uncompressed.
+  google.internal.federatedcompute.v1.ResourceCompressionFormat compression_format = 3;
+}
diff --git a/fcp/protos/ondevicepersonalization/exception_reporting.proto b/fcp/protos/ondevicepersonalization/exception_reporting.proto
index ff1c1b7..5e016cb 100644
--- a/fcp/protos/ondevicepersonalization/exception_reporting.proto
+++ b/fcp/protos/ondevicepersonalization/exception_reporting.proto
@@ -18,8 +18,7 @@ syntax = "proto3";
 package google.ondevicepersonalization.federatedcompute.proto;
 
 import "fcp/protos/federatedcompute/common.proto";
-import "fcp/protos/plan.proto";
-import "fcp/protos/ondevicepersonalization/eligibility_spec.proto";
+import "fcp/protos/ondevicepersonalization/common.proto";
 import "google/protobuf/timestamp.proto";
 
 option java_package = "com.google.ondevicepersonalization.federatedcompute.proto";
@@ -27,7 +26,7 @@ option java_multiple_files = true;
 
 // Report exception request.
 // The url to report exception counts under v1 API is:
-// https://{host}/debugreporting/v1/exceptions:report-exceptions
+// https://{host}/debugreporting/v1/exceptions:report
 // Next Id: 4
 message ReportExceptionRequest {
    // Request time for this current request in UTC (as seconds since epoch)
@@ -44,7 +43,7 @@ message ReportExceptionRequest {
 // Next id: 3
 message ReportExceptionResponse {
   // Upload result instruction on succeeded.
-  google.internal.federatedcompute.v1.UploadInstruction upload_instruction = 1;
+  UploadInstruction upload_instruction = 1;
 
   // Rejection reason.
   google.internal.federatedcompute.v1.RejectionInfo rejection_info = 2;
diff --git a/fcp/protos/ondevicepersonalization/task_assignments.proto b/fcp/protos/ondevicepersonalization/task_assignments.proto
index 92d9abe..1d3513a 100644
--- a/fcp/protos/ondevicepersonalization/task_assignments.proto
+++ b/fcp/protos/ondevicepersonalization/task_assignments.proto
@@ -20,6 +20,7 @@ package google.ondevicepersonalization.federatedcompute.proto;
 import "fcp/protos/federatedcompute/common.proto";
 import "fcp/protos/plan.proto";
 import "fcp/protos/ondevicepersonalization/eligibility_spec.proto";
+import "fcp/protos/ondevicepersonalization/common.proto";
 
 option java_package = "com.google.ondevicepersonalization.federatedcompute.proto";
 option java_multiple_files = true;
@@ -133,7 +134,7 @@ message ReportResultRequest {
 // Report result response.
 message ReportResultResponse {
   // Upload result instruction on succeeded.
-  google.internal.federatedcompute.v1.UploadInstruction upload_instruction = 1;
+  UploadInstruction upload_instruction = 1;
 
   // Rejection reason.
   google.internal.federatedcompute.v1.RejectionInfo rejection_info = 2;
diff --git a/fcp/tensorflow/external_dataset.h b/fcp/tensorflow/external_dataset.h
index 0b2559f..700c04b 100644
--- a/fcp/tensorflow/external_dataset.h
+++ b/fcp/tensorflow/external_dataset.h
@@ -22,6 +22,7 @@
 
 #include "absl/status/status.h"
 #include "absl/status/statusor.h"
+#include "absl/strings/str_cat.h"
 #include "absl/strings/string_view.h"
 #include "fcp/base/bounds.h"
 #include "fcp/tensorflow/host_object.h"
diff --git a/fcp/tensorflow/external_dataset_op.cc b/fcp/tensorflow/external_dataset_op.cc
index 16a373b..56789fa 100644
--- a/fcp/tensorflow/external_dataset_op.cc
+++ b/fcp/tensorflow/external_dataset_op.cc
@@ -17,6 +17,7 @@
 #include <string>
 #include <utility>
 
+#include "absl/strings/str_cat.h"
 #include "absl/strings/str_format.h"
 #include "fcp/base/random_token.h"
 #include "fcp/tensorflow/external_dataset.h"
```

