```diff
diff --git a/Android.bp b/Android.bp
index bee5652..3130368 100644
--- a/Android.bp
+++ b/Android.bp
@@ -49,6 +49,7 @@ java_library_static {
     srcs: [
         "fcp/protos/ondevicepersonalization/task_assignments.proto",
         "fcp/protos/ondevicepersonalization/eligibility_spec.proto",
+        "fcp/protos/ondevicepersonalization/exception_reporting.proto",
         "fcp/protos/federatedcompute/common.proto",
         "fcp/protos/plan.proto",
         "fcp/client/**/*.proto",
diff --git a/fcp/protos/federatedcompute/common.proto b/fcp/protos/federatedcompute/common.proto
index 2c6f05c..1cc8ae3 100644
--- a/fcp/protos/federatedcompute/common.proto
+++ b/fcp/protos/federatedcompute/common.proto
@@ -357,3 +357,17 @@ enum Code {
   DATA_LOSS = 15;
 }
 
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
new file mode 100644
index 0000000..ff1c1b7
--- /dev/null
+++ b/fcp/protos/ondevicepersonalization/exception_reporting.proto
@@ -0,0 +1,74 @@
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
+import "fcp/protos/plan.proto";
+import "fcp/protos/ondevicepersonalization/eligibility_spec.proto";
+import "google/protobuf/timestamp.proto";
+
+option java_package = "com.google.ondevicepersonalization.federatedcompute.proto";
+option java_multiple_files = true;
+
+// Report exception request.
+// The url to report exception counts under v1 API is:
+// https://{host}/debugreporting/v1/exceptions:report-exceptions
+// Next Id: 4
+message ReportExceptionRequest {
+   // Request time for this current request in UTC (as seconds since epoch)
+   google.protobuf.Timestamp request_timestamp = 1;
+
+   // Last successful report by device in UTC (as seconds since epoch)
+   google.protobuf.Timestamp last_reported_timestamp = 2;
+
+  // The client's capabilities when uploading result.
+  google.internal.federatedcompute.v1.ResourceCapabilities resource_capabilities = 3;
+}
+
+// Report exception response.
+// Next id: 3
+message ReportExceptionResponse {
+  // Upload result instruction on succeeded.
+  google.internal.federatedcompute.v1.UploadInstruction upload_instruction = 1;
+
+  // Rejection reason.
+  google.internal.federatedcompute.v1.RejectionInfo rejection_info = 2;
+}
+
+// Aggregated error data sent from client -> server.
+// Next id: 2
+message ErrorDataList {
+  // Payload of error-data sent from client-> server, list of aggregated error data records.
+  repeated ErrorData error_data = 1;
+}
+
+// Single entry in error data sent from client -> server.
+// Next id: 5
+message ErrorData {
+   // The error code returned by the IsolatedService.
+   uint32 error_code = 1;
+
+   // The aggregated count of error_code on the given epoch_day.
+   uint32 error_count = 2;
+
+    /** The date associated with this record of aggregated errors. */
+    uint32 epoch_day = 3;
+
+    // The version of the package of the IsolatedService.
+    uint64 service_package_version = 4;
+}
diff --git a/fcp/protos/ondevicepersonalization/task_assignments.proto b/fcp/protos/ondevicepersonalization/task_assignments.proto
index fb4cd08..92d9abe 100644
--- a/fcp/protos/ondevicepersonalization/task_assignments.proto
+++ b/fcp/protos/ondevicepersonalization/task_assignments.proto
@@ -113,6 +113,15 @@ message ReportResultRequest {
 
     // Failed due to eligibility task is not qualified.
     NOT_ELIGIBLE = 3;
+
+    // Failed due to example generation failure
+    FAILED_EXAMPLE_GENERATION = 4;
+
+    // Failed due to model computation error
+    FAILED_MODEL_COMPUTATION = 5;
+
+    // Failed due to model ops error
+    FAILED_OPS_ERROR = 6;
   }
 
   Result result = 1;
@@ -124,22 +133,8 @@ message ReportResultRequest {
 // Report result response.
 message ReportResultResponse {
   // Upload result instruction on succeeded.
-  UploadInstruction upload_instruction = 1;
+  google.internal.federatedcompute.v1.UploadInstruction upload_instruction = 1;
 
   // Rejection reason.
   google.internal.federatedcompute.v1.RejectionInfo rejection_info = 2;
 }
-
-// The upload instruction.
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
```

