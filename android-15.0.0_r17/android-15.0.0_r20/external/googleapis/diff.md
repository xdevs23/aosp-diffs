```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 000000000..a95ebc898
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,42 @@
+// Copyright 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library {
+    name: "libgoogleapis-status-proto",
+    visibility: [
+        "//device/google/cuttlefish:__subpackages__",
+    ],
+    srcs: [
+        "google/rpc/code.proto",
+        "google/rpc/status.proto",
+        ":libprotobuf-internal-any-proto",
+    ],
+    host_supported: true,
+    proto: {
+        canonical_path_from_root: false,
+        export_proto_headers: true,
+        include_dirs: [
+            "external/googleapis",
+            "external/protobuf/src",
+        ],
+        type: "full",
+    },
+    shared_libs: [
+        "libprotobuf-cpp-full",
+    ],
+}
diff --git a/google/api/Android.bp b/google/api/Android.bp
index 9c396ecd5..5cca5797c 100644
--- a/google/api/Android.bp
+++ b/google/api/Android.bp
@@ -89,3 +89,19 @@ java_library_host {
     // TODO(b/339514031): Unpin tradefed dependencies to Java 11.
     java_version: "11",
 }
+
+java_library_host {
+    name: "googleapis-field-behavior-java-proto",
+    srcs: [
+        "field_behavior.proto",
+    ],
+    proto: {
+        include_dirs: [
+            "external/googleapis",
+            "external/protobuf/src",
+        ],
+        type: "full",
+    },
+    // TODO(b/339514031): Unpin tradefed dependencies to Java 11.
+    java_version: "11",
+}
```

