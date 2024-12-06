```diff
diff --git a/Android.bp b/Android.bp
index 25e1c50ae0..72c7870768 100644
--- a/Android.bp
+++ b/Android.bp
@@ -792,8 +792,8 @@ genrule {
     ],
 }
 
-cc_library_host_static {
-    name: "libgrpc++_reflection",
+cc_defaults {
+    name: "grpc_reflection_defaults",
     defaults: ["grpc_defaults"],
     srcs: [
         "src/cpp/ext/proto_server_reflection.cc",
@@ -810,11 +810,23 @@ cc_library_host_static {
     ],
     static_libs: [
         "libgrpc++_common",
+    ],
+    shared_libs: [
         "libprotobuf-cpp-full",
     ],
     visibility: ["//visibility:public"],
 }
 
+cc_library_host_static {
+    name: "libgrpc++_reflection",
+    defaults: ["grpc_reflection_defaults"],
+}
+
+cc_library_static {
+    name: "libgrpc++_reflection_target",
+    defaults: ["grpc_reflection_defaults"],
+}
+
 cc_library_host_static {
     name: "grpc_cli_libs",
     srcs: [
@@ -868,6 +880,11 @@ cc_library_static {
         "libgrpc_upb_protos",
     ],
     shared_libs: ["liblog"],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+
 }
 
 // gRPC C++ library target with no encryption or authentication
@@ -926,6 +943,11 @@ cc_library_shared {
         "include",
     ],
     visibility: ["//visibility:public"],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+
 }
 
 cc_library_static {
@@ -942,6 +964,11 @@ cc_library_static {
     header_libs: [
         "libgrpc_third_party_upb_headers",
     ],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+
 }
 
 cc_library_static {
diff --git a/third_party/upb/Android.bp b/third_party/upb/Android.bp
index 83f22fb31d..01eab1b2ee 100644
--- a/third_party/upb/Android.bp
+++ b/third_party/upb/Android.bp
@@ -19,6 +19,11 @@ cc_library_headers {
     export_include_dirs: [
         ".",
     ],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+
 }
 
 cc_library_static {
@@ -88,4 +93,9 @@ cc_library_static {
     export_include_dirs: [
         ".",
     ],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+
 }
diff --git a/third_party/utf8_range/Android.bp b/third_party/utf8_range/Android.bp
index 3604a6313b..3923b2999f 100644
--- a/third_party/utf8_range/Android.bp
+++ b/third_party/utf8_range/Android.bp
@@ -25,4 +25,9 @@ cc_library_static {
     export_include_dirs: [
         ".",
     ],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+
 }
diff --git a/third_party/xxhash/Android.bp b/third_party/xxhash/Android.bp
index 2c2e0dc63b..b2d272c03a 100644
--- a/third_party/xxhash/Android.bp
+++ b/third_party/xxhash/Android.bp
@@ -17,4 +17,9 @@ cc_library_headers {
     name: "libgrpc_third_party_xxhash",
     defaults: ["grpc_deps_defaults"],
     export_include_dirs: ["."],
+    apex_available: [
+        "//apex_available:anyapex",
+        "//apex_available:platform",
+    ],
+
 }
```

