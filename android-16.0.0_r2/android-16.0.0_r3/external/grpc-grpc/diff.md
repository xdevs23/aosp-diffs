```diff
diff --git a/Android.bp b/Android.bp
index 686ad6bc80..890c24a323 100644
--- a/Android.bp
+++ b/Android.bp
@@ -666,6 +666,22 @@ cc_defaults {
     visibility: ["//external/grpc-grpc:__subpackages__"],
 }
 
+GRPC_ABSL_LIBS = [
+    "absl_status",
+    "absl_status_statusor",
+    "absl_debugging_failure_signal_handler",
+    "absl_hash",
+    "absl_container_flat_hash_set",
+    "absl_container_flat_hash_map",
+    "absl_random",
+    "absl_random_bit_gen_ref",
+    "absl_cleanup",
+    "absl_flags_flag",
+    "absl_flags_parse",
+    "absl_functional_bind_front",
+    "absl_log",
+]
+
 cc_defaults {
     name: "grpc_defaults",
     defaults: ["grpc_deps_defaults"],
@@ -679,9 +695,8 @@ cc_defaults {
         "libgrpc_third_party_xxhash",
     ],
     static_libs: [
-        "libabsl",
         "libregex_re2",
-    ],
+    ] + GRPC_ABSL_LIBS,
     shared_libs: [
         "libbinder_ndk",
         "libz",
@@ -842,9 +857,7 @@ cc_library_host_static {
     local_include_dirs: [
         "include",
     ],
-    static_libs: [
-        "libabsl",
-    ],
+    static_libs: GRPC_ABSL_LIBS,
     generated_headers: [
         "reflection_proto_h",
     ],
@@ -907,9 +920,7 @@ cc_library_shared {
     shared_libs: [
         "liblog",
     ],
-    export_static_lib_headers: [
-        "libabsl",
-    ],
+    export_static_lib_headers: GRPC_ABSL_LIBS,
     export_include_dirs: [
         "include",
     ],
@@ -937,9 +948,7 @@ cc_library_shared {
         "libcrypto",
         "libssl",
     ],
-    export_static_lib_headers: [
-        "libabsl",
-    ],
+    export_static_lib_headers: GRPC_ABSL_LIBS,
     export_include_dirs: [
         "include",
     ],
```

