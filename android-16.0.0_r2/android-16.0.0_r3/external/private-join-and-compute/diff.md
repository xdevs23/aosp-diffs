```diff
diff --git a/Android.bp b/Android.bp
index 4425e06..f173857 100644
--- a/Android.bp
+++ b/Android.bp
@@ -76,7 +76,14 @@ cc_library {
         "liblog",
     ],
     static_libs: [
-        "libabsl",
+        "absl_log",
+        "absl_log_check",
+        "absl_strings",
+        "absl_flags_flag",
+        "absl_container_node_hash_map",
+        "absl_status_statusor",
+        "absl_status",
+        "absl_memory",
     ],
     cflags: ["-Wno-unused-parameter"],
     proto: {
@@ -128,7 +135,12 @@ cc_test {
     ],
     static_libs: [
         "libgmock",
-        "libabsl",
+        "absl_strings",
+        "absl_status",
+        "absl_status_statusor",
+        "absl_log",
+        "absl_log_check",
+        "absl_flags_flag",
     ],
     include_dirs: [
         "external/protobuf",
@@ -164,7 +176,6 @@ cc_test {
     ],
     static_libs: [
         "libgmock",
-        "libabsl",
     ],
     target: {
         host: {
```

