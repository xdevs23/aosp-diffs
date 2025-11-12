```diff
diff --git a/Android.bp b/Android.bp
index 0081294..5d40521 100644
--- a/Android.bp
+++ b/Android.bp
@@ -43,7 +43,10 @@ cc_library_static {
     ],
     whole_static_libs: [
         "libpjc_crypto",
-        "libabsl",
+        "absl_status",
+        "absl_status_statusor",
+        "absl_log_check",
+        "absl_flags_flag",
     ],
     cflags: ["-Wno-unused-parameter"],
     export_include_dirs: ["."],
@@ -99,7 +102,10 @@ cc_test {
         "libpjc_crypto",
         "libact",
         "libgmock",
-        "libabsl",
+        "absl_status",
+        "absl_status_statusor",
+        "absl_log_check",
+        "absl_flags_flag",
     ],
     cflags: ["-Wno-unused-parameter"],
 }
@@ -119,7 +125,10 @@ cc_test {
         "libpjc_crypto",
         "libact",
         "libgmock",
-        "libabsl",
+        "absl_status",
+        "absl_status_statusor",
+        "absl_log_check",
+        "absl_flags_flag",
     ],
     cflags: ["-Wno-unused-parameter"],
     test_suites: ["general-tests"],
@@ -142,7 +151,10 @@ cc_test {
         "libpjc_crypto",
         "libact",
         "libgmock",
-        "libabsl",
+        "absl_status",
+        "absl_status_statusor",
+        "absl_log_check",
+        "absl_flags_flag",
     ],
     cflags: ["-Wno-unused-parameter"],
 }
```

