```diff
diff --git a/Android.bp b/Android.bp
index aa6a9a1093..7ff920520c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -98,7 +98,17 @@ cc_defaults {
         "-Woverloaded-virtual",
     ],
     static_libs: [
-        "libabsl",
+        "absl_algorithm_container",
+        "absl_cleanup",
+        "absl_container_inlined_vector",
+        "absl_flags_flag",
+        "absl_flags_parse",
+        "absl_functional_any_invocable",
+        "absl_functional_bind_front",
+        "absl_memory",
+        "absl_strings",
+        "absl_types_optional",
+        "absl_types_variant",
         "libaom",
         "libevent",
         "libopus",
```

