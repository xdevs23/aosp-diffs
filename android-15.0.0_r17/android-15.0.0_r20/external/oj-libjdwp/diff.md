```diff
diff --git a/Android.bp b/Android.bp
index a27b4ed8b..ebd711d1f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -151,7 +151,7 @@ cc_library {
         "libjdwp_headers",
         "libnpt_headers",
     ],
-    required: [
+    runtime_libs: [
         "libnpt",
         "libdt_socket",
     ],
@@ -178,7 +178,7 @@ cc_library {
         "libjdwp_headers",
         "libnpt_headers",
     ],
-    required: ["libnpt"],
+    runtime_libs: ["libnpt"],
     defaults: ["upstream-jdwp-defaults"],
     apex_available: [
         "com.android.art",
```

