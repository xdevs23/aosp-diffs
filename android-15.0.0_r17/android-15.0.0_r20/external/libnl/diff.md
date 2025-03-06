```diff
diff --git a/Android.bp b/Android.bp
index e711be01..9f8e3ee2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1,4 +1,3 @@
-
 package {
     default_applicable_licenses: ["external_libnl_license"],
 }
@@ -108,5 +107,7 @@ cc_library {
     apex_available: [
         "//apex_available:platform",
         "com.android.virt",
+        "com.android.wifi",
     ],
+    min_sdk_version: "apex_inherit",
 }
```

