```diff
diff --git a/test/java_test/Android.bp b/test/java_test/Android.bp
index ec34d748..97ecce85 100644
--- a/test/java_test/Android.bp
+++ b/test/java_test/Android.bp
@@ -1,4 +1,5 @@
 package {
+    default_team: "trendy_team_android_kernel",
     // See: http://go/android-license-faq
     // A large-scale-change added 'default_applicable_licenses' to import
     // all of the 'license_kinds' from "system_tools_hidl_license"
@@ -20,7 +21,7 @@ python_test_host {
         unit_test: false,
     },
     data_device_bins_both: ["hidl_test_java_native"],
-    data: [
+    device_common_data: [
         ":hidl_test_java_java",
     ],
 }
```

