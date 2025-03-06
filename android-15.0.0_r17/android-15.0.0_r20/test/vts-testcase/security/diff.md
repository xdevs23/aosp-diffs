```diff
diff --git a/avb/Android.bp b/avb/Android.bp
index ee70dfa..f56ebb3 100644
--- a/avb/Android.bp
+++ b/avb/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/avb/kernel_version_test.cpp b/avb/kernel_version_test.cpp
index 0803c39..927ffb8 100644
--- a/avb/kernel_version_test.cpp
+++ b/avb/kernel_version_test.cpp
@@ -330,11 +330,20 @@ TEST(KernelVersionTest, AgainstPlatformRelease) {
       << " should not exceed the platform release " << android_platform_release
       << ".";
 
+  auto runtime_info =
+      android::vintf::VintfObject::GetInstance()->getRuntimeInfo(
+          android::vintf::RuntimeInfo::FetchFlag::CPU_VERSION);
+  ASSERT_NE(runtime_info, nullptr);
+
   const static bool is_tv_device =
       DeviceSupportsFeature("android.software.leanback");
-  if (product_first_api_level <= 33 && is_tv_device) {
+
+  if (is_tv_device &&
+    (product_first_api_level <= 33 ||
+        (runtime_info->hardwareId() != "aarch64" &&
+         runtime_info->hardwareId() != "armv8l"))) {
     GTEST_SKIP()
-        << "Exempt from GKI test on TV devices launched before Android U";
+      << "Exempt from GKI test on TV devices launched before Android U or using 32bit kernel";
   }
 
   bool is_launch = product_first_api_level >= android_platform_release;
diff --git a/system_property/Android.bp b/system_property/Android.bp
index 01d4242..a0fe6de 100644
--- a/system_property/Android.bp
+++ b/system_property/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_virtualization",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
```

