```diff
diff --git a/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java b/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
index 0404db9..4d8fa66 100644
--- a/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
+++ b/harness/src/main/java/com/android/csuite/core/AppCrawlTester.java
@@ -318,6 +318,9 @@ public final class AppCrawlTester {
         // Minimum timeout 3 minutes plus crawl test timeout.
         long commandTimeout = 3L * 60 * 1000 + getOptions().getTimeoutSec() * 1000;
 
+        CLog.i(
+                "Starting to crawl the package %s with command %s",
+                mPackageName, String.join(" ", command.get()));
         // TODO(yuexima): When the obb_file option is supported in espresso mode, the timeout need
         // to be extended.
         if (getOptions().isRecordScreen()) {
diff --git a/integration_tests/Android.bp b/integration_tests/Android.bp
index cdb2b44..78c2152 100644
--- a/integration_tests/Android.bp
+++ b/integration_tests/Android.bp
@@ -119,7 +119,7 @@ python_test_host {
 python_library_host {
     name: "csuite_crash_detection_test_data",
     pkg_path: "testdata",
-    data: [
+    device_common_data: [
         ":csuite_crash_on_launch_test_app",
         ":csuite_no_crash_test_app",
     ],
diff --git a/test_targets/webview-app-launch/plan.xml b/test_targets/webview-app-launch/plan.xml
index 5d3c48f..102612c 100644
--- a/test_targets/webview-app-launch/plan.xml
+++ b/test_targets/webview-app-launch/plan.xml
@@ -1,3 +1,3 @@
 <configuration description="WebView C-Suite Crawler Test Plan">
-  <target_preparer class="com.android.webview.tests.WebviewInstallerToolPreparer"/>
+  <target_preparer class="com.android.webview.lib.WebviewInstallerToolPreparer"/>
 </configuration>
```

