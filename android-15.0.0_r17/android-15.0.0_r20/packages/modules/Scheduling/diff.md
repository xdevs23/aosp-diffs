```diff
diff --git a/tests/hostsidetests/Android.bp b/tests/hostsidetests/Android.bp
index c1e4c05..90acd84 100644
--- a/tests/hostsidetests/Android.bp
+++ b/tests/hostsidetests/Android.bp
@@ -23,7 +23,7 @@ java_test_host {
         "tradefed",
         "truth",
     ],
-    data: [
+    device_common_data: [
         ":RebootReadinessTestApp",
     ],
     test_suites: ["general-tests"],
diff --git a/tests/hostsidetests/testapp/src/com/android/tests/scheduling/RebootReadinessTest.java b/tests/hostsidetests/testapp/src/com/android/tests/scheduling/RebootReadinessTest.java
index 81e2831..bc564b4 100644
--- a/tests/hostsidetests/testapp/src/com/android/tests/scheduling/RebootReadinessTest.java
+++ b/tests/hostsidetests/testapp/src/com/android/tests/scheduling/RebootReadinessTest.java
@@ -70,7 +70,8 @@ public class RebootReadinessTest {
     // Set DeviceConfig properties so the device is reboot ready.
     private void setTestConfigurations() {
         InstrumentationRegistry.getInstrumentation().getUiAutomation().adoptShellPermissionIdentity(
-                Manifest.permission.WRITE_DEVICE_CONFIG);
+                Manifest.permission.WRITE_DEVICE_CONFIG,
+                Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG);
         DeviceConfig.setProperty(DeviceConfig.NAMESPACE_REBOOT_READINESS,
                 PROPERTY_ACTIVE_POLLING_INTERVAL_MS, "1000", false);
         DeviceConfig.setProperty(DeviceConfig.NAMESPACE_REBOOT_READINESS,
diff --git a/tests/src/com/android/cts/scheduling/RebootReadinessManagerTest.java b/tests/src/com/android/cts/scheduling/RebootReadinessManagerTest.java
index f460fd3..136d345 100644
--- a/tests/src/com/android/cts/scheduling/RebootReadinessManagerTest.java
+++ b/tests/src/com/android/cts/scheduling/RebootReadinessManagerTest.java
@@ -293,6 +293,7 @@ public class RebootReadinessManagerTest {
         InstrumentationRegistry.getInstrumentation().getUiAutomation().adoptShellPermissionIdentity(
                 Manifest.permission.REBOOT,
                 Manifest.permission.WRITE_DEVICE_CONFIG, // permission required for T-
+                Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG,
                 Manifest.permission.READ_DEVICE_CONFIG,  // permission required for T-
                 Manifest.permission.SIGNAL_REBOOT_READINESS,
                 Manifest.permission.INTERACT_ACROSS_USERS_FULL);
diff --git a/tests/unittests/src/com/android/server/scheduling/RebootReadinessUnitTest.java b/tests/unittests/src/com/android/server/scheduling/RebootReadinessUnitTest.java
index ff4c84c..5e10d49 100644
--- a/tests/unittests/src/com/android/server/scheduling/RebootReadinessUnitTest.java
+++ b/tests/unittests/src/com/android/server/scheduling/RebootReadinessUnitTest.java
@@ -169,6 +169,7 @@ public class RebootReadinessUnitTest {
         when(mMockContext.getPackageManager()).thenReturn(mPackageManager);
         InstrumentationRegistry.getInstrumentation().getUiAutomation()
                 .adoptShellPermissionIdentity(Manifest.permission.WRITE_DEVICE_CONFIG,
+                        Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG,
                         Manifest.permission.READ_DEVICE_CONFIG,
                         Manifest.permission.SCHEDULE_EXACT_ALARM,
                         Manifest.permission.ACCESS_NETWORK_STATE);
```

