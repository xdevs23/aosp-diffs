```diff
diff --git a/app/Android.bp b/app/Android.bp
index 965fef2..7293709 100644
--- a/app/Android.bp
+++ b/app/Android.bp
@@ -65,9 +65,9 @@ android_app {
     privileged: true,
     libs: [
         "framework-annotations-lib",
-        "framework-connectivity",
-        "framework-connectivity-t",
-        "framework-statsd",
+        "framework-connectivity.stubs.module_lib",
+        "framework-connectivity-t.stubs.module_lib",
+        "framework-statsd.stubs.module_lib",
     ],
     optimize: {
         proguard_flags_files: ["proguard.flags"],
diff --git a/app/src/com/android/rkpdapp/BootReceiver.java b/app/src/com/android/rkpdapp/BootReceiver.java
index 0c88f1e..72453a0 100644
--- a/app/src/com/android/rkpdapp/BootReceiver.java
+++ b/app/src/com/android/rkpdapp/BootReceiver.java
@@ -49,6 +49,7 @@ public class BootReceiver extends BroadcastReceiver {
 
         Constraints constraints = new Constraints.Builder()
                 .setRequiredNetworkType(NetworkType.CONNECTED)
+                .setRequiresBatteryNotLow(true)
                 .build();
 
         PeriodicWorkRequest workRequest =
diff --git a/app/tests/avf/Android.bp b/app/tests/avf/Android.bp
index 438c75e..1d0cd37 100644
--- a/app/tests/avf/Android.bp
+++ b/app/tests/avf/Android.bp
@@ -20,7 +20,6 @@ android_test {
     platform_apis: true,
     test_suites: [
         "general-tests",
-        "device-tests",
         "mts-rkpd",
     ],
     min_sdk_version: "33",
diff --git a/app/tests/e2e/src/com/android/rkpdapp/e2etest/KeystoreIntegrationTest.java b/app/tests/e2e/src/com/android/rkpdapp/e2etest/KeystoreIntegrationTest.java
index 016d2c9..0d8a66f 100644
--- a/app/tests/e2e/src/com/android/rkpdapp/e2etest/KeystoreIntegrationTest.java
+++ b/app/tests/e2e/src/com/android/rkpdapp/e2etest/KeystoreIntegrationTest.java
@@ -354,7 +354,7 @@ public class KeystoreIntegrationTest {
             try {
                 Thread.sleep(60 * 1000);
             } catch (InterruptedException e) {
-                assertWithMessage("sleep failed", e).fail();
+                assertWithMessage("sleep failed: %s", e).fail();
             }
             return null;
         };
diff --git a/app/tests/stress/src/com/android/rkpdapp/stress/RegistrationBinderStressTest.java b/app/tests/stress/src/com/android/rkpdapp/stress/RegistrationBinderStressTest.java
index 4ab5438..efe8925 100644
--- a/app/tests/stress/src/com/android/rkpdapp/stress/RegistrationBinderStressTest.java
+++ b/app/tests/stress/src/com/android/rkpdapp/stress/RegistrationBinderStressTest.java
@@ -67,6 +67,8 @@ public class RegistrationBinderStressTest {
 
     @Before
     public void setUp() throws Exception {
+        mContext = ApplicationProvider.getApplicationContext();
+
         assume()
                 .withMessage("The RKP server hostname is not configured -- assume RKP disabled.")
                 .that(SystemProperties.get("remote_provisioning.hostname"))
@@ -75,7 +77,11 @@ public class RegistrationBinderStressTest {
                 .withMessage("Remotely Provisioned Component is not found -- RKP disabled.")
                 .that(ServiceManager.isDeclared(SERVICE))
                 .isTrue();
-        mContext = ApplicationProvider.getApplicationContext();
+        assume()
+                .withMessage("RKP Stress tests rely on network availability.")
+                .that(ServerInterface.isNetworkConnected(mContext))
+                .isTrue();
+
         mIrpcHal = ServiceManagerInterface.getInstance(SERVICE);
         mKeyDao = RkpdDatabase.getDatabase(mContext).provisionedKeyDao();
         mKeyDao.deleteAllKeys();
diff --git a/system-server/tests/unit/Android.bp b/system-server/tests/unit/Android.bp
index a44c774..b461e41 100644
--- a/system-server/tests/unit/Android.bp
+++ b/system-server/tests/unit/Android.bp
@@ -27,7 +27,7 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.mock",
+        "android.test.mock.stubs.system",
     ],
     min_sdk_version: "33",
     target_sdk_version: "current",
```

