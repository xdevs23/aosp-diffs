```diff
diff --git a/hostsidetests/packageinstaller/Android.bp b/hostsidetests/packageinstaller/Android.bp
index d7ae38c..136b9bc 100644
--- a/hostsidetests/packageinstaller/Android.bp
+++ b/hostsidetests/packageinstaller/Android.bp
@@ -26,7 +26,7 @@ java_test_host {
         "tradefed",
         "truth",
     ],
-    data: [
+    device_common_data: [
         ":CtsRootPackageInstallerTestCases",
         ":CtsRootRollbackManagerHostTestHelperApp",
     ],
diff --git a/hostsidetests/rollback/Android.bp b/hostsidetests/rollback/Android.bp
index 3a26433..997c9f9 100644
--- a/hostsidetests/rollback/Android.bp
+++ b/hostsidetests/rollback/Android.bp
@@ -27,7 +27,7 @@ java_test_host {
         "truth",
     ],
     static_libs: ["cts-install-lib-host"],
-    data: [":CtsRootRollbackManagerHostTestHelperApp"],
+    device_common_data: [":CtsRootRollbackManagerHostTestHelperApp"],
     test_suites: [
         "cts_root",
         "general-tests",
diff --git a/hostsidetests/rollback/app/src/com/android/cts_root/rollback/host/app/HostTestHelper.java b/hostsidetests/rollback/app/src/com/android/cts_root/rollback/host/app/HostTestHelper.java
index 7b5aa79..9e9047a 100644
--- a/hostsidetests/rollback/app/src/com/android/cts_root/rollback/host/app/HostTestHelper.java
+++ b/hostsidetests/rollback/app/src/com/android/cts_root/rollback/host/app/HostTestHelper.java
@@ -61,7 +61,8 @@ public class HostTestHelper {
                     Manifest.permission.DELETE_PACKAGES,
                     Manifest.permission.TEST_MANAGE_ROLLBACKS,
                     Manifest.permission.FORCE_STOP_PACKAGES,
-                    Manifest.permission.WRITE_DEVICE_CONFIG);
+                    Manifest.permission.WRITE_DEVICE_CONFIG,
+                    Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG);
     }
 
     @After
diff --git a/tests/input/AndroidManifest.xml b/tests/input/AndroidManifest.xml
index 47b55be..5f2ae83 100644
--- a/tests/input/AndroidManifest.xml
+++ b/tests/input/AndroidManifest.xml
@@ -17,6 +17,8 @@
 <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="android.input.cts_root">
     <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
     <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
+    <uses-permission android:name="android.permission.CREATE_VIRTUAL_DEVICE" />
+    <uses-permission android:name="android.permission.ADD_TRUSTED_DISPLAY" />
     <application android:label="InputTest"
                  android:requestLegacyExternalStorage="true">
         <activity android:name="android.input.cts_root.CaptureEventActivity"
diff --git a/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt b/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
index 471084b..d907f41 100644
--- a/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
+++ b/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
@@ -23,7 +23,7 @@ import android.os.SystemProperties
 import android.platform.test.annotations.EnableFlags
 import android.view.MotionEvent
 import android.view.WindowManager
-import android.virtualdevice.cts.common.FakeAssociationRule
+import android.virtualdevice.cts.common.VirtualDeviceRule
 import androidx.test.filters.MediumTest
 import androidx.test.platform.app.InstrumentationRegistry
 import com.android.cts.input.DefaultPointerSpeedRule
@@ -71,13 +71,15 @@ class HidePointerIconOnSecureWindowScreenshotTest {
     @get:Rule
     val testName = TestName()
     @get:Rule
+    val virtualDeviceRule = VirtualDeviceRule.createDefault()!!
+    // TODO(b/366492484): Remove reliance on VDM.
+    @get:Rule
     val virtualDisplayRule = VirtualDisplayActivityScenario.Rule<CaptureEventActivity>(
         testName,
         useSecureDisplay = true,
+        virtualDeviceRule = virtualDeviceRule
     )
     @get:Rule
-    val fakeAssociationRule = FakeAssociationRule()
-    @get:Rule
     val defaultPointerSpeedRule = DefaultPointerSpeedRule()
     @get:Rule
     val screenshotRule = ScreenshotTestRule(GoldenPathManager(
@@ -92,7 +94,6 @@ class HidePointerIconOnSecureWindowScreenshotTest {
 
     @Before
     fun setUp() {
-        val context = InstrumentationRegistry.getInstrumentation().targetContext
         activity = virtualDisplayRule.activity
         activity.runOnUiThread {
             activity.actionBar?.hide()
@@ -101,9 +102,8 @@ class HidePointerIconOnSecureWindowScreenshotTest {
         }
 
         device.setUp(
-            context,
+            virtualDeviceRule.defaultVirtualDevice,
             virtualDisplayRule.virtualDisplay.display,
-            fakeAssociationRule.associationInfo,
         )
 
         verifier = EventVerifier(activity::getInputEvent)
diff --git a/tests/packagewatchdog/Android.bp b/tests/packagewatchdog/Android.bp
index 6bc2d6c..3cbb333 100644
--- a/tests/packagewatchdog/Android.bp
+++ b/tests/packagewatchdog/Android.bp
@@ -26,6 +26,7 @@ android_test {
         "services.core",
         "truth",
         "platform-test-annotations",
+        "service-crashrecovery-pre-jarjar",
     ],
     libs: [
         "android.test.runner.stubs.test",
@@ -35,6 +36,7 @@ android_test {
     test_suites: [
         "cts_root",
         "general-tests",
+        "mts-crashrecovery",
     ],
-    sdk_version: "test_current",
+    sdk_version: "system_server_current",
 }
diff --git a/tests/packagewatchdog/AndroidTest.xml b/tests/packagewatchdog/AndroidTest.xml
index 6620098..4dc2aeb 100644
--- a/tests/packagewatchdog/AndroidTest.xml
+++ b/tests/packagewatchdog/AndroidTest.xml
@@ -35,4 +35,9 @@
         <option name="runner" value="androidx.test.runner.AndroidJUnitRunner" />
         <option name="restart" value="false" />
     </test>
+
+    <!-- Only run Cts Tests in MTS if the Crashrecovery Mainline module is installed. -->
+    <object type="module_controller" class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
+        <option name="mainline-module-package-name" value="com.google.android.crashrecovery" />
+    </object>
 </configuration>
diff --git a/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java b/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
index 503b5c0..fc0c3e8 100644
--- a/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
+++ b/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
@@ -39,7 +39,7 @@ import java.util.concurrent.TimeUnit;
 public class PackageWatchdogTest {
 
     private PackageWatchdog mPackageWatchdog;
-
+    private Context mContext;
 
     private static final String APP_A = "com.app.a";
     private static final String APP_B = "com.app.b";
@@ -55,7 +55,7 @@ public class PackageWatchdogTest {
     @Before
     @UiThreadTest
     public void setUp() {
-        Context mContext = InstrumentationRegistry.getInstrumentation().getContext();
+        mContext = InstrumentationRegistry.getInstrumentation().getContext();
         mPackageWatchdog = PackageWatchdog.getInstance(mContext);
         mLatch1 = new CountDownLatch(1);
         mLatch2 = new CountDownLatch(1);
@@ -75,8 +75,8 @@ public class PackageWatchdogTest {
     public void testAppCrashIsMitigated() throws Exception {
         CountDownLatch latch = new CountDownLatch(1);
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1, latch);
-        mPackageWatchdog.registerHealthObserver(mTestObserver1);
-        mPackageWatchdog.startObservingHealth(
+        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(
                 mTestObserver1, List.of(APP_A), SHORT_DURATION);
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A,
                 VERSION_CODE)), PackageWatchdog.FAILURE_REASON_APP_CRASH);
@@ -89,7 +89,9 @@ public class PackageWatchdogTest {
     public void testAppCrashWithoutObserver() throws Exception {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1, mLatch1);
 
-        mPackageWatchdog.startObservingHealth(mTestObserver1, Arrays.asList(APP_A), SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
+                SHORT_DURATION);
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_B,
                 VERSION_CODE)), PackageWatchdog.FAILURE_REASON_APP_CRASH);
 
@@ -107,8 +109,11 @@ public class PackageWatchdogTest {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1, mLatch1);
         mTestObserver2 = new TestObserver(OBSERVER_NAME_2, mLatch2);
 
-        mPackageWatchdog.startObservingHealth(mTestObserver1, Arrays.asList(APP_A), SHORT_DURATION);
-        mPackageWatchdog.startObservingHealth(
+        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
+                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver2, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(
                 mTestObserver2, Arrays.asList(APP_A, APP_B), SHORT_DURATION);
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A, VERSION_CODE),
                 new VersionedPackage(APP_B, VERSION_CODE)),
@@ -131,8 +136,12 @@ public class PackageWatchdogTest {
     public void testUnregistration() throws Exception {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1);
         mTestObserver2 = new TestObserver(OBSERVER_NAME_2, mLatch2);
-        mPackageWatchdog.startObservingHealth(mTestObserver2, Arrays.asList(APP_A), SHORT_DURATION);
-        mPackageWatchdog.startObservingHealth(mTestObserver1, Arrays.asList(APP_A), SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver2, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver2, Arrays.asList(APP_A),
+                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
+                SHORT_DURATION);
 
         mPackageWatchdog.unregisterHealthObserver(mTestObserver1);
 
@@ -155,11 +164,15 @@ public class PackageWatchdogTest {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1);
         mTestObserver2 = new TestObserver(OBSERVER_NAME_2);
 
-        mPackageWatchdog.startObservingHealth(mTestObserver2, Arrays.asList(APP_A), SHORT_DURATION);
-        mPackageWatchdog.startObservingHealth(mTestObserver1, Arrays.asList(APP_A), SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver2, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver2, Arrays.asList(APP_A),
+                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
+                SHORT_DURATION);
 
         for (int i = 0; i < FAILURE_COUNT_THRESHOLD - 1; i++) {
-            mPackageWatchdog.onPackageFailure(Arrays.asList(
+            mPackageWatchdog.notifyPackageFailure(Arrays.asList(
                     new VersionedPackage(APP_A, VERSION_CODE)),
                     PackageWatchdog.FAILURE_REASON_UNKNOWN);
         }
@@ -178,7 +191,9 @@ public class PackageWatchdogTest {
         mLatch1 = new CountDownLatch(2);
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1, mLatch1);
 
-        mPackageWatchdog.startObservingHealth(mTestObserver1, Arrays.asList(APP_A), SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
+                SHORT_DURATION);
 
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A, VERSION_CODE)),
                 PackageWatchdog.FAILURE_REASON_EXPLICIT_HEALTH_CHECK);
@@ -200,7 +215,9 @@ public class PackageWatchdogTest {
 
         mTestObserver2 = new TestObserver(OBSERVER_NAME_2, mLatch2);
 
-        mPackageWatchdog.startObservingHealth(mTestObserver1, Arrays.asList(APP_B), SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_B),
+                SHORT_DURATION);
 
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A,
                 VERSION_CODE)), PackageWatchdog.FAILURE_REASON_APP_CRASH);
@@ -223,7 +240,9 @@ public class PackageWatchdogTest {
         mTestObserver1.setPersistent(true);
         mTestObserver1.setMayObservePackages(false);
 
-        mPackageWatchdog.startObservingHealth(mTestObserver1, Arrays.asList(APP_B), SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
+        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_B),
+                SHORT_DURATION);
 
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A,
                 VERSION_CODE)), PackageWatchdog.FAILURE_REASON_UNKNOWN);
@@ -237,7 +256,7 @@ public class PackageWatchdogTest {
             failureCount = 1;
         }
         for (int i = 0; i < failureCount; i++) {
-            mPackageWatchdog.onPackageFailure(failingPackages, failureReason);
+            mPackageWatchdog.notifyPackageFailure(failingPackages, failureReason);
         }
         try {
             // Wait for DEFAULT_MITIGATION_WINDOW_MS before applying another mitigation
@@ -274,8 +293,8 @@ public class PackageWatchdogTest {
             return mImpact;
         }
 
-        public boolean execute(VersionedPackage versionedPackage, int failureReason,
-                int mitigationCount) {
+        public boolean onExecuteHealthCheckMitigation(VersionedPackage versionedPackage,
+                int failureReason, int mitigationCount) {
             mMitigatedPackages.add(versionedPackage.getPackageName());
             mLatch.countDown();
             return true;
@@ -289,7 +308,7 @@ public class PackageWatchdogTest {
             return mImpact;
         }
 
-        public boolean executeBootLoopMitigation(int level) {
+        public boolean onExecuteBootLoopMitigation(int level) {
             return true;
         }
 
```

