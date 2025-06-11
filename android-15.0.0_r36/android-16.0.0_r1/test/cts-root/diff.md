```diff
diff --git a/tests/bluetooth/Android.bp b/tests/bluetooth/Android.bp
index bdd14dd..ccb5125 100644
--- a/tests/bluetooth/Android.bp
+++ b/tests/bluetooth/Android.bp
@@ -40,6 +40,7 @@ android_test {
         "cts_root",
         "general-tests",
         "mts-bluetooth",
+        "mts-bt",
     ],
     min_sdk_version: "UpsideDownCake",
 }
diff --git a/tests/bluetooth/AndroidTest.xml b/tests/bluetooth/AndroidTest.xml
index 87be477..97bf9d8 100644
--- a/tests/bluetooth/AndroidTest.xml
+++ b/tests/bluetooth/AndroidTest.xml
@@ -46,7 +46,7 @@
     <!-- Only run Cts Tests in MTS if the Bluetooth Mainline module is installed. -->
     <object type="module_controller"
             class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
-        <option name="mainline-module-package-name" value="com.android.btservices" />
-        <option name="mainline-module-package-name" value="com.google.android.btservices" />
+        <option name="mainline-module-package-name" value="com.android.bt" />
+        <option name="mainline-module-package-name" value="com.google.android.bt" />
     </object>
 </configuration>
diff --git a/tests/bluetooth/OWNERS b/tests/bluetooth/OWNERS
index f5f3106..8719a0c 100644
--- a/tests/bluetooth/OWNERS
+++ b/tests/bluetooth/OWNERS
@@ -2,4 +2,3 @@ siyuanh@google.com
 muhammadfalam@google.com
 sattiraju@google.com
 girardier@google.com
-sungsoo@google.com
diff --git a/tests/bugreport/Android.bp b/tests/bugreport/Android.bp
index 7c70fef..8758bda 100644
--- a/tests/bugreport/Android.bp
+++ b/tests/bugreport/Android.bp
@@ -24,11 +24,11 @@ android_test {
         "androidx.test.uiautomator_uiautomator",
         "compatibility-device-util-axt",
         "truth",
+        "device_policy_aconfig_flags_lib",
     ],
     libs: [
         "android.test.runner.stubs.test",
         "android.test.base.stubs.test",
-        "device_policy_aconfig_flags_lib",
     ],
     data: [":ctsroot-bugreport-artifacts"],
     srcs: ["src/**/*.java"],
diff --git a/tests/bugreport/src/android/bugreport/cts_root/BugreportManagerTest.java b/tests/bugreport/src/android/bugreport/cts_root/BugreportManagerTest.java
index 53f351d..5de28a7 100644
--- a/tests/bugreport/src/android/bugreport/cts_root/BugreportManagerTest.java
+++ b/tests/bugreport/src/android/bugreport/cts_root/BugreportManagerTest.java
@@ -48,6 +48,7 @@ import androidx.test.uiautomator.UiDevice;
 import androidx.test.uiautomator.UiObject2;
 import androidx.test.uiautomator.Until;
 
+import com.android.compatibility.common.util.ShellIdentityUtils;
 import com.android.compatibility.common.util.SystemUtil;
 
 import org.junit.AfterClass;
@@ -76,6 +77,7 @@ public class BugreportManagerTest {
 
     private Context mContext;
     private BugreportManager mBugreportManager;
+    private Method mGetServiceMethod;
 
     @Rule
     public TestName name = new TestName();
@@ -95,9 +97,10 @@ public class BugreportManagerTest {
     public void setup() throws Exception {
         mContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
         mBugreportManager = mContext.getSystemService(BugreportManager.class);
+        mGetServiceMethod = Class.forName("android.os.ServiceManager").getMethod(
+            "getService", String.class);
         ensureNoConsentDialogShown();
 
-
         // Unlock before finding/clicking an object.
         final UiDevice device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
         device.wakeUp();
@@ -396,6 +399,7 @@ public class BugreportManagerTest {
         mBugreportManager.startBugreport(parcelFd(bugreportFile), null,
                 new BugreportParams(BugreportParams.BUGREPORT_MODE_ONBOARDING, 0),
                 mContext.getMainExecutor(), callback);
+        callback.waitForUiReady();
         if (!skipConsent) {
             shareConsentDialog(ConsentReply.ALLOW);
         }
@@ -507,6 +511,7 @@ public class BugreportManagerTest {
         private boolean mSuccess = false;
         private String mBugreportFile;
         private final Object mLock = new Object();
+        private final CountDownLatch mUiReadyLatch = new CountDownLatch(1);
 
         private final CountDownLatch mLatch;
 
@@ -522,6 +527,20 @@ public class BugreportManagerTest {
             }
         }
 
+        @Override
+        public void onEarlyReportFinished() {
+            mUiReadyLatch.countDown();
+        }
+
+        /**
+         * Wait for onEarlyReportFinished to be called. If this invocation of
+         * startBugreport requires user consent, the dialog will show then;
+         * otherwise, it won't.
+         */
+        public void waitForUiReady() throws Exception {
+            mUiReadyLatch.await(30, TimeUnit.SECONDS);
+        }
+
         @Override
         public void onFinished(String bugreportFile) {
             synchronized (mLock) {
@@ -614,21 +633,30 @@ public class BugreportManagerTest {
 
 
     /** Waits for the dumpstate service to stop, for up to 5 seconds. */
+    private boolean isDumpstateServiceStopped() throws Exception {
+        // If getService() returns null, the service has stopped.
+        return ShellIdentityUtils.invokeMethodWithShellPermissions(mGetServiceMethod, (m) -> {
+            try {
+                return m.invoke(null, "dumpstate");
+            } catch (Exception e) {
+                return null;
+            }
+        }) == null;
+    }
+
     private void waitForDumpstateServiceToStop() throws Exception {
         int pollingIntervalMillis = 100;
-        Method method = Class.forName("android.os.ServiceManager").getMethod(
-                "getService", String.class);
+
         for (int i = 0; i < 10; i++) {
             int numPolls = 50;
             while (numPolls-- > 0) {
-                // If getService() returns null, the service has stopped.
-                if (method.invoke(null, "dumpstate") == null) {
+                if (isDumpstateServiceStopped()) {
                     break;
                 }
                 Thread.sleep(pollingIntervalMillis);
             }
         }
-        if (method.invoke(null, "dumpstate") == null) {
+        if (isDumpstateServiceStopped()) {
             return;
         }
         fail("Dumpstate did not stop within 25 seconds");
diff --git a/tests/input/AndroidManifest.xml b/tests/input/AndroidManifest.xml
index 5f2ae83..c33361b 100644
--- a/tests/input/AndroidManifest.xml
+++ b/tests/input/AndroidManifest.xml
@@ -17,11 +17,9 @@
 <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="android.input.cts_root">
     <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
     <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
-    <uses-permission android:name="android.permission.CREATE_VIRTUAL_DEVICE" />
-    <uses-permission android:name="android.permission.ADD_TRUSTED_DISPLAY" />
     <application android:label="InputTest"
                  android:requestLegacyExternalStorage="true">
-        <activity android:name="android.input.cts_root.CaptureEventActivity"
+        <activity android:name="com.android.cts.input.CaptureEventActivity"
                   android:label="Capture events"
                   android:configChanges="touchscreen|uiMode|orientation|screenSize|screenLayout|keyboardHidden|uiMode|navigation|keyboard|density|fontScale|layoutDirection|locale|mcc|mnc|smallestScreenSize"
                   android:enableOnBackInvokedCallback="false"
diff --git a/tests/input/src/android/input/cts_root/CaptureEventActivity.kt b/tests/input/src/android/input/cts_root/CaptureEventActivity.kt
deleted file mode 100644
index 246e6af..0000000
--- a/tests/input/src/android/input/cts_root/CaptureEventActivity.kt
+++ /dev/null
@@ -1,52 +0,0 @@
-/*
- * Copyright 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package android.input.cts_root
-
-import android.app.Activity
-import android.view.InputEvent
-import android.view.KeyEvent
-import android.view.MotionEvent
-import java.util.concurrent.LinkedBlockingQueue
-import java.util.concurrent.TimeUnit
-
-class CaptureEventActivity : Activity() {
-    private val events = LinkedBlockingQueue<InputEvent>()
-
-    override fun dispatchGenericMotionEvent(ev: MotionEvent?): Boolean {
-        events.add(MotionEvent.obtain(ev))
-        return true
-    }
-
-    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
-        events.add(MotionEvent.obtain(ev))
-        return true
-    }
-
-    override fun dispatchKeyEvent(event: KeyEvent?): Boolean {
-        events.add(KeyEvent(event))
-        return true
-    }
-
-    override fun dispatchTrackballEvent(ev: MotionEvent?): Boolean {
-        events.add(MotionEvent.obtain(ev))
-        return true
-    }
-
-    fun getInputEvent(): InputEvent? {
-        return events.poll(5, TimeUnit.SECONDS)
-    }
-}
diff --git a/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt b/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
index d907f41..a6d9427 100644
--- a/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
+++ b/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
@@ -20,20 +20,20 @@ import android.cts.input.EventVerifier
 import android.graphics.Bitmap
 import android.graphics.Color
 import android.os.SystemProperties
-import android.platform.test.annotations.EnableFlags
 import android.view.MotionEvent
 import android.view.WindowManager
 import android.virtualdevice.cts.common.VirtualDeviceRule
 import androidx.test.filters.MediumTest
 import androidx.test.platform.app.InstrumentationRegistry
+import com.android.cts.input.CaptureEventActivity
 import com.android.cts.input.DefaultPointerSpeedRule
 import com.android.cts.input.TestPointerDevice
 import com.android.cts.input.VirtualDisplayActivityScenario
 import com.android.cts.input.inputeventmatchers.withMotionAction
-import com.android.input.flags.Flags
 import com.android.xts.root.annotations.RequireAdbRoot
 import org.junit.After
 import org.junit.Before
+import org.junit.Ignore
 import org.junit.Rule
 import org.junit.Test
 import org.junit.rules.TestName
@@ -47,7 +47,6 @@ import platform.test.screenshot.assertAgainstGolden
 import platform.test.screenshot.matchers.AlmostPerfectMatcher
 import platform.test.screenshot.matchers.BitmapMatcher
 import kotlin.test.assertNotNull
-import org.junit.Ignore
 
 /**
  * End-to-end tests for the hiding pointer icons of screenshots of secure displays
@@ -119,7 +118,6 @@ class HidePointerIconOnSecureWindowScreenshotTest {
 
     @Ignore("b/366475909")
     @Test
-    @EnableFlags(Flags.FLAG_HIDE_POINTER_INDICATORS_FOR_SECURE_WINDOWS)
     fun testHidePointerIconOnSecureWindowScreenshot() {
         device.hoverMove(1, 1)
         verifier.assertReceivedMotion(withMotionAction(MotionEvent.ACTION_HOVER_ENTER))
diff --git a/tests/packagewatchdog/Android.bp b/tests/packagewatchdog/Android.bp
index 3cbb333..05787e1 100644
--- a/tests/packagewatchdog/Android.bp
+++ b/tests/packagewatchdog/Android.bp
@@ -39,4 +39,5 @@ android_test {
         "mts-crashrecovery",
     ],
     sdk_version: "system_server_current",
+    min_sdk_version: "36",
 }
diff --git a/tests/packagewatchdog/OWNERS b/tests/packagewatchdog/OWNERS
index b929d27..86b12cd 100644
--- a/tests/packagewatchdog/OWNERS
+++ b/tests/packagewatchdog/OWNERS
@@ -1,4 +1,3 @@
 # Bug component: 1306443
-ancr@google.com
 harshitmahajan@google.com
 wangchun@google.com
\ No newline at end of file
diff --git a/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java b/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
index fc0c3e8..9715f71 100644
--- a/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
+++ b/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
@@ -16,6 +16,8 @@
 
 package android.packagewatchdog.cts;
 
+import static com.android.server.PackageWatchdog.MITIGATION_RESULT_SUCCESS;
+
 import static com.google.common.truth.Truth.assertThat;
 
 import android.content.Context;
@@ -28,6 +30,7 @@ import com.android.server.PackageWatchdog;
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Test;
 
 import java.util.ArrayList;
@@ -75,9 +78,8 @@ public class PackageWatchdogTest {
     public void testAppCrashIsMitigated() throws Exception {
         CountDownLatch latch = new CountDownLatch(1);
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1, latch);
-        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(
-                mTestObserver1, List.of(APP_A), SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver1);
+        mPackageWatchdog.startExplicitHealthCheck(List.of(APP_A), SHORT_DURATION, mTestObserver1);
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A,
                 VERSION_CODE)), PackageWatchdog.FAILURE_REASON_APP_CRASH);
         assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
@@ -89,9 +91,9 @@ public class PackageWatchdogTest {
     public void testAppCrashWithoutObserver() throws Exception {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1, mLatch1);
 
-        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
-                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver1);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_A), SHORT_DURATION,
+                mTestObserver1);
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_B,
                 VERSION_CODE)), PackageWatchdog.FAILURE_REASON_APP_CRASH);
 
@@ -109,12 +111,12 @@ public class PackageWatchdogTest {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1, mLatch1);
         mTestObserver2 = new TestObserver(OBSERVER_NAME_2, mLatch2);
 
-        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
-                SHORT_DURATION);
-        mPackageWatchdog.registerHealthObserver(mTestObserver2, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(
-                mTestObserver2, Arrays.asList(APP_A, APP_B), SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver1);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_A), SHORT_DURATION,
+                mTestObserver1);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver2);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_A, APP_B), SHORT_DURATION,
+                mTestObserver2);
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A, VERSION_CODE),
                 new VersionedPackage(APP_B, VERSION_CODE)),
                 PackageWatchdog.FAILURE_REASON_APP_CRASH);
@@ -133,15 +135,16 @@ public class PackageWatchdogTest {
      * observed.
      */
     @Test
+    @Ignore("b/354112511")
     public void testUnregistration() throws Exception {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1);
         mTestObserver2 = new TestObserver(OBSERVER_NAME_2, mLatch2);
-        mPackageWatchdog.registerHealthObserver(mTestObserver2, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver2, Arrays.asList(APP_A),
-                SHORT_DURATION);
-        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
-                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver2);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_A), SHORT_DURATION,
+                mTestObserver2);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver1);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_A), SHORT_DURATION,
+                mTestObserver1);
 
         mPackageWatchdog.unregisterHealthObserver(mTestObserver1);
 
@@ -164,12 +167,12 @@ public class PackageWatchdogTest {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1);
         mTestObserver2 = new TestObserver(OBSERVER_NAME_2);
 
-        mPackageWatchdog.registerHealthObserver(mTestObserver2, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver2, Arrays.asList(APP_A),
-                SHORT_DURATION);
-        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
-                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver2);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_A), SHORT_DURATION,
+                mTestObserver2);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver1);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_A), SHORT_DURATION,
+                mTestObserver1);
 
         for (int i = 0; i < FAILURE_COUNT_THRESHOLD - 1; i++) {
             mPackageWatchdog.notifyPackageFailure(Arrays.asList(
@@ -187,13 +190,14 @@ public class PackageWatchdogTest {
 
     /** Test that observers execute correctly for failures reasons that skip thresholding. */
     @Test
+    @Ignore("b/354112511")
     public void testImmediateFailures() throws Exception {
         mLatch1 = new CountDownLatch(2);
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1, mLatch1);
 
-        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_A),
-                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver1);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_A), SHORT_DURATION,
+                mTestObserver1);
 
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A, VERSION_CODE)),
                 PackageWatchdog.FAILURE_REASON_EXPLICIT_HEALTH_CHECK);
@@ -215,9 +219,9 @@ public class PackageWatchdogTest {
 
         mTestObserver2 = new TestObserver(OBSERVER_NAME_2, mLatch2);
 
-        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_B),
-                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver1);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_B), SHORT_DURATION,
+                mTestObserver1);
 
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A,
                 VERSION_CODE)), PackageWatchdog.FAILURE_REASON_APP_CRASH);
@@ -235,14 +239,15 @@ public class PackageWatchdogTest {
      * a given package.
      */
     @Test
+    @Ignore("b/354112511")
     public void testPersistentObserverDoesNotWatchPackage() {
         mTestObserver1 = new TestObserver(OBSERVER_NAME_1);
         mTestObserver1.setPersistent(true);
         mTestObserver1.setMayObservePackages(false);
 
-        mPackageWatchdog.registerHealthObserver(mTestObserver1, mContext.getMainExecutor());
-        mPackageWatchdog.startExplicitHealthCheck(mTestObserver1, Arrays.asList(APP_B),
-                SHORT_DURATION);
+        mPackageWatchdog.registerHealthObserver(mContext.getMainExecutor(), mTestObserver1);
+        mPackageWatchdog.startExplicitHealthCheck(Arrays.asList(APP_B), SHORT_DURATION,
+                mTestObserver1);
 
         raiseFatalFailure(Arrays.asList(new VersionedPackage(APP_A,
                 VERSION_CODE)), PackageWatchdog.FAILURE_REASON_UNKNOWN);
@@ -269,7 +274,7 @@ public class PackageWatchdogTest {
     private static class TestObserver implements PackageWatchdog.PackageHealthObserver {
         private final String mName;
         private final int mImpact;
-        private boolean mIsPersistent = false;
+        private boolean mIsPersistent = true;
         private boolean mMayObservePackages = false;
         final List<String> mMitigatedPackages = new ArrayList<>();
         final List<String> mHealthCheckFailedPackages = new ArrayList<>();
@@ -293,11 +298,11 @@ public class PackageWatchdogTest {
             return mImpact;
         }
 
-        public boolean onExecuteHealthCheckMitigation(VersionedPackage versionedPackage,
+        public int onExecuteHealthCheckMitigation(VersionedPackage versionedPackage,
                 int failureReason, int mitigationCount) {
             mMitigatedPackages.add(versionedPackage.getPackageName());
             mLatch.countDown();
-            return true;
+            return MITIGATION_RESULT_SUCCESS;
         }
 
         public String getUniqueIdentifier() {
@@ -308,8 +313,8 @@ public class PackageWatchdogTest {
             return mImpact;
         }
 
-        public boolean onExecuteBootLoopMitigation(int level) {
-            return true;
+        public int onExecuteBootLoopMitigation(int level) {
+            return MITIGATION_RESULT_SUCCESS;
         }
 
         public boolean isPersistent() {
```

