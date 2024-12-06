```diff
diff --git a/hostsidetests/rollback/src/com/android/cts_root/rollback/host/WatchdogEventLogger.java b/hostsidetests/rollback/src/com/android/cts_root/rollback/host/WatchdogEventLogger.java
index 59eb027..6aaaf61 100644
--- a/hostsidetests/rollback/src/com/android/cts_root/rollback/host/WatchdogEventLogger.java
+++ b/hostsidetests/rollback/src/com/android/cts_root/rollback/host/WatchdogEventLogger.java
@@ -19,46 +19,36 @@ package com.android.cts_root.rollback.host;
 import static com.google.common.truth.Truth.assertThat;
 
 import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
 
 import com.google.common.truth.FailureMetadata;
 import com.google.common.truth.Truth;
 
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+
 public class WatchdogEventLogger {
-    private static final String[] ROLLBACK_EVENT_TYPES = {
-            "ROLLBACK_INITIATE", "ROLLBACK_BOOT_TRIGGERED", "ROLLBACK_SUCCESS"};
-    private static final String[] ROLLBACK_EVENT_ATTRS = {
-            "logPackage", "rollbackReason", "failedPackageName"};
-    private static final String PROP_PREFIX = "persist.sys.rollbacktest.";
 
     private ITestDevice mDevice;
 
-    private void resetProperties(boolean enabled) throws Exception {
+    private void updateTestSysProp(boolean enabled) throws Exception {
         assertThat(mDevice.setProperty(
-                PROP_PREFIX + "enabled", String.valueOf(enabled))).isTrue();
-        for (String type : ROLLBACK_EVENT_TYPES) {
-            String key = PROP_PREFIX + type;
-            assertThat(mDevice.setProperty(key, "")).isTrue();
-            for (String attr : ROLLBACK_EVENT_ATTRS) {
-                assertThat(mDevice.setProperty(key + "." + attr, "")).isTrue();
-            }
-        }
+                "persist.sys.rollbacktest.enabled", String.valueOf(enabled))).isTrue();
     }
 
     public void start(ITestDevice device) throws Exception {
         mDevice = device;
-        resetProperties(true);
+        updateTestSysProp(true);
     }
 
     public void stop() throws Exception {
         if (mDevice != null) {
-            resetProperties(false);
+            updateTestSysProp(false);
         }
     }
 
-    private boolean matchProperty(String type, String attr, String expectedVal) throws Exception {
-        String key = PROP_PREFIX + type + "." + attr;
-        String val = mDevice.getProperty(key);
-        return expectedVal == null || expectedVal.equals(val);
+    private boolean verifyEventContainsVal(String watchdogEvent, String expectedVal) {
+        return expectedVal == null || watchdogEvent.contains(expectedVal);
     }
 
     /**
@@ -68,11 +58,33 @@ public class WatchdogEventLogger {
      * occurred, and return {@code true} if an event exists which matches all criteria.
      */
     public boolean watchdogEventOccurred(String type, String logPackage,
-            String rollbackReason, String failedPackageName) throws Exception {
-        return mDevice.getBooleanProperty(PROP_PREFIX + type, false)
-                && matchProperty(type, "logPackage", logPackage)
-                && matchProperty(type, "rollbackReason", rollbackReason)
-                && matchProperty(type, "failedPackageName", failedPackageName);
+            String rollbackReason, String failedPackageName) {
+        String watchdogEvent = getEventForRollbackType(type);
+        return (watchdogEvent != null)
+                && verifyEventContainsVal(watchdogEvent, logPackage)
+                && verifyEventContainsVal(watchdogEvent, rollbackReason)
+                && verifyEventContainsVal(watchdogEvent, failedPackageName);
+    }
+
+    /** Returns last matched event for rollbackType **/
+    private String getEventForRollbackType(String rollbackType) {
+        String lastMatchedEvent = null;
+        try {
+            String rollbackDump = mDevice.executeShellCommand("dumpsys rollback");
+            String eventRegex = ".*%s%s(.*)\\n";
+            String eventPrefix = "Watchdog event occurred with type: ";
+
+            final Pattern pattern = Pattern.compile(
+                    String.format(eventRegex, eventPrefix, rollbackType));
+            final Matcher matcher = pattern.matcher(rollbackDump);
+            while (matcher.find()) {
+                lastMatchedEvent = matcher.group(1);
+            }
+            CLog.d("Found watchdogEvent: " + lastMatchedEvent + " for type: " + rollbackType);
+        } catch (Exception e) {
+            CLog.e("Unable to find event for type: " + rollbackType, e);
+        }
+        return lastMatchedEvent;
     }
 
     static class Subject extends com.google.common.truth.Subject {
@@ -93,7 +105,7 @@ public class WatchdogEventLogger {
         }
 
         void eventOccurred(String type, String logPackage, String rollbackReason,
-                String failedPackageName) throws Exception {
+                String failedPackageName) {
             check("watchdogEventOccurred(type=%s, logPackage=%s, rollbackReason=%s, "
                     + "failedPackageName=%s)", type, logPackage, rollbackReason, failedPackageName)
                     .that(mActual.watchdogEventOccurred(type, logPackage, rollbackReason,
diff --git a/tests/bluetooth/Android.bp b/tests/bluetooth/Android.bp
index 211031f..bdd14dd 100644
--- a/tests/bluetooth/Android.bp
+++ b/tests/bluetooth/Android.bp
@@ -28,8 +28,8 @@ android_test {
         "statsd-helper",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
         "statsdprotonano",
     ],
     srcs: ["src/**/*.java"],
diff --git a/tests/bugreport/Android.bp b/tests/bugreport/Android.bp
index ef82e1e..7c70fef 100644
--- a/tests/bugreport/Android.bp
+++ b/tests/bugreport/Android.bp
@@ -26,8 +26,8 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.test",
+        "android.test.base.stubs.test",
         "device_policy_aconfig_flags_lib",
     ],
     data: [":ctsroot-bugreport-artifacts"],
diff --git a/tests/input/Android.bp b/tests/input/Android.bp
new file mode 100644
index 0000000..52c94d5
--- /dev/null
+++ b/tests/input/Android.bp
@@ -0,0 +1,57 @@
+// Copyright 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_input_framework",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+android_test {
+    name: "CtsInputRootTestCases",
+    defaults: ["cts_defaults"],
+    // Tag this module as a cts test artifact
+    test_suites: [
+        "cts_root",
+        "general-tests",
+    ],
+
+    compile_multilib: "both",
+    kotlincflags: [
+        "-Werror",
+    ],
+    srcs: [
+        "src/**/*.kt",
+    ],
+    asset_dirs: ["assets"],
+    static_libs: [
+        "cts-input-lib",
+        "CtsVirtualDeviceCommonLib",
+        "android.view.flags-aconfig-java",
+        "androidx.test.core",
+        "androidx.test.ext.junit",
+        "bedstead-root-annotations",
+        "com.android.hardware.input-aconfig-java",
+        "com.android.input.flags-aconfig-java",
+        "compatibility-device-util-axt",
+        "cts-input-lib",
+        "cts-wm-util",
+        "flag-junit",
+        "kotlin-test",
+        "ui-trace-collector",
+        "collector-device-lib",
+        "platform-screenshot-diff-core",
+    ],
+    sdk_version: "test_current",
+    per_testcase_directory: true,
+}
diff --git a/tests/input/AndroidManifest.xml b/tests/input/AndroidManifest.xml
new file mode 100644
index 0000000..47b55be
--- /dev/null
+++ b/tests/input/AndroidManifest.xml
@@ -0,0 +1,34 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+ * Copyright 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ -->
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="android.input.cts_root">
+    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
+    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
+    <application android:label="InputTest"
+                 android:requestLegacyExternalStorage="true">
+        <activity android:name="android.input.cts_root.CaptureEventActivity"
+                  android:label="Capture events"
+                  android:configChanges="touchscreen|uiMode|orientation|screenSize|screenLayout|keyboardHidden|uiMode|navigation|keyboard|density|fontScale|layoutDirection|locale|mcc|mnc|smallestScreenSize"
+                  android:enableOnBackInvokedCallback="false"
+                  android:turnScreenOn="true"
+                  android:exported="true">
+        </activity>
+    </application>
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+         android:targetPackage="android.input.cts_root"
+         android:label="Tests for input APIs and behaviours.">
+    </instrumentation>
+</manifest>
diff --git a/tests/input/AndroidTest.xml b/tests/input/AndroidTest.xml
new file mode 100644
index 0000000..fa5797e
--- /dev/null
+++ b/tests/input/AndroidTest.xml
@@ -0,0 +1,63 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Config for CTS-root input test cases">
+    <option name="test-suite-tag" value="cts_root" />
+    <option name="config-descriptor:metadata" key="component" value="framework" />
+    <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
+    <option name="config-descriptor:metadata" key="parameter" value="multi_abi" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="all_foldable_states" />
+    <option name="config-descriptor:metadata" key="parameter" value="run_on_sdk_sandbox" />
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true" />
+        <option name="test-file-name" value="CtsInputRootTestCases.apk" />
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest" >
+        <option name="package" value="android.input.cts_root" />
+        <option name="runtime-hint" value="14s" />
+        <!-- test-timeout unit is ms, value = 10 min -->
+        <option name="test-timeout" value="600000" />
+        <option name="device-listeners" value="android.device.collectors.ScreenshotOnFailureCollector"/>
+        <option name="device-listeners" value="android.tools.collectors.DefaultUITraceListener"/>
+        <!-- DefaultUITraceListener args -->
+        <option name="instrumentation-arg" key="skip_test_success_metrics" value="true"/>
+    </test>
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <!-- TODO(b/285554134): Remove once underlying issue is fixed-->
+        <option name="run-command" value="wm set-ignore-orientation-request false" />
+        <option name="run-command" value="wm set-letterbox-style --isEducationEnabled false" />
+        <!-- Unlock screen -->
+        <option name="run-command" value="input keyevent KEYCODE_WAKEUP" />
+        <!-- Dismiss keyguard, in case it's set as "Swipe to unlock" -->
+        <option name="run-command" value="wm dismiss-keyguard" />
+        <!-- Collapse notifications -->
+        <option name="run-command" value="cmd statusbar collapse" />
+        <!-- dismiss all system dialogs before launch test -->
+        <option name="run-command" value="am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS" />
+    </target_preparer>
+    <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
+        <option name="pull-pattern-keys" value="input_.*" />
+        <!-- Pull perfetto traces from DefaultUITraceListener -->
+        <option name="pull-pattern-keys" value="perfetto_file_path*" />
+        <!-- Pull screenshot on test failure -->
+        <option name="pull-pattern-keys"
+            value="android.device.collectors.ScreenshotOnFailureCollector.*\.png" />
+        <!-- Pull files created by tests, like the output of screenshot tests -->
+        <option name="directory-keys" value="/sdcard/Download/CtsInputRootTestCases" />
+        <option name="collect-on-run-ended-only" value="false" />
+    </metrics_collector>
+</configuration>
diff --git a/tests/input/OWNERS b/tests/input/OWNERS
new file mode 100644
index 0000000..21d208f
--- /dev/null
+++ b/tests/input/OWNERS
@@ -0,0 +1,2 @@
+# Bug component: 136048
+include platform/frameworks/base:/INPUT_OWNERS
diff --git a/tests/input/TEST_MAPPING b/tests/input/TEST_MAPPING
new file mode 100644
index 0000000..cb36f58
--- /dev/null
+++ b/tests/input/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "CtsInputRootTestCases"
+    }
+  ]
+}
diff --git a/tests/input/assets/testHidePointerIconOnSecureWindowScreenshot_DRAWING_TABLET_expected.png b/tests/input/assets/testHidePointerIconOnSecureWindowScreenshot_DRAWING_TABLET_expected.png
new file mode 100644
index 0000000..2774392
Binary files /dev/null and b/tests/input/assets/testHidePointerIconOnSecureWindowScreenshot_DRAWING_TABLET_expected.png differ
diff --git a/tests/input/assets/testHidePointerIconOnSecureWindowScreenshot_MOUSE_expected.png b/tests/input/assets/testHidePointerIconOnSecureWindowScreenshot_MOUSE_expected.png
new file mode 100644
index 0000000..2774392
Binary files /dev/null and b/tests/input/assets/testHidePointerIconOnSecureWindowScreenshot_MOUSE_expected.png differ
diff --git a/tests/input/src/android/input/cts_root/CaptureEventActivity.kt b/tests/input/src/android/input/cts_root/CaptureEventActivity.kt
new file mode 100644
index 0000000..246e6af
--- /dev/null
+++ b/tests/input/src/android/input/cts_root/CaptureEventActivity.kt
@@ -0,0 +1,52 @@
+/*
+ * Copyright 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.input.cts_root
+
+import android.app.Activity
+import android.view.InputEvent
+import android.view.KeyEvent
+import android.view.MotionEvent
+import java.util.concurrent.LinkedBlockingQueue
+import java.util.concurrent.TimeUnit
+
+class CaptureEventActivity : Activity() {
+    private val events = LinkedBlockingQueue<InputEvent>()
+
+    override fun dispatchGenericMotionEvent(ev: MotionEvent?): Boolean {
+        events.add(MotionEvent.obtain(ev))
+        return true
+    }
+
+    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
+        events.add(MotionEvent.obtain(ev))
+        return true
+    }
+
+    override fun dispatchKeyEvent(event: KeyEvent?): Boolean {
+        events.add(KeyEvent(event))
+        return true
+    }
+
+    override fun dispatchTrackballEvent(ev: MotionEvent?): Boolean {
+        events.add(MotionEvent.obtain(ev))
+        return true
+    }
+
+    fun getInputEvent(): InputEvent? {
+        return events.poll(5, TimeUnit.SECONDS)
+    }
+}
diff --git a/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt b/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
new file mode 100644
index 0000000..471084b
--- /dev/null
+++ b/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
@@ -0,0 +1,167 @@
+/*
+ * Copyright 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+package android.input.cts_root
+
+import android.cts.input.EventVerifier
+import android.graphics.Bitmap
+import android.graphics.Color
+import android.os.SystemProperties
+import android.platform.test.annotations.EnableFlags
+import android.view.MotionEvent
+import android.view.WindowManager
+import android.virtualdevice.cts.common.FakeAssociationRule
+import androidx.test.filters.MediumTest
+import androidx.test.platform.app.InstrumentationRegistry
+import com.android.cts.input.DefaultPointerSpeedRule
+import com.android.cts.input.TestPointerDevice
+import com.android.cts.input.VirtualDisplayActivityScenario
+import com.android.cts.input.inputeventmatchers.withMotionAction
+import com.android.input.flags.Flags
+import com.android.xts.root.annotations.RequireAdbRoot
+import org.junit.After
+import org.junit.Before
+import org.junit.Rule
+import org.junit.Test
+import org.junit.rules.TestName
+import org.junit.runner.RunWith
+import org.junit.runners.Parameterized
+import org.junit.runners.Parameterized.Parameter
+import platform.test.screenshot.GoldenPathManager
+import platform.test.screenshot.PathConfig
+import platform.test.screenshot.ScreenshotTestRule
+import platform.test.screenshot.assertAgainstGolden
+import platform.test.screenshot.matchers.AlmostPerfectMatcher
+import platform.test.screenshot.matchers.BitmapMatcher
+import kotlin.test.assertNotNull
+import org.junit.Ignore
+
+/**
+ * End-to-end tests for the hiding pointer icons of screenshots of secure displays
+ *
+ * We use a secure virtual display to launch the test activity, and use virtual Input devices to
+ * move the pointer for it to show up. We then take a screenshot of the display to ensure the icon
+ * does not shows up on screenshot. We use the virtual display to be able to precisely compare the
+ * screenshots across devices of various form factors and sizes.
+ *
+ * Following tests must be run as root as they require CAPTURE_SECURE_VIDEO_OUTPUT permission
+ * override which can only be done by root.
+ */
+@MediumTest
+@RunWith(Parameterized::class)
+@RequireAdbRoot
+class HidePointerIconOnSecureWindowScreenshotTest {
+    private lateinit var activity: CaptureEventActivity
+    private lateinit var verifier: EventVerifier
+    private lateinit var exactScreenshotMatcher: BitmapMatcher
+
+    @get:Rule
+    val testName = TestName()
+    @get:Rule
+    val virtualDisplayRule = VirtualDisplayActivityScenario.Rule<CaptureEventActivity>(
+        testName,
+        useSecureDisplay = true,
+    )
+    @get:Rule
+    val fakeAssociationRule = FakeAssociationRule()
+    @get:Rule
+    val defaultPointerSpeedRule = DefaultPointerSpeedRule()
+    @get:Rule
+    val screenshotRule = ScreenshotTestRule(GoldenPathManager(
+        InstrumentationRegistry.getInstrumentation().context,
+        ASSETS_PATH,
+        TEST_OUTPUT_PATH,
+        PathConfig()
+    ), disableIconPool = false)
+
+    @Parameter(0)
+    lateinit var device: TestPointerDevice
+
+    @Before
+    fun setUp() {
+        val context = InstrumentationRegistry.getInstrumentation().targetContext
+        activity = virtualDisplayRule.activity
+        activity.runOnUiThread {
+            activity.actionBar?.hide()
+            activity.window.decorView.rootView.setBackgroundColor(Color.WHITE)
+            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
+        }
+
+        device.setUp(
+            context,
+            virtualDisplayRule.virtualDisplay.display,
+            fakeAssociationRule.associationInfo,
+        )
+
+        verifier = EventVerifier(activity::getInputEvent)
+
+        exactScreenshotMatcher =
+            AlmostPerfectMatcher(acceptableThresholdCount = MAX_PIXELS_DIFFERENT)
+    }
+
+    @After
+    fun tearDown() {
+        device.tearDown()
+    }
+
+    @Ignore("b/366475909")
+    @Test
+    @EnableFlags(Flags.FLAG_HIDE_POINTER_INDICATORS_FOR_SECURE_WINDOWS)
+    fun testHidePointerIconOnSecureWindowScreenshot() {
+        device.hoverMove(1, 1)
+        verifier.assertReceivedMotion(withMotionAction(MotionEvent.ACTION_HOVER_ENTER))
+        waitForPointerIconUpdate()
+
+        assertScreenshotsMatch()
+    }
+
+    private fun getActualScreenshot(): Bitmap {
+        val actualBitmap: Bitmap? = virtualDisplayRule.getScreenshot()
+        assertNotNull(actualBitmap, "Screenshot is null.")
+        return actualBitmap
+    }
+
+    private fun assertScreenshotsMatch() {
+        getActualScreenshot().assertAgainstGolden(
+            screenshotRule,
+            getParameterizedExpectedScreenshotName(),
+            exactScreenshotMatcher
+        )
+    }
+
+    private fun getParameterizedExpectedScreenshotName(): String {
+        // Replace illegal characters '[' and ']' in expected screenshot name with underscores.
+        return "${testName.methodName}expected".replace("""\[|\]""".toRegex(), "_")
+    }
+
+    // We don't have a way to synchronously know when the requested pointer icon has been drawn
+    // to the display, so wait some time (at least one display frame) for the icon to propagate.
+    private fun waitForPointerIconUpdate() = Thread.sleep(500L * HW_TIMEOUT_MULTIPLIER)
+
+    companion object {
+        const val MAX_PIXELS_DIFFERENT = 5
+        const val ASSETS_PATH = "tests/input/assets"
+        val TEST_OUTPUT_PATH =
+            "/sdcard/Download/CtsInputRootTestCases/" +
+            HidePointerIconOnSecureWindowScreenshotTest::class.java.simpleName
+        val HW_TIMEOUT_MULTIPLIER = SystemProperties.getInt("ro.hw_timeout_multiplier", 1);
+
+        @JvmStatic
+        @Parameterized.Parameters(name = "{0}")
+        fun data(): Iterable<Any> =
+            listOf(TestPointerDevice.MOUSE, TestPointerDevice.DRAWING_TABLET)
+    }
+}
diff --git a/tests/packagemanagerlocal/Android.bp b/tests/packagemanagerlocal/Android.bp
index 55e7861..0202f4e 100644
--- a/tests/packagemanagerlocal/Android.bp
+++ b/tests/packagemanagerlocal/Android.bp
@@ -28,8 +28,8 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.test",
+        "android.test.base.stubs.test",
     ],
     srcs: ["src/**/*.java"],
     test_suites: [
diff --git a/tests/packagewatchdog/Android.bp b/tests/packagewatchdog/Android.bp
index ab1b9bc..6bc2d6c 100644
--- a/tests/packagewatchdog/Android.bp
+++ b/tests/packagewatchdog/Android.bp
@@ -28,8 +28,8 @@ android_test {
         "platform-test-annotations",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.test",
+        "android.test.base.stubs.test",
     ],
     srcs: ["src/**/*.java"],
     test_suites: [
diff --git a/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java b/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
index 3d5ae6b..503b5c0 100644
--- a/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
+++ b/tests/packagewatchdog/src/android/packagewatchdog/cts_root/PackageWatchdogTest.java
@@ -281,7 +281,7 @@ public class PackageWatchdogTest {
             return true;
         }
 
-        public String getName() {
+        public String getUniqueIdentifier() {
             return mName;
         }
 
@@ -309,4 +309,4 @@ public class PackageWatchdogTest {
             mMayObservePackages = mayObservePackages;
         }
     }
-}
\ No newline at end of file
+}
diff --git a/tests/permission/Android.bp b/tests/permission/Android.bp
index 17b290c..fd69606 100644
--- a/tests/permission/Android.bp
+++ b/tests/permission/Android.bp
@@ -24,8 +24,8 @@ android_test {
         ":CtsRootPermissionSignaturePermissionAllowlistNormalApp",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
         "bedstead-root-annotations",
     ],
     min_sdk_version: "30",
diff --git a/tests/stats/Android.bp b/tests/stats/Android.bp
index dcbb4e3..2567075 100644
--- a/tests/stats/Android.bp
+++ b/tests/stats/Android.bp
@@ -13,7 +13,7 @@
 // limitations under the License.
 
 package {
-    default_team: "trendy_team_android_telemetry_infra",
+    default_team: "trendy_team_android_telemetry_client_infra",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -35,8 +35,8 @@ android_test {
         "platform-test-annotations",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.test",
+        "android.test.base.stubs.test",
     ],
     srcs: ["src/**/*.java"],
     test_suites: [
diff --git a/tests/usage/Android.bp b/tests/usage/Android.bp
index 5936bc4..7bd028b 100644
--- a/tests/usage/Android.bp
+++ b/tests/usage/Android.bp
@@ -28,8 +28,8 @@ android_test {
         "truth",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
+        "android.test.runner.stubs.test",
+        "android.test.base.stubs.test",
         "services.core",
         "services.usage",
     ],
```

