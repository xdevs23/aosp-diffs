```diff
diff --git a/packagemanager/.gitignore b/packagemanager/.gitignore
new file mode 100644
index 0000000..95f8fda
--- /dev/null
+++ b/packagemanager/.gitignore
@@ -0,0 +1,16 @@
+*.pyc
+*.*~
+*.py~
+.cproject
+/bin
+.idea/*
+.idea/
+.project
+.vscode/
+gen/
+*.iml
+*.class
+*.sw*
+
+# Jars added by Idea's "Konfigure kotlin in project" action
+**/lib/kotlin-*.jar
diff --git a/packagemanager/OWNERS b/packagemanager/OWNERS
new file mode 100644
index 0000000..a370d8a
--- /dev/null
+++ b/packagemanager/OWNERS
@@ -0,0 +1,2 @@
+# Bug component: 36137
+include platform/frameworks/base:/PACKAGE_MANAGER_OWNERS
diff --git a/tests/bugreport/OWNERS b/tests/bugreport/OWNERS
index 0819864..844685a 100644
--- a/tests/bugreport/OWNERS
+++ b/tests/bugreport/OWNERS
@@ -1,3 +1,3 @@
 # Bug component: 153446
-ronish@google.com
+himanshuz@google.com
 nandana@google.com
diff --git a/tests/input/AndroidTest.xml b/tests/input/AndroidTest.xml
index fa5797e..bb4e2a3 100644
--- a/tests/input/AndroidTest.xml
+++ b/tests/input/AndroidTest.xml
@@ -52,7 +52,7 @@
     <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
         <option name="pull-pattern-keys" value="input_.*" />
         <!-- Pull perfetto traces from DefaultUITraceListener -->
-        <option name="pull-pattern-keys" value="perfetto_file_path*" />
+        <option name="pull-pattern-keys" value="perfetto_file_path" />
         <!-- Pull screenshot on test failure -->
         <option name="pull-pattern-keys"
             value="android.device.collectors.ScreenshotOnFailureCollector.*\.png" />
diff --git a/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt b/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
index a6d9427..fc7de7b 100644
--- a/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
+++ b/tests/input/src/android/input/cts_root/HidePointerIconOnSecureWindowScreenshotTest.kt
@@ -16,7 +16,6 @@
 
 package android.input.cts_root
 
-import android.cts.input.EventVerifier
 import android.graphics.Bitmap
 import android.graphics.Color
 import android.os.SystemProperties
@@ -25,12 +24,14 @@ import android.view.WindowManager
 import android.virtualdevice.cts.common.VirtualDeviceRule
 import androidx.test.filters.MediumTest
 import androidx.test.platform.app.InstrumentationRegistry
+import com.android.cts.input.BlockingQueueEventVerifier
 import com.android.cts.input.CaptureEventActivity
 import com.android.cts.input.DefaultPointerSpeedRule
 import com.android.cts.input.TestPointerDevice
 import com.android.cts.input.VirtualDisplayActivityScenario
 import com.android.cts.input.inputeventmatchers.withMotionAction
 import com.android.xts.root.annotations.RequireAdbRoot
+import kotlin.test.assertNotNull
 import org.junit.After
 import org.junit.Before
 import org.junit.Ignore
@@ -46,7 +47,6 @@ import platform.test.screenshot.ScreenshotTestRule
 import platform.test.screenshot.assertAgainstGolden
 import platform.test.screenshot.matchers.AlmostPerfectMatcher
 import platform.test.screenshot.matchers.BitmapMatcher
-import kotlin.test.assertNotNull
 
 /**
  * End-to-end tests for the hiding pointer icons of screenshots of secure displays
@@ -64,7 +64,7 @@ import kotlin.test.assertNotNull
 @RequireAdbRoot
 class HidePointerIconOnSecureWindowScreenshotTest {
     private lateinit var activity: CaptureEventActivity
-    private lateinit var verifier: EventVerifier
+    private lateinit var verifier: BlockingQueueEventVerifier
     private lateinit var exactScreenshotMatcher: BitmapMatcher
 
     @get:Rule
@@ -105,7 +105,7 @@ class HidePointerIconOnSecureWindowScreenshotTest {
             virtualDisplayRule.virtualDisplay.display,
         )
 
-        verifier = EventVerifier(activity::getInputEvent)
+        verifier = activity.verifier
 
         exactScreenshotMatcher =
             AlmostPerfectMatcher(acceptableThresholdCount = MAX_PIXELS_DIFFERENT)
diff --git a/tests/stats/OWNERS b/tests/stats/OWNERS
index efd3686..bb6a08d 100644
--- a/tests/stats/OWNERS
+++ b/tests/stats/OWNERS
@@ -1,7 +1,6 @@
 jeffreyhuang@google.com
 monicamwang@google.com
 muhammadq@google.com
-rayhdez@google.com
 sharaienko@google.com
 singhtejinder@google.com
 tsaichristine@google.com
```

