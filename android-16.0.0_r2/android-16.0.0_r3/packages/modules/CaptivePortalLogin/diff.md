```diff
diff --git a/Android.bp b/Android.bp
index 799f302..551cd71 100644
--- a/Android.bp
+++ b/Android.bp
@@ -81,6 +81,10 @@ android_app {
     jarjar_rules: ":CaptivePortalLoginJarJarRules",
     certificate: "networkstack",
     updatable: true,
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 android_library {
diff --git a/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java b/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
index 96c0b27..25583c8 100755
--- a/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
+++ b/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java
@@ -289,6 +289,10 @@ public class CaptivePortalLoginActivity extends Activity {
                     // Don't hide the URL bar when scrolling down, to make sure the user is always
                     // aware they are on the page from a captive portal.
                     .setUrlBarHidingEnabled(false)
+                    // Remove the close button from tab.
+                    // TODO: remove above temporary workaround: setCloseButtonIcon with an empty
+                    // close button icon once all custom tabs provider support this API.
+                    .setCloseButtonEnabled(false)
                     .build();
 
             // Remove Referrer Header from HTTP probe packet by setting an empty Uri
@@ -594,7 +598,7 @@ public class CaptivePortalLoginActivity extends Activity {
     }
 
     @RequiresApi(Build.VERSION_CODES.S)
-    private boolean bypassVpnForCustomTabsProvider(
+    private boolean bypassVpnAndPrivateDnsForCustomTabsProvider(
             @NonNull final String customTabsProviderPackageName,
             @NonNull final OutcomeReceiver<Void, ServiceSpecificException> receiver) {
         final Class captivePortalClass = mCaptivePortal.getClass();
@@ -620,14 +624,6 @@ public class CaptivePortalLoginActivity extends Activity {
     private String getCustomTabsProviderPackageIfEnabled() {
         if (!mCaptivePortalCustomTabsEnabled) return null;
 
-        // TODO: b/330670424 - check if privacy settings such as private DNS is bypassable,
-        // otherwise, fallback to WebView.
-        final LinkProperties lp = mCm.getLinkProperties(mNetwork);
-        if (lp == null || lp.getPrivateDnsServerName() != null) {
-            Log.i(TAG, "Do not use custom tabs if private DNS (strict mode) is enabled");
-            return null;
-        }
-
         final String defaultPackage = getDefaultCustomTabsProviderPackage();
         if (null != defaultPackage && isMultiNetworkingSupportedByProvider(defaultPackage)) {
             return defaultPackage;
@@ -733,11 +729,10 @@ public class CaptivePortalLoginActivity extends Activity {
             } else {
                 mPersistentState.mServiceConnection =
                         new CaptivePortalCustomTabsServiceConnection(this);
-                // TODO: Fall back to WebView iff VPN is enabled and the custom tabs provider is not
-                // allowed to bypass VPN, e.g. an error or exception happens when calling the
-                // {@link CaptivePortal#setDelegateUid} API. Otherwise, force launch the custom tabs
-                // even if VPN cannot be bypassed.
-                final boolean success = bypassVpnForCustomTabsProvider(
+                // TODO: Fall back to WebView if the custom tabs provider is not allowed to
+                // bypass VPN or private DNS, e.g. an error or exception happens when calling
+                // the {@link CaptivePortal#setDelegateUid} API.
+                final boolean success = bypassVpnAndPrivateDnsForCustomTabsProvider(
                         customTabsProviderPackageName,
                         new OutcomeReceiver<Void, ServiceSpecificException>() {
                             // TODO: log the callback result metrics.
diff --git a/tests/AndroidTest.xml b/tests/AndroidTest.xml
index 1230df5..205958f 100644
--- a/tests/AndroidTest.xml
+++ b/tests/AndroidTest.xml
@@ -36,7 +36,5 @@
     <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
         <option name="pull-pattern-keys" value="android.device.collectors.ScreenshotOnFailureCollector.*\.png"/>
         <option name="pull-pattern-keys" value="com.android.testutils.ConnectivityDiagnosticsCollector.*"/>
-        <option name="directory-keys" value="/data/user/0/com.android.captiveportallogin.tests/files" />
-        <option name="collect-on-run-ended-only" value="false" />
     </metrics_collector>
 </configuration>
diff --git a/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java b/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
index 7688bfa..2e7efc9 100644
--- a/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
+++ b/tests/src/com/android/captiveportallogin/CaptivePortalLoginActivityTest.java
@@ -166,6 +166,7 @@ public class CaptivePortalLoginActivityTest {
     private static final String TEST_PORTAL_HOSTNAME = "localhost";
     private static final String TEST_CUSTOM_TABS_PACKAGE_NAME = "com.android.customtabs";
     private static final String TEST_WIFI_CONFIG_TYPE = "application/x-wifi-config";
+    private static final String TEST_PRIVATE_DNS_SERVER = "dns.server";
     private static final String TEST_DOWNLOAD_SERVICE_COMPONENT_CLASS_NAME =
             DownloadService.class.getName();
     private ActivityScenario<InstrumentedCaptivePortalLoginActivity> mActivityScenario;
@@ -594,6 +595,7 @@ public class CaptivePortalLoginActivityTest {
     }
 
     @Test @SdkSuppress(minSdkVersion = Build.VERSION_CODES.R)
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = false)
     public void testVpnMsgOrLinkToBrowser() throws Exception {
         // After Android R(including), DevicePolicyManager allows the caller who has the
         // PERMISSION_MAINLINE_NETWORK_STACK can call the isAlwaysOnVpnLockdownEnabled() to get the
@@ -1162,9 +1164,16 @@ public class CaptivePortalLoginActivityTest {
         server.stop();
     }
 
-    private void runCaptivePortalUsingCustomTabsTest(boolean isVpnBypassable) {
-        sIsMultiNetworkingSupportedByProvider = true;
+    private LinkProperties makeLinkPropertiesWithPrivateDns() {
         final LinkProperties linkProperties = new LinkProperties();
+        linkProperties.setUsePrivateDns(true);
+        linkProperties.setPrivateDnsServerName(TEST_PRIVATE_DNS_SERVER);
+        return linkProperties;
+    }
+
+    private void runCaptivePortalUsingCustomTabsTest(boolean isDelegateUidSetSuccessfully,
+            final LinkProperties linkProperties) {
+        sIsMultiNetworkingSupportedByProvider = true;
         doReturn(linkProperties).when(sConnectivityManager).getLinkProperties(mNetwork);
 
         // Set up result stubbing for the CustomTabsIntent#launchUrl, this stub should be
@@ -1175,15 +1184,13 @@ public class CaptivePortalLoginActivityTest {
                 .respondWith(new ActivityResult(RESULT_OK, null));
         initActivity(TEST_URL);
         final MockCaptivePortal cp = getCaptivePortal();
-        if (isVpnBypassable) {
+        if (isDelegateUidSetSuccessfully) {
             mActivityScenario.onActivity(a -> cp.mDelegateUidReceiver.onResult(null));
         } else {
             mActivityScenario.onActivity(a -> cp.mDelegateUidReceiver.onError(
                     new ServiceSpecificException(OsConstants.EBUSY)));
         }
 
-        // TODO: check the WebView should be initialized if VPN is not allowed to bypass. So far
-        // we force launch the custom tab even if VPN cannot be bypassed in production code.
         final ArgumentCaptor<CustomTabsCallback> captor =
                 ArgumentCaptor.forClass(CustomTabsCallback.class);
         verify(sMockCustomTabsClient, timeout(TEST_TIMEOUT_MS)).newSession(captor.capture());
@@ -1203,15 +1210,55 @@ public class CaptivePortalLoginActivityTest {
     @Test
     @IgnoreUpTo(Build.VERSION_CODES.R)
     @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
-    public void testCaptivePortalUsingCustomTabs() throws Exception {
-        runCaptivePortalUsingCustomTabsTest(true /* isVpnBypassable */);
+    public void testCaptivePortalUsingCustomTabs_privateDnsOn_bypassVpnOrPrivateDnsSuccess()
+            throws Exception {
+        final LinkProperties lp = makeLinkPropertiesWithPrivateDns();
+        runCaptivePortalUsingCustomTabsTest(true /* isDelegateUidSetSuccessfully */, lp);
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.R)
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_privateDnsOn_bypassVpnOrPrivateDnsFailure()
+            throws Exception {
+        final LinkProperties lp = makeLinkPropertiesWithPrivateDns();
+        runCaptivePortalUsingCustomTabsTest(false /* isDelegateUidSetSuccessfully */, lp);
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.R)
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_privateDnsOff_bypassVpnOrPrivateDnsSuccess()
+            throws Exception {
+        final LinkProperties lp = new LinkProperties();
+        runCaptivePortalUsingCustomTabsTest(true /* isDelegateUidSetSuccessfully */, lp);
     }
 
     @Test
     @IgnoreUpTo(Build.VERSION_CODES.R)
     @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
-    public void testCaptivePortalUsingCustomTabs_bypassVpnFailure() throws Exception {
-        runCaptivePortalUsingCustomTabsTest(false /* isVpnBypassable */);
+    public void testCaptivePortalUsingCustomTabs_privateDnsOff_bypassVpnOrPrivateDnsFailure()
+            throws Exception {
+        final LinkProperties lp = new LinkProperties();
+        runCaptivePortalUsingCustomTabsTest(false /* isDelegateUidSetSuccessfully */, lp);
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.R)
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_nullLinkProperties_bypassVpnOrPrivateDnsSuccess()
+            throws Exception {
+        runCaptivePortalUsingCustomTabsTest(true /* isDelegateUidSetSuccessfully */,
+                null /* LinkProperties */);
+    }
+
+    @Test
+    @IgnoreUpTo(Build.VERSION_CODES.R)
+    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
+    public void testCaptivePortalUsingCustomTabs_nullLinkProperties_bypassVpnOrPrivateDnsFailure()
+            throws Exception {
+        runCaptivePortalUsingCustomTabsTest(false /* isDelegateUidSetSuccessfully */,
+                null /* LinkProperties */);
     }
 
     private void verifyWebViewInitialization() {
@@ -1244,14 +1291,6 @@ public class CaptivePortalLoginActivityTest {
         verifyUsingWebViewRatherThanCustomTabs();
     }
 
-    @Test
-    @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
-    public void testCaptivePortalUsingCustomTabs_nullLinkProperties() throws Exception {
-        sIsMultiNetworkingSupportedByProvider = true;
-        doReturn(null).when(sConnectivityManager).getLinkProperties(mNetwork);
-        verifyUsingWebViewRatherThanCustomTabs();
-    }
-
     @Test
     @FeatureFlag(name = CAPTIVE_PORTAL_CUSTOM_TABS, enabled = true)
     public void testCaptivePortalUsingCustomTabs_multiNetworkNotSupported() throws Exception {
diff --git a/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt b/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
index f17944b..232679e 100644
--- a/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
+++ b/tests/src/com/android/captiveportallogin/DownloadServiceTest.kt
@@ -24,7 +24,6 @@ import android.content.ServiceConnection
 import android.content.res.Configuration
 import android.net.Network
 import android.net.Uri
-import android.os.Build
 import android.os.Bundle
 import android.os.IBinder
 import android.os.Parcel
@@ -32,7 +31,6 @@ import android.os.Parcelable
 import android.os.SystemClock
 import android.util.Log
 import android.widget.TextView
-import androidx.annotation.ChecksSdkIntAtLeast
 import androidx.core.content.FileProvider
 import androidx.test.core.app.ActivityScenario
 import androidx.test.ext.junit.runners.AndroidJUnit4
@@ -48,11 +46,6 @@ import androidx.test.uiautomator.Until
 import com.android.captiveportallogin.DownloadService.DOWNLOAD_ABORTED_REASON_FILE_TOO_LARGE
 import com.android.captiveportallogin.DownloadService.DownloadServiceBinder
 import com.android.captiveportallogin.DownloadService.ProgressCallback
-import com.android.modules.utils.build.SdkLevel.isAtLeastS
-import com.android.testutils.ConnectivityDiagnosticsCollector
-import com.android.testutils.DeviceInfoUtils
-import com.android.testutils.runCommandInRootShell
-import com.android.testutils.runCommandInShell
 import java.io.ByteArrayInputStream
 import java.io.File
 import java.io.FileInputStream
@@ -72,15 +65,11 @@ import kotlin.test.assertFalse
 import kotlin.test.assertNotEquals
 import kotlin.test.assertTrue
 import kotlin.test.fail
-import org.junit.AfterClass
 import org.junit.Assert.assertNotNull
 import org.junit.Assume.assumeFalse
 import org.junit.Before
-import org.junit.BeforeClass
 import org.junit.Rule
 import org.junit.Test
-import org.junit.rules.TestWatcher
-import org.junit.runner.Description
 import org.junit.runner.RunWith
 import org.mockito.Mockito.doReturn
 import org.mockito.Mockito.mock
@@ -126,65 +115,6 @@ val mServiceRule = ServiceTestRule()
 @RunWith(AndroidJUnit4::class)
 @SmallTest
 class DownloadServiceTest {
-    companion object {
-        private var originalTraceBufferSizeKb = 0
-
-        // To identify which process is deleting test files during the run (b/317602748), enable
-        // tracing for file deletion in f2fs (the filesystem used for /data on test devices) and
-        // process creation/exit
-        private const val tracePath = "/sys/kernel/tracing"
-        private val traceEnablePaths = listOf(
-            "$tracePath/events/f2fs/f2fs_unlink_enter",
-            "$tracePath/events/sched/sched_process_exec",
-            "$tracePath/events/sched/sched_process_fork",
-            "$tracePath/events/sched/sched_process_exit",
-            "$tracePath/tracing_on"
-        )
-
-        @JvmStatic
-        @BeforeClass
-        fun setUpClass() {
-            if (!enableTracing()) return
-            val originalSize = runCommandInShell("cat $tracePath/buffer_size_kb").trim()
-            // Buffer size may be small on boot when tracing is disabled, and automatically expanded
-            // when enabled (buffer_size_kb will report  something like: "7 (expanded: 1408)"). As
-            // only fixed values can be used when resetting, reset to the expanded size in that
-            // case.
-            val match = Regex("([0-9]+)|[0-9]+ \\(expanded: ([0-9]+)\\)")
-                .matchEntire(originalSize)
-                ?: fail("Could not parse original buffer size: $originalSize")
-            originalTraceBufferSizeKb = (match.groups[2]?.value ?: match.groups[1]?.value)?.toInt()
-                ?: fail("Buffer size not found in $originalSize")
-            traceEnablePaths.forEach {
-                runCommandInRootShell("echo 1 > $it")
-            }
-            runCommandInRootShell("echo 96000 > $tracePath/buffer_size_kb")
-        }
-
-        @JvmStatic
-        @AfterClass
-        fun tearDownClass() {
-            if (!enableTracing()) return
-            traceEnablePaths.asReversed().forEach {
-                runCommandInRootShell("echo 0 > $it")
-            }
-            runCommandInRootShell("echo $originalTraceBufferSizeKb > $tracePath/buffer_size_kb")
-        }
-
-        @ChecksSdkIntAtLeast(Build.VERSION_CODES.S)
-        fun enableTracing() = DeviceInfoUtils.isDebuggable() && isAtLeastS()
-    }
-
-    @get:Rule
-    val collectTraceOnFailureRule = object : TestWatcher() {
-        override fun failed(e: Throwable, description: Description) {
-            if (!enableTracing()) return
-            ConnectivityDiagnosticsCollector.instance?.let {
-                it.collectCommandOutput("su 0 cat $tracePath/trace")
-            }
-        }
-    }
-
     private val connection = mock(HttpURLConnection::class.java)
 
     private val context by lazy { getInstrumentation().context }
```

