```diff
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 946dd8b..50b264f 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -27,6 +27,7 @@
     <uses-permission android:name="com.google.android.setupwizard.SETUP_COMPAT_SERVICE"/>
 
     <application
+      android:enableOnBackInvokedCallback="false"
       android:networkSecurityConfig="@xml/network_security_config" >
 
         <activity
diff --git a/OWNERS b/OWNERS
index d07dd7f..99db2e3 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 seanjstsai@google.com
-mewan@google.com
 
 # Backup
 akaustubh@google.com
diff --git a/res/layout/fragment_webview.xml b/res/layout/fragment_webview.xml
index 0cede7d..d797d6e 100644
--- a/res/layout/fragment_webview.xml
+++ b/res/layout/fragment_webview.xml
@@ -18,7 +18,8 @@
 <!-- Layout for a full screen webview -->
 <RelativeLayout xmlns:android="http://schemas.android.com/apk/res/android"
                 android:layout_width="match_parent"
-                android:layout_height="match_parent">
+                android:layout_height="match_parent"
+                android:fitsSystemWindows="true">
 
     <WebView
         android:id="@+id/webview"
diff --git a/src/com/android/imsserviceentitlement/WfcActivationController.java b/src/com/android/imsserviceentitlement/WfcActivationController.java
index 4b65e46..ccf6015 100644
--- a/src/com/android/imsserviceentitlement/WfcActivationController.java
+++ b/src/com/android/imsserviceentitlement/WfcActivationController.java
@@ -31,7 +31,8 @@ import static com.android.imsserviceentitlement.ImsServiceEntitlementStatsLog.IM
 import android.app.Activity;
 import android.content.Context;
 import android.content.Intent;
-import android.os.CountDownTimer;
+import android.os.Handler;
+import android.os.Looper;
 import android.text.TextUtils;
 import android.util.Log;
 
@@ -70,6 +71,7 @@ public class WfcActivationController {
     private final Intent mStartIntent;
     private final MetricsLogger mMetricsLogger;
     private final Context mContext;
+    private final Handler mMainThreadHandler;
 
     // States
     private int mEvaluateTimes = 0;
@@ -88,6 +90,7 @@ public class WfcActivationController {
         this.mTelephonyUtils = new TelephonyUtils(context, getSubId());
         this.mImsUtils = ImsUtils.getInstance(context, getSubId());
         this.mMetricsLogger = new MetricsLogger(mTelephonyUtils);
+        this.mMainThreadHandler = new Handler(Looper.getMainLooper());
     }
 
     @VisibleForTesting
@@ -97,7 +100,8 @@ public class WfcActivationController {
             ImsEntitlementApi imsEntitlementApi,
             Intent intent,
             ImsUtils imsUtils,
-            MetricsLogger metricsLogger) {
+            MetricsLogger metricsLogger,
+            Handler handler) {
         this.mContext = context;
         this.mStartIntent = intent;
         this.mActivationUi = wfcActivationUi;
@@ -105,6 +109,7 @@ public class WfcActivationController {
         this.mTelephonyUtils = new TelephonyUtils(context, getSubId());
         this.mImsUtils = imsUtils;
         this.mMetricsLogger = metricsLogger;
+        this.mMainThreadHandler = handler;
     }
 
     /** Indicates the controller to start WFC activation or emergency address update flow. */
@@ -127,7 +132,9 @@ public class WfcActivationController {
             return;
         }
         EntitlementUtils.entitlementCheck(
-                mImsEntitlementApi, result -> handleInitialEntitlementStatus(result));
+                mImsEntitlementApi,
+                result -> mMainThreadHandler.post(
+                        () -> handleInitialEntitlementStatus(result)));
     }
 
     /**
@@ -144,7 +151,9 @@ public class WfcActivationController {
     @MainThread
     public void reevaluateEntitlementStatus() {
         EntitlementUtils.entitlementCheck(
-                mImsEntitlementApi, result -> handleReevaluationEntitlementStatus(result));
+                mImsEntitlementApi,
+                result -> mMainThreadHandler.post(
+                        () -> handleReevaluationEntitlementStatus(result)));
     }
 
     /** The interface for handling the entitlement check result. */
@@ -314,9 +323,9 @@ public class WfcActivationController {
                 // Check again after 5s, max retry 6 times
                 if (mEvaluateTimes < ENTITLEMENT_STATUS_UPDATE_RETRY_MAX) {
                     mEvaluateTimes += 1;
-                    postDelay(
-                            getEntitlementStatusUpdateRetryIntervalMs(),
-                            this::reevaluateEntitlementStatus);
+                    mMainThreadHandler.postDelayed(
+                            this::reevaluateEntitlementStatus,
+                            getEntitlementStatusUpdateRetryIntervalMs());
                 } else {
                     mEvaluateTimes = 0;
                     showGeneralErrorUi();
@@ -359,22 +368,6 @@ public class WfcActivationController {
         }
     }
 
-    /** Runs {@code action} on caller's thread after {@code delayMillis} ms. */
-    private static void postDelay(long delayMillis, Runnable action) {
-        new CountDownTimer(delayMillis, delayMillis + 100) {
-            // Use a countDownInterval bigger than millisInFuture so onTick never fires.
-            @Override
-            public void onTick(long millisUntilFinished) {
-                // Do nothing
-            }
-
-            @Override
-            public void onFinish() {
-                action.run();
-            }
-        }.start();
-    }
-
     private void finishStatsLog(int result) {
         mAppResult = result;
     }
diff --git a/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationControllerTest.java b/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationControllerTest.java
index b69127c..8599f5c 100644
--- a/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationControllerTest.java
+++ b/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationControllerTest.java
@@ -36,11 +36,16 @@ import android.content.Intent;
 import android.net.ConnectivityManager;
 import android.net.NetworkInfo;
 import android.os.PersistableBundle;
+import android.os.Handler;
+import android.os.HandlerThread;
+import android.os.Message;
+import android.os.TestLooperManager;
 import android.telephony.CarrierConfigManager;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
 
 import androidx.test.core.app.ApplicationProvider;
+import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.runner.AndroidJUnit4;
 
 import com.android.imsserviceentitlement.entitlement.EntitlementResult;
@@ -53,6 +58,7 @@ import com.android.imsserviceentitlement.utils.Executors;
 import com.android.imsserviceentitlement.utils.ImsUtils;
 import com.android.imsserviceentitlement.utils.MetricsLogger;
 
+import org.junit.After;
 import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
@@ -86,11 +92,21 @@ public class WfcActivationControllerTest {
     private WfcActivationController mWfcActivationController;
     private Context mContext;
     private PersistableBundle mCarrierConfig;
+    private TestLooperManager mTestLooperManager;
+    private Handler mUiHandler;
+    private HandlerThread mUiHandlerThread;
 
     @Before
     public void setUp() throws Exception {
         mContext = spy(ApplicationProvider.getApplicationContext());
 
+        mUiHandlerThread = new HandlerThread("MockUiThread");
+        mUiHandlerThread.start();
+        mUiHandler = new Handler(mUiHandlerThread.getLooper());
+        mTestLooperManager =
+                InstrumentationRegistry.getInstrumentation()
+                        .acquireLooperManager(mUiHandlerThread.getLooper());
+
         when(mContext.getSystemService(CarrierConfigManager.class))
                 .thenReturn(mMockCarrierConfigManager);
         when(mContext.getSystemService(TelephonyManager.class)).thenReturn(mMockTelephonyManager);
@@ -104,6 +120,12 @@ public class WfcActivationControllerTest {
         field.set(null, true);
     }
 
+    @After
+    public void tearDown() {
+        mTestLooperManager.release();
+        mUiHandlerThread.quit();
+    }
+
     @Test
     public void startFlow_launchAppForActivation_setPurposeActivation() {
         InOrder mOrderVerifier = inOrder(mMockActivationUi);
@@ -149,18 +171,7 @@ public class WfcActivationControllerTest {
     @Test
     public void finish_launchAppForActivateWithIsSkipWfcActivationTrue_notWriteMetrics() {
         setIsSkipWfcActivation(true);
-        Intent startIntent = new Intent(Intent.ACTION_MAIN);
-        startIntent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
-        startIntent.putExtra(
-                ActivityConstants.EXTRA_LAUNCH_CARRIER_APP, ActivityConstants.LAUNCH_APP_ACTIVATE);
-        mWfcActivationController =
-                new WfcActivationController(
-                        mContext,
-                        mMockActivationUi,
-                        mMockActivationApi,
-                        startIntent,
-                        mMockImsUtils,
-                        mMockMetricsLogger);
+        buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.finish();
 
@@ -170,18 +181,7 @@ public class WfcActivationControllerTest {
     @Test
     public void finish_launchAppForUpdateWithIsSkipWfcActivationTrue_writeMetrics() {
         setIsSkipWfcActivation(true);
-        Intent startIntent = new Intent(Intent.ACTION_MAIN);
-        startIntent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
-        startIntent.putExtra(
-                ActivityConstants.EXTRA_LAUNCH_CARRIER_APP, ActivityConstants.LAUNCH_APP_UPDATE);
-        mWfcActivationController =
-                new WfcActivationController(
-                        mContext,
-                        mMockActivationUi,
-                        mMockActivationApi,
-                        startIntent,
-                        mMockImsUtils,
-                        mMockMetricsLogger);
+        buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.finish();
 
@@ -190,18 +190,7 @@ public class WfcActivationControllerTest {
 
     @Test
     public void finish_launchAppForUpdateAndIsSkipWfcActivationFalse_writeMetrics() {
-        Intent startIntent = new Intent(Intent.ACTION_MAIN);
-        startIntent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
-        startIntent.putExtra(
-                ActivityConstants.EXTRA_LAUNCH_CARRIER_APP, ActivityConstants.LAUNCH_APP_UPDATE);
-        mWfcActivationController =
-                new WfcActivationController(
-                        mContext,
-                        mMockActivationUi,
-                        mMockActivationApi,
-                        startIntent,
-                        mMockImsUtils,
-                        mMockMetricsLogger);
+        buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.finish();
 
@@ -215,6 +204,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.finishFlow();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         mOrderVerifier
                 .verify(mMockActivationUi)
@@ -250,20 +240,10 @@ public class WfcActivationControllerTest {
                                                 .build())
                                 .build());
         setNetworkConnected(false);
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
-        intent.putExtra(ActivityConstants.EXTRA_LAUNCH_CARRIER_APP,
-                ActivityConstants.LAUNCH_APP_UPDATE);
-        mWfcActivationController =
-                new WfcActivationController(
-                        mContext,
-                        mMockActivationUi,
-                        mMockActivationApi,
-                        null,
-                        mMockImsUtils,
-                        mMockMetricsLogger);
+        buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.finishFlow();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockActivationUi).setResultAndFinish(eq(Activity.RESULT_OK));
     }
@@ -272,20 +252,10 @@ public class WfcActivationControllerTest {
     public void finish_startFlowForActivate_writeLoggerPurposeActivation() {
         when(mMockTelephonyManager.getSimCarrierId()).thenReturn(CARRIER_ID);
         when(mMockTelephonyManager.getSimSpecificCarrierId()).thenReturn(CARRIER_ID);
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
-        intent.putExtra(ActivityConstants.EXTRA_LAUNCH_CARRIER_APP,
-                ActivityConstants.LAUNCH_APP_ACTIVATE);
-        mWfcActivationController =
-                new WfcActivationController(
-                        mContext,
-                        mMockActivationUi,
-                        mMockActivationApi,
-                        intent,
-                        mMockImsUtils,
-                        mMockMetricsLogger);
+        buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.startFlow();
+        mTestLooperManager.execute(mTestLooperManager.next());
         mWfcActivationController.finish();
 
         verify(mMockMetricsLogger).start(eq(IMS_SERVICE_ENTITLEMENT_UPDATED__PURPOSE__ACTIVATION));
@@ -298,10 +268,6 @@ public class WfcActivationControllerTest {
     public void finish_entitlementResultWfcEntitled_writeLoggerAppResultSuccessful() {
         when(mMockTelephonyManager.getSimCarrierId()).thenReturn(CARRIER_ID);
         when(mMockTelephonyManager.getSimSpecificCarrierId()).thenReturn(CARRIER_ID);
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
-        intent.putExtra(ActivityConstants.EXTRA_LAUNCH_CARRIER_APP,
-                ActivityConstants.LAUNCH_APP_ACTIVATE);
         when(mMockActivationApi.checkEntitlementStatus())
                 .thenReturn(
                         EntitlementResult.builder(false)
@@ -313,16 +279,10 @@ public class WfcActivationControllerTest {
                                                 .setAddrStatus(AddrStatus.AVAILABLE)
                                                 .build())
                                 .build());
-        mWfcActivationController =
-                new WfcActivationController(
-                        mContext,
-                        mMockActivationUi,
-                        mMockActivationApi,
-                        intent,
-                        mMockImsUtils,
-                        mMockMetricsLogger);
+        buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.startFlow();
+        mTestLooperManager.execute(mTestLooperManager.next());
         mWfcActivationController.finish();
 
         verify(mMockMetricsLogger).start(eq(IMS_SERVICE_ENTITLEMENT_UPDATED__PURPOSE__ACTIVATION));
@@ -347,6 +307,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockActivationUi).setResultAndFinish(Activity.RESULT_OK);
     }
@@ -368,6 +329,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockActivationUi).showWebview(EMERGENCY_ADDRESS_WEB_URL,
                 EMERGENCY_ADDRESS_WEB_DATA);
@@ -389,6 +351,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockActivationUi).showWebview(EMERGENCY_ADDRESS_WEB_URL, null);
     }
@@ -406,6 +369,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verifyErrorUi(R.string.activate_title, R.string.failure_contact_carrier);
     }
@@ -425,6 +389,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verifyErrorUi(R.string.activate_title, R.string.wfc_activation_error);
     }
@@ -445,6 +410,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.reevaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockActivationUi).setResultAndFinish(Activity.RESULT_OK);
     }
@@ -464,6 +430,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_ACTIVATE);
 
         mWfcActivationController.reevaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verifyErrorUi(R.string.activate_title, R.string.wfc_activation_error);
     }
@@ -484,6 +451,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.reevaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockActivationUi).setResultAndFinish(eq(Activity.RESULT_OK));
     }
@@ -500,20 +468,10 @@ public class WfcActivationControllerTest {
                                         .build())
                         .build();
         when(mMockActivationApi.checkEntitlementStatus()).thenReturn(entitlementResult);
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
-        intent.putExtra(ActivityConstants.EXTRA_LAUNCH_CARRIER_APP,
-                ActivityConstants.LAUNCH_APP_UPDATE);
-        mWfcActivationController =
-                new WfcActivationController(
-                        mContext,
-                        mMockActivationUi,
-                        mMockActivationApi,
-                        intent,
-                        mMockImsUtils,
-                        mMockMetricsLogger);
+        buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.reevaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockImsUtils).turnOffWfc(any());
     }
@@ -533,6 +491,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.reevaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verifyErrorUi(R.string.e911_title, R.string.address_update_error);
     }
@@ -555,6 +514,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockActivationUi).showWebview(EMERGENCY_ADDRESS_WEB_URL,
                 EMERGENCY_ADDRESS_WEB_DATA);
@@ -577,6 +537,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_SHOW_TC);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verify(mMockActivationUi).showWebview(EMERGENCY_ADDRESS_WEB_URL, null);
     }
@@ -594,6 +555,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verifyErrorUi(R.string.e911_title, R.string.failure_contact_carrier);
     }
@@ -611,6 +573,7 @@ public class WfcActivationControllerTest {
         buildActivity(ActivityConstants.LAUNCH_APP_UPDATE);
 
         mWfcActivationController.evaluateEntitlementStatus();
+        mTestLooperManager.execute(mTestLooperManager.next());
 
         verifyErrorUi(R.string.e911_title, R.string.address_update_error);
     }
@@ -620,8 +583,14 @@ public class WfcActivationControllerTest {
         intent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
         intent.putExtra(ActivityConstants.EXTRA_LAUNCH_CARRIER_APP, extraLaunchCarrierApp);
         mWfcActivationController =
-                new WfcActivationController(mContext, mMockActivationUi, mMockActivationApi,
-                        intent);
+                new WfcActivationController(
+                        mContext,
+                        mMockActivationUi,
+                        mMockActivationApi,
+                        intent,
+                        mMockImsUtils,
+                        mMockMetricsLogger,
+                        mUiHandler);
     }
 
     private void setNetworkConnected(boolean isConnected) {
```

