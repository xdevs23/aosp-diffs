```diff
diff --git a/src/com/android/imsserviceentitlement/WfcActivationActivity.java b/src/com/android/imsserviceentitlement/WfcActivationActivity.java
index f384362..aadf999 100644
--- a/src/com/android/imsserviceentitlement/WfcActivationActivity.java
+++ b/src/com/android/imsserviceentitlement/WfcActivationActivity.java
@@ -16,6 +16,7 @@
 
 package com.android.imsserviceentitlement;
 
+import android.app.Activity;
 import android.content.Intent;
 import android.os.Bundle;
 import android.os.SystemProperties;
@@ -34,6 +35,8 @@ public class WfcActivationActivity extends FragmentActivity implements WfcActiva
     private static final String TAG = "IMSSE-WfcActivationActivity";
 
     // Dependencies
+    @SuppressWarnings("StaticFieldLeak")
+    private static WfcActivationController sWfcActivationController;
     private WfcActivationController mWfcActivationController;
     private WfcWebPortalFragment mWfcWebPortalFragment;
 
@@ -45,7 +48,13 @@ public class WfcActivationActivity extends FragmentActivity implements WfcActiva
         super.onCreate(savedInstanceState);
         setContentView(R.layout.activity_wfc_activation);
 
-        int subId = ActivityConstants.getSubId(getIntent());
+        if (mWfcActivationController.isSkipWfcActivation()
+                && ActivityConstants.isActivationFlow(getIntent())) {
+            Log.d(TAG, "Skip wfc activation");
+            setResultAndFinish(Activity.RESULT_OK);
+            return;
+        }
+
         mWfcActivationController.startFlow();
     }
 
@@ -140,7 +149,7 @@ public class WfcActivationActivity extends FragmentActivity implements WfcActiva
     private void createDependeny() {
         Log.d(TAG, "Loading dependencies...");
         // TODO(b/177495634) Use DependencyInjector
-        if (mWfcActivationController == null) {
+        if (sWfcActivationController == null) {
             // Default initialization
             Log.d(TAG, "Default WfcActivationController initialization");
             Intent startIntent = this.getIntent();
@@ -150,7 +159,9 @@ public class WfcActivationActivity extends FragmentActivity implements WfcActiva
                             /* context = */ this,
                             /* wfcActivationUi = */ this,
                             new ImsEntitlementApi(this, subId),
-                            this.getIntent());
+                            startIntent);
+        } else {
+            mWfcActivationController = sWfcActivationController;
         }
     }
 }
diff --git a/src/com/android/imsserviceentitlement/WfcActivationController.java b/src/com/android/imsserviceentitlement/WfcActivationController.java
index 6bcd9ec..4b65e46 100644
--- a/src/com/android/imsserviceentitlement/WfcActivationController.java
+++ b/src/com/android/imsserviceentitlement/WfcActivationController.java
@@ -69,6 +69,7 @@ public class WfcActivationController {
     private final ImsUtils mImsUtils;
     private final Intent mStartIntent;
     private final MetricsLogger mMetricsLogger;
+    private final Context mContext;
 
     // States
     private int mEvaluateTimes = 0;
@@ -80,6 +81,7 @@ public class WfcActivationController {
             WfcActivationUi wfcActivationUi,
             ImsEntitlementApi imsEntitlementApi,
             Intent intent) {
+        this.mContext = context;
         this.mStartIntent = intent;
         this.mActivationUi = wfcActivationUi;
         this.mImsEntitlementApi = imsEntitlementApi;
@@ -96,6 +98,7 @@ public class WfcActivationController {
             Intent intent,
             ImsUtils imsUtils,
             MetricsLogger metricsLogger) {
+        this.mContext = context;
         this.mStartIntent = intent;
         this.mActivationUi = wfcActivationUi;
         this.mImsEntitlementApi = imsEntitlementApi;
@@ -154,6 +157,9 @@ public class WfcActivationController {
     public void finish() {
         EntitlementUtils.cancelEntitlementCheck();
 
+        if (isSkipWfcActivation() && isActivationFlow()) {
+            return;
+        }
         // If no result set, it must be cancelled by user pressing back button.
         if (mAppResult == IMS_SERVICE_ENTITLEMENT_UPDATED__APP_RESULT__UNKNOWN_RESULT) {
             mAppResult = IMS_SERVICE_ENTITLEMENT_UPDATED__APP_RESULT__CANCELED;
@@ -329,6 +335,10 @@ public class WfcActivationController {
         return ENTITLEMENT_STATUS_UPDATE_RETRY_INTERVAL_MS;
     }
 
+    public boolean isSkipWfcActivation() {
+        return TelephonyUtils.isSkipWfcActivation(mContext, getSubId());
+    }
+
     @MainThread
     private void handleEntitlementStatusAfterUpdating(EntitlementResult result) {
         Ts43VowifiStatus vowifiStatus = result.getVowifiStatus();
diff --git a/src/com/android/imsserviceentitlement/utils/TelephonyUtils.java b/src/com/android/imsserviceentitlement/utils/TelephonyUtils.java
index 5306b26..1a39c11 100644
--- a/src/com/android/imsserviceentitlement/utils/TelephonyUtils.java
+++ b/src/com/android/imsserviceentitlement/utils/TelephonyUtils.java
@@ -40,6 +40,8 @@ public class TelephonyUtils {
             "imsserviceentitlement.entitlement_version_int";
     private static final String KEY_DEFAULT_SERVICE_ENTITLEMENT_STATUS_BOOL =
             "imsserviceentitlement.default_service_entitlement_status_bool";
+    private static final String KEY_SKIP_WFC_ACTIVATION_BOOL =
+            "imsserviceentitlement.skip_wfc_activation_bool";
 
     private final ConnectivityManager mConnectivityManager;
     private final TelephonyManager mTelephonyManager;
@@ -172,6 +174,14 @@ public class TelephonyUtils {
         );
     }
 
+    /** Returns true if app can skip wfc activation and support emergency address update only. */
+    public static boolean isSkipWfcActivation(Context context, int subId) {
+        return getConfigForSubId(context, subId).getBoolean(
+                KEY_SKIP_WFC_ACTIVATION_BOOL,
+                false
+        );
+    }
+
     /**
      * Returns default service entitlement status for the {@code subId} or false if it is not
      * available.
diff --git a/tests/unittests/AndroidManifest.xml b/tests/unittests/AndroidManifest.xml
index be8024f..6ef1fbf 100644
--- a/tests/unittests/AndroidManifest.xml
+++ b/tests/unittests/AndroidManifest.xml
@@ -14,7 +14,8 @@
      limitations under the License.
 -->
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.android.imsserviceentitlement.tests">
+    package="com.android.imsserviceentitlement">
+
     <application>
         <uses-library android:name="android.test.runner" />
     </application>
diff --git a/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationActivityTest.java b/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationActivityTest.java
new file mode 100644
index 0000000..3755c10
--- /dev/null
+++ b/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationActivityTest.java
@@ -0,0 +1,134 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.imsserviceentitlement;
+
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+import android.content.Intent;
+import android.telephony.SubscriptionManager;
+import android.testing.AndroidTestingRunner;
+import android.util.Log;
+
+import androidx.test.core.app.ActivityScenario;
+import androidx.test.core.app.ApplicationProvider;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.Spy;
+import org.mockito.junit.MockitoJUnit;
+import org.mockito.junit.MockitoRule;
+
+import java.lang.reflect.Field;
+
+@RunWith(AndroidTestingRunner.class)
+public final class WfcActivationActivityTest {
+    @Rule public final MockitoRule mockito = MockitoJUnit.rule();
+
+    private static final String TAG = "IMSSE-WfcActivationActivityTest";
+    private static final int SUB_ID = 1;
+    private static final String EXTRA_LAUNCH_CARRIER_APP = "EXTRA_LAUNCH_CARRIER_APP";
+    private static final int LAUNCH_APP_ACTIVATE = 0;
+    private static final int LAUNCH_APP_UPDATE = 1;
+
+    @Mock private WfcActivationController mMockWfcActivationController;
+
+    private final Context mAppContext = ApplicationProvider.getApplicationContext();
+    private ActivityScenario<WfcActivationActivity> mActivityScenario;
+
+    @Before
+    public void setUp() {
+        when(mMockWfcActivationController.isSkipWfcActivation()).thenReturn(false);
+    }
+
+    @After
+    public void tearDown() {
+        if (mActivityScenario != null) {
+            mActivityScenario.close();
+        }
+    }
+
+    @Test
+    public void launchAppForActivate_isSkipWfcActivationTrue_notDoStartFlow() {
+        when(mMockWfcActivationController.isSkipWfcActivation()).thenReturn(true);
+        Intent launchIntent =
+                new Intent(mAppContext, WfcActivationActivity.class)
+                        .putExtra(EXTRA_LAUNCH_CARRIER_APP, LAUNCH_APP_ACTIVATE)
+                        .putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
+        mockWfcActivationController(mMockWfcActivationController);
+
+        mActivityScenario = ActivityScenario.launch(launchIntent);
+
+        verify(mMockWfcActivationController, never()).startFlow();
+    }
+
+    @Test
+    public void launchAppForActivate_isSkipWfcActivationFalse_doStartFlow() {
+        Intent launchIntent =
+                new Intent(mAppContext, WfcActivationActivity.class)
+                        .putExtra(EXTRA_LAUNCH_CARRIER_APP, LAUNCH_APP_ACTIVATE)
+                        .putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
+        mockWfcActivationController(mMockWfcActivationController);
+
+        mActivityScenario = ActivityScenario.launch(launchIntent);
+
+        verify(mMockWfcActivationController).startFlow();
+    }
+
+    @Test
+    public void launchAppForUpdate_isSkipWfcActivationTrue_doStartFlow() {
+        when(mMockWfcActivationController.isSkipWfcActivation()).thenReturn(true);
+        Intent launchIntent =
+                new Intent(mAppContext, WfcActivationActivity.class)
+                        .putExtra(EXTRA_LAUNCH_CARRIER_APP, LAUNCH_APP_UPDATE)
+                        .putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
+        mockWfcActivationController(mMockWfcActivationController);
+
+        mActivityScenario = ActivityScenario.launch(launchIntent);
+
+        verify(mMockWfcActivationController).startFlow();
+    }
+
+    @Test
+    public void launchAppForUpdate_isSkipWfcActivationFalse_doStartFlow() {
+        Intent launchIntent =
+                new Intent(mAppContext, WfcActivationActivity.class)
+                        .putExtra(EXTRA_LAUNCH_CARRIER_APP, LAUNCH_APP_UPDATE)
+                        .putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
+        mockWfcActivationController(mMockWfcActivationController);
+
+        mActivityScenario = ActivityScenario.launch(launchIntent);
+
+        verify(mMockWfcActivationController).startFlow();
+    }
+
+    private void mockWfcActivationController(WfcActivationController mockWfcActivationController) {
+        try {
+            Field field = WfcActivationActivity.class.getDeclaredField("sWfcActivationController");
+            field.setAccessible(true);
+            field.set(null, mockWfcActivationController);
+        } catch (Exception e) {
+            Log.d(TAG, "Mocking WfcActivationController failed.");
+        }
+    }
+}
\ No newline at end of file
diff --git a/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationControllerTest.java b/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationControllerTest.java
index b986f54..b69127c 100644
--- a/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationControllerTest.java
+++ b/tests/unittests/src/com/android/imsserviceentitlement/WfcActivationControllerTest.java
@@ -22,8 +22,10 @@ import static com.android.imsserviceentitlement.ImsServiceEntitlementStatsLog.IM
 import static com.android.imsserviceentitlement.ImsServiceEntitlementStatsLog.IMS_SERVICE_ENTITLEMENT_UPDATED__SERVICE_TYPE__VOWIFI;
 
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.inOrder;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
@@ -33,6 +35,8 @@ import android.content.Context;
 import android.content.Intent;
 import android.net.ConnectivityManager;
 import android.net.NetworkInfo;
+import android.os.PersistableBundle;
+import android.telephony.CarrierConfigManager;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
 
@@ -70,23 +74,30 @@ public class WfcActivationControllerTest {
     @Mock private NetworkInfo mMockNetworkInfo;
     @Mock private ImsUtils mMockImsUtils;
     @Mock private MetricsLogger mMockMetricsLogger;
+    @Mock private CarrierConfigManager mMockCarrierConfigManager;
 
     private static final int SUB_ID = 1;
     private static final int CARRIER_ID = 1234;
     private static final String EMERGENCY_ADDRESS_WEB_URL = "webUrl";
     private static final String EMERGENCY_ADDRESS_WEB_DATA = "webData";
+    private static final String KEY_SKIP_WFC_ACTIVATION_BOOL =
+            "imsserviceentitlement.skip_wfc_activation_bool";
 
     private WfcActivationController mWfcActivationController;
     private Context mContext;
+    private PersistableBundle mCarrierConfig;
 
     @Before
     public void setUp() throws Exception {
         mContext = spy(ApplicationProvider.getApplicationContext());
 
+        when(mContext.getSystemService(CarrierConfigManager.class))
+                .thenReturn(mMockCarrierConfigManager);
         when(mContext.getSystemService(TelephonyManager.class)).thenReturn(mMockTelephonyManager);
         when(mMockTelephonyManager.createForSubscriptionId(SUB_ID)).thenReturn(
                 mMockTelephonyManager);
         setNetworkConnected(true);
+        setIsSkipWfcActivation(false);
 
         Field field = Executors.class.getDeclaredField("sUseDirectExecutorForTest");
         field.setAccessible(true);
@@ -135,6 +146,68 @@ public class WfcActivationControllerTest {
                 R.string.show_terms_and_condition_error);
     }
 
+    @Test
+    public void finish_launchAppForActivateWithIsSkipWfcActivationTrue_notWriteMetrics() {
+        setIsSkipWfcActivation(true);
+        Intent startIntent = new Intent(Intent.ACTION_MAIN);
+        startIntent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
+        startIntent.putExtra(
+                ActivityConstants.EXTRA_LAUNCH_CARRIER_APP, ActivityConstants.LAUNCH_APP_ACTIVATE);
+        mWfcActivationController =
+                new WfcActivationController(
+                        mContext,
+                        mMockActivationUi,
+                        mMockActivationApi,
+                        startIntent,
+                        mMockImsUtils,
+                        mMockMetricsLogger);
+
+        mWfcActivationController.finish();
+
+        verify(mMockMetricsLogger, never()).write(anyInt(), anyInt());
+    }
+
+    @Test
+    public void finish_launchAppForUpdateWithIsSkipWfcActivationTrue_writeMetrics() {
+        setIsSkipWfcActivation(true);
+        Intent startIntent = new Intent(Intent.ACTION_MAIN);
+        startIntent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
+        startIntent.putExtra(
+                ActivityConstants.EXTRA_LAUNCH_CARRIER_APP, ActivityConstants.LAUNCH_APP_UPDATE);
+        mWfcActivationController =
+                new WfcActivationController(
+                        mContext,
+                        mMockActivationUi,
+                        mMockActivationApi,
+                        startIntent,
+                        mMockImsUtils,
+                        mMockMetricsLogger);
+
+        mWfcActivationController.finish();
+
+        verify(mMockMetricsLogger).write(anyInt(), anyInt());
+    }
+
+    @Test
+    public void finish_launchAppForUpdateAndIsSkipWfcActivationFalse_writeMetrics() {
+        Intent startIntent = new Intent(Intent.ACTION_MAIN);
+        startIntent.putExtra(SubscriptionManager.EXTRA_SUBSCRIPTION_INDEX, SUB_ID);
+        startIntent.putExtra(
+                ActivityConstants.EXTRA_LAUNCH_CARRIER_APP, ActivityConstants.LAUNCH_APP_UPDATE);
+        mWfcActivationController =
+                new WfcActivationController(
+                        mContext,
+                        mMockActivationUi,
+                        mMockActivationApi,
+                        startIntent,
+                        mMockImsUtils,
+                        mMockMetricsLogger);
+
+        mWfcActivationController.finish();
+
+        verify(mMockMetricsLogger).write(anyInt(), anyInt());
+    }
+
     @Test
     public void finishFlow_isFinishing_showGeneralWaitingUi() {
         InOrder mOrderVerifier = inOrder(mMockActivationUi);
@@ -583,4 +656,16 @@ public class WfcActivationControllerTest {
         inOrder.verify(mMockActivationUi)
                 .showActivationUi(title, R.string.progress_text, true, 0, 0, 0);
     }
+
+    private void setIsSkipWfcActivation(boolean isSkip) {
+        initializeCarrierConfig();
+        mCarrierConfig.putBoolean(KEY_SKIP_WFC_ACTIVATION_BOOL, isSkip);
+    }
+
+    private void initializeCarrierConfig() {
+        if (mCarrierConfig == null) {
+            mCarrierConfig = new PersistableBundle();
+            when(mMockCarrierConfigManager.getConfigForSubId(SUB_ID)).thenReturn(mCarrierConfig);
+        }
+    }
 }
```

