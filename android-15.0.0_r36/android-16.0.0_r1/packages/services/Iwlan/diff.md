```diff
diff --git a/Android.bp b/Android.bp
index b26648c..28ce744 100644
--- a/Android.bp
+++ b/Android.bp
@@ -123,6 +123,8 @@ android_test {
         "iwlan_telephony_flags_lib",
         "platform-test-annotations",
         "flag-junit",
+        "StatsdTestUtils",
+        "statsdprotolite",
     ],
 
     jni_libs: [
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index 5f44f46..8edca71 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -16,6 +16,10 @@
   <uses-permission android:name="android.permission.WAKE_LOCK" />
   <uses-permission android:name="android.permission.SCHEDULE_EXACT_ALARM" />
 
+  <permission android:name="android.iwlan.permission.RESTART_IWLAN"
+                android:label="Permission to restart Iwlan"
+                android:protectionLevel="signature|privileged" />
+
   <application
       android:directBootAware="true"
       android:defaultToDeviceProtectedStorage="true">
@@ -35,6 +39,9 @@
               <action android:name="android.telephony.NetworkService" />
           </intent-filter>
       </service>
-      <uses-library android:name="android.net.ipsec.ike" />
+      <provider android:name=".IwlanSilentRestart"
+            android:authorities="com.google.android.iwlan.iwlansilentrestart"
+            android:exported="true">
+    </provider>
   </application>
 </manifest>
diff --git a/flags/Android.bp b/flags/Android.bp
index f3e0c76..77eac07 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -21,7 +21,7 @@ package {
 aconfig_declarations {
     name: "iwlan_telephony_flags",
     package: "com.google.android.iwlan.flags",
-    container: "system",
+    container: "system_ext",
     srcs: [
         "main.aconfig",
     ],
diff --git a/flags/main.aconfig b/flags/main.aconfig
index c9a38b6..0344e1a 100644
--- a/flags/main.aconfig
+++ b/flags/main.aconfig
@@ -1,5 +1,5 @@
 package: "com.google.android.iwlan.flags"
-container: "system"
+container: "system_ext"
 
 flag {
     name: "prevent_epdg_selection_threads_exhausted"
@@ -49,3 +49,9 @@ flag {
     description: "Trigger underlying network validation check upon no network response"
     bug: "274863262"
 }
+flag {
+    name: "iwlan_silent_restart"
+    namespace: "iwlan_telephony"
+    description: "Clear tunnels and other resources in IWLAN and restart the process"
+    bug: "392910631"
+}
diff --git a/src/com/google/android/iwlan/ErrorPolicyManager.java b/src/com/google/android/iwlan/ErrorPolicyManager.java
index 7134b3c..01ae435 100644
--- a/src/com/google/android/iwlan/ErrorPolicyManager.java
+++ b/src/com/google/android/iwlan/ErrorPolicyManager.java
@@ -863,7 +863,7 @@ public class ErrorPolicyManager {
             abstract Builder setRetryArray(List<Integer> retryArray);
 
             abstract Builder setInfiniteRetriesWithLastRetryTime(
-                    Boolean infiniteRetriesWithLastRetryTime);
+                    boolean infiniteRetriesWithLastRetryTime);
 
             abstract Builder setUnthrottlingEvents(List<Integer> unthrottlingEvents);
 
diff --git a/src/com/google/android/iwlan/IwlanCarrierConfig.java b/src/com/google/android/iwlan/IwlanCarrierConfig.java
index 822ff3f..c679d56 100644
--- a/src/com/google/android/iwlan/IwlanCarrierConfig.java
+++ b/src/com/google/android/iwlan/IwlanCarrierConfig.java
@@ -21,6 +21,7 @@ import android.os.PersistableBundle;
 import android.support.annotation.IntDef;
 import android.support.annotation.NonNull;
 import android.telephony.CarrierConfigManager;
+import android.telephony.SubscriptionManager;
 
 import androidx.annotation.VisibleForTesting;
 
@@ -302,8 +303,18 @@ public class IwlanCarrierConfig {
         }
 
         int subId = IwlanHelper.getSubId(context, slotId);
-        PersistableBundle bundle = carrierConfigManager.getConfigForSubId(subId, key);
-        return bundle.containsKey(key) ? bundle : getDefaultConfig(key);
+        if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+            return getDefaultConfig(key);
+        }
+
+        try {
+            PersistableBundle bundle = carrierConfigManager.getConfigForSubId(subId, key);
+            return bundle.containsKey(key) ? bundle : getDefaultConfig(key);
+        } catch (IllegalStateException e) {
+            // Fall through to return default config
+        }
+
+        return getDefaultConfig(key);
     }
 
     private static PersistableBundle getDefaultConfig(String key) {
@@ -319,6 +330,37 @@ public class IwlanCarrierConfig {
         throw new IllegalArgumentException("Default config not found for key: " + key);
     }
 
+    /**
+     * Returns whether CarrierConfig is loaded for the given slot ID.
+     *
+     * @param context the application context
+     * @param slotId the slot ID
+     * @return Returns {@code true} if the CarrierConfig for the given slot ID is loaded.
+     */
+    static boolean isCarrierConfigLoaded(Context context, int slotId) {
+        int subId = IwlanHelper.getSubId(context, slotId);
+
+        if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+            // Fail to query subscription id, just return false.
+            return false;
+        }
+
+        CarrierConfigManager carrierConfigManager =
+                context.getSystemService(CarrierConfigManager.class);
+        PersistableBundle bundle;
+        try {
+            bundle =
+                    carrierConfigManager != null
+                            ? carrierConfigManager.getConfigForSubId(
+                                    subId, CarrierConfigManager.KEY_CARRIER_CONFIG_APPLIED_BOOL)
+                            : new PersistableBundle();
+        } catch (Exception e) {
+            bundle = new PersistableBundle();
+        }
+
+        return CarrierConfigManager.isConfigForIdentifiedCarrier(bundle);
+    }
+
     /**
      * Gets a configuration int value for a given slot ID and key.
      *
diff --git a/src/com/google/android/iwlan/IwlanDataService.java b/src/com/google/android/iwlan/IwlanDataService.java
index 9a70a39..c2af7a0 100644
--- a/src/com/google/android/iwlan/IwlanDataService.java
+++ b/src/com/google/android/iwlan/IwlanDataService.java
@@ -67,7 +67,7 @@ import android.telephony.data.NetworkSliceInfo;
 import android.telephony.data.TrafficDescriptor;
 import android.util.Log;
 
-import com.android.internal.annotations.VisibleForTesting;
+import androidx.annotation.VisibleForTesting;
 
 import com.google.android.iwlan.TunnelMetricsInterface.OnClosedMetrics;
 import com.google.android.iwlan.TunnelMetricsInterface.OnOpenedMetrics;
@@ -106,10 +106,15 @@ public class IwlanDataService extends DataService {
     private static Network sNetwork = null;
     private static LinkProperties sLinkProperties = null;
     private static NetworkCapabilities sNetworkCapabilities;
+
     @VisibleForTesting Handler mHandler;
     private HandlerThread mHandlerThread;
-    private static final Map<Integer, IwlanDataServiceProvider> sIwlanDataServiceProviders =
+    private static final Map<Integer, IwlanDataServiceProvider> sDataServiceProviders =
             new ConcurrentHashMap<>();
+
+    private ConnectivityManager mConnectivityManager;
+    private TelephonyManager mTelephonyManager;
+
     private static final int INVALID_SUB_ID = -1;
 
     // The current subscription with the active internet PDN. Need not be the default data sub.
@@ -137,8 +142,6 @@ public class IwlanDataService extends DataService {
 
     private boolean mIs5GEnabledOnUi;
 
-    public IwlanDataService() {}
-
     // TODO: see if network monitor callback impl can be shared between dataservice and
     // networkservice
     // This callback runs in the same thread as IwlanDataServiceHandler
@@ -188,7 +191,7 @@ public class IwlanDataService extends DataService {
             }
 
             if (!linkProperties.equals(sLinkProperties)) {
-                for (IwlanDataServiceProvider dp : sIwlanDataServiceProviders.values()) {
+                for (IwlanDataServiceProvider dp : sDataServiceProviders.values()) {
                     dp.dnsPrefetchCheck();
                     sLinkProperties = linkProperties;
                     dp.updateNetwork(network, linkProperties);
@@ -236,7 +239,6 @@ public class IwlanDataService extends DataService {
         private static final int CALLBACK_TYPE_GET_DATACALL_LIST_COMPLETE = 3;
 
         private final String SUB_TAG;
-        private final IwlanDataService mIwlanDataService;
         // TODO(b/358152549): Remove metrics handling inside IwlanTunnelCallback
         private final IwlanTunnelCallback mIwlanTunnelCallback;
         private final EpdgTunnelManager mEpdgTunnelManager;
@@ -647,18 +649,19 @@ public class IwlanDataService extends DataService {
          *
          * @param slotIndex SIM slot index the data service provider associated with.
          */
-        public IwlanDataServiceProvider(int slotIndex, IwlanDataService iwlanDataService) {
+        public IwlanDataServiceProvider(int slotIndex) {
             super(slotIndex);
             SUB_TAG = TAG + "[" + slotIndex + "]";
 
             // TODO:
             // get reference carrier config for this sub
             // get reference to resolver
-            mIwlanDataService = iwlanDataService;
             mIwlanTunnelCallback = new IwlanTunnelCallback(this);
             mEpdgTunnelManager = EpdgTunnelManager.getInstance(mContext, slotIndex);
             mCalendar = Calendar.getInstance();
             mTunnelStats = new IwlanDataTunnelStats();
+            mWfcEnabled = IwlanHelper.isWfcEnabled(mContext, slotIndex);
+            mCarrierConfigReady = IwlanCarrierConfig.isCarrierConfigLoaded(mContext, slotIndex);
 
             // Register IwlanEventListener
             List<Integer> events = new ArrayList<Integer>();
@@ -1186,7 +1189,6 @@ public class IwlanDataService extends DataService {
          */
         @Override
         public void close() {
-            mIwlanDataService.removeDataServiceProvider(this);
             IwlanEventListener iwlanEventListener =
                     IwlanEventListener.getInstance(mContext, getSlotIndex());
             iwlanEventListener.removeEventListener(getHandler());
@@ -1319,7 +1321,6 @@ public class IwlanDataService extends DataService {
 
             IwlanDataServiceProvider iwlanDataServiceProvider;
             DataServiceCallback callback;
-            int slotId;
 
             switch (msg.what) {
                 case IwlanEventListener.CARRIER_CONFIG_CHANGED_EVENT:
@@ -1451,30 +1452,11 @@ public class IwlanDataService extends DataService {
                     break;
 
                 case EVENT_FORCE_CLOSE_TUNNEL:
-                    for (IwlanDataServiceProvider dp : sIwlanDataServiceProviders.values()) {
+                    for (IwlanDataServiceProvider dp : sDataServiceProviders.values()) {
                         dp.forceCloseTunnels(EpdgTunnelManager.BRINGDOWN_REASON_UNKNOWN);
                     }
                     break;
 
-                case EVENT_ADD_DATA_SERVICE_PROVIDER:
-                    iwlanDataServiceProvider = (IwlanDataServiceProvider) msg.obj;
-                    addIwlanDataServiceProvider(iwlanDataServiceProvider);
-                    break;
-
-                case EVENT_REMOVE_DATA_SERVICE_PROVIDER:
-                    iwlanDataServiceProvider = (IwlanDataServiceProvider) msg.obj;
-
-                    slotId = iwlanDataServiceProvider.getSlotIndex();
-                    IwlanDataServiceProvider dsp = sIwlanDataServiceProviders.remove(slotId);
-                    if (dsp == null) {
-                        Log.w(TAG + "[" + slotId + "]", "No DataServiceProvider exists for slot!");
-                    }
-
-                    if (sIwlanDataServiceProviders.isEmpty()) {
-                        deinitNetworkCallback();
-                    }
-                    break;
-
                 case EVENT_ON_LIVENESS_STATUS_CHANGED:
                     handleLivenessStatusChange((TunnelValidationStatusData) msg.obj);
                     break;
@@ -1645,7 +1627,7 @@ public class IwlanDataService extends DataService {
             if (hasTransportChanged) {
                 // Perform forceClose for tunnels in bringdown.
                 // let framework handle explicit teardown
-                for (IwlanDataServiceProvider dp : sIwlanDataServiceProviders.values()) {
+                for (IwlanDataServiceProvider dp : sDataServiceProviders.values()) {
                     dp.forceCloseTunnelsInDeactivatingState();
                 }
             }
@@ -1659,14 +1641,14 @@ public class IwlanDataService extends DataService {
                         mContext.getSystemService(ConnectivityManager.class);
                 LinkProperties linkProperties = connectivityManager.getLinkProperties(network);
                 sLinkProperties = linkProperties;
-                for (IwlanDataServiceProvider dp : sIwlanDataServiceProviders.values()) {
+                for (IwlanDataServiceProvider dp : sDataServiceProviders.values()) {
                     dp.dnsPrefetchCheck();
                     dp.updateNetwork(network, linkProperties);
                 }
                 IwlanHelper.updateCountryCodeWhenNetworkConnected();
             }
         } else {
-            for (IwlanDataServiceProvider dp : sIwlanDataServiceProviders.values()) {
+            for (IwlanDataServiceProvider dp : sDataServiceProviders.values()) {
                 // once network is disconnected, even NAT KA offload fails
                 // But we should still let framework do an explicit teardown
                 // so as to not affect an ongoing handover
@@ -1681,14 +1663,8 @@ public class IwlanDataService extends DataService {
         sNetworkCapabilities = networkCapabilities;
     }
 
-    /**
-     * Get the DataServiceProvider associated with the slotId
-     *
-     * @param slotId slot index
-     * @return DataService.DataServiceProvider associated with the slot
-     */
     public static DataService.DataServiceProvider getDataServiceProvider(int slotId) {
-        return sIwlanDataServiceProviders.get(slotId);
+        return sDataServiceProviders.get(slotId);
     }
 
     public static Context getContext() {
@@ -1697,48 +1673,26 @@ public class IwlanDataService extends DataService {
 
     @Override
     public DataServiceProvider onCreateDataServiceProvider(int slotIndex) {
-        // TODO: validity check on slot index
-        Log.d(TAG, "Creating provider for " + slotIndex);
+        Log.d(TAG, "Creating DataServiceProvider for " + slotIndex);
 
-        if (mNetworkMonitorCallback == null) {
-            // start monitoring network and register for default network callback
-            ConnectivityManager connectivityManager =
-                    mContext.getSystemService(ConnectivityManager.class);
-            mNetworkMonitorCallback = new IwlanNetworkMonitorCallback();
-            if (connectivityManager != null) {
-                connectivityManager.registerSystemDefaultNetworkCallback(
-                        mNetworkMonitorCallback, getHandler());
-            }
-            Log.d(TAG, "Registered with Connectivity Service");
+        IwlanDataServiceProvider dataServiceProvider = sDataServiceProviders.get(slotIndex);
+        if (dataServiceProvider != null) {
+            Log.w(
+                    TAG,
+                    "DataServiceProvider already exists for slot "
+                            + slotIndex
+                            + ". Closing and recreating.");
+            dataServiceProvider.close();
         }
 
-        IwlanDataServiceProvider dp = new IwlanDataServiceProvider(slotIndex, this);
-
-        getHandler().obtainMessage(EVENT_ADD_DATA_SERVICE_PROVIDER, dp).sendToTarget();
-        return dp;
-    }
-
-    public void removeDataServiceProvider(IwlanDataServiceProvider dp) {
-        getHandler().obtainMessage(EVENT_REMOVE_DATA_SERVICE_PROVIDER, dp).sendToTarget();
-    }
+        dataServiceProvider = new IwlanDataServiceProvider(slotIndex);
+        sDataServiceProviders.put(slotIndex, dataServiceProvider);
 
-    @VisibleForTesting
-    void addIwlanDataServiceProvider(IwlanDataServiceProvider dp) {
-        int slotIndex = dp.getSlotIndex();
-        if (sIwlanDataServiceProviders.containsKey(slotIndex)) {
-            throw new IllegalStateException(
-                    "DataServiceProvider already exists for slot " + slotIndex);
-        }
-        sIwlanDataServiceProviders.put(slotIndex, dp);
+        return dataServiceProvider;
     }
 
     void deinitNetworkCallback() {
-        // deinit network related stuff
-        ConnectivityManager connectivityManager =
-                mContext.getSystemService(ConnectivityManager.class);
-        if (connectivityManager != null) {
-            connectivityManager.unregisterNetworkCallback(mNetworkMonitorCallback);
-        }
+        mConnectivityManager.unregisterNetworkCallback(mNetworkMonitorCallback);
         mNetworkMonitorCallback = null;
     }
 
@@ -1794,7 +1748,6 @@ public class IwlanDataService extends DataService {
     }
 
     private void initAllowedNetworkType() {
-        TelephonyManager mTelephonyManager = mContext.getSystemService(TelephonyManager.class);
         mIs5GEnabledOnUi =
                 ((mTelephonyManager.getAllowedNetworkTypesBitmask()
                                 & TelephonyManager.NETWORK_TYPE_BITMASK_NR)
@@ -1828,20 +1781,42 @@ public class IwlanDataService extends DataService {
                 : null;
     }
 
+    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
+    void registerServices(Context context) {
+        mConnectivityManager = context.getSystemService(ConnectivityManager.class);
+        Objects.requireNonNull(mConnectivityManager);
+
+        mTelephonyManager = context.getSystemService(TelephonyManager.class);
+        Objects.requireNonNull(mTelephonyManager);
+
+        mNetworkMonitorCallback = new IwlanNetworkMonitorCallback();
+        mConnectivityManager.registerSystemDefaultNetworkCallback(
+                mNetworkMonitorCallback, getHandler());
+
+        IwlanBroadcastReceiver.startListening(context);
+        IwlanCarrierConfigChangeListener.startListening(context);
+        IwlanHelper.startCountryDetector(context);
+        initAllowedNetworkType();
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
+    void unregisterServices() {
+        IwlanCarrierConfigChangeListener.stopListening(mContext);
+        IwlanBroadcastReceiver.stopListening(mContext);
+        deinitNetworkCallback();
+    }
+
     @Override
     public void onCreate() {
         Context context = getApplicationContext().createAttributionContext(CONTEXT_ATTRIBUTION_TAG);
         setAppContext(context);
-        IwlanBroadcastReceiver.startListening(mContext);
-        IwlanCarrierConfigChangeListener.startListening(mContext);
-        IwlanHelper.startCountryDetector(mContext);
-        initAllowedNetworkType();
+        registerServices(context);
     }
 
     @Override
     public void onDestroy() {
-        IwlanCarrierConfigChangeListener.stopListening(mContext);
-        IwlanBroadcastReceiver.stopListening(mContext);
+        unregisterServices();
+        super.onDestroy();
     }
 
     @Override
@@ -2370,7 +2345,7 @@ public class IwlanDataService extends DataService {
             transport = "WIFI";
         }
         pw.println("Default transport: " + transport);
-        for (IwlanDataServiceProvider provider : sIwlanDataServiceProviders.values()) {
+        for (IwlanDataServiceProvider provider : sDataServiceProviders.values()) {
             pw.println();
             provider.dump(fd, pw, args);
             pw.println();
diff --git a/src/com/google/android/iwlan/IwlanHelper.java b/src/com/google/android/iwlan/IwlanHelper.java
index 85fc8cc..6f051b5 100644
--- a/src/com/google/android/iwlan/IwlanHelper.java
+++ b/src/com/google/android/iwlan/IwlanHelper.java
@@ -200,6 +200,28 @@ public class IwlanHelper {
         return false;
     }
 
+    static boolean isWfcEnabled(Context context, int slotId) {
+        boolean isWfcEnabled = false;
+        int subId = getSubId(context, slotId);
+
+        if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+            // Fail to query subscription id, just return false.
+            return false;
+        }
+
+        ImsManager imsManager = context.getSystemService(ImsManager.class);
+        if (imsManager != null) {
+            return false;
+        }
+
+        try {
+            isWfcEnabled = imsManager.getImsMmTelManager(subId).isVoWiFiSettingEnabled();
+        } catch (Exception e) {
+            Log.e(TAG, "Fail to query Wi-Fi calling setting");
+        }
+        return isWfcEnabled;
+    }
+
     public static boolean isCrossSimCallingEnabled(Context context, int slotId) {
         boolean isCstEnabled = false;
         int subid = getSubId(context, slotId);
diff --git a/src/com/google/android/iwlan/IwlanSilentRestart.java b/src/com/google/android/iwlan/IwlanSilentRestart.java
new file mode 100644
index 0000000..04ebc91
--- /dev/null
+++ b/src/com/google/android/iwlan/IwlanSilentRestart.java
@@ -0,0 +1,128 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.google.android.iwlan;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.content.ContentProvider;
+import android.content.ContentValues;
+import android.content.Context;
+import android.database.Cursor;
+import android.net.Uri;
+import android.os.Bundle;
+import android.os.Handler;
+import android.os.HandlerThread;
+import android.util.Log;
+
+import com.google.android.iwlan.epdg.EpdgTunnelManager;
+import com.google.android.iwlan.flags.FeatureFlags;
+import com.google.android.iwlan.flags.FeatureFlagsImpl;
+
+public class IwlanSilentRestart extends ContentProvider {
+    private static final String TAG = IwlanSilentRestart.class.getSimpleName();
+
+    private static final String METHOD_RESTART_IWLAN = "restart_iwlan";
+
+    private static final String PERMISSION_RESTART_IWLAN = "android.iwlan.permission.RESTART_IWLAN";
+
+    private final FeatureFlags mFeatureFlags = new FeatureFlagsImpl();
+    private Handler mHandler;
+
+    @Override
+    public boolean onCreate() {
+        Log.d(TAG, "onCreate");
+        if (!mFeatureFlags.iwlanSilentRestart()) {
+            Log.d(TAG, "feature not available");
+            return false;
+        }
+
+        HandlerThread handlerThread = new HandlerThread("IwlanSilentRestartThread");
+        handlerThread.start();
+        mHandler = new Handler(handlerThread.getLooper());
+
+        return true;
+    }
+
+    private void clearAndExit() {
+        deinitService();
+        Log.i(TAG, "Restart com.google.pixel.iwlan by killing it");
+        System.exit(0);
+    }
+
+    private void deinitService() {
+        EpdgTunnelManager.deinit();
+    }
+
+    @Override
+    public @Nullable Bundle call(
+            @NonNull String authority,
+            @NonNull String method,
+            @Nullable String arg,
+            @Nullable Bundle extras) {
+        Log.d(TAG, "called " + authority + " " + method);
+
+        if (METHOD_RESTART_IWLAN.equals(method)) {
+            final Context context = getContext();
+            if (context == null) {
+                Log.d(TAG, "Cannot find context from the content provider");
+                return null;
+            }
+
+            context.enforceCallingOrSelfPermission(PERMISSION_RESTART_IWLAN, null);
+            Log.i(TAG, "Restart com.google.android.iwlan");
+
+            mHandler.post(this::clearAndExit);
+        }
+
+        return null;
+    }
+
+    @Override
+    public @Nullable Cursor query(
+            @NonNull Uri uri,
+            @Nullable String[] projection,
+            @Nullable String selection,
+            @Nullable String[] selectionArgs,
+            @Nullable String sortOrder) {
+        throw new UnsupportedOperationException();
+    }
+
+    @Override
+    public @Nullable String getType(@NonNull Uri uri) {
+        throw new UnsupportedOperationException();
+    }
+
+    @Override
+    public @Nullable Uri insert(@NonNull Uri uri, @Nullable ContentValues values) {
+        throw new UnsupportedOperationException();
+    }
+
+    @Override
+    public int delete(
+            @NonNull Uri uri, @Nullable String selection, @Nullable String[] selectionArgs) {
+        throw new UnsupportedOperationException();
+    }
+
+    @Override
+    public int update(
+            @NonNull Uri uri,
+            @Nullable ContentValues values,
+            @Nullable String selection,
+            @Nullable String[] selectionArgs) {
+        throw new UnsupportedOperationException();
+    }
+}
diff --git a/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java b/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
index 18526d5..28dcdab 100644
--- a/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
+++ b/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
@@ -193,6 +193,8 @@ public class EpdgTunnelManager {
     private final EpdgSelector mEpdgSelector;
 
     private final Map<String, TunnelConfig> mApnNameToTunnelConfig = new ConcurrentHashMap<>();
+    private final Map<String, IpsecTransformData> mApnNameToIpsecTransform =
+            new ConcurrentHashMap<>();
     private final Map<String, Integer> mApnNameToCurrentToken = new ConcurrentHashMap<>();
 
     private final String TAG;
@@ -502,6 +504,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onOpened(IkeSessionConfiguration sessionConfiguration) {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             Log.d(TAG, "Ike session opened for apn: " + mApnName + " with token: " + mToken);
             mHandler.obtainMessage(
                             EVENT_IKE_SESSION_OPENED,
@@ -511,6 +517,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onClosed() {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             Log.d(TAG, "Ike session closed for apn: " + mApnName + " with token: " + mToken);
             mHandler.obtainMessage(
                             EVENT_IKE_SESSION_CLOSED,
@@ -541,6 +551,10 @@ public class EpdgTunnelManager {
         @Override
         public void onIkeSessionConnectionInfoChanged(
                 IkeSessionConnectionInfo ikeSessionConnectionInfo) {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             Network network = ikeSessionConnectionInfo.getNetwork();
             Log.d(
                     TAG,
@@ -559,6 +573,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onLivenessStatusChanged(int status) {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             Log.d(
                     TAG,
                     "Ike liveness status changed for apn: " + mApnName + " with status: " + status);
@@ -599,6 +617,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onIke3gppDataReceived(List<Ike3gppData> payloads) {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             mHandler.obtainMessage(
                             EVENT_IKE_3GPP_DATA_RECEIVED,
                             new Ike3gppDataReceived(mApnName, mToken, payloads))
@@ -619,6 +641,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onOpened(ChildSessionConfiguration sessionConfiguration) {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             Log.d(TAG, "onOpened child session for apn: " + mApnName + " with token: " + mToken);
             mHandler.obtainMessage(
                             EVENT_CHILD_SESSION_OPENED,
@@ -632,6 +658,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onClosed() {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             Log.d(TAG, "onClosed child session for apn: " + mApnName + " with token: " + mToken);
             mHandler.obtainMessage(
                             EVENT_CHILD_SESSION_CLOSED,
@@ -647,6 +677,10 @@ public class EpdgTunnelManager {
         @Override
         public void onIpSecTransformsMigrated(
                 IpSecTransform inIpSecTransform, IpSecTransform outIpSecTransform) {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             // migration is similar to addition
             Log.d(TAG, "Transforms migrated for apn: " + mApnName + " with token: " + mToken);
             mHandler.obtainMessage(
@@ -666,6 +700,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onIpSecTransformCreated(IpSecTransform ipSecTransform, int direction) {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             Log.d(
                     TAG,
                     "Transform created, direction: "
@@ -682,6 +720,10 @@ public class EpdgTunnelManager {
 
         @Override
         public void onIpSecTransformDeleted(IpSecTransform ipSecTransform, int direction) {
+            if (mHandler == null) {
+                Log.d(TAG, "Handler unavailable");
+                return;
+            }
             Log.d(
                     TAG,
                     "Transform deleted, direction: "
@@ -747,22 +789,29 @@ public class EpdgTunnelManager {
                             return;
                         }
                         reportValidationMetricsAtom(
-                                network, getMetricsValidationResult(mNetworkValidationResult));
+                                network,
+                                getMetricsValidationResult(mNetworkValidationResult),
+                                /* validationTriggered */ true);
                     }
                 };
         connectivityDiagnosticsManager.registerConnectivityDiagnosticsCallback(
                 networkRequest, new HandlerExecutor(mHandler), mConnectivityDiagnosticsCallback);
     }
 
-    private void reportValidationMetricsAtom(Network network, int validationResult) {
+    private void reportValidationMetricsAtom(
+            @NonNull Network network, int validationResult, boolean validationTriggered) {
         if (!mMetricsAtomForNetwork.containsKey(network)) {
             return;
         }
         MetricsAtom metricsAtom = mMetricsAtomForNetwork.get(network);
         metricsAtom.setValidationResult(validationResult);
+        metricsAtom.setValidationTriggered(validationTriggered);
         metricsAtom.setValidationDurationMills(
-                (int) (IwlanHelper.elapsedRealtime() - metricsAtom.getValidationStartTimeMills()));
-
+                validationTriggered
+                        ? (int)
+                                (IwlanHelper.elapsedRealtime()
+                                        - metricsAtom.getValidationStartTimeMills())
+                        : 0);
         Log.d(
                 TAG,
                 "reportValidationMetricsAtom: reason="
@@ -772,7 +821,9 @@ public class EpdgTunnelManager {
                         + " transportType="
                         + metricsAtom.getValidationTransportType()
                         + " duration="
-                        + metricsAtom.getValidationDurationMills());
+                        + metricsAtom.getValidationDurationMills()
+                        + " validationTriggered="
+                        + metricsAtom.getValidationTriggered());
         metricsAtom.sendMetricsData();
         mMetricsAtomForNetwork.remove(network);
     }
@@ -822,6 +873,33 @@ public class EpdgTunnelManager {
         sLastUnderlyingNetworkValidationMs = 0;
     }
 
+    private void reset() {
+        if (mHandler != null) {
+            mHandler.getLooper().quit();
+            mHandler = null;
+        }
+
+        mApnNameToTunnelConfig.forEach(
+                (apn, config) -> {
+                    config.getIkeSession().kill();
+                    IpSecManager.IpSecTunnelInterface iface = config.getIface();
+                    if (iface != null) {
+                        iface.close();
+                    }
+                    IpsecTransformData transformData = mApnNameToIpsecTransform.get(apn);
+                    if (transformData != null) {
+                        transformData.getTransform().close();
+                        mApnNameToIpsecTransform.remove(apn);
+                    }
+                });
+
+        mApnNameToTunnelConfig.clear();
+    }
+
+    public static void deinit() {
+        mTunnelManagerInstances.values().forEach(EpdgTunnelManager::reset);
+    }
+
     public interface TunnelCallback {
         /**
          * Called when the tunnel is opened.
@@ -2240,6 +2318,7 @@ public class EpdgTunnelManager {
                         closeIkeSession(
                                 apnName, new IwlanError(IwlanError.TUNNEL_TRANSFORM_FAILED));
                     }
+                    mApnNameToIpsecTransform.put(apnName, transformData);
                     if (tunnelConfig.getIkeSessionState()
                             == IkeSessionState.IKE_MOBILITY_IN_PROGRESS) {
                         tunnelConfig.setIkeSessionState(IkeSessionState.CHILD_SESSION_OPENED);
@@ -2250,6 +2329,7 @@ public class EpdgTunnelManager {
                     transformData = (IpsecTransformData) msg.obj;
                     IpSecTransform transform = transformData.getTransform();
                     transform.close();
+                    mApnNameToIpsecTransform.remove(transformData.getApnName());
                     break;
 
                 case EVENT_CHILD_SESSION_CLOSED:
@@ -3139,6 +3219,8 @@ public class EpdgTunnelManager {
     }
 
     private boolean isUnderlyingNetworkValidated(Network network) {
+        if (network == null) return false;
+
         ConnectivityManager connectivityManager =
                 Objects.requireNonNull(mContext).getSystemService(ConnectivityManager.class);
         NetworkCapabilities networkCapabilities =
@@ -3189,19 +3271,27 @@ public class EpdgTunnelManager {
     }
 
     private void onTriggerUnderlyingNetworkValidation(int event) {
+        if (mDefaultNetwork == null) return;
+
+        setupValidationMetricsAtom(mDefaultNetwork, event);
+
         if (!isUnderlyingNetworkValidated(mDefaultNetwork)) {
             Log.d(TAG, "Network " + mDefaultNetwork + " is already not validated.");
+            reportValidationMetricsAtom(
+                    mDefaultNetwork,
+                    NETWORK_VALIDATION_RESULT_INVALID,
+                    /* validationTriggered */ false);
             return;
         }
 
-        setupValidationMetricsAtom(event);
         ConnectivityManager connectivityManager =
                 Objects.requireNonNull(mContext).getSystemService(ConnectivityManager.class);
         Log.d(TAG, "Trigger underlying network validation on network: " + mDefaultNetwork);
-        connectivityManager.reportNetworkConnectivity(mDefaultNetwork, false);
+        Objects.requireNonNull(connectivityManager)
+                .reportNetworkConnectivity(mDefaultNetwork, false);
     }
 
-    private void setupValidationMetricsAtom(int event) {
+    private void setupValidationMetricsAtom(@NonNull Network network, int event) {
         MetricsAtom metricsAtom = new MetricsAtom();
         metricsAtom.setMessageId(IwlanStatsLog.IWLAN_UNDERLYING_NETWORK_VALIDATION_RESULT_REPORTED);
         metricsAtom.setTriggerReason(getMetricsTriggerReason(event));
@@ -3221,7 +3311,7 @@ public class EpdgTunnelManager {
         metricsAtom.setValidationTransportType(validationTransportType);
 
         metricsAtom.setValidationStartTimeMills(IwlanHelper.elapsedRealtime());
-        mMetricsAtomForNetwork.put(mDefaultNetwork, metricsAtom);
+        mMetricsAtomForNetwork.put(network, metricsAtom);
     }
 
     boolean isUnderlyingNetworkValidationRequired(int error) {
diff --git a/src/com/google/android/iwlan/proto/MetricsAtom.java b/src/com/google/android/iwlan/proto/MetricsAtom.java
index 8e17516..97c0940 100644
--- a/src/com/google/android/iwlan/proto/MetricsAtom.java
+++ b/src/com/google/android/iwlan/proto/MetricsAtom.java
@@ -69,6 +69,7 @@ public class MetricsAtom {
     private int mValidationTransportType;
     private int mValidationDurationMills;
     private long mValidationStartTimeMills;
+    private boolean mValidationTriggered;
 
     public void setMessageId(int messageId) {
         this.mMessageId = messageId;
@@ -228,6 +229,14 @@ public class MetricsAtom {
         return mValidationStartTimeMills;
     }
 
+    public boolean getValidationTriggered() {
+        return mValidationTriggered;
+    }
+
+    public void setValidationTriggered(boolean validationTriggered) {
+        mValidationTriggered = validationTriggered;
+    }
+
     public void sendMetricsData() {
         if (mMessageId == IwlanStatsLog.IWLAN_SETUP_DATA_CALL_RESULT_REPORTED) {
             Log.d(TAG, "Send metrics data IWLAN_SETUP_DATA_CALL_RESULT_REPORTED");
@@ -269,7 +278,8 @@ public class MetricsAtom {
                     mTriggerReason,
                     mValidationResult,
                     mValidationTransportType,
-                    mValidationDurationMills);
+                    mValidationDurationMills,
+                    mValidationTriggered);
         } else {
             Log.d("IwlanMetrics", "Invalid Message ID: " + mMessageId);
         }
diff --git a/test/AndroidManifest.xml b/test/AndroidManifest.xml
index 029abe3..f4c72d9 100644
--- a/test/AndroidManifest.xml
+++ b/test/AndroidManifest.xml
@@ -7,7 +7,6 @@
 
     <application android:label="IwlanUnitTest" android:debuggable="true">
         <uses-library android:name="android.test.runner" />
-        <uses-library android:name="android.net.ipsec.ike" />
     </application>
 
     <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
diff --git a/test/com/google/android/iwlan/IwlanCarrierConfigTest.java b/test/com/google/android/iwlan/IwlanCarrierConfigTest.java
index 5318448..e0ba466 100644
--- a/test/com/google/android/iwlan/IwlanCarrierConfigTest.java
+++ b/test/com/google/android/iwlan/IwlanCarrierConfigTest.java
@@ -336,4 +336,32 @@ public class IwlanCarrierConfigTest {
     public void testGetDefaultConfig_KeyNotFound() {
         IwlanCarrierConfig.getDefaultConfigInt(KEY_NON_EXISTING);
     }
+
+    @Test
+    public void testGetConfig_invalidSubId() {
+        String configKey = "KeyInvalidSubId";
+
+        when(mMockSubscriptionInfo.getSubscriptionId())
+                .thenReturn(SubscriptionManager.INVALID_SUBSCRIPTION_ID);
+        mBundleForSub.putInt(configKey, VALUE_CONFIG_IN_SUB_INT);
+        mBundleForDefault.putInt(configKey, VALUE_CONFIG_IN_DEFAULT_INT);
+
+        int result = IwlanCarrierConfig.getConfigInt(mMockContext, DEFAULT_SLOT_ID, configKey);
+
+        assertEquals(VALUE_CONFIG_IN_DEFAULT_INT, result);
+    }
+
+    @Test
+    public void testGetConfig_illegalStateException() {
+        String configKey = "KeyException";
+
+        when(mMockCarrierConfigManager.getConfigForSubId(DEFAULT_SUB_ID, configKey))
+                .thenThrow(new IllegalStateException());
+        mBundleForSub.putInt(configKey, VALUE_CONFIG_IN_SUB_INT);
+        mBundleForDefault.putInt(configKey, VALUE_CONFIG_IN_DEFAULT_INT);
+
+        int result = IwlanCarrierConfig.getConfigInt(mMockContext, DEFAULT_SLOT_ID, configKey);
+
+        assertEquals(VALUE_CONFIG_IN_DEFAULT_INT, result);
+    }
 }
diff --git a/test/com/google/android/iwlan/IwlanDataServiceTest.java b/test/com/google/android/iwlan/IwlanDataServiceTest.java
index 58369ba..cd2bb69 100644
--- a/test/com/google/android/iwlan/IwlanDataServiceTest.java
+++ b/test/com/google/android/iwlan/IwlanDataServiceTest.java
@@ -37,7 +37,6 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
-import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.isNull;
 import static org.mockito.Mockito.any;
@@ -99,6 +98,7 @@ import com.google.android.iwlan.proto.MetricsAtom;
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Test;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
@@ -138,7 +138,6 @@ public class IwlanDataServiceTest {
     @Mock private ConnectivityManager mMockConnectivityManager;
     @Mock private DataServiceCallback mMockDataServiceCallback;
     @Mock private EpdgTunnelManager mMockEpdgTunnelManager;
-    @Mock private IwlanDataServiceProvider mMockIwlanDataServiceProvider;
     @Mock private Network mMockNetwork;
     @Mock private TunnelLinkProperties mMockTunnelLinkProperties;
     @Mock private TunnelMetricsInterface.OnOpenedMetrics mMockOnOpenedMetrics;
@@ -158,7 +157,7 @@ public class IwlanDataServiceTest {
     private List<DataCallResponse> mResultDataCallList;
     private @DataServiceCallback.ResultCode int mResultCode;
     private IwlanDataService mIwlanDataService;
-    private IwlanDataServiceProvider mSpyIwlanDataServiceProvider;
+    private IwlanDataServiceProvider mIwlanDataServiceProvider;
     private final TestLooper mTestLooper = new TestLooper();
     private long mMockedCalendarTime;
     private final ArgumentCaptor<NetworkCallback> mNetworkCallbackCaptor =
@@ -216,6 +215,11 @@ public class IwlanDataServiceTest {
                         .strictness(Strictness.LENIENT)
                         .startMocking();
 
+        mIwlanDataService = spy(new IwlanDataService());
+        mLinkProperties = new LinkProperties();
+        mLinkProperties.setInterfaceName("wlan0");
+        mLinkProperties.addLinkAddress(mMockIPv4LinkAddress);
+
         lenient()
                 .when(SubscriptionManager.getDefaultDataSubscriptionId())
                 .thenReturn(DEFAULT_SUB_INDEX);
@@ -228,8 +232,11 @@ public class IwlanDataServiceTest {
 
         when(mMockContext.getSystemService(eq(ConnectivityManager.class)))
                 .thenReturn(mMockConnectivityManager);
+        when(mMockContext.getSystemService(eq(ImsManager.class))).thenReturn(mMockImsManager);
         when(mMockContext.getSystemService(eq(SubscriptionManager.class)))
                 .thenReturn(mMockSubscriptionManager);
+        when(mMockContext.getSystemService(eq(TelephonyManager.class)))
+                .thenReturn(mMockTelephonyManager);
 
         doNothing()
                 .when(mMockConnectivityManager)
@@ -244,9 +251,6 @@ public class IwlanDataServiceTest {
 
         when(mMockSubscriptionInfo.getSubscriptionId()).thenReturn(DEFAULT_SUB_INDEX);
 
-        when(mMockContext.getSystemService(eq(TelephonyManager.class)))
-                .thenReturn(mMockTelephonyManager);
-
         when(mMockTelephonyManager.createForSubscriptionId(eq(DEFAULT_SUB_INDEX)))
                 .thenReturn(mMockTelephonyManager);
 
@@ -254,8 +258,6 @@ public class IwlanDataServiceTest {
 
         when(mMockContext.getContentResolver()).thenReturn(mMockContentResolver);
 
-        when(mMockContext.getSystemService(eq(ImsManager.class))).thenReturn(mMockImsManager);
-
         when(mMockImsManager.getImsMmTelManager(anyInt())).thenReturn(mMockImsMmTelManager);
 
         when(mMockImsMmTelManager.isVoWiFiSettingEnabled()).thenReturn(false);
@@ -263,30 +265,23 @@ public class IwlanDataServiceTest {
         when(mMockIPv4LinkAddress.getAddress()).thenReturn(mMockInet4Address);
         when(mMockIPv6LinkAddress.getAddress()).thenReturn(mMockInet6Address);
 
-        mIwlanDataService = spy(new IwlanDataService());
+        when(mMockConnectivityManager.getLinkProperties(eq(mMockNetwork)))
+                .thenReturn(mLinkProperties);
+        when(mMockTunnelLinkProperties.ifaceName()).thenReturn("mockipsec0");
 
-        // Injects the test looper into the IwlanDataServiceHandler
         doReturn(mTestLooper.getLooper()).when(mIwlanDataService).getLooper();
-        mIwlanDataService.setAppContext(mMockContext);
-        mSpyIwlanDataServiceProvider =
-                spy(
-                        (IwlanDataServiceProvider)
-                                mIwlanDataService.onCreateDataServiceProvider(DEFAULT_SLOT_INDEX));
-        mTestLooper.dispatchAll();
-
-        when(Calendar.getInstance().getTime()).thenAnswer(i -> mMockedCalendarTime);
 
-        mLinkProperties = new LinkProperties();
-        mLinkProperties.setInterfaceName("wlan0");
-        mLinkProperties.addLinkAddress(mMockIPv4LinkAddress);
+        doNothing().when(mMockEpdgTunnelManager).close();
 
-        when(mMockConnectivityManager.getLinkProperties(eq(mMockNetwork)))
-                .thenReturn(mLinkProperties);
-        when(mMockTunnelLinkProperties.ifaceName()).thenReturn("mockipsec0");
+        mIwlanDataService.setAppContext(mMockContext);
+        mIwlanDataService.registerServices(mMockContext);
 
         mockCarrierConfigForN1Mode(true);
 
-        doNothing().when(mMockEpdgTunnelManager).close();
+        mIwlanDataServiceProvider =
+                (IwlanDataServiceProvider)
+                        mIwlanDataService.onCreateDataServiceProvider(DEFAULT_SLOT_INDEX);
+        mTestLooper.dispatchAll();
     }
 
     private void moveTimeForwardAndDispatch(long milliSeconds) {
@@ -296,13 +291,9 @@ public class IwlanDataServiceTest {
 
     @After
     public void cleanUp() throws Exception {
-        mStaticMockSession.finishMocking();
         IwlanCarrierConfig.resetTestConfig();
-        mSpyIwlanDataServiceProvider.close();
         mTestLooper.dispatchAll();
-        if (mIwlanDataService != null) {
-            mIwlanDataService.onDestroy();
-        }
+        mStaticMockSession.finishMocking();
     }
 
     public Network createMockNetwork(LinkProperties linkProperties) {
@@ -349,17 +340,26 @@ public class IwlanDataServiceTest {
     }
 
     @Test
-    public void testWifiOnLost() {
-        when(mMockIwlanDataServiceProvider.getSlotIndex()).thenReturn(DEFAULT_SLOT_INDEX + 1);
-        mIwlanDataService.addIwlanDataServiceProvider(mMockIwlanDataServiceProvider);
+    public void testWifiLostInBringingDownState_shouldCloseTunnel() {
+        DataProfile dataProfile = buildImsDataProfile();
+
+        mIwlanDataServiceProvider.setTunnelState(
+                dataProfile,
+                mMockDataServiceCallback,
+                TunnelState.TUNNEL_IN_BRINGDOWN,
+                /* linkProperties */ null,
+                /* isHandover */ false,
+                /* pduSessionId */ 1,
+                /* isImsOrEmergency */ true,
+                /* isDataCallSetupWithN1 */ true);
 
         onSystemDefaultNetworkLost();
+
         assertFalse(
                 IwlanDataService.isNetworkConnected(
                         false /* isActiveDataOnOtherSub */, false /* isCstEnabled */));
-        verify(mMockIwlanDataServiceProvider).forceCloseTunnelsInDeactivatingState();
-        mIwlanDataService.removeDataServiceProvider(mMockIwlanDataServiceProvider);
-        mTestLooper.dispatchAll();
+        verify(mMockEpdgTunnelManager, atLeastOnce())
+                .closeTunnel(any(), eq(true) /* forceClose */, any(), anyInt());
     }
 
     @Test
@@ -444,7 +444,7 @@ public class IwlanDataServiceTest {
 
         clearInvocations(mMockEpdgTunnelManager);
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -583,21 +583,12 @@ public class IwlanDataServiceTest {
     }
 
     @Test
-    public void testAddDuplicateDataServiceProviderThrows() throws Exception {
-        when(mMockIwlanDataServiceProvider.getSlotIndex()).thenReturn(DEFAULT_SLOT_INDEX);
-        assertThrows(
-                IllegalStateException.class,
-                () -> mIwlanDataService.addIwlanDataServiceProvider(mMockIwlanDataServiceProvider));
-    }
-
-    @Test
-    public void testRemoveDataServiceProvider() {
-        when(mMockIwlanDataServiceProvider.getSlotIndex()).thenReturn(DEFAULT_SLOT_INDEX);
-        mIwlanDataService.removeDataServiceProvider(mMockIwlanDataServiceProvider);
-        mTestLooper.dispatchAll();
-        verify(mIwlanDataService).deinitNetworkCallback();
-        mIwlanDataService.onCreateDataServiceProvider(DEFAULT_SLOT_INDEX);
-        mTestLooper.dispatchAll();
+    public void testOnCreateDataServiceProvider_shouldCloseAndCreateNewIfExist() {
+        DataService.DataServiceProvider dataServiceProvider =
+                mIwlanDataService.onCreateDataServiceProvider(DEFAULT_SLOT_INDEX);
+        verify(mMockEpdgTunnelManager).close();
+        assertNotNull(dataServiceProvider);
+        assertNotEquals(dataServiceProvider, mIwlanDataServiceProvider);
     }
 
     @Test
@@ -610,7 +601,7 @@ public class IwlanDataServiceTest {
 
         IwlanDataServiceCallback callback = new IwlanDataServiceCallback();
         TunnelLinkProperties mLinkProperties = createTunnelLinkProperties();
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 new DataServiceCallback(callback),
                 TunnelState.TUNNEL_UP,
@@ -619,7 +610,7 @@ public class IwlanDataServiceTest {
                 1, /* pduSessionId */
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
-        mSpyIwlanDataServiceProvider.requestDataCallList(new DataServiceCallback(callback));
+        mIwlanDataServiceProvider.requestDataCallList(new DataServiceCallback(callback));
         mTestLooper.dispatchAll();
 
         assertEquals(DataServiceCallback.RESULT_SUCCESS, mResultCode);
@@ -662,7 +653,7 @@ public class IwlanDataServiceTest {
     @Test
     public void testRequestDataCallListEmpty() throws Exception {
         IwlanDataServiceCallback callback = new IwlanDataServiceCallback();
-        mSpyIwlanDataServiceProvider.requestDataCallList(new DataServiceCallback(callback));
+        mIwlanDataServiceProvider.requestDataCallList(new DataServiceCallback(callback));
         mTestLooper.dispatchAll();
 
         assertEquals(DataServiceCallback.RESULT_SUCCESS, mResultCode);
@@ -671,7 +662,7 @@ public class IwlanDataServiceTest {
 
     @Test
     public void testIwlanSetupDataCallWithInvalidArg() {
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.UNKNOWN, /* AccessNetworkType */
                 null, /* dataProfile */
                 false, /* isRoaming */
@@ -697,7 +688,7 @@ public class IwlanDataServiceTest {
         /* Wifi is not connected */
         onSystemDefaultNetworkLost();
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -719,7 +710,7 @@ public class IwlanDataServiceTest {
 
     @Test
     public void testIwlanDeactivateDataCallWithInvalidArg() {
-        mSpyIwlanDataServiceProvider.deactivateDataCall(
+        mIwlanDataServiceProvider.deactivateDataCall(
                 0, /* cid */
                 DataService.REQUEST_REASON_NORMAL, /* DataService.REQUEST_REASON_NORMAL */
                 mMockDataServiceCallback);
@@ -737,7 +728,7 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(
                 mMockNetwork, mLinkProperties, TRANSPORT_WIFI, INVALID_SUB_INDEX);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -757,7 +748,7 @@ public class IwlanDataServiceTest {
 
         /* Check callback result is RESULT_SUCCESS when onOpened() is called. */
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -774,7 +765,7 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(
                 mMockNetwork, mLinkProperties, TRANSPORT_WIFI, INVALID_SUB_INDEX);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -801,7 +792,7 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(
                 mMockNetwork, mLinkProperties, TRANSPORT_WIFI, INVALID_SUB_INDEX);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -826,7 +817,7 @@ public class IwlanDataServiceTest {
                 ArgumentCaptor.forClass(DataCallResponse.class);
 
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, tp, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -846,7 +837,7 @@ public class IwlanDataServiceTest {
 
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -856,7 +847,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.deactivateDataCall(
+        mIwlanDataServiceProvider.deactivateDataCall(
                 TEST_APN_NAME.hashCode() /* cid: hashcode() of "ims" */,
                 DataService.REQUEST_REASON_NORMAL,
                 mMockDataServiceCallback);
@@ -870,7 +861,7 @@ public class IwlanDataServiceTest {
                         eq(BRINGDOWN_REASON_DEACTIVATE_DATA_CALL));
 
         /* Check callback result is RESULT_SUCCESS when onClosed() is called. */
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -884,7 +875,7 @@ public class IwlanDataServiceTest {
 
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_UP,
@@ -894,7 +885,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.deactivateDataCall(
+        mIwlanDataServiceProvider.deactivateDataCall(
                 TEST_APN_NAME.hashCode() /* cid: hashcode() of "ims" */,
                 DataService.REQUEST_REASON_HANDOVER,
                 mMockDataServiceCallback);
@@ -910,7 +901,7 @@ public class IwlanDataServiceTest {
                         eq(BRINGDOWN_REASON_DEACTIVATE_DATA_CALL));
 
         /* Check callback result is RESULT_SUCCESS when onClosed() is called. */
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -926,7 +917,7 @@ public class IwlanDataServiceTest {
                 IwlanCarrierConfig.KEY_HANDOVER_TO_WWAN_RELEASE_DELAY_SECOND_INT, 3);
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_UP,
@@ -936,7 +927,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.deactivateDataCall(
+        mIwlanDataServiceProvider.deactivateDataCall(
                 TEST_APN_NAME.hashCode() /* cid: hashcode() of "ims" */,
                 DataService.REQUEST_REASON_HANDOVER,
                 mMockDataServiceCallback);
@@ -961,7 +952,7 @@ public class IwlanDataServiceTest {
                         eq(BRINGDOWN_REASON_DEACTIVATE_DATA_CALL));
 
         /* Check callback result is RESULT_SUCCESS when onClosed() is called. */
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -980,7 +971,7 @@ public class IwlanDataServiceTest {
 
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_UP,
@@ -990,7 +981,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, /* type IMS */
                 true,
@@ -999,7 +990,7 @@ public class IwlanDataServiceTest {
                 true,
                 1 /* Transport WiFi */);
 
-        mSpyIwlanDataServiceProvider.deactivateDataCall(
+        mIwlanDataServiceProvider.deactivateDataCall(
                 TEST_APN_NAME.hashCode() /* cid: hashcode() of "ims" */,
                 DataService.REQUEST_REASON_HANDOVER,
                 mMockDataServiceCallback);
@@ -1012,7 +1003,7 @@ public class IwlanDataServiceTest {
                         eq(TEST_APN_NAME), anyBoolean(), any(IwlanTunnelCallback.class), anyInt());
 
         /* Check callback result is RESULT_SUCCESS when onClosed() is called. */
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1038,7 +1029,7 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.USER_AUTHENTICATION);
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1048,7 +1039,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, // type IMS
                 true,
@@ -1058,7 +1049,7 @@ public class IwlanDataServiceTest {
                 1 // Transport Wi-Fi
                 );
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1089,7 +1080,7 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.shouldRetryWithInitialAttach(eq(TEST_APN_NAME)))
                 .thenReturn(false);
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1099,7 +1090,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, // type IMS
                 true,
@@ -1109,7 +1100,7 @@ public class IwlanDataServiceTest {
                 1 // Transport Wi-Fi
                 );
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1149,7 +1140,7 @@ public class IwlanDataServiceTest {
                         CALL_STATE_IDLE)
                 .sendToTarget();
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1159,7 +1150,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, // type IMS
                 true,
@@ -1169,7 +1160,7 @@ public class IwlanDataServiceTest {
                 1 // Transport Wi-Fi
                 );
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1206,7 +1197,7 @@ public class IwlanDataServiceTest {
                         CALL_STATE_IDLE)
                 .sendToTarget();
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1216,7 +1207,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 512, // type Emergency
                 true,
@@ -1226,7 +1217,7 @@ public class IwlanDataServiceTest {
                 1 // Transport Wi-Fi
                 );
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1263,7 +1254,7 @@ public class IwlanDataServiceTest {
                         TelephonyManager.CALL_STATE_OFFHOOK)
                 .sendToTarget();
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1273,7 +1264,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, // type IMS
                 true,
@@ -1283,7 +1274,7 @@ public class IwlanDataServiceTest {
                 1 // Transport Wi-Fi
                 );
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1320,7 +1311,7 @@ public class IwlanDataServiceTest {
                         TelephonyManager.CALL_STATE_OFFHOOK)
                 .sendToTarget();
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1330,7 +1321,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 512, // type Emergency
                 true,
@@ -1340,7 +1331,7 @@ public class IwlanDataServiceTest {
                 1 // Transport Wi-Fi
                 );
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1477,7 +1468,7 @@ public class IwlanDataServiceTest {
                         TRANSPORT_CELLULAR, DEFAULT_SUB_INDEX, false /* isVcn */);
         getNetworkMonitorCallback().onCapabilitiesChanged(mMockNetwork, nc);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -1509,7 +1500,7 @@ public class IwlanDataServiceTest {
                         TRANSPORT_CELLULAR, DEFAULT_SUB_INDEX, false /* isVcn */);
         getNetworkMonitorCallback().onCapabilitiesChanged(mMockNetwork, nc);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -1542,7 +1533,7 @@ public class IwlanDataServiceTest {
                         TRANSPORT_CELLULAR, DEFAULT_SUB_INDEX + 1, false /* isVcn */);
         getNetworkMonitorCallback().onCapabilitiesChanged(mMockNetwork, nc);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -1562,7 +1553,7 @@ public class IwlanDataServiceTest {
 
         /* Check callback result is RESULT_SUCCESS when onOpened() is called. */
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -1585,7 +1576,7 @@ public class IwlanDataServiceTest {
         }
 
         IwlanDataServiceProvider.IwlanDataTunnelStats stats =
-                mSpyIwlanDataServiceProvider.getTunnelStats();
+                mIwlanDataServiceProvider.getTunnelStats();
         long result = stats.mTunnelSetupFailureCounts.get(TEST_APN_NAME);
         assertEquals(count, result);
     }
@@ -1607,7 +1598,7 @@ public class IwlanDataServiceTest {
         }
 
         IwlanDataServiceProvider.IwlanDataTunnelStats stats =
-                mSpyIwlanDataServiceProvider.getTunnelStats();
+                mIwlanDataServiceProvider.getTunnelStats();
         long result = stats.mUnsolTunnelDownCounts.get(TEST_APN_NAME);
         assertEquals(result, count);
     }
@@ -1618,7 +1609,7 @@ public class IwlanDataServiceTest {
         Calendar calendar = mock(Calendar.class);
         when(calendar.getTime()).thenAnswer(i -> new Date(mMockedCalendarTime));
 
-        mSpyIwlanDataServiceProvider.setCalendar(calendar);
+        mIwlanDataServiceProvider.setCalendar(calendar);
         onSystemDefaultNetworkConnected(
                 mMockNetwork, mLinkProperties, TRANSPORT_WIFI, INVALID_SUB_INDEX);
 
@@ -1650,7 +1641,7 @@ public class IwlanDataServiceTest {
         tunnelUpStats.accept(tunnelDown.getTime() - tunnelUp.getTime());
 
         IwlanDataServiceProvider.IwlanDataTunnelStats stats =
-                mSpyIwlanDataServiceProvider.getTunnelStats();
+                mIwlanDataServiceProvider.getTunnelStats();
         LongSummaryStatistics finalSetupStats = stats.mTunnelSetupSuccessStats.get(TEST_APN_NAME);
         LongSummaryStatistics finalUpStats = stats.mTunnelUpStats.get(TEST_APN_NAME);
 
@@ -1672,7 +1663,7 @@ public class IwlanDataServiceTest {
     public void testIwlanDataServiceHandlerOnUnbind() {
         DataProfile dp = buildImsDataProfile();
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_UP,
@@ -1682,7 +1673,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, // type IMS
                 true,
@@ -1696,9 +1687,9 @@ public class IwlanDataServiceTest {
                 .thenReturn(DataFailCause.ERROR_UNSPECIFIED);
 
         // Simulate IwlanDataService.onUnbind() which force close all tunnels
-        mSpyIwlanDataServiceProvider.forceCloseTunnels(EpdgTunnelManager.BRINGDOWN_REASON_UNKNOWN);
+        mIwlanDataServiceProvider.forceCloseTunnels(EpdgTunnelManager.BRINGDOWN_REASON_UNKNOWN);
         // Simulate DataService.onUnbind() which remove all IwlanDataServiceProviders
-        mSpyIwlanDataServiceProvider.close();
+        mIwlanDataServiceProvider.close();
         mTestLooper.dispatchAll();
 
         verify(mMockEpdgTunnelManager, atLeastOnce())
@@ -1710,7 +1701,7 @@ public class IwlanDataServiceTest {
         assertNotNull(mIwlanDataService.mHandler);
         verify(mMockEpdgTunnelManager, times(1)).close();
         // Should not raise NullPointerException
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1726,7 +1717,7 @@ public class IwlanDataServiceTest {
     public void testMetricsWhenTunnelClosedWithWrappedException() {
         DataProfile dp = buildImsDataProfile();
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1736,7 +1727,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, // type IMS
                 true,
@@ -1746,7 +1737,7 @@ public class IwlanDataServiceTest {
                 1 // Transport Wi-Fi
                 );
 
-        MetricsAtom metricsAtom = mSpyIwlanDataServiceProvider.getMetricsAtomByApn(TEST_APN_NAME);
+        MetricsAtom metricsAtom = mIwlanDataServiceProvider.getMetricsAtomByApn(TEST_APN_NAME);
         assertNotNull(metricsAtom);
 
         String exceptionMessage = "Some exception message";
@@ -1768,7 +1759,7 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
                 .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(
                         TEST_APN_NAME,
@@ -1798,7 +1789,7 @@ public class IwlanDataServiceTest {
     public void testMetricsWhenTunnelClosedWithoutWrappedException() {
         DataProfile dp = buildImsDataProfile();
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1808,7 +1799,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, // type IMS
                 true,
@@ -1818,7 +1809,7 @@ public class IwlanDataServiceTest {
                 1 // Transport Wi-Fi
                 );
 
-        MetricsAtom metricsAtom = mSpyIwlanDataServiceProvider.getMetricsAtomByApn(TEST_APN_NAME);
+        MetricsAtom metricsAtom = mIwlanDataServiceProvider.getMetricsAtomByApn(TEST_APN_NAME);
         assertNotNull(metricsAtom);
 
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
@@ -1827,7 +1818,7 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
                 .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(
                         TEST_APN_NAME,
@@ -1844,7 +1835,7 @@ public class IwlanDataServiceTest {
     public void testMetricsWhenTunnelClosedWithErrorCount() {
         DataProfile dp = buildImsDataProfile();
 
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_IN_BRINGUP,
@@ -1854,7 +1845,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, /* type IMS */
                 true,
@@ -1863,7 +1854,7 @@ public class IwlanDataServiceTest {
                 true,
                 1 /* Transport Wi-Fi */);
 
-        MetricsAtom metricsAtom = mSpyIwlanDataServiceProvider.getMetricsAtomByApn(TEST_APN_NAME);
+        MetricsAtom metricsAtom = mIwlanDataServiceProvider.getMetricsAtomByApn(TEST_APN_NAME);
         assertNotNull(metricsAtom);
 
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
@@ -1874,7 +1865,7 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
                 .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(
                         TEST_APN_NAME,
@@ -1886,7 +1877,7 @@ public class IwlanDataServiceTest {
     }
 
     private void mockTunnelSetupFail(DataProfile dp) {
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -1902,7 +1893,7 @@ public class IwlanDataServiceTest {
                 .when(mMockEpdgTunnelManager)
                 .bringUpTunnel(any(TunnelSetupRequest.class), any(IwlanTunnelCallback.class));
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(
                         TEST_APN_NAME,
@@ -1915,7 +1906,7 @@ public class IwlanDataServiceTest {
     }
 
     private void mockTunnelSetupSuccess(DataProfile dp, long setupTime, Calendar calendar) {
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -1935,7 +1926,7 @@ public class IwlanDataServiceTest {
         advanceCalendarByTimeMs(setupTime, calendar);
 
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -1945,7 +1936,7 @@ public class IwlanDataServiceTest {
     }
 
     private void mockUnsolTunnelDown() {
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(
                         TEST_APN_NAME,
@@ -1955,7 +1946,7 @@ public class IwlanDataServiceTest {
     }
 
     private void mockDeactivateTunnel(long deactivationTime, Calendar calendar) {
-        mSpyIwlanDataServiceProvider.deactivateDataCall(
+        mIwlanDataServiceProvider.deactivateDataCall(
                 TEST_APN_NAME.hashCode() /* cid: hashcode() of "ims" */,
                 DataService.REQUEST_REASON_NORMAL /* DataService.REQUEST_REASON_NORMAL */,
                 mMockDataServiceCallback);
@@ -1969,7 +1960,7 @@ public class IwlanDataServiceTest {
 
         advanceCalendarByTimeMs(deactivationTime, calendar);
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -1992,7 +1983,7 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(
                 newNetwork1, mLinkProperties, TRANSPORT_WIFI, DEFAULT_SUB_INDEX);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -2079,7 +2070,7 @@ public class IwlanDataServiceTest {
 
         sendCallStateChangedEvent(callState);
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME, 64, true, TelephonyManager.NETWORK_TYPE_LTE, false, true, 1);
     }
 
@@ -2105,7 +2096,7 @@ public class IwlanDataServiceTest {
                     CarrierConfigManager.CARRIER_NR_AVAILABILITY_SA
                 });
         IwlanCarrierConfig.putTestConfigBundle(bundle);
-        assertTrue(mSpyIwlanDataServiceProvider.isN1ModeSupported());
+        assertTrue(mIwlanDataServiceProvider.isN1ModeSupported());
 
         bundle.putIntArray(
                 CarrierConfigManager.KEY_CARRIER_NR_AVAILABILITIES_INT_ARRAY,
@@ -2113,7 +2104,7 @@ public class IwlanDataServiceTest {
                     CarrierConfigManager.CARRIER_NR_AVAILABILITY_NSA,
                 });
         IwlanCarrierConfig.putTestConfigBundle(bundle);
-        assertFalse(mSpyIwlanDataServiceProvider.isN1ModeSupported());
+        assertFalse(mIwlanDataServiceProvider.isN1ModeSupported());
     }
 
     @Test
@@ -2126,7 +2117,7 @@ public class IwlanDataServiceTest {
         mockCallState(CALL_STATE_IDLE);
         mockSetupDataCallWithPduSessionId(0);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2143,7 +2134,7 @@ public class IwlanDataServiceTest {
                         any(IwlanTunnelCallback.class),
                         eq(EpdgTunnelManager.BRINGDOWN_REASON_ENABLE_N1_MODE));
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -2166,7 +2157,7 @@ public class IwlanDataServiceTest {
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
         mockSetupDataCallWithPduSessionId(5 /* pduSessionId */);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2183,7 +2174,7 @@ public class IwlanDataServiceTest {
                         any(IwlanTunnelCallback.class),
                         eq(EpdgTunnelManager.BRINGDOWN_REASON_DISABLE_N1_MODE));
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -2207,7 +2198,7 @@ public class IwlanDataServiceTest {
         mockCallState(CALL_STATE_RINGING);
         mockSetupDataCallWithPduSessionId(0);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2237,7 +2228,7 @@ public class IwlanDataServiceTest {
                         any(IwlanTunnelCallback.class),
                         eq(EpdgTunnelManager.BRINGDOWN_REASON_ENABLE_N1_MODE));
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -2259,7 +2250,7 @@ public class IwlanDataServiceTest {
         mockCallState(CALL_STATE_RINGING);
         mockSetupDataCallWithPduSessionId(0);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2293,7 +2284,7 @@ public class IwlanDataServiceTest {
         mockCallState(CALL_STATE_IDLE);
         mockSetupDataCallWithPduSessionId(0);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2314,7 +2305,7 @@ public class IwlanDataServiceTest {
         mockCallState(CALL_STATE_IDLE);
         mockSetupDataCallWithPduSessionId(0);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2334,7 +2325,7 @@ public class IwlanDataServiceTest {
 
         mockSetupDataCallWithPduSessionId(1);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2357,7 +2348,7 @@ public class IwlanDataServiceTest {
 
         mockSetupDataCallWithPduSessionId(0);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2374,7 +2365,7 @@ public class IwlanDataServiceTest {
         updatePreferredNetworkType(NETWORK_TYPE_BITMASK_NR);
         mockSetupDataCallWithPduSessionId(1);
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(TEST_APN_NAME, mMockTunnelLinkProperties, mMockOnOpenedMetrics);
         mTestLooper.dispatchAll();
@@ -2395,7 +2386,7 @@ public class IwlanDataServiceTest {
     private void verifySetupDataCallRequestHandled(int pduSessionId, DataProfile dp) {
         onSystemDefaultNetworkConnected(
                 mMockNetwork, mLinkProperties, TRANSPORT_WIFI, INVALID_SUB_INDEX);
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -2447,7 +2438,7 @@ public class IwlanDataServiceTest {
         int index = 0;
         String apnName = "mms";
         ArrayList<Integer> resultCodeCallback = new ArrayList<>();
-        mSpyIwlanDataServiceProvider.requestNetworkValidation(
+        mIwlanDataServiceProvider.requestNetworkValidation(
                 apnName.hashCode(), Runnable::run, resultCodeCallback::add);
         mTestLooper.dispatchAll();
 
@@ -2462,7 +2453,7 @@ public class IwlanDataServiceTest {
         verifySetupDataCallRequestHandled(5 /* pduSessionId */, dp);
 
         stubMockOnOpenedMetrics();
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onOpened(
                         dp.getApnSetting().getApnName(),
@@ -2474,7 +2465,7 @@ public class IwlanDataServiceTest {
     private List<DataCallResponse> verifyDataCallListChangeAndCaptureUpdatedList() {
         ArgumentCaptor<List<DataCallResponse>> dataCallListCaptor =
                 ArgumentCaptor.forClass((Class) List.class);
-        verify(mSpyIwlanDataServiceProvider, atLeastOnce())
+        verify(mIwlanDataServiceProvider, atLeastOnce())
                 .notifyDataCallListChanged(dataCallListCaptor.capture());
         return dataCallListCaptor.getValue();
     }
@@ -2496,6 +2487,9 @@ public class IwlanDataServiceTest {
     }
 
     @Test
+    @Ignore(
+            "b/324874097 - Fix IwlanDataServiceTest to correctly spy on IwlanDataServiceProvider."
+                    + " Address flakiness caused by Mockito spy instrumentation issues on Android.")
     public void testOnNetworkValidationStatusChangedForRegisteredApn() {
         List<DataCallResponse> dataCallList;
 
@@ -2507,30 +2501,22 @@ public class IwlanDataServiceTest {
         verifySetupDataCallSuccess(dp);
         dataCallList = verifyDataCallListChangeAndCaptureUpdatedList();
         assertEquals(1, dataCallList.size());
-        // TODO: b/324874097 - Fix IwlanDataServiceTest to correctly spy on
-        // IwlanDataServiceProvider. Address flakiness caused by Mockito spy instrumentation issues
-        // on Android. Investigate solutions.
-        //
-        // assertDataCallResponsePresentByCidAndStatus(
-        //        cid, PreciseDataConnectionState.NETWORK_VALIDATION_SUCCESS, dataCallList);
+        assertDataCallResponsePresentByCidAndStatus(
+                cid, PreciseDataConnectionState.NETWORK_VALIDATION_SUCCESS, dataCallList);
 
         // Requests network validation
-        mSpyIwlanDataServiceProvider.requestNetworkValidation(
+        mIwlanDataServiceProvider.requestNetworkValidation(
                 cid, Runnable::run, mockResultCodeCallback);
         mTestLooper.dispatchAll();
         verify(mockResultCodeCallback, times(1)).accept(DataServiceCallback.RESULT_SUCCESS);
 
         dataCallList = verifyDataCallListChangeAndCaptureUpdatedList();
         assertEquals(1, dataCallList.size());
-        // TODO: b/324874097 - Fix IwlanDataServiceTest to correctly spy on
-        // IwlanDataServiceProvider. Address flakiness caused by Mockito spy instrumentation issues
-        // on Android. Investigate solutions.
-        //
-        // assertDataCallResponsePresentByCidAndStatus(
-        //        cid, PreciseDataConnectionState.NETWORK_VALIDATION_IN_PROGRESS, dataCallList);
+        assertDataCallResponsePresentByCidAndStatus(
+                cid, PreciseDataConnectionState.NETWORK_VALIDATION_IN_PROGRESS, dataCallList);
 
         // Validation success
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onNetworkValidationStatusChanged(
                         dp.getApnSetting().getApnName(),
@@ -2539,12 +2525,8 @@ public class IwlanDataServiceTest {
 
         dataCallList = verifyDataCallListChangeAndCaptureUpdatedList();
         assertEquals(1, dataCallList.size());
-        // TODO: b/324874097 - Fix IwlanDataServiceTest to correctly spy on
-        // IwlanDataServiceProvider. Address flakiness caused by Mockito spy instrumentation issues
-        // on Android. Investigate solutions.
-        //
-        // assertDataCallResponsePresentByCidAndStatus(
-        //        cid, PreciseDataConnectionState.NETWORK_VALIDATION_SUCCESS, dataCallList);
+        assertDataCallResponsePresentByCidAndStatus(
+                cid, PreciseDataConnectionState.NETWORK_VALIDATION_SUCCESS, dataCallList);
     }
 
     @Test
@@ -2558,13 +2540,13 @@ public class IwlanDataServiceTest {
         verifySetupDataCallSuccess(dp);
 
         // Requests network validation, network validation status in progress
-        mSpyIwlanDataServiceProvider.requestNetworkValidation(
+        mIwlanDataServiceProvider.requestNetworkValidation(
                 cid, Runnable::run, mockResultCodeCallback);
         mTestLooper.dispatchAll();
         verify(mockResultCodeCallback, times(1)).accept(DataServiceCallback.RESULT_SUCCESS);
 
         // Requests data call list
-        mSpyIwlanDataServiceProvider.requestDataCallList(mMockDataServiceCallback);
+        mIwlanDataServiceProvider.requestDataCallList(mMockDataServiceCallback);
         mTestLooper.dispatchAll();
 
         verify(mMockDataServiceCallback)
@@ -2587,7 +2569,7 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
         DataProfile dp = buildImsDataProfile();
-        mSpyIwlanDataServiceProvider.setTunnelState(
+        mIwlanDataServiceProvider.setTunnelState(
                 dp,
                 mMockDataServiceCallback,
                 TunnelState.TUNNEL_UP,
@@ -2597,7 +2579,7 @@ public class IwlanDataServiceTest {
                 true /* isImsOrEmergency */,
                 true /* isDataCallSetupWithN1 */);
 
-        mSpyIwlanDataServiceProvider.deactivateDataCall(
+        mIwlanDataServiceProvider.deactivateDataCall(
                 TEST_APN_NAME.hashCode() /* cid: hashcode() of "ims" */,
                 DataService.REQUEST_REASON_HANDOVER,
                 mMockDataServiceCallback);
@@ -2609,7 +2591,7 @@ public class IwlanDataServiceTest {
                 .closeTunnel(
                         eq(TEST_APN_NAME), anyBoolean(), any(IwlanTunnelCallback.class), anyInt());
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -2632,7 +2614,7 @@ public class IwlanDataServiceTest {
         verify(mMockDataServiceCallback)
                 .onSetupDataCallComplete(
                         eq(DataServiceCallback.RESULT_ERROR_TEMPORARILY_UNAVAILABLE), isNull());
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -2652,7 +2634,7 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
         DataProfile dp = buildImsDataProfile();
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -2678,7 +2660,7 @@ public class IwlanDataServiceTest {
                                 EpdgTunnelManager
                                         .BRINGDOWN_REASON_NETWORK_UPDATE_WHEN_TUNNEL_IN_BRINGUP));
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -2700,7 +2682,7 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.USER_AUTHENTICATION);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -2714,7 +2696,7 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         mTestLooper.dispatchAll();
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, /* type IMS */
                 true,
@@ -2723,7 +2705,7 @@ public class IwlanDataServiceTest {
                 true,
                 1 /* Transport Wi-Fi */);
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -2749,7 +2731,7 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.USER_AUTHENTICATION);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -2763,7 +2745,7 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         mTestLooper.dispatchAll();
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, /* type IMS */
                 true,
@@ -2772,7 +2754,7 @@ public class IwlanDataServiceTest {
                 true,
                 1 /* Transport Wi-Fi */);
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
@@ -2852,7 +2834,7 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.USER_AUTHENTICATION);
 
-        mSpyIwlanDataServiceProvider.setupDataCall(
+        mIwlanDataServiceProvider.setupDataCall(
                 AccessNetworkType.IWLAN, /* AccessNetworkType */
                 dp, /* dataProfile */
                 false, /* isRoaming */
@@ -2866,7 +2848,7 @@ public class IwlanDataServiceTest {
                 mMockDataServiceCallback);
         mTestLooper.dispatchAll();
 
-        mSpyIwlanDataServiceProvider.setMetricsAtom(
+        mIwlanDataServiceProvider.setMetricsAtom(
                 TEST_APN_NAME,
                 64, /* type IMS */
                 true,
@@ -2875,7 +2857,7 @@ public class IwlanDataServiceTest {
                 true,
                 1 /* Transport Wi-Fi */);
 
-        mSpyIwlanDataServiceProvider
+        mIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(TEST_APN_NAME, new IwlanError(IwlanError.NO_ERROR), mMockOnClosedMetrics);
         mTestLooper.dispatchAll();
diff --git a/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java b/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
index 9317c36..60e0f24 100644
--- a/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
+++ b/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
@@ -17,9 +17,9 @@
 package com.google.android.iwlan.epdg;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
+import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 
 import static com.google.android.iwlan.epdg.EpdgTunnelManager.BRINGDOWN_REASON_UNKNOWN;
-import static com.google.android.iwlan.proto.MetricsAtom.*;
 
 import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
@@ -42,7 +42,6 @@ import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.reset;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
-import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.content.Context;
@@ -84,16 +83,26 @@ import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
 import android.telephony.data.ApnSetting;
 import android.util.Pair;
+import android.util.StatsEvent;
+import android.util.StatsEventTestUtils;
+import android.util.StatsLog;
+
+import com.android.os.AtomsProto;
+import com.android.os.AtomsProto.Atom;
+import com.android.os.telephony.iwlan.IwlanExtensionAtoms;
+import com.android.os.telephony.iwlan.IwlanProtoEnums;
+import com.android.os.telephony.iwlan.IwlanUnderlyingNetworkValidationResultReported;
 
 import com.google.android.iwlan.ErrorPolicyManager;
 import com.google.android.iwlan.IwlanCarrierConfig;
 import com.google.android.iwlan.IwlanError;
 import com.google.android.iwlan.IwlanHelper;
-import com.google.android.iwlan.IwlanStatsLog;
 import com.google.android.iwlan.TunnelMetricsInterface.OnClosedMetrics;
 import com.google.android.iwlan.TunnelMetricsInterface.OnOpenedMetrics;
 import com.google.android.iwlan.flags.FeatureFlags;
-import com.google.android.iwlan.proto.MetricsAtom;
+import com.google.protobuf.CodedInputStream;
+import com.google.protobuf.CodedOutputStream;
+import com.google.protobuf.ExtensionRegistryLite;
 
 import org.junit.After;
 import org.junit.Before;
@@ -101,11 +110,14 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+import java.io.ByteArrayInputStream;
+import java.io.ByteArrayOutputStream;
 import java.io.IOException;
 import java.net.Inet4Address;
 import java.net.Inet6Address;
@@ -159,6 +171,7 @@ public class EpdgTunnelManagerTest {
 
     private final TestLooper mTestLooper = new TestLooper();
 
+    @Captor ArgumentCaptor<StatsEvent> mStatsEventCaptor;
     @Mock private Context mMockContext;
     @Mock private Network mMockDefaultNetwork;
     @Mock private IwlanTunnelCallback mMockIwlanTunnelCallback;
@@ -189,6 +202,7 @@ public class EpdgTunnelManagerTest {
             mConnectivityDiagnosticsCallbackArgumentCaptor =
                     ArgumentCaptor.forClass(
                             ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback.class);
+    private ExtensionRegistryLite mRegistry;
 
     static class IkeSessionArgumentCaptors {
         ArgumentCaptor<IkeSessionParams> mIkeSessionParamsCaptor =
@@ -209,7 +223,7 @@ public class EpdgTunnelManagerTest {
                 mockitoSession()
                         .mockStatic(EpdgSelector.class)
                         .mockStatic(ErrorPolicyManager.class)
-                        .mockStatic(IwlanStatsLog.class)
+                        .mockStatic(StatsLog.class)
                         .spyStatic(IwlanHelper.class)
                         .strictness(Strictness.LENIENT)
                         .startMocking();
@@ -285,6 +299,8 @@ public class EpdgTunnelManagerTest {
         when(mMockLinkProperties.isReachable(any())).thenReturn(true);
         mEpdgTunnelManager.updateNetwork(mMockDefaultNetwork, mMockLinkProperties);
         mTestLooper.dispatchAll();
+        mRegistry = ExtensionRegistryLite.newInstance();
+        IwlanExtensionAtoms.registerAllExtensions(mRegistry);
     }
 
     @After
@@ -3329,19 +3345,53 @@ public class EpdgTunnelManagerTest {
                 .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
     }
 
+    private Atom getAtomWithExtensions(Atom atom) throws Exception {
+        // The returned atom does not have external extensions registered.
+        // So we serialize and then deserialize with extensions registered.
+        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
+        CodedOutputStream codedos = CodedOutputStream.newInstance(outputStream);
+        atom.writeTo(codedos);
+        codedos.flush();
+
+        ByteArrayInputStream inputStream = new ByteArrayInputStream(outputStream.toByteArray());
+        CodedInputStream codedis = CodedInputStream.newInstance(inputStream);
+        return AtomsProto.Atom.parseFrom(codedis, mRegistry);
+    }
+
+    private List<Atom> getValidationAtomList(List<StatsEvent> atomList) {
+        return atomList.stream()
+                .map(
+                        statsEvent -> {
+                            try {
+                                return getAtomWithExtensions(
+                                        StatsEventTestUtils.convertToAtom(statsEvent));
+                            } catch (Exception e) {
+                                throw new RuntimeException(e);
+                            }
+                        })
+                .filter(
+                        atom ->
+                                atom.hasExtension(
+                                        IwlanExtensionAtoms
+                                                .iwlanUnderlyingNetworkValidationResultReported))
+                .toList();
+    }
+
     private void verifyValidationMetricsAtom(
-            MetricsAtom metricsAtom,
-            int triggerReason,
+            Atom atom,
+            int triggerEvent,
             int validationResult,
             int transportType,
-            int duration) {
-        assertEquals(
-                IwlanStatsLog.IWLAN_UNDERLYING_NETWORK_VALIDATION_RESULT_REPORTED,
-                metricsAtom.getMessageId());
-        assertEquals(triggerReason, metricsAtom.getTriggerReason());
-        assertEquals(validationResult, metricsAtom.getValidationResult());
-        assertEquals(transportType, metricsAtom.getValidationTransportType());
-        assertEquals(duration, metricsAtom.getValidationDurationMills());
+            int duration,
+            boolean validationTriggered) {
+        IwlanUnderlyingNetworkValidationResultReported result =
+                atom.getExtension(
+                        IwlanExtensionAtoms.iwlanUnderlyingNetworkValidationResultReported);
+        assertEquals(triggerEvent, result.getTriggerEvent().getNumber());
+        assertEquals(validationResult, result.getValidationResult().getNumber());
+        assertEquals(transportType, result.getTransportType().getNumber());
+        assertEquals(duration, result.getValidationDurationMillis());
+        assertEquals(validationTriggered, result.getValidationTriggered());
     }
 
     private ConnectivityReport createConnectivityReport(Network network, int validationResult) {
@@ -3356,7 +3406,7 @@ public class EpdgTunnelManagerTest {
     }
 
     @Test
-    public void testReportValidationMetricsAtom_Validated() {
+    public void testReportValidationMetricsAtom_Validated() throws Exception {
         ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback callback =
                 mConnectivityDiagnosticsCallbackArgumentCaptor.getValue();
         when(mMockNetworkCapabilities.hasCapability(
@@ -3378,22 +3428,26 @@ public class EpdgTunnelManagerTest {
         verify(mMockConnectivityManager, times(1))
                 .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
 
-        MetricsAtom metricsAtom = mEpdgTunnelManager.getValidationMetricsAtom(mMockDefaultNetwork);
         advanceClockByTimeMs(1000);
         callback.onConnectivityReportAvailable(
                 createConnectivityReport(
                         mMockDefaultNetwork, ConnectivityReport.NETWORK_VALIDATION_RESULT_VALID));
 
+        verify(() -> StatsLog.write(mStatsEventCaptor.capture()), atLeastOnce());
+        List<Atom> validationResultAtomList =
+                getValidationAtomList(mStatsEventCaptor.getAllValues());
+        assertEquals(1, validationResultAtomList.size());
         verifyValidationMetricsAtom(
-                metricsAtom,
-                NETWORK_VALIDATION_EVENT_MAKING_CALL,
-                NETWORK_VALIDATION_RESULT_VALID,
-                NETWORK_VALIDATION_TRANSPORT_TYPE_WIFI,
-                /* duration= */ 1000);
+                validationResultAtomList.getFirst(),
+                IwlanProtoEnums.NETWORK_VALIDATION_EVENT_MAKING_CALL,
+                IwlanProtoEnums.NETWORK_VALIDATION_RESULT_VALID,
+                IwlanProtoEnums.TRANSPORT_TYPE_WIFI,
+                /* duration= */ 1000,
+                true);
     }
 
     @Test
-    public void testReportValidationMetricsAtom_NotValidated() {
+    public void testReportValidationMetricsAtom_NotValidated() throws Exception {
         ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback callback =
                 mConnectivityDiagnosticsCallbackArgumentCaptor.getValue();
         when(mMockNetworkCapabilities.hasCapability(
@@ -3415,18 +3469,74 @@ public class EpdgTunnelManagerTest {
         verify(mMockConnectivityManager, times(1))
                 .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
 
-        MetricsAtom metricsAtom = mEpdgTunnelManager.getValidationMetricsAtom(mMockDefaultNetwork);
         advanceClockByTimeMs(1000);
         callback.onConnectivityReportAvailable(
                 createConnectivityReport(
                         mMockDefaultNetwork, ConnectivityReport.NETWORK_VALIDATION_RESULT_INVALID));
 
+        verify(() -> StatsLog.write(mStatsEventCaptor.capture()), atLeastOnce());
+        List<Atom> validationResultAtomList =
+                getValidationAtomList(mStatsEventCaptor.getAllValues());
+        assertEquals(1, validationResultAtomList.size());
         verifyValidationMetricsAtom(
-                metricsAtom,
-                NETWORK_VALIDATION_EVENT_SCREEN_ON,
-                NETWORK_VALIDATION_RESULT_INVALID,
-                NETWORK_VALIDATION_TRANSPORT_TYPE_CELLULAR,
-                /* duration= */ 1000);
+                validationResultAtomList.getFirst(),
+                IwlanProtoEnums.NETWORK_VALIDATION_EVENT_SCREEN_ON,
+                IwlanProtoEnums.NETWORK_VALIDATION_RESULT_INVALID,
+                IwlanProtoEnums.TRANSPORT_TYPE_CELLULAR,
+                /* duration= */ 1000,
+                true);
+    }
+
+    @Test
+    public void testReportValidationMetricsAtom_validationNotTriggered() throws Exception {
+        when(mMockNetworkCapabilities.hasCapability(
+                        eq(NetworkCapabilities.NET_CAPABILITY_VALIDATED)))
+                .thenReturn(false);
+        when(mMockNetworkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
+                .thenReturn(true);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL,
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON
+                });
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
+        mTestLooper.dispatchAll();
+        verify(mMockConnectivityManager, never())
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
+
+        verify(() -> StatsLog.write(mStatsEventCaptor.capture()), atLeastOnce());
+        List<Atom> validationResultAtomList =
+                getValidationAtomList(mStatsEventCaptor.getAllValues());
+        assertEquals(1, validationResultAtomList.size());
+        verifyValidationMetricsAtom(
+                validationResultAtomList.getFirst(),
+                IwlanProtoEnums.NETWORK_VALIDATION_EVENT_SCREEN_ON,
+                IwlanProtoEnums.NETWORK_VALIDATION_RESULT_INVALID,
+                IwlanProtoEnums.TRANSPORT_TYPE_CELLULAR,
+                /* duration= */ 0,
+                false);
+    }
+
+    @Test
+    public void testReportValidationMetricsAtom_networkLost() {
+        mEpdgTunnelManager.updateNetwork(/* network= */ null, /* linkProperties= */ null);
+        IwlanCarrierConfig.putTestConfigIntArray(
+                IwlanCarrierConfig.KEY_UNDERLYING_NETWORK_VALIDATION_EVENTS_INT_ARRAY,
+                new int[] {
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL,
+                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON
+                });
+
+        advanceClockByTimeMs(100000);
+        mEpdgTunnelManager.validateUnderlyingNetwork(
+                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
+        mTestLooper.dispatchAll();
+        verify(mMockConnectivityManager, never())
+                .reportNetworkConnectivity(eq(mMockDefaultNetwork), eq(false));
     }
 
     @Test
```

