```diff
diff --git a/src/com/android/ons/ONSAutoBoot.java b/src/com/android/ons/ONSAutoBoot.java
index 77c5c8f..bfb0ebf 100644
--- a/src/com/android/ons/ONSAutoBoot.java
+++ b/src/com/android/ons/ONSAutoBoot.java
@@ -22,6 +22,11 @@ import android.content.Context;
 import android.content.Intent;
 import android.util.Log;
 
+/**
+ * ONSAutoBoot is a {@link BroadcastReceiver} that listens to
+ * {@link Intent#ACTION_LOCKED_BOOT_COMPLETED} event. Once the event is received, it will start
+ * {@link OpportunisticNetworkService}.
+ */
 public class ONSAutoBoot extends BroadcastReceiver {
     private static final String TAG = "ONSAutoboot";
 
@@ -33,7 +38,7 @@ public class ONSAutoBoot extends BroadcastReceiver {
                     OpportunisticNetworkService.class.getName());
             ComponentName service = context.startService(new Intent().setComponent(comp));
             if (service == null) {
-                Log.d(TAG, "Could not start service " + comp.toString());
+                Log.d(TAG, "Could not start service " + comp);
             }
         }
     }
diff --git a/src/com/android/ons/ONSConfigInput.java b/src/com/android/ons/ONSConfigInput.java
index 8cdab96..6542a74 100644
--- a/src/com/android/ons/ONSConfigInput.java
+++ b/src/com/android/ons/ONSConfigInput.java
@@ -16,67 +16,31 @@
 
 package com.android.ons;
 
+import static android.telephony.SubscriptionManager.INVALID_SUBSCRIPTION_ID;
+
 import android.telephony.AvailableNetworkInfo;
-import android.telephony.SubscriptionManager;
 
 import com.android.internal.telephony.IUpdateAvailableNetworksCallback;
 
-import java.util.ArrayList;
 import java.util.List;
 
 /**
- * OpportunisticNetworkService implements ions.
- * It scans network and matches the results with opportunistic subscriptions.
- * Use the same to provide user opportunistic data in areas with corresponding networks
+ * ONSConfigInput is data class that passes configuration parameters to
+ * {@link OpportunisticNetworkService}.
  */
-public class ONSConfigInput {
-    private static final String TAG = "ONSConfigInput";
-    private static final boolean DBG = true;
-    private ArrayList<AvailableNetworkInfo> mAvailableNetworkInfos;
-    private int mPreferredDataSub;
-    private int mPrimarySub;
-    private IUpdateAvailableNetworksCallback mAvailableNetworkCallback;
-
-    ONSConfigInput(ArrayList<AvailableNetworkInfo> availableNetworkInfos,
+public record ONSConfigInput(List<AvailableNetworkInfo> availableNetworkInfos,
+                             IUpdateAvailableNetworksCallback availableNetworkCallback,
+                             int preferredDataSub, int primarySub) {
+    /**
+     * Construct ONSConfigInput with INVALID_SUBSCRIPTION_ID as default value for both {@code
+     * preferredDataSub} and {@code primarySub}
+     *
+     * @param availableNetworkInfos A List of AvailableNetworkInfo
+     * @param callback              IUpdateAvailableNetworksCallback to receive callback on update
+     */
+    public ONSConfigInput(List<AvailableNetworkInfo> availableNetworkInfos,
             IUpdateAvailableNetworksCallback callback) {
-        mAvailableNetworkInfos = availableNetworkInfos;
-        mPreferredDataSub = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
-        mPrimarySub = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
-        mAvailableNetworkCallback = callback;
-    }
-
-    public IUpdateAvailableNetworksCallback getAvailableNetworkCallback() {
-        return mAvailableNetworkCallback;
-    }
-
-    public void setAvailableNetworkInfo(ArrayList<AvailableNetworkInfo> availableNetworkInfos) {
-        mAvailableNetworkInfos = availableNetworkInfos;
-    }
-
-    public void setPreferredDataSub(int preferredDataSub) {
-        mPreferredDataSub = preferredDataSub;
-    }
-
-    public int getPreferredDataSub() {
-        return mPreferredDataSub;
-    }
-
-    public void setPrimarySub(int primarySub) {
-        mPrimarySub = primarySub;
-    }
-
-    public int getPrimarySub() {
-        return mPrimarySub;
-    }
-
-    public ArrayList<AvailableNetworkInfo> getAvailableNetworkInfos() {
-        return mAvailableNetworkInfos;
-    }
-
-    @Override
-    public String toString() {
-        return ("ONSConfigInput:"
-                + " " + mAvailableNetworkInfos
-                + " " + mPreferredDataSub);
+        this(availableNetworkInfos, callback, INVALID_SUBSCRIPTION_ID,
+                INVALID_SUBSCRIPTION_ID);
     }
 }
diff --git a/src/com/android/ons/ONSNetworkScanCtlr.java b/src/com/android/ons/ONSNetworkScanCtlr.java
index e14148f..f926c83 100644
--- a/src/com/android/ons/ONSNetworkScanCtlr.java
+++ b/src/com/android/ons/ONSNetworkScanCtlr.java
@@ -16,6 +16,7 @@
 
 package com.android.ons;
 
+import android.annotation.NonNull;
 import android.content.Context;
 import android.os.Handler;
 import android.os.HandlerThread;
@@ -34,31 +35,31 @@ import android.telephony.RadioAccessSpecifier;
 import android.telephony.TelephonyManager;
 import android.telephony.TelephonyScanManager;
 import android.util.ArraySet;
+import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
-import com.android.telephony.Rlog;
 
+import java.io.FileDescriptor;
+import java.io.PrintWriter;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 import java.util.Set;
 import java.util.concurrent.TimeUnit;
-import java.util.stream.Collectors;
 
 /**
- * Network Scan controller class which will scan for the specific bands as requested and
- * provide results to caller when ready.
+ * ONSNetworkScanCtlr accepts NetworkScan requests, performs NetworkScan and notifies registrants
+ * the network availability with the scan results.
  */
 public class ONSNetworkScanCtlr {
-    private static final String LOG_TAG = "ONSNetworkScanCtlr";
+    private static final String TAG = "ONSNetworkScanCtlr";
     private static final boolean DBG = true;
-    private static final int SEARCH_PERIODICITY_SLOW = (int) TimeUnit.MINUTES.toSeconds(5);
     private static final int SEARCH_PERIODICITY_FAST = (int) TimeUnit.MINUTES.toSeconds(1);
     private static final int MAX_SEARCH_TIME = (int) TimeUnit.MINUTES.toSeconds(1);
     private static final int SCAN_RESTART_TIME = (int) TimeUnit.MINUTES.toMillis(1);
     private final Object mLock = new Object();
 
-    /* message  to handle scan responses from modem */
+    /** Message  to handle scan responses from modem */
     private static final int MSG_SCAN_RESULTS_AVAILABLE = 1;
     private static final int MSG_SCAN_COMPLETE = 2;
     private static final int MSG_SCAN_ERROR = 3;
@@ -74,13 +75,13 @@ public class ONSNetworkScanCtlr {
             null);
     @VisibleForTesting
     static final RadioAccessSpecifier DEFAULT_4G_RAS = new RadioAccessSpecifier(
-        AccessNetworkConstants.AccessNetworkType.NGRAN,
+        AccessNetworkConstants.AccessNetworkType.EUTRAN,
         new int[] {
                 AccessNetworkConstants.EutranBand.BAND_48,
                 AccessNetworkConstants.EutranBand.BAND_71},
         null);
 
-    /* scan object to keep track of current scan request */
+    /** Scan object to keep track of current scan request */
     private NetworkScan mCurrentScan;
     private boolean mIsScanActive;
     private NetworkScanRequest mCurrentScanRequest;
@@ -151,34 +152,27 @@ public class ONSNetworkScanCtlr {
 
     private int getIntCarrierConfig(String key) {
         PersistableBundle b = getConfigBundle();
-        if (b != null) {
-            return b.getInt(key);
-        } else {
-            // Return static default defined in CarrierConfigManager.
-            return CarrierConfigManager.getDefaultConfig().getInt(key);
-        }
+        // Return static default defined in CarrierConfigManager.
+        return b != null ? b.getInt(key) : CarrierConfigManager.getDefaultConfig().getInt(key);
     }
 
     private boolean getBooleanCarrierConfig(String key) {
         PersistableBundle b = getConfigBundle();
-        if (b != null) {
-            return b.getBoolean(key);
-        } else {
-            // Return static default defined in CarrierConfigManager.
-            return CarrierConfigManager.getDefaultConfig().getBoolean(key);
-        }
+        // Return static default defined in CarrierConfigManager.
+        return b != null ? b.getBoolean(key) : CarrierConfigManager.getDefaultConfig().getBoolean(
+                key);
     }
 
     /**
-     * analyze scan results
+     * Analyze scan results
      * @param results contains all available cells matching the scan request at current location.
      */
     public void analyzeScanResults(List<CellInfo> results) {
-        /* Inform registrants about availability of network */
+        // Inform registrants about availability of network
         if (!mIsScanActive || results == null) {
           return;
         }
-        List<CellInfo> filteredResults = new ArrayList<CellInfo>();
+        List<CellInfo> filteredResults = new ArrayList<>();
         mIs4gScanEnabled = getIs4gScanEnabled();
         synchronized (mLock) {
             for (CellInfo cellInfo : results) {
@@ -202,8 +196,8 @@ public class ONSNetworkScanCtlr {
                 }
             }
         }
-        if ((filteredResults.size() >= 1) && (mNetworkAvailableCallBack != null)) {
-            /* Todo: change to aggregate results on success. */
+        if ((!filteredResults.isEmpty()) && (mNetworkAvailableCallBack != null)) {
+            // Todo: change to aggregate results on success.
             mNetworkAvailableCallBack.onNetworkAvailability(filteredResults);
         }
     }
@@ -226,15 +220,15 @@ public class ONSNetworkScanCtlr {
     }
 
     /**
-     * initialize Network Scan controller
-     * @param c context
+     * Initialize Network Scan controller
+     * @param context context
      * @param telephonyManager Telephony manager instance
      * @param networkAvailableCallBack callback to be called when network selection is done
      */
     public void init(Context context, TelephonyManager telephonyManager,
             NetworkAvailableCallBack networkAvailableCallBack) {
         log("init called");
-        mThread = new HandlerThread(LOG_TAG);
+        mThread = new HandlerThread(TAG);
         mThread.start();
         mHandler =  new Handler(mThread.getLooper()) {
             @Override
@@ -295,16 +289,16 @@ public class ONSNetworkScanCtlr {
     }
 
     @VisibleForTesting
-    NetworkScanRequest createNetworkScanRequest(ArrayList<AvailableNetworkInfo> availableNetworks,
+    NetworkScanRequest createNetworkScanRequest(List<AvailableNetworkInfo> availableNetworks,
         int periodicity) {
         RadioAccessSpecifier[] ras;
-        ArrayList<String> mccMncs = new ArrayList<String>();
+        ArrayList<String> mccMncs = new ArrayList<>();
         Set<Integer> bandSet5G = new ArraySet<>();
         Set<Integer> bandSet4G = new ArraySet<>();
 
         mIs4gScanEnabled = getIs4gScanEnabled();
 
-        /* retrieve mcc mncs and bands for available networks */
+        // retrieve mcc mncs and bands for available networks
         for (AvailableNetworkInfo availableNetwork : availableNetworks) {
             mccMncs.addAll(availableNetwork.getMccMncs());
             List<RadioAccessSpecifier> radioAccessSpecifiers =
@@ -321,11 +315,11 @@ public class ONSNetworkScanCtlr {
                             radioAccessNetworkType ==
                                     AccessNetworkConstants.AccessNetworkType.EUTRAN) {
                         bandSet4G.addAll(Arrays.stream(radioAccessSpecifier.getBands())
-                                .boxed().collect(Collectors.toList()));
+                                .boxed().toList());
                     } else if (radioAccessNetworkType ==
                             AccessNetworkConstants.AccessNetworkType.NGRAN) {
                         bandSet5G.addAll(Arrays.stream(radioAccessSpecifier.getBands())
-                                .boxed().collect(Collectors.toList()));
+                                .boxed().toList());
                     }
                 }
             }
@@ -368,11 +362,11 @@ public class ONSNetworkScanCtlr {
     }
 
     /**
-     * start less interval network scan
+     * Start less interval network scan
      * @param availableNetworks list of subscriptions for which the scanning needs to be started.
      * @return true if successfully accepted request.
      */
-    public boolean startFastNetworkScan(ArrayList<AvailableNetworkInfo> availableNetworks) {
+    public boolean startFastNetworkScan(List<AvailableNetworkInfo> availableNetworks) {
         NetworkScanRequest networkScanRequest = createNetworkScanRequest(availableNetworks,
                 SEARCH_PERIODICITY_FAST);
         return startNetworkScan(networkScanRequest);
@@ -382,15 +376,15 @@ public class ONSNetworkScanCtlr {
     private boolean startNetworkScan(NetworkScanRequest networkScanRequest) {
         NetworkScan networkScan;
         synchronized (mLock) {
-            /* if the request is same as existing one, then make sure to not proceed */
+            // if the request is same as existing one, then make sure to not proceed
             if (mIsScanActive && mCurrentScanRequest.equals(networkScanRequest)) {
                 return true;
             }
 
-            /* Need to stop current scan if we already have one */
+            // Need to stop current scan if we already have one
             stopNetworkScan();
 
-            /* user lower threshold to enable modem stack */
+            // user lower threshold to enable modem stack
             mRsrpEntryThreshold =
                 getIntCarrierConfig(
                     CarrierConfigManager.KEY_OPPORTUNISTIC_NETWORK_EXIT_THRESHOLD_RSRP_INT);
@@ -398,7 +392,7 @@ public class ONSNetworkScanCtlr {
             mSsRsrpEntryThreshold = getIntCarrierConfig(
                     CarrierConfigManager.OpportunisticNetwork.KEY_ENTRY_THRESHOLD_SS_RSRP_INT);
 
-            /* start new scan */
+            // start new scan
             networkScan = mTelephonyManager.requestNetworkScan(networkScanRequest,
                     mNetworkScanCallback);
 
@@ -424,7 +418,7 @@ public class ONSNetworkScanCtlr {
     }
 
     /**
-     * stop network scan
+     * Stop network scan
      */
     public void stopNetworkScan() {
         logDebug("stopNetworkScan");
@@ -443,12 +437,26 @@ public class ONSNetworkScanCtlr {
     }
 
     private static void log(String msg) {
-        Rlog.d(LOG_TAG, msg);
+        Log.d(TAG, msg);
     }
 
     private static void logDebug(String msg) {
         if (DBG) {
-            Rlog.d(LOG_TAG, msg);
+            Log.d(TAG, msg);
         }
     }
+
+    /**
+     * Dump the state of {@link ONSNetworkScanCtlr}.
+     */
+    public void dump(@NonNull FileDescriptor fd, @NonNull PrintWriter pw,
+            @NonNull String[] args) {
+        pw.println(TAG + ":");
+        pw.println("  mIs4gScanEnabled: " + mIs4gScanEnabled);
+        pw.println("  mIsScanActive: " + mIsScanActive);
+        pw.println("  mCurrentScanRequest: " + mCurrentScanRequest);
+        pw.println("  mMccMncs: " + mMccMncs);
+        pw.println("  mRsrpEntryThreshold: " + mRsrpEntryThreshold);
+        pw.println("  mSsRsrpEntryThreshold: " + mSsRsrpEntryThreshold);
+    }
 }
diff --git a/src/com/android/ons/ONSProfileActivator.java b/src/com/android/ons/ONSProfileActivator.java
index 9c270a2..6293ca3 100644
--- a/src/com/android/ons/ONSProfileActivator.java
+++ b/src/com/android/ons/ONSProfileActivator.java
@@ -16,6 +16,7 @@
 
 package com.android.ons;
 
+import android.annotation.NonNull;
 import android.annotation.TestApi;
 import android.content.Context;
 import android.net.ConnectivityManager;
@@ -39,13 +40,13 @@ import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.flags.Flags;
 import com.android.ons.ONSProfileDownloader.DownloadRetryResultCode;
 
-import java.util.ArrayList;
+import java.io.FileDescriptor;
+import java.io.PrintWriter;
 import java.util.List;
 import java.util.Random;
 
 /**
- * @class ONSProfileActivator
- * @brief ONSProfileActivator makes sure that the CBRS profile is downloaded, activated and grouped
+ * ONSProfileActivator makes sure that the CBRS profile is downloaded, activated and grouped
  * when an opportunistic data enabled pSIM is inserted.
  */
 public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfigListener,
@@ -79,8 +80,9 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
         mEuiccManager = mContext.getSystemService(EuiccManager.class);
         mONSProfileConfig = new ONSProfileConfigurator(mContext, mSubManager,
                 mCarrierConfigMgr, mEuiccManager, this);
-        mONSProfileDownloader = new ONSProfileDownloader(mContext, mCarrierConfigMgr,
-                mEuiccManager, mSubManager, mONSProfileConfig, this);
+        mONSProfileDownloader =
+                new ONSProfileDownloader(
+                        mContext, mCarrierConfigMgr, mEuiccManager, mSubManager, this);
 
         //Monitor internet connection.
         mConnectivityManager = context.getSystemService(ConnectivityManager.class);
@@ -125,7 +127,10 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
                 case REQUEST_CODE_DOWNLOAD_RETRY: {
                     Result res = provisionCBRS();
                     Log.d(TAG, res.toString());
-                    mONSStats.logEvent(new ONSStatsInfo().setProvisioningResult(res));
+                    mONSStats.logEvent(
+                            new ONSStatsInfo.Builder()
+                                    .setProvisioningResult(mContext, res)
+                                    .build());
                 }
                 break;
             }
@@ -138,7 +143,7 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
     public Result handleCarrierConfigChange() {
         Result res = provisionCBRS();
         Log.d(TAG, res.toString());
-        mONSStats.logEvent(new ONSStatsInfo().setProvisioningResult(res));
+        mONSStats.logEvent(new ONSStatsInfo.Builder().setProvisioningResult(mContext, res).build());
 
         // Reset mDownloadRetryCount as carrier config change event is received. Either new SIM card
         // is inserted or carrier config values are updated.
@@ -153,7 +158,7 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
     public void onOppSubscriptionDeleted(int pSIMId) {
         Result res = provisionCBRS();
         Log.d(TAG, res.toString());
-        mONSStats.logEvent(new ONSStatsInfo().setProvisioningResult(res));
+        mONSStats.logEvent(new ONSStatsInfo.Builder().setProvisioningResult(mContext, res).build());
     }
 
     /**
@@ -179,14 +184,14 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
 
         //Check the number of active subscriptions.
         List<SubscriptionInfo> activeSubInfos = mSubManager.getActiveSubscriptionInfoList();
-        if (activeSubInfos == null || activeSubInfos.size() <= 0) {
+        if (activeSubInfos == null || activeSubInfos.isEmpty()) {
             return Result.ERR_NO_SIM_INSERTED;
         }
         int activeSubCount = activeSubInfos.size();
         Log.d(TAG, "Active subscription count:" + activeSubCount);
 
         if (activeSubCount == 1) {
-            SubscriptionInfo pSubInfo = activeSubInfos.get(0);
+            SubscriptionInfo pSubInfo = activeSubInfos.getFirst();
             if (pSubInfo.isOpportunistic()) {
                 //Only one SIM is active and its opportunistic SIM.
                 //Opportunistic eSIM shouldn't be used without pSIM.
@@ -291,13 +296,12 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
         ONSProfileDownloader.DownloadProfileResult res = mONSProfileDownloader.downloadProfile(
                 primaryCBRSSubInfo.getSubscriptionId());
 
-        switch (res) {
-            case DUPLICATE_REQUEST: return Result.ERR_DUPLICATE_DOWNLOAD_REQUEST;
-            case INVALID_SMDP_ADDRESS: return Result.ERR_INVALID_CARRIER_CONFIG;
-            case SUCCESS: return Result.DOWNLOAD_REQUESTED;
-        }
+        return switch (res) {
+            case DUPLICATE_REQUEST -> Result.ERR_DUPLICATE_DOWNLOAD_REQUEST;
+            case INVALID_SMDP_ADDRESS -> Result.ERR_INVALID_CARRIER_CONFIG;
+            case SUCCESS -> Result.DOWNLOAD_REQUESTED;
+        };
 
-        return Result.ERR_UNKNOWN;
     }
 
     @Override
@@ -307,10 +311,11 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
                 primarySubId);
         if (opportunisticESIM == null) {
             Log.e(TAG, "Downloaded Opportunistic eSIM not found. Unable to group with pSIM");
-            mONSStats.logEvent(new ONSStatsInfo()
-                    .setProvisioningResult(Result.ERR_DOWNLOADED_ESIM_NOT_FOUND)
+            mONSStats.logEvent(new ONSStatsInfo.Builder()
+                    .setProvisioningResult(mContext, Result.ERR_DOWNLOADED_ESIM_NOT_FOUND)
                     .setPrimarySimSubId(primarySubId)
-                    .setWifiConnected(isWiFiConnected()));
+                    .setWifiConnected(isWiFiConnected())
+                    .build());
             return;
         }
 
@@ -320,16 +325,18 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
             mONSProfileConfig.groupWithPSIMAndSetOpportunistic(
                     opportunisticESIM, pSIMSubInfo.getGroupUuid());
             Log.d(TAG, "eSIM downloaded and configured successfully");
-            mONSStats.logEvent(new ONSStatsInfo()
-                    .setProvisioningResult(Result.SUCCESS)
+            mONSStats.logEvent(new ONSStatsInfo.Builder()
+                    .setProvisioningResult(mContext, Result.SUCCESS)
                     .setRetryCount(mDownloadRetryCount)
-                    .setWifiConnected(isWiFiConnected()));
+                    .setWifiConnected(isWiFiConnected())
+                    .build());
         } else {
             Log.d(TAG, "ESIM downloaded but pSIM is not active or removed");
-            mONSStats.logEvent(new ONSStatsInfo()
-                    .setProvisioningResult(Result.ERR_PSIM_NOT_FOUND)
+            mONSStats.logEvent(new ONSStatsInfo.Builder()
+                    .setProvisioningResult(mContext, Result.ERR_PSIM_NOT_FOUND)
                     .setOppSimCarrierId(opportunisticESIM.getCarrierId())
-                    .setWifiConnected(isWiFiConnected()));
+                    .setWifiConnected(isWiFiConnected())
+                    .build());
         }
     }
 
@@ -343,10 +350,10 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
 
                 //First find and delete any opportunistic eSIMs from the operator same as the
                 // current primary SIM.
-                ArrayList<Integer> oppSubIds = mONSProfileConfig
+                List<Integer> oppSubIds = mONSProfileConfig
                         .getOpportunisticSubIdsofPSIMOperator(pSIMSubId);
-                if (oppSubIds != null && oppSubIds.size() > 0) {
-                    mONSProfileConfig.deleteSubscription(oppSubIds.get(0));
+                if (oppSubIds != null && !oppSubIds.isEmpty()) {
+                    mONSProfileConfig.deleteSubscription(oppSubIds.getFirst());
                 } else {
                     //else, find the inactive opportunistic eSIMs (any operator) and delete one of
                     // them and retry download again.
@@ -364,11 +371,11 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
                 //Since the installation of eSIM profile has failed there may be an issue with the
                 //format or profile data. We retry by first deleting existing eSIM profile from the
                 //operator same as the primary SIM and retry download opportunistic eSIM.
-                ArrayList<Integer> oppSubIds = mONSProfileConfig
+                List<Integer> oppSubIds = mONSProfileConfig
                         .getOpportunisticSubIdsofPSIMOperator(pSIMSubId);
 
-                if (oppSubIds != null && oppSubIds.size() > 0) {
-                    mONSProfileConfig.deleteSubscription(oppSubIds.get(0));
+                if (oppSubIds != null && !oppSubIds.isEmpty()) {
+                    mONSProfileConfig.deleteSubscription(oppSubIds.getFirst());
                 }
 
                 //Download retry will stop if there are no opportunistic eSIM profiles to delete
@@ -389,12 +396,13 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
             }
         }
         if (logStats) {
-            mONSStats.logEvent(new ONSStatsInfo()
+            mONSStats.logEvent(new ONSStatsInfo.Builder()
                     .setDownloadResult(resultCode)
                     .setPrimarySimSubId(pSIMSubId)
                     .setRetryCount(mDownloadRetryCount)
                     .setDetailedErrCode(detailedErrorCode)
-                    .setWifiConnected(isWiFiConnected()));
+                    .setWifiConnected(isWiFiConnected())
+                    .build());
         }
     }
 
@@ -543,12 +551,8 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
 
     private boolean isWiFiConnected() {
         Network activeNetwork = mConnectivityManager.getActiveNetwork();
-        if ((activeNetwork != null) && mConnectivityManager.getNetworkCapabilities(activeNetwork)
-                .hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
-            return true;
-        }
-
-        return false;
+        return (activeNetwork != null) && mConnectivityManager.getNetworkCapabilities(activeNetwork)
+                .hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
     }
 
     /**
@@ -572,7 +576,9 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
             if (mRetryDownloadWhenNWConnected) {
                 Result res = provisionCBRS();
                 Log.d(TAG, res.toString());
-                mONSStats.logEvent(new ONSStatsInfo().setProvisioningResult(res));
+                mONSStats.logEvent(new ONSStatsInfo.Builder()
+                        .setProvisioningResult(mContext, res)
+                        .build());
             }
         }
 
@@ -606,6 +612,18 @@ public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfig
         ERR_INVALID_CARRIER_CONFIG,
         ERR_DOWNLOADED_ESIM_NOT_FOUND,
         ERR_PSIM_NOT_FOUND,
-        ERR_UNKNOWN;
+        ERR_UNKNOWN
+    }
+
+    /**
+     * Dump the state of {@link ONSProfileActivator}.
+     */
+    public void dump(@NonNull FileDescriptor fd, @NonNull PrintWriter pw,
+            @NonNull String[] args) {
+        pw.println(TAG + ":");
+        pw.println("  mIsInternetConnAvailable: " + mIsInternetConnAvailable);
+        pw.println("  mRetryDownloadWhenNWConnected: " + mRetryDownloadWhenNWConnected);
+        pw.println("  mDownloadRetryCount: " + mDownloadRetryCount);
+        mONSProfileDownloader.dump(fd, pw, args);
     }
 }
diff --git a/src/com/android/ons/ONSProfileConfigurator.java b/src/com/android/ons/ONSProfileConfigurator.java
index c0f0c70..0925df0 100644
--- a/src/com/android/ons/ONSProfileConfigurator.java
+++ b/src/com/android/ons/ONSProfileConfigurator.java
@@ -36,9 +36,8 @@ import java.util.ArrayList;
 import java.util.List;
 
 /**
- * @class ONSProfileConfigurator
- * @brief Helper class to support ONSProfileActivator to read and update profile, operator and CBRS
- * configurations.
+ * ONSProfileConfigurator is a helper class to support ONSProfileActivator reading and
+ * updating profile, operator and CBRS configurations.
  */
 public class ONSProfileConfigurator {
 
@@ -128,10 +127,10 @@ public class ONSProfileConfigurator {
     protected void groupWithPSIMAndSetOpportunistic(
             SubscriptionInfo opportunisticESIM, ParcelUuid groupUuid) {
         if (groupUuid != null && groupUuid.equals(opportunisticESIM.getGroupUuid())) {
-            Log.d(TAG, "opportunistc eSIM and CBRS pSIM already grouped");
+            Log.d(TAG, "opportunistic eSIM and CBRS pSIM already grouped");
         } else {
-            Log.d(TAG, "Grouping opportunistc eSIM and CBRS pSIM");
-            ArrayList<Integer> subList = new ArrayList<>();
+            Log.d(TAG, "Grouping opportunistic eSIM and CBRS pSIM");
+            List<Integer> subList = new ArrayList<>();
             subList.add(opportunisticESIM.getSubscriptionId());
             try {
                 mSubscriptionManager.addSubscriptionsIntoGroup(subList, groupUuid);
@@ -187,7 +186,7 @@ public class ONSProfileConfigurator {
         Log.d(TAG, "deleteInactiveOpportunisticSubscriptions");
 
         List<SubscriptionInfo> subList = mSubscriptionManager.getOpportunisticSubscriptions();
-        if (subList == null || subList.size() <= 0) {
+        if (subList == null || subList.isEmpty()) {
             return false;
         }
 
@@ -209,9 +208,9 @@ public class ONSProfileConfigurator {
      * @return true - If an eSIM is found.
      *          false - If no eSIM is found.
      */
-    ArrayList<Integer> getOpportunisticSubIdsofPSIMOperator(int pSIMSubId) {
+    List<Integer> getOpportunisticSubIdsofPSIMOperator(int pSIMSubId) {
         Log.d(TAG, "getOpportunisticSubIdsofPSIMOperator");
-        ArrayList<Integer> opportunisticSubIds = new ArrayList<Integer>();
+        List<Integer> opportunisticSubIds = new ArrayList<>();
         //1.Get the list of all opportunistic carrier-ids of newly inserted pSIM from carrier config
         PersistableBundle config = mCarrierConfigManager.getConfigForSubId(pSIMSubId);
         int[] oppCarrierIdArr = config.getIntArray(
@@ -224,7 +223,7 @@ public class ONSProfileConfigurator {
         List<SubscriptionInfo> oppSubList = mSubscriptionManager.getAvailableSubscriptionInfoList();
         for (SubscriptionInfo subInfo : oppSubList) {
             for (int oppCarrierId : oppCarrierIdArr) {
-                //Carrier-id of opportunistic eSIM matches with one of thecarrier-ids in carrier
+                //Carrier-id of opportunistic eSIM matches with one of the carrier-ids in carrier
                 // config of pSIM
                 if (subInfo.isEmbedded() && oppCarrierId == subInfo
                         .getCarrierId()) {
diff --git a/src/com/android/ons/ONSProfileDownloader.java b/src/com/android/ons/ONSProfileDownloader.java
index a052e07..9e1bc1c 100644
--- a/src/com/android/ons/ONSProfileDownloader.java
+++ b/src/com/android/ons/ONSProfileDownloader.java
@@ -16,6 +16,7 @@
 
 package com.android.ons;
 
+import android.annotation.NonNull;
 import android.app.PendingIntent;
 import android.content.Context;
 import android.content.Intent;
@@ -33,8 +34,13 @@ import android.util.Pair;
 
 import com.android.internal.annotations.VisibleForTesting;
 
+import java.io.FileDescriptor;
+import java.io.PrintWriter;
 import java.util.Stack;
 
+/**
+ * ONSProfileDownloader is responsible for downloading ONS profiles from the remote server.
+ */
 public class ONSProfileDownloader {
 
     interface IONSProfileDownloaderListener {
@@ -54,7 +60,6 @@ public class ONSProfileDownloader {
     private final CarrierConfigManager mCarrierConfigManager;
     private final EuiccManager mEuiccManager;
     private final SubscriptionManager mSubManager;
-    private final ONSProfileConfigurator mONSProfileConfig;
     private IONSProfileDownloaderListener mListener;
 
     // Subscription Id of the CBRS PSIM for which opportunistic eSIM is being downloaded. Used to
@@ -71,13 +76,11 @@ public class ONSProfileDownloader {
 
     public ONSProfileDownloader(Context context, CarrierConfigManager carrierConfigManager,
                                 EuiccManager euiccManager, SubscriptionManager subManager,
-                                ONSProfileConfigurator onsProfileConfigurator,
                                 IONSProfileDownloaderListener listener) {
         mContext = context;
         mListener = listener;
         mEuiccManager = euiccManager;
         mSubManager = subManager;
-        mONSProfileConfig = onsProfileConfigurator;
         mCarrierConfigManager = carrierConfigManager;
 
         mHandler = new DownloadHandler();
@@ -90,50 +93,55 @@ public class ONSProfileDownloader {
 
         @Override
         public void handleMessage(Message msg) {
-            switch (msg.what) {
-                // Received Response for download request. REQUEST_CODE_DOWNLOAD_SUB was sent to LPA
-                // as part of request intent.
-                case REQUEST_CODE_DOWNLOAD_SUB: {
-                    Log.d(TAG, "REQUEST_CODE_DOWNLOAD_SUB callback received");
-
-                    //Clear downloading subscription flag. Indicates no download in progress.
-                    synchronized (this) {
-                        mDownloadingPSimSubId = -1;
-                    }
-
-                    int pSIMSubId = ((Intent) msg.obj).getIntExtra(PARAM_PRIMARY_SUBID, 0);
-                    int detailedErrCode = ((Intent) msg.obj).getIntExtra(
-                            EuiccManager.EXTRA_EMBEDDED_SUBSCRIPTION_DETAILED_CODE, 0);
-                    int operationCode = ((Intent) msg.obj).getIntExtra(
-                            EuiccManager.EXTRA_EMBEDDED_SUBSCRIPTION_OPERATION_CODE, 0);
-                    int errorCode = ((Intent) msg.obj).getIntExtra(
-                            EuiccManager.EXTRA_EMBEDDED_SUBSCRIPTION_ERROR_CODE, 0);
-
-                    Log.d(TAG, "Result Code : " + detailedErrCode);
-                    Log.d(TAG, "Operation Code : " + operationCode);
-                    Log.d(TAG, "Error Code : " + errorCode);
-
-                    DownloadRetryResultCode resultCode = mapDownloaderErrorCode(msg.arg1,
-                            detailedErrCode, operationCode, errorCode);
-                    Log.d(TAG, "DownloadRetryResultCode: " + resultCode);
-
-                    switch (resultCode) {
-                        case DOWNLOAD_SUCCESSFUL:
-                            mListener.onDownloadComplete(pSIMSubId);
-                            break;
-
-                        case ERR_UNRESOLVABLE:
-                            mListener.onDownloadError(pSIMSubId, resultCode, detailedErrCode);
-                            Log.e(TAG, "Unresolvable download error: "
+            if (REQUEST_CODE_DOWNLOAD_SUB != msg.what) {
+                return;
+            }
+
+            // Received Response for download request. REQUEST_CODE_DOWNLOAD_SUB was sent to LPA
+            // as part of request intent.
+            Log.d(TAG, "REQUEST_CODE_DOWNLOAD_SUB callback received");
+
+            // Clear downloading subscription flag. Indicates no download in progress.
+            synchronized (this) {
+                mDownloadingPSimSubId = -1;
+            }
+
+            int pSIMSubId = ((Intent) msg.obj).getIntExtra(PARAM_PRIMARY_SUBID, 0);
+            int detailedErrCode =
+                    ((Intent) msg.obj)
+                            .getIntExtra(EuiccManager.EXTRA_EMBEDDED_SUBSCRIPTION_DETAILED_CODE, 0);
+            int operationCode =
+                    ((Intent) msg.obj)
+                            .getIntExtra(
+                                    EuiccManager.EXTRA_EMBEDDED_SUBSCRIPTION_OPERATION_CODE, 0);
+            int errorCode =
+                    ((Intent) msg.obj)
+                            .getIntExtra(EuiccManager.EXTRA_EMBEDDED_SUBSCRIPTION_ERROR_CODE, 0);
+
+            Log.d(TAG, "Result Code : " + detailedErrCode);
+            Log.d(TAG, "Operation Code : " + operationCode);
+            Log.d(TAG, "Error Code : " + errorCode);
+
+            DownloadRetryResultCode resultCode =
+                    mapDownloaderErrorCode(msg.arg1, detailedErrCode, operationCode, errorCode);
+            Log.d(TAG, "DownloadRetryResultCode: " + resultCode);
+
+            switch (resultCode) {
+                case DOWNLOAD_SUCCESSFUL:
+                    mListener.onDownloadComplete(pSIMSubId);
+                    break;
+
+                case ERR_UNRESOLVABLE:
+                    mListener.onDownloadError(pSIMSubId, resultCode, detailedErrCode);
+                    Log.e(
+                            TAG,
+                            "Unresolvable download error: "
                                     + getUnresolvableErrorDescription(errorCode));
-                            break;
+                    break;
 
-                        default:
-                            mListener.onDownloadError(pSIMSubId, resultCode, detailedErrCode);
-                            break;
-                    }
-                }
-                break;
+                default:
+                    mListener.onDownloadError(pSIMSubId, resultCode, detailedErrCode);
+                    break;
             }
         }
 
@@ -345,4 +353,13 @@ public class ONSProfileDownloader {
         msg.obj = intent;
         mHandler.sendMessage(msg);
     }
+
+    /**
+     * Dump the state of {@link ONSProfileDownloader}.
+     */
+    public void dump(@NonNull FileDescriptor fd, @NonNull PrintWriter pw,
+            @NonNull String[] args) {
+        pw.println(TAG + ":");
+        pw.println("  mDownloadingPSimSubId: " + mDownloadingPSimSubId);
+    }
 }
diff --git a/src/com/android/ons/ONSProfileResultReceiver.java b/src/com/android/ons/ONSProfileResultReceiver.java
index 2cc89b1..89d8239 100644
--- a/src/com/android/ons/ONSProfileResultReceiver.java
+++ b/src/com/android/ons/ONSProfileResultReceiver.java
@@ -45,14 +45,14 @@ public class ONSProfileResultReceiver extends BroadcastReceiver {
 
         if (action.equals(TelephonyManager.ACTION_MULTI_SIM_CONFIG_CHANGED)) {
             int simCount = intent.getIntExtra(TelephonyManager.EXTRA_ACTIVE_SIM_SUPPORTED_COUNT, 0);
-            Log.d(TAG, "Mutli-SIM configed for " + simCount + "SIMs");
+            Log.d(TAG, "Multi-SIM configed for " + simCount + "SIMs");
         } else {
             Intent serviceIntent = new Intent(context, OpportunisticNetworkService.class);
             serviceIntent.setAction(intent.getAction());
             serviceIntent.putExtra(EXTRA_RESULT_CODE, getResultCode());
             serviceIntent.putExtra(Intent.EXTRA_INTENT, intent);
             context.startService(serviceIntent);
-            Log.d(TAG, "Service Started:" + serviceIntent.toString());
+            Log.d(TAG, "Service Started:" + serviceIntent);
         }
     }
 }
diff --git a/src/com/android/ons/ONSProfileSelector.java b/src/com/android/ons/ONSProfileSelector.java
index ba2c877..b246e9d 100644
--- a/src/com/android/ons/ONSProfileSelector.java
+++ b/src/com/android/ons/ONSProfileSelector.java
@@ -19,6 +19,7 @@ package com.android.ons;
 import static android.telephony.AvailableNetworkInfo.PRIORITY_HIGH;
 import static android.telephony.AvailableNetworkInfo.PRIORITY_LOW;
 
+import android.annotation.NonNull;
 import android.app.PendingIntent;
 import android.compat.Compatibility;
 import android.content.Context;
@@ -40,16 +41,19 @@ import android.telephony.UiccCardInfo;
 import android.telephony.UiccPortInfo;
 import android.telephony.euicc.EuiccManager;
 import android.text.TextUtils;
+import android.util.IndentingPrintWriter;
+import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.ISetOpportunisticDataCallback;
 import com.android.internal.telephony.IUpdateAvailableNetworksCallback;
-import com.android.telephony.Rlog;
 
+import java.io.FileDescriptor;
+import java.io.PrintWriter;
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.Collections;
 import java.util.Comparator;
-import java.util.HashMap;
 import java.util.HashSet;
 import java.util.List;
 import java.util.stream.Collectors;
@@ -59,23 +63,23 @@ import java.util.stream.Collectors;
  * geographic information input and network scan results.
  */
 public class ONSProfileSelector {
-    private static final String LOG_TAG = "ONSProfileSelector";
+    private static final String TAG = "ONSProfileSelector";
     private static final boolean DBG = true;
     private final Object mLock = new Object();
 
     private static final int INVALID_SEQUENCE_ID = -1;
     private static final int START_SEQUENCE_ID = 1;
 
-    /* message to indicate profile update */
+    /** Message to indicate profile update */
     private static final int MSG_PROFILE_UPDATE = 1;
 
-    /* message to indicate start of profile selection process */
+    /** Message to indicate start of profile selection process */
     private static final int MSG_START_PROFILE_SELECTION = 2;
 
-    /* message to indicate Subscription switch completion */
+    /** Message to indicate Subscription switch completion */
     private static final int MSG_SUB_SWITCH_COMPLETE = 3;
 
-    /* message to stop profile selection process */
+    /** Message to stop profile selection process */
     private static final int MSG_STOP_PROFILE_SELECTION = 4;
 
     private boolean mIsEnabled = false;
@@ -104,7 +108,7 @@ public class ONSProfileSelector {
     private int mSubId;
     @VisibleForTesting
     protected int mCurrentDataSubId = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
-    private ArrayList<AvailableNetworkInfo> mAvailableNetworkInfos;
+    private List<AvailableNetworkInfo> mAvailableNetworkInfos;
     private IUpdateAvailableNetworksCallback mNetworkScanCallback;
 
     public static final String ACTION_SUB_SWITCH =
@@ -132,7 +136,7 @@ public class ONSProfileSelector {
                         return;
                     }
 
-                    /* stop scanning further */
+                    // stop scanning further
                     mNetworkScanCtlr.stopNetworkScan();
                     handleNetworkScanResult(subId);
                 }
@@ -142,8 +146,8 @@ public class ONSProfileSelector {
                     log("Network scan failed with error " + error);
                     synchronized (mLock) {
                         if (mIsEnabled && mAvailableNetworkInfos != null
-                            && mAvailableNetworkInfos.size() > 0) {
-                            handleNetworkScanResult(mAvailableNetworkInfos.get(0).getSubId());
+                                && !mAvailableNetworkInfos.isEmpty()) {
+                            handleNetworkScanResult(mAvailableNetworkInfos.getFirst().getSubId());
                         } else {
                             if (mNetworkScanCallback != null) {
                                 if (mIsEnabled) {
@@ -170,7 +174,7 @@ public class ONSProfileSelector {
                 }
 
                 private void handleNetworkScanResult(int subId) {
-                    /* if subscription is already active, just enable modem */
+                    // if subscription is already active, just enable modem
                     if (mSubscriptionManager.isActiveSubId(subId)) {
                         if (enableModem(subId, true)) {
                             sendUpdateNetworksCallbackHelper(mNetworkScanCallback,
@@ -211,12 +215,12 @@ public class ONSProfileSelector {
             };
 
     /**
-     * interface call back to confirm profile selection
+     * Interface call back to confirm profile selection
      */
     public interface ONSProfileSelectionCallback {
 
         /**
-         * interface call back to confirm profile selection
+         * Interface call back to confirm profile selection
          */
         void onProfileSelectionDone();
     }
@@ -311,8 +315,8 @@ public class ONSProfileSelector {
         return SubscriptionManager.INVALID_SUBSCRIPTION_ID;
     }
 
-    public SubscriptionInfo getOpprotunisticSubInfo(int subId) {
-        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.size() == 0)) {
+    public SubscriptionInfo getOpportunisticSubInfo(int subId) {
+        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.isEmpty())) {
             return null;
         }
         for (SubscriptionInfo subscriptionInfo : mOppSubscriptionInfos) {
@@ -330,7 +334,7 @@ public class ONSProfileSelector {
      * @return true if the subscription is opportunistic
      */
     public boolean isOpportunisticSub(int subId) {
-        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.size() == 0)) {
+        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.isEmpty())) {
             return false;
         }
         for (SubscriptionInfo subscriptionInfo : mOppSubscriptionInfos) {
@@ -341,11 +345,11 @@ public class ONSProfileSelector {
         return false;
     }
 
-    public boolean hasOpprotunisticSub(List<AvailableNetworkInfo> availableNetworks) {
-        if ((availableNetworks == null) || (availableNetworks.size() == 0)) {
+    public boolean hasOpportunisticSub(List<AvailableNetworkInfo> availableNetworks) {
+        if ((availableNetworks == null) || (availableNetworks.isEmpty())) {
             return false;
         }
-        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.size() == 0)) {
+        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.isEmpty())) {
             return false;
         }
 
@@ -357,12 +361,6 @@ public class ONSProfileSelector {
         return true;
     }
 
-    private boolean isAvtiveSub(int subId) {
-        return mSubscriptionManager.isActiveSubscriptionId(subId);
-    }
-
-    private HashMap<Integer, IUpdateAvailableNetworksCallback> callbackStubs = new HashMap<>();
-
     private void switchToSubscription(int subId, int availableSIMPortIndex) {
         Intent callbackIntent = new Intent(ACTION_SUB_SWITCH);
         callbackIntent.setClass(mContext, OpportunisticNetworkService.class);
@@ -438,7 +436,7 @@ public class ONSProfileSelector {
     }
 
     private void onSubSwitchComplete(int subId) {
-        /* Ignore if this is callback for an older request */
+        // Ignore if this is callback for an older request
         if (mSubId != subId) {
             return;
         }
@@ -467,14 +465,14 @@ public class ONSProfileSelector {
         }
     }
 
-    private ArrayList<AvailableNetworkInfo> getFilteredAvailableNetworks(
-            ArrayList<AvailableNetworkInfo> availableNetworks,
+    private List<AvailableNetworkInfo> getFilteredAvailableNetworks(
+            List<AvailableNetworkInfo> availableNetworks,
             List<SubscriptionInfo> subscriptionInfoList) {
-        ArrayList<AvailableNetworkInfo> filteredAvailableNetworks =
-                new ArrayList<AvailableNetworkInfo>();
+        List<AvailableNetworkInfo> filteredAvailableNetworks =
+                new ArrayList<>();
 
-        /* instead of checking each element of a list every element of the other, sort them in
-           the order of sub id and compare to improve the filtering performance. */
+        // instead of checking each element of a list every element of the other, sort them in
+        // the order of sub id and compare to improve the filtering performance.
         Collections.sort(subscriptionInfoList, new SortSubInfo());
         Collections.sort(availableNetworks, new SortAvailableNetworks());
         int availableNetworksIndex = 0;
@@ -499,8 +497,8 @@ public class ONSProfileSelector {
         return filteredAvailableNetworks;
     }
 
-    private boolean isSame(ArrayList<AvailableNetworkInfo> availableNetworks1,
-            ArrayList<AvailableNetworkInfo> availableNetworks2) {
+    private boolean isSame(List<AvailableNetworkInfo> availableNetworks1,
+            List<AvailableNetworkInfo> availableNetworks2) {
         if ((availableNetworks1 == null) || (availableNetworks2 == null)) {
             return false;
         }
@@ -521,8 +519,8 @@ public class ONSProfileSelector {
     }
 
     private void checkProfileUpdate(Object[] objects) {
-        ArrayList<AvailableNetworkInfo> availableNetworks =
-                (ArrayList<AvailableNetworkInfo>) objects[0];
+        List<AvailableNetworkInfo> availableNetworks =
+                (List<AvailableNetworkInfo>) objects[0];
         IUpdateAvailableNetworksCallback callbackStub =
                 (IUpdateAvailableNetworksCallback) objects[1];
         if (mOppSubscriptionInfos == null) {
@@ -538,7 +536,7 @@ public class ONSProfileSelector {
             return;
         }
 
-        /* Check if ports are available on the embedded slot */
+        // Check if ports are available on the embedded slot
         int availSIMPortIndex = getAvailableESIMPortIndex();
         if (availSIMPortIndex == TelephonyManager.INVALID_PORT_INDEX) {
             logDebug("SIM port not available.");
@@ -549,37 +547,37 @@ public class ONSProfileSelector {
 
         if (isSame(availableNetworks, mAvailableNetworkInfos)) {
             logDebug("received duplicate requests");
-            /* If we receive same request more than once, send abort response for earlier one
-               and send actual response for the latest callback.
-            */
+            // If we receive same request more than once, send abort response for earlier one
+            // and send actual response for the latest callback.
             sendUpdateNetworksCallbackHelper(mNetworkScanCallback,
                 TelephonyManager.UPDATE_AVAILABLE_NETWORKS_ABORTED);
             mNetworkScanCallback = callbackStub;
             return;
         }
 
-        stopProfileScanningPrecedure();
+        stopProfileScanningProcedure();
         mIsEnabled = true;
         mAvailableNetworkInfos = availableNetworks;
-        /* sort in the order of priority */
+        // sort in the order of priority
         Collections.sort(mAvailableNetworkInfos, new SortAvailableNetworksInPriority());
         logDebug("availableNetworks: " + availableNetworks);
 
-        if (mOppSubscriptionInfos.size() > 0) {
+        if (!mOppSubscriptionInfos.isEmpty()) {
             logDebug("opportunistic subscriptions size " + mOppSubscriptionInfos.size());
-            ArrayList<AvailableNetworkInfo> filteredAvailableNetworks =
-                    getFilteredAvailableNetworks((ArrayList<AvailableNetworkInfo>)availableNetworks,
+            List<AvailableNetworkInfo> filteredAvailableNetworks =
+                    getFilteredAvailableNetworks(availableNetworks,
                             mOppSubscriptionInfos);
             if ((filteredAvailableNetworks.size() == 1)
-                    && ((filteredAvailableNetworks.get(0).getMccMncs() == null)
-                    || (filteredAvailableNetworks.get(0).getMccMncs().size() == 0))) {
-                /* if subscription is not active, activate the sub */
-                if (!mSubscriptionManager.isActiveSubId(filteredAvailableNetworks.get(0).getSubId())) {
+                    && ((filteredAvailableNetworks.getFirst().getMccMncs() == null)
+                    || (filteredAvailableNetworks.getFirst().getMccMncs().isEmpty()))) {
+                // if subscription is not active, activate the sub
+                if (!mSubscriptionManager.isActiveSubId(
+                        filteredAvailableNetworks.getFirst().getSubId())) {
                     mNetworkScanCallback = callbackStub;
-                    switchToSubscription(filteredAvailableNetworks.get(0).getSubId(),
+                    switchToSubscription(filteredAvailableNetworks.getFirst().getSubId(),
                             availSIMPortIndex);
                 } else {
-                    if (enableModem(filteredAvailableNetworks.get(0).getSubId(), true)) {
+                    if (enableModem(filteredAvailableNetworks.getFirst().getSubId(), true)) {
                         sendUpdateNetworksCallbackHelper(callbackStub,
                             TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
                     } else {
@@ -597,10 +595,10 @@ public class ONSProfileSelector {
                 }
             } else {
                 mNetworkScanCallback = callbackStub;
-                /* start scan immediately */
+                // start scan immediately
                 mNetworkScanCtlr.startFastNetworkScan(filteredAvailableNetworks);
             }
-        } else if (mOppSubscriptionInfos.size() == 0) {
+        } else {
             if (Compatibility.isChangeEnabled(
                     OpportunisticNetworkService.CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
                 sendUpdateNetworksCallbackHelper(callbackStub,
@@ -609,28 +607,12 @@ public class ONSProfileSelector {
                 sendUpdateNetworksCallbackHelper(callbackStub,
                         TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
             }
-            /* check if no profile */
+            // check if no profile
             logDebug("stopping scan");
             mNetworkScanCtlr.stopNetworkScan();
         }
     }
 
-    private boolean isActiveSub(int subId) {
-        List<SubscriptionInfo> subscriptionInfos =
-                mSubscriptionManager.getActiveSubscriptionInfoList(false);
-        if (subscriptionInfos == null) {
-            return false;
-        }
-
-        for (SubscriptionInfo subscriptionInfo : subscriptionInfos) {
-            if (subscriptionInfo.getSubscriptionId() == subId) {
-                return true;
-            }
-        }
-
-        return false;
-    }
-
     @VisibleForTesting
     protected int retrieveBestSubscription(List<CellInfo> results) {
         /* sort the results according to signal strength level */
@@ -654,25 +636,6 @@ public class ONSProfileSelector {
         return SubscriptionManager.INVALID_SUBSCRIPTION_ID;
     }
 
-    private boolean isOpportunisticSubEmbedded(
-            ArrayList<AvailableNetworkInfo> availableNetworks) {
-        List<SubscriptionInfo> subscriptionInfos =
-            mSubscriptionManager.getOpportunisticSubscriptions();
-        if (subscriptionInfos == null) {
-            return false;
-        }
-        for (AvailableNetworkInfo availableNetworkInfo : availableNetworks) {
-            for (SubscriptionInfo subscriptionInfo : subscriptionInfos) {
-                if (subscriptionInfo.getSubscriptionId() == availableNetworkInfo.getSubId()
-                        && subscriptionInfo.isEmbedded()) {
-                    return true;
-                }
-            }
-        }
-
-        return false;
-    }
-
     private int getActiveOpportunisticSubId() {
         List<SubscriptionInfo> subscriptionInfos =
             mSubscriptionManager.getActiveSubscriptionInfoList(false);
@@ -731,7 +694,7 @@ public class ONSProfileSelector {
         }
         int phoneId = info.getSimSlotIndex();
         /*  Todo: b/135067156
-         *  Reenable this code once 135067156 is fixed
+         *  Re-enable this code once 135067156 is fixed
         if (mSubscriptionBoundTelephonyManager.isModemEnabledForSlot(phoneId) == enable) {
             logDebug("modem is already enabled ");
             return true;
@@ -741,12 +704,12 @@ public class ONSProfileSelector {
     }
 
     private void stopProfileSelectionProcess(IUpdateAvailableNetworksCallback callbackStub) {
-        stopProfileScanningPrecedure();
+        stopProfileScanningProcedure();
         logDebug("stopProfileSelection");
         disableOpportunisticModem(callbackStub);
     }
 
-    private void stopProfileScanningPrecedure() {
+    private void stopProfileScanningProcedure() {
         synchronized (mLock) {
             if (mNetworkScanCallback != null) {
                 sendUpdateNetworksCallbackHelper(mNetworkScanCallback,
@@ -760,64 +723,28 @@ public class ONSProfileSelector {
         }
     }
 
-    public boolean containsOpportunisticSubs(ArrayList<AvailableNetworkInfo> availableNetworks) {
-        if (mOppSubscriptionInfos == null) {
-            logDebug("received null subscription infos");
-            return false;
-        }
-
-        if (mOppSubscriptionInfos.size() > 0) {
-            logDebug("opportunistic subscriptions size " + mOppSubscriptionInfos.size());
-            ArrayList<AvailableNetworkInfo> filteredAvailableNetworks =
-                    getFilteredAvailableNetworks(
-                            (ArrayList<AvailableNetworkInfo>)availableNetworks, mOppSubscriptionInfos);
-            if (filteredAvailableNetworks.size() > 0) {
-                return true;
-            }
-        }
-
-        return false;
-    }
-
-    public boolean containStandaloneOppSubs(ArrayList<AvailableNetworkInfo> availableNetworks) {
-        if (mStandaloneOppSubInfos == null) {
-            logDebug("received null subscription infos");
-            return false;
-        }
-        if (mStandaloneOppSubInfos.size() > 0) {
-            logDebug("Standalone opportunistic subInfos size " + mStandaloneOppSubInfos.size());
-            ArrayList<AvailableNetworkInfo> filteredAvailableNetworks =
-                    getFilteredAvailableNetworks(
-                            (ArrayList<AvailableNetworkInfo>) availableNetworks,
-                            mStandaloneOppSubInfos);
-            if (filteredAvailableNetworks.size() > 0) {
-                return true;
-            }
-        }
-        return false;
-    }
-
-    public boolean isOpportunisticSubActive() {
-        if (mOppSubscriptionInfos == null) {
-            logDebug("received null subscription infos");
+    /**
+     * Return {@code true} if the provided {@code availableNetworks} contains standalone oppt subs.
+     */
+    public boolean containStandaloneOppSubs(List<AvailableNetworkInfo> availableNetworks) {
+        if (mStandaloneOppSubInfos == null || mStandaloneOppSubInfos.isEmpty()) {
+            logDebug("received null or empty subscription infos");
             return false;
         }
 
-        if (mOppSubscriptionInfos.size() > 0) {
-            logDebug("opportunistic subscriptions size " + mOppSubscriptionInfos.size());
-            for (SubscriptionInfo subscriptionInfo : mOppSubscriptionInfos) {
-                if (mSubscriptionManager.isActiveSubId(subscriptionInfo.getSubscriptionId())) {
-                    return true;
-                }
-            }
-        }
-        return false;
+        logDebug("Standalone opportunistic subInfos size " + mStandaloneOppSubInfos.size());
+        List<AvailableNetworkInfo> filteredAvailableNetworks =
+                getFilteredAvailableNetworks(availableNetworks, mStandaloneOppSubInfos);
+        return !filteredAvailableNetworks.isEmpty();
     }
 
-    public void startProfileSelection(ArrayList<AvailableNetworkInfo> availableNetworks,
+    /**
+     * Start profile selection.
+     */
+    public void startProfileSelection(List<AvailableNetworkInfo> availableNetworks,
             IUpdateAvailableNetworksCallback callbackStub) {
         logDebug("startProfileSelection availableNetworks: " + availableNetworks);
-        if (availableNetworks == null || availableNetworks.size() == 0) {
+        if (availableNetworks == null || availableNetworks.isEmpty()) {
             if (callbackStub != null) {
                 sendUpdateNetworksCallbackHelper(callbackStub,
                         TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
@@ -839,7 +766,7 @@ public class ONSProfileSelector {
     }
 
     /**
-     * select opportunistic profile for data if passing a valid subId.
+     * Select opportunistic profile for data if passing a valid subId.
      * @param subId : opportunistic subId or SubscriptionManager.DEFAULT_SUBSCRIPTION_ID if
      *              deselecting previously set preference.
      */
@@ -890,7 +817,7 @@ public class ONSProfileSelector {
     }
 
     /**
-     * stop profile selection procedure
+     * Stop profile selection procedure
      */
     public void stopProfileSelection(IUpdateAvailableNetworksCallback callbackStub) {
         logDebug("stopProfileSelection");
@@ -903,7 +830,7 @@ public class ONSProfileSelector {
         synchronized (mLock) {
             mOppSubscriptionInfos = mSubscriptionManager
                     .getOpportunisticSubscriptions().stream()
-                    .filter(subInfo -> subInfo.isGroupDisabled() != true)
+                    .filter(subInfo -> !subInfo.isGroupDisabled())
                     .collect(Collectors.toList());
             if (mOppSubscriptionInfos != null) {
                 mStandaloneOppSubInfos = mOppSubscriptionInfos.stream()
@@ -926,7 +853,7 @@ public class ONSProfileSelector {
                 }
             }
             // If the slot doesn't have active opportunistic profile anymore, it's back to
-            // DSDS use-case. Make sure the the modem stack is enabled.
+            // DSDS use-case. Make sure the modem stack is enabled.
             if (!hasActiveOpptProfile) mTelephonyManager.enableModemForSlot(i, true);
         }
     }
@@ -945,7 +872,7 @@ public class ONSProfileSelector {
                 mNetworkAvailableCallBack);
         mEuiccManager = c.getSystemService(EuiccManager.class);
         updateOpportunisticSubscriptions();
-        mThread = new HandlerThread(LOG_TAG);
+        mThread = new HandlerThread(TAG);
         mThread.start();
         mHandler = new Handler(mThread.getLooper()) {
             @Override
@@ -981,18 +908,46 @@ public class ONSProfileSelector {
                 }
             }
         };
-        /* register for profile update events */
+        // register for profile update events
         mSubscriptionManager.addOnOpportunisticSubscriptionsChangedListener(
                 AsyncTask.SERIAL_EXECUTOR, mProfileChangeListener);
     }
 
     private void log(String msg) {
-        Rlog.d(LOG_TAG, msg);
+        Log.d(TAG, msg);
     }
 
     private void logDebug(String msg) {
         if (DBG) {
-            Rlog.d(LOG_TAG, msg);
+            Log.d(TAG, msg);
+        }
+    }
+
+    /**
+     * Dump the state of {@link ONSProfileSelector}.
+     */
+    public void dump(@NonNull FileDescriptor fd, @NonNull PrintWriter printWriter,
+            @NonNull String[] args) {
+        IndentingPrintWriter pw = new IndentingPrintWriter(printWriter, "  ");
+        pw.println(TAG + ":");
+        pw.println("  subId: " + mSubId);
+        pw.println("  mCurrentDataSubId: " + mCurrentDataSubId);
+        pw.println("  mOppSubscriptionInfos: " + (
+                mOppSubscriptionInfos == null || mOppSubscriptionInfos.isEmpty() ? "[]"
+                        : Arrays.toString(mOppSubscriptionInfos.stream().map(
+                                SubscriptionInfo::getSubscriptionId).toArray())));
+        pw.println("  mStandaloneOppSubInfos: " + (
+                mStandaloneOppSubInfos == null || mStandaloneOppSubInfos.isEmpty() ? "[]"
+                        : Arrays.toString(mStandaloneOppSubInfos.stream().map(
+                                SubscriptionInfo::getSubscriptionId).toArray())));
+        pw.println("  mAvailableNetworkInfos:");
+        if (mAvailableNetworkInfos != null && !mAvailableNetworkInfos.isEmpty()) {
+            pw.increaseIndent();
+            for (AvailableNetworkInfo availableNetworkInfo : mAvailableNetworkInfos) {
+                pw.println(availableNetworkInfo);
+            }
+            pw.decreaseIndent();
         }
+        mNetworkScanCtlr.dump(fd, printWriter, args);
     }
 }
diff --git a/src/com/android/ons/ONSStats.java b/src/com/android/ons/ONSStats.java
index d961344..e881af5 100644
--- a/src/com/android/ons/ONSStats.java
+++ b/src/com/android/ons/ONSStats.java
@@ -24,8 +24,9 @@ import android.telephony.SubscriptionManager;
 import com.android.ons.ONSProfileActivator.Result;
 import com.android.ons.ONSProfileDownloader.DownloadRetryResultCode;
 
-import java.util.List;
-
+/**
+ * ONSStats is responsible for collecting and reporting ONS statistics.
+ */
 public class ONSStats {
     private static final String ONS_ATOM_LOG_FILE = "ons_atom_log_info";
     private static final String KEY_PROVISIONING_RESULT = "_provisioning_result";
@@ -55,9 +56,10 @@ public class ONSStats {
         if (ignoreEvent(info)) {
             return false;
         }
+
         int statsCode = OnsStatsLog.ONS_OPPORTUNISTIC_ESIM_PROVISIONING_COMPLETE__ERROR_CODE__RESULT_UNKNOWN;
         if (info.isProvisioningResultUpdated()) {
-            switch (info.getProvisioningResult()) {
+            switch (info.provisioningResult()) {
                 case SUCCESS:
                     statsCode = OnsStatsLog.ONS_OPPORTUNISTIC_ESIM_PROVISIONING_COMPLETE__ERROR_CODE__RESULT_SUCCESS;
                     break;
@@ -89,7 +91,7 @@ public class ONSStats {
                     break;
             }
         } else {
-            switch (info.getDownloadResult()) {
+            switch (info.downloadResult()) {
                 case ERR_UNRESOLVABLE:
                     statsCode = OnsStatsLog.ONS_OPPORTUNISTIC_ESIM_PROVISIONING_COMPLETE__ERROR_CODE__RESULT_UNRESOLVABLE_ERROR;
                     break;
@@ -108,12 +110,12 @@ public class ONSStats {
         }
         OnsStatsLog.write(
                 OnsStatsLog.ONS_OPPORTUNISTIC_ESIM_PROVISIONING_COMPLETE,
-                getSimCarrierId(info.getPrimarySimSubId()),
-                info.getOppSimCarrierId(),
+                getSimCarrierId(info.primarySimSubId()),
+                info.oppSimCarrierId(),
                 info.isWifiConnected(),
                 statsCode,
-                info.getRetryCount(),
-                info.getDetailedErrCode());
+                info.retryCount(),
+                info.detailedErrCode());
         updateSharedPreferences(info);
         return true;
     }
@@ -123,23 +125,22 @@ public class ONSStats {
                 mContext.getSharedPreferences(ONS_ATOM_LOG_FILE, Context.MODE_PRIVATE);
         SharedPreferences.Editor editor = sharedPref.edit();
         if (info.isProvisioningResultUpdated()) {
-            editor.putInt(KEY_PROVISIONING_RESULT, info.getProvisioningResult().ordinal());
+            editor.putInt(KEY_PROVISIONING_RESULT, info.provisioningResult().ordinal());
             editor.remove(KEY_DOWNLOAD_RESULT);
         } else {
-            editor.putInt(KEY_DOWNLOAD_RESULT, info.getDownloadResult().ordinal());
+            editor.putInt(KEY_DOWNLOAD_RESULT, info.downloadResult().ordinal());
             editor.remove(KEY_PROVISIONING_RESULT);
         }
-        editor.putInt(KEY_PRIMARY_CARRIER_ID, getSimCarrierId(info.getPrimarySimSubId()))
-                .putInt(KEY_RETRY_COUNT, info.getRetryCount())
-                .putInt(KEY_OPP_CARRIER_ID, info.getOppSimCarrierId())
-                .putInt(KEY_DETAILED_ERROR_CODE, info.getDetailedErrCode())
+        editor.putInt(KEY_PRIMARY_CARRIER_ID, getSimCarrierId(info.primarySimSubId()))
+                .putInt(KEY_RETRY_COUNT, info.retryCount())
+                .putInt(KEY_OPP_CARRIER_ID, info.oppSimCarrierId())
+                .putInt(KEY_DETAILED_ERROR_CODE, info.detailedErrCode())
                 .apply();
     }
 
     private boolean ignoreEvent(ONSStatsInfo info) {
-        Result result = info.getProvisioningResult();
+        Result result = info.provisioningResult();
         if (info.isProvisioningResultUpdated()) {
-            info.setDetailedErrCode(result.ordinal());
             // Codes are ignored since they are intermediate state of CBRS provisioning check.
             if ((result == Result.DOWNLOAD_REQUESTED)
                     || result == Result.ERR_NO_SIM_INSERTED
@@ -147,16 +148,6 @@ public class ONSStats {
                     || result == Result.ERR_SWITCHING_TO_DUAL_SIM_MODE) {
                 return true;
             }
-
-            // add subscription id for carrier if it doesn't support CBRS.
-            if (result == Result.ERR_CARRIER_DOESNT_SUPPORT_CBRS) {
-                List<SubscriptionInfo> subInfos =
-                        mSubscriptionManager.getActiveSubscriptionInfoList();
-                info.setPrimarySimSubId(
-                        (subInfos != null && !subInfos.isEmpty())
-                                ? subInfos.get(0).getSubscriptionId()
-                                : -1);
-            }
         }
 
         SharedPreferences sharedPref =
@@ -166,15 +157,15 @@ public class ONSStats {
                 (info.isProvisioningResultUpdated()
                         ? sharedPref.getInt(KEY_PROVISIONING_RESULT, -1) != result.ordinal()
                         : sharedPref.getInt(KEY_DOWNLOAD_RESULT, -1)
-                                != info.getDownloadResult().ordinal());
+                                != info.downloadResult().ordinal());
         boolean carrierIdUpdated =
                 sharedPref.getInt(KEY_PRIMARY_CARRIER_ID, -1)
-                        != getSimCarrierId(info.getPrimarySimSubId());
-        boolean retryCountUpdated = sharedPref.getInt(KEY_RETRY_COUNT, -1) != info.getRetryCount();
+                        != getSimCarrierId(info.primarySimSubId());
+        boolean retryCountUpdated = sharedPref.getInt(KEY_RETRY_COUNT, -1) != info.retryCount();
         boolean oppCarrierIdChanged =
-                sharedPref.getInt(KEY_OPP_CARRIER_ID, -1) != info.getOppSimCarrierId();
+                sharedPref.getInt(KEY_OPP_CARRIER_ID, -1) != info.oppSimCarrierId();
         boolean detailedErrorChanged =
-                sharedPref.getInt(KEY_DETAILED_ERROR_CODE, -1) != info.getDetailedErrCode();
+                sharedPref.getInt(KEY_DETAILED_ERROR_CODE, -1) != info.detailedErrCode();
         if (!(errorCodeUpdated
                 || carrierIdUpdated
                 || retryCountUpdated
@@ -183,7 +174,7 @@ public class ONSStats {
             // Result codes are meant to log on every occurrence. These should not be ignored.
             if (result == Result.SUCCESS
                     || result == Result.ERR_DOWNLOADED_ESIM_NOT_FOUND
-                    || info.getDownloadResult()
+                    || info.downloadResult()
                             == DownloadRetryResultCode.ERR_INSTALL_ESIM_PROFILE_FAILED) {
                 return false;
             }
diff --git a/src/com/android/ons/ONSStatsInfo.java b/src/com/android/ons/ONSStatsInfo.java
index 080ed4a..a7b90bf 100644
--- a/src/com/android/ons/ONSStatsInfo.java
+++ b/src/com/android/ons/ONSStatsInfo.java
@@ -16,110 +16,151 @@
 
 package com.android.ons;
 
+import android.annotation.Nullable;
+import android.content.Context;
+import android.telephony.SubscriptionInfo;
+import android.telephony.SubscriptionManager;
+
 import com.android.ons.ONSProfileActivator.Result;
 import com.android.ons.ONSProfileDownloader.DownloadRetryResultCode;
 
-public final class ONSStatsInfo {
-    public static final int INVALID_VALUE = -1;
-    private Result mProvisioningResult = null;
-    private DownloadRetryResultCode mDownloadResult = null;
-    private int mPrimarySimSubId = INVALID_VALUE;
-    private int mOppSimCarrierId = INVALID_VALUE;
-    private int mRetryCount = INVALID_VALUE;
-    private int mDetailedErrCode = INVALID_VALUE;
-    private boolean mIsWifiConnected = false;
-    private boolean mIsProvisioningResultUpdated = false;
-
-    public Result getProvisioningResult() {
-        return mProvisioningResult;
-    }
-
-    public DownloadRetryResultCode getDownloadResult() {
-        return mDownloadResult;
-    }
-
-    public int getPrimarySimSubId() {
-        return mPrimarySimSubId;
-    }
-
-    public int getOppSimCarrierId() {
-        return mOppSimCarrierId;
-    }
-
-    public int getRetryCount() {
-        return mRetryCount;
-    }
-
-    public int getDetailedErrCode() {
-        return mDetailedErrCode;
-    }
+import java.util.List;
 
-    public boolean isWifiConnected() {
-        return mIsWifiConnected;
-    }
+/**
+ * ONSStatsInfo is the container class for ONS statistic information.
+ */
+public record ONSStatsInfo(Result provisioningResult, DownloadRetryResultCode downloadResult,
+                           int primarySimSubId, int oppSimCarrierId, int retryCount,
+                           int detailedErrCode, boolean isWifiConnected) {
+    public static final int INVALID_VALUE = -1;
 
     public boolean isProvisioningResultUpdated() {
-        return mIsProvisioningResultUpdated;
-    }
-
-    public ONSStatsInfo setProvisioningResult(Result result) {
-        mProvisioningResult = result;
-        mDownloadResult = null;
-        mIsProvisioningResultUpdated = true;
-        return this;
-    }
-
-    public ONSStatsInfo setDownloadResult(DownloadRetryResultCode retryResultCode) {
-        mProvisioningResult = null;
-        mDownloadResult = retryResultCode;
-        mIsProvisioningResultUpdated = false;
-        return this;
-    }
-
-    public ONSStatsInfo setPrimarySimSubId(int primarySimSubId) {
-        mPrimarySimSubId = primarySimSubId;
-        return this;
-    }
-
-    public ONSStatsInfo setOppSimCarrierId(int oppSimCarrierId) {
-        mOppSimCarrierId = oppSimCarrierId;
-        return this;
-    }
-
-    public ONSStatsInfo setRetryCount(int retryCount) {
-        mRetryCount = retryCount;
-        return this;
-    }
-
-    public ONSStatsInfo setDetailedErrCode(int detailedErrCode) {
-        mDetailedErrCode = detailedErrCode;
-        return this;
-    }
-
-    public ONSStatsInfo setWifiConnected(boolean wifiConnected) {
-        mIsWifiConnected = wifiConnected;
-        return this;
-    }
-
-    @Override
-    public String toString() {
-        return "ONSStatsInfo{"
-                + "mProvisioningResult="
-                + mProvisioningResult
-                + ", mDownloadResult="
-                + mDownloadResult
-                + ", mPrimarySimSubId="
-                + mPrimarySimSubId
-                + ", mOppSimCarrierId="
-                + mOppSimCarrierId
-                + ", mRetryCount="
-                + mRetryCount
-                + ", mDetailedErrCode="
-                + mDetailedErrCode
-                + ", mIsWifiConnected="
-                + mIsWifiConnected
-                + ", mIsProvisioningResultUpdated="
-                + mIsProvisioningResultUpdated
-                + '}';
+        return provisioningResult != null;
+    }
+
+    private ONSStatsInfo(Builder builder) {
+        this(builder.mProvisioningResult, builder.mDownloadResult, builder.mPrimarySimSubId,
+                builder.mOppSimCarrierId, builder.mRetryCount, builder.mDetailedErrCode,
+                builder.mIsWifiConnected);
+    }
+
+    /**
+     * Builder for {@link ONSStatsInfo}
+     */
+    public static final class Builder {
+        @Nullable
+        private Result mProvisioningResult;
+        @Nullable
+        private DownloadRetryResultCode mDownloadResult;
+        private int mPrimarySimSubId;
+        private int mOppSimCarrierId;
+        private int mRetryCount;
+        private int mDetailedErrCode;
+        private boolean mIsWifiConnected;
+
+        /**
+         * Create a new Builder initialized data from the given ONSStatsInfo
+         * @param other ONSStatsInfo for initial data
+         */
+        public Builder(ONSStatsInfo other) {
+            mProvisioningResult = other.provisioningResult;
+            mDownloadResult = other.downloadResult;
+            mPrimarySimSubId = other.primarySimSubId;
+            mOppSimCarrierId = other.oppSimCarrierId;
+            mRetryCount = other.retryCount;
+            mDetailedErrCode = other.detailedErrCode;
+            mIsWifiConnected = other.isWifiConnected;
+        }
+
+        /**
+         * Create a new Builder with default values.
+         */
+        public Builder() {
+            mProvisioningResult = null;
+            mDownloadResult = null;
+            mPrimarySimSubId = INVALID_VALUE;
+            mOppSimCarrierId = INVALID_VALUE;
+            mRetryCount = INVALID_VALUE;
+            mDetailedErrCode = INVALID_VALUE;
+            mIsWifiConnected = false;
+        }
+
+        /**
+         * Set the provisioning result.
+         */
+        public Builder setProvisioningResult(Context context, @Nullable Result result) {
+            mProvisioningResult = result;
+            mDownloadResult = null;
+            // For provisioning errors, Result enum ordinal is set as detailed error code.
+            mDetailedErrCode = result.ordinal();
+            // add subscription id for carrier if it doesn't support CBRS.
+            if (result == Result.ERR_CARRIER_DOESNT_SUPPORT_CBRS) {
+                SubscriptionManager sm = context.getSystemService(SubscriptionManager.class);
+                if (sm != null) {
+                    List<SubscriptionInfo> subInfos = sm.getActiveSubscriptionInfoList();
+                    mPrimarySimSubId =
+                            (subInfos != null && !subInfos.isEmpty())
+                                    ? subInfos.getFirst().getSubscriptionId()
+                                    : INVALID_VALUE;
+                }
+            }
+            return this;
+        }
+
+        /**
+         * Set the download result
+         */
+        public Builder setDownloadResult(@Nullable DownloadRetryResultCode result) {
+            mProvisioningResult = null;
+            mDownloadResult = result;
+            return this;
+        }
+
+        /**
+         * Set the primary SIM subscription Id.
+         */
+        public Builder setPrimarySimSubId(int primarySimSubId) {
+            mPrimarySimSubId = primarySimSubId;
+            return this;
+        }
+
+        /**
+         * Set the opportunistic SIM carrier Id.n
+         */
+        public Builder setOppSimCarrierId(int oppSimCarrierId) {
+            mOppSimCarrierId = oppSimCarrierId;
+            return this;
+        }
+
+        /**
+         * Set the retry count.
+         */
+        public Builder setRetryCount(int retryCount) {
+            mRetryCount = retryCount;
+            return this;
+        }
+
+        /**
+         * Set the detailed error code
+         */
+        public Builder setDetailedErrCode(int detailedErrCode) {
+            mDetailedErrCode = detailedErrCode;
+            return this;
+        }
+
+        /**
+         * Set if WI-FI is connected.
+         */
+        public Builder setWifiConnected(boolean wifiConnected) {
+            mIsWifiConnected = wifiConnected;
+            return this;
+        }
+
+        /**
+         * Build out a ONSStatsInfo object.
+         */
+        public ONSStatsInfo build() {
+            return new ONSStatsInfo(this);
+        }
     }
 }
diff --git a/src/com/android/ons/OpportunisticNetworkService.java b/src/com/android/ons/OpportunisticNetworkService.java
index 771a21b..f399e88 100644
--- a/src/com/android/ons/OpportunisticNetworkService.java
+++ b/src/com/android/ons/OpportunisticNetworkService.java
@@ -49,6 +49,7 @@ import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyFrameworkInitializer;
 import android.telephony.TelephonyManager;
+import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.IOns;
@@ -57,9 +58,9 @@ import com.android.internal.telephony.IUpdateAvailableNetworksCallback;
 import com.android.internal.telephony.TelephonyIntents;
 import com.android.internal.telephony.TelephonyPermissions;
 import com.android.internal.telephony.flags.Flags;
-import com.android.telephony.Rlog;
 
-import java.util.ArrayList;
+import java.io.FileDescriptor;
+import java.io.PrintWriter;
 import java.util.HashMap;
 import java.util.List;
 
@@ -90,7 +91,7 @@ public class OpportunisticNetworkService extends Service {
     private static final String CARRIER_APP_CONFIG_NAME = "carrierApp";
     private static final String SYSTEM_APP_CONFIG_NAME = "systemApp";
     private static final boolean DBG = true;
-    /* message to indicate sim state update */
+    /** Message to indicate sim state update */
     private static final int MSG_SIM_STATE_CHANGE = 1;
     @VisibleForTesting protected CarrierConfigManager mCarrierConfigManager;
     @VisibleForTesting protected UserManager mUserManager;
@@ -168,12 +169,8 @@ public class OpportunisticNetworkService extends Service {
     }
 
     private static boolean enforceModifyPhoneStatePermission(Context context) {
-        if (context.checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE)
-                == PackageManager.PERMISSION_GRANTED) {
-            return true;
-        }
-
-        return false;
+        return context.checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE)
+                == PackageManager.PERMISSION_GRANTED;
     }
 
     @VisibleForTesting
@@ -192,7 +189,7 @@ public class OpportunisticNetworkService extends Service {
 
         logDebug("handleSimStateChange: subscriptionInfos - " + subscriptionInfos);
         for (SubscriptionInfo subscriptionInfo : subscriptionInfos) {
-            if (subscriptionInfo.getSubscriptionId() == carrierAppConfigInput.getPrimarySub()) {
+            if (subscriptionInfo.getSubscriptionId() == carrierAppConfigInput.primarySub()) {
                 return;
             }
         }
@@ -204,16 +201,16 @@ public class OpportunisticNetworkService extends Service {
         }
         if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null) {
             mProfileSelector.startProfileSelection(
-                    mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME).getAvailableNetworkInfos(),
+                    mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME).availableNetworkInfos(),
                     mONSConfigInputHashMap.get(
-                            SYSTEM_APP_CONFIG_NAME).getAvailableNetworkCallback());
+                            SYSTEM_APP_CONFIG_NAME).availableNetworkCallback());
         }
     }
 
     private boolean hasOpportunisticSubPrivilege(String callingPackage, int subId) {
         return mTelephonyManager.hasCarrierPrivileges(subId)
                 || canManageSubscription(
-                mProfileSelector.getOpprotunisticSubInfo(subId), callingPackage);
+                mProfileSelector.getOpportunisticSubInfo(subId), callingPackage);
     }
 
     private final IOns.Stub mBinder = new IOns.Stub() {
@@ -235,7 +232,7 @@ public class OpportunisticNetworkService extends Service {
         @Override
         public boolean setEnable(boolean enable, String callingPackage) {
             TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
-                    mContext, mSubscriptionManager.getDefaultSubscriptionId(), "setEnable");
+                    mContext, SubscriptionManager.getDefaultSubscriptionId(), "setEnable");
 
             enforceTelephonyFeatureWithException(callingPackage,
                     PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "setEnable");
@@ -253,7 +250,7 @@ public class OpportunisticNetworkService extends Service {
         }
 
         /**
-         * is Opportunistic Network service enabled
+         * Is Opportunistic Network service enabled
          *
          * This method should be called to determine if the Opportunistic Network service
          * is enabled
@@ -269,7 +266,7 @@ public class OpportunisticNetworkService extends Service {
         public boolean isEnabled(String callingPackage) {
             TelephonyPermissions
                     .enforceCallingOrSelfReadPrivilegedPhoneStatePermissionOrCarrierPrivilege(
-                            mContext, mSubscriptionManager.getDefaultSubscriptionId(), "isEnabled");
+                            mContext, SubscriptionManager.getDefaultSubscriptionId(), "isEnabled");
 
             enforceTelephonyFeatureWithException(callingPackage,
                     PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "isEnabled");
@@ -282,7 +279,7 @@ public class OpportunisticNetworkService extends Service {
          *
          * <p>Requires that the calling app has carrier privileges on both primary and
          * secondary subscriptions (see
-         * {@link #hasCarrierPrivileges}), or has permission
+         * {@link TelephonyManager#hasCarrierPrivileges}), or has permission
          * {@link android.Manifest.permission#MODIFY_PHONE_STATE MODIFY_PHONE_STATE}.
          * @param subId which opportunistic subscription
          * {@link SubscriptionManager#getOpportunisticSubscriptions} is preferred for cellular data.
@@ -293,19 +290,20 @@ public class OpportunisticNetworkService extends Service {
          *
          */
         public void setPreferredDataSubscriptionId(int subId, boolean needValidation,
-                ISetOpportunisticDataCallback callbackStub, String callingPackage) {
+                ISetOpportunisticDataCallback callback, String callingPackage) {
             logDebug("setPreferredDataSubscriptionId subId:" + subId
                     + " callingPackage:" + callingPackage);
             if (!enforceModifyPhoneStatePermission(mContext)) {
                 TelephonyPermissions.enforceCallingOrSelfCarrierPrivilege(mContext,
-                        mSubscriptionManager.getDefaultSubscriptionId(), "setPreferredDataSubscriptionId");
+                        SubscriptionManager.getDefaultSubscriptionId(),
+                        "setPreferredDataSubscriptionId");
                 if (subId != SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
                     TelephonyPermissions.enforceCallingOrSelfCarrierPrivilege(mContext, subId,
                             "setPreferredDataSubscriptionId");
                 }
             } else {
                 if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) != null) {
-                    sendSetOpptCallbackHelper(callbackStub,
+                    sendSetOpptCallbackHelper(callback,
                         TelephonyManager.SET_OPPORTUNISTIC_SUB_VALIDATION_FAILED);
                     return;
                 }
@@ -316,7 +314,7 @@ public class OpportunisticNetworkService extends Service {
 
             final long identity = Binder.clearCallingIdentity();
             try {
-                mProfileSelector.selectProfileForData(subId, needValidation, callbackStub);
+                mProfileSelector.selectProfileForData(subId, needValidation, callback);
             } finally {
                 Binder.restoreCallingIdentity(identity);
             }
@@ -326,7 +324,7 @@ public class OpportunisticNetworkService extends Service {
          * Get preferred default data sub Id
          *
          * <p>Requires that the calling app has carrier privileges
-         * (see {@link #hasCarrierPrivileges}),or has either
+         * (see {@link TelephonyManager#hasCarrierPrivileges}),or has either
          * {@link android.Manifest.permission#READ_PRIVILEGED_PHONE_STATE} or.
          * {@link android.Manifest.permission#READ_PHONE_STATE} permission.
          * @return subId preferred opportunistic subscription id or
@@ -374,34 +372,41 @@ public class OpportunisticNetworkService extends Service {
          * <p>
          * <p>Requires that the calling app has carrier privileges on both primary and
          * secondary subscriptions (see
-         * {@link #hasCarrierPrivileges}), or has permission
+         * {@link TelephonyManager#hasCarrierPrivileges}), or has permission
          * {@link android.Manifest.permission#MODIFY_PHONE_STATE MODIFY_PHONE_STATE}.
          *
          */
         public void updateAvailableNetworks(List<AvailableNetworkInfo> availableNetworks,
-                IUpdateAvailableNetworksCallback callbackStub, String callingPackage) {
+                IUpdateAvailableNetworksCallback callback, String callingPackage) {
             logDebug("updateAvailableNetworks: " + availableNetworks);
-            /* check if system app */
+            // check if system app
             if (enforceModifyPhoneStatePermission(mContext)) {
 
                 enforceTelephonyFeatureWithException(callingPackage,
                         PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "updateAvailableNetworks");
 
-                handleSystemAppAvailableNetworks(
-                        (ArrayList<AvailableNetworkInfo>) availableNetworks, callbackStub);
+                handleSystemAppAvailableNetworks(availableNetworks, callback);
             } else {
-                /* check if the app has primary carrier permission */
+                // check if the app has primary carrier permission
                 TelephonyPermissions.enforceCallingOrSelfCarrierPrivilege(mContext,
-                        mSubscriptionManager.getDefaultSubscriptionId(), "updateAvailableNetworks");
+                        SubscriptionManager.getDefaultSubscriptionId(), "updateAvailableNetworks");
 
                 enforceTelephonyFeatureWithException(callingPackage,
                         PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "updateAvailableNetworks");
 
-                handleCarrierAppAvailableNetworks(
-                        (ArrayList<AvailableNetworkInfo>) availableNetworks, callbackStub,
+                handleCarrierAppAvailableNetworks(availableNetworks, callback,
                         callingPackage);
             }
         }
+
+        /**
+         * Dump the state of {@link IOns}.
+         */
+        @Override
+        public void dump(@NonNull FileDescriptor fd, @NonNull PrintWriter printWriter,
+                @NonNull String[] args) {
+            OpportunisticNetworkService.this.dump(fd, printWriter, args);
+        }
     };
 
     @Override
@@ -413,7 +418,7 @@ public class OpportunisticNetworkService extends Service {
     public void onCreate() {
         startWorkerThreadAndInit();
 
-        /* register the service */
+        // register the service
         ServiceRegisterer opportunisticNetworkServiceRegisterer = TelephonyFrameworkInitializer
                 .getTelephonyServiceManager()
                 .getOpportunisticNetworkServiceRegisterer();
@@ -486,9 +491,9 @@ public class OpportunisticNetworkService extends Service {
     }
 
     /**
-     * initialize ONS and register as service.
+     * Initialize ONS and register as service.
      * Read persistent state to update enable state
-     * Start sub components if already enabled.
+     * Start subcomponents if already enabled.
      * @param context context instance
      */
     @VisibleForTesting
@@ -564,9 +569,9 @@ public class OpportunisticNetworkService extends Service {
     };
 
     private void handleCarrierAppAvailableNetworks(
-            ArrayList<AvailableNetworkInfo> availableNetworks,
+            List<AvailableNetworkInfo> availableNetworks,
             IUpdateAvailableNetworksCallback callbackStub, String callingPackage) {
-        if ((availableNetworks != null) && (availableNetworks.size() > 0)) {
+        if (availableNetworks != null && !availableNetworks.isEmpty()) {
             /* carrier apps should report only subscription */
             if (availableNetworks.size() > 1) {
                 log("Carrier app should not pass more than one subscription");
@@ -581,7 +586,7 @@ public class OpportunisticNetworkService extends Service {
                 return;
             }
 
-            if (!mProfileSelector.hasOpprotunisticSub(availableNetworks)) {
+            if (!mProfileSelector.hasOpportunisticSub(availableNetworks)) {
                 log("No opportunistic subscriptions received");
                 if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
                     sendUpdateNetworksCallbackHelper(callbackStub,
@@ -607,7 +612,7 @@ public class OpportunisticNetworkService extends Service {
                     TelephonyPermissions.enforceCallingOrSelfCarrierPrivilege(mContext,
                         availableNetworkInfo.getSubId(), "updateAvailableNetworks");
                 } else {
-                    /* check if the app has opportunistic carrier permission */
+                    // check if the app has opportunistic carrier permission
                     if (!hasOpportunisticSubPrivilege(callingPackage,
                         availableNetworkInfo.getSubId())) {
                         log("No carrier privilege for opportunistic subscription");
@@ -620,24 +625,24 @@ public class OpportunisticNetworkService extends Service {
 
             final long identity = Binder.clearCallingIdentity();
             try {
-                ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworks, callbackStub);
                 SubscriptionInfo subscriptionInfo = mSubscriptionManager.getDefaultVoiceSubscriptionInfo();
                 if (subscriptionInfo != null) {
-                    onsConfigInput.setPrimarySub(subscriptionInfo.getSubscriptionId());
-                    onsConfigInput.setPreferredDataSub(availableNetworks.get(0).getSubId());
+                    ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworks,
+                            callbackStub, subscriptionInfo.getSubscriptionId(),
+                            availableNetworks.getFirst().getSubId());
                     mONSConfigInputHashMap.put(CARRIER_APP_CONFIG_NAME, onsConfigInput);
                 }
-                /* standalone opportunistic subscription should be handled in priority. */
+                // standalone opportunistic subscription should be handled in priority.
                 if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null) {
                     if (mProfileSelector.containStandaloneOppSubs(mONSConfigInputHashMap.get(
-                            SYSTEM_APP_CONFIG_NAME).getAvailableNetworkInfos())) {
+                            SYSTEM_APP_CONFIG_NAME).availableNetworkInfos())) {
                         log("standalone opportunistic subscription is using.");
                         return;
                     }
                 }
 
                 if (mIsEnabled) {
-                    /*  if carrier is reporting availability, then it takes higher priority. */
+                    //  if carrier is reporting availability, then it takes higher priority.
                     mProfileSelector.startProfileSelection(availableNetworks, callbackStub);
                 } else {
                     if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
@@ -660,16 +665,16 @@ public class OpportunisticNetworkService extends Service {
                         TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
                     return;
                 }
-                /* if carrier is reporting unavailability, then decide whether to start
-                   system app request or not. */
+                // If carrier is reporting unavailability, then decide whether to start
+                // system app request or not.
                 if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null) {
                     sendUpdateNetworksCallbackHelper(callbackStub,
                             TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
                     mProfileSelector.startProfileSelection(
                             mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME)
-                                    .getAvailableNetworkInfos(),
+                                    .availableNetworkInfos(),
                             mONSConfigInputHashMap.get(
-                                    SYSTEM_APP_CONFIG_NAME).getAvailableNetworkCallback());
+                                    SYSTEM_APP_CONFIG_NAME).availableNetworkCallback());
                 } else {
                     mProfileSelector.stopProfileSelection(callbackStub);
                 }
@@ -702,13 +707,13 @@ public class OpportunisticNetworkService extends Service {
     }
 
     private void handleSystemAppAvailableNetworks(
-            ArrayList<AvailableNetworkInfo> availableNetworks,
+            List<AvailableNetworkInfo> availableNetworks,
             IUpdateAvailableNetworksCallback callbackStub) {
         final long identity = Binder.clearCallingIdentity();
         try {
-            if ((availableNetworks != null) && (availableNetworks.size() > 0)) {
-                /* all subscriptions should be opportunistic subscriptions */
-                if (!mProfileSelector.hasOpprotunisticSub(availableNetworks)) {
+            if ((availableNetworks != null) && (!availableNetworks.isEmpty())) {
+                // all subscriptions should be opportunistic subscriptions
+                if (!mProfileSelector.hasOpportunisticSub(availableNetworks)) {
                     log("No opportunistic subscriptions received");
                     if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
                         sendUpdateNetworksCallbackHelper(callbackStub,
@@ -722,8 +727,8 @@ public class OpportunisticNetworkService extends Service {
                 }
                 mONSConfigInputHashMap.put(SYSTEM_APP_CONFIG_NAME,
                         new ONSConfigInput(availableNetworks, callbackStub));
-                /* reporting availability. proceed if carrier app has not requested any, but
-                   standalone opportunistic subscription should be handled in priority. */
+                // Reporting availability. proceed if carrier app has not requested any, but
+                // standalone opportunistic subscription should be handled in priority.
                 if (mIsEnabled) {
                     if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) == null
                             || mProfileSelector.containStandaloneOppSubs(availableNetworks)) {
@@ -745,8 +750,8 @@ public class OpportunisticNetworkService extends Service {
                         TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
                     return;
                 }
-                /* if system is reporting unavailability, then decide whether to start
-                   carrier app request or not. */
+                // If system is reporting unavailability, then decide whether to start carrier
+                // app request or not.
                 mONSConfigInputHashMap.put(SYSTEM_APP_CONFIG_NAME, null);
                 if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) == null) {
                     mProfileSelector.stopProfileSelection(callbackStub);
@@ -756,9 +761,9 @@ public class OpportunisticNetworkService extends Service {
                     log("Try to start carrier app request");
                     mProfileSelector.startProfileSelection(
                             mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME)
-                                    .getAvailableNetworkInfos(),
+                                    .availableNetworkInfos(),
                             mONSConfigInputHashMap.get(
-                                    CARRIER_APP_CONFIG_NAME).getAvailableNetworkCallback());
+                                    CARRIER_APP_CONFIG_NAME).availableNetworkCallback());
                 }
             }
         } finally {
@@ -778,28 +783,29 @@ public class OpportunisticNetworkService extends Service {
      */
     private void enableOpportunisticNetwork(boolean enable) {
         synchronized (mLock) {
-            if (mIsEnabled != enable) {
-                updateEnableState(enable);
-                if (!mIsEnabled) {
-                    mProfileSelector.stopProfileSelection(null);
-                } else {
-                    if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) != null &&
-                        mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME)
-                            .getAvailableNetworkInfos() != null) {
-                        mProfileSelector.startProfileSelection(
+            if (mIsEnabled == enable) {
+                return;
+            }
+            updateEnableState(enable);
+            if (!mIsEnabled) {
+                mProfileSelector.stopProfileSelection(null);
+            } else {
+                if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) != null
+                        && mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME)
+                        .availableNetworkInfos() != null) {
+                    mProfileSelector.startProfileSelection(
                             mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME)
-                                .getAvailableNetworkInfos(),
+                                    .availableNetworkInfos(),
                             mONSConfigInputHashMap.get(
-                                CARRIER_APP_CONFIG_NAME).getAvailableNetworkCallback());
-                    } else if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null &&
-                        mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME)
-                            .getAvailableNetworkInfos() != null) {
-                        mProfileSelector.startProfileSelection(
+                                    CARRIER_APP_CONFIG_NAME).availableNetworkCallback());
+                } else if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null
+                        && mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME)
+                        .availableNetworkInfos() != null) {
+                    mProfileSelector.startProfileSelection(
                             mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME)
-                                .getAvailableNetworkInfos(),
+                                    .availableNetworkInfos(),
                             mONSConfigInputHashMap.get(
-                                SYSTEM_APP_CONFIG_NAME).getAvailableNetworkCallback());
-                    }
+                                    SYSTEM_APP_CONFIG_NAME).availableNetworkCallback());
                 }
             }
         }
@@ -817,8 +823,7 @@ public class OpportunisticNetworkService extends Service {
             return;
         }
 
-        if (!Flags.enforceTelephonyFeatureMappingForPublicApis()
-                || !CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
+        if (!CompatChanges.isChangeEnabled(ENABLE_FEATURE_MAPPING, callingPackage,
                 Binder.getCallingUserHandle())
                 || mVendorApiLevel < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
             // Skip to check associated telephony feature,
@@ -843,10 +848,33 @@ public class OpportunisticNetworkService extends Service {
     }
 
     private void log(String msg) {
-        Rlog.d(TAG, msg);
+        Log.d(TAG, msg);
     }
 
     private void logDebug(String msg) {
-        if (DBG) Rlog.d(TAG, msg);
+        if (DBG) Log.d(TAG, msg);
+    }
+
+    /**
+     * Dump the state of {@link OpportunisticNetworkService}.
+     *
+     * @param fd File descriptor
+     * @param pw Print writer
+     * @param args Arguments
+     */
+    @Override
+    public void dump(@NonNull FileDescriptor fd, @NonNull PrintWriter pw,
+            @NonNull String[] args) {
+        mContext.enforceCallingOrSelfPermission(android.Manifest.permission.DUMP,
+                "Requires android.Manifest.permission.DUMP");
+        final long token = Binder.clearCallingIdentity();
+        try {
+            pw.println(OpportunisticNetworkService.class.getSimpleName() + ":");
+            pw.println("  mIsEnabled = " + mIsEnabled);
+            mONSProfileActivator.dump(fd, pw, args);
+            mProfileSelector.dump(fd, pw, args);
+        } finally {
+            Binder.restoreCallingIdentity(token);
+        }
     }
 }
diff --git a/tests/src/com/android/ons/ONSNetworkScanCtlrTest.java b/tests/src/com/android/ons/ONSNetworkScanCtlrTest.java
index 0053adc..399838a 100644
--- a/tests/src/com/android/ons/ONSNetworkScanCtlrTest.java
+++ b/tests/src/com/android/ons/ONSNetworkScanCtlrTest.java
@@ -67,7 +67,7 @@ public class ONSNetworkScanCtlrTest extends ONSBaseTest {
         super.setUp("ONSTest");
         mLooper = null;
         mNetworkScan = new NetworkScan(1, 1);
-        doReturn(mNetworkScan).when(mMockTelephonyManager).requestNetworkScan(anyObject(), anyObject());
+        doReturn(mNetworkScan).when(mMockTelephonyManager).requestNetworkScan(any(), any());
     }
 
     @After
@@ -85,7 +85,7 @@ public class ONSNetworkScanCtlrTest extends ONSBaseTest {
         mccMncs.add("310210");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
                 new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<AvailableNetworkInfo>();
+        List<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<AvailableNetworkInfo>();
         availableNetworkInfos.add(availableNetworkInfo);
         List<CellInfo> expectedResults = new ArrayList<CellInfo>();
         CellIdentityLte cellIdentityLte = new CellIdentityLte(310, 210, 1, 1, 1);
@@ -113,7 +113,7 @@ public class ONSNetworkScanCtlrTest extends ONSBaseTest {
         mccMncs.add("310210");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
                 new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<AvailableNetworkInfo>();
+        List<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<AvailableNetworkInfo>();
         availableNetworkInfos.add(availableNetworkInfo);
         mError = NetworkScan.SUCCESS;
 
@@ -138,7 +138,7 @@ public class ONSNetworkScanCtlrTest extends ONSBaseTest {
         mccMncs.add("310211");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
             new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<AvailableNetworkInfo>();
+        List<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<AvailableNetworkInfo>();
         availableNetworkInfos.add(availableNetworkInfo);
 
         initONSNetworkScanCtrl();
@@ -161,7 +161,7 @@ public class ONSNetworkScanCtlrTest extends ONSBaseTest {
         mccMncs.add("310210");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
                 new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos =
+        List<AvailableNetworkInfo> availableNetworkInfos =
                 new ArrayList<AvailableNetworkInfo>();
         availableNetworkInfos.add(availableNetworkInfo);
         mCallbackInvoked = false;
@@ -295,7 +295,7 @@ public class ONSNetworkScanCtlrTest extends ONSBaseTest {
                         .setMccMncs(new ArrayList<>(Arrays.asList("310210")))
                         .setRadioAccessSpecifiers(ras)
                         .build();
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos =
+        List<AvailableNetworkInfo> availableNetworkInfos =
             new ArrayList<AvailableNetworkInfo>();
         availableNetworkInfos.add(availableNetworkInfo);
 
diff --git a/tests/src/com/android/ons/ONSProfileActivatorTest.java b/tests/src/com/android/ons/ONSProfileActivatorTest.java
index 3a259b8..f1354d9 100644
--- a/tests/src/com/android/ons/ONSProfileActivatorTest.java
+++ b/tests/src/com/android/ons/ONSProfileActivatorTest.java
@@ -104,8 +104,8 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
                 .KEY_CARRIER_SUPPORTS_OPP_DATA_AUTO_PROVISIONING_BOOL, true);
         doReturn(persistableBundle).when(mMockCarrierConfigManager).getConfigForSubId(TEST_SUBID_1);
 
-        ArrayList<UiccCardInfo> uiccCardInfoList = new ArrayList<>();
-        ArrayList<UiccPortInfo> uiccPortInfoList =  new ArrayList<>();
+        List<UiccCardInfo> uiccCardInfoList = new ArrayList<>();
+        List<UiccPortInfo> uiccPortInfoList =  new ArrayList<>();
         uiccPortInfoList.add(
                 new UiccPortInfo("123451234567890" /* iccId */,
                 0 /* portIdx */,
@@ -219,7 +219,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
         doReturn(true).when(mMockTeleManager).doesSwitchMultiSimConfigTriggerReboot();
         doReturn(mMockactiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
         doReturn(1).when(mMockactiveSubInfos).size();
-        doReturn(mMockSubInfo).when(mMockactiveSubInfos).get(TEST_SUBID_0);
+        doReturn(mMockSubInfo).when(mMockactiveSubInfos).getFirst();
         doReturn(1).when(mMockSubInfo).getSubscriptionId();
         doReturn(false).when(mMockSubInfo).isOpportunistic();
 
@@ -241,7 +241,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
         doReturn(1).when(mMockTeleManager).getActiveModemCount();
         doReturn(mMockactiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
         doReturn(1).when(mMockactiveSubInfos).size();
-        doReturn(mMockSubInfo).when(mMockactiveSubInfos).get(TEST_SUBID_0);
+        doReturn(mMockSubInfo).when(mMockactiveSubInfos).getFirst();
         doReturn(1).when(mMockSubInfo).getSubscriptionId();
         doReturn(false).when(mMockSubInfo).isOpportunistic();
 
@@ -265,6 +265,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
         doReturn(2).when(mMockTeleManager).getActiveModemCount();
         doReturn(mMockactiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
         doReturn(0).when(mMockactiveSubInfos).size();
+        doReturn(true).when(mMockactiveSubInfos).isEmpty();
 
         ONSProfileActivator onsProfileActivator = new ONSProfileActivator(mMockContext,
                 mMockSubManager, mMockTeleManager, mMockCarrierConfigManager, mMockEuiccManager,
@@ -308,7 +309,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
 
         doReturn(mMockactiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
         doReturn(1).when(mMockactiveSubInfos).size();
-        doReturn(mMockSubInfo).when(mMockactiveSubInfos).get(TEST_SUBID_0);
+        doReturn(mMockSubInfo).when(mMockactiveSubInfos).getFirst();
         doReturn(TEST_SUBID_0).when(mMockSubInfo).getSubscriptionId();
         doReturn(false).when(mMockSubInfo).isOpportunistic();
 
@@ -330,7 +331,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
         doReturn(2).when(mMockTeleManager).getSupportedModemCount();
         doReturn(2).when(mMockTeleManager).getActiveModemCount();
 
-        ArrayList<SubscriptionInfo> mActiveSubInfos = new ArrayList<>();
+        List<SubscriptionInfo> mActiveSubInfos = new ArrayList<>();
         mActiveSubInfos.add(mMockSubInfo);
         mActiveSubInfos.add(mMockSubInfo1);
         doReturn(mActiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
@@ -353,7 +354,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
         doReturn(2).when(mMockTeleManager).getSupportedModemCount();
         doReturn(2).when(mMockTeleManager).getActiveModemCount();
 
-        ArrayList<SubscriptionInfo> mActiveSubInfos = new ArrayList<>();
+        List<SubscriptionInfo> mActiveSubInfos = new ArrayList<>();
         mActiveSubInfos.add(mMockSubInfo);
         mActiveSubInfos.add(mMockSubInfo1);
         doReturn(mActiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
@@ -383,7 +384,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
         doReturn(2).when(mMockTeleManager).getSupportedModemCount();
         doReturn(2).when(mMockTeleManager).getActiveModemCount();
 
-        ArrayList<SubscriptionInfo> mActiveSubInfos = new ArrayList<>();
+        List<SubscriptionInfo> mActiveSubInfos = new ArrayList<>();
         mActiveSubInfos.add(mMockSubInfo); //Primary CBRS SIM
         mActiveSubInfos.add(mMockSubInfo1); //Opportunistic eSIM
         doReturn(mActiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
@@ -433,7 +434,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
         doReturn(2).when(mMockTeleManager).getActiveModemCount();
         doReturn(mMockactiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
         doReturn(1).when(mMockactiveSubInfos).size();
-        doReturn(mMockSubInfo).when(mMockactiveSubInfos).get(0);
+        doReturn(mMockSubInfo).when(mMockactiveSubInfos).getFirst();
         doReturn(true).when(mMockSubInfo).isOpportunistic();
 
         ONSProfileActivator onsProfileActivator = new ONSProfileActivator(mMockContext,
@@ -456,7 +457,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
 
         doReturn(mMockactiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
         doReturn(1).when(mMockactiveSubInfos).size();
-        doReturn(mMockSubInfo).when(mMockactiveSubInfos).get(0);
+        doReturn(mMockSubInfo).when(mMockactiveSubInfos).getFirst();
         doReturn(false).when(mMockSubInfo).isOpportunistic();
         doReturn(TEST_SUBID_1).when(mMockSubInfo).getSubscriptionId();
         doReturn(null).when(mMockSubInfo).getGroupUuid();
@@ -655,7 +656,7 @@ public class ONSProfileActivatorTest extends ONSBaseTest {
 
         doReturn(mMockactiveSubInfos).when(mMockSubManager).getActiveSubscriptionInfoList();
         doReturn(1).when(mMockactiveSubInfos).size();
-        doReturn(mMockSubInfo).when(mMockactiveSubInfos).get(0);
+        doReturn(mMockSubInfo).when(mMockactiveSubInfos).getFirst();
         doReturn(false).when(mMockSubInfo).isOpportunistic();
         doReturn(TEST_SUBID_0).when(mMockSubInfo).getSubscriptionId();
         doReturn(null).when(mMockSubInfo).getGroupUuid();
diff --git a/tests/src/com/android/ons/ONSProfileConfiguratorTest.java b/tests/src/com/android/ons/ONSProfileConfiguratorTest.java
index c13acbc..704b2a4 100644
--- a/tests/src/com/android/ons/ONSProfileConfiguratorTest.java
+++ b/tests/src/com/android/ons/ONSProfileConfiguratorTest.java
@@ -38,6 +38,7 @@ import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
 import java.util.ArrayList;
+import java.util.List;
 import java.util.UUID;
 
 public class ONSProfileConfiguratorTest extends ONSBaseTest {
@@ -98,7 +99,7 @@ public class ONSProfileConfiguratorTest extends ONSBaseTest {
         mOnsProfileConfigurator.groupWithPSIMAndSetOpportunistic(
                 mMockSubscriptionInfo1, parcelUuid);
 
-        ArrayList<Integer> subList = new ArrayList<>();
+        List<Integer> subList = new ArrayList<>();
         subList.add(TEST_SUB_ID);
         verify(mMockSubManager).addSubscriptionsIntoGroup(subList, parcelUuid);
     }
@@ -137,7 +138,7 @@ public class ONSProfileConfiguratorTest extends ONSBaseTest {
                         intent,
                         PendingIntent.FLAG_IMMUTABLE);
 
-        ArrayList<SubscriptionInfo> activeSubInfos = new ArrayList<>();
+        List<SubscriptionInfo> activeSubInfos = new ArrayList<>();
 
         doReturn(1).when(mMockSubscriptionInfo1).getSubscriptionId();
         doReturn(1).when(mMockSubscriptionInfo1).getCardId();
@@ -180,7 +181,7 @@ public class ONSProfileConfiguratorTest extends ONSBaseTest {
         doReturn(2).when(mMockSubscriptionInfo2).getCardId();
         doReturn(false).when(mMockSubManager).isActiveSubscriptionId(2);
 
-        ArrayList<SubscriptionInfo> oppSubList = new ArrayList<>();
+        List<SubscriptionInfo> oppSubList = new ArrayList<>();
         oppSubList.add(mMockSubscriptionInfo1);
         oppSubList.add(mMockSubscriptionInfo2);
         doReturn(oppSubList).when(mMockSubManager).getOpportunisticSubscriptions();
@@ -218,7 +219,7 @@ public class ONSProfileConfiguratorTest extends ONSBaseTest {
                 CarrierConfigManager.KEY_OPPORTUNISTIC_CARRIER_IDS_INT_ARRAY, oppCarrierList);
         doReturn(persistableBundle).when(mMockCarrierConfigManager).getConfigForSubId(TEST_SUB_ID);
 
-        ArrayList<SubscriptionInfo> oppSubList = new ArrayList<>();
+        List<SubscriptionInfo> oppSubList = new ArrayList<>();
         oppSubList.add(mMockSubscriptionInfo1);
         oppSubList.add(mMockSubscriptionInfo2);
         doReturn(oppSubList).when(mMockSubManager).getAvailableSubscriptionInfoList();
diff --git a/tests/src/com/android/ons/ONSProfileDownloaderTest.java b/tests/src/com/android/ons/ONSProfileDownloaderTest.java
index e8a0912..42ffe73 100644
--- a/tests/src/com/android/ons/ONSProfileDownloaderTest.java
+++ b/tests/src/com/android/ons/ONSProfileDownloaderTest.java
@@ -23,7 +23,7 @@ import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.verifyZeroInteractions;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
 
 import android.content.Context;
 import android.content.Intent;
@@ -64,8 +64,6 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
     @Mock
     CarrierConfigManager mMockCarrierConfigManager;
     @Mock
-    private ONSProfileConfigurator mMockONSProfileConfig;
-    @Mock
     ONSProfileDownloader.IONSProfileDownloaderListener mMockDownloadListener;
 
     @Before
@@ -108,7 +106,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
         ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mMockContext,
                 mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                mMockONSProfileConfig, null);
+                null);
 
         onsProfileDownloader.downloadProfile(mMockSubInfo.getSubscriptionId());
 
@@ -146,7 +144,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
                 ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mMockContext,
                         mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                        mMockONSProfileConfig, mListener);
+                        mListener);
 
                 Intent intent = new Intent(mContext, ONSProfileResultReceiver.class);
                 intent.setAction(ONSProfileDownloader.ACTION_ONS_ESIM_DOWNLOAD);
@@ -191,7 +189,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
                 ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mMockContext,
                         mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                        mMockONSProfileConfig, mMockDownloadListener);
+                        mMockDownloadListener);
 
                 Intent intent = new Intent(mContext, ONSProfileResultReceiver.class);
                 intent.setAction(ONSProfileDownloader.ACTION_ONS_ESIM_DOWNLOAD);
@@ -214,7 +212,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
             e.printStackTrace();
         }
 
-        verifyZeroInteractions(mMockEuiccManager);
+        verifyNoMoreInteractions(mMockEuiccManager);
         workerThread.exit();
     }
 
@@ -229,7 +227,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
                 ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mMockContext,
                         mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                        mMockONSProfileConfig, mMockDownloadListener);
+                        mMockDownloadListener);
 
                 Intent intent = new Intent(mContext, ONSProfileResultReceiver.class);
                 intent.setAction(ONSProfileDownloader.ACTION_ONS_ESIM_DOWNLOAD);
@@ -279,7 +277,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
                 ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mContext,
                         mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                        mMockONSProfileConfig, mMockDownloadListener);
+                        mMockDownloadListener);
 
                 Intent intent = new Intent(mContext, ONSProfileResultReceiver.class);
                 intent.setAction(ONSProfileDownloader.ACTION_ONS_ESIM_DOWNLOAD);
@@ -336,7 +334,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
                 ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mContext,
                         mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                        mMockONSProfileConfig, mMockDownloadListener);
+                        mMockDownloadListener);
 
                 Intent intent = new Intent(mContext, ONSProfileResultReceiver.class);
                 intent.setAction(ONSProfileDownloader.ACTION_ONS_ESIM_DOWNLOAD);
@@ -393,7 +391,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
                 ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mContext,
                         mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                        mMockONSProfileConfig, mMockDownloadListener);
+                        mMockDownloadListener);
 
                 Intent intent = new Intent(mContext, ONSProfileResultReceiver.class);
                 intent.setAction(ONSProfileDownloader.ACTION_ONS_ESIM_DOWNLOAD);
@@ -450,7 +448,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
                 ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mContext,
                         mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                        mMockONSProfileConfig, mMockDownloadListener);
+                        mMockDownloadListener);
 
                 Intent intent = new Intent(mContext, ONSProfileResultReceiver.class);
                 intent.setAction(ONSProfileDownloader.ACTION_ONS_ESIM_DOWNLOAD);
@@ -494,7 +492,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
                 ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mMockContext,
                         mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                        mMockONSProfileConfig, mMockDownloadListener);
+                        mMockDownloadListener);
 
                 ONSProfileDownloader.DownloadHandler downloadHandler =
                         onsProfileDownloader.new DownloadHandler();
@@ -636,7 +634,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
         ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mContext,
                 mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                mMockONSProfileConfig, mMockDownloadListener);
+                mMockDownloadListener);
 
         //When multiple download requests are received, download should be triggered only once.
         onsProfileDownloader.downloadProfile(mMockSubInfo.getSubscriptionId());
@@ -693,7 +691,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
 
         ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mContext,
                 mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                mMockONSProfileConfig, mMockDownloadListener);
+                mMockDownloadListener);
 
         // First download request to be failed with INVALID_SMDP_ADDRESS error because of empty SMDP
         // server address in configuration.
@@ -739,7 +737,7 @@ public class ONSProfileDownloaderTest extends ONSBaseTest {
         doReturn(mMockSubInfo).when(mMockSubManager).getActiveSubscriptionInfo(TEST_SUB_ID);
         ONSProfileDownloader onsProfileDownloader = new ONSProfileDownloader(mContext,
                 mMockCarrierConfigManager, mMockEuiccManager, mMockSubManager,
-                mMockONSProfileConfig, mMockDownloadListener);
+                mMockDownloadListener);
 
         onsProfileDownloader.downloadProfile(TEST_SUB_ID);
         verify(mMockEuiccManagerForCard1, times(1)).downloadSubscription(any(), eq(true), any());
diff --git a/tests/src/com/android/ons/ONSProfileSelectorTest.java b/tests/src/com/android/ons/ONSProfileSelectorTest.java
index 68925f7..5538b04 100644
--- a/tests/src/com/android/ons/ONSProfileSelectorTest.java
+++ b/tests/src/com/android/ons/ONSProfileSelectorTest.java
@@ -195,7 +195,7 @@ public class ONSProfileSelectorTest extends ONSBaseTest {
             @Override
             public void run() {
                 Looper.prepare();
-                doReturn(true).when(mONSNetworkScanCtlr).startFastNetworkScan(anyObject());
+                doReturn(true).when(mONSNetworkScanCtlr).startFastNetworkScan(any());
                 doReturn(new ArrayList<>()).when(mSubscriptionManager)
                     .getOpportunisticSubscriptions();
                 mONSProfileSelector = new MyONSProfileSelector(mContext,
@@ -214,7 +214,7 @@ public class ONSProfileSelectorTest extends ONSBaseTest {
         waitUntilReady();
         mReady = false;
 
-        // Testing startProfileSelection without any oppotunistic data.
+        // Testing startProfileSelection without any opportunistic data.
         // should not get any callback invocation.
         waitUntilReady(100);
         assertEquals(
@@ -292,7 +292,7 @@ public class ONSProfileSelectorTest extends ONSBaseTest {
         mReady = false;
         mDataSubId = -1;
 
-        // Testing startProfileSelection with oppotunistic sub.
+        // Testing startProfileSelection with opportunistic sub.
         // On success onProfileSelectionDone must get invoked.
         assertFalse(mReady);
         waitForMs(500);
@@ -485,7 +485,7 @@ public class ONSProfileSelectorTest extends ONSBaseTest {
     }
 
     @Test
-    public void testselectProfileForDataWithNoOpportunsticSub() {
+    public void testselectProfileForDataWithNoOpportunisticSub() {
         mReady = false;
         doReturn(new ArrayList<>()).when(mSubscriptionManager).getOpportunisticSubscriptions();
         new Thread(new Runnable() {
@@ -506,7 +506,7 @@ public class ONSProfileSelectorTest extends ONSBaseTest {
         // Wait till initialization is complete.
         waitUntilReady();
 
-        // Testing selectProfileForData with no oppotunistic sub and the function should
+        // Testing selectProfileForData with no opportunistic sub and the function should
         // return false.
         mONSProfileSelector.selectProfileForData(1, false, null);
     }
@@ -685,7 +685,7 @@ public class ONSProfileSelectorTest extends ONSBaseTest {
         mReady = false;
         mDataSubId = -1;
 
-        // Testing startProfileSelection with oppotunistic sub.
+        // Testing startProfileSelection with opportunistic sub.
         // On success onProfileSelectionDone must get invoked.
         assertFalse(mReady);
         waitForMs(500);
@@ -721,7 +721,7 @@ public class ONSProfileSelectorTest extends ONSBaseTest {
         mReady = false;
         mDataSubId = -1;
 
-        // Testing startProfileSelection with oppotunistic sub.
+        // Testing startProfileSelection with opportunistic sub.
         // On success onProfileSelectionDone must get invoked.
         assertFalse(mReady);
         waitForMs(500);
@@ -1022,12 +1022,12 @@ public class ONSProfileSelectorTest extends ONSBaseTest {
 
         UiccPortInfo uiccPortInfo1 = new UiccPortInfo("", 0, 0, false);
         UiccPortInfo uiccPortInfo2 = new UiccPortInfo("", 1, 0, false);
-        ArrayList<UiccPortInfo> uiccPortInfoList = new ArrayList<>();
+        List<UiccPortInfo> uiccPortInfoList = new ArrayList<>();
         uiccPortInfoList.add(uiccPortInfo1);
         uiccPortInfoList.add(uiccPortInfo2);
 
         UiccCardInfo uiccCardInfo = new UiccCardInfo(true, 1, "", 0, false, true, uiccPortInfoList);
-        ArrayList<UiccCardInfo> uiccCardInfoList = new ArrayList<>();
+        List<UiccCardInfo> uiccCardInfoList = new ArrayList<>();
         uiccCardInfoList.add(uiccCardInfo);
 
         doReturn(uiccCardInfoList).when(mMockTelephonyManager).getUiccCardsInfo();
diff --git a/tests/src/com/android/ons/ONSStatsInfoTest.java b/tests/src/com/android/ons/ONSStatsInfoTest.java
index 3cd0456..bcf4ce1 100644
--- a/tests/src/com/android/ons/ONSStatsInfoTest.java
+++ b/tests/src/com/android/ons/ONSStatsInfoTest.java
@@ -21,76 +21,95 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 
+import android.content.Context;
+
+import androidx.test.InstrumentationRegistry;
+
 import com.android.ons.ONSProfileActivator.Result;
 import com.android.ons.ONSProfileDownloader.DownloadRetryResultCode;
 
+import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 
 @RunWith(JUnit4.class)
 public class ONSStatsInfoTest {
+    private Context mContext;
+
+    @Before
+    public void setUp() {
+        mContext = InstrumentationRegistry.getTargetContext();
+    }
 
     @Test
     public void testProvisioningResult() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setProvisioningResult(Result.ERR_AUTO_PROVISIONING_DISABLED);
-        assertEquals(Result.ERR_AUTO_PROVISIONING_DISABLED, info.getProvisioningResult());
-        assertNull(info.getDownloadResult());
+        info = new ONSStatsInfo.Builder()
+                .setProvisioningResult(mContext, Result.ERR_AUTO_PROVISIONING_DISABLED)
+                .build();
+        assertEquals(Result.ERR_AUTO_PROVISIONING_DISABLED, info.provisioningResult());
+        assertNull(info.downloadResult());
         assertTrue(info.isProvisioningResultUpdated());
     }
 
     @Test
     public void testDownloadResult() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setDownloadResult(DownloadRetryResultCode.ERR_MEMORY_FULL);
-        assertEquals(DownloadRetryResultCode.ERR_MEMORY_FULL, info.getDownloadResult());
-        assertNull(info.getProvisioningResult());
+        info = new ONSStatsInfo.Builder()
+                .setDownloadResult(DownloadRetryResultCode.ERR_MEMORY_FULL)
+                .build();
+        assertEquals(DownloadRetryResultCode.ERR_MEMORY_FULL, info.downloadResult());
+        assertNull(info.provisioningResult());
         assertFalse(info.isProvisioningResultUpdated());
     }
 
     @Test
     public void testPrimarySimSubId() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setPrimarySimSubId(1);
-        assertEquals(1, info.getPrimarySimSubId());
+        info = new ONSStatsInfo.Builder().setPrimarySimSubId(1).build();
+        assertEquals(1, info.primarySimSubId());
     }
 
     @Test
     public void testOppSimCarrierId() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setOppSimCarrierId(1221);
-        assertEquals(1221, info.getOppSimCarrierId());
+        info = new ONSStatsInfo.Builder().setOppSimCarrierId(1221).build();
+        assertEquals(1221, info.oppSimCarrierId());
     }
 
     @Test
     public void testRetryCount() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setRetryCount(3);
-        assertEquals(3, info.getRetryCount());
+        info = new ONSStatsInfo.Builder().setRetryCount(3).build();
+        assertEquals(3, info.retryCount());
     }
 
     @Test
     public void testDetailedErrCode() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setDetailedErrCode(1000);
-        assertEquals(1000, info.getDetailedErrCode());
+        info = new ONSStatsInfo.Builder().setDetailedErrCode(1000).build();
+        assertEquals(1000, info.detailedErrCode());
     }
 
     @Test
     public void testIsWifiConnected() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setWifiConnected(true);
+        info = new ONSStatsInfo.Builder().setWifiConnected(true).build();
         assertTrue(info.isWifiConnected());
     }
 
     @Test
     public void testIsProvisioningResultUpdated() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setProvisioningResult(Result.ERR_ESIM_NOT_SUPPORTED);
+        info = new ONSStatsInfo.Builder()
+                .setProvisioningResult(mContext, Result.ERR_ESIM_NOT_SUPPORTED)
+                .build();
         assertTrue(info.isProvisioningResultUpdated());
 
-        info.setDownloadResult(DownloadRetryResultCode.ERR_MEMORY_FULL);
+        info = new ONSStatsInfo.Builder(info)
+                .setDownloadResult(DownloadRetryResultCode.ERR_MEMORY_FULL)
+                .build();
         assertFalse(info.isProvisioningResultUpdated());
     }
 }
diff --git a/tests/src/com/android/ons/ONSStatsTest.java b/tests/src/com/android/ons/ONSStatsTest.java
index 12c49af..096dda8 100644
--- a/tests/src/com/android/ons/ONSStatsTest.java
+++ b/tests/src/com/android/ons/ONSStatsTest.java
@@ -205,25 +205,38 @@ public class ONSStatsTest {
     @Test
     public void testLogEvent() {
         ONSStatsInfo info =
-                new ONSStatsInfo()
+                new ONSStatsInfo.Builder()
                         .setPrimarySimSubId(1)
-                        .setProvisioningResult(Result.ERR_CANNOT_SWITCH_TO_DUAL_SIM_MODE);
+                        .setProvisioningResult(mContext, Result.ERR_CANNOT_SWITCH_TO_DUAL_SIM_MODE)
+                        .build();
         assertTrue(mONSStats.logEvent(info));
     }
 
     @Test
     public void testIgnoredLogEvents() {
         // ignored error codes should not log.
-        ONSStatsInfo info = new ONSStatsInfo().setProvisioningResult(Result.DOWNLOAD_REQUESTED);
+        ONSStatsInfo info =
+                new ONSStatsInfo.Builder()
+                        .setProvisioningResult(mContext, Result.DOWNLOAD_REQUESTED)
+                        .build();
         assertFalse(mONSStats.logEvent(info));
 
-        info = new ONSStatsInfo().setProvisioningResult(Result.ERR_NO_SIM_INSERTED);
+        info =
+                new ONSStatsInfo.Builder()
+                        .setProvisioningResult(mContext, Result.ERR_NO_SIM_INSERTED)
+                        .build();
         assertFalse(mONSStats.logEvent(info));
 
-        info = new ONSStatsInfo().setProvisioningResult(Result.ERR_DUPLICATE_DOWNLOAD_REQUEST);
+        info =
+                new ONSStatsInfo.Builder()
+                        .setProvisioningResult(mContext, Result.ERR_DUPLICATE_DOWNLOAD_REQUEST)
+                        .build();
         assertFalse(mONSStats.logEvent(info));
 
-        info = new ONSStatsInfo().setProvisioningResult(Result.ERR_SWITCHING_TO_DUAL_SIM_MODE);
+        info =
+                new ONSStatsInfo.Builder()
+                        .setProvisioningResult(mContext, Result.ERR_SWITCHING_TO_DUAL_SIM_MODE)
+                        .build();
         assertFalse(mONSStats.logEvent(info));
     }
 
@@ -231,9 +244,10 @@ public class ONSStatsTest {
     public void testRepeatedLogEvents() {
         ONSStatsInfo info;
         info =
-                new ONSStatsInfo()
+                new ONSStatsInfo.Builder()
                         .setDownloadResult(DownloadRetryResultCode.ERR_MEMORY_FULL)
-                        .setDetailedErrCode(10011);
+                        .setDetailedErrCode(10011)
+                        .build();
         assertTrue(mONSStats.logEvent(info));
 
         // same result should not log consecutively
@@ -244,7 +258,10 @@ public class ONSStatsTest {
     @Test
     public void testRepeatedAllowedLogEvents() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setProvisioningResult(Result.ERR_DOWNLOADED_ESIM_NOT_FOUND);
+        info =
+                new ONSStatsInfo.Builder()
+                        .setProvisioningResult(mContext, Result.ERR_DOWNLOADED_ESIM_NOT_FOUND)
+                        .build();
         assertTrue(mONSStats.logEvent(info));
 
         // ERR_DOWNLOADED_ESIM_NOT_FOUND is allowed to log consecutively
@@ -252,8 +269,9 @@ public class ONSStatsTest {
         assertTrue(mONSStats.logEvent(info));
 
         info =
-                new ONSStatsInfo()
-                        .setDownloadResult(DownloadRetryResultCode.ERR_INSTALL_ESIM_PROFILE_FAILED);
+                new ONSStatsInfo.Builder()
+                        .setDownloadResult(DownloadRetryResultCode.ERR_INSTALL_ESIM_PROFILE_FAILED)
+                        .build();
         assertTrue(mONSStats.logEvent(info));
 
         // ERR_INSTALL_ESIM_PROFILE_FAILED is allowed to log consecutively
@@ -264,13 +282,17 @@ public class ONSStatsTest {
     @Test
     public void testRepeatedSuccessLogEvents() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setProvisioningResult(Result.SUCCESS).setRetryCount(2);
+        info =
+                new ONSStatsInfo.Builder()
+                .setProvisioningResult(mContext, Result.SUCCESS)
+                .setRetryCount(2)
+                .build();
 
         // should log every time if eSIM is newly downloaded.
         assertTrue(mONSStats.logEvent(info));
         assertTrue(mONSStats.logEvent(info));
 
-        info = new ONSStatsInfo().setProvisioningResult(Result.SUCCESS);
+        info = new ONSStatsInfo.Builder().setProvisioningResult(mContext, Result.SUCCESS).build();
         // should log even if eSIM is already downloaded and event triggered just to group it.
         assertTrue(mONSStats.logEvent(info));
         assertTrue(mONSStats.logEvent(info));
@@ -279,13 +301,14 @@ public class ONSStatsTest {
     @Test
     public void testRepeatedErrorWithInfoChangeLogEvents() {
         ONSStatsInfo info =
-                new ONSStatsInfo()
+                new ONSStatsInfo.Builder()
                         .setPrimarySimSubId(1)
-                        .setProvisioningResult(Result.ERR_AUTO_PROVISIONING_DISABLED);
+                        .setProvisioningResult(mContext, Result.ERR_AUTO_PROVISIONING_DISABLED)
+                        .build();
         assertTrue(mONSStats.logEvent(info));
 
         // Same error should log if the info is changed.
-        info.setPrimarySimSubId(2);
+        info = new ONSStatsInfo.Builder(info).setPrimarySimSubId(2).build();
         assertTrue(mONSStats.logEvent(info));
 
         // no change in info
@@ -295,7 +318,9 @@ public class ONSStatsTest {
     @Test
     public void testDetailedErrorCodeLogEvents() {
         ONSStatsInfo info;
-        info = new ONSStatsInfo().setProvisioningResult(Result.ERR_WAITING_FOR_INTERNET_CONNECTION);
+        info = new ONSStatsInfo.Builder()
+                .setProvisioningResult(mContext, Result.ERR_WAITING_FOR_INTERNET_CONNECTION)
+                .build();
         assertTrue(mONSStats.logEvent(info));
 
         // For provisioning errors; Result enum ordinal is set as detailed error code.
@@ -303,15 +328,16 @@ public class ONSStatsTest {
                 Result.ERR_WAITING_FOR_INTERNET_CONNECTION.ordinal(),
                 mSharedPreferences.getInt(KEY_DETAILED_ERROR_CODE, -1));
         assertEquals(
-                Result.ERR_WAITING_FOR_INTERNET_CONNECTION.ordinal(), info.getDetailedErrCode());
+                Result.ERR_WAITING_FOR_INTERNET_CONNECTION.ordinal(), info.detailedErrCode());
 
         // For Download errors; detailed error code is updated from EuiccManager.
         info =
-                new ONSStatsInfo()
+                new ONSStatsInfo.Builder(info)
                         .setDownloadResult(DownloadRetryResultCode.ERR_MEMORY_FULL)
-                        .setDetailedErrCode(10223);
+                        .setDetailedErrCode(10223)
+                        .build();
         assertTrue(mONSStats.logEvent(info));
         assertEquals(10223, mSharedPreferences.getInt(KEY_DETAILED_ERROR_CODE, -1));
-        assertEquals(10223, info.getDetailedErrCode());
+        assertEquals(10223, info.detailedErrCode());
     }
 }
diff --git a/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java b/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
index fdab774..402c7c2 100644
--- a/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
+++ b/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
@@ -46,7 +46,6 @@ import androidx.test.runner.AndroidJUnit4;
 import com.android.internal.telephony.IOns;
 import com.android.internal.telephony.ISetOpportunisticDataCallback;
 import com.android.internal.telephony.IUpdateAvailableNetworksCallback;
-import com.android.internal.telephony.flags.Flags;
 
 import libcore.junit.util.compat.CoreCompatChangeRule.EnableCompatChanges;
 
@@ -62,6 +61,7 @@ import org.mockito.Mock;
 import java.lang.reflect.Field;
 import java.util.ArrayList;
 import java.util.HashMap;
+import java.util.List;
 
 @RunWith(AndroidJUnit4.class)
 public class OpportunisticNetworkServiceTest extends ONSBaseTest {
@@ -167,7 +167,7 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
         mccMncs.add("310210");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
                 new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos =
+        List<AvailableNetworkInfo> availableNetworkInfos =
                 new ArrayList<AvailableNetworkInfo>();
         availableNetworkInfos.add(availableNetworkInfo);
         IUpdateAvailableNetworksCallback mCallback = new IUpdateAvailableNetworksCallback.Stub() {
@@ -177,10 +177,9 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
                 Log.d(TAG, "result: " + result);
             }
         };
-        ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworkInfos, mCallback);
-        onsConfigInput.setPrimarySub(1);
-        onsConfigInput.setPreferredDataSub(availableNetworkInfos.get(0).getSubId());
-        ArrayList<SubscriptionInfo> subscriptionInfos = new ArrayList<SubscriptionInfo>();
+        ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworkInfos, mCallback,
+                availableNetworkInfos.get(0).getSubId(), 1);
+        List<SubscriptionInfo> subscriptionInfos = new ArrayList<SubscriptionInfo>();
 
         // Case 1: There is no Carrier app using ONS.
         doReturn(null).when(mockONSConfigInputHashMap).get(CARRIER_APP_CONFIG_NAME);
@@ -208,7 +207,7 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
         mccMncs.add("310210");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
             new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos =
+        List<AvailableNetworkInfo> availableNetworkInfos =
             new ArrayList<AvailableNetworkInfo>();
         availableNetworkInfos.add(availableNetworkInfo);
         IUpdateAvailableNetworksCallback mCallback = new IUpdateAvailableNetworksCallback.Stub() {
@@ -218,10 +217,9 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
                 Log.d(TAG, "result: " + result);
             }
         };
-        ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworkInfos, mCallback);
-        onsConfigInput.setPrimarySub(1);
-        onsConfigInput.setPreferredDataSub(availableNetworkInfos.get(0).getSubId());
-        ArrayList<SubscriptionInfo> subscriptionInfos = new ArrayList<SubscriptionInfo>();
+        ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworkInfos, mCallback,
+                availableNetworkInfos.get(0).getSubId(), 1);
+        List<SubscriptionInfo> subscriptionInfos = new ArrayList<SubscriptionInfo>();
 
         doReturn(subscriptionInfos).when(mSubscriptionManager).getActiveSubscriptionInfoList(false);
         doReturn(onsConfigInput).when(mockONSConfigInputHashMap).get(CARRIER_APP_CONFIG_NAME);
@@ -299,7 +297,7 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
         mccMncs.add("310210");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
                 new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<>();
+        List<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<>();
         availableNetworkInfos.add(availableNetworkInfo);
 
         try {
@@ -322,7 +320,7 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
                 mResult = result;
             }
         };
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<>();
+        List<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<>();
         try {
             iOpportunisticNetworkService.setEnable(false, pkgForDebug);
             iOpportunisticNetworkService.updateAvailableNetworks(availableNetworkInfos, mCallback,
@@ -339,7 +337,7 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
         mccMncs.add("310210");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
                 new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos =
+        List<AvailableNetworkInfo> availableNetworkInfos =
                 new ArrayList<AvailableNetworkInfo>();
         availableNetworkInfos.add(availableNetworkInfo);
         mResult = -1;
@@ -350,11 +348,10 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
                 Log.d(TAG, "result: " + result);
             }
         };
-        ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworkInfos, mCallback);
-        onsConfigInput.setPrimarySub(1);
-        onsConfigInput.setPreferredDataSub(availableNetworkInfos.get(0).getSubId());
+        ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworkInfos, mCallback,
+                availableNetworkInfos.get(0).getSubId(), 1);
         doReturn(onsConfigInput).when(mockONSConfigInputHashMap).get(CARRIER_APP_CONFIG_NAME);
-        doReturn(true).when(mockProfileSelector).hasOpprotunisticSub(any());
+        doReturn(true).when(mockProfileSelector).hasOpportunisticSub(any());
         doReturn(false).when(mockProfileSelector).containStandaloneOppSubs(any());
         mOpportunisticNetworkService.mIsEnabled = true;
         mOpportunisticNetworkService.mONSConfigInputHashMap = mockONSConfigInputHashMap;
@@ -443,13 +440,11 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
     @Test
     @EnableCompatChanges({TelephonyManager.ENABLE_FEATURE_MAPPING})
     public void testTelephonyFeatureAndCompatChanges() throws Exception {
-        mSetFlagsRule.enableFlags(Flags.FLAG_ENFORCE_TELEPHONY_FEATURE_MAPPING_FOR_PUBLIC_APIS);
-
         ArrayList<String> mccMncs = new ArrayList<>();
         mccMncs.add("310210");
         AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
                 new ArrayList<Integer>());
-        ArrayList<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<>();
+        List<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<>();
         availableNetworkInfos.add(availableNetworkInfo);
 
         // Enabled FeatureFlags and ENABLE_FEATURE_MAPPING, telephony features are defined
```

