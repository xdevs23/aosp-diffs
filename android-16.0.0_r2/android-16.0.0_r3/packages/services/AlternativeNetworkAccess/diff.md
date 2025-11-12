```diff
diff --git a/src/com/android/ons/ONSProfileActivator.java b/src/com/android/ons/ONSProfileActivator.java
index 6293ca3..d2b8962 100644
--- a/src/com/android/ons/ONSProfileActivator.java
+++ b/src/com/android/ons/ONSProfileActivator.java
@@ -52,7 +52,7 @@ import java.util.Random;
 public class ONSProfileActivator implements ONSProfileConfigurator.ONSProfConfigListener,
         ONSProfileDownloader.IONSProfileDownloaderListener {
 
-    private static final String TAG = ONSProfileActivator.class.getName();
+    private static final String TAG = ONSProfileActivator.class.getSimpleName();
     private final Context mContext;
     private final SubscriptionManager mSubManager;
     private final TelephonyManager mTelephonyManager;
diff --git a/src/com/android/ons/ONSProfileConfigurator.java b/src/com/android/ons/ONSProfileConfigurator.java
index 0925df0..07a898f 100644
--- a/src/com/android/ons/ONSProfileConfigurator.java
+++ b/src/com/android/ons/ONSProfileConfigurator.java
@@ -41,7 +41,7 @@ import java.util.List;
  */
 public class ONSProfileConfigurator {
 
-    private static final String TAG = ONSProfileConfigurator.class.getName();
+    private static final String TAG = ONSProfileConfigurator.class.getSimpleName();
     @VisibleForTesting protected static final String PARAM_SUB_ID = "SUB_ID";
     @VisibleForTesting protected static final String PARAM_REQUEST_TYPE = "REQUEST_TYPE";
     @VisibleForTesting protected static final int REQUEST_CODE_ACTIVATE_SUB = 1;
diff --git a/src/com/android/ons/ONSProfileDownloader.java b/src/com/android/ons/ONSProfileDownloader.java
index 9e1bc1c..9c98bd9 100644
--- a/src/com/android/ons/ONSProfileDownloader.java
+++ b/src/com/android/ons/ONSProfileDownloader.java
@@ -48,7 +48,7 @@ public class ONSProfileDownloader {
         void onDownloadError(int pSIMSubId, DownloadRetryResultCode resultCode, int detailErrCode);
     }
 
-    private static final String TAG = ONSProfileDownloader.class.getName();
+    private static final String TAG = ONSProfileDownloader.class.getSimpleName();
     public static final String ACTION_ONS_ESIM_DOWNLOAD = "com.android.ons.action.ESIM_DOWNLOAD";
 
     @VisibleForTesting protected static final String PARAM_PRIMARY_SUBID = "PrimarySubscriptionID";
diff --git a/src/com/android/ons/ONSProfileResultReceiver.java b/src/com/android/ons/ONSProfileResultReceiver.java
index 89d8239..9daf143 100644
--- a/src/com/android/ons/ONSProfileResultReceiver.java
+++ b/src/com/android/ons/ONSProfileResultReceiver.java
@@ -33,7 +33,7 @@ import android.util.Log;
  */
 public class ONSProfileResultReceiver extends BroadcastReceiver {
 
-    private static final String TAG = ONSProfileResultReceiver.class.getName();
+    private static final String TAG = ONSProfileResultReceiver.class.getSimpleName();
     public static final String EXTRA_RESULT_CODE = "ResultCode";
 
     @Override
diff --git a/src/com/android/ons/ONSProfileSelector.java b/src/com/android/ons/ONSProfileSelector.java
index b246e9d..1c0e0f8 100644
--- a/src/com/android/ons/ONSProfileSelector.java
+++ b/src/com/android/ons/ONSProfileSelector.java
@@ -20,6 +20,7 @@ import static android.telephony.AvailableNetworkInfo.PRIORITY_HIGH;
 import static android.telephony.AvailableNetworkInfo.PRIORITY_LOW;
 
 import android.annotation.NonNull;
+import android.annotation.Nullable;
 import android.app.PendingIntent;
 import android.compat.Compatibility;
 import android.content.Context;
@@ -315,11 +316,20 @@ public class ONSProfileSelector {
         return SubscriptionManager.INVALID_SUBSCRIPTION_ID;
     }
 
+    @Nullable private List<SubscriptionInfo> getStandaloneOppSubsInfos() {
+        return mStandaloneOppSubInfos;
+    }
+
+    @Nullable private List<SubscriptionInfo> getOppSubscriptionInfos() {
+        return mOppSubscriptionInfos;
+    }
+
     public SubscriptionInfo getOpportunisticSubInfo(int subId) {
-        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.isEmpty())) {
+        List<SubscriptionInfo> oppSubInfos = getOppSubscriptionInfos();
+        if ((oppSubInfos == null) || (oppSubInfos.isEmpty())) {
             return null;
         }
-        for (SubscriptionInfo subscriptionInfo : mOppSubscriptionInfos) {
+        for (SubscriptionInfo subscriptionInfo : oppSubInfos) {
             if (subscriptionInfo.getSubscriptionId() == subId) {
                 return subscriptionInfo;
             }
@@ -334,10 +344,11 @@ public class ONSProfileSelector {
      * @return true if the subscription is opportunistic
      */
     public boolean isOpportunisticSub(int subId) {
-        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.isEmpty())) {
+        List<SubscriptionInfo> oppSubInfos = getOppSubscriptionInfos();
+        if ((oppSubInfos == null) || (oppSubInfos.isEmpty())) {
             return false;
         }
-        for (SubscriptionInfo subscriptionInfo : mOppSubscriptionInfos) {
+        for (SubscriptionInfo subscriptionInfo : oppSubInfos) {
             if (subscriptionInfo.getSubscriptionId() == subId) {
                 return true;
             }
@@ -349,7 +360,8 @@ public class ONSProfileSelector {
         if ((availableNetworks == null) || (availableNetworks.isEmpty())) {
             return false;
         }
-        if ((mOppSubscriptionInfos == null) || (mOppSubscriptionInfos.isEmpty())) {
+        List<SubscriptionInfo> oppSubInfos = getOppSubscriptionInfos();
+        if ((oppSubInfos == null) || (oppSubInfos.isEmpty())) {
             return false;
         }
 
@@ -523,7 +535,8 @@ public class ONSProfileSelector {
                 (List<AvailableNetworkInfo>) objects[0];
         IUpdateAvailableNetworksCallback callbackStub =
                 (IUpdateAvailableNetworksCallback) objects[1];
-        if (mOppSubscriptionInfos == null) {
+        List<SubscriptionInfo> oppSubInfos = getOppSubscriptionInfos();
+        if (oppSubInfos == null) {
             logDebug("null subscription infos");
             if (Compatibility.isChangeEnabled(
                     OpportunisticNetworkService.CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
@@ -562,11 +575,11 @@ public class ONSProfileSelector {
         Collections.sort(mAvailableNetworkInfos, new SortAvailableNetworksInPriority());
         logDebug("availableNetworks: " + availableNetworks);
 
-        if (!mOppSubscriptionInfos.isEmpty()) {
-            logDebug("opportunistic subscriptions size " + mOppSubscriptionInfos.size());
+        if (!oppSubInfos.isEmpty()) {
+            logDebug("opportunistic subscriptions size " + oppSubInfos.size());
             List<AvailableNetworkInfo> filteredAvailableNetworks =
                     getFilteredAvailableNetworks(availableNetworks,
-                            mOppSubscriptionInfos);
+                            oppSubInfos);
             if ((filteredAvailableNetworks.size() == 1)
                     && ((filteredAvailableNetworks.getFirst().getMccMncs() == null)
                     || (filteredAvailableNetworks.getFirst().getMccMncs().isEmpty()))) {
@@ -727,14 +740,15 @@ public class ONSProfileSelector {
      * Return {@code true} if the provided {@code availableNetworks} contains standalone oppt subs.
      */
     public boolean containStandaloneOppSubs(List<AvailableNetworkInfo> availableNetworks) {
-        if (mStandaloneOppSubInfos == null || mStandaloneOppSubInfos.isEmpty()) {
+        List<SubscriptionInfo> standaloneOppSubInfos = getStandaloneOppSubsInfos();
+        if (standaloneOppSubInfos == null || standaloneOppSubInfos.isEmpty()) {
             logDebug("received null or empty subscription infos");
             return false;
         }
 
-        logDebug("Standalone opportunistic subInfos size " + mStandaloneOppSubInfos.size());
+        logDebug("Standalone opportunistic subInfos size " + standaloneOppSubInfos.size());
         List<AvailableNetworkInfo> filteredAvailableNetworks =
-                getFilteredAvailableNetworks(availableNetworks, mStandaloneOppSubInfos);
+                getFilteredAvailableNetworks(availableNetworks, standaloneOppSubInfos);
         return !filteredAvailableNetworks.isEmpty();
     }
 
@@ -845,11 +859,14 @@ public class ONSProfileSelector {
         // Do nothing in single SIM mode.
         if (phoneCount < 2) return;
 
+        List<SubscriptionInfo> oppSubInfos = getOppSubscriptionInfos();
         for (int i = 0; i < phoneCount; i++) {
             boolean hasActiveOpptProfile = false;
-            for (SubscriptionInfo info : mOppSubscriptionInfos) {
-                if (info.getSimSlotIndex() == i) {
-                    hasActiveOpptProfile = true;
+            if (oppSubInfos != null) {
+                for (SubscriptionInfo info : oppSubInfos) {
+                    if (info.getSimSlotIndex() == i) {
+                        hasActiveOpptProfile = true;
+                    }
                 }
             }
             // If the slot doesn't have active opportunistic profile anymore, it's back to
@@ -932,13 +949,15 @@ public class ONSProfileSelector {
         pw.println(TAG + ":");
         pw.println("  subId: " + mSubId);
         pw.println("  mCurrentDataSubId: " + mCurrentDataSubId);
+        List<SubscriptionInfo> oppSubInfos = getOppSubscriptionInfos();
         pw.println("  mOppSubscriptionInfos: " + (
-                mOppSubscriptionInfos == null || mOppSubscriptionInfos.isEmpty() ? "[]"
-                        : Arrays.toString(mOppSubscriptionInfos.stream().map(
+                oppSubInfos == null || oppSubInfos.isEmpty() ? "[]"
+                        : Arrays.toString(oppSubInfos.stream().map(
                                 SubscriptionInfo::getSubscriptionId).toArray())));
+        List<SubscriptionInfo> standaloneOppSubInfos = getStandaloneOppSubsInfos();
         pw.println("  mStandaloneOppSubInfos: " + (
-                mStandaloneOppSubInfos == null || mStandaloneOppSubInfos.isEmpty() ? "[]"
-                        : Arrays.toString(mStandaloneOppSubInfos.stream().map(
+                standaloneOppSubInfos == null || standaloneOppSubInfos.isEmpty() ? "[]"
+                        : Arrays.toString(standaloneOppSubInfos.stream().map(
                                 SubscriptionInfo::getSubscriptionId).toArray())));
         pw.println("  mAvailableNetworkInfos:");
         if (mAvailableNetworkInfos != null && !mAvailableNetworkInfos.isEmpty()) {
diff --git a/src/com/android/ons/OpportunisticNetworkService.java b/src/com/android/ons/OpportunisticNetworkService.java
index f399e88..9ff462c 100644
--- a/src/com/android/ons/OpportunisticNetworkService.java
+++ b/src/com/android/ons/OpportunisticNetworkService.java
@@ -50,7 +50,6 @@ import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyFrameworkInitializer;
 import android.telephony.TelephonyManager;
 import android.util.Log;
-
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.IOns;
 import com.android.internal.telephony.ISetOpportunisticDataCallback;
@@ -58,7 +57,6 @@ import com.android.internal.telephony.IUpdateAvailableNetworksCallback;
 import com.android.internal.telephony.TelephonyIntents;
 import com.android.internal.telephony.TelephonyPermissions;
 import com.android.internal.telephony.flags.Flags;
-
 import java.io.FileDescriptor;
 import java.io.PrintWriter;
 import java.util.HashMap;
@@ -177,7 +175,7 @@ public class OpportunisticNetworkService extends Service {
     protected void handleSimStateChange() {
         logDebug("SIM state changed");
 
-        ONSConfigInput carrierAppConfigInput = mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME);
+        ONSConfigInput carrierAppConfigInput = getCarrierAppConfig();
         if (carrierAppConfigInput == null) {
             return;
         }
@@ -195,15 +193,15 @@ public class OpportunisticNetworkService extends Service {
         }
 
         logDebug("Carrier subscription is not available, removing entry");
-        mONSConfigInputHashMap.put(CARRIER_APP_CONFIG_NAME, null);
-        if (!mIsEnabled) {
+        setCarrierAppConfig(null);
+        if (!getEnableState()) {
             return;
         }
-        if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null) {
+        ONSConfigInput systemConfig = getSystemAppConfig();
+        if (systemConfig != null) {
             mProfileSelector.startProfileSelection(
-                    mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME).availableNetworkInfos(),
-                    mONSConfigInputHashMap.get(
-                            SYSTEM_APP_CONFIG_NAME).availableNetworkCallback());
+                    systemConfig.availableNetworkInfos(),
+                    systemConfig.availableNetworkCallback());
         }
     }
 
@@ -271,7 +269,7 @@ public class OpportunisticNetworkService extends Service {
             enforceTelephonyFeatureWithException(callingPackage,
                     PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "isEnabled");
 
-            return mIsEnabled;
+            return getEnableState();
         }
 
         /**
@@ -302,7 +300,7 @@ public class OpportunisticNetworkService extends Service {
                             "setPreferredDataSubscriptionId");
                 }
             } else {
-                if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) != null) {
+                if (getCarrierAppConfig() != null) {
                     sendSetOpptCallbackHelper(callback,
                         TelephonyManager.SET_OPPORTUNISTIC_SUB_VALIDATION_FAILED);
                     return;
@@ -385,7 +383,12 @@ public class OpportunisticNetworkService extends Service {
                 enforceTelephonyFeatureWithException(callingPackage,
                         PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "updateAvailableNetworks");
 
-                handleSystemAppAvailableNetworks(availableNetworks, callback);
+                final long identity = Binder.clearCallingIdentity();
+                try {
+                    handleSystemAppAvailableNetworks(availableNetworks, callback);
+                } finally {
+                    Binder.restoreCallingIdentity(identity);
+                }
             } else {
                 // check if the app has primary carrier permission
                 TelephonyPermissions.enforceCallingOrSelfCarrierPrivilege(mContext,
@@ -394,11 +397,118 @@ public class OpportunisticNetworkService extends Service {
                 enforceTelephonyFeatureWithException(callingPackage,
                         PackageManager.FEATURE_TELEPHONY_RADIO_ACCESS, "updateAvailableNetworks");
 
-                handleCarrierAppAvailableNetworks(availableNetworks, callback,
-                        callingPackage);
+                if (Flags.onsThreadConsolidation() && availableNetworks != null
+                        && !availableNetworks.isEmpty()) {
+                    if (!enforceAvailableNetworksSize(availableNetworks, callback)) {
+                        return;
+                    }
+
+                    if (!enforceAvailableNetworksContainsOppSub(availableNetworks, callback)) {
+                        return;
+                    }
+
+                    if (!enforceCarrierPrivilegeOrCanManageSubPermission(
+                           availableNetworks, callback, callingPackage)) {
+                        return;
+                    }
+                }
+
+                if (!Flags.onsThreadConsolidation()) {
+                    handleCarrierAppAvailableNetworks(availableNetworks, callback,
+                            callingPackage);
+                } else {
+                    final long identity = Binder.clearCallingIdentity();
+                    try {
+                        handleCarrierAppAvailableNetworks(availableNetworks, callback,
+                                callingPackage);
+                    } finally {
+                        Binder.restoreCallingIdentity(identity);
+                    }
+                }
             }
         }
 
+        /**
+         * Returns true if all size conditions are met, otherwise
+         * returns false and invokes the appropriate callback if
+         * applicable.
+         */
+        private boolean enforceAvailableNetworksSize(
+                @NonNull List<AvailableNetworkInfo> availableNetworks,
+                IUpdateAvailableNetworksCallback callbackStub) {
+            /* carrier apps should report only subscription */
+            if (availableNetworks.size() != 1) {
+                log("Carrier app should not pass more than one subscription");
+                if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
+                    sendUpdateNetworksCallbackHelper(callbackStub,
+                            TelephonyManager
+                                    .UPDATE_AVAILABLE_NETWORKS_MULTIPLE_NETWORKS_NOT_SUPPORTED);
+                } else {
+                    sendUpdateNetworksCallbackHelper(callbackStub,
+                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
+                }
+                return false;
+            }
+            return true;
+        }
+
+        /**
+         * Returns true if availableNetworks contains an opportunistic
+         * subscription, otherwise returns false and invokes the
+         * appropriate callback if applicable.
+         */
+        private boolean enforceAvailableNetworksContainsOppSub(
+                @NonNull List<AvailableNetworkInfo> availableNetworks,
+                IUpdateAvailableNetworksCallback callbackStub) {
+            if (!mProfileSelector.hasOpportunisticSub(availableNetworks)) {
+                log("No opportunistic subscriptions received");
+                if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
+                    sendUpdateNetworksCallbackHelper(callbackStub,
+                            TelephonyManager
+                                    .UPDATE_AVAILABLE_NETWORKS_NO_OPPORTUNISTIC_SUB_AVAILABLE);
+                } else {
+                    sendUpdateNetworksCallbackHelper(callbackStub,
+                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
+                }
+                return false;
+            }
+            return true;
+        }
+
+        /**
+         * Returns true if all permissions requirements are met,
+         * otherwise returns false and invokes the appropriate
+         * callback if applicable.
+         */
+        private boolean enforceCarrierPrivilegeOrCanManageSubPermission(
+                @NonNull List<AvailableNetworkInfo> availableNetworks,
+                IUpdateAvailableNetworksCallback callbackStub, String callingPackage) {
+            for (AvailableNetworkInfo availableNetworkInfo : availableNetworks) {
+                final long identity = Binder.clearCallingIdentity();
+                boolean isActiveSubId = false;
+                try {
+                    isActiveSubId =
+                            mSubscriptionManager.isActiveSubId(availableNetworkInfo.getSubId());
+                } finally {
+                    Binder.restoreCallingIdentity(identity);
+                }
+                if (isActiveSubId) {
+                    TelephonyPermissions.enforceCallingOrSelfCarrierPrivilege(mContext,
+                        availableNetworkInfo.getSubId(), "updateAvailableNetworks");
+                } else {
+                    // check if the app has opportunistic carrier permission
+                    if (!hasOpportunisticSubPrivilege(callingPackage,
+                        availableNetworkInfo.getSubId())) {
+                        log("No carrier privilege for opportunistic subscription");
+                        sendUpdateNetworksCallbackHelper(callbackStub,
+                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_NO_CARRIER_PRIVILEGE);
+                        return false;
+                    }
+                }
+            }
+            return true;
+        }
+
         /**
          * Dump the state of {@link IOns}.
          */
@@ -571,54 +681,57 @@ public class OpportunisticNetworkService extends Service {
     private void handleCarrierAppAvailableNetworks(
             List<AvailableNetworkInfo> availableNetworks,
             IUpdateAvailableNetworksCallback callbackStub, String callingPackage) {
+        boolean isEnabled = getEnableState();
         if (availableNetworks != null && !availableNetworks.isEmpty()) {
-            /* carrier apps should report only subscription */
-            if (availableNetworks.size() > 1) {
-                log("Carrier app should not pass more than one subscription");
-                if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
-                    sendUpdateNetworksCallbackHelper(callbackStub,
-                            TelephonyManager
-                                    .UPDATE_AVAILABLE_NETWORKS_MULTIPLE_NETWORKS_NOT_SUPPORTED);
-                } else {
-                    sendUpdateNetworksCallbackHelper(callbackStub,
-                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
+            if (!Flags.onsThreadConsolidation()) {
+                /* carrier apps should report only subscription */
+                if (availableNetworks.size() > 1) {
+                    log("Carrier app should not pass more than one subscription");
+                    if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
+                        sendUpdateNetworksCallbackHelper(callbackStub,
+                                TelephonyManager
+                                        .UPDATE_AVAILABLE_NETWORKS_MULTIPLE_NETWORKS_NOT_SUPPORTED);
+                    } else {
+                        sendUpdateNetworksCallbackHelper(callbackStub,
+                                TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
+                    }
+                    return;
                 }
-                return;
-            }
 
-            if (!mProfileSelector.hasOpportunisticSub(availableNetworks)) {
-                log("No opportunistic subscriptions received");
-                if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
-                    sendUpdateNetworksCallbackHelper(callbackStub,
-                            TelephonyManager
-                                    .UPDATE_AVAILABLE_NETWORKS_NO_OPPORTUNISTIC_SUB_AVAILABLE);
-                } else {
-                    sendUpdateNetworksCallbackHelper(callbackStub,
-                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
+                if (!mProfileSelector.hasOpportunisticSub(availableNetworks)) {
+                    log("No opportunistic subscriptions received");
+                    if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
+                        sendUpdateNetworksCallbackHelper(callbackStub,
+                                TelephonyManager
+                                        .UPDATE_AVAILABLE_NETWORKS_NO_OPPORTUNISTIC_SUB_AVAILABLE);
+                    } else {
+                        sendUpdateNetworksCallbackHelper(callbackStub,
+                                TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
+                    }
+                    return;
                 }
-                return;
-            }
 
-            for (AvailableNetworkInfo availableNetworkInfo : availableNetworks) {
-                final long identity = Binder.clearCallingIdentity();
-                boolean isActiveSubId = false;
-                try {
-                    isActiveSubId =
-                            mSubscriptionManager.isActiveSubId(availableNetworkInfo.getSubId());
-                } finally {
-                    Binder.restoreCallingIdentity(identity);
-                }
-                if (isActiveSubId) {
-                    TelephonyPermissions.enforceCallingOrSelfCarrierPrivilege(mContext,
-                        availableNetworkInfo.getSubId(), "updateAvailableNetworks");
-                } else {
-                    // check if the app has opportunistic carrier permission
-                    if (!hasOpportunisticSubPrivilege(callingPackage,
-                        availableNetworkInfo.getSubId())) {
-                        log("No carrier privilege for opportunistic subscription");
-                        sendUpdateNetworksCallbackHelper(callbackStub,
-                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_NO_CARRIER_PRIVILEGE);
-                        return;
+                for (AvailableNetworkInfo availableNetworkInfo : availableNetworks) {
+                    final long identity = Binder.clearCallingIdentity();
+                    boolean isActiveSubId = false;
+                    try {
+                        isActiveSubId =
+                                mSubscriptionManager.isActiveSubId(availableNetworkInfo.getSubId());
+                    } finally {
+                        Binder.restoreCallingIdentity(identity);
+                    }
+                    if (isActiveSubId) {
+                        TelephonyPermissions.enforceCallingOrSelfCarrierPrivilege(mContext,
+                            availableNetworkInfo.getSubId(), "updateAvailableNetworks");
+                    } else {
+                        // check if the app has opportunistic carrier permission
+                        if (!hasOpportunisticSubPrivilege(callingPackage,
+                            availableNetworkInfo.getSubId())) {
+                            log("No carrier privilege for opportunistic subscription");
+                            sendUpdateNetworksCallbackHelper(callbackStub,
+                                TelephonyManager.UPDATE_AVAILABLE_NETWORKS_NO_CARRIER_PRIVILEGE);
+                            return;
+                        }
                     }
                 }
             }
@@ -630,18 +743,19 @@ public class OpportunisticNetworkService extends Service {
                     ONSConfigInput onsConfigInput = new ONSConfigInput(availableNetworks,
                             callbackStub, subscriptionInfo.getSubscriptionId(),
                             availableNetworks.getFirst().getSubId());
-                    mONSConfigInputHashMap.put(CARRIER_APP_CONFIG_NAME, onsConfigInput);
+                    setCarrierAppConfig(onsConfigInput);
                 }
                 // standalone opportunistic subscription should be handled in priority.
-                if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null) {
-                    if (mProfileSelector.containStandaloneOppSubs(mONSConfigInputHashMap.get(
-                            SYSTEM_APP_CONFIG_NAME).availableNetworkInfos())) {
+                ONSConfigInput systemConfig = getSystemAppConfig();
+                if (systemConfig != null) {
+                    if (mProfileSelector.containStandaloneOppSubs(
+                        systemConfig.availableNetworkInfos())) {
                         log("standalone opportunistic subscription is using.");
                         return;
                     }
                 }
 
-                if (mIsEnabled) {
+                if (isEnabled) {
                     //  if carrier is reporting availability, then it takes higher priority.
                     mProfileSelector.startProfileSelection(availableNetworks, callbackStub);
                 } else {
@@ -659,22 +773,21 @@ public class OpportunisticNetworkService extends Service {
         } else {
             final long identity = Binder.clearCallingIdentity();
             try {
-                mONSConfigInputHashMap.put(CARRIER_APP_CONFIG_NAME, null);
-                if (!mIsEnabled) {
+                setCarrierAppConfig(null);
+                if (!isEnabled) {
                     sendUpdateNetworksCallbackHelper(callbackStub,
                         TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
                     return;
                 }
                 // If carrier is reporting unavailability, then decide whether to start
                 // system app request or not.
-                if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null) {
+                ONSConfigInput systemConfig = getSystemAppConfig();
+                if (systemConfig != null) {
                     sendUpdateNetworksCallbackHelper(callbackStub,
                             TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
                     mProfileSelector.startProfileSelection(
-                            mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME)
-                                    .availableNetworkInfos(),
-                            mONSConfigInputHashMap.get(
-                                    SYSTEM_APP_CONFIG_NAME).availableNetworkCallback());
+                            systemConfig.availableNetworkInfos(),
+                            systemConfig.availableNetworkCallback());
                 } else {
                     mProfileSelector.stopProfileSelection(callbackStub);
                 }
@@ -709,73 +822,88 @@ public class OpportunisticNetworkService extends Service {
     private void handleSystemAppAvailableNetworks(
             List<AvailableNetworkInfo> availableNetworks,
             IUpdateAvailableNetworksCallback callbackStub) {
-        final long identity = Binder.clearCallingIdentity();
-        try {
-            if ((availableNetworks != null) && (!availableNetworks.isEmpty())) {
-                // all subscriptions should be opportunistic subscriptions
-                if (!mProfileSelector.hasOpportunisticSub(availableNetworks)) {
-                    log("No opportunistic subscriptions received");
-                    if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
-                        sendUpdateNetworksCallbackHelper(callbackStub,
-                                TelephonyManager
-                                        .UPDATE_AVAILABLE_NETWORKS_NO_OPPORTUNISTIC_SUB_AVAILABLE);
-                    } else {
-                        sendUpdateNetworksCallbackHelper(callbackStub,
-                                TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
-                    }
-                    return;
-                }
-                mONSConfigInputHashMap.put(SYSTEM_APP_CONFIG_NAME,
-                        new ONSConfigInput(availableNetworks, callbackStub));
-                // Reporting availability. proceed if carrier app has not requested any, but
-                // standalone opportunistic subscription should be handled in priority.
-                if (mIsEnabled) {
-                    if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) == null
-                            || mProfileSelector.containStandaloneOppSubs(availableNetworks)) {
-                        mProfileSelector.startProfileSelection(availableNetworks, callbackStub);
-                    }
+        boolean isEnabled = getEnableState();
+        if ((availableNetworks != null) && (!availableNetworks.isEmpty())) {
+            // all subscriptions should be opportunistic subscriptions
+            if (!mProfileSelector.hasOpportunisticSub(availableNetworks)) {
+                log("No opportunistic subscriptions received");
+                if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
+                    sendUpdateNetworksCallbackHelper(callbackStub,
+                            TelephonyManager
+                                    .UPDATE_AVAILABLE_NETWORKS_NO_OPPORTUNISTIC_SUB_AVAILABLE);
                 } else {
-                    if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
-                        sendUpdateNetworksCallbackHelper(callbackStub,
-                                TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SERVICE_IS_DISABLED);
-                    } else {
-                        sendUpdateNetworksCallbackHelper(callbackStub,
-                                TelephonyManager.UPDATE_AVAILABLE_NETWORKS_ABORTED);
-                    }
+                    sendUpdateNetworksCallbackHelper(callbackStub,
+                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_INVALID_ARGUMENTS);
+                }
+                return;
+            }
+            setSystemAppConfig(new ONSConfigInput(availableNetworks, callbackStub));
+            // Reporting availability. proceed if carrier app has not requested any, but
+            // standalone opportunistic subscription should be handled in priority.
+            ONSConfigInput carrierConfig = getCarrierAppConfig();
+            if (isEnabled) {
+                if (carrierConfig == null
+                        || mProfileSelector.containStandaloneOppSubs(availableNetworks)) {
+                    mProfileSelector.startProfileSelection(availableNetworks, callbackStub);
                 }
             } else {
-                if (!mIsEnabled) {
-                    mONSConfigInputHashMap.put(SYSTEM_APP_CONFIG_NAME, null);
+                if (Compatibility.isChangeEnabled(CALLBACK_ON_MORE_ERROR_CODE_CHANGE)) {
                     sendUpdateNetworksCallbackHelper(callbackStub,
-                        TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
-                    return;
-                }
-                // If system is reporting unavailability, then decide whether to start carrier
-                // app request or not.
-                mONSConfigInputHashMap.put(SYSTEM_APP_CONFIG_NAME, null);
-                if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) == null) {
-                    mProfileSelector.stopProfileSelection(callbackStub);
+                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SERVICE_IS_DISABLED);
                 } else {
                     sendUpdateNetworksCallbackHelper(callbackStub,
-                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
-                    log("Try to start carrier app request");
-                    mProfileSelector.startProfileSelection(
-                            mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME)
-                                    .availableNetworkInfos(),
-                            mONSConfigInputHashMap.get(
-                                    CARRIER_APP_CONFIG_NAME).availableNetworkCallback());
+                            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_ABORTED);
                 }
             }
-        } finally {
-            Binder.restoreCallingIdentity(identity);
+        } else {
+            if (!isEnabled) {
+                setSystemAppConfig(null);
+                sendUpdateNetworksCallbackHelper(callbackStub,
+                    TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
+                return;
+            }
+            // If system is reporting unavailability, then decide whether to start carrier
+            // app request or not.
+            setSystemAppConfig(null);
+            ONSConfigInput carrierConfig = getCarrierAppConfig();
+            if (carrierConfig == null) {
+                mProfileSelector.stopProfileSelection(callbackStub);
+            } else {
+                sendUpdateNetworksCallbackHelper(callbackStub,
+                        TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS);
+                log("Try to start carrier app request");
+                mProfileSelector.startProfileSelection(
+                        carrierConfig.availableNetworkInfos(),
+                        carrierConfig.availableNetworkCallback());
+            }
         }
     }
 
+    @Nullable private ONSConfigInput getCarrierAppConfig() {
+        return mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME);
+    }
+
+    @Nullable private ONSConfigInput getSystemAppConfig() {
+        return mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME);
+    }
+
+    private void setCarrierAppConfig(ONSConfigInput config) {
+        mONSConfigInputHashMap.put(CARRIER_APP_CONFIG_NAME, config);
+    }
+
+    private void setSystemAppConfig(ONSConfigInput config) {
+        mONSConfigInputHashMap.put(SYSTEM_APP_CONFIG_NAME, config);
+    }
+
     private void updateEnableState(boolean enable) {
         mIsEnabled = enable;
         mSharedPref.edit().putBoolean(PREF_ENABLED, mIsEnabled).apply();
     }
 
+    private boolean getEnableState() {
+        return mIsEnabled;
+    }
+
     /**
      * update the enable state
      * start profile selection if enabled.
@@ -783,33 +911,29 @@ public class OpportunisticNetworkService extends Service {
      */
     private void enableOpportunisticNetwork(boolean enable) {
         synchronized (mLock) {
-            if (mIsEnabled == enable) {
+            if (getEnableState() == enable) {
                 return;
             }
             updateEnableState(enable);
-            if (!mIsEnabled) {
+            if (!getEnableState()) {
                 mProfileSelector.stopProfileSelection(null);
             } else {
-                if (mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME) != null
-                        && mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME)
-                        .availableNetworkInfos() != null) {
+                ONSConfigInput carrierConfig = getCarrierAppConfig();
+                ONSConfigInput systemConfig = getSystemAppConfig();
+                if (carrierConfig != null
+                        && carrierConfig.availableNetworkInfos() != null) {
                     mProfileSelector.startProfileSelection(
-                            mONSConfigInputHashMap.get(CARRIER_APP_CONFIG_NAME)
-                                    .availableNetworkInfos(),
-                            mONSConfigInputHashMap.get(
-                                    CARRIER_APP_CONFIG_NAME).availableNetworkCallback());
-                } else if (mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME) != null
-                        && mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME)
-                        .availableNetworkInfos() != null) {
+                            carrierConfig.availableNetworkInfos(),
+                            carrierConfig.availableNetworkCallback());
+                } else if (systemConfig != null
+                        && systemConfig.availableNetworkInfos() != null) {
                     mProfileSelector.startProfileSelection(
-                            mONSConfigInputHashMap.get(SYSTEM_APP_CONFIG_NAME)
-                                    .availableNetworkInfos(),
-                            mONSConfigInputHashMap.get(
-                                    SYSTEM_APP_CONFIG_NAME).availableNetworkCallback());
+                            systemConfig.availableNetworkInfos(),
+                            systemConfig.availableNetworkCallback());
                 }
             }
         }
-        logDebug("service is enable state " + mIsEnabled);
+        logDebug("service is enable state " + getEnableState());
     }
 
     /**
@@ -839,7 +963,7 @@ public class OpportunisticNetworkService extends Service {
     }
 
     private boolean canManageSubscription(SubscriptionInfo subInfo, String packageName) {
-        if (Flags.hsumPackageManager() && UserManager.isHeadlessSystemUserMode()) {
+        if (UserManager.isHeadlessSystemUserMode()) {
             return mSubscriptionManager.canManageSubscriptionAsUser(subInfo, packageName,
                     UserHandle.of(ActivityManager.getCurrentUser()));
         } else {
@@ -870,7 +994,7 @@ public class OpportunisticNetworkService extends Service {
         final long token = Binder.clearCallingIdentity();
         try {
             pw.println(OpportunisticNetworkService.class.getSimpleName() + ":");
-            pw.println("  mIsEnabled = " + mIsEnabled);
+            pw.println("  mIsEnabled = " + getEnableState());
             mONSProfileActivator.dump(fd, pw, args);
             mProfileSelector.dump(fd, pw, args);
         } finally {
diff --git a/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java b/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
index 402c7c2..58c5dc6 100644
--- a/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
+++ b/tests/src/com/android/ons/OpportunisticNetworkServiceTest.java
@@ -51,6 +51,7 @@ import libcore.junit.util.compat.CoreCompatChangeRule.EnableCompatChanges;
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
@@ -78,6 +79,7 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
     private IOns iOpportunisticNetworkService;
     private Looper mLooper;
     private OpportunisticNetworkService mOpportunisticNetworkService;
+    private IUpdateAvailableNetworksCallback mCarrierCallback;
     private static final String CARRIER_APP_CONFIG_NAME = "carrierApp";
     private static final String SYSTEM_APP_CONFIG_NAME = "systemApp";
 
@@ -99,6 +101,11 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
     @Before
     public void setUp() throws Exception {
         super.setUp("ONSTest");
+        initONS();
+        initONSCallback();
+    }
+
+    private void initONS() {
         pkgForDebug = mContext != null ? mContext.getOpPackageName() : "<unknown>";
         pkgForFeature = mContext != null ? mContext.getAttributionTag() : null;
         Intent intent = new Intent(mContext, OpportunisticNetworkService.class);
@@ -138,6 +145,20 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
                 .thenReturn(true);
     }
 
+    private void initONSCallback() {
+        mResult = -1;
+        mReady = false;
+        mCarrierCallback =
+            new IUpdateAvailableNetworksCallback.Stub() {
+            @Override
+            public void onComplete(int result) {
+                Log.d(TAG, "mResult end:" + result);
+                mResult = result;
+                mReady = true;
+            }
+        };
+    }
+
     @After
     public void tearDown() throws Exception {
         super.tearDown();
@@ -491,6 +512,160 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
                         availableNetworkInfos, null, pkgForDebug));
     }
 
+    @Test
+    public void testUpdateAvailableNetworksForCarrierAppWithEmptyAvailableNetworksDisabled()
+        throws Exception {
+        doReturn(PackageManager.PERMISSION_DENIED).when(mMockContext)
+            .checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE);
+        mOpportunisticNetworkService.mContext = mMockContext;
+        List<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<>();
+
+        setAndAssertEnableState(false);
+        iOpportunisticNetworkService.updateAvailableNetworks(
+            availableNetworkInfos, mCarrierCallback, pkgForDebug);
+
+        waitUntilReady();
+        assertEquals(TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS, mResult);
+    }
+
+    // TODO(b/414649249): Enable test case when bug is fixed.
+    @Test
+    @Ignore
+    public void testUpdateAvailableNetworksForCarrierAppWithEmptyAvailableNetworksEnabled()
+        throws Exception {
+        doReturn(PackageManager.PERMISSION_DENIED).when(mMockContext)
+            .checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE);
+        mOpportunisticNetworkService.mContext = mMockContext;
+        List<AvailableNetworkInfo> availableNetworkInfos = new ArrayList<>();
+
+        setAndAssertEnableState(true);
+        iOpportunisticNetworkService.updateAvailableNetworks(
+            availableNetworkInfos, mCarrierCallback, pkgForDebug);
+
+        waitUntilReady();
+        // TODO(b/414649249): For reference until bug is fixed, this is the actual value returned.
+        // assertEquals(
+        //     TelephonyManager.UPDATE_AVAILABLE_NETWORKS_NO_OPPORTUNISTIC_SUB_AVAILABLE, mResult);
+        assertEquals(TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SUCCESS, mResult);
+    }
+
+    @Test
+    public void testUpdateAvailableNetworksForCarrierAppWithTooManyNetworks() throws Exception {
+        doReturn(PackageManager.PERMISSION_DENIED).when(mMockContext)
+            .checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE);
+        mOpportunisticNetworkService.mContext = mMockContext;
+        ArrayList<String> mccMncs = new ArrayList<>();
+        mccMncs.add("310210");
+        AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
+            new ArrayList<Integer>());
+        List<AvailableNetworkInfo> availableNetworkInfos =
+            new ArrayList<AvailableNetworkInfo>();
+        availableNetworkInfos.add(availableNetworkInfo);
+        availableNetworkInfos.add(availableNetworkInfo);
+
+        setAndAssertEnableState(false);
+        iOpportunisticNetworkService.updateAvailableNetworks(
+            availableNetworkInfos, mCarrierCallback, pkgForDebug);
+
+        waitUntilReady();
+        assertEquals(
+            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_MULTIPLE_NETWORKS_NOT_SUPPORTED, mResult);
+    }
+
+    @Test
+    public void testUpdateAvailableNetworksForCarrierAppWithoutOppSubs() throws Exception {
+        doReturn(PackageManager.PERMISSION_DENIED).when(mMockContext)
+            .checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE);
+        mOpportunisticNetworkService.mContext = mMockContext;
+        ArrayList<String> mccMncs = new ArrayList<>();
+        mccMncs.add("310210");
+        AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
+            new ArrayList<Integer>());
+        List<AvailableNetworkInfo> availableNetworkInfos =
+            new ArrayList<AvailableNetworkInfo>();
+        availableNetworkInfos.add(availableNetworkInfo);
+
+        setAndAssertEnableState(false);
+        iOpportunisticNetworkService.updateAvailableNetworks(
+            availableNetworkInfos, mCarrierCallback, pkgForDebug);
+
+        waitUntilReady();
+        assertEquals(
+            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_NO_OPPORTUNISTIC_SUB_AVAILABLE, mResult);
+    }
+
+    @Test
+    public void testUpdateAvailableNetworksForCarrierAppWithOppSubsNoActiveSubs() throws Exception {
+        doReturn(PackageManager.PERMISSION_DENIED).when(mMockContext)
+            .checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE);
+        doReturn(true).when(mockProfileSelector).hasOpportunisticSub(any());
+        mOpportunisticNetworkService.mProfileSelector = mockProfileSelector;
+        mOpportunisticNetworkService.mContext = mMockContext;
+        ArrayList<String> mccMncs = new ArrayList<>();
+        mccMncs.add("310210");
+        AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
+            new ArrayList<Integer>());
+        List<AvailableNetworkInfo> availableNetworkInfos =
+            new ArrayList<AvailableNetworkInfo>();
+        availableNetworkInfos.add(availableNetworkInfo);
+
+        setAndAssertEnableState(false);
+        iOpportunisticNetworkService.updateAvailableNetworks(
+            availableNetworkInfos, mCarrierCallback, pkgForDebug);
+
+        waitUntilReady();
+        assertEquals(
+            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_NO_CARRIER_PRIVILEGE, mResult);
+    }
+
+    @Test
+    public void testUpdateAvailableNetworksForCarrierAppWithOppSubsONSDisabled() throws Exception {
+        doReturn(PackageManager.PERMISSION_DENIED).when(mMockContext)
+            .checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE);
+        doReturn(true).when(mockProfileSelector).hasOpportunisticSub(any());
+        doReturn(true).when(mSubscriptionManager).isActiveSubId(1);
+        mOpportunisticNetworkService.mProfileSelector = mockProfileSelector;
+        mOpportunisticNetworkService.mContext = mMockContext;
+        ArrayList<String> mccMncs = new ArrayList<>();
+        mccMncs.add("310210");
+        AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
+            new ArrayList<Integer>());
+        List<AvailableNetworkInfo> availableNetworkInfos =
+            new ArrayList<AvailableNetworkInfo>();
+        availableNetworkInfos.add(availableNetworkInfo);
+
+        setAndAssertEnableState(false);
+        iOpportunisticNetworkService.updateAvailableNetworks(
+            availableNetworkInfos, mCarrierCallback, pkgForDebug);
+
+        waitUntilReady();
+        assertEquals(
+            TelephonyManager.UPDATE_AVAILABLE_NETWORKS_SERVICE_IS_DISABLED, mResult);
+    }
+
+    @Test
+    public void testUpdateAvailableNetworksForCarrierAppWithOppSubsONSEnabled() throws Exception {
+        doReturn(PackageManager.PERMISSION_DENIED).when(mMockContext)
+            .checkCallingOrSelfPermission(android.Manifest.permission.MODIFY_PHONE_STATE);
+        doReturn(true).when(mockProfileSelector).hasOpportunisticSub(any());
+        doReturn(true).when(mSubscriptionManager).isActiveSubId(1);
+        mOpportunisticNetworkService.mProfileSelector = mockProfileSelector;
+        mOpportunisticNetworkService.mContext = mMockContext;
+        ArrayList<String> mccMncs = new ArrayList<>();
+        mccMncs.add("310210");
+        AvailableNetworkInfo availableNetworkInfo = new AvailableNetworkInfo(1, 1, mccMncs,
+            new ArrayList<Integer>());
+        List<AvailableNetworkInfo> availableNetworkInfos =
+            new ArrayList<AvailableNetworkInfo>();
+        availableNetworkInfos.add(availableNetworkInfo);
+
+        setAndAssertEnableState(true);
+        iOpportunisticNetworkService.updateAvailableNetworks(
+            availableNetworkInfos, mCarrierCallback, pkgForDebug);
+
+        verify(mockProfileSelector).startProfileSelection(availableNetworkInfos, mCarrierCallback);
+    }
+
     private void replaceInstance(final Class c, final String instanceName, final Object obj,
             final Object newValue) throws Exception {
         Field field = c.getDeclaredField(instanceName);
@@ -498,14 +673,6 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
         field.set(obj, newValue);
     }
 
-    private IOns getIOns() {
-        return IOns.Stub.asInterface(
-                TelephonyFrameworkInitializer
-                        .getTelephonyServiceManager()
-                        .getOpportunisticNetworkServiceRegisterer()
-                        .get());
-    }
-
     public static void waitForMs(long ms) {
         try {
             Thread.sleep(ms);
@@ -513,4 +680,9 @@ public class OpportunisticNetworkServiceTest extends ONSBaseTest {
             Log.d(TAG, "InterruptedException while waiting: " + e);
         }
     }
+
+    private void setAndAssertEnableState(boolean enable) throws Exception {
+        iOpportunisticNetworkService.setEnable(enable, pkgForDebug);
+        assertEquals(enable, iOpportunisticNetworkService.isEnabled(pkgForDebug));
+    }
 }
```

