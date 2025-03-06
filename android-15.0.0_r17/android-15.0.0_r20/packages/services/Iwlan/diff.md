```diff
diff --git a/src/com/google/android/iwlan/ErrorPolicyManager.java b/src/com/google/android/iwlan/ErrorPolicyManager.java
index e3eeb8f..7134b3c 100644
--- a/src/com/google/android/iwlan/ErrorPolicyManager.java
+++ b/src/com/google/android/iwlan/ErrorPolicyManager.java
@@ -27,6 +27,7 @@ import android.support.annotation.NonNull;
 import android.support.annotation.Nullable;
 import android.telephony.DataFailCause;
 import android.telephony.TelephonyManager;
+import android.telephony.data.DataCallResponse;
 import android.telephony.data.DataService;
 import android.text.TextUtils;
 import android.util.Log;
@@ -40,6 +41,7 @@ import org.json.JSONException;
 import org.json.JSONObject;
 
 import java.io.PrintWriter;
+import java.time.Duration;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Calendar;
@@ -121,11 +123,16 @@ public class ErrorPolicyManager {
     private static final int IKE_PROTOCOL_ERROR_PLMN_NOT_ALLOWED = 11011;
     private static final int IKE_PROTOCOL_ERROR_UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED = 11055;
 
+    /**
+     * Represents the retry backoff duration is unspecified, see {@link
+     * android.telephony.data.DataCallResponse#RETRY_DURATION_UNDEFINED}
+     */
+    public static final Duration UNSPECIFIED_RETRY_DURATION =
+            Duration.ofMillis(DataCallResponse.RETRY_DURATION_UNDEFINED);
+
     /** Private IKEv2 notify message types, as defined in TS 124 502 (section 9.2.4.1) */
     private static final int IKE_PROTOCOL_ERROR_CONGESTION = 15500;
 
-    private static final int IWLAN_NO_ERROR_RETRY_TIME = -1;
-
     private static final ErrorPolicy FALLBACK_ERROR_POLICY =
             builder()
                     .setErrorType(FALLBACK_ERROR_TYPE)
@@ -206,7 +213,7 @@ public class ErrorPolicyManager {
         if (iwlanError.getErrorType() == IwlanError.NO_ERROR) {
             Log.d(LOG_TAG, "reportIwlanError: NO_ERROR");
             mRetryActionStoreByApn.remove(apn);
-            return IWLAN_NO_ERROR_RETRY_TIME;
+            return DataCallResponse.RETRY_DURATION_UNDEFINED;
         }
         mErrorStats.update(apn, iwlanError);
 
@@ -220,8 +227,8 @@ public class ErrorPolicyManager {
                 "Current RetryAction index: "
                         + newRetryAction.currentRetryIndex()
                         + " and time: "
-                        + newRetryAction.totalRetryTimeMs());
-        return newRetryAction.totalRetryTimeMs() / 1000;
+                        + newRetryAction.totalBackoffDuration());
+        return newRetryAction.totalBackoffDuration().toSeconds();
     }
 
     /**
@@ -237,17 +244,17 @@ public class ErrorPolicyManager {
         if (iwlanError.getErrorType() == IwlanError.NO_ERROR) {
             Log.d(LOG_TAG, "reportIwlanError: NO_ERROR");
             mRetryActionStoreByApn.remove(apn);
-            return IWLAN_NO_ERROR_RETRY_TIME;
+            return DataCallResponse.RETRY_DURATION_UNDEFINED;
         }
         mErrorStats.update(apn, iwlanError);
 
         IkeBackoffNotifyRetryAction newRetryAction =
                 mRetryActionStoreByApn
                         .computeIfAbsent(apn, ApnRetryActionStore::new)
-                        .generateRetryAction(iwlanError, backoffTime);
-        Log.d(LOG_TAG, "Current configured backoff time: " + newRetryAction.backoffTime());
+                        .generateRetryAction(iwlanError, Duration.ofSeconds(backoffTime));
+        Log.d(LOG_TAG, "Current configured backoff time: " + newRetryAction.totalBackoffDuration);
 
-        return newRetryAction.backoffTime();
+        return newRetryAction.totalBackoffDuration.toSeconds();
     }
 
     /**
@@ -259,7 +266,9 @@ public class ErrorPolicyManager {
     public synchronized boolean canBringUpTunnel(String apn) {
         RetryAction lastRetryAction = getLastRetryAction(apn);
         boolean canBringUp =
-                lastRetryAction == null || getRemainingRetryTimeMs(lastRetryAction) <= 0;
+                lastRetryAction == null
+                        || getRemainingBackoffDuration(lastRetryAction).isNegative()
+                        || getRemainingBackoffDuration(lastRetryAction).isZero();
         Log.d(LOG_TAG, "canBringUpTunnel: " + canBringUp);
         return canBringUp;
     }
@@ -357,25 +366,30 @@ public class ErrorPolicyManager {
     }
 
     /**
-     * Returns the current retryTime based on the lastErrorForApn
+     * Returns the current remaining backoff duration of the APN
      *
-     * @param apn apn name for which curren retry time is needed
+     * @param apn APN name for which current backoff duration is needed
      * @return long current retry time in milliseconds
      */
-    public synchronized long getRemainingRetryTimeMs(String apn) {
+    public synchronized Duration getRemainingBackoffDuration(String apn) {
         RetryAction lastRetryAction = getLastRetryAction(apn);
-        return lastRetryAction == null ? -1 : getRemainingRetryTimeMs(lastRetryAction);
+        return lastRetryAction == null
+                ? UNSPECIFIED_RETRY_DURATION
+                : getRemainingBackoffDuration(lastRetryAction);
     }
 
     /**
-     * Get the remaining time in millis should be waited before retry, based on the current time and
-     * the RetryAction.
+     * Returns the current remaining backoff duration based on the last retryAction time
+     *
+     * @param retryAction the last error
      */
-    private static long getRemainingRetryTimeMs(RetryAction retryAction) {
-        long totalRetryTimeMs = retryAction.totalRetryTimeMs();
+    private static Duration getRemainingBackoffDuration(RetryAction retryAction) {
+        Duration totalBackoffDuration = retryAction.totalBackoffDuration();
         long errorTime = retryAction.lastErrorTime();
         long currentTime = IwlanHelper.elapsedRealtime();
-        return Math.max(0, totalRetryTimeMs - (currentTime - errorTime));
+        Duration sinceLastErrorDuration = Duration.ofMillis(currentTime - errorTime);
+        Duration remainingBackupDuration = totalBackoffDuration.minus(sinceLastErrorDuration);
+        return remainingBackupDuration.isNegative() ? Duration.ZERO : remainingBackupDuration;
     }
 
     /**
@@ -832,7 +846,7 @@ public class ErrorPolicyManager {
 
         abstract List<Integer> retryArray();
 
-        abstract Boolean infiniteRetriesWithLastRetryTime();
+        abstract boolean infiniteRetriesWithLastRetryTime();
 
         abstract List<Integer> unthrottlingEvents();
 
@@ -996,7 +1010,7 @@ public class ErrorPolicyManager {
         long lastErrorTime();
 
         /** The total time should be waited between lastErrorTime and next retry. */
-        long totalRetryTimeMs();
+        Duration totalBackoffDuration();
 
         /** The number of same cause error observed since last success / unthrottle event. */
         int errorCountOfSameCause();
@@ -1015,8 +1029,8 @@ public class ErrorPolicyManager {
             int currentRetryIndex)
             implements RetryAction {
         @Override
-        public long totalRetryTimeMs() {
-            return TimeUnit.SECONDS.toMillis(errorPolicy().getRetryTime(currentRetryIndex()));
+        public Duration totalBackoffDuration() {
+            return Duration.ofSeconds(errorPolicy().getRetryTime(currentRetryIndex()));
         }
 
         @Override
@@ -1043,12 +1057,8 @@ public class ErrorPolicyManager {
             @Override ErrorPolicy errorPolicy,
             @Override long lastErrorTime,
             @Override int errorCountOfSameCause,
-            long backoffTime)
+            @Override Duration totalBackoffDuration)
             implements RetryAction {
-        @Override
-        public long totalRetryTimeMs() {
-            return TimeUnit.SECONDS.toMillis(backoffTime());
-        }
 
         @Override
         public int getCurrentFqdnIndex(int numFqdns) {
@@ -1174,7 +1184,7 @@ public class ErrorPolicyManager {
         }
 
         private IkeBackoffNotifyRetryAction generateRetryAction(
-                IwlanError iwlanError, long backoffTime) {
+                IwlanError iwlanError, Duration backoffDuration) {
             ErrorCause errorCause = ErrorCause.fromIwlanError(iwlanError);
             @Nullable RetryAction prevRetryAction = mLastRetryActionByCause.get(errorCause);
             int newErrorCount =
@@ -1188,7 +1198,7 @@ public class ErrorPolicyManager {
                             policy,
                             IwlanHelper.elapsedRealtime(),
                             newErrorCount,
-                            backoffTime);
+                            backoffDuration);
             mLastRetryActionByCause.put(errorCause, newRetryAction);
             mLastRetryAction = newRetryAction;
 
diff --git a/src/com/google/android/iwlan/IwlanDataService.java b/src/com/google/android/iwlan/IwlanDataService.java
index 80029fa..9a70a39 100644
--- a/src/com/google/android/iwlan/IwlanDataService.java
+++ b/src/com/google/android/iwlan/IwlanDataService.java
@@ -37,6 +37,7 @@ import android.net.NetworkSpecifier;
 import android.net.TelephonyNetworkSpecifier;
 import android.net.TransportInfo;
 import android.net.vcn.VcnTransportInfo;
+import android.net.vcn.VcnUtils;
 import android.net.wifi.WifiInfo;
 import android.net.wifi.WifiManager;
 import android.os.Handler;
@@ -211,7 +212,10 @@ public class IwlanDataService extends DataService {
             if (networkCapabilities != null) {
                 if (networkCapabilities.hasTransport(TRANSPORT_CELLULAR)) {
                     Log.d(TAG, "Network " + network + " connected using transport MOBILE");
-                    IwlanDataService.setConnectedDataSub(getConnectedDataSub(networkCapabilities));
+                    IwlanDataService.setConnectedDataSub(
+                            getConnectedDataSub(
+                                    mContext.getSystemService(ConnectivityManager.class),
+                                    networkCapabilities));
                     IwlanDataService.setNetworkConnected(true, network, Transport.MOBILE);
                 } else if (networkCapabilities.hasTransport(TRANSPORT_WIFI)) {
                     Log.d(TAG, "Network " + network + " connected using transport WIFI");
@@ -1214,7 +1218,7 @@ public class IwlanDataService extends DataService {
                 pw.println(entry.getValue());
             }
             pw.println(mTunnelStats);
-            EpdgTunnelManager.getInstance(mContext, getSlotIndex()).dump(pw);
+            mEpdgTunnelManager.dump(pw);
             ErrorPolicyManager.getInstance(mContext, getSlotIndex()).dump(pw);
             pw.println("-------------------------------------");
         }
@@ -1377,9 +1381,10 @@ public class IwlanDataService extends DataService {
                     break;
 
                 case IwlanEventListener.SCREEN_ON_EVENT:
-                    EpdgTunnelManager.getInstance(mContext, msg.arg1)
-                            .validateUnderlyingNetwork(
-                                    IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
+                    iwlanDataServiceProvider =
+                            (IwlanDataServiceProvider) getDataServiceProvider(msg.arg1);
+                    iwlanDataServiceProvider.mEpdgTunnelManager.validateUnderlyingNetwork(
+                            IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_SCREEN_ON);
                     break;
 
                 case IwlanEventListener.CALL_STATE_CHANGED_EVENT:
@@ -1393,10 +1398,8 @@ public class IwlanDataService extends DataService {
                                     && currentCallState == TelephonyManager.CALL_STATE_OFFHOOK;
 
                     if (isCallInitiating) {
-                        int slotIndex = msg.arg1;
-                        EpdgTunnelManager.getInstance(mContext, slotIndex)
-                                .validateUnderlyingNetwork(
-                                        IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
+                        iwlanDataServiceProvider.mEpdgTunnelManager.validateUnderlyingNetwork(
+                                IwlanCarrierConfig.NETWORK_VALIDATION_EVENT_MAKING_CALL);
                     }
 
                     if (!IwlanCarrierConfig.getConfigBoolean(
@@ -1549,7 +1552,8 @@ public class IwlanDataService extends DataService {
         }
     }
 
-    static int getConnectedDataSub(NetworkCapabilities networkCapabilities) {
+    static int getConnectedDataSub(
+            ConnectivityManager connectivityManager, NetworkCapabilities networkCapabilities) {
         int connectedDataSub = INVALID_SUB_ID;
         NetworkSpecifier specifier = networkCapabilities.getNetworkSpecifier();
         TransportInfo transportInfo = networkCapabilities.getTransportInfo();
@@ -1557,7 +1561,8 @@ public class IwlanDataService extends DataService {
         if (specifier instanceof TelephonyNetworkSpecifier) {
             connectedDataSub = ((TelephonyNetworkSpecifier) specifier).getSubscriptionId();
         } else if (transportInfo instanceof VcnTransportInfo) {
-            connectedDataSub = ((VcnTransportInfo) transportInfo).getSubId();
+            connectedDataSub =
+                    VcnUtils.getSubIdFromVcnCaps(connectivityManager, networkCapabilities);
         }
         return connectedDataSub;
     }
@@ -1956,7 +1961,8 @@ public class IwlanDataService extends DataService {
                         (int)
                                 ErrorPolicyManager.getInstance(
                                                 mContext, iwlanDataServiceProvider.getSlotIndex())
-                                        .getRemainingRetryTimeMs(apnName);
+                                        .getRemainingBackoffDuration(apnName)
+                                        .toMillis();
                 // TODO(b/343962773): Need to refactor into ErrorPolicyManager
                 if (!tunnelState.getIsHandover()
                         && tunnelState.hasApnType(ApnSetting.TYPE_EMERGENCY)) {
@@ -2301,25 +2307,33 @@ public class IwlanDataService extends DataService {
         int cid = networkValidationInfo.mCid;
         Executor executor = networkValidationInfo.mExecutor;
         Consumer<Integer> resultCodeCallback = networkValidationInfo.mResultCodeCallback;
-        IwlanDataServiceProvider.TunnelState tunnelState;
 
         String apnName = findMatchingApn(iwlanDataServiceProvider, cid);
-        int resultCode;
         if (apnName == null) {
-            Log.w(TAG, "no matching APN name found for network validation.");
-            resultCode = DataServiceCallback.RESULT_ERROR_UNSUPPORTED;
-        } else {
-            iwlanDataServiceProvider.mEpdgTunnelManager.requestNetworkValidationForApn(apnName);
-            resultCode = DataServiceCallback.RESULT_SUCCESS;
-            tunnelState = iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
-            if (tunnelState == null) {
-                Log.w(TAG, "EVENT_REQUEST_NETWORK_VALIDATION: tunnel state is null.");
-            } else {
-                tunnelState.setNetworkValidationStatus(
-                        PreciseDataConnectionState.NETWORK_VALIDATION_IN_PROGRESS);
-            }
+            Log.w(TAG, "handleNetworkValidationRequest: No APN for CID: " + cid);
+            executor.execute(
+                    () ->
+                            resultCodeCallback.accept(
+                                    DataServiceCallback.RESULT_ERROR_ILLEGAL_STATE));
+            return;
         }
-        executor.execute(() -> resultCodeCallback.accept(resultCode));
+
+        IwlanDataServiceProvider.TunnelState tunnelState =
+                iwlanDataServiceProvider.mTunnelStateForApn.get(apnName);
+        if (tunnelState == null) {
+            Log.e(TAG, "handleNetworkValidationRequest: No tunnel state for APN: " + apnName);
+            executor.execute(
+                    () ->
+                            resultCodeCallback.accept(
+                                    DataServiceCallback.RESULT_ERROR_ILLEGAL_STATE));
+            return;
+        }
+
+        Log.d(TAG, "handleNetworkValidationRequest: Validating network for APN: " + apnName);
+        executor.execute(() -> resultCodeCallback.accept(DataServiceCallback.RESULT_SUCCESS));
+        iwlanDataServiceProvider.mEpdgTunnelManager.requestNetworkValidationForApn(apnName);
+        tunnelState.setNetworkValidationStatus(
+                PreciseDataConnectionState.NETWORK_VALIDATION_IN_PROGRESS);
     }
 
     private static void handleLivenessStatusChange(
diff --git a/src/com/google/android/iwlan/IwlanNetworkService.java b/src/com/google/android/iwlan/IwlanNetworkService.java
index ad7bd59..ce7b1f7 100644
--- a/src/com/google/android/iwlan/IwlanNetworkService.java
+++ b/src/com/google/android/iwlan/IwlanNetworkService.java
@@ -29,6 +29,7 @@ import android.net.NetworkSpecifier;
 import android.net.TelephonyNetworkSpecifier;
 import android.net.TransportInfo;
 import android.net.vcn.VcnTransportInfo;
+import android.net.vcn.VcnUtils;
 import android.os.Handler;
 import android.os.HandlerExecutor;
 import android.os.HandlerThread;
@@ -136,7 +137,9 @@ public class IwlanNetworkService extends NetworkService {
             if (networkCapabilities != null) {
                 if (networkCapabilities.hasTransport(TRANSPORT_CELLULAR)) {
                     IwlanNetworkService.setConnectedDataSub(
-                            getConnectedDataSub(networkCapabilities));
+                            getConnectedDataSub(
+                                    mContext.getSystemService(ConnectivityManager.class),
+                                    networkCapabilities));
                     IwlanNetworkService.setNetworkConnected(
                             true, IwlanNetworkService.Transport.MOBILE);
                 } else if (networkCapabilities.hasTransport(TRANSPORT_WIFI)) {
@@ -371,7 +374,8 @@ public class IwlanNetworkService extends NetworkService {
         mConnectedDataSub = subId;
     }
 
-    static int getConnectedDataSub(NetworkCapabilities networkCapabilities) {
+    static int getConnectedDataSub(
+            ConnectivityManager connectivityManager, NetworkCapabilities networkCapabilities) {
         int connectedDataSub = INVALID_SUB_ID;
         NetworkSpecifier specifier = networkCapabilities.getNetworkSpecifier();
         TransportInfo transportInfo = networkCapabilities.getTransportInfo();
@@ -379,7 +383,8 @@ public class IwlanNetworkService extends NetworkService {
         if (specifier instanceof TelephonyNetworkSpecifier telephonyNetworkSpecifier) {
             connectedDataSub = telephonyNetworkSpecifier.getSubscriptionId();
         } else if (transportInfo instanceof VcnTransportInfo vcnTransportInfo) {
-            connectedDataSub = vcnTransportInfo.getSubId();
+            connectedDataSub =
+                    VcnUtils.getSubIdFromVcnCaps(connectivityManager, networkCapabilities);
         }
         return connectedDataSub;
     }
diff --git a/src/com/google/android/iwlan/epdg/EpdgSelector.java b/src/com/google/android/iwlan/epdg/EpdgSelector.java
index a3e2aa0..2320e40 100644
--- a/src/com/google/android/iwlan/epdg/EpdgSelector.java
+++ b/src/com/google/android/iwlan/epdg/EpdgSelector.java
@@ -57,7 +57,6 @@ import com.google.android.iwlan.IwlanError;
 import com.google.android.iwlan.IwlanHelper;
 import com.google.android.iwlan.epdg.NaptrDnsResolver.NaptrTarget;
 import com.google.android.iwlan.flags.FeatureFlags;
-import com.google.android.iwlan.flags.FeatureFlagsImpl;
 
 import java.net.Inet4Address;
 import java.net.Inet6Address;
@@ -76,7 +75,6 @@ import java.util.Set;
 import java.util.concurrent.ArrayBlockingQueue;
 import java.util.concurrent.BlockingQueue;
 import java.util.concurrent.CompletableFuture;
-import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.Executor;
 import java.util.concurrent.ExecutorService;
@@ -93,8 +91,6 @@ public class EpdgSelector {
     private static final String TAG = "EpdgSelector";
     private final Context mContext;
     private final int mSlotId;
-    private static final ConcurrentHashMap<Integer, EpdgSelector> mSelectorInstances =
-            new ConcurrentHashMap<>();
 
     private final ConnectivityManager mConnectivityManager;
 
@@ -166,7 +162,6 @@ public class EpdgSelector {
         void onError(int transactionId, IwlanError error);
     }
 
-    @VisibleForTesting
     EpdgSelector(Context context, int slotId, FeatureFlags featureFlags) {
         mContext = context;
         mSlotId = slotId;
@@ -228,12 +223,6 @@ public class EpdgSelector {
                         new SynchronousQueue<>());
     }
 
-    public static EpdgSelector getSelectorInstance(Context context, int slotId) {
-        mSelectorInstances.computeIfAbsent(
-                slotId, k -> new EpdgSelector(context, slotId, new FeatureFlagsImpl()));
-        return mSelectorInstances.get(slotId);
-    }
-
     private void clearPcoData() {
         Log.d(TAG, "Clear PCO data");
         mV4PcoId = -1;
@@ -1374,12 +1363,7 @@ public class EpdgSelector {
         return new IwlanError(IwlanError.NO_ERROR);
     }
 
-    /**
-     * Validates a PLMN (Public Land Mobile Network) identifier string.
-     *
-     * @param plmn The PLMN identifier string to validate.
-     * @return True if the PLMN identifier is valid, false otherwise.
-     */
+    /* Validates a PLMN (Public Land Mobile Network) identifier string. */
     private static boolean isValidPlmn(String plmn) {
         return plmn != null && PLMN_PATTERN.matcher(plmn).matches();
     }
diff --git a/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java b/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
index ab30c33..18526d5 100644
--- a/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
+++ b/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
@@ -697,16 +697,30 @@ public class EpdgTunnelManager {
         }
     }
 
-    @VisibleForTesting
-    EpdgTunnelManager(Context context, int slotId, FeatureFlags featureFlags) {
+    private EpdgTunnelManager(Context context, int slotId, FeatureFlags featureFlags) {
+        this(
+                context,
+                slotId,
+                featureFlags,
+                new IkeSessionCreator(),
+                new EpdgSelector(context, slotId, featureFlags));
+    }
+
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    EpdgTunnelManager(
+            Context context,
+            int slotIndex,
+            FeatureFlags featureFlags,
+            IkeSessionCreator ikeSessionCreator,
+            EpdgSelector epdgSelector) {
         mContext = context;
-        mSlotId = slotId;
+        mSlotId = slotIndex;
         mFeatureFlags = featureFlags;
-        mIkeSessionCreator = new IkeSessionCreator();
+        mIkeSessionCreator = ikeSessionCreator;
         mIpSecManager = mContext.getSystemService(IpSecManager.class);
         // Adding this here is necessary because we need to initialize EpdgSelector at the beginning
         // to ensure no broadcasts are missed.
-        mEpdgSelector = EpdgSelector.getSelectorInstance(mContext, mSlotId);
+        mEpdgSelector = epdgSelector;
         TAG = EpdgTunnelManager.class.getSimpleName() + "[" + mSlotId + "]";
         initHandler();
         registerConnectivityDiagnosticsCallback();
diff --git a/test/com/google/android/iwlan/ErrorPolicyManagerTest.java b/test/com/google/android/iwlan/ErrorPolicyManagerTest.java
index c3df454..9f7847d 100644
--- a/test/com/google/android/iwlan/ErrorPolicyManagerTest.java
+++ b/test/com/google/android/iwlan/ErrorPolicyManagerTest.java
@@ -53,6 +53,7 @@ import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+import java.time.Duration;
 import java.util.List;
 import java.util.Map;
 import java.util.Optional;
@@ -1005,12 +1006,9 @@ public class ErrorPolicyManagerTest {
         failCause = mErrorPolicyManager.getDataFailCause(apn2);
         assertEquals(DataFailCause.IWLAN_PDN_CONNECTION_REJECTION, failCause);
 
-        long retryTime =
-                Math.round((double) mErrorPolicyManager.getRemainingRetryTimeMs(apn1) / 1000);
-        assertEquals(4, retryTime);
+        assertEquals(Duration.ofSeconds(4), mErrorPolicyManager.getRemainingBackoffDuration(apn1));
 
-        retryTime = Math.round((double) mErrorPolicyManager.getRemainingRetryTimeMs(apn2) / 1000);
-        assertEquals(5, retryTime);
+        assertEquals(Duration.ofSeconds(5), mErrorPolicyManager.getRemainingBackoffDuration(apn2));
     }
 
     @Test
@@ -1053,8 +1051,7 @@ public class ErrorPolicyManagerTest {
         IwlanError iwlanError = buildIwlanIkeAuthFailedError();
         mErrorPolicyManager.reportIwlanError(apn, iwlanError, 2);
 
-        long time = Math.round((double) mErrorPolicyManager.getRemainingRetryTimeMs(apn) / 1000);
-        assertEquals(time, 2);
+        assertEquals(Duration.ofSeconds(2), mErrorPolicyManager.getRemainingBackoffDuration(apn));
 
         // advanceClockByTimeMs for 2 seconds and make sure that we can bring up tunnel after 2 secs
         // as back off time - 2 secs should override the retry time in policy - 10 secs
@@ -1063,15 +1060,14 @@ public class ErrorPolicyManagerTest {
         assertTrue(bringUpTunnel);
 
         // test whether the same error reported later uses the right policy
-        time = mErrorPolicyManager.reportIwlanError(apn, iwlanError);
+        long time = mErrorPolicyManager.reportIwlanError(apn, iwlanError);
         assertEquals(10, time);
 
         bringUpTunnel = mErrorPolicyManager.canBringUpTunnel(apn);
         assertFalse(bringUpTunnel);
 
         mErrorPolicyManager.reportIwlanError(apn, iwlanError, 5);
-        time = Math.round((double) mErrorPolicyManager.getRemainingRetryTimeMs(apn) / 1000);
-        assertEquals(time, 5);
+        assertEquals(Duration.ofSeconds(5), mErrorPolicyManager.getRemainingBackoffDuration(apn));
 
         // test whether the same error reported later starts from the beginning of retry array
         time = mErrorPolicyManager.reportIwlanError(apn, iwlanError);
diff --git a/test/com/google/android/iwlan/IwlanDataServiceTest.java b/test/com/google/android/iwlan/IwlanDataServiceTest.java
index 417858c..58369ba 100644
--- a/test/com/google/android/iwlan/IwlanDataServiceTest.java
+++ b/test/com/google/android/iwlan/IwlanDataServiceTest.java
@@ -110,12 +110,14 @@ import java.lang.reflect.Method;
 import java.net.Inet4Address;
 import java.net.Inet6Address;
 import java.net.InetAddress;
+import java.time.Duration;
 import java.util.ArrayList;
 import java.util.Calendar;
 import java.util.Collections;
 import java.util.Date;
 import java.util.List;
 import java.util.LongSummaryStatistics;
+import java.util.function.Consumer;
 
 public class IwlanDataServiceTest {
     private static final int DEFAULT_SLOT_INDEX = 0;
@@ -1031,7 +1033,8 @@ public class IwlanDataServiceTest {
     public void testHandoverFailureModeDefault() {
         DataProfile dp = buildImsDataProfile();
 
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(5L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(Duration.ofMillis(5));
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.USER_AUTHENTICATION);
 
@@ -1079,7 +1082,8 @@ public class IwlanDataServiceTest {
     public void testHandoverFailureModeHandover() {
         DataProfile dp = buildImsDataProfile();
 
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(-1L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.ERROR_UNSPECIFIED);
         when(mMockErrorPolicyManager.shouldRetryWithInitialAttach(eq(TEST_APN_NAME)))
@@ -1129,7 +1133,8 @@ public class IwlanDataServiceTest {
     public void testSupportInitialAttachSuccessOnIms() {
         DataProfile dp = buildImsDataProfile();
 
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(-1L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.ERROR_UNSPECIFIED);
         when(mMockErrorPolicyManager.shouldRetryWithInitialAttach(eq(TEST_APN_NAME)))
@@ -1185,7 +1190,8 @@ public class IwlanDataServiceTest {
     public void testSupportInitialAttachSuccessOnEmergency() {
         DataProfile dp = buildDataProfile(ApnSetting.TYPE_EMERGENCY);
 
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(-1L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.ERROR_UNSPECIFIED);
         when(mMockErrorPolicyManager.shouldRetryWithInitialAttach(eq(TEST_APN_NAME)))
@@ -1241,7 +1247,8 @@ public class IwlanDataServiceTest {
     public void testSupportInitialAttachOnImsCall() {
         DataProfile dp = buildImsDataProfile();
 
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(-1L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.ERROR_UNSPECIFIED);
         when(mMockErrorPolicyManager.shouldRetryWithInitialAttach(eq(TEST_APN_NAME)))
@@ -1297,7 +1304,8 @@ public class IwlanDataServiceTest {
     public void testSupportInitialAttachOnEmergencyCall() {
         DataProfile dp = buildDataProfile(ApnSetting.TYPE_EMERGENCY);
 
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(-1L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.ERROR_UNSPECIFIED);
         when(mMockErrorPolicyManager.shouldRetryWithInitialAttach(eq(TEST_APN_NAME)))
@@ -1433,12 +1441,25 @@ public class IwlanDataServiceTest {
                 .build();
     }
 
+    static Network newCellNetwork(ConnectivityManager connectivityMgr, int subId) {
+        Network cellNetwork = mock(Network.class);
+        NetworkCapabilities caps =
+                new NetworkCapabilities.Builder()
+                        .addTransportType(TRANSPORT_CELLULAR)
+                        .setNetworkSpecifier(new TelephonyNetworkSpecifier(subId))
+                        .build();
+        when(connectivityMgr.getNetworkCapabilities(cellNetwork)).thenReturn(caps);
+        return cellNetwork;
+    }
+
     private NetworkCapabilities prepareNetworkCapabilitiesForTest(
             int transportType, int subId, boolean isVcn) {
         NetworkCapabilities.Builder builder =
                 new NetworkCapabilities.Builder().addTransportType(transportType);
         if (isVcn) {
-            builder.setTransportInfo(new VcnTransportInfo(subId));
+            Network underlyingCell = newCellNetwork(mMockConnectivityManager, subId);
+            builder.setTransportInfo(new VcnTransportInfo.Builder().build())
+                    .setUnderlyingNetworks(Collections.singletonList(underlyingCell));
         } else {
             builder.setNetworkSpecifier(new TelephonyNetworkSpecifier(subId));
         }
@@ -1744,6 +1765,9 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.ERROR_UNSPECIFIED);
 
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
+
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(
@@ -1800,6 +1824,9 @@ public class IwlanDataServiceTest {
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.ERROR_UNSPECIFIED);
 
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
+
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(
@@ -1844,6 +1871,9 @@ public class IwlanDataServiceTest {
 
         when(mMockErrorPolicyManager.getLastErrorCountOfSameCause(eq(TEST_APN_NAME))).thenReturn(5);
 
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(ErrorPolicyManager.UNSPECIFIED_RETRY_DURATION);
+
         mSpyIwlanDataServiceProvider
                 .getIwlanTunnelCallback()
                 .onClosed(
@@ -2423,7 +2453,7 @@ public class IwlanDataServiceTest {
 
         assertEquals(1, resultCodeCallback.size());
         assertEquals(
-                DataServiceCallback.RESULT_ERROR_UNSUPPORTED,
+                DataServiceCallback.RESULT_ERROR_ILLEGAL_STATE,
                 resultCodeCallback.get(index).intValue());
         verify(mMockEpdgTunnelManager, never()).requestNetworkValidationForApn(eq(apnName));
     }
@@ -2469,7 +2499,7 @@ public class IwlanDataServiceTest {
     public void testOnNetworkValidationStatusChangedForRegisteredApn() {
         List<DataCallResponse> dataCallList;
 
-        ArrayList<Integer> resultCodeCallback = new ArrayList<>();
+        Consumer<Integer> mockResultCodeCallback = mock(Consumer.class);
         DataProfile dp = buildImsDataProfile();
         String apnName = dp.getApnSetting().getApnName();
         int cid = apnName.hashCode();
@@ -2486,8 +2516,9 @@ public class IwlanDataServiceTest {
 
         // Requests network validation
         mSpyIwlanDataServiceProvider.requestNetworkValidation(
-                cid, Runnable::run, resultCodeCallback::add);
+                cid, Runnable::run, mockResultCodeCallback);
         mTestLooper.dispatchAll();
+        verify(mockResultCodeCallback, times(1)).accept(DataServiceCallback.RESULT_SUCCESS);
 
         dataCallList = verifyDataCallListChangeAndCaptureUpdatedList();
         assertEquals(1, dataCallList.size());
@@ -2518,6 +2549,7 @@ public class IwlanDataServiceTest {
 
     @Test
     public void testGetCallListWithRequestNetworkValidationInProgress() {
+        Consumer<Integer> mockResultCodeCallback = mock(Consumer.class);
         ArgumentCaptor<List<DataCallResponse>> dataCallListCaptor =
                 ArgumentCaptor.forClass((Class) List.class);
         DataProfile dp = buildImsDataProfile();
@@ -2526,10 +2558,10 @@ public class IwlanDataServiceTest {
         verifySetupDataCallSuccess(dp);
 
         // Requests network validation, network validation status in progress
-        ArrayList<Integer> resultCodeCallback = new ArrayList<>();
         mSpyIwlanDataServiceProvider.requestNetworkValidation(
-                cid, Runnable::run, resultCodeCallback::add);
+                cid, Runnable::run, mockResultCodeCallback);
         mTestLooper.dispatchAll();
+        verify(mockResultCodeCallback, times(1)).accept(DataServiceCallback.RESULT_SUCCESS);
 
         // Requests data call list
         mSpyIwlanDataServiceProvider.requestDataCallList(mMockDataServiceCallback);
@@ -2663,7 +2695,8 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
         DataProfile dp = buildImsDataProfile();
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(5L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(Duration.ofMillis(5));
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.USER_AUTHENTICATION);
 
@@ -2711,7 +2744,8 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
         DataProfile dp = buildDataProfile(ApnSetting.TYPE_EMERGENCY);
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(5L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(Duration.ofMillis(5));
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.USER_AUTHENTICATION);
 
@@ -2813,7 +2847,8 @@ public class IwlanDataServiceTest {
         onSystemDefaultNetworkConnected(TRANSPORT_WIFI);
 
         DataProfile dp = buildDataProfile(ApnSetting.TYPE_EMERGENCY);
-        when(mMockErrorPolicyManager.getRemainingRetryTimeMs(eq(TEST_APN_NAME))).thenReturn(5L);
+        when(mMockErrorPolicyManager.getRemainingBackoffDuration(eq(TEST_APN_NAME)))
+                .thenReturn(Duration.ofMillis(5));
         when(mMockErrorPolicyManager.getDataFailCause(eq(TEST_APN_NAME)))
                 .thenReturn(DataFailCause.USER_AUTHENTICATION);
 
diff --git a/test/com/google/android/iwlan/IwlanNetworkServiceTest.java b/test/com/google/android/iwlan/IwlanNetworkServiceTest.java
index 2dc62d7..7edbefe 100644
--- a/test/com/google/android/iwlan/IwlanNetworkServiceTest.java
+++ b/test/com/google/android/iwlan/IwlanNetworkServiceTest.java
@@ -53,6 +53,7 @@ import org.mockito.MockitoAnnotations;
 import org.mockito.MockitoSession;
 import org.mockito.quality.Strictness;
 
+import java.util.Collections;
 import java.util.List;
 
 public class IwlanNetworkServiceTest {
@@ -167,7 +168,10 @@ public class IwlanNetworkServiceTest {
                 new NetworkCapabilities.Builder()
                         .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR);
         if (isVcn) {
-            builder.setTransportInfo(new VcnTransportInfo(subId));
+            Network underlyingCell =
+                    IwlanDataServiceTest.newCellNetwork(mMockConnectivityManager, subId);
+            builder.setTransportInfo(new VcnTransportInfo.Builder().build())
+                    .setUnderlyingNetworks(Collections.singletonList(underlyingCell));
         } else {
             builder.setNetworkSpecifier(new TelephonyNetworkSpecifier(subId));
         }
diff --git a/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java b/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
index 55b40b1..9317c36 100644
--- a/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
+++ b/test/com/google/android/iwlan/epdg/EpdgTunnelManagerTest.java
@@ -117,7 +117,7 @@ import java.util.concurrent.Executor;
 @RunWith(JUnit4.class)
 public class EpdgTunnelManagerTest {
     public static final int DEFAULT_SLOT_INDEX = 0;
-    public static final int DEFAULT_SUBID = 0;
+    public static final int DEFAULT_SUB_ID = 0;
     public static final int DEFAULT_TOKEN = 0;
 
     private static final String EPDG_ADDRESS = "127.0.0.1";
@@ -215,11 +215,9 @@ public class EpdgTunnelManagerTest {
                         .startMocking();
         mMockedClockTime = 0;
         when(IwlanHelper.elapsedRealtime()).thenAnswer(i -> mMockedClockTime);
+
         EpdgTunnelManager.resetAllInstances();
         ErrorPolicyManager.resetAllInstances();
-
-        when(EpdgSelector.getSelectorInstance(eq(mMockContext), eq(DEFAULT_SLOT_INDEX)))
-                .thenReturn(mMockEpdgSelector);
         when(ErrorPolicyManager.getInstance(eq(mMockContext), eq(DEFAULT_SLOT_INDEX)))
                 .thenReturn(mMockErrorPolicyManager);
         when(mMockContext.getSystemService(eq(ConnectivityManager.class)))
@@ -230,7 +228,7 @@ public class EpdgTunnelManagerTest {
                 .thenReturn(mMockTelephonyManager);
         when(mMockContext.getSystemService(eq(ConnectivityDiagnosticsManager.class)))
                 .thenReturn(mMockConnectivityDiagnosticsManager);
-        when(mMockTelephonyManager.createForSubscriptionId(DEFAULT_SUBID))
+        when(mMockTelephonyManager.createForSubscriptionId(DEFAULT_SUB_ID))
                 .thenReturn(mMockTelephonyManager);
         when(mMockTelephonyManager.getSimCarrierId()).thenReturn(0);
         when(mMockContext.getSystemService(eq(IpSecManager.class))).thenReturn(mMockIpSecManager);
@@ -238,14 +236,20 @@ public class EpdgTunnelManagerTest {
         when(mMockConnectivityManager.getNetworkCapabilities(any(Network.class)))
                 .thenReturn(mMockNetworkCapabilities);
         when(mMockNetworkCapabilities.hasCapability(anyInt())).thenReturn(false);
+
         mEpdgTunnelManager =
-                spy(new EpdgTunnelManager(mMockContext, DEFAULT_SLOT_INDEX, mFakeFeatureFlags));
+                spy(
+                        new EpdgTunnelManager(
+                                mMockContext,
+                                DEFAULT_SLOT_INDEX,
+                                mFakeFeatureFlags,
+                                mMockIkeSessionCreator,
+                                mMockEpdgSelector));
         verify(mMockConnectivityDiagnosticsManager)
                 .registerConnectivityDiagnosticsCallback(
                         any(), any(), mConnectivityDiagnosticsCallbackArgumentCaptor.capture());
         doReturn(mTestLooper.getLooper()).when(mEpdgTunnelManager).getLooper();
         mEpdgTunnelManager.initHandler();
-        when(mEpdgTunnelManager.getIkeSessionCreator()).thenReturn(mMockIkeSessionCreator);
 
         when(mMockEpdgSelector.getValidatedServerList(
                         anyInt(),
@@ -275,7 +279,7 @@ public class EpdgTunnelManagerTest {
 
         when(mMockSubscriptionManager.getActiveSubscriptionInfoForSimSlotIndex(DEFAULT_SLOT_INDEX))
                 .thenReturn(mMockSubscriptionInfo);
-        when(mMockSubscriptionInfo.getSubscriptionId()).thenReturn(DEFAULT_SUBID);
+        when(mMockSubscriptionInfo.getSubscriptionId()).thenReturn(DEFAULT_SUB_ID);
         when(mMockSubscriptionInfo.getMncString()).thenReturn("344");
 
         when(mMockLinkProperties.isReachable(any())).thenReturn(true);
```

