```diff
diff --git a/OWNERS b/OWNERS
index 0e102e3..0f0c27f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,7 +1,6 @@
 jackyu@google.com
 rgreenwalt@google.com
 amruthr@google.com
-tomtaylor@google.com
 afurtado@google.com
 jianxiangp@google.com
 sasindran@google.com
diff --git a/proto/src/persist_mms_atoms.proto b/proto/src/persist_mms_atoms.proto
index 2a05163..cbaf5a9 100644
--- a/proto/src/persist_mms_atoms.proto
+++ b/proto/src/persist_mms_atoms.proto
@@ -53,6 +53,7 @@ message IncomingMms {
   optional bool is_managed_profile = 12;
   optional bool is_ntn = 13;
   optional bool is_nb_iot_ntn = 14;
+  optional int32 pdu_length = 15;
 }
 
 message OutgoingMms {
@@ -71,4 +72,7 @@ message OutgoingMms {
   optional bool is_managed_profile = 13;
   optional bool is_ntn = 14;
   optional bool is_nb_iot_ntn = 15;
+  optional int32 pdu_length = 16;
+  optional string calling_package_name = 17;
+  optional int32 app_uid = 18;
 }
diff --git a/src/com/android/mms/service/DownloadRequest.java b/src/com/android/mms/service/DownloadRequest.java
index 461cb64..7ef789b 100644
--- a/src/com/android/mms/service/DownloadRequest.java
+++ b/src/com/android/mms/service/DownloadRequest.java
@@ -378,4 +378,20 @@ public class DownloadRequest extends MmsRequest {
         }
         return wapSize;
     }
+
+    /**
+     * Calculates the PDU length for downloaded MMS.
+     *
+     * @param result Operation result code.
+     * @param response Received PDU bytes for download.
+     * @return The length of downloaded PDU if successful, otherwise 0.
+     */
+    @Override
+    protected int getPduLength(int result, byte[] response) {
+        int payloadSize = 0;
+        if (result == Activity.RESULT_OK && response != null) {
+            payloadSize = response.length;
+        }
+        return payloadSize;
+    }
 }
diff --git a/src/com/android/mms/service/MmsRequest.java b/src/com/android/mms/service/MmsRequest.java
index bc0233b..9a14d44 100644
--- a/src/com/android/mms/service/MmsRequest.java
+++ b/src/com/android/mms/service/MmsRequest.java
@@ -150,10 +150,8 @@ public abstract class MmsRequest {
                 if ((apnSetting.getApnTypeBitmask() & ApnSetting.TYPE_MMS) != 0) {
                     LogUtil.d("onPreciseDataConnectionStateChanged: " + connectionState);
                     mLastConnectionFailure = connectionState.getLastCauseCode();
-                    if (Flags.mmsGetApnFromPdsc()) {
-                        synchronized (mLock) {
-                            mNetworkIdToApn.put(connectionState.getNetId(), apnSetting);
-                        }
+                    synchronized (mLock) {
+                        mNetworkIdToApn.put(connectionState.getNetId(), apnSetting);
                     }
                 }
             }
@@ -209,13 +207,11 @@ public abstract class MmsRequest {
                     currentState = MmsRequestState.LoadingApn;
                     ApnSettings apn = null;
                     ApnSetting networkApn = null;
-                    if (Flags.mmsGetApnFromPdsc()) {
-                        synchronized (connectionStateCallback.mLock) {
-                            networkApn = connectionStateCallback.mNetworkIdToApn.get(networkId);
-                        }
-                        if (networkApn != null) {
-                            apn = ApnSettings.getApnSettingsFromNetworkApn(networkApn);
-                        }
+                    synchronized (connectionStateCallback.mLock) {
+                        networkApn = connectionStateCallback.mNetworkIdToApn.get(networkId);
+                    }
+                    if (networkApn != null) {
+                        apn = ApnSettings.getApnSettingsFromNetworkApn(networkApn);
                     }
                     if (apn == null) {
                         final String apnName = networkManager.getApnName();
@@ -234,11 +230,6 @@ public abstract class MmsRequest {
                         }
                     }
 
-                    if (Flags.mmsGetApnFromPdsc() && networkApn == null && apn != null) {
-                        reportAnomaly("Can't find MMS APN in mms network",
-                                UUID.fromString("2bdda74d-3cf4-44ad-a87f-24c961212a6f"));
-                    }
-
                     LogUtil.d(requestId, "Using APN " + apn);
                     if (networkManager.isSatelliteTransport()
                             && !canTransferPayloadOnCurrentNetwork()) {
@@ -357,7 +348,8 @@ public abstract class MmsRequest {
                 }
                 reportPossibleAnomaly(result, httpStatusCode);
                 pendingIntent.send(context, result, fillIn);
-                mMmsStats.addAtomToStorage(result, retryId, handledByCarrierApp, mMessageId);
+                mMmsStats.addAtomToStorage(result, retryId, handledByCarrierApp, mMessageId,
+                        getPduLength(result, response));
             } catch (PendingIntent.CanceledException e) {
                 LogUtil.e(requestId, "Sending pending intent canceled", e);
             }
@@ -453,6 +445,15 @@ public abstract class MmsRequest {
         }
     }
 
+    /**
+     * Calculates the PDU length for MMS based on the request type.
+     *
+     * @param result Operation result code.
+     * @param response Received PDU bytes (for download).
+     * @return PDU length.
+     */
+    protected abstract int getPduLength(int result, byte[] response);
+
     /**
      * Returns true if sending / downloading using the carrier app has failed and completes the
      * action using platform API's, otherwise false.
diff --git a/src/com/android/mms/service/MmsService.java b/src/com/android/mms/service/MmsService.java
index 6897e40..4eabfd7 100644
--- a/src/com/android/mms/service/MmsService.java
+++ b/src/com/android/mms/service/MmsService.java
@@ -42,7 +42,6 @@ import android.os.RemoteException;
 import android.os.UserHandle;
 import android.provider.Settings;
 import android.provider.Telephony;
-import android.security.NetworkSecurityPolicy;
 import android.service.carrier.CarrierMessagingService;
 import android.telephony.AnomalyReporter;
 import android.telephony.SmsManager;
@@ -222,7 +221,7 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
 
             MmsStats mmsStats = new MmsStats(MmsService.this,
                     mMmsMetricsCollector.getAtomsStorage(), subId, getTelephonyManager(subId),
-                    callingPkg, false);
+                    callingPkg, false, callingUser);
 
             // Make sure the subId is correct
             if (!SubscriptionManager.isValidSubscriptionId(subId)) {
@@ -311,7 +310,7 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
 
             MmsStats mmsStats = new MmsStats(MmsService.this,
                     mMmsMetricsCollector.getAtomsStorage(), subId, getTelephonyManager(subId),
-                    callingPkg, true);
+                    callingPkg, true, callingUser);
 
             // Make sure the subId is correct
             if (!SubscriptionManager.isValidSubscriptionId(subId)) {
@@ -742,8 +741,6 @@ public class MmsService extends Service implements MmsRequest.RequestManager {
         // Load mms_config
         MmsConfigManager.getInstance().init(this);
 
-        NetworkSecurityPolicy.getInstance().setCleartextTrafficPermitted(true);
-
         // Registers statsd pullers
         mMmsMetricsCollector = new MmsMetricsCollector(this);
 
diff --git a/src/com/android/mms/service/SendRequest.java b/src/com/android/mms/service/SendRequest.java
index dd44f2c..e7241e3 100644
--- a/src/com/android/mms/service/SendRequest.java
+++ b/src/com/android/mms/service/SendRequest.java
@@ -516,4 +516,17 @@ public class SendRequest extends MmsRequest {
         }
         return mPduData.length;
     }
+
+    /**
+     * Calculates the PDU length for sent MMS.
+     * <p>
+     * This implementation returns the size of the payload that was intended to be sent, obtained
+     * via {@link #getPayloadSize()}.
+     * The {@code result} and {@code response} parameters are ignored for this request type, as the
+     * size is known before the send operation occurs.
+     */
+    @Override
+    protected int getPduLength(int result, byte[] response) {
+        return (int) this.getPayloadSize();
+    }
 }
diff --git a/src/com/android/mms/service/metrics/MmsMetricsCollector.java b/src/com/android/mms/service/metrics/MmsMetricsCollector.java
index 233f3a5..0ffb6dd 100644
--- a/src/com/android/mms/service/metrics/MmsMetricsCollector.java
+++ b/src/com/android/mms/service/metrics/MmsMetricsCollector.java
@@ -92,7 +92,8 @@ public class MmsMetricsCollector implements StatsManager.StatsPullAtomCallback {
                 mms.getHandledByCarrierApp(),
                 mms.getIsManagedProfile(),
                 mms.getIsNtn(),
-                mms.getIsNbIotNtn());
+                mms.getIsNbIotNtn(),
+                mms.getPduLength());
     }
 
     private static StatsEvent buildStatsEvent(OutgoingMms mms) {
@@ -112,7 +113,10 @@ public class MmsMetricsCollector implements StatsManager.StatsPullAtomCallback {
                 mms.getHandledByCarrierApp(),
                 mms.getIsManagedProfile(),
                 mms.getIsNtn(),
-                mms.getIsNbIotNtn());
+                mms.getIsNbIotNtn(),
+                mms.getPduLength(),
+                mms.getCallingPackageName(),
+                mms.getAppUid());
     }
 
     @Override
diff --git a/src/com/android/mms/service/metrics/MmsStats.java b/src/com/android/mms/service/metrics/MmsStats.java
index 69126cc..4870ec3 100644
--- a/src/com/android/mms/service/metrics/MmsStats.java
+++ b/src/com/android/mms/service/metrics/MmsStats.java
@@ -21,6 +21,7 @@ import static com.android.mms.MmsStatsLog.INCOMING_MMS__RESULT__MMS_RESULT_SUCCE
 import static com.android.mms.MmsStatsLog.OUTGOING_MMS__RESULT__MMS_RESULT_ERROR_UNSPECIFIED;
 import static com.android.mms.MmsStatsLog.OUTGOING_MMS__RESULT__MMS_RESULT_SUCCESS;
 
+import android.annotation.NonNull;
 import android.app.Activity;
 import android.content.Context;
 import android.os.Binder;
@@ -58,16 +59,21 @@ public class MmsStats {
     private final long mTimestamp;
     private int mSubId;
     private TelephonyManager mTelephonyManager;
+    private SatelliteController mSatelliteController;
+    private final int mAppUid;
 
     public MmsStats(Context context, PersistMmsAtomsStorage persistMmsAtomsStorage, int subId,
-            TelephonyManager telephonyManager, String callingPkg, boolean isIncomingMms) {
+            TelephonyManager telephonyManager, String callingPkg, boolean isIncomingMms,
+            int appUid) {
         mContext = context;
         mPersistMmsAtomsStorage = persistMmsAtomsStorage;
         mSubId = subId;
         mTelephonyManager = telephonyManager;
+        mSatelliteController = SatelliteController.getInstance();
         mCallingPkg = callingPkg;
         mIsIncomingMms = isIncomingMms;
         mTimestamp = SystemClock.elapsedRealtime();
+        mAppUid = appUid;
     }
 
     /** Updates subId and corresponding telephonyManager. */
@@ -78,20 +84,21 @@ public class MmsStats {
 
     /** Adds incoming or outgoing mms atom to storage. */
     public void addAtomToStorage(int result) {
-        addAtomToStorage(result, 0, false, 0);
+        addAtomToStorage(result, 0, false, 0, 0);
     }
 
     /** Adds incoming or outgoing mms atom to storage. */
     public void addAtomToStorage(int result, int retryId, boolean handledByCarrierApp,
-            long mMessageId) {
+            long mMessageId, int pduLength) {
+
         long identity = Binder.clearCallingIdentity();
         try {
             if (mIsIncomingMms) {
-                onIncomingMms(result, retryId, handledByCarrierApp);
+                onIncomingMms(result, retryId, handledByCarrierApp, pduLength);
             } else {
-                onOutgoingMms(result, retryId, handledByCarrierApp);
+                onOutgoingMms(result, retryId, handledByCarrierApp, pduLength);
             }
-            if (isUsingNonTerrestrialNetwork()) {
+            if (isInSatelliteModeForCarrierRoaming(mSubId)) {
                 CarrierRoamingSatelliteSessionStats carrierRoamingSatelliteSessionStats =
                         CarrierRoamingSatelliteSessionStats.getInstance(mSubId);
                 carrierRoamingSatelliteSessionStats.onMms(mIsIncomingMms, mMessageId);
@@ -102,7 +109,8 @@ public class MmsStats {
     }
 
     /** Creates a new atom when MMS is received. */
-    private void onIncomingMms(int result, int retryId, boolean handledByCarrierApp) {
+    private void onIncomingMms(int result, int retryId, boolean handledByCarrierApp,
+            int pduLength) {
         IncomingMms incomingMms = IncomingMms.newBuilder()
                 .setRat(getDataNetworkType())
                 .setResult(getIncomingMmsResult(result))
@@ -116,14 +124,16 @@ public class MmsStats {
                 .setRetryId(retryId)
                 .setHandledByCarrierApp(handledByCarrierApp)
                 .setIsManagedProfile(isManagedProfile())
-                .setIsNtn(isUsingNonTerrestrialNetwork())
+                .setIsNtn(isInSatelliteModeForCarrierRoaming(mSubId))
                 .setIsNbIotNtn(isNbIotNtn(mSubId))
+                .setPduLength(pduLength)
                 .build();
         mPersistMmsAtomsStorage.addIncomingMms(incomingMms);
     }
 
     /** Creates a new atom when MMS is sent. */
-    private void onOutgoingMms(int result, int retryId, boolean handledByCarrierApp) {
+    private void onOutgoingMms(int result, int retryId, boolean handledByCarrierApp,
+            int pduLength) {
         OutgoingMms outgoingMms = OutgoingMms.newBuilder()
                 .setRat(getDataNetworkType())
                 .setResult(getOutgoingMmsResult(result))
@@ -138,8 +148,11 @@ public class MmsStats {
                 .setRetryId(retryId)
                 .setHandledByCarrierApp(handledByCarrierApp)
                 .setIsManagedProfile(isManagedProfile())
-                .setIsNtn(isUsingNonTerrestrialNetwork())
+                .setIsNtn(isInSatelliteModeForCarrierRoaming(mSubId))
                 .setIsNbIotNtn(isNbIotNtn(mSubId))
+                .setPduLength(pduLength)
+                .setCallingPackageName(getSanitizedCallingPackageName())
+                .setAppUid(mAppUid)
                 .build();
         mPersistMmsAtomsStorage.addOutgoingMms(outgoingMms);
     }
@@ -231,7 +244,8 @@ public class MmsStats {
     }
 
     /** Returns if the MMS was originated from the default MMS application. */
-    private boolean isDefaultMmsApp() {
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    protected boolean isDefaultMmsApp() {
         UserHandle userHandle = null;
         SubscriptionManager subManager = mContext.getSystemService(SubscriptionManager.class);
         if ((subManager != null) && (subManager.isActiveSubscriptionId(mSubId))) {
@@ -240,20 +254,9 @@ public class MmsStats {
         return SmsApplication.isDefaultMmsApplicationAsUser(mContext, mCallingPkg, userHandle);
     }
 
-    /** Determines whether device is non-terrestrial network or not. */
-    private boolean isUsingNonTerrestrialNetwork() {
-        ServiceState ss = mTelephonyManager.getServiceState();
-        if (ss != null) {
-            return ss.isUsingNonTerrestrialNetwork();
-        } else {
-            Log.e(TAG, "isUsingNonTerrestrialNetwork(): ServiceState is null");
-        }
-        return false;
-    }
-
     /** Determines whether the subscription is in carrier roaming NB-IoT NTN or not. */
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
-    public boolean isNbIotNtn(int subId) {
+    protected boolean isNbIotNtn(int subId) {
         Phone phone = PhoneFactory.getPhone(SubscriptionManager.getPhoneId(subId));
         if (phone == null) {
             Log.e(TAG, "isNbIotNtn(): phone is null");
@@ -277,4 +280,20 @@ public class MmsStats {
     private long getInterval() {
         return (SystemClock.elapsedRealtime() - mTimestamp);
     }
+
+    @NonNull
+    private String getSanitizedCallingPackageName() {
+        return (isInSatelliteModeForCarrierRoaming(mSubId) && mCallingPkg != null) ? mCallingPkg
+                : "";
+    }
+
+    /** Determines whether the subscription is in carrier roaming satellite mode or not. */
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    protected boolean isInSatelliteModeForCarrierRoaming(int subId) {
+        if (mSatelliteController == null) {
+            return false;
+        }
+        return mSatelliteController.isInSatelliteModeForCarrierRoaming(
+                PhoneFactory.getPhone(SubscriptionManager.getPhoneId(subId)));
+    }
 }
diff --git a/src/com/android/mms/service/metrics/PersistMmsAtomsStorage.java b/src/com/android/mms/service/metrics/PersistMmsAtomsStorage.java
index 673eb6d..adadb05 100644
--- a/src/com/android/mms/service/metrics/PersistMmsAtomsStorage.java
+++ b/src/com/android/mms/service/metrics/PersistMmsAtomsStorage.java
@@ -341,7 +341,9 @@ public class PersistMmsAtomsStorage {
                     && mms.getRetryId() == key.getRetryId()
                     && mms.getHandledByCarrierApp() == key.getHandledByCarrierApp()
                     && mms.getIsNtn() == key.getIsNtn()
-                    && mms.getIsNbIotNtn() == key.getIsNbIotNtn()) {
+                    && mms.getIsNbIotNtn() == key.getIsNbIotNtn()
+                    && mms.getPduLength() == key.getPduLength()
+                    && mms.getCallingPackageName().equals(key.getCallingPackageName())) {
                 return i;
             }
         }
diff --git a/tests/robotests/src/com/android/mms/service/MmsRequestRoboTest.java b/tests/robotests/src/com/android/mms/service/MmsRequestRoboTest.java
index 4430f42..ea7a2ea 100644
--- a/tests/robotests/src/com/android/mms/service/MmsRequestRoboTest.java
+++ b/tests/robotests/src/com/android/mms/service/MmsRequestRoboTest.java
@@ -82,7 +82,7 @@ public class MmsRequestRoboTest {
 
         mPersistMmsAtomsStorage = mock(PersistMmsAtomsStorage.class);
         mMmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, mSubId,
-                mTelephonyManager, null, true);
+                mTelephonyManager, null, true, 0);
         mCarrierConfigValues = new Bundle();
         mCarrierConfigValues.putInt(
                 CarrierConfigManager.KEY_MMS_MAX_NTN_PAYLOAD_SIZE_BYTES_INT,
diff --git a/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java b/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
index 7f25f5d..a0d3f21 100644
--- a/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
+++ b/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
@@ -23,6 +23,9 @@ import static com.android.mms.MmsStatsLog.OUTGOING_MMS__RESULT__MMS_RESULT_SUCCE
 
 import static com.google.common.truth.Truth.assertThat;
 
+import static junit.framework.Assert.assertTrue;
+
+import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
@@ -44,6 +47,7 @@ import com.android.mms.OutgoingMms;
 
 import org.junit.After;
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Test;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mockito;
@@ -56,6 +60,7 @@ public class MmsStatsTest {
     private TelephonyManager mTelephonyManager;
     private SubscriptionManager mSubscriptionManager;
     @Spy private MmsStats mSpyMmsStats;
+    private static final String TEST_CALLING_PACKAGE_NAME = "TEST_CALLING_PACKAGE_NAME";
 
     @Before
     public void setUp() {
@@ -81,10 +86,11 @@ public class MmsStatsTest {
         doReturn(TelephonyManager.UNKNOWN_CARRIER_ID).when(mTelephonyManager).getSimCarrierId();
         int inactiveSubId = 123;
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, inactiveSubId,
-                mTelephonyManager, null, true);
+                mTelephonyManager, null, true, 10000);
         mSpyMmsStats = Mockito.spy(mmsStats);
-        doReturn(false).when(mSpyMmsStats).isNbIotNtn(inactiveSubId);
-        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(anyInt());
+        doReturn(false).when(mSpyMmsStats).isInSatelliteModeForCarrierRoaming(anyInt());
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK, 0, false, 0, 10);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
         verify(mPersistMmsAtomsStorage).addIncomingMms(incomingMmsCaptor.capture());
@@ -103,19 +109,21 @@ public class MmsStatsTest {
         assertThat(incomingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(incomingMms.getIsNtn()).isEqualTo(false);
         assertThat(incomingMms.getIsNbIotNtn()).isEqualTo(false);
+        assertThat(incomingMms.getPduLength()).isEqualTo(10);
         verifyNoMoreInteractions(mPersistMmsAtomsStorage);
     }
 
     private OutgoingMms addAtomToStorage_outgoingMms(
-            int result, int retryId, boolean handledByCarrierApp, long mMessageId) {
+            int result, int retryId, boolean handledByCarrierApp, long mMessageId, int pduLength) {
         doReturn(null).when(mTelephonyManager).getServiceState();
         doReturn(TelephonyManager.UNKNOWN_CARRIER_ID).when(mTelephonyManager).getSimCarrierId();
         int inactiveSubId = 123;
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, inactiveSubId,
-                mTelephonyManager, null, false);
+                mTelephonyManager, null, false, 10000);
         mSpyMmsStats = Mockito.spy(mmsStats);
-        doReturn(false).when(mSpyMmsStats).isNbIotNtn(inactiveSubId);
-        mSpyMmsStats.addAtomToStorage(result, retryId, handledByCarrierApp, mMessageId);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(anyInt());
+        doReturn(false).when(mSpyMmsStats).isInSatelliteModeForCarrierRoaming(anyInt());
+        mSpyMmsStats.addAtomToStorage(result, retryId, handledByCarrierApp, mMessageId, pduLength);
 
         ArgumentCaptor<OutgoingMms> outgoingMmsCaptor = ArgumentCaptor.forClass(OutgoingMms.class);
         verify(mPersistMmsAtomsStorage).addOutgoingMms(outgoingMmsCaptor.capture());
@@ -125,7 +133,7 @@ public class MmsStatsTest {
 
     @Test
     public void addAtomToStorage_outgoingMms_default() {
-        OutgoingMms outgoingMms = addAtomToStorage_outgoingMms(Activity.RESULT_OK, 0, false, 0);
+        OutgoingMms outgoingMms = addAtomToStorage_outgoingMms(Activity.RESULT_OK, 0, false, 0, 10);
         assertThat(outgoingMms.getRat()).isEqualTo(TelephonyManager.NETWORK_TYPE_UNKNOWN);
         assertThat(outgoingMms.getResult()).isEqualTo(OUTGOING_MMS__RESULT__MMS_RESULT_SUCCESS);
         assertThat(outgoingMms.getRoaming()).isEqualTo(ServiceState.ROAMING_TYPE_NOT_ROAMING);
@@ -141,11 +149,14 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
         assertThat(outgoingMms.getIsNbIotNtn()).isEqualTo(false);
+        assertThat(outgoingMms.getPduLength()).isEqualTo(10);
+        assertTrue(outgoingMms.getCallingPackageName().isEmpty());
+        assertThat(outgoingMms.getAppUid()).isEqualTo(10000);
     }
 
     @Test
     public void addAtomToStorage_outgoingMms_handledByCarrierApp_Succeeded() {
-        OutgoingMms outgoingMms = addAtomToStorage_outgoingMms(Activity.RESULT_OK, 0, true, 0);
+        OutgoingMms outgoingMms = addAtomToStorage_outgoingMms(Activity.RESULT_OK, 0, true, 0, 0);
         assertThat(outgoingMms.getRat()).isEqualTo(TelephonyManager.NETWORK_TYPE_UNKNOWN);
         assertThat(outgoingMms.getResult()).isEqualTo(OUTGOING_MMS__RESULT__MMS_RESULT_SUCCESS);
         assertThat(outgoingMms.getRoaming()).isEqualTo(ServiceState.ROAMING_TYPE_NOT_ROAMING);
@@ -161,12 +172,15 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
         assertThat(outgoingMms.getIsNbIotNtn()).isEqualTo(false);
+        assertThat(outgoingMms.getPduLength()).isEqualTo(0);
+        assertTrue(outgoingMms.getCallingPackageName().isEmpty());
+        assertThat(outgoingMms.getAppUid()).isEqualTo(10000);
     }
 
     @Test
     public void addAtomToStorage_outgoingMms_handledByCarrierApp_FailedWithoutReason() {
         OutgoingMms outgoingMms =
-                addAtomToStorage_outgoingMms(SmsManager.MMS_ERROR_UNSPECIFIED, 0, true, 0);
+                addAtomToStorage_outgoingMms(SmsManager.MMS_ERROR_UNSPECIFIED, 0, true, 0, 10);
         assertThat(outgoingMms.getRat()).isEqualTo(TelephonyManager.NETWORK_TYPE_UNKNOWN);
         assertThat(outgoingMms.getResult())
                 .isEqualTo(OUTGOING_MMS__RESULT__MMS_RESULT_ERROR_UNSPECIFIED);
@@ -183,6 +197,9 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
         assertThat(outgoingMms.getIsNbIotNtn()).isEqualTo(false);
+        assertThat(outgoingMms.getPduLength()).isEqualTo(10);
+        assertTrue(outgoingMms.getCallingPackageName().isEmpty());
+        assertThat(outgoingMms.getAppUid()).isEqualTo(10000);
     }
 
     @Test
@@ -191,7 +208,7 @@ public class MmsStatsTest {
             return;
         }
         OutgoingMms outgoingMms =
-                addAtomToStorage_outgoingMms(SmsManager.MMS_ERROR_NO_DATA_NETWORK, 0, true, 0);
+                addAtomToStorage_outgoingMms(SmsManager.MMS_ERROR_NO_DATA_NETWORK, 0, true, 0, 0);
         assertThat(outgoingMms.getRat()).isEqualTo(TelephonyManager.NETWORK_TYPE_UNKNOWN);
         assertThat(outgoingMms.getResult())
                 .isEqualTo(OUTGOING_MMS__RESULT__MMS_RESULT_ERROR_NO_DATA_NETWORK);
@@ -208,6 +225,9 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
         assertThat(outgoingMms.getIsNbIotNtn()).isEqualTo(false);
+        assertThat(outgoingMms.getPduLength()).isEqualTo(0);
+        assertTrue(outgoingMms.getCallingPackageName().isEmpty());
+        assertThat(outgoingMms.getAppUid()).isEqualTo(10000);
     }
 
     @Test
@@ -215,9 +235,10 @@ public class MmsStatsTest {
         ServiceState serviceState = mock(ServiceState.class);
         doReturn(serviceState).when(mTelephonyManager).getServiceState();
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
-                mTelephonyManager, null, true);
+                mTelephonyManager, null, true, 10000);
         mSpyMmsStats = Mockito.spy(mmsStats);
-        doReturn(false).when(mSpyMmsStats).isNbIotNtn(1);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(anyInt());
+        doReturn(false).when(mSpyMmsStats).isInSatelliteModeForCarrierRoaming(anyInt());
         mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
@@ -234,15 +255,17 @@ public class MmsStatsTest {
                 .isActiveSubscriptionId(eq(inactiveSubId));
 
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, inactiveSubId,
-                mTelephonyManager, null, false);
+                mTelephonyManager, null, false, 10000);
         mSpyMmsStats = Mockito.spy(mmsStats);
-        doReturn(false).when(mSpyMmsStats).isNbIotNtn(inactiveSubId);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(anyInt());
+        doReturn(false).when(mSpyMmsStats).isInSatelliteModeForCarrierRoaming(anyInt());
         mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         // getSubscriptionUserHandle should not be called if subID is inactive.
         verify(mSubscriptionManager, never()).getSubscriptionUserHandle(eq(inactiveSubId));
     }
 
+    @Ignore("Should be enabled after resolving b/415883449")
     @Test
     public void testIsNtn_serviceState_notNull() {
         ServiceState serviceState = mock(ServiceState.class);
@@ -250,9 +273,10 @@ public class MmsStatsTest {
         doReturn(true).when(serviceState).isUsingNonTerrestrialNetwork();
 
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
-                mTelephonyManager, null, true);
+                mTelephonyManager, null, true, 10000);
         mSpyMmsStats = Mockito.spy(mmsStats);
-        doReturn(false).when(mSpyMmsStats).isNbIotNtn(1);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(anyInt());
+        doReturn(false).when(mSpyMmsStats).isInSatelliteModeForCarrierRoaming(anyInt());
         mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
@@ -276,9 +300,10 @@ public class MmsStatsTest {
         doReturn(null).when(mTelephonyManager).getServiceState();
 
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
-                mTelephonyManager, null, true);
+                mTelephonyManager, null, true, 10000);
         mSpyMmsStats = Mockito.spy(mmsStats);
-        doReturn(false).when(mSpyMmsStats).isNbIotNtn(1);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(anyInt());
+        doReturn(false).when(mSpyMmsStats).isInSatelliteModeForCarrierRoaming(anyInt());
         mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
@@ -290,9 +315,10 @@ public class MmsStatsTest {
     @Test
     public void testIsNbIotNtn_serviceState_notNull() {
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
-                mTelephonyManager, null, true);
+                mTelephonyManager, null, true, 10000);
         mSpyMmsStats = Mockito.spy(mmsStats);
-        doReturn(true).when(mSpyMmsStats).isNbIotNtn(1);
+        doReturn(true).when(mSpyMmsStats).isNbIotNtn(anyInt());
+        doReturn(false).when(mSpyMmsStats).isInSatelliteModeForCarrierRoaming(anyInt());
         mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
@@ -309,4 +335,35 @@ public class MmsStatsTest {
         incomingMms = incomingMmsCaptor.getValue();
         assertThat(incomingMms.getIsNbIotNtn()).isEqualTo(false);
     }
+
+    @Test
+    public void setTestCallingPackageName() {
+        ServiceState serviceState = mock(ServiceState.class);
+        doReturn(serviceState).when(mTelephonyManager).getServiceState();
+        MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
+                mTelephonyManager, TEST_CALLING_PACKAGE_NAME, false, 10000);
+        mSpyMmsStats = Mockito.spy(mmsStats);
+        doReturn(true).when(mSpyMmsStats).isNbIotNtn(anyInt());
+        doReturn(true).when(mSpyMmsStats).isDefaultMmsApp();
+        doReturn(false).when(mSpyMmsStats).isInSatelliteModeForCarrierRoaming(anyInt());
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
+
+        ArgumentCaptor<OutgoingMms> outgoingMmsCaptor = ArgumentCaptor.forClass(OutgoingMms.class);
+        verify(mPersistMmsAtomsStorage).addOutgoingMms(outgoingMmsCaptor.capture());
+        OutgoingMms outgoingMms = outgoingMmsCaptor.getValue();
+        assertTrue(outgoingMms.getCallingPackageName().isEmpty());
+        assertThat(outgoingMms.getAppUid()).isEqualTo(10000);
+
+        // TODO Should be enabled after resolving b/415883449
+//        reset(mPersistMmsAtomsStorage);
+//        reset(serviceState);
+//        doReturn(true).when(serviceState).isInSatelliteModeForCarrierRoaming(anyInt());
+//        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
+//
+//        outgoingMmsCaptor = ArgumentCaptor.forClass(OutgoingMms.class);
+//        verify(mPersistMmsAtomsStorage).addOutgoingMms(outgoingMmsCaptor.capture());
+//        outgoingMms = outgoingMmsCaptor.getValue();
+//        assertThat(outgoingMms.getCallingPackageName()).isEqualTo(TEST_CALLING_PACKAGE_NAME);
+//        assertThat(outgoingMms.getAppUid()).isEqualTo(10000);
+    }
 }
\ No newline at end of file
```

