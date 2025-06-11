```diff
diff --git a/OWNERS b/OWNERS
index 1befe3e..0e102e3 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,6 +4,4 @@ amruthr@google.com
 tomtaylor@google.com
 afurtado@google.com
 jianxiangp@google.com
-stephshi@google.com
-bellavicevh@google.com
 sasindran@google.com
diff --git a/proto/src/persist_mms_atoms.proto b/proto/src/persist_mms_atoms.proto
index 8be233b..2a05163 100644
--- a/proto/src/persist_mms_atoms.proto
+++ b/proto/src/persist_mms_atoms.proto
@@ -52,6 +52,7 @@ message IncomingMms {
   optional bool handled_by_carrier_app = 11;
   optional bool is_managed_profile = 12;
   optional bool is_ntn = 13;
+  optional bool is_nb_iot_ntn = 14;
 }
 
 message OutgoingMms {
@@ -69,4 +70,5 @@ message OutgoingMms {
   optional bool handled_by_carrier_app = 12;
   optional bool is_managed_profile = 13;
   optional bool is_ntn = 14;
+  optional bool is_nb_iot_ntn = 15;
 }
diff --git a/src/com/android/mms/service/MmsNetworkManager.java b/src/com/android/mms/service/MmsNetworkManager.java
index 91ff3dd..64d7b97 100644
--- a/src/com/android/mms/service/MmsNetworkManager.java
+++ b/src/com/android/mms/service/MmsNetworkManager.java
@@ -38,7 +38,6 @@ import android.telephony.TelephonyManager;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.PhoneConstants;
-import com.android.internal.telephony.flags.Flags;
 import com.android.mms.service.exception.MmsNetworkException;
 
 /**
@@ -250,8 +249,8 @@ public class MmsNetworkManager {
 
                 // New available network
                 if (mNetwork == null && isAvailable) {
-                    mIsSatelliteTransport = Flags.satelliteInternet()
-                            && nc.hasTransport(NetworkCapabilities.TRANSPORT_SATELLITE);
+                    mIsSatelliteTransport = nc.hasTransport(
+                            NetworkCapabilities.TRANSPORT_SATELLITE);
                     mNetwork = network;
                     MmsNetworkManager.this.notifyAll();
                 }
@@ -302,16 +301,14 @@ public class MmsNetworkManager {
 
         // With Satellite internet support, add satellite transport with restricted capability to
         // support mms over satellite network
-        if (Flags.satelliteInternet()) {
-            builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
-            try {
-                // TODO: b/331622062 remove the try/catch
-                builder.addTransportType(NetworkCapabilities.TRANSPORT_SATELLITE);
-                builder.removeCapability(NetworkCapabilities
-                        .NET_CAPABILITY_NOT_BANDWIDTH_CONSTRAINED);
-            } catch (IllegalArgumentException exception) {
-                LogUtil.e("TRANSPORT_SATELLITE or NOT_BANDWIDTH_CONSTRAINED is not supported.");
-            }
+        builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
+        try {
+            // TODO: b/331622062 remove the try/catch
+            builder.addTransportType(NetworkCapabilities.TRANSPORT_SATELLITE);
+            builder.removeCapability(NetworkCapabilities
+                    .NET_CAPABILITY_NOT_BANDWIDTH_CONSTRAINED);
+        } catch (IllegalArgumentException exception) {
+            LogUtil.e("TRANSPORT_SATELLITE or NOT_BANDWIDTH_CONSTRAINED is not supported.");
         }
         mNetworkRequest = builder.build();
 
diff --git a/src/com/android/mms/service/MmsRequest.java b/src/com/android/mms/service/MmsRequest.java
index 8b68d48..bc0233b 100644
--- a/src/com/android/mms/service/MmsRequest.java
+++ b/src/com/android/mms/service/MmsRequest.java
@@ -240,8 +240,7 @@ public abstract class MmsRequest {
                     }
 
                     LogUtil.d(requestId, "Using APN " + apn);
-                    if (Flags.carrierEnabledSatelliteFlag()
-                            && networkManager.isSatelliteTransport()
+                    if (networkManager.isSatelliteTransport()
                             && !canTransferPayloadOnCurrentNetwork()) {
                         LogUtil.e(requestId, "PDU too large for satellite");
                         result = SmsManager.MMS_ERROR_TOO_LARGE_FOR_TRANSPORT;
@@ -692,6 +691,6 @@ public abstract class MmsRequest {
                 .getInt(CarrierConfigManager.KEY_MMS_MAX_NTN_PAYLOAD_SIZE_BYTES_INT);
         LogUtil.d("canTransferPayloadOnCurrentNetwork payloadSize: " + payloadSize
                 + " maxPduSize: " + maxPduSize);
-        return payloadSize > 0 && payloadSize <= maxPduSize;
+        return payloadSize > 0 && (maxPduSize == -1 || payloadSize <= maxPduSize);
     }
 }
diff --git a/src/com/android/mms/service/metrics/MmsMetricsCollector.java b/src/com/android/mms/service/metrics/MmsMetricsCollector.java
index 1bf9211..233f3a5 100644
--- a/src/com/android/mms/service/metrics/MmsMetricsCollector.java
+++ b/src/com/android/mms/service/metrics/MmsMetricsCollector.java
@@ -91,7 +91,8 @@ public class MmsMetricsCollector implements StatsManager.StatsPullAtomCallback {
                 mms.getRetryId(),
                 mms.getHandledByCarrierApp(),
                 mms.getIsManagedProfile(),
-                mms.getIsNtn());
+                mms.getIsNtn(),
+                mms.getIsNbIotNtn());
     }
 
     private static StatsEvent buildStatsEvent(OutgoingMms mms) {
@@ -110,7 +111,8 @@ public class MmsMetricsCollector implements StatsManager.StatsPullAtomCallback {
                 mms.getRetryId(),
                 mms.getHandledByCarrierApp(),
                 mms.getIsManagedProfile(),
-                mms.getIsNtn());
+                mms.getIsNtn(),
+                mms.getIsNbIotNtn());
     }
 
     @Override
diff --git a/src/com/android/mms/service/metrics/MmsStats.java b/src/com/android/mms/service/metrics/MmsStats.java
index dec5129..69126cc 100644
--- a/src/com/android/mms/service/metrics/MmsStats.java
+++ b/src/com/android/mms/service/metrics/MmsStats.java
@@ -35,8 +35,12 @@ import android.telephony.TelephonyManager;
 import android.telephony.UiccCardInfo;
 import android.util.Log;
 
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.telephony.Phone;
+import com.android.internal.telephony.PhoneFactory;
 import com.android.internal.telephony.SmsApplication;
 import com.android.internal.telephony.flags.Flags;
+import com.android.internal.telephony.satellite.SatelliteController;
 import com.android.internal.telephony.satellite.metrics.CarrierRoamingSatelliteSessionStats;
 import com.android.mms.IncomingMms;
 import com.android.mms.OutgoingMms;
@@ -113,6 +117,7 @@ public class MmsStats {
                 .setHandledByCarrierApp(handledByCarrierApp)
                 .setIsManagedProfile(isManagedProfile())
                 .setIsNtn(isUsingNonTerrestrialNetwork())
+                .setIsNbIotNtn(isNbIotNtn(mSubId))
                 .build();
         mPersistMmsAtomsStorage.addIncomingMms(incomingMms);
     }
@@ -134,6 +139,7 @@ public class MmsStats {
                 .setHandledByCarrierApp(handledByCarrierApp)
                 .setIsManagedProfile(isManagedProfile())
                 .setIsNtn(isUsingNonTerrestrialNetwork())
+                .setIsNbIotNtn(isNbIotNtn(mSubId))
                 .build();
         mPersistMmsAtomsStorage.addOutgoingMms(outgoingMms);
     }
@@ -236,10 +242,6 @@ public class MmsStats {
 
     /** Determines whether device is non-terrestrial network or not. */
     private boolean isUsingNonTerrestrialNetwork() {
-        if (!Flags.carrierEnabledSatelliteFlag()) {
-            return false;
-        }
-
         ServiceState ss = mTelephonyManager.getServiceState();
         if (ss != null) {
             return ss.isUsingNonTerrestrialNetwork();
@@ -249,6 +251,24 @@ public class MmsStats {
         return false;
     }
 
+    /** Determines whether the subscription is in carrier roaming NB-IoT NTN or not. */
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    public boolean isNbIotNtn(int subId) {
+        Phone phone = PhoneFactory.getPhone(SubscriptionManager.getPhoneId(subId));
+        if (phone == null) {
+            Log.e(TAG, "isNbIotNtn(): phone is null");
+            return false;
+        }
+
+        SatelliteController satelliteController = SatelliteController.getInstance();
+        if (satelliteController == null) {
+            Log.e(TAG, "isNbIotNtn(): satelliteController is null");
+            return false;
+        }
+
+        return satelliteController.isInCarrierRoamingNbIotNtn(phone);
+    }
+
     /**
      * Returns the interval in milliseconds between sending/receiving MMS message and current time.
      * Calculates the time taken to send message to the network
diff --git a/src/com/android/mms/service/metrics/PersistMmsAtomsStorage.java b/src/com/android/mms/service/metrics/PersistMmsAtomsStorage.java
index 4e9ffc7..673eb6d 100644
--- a/src/com/android/mms/service/metrics/PersistMmsAtomsStorage.java
+++ b/src/com/android/mms/service/metrics/PersistMmsAtomsStorage.java
@@ -22,6 +22,7 @@ import android.os.Build;
 import android.os.Handler;
 import android.os.HandlerThread;
 import android.util.Log;
+
 import androidx.annotation.Nullable;
 import androidx.annotation.VisibleForTesting;
 
@@ -313,7 +314,9 @@ public class PersistMmsAtomsStorage {
                     && mms.getIsEsim() == key.getIsEsim()
                     && mms.getCarrierId() == key.getCarrierId()
                     && mms.getRetryId() == key.getRetryId()
-                    && mms.getHandledByCarrierApp() == key.getHandledByCarrierApp()) {
+                    && mms.getHandledByCarrierApp() == key.getHandledByCarrierApp()
+                    && mms.getIsNtn() == key.getIsNtn()
+                    && mms.getIsNbIotNtn() == key.getIsNbIotNtn()) {
                 return i;
             }
         }
@@ -336,7 +339,9 @@ public class PersistMmsAtomsStorage {
                     && mms.getCarrierId() == key.getCarrierId()
                     && mms.getIsFromDefaultApp() == key.getIsFromDefaultApp()
                     && mms.getRetryId() == key.getRetryId()
-                    && mms.getHandledByCarrierApp() == key.getHandledByCarrierApp()) {
+                    && mms.getHandledByCarrierApp() == key.getHandledByCarrierApp()
+                    && mms.getIsNtn() == key.getIsNtn()
+                    && mms.getIsNbIotNtn() == key.getIsNbIotNtn()) {
                 return i;
             }
         }
diff --git a/tests/robotests/Android.bp b/tests/robotests/Android.bp
index 0c41dbf..4285406 100644
--- a/tests/robotests/Android.bp
+++ b/tests/robotests/Android.bp
@@ -20,7 +20,6 @@ android_robolectric_test {
     ],
 
     instrumentation_for: "MmsService",
-    upstream: true,
 
     strict_mode: false,
 }
diff --git a/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java b/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
index 3350e53..7f25f5d 100644
--- a/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
+++ b/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
@@ -46,6 +46,8 @@ import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.mockito.ArgumentCaptor;
+import org.mockito.Mockito;
+import org.mockito.Spy;
 
 public class MmsStatsTest {
     // Mocked classes
@@ -53,6 +55,7 @@ public class MmsStatsTest {
     private PersistMmsAtomsStorage mPersistMmsAtomsStorage;
     private TelephonyManager mTelephonyManager;
     private SubscriptionManager mSubscriptionManager;
+    @Spy private MmsStats mSpyMmsStats;
 
     @Before
     public void setUp() {
@@ -79,7 +82,9 @@ public class MmsStatsTest {
         int inactiveSubId = 123;
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, inactiveSubId,
                 mTelephonyManager, null, true);
-        mmsStats.addAtomToStorage(Activity.RESULT_OK);
+        mSpyMmsStats = Mockito.spy(mmsStats);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(inactiveSubId);
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
         verify(mPersistMmsAtomsStorage).addIncomingMms(incomingMmsCaptor.capture());
@@ -97,6 +102,7 @@ public class MmsStatsTest {
         assertThat(incomingMms.getHandledByCarrierApp()).isEqualTo(false);
         assertThat(incomingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(incomingMms.getIsNtn()).isEqualTo(false);
+        assertThat(incomingMms.getIsNbIotNtn()).isEqualTo(false);
         verifyNoMoreInteractions(mPersistMmsAtomsStorage);
     }
 
@@ -107,7 +113,9 @@ public class MmsStatsTest {
         int inactiveSubId = 123;
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, inactiveSubId,
                 mTelephonyManager, null, false);
-        mmsStats.addAtomToStorage(result, retryId, handledByCarrierApp, mMessageId);
+        mSpyMmsStats = Mockito.spy(mmsStats);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(inactiveSubId);
+        mSpyMmsStats.addAtomToStorage(result, retryId, handledByCarrierApp, mMessageId);
 
         ArgumentCaptor<OutgoingMms> outgoingMmsCaptor = ArgumentCaptor.forClass(OutgoingMms.class);
         verify(mPersistMmsAtomsStorage).addOutgoingMms(outgoingMmsCaptor.capture());
@@ -132,6 +140,7 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsFromDefaultApp()).isEqualTo(false);
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
+        assertThat(outgoingMms.getIsNbIotNtn()).isEqualTo(false);
     }
 
     @Test
@@ -151,6 +160,7 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsFromDefaultApp()).isEqualTo(false);
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
+        assertThat(outgoingMms.getIsNbIotNtn()).isEqualTo(false);
     }
 
     @Test
@@ -172,6 +182,7 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsFromDefaultApp()).isEqualTo(false);
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
+        assertThat(outgoingMms.getIsNbIotNtn()).isEqualTo(false);
     }
 
     @Test
@@ -196,6 +207,7 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsFromDefaultApp()).isEqualTo(false);
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
+        assertThat(outgoingMms.getIsNbIotNtn()).isEqualTo(false);
     }
 
     @Test
@@ -204,7 +216,9 @@ public class MmsStatsTest {
         doReturn(serviceState).when(mTelephonyManager).getServiceState();
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
                 mTelephonyManager, null, true);
-        mmsStats.addAtomToStorage(Activity.RESULT_OK);
+        mSpyMmsStats = Mockito.spy(mmsStats);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(1);
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
         verify(mPersistMmsAtomsStorage).addIncomingMms(incomingMmsCaptor.capture());
@@ -221,7 +235,9 @@ public class MmsStatsTest {
 
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, inactiveSubId,
                 mTelephonyManager, null, false);
-        mmsStats.addAtomToStorage(Activity.RESULT_OK);
+        mSpyMmsStats = Mockito.spy(mmsStats);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(inactiveSubId);
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         // getSubscriptionUserHandle should not be called if subID is inactive.
         verify(mSubscriptionManager, never()).getSubscriptionUserHandle(eq(inactiveSubId));
@@ -229,17 +245,15 @@ public class MmsStatsTest {
 
     @Test
     public void testIsNtn_serviceState_notNull() {
-        if (!Flags.carrierEnabledSatelliteFlag()) {
-            return;
-        }
-
         ServiceState serviceState = mock(ServiceState.class);
         doReturn(serviceState).when(mTelephonyManager).getServiceState();
         doReturn(true).when(serviceState).isUsingNonTerrestrialNetwork();
 
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
                 mTelephonyManager, null, true);
-        mmsStats.addAtomToStorage(Activity.RESULT_OK);
+        mSpyMmsStats = Mockito.spy(mmsStats);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(1);
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
         verify(mPersistMmsAtomsStorage).addIncomingMms(incomingMmsCaptor.capture());
@@ -249,10 +263,7 @@ public class MmsStatsTest {
         reset(mPersistMmsAtomsStorage);
         reset(serviceState);
         doReturn(false).when(serviceState).isUsingNonTerrestrialNetwork();
-
-        mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
-                mTelephonyManager, null, true);
-        mmsStats.addAtomToStorage(Activity.RESULT_OK);
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
         verify(mPersistMmsAtomsStorage).addIncomingMms(incomingMmsCaptor.capture());
@@ -262,19 +273,40 @@ public class MmsStatsTest {
 
     @Test
     public void testIsNtn_serviceState_Null() {
-        if (!Flags.carrierEnabledSatelliteFlag()) {
-            return;
-        }
-
         doReturn(null).when(mTelephonyManager).getServiceState();
 
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
                 mTelephonyManager, null, true);
-        mmsStats.addAtomToStorage(Activity.RESULT_OK);
+        mSpyMmsStats = Mockito.spy(mmsStats);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(1);
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
 
         ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
         verify(mPersistMmsAtomsStorage).addIncomingMms(incomingMmsCaptor.capture());
         IncomingMms incomingMms = incomingMmsCaptor.getValue();
         assertThat(incomingMms.getIsNtn()).isEqualTo(false);
     }
+
+    @Test
+    public void testIsNbIotNtn_serviceState_notNull() {
+        MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, 1,
+                mTelephonyManager, null, true);
+        mSpyMmsStats = Mockito.spy(mmsStats);
+        doReturn(true).when(mSpyMmsStats).isNbIotNtn(1);
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
+
+        ArgumentCaptor<IncomingMms> incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
+        verify(mPersistMmsAtomsStorage).addIncomingMms(incomingMmsCaptor.capture());
+        IncomingMms incomingMms = incomingMmsCaptor.getValue();
+        assertThat(incomingMms.getIsNbIotNtn()).isEqualTo(true);
+
+        reset(mPersistMmsAtomsStorage);
+        doReturn(false).when(mSpyMmsStats).isNbIotNtn(1);
+        mSpyMmsStats.addAtomToStorage(Activity.RESULT_OK);
+
+        incomingMmsCaptor = ArgumentCaptor.forClass(IncomingMms.class);
+        verify(mPersistMmsAtomsStorage).addIncomingMms(incomingMmsCaptor.capture());
+        incomingMms = incomingMmsCaptor.getValue();
+        assertThat(incomingMms.getIsNbIotNtn()).isEqualTo(false);
+    }
 }
\ No newline at end of file
```

