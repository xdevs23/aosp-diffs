```diff
diff --git a/src/java/com/android/internal/telephony/satellite/DatagramDispatcher.java b/src/java/com/android/internal/telephony/satellite/DatagramDispatcher.java
index d1d8726ef4..a40275f8ba 100644
--- a/src/java/com/android/internal/telephony/satellite/DatagramDispatcher.java
+++ b/src/java/com/android/internal/telephony/satellite/DatagramDispatcher.java
@@ -82,6 +82,8 @@ public class DatagramDispatcher extends Handler {
     private static final int CMD_SEND_SMS = 8;
     private static final int EVENT_SEND_SMS_DONE = 9;
     private static final int EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT = 10;
+    private static final int CMD_SEND_MT_SMS_POLLING_MESSAGE = 11;
+
     private static final Long TIMEOUT_DATAGRAM_DELAY_IN_DEMO_MODE = TimeUnit.SECONDS.toMillis(10);
     @NonNull private static DatagramDispatcher sInstance;
     @NonNull private final Context mContext;
@@ -426,10 +428,16 @@ public class DatagramDispatcher extends Handler {
             case EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT: {
                 synchronized (mLock) {
                     mIsMtSmsPollingThrottled = false;
-                    if (allowMtSmsPolling()) {
-                        sendMtSmsPollingMessage();
-                    }
                 }
+                if (allowMtSmsPolling()) {
+                    sendMessage(obtainMessage(CMD_SEND_MT_SMS_POLLING_MESSAGE));
+                }
+                break;
+            }
+
+            case CMD_SEND_MT_SMS_POLLING_MESSAGE: {
+                plogd("CMD_SEND_MT_SMS_POLLING_MESSAGE");
+                handleCmdSendMtSmsPollingMessage();
                 break;
             }
 
@@ -521,9 +529,9 @@ public class DatagramDispatcher extends Handler {
             mIsAligned = isAligned;
             plogd("setDeviceAlignedWithSatellite: " + mIsAligned);
             if (isAligned && mIsDemoMode) handleEventSatelliteAligned();
-            if (allowMtSmsPolling()) {
-                sendMtSmsPollingMessage();
-            }
+        }
+        if (allowMtSmsPolling()) {
+            sendMessage(obtainMessage(CMD_SEND_MT_SMS_POLLING_MESSAGE));
         }
     }
 
@@ -845,10 +853,9 @@ public class DatagramDispatcher extends Handler {
                     mShouldPollMtSms = shouldPollMtSms();
                 }
             }
-
-            if (allowMtSmsPolling()) {
-                sendMtSmsPollingMessage();
-            }
+        }
+        if (allowMtSmsPolling()) {
+            sendMessage(obtainMessage(CMD_SEND_MT_SMS_POLLING_MESSAGE));
         }
     }
 
@@ -1325,22 +1332,25 @@ public class DatagramDispatcher extends Handler {
                 && satelliteController.shouldSendSmsToDatagramDispatcher(satellitePhone);
     }
 
-    @GuardedBy("mLock")
-    private void sendMtSmsPollingMessage() {
-        if (!mShouldPollMtSms) {
-            return;
-        }
+    private void handleCmdSendMtSmsPollingMessage() {
+        synchronized (mLock) {
+            if (!mShouldPollMtSms) {
+                plogd("sendMtSmsPollingMessage: mShouldPollMtSms=" + mShouldPollMtSms);
+                return;
+            }
 
-        plogd("sendMtSmsPollingMessage");
-        if (!allowCheckMessageInNotConnected()) {
-            mShouldPollMtSms = false;
-        }
+            plogd("sendMtSmsPollingMessage");
+            if (!allowCheckMessageInNotConnected()) {
+                mShouldPollMtSms = false;
+            }
 
-        for (Entry<Long, PendingRequest> entry : mPendingSmsMap.entrySet()) {
-            PendingRequest pendingRequest = entry.getValue();
-            if (pendingRequest.isMtSmsPolling) {
-                plogd("sendMtSmsPollingMessage: mPendingSmsMap already has the polling message.");
-                return;
+            for (Entry<Long, PendingRequest> entry : mPendingSmsMap.entrySet()) {
+                PendingRequest pendingRequest = entry.getValue();
+                if (pendingRequest.isMtSmsPolling) {
+                    plogd("sendMtSmsPollingMessage: mPendingSmsMap already "
+                            + "has the polling message.");
+                    return;
+                }
             }
         }
 
@@ -1374,17 +1384,20 @@ public class DatagramDispatcher extends Handler {
         removeMessages(EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT);
     }
 
-    @GuardedBy("mLock")
     private boolean allowMtSmsPolling() {
         if (!mFeatureFlags.carrierRoamingNbIotNtn()) return false;
 
         if (mIsMtSmsPollingThrottled) return false;
 
-        if (!mIsAligned) return false;
+        boolean isModemStateConnectedOrTransferring;
+        synchronized (mLock) {
+            if (!mIsAligned) return false;
+
+            isModemStateConnectedOrTransferring =
+                    mModemState == SATELLITE_MODEM_STATE_CONNECTED
+                            || mModemState == SATELLITE_MODEM_STATE_DATAGRAM_TRANSFERRING;
+        }
 
-        boolean isModemStateConnectedOrTransferring =
-                mModemState == SATELLITE_MODEM_STATE_CONNECTED
-                        || mModemState == SATELLITE_MODEM_STATE_DATAGRAM_TRANSFERRING;
         if (!isModemStateConnectedOrTransferring && !allowCheckMessageInNotConnected()) {
             plogd("EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT:"
                     + " allow_check_message_in_not_connected is disabled");
diff --git a/src/java/com/android/internal/telephony/satellite/SatelliteController.java b/src/java/com/android/internal/telephony/satellite/SatelliteController.java
index d455863342..0f922c293a 100644
--- a/src/java/com/android/internal/telephony/satellite/SatelliteController.java
+++ b/src/java/com/android/internal/telephony/satellite/SatelliteController.java
@@ -614,7 +614,6 @@ public class SatelliteController extends Handler {
     private List<SatelliteSubscriberProvisionStatus> mLastEvaluatedSubscriberProvisionStatus =
             new ArrayList<>();
     // The ID of the satellite subscription that has highest priority and is provisioned.
-    @GuardedBy("mSatelliteTokenProvisionedLock")
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     protected int mSelectedSatelliteSubId = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
     // The last ICC ID that framework configured to modem.
@@ -7332,6 +7331,7 @@ public class SatelliteController extends Handler {
      */
     public void requestSatelliteSubscriberProvisionStatus(@NonNull ResultReceiver result) {
         if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            logd("requestSatelliteSubscriberProvisionStatus: carrierRoamingNbIotNtn is disabled");
             result.send(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, null);
             return;
         }
@@ -7397,10 +7397,8 @@ public class SatelliteController extends Handler {
     }
 
     public int getSelectedSatelliteSubId() {
-        synchronized (mSatelliteTokenProvisionedLock) {
-            plogd("getSelectedSatelliteSubId: subId=" + mSelectedSatelliteSubId);
-            return mSelectedSatelliteSubId;
-        }
+        plogd("getSelectedSatelliteSubId: subId=" + mSelectedSatelliteSubId);
+        return mSelectedSatelliteSubId;
     }
 
     /**
@@ -7762,15 +7760,13 @@ public class SatelliteController extends Handler {
 
     /** Return the carrier ID of the binding satellite subscription. */
     public int getSatelliteCarrierId() {
-        synchronized (mSatelliteTokenProvisionedLock) {
-            SubscriptionInfo subInfo = mSubscriptionManagerService.getSubscriptionInfo(
-                    mSelectedSatelliteSubId);
-            if (subInfo == null) {
-                logd("getSatelliteCarrierId: returns UNKNOWN_CARRIER_ID");
-                return UNKNOWN_CARRIER_ID;
-            }
-            return subInfo.getCarrierId();
+        SubscriptionInfo subInfo = mSubscriptionManagerService.getSubscriptionInfo(
+            mSelectedSatelliteSubId);
+        if (subInfo == null) {
+            logd("getSatelliteCarrierId: returns UNKNOWN_CARRIER_ID");
+            return UNKNOWN_CARRIER_ID;
         }
+        return subInfo.getCarrierId();
     }
 
     /**
diff --git a/tests/telephonytests/src/com/android/internal/telephony/satellite/DatagramDispatcherTest.java b/tests/telephonytests/src/com/android/internal/telephony/satellite/DatagramDispatcherTest.java
index b4de67240c..b6828df79e 100644
--- a/tests/telephonytests/src/com/android/internal/telephony/satellite/DatagramDispatcherTest.java
+++ b/tests/telephonytests/src/com/android/internal/telephony/satellite/DatagramDispatcherTest.java
@@ -1157,6 +1157,7 @@ public class DatagramDispatcherTest extends TelephonyTest {
         mDatagramDispatcherUT.handleMessage(
                 mDatagramDispatcherUT.obtainMessage(10 /*EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT*/,
                         new AsyncResult(null, null, null)));
+        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
    }
@@ -1205,6 +1206,7 @@ public class DatagramDispatcherTest extends TelephonyTest {
                 R.bool.config_satellite_allow_check_message_in_not_connected, true);
 
         mDatagramDispatcherUT.setDeviceAlignedWithSatellite(true);
+        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
@@ -1231,6 +1233,7 @@ public class DatagramDispatcherTest extends TelephonyTest {
 
         mDatagramDispatcherUT.onSatelliteModemStateChanged(
                 SatelliteManager.SATELLITE_MODEM_STATE_NOT_CONNECTED);
+        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
@@ -1243,6 +1246,7 @@ public class DatagramDispatcherTest extends TelephonyTest {
 
         mDatagramDispatcherUT.onSatelliteModemStateChanged(
                 SatelliteManager.SATELLITE_MODEM_STATE_CONNECTED);
+        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
@@ -1255,6 +1259,7 @@ public class DatagramDispatcherTest extends TelephonyTest {
 
         mDatagramDispatcherUT.onSatelliteModemStateChanged(
                 SatelliteManager.SATELLITE_MODEM_STATE_DATAGRAM_TRANSFERRING);
+        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
@@ -1285,6 +1290,7 @@ public class DatagramDispatcherTest extends TelephonyTest {
 
         mDatagramDispatcherUT.onSatelliteModemStateChanged(
                 SatelliteManager.SATELLITE_MODEM_STATE_CONNECTED);
+        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
```

