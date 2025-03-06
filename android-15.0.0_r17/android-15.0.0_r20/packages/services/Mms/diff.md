```diff
diff --git a/src/com/android/mms/service/DownloadRequest.java b/src/com/android/mms/service/DownloadRequest.java
index ebbeb68..461cb64 100644
--- a/src/com/android/mms/service/DownloadRequest.java
+++ b/src/com/android/mms/service/DownloadRequest.java
@@ -356,8 +356,12 @@ public class DownloadRequest extends MmsRequest {
             mCarrierDownloadManager.disposeConnection(mContext);
 
             if (!maybeFallbackToRegularDelivery(result)) {
-                processResult(mContext, toSmsManagerResult(result), null/* response */,
-                        0/* httpStatusCode */, /* handledByCarrierApp= */ true);
+                processResult(
+                        mContext,
+                        toSmsManagerResultForInboundMms(result),
+                        null /* response */,
+                        0 /* httpStatusCode */,
+                        /* handledByCarrierApp= */ true);
             }
         }
     }
diff --git a/src/com/android/mms/service/MmsRequest.java b/src/com/android/mms/service/MmsRequest.java
index 40dde58..8b68d48 100644
--- a/src/com/android/mms/service/MmsRequest.java
+++ b/src/com/android/mms/service/MmsRequest.java
@@ -486,6 +486,95 @@ public abstract class MmsRequest {
         }
     }
 
+    /**
+     * Converts from {@code carrierMessagingAppResult} to a platform result code for outbound MMS
+     * requests.
+     */
+    protected static int toSmsManagerResultForOutboundMms(int carrierMessagingAppResult) {
+        if (Flags.temporaryFailuresInCarrierMessagingService()) {
+            switch (carrierMessagingAppResult) {
+                case CarrierMessagingService.SEND_STATUS_OK:
+                    // TODO: b/378931437 - Update to an SmsManager result code when one is
+                    // available.
+                    return Activity.RESULT_OK;
+                case CarrierMessagingService.SEND_STATUS_RETRY_ON_CARRIER_NETWORK, // fall through
+                    CarrierMessagingService.SEND_STATUS_MMS_ERROR_RETRY:
+                    return SmsManager.MMS_ERROR_RETRY;
+                case CarrierMessagingService.SEND_STATUS_ERROR: // fall through
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_UNSPECIFIED:
+                    return SmsManager.MMS_ERROR_UNSPECIFIED;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_INVALID_APN:
+                    return SmsManager.MMS_ERROR_INVALID_APN;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_UNABLE_CONNECT_MMS:
+                    return SmsManager.MMS_ERROR_UNABLE_CONNECT_MMS;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_HTTP_FAILURE:
+                    return SmsManager.MMS_ERROR_HTTP_FAILURE;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_IO_ERROR:
+                    return SmsManager.MMS_ERROR_IO_ERROR;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_CONFIGURATION_ERROR:
+                    return SmsManager.MMS_ERROR_CONFIGURATION_ERROR;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_NO_DATA_NETWORK:
+                    return SmsManager.MMS_ERROR_NO_DATA_NETWORK;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_INVALID_SUBSCRIPTION_ID:
+                    return SmsManager.MMS_ERROR_INVALID_SUBSCRIPTION_ID;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_INACTIVE_SUBSCRIPTION:
+                    return SmsManager.MMS_ERROR_INACTIVE_SUBSCRIPTION;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_DATA_DISABLED:
+                    return SmsManager.MMS_ERROR_DATA_DISABLED;
+                case CarrierMessagingService.SEND_STATUS_MMS_ERROR_MMS_DISABLED_BY_CARRIER:
+                    return SmsManager.MMS_ERROR_MMS_DISABLED_BY_CARRIER;
+                default:
+                    return SmsManager.MMS_ERROR_UNSPECIFIED;
+            }
+        } else {
+            return toSmsManagerResult(carrierMessagingAppResult);
+        }
+    }
+
+    /**
+     * Converts from {@code carrierMessagingAppResult} to a platform result code for download MMS
+     * requests.
+     */
+    protected static int toSmsManagerResultForInboundMms(int carrierMessagingAppResult) {
+        if (Flags.temporaryFailuresInCarrierMessagingService()) {
+            switch (carrierMessagingAppResult) {
+                case CarrierMessagingService.DOWNLOAD_STATUS_OK:
+                    return Activity.RESULT_OK;
+                case CarrierMessagingService.DOWNLOAD_STATUS_RETRY_ON_CARRIER_NETWORK:
+                    return SmsManager.MMS_ERROR_RETRY;
+                case CarrierMessagingService.DOWNLOAD_STATUS_ERROR: // fall through
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_UNSPECIFIED:
+                    return SmsManager.MMS_ERROR_UNSPECIFIED;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_INVALID_APN:
+                    return SmsManager.MMS_ERROR_INVALID_APN;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_UNABLE_CONNECT_MMS:
+                    return SmsManager.MMS_ERROR_UNABLE_CONNECT_MMS;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_HTTP_FAILURE:
+                    return SmsManager.MMS_ERROR_HTTP_FAILURE;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_IO_ERROR:
+                    return SmsManager.MMS_ERROR_IO_ERROR;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_RETRY:
+                    return SmsManager.MMS_ERROR_RETRY;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_CONFIGURATION_ERROR:
+                    return SmsManager.MMS_ERROR_CONFIGURATION_ERROR;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_NO_DATA_NETWORK:
+                    return SmsManager.MMS_ERROR_NO_DATA_NETWORK;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_INVALID_SUBSCRIPTION_ID:
+                    return SmsManager.MMS_ERROR_INVALID_SUBSCRIPTION_ID;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_INACTIVE_SUBSCRIPTION:
+                    return SmsManager.MMS_ERROR_INACTIVE_SUBSCRIPTION;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_DATA_DISABLED:
+                    return SmsManager.MMS_ERROR_DATA_DISABLED;
+                case CarrierMessagingService.DOWNLOAD_STATUS_MMS_ERROR_MMS_DISABLED_BY_CARRIER:
+                    return SmsManager.MMS_ERROR_MMS_DISABLED_BY_CARRIER;
+                default:
+                    return SmsManager.MMS_ERROR_UNSPECIFIED;
+            }
+        } else {
+            return toSmsManagerResult(carrierMessagingAppResult);
+        }
+    }
+
     @Override
     public String toString() {
         return getClass().getSimpleName() + '@' + Integer.toHexString(hashCode())
diff --git a/src/com/android/mms/service/SendRequest.java b/src/com/android/mms/service/SendRequest.java
index 19ddeb8..dd44f2c 100644
--- a/src/com/android/mms/service/SendRequest.java
+++ b/src/com/android/mms/service/SendRequest.java
@@ -493,8 +493,12 @@ public class SendRequest extends MmsRequest {
             mCarrierSendManager.disposeConnection(mContext);
 
             if (!maybeFallbackToRegularDelivery(result)) {
-                processResult(mContext, toSmsManagerResult(result), sendConfPdu,
-                        0/* httpStatusCode */, /* handledByCarrierApp= */ true);
+                processResult(
+                        mContext,
+                        toSmsManagerResultForOutboundMms(result),
+                        sendConfPdu,
+                        0 /* httpStatusCode */,
+                        /* handledByCarrierApp= */ true);
             }
         }
 
diff --git a/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java b/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
index 089b3d7..3350e53 100644
--- a/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
+++ b/tests/unittests/src/com/android/mms/service/metrics/MmsStatsTest.java
@@ -17,6 +17,8 @@
 package com.android.mms.service.metrics;
 
 import static com.android.mms.MmsStatsLog.INCOMING_MMS__RESULT__MMS_RESULT_SUCCESS;
+import static com.android.mms.MmsStatsLog.OUTGOING_MMS__RESULT__MMS_RESULT_ERROR_NO_DATA_NETWORK;
+import static com.android.mms.MmsStatsLog.OUTGOING_MMS__RESULT__MMS_RESULT_ERROR_UNSPECIFIED;
 import static com.android.mms.MmsStatsLog.OUTGOING_MMS__RESULT__MMS_RESULT_SUCCESS;
 
 import static com.google.common.truth.Truth.assertThat;
@@ -32,6 +34,7 @@ import static org.mockito.Mockito.verifyNoMoreInteractions;
 import android.app.Activity;
 import android.content.Context;
 import android.telephony.ServiceState;
+import android.telephony.SmsManager;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
 
@@ -97,18 +100,24 @@ public class MmsStatsTest {
         verifyNoMoreInteractions(mPersistMmsAtomsStorage);
     }
 
-    @Test
-    public void addAtomToStorage_outgoingMms_default() {
+    private OutgoingMms addAtomToStorage_outgoingMms(
+            int result, int retryId, boolean handledByCarrierApp, long mMessageId) {
         doReturn(null).when(mTelephonyManager).getServiceState();
         doReturn(TelephonyManager.UNKNOWN_CARRIER_ID).when(mTelephonyManager).getSimCarrierId();
         int inactiveSubId = 123;
         MmsStats mmsStats = new MmsStats(mContext, mPersistMmsAtomsStorage, inactiveSubId,
                 mTelephonyManager, null, false);
-        mmsStats.addAtomToStorage(Activity.RESULT_OK);
+        mmsStats.addAtomToStorage(result, retryId, handledByCarrierApp, mMessageId);
 
         ArgumentCaptor<OutgoingMms> outgoingMmsCaptor = ArgumentCaptor.forClass(OutgoingMms.class);
         verify(mPersistMmsAtomsStorage).addOutgoingMms(outgoingMmsCaptor.capture());
-        OutgoingMms outgoingMms = outgoingMmsCaptor.getValue();
+        verifyNoMoreInteractions(mPersistMmsAtomsStorage);
+        return outgoingMmsCaptor.getValue();
+    }
+
+    @Test
+    public void addAtomToStorage_outgoingMms_default() {
+        OutgoingMms outgoingMms = addAtomToStorage_outgoingMms(Activity.RESULT_OK, 0, false, 0);
         assertThat(outgoingMms.getRat()).isEqualTo(TelephonyManager.NETWORK_TYPE_UNKNOWN);
         assertThat(outgoingMms.getResult()).isEqualTo(OUTGOING_MMS__RESULT__MMS_RESULT_SUCCESS);
         assertThat(outgoingMms.getRoaming()).isEqualTo(ServiceState.ROAMING_TYPE_NOT_ROAMING);
@@ -123,7 +132,70 @@ public class MmsStatsTest {
         assertThat(outgoingMms.getIsFromDefaultApp()).isEqualTo(false);
         assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
         assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
-        verifyNoMoreInteractions(mPersistMmsAtomsStorage);
+    }
+
+    @Test
+    public void addAtomToStorage_outgoingMms_handledByCarrierApp_Succeeded() {
+        OutgoingMms outgoingMms = addAtomToStorage_outgoingMms(Activity.RESULT_OK, 0, true, 0);
+        assertThat(outgoingMms.getRat()).isEqualTo(TelephonyManager.NETWORK_TYPE_UNKNOWN);
+        assertThat(outgoingMms.getResult()).isEqualTo(OUTGOING_MMS__RESULT__MMS_RESULT_SUCCESS);
+        assertThat(outgoingMms.getRoaming()).isEqualTo(ServiceState.ROAMING_TYPE_NOT_ROAMING);
+        assertThat(outgoingMms.getSimSlotIndex())
+                .isEqualTo(SubscriptionManager.INVALID_SIM_SLOT_INDEX);
+        assertThat(outgoingMms.getIsMultiSim()).isEqualTo(false);
+        assertThat(outgoingMms.getIsEsim()).isEqualTo(false);
+        assertThat(outgoingMms.getCarrierId()).isEqualTo(TelephonyManager.UNKNOWN_CARRIER_ID);
+        assertThat(outgoingMms.getMmsCount()).isEqualTo(1);
+        assertThat(outgoingMms.getRetryId()).isEqualTo(0);
+        assertThat(outgoingMms.getHandledByCarrierApp()).isEqualTo(true);
+        assertThat(outgoingMms.getIsFromDefaultApp()).isEqualTo(false);
+        assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
+        assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
+    }
+
+    @Test
+    public void addAtomToStorage_outgoingMms_handledByCarrierApp_FailedWithoutReason() {
+        OutgoingMms outgoingMms =
+                addAtomToStorage_outgoingMms(SmsManager.MMS_ERROR_UNSPECIFIED, 0, true, 0);
+        assertThat(outgoingMms.getRat()).isEqualTo(TelephonyManager.NETWORK_TYPE_UNKNOWN);
+        assertThat(outgoingMms.getResult())
+                .isEqualTo(OUTGOING_MMS__RESULT__MMS_RESULT_ERROR_UNSPECIFIED);
+        assertThat(outgoingMms.getRoaming()).isEqualTo(ServiceState.ROAMING_TYPE_NOT_ROAMING);
+        assertThat(outgoingMms.getSimSlotIndex())
+                .isEqualTo(SubscriptionManager.INVALID_SIM_SLOT_INDEX);
+        assertThat(outgoingMms.getIsMultiSim()).isEqualTo(false);
+        assertThat(outgoingMms.getIsEsim()).isEqualTo(false);
+        assertThat(outgoingMms.getCarrierId()).isEqualTo(TelephonyManager.UNKNOWN_CARRIER_ID);
+        assertThat(outgoingMms.getMmsCount()).isEqualTo(1);
+        assertThat(outgoingMms.getRetryId()).isEqualTo(0);
+        assertThat(outgoingMms.getHandledByCarrierApp()).isEqualTo(true);
+        assertThat(outgoingMms.getIsFromDefaultApp()).isEqualTo(false);
+        assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
+        assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
+    }
+
+    @Test
+    public void addAtomToStorage_outgoingMms_handledByCarrierApp_FailedWithReason() {
+        if (!Flags.temporaryFailuresInCarrierMessagingService()) {
+            return;
+        }
+        OutgoingMms outgoingMms =
+                addAtomToStorage_outgoingMms(SmsManager.MMS_ERROR_NO_DATA_NETWORK, 0, true, 0);
+        assertThat(outgoingMms.getRat()).isEqualTo(TelephonyManager.NETWORK_TYPE_UNKNOWN);
+        assertThat(outgoingMms.getResult())
+                .isEqualTo(OUTGOING_MMS__RESULT__MMS_RESULT_ERROR_NO_DATA_NETWORK);
+        assertThat(outgoingMms.getRoaming()).isEqualTo(ServiceState.ROAMING_TYPE_NOT_ROAMING);
+        assertThat(outgoingMms.getSimSlotIndex())
+                .isEqualTo(SubscriptionManager.INVALID_SIM_SLOT_INDEX);
+        assertThat(outgoingMms.getIsMultiSim()).isEqualTo(false);
+        assertThat(outgoingMms.getIsEsim()).isEqualTo(false);
+        assertThat(outgoingMms.getCarrierId()).isEqualTo(TelephonyManager.UNKNOWN_CARRIER_ID);
+        assertThat(outgoingMms.getMmsCount()).isEqualTo(1);
+        assertThat(outgoingMms.getRetryId()).isEqualTo(0);
+        assertThat(outgoingMms.getHandledByCarrierApp()).isEqualTo(true);
+        assertThat(outgoingMms.getIsFromDefaultApp()).isEqualTo(false);
+        assertThat(outgoingMms.getIsManagedProfile()).isEqualTo(false);
+        assertThat(outgoingMms.getIsNtn()).isEqualTo(false);
     }
 
     @Test
```

