```diff
diff --git a/src/java/com/android/internal/telephony/data/AutoDataSwitchController.java b/src/java/com/android/internal/telephony/data/AutoDataSwitchController.java
index 7486b6169f..7131583852 100644
--- a/src/java/com/android/internal/telephony/data/AutoDataSwitchController.java
+++ b/src/java/com/android/internal/telephony/data/AutoDataSwitchController.java
@@ -30,6 +30,7 @@ import android.app.PendingIntent;
 import android.content.Context;
 import android.content.Intent;
 import android.net.NetworkCapabilities;
+import android.net.NetworkRequest;
 import android.os.AsyncResult;
 import android.os.Bundle;
 import android.os.Handler;
@@ -44,6 +45,7 @@ import android.telephony.ServiceState;
 import android.telephony.SignalStrength;
 import android.telephony.SubscriptionInfo;
 import android.telephony.TelephonyDisplayInfo;
+import android.util.ArrayMap;
 import android.util.IndentingPrintWriter;
 import android.util.LocalLog;
 
@@ -100,6 +102,38 @@ public class AutoDataSwitchController extends Handler {
                     EVALUATION_REASON_VOICE_CALL_END})
     public @interface AutoDataSwitchEvaluationReason {}
 
+    /**
+     * Defines the switch type for considering a subscription as out of service before switching
+     * data, in milliseconds.
+     * If one SIM has service while the other is out of service for this duration,
+     * data will be switched to the SIM with service.
+     */
+    private static final int STABILITY_CHECK_AVAILABILITY_SWITCH = 0;
+    /**
+     * Defines the switch type for considering the RAT and signal strength advantage of a
+     * subscription to be stable before switching data, in milliseconds.
+     * Each RAT and signal strength is assigned a score. If one SIM's score is higher
+     * than the other SIM's score for this duration, data will be switched to that SIM.
+     */
+    private static final int STABILITY_CHECK_PERFORMANCE_SWITCH = 1;
+    /**
+     * Defines the switch type for switching data back to the default SIM when both SIMs are out of
+     * service, in milliseconds.
+     * If the current data is on the backup SIM and both SIMs remain out of service,
+     * data will be switched back to the default SIM.
+     */
+    private static final int STABILITY_CHECK_AVAILABILITY_SWITCH_BACK = 2;
+    @Retention(RetentionPolicy.SOURCE)
+    @IntDef(prefix = "STABILITY_CHECK_",
+            value = {STABILITY_CHECK_AVAILABILITY_SWITCH,
+                    STABILITY_CHECK_PERFORMANCE_SWITCH,
+                    STABILITY_CHECK_AVAILABILITY_SWITCH_BACK,
+            })
+    public @interface PreSwitchStabilityCheckType {}
+
+    /** stability check type to timer in milliseconds. */
+    private static final Map<Integer, Long> STABILITY_CHECK_TIMER_MAP = new ArrayMap<>();
+
     private static final String LOG_TAG = "ADSC";
 
     /** Event for service state changed. */
@@ -160,11 +194,22 @@ public class AutoDataSwitchController extends Handler {
     /**
      * Event extras for checking environment stability.
      * @param targetPhoneId The target phone Id to switch to when the stability check pass.
-     * @param isForPerformance Whether the switch is due to RAT/signal strength performance.
+     * @param switchType Whether the switch is due to OOS, RAT/signal strength performance, or
+     *                   switch back.
      * @param needValidation Whether ping test needs to pass.
      */
-    private record StabilityEventExtra(int targetPhoneId, boolean isForPerformance,
-                               boolean needValidation) {}
+    private record StabilityEventExtra(int targetPhoneId,
+                                       @PreSwitchStabilityCheckType int switchType,
+                                       boolean needValidation) {
+        @Override
+        public String toString() {
+            return "StabilityEventExtra{"
+                    + "targetPhoneId=" + targetPhoneId
+                    + ", switchType=" + switchTypeToString(switchType)
+                    + ", needValidation=" + needValidation
+                    + "}";
+        }
+    }
 
     /**
      * Event extras for evaluating switch environment.
@@ -174,18 +219,6 @@ public class AutoDataSwitchController extends Handler {
     private boolean mDefaultNetworkIsOnNonCellular = false;
     /** {@code true} if we've displayed the notification the first time auto switch occurs **/
     private boolean mDisplayedNotification = false;
-    /**
-     * Configurable time threshold in ms to define an internet connection status to be stable(e.g.
-     * out of service, in service, wifi is the default active network.etc), while -1 indicates auto
-     * switch feature disabled.
-     */
-    private long mAutoDataSwitchAvailabilityStabilityTimeThreshold = -1;
-    /**
-     * Configurable time threshold in ms to define an internet connection performance status to be
-     * stable (e.g. LTE + 4 signal strength, UMTS + 2 signal strength), while -1 indicates
-     * auto switch feature based on RAT/SS is disabled.
-     */
-    private long mAutoDataSwitchPerformanceStabilityTimeThreshold = -1;
     /**
      * The tolerated gap of score for auto data switch decision, larger than which the device will
      * switch to the SIM with higher score. If 0, the device will always switch to the higher score
@@ -462,10 +495,14 @@ public class AutoDataSwitchController extends Handler {
         mScoreTolerance =  dataConfig.getAutoDataSwitchScoreTolerance();
         mRequirePingTestBeforeSwitch = dataConfig.isPingTestBeforeAutoDataSwitchRequired();
         mAllowNddsRoaming = dataConfig.doesAutoDataSwitchAllowRoaming();
-        mAutoDataSwitchAvailabilityStabilityTimeThreshold =
-                dataConfig.getAutoDataSwitchAvailabilityStabilityTimeThreshold();
-        mAutoDataSwitchPerformanceStabilityTimeThreshold =
-                dataConfig.getAutoDataSwitchPerformanceStabilityTimeThreshold();
+        STABILITY_CHECK_TIMER_MAP.put(STABILITY_CHECK_AVAILABILITY_SWITCH,
+                dataConfig.getAutoDataSwitchAvailabilityStabilityTimeThreshold());
+        STABILITY_CHECK_TIMER_MAP.put(STABILITY_CHECK_PERFORMANCE_SWITCH,
+                dataConfig.getAutoDataSwitchPerformanceStabilityTimeThreshold());
+        STABILITY_CHECK_TIMER_MAP.put(STABILITY_CHECK_AVAILABILITY_SWITCH_BACK,
+                dataConfig.getAutoDataSwitchAvailabilitySwitchbackStabilityTimeThreshold() >= 0
+                        ? dataConfig.getAutoDataSwitchAvailabilitySwitchbackStabilityTimeThreshold()
+                        : dataConfig.getAutoDataSwitchAvailabilityStabilityTimeThreshold());
         mAutoDataSwitchValidationMaxRetry =
                 dataConfig.getAutoDataSwitchValidationMaxRetry();
     }
@@ -628,7 +665,7 @@ public class AutoDataSwitchController extends Handler {
      */
     public void evaluateAutoDataSwitch(@AutoDataSwitchEvaluationReason int reason) {
         long delayMs = reason == EVALUATION_REASON_RETRY_VALIDATION
-                ? mAutoDataSwitchAvailabilityStabilityTimeThreshold
+                ? STABILITY_CHECK_TIMER_MAP.get(STABILITY_CHECK_AVAILABILITY_SWITCH)
                 << mAutoSwitchValidationFailedCount
                 : 0;
         if (!mScheduledEventsToExtras.containsKey(EVENT_EVALUATE_AUTO_SWITCH)) {
@@ -645,7 +682,7 @@ public class AutoDataSwitchController extends Handler {
      */
     private void onEvaluateAutoDataSwitch(@AutoDataSwitchEvaluationReason int reason) {
         // auto data switch feature is disabled.
-        if (mAutoDataSwitchAvailabilityStabilityTimeThreshold < 0) return;
+        if (STABILITY_CHECK_TIMER_MAP.get(STABILITY_CHECK_AVAILABILITY_SWITCH) < 0) return;
         int defaultDataSubId = mSubscriptionManagerService.getDefaultDataSubId();
         // check is valid DSDS
         if (mSubscriptionManagerService.getActiveSubIdList(true).length < 2) return;
@@ -669,7 +706,7 @@ public class AutoDataSwitchController extends Handler {
             log(debugMessage.toString());
             if (res.targetPhoneId != INVALID_PHONE_INDEX) {
                 mSelectedTargetPhoneId = res.targetPhoneId;
-                startStabilityCheck(res.targetPhoneId, res.isForPerformance, res.needValidation);
+                startStabilityCheck(res.targetPhoneId, res.switchType, res.needValidation);
             } else {
                 cancelAnyPendingSwitch();
             }
@@ -690,8 +727,7 @@ public class AutoDataSwitchController extends Handler {
                     log(debugMessage.append(
                             ", immediately back to default as user turns off default").toString());
                     return;
-                } else if (!(internetEvaluation = backupDataPhone.getDataNetworkController()
-                        .getInternetEvaluation(false/*ignoreExistingNetworks*/))
+                } else if (!(internetEvaluation = getInternetEvaluation(backupDataPhone))
                         .isSubsetOf(DataEvaluation.DataDisallowedReason.NOT_IN_SERVICE)) {
                     mPhoneSwitcherCallback.onRequireImmediatelySwitchToPhone(
                             DEFAULT_PHONE_INDEX, EVALUATION_REASON_DATA_SETTINGS_CHANGED);
@@ -711,7 +747,7 @@ public class AutoDataSwitchController extends Handler {
             }
 
             boolean backToDefault = false;
-            boolean isForPerformance = false;
+            int switchType = STABILITY_CHECK_AVAILABILITY_SWITCH;
             boolean needValidation = true;
 
             if (isNddsRoamingEnabled()) {
@@ -755,7 +791,7 @@ public class AutoDataSwitchController extends Handler {
                                             .append(defaultScore).append(" versus current ")
                                             .append(currentScore);
                                     backToDefault = true;
-                                    isForPerformance = true;
+                                    switchType = STABILITY_CHECK_PERFORMANCE_SWITCH;
                                     needValidation = mRequirePingTestBeforeSwitch;
                                 }
                             } else {
@@ -767,6 +803,7 @@ public class AutoDataSwitchController extends Handler {
                         } else {
                             debugMessage.append(", back to default as both phones are unusable.");
                             backToDefault = true;
+                            switchType = STABILITY_CHECK_AVAILABILITY_SWITCH_BACK;
                             needValidation = false;
                         }
                     }
@@ -790,7 +827,7 @@ public class AutoDataSwitchController extends Handler {
                                 .append(defaultScore).append(" versus current ")
                                 .append(currentScore);
                         backToDefault = true;
-                        isForPerformance = true;
+                        switchType = STABILITY_CHECK_PERFORMANCE_SWITCH;
                         needValidation = mRequirePingTestBeforeSwitch;
                     }
                 } else if (isInService(mPhonesSignalStatus[defaultDataPhoneId].mDataRegState)) {
@@ -803,7 +840,7 @@ public class AutoDataSwitchController extends Handler {
             if (backToDefault) {
                 log(debugMessage.toString());
                 mSelectedTargetPhoneId = defaultDataPhoneId;
-                startStabilityCheck(DEFAULT_PHONE_INDEX, isForPerformance, needValidation);
+                startStabilityCheck(DEFAULT_PHONE_INDEX, switchType, needValidation);
             } else {
                 // cancel any previous attempts of switching back to default phone
                 cancelAnyPendingSwitch();
@@ -820,9 +857,9 @@ public class AutoDataSwitchController extends Handler {
     @NonNull private StabilityEventExtra evaluateAnyCandidateToUse(int defaultPhoneId,
             @NonNull StringBuilder debugMessage) {
         Phone defaultDataPhone = PhoneFactory.getPhone(defaultPhoneId);
-        boolean isForPerformance = false;
+        int switchType = STABILITY_CHECK_AVAILABILITY_SWITCH;
         StabilityEventExtra invalidResult = new StabilityEventExtra(INVALID_PHONE_INDEX,
-                isForPerformance, mRequirePingTestBeforeSwitch);
+                switchType, mRequirePingTestBeforeSwitch);
 
         if (defaultDataPhone == null) {
             debugMessage.append(", no candidate as no sim loaded");
@@ -882,7 +919,7 @@ public class AutoDataSwitchController extends Handler {
                         debugMessage.append(" with ").append(defaultScore)
                                 .append(" versus candidate higher score ").append(candidateScore);
                         secondaryDataPhone = PhoneFactory.getPhone(phoneId);
-                        isForPerformance = true;
+                        switchType = STABILITY_CHECK_PERFORMANCE_SWITCH;
                     } else {
                         debugMessage.append(", candidate's score ").append(candidateScore)
                                 .append(" doesn't justify the switch given the current ")
@@ -903,7 +940,7 @@ public class AutoDataSwitchController extends Handler {
                             debugMessage.append(" with higher score ").append(candidateScore)
                                     .append(" versus current ").append(defaultScore);
                             secondaryDataPhone = PhoneFactory.getPhone(phoneId);
-                            isForPerformance = true;
+                            switchType = STABILITY_CHECK_PERFORMANCE_SWITCH;
                         } else {
                             debugMessage.append(", but its score ").append(candidateScore)
                                     .append(" doesn't meet the bar to switch given the current ")
@@ -917,15 +954,14 @@ public class AutoDataSwitchController extends Handler {
             }
 
             if (secondaryDataPhone != null) {
+                DataEvaluation evaluation = getInternetEvaluation(secondaryDataPhone);
                 // check internet data is allowed on the candidate
-                DataEvaluation internetEvaluation = secondaryDataPhone.getDataNetworkController()
-                        .getInternetEvaluation(false/*ignoreExistingNetworks*/);
-                if (!internetEvaluation.containsDisallowedReasons()) {
+                if (!evaluation.containsDisallowedReasons()) {
                     return new StabilityEventExtra(phoneId,
-                            isForPerformance, mRequirePingTestBeforeSwitch);
+                            switchType, mRequirePingTestBeforeSwitch);
                 } else {
                     debugMessage.append(", but candidate's data is not allowed ")
-                            .append(internetEvaluation);
+                            .append(evaluation);
                 }
             }
         }
@@ -933,11 +969,32 @@ public class AutoDataSwitchController extends Handler {
         return invalidResult;
     }
 
+    /**
+     * Get internet evaluation base on phone's satellite/terrestrial env.
+     * @param phone the target phone
+     * @return internet evaluation.
+     */
+    @NonNull
+    private DataEvaluation getInternetEvaluation(@NonNull Phone phone) {
+        NetworkRequest.Builder reqBuilder = new NetworkRequest.Builder()
+                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
+
+        if (phone.getServiceState().isUsingNonTerrestrialNetwork()) {
+            // When satellite, RCS requests are restricted.
+            reqBuilder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
+        }
+
+        return phone.getDataNetworkController().evaluateNetworkRequest(
+                new TelephonyNetworkRequest(reqBuilder.build(), phone, sFeatureFlags),
+                DataEvaluation.DataEvaluationReason.EXTERNAL_QUERY);
+    }
+
     /**
      * @return {@code true} If the feature of switching base on RAT and signal strength is enabled.
      */
     private boolean isRatSignalStrengthBasedSwitchEnabled() {
-        return mScoreTolerance >= 0 && mAutoDataSwitchPerformanceStabilityTimeThreshold >= 0;
+        return mScoreTolerance >= 0
+                && STABILITY_CHECK_TIMER_MAP.get(STABILITY_CHECK_PERFORMANCE_SWITCH) >= 0;
     }
 
     /**
@@ -950,29 +1007,27 @@ public class AutoDataSwitchController extends Handler {
     /**
      * Called when the current environment suits auto data switch.
      * Start pre-switch validation if the current environment suits auto data switch for
-     * {@link #mAutoDataSwitchAvailabilityStabilityTimeThreshold} MS.
+     * {@link #STABILITY_CHECK_TIMER_MAP} MS.
      * @param targetPhoneId the target phone Id.
-     * @param isForPerformance {@code true} entails longer stability check.
+     * @param switchType {@code true} determines stability check timer.
      * @param needValidation {@code true} if validation is needed.
      */
-    private void startStabilityCheck(int targetPhoneId, boolean isForPerformance,
+    private void startStabilityCheck(int targetPhoneId, @PreSwitchStabilityCheckType int switchType,
             boolean needValidation) {
         StabilityEventExtra eventExtras = (StabilityEventExtra)
                 mScheduledEventsToExtras.getOrDefault(EVENT_STABILITY_CHECK_PASSED,
-                        new StabilityEventExtra(INVALID_PHONE_INDEX, false /*need validation*/,
+                        new StabilityEventExtra(INVALID_PHONE_INDEX, -1 /*invalid switch type*/,
                                 false /*isForPerformance*/));
         long delayMs = -1;
         // Check if already scheduled one with that combination of extras.
         if (eventExtras.targetPhoneId != targetPhoneId
                 || eventExtras.needValidation != needValidation
-                || eventExtras.isForPerformance != isForPerformance) {
+                || eventExtras.switchType != switchType) {
             eventExtras =
-                    new StabilityEventExtra(targetPhoneId, isForPerformance, needValidation);
+                    new StabilityEventExtra(targetPhoneId, switchType, needValidation);
 
             // Reset with new timer.
-            delayMs = isForPerformance
-                    ? mAutoDataSwitchPerformanceStabilityTimeThreshold
-                    : mAutoDataSwitchAvailabilityStabilityTimeThreshold;
+            delayMs = STABILITY_CHECK_TIMER_MAP.get(switchType);
             scheduleEventWithTimer(EVENT_STABILITY_CHECK_PASSED, eventExtras, delayMs);
         }
         log("startStabilityCheck: "
@@ -1165,6 +1220,17 @@ public class AutoDataSwitchController extends Handler {
         return phoneId >= 0 && phoneId < mPhonesSignalStatus.length;
     }
 
+    /** Auto data switch stability check type to string. */
+    @NonNull
+    public static String switchTypeToString(@PreSwitchStabilityCheckType int switchType) {
+        return switch (switchType) {
+            case STABILITY_CHECK_AVAILABILITY_SWITCH -> "AVAILABILITY_SWITCH";
+            case STABILITY_CHECK_PERFORMANCE_SWITCH -> "PERFORMANCE_SWITCH";
+            case STABILITY_CHECK_AVAILABILITY_SWITCH_BACK -> "AVAILABILITY_SWITCH_BACK";
+            default -> "Unknown(" + switchType + ")";
+        };
+    }
+
     /**
      * Log debug messages.
      * @param s debug messages
@@ -1205,8 +1271,9 @@ public class AutoDataSwitchController extends Handler {
         pw.println("mAutoDataSwitchValidationMaxRetry=" + mAutoDataSwitchValidationMaxRetry
                 + " mAutoSwitchValidationFailedCount=" + mAutoSwitchValidationFailedCount);
         pw.println("mRequirePingTestBeforeDataSwitch=" + mRequirePingTestBeforeSwitch);
-        pw.println("mAutoDataSwitchAvailabilityStabilityTimeThreshold="
-                + mAutoDataSwitchAvailabilityStabilityTimeThreshold);
+        pw.println("STABILITY_CHECK_TIMER_MAP:");
+        STABILITY_CHECK_TIMER_MAP.forEach((key, value)
+                -> pw.println(switchTypeToString(key) + ": " + value));
         pw.println("mSelectedTargetPhoneId=" + mSelectedTargetPhoneId);
         pw.increaseIndent();
         for (PhoneSignalStatus status: mPhonesSignalStatus) {
diff --git a/src/java/com/android/internal/telephony/data/CellularNetworkValidator.java b/src/java/com/android/internal/telephony/data/CellularNetworkValidator.java
index ad1a8aa4ce..026fbf4b2b 100644
--- a/src/java/com/android/internal/telephony/data/CellularNetworkValidator.java
+++ b/src/java/com/android/internal/telephony/data/CellularNetworkValidator.java
@@ -268,7 +268,8 @@ public class CellularNetworkValidator {
 
         mNetworkCallback = new ConnectivityNetworkCallback(subId);
 
-        mConnectivityManager.requestNetwork(createNetworkRequest(), mNetworkCallback, mHandler);
+        mConnectivityManager.requestNetwork(
+                createNetworkRequest(subId), mNetworkCallback, mHandler);
         mHandler.postDelayed(() -> onValidationTimeout(subId), timeoutInMs);
     }
 
@@ -309,13 +310,22 @@ public class CellularNetworkValidator {
         return mState != STATE_IDLE;
     }
 
-    private NetworkRequest createNetworkRequest() {
-        return new NetworkRequest.Builder()
+    private NetworkRequest createNetworkRequest(int subId) {
+        NetworkRequest.Builder req = new NetworkRequest.Builder()
                 .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                 .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                 .setNetworkSpecifier(new TelephonyNetworkSpecifier.Builder()
-                        .setSubscriptionId(mSubId).build())
-                .build();
+                        .setSubscriptionId(subId).build());
+
+        // Satellite is considered valid as long as it can serve restricted requests.
+        Phone target = PhoneFactory.getPhone(SubscriptionManager.getPhoneId(subId));
+        boolean isSatellite = target != null
+                && target.getServiceState().isUsingNonTerrestrialNetwork();
+        if (isSatellite) {
+            req.addTransportType(NetworkCapabilities.TRANSPORT_SATELLITE)
+                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
+        }
+        return req.build();
     }
 
     private synchronized void reportValidationResult(boolean passed, int subId) {
diff --git a/src/java/com/android/internal/telephony/data/DataConfigManager.java b/src/java/com/android/internal/telephony/data/DataConfigManager.java
index 89b0fec040..6dec224279 100644
--- a/src/java/com/android/internal/telephony/data/DataConfigManager.java
+++ b/src/java/com/android/internal/telephony/data/DataConfigManager.java
@@ -1150,6 +1150,19 @@ public class DataConfigManager extends Handler {
                 .auto_data_switch_performance_stability_time_threshold_millis);
     }
 
+    /**
+     * Defines the threshold for switching data back to the default SIM when both SIMs are out of
+     * service, in milliseconds.
+     * If the current data is on the backup SIM and both SIMs remain out of service for this
+     * duration, data will be switched back to the default SIM.
+     * A value of 0 means an immediate switch. If the value is negative, the threshold defined by
+     * {@link #getAutoDataSwitchAvailabilityStabilityTimeThreshold()} will be used instead.
+     */
+    public long getAutoDataSwitchAvailabilitySwitchbackStabilityTimeThreshold() {
+        return mResources.getInteger(com.android.internal.R.integer
+                .auto_data_switch_availability_switchback_stability_time_threshold_millis);
+    }
+
     /**
      * Get the TCP config string, used by {@link LinkProperties#setTcpBufferSizes(String)}.
      * The config string will have the following form, with values in bytes:
diff --git a/src/java/com/android/internal/telephony/data/DataNetworkController.java b/src/java/com/android/internal/telephony/data/DataNetworkController.java
index d5bc741902..b5bfc1d318 100644
--- a/src/java/com/android/internal/telephony/data/DataNetworkController.java
+++ b/src/java/com/android/internal/telephony/data/DataNetworkController.java
@@ -1580,7 +1580,8 @@ public class DataNetworkController extends Handler {
      * @return The data evaluation result.
      */
     @NonNull
-    private DataEvaluation evaluateNetworkRequest(
+    @VisibleForTesting
+    public DataEvaluation evaluateNetworkRequest(
             @NonNull TelephonyNetworkRequest networkRequest, DataEvaluationReason reason) {
         DataEvaluation evaluation = new DataEvaluation(reason);
         int transport = mAccessNetworksManager.getPreferredTransportByNetworkCapability(
@@ -2235,6 +2236,9 @@ public class DataNetworkController extends Handler {
             }
             // When the device is on satellite, internet with restricted capabilities always honor
             // soft disallowed reasons and not respected as restricted request
+            // Note - ping test are performed with restricted request on satellite assuming they cannot
+            // bypass any checks. If below is removed, reevaluate the ping request in
+            // CellularNetworkValidator and the getInternetEvaluation in AutoDataSwitchController
             return !(mServiceState.isUsingNonTerrestrialNetwork()
                     && networkRequest.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET));
 
diff --git a/src/java/com/android/internal/telephony/satellite/DatagramDispatcher.java b/src/java/com/android/internal/telephony/satellite/DatagramDispatcher.java
index a40275f8ba..d1d8726ef4 100644
--- a/src/java/com/android/internal/telephony/satellite/DatagramDispatcher.java
+++ b/src/java/com/android/internal/telephony/satellite/DatagramDispatcher.java
@@ -82,8 +82,6 @@ public class DatagramDispatcher extends Handler {
     private static final int CMD_SEND_SMS = 8;
     private static final int EVENT_SEND_SMS_DONE = 9;
     private static final int EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT = 10;
-    private static final int CMD_SEND_MT_SMS_POLLING_MESSAGE = 11;
-
     private static final Long TIMEOUT_DATAGRAM_DELAY_IN_DEMO_MODE = TimeUnit.SECONDS.toMillis(10);
     @NonNull private static DatagramDispatcher sInstance;
     @NonNull private final Context mContext;
@@ -428,16 +426,10 @@ public class DatagramDispatcher extends Handler {
             case EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT: {
                 synchronized (mLock) {
                     mIsMtSmsPollingThrottled = false;
+                    if (allowMtSmsPolling()) {
+                        sendMtSmsPollingMessage();
+                    }
                 }
-                if (allowMtSmsPolling()) {
-                    sendMessage(obtainMessage(CMD_SEND_MT_SMS_POLLING_MESSAGE));
-                }
-                break;
-            }
-
-            case CMD_SEND_MT_SMS_POLLING_MESSAGE: {
-                plogd("CMD_SEND_MT_SMS_POLLING_MESSAGE");
-                handleCmdSendMtSmsPollingMessage();
                 break;
             }
 
@@ -529,9 +521,9 @@ public class DatagramDispatcher extends Handler {
             mIsAligned = isAligned;
             plogd("setDeviceAlignedWithSatellite: " + mIsAligned);
             if (isAligned && mIsDemoMode) handleEventSatelliteAligned();
-        }
-        if (allowMtSmsPolling()) {
-            sendMessage(obtainMessage(CMD_SEND_MT_SMS_POLLING_MESSAGE));
+            if (allowMtSmsPolling()) {
+                sendMtSmsPollingMessage();
+            }
         }
     }
 
@@ -853,9 +845,10 @@ public class DatagramDispatcher extends Handler {
                     mShouldPollMtSms = shouldPollMtSms();
                 }
             }
-        }
-        if (allowMtSmsPolling()) {
-            sendMessage(obtainMessage(CMD_SEND_MT_SMS_POLLING_MESSAGE));
+
+            if (allowMtSmsPolling()) {
+                sendMtSmsPollingMessage();
+            }
         }
     }
 
@@ -1332,25 +1325,22 @@ public class DatagramDispatcher extends Handler {
                 && satelliteController.shouldSendSmsToDatagramDispatcher(satellitePhone);
     }
 
-    private void handleCmdSendMtSmsPollingMessage() {
-        synchronized (mLock) {
-            if (!mShouldPollMtSms) {
-                plogd("sendMtSmsPollingMessage: mShouldPollMtSms=" + mShouldPollMtSms);
-                return;
-            }
+    @GuardedBy("mLock")
+    private void sendMtSmsPollingMessage() {
+        if (!mShouldPollMtSms) {
+            return;
+        }
 
-            plogd("sendMtSmsPollingMessage");
-            if (!allowCheckMessageInNotConnected()) {
-                mShouldPollMtSms = false;
-            }
+        plogd("sendMtSmsPollingMessage");
+        if (!allowCheckMessageInNotConnected()) {
+            mShouldPollMtSms = false;
+        }
 
-            for (Entry<Long, PendingRequest> entry : mPendingSmsMap.entrySet()) {
-                PendingRequest pendingRequest = entry.getValue();
-                if (pendingRequest.isMtSmsPolling) {
-                    plogd("sendMtSmsPollingMessage: mPendingSmsMap already "
-                            + "has the polling message.");
-                    return;
-                }
+        for (Entry<Long, PendingRequest> entry : mPendingSmsMap.entrySet()) {
+            PendingRequest pendingRequest = entry.getValue();
+            if (pendingRequest.isMtSmsPolling) {
+                plogd("sendMtSmsPollingMessage: mPendingSmsMap already has the polling message.");
+                return;
             }
         }
 
@@ -1384,20 +1374,17 @@ public class DatagramDispatcher extends Handler {
         removeMessages(EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT);
     }
 
+    @GuardedBy("mLock")
     private boolean allowMtSmsPolling() {
         if (!mFeatureFlags.carrierRoamingNbIotNtn()) return false;
 
         if (mIsMtSmsPollingThrottled) return false;
 
-        boolean isModemStateConnectedOrTransferring;
-        synchronized (mLock) {
-            if (!mIsAligned) return false;
-
-            isModemStateConnectedOrTransferring =
-                    mModemState == SATELLITE_MODEM_STATE_CONNECTED
-                            || mModemState == SATELLITE_MODEM_STATE_DATAGRAM_TRANSFERRING;
-        }
+        if (!mIsAligned) return false;
 
+        boolean isModemStateConnectedOrTransferring =
+                mModemState == SATELLITE_MODEM_STATE_CONNECTED
+                        || mModemState == SATELLITE_MODEM_STATE_DATAGRAM_TRANSFERRING;
         if (!isModemStateConnectedOrTransferring && !allowCheckMessageInNotConnected()) {
             plogd("EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT:"
                     + " allow_check_message_in_not_connected is disabled");
diff --git a/src/java/com/android/internal/telephony/satellite/SatelliteController.java b/src/java/com/android/internal/telephony/satellite/SatelliteController.java
index 0f922c293a..d455863342 100644
--- a/src/java/com/android/internal/telephony/satellite/SatelliteController.java
+++ b/src/java/com/android/internal/telephony/satellite/SatelliteController.java
@@ -614,6 +614,7 @@ public class SatelliteController extends Handler {
     private List<SatelliteSubscriberProvisionStatus> mLastEvaluatedSubscriberProvisionStatus =
             new ArrayList<>();
     // The ID of the satellite subscription that has highest priority and is provisioned.
+    @GuardedBy("mSatelliteTokenProvisionedLock")
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     protected int mSelectedSatelliteSubId = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
     // The last ICC ID that framework configured to modem.
@@ -7331,7 +7332,6 @@ public class SatelliteController extends Handler {
      */
     public void requestSatelliteSubscriberProvisionStatus(@NonNull ResultReceiver result) {
         if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
-            logd("requestSatelliteSubscriberProvisionStatus: carrierRoamingNbIotNtn is disabled");
             result.send(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, null);
             return;
         }
@@ -7397,8 +7397,10 @@ public class SatelliteController extends Handler {
     }
 
     public int getSelectedSatelliteSubId() {
-        plogd("getSelectedSatelliteSubId: subId=" + mSelectedSatelliteSubId);
-        return mSelectedSatelliteSubId;
+        synchronized (mSatelliteTokenProvisionedLock) {
+            plogd("getSelectedSatelliteSubId: subId=" + mSelectedSatelliteSubId);
+            return mSelectedSatelliteSubId;
+        }
     }
 
     /**
@@ -7760,13 +7762,15 @@ public class SatelliteController extends Handler {
 
     /** Return the carrier ID of the binding satellite subscription. */
     public int getSatelliteCarrierId() {
-        SubscriptionInfo subInfo = mSubscriptionManagerService.getSubscriptionInfo(
-            mSelectedSatelliteSubId);
-        if (subInfo == null) {
-            logd("getSatelliteCarrierId: returns UNKNOWN_CARRIER_ID");
-            return UNKNOWN_CARRIER_ID;
+        synchronized (mSatelliteTokenProvisionedLock) {
+            SubscriptionInfo subInfo = mSubscriptionManagerService.getSubscriptionInfo(
+                    mSelectedSatelliteSubId);
+            if (subInfo == null) {
+                logd("getSatelliteCarrierId: returns UNKNOWN_CARRIER_ID");
+                return UNKNOWN_CARRIER_ID;
+            }
+            return subInfo.getCarrierId();
         }
-        return subInfo.getCarrierId();
     }
 
     /**
diff --git a/tests/telephonytests/src/com/android/internal/telephony/data/AutoDataSwitchControllerTest.java b/tests/telephonytests/src/com/android/internal/telephony/data/AutoDataSwitchControllerTest.java
index d3f30507d6..0d6a668d96 100644
--- a/tests/telephonytests/src/com/android/internal/telephony/data/AutoDataSwitchControllerTest.java
+++ b/tests/telephonytests/src/com/android/internal/telephony/data/AutoDataSwitchControllerTest.java
@@ -142,7 +142,9 @@ public class AutoDataSwitchControllerTest extends TelephonyTest {
                     .when(phone).isUserDataEnabled();
         }
         mDataEvaluation = new DataEvaluation(DataEvaluation.DataEvaluationReason.EXTERNAL_QUERY);
-        doReturn(mDataEvaluation).when(mDataNetworkController).getInternetEvaluation(anyBoolean());
+        doReturn(mDataEvaluation).when(mDataNetworkController).evaluateNetworkRequest(
+                any(TelephonyNetworkRequest.class),
+                eq(DataEvaluation.DataEvaluationReason.EXTERNAL_QUERY));
         doReturn(new int[]{SUB_1, SUB_2}).when(mSubscriptionManagerService)
                 .getActiveSubIdList(true);
         doAnswer(invocation -> {
@@ -167,6 +169,8 @@ public class AutoDataSwitchControllerTest extends TelephonyTest {
                 .getAutoDataSwitchAvailabilityStabilityTimeThreshold();
         doReturn(120000L).when(mDataConfigManager)
                 .getAutoDataSwitchPerformanceStabilityTimeThreshold();
+        doReturn(150000L).when(mDataConfigManager)
+                .getAutoDataSwitchAvailabilitySwitchbackStabilityTimeThreshold();
         doReturn(MAX_RETRY).when(mDataConfigManager).getAutoDataSwitchValidationMaxRetry();
         doReturn(SCORE_TOLERANCE).when(mDataConfigManager).getAutoDataSwitchScoreTolerance();
         doAnswer(invocation -> {
@@ -252,7 +256,9 @@ public class AutoDataSwitchControllerTest extends TelephonyTest {
         mDataEvaluation.addDataDisallowedReason(DataEvaluation.DataDisallowedReason
                 .NO_SUITABLE_DATA_PROFILE);
         doReturn(mDataEvaluation)
-                .when(mDataNetworkController).getInternetEvaluation(anyBoolean());
+                .when(mDataNetworkController).evaluateNetworkRequest(
+                        any(TelephonyNetworkRequest.class),
+                        eq(DataEvaluation.DataEvaluationReason.EXTERNAL_QUERY));
         mAutoDataSwitchControllerUT.evaluateAutoDataSwitch(EVALUATION_REASON_DATA_SETTINGS_CHANGED);
         processAllFutureMessages();
 
diff --git a/tests/telephonytests/src/com/android/internal/telephony/satellite/DatagramDispatcherTest.java b/tests/telephonytests/src/com/android/internal/telephony/satellite/DatagramDispatcherTest.java
index b6828df79e..b4de67240c 100644
--- a/tests/telephonytests/src/com/android/internal/telephony/satellite/DatagramDispatcherTest.java
+++ b/tests/telephonytests/src/com/android/internal/telephony/satellite/DatagramDispatcherTest.java
@@ -1157,7 +1157,6 @@ public class DatagramDispatcherTest extends TelephonyTest {
         mDatagramDispatcherUT.handleMessage(
                 mDatagramDispatcherUT.obtainMessage(10 /*EVENT_MT_SMS_POLLING_THROTTLE_TIMED_OUT*/,
                         new AsyncResult(null, null, null)));
-        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
    }
@@ -1206,7 +1205,6 @@ public class DatagramDispatcherTest extends TelephonyTest {
                 R.bool.config_satellite_allow_check_message_in_not_connected, true);
 
         mDatagramDispatcherUT.setDeviceAlignedWithSatellite(true);
-        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
@@ -1233,7 +1231,6 @@ public class DatagramDispatcherTest extends TelephonyTest {
 
         mDatagramDispatcherUT.onSatelliteModemStateChanged(
                 SatelliteManager.SATELLITE_MODEM_STATE_NOT_CONNECTED);
-        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
@@ -1246,7 +1243,6 @@ public class DatagramDispatcherTest extends TelephonyTest {
 
         mDatagramDispatcherUT.onSatelliteModemStateChanged(
                 SatelliteManager.SATELLITE_MODEM_STATE_CONNECTED);
-        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
@@ -1259,7 +1255,6 @@ public class DatagramDispatcherTest extends TelephonyTest {
 
         mDatagramDispatcherUT.onSatelliteModemStateChanged(
                 SatelliteManager.SATELLITE_MODEM_STATE_DATAGRAM_TRANSFERRING);
-        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
@@ -1290,7 +1285,6 @@ public class DatagramDispatcherTest extends TelephonyTest {
 
         mDatagramDispatcherUT.onSatelliteModemStateChanged(
                 SatelliteManager.SATELLITE_MODEM_STATE_CONNECTED);
-        processAllMessages();
 
         verify(mMockSmsDispatchersController, times(1)).sendMtSmsPollingMessage();
     }
```

