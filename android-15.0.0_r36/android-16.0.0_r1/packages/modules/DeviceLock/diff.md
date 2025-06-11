```diff
diff --git a/DeviceLockController/proto/checkin_service.proto b/DeviceLockController/proto/checkin_service.proto
index f1f1a3a7..0292b67e 100644
--- a/DeviceLockController/proto/checkin_service.proto
+++ b/DeviceLockController/proto/checkin_service.proto
@@ -72,6 +72,10 @@ message GetDeviceCheckinStatusRequest {
   optional string device_model = 5;
   // The internal name of the device.
   optional string device_internal_name = 6;
+  // The locale of the device.
+  optional string device_locale = 7;
+  // The version of the apex package on the device.
+  optional uint64 apex_version = 8;
 }
 
 message ClientDeviceIdentifier {
diff --git a/DeviceLockController/res/values-ar/strings.xml b/DeviceLockController/res/values-ar/strings.xml
index 576608b8..edf392ff 100644
--- a/DeviceLockController/res/values-ar/strings.xml
+++ b/DeviceLockController/res/values-ar/strings.xml
@@ -90,7 +90,7 @@
     <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
     <string name="settings_safe_mode" msgid="3035228015586375153">"إعادة تشغيل الجهاز باستخدام ميزة \"الوضع الآمن\""</string>
     <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
-    <string name="settings_developer_options" msgid="880701002025216672">"استخدام ميزة \"خيارات المطوّرين\""</string>
+    <string name="settings_developer_options" msgid="880701002025216672">"استخدام خيارات المطوّرين"</string>
     <string name="settings_developer_options_preference_key" msgid="6807036808722582954">"settings_developer_options_preference_key"</string>
     <string name="settings_credit_provider_capabilities_category" msgid="1274440595211820868">"إذا حدث خطأ في جهازك، سيكون بإمكان \"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g>\":"</string>
     <string name="settings_credit_provider_capabilities_category_preference_key" msgid="4571685720898641262">"settings_credit_provider_capabilities_category_preference_key"</string>
diff --git a/DeviceLockController/res/values-el/strings.xml b/DeviceLockController/res/values-el/strings.xml
index 80d4f1ec..a59be890 100644
--- a/DeviceLockController/res/values-el/strings.xml
+++ b/DeviceLockController/res/values-el/strings.xml
@@ -33,7 +33,7 @@
     <string name="control_section_title" msgid="2213476068991045785">"Τι μπορεί να κάνει η εφαρμογή <xliff:g id="CREDITOR_APP">%1$s</xliff:g>;"</string>
     <string name="control_lock_device_text" msgid="8253302484073757764">"Εφαρμογή περιορισμών σε αυτήν τη συσκευή αν δεν καταβάλετε κάποια πληρωμή"</string>
     <string name="control_download_text" msgid="8514650561843088172">"Λήψη, εγκατάσταση και ενημέρωση της εφαρμογής <xliff:g id="CREDITOR_APP">%1$s</xliff:g>"</string>
-    <string name="control_disable_debug_text" msgid="8112443250013094442">"Απενεργοποίηση λειτουργιών εντοπισμού και διόρθωσης σφαλμάτων"</string>
+    <string name="control_disable_debug_text" msgid="8112443250013094442">"Απενεργοποίηση λειτουργιών αποσφαλμάτωσης"</string>
     <string name="locked_section_title" msgid="2748725389334076510">"Τι θα λειτουργεί αν αυτή η συσκευή κλειδωθεί;"</string>
     <string name="locked_emergency_text" msgid="3509216445555779286">"Υπηρεσίες κλήσεων έκτακτης ανάγκης"</string>
     <string name="locked_phone_usage_text" msgid="1913605870324552847">"Εισερχόμενες και ορισμένες εξερχόμενες κλήσεις"</string>
diff --git a/DeviceLockController/res/values-my/strings.xml b/DeviceLockController/res/values-my/strings.xml
index 8d53083c..741a5f82 100644
--- a/DeviceLockController/res/values-my/strings.xml
+++ b/DeviceLockController/res/values-my/strings.xml
@@ -79,7 +79,7 @@
     <string name="opening_kiosk_app" msgid="2021888641430165654">"<xliff:g id="CREDITOR_APP">%1$s</xliff:g> အက်ပ်ကို ဖွင့်နေသည်…"</string>
     <string name="settings_banner_title" msgid="527041021011279252">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> က ပံ့ပိုးထားသော စက်ပစ္စည်း"</string>
     <string name="settings_banner_body" msgid="5814902066260202824">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> သည် ဤစက်တွင် ဆက်တင်များကို ပြောင်းနိုင်သည်"</string>
-    <string name="settings_banner_button" msgid="1831020849782670907">"ပိုမိုလေ့လာရန်"</string>
+    <string name="settings_banner_button" msgid="1831020849782670907">"ပိုလေ့လာရန်"</string>
     <string name="settings_screen_title" msgid="721470080648091035">"အရစ်ကျပေးချေဆဲ စက်၏အချက်အလက်"</string>
     <string name="settings_intro_device_financing" msgid="2548476558131048133">"<xliff:g id="PROVIDER_NAME_0">%1$s</xliff:g> သည် ဤစက်တွင် ဆက်တင်များပြောင်းနိုင်ပြီး Kiosk app ထည့်သွင်းနိုင်သည်။\n\nငွေပေးချေမှု မပြုလုပ်ပါက <xliff:g id="PROVIDER_NAME_1">%1$s</xliff:g> သည် သင့်စက်ကို ကန့်သတ်နိုင်သည်။\n\nပိုမိုလေ့လာရန် <xliff:g id="PROVIDER_NAME_2">%1$s</xliff:g> ကို ဆက်သွယ်နိုင်သည်။"</string>
     <string name="settings_intro_device_subsidy" msgid="4274945644204818702">"<xliff:g id="PROVIDER_NAME_0">%1$s</xliff:g> သည် ဤစက်တွင် ဆက်တင်များပြောင်းနိုင်ပြီး Kiosk app ထည့်သွင်းနိုင်သည်။\n\nငွေပေးချေမှု မပြုလုပ်ပါက (သို့) <xliff:g id="PROVIDER_NAME_2">%1$s</xliff:g> ၏ ဆင်းမ်ကတ်ကို မသုံးတော့ပါက <xliff:g id="PROVIDER_NAME_1">%1$s</xliff:g> သည် ဤစက်ကိုလည်း ကန့်သတ်နိုင်သည်။\n\nပိုမိုလေ့လာရန် <xliff:g id="PROVIDER_NAME_3">%1$s</xliff:g> ကို ဆက်သွယ်နိုင်သည်။"</string>
diff --git a/DeviceLockController/res/values-zh-rHK/strings.xml b/DeviceLockController/res/values-zh-rHK/strings.xml
index ed15c8cb..e698fffc 100644
--- a/DeviceLockController/res/values-zh-rHK/strings.xml
+++ b/DeviceLockController/res/values-zh-rHK/strings.xml
@@ -74,7 +74,7 @@
     <string name="restrictions_lifted" msgid="5785586265984319396">"所有裝置限制均已解除"</string>
     <string name="uninstall_kiosk_app" msgid="3459557395024053988">"你可在裝置上解除安裝 Kiosk 應用程式"</string>
     <string name="getting_device_ready" msgid="2829009584599871699">"正在準備裝置…"</string>
-    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"此程序可能需時幾分鐘"</string>
+    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"可能需時幾分鐘"</string>
     <string name="installing_kiosk_app" msgid="324208168205545860">"正在安裝「<xliff:g id="CREDITOR_APP">%1$s</xliff:g>」應用程式…"</string>
     <string name="opening_kiosk_app" msgid="2021888641430165654">"正在開啟「<xliff:g id="CREDITOR_APP">%1$s</xliff:g>」應用程式…"</string>
     <string name="settings_banner_title" msgid="527041021011279252">"「<xliff:g id="PROVIDER_NAME">%1$s</xliff:g>」提供的裝置"</string>
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/activities/ProgressFragment.java b/DeviceLockController/src/com/android/devicelockcontroller/activities/ProgressFragment.java
index b3660dbb..db0ef6c7 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/activities/ProgressFragment.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/activities/ProgressFragment.java
@@ -47,6 +47,7 @@ import com.android.devicelockcontroller.policy.ProvisionHelper;
 import com.android.devicelockcontroller.policy.ProvisionHelperImpl;
 import com.android.devicelockcontroller.policy.ProvisionStateController;
 import com.android.devicelockcontroller.provision.worker.ReportDeviceProvisionStateWorker;
+import com.android.devicelockcontroller.provision.worker.ReviewDeviceProvisionStateWorker;
 import com.android.devicelockcontroller.util.LogUtil;
 
 import com.google.common.util.concurrent.FutureCallback;
@@ -158,6 +159,8 @@ public final class ProgressFragment extends Fragment {
                                             getActivity().finish();
                                             return;
                                         }
+                                        ReviewDeviceProvisionStateWorker.cancelJobs(
+                                                WorkManager.getInstance(requireContext()));
                                         ReportDeviceProvisionStateWorker.reportSetupFailed(
                                                 WorkManager.getInstance(requireContext()),
                                                 provisioningProgress.mFailureReason);
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java b/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
index 05f8c555..22f867ae 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
@@ -107,6 +107,7 @@ public final class DeviceLockConstants {
             ProvisionFailureReason.COUNTRY_INFO_UNAVAILABLE,
             ProvisionFailureReason.NOT_IN_ELIGIBLE_COUNTRY,
             ProvisionFailureReason.POLICY_ENFORCEMENT_FAILED,
+            ProvisionFailureReason.DEADLINE_PASSED
     })
     public @interface ProvisionFailureReason {
         int UNKNOWN_REASON = 0;
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceCheckInClientDebug.java b/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceCheckInClientDebug.java
index 1c674717..57015e12 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceCheckInClientDebug.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceCheckInClientDebug.java
@@ -120,12 +120,14 @@ public final class DeviceCheckInClientDebug extends DeviceCheckInClient {
         return value == null ? defValue : value;
     }
 
-    /**
-     * Check In with DeviceLock backend server and get the next step for the device.
-     */
+    /** Check In with DeviceLock backend server and get the next step for the device. */
     @Override
-    public GetDeviceCheckInStatusGrpcResponse getDeviceCheckInStatus(ArraySet<DeviceId> deviceIds,
-            String carrierInfo, @Nullable String fcmRegistrationToken) {
+    public GetDeviceCheckInStatusGrpcResponse getDeviceCheckInStatus(
+            ArraySet<DeviceId> deviceIds,
+            String carrierInfo,
+            String deviceLocale,
+            long deviceLockApexVersion,
+            @Nullable String fcmRegistrationToken) {
         ThreadAsserts.assertWorkerThread("getDeviceCheckInStatus");
         return new GetDeviceCheckInStatusGrpcResponse() {
             @Override
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceLockCommandReceiver.java b/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceLockCommandReceiver.java
index f52f77e5..3672fa16 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceLockCommandReceiver.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceLockCommandReceiver.java
@@ -366,10 +366,6 @@ public final class DeviceLockCommandReceiver extends BroadcastReceiver {
                 context, /* ignored */ 0,
                 new Intent(context, ResumeProvisionReceiver.class),
                 PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE));
-        alarmManager.cancel(PendingIntent.getBroadcast(
-                context, /* ignored */ 0,
-                new Intent(context, NextProvisionFailedStepReceiver.class),
-                PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE));
         alarmManager.cancel(PendingIntent.getBroadcast(
                 context, /* ignored */ 0,
                 new Intent(context, WorkFailureAlarmReceiver.class),
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/DeviceStateControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/DeviceStateControllerImpl.java
index 82b9f8f3..1e8e8581 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/DeviceStateControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/DeviceStateControllerImpl.java
@@ -47,6 +47,7 @@ public final class DeviceStateControllerImpl implements DeviceStateController {
     // intended purpose.
     @VisibleForTesting
     volatile @DeviceState int mPseudoDeviceState;
+    private boolean mClearingInProgress;
 
     public DeviceStateControllerImpl(DevicePolicyController policyController,
             ProvisionStateController provisionStateController, Executor executor) {
@@ -55,6 +56,7 @@ public final class DeviceStateControllerImpl implements DeviceStateController {
         mGlobalParametersClient = GlobalParametersClient.getInstance();
         mExecutor = executor;
         mPseudoDeviceState = UNDEFINED;
+        mClearingInProgress = false;
     }
 
     @Override
@@ -69,6 +71,7 @@ public final class DeviceStateControllerImpl implements DeviceStateController {
 
     @Override
     public ListenableFuture<Void> clearDevice() {
+        mClearingInProgress = true;
         return setDeviceState(CLEARED);
     }
 
@@ -110,7 +113,7 @@ public final class DeviceStateControllerImpl implements DeviceStateController {
                     return Futures.transformAsync(maybeSetProvisioningSuccess,
                             unused -> Futures.transformAsync(isCleared(),
                                     isCleared -> {
-                                        if (isCleared) {
+                                        if (isClearingInProgress(deviceState) || isCleared) {
                                             throw new IllegalStateException("Device has been "
                                                     + "cleared!");
                                         }
@@ -154,4 +157,12 @@ public final class DeviceStateControllerImpl implements DeviceStateController {
         return Futures.transform(mGlobalParametersClient.getDeviceState(),
                 s -> s == CLEARED, MoreExecutors.directExecutor());
     }
+
+    // If a clear operation is immediately followed by an unlock command, sometimes a race
+    // condition occurs that results in the unlock state being enforced. This method is used to
+    // ensure that clear is always terminal.
+    // TODO: b/286324034 - these operations should be made thread safe
+    private boolean isClearingInProgress(@DeviceState int deviceStateBeingEnforced) {
+        return deviceStateBeingEnforced != CLEARED && mClearingInProgress;
+    }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionHelperImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionHelperImpl.java
index d30dd78c..edf15d40 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionHelperImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionHelperImpl.java
@@ -60,6 +60,7 @@ import com.android.devicelockcontroller.common.DeviceLockConstants.ProvisionFail
 import com.android.devicelockcontroller.provision.worker.IsDeviceInApprovedCountryWorker;
 import com.android.devicelockcontroller.provision.worker.PauseProvisioningWorker;
 import com.android.devicelockcontroller.provision.worker.ReportDeviceProvisionStateWorker;
+import com.android.devicelockcontroller.provision.worker.ReviewDeviceProvisionStateWorker;
 import com.android.devicelockcontroller.receivers.ResumeProvisionReceiver;
 import com.android.devicelockcontroller.schedule.DeviceLockControllerScheduler;
 import com.android.devicelockcontroller.schedule.DeviceLockControllerSchedulerProvider;
@@ -186,7 +187,10 @@ public final class ProvisionHelperImpl implements ProvisionHelper {
                         LogUtil.i(TAG, "Kiosk app is pre-installed");
                         progressController.setProvisioningProgress(
                                 ProvisioningProgress.OPENING_KIOSK_APP);
+
                         ReportDeviceProvisionStateWorker.reportSetupCompleted(workManager);
+                        ReviewDeviceProvisionStateWorker.cancelJobs(
+                                WorkManager.getInstance(mContext));
                         mStateController.postSetNextStateForEventRequest(PROVISION_KIOSK);
                     } catch (NameNotFoundException e) {
                         LogUtil.i(TAG, "Kiosk app is not pre-installed");
@@ -305,6 +309,8 @@ public final class ProvisionHelperImpl implements ProvisionHelper {
                                 progressController.setProvisioningProgress(
                                         ProvisioningProgress.OPENING_KIOSK_APP);
                                 ReportDeviceProvisionStateWorker.reportSetupCompleted(workManager);
+                                ReviewDeviceProvisionStateWorker.cancelJobs(
+                                        WorkManager.getInstance(mContext));
                                 mStateController.postSetNextStateForEventRequest(PROVISION_KIOSK);
                             } else if (state == FAILED) {
                                 LogUtil.w(TAG, "Play installation failed!");
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
index a7cd1462..c074dc99 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
@@ -41,8 +41,10 @@ import android.provider.Settings;
 import androidx.annotation.GuardedBy;
 import androidx.annotation.NonNull;
 import androidx.annotation.VisibleForTesting;
+import androidx.work.WorkManager;
 
 import com.android.devicelockcontroller.SystemDeviceLockManagerImpl;
+import com.android.devicelockcontroller.provision.worker.ReviewDeviceProvisionStateWorker;
 import com.android.devicelockcontroller.receivers.LockedBootCompletedReceiver;
 import com.android.devicelockcontroller.services.SetupWizardCompletionTimeoutJobService;
 import com.android.devicelockcontroller.stats.StatsLoggerProvider;
@@ -137,7 +139,10 @@ public final class ProvisionStateControllerImpl implements ProvisionStateControl
                                 if (PROVISION_READY == event) {
                                     UserParameters.setProvisioningStartTimeMillis(mContext,
                                             SystemClock.elapsedRealtime());
+                                    ReviewDeviceProvisionStateWorker.scheduleDailyReview(
+                                            WorkManager.getInstance(mContext));
                                 }
+
                                 if (PROVISION_SUCCESS == event) {
                                     ((StatsLoggerProvider) mContext.getApplicationContext())
                                             .getStatsLogger().logSuccessfulProvisioning();
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
index e58f4e08..e59f7f41 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
@@ -139,12 +139,15 @@ public abstract class DeviceCheckInClient {
      * @param carrierInfo          The information of the device's sim operator which is used to
      *                             determine the device's geological location and eventually
      *                             eligibility of the DeviceLock program.
+     * @param deviceLocale         The locale of the device.
+     * @param deviceLockApexVersion The version of the device lock apex.
      * @param fcmRegistrationToken The fcm registration token
      * @return A class that encapsulate the response from the backend server.
      */
     @WorkerThread
     public abstract GetDeviceCheckInStatusGrpcResponse getDeviceCheckInStatus(
             ArraySet<DeviceId> deviceIds, String carrierInfo,
+            String deviceLocale, long deviceLockApexVersion,
             @Nullable String fcmRegistrationToken);
 
     /**
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
index 767c0f9b..b58f2e98 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
@@ -178,11 +178,19 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
 
     @Override
     public GetDeviceCheckInStatusGrpcResponse getDeviceCheckInStatus(
-            ArraySet<DeviceId> deviceIds, String carrierInfo,
+            ArraySet<DeviceId> deviceIds,
+            String carrierInfo,
+            String deviceLocale,
+            long deviceLockApexVersion,
             @Nullable String fcmRegistrationToken) {
         ThreadAsserts.assertWorkerThread("getDeviceCheckInStatus");
         GetDeviceCheckInStatusGrpcResponse response =
-                getDeviceCheckInStatus(deviceIds, carrierInfo, fcmRegistrationToken,
+                getDeviceCheckInStatus(
+                        deviceIds,
+                        carrierInfo,
+                        deviceLocale,
+                        deviceLockApexVersion,
+                        fcmRegistrationToken,
                         mDefaultBlockingStub);
         if (response.hasRecoverableError()) {
             DeviceLockCheckinServiceBlockingStub stub;
@@ -193,20 +201,34 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
                 stub = mNonVpnBlockingStub;
             }
             LogUtil.d(TAG, "Non-VPN network fallback detected. Re-attempt check-in.");
-            return getDeviceCheckInStatus(deviceIds, carrierInfo, fcmRegistrationToken, stub);
+            return getDeviceCheckInStatus(
+                    deviceIds,
+                    carrierInfo,
+                    deviceLocale,
+                    deviceLockApexVersion,
+                    fcmRegistrationToken,
+                    stub);
         }
         return response;
     }
 
     private GetDeviceCheckInStatusGrpcResponse getDeviceCheckInStatus(
-            ArraySet<DeviceId> deviceIds, String carrierInfo,
+            ArraySet<DeviceId> deviceIds,
+            String carrierInfo,
+            String deviceLocale,
+            long deviceLockApexVersion,
             @Nullable String fcmRegistrationToken,
             @NonNull DeviceLockCheckinServiceBlockingStub stub) {
         try {
             return new GetDeviceCheckInStatusGrpcResponseWrapper(
                     stub.withDeadlineAfter(GRPC_DEADLINE_MS, TimeUnit.MILLISECONDS)
-                            .getDeviceCheckinStatus(createGetDeviceCheckinStatusRequest(
-                                    deviceIds, carrierInfo, fcmRegistrationToken)));
+                            .getDeviceCheckinStatus(
+                                    createGetDeviceCheckinStatusRequest(
+                                            deviceIds,
+                                            carrierInfo,
+                                            deviceLocale,
+                                            deviceLockApexVersion,
+                                            fcmRegistrationToken)));
         } catch (StatusRuntimeException e) {
             return new GetDeviceCheckInStatusGrpcResponseWrapper(e.getStatus());
         }
@@ -387,7 +409,10 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
     }
 
     private static GetDeviceCheckinStatusRequest createGetDeviceCheckinStatusRequest(
-            ArraySet<DeviceId> deviceIds, String carrierInfo,
+            ArraySet<DeviceId> deviceIds,
+            String carrierInfo,
+            String deviceLocale,
+            long deviceLockApexVersion,
             @Nullable String fcmRegistrationToken) {
         GetDeviceCheckinStatusRequest.Builder builder = GetDeviceCheckinStatusRequest.newBuilder();
         for (DeviceId deviceId : deviceIds) {
@@ -404,6 +429,8 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
         if (!Strings.isNullOrEmpty(fcmRegistrationToken) && !fcmRegistrationToken.isBlank()) {
             builder.setFcmRegistrationToken(fcmRegistrationToken);
         }
+        builder.setDeviceLocale(deviceLocale);
+        builder.setApexVersion(deviceLockApexVersion);
         return builder.build();
     }
 
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/AbstractDeviceCheckInHelper.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/AbstractDeviceCheckInHelper.java
index 1fd57cda..ed44cbc4 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/AbstractDeviceCheckInHelper.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/AbstractDeviceCheckInHelper.java
@@ -34,6 +34,10 @@ public abstract class AbstractDeviceCheckInHelper {
 
     abstract String getCarrierInfo();
 
+    abstract String getDeviceLocale();
+
+    abstract long getDeviceLockApexVersion(String packageName);
+
     @WorkerThread
     abstract boolean handleGetDeviceCheckInStatusResponse(
             GetDeviceCheckInStatusGrpcResponse response,
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInHelper.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInHelper.java
index 66b53a80..ac5094b4 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInHelper.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInHelper.java
@@ -44,6 +44,7 @@ import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.net.NetworkRequest;
 import android.os.Bundle;
+import android.os.LocaleList;
 import android.os.SystemClock;
 import android.os.UserHandle;
 import android.telephony.TelephonyManager;
@@ -97,11 +98,6 @@ public final class DeviceCheckInHelper extends AbstractDeviceCheckInHelper {
         mStatsLogger = ((StatsLoggerProvider) mAppContext).getStatsLogger();
     }
 
-    private boolean hasGsm() {
-        return mAppContext.getPackageManager().hasSystemFeature(
-                PackageManager.FEATURE_TELEPHONY_GSM);
-    }
-
     private boolean hasCdma() {
         return mAppContext.getPackageManager().hasSystemFeature(
                 PackageManager.FEATURE_TELEPHONY_CDMA);
@@ -128,7 +124,7 @@ public final class DeviceCheckInHelper extends AbstractDeviceCheckInHelper {
         if (maximumIdCount == 0) return deviceIds;
 
         for (int i = 0; i < totalSlotCount; i++) {
-            if (hasGsm() && (deviceIdTypeBitmap & (1 << DEVICE_ID_TYPE_IMEI)) != 0) {
+            if ((deviceIdTypeBitmap & (1 << DEVICE_ID_TYPE_IMEI)) != 0) {
                 final String imei = mTelephonyManager.getImei(i);
 
                 if (imei != null) {
@@ -263,4 +259,22 @@ public final class DeviceCheckInHelper extends AbstractDeviceCheckInHelper {
                 UserHandle.ALL);
         return true;
     }
+
+    @Override
+    String getDeviceLocale() {
+        return LocaleList.getAdjustedDefault().get(0).toLanguageTag();
+    }
+
+    @Override
+    long getDeviceLockApexVersion(String packageName) {
+        try {
+            return mAppContext
+                    .getPackageManager()
+                    .getPackageInfo(packageName, PackageManager.MATCH_APEX)
+                    .getLongVersionCode();
+        } catch (PackageManager.NameNotFoundException e) {
+            LogUtil.e(TAG, "Failed to get device lock apex version", e);
+        }
+        return 0;
+    }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorker.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorker.java
index b3001856..1a937dc3 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorker.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorker.java
@@ -100,7 +100,12 @@ public final class DeviceCheckInWorker extends AbstractCheckInWorker {
                         String fcmToken = Futures.getDone(fcmRegistrationToken);
                         GetDeviceCheckInStatusGrpcResponse response =
                                 client.getDeviceCheckInStatus(
-                                        deviceIds, carrierInfo, fcmToken);
+                                        deviceIds,
+                                        carrierInfo,
+                                        mCheckInHelper.getDeviceLocale(),
+                                        mCheckInHelper.getDeviceLockApexVersion(
+                                                mContext.getPackageName()),
+                                        fcmToken);
                         mStatsLogger.logGetDeviceCheckInStatus();
                         if (response.hasRecoverableError()) {
                             LogUtil.w(TAG, "Check-in failed w/ recoverable error " + response
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReportDeviceProvisionStateWorker.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReportDeviceProvisionStateWorker.java
index 8d48e623..b366b62a 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReportDeviceProvisionStateWorker.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReportDeviceProvisionStateWorker.java
@@ -70,9 +70,7 @@ public final class ReportDeviceProvisionStateWorker extends AbstractCheckInWorke
 
     private final StatsLogger mStatsLogger;
 
-    /**
-     * Report provision failure and get next failed step
-     */
+    /** Report provision failure and get next failed step */
     public static void reportSetupFailed(WorkManager workManager,
             @ProvisionFailureReason int reason) {
         Data inputData = new Data.Builder()
@@ -169,6 +167,7 @@ public final class ReportDeviceProvisionStateWorker extends AbstractCheckInWorke
             if (!isSuccessful && failureReason == ProvisionFailureReason.UNKNOWN_REASON) {
                 LogUtil.e(TAG, "Reporting failure with an unknown reason is not allowed");
             }
+
             ReportDeviceProvisionStateGrpcResponse response =
                     Futures.getDone(mClient).reportDeviceProvisionState(
                             Futures.getDone(lastState),
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReviewDeviceProvisionStateWorker.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReviewDeviceProvisionStateWorker.java
new file mode 100644
index 00000000..281e534c
--- /dev/null
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReviewDeviceProvisionStateWorker.java
@@ -0,0 +1,192 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.devicelockcontroller.provision.worker;
+
+import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent.PROVISION_FAILURE;
+import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.PROVISION_FAILED;
+import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.PROVISION_SUCCEEDED;
+
+import android.app.PendingIntent;
+import android.content.BroadcastReceiver;
+import android.content.Context;
+import android.content.Intent;
+import android.os.SystemClock;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.VisibleForTesting;
+import androidx.work.BackoffPolicy;
+import androidx.work.ExistingPeriodicWorkPolicy;
+import androidx.work.Operation;
+import androidx.work.PeriodicWorkRequest;
+import androidx.work.WorkManager;
+import androidx.work.WorkerParameters;
+
+import com.android.devicelockcontroller.WorkManagerExceptionHandler.WorkFailureAlarmReceiver;
+import com.android.devicelockcontroller.common.DeviceLockConstants;
+import com.android.devicelockcontroller.policy.PolicyObjectsProvider;
+import com.android.devicelockcontroller.provision.grpc.DeviceCheckInClient;
+import com.android.devicelockcontroller.receivers.NextProvisionFailedStepReceiver;
+import com.android.devicelockcontroller.receivers.ResetDeviceReceiver;
+import com.android.devicelockcontroller.receivers.ResumeProvisionReceiver;
+import com.android.devicelockcontroller.storage.UserParameters;
+import com.android.devicelockcontroller.util.LogUtil;
+
+import com.google.common.util.concurrent.FutureCallback;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+
+import java.util.concurrent.TimeUnit;
+
+/**
+ * A worker class to ensure provision failure is detected and reported. Provision can fail
+ * undetected for a number of reasons. If provision does not complete successfully after 1 day, and
+ * no alarms to resume it have been set, it should be assumed that it failed and reported.
+ */
+public final class ReviewDeviceProvisionStateWorker extends AbstractCheckInWorker {
+
+    public static final String REVIEW_DEVICE_PROVISION_STATE_WORK_NAME =
+            "review-device-provision-state";
+    private static final float MILLISECONDS_IN_A_DAY = 86400000F;
+
+    /**
+     * Schedules this job daily with an initial delay of 26 hours.
+     *
+     * <p>The 26 hour initial delay provides a 2 hour buffer so that the 1 day condition evaluated
+     * in {@code #hasProvisionFailedOr1DayLapsedSinceProvisioning} is met during the first run.
+     *
+     */
+    public static void scheduleDailyReview(WorkManager workManager) {
+        PeriodicWorkRequest work =
+                new PeriodicWorkRequest.Builder(ReviewDeviceProvisionStateWorker.class, 1,
+                        TimeUnit.DAYS)
+                        .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, BACKOFF_DELAY)
+                        .setInitialDelay(26, TimeUnit.HOURS)
+                        .build();
+        ListenableFuture<Operation.State.SUCCESS> result =
+                workManager
+                        .enqueueUniquePeriodicWork(
+                                REVIEW_DEVICE_PROVISION_STATE_WORK_NAME,
+                                ExistingPeriodicWorkPolicy.UPDATE, work)
+                        .getResult();
+        Futures.addCallback(
+                result,
+                new FutureCallback<>() {
+                    @Override
+                    public void onSuccess(Operation.State.SUCCESS result) {
+                        // no-op
+                    }
+
+                    @Override
+                    public void onFailure(Throwable t) {
+                        // Log an error but don't reset the device (non critical failure).
+                        LogUtil.e(TAG, "Failed to enqueue 'review provision state' work");
+                    }
+                },
+                MoreExecutors.directExecutor());
+    }
+
+    public static void cancelJobs(WorkManager workManager) {
+        // Executing jobs will still run but it will certainly cancel all jobs
+        workManager.cancelUniqueWork(REVIEW_DEVICE_PROVISION_STATE_WORK_NAME);
+    }
+
+    public ReviewDeviceProvisionStateWorker(
+            @NonNull Context context,
+            @NonNull WorkerParameters workerParams,
+            ListeningExecutorService executorService) {
+        this(context, workerParams, /* client= */ null, executorService);
+    }
+
+    @VisibleForTesting
+    ReviewDeviceProvisionStateWorker(
+            @NonNull Context context,
+            @NonNull WorkerParameters workerParams,
+            DeviceCheckInClient client,
+            ListeningExecutorService executorService) {
+        super(context, workerParams, client, executorService);
+    }
+
+    private boolean anyAlarmsScheduled() {
+        return isAlarmSet(ResetDeviceReceiver.class)
+                || isAlarmSet(NextProvisionFailedStepReceiver.class)
+                || isAlarmSet(ResumeProvisionReceiver.class)
+                || isAlarmSet(WorkFailureAlarmReceiver.class);
+    }
+
+    private boolean isAlarmSet(Class<? extends BroadcastReceiver> receiverClass) {
+        return PendingIntent.getBroadcast(
+                mContext, /* ignored */
+                0,
+                new Intent(mContext, receiverClass),
+                PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_NO_CREATE
+                        | PendingIntent.FLAG_IMMUTABLE)
+                != null;
+    }
+
+    private boolean hasProvisionFailedOr1DayLapsedSinceProvisioning(int provisionState) {
+        float daysLapsed =
+                (SystemClock.elapsedRealtime() - UserParameters.getProvisioningStartTimeMillis(
+                        mContext))
+                        / MILLISECONDS_IN_A_DAY;
+
+        return provisionState == PROVISION_FAILED || daysLapsed >= 1.0F;
+    }
+
+    private boolean hasProvisionSucceeded(int provisionState) {
+        return provisionState == PROVISION_SUCCEEDED;
+    }
+
+    private ListenableFuture<Integer> getProvisionState() {
+        return mExecutorService.submit(() -> UserParameters.getProvisionState(mContext));
+    }
+
+    @NonNull
+    @Override
+    public ListenableFuture<Result> startWork() {
+        return Futures.transform(
+                getProvisionState(),
+                provisionState -> {
+                    if (hasProvisionSucceeded(provisionState)) {
+                        ReviewDeviceProvisionStateWorker.cancelJobs(
+                                WorkManager.getInstance(mContext));
+                        return Result.success();
+                    }
+
+                    if (!hasProvisionFailedOr1DayLapsedSinceProvisioning(provisionState)) {
+                        return Result.success();
+                    }
+
+                    if (anyAlarmsScheduled()) {
+                        // Do nothing, check back tomorrow and the other day until the alarms are
+                        // cleared
+                        return Result.success();
+                    }
+
+                    ReportDeviceProvisionStateWorker.reportSetupFailed(
+                            WorkManager.getInstance(mContext),
+                            DeviceLockConstants.ProvisionFailureReason.DEADLINE_PASSED);
+                    ((PolicyObjectsProvider) mContext).getProvisionStateController()
+                            .postSetNextStateForEventRequest(PROVISION_FAILURE);
+                    ReviewDeviceProvisionStateWorker.cancelJobs(WorkManager.getInstance(mContext));
+
+                    return Result.success();
+                },
+                mExecutorService);
+    }
+}
diff --git a/DeviceLockController/tests/robolectric/Android.bp b/DeviceLockController/tests/robolectric/Android.bp
index 161fd64f..73bf4596 100644
--- a/DeviceLockController/tests/robolectric/Android.bp
+++ b/DeviceLockController/tests/robolectric/Android.bp
@@ -20,7 +20,6 @@ android_robolectric_test {
     name: "DeviceLockControllerRoboTests",
     team: "trendy_team_android_go",
     instrumentation_for: "DeviceLockController",
-    upstream: true,
     java_resource_dirs: [
         "config",
     ],
diff --git a/DeviceLockController/tests/robolectric/AndroidTest.xml b/DeviceLockController/tests/robolectric/AndroidTest.xml
deleted file mode 100644
index 62bab5f3..00000000
--- a/DeviceLockController/tests/robolectric/AndroidTest.xml
+++ /dev/null
@@ -1,32 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-<configuration description="Runs DeviceLockControllerRoboTests">
-    <option name="test-suite-tag" value="robolectric" />
-    <option name="test-suite-tag" value="robolectric-tests" />
-
-    <option name="java-folder" value="prebuilts/jdk/jdk21/linux-x86/" />
-    <option name="exclude-paths" value="java" />
-    <option name="use-robolectric-resources" value="true" />
-
-    <test class="com.android.tradefed.testtype.IsolatedHostTest" >
-        <option name="jar" value="DeviceLockControllerRoboTests.jar" />
-        <option name="java-flags" value="--add-modules=jdk.compiler"/>
-        <option name="java-flags" value="--add-opens=java.base/java.lang=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-opens=java.base/java.lang.reflect=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-opens=java.base/jdk.internal.util.random=ALL-UNNAMED"/>
-        <option name="java-flags" value="--add-opens=java.base/java.io=ALL-UNNAMED"/>
-    </test>
-</configuration>
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/activities/ProgressFragmentTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/activities/ProgressFragmentTest.java
index 564e1cb1..fd7a62e6 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/activities/ProgressFragmentTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/activities/ProgressFragmentTest.java
@@ -27,6 +27,7 @@ import static com.android.devicelockcontroller.common.DeviceLockConstants.Provis
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent.PROVISION_FAILURE;
 import static com.android.devicelockcontroller.provision.worker.ReportDeviceProvisionStateWorker.KEY_PROVISION_FAILURE_REASON;
 import static com.android.devicelockcontroller.provision.worker.ReportDeviceProvisionStateWorker.REPORT_PROVISION_STATE_WORK_NAME;
+import static com.android.devicelockcontroller.provision.worker.ReviewDeviceProvisionStateWorker.REVIEW_DEVICE_PROVISION_STATE_WORK_NAME;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -66,6 +67,7 @@ import com.android.devicelockcontroller.TestDeviceLockControllerApplication;
 import com.android.devicelockcontroller.policy.ProvisionHelper;
 import com.android.devicelockcontroller.policy.ProvisionStateController;
 import com.android.devicelockcontroller.provision.worker.ReportDeviceProvisionStateWorker;
+import com.android.devicelockcontroller.provision.worker.ReviewDeviceProvisionStateWorker;
 
 import com.google.common.truth.Truth;
 import com.google.common.util.concurrent.Futures;
@@ -90,7 +92,6 @@ import java.util.List;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.TimeUnit;
 
-
 @RunWith(ParameterizedRobolectricTestRunner.class)
 public final class ProgressFragmentTest {
 
@@ -214,6 +215,9 @@ public final class ProgressFragmentTest {
         // Check bottom views
         View bottomView = activity.findViewById(R.id.bottom);
         if (mProvisioningProgress.mBottomViewVisible) {
+            WorkManager workManager = WorkManager.getInstance(applicationContext);
+            ReviewDeviceProvisionStateWorker.scheduleDailyReview(workManager);
+
             assertThat(bottomView.getVisibility()).isEqualTo(View.VISIBLE);
 
             ((Button) activity.findViewById(R.id.button_retry)).callOnClick();
@@ -222,10 +226,17 @@ public final class ProgressFragmentTest {
             ((Button) activity.findViewById(R.id.button_exit)).performClick();
             Shadows.shadowOf(Looper.getMainLooper()).idle();
             verify(provisionStateController).postSetNextStateForEventRequest(eq(PROVISION_FAILURE));
-            WorkManager workManager = WorkManager.getInstance(applicationContext);
+
             List<WorkInfo> workInfos = workManager.getWorkInfosForUniqueWork(
                     REPORT_PROVISION_STATE_WORK_NAME).get();
-            assertThat(workInfos.size()).isEqualTo(1);
+            assertThat(workInfos).hasSize(1);
+            List<WorkInfo> reviewDeviceProvisionStateWorkInfos =
+                    workManager
+                            .getWorkInfosForUniqueWork(REVIEW_DEVICE_PROVISION_STATE_WORK_NAME)
+                            .get();
+            assertThat(reviewDeviceProvisionStateWorkInfos).hasSize(1);
+            assertThat(reviewDeviceProvisionStateWorkInfos.get(0).getState())
+                    .isEqualTo(WorkInfo.State.CANCELLED);
         } else {
             assertThat(bottomView.getVisibility()).isEqualTo(View.GONE);
         }
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/ProvisionStateControllerThreadSafetyTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/ProvisionStateControllerThreadSafetyTest.java
index 705551ed..255e0904 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/ProvisionStateControllerThreadSafetyTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/ProvisionStateControllerThreadSafetyTest.java
@@ -25,6 +25,9 @@ import static org.mockito.Mockito.when;
 import static org.robolectric.annotation.LooperMode.Mode.LEGACY;
 
 import androidx.test.core.app.ApplicationProvider;
+import androidx.work.Configuration;
+import androidx.work.testing.SynchronousExecutor;
+import androidx.work.testing.WorkManagerTestInitHelper;
 
 import com.android.devicelockcontroller.TestDeviceLockControllerApplication;
 import com.android.devicelockcontroller.policy.ProvisionStateControllerImpl.StateTransitionException;
@@ -60,6 +63,12 @@ public class ProvisionStateControllerThreadSafetyTest {
                 ApplicationProvider.getApplicationContext();
         UserParameters.setProvisionState(testApplication, UNPROVISIONED);
         DevicePolicyController policyController = testApplication.getPolicyController();
+        WorkManagerTestInitHelper.initializeTestWorkManager(
+                testApplication,
+                new Configuration.Builder()
+                        .setMinimumLoggingLevel(android.util.Log.DEBUG)
+                        .setExecutor(new SynchronousExecutor())
+                        .build());
         mProvisionStateController = new ProvisionStateControllerImpl(testApplication,
                 policyController, testApplication.getDeviceStateController(),
                 Executors.newCachedThreadPool());
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
index d3d3c01a..f86c5815 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
@@ -93,6 +93,8 @@ public final  class DeviceCheckinClientImplTest {
     private static final String TEST_REGISTERED_ID = "1234567890";
     private static final String TEST_FCM_TOKEN = "token";
     private static final int NON_VPN_NET_ID = 10;
+    private static final String TEST_DEVICE_LOCALE = "en-US";
+    private static final long TEST_DEVICE_LOCK_APEX_VERSION = 1234567890;
 
     @Rule
     public MockitoRule mMockitoRule = MockitoJUnit.rule();
@@ -111,6 +113,8 @@ public final  class DeviceCheckinClientImplTest {
     private DeviceCheckInClientImpl mDeviceCheckInClientImpl;
 
     private String mReceivedFcmToken;
+    private String mReceivedDeviceLocale;
+    private long mReceivedDeviceLockApexVersion;
 
     @Before
     public void setUp() throws Exception {
@@ -163,8 +167,12 @@ public final  class DeviceCheckinClientImplTest {
         // WHEN we ask for the check in status
         AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
         mBgExecutor.submit(() -> response.set(
-                mDeviceCheckInClientImpl.getDeviceCheckInStatus(
-                        new ArraySet<>(), TEST_CARRIER_INFO, TEST_FCM_TOKEN)))
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                TEST_DEVICE_LOCALE,
+                                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                                TEST_FCM_TOKEN)))
                 .get();
 
         // THEN the response is successful
@@ -185,9 +193,12 @@ public final  class DeviceCheckinClientImplTest {
         // WHEN we ask for the check in status without an FCM token
         AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
         mBgExecutor.submit(() -> response.set(
-                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
-                                new ArraySet<>(), TEST_CARRIER_INFO,
-                                /* fcmRegistrationToken= */ null)))
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                TEST_DEVICE_LOCALE,
+                                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                                /* fcmRegistrationToken= */ null)))
                 .get();
 
         // THEN the response is successful
@@ -208,8 +219,12 @@ public final  class DeviceCheckinClientImplTest {
         // WHEN we ask for the check in status with an empty FCM token
         AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
         mBgExecutor.submit(() -> response.set(
-                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
-                                new ArraySet<>(), TEST_CARRIER_INFO, "")))
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                TEST_DEVICE_LOCALE,
+                                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                                "")))
                 .get();
 
         // THEN the response is successful
@@ -229,9 +244,16 @@ public final  class DeviceCheckinClientImplTest {
 
         // WHEN we ask for the check in status with a blank FCM token
         AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
-        mBgExecutor.submit(() -> response.set(
-                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
-                                new ArraySet<>(), TEST_CARRIER_INFO, "   ")))
+        mBgExecutor
+                .submit(
+                        () ->
+                                response.set(
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                TEST_DEVICE_LOCALE,
+                                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                                "   ")))
                 .get();
 
         // THEN the response is successful
@@ -239,6 +261,64 @@ public final  class DeviceCheckinClientImplTest {
         assertThat(mReceivedFcmToken).isEmpty();
     }
 
+    @Test
+    public void getCheckInStatus_emptyDeviceLocale_succeeds() throws Exception {
+        // GIVEN the service succeeds through the default network
+        mGrpcCleanup.register(InProcessServerBuilder
+                .forName(mDefaultNetworkServerName)
+                .directExecutor()
+                .addService(makeSucceedingService())
+                .build()
+                .start());
+
+        // WHEN we ask for the check in status with an empty FCM token
+        AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
+        mBgExecutor
+                .submit(
+                        () ->
+                                response.set(
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                "",
+                                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                                TEST_FCM_TOKEN)))
+                .get();
+
+        // THEN the response is successful
+        assertThat(response.get().isSuccessful()).isTrue();
+        assertThat(mReceivedDeviceLocale).isEmpty();
+    }
+
+    @Test
+    public void getCheckInStatus_emptyApexVersion_succeeds() throws Exception {
+        // GIVEN the service succeeds through the default network
+        mGrpcCleanup.register(InProcessServerBuilder
+                .forName(mDefaultNetworkServerName)
+                .directExecutor()
+                .addService(makeSucceedingService())
+                .build()
+                .start());
+
+        // WHEN we ask for the check in status with an empty FCM token
+        AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
+        mBgExecutor
+                .submit(
+                        () ->
+                                response.set(
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                TEST_DEVICE_LOCALE,
+                                                0L,
+                                                TEST_FCM_TOKEN)))
+                .get();
+
+        // THEN the response is successful
+        assertThat(response.get().isSuccessful()).isTrue();
+        assertThat(mReceivedDeviceLockApexVersion).isEqualTo(0L);
+    }
+
     @Test
     public void getCheckInStatus_noDefaultConnectivity_fallsBackToNonVpn() throws Exception {
         // GIVEN a non-VPN network is connected with connectivity
@@ -269,8 +349,12 @@ public final  class DeviceCheckinClientImplTest {
         // WHEN we ask for the check in status
         AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
         mBgExecutor.submit(() -> response.set(
-                mDeviceCheckInClientImpl.getDeviceCheckInStatus(
-                        new ArraySet<>(), TEST_CARRIER_INFO, TEST_FCM_TOKEN)))
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                TEST_DEVICE_LOCALE,
+                                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                                TEST_FCM_TOKEN)))
                 .get();
 
         // THEN the response is successful
@@ -297,8 +381,12 @@ public final  class DeviceCheckinClientImplTest {
         // WHEN we ask for the check in status
         AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
         mBgExecutor.submit(() -> response.set(
-                mDeviceCheckInClientImpl.getDeviceCheckInStatus(
-                        new ArraySet<>(), TEST_CARRIER_INFO, TEST_FCM_TOKEN)))
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                TEST_DEVICE_LOCALE,
+                                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                                TEST_FCM_TOKEN)))
                 .get();
 
         // THEN the response is unsuccessful
@@ -330,9 +418,14 @@ public final  class DeviceCheckinClientImplTest {
 
         // WHEN we ask for the check in status
         AtomicReference<GetDeviceCheckInStatusGrpcResponse> response = new AtomicReference<>();
-        mBgExecutor.submit(() -> response.set(
-                mDeviceCheckInClientImpl.getDeviceCheckInStatus(
-                        new ArraySet<>(), TEST_CARRIER_INFO, TEST_FCM_TOKEN)))
+        mBgExecutor.submit(() ->
+                                response.set(
+                                        mDeviceCheckInClientImpl.getDeviceCheckInStatus(
+                                                new ArraySet<>(),
+                                                TEST_CARRIER_INFO,
+                                                TEST_DEVICE_LOCALE,
+                                                TEST_DEVICE_LOCK_APEX_VERSION,
+                                                TEST_FCM_TOKEN)))
                 .get();
 
         // THEN the response is unsuccessful
@@ -872,6 +965,8 @@ public final  class DeviceCheckinClientImplTest {
             public void getDeviceCheckinStatus(GetDeviceCheckinStatusRequest req,
                     StreamObserver<GetDeviceCheckinStatusResponse> responseObserver) {
                 mReceivedFcmToken = req.getFcmRegistrationToken();
+                mReceivedDeviceLocale = req.getDeviceLocale();
+                mReceivedDeviceLockApexVersion = req.getApexVersion();
                 GetDeviceCheckinStatusResponse response = GetDeviceCheckinStatusResponse
                         .newBuilder()
                         .build();
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInHelperTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInHelperTest.java
index 74f0e790..c91a51fb 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInHelperTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInHelperTest.java
@@ -40,6 +40,7 @@ import static org.mockito.Mockito.when;
 import static org.robolectric.annotation.LooperMode.Mode.LEGACY;
 
 import android.content.Intent;
+import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.net.NetworkRequest;
 import android.os.SystemClock;
@@ -117,6 +118,9 @@ public final class DeviceCheckInHelperTest {
     );
     static final int DEVICE_ID_TYPE_BITMAP =
             (1 << DEVICE_ID_TYPE_IMEI) | (1 << DEVICE_ID_TYPE_MEID);
+    static final String FAKE_APEX_PACKAGE = "fake_apex";
+    static final long APEX_VERSION = 1111;
+    static final String DEVICE_LOCALE = "en-US";
 
     private FinalizationController mFinalizationController;
     private DeviceCheckInHelper mHelper;
@@ -159,8 +163,6 @@ public final class DeviceCheckInHelperTest {
 
     @Test
     public void getDeviceAvailableUniqueIds_shouldReturnAllAvailableUniqueIds() {
-        mPackageManager.setSystemFeature(PackageManager.FEATURE_TELEPHONY_GSM,
-                /* supported= */ true);
         mPackageManager.setSystemFeature(PackageManager.FEATURE_TELEPHONY_CDMA,
                 /* supported= */ true);
         mTelephonyManager.setActiveModemCount(TOTAL_SLOT_COUNT);
@@ -307,6 +309,26 @@ public final class DeviceCheckInHelperTest {
         verify(mScheduler).scheduleRetryCheckInWork(eq(Duration.ZERO));
     }
 
+    @Test
+    public void getDeviceLockApexVersion_missingPackageName_shouldReturnZero() {
+        assertThat(mHelper.getDeviceLockApexVersion("non_existent_package")).isEqualTo(0);
+    }
+
+    @Test
+    public void getDeviceLockApexVersion_validPackageName_returnsVersion() {
+        PackageInfo packageInfo = new PackageInfo();
+        packageInfo.setLongVersionCode(APEX_VERSION);
+        packageInfo.packageName = FAKE_APEX_PACKAGE;
+        packageInfo.isApex = true;
+        mPackageManager.installPackage(packageInfo);
+        assertThat(mHelper.getDeviceLockApexVersion(FAKE_APEX_PACKAGE)).isEqualTo(APEX_VERSION);
+    }
+
+    @Test
+    public void getDeviceLocale_returnsDefaultLocale() {
+        assertThat(mHelper.getDeviceLocale()).isEqualTo(DEVICE_LOCALE);
+    }
+
     private void assertNetworkRequestCapabilities(NetworkRequest networkRequest) {
         assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_RESTRICTED)).isTrue();
         assertThat(networkRequest.hasCapability(NET_CAPABILITY_TRUSTED)).isTrue();
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorkerTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorkerTest.java
index d3f793f6..f637e257 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorkerTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/DeviceCheckInWorkerTest.java
@@ -24,6 +24,7 @@ import static com.google.common.truth.Truth.assertThat;
 
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.verify;
@@ -69,6 +70,9 @@ public class DeviceCheckInWorkerTest {
     public static final ArraySet<DeviceId> EMPTY_DEVICE_IDS = new ArraySet<>(new DeviceId[]{});
     public static final String TEST_CARRIER_INFO = "1234567890";
     public static final String EMPTY_CARRIER_INFO = "";
+    public static final String TEST_DEVICE_LOCALE = "en-US";
+    public static final String EMPTY_DEVICE_LOCALE = "";
+    public static final long TEST_DEVICE_LOCK_APEX_VERSION = 1234567890;
     @Rule
     public final MockitoRule mMocks = MockitoJUnit.rule();
     @Mock
@@ -91,7 +95,8 @@ public class DeviceCheckInWorkerTest {
         when(mFcmRegistrationTokenProvider.getFcmRegistrationToken()).thenReturn(
                 mContext.getFcmRegistrationToken());
         when(mClient.getDeviceCheckInStatus(
-                eq(TEST_DEVICE_IDS), anyString(), any())).thenReturn(mResponse);
+                        eq(TEST_DEVICE_IDS), anyString(), anyString(), anyLong(), any()))
+                .thenReturn(mResponse);
         mWorker = TestListenableWorkerBuilder.from(
                         mContext, DeviceCheckInWorker.class)
                 .setWorkerFactory(
@@ -119,6 +124,8 @@ public class DeviceCheckInWorkerTest {
         // GIVEN all device info available
         setDeviceIdAvailability(/* isAvailable= */ true);
         setCarrierInfoAvailability(/* isAvailable= */ true);
+        setDeviceLocaleAvailability(/* isAvailable= */ true);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ true);
 
         // GIVEN check-in response is successful
         setUpSuccessfulCheckInResponse(/* isHandleable= */ true);
@@ -138,6 +145,8 @@ public class DeviceCheckInWorkerTest {
         // GIVEN all device info available
         setDeviceIdAvailability(/* isAvailable= */ true);
         setCarrierInfoAvailability(/* isAvailable= */ true);
+        setDeviceLocaleAvailability(/* isAvailable= */ true);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ true);
 
         // GIVEN check-in response is successful
         setUpSuccessfulCheckInResponse(/* isHandleable= */ false);
@@ -157,6 +166,8 @@ public class DeviceCheckInWorkerTest {
         // GIVEN all device info available
         setDeviceIdAvailability(/* isAvailable= */ true);
         setCarrierInfoAvailability(/* isAvailable= */ true);
+        setDeviceLocaleAvailability(/* isAvailable= */ true);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ true);
 
         // GIVEN check-in response has recoverable failure.
         setUpFailedCheckInResponse(/* isRecoverable= */ true);
@@ -176,6 +187,8 @@ public class DeviceCheckInWorkerTest {
         // GIVEN all device info available
         setDeviceIdAvailability(/* isAvailable= */ true);
         setCarrierInfoAvailability(/* isAvailable= */ true);
+        setDeviceLocaleAvailability(/* isAvailable= */ true);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ true);
 
         // GIVEN check-in response has non-recoverable failure.
         setUpFailedCheckInResponse(/* isRecoverable= */ false);
@@ -201,13 +214,20 @@ public class DeviceCheckInWorkerTest {
         // GIVEN only device ids available
         setDeviceIdAvailability(/* isAvailable= */ true);
         setCarrierInfoAvailability(/* isAvailable= */ false);
+        setDeviceLocaleAvailability(/* isAvailable= */ true);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ true);
 
         // WHEN work runs
         Futures.getUnchecked(mWorker.startWork());
 
         // THEN check-in is requested
-        verify(mClient).getDeviceCheckInStatus(eq(TEST_DEVICE_IDS), eq(EMPTY_CARRIER_INFO),
-                eq(TEST_FCM_TOKEN));
+        verify(mClient)
+                .getDeviceCheckInStatus(
+                        eq(TEST_DEVICE_IDS),
+                        eq(EMPTY_CARRIER_INFO),
+                        eq(TEST_DEVICE_LOCALE),
+                        eq(TEST_DEVICE_LOCK_APEX_VERSION),
+                        eq(TEST_FCM_TOKEN));
     }
 
     @Test
@@ -218,13 +238,20 @@ public class DeviceCheckInWorkerTest {
         // GIVEN only device ids available
         setDeviceIdAvailability(/* isAvailable= */ false);
         setCarrierInfoAvailability(/* isAvailable= */ false);
+        setDeviceLocaleAvailability(/* isAvailable= */ true);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ true);
 
         // WHEN work runs
         Futures.getUnchecked(mWorker.startWork());
 
         // THEN check-in is not requested
-        verify(mClient, never()).getDeviceCheckInStatus(eq(TEST_DEVICE_IDS), eq(EMPTY_CARRIER_INFO),
-                eq(TEST_FCM_TOKEN));
+        verify(mClient, never())
+                .getDeviceCheckInStatus(
+                        eq(TEST_DEVICE_IDS),
+                        eq(EMPTY_CARRIER_INFO),
+                        eq(TEST_DEVICE_LOCALE),
+                        eq(TEST_DEVICE_LOCK_APEX_VERSION),
+                        eq(TEST_FCM_TOKEN));
 
         // THEN non enrolled device should be finalized
         verify(mFinalizationController).finalizeNotEnrolledDevice();
@@ -235,6 +262,8 @@ public class DeviceCheckInWorkerTest {
         // GIVEN FCM registration token unavailable
         setDeviceIdAvailability(/* isAvailable= */ true);
         setCarrierInfoAvailability(/* isAvailable= */ true);
+        setDeviceLocaleAvailability(/* isAvailable= */ true);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ true);
         when(mFcmRegistrationTokenProvider.getFcmRegistrationToken()).thenReturn(
                 Futures.immediateFuture(/* value= */ null));
 
@@ -251,6 +280,48 @@ public class DeviceCheckInWorkerTest {
         verify(mStatsLogger).logSuccessfulCheckIn();
     }
 
+    @Test
+    public void checkIn_apexVersionUnavailable_shouldAtLeastSendCheckInRequest() {
+        // GIVEN only device ids available
+        setDeviceIdAvailability(/* isAvailable= */ true);
+        setCarrierInfoAvailability(/* isAvailable= */ true);
+        setDeviceLocaleAvailability(/* isAvailable= */ true);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ false);
+
+        // WHEN work runs
+        Futures.getUnchecked(mWorker.startWork());
+
+        // THEN check-in is requested
+        verify(mClient)
+                .getDeviceCheckInStatus(
+                        eq(TEST_DEVICE_IDS),
+                        eq(TEST_CARRIER_INFO),
+                        eq(TEST_DEVICE_LOCALE),
+                        eq(0L),
+                        eq(TEST_FCM_TOKEN));
+    }
+
+    @Test
+    public void checkIn_deviceLocaleUnavailable_shouldAtLeastSendCheckInRequest() {
+        // GIVEN only device ids available
+        setDeviceIdAvailability(/* isAvailable= */ true);
+        setCarrierInfoAvailability(/* isAvailable= */ true);
+        setDeviceLocaleAvailability(/* isAvailable= */ false);
+        setDeviceLockApexVersionAvailability(/* isAvailable= */ true);
+
+        // WHEN work runs
+        Futures.getUnchecked(mWorker.startWork());
+
+        // THEN check-in is requested
+        verify(mClient)
+                .getDeviceCheckInStatus(
+                        eq(TEST_DEVICE_IDS),
+                        eq(TEST_CARRIER_INFO),
+                        eq(EMPTY_DEVICE_LOCALE),
+                        eq(TEST_DEVICE_LOCK_APEX_VERSION),
+                        eq(TEST_FCM_TOKEN));
+    }
+
     private void setDeviceIdAvailability(boolean isAvailable) {
         when(mHelper.getDeviceUniqueIds()).thenReturn(
                 isAvailable ? TEST_DEVICE_IDS : EMPTY_DEVICE_IDS);
@@ -261,6 +332,16 @@ public class DeviceCheckInWorkerTest {
                 isAvailable ? TEST_CARRIER_INFO : EMPTY_CARRIER_INFO);
     }
 
+    private void setDeviceLocaleAvailability(boolean isAvailable) {
+        when(mHelper.getDeviceLocale())
+                .thenReturn(isAvailable ? TEST_DEVICE_LOCALE : EMPTY_DEVICE_LOCALE);
+    }
+
+    private void setDeviceLockApexVersionAvailability(boolean isAvailable) {
+        when(mHelper.getDeviceLockApexVersion(anyString()))
+                .thenReturn(isAvailable ? TEST_DEVICE_LOCK_APEX_VERSION : 0);
+    }
+
     private void setUpSuccessfulCheckInResponse(boolean isHandleable) {
         when(mResponse.hasRecoverableError()).thenReturn(false);
         when(mResponse.isSuccessful()).thenReturn(true);
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/GetFcmTokenWorkerTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/GetFcmTokenWorkerTest.java
index b20ce5f6..85199fb4 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/GetFcmTokenWorkerTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/GetFcmTokenWorkerTest.java
@@ -58,10 +58,10 @@ public final class GetFcmTokenWorkerTest {
     private GetFcmTokenWorker mWorker;
     private TestDeviceLockControllerApplication mContext;
 
-    @ParameterizedRobolectricTestRunner.Parameter
+    @ParameterizedRobolectricTestRunner.Parameter(0)
     public String mFcmToken;
 
-    @ParameterizedRobolectricTestRunner.Parameter
+    @ParameterizedRobolectricTestRunner.Parameter(1)
     public Result mExpectedResult;
 
     /** Expected input and output for work result */
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/ReviewDeviceProvisionStateWorkerTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/ReviewDeviceProvisionStateWorkerTest.java
new file mode 100644
index 00000000..3c488780
--- /dev/null
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/ReviewDeviceProvisionStateWorkerTest.java
@@ -0,0 +1,279 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+package com.android.devicelockcontroller.provision.worker;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.app.AlarmManager;
+import android.app.PendingIntent;
+import android.content.Context;
+import android.content.Intent;
+import android.os.SystemClock;
+
+import androidx.annotation.NonNull;
+import androidx.test.core.app.ApplicationProvider;
+import androidx.work.Configuration;
+import androidx.work.ListenableWorker;
+import androidx.work.ListenableWorker.Result;
+import androidx.work.WorkInfo;
+import androidx.work.WorkManager;
+import androidx.work.WorkerFactory;
+import androidx.work.WorkerParameters;
+import androidx.work.testing.SynchronousExecutor;
+import androidx.work.testing.TestListenableWorkerBuilder;
+import androidx.work.testing.WorkManagerTestInitHelper;
+
+import com.android.devicelockcontroller.TestDeviceLockControllerApplication;
+import com.android.devicelockcontroller.policy.ProvisionStateController;
+import com.android.devicelockcontroller.provision.grpc.DeviceCheckInClient;
+import com.android.devicelockcontroller.receivers.ResumeProvisionReceiver;
+import com.android.devicelockcontroller.storage.UserParameters;
+
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.junit.MockitoJUnit;
+import org.mockito.junit.MockitoRule;
+import org.robolectric.RobolectricTestRunner;
+
+import java.time.Duration;
+import java.util.List;
+import java.util.Objects;
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.Executors;
+
+@RunWith(RobolectricTestRunner.class)
+public final class ReviewDeviceProvisionStateWorkerTest {
+
+    @Rule
+    public final MockitoRule mMocks = MockitoJUnit.rule();
+    @Mock
+    private DeviceCheckInClient mClient;
+    private ReviewDeviceProvisionStateWorker mWorker;
+    private TestDeviceLockControllerApplication mTestApp;
+
+    private WorkManager mWorkManager;
+
+    @Before
+    public void setUp() throws Exception {
+        mTestApp = ApplicationProvider.getApplicationContext();
+        WorkManagerTestInitHelper.initializeTestWorkManager(
+                mTestApp,
+                new Configuration.Builder()
+                        .setMinimumLoggingLevel(android.util.Log.DEBUG)
+                        .setExecutor(new SynchronousExecutor())
+                        .build());
+        mWorker =
+                TestListenableWorkerBuilder.from(mTestApp, ReviewDeviceProvisionStateWorker.class)
+                        .setWorkerFactory(
+                                new WorkerFactory() {
+                                    @Override
+                                    public ListenableWorker createWorker(
+                                            @NonNull Context context,
+                                            @NonNull String workerClassName,
+                                            @NonNull WorkerParameters workerParameters) {
+                                        return workerClassName.equals(
+                                                ReviewDeviceProvisionStateWorker.class.getName())
+                                                ? new ReviewDeviceProvisionStateWorker(
+                                                context,
+                                                workerParameters,
+                                                mClient,
+                                                MoreExecutors.listeningDecorator(
+                                                        Executors.newSingleThreadExecutor()))
+                                                : null;
+                                    }
+                                })
+                        .build();
+        mWorkManager = WorkManager.getInstance(mTestApp);
+    }
+
+    @Test
+    public void doWork_responseSuccessAndCancelJobs_whenProvisionStateSucceeded()
+            throws ExecutionException, InterruptedException {
+        ReviewDeviceProvisionStateWorker.scheduleDailyReview(mWorkManager);
+
+        Executors.newSingleThreadExecutor().submit(
+                () ->
+                        UserParameters.setProvisionState(
+                                mTestApp,
+                                ProvisionStateController.ProvisionState.PROVISION_SUCCEEDED))
+                .get();
+
+        Result jobStartResult = Futures.getUnchecked(mWorker.startWork());
+
+        assertThat(jobStartResult).isEqualTo(Result.success());
+        List<WorkInfo> workInfos = Futures.getUnchecked(mWorkManager.getWorkInfosForUniqueWork(
+                ReviewDeviceProvisionStateWorker.REVIEW_DEVICE_PROVISION_STATE_WORK_NAME));
+        assertThat(workInfos).hasSize(1);
+        assertThat(workInfos.get(0).getState()).isEqualTo(WorkInfo.State.CANCELLED);
+    }
+
+    @Test
+    public void scheduleDailyReview_shouldEnqueueJob() {
+        ReviewDeviceProvisionStateWorker.scheduleDailyReview(mWorkManager);
+
+        List<WorkInfo> workInfos = Futures.getUnchecked(mWorkManager.getWorkInfosForUniqueWork(
+                ReviewDeviceProvisionStateWorker.REVIEW_DEVICE_PROVISION_STATE_WORK_NAME));
+        assertThat(workInfos).hasSize(1);
+        assertThat(workInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
+        assertThat(workInfos.get(0).getTags())
+                .contains(
+                        "com.android.devicelockcontroller.provision.worker"
+                                + ".ReviewDeviceProvisionStateWorker");
+    }
+
+    @Test
+    public void doWork_responseSuccess_whenNoProvisionState() {
+        ReviewDeviceProvisionStateWorker.scheduleDailyReview(mWorkManager);
+
+        Result jobStartResult = Futures.getUnchecked(mWorker.startWork());
+
+        assertThat(jobStartResult).isEqualTo(Result.success());
+        List<WorkInfo> workInfos = Futures.getUnchecked(mWorkManager.getWorkInfosForUniqueWork(
+                ReviewDeviceProvisionStateWorker.REVIEW_DEVICE_PROVISION_STATE_WORK_NAME));
+        assertThat(workInfos).hasSize(1);
+        assertThat(workInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
+        assertThat(workInfos.get(0).getTags())
+                .contains(
+                        "com.android.devicelockcontroller.provision.worker"
+                                + ".ReviewDeviceProvisionStateWorker");
+    }
+
+    @Test
+    public void doWork_responseSuccess_whenProvisionStateInProgress()
+            throws ExecutionException, InterruptedException {
+        ReviewDeviceProvisionStateWorker.scheduleDailyReview(mWorkManager);
+        Executors.newSingleThreadExecutor().submit(() -> UserParameters.setProvisionState(
+                mTestApp,
+                ProvisionStateController.ProvisionState.PROVISION_IN_PROGRESS))
+                .get();
+
+        Result jobStartResult = Futures.getUnchecked(mWorker.startWork());
+
+        assertThat(jobStartResult).isEqualTo(Result.success());
+        List<WorkInfo> workInfos = Futures.getUnchecked(mWorkManager.getWorkInfosForUniqueWork(
+                ReviewDeviceProvisionStateWorker.REVIEW_DEVICE_PROVISION_STATE_WORK_NAME));
+        assertThat(workInfos).hasSize(1);
+        assertThat(workInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
+        assertThat(workInfos.get(0).getTags())
+                .contains(
+                        "com.android.devicelockcontroller.provision.worker"
+                                + ".ReviewDeviceProvisionStateWorker");
+    }
+
+    @Test
+    public void doWork_responseSuccess_whenProvisionStartedLessThanADay()
+            throws ExecutionException, InterruptedException {
+        ReviewDeviceProvisionStateWorker.scheduleDailyReview(mWorkManager);
+        Executors.newSingleThreadExecutor().submit(() ->
+                        UserParameters.setProvisioningStartTimeMillis(
+                                mTestApp,
+                                SystemClock.elapsedRealtime() - (long) (1000 * 60 * 60
+                                                * 23.90)))
+                .get();
+
+        Result jobStartResult = Futures.getUnchecked(mWorker.startWork());
+
+        assertThat(jobStartResult).isEqualTo(Result.success());
+        List<WorkInfo> workInfos = Futures.getUnchecked(mWorkManager.getWorkInfosForUniqueWork(
+                ReviewDeviceProvisionStateWorker.REVIEW_DEVICE_PROVISION_STATE_WORK_NAME));
+        assertThat(workInfos).hasSize(1);
+        assertThat(workInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
+        assertThat(workInfos.get(0).getTags())
+                .contains(
+                        "com.android.devicelockcontroller.provision.worker"
+                                + ".ReviewDeviceProvisionStateWorker");
+    }
+
+    @Test
+    public void doWork_responseSuccessCancelJobAndScheduleReportFailureJob_whenProvisionFailed()
+            throws ExecutionException, InterruptedException {
+        ReviewDeviceProvisionStateWorker.scheduleDailyReview(mWorkManager);
+        Executors.newSingleThreadExecutor()
+                .submit(
+                        () ->
+                                UserParameters.setProvisionState(
+                                        mTestApp,
+                                        ProvisionStateController.ProvisionState.PROVISION_FAILED))
+                .get();
+
+        Result jobStartResult = Futures.getUnchecked(mWorker.startWork());
+
+        assertThat(jobStartResult).isEqualTo(Result.success());
+        List<WorkInfo> reviewDeviceStateWorkInfos = Futures.getUnchecked(mWorkManager
+                .getWorkInfosForUniqueWork(
+                        ReviewDeviceProvisionStateWorker.REVIEW_DEVICE_PROVISION_STATE_WORK_NAME));
+        assertThat(reviewDeviceStateWorkInfos).hasSize(1);
+        assertThat(reviewDeviceStateWorkInfos.get(0).getState()).isEqualTo(
+                WorkInfo.State.CANCELLED);
+        assertThat(reviewDeviceStateWorkInfos.get(0).getTags())
+                .contains(
+                        "com.android.devicelockcontroller.provision.worker"
+                                + ".ReviewDeviceProvisionStateWorker");
+        List<WorkInfo> reportDeviceStateWorkInfos =
+                Futures.getUnchecked(
+                        mWorkManager.getWorkInfosForUniqueWork(
+                                ReportDeviceProvisionStateWorker.REPORT_PROVISION_STATE_WORK_NAME));
+        assertThat(reportDeviceStateWorkInfos).hasSize(1);
+        assertThat(reportDeviceStateWorkInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
+        assertThat(reportDeviceStateWorkInfos.get(0).getTags())
+                .contains(
+                        "com.android.devicelockcontroller.provision.worker"
+                                + ".ReportDeviceProvisionStateWorker");
+    }
+
+    @Test
+    public void doWork_responseSuccess_whenProvisionFailedAndAlarmScheduled()
+            throws ExecutionException, InterruptedException {
+        ReviewDeviceProvisionStateWorker.scheduleDailyReview(mWorkManager);
+        Executors.newSingleThreadExecutor().submit(() -> UserParameters.setProvisionState(
+                mTestApp,
+                ProvisionStateController.ProvisionState.PROVISION_FAILED))
+                .get();
+        long countDownBase = SystemClock.elapsedRealtime() + Duration.ofHours(4).toMillis();
+        AlarmManager alarmManager = mTestApp.getSystemService(AlarmManager.class);
+        PendingIntent pendingIntent =
+                PendingIntent.getBroadcast(
+                        mTestApp, /* ignored */
+                        0,
+                        new Intent(mTestApp, ResumeProvisionReceiver.class),
+                        PendingIntent.FLAG_ONE_SHOT | PendingIntent.FLAG_IMMUTABLE);
+        Objects.requireNonNull(alarmManager)
+                .setExactAndAllowWhileIdle(
+                        AlarmManager.ELAPSED_REALTIME_WAKEUP, countDownBase, pendingIntent);
+
+        Result jobStartResult = Futures.getUnchecked(mWorker.startWork());
+
+        assertThat(jobStartResult).isEqualTo(Result.success());
+        List<WorkInfo> workInfos =
+                Futures.getUnchecked(
+                        mWorkManager.getWorkInfosForUniqueWork(
+                                ReviewDeviceProvisionStateWorker
+                                        .REVIEW_DEVICE_PROVISION_STATE_WORK_NAME));
+        assertThat(workInfos).hasSize(1);
+        assertThat(workInfos.get(0).getState()).isEqualTo(WorkInfo.State.ENQUEUED);
+        assertThat(workInfos.get(0).getTags()).contains(
+                "com.android.devicelockcontroller.provision.worker"
+                        + ".ReviewDeviceProvisionStateWorker");
+    }
+}
diff --git a/OWNERS b/OWNERS
index 0418bdbd..7ae5c0a2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,7 +1,3 @@
-# Bug component: 1311720
+# Bug component: 1688676
 
-rajekumar@google.com
-amosbianchi@google.com
-zzhen@google.com
-kevhan@google.com
 dmusila@google.com
diff --git a/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java b/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
index ee384dff..309e090f 100644
--- a/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
+++ b/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
@@ -598,11 +598,6 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
         });
     }
 
-    private boolean hasGsm() {
-        return mContext.getPackageManager().hasSystemFeature(
-                PackageManager.FEATURE_TELEPHONY_GSM);
-    }
-
     private boolean hasCdma() {
         return mContext.getPackageManager().hasSystemFeature(
                 PackageManager.FEATURE_TELEPHONY_CDMA);
@@ -624,7 +619,7 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
         List<String> imeiList = new ArrayList<String>();
         List<String> meidList = new ArrayList<String>();
 
-        if (hasGsm() && ((deviceIdTypeBitmap & (1 << DEVICE_ID_TYPE_IMEI)) != 0)) {
+        if ((deviceIdTypeBitmap & (1 << DEVICE_ID_TYPE_IMEI)) != 0) {
             for (int i = 0; i < activeModemCount; i++) {
                 String imei = mTelephonyManager.getImei(i);
                 if (!TextUtils.isEmpty(imei)) {
diff --git a/tests/unittests/Android.bp b/tests/unittests/Android.bp
index 9c44d906..4aad12b5 100644
--- a/tests/unittests/Android.bp
+++ b/tests/unittests/Android.bp
@@ -42,6 +42,5 @@ android_robolectric_test {
         "framework-annotations-lib",
     ],
     instrumentation_for: "DeviceLockTestApp",
-    upstream: true,
     strict_mode: false,
 }
diff --git a/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java b/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
index 48ebeafc..72f7a085 100644
--- a/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
+++ b/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
@@ -175,8 +175,6 @@ public final class DeviceLockServiceImplTest {
         final String testImei = "983402979622353";
         mShadowTelephonyManager.setActiveModemCount(1);
         mShadowTelephonyManager.setImei(/* slotIndex= */ 0, testImei);
-        mShadowPackageManager.setSystemFeature(PackageManager.FEATURE_TELEPHONY_GSM,
-                /* supported= */ true);
 
         // GIVEN a successful service call to DLC app
         doAnswer((Answer<Void>) invocation -> {
```

