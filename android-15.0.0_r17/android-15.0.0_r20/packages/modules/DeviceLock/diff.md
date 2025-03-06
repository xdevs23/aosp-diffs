```diff
diff --git a/DeviceLockController/AndroidManifestBase.xml b/DeviceLockController/AndroidManifestBase.xml
index 42339557..fe9d4ae5 100644
--- a/DeviceLockController/AndroidManifestBase.xml
+++ b/DeviceLockController/AndroidManifestBase.xml
@@ -263,6 +263,10 @@
             </intent-filter>
         </service>
 
+        <service
+            android:name="com.android.devicelockcontroller.services.SetupWizardCompletionTimeoutJobService"
+            android:permission="android.permission.BIND_JOB_SERVICE"/>
+
     </application>
 
 </manifest>
diff --git a/DeviceLockController/res/values-ca/strings.xml b/DeviceLockController/res/values-ca/strings.xml
index 16076356..b699d008 100644
--- a/DeviceLockController/res/values-ca/strings.xml
+++ b/DeviceLockController/res/values-ca/strings.xml
@@ -90,7 +90,7 @@
     <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
     <string name="settings_safe_mode" msgid="3035228015586375153">"Reiniciar el dispositiu en mode segur"</string>
     <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
-    <string name="settings_developer_options" msgid="880701002025216672">"Utilitzar opcions per a desenvolupadors"</string>
+    <string name="settings_developer_options" msgid="880701002025216672">"Opcions per a desenvolupadors"</string>
     <string name="settings_developer_options_preference_key" msgid="6807036808722582954">"settings_developer_options_preference_key"</string>
     <string name="settings_credit_provider_capabilities_category" msgid="1274440595211820868">"Si hi ha cap error amb el dispositiu, <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> pot:"</string>
     <string name="settings_credit_provider_capabilities_category_preference_key" msgid="4571685720898641262">"settings_credit_provider_capabilities_category_preference_key"</string>
diff --git a/DeviceLockController/res/values-gl/strings.xml b/DeviceLockController/res/values-gl/strings.xml
index f9521744..124327fb 100644
--- a/DeviceLockController/res/values-gl/strings.xml
+++ b/DeviceLockController/res/values-gl/strings.xml
@@ -90,7 +90,7 @@
     <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
     <string name="settings_safe_mode" msgid="3035228015586375153">"Reiniciar o dispositivo no modo seguro"</string>
     <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
-    <string name="settings_developer_options" msgid="880701002025216672">"Usar as opcións de programador"</string>
+    <string name="settings_developer_options" msgid="880701002025216672">"Usar as opcións de programación"</string>
     <string name="settings_developer_options_preference_key" msgid="6807036808722582954">"settings_developer_options_preference_key"</string>
     <string name="settings_credit_provider_capabilities_category" msgid="1274440595211820868">"En caso de problema co dispositivo, <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> pode:"</string>
     <string name="settings_credit_provider_capabilities_category_preference_key" msgid="4571685720898641262">"settings_credit_provider_capabilities_category_preference_key"</string>
diff --git a/DeviceLockController/res/values-hr/strings.xml b/DeviceLockController/res/values-hr/strings.xml
index 9a63a47c..140acf70 100644
--- a/DeviceLockController/res/values-hr/strings.xml
+++ b/DeviceLockController/res/values-hr/strings.xml
@@ -90,7 +90,7 @@
     <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
     <string name="settings_safe_mode" msgid="3035228015586375153">"ponovno pokrenuti uređaj u sigurnom načinu rada"</string>
     <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
-    <string name="settings_developer_options" msgid="880701002025216672">"koristiti opcije za razvojne programere"</string>
+    <string name="settings_developer_options" msgid="880701002025216672">"Koristi opcije za razvojne programere"</string>
     <string name="settings_developer_options_preference_key" msgid="6807036808722582954">"settings_developer_options_preference_key"</string>
     <string name="settings_credit_provider_capabilities_category" msgid="1274440595211820868">"U slučaju pogreške s uređajem <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> može:"</string>
     <string name="settings_credit_provider_capabilities_category_preference_key" msgid="4571685720898641262">"settings_credit_provider_capabilities_category_preference_key"</string>
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerApplication.java b/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerApplication.java
index 10e2d831..ef69e518 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerApplication.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerApplication.java
@@ -28,6 +28,7 @@ import androidx.work.Configuration;
 import androidx.work.DelegatingWorkerFactory;
 import androidx.work.ListenableWorker;
 
+import com.android.devicelockcontroller.common.DeviceLockConstants;
 import com.android.devicelockcontroller.policy.DevicePolicyController;
 import com.android.devicelockcontroller.policy.DeviceStateController;
 import com.android.devicelockcontroller.policy.FinalizationController;
@@ -145,6 +146,8 @@ public class DeviceLockControllerApplication extends Application implements
                         (t) -> mWorkManagerExceptionHandler
                                 .initializationExceptionHandler(this, t))
                 .setTaskExecutor(mWorkManagerExceptionHandler.getWorkManagerTaskExecutor())
+                .setJobSchedulerJobIdRange(/* minJobSchedulerId= */ 0,
+                        DeviceLockConstants.WORK_MANAGER_MAX_JOB_SCHEDULER_ID)
                 .build();
     }
 
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java b/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
index 356d7ae8..05f8c555 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/common/DeviceLockConstants.java
@@ -30,6 +30,15 @@ public final class DeviceLockConstants {
     /** Device reset count down minute when non-mandatory provision fails */
     public static final int NON_MANDATORY_PROVISION_DEVICE_RESET_COUNTDOWN_MINUTE = 30;
 
+    // JobSchedule Job IDs have to be unique across the same UID, so they need to be centrally
+    // managed.
+
+    /** Max value for Job ID for use by WorkManager */
+    public static final int WORK_MANAGER_MAX_JOB_SCHEDULER_ID = 100_000;
+
+    /** Job Id for Setup Wizard Timeout Job */
+    public static final int SETUP_WIZARD_TIMEOUT_JOB_ID = WORK_MANAGER_MAX_JOB_SCHEDULER_ID + 1;
+
     // Constants related to unique device identifiers.
     @Retention(RetentionPolicy.SOURCE)
     @IntDef(value = {
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
index 96544140..a7cd1462 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionStateControllerImpl.java
@@ -43,8 +43,8 @@ import androidx.annotation.NonNull;
 import androidx.annotation.VisibleForTesting;
 
 import com.android.devicelockcontroller.SystemDeviceLockManagerImpl;
-import com.android.devicelockcontroller.provision.worker.SetupWizardCompletionTimeoutWorker;
 import com.android.devicelockcontroller.receivers.LockedBootCompletedReceiver;
+import com.android.devicelockcontroller.services.SetupWizardCompletionTimeoutJobService;
 import com.android.devicelockcontroller.stats.StatsLoggerProvider;
 import com.android.devicelockcontroller.storage.GlobalParametersClient;
 import com.android.devicelockcontroller.storage.UserParameters;
@@ -268,8 +268,8 @@ public final class ProvisionStateControllerImpl implements ProvisionStateControl
                 state -> {
                     if (state == UNPROVISIONED) {
                         if (!isUserSetupComplete()) {
-                            SetupWizardCompletionTimeoutWorker
-                                    .scheduleSetupWizardCompletionTimeoutWork(mContext);
+                            SetupWizardCompletionTimeoutJobService
+                                    .scheduleSetupWizardCompletionTimeoutJob(mContext);
                         }
                         return checkReadyToStartProvisioning();
                     } else {
@@ -281,7 +281,7 @@ public final class ProvisionStateControllerImpl implements ProvisionStateControl
 
     @Override
     public ListenableFuture<Void> onUserSetupCompleted() {
-        SetupWizardCompletionTimeoutWorker.cancelSetupWizardCompletionTimeoutWork(mContext);
+        SetupWizardCompletionTimeoutJobService.cancelSetupWizardCompletionTimeoutJob(mContext);
         return checkReadyToStartProvisioning();
     }
 
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/SetupWizardCompletionTimeoutWorker.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/SetupWizardCompletionTimeoutWorker.java
deleted file mode 100644
index 90719793..00000000
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/SetupWizardCompletionTimeoutWorker.java
+++ /dev/null
@@ -1,149 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.devicelockcontroller.provision.worker;
-
-import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
-
-import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent.PROVISION_READY;
-import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.UNPROVISIONED;
-
-import android.content.Context;
-import android.net.NetworkRequest;
-import android.provider.Settings;
-
-import androidx.annotation.NonNull;
-import androidx.work.Constraints;
-import androidx.work.ExistingWorkPolicy;
-import androidx.work.ListenableWorker;
-import androidx.work.NetworkType;
-import androidx.work.OneTimeWorkRequest;
-import androidx.work.WorkManager;
-import androidx.work.WorkerParameters;
-
-import com.android.devicelockcontroller.policy.PolicyObjectsProvider;
-import com.android.devicelockcontroller.policy.ProvisionStateController;
-import com.android.devicelockcontroller.storage.GlobalParametersClient;
-import com.android.devicelockcontroller.storage.UserParameters;
-import com.android.devicelockcontroller.util.LogUtil;
-
-import com.google.common.util.concurrent.Futures;
-import com.google.common.util.concurrent.ListenableFuture;
-import com.google.common.util.concurrent.ListeningExecutorService;
-
-import java.util.concurrent.TimeUnit;
-
-public final class SetupWizardCompletionTimeoutWorker extends ListenableWorker {
-    private static final String TAG = "SetupWizardCompletionTimeoutWorker";
-
-    private static final String SETUP_WIZARD_COMPLETION_TIMEOUT_WORK_NAME =
-            "setup-wizard-completion-timeout";
-    private static final long TIMEOUT_MINUTES = 60;
-
-    private final ListeningExecutorService mListeningExecutorService;
-    private final Context mAppContext;
-
-    public SetupWizardCompletionTimeoutWorker(@NonNull Context appContext,
-            @NonNull WorkerParameters workerParams, ListeningExecutorService executorService) {
-        super(appContext, workerParams);
-        mAppContext = appContext;
-        mListeningExecutorService = executorService;
-    }
-
-    @NonNull
-    @Override
-    public ListenableFuture<Result> startWork() {
-        // If SUW is already finished, there's nothing left to do.
-        if (isUserSetupComplete()) {
-            return Futures.immediateFuture(Result.success());
-        }
-        // SUW did not finished in the allotted time. If the device is still unprovisioned
-        // and provisioning information is ready, start the provisioning flow.
-
-        PolicyObjectsProvider policyObjects =
-                (PolicyObjectsProvider) mAppContext;
-        ProvisionStateController provisionStateController =
-                policyObjects.getProvisionStateController();
-
-        return Futures.transformAsync(provisionStateController.getState(),
-                state -> {
-                    UserParameters.setSetupWizardTimedOut(mAppContext);
-
-                    if (state != UNPROVISIONED) {
-                        return Futures.immediateFuture(Result.success());
-                    }
-                    GlobalParametersClient globalParametersClient =
-                            GlobalParametersClient.getInstance();
-                    return Futures.transformAsync(globalParametersClient.isProvisionReady(),
-                            isReady -> {
-                                if (isReady) {
-                                    LogUtil.i(TAG, "Starting provisioning flow since "
-                                            + "SUW did not complete in " + TIMEOUT_MINUTES
-                                            + " minutes");
-                                    return Futures.transform(provisionStateController
-                                            .setNextStateForEvent(PROVISION_READY),
-                                            unused -> Result.success(), mListeningExecutorService);
-                                }
-                                return Futures.immediateFuture(Result.success());
-                            },
-                            mListeningExecutorService);
-                }, mListeningExecutorService);
-    }
-
-    /**
-     * Schedule a worker that starts the provisioning flow in case SetupWizard does not complete
-     * in the allotted time.
-     */
-    public static void scheduleSetupWizardCompletionTimeoutWork(Context context) {
-        NetworkRequest request = new NetworkRequest.Builder()
-                .addCapability(NET_CAPABILITY_NOT_RESTRICTED)
-                .addCapability(NET_CAPABILITY_TRUSTED)
-                .addCapability(NET_CAPABILITY_INTERNET)
-                .addCapability(NET_CAPABILITY_NOT_VPN)
-                .build();
-
-        // Beside setting a delay, we also require network connectivity since for the case of
-        // mandatory provisioning, the setup flow cannot be interrupted and eventual errors
-        // due to network unavailable would result in the device being reset.
-        OneTimeWorkRequest workRequest =
-                new OneTimeWorkRequest.Builder(SetupWizardCompletionTimeoutWorker.class)
-                        .setInitialDelay(TIMEOUT_MINUTES, TimeUnit.MINUTES)
-                        .setConstraints(new Constraints.Builder().setRequiredNetworkRequest(
-                                request, NetworkType.CONNECTED).build())
-                        .build();
-
-        WorkManager.getInstance(context)
-                .enqueueUniqueWork(SETUP_WIZARD_COMPLETION_TIMEOUT_WORK_NAME,
-                        ExistingWorkPolicy.REPLACE, workRequest);
-    }
-
-    /**
-     * Cancel the worker that starts the provisioning flow if SetupWizard does not complete in
-     * the allotted time.
-     */
-    public static void cancelSetupWizardCompletionTimeoutWork(Context context) {
-        WorkManager.getInstance(context)
-                .cancelUniqueWork(SETUP_WIZARD_COMPLETION_TIMEOUT_WORK_NAME);
-    }
-
-    private boolean isUserSetupComplete() {
-        return Settings.Secure.getInt(
-                mAppContext.getContentResolver(), Settings.Secure.USER_SETUP_COMPLETE, 0) != 0;
-    }
-}
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/UpdateFcmTokenWorker.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/UpdateFcmTokenWorker.java
new file mode 100644
index 00000000..b3455ea9
--- /dev/null
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/UpdateFcmTokenWorker.java
@@ -0,0 +1,107 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+import static com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse.FcmTokenResult.RESULT_FAILURE;
+import static com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse.FcmTokenResult.RESULT_SUCCESS;
+import static com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse.FcmTokenResult.RESULT_UNSPECIFIED;
+
+import android.content.Context;
+
+import androidx.annotation.NonNull;
+import androidx.annotation.VisibleForTesting;
+import androidx.work.WorkerParameters;
+
+import com.android.devicelockcontroller.FcmRegistrationTokenProvider;
+import com.android.devicelockcontroller.provision.grpc.DeviceCheckInClient;
+import com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse;
+import com.android.devicelockcontroller.util.LogUtil;
+
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+
+import java.time.Duration;
+
+public final class UpdateFcmTokenWorker extends AbstractCheckInWorker {
+    public static final Duration UPDATE_FCM_TOKEN_WORKER_BACKOFF_DELAY = Duration.ofMinutes(30);
+    public static final String UPDATE_FCM_TOKEN_WORK_NAME = "update-fcm-token";
+
+    private final AbstractDeviceCheckInHelper mCheckInHelper;
+    private final FcmRegistrationTokenProvider mFcmRegistrationTokenProvider;
+
+    public UpdateFcmTokenWorker(@NonNull Context context,
+            @NonNull WorkerParameters workerParameters,
+            ListeningExecutorService executorService) {
+        this(context, workerParameters, new DeviceCheckInHelper(context),
+                (FcmRegistrationTokenProvider) context.getApplicationContext(), /* client= */ null,
+                executorService);
+    }
+
+    @VisibleForTesting
+    UpdateFcmTokenWorker(@NonNull Context context, @NonNull WorkerParameters workerParameters,
+            AbstractDeviceCheckInHelper helper,  FcmRegistrationTokenProvider tokenProvider,
+            DeviceCheckInClient client, ListeningExecutorService executorService) {
+        super(context, workerParameters, client, executorService);
+        mFcmRegistrationTokenProvider = tokenProvider;
+        mCheckInHelper = helper;
+    }
+
+    @NonNull
+    @Override
+    public ListenableFuture<Result> startWork() {
+        return Futures.transformAsync(
+                mExecutorService.submit(mCheckInHelper::getDeviceUniqueIds),
+                deviceIds -> {
+                    if (deviceIds.isEmpty()) {
+                        LogUtil.w(TAG, "Update fcm failed. No device identifier available!");
+                        return Futures.immediateFuture(Result.failure());
+                    }
+                    ListenableFuture<String> fcmRegistrationToken =
+                            mFcmRegistrationTokenProvider.getFcmRegistrationToken();
+                    return Futures.whenAllSucceed(mClient, fcmRegistrationToken).call(() -> {
+                        DeviceCheckInClient client = Futures.getDone(mClient);
+                        String fcmToken = Futures.getDone(fcmRegistrationToken);
+                        UpdateFcmTokenGrpcResponse response = client.updateFcmToken(
+                                deviceIds, fcmToken);
+                        if (response.hasRecoverableError()) {
+                            LogUtil.w(TAG, "Update FCM failed w/ recoverable error " + response
+                                    + "\nRetrying...");
+                            return Result.retry();
+                        }
+                        if (!response.isSuccessful()) {
+                            LogUtil.d(TAG, "Update FCM failed: " + response);
+                            return Result.failure();
+                        }
+                        if (response.getFcmTokenResult() != RESULT_SUCCESS) {
+                            if (response.getFcmTokenResult() == RESULT_FAILURE) {
+                                // This can happen if there is a failed precondition e.g.
+                                // device is finalized or it hasn't checked in yet. In both cases,
+                                // we should not retry the job
+                                LogUtil.e(TAG, "Update FCM got successful response but server "
+                                        + "indicated failure");
+                            } else if (response.getFcmTokenResult() == RESULT_UNSPECIFIED) {
+                                LogUtil.e(TAG, "Update FCM got successful response but it was "
+                                        + "unspecified");
+                            }
+                            return Result.failure();
+                        }
+                        return Result.success();
+                    }, mExecutorService);
+                }, mExecutorService);
+    }
+}
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/services/SetupWizardCompletionTimeoutJobService.java b/DeviceLockController/src/com/android/devicelockcontroller/services/SetupWizardCompletionTimeoutJobService.java
new file mode 100644
index 00000000..5ba3ed0e
--- /dev/null
+++ b/DeviceLockController/src/com/android/devicelockcontroller/services/SetupWizardCompletionTimeoutJobService.java
@@ -0,0 +1,204 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.android.devicelockcontroller.services;
+
+import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
+import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
+import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
+import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
+
+import static com.android.devicelockcontroller.common.DeviceLockConstants.SETUP_WIZARD_TIMEOUT_JOB_ID;
+import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent.PROVISION_READY;
+import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.UNPROVISIONED;
+
+import android.app.job.JobInfo;
+import android.app.job.JobParameters;
+import android.app.job.JobScheduler;
+import android.app.job.JobService;
+import android.content.ComponentName;
+import android.content.Context;
+import android.net.NetworkRequest;
+import android.provider.Settings;
+
+import com.android.devicelockcontroller.policy.PolicyObjectsProvider;
+import com.android.devicelockcontroller.policy.ProvisionStateController;
+import com.android.devicelockcontroller.storage.GlobalParametersClient;
+import com.android.devicelockcontroller.storage.UserParameters;
+import com.android.devicelockcontroller.util.LogUtil;
+
+import com.google.common.annotations.VisibleForTesting;
+import com.google.common.util.concurrent.FutureCallback;
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.ListenableFuture;
+import com.google.common.util.concurrent.ListeningExecutorService;
+import com.google.common.util.concurrent.MoreExecutors;
+
+import java.util.concurrent.Executors;
+import java.util.concurrent.TimeUnit;
+
+public final class SetupWizardCompletionTimeoutJobService extends JobService {
+    private static final String TAG = "SetupWizardCompletionTimeoutJobService";
+    private static final long TIMEOUT_MINUTES = 60;
+
+    private final ListeningExecutorService mListeningExecutorService =
+            MoreExecutors.listeningDecorator(Executors.newCachedThreadPool());
+    private final Context mContext;
+
+    @VisibleForTesting
+    ListenableFuture<Void> mFuture;
+
+    /**
+     * Create an instance of the job.
+     */
+    public SetupWizardCompletionTimeoutJobService() {
+        super();
+        mContext = this;
+    }
+
+    @VisibleForTesting
+    SetupWizardCompletionTimeoutJobService(Context context) {
+        super();
+        mContext = context;
+    }
+
+    @Override
+    public boolean onStartJob(JobParameters params) {
+        LogUtil.i(TAG, "Starting job");
+
+        // If SUW is already finished, there's nothing left to do.
+        if (isUserSetupComplete()) {
+            return false;
+        }
+
+        // SUW did not finished in the allotted time. If the device is still unprovisioned
+        // and provisioning information is ready, start the provisioning flow.
+        Context appContext = mContext.getApplicationContext();
+        PolicyObjectsProvider policyObjects =
+                (PolicyObjectsProvider) appContext;
+        ProvisionStateController provisionStateController =
+                policyObjects.getProvisionStateController();
+
+        mFuture = Futures.transformAsync(provisionStateController.getState(),
+                state -> {
+                    UserParameters.setSetupWizardTimedOut(appContext);
+
+                    if (state != UNPROVISIONED) {
+                        return Futures.immediateVoidFuture();
+                    }
+
+                    GlobalParametersClient globalParametersClient =
+                            GlobalParametersClient.getInstance();
+                    return Futures.transformAsync(globalParametersClient.isProvisionReady(),
+                        isReady -> {
+                            if (isReady) {
+                                LogUtil.i(TAG, "Starting provisioning flow since "
+                                        + "SUW did not complete in " + TIMEOUT_MINUTES
+                                        + " minutes");
+                                return Futures.transform(provisionStateController
+                                        .setNextStateForEvent(PROVISION_READY),
+                                        unused -> null,
+                                        mListeningExecutorService);
+                            }
+                            return Futures.immediateVoidFuture();
+                        }, mListeningExecutorService);
+                }, mListeningExecutorService);
+
+        Futures.addCallback(mFuture, new FutureCallback<>() {
+            @Override
+            public void onSuccess(Void result) {
+                LogUtil.i(TAG, "Job completed");
+
+                jobFinished(params, /* wantsReschedule= */ false);
+            }
+
+            @Override
+            public void onFailure(Throwable t) {
+                LogUtil.e(TAG, "Job failed", t);
+
+                jobFinished(params, /* wantsReschedule= */ true);
+            }
+        }, mListeningExecutorService);
+
+        return true;
+    }
+
+    @Override
+    public boolean onStopJob(JobParameters params) {
+        LogUtil.i(TAG, "Stopping job");
+
+        if (mFuture != null) {
+            mFuture.cancel(true);
+        }
+
+        return true;
+    }
+
+    /**
+     * Schedule a job that starts the provisioning flow in case SetupWizard does not complete
+     * in the allotted time.
+     */
+    public static void scheduleSetupWizardCompletionTimeoutJob(Context context) {
+        JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
+
+        if (jobScheduler.getPendingJob(SETUP_WIZARD_TIMEOUT_JOB_ID) != null) {
+            LogUtil.w(TAG, "Job already scheduled");
+
+            return;
+        }
+
+        ComponentName componentName =
+                new ComponentName(context, SetupWizardCompletionTimeoutJobService.class);
+        long delayMillis = TimeUnit.MINUTES.toMillis(TIMEOUT_MINUTES);
+
+        NetworkRequest request = new NetworkRequest.Builder()
+                .addCapability(NET_CAPABILITY_NOT_RESTRICTED)
+                .addCapability(NET_CAPABILITY_TRUSTED)
+                .addCapability(NET_CAPABILITY_INTERNET)
+                .addCapability(NET_CAPABILITY_NOT_VPN)
+                .build();
+
+        JobInfo jobInfo = new JobInfo.Builder(SETUP_WIZARD_TIMEOUT_JOB_ID, componentName)
+                .setMinimumLatency(delayMillis)
+                .setRequiredNetwork(request)
+                .build();
+
+        int schedulingResult = jobScheduler.schedule(jobInfo);
+
+        if (schedulingResult == JobScheduler.RESULT_SUCCESS) {
+            LogUtil.i(TAG, "Job scheduled");
+        } else {
+            LogUtil.e(TAG, "Failed to schedule job");
+        }
+    }
+
+    /**
+     * Cancel the job that starts the provisioning flow if SetupWizard does not complete in
+     * the allotted time.
+     */
+    public static void cancelSetupWizardCompletionTimeoutJob(Context context) {
+        JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
+
+        jobScheduler.cancel(SETUP_WIZARD_TIMEOUT_JOB_ID);
+
+        LogUtil.i(TAG, "Job cancelled");
+    }
+
+    private boolean isUserSetupComplete() {
+        return Settings.Secure.getInt(
+                mContext.getContentResolver(), Settings.Secure.USER_SETUP_COMPLETE, 0) != 0;
+    }
+}
diff --git a/DeviceLockController/tests/robolectric/config/robolectric.properties b/DeviceLockController/tests/robolectric/config/robolectric.properties
index 2f7dec2e..8a5cc29b 100644
--- a/DeviceLockController/tests/robolectric/config/robolectric.properties
+++ b/DeviceLockController/tests/robolectric/config/robolectric.properties
@@ -13,3 +13,4 @@
 # limitations under the License.
 sdk=NEWEST_SDK
 application=com.android.devicelockcontroller.TestDeviceLockControllerApplication
+sqliteMode=native
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/UpdateFcmTokenWorkerTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/UpdateFcmTokenWorkerTest.java
new file mode 100644
index 00000000..a8039c1c
--- /dev/null
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/UpdateFcmTokenWorkerTest.java
@@ -0,0 +1,188 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+import static com.android.devicelockcontroller.common.DeviceLockConstants.DeviceIdType.DEVICE_ID_TYPE_IMEI;
+import static com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse.FcmTokenResult.RESULT_FAILURE;
+import static com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse.FcmTokenResult.RESULT_SUCCESS;
+import static com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse.FcmTokenResult.RESULT_UNSPECIFIED;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+import android.util.ArraySet;
+
+import androidx.annotation.NonNull;
+import androidx.test.core.app.ApplicationProvider;
+import androidx.work.ListenableWorker;
+import androidx.work.ListenableWorker.Result;
+import androidx.work.WorkerFactory;
+import androidx.work.WorkerParameters;
+import androidx.work.testing.TestListenableWorkerBuilder;
+
+import com.android.devicelockcontroller.FcmRegistrationTokenProvider;
+import com.android.devicelockcontroller.TestDeviceLockControllerApplication;
+import com.android.devicelockcontroller.common.DeviceId;
+import com.android.devicelockcontroller.provision.grpc.DeviceCheckInClient;
+import com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse;
+
+import com.google.common.util.concurrent.Futures;
+import com.google.common.util.concurrent.testing.TestingExecutors;
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
+@RunWith(RobolectricTestRunner.class)
+public final class UpdateFcmTokenWorkerTest {
+    public static final ArraySet<DeviceId> TEST_DEVICE_IDS = new ArraySet<>(
+            new DeviceId[]{new DeviceId(DEVICE_ID_TYPE_IMEI, "1234667890")});
+    public static final ArraySet<DeviceId> EMPTY_DEVICE_IDS = new ArraySet<>(new DeviceId[]{});
+
+    @Rule
+    public final MockitoRule mMocks = MockitoJUnit.rule();
+    @Mock
+    private AbstractDeviceCheckInHelper mHelper;
+    @Mock
+    private FcmRegistrationTokenProvider mFcmRegistrationTokenProvider;
+    @Mock
+    private DeviceCheckInClient mClient;
+    @Mock
+    private UpdateFcmTokenGrpcResponse mResponse;
+    private UpdateFcmTokenWorker mWorker;
+    private TestDeviceLockControllerApplication mContext =
+            ApplicationProvider.getApplicationContext();
+
+    @Before
+    public void setUp() throws Exception {
+        when(mFcmRegistrationTokenProvider.getFcmRegistrationToken()).thenReturn(
+                mContext.getFcmRegistrationToken());
+        when(mClient.updateFcmToken(eq(TEST_DEVICE_IDS), any())).thenReturn(mResponse);
+        mWorker = TestListenableWorkerBuilder.from(
+                        mContext, UpdateFcmTokenWorker.class)
+                .setWorkerFactory(
+                        new WorkerFactory() {
+                            @Override
+                            public ListenableWorker createWorker(
+                                    @NonNull Context context, @NonNull String workerClassName,
+                                    @NonNull WorkerParameters workerParameters) {
+                                return workerClassName.equals(UpdateFcmTokenWorker.class.getName())
+                                        ? new UpdateFcmTokenWorker(
+                                        context, workerParameters, mHelper,
+                                        mFcmRegistrationTokenProvider, mClient,
+                                        TestingExecutors.sameThreadScheduledExecutor())
+                                        : null;
+                            }
+                        }).build();
+    }
+
+    @Test
+    public void updateFcmToken_succeeds() {
+        // GIVEN valid device ids and server response is successful
+        when(mHelper.getDeviceUniqueIds()).thenReturn(TEST_DEVICE_IDS);
+        when(mResponse.hasRecoverableError()).thenReturn(false);
+        when(mResponse.isSuccessful()).thenReturn(true);
+        when(mResponse.getFcmTokenResult()).thenReturn(RESULT_SUCCESS);
+
+        // WHEN the work runs
+        final Result result = Futures.getUnchecked(mWorker.startWork());
+
+        // THEN the work succeeds
+        assertThat(result).isEqualTo(Result.success());
+    }
+
+    @Test
+    public void updateFcmToken_noDeviceIds_fails() {
+        // GIVEN empty device ids
+        when(mHelper.getDeviceUniqueIds()).thenReturn(new ArraySet<>());
+
+        // WHEN the work runs
+        final Result result = Futures.getUnchecked(mWorker.startWork());
+
+        // THEN the work fails
+        assertThat(result).isEqualTo(Result.failure());
+    }
+
+    @Test
+    public void updateFcmToken_recoverableError_retries() {
+        // GIVEN valid device ids and there is a recoverable error
+        when(mHelper.getDeviceUniqueIds()).thenReturn(TEST_DEVICE_IDS);
+        when(mResponse.hasRecoverableError()).thenReturn(true);
+        when(mResponse.isSuccessful()).thenReturn(false);
+
+        // WHEN the work runs
+        final Result result = Futures.getUnchecked(mWorker.startWork());
+
+        // THEN the work retries
+        assertThat(result).isEqualTo(Result.retry());
+    }
+
+    @Test
+    public void updateFcmToken_unrecoverableError_fails() {
+        // GIVEN valid device ids and there is an unrecoverable error
+        when(mHelper.getDeviceUniqueIds()).thenReturn(TEST_DEVICE_IDS);
+        when(mResponse.hasRecoverableError()).thenReturn(false);
+        when(mResponse.isSuccessful()).thenReturn(false);
+
+        // WHEN the work runs
+        final Result result = Futures.getUnchecked(mWorker.startWork());
+
+        // THEN the work fails
+        assertThat(result).isEqualTo(Result.failure());
+    }
+
+    @Test
+    public void updateFcmToken_getsFcmResultFailure_fails() {
+        // GIVEN valid device ids, successful response from server, but response indicates a failed
+        // precondition
+        when(mHelper.getDeviceUniqueIds()).thenReturn(TEST_DEVICE_IDS);
+        when(mResponse.hasRecoverableError()).thenReturn(false);
+        when(mResponse.isSuccessful()).thenReturn(true);
+        when(mResponse.getFcmTokenResult()).thenReturn(RESULT_FAILURE);
+
+        // WHEN the work runs
+        final Result result = Futures.getUnchecked(mWorker.startWork());
+
+        // THEN the work fails
+        assertThat(result).isEqualTo(Result.failure());
+    }
+
+    @Test
+    public void updateFcmToken_getsFcmResultUnspecified_fails() {
+        // GIVEN valid device ids, successful response from server, but response indicates
+        // and unspecified value
+        when(mHelper.getDeviceUniqueIds()).thenReturn(TEST_DEVICE_IDS);
+        when(mResponse.hasRecoverableError()).thenReturn(false);
+        when(mResponse.isSuccessful()).thenReturn(true);
+        when(mResponse.getFcmTokenResult()).thenReturn(RESULT_UNSPECIFIED);
+
+        // WHEN the work runs
+        final Result result = Futures.getUnchecked(mWorker.startWork());
+
+        // THEN the work fails
+        assertThat(result).isEqualTo(Result.failure());
+    }
+}
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/SetupWizardCompletionTimeoutWorkerTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/services/SetupWizardCompletionTimeoutJobTest.java
similarity index 67%
rename from DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/SetupWizardCompletionTimeoutWorkerTest.java
rename to DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/services/SetupWizardCompletionTimeoutJobTest.java
index 033be457..2bc3f748 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/worker/SetupWizardCompletionTimeoutWorkerTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/services/SetupWizardCompletionTimeoutJobTest.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.devicelockcontroller.provision.worker;
+package com.android.devicelockcontroller.services;
 
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent.PROVISION_READY;
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.PROVISION_IN_PROGRESS;
@@ -29,15 +29,9 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.content.ContentResolver;
-import android.content.Context;
 import android.provider.Settings;
 
-import androidx.annotation.NonNull;
 import androidx.test.core.app.ApplicationProvider;
-import androidx.work.ListenableWorker;
-import androidx.work.WorkerFactory;
-import androidx.work.WorkerParameters;
-import androidx.work.testing.TestListenableWorkerBuilder;
 
 import com.android.devicelockcontroller.TestDeviceLockControllerApplication;
 import com.android.devicelockcontroller.policy.ProvisionStateController;
@@ -45,7 +39,6 @@ import com.android.devicelockcontroller.storage.GlobalParametersClient;
 import com.android.devicelockcontroller.storage.UserParameters;
 
 import com.google.common.util.concurrent.Futures;
-import com.google.common.util.concurrent.testing.TestingExecutors;
 
 import org.junit.Before;
 import org.junit.Test;
@@ -54,49 +47,41 @@ import org.robolectric.RobolectricTestRunner;
 
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.Executors;
+import java.util.concurrent.TimeUnit;
+import java.util.concurrent.TimeoutException;
 
 @RunWith(RobolectricTestRunner.class)
-public final class SetupWizardCompletionTimeoutWorkerTest {
+public final class SetupWizardCompletionTimeoutJobTest {
     private TestDeviceLockControllerApplication mTestApp;
-    private SetupWizardCompletionTimeoutWorker mWorker;
     private ProvisionStateController mMockProvisionStateController;
+    private SetupWizardCompletionTimeoutJobService mJob;
+    private static final long TIMEOUT_MILLIS = 1000;
 
     @Before
     public void setUp() throws Exception {
         mTestApp = ApplicationProvider.getApplicationContext();
         mMockProvisionStateController = mTestApp.getProvisionStateController();
-        mWorker = TestListenableWorkerBuilder.from(
-                        mTestApp, SetupWizardCompletionTimeoutWorker.class)
-                .setWorkerFactory(
-                        new WorkerFactory() {
-                            @Override
-                            public ListenableWorker createWorker(
-                                    @NonNull Context context, @NonNull String workerClassName,
-                                    @NonNull WorkerParameters workerParameters) {
-                                return workerClassName.equals(
-                                        SetupWizardCompletionTimeoutWorker.class.getName())
-                                        ? new SetupWizardCompletionTimeoutWorker(context,
-                                        workerParameters,
-                                        TestingExecutors.sameThreadScheduledExecutor())
-                                        : null;
-                            }
-                        }).build();
+
+        mJob = new SetupWizardCompletionTimeoutJobService(mTestApp);
     }
 
     @Test
-    public void doWork_suwComplete_doesNotStartFlow() {
+    public void doWork_suwComplete_doesNotStartFlow()
+            throws InterruptedException, ExecutionException, TimeoutException {
         // Device setup is complete
         ContentResolver contentResolver = mTestApp.getContentResolver();
         Settings.Secure.putInt(contentResolver, Settings.Secure.USER_SETUP_COMPLETE, 1);
 
-        assertThat(Futures.getUnchecked(mWorker.startWork()))
-                .isEqualTo(ListenableWorker.Result.success());
+        boolean result = mJob.onStartJob(/* params= */ null);
+
+        assertThat(result).isFalse();
 
         verify(mMockProvisionStateController, never()).setNextStateForEvent(anyInt());
     }
 
     @Test
-    public void doWork_suwNotComplete_notUnprovisioned_doesNotStartFlow() {
+    public void doWork_suwNotComplete_notUnprovisioned_doesNotStartFlow()
+            throws ExecutionException, InterruptedException, TimeoutException {
         // Device setup is not complete
         ContentResolver contentResolver = mTestApp.getContentResolver();
         Settings.Secure.putInt(contentResolver, Settings.Secure.USER_SETUP_COMPLETE, 0);
@@ -104,15 +89,18 @@ public final class SetupWizardCompletionTimeoutWorkerTest {
         when(mMockProvisionStateController.getState())
                 .thenReturn(Futures.immediateFuture(PROVISION_IN_PROGRESS));
 
-        assertThat(Futures.getUnchecked(mWorker.startWork()))
-                .isEqualTo(ListenableWorker.Result.success());
+        boolean result = mJob.onStartJob(/* params= */ null);
+
+        assertThat(result).isTrue();
+
+        mJob.mFuture.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         verify(mMockProvisionStateController, never()).setNextStateForEvent(anyInt());
     }
 
     @Test
     public void doWork_suwNotComplete_unprovisioned_provisionNotReady_doesNotStartFlow()
-            throws ExecutionException, InterruptedException {
+            throws ExecutionException, InterruptedException, TimeoutException {
         // Device setup is not complete
         ContentResolver contentResolver = mTestApp.getContentResolver();
         Settings.Secure.putInt(contentResolver, Settings.Secure.USER_SETUP_COMPLETE, 0);
@@ -122,15 +110,18 @@ public final class SetupWizardCompletionTimeoutWorkerTest {
 
         GlobalParametersClient.getInstance().setProvisionReady(false).get();
 
-        assertThat(Futures.getUnchecked(mWorker.startWork()))
-                .isEqualTo(ListenableWorker.Result.success());
+        boolean result = mJob.onStartJob(/* params= */ null);
+
+        assertThat(result).isTrue();
+
+        mJob.mFuture.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         verify(mMockProvisionStateController, never()).setNextStateForEvent(anyInt());
     }
 
     @Test
     public void doWork_suwNotComplete_unprovisioned_provisionReady_startsFlow()
-            throws ExecutionException, InterruptedException {
+            throws ExecutionException, InterruptedException, TimeoutException {
         // Device setup is not complete
         ContentResolver contentResolver = mTestApp.getContentResolver();
         Settings.Secure.putInt(contentResolver, Settings.Secure.USER_SETUP_COMPLETE, 0);
@@ -142,8 +133,11 @@ public final class SetupWizardCompletionTimeoutWorkerTest {
 
         GlobalParametersClient.getInstance().setProvisionReady(true).get();
 
-        assertThat(Futures.getUnchecked(mWorker.startWork()))
-                .isEqualTo(ListenableWorker.Result.success());
+        boolean result = mJob.onStartJob(/* params= */ null);
+
+        assertThat(result).isTrue();
+
+        mJob.mFuture.get(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
 
         Executors.newSingleThreadExecutor().submit(
                 () -> assertThat(UserParameters.isSetupWizardTimedOut(mTestApp)).isTrue()).get();
diff --git a/OWNERS b/OWNERS
index 0fcc31e9..0418bdbd 100644
--- a/OWNERS
+++ b/OWNERS
@@ -4,3 +4,4 @@ rajekumar@google.com
 amosbianchi@google.com
 zzhen@google.com
 kevhan@google.com
+dmusila@google.com
diff --git a/framework/Android.bp b/framework/Android.bp
index b7c6a7df..646d97dd 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -54,4 +54,7 @@ java_sdk_library {
     min_sdk_version: "UpsideDownCake",
     libs: ["framework-annotations-lib"],
     static_libs: ["devicelock-aconfig-flags-lib"],
+    lint: {
+        baseline_filename: "lint-baseline.xml",
+    },
 }
diff --git a/framework/lint-baseline.xml b/framework/lint-baseline.xml
new file mode 100644
index 00000000..0b9581f9
--- /dev/null
+++ b/framework/lint-baseline.xml
@@ -0,0 +1,70 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<issues format="6" by="lint 8.4.0-alpha08" type="baseline" client="" dependencies="true" name="" variant="all" version="8.4.0-alpha08">
+
+    <issue
+        id="MissingPermissionAnnotation"
+        message="onSuccess should be annotated with either @EnforcePermission, @RequiresNoPermission or @PermissionManuallyEnforced."
+        errorLine1="                        @Override"
+        errorLine2="                        ^">
+        <location
+            file="packages/modules/DeviceLock/framework/java/android/devicelock/DeviceLockManager.java"
+            line="108"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="MissingPermissionAnnotation"
+        message="onError should be annotated with either @EnforcePermission, @RequiresNoPermission or @PermissionManuallyEnforced."
+        errorLine1="                        @Override"
+        errorLine2="                        ^">
+        <location
+            file="packages/modules/DeviceLock/framework/java/android/devicelock/DeviceLockManager.java"
+            line="113"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="MissingPermissionAnnotation"
+        message="onSuccess should be annotated with either @EnforcePermission, @RequiresNoPermission or @PermissionManuallyEnforced."
+        errorLine1="                        @Override"
+        errorLine2="                        ^">
+        <location
+            file="packages/modules/DeviceLock/framework/java/android/devicelock/DeviceLockManager.java"
+            line="138"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="MissingPermissionAnnotation"
+        message="onError should be annotated with either @EnforcePermission, @RequiresNoPermission or @PermissionManuallyEnforced."
+        errorLine1="                        @Override"
+        errorLine2="                        ^">
+        <location
+            file="packages/modules/DeviceLock/framework/java/android/devicelock/DeviceLockManager.java"
+            line="143"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="MissingPermissionAnnotation"
+        message="onSuccess should be annotated with either @EnforcePermission, @RequiresNoPermission or @PermissionManuallyEnforced."
+        errorLine1="                        @Override"
+        errorLine2="                        ^">
+        <location
+            file="packages/modules/DeviceLock/framework/java/android/devicelock/DeviceLockManager.java"
+            line="227"
+            column="25"/>
+    </issue>
+
+    <issue
+        id="MissingPermissionAnnotation"
+        message="onError should be annotated with either @EnforcePermission, @RequiresNoPermission or @PermissionManuallyEnforced."
+        errorLine1="                        @Override"
+        errorLine2="                        ^">
+        <location
+            file="packages/modules/DeviceLock/framework/java/android/devicelock/DeviceLockManager.java"
+            line="232"
+            column="25"/>
+    </issue>
+
+</issues>
```

