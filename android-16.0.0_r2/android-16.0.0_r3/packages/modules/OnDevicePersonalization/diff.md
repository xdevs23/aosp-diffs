```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 71bb9fcf..e9d744bf 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -8,6 +8,10 @@
       // Install com.google.android.ondevicepersonalization.apex and run OnDevicePersonalizationManagingServicesTests.
       "name": "OnDevicePersonalizationManagingServicesTests[com.google.android.ondevicepersonalization.apex]"
     },
+    {
+      // Install com.google.android.ondevicepersonalization.apex and run OnDevicePersonalizationEndToEndTests.
+      "name": "OnDevicePersonalizationEndToEndTests[com.google.android.ondevicepersonalization.apex]"
+    },
     {
       // Install com.google.android.ondevicepersonalization.apex and run OdpChronicleTests.
       "name": "OdpChronicleTests[com.google.android.ondevicepersonalization.apex]"
@@ -44,6 +48,9 @@
     {
       "name": "OnDevicePersonalizationManagingServicesTests"
     },
+    {
+      "name": "OnDevicePersonalizationEndToEndTests"
+    },
     {
       "name": "OdpChronicleTests"
     },
@@ -73,6 +80,9 @@
     {
       "name": "OnDevicePersonalizationManagingServicesTests"
     },
+    {
+      "name": "OnDevicePersonalizationEndToEndTests"
+    },
     {
       "name": "OdpChronicleTests"
     },
diff --git a/apex/Android.bp b/apex/Android.bp
index c0666d5e..144905b6 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -98,6 +98,10 @@ apex {
     prebuilts: ["current_sdkinfo"],
     jni_libs: ["libfcp_cpp_dep_jni", "libfcp_hpke_jni"],
     visibility: ["//packages/modules/common/build"],
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 filegroup {
diff --git a/federatedcompute/OWNERS b/federatedcompute/OWNERS
index 27ff0037..b0e03518 100644
--- a/federatedcompute/OWNERS
+++ b/federatedcompute/OWNERS
@@ -2,6 +2,5 @@ alexbuy@google.com
 karthikmahesh@google.com
 maco@google.com
 qiaoli@google.com
-tarading@google.com
 xueyiwang@google.com
 ymu@google.com
diff --git a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
index 7de91f3c..9de2cbd6 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegate.java
@@ -23,16 +23,20 @@ import static android.federatedcompute.common.ClientConstants.STATUS_SUCCESS;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_API_CALLED__API_NAME__CANCEL;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_API_CALLED__API_NAME__SCHEDULE;
 
+import android.adservices.ondevicepersonalization.Constants;
 import android.annotation.NonNull;
 import android.content.ComponentName;
 import android.content.Context;
 import android.federatedcompute.aidl.IFederatedComputeCallback;
 import android.federatedcompute.aidl.IFederatedComputeService;
+import android.federatedcompute.aidl.IIsFeatureEnabledCallback;
 import android.federatedcompute.common.TrainingOptions;
 import android.os.Binder;
 import android.os.RemoteException;
+import android.os.SystemClock;
 
 import com.android.federatedcompute.internal.util.LogUtil;
+import com.android.federatedcompute.services.common.FeatureStatusManager;
 import com.android.federatedcompute.services.common.FederatedComputeExecutors;
 import com.android.federatedcompute.services.common.FlagsFactory;
 import com.android.federatedcompute.services.scheduling.FederatedComputeJobManager;
@@ -236,6 +240,29 @@ class FederatedComputeManagingServiceDelegate extends IFederatedComputeService.S
         return killSwitchEnabled;
     }
 
+    @Override
+    public void isFeatureEnabled(
+            String featureName,
+            IIsFeatureEnabledCallback callback) {
+        if (!FlagsFactory.getFlags().isFeatureEnabledApiEnabled()) {
+            throw new IllegalStateException("isFeatureEnabled flag is not enabled.");
+        }
+
+        long serviceEntryTimeMillis = SystemClock.elapsedRealtime();
+
+        FeatureStatusManager.getFeatureStatusAndSendResult(featureName,
+                serviceEntryTimeMillis,
+                callback);
+
+        mFcStatsdLogger.logApiCallStats(
+                new ApiCallStats.Builder().setApiName(
+                                Constants.API_NAME_IS_FEATURE_ENABLED)
+                        .setLatencyMillis((int) (mClock.elapsedRealtime() - serviceEntryTimeMillis))
+                        .setResponseCode(STATUS_SUCCESS)
+                        .setSdkPackageName("")
+                        .build());
+    }
+
     private static void sendResult(@NonNull IFederatedComputeCallback callback, int resultCode) {
         try {
             if (resultCode == STATUS_SUCCESS) {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/FeatureStatusManager.java b/federatedcompute/src/com/android/federatedcompute/services/common/FeatureStatusManager.java
new file mode 100644
index 00000000..d0710a14
--- /dev/null
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/FeatureStatusManager.java
@@ -0,0 +1,109 @@
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
+package com.android.federatedcompute.services.common;
+
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.federatedcompute.aidl.IIsFeatureEnabledCallback;
+import android.os.Binder;
+import android.os.RemoteException;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+import java.util.function.Supplier;
+public class FeatureStatusManager {
+    private static final Object sLock = new Object();
+
+    private static final String TAG = FeatureStatusManager.class.getSimpleName();
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static volatile FeatureStatusManager sFeatureStatusManager = null;
+
+    private final Map<String, Supplier<Boolean>> mFlaggedFeaturesMap = new HashMap<>();
+
+    private final Set<String> mNonFlaggedFeaturesSet = new HashSet<>();
+
+    private Flags mFlags;
+
+    /** Returns the status of the feature. */
+    public static void getFeatureStatusAndSendResult(
+            String featureName,
+            long serviceEntryTime,
+            IIsFeatureEnabledCallback callback) {
+        int result = getInstance().isFeatureEnabled(featureName);
+        try {
+            callback.onResult(result);
+        } catch (RemoteException e) {
+            sLogger.w(TAG + ": Callback error", e);
+        }
+    }
+
+    /** Returns the singleton instance of FeatureManager. */
+    public static FeatureStatusManager getInstance() {
+        if (sFeatureStatusManager == null) {
+            synchronized (sLock) {
+                if (sFeatureStatusManager == null) {
+                    long origId = Binder.clearCallingIdentity();
+                    sFeatureStatusManager = new FeatureStatusManager(FlagsFactory.getFlags());
+                    Binder.restoreCallingIdentity(origId);
+                }
+            }
+        }
+        return sFeatureStatusManager;
+    }
+
+    @VisibleForTesting
+    FeatureStatusManager(Flags flags) {
+        mFlags = flags;
+        // Add flagged features here, for example:
+        // mFlaggedFeaturesMap.put("featureName", mFlags::isFeatureEnabled);
+
+        // Add non-flagged features here, for example:
+        // mNonFlaggedFeaturesSet.add("featureName");
+    }
+
+    @VisibleForTesting
+    FeatureStatusManager(Flags flags,
+            Map<String, Supplier<Boolean>> flaggedFeaturesMap,
+            Set<String> nonFlaggedFeaturesSet) {
+        mFlags = flags;
+
+        // Add flagged features here
+        mFlaggedFeaturesMap.putAll(flaggedFeaturesMap);
+
+        // Add non-flagged features here
+        mNonFlaggedFeaturesSet.addAll(nonFlaggedFeaturesSet);
+    }
+
+    @VisibleForTesting
+    int isFeatureEnabled(String featureName) {
+        if (mNonFlaggedFeaturesSet.contains(featureName)) {
+            return OnDevicePersonalizationManager.FEATURE_ENABLED;
+        }
+
+        if (mFlaggedFeaturesMap.containsKey(featureName)) {
+            boolean flagValue = mFlaggedFeaturesMap.get(featureName).get();
+            return flagValue ? OnDevicePersonalizationManager.FEATURE_ENABLED
+                    : OnDevicePersonalizationManager.FEATURE_DISABLED;
+        }
+
+        return OnDevicePersonalizationManager.FEATURE_UNSUPPORTED;
+    }
+}
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/FederatedComputeExecutors.java b/federatedcompute/src/com/android/federatedcompute/services/common/FederatedComputeExecutors.java
index 53a13cb5..7c7ad51c 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/common/FederatedComputeExecutors.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/FederatedComputeExecutors.java
@@ -17,8 +17,6 @@
 package com.android.federatedcompute.services.common;
 
 import android.annotation.NonNull;
-import android.os.Handler;
-import android.os.HandlerThread;
 import android.os.Process;
 import android.os.StrictMode;
 import android.os.StrictMode.ThreadPolicy;
@@ -32,8 +30,8 @@ import java.util.concurrent.Executors;
 import java.util.concurrent.ThreadFactory;
 
 /**
- * All executors of the FederatedCompute APK. Copied from
- * com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors.
+ * All executors of the FederatedCompute APK. Copied from {@link
+ * com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors}.
  */
 public final class FederatedComputeExecutors {
     private static final ListeningExecutorService sBackgroundExecutor =
@@ -64,10 +62,6 @@ public final class FederatedComputeExecutors {
                                             + Process.THREAD_PRIORITY_LESS_FAVORABLE,
                                     Optional.empty())));
 
-    private static final HandlerThread sHandlerThread = createHandlerThread();
-
-    private static final Handler sHandler = new Handler(sHandlerThread.getLooper());
-
     private FederatedComputeExecutors() {}
 
     /**
@@ -94,11 +88,6 @@ public final class FederatedComputeExecutors {
         return sBlockingExecutor;
     }
 
-    /** Returns a Handler that can post messages to a HandlerThread. */
-    public static Handler getHandler() {
-        return sHandler;
-    }
-
     private static ThreadFactory createThreadFactory(
             final String name, final int priority, final Optional<StrictMode.ThreadPolicy> policy) {
         return new ThreadFactoryBuilder()
@@ -110,9 +99,7 @@ public final class FederatedComputeExecutors {
                             public Thread newThread(final Runnable runnable) {
                                 return new Thread(
                                         () -> {
-                                            if (policy.isPresent()) {
-                                                StrictMode.setThreadPolicy(policy.get());
-                                            }
+                                            policy.ifPresent(StrictMode::setThreadPolicy);
                                             // Process class operates on the current thread.
                                             Process.setThreadPriority(priority);
                                             runnable.run();
@@ -134,10 +121,4 @@ public final class FederatedComputeExecutors {
                 .penaltyLog()
                 .build();
     }
-
-    private static HandlerThread createHandlerThread() {
-        HandlerThread handlerThread = new HandlerThread("DisplayThread");
-        handlerThread.start();
-        return handlerThread;
-    }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/Flags.java b/federatedcompute/src/com/android/federatedcompute/services/common/Flags.java
index cb9155eb..f5038659 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/common/Flags.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/Flags.java
@@ -168,6 +168,7 @@ public interface Flags extends ModuleSharedFlags {
         return HTTP_REQUEST_RETRY_LIMIT;
     }
 
+    /** Encryption is enabled for FCP by default. */
     Boolean ENCRYPTION_ENABLED = true;
 
     /** Whether to enable encryption when uploading results. */
@@ -195,8 +196,8 @@ public interface Flags extends ModuleSharedFlags {
 
     /**
      * Limitation of how much times can FCP task job can be rescheduled if it failed, if federated
-     * compute job retry times exceeds this limit, the job will be canceled/abort.
-     * This one is for recurrent jobs.
+     * compute job retry times exceeds this limit, the job will be canceled/abort. This one is for
+     * recurrent jobs.
      */
     default int getFcpRecurrentRescheduleLimit() {
         return FCP_RECURRENT_RESCHEDULE_LIMIT;
@@ -263,15 +264,15 @@ public interface Flags extends ModuleSharedFlags {
     }
 
     /**
-     * Default enablement for applying SPE (Scheduling Policy Engine) to
-     * {@code BackgroundKeyFetchJobService}
+     * Default enablement for applying SPE (Scheduling Policy Engine) to {@code
+     * BackgroundKeyFetchJobService}
      */
-    @FeatureFlag boolean
-            DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB = false;
+    @FeatureFlag
+    boolean DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB = false;
 
     /**
-     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to
-     * {@code BackgroundKeyFetchJobService}
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to {@code
+     * BackgroundKeyFetchJobService}
      */
     default boolean getSpeOnBackgroundKeyFetchJobEnabled() {
         return DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
@@ -283,8 +284,8 @@ public interface Flags extends ModuleSharedFlags {
     @FeatureFlag boolean DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB = false;
 
     /**
-     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to
-     * {@code FederatedJobService}
+     * Returns the default enablement of applying SPE (Scheduling Policy Engine) to {@code
+     * FederatedJobService}
      */
     default boolean getSpeOnFederatedJobEnabled() {
         return DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB;
@@ -315,4 +316,22 @@ public interface Flags extends ModuleSharedFlags {
     default long getTempFileTtlMillis() {
         return DEFAULT_TEMP_FILE_TTL_MILLIS;
     }
+
+    boolean DEFAULT_IS_FEATURE_ENABLED_API_ENABLED = false;
+
+    default boolean isFeatureEnabledApiEnabled() {
+        return DEFAULT_IS_FEATURE_ENABLED_API_ENABLED;
+    }
+
+    String DEFAULT_BACKGROUND_KEY_FETCH_JOB_POLICY = "";
+
+    default String getBackgroundKeyFetchJobPolicy() {
+        return DEFAULT_BACKGROUND_KEY_FETCH_JOB_POLICY;
+    }
+
+    String DEFAULT_DELETE_EXPIRED_DATA_JOB_POLICY = "";
+
+    default String getDeleteExpiredDataJobPolicy() {
+        return DEFAULT_DELETE_EXPIRED_DATA_JOB_POLICY;
+    }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/FlagsConstants.java b/federatedcompute/src/com/android/federatedcompute/services/common/FlagsConstants.java
index 60bdb711..caeb3348 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/common/FlagsConstants.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/FlagsConstants.java
@@ -89,4 +89,11 @@ public final class FlagsConstants {
     static final String FCP_TF_ERROR_RESCHEDULE_SECONDS_CONFIG_NAME = "tf_error_reschedule_seconds";
     static final String EXAMPLE_ITERATOR_NEXT_TIMEOUT_SEC = "example_iterator_next_timeout_sec";
     static final String FCP_TEMP_FILE_TTL_IN_MILLIS_NAME = "FcpFeatures__temp_file_ttl_in_millis";
+    static final String KEY_IS_FEATURE_ENABLED_API_ENABLED =
+            "FcpFeatures__enable_is_feature_enabled";
+    static final String KEY_ENABLE_PER_JOB_POLICY = "FcpBackgroundJobs__enable_per_job_policy";
+    static final String KEY_BACKGROUND_KEY_FETCH_JOB_POLICY =
+            "FcpBackgroundJobs__background_key_fetch_job_policy";
+    static final String KEY_DELETE_EXPIRED_DATA_JOB_POLICY =
+            "FcpBackgroundJobs__delete_expired_data_job_policy";
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/PhFlags.java b/federatedcompute/src/com/android/federatedcompute/services/common/PhFlags.java
index 401818d9..69f49ab6 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/common/PhFlags.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/PhFlags.java
@@ -39,7 +39,11 @@ import static com.android.federatedcompute.services.common.FlagsConstants.FCP_TE
 import static com.android.federatedcompute.services.common.FlagsConstants.FCP_TF_ERROR_RESCHEDULE_SECONDS_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.FEDERATED_COMPUTATION_ENCRYPTION_KEY_DOWNLOAD_URL;
 import static com.android.federatedcompute.services.common.FlagsConstants.HTTP_REQUEST_RETRY_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_BACKGROUND_KEY_FETCH_JOB_POLICY;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_DELETE_EXPIRED_DATA_JOB_POLICY;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_ENABLE_PER_JOB_POLICY;
 import static com.android.federatedcompute.services.common.FlagsConstants.KEY_FEDERATED_COMPUTE_KILL_SWITCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_IS_FEATURE_ENABLED_API_ENABLED;
 import static com.android.federatedcompute.services.common.FlagsConstants.MAX_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.MAX_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.MIN_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
@@ -54,16 +58,16 @@ import static com.android.federatedcompute.services.common.FlagsConstants.TRANSI
 import android.os.SystemProperties;
 import android.provider.DeviceConfig;
 
-import com.android.internal.annotations.VisibleForTesting;
-
 /** A placeholder class for PhFlag. */
 public final class PhFlags implements Flags {
     private static final PhFlags sSingleton = new PhFlags();
-    // SystemProperty prefix. SystemProperty is for overriding OnDevicePersonalization Configs.
-    private static final String SYSTEM_PROPERTY_PREFIX = "debug.ondevicepersonalization.";
 
-    private PhFlags() {
-    }
+    /*
+     * The FCP SystemProperty prefix. SystemProperty is used to provide values for some
+     * flags, but most rely on device-config. */
+    private static final String SYSTEM_PROPERTY_PREFIX = "debug.federatedcompute.";
+
+    private PhFlags() {}
 
     /** Returns the singleton instance of the PhFlags. */
     static PhFlags getInstance() {
@@ -83,8 +87,7 @@ public final class PhFlags implements Flags {
                         /* defaultValue= */ FEDERATED_COMPUTE_GLOBAL_KILL_SWITCH));
     }
 
-    @VisibleForTesting
-    static String getSystemPropertyName(String key) {
+    private static String getSystemPropertyName(String key) {
         return SYSTEM_PROPERTY_PREFIX + key;
     }
 
@@ -112,11 +115,16 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */ HTTP_REQUEST_RETRY_LIMIT);
     }
 
+    @Override
+    /**
+     * Whether to enable encryption when uploading results.
+     *
+     * <p>This flag is guarded only by a System Property unlike most flags that rely on device
+     * config instead.
+     */
     public Boolean isEncryptionEnabled() {
-        return DeviceConfig.getBoolean(
-                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
-                /* name= */ FCP_ENABLE_ENCRYPTION,
-                /* defaultValue= */ ENCRYPTION_ENABLED);
+        return SystemProperties.getBoolean(
+                getSystemPropertyName(FCP_ENABLE_ENCRYPTION), ENCRYPTION_ENABLED);
     }
 
     @Override
@@ -288,8 +296,7 @@ public final class PhFlags implements Flags {
         return DeviceConfig.getBoolean(
                 /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
                 /* name= */ FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB,
-                /* defaultValue= */
-                DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB);
+                /* defaultValue= */ DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB);
     }
 
     @Override
@@ -355,4 +362,36 @@ public final class PhFlags implements Flags {
                 /* name= */ FCP_TEMP_FILE_TTL_IN_MILLIS_NAME,
                 /* defaultValue= */ DEFAULT_TEMP_FILE_TTL_MILLIS);
     }
+
+    @Override
+    public boolean isFeatureEnabledApiEnabled() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_IS_FEATURE_ENABLED_API_ENABLED,
+                /* defaultValue= */ DEFAULT_IS_FEATURE_ENABLED_API_ENABLED);
+    }
+
+    @Override
+    public boolean getSpeEnablePerJobPolicy() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ENABLE_PER_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_SPE_ENABLE_PER_JOB_POLICY);
+    }
+
+    @Override
+    public String getBackgroundKeyFetchJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_BACKGROUND_KEY_FETCH_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_BACKGROUND_KEY_FETCH_JOB_POLICY);
+    }
+
+    @Override
+    public String getDeleteExpiredDataJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_DELETE_EXPIRED_DATA_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_BACKGROUND_KEY_FETCH_JOB_POLICY);
+    }
 }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/common/TrainingEventLogger.java b/federatedcompute/src/com/android/federatedcompute/services/common/TrainingEventLogger.java
index c84382d5..ac877c87 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/common/TrainingEventLogger.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/common/TrainingEventLogger.java
@@ -45,6 +45,8 @@ import static com.android.federatedcompute.services.stats.FederatedComputeStatsL
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_RUN_FAILED_ENCRYPTION_KEY_FETCH_FAILED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_TASK_ASSIGNMENT_AUTH_SUCCEEDED;
 import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_TASK_ASSIGNMENT_UNAUTHORIZED;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY_CLIENT_VERSION_MISMATCH;
+import static com.android.federatedcompute.services.stats.FederatedComputeStatsLog.FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY_NO_ACTIVE_TASK_EXISTS;
 
 import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.statsd.FederatedComputeStatsdLogger;
@@ -113,6 +115,16 @@ public class TrainingEventLogger implements EventLogger {
                         FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY_NO_TASK_AVAILABLE,
                         networkStats);
                 break;
+            case CLIENT_VERSION_MISMATCH:
+                logNetworkEvent(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY_CLIENT_VERSION_MISMATCH,
+                        networkStats);
+                break;
+            case NO_ACTIVE_TASK_EXISTS:
+                logNetworkEvent(
+                        FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY_NO_ACTIVE_TASK_EXISTS,
+                        networkStats);
+                break;
             default:
                 logNetworkEvent(
                         FEDERATED_COMPUTE_TRAINING_EVENT_REPORTED__KIND__TRAIN_DOWNLOAD_TURNED_AWAY,
diff --git a/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJob.java b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJob.java
index 5a643dea..b2463041 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJob.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJob.java
@@ -128,15 +128,22 @@ public final class BackgroundKeyFetchJob implements JobWorker {
         return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
     }
 
+    @Override
+    public String getJobPolicyString(int jobId) {
+        return FlagsFactory.getFlags().getBackgroundKeyFetchJobPolicy();
+    }
+
     /** Schedules a unique instance of {@link BackgroundKeyFetchJobService}. */
     public static void schedule(Context context) {
         // If SPE is not enabled, force to schedule the job with the old JobService.
         if (!FlagsFactory.getFlags().getSpeOnBackgroundKeyFetchJobEnabled()) {
-            LogUtil.d(TAG, "SPE is not enabled. Schedule the job with "
-                    + "BackgroundKeyFetchJobService.");
+            LogUtil.d(
+                    TAG,
+                    "SPE is not enabled. Schedule the job with " + "BackgroundKeyFetchJobService.");
 
-            int resultCode = BackgroundKeyFetchJobService.scheduleJobIfNeeded(
-                    context, FlagsFactory.getFlags(), /* forceSchedule */ false);
+            int resultCode =
+                    BackgroundKeyFetchJobService.scheduleJobIfNeeded(
+                            context, FlagsFactory.getFlags(), /* forceSchedule */ false);
             FederatedComputeJobServiceFactory.getInstance(context)
                     .getJobSchedulingLogger()
                     .recordOnSchedulingLegacy(ENCRYPTION_KEY_FETCH_JOB_ID, resultCode);
diff --git a/federatedcompute/src/com/android/federatedcompute/services/http/CheckinResult.java b/federatedcompute/src/com/android/federatedcompute/services/http/CheckinResult.java
index d940935e..c765c4cc 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/http/CheckinResult.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/http/CheckinResult.java
@@ -31,7 +31,7 @@ public class CheckinResult {
     private final String mInputCheckpoint;
     private final ClientOnlyPlan mPlanData;
     private final TaskAssignment mTaskAssignment;
-    private final RejectionInfo mRejectionInfo;
+    @Nullable private final RejectionInfo mRejectionInfo;
 
     public CheckinResult(
             String inputCheckpoint, ClientOnlyPlan planData, TaskAssignment taskAssignment) {
@@ -41,18 +41,11 @@ public class CheckinResult {
         this.mRejectionInfo = null;
     }
 
-    public CheckinResult(RejectionInfo mRejectionInfo) {
-        this.mRejectionInfo = mRejectionInfo;
-        this.mInputCheckpoint = null;
-        this.mPlanData = null;
-        this.mTaskAssignment = null;
-    }
-
     @Nullable
     public String getInputCheckpointFile() {
         Preconditions.checkArgument(
                 mInputCheckpoint != null && !mInputCheckpoint.isEmpty(),
-                "Input checkpoint file should not be none or empty");
+                "Input checkpoint file should not be null or empty");
         return mInputCheckpoint;
     }
 
diff --git a/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java b/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
index cba9a2db..08c3f82c 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/http/HttpFederatedProtocol.java
@@ -86,7 +86,8 @@ import java.util.zip.GZIPInputStream;
 
 /** Implements a single session of HTTP-based federated compute protocol. */
 public final class HttpFederatedProtocol {
-    public static final String TAG = HttpFederatedProtocol.class.getSimpleName();
+    private static final String TAG = HttpFederatedProtocol.class.getSimpleName();
+
     private final long mClientVersion;
     private final String mPopulationName;
     private final HttpClient mHttpClient;
@@ -494,6 +495,7 @@ public final class HttpFederatedProtocol {
         byte[] fileOutputBytes = readFileAsByteArray(filePath);
         if (!FlagsFactory.getFlags().isEncryptionEnabled()) {
             // encryption not enabled, upload the file contents directly
+            LogUtil.d(TAG, "Encryption for request body is disabled.");
             return fileOutputBytes;
         }
         fileOutputBytes = compressWithGzip(fileOutputBytes);
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
index c8696adc..395a7c2b 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJob.java
@@ -135,6 +135,11 @@ public final class DeleteExpiredJob implements JobWorker {
         return JOB_ENABLED_STATUS_ENABLED;
     }
 
+    @Override
+    public String getJobPolicyString(int jobId) {
+        return FlagsFactory.getFlags().getDeleteExpiredDataJobPolicy();
+    }
+
     /** Schedule the periodic {@link DeleteExpiredJob}. */
     public static void schedule(Context context, Flags flags) {
         // If SPE is not enabled, force to schedule the job with the old JobService.
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java
index 9b805c1b..8403e936 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeJobManager.java
@@ -111,12 +111,9 @@ public class FederatedComputeJobManager {
         builder.finish(
                 TrainingConstraints.createTrainingConstraints(
                         builder,
-                        /** requiresSchedulerIdle= */
-                        true,
-                        /** requiresSchedulerBatteryNotLow= */
-                        true,
-                        /** requiresSchedulerUnmeteredNetwork= */
-                        true));
+                        /* requiresSchedulerIdle= */ true,
+                        /* requiresSchedulerBatteryNotLow= */ true,
+                        /* requiresSchedulerUnmeteredNetwork= */ true));
         return builder.sizedByteArray();
     }
 
@@ -124,7 +121,7 @@ public class FederatedComputeJobManager {
         FlatBufferBuilder builder = new FlatBufferBuilder();
         builder.finish(
                 TrainingIntervalOptions.createTrainingIntervalOptions(
-                        builder, SchedulingMode.ONE_TIME, 0));
+                        builder, SchedulingMode.ONE_TIME, /* minIntervalMillis= */ 0));
         return builder.sizedByteArray();
     }
 
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeLearningJobScheduleOrchestrator.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeLearningJobScheduleOrchestrator.java
index 56f1fba6..f9c43ea6 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeLearningJobScheduleOrchestrator.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedComputeLearningJobScheduleOrchestrator.java
@@ -16,14 +16,12 @@
 
 package com.android.federatedcompute.services.scheduling;
 
-import android.annotation.NonNull;
 import android.app.job.JobScheduler;
 import android.content.Context;
 
 import com.android.federatedcompute.internal.util.LogUtil;
 import com.android.federatedcompute.services.data.FederatedTrainingTask;
 import com.android.federatedcompute.services.data.FederatedTrainingTaskDao;
-import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
 
 import com.google.common.annotations.VisibleForTesting;
@@ -39,14 +37,14 @@ public class FederatedComputeLearningJobScheduleOrchestrator {
             FederatedComputeLearningJobScheduleOrchestrator.class.getSimpleName();
 
     private static volatile FederatedComputeLearningJobScheduleOrchestrator sInstance;
-    @NonNull
+
     private final Context mContext;
     private final FederatedTrainingTaskDao mFederatedTrainingTaskDao;
     private final JobSchedulerHelper mJobSchedulerHelper;
 
     @VisibleForTesting
     FederatedComputeLearningJobScheduleOrchestrator(
-            @NonNull Context context,
+            Context context,
             FederatedTrainingTaskDao federatedTrainingTaskDao,
             JobSchedulerHelper jobSchedulerHelper) {
         this.mContext = context.getApplicationContext();
@@ -57,17 +55,15 @@ public class FederatedComputeLearningJobScheduleOrchestrator {
     /**
      * Returns an instance of the FederatedComputeLearningJobScheduleOrchestrator given a context.
      */
-    public static FederatedComputeLearningJobScheduleOrchestrator getInstance(
-            @NonNull Context context) {
+    public static FederatedComputeLearningJobScheduleOrchestrator getInstance(Context context) {
         if (sInstance == null) {
             synchronized (FederatedComputeLearningJobScheduleOrchestrator.class) {
                 if (sInstance == null) {
-                    Clock clock = MonotonicClock.getInstance();
                     sInstance =
                             new FederatedComputeLearningJobScheduleOrchestrator(
                                     context.getApplicationContext(),
                                     FederatedTrainingTaskDao.getInstance(context),
-                                    new JobSchedulerHelper(clock));
+                                    new JobSchedulerHelper(MonotonicClock.getInstance()));
                 }
             }
         }
@@ -87,16 +83,20 @@ public class FederatedComputeLearningJobScheduleOrchestrator {
         }
         // get all tasks from DB
         List<FederatedTrainingTask> tasks =
-                mFederatedTrainingTaskDao.getFederatedTrainingTask(null, null);
-        if (tasks != null) {
-            for (FederatedTrainingTask task : tasks) {
-                LogUtil.d(TAG, "checkAndSchedule found task with jobId %d!", task.jobId());
-                // check if task is scheduled already
-                if (jobScheduler.getPendingJob(task.jobId()) == null) {
-                    LogUtil.d(TAG, "task with jobId %d is not scheduled!", task.jobId());
-                    //reschedule if task is not scheduled already
-                    mJobSchedulerHelper.scheduleTask(mContext, task);
-                }
+                mFederatedTrainingTaskDao.getFederatedTrainingTask(
+                        /* selection= */ null, /* selectionArgs= */ null);
+        if (tasks == null) {
+            // No existing tasks that need to be scheduled
+            return;
+        }
+        for (FederatedTrainingTask task : tasks) {
+            LogUtil.d(TAG, "checkAndSchedule found task with jobId %d!", task.jobId());
+
+            // check if task is scheduled already
+            if (jobScheduler.getPendingJob(task.jobId()) == null) {
+                LogUtil.d(TAG, "task with jobId %d is not scheduled!", task.jobId());
+                // reschedule if task is not scheduled already
+                mJobSchedulerHelper.scheduleTask(mContext, task);
             }
         }
     }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedJobIdGenerator.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedJobIdGenerator.java
index 77475854..989e834e 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedJobIdGenerator.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/FederatedJobIdGenerator.java
@@ -18,14 +18,18 @@ package com.android.federatedcompute.services.scheduling;
 
 import android.content.Context;
 
+import com.android.internal.annotations.GuardedBy;
+
 /** Used to generate job scheduler ids for federated compute jobs. */
-public class FederatedJobIdGenerator {
+class FederatedJobIdGenerator {
+
+    @GuardedBy("FederatedJobIdGenerator.class")
     private static FederatedJobIdGenerator sSingleton = null;
 
     private FederatedJobIdGenerator() {}
 
     /** Gets a singleton instance of {@link FederatedJobIdGenerator}. */
-    public static FederatedJobIdGenerator getInstance() {
+    static FederatedJobIdGenerator getInstance() {
         synchronized (FederatedJobIdGenerator.class) {
             if (sSingleton == null) {
                 sSingleton = new FederatedJobIdGenerator();
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelper.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelper.java
index a45c0720..bdc61a63 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelper.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/JobSchedulerHelper.java
@@ -28,19 +28,21 @@ import com.android.odp.module.common.Clock;
 import com.google.common.annotations.VisibleForTesting;
 
 /** The helper class of JobScheduler. */
-public class JobSchedulerHelper {
+class JobSchedulerHelper {
     private static final String TAG = JobSchedulerHelper.class.getSimpleName();
+
     @VisibleForTesting
-    public static final String TRAINING_JOB_SERVICE =
+    static final String TRAINING_JOB_SERVICE =
             "com.android.federatedcompute.services.training.FederatedJobService";
-    private Clock mClock;
 
-    public JobSchedulerHelper(Clock clock) {
+    private final Clock mClock;
+
+    JobSchedulerHelper(Clock clock) {
         this.mClock = clock;
     }
 
     /** Schedules a task using JobScheduler. */
-    public boolean scheduleTask(Context context, FederatedTrainingTask newTask) {
+    boolean scheduleTask(Context context, FederatedTrainingTask newTask) {
         JobInfo jobInfo = convertToJobInfo(context, newTask);
         LogUtil.i(
                 TAG,
@@ -51,7 +53,7 @@ public class JobSchedulerHelper {
     }
 
     /** Cancels a task using JobScheduler. */
-    public void cancelTask(Context context, FederatedTrainingTask taskToCancel) {
+    void cancelTask(Context context, FederatedTrainingTask taskToCancel) {
         final JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
         jobScheduler.cancel(taskToCancel.jobId());
     }
@@ -74,7 +76,7 @@ public class JobSchedulerHelper {
         return jobScheduler.schedule(jobInfo) == JobScheduler.RESULT_SUCCESS;
     }
 
-    private boolean checkCollidesWithNonFederatedComputationJob(
+    private static boolean checkCollidesWithNonFederatedComputationJob(
             JobScheduler jobScheduler, JobInfo jobInfo) {
         JobInfo existingJobInfo = jobScheduler.getPendingJob(jobInfo.getId());
         if (existingJobInfo == null) {
@@ -108,7 +110,7 @@ public class JobSchedulerHelper {
     }
 
     /** Checks if a task is already scheduled by JobScheduler. */
-    public boolean isTaskScheduled(Context context, FederatedTrainingTask task) {
+    boolean isTaskScheduled(Context context, FederatedTrainingTask task) {
         final JobScheduler jobScheduler = context.getSystemService(JobScheduler.class);
         return jobScheduler.getPendingJob(task.jobId()) != null;
     }
diff --git a/federatedcompute/src/com/android/federatedcompute/services/scheduling/SchedulingUtil.java b/federatedcompute/src/com/android/federatedcompute/services/scheduling/SchedulingUtil.java
index 3b593270..d0de4319 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/scheduling/SchedulingUtil.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/scheduling/SchedulingUtil.java
@@ -33,11 +33,11 @@ import com.google.intelligence.fcp.client.engine.TaskRetry;
 import java.util.Random;
 
 /** The util function about federated job scheduler. */
-public class SchedulingUtil {
+class SchedulingUtil {
     private SchedulingUtil() {}
 
     /** Gets the next run time when federated compute job finishes. */
-    public static long getEarliestRuntimeForFCReschedule(
+    static long getEarliestRuntimeForFCReschedule(
             long nowMs,
             TrainingIntervalOptions interval,
             TaskRetry taskRetry,
@@ -77,7 +77,7 @@ public class SchedulingUtil {
     }
 
     /** Gets the next run time when first time schedule the federated compute job. */
-    public static long getEarliestRuntimeForInitialSchedule(
+    static long getEarliestRuntimeForInitialSchedule(
             long nowMs, long lastRunTimeMs, TrainingOptions trainerOptions, Flags flags) {
         long defaultNextRunTimeMs =
                 nowMs + SECONDS.toMillis(flags.getDefaultSchedulingPeriodSecs());
@@ -114,7 +114,7 @@ public class SchedulingUtil {
     }
 
     /** Gets the next run time when the federated job with same job id may be running. */
-    public static long getEarliestRuntimeForExistingTask(
+    static long getEarliestRuntimeForExistingTask(
             FederatedTrainingTask existingTask,
             TrainingOptions trainingOptions,
             Flags flags,
@@ -131,7 +131,7 @@ public class SchedulingUtil {
     }
 
     /** Gets the task retry range for transient error happens and worth retry. */
-    public static TaskRetry generateTransientErrorTaskRetry(Flags flags) {
+    static TaskRetry generateTransientErrorTaskRetry(Flags flags) {
         double jitterPercent = min(1.0, max(0.0, flags.getTransientErrorRetryDelayJitterPercent()));
         long targetDelayMillis = SECONDS.toMillis(flags.getTransientErrorRetryDelaySecs());
         long maxDelay = (long) (targetDelayMillis * (1.0 + jitterPercent));
@@ -140,7 +140,7 @@ public class SchedulingUtil {
     }
 
     /** Generates a random delay between the provided min and max values. */
-    private static long generateMinimumDelayMillisFromRange(long minMillis, long maxMillis) {
+    static long generateMinimumDelayMillisFromRange(long minMillis, long maxMillis) {
         // Sanitize the min/max values.
         minMillis = max(0, minMillis);
         maxMillis = max(minMillis, maxMillis);
@@ -167,7 +167,7 @@ public class SchedulingUtil {
     }
 
     /** Converts from TrainingOptions SchedulingMode to the storage fbs.SchedulingMode. */
-    public static int convertSchedulingMode(@TrainingInterval.SchedulingMode int schedulingMode) {
+    static int convertSchedulingMode(@TrainingInterval.SchedulingMode int schedulingMode) {
         if (schedulingMode == TrainingInterval.SCHEDULING_MODE_RECURRENT) {
             return SchedulingMode.RECURRENT;
         } else if (schedulingMode == TrainingInterval.SCHEDULING_MODE_ONE_TIME) {
diff --git a/federatedcompute/src/com/android/federatedcompute/services/training/ComputationRunner.java b/federatedcompute/src/com/android/federatedcompute/services/training/ComputationRunner.java
index 6c5b6311..e80fbf5c 100644
--- a/federatedcompute/src/com/android/federatedcompute/services/training/ComputationRunner.java
+++ b/federatedcompute/src/com/android/federatedcompute/services/training/ComputationRunner.java
@@ -30,17 +30,17 @@ import com.google.internal.federated.plan.ExampleSelector;
 
 /**
  * Centralized class for running a single computation session. It calls to native fcp client to
- * start federated ananlytic and federated training jobs.
+ * start federated analytics and federated training jobs.
  */
-public class ComputationRunner {
+class ComputationRunner {
     private final Context mContext;
 
-    public ComputationRunner(Context context) {
+    ComputationRunner(Context context) {
         this.mContext = context;
     }
 
     /** Run a single round of federated computation. */
-    public FLRunnerResult runTaskWithNativeRunner(
+    FLRunnerResult runTaskWithNativeRunner(
             String taskName,
             String populationName,
             String inputCheckpointFd,
@@ -62,14 +62,7 @@ public class ComputationRunner {
         FlRunnerWrapper flRunnerWrapper =
                 new FlRunnerWrapper(interruptState, populationName, federatedExampleIterator);
 
-        FLRunnerResult runResult =
-                flRunnerWrapper.run(
-                        taskName,
-                        populationName,
-                        clientOnlyPlan,
-                        inputCheckpointFd,
-                        outputCheckpointFd);
-
-        return runResult;
+        return flRunnerWrapper.run(
+                taskName, populationName, clientOnlyPlan, inputCheckpointFd, outputCheckpointFd);
     }
 }
diff --git a/framework/java/android/adservices/ondevicepersonalization/Constants.java b/framework/java/android/adservices/ondevicepersonalization/Constants.java
index c4fb23d4..2afa3bef 100644
--- a/framework/java/android/adservices/ondevicepersonalization/Constants.java
+++ b/framework/java/android/adservices/ondevicepersonalization/Constants.java
@@ -93,6 +93,10 @@ public class Constants {
     public static final int STATUS_PARSE_ERROR = 128;
     // Internal code that tracks non-empty but not enough data from data storage or example store.
     public static final int STATUS_SUCCESS_NOT_ENOUGH_DATA = 129;
+    // Download file size exceeds size limit.
+    public static final int STATUS_DOWNLOAD_SIZE_EXCEED_CAP_ERROR = 130;
+    // Store content size exceeds size limit.
+    public static final int STATUS_STORAGE_SIZE_EXCEED_CAP_ERROR = 131;
 
     // Operations implemented by IsolatedService.
     public static final int OP_EXECUTE = 1;
diff --git a/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesInput.java b/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesInput.java
index 69ec0cde..e79e0c8c 100644
--- a/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesInput.java
+++ b/framework/java/android/adservices/ondevicepersonalization/TrainingExamplesInput.java
@@ -30,14 +30,14 @@ public final class TrainingExamplesInput {
      * The name of the federated compute population. It should match the population name in {@link
      * FederatedComputeInput#getPopulationName}.
      */
-    @NonNull private String mPopulationName = "";
+    @NonNull private final String mPopulationName;
 
     /**
      * The name of the task within the population. It should match task plan configured at remote
      * federated compute server. One population may have multiple tasks. The task name can be used
      * to uniquely identify the job.
      */
-    @NonNull private String mTaskName = "";
+    @NonNull private final String mTaskName;
 
     /**
      * Token used to support the resumption of training. If client app wants to use resumption token
@@ -45,15 +45,13 @@ public final class TrainingExamplesInput {
      * {@link TrainingExampleRecord.Builder#setResumptionToken}, OnDevicePersonalization will store
      * it and pass it here for generating new training examples.
      */
-    @Nullable private byte[] mResumptionToken = null;
+    @Nullable private final byte[] mResumptionToken;
 
-    /**
-     * The data collection name to use to create training examples.
-     */
-    @Nullable private String mCollectionName;
+    /** The data collection name to use to create training examples. */
+    @Nullable private final String mCollectionName;
 
     /** @hide */
-    public TrainingExamplesInput(@NonNull TrainingExamplesInputParcel parcel) {
+    TrainingExamplesInput(@NonNull TrainingExamplesInputParcel parcel) {
         this(
                 parcel.getPopulationName(),
                 parcel.getTaskName(),
@@ -92,7 +90,8 @@ public final class TrainingExamplesInput {
      * The name of the federated compute population. It should match the population name in {@link
      * FederatedComputeInput#getPopulationName}.
      */
-    public @NonNull String getPopulationName() {
+    @NonNull
+    public String getPopulationName() {
         return mPopulationName;
     }
 
@@ -101,7 +100,8 @@ public final class TrainingExamplesInput {
      * federated compute server. One population may have multiple tasks. The task name can be used
      * to uniquely identify the job.
      */
-    public @NonNull String getTaskName() {
+    @NonNull
+    public String getTaskName() {
         return mTaskName;
     }
 
@@ -111,13 +111,15 @@ public final class TrainingExamplesInput {
      * {@link TrainingExampleRecord.Builder#setResumptionToken}, OnDevicePersonalization will store
      * it and pass it here for generating new training examples.
      */
-    public @Nullable byte[] getResumptionToken() {
+    @Nullable
+    public byte[] getResumptionToken() {
         return mResumptionToken;
     }
 
     /** The data collection name to use to create training examples. */
     @FlaggedApi(Flags.FLAG_FCP_MODEL_VERSION_ENABLED)
-    public @Nullable String getCollectionName() {
+    @Nullable
+    public String getCollectionName() {
         return mCollectionName;
     }
 
diff --git a/framework/java/android/federatedcompute/FederatedComputeManager.java b/framework/java/android/federatedcompute/FederatedComputeManager.java
index d28cea46..28364038 100644
--- a/framework/java/android/federatedcompute/FederatedComputeManager.java
+++ b/framework/java/android/federatedcompute/FederatedComputeManager.java
@@ -22,12 +22,15 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.federatedcompute.aidl.IFederatedComputeCallback;
 import android.federatedcompute.aidl.IFederatedComputeService;
+import android.federatedcompute.aidl.IIsFeatureEnabledCallback;
 import android.federatedcompute.common.ScheduleFederatedComputeRequest;
 import android.os.Binder;
 import android.os.OutcomeReceiver;
 
 import com.android.federatedcompute.internal.util.AbstractServiceBinder;
 import com.android.federatedcompute.internal.util.LogUtil;
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 
 import java.util.List;
 import java.util.Objects;
@@ -56,6 +59,7 @@ public final class FederatedComputeManager {
     private static final String ALT_FEDERATED_COMPUTATION_SERVICE_PACKAGE =
             "com.google.android.federatedcompute";
 
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
     private final Context mContext;
 
     private final AbstractServiceBinder<IFederatedComputeService> mServiceBinder;
@@ -71,6 +75,14 @@ public final class FederatedComputeManager {
                                 ALT_FEDERATED_COMPUTATION_SERVICE_PACKAGE),
                         IFederatedComputeService.Stub::asInterface);
     }
+    /** @hide */
+    @VisibleForTesting
+    public FederatedComputeManager(
+            Context context,
+            AbstractServiceBinder<IFederatedComputeService> serviceBinder) {
+        mContext = context;
+        mServiceBinder = serviceBinder;
+    }
 
     /**
      * Schedule FederatedCompute task.
@@ -162,6 +174,33 @@ public final class FederatedComputeManager {
         }
     }
 
+    /**
+     * Check feature availability.
+     *
+     * @hide
+     */
+    public void isFeatureEnabled(
+            @NonNull String featureName,
+            @NonNull @CallbackExecutor Executor executor,
+            @NonNull OutcomeReceiver<Integer, Exception> callback) {
+        Objects.requireNonNull(featureName);
+        final IFederatedComputeService service = mServiceBinder.getService(executor);
+        try {
+            IIsFeatureEnabledCallback callbackWrapper = new IIsFeatureEnabledCallback.Stub() {
+                @Override
+                public void onResult(int result) {
+                    executor.execute(() -> callback.onResult(result));
+                    unbindFromService();
+                }
+            };
+            service.isFeatureEnabled(featureName, callbackWrapper);
+        } catch (Exception e) {
+            LogUtil.e(TAG, e, "Exception querying feature availability %s", featureName);
+            executor.execute(() -> callback.onError(e));
+            unbindFromService();
+        }
+    }
+
     public void unbindFromService() {
         mServiceBinder.unbindFromService();
     }
diff --git a/framework/java/android/federatedcompute/aidl/IFederatedComputeService.aidl b/framework/java/android/federatedcompute/aidl/IFederatedComputeService.aidl
index 7b55b06a..56ea78bf 100644
--- a/framework/java/android/federatedcompute/aidl/IFederatedComputeService.aidl
+++ b/framework/java/android/federatedcompute/aidl/IFederatedComputeService.aidl
@@ -18,6 +18,7 @@ package android.federatedcompute.aidl;
 
 import android.federatedcompute.common.TrainingOptions;
 import android.federatedcompute.aidl.IFederatedComputeCallback;
+import android.federatedcompute.aidl.IIsFeatureEnabledCallback;
 
 /** @hide */
 interface IFederatedComputeService {
@@ -30,4 +31,8 @@ interface IFederatedComputeService {
     in ComponentName ownerComponent,
     in String populationName,
     in IFederatedComputeCallback callback);
+
+    void isFeatureEnabled(
+    in String featureName,
+    in IIsFeatureEnabledCallback callback);
 }
\ No newline at end of file
diff --git a/framework/java/android/federatedcompute/aidl/IIsFeatureEnabledCallback.aidl b/framework/java/android/federatedcompute/aidl/IIsFeatureEnabledCallback.aidl
new file mode 100644
index 00000000..74d6e92e
--- /dev/null
+++ b/framework/java/android/federatedcompute/aidl/IIsFeatureEnabledCallback.aidl
@@ -0,0 +1,22 @@
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
+package android.federatedcompute.aidl;
+
+/** @hide */
+oneway interface IIsFeatureEnabledCallback {
+    void onResult(in int result);
+}
\ No newline at end of file
diff --git a/src/com/android/ondevicepersonalization/services/Flags.java b/src/com/android/ondevicepersonalization/services/Flags.java
index 17cee0d1..a31cb032 100644
--- a/src/com/android/ondevicepersonalization/services/Flags.java
+++ b/src/com/android/ondevicepersonalization/services/Flags.java
@@ -72,9 +72,7 @@ public interface Flags extends ModuleSharedFlags {
      */
     int WEB_VIEW_FLOW_DEADLINE_SECONDS = 30;
 
-    /**
-     * Executiton deadline for web trigger flow.
-     */
+    /** Execution deadline for web trigger flow. */
     int WEB_TRIGGER_FLOW_DEADLINE_SECONDS = 30;
 
     /** Default value for the list of trusted partner app names. */
@@ -363,6 +361,16 @@ public interface Flags extends ModuleSharedFlags {
         return DEFAULT_AGGREGATED_ERROR_REPORT_TTL_DAYS;
     }
 
+    String DEFAULT_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL = "";
+
+    /**
+     * Override URL that the reporting job will use to send adopters daily aggregated counts of
+     * {@link android.adservices.ondevicepersonalization.IsolatedServiceException}s.
+     */
+    default String getAggregatedErrorReportingServerOverrideUrl() {
+        return DEFAULT_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL;
+    }
+
     String DEFAULT_AGGREGATED_ERROR_REPORTING_URL_PATH =
             "/debugreporting/v1/exceptions:report-exceptions";
 
@@ -464,6 +472,24 @@ public interface Flags extends ModuleSharedFlags {
         return DEFAULT_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS;
     }
 
+    /**
+     * Default download size limit in MB.
+     */
+    long DEFAULT_DOWNLOAD_REJECT_CAP_IN_MB = 100 * 1024 * 1024;
+
+    default long getDefaultDownloadRejectCapInMb() {
+        return DEFAULT_DOWNLOAD_REJECT_CAP_IN_MB;
+    }
+
+    /**
+     * Default storage size limit in MB to reject any remote storage attempt.
+     */
+    long DEFAULT_STORAGE_CAP_IN_MB = 100 * 1024 * 1024;
+
+    default long getDefaultStorageCapInMb() {
+        return DEFAULT_STORAGE_CAP_IN_MB;
+    }
+
     String DEFAULT_PLATFORM_DATA_FOR_TRAINING_ALLOWLIST = "";
 
     default String getPlatformDataForTrainingAllowlist() {
@@ -491,4 +517,58 @@ public interface Flags extends ModuleSharedFlags {
     default boolean isFeatureEnabledApiEnabled() {
         return DEFAULT_IS_FEATURE_ENABLED_API_ENABLED;
     }
+
+    String DEFAULT_MDD_MAINTENANCE_JOB_POLICY = "";
+
+    default String getMddMaintenanceJobPolicy() {
+        return DEFAULT_MDD_MAINTENANCE_JOB_POLICY;
+    }
+
+    String DEFAULT_MDD_CHARGING_JOB_POLICY = "";
+
+    default String getMddChargingJobPolicy() {
+        return DEFAULT_MDD_CHARGING_JOB_POLICY;
+    }
+
+    String DEFAULT_MDD_CELLULAR_CHARGING_JOB_POLICY = "";
+
+    default String getMddCellularChargingJobPolicy() {
+        return DEFAULT_MDD_CELLULAR_CHARGING_JOB_POLICY;
+    }
+
+    String DEFAULT_MDD_WIFI_CHARGING_JOB_POLICY = "";
+
+    default String getMddWifiChargingJobPolicy() {
+        return DEFAULT_MDD_WIFI_CHARGING_JOB_POLICY;
+    }
+
+    String DEFAULT_DOWNLOAD_PROCESSING_JOB_POLICY = "";
+
+    default String getDownloadProcessingJobPolicy() {
+        return DEFAULT_DOWNLOAD_PROCESSING_JOB_POLICY;
+    }
+
+    String DEFAULT_MAINTENANCE_JOB_POLICY = "";
+
+    default String getMaintenanceJobPolicy() {
+        return DEFAULT_MAINTENANCE_JOB_POLICY;
+    }
+
+    String DEFAULT_USER_DATA_COLLECTION_JOB_POLICY = "";
+
+    default String getUserDataCollectionJobPolicy() {
+        return DEFAULT_USER_DATA_COLLECTION_JOB_POLICY;
+    }
+
+    String DEFAULT_RESET_DATA_JOB_POLICY = "";
+
+    default String getResetDataJobPolicy() {
+        return DEFAULT_RESET_DATA_JOB_POLICY;
+    }
+
+    String DEFAULT_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY = "";
+
+    default String getAggregateErrorDataReportingJobPolicy() {
+        return DEFAULT_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY;
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/FlagsConstants.java b/src/com/android/ondevicepersonalization/services/FlagsConstants.java
index fc014332..6dd98d30 100644
--- a/src/com/android/ondevicepersonalization/services/FlagsConstants.java
+++ b/src/com/android/ondevicepersonalization/services/FlagsConstants.java
@@ -108,6 +108,9 @@ public final class FlagsConstants {
     public static final String KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS =
             "Odp__aggregated_error_report_ttl_days";
 
+    public static final String KEY_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL =
+            "Odp__override_aggregated_error_reporting_url";
+
     public static final String KEY_AGGREGATED_ERROR_REPORTING_PATH =
             "Odp__aggregated_error_reporting_path";
 
@@ -133,6 +136,10 @@ public final class FlagsConstants {
 
     public static final String KEY_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS =
             "adservices_ipc_call_timeout_in_millis";
+
+    public static final String KEY_DOWNLOAD_REJECT_CAP_IN_MB = "Odp__download_reject_cap_in_mb";
+
+    public static final String KEY_STORAGE_CAP_IN_MB = "Odp__storage_cap_in_mb";
     public static final String KEY_PLATFORM_DATA_FOR_TRAINING_ALLOWLIST =
             "platform_data_for_training_allowlist";
     public static final String KEY_PLATFORM_DATA_FOR_EXECUTE_ALLOWLIST =
@@ -152,4 +159,34 @@ public final class FlagsConstants {
 
     public static final String KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS =
             "example_store_flow_deadline_seconds";
+
+    public static final String KEY_ENABLE_PER_JOB_POLICY =
+            "OdpBackgroundJobs__enable_per_job_policy";
+
+    public static final String KEY_MDD_MAINTENANCE_JOB_POLICY =
+            "OdpBackgroundJobs__mdd_maintenance_job_policy";
+
+    public static final String KEY_MDD_CHARGING_JOB_POLICY =
+            "OdpBackgroundJobs__mdd_charging_job_policy";
+
+    public static final String KEY_MDD_CELLULAR_CHARGING_JOB_POLICY =
+            "OdpBackgroundJobs__mdd_cellular_charging_job_policy";
+
+    public static final String KEY_MDD_WIFI_CHARGING_JOB_POLICY =
+            "OdpBackgroundJobs__mdd_wifi_charging_job_policy";
+
+    public static final String KEY_DOWNLOAD_PROCESSING_JOB_POLICY =
+            "OdpBackgroundJobs__download_processing_job_policy";
+
+    public static final String KEY_MAINTENANCE_JOB_POLICY =
+            "OdpBackgroundJobs__maintenance_job_policy";
+
+    public static final String KEY_USER_DATA_COLLECTION_JOB_POLICY =
+            "OdpBackgroundJobs__user_data_collection_job_policy";
+
+    public static final String KEY_RESET_DATA_JOB_POLICY =
+            "OdpBackgroundJobs__reset_data_job_policy";
+
+    public static final String KEY_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY =
+            "OdpBackgroundJobs__aggregate_error_data_reporting_job_policy";
 }
diff --git a/src/com/android/ondevicepersonalization/services/FlagsFactory.java b/src/com/android/ondevicepersonalization/services/FlagsFactory.java
index 62e3aa4a..a20b0dd0 100644
--- a/src/com/android/ondevicepersonalization/services/FlagsFactory.java
+++ b/src/com/android/ondevicepersonalization/services/FlagsFactory.java
@@ -18,6 +18,9 @@ package com.android.ondevicepersonalization.services;
 
 /** Factory class for creating OnDevicePersonalization Flags */
 public class FlagsFactory {
+
+    private FlagsFactory() {}
+
     /** OnDevicePersonalization Flags backed by Phenotype/Heterodyne. */
     public static Flags getFlags() {
         // Use the Flags backed by PH.
diff --git a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceImpl.java b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceImpl.java
index 95fe0e95..748520d8 100644
--- a/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceImpl.java
+++ b/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceImpl.java
@@ -25,12 +25,17 @@ import android.os.IBinder;
 import android.os.Trace;
 
 
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+
 import com.google.common.annotations.VisibleForTesting;
 
 import java.util.concurrent.Executor;
 
 /** Implementation of OnDevicePersonalization Service */
 public class OnDevicePersonalizationManagingServiceImpl extends Service {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG =
+            OnDevicePersonalizationManagingServiceImpl.class.getSimpleName();
     private IOnDevicePersonalizationManagingService.Stub mBinder;
 
     private Executor mExecutor;
@@ -46,6 +51,10 @@ public class OnDevicePersonalizationManagingServiceImpl extends Service {
 
     @Override
     public void onCreate() {
+        if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
+            sLogger.d(TAG + "ODP Global kill switch is on, ODP is disabled.");
+            return;
+        }
         Trace.beginSection("OdpManagingService#Initialization");
         if (mBinder == null) {
             mBinder = new OnDevicePersonalizationManagingServiceDelegate(this);
@@ -56,6 +65,11 @@ public class OnDevicePersonalizationManagingServiceImpl extends Service {
 
     @Override
     public IBinder onBind(Intent intent) {
+        if (FlagsFactory.getFlags().getGlobalKillSwitch()) {
+            sLogger.d(TAG + "ODP Global kill switch is on, ODP is disabled.");
+            // Return null so that clients can not bind to the service.
+            return null;
+        }
         return mBinder;
     }
 }
diff --git a/src/com/android/ondevicepersonalization/services/PhFlags.java b/src/com/android/ondevicepersonalization/services/PhFlags.java
index 68211f3b..297a8c52 100644
--- a/src/com/android/ondevicepersonalization/services/PhFlags.java
+++ b/src/com/android/ondevicepersonalization/services/PhFlags.java
@@ -22,15 +22,20 @@ import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AD
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_PATH;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_CALLER_APP_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_DOWNLOAD_PROCESSING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_DOWNLOAD_REJECT_CAP_IN_MB;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PER_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENCRYPTION_KEY_URL;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS;
@@ -41,6 +46,16 @@ import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_FEATURE_ENABLED_API_ENABLED;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_LOG_ISOLATED_SERVICE_ERROR_CODE_NON_AGGREGATED_ALLOWLIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MAINTENANCE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MDD_CELLULAR_CHARGING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MDD_CHARGING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MDD_MAINTENANCE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MDD_WIFI_CHARGING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_JOB_SCHEDULING_LOGGING_ENABLED;
@@ -55,35 +70,30 @@ import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PL
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RENDER_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RESET_DATA_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RESET_DATA_DELAY_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RESET_DATA_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_STORAGE_CAP_IN_MB;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_TRUSTED_PARTNER_APPS_LIST;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_USER_CONTROL_CACHE_IN_MILLIS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_USER_DATA_COLLECTION_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.MAX_INT_VALUES_LIMIT;
+import static com.android.ondevicepersonalization.services.util.DebugUtils.getSystemPropertyName;
 
 import android.annotation.NonNull;
+import android.os.SystemProperties;
 import android.provider.DeviceConfig;
 
 import com.android.modules.utils.build.SdkLevel;
 
-import java.util.HashMap;
-import java.util.Map;
-
 /** Flags Implementation that delegates to DeviceConfig. */
 public final class PhFlags implements Flags {
 
     // OnDevicePersonalization Namespace String from DeviceConfig class
-    public static final String NAMESPACE_ON_DEVICE_PERSONALIZATION = "on_device_personalization";
+    private static final String NAMESPACE_ON_DEVICE_PERSONALIZATION = "on_device_personalization";
 
-    private final Map<String, Object> mStableFlags = new HashMap<>();
-
-    PhFlags() {}
+    private PhFlags() {}
 
     /** Returns the singleton instance of the PhFlags. */
     @NonNull
@@ -403,6 +413,14 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */ DEFAULT_AGGREGATED_ERROR_REPORT_TTL_DAYS);
     }
 
+    @Override
+    public String getAggregatedErrorReportingServerOverrideUrl() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL,
+                /* defaultValue= */ DEFAULT_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL);
+    }
+
     @Override
     public String getAggregatedErrorReportingServerPath() {
         return DeviceConfig.getString(
@@ -428,11 +446,16 @@ public final class PhFlags implements Flags {
     }
 
     @Override
+    /**
+     * Whether to disable encryption when uploading aggregated error results. Defaults to false.
+     *
+     * <p>This flag is configured via a System Property unlike most flags that rely on device config
+     * instead.
+     */
     public boolean getAllowUnencryptedAggregatedErrorReportingPayload() {
-        return DeviceConfig.getBoolean(
-                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
-                /* name= */ KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING,
-                /* defaultValue= */ DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD);
+        return SystemProperties.getBoolean(
+                getSystemPropertyName(KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING),
+                DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD);
     }
 
     @Override
@@ -483,6 +506,22 @@ public final class PhFlags implements Flags {
                 /* defaultValue= */ DEFAULT_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS);
     }
 
+    @Override
+    public long getDefaultDownloadRejectCapInMb() {
+        return DeviceConfig.getLong(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_DOWNLOAD_REJECT_CAP_IN_MB,
+                /* defaultValue= */ DEFAULT_DOWNLOAD_REJECT_CAP_IN_MB);
+    }
+
+    @Override
+    public long getDefaultStorageCapInMb() {
+        return DeviceConfig.getLong(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_STORAGE_CAP_IN_MB,
+                /* defaultValue= */ DEFAULT_STORAGE_CAP_IN_MB);
+    }
+
     @Override
     public String getPlatformDataForTrainingAllowlist() {
         return DeviceConfig.getString(
@@ -523,4 +562,84 @@ public final class PhFlags implements Flags {
                 /* name= */ KEY_IS_FEATURE_ENABLED_API_ENABLED,
                 /* defaultValue= */ DEFAULT_IS_FEATURE_ENABLED_API_ENABLED);
     }
+
+    @Override
+    public boolean getSpeEnablePerJobPolicy() {
+        return DeviceConfig.getBoolean(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_ENABLE_PER_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_SPE_ENABLE_PER_JOB_POLICY);
+    }
+
+    @Override
+    public String getMddMaintenanceJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_MDD_MAINTENANCE_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_MDD_MAINTENANCE_JOB_POLICY);
+    }
+
+    @Override
+    public String getMddChargingJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_MDD_CHARGING_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_MDD_CHARGING_JOB_POLICY);
+    }
+
+    @Override
+    public String getMddCellularChargingJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_MDD_CELLULAR_CHARGING_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_MDD_CELLULAR_CHARGING_JOB_POLICY);
+    }
+
+    @Override
+    public String getMddWifiChargingJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_MDD_WIFI_CHARGING_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_MDD_WIFI_CHARGING_JOB_POLICY);
+    }
+
+    @Override
+    public String getDownloadProcessingJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_DOWNLOAD_PROCESSING_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_DOWNLOAD_PROCESSING_JOB_POLICY);
+    }
+
+    @Override
+    public String getMaintenanceJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_MAINTENANCE_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_MAINTENANCE_JOB_POLICY);
+    }
+
+    @Override
+    public String getUserDataCollectionJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_USER_DATA_COLLECTION_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_USER_DATA_COLLECTION_JOB_POLICY);
+    }
+
+    @Override
+    public String getResetDataJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_RESET_DATA_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_RESET_DATA_JOB_POLICY);
+    }
+
+    @Override
+    public String getAggregateErrorDataReportingJobPolicy() {
+        return DeviceConfig.getString(
+                /* namespace= */ NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                /* name= */ KEY_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY,
+                /* defaultValue= */ DEFAULT_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY);
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJob.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJob.java
index 847075a3..fee34f55 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJob.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJob.java
@@ -132,15 +132,22 @@ public final class AggregateErrorDataReportingJob implements JobWorker {
         return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
     }
 
+    @Override
+    public String getJobPolicyString(int jobId) {
+        return FlagsFactory.getFlags().getAggregateErrorDataReportingJobPolicy();
+    }
+
     /** Schedules a unique instance of {@link AggregateErrorDataReportingJob}. */
     public static void schedule(Context context) {
         // If SPE is not enabled, force to schedule the job with the old JobService.
         if (!FlagsFactory.getFlags().getSpeOnAggregateErrorDataReportingJobEnabled()) {
-            sLogger.d("SPE is not enabled. Schedule the job with"
-                    + " AggregateErrorDataReportingService.");
+            sLogger.d(
+                    "SPE is not enabled. Schedule the job with"
+                            + " AggregateErrorDataReportingService.");
 
-            int resultCode = AggregateErrorDataReportingService
-                    .scheduleIfNeeded(context, /* forceSchedule */ false);
+            int resultCode =
+                    AggregateErrorDataReportingService.scheduleIfNeeded(
+                            context, /* forceSchedule */ false);
             OdpJobServiceFactory.getInstance(context)
                     .getJobSchedulingLogger()
                     .recordOnSchedulingLegacy(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID, resultCode);
diff --git a/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java
index a0d2a5a6..1620c9ab 100644
--- a/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java
+++ b/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorker.java
@@ -97,6 +97,13 @@ class AggregatedErrorReportingWorker {
             return AggregatedErrorReportingWorker.getFcRemoteServerUrl(context, packageName);
         }
 
+        String getErrorReportingServerOverrideUrl() {
+            // URL set by PH Flags to override manifest based url.
+            // Note that this only overrides the base path and the override value is shared
+            // across all adopters.
+            return FlagsFactory.getFlags().getAggregatedErrorReportingServerOverrideUrl();
+        }
+
         long getErrorReportingIntervalHours() {
             return FlagsFactory.getFlags().getAggregatedErrorReportingIntervalInHours();
         }
@@ -231,8 +238,17 @@ class AggregatedErrorReportingWorker {
                     continue;
                 }
 
-                String fcServerUrl =
-                        mInjector.getServerUrl(context, componentName.getPackageName());
+                // Defer to override url if present, else use the URL from adopter manifest.
+                // Note that override url is not adopter specific.
+                String overrideUrl = mInjector.getErrorReportingServerOverrideUrl();
+                String fcServerUrl = "";
+                if (overrideUrl.isEmpty()) {
+                    fcServerUrl = mInjector.getServerUrl(context, componentName.getPackageName());
+                } else {
+                    sLogger.d(TAG + ": Using override URL for error reporting :" + overrideUrl);
+                    fcServerUrl = overrideUrl;
+                }
+
                 if (fcServerUrl.isEmpty()) {
                     sLogger.d(
                             TAG
diff --git a/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJob.java b/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJob.java
index 3d7a6b20..e20b22a8 100644
--- a/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJob.java
+++ b/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJob.java
@@ -107,6 +107,11 @@ public final class UserDataCollectionJob implements JobWorker {
         return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
     }
 
+    @Override
+    public String getJobPolicyString(int jobId) {
+        return FlagsFactory.getFlags().getUserDataCollectionJobPolicy();
+    }
+
     /** Schedules a unique instance of {@link UserDataCollectionJob}. */
     public static void schedule(Context context) {
         // If SPE is not enabled, force to schedule the job with the old JobService.
diff --git a/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java b/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
index d46e9ab7..eb315b6d 100644
--- a/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
+++ b/src/com/android/ondevicepersonalization/services/download/DownloadFlow.java
@@ -30,6 +30,7 @@ import com.android.odp.module.common.Clock;
 import com.android.odp.module.common.MonotonicClock;
 import com.android.odp.module.common.PackageUtils;
 import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+import com.android.ondevicepersonalization.services.FlagsFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 import com.android.ondevicepersonalization.services.data.DataAccessPermission;
 import com.android.ondevicepersonalization.services.data.DataAccessServiceImpl;
@@ -334,6 +335,20 @@ public class DownloadFlow implements ServiceFlow<DownloadCompletedOutputParcel>
         }
 
         ClientConfigProto.ClientFile clientFile = cfg.getFile(0);
+        int fileSize = clientFile.getFullSizeInBytes();
+        if (fileSize > FlagsFactory.getFlags().getDefaultDownloadRejectCapInMb()) {
+            // File size exceeds download limit is a valid case. Mark as success and return null.
+            StatsUtils.writeServiceRequestMetrics(
+                    Constants.API_NAME_SERVICE_ON_DOWNLOAD_COMPLETED,
+                    mService.getPackageName(),
+                    /* result= */ null,
+                    mInjector.getClock(),
+                    Constants.STATUS_DOWNLOAD_SIZE_EXCEED_CAP_ERROR,
+                    mStartServiceTimeMillis);
+            sLogger.d(TAG + ": File size " + fileSize + " exceed download size cap.");
+            mCallback.onSuccess(null);
+            return null;
+        }
         return Uri.parse(clientFile.getFileUri());
     }
 
diff --git a/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJob.java b/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJob.java
index d07e8aec..6cbdf241 100644
--- a/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJob.java
+++ b/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJob.java
@@ -122,15 +122,22 @@ public final class OnDevicePersonalizationDownloadProcessingJob implements JobWo
         return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
     }
 
+    @Override
+    public String getJobPolicyString(int jobId) {
+        return FlagsFactory.getFlags().getDownloadProcessingJobPolicy();
+    }
+
     /** Schedules a unique instance of {@link OnDevicePersonalizationDownloadProcessingJob}. */
     public static void schedule(Context context) {
         // If SPE is not enabled, force to schedule the job with the old JobService.
         if (!FlagsFactory.getFlags().getSpeOnOdpDownloadProcessingJobEnabled()) {
-            sLogger.d("SPE is not enabled. Schedule the job with "
-                    + "OnDevicePersonalizationDownloadProcessingJobService.");
+            sLogger.d(
+                    "SPE is not enabled. Schedule the job with "
+                            + "OnDevicePersonalizationDownloadProcessingJobService.");
 
-            int resultCode = OnDevicePersonalizationDownloadProcessingJobService.schedule(
-                    context, /* forceSchedule */ false);
+            int resultCode =
+                    OnDevicePersonalizationDownloadProcessingJobService.schedule(
+                            context, /* forceSchedule */ false);
             OdpJobServiceFactory.getInstance(context)
                     .getJobSchedulingLogger()
                     .recordOnSchedulingLegacy(DOWNLOAD_PROCESSING_TASK_JOB_ID, resultCode);
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/MddJob.java b/src/com/android/ondevicepersonalization/services/download/mdd/MddJob.java
index 62d12dc7..3c1cd6ab 100644
--- a/src/com/android/ondevicepersonalization/services/download/mdd/MddJob.java
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/MddJob.java
@@ -16,13 +16,17 @@
 
 package com.android.ondevicepersonalization.services.download.mdd;
 
-
 import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_KILL_SWITCH_ON;
 import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED;
 import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
 
 import static com.google.android.libraries.mobiledatadownload.TaskScheduler.WIFI_CHARGING_PERIODIC_TASK;
 
+import android.annotation.Nullable;
 import android.content.Context;
 
 import com.android.adservices.shared.spe.framework.ExecutionResult;
@@ -121,4 +125,22 @@ public final class MddJob implements JobWorker {
     public BackoffPolicy getBackoffPolicy() {
         return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
     }
+
+    @Override
+    @Nullable
+    public String getJobPolicyString(int jobId) {
+        Flags flags = FlagsFactory.getFlags();
+
+        if (jobId == MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID) {
+            return flags.getMddMaintenanceJobPolicy();
+        } else if (jobId == MDD_CHARGING_PERIODIC_TASK_JOB_ID) {
+            return flags.getMddChargingJobPolicy();
+        } else if (jobId == MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID) {
+            return flags.getMddCellularChargingJobPolicy();
+        } else if (jobId == MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID) {
+            return flags.getMddWifiChargingJobPolicy();
+        }
+
+        return null;
+    }
 }
diff --git a/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java b/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
index 44d30c82..4cd04485 100644
--- a/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
+++ b/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulator.java
@@ -28,6 +28,7 @@ import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 import com.android.ondevicepersonalization.services.data.vendor.OnDevicePersonalizationVendorDataDao;
 import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
+import com.android.ondevicepersonalization.services.util.DebugUtils;
 
 import com.google.android.libraries.mobiledatadownload.AddFileGroupRequest;
 import com.google.android.libraries.mobiledatadownload.FileGroupPopulator;
@@ -55,7 +56,8 @@ import java.util.Set;
  */
 public class OnDevicePersonalizationFileGroupPopulator implements FileGroupPopulator {
     private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
-    private static final String TAG = "OnDevicePersonalizationFileGroupPopulator";
+    private static final String TAG =
+            OnDevicePersonalizationFileGroupPopulator.class.getSimpleName();
 
     private final Context mContext;
 
@@ -64,10 +66,14 @@ public class OnDevicePersonalizationFileGroupPopulator implements FileGroupPopul
 
     // Set files to expire after 2 days.
     private static final long EXPIRATION_TIME_SECS = 172800;
-    private static final String OVERRIDE_DOWNLOAD_URL_PACKAGE =
-            "debug.ondevicepersonalization.override_download_url_package";
-    private static final String OVERRIDE_DOWNLOAD_URL =
-            "debug.ondevicepersonalization.override_download_url";
+
+    @VisibleForTesting
+    static final String OVERRIDE_DOWNLOAD_URL_PACKAGE =
+            DebugUtils.getSystemPropertyName(/* key= */ "override_download_url_package");
+
+    @VisibleForTesting
+    static final String OVERRIDE_DOWNLOAD_URL =
+            DebugUtils.getSystemPropertyName(/* key= */ "override_download_url");
 
     public OnDevicePersonalizationFileGroupPopulator(Context context) {
         this.mContext = context;
diff --git a/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImpl.java b/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImpl.java
index c524687c..1f95fdcc 100644
--- a/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImpl.java
+++ b/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImpl.java
@@ -32,10 +32,9 @@ import android.os.Bundle;
 import android.os.ParcelFileDescriptor;
 import android.os.RemoteException;
 import android.os.Trace;
+import android.util.Log;
 
-import com.android.internal.annotations.VisibleForTesting;
 import com.android.ondevicepersonalization.internal.util.ByteArrayUtil;
-import com.android.ondevicepersonalization.internal.util.LoggerFactory;
 import com.android.ondevicepersonalization.services.OnDevicePersonalizationExecutors;
 import com.android.ondevicepersonalization.services.util.IoUtils;
 
@@ -44,34 +43,25 @@ import com.google.common.util.concurrent.ListeningExecutorService;
 import org.tensorflow.lite.InterpreterApi;
 import org.tensorflow.lite.Tensor;
 
-import java.io.ByteArrayInputStream;
 import java.io.IOException;
-import java.io.ObjectInputStream;
 import java.nio.ByteBuffer;
 import java.util.HashMap;
-import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.concurrent.ArrayBlockingQueue;
 import java.util.concurrent.BlockingQueue;
 
 /** The implementation of {@link IsolatedModelService}. */
-public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
-    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
     private static final String TAG = IsolatedModelServiceImpl.class.getSimpleName();
-    @NonNull private final Injector mInjector;
+    private final Injector mInjector;
 
     static {
         System.loadLibrary("fcp_cpp_dep_jni");
     }
 
-    @VisibleForTesting
-    public IsolatedModelServiceImpl(@NonNull Injector injector) {
-        this.mInjector = injector;
-    }
-
-    public IsolatedModelServiceImpl() {
-        this(new Injector());
+    IsolatedModelServiceImpl() {
+        this.mInjector = new Injector();
     }
 
     @Override
@@ -100,7 +90,7 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
                         });
     }
 
-    private void runTfliteInterpreter(
+    private static void runTfliteInterpreter(
             InferenceInputParcel inputParcel,
             InferenceOutputParcel outputParcel,
             IDataAccessService binder,
@@ -111,7 +101,7 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
             Object[] inputs =
                     (Object[]) ByteArrayUtil.deserializeObject(inputParcel.getInputData());
             if (inputs == null || inputs.length == 0) {
-                sLogger.e("Input data can not be empty for inference.");
+                Log.e(TAG, "Input data can not be empty for inference.");
                 sendError(callback, OnDevicePersonalizationException.ERROR_INFERENCE_FAILED);
             }
             Map<Integer, Object> outputs = new HashMap<>();
@@ -124,14 +114,14 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
             }
 
             if (outputs.isEmpty()) {
-                sLogger.e("Output data can not be empty for inference.");
+                Log.e(TAG, "Output data can not be empty for inference.");
                 sendError(callback, OnDevicePersonalizationException.ERROR_INFERENCE_FAILED);
             }
 
             ModelId modelId = inputParcel.getModelId();
             ParcelFileDescriptor modelFd = fetchModel(binder, modelId);
             if (modelFd == null) {
-                sLogger.e(TAG + ": Failed to fetch model %s.", modelId.getKey());
+                Log.e(TAG, "Failed to fetch model: " + modelId.getKey());
                 sendError(
                         callback, OnDevicePersonalizationException.ERROR_INFERENCE_MODEL_NOT_FOUND);
                 return;
@@ -168,37 +158,23 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
             Trace.endSection();
         } catch (Exception e) {
             // Catch all exceptions including TFLite errors.
-            sLogger.e(e, TAG + ": Failed to run inference job.");
+            Log.e(TAG, "Failed to run inference job.");
             sendError(callback, OnDevicePersonalizationException.ERROR_INFERENCE_FAILED);
         }
     }
 
-    private Object[] convertToObjArray(List<byte[]> input) {
-        Object[] output = new Object[input.size()];
-        for (int i = 0; i < input.size(); i++) {
-            ByteArrayInputStream bais = new ByteArrayInputStream(input.get(i));
-            try {
-                ObjectInputStream ois = new ObjectInputStream(bais);
-                output[i] = ois.readObject();
-            } catch (Exception e) {
-                sLogger.e(e, "Failed to parse inference input");
-                return null;
-            }
-        }
-        return output;
-    }
-
-    private void closeFd(ParcelFileDescriptor fd) {
+    private static void closeFd(ParcelFileDescriptor fd) {
         try {
             fd.close();
         } catch (IOException e) {
-            sLogger.e(e, TAG + ": Failed to close model file descriptor");
+            Log.e(TAG, "Failed to close model file descriptor.");
         }
     }
 
-    private ParcelFileDescriptor fetchModel(IDataAccessService dataAccessService, ModelId modelId) {
+    private static ParcelFileDescriptor fetchModel(
+            IDataAccessService dataAccessService, ModelId modelId) {
         try {
-            sLogger.d(TAG + ": Start fetch model %s %d", modelId.getKey(), modelId.getTableId());
+            Log.d(TAG, ": Start fetch model " + modelId.getKey() + " " + modelId.getTableId());
             BlockingQueue<Bundle> asyncResult = new ArrayBlockingQueue<>(1);
             Bundle params = new Bundle();
             params.putParcelable(Constants.EXTRA_MODEL_ID, modelId);
@@ -225,7 +201,7 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
                     result.getParcelable(Constants.EXTRA_RESULT, ParcelFileDescriptor.class);
             return modelFd;
         } catch (Exception e) {
-            sLogger.e(e, TAG + ": Failed to fetch model from DataAccessService");
+            Log.e(TAG, "Failed to fetch model from DataAccessService.", e);
             return null;
         }
     }
@@ -234,7 +210,7 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
         try {
             callback.onError(errorCode);
         } catch (RemoteException e) {
-            sLogger.e(TAG + ": Callback error", e);
+            Log.e(TAG, "Callback error.", e);
         }
     }
 
@@ -243,12 +219,11 @@ public class IsolatedModelServiceImpl extends IIsolatedModelService.Stub {
         try {
             callback.onSuccess(result);
         } catch (RemoteException e) {
-            sLogger.e(e, TAG + ": Callback error");
+            Log.e(TAG, "Callback error.", e);
         }
     }
 
-    @VisibleForTesting
-    static class Injector {
+    private static class Injector {
         ListeningExecutorService getExecutor() {
             return OnDevicePersonalizationExecutors.getBackgroundExecutor();
         }
diff --git a/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceProvider.java b/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceProvider.java
index c136c968..5737769f 100644
--- a/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceProvider.java
+++ b/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceProvider.java
@@ -28,7 +28,7 @@ import com.android.modules.utils.build.SdkLevel;
  * Provides {@link IsolatedModelService}.
  */
 public class IsolatedModelServiceProvider {
-    public static final String ISOLATED_MODEL_SERVICE_NAME =
+    private static final String ISOLATED_MODEL_SERVICE_NAME =
             "com.android.ondevicepersonalization.services.inference.IsolatedModelService";
     private AbstractServiceBinder<IIsolatedModelService> mModelService;
 
diff --git a/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJob.java b/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJob.java
index e83315c1..c2aac9aa 100644
--- a/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJob.java
+++ b/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJob.java
@@ -88,6 +88,11 @@ public final class OnDevicePersonalizationMaintenanceJob implements JobWorker {
         return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
     }
 
+    @Override
+    public String getJobPolicyString(int jobId) {
+        return FlagsFactory.getFlags().getMaintenanceJobPolicy();
+    }
+
     /** Schedules a unique instance of {@link OnDevicePersonalizationMaintenanceJob}. */
     public static void schedule(Context context) {
         // If SPE is not enabled, force to schedule the job with the old JobService.
diff --git a/src/com/android/ondevicepersonalization/services/reset/ResetDataJob.java b/src/com/android/ondevicepersonalization/services/reset/ResetDataJob.java
index 02452cf8..9a096248 100644
--- a/src/com/android/ondevicepersonalization/services/reset/ResetDataJob.java
+++ b/src/com/android/ondevicepersonalization/services/reset/ResetDataJob.java
@@ -110,6 +110,11 @@ public final class ResetDataJob implements JobWorker {
         return new BackoffPolicy.Builder().setShouldRetryOnExecutionStop(true).build();
     }
 
+    @Override
+    public String getJobPolicyString(int jobId) {
+        return FlagsFactory.getFlags().getResetDataJobPolicy();
+    }
+
     @VisibleForTesting
     void deleteMeasurementData() {
         ResetDataTask.deleteMeasurementData();
diff --git a/src/com/android/ondevicepersonalization/services/util/DebugUtils.java b/src/com/android/ondevicepersonalization/services/util/DebugUtils.java
index 1f5e0957..f431c6d5 100644
--- a/src/com/android/ondevicepersonalization/services/util/DebugUtils.java
+++ b/src/com/android/ondevicepersonalization/services/util/DebugUtils.java
@@ -41,10 +41,20 @@ public class DebugUtils {
     private static final String TAG = DebugUtils.class.getSimpleName();
     private static final int MAX_EXCEPTION_CHAIN_DEPTH = 3;
 
-    private static final String OVERRIDE_FC_SERVER_URL_PACKAGE =
-            "debug.ondevicepersonalization.override_fc_server_url_package";
-    private static final String OVERRIDE_FC_SERVER_URL =
-            "debug.ondevicepersonalization.override_fc_server_url";
+    public static final String OVERRIDE_FC_SERVER_URL_PACKAGE =
+            getSystemPropertyName(/* key= */ "override_fc_server_url_package");
+    public static final String OVERRIDE_FC_SERVER_URL =
+            getSystemPropertyName(/* key= */ "override_fc_server_url");
+
+    /**
+     * ODP SystemProperty prefix. SystemProperty is for overriding OnDevicePersonalization Configs.
+     */
+    private static final String SYSTEM_PROPERTY_PREFIX = "debug.ondevicepersonalization.";
+
+    /** Gets the ODP system property name corresponding to the given key name. */
+    public static String getSystemPropertyName(String key) {
+        return SYSTEM_PROPERTY_PREFIX + key;
+    }
 
     /** Returns true if the device is debuggable. */
     public static boolean isDeveloperModeEnabled(@NonNull Context context) {
diff --git a/src/com/android/ondevicepersonalization/services/util/NoiseUtil.java b/src/com/android/ondevicepersonalization/services/util/NoiseUtil.java
index b3cd7834..bf57d147 100644
--- a/src/com/android/ondevicepersonalization/services/util/NoiseUtil.java
+++ b/src/com/android/ondevicepersonalization/services/util/NoiseUtil.java
@@ -27,8 +27,16 @@ public class NoiseUtil {
     private static final String TAG = NoiseUtil.class.getSimpleName();
 
     /**
-     * Add noise to {@link OnDevicePersonalizationManager#executeInIsolatedService} with best value
-     * option.
+     * Add noise to provided value based on input params.
+     *
+     * <p>Used by {@link
+     * android.adservices.ondevicepersonalization.OnDevicePersonalizationManager#executeInIsolatedService}
+     * with best value option.
+     *
+     * @param actualValue the original unmodified value.
+     * @param maxValue the maximum value that can be returned.
+     * @param random instance used to generate random values.
+     * @return the noised value based on input params.
      */
     public int applyNoiseToBestValue(int actualValue, int maxValue, ThreadLocalRandom random) {
         if (actualValue < 0 || actualValue > maxValue) {
diff --git a/tests/cts/endtoend/AndroidTest.xml b/tests/cts/endtoend/AndroidTest.xml
index 06ab578d..681c3d41 100644
--- a/tests/cts/endtoend/AndroidTest.xml
+++ b/tests/cts/endtoend/AndroidTest.xml
@@ -34,6 +34,7 @@
         <option name="run-command" value="device_config put on_device_personalization enable_personalization_status_override true"/>
         <option name="run-command" value="device_config put on_device_personalization personalization_status_override_value true"/>
         <option name="run-command" value="device_config put on_device_personalization isolated_service_debugging_enabled true"/>
+        <option name="run-command" value="device_config put on_device_personalization caller_app_allow_list com.android.ondevicepersonalization.cts.e2e"/>
         <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
         <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
         <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
@@ -49,6 +50,7 @@
         <option name="teardown-command" value="device_config delete on_device_personalization enable_personalization_status_override" />
         <option name="teardown-command" value="device_config delete on_device_personalization personalization_status_override_value" />
         <option name="teardown-command" value="device_config delete on_device_personalization isolated_service_debugging_enabled" />
+        <option name="teardown-command" value="device_config delete on_device_personalization caller_app_allow_list" />
         <option name="teardown-command" value="device_config set_sync_disabled_for_tests none" />
     </target_preparer>
 
diff --git a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
index ca97f215..63317e1f 100644
--- a/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
+++ b/tests/cts/endtoend/src/com/android/ondevicepersonalization/cts/e2e/CtsOdpManagerTests.java
@@ -539,30 +539,6 @@ public class CtsOdpManagerTests {
         checkExpectedMissingLocalData(manager, tableKey);
     }
 
-    @Test
-    public void testExecuteSendLargeBlob() throws InterruptedException {
-        final String tableKey = "testKey_" + System.currentTimeMillis();
-        OnDevicePersonalizationManager manager =
-                mContext.getSystemService(OnDevicePersonalizationManager.class);
-        assertNotNull(manager);
-        var receiver = new ResultReceiver<ExecuteResult>();
-        PersistableBundle appParams = new PersistableBundle();
-        appParams.putString(
-                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_CHECK_VALUE_LENGTH);
-        byte[] buffer = new byte[LARGE_BLOB_SIZE];
-        for (int i = 0; i < LARGE_BLOB_SIZE; ++i) {
-            buffer[i] = 'A';
-        }
-        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(buffer, 0));
-        appParams.putInt(SampleServiceApi.KEY_VALUE_LENGTH, LARGE_BLOB_SIZE);
-        manager.execute(
-                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
-                appParams,
-                Executors.newSingleThreadExecutor(),
-                receiver);
-        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-    }
-
     @Test
     public void testRunModelInference() throws Exception {
         final String tableKey = "model_" + System.currentTimeMillis();
@@ -1111,32 +1087,6 @@ public class CtsOdpManagerTests {
         checkExpectedMissingLocalDataNewExecuteApi(manager, tableKey);
     }
 
-    @Test
-    @RequiresFlagsEnabled(Flags.FLAG_EXECUTE_IN_ISOLATED_SERVICE_API_ENABLED)
-    public void testExecuteInIsolatedServiceSendLargeBlob() throws InterruptedException {
-        OnDevicePersonalizationManager manager =
-                mContext.getSystemService(OnDevicePersonalizationManager.class);
-        assertNotNull(manager);
-        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
-        PersistableBundle appParams = new PersistableBundle();
-        appParams.putString(
-                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_CHECK_VALUE_LENGTH);
-        byte[] buffer = new byte[LARGE_BLOB_SIZE];
-        for (int i = 0; i < LARGE_BLOB_SIZE; ++i) {
-            buffer[i] = 'A';
-        }
-        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(buffer, 0));
-        appParams.putInt(SampleServiceApi.KEY_VALUE_LENGTH, LARGE_BLOB_SIZE);
-        ExecuteInIsolatedServiceRequest request =
-                new ExecuteInIsolatedServiceRequest.Builder(
-                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
-                        .setAppParams(appParams)
-                        .build();
-
-        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
-        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
-    }
-
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_EXECUTE_IN_ISOLATED_SERVICE_API_ENABLED)
     public void testExecuteInIsolatedServiceWithModelInference() throws Exception {
diff --git a/tests/endtoendtests/Android.bp b/tests/endtoendtests/Android.bp
new file mode 100644
index 00000000..60006261
--- /dev/null
+++ b/tests/endtoendtests/Android.bp
@@ -0,0 +1,60 @@
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+// Make test APK
+// ============================================================
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_rubidium",
+}
+
+android_test {
+    name: "OnDevicePersonalizationEndToEndTests",
+    srcs: ["src/**/*.java"],
+    defaults: ["framework-ondevicepersonalization-test-defaults"],
+    min_sdk_version: "Tiramisu",
+    target_sdk_version: "Tiramisu",
+    static_libs: [
+        "androidx.test.core",
+        "androidx.test.ext.junit",
+        "androidx.test.ext.truth",
+        "androidx.test.rules",
+        "compatibility-device-util-axt",
+        "flag-junit",
+        "hamcrest-library",
+        "ondevicepersonalization_flags_lib",
+        "ondevicepersonalization-testing-sample-service-api",
+        "ondevicepersonalization-testing-utils",
+        "platform-test-rules",
+        "platform-compat-test-rules",
+    ],
+    libs: [
+        "sdk_public_33_android.test.base",
+        "sdk_public_33_android.test.runner",
+        "truth",
+    ],
+    data: [
+        ":OdpTestingSampleService",
+    ],
+    resource_dirs: [
+        "res",
+    ],
+    test_mainline_modules: ["com.google.android.ondevicepersonalization.apex"],
+    test_suites: [
+        "general-tests",
+        "mts-ondevicepersonalization",
+    ],
+    test_config: "AndroidTest.xml",
+}
diff --git a/tests/endtoendtests/AndroidManifest.xml b/tests/endtoendtests/AndroidManifest.xml
new file mode 100644
index 00000000..6464b3e8
--- /dev/null
+++ b/tests/endtoendtests/AndroidManifest.xml
@@ -0,0 +1,39 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+    package="com.android.ondevicepersonalization.e2etests">
+    <uses-sdk android:minSdkVersion="33"
+              android:targetSdkVersion="33" />
+    <application android:debuggable="true"
+                 android:largeHeap="true">
+        android:label="OnDevicePersonalizationEndToEndTests">
+        <uses-library android:name="android.test.runner" />
+        <activity
+            android:name=".TestActivity"
+            android:exported="true">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN" />
+                <category android:name="android.intent.category.LAUNCHER" />
+            </intent-filter>
+        </activity>
+    </application>
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+                     android:targetPackage="com.android.ondevicepersonalization.e2etests"
+                     android:label="OnDevicePersonalizationManager Tests">
+    </instrumentation>
+
+</manifest>
diff --git a/tests/endtoendtests/AndroidTest.xml b/tests/endtoendtests/AndroidTest.xml
new file mode 100644
index 00000000..91b2f022
--- /dev/null
+++ b/tests/endtoendtests/AndroidTest.xml
@@ -0,0 +1,71 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Config for OnDevicePersonalizationEndToEndTests">
+    <option name="config-descriptor:metadata" key="component" value="framework" />
+    <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
+    <option name="config-descriptor:metadata" key="parameter" value="not_multi_abi" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
+    <option name="config-descriptor:metadata" key="parameter" value="secondary_user_on_secondary_display" />
+
+    <target_preparer class="com.android.tradefed.targetprep.suite.SuiteApkInstaller">
+        <option name="cleanup-apks" value="true"/>
+        <option name="test-file-name" value="OnDevicePersonalizationEndToEndTests.apk"/>
+        <option name="test-file-name" value="OdpTestingSampleService.apk"/>
+    </target_preparer>
+
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="device_config set_sync_disabled_for_tests persistent" />
+        <option name="run-command" value="device_config put on_device_personalization global_kill_switch false" />
+        <option name="run-command" value="device_config put on_device_personalization federated_compute_kill_switch false" />
+        <option name="run-command" value="device_config put on_device_personalization enable_personalization_status_override true"/>
+        <option name="run-command" value="device_config put on_device_personalization personalization_status_override_value true"/>
+        <option name="run-command" value="device_config put on_device_personalization isolated_service_debugging_enabled true"/>
+        <option name="run-command" value="device_config put on_device_personalization caller_app_allow_list com.android.ondevicepersonalization.e2etests" />
+        <option name="run-command" value="setprop log.tag.federatedcompute VERBOSE" />
+        <option name="run-command" value="setprop log.tag.ondevicepersonalization VERBOSE" />
+        <option name="run-command" value="setprop log.tag.OdpParceledListSlice VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginControllerImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginLoaderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorService VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutor VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginArchiveManager VERBOSE" />
+        <option name="run-command" value="setprop log.tag.PluginExecutorServiceProviderImpl VERBOSE" />
+        <option name="run-command" value="setprop log.tag.TestPersonalizationHandler VERBOSE" />
+        <option name="teardown-command" value="device_config delete on_device_personalization global_kill_switch" />
+        <option name="teardown-command" value="device_config delete on_device_personalization federated_compute_kill_switch" />
+        <option name="teardown-command" value="device_config delete on_device_personalization enable_personalization_status_override" />
+        <option name="teardown-command" value="device_config delete on_device_personalization personalization_status_override_value" />
+        <option name="teardown-command" value="device_config delete on_device_personalization isolated_service_debugging_enabled" />
+        <option name="teardown-command" value="device_config delete on_device_personalization caller_app_allow_list" />
+        <option name="teardown-command" value="device_config set_sync_disabled_for_tests none" />
+    </target_preparer>
+
+    <metrics_collector class="com.android.tradefed.device.metric.FilePullerLogCollector">
+        <option name="directory-keys" value="/data/system/files" />
+        <option name="clean-up" value="false" />
+        <option name="collect-on-run-ended-only" value="true" />
+    </metrics_collector>
+
+    <test class="com.android.tradefed.testtype.AndroidJUnitTest">
+        <option name="hidden-api-checks" value="false" /> <!-- Allow hidden API uses -->
+        <option name="package" value="com.android.ondevicepersonalization.e2etests"/>
+    </test>
+
+    <object type="module_controller" class="com.android.tradefed.testtype.suite.module.MainlineTestModuleController">
+        <option name="mainline-module-package-name" value="com.google.android.ondevicepersonalization" />
+    </object>
+    <option name="config-descriptor:metadata" key="mainline-param" value="com.google.android.ondevicepersonalization.apex" />
+</configuration>
diff --git a/tests/endtoendtests/res/layout/activity_main.xml b/tests/endtoendtests/res/layout/activity_main.xml
new file mode 100644
index 00000000..866d0606
--- /dev/null
+++ b/tests/endtoendtests/res/layout/activity_main.xml
@@ -0,0 +1,26 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+  ~ Copyright (C) 2025 The Android Open Source Project
+  ~
+  ~ Licensed under the Apache License, Version 2.0 (the "License");
+  ~ you may not use this file except in compliance with the License.
+  ~ You may obtain a copy of the License at
+  ~
+  ~      http://www.apache.org/licenses/LICENSE-2.0
+  ~
+  ~ Unless required by applicable law or agreed to in writing, software
+  ~ distributed under the License is distributed on an "AS IS" BASIS,
+  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  ~ See the License for the specific language governing permissions and
+  ~ limitations under the License.
+  -->
+
+<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+              android:orientation="vertical"
+              android:layout_width="match_parent"
+              android:layout_height="match_parent">
+    <SurfaceView
+        android:id="@+id/test_surface_view"
+        android:layout_width="200dp"
+        android:layout_height="200dp" />
+</LinearLayout>
diff --git a/tests/endtoendtests/res/raw/model.tflite b/tests/endtoendtests/res/raw/model.tflite
new file mode 100644
index 00000000..3a7595ee
Binary files /dev/null and b/tests/endtoendtests/res/raw/model.tflite differ
diff --git a/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/OdpManagerTests.java b/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/OdpManagerTests.java
new file mode 100644
index 00000000..8d5cbf8a
--- /dev/null
+++ b/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/OdpManagerTests.java
@@ -0,0 +1,1506 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.ondevicepersonalization.e2etests;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
+
+import android.adservices.ondevicepersonalization.ExecuteInIsolatedServiceRequest;
+import android.adservices.ondevicepersonalization.ExecuteInIsolatedServiceResponse;
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationException;
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager.ExecuteResult;
+import android.adservices.ondevicepersonalization.SurfacePackageToken;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.pm.PackageManager.NameNotFoundException;
+import android.net.Uri;
+import android.os.PersistableBundle;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.util.Base64;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.compatibility.common.util.ShellUtils;
+import com.android.modules.utils.build.SdkLevel;
+import com.android.ondevicepersonalization.testing.sampleserviceapi.SampleServiceApi;
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
+import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
+
+import org.junit.After;
+import org.junit.Assume;
+import org.junit.Before;
+import org.junit.Ignore;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.io.ByteArrayOutputStream;
+import java.io.InputStream;
+import java.util.concurrent.Executors;
+
+/** Test cases for OnDevicePersonalizationManager APIs. */
+@RunWith(JUnit4.class)
+public class OdpManagerTests {
+
+    private static final String SERVICE_PACKAGE =
+            "com.android.ondevicepersonalization.testing.sampleservice";
+    private static final String SERVICE_CLASS =
+            "com.android.ondevicepersonalization.testing.sampleservice.SampleService";
+    private static final int LARGE_BLOB_SIZE = 10000000;
+    private static final int DELAY_MILLIS = 2000;
+
+    private static final String TEST_POPULATION_NAME = "criteo_app_test_task";
+    private static final String TEST_WRITE_DATA = Base64.encodeToString(new byte[] {'A'}, 0);
+
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    @Before
+    public void setUp() {
+        // Skip the test if it runs on unsupported platforms.
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
+
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "shared_isolated_process_feature_enabled "
+                        + SdkLevel.isAtLeastU());
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "debug.validate_rendering_config_keys "
+                        + false);
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "isolated_service_allow_list "
+                        + "com.android.ondevicepersonalization.testing.sampleservice,"
+                        + "com.example.odptargetingapp2");
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "isolated_service_debugging_enabled "
+                        + true);
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "output_data_allow_list "
+                        + mContext.getPackageName()
+                        + ";com.android.ondevicepersonalization.testing.sampleservice");
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "Odp__enable_is_feature_enabled "
+                        + true);
+    }
+
+    @After
+    public void reset() {
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "isolated_service_allow_list "
+                        + "null");
+        ShellUtils.runShellCommand("device_config delete output_data_allow_list");
+
+        ShellUtils.runShellCommand(
+                "am force-stop com.google.android.ondevicepersonalization.services");
+        ShellUtils.runShellCommand("am force-stop com.android.ondevicepersonalization.services");
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "Odp__enable_is_feature_enabled "
+                        + "null");
+    }
+
+    @Test
+    public void testExecuteThrowsIfComponentNameMissing() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.execute(
+                                null,
+                                PersistableBundle.EMPTY,
+                                Executors.newSingleThreadExecutor(),
+                                new ResultReceiver<ExecuteResult>()));
+    }
+
+    @Test
+    public void testExecuteThrowsIfParamsMissing() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.execute(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                                null,
+                                Executors.newSingleThreadExecutor(),
+                                new ResultReceiver<ExecuteResult>()));
+    }
+
+    @Test
+    public void testExecuteThrowsIfExecutorMissing() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.execute(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                                PersistableBundle.EMPTY,
+                                null,
+                                new ResultReceiver<ExecuteResult>()));
+    }
+
+    @Test
+    public void testExecuteThrowsIfReceiverMissing() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.execute(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                                PersistableBundle.EMPTY,
+                                Executors.newSingleThreadExecutor(),
+                                null));
+    }
+
+    @Test
+    public void testExecuteThrowsIfPackageNameMissing() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        assertThrows(
+                IllegalArgumentException.class,
+                () ->
+                        manager.execute(
+                                new ComponentName("", SERVICE_CLASS),
+                                PersistableBundle.EMPTY,
+                                Executors.newSingleThreadExecutor(),
+                                new ResultReceiver<ExecuteResult>()));
+    }
+
+    @Test
+    public void testExecuteThrowsIfClassNameMissing() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        assertThrows(
+                IllegalArgumentException.class,
+                () ->
+                        manager.execute(
+                                new ComponentName(SERVICE_PACKAGE, ""),
+                                PersistableBundle.EMPTY,
+                                Executors.newSingleThreadExecutor(),
+                                new ResultReceiver<ExecuteResult>()));
+    }
+
+    @Test
+    public void testExecuteReturnsIllegalStateIfServiceNotEnrolled() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        manager.execute(
+                new ComponentName("somepackage", "someclass"),
+                PersistableBundle.EMPTY,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertNull(receiver.getResult());
+        assertThat(receiver.getException()).isInstanceOf(IllegalStateException.class);
+    }
+
+    @Test
+    public void testExecuteReturnsNameNotFoundIfServiceNotInstalled() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+
+        manager.execute(
+                new ComponentName("com.example.odptargetingapp2", "someclass"),
+                PersistableBundle.EMPTY,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertNull(receiver.getResult());
+        assertThat(receiver.getException()).isInstanceOf(NameNotFoundException.class);
+    }
+
+    @Test
+    public void testExecuteReturnsClassNotFoundIfServiceClassNotFound()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, "someclass"),
+                PersistableBundle.EMPTY,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertNull(receiver.getResult());
+        assertThat(receiver.getException()).isInstanceOf(ClassNotFoundException.class);
+    }
+
+    @Test
+    public void testExecuteNoOp() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                PersistableBundle.EMPTY,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        SurfacePackageToken token = receiver.getResult().getSurfacePackageToken();
+        assertNull(token);
+    }
+
+    @Test
+    public void testExecuteWithRenderAndLogging() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+        appParams.putString(SampleServiceApi.KEY_RENDERING_CONFIG_IDS, "id1");
+        PersistableBundle logData = new PersistableBundle();
+        logData.putString("id", "a1");
+        logData.putDouble("val", 5.0);
+        appParams.putPersistableBundle(SampleServiceApi.KEY_LOG_DATA, logData);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        SurfacePackageToken token = receiver.getResult().getSurfacePackageToken();
+        assertNotNull(token);
+    }
+
+    @Test
+    public void testExecuteWithRender() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+        appParams.putString(SampleServiceApi.KEY_RENDERING_CONFIG_IDS, "id1");
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        SurfacePackageToken token = receiver.getResult().getSurfacePackageToken();
+        assertNotNull(token);
+    }
+
+    @Test
+    @Ignore("b/377212275")
+    public void testExecuteWithOutputDataDisabled() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RETURN_OUTPUT_DATA);
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, TEST_WRITE_DATA);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        assertThat(receiver.getResult().getOutputData()).isNull();
+    }
+
+    @Test
+    public void testExecuteReadRemoteData() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_REMOTE_DATA);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteReadUserData() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_USER_DATA);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteWithLogging() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+        PersistableBundle logData = new PersistableBundle();
+        logData.putString("id", "a1");
+        logData.putDouble("val", 5.0);
+        appParams.putPersistableBundle(SampleServiceApi.KEY_LOG_DATA, logData);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        SurfacePackageToken token = receiver.getResult().getSurfacePackageToken();
+        assertNull(token);
+    }
+
+    @Test
+    public void testExecuteReadLog() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        final long now = System.currentTimeMillis();
+
+        {
+            var receiver = new ResultReceiver<ExecuteResult>();
+            PersistableBundle appParams = new PersistableBundle();
+            appParams.putString(
+                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+            PersistableBundle logData = new PersistableBundle();
+            logData.putLong(SampleServiceApi.KEY_EXPECTED_LOG_DATA_KEY, now);
+            appParams.putPersistableBundle(SampleServiceApi.KEY_LOG_DATA, logData);
+            manager.execute(
+                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                    appParams,
+                    Executors.newSingleThreadExecutor(),
+                    receiver);
+            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        }
+
+        Thread.sleep(DELAY_MILLIS);
+
+        {
+            var receiver = new ResultReceiver<ExecuteResult>();
+            PersistableBundle appParams = new PersistableBundle();
+            appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOG);
+            appParams.putLong(SampleServiceApi.KEY_EXPECTED_LOG_DATA_VALUE, now);
+            manager.execute(
+                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                    appParams,
+                    Executors.newSingleThreadExecutor(),
+                    receiver);
+            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        }
+    }
+
+    @Test
+    public void testExecuteReturnsErrorIfServiceThrows() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_THROW_EXCEPTION);
+        appParams.putString(SampleServiceApi.KEY_EXCEPTION_CLASS, "java.lang.NullPointerException");
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.isError());
+        assertNull(receiver.getResult());
+        assertThat(receiver.getException()).isInstanceOf(OnDevicePersonalizationException.class);
+        assertEquals(
+                ((OnDevicePersonalizationException) receiver.getException()).getErrorCode(),
+                OnDevicePersonalizationException.ERROR_ISOLATED_SERVICE_FAILED);
+    }
+
+    @Test
+    public void testExecuteReturnsErrorIfServiceReturnsError() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_FAIL_WITH_ERROR_CODE);
+        appParams.putInt(SampleServiceApi.KEY_ERROR_CODE, 10);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.isError());
+        assertNull(receiver.getResult());
+        assertThat(receiver.getException()).isInstanceOf(OnDevicePersonalizationException.class);
+        assertEquals(
+                ((OnDevicePersonalizationException) receiver.getException()).getErrorCode(),
+                OnDevicePersonalizationException.ERROR_ISOLATED_SERVICE_FAILED);
+    }
+
+    @Test
+    public void testExecuteWriteAndReadLocalData() throws InterruptedException {
+        final String tableKey = "testKey_" + System.currentTimeMillis();
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        // Write 1 byte.
+        writeLocalData(manager, tableKey, /* writeLargeData= */ false);
+        Thread.sleep(DELAY_MILLIS);
+
+        // Read and check whether value matches written value.
+        readExpectedLocalData(manager, tableKey, TEST_WRITE_DATA, /* expectLargeData= */ false);
+        Thread.sleep(DELAY_MILLIS);
+
+        // Remove.
+        removeLocalData(manager, tableKey);
+        Thread.sleep(DELAY_MILLIS);
+
+        // Read and check whether value was removed.
+        checkExpectedMissingLocalData(manager, tableKey);
+    }
+
+    @Test
+    public void testExecuteWriteAndReadLargeLocalData() throws InterruptedException {
+        final String tableKey = "testKey_" + System.currentTimeMillis();
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        // Write 10MB.
+        writeLocalData(manager, tableKey, /* writeLargeData= */ true);
+        Thread.sleep(DELAY_MILLIS);
+
+        // Read and check whether value matches written value.
+        readExpectedLocalData(manager, tableKey, TEST_WRITE_DATA, /* expectLargeData= */ true);
+        Thread.sleep(DELAY_MILLIS);
+
+        // Remove.
+        removeLocalData(manager, tableKey);
+        Thread.sleep(DELAY_MILLIS);
+
+        // Read and check whether value was removed.
+        checkExpectedMissingLocalData(manager, tableKey);
+    }
+
+    @Test
+    public void testExecuteSendLargeBlob() throws InterruptedException {
+        final String tableKey = "testKey_" + System.currentTimeMillis();
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_CHECK_VALUE_LENGTH);
+        byte[] buffer = new byte[LARGE_BLOB_SIZE];
+        for (int i = 0; i < LARGE_BLOB_SIZE; ++i) {
+            buffer[i] = 'A';
+        }
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(buffer, 0));
+        appParams.putInt(SampleServiceApi.KEY_VALUE_LENGTH, LARGE_BLOB_SIZE);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testRunModelInference() throws Exception {
+        final String tableKey = "model_" + System.currentTimeMillis();
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        Uri modelUri =
+                Uri.parse(
+                        "android.resource://"
+                                + ApplicationProvider.getApplicationContext().getPackageName()
+                                + "/raw/model");
+        Context context = ApplicationProvider.getApplicationContext();
+        InputStream in = context.getContentResolver().openInputStream(modelUri);
+        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
+        byte[] buf = new byte[4096];
+        int bytesRead;
+        while ((bytesRead = in.read(buf)) != -1) {
+            outputStream.write(buf, 0, bytesRead);
+        }
+        byte[] buffer = outputStream.toByteArray();
+        outputStream.close();
+        // Write model to local data.
+        {
+            var receiver = new ResultReceiver<ExecuteResult>();
+            PersistableBundle appParams = new PersistableBundle();
+            appParams.putString(
+                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+            appParams.putString(
+                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(buffer, 0));
+            manager.execute(
+                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                    appParams,
+                    Executors.newSingleThreadExecutor(),
+                    receiver);
+            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        }
+
+        Thread.sleep(DELAY_MILLIS);
+
+        // Run model inference
+        {
+            var receiver = new ResultReceiver<ExecuteResult>();
+            PersistableBundle appParams = new PersistableBundle();
+            appParams.putString(
+                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RUN_MODEL_INFERENCE);
+            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+            appParams.putDouble(SampleServiceApi.KEY_INFERENCE_RESULT, 0.5922908);
+            manager.execute(
+                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                    appParams,
+                    Executors.newSingleThreadExecutor(),
+                    receiver);
+            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        }
+    }
+
+    @Test
+    public void testExecuteWithScheduleFederatedJob() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = getScheduleFCJobParams(/* useLegacyApi= */ true);
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteWithScheduleFederatedJobWithOutcomeReceiver() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = getScheduleFCJobParams(/* useLegacyApi= */ false);
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteWithCancelFederatedJob() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_CANCEL_FEDERATED_JOB);
+        appParams.putString(SampleServiceApi.KEY_POPULATION_NAME, TEST_POPULATION_NAME);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceThrowsNPEIfExecutorMissing() {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(PersistableBundle.EMPTY)
+                        .build();
+
+        assertThrows(
+                NullPointerException.class,
+                () -> manager.executeInIsolatedService(request, null, new ResultReceiver<>()));
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceThrowsNPEIfReceiverMissing() {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(PersistableBundle.EMPTY)
+                        .build();
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.executeInIsolatedService(
+                                request, Executors.newSingleThreadExecutor(), null));
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceThrowsIAEIfPackageNameMissing() {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(new ComponentName("", SERVICE_CLASS))
+                        .setAppParams(PersistableBundle.EMPTY)
+                        .build();
+        assertThrows(
+                IllegalArgumentException.class,
+                () ->
+                        manager.executeInIsolatedService(
+                                request,
+                                Executors.newSingleThreadExecutor(),
+                                new ResultReceiver<>()));
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceThrowsIAEIfClassNameMissing()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(new ComponentName(SERVICE_PACKAGE, ""))
+                        .setAppParams(PersistableBundle.EMPTY)
+                        .build();
+        assertThrows(
+                IllegalArgumentException.class,
+                () ->
+                        manager.executeInIsolatedService(
+                                request,
+                                Executors.newSingleThreadExecutor(),
+                                new ResultReceiver<>()));
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceReturnsIllegalStateIfServiceNotEnrolled()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName("somepackage", "someclass"))
+                        .setAppParams(PersistableBundle.EMPTY)
+                        .build();
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertNull(receiver.getResult());
+        assertTrue(receiver.getException() instanceof IllegalStateException);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceReturnsNameNotFoundIfServiceNotInstalled()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName("com.example.odptargetingapp2", "someclass"))
+                        .setAppParams(PersistableBundle.EMPTY)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertNull(receiver.getResult());
+        assertThat(receiver.getException()).isInstanceOf(OnDevicePersonalizationException.class);
+        OnDevicePersonalizationException exception =
+                (OnDevicePersonalizationException) receiver.getException();
+        assertThat(exception.getErrorCode())
+                .isEqualTo(
+                        OnDevicePersonalizationException
+                                .ERROR_ISOLATED_SERVICE_MANIFEST_PARSING_FAILED);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceReturnsManifestParsingErrorIfServiceClassNotFound()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, "someclass"))
+                        .setAppParams(PersistableBundle.EMPTY)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertNull(receiver.getResult());
+        assertThat(receiver.getException()).isInstanceOf(OnDevicePersonalizationException.class);
+        OnDevicePersonalizationException exception =
+                (OnDevicePersonalizationException) receiver.getException();
+        assertThat(exception.getErrorCode())
+                .isEqualTo(
+                        OnDevicePersonalizationException
+                                .ERROR_ISOLATED_SERVICE_MANIFEST_PARSING_FAILED);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceNoOp() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(PersistableBundle.EMPTY)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        SurfacePackageToken token = receiver.getResult().getSurfacePackageToken();
+        assertNull(token);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceWithRenderAndLogging() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+        appParams.putString(SampleServiceApi.KEY_RENDERING_CONFIG_IDS, "id1");
+        PersistableBundle logData = new PersistableBundle();
+        logData.putString("id", "a1");
+        logData.putDouble("val", 5.0);
+        appParams.putPersistableBundle(SampleServiceApi.KEY_LOG_DATA, logData);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        SurfacePackageToken token = receiver.getResult().getSurfacePackageToken();
+        assertNotNull(token);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceWithRender() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+        appParams.putString(SampleServiceApi.KEY_RENDERING_CONFIG_IDS, "id1");
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        SurfacePackageToken token = receiver.getResult().getSurfacePackageToken();
+        assertNotNull(token);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceReadRemoteData() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_REMOTE_DATA);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceReadUserData() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_USER_DATA);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceWithLogging() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+        PersistableBundle logData = new PersistableBundle();
+        logData.putString("id", "a1");
+        logData.putDouble("val", 5.0);
+        appParams.putPersistableBundle(SampleServiceApi.KEY_LOG_DATA, logData);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        SurfacePackageToken token = receiver.getResult().getSurfacePackageToken();
+        assertNull(token);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceReadLog() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        final long now = System.currentTimeMillis();
+
+        {
+            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+            PersistableBundle appParams = new PersistableBundle();
+            appParams.putString(
+                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+            PersistableBundle logData = new PersistableBundle();
+            logData.putLong(SampleServiceApi.KEY_EXPECTED_LOG_DATA_KEY, now);
+            appParams.putPersistableBundle(SampleServiceApi.KEY_LOG_DATA, logData);
+            ExecuteInIsolatedServiceRequest request =
+                    new ExecuteInIsolatedServiceRequest.Builder(
+                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                            .setAppParams(appParams)
+                            .build();
+
+            manager.executeInIsolatedService(
+                    request, Executors.newSingleThreadExecutor(), receiver);
+            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        }
+
+        // Add delay between writing and read from db to reduce flakiness.
+        Thread.sleep(DELAY_MILLIS);
+
+        {
+            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+            PersistableBundle appParams = new PersistableBundle();
+            appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOG);
+            appParams.putLong(SampleServiceApi.KEY_EXPECTED_LOG_DATA_VALUE, now);
+            ExecuteInIsolatedServiceRequest request =
+                    new ExecuteInIsolatedServiceRequest.Builder(
+                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                            .setAppParams(appParams)
+                            .build();
+
+            manager.executeInIsolatedService(
+                    request, Executors.newSingleThreadExecutor(), receiver);
+            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        }
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceReturnsErrorIfServiceThrows()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_THROW_EXCEPTION);
+        appParams.putString(SampleServiceApi.KEY_EXCEPTION_CLASS, "java.lang.NullPointerException");
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.isError());
+        assertNull(receiver.getResult());
+        assertTrue(receiver.getException() instanceof OnDevicePersonalizationException);
+        assertEquals(
+                ((OnDevicePersonalizationException) receiver.getException()).getErrorCode(),
+                OnDevicePersonalizationException.ERROR_ISOLATED_SERVICE_FAILED);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceReturnsErrorIfServiceReturnsError()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_FAIL_WITH_ERROR_CODE);
+        appParams.putInt(SampleServiceApi.KEY_ERROR_CODE, 10);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.isError());
+        assertNull(receiver.getResult());
+        assertTrue(receiver.getException() instanceof OnDevicePersonalizationException);
+        assertEquals(
+                ((OnDevicePersonalizationException) receiver.getException()).getErrorCode(),
+                OnDevicePersonalizationException.ERROR_ISOLATED_SERVICE_FAILED);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceWriteAndReadLocalData() throws InterruptedException {
+        final String tableKey = "testKey_" + System.currentTimeMillis();
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        // Write 1 byte.
+        writeLocalDataNewExecuteApi(manager, tableKey, /* writeLargeData= */ false);
+        // Add delay between writing and read from db to reduce flakiness.
+        Thread.sleep(DELAY_MILLIS);
+
+        // Read and check whether value matches written value.
+        readExpectedLocalDataNewExecuteApi(
+                manager, tableKey, TEST_WRITE_DATA, /* expectLargeData= */ false);
+        // Add delay between writing and read from db to reduce flakiness.
+        Thread.sleep(DELAY_MILLIS);
+
+        // Remove.
+        removeLocalDataNewExecuteApi(manager, tableKey);
+        // Add delay between writing and read from db to reduce flakiness.
+        Thread.sleep(DELAY_MILLIS);
+
+        // Read and check whether value was removed.
+        checkExpectedMissingLocalDataNewExecuteApi(manager, tableKey);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceWriteAndReadLargeLocalData()
+            throws InterruptedException {
+        final String tableKey = "testKey_" + System.currentTimeMillis();
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+
+        // Write 10MB.
+        writeLocalDataNewExecuteApi(manager, tableKey, /* writeLargeData= */ true);
+        // Add delay between writing and read from db to reduce flakiness.
+        Thread.sleep(DELAY_MILLIS);
+
+        // Read and check whether value matches written value.
+        readExpectedLocalDataNewExecuteApi(
+                manager, tableKey, TEST_WRITE_DATA, /* expectLargeData= */ true);
+        // Add delay between writing and read from db to reduce flakiness.
+        Thread.sleep(DELAY_MILLIS);
+
+        // Remove.
+        removeLocalDataNewExecuteApi(manager, tableKey);
+        // Add delay between writing and read from db to reduce flakiness.
+        Thread.sleep(DELAY_MILLIS);
+
+        checkExpectedMissingLocalDataNewExecuteApi(manager, tableKey);
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceSendLargeBlob() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_CHECK_VALUE_LENGTH);
+        byte[] buffer = new byte[LARGE_BLOB_SIZE];
+        for (int i = 0; i < LARGE_BLOB_SIZE; ++i) {
+            buffer[i] = 'A';
+        }
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(buffer, 0));
+        appParams.putInt(SampleServiceApi.KEY_VALUE_LENGTH, LARGE_BLOB_SIZE);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceWithModelInference() throws Exception {
+        final String tableKey = "model_" + System.currentTimeMillis();
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        Uri modelUri =
+                Uri.parse(
+                        "android.resource://"
+                                + ApplicationProvider.getApplicationContext().getPackageName()
+                                + "/raw/model");
+        Context context = ApplicationProvider.getApplicationContext();
+        InputStream in = context.getContentResolver().openInputStream(modelUri);
+        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
+        byte[] buf = new byte[4096];
+        int bytesRead;
+        while ((bytesRead = in.read(buf)) != -1) {
+            outputStream.write(buf, 0, bytesRead);
+        }
+        byte[] buffer = outputStream.toByteArray();
+        outputStream.close();
+        // Write model to local data.
+        {
+            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+            PersistableBundle appParams = new PersistableBundle();
+            appParams.putString(
+                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+            appParams.putString(
+                    SampleServiceApi.KEY_BASE64_VALUE, Base64.encodeToString(buffer, 0));
+            ExecuteInIsolatedServiceRequest request =
+                    new ExecuteInIsolatedServiceRequest.Builder(
+                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                            .setAppParams(appParams)
+                            .build();
+
+            manager.executeInIsolatedService(
+                    request, Executors.newSingleThreadExecutor(), receiver);
+
+            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        }
+
+        // Add delay between writing and read from db to reduce flakiness.
+        Thread.sleep(DELAY_MILLIS);
+
+        // Run model inference
+        {
+            var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+            PersistableBundle appParams = new PersistableBundle();
+            appParams.putString(
+                    SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RUN_MODEL_INFERENCE);
+            appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+            appParams.putDouble(SampleServiceApi.KEY_INFERENCE_RESULT, 0.5922908);
+            ExecuteInIsolatedServiceRequest request =
+                    new ExecuteInIsolatedServiceRequest.Builder(
+                                    new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                            .setAppParams(appParams)
+                            .build();
+
+            manager.executeInIsolatedService(
+                    request, Executors.newSingleThreadExecutor(), receiver);
+
+            assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        }
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceWithScheduleFederatedJob() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(getScheduleFCJobParams(/* useLegacyApi= */ true))
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testExecuteInIsolatedServiceWithCancelFederatedJob() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_CANCEL_FEDERATED_JOB);
+        appParams.putString(SampleServiceApi.KEY_POPULATION_NAME, TEST_POPULATION_NAME);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testQueryFeatureAvailableApi() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<Integer>();
+
+        manager.queryFeatureAvailability("featureName",
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    @Test
+    public void testQueryFeatureAvailableApiThrowsIfFeatureNameMissing() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<Integer>();
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.queryFeatureAvailability(null,
+                                Executors.newSingleThreadExecutor(),
+                                receiver));
+    }
+
+    @Test
+    public void testQueryFeatureAvailableApiThrowsIfExecutorMissing() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<Integer>();
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.queryFeatureAvailability("featureName",
+                                null,
+                                receiver));
+    }
+
+    @Test
+    public void testExecuteNoOutputData() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RETURN_OUTPUT_DATA);
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, TEST_WRITE_DATA);
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+        assertThat(receiver.getResult().getOutputData()).isNull();
+    }
+
+    @Test
+    public void testQueryFeatureAvailableApiThrowsIfReceiverMissing() throws Exception {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        assertNotNull(manager);
+        var receiver = new ResultReceiver<Integer>();
+
+        assertThrows(
+                NullPointerException.class,
+                () ->
+                        manager.queryFeatureAvailability("featureName",
+                                Executors.newSingleThreadExecutor(),
+                                null));
+    }
+
+    private static PersistableBundle getScheduleFCJobParams(boolean useLegacyApi) {
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(
+                SampleServiceApi.KEY_OPCODE,
+                useLegacyApi
+                        ? SampleServiceApi.OPCODE_SCHEDULE_FEDERATED_JOB
+                        : SampleServiceApi.OPCODE_SCHEDULE_FEDERATED_JOB_V2);
+        appParams.putString(SampleServiceApi.KEY_POPULATION_NAME, TEST_POPULATION_NAME);
+        return appParams;
+    }
+
+    /**
+     * Sends a request to the sample service to write to local data using {@code TEST_WRITE_DATA}. *
+     *
+     * <p>Uses the legacy {@code execute} API.
+     */
+    private static void writeLocalData(
+            OnDevicePersonalizationManager manager, String tableKey, boolean writeLargeData)
+            throws InterruptedException {
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, TEST_WRITE_DATA);
+
+        if (writeLargeData) {
+            // Set repeat count to inform sample service to write a large blob of data.
+            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
+        }
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to write to local data using {@code TEST_WRITE_DATA}
+     *
+     * <p>Uses the new {@code executeInIsolatedService} API.
+     */
+    private static void writeLocalDataNewExecuteApi(
+            OnDevicePersonalizationManager manager, String tableKey, boolean writeLargeData)
+            throws InterruptedException {
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, TEST_WRITE_DATA);
+
+        if (writeLargeData) {
+            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
+        }
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to confirm that the given key does not exist in local
+     * data.
+     *
+     * <p>Uses the legacy {@code execute} API.
+     */
+    private static void checkExpectedMissingLocalData(
+            OnDevicePersonalizationManager manager, String tableKey) throws InterruptedException {
+        // Check to ensure that the given key is missing in the local data
+        readExpectedLocalData(
+                manager, tableKey, /* expectedDataValue= */ "", /* expectLargeData= */ false);
+    }
+
+    /**
+     * Sends a request to the sample service to confirm that the given key does not exist in local
+     * data.
+     *
+     * <p>Uses the new {@code executeInIsolatedProcess} API.
+     */
+    private static void checkExpectedMissingLocalDataNewExecuteApi(
+            OnDevicePersonalizationManager manager, String tableKey) throws InterruptedException {
+        readExpectedLocalDataNewExecuteApi(
+                manager, tableKey, /* expectedDataValue= */ "", /* expectLargeData= */ false);
+    }
+
+    /**
+     * Sends a request to the sample service to confirm that the given key has a matching value in
+     * the local data table.
+     *
+     * <p>Uses the new {@code executeInIsolatedProcess} API.
+     */
+    private static void readExpectedLocalDataNewExecuteApi(
+            OnDevicePersonalizationManager manager,
+            String tableKey,
+            String expectedDataValue,
+            boolean expectLargeData)
+            throws InterruptedException {
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        if (!expectedDataValue.isEmpty()) {
+            // If expected data value is empty, and we do not include it in the bundle to the
+            // SampleService, it will check to ensure that the key does not exist in local data.
+            appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, expectedDataValue);
+        }
+
+        if (expectLargeData) {
+            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
+        }
+
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to confirm that the given key has a matching value in
+     * the local data table.
+     *
+     * <p>Uses the legacy {@code execute} API.
+     */
+    private static void readExpectedLocalData(
+            OnDevicePersonalizationManager manager,
+            String tableKey,
+            String expectedDataValue,
+            boolean expectLargeData)
+            throws InterruptedException {
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_READ_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        if (!expectedDataValue.isEmpty()) {
+            appParams.putString(SampleServiceApi.KEY_BASE64_VALUE, expectedDataValue);
+        }
+
+        if (expectLargeData) {
+            appParams.putInt(SampleServiceApi.KEY_TABLE_VALUE_REPEAT_COUNT, LARGE_BLOB_SIZE);
+        }
+
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to remove the given key from the local data table.
+     *
+     * <p>Uses the legacy {@code execute} API.
+     */
+    private static void removeLocalData(OnDevicePersonalizationManager manager, String tableKey)
+            throws InterruptedException {
+        // Remove local data associated with the given tableKey and assert that the execute
+        // call is successful. Uses the legacy execute API.
+        var receiver = new ResultReceiver<ExecuteResult>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                appParams,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+
+    /**
+     * Sends a request to the sample service to remove the given key from the local data table.
+     *
+     * <p>Uses the new {@code executeInIsolatedProcess} API.
+     */
+    private static void removeLocalDataNewExecuteApi(
+            OnDevicePersonalizationManager manager, String tableKey) throws InterruptedException {
+        // Remove local data associated with the given tableKey and assert that the execute
+        // call is successful. Uses the new execute API.
+        var receiver = new ResultReceiver<ExecuteInIsolatedServiceResponse>();
+        PersistableBundle appParams = new PersistableBundle();
+        appParams.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_WRITE_LOCAL_DATA);
+        appParams.putString(SampleServiceApi.KEY_TABLE_KEY, tableKey);
+        ExecuteInIsolatedServiceRequest request =
+                new ExecuteInIsolatedServiceRequest.Builder(
+                                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS))
+                        .setAppParams(appParams)
+                        .build();
+
+        manager.executeInIsolatedService(request, Executors.newSingleThreadExecutor(), receiver);
+
+        assertTrue(receiver.getErrorMessage(), receiver.isSuccess());
+    }
+}
diff --git a/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/OdpSystemEventManagerTests.java b/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/OdpSystemEventManagerTests.java
new file mode 100644
index 00000000..c3db2e49
--- /dev/null
+++ b/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/OdpSystemEventManagerTests.java
@@ -0,0 +1,72 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.ondevicepersonalization.e2etests;
+
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+
+import android.adservices.ondevicepersonalization.MeasurementWebTriggerEventParams;
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationSystemEventManager;
+import android.content.ComponentName;
+import android.content.Context;
+import android.net.Uri;
+
+import androidx.test.core.app.ApplicationProvider;
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
+import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
+
+import org.junit.Assume;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.util.concurrent.Executors;
+
+/** Test cases for OnDevicePersonalizationConfigManager APIs. */
+@RunWith(AndroidJUnit4.class)
+public class OdpSystemEventManagerTests {
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+
+    @Before
+    public void setUp() throws Exception {
+        // Skip the test if it runs on unsupported platforms.
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
+    }
+
+    @Test
+    public void testNotifyMeasurementEventPermissionDenied() throws Exception {
+        OnDevicePersonalizationSystemEventManager manager =
+                mContext.getSystemService(OnDevicePersonalizationSystemEventManager.class);
+        assertNotNull(manager);
+        ResultReceiver<Void> receiver = new ResultReceiver<>();
+        MeasurementWebTriggerEventParams params =
+                new MeasurementWebTriggerEventParams.Builder(
+                        Uri.parse("http://example.com"),
+                        "com.example.testapp",
+                        ComponentName.createRelative("com.example.service", ".ServiceClass"))
+                .setCertDigest("ABCD")
+                .setEventData(new byte[] {1, 2, 3})
+                .build();
+        manager.notifyMeasurementEvent(params, Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.isError());
+        assertNotNull(receiver.getException());
+        assertTrue(receiver.getException().getClass().getSimpleName(),
+                receiver.getException() instanceof SecurityException);
+    }
+}
diff --git a/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/RequestSurfacePackageTests.java b/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/RequestSurfacePackageTests.java
new file mode 100644
index 00000000..6c20b509
--- /dev/null
+++ b/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/RequestSurfacePackageTests.java
@@ -0,0 +1,350 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package com.android.ondevicepersonalization.e2etests;
+
+import static android.view.Display.DEFAULT_DISPLAY;
+
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertThrows;
+
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager.ExecuteResult;
+import android.adservices.ondevicepersonalization.SurfacePackageToken;
+import android.content.ComponentName;
+import android.content.Context;
+import android.hardware.display.DisplayManager;
+import android.os.Handler;
+import android.os.Looper;
+import android.os.PersistableBundle;
+import android.platform.test.rule.ScreenRecordRule;
+import android.util.Log;
+import android.view.Display;
+import android.view.SurfaceControlViewHost.SurfacePackage;
+import android.view.SurfaceView;
+import android.view.View;
+
+import androidx.test.core.app.ApplicationProvider;
+import androidx.test.ext.junit.rules.ActivityScenarioRule;
+import androidx.test.platform.app.InstrumentationRegistry;
+import androidx.test.uiautomator.By;
+import androidx.test.uiautomator.UiDevice;
+import androidx.test.uiautomator.UiObject2;
+
+import com.android.compatibility.common.util.ShellUtils;
+import com.android.modules.utils.build.SdkLevel;
+import com.android.ondevicepersonalization.testing.sampleserviceapi.SampleServiceApi;
+import com.android.ondevicepersonalization.testing.utils.DeviceSupportHelper;
+import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
+
+import org.junit.After;
+import org.junit.Assume;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+import java.util.concurrent.ArrayBlockingQueue;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.Executors;
+
+/**
+ * Test cases for OnDevicePersonalizationManager#requestSurfacePackage.
+ */
+@RunWith(JUnit4.class)
+@ScreenRecordRule.ScreenRecord
+public class RequestSurfacePackageTests {
+
+    @Rule public final ScreenRecordRule sScreenRecordRule = new ScreenRecordRule();
+
+    private static final String SERVICE_PACKAGE =
+            "com.android.ondevicepersonalization.testing.sampleservice";
+    private static final String SERVICE_CLASS =
+            "com.android.ondevicepersonalization.testing.sampleservice.SampleService";
+
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+
+    private static final String TAG = RequestSurfacePackageTests.class.getSimpleName();
+
+    private UiDevice mDevice;
+
+    private static final int DELAY_MILLIS = 2000;
+
+    @Before
+    public void setUp() {
+        // Skip the test if it runs on unsupported platforms.
+        Assume.assumeTrue(DeviceSupportHelper.isDeviceSupported());
+        Assume.assumeTrue(DeviceSupportHelper.isOdpModuleAvailable());
+
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "shared_isolated_process_feature_enabled "
+                        + SdkLevel.isAtLeastU());
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "debug.validate_rendering_config_keys "
+                        + false);
+
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "isolated_service_allow_list "
+                        + "com.android.ondevicepersonalization.testing.sampleservice,"
+                        + "com.example.odptargetingapp2");
+
+        mDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
+    }
+
+    @After
+    public void reset() {
+        ShellUtils.runShellCommand(
+                "device_config put on_device_personalization "
+                        + "isolated_service_allow_list "
+                        + "null");
+
+        ShellUtils.runShellCommand(
+                "am force-stop com.google.android.ondevicepersonalization.services");
+        ShellUtils.runShellCommand(
+                "am force-stop com.android.ondevicepersonalization.services");
+
+    }
+
+    @Rule
+    public final ActivityScenarioRule<TestActivity> mActivityScenarioRule =
+            new ActivityScenarioRule<>(TestActivity.class);
+
+    @Test
+    public void testRequestSurfacePackageSuccess() throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        SurfacePackageToken token = runExecute(manager);
+
+        Log.i(TAG, "Finished getting token");
+        Thread.sleep(DELAY_MILLIS);
+
+        var receiver = new ResultReceiver<SurfacePackage>();
+        SurfaceView surfaceView = createSurfaceView();
+        manager.requestSurfacePackage(
+                token,
+                surfaceView.getHostToken(),
+                getDisplayId(),
+                surfaceView.getWidth(),
+                surfaceView.getHeight(),
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        SurfacePackage surfacePackage = receiver.getResult();
+        assertNotNull(surfacePackage);
+
+        Log.i(TAG, "Finished requesting surface package");
+        Thread.sleep(DELAY_MILLIS);
+
+        CountDownLatch latch = new CountDownLatch(1);
+        new Handler(Looper.getMainLooper()).post(
+                () -> {
+                    surfaceView.setChildSurfacePackage(surfacePackage);
+                    surfaceView.setZOrderOnTop(true);
+                    surfaceView.setVisibility(View.VISIBLE);
+                    latch.countDown();
+                });
+        latch.await();
+
+        Log.i(TAG, "Finished posting surface view");
+        Thread.sleep(DELAY_MILLIS);
+
+        for (int i = 0; i < 5; i++) {
+            try {
+                UiObject2 clickableLink =
+                        mDevice.findObject(By.text(SampleServiceApi.LINK_TEXT));
+                clickableLink.click();
+
+                // Retry if unable to click on the link.
+                Thread.sleep(2500);
+
+                surfacePackage.release();
+                mDevice.pressHome();
+
+                return;
+            } catch (Exception e) {
+                Log.e(TAG, "Failed to click on webview link.");
+            }
+        }
+
+        // TODO(b/331286466): Investigate failures in this test case.
+        // throw new RuntimeException("Failed to request and render surface package.");
+    }
+
+    @Test
+    public void testRequestSurfacePackageThrowsIfSurfacePackageTokenMissing()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        SurfaceView surfaceView = createSurfaceView();
+        assertThrows(
+                NullPointerException.class,
+                () -> manager.requestSurfacePackage(
+                        null,
+                        surfaceView.getHostToken(),
+                        getDisplayId(),
+                        surfaceView.getWidth(),
+                        surfaceView.getHeight(),
+                        Executors.newSingleThreadExecutor(),
+                        new ResultReceiver<SurfacePackage>()));
+    }
+
+    @Test
+    public void testRequestSurfacePackageThrowsIfSurfaceViewHostTokenMissing()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        SurfacePackageToken token = runExecute(manager);
+        SurfaceView surfaceView = createSurfaceView();
+        assertThrows(
+                NullPointerException.class,
+                () -> manager.requestSurfacePackage(
+                        token,
+                        null,
+                        getDisplayId(),
+                        surfaceView.getWidth(),
+                        surfaceView.getHeight(),
+                        Executors.newSingleThreadExecutor(),
+                        new ResultReceiver<SurfacePackage>()));
+    }
+
+    @Test
+    public void testRequestSurfacePackageThrowsIfInvalidDisplayId()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        SurfacePackageToken token = runExecute(manager);
+        SurfaceView surfaceView = createSurfaceView();
+        assertThrows(
+                IllegalArgumentException.class,
+                () -> manager.requestSurfacePackage(
+                        token,
+                        surfaceView.getHostToken(),
+                        -1,
+                        surfaceView.getWidth(),
+                        surfaceView.getHeight(),
+                        Executors.newSingleThreadExecutor(),
+                        new ResultReceiver<SurfacePackage>()));
+    }
+
+    @Test
+    public void testRequestSurfacePackageThrowsIfInvalidWidth()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        SurfacePackageToken token = runExecute(manager);
+        SurfaceView surfaceView = createSurfaceView();
+        assertThrows(
+                IllegalArgumentException.class,
+                () -> manager.requestSurfacePackage(
+                        token,
+                        surfaceView.getHostToken(),
+                        getDisplayId(),
+                        0,
+                        surfaceView.getHeight(),
+                        Executors.newSingleThreadExecutor(),
+                        new ResultReceiver<SurfacePackage>()));
+    }
+
+    @Test
+    public void testRequestSurfacePackageThrowsIfInvalidHeight()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        SurfacePackageToken token = runExecute(manager);
+        SurfaceView surfaceView = createSurfaceView();
+        assertThrows(
+                IllegalArgumentException.class,
+                () -> manager.requestSurfacePackage(
+                        token,
+                        surfaceView.getHostToken(),
+                        getDisplayId(),
+                        surfaceView.getWidth(),
+                        0,
+                        Executors.newSingleThreadExecutor(),
+                        new ResultReceiver<SurfacePackage>()));
+    }
+
+    @Test
+    public void testRequestSurfacePackageThrowsIfExecutorMissing()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        SurfacePackageToken token = runExecute(manager);
+        SurfaceView surfaceView = createSurfaceView();
+        assertThrows(
+                NullPointerException.class,
+                () -> manager.requestSurfacePackage(
+                        token,
+                        surfaceView.getHostToken(),
+                        getDisplayId(),
+                        surfaceView.getWidth(),
+                        surfaceView.getHeight(),
+                        null,
+                        new ResultReceiver<SurfacePackage>()));
+    }
+
+    @Test
+    public void testRequestSurfacePackageThrowsIfOutcomeReceiverMissing()
+            throws InterruptedException {
+        OnDevicePersonalizationManager manager =
+                mContext.getSystemService(OnDevicePersonalizationManager.class);
+        SurfacePackageToken token = runExecute(manager);
+        SurfaceView surfaceView = createSurfaceView();
+        assertThrows(
+                NullPointerException.class,
+                () -> manager.requestSurfacePackage(
+                        token,
+                        surfaceView.getHostToken(),
+                        getDisplayId(),
+                        surfaceView.getWidth(),
+                        surfaceView.getHeight(),
+                        Executors.newSingleThreadExecutor(),
+                        null));
+    }
+
+    int getDisplayId() {
+        final DisplayManager dm = mContext.getSystemService(DisplayManager.class);
+        final Display primaryDisplay = dm.getDisplay(DEFAULT_DISPLAY);
+        final Context windowContext = mContext.createDisplayContext(primaryDisplay);
+        return windowContext.getDisplay().getDisplayId();
+    }
+
+    SurfaceView createSurfaceView() throws InterruptedException {
+        ArrayBlockingQueue<SurfaceView> viewQueue = new ArrayBlockingQueue<>(1);
+        mActivityScenarioRule.getScenario().onActivity(
+                a -> viewQueue.add(a.findViewById(R.id.test_surface_view)));
+        return viewQueue.take();
+    }
+
+    private SurfacePackageToken runExecute(
+            OnDevicePersonalizationManager manager)
+            throws InterruptedException {
+        PersistableBundle params = new PersistableBundle();
+        params.putString(SampleServiceApi.KEY_OPCODE, SampleServiceApi.OPCODE_RENDER_AND_LOG);
+        params.putString(SampleServiceApi.KEY_RENDERING_CONFIG_IDS, "id1");
+        var receiver = new ResultReceiver<ExecuteResult>();
+        manager.execute(
+                new ComponentName(SERVICE_PACKAGE, SERVICE_CLASS),
+                params,
+                Executors.newSingleThreadExecutor(),
+                receiver);
+        assertNotNull(receiver.getResult());
+        assertNotNull(receiver.getResult().getSurfacePackageToken());
+        return receiver.getResult().getSurfacePackageToken();
+    }
+}
diff --git a/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/TestActivity.java b/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/TestActivity.java
new file mode 100644
index 00000000..6ef00e2f
--- /dev/null
+++ b/tests/endtoendtests/src/com/android/ondevicepersonalization/e2etests/TestActivity.java
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.ondevicepersonalization.e2etests;
+
+import android.app.Activity;
+import android.os.Bundle;
+
+/**
+ * A simple activity that can contain views.
+ */
+public class TestActivity extends Activity {
+    @Override
+    public void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setContentView(R.layout.activity_main);
+    }
+}
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegateTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegateTest.java
index 3c13e4b7..ef2084d8 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegateTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/FederatedComputeManagingServiceDelegateTest.java
@@ -27,16 +27,20 @@ import static com.android.federatedcompute.services.stats.FederatedComputeStatsL
 import static com.google.common.truth.Truth.assertThat;
 
 import static org.junit.Assert.assertThrows;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
+import android.adservices.ondevicepersonalization.Constants;
 import android.content.ComponentName;
 import android.content.Context;
 import android.federatedcompute.aidl.IFederatedComputeCallback;
+import android.federatedcompute.aidl.IIsFeatureEnabledCallback;
 import android.federatedcompute.common.TrainingOptions;
+import android.os.RemoteException;
 
 import androidx.test.core.app.ApplicationProvider;
 
@@ -294,6 +298,53 @@ public final class FederatedComputeManagingServiceDelegateTest {
                                 new FederatedComputeCallback()));
     }
 
+    @Test
+    public void testIsFeatureEnabledFlagDisabled_returnsError() throws Exception {
+        PhFlagsTestUtil.disableIsFeatureEnabled();
+        assertThrows(
+                IllegalStateException.class,
+                () ->
+                        mFcpService.isFeatureEnabled(
+                                "featureName",
+                                new IsFeatureEnabledCallback()));
+    }
+
+    @Test
+    public void testIsFeatureEnabledAndLogging() throws Exception {
+        PhFlagsTestUtil.enableIsFeatureEnabled();
+        final CountDownLatch logOperationCalledLatch = new CountDownLatch(1);
+        ArgumentCaptor<ApiCallStats> argument = ArgumentCaptor.forClass(ApiCallStats.class);
+
+        doAnswer(
+                new Answer<Object>() {
+                    @Override
+                    public Object answer(InvocationOnMock invocation) throws Throwable {
+                        // The method logAPiCallStats is called.
+                        invocation.callRealMethod();
+                        logOperationCalledLatch.countDown();
+                        return null;
+                    }
+                })
+                .when(mFcStatsdLogger)
+                .logApiCallStats(argument.capture());
+        var callback = new IsFeatureEnabledCallback();
+        mFcpService.isFeatureEnabled(
+                "featureName",
+                callback);
+
+        callback.await();
+        assertTrue(callback.mWasInvoked);
+
+        logOperationCalledLatch.await(BINDER_CONNECTION_TIMEOUT_MS, TimeUnit.MILLISECONDS);
+
+        assertThat(argument.getValue().getResponseCode()).isEqualTo(Constants.STATUS_SUCCESS);
+        assertThat(argument.getValue().getApiName())
+                .isEqualTo(Constants.API_NAME_IS_FEATURE_ENABLED);
+
+        PhFlagsTestUtil.disableIsFeatureEnabled();
+
+    }
+
     private void invokeScheduleAndVerifyLogging(
             TrainingOptions trainingOptions, int expectedResultCode) throws InterruptedException {
         invokeScheduleAndVerifyLogging(trainingOptions, expectedResultCode, 100L);
@@ -382,6 +433,21 @@ public final class FederatedComputeManagingServiceDelegateTest {
         }
     }
 
+    static class IsFeatureEnabledCallback extends IIsFeatureEnabledCallback.Stub {
+        public boolean mWasInvoked = false;
+        private final CountDownLatch mLatch = new CountDownLatch(1);
+
+        @Override
+        public void onResult(int result) throws RemoteException {
+            mWasInvoked = true;
+            mLatch.countDown();
+        }
+
+        public void await() throws Exception {
+            mLatch.await();
+        }
+    }
+
     class TestInjector extends FederatedComputeManagingServiceDelegate.Injector {
         FederatedComputeJobManager getJobManager(Context mContext) {
             return mMockJobManager;
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/FeatureStatusManagerTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/FeatureStatusManagerTest.java
new file mode 100644
index 00000000..dd9d4f95
--- /dev/null
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/FeatureStatusManagerTest.java
@@ -0,0 +1,148 @@
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
+package com.android.federatedcompute.services.common;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertTrue;
+
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.federatedcompute.aidl.IIsFeatureEnabledCallback;
+
+import com.android.dx.mockito.inline.extended.ExtendedMockito;
+import com.android.modules.utils.testing.ExtendedMockitoRule;
+import com.android.ondevicepersonalization.internal.util.LoggerFactory;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.quality.Strictness;
+
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.Map;
+import java.util.Set;
+import java.util.concurrent.CountDownLatch;
+import java.util.function.Supplier;
+@RunWith(JUnit4.class)
+public class FeatureStatusManagerTest {
+    private static final LoggerFactory.Logger sLogger = LoggerFactory.getLogger();
+    private static final String TAG = FeatureStatusManagerTest.class.getSimpleName();
+    private static final long SERVICE_ENTRY_TIME = 100L;
+    private final CountDownLatch mLatch = new CountDownLatch(1);
+    private volatile boolean mCallbackSuccess;
+    private volatile int mResult;
+
+    @Rule
+    public final ExtendedMockitoRule mExtendedMockitoRule =
+            new ExtendedMockitoRule.Builder(this)
+                    .spyStatic(FlagsFactory.class)
+                    .setStrictness(Strictness.LENIENT)
+                    .build();
+
+    @Before
+    public void setUp() {
+        ExtendedMockito.doReturn(new TestFlags() {}).when(FlagsFactory::getFlags);
+    }
+
+    @Test
+    public void testEnabledNonFlaggedFeature() {
+        Set<String> nonFlaggedFeatures = new HashSet<>();
+        nonFlaggedFeatures.add("featureName");
+        FeatureStatusManager featureStatusManager =
+                new FeatureStatusManager(
+                        FlagsFactory.getFlags(),
+                        new HashMap<>(),
+                        nonFlaggedFeatures);
+        assertThat(featureStatusManager.isFeatureEnabled("featureName")).isEqualTo(
+                OnDevicePersonalizationManager.FEATURE_ENABLED);
+    }
+
+    @Test
+    public void testEnabledFlaggedFeature() {
+        Map<String, Supplier<Boolean>> flaggedFeatures = new HashMap<>();
+
+        flaggedFeatures.put("featureName", (new TestFlags() {})::getEnabledFeature);
+        FeatureStatusManager featureStatusManager =
+                new FeatureStatusManager(
+                        FlagsFactory.getFlags(),
+                        flaggedFeatures,
+                        new HashSet<>());
+        assertThat(featureStatusManager.isFeatureEnabled("featureName")).isEqualTo(
+                OnDevicePersonalizationManager.FEATURE_ENABLED);
+    }
+
+    @Test
+    public void testDisabledFlaggedFeature() {
+        Map<String, Supplier<Boolean>> flaggedFeatures = new HashMap<>();
+
+        flaggedFeatures.put("featureName", (new TestFlags() {})::getDisabledFeature);
+        FeatureStatusManager featureStatusManager =
+                new FeatureStatusManager(
+                        FlagsFactory.getFlags(),
+                        flaggedFeatures,
+                        new HashSet<>());
+        assertThat(featureStatusManager.isFeatureEnabled("featureName")).isEqualTo(
+                OnDevicePersonalizationManager.FEATURE_DISABLED);
+    }
+
+    @Test
+    public void testUnsupportedFeature() {
+        FeatureStatusManager featureStatusManager = new FeatureStatusManager(
+                FlagsFactory.getFlags(),
+                new HashMap<>(),
+                new HashSet<>());
+        assertThat(featureStatusManager.isFeatureEnabled("featureName")).isEqualTo(
+                OnDevicePersonalizationManager.FEATURE_UNSUPPORTED);
+    }
+
+    @Test
+    public void testGetFeatureStatusAndSendResult() throws InterruptedException {
+        FeatureStatusManager.getFeatureStatusAndSendResult(
+                "featureName",
+                SERVICE_ENTRY_TIME,
+                new TestIsFeatureEnabledCallback());
+        mLatch.await();
+
+        assertTrue(mCallbackSuccess);
+        assertEquals(mResult, OnDevicePersonalizationManager.FEATURE_UNSUPPORTED);
+    }
+
+    class TestFlags implements Flags {
+
+        public boolean getDisabledFeature() {
+            return false;
+        }
+
+        public boolean getEnabledFeature() {
+            return true;
+        }
+    }
+
+    class TestIsFeatureEnabledCallback extends IIsFeatureEnabledCallback.Stub {
+        @Override
+        public void onResult(int result) {
+            sLogger.d(TAG + " : onResult callback.");
+            mCallbackSuccess = true;
+            mResult = result;
+            mLatch.countDown();
+        }
+    }
+}
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTest.java
index 7c9bbf47..2f23740c 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTest.java
@@ -19,11 +19,15 @@ package com.android.federatedcompute.services.common;
 import static com.android.adservices.shared.common.flags.ModuleSharedFlags.BACKGROUND_JOB_LOGGING_ENABLED;
 import static com.android.adservices.shared.common.flags.ModuleSharedFlags.DEFAULT_JOB_SCHEDULING_LOGGING_ENABLED;
 import static com.android.adservices.shared.common.flags.ModuleSharedFlags.DEFAULT_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
+import static com.android.adservices.shared.common.flags.ModuleSharedFlags.DEFAULT_SPE_ENABLE_PER_JOB_POLICY;
+import static com.android.federatedcompute.services.common.Flags.DEFAULT_BACKGROUND_KEY_FETCH_JOB_POLICY;
+import static com.android.federatedcompute.services.common.Flags.DEFAULT_DELETE_EXPIRED_DATA_JOB_POLICY;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_ENABLE_ELIGIBILITY_TASK;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_FCP_MODULE_JOB_POLICY;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_FCP_TASK_LIMIT_PER_PACKAGE;
+import static com.android.federatedcompute.services.common.Flags.DEFAULT_IS_FEATURE_ENABLED_API_ENABLED;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_SCHEDULING_PERIOD_SECS;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_SPE_PILOT_JOB_ENABLED;
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_THERMAL_STATUS_TO_THROTTLE;
@@ -43,12 +47,11 @@ import static com.android.federatedcompute.services.common.Flags.MIN_SCHEDULING_
 import static com.android.federatedcompute.services.common.Flags.TRANSIENT_ERROR_RETRY_DELAY_JITTER_PERCENT;
 import static com.android.federatedcompute.services.common.Flags.TRANSIENT_ERROR_RETRY_DELAY_SECS;
 import static com.android.federatedcompute.services.common.Flags.USE_BACKGROUND_ENCRYPTION_KEY_FETCH;
-import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
-import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB;
-import static com.android.federatedcompute.services.common.FlagsConstants.HTTP_REQUEST_RETRY_LIMIT_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.DEFAULT_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH;
 import static com.android.federatedcompute.services.common.FlagsConstants.ENABLE_ELIGIBILITY_TASK;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
+import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB;
 import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOB_LOGGING_SAMPLING_RATE;
 import static com.android.federatedcompute.services.common.FlagsConstants.FCP_CHECKPOINT_FILE_SIZE_LIMIT_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.FCP_ENABLE_BACKGROUND_JOBS_LOGGING;
@@ -63,7 +66,12 @@ import static com.android.federatedcompute.services.common.FlagsConstants.FCP_RE
 import static com.android.federatedcompute.services.common.FlagsConstants.FCP_SPE_PILOT_JOB_ENABLED;
 import static com.android.federatedcompute.services.common.FlagsConstants.FCP_TASK_LIMIT_PER_PACKAGE_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.FEDERATED_COMPUTATION_ENCRYPTION_KEY_DOWNLOAD_URL;
+import static com.android.federatedcompute.services.common.FlagsConstants.HTTP_REQUEST_RETRY_LIMIT_CONFIG_NAME;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_BACKGROUND_KEY_FETCH_JOB_POLICY;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_DELETE_EXPIRED_DATA_JOB_POLICY;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_ENABLE_PER_JOB_POLICY;
 import static com.android.federatedcompute.services.common.FlagsConstants.KEY_FEDERATED_COMPUTE_KILL_SWITCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_IS_FEATURE_ENABLED_API_ENABLED;
 import static com.android.federatedcompute.services.common.FlagsConstants.MAX_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.MAX_SCHEDULING_PERIOD_SECS_CONFIG_NAME;
 import static com.android.federatedcompute.services.common.FlagsConstants.MIN_SCHEDULING_INTERVAL_SECS_FOR_FEDERATED_COMPUTATION_CONFIG_NAME;
@@ -219,6 +227,11 @@ public class PhFlagsTest {
                 FCP_CHECKPOINT_FILE_SIZE_LIMIT_CONFIG_NAME,
                 Integer.toString(FCP_DEFAULT_CHECKPOINT_FILE_SIZE_LIMIT),
                 /* makeDefault= */ false);
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_IS_FEATURE_ENABLED_API_ENABLED,
+                Boolean.toString(DEFAULT_IS_FEATURE_ENABLED_API_ENABLED),
+                /* makeDefault= */ false);
     }
 
     @Test
@@ -284,24 +297,8 @@ public class PhFlagsTest {
 
     @Test
     public void testEnableEncryption() {
-        // Without Overriding
-        DeviceConfig.setProperty(
-                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
-                FCP_ENABLE_ENCRYPTION,
-                Boolean.toString(ENCRYPTION_ENABLED),
-                /* makeDefault */ false);
-        assertThat(FlagsFactory.getFlags().isEncryptionEnabled()).isEqualTo(ENCRYPTION_ENABLED);
-
-        // Now overriding the value from PH
-        boolean overrideEnableEncryption = !ENCRYPTION_ENABLED;
-        DeviceConfig.setProperty(
-                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
-                FCP_ENABLE_ENCRYPTION,
-                Boolean.toString(overrideEnableEncryption),
-                /* makeDefault */ false);
-
-        Flags phFlags = FlagsFactory.getFlags();
-        assertThat(phFlags.isEncryptionEnabled()).isEqualTo(overrideEnableEncryption);
+        // Test default value of encryption is enabled.
+        assertThat(FlagsFactory.getFlags().isEncryptionEnabled()).isTrue();
     }
 
     @Test
@@ -633,8 +630,7 @@ public class PhFlagsTest {
 
     @Test
     public void testGetBackgroundJobsLoggingEnabled() {
-        assertThat(FlagsFactory.getFlags().getBackgroundJobsLoggingEnabled())
-                .isEqualTo(true);
+        assertThat(FlagsFactory.getFlags().getBackgroundJobsLoggingEnabled()).isEqualTo(true);
     }
 
     @Test
@@ -771,7 +767,7 @@ public class PhFlagsTest {
 
     @Test
     public void testGetSpePilotJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpePilotJobEnabled(),
                 /* flagName */ FCP_SPE_PILOT_JOB_ENABLED,
                 /* defaultValue */ DEFAULT_SPE_PILOT_JOB_ENABLED);
@@ -779,7 +775,7 @@ public class PhFlagsTest {
 
     @Test
     public void testGetSpeOnBackgroundKeyFetchJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpeOnBackgroundKeyFetchJobEnabled(),
                 /* flagName */ FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB,
                 /* defaultValue */
@@ -788,13 +784,55 @@ public class PhFlagsTest {
 
     @Test
     public void testGetSpeOnFederatedJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpeOnFederatedJobEnabled(),
                 /* flagName */ FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB,
                 /* defaultValue */ DEFAULT_FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_FEDERATED_JOB);
     }
 
-    private void assertSpeFeatureFlags(
+    @Test
+    public void testIsFeatureEnabledApiEnabled() {
+        // read a stable flag value and verify it's equal to the default value.
+        boolean stableValue = FlagsFactory.getFlags().isFeatureEnabledApiEnabled();
+        assertThat(stableValue).isEqualTo(DEFAULT_IS_FEATURE_ENABLED_API_ENABLED);
+
+        // override the value in device config.
+        boolean overrideEnabled = !stableValue;
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_IS_FEATURE_ENABLED_API_ENABLED,
+                Boolean.toString(overrideEnabled),
+                /* makeDefault= */ false);
+
+        // the flag value remains stable
+        assertThat(FlagsFactory.getFlags().isFeatureEnabledApiEnabled()).isEqualTo(overrideEnabled);
+    }
+
+    @Test
+    public void testGetEnablePerJobPolicy() {
+        assertBooleanFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeEnablePerJobPolicy(),
+                KEY_ENABLE_PER_JOB_POLICY,
+                DEFAULT_SPE_ENABLE_PER_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetBackgroundKeyFetchJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getBackgroundKeyFetchJobPolicy(),
+                KEY_BACKGROUND_KEY_FETCH_JOB_POLICY,
+                DEFAULT_BACKGROUND_KEY_FETCH_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetDeleteExpiredDataJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getDeleteExpiredDataJobPolicy(),
+                KEY_DELETE_EXPIRED_DATA_JOB_POLICY,
+                DEFAULT_DELETE_EXPIRED_DATA_JOB_POLICY);
+    }
+
+    private void assertBooleanFeatureFlags(
             Supplier<Boolean> flagSupplier, String flagName, boolean defaultValue) {
         // Test override value
         boolean overrideValue = !defaultValue;
@@ -813,4 +851,24 @@ public class PhFlagsTest {
                 /* makeDefault */ false);
         assertThat(flagSupplier.get()).isEqualTo(defaultValue);
     }
+
+    private void assertStringFeatureFlags(
+            Supplier<String> flagSupplier, String flagName, String defaultValue) {
+        // Test override value
+        String overrideValue = "" + "_test_value";
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                flagName,
+                overrideValue,
+                /* makeDefault */ false);
+        assertThat(flagSupplier.get()).isEqualTo(overrideValue);
+
+        // Test default value
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                flagName,
+                defaultValue,
+                /* makeDefault */ false);
+        assertThat(flagSupplier.get()).isEqualTo(defaultValue);
+    }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
index 3213a747..341296bd 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/common/PhFlagsTestUtil.java
@@ -20,6 +20,7 @@ import static com.android.federatedcompute.services.common.Flags.USE_BACKGROUND_
 import static com.android.federatedcompute.services.common.FlagsConstants.ENABLE_BACKGROUND_ENCRYPTION_KEY_FETCH;
 import static com.android.federatedcompute.services.common.FlagsConstants.FCP_BACKGROUND_JOBS__ENABLE_SPE_ON_BACKGROUND_KEY_FETCH_JOB;
 import static com.android.federatedcompute.services.common.FlagsConstants.KEY_FEDERATED_COMPUTE_KILL_SWITCH;
+import static com.android.federatedcompute.services.common.FlagsConstants.KEY_IS_FEATURE_ENABLED_API_ENABLED;
 
 import android.provider.DeviceConfig;
 
@@ -102,4 +103,22 @@ public class PhFlagsTestUtil {
                 Boolean.toString(false),
                 /* makeDefault= */ false);
     }
+
+    /** Enable isFeatureEnabled. */
+    public static void enableIsFeatureEnabled() {
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_IS_FEATURE_ENABLED_API_ENABLED,
+                Boolean.toString(true),
+                /* makeDefault= */ false);
+    }
+
+    /** Disable isFeatureEnabled. */
+    public static void disableIsFeatureEnabled() {
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_IS_FEATURE_ENABLED_API_ENABLED,
+                Boolean.toString(false),
+                /* makeDefault= */ false);
+    }
 }
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobTest.java
index 03ac6b3a..13b5669d 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/encryption/BackgroundKeyFetchJobTest.java
@@ -25,6 +25,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.federatedcompute.services.common.FederatedComputeJobInfo.ENCRYPTION_KEY_FETCH_JOB_ID;
 
+import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 
 import static org.junit.Assert.assertThrows;
@@ -238,6 +239,16 @@ public final class BackgroundKeyFetchJobTest {
                 .isEqualTo(expectedBackoffPolicy);
     }
 
+    @Test
+    public void testGetJobPolicyString() {
+        String testPolicyString = "test_string";
+
+        when(mMockFlags.getBackgroundKeyFetchJobPolicy()).thenReturn(testPolicyString);
+
+        assertThat(mBackgroundKeyFetchJob.getJobPolicyString(/* jobId= */ 0))
+                .isEqualTo(testPolicyString);
+    }
+
     public class TestInjector extends BackgroundKeyFetchJob.Injector {
         @Override
         ListeningExecutorService getLightWeightExecutor() {
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
index 4067e76c..a70e4b13 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/DeleteExpiredJobTest.java
@@ -27,6 +27,7 @@ import static com.android.federatedcompute.services.common.FederatedComputeJobIn
 import static com.android.federatedcompute.services.common.Flags.DEFAULT_TASK_HISTORY_TTL_MILLIS;
 import static com.android.federatedcompute.services.common.Flags.ODP_AUTHORIZATION_TOKEN_DELETION_PERIOD_SECONDs;
 
+import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 
 import static org.mockito.ArgumentMatchers.any;
@@ -195,6 +196,16 @@ public class DeleteExpiredJobTest {
                 .isEqualTo(new JobSpec.Builder(expectedJobPolicy).build());
     }
 
+    @Test
+    public void testGetJobPolicyString() {
+        String testPolicyString = "test_string";
+
+        when(mMockFlags.getDeleteExpiredDataJobPolicy()).thenReturn(testPolicyString);
+
+        assertThat(mDeleteExpiredJob.getJobPolicyString(/* jobId= */ 0))
+                .isEqualTo(testPolicyString);
+    }
+
     private class TestInjector extends Injector {
         @Override
         ListeningExecutorService getExecutor() {
diff --git a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/FederatedComputeLearningJobScheduleOrchestratorTest.java b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/FederatedComputeLearningJobScheduleOrchestratorTest.java
index 340c6f5a..a5b51343 100644
--- a/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/FederatedComputeLearningJobScheduleOrchestratorTest.java
+++ b/tests/federatedcomputetests/src/com/android/federatedcompute/services/scheduling/FederatedComputeLearningJobScheduleOrchestratorTest.java
@@ -45,16 +45,19 @@ import com.google.flatbuffers.FlatBufferBuilder;
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.junit.MockitoJUnitRunner;
 
+@RunWith(MockitoJUnitRunner.class)
 public class FederatedComputeLearningJobScheduleOrchestratorTest {
 
     private static final String CALLING_PACKAGE_NAME = "callingPkg";
     private static final String CALLING_CLASS_NAME =
-            "FederatedComputeLearningJobScheduleOrchestratorTest";
+            FederatedComputeLearningJobScheduleOrchestratorTest.class.getSimpleName();
     private static final String POPULATION_NAME = "population";
     private static final String SERVER_ADDRESS = "https://server.uri/";
 
-    private final Context mContext = ApplicationProvider.getApplicationContext();
+    private static final Context TEST_CONTEXT = ApplicationProvider.getApplicationContext();
 
     private FederatedTrainingTaskDao mTrainingTaskDao;
     private Clock mClock;
@@ -64,22 +67,23 @@ public class FederatedComputeLearningJobScheduleOrchestratorTest {
     @Before
     public void setUp() {
         mClock =  MonotonicClock.getInstance();
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
+        JobScheduler jobScheduler = TEST_CONTEXT.getSystemService(JobScheduler.class);
         jobScheduler.cancelAll();
-        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(mContext);
+        mTrainingTaskDao = FederatedTrainingTaskDao.getInstanceForTest(TEST_CONTEXT);
 
         mOrchestrator =
                 new FederatedComputeLearningJobScheduleOrchestrator(
-                        mContext, mTrainingTaskDao, new JobSchedulerHelper(mClock));
+                        TEST_CONTEXT, mTrainingTaskDao, new JobSchedulerHelper(mClock));
     }
 
     @After
     public void tearDown() {
-        FederatedComputeDbHelper dbHelper = FederatedComputeDbHelper.getInstanceForTest(mContext);
+        FederatedComputeDbHelper dbHelper =
+                FederatedComputeDbHelper.getInstanceForTest(TEST_CONTEXT);
         dbHelper.getWritableDatabase().close();
         dbHelper.getReadableDatabase().close();
         dbHelper.close();
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
+        JobScheduler jobScheduler = TEST_CONTEXT.getSystemService(JobScheduler.class);
         jobScheduler.cancelAll();
     }
 
@@ -93,7 +97,8 @@ public class FederatedComputeLearningJobScheduleOrchestratorTest {
                         .ownerPackageName(CALLING_PACKAGE_NAME)
                         .ownerClassName(CALLING_CLASS_NAME)
                         .ownerIdCertDigest(
-                                PackageUtils.getCertDigest(mContext, mContext.getPackageName()))
+                                PackageUtils.getCertDigest(
+                                        TEST_CONTEXT, TEST_CONTEXT.getPackageName()))
                         .populationName(POPULATION_NAME)
                         .serverAddress(SERVER_ADDRESS)
                         .creationTime(nowMillis)
@@ -109,7 +114,8 @@ public class FederatedComputeLearningJobScheduleOrchestratorTest {
                         .ownerPackageName(CALLING_PACKAGE_NAME)
                         .ownerClassName(CALLING_CLASS_NAME)
                         .ownerIdCertDigest(
-                                PackageUtils.getCertDigest(mContext, mContext.getPackageName()))
+                                PackageUtils.getCertDigest(
+                                        TEST_CONTEXT, TEST_CONTEXT.getPackageName()))
                         .populationName(POPULATION_NAME)
                         .serverAddress(SERVER_ADDRESS)
                         .creationTime(nowMillis)
@@ -120,12 +126,12 @@ public class FederatedComputeLearningJobScheduleOrchestratorTest {
                         .build();
         mTrainingTaskDao.updateOrInsertFederatedTrainingTask(task1);
         mTrainingTaskDao.updateOrInsertFederatedTrainingTask(task2);
-        ComponentName jobComponent = new ComponentName(mContext, TRAINING_JOB_SERVICE);
+        ComponentName jobComponent = new ComponentName(TEST_CONTEXT, TRAINING_JOB_SERVICE);
         JobInfo jobInfo2 =
                 new JobInfo.Builder(task2.jobId(), jobComponent)
                         .setMinimumLatency(1000000000)
                         .build();
-        JobScheduler jobScheduler = mContext.getSystemService(JobScheduler.class);
+        JobScheduler jobScheduler = TEST_CONTEXT.getSystemService(JobScheduler.class);
         jobScheduler.schedule(jobInfo2);
 
         mOrchestrator.checkAndSchedule();
diff --git a/tests/frameworktests/src/android/federatedcompute/FederatedComputeIsFeatureEnabledManagerTest.java b/tests/frameworktests/src/android/federatedcompute/FederatedComputeIsFeatureEnabledManagerTest.java
new file mode 100644
index 00000000..0eea00e3
--- /dev/null
+++ b/tests/frameworktests/src/android/federatedcompute/FederatedComputeIsFeatureEnabledManagerTest.java
@@ -0,0 +1,117 @@
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
+package android.federatedcompute;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+
+import android.adservices.ondevicepersonalization.OnDevicePersonalizationManager;
+import android.content.ComponentName;
+import android.content.Context;
+import android.federatedcompute.aidl.IFederatedComputeCallback;
+import android.federatedcompute.aidl.IFederatedComputeService;
+import android.federatedcompute.aidl.IIsFeatureEnabledCallback;
+import android.federatedcompute.common.TrainingOptions;
+import android.os.RemoteException;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.federatedcompute.internal.util.AbstractServiceBinder;
+import com.android.ondevicepersonalization.testing.utils.ResultReceiver;
+
+import org.junit.Test;
+
+import java.util.concurrent.Executor;
+import java.util.concurrent.Executors;
+
+public class FederatedComputeIsFeatureEnabledManagerTest {
+    private static final String TAG = "FederatedComputeIsFeatureEnabledManagerTest";
+    private final Context mContext = ApplicationProvider.getApplicationContext();
+    private final TestServiceBinder mTestBinder = new TestServiceBinder(
+            IFederatedComputeService.Stub.asInterface(new TestService()));
+    private final FederatedComputeManager mManager =
+            new FederatedComputeManager(mContext, mTestBinder);
+
+    @Test
+    public void testIsFeatureEnabledSuccess() throws Exception {
+        var receiver = new ResultReceiver<Integer>();
+
+        mManager.isFeatureEnabled(
+                "success", Executors.newSingleThreadExecutor(), receiver);
+        assertTrue(receiver.isSuccess());
+        assertFalse(receiver.isError());
+        assertNotNull(receiver.getResult());
+        assertThat(receiver.getResult()).isEqualTo(OnDevicePersonalizationManager.FEATURE_DISABLED);
+    }
+
+    @Test
+    public void testIsFeatureEnabledException() throws Exception {
+        var receiver = new ResultReceiver<Integer>();
+
+        mManager.isFeatureEnabled(
+                "error", Executors.newSingleThreadExecutor(), receiver);
+        assertFalse(receiver.isSuccess());
+        assertTrue(receiver.isError());
+        assertTrue(receiver.getException() instanceof IllegalStateException);
+    }
+
+    private class TestService extends IFederatedComputeService.Stub {
+
+        @Override
+        public void schedule(String s, TrainingOptions trainingOptions,
+                IFederatedComputeCallback iFederatedComputeCallback) throws RemoteException {
+            throw new UnsupportedOperationException();        }
+
+        @Override
+        public void cancel(ComponentName componentName, String s,
+                IFederatedComputeCallback iFederatedComputeCallback) throws RemoteException {
+            throw new UnsupportedOperationException();
+        }
+
+        @Override
+        public void isFeatureEnabled(
+                String featureName,
+                IIsFeatureEnabledCallback callback) throws RemoteException {
+            if (featureName.equals("success")) {
+                callback.onResult(OnDevicePersonalizationManager.FEATURE_DISABLED);
+            } else if (featureName.equals("error")) {
+                throw new IllegalStateException();
+            } else {
+                throw new UnsupportedOperationException();
+            }
+        }
+    }
+
+    private static class TestServiceBinder extends AbstractServiceBinder<IFederatedComputeService> {
+
+        private final IFederatedComputeService mService;
+
+        TestServiceBinder(IFederatedComputeService service) {
+            mService = service;
+        }
+        @Override
+        public IFederatedComputeService getService(Executor executor) {
+            return mService;
+        }
+
+        @Override
+        public void unbindFromService() {}
+    }
+}
diff --git a/tests/frameworktests/src/com/android/federatedcompute/internal/util/AndroidServiceBinderTest.java b/tests/frameworktests/src/com/android/federatedcompute/internal/util/AndroidServiceBinderTest.java
index 7afd4165..187ff3d7 100644
--- a/tests/frameworktests/src/com/android/federatedcompute/internal/util/AndroidServiceBinderTest.java
+++ b/tests/frameworktests/src/com/android/federatedcompute/internal/util/AndroidServiceBinderTest.java
@@ -18,10 +18,7 @@ package com.android.federatedcompute.internal.util;
 
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertThrows;
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.spy;
-import static org.mockito.Mockito.verify;
 
 import android.adservices.ondevicepersonalization.aidl.IOnDevicePersonalizationManagingService;
 import android.content.Context;
@@ -64,9 +61,7 @@ public class AndroidServiceBinderTest {
                                 ALT_ODP_MANAGING_SERVICE_PACKAGE),
                         IOnDevicePersonalizationManagingService.Stub::asInterface);
 
-        final IOnDevicePersonalizationManagingService service =
-                serviceBinder.getService(Runnable::run);
-        assertNotNull(service);
+        assertNotNull(serviceBinder);
     }
 
     @Test
@@ -81,15 +76,7 @@ public class AndroidServiceBinderTest {
                         Context.BIND_ALLOW_ACTIVITY_STARTS,
                         IOnDevicePersonalizationManagingService.Stub::asInterface);
 
-        final IOnDevicePersonalizationManagingService service =
-                serviceBinder.getService(Runnable::run);
-        verify(mSpyContext)
-                .bindService(
-                        any(),
-                        eq(Context.BIND_ALLOW_ACTIVITY_STARTS | Context.BIND_AUTO_CREATE),
-                        any(),
-                        any());
-        assertNotNull(service);
+        assertNotNull(serviceBinder);
     }
 
     @Test
diff --git a/tests/servicetests/res/raw/model.tflite b/tests/servicetests/res/raw/model.tflite
index 3a7595ee..ce3755f4 100644
Binary files a/tests/servicetests/res/raw/model.tflite and b/tests/servicetests/res/raw/model.tflite differ
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
index e79b0e53..ee26e7cc 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/OnDevicePersonalizationManagingServiceTest.java
@@ -22,6 +22,7 @@ import static com.android.adservices.shared.spe.JobServiceConstants.SCHEDULING_R
 import static com.google.common.util.concurrent.Futures.immediateVoidFuture;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
@@ -630,6 +631,18 @@ public class OnDevicePersonalizationManagingServiceTest {
         verify(mMockMdd).schedulePeriodicBackgroundTasks();
     }
 
+    @Test
+    public void testEnabledGlobalKillOnOnCreateFailFast() {
+        OnDevicePersonalizationManagingServiceImpl service =
+                new OnDevicePersonalizationManagingServiceImpl(Runnable::run);
+        when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
+        service.onCreate();
+        Intent serviceIntent =
+                new Intent(mContext, OnDevicePersonalizationManagingServiceImpl.class);
+        IBinder binder = service.onBind(serviceIntent);
+        assertNull(binder);
+    }
+
     @Test
     public void testEnabledGlobalKillOnIsFeatureEnabled() {
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
index 8809e4d7..952fe11a 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/PhFlagsTest.java
@@ -18,34 +18,46 @@ package com.android.ondevicepersonalization.services;
 
 import static com.android.adservices.shared.common.flags.ModuleSharedFlags.BACKGROUND_JOB_SAMPLING_LOGGING_RATE;
 import static com.android.adservices.shared.common.flags.ModuleSharedFlags.DEFAULT_JOB_SCHEDULING_LOGGING_SAMPLING_RATE;
+import static com.android.adservices.shared.common.flags.ModuleSharedFlags.DEFAULT_SPE_ENABLE_PER_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.Flags.APP_REQUEST_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORTING_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORTING_THRESHOLD;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORTING_URL_PATH;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATED_ERROR_REPORT_TTL_DAYS;
-import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_APP_INSTALL_HISTORY_TTL_MILLIS;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_CALLER_APP_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_CLIENT_ERROR_LOGGING_ENABLED;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_DOWNLOAD_PROCESSING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_DOWNLOAD_REJECT_CAP_IN_MB;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ENCRYPTION_KEY_MAX_AGE_SECONDS;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ENCRYPTION_KEY_URL;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ISOLATED_SERVICE_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_IS_FEATURE_ENABLED_API_ENABLED;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_MAINTENANCE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_MDD_CELLULAR_CHARGING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_MDD_CHARGING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_MDD_MAINTENANCE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_MDD_WIFI_CHARGING_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
-import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_MODULE_JOB_POLICY;
-import static com.android.ondevicepersonalization.services.Flags.DEFAULT_OUTPUT_DATA_ALLOW_LIST;
-import static com.android.ondevicepersonalization.services.Flags.DEFAULT_PLUGIN_PROCESS_RUNNER_ENABLED;
-import static com.android.ondevicepersonalization.services.Flags.DEFAULT_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_ODP_MODULE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_OUTPUT_DATA_ALLOW_LIST;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_PLUGIN_PROCESS_RUNNER_ENABLED;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_RESET_DATA_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_SPE_PILOT_JOB_ENABLED;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_STORAGE_CAP_IN_MB;
 import static com.android.ondevicepersonalization.services.Flags.DEFAULT_TRUSTED_PARTNER_APPS_LIST;
+import static com.android.ondevicepersonalization.services.Flags.DEFAULT_USER_DATA_COLLECTION_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.Flags.DOWNLOAD_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.Flags.ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
 import static com.android.ondevicepersonalization.services.Flags.EXAMPLE_STORE_FLOW_DEADLINE_SECONDS;
@@ -60,15 +72,19 @@ import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AD
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_INTERVAL_HOURS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_PATH;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORTING_THRESHOLD;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATED_ERROR_REPORT_TTL_DAYS;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_APP_REQUEST_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_CALLER_APP_ALLOW_LIST;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_DOWNLOAD_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_DOWNLOAD_PROCESSING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_DOWNLOAD_REJECT_CAP_IN_MB;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_AGGREGATED_ERROR_REPORTING;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENABLE_PER_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENCRYPTION_KEY_MAX_AGE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ENCRYPTION_KEY_URL;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_EXAMPLE_STORE_FLOW_DEADLINE_SECONDS;
@@ -77,6 +93,16 @@ import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ISOLATED_SERVICE_DEBUGGING_ENABLED;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_ART_IMAGE_LOADING_OPTIMIZATION_ENABLED;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_IS_FEATURE_ENABLED_API_ENABLED;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MAINTENANCE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MDD_CELLULAR_CHARGING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MDD_CHARGING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MDD_MAINTENANCE_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_MDD_WIFI_CHARGING_JOB_POLICY;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOB_SAMPLING_LOGGING_RATE;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_JOB_SCHEDULING_LOGGING_ENABLED;
@@ -87,13 +113,11 @@ import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_OU
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_PLUGIN_PROCESS_RUNNER_ENABLED;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RENDER_FLOW_DEADLINE_SECONDS;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_RESET_DATA_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB;
-import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_STORAGE_CAP_IN_MB;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_TRUSTED_PARTNER_APPS_LIST;
+import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_USER_DATA_COLLECTION_JOB_POLICY;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_WEB_TRIGGER_FLOW_DEADLINE_SECONDS;
 import static com.android.ondevicepersonalization.services.FlagsConstants.KEY_WEB_VIEW_FLOW_DEADLINE_SECONDS;
 
@@ -107,7 +131,6 @@ import com.android.modules.utils.build.SdkLevel;
 import com.android.modules.utils.testing.TestableDeviceConfig;
 
 import org.junit.Before;
-import org.junit.Ignore;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
@@ -116,15 +139,12 @@ import java.util.function.Supplier;
 
 /** Unit tests for {@link com.android.ondevicepersonalization.services.PhFlags} */
 @RunWith(AndroidJUnit4.class)
-@Ignore("b/375661140")
 public class PhFlagsTest {
     @Rule
     public final TestableDeviceConfig.TestableDeviceConfigRule mDeviceConfigRule =
             new TestableDeviceConfig.TestableDeviceConfigRule();
 
-    /**
-     * Get necessary permissions to access Setting.Config API and set up context
-     */
+    /** Get necessary permissions to access Setting.Config API and set up context */
     @Before
     public void setUpContext() throws Exception {
         PhFlagsTestUtil.setUpDeviceConfigPermissions();
@@ -160,8 +180,8 @@ public class PhFlagsTest {
                 KEY_ENABLE_PERSONALIZATION_STATUS_OVERRIDE,
                 Boolean.toString(ENABLE_PERSONALIZATION_STATUS_OVERRIDE),
                 /* makeDefault */ false);
-        assertThat(FlagsFactory.getFlags().isPersonalizationStatusOverrideEnabled()).isEqualTo(
-                ENABLE_PERSONALIZATION_STATUS_OVERRIDE);
+        assertThat(FlagsFactory.getFlags().isPersonalizationStatusOverrideEnabled())
+                .isEqualTo(ENABLE_PERSONALIZATION_STATUS_OVERRIDE);
 
         final boolean phOverridingValue = true;
         DeviceConfig.setProperty(
@@ -182,8 +202,8 @@ public class PhFlagsTest {
                 KEY_PERSONALIZATION_STATUS_OVERRIDE_VALUE,
                 Boolean.toString(PERSONALIZATION_STATUS_OVERRIDE_VALUE),
                 /* makeDefault */ false);
-        assertThat(FlagsFactory.getFlags().getPersonalizationStatusOverrideValue()).isEqualTo(
-                PERSONALIZATION_STATUS_OVERRIDE_VALUE);
+        assertThat(FlagsFactory.getFlags().getPersonalizationStatusOverrideValue())
+                .isEqualTo(PERSONALIZATION_STATUS_OVERRIDE_VALUE);
 
         final boolean phOverridingValue = true;
         DeviceConfig.setProperty(
@@ -255,8 +275,7 @@ public class PhFlagsTest {
                 String.valueOf(test_deadline),
                 /* makeDefault */ false);
 
-        assertThat(FlagsFactory.getFlags().getRenderFlowDeadlineSeconds())
-                .isEqualTo(test_deadline);
+        assertThat(FlagsFactory.getFlags().getRenderFlowDeadlineSeconds()).isEqualTo(test_deadline);
 
         DeviceConfig.setProperty(
                 DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
@@ -346,8 +365,7 @@ public class PhFlagsTest {
             assertThat(FlagsFactory.getFlags().getTrustedPartnerAppsList())
                     .isEqualTo(DEFAULT_TRUSTED_PARTNER_APPS_LIST);
         } else {
-            assertThat(FlagsFactory.getFlags().getTrustedPartnerAppsList())
-                    .isEqualTo("");
+            assertThat(FlagsFactory.getFlags().getTrustedPartnerAppsList()).isEqualTo("");
         }
 
         final String testTrustedPartnerAppsList =
@@ -363,8 +381,7 @@ public class PhFlagsTest {
             assertThat(FlagsFactory.getFlags().getTrustedPartnerAppsList())
                     .isEqualTo(testTrustedPartnerAppsList);
         } else {
-            assertThat(FlagsFactory.getFlags().getTrustedPartnerAppsList())
-                    .isEqualTo("");
+            assertThat(FlagsFactory.getFlags().getTrustedPartnerAppsList()).isEqualTo("");
         }
     }
 
@@ -380,8 +397,7 @@ public class PhFlagsTest {
             assertThat(FlagsFactory.getFlags().isSharedIsolatedProcessFeatureEnabled())
                     .isEqualTo(DEFAULT_SHARED_ISOLATED_PROCESS_FEATURE_ENABLED);
         } else {
-            assertThat(FlagsFactory.getFlags().isSharedIsolatedProcessFeatureEnabled())
-                    .isFalse();
+            assertThat(FlagsFactory.getFlags().isSharedIsolatedProcessFeatureEnabled()).isFalse();
         }
 
         final boolean testIsolatedProcessFeatureEnabled =
@@ -397,8 +413,7 @@ public class PhFlagsTest {
             assertThat(FlagsFactory.getFlags().isSharedIsolatedProcessFeatureEnabled())
                     .isEqualTo(testIsolatedProcessFeatureEnabled);
         } else {
-            assertThat(FlagsFactory.getFlags().isSharedIsolatedProcessFeatureEnabled())
-                    .isFalse();
+            assertThat(FlagsFactory.getFlags().isSharedIsolatedProcessFeatureEnabled()).isFalse();
         }
     }
 
@@ -413,8 +428,7 @@ public class PhFlagsTest {
         assertThat(FlagsFactory.getFlags().getCallerAppAllowList())
                 .isEqualTo(DEFAULT_CALLER_APP_ALLOW_LIST);
 
-        final String testCallerAppAllowList =
-                "com.example.odpclient";
+        final String testCallerAppAllowList = "com.example.odpclient";
 
         DeviceConfig.setProperty(
                 DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
@@ -434,8 +448,7 @@ public class PhFlagsTest {
                 Boolean.toString(false),
                 /* makeDefault */ false);
 
-        assertThat(FlagsFactory.getFlags().isIsolatedServiceDebuggingEnabled())
-                .isEqualTo(false);
+        assertThat(FlagsFactory.getFlags().isIsolatedServiceDebuggingEnabled()).isEqualTo(false);
 
         DeviceConfig.setProperty(
                 DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
@@ -443,8 +456,7 @@ public class PhFlagsTest {
                 Boolean.toString(true),
                 /* makeDefault */ false);
 
-        assertThat(FlagsFactory.getFlags().isIsolatedServiceDebuggingEnabled())
-                .isEqualTo(true);
+        assertThat(FlagsFactory.getFlags().isIsolatedServiceDebuggingEnabled()).isEqualTo(true);
     }
 
     @Test
@@ -481,8 +493,7 @@ public class PhFlagsTest {
         assertThat(FlagsFactory.getFlags().getIsolatedServiceAllowList())
                 .isEqualTo(DEFAULT_ISOLATED_SERVICE_ALLOW_LIST);
 
-        final String testIsolatedServiceAllowList =
-                "com.example.odpsamplenetwork";
+        final String testIsolatedServiceAllowList = "com.example.odpsamplenetwork";
 
         DeviceConfig.setProperty(
                 DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
@@ -505,8 +516,7 @@ public class PhFlagsTest {
         assertThat(FlagsFactory.getFlags().getOutputDataAllowList())
                 .isEqualTo(DEFAULT_OUTPUT_DATA_ALLOW_LIST);
 
-        final String testOutputDataAllowList =
-                "com.example.odpclient;com.example.odpsamplenetwork";
+        final String testOutputDataAllowList = "com.example.odpclient;com.example.odpsamplenetwork";
 
         DeviceConfig.setProperty(
                 DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
@@ -535,14 +545,12 @@ public class PhFlagsTest {
                 KEY_ODP_ENABLE_CLIENT_ERROR_LOGGING,
                 Boolean.toString(overrideEnable),
                 /* makeDefault= */ false);
-        assertThat(FlagsFactory.getFlags().getEnableClientErrorLogging())
-                .isEqualTo(overrideEnable);
+        assertThat(FlagsFactory.getFlags().getEnableClientErrorLogging()).isEqualTo(overrideEnable);
     }
 
     @Test
     public void testGetBackgroundJobsLoggingEnabled() {
-        assertThat(FlagsFactory.getFlags().getBackgroundJobsLoggingEnabled())
-                .isEqualTo(true);
+        assertThat(FlagsFactory.getFlags().getBackgroundJobsLoggingEnabled()).isEqualTo(true);
     }
 
     @Test
@@ -609,56 +617,50 @@ public class PhFlagsTest {
 
     @Test
     public void testGetSpePilotJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpePilotJobEnabled(),
                 KEY_ODP_SPE_PILOT_JOB_ENABLED,
-                DEFAULT_SPE_PILOT_JOB_ENABLED
-        );
+                DEFAULT_SPE_PILOT_JOB_ENABLED);
     }
 
     @Test
     public void testGetSpeOnAggregateErrorDataReportingJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpeOnAggregateErrorDataReportingJobEnabled(),
                 KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB,
-                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB
-        );
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_AGGREGATE_ERROR_DATA_REPORTING_JOB);
     }
 
     @Test
     public void testGetSpeOnMddJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpeOnMddJobEnabled(),
                 KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB,
-                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB
-        );
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_MDD_JOB);
     }
 
     @Test
     public void testGetSpeOnOdpDownloadProcessingJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpeOnOdpDownloadProcessingJobEnabled(),
                 KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB,
-                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB
-        );
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_ODP_DOWNLOAD_PROCESSING_JOB);
     }
 
     @Test
     public void testGetSpeOnResetDataJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpeOnResetDataJobEnabled(),
                 KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB,
-                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB
-        );
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_RESET_DATA_JOB);
     }
 
     @Test
     public void testGetSpeOnUserDataCollectionJobEnabled() {
-        assertSpeFeatureFlags(
+        assertBooleanFeatureFlags(
                 () -> FlagsFactory.getFlags().getSpeOnUserDataCollectionJobEnabled(),
                 KEY_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB,
-                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB
-        );
+                DEFAULT_ODP_BACKGROUND_JOBS__ENABLE_SPE_ON_USER_DATA_COLLECTION_JOB);
     }
 
     @Test
@@ -746,6 +748,30 @@ public class PhFlagsTest {
                 .isEqualTo(DEFAULT_AGGREGATED_ERROR_REPORTING_URL_PATH);
     }
 
+    @Test
+    public void testAggregateErrorReportingOverrideUrl() {
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingServerOverrideUrl())
+                .isEmpty();
+        String testValue = "foo/bar";
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL,
+                testValue,
+                /* makeDefault */ false);
+
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingServerOverrideUrl())
+                .isEqualTo(testValue);
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL,
+                DEFAULT_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL,
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingServerOverrideUrl())
+                .isEqualTo(DEFAULT_AGGREGATED_ERROR_REPORTING_OVERRIDE_URL);
+    }
+
     @Test
     public void testAggregateErrorReportingThreshold() {
         int testValue = 5;
@@ -791,24 +817,9 @@ public class PhFlagsTest {
 
     @Test
     public void testAllowUnencryptedAggregatedErrorReportingPayload() {
-        boolean testValue = !DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD;
-
-        DeviceConfig.setProperty(
-                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
-                KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING,
-                Boolean.toString(testValue),
-                /* makeDefault */ false);
-
+        // Test that by default encryption is enabled
         assertThat(FlagsFactory.getFlags().getAllowUnencryptedAggregatedErrorReportingPayload())
-                .isEqualTo(testValue);
-
-        DeviceConfig.setProperty(
-                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
-                KEY_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING,
-                Boolean.toString(DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD),
-                /* makeDefault */ false);
-        assertThat(FlagsFactory.getFlags().getAllowUnencryptedAggregatedErrorReportingPayload())
-                .isEqualTo(DEFAULT_ALLOW_UNENCRYPTED_AGGREGATED_ERROR_REPORTING_PAYLOAD);
+                .isFalse();
     }
 
     @Test
@@ -829,7 +840,7 @@ public class PhFlagsTest {
                 KEY_AGGREGATED_ERROR_REPORTING_HTTP_TIMEOUT_SECONDS,
                 Integer.toString(DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS),
                 /* makeDefault */ false);
-        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingIntervalInHours())
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingHttpTimeoutSeconds())
                 .isEqualTo(DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_TIMEOUT_SECONDS);
     }
 
@@ -851,7 +862,7 @@ public class PhFlagsTest {
                 KEY_AGGREGATED_ERROR_REPORTING_HTTP_RETRY_LIMIT,
                 Integer.toString(DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT),
                 /* makeDefault */ false);
-        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingIntervalInHours())
+        assertThat(FlagsFactory.getFlags().getAggregatedErrorReportingHttpRetryLimit())
                 .isEqualTo(DEFAULT_AGGREGATED_ERROR_REPORT_HTTP_RETRY_LIMIT);
     }
 
@@ -919,6 +930,48 @@ public class PhFlagsTest {
                 .isEqualTo(DEFAULT_ADSERVICES_IPC_CALL_TIMEOUT_IN_MILLIS);
     }
 
+    @Test
+    public void testGetDefaultDownloadRejectCapInMb() {
+        long testDownloadRejectCap = 100L;
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_DOWNLOAD_REJECT_CAP_IN_MB,
+                Long.toString(testDownloadRejectCap),
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getDefaultDownloadRejectCapInMb())
+                .isEqualTo(testDownloadRejectCap);
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_DOWNLOAD_REJECT_CAP_IN_MB,
+                Long.toString(DEFAULT_DOWNLOAD_REJECT_CAP_IN_MB),
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getDefaultDownloadRejectCapInMb())
+                .isEqualTo(DEFAULT_DOWNLOAD_REJECT_CAP_IN_MB);
+    }
+
+    @Test
+    public void testGetDefaultStorageCapInMb() {
+        long testStorageCap = 100L;
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_STORAGE_CAP_IN_MB,
+                Long.toString(testStorageCap),
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getDefaultStorageCapInMb())
+                .isEqualTo(testStorageCap);
+
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                KEY_STORAGE_CAP_IN_MB,
+                Long.toString(DEFAULT_STORAGE_CAP_IN_MB),
+                /* makeDefault */ false);
+        assertThat(FlagsFactory.getFlags().getDefaultStorageCapInMb())
+                .isEqualTo(DEFAULT_STORAGE_CAP_IN_MB);
+    }
+
     @Test
     public void testIsPluginProcessRunnerEnabled() {
         // read a stable flag value and verify it's equal to the default value.
@@ -934,8 +987,8 @@ public class PhFlagsTest {
                 /* makeDefault= */ false);
 
         // the flag value remains stable
-        assertThat(FlagsFactory.getFlags().isPluginProcessRunnerEnabled()).isEqualTo(
-                overrideEnabled);
+        assertThat(FlagsFactory.getFlags().isPluginProcessRunnerEnabled())
+                .isEqualTo(overrideEnabled);
     }
 
     @Test
@@ -953,7 +1006,87 @@ public class PhFlagsTest {
         assertThat(FlagsFactory.getFlags().isFeatureEnabledApiEnabled()).isEqualTo(overrideEnabled);
     }
 
-    private void assertSpeFeatureFlags(
+    @Test
+    public void testGetEnablePerJobPolicy() {
+        assertBooleanFeatureFlags(
+                () -> FlagsFactory.getFlags().getSpeEnablePerJobPolicy(),
+                KEY_ENABLE_PER_JOB_POLICY,
+                DEFAULT_SPE_ENABLE_PER_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetMddMaintenanceJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getMddMaintenanceJobPolicy(),
+                KEY_MDD_MAINTENANCE_JOB_POLICY,
+                DEFAULT_MDD_MAINTENANCE_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetMddChargingJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getMddChargingJobPolicy(),
+                KEY_MDD_CHARGING_JOB_POLICY,
+                DEFAULT_MDD_CHARGING_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetMddCellularChargingJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getMddCellularChargingJobPolicy(),
+                KEY_MDD_CELLULAR_CHARGING_JOB_POLICY,
+                DEFAULT_MDD_CELLULAR_CHARGING_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetMddWifiChargingJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getMddWifiChargingJobPolicy(),
+                KEY_MDD_WIFI_CHARGING_JOB_POLICY,
+                DEFAULT_MDD_WIFI_CHARGING_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetDownloadProcessingJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getDownloadProcessingJobPolicy(),
+                KEY_DOWNLOAD_PROCESSING_JOB_POLICY,
+                DEFAULT_DOWNLOAD_PROCESSING_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetMaintenanceJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getMaintenanceJobPolicy(),
+                KEY_MAINTENANCE_JOB_POLICY,
+                DEFAULT_MAINTENANCE_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetUserDataCollectionJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getUserDataCollectionJobPolicy(),
+                KEY_USER_DATA_COLLECTION_JOB_POLICY,
+                DEFAULT_USER_DATA_COLLECTION_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetResetDataJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getResetDataJobPolicy(),
+                KEY_RESET_DATA_JOB_POLICY,
+                DEFAULT_RESET_DATA_JOB_POLICY);
+    }
+
+    @Test
+    public void testGetAggregateErrorDataReportingJobPolicy() {
+        assertStringFeatureFlags(
+                () -> FlagsFactory.getFlags().getAggregateErrorDataReportingJobPolicy(),
+                KEY_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY,
+                DEFAULT_AGGREGATE_ERROR_DATA_REPORTING_JOB_POLICY);
+    }
+
+    private void assertBooleanFeatureFlags(
             Supplier<Boolean> flagSupplier, String flagName, boolean defaultValue) {
         // Test override value
         boolean overrideValue = !defaultValue;
@@ -972,4 +1105,24 @@ public class PhFlagsTest {
                 /* makeDefault */ false);
         assertThat(flagSupplier.get()).isEqualTo(defaultValue);
     }
+
+    private void assertStringFeatureFlags(
+            Supplier<String> flagSupplier, String flagName, String defaultValue) {
+        // Test override value
+        String overrideValue = "" + "_test_value";
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                flagName,
+                overrideValue,
+                /* makeDefault */ false);
+        assertThat(flagSupplier.get()).isEqualTo(overrideValue);
+
+        // Test default value
+        DeviceConfig.setProperty(
+                DeviceConfig.NAMESPACE_ON_DEVICE_PERSONALIZATION,
+                flagName,
+                defaultValue,
+                /* makeDefault */ false);
+        assertThat(flagSupplier.get()).isEqualTo(defaultValue);
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJobTest.java
index 40eb693c..7656b386 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJobTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregateErrorDataReportingJobTest.java
@@ -26,6 +26,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.AGGREGATE_ERROR_DATA_REPORTING_JOB_ID;
 
+import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 
 import static org.mockito.ArgumentMatchers.any;
@@ -81,18 +82,12 @@ public class AggregateErrorDataReportingJobTest {
     private static final Context sContext = ApplicationProvider.getApplicationContext();
 
     private AggregateErrorDataReportingJob mSpyAggregateErrorDataReportingJob;
-    @Mock
-    private Flags mMockFlags;
-    @Mock
-    private ExecutionRuntimeParameters mMockParams;
-    @Mock
-    private OdpJobScheduler mMockOdpJobScheduler;
-    @Mock
-    private OdpJobServiceFactory mMockOdpJobServiceFactory;
-    @Mock
-    private AggregatedErrorReportingWorker mMockReportingWorker;
-    @Mock
-    private OdpEncryptionKeyManager mMockEncryptionKeyManager;
+    @Mock private Flags mMockFlags;
+    @Mock private ExecutionRuntimeParameters mMockParams;
+    @Mock private OdpJobScheduler mMockOdpJobScheduler;
+    @Mock private OdpJobServiceFactory mMockOdpJobServiceFactory;
+    @Mock private AggregatedErrorReportingWorker mMockReportingWorker;
+    @Mock private OdpEncryptionKeyManager mMockEncryptionKeyManager;
 
     @Before
     public void setup() throws Exception {
@@ -121,8 +116,7 @@ public class AggregateErrorDataReportingJobTest {
 
     @Test
     public void testGetExecutionFuture_encryptedFlow() throws Exception {
-        when(mMockFlags.getAllowUnencryptedAggregatedErrorReportingPayload())
-                .thenReturn(false);
+        when(mMockFlags.getAllowUnencryptedAggregatedErrorReportingPayload()).thenReturn(false);
         when(mMockReportingWorker.reportAggregateErrors(any(), any()))
                 .thenReturn(Futures.immediateVoidFuture());
         when(mMockEncryptionKeyManager.fetchAndPersistActiveKeys(anyInt(), anyBoolean(), any()))
@@ -184,16 +178,21 @@ public class AggregateErrorDataReportingJobTest {
 
         JobSchedulingLogger loggerMock = mock(JobSchedulingLogger.class);
         when(mMockOdpJobServiceFactory.getJobSchedulingLogger()).thenReturn(loggerMock);
-        doReturn(resultCode).when(() -> AggregateErrorDataReportingService
-                .scheduleIfNeeded(any(), /* forceSchedule */ eq(false)));
+        doReturn(resultCode)
+                .when(
+                        () ->
+                                AggregateErrorDataReportingService.scheduleIfNeeded(
+                                        any(), /* forceSchedule */ eq(false)));
 
         AggregateErrorDataReportingJob.schedule(sContext);
 
         verify(mMockOdpJobScheduler, never()).schedule(eq(sContext), any());
-        verify(() -> AggregateErrorDataReportingService
-                .scheduleIfNeeded(any(), /* forceSchedule */ eq(false)));
-        verify(loggerMock).recordOnSchedulingLegacy(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID,
-                resultCode);
+        verify(
+                () ->
+                        AggregateErrorDataReportingService.scheduleIfNeeded(
+                                any(), /* forceSchedule */ eq(false)));
+        verify(loggerMock)
+                .recordOnSchedulingLegacy(AGGREGATE_ERROR_DATA_REPORTING_JOB_ID, resultCode);
     }
 
     @Test
@@ -206,10 +205,13 @@ public class AggregateErrorDataReportingJobTest {
                         .setRequireStorageNotLow(true)
                         .setNetworkType(NETWORK_TYPE_UNMETERED)
                         .setPeriodicJobParams(
-                                JobPolicy.PeriodicJobParams.newBuilder().setPeriodicIntervalMs(
-                                        mMockFlags.getAggregatedErrorReportingIntervalInHours()
-                                                * 1000L * 3600L
-                                        ).build())
+                                JobPolicy.PeriodicJobParams.newBuilder()
+                                        .setPeriodicIntervalMs(
+                                                mMockFlags
+                                                                .getAggregatedErrorReportingIntervalInHours()
+                                                        * 1000L
+                                                        * 3600L)
+                                        .build())
                         .setIsPersisted(true)
                         .build();
 
@@ -228,6 +230,16 @@ public class AggregateErrorDataReportingJobTest {
                 .isEqualTo(expectedBackoffPolicy);
     }
 
+    @Test
+    public void testGetJobPolicyString() {
+        String testPolicyString = "test_string";
+
+        when(mMockFlags.getAggregateErrorDataReportingJobPolicy()).thenReturn(testPolicyString);
+
+        assertThat(mSpyAggregateErrorDataReportingJob.getJobPolicyString(/* jobId= */ 0))
+                .isEqualTo(testPolicyString);
+    }
+
     public class TestInjector extends AggregateErrorDataReportingJob.Injector {
         @Override
         ListeningExecutorService getExecutor() {
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java
index 7f132a79..0028d733 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/errors/AggregatedErrorReportingWorkerTest.java
@@ -27,7 +27,6 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
@@ -56,18 +55,20 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.junit.runners.JUnit4;
+import org.junit.runners.Parameterized;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 import org.mockito.quality.Strictness;
 
+import java.util.Arrays;
+import java.util.Collection;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.TimeoutException;
 import java.util.concurrent.atomic.AtomicInteger;
 
-@RunWith(JUnit4.class)
+@RunWith(Parameterized.class)
 @ExtendedMockitoRule.MockStatic(PackageUtils.class)
 @ExtendedMockitoRule.MockStatic(AppManifestConfigHelper.class)
 public class AggregatedErrorReportingWorkerTest {
@@ -76,6 +77,8 @@ public class AggregatedErrorReportingWorkerTest {
     private static final String TEST_CLASS = "test_class";
     private static final String TEST_SERVER_URL = "https://google.com";
 
+    private static final String TEST_OVERRIDE_URL = "https://foo.com";
+
     private static final ComponentName TEST_COMPONENT_NAME =
             new ComponentName(TEST_PACKAGE, TEST_CLASS);
 
@@ -91,6 +94,14 @@ public class AggregatedErrorReportingWorkerTest {
 
     private static final ImmutableList<ComponentName> EMPTY_ODP_SERVICE_LIST = ImmutableList.of();
 
+    @Parameterized.Parameter(0)
+    public boolean mUsedOverrideUrl = true;
+
+    @Parameterized.Parameters
+    public static Collection<Object[]> data() {
+        return Arrays.asList(new Object[][] {{false}, {true}});
+    }
+
     private final Context mContext = ApplicationProvider.getApplicationContext();
 
     private final OnDevicePersonalizationAggregatedErrorDataDao mErrorDataDao =
@@ -136,7 +147,11 @@ public class AggregatedErrorReportingWorkerTest {
 
         // Inject a test ReportingProtocol object and a mock metadata store.
         mTestReportingProtocol = new TestReportingProtocol();
-        mTestInjector = new TestInjector(mTestReportingProtocol, mMockMetadataStore);
+        mTestInjector =
+                mUsedOverrideUrl
+                        ? new TestInjector(
+                                mTestReportingProtocol, mMockMetadataStore, TEST_OVERRIDE_URL)
+                        : new TestInjector(mTestReportingProtocol, mMockMetadataStore);
         mInstanceUnderTest = AggregatedErrorReportingWorker.createWorker(mTestInjector);
     }
 
@@ -187,7 +202,8 @@ public class AggregatedErrorReportingWorkerTest {
 
         assertTrue(returnedFuture.isDone());
         assertEquals(1, mTestInjector.mCallCount.get());
-        assertEquals(TEST_SERVER_URL, mTestInjector.mRequestUri);
+        assertEquals(
+                mUsedOverrideUrl ? TEST_OVERRIDE_URL : TEST_SERVER_URL, mTestInjector.mRequestUri);
         assertEquals(getExpectedErrorData(mDayIndexUtc), mTestInjector.mErrorData.get(0));
         assertEquals(1, mTestReportingProtocol.mCallCount.get());
         assertThat(mTestReportingProtocol.mOdpEncryptionKey).isSameInstanceAs(mMockEncryptionKey);
@@ -252,7 +268,8 @@ public class AggregatedErrorReportingWorkerTest {
 
         assertTrue(returnedFuture.isDone());
         assertEquals(1, mTestInjector.mCallCount.get());
-        assertEquals(TEST_SERVER_URL, mTestInjector.mRequestUri);
+        assertEquals(
+                mUsedOverrideUrl ? TEST_OVERRIDE_URL : TEST_SERVER_URL, mTestInjector.mRequestUri);
         assertEquals(getExpectedErrorData(mDayIndexUtc), mTestInjector.mErrorData.get(0));
         assertEquals(1, mTestReportingProtocol.mCallCount.get());
     }
@@ -296,10 +313,12 @@ public class AggregatedErrorReportingWorkerTest {
     }
 
     private static final class TestInjector extends AggregatedErrorReportingWorker.Injector {
+        // Immutable state provided by test setup
         private final ReportingProtocol mTestProtocol;
-
         private final ErrorReportingMetadataStore mStore;
+        private final String mOverrideUrl;
 
+        // Mutable state used by test for assertions
         private String mRequestUri;
         private ImmutableList<ErrorData> mErrorData;
         private final AtomicInteger mCallCount = new AtomicInteger(0);
@@ -307,8 +326,16 @@ public class AggregatedErrorReportingWorkerTest {
         TestInjector(
                 ReportingProtocol testProtocol,
                 ErrorReportingMetadataStore errorReportingMetadataStore) {
+            this(testProtocol, errorReportingMetadataStore, /* overrideUrl= */ "");
+        }
+
+        TestInjector(
+                ReportingProtocol testProtocol,
+                ErrorReportingMetadataStore errorReportingMetadataStore,
+                String overrideUrl) {
             this.mTestProtocol = testProtocol;
             this.mStore = errorReportingMetadataStore;
+            this.mOverrideUrl = overrideUrl;
         }
 
         @Override
@@ -337,6 +364,11 @@ public class AggregatedErrorReportingWorkerTest {
             return TEST_SERVER_URL;
         }
 
+        @Override
+        String getErrorReportingServerOverrideUrl() {
+            return mOverrideUrl;
+        }
+
         @Override
         long getErrorReportingIntervalHours() {
             return DEFAULT_REPORTING_INTERVAL_HOURS;
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobTest.java
index e1145d27..e0135ef4 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/data/user/UserDataCollectionJobTest.java
@@ -27,6 +27,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.modules.utils.testing.ExtendedMockitoRule.MockStatic;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.USER_DATA_COLLECTION_ID;
 
+import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 
 import static org.mockito.ArgumentMatchers.any;
@@ -217,11 +218,22 @@ public final class UserDataCollectionJobTest {
                 .isEqualTo(expectedBackoffPolicy);
     }
 
+    @Test
+    public void testGetJobPolicyString() {
+        String testPolicyString = "test_string";
+
+        when(mMockFlags.getUserDataCollectionJobPolicy()).thenReturn(testPolicyString);
+
+        assertThat(mSpyUserDataCollectionJob.getJobPolicyString(/* jobId= */ 0))
+                .isEqualTo(testPolicyString);
+    }
+
     public class TestInjector extends UserDataCollectionJob.Injector {
         @Override
         ListeningExecutorService getExecutor() {
             return MoreExecutors.newDirectExecutorService();
         }
+
         @Override
         Flags getFlags() {
             return mMockFlags;
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobTests.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobTests.java
index 779c548e..22364310 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobTests.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/OnDevicePersonalizationDownloadProcessingJobTests.java
@@ -25,6 +25,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.DOWNLOAD_PROCESSING_TASK_JOB_ID;
 
+import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 
 import static org.mockito.ArgumentMatchers.any;
@@ -202,4 +203,14 @@ public final class OnDevicePersonalizationDownloadProcessingJobTests {
                 .that(new OnDevicePersonalizationDownloadProcessingJob().getBackoffPolicy())
                 .isEqualTo(expectedBackoffPolicy);
     }
+
+    @Test
+    public void testGetJobPolicyString() {
+        String testPolicyString = "test_string";
+
+        when(mMockFlags.getDownloadProcessingJobPolicy()).thenReturn(testPolicyString);
+
+        assertThat(mSpyOdpDownloadProcessingJob.getJobPolicyString(/* jobId= */ 0))
+                .isEqualTo(testPolicyString);
+    }
 }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobTest.java
index ac7736f1..50b73f40 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/MddJobTest.java
@@ -21,9 +21,14 @@ import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_
 import static com.android.adservices.shared.spe.JobServiceConstants.JOB_ENABLED_STATUS_ENABLED;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_CHARGING_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID;
+import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID;
 
 import static com.google.android.libraries.mobiledatadownload.TaskScheduler.CHARGING_PERIODIC_TASK;
 import static com.google.android.libraries.mobiledatadownload.TaskScheduler.WIFI_CHARGING_PERIODIC_TASK;
+import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 import static com.google.common.util.concurrent.Futures.immediateVoidFuture;
 
@@ -73,18 +78,12 @@ public final class MddJobTest {
     private static final Context sContext = ApplicationProvider.getApplicationContext();
 
     private MddJob mMddJobChargingPeriodic;
-    @Mock
-    private Flags mMockFlags;
-    @Mock
-    private UserPrivacyStatus mMockUserPrivacyStatus;
-    @Mock
-    private MobileDataDownload mMockMobileDataDownload;
-    @Mock
-    private ExecutionRuntimeParameters mMockParams;
-    @Mock
-    private OdpJobScheduler mMockOdpJobScheduler;
-    @Mock
-    private OdpJobServiceFactory mMockOdpJobServiceFactory;
+    @Mock private Flags mMockFlags;
+    @Mock private UserPrivacyStatus mMockUserPrivacyStatus;
+    @Mock private MobileDataDownload mMockMobileDataDownload;
+    @Mock private ExecutionRuntimeParameters mMockParams;
+    @Mock private OdpJobScheduler mMockOdpJobScheduler;
+    @Mock private OdpJobServiceFactory mMockOdpJobServiceFactory;
 
     @Before
     public void setup() throws Exception {
@@ -102,8 +101,7 @@ public final class MddJobTest {
         ListenableFuture<ExecutionResult> executionFuture =
                 mMddJobChargingPeriodic.getExecutionFuture(sContext, mMockParams);
 
-        assertWithMessage(
-                "testGetExecutionFuture_executionSuccess()")
+        assertWithMessage("testGetExecutionFuture_executionSuccess()")
                 .that(executionFuture.get())
                 .isEqualTo(ExecutionResult.SUCCESS);
         verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()), never());
@@ -115,8 +113,7 @@ public final class MddJobTest {
         ListenableFuture<ExecutionResult> executionFuture =
                 mddWifiChargingPeriodicJob.getExecutionFuture(sContext, mMockParams);
 
-        assertWithMessage(
-                "testGetExecutionFuture_wifiChargingPeriodic_scheduleDownloadJob()")
+        assertWithMessage("testGetExecutionFuture_wifiChargingPeriodic_scheduleDownloadJob()")
                 .that(executionFuture.get())
                 .isEqualTo(ExecutionResult.SUCCESS);
         verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()));
@@ -129,7 +126,7 @@ public final class MddJobTest {
                 mMddJobChargingPeriodic.getExecutionStopFuture(sContext, mMockParams);
 
         assertWithMessage(
-                "testGetExecutionStopFuture_notWifiChargingPeriodic_dontScheduleDownloadJob()")
+                        "testGetExecutionStopFuture_notWifiChargingPeriodic_dontScheduleDownloadJob()")
                 .that(executionFuture.get())
                 .isNull();
         verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()), never());
@@ -142,8 +139,7 @@ public final class MddJobTest {
         ListenableFuture<Void> executionFuture =
                 mddWifiChargingPeriodicJob.getExecutionStopFuture(sContext, mMockParams);
 
-        assertWithMessage(
-                "testGetExecutionStopFuture_wifiChargingPeriodic_scheduleDownloadJob()")
+        assertWithMessage("testGetExecutionStopFuture_wifiChargingPeriodic_scheduleDownloadJob()")
                 .that(executionFuture.get())
                 .isNull();
         verify(() -> OnDevicePersonalizationDownloadProcessingJob.schedule(any()));
@@ -153,8 +149,8 @@ public final class MddJobTest {
     public void testGetJobEnablementStatus_enabled() {
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
         when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
-        when(mMockUserPrivacyStatus
-                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+        when(mMockUserPrivacyStatus.isProtectedAudienceAndMeasurementBothDisabled())
+                .thenReturn(false);
 
         assertWithMessage("testGetJobEnablementStatus_enabled()")
                 .that(mMddJobChargingPeriodic.getJobEnablementStatus())
@@ -165,8 +161,8 @@ public final class MddJobTest {
     public void testGetJobEnablementStatus_disabled_globalKillSwitch() {
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(true);
         when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
-        when(mMockUserPrivacyStatus
-                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+        when(mMockUserPrivacyStatus.isProtectedAudienceAndMeasurementBothDisabled())
+                .thenReturn(false);
 
         assertWithMessage("testGetJobEnablementStatus_disabled_globalKillSwitch()")
                 .that(mMddJobChargingPeriodic.getJobEnablementStatus())
@@ -177,8 +173,8 @@ public final class MddJobTest {
     public void testGetJobEnablementStatus_disabled_speOff() {
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
         when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(false);
-        when(mMockUserPrivacyStatus
-                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(false);
+        when(mMockUserPrivacyStatus.isProtectedAudienceAndMeasurementBothDisabled())
+                .thenReturn(false);
 
         assertWithMessage("testGetJobEnablementStatus_disabled_speOff()")
                 .that(mMddJobChargingPeriodic.getJobEnablementStatus())
@@ -189,11 +185,11 @@ public final class MddJobTest {
     public void testGetJobEnablementStatus_disabled_noMeasurementNorProtectedAudienceConsent() {
         when(mMockFlags.getGlobalKillSwitch()).thenReturn(false);
         when(mMockFlags.getSpeOnMddJobEnabled()).thenReturn(true);
-        when(mMockUserPrivacyStatus
-                .isProtectedAudienceAndMeasurementBothDisabled()).thenReturn(true);
+        when(mMockUserPrivacyStatus.isProtectedAudienceAndMeasurementBothDisabled())
+                .thenReturn(true);
 
         assertWithMessage(
-                "testGetJobEnablementStatus_disabled_noMeasurementNorProtectedAudienceConsent()")
+                        "testGetJobEnablementStatus_disabled_noMeasurementNorProtectedAudienceConsent()")
                 .that(mMddJobChargingPeriodic.getJobEnablementStatus())
                 .isEqualTo(JOB_ENABLED_STATUS_DISABLED_FOR_USER_CONSENT_REVOKED);
     }
@@ -208,6 +204,36 @@ public final class MddJobTest {
                 .isEqualTo(expectedBackoffPolicy);
     }
 
+    @Test
+    public void testGetJobPolicyString() {
+        String testMddMaintenanceJobPolicyString = "mdd_maintenance_job_policy_string";
+        String testMddChargingJobPolicyString = "mdd_charging_job_policy_string";
+        String testMddCellularChargingJobPolicyString = "mdd_cellular_charging_job_policy_string";
+        String testMddWifiChargingJobPolicyString = "mdd_wifi_charging_job_policy_string";
+
+        when(mMockFlags.getMddMaintenanceJobPolicy()).thenReturn(testMddMaintenanceJobPolicyString);
+        when(mMockFlags.getMddChargingJobPolicy()).thenReturn(testMddChargingJobPolicyString);
+        when(mMockFlags.getMddCellularChargingJobPolicy())
+                .thenReturn(testMddCellularChargingJobPolicyString);
+        when(mMockFlags.getMddWifiChargingJobPolicy())
+                .thenReturn(testMddWifiChargingJobPolicyString);
+
+        assertThat(mMddJobChargingPeriodic.getJobPolicyString(MDD_MAINTENANCE_PERIODIC_TASK_JOB_ID))
+                .isEqualTo(testMddMaintenanceJobPolicyString);
+        assertThat(mMddJobChargingPeriodic.getJobPolicyString(MDD_CHARGING_PERIODIC_TASK_JOB_ID))
+                .isEqualTo(testMddChargingJobPolicyString);
+        assertThat(
+                        mMddJobChargingPeriodic.getJobPolicyString(
+                                MDD_CELLULAR_CHARGING_PERIODIC_TASK_JOB_ID))
+                .isEqualTo(testMddCellularChargingJobPolicyString);
+        assertThat(
+                        mMddJobChargingPeriodic.getJobPolicyString(
+                                MDD_WIFI_CHARGING_PERIODIC_TASK_JOB_ID))
+                .isEqualTo(testMddWifiChargingJobPolicyString);
+
+        assertThat(mMddJobChargingPeriodic.getJobPolicyString(/* jobId= */ 0)).isNull();
+    }
+
     private MddJob createWifiChargingPeriodicMddJob() {
         return new MddJob(WIFI_CHARGING_PERIODIC_TASK);
     }
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulatorTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulatorTest.java
index 1ea37c78..98b333f8 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulatorTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/download/mdd/OnDevicePersonalizationFileGroupPopulatorTest.java
@@ -32,7 +32,6 @@ import com.android.ondevicepersonalization.services.PhFlagsTestUtil;
 import com.android.ondevicepersonalization.services.data.OnDevicePersonalizationDbHelper;
 import com.android.ondevicepersonalization.services.data.vendor.OnDevicePersonalizationVendorDataDao;
 
-
 import com.google.android.libraries.mobiledatadownload.AddFileGroupRequest;
 import com.google.android.libraries.mobiledatadownload.DownloadFileGroupRequest;
 import com.google.android.libraries.mobiledatadownload.GetFileGroupsByFilterRequest;
@@ -139,11 +138,16 @@ public class OnDevicePersonalizationFileGroupPopulatorTest {
     @Test
     public void testCreateDownloadUrlOverrideManifest() throws Exception {
         ShellUtils.runShellCommand(
-                "setprop debug.ondevicepersonalization.override_download_url_package "
+                "setprop "
+                        + OnDevicePersonalizationFileGroupPopulator.OVERRIDE_DOWNLOAD_URL_PACKAGE
+                        + " "
                         + mPackageName);
         String overrideUrl = "https://google.com";
         ShellUtils.runShellCommand(
-                "setprop debug.ondevicepersonalization.override_download_url " + overrideUrl);
+                "setprop "
+                        + OnDevicePersonalizationFileGroupPopulator.OVERRIDE_DOWNLOAD_URL
+                        + " "
+                        + overrideUrl);
         String downloadUrl = OnDevicePersonalizationFileGroupPopulator.createDownloadUrl(
                 mPackageName, mContext);
         assertTrue(downloadUrl.startsWith(overrideUrl));
@@ -194,9 +198,13 @@ public class OnDevicePersonalizationFileGroupPopulatorTest {
     @After
     public void cleanup() {
         ShellUtils.runShellCommand(
-                "setprop debug.ondevicepersonalization.override_download_url_package \"\"");
+                "setprop "
+                        + OnDevicePersonalizationFileGroupPopulator.OVERRIDE_DOWNLOAD_URL_PACKAGE
+                        + " \"\"");
         ShellUtils.runShellCommand(
-                "setprop debug.ondevicepersonalization.override_download_url \"\"");
+                "setprop "
+                        + OnDevicePersonalizationFileGroupPopulator.OVERRIDE_DOWNLOAD_URL
+                        + " \"\"");
         OnDevicePersonalizationDbHelper dbHelper =
                 OnDevicePersonalizationDbHelper.getInstanceForTest(mContext);
         dbHelper.getWritableDatabase().close();
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
index 275fe9b6..e7ab85a9 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/federatedcompute/FederatedComputeServiceImplTest.java
@@ -46,6 +46,7 @@ import com.android.ondevicepersonalization.services.data.events.EventState;
 import com.android.ondevicepersonalization.services.data.events.EventsDao;
 import com.android.ondevicepersonalization.services.data.user.UserPrivacyStatus;
 import com.android.ondevicepersonalization.services.manifest.AppManifestConfigHelper;
+import com.android.ondevicepersonalization.services.util.DebugUtils;
 
 import com.google.common.util.concurrent.ListeningExecutorService;
 import com.google.common.util.concurrent.MoreExecutors;
@@ -89,7 +90,6 @@ public class FederatedComputeServiceImplTest {
     private int mErrorCode = 0;
     private boolean mOnSuccessCalled = false;
     private boolean mOnErrorCalled = false;
-    private FederatedComputeServiceImpl mServiceImpl;
     private IFederatedComputeService mServiceProxy;
     private FederatedComputeManager mMockManager;
     private ComponentName mIsolatedService;
@@ -118,7 +118,7 @@ public class FederatedComputeServiceImplTest {
                 .when(mMockManager)
                 .schedule(mRequestCapture.capture(), any(), mCallbackCapture.capture());
 
-        mServiceImpl =
+        FederatedComputeServiceImpl serviceImpl =
                 new FederatedComputeServiceImpl(
                         ComponentName.createRelative(
                                 mApplicationContext.getPackageName(),
@@ -126,7 +126,7 @@ public class FederatedComputeServiceImplTest {
                                         mApplicationContext, mApplicationContext.getPackageName())),
                         mApplicationContext,
                         mInjector);
-        mServiceProxy = IFederatedComputeService.Stub.asInterface(mServiceImpl);
+        mServiceProxy = IFederatedComputeService.Stub.asInterface(serviceImpl);
     }
 
     @Test
@@ -156,11 +156,13 @@ public class FederatedComputeServiceImplTest {
     @Test
     public void testScheduleUrlOverride() throws Exception {
         ShellUtils.runShellCommand(
-                "setprop debug.ondevicepersonalization.override_fc_server_url_package "
+                "setprop "
+                        + DebugUtils.OVERRIDE_FC_SERVER_URL_PACKAGE
+                        + " "
                         + mApplicationContext.getPackageName());
         String overrideUrl = "https://android.com";
         ShellUtils.runShellCommand(
-                "setprop debug.ondevicepersonalization.override_fc_server_url " + overrideUrl);
+                "setprop " + DebugUtils.OVERRIDE_FC_SERVER_URL + " " + overrideUrl);
 
         mServiceProxy.schedule(TEST_OPTIONS, new TestCallback());
         mCallbackCapture.getValue().onResult(null);
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImplTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImplTest.java
index e62f7834..5f15f5ec 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImplTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/inference/IsolatedModelServiceImplTest.java
@@ -184,8 +184,8 @@ public class IsolatedModelServiceImplTest {
     @Test
     public void runModelInference_invalidInputFormat() throws Exception {
         // Misconfigured inputs.
-        float[] input0 = {1.23f};
-        float[] input1 = {2.43f};
+        float input0 = 1.23f;
+        float input1 = 2.43f;
         Object[] invalidInput = {input0, input1, input0};
 
         InferenceInput inferenceInput =
@@ -295,11 +295,28 @@ public class IsolatedModelServiceImplTest {
     }
 
     private Object[] generateInferenceInput(int numExample) {
-        float[][] input0 = new float[numExample][100];
-        for (int i = 0; i < numExample; i++) {
-            input0[i][0] = mRandom.nextFloat();
+        int numFloatFeatures = 13;
+        int numStringFeatures = 26;
+        int totalInputs = numFloatFeatures + numStringFeatures;
+
+        Object[] inputs = new Object[totalInputs];
+        // Generate 13 float input tensors
+        for (int i = 0; i < numFloatFeatures; i++) {
+            float[][] floatInput = new float[numExample][1];
+            for (int j = 0; j < numExample; j++) {
+                floatInput[j][0] = mRandom.nextFloat() * 100;
+            }
+            inputs[i] = floatInput;
+        }
+        // Generate 26 string input tensors
+        for (int i = 0; i < numStringFeatures; i++) {
+            String[][] stringInput = new String[numExample][1];
+            for (int j = 0; j < numExample; j++) {
+                stringInput[j][0] = "example_cat_" + mRandom.nextInt(100);
+            }
+            inputs[numFloatFeatures + i] = stringInput;
         }
-        return new Object[] {input0};
+        return inputs;
     }
 
     private InferenceOutput generateInferenceOutput(int numExample) {
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobTest.java
index d0019a3d..c6c2a8a4 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/maintenance/OnDevicePersonalizationMaintenanceJobTest.java
@@ -371,6 +371,16 @@ public final class OnDevicePersonalizationMaintenanceJobTest {
         assertThat(localDir.listFiles()).hasLength(1);
     }
 
+    @Test
+    public void testGetJobPolicyString() {
+        String testPolicyString = "test_string";
+
+        when(mMockFlags.getMaintenanceJobPolicy()).thenReturn(testPolicyString);
+
+        assertThat(mSpyOnDevicePersonalizationMaintenanceJob.getJobPolicyString(/* jobId= */ 0))
+                .isEqualTo(testPolicyString);
+    }
+
     private static void addTestData(long timestamp, OnDevicePersonalizationVendorDataDao dao) {
         String key1 = "key1";
         String key2 = "key2";
diff --git a/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobTest.java b/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobTest.java
index 3adbe5c3..f69a8de4 100644
--- a/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobTest.java
+++ b/tests/servicetests/src/com/android/ondevicepersonalization/services/reset/ResetDataJobTest.java
@@ -26,6 +26,7 @@ import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.ondevicepersonalization.services.OnDevicePersonalizationConfig.RESET_DATA_JOB_ID;
 
+import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 
 import static org.mockito.ArgumentMatchers.any;
@@ -185,4 +186,13 @@ public final class ResetDataJobTest {
                 .that(new ResetDataJob().getBackoffPolicy())
                 .isEqualTo(expectedBackoffPolicy);
     }
+
+    @Test
+    public void testGetJobPolicyString() {
+        String testPolicyString = "test_string";
+
+        when(mMockFlags.getResetDataJobPolicy()).thenReturn(testPolicyString);
+
+        assertThat(mSpyResetDataJob.getJobPolicyString(/* jobId= */ 0)).isEqualTo(testPolicyString);
+    }
 }
```

