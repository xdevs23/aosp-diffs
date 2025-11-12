```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
new file mode 100644
index 0000000..269e995
--- /dev/null
+++ b/PREUPLOAD.cfg
@@ -0,0 +1,14 @@
+[Builtin Hooks]
+aidl_format = true
+android_test_mapping_format = true
+bpfmt = true
+commit_msg_bug_field = true
+commit_msg_changeid_field = true
+commit_msg_test_field = true
+google_java_format = true
+
+[Builtin Hooks Options]
+bpfmt = -s
+
+[Hook Scripts]
+checkstyle_hook = ${REPO_ROOT}/prebuilts/checkstyle/checkstyle.py --sha ${PREUPLOAD_COMMIT}
diff --git a/apex/Android.bp b/apex/Android.bp
index 248a3d9..f1aefd8 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -92,6 +92,10 @@ apex {
     key: "com.android.crashrecovery.key",
     certificate: ":com.android.crashrecovery.certificate",
     manifest: "manifest.json",
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 sdk {
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 0000000..74b6925
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,40 @@
+//
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aconfig_declarations {
+    name: "com.android.crashrecovery.flags-aconfig",
+    package: "com.android.crashrecovery.flags",
+    container: "com.android.crashrecovery",
+    srcs: ["flags.aconfig"],
+}
+
+java_aconfig_library {
+    name: "com.android.crashrecovery.flags-aconfig-java",
+    aconfig_declarations: "com.android.crashrecovery.flags-aconfig",
+    min_sdk_version: "36",
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.crashrecovery",
+    ],
+    visibility: [
+        "//packages/modules/CrashRecovery:__subpackages__",
+        "//frameworks/base/services/tests/mockingservicestests",
+    ],
+}
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
new file mode 100644
index 0000000..0c349a7
--- /dev/null
+++ b/flags/flags.aconfig
@@ -0,0 +1,36 @@
+package: "com.android.crashrecovery.flags"
+container: "com.android.crashrecovery"
+
+flag {
+    name: "configure_package_health_observer_rollback_timeout"
+    namespace: "modularization"
+    description: "Individually configure rollbacks availability for RollbackPackageHealthObserver to 14 days."
+    bug: "416259905"
+}
+
+flag {
+    name: "synchronous_reboot_in_rescue_party"
+    namespace: "modularization"
+    description: "Makes reboot and factory reset synchronous in RescueParty"
+    bug: "328203835"
+}
+
+# Following two flags would be working together
+# 1. flag_reset_enabled  enabling the feature
+# 2. flag_reset_disabled disabling the feature
+#
+# Note: flag_reset_disabled will never be promoted to next. Do not clean it up.
+
+flag {
+    name: "flag_reset_disabled"
+    namespace: "modularization"
+    description: "Disables flag reset functionality for internal users"
+    bug: "397776123"
+}
+
+flag {
+    name: "flag_reset_enabled"
+    namespace: "modularization"
+    description: "Enables flag reset functionality during crash recovery"
+    bug: "397776123"
+}
\ No newline at end of file
diff --git a/framework/Android.bp b/framework/Android.bp
index 1cbb4f1..5bac1aa 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -55,4 +55,5 @@ java_sdk_library {
         "//frameworks/base/tests:__subpackages__",
         "//cts:__subpackages__",
     ],
+    jarjar_rules: "jarjar-rules.txt",
 }
diff --git a/framework/jarjar-rules.txt b/framework/jarjar-rules.txt
new file mode 100644
index 0000000..1ad9ea1
--- /dev/null
+++ b/framework/jarjar-rules.txt
@@ -0,0 +1 @@
+rule android.crashrecovery.flags.** android.crashrecovery.internal.flags.@1
\ No newline at end of file
diff --git a/service/Android.bp b/service/Android.bp
index 5ed09b6..bf88785 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -43,15 +43,17 @@ java_defaults {
         "framework-system-server-module-defaults",
     ],
     static_libs: [
-        "android.crashrecovery.flags-aconfig-java",
+        "com.android.crashrecovery.flags-aconfig-java",
         "crashrecovery-statslog",
         "modules-utils-preconditions",
         "modules-utils-backgroundthread",
         "modules-utils-binary-xml",
         "modules-utils-fastxmlserializer",
+        "modules-utils-handlerexecutor",
         "PlatformProperties",
     ],
     libs: [
+        "android.crashrecovery.flags-aconfig-java",
         "unsupportedappusage",
         "framework-configinfrastructure.stubs.module_lib",
         "framework-crashrecovery.impl",
@@ -67,6 +69,7 @@ java_sdk_library {
     permitted_packages: [
         "com.android.server",
         "android.crashrecovery",
+        "com.android.crashrecovery",
     ],
     apex_available: [
         "com.android.crashrecovery",
@@ -80,6 +83,7 @@ java_sdk_library {
     ],
     aconfig_declarations: [
         "android.crashrecovery.flags-aconfig",
+        "com.android.crashrecovery.flags-aconfig",
     ],
     jarjar_rules: "jarjar-rules.txt",
 }
diff --git a/service/jarjar-rules.txt b/service/jarjar-rules.txt
index 253d6e4..da042d7 100644
--- a/service/jarjar-rules.txt
+++ b/service/jarjar-rules.txt
@@ -1,4 +1,4 @@
-rule android.crashrecovery.flags.** android.crashrecovery.server.flags.@1
+rule android.crashrecovery.flags.** android.crashrecovery.internal.flags.@1
 rule android.sysprop.** com.android.server.crashrecovery.sysprop.@1
 rule com.android.server.crashrecovery.proto.** com.android.server.crashrecovery.module.proto.@1
 rule com.android.modules.utils.** com.android.server.crashrecovery.modules.utils.@1
diff --git a/service/java/com/android/server/PackageWatchdog.java b/service/java/com/android/server/PackageWatchdog.java
index 318a749..a6d8414 100644
--- a/service/java/com/android/server/PackageWatchdog.java
+++ b/service/java/com/android/server/PackageWatchdog.java
@@ -1482,7 +1482,13 @@ public class PackageWatchdog {
                 MonitoredPackage p = packages.get(pIndex);
                 MonitoredPackage existingPackage = getMonitoredPackage(p.getName());
                 if (existingPackage != null) {
-                    existingPackage.updateHealthCheckDuration(p.mDurationMs);
+                    // Reset the state if explicit health check is triggered after the package
+                    // reaches a terminal health state, else only update the health check duration.
+                    if (existingPackage.isPendingHealthChecksLocked()) {
+                        existingPackage.updateHealthCheckDuration(p.mDurationMs);
+                    } else {
+                        existingPackage.resetHealthState(p.mDurationMs);
+                    }
                 } else {
                     putMonitoredPackage(p);
                 }
@@ -1861,6 +1867,19 @@ public class PackageWatchdog {
             mDurationMs = newDurationMs;
         }
 
+        /**
+         * Explicitly reset the health state of the package to be INACTIVE.
+         *
+         * Note: newDurationMs should be greater than 0 for reset to happen.
+         */
+        @GuardedBy("sLock")
+        public void resetHealthState(long newDurationMs) {
+            updateHealthCheckDuration(newDurationMs);
+            mHasPassedHealthCheck = false;
+            mHealthCheckDurationMs = Long.MAX_VALUE;
+            updateHealthCheckStateLocked();
+        }
+
         /**
          * Marks the health check as passed and transitions to {@link HealthCheckState.PASSED}
          * if not yet {@link HealthCheckState.FAILED}.
@@ -2202,4 +2221,17 @@ public class PackageWatchdog {
         mContext.registerReceiverForAllUsers(shutdownEventReceiver, filter, null,
                 /* run on main thread */ null);
     }
+
+    /** @hide **/
+    public static String failureReasonToLog(@FailureReasons int failureReason) {
+        return switch (failureReason) {
+            case FAILURE_REASON_NATIVE_CRASH -> "NATIVE_CRASH";
+            case FAILURE_REASON_EXPLICIT_HEALTH_CHECK -> "EXPLICIT_HEALTH_CHECK";
+            case FAILURE_REASON_APP_CRASH -> "APP_CRASH";
+            case FAILURE_REASON_APP_NOT_RESPONDING -> "APP_NOT_RESPONDING";
+            case FAILURE_REASON_BOOT_LOOP -> "BOOT_LOOP";
+            default -> "UNKNOWN";
+        };
+    }
+
 }
diff --git a/service/java/com/android/server/RescueParty.java b/service/java/com/android/server/RescueParty.java
index 3bf2ce5..e1f3ced 100644
--- a/service/java/com/android/server/RescueParty.java
+++ b/service/java/com/android/server/RescueParty.java
@@ -27,7 +27,7 @@ import android.content.Context;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.content.pm.VersionedPackage;
-import android.crashrecovery.flags.Flags;
+import com.android.crashrecovery.flags.Flags;
 import android.os.Build;
 import android.os.PowerManager;
 import android.os.RecoverySystem;
diff --git a/service/java/com/android/server/crashrecovery/CrashRecoveryUtils.java b/service/java/com/android/server/crashrecovery/CrashRecoveryUtils.java
index 2e2a937..9eb523e 100644
--- a/service/java/com/android/server/crashrecovery/CrashRecoveryUtils.java
+++ b/service/java/com/android/server/crashrecovery/CrashRecoveryUtils.java
@@ -17,8 +17,10 @@
 package com.android.server.crashrecovery;
 
 import android.os.Environment;
+import android.util.FileUtils;
 import android.util.IndentingPrintWriter;
 import android.util.Log;
+import android.util.SparseArray;
 
 import java.io.BufferedReader;
 import java.io.File;
@@ -82,4 +84,59 @@ public class CrashRecoveryUtils {
         File systemDir = new File(Environment.getDataDirectory(), "system");
         return new File(systemDir, "crashrecovery-events.txt");
     }
+
+    /** Append "key,value" into designated file **/
+    public static void putKeyValue(File file, int key, String value) {
+        try {
+            FileOutputStream fos = new FileOutputStream(file, true);
+            PrintWriter pw = new PrintWriter(fos);
+            pw.append(String.valueOf(key)).append(",").append(value);
+            pw.println();
+            pw.flush();
+            FileUtils.sync(fos);
+            pw.close();
+        } catch (IOException e) {
+            Log.e(TAG, String.format("Failed to save id %s, value %s into %s", key, value,
+                    file.getAbsolutePath()), e);
+            file.delete();
+        }
+    }
+
+    /** Overwrite the content of designated file with input keyValues **/
+    public static void writeAllKeyValues(File file, SparseArray<String> keyValues) {
+        StringBuilder content = new StringBuilder();
+        for (int i = 0; i < keyValues.size(); i++) {
+            int key = keyValues.keyAt(i);
+            String value = keyValues.get(key);
+            content.append(key).append(",").append(value).append(System.lineSeparator());
+        }
+
+        try (FileOutputStream fos = new FileOutputStream(file)) {
+            fos.write(content.toString().getBytes());
+        } catch (IOException e) {
+            Log.e(TAG, String.format("Failed to write %s", file.getAbsolutePath()), e);
+            file.delete();
+        }
+    }
+
+    public static SparseArray<String> readAllKeyValues(File file) {
+        SparseArray<String> result = new SparseArray<>();
+        try {
+            String line;
+            BufferedReader reader = new BufferedReader(new FileReader(file));
+            while ((line = reader.readLine()) != null) {
+                // Each line is of the format: "id,value"
+                String[] values = line.trim().split(",");
+                String key = values[0];
+                String value = "";
+                if (values.length > 1) {
+                    value = values[1];
+                }
+                result.put(Integer.parseInt(key), value);
+            }
+        } catch (Exception ignore) {
+            return new SparseArray<>();
+        }
+        return result;
+    }
 }
diff --git a/service/java/com/android/server/rollback/RollbackPackageHealthObserver.java b/service/java/com/android/server/rollback/RollbackPackageHealthObserver.java
index ef89305..08ea751 100644
--- a/service/java/com/android/server/rollback/RollbackPackageHealthObserver.java
+++ b/service/java/com/android/server/rollback/RollbackPackageHealthObserver.java
@@ -17,7 +17,7 @@
 package com.android.server.rollback;
 
 import static com.android.server.PackageWatchdog.MITIGATION_RESULT_SUCCESS;
-import static com.android.server.crashrecovery.CrashRecoveryUtils.logCrashRecoveryEvent;
+import static com.android.server.PackageWatchdog.failureReasonToLog;
 
 import android.annotation.AnyThread;
 import android.annotation.FlaggedApi;
@@ -38,12 +38,13 @@ import android.content.pm.VersionedPackage;
 import android.content.rollback.PackageRollbackInfo;
 import android.content.rollback.RollbackInfo;
 import android.content.rollback.RollbackManager;
-import android.crashrecovery.flags.Flags;
 import android.os.Environment;
 import android.os.Handler;
 import android.os.HandlerThread;
 import android.os.PowerManager;
+import android.os.SystemClock;
 import android.os.SystemProperties;
+import android.provider.DeviceConfig;
 import android.sysprop.CrashRecoveryProperties;
 import android.util.ArraySet;
 import android.util.FileUtils;
@@ -53,23 +54,25 @@ import android.util.SparseArray;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.util.Preconditions;
+import com.android.modules.utils.HandlerExecutor;
 import com.android.server.PackageWatchdog;
 import com.android.server.PackageWatchdog.FailureReasons;
 import com.android.server.PackageWatchdog.PackageHealthObserver;
 import com.android.server.PackageWatchdog.PackageHealthObserverImpact;
+import com.android.server.crashrecovery.CrashRecoveryUtils;
 import com.android.server.crashrecovery.proto.CrashRecoveryStatsLog;
 
-import java.io.BufferedReader;
 import java.io.File;
 import java.io.FileInputStream;
 import java.io.FileOutputStream;
-import java.io.FileReader;
 import java.io.IOException;
-import java.io.PrintWriter;
+import java.time.Instant;
 import java.util.Collections;
 import java.util.Comparator;
 import java.util.List;
 import java.util.Set;
+import java.util.concurrent.Executor;
+import java.util.concurrent.TimeUnit;
 import java.util.function.Consumer;
 
 /**
@@ -79,7 +82,7 @@ import java.util.function.Consumer;
  *
  * @hide
  */
-@FlaggedApi(Flags.FLAG_ENABLE_CRASHRECOVERY)
+@FlaggedApi(android.crashrecovery.flags.Flags.FLAG_ENABLE_CRASHRECOVERY)
 @SuppressLint({"CallbackName"})
 @SystemApi(client = SystemApi.Client.SYSTEM_SERVER)
 public final class RollbackPackageHealthObserver implements PackageHealthObserver {
@@ -93,25 +96,44 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
     private static final String PROP_DISABLE_HIGH_IMPACT_ROLLBACK_FLAG =
             "persist.device_config.configuration.disable_high_impact_rollback";
 
+    private static final String PROP_OBSERVER_ROLLBACK_AVAILABILITY_MILLIS =
+            "observer_rollback_availability_in_millis";
+
+    // Rollbacks available for RollbackPackageHealthObserver for the first 14 days.
+    private static final long DEFAULT_ROLLBACK_AVAILABILITY_DURATION_MILLIS =
+            TimeUnit.DAYS.toMillis(14);
+
+    private long mRollbackAvailabilityDurationInMillis =
+            DEFAULT_ROLLBACK_AVAILABILITY_DURATION_MILLIS;
+
     private final Context mContext;
     private final Handler mHandler;
+    private final Executor mExecutor;
     private final File mLastStagedRollbackIdsFile;
     private final File mTwoPhaseRollbackEnabledFile;
+    private final File mRollbackTimestampsFile;
+    private final Object mRollbackTimestampsFileLock = new Object();
     // Staged rollback ids that have been committed but their session is not yet ready
     private final Set<Integer> mPendingStagedRollbackIds = new ArraySet<>();
     // True if needing to roll back only rebootless apexes when native crash happens
     private boolean mTwoPhaseRollbackEnabled;
 
+    // The timestamp when device is booted.
+    // This is used as a reference for the timestamp recorded in mRollbackTimestampsFile.
+    private long  mBootTimestamp;
+
     @VisibleForTesting
     public RollbackPackageHealthObserver(@NonNull Context context) {
         mContext = context;
         HandlerThread handlerThread = new HandlerThread("RollbackPackageHealthObserver");
         handlerThread.start();
         mHandler = new Handler(handlerThread.getLooper());
+        mExecutor = new HandlerExecutor(getHandler());
         File dataDir = new File(Environment.getDataDirectory(), "rollback-observer");
         dataDir.mkdirs();
         mLastStagedRollbackIdsFile = new File(dataDir, "last-staged-rollback-ids");
         mTwoPhaseRollbackEnabledFile = new File(dataDir, "two-phase-rollback-enabled");
+        mRollbackTimestampsFile = new File(dataDir, "rollback-timestamps");
         PackageWatchdog.getInstance(mContext).registerHealthObserver(context.getMainExecutor(),
                 this);
 
@@ -124,6 +146,24 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
             mTwoPhaseRollbackEnabled = false;
             writeBoolean(mTwoPhaseRollbackEnabledFile, false);
         }
+
+        if (com.android.crashrecovery.flags.Flags
+                .configurePackageHealthObserverRollbackTimeout()) {
+            getHandler().post(this::updateBootTimestamp);
+            registerTimeChangeReceiver();
+        }
+    }
+
+    private String getFailedPackageName(@Nullable VersionedPackage failedPackage,
+            @FailureReasons int failureReason) {
+        if (failureReason == PackageWatchdog.FAILURE_REASON_NATIVE_CRASH) {
+            return SystemProperties.get(
+                    "sys.init.updatable_crashing_process_name", "UNKNOWN_NATIVE");
+        }
+        if (failureReason == PackageWatchdog.FAILURE_REASON_BOOT_LOOP) {
+            return "UNKNOWN_BOOT_LOOP";
+        }
+        return (failedPackage == null ? "UNKNOWN" : failedPackage.getPackageName());
     }
 
     @Override
@@ -147,9 +187,8 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
         }
 
         Slog.i(TAG, "Checking available remediations for health check failure."
-                + " failedPackage: "
-                + (failedPackage == null ? null : failedPackage.getPackageName())
-                + " failureReason: " + failureReason
+                + " failedPackage: " + getFailedPackageName(failedPackage, failureReason)
+                + " failureReason: " + failureReasonToLog(failureReason)
                 + " available impact: " + impact);
         return impact;
     }
@@ -157,14 +196,15 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
     @Override
     public int onExecuteHealthCheckMitigation(@Nullable VersionedPackage failedPackage,
             @FailureReasons int rollbackReason, int mitigationCount) {
+        String failedPackageName = getFailedPackageName(failedPackage, rollbackReason);
         Slog.i(TAG, "Executing remediation."
-                + " failedPackage: "
-                + (failedPackage == null ? null : failedPackage.getPackageName())
-                + " rollbackReason: " + rollbackReason
+                + " failedPackage: " + failedPackageName
+                + " rollbackReason: " + failureReasonToLog(rollbackReason)
                 + " mitigationCount: " + mitigationCount);
         List<RollbackInfo> availableRollbacks = getAvailableRollbacks();
         if (rollbackReason == PackageWatchdog.FAILURE_REASON_NATIVE_CRASH) {
-            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks, rollbackReason));
+            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks, failedPackageName,
+                    rollbackReason));
             return MITIGATION_RESULT_SUCCESS;
         }
 
@@ -172,10 +212,12 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
                 availableRollbacks, PackageManager.ROLLBACK_USER_IMPACT_LOW);
         RollbackInfo rollback = getRollbackForPackage(failedPackage, lowImpactRollbacks);
         if (rollback != null) {
-            mHandler.post(() -> rollbackPackage(rollback, failedPackage, rollbackReason));
+            mHandler.post(() -> rollbackPackage(rollback, failedPackage, rollbackReason,
+                    failedPackageName));
         } else if (!lowImpactRollbacks.isEmpty()) {
             // Apply all available low impact rollbacks.
-            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks, rollbackReason));
+            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks, failedPackageName,
+                    rollbackReason));
         }
 
         // Assume rollbacks executed successfully
@@ -220,8 +262,26 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
         return isPersistentSystemApp(packageName);
     }
 
-    private List<RollbackInfo> getAvailableRollbacks() {
-        return mContext.getSystemService(RollbackManager.class).getAvailableRollbacks();
+    @VisibleForTesting
+    List<RollbackInfo> getAvailableRollbacks() {
+        final List<RollbackInfo> availableRollbacks =
+                mContext.getSystemService(RollbackManager.class).getAvailableRollbacks();
+        if (com.android.crashrecovery.flags.Flags
+                .configurePackageHealthObserverRollbackTimeout()) {
+            final SparseArray<String> rollbackTimestamps;
+            synchronized (mRollbackTimestampsFileLock) {
+                rollbackTimestamps = CrashRecoveryUtils.readAllKeyValues(mRollbackTimestampsFile);
+            }
+            return availableRollbacks.stream().filter(r -> {
+                String timestamp = rollbackTimestamps.get(r.getRollbackId());
+                // If the timestamp cannot be found, it means that such rollback is created before
+                // installing the CrashRecovery version with "rollback-observer/rollback-timestamp".
+                // On the safe side, it should be considered as available rollback.
+                return timestamp == null || Instant.now().isBefore(Instant.parse(timestamp)
+                        .plusMillis(mRollbackAvailabilityDurationInMillis));
+            }).toList();
+        }
+        return availableRollbacks;
     }
 
     private boolean isPersistentSystemApp(@NonNull String packageName) {
@@ -242,6 +302,10 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
     @NonNull
     public void notifyRollbackAvailable(@NonNull RollbackInfo rollback) {
         mHandler.post(() -> {
+            if (com.android.crashrecovery.flags.Flags
+                    .configurePackageHealthObserverRollbackTimeout()) {
+                recordRollbackTimestamp(rollback, Instant.now());
+            }
             // Enable two-phase rollback when a rebootless apex rollback is made available.
             // We assume the rebootless apex is stable and is less likely to be the cause
             // if native crash doesn't happen before reboot. So we will clear the flag and disable
@@ -253,6 +317,14 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
         });
     }
 
+    @VisibleForTesting
+    void recordRollbackTimestamp(RollbackInfo rollback, Instant timestamp) {
+        synchronized (mRollbackTimestampsFileLock) {
+            CrashRecoveryUtils.putKeyValue(mRollbackTimestampsFile, rollback.getRollbackId(),
+                    timestamp.toString());
+        }
+    }
+
     private static boolean isRebootlessApex(RollbackInfo rollback) {
         if (!rollback.isStaged()) {
             for (PackageRollbackInfo info : rollback.getPackages()) {
@@ -264,6 +336,20 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
         return false;
     }
 
+    @WorkerThread
+    private void updateRollbackAvailabilityDurationInMillis() {
+        assertInWorkerThread();
+        mRollbackAvailabilityDurationInMillis = DeviceConfig.getLong(
+                DeviceConfig.NAMESPACE_ROLLBACK,
+                PROP_OBSERVER_ROLLBACK_AVAILABILITY_MILLIS,
+                DEFAULT_ROLLBACK_AVAILABILITY_DURATION_MILLIS);
+        if (mRollbackAvailabilityDurationInMillis < 0) {
+            mRollbackAvailabilityDurationInMillis = DEFAULT_ROLLBACK_AVAILABILITY_DURATION_MILLIS;
+        }
+        Slog.d(TAG, "mRollbackAvailabilityDurationInMillis=" +
+                mRollbackAvailabilityDurationInMillis);
+    }
+
     /** Verifies the rollback state after a reboot and schedules polling for sometime after reboot
      * to check for native crashes and mitigate them if needed.
      */
@@ -276,8 +362,14 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
     private void onBootCompleted() {
         assertInWorkerThread();
 
+        if (com.android.crashrecovery.flags.Flags
+                .configurePackageHealthObserverRollbackTimeout()) {
+            DeviceConfig.addOnPropertiesChangedListener(DeviceConfig.NAMESPACE_ROLLBACK,
+                    mExecutor, properties -> updateRollbackAvailabilityDurationInMillis());
+            updateRollbackAvailabilityDurationInMillis();
+        }
         RollbackManager rollbackManager = mContext.getSystemService(RollbackManager.class);
-        if (!rollbackManager.getAvailableRollbacks().isEmpty()) {
+        if (!getAvailableRollbacks().isEmpty()) {
             // TODO(gavincorkery): Call into Package Watchdog from outside the observer
             PackageWatchdog.getInstance(mContext).scheduleCheckAndMitigateNativeCrashes();
         }
@@ -369,19 +461,8 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
 
     static void writeStagedRollbackId(File file, int stagedRollbackId,
             @Nullable VersionedPackage logPackage) {
-        try {
-            FileOutputStream fos = new FileOutputStream(file, true);
-            PrintWriter pw = new PrintWriter(fos);
-            String logPackageName = logPackage != null ? logPackage.getPackageName() : "";
-            pw.append(String.valueOf(stagedRollbackId)).append(",").append(logPackageName);
-            pw.println();
-            pw.flush();
-            FileUtils.sync(fos);
-            pw.close();
-        } catch (IOException e) {
-            Slog.e(TAG, "Failed to save last staged rollback id", e);
-            file.delete();
-        }
+        String logPackageName = logPackage != null ? logPackage.getPackageName() : "";
+        CrashRecoveryUtils.putKeyValue(file, stagedRollbackId, logPackageName);
     }
 
     @WorkerThread
@@ -395,27 +476,9 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
     }
 
     static SparseArray<String> readStagedRollbackIds(File file) {
-        SparseArray<String> result = new SparseArray<>();
-        try {
-            String line;
-            BufferedReader reader = new BufferedReader(new FileReader(file));
-            while ((line = reader.readLine()) != null) {
-                // Each line is of the format: "id,logging_package"
-                String[] values = line.trim().split(",");
-                String rollbackId = values[0];
-                String logPackageName = "";
-                if (values.length > 1) {
-                    logPackageName = values[1];
-                }
-                result.put(Integer.parseInt(rollbackId), logPackageName);
-            }
-        } catch (Exception ignore) {
-            return new SparseArray<>();
-        }
-        return result;
+        return CrashRecoveryUtils.readAllKeyValues(file);
     }
 
-
     /**
      * Returns true if the package name is the name of a module.
      */
@@ -445,24 +508,18 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
      */
     @WorkerThread
     private void rollbackPackage(RollbackInfo rollback, VersionedPackage failedPackage,
-            @FailureReasons int rollbackReason) {
+            @FailureReasons int rollbackReason, String failedPackageName) {
         assertInWorkerThread();
-        String failedPackageName = (failedPackage == null ? null : failedPackage.getPackageName());
 
         Slog.i(TAG, "Rolling back package. RollbackId: " + rollback.getRollbackId()
                 + " failedPackage: " + failedPackageName
-                + " rollbackReason: " + rollbackReason);
-        logCrashRecoveryEvent(Log.DEBUG, String.format("Rolling back %s. Reason: %s",
-                failedPackageName, rollbackReason));
+                + " rollbackReason: " + failureReasonToLog(rollbackReason));
+        CrashRecoveryUtils.logCrashRecoveryEvent(Log.DEBUG,
+                String.format("Rolling back %s. Reason: %s", failedPackageName,
+                        failureReasonToLog(rollbackReason)));
         final RollbackManager rollbackManager = mContext.getSystemService(RollbackManager.class);
         int reasonToLog = WatchdogRollbackLogger.mapFailureReasonToMetric(rollbackReason);
-        final String failedPackageToLog;
-        if (rollbackReason == PackageWatchdog.FAILURE_REASON_NATIVE_CRASH) {
-            failedPackageToLog = SystemProperties.get(
-                    "sys.init.updatable_crashing_process_name", "");
-        } else {
-            failedPackageToLog = failedPackage.getPackageName();
-        }
+
         VersionedPackage logPackageTemp = null;
         if (isModule(failedPackage.getPackageName())) {
             logPackageTemp = WatchdogRollbackLogger.getLogPackage(mContext, failedPackage);
@@ -471,7 +528,7 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
         final VersionedPackage logPackage = logPackageTemp;
         WatchdogRollbackLogger.logEvent(logPackage,
                 CrashRecoveryStatsLog.WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_INITIATE,
-                reasonToLog, failedPackageToLog);
+                reasonToLog, failedPackageName);
 
         Consumer<Intent> onResult = result -> {
             assertInWorkerThread();
@@ -484,19 +541,19 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
                     WatchdogRollbackLogger.logEvent(logPackage,
                             CrashRecoveryStatsLog
                             .WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_BOOT_TRIGGERED,
-                            reasonToLog, failedPackageToLog);
+                            reasonToLog, failedPackageName);
 
                 } else {
                     WatchdogRollbackLogger.logEvent(logPackage,
                             CrashRecoveryStatsLog
                                     .WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_SUCCESS,
-                            reasonToLog, failedPackageToLog);
+                            reasonToLog, failedPackageName);
                 }
             } else {
                 WatchdogRollbackLogger.logEvent(logPackage,
                         CrashRecoveryStatsLog
                                 .WATCHDOG_ROLLBACK_OCCURRED__ROLLBACK_TYPE__ROLLBACK_FAILURE,
-                        reasonToLog, failedPackageToLog);
+                        reasonToLog, failedPackageName);
             }
             if (rollback.isStaged()) {
                 markStagedSessionHandled(rollback.getRollbackId());
@@ -560,7 +617,8 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
                 VersionedPackage firstRollback =
                         rollback.getPackages().get(0).getVersionRolledBackFrom();
                 rollbackPackage(rollback, firstRollback,
-                        PackageWatchdog.FAILURE_REASON_NATIVE_CRASH);
+                        PackageWatchdog.FAILURE_REASON_NATIVE_CRASH,
+                        getFailedPackageName(null, PackageWatchdog.FAILURE_REASON_NATIVE_CRASH));
                 found = true;
             }
         }
@@ -578,7 +636,8 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
 
         if (minRollbackImpactLevel == PackageManager.ROLLBACK_USER_IMPACT_LOW) {
             // Apply all available low impact rollbacks.
-            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks, rollbackReason));
+            mHandler.post(() -> rollbackAllLowImpact(availableRollbacks,
+                    getFailedPackageName(null, rollbackReason), rollbackReason));
         } else if (minRollbackImpactLevel == PackageManager.ROLLBACK_USER_IMPACT_HIGH) {
             // Check disable_high_impact_rollback device config before performing rollback
             if (SystemProperties.getBoolean(PROP_DISABLE_HIGH_IMPACT_ROLLBACK_FLAG, false)) {
@@ -616,17 +675,21 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
                         .getVersionRolledBackFrom();
         Slog.i(TAG, "Rolling back high impact rollback for package: "
                 + firstRollback.getPackageName());
-        rollbackPackage(sortedHighImpactRollbacks.get(0), firstRollback, rollbackReason);
+        rollbackPackage(sortedHighImpactRollbacks.get(0), firstRollback, rollbackReason,
+                getFailedPackageName(null, rollbackReason));
     }
 
     /**
      * Rollback all available low impact rollbacks
      * @param availableRollbacks all available rollbacks
+     * @param failedPackageName Name of package failed if any
      * @param rollbackReason reason to rollbacks
      */
     @WorkerThread
     private void rollbackAllLowImpact(
-            List<RollbackInfo> availableRollbacks, @FailureReasons int rollbackReason) {
+            List<RollbackInfo> availableRollbacks,
+            String failedPackageName,
+            @FailureReasons int rollbackReason) {
         assertInWorkerThread();
 
         List<RollbackInfo> lowImpactRollbacks = getRollbacksAvailableForImpactLevel(
@@ -636,8 +699,9 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
             return;
         }
 
-        Slog.i(TAG, "Rolling back all available low impact rollbacks");
-        logCrashRecoveryEvent(Log.DEBUG, "Rolling back all available. Reason: " + rollbackReason);
+        Slog.i(TAG, "Rolling back all available low impact rollbacks due to " + failedPackageName);
+        CrashRecoveryUtils.logCrashRecoveryEvent(Log.DEBUG,
+                "Rolling back all available. Reason: " + failureReasonToLog(rollbackReason));
         // Add all rollback ids to mPendingStagedRollbackIds, so that we do not reboot before all
         // pending staged rollbacks are handled.
         for (RollbackInfo rollback : lowImpactRollbacks) {
@@ -649,7 +713,7 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
         for (RollbackInfo rollback : lowImpactRollbacks) {
             VersionedPackage firstRollback =
                     rollback.getPackages().get(0).getVersionRolledBackFrom();
-            rollbackPackage(rollback, firstRollback, rollbackReason);
+            rollbackPackage(rollback, firstRollback, rollbackReason, failedPackageName);
         }
     }
 
@@ -689,4 +753,53 @@ public final class RollbackPackageHealthObserver implements PackageHealthObserve
     Handler getHandler() {
         return mHandler;
     }
+
+    @AnyThread
+    private void registerTimeChangeReceiver() {
+        final BroadcastReceiver timeChangeIntentReceiver = new BroadcastReceiver() {
+            @Override
+            public void onReceive(Context context, Intent intent) {
+                assertInWorkerThread();
+                updateRollbackTimestampFile();
+            }
+        };
+        final IntentFilter filter = new IntentFilter();
+        filter.addAction(Intent.ACTION_TIME_CHANGED);
+        mContext.registerReceiver(timeChangeIntentReceiver, filter,
+                null /* broadcastPermission */, getHandler());
+    }
+
+    @VisibleForTesting
+    void updateRollbackTimestampFile() {
+        final long oldBootTimestamp = getBootTimestamp();
+        final long offset = updateBootTimestamp() - oldBootTimestamp;
+
+        synchronized (mRollbackTimestampsFileLock) {
+            final SparseArray<String> rollbackTimestamps =
+                    CrashRecoveryUtils.readAllKeyValues(mRollbackTimestampsFile);
+            SparseArray<String> updatedRollbackTimestamps =
+                    new SparseArray<>(rollbackTimestamps.size());
+            for (int i = 0; i < rollbackTimestamps.size(); i++) {
+                int rollbackId = rollbackTimestamps.keyAt(i);
+                Instant updatedTimestamp =
+                        Instant.parse(rollbackTimestamps.get(rollbackId)).plusMillis(
+                                offset);
+                updatedRollbackTimestamps.put(rollbackId, updatedTimestamp.toString());
+            }
+            CrashRecoveryUtils.writeAllKeyValues(mRollbackTimestampsFile,
+                    updatedRollbackTimestamps);
+        }
+    }
+
+    @VisibleForTesting
+    @AnyThread
+    long getBootTimestamp() {
+        return mBootTimestamp;
+    }
+
+    @VisibleForTesting
+    long updateBootTimestamp() {
+        mBootTimestamp = System.currentTimeMillis() - SystemClock.elapsedRealtime();
+        return mBootTimestamp;
+    }
 }
```

