```diff
diff --git a/aidl/android/os/IProfilingService.aidl b/aidl/android/os/IProfilingService.aidl
index 5a9a8e3..5d5b486 100644
--- a/aidl/android/os/IProfilingService.aidl
+++ b/aidl/android/os/IProfilingService.aidl
@@ -43,8 +43,10 @@ interface IProfilingService {
 
     oneway void removeProfilingTriggers(in int[] triggers, String packageName);
 
+    oneway void addAllProfilingTriggers(String packageName);
+
     oneway void clearProfilingTriggers(String packageName);
 
-    oneway void processTrigger(int uid, String packageName, int triggerType);
+    oneway void processTrigger(int uid, String packageName, int triggerType, String tag);
 
 }
diff --git a/apex/Android.bp b/apex/Android.bp
index 1c56a80..5100c6d 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -45,6 +45,11 @@ apex {
 
     bootclasspath_fragments: ["com.android.profiling-bootclasspath-fragment"],
     systemserverclasspath_fragments: ["com.android.profiling-systemserverclasspath-fragment"],
+    
+    licenses: [
+        "Android-Apache-2.0",
+        "opensourcerequest",
+    ],
 }
 
 systemserverclasspath_fragment {
diff --git a/framework/api/current.txt b/framework/api/current.txt
index 5e02815..574f96a 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -2,11 +2,13 @@
 package android.os {
 
   @FlaggedApi("android.os.profiling.telemetry_apis") public final class ProfilingManager {
+    method @FlaggedApi("android.os.profiling.profiling_25q4") public void addAllProfilingTriggers();
     method @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public void addProfilingTriggers(@NonNull java.util.List<android.os.ProfilingTrigger>);
     method @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public void clearProfilingTriggers();
     method public void registerForAllProfilingResults(@NonNull java.util.concurrent.Executor, @NonNull java.util.function.Consumer<android.os.ProfilingResult>);
     method @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public void removeProfilingTriggersByType(@NonNull int[]);
     method public void requestProfiling(int, @Nullable android.os.Bundle, @Nullable String, @Nullable android.os.CancellationSignal, @Nullable java.util.concurrent.Executor, @Nullable java.util.function.Consumer<android.os.ProfilingResult>);
+    method @FlaggedApi("android.os.profiling.profiling_25q4") public void requestRunningSystemTrace(@Nullable String);
     method public void unregisterForAllProfilingResults(@Nullable java.util.function.Consumer<android.os.ProfilingResult>);
     field public static final int PROFILING_TYPE_HEAP_PROFILE = 2; // 0x2
     field public static final int PROFILING_TYPE_JAVA_HEAP_DUMP = 1; // 0x1
@@ -39,6 +41,10 @@ package android.os {
     method public int getTriggerType();
     field public static final int TRIGGER_TYPE_ANR = 2; // 0x2
     field public static final int TRIGGER_TYPE_APP_FULLY_DRAWN = 1; // 0x1
+    field @FlaggedApi("android.os.profiling.profiling_25q4") public static final int TRIGGER_TYPE_APP_REQUEST_RUNNING_TRACE = 3; // 0x3
+    field @FlaggedApi("android.os.profiling.profiling_25q4") public static final int TRIGGER_TYPE_KILL_FORCE_STOP = 4; // 0x4
+    field @FlaggedApi("android.os.profiling.profiling_trigger_kill_recents") public static final int TRIGGER_TYPE_KILL_RECENTS = 5; // 0x5
+    field @FlaggedApi("android.os.profiling.profiling_25q4") public static final int TRIGGER_TYPE_KILL_TASK_MANAGER = 6; // 0x6
     field public static final int TRIGGER_TYPE_NONE = 0; // 0x0
   }
 
diff --git a/framework/java/android/os/ProfilingManager.java b/framework/java/android/os/ProfilingManager.java
index 260876c..59ae4b5 100644
--- a/framework/java/android/os/ProfilingManager.java
+++ b/framework/java/android/os/ProfilingManager.java
@@ -486,6 +486,7 @@ public final class ProfilingManager {
 
             String packageName = mContext.getPackageName();
             if (packageName == null) {
+                // This should never happen.
                 if (DEBUG) Log.d(TAG, "Failed to resolve package name.");
                 return;
             }
@@ -494,7 +495,49 @@ public final class ProfilingManager {
                 service.addProfilingTriggers(toValueParcelList(triggers), packageName);
             } catch (RemoteException e) {
                 if (DEBUG) Log.d(TAG, "Binder exception processing request", e);
-                throw new RuntimeException("Unable to add profiling triggers.");
+                e.rethrowAsRuntimeException();
+            }
+        }
+    }
+
+    /**
+     * <p>
+     * Register this process for all triggers.
+     * </p>
+     *
+     * <p>
+     * Registering for all triggers is in addition to any specific triggers registered. Any triggers
+     * already registered when this is called, along with their parameters, will not be impacted.
+     * Any triggers specifically registered after calling this, along with any parameters set on
+     * them, will take precedence over what is set here.
+     * </p>
+     *
+     * <p>
+     * See {@link #addProfilingTriggers} for more on triggers.
+     * </p>
+     */
+    @FlaggedApi(Flags.FLAG_PROFILING_25Q4)
+    public void addAllProfilingTriggers() {
+        synchronized (mLock) {
+            final IProfilingService service = getOrCreateIProfilingServiceLocked(false);
+            if (service == null) {
+                // If we can't access service then we can't do anything. Throw.
+                if (DEBUG) Log.d(TAG, "ProfilingService is not available.");
+                throw new RuntimeException("ProfilingService is not available");
+            }
+
+            String packageName = mContext.getPackageName();
+            if (packageName == null) {
+                // This should never happen.
+                if (DEBUG) Log.d(TAG, "Failed to resolve package name.");
+                throw new RuntimeException("Failed to resolve package name");
+            }
+
+            try {
+                service.addAllProfilingTriggers(packageName);
+            } catch (RemoteException e) {
+                if (DEBUG) Log.d(TAG, "Binder exception processing request", e);
+                e.rethrowAsRuntimeException();
             }
         }
     }
@@ -574,6 +617,46 @@ public final class ProfilingManager {
         }
     }
 
+    /**
+     * <p>
+     * Request a snapshot of a background trace, if one is running.
+     * </p>
+     *
+     * <p>
+     * This request sends a {@link ProfilingTrigger#TRIGGER_TYPE_APP_REQUEST_RUNNING_TRACE} trigger.
+     * Apps must register interest in this trigger in order to receive the result using either
+     * {@link #addProfilingTriggers} or {@link #addAllProfilingTriggers()}.
+     * </p>
+     */
+    @FlaggedApi(Flags.FLAG_PROFILING_25Q4)
+    public void requestRunningSystemTrace(@Nullable String tag) {
+        synchronized (mLock) {
+            final IProfilingService service = getOrCreateIProfilingServiceLocked(false);
+            if (service == null) {
+                // If we can't access service then we can't do anything. Return.
+                if (DEBUG) {
+                    Log.d(TAG, "ProfilingService is not available, requestRunningSystemTrace "
+                            + "ignored.");
+                }
+                return;
+            }
+
+            String packageName = mContext.getPackageName();
+            if (packageName == null) {
+                if (DEBUG) Log.d(TAG, "Failed to resolve package name.");
+                return;
+            }
+
+            try {
+                service.processTrigger(Binder.getCallingUid(), packageName,
+                        ProfilingTrigger.TRIGGER_TYPE_APP_REQUEST_RUNNING_TRACE, tag);
+            } catch (RemoteException e) {
+                if (DEBUG) Log.d(TAG, "Binder exception processing request", e);
+                e.rethrowAsRuntimeException();
+            }
+        }
+    }
+
     /** @hide */
     @VisibleForTesting
     @GuardedBy("mLock")
diff --git a/framework/java/android/os/ProfilingServiceHelper.java b/framework/java/android/os/ProfilingServiceHelper.java
index 9c2c588..aacfc39 100644
--- a/framework/java/android/os/ProfilingServiceHelper.java
+++ b/framework/java/android/os/ProfilingServiceHelper.java
@@ -83,7 +83,7 @@ public class ProfilingServiceHelper {
     public void onProfilingTriggerOccurred(int uid, @NonNull String packageName, int triggerType) {
         synchronized (mLock) {
             try {
-                mProfilingService.processTrigger(uid, packageName, triggerType);
+                mProfilingService.processTrigger(uid, packageName, triggerType, null);
             } catch (RemoteException e) {
                 // Exception sending trigger to service. Nothing to do here, trigger will be lost.
                 if (DEBUG) Log.e(TAG, "Exception sending trigger", e);
diff --git a/framework/java/android/os/ProfilingTrigger.java b/framework/java/android/os/ProfilingTrigger.java
index 53ba4e8..13008e9 100644
--- a/framework/java/android/os/ProfilingTrigger.java
+++ b/framework/java/android/os/ProfilingTrigger.java
@@ -32,20 +32,68 @@ public final class ProfilingTrigger {
     /** No trigger. Used in {@link ProfilingResult} for non trigger caused results. */
     public static final int TRIGGER_TYPE_NONE = 0;
 
-    /** Trigger occurs after {@link Activity#reportFullyDrawn} is called for a cold start. */
+    /**
+     * Trigger occurs after {@link Activity#reportFullyDrawn} is called for a cold start.
+     *
+     * System will provide a snapshot of a running system trace in response to this trigger.
+     */
     public static final int TRIGGER_TYPE_APP_FULLY_DRAWN = 1;
 
     /**
      * Trigger occurs after an ANR has been identified, but before the system would attempt to kill
      * the app. The trigger does not necessarily indicate that the app was killed due to the ANR.
+     *
+     * System will provide a snapshot of a running system trace in response to this trigger.
      */
     public static final int TRIGGER_TYPE_ANR = 2;
 
+    /**
+     * Trigger occurs when an app requests the actively running trace by calling
+     * {@link ProfilingManager#requestRunningSystemTrace}.
+     *
+     * System will provide a snapshot of a running system trace in response to this trigger.
+     */
+    @FlaggedApi(Flags.FLAG_PROFILING_25Q4)
+    public static final int TRIGGER_TYPE_APP_REQUEST_RUNNING_TRACE = 3;
+
+    /**
+     * Trigger occurs when an app is killed due to the user clicking the "Force stop" button of the
+     * App info page in Settings.
+     *
+     * System will provide a snapshot of a running system trace in response to this trigger.
+     */
+    @FlaggedApi(Flags.FLAG_PROFILING_25Q4)
+    public static final int TRIGGER_TYPE_KILL_FORCE_STOP = 4;
+
+    /**
+     * Trigger occurs when an app is killed due to the user removing it in the <a
+     * href="https://developer.android.com/guide/components/activities/recents">Recents screen</a>.
+     *
+     * System will provide a snapshot of a running system trace in response to this trigger.
+     */
+    @FlaggedApi(Flags.FLAG_PROFILING_TRIGGER_KILL_RECENTS)
+    public static final int TRIGGER_TYPE_KILL_RECENTS = 5;
+
+    /**
+     * Trigger occurs when an app is killed due to the user clicking the "Stop" button for the
+     * application in <a href=
+     * "https://developer.android.com/develop/background-work/services/fgs/handle-user-stopping">
+     * Task Manager</a>.
+     *
+     * System will provide a snapshot of a running system trace in response to this trigger.
+     */
+    @FlaggedApi(Flags.FLAG_PROFILING_25Q4)
+    public static final int TRIGGER_TYPE_KILL_TASK_MANAGER = 6;
+
     /** @hide */
     @IntDef(value = {
         TRIGGER_TYPE_NONE,
         TRIGGER_TYPE_APP_FULLY_DRAWN,
         TRIGGER_TYPE_ANR,
+        TRIGGER_TYPE_APP_REQUEST_RUNNING_TRACE,
+        TRIGGER_TYPE_KILL_FORCE_STOP,
+        TRIGGER_TYPE_KILL_RECENTS,
+        TRIGGER_TYPE_KILL_TASK_MANAGER,
     })
     @Retention(RetentionPolicy.SOURCE)
     @interface TriggerType {}
@@ -78,6 +126,7 @@ public final class ProfilingTrigger {
          * Requires a trigger type. An app can only have one registered trigger per trigger type.
          * Adding a new trigger with the same type will override the previously set one.
          *
+         *
          * @throws IllegalArgumentException if the trigger type is not valid.
          */
         public Builder(@TriggerType int triggerType) {
@@ -160,7 +209,10 @@ public final class ProfilingTrigger {
      */
     public static boolean isValidRequestTriggerType(int triggerType) {
         return triggerType == TRIGGER_TYPE_APP_FULLY_DRAWN
-                || triggerType == TRIGGER_TYPE_ANR;
+            || triggerType == TRIGGER_TYPE_ANR
+            || (Flags.profiling25q4() && triggerType == TRIGGER_TYPE_APP_REQUEST_RUNNING_TRACE)
+            || (Flags.profiling25q4() && triggerType == TRIGGER_TYPE_KILL_FORCE_STOP)
+            || (Flags.profilingTriggerKillRecents() && triggerType == TRIGGER_TYPE_KILL_RECENTS)
+            || (Flags.profiling25q4() && triggerType == TRIGGER_TYPE_KILL_TASK_MANAGER);
     }
-
 }
diff --git a/framework/java/android/os/flags.aconfig b/framework/java/android/os/flags.aconfig
index 2fec64e..c26b878 100644
--- a/framework/java/android/os/flags.aconfig
+++ b/framework/java/android/os/flags.aconfig
@@ -51,3 +51,19 @@ flag {
      is_fixed_read_only: true
      bug: "373461116"
 }
+
+flag {
+     name: "profiling_25q4"
+     namespace: "system_performance"
+     is_exported: true
+     description: "Enables new functionality for 25Q4 including new triggers and add all triggers api."
+     bug: "406809160"
+}
+
+flag {
+     name: "profiling_trigger_kill_recents"
+     namespace: "system_performance"
+     is_exported: true
+     description: "Enables the kill recents trigger."
+     bug: "406809160"
+}
diff --git a/service/java/com/android/os/profiling/ProfilingService.java b/service/java/com/android/os/profiling/ProfilingService.java
index e12c59f..eb50ee0 100644
--- a/service/java/com/android/os/profiling/ProfilingService.java
+++ b/service/java/com/android/os/profiling/ProfilingService.java
@@ -1184,6 +1184,11 @@ public class ProfilingService extends IProfilingService.Stub {
         }
     }
 
+    /** Add an all profiling trigger for the provided package name and the callers uid. */
+    public void addAllProfilingTriggers(String packageName) {
+        addTrigger(Binder.getCallingUid(), packageName, ProfilingTriggerData.TRIGGER_ALL, 0);
+    }
+
     /**
      * Remove the provided list of validated trigger codes from a process with the provided package
      * name and the uid of the caller.
@@ -1602,7 +1607,8 @@ public class ProfilingService extends IProfilingService.Stub {
      * Cloning will fork the running trace, stop the new forked trace, and output the result to a
      * separate file. This leaves the original trace running.
      */
-    public void processTrigger(int uid, @NonNull String packageName, int triggerType) {
+    public void processTrigger(int uid, @NonNull String packageName, int triggerType,
+            @Nullable String tag) {
         if (!Flags.systemTriggeredProfilingNew()) {
             // Flag disabled.
             return;
@@ -1612,7 +1618,7 @@ public class ProfilingService extends IProfilingService.Stub {
         getHandler().post(new Runnable() {
             @Override
             public void run() {
-                processTriggerInternal(uid, packageName, triggerType);
+                processTriggerInternal(uid, packageName, triggerType, tag);
             }
         });
     }
@@ -1621,7 +1627,8 @@ public class ProfilingService extends IProfilingService.Stub {
      * Internal call to process trigger, not to be called on the thread that passed the trigger in.
      */
     @VisibleForTesting
-    public void processTriggerInternal(int uid, @NonNull String packageName, int triggerType) {
+    public void processTriggerInternal(int uid, @NonNull String packageName, int triggerType,
+            @Nullable String tag) {
         synchronized (mLock) {
             if (mSystemTriggeredTraceUniqueSessionName == null) {
                 // If we don't have the session name then we don't know how to clone the trace so
@@ -1649,55 +1656,18 @@ public class ProfilingService extends IProfilingService.Stub {
             }
         }
 
-        // Then check if the app has registered interest in this combo.
-        SparseArray<ProfilingTriggerData> perProcessTriggers = mAppTriggers.get(packageName, uid);
-        if (perProcessTriggers == null) {
-            // This uid hasn't registered any triggers.
-            if (DEBUG) {
-                Log.d(TAG, String.format("Profiling triggered for uid %d with no registered "
-                        + "triggers", uid));
-            }
-            return;
-        }
-
-        ProfilingTriggerData trigger = perProcessTriggers.get(triggerType);
+        ProfilingTriggerData trigger = getTriggerDataObject(uid, packageName, triggerType);
         if (trigger == null) {
-            // This uid hasn't registered a trigger for this type.
-            if (DEBUG) {
-                Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d, but "
-                        + "app has not registered for this trigger type.", uid, triggerType));
-            }
+            // No trigger object, process isn't registered for this trigger.
             return;
         }
 
-        // Now apply system and app provided rate limiting.
-        if (System.currentTimeMillis() - trigger.getLastTriggeredTimeMs()
-                < trigger.getRateLimitingPeriodHours() * 60L * 60L * 1000L) {
-            // App provided rate limiting doesn't allow for this run, return.
-            if (DEBUG) {
-                Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d but blocked"
-                        + " by app provided rate limiting ", uid, triggerType));
-            }
+        // Then check rate limiting, both app and system.
+        if (!isTriggerRateLimitingAllowed(trigger, ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE)) {
             return;
         }
 
-        // If this is from the test package, skip system rate limiting.
-        if (!packageName.equals(mTestPackageName)) {
-            int systemRateLimiterResult = getRateLimiter().isProfilingRequestAllowed(uid,
-                    ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE, true, null);
-            if (systemRateLimiterResult != RateLimiter.RATE_LIMIT_RESULT_ALLOWED) {
-                // Blocked by system rate limiter, return. Since this is system triggered there is
-                // no callback and therefore no need to distinguish between per app and system
-                // denials within the system rate limiter.
-                if (DEBUG) {
-                    Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d but "
-                            + "blocked by system rate limiting ", uid, triggerType));
-                }
-                return;
-            }
-        }
-
-        // Now that it's approved by both rate limiters, update their values.
+        // Now that it's approved by both rate limiters, update the last run value.
         trigger.setLastTriggeredTimeMs(System.currentTimeMillis());
 
         // If we made it this far, a trace is running, the app has registered interest in this
@@ -1745,7 +1715,7 @@ public class ProfilingService extends IProfilingService.Stub {
         // If we get here the clone was successful. Create a new TracingSession to track this and
         // continue moving it along the processing process.
         TracingSession session = new TracingSession(
-                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE, uid, packageName, triggerType);
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE, uid, packageName, triggerType, tag);
         session.setRedactedFileName(baseFileName + OUTPUT_FILE_TRACE_SUFFIX);
         session.setFileName(unredactedFullName);
         session.setProfilingStartTimeMs(System.currentTimeMillis());
@@ -1755,6 +1725,87 @@ public class ProfilingService extends IProfilingService.Stub {
         maybePersistToDisk();
     }
 
+    /**
+     * Get trigger data object for a specific process/trigger combo.
+     *
+     * Return object:
+     * - With type matching provided triggerType if the provided process has explicitly registered
+     *      for that trigger.
+     * - With type of TRIGGER_ALL if the provided process has registered for all triggers and has
+     *      not explicitly registered for the provided trigger type.
+     * - Null if the provied process has not registered for the specific provided triggerType nor
+     *      for all trigger types.
+     */
+    @Nullable
+    @VisibleForTesting
+    public ProfilingTriggerData getTriggerDataObject(int uid, @NonNull String packageName,
+            int triggerType) {
+        SparseArray<ProfilingTriggerData> perProcessTriggers = mAppTriggers.get(packageName, uid);
+        if (perProcessTriggers == null) {
+            // This uid/package hasn't registered any triggers.
+            if (DEBUG) {
+                Log.d(TAG, String.format("Profiling triggered for uid %d with no registered "
+                        + "triggers", uid));
+            }
+            return null;
+        }
+
+        ProfilingTriggerData trigger = perProcessTriggers.get(triggerType);
+
+        if (trigger == null) {
+            // This uid hasn't registered a trigger for this type. Check if they've registered for
+            // all triggers.
+            trigger = perProcessTriggers.get(ProfilingTriggerData.TRIGGER_ALL);
+
+            if (trigger == null) {
+                // This uid hasn't registered a trigger for this type or for all types.
+                if (DEBUG) {
+                    Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d, but "
+                            + "app has not registered for this trigger type or all triggers.",
+                            uid, triggerType));
+                }
+                return null;
+            }
+        }
+
+        return trigger;
+    }
+
+    /** Check rate limiting for a potential system triggered profiling run. */
+    private boolean isTriggerRateLimitingAllowed(ProfilingTriggerData trigger, int profilingType) {
+        // Check app provided rate limiting.
+        if (System.currentTimeMillis() - trigger.getLastTriggeredTimeMs()
+                < trigger.getRateLimitingPeriodHours() * 60L * 60L * 1000L) {
+            // App provided rate limiting doesn't allow for this run, return.
+            if (DEBUG) {
+                Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d but blocked"
+                        + " by app provided rate limiting ", trigger.getUid(),
+                        trigger.getTriggerType()));
+            }
+            return false;
+        }
+
+        // Only perform system rate limiting if this is not the test package.
+        if (!trigger.getPackageName().equals(mTestPackageName)) {
+            // Lastly, check system rate limiting.
+            int systemRateLimiterResult = getRateLimiter().isProfilingRequestAllowed(
+                    trigger.getUid(), profilingType, true, null);
+            if (systemRateLimiterResult != RateLimiter.RATE_LIMIT_RESULT_ALLOWED) {
+                // Blocked by system rate limiter, return. Since this is system triggered there is
+                // no callback and therefore no need to distinguish between per app and system
+                // denials within the system rate limiter.
+                if (DEBUG) {
+                    Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d but "
+                            + "blocked by system rate limiting ", trigger.getUid(),
+                            trigger.getTriggerType()));
+                }
+                return false;
+            }
+        }
+
+        return true;
+    }
+
     /** Add a profiling trigger to the supporting data structure. */
     @VisibleForTesting
     public void addTrigger(int uid, @NonNull String packageName, int triggerType,
diff --git a/service/java/com/android/os/profiling/ProfilingTriggerData.java b/service/java/com/android/os/profiling/ProfilingTriggerData.java
index 5a93b5b..41b7a1a 100644
--- a/service/java/com/android/os/profiling/ProfilingTriggerData.java
+++ b/service/java/com/android/os/profiling/ProfilingTriggerData.java
@@ -20,6 +20,9 @@ import android.annotation.NonNull;
 import android.os.ProfilingTriggersWrapper;
 
 public final class ProfilingTriggerData {
+
+    public static final int TRIGGER_ALL = -1;
+
     // LINT.IfChange(params)
     private final int mUid;
     @NonNull private final String mPackageName;
diff --git a/service/java/com/android/os/profiling/TracingSession.java b/service/java/com/android/os/profiling/TracingSession.java
index e6f8a44..a4dc802 100644
--- a/service/java/com/android/os/profiling/TracingSession.java
+++ b/service/java/com/android/os/profiling/TracingSession.java
@@ -61,13 +61,14 @@ public final class TracingSession {
     private long mRedactionStartTimeMs;
     private int mMaxProfilingTimeAllowedMs = 0;
 
-    public TracingSession(int profilingType,  int uid, String packageName, int triggerType) {
+    public TracingSession(int profilingType,  int uid, String packageName, int triggerType,
+            String tag) {
         this(
                 profilingType,
                 null,
                 uid,
                 packageName,
-                null,
+                tag,
                 0L,
                 0L,
                 triggerType);
diff --git a/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java b/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
index 1e3fbb6..79f7f29 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
@@ -149,6 +149,8 @@ public final class ProfilingFrameworkTests {
         mProfilingManager = mContext.getSystemService(ProfilingManager.class);
         mInstrumentation = InstrumentationRegistry.getInstrumentation();
 
+        mProfilingManager.clearProfilingTriggers();
+
         executeShellCmd(RESET_NAMESPACE, DeviceConfigHelper.NAMESPACE);
         executeShellCmd(RESET_NAMESPACE, DeviceConfigHelper.NAMESPACE_TESTING);
 
@@ -1024,6 +1026,98 @@ public final class ProfilingFrameworkTests {
                 ProfilingTrigger.TRIGGER_TYPE_ANR);
     }
 
+    /**
+     * Test add all profiling triggers and receiving a result works correctly.
+     *
+     * This is done by: adding all triggers through the public api, force starting a system
+     * triggered trace, sending a fake trigger as if from the system, and then confirming the result
+     * is received.
+     */
+    @SuppressWarnings("GuardedBy") // Suppress warning for mProfilingManager lock.
+    @Test
+    @RequiresFlagsEnabled(android.os.profiling.Flags.FLAG_PROFILING_25Q4)
+    public void testSystemTriggeredProfilingAddAll() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        disableRateLimiter();
+
+        mProfilingManager.addAllProfilingTriggers();
+
+        // And add a global listener
+        AppCallback callbackGeneral = new AppCallback();
+        mProfilingManager.registerForAllProfilingResults(
+                new ProfilingTestUtils.ImmediateExecutor(), callbackGeneral);
+
+        // Then start the system triggered trace for testing.
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_STRING,
+                DeviceConfigHelper.NAMESPACE_TESTING,
+                DeviceConfigHelper.SYSTEM_TRIGGERED_TEST_PACKAGE_NAME,
+                REAL_PACKAGE_NAME);
+
+        // Wait a bit so the trace can get started and actually collect something.
+        sleep(WAIT_TIME_FOR_PROFILING_START_MS);
+
+        // Now fake a system trigger.
+        ProfilingServiceHelper.getInstance().onProfilingTriggerOccurred(Binder.getCallingUid(),
+                REAL_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_KILL_FORCE_STOP);
+
+        // Wait for the trace to process.
+        waitForCallback(callbackGeneral);
+
+        // Finally, confirm that a result was received.
+        confirmCollectionSuccess(callbackGeneral.mResult, OUTPUT_FILE_TRACE_SUFFIX,
+                ProfilingTrigger.TRIGGER_TYPE_KILL_FORCE_STOP);
+    }
+
+    /**
+     * Test request running trace trigger.
+     *
+     * This is done by: adding the app request trigger through the public api, force starting a
+     * system triggered trace, calling the app requested trace api, and then confirming the result
+     * is received.
+     */
+    @SuppressWarnings("GuardedBy") // Suppress warning for mProfilingManager lock.
+    @Test
+    @RequiresFlagsEnabled(android.os.profiling.Flags.FLAG_PROFILING_25Q4)
+    public void testSystemTriggeredProfilingRequestRunningTrace() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        disableRateLimiter();
+
+        // First add a trigger
+        ProfilingTrigger trigger = new ProfilingTrigger
+                .Builder(ProfilingTrigger.TRIGGER_TYPE_APP_REQUEST_RUNNING_TRACE).build();
+        mProfilingManager.addProfilingTriggers(List.of(trigger));
+
+        // And add a global listener
+        AppCallback callbackGeneral = new AppCallback();
+        mProfilingManager.registerForAllProfilingResults(
+                new ProfilingTestUtils.ImmediateExecutor(), callbackGeneral);
+
+        // Then start the system triggered trace for testing.
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_STRING,
+                DeviceConfigHelper.NAMESPACE_TESTING,
+                DeviceConfigHelper.SYSTEM_TRIGGERED_TEST_PACKAGE_NAME,
+                REAL_PACKAGE_NAME);
+
+        // Wait a bit so the trace can get started and actually collect something.
+        sleep(WAIT_TIME_FOR_PROFILING_START_MS);
+
+        String tag = "some_tag";
+
+        // Now request the running trace.
+        mProfilingManager.requestRunningSystemTrace(tag);
+
+        // Wait for the trace to process.
+        waitForCallback(callbackGeneral);
+
+        // Finally, confirm that a result was received.
+        confirmCollectionSuccess(callbackGeneral.mResult, OUTPUT_FILE_TRACE_SUFFIX,
+                ProfilingTrigger.TRIGGER_TYPE_APP_REQUEST_RUNNING_TRACE);
+        assertTrue(tag.equals(callbackGeneral.mResult.getTag()));
+    }
+
     /**
      * Test removing profiling trigger.
      *
@@ -1302,6 +1396,30 @@ public final class ProfilingFrameworkTests {
         assertEquals(ProfilingResult.ERROR_NONE, callback.mResult.getErrorCode());
     }
 
+    /**
+     * Test that registering a trigger with an invalid trigger type fails with the correct
+     * exception. The invalid type used here is value 1000 which is noted in docs to be reserved,
+     * thus this test covers both that invalid triggers fail and that the reserved value isn't
+     * used.
+     */
+    @Test
+    public void testInvalidTriggerType() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        try {
+            ProfilingTrigger trigger =
+                    new ProfilingTrigger.Builder(-1 /* Invalid value reserved for all */).build();
+
+            // This is not expected to happen as trigger type -1 should throw an exception.
+            fail("Invalid trigger type did not throw Exception");
+        } catch (IllegalArgumentException e) {
+            // Do nothing, this is what we want.
+        } catch (Exception e) {
+            // Wrong exception type thrown, fail.
+            fail("Invalid trigger type did not throw correct Exception");
+        }
+    }
+
     /** Disable the rate limiter and wait long enough for the update to be picked up. */
     private void disableRateLimiter() throws Exception {
         overrideRateLimiter(true);
diff --git a/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java b/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
index 6d69ea2..4a12b5e 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
@@ -1976,7 +1976,7 @@ public final class ProfilingServiceTests {
 
         // Now process the trigger.
         mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME,
-                ProfilingTrigger.TRIGGER_TYPE_ANR);
+                ProfilingTrigger.TRIGGER_TYPE_ANR, null);
 
         // Get the new trigger time and make sure it's later than the fake one, indicating it ran.
         long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
@@ -2017,7 +2017,7 @@ public final class ProfilingServiceTests {
 
         // Now process the trigger.
         mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME,
-                ProfilingTrigger.TRIGGER_TYPE_ANR);
+                ProfilingTrigger.TRIGGER_TYPE_ANR, null);
 
         // Get the new trigger time and make sure it's equal to the fake one, indicating it did not
         // run.
@@ -2047,7 +2047,7 @@ public final class ProfilingServiceTests {
 
         // Now process the trigger.
         mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME,
-                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN);
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN, null);
 
         // Get the new trigger time and make sure it's later than 0, indicating it ran.
         long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
@@ -2082,7 +2082,7 @@ public final class ProfilingServiceTests {
 
         // Now process the trigger.
         mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME,
-                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN);
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN, null);
 
         // Get the new trigger time and make sure it's equal to 0, indicating it did not run.
         long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
@@ -2134,6 +2134,101 @@ public final class ProfilingServiceTests {
         verify(mProfilingService, times(1)).startSystemTriggeredTrace();
     }
 
+    /**
+     * Test that the all trigger type works correctly, not impacting or being impacted by adding
+     * individual triggers.
+     */
+    @Test
+    @EnableFlags({android.os.profiling.Flags.FLAG_PROFILING_25Q4,
+            android.os.profiling.Flags.FLAG_PROFILING_TRIGGER_KILL_RECENTS})
+    public void testSystemTriggeredProfiling_AddTriggerAll() throws Exception {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Add a trigger.
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_KILL_RECENTS, 0);
+
+        // Verify that the trigger is added.
+        assertTrue(mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .contains(ProfilingTrigger.TRIGGER_TYPE_KILL_RECENTS));
+
+        // Add all profiling triggers.
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTriggerData.TRIGGER_ALL, 0);
+
+        // Verify that the all trigger was added and that previously registered one remained.
+        assertEquals(2, mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).size());
+        assertTrue(mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .contains(ProfilingTriggerData.TRIGGER_ALL));
+        assertTrue(mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .contains(ProfilingTrigger.TRIGGER_TYPE_KILL_RECENTS));
+
+        // Add another trigger.
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_KILL_TASK_MANAGER, 0);
+
+        // Verify that the new trigger was added, and that the previously present all and specific
+        // triggers remain.
+        assertEquals(3, mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).size());
+        assertTrue(mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .contains(ProfilingTriggerData.TRIGGER_ALL));
+        assertTrue(mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .contains(ProfilingTrigger.TRIGGER_TYPE_KILL_TASK_MANAGER));
+        assertTrue(mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .contains(ProfilingTrigger.TRIGGER_TYPE_KILL_RECENTS));
+    }
+
+    /**
+     * Test that getTriggerDataObject returns the correct object for different states. See method
+     * javadoc for more details.
+     */
+    @Test
+    @EnableFlags({android.os.profiling.Flags.FLAG_PROFILING_25Q4,
+            android.os.profiling.Flags.FLAG_PROFILING_TRIGGER_KILL_RECENTS})
+    public void testSystemTriggeredProfiling_GetTriggerDataObject() throws Exception {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Get the trigger object for any trigger type.
+        ProfilingTriggerData trigger = mProfilingService.getTriggerDataObject(
+                FAKE_UID, APP_PACKAGE_NAME, ProfilingTrigger.TRIGGER_TYPE_KILL_FORCE_STOP);
+
+        // Verify that the trigger object is null.
+        assertNull(trigger);
+
+        // Add all profiling triggers.
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTriggerData.TRIGGER_ALL, 0);
+
+        // Get the trigger object for any trigger type.
+        trigger = mProfilingService.getTriggerDataObject(
+                FAKE_UID, APP_PACKAGE_NAME, ProfilingTrigger.TRIGGER_TYPE_KILL_FORCE_STOP);
+
+        // Verify that the all triggers object is returned.
+        assertEquals(ProfilingTriggerData.TRIGGER_ALL, trigger.getTriggerType());
+
+        // Now add a specific trigger.
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_KILL_FORCE_STOP, 0);
+
+        // Get the trigger object for the added trigger type.
+        trigger = mProfilingService.getTriggerDataObject(
+                FAKE_UID, APP_PACKAGE_NAME, ProfilingTrigger.TRIGGER_TYPE_KILL_FORCE_STOP);
+
+        // Verify that the correct specific trigger type object is returned, and not the all
+        // triggers object is not returned.
+        assertNotEquals(ProfilingTriggerData.TRIGGER_ALL, trigger.getTriggerType());
+        assertEquals(ProfilingTrigger.TRIGGER_TYPE_KILL_FORCE_STOP, trigger.getTriggerType());
+
+        // Get the trigger object for a different not added trigger type.
+        trigger = mProfilingService.getTriggerDataObject(
+                FAKE_UID, APP_PACKAGE_NAME, ProfilingTrigger.TRIGGER_TYPE_KILL_RECENTS);
+
+        // Verify that the all triggers object is returned.
+        assertEquals(ProfilingTriggerData.TRIGGER_ALL, trigger.getTriggerType());
+    }
+
     private File createAndConfirmFileExists(File directory, String fileName) throws Exception {
         File file = new File(directory, fileName);
         file.createNewFile();
```

