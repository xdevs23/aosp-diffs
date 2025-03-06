```diff
diff --git a/aidl/android/os/IProfilingResultCallback.aidl b/aidl/android/os/IProfilingResultCallback.aidl
index 6c1fc93..69933b5 100644
--- a/aidl/android/os/IProfilingResultCallback.aidl
+++ b/aidl/android/os/IProfilingResultCallback.aidl
@@ -22,7 +22,7 @@ interface IProfilingResultCallback {
 
     oneway void sendResult(String resultFile, long keyMostSigBits, long keyLeastSigBits, int status, String tag, String error);
 
-    oneway void generateFile(String filePathAbsolute, String fileName, long keyMostSigBits, long keyLeastSigBits);
+    oneway void generateFile(String filePathRelative, String fileName, long keyMostSigBits, long keyLeastSigBits);
 
-    oneway void deleteFile(String filePathAndName);
+    oneway void deleteFile(String relativeFilePathAndName);
 }
diff --git a/aidl/android/os/IProfilingService.aidl b/aidl/android/os/IProfilingService.aidl
index 02a0a03..c1b66c4 100644
--- a/aidl/android/os/IProfilingService.aidl
+++ b/aidl/android/os/IProfilingService.aidl
@@ -18,13 +18,14 @@ package android.os;
 
 import android.os.Bundle;
 import android.os.IProfilingResultCallback;
+import android.os.ProfilingTriggerValueParcel;
 
 /**
  * {@hide}
  */
 interface IProfilingService {
 
-    oneway void requestProfiling(int profilingType, in Bundle params, String filePath, String tag, long keyMostSigBits, long keyLeastSigBits, String packageName);
+    oneway void requestProfiling(int profilingType, in Bundle params, String tag, long keyMostSigBits, long keyLeastSigBits, String packageName);
 
     oneway void registerResultsCallback(boolean isGeneralCallback, IProfilingResultCallback callback);
 
@@ -34,4 +35,12 @@ interface IProfilingService {
 
     oneway void receiveFileDescriptor(in ParcelFileDescriptor fileDescriptor, long keyMostSigBits, long keyLeastSigBits);
 
+    oneway void addProfilingTriggers(in List<ProfilingTriggerValueParcel> triggers, String packageName);
+
+    oneway void removeProfilingTriggers(in int[] triggers, String packageName);
+
+    oneway void clearProfilingTriggers(String packageName);
+
+    oneway void processTrigger(int uid, String packageName, int triggerType);
+
 }
diff --git a/aidl/android/os/ProfilingTriggerValueParcel.aidl b/aidl/android/os/ProfilingTriggerValueParcel.aidl
new file mode 100644
index 0000000..c9ebf2c
--- /dev/null
+++ b/aidl/android/os/ProfilingTriggerValueParcel.aidl
@@ -0,0 +1,25 @@
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
+package android.os;
+
+/**
+ * {@hide}
+ */
+parcelable ProfilingTriggerValueParcel {
+    int triggerType;
+    int rateLimitingPeriodHours;
+}
\ No newline at end of file
diff --git a/apex/Android.bp b/apex/Android.bp
index 625d324..cf360be 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -36,12 +36,14 @@ apex {
 
     name: "com.android.profiling",
     manifest: "manifest.json",
-    file_contexts: ":apex.test-file_contexts",
+    file_contexts: ":com.android.profiling-file_contexts",
     key: "com.android.profiling.key",
     certificate: ":com.android.profiling.certificate",
     defaults: ["v-launched-apex-module"],
     min_sdk_version: "35",
 
+    binaries: ["trace_redactor"],
+
     bootclasspath_fragments: ["com.android.profiling-bootclasspath-fragment"],
     systemserverclasspath_fragments: ["com.android.profiling-systemserverclasspath-fragment"],
 }
diff --git a/framework/Android.bp b/framework/Android.bp
index 45575ac..51bf6c8 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -48,7 +48,7 @@ java_sdk_library {
 
     static_libs: [
         "modules-utils-build",
-        "android.os.profiling.flags-aconfig-java",
+        "profiling_flags_lib",
     ],
 
     permitted_packages: [
@@ -86,15 +86,17 @@ aconfig_declarations {
 }
 
 java_aconfig_library {
-    name: "android.os.profiling.flags-aconfig-java",
+    name: "profiling_flags_lib",
     aconfig_declarations: "android.os.profiling.flags-aconfig",
     apex_available: [
         "com.android.profiling",
+        "//apex_available:platform",
     ],
     mode: "exported",
     min_sdk_version: "35",
     defaults: ["framework-minus-apex-aconfig-java-defaults"],
     visibility: [
         "//packages/modules/Profiling:__subpackages__",
+        "//frameworks/base/services/core",
     ],
 }
diff --git a/framework/api/current.txt b/framework/api/current.txt
index fca446a..5e02815 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -2,7 +2,10 @@
 package android.os {
 
   @FlaggedApi("android.os.profiling.telemetry_apis") public final class ProfilingManager {
+    method @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public void addProfilingTriggers(@NonNull java.util.List<android.os.ProfilingTrigger>);
+    method @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public void clearProfilingTriggers();
     method public void registerForAllProfilingResults(@NonNull java.util.concurrent.Executor, @NonNull java.util.function.Consumer<android.os.ProfilingResult>);
+    method @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public void removeProfilingTriggersByType(@NonNull int[]);
     method public void requestProfiling(int, @Nullable android.os.Bundle, @Nullable String, @Nullable android.os.CancellationSignal, @Nullable java.util.concurrent.Executor, @Nullable java.util.function.Consumer<android.os.ProfilingResult>);
     method public void unregisterForAllProfilingResults(@Nullable java.util.function.Consumer<android.os.ProfilingResult>);
     field public static final int PROFILING_TYPE_HEAP_PROFILE = 2; // 0x2
@@ -17,6 +20,7 @@ package android.os {
     method @Nullable public String getErrorMessage();
     method @Nullable public String getResultFilePath();
     method @Nullable public String getTag();
+    method @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public int getTriggerType();
     method public void writeToParcel(@NonNull android.os.Parcel, int);
     field @NonNull public static final android.os.Parcelable.Creator<android.os.ProfilingResult> CREATOR;
     field public static final int ERROR_FAILED_EXECUTING = 4; // 0x4
@@ -30,5 +34,19 @@ package android.os {
     field public static final int ERROR_UNKNOWN = 8; // 0x8
   }
 
+  @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public final class ProfilingTrigger {
+    method public int getRateLimitingPeriodHours();
+    method public int getTriggerType();
+    field public static final int TRIGGER_TYPE_ANR = 2; // 0x2
+    field public static final int TRIGGER_TYPE_APP_FULLY_DRAWN = 1; // 0x1
+    field public static final int TRIGGER_TYPE_NONE = 0; // 0x0
+  }
+
+  @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public static final class ProfilingTrigger.Builder {
+    ctor public ProfilingTrigger.Builder(int);
+    method @NonNull public android.os.ProfilingTrigger build();
+    method @NonNull public android.os.ProfilingTrigger.Builder setRateLimitingPeriodHours(int);
+  }
+
 }
 
diff --git a/framework/api/module-lib-current.txt b/framework/api/module-lib-current.txt
index 2f6a35a..2aff331 100644
--- a/framework/api/module-lib-current.txt
+++ b/framework/api/module-lib-current.txt
@@ -6,5 +6,10 @@ package android.os {
     method public static void setProfilingServiceManager(@NonNull android.os.ProfilingServiceManager);
   }
 
+  @FlaggedApi("android.os.profiling.system_triggered_profiling_new") public class ProfilingServiceHelper {
+    method @NonNull public static android.os.ProfilingServiceHelper getInstance();
+    method public void onProfilingTriggerOccurred(int, @NonNull String, int);
+  }
+
 }
 
diff --git a/framework/java/android/os/ProfilingManager.java b/framework/java/android/os/ProfilingManager.java
index c0db9c7..fa3ac0b 100644
--- a/framework/java/android/os/ProfilingManager.java
+++ b/framework/java/android/os/ProfilingManager.java
@@ -15,6 +15,8 @@
  */
 package android.os;
 
+import static android.os.ProfilingTrigger.TriggerType;
+
 import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
 import android.annotation.NonNull;
@@ -33,14 +35,17 @@ import java.lang.annotation.RetentionPolicy;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.util.ArrayList;
+import java.util.List;
 import java.util.UUID;
 import java.util.concurrent.Executor;
 import java.util.function.Consumer;
 
 /**
  * <p>
- * This class allows the caller to request profiling and listen for results. Profiling types
- * supported are: system traces, java heap dumps, heap profiles, and stack traces.
+ * This class allows the caller to:
+ * - Request profiling and listen for results. Profiling types supported are: system traces,
+ *      java heap dumps, heap profiles, and stack traces.
+ * - Register triggers for the system to capture profiling on the apps behalf.
  * </p>
  *
  * <p>
@@ -59,16 +64,27 @@ import java.util.function.Consumer;
  * - A request-specific listener included with the request. This will trigger only with a result
  *     from the request it was provided with.
  * - A global listener provided by {@link #registerForAllProfilingResults}. This will be triggered
- *     for all results belonging to your app.
+ *     for all results belonging to your app. This listener is the only way to receive results from
+ *     system triggered profiling instances set up with {@link #addProfilingTriggers}.
  * </p>
  *
  * <p>
  * Requests are rate limited and not guaranteed to be filled. Rate limiting can be disabled for
- * local testing using the shell command
+ * local testing of {@link #requestProfiling} using the shell command
  * {@code device_config put profiling_testing rate_limiter.disabled true}
  * </p>
  *
  * <p>
+ * In order to test profiling triggers, enable testing mode for your app with the shell command
+ * {@code device_config put profiling_testing system_triggered_profiling.testing_package_name
+ * com.your.app} which will:
+ * - Ensure that a background trace is running.
+ * - Allow all triggers for the provided package name to pass the system level rate limiter.
+ * This mode will continue until manually stopped with the shell command
+ * {@code device_config delete profiling_testing system_triggered_profiling.testing_package_name}
+ * </p>
+ *
+ * <p>
  * Results are redacted and contain specific information about the requesting process only.
  * </p>
  */
@@ -256,7 +272,9 @@ public final class ProfilingManager {
                 if (service == null) {
                     executor.execute(() -> listener.accept(
                             new ProfilingResult(ProfilingResult.ERROR_UNKNOWN, null, tag,
-                                "ProfilingService is not available")));
+                                "ProfilingService is not available",
+                                Flags.systemTriggeredProfilingNew()
+                                        ? ProfilingTrigger.TRIGGER_TYPE_NONE : 0)));
                     if (DEBUG) Log.d(TAG, "ProfilingService is not available");
                     return;
                 }
@@ -265,15 +283,16 @@ public final class ProfilingManager {
                 if (packageName == null) {
                     executor.execute(() -> listener.accept(
                             new ProfilingResult(ProfilingResult.ERROR_UNKNOWN, null, tag,
-                                    "Failed to resolve package name")));
+                                    "Failed to resolve package name",
+                                    Flags.systemTriggeredProfilingNew()
+                                            ? ProfilingTrigger.TRIGGER_TYPE_NONE : 0)));
                     if (DEBUG) Log.d(TAG, "Failed to resolve package name.");
                     return;
                 }
 
                 // For key, use most and least significant bits so we can create an identical UUID
                 // after passing over binder.
-                service.requestProfiling(profilingType, parameters,
-                        mContext.getFilesDir().getPath(), tag,
+                service.requestProfiling(profilingType, parameters, tag,
                         key.getMostSignificantBits(), key.getLeastSignificantBits(),
                         packageName);
                 if (cancellationSignal != null) {
@@ -294,7 +313,9 @@ public final class ProfilingManager {
                 if (DEBUG) Log.d(TAG, "Binder exception processing request", e);
                 executor.execute(() -> listener.accept(
                         new ProfilingResult(ProfilingResult.ERROR_UNKNOWN, null, tag,
-                                "Binder exception processing request")));
+                                "Binder exception processing request",
+                                Flags.systemTriggeredProfilingNew()
+                                        ? ProfilingTrigger.TRIGGER_TYPE_NONE : 0)));
                 throw new RuntimeException("Unable to request profiling.");
             }
         }
@@ -324,7 +345,9 @@ public final class ProfilingManager {
                 // not ever be triggered.
                 executor.execute(() -> listener.accept(new ProfilingResult(
                         ProfilingResult.ERROR_UNKNOWN, null, null,
-                        "Binder exception processing request")));
+                        "Binder exception processing request",
+                        Flags.systemTriggeredProfilingNew()
+                                ? ProfilingTrigger.TRIGGER_TYPE_NONE : 0)));
                 return;
             }
             mCallbacks.add(new ProfilingRequestCallbackWrapper(executor, listener, null));
@@ -385,6 +408,125 @@ public final class ProfilingManager {
         }
     }
 
+    /**
+     * Register the provided list of triggers for this process.
+     *
+     * Profiling triggers are system triggered events that an app can register interest in receiving
+     * profiling of. There is no guarantee that these triggers will be filled. Results, if
+     * available, will be delivered only to a global listener added using
+     * {@link #registerForAllProfilingResults}.
+     *
+     * Only one of each trigger type can be added at a time.
+     * - If the provided list contains a trigger type that is already registered then the new one
+     *      will replace the existing one.
+     * - If the provided list contains more than one trigger object for a trigger type then only one
+     *      will be kept.
+     */
+    @FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void addProfilingTriggers(@NonNull List<ProfilingTrigger> triggers) {
+        synchronized (mLock) {
+            if (triggers.isEmpty()) {
+                // No triggers are being added, nothing to do.
+                if (DEBUG) Log.d(TAG, "Trying to add an empty list of triggers.");
+                return;
+            }
+
+            final IProfilingService service = getOrCreateIProfilingServiceLocked(false);
+            if (service == null) {
+                // If we can't access service then we can't do anything. Return.
+                if (DEBUG) Log.d(TAG, "ProfilingService is not available, triggers will be lost.");
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
+                service.addProfilingTriggers(toValueParcelList(triggers), packageName);
+            } catch (RemoteException e) {
+                if (DEBUG) Log.d(TAG, "Binder exception processing request", e);
+                throw new RuntimeException("Unable to add profiling triggers.");
+            }
+        }
+    }
+
+    @FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    private List<ProfilingTriggerValueParcel> toValueParcelList(
+            List<ProfilingTrigger> triggerList) {
+        List<ProfilingTriggerValueParcel> triggerValueParcelList =
+                new ArrayList<ProfilingTriggerValueParcel>();
+
+        for (int i = 0; i < triggerList.size(); i++) {
+            triggerValueParcelList.add(triggerList.get(i).toValueParcel());
+        }
+
+        return triggerValueParcelList;
+    }
+
+    /** Remove triggers for this process with trigger types in the provided list. */
+    @FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void removeProfilingTriggersByType(@NonNull @TriggerType int[] triggers) {
+        synchronized (mLock) {
+            if (triggers.length == 0) {
+                // No triggers are being removed, nothing to do.
+                if (DEBUG) Log.d(TAG, "Trying to remove an empty list of triggers.");
+                return;
+            }
+
+            final IProfilingService service = getOrCreateIProfilingServiceLocked(false);
+            if (service == null) {
+                // If we can't access service then we can't do anything. Return.
+                if (DEBUG) {
+                    Log.d(TAG, "ProfilingService is not available, triggers will not be removed.");
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
+                service.removeProfilingTriggers(triggers, packageName);
+            } catch (RemoteException e) {
+                if (DEBUG) Log.d(TAG, "Binder exception processing request", e);
+                throw new RuntimeException("Unable to remove profiling triggers.");
+            }
+        }
+    }
+
+    /** Remove all triggers for this process. */
+    @FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void clearProfilingTriggers() {
+        synchronized (mLock) {
+            final IProfilingService service = getOrCreateIProfilingServiceLocked(false);
+            if (service == null) {
+                // If we can't access service then we can't do anything. Return.
+                if (DEBUG) {
+                    Log.d(TAG, "ProfilingService is not available, triggers will not be removed.");
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
+                service.clearProfilingTriggers(packageName);
+            } catch (RemoteException e) {
+                if (DEBUG) Log.d(TAG, "Binder exception processing request", e);
+                throw new RuntimeException("Unable to clear profiling triggers.");
+            }
+        }
+    }
 
     /** @hide */
     @VisibleForTesting
@@ -461,7 +603,10 @@ public final class ProfilingManager {
                                     wrapper.mExecutor.execute(() -> wrapper.mListener.accept(
                                             new ProfilingResult(overrideStatusToError
                                                     ? ProfilingResult.ERROR_UNKNOWN : status,
-                                                    resultFile, tag, error)));
+                                                    getAppFileDir() + resultFile, tag, error,
+                                                    Flags.systemTriggeredProfilingNew()
+                                                            ? ProfilingTrigger.TRIGGER_TYPE_NONE
+                                                            : 0)));
                                 }
 
                                 // Remove the single listener that was tied to the request, if
@@ -484,9 +629,10 @@ public final class ProfilingManager {
                          * write to the generated file.
                          */
                         @Override
-                        public void generateFile(String filePathAbsolute, String fileName,
+                        public void generateFile(String filePathRelative, String fileName,
                                 long keyMostSigBits, long keyLeastSigBits) {
                             synchronized (mLock) {
+                                String filePathAbsolute = getAppFileDir() + filePathRelative;
                                 try {
                                     // Ensure the profiling directory exists. Create it if it
                                     // doesn't.
@@ -574,13 +720,17 @@ public final class ProfilingManager {
                          * Delete a file. To be used only for files created by {@link generateFile}.
                          */
                         @Override
-                        public void deleteFile(String filePathAndName) {
+                        public void deleteFile(String relativeFilePathAndName) {
                             try {
-                                Files.delete(Path.of(filePathAndName));
+                                Files.delete(Path.of(getAppFileDir() + relativeFilePathAndName));
                             } catch (Exception exception) {
                                 if (DEBUG) Log.e(TAG, "Failed to delete file.", exception);
                             }
                         }
+
+                        private String getAppFileDir() {
+                            return mContext.getFilesDir().getPath();
+                        }
                     });
         } catch (RemoteException e) {
             if (DEBUG) Log.d(TAG, "Exception registering service callback", e);
diff --git a/framework/java/android/os/ProfilingResult.java b/framework/java/android/os/ProfilingResult.java
index 61357e1..0ed84ea 100644
--- a/framework/java/android/os/ProfilingResult.java
+++ b/framework/java/android/os/ProfilingResult.java
@@ -43,6 +43,9 @@ public final class ProfilingResult implements Parcelable {
     /** @see #getErrorMessage */
     @Nullable final String mErrorMessage;
 
+    /** @see #getTriggerType */
+    final int mTriggerType;
+
     /** The request was executed and succeeded. */
     public static final int ERROR_NONE = 0;
 
@@ -85,11 +88,12 @@ public final class ProfilingResult implements Parcelable {
     @interface ErrorCode {}
 
     ProfilingResult(@ErrorCode int errorCode, String resultFilePath, String tag,
-            String errorMessage) {
+            String errorMessage, int triggerType) {
         mErrorCode = errorCode;
         mResultFilePath = resultFilePath;
         mTag = tag;
         mErrorMessage = errorMessage;
+        mTriggerType = triggerType;
     }
 
     private ProfilingResult(@NonNull Parcel in) {
@@ -97,6 +101,7 @@ public final class ProfilingResult implements Parcelable {
         mResultFilePath = in.readString();
         mTag = in.readString();
         mErrorMessage = in.readString();
+        mTriggerType = in.readInt();
     }
 
     @Override
@@ -105,6 +110,7 @@ public final class ProfilingResult implements Parcelable {
         dest.writeString(mResultFilePath);
         dest.writeString(mTag);
         dest.writeString(mErrorMessage);
+        dest.writeInt(mTriggerType);
     }
 
     @Override
@@ -154,4 +160,13 @@ public final class ProfilingResult implements Parcelable {
     public @Nullable String getErrorMessage() {
         return mErrorMessage;
     }
+
+    /**
+     * Trigger type that started this profiling, or {@link ProfilingTrigger#TRIGGER_TYPE_NONE} for
+     * profiling not started by a trigger.
+     */
+    @FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public int getTriggerType() {
+        return mTriggerType;
+    }
 }
diff --git a/framework/java/android/os/ProfilingServiceHelper.java b/framework/java/android/os/ProfilingServiceHelper.java
new file mode 100644
index 0000000..9c2c588
--- /dev/null
+++ b/framework/java/android/os/ProfilingServiceHelper.java
@@ -0,0 +1,93 @@
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
+package android.os;
+
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.annotation.SystemApi;
+import android.annotation.SystemApi.Client;
+import android.os.profiling.Flags;
+import android.util.Log;
+
+import com.android.internal.annotations.GuardedBy;
+
+/**
+ * Class for system to interact with {@link ProfilingService} to notify of trigger occurrences.
+ *
+ * @hide
+ */
+@FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+@SystemApi(client = Client.MODULE_LIBRARIES)
+public class ProfilingServiceHelper {
+    private static final String TAG = ProfilingServiceHelper.class.getSimpleName();
+    private static final boolean DEBUG = false;
+
+    private static final Object sLock = new Object();
+
+    @Nullable
+    @GuardedBy("sLock")
+    private static ProfilingServiceHelper sInstance;
+
+    private final Object mLock = new Object();
+
+    @NonNull
+    @GuardedBy("mLock")
+    private final IProfilingService mProfilingService;
+
+    private ProfilingServiceHelper(@NonNull IProfilingService service) {
+        mProfilingService = service;
+    }
+
+    /**
+     * Returns an instance of {@link ProfilingServiceHelper}.
+     *
+     * @throws IllegalStateException if called before ProfilingService is set up.
+     */
+    @NonNull
+    public static ProfilingServiceHelper getInstance() {
+        synchronized (sLock) {
+            if (sInstance != null) {
+                return sInstance;
+            }
+
+            IProfilingService service = Flags.telemetryApis() ? IProfilingService.Stub.asInterface(
+                    ProfilingFrameworkInitializer.getProfilingServiceManager()
+                            .getProfilingServiceRegisterer().get()) : null;
+
+            if (service == null) {
+                throw new IllegalStateException("ProfilingService not yet set up.");
+            }
+
+            sInstance = new ProfilingServiceHelper(service);
+
+            return sInstance;
+        }
+    }
+
+    /** Send a trigger to {@link ProfilingService}. */
+    public void onProfilingTriggerOccurred(int uid, @NonNull String packageName, int triggerType) {
+        synchronized (mLock) {
+            try {
+                mProfilingService.processTrigger(uid, packageName, triggerType);
+            } catch (RemoteException e) {
+                // Exception sending trigger to service. Nothing to do here, trigger will be lost.
+                if (DEBUG) Log.e(TAG, "Exception sending trigger", e);
+            }
+        }
+    }
+}
diff --git a/framework/java/android/os/ProfilingTrigger.java b/framework/java/android/os/ProfilingTrigger.java
new file mode 100644
index 0000000..1a6bd3a
--- /dev/null
+++ b/framework/java/android/os/ProfilingTrigger.java
@@ -0,0 +1,163 @@
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
+package android.os;
+
+import android.annotation.FlaggedApi;
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.os.profiling.Flags;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+
+/**
+ * Encapsulates a single profiling trigger.
+ */
+@FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+public final class ProfilingTrigger {
+
+    /** No trigger. Used in {@link ProfilingResult} for non trigger caused results. */
+    public static final int TRIGGER_TYPE_NONE = 0;
+
+    /** Trigger occurs after {@link Activity#reportFullyDrawn} is called for a cold start. */
+    public static final int TRIGGER_TYPE_APP_FULLY_DRAWN = 1;
+
+    /** Trigger occurs after the app was killed due to an ANR */
+    public static final int TRIGGER_TYPE_ANR = 2;
+
+    /** @hide */
+    @IntDef(value = {
+        TRIGGER_TYPE_NONE,
+        TRIGGER_TYPE_APP_FULLY_DRAWN,
+        TRIGGER_TYPE_ANR,
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    @interface TriggerType {}
+
+    /** @see #getTriggerType */
+    private final @TriggerType int mTriggerType;
+
+    /** @see #getRateLimitingPeriodHours  */
+    private final int mRateLimitingPeriodHours;
+
+    private ProfilingTrigger(@TriggerType int triggerType, int rateLimitingPeriodHours) {
+        mTriggerType = triggerType;
+        mRateLimitingPeriodHours = rateLimitingPeriodHours;
+    }
+
+    /**
+     * Builder class to create a {@link ProfilingTrigger} object.
+     */
+    @FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public static final class Builder {
+        // Trigger type has to be set, so make it an object and set to null.
+        private int mBuilderTriggerType;
+
+        // Rate limiter period default is 0 which will make it do nothing.
+        private int mBuilderRateLimitingPeriodHours = 0;
+
+        /**
+         * Create a new builder instance to create a {@link ProfilingTrigger} object.
+         *
+         * Requires a trigger type. An app can only have one registered trigger per trigger type.
+         * Adding a new trigger with the same type will override the previously set one.
+         *
+         * @throws IllegalArgumentException if the trigger type is not valid.
+         */
+        public Builder(@TriggerType int triggerType) {
+            if (!isValidRequestTriggerType(triggerType)) {
+                throw new IllegalArgumentException("Invalid trigger type.");
+            }
+
+            mBuilderTriggerType = triggerType;
+        }
+
+        /** Build the {@link ProfilingTrigger} object. */
+        @NonNull
+        public ProfilingTrigger build() {
+            return new ProfilingTrigger(mBuilderTriggerType,
+                    mBuilderRateLimitingPeriodHours);
+        }
+
+        /**
+         * Set a rate limiting period in hours.
+         *
+         * The period is the minimum time the system should wait before providing another
+         * profiling result for the same trigger; actual time between events may be longer.
+         *
+         * If the rate limiting period is not provided or set to 0, no app-provided rate limiting
+         * will be used.
+         *
+         * This rate limiting is in addition to any system level rate limiting that may be applied.
+         *
+         * @throws IllegalArgumentException if the value is less than 0.
+         */
+        @NonNull
+        public Builder setRateLimitingPeriodHours(int rateLimitingPeriodHours) {
+            if (rateLimitingPeriodHours < 0) {
+                throw new IllegalArgumentException("Hours can't be negative. Try again.");
+            }
+
+            mBuilderRateLimitingPeriodHours = rateLimitingPeriodHours;
+            return this;
+        }
+    }
+
+    /** The trigger type indicates which event should trigger the requested profiling. */
+    public @TriggerType int getTriggerType() {
+        return mTriggerType;
+    }
+
+    /**
+     * The requester set rate limiting period in hours.
+     *
+     * The period is the minimum time the system should wait before providing another
+     * profiling result for the same trigger; actual time between events may be longer.
+     *
+     * If the rate limiting period is set to 0, no app-provided rate limiting will be used.
+     *
+     * This rate limiting is in addition to any system level rate limiting that may be applied.
+     */
+    public int getRateLimitingPeriodHours() {
+        return mRateLimitingPeriodHours;
+    }
+
+    /**
+     * Convert to value parcel. Used for binder.
+     *
+     * @hide
+     */
+    public ProfilingTriggerValueParcel toValueParcel() {
+        ProfilingTriggerValueParcel valueParcel = new ProfilingTriggerValueParcel();
+
+        valueParcel.triggerType = mTriggerType;
+        valueParcel.rateLimitingPeriodHours = mRateLimitingPeriodHours;
+
+        return valueParcel;
+    }
+
+    /**
+     * Check whether the trigger type is valid for request use. Note that this means that a value of
+     * {@link TRIGGER_TYPE_NONE} will return false.
+     *
+     * @hide
+     */
+    public static boolean isValidRequestTriggerType(int triggerType) {
+        return triggerType == TRIGGER_TYPE_APP_FULLY_DRAWN
+                || triggerType == TRIGGER_TYPE_ANR;
+    }
+
+}
diff --git a/framework/java/android/os/flags.aconfig b/framework/java/android/os/flags.aconfig
index 8614494..1b21e88 100644
--- a/framework/java/android/os/flags.aconfig
+++ b/framework/java/android/os/flags.aconfig
@@ -20,3 +20,20 @@ flag {
         purpose: PURPOSE_BUGFIX
      }
 }
+
+flag {
+     name: "persist_queue"
+     namespace: "system_performance"
+     is_exported: true
+     description: "Enables profiling queue persist and restore."
+     bug: "342435438"
+}
+
+flag {
+     name: "system_triggered_profiling_new"
+     namespace: "system_performance"
+     is_exported: true
+     description: "Enables system triggered profiling apis and functionality."
+     is_fixed_read_only: true
+     bug: "373461116"
+}
diff --git a/service/Android.bp b/service/Android.bp
index a8edfde..4f8bfd5 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -35,7 +35,7 @@ java_library {
     ],
     static_libs: [
         "modules-utils-build",
-        "android.os.profiling.flags-aconfig-java",
+        "profiling_flags_lib",
         "service-profiling-proto",
         "perfetto_config_java_protos_system_server_current",
     ],
diff --git a/service/java/com/android/os/profiling/Configs.java b/service/java/com/android/os/profiling/Configs.java
index bbc6f77..27225ca 100644
--- a/service/java/com/android/os/profiling/Configs.java
+++ b/service/java/com/android/os/profiling/Configs.java
@@ -39,11 +39,20 @@ public final class Configs {
     // value is used to calculate max profiling time.
     private static final int MAX_PROFILING_TIME_BUFFER_MS = 10 * 1000;
 
+    private static final int FOUR_MB = 4096;
+
+    private static final int ONE_DAY_MS = 24 * 60 * 60 * 1000;
+
+    private static boolean sSystemTriggeredSystemTraceConfigsInitialized = false;
     private static boolean sSystemTraceConfigsInitialized = false;
     private static boolean sHeapProfileConfigsInitialized = false;
     private static boolean sJavaHeapDumpConfigsInitialized = false;
     private static boolean sStackSamplingConfigsInitialized = false;
 
+    private static int sSystemTriggeredSystemTraceDurationMs;
+    private static int sSystemTriggeredSystemTraceDiscardBufferSizeKb;
+    private static int sSystemTriggeredSystemTraceRingBufferSizeKb;
+
     private static boolean sKillswitchSystemTrace;
     private static int sSystemTraceDurationMsDefault;
     private static int sSystemTraceDurationMsMin;
@@ -84,6 +93,29 @@ public final class Configs {
     private static int sStackSamplingSamplingFrequencyMin;
     private static int sStackSamplingSamplingFrequencyMax;
 
+    /**
+     * Initialize System Triggered System Trace related DeviceConfig values if they have not been
+     * yet.
+     */
+    private static void initializeSystemTriggeredSystemTraceConfigsIfNecessary() {
+        if (sSystemTriggeredSystemTraceConfigsInitialized) {
+            return;
+        }
+
+        DeviceConfig.Properties properties =
+                DeviceConfigHelper.getAllSystemTriggeredSystemTraceProperties();
+
+        sSystemTriggeredSystemTraceDurationMs = properties.getInt(
+                DeviceConfigHelper.SYSTEM_TRIGGERED_SYSTEM_TRACE_DURATION_MS,
+                30 * 60 * 1000 /* 30 minutes */);
+        sSystemTriggeredSystemTraceDiscardBufferSizeKb = properties.getInt(
+                DeviceConfigHelper.SYSTEM_TRIGGERED_SYSTEM_TRACE_DISCARD_BUFFER_SIZE_KB, FOUR_MB);
+        sSystemTriggeredSystemTraceRingBufferSizeKb = properties.getInt(
+                DeviceConfigHelper.SYSTEM_TRIGGERED_SYSTEM_TRACE_RING_BUFFER_SIZE_KB, 32768);
+
+        sSystemTriggeredSystemTraceConfigsInitialized = true;
+    }
+
     /** Initialize System Trace related DeviceConfig set values if they have not been yet. */
     private static void initializeSystemTraceConfigsIfNecessary() {
         if (sSystemTraceConfigsInitialized) {
@@ -730,16 +762,58 @@ public final class Configs {
             int durationMs, TraceConfig.BufferConfig.FillPolicy bufferFillPolicy) {
         TraceConfig.Builder builder = TraceConfig.newBuilder();
 
-        // Add 2 buffers, discard for data sources dumped at beginning and ring for contiuously
-        // updated data sources.
+        addSystemTraceGeneralConfigs(
+                builder,
+                new String[] {packageName},
+                FOUR_MB,
+                bufferSizeKb,
+                durationMs,
+                bufferFillPolicy);
+
+        return builder.build().toByteArray();
+    }
+
+    /**
+     * Generate config for system triggered background system trace.
+     *
+     * @param extraLong should only be set to true for testing.
+     */
+    public static byte[] generateSystemTriggeredTraceConfig(String uniqueSessionName,
+            String[] packageNames, boolean extraLong) {
+        // Make sure we have our config values set. This is the only config specific method which is
+        // called directly and therefore needs to verify the config value initialization directly.
+        initializeSystemTriggeredSystemTraceConfigsIfNecessary();
+
+        TraceConfig.Builder builder = TraceConfig.newBuilder();
+
+        addSystemTraceGeneralConfigs(
+                builder,
+                packageNames,
+                sSystemTriggeredSystemTraceDiscardBufferSizeKb,
+                sSystemTriggeredSystemTraceRingBufferSizeKb,
+                extraLong
+                        ? ONE_DAY_MS
+                        : sSystemTriggeredSystemTraceDurationMs,
+                TraceConfig.BufferConfig.FillPolicy.RING_BUFFER);
+
+        builder.setUniqueSessionName(uniqueSessionName);
+
+        return builder.build().toByteArray();
+    }
+
+    private static void addSystemTraceGeneralConfigs(TraceConfig.Builder builder,
+            String[] packageNames, int bufferOneSizeKb, int bufferTwoSizeKb, int durationMs,
+            TraceConfig.BufferConfig.FillPolicy bufferTwoFillPolicy) {
+        // Add 2 buffers, discard for data sources dumped at beginning and caller set for all other
+        // data sources.
         TraceConfig.BufferConfig buffer0 = TraceConfig.BufferConfig.newBuilder()
-                .setSizeKb(4096)
+                .setSizeKb(bufferOneSizeKb)
                 .setFillPolicy(TraceConfig.BufferConfig.FillPolicy.DISCARD)
                 .build();
         builder.addBuffers(buffer0);
         TraceConfig.BufferConfig buffer1 = TraceConfig.BufferConfig.newBuilder()
-                .setSizeKb(bufferSizeKb)
-                .setFillPolicy(bufferFillPolicy)
+                .setSizeKb(bufferTwoSizeKb)
+                .setFillPolicy(bufferTwoFillPolicy)
                 .build();
         builder.addBuffers(buffer1);
 
@@ -759,14 +833,27 @@ public final class Configs {
                 .build();
         builder.addDataSources(dataSourceProcessStats);
 
-        // Dump details about the requesting package to buffer 0
-        PackagesListConfig packagesListConfig = PackagesListConfig.newBuilder()
-                .addPackageNameFilter(packageName)
-                .build();
+        // Initialize the builders that require package names so we only need to iterate through the
+        // list once. These will be used in the following two sections.
+        PackagesListConfig.Builder packagesListConfigBuilder = PackagesListConfig.newBuilder();
+        FtraceConfig.Builder ftraceConfigBuilder = FtraceConfig.newBuilder();
+
+        for (int i = 0; i < packageNames.length; i++) {
+            String packageName = packageNames[i];
+
+            // Enable atrace events for each app.
+            ftraceConfigBuilder.addAtraceApps(packageName);
+
+            // Add to package list config so data is kept by filter.
+            packagesListConfigBuilder.addPackageNameFilter(packageName);
+        }
+
+        // Dump details about all listed packages to buffer 0. Redactor will filter out the ones
+        // that should not end up in the finished output.
         DataSourceConfig dataSourceConfigPackagesList = DataSourceConfig.newBuilder()
                 .setName("android.packages_list")
                 .setTargetBuffer(0)
-                .setPackagesListConfig(packagesListConfig)
+                .setPackagesListConfig(packagesListConfigBuilder.build())
                 .build();
         TraceConfig.DataSource dataSourcePackagesList = TraceConfig.DataSource.newBuilder()
                 .setConfig(dataSourceConfigPackagesList)
@@ -778,7 +865,7 @@ public final class Configs {
                 .newBuilder()
                 .setEnabled(true)
                 .build();
-        FtraceConfig ftraceConfig = FtraceConfig.newBuilder()
+        ftraceConfigBuilder
                 .setThrottleRssStat(true)
                 .setDisableGenericEvents(true)
                 .setCompactSched(compactSchedConfig)
@@ -812,14 +899,12 @@ public final class Configs {
                 // Input:
                 .addAtraceCategories("input")
                 // Graphics:
-                .addAtraceCategories("gfx")
-                // Enable events for requesting app only:
-                .addAtraceApps(packageName)
-                .build();
+                .addAtraceCategories("gfx");
+
         DataSourceConfig dataSourceConfigFtrace = DataSourceConfig.newBuilder()
                 .setName("linux.ftrace")
                 .setTargetBuffer(1)
-                .setFtraceConfig(ftraceConfig)
+                .setFtraceConfig(ftraceConfigBuilder.build())
                 .build();
         TraceConfig.DataSource dataSourceFtrace = TraceConfig.DataSource.newBuilder()
                 .setConfig(dataSourceConfigFtrace)
@@ -845,8 +930,6 @@ public final class Configs {
 
         // Add duration
         builder.setDurationMs(durationMs);
-
-        return builder.build().toByteArray();
     }
 
 }
diff --git a/service/java/com/android/os/profiling/DeviceConfigHelper.java b/service/java/com/android/os/profiling/DeviceConfigHelper.java
index f563166..6a52825 100644
--- a/service/java/com/android/os/profiling/DeviceConfigHelper.java
+++ b/service/java/com/android/os/profiling/DeviceConfigHelper.java
@@ -33,6 +33,8 @@ public final class DeviceConfigHelper {
     public static final String RATE_LIMITER_DISABLE_PROPERTY = "rate_limiter.disabled";
     public static final String DISABLE_DELETE_UNREDACTED_TRACE =
             "delete_unredacted_trace.disabled";
+    public static final String SYSTEM_TRIGGERED_TEST_PACKAGE_NAME =
+            "system_triggered_profiling.testing_package_name";
 
     // End section: Testing specific constants
 
@@ -102,6 +104,16 @@ public final class DeviceConfigHelper {
     public static final String STACK_SAMPLING_FREQUENCY_MIN = "stack_sampling_frequency_min";
     public static final String STACK_SAMPLING_FREQUENCY_MAX = "stack_sampling_frequency_max";
 
+    // System Triggered System Trace
+    public static final String COST_SYSTEM_TRIGGERED_SYSTEM_TRACE =
+            "cost_system_triggered_system_trace";
+    public static final String SYSTEM_TRIGGERED_SYSTEM_TRACE_DURATION_MS =
+            "system_triggered_system_trace_duration_ms";
+    public static final String SYSTEM_TRIGGERED_SYSTEM_TRACE_DISCARD_BUFFER_SIZE_KB =
+            "system_triggered_system_trace_discard_buffer_size_kb";
+    public static final String SYSTEM_TRIGGERED_SYSTEM_TRACE_RING_BUFFER_SIZE_KB =
+            "system_triggered_system_trace_ring_buffer_size_kb";
+
     // Rate limiter configs
     public static final String PERSIST_TO_DISK_FREQUENCY_MS = "persist_to_disk_frequency_ms";
     public static final String MAX_COST_SYSTEM_1_HOUR = "max_cost_system_1_hour";
@@ -121,6 +133,12 @@ public final class DeviceConfigHelper {
     public static final String CLEAR_TEMPORARY_DIRECTORY_BOOT_DELAY_MS =
             "clear_temporary_directory_boot_delay_ms";
 
+    // System triggered run configs
+    public static final String SYSTEM_TRIGGERED_TRACE_MIN_PERIOD_SECONDS =
+            "system_triggered_trace_min_period_seconds";
+    public static final String SYSTEM_TRIGGERED_TRACE_MAX_PERIOD_SECONDS =
+            "system_triggered_trace_max_period_seconds";
+
     // Post Processing Configs
     public static final String PROFILING_RECHECK_DELAY_MS = "profiling_recheck_delay_ms";
 
@@ -227,6 +245,14 @@ public final class DeviceConfigHelper {
                 SYSTEM_TRACE_SIZE_KB_MAX);
     }
 
+    /** Get all properties related to System Triggered System Trace configuration. */
+    public static DeviceConfig.Properties getAllSystemTriggeredSystemTraceProperties() {
+        return DeviceConfig.getProperties(NAMESPACE,
+                SYSTEM_TRIGGERED_SYSTEM_TRACE_DURATION_MS,
+                SYSTEM_TRIGGERED_SYSTEM_TRACE_DISCARD_BUFFER_SIZE_KB,
+                SYSTEM_TRIGGERED_SYSTEM_TRACE_RING_BUFFER_SIZE_KB);
+    }
+
     /** Get all properties related to rate limiter. */
     public static DeviceConfig.Properties getAllRateLimiterProperties() {
         return DeviceConfig.getProperties(NAMESPACE,
@@ -240,6 +266,7 @@ public final class DeviceConfigHelper {
                 COST_HEAP_PROFILE,
                 COST_STACK_SAMPLING,
                 COST_SYSTEM_TRACE,
+                COST_SYSTEM_TRIGGERED_SYSTEM_TRACE,
                 PERSIST_TO_DISK_FREQUENCY_MS);
     }
 
diff --git a/service/java/com/android/os/profiling/ProcessMap.java b/service/java/com/android/os/profiling/ProcessMap.java
new file mode 100644
index 0000000..1868ef9
--- /dev/null
+++ b/service/java/com/android/os/profiling/ProcessMap.java
@@ -0,0 +1,61 @@
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
+package android.os.profiling;
+
+import android.util.ArrayMap;
+import android.util.SparseArray;
+
+/**
+ * This is a copy/paste of {@link com.android.internal.app.ProcessMap} with change:
+ * - remove does not return the removed object which leveraged a hidden SparseArray API.
+ */
+public class ProcessMap<E> {
+    final ArrayMap<String, SparseArray<E>> mMap = new ArrayMap<String, SparseArray<E>>();
+
+    public E get(String name, int uid) {
+        SparseArray<E> uids = mMap.get(name);
+        if (uids == null) return null;
+        return uids.get(uid);
+    }
+
+    public void put(String name, int uid, E value) {
+        SparseArray<E> uids = mMap.get(name);
+        if (uids == null) {
+            uids = new SparseArray<E>(1);
+            mMap.put(name, uids);
+        }
+        uids.put(uid, value);
+    }
+
+    public void remove(String name, int uid) {
+        SparseArray<E> uids = mMap.get(name);
+        if (uids != null) {
+            uids.remove(uid);
+            if (uids.size() == 0) {
+                mMap.remove(name);
+            }
+        }
+    }
+
+    public ArrayMap<String, SparseArray<E>> getMap() {
+        return mMap;
+    }
+
+    public int size() {
+        return mMap.size();
+    }
+}
diff --git a/service/java/com/android/os/profiling/ProfilingService.java b/service/java/com/android/os/profiling/ProfilingService.java
index 565b442..9fdbc86 100644
--- a/service/java/com/android/os/profiling/ProfilingService.java
+++ b/service/java/com/android/os/profiling/ProfilingService.java
@@ -24,6 +24,7 @@ import android.icu.util.Calendar;
 import android.icu.util.TimeZone;
 import android.os.Binder;
 import android.os.Bundle;
+import android.os.Environment;
 import android.os.FileUtils;
 import android.os.Handler;
 import android.os.HandlerThread;
@@ -33,10 +34,14 @@ import android.os.IProfilingService;
 import android.os.ParcelFileDescriptor;
 import android.os.ProfilingManager;
 import android.os.ProfilingResult;
+import android.os.ProfilingTriggerValueParcel;
+import android.os.ProfilingTriggersWrapper;
+import android.os.QueuedResultsWrapper;
 import android.os.RemoteException;
 import android.provider.DeviceConfig;
 import android.text.TextUtils;
 import android.util.ArrayMap;
+import android.util.AtomicFile;
 import android.util.Log;
 import android.util.SparseArray;
 
@@ -52,10 +57,18 @@ import java.io.IOException;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.List;
 import java.util.Locale;
+import java.util.Random;
+import java.util.Set;
 import java.util.UUID;
+import java.util.concurrent.Executors;
+import java.util.concurrent.ScheduledExecutorService;
+import java.util.concurrent.ScheduledFuture;
 import java.util.concurrent.TimeUnit;
+import java.util.concurrent.atomic.AtomicInteger;
+import java.util.function.Consumer;
 
 public class ProfilingService extends IProfilingService.Stub {
     private static final String TAG = ProfilingService.class.getSimpleName();
@@ -71,6 +84,16 @@ public class ProfilingService extends IProfilingService.Stub {
     private static final String OUTPUT_FILE_STACK_SAMPLING_SUFFIX = ".perfetto-stack-sample";
     private static final String OUTPUT_FILE_TRACE_SUFFIX = ".perfetto-trace";
     private static final String OUTPUT_FILE_UNREDACTED_TRACE_SUFFIX = ".perfetto-trace-unredacted";
+    private static final String OUTPUT_FILE_TRIGGER = "trigger";
+    private static final String OUTPUT_FILE_IN_PROGRESS = "in-progress";
+
+    private static final String PERSIST_SYSTEM_DIR = "system";
+    private static final String PERSIST_STORE_DIR = "profiling_service_data";
+    private static final String QUEUED_RESULTS_INFO_FILE = "profiling_queued_results_info";
+    private static final String APP_TRIGGERS_INFO_FILE = "profiling_app_triggers_info";
+
+    // Used for unique session name only, not filename.
+    private static final String SYSTEM_TRIGGERED_SESSION_NAME_PREFIX = "system_triggered_session_";
 
     private static final int TAG_MAX_CHARS_FOR_FILENAME = 20;
 
@@ -94,6 +117,12 @@ public class ProfilingService extends IProfilingService.Stub {
     @VisibleForTesting
     public static final int QUEUED_RESULT_MAX_RETAINED_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
 
+    private static final int PERSIST_TO_DISK_DEFAULT_FREQUENCY_MS = 30 * 60 * 1000;
+
+    // Targeting a period of around 24 hours, so set max and min to 24 +/- 6 hours, respectively.
+    private static final int DEFAULT_SYSTEM_TRIGGERED_TRACE_MIN_PERIOD_SECONDS = 18 * 60 * 60;
+    private static final int DEFAULT_SYSTEM_TRIGGERED_TRACE_MAX_PERIOD_SECONDS = 30 * 60 * 60;
+
     private final Context mContext;
     private final Object mLock = new Object();
     private final HandlerThread mHandlerThread = new HandlerThread("ProfilingService");
@@ -127,15 +156,77 @@ public class ProfilingService extends IProfilingService.Stub {
     @VisibleForTesting
     public ArrayMap<String, TracingSession> mActiveTracingSessions = new ArrayMap<>();
 
+    // System triggered trace is another actively running profiling session, but not included in
+    // the active sessions above as it's not associated with a TracingSession until it has been
+    // cloned.
+    @VisibleForTesting
+    public Process mSystemTriggeredTraceProcess = null;
+    @VisibleForTesting
+    public String mSystemTriggeredTraceUniqueSessionName = null;
+    private long mLastStartedSystemTriggeredTraceMs = 0;
+
+    // Map of uid + package name to a sparse array of trigger objects.
+    @VisibleForTesting
+    public ProcessMap<SparseArray<ProfilingTrigger>> mAppTriggers = new ProcessMap<>();
+    @VisibleForTesting
+    public boolean mAppTriggersLoaded = false;
+
     // uid indexed storage of completed tracing sessions that have not yet successfully handled the
     // result.
     @VisibleForTesting
     public SparseArray<List<TracingSession>> mQueuedTracingResults = new SparseArray<>();
 
+    private boolean mPersistScheduled = false;
+    // Frequency of 0 would result in immediate persist.
+    @GuardedBy("mLock")
+    private AtomicInteger mPersistFrequencyMs;
+    @GuardedBy("mLock")
+    private long mLastPersistedTimestampMs = 0L;
+    private Runnable mPersistRunnable = null;
+
+    /** The path to the directory which includes all persisted results from this class. */
+    @VisibleForTesting
+    public File mPersistStoreDir = null;
+
+    /** The queued results data file, persisted in the storage. */
+    @VisibleForTesting
+    public File mPersistQueueFile = null;
+
+    /** The app triggers results data file, persisted in the storage. */
+    @VisibleForTesting
+    public File mPersistAppTriggersFile = null;
+
     /** To be disabled for testing only. */
     @GuardedBy("mLock")
     private boolean mKeepUnredactedTrace = false;
 
+    /** Executor for scheduling system triggered profiling trace. */
+    private ScheduledExecutorService mScheduledExecutorService = null;
+
+    /** Future for the start system triggered trace. */
+    @VisibleForTesting
+    public ScheduledFuture<?> mStartSystemTriggeredTraceScheduledFuture = null;
+
+    @GuardedBy("mLock")
+    private AtomicInteger mSystemTriggeredTraceMinPeriodSeconds;
+    @GuardedBy("mLock")
+    private AtomicInteger mSystemTriggeredTraceMaxPeriodSeconds;
+
+    /**
+     * Package name of app being tested, or null if no app is being tested. To be used both for
+     * automated testing and developer manual testing.
+     *
+     * Setting this package name will:
+     * - Ensure a system triggered trace is always running.
+     * - Allow all triggers for the specified package name to be executed.
+     *
+     * This is not intended to be set directly. Instead, set this package name by using
+     * device_config commands described at {@link ProfilingManager}.
+     *
+     * There is no time limit on how long this can be left enabled for.
+     */
+    private String mTestPackageName = null;
+
     /**
      * State the {@link TracingSession} is in.
      *
@@ -159,8 +250,7 @@ public class ProfilingService extends IProfilingService.Stub {
      * CLEANED_UP - Local only, not in any data structure.
      */
     public enum TracingState {
-        // Intentionally skipping 0 since proto, which willl be used for persist, treats it as
-        // unset.
+        // Intentionally skipping 0 since proto, which will be used for persist, treats it as unset.
         REQUESTED(1),
         APPROVED(2),
         PROFILING_STARTED(3),
@@ -171,11 +261,27 @@ public class ProfilingService extends IProfilingService.Stub {
         NOTIFIED_REQUESTER(8),
         CLEANED_UP(9);
 
+        /** Data structure for efficiently mapping int values back to their enum values. */
+        private static List<TracingState> sStatesList;
+
+        static {
+            sStatesList = Arrays.asList(TracingState.values());
+        }
+
         private final int mValue;
         TracingState(int value) {
             mValue = value;
         }
 
+        /** Obtain TracingState from int value. */
+        public static TracingState of(int value) {
+            if (value < 1 || value >= sStatesList.size() + 1) {
+                return null;
+            }
+
+            return sStatesList.get(value - 1);
+        }
+
         public int getValue() {
             return mValue;
         }
@@ -213,7 +319,6 @@ public class ProfilingService extends IProfilingService.Stub {
                 DeviceConfigHelper.REDACTION_MAX_RUNTIME_ALLOTTED_MS,
                 REDACTION_DEFAULT_MAX_RUNTIME_ALLOTTED_MS);
 
-
         mHandlerThread.start();
 
         // Get initial value for whether unredacted trace should be retained.
@@ -221,6 +326,18 @@ public class ProfilingService extends IProfilingService.Stub {
         synchronized (mLock) {
             mKeepUnredactedTrace = DeviceConfigHelper.getTestBoolean(
                     DeviceConfigHelper.DISABLE_DELETE_UNREDACTED_TRACE, false);
+
+            mPersistFrequencyMs = new AtomicInteger(DeviceConfigHelper.getInt(
+                    DeviceConfigHelper.PERSIST_TO_DISK_FREQUENCY_MS,
+                    PERSIST_TO_DISK_DEFAULT_FREQUENCY_MS));
+
+            mSystemTriggeredTraceMinPeriodSeconds = new AtomicInteger(DeviceConfigHelper.getInt(
+                    DeviceConfigHelper.SYSTEM_TRIGGERED_TRACE_MIN_PERIOD_SECONDS,
+                    DEFAULT_SYSTEM_TRIGGERED_TRACE_MIN_PERIOD_SECONDS));
+
+            mSystemTriggeredTraceMaxPeriodSeconds = new AtomicInteger(DeviceConfigHelper.getInt(
+                    DeviceConfigHelper.SYSTEM_TRIGGERED_TRACE_MAX_PERIOD_SECONDS,
+                    DEFAULT_SYSTEM_TRIGGERED_TRACE_MAX_PERIOD_SECONDS));
         }
         // Now subscribe to updates on test config.
         DeviceConfig.addOnPropertiesChangedListener(DeviceConfigHelper.NAMESPACE_TESTING,
@@ -231,6 +348,10 @@ public class ProfilingService extends IProfilingService.Stub {
                             mKeepUnredactedTrace = properties.getBoolean(
                                     DeviceConfigHelper.DISABLE_DELETE_UNREDACTED_TRACE, false);
                             getRateLimiter().maybeUpdateRateLimiterDisabled(properties);
+
+                            String newTestPackageName = properties.getString(
+                                    DeviceConfigHelper.SYSTEM_TRIGGERED_TEST_PACKAGE_NAME, null);
+                            handleTestPackageChangeLocked(newTestPackageName);
                         }
                     }
                 });
@@ -272,18 +393,330 @@ public class ProfilingService extends IProfilingService.Stub {
                             mRedactionMaxRuntimeAllottedMs = properties.getInt(
                                     DeviceConfigHelper.REDACTION_MAX_RUNTIME_ALLOTTED_MS,
                                     mRedactionMaxRuntimeAllottedMs);
+
+                            mPersistFrequencyMs.set(properties.getInt(
+                                    DeviceConfigHelper.PERSIST_TO_DISK_FREQUENCY_MS,
+                                    mPersistFrequencyMs.get()));
+
+                            mSystemTriggeredTraceMinPeriodSeconds.set(DeviceConfigHelper.getInt(
+                                    DeviceConfigHelper.SYSTEM_TRIGGERED_TRACE_MIN_PERIOD_SECONDS,
+                                    mSystemTriggeredTraceMinPeriodSeconds.get()));
+
+                            mSystemTriggeredTraceMaxPeriodSeconds.set(DeviceConfigHelper.getInt(
+                                    DeviceConfigHelper.SYSTEM_TRIGGERED_TRACE_MAX_PERIOD_SECONDS,
+                                    mSystemTriggeredTraceMaxPeriodSeconds.get()));
                         }
                     }
                 });
 
-        // Schedule initial storage cleanup after delay so as not to increase non-critical work
-        // during boot.
+        // Schedule initial storage cleanup and system triggered trace start after a delay so as not
+        // to increase non-critical or work during boot.
         getHandler().postDelayed(new Runnable() {
             @Override
             public void run() {
+                scheduleNextSystemTriggeredTraceStart();
                 maybeCleanupTemporaryDirectory();
             }
         }, mClearTemporaryDirectoryBootDelayMs);
+
+        // Load the queue and triggers right away.
+        loadQueueFromPersistedData();
+        loadAppTriggersFromPersistedData();
+    }
+
+    /**
+     * Load persisted queue entries. If any issue is encountered reading/parsing the file, delete it
+     * and return as failure to load queue does not block the feature.
+     */
+    @VisibleForTesting
+    public void loadQueueFromPersistedData() {
+        if (!Flags.persistQueue()) {
+            return;
+        }
+
+        // Setup persist files
+        try {
+            if (!setupPersistQueueFiles()) {
+                // If setting up the directory and file was unsuccessful then just return. Past and
+                // future queued results will be lost, but the feature as a whole still works.
+                if (DEBUG) Log.d(TAG, "Failed to setup queue persistence directory/files.");
+                return;
+            }
+        } catch (SecurityException e) {
+            // Can't access files.
+            if (DEBUG) Log.e(TAG, "Failed to setup queue persistence directory/files.", e);
+            return;
+        }
+
+        // Check if file exists
+        try {
+            if (!mPersistQueueFile.exists()) {
+                // No file, nothing to load. This is an expected state for before the feature has
+                // ever been used or if the queue was emptied.
+                if (DEBUG) {
+                    Log.d(TAG, "Queue persistence file does not exist, skipping load from disk.");
+                }
+                return;
+            }
+        } catch (SecurityException e) {
+            // Can't access file.
+            if (DEBUG) Log.e(TAG, "Exception accessing queue persistence file", e);
+            return;
+        }
+
+        // Read the file
+        AtomicFile persistFile = new AtomicFile(mPersistQueueFile);
+        byte[] bytes;
+        try {
+            bytes = persistFile.readFully();
+        } catch (IOException e) {
+            if (DEBUG) Log.e(TAG, "Exception reading queue persistence file", e);
+            // Failed to read the file. No reason to believe we'll have better luck next time,
+            // delete the file and return. Results in the queue will be lost.
+            deletePersistQueueFile();
+            return;
+        }
+        if (bytes.length == 0) {
+            if (DEBUG) Log.d(TAG, "Queue persistence file is empty, skipping load from disk.");
+            // Empty queue persist file. Delete the file and return.
+            deletePersistQueueFile();
+            return;
+        }
+
+        // Parse file bytes to proto
+        QueuedResultsWrapper wrapper;
+        try {
+            wrapper = QueuedResultsWrapper.parseFrom(bytes);
+        } catch (Exception e) {
+            if (DEBUG) Log.e(TAG, "Error parsing proto from persisted bytes", e);
+            // Failed to parse the file contents. No reason to believe we'll have better luck next
+            // time, delete the file and return. Results in the queue will be lost.
+            deletePersistQueueFile();
+            return;
+        }
+
+        // Populate in memory records store
+        for (int i = 0; i < wrapper.getSessionsCount(); i++) {
+            QueuedResultsWrapper.TracingSession sessionsProto = wrapper.getSessions(i);
+            TracingSession session = new TracingSession(sessionsProto);
+            // Since we're populating the in memory store from the persisted queue we don't want to
+            // trigger a persist, so pass param false. If we did trigger the persist from here, it
+            // would overwrite the file with the first record only and then queue the remaining
+            // records for later, thereby leaving the persisted queue with less data than it
+            // currently contains and potentially leading to lost data in event of shutdown before
+            // the scheduled persist occurs.
+            moveSessionToQueue(session, false);
+        }
+    }
+
+    /**
+     * Load persisted app triggers from disk.
+     *
+     * If any issue is encountered during loading, mark as completed and delete the file. Persisted
+     * app triggers will be lost.
+     */
+    @VisibleForTesting
+    public void loadAppTriggersFromPersistedData() {
+        // Setup persist files
+        try {
+            if (!setupPersistAppTriggerFiles()) {
+                // If setting up the directory and file was unsuccessful then just return without
+                // marking loaded so it can be tried again.
+                if (DEBUG) Log.d(TAG, "Failed to setup app trigger persistence directory/files.");
+                return;
+            }
+        } catch (SecurityException e) {
+            // Can't access files.
+            Log.w(TAG, "Failed to setup app trigger persistence directory/files.", e);
+            return;
+        }
+
+        // Check if file exists
+        try {
+            if (!mPersistAppTriggersFile.exists()) {
+                // No file, nothing to load. This is an expected state for before the feature has
+                // ever been used or if the triggers were empty.
+                if (DEBUG) {
+                    Log.d(TAG, "App trigger persistence file does not exist, skipping load from "
+                            + "disk.");
+                }
+                mAppTriggersLoaded = true;
+                return;
+            }
+        } catch (SecurityException e) {
+            // Can't access file.
+            if (DEBUG) Log.e(TAG, "Exception accessing app triggers persistence file", e);
+            return;
+        }
+
+        // Read the file
+        AtomicFile persistFile = new AtomicFile(mPersistAppTriggersFile);
+        byte[] bytes;
+        try {
+            bytes = persistFile.readFully();
+        } catch (IOException e) {
+            Log.w(TAG, "Exception reading app triggers persistence file", e);
+            // Failed to read the file. No reason to believe we'll have better luck next time,
+            // delete the file and return. Persisted triggers will be lost until the app re-adds
+            // them.
+            deletePersistAppTriggersFile();
+            mAppTriggersLoaded = true;
+            return;
+        }
+        if (bytes.length == 0) {
+            if (DEBUG) Log.d(TAG, "App triggers persistence file empty, skipping load from disk.");
+            // Empty app triggers persist file. Delete the file, mark loaded, and return.
+            deletePersistAppTriggersFile();
+            mAppTriggersLoaded = true;
+            return;
+        }
+
+        // Parse file bytes to proto
+        ProfilingTriggersWrapper wrapper;
+        try {
+            wrapper = ProfilingTriggersWrapper.parseFrom(bytes);
+        } catch (Exception e) {
+            Log.w(TAG, "Error parsing proto from persisted bytes", e);
+            // Failed to parse the file contents. No reason to believe we'll have better luck next
+            // time, delete the file, mark loaded, and return. Persisted app triggers will be lost
+            // until re-added by the app.
+            deletePersistAppTriggersFile();
+            mAppTriggersLoaded = true;
+            return;
+        }
+
+        // Populate in memory app triggers store
+        for (int i = 0; i < wrapper.getTriggersCount(); i++) {
+            ProfilingTriggersWrapper.ProfilingTrigger triggerProto = wrapper.getTriggers(i);
+            addTrigger(new ProfilingTrigger(triggerProto), false);
+        }
+
+        mAppTriggersLoaded = true;
+    }
+
+    /** Setup the directory and file for persisting queue. */
+    @VisibleForTesting
+    public boolean setupPersistQueueFiles() {
+        if (mPersistStoreDir == null) {
+            if (!setupPersistDir()) {
+                return false;
+            }
+        }
+        mPersistQueueFile = new File(mPersistStoreDir, QUEUED_RESULTS_INFO_FILE);
+        return true;
+    }
+
+    /** Setup the directory and file for persisting app triggers. */
+    @VisibleForTesting
+    public boolean setupPersistAppTriggerFiles() {
+        if (mPersistStoreDir == null) {
+            if (!setupPersistDir()) {
+                return false;
+            }
+        }
+        mPersistAppTriggersFile = new File(mPersistStoreDir, APP_TRIGGERS_INFO_FILE);
+        return true;
+    }
+
+    /** Setup the directory and file for persisting. */
+    @VisibleForTesting
+    public boolean setupPersistDir() {
+        File dataDir = Environment.getDataDirectory();
+        File systemDir = new File(dataDir, PERSIST_SYSTEM_DIR);
+        mPersistStoreDir = new File(systemDir, PERSIST_STORE_DIR);
+        return createDir(mPersistStoreDir);
+    }
+
+    /** Delete the persist queue file. */
+    @VisibleForTesting
+    public void deletePersistQueueFile() {
+        try {
+            mPersistQueueFile.delete();
+            if (DEBUG) Log.d(TAG, "Deleted queue persist file.");
+        } catch (SecurityException e) {
+            // Can't delete file.
+            if (DEBUG) Log.d(TAG, "Failed to delete queue persist file", e);
+        }
+    }
+
+    /** Delete the persist app triggers file. */
+    @VisibleForTesting
+    public void deletePersistAppTriggersFile() {
+        try {
+            mPersistAppTriggersFile.delete();
+            if (DEBUG) Log.d(TAG, "Deleted app triggers persist file.");
+        } catch (SecurityException e) {
+            // Can't delete file.
+            if (DEBUG) Log.d(TAG, "Failed to delete app triggers persist file", e);
+        }
+    }
+
+    private static boolean createDir(File dir) throws SecurityException {
+        if (dir.mkdir()) {
+            return true;
+        }
+
+        if (dir.exists()) {
+            return dir.isDirectory();
+        }
+
+        return false;
+    }
+
+    /**
+     * Schedule the next start of system triggered profiling trace for a random time between min and
+     * max period.
+     */
+    @VisibleForTesting
+    public void scheduleNextSystemTriggeredTraceStart() {
+        if (!Flags.systemTriggeredProfilingNew()) {
+            // Feature disabled.
+            return;
+        }
+
+        if (mStartSystemTriggeredTraceScheduledFuture != null) {
+            // If an existing start is already scheduled, don't schedule another.
+            // This should not happen.
+            Log.e(TAG, "Attempted to schedule a system triggered trace start with one already "
+                    + "scheduled.");
+            return;
+        }
+
+        if (mScheduledExecutorService == null) {
+            mScheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
+        }
+
+        int scheduledDelaySeconds;
+
+        synchronized (mLock) {
+            // It's important that trace doesn't always run at the same time as this will bias the
+            // results, so grab a random number between min and max.
+            scheduledDelaySeconds = mSystemTriggeredTraceMinPeriodSeconds.get()
+                    + (new Random()).nextInt(mSystemTriggeredTraceMaxPeriodSeconds.get()
+                    - mSystemTriggeredTraceMinPeriodSeconds.get());
+
+            if (DEBUG) {
+                Log.d(TAG, String.format("System triggered trace scheduled in %d seconds for params"
+                        + " min %d and max %d seconds.",
+                        scheduledDelaySeconds,
+                        mSystemTriggeredTraceMinPeriodSeconds.get(),
+                        mSystemTriggeredTraceMaxPeriodSeconds.get()));
+            }
+        }
+
+        // Scheduling of system triggered trace setup is done out of the lock to avoid a potential
+        // deadlock in the case of really frequent triggering due to low min/max values for period.
+        mStartSystemTriggeredTraceScheduledFuture = mScheduledExecutorService.schedule(() -> {
+            // Start the system triggered trace.
+            startSystemTriggeredTrace();
+
+            mStartSystemTriggeredTraceScheduledFuture = null;
+
+            // In all cases, schedule again. Feature flagged off is handled earlier in this
+            // method, and all return cases in {@link #startSystemTriggeredTrace} should result
+            // in trying again at the next regularly scheduled time.
+            scheduleNextSystemTriggeredTraceStart();
+        }, scheduledDelaySeconds, TimeUnit.SECONDS);
     }
 
     /**
@@ -368,10 +801,26 @@ public class ProfilingService extends IProfilingService.Stub {
                 // File has already been copied to app storage, proceed to callback.
                 session.setError(ProfilingResult.ERROR_NONE);
                 processTracingSessionResultCallback(session, true /* Continue advancing session */);
+
+                // This is a good place to persist the queue if possible because the processing work
+                // is complete and we tried to send a callback to the app. If the callback
+                // succeeded, then we will already have recursed on this method with new state of
+                // NOTIFIED_REQUESTER and the only potential remaining work to be repeated will be
+                // cleanup. If the callback failed, then we won't have recursed here and we'll pick
+                // back up this stage next time thereby minimizing repeated work.
+                maybePersistToDisk();
                 break;
             case ERROR_OCCURRED:
                 // An error has occurred, proceed to callback.
                 processTracingSessionResultCallback(session, true /* Continue advancing session */);
+
+                // This is a good place to persist the queue if possible because the processing work
+                // is complete and we tried to send a callback to the app. If the callback
+                // succeeded, then we will already have recursed on this method with new state of
+                // NOTIFIED_REQUESTER and the only potential remaining work to be repeated will be
+                // cleanup. If the callback failed, then we won't have recursed here and we'll pick
+                // back up this stage next time thereby minimizing repeated work.
+                maybePersistToDisk();
                 break;
             case NOTIFIED_REQUESTER:
                 // Callback has been completed successfully, start cleanup.
@@ -501,7 +950,7 @@ public class ProfilingService extends IProfilingService.Stub {
      * This method validates the request, arguments, whether the app is allowed to profile now,
      * and if so, starts the profiling.
      */
-    public void requestProfiling(int profilingType, Bundle params, String filePath, String tag,
+    public void requestProfiling(int profilingType, Bundle params, String tag,
             long keyMostSigBits, long keyLeastSigBits, String packageName) {
         int uid = Binder.getCallingUid();
 
@@ -567,12 +1016,12 @@ public class ProfilingService extends IProfilingService.Stub {
 
         // Check with rate limiter if this request is allowed.
         final int status = getRateLimiter().isProfilingRequestAllowed(Binder.getCallingUid(),
-                profilingType, params);
+                profilingType, false, params);
         if (DEBUG) Log.d(TAG, "Rate limiter status: " + status);
         if (status == RateLimiter.RATE_LIMIT_RESULT_ALLOWED) {
             // Rate limiter approved, try to start the request.
             try {
-                TracingSession session = new TracingSession(profilingType, params, filePath, uid,
+                TracingSession session = new TracingSession(profilingType, params, uid,
                         packageName, tag, keyMostSigBits, keyLeastSigBits);
                 advanceTracingSession(session, TracingState.APPROVED);
                 return;
@@ -686,6 +1135,47 @@ public class ProfilingService extends IProfilingService.Stub {
         stopProfiling(key);
     }
 
+    /**
+     * Add the provided list of validated triggers with the provided package name and the callers
+     * uid being applied to all.
+     */
+    public void addProfilingTriggers(List<ProfilingTriggerValueParcel> triggers,
+            String packageName) {
+        int uid = Binder.getCallingUid();
+        for (int i = 0; i < triggers.size(); i++) {
+            ProfilingTriggerValueParcel trigger = triggers.get(i);
+            addTrigger(uid, packageName, trigger.triggerType, trigger.rateLimitingPeriodHours);
+        }
+    }
+
+    /**
+     * Remove the provided list of validated trigger codes from a process with the provided package
+     * name and the uid of the caller.
+     */
+    public void removeProfilingTriggers(int[] triggerTypesToRemove, String packageName) {
+        SparseArray<ProfilingTrigger> triggers =
+                mAppTriggers.get(packageName, Binder.getCallingUid());
+
+        for (int i = 0; i < triggerTypesToRemove.length; i++) {
+            int index = triggers.indexOfKey(triggerTypesToRemove[i]);
+            if (index >= 0) {
+                triggers.removeAt(index);
+            }
+        }
+
+        if (triggers.size() == 0) {
+            // Nothing left, remove.
+            mAppTriggers.remove(packageName, Binder.getCallingUid());
+        }
+    }
+
+    /**
+     * Remove all triggers from a process with the provided packagename and the uid of the caller.
+     */
+    public void clearProfilingTriggers(String packageName) {
+        mAppTriggers.remove(packageName, Binder.getCallingUid());
+    }
+
     /**
      * Method called by manager, after creating a file from within application context, to send a
      * file descriptor for service to write the result of the profiling session to.
@@ -872,7 +1362,8 @@ public class ProfilingService extends IProfilingService.Stub {
      * @return whether at least one callback was successfully sent to the app.
      */
     private boolean processResultCallback(int uid, long keyMostSigBits, long keyLeastSigBits,
-            int status, @Nullable String filePath, @Nullable String tag, @Nullable String error) {
+            int status, @Nullable String fileResultPathAndName, @Nullable String tag,
+            @Nullable String error) {
         List<IProfilingResultCallback> perUidCallbacks = mResultCallbacks.get(uid);
         if (perUidCallbacks == null || perUidCallbacks.isEmpty()) {
             // No callbacks, nowhere to notify with result or failure.
@@ -885,7 +1376,8 @@ public class ProfilingService extends IProfilingService.Stub {
             try {
                 if (status == ProfilingResult.ERROR_NONE) {
                     perUidCallbacks.get(i).sendResult(
-                            filePath, keyMostSigBits, keyLeastSigBits, status, tag, error);
+                            fileResultPathAndName, keyMostSigBits, keyLeastSigBits, status, tag,
+                            error);
                 } else {
                     perUidCallbacks.get(i).sendResult(
                             null, keyMostSigBits, keyLeastSigBits, status, tag, error);
@@ -928,7 +1420,7 @@ public class ProfilingService extends IProfilingService.Stub {
             // Request couldn't be processed. This shouldn't happen.
             if (DEBUG) Log.d(TAG, "Request couldn't be processed", e);
             session.setError(ProfilingResult.ERROR_FAILED_INVALID_REQUEST, e.getMessage());
-            moveSessionToQueue(session);
+            moveSessionToQueue(session, true);
             advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
 
@@ -946,21 +1438,17 @@ public class ProfilingService extends IProfilingService.Stub {
 
         session.setFileName(baseFileName + suffix);
 
-        try {
-            ProcessBuilder pb = new ProcessBuilder("/system/bin/perfetto", "-o",
-                    TEMP_TRACE_PATH + session.getFileName(), "-c", "-");
-            Process activeTrace = pb.start();
-            activeTrace.getOutputStream().write(config);
-            activeTrace.getOutputStream().close();
-            // If we made it this far the trace is running, save the session.
-            session.setActiveTrace(activeTrace);
+        Process activeProfiling = startProfilingProcess(config,
+                TEMP_TRACE_PATH + session.getFileName());
+
+        if (activeProfiling != null) {
+            // Profiling is running, save the session.
+            session.setActiveTrace(activeProfiling);
             session.setProfilingStartTimeMs(System.currentTimeMillis());
             mActiveTracingSessions.put(session.getKey(), session);
-        } catch (Exception e) {
-            // Catch all exceptions related to starting process as they'll all be handled similarly.
-            if (DEBUG) Log.d(TAG, "Trace couldn't be started", e);
+        } else {
             session.setError(ProfilingResult.ERROR_FAILED_EXECUTING, "Trace couldn't be started");
-            moveSessionToQueue(session);
+            moveSessionToQueue(session, true);
             advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
         }
@@ -978,6 +1466,277 @@ public class ProfilingService extends IProfilingService.Stub {
         advanceTracingSession(session, TracingState.PROFILING_STARTED);
     }
 
+    /** Start a trace to be used for system triggered profiling. */
+    @VisibleForTesting
+    public void startSystemTriggeredTrace() {
+        if (!Flags.systemTriggeredProfilingNew()) {
+            // Flag disabled.
+            return;
+        }
+
+        if (!mAppTriggersLoaded) {
+            // Until the triggers are loaded we can't create a proper config so just return.
+            if (DEBUG) {
+                Log.d(TAG, "System triggered trace not started due to app triggers not loaded.");
+            }
+            return;
+        }
+
+        String[] packageNames = getActiveTriggerPackageNames();
+        if (packageNames.length == 0) {
+            // No apps have registered interest in system triggered profiling, so don't bother to
+            // start a trace for it.
+            if (DEBUG) {
+                Log.d(TAG,
+                        "System triggered trace not started due to no apps registering interest");
+            }
+            return;
+        }
+
+        String uniqueSessionName = SYSTEM_TRIGGERED_SESSION_NAME_PREFIX
+                + System.currentTimeMillis();
+
+        byte[] config = Configs.generateSystemTriggeredTraceConfig(uniqueSessionName, packageNames,
+                mTestPackageName != null);
+        String outputFile = TEMP_TRACE_PATH + SYSTEM_TRIGGERED_SESSION_NAME_PREFIX
+                + OUTPUT_FILE_IN_PROGRESS + OUTPUT_FILE_UNREDACTED_TRACE_SUFFIX;
+
+        Process activeTrace = startProfilingProcess(config, outputFile);
+
+        if (activeTrace != null) {
+            mSystemTriggeredTraceProcess = activeTrace;
+            mSystemTriggeredTraceUniqueSessionName = uniqueSessionName;
+            mLastStartedSystemTriggeredTraceMs = System.currentTimeMillis();
+        }
+    }
+
+    /**
+     * Start the actual profiling process with necessary config details.
+     *
+     * @return the started process if it started successfully, or null if it failed to start.
+     */
+    @Nullable
+    private Process startProfilingProcess(byte[] config, String outputFile) {
+        try {
+            ProcessBuilder processBuilder = new ProcessBuilder("/system/bin/perfetto", "-o",
+                    outputFile, "-c", "-");
+            Process activeProfiling = processBuilder.start();
+            activeProfiling.getOutputStream().write(config);
+            activeProfiling.getOutputStream().close();
+            return activeProfiling;
+        } catch (Exception e) {
+            // Catch all exceptions related to starting process as they'll all be handled similarly.
+            if (DEBUG) Log.d(TAG, "Profiling couldn't be started", e);
+            return null;
+        }
+    }
+
+    /**
+     * Process a trigger for a uid + package name + trigger combination. This is done by verifying
+     * that a trace is active, the app has registered interest in this combo, and that both system
+     * and app provided rate limiting allow for it. If confirmed, it will proceed to clone the
+     * active profiling and continue processing the result.
+     *
+     * Cloning will fork the running trace, stop the new forked trace, and output the result to a
+     * separate file. This leaves the original trace running.
+     */
+    public void processTrigger(int uid, @NonNull String packageName, int triggerType) {
+        if (!Flags.systemTriggeredProfilingNew()) {
+            // Flag disabled.
+            return;
+        }
+
+        // Don't block the calling thread.
+        getHandler().post(new Runnable() {
+            @Override
+            public void run() {
+                processTriggerInternal(uid, packageName, triggerType);
+            }
+        });
+    }
+
+    /**
+     * Internal call to process trigger, not to be called on the thread that passed the trigger in.
+     */
+    @VisibleForTesting
+    public void processTriggerInternal(int uid, @NonNull String packageName, int triggerType) {
+        if (mSystemTriggeredTraceUniqueSessionName == null) {
+            // If we don't have the session name then we don't know how to clone the trace so stop
+            // it if it's still running and then return.
+            stopSystemTriggeredTrace();
+
+            // There is no active system triggered trace so there's nothing to clone. Return.
+            if (DEBUG) {
+                Log.d(TAG, "Requested clone system triggered trace but we don't have the session "
+                        + "name.");
+            }
+            return;
+        }
+
+        if (mSystemTriggeredTraceProcess == null || !mSystemTriggeredTraceProcess.isAlive()) {
+            // If we make it to this path then session name wasn't set to null but can't be used
+            // anymore as its associated trace is not running, so set to null now.
+            mSystemTriggeredTraceUniqueSessionName = null;
+
+            // There is no active system triggered trace so there's nothing to clone. Return.
+            if (DEBUG) Log.d(TAG, "Requested clone system triggered trace but no trace active.");
+            return;
+        }
+
+        // Then check if the app has registered interest in this combo.
+        SparseArray<ProfilingTrigger> perProcessTriggers = mAppTriggers.get(packageName, uid);
+        if (perProcessTriggers == null) {
+            // This uid hasn't registered any triggers.
+            if (DEBUG) {
+                Log.d(TAG, String.format("Profiling triggered for uid %d with no registered "
+                        + "triggers", uid));
+            }
+            return;
+        }
+
+        ProfilingTrigger trigger = perProcessTriggers.get(triggerType);
+        if (trigger == null) {
+            // This uid hasn't registered a trigger for this type.
+            if (DEBUG) {
+                Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d, but "
+                        + "app has not registered for this trigger type.", uid, triggerType));
+            }
+            return;
+        }
+
+        // Now apply system and app provided rate limiting.
+        if (System.currentTimeMillis() - trigger.getLastTriggeredTimeMs()
+                < trigger.getRateLimitingPeriodHours() * 60L * 60L * 1000L) {
+            // App provided rate limiting doesn't allow for this run, return.
+            if (DEBUG) {
+                Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d but blocked"
+                        + " by app provided rate limiting ", uid, triggerType));
+            }
+            return;
+        }
+
+        // If this is from the test package, skip system rate limiting.
+        if (!packageName.equals(mTestPackageName)) {
+            int systemRateLimiterResult = getRateLimiter().isProfilingRequestAllowed(uid,
+                    ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE, true, null);
+            if (systemRateLimiterResult != RateLimiter.RATE_LIMIT_RESULT_ALLOWED) {
+                // Blocked by system rate limiter, return. Since this is system triggered there is
+                // no callback and therefore no need to distinguish between per app and system
+                // denials within the system rate limiter.
+                if (DEBUG) {
+                    Log.d(TAG, String.format("Profiling triggered for uid %d and trigger %d but "
+                            + "blocked by system rate limiting ", uid, triggerType));
+                }
+                return;
+            }
+        }
+
+        // Now that it's approved by both rate limiters, update their values.
+        trigger.setLastTriggeredTimeMs(System.currentTimeMillis());
+
+        // If we made it this far, a trace is running, the app has registered interest in this
+        // trigger, and rate limiting allows for capturing the result.
+
+        // Create the file names
+        String baseFileName = OUTPUT_FILE_PREFIX
+                + OUTPUT_FILE_SECTION_SEPARATOR + OUTPUT_FILE_TRIGGER
+                + OUTPUT_FILE_SECTION_SEPARATOR + triggerType
+                + OUTPUT_FILE_SECTION_SEPARATOR + getFormattedDate();
+        String unredactedFullName = baseFileName + OUTPUT_FILE_UNREDACTED_TRACE_SUFFIX;
+
+        try {
+            // Try to clone the running trace.
+            Process clone = Runtime.getRuntime().exec(new String[] {
+                    "/system/bin/perfetto",
+                    "--clone-by-name",
+                    mSystemTriggeredTraceUniqueSessionName,
+                    "--out",
+                    TEMP_TRACE_PATH + unredactedFullName});
+
+            // Wait for cloned process to stop.
+            if (!clone.waitFor(mPerfettoDestroyTimeoutMs, TimeUnit.MILLISECONDS)) {
+                // Cloned process did not stop, try to stop it forcibly.
+                if (DEBUG) {
+                    Log.d(TAG, "Cloned system triggered trace didn't stop on its own, trying to "
+                            + "stop it forcibly.");
+                }
+                clone.destroyForcibly();
+
+                // Wait again to see if it stops now.
+                if (!clone.waitFor(mPerfettoDestroyTimeoutMs, TimeUnit.MILLISECONDS)) {
+                    // Nothing more to do, result won't be ready so return.
+                    if (DEBUG) Log.d(TAG, "Cloned system triggered trace timed out.");
+                    return;
+                }
+            }
+        } catch (IOException | InterruptedException e) {
+            // Failed. There's nothing to clean up as we haven't created a session for this clone
+            // yet so just fail quietly. The result for this trigger instance combo will be lost.
+            if (DEBUG) Log.d(TAG, "Failed to clone running system triggered trace.", e);
+            return;
+        }
+
+        // If we get here the clone was successful. Create a new TracingSession to track this and
+        // continue moving it along the processing process.
+        TracingSession session = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE, uid, packageName, triggerType);
+        session.setRedactedFileName(baseFileName + OUTPUT_FILE_TRACE_SUFFIX);
+        session.setFileName(unredactedFullName);
+        moveSessionToQueue(session, true);
+        advanceTracingSession(session, TracingState.PROFILING_FINISHED);
+
+        maybePersistToDisk();
+    }
+
+    /** Add a profiling trigger to the supporting data structure. */
+    @VisibleForTesting
+    public void addTrigger(int uid, @NonNull String packageName, int triggerType,
+            int rateLimitingPeriodHours) {
+        addTrigger(new ProfilingTrigger(uid, packageName, triggerType, rateLimitingPeriodHours),
+                true);
+    }
+
+    /**
+     * Add a profiling trigger to the supporting data structure.
+     *
+     * @param trigger       The trigger to add.
+     * @param maybePersist  Whether to persist to disk, if eligible based on frequency. This is
+     *                          intended to be set to false only when loading triggers from disk.
+     */
+    @VisibleForTesting
+    public void addTrigger(ProfilingTrigger trigger, boolean maybePersist) {
+        if (!Flags.systemTriggeredProfilingNew()) {
+            // Flag disabled.
+            return;
+        }
+
+        SparseArray<ProfilingTrigger> perProcessTriggers = mAppTriggers.get(
+                trigger.getPackageName(), trigger.getUid());
+
+        if (perProcessTriggers == null) {
+            perProcessTriggers = new SparseArray<ProfilingTrigger>();
+            mAppTriggers.put(trigger.getPackageName(), trigger.getUid(), perProcessTriggers);
+        }
+
+        // Only 1 trigger is allowed per uid + trigger type so this will override any previous
+        // triggers of this type registered for this uid.
+        perProcessTriggers.put(trigger.getTriggerType(), trigger);
+
+        if (maybePersist) {
+            maybePersistToDisk();
+        }
+    }
+
+    /** Get a list of all package names which have registered profiling triggers. */
+    private String[] getActiveTriggerPackageNames() {
+        // Since only system trace is supported for triggers, we can simply grab the key set of the
+        // backing map for the ProcessMap which will contain all the package names. Once other
+        // profiling types are supported, we'll need to filter these more intentionally to just the
+        // ones that have an associated trace trigger.
+        Set<String> packageNamesSet = mAppTriggers.getMap().keySet();
+        return packageNamesSet.toArray(new String[packageNamesSet.size()]);
+    }
+
     /**
         This method will check if the profiling subprocess is still alive. If it's still alive and
         there is still time permitted to run, another check will be scheduled. If the process is
@@ -1002,7 +1761,7 @@ public class ProfilingService extends IProfilingService.Stub {
         } else {
             // complete, process results and deliver.
             session.setProcessResultRunnable(null);
-            moveSessionToQueue(session);
+            moveSessionToQueue(session, true);
             advanceTracingSession(session, TracingState.PROFILING_FINISHED);
         }
     }
@@ -1166,8 +1925,7 @@ public class ProfilingService extends IProfilingService.Stub {
                         ? session.getRedactedFileName() : session.getFileName();
                 IProfilingResultCallback callback = perUidCallbacks.get(i);
                 if (callback.asBinder().isBinderAlive()) {
-                    callback.deleteFile(
-                            session.getAppFilePath() + OUTPUT_FILE_RELATIVE_PATH + fileName);
+                    callback.deleteFile(OUTPUT_FILE_RELATIVE_PATH + fileName);
                     // Only need one delete call, return.
                     return;
                 }
@@ -1190,7 +1948,6 @@ public class ProfilingService extends IProfilingService.Stub {
     @Nullable
     private void requestFileForResult(
             @NonNull List<IProfilingResultCallback> perUidCallbacks, TracingSession session) {
-        String filePath = session.getAppFilePath() + OUTPUT_FILE_RELATIVE_PATH;
         String fileName = session.getProfilingType() == ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE
                 ? session.getRedactedFileName()
                 : session.getFileName();
@@ -1199,7 +1956,7 @@ public class ProfilingService extends IProfilingService.Stub {
                 IProfilingResultCallback callback = perUidCallbacks.get(i);
                 if (callback.asBinder().isBinderAlive()) {
                     // Great, this one works! Call it and exit if we don't hit an exception.
-                    perUidCallbacks.get(i).generateFile(filePath, fileName,
+                    perUidCallbacks.get(i).generateFile(OUTPUT_FILE_RELATIVE_PATH, fileName,
                             session.getKeyMostSigBits(), session.getKeyLeastSigBits());
                     return;
                 }
@@ -1230,7 +1987,8 @@ public class ProfilingService extends IProfilingService.Stub {
             // Start the redaction process and log the time of start.  Redaction has
             // mRedactionMaxRuntimeAllottedMs to complete. Redaction status will be checked every
             // mRedactionCheckFrequencyMs.
-            ProcessBuilder redactionProcess = new ProcessBuilder("/system/bin/trace_redactor",
+            ProcessBuilder redactionProcess = new ProcessBuilder(
+                    "/apex/com.android.profiling/bin/trace_redactor",
                     TEMP_TRACE_PATH + session.getFileName(),
                     TEMP_TRACE_PATH + session.getRedactedFileName(),
                     session.getPackageName());
@@ -1445,8 +2203,12 @@ public class ProfilingService extends IProfilingService.Stub {
      *
      * Sessions are expected to be in the queue when their states are between PROFILING_FINISHED and
      * NOTIFIED_REQUESTER, inclusive.
+     *
+     * @param session      the session to move to the queue
+     * @param maybePersist whether to persist the queue to disk if the queue is eligible to be
+     *          persisted
      */
-    private void moveSessionToQueue(TracingSession session) {
+    private void moveSessionToQueue(TracingSession session, boolean maybePersist) {
         List<TracingSession> queuedResults = mQueuedTracingResults.get(session.getUid());
         if (queuedResults == null) {
             queuedResults = new ArrayList<TracingSession>();
@@ -1454,6 +2216,10 @@ public class ProfilingService extends IProfilingService.Stub {
         }
         queuedResults.add(session);
         mActiveTracingSessions.remove(session.getKey());
+
+        if (maybePersist) {
+            maybePersistToDisk();
+        }
     }
 
     private boolean needsRedaction(TracingSession session) {
@@ -1532,6 +2298,258 @@ public class ProfilingService extends IProfilingService.Stub {
         return false;
     }
 
+    /**
+     * Persist service data to disk following the following rules:
+     * - If a persist is already scheduled, do nothing.
+     * - If a persist happened within the last {@link #mPersistFrequencyMs} then schedule a
+     *      persist for {@link #mPersistFrequencyMs} after the last persist.
+     * - If no persist has occurred yet or the most recent persist was more than
+     *      {@link #mPersistFrequencyMs} ago, persist immediately.
+     */
+    @VisibleForTesting
+    public void maybePersistToDisk() {
+        if (!Flags.persistQueue() && !Flags.systemTriggeredProfilingNew()) {
+            // No persisting is enabled.
+            return;
+        }
+
+        synchronized (mLock) {
+            if (mPersistScheduled) {
+                // We're already waiting on a scheduled persist job, do nothing.
+                return;
+            }
+
+            if (mPersistFrequencyMs.get() != 0
+                    && (System.currentTimeMillis() - mLastPersistedTimestampMs
+                    < mPersistFrequencyMs.get())) {
+                // Schedule the persist job.
+                if (mPersistRunnable == null) {
+                    mPersistRunnable = new Runnable() {
+                        @Override
+                        public void run() {
+                            if (Flags.persistQueue()) {
+                                persistQueueToDisk();
+                            }
+                            if (Flags.systemTriggeredProfilingNew()) {
+                                persistAppTriggersToDisk();
+                            }
+                            mPersistScheduled = false;
+                        }
+                    };
+                }
+                mPersistScheduled = true;
+                long persistDelay = mLastPersistedTimestampMs + mPersistFrequencyMs.get()
+                        - System.currentTimeMillis();
+                getHandler().postDelayed(mPersistRunnable, persistDelay);
+                return;
+            }
+        }
+
+        // If we got here then either persist frequency is 0 or it has already been longer than
+        // persist frequency since the last persist. Persist immediately.
+        if (Flags.persistQueue()) {
+            persistQueueToDisk();
+        }
+        if (Flags.systemTriggeredProfilingNew()) {
+            persistAppTriggersToDisk();
+        }
+    }
+
+    /** Persist the current queue to disk after cleaning it up. */
+    @VisibleForTesting
+    public void persistQueueToDisk() {
+        if (!Flags.persistQueue()) {
+            return;
+        }
+
+        // Check if file exists
+        try {
+            if (mPersistQueueFile == null) {
+                // Try again to create the necessary files.
+                if (!setupPersistQueueFiles()) {
+                    // No file, nowhere to save.
+                    if (DEBUG) {
+                        Log.d(TAG, "Failed setting up queue persist files so nowhere to save to.");
+                    }
+                    return;
+                }
+            }
+
+            if (!mPersistQueueFile.exists()) {
+                // File doesn't exist, try to create it.
+                mPersistQueueFile.createNewFile();
+            }
+        } catch (Exception e) {
+            if (DEBUG) Log.e(TAG, "Exception accessing persisted records store.", e);
+            return;
+        }
+
+        // Clean up queue to reduce extraneous writes
+        maybeCleanupQueue();
+
+        // Generate proto for queue.
+        QueuedResultsWrapper.Builder builder = QueuedResultsWrapper.newBuilder();
+
+        boolean recordAdded = false;
+
+        for (int i = 0; i < mQueuedTracingResults.size(); i++) {
+            List<TracingSession> perUidSessions = mQueuedTracingResults.valueAt(i);
+            if (!perUidSessions.isEmpty()) {
+                for (int j = 0; j < perUidSessions.size(); j++) {
+                    builder.addSessions(perUidSessions.get(j).toProto());
+
+                    if (!recordAdded) {
+                        recordAdded = true;
+                    }
+                }
+            }
+        }
+
+        if (!recordAdded) {
+            // No results, nothing to persist, delete the file as it may contain results that are no
+            // longer meaningful and will just increase future work and then return.
+            deletePersistQueueFile();
+            return;
+        }
+
+        QueuedResultsWrapper queuedResultsWrapper = builder.build();
+
+        // Write to disk
+        byte[] protoBytes = queuedResultsWrapper.toByteArray();
+        AtomicFile persistFile = new AtomicFile(mPersistQueueFile);
+        FileOutputStream out = null;
+        try {
+            out = persistFile.startWrite();
+            out.write(protoBytes);
+            persistFile.finishWrite(out);
+            synchronized (mLock) {
+                mLastPersistedTimestampMs = System.currentTimeMillis();
+            }
+        } catch (IOException e) {
+            if (DEBUG) Log.e(TAG, "Exception writing queued results", e);
+            persistFile.failWrite(out);
+        }
+    }
+
+    /** Persist the current app triggers to disk. */
+    @VisibleForTesting
+    public void persistAppTriggersToDisk() {
+        // Check if file exists
+        try {
+            if (mPersistAppTriggersFile == null) {
+                // Try again to create the necessary files.
+                if (!setupPersistAppTriggerFiles()) {
+                    // No file, nowhere to save.
+                    if (DEBUG) {
+                        Log.d(TAG, "Failed setting up app triggers persist files so nowhere to save"
+                                + " to.");
+                    }
+                    return;
+                }
+            }
+
+            if (!mPersistAppTriggersFile.exists()) {
+                // File doesn't exist, try to create it.
+                mPersistAppTriggersFile.createNewFile();
+            }
+        } catch (Exception e) {
+            if (DEBUG) Log.e(TAG, "Exception accessing persisted app triggers store.", e);
+            return;
+        }
+
+        // Generate proto for queue.
+        ProfilingTriggersWrapper.Builder builder = ProfilingTriggersWrapper.newBuilder();
+
+        forEachTrigger(mAppTriggers.getMap(), (trigger) -> builder.addTriggers(trigger.toProto()));
+
+        ProfilingTriggersWrapper queuedTriggersWrapper = builder.build();
+
+        // Write to disk
+        byte[] protoBytes = queuedTriggersWrapper.toByteArray();
+        AtomicFile persistFile = new AtomicFile(mPersistAppTriggersFile);
+        FileOutputStream out = null;
+        try {
+            out = persistFile.startWrite();
+            out.write(protoBytes);
+            persistFile.finishWrite(out);
+            synchronized (mLock) {
+                mLastPersistedTimestampMs = System.currentTimeMillis();
+            }
+        } catch (IOException e) {
+            if (DEBUG) Log.e(TAG, "Exception writing app triggers", e);
+            persistFile.failWrite(out);
+        }
+    }
+
+    /** Receive a callback with each of the tracked profiling triggers. */
+    private void forEachTrigger(
+            ArrayMap<String, SparseArray<SparseArray<ProfilingTrigger>>> triggersOuterMap,
+            Consumer<ProfilingTrigger> callback) {
+
+        for (int i = 0; i < triggersOuterMap.size(); i++) {
+            SparseArray<SparseArray<ProfilingTrigger>> triggerUidList = triggersOuterMap.valueAt(i);
+
+            for (int j = 0; j < triggerUidList.size(); j++) {
+                int uidKey = triggerUidList.keyAt(j);
+                SparseArray<ProfilingTrigger> triggersList = triggerUidList.get(uidKey);
+
+                if (triggersList != null) {
+                    for (int k = 0; k < triggersList.size(); k++) {
+                        int triggerTypeKey = triggersList.keyAt(k);
+                        ProfilingTrigger trigger = triggersList.get(triggerTypeKey);
+
+                        if (trigger != null) {
+                            callback.accept(trigger);
+                        }
+                    }
+                }
+            }
+        }
+    }
+
+    /** Handle updates to test package config value. */
+    @GuardedBy("mLock")
+    private void handleTestPackageChangeLocked(String newTestPackageName) {
+        if (newTestPackageName == null) {
+
+            // Test package has been set to null, check whether it was null previously.
+            if (mTestPackageName != null) {
+
+                // New null state is a changed from previous state, disable test mode.
+                mTestPackageName = null;
+                stopSystemTriggeredTrace();
+            }
+            // If new state is unchanged from previous null state, do nothing.
+        } else {
+
+            // Test package has been set with a value. Stop running system triggered trace if
+            // applicable so we can start a new one that will have most up to date package names.
+            // This should not be called when the new test package name matches the old one as
+            // device config should not be sending an update for a value change when the value
+            // remains the same, but no need to check as the best experience for caller is to always
+            // stop the current trace and start a new one for most up to date package list.
+            stopSystemTriggeredTrace();
+
+            // Now update the test package name and start the system triggered trace.
+            mTestPackageName = newTestPackageName;
+            startSystemTriggeredTrace();
+        }
+    }
+
+    /** Stop the system triggered trace. */
+    private void stopSystemTriggeredTrace() {
+        // If the trace is alive, stop it.
+        if (mSystemTriggeredTraceProcess != null) {
+            if (mSystemTriggeredTraceProcess.isAlive()) {
+                mSystemTriggeredTraceProcess.destroyForcibly();
+            }
+            mSystemTriggeredTraceProcess = null;
+        }
+
+        // Set session name to null.
+        mSystemTriggeredTraceUniqueSessionName = null;
+    }
+
     private class ProfilingDeathRecipient implements IBinder.DeathRecipient {
         private final int mUid;
 
diff --git a/service/java/com/android/os/profiling/ProfilingTrigger.java b/service/java/com/android/os/profiling/ProfilingTrigger.java
new file mode 100644
index 0000000..6800cb0
--- /dev/null
+++ b/service/java/com/android/os/profiling/ProfilingTrigger.java
@@ -0,0 +1,88 @@
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
+package android.os.profiling;
+
+import android.annotation.NonNull;
+import android.os.ProfilingTriggersWrapper;
+
+public final class ProfilingTrigger {
+    // LINT.IfChange(params)
+    private final int mUid;
+    @NonNull private final String mPackageName;
+    private final int mTriggerType;
+    private final int mRateLimitingPeriodHours;
+    private long mLastTriggeredTimeMs = 0;
+    // LINT.ThenChange(:from_proto)
+
+    public ProfilingTrigger(int uid, @NonNull String packageName, int triggerType,
+            int rateLimitingPeriodHours) {
+        mUid = uid;
+        mPackageName = packageName;
+        mTriggerType = triggerType;
+        mRateLimitingPeriodHours = rateLimitingPeriodHours;
+    }
+
+    // LINT.IfChange(from_proto)
+    public ProfilingTrigger(@NonNull ProfilingTriggersWrapper.ProfilingTrigger triggerProto) {
+        mUid = triggerProto.getUid();
+        mPackageName = triggerProto.getPackageName();
+        mTriggerType = triggerProto.getTriggerType();
+        mRateLimitingPeriodHours = triggerProto.getRateLimitingPeriodHours();
+        mLastTriggeredTimeMs = triggerProto.getLastTriggeredTimeMillis();
+    }
+    // LINT.ThenChange(:to_proto)
+
+
+    public void setLastTriggeredTimeMs(long lastTriggeredTimeMs) {
+        mLastTriggeredTimeMs = lastTriggeredTimeMs;
+    }
+
+    public int getUid() {
+        return mUid;
+    }
+
+    public int getTriggerType() {
+        return mTriggerType;
+    }
+
+    public String getPackageName() {
+        return mPackageName;
+    }
+
+    public int getRateLimitingPeriodHours() {
+        return mRateLimitingPeriodHours;
+    }
+
+    public long getLastTriggeredTimeMs() {
+        return mLastTriggeredTimeMs;
+    }
+
+    // LINT.IfChange(to_proto)
+    public ProfilingTriggersWrapper.ProfilingTrigger toProto() {
+        ProfilingTriggersWrapper.ProfilingTrigger.Builder builder =
+                ProfilingTriggersWrapper.ProfilingTrigger.newBuilder();
+
+        builder.setUid(mUid);
+        builder.setPackageName(mPackageName);
+        builder.setTriggerType(mTriggerType);
+        builder.setRateLimitingPeriodHours(mRateLimitingPeriodHours);
+        builder.setLastTriggeredTimeMillis(mLastTriggeredTimeMs);
+
+        return builder.build();
+    }
+    // LINT.ThenChange(/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java:trigger_equals)
+}
diff --git a/service/java/com/android/os/profiling/RateLimiter.java b/service/java/com/android/os/profiling/RateLimiter.java
index 0cf843d..a57b840 100644
--- a/service/java/com/android/os/profiling/RateLimiter.java
+++ b/service/java/com/android/os/profiling/RateLimiter.java
@@ -52,13 +52,14 @@ public class RateLimiter {
     private static final long TIME_DAY_MS = 24 * 60 * 60 * 1000;
     private static final long TIME_WEEK_MS = 7 * 24 * 60 * 60 * 1000;
 
-    private static final int DEFAULT_MAX_COST_SYSTEM_HOUR = 2;
-    private static final int DEFAULT_MAX_COST_PROCESS_HOUR = 1;
-    private static final int DEFAULT_MAX_COST_SYSTEM_DAY = 5;
-    private static final int DEFAULT_MAX_COST_PROCESS_DAY = 2;
-    private static final int DEFAULT_MAX_COST_SYSTEM_WEEK = 15;
-    private static final int DEFAULT_MAX_COST_PROCESS_WEEK = 3;
-    private static final int DEFAULT_COST_PER_SESSION = 1;
+    private static final int DEFAULT_MAX_COST_SYSTEM_HOUR = 20;
+    private static final int DEFAULT_MAX_COST_PROCESS_HOUR = 10;
+    private static final int DEFAULT_MAX_COST_SYSTEM_DAY = 50;
+    private static final int DEFAULT_MAX_COST_PROCESS_DAY = 20;
+    private static final int DEFAULT_MAX_COST_SYSTEM_WEEK = 150;
+    private static final int DEFAULT_MAX_COST_PROCESS_WEEK = 30;
+    private static final int DEFAULT_COST_PER_SESSION = 10;
+    private static final int DEFAULT_COST_PER_SYSTEM_TRIGGERED_SESSION = 5;
 
     public static final int RATE_LIMIT_RESULT_ALLOWED = 0;
     public static final int RATE_LIMIT_RESULT_BLOCKED_PROCESS = 1;
@@ -88,6 +89,7 @@ public class RateLimiter {
     private int mCostHeapProfile;
     private int mCostStackSampling;
     private int mCostSystemTrace;
+    private int mCostSystemTriggeredSystemTrace;
 
     private final HandlerCallback mHandlerCallback;
 
@@ -154,6 +156,9 @@ public class RateLimiter {
                 DEFAULT_COST_PER_SESSION);
         mCostSystemTrace = properties.getInt(DeviceConfigHelper.COST_SYSTEM_TRACE,
                 DEFAULT_COST_PER_SESSION);
+        mCostSystemTriggeredSystemTrace = properties.getInt(
+                DeviceConfigHelper.COST_SYSTEM_TRIGGERED_SYSTEM_TRACE,
+                DEFAULT_COST_PER_SYSTEM_TRIGGERED_SESSION);
 
         mPersistToDiskFrequency = properties.getLong(
                 DeviceConfigHelper.PERSIST_TO_DISK_FREQUENCY_MS, 0);
@@ -170,10 +175,11 @@ public class RateLimiter {
     }
 
     public @RateLimitResult int isProfilingRequestAllowed(int uid,
-            int profilingType, @Nullable Bundle params) {
+            int profilingType, boolean isTriggered, @Nullable Bundle params) {
         synchronized (mLock) {
-            if (mRateLimiterDisabled) {
+            if (mRateLimiterDisabled && !isTriggered) {
                 // Rate limiter is disabled for testing, approve request and don't store cost.
+                // This mechanism applies only to direct requests, not system triggered ones.
                 Log.w(TAG, "Rate limiter disabled, request allowed.");
                 return RATE_LIMIT_RESULT_ALLOWED;
             }
@@ -182,7 +188,7 @@ public class RateLimiter {
                 Log.e(TAG, "Data loading in progress or failed, request denied.");
                 return RATE_LIMIT_RESULT_BLOCKED_SYSTEM;
             }
-            final int cost = getCostForProfiling(profilingType);
+            final int cost = getCostForProfiling(profilingType, isTriggered);
             final long currentTimeMillis = System.currentTimeMillis();
             int status = mPastRunsHour.isProfilingAllowed(uid, cost, currentTimeMillis);
             if (status == RATE_LIMIT_RESULT_ALLOWED) {
@@ -202,7 +208,10 @@ public class RateLimiter {
         }
     }
 
-    private int getCostForProfiling(int profilingType) {
+    private int getCostForProfiling(int profilingType, boolean isTriggered) {
+        if (isTriggered) {
+            return mCostSystemTriggeredSystemTrace;
+        }
         switch (profilingType) {
             case ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP:
                 return mCostJavaHeapDump;
@@ -503,6 +512,9 @@ public class RateLimiter {
                 mCostStackSampling);
         mCostSystemTrace = properties.getInt(DeviceConfigHelper.COST_SYSTEM_TRACE,
                 mCostSystemTrace);
+        mCostSystemTriggeredSystemTrace = properties.getInt(
+                DeviceConfigHelper.COST_SYSTEM_TRIGGERED_SYSTEM_TRACE,
+                mCostSystemTriggeredSystemTrace);
 
         // For max cost values, set a invalid default value and pass through to each group wrapper
         // to determine whether to update values.
diff --git a/service/java/com/android/os/profiling/TracingSession.java b/service/java/com/android/os/profiling/TracingSession.java
index b2a8c2d..428f00b 100644
--- a/service/java/com/android/os/profiling/TracingSession.java
+++ b/service/java/com/android/os/profiling/TracingSession.java
@@ -18,7 +18,11 @@ package android.os.profiling;
 
 import static android.os.profiling.ProfilingService.TracingState;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 import android.os.Bundle;
+import android.os.QueuedResultsWrapper;
+import android.util.Log;
 
 import java.util.UUID;
 
@@ -26,37 +30,67 @@ import java.util.UUID;
  * Represents a single in progress tracing session and all necessary data to manage and process it.
  */
 public final class TracingSession {
+    private static final String TAG = TracingSession.class.getSimpleName();
 
-    private Process mActiveTrace;
-    private Process mActiveRedaction;
-    private Runnable mProcessResultRunnable;
+    // LINT.IfChange(persisted_params)
+    // Persisted params
     private final int mProfilingType;
-    private final Bundle mParams;
-    private final String mAppFilePath;
+    private final int mTriggerType;
     private final int mUid;
-    private final String mPackageName;
-    private final String mTag;
+    @NonNull private final String mPackageName;
+    @Nullable private final String mTag;
     private final long mKeyMostSigBits;
     private final long mKeyLeastSigBits;
-    private String mKey = null;
-    private String mFileName;
-    private String mDestinationFileName = null;
-    private String mRedactedFileName = null;
-    private long mRedactionStartTimeMs;
-    private TracingState mState;
+    @Nullable private String mFileName = null;
+    @Nullable private String mRedactedFileName = null;
+    @NonNull private TracingState mState;
     private int mRetryCount = 0;
-    private long mProfilingStartTimeMs;
-    private int mMaxProfilingTimeAllowedMs = 0;
-    private String mErrorMessage = null;
-
+    @Nullable private String mErrorMessage = null;
     // Expected to be populated with ProfilingResult.ERROR_* values.
     private int mErrorStatus = -1; // Default to invalid value.
+    // LINT.ThenChange(:from_proto)
+
+    // Non-persisted params
+    @Nullable private final Bundle mParams;
+    @Nullable private Process mActiveTrace;
+    @Nullable private Process mActiveRedaction;
+    @Nullable private Runnable mProcessResultRunnable;
+    @Nullable private String mKey = null;
+    @Nullable private String mDestinationFileName = null;
+    private long mRedactionStartTimeMs;
+    private long mProfilingStartTimeMs;
+    private int mMaxProfilingTimeAllowedMs = 0;
 
-    public TracingSession(int profilingType, Bundle params, String appFilePath, int uid,
-                String packageName, String tag, long keyMostSigBits, long keyLeastSigBits) {
+    public TracingSession(int profilingType,  int uid, String packageName, int triggerType) {
+        this(
+                profilingType,
+                null,
+                uid,
+                packageName,
+                null,
+                0L,
+                0L,
+                triggerType);
+    }
+
+    public TracingSession(int profilingType, Bundle params, int uid, String packageName, String tag,
+            long keyMostSigBits, long keyLeastSigBits) {
+        this(
+                profilingType,
+                params,
+                uid,
+                packageName,
+                tag,
+                keyMostSigBits,
+                keyLeastSigBits,
+                -1); // TODO: b/373461116 - set to NONE after API is published.
+    }
+
+    public TracingSession(int profilingType, Bundle params, int uid, String packageName, String tag,
+            long keyMostSigBits, long keyLeastSigBits, int triggerType) {
         mProfilingType = profilingType;
+        mTriggerType = triggerType;
         mParams = params;
-        mAppFilePath = appFilePath;
         mUid = uid;
         mPackageName = packageName;
         mTag = tag;
@@ -65,6 +99,45 @@ public final class TracingSession {
         mState = TracingState.REQUESTED;
     }
 
+    // LINT.IfChange(from_proto)
+    public TracingSession(QueuedResultsWrapper.TracingSession sessionProto) {
+        mProfilingType = sessionProto.getProfilingType();
+        mUid = sessionProto.getUid();
+        mPackageName = sessionProto.getPackageName();
+        mTag = sessionProto.getTag();
+        mKeyMostSigBits = sessionProto.getKeyMostSigBits();
+        mKeyLeastSigBits = sessionProto.getKeyLeastSigBits();
+        if (sessionProto.hasFileName()) {
+            mFileName = sessionProto.getFileName();
+        }
+        if (sessionProto.hasRedactedFileName()) {
+            mRedactedFileName = sessionProto.getRedactedFileName();
+        }
+        mState = TracingState.of(sessionProto.getTracingState());
+        mRetryCount = sessionProto.getRetryCount();
+        if (sessionProto.hasErrorMessage()) {
+            mErrorMessage = sessionProto.getErrorMessage();
+        }
+        mErrorStatus = sessionProto.getErrorStatus();
+        mTriggerType = sessionProto.getTriggerType();
+
+        // params is not persisted because we cannot guarantee that it does not contain some large
+        // store of data, and because we don't need it anymore once the request has gotten to the
+        // point of being persisted.
+        mParams = null;
+
+        if (mState == null || mState.getValue() < TracingState.PROFILING_FINISHED.getValue()) {
+            // This should never happen. If state is null, then we can't know what to do next. If
+            // the state is earlier than PROFILING_FINISHED then it should not have been in the
+            // queue and therefore should not have been persisted. Either way, update the state to
+            // indicate that the caller was already notified (because we can't know what to notify),
+            // this will ensure that all that's remaining is cleanup.
+            mState = TracingState.NOTIFIED_REQUESTER;
+            Log.e(TAG, "Attempting to load a queued session with an invalid state.");
+        }
+    }
+    // LINT.ThenChange(:to_proto)
+
     public byte[] getConfigBytes() throws IllegalArgumentException {
         return Configs.generateConfigForRequest(mProfilingType, mParams, mPackageName);
     }
@@ -86,6 +159,7 @@ public final class TracingSession {
         return mMaxProfilingTimeAllowedMs;
     }
 
+    @Nullable
     public String getKey() {
         if (mKey == null) {
             mKey = (new UUID(mKeyMostSigBits, mKeyLeastSigBits)).toString();
@@ -154,14 +228,17 @@ public final class TracingSession {
         mErrorMessage = message;
     }
 
+    @Nullable
     public Process getActiveTrace() {
         return mActiveTrace;
     }
 
+    @Nullable
     public Process getActiveRedaction() {
         return mActiveRedaction;
     }
 
+    @Nullable
     public Runnable getProcessResultRunnable() {
         return mProcessResultRunnable;
     }
@@ -170,18 +247,16 @@ public final class TracingSession {
         return mProfilingType;
     }
 
-    public String getAppFilePath() {
-        return mAppFilePath;
-    }
-
     public int getUid() {
         return mUid;
     }
 
+    @NonNull
     public String getPackageName() {
         return mPackageName;
     }
 
+    @Nullable
     public String getTag() {
         return mTag;
     }
@@ -194,12 +269,14 @@ public final class TracingSession {
         return mKeyLeastSigBits;
     }
 
-    // This returns the name of the file that perfetto created during profiling.  If the profling
+    // This returns the name of the file that perfetto created during profiling. If the profiling
     // type was a trace collection it will return the unredacted trace file name.
+    @Nullable
     public String getFileName() {
         return mFileName;
     }
 
+    @Nullable
     public String getRedactedFileName() {
         return mRedactedFileName;
     }
@@ -213,21 +290,24 @@ public final class TracingSession {
     }
 
     /**
-     * Returns the full path including name of the file being returned to the client.
+     * Returns the relative path starting from apps storage dir including name of the file being
+     * returned to the client.
      * @param appRelativePath relative path to app storage.
-     * @return full file path and name of file.
+     * @return relative file path and name of file.
      */
+    @Nullable
     public String getDestinationFileName(String appRelativePath) {
         if (mFileName == null) {
             return null;
         }
         if (mDestinationFileName == null) {
-            mDestinationFileName = mAppFilePath + appRelativePath
+            mDestinationFileName = appRelativePath
                     + ((this.getRedactedFileName() == null) ? mFileName : mRedactedFileName);
         }
         return mDestinationFileName;
     }
 
+    @NonNull
     public TracingState getState() {
         return mState;
     }
@@ -236,6 +316,7 @@ public final class TracingSession {
         return mRetryCount;
     }
 
+    @Nullable
     public String getErrorMessage() {
         return mErrorMessage;
     }
@@ -243,4 +324,40 @@ public final class TracingSession {
     public int getErrorStatus() {
         return mErrorStatus;
     }
+
+    public int getTriggerType() {
+        return mTriggerType;
+    }
+
+    // LINT.IfChange(to_proto)
+    /** Convert this session to a proto for persisting. */
+    public QueuedResultsWrapper.TracingSession toProto() {
+        QueuedResultsWrapper.TracingSession.Builder tracingSessionBuilder =
+                QueuedResultsWrapper.TracingSession.newBuilder();
+
+        tracingSessionBuilder.setProfilingType(mProfilingType);
+        tracingSessionBuilder.setUid(mUid);
+        tracingSessionBuilder.setPackageName(mPackageName);
+        if (mTag != null) {
+            tracingSessionBuilder.setTag(mTag);
+        }
+        tracingSessionBuilder.setKeyMostSigBits(mKeyMostSigBits);
+        tracingSessionBuilder.setKeyLeastSigBits(mKeyLeastSigBits);
+        if (mFileName != null) {
+            tracingSessionBuilder.setFileName(mFileName);
+        }
+        if (mRedactedFileName != null) {
+            tracingSessionBuilder.setRedactedFileName(mRedactedFileName);
+        }
+        tracingSessionBuilder.setTracingState(mState.getValue());
+        tracingSessionBuilder.setRetryCount(mRetryCount);
+        if (mErrorMessage != null) {
+            tracingSessionBuilder.setErrorMessage(mErrorMessage);
+        }
+        tracingSessionBuilder.setErrorStatus(mErrorStatus);
+        tracingSessionBuilder.setTriggerType(mTriggerType);
+
+        return tracingSessionBuilder.build();
+    }
+    // LINT.ThenChange(/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java:equals)
 }
diff --git a/service/proto/android/os/queue.proto b/service/proto/android/os/queue.proto
new file mode 100644
index 0000000..33d4fee
--- /dev/null
+++ b/service/proto/android/os/queue.proto
@@ -0,0 +1,27 @@
+syntax = "proto2";
+
+package android.os;
+
+option java_multiple_files = true;
+
+// LINT.IfChange(proto)
+message QueuedResultsWrapper {
+  message TracingSession {
+    reserved 2;
+    optional int32 profiling_type = 1;
+    optional int32 uid = 3;
+    optional string package_name = 4;
+    optional string tag = 5;
+    optional int64 key_most_sig_bits = 6;
+    optional int64 key_least_sig_bits = 7;
+    optional string file_name = 8;
+    optional string redacted_file_name = 9;
+    optional int32 tracing_state = 10;
+    optional int32 retry_count = 11;
+    optional string error_message = 12;
+    optional int32 error_status = 13;
+    optional int32 trigger_type = 14;
+  }
+  repeated TracingSession sessions = 1;
+}
+// LINT.ThenChange(/service/java/com/android/os/profiling/TracingSession.java:persisted_params)
\ No newline at end of file
diff --git a/service/proto/android/os/trigger.proto b/service/proto/android/os/trigger.proto
new file mode 100644
index 0000000..186b019
--- /dev/null
+++ b/service/proto/android/os/trigger.proto
@@ -0,0 +1,18 @@
+syntax = "proto2";
+
+package android.os;
+
+option java_multiple_files = true;
+
+// LINT.IfChange(proto)
+message ProfilingTriggersWrapper {
+  message ProfilingTrigger {
+    optional int32 uid = 1;
+    optional string package_name = 2;
+    optional int32 trigger_type = 3;
+    optional int32 rate_limiting_period_hours = 4;
+    optional int64 last_triggered_time_millis = 5;
+  }
+  repeated ProfilingTrigger triggers = 1;
+}
+// LINT.ThenChange(/service/java/com/android/os/profiling/ProfilingTrigger.java:params)
\ No newline at end of file
diff --git a/tests/cts/Android.bp b/tests/cts/Android.bp
index aa9b919..4be6a43 100644
--- a/tests/cts/Android.bp
+++ b/tests/cts/Android.bp
@@ -14,7 +14,7 @@ android_test {
         "cts-wm-util",
         "modules-utils-build",
         "service-profiling",
-        "android.os.profiling.flags-aconfig-java",
+        "profiling_flags_lib",
         "framework-profiling.impl",
         "testng",
     ],
diff --git a/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java b/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
index acf60b4..d85dcc4 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
@@ -30,10 +30,13 @@ import static org.mockito.Mockito.verify;
 
 import android.app.Instrumentation;
 import android.content.Context;
+import android.os.Binder;
 import android.os.Bundle;
 import android.os.CancellationSignal;
 import android.os.ProfilingManager;
 import android.os.ProfilingResult;
+import android.os.ProfilingServiceHelper;
+import android.os.ProfilingTrigger;
 import android.os.profiling.DeviceConfigHelper;
 import android.os.profiling.Flags;
 import android.os.profiling.ProfilingService;
@@ -64,6 +67,7 @@ import java.nio.file.FileSystems;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.Paths;
+import java.util.List;
 import java.util.concurrent.atomic.AtomicBoolean;
 import java.util.function.Consumer;
 
@@ -92,8 +96,13 @@ public final class ProfilingFrameworkTests {
     private static final int RATE_LIMITER_WAIT_TIME_INCREMENTS_COUNT = 12;
 
     // Wait 2 seconds for profiling to get started before attempting to cancel it.
+    // TODO: b/376440094 - change to query perfetto and confirm profiling is running.
     private static final int WAIT_TIME_FOR_PROFILING_START_MS = 2 * 1000;
 
+    // Wait 10 seconds for profiling to potentially clone, process, and return result to confirm it
+    // did not occur.
+    private static final int WAIT_TIME_FOR_TRIGGERED_PROFILING_NO_RESULT = 10 * 1000;
+
     // Keep in sync with {@link ProfilingService} because we can't access it.
     private static final String OUTPUT_FILE_JAVA_HEAP_DUMP_SUFFIX = ".perfetto-java-heap-dump";
     private static final String OUTPUT_FILE_HEAP_PROFILE_SUFFIX = ".perfetto-heap-profile";
@@ -105,6 +114,11 @@ public final class ProfilingFrameworkTests {
 
     private static final String COMMAND_OVERRIDE_DEVICE_CONFIG_INT = "device_config put %s %s %d";
     private static final String COMMAND_OVERRIDE_DEVICE_CONFIG_BOOL = "device_config put %s %s %b";
+    private static final String COMMAND_OVERRIDE_DEVICE_CONFIG_STRING =
+            "device_config put %s %s %s";
+    private static final String COMMAND_DELETE_DEVICE_CONFIG_STRING = "device_config delete %s %s";
+
+    private static final String REAL_PACKAGE_NAME = "com.android.profiling.tests";
 
     private static final int ONE_SECOND_MS = 1 * 1000;
     private static final int FIVE_SECONDS_MS = 5 * 1000;
@@ -143,8 +157,10 @@ public final class ProfilingFrameworkTests {
 
     @SuppressWarnings("GuardedBy") // Suppress warning for mProfilingManager.mProfilingService lock.
     @After
-    public void cleanup() {
+    public void cleanup() throws Exception {
         mProfilingManager.mProfilingService = null;
+        executeShellCmd(COMMAND_DELETE_DEVICE_CONFIG_STRING, DeviceConfigHelper.NAMESPACE_TESTING,
+                DeviceConfigHelper.SYSTEM_TRIGGERED_TEST_PACKAGE_NAME);
     }
 
     /** Check and see if we can get a reference to the ProfilingManager service. */
@@ -862,6 +878,99 @@ public final class ProfilingFrameworkTests {
         verify(mProfilingManager.mProfilingService, times(0)).generalListenerAdded();
     }
 
+    /**
+     * Test adding a profiling trigger and receiving a result works correctly.
+     *
+     * This is done by: adding the trigger through the public api, force starting a system triggered
+     * trace, sending a fake trigger as if from the system, and then confirming the result is
+     * received.
+     */
+    @SuppressWarnings("GuardedBy") // Suppress warning for mProfilingManager lock.
+    @Test
+    @RequiresFlagsEnabled(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testSystemTriggeredProfiling() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        // First add a trigger
+        ProfilingTrigger trigger = new ProfilingTrigger.Builder(ProfilingTrigger.TRIGGER_TYPE_ANR)
+                .setRateLimitingPeriodHours(1)
+                .build();
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
+        // Now fake a system trigger.
+        ProfilingServiceHelper.getInstance().onProfilingTriggerOccurred(Binder.getCallingUid(),
+                REAL_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR);
+
+        // Wait for the trace to process.
+        waitForCallback(callbackGeneral);
+
+        // Finally, confirm that a result was received.
+        confirmCollectionSuccess(callbackGeneral.mResult, OUTPUT_FILE_TRACE_SUFFIX);
+    }
+
+    /**
+     * Test removing profiling trigger.
+     *
+     * There is no way to check the data structure from this context and that specifically is tested
+     * in {@link ProfilingServiceTests}, so this test just ensures that a result is not received.
+     */
+    @SuppressWarnings("GuardedBy") // Suppress warning for mProfilingManager lock.
+    @Test
+    @RequiresFlagsEnabled(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testSystemTriggeredProfilingRemove() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        // First add a trigger
+        ProfilingTrigger trigger = new ProfilingTrigger.Builder(ProfilingTrigger.TRIGGER_TYPE_ANR)
+                .setRateLimitingPeriodHours(1)
+                .build();
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
+        // Remove the trigger.
+        mProfilingManager.removeProfilingTriggersByType(
+                new int[]{ProfilingTrigger.TRIGGER_TYPE_ANR});
+
+        // Now fake a system trigger.
+        ProfilingServiceHelper.getInstance().onProfilingTriggerOccurred(Binder.getCallingUid(),
+                REAL_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR);
+
+        // We can't wait for nothing to happen, so wait 10 seconds which should be long enough.
+        sleep(WAIT_TIME_FOR_TRIGGERED_PROFILING_NO_RESULT);
+
+        // Finally, confirm that no callback was received.
+        assertNull(callbackGeneral.mResult);
+    }
+
     /** Disable the rate limiter and wait long enough for the update to be picked up. */
     private void disableRateLimiter() {
         SystemUtil.runShellCommand(
diff --git a/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java b/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
index fc11e73..80061d1 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
@@ -23,6 +23,7 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
@@ -43,10 +44,14 @@ import android.os.ProfilingManager;
 import android.os.ProfilingResult;
 import android.os.profiling.DeviceConfigHelper;
 import android.os.profiling.ProfilingService;
+import android.os.profiling.ProfilingTrigger;
 import android.os.profiling.RateLimiter;
 import android.os.profiling.TracingSession;
+import android.platform.test.annotations.EnableFlags;
 import android.platform.test.flag.junit.CheckFlagsRule;
 import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.platform.test.flag.junit.SetFlagsRule;
+import android.util.SparseArray;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.test.platform.app.InstrumentationRegistry;
@@ -56,6 +61,7 @@ import com.android.compatibility.common.util.SystemUtil;
 
 import com.google.errorprone.annotations.FormatMethod;
 
+import org.junit.After;
 import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
@@ -69,6 +75,7 @@ import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.List;
 import java.util.UUID;
+import java.util.concurrent.TimeUnit;
 
 /**
  * Tests in this class are for testing the ProfilingService directly without the need to get a
@@ -78,11 +85,15 @@ import java.util.UUID;
 @RunWith(AndroidJUnit4.class)
 public final class ProfilingServiceTests {
 
-    private static final String APP_FILE_PATH = "/data/user/0/com.android.profiling.tests/files";
     private static final String APP_PACKAGE_NAME = "com.android.profiling.tests";
     private static final String REQUEST_TAG = "some unique string";
 
     private static final String OVERRIDE_DEVICE_CONFIG_INT = "device_config put %s %s %d";
+    private static final String GET_DEVICE_CONFIG = "device_config get %s %s";
+    private static final String DELETE_DEVICE_CONFIG = "device_config delete %s %s";
+
+    private static final String PERSIST_TEST_DIR = "testdir";
+    private static final String PERSIST_TEST_FILE = "testfile";
 
     // Key most and least significant bits are used to generate a unique key specific to each
     // request. Key is used to pair request back to caller and callbacks so test to keep consistent.
@@ -90,9 +101,11 @@ public final class ProfilingServiceTests {
     private static final long KEY_LEAST_SIG_BITS = 123l;
 
     private static final int FAKE_UID = 12345;
+    private static final int FAKE_UID_2 = 12346;
 
     @Rule
     public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+    @Rule public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
 
     @Mock private Process mActiveTrace;
 
@@ -115,12 +128,43 @@ public final class ProfilingServiceTests {
         }));
         mProfilingService.mRateLimiter = mRateLimiter;
 
-        // Override the persist file/directory and instead point to our own file/directory in app
-        // storage, since the test app context can't access /data/system
+        // Override the persist file/directory, for both queue and rate limiter, and instead point
+        // to our own file/directory in app storage, since the test app context can't access
+        // /data/system
         doReturn(true).when(mRateLimiter).setupPersistFiles();
-        mRateLimiter.mPersistStoreDir = new File(mContext.getFilesDir(), "testdir");
+        mRateLimiter.mPersistStoreDir = new File(mContext.getFilesDir(), PERSIST_TEST_DIR);
         mRateLimiter.mPersistStoreDir.mkdir();
-        mRateLimiter.mPersistFile = new File(mRateLimiter.mPersistStoreDir, "testfile");
+        mRateLimiter.mPersistFile = new File(mRateLimiter.mPersistStoreDir, PERSIST_TEST_FILE);
+
+        doReturn(true).when(mProfilingService).setupPersistQueueFiles();
+        mProfilingService.mPersistStoreDir =
+                new File(mContext.getFilesDir(), PERSIST_TEST_DIR);
+        // Same dir for both, no need to create the 2nd time.
+        mProfilingService.mPersistQueueFile =
+                new File(mProfilingService.mPersistStoreDir, PERSIST_TEST_FILE);
+
+        doReturn(true).when(mProfilingService).setupPersistAppTriggerFiles();
+        mProfilingService.mPersistAppTriggersFile =
+                new File(mProfilingService.mPersistStoreDir, PERSIST_TEST_FILE);
+    }
+
+    @After
+    public void cleanup() throws Exception {
+        // Delete any local persist files.
+        if (mRateLimiter.mPersistFile != null) {
+            mRateLimiter.mPersistFile.delete();
+        }
+        if (mProfilingService.mPersistQueueFile != null) {
+            // This doesn't really do anything as the 2 file objects point to the same actual file
+            // on disk, but just in case that changes try the delete here too.
+            mProfilingService.mPersistQueueFile.delete();
+        }
+
+        // Remove any overrides set for period.
+        executeShellCmd(DELETE_DEVICE_CONFIG, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.SYSTEM_TRIGGERED_TRACE_MIN_PERIOD_SECONDS);
+        executeShellCmd(DELETE_DEVICE_CONFIG, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.SYSTEM_TRIGGERED_TRACE_MAX_PERIOD_SECONDS);
     }
 
     /** Test that registering binder callbacks works as expected. */
@@ -160,8 +204,7 @@ public final class ProfilingServiceTests {
 
         // Kick off request.
         mProfilingService.requestProfiling(ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null,
-                APP_FILE_PATH, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
-                APP_PACKAGE_NAME);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, APP_PACKAGE_NAME);
 
         // Confirm callbacks was triggered for callback registered to this process.
         assertTrue(callback.mResultSent);
@@ -191,8 +234,7 @@ public final class ProfilingServiceTests {
 
         // Kick off request.
         mProfilingService.requestProfiling(ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null,
-                APP_FILE_PATH, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
-                APP_PACKAGE_NAME);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, APP_PACKAGE_NAME);
 
         // Confirm callbacks was triggered for callback registered to this process.
         assertTrue(callbackOne.mResultSent);
@@ -214,8 +256,7 @@ public final class ProfilingServiceTests {
 
         // Kick off request.
         mProfilingService.requestProfiling(ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null,
-                APP_FILE_PATH, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
-                APP_PACKAGE_NAME);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, APP_PACKAGE_NAME);
 
         // Confirm result matches failure expectation.
         confirmResultCallback(callback, null, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
@@ -236,8 +277,8 @@ public final class ProfilingServiceTests {
         mProfilingService.registerResultsCallback(false, callback);
 
         // Kick off request.
-        mProfilingService.requestProfiling(-1, null, APP_FILE_PATH, REQUEST_TAG,
-                KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, APP_PACKAGE_NAME);
+        mProfilingService.requestProfiling(-1, null, REQUEST_TAG, KEY_MOST_SIG_BITS,
+                KEY_LEAST_SIG_BITS, APP_PACKAGE_NAME);
 
         // Confirm result matches failure expectation.
         confirmResultCallback(callback, null, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
@@ -253,8 +294,7 @@ public final class ProfilingServiceTests {
 
         // Kick off request.
         mProfilingService.requestProfiling(ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null,
-                APP_FILE_PATH, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
-                null);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, null);
 
         // Confirm result matches failure expectation.
         confirmResultCallback(callback, null, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
@@ -270,8 +310,7 @@ public final class ProfilingServiceTests {
 
         // Kick off request.
         mProfilingService.requestProfiling(ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null,
-                APP_FILE_PATH, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
-                "not.my.application");
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, "not.my.application");
 
         // Confirm result matches failure expectation.
         confirmResultCallback(callback, null, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
@@ -286,7 +325,7 @@ public final class ProfilingServiceTests {
 
         // Mock rate limiter result to simulate failure case.
         doReturn(RateLimiter.RATE_LIMIT_RESULT_BLOCKED_PROCESS).when(mRateLimiter)
-              .isProfilingRequestAllowed(anyInt(), anyInt(), any());
+              .isProfilingRequestAllowed(anyInt(), anyInt(), eq(false), any());
 
         // Register callback.
         ProfilingResultCallback callback = new ProfilingResultCallback();
@@ -294,8 +333,7 @@ public final class ProfilingServiceTests {
 
         // Kick off request.
         mProfilingService.requestProfiling(ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null,
-                APP_FILE_PATH, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
-                APP_PACKAGE_NAME);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, APP_PACKAGE_NAME);
 
         // Confirm result matches failure expectation.
         confirmResultCallback(callback, null, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
@@ -315,8 +353,7 @@ public final class ProfilingServiceTests {
 
         // Kick off request.
         mProfilingService.requestProfiling(ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null,
-                APP_FILE_PATH, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
-                APP_PACKAGE_NAME);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, APP_PACKAGE_NAME);
 
         // Perfetto cannot be run from this context, ensure it was attempted and failed permissions.
         confirmResultCallback(callback, null, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS,
@@ -333,8 +370,8 @@ public final class ProfilingServiceTests {
 
         // Create a tracing session.
         TracingSession tracingSession = new TracingSession(
-                ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, APP_FILE_PATH, 123,
-                APP_PACKAGE_NAME, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
+                ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, 123, APP_PACKAGE_NAME,
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
 
         // Mock tracing session to be running.
         doReturn(true).when(mActiveTrace).isAlive();
@@ -356,8 +393,8 @@ public final class ProfilingServiceTests {
         assertFalse(mProfilingService.areAnyTracesRunning());
 
         TracingSession tracingSession = new TracingSession(
-                ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, APP_FILE_PATH, 123,
-                APP_PACKAGE_NAME, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
+                ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, 123, APP_PACKAGE_NAME,
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
         mProfilingService.mActiveTracingSessions.put(
                 (new UUID(KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS)).toString(), tracingSession);
 
@@ -373,8 +410,8 @@ public final class ProfilingServiceTests {
         assertFalse(mProfilingService.areAnyTracesRunning());
 
         TracingSession tracingSession = new TracingSession(
-                ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, APP_FILE_PATH, 123,
-                APP_PACKAGE_NAME, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
+                ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, 123, APP_PACKAGE_NAME,
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
         mProfilingService.mActiveTracingSessions.put(
                 (new UUID(KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS)).toString(), tracingSession);
 
@@ -643,7 +680,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -670,7 +706,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -700,7 +735,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -719,6 +753,428 @@ public final class ProfilingServiceTests {
         verify(mProfilingService, times(1)).cleanupTracingSession(any());
     }
 
+    /**
+     * Test that persisting the queue and then reloading it from disk works correctly, loading the
+     * previous queue and all persistable fields.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_PERSIST_QUEUE)
+    public void testQueuePersist_PersistAndRestore() {
+        // Clear the queue.
+        mProfilingService.mQueuedTracingResults.clear();
+
+        // A 2nd fake uid so we can have records belonging to multiple uids.
+        int fakeUid2 = FAKE_UID + 1;
+
+        // Create 3 fake sessions with various fields set on each.
+        TracingSession session1 = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
+                new Bundle(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session1.setProfilingStartTimeMs(System.currentTimeMillis());
+        session1.setState(TracingState.PROFILING_FINISHED);
+
+        TracingSession session2 = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP,
+                new Bundle(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session2.setProfilingStartTimeMs(System.currentTimeMillis());
+        session2.setState(TracingState.ERROR_OCCURRED);
+        session2.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING, "some error message");
+
+        TracingSession session3 = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
+                new Bundle(),
+                fakeUid2,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session3.setProfilingStartTimeMs(System.currentTimeMillis());
+        session3.setState(TracingState.REDACTED);
+
+        // Create 2 session lists.
+        List<TracingSession> sessionListUid1 = new ArrayList<TracingSession>();
+        List<TracingSession> sessionListUid2 = new ArrayList<TracingSession>();
+
+        // Add 2 sessions to the first list and 1 to the second list.
+        sessionListUid1.add(session1);
+        sessionListUid1.add(session2);
+        sessionListUid2.add(session3);
+
+        // Add each of the lists to the queue.
+        mProfilingService.mQueuedTracingResults.put(FAKE_UID, sessionListUid1);
+        mProfilingService.mQueuedTracingResults.put(fakeUid2, sessionListUid2);
+
+        // Trigger a persist.
+        mProfilingService.persistQueueToDisk();
+
+        // Confirm file was written to
+        confirmNonEmptyFileExists(mProfilingService.mPersistQueueFile);
+
+        // Clear the queue so we can ensure it is reloaded properly.
+        mProfilingService.mQueuedTracingResults.clear();
+        assertEquals(0, mProfilingService.mQueuedTracingResults.size());
+
+        // Load the queue from disk.
+        mProfilingService.loadQueueFromPersistedData();
+
+        // Finally, verify the loaded contents match the ones that were persisted.
+        // First check that the queue contains 2 lists, as added above.
+        assertEquals(2, mProfilingService.mQueuedTracingResults.size());
+
+        // Now, confirm that there are 2 queued results belonging to the first uid, and 1 belonging
+        // to the 2nd uid, as defined above.
+        assertEquals(2, mProfilingService.mQueuedTracingResults.get(FAKE_UID).size());
+        assertEquals(1, mProfilingService.mQueuedTracingResults.get(fakeUid2).size());
+
+        // Lastly, check that each loaded session is equal its persisted counterpart.
+        confirmTracingSessionsEqual(session1,
+                mProfilingService.mQueuedTracingResults.get(FAKE_UID).get(0));
+        confirmTracingSessionsEqual(session2,
+                mProfilingService.mQueuedTracingResults.get(FAKE_UID).get(1));
+        confirmTracingSessionsEqual(session3,
+                mProfilingService.mQueuedTracingResults.get(fakeUid2).get(0));
+    }
+
+    /**
+     * Test that loading queue with no persist file works as intended with no records added and
+     * correct methods called.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_PERSIST_QUEUE)
+    public void testQueuePersist_NoPersistFile() {
+        // Clear the queue.
+        mProfilingService.mQueuedTracingResults.clear();
+
+        // Ensure the file doesn't exist.
+        mProfilingService.mPersistQueueFile.delete();
+        assertFalse(mProfilingService.mPersistQueueFile.exists());
+
+        // Load the queue from disk.
+        mProfilingService.loadQueueFromPersistedData();
+
+        // Ensure queue still empty.
+        assertEquals(0, mProfilingService.mQueuedTracingResults.size());
+        verify(mProfilingService, times(0)).deletePersistQueueFile();
+    }
+
+    /**
+     * Test that loading queue with an empty persist file works as intended with no records added
+     * and correct methods called.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_PERSIST_QUEUE)
+    public void testQueuePersist_EmptyPersistFile() throws Exception {
+        // Clear the queue.
+        mProfilingService.mQueuedTracingResults.clear();
+
+        // Ensure the file exists and is empty.
+        mProfilingService.mPersistQueueFile.delete();
+        assertFalse(mProfilingService.mPersistQueueFile.exists());
+        mProfilingService.mPersistQueueFile.createNewFile();
+        assertTrue(mProfilingService.mPersistQueueFile.exists());
+        assertEquals(0L, mProfilingService.mPersistQueueFile.length());
+
+        // Load the queue from disk.
+        mProfilingService.loadQueueFromPersistedData();
+
+        // Ensure that the queue is still empty and that a delete was attempted as expected for the
+        // bad file state.
+        assertEquals(0, mProfilingService.mQueuedTracingResults.size());
+        verify(mProfilingService, times(1)).deletePersistQueueFile();
+    }
+
+    /**
+     * Test that loading queue with a invalid persist file works as intended with no records added
+     * and correct methods called.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_PERSIST_QUEUE)
+    public void testQueuePersist_BadPersistFile() throws Exception {
+        // Clear the queue.
+        mProfilingService.mQueuedTracingResults.clear();
+
+        // Ensure the file exists and is empty.
+        mProfilingService.mPersistQueueFile.delete();
+        mProfilingService.mPersistQueueFile.createNewFile();
+        FileOutputStream fileOutputStream = new FileOutputStream(
+                mProfilingService.mPersistQueueFile);
+        fileOutputStream.write("some text that is definitely not a proto".getBytes());
+        fileOutputStream.close();
+        confirmNonEmptyFileExists(mProfilingService.mPersistQueueFile);
+
+        // Load the queue from disk.
+        mProfilingService.loadQueueFromPersistedData();
+
+        // Ensure that the queue is still empty and that a delete was attempted as expected for the
+        // bad file state.
+        assertEquals(0, mProfilingService.mQueuedTracingResults.size());
+        verify(mProfilingService, times(1)).deletePersistQueueFile();
+    }
+
+    /**
+     * Test that persisting queue respects the frequency defined, allowing the persist on the first
+     * instance but rejecting the subsequent persist.
+     *
+     * While this test focuses on queue persist, the logic for respect frequency is shared with
+     * triggers so this test covers both.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_PERSIST_QUEUE)
+    public void testQueuePersist_RespectFrequency() throws Exception {
+        // Override persist frequency to something large.
+        updateDeviceConfigAndWaitForChange(DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.PERSIST_TO_DISK_FREQUENCY_MS, 60 * 60 * 1000);
+
+        // Clear the queue.
+        mProfilingService.mQueuedTracingResults.clear();
+
+        // Populate the queue.
+        List<TracingSession> sessionList = new ArrayList<TracingSession>();
+        TracingSession session1 = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
+                new Bundle(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session1.setProfilingStartTimeMs(System.currentTimeMillis());
+        session1.setState(TracingState.PROFILING_FINISHED);
+        TracingSession session2 = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP,
+                new Bundle(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session2.setProfilingStartTimeMs(System.currentTimeMillis());
+        session2.setState(TracingState.ERROR_OCCURRED);
+        session2.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING, "some error message");
+
+        sessionList.add(session1);
+        sessionList.add(session2);
+        mProfilingService.mQueuedTracingResults.put(FAKE_UID, sessionList);
+
+        // Trigger a persist.
+        mProfilingService.maybePersistToDisk();
+
+        // Confirm that it actually persisted.
+        verify(mProfilingService, times(1)).persistQueueToDisk();
+        assertTrue(mProfilingService.mPersistQueueFile.exists());
+
+        // Delete the file so we can confirm the next call does nothing.
+        assertTrue(mProfilingService.mPersistQueueFile.delete());
+
+        // Finally, trigger another persist.
+        mProfilingService.maybePersistToDisk();
+
+        // And confirm the persist did not immediately run.
+        assertFalse(mProfilingService.mPersistQueueFile.exists());
+        // Verify with same value as earlier so we know it didn't get triggered again.
+        verify(mProfilingService, times(1)).persistQueueToDisk();
+    }
+
+    /**
+     * Test that persists that are scheduled for the future due to a persist having recently
+     * occurred, occur at a future time as expected.
+     *
+     * While this test focuses on queue persist, the logic for scheduling is shared with triggers so
+     * this test covers both.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_PERSIST_QUEUE)
+    public void testQueuePersist_Scheduling() throws Exception {
+        // Override persist frequency to 5 seconds that way we can confirm both that the persist did
+        // not happen immediately and that it did eventually happen. This is the time from the first
+        // call to maybePersistToDisk until the next call to the same method for the scheduling
+        // of the next persist to occur as expected, rather than immediately persisting.
+        updateDeviceConfigAndWaitForChange(DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.PERSIST_TO_DISK_FREQUENCY_MS, 5 * 1000);
+
+        // Clear the queue.
+        mProfilingService.mQueuedTracingResults.clear();
+
+        // Populate the queue.
+        TracingSession session = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
+                new Bundle(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session.setProfilingStartTimeMs(System.currentTimeMillis());
+        session.setState(TracingState.PROFILING_FINISHED);
+
+        List<TracingSession> sessionList = new ArrayList<TracingSession>();
+        sessionList.add(session);
+        mProfilingService.mQueuedTracingResults.put(FAKE_UID, sessionList);
+
+        // Trigger a persist.
+        mProfilingService.maybePersistToDisk();
+
+        // Confirm that it actually persisted.
+        assertTrue(mProfilingService.mPersistQueueFile.exists());
+
+        // Delete the file so that we can later use its existence to confirm whether the next
+        // persist occurred.
+        assertTrue(mProfilingService.mPersistQueueFile.delete());
+
+        // Trigger another persist.
+        mProfilingService.maybePersistToDisk();
+
+        // And confirm the persist did not immediately run.
+        assertFalse(mProfilingService.mPersistQueueFile.exists());
+
+        // Wait 1 second longer than the configured delay to be sure the persist had time to finish.
+        sleep(6 * 1000);
+
+        // Finally, confirm that the file now exists.
+        assertTrue(mProfilingService.mPersistQueueFile.exists());
+    }
+
+    /**
+     * Test that persisting app triggers and then reloading them from disk works correctly, loading
+     * all previous triggers.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testAppTriggersPersist_PersistAndRestore() {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Create 3 triggers belonging to 2 uids. Add a last triggered time to one of them.
+        ProfilingTrigger trigger1 = new ProfilingTrigger(FAKE_UID, APP_PACKAGE_NAME, 1, 0);
+
+        ProfilingTrigger trigger2 = new ProfilingTrigger(FAKE_UID, APP_PACKAGE_NAME, 2, 1);
+        trigger2.setLastTriggeredTimeMs(123L);
+
+        ProfilingTrigger trigger3 = new ProfilingTrigger(FAKE_UID_2, APP_PACKAGE_NAME, 1, 2);
+
+        // Group into sparse arrays by uid.
+        SparseArray<ProfilingTrigger> triggerArray1 = new SparseArray<ProfilingTrigger>();
+        triggerArray1.put(1, trigger1);
+        triggerArray1.put(2, trigger2);
+
+        SparseArray<ProfilingTrigger> triggerArray2 = new SparseArray<ProfilingTrigger>();
+        triggerArray2.put(1, trigger3);
+
+        mProfilingService.mAppTriggers.put(APP_PACKAGE_NAME, FAKE_UID, triggerArray1);
+        mProfilingService.mAppTriggers.put(APP_PACKAGE_NAME, FAKE_UID_2, triggerArray2);
+
+        // Trigger a persist.
+        mProfilingService.persistAppTriggersToDisk();
+
+        // Confirm file was written to
+        confirmNonEmptyFileExists(mProfilingService.mPersistAppTriggersFile);
+
+        // Clear app triggers so we can ensure it is reloaded properly.
+        mProfilingService.mAppTriggers.getMap().clear();
+        assertEquals(0, mProfilingService.mAppTriggers.getMap().size());
+
+        // Load app triggers from disk.
+        mProfilingService.loadAppTriggersFromPersistedData();
+
+        // Finally, verify the loaded contents match the ones that were persisted.
+        confirmProfilingTriggerEquals(trigger1,
+                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(1));
+        confirmProfilingTriggerEquals(trigger2,
+                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(2));
+        confirmProfilingTriggerEquals(trigger3,
+                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID_2).get(1));
+    }
+
+    /**
+     * Test that loading app triggers with no persist file works as intended with no triggers added,
+     * loaded set to true, and correct methods called.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testAppTriggersPersist_NoPersistFile() {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Ensure the file doesn't exist.
+        mProfilingService.mPersistAppTriggersFile.delete();
+        assertFalse(mProfilingService.mPersistAppTriggersFile.exists());
+
+        // Load app triggers from disk.
+        mProfilingService.loadAppTriggersFromPersistedData();
+
+        // Ensure that the triggers are still empty, that loaded was set to true, and that a delete
+        // was not attempted as there was no file to delete.
+        assertEquals(0, mProfilingService.mAppTriggers.getMap().size());
+        assertTrue(mProfilingService.mAppTriggersLoaded);
+        verify(mProfilingService, times(0)).deletePersistAppTriggersFile();
+    }
+
+    /**
+     * Test that loading app triggers with an empty persist file works as intended with no triggers
+     * added, loaded set to true, and correct methods called.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_PERSIST_QUEUE)
+    public void testAppTriggersPersist_EmptyPersistFile() throws Exception {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Ensure the file exists and is empty.
+        mProfilingService.mPersistAppTriggersFile.delete();
+        assertFalse(mProfilingService.mPersistAppTriggersFile.exists());
+        mProfilingService.mPersistAppTriggersFile.createNewFile();
+        assertTrue(mProfilingService.mPersistAppTriggersFile.exists());
+        assertEquals(0L, mProfilingService.mPersistAppTriggersFile.length());
+
+        // Load app triggers from disk.
+        mProfilingService.loadAppTriggersFromPersistedData();
+
+        // Ensure that the triggers are still empty, that loaded was set to true, and that a delete
+        // was attempted as expected for the bad file state.
+        assertEquals(0, mProfilingService.mAppTriggers.getMap().size());
+        assertTrue(mProfilingService.mAppTriggersLoaded);
+        verify(mProfilingService, times(1)).deletePersistAppTriggersFile();
+    }
+
+    /**
+     * Test that loading app triggers with an invalid persist file works as intended with no
+     * triggers added, loaded set to true, and correct methods called.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_PERSIST_QUEUE)
+    public void testAppTriggersPersist_BadPersistFile() throws Exception {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Ensure the file exists and contains some non proto contents.
+        mProfilingService.mPersistAppTriggersFile.delete();
+        mProfilingService.mPersistAppTriggersFile.createNewFile();
+        FileOutputStream fileOutputStream = new FileOutputStream(
+                mProfilingService.mPersistAppTriggersFile);
+        fileOutputStream.write("some text that is definitely not a proto".getBytes());
+        fileOutputStream.close();
+        confirmNonEmptyFileExists(mProfilingService.mPersistAppTriggersFile);
+
+        // Load app triggers from disk.
+        mProfilingService.loadAppTriggersFromPersistedData();
+
+        // Ensure that the triggers are still empty, that loaded was set to true, and that a delete
+        // was attempted as expected for the bad file state.
+        assertEquals(0, mProfilingService.mAppTriggers.getMap().size());
+        assertTrue(mProfilingService.mAppTriggersLoaded);
+        verify(mProfilingService, times(1)).deletePersistAppTriggersFile();
+    }
+
     /** Test that adding a specific listener does not trigger handling queued results. */
     @Test
     public void testQueuedResult_RequestSpecificListener() {
@@ -767,7 +1223,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -806,7 +1261,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -844,7 +1298,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_STACK_SAMPLING,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 uid,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -883,7 +1336,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -921,7 +1373,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 uid,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -964,7 +1415,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -1001,7 +1451,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -1039,7 +1488,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -1077,7 +1525,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -1121,7 +1568,6 @@ public final class ProfilingServiceTests {
         TracingSession session = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -1164,7 +1610,6 @@ public final class ProfilingServiceTests {
         TracingSession session1 = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 FAKE_UID,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -1174,7 +1619,6 @@ public final class ProfilingServiceTests {
         TracingSession session2 = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 fakeUid2,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -1184,7 +1628,6 @@ public final class ProfilingServiceTests {
         TracingSession session3 = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP,
                 new Bundle(),
-                mContext.getFilesDir().getPath(),
                 fakeUid2,
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
@@ -1248,6 +1691,246 @@ public final class ProfilingServiceTests {
         assertEquals(2, mProfilingService.mResultCallbacks.get(Binder.getCallingUid()).size());
     }
 
+    /**
+     * Test that adding triggers adds to the correct process and overwrites with new results when
+     * the same trigger, uid, and process name are used.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testAddTriggers() throws Exception {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Now add several triggers:
+        // First add 2 different triggers to the same uid/package
+        // TODO: b/373461116 - update hardcoded triggers to api value
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, 1, 0);
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, 2, 0);
+        // And add one to another uid with the same package name.
+        mProfilingService.addTrigger(FAKE_UID_2, APP_PACKAGE_NAME, 2, 0);
+
+        // Grab the per process arrays.
+        SparseArray<ProfilingTrigger> uid1Triggers =
+                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID);
+        SparseArray<ProfilingTrigger> uid2Triggers =
+                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID_2);
+
+        // Confirm they are represented correctly.
+        assertEquals(2, uid1Triggers.size());
+        assertEquals(1, uid2Triggers.size());
+        confirmProfilingTriggerEquals(uid1Triggers.get(1), FAKE_UID, APP_PACKAGE_NAME, 1, 0);
+        confirmProfilingTriggerEquals(uid1Triggers.get(2), FAKE_UID, APP_PACKAGE_NAME, 2, 0);
+        confirmProfilingTriggerEquals(uid2Triggers.get(2), FAKE_UID_2, APP_PACKAGE_NAME, 2, 0);
+
+        // Now add a repeated trigger with 1 field changed.
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, 2, 100);
+
+        // Confirm the new value is set.
+        assertEquals(100, mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(2)
+                .getRateLimitingPeriodHours());
+    }
+
+    /** Test that app level rate limiting works correctly in the allow case. */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testProcessTrigger_appLevelRateLimit_allow() throws Exception {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Override the system rate limiter to always pass, we're not testing that here.
+        doReturn(RateLimiter.RATE_LIMIT_RESULT_ALLOWED).when(mRateLimiter)
+                .isProfilingRequestAllowed(anyInt(), anyInt(), eq(true), any());
+
+        // And setup some mocks.
+        mProfilingService.mSystemTriggeredTraceUniqueSessionName = "something_non_null";
+        doReturn(true).when(mActiveTrace).isAlive();
+        mProfilingService.mSystemTriggeredTraceProcess = mActiveTrace;
+
+        // TODO: b/373461116 - update hardcoded trigger to api value
+        int fakeTrigger = 1;
+
+        // Setup some rate limiting values. Since this is an allow test, set the last run to be 1
+        // hour more than the rate limiting period.
+        int rateLimitingPeriodHours = 10;
+        long fakeLastTriggerTimeMs = System.currentTimeMillis()
+                - ((rateLimitingPeriodHours + 1) * 60L * 60L * 1000L);
+
+        // Add the trigger we'll use.
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger,
+                rateLimitingPeriodHours);
+
+        // Set the last run time.
+        mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(fakeTrigger)
+                .setLastTriggeredTimeMs(fakeLastTriggerTimeMs);
+
+        // Now process the trigger.
+        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger);
+
+        // Get the new trigger time and make sure it's later than the fake one, indicating it ran.
+        long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .get(fakeTrigger).getLastTriggeredTimeMs();
+        assertTrue(newTriggerTime > fakeLastTriggerTimeMs);
+    }
+
+    /** Test that app level rate limiting works correctly in the deny case. */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testProcessTrigger_appLevelRateLimit_deny() throws Exception {
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // Override the system rate limiter to always pass, we're not testing that here.
+        doReturn(RateLimiter.RATE_LIMIT_RESULT_ALLOWED).when(mRateLimiter)
+                .isProfilingRequestAllowed(anyInt(), anyInt(), eq(true), any());
+
+        // And setup some mocks.
+        mProfilingService.mSystemTriggeredTraceUniqueSessionName = "something_non_null";
+        doReturn(true).when(mActiveTrace).isAlive();
+        mProfilingService.mSystemTriggeredTraceProcess = mActiveTrace;
+
+        // TODO: b/373461116 - update hardcoded trigger to api value
+        int fakeTrigger = 1;
+
+        // Setup some rate limiting values. Since this is a deny test, set the last run to be 1 hour
+        // less than the rate limiting period.
+        int rateLimitingPeriodHours = 10;
+        long fakeLastTriggerTimeMs = System.currentTimeMillis()
+                - ((rateLimitingPeriodHours - 1) * 60L * 60L * 1000L);
+
+        // Add the trigger we'll use,
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger,
+                rateLimitingPeriodHours);
+
+        // Set the last run time.
+        mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(fakeTrigger)
+                .setLastTriggeredTimeMs(fakeLastTriggerTimeMs);
+
+        // Now process the trigger.
+        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger);
+
+        // Get the new trigger time and make sure it's equal to the fake one, indicating it did not
+        // run.
+        long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .get(fakeTrigger).getLastTriggeredTimeMs();
+        assertEquals(fakeLastTriggerTimeMs, newTriggerTime);
+    }
+
+    /** Test that system level rate limiting works correctly in the allow case. */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testProcessTrigger_systemLevelRateLimit_allow() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // And setup some mocks.
+        mProfilingService.mSystemTriggeredTraceUniqueSessionName = "something_non_null";
+        doReturn(true).when(mActiveTrace).isAlive();
+        mProfilingService.mSystemTriggeredTraceProcess = mActiveTrace;
+
+        // TODO: b/373461116 - update hardcoded trigger to api value
+        int fakeTrigger = 1;
+
+        // Set app level rate limiting to 0, we're not testing that here.
+        int rateLimitingPeriodHours = 0;
+
+        // Add the trigger we'll use.
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger,
+                rateLimitingPeriodHours);
+
+        // Now process the trigger.
+        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger);
+
+        // Get the new trigger time and make sure it's later than 0, indicating it ran.
+        long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .get(fakeTrigger).getLastTriggeredTimeMs();
+        assertTrue(newTriggerTime > 0);
+    }
+
+    /** Test that system level rate limiting works correctly in the deny case. */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testProcessTrigger_systemLevelRateLimit_deny() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // First, clear the data structure.
+        mProfilingService.mAppTriggers.getMap().clear();
+
+        // And setup some mocks.
+        mProfilingService.mSystemTriggeredTraceUniqueSessionName = "something_non_null";
+        doReturn(true).when(mActiveTrace).isAlive();
+        mProfilingService.mSystemTriggeredTraceProcess = mActiveTrace;
+
+        // Add record with high cost to rate limiter so that it won't allow future runs.
+        mRateLimiter.mPastRunsHour.add(FAKE_UID, 1000, System.currentTimeMillis());
+
+        // Wait 1 ms to ensure time has ticked and avoid potential flake.
+        sleep(1);
+
+        // TODO: b/373461116 - update hardcoded trigger to api value
+        int fakeTrigger = 1;
+
+        // Set app level rate limiting to 0, we're not testing that here.
+        int rateLimitingPeriodHours = 0;
+
+        // Add the trigger we'll use,
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger,
+                rateLimitingPeriodHours);
+
+        // Now process the trigger.
+        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger);
+
+        // Get the new trigger time and make sure it's equal to 0, indicating it did not run.
+        long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .get(fakeTrigger).getLastTriggeredTimeMs();
+        assertEquals(0, newTriggerTime);
+    }
+
+    /**
+     * Test that scheduling for system triggered profiling trace start works correctly, configuring
+     * run delay for correct amount of time.
+     */
+    @Test
+    @EnableFlags(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testSystemTriggeredProfiling_Scheduling() throws Exception {
+        // Override system triggered trace start values so that the trace will be attempted to be
+        // started within the test duration. If these values are changed, make sure to update the
+        // additional delay below as well.
+        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.SYSTEM_TRIGGERED_TRACE_MIN_PERIOD_SECONDS, 3);
+        updateDeviceConfigAndWaitForChange(DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.SYSTEM_TRIGGERED_TRACE_MAX_PERIOD_SECONDS, 4);
+
+        // Cancel the already scheduled future and set to null, if applicable.
+        if (mProfilingService.mStartSystemTriggeredTraceScheduledFuture != null) {
+            mProfilingService.mStartSystemTriggeredTraceScheduledFuture.cancel(true);
+            mProfilingService.mStartSystemTriggeredTraceScheduledFuture = null;
+        }
+
+        // Schedule a start of system triggered trace.
+        mProfilingService.scheduleNextSystemTriggeredTraceStart();
+
+        // Confirm the future is scheduled and that an attempt to start the trace has not occurred
+        // yet.
+        assertNotNull(mProfilingService.mStartSystemTriggeredTraceScheduledFuture);
+        assertFalse(mProfilingService.mStartSystemTriggeredTraceScheduledFuture.isDone());
+        verify(mProfilingService, times(0)).startSystemTriggeredTrace();
+
+        // Wait for 2 seconds longer than the scheduled future delay so that the future can execute
+        // once, but not twice. 2 seconds is selected as the extra delay because it is less than 3
+        // which is set as min for period above, but also the highest value possible to give time to
+        // execute.
+        long delay = mProfilingService.mStartSystemTriggeredTraceScheduledFuture.getDelay(
+                TimeUnit.SECONDS);
+        sleep((delay + 2L) * 1000L);
+
+        // Finally, confirm that the future ran by confirming that an attempt to start the trace was
+        // made. We don't confirm that it actually started as we can't actually start the trace from
+        // this context.
+        verify(mProfilingService, times(1)).startSystemTriggeredTrace();
+    }
+
     private File createAndConfirmFileExists(File directory, String fileName) throws Exception {
         File file = new File(directory, fileName);
         file.createNewFile();
@@ -1266,12 +1949,13 @@ public final class ProfilingServiceTests {
     private void overrideRateLimiterDefaults() throws Exception {
         // Update DeviceConfig defaults to general high enough limits, cost of 1, and persist
         // frequency 0.
-        overrideRateLimiterDefaults(5, 10, 20, 50, 50, 100, 1, 1, 1, 1, 0);
+        overrideRateLimiterDefaults(5, 10, 20, 50, 50, 100, 1, 1, 1, 1, 1, 0);
     }
 
     private void overrideRateLimiterDefaults(int systemHour, int processHour, int systemDay,
             int processDay, int systemWeek, int processWeek, int costHeapDump, int costHeapProfile,
-            int costStackSampling, int costSystemTrace, int persistToDiskFrequency)
+            int costStackSampling, int costSystemTrace, int costSystemTriggeredSystemProfiling,
+            int persistToDiskFrequency)
             throws Exception {
         executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
                 DeviceConfigHelper.MAX_COST_SYSTEM_1_HOUR, systemHour);
@@ -1293,6 +1977,9 @@ public final class ProfilingServiceTests {
                 DeviceConfigHelper.COST_STACK_SAMPLING, costStackSampling);
         executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
                 DeviceConfigHelper.COST_SYSTEM_TRACE, costSystemTrace);
+        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.COST_SYSTEM_TRIGGERED_SYSTEM_TRACE,
+                costSystemTriggeredSystemProfiling);
         executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
                 DeviceConfigHelper.PERSIST_TO_DISK_FREQUENCY_MS, persistToDiskFrequency);
     }
@@ -1313,6 +2000,40 @@ public final class ProfilingServiceTests {
         }
     }
 
+    // LINT.IfChange(equals)
+    private void confirmTracingSessionsEqual(TracingSession s1, TracingSession s2) {
+        assertEquals(s1.getProfilingType(), s2.getProfilingType());
+        assertEquals(s1.getUid(), s2.getUid());
+        assertEquals(s1.getPackageName(), s2.getPackageName());
+        assertEquals(s1.getTag(), s2.getTag());
+        assertEquals(s1.getKeyMostSigBits(), s2.getKeyMostSigBits());
+        assertEquals(s1.getKeyLeastSigBits(), s2.getKeyLeastSigBits());
+        assertEquals(s1.getFileName(), s2.getFileName());
+        assertEquals(s1.getRedactedFileName(), s2.getRedactedFileName());
+        assertEquals(s1.getState().getValue(), s2.getState().getValue());
+        assertEquals(s1.getRetryCount(), s2.getRetryCount());
+        assertEquals(s1.getErrorMessage(), s2.getErrorMessage());
+        assertEquals(s1.getErrorStatus(), s2.getErrorStatus());
+        assertEquals(s1.getTriggerType(), s2.getTriggerType());
+    }
+    // LINT.ThenChange(/service/proto/android/os/queue.proto:proto)
+
+    // LINT.IfChange(trigger_equals)
+    private void confirmProfilingTriggerEquals(ProfilingTrigger t1, int uid, String packageName,
+            int triggerType, int rateLimitingPeriodHours) {
+        confirmProfilingTriggerEquals(t1,
+                new ProfilingTrigger(uid, packageName, triggerType, rateLimitingPeriodHours));
+    }
+
+    private void confirmProfilingTriggerEquals(ProfilingTrigger t1, ProfilingTrigger t2) {
+        assertEquals(t1.getUid(), t2.getUid());
+        assertEquals(t1.getPackageName(), t2.getPackageName());
+        assertEquals(t1.getTriggerType(), t2.getTriggerType());
+        assertEquals(t1.getRateLimitingPeriodHours(), t2.getRateLimitingPeriodHours());
+        assertEquals(t1.getLastTriggeredTimeMs(), t2.getLastTriggeredTimeMs());
+    }
+    // LINT.ThenChange(/service/proto/android/os/trigger.proto:proto)
+
     /** Confirm that all fields returned by callback match expectation. */
     private void confirmResultCallback(ProfilingResultCallback callback, String resultFile,
             long keyMostSigBits, long keyLeastSigBits, int status, String tag,
@@ -1329,6 +2050,36 @@ public final class ProfilingServiceTests {
         }
     }
 
+    /**
+     * Update the provided device config value and wait for up to 2 seconds, checking every 100ms,
+     * for the value change to take effect.
+     */
+    private void updateDeviceConfigAndWaitForChange(String namespace, String config, int newValue)
+            throws Exception {
+        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, namespace, config, newValue);
+        for (int i = 0; i < 20; i++) {
+            sleep(100);
+            String s = executeShellCmd(GET_DEVICE_CONFIG, namespace, config);
+            try {
+                int val = Integer.parseInt(s.trim());
+                if (val == newValue) {
+                    return;
+                }
+            } catch (NumberFormatException e) {
+                // Ignore and continue.
+            }
+        }
+        fail("DeviceConfig value never updated to match expected value.");
+    }
+
+    private static void sleep(long ms) {
+        try {
+            Thread.sleep(ms);
+        } catch (InterruptedException e) {
+            // Do nothing.
+        }
+    }
+
     public class ProfilingResultCallback extends IProfilingResultCallback.Stub {
         boolean mResultSent = false;
         boolean mFileRequested = false;
```

