```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index be1f046..728e4cf 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,4 +1,14 @@
 {
+  "mainline-presubmit": [
+    {
+      "name": "CtsProfilingModuleTests[com.google.android.profiling.apex]",
+      "options": [
+        {
+          "exclude-annotation": "androidx.test.filters.LargeTest"
+        }
+      ]
+    }
+  ],
   "presubmit": [
     {
       "name": "CtsProfilingModuleTests",
diff --git a/apex/Android.bp b/apex/Android.bp
index f890da6..625d324 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -27,26 +27,12 @@ android_app_certificate {
     certificate: "com.android.profiling",
 }
 
-soong_config_module_type {
-    name: "custom_apex",
-    module_type: "apex",
-    config_namespace: "ANDROID",
-    bool_variables: [
-        "release_package_profiling_module",
-    ],
-    properties: [
-        "enabled",
-    ],
-}
-
-custom_apex {
+apex {
     // This apex will be enabled with release_package_profiling_module flag
-    enabled: false,
-    soong_config_variables: {
-        release_package_profiling_module: {
-            enabled: true,
-        },
-    },
+    enabled: select(release_flag("RELEASE_PACKAGE_PROFILING_MODULE"), {
+        true: true,
+        false: false,
+    }),
 
     name: "com.android.profiling",
     manifest: "manifest.json",
@@ -54,58 +40,30 @@ custom_apex {
     key: "com.android.profiling.key",
     certificate: ":com.android.profiling.certificate",
     defaults: ["v-launched-apex-module"],
-    min_sdk_version: "current",
+    min_sdk_version: "35",
 
     bootclasspath_fragments: ["com.android.profiling-bootclasspath-fragment"],
     systemserverclasspath_fragments: ["com.android.profiling-systemserverclasspath-fragment"],
 }
 
-soong_config_module_type {
-    name: "custom_systemserverclasspath_fragment",
-    module_type: "systemserverclasspath_fragment",
-    config_namespace: "ANDROID",
-    bool_variables: [
-        "release_package_profiling_module",
-    ],
-    properties: [
-        "enabled",
-    ],
-}
-
-custom_systemserverclasspath_fragment {
+systemserverclasspath_fragment {
     // This fragment will be enabled with release_package_profiling_module flag
-    enabled: false,
-    soong_config_variables: {
-        release_package_profiling_module: {
-            enabled: true,
-        },
-    },
+    enabled: select(release_flag("RELEASE_PACKAGE_PROFILING_MODULE"), {
+        true: true,
+        false: false,
+    }),
 
     name: "com.android.profiling-systemserverclasspath-fragment",
     standalone_contents: ["service-profiling"],
     apex_available: ["com.android.profiling"],
 }
 
-soong_config_module_type {
-    name: "custom_bootclasspath_fragment",
-    module_type: "bootclasspath_fragment",
-    config_namespace: "ANDROID",
-    bool_variables: [
-        "release_package_profiling_module",
-    ],
-    properties: [
-        "enabled",
-    ],
-}
-
-custom_bootclasspath_fragment {
+bootclasspath_fragment {
     // This fragment will be enabled with release_package_profiling_module flag
-    enabled: false,
-    soong_config_variables: {
-        release_package_profiling_module: {
-            enabled: true,
-        },
-    },
+    enabled: select(release_flag("RELEASE_PACKAGE_PROFILING_MODULE"), {
+        true: true,
+        false: false,
+    }),
 
     name: "com.android.profiling-bootclasspath-fragment",
     contents: ["framework-profiling"],
diff --git a/framework/Android.bp b/framework/Android.bp
index ee1f609..45575ac 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -74,7 +74,7 @@ java_sdk_library {
     apex_available: [
         "com.android.profiling",
     ],
-    min_sdk_version: "current",
+    min_sdk_version: "35",
 }
 
 aconfig_declarations {
@@ -92,6 +92,7 @@ java_aconfig_library {
         "com.android.profiling",
     ],
     mode: "exported",
+    min_sdk_version: "35",
     defaults: ["framework-minus-apex-aconfig-java-defaults"],
     visibility: [
         "//packages/modules/Profiling:__subpackages__",
diff --git a/framework/java/android/os/ProfilingManager.java b/framework/java/android/os/ProfilingManager.java
index 011738f..c0db9c7 100644
--- a/framework/java/android/os/ProfilingManager.java
+++ b/framework/java/android/os/ProfilingManager.java
@@ -38,7 +38,39 @@ import java.util.concurrent.Executor;
 import java.util.function.Consumer;
 
 /**
- * API for apps to request and listen for app specific profiling.
+ * <p>
+ * This class allows the caller to request profiling and listen for results. Profiling types
+ * supported are: system traces, java heap dumps, heap profiles, and stack traces.
+ * </p>
+ *
+ * <p>
+ * The {@link #requestProfiling} API can be used to begin profiling. Profiling may be ended manually
+ * using the CancellationSignal provided in the request, or as a result of a timeout. The timeout
+ * may be either the system default or caller defined in the parameter bundle for select types.
+ * </p>
+ *
+ * <p>
+ * The profiling results are delivered to the requesting app's data directory and a pointer to the
+ * file will be received using the app provided listeners.
+ * </p>
+ *
+ * <p>
+ * Apps can provide listeners in one or both of two ways:
+ * - A request-specific listener included with the request. This will trigger only with a result
+ *     from the request it was provided with.
+ * - A global listener provided by {@link #registerForAllProfilingResults}. This will be triggered
+ *     for all results belonging to your app.
+ * </p>
+ *
+ * <p>
+ * Requests are rate limited and not guaranteed to be filled. Rate limiting can be disabled for
+ * local testing using the shell command
+ * {@code device_config put profiling_testing rate_limiter.disabled true}
+ * </p>
+ *
+ * <p>
+ * Results are redacted and contain specific information about the requesting process only.
+ * </p>
  */
 @FlaggedApi(Flags.FLAG_TELEMETRY_APIS)
 public final class ProfilingManager {
@@ -156,7 +188,7 @@ public final class ProfilingManager {
      * <p>
      *   Both a listener and an executor must be set at the time of the request for the request to
      *   be considered for fulfillment. Listener/executor pairs can be set in this method, with
-     *   {@link registerForAllProfilingResults}, or both. The listener and executor must be set
+     *   {@link #registerForAllProfilingResults}, or both. The listener and executor must be set
      *   together, in the same call. If no listener and executor combination is set, the request
      *   will be discarded and no callback will be received.
      * </p>
@@ -168,7 +200,7 @@ public final class ProfilingManager {
      * <p>
      *   There might be a delay before profiling begins.
      *   For continuous profiling types (system tracing, stack sampling, and heap profiling),
-     *   we recommend starting the collection early and stopping it with {@link cancellationSignal}
+     *   we recommend starting the collection early and stopping it with {@code cancellationSignal}
      *   immediately after the area of interest to ensure that the section you want profiled is
      *   captured.
      *   For heap dumps, we recommend testing locally to ensure that the heap dump is collected at
@@ -178,9 +210,9 @@ public final class ProfilingManager {
      * @param profilingType Type of profiling to collect.
      * @param parameters Bundle of request related parameters. If the bundle contains any
      *                  unrecognized parameters, the request will be fail with
-     *                  {@link #ProfilingResult#ERROR_FAILED_INVALID_REQUEST}. If the values for
-     *                  the parameters are out of supported range, the closest possible in range
-     *                  value will be chosen.
+     *                  {@link android.os.ProfilingResult#ERROR_FAILED_INVALID_REQUEST}. If the
+     *                  values for the parameters are out of supported range, the closest possible
+     *                  in range value will be chosen.
      *                  Use of androidx wrappers is recommended over generating this directly.
      * @param tag Caller defined data to help identify the output.
      *                  The first 20 alphanumeric characters, plus dashes, will be lowercased
diff --git a/service/Android.bp b/service/Android.bp
index 51c6b76..a8edfde 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -31,7 +31,7 @@ java_library {
     libs: [
         "framework-annotations-lib",
         "framework-profiling.impl",
-        "framework-configinfrastructure",
+        "framework-configinfrastructure.stubs.module_lib",
     ],
     static_libs: [
         "modules-utils-build",
@@ -45,7 +45,7 @@ java_library {
     apex_available: [
         "com.android.profiling",
     ],
-    min_sdk_version: "current",
+    min_sdk_version: "35",
     installable: true,
 }
 
@@ -66,7 +66,7 @@ java_library {
         "//packages/modules/Profiling/tests:__subpackages__",
     ],
     installable: false,
-    min_sdk_version: "current",
+    min_sdk_version: "35",
     sdk_version: "system_server_current",
     apex_available: [
         "com.android.profiling",
diff --git a/service/java/com/android/os/profiling/ProfilingService.java b/service/java/com/android/os/profiling/ProfilingService.java
index b21181f..565b442 100644
--- a/service/java/com/android/os/profiling/ProfilingService.java
+++ b/service/java/com/android/os/profiling/ProfilingService.java
@@ -125,7 +125,7 @@ public class ProfilingService extends IProfilingService.Stub {
     // Request UUID key indexed storage of active tracing sessions. Currently only 1 active session
     // is supported at a time, but this will be used in future to support multiple.
     @VisibleForTesting
-    public ArrayMap<String, TracingSession> mTracingSessions = new ArrayMap<>();
+    public ArrayMap<String, TracingSession> mActiveTracingSessions = new ArrayMap<>();
 
     // uid indexed storage of completed tracing sessions that have not yet successfully handled the
     // result.
@@ -136,6 +136,51 @@ public class ProfilingService extends IProfilingService.Stub {
     @GuardedBy("mLock")
     private boolean mKeepUnredactedTrace = false;
 
+    /**
+     * State the {@link TracingSession} is in.
+     *
+     * State represents the most recently confirmed completed step in the process. Steps represent
+     * save points which the process would have to go back to if it did not successfully reach the
+     * next step.
+     *
+     * States are sequential. It can be expected that state value will only increase throughout a
+     * sessions life.
+     *
+     * At different states, the containing object can be assumed to exist in different data
+     * structures as follows:
+     * REQUESTED - Local only, not in any data structure.
+     * APPROVED - Local only, not in any data structure.
+     * PROFILING_STARTED - Stored in {@link mActiveTracingSessions}.
+     * PROFILING_FINISHED - Stored in {@link mQueuedTracingResults}.
+     * REDACTED - Stored in {@link mQueuedTracingResults}.
+     * COPIED_FILE - Stored in {@link mQueuedTracingResults}.
+     * ERROR_OCCURRED - Stored in {@link mQueuedTracingResults}.
+     * NOTIFIED_REQUESTER - Stored in {@link mQueuedTracingResults}.
+     * CLEANED_UP - Local only, not in any data structure.
+     */
+    public enum TracingState {
+        // Intentionally skipping 0 since proto, which willl be used for persist, treats it as
+        // unset.
+        REQUESTED(1),
+        APPROVED(2),
+        PROFILING_STARTED(3),
+        PROFILING_FINISHED(4),
+        REDACTED(5),
+        COPIED_FILE(6),
+        ERROR_OCCURRED(7),
+        NOTIFIED_REQUESTER(8),
+        CLEANED_UP(9);
+
+        private final int mValue;
+        TracingState(int value) {
+            mValue = value;
+        }
+
+        public int getValue() {
+            return mValue;
+        }
+    }
+
     @VisibleForTesting
     public ProfilingService(Context context) {
         mContext = context;
@@ -241,6 +286,103 @@ public class ProfilingService extends IProfilingService.Stub {
         }, mClearTemporaryDirectoryBootDelayMs);
     }
 
+    /**
+     * This is the core method that keeps the profiling flow moving.
+     *
+     * This is the only way that state should be set. Do not use {@link TracingSession#setState}
+     * directly.
+     *
+     * The passed newState represents the state that was just completed. Passing null for new state
+     * will continue using the current state as the last completed state, this is intended only for
+     * resuming the queue.
+     *
+     * Generally, this should be the last call in a method before returning.
+     */
+    @VisibleForTesting
+    public void advanceTracingSession(TracingSession session, @Nullable TracingState newState) {
+        if (newState == null) {
+            if (session.getRetryCount() == 0) {
+                // The new state should only be null if this is triggered from the queue in which
+                // case the retry count should be greater than 0. If retry count is 0 here then
+                // we're in an unexpected state. Cleanup and discard. Result will be lost.
+                cleanupTracingSession(session);
+                return;
+            }
+        } else if (newState == session.getState()) {
+            // This should never happen.
+            // If the state is not actually changing then we may find ourselves in an infinite
+            // loop. Terminate this attempt and increment the retry count to ensure there's a
+            // path to breaking out of a potential infinite queue retries.
+            session.incrementRetryCount();
+            return;
+        } else if (newState.getValue() < session.getState().getValue()) {
+            // This should also never happen.
+            // States should always move forward. If the state is trying to move backwards then
+            // we don't actually know what to do next. Clean up the session and delete
+            // everything. Results will be lost.
+            cleanupTracingSession(session);
+            return;
+        } else {
+            // The new state is not null so update the sessions state.
+            session.setState(newState);
+        }
+
+        switch (session.getState()) {
+            case REQUESTED:
+                // This should never happen as requested state is expected to handled by the request
+                // method, the first actionable state is approved. Ignore it.
+                if (DEBUG) {
+                    Log.e(TAG, "Session attempting to advance with REQUESTED state unsupported.");
+                }
+                break;
+            case APPROVED:
+                // Session has been approved by rate limiter, so continue on to start profiling.
+                startProfiling(session);
+                break;
+            case PROFILING_STARTED:
+                // Profiling has been successfully started. Next step depends on whether or not the
+                // profiling is alive.
+                if (session.getActiveTrace() == null || !session.getActiveTrace().isAlive()
+                        || session.getProcessResultRunnable() == null) {
+                    // This really should not happen, but if profiling is not in correct started
+                    // state then try to stop and continue processing it.
+                    stopProfiling(session);
+                } // else: do nothing. The runnable we just verified exists will return us to this
+                // method when profiling is finished.
+                break;
+            case PROFILING_FINISHED:
+                // Next step depends on whether or not the result requires redaction.
+                if (needsRedaction(session)) {
+                    // Redaction needed, kick it off.
+                    handleRedactionRequiredResult(session);
+                } else {
+                    // No redaction needed, move straight to copying to app storage.
+                    beginMoveFileToAppStorage(session);
+                }
+                break;
+            case REDACTED:
+                // Redaction completed, move on to copying to app storage.
+                beginMoveFileToAppStorage(session);
+                break;
+            case COPIED_FILE:
+                // File has already been copied to app storage, proceed to callback.
+                session.setError(ProfilingResult.ERROR_NONE);
+                processTracingSessionResultCallback(session, true /* Continue advancing session */);
+                break;
+            case ERROR_OCCURRED:
+                // An error has occurred, proceed to callback.
+                processTracingSessionResultCallback(session, true /* Continue advancing session */);
+                break;
+            case NOTIFIED_REQUESTER:
+                // Callback has been completed successfully, start cleanup.
+                cleanupTracingSession(session);
+                break;
+            case CLEANED_UP:
+                // Session was cleaned up, nothing left to do.
+                break;
+        }
+    }
+
     /** Perform a temporary directory cleanup if it has been long enough to warrant one. */
     private void maybeCleanupTemporaryDirectory() {
         synchronized (mLock) {
@@ -318,9 +460,9 @@ public class ProfilingService extends IProfilingService.Stub {
         List<String> filenames = new ArrayList<String>();
 
         // If active sessions is not empty, iterate through and add the filenames from each.
-        if (!mTracingSessions.isEmpty()) {
-            for (int i = 0; i < mTracingSessions.size(); i++) {
-                TracingSession session = mTracingSessions.valueAt(i);
+        if (!mActiveTracingSessions.isEmpty()) {
+            for (int i = 0; i < mActiveTracingSessions.size(); i++) {
+                TracingSession session = mActiveTracingSessions.valueAt(i);
                 String filename = session.getFileName();
                 if (filename != null) {
                     filenames.add(filename);
@@ -432,7 +574,8 @@ public class ProfilingService extends IProfilingService.Stub {
             try {
                 TracingSession session = new TracingSession(profilingType, params, filePath, uid,
                         packageName, tag, keyMostSigBits, keyLeastSigBits);
-                startProfiling(session);
+                advanceTracingSession(session, TracingState.APPROVED);
+                return;
             } catch (IllegalArgumentException e) {
                 // This should not happen, it should have been caught when checking rate limiter.
                 // Issue with the request. Apps fault.
@@ -609,43 +752,39 @@ public class ProfilingService extends IProfilingService.Stub {
             return;
         }
 
-        // Only copy the file if we haven't previously.
-        if (session.getState().getValue() < TracingSession.TracingState.COPIED_FILE.getValue()) {
-            // Setup file streams.
-            try {
-                tempPerfettoFileInStream = new FileInputStream(tempResultFile);
-            } catch (IOException e) {
-                // IO Exception opening temp perfetto file. No result.
-                if (DEBUG) Log.d(TAG, "Exception opening temp perfetto file.", e);
-                finishReceiveFileDescriptor(session, fileDescriptor, tempPerfettoFileInStream,
-                        appFileOutStream, false);
-                return;
-            }
+        // Setup file streams.
+        try {
+            tempPerfettoFileInStream = new FileInputStream(tempResultFile);
+        } catch (IOException e) {
+            // IO Exception opening temp perfetto file. No result.
+            if (DEBUG) Log.d(TAG, "Exception opening temp perfetto file.", e);
+            finishReceiveFileDescriptor(session, fileDescriptor, tempPerfettoFileInStream,
+                    appFileOutStream, false);
+            return;
+        }
 
-            // Obtain a file descriptor for the result file in app storage from
-            // {@link ProfilingManager}
-            if (fileDescriptor != null) {
-                appFileOutStream = new FileOutputStream(fileDescriptor.getFileDescriptor());
-            }
+        // Obtain a file descriptor for the result file in app storage from
+        // {@link ProfilingManager}
+        if (fileDescriptor != null) {
+            appFileOutStream = new FileOutputStream(fileDescriptor.getFileDescriptor());
+        }
 
-            if (appFileOutStream == null) {
-                finishReceiveFileDescriptor(session, fileDescriptor, tempPerfettoFileInStream,
-                        appFileOutStream, false);
-                return;
-            }
+        if (appFileOutStream == null) {
+            finishReceiveFileDescriptor(session, fileDescriptor, tempPerfettoFileInStream,
+                    appFileOutStream, false);
+            return;
+        }
 
-            // Now copy the file over.
-            try {
-                FileUtils.copy(tempPerfettoFileInStream, appFileOutStream);
-                session.setState(TracingSession.TracingState.COPIED_FILE);
-            } catch (IOException e) {
-                // Exception writing to local app file. Attempt to delete the bad copy.
-                deleteBadCopiedFile(session);
-                if (DEBUG) Log.d(TAG, "Exception writing to local app file.", e);
-                finishReceiveFileDescriptor(session, fileDescriptor, tempPerfettoFileInStream,
-                        appFileOutStream, false);
-                return;
-            }
+        // Now copy the file over.
+        try {
+            FileUtils.copy(tempPerfettoFileInStream, appFileOutStream);
+        } catch (IOException e) {
+            // Exception writing to local app file. Attempt to delete the bad copy.
+            deleteBadCopiedFile(session);
+            if (DEBUG) Log.d(TAG, "Exception writing to local app file.", e);
+            finishReceiveFileDescriptor(session, fileDescriptor, tempPerfettoFileInStream,
+                    appFileOutStream, false);
+            return;
         }
 
         finishReceiveFileDescriptor(session, fileDescriptor, tempPerfettoFileInStream,
@@ -679,15 +818,46 @@ public class ProfilingService extends IProfilingService.Stub {
         }
 
         if (session != null) {
-            finishProcessingResult(session, succeeded);
+            if (succeeded) {
+                advanceTracingSession(session, TracingState.COPIED_FILE);
+            } else {
+                // Couldn't move file. File is still in temp directory and will be tried later.
+                // Leave state unchanged so it can get triggered again from the queue, but update
+                // the error and trigger a callback.
+                if (DEBUG) Log.d(TAG, "Couldn't move file to app storage.");
+                session.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING,
+                        "Failed to copy result to app storage. May try again later.");
+                processTracingSessionResultCallback(session, false /* Do not continue */);
+            }
+
+            // Clean up temporary directory if it has been long enough to warrant it.
+            maybeCleanupTemporaryDirectory();
         }
     }
 
-    private void processResultCallback(TracingSession session, int status, @Nullable String error) {
-        processResultCallback(session.getUid(), session.getKeyMostSigBits(),
-                session.getKeyLeastSigBits(), status,
+    /**
+     * An app can register multiple callbacks between this service and {@link ProfilingManager}, one
+     * per context that the app created a manager instance with. As we do not know on this service
+     * side which callbacks need to be triggered with this result, trigger all of them and let them
+     * decide whether to finish delivering it.
+     *
+     * Call this method if a {@link TracingSession} already exists. If no session exists yet, call
+     * {@link #processResultCallback} directly instead.
+     *
+     * @param session           The session for which to callback and potentially advance.
+     * @param continueAdvancing Whether to continue advancing or stop after attempting the callback.
+     */
+    @VisibleForTesting
+    public void processTracingSessionResultCallback(TracingSession session,
+            boolean continueAdvancing) {
+        boolean succeeded = processResultCallback(session.getUid(), session.getKeyMostSigBits(),
+                session.getKeyLeastSigBits(), session.getErrorStatus(),
                 session.getDestinationFileName(OUTPUT_FILE_RELATIVE_PATH),
-                session.getTag(), error);
+                session.getTag(), session.getErrorMessage());
+
+        if (continueAdvancing && succeeded) {
+            advanceTracingSession(session, TracingState.NOTIFIED_REQUESTER);
+        }
     }
 
     /**
@@ -695,25 +865,43 @@ public class ProfilingService extends IProfilingService.Stub {
      * per context that the app created a manager instance with. As we do not know on this service
      * side which callbacks need to be triggered with this result, trigger all of them and let them
      * decide whether to finish delivering it.
+     *
+     * Call this directly only if no {@link TracingSession} exists yet. If a session already exists,
+     * call {@link #processTracingSessionResultCallback} instead.
+     *
+     * @return whether at least one callback was successfully sent to the app.
      */
-    private void processResultCallback(int uid, long keyMostSigBits, long keyLeastSigBits,
+    private boolean processResultCallback(int uid, long keyMostSigBits, long keyLeastSigBits,
             int status, @Nullable String filePath, @Nullable String tag, @Nullable String error) {
         List<IProfilingResultCallback> perUidCallbacks = mResultCallbacks.get(uid);
         if (perUidCallbacks == null || perUidCallbacks.isEmpty()) {
             // No callbacks, nowhere to notify with result or failure.
             if (DEBUG) Log.d(TAG, "No callback to ProfilingManager, callback dropped.");
-            return;
+            return false;
         }
 
+        boolean succeeded = false;
         for (int i = 0; i < perUidCallbacks.size(); i++) {
             try {
-                perUidCallbacks.get(i).sendResult(filePath, keyMostSigBits, keyLeastSigBits, status,
-                        tag, error);
+                if (status == ProfilingResult.ERROR_NONE) {
+                    perUidCallbacks.get(i).sendResult(
+                            filePath, keyMostSigBits, keyLeastSigBits, status, tag, error);
+                } else {
+                    perUidCallbacks.get(i).sendResult(
+                            null, keyMostSigBits, keyLeastSigBits, status, tag, error);
+                }
+                // One success is all we need to know that a callback was sent to the app.
+                // This is not perfect but sufficient given we cannot verify the success of
+                // individual listeners without either a blocking binder call into the app or an
+                // extra binder call back from the app.
+                succeeded = true;
             } catch (RemoteException e) {
                 // Failed to send result. Ignore.
                 if (DEBUG) Log.d(TAG, "Exception processing result callback", e);
             }
         }
+
+        return succeeded;
     }
 
     private void startProfiling(final TracingSession session)
@@ -739,8 +927,9 @@ public class ProfilingService extends IProfilingService.Stub {
         } catch (IllegalArgumentException e) {
             // Request couldn't be processed. This shouldn't happen.
             if (DEBUG) Log.d(TAG, "Request couldn't be processed", e);
-            processResultCallback(session, ProfilingResult.ERROR_FAILED_INVALID_REQUEST,
-                    e.getMessage());
+            session.setError(ProfilingResult.ERROR_FAILED_INVALID_REQUEST, e.getMessage());
+            moveSessionToQueue(session);
+            advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
 
         }
@@ -766,16 +955,16 @@ public class ProfilingService extends IProfilingService.Stub {
             // If we made it this far the trace is running, save the session.
             session.setActiveTrace(activeTrace);
             session.setProfilingStartTimeMs(System.currentTimeMillis());
-            mTracingSessions.put(session.getKey(), session);
+            mActiveTracingSessions.put(session.getKey(), session);
         } catch (Exception e) {
             // Catch all exceptions related to starting process as they'll all be handled similarly.
             if (DEBUG) Log.d(TAG, "Trace couldn't be started", e);
-            processResultCallback(session, ProfilingResult.ERROR_FAILED_EXECUTING, null);
+            session.setError(ProfilingResult.ERROR_FAILED_EXECUTING, "Trace couldn't be started");
+            moveSessionToQueue(session);
+            advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
         }
 
-        session.setState(TracingSession.TracingState.PROFILING_STARTED);
-
         // Create post process runnable, store it, and schedule it.
         session.setProcessResultRunnable(new Runnable() {
             @Override
@@ -785,6 +974,8 @@ public class ProfilingService extends IProfilingService.Stub {
             }
         });
         getHandler().postDelayed(session.getProcessResultRunnable(), postProcessingInitialDelayMs);
+
+        advanceTracingSession(session, TracingState.PROFILING_STARTED);
     }
 
     /**
@@ -795,7 +986,6 @@ public class ProfilingService extends IProfilingService.Stub {
         complete results will be processed and returned to the client.
      */
     private void checkProfilingCompleteRescheduleIfNeeded(TracingSession session) {
-
         long processingTimeRemaining = session.getMaxProfilingTimeAllowedMs()
                 - (System.currentTimeMillis() - session.getProfilingStartTimeMs());
 
@@ -812,21 +1002,22 @@ public class ProfilingService extends IProfilingService.Stub {
         } else {
             // complete, process results and deliver.
             session.setProcessResultRunnable(null);
-            processResult(session);
+            moveSessionToQueue(session);
+            advanceTracingSession(session, TracingState.PROFILING_FINISHED);
         }
     }
 
     /** Stop any active profiling sessions belonging to the provided uid. */
     private void stopAllProfilingForUid(int uid) {
-        if (mTracingSessions.isEmpty()) {
+        if (mActiveTracingSessions.isEmpty()) {
             // If there are no active traces, then there are none for this uid.
             return;
         }
 
         // Iterate through active sessions and stop profiling if they belong to the provided uid.
         // Note: Currently, this will only ever have 1 session.
-        for (int i = 0; i < mTracingSessions.size(); i++) {
-            TracingSession session = mTracingSessions.valueAt(i);
+        for (int i = 0; i < mActiveTracingSessions.size(); i++) {
+            TracingSession session = mActiveTracingSessions.valueAt(i);
             if (session.getUid() == uid) {
                 stopProfiling(session);
             }
@@ -834,7 +1025,7 @@ public class ProfilingService extends IProfilingService.Stub {
     }
 
     private void stopProfiling(String key) throws RuntimeException {
-        TracingSession session = mTracingSessions.get(key);
+        TracingSession session = mActiveTracingSessions.get(key);
         stopProfiling(session);
     }
 
@@ -873,8 +1064,8 @@ public class ProfilingService extends IProfilingService.Stub {
     }
 
     public boolean areAnyTracesRunning() throws RuntimeException {
-        for (int i = 0; i < mTracingSessions.size(); i++) {
-            if (isTraceRunning(mTracingSessions.keyAt(i))) {
+        for (int i = 0; i < mActiveTracingSessions.size(); i++) {
+            if (isTraceRunning(mActiveTracingSessions.keyAt(i))) {
                 return true;
             }
         }
@@ -883,9 +1074,9 @@ public class ProfilingService extends IProfilingService.Stub {
 
     /**
      * Cleanup the data structure of active sessions. Non active sessions are never expected to be
-     * present in {@link mTracingSessions} as they would be moved to {@link mQueuedTracingResults}
-     * when profiling completes. If a session is present but not running, remove it. If a session
-     * has a not alive process, try to stop it.
+     * present in {@link mActiveTracingSessions} as they would be moved to
+     * {@link mQueuedTracingResults} when profiling completes. If a session is present but not
+     * running, remove it. If a session has a not alive process, try to stop it.
      */
     public void cleanupActiveTracingSessions() throws RuntimeException {
         // Create a temporary list to store the keys of sessions to be stopped.
@@ -893,13 +1084,13 @@ public class ProfilingService extends IProfilingService.Stub {
 
         // Iterate through in reverse order so we can immediately remove the non running sessions
         // that don't have to be stopped.
-        for (int i = mTracingSessions.size() - 1; i >= 0; i--) {
-            String key = mTracingSessions.keyAt(i);
-            TracingSession session = mTracingSessions.get(key);
+        for (int i = mActiveTracingSessions.size() - 1; i >= 0; i--) {
+            String key = mActiveTracingSessions.keyAt(i);
+            TracingSession session = mActiveTracingSessions.get(key);
 
             if (session == null || session.getActiveTrace() == null) {
                 // Profiling isn't running, remove from list.
-                mTracingSessions.removeAt(i);
+                mActiveTracingSessions.removeAt(i);
             } else if (!session.getActiveTrace().isAlive()) {
                 // Profiling process exists but isn't alive, add to list of sessions to stop. Do not
                 // stop here due to potential unanticipated modification of list being iterated
@@ -917,7 +1108,7 @@ public class ProfilingService extends IProfilingService.Stub {
     }
 
     public boolean isTraceRunning(String key) throws RuntimeException {
-        TracingSession session = mTracingSessions.get(key);
+        TracingSession session = mActiveTracingSessions.get(key);
         if (session == null || session.getActiveTrace() == null) {
             // No subprocess, nothing running.
             if (DEBUG) Log.d(TAG, "No subprocess, nothing running.");
@@ -940,14 +1131,14 @@ public class ProfilingService extends IProfilingService.Stub {
      */
     @VisibleForTesting
     public void beginMoveFileToAppStorage(TracingSession session) {
-        if (session.getState() == TracingSession.TracingState.DISCARDED) {
-            // This should not have happened, if the session was discarded why are we trying to
-            // continue processing it? Remove from all data stores just in case.
+        if (session.getState().getValue() >= TracingState.ERROR_OCCURRED.getValue()) {
+            // This should not have happened, if the session has a state of error or later then why
+            // are we trying to continue processing it? Remove from all data stores just in case.
             if (DEBUG) {
-                Log.d(TAG, "Attempted beginMoveFileToAppStorage on a session with status discarded"
+                Log.d(TAG, "Attempted beginMoveFileToAppStorage on a session with status error"
                         + " or an invalid status.");
             }
-            mTracingSessions.remove(session.getKey());
+            mActiveTracingSessions.remove(session.getKey());
             cleanupTracingSession(session);
             return;
         }
@@ -963,25 +1154,6 @@ public class ProfilingService extends IProfilingService.Stub {
         requestFileForResult(perUidCallbacks, session);
     }
 
-    /**
-     * Finish processing profiling result by sending the appropriate callback and cleaning up
-     * temporary directory.
-     */
-    @VisibleForTesting
-    public void finishProcessingResult(TracingSession session, boolean success) {
-        if (success) {
-            processResultCallback(session, ProfilingResult.ERROR_NONE, null);
-            cleanupTracingSession(session);
-        } else {
-            // Couldn't move file. File is still in temp directory and will be tried later.
-            if (DEBUG) Log.d(TAG, "Couldn't move file to app storage.");
-            processResultCallback(session, ProfilingResult.ERROR_FAILED_POST_PROCESSING, null);
-        }
-
-        // Clean up temporary directory if it has been long enough to warrant it.
-        maybeCleanupTemporaryDirectory();
-    }
-
     /**
      * Delete a file which failed to copy via ProfilingManager.
      */
@@ -1039,32 +1211,9 @@ public class ProfilingService extends IProfilingService.Stub {
         if (DEBUG) Log.d(TAG, "Failed to obtain file descriptor from callbacks.");
     }
 
-
-    // processResult will be called after every profiling type is collected, traces will go
-    // through a redaction process before being returned to the client.  All other profiling types
-    // can be returned as is.
-    private void processResult(TracingSession session) {
-        // Move this session from active to queued results.
-        List<TracingSession> queuedResults = mQueuedTracingResults.get(session.getUid());
-        if (queuedResults == null) {
-            queuedResults = new ArrayList<TracingSession>();
-            mQueuedTracingResults.put(session.getUid(), queuedResults);
-        }
-        queuedResults.add(session);
-        mTracingSessions.remove(session.getKey());
-
-        session.setState(TracingSession.TracingState.PROFILING_FINISHED);
-
-        if (session.getProfilingType() == ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE) {
-            handleTraceResult(session);
-        } else {
-            beginMoveFileToAppStorage(session);
-        }
-    }
-
-    /** Handle a trace result by attempting to kick off redaction process. */
+    /** Handle a result which required redaction by attempting to kick off redaction process. */
     @VisibleForTesting
-    public void handleTraceResult(TracingSession session) {
+    public void handleRedactionRequiredResult(TracingSession session) {
         try {
             // We need to create an empty file for the redaction process to write the output into.
             File emptyRedactedTraceFile = new File(TEMP_TRACE_PATH
@@ -1072,7 +1221,8 @@ public class ProfilingService extends IProfilingService.Stub {
             emptyRedactedTraceFile.createNewFile();
         } catch (Exception exception) {
             if (DEBUG) Log.e(TAG, "Creating empty redacted file failed.", exception);
-            processResultCallback(session, ProfilingResult.ERROR_FAILED_POST_PROCESSING, null);
+            session.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING);
+            advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
         }
 
@@ -1088,9 +1238,11 @@ public class ProfilingService extends IProfilingService.Stub {
             session.setRedactionStartTimeMs(System.currentTimeMillis());
         } catch (Exception exception) {
             if (DEBUG) Log.e(TAG, "Redaction failed to run completely.", exception);
-            processResultCallback(session, ProfilingResult.ERROR_FAILED_POST_PROCESSING, null);
+            session.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING);
+            advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
         }
+
         session.setProcessResultRunnable(new Runnable() {
 
             @Override
@@ -1098,7 +1250,6 @@ public class ProfilingService extends IProfilingService.Stub {
                 checkRedactionStatus(session);
             }
         });
-
         getHandler().postDelayed(session.getProcessResultRunnable(),
                 mRedactionCheckFrequencyMs);
     }
@@ -1118,11 +1269,12 @@ public class ProfilingService extends IProfilingService.Stub {
 
             session.getActiveRedaction().destroyForcibly();
             session.setProcessResultRunnable(null);
-            processResultCallback(session, ProfilingResult.ERROR_FAILED_POST_PROCESSING,
-                    null);
-
+            session.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING);
+            advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
         }
+
+        // Schedule the next check.
         getHandler().postDelayed(session.getProcessResultRunnable(),
                 Math.min(mRedactionCheckFrequencyMs, mRedactionMaxRuntimeAllottedMs
                         - (System.currentTimeMillis() - session.getRedactionStartTimeMs())));
@@ -1138,7 +1290,8 @@ public class ProfilingService extends IProfilingService.Stub {
                         redactionErrorCode));
             }
             cleanupTracingSession(session);
-            processResultCallback(session, ProfilingResult.ERROR_FAILED_POST_PROCESSING, null);
+            session.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING);
+            advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
         }
 
@@ -1154,9 +1307,7 @@ public class ProfilingService extends IProfilingService.Stub {
             }
         }
 
-        session.setState(TracingSession.TracingState.REDACTED);
-
-        beginMoveFileToAppStorage(session);
+        advanceTracingSession(session, TracingState.REDACTED);
     }
 
     /**
@@ -1186,34 +1337,8 @@ public class ProfilingService extends IProfilingService.Stub {
             }
             session.incrementRetryCount();
 
-            switch (session.getState()) {
-                case NOT_STARTED:
-                case PROFILING_STARTED:
-                    // This should never happen as the session should not be in queuedSessions until
-                    // past this state, but run stop and cleanup just in case.
-                    stopProfiling(session);
-                    cleanupTracingSession(session);
-                    break;
-                case PROFILING_FINISHED:
-                    if (session.getProfilingType()
-                            == ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE) {
-                        handleTraceResult(session);
-                    } else {
-                        beginMoveFileToAppStorage(session);
-                    }
-                    break;
-                case REDACTED:
-                    beginMoveFileToAppStorage(session);
-                    break;
-                case COPIED_FILE:
-                    finishProcessingResult(session, true);
-                    break;
-                case DISCARDED:
-                    // This should never happen as this state should only occur after cleanup of
-                    // this file.
-                    cleanupTracingSession(session, queuedSessions);
-                    break;
-            }
+            // Advance with new state null so that it picks up where it left off.
+            advanceTracingSession(session, null);
         }
 
         // Now attempt to cleanup the queue.
@@ -1252,7 +1377,8 @@ public class ProfilingService extends IProfilingService.Stub {
      *
      * Cleanup will attempt to delete the temporary file(s) and then remove it from the queue.
      */
-    private void cleanupTracingSession(TracingSession session) {
+    @VisibleForTesting
+    public void cleanupTracingSession(TracingSession session) {
         List<TracingSession> queuedSessions = mQueuedTracingResults.get(session.getUid());
         cleanupTracingSession(session, queuedSessions);
     }
@@ -1264,7 +1390,7 @@ public class ProfilingService extends IProfilingService.Stub {
      * Cleanup will attempt to delete the temporary file(s) and then remove it from the queue.
      */
     private void cleanupTracingSession(TracingSession session,
-            List<TracingSession> queuedSessions) {
+            @Nullable List<TracingSession> queuedSessions) {
         // Delete all files
         if (session.getProfilingType() == ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE) {
             // If type is trace, try to delete the temp file only if {@link mKeepUnredactedTrace} is
@@ -1285,12 +1411,14 @@ public class ProfilingService extends IProfilingService.Stub {
 
         }
 
-        session.setState(TracingSession.TracingState.DISCARDED);
-        queuedSessions.remove(session);
-
-        if (queuedSessions.isEmpty()) {
-            mQueuedTracingResults.remove(session.getUid());
+        if (queuedSessions != null) {
+            queuedSessions.remove(session);
+            if (queuedSessions.isEmpty()) {
+                mQueuedTracingResults.remove(session.getUid());
+            }
         }
+
+        advanceTracingSession(session, TracingState.CLEANED_UP);
     }
 
     /**
@@ -1311,6 +1439,27 @@ public class ProfilingService extends IProfilingService.Stub {
         }
     }
 
+    /**
+     * Move session to list of queued sessions. Removes the session from the list of active
+     * sessions, if it is present.
+     *
+     * Sessions are expected to be in the queue when their states are between PROFILING_FINISHED and
+     * NOTIFIED_REQUESTER, inclusive.
+     */
+    private void moveSessionToQueue(TracingSession session) {
+        List<TracingSession> queuedResults = mQueuedTracingResults.get(session.getUid());
+        if (queuedResults == null) {
+            queuedResults = new ArrayList<TracingSession>();
+            mQueuedTracingResults.put(session.getUid(), queuedResults);
+        }
+        queuedResults.add(session);
+        mActiveTracingSessions.remove(session.getKey());
+    }
+
+    private boolean needsRedaction(TracingSession session) {
+        return session.getProfilingType() == ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE;
+    }
+
     private Handler getHandler() {
         if (mHandler == null) {
             mHandler = new Handler(mHandlerThread.getLooper());
diff --git a/service/java/com/android/os/profiling/TracingSession.java b/service/java/com/android/os/profiling/TracingSession.java
index a0f1562..b2a8c2d 100644
--- a/service/java/com/android/os/profiling/TracingSession.java
+++ b/service/java/com/android/os/profiling/TracingSession.java
@@ -16,6 +16,8 @@
 
 package android.os.profiling;
 
+import static android.os.profiling.ProfilingService.TracingState;
+
 import android.os.Bundle;
 
 import java.util.UUID;
@@ -25,25 +27,6 @@ import java.util.UUID;
  */
 public final class TracingSession {
 
-    public enum TracingState {
-        NOT_STARTED(0),
-        PROFILING_STARTED(1),
-        PROFILING_FINISHED(2),
-        REDACTED(3),
-        COPIED_FILE(4),
-        DISCARDED(5);
-
-        private final int mValue;
-
-        TracingState(int value) {
-            mValue = value;
-        }
-
-        public int getValue() {
-            return mValue;
-        }
-    }
-
     private Process mActiveTrace;
     private Process mActiveRedaction;
     private Runnable mProcessResultRunnable;
@@ -64,6 +47,10 @@ public final class TracingSession {
     private int mRetryCount = 0;
     private long mProfilingStartTimeMs;
     private int mMaxProfilingTimeAllowedMs = 0;
+    private String mErrorMessage = null;
+
+    // Expected to be populated with ProfilingResult.ERROR_* values.
+    private int mErrorStatus = -1; // Default to invalid value.
 
     public TracingSession(int profilingType, Bundle params, String appFilePath, int uid,
                 String packageName, String tag, long keyMostSigBits, long keyLeastSigBits) {
@@ -75,7 +62,7 @@ public final class TracingSession {
         mTag = tag;
         mKeyMostSigBits = keyMostSigBits;
         mKeyLeastSigBits = keyLeastSigBits;
-        mState = TracingState.NOT_STARTED;
+        mState = TracingState.REQUESTED;
     }
 
     public byte[] getConfigBytes() throws IllegalArgumentException {
@@ -136,6 +123,10 @@ public final class TracingSession {
         mRetryCount = retryCount;
     }
 
+    /**
+     * Do not call directly!
+     * State should only be updated with {@link ProfilingService#advanceStateAndContinue}.
+     */
     public void setState(TracingState state) {
         mState = state;
     }
@@ -149,6 +140,20 @@ public final class TracingSession {
         mProfilingStartTimeMs = startTime;
     }
 
+    /**
+     * Update error status. Also overrides error message to null as the two fields must be set
+     * together to ensure they make sense.
+     */
+    public void setError(int status) {
+        setError(status, null);
+    }
+
+    /** Update error status and message. */
+    public void setError(int status, String message) {
+        mErrorStatus = status;
+        mErrorMessage = message;
+    }
+
     public Process getActiveTrace() {
         return mActiveTrace;
     }
@@ -230,4 +235,12 @@ public final class TracingSession {
     public int getRetryCount() {
         return mRetryCount;
     }
+
+    public String getErrorMessage() {
+        return mErrorMessage;
+    }
+
+    public int getErrorStatus() {
+        return mErrorStatus;
+    }
 }
diff --git a/tests/cts/Android.bp b/tests/cts/Android.bp
index 2f7563a..aa9b919 100644
--- a/tests/cts/Android.bp
+++ b/tests/cts/Android.bp
@@ -19,19 +19,26 @@ android_test {
         "testng",
     ],
     libs: [
-        "android.test.runner",
-        "android.test.base",
-        "android.test.mock",
+        "android.test.runner.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
         "junit",
     ],
+    // include both the 32 and 64 bit versions
+    compile_multilib: "both",
     srcs: [
         "src/android/profiling/cts/*.java",
     ],
+    jni_libs: [
+        "libcts_profiling_module_test_native",
+    ],
     jarjar_rules: "jarjar-rules.txt",
     test_suites: [
         "cts",
         "general-tests",
+        "mts-profiling",
+        "mcts-profiling",
     ],
-    min_sdk_version: "current",
+    min_sdk_version: "35",
     sdk_version: "module_current",
 }
diff --git a/tests/cts/AndroidTest.xml b/tests/cts/AndroidTest.xml
index 5262996..6c955a7 100644
--- a/tests/cts/AndroidTest.xml
+++ b/tests/cts/AndroidTest.xml
@@ -14,7 +14,7 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License
   -->
-<configuration description="Config for Profiling service test cases">
+<configuration description="Config for Profiling test cases">
     <option name="test-suite-tag" value="cts" />
     <option name="config-descriptor:metadata" key="component" value="systems" />
     <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
diff --git a/tests/cts/jni/Android.bp b/tests/cts/jni/Android.bp
new file mode 100644
index 0000000..bae6880
--- /dev/null
+++ b/tests/cts/jni/Android.bp
@@ -0,0 +1,13 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_shared {
+    name: "libcts_profiling_module_test_native",
+    compile_multilib: "both",
+    header_libs: ["jni_headers"],
+    srcs: [
+        "target.c",
+    ],
+    sdk_version: "current",
+}
diff --git a/tests/cts/jni/target.c b/tests/cts/jni/target.c
new file mode 100644
index 0000000..d977650
--- /dev/null
+++ b/tests/cts/jni/target.c
@@ -0,0 +1,30 @@
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
+#include <jni.h>
+#include <stdlib.h>
+
+JNIEXPORT void JNICALL
+Java_android_profiling_cts_ProfilingFrameworkTests_doMallocAndFree(JNIEnv* env,
+                                                                   jclass klass) {
+  (void) env;
+  (void) klass;
+  volatile char* x = malloc(4200);
+  if (x) {
+    x[0] = '\0';
+    free((char*)x);
+  }
+}
diff --git a/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java b/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
index bf6def5..acf60b4 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
@@ -117,6 +117,10 @@ public final class ProfilingFrameworkTests {
     private Context mContext = null;
     private Instrumentation mInstrumentation;
 
+    static {
+        System.loadLibrary("cts_profiling_module_test_native");
+    }
+
     @Rule
     public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
 
@@ -251,9 +255,13 @@ public final class ProfilingFrameworkTests {
                 new ProfilingTestUtils.ImmediateExecutor(),
                 callback);
 
+        MallocLoopThread mallocThread = new MallocLoopThread();
+
         // Wait until callback#onAccept is triggered so we can confirm the result.
         waitForCallback(callback);
 
+        mallocThread.stop();
+
         // Assert that result matches assumptions for success.
         confirmCollectionSuccess(callback.mResult, OUTPUT_FILE_HEAP_PROFILE_SUFFIX);
         dumpTrace(callback.mResult);
@@ -992,6 +1000,8 @@ public final class ProfilingFrameworkTests {
         }
     }
 
+    private static native void doMallocAndFree();
+
     public static class AppCallback implements Consumer<ProfilingResult> {
 
         public ProfilingResult mResult;
@@ -1025,4 +1035,30 @@ public final class ProfilingFrameworkTests {
             }
         }
     }
+
+    // Starts a thread that repeatedly issues malloc() and free().
+    private static class MallocLoopThread {
+        private Thread thread;
+        private AtomicBoolean done = new AtomicBoolean(false);
+
+        public MallocLoopThread() {
+            done.set(false);
+            thread = new Thread(() -> {
+                while (!done.get()) {
+                    doMallocAndFree();
+                    sleep(10);
+                }
+            });
+            thread.start();
+        }
+
+        public void stop() {
+            done.set(true);
+            try {
+                thread.join();
+            } catch (InterruptedException e) {
+                throw new AssertionError("InterruptedException", e);
+            }
+        }
+    }
 }
diff --git a/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java b/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
index b164310..fc11e73 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
@@ -16,6 +16,8 @@
 
 package android.profiling.cts;
 
+import static android.os.profiling.ProfilingService.TracingState;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
@@ -23,9 +25,10 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.doThrow;
-import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
@@ -325,7 +328,7 @@ public final class ProfilingServiceTests {
     @Test
     public void testAreAnyTracesRunning_True() {
         // Ensure no active tracing sessions tracked.
-        mProfilingService.mTracingSessions.clear();
+        mProfilingService.mActiveTracingSessions.clear();
         assertFalse(mProfilingService.areAnyTracesRunning());
 
         // Create a tracing session.
@@ -338,7 +341,7 @@ public final class ProfilingServiceTests {
 
         // Add trace to session and session to ProfilingService tracked sessions.
         tracingSession.setActiveTrace(mActiveTrace);
-        mProfilingService.mTracingSessions.put(
+        mProfilingService.mActiveTracingSessions.put(
                 (new UUID(KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS)).toString(), tracingSession);
 
         // Confirm check returns that a trace is running.
@@ -348,14 +351,14 @@ public final class ProfilingServiceTests {
     /** Test that checking if any traces are running works when trace is not running. */
     @Test
     public void testAreAnyTracesRunning_False() {
-        mProfilingService.mTracingSessions.clear();
-        assertEquals(0, mProfilingService.mTracingSessions.size());
+        mProfilingService.mActiveTracingSessions.clear();
+        assertEquals(0, mProfilingService.mActiveTracingSessions.size());
         assertFalse(mProfilingService.areAnyTracesRunning());
 
         TracingSession tracingSession = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, APP_FILE_PATH, 123,
                 APP_PACKAGE_NAME, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
-        mProfilingService.mTracingSessions.put(
+        mProfilingService.mActiveTracingSessions.put(
                 (new UUID(KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS)).toString(), tracingSession);
 
         // Confirm no traces are running because the 1 we added is not in a running state.
@@ -365,18 +368,18 @@ public final class ProfilingServiceTests {
     /** Test that cleaning up active traces list works correctly. */
     @Test
     public void testActiveTracesCleanup() {
-        mProfilingService.mTracingSessions.clear();
-        assertEquals(0, mProfilingService.mTracingSessions.size());
+        mProfilingService.mActiveTracingSessions.clear();
+        assertEquals(0, mProfilingService.mActiveTracingSessions.size());
         assertFalse(mProfilingService.areAnyTracesRunning());
 
         TracingSession tracingSession = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, APP_FILE_PATH, 123,
                 APP_PACKAGE_NAME, REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
-        mProfilingService.mTracingSessions.put(
+        mProfilingService.mActiveTracingSessions.put(
                 (new UUID(KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS)).toString(), tracingSession);
 
         // Confirm the session was added.
-        assertEquals(1, mProfilingService.mTracingSessions.size());
+        assertEquals(1, mProfilingService.mActiveTracingSessions.size());
 
         // Confirm no traces are running because the 1 we added is not in a running state.
         assertFalse(mProfilingService.areAnyTracesRunning());
@@ -385,14 +388,14 @@ public final class ProfilingServiceTests {
         mProfilingService.cleanupActiveTracingSessions();
 
         // Confirm the non running session was cleaned up.
-        assertEquals(0, mProfilingService.mTracingSessions.size());
+        assertEquals(0, mProfilingService.mActiveTracingSessions.size());
     }
 
     /** Test that request cancel trace does nothing if no trace is running. */
     @Test
     public void testRequestCancel_NotRunning() {
         // Ensure no active tracing sessions tracked.
-        mProfilingService.mTracingSessions.clear();
+        mProfilingService.mActiveTracingSessions.clear();
         assertFalse(mProfilingService.areAnyTracesRunning());
 
         // Register callback.
@@ -633,6 +636,89 @@ public final class ProfilingServiceTests {
 
     // TODO: b/333579817 - Add more rate limiter tests
 
+    /** Test that advancing state in forward direction works as expected. */
+    @Test
+    public void testSessionState_AdvanceForwardSucceeds() {
+        // Create a session with some state.
+        TracingSession session = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
+                new Bundle(),
+                mContext.getFilesDir().getPath(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session.setState(TracingState.PROFILING_FINISHED);
+
+        // Trigger an advance to a subsequent state.
+        mProfilingService.advanceTracingSession(session, TracingState.ERROR_OCCURRED);
+
+        // Ensure it does try to advance.
+        verify(mProfilingService, times(1)).processTracingSessionResultCallback(any(), eq(true));
+    }
+
+    /** Test that advancing state in backwards direction does not work. */
+    @Test
+    public void testSessionState_AdvanceBackwardsFails() {
+        // Override cleanupTracingSession to do nothing or it will call through to
+        // advanceTracingSession after cleanup and we need to confirm that advanceTracingSession is
+        // not immediately called.
+        doNothing().when(mProfilingService).cleanupTracingSession(any());
+
+        // Create a session with some state.
+        TracingSession session = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
+                new Bundle(),
+                mContext.getFilesDir().getPath(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session.setState(TracingState.APPROVED);
+
+        // Attempt to advance to earlier state.
+        mProfilingService.advanceTracingSession(session, TracingState.REQUESTED);
+
+        // Ensure service determines something is broken, does not try to advance, and triggers a
+        // cleanup.
+        verify(mProfilingService, times(1)).cleanupTracingSession(any());
+    }
+
+    /**
+     * Test that advancing state with a null new state and no retries (i.e. not from queue retry)
+     * does not work. */
+    @Test
+    public void testSessionState_AdvanceNullFails() {
+        // Override cleanupTracingSession to do nothing or it will call through to
+        // advanceTracingSession after cleanup and we need to confirm that advanceTracingSession is
+        // not immediately called.
+        doNothing().when(mProfilingService).cleanupTracingSession(any());
+
+        // Create a session with some state.
+        TracingSession session = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_HEAP_PROFILE,
+                new Bundle(),
+                mContext.getFilesDir().getPath(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session.setState(TracingState.REQUESTED);
+
+        // Make sure retry count is 0 (default value).
+        assertEquals(0, session.getRetryCount());
+
+        // Attempt to advance with null new state.
+        mProfilingService.advanceTracingSession(session, null);
+
+        // Ensure service determines something is broken, does not try to advance, and triggers a
+        // cleanup.
+        verify(mProfilingService, times(1)).cleanupTracingSession(any());
+    }
+
     /** Test that adding a specific listener does not trigger handling queued results. */
     @Test
     public void testQueuedResult_RequestSpecificListener() {
@@ -687,7 +773,7 @@ public final class ProfilingServiceTests {
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
                 KEY_MOST_SIG_BITS);
-        session.setState(TracingSession.TracingState.PROFILING_STARTED);
+        session.setState(TracingState.PROFILING_STARTED);
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(FAKE_UID, queue);
 
@@ -726,7 +812,7 @@ public final class ProfilingServiceTests {
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
                 KEY_MOST_SIG_BITS);
-        session.setState(TracingSession.TracingState.PROFILING_FINISHED);
+        session.setState(TracingState.PROFILING_FINISHED);
         session.setRetryCount(3);
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(FAKE_UID, queue);
@@ -764,7 +850,7 @@ public final class ProfilingServiceTests {
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
                 KEY_MOST_SIG_BITS);
-        session.setState(TracingSession.TracingState.PROFILING_FINISHED);
+        session.setState(TracingState.PROFILING_FINISHED);
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(uid, queue);
 
@@ -778,7 +864,7 @@ public final class ProfilingServiceTests {
         // Confirm that the correct path was called. Callback will be for failed post processing
         // because we cannot copy from this context.
         verify(mProfilingService, times(1)).beginMoveFileToAppStorage(any());
-        verify(mProfilingService, times(1)).finishProcessingResult(any(), eq(false));
+        verify(mProfilingService, times(1)).processTracingSessionResultCallback(any(), eq(false));
         assertTrue(callback.mFileRequested);
         assertTrue(callback.mResultSent);
         assertEquals(ProfilingResult.ERROR_FAILED_POST_PROCESSING, callback.mStatus);
@@ -803,7 +889,7 @@ public final class ProfilingServiceTests {
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
                 KEY_MOST_SIG_BITS);
-        session.setState(TracingSession.TracingState.PROFILING_FINISHED);
+        session.setState(TracingState.PROFILING_FINISHED);
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(FAKE_UID, queue);
 
@@ -816,7 +902,7 @@ public final class ProfilingServiceTests {
 
         // Confirm that the correct path was called. Callback will be for failed post processing
         // because we cannot copy from this context.
-        verify(mProfilingService, times(1)).handleTraceResult(any());
+        verify(mProfilingService, times(1)).handleRedactionRequiredResult(any());
         assertTrue(callback.mResultSent);
         assertEquals(ProfilingResult.ERROR_FAILED_POST_PROCESSING, callback.mStatus);
     }
@@ -841,7 +927,7 @@ public final class ProfilingServiceTests {
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
                 KEY_MOST_SIG_BITS);
-        session.setState(TracingSession.TracingState.REDACTED);
+        session.setState(TracingState.REDACTED);
         session.setProfilingStartTimeMs(System.currentTimeMillis());
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(uid, queue);
@@ -855,7 +941,7 @@ public final class ProfilingServiceTests {
 
         // Confirm that the correct path was called.
         verify(mProfilingService, times(1)).beginMoveFileToAppStorage(any());
-        verify(mProfilingService, times(1)).finishProcessingResult(any(), eq(false));
+        verify(mProfilingService, times(1)).processTracingSessionResultCallback(any(), eq(false));
         assertTrue(callback.mFileRequested);
         assertTrue(callback.mResultSent);
         assertEquals(ProfilingResult.ERROR_FAILED_POST_PROCESSING, callback.mStatus);
@@ -884,7 +970,8 @@ public final class ProfilingServiceTests {
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
                 KEY_MOST_SIG_BITS);
-        session.setState(TracingSession.TracingState.COPIED_FILE);
+        session.setState(TracingState.COPIED_FILE);
+        session.setError(ProfilingResult.ERROR_NONE);
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(FAKE_UID, queue);
 
@@ -896,11 +983,86 @@ public final class ProfilingServiceTests {
         mProfilingService.handleQueuedResults(FAKE_UID);
 
         // Confirm that the correct path was called that a success callback was received.
-        verify(mProfilingService, times(1)).finishProcessingResult(any(), eq(true));
-        assertEquals(ProfilingResult.ERROR_NONE, callback.mStatus);
+        verify(mProfilingService, times(1)).processTracingSessionResultCallback(any(), eq(true));
         assertFalse(mProfilingService.mQueuedTracingResults.contains(FAKE_UID));
     }
 
+    /**
+     * Test that a queued result for a session with state of error occurred correctly progresses
+     * to next step of triggering callback.
+     */
+    @Test
+    public void testQueuedResult_ErrorOccurred() {
+        // Clear all existing queued results.
+        mProfilingService.mQueuedTracingResults.clear();
+
+        // Add a in progress session to queue with state error occurred
+        List<TracingSession> queue = new ArrayList<TracingSession>();
+        TracingSession session = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
+                new Bundle(),
+                mContext.getFilesDir().getPath(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session.setState(TracingState.ERROR_OCCURRED);
+        session.setError(ProfilingResult.ERROR_UNKNOWN);
+        queue.add(session);
+        mProfilingService.mQueuedTracingResults.put(FAKE_UID, queue);
+
+        // Add a callback directly with fake uid
+        ProfilingResultCallback callback = new ProfilingResultCallback();
+        mProfilingService.mResultCallbacks.put(FAKE_UID, Arrays.asList(callback));
+
+        // Trigger handle queued results
+        mProfilingService.handleQueuedResults(FAKE_UID);
+
+        // Confirm that the correct path was called that an error callback was received.
+        verify(mProfilingService, times(1)).processTracingSessionResultCallback(any(), eq(true));
+        assertTrue(callback.mResultSent);
+        assertEquals(ProfilingResult.ERROR_UNKNOWN, callback.mStatus);
+    }
+
+    /**
+     * Test that a queued result for a session with state of notified requester correctly progresses
+     * to next step of cleaning up and does not trigger any further callbacks.
+     */
+    @Test
+    public void testQueuedResult_NotifiedRequester() {
+        // Clear all existing queued results.
+        mProfilingService.mQueuedTracingResults.clear();
+
+        // Add a in progress session to queue with state notified requester
+        List<TracingSession> queue = new ArrayList<TracingSession>();
+        TracingSession session = new TracingSession(
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
+                new Bundle(),
+                mContext.getFilesDir().getPath(),
+                FAKE_UID,
+                APP_PACKAGE_NAME,
+                REQUEST_TAG,
+                KEY_LEAST_SIG_BITS,
+                KEY_MOST_SIG_BITS);
+        session.setState(TracingState.NOTIFIED_REQUESTER);
+        session.setError(ProfilingResult.ERROR_NONE);
+        queue.add(session);
+        mProfilingService.mQueuedTracingResults.put(FAKE_UID, queue);
+
+        // Add a callback directly with fake uid
+        ProfilingResultCallback callback = new ProfilingResultCallback();
+        mProfilingService.mResultCallbacks.put(FAKE_UID, Arrays.asList(callback));
+
+        // Trigger handle queued results
+        mProfilingService.handleQueuedResults(FAKE_UID);
+
+        // Confirm that the correct path was called.
+        verify(mProfilingService, times(1)).cleanupTracingSession(any());
+        assertFalse(mProfilingService.mQueuedTracingResults.contains(FAKE_UID));
+        assertFalse(callback.mResultSent);
+    }
+
     /**
      * Test that a queued result that was started longer than max queue time ago is successfully
      * cleaned up when the queue is triggered for a different uid.
@@ -921,7 +1083,7 @@ public final class ProfilingServiceTests {
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
                 KEY_MOST_SIG_BITS);
-        session.setState(TracingSession.TracingState.COPIED_FILE);
+        session.setState(TracingState.COPIED_FILE);
         session.setProfilingStartTimeMs(System.currentTimeMillis() - 1000
                 - ProfilingService.QUEUED_RESULT_MAX_RETAINED_DURATION_MS);
         queue.add(session);
@@ -966,8 +1128,8 @@ public final class ProfilingServiceTests {
                 KEY_LEAST_SIG_BITS,
                 KEY_MOST_SIG_BITS);
         session.setFileName(trackedFile.getName());
-        mProfilingService.mTracingSessions.put(session.getKey(), session);
-        assertEquals(1, mProfilingService.mTracingSessions.size());
+        mProfilingService.mActiveTracingSessions.put(session.getKey(), session);
+        assertEquals(1, mProfilingService.mActiveTracingSessions.size());
 
         // Now trigger the cleanup
         mProfilingService.cleanupTemporaryDirectoryLocked(directory.getPath());
```

