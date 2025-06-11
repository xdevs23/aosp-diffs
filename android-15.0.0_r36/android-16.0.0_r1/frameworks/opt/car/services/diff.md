```diff
diff --git a/builtInServices/Android.bp b/builtInServices/Android.bp
index 246119e..26a1345 100644
--- a/builtInServices/Android.bp
+++ b/builtInServices/Android.bp
@@ -8,7 +8,7 @@ java_sdk_library {
     libs: [
         "services",
         "android.car",
-        "android.car.builtin.stubs.module_lib",  // Will remove once split is complete
+        "android.car.builtin.stubs.module_lib", // Will remove once split is complete
         "android.hardware.automotive.vehicle-V2.0-java",
     ],
     srcs: [
@@ -17,6 +17,7 @@ java_sdk_library {
     static_libs: [
         "android.car.watchdoglib",
         "android.automotive.watchdog.internal-java",
+        "car-builtin-protos",
     ],
     api_lint: {
         enabled: true,
@@ -27,12 +28,12 @@ java_sdk_library {
     ],
 
     droiddoc_options: [
-       "--include-annotations --pass-through-annotation android.annotation.RequiresApi"
+        "--include-annotations --pass-through-annotation android.annotation.RequiresApi",
     ],
 
     apex_available: [
         "//apex_available:platform",
-        "com.android.car.framework"
+        "com.android.car.framework",
     ],
 
     unsafe_ignore_missing_latest_api: true,
diff --git a/builtInServices/api/module-lib-current.txt b/builtInServices/api/module-lib-current.txt
index 3a9ce4e..85291b7 100644
--- a/builtInServices/api/module-lib-current.txt
+++ b/builtInServices/api/module-lib-current.txt
@@ -142,6 +142,7 @@ package com.android.server.wm {
     method public com.android.server.wm.TaskDisplayAreaWrapper getPreferredTaskDisplayArea();
     method public int getWindowingMode();
     method public void setBounds(android.graphics.Rect);
+    method @FlaggedApi("com.android.window.flags.safe_region_letterboxing") public void setNeedsSafeRegionBounds(boolean);
     method public void setPreferredTaskDisplayArea(com.android.server.wm.TaskDisplayAreaWrapper);
     method public void setWindowingMode(int);
     field public static int RESULT_CONTINUE;
@@ -149,6 +150,11 @@ package com.android.server.wm {
     field public static int RESULT_SKIP;
   }
 
+  public final class MediaTemplateActivityInterceptorForSuspension implements com.android.server.wm.CarActivityInterceptorUpdatable {
+    ctor public MediaTemplateActivityInterceptorForSuspension();
+    method @Nullable public com.android.server.wm.ActivityInterceptResultWrapper onInterceptActivityLaunch(com.android.server.wm.ActivityInterceptorInfoWrapper);
+  }
+
   public final class RequestWrapper {
   }
 
diff --git a/builtInServices/proto/Android.bp b/builtInServices/proto/Android.bp
new file mode 100644
index 0000000..d5af5e6
--- /dev/null
+++ b/builtInServices/proto/Android.bp
@@ -0,0 +1,27 @@
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_library_static {
+    name: "car-builtin-protos",
+    proto: {
+        type: "lite",
+    },
+    srcs: ["src/**/*.proto"],
+    sdk_version: "system_current",
+    jarjar_rules: "jarjar-rules.txt",
+}
diff --git a/builtInServices/proto/jarjar-rules.txt b/builtInServices/proto/jarjar-rules.txt
new file mode 100644
index 0000000..caa4764
--- /dev/null
+++ b/builtInServices/proto/jarjar-rules.txt
@@ -0,0 +1 @@
+rule com.google.protobuf.** com.android.internal.car.protobuf.@1
diff --git a/builtInServices/proto/src/atoms.proto b/builtInServices/proto/src/atoms.proto
new file mode 100644
index 0000000..198b212
--- /dev/null
+++ b/builtInServices/proto/src/atoms.proto
@@ -0,0 +1,100 @@
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
+// Clone of packages/services/Car/service/proto/android/car/watchdog/atoms.proto.
+
+syntax = "proto2";
+
+package com.android.internal;
+option java_multiple_files = true;
+option java_package = "com.android.internal.util";
+option java_outer_classname = "AtomsProto";
+
+/**
+ * Logs the current state of an application/process before it is killed.
+ *
+ * Keep in sync with proto file at frameworks/proto_logging/stats/atoms.proto
+ */
+message CarWatchdogKillStatsReported {
+  // Linux process uid for the package.
+  optional int32 uid = 1;
+
+  // State of the uid when it was killed.
+  enum UidState {
+    UNKNOWN_UID_STATE = 0;
+    BACKGROUND_MODE = 1;
+    FOREGROUND_MODE = 2;
+  }
+  optional UidState uid_state = 2;
+
+  // System state indicating whether the system was in normal mode or garage mode.
+  enum SystemState {
+    UNKNOWN_SYSTEM_STATE = 0;
+    USER_INTERACTION_MODE = 1;
+    USER_NO_INTERACTION_MODE = 2;
+    GARAGE_MODE = 3;
+  }
+  optional SystemState system_state = 3;
+
+  // Reason for killing the application.
+  // Keep in sync with proto file at packages/services/Car/cpp/watchdog/proto
+  enum KillReason {
+    UNKNOWN_KILL_REASON = 0;
+    KILLED_ON_ANR = 1;
+    KILLED_ON_IO_OVERUSE = 2;
+    KILLED_ON_MEMORY_OVERUSE = 3;
+  }
+  optional KillReason kill_reason = 4;
+
+  // Stats of the processes owned by the application when the application was killed.
+  // The process stack traces are not collected when the application was killed due to IO_OVERUSE.
+  optional CarWatchdogProcessStats process_stats = 5;
+
+  reserved 6; //CarWatchdogIoOveruseStats
+}
+
+/**
+ * Logs each CarWatchdogProcessStat in CarWatchdogProcessStats.
+ *
+ * Keep in sync with proto file at frameworks/proto_logging/stats/atoms.proto
+ */
+message CarWatchdogProcessStats {
+  // Records the stats of the processes owned by an application.
+  repeated CarWatchdogProcessStat process_stat = 1;
+}
+
+/**
+ * Logs a process's stats.
+ *
+ * Keep in sync with proto file at frameworks/proto_logging/stats/atoms.proto
+ */
+message CarWatchdogProcessStat {
+  // Command name of the process.
+  optional string process_name = 1;
+
+  // Process uptime.
+  optional uint64 uptime_millis = 2;
+
+  reserved 3; //major_page_faults
+
+  reserved 4; //vm_peak_kb
+
+  reserved 5; //vm_size_kb
+
+  reserved 6; //vm_hwm_kb
+
+  reserved 7; //vm_rss_kb
+}
diff --git a/builtInServices/src/com/android/internal/car/CarServiceHelperService.java b/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
index 4bf9c12..3724bf5 100644
--- a/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
+++ b/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
@@ -31,6 +31,11 @@ import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVE
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_UNLOCKED;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_UNLOCKING;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_VISIBLE;
+import static com.android.internal.util.FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED;
+import static com.android.internal.util.FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED__KILL_REASON__KILLED_ON_ANR;
+import static com.android.internal.util.FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED__UID_STATE__UNKNOWN_UID_STATE;
+import static com.android.internal.util.FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__GARAGE_MODE;
+import static com.android.internal.util.FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__UNKNOWN_SYSTEM_STATE;
 import static com.android.internal.util.function.pooled.PooledLambda.obtainMessage;
 import static com.android.server.wm.ActivityInterceptorCallback.PRODUCT_ORDERED_ID;
 
@@ -42,6 +47,8 @@ import android.app.admin.DevicePolicyManager;
 import android.app.admin.DevicePolicyManager.DevicePolicyOperation;
 import android.app.admin.DevicePolicyManager.OperationSafetyReason;
 import android.app.admin.DevicePolicySafetyChecker;
+import android.automotive.watchdog.internal.ClientsNotRespondingInfo;
+import android.automotive.watchdog.internal.GarageMode;
 import android.automotive.watchdog.internal.ICarWatchdogMonitor;
 import android.automotive.watchdog.internal.ProcessIdentifier;
 import android.automotive.watchdog.internal.StateType;
@@ -53,6 +60,7 @@ import android.hardware.display.DisplayManager;
 import android.hidl.manager.V1_0.IServiceManager;
 import android.os.Handler;
 import android.os.HandlerThread;
+import android.os.IBinder;
 import android.os.Process;
 import android.os.RemoteException;
 import android.os.ServiceDebugInfo;
@@ -66,6 +74,7 @@ import android.system.OsConstants;
 import android.util.ArrayMap;
 import android.util.Dumpable;
 import android.util.Log;
+import android.util.SparseArray;
 import android.util.TimeUtils;
 import android.view.Display;
 
@@ -74,6 +83,9 @@ import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.car.os.Util;
 import com.android.internal.os.IResultReceiver;
+import com.android.internal.util.CarWatchdogProcessStat;
+import com.android.internal.util.CarWatchdogProcessStats;
+import com.android.internal.util.FrameworkStatsLog;
 import com.android.server.LocalServices;
 import com.android.server.SystemService;
 import com.android.server.Watchdog;
@@ -89,7 +101,7 @@ import com.android.server.wm.CarDisplayCompatScaleProvider;
 import com.android.server.wm.CarDisplayCompatScaleProviderInterface;
 import com.android.server.wm.CarLaunchParamsModifier;
 import com.android.server.wm.CarLaunchParamsModifierInterface;
-import com.android.server.wm.WindowManagerService;
+import com.android.server.wm.WindowManagerInternal;
 import com.android.server.wm.WindowProcessController;
 import com.android.server.wm.WindowProcessControllerHelper;
 
@@ -150,8 +162,8 @@ public class CarServiceHelperService extends SystemService
 
     // Message ID representing post-processing of process dumping.
     private static final int WHAT_POST_PROCESS_DUMPING = 1;
-    // Message ID representing process killing.
-    private static final int WHAT_PROCESS_KILL = 2;
+    // Message ID representing uploading metrics.
+    private static final int WHAT_UPLOAD_METRICS = 2;
 
     private static final String CSHS_UPDATABLE_CLASSNAME_STRING =
             "com.android.internal.car.updatable.CarServiceHelperServiceUpdatableImpl";
@@ -164,6 +176,8 @@ public class CarServiceHelperService extends SystemService
     private static final boolean sVisibleBackgroundUsersEnabled =
             UserManager.isVisibleBackgroundUsersEnabled();
 
+    private static final Pattern sProcPidStatPattern = Pattern.compile(PROC_PID_STAT_PATTERN);
+
     static  {
         // Load this JNI before other classes are loaded.
         System.loadLibrary("carservicehelperjni");
@@ -185,8 +199,6 @@ public class CarServiceHelperService extends SystemService
 
     private final ProcessTerminator mProcessTerminator = new ProcessTerminator();
 
-    private final Pattern mProcPidStatPattern = Pattern.compile(PROC_PID_STAT_PATTERN);
-
     private final CarWatchdogDaemonHelper mCarWatchdogDaemonHelper;
     private final ICarWatchdogMonitorImpl mCarWatchdogMonitor = new ICarWatchdogMonitorImpl(this);
     private final CarWatchdogDaemonHelper.OnConnectionChangeListener mConnectionListener =
@@ -199,7 +211,6 @@ public class CarServiceHelperService extends SystemService
     private final CarDevicePolicySafetyChecker mCarDevicePolicySafetyChecker;
 
     private CarServiceHelperServiceUpdatable mCarServiceHelperServiceUpdatable;
-    private WindowManagerService mWindowManagerService;
 
     /**
      * End-to-end time (from process start) for unlocking the first non-system user.
@@ -353,20 +364,14 @@ public class CarServiceHelperService extends SystemService
         mCarWatchdogDaemonHelper.connect();
         mCarServiceHelperServiceUpdatable.onStart();
 
-        mWindowManagerService = (WindowManagerService) ServiceManager.getService(
-                Context.WINDOW_SERVICE);
-        mWindowManagerService.addWindowChangeListener(mWindowChangeListener);
+        WindowManagerInternal wmInternal = LocalServices.getService(WindowManagerInternal.class);
+        wmInternal.registerWindowFocusChangeListener(mWindowFocusChangeListener);
     }
 
-    private final WindowManagerService.WindowChangeListener mWindowChangeListener =
-            new WindowManagerService.WindowChangeListener() {
-                @Override
-                public void windowsChanged() {
-                    // Do nothing
-                }
-
+    private final WindowManagerInternal.WindowFocusChangeListener mWindowFocusChangeListener =
+            new WindowManagerInternal.WindowFocusChangeListener() {
                 @Override
-                public void focusChanged() {
+                public void focusChanged(IBinder focusedWindowToken) {
                     WindowProcessController topApp = mActivityTaskManagerInternal.getTopApp();
                     if (topApp == null) {
                         return;
@@ -608,6 +613,21 @@ public class CarServiceHelperService extends SystemService
         return new ArrayList<Integer>(pids);
     }
 
+    static CarWatchdogProcessStats constructCarWatchdogProcessStatsLocked(
+            List<ProcessIdentifier> clients) {
+        CarWatchdogProcessStats.Builder carWatchdogProcessStats =
+                CarWatchdogProcessStats.newBuilder();
+        for (int i = 0; i < clients.size(); i++) {
+            ProcessIdentifier client = clients.get(i);
+            CarWatchdogProcessStat.Builder carWatchdogProcessStat =
+                    CarWatchdogProcessStat.newBuilder()
+                        .setProcessName(client.processName)
+                        .setUptimeMillis(client.startTimeMillis);
+            carWatchdogProcessStats.addProcessStat(carWatchdogProcessStat.build());
+        }
+        return carWatchdogProcessStats.build();
+    }
+
     /**
      * Dumps service stack
      */
@@ -666,8 +686,14 @@ public class CarServiceHelperService extends SystemService
         return INVALID_PID;
     }
 
-    private void handleClientsNotResponding(@NonNull List<ProcessIdentifier> processIdentifiers) {
-        mProcessTerminator.requestTerminateProcess(processIdentifiers);
+    @VisibleForTesting
+    void handleClientsNotResponding(@NonNull List<ProcessIdentifier> processIdentifiers) {
+        mProcessTerminator.requestTerminateProcesses(processIdentifiers);
+    }
+
+    @VisibleForTesting
+    void handleClientsNotResponding(@NonNull ClientsNotRespondingInfo clientsNotRespondingInfo) {
+        mProcessTerminator.requestTerminateProcesses(clientsNotRespondingInfo);
     }
 
     private void registerMonitorToWatchdogDaemon() {
@@ -685,18 +711,39 @@ public class CarServiceHelperService extends SystemService
         }
     }
 
-    private void killProcessAndReportToMonitor(ProcessIdentifier processIdentifier) {
-        ProcessInfo processInfo = getProcessInfo(processIdentifier.pid);
-        if (!processInfo.doMatch(processIdentifier.pid, processIdentifier.startTimeMillis)) {
+    private static void killProcesses(List<ProcessIdentifier> processIdentifiers,
+            boolean useSigsys) {
+        for (int i = 0; i < processIdentifiers.size(); i++) {
+            ProcessIdentifier processIdentifier = processIdentifiers.get(i);
+            ProcessInfo processInfo = getProcessInfo(processIdentifier.pid);
+            // TODO(b/392937279): add a CTS test to verify that the processes are killed
+            if (useSigsys) {
+                Process.sendSignal(processIdentifier.pid, OsConstants.SIGSYS);
+            } else {
+                Process.killProcess(processIdentifier.pid);
+            }
+            Slogf.w(TAG, "carwatchdog killed %s %s", getProcessCmdLine(processIdentifier.pid),
+                    processInfo);
+        }
+    }
+
+    private void reportProcessesToMonitor(List<ProcessIdentifier> processIdentifiers) {
+        if (processIdentifiers.isEmpty()) {
             return;
         }
-        String cmdline = getProcessCmdLine(processIdentifier.pid);
-        Process.killProcess(processIdentifier.pid);
-        Slogf.w(TAG, "carwatchdog killed %s %s", cmdline, processInfo);
         try {
-            mCarWatchdogDaemonHelper.tellDumpFinished(mCarWatchdogMonitor, processIdentifier);
+            mCarWatchdogDaemonHelper.tellDumpFinished(mCarWatchdogMonitor, processIdentifiers);
         } catch (RemoteException | RuntimeException e) {
-            Slogf.w(TAG, "Cannot report monitor result to car watchdog daemon: %s", e);
+            StringBuilder builder = new StringBuilder("[");
+            for (int i = 1; i < processIdentifiers.size(); i++) {
+                builder.append(processIdentifiers.get(i)).append(", ");
+            }
+            if (builder.length() > 1) {
+                builder.delete(builder.length() - 2, builder.length());
+            }
+            builder.append(']');
+            Slogf.e(TAG, "Cannot report monitor result to car "
+                    + "watchdog daemon for PIDs = %s: %s", builder.toString(), e);
         }
     }
 
@@ -715,11 +762,15 @@ public class CarServiceHelperService extends SystemService
         }
     }
 
-    private ProcessInfo getProcessInfo(int pid) {
+    static ProcessInfo getProcessInfo(int pid) {
+        // TODO(b/400455938): This function used to be private but it was updated to enable
+        // tests to access this method for stubbing. However, this approach is not
+        // recommended. Once the tests are modified to use fake proc fs files, revert this
+        // change. The tests must verify this implementation and not stub it.
         String filename = "/proc/" + pid + "/stat";
         try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
             String line = reader.readLine().replace('\0', ' ').trim();
-            Matcher m = mProcPidStatPattern.matcher(line);
+            Matcher m = sProcPidStatPattern.matcher(line);
             if (m.find()) {
                 int readPid = Integer.parseInt(Objects.requireNonNull(m.group("pid")));
                 if (readPid == pid) {
@@ -851,18 +902,35 @@ public class CarServiceHelperService extends SystemService
             }
             service.handleClientsNotResponding(processIdentifiers);
         }
+        @Override
+        public void onClientsNotRespondingWithSystemState(
+                    ClientsNotRespondingInfo clientsNotRespondingInfo) {
+            CarServiceHelperService service = mService.get();
+            if (service == null || clientsNotRespondingInfo == null
+                    || clientsNotRespondingInfo.processIdentifiers == null
+                    || clientsNotRespondingInfo.processIdentifiers.isEmpty()) {
+                return;
+            }
+            service.handleClientsNotResponding(clientsNotRespondingInfo);
+        }
     }
 
     private final class ProcessTerminator {
 
         private static final long ONE_SECOND_MS = 1_000L;
 
+        private static final long SIGSYS_DELAY_MS = 500;
+
         private final Object mProcessLock = new Object();
         private ExecutorService mExecutor;
         @GuardedBy("mProcessLock")
         private int mQueuedTask;
 
-        public void requestTerminateProcess(@NonNull List<ProcessIdentifier> processIdentifiers) {
+        public void requestTerminateProcesses(@NonNull List<ProcessIdentifier> processIdentifiers) {
+            if (processIdentifiers.isEmpty()) {
+                return;
+            }
+            long startTimeMs = SystemClock.uptimeMillis();
             synchronized (mProcessLock) {
                 // If there is a running thread, we re-use it instead of starting a new thread.
                 if (mExecutor == null) {
@@ -871,17 +939,102 @@ public class CarServiceHelperService extends SystemService
                 mQueuedTask++;
             }
             mExecutor.execute(() -> {
-                for (int i = 0; i < processIdentifiers.size(); i++) {
-                    ProcessIdentifier processIdentifier = processIdentifiers.get(i);
-                    ProcessInfo processInfo = getProcessInfo(processIdentifier.pid);
-                    if (processInfo.doMatch(processIdentifier.pid,
-                            processIdentifier.startTimeMillis)) {
-                        dumpAndKillProcess(processIdentifier);
+                TimingsTraceAndSlog t = newTimingsTraceAndSlog();
+                t.traceBegin("DumpAndKillProcesses_ProcessIdentifiers");
+                EventLogHelper.writeCarHelperWatchdogAnrKill();
+                removeDeadProcesses(/* out */ processIdentifiers);
+                if (processIdentifiers.isEmpty()) {
+                    t.traceEnd();
+                    return;
+                }
+
+                dumpProcesses(processIdentifiers);
+
+                long killWaitMs = SystemClock.uptimeMillis() - startTimeMs;
+                // To give clients a chance of wrapping up before the termination.
+                mHandler.postDelayed(() -> {
+                    removeDeadProcesses(/* out */ processIdentifiers);
+                    if (processIdentifiers.isEmpty()) {
+                        return;
                     }
+                    killProcesses(processIdentifiers, /* useSigsys= */ false);
+                    reportProcessesToMonitor(processIdentifiers);
+                }, (killWaitMs < ONE_SECOND_MS ? ONE_SECOND_MS - killWaitMs : 0));
+
+                // mExecutor will be stopped from the main thread, if there is no queued task.
+                mHandler.sendMessage(obtainMessage(ProcessTerminator::postProcessing, this)
+                        .setWhat(WHAT_POST_PROCESS_DUMPING));
+                t.traceEnd();
+            });
+        }
+
+        public void requestTerminateProcesses(
+                @NonNull ClientsNotRespondingInfo clientsNotRespondingInfo) {
+            if (clientsNotRespondingInfo.processIdentifiers.isEmpty()) {
+                return;
+            }
+            long startTimeMs = SystemClock.uptimeMillis();
+            synchronized (mProcessLock) {
+                // If there is a running thread, we re-use it instead of starting a new thread.
+                if (mExecutor == null) {
+                    mExecutor = Executors.newSingleThreadExecutor();
                 }
+                mQueuedTask++;
+            }
+            mExecutor.execute(() -> {
+                TimingsTraceAndSlog t = newTimingsTraceAndSlog();
+                t.traceBegin("DumpAndKillProcesses");
+                EventLogHelper.writeCarHelperWatchdogAnrKill();
+                List<ProcessIdentifier> processIdentifiers =
+                        clientsNotRespondingInfo.processIdentifiers;
+                removeDeadProcesses(/* out */ processIdentifiers);
+                if (processIdentifiers.isEmpty()) {
+                    t.traceEnd();
+                    return;
+                }
+
+                dumpProcesses(processIdentifiers);
+
+                Runnable killProcessRunnable = new Runnable() {
+                    public void run() {
+                        removeDeadProcesses(/* out */ processIdentifiers);
+                        if (processIdentifiers.isEmpty()) {
+                            return;
+                        }
+                        killProcesses(processIdentifiers, /* useSigsys= */ true);
+                        mHandler.postDelayed(() -> {
+                            List<ProcessIdentifier> processIdentifiersNotKilled =
+                                    new ArrayList<>();
+
+                            for (int i = 0; i < processIdentifiers.size(); i++) {
+                                ProcessIdentifier processIdentifier = processIdentifiers.get(i);
+                                if (getProcessInfo(processIdentifier.pid).name
+                                        != ProcessInfo.UNKNOWN_PROCESS) {
+                                    processIdentifiersNotKilled.add(processIdentifier);
+                                }
+                            }
+
+                            killProcesses(processIdentifiersNotKilled, /* useSigsys= */ false);
+                            reportProcessesToMonitor(processIdentifiers);
+
+                            mHandler.sendMessage(
+                                    obtainMessage(
+                                        ProcessTerminator::pushClientsNotRespondingKillMetrics,
+                                        processIdentifiers, clientsNotRespondingInfo.garageMode)
+                                        .setWhat(WHAT_UPLOAD_METRICS));
+                        }, SIGSYS_DELAY_MS);
+                    }
+                };
+
+                long killWaitMs = SystemClock.uptimeMillis() - startTimeMs;
+                // To give clients a chance of wrapping up before the termination.
+                mHandler.postDelayed(killProcessRunnable,
+                        (killWaitMs < ONE_SECOND_MS ? ONE_SECOND_MS - killWaitMs : 0));
+
                 // mExecutor will be stopped from the main thread, if there is no queued task.
                 mHandler.sendMessage(obtainMessage(ProcessTerminator::postProcessing, this)
                         .setWhat(WHAT_POST_PROCESS_DUMPING));
+                t.traceEnd();
             });
         }
 
@@ -895,55 +1048,82 @@ public class CarServiceHelperService extends SystemService
             }
         }
 
-        private void dumpAndKillProcess(ProcessIdentifier processIdentifier) {
-            if (DBG) {
-                Slogf.d(TAG, "Dumping and killing process(pid: %d)", processIdentifier.pid);
-            }
+        private static void dumpProcesses(List<ProcessIdentifier> processIdentifiers) {
             ArrayList<Integer> javaPids = new ArrayList<>(1);
             ArrayList<Integer> nativePids = new ArrayList<>();
-            try {
-                if (isJavaApp(processIdentifier.pid)) {
-                    javaPids.add(processIdentifier.pid);
-                } else {
-                    nativePids.add(processIdentifier.pid);
+            for (int i = 0; i < processIdentifiers.size(); i++) {
+                ProcessIdentifier processIdentifier = processIdentifiers.get(i);
+                if (DBG) {
+                    Slogf.d(TAG, "Dumping and killing process(pid: %d)", processIdentifier.pid);
+                }
+                try {
+                    if (isJavaApp(processIdentifier.pid)) {
+                        javaPids.add(processIdentifier.pid);
+                    } else {
+                        nativePids.add(processIdentifier.pid);
+                    }
+                } catch (IOException e) {
+                    Slogf.w(TAG, "Cannot get process information for pid %d: %s",
+                            processIdentifier.pid, e);
                 }
-            } catch (IOException e) {
-                Slogf.w(TAG, "Cannot get process information: %s", e);
-                return;
             }
             nativePids.addAll(getInterestingNativePids());
-            long startDumpTime = SystemClock.uptimeMillis();
             StackTracesDumpHelper.dumpStackTraces(
                     /* firstPids= */ javaPids, /* processCpuTracker= */ null, /* lastPids= */ null,
                     /* nativePids= */ CompletableFuture.completedFuture(nativePids),
                     /* logExceptionCreatingFile= */ null,
                     /* auxiliaryTaskExecutor= */ Runnable::run, /* latencyTracker= */ null);
-            long dumpTime = SystemClock.uptimeMillis() - startDumpTime;
-            if (DBG) {
-                Slogf.d(TAG, "Dumping process took %dms", dumpTime);
-            }
-            // To give clients a chance of wrapping up before the termination.
-            if (dumpTime < ONE_SECOND_MS) {
-                mHandler.sendMessageDelayed(obtainMessage(
-                        CarServiceHelperService::killProcessAndReportToMonitor,
-                        CarServiceHelperService.this, processIdentifier).setWhat(WHAT_PROCESS_KILL),
-                        ONE_SECOND_MS - dumpTime);
-            } else {
-                killProcessAndReportToMonitor(processIdentifier);
-            }
         }
 
-        private boolean isJavaApp(int pid) throws IOException {
+        private static boolean isJavaApp(int pid) throws IOException {
             Path exePath = new File("/proc/" + pid + "/exe").toPath();
             String target = Files.readSymbolicLink(exePath).toString();
             // Zygote's target exe is also /system/bin/app_process32 or /system/bin/app_process64.
             // But, we can be very sure that Zygote will not be the client of car watchdog daemon.
-            return target.equals("/system/bin/app_process32") ||
-                    target.equals("/system/bin/app_process64");
+            return target.equals("/system/bin/app_process32")
+                || target.equals("/system/bin/app_process64");
+        }
+
+        private static void pushClientsNotRespondingKillMetrics(
+                List<ProcessIdentifier> processIdentifiers, int garageMode) {
+            SparseArray<List<ProcessIdentifier>> clientsByUid = new SparseArray<>();
+            for (int i = 0; i < processIdentifiers.size(); i++) {
+                ProcessIdentifier processIdentifier = processIdentifiers.get(i);
+                if (!clientsByUid.contains(processIdentifier.uid)) {
+                    clientsByUid.put(processIdentifier.uid, new ArrayList());
+                }
+                clientsByUid.get(processIdentifier.uid).add(processIdentifier);
+            }
+
+            for (int i = 0; i < clientsByUid.size(); i++) {
+                List<ProcessIdentifier> clients = clientsByUid.valueAt(i);
+                FrameworkStatsLog.write(CAR_WATCHDOG_KILL_STATS_REPORTED,
+                        clientsByUid.keyAt(i),
+                        CAR_WATCHDOG_KILL_STATS_REPORTED__UID_STATE__UNKNOWN_UID_STATE,
+                        garageMode == GarageMode.GARAGE_MODE_ON
+                            ? CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__GARAGE_MODE
+                            : CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__UNKNOWN_SYSTEM_STATE,
+                        CAR_WATCHDOG_KILL_STATS_REPORTED__KILL_REASON__KILLED_ON_ANR,
+                        constructCarWatchdogProcessStatsLocked(clients).toByteArray(),
+                       /* arg6= */ null);
+            }
+        }
+
+        private static List<ProcessIdentifier> removeDeadProcesses(
+                List<ProcessIdentifier> processIdentifiers) {
+            processIdentifiers.removeIf(processIdentifier -> {
+                ProcessInfo processInfo = getProcessInfo(processIdentifier.pid);
+                return !processInfo.doMatch(processIdentifier.pid,
+                    processIdentifier.startTimeMillis);
+            });
+            return processIdentifiers;
         }
     }
 
-    private static final class ProcessInfo {
+    @VisibleForTesting
+    static final class ProcessInfo {
+        // TODO(b/400455938): Refer to the comment in `getProcessInfo` for context.
+        // Revert this class to private.
         public static final String UNKNOWN_PROCESS = "unknown process";
         public static final int INVALID_START_TIME = -1;
 
diff --git a/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProvider.java b/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProvider.java
index eb7d1a1..924bd05 100644
--- a/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProvider.java
+++ b/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProvider.java
@@ -17,6 +17,8 @@ package com.android.server.wm;
 
 import static android.content.pm.PackageManager.FEATURE_CAR_DISPLAY_COMPATIBILITY;
 
+import static com.android.server.wm.CompatModePackages.DOWNSCALED;
+import static com.android.server.wm.CompatModePackages.DOWNSCALED_INVERSE;
 import static com.android.server.wm.CompatModePackages.DOWNSCALE_90;
 import static com.android.server.wm.CompatModePackages.DOWNSCALE_85;
 import static com.android.server.wm.CompatModePackages.DOWNSCALE_80;
@@ -155,44 +157,53 @@ public final class CarDisplayCompatScaleProvider implements CompatScaleProvider
             @Override
             public float getCompatModeScalingFactor(@NonNull String packageName,
                     @NonNull UserHandle userHandle) {
+                boolean isDownscaled =
+                        CompatChanges.isChangeEnabled(DOWNSCALED, packageName, userHandle);
+                boolean isDownscaledInverse =
+                        CompatChanges.isChangeEnabled(DOWNSCALED_INVERSE, packageName, userHandle);
+
+                if (!isDownscaled && !isDownscaledInverse) {
+                    return 1f;
+                }
+
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_90, packageName, userHandle)) {
-                    return 0.9f;
+                    return isDownscaledInverse ? 0.9f : 1 / 0.9f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_85, packageName, userHandle)) {
-                    return 0.85f;
+                    return isDownscaledInverse ? 0.85f : 1 / 0.85f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_80, packageName, userHandle)) {
-                    return 0.8f;
+                    return isDownscaledInverse ? 0.8f : 1 / 0.8f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_75, packageName, userHandle)) {
-                    return 0.75f;
+                    return isDownscaledInverse ? 0.75f : 1 / 0.75f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_70, packageName, userHandle)) {
-                    return 0.7f;
+                    return isDownscaledInverse ? 0.7f : 1 / 0.7f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_65, packageName, userHandle)) {
-                    return 0.65f;
+                    return isDownscaledInverse ? 0.65f : 1 / 0.65f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_60, packageName, userHandle)) {
-                    return 0.6f;
+                    return isDownscaledInverse ? 0.6f : 1 / 0.6f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_55, packageName, userHandle)) {
-                    return 0.55f;
+                    return isDownscaledInverse ? 0.55f : 1 / 0.55f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_50, packageName, userHandle)) {
-                    return 0.5f;
+                    return isDownscaledInverse ? 0.5f : 1 / 0.50f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_45, packageName, userHandle)) {
-                    return 0.45f;
+                    return isDownscaledInverse ? 0.45f : 1 / 0.45f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_40, packageName, userHandle)) {
-                    return 0.4f;
+                    return isDownscaledInverse ? 0.4f : 1 / 0.4f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_35, packageName, userHandle)) {
-                    return 0.35f;
+                    return isDownscaledInverse ? 0.35f : 1 / 0.35f;
                 }
                 if (CompatChanges.isChangeEnabled(DOWNSCALE_30, packageName, userHandle)) {
-                    return 0.3f;
+                    return isDownscaledInverse ? 0.3f : 1 / 0.3f;
                 }
                 return 1f;
             }
diff --git a/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProviderInterface.java b/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProviderInterface.java
index 160f2f4..f6f27b3 100644
--- a/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProviderInterface.java
+++ b/builtInServices/src/com/android/server/wm/CarDisplayCompatScaleProviderInterface.java
@@ -89,5 +89,5 @@ public interface CarDisplayCompatScaleProviderInterface {
      * see {@link CompatChanges#isChangeEnabled}
      */
     float getCompatModeScalingFactor(@NonNull String packageName,
-            @NonNull UserHandle user);
+            @NonNull UserHandle userHandle);
 }
diff --git a/builtInServices/src/com/android/server/wm/LaunchParamsWrapper.java b/builtInServices/src/com/android/server/wm/LaunchParamsWrapper.java
index a9b61ac..c582b87 100644
--- a/builtInServices/src/com/android/server/wm/LaunchParamsWrapper.java
+++ b/builtInServices/src/com/android/server/wm/LaunchParamsWrapper.java
@@ -16,6 +16,7 @@
 
 package com.android.server.wm;
 
+import android.annotation.FlaggedApi;
 import android.annotation.Nullable;
 import android.annotation.SystemApi;
 import android.graphics.Rect;
@@ -81,6 +82,14 @@ public final class LaunchParamsWrapper {
         mLaunchParams.mWindowingMode = windowingMode;
     }
 
+    /**
+     * Sets whether safe region bounds are needed for the Activity in this launch.
+     */
+    @FlaggedApi(com.android.window.flags.Flags.FLAG_SAFE_REGION_LETTERBOXING)
+    public void setNeedsSafeRegionBounds(boolean needsSafeRegionBounds) {
+        mLaunchParams.mNeedsSafeRegionBounds = needsSafeRegionBounds;
+    }
+
     /**
      *  Gets the bounds within the parent container.
      */
@@ -97,9 +106,10 @@ public final class LaunchParamsWrapper {
 
     @Override
     public String toString() {
-        return "LaunchParams{" +
-                "mPreferredTaskDisplayArea=" + mLaunchParams.mPreferredTaskDisplayArea +
-                ", mWindowingMode=" + mLaunchParams.mWindowingMode +
-                ", mBounds=" + mLaunchParams.mBounds.toString() + '}';
+        return "LaunchParams{"
+                + "mPreferredTaskDisplayArea=" + mLaunchParams.mPreferredTaskDisplayArea
+                + ", mWindowingMode=" + mLaunchParams.mWindowingMode
+                + ", mNeedsSafeRegionBounds=" + mLaunchParams.mNeedsSafeRegionBounds
+                + ", mBounds=" + mLaunchParams.mBounds.toString() + '}';
     }
 }
diff --git a/builtInServices/src/com/android/server/wm/MediaTemplateActivityInterceptorForSuspension.java b/builtInServices/src/com/android/server/wm/MediaTemplateActivityInterceptorForSuspension.java
new file mode 100644
index 0000000..196606c
--- /dev/null
+++ b/builtInServices/src/com/android/server/wm/MediaTemplateActivityInterceptorForSuspension.java
@@ -0,0 +1,117 @@
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
+package com.android.server.wm;
+
+import static android.car.media.CarMediaIntents.ACTION_MEDIA_TEMPLATE;
+import static android.car.media.CarMediaIntents.EXTRA_MEDIA_COMPONENT;
+
+import android.annotation.Nullable;
+import android.annotation.SystemApi;
+import android.app.ActivityOptions;
+import android.car.feature.Flags;
+import android.content.ComponentName;
+import android.content.Intent;
+import android.content.pm.PackageManagerInternal;
+import android.content.pm.SuspendDialogInfo;
+import android.content.pm.UserPackage;
+
+import com.android.internal.app.SuspendedAppActivity;
+import com.android.server.LocalServices;
+
+import java.util.regex.Pattern;
+
+/**
+ * This class handles interception of suspended templated media apps.
+ *
+ * @hide
+ */
+@SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
+public final class MediaTemplateActivityInterceptorForSuspension
+        implements CarActivityInterceptorUpdatable {
+    private static final String MEDIA_TEMPLATE_REGEX =
+            "androidx\\.car\\.app\\.mediaextensions\\.action\\.MEDIA_TEMPLATE_V.+";
+    private static final Pattern MEDIA_TEMPLATE_ACTION_PATTERN =
+            Pattern.compile(MEDIA_TEMPLATE_REGEX);
+
+    private final PackageManagerInternal mPackageManagerInternal;
+
+    public MediaTemplateActivityInterceptorForSuspension() {
+        mPackageManagerInternal = LocalServices.getService(PackageManagerInternal.class);
+    }
+
+    @Nullable
+    @Override
+    public ActivityInterceptResultWrapper onInterceptActivityLaunch(
+            ActivityInterceptorInfoWrapper info) {
+        if (!Flags.carMediaAppsSuspension()) {
+            return null;
+        }
+        Intent launchIntent = info.getIntent();
+        if (launchIntent == null) {
+            return null;
+        }
+        if (!isActionMediaTemplate(launchIntent.getAction())) {
+            return null;
+        }
+        String packageName = getMediaPackage(launchIntent);
+        if (packageName == null) {
+            return null;
+        }
+        int userId = info.getUserId();
+        if (!mPackageManagerInternal.isPackageSuspended(packageName, userId)) {
+            return null;
+        }
+        UserPackage suspender = mPackageManagerInternal.getSuspendingPackage(packageName, userId);
+        SuspendDialogInfo dialogInfo =
+                mPackageManagerInternal.getSuspendedDialogInfo(packageName, suspender, userId);
+        Intent intent = SuspendedAppActivity.createSuspendedAppInterceptIntent(
+                packageName,
+                suspender,
+                dialogInfo,
+                /* options = */ null,
+                /* onUnsuspend = */ null,
+                userId
+        );
+        // SuspendedAppActivity should be launched with the default options, the calling activity
+        // options should not affect the default dialog.
+        return ActivityInterceptResultWrapper.create(intent, ActivityOptions.makeBasic());
+    }
+
+    private static boolean isActionMediaTemplate(@Nullable String action) {
+        if (action == null) {
+            return false;
+        }
+        if (ACTION_MEDIA_TEMPLATE.equals(action)) {
+            return true;
+        }
+        return MEDIA_TEMPLATE_ACTION_PATTERN.matcher(action).matches();
+    }
+
+    @Nullable
+    private static String getMediaPackage(Intent intent) {
+        // Media Template Activity have the MBS service defined in the EXTRA_MEDIA_COMPONENT
+        String componentNameString = intent.getStringExtra(EXTRA_MEDIA_COMPONENT);
+        if (componentNameString == null) {
+            return null;
+        }
+        ComponentName componentName = ComponentName.unflattenFromString(componentNameString);
+        if (componentName == null) {
+            return null;
+        }
+        return componentName.getPackageName();
+    }
+}
diff --git a/builtInServices/tests/Android.bp b/builtInServices/tests/Android.bp
index 61faeb5..b60109a 100644
--- a/builtInServices/tests/Android.bp
+++ b/builtInServices/tests/Android.bp
@@ -39,6 +39,7 @@ android_test {
         "testng",
         "truth",
         "car-frameworks-service.impl",
+        "flag-junit",
     ],
 
     // mockito-target-extended dependencies
@@ -50,6 +51,6 @@ android_test {
 
     test_suites: [
         "general-tests",
-        "automotive-tests",
+        "automotive-general-tests",
     ],
 }
diff --git a/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java b/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
index dc17c99..84a55c8 100644
--- a/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
+++ b/builtInServices/tests/src/com/android/car/rotary/ActivityResolverTest.java
@@ -26,6 +26,7 @@ import android.content.Intent;
 import android.view.KeyEvent;
 import android.view.accessibility.AccessibilityManager;
 
+import androidx.test.filters.FlakyTest;
 import androidx.test.platform.app.InstrumentationRegistry;
 import androidx.test.uiautomator.Condition;
 import androidx.test.uiautomator.UiDevice;
@@ -107,6 +108,7 @@ public final class ActivityResolverTest {
     }
 
     @Test
+    @FlakyTest(bugId = 397717760)
     public void testListItemFocusable_twoItems() throws UiObjectNotFoundException, IOException {
         assumeHasRotaryService();
         launchResolverActivity();
@@ -205,6 +207,7 @@ public final class ActivityResolverTest {
     }
 
     @Test
+    @FlakyTest(bugId = 397717760)
     public void testClickListItem_twoItems() throws UiObjectNotFoundException, IOException {
         assumeHasRotaryService();
         launchResolverActivity();
@@ -226,6 +229,7 @@ public final class ActivityResolverTest {
     }
 
     @Test
+    @FlakyTest(bugId = 397717760)
     public void testClickJustOnceButton_twoItems() throws UiObjectNotFoundException, IOException {
         assumeHasRotaryService();
         launchResolverActivity();
diff --git a/builtInServices/tests/src/com/android/internal/car/CarServiceHelperServiceTest.java b/builtInServices/tests/src/com/android/internal/car/CarServiceHelperServiceTest.java
index dc07ed8..2933704 100644
--- a/builtInServices/tests/src/com/android/internal/car/CarServiceHelperServiceTest.java
+++ b/builtInServices/tests/src/com/android/internal/car/CarServiceHelperServiceTest.java
@@ -23,6 +23,9 @@ import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVE
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_STOPPING;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_SWITCHING;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_UNLOCKING;
+import static com.android.internal.util.FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED__KILL_REASON__KILLED_ON_ANR;
+import static com.android.internal.util.FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED__UID_STATE__UNKNOWN_UID_STATE;
+import static com.android.internal.util.FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__GARAGE_MODE;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mock;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
@@ -31,8 +34,16 @@ import static com.android.server.SystemService.UserCompletedEventType.newUserCom
 
 import static com.google.common.truth.Truth.assertWithMessage;
 
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.timeout;
+
 import android.annotation.UserIdInt;
 import android.app.ActivityManager;
+import android.automotive.watchdog.internal.ClientsNotRespondingInfo;
+import android.automotive.watchdog.internal.GarageMode;
+import android.automotive.watchdog.internal.ProcessIdentifier;
 import android.car.test.mocks.AbstractExtendedMockitoTestCase;
 import android.car.watchdoglib.CarWatchdogDaemonHelper;
 import android.content.Context;
@@ -44,9 +55,13 @@ import android.os.UserHandle;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
+import com.android.internal.util.CarWatchdogKillStatsReported;
+import com.android.internal.util.CarWatchdogProcessStats;
+import com.android.internal.util.FrameworkStatsLog;
 import com.android.server.LocalServices;
 import com.android.server.SystemService.TargetUser;
 import com.android.server.SystemService.UserCompletedEventType;
+import com.android.server.am.StackTracesDumpHelper;
 import com.android.server.pm.UserManagerInternal;
 import com.android.server.wm.CarDisplayCompatScaleProvider;
 import com.android.server.wm.CarLaunchParamsModifier;
@@ -54,8 +69,16 @@ import com.android.server.wm.CarLaunchParamsModifier;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Captor;
 import org.mockito.Mock;
 
+import java.nio.file.Files;
+import java.nio.file.Path;
+import java.util.ArrayList;
+import java.util.List;
+import java.util.concurrent.Future;
+
 /**
  * This class contains unit tests for the {@link CarServiceHelperService}.
  */
@@ -63,12 +86,15 @@ import org.mockito.Mock;
 public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase {
     private static final String SAMPLE_AIDL_VHAL_INTERFACE_NAME =
             "android.hardware.automotive.vehicle.IVehicle/SampleVehicleHalService";
+    private static final int MAX_WAIT_TIME_MS = 3000;
 
     private CarServiceHelperService mHelper;
 
     @Mock
     private Context mMockContext;
     @Mock
+    private Path mMockPath;
+    @Mock
     private PackageManager mPackageManager;
     @Mock
     private CarLaunchParamsModifier mCarLaunchParamsModifier;
@@ -93,6 +119,15 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
     @Mock
     private CarDisplayCompatScaleProvider mCarDisplayCompatScaleProvider;
 
+    @Captor private ArgumentCaptor<byte[]> mKilledStatsCaptor;
+    @Captor private ArgumentCaptor<Integer> mKilledUidCaptor;
+    @Captor private ArgumentCaptor<Integer> mUidStateCaptor;
+    @Captor private ArgumentCaptor<Integer> mSystemStateCaptor;
+    @Captor private ArgumentCaptor<Integer> mKillReasonCaptor;
+    @Captor private ArgumentCaptor<ArrayList<Integer>> mDumpJavaPidCaptor;
+    @Captor private ArgumentCaptor<Future<ArrayList<Integer>>> mDumpNativePidCaptor;
+    @Captor private ArgumentCaptor<ArrayList<ProcessIdentifier>> mProcessIdentifierCaptor;
+
     public CarServiceHelperServiceTest() {
         super(CarServiceHelperService.TAG);
     }
@@ -104,7 +139,11 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
     protected void onSessionBuilder(CustomMockitoSessionBuilder session) {
         session
                 .spyStatic(ServiceManager.class)
-                .spyStatic(LocalServices.class);
+                .spyStatic(LocalServices.class)
+                .spyStatic(Files.class)
+                .spyStatic(FrameworkStatsLog.class)
+                .spyStatic(CarServiceHelperService.class)
+                .spyStatic(StackTracesDumpHelper.class);
     }
 
     @Before
@@ -245,6 +284,408 @@ public class CarServiceHelperServiceTest extends AbstractExtendedMockitoTestCase
                 .isEqualTo(INVALID_PID);
     }
 
+    @Test
+    public void
+            testHandleClientsNotRespondingWithAnrMetricsFeatureDisabledOnEmptyProcessIdentifiers()
+            throws Exception {
+        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
+        List<ProcessIdentifier> processIdentifiers = new ArrayList<ProcessIdentifier>();
+
+        mHelper.handleClientsNotResponding(processIdentifiers);
+
+        verify(() -> StackTracesDumpHelper.dumpStackTraces(any(), any(), any(), any(), any(),
+                any(), any()), never());
+        verify(mCarWatchdogDaemonHelper, never()).tellDumpFinished(any(), any());
+    }
+
+    @Test
+    public void testHandleClientsNotRespondingWithAnrMetricsFeatureDisabledOnDeadProcessIdentifier()
+            throws Exception {
+        int testUid1 = 1001;
+        int testUid2 = 1002;
+        List<ProcessIdentifier> processIdentifiers = new ArrayList<ProcessIdentifier>();
+        List<ProcessIdentifier> expectedProcessIdentifiers = new ArrayList<ProcessIdentifier>();
+
+        ProcessIdentifier processIdentifier1 = new ProcessIdentifier();
+        processIdentifier1.processName = "name1";
+        processIdentifier1.pid = 1;
+        processIdentifier1.uid = testUid1;
+        processIdentifier1.startTimeMillis = 1000;
+        processIdentifiers.add(processIdentifier1);
+        expectedProcessIdentifiers.add(processIdentifier1);
+
+        ProcessIdentifier processIdentifier2 = new ProcessIdentifier();
+        processIdentifier2.processName = "name2";
+        processIdentifier2.pid = 2;
+        processIdentifier2.uid = testUid1;
+        processIdentifier2.startTimeMillis = 2000;
+        processIdentifiers.add(processIdentifier2);
+        expectedProcessIdentifiers.add(processIdentifier2);
+
+        ProcessIdentifier processIdentifier3 = new ProcessIdentifier();
+        processIdentifier3.processName = "name3";
+        processIdentifier3.pid = 3;
+        processIdentifier3.uid = testUid2;
+        processIdentifier3.startTimeMillis = 3000;
+        processIdentifiers.add(processIdentifier3);
+        expectedProcessIdentifiers.add(processIdentifier3);
+
+        ProcessIdentifier processIdentifier4 = new ProcessIdentifier();
+        processIdentifier4.processName = "name4";
+        processIdentifier4.pid = 4;
+        processIdentifier4.uid = testUid2;
+        processIdentifier4.startTimeMillis = 4000;
+        processIdentifiers.add(processIdentifier4);
+
+        List<Integer> expectedPids = new ArrayList<>();
+        for (ProcessIdentifier processIdentifier : expectedProcessIdentifiers) {
+            expectedPids.add(processIdentifier.pid);
+        }
+
+        CarServiceHelperService.ProcessInfo invalidProcess =
+                new CarServiceHelperService.ProcessInfo(4,
+                    CarServiceHelperService.ProcessInfo.UNKNOWN_PROCESS,
+                    5000);
+
+        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
+        doReturn(invalidProcess).when(() -> CarServiceHelperService.getProcessInfo(4));
+        doReturn(null).when(() -> StackTracesDumpHelper.dumpStackTraces(any(), any(), any(), any(),
+                any(), any(), any()));
+        doReturn(mMockPath).when(() -> Files.readSymbolicLink(any()));
+        doReturn("/system/bin/app_process32").when(mMockPath).toString();
+
+        mHelper.handleClientsNotResponding(processIdentifiers);
+
+        verify(() -> StackTracesDumpHelper.dumpStackTraces(mDumpJavaPidCaptor.capture(), eq(null),
+                    eq(null), mDumpNativePidCaptor.capture(), eq(null), any(), eq(null)),
+                timeout(MAX_WAIT_TIME_MS).times(1));
+        verify(mCarWatchdogDaemonHelper, timeout(MAX_WAIT_TIME_MS).times(1))
+                .tellDumpFinished(any(), mProcessIdentifierCaptor.capture());
+
+        // Methods are only called once, so they will only contain one list at index 0
+        List<ProcessIdentifier> actualProcessIdentifiers =
+                new ArrayList<>(mProcessIdentifierCaptor.getAllValues().get(0));
+        List<Integer> actualPids = new ArrayList<>(mDumpJavaPidCaptor.getAllValues().get(0));
+        // Call .get() because mDumpNativePidCaptor contains future objects
+        actualPids.addAll(mDumpNativePidCaptor.getAllValues().get(0).get());
+
+        assertWithMessage("ANRed processes dumped").that(actualPids)
+                .containsAtLeastElementsIn(expectedPids);
+        assertWithMessage("ANRed processes told dump finished")
+                .that(actualProcessIdentifiers)
+                .containsExactlyElementsIn(expectedProcessIdentifiers);
+    }
+
+    @Test
+    public void testHandleClientsNotRespondingWithAnrMetricsFeatureDisabled() throws Exception {
+        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
+        int testUid1 = 1001;
+        int testUid2 = 1002;
+        List<ProcessIdentifier> expectedProcessIdentifiers = new ArrayList<ProcessIdentifier>();
+
+        ProcessIdentifier processIdentifier1 = new ProcessIdentifier();
+        processIdentifier1.processName = "name1";
+        processIdentifier1.pid = 1;
+        processIdentifier1.uid = testUid1;
+        processIdentifier1.startTimeMillis = 1000;
+        expectedProcessIdentifiers.add(processIdentifier1);
+
+        ProcessIdentifier processIdentifier2 = new ProcessIdentifier();
+        processIdentifier2.processName = "name2";
+        processIdentifier2.pid = 2;
+        processIdentifier2.uid = testUid1;
+        processIdentifier2.startTimeMillis = 2000;
+        expectedProcessIdentifiers.add(processIdentifier2);
+
+        ProcessIdentifier processIdentifier3 = new ProcessIdentifier();
+        processIdentifier3.processName = "name3";
+        processIdentifier3.pid = 3;
+        processIdentifier3.uid = testUid2;
+        processIdentifier3.startTimeMillis = 3000;
+        expectedProcessIdentifiers.add(processIdentifier3);
+
+        ProcessIdentifier processIdentifier4 = new ProcessIdentifier();
+        processIdentifier4.processName = "name4";
+        processIdentifier4.pid = 4;
+        processIdentifier4.uid = testUid2;
+        processIdentifier4.startTimeMillis = 4000;
+        expectedProcessIdentifiers.add(processIdentifier4);
+
+        List<Integer> expectedPids = new ArrayList<>();
+        for (ProcessIdentifier processIdentifier : expectedProcessIdentifiers) {
+            expectedPids.add(processIdentifier.pid);
+        }
+
+        doReturn(null).when(() -> StackTracesDumpHelper.dumpStackTraces(any(), any(), any(), any(),
+                any(), any(), any()));
+        doReturn(mMockPath).when(() -> Files.readSymbolicLink(any()));
+        doReturn("/system/bin/app_process32").when(mMockPath).toString();
+
+        mHelper.handleClientsNotResponding(
+                new ArrayList<ProcessIdentifier>(expectedProcessIdentifiers));
+
+        verify(() -> StackTracesDumpHelper.dumpStackTraces(mDumpJavaPidCaptor.capture(), eq(null),
+                eq(null), mDumpNativePidCaptor.capture(), eq(null), any(), eq(null)),
+                timeout(MAX_WAIT_TIME_MS).times(1));
+        verify(mCarWatchdogDaemonHelper, timeout(MAX_WAIT_TIME_MS).times(1))
+                .tellDumpFinished(any(), mProcessIdentifierCaptor.capture());
+
+        // Methods are only called once, so they will only contain one list at index 0
+        List<ProcessIdentifier> actualProcessIdentifiers =
+                new ArrayList<>(mProcessIdentifierCaptor.getAllValues().get(0));
+        List<Integer> actualPids = new ArrayList<>(mDumpJavaPidCaptor.getAllValues().get(0));
+        // Call .get() because mDumpNativePidCaptor contains future objects
+        actualPids.addAll(mDumpNativePidCaptor.getAllValues().get(0).get());
+
+        assertWithMessage("ANRed processes dumped").that(actualPids)
+                .containsAtLeastElementsIn(expectedPids);
+        assertWithMessage("ANRed processes told dump finished")
+                .that(actualProcessIdentifiers)
+                .containsExactlyElementsIn(expectedProcessIdentifiers);
+    }
+
+    @Test
+    public void testHandleClientsNotRespondingOnEmptyClientsNotRespondingInfo() throws Exception {
+        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
+        List<ProcessIdentifier> processIdentifiers = new ArrayList<ProcessIdentifier>();
+
+        ClientsNotRespondingInfo clientsNotRespondingInfo = new ClientsNotRespondingInfo();
+        clientsNotRespondingInfo.processIdentifiers = processIdentifiers;
+        clientsNotRespondingInfo.garageMode = GarageMode.GARAGE_MODE_ON;
+
+        mHelper.handleClientsNotResponding(clientsNotRespondingInfo);
+
+        verify(() -> StackTracesDumpHelper.dumpStackTraces(any(), any(), any(), any(), any(),
+                any(), any()), never());
+        verify(mCarWatchdogDaemonHelper, never()).tellDumpFinished(any(), any());
+    }
+
+    @Test
+    public void testHandleClientsNotRespondingOnDeadClientsNotRespondingInfo() throws Exception {
+        int testUid1 = 1001;
+        int testUid2 = 1002;
+        List<ProcessIdentifier> processIdentifiers = new ArrayList<ProcessIdentifier>();
+        List<ProcessIdentifier> expectedProcessIdentifiers = new ArrayList<ProcessIdentifier>();
+
+        ProcessIdentifier processIdentifier1 = new ProcessIdentifier();
+        processIdentifier1.processName = "name1";
+        processIdentifier1.pid = 1;
+        processIdentifier1.uid = testUid1;
+        processIdentifier1.startTimeMillis = 1000;
+        processIdentifiers.add(processIdentifier1);
+        expectedProcessIdentifiers.add(processIdentifier1);
+
+        ProcessIdentifier processIdentifier2 = new ProcessIdentifier();
+        processIdentifier2.processName = "name2";
+        processIdentifier2.pid = 2;
+        processIdentifier2.uid = testUid1;
+        processIdentifier2.startTimeMillis = 2000;
+        processIdentifiers.add(processIdentifier2);
+        expectedProcessIdentifiers.add(processIdentifier2);
+
+        ProcessIdentifier processIdentifier3 = new ProcessIdentifier();
+        processIdentifier3.processName = "name3";
+        processIdentifier3.pid = 3;
+        processIdentifier3.uid = testUid2;
+        processIdentifier3.startTimeMillis = 3000;
+        processIdentifiers.add(processIdentifier3);
+        expectedProcessIdentifiers.add(processIdentifier3);
+
+        ProcessIdentifier processIdentifier4 = new ProcessIdentifier();
+        processIdentifier4.processName = "name4";
+        processIdentifier4.pid = 4;
+        processIdentifier4.uid = testUid2;
+        processIdentifier4.startTimeMillis = 4000;
+        processIdentifiers.add(processIdentifier4);
+
+        List<Integer> expectedPids = new ArrayList<>();
+        for (ProcessIdentifier processIdentifier : expectedProcessIdentifiers) {
+            expectedPids.add(processIdentifier.pid);
+        }
+
+        ClientsNotRespondingInfo clientsNotRespondingInfo = new ClientsNotRespondingInfo();
+        clientsNotRespondingInfo.processIdentifiers = processIdentifiers;
+        clientsNotRespondingInfo.garageMode = GarageMode.GARAGE_MODE_ON;
+
+        CarServiceHelperService.ProcessInfo invalidProcess =
+                new CarServiceHelperService.ProcessInfo(4,
+                    CarServiceHelperService.ProcessInfo.UNKNOWN_PROCESS,
+                    5000);
+
+        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
+        doReturn(invalidProcess).when(() -> CarServiceHelperService.getProcessInfo(4));
+        doReturn(null).when(() -> StackTracesDumpHelper.dumpStackTraces(any(), any(), any(), any(),
+                any(), any(), any()));
+        doReturn(mMockPath).when(() -> Files.readSymbolicLink(any()));
+        doReturn("/system/bin/app_process32").when(mMockPath).toString();
+
+        mHelper.handleClientsNotResponding(clientsNotRespondingInfo);
+
+        verify(() -> StackTracesDumpHelper.dumpStackTraces(mDumpJavaPidCaptor.capture(), eq(null),
+                    eq(null), mDumpNativePidCaptor.capture(), eq(null), any(), eq(null)),
+                timeout(MAX_WAIT_TIME_MS).times(1));
+        verify(mCarWatchdogDaemonHelper, timeout(MAX_WAIT_TIME_MS).times(1))
+                .tellDumpFinished(any(), mProcessIdentifierCaptor.capture());
+
+        // Methods are only called once, so they will only contain one list at index 0
+        List<ProcessIdentifier> actualProcessIdentifiers =
+                new ArrayList<>(mProcessIdentifierCaptor.getAllValues().get(0));
+        List<Integer> actualPids = new ArrayList<>(mDumpJavaPidCaptor.getAllValues().get(0));
+        // Call .get() because mDumpNativePidCaptor contains future objects
+        actualPids.addAll(mDumpNativePidCaptor.getAllValues().get(0).get());
+
+        assertWithMessage("ANRed processes dumped").that(actualPids)
+                .containsAtLeastElementsIn(expectedPids);
+        assertWithMessage("ANRed processes told dump finished")
+                .that(actualProcessIdentifiers)
+                .containsExactlyElementsIn(expectedProcessIdentifiers);
+
+        captureAndVerifyKillStatsReported(
+            new ArrayList<CarWatchdogKillStatsReported>(
+                List.of(constructCarWatchdogKillStatsReported(
+                        testUid1,
+                        CAR_WATCHDOG_KILL_STATS_REPORTED__UID_STATE__UNKNOWN_UID_STATE,
+                        CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__GARAGE_MODE,
+                        CAR_WATCHDOG_KILL_STATS_REPORTED__KILL_REASON__KILLED_ON_ANR,
+                        CarServiceHelperService.constructCarWatchdogProcessStatsLocked(
+                            List.of(processIdentifier1, processIdentifier2))),
+                    constructCarWatchdogKillStatsReported(
+                        testUid2,
+                        CAR_WATCHDOG_KILL_STATS_REPORTED__UID_STATE__UNKNOWN_UID_STATE,
+                        CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__GARAGE_MODE,
+                        CAR_WATCHDOG_KILL_STATS_REPORTED__KILL_REASON__KILLED_ON_ANR,
+                        CarServiceHelperService.constructCarWatchdogProcessStatsLocked(
+                            List.of(processIdentifier3))))));
+    }
+
+    @Test
+    public void testHandleClientsNotResponding() throws Exception {
+        // TODO(b/400455938): Update ANR metrics tests to mock the /proc/<pid>/stat files
+        int testUid1 = 1001;
+        int testUid2 = 1002;
+        List<ProcessIdentifier> expectedProcessIdentifiers = new ArrayList<ProcessIdentifier>();
+
+        ProcessIdentifier processIdentifier1 = new ProcessIdentifier();
+        processIdentifier1.processName = "name1";
+        processIdentifier1.pid = 1;
+        processIdentifier1.uid = testUid1;
+        processIdentifier1.startTimeMillis = 1000;
+        expectedProcessIdentifiers.add(processIdentifier1);
+
+        ProcessIdentifier processIdentifier2 = new ProcessIdentifier();
+        processIdentifier2.processName = "name2";
+        processIdentifier2.pid = 2;
+        processIdentifier2.uid = testUid1;
+        processIdentifier2.startTimeMillis = 2000;
+        expectedProcessIdentifiers.add(processIdentifier2);
+
+        ProcessIdentifier processIdentifier3 = new ProcessIdentifier();
+        processIdentifier3.processName = "name3";
+        processIdentifier3.pid = 3;
+        processIdentifier3.uid = testUid2;
+        processIdentifier3.startTimeMillis = 3000;
+        expectedProcessIdentifiers.add(processIdentifier3);
+
+        ProcessIdentifier processIdentifier4 = new ProcessIdentifier();
+        processIdentifier4.processName = "name4";
+        processIdentifier4.pid = 4;
+        processIdentifier4.uid = testUid2;
+        processIdentifier4.startTimeMillis = 4000;
+        expectedProcessIdentifiers.add(processIdentifier4);
+
+        List<Integer> expectedPids = new ArrayList<>();
+        for (ProcessIdentifier processIdentifier : expectedProcessIdentifiers) {
+            expectedPids.add(processIdentifier.pid);
+        }
+
+        ClientsNotRespondingInfo clientsNotRespondingInfo = new ClientsNotRespondingInfo();
+        clientsNotRespondingInfo.processIdentifiers =
+                new ArrayList<ProcessIdentifier>(expectedProcessIdentifiers);
+        clientsNotRespondingInfo.garageMode = GarageMode.GARAGE_MODE_ON;
+
+        doReturn(null).when(() -> StackTracesDumpHelper.dumpStackTraces(any(), any(), any(), any(),
+                any(), any(), any()));
+        doReturn(mMockPath).when(() -> Files.readSymbolicLink(any()));
+        doReturn("/system/bin/app_process32").when(mMockPath).toString();
+
+        mHelper.handleClientsNotResponding(clientsNotRespondingInfo);
+
+        verify(() -> StackTracesDumpHelper.dumpStackTraces(mDumpJavaPidCaptor.capture(), eq(null),
+                eq(null), mDumpNativePidCaptor.capture(), eq(null), any(), eq(null)),
+                timeout(MAX_WAIT_TIME_MS).times(1));
+        verify(mCarWatchdogDaemonHelper, timeout(MAX_WAIT_TIME_MS).times(1))
+                .tellDumpFinished(any(), mProcessIdentifierCaptor.capture());
+
+        // Methods are only called once, so they will only contain one list at index 0
+        List<ProcessIdentifier> actualProcessIdentifiers =
+                new ArrayList<>(mProcessIdentifierCaptor.getAllValues().get(0));
+        List<Integer> actualPids = new ArrayList<>(mDumpJavaPidCaptor.getAllValues().get(0));
+        // Call .get() because mDumpNativePidCaptor contains future objects
+        actualPids.addAll(mDumpNativePidCaptor.getAllValues().get(0).get());
+
+        assertWithMessage("ANRed processes dumped").that(actualPids)
+                .containsAtLeastElementsIn(expectedPids);
+        assertWithMessage("ANRed processes told dump finished")
+                .that(actualProcessIdentifiers)
+                .containsExactlyElementsIn(expectedProcessIdentifiers);
+
+        captureAndVerifyKillStatsReported(
+            new ArrayList<CarWatchdogKillStatsReported>(
+                List.of(constructCarWatchdogKillStatsReported(
+                            testUid1,
+                            CAR_WATCHDOG_KILL_STATS_REPORTED__UID_STATE__UNKNOWN_UID_STATE,
+                            CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__GARAGE_MODE,
+                            CAR_WATCHDOG_KILL_STATS_REPORTED__KILL_REASON__KILLED_ON_ANR,
+                            CarServiceHelperService.constructCarWatchdogProcessStatsLocked(
+                                List.of(processIdentifier1, processIdentifier2))),
+                        constructCarWatchdogKillStatsReported(
+                            testUid2,
+                            CAR_WATCHDOG_KILL_STATS_REPORTED__UID_STATE__UNKNOWN_UID_STATE,
+                            CAR_WATCHDOG_KILL_STATS_REPORTED__SYSTEM_STATE__GARAGE_MODE,
+                            CAR_WATCHDOG_KILL_STATS_REPORTED__KILL_REASON__KILLED_ON_ANR,
+                            CarServiceHelperService.constructCarWatchdogProcessStatsLocked(
+                                List.of(processIdentifier3, processIdentifier4))))));
+    }
+
+    private void captureAndVerifyKillStatsReported(
+            List<CarWatchdogKillStatsReported> expected) throws Exception {
+        verify(() -> FrameworkStatsLog.write(eq(FrameworkStatsLog.CAR_WATCHDOG_KILL_STATS_REPORTED),
+                mKilledUidCaptor.capture(), mUidStateCaptor.capture(),
+                mSystemStateCaptor.capture(), mKillReasonCaptor.capture(),
+                mKilledStatsCaptor.capture(), eq(null)),
+                timeout(MAX_WAIT_TIME_MS).times(expected.size()));
+
+        List<Integer> allUidValues = mKilledUidCaptor.getAllValues();
+        List<Integer> allUidStateValues = mUidStateCaptor.getAllValues();
+        List<Integer> allSystemStateValues = mSystemStateCaptor.getAllValues();
+        List<Integer> allKillReasonValues = mKillReasonCaptor.getAllValues();
+        List<byte[]> allProcessStats = mKilledStatsCaptor.getAllValues();
+        List<CarWatchdogKillStatsReported> actual = new ArrayList<>();
+        for (int i = 0; i < expected.size(); i++) {
+            actual.add(constructCarWatchdogKillStatsReported(allUidValues.get(i),
+                    allUidStateValues.get(i), allSystemStateValues.get(i),
+                    allKillReasonValues.get(i),
+                    CarWatchdogProcessStats.parseFrom(
+                        allProcessStats.get(i))));
+        }
+        assertWithMessage("ANR kill stats reported to statsd").that(actual)
+            .containsExactlyElementsIn(expected);
+    }
+
+    private static CarWatchdogKillStatsReported constructCarWatchdogKillStatsReported(
+            int uid, int uidState, int systemState, int killReason,
+            CarWatchdogProcessStats processStats) {
+        return CarWatchdogKillStatsReported.newBuilder()
+                .setUid(uid)
+                .setUidState(CarWatchdogKillStatsReported.UidState.forNumber(uidState))
+                .setSystemState(CarWatchdogKillStatsReported.SystemState.forNumber(
+                    systemState))
+                .setKillReason(CarWatchdogKillStatsReported.KillReason.forNumber(
+                    killReason))
+                .setProcessStats(processStats)
+                .build();
+    }
+
     private TargetUser newTargetUser(int userId) {
         return newTargetUser(userId, /* preCreated= */ false);
     }
diff --git a/builtInServices/tests/src/com/android/server/inputmethod/ImeSmokeTest.java b/builtInServices/tests/src/com/android/server/inputmethod/ImeSmokeTest.java
deleted file mode 100644
index 07abccf..0000000
--- a/builtInServices/tests/src/com/android/server/inputmethod/ImeSmokeTest.java
+++ /dev/null
@@ -1,151 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-package com.android.server.inputmethod;
-
-import static com.google.common.truth.Truth.assertThat;
-
-import static org.junit.Assume.assumeTrue;
-
-import android.app.Instrumentation;
-import android.content.ContentResolver;
-import android.content.Context;
-import android.content.Intent;
-import android.content.pm.PackageManager;
-import android.os.SystemClock;
-import android.provider.Settings;
-import android.view.accessibility.AccessibilityWindowInfo;
-
-import androidx.test.platform.app.InstrumentationRegistry;
-import androidx.test.uiautomator.Condition;
-import androidx.test.uiautomator.UiDevice;
-import androidx.test.uiautomator.UiObject;
-import androidx.test.uiautomator.UiObjectNotFoundException;
-import androidx.test.uiautomator.UiSelector;
-
-import org.junit.After;
-import org.junit.AfterClass;
-import org.junit.Before;
-import org.junit.BeforeClass;
-import org.junit.Test;
-
-import java.io.IOException;
-
-/**
- * This is a simple smoke test to help finding culprit CLs when using bisect.
- */
-public final class ImeSmokeTest {
-
-    private static final long KEYBOARD_LAUNCH_TIMEOUT = 5_000;
-
-    private static final long SWITCH_TO_HARD_IME_TIMEOUT_SECONDS = 5_000;
-
-    private static final String PLAIN_TEXT_EDIT_RESOURCE_ID =
-            "com.google.android.car.kitchensink:id/plain_text_edit";
-
-    private static final String KITCHEN_SINK_APP =
-            "com.google.android.car.kitchensink";
-
-    // Values of setting key SHOW_IME_WITH_HARD_KEYBOARD settings.
-    private static final int STATE_HIDE_IME = 0;
-    private static final int STATE_SHOW_IME = 1;
-
-    private static Instrumentation sInstrumentation;
-    private static UiDevice sDevice;
-    private static Context sContext;
-    private static ContentResolver sContentResolver;
-    private static int sOriginalShowImeWithHardKeyboard;
-
-    @BeforeClass
-    public static void setUpClass() throws Exception {
-        sInstrumentation = InstrumentationRegistry.getInstrumentation();
-        sDevice = UiDevice.getInstance(sInstrumentation);
-        sContext = sInstrumentation.getContext();
-        sContentResolver = sContext.getContentResolver();
-
-        // Set this test to run on auto only, it was mostly designed to capture configuration
-        // issues on auto keyboards.
-        assumeTrue(sContext.getPackageManager()
-                .hasSystemFeature(PackageManager.FEATURE_AUTOMOTIVE));
-
-        // Ensure that the DUT doesn't have hard keyboard enabled.
-        sOriginalShowImeWithHardKeyboard = Settings.Secure.getInt(sContentResolver,
-                Settings.Secure.SHOW_IME_WITH_HARD_KEYBOARD, /*def=*/STATE_SHOW_IME);
-        if (sOriginalShowImeWithHardKeyboard == STATE_HIDE_IME) {
-            assertThat(Settings.Secure.putInt(
-                    sContentResolver, Settings.Secure.SHOW_IME_WITH_HARD_KEYBOARD,
-                    /*def=*/STATE_SHOW_IME)).isTrue();
-
-            // Give 5 seconds for IME to properly act on the settings change.
-            // TODO(b/301521594): Instead of sleeping, just verify the mShowImeWithHardKeyboard
-            // field from the current IME in IMMS.
-            SystemClock.sleep(SWITCH_TO_HARD_IME_TIMEOUT_SECONDS);
-        }
-    }
-
-    @Before
-    public void setUp() throws IOException {
-        closeKitchenSink();
-    }
-
-    @After
-    public void tearDown() throws IOException {
-        closeKitchenSink();
-    }
-
-    @AfterClass
-    public static void tearDownClass() {
-        // Change back the original value of show_ime_with_hard_keyboard in Settings.
-        if (sOriginalShowImeWithHardKeyboard == STATE_HIDE_IME) {
-            assertThat(Settings.Secure.putInt(
-                    sContentResolver, Settings.Secure.SHOW_IME_WITH_HARD_KEYBOARD,
-                    /*def=*/STATE_HIDE_IME)).isTrue();
-        }
-    }
-
-    private void closeKitchenSink() throws IOException {
-        sDevice.executeShellCommand(String.format("am force-stop %s", KITCHEN_SINK_APP));
-    }
-
-    @Test
-    public void canOpenIME() throws UiObjectNotFoundException {
-        // Open KitchenSink > Carboard
-        Intent intent = sInstrumentation
-                .getContext()
-                .getPackageManager()
-                .getLaunchIntentForPackage(KITCHEN_SINK_APP);
-        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
-        intent.putExtra("select", "carboard");
-        sContext.startActivity(intent);
-
-        UiObject editText = sDevice.findObject((new UiSelector().resourceId(
-                PLAIN_TEXT_EDIT_RESOURCE_ID)));
-        editText.click();
-
-        assertThat(sDevice.wait(isKeyboardOpened(), KEYBOARD_LAUNCH_TIMEOUT)).isTrue();
-    }
-
-    private static Condition<UiDevice, Boolean> isKeyboardOpened() {
-        return unusedDevice -> {
-            for (AccessibilityWindowInfo window : sInstrumentation.getUiAutomation().getWindows()) {
-                if (window.getType() == AccessibilityWindowInfo.TYPE_INPUT_METHOD) {
-                    return true;
-                }
-            }
-            return false;
-        };
-    }
-}
diff --git a/builtInServices/tests/src/com/android/server/wm/MediaTemplateActivityInterceptorForSuspensionTest.java b/builtInServices/tests/src/com/android/server/wm/MediaTemplateActivityInterceptorForSuspensionTest.java
new file mode 100644
index 0000000..3908eaf
--- /dev/null
+++ b/builtInServices/tests/src/com/android/server/wm/MediaTemplateActivityInterceptorForSuspensionTest.java
@@ -0,0 +1,235 @@
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
+package com.android.server.wm;
+
+import static android.car.feature.Flags.FLAG_CAR_MEDIA_APPS_SUSPENSION;
+import static android.car.media.CarMediaIntents.ACTION_MEDIA_TEMPLATE;
+import static android.car.media.CarMediaIntents.EXTRA_MEDIA_COMPONENT;
+
+import static com.android.internal.app.SuspendedAppActivity.EXTRA_DIALOG_INFO;
+import static com.android.internal.app.SuspendedAppActivity.EXTRA_SUSPENDED_PACKAGE;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.when;
+
+import android.app.ActivityOptions;
+import android.content.ComponentName;
+import android.content.Intent;
+import android.content.pm.PackageManagerInternal;
+import android.content.pm.SuspendDialogInfo;
+import android.content.pm.UserPackage;
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.flag.junit.SetFlagsRule;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.server.LocalServices;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@EnableFlags(FLAG_CAR_MEDIA_APPS_SUSPENSION)
+@RunWith(AndroidJUnit4.class)
+public final class MediaTemplateActivityInterceptorForSuspensionTest {
+    @Rule public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
+    private static final int USER_ID = 10;
+    private static final String PACKAGE_NAME = "com.test.package";
+    private static final String PACKAGE_CLASS_NAME = "Test package";
+    private static final String ACTION_MEDIA_TEMPLATE_V2 =
+            "androidx.car.app.mediaextensions.action.MEDIA_TEMPLATE_V2";
+    private static final String ACTION_MEDIA_TEMPLATE_V3 =
+            "androidx.car.app.mediaextensions.action.MEDIA_TEMPLATE_V3";
+
+    private static final String ACTION_MEDIA_TEMPLATE_V3ALPHA =
+            "androidx.car.app.mediaextensions.action.MEDIA_TEMPLATE_V3.5-alpha";
+    private static final String INVALID_PREFIX_ACTION_MEDIA_TEMPLATE =
+            "androidx.car.app.media.action.MEDIA_TEMPLATE_V2";
+    private static final ActivityOptions BASIC_ACTIVITY_OPTIONS = ActivityOptions.makeBasic();
+
+    private final ActivityInterceptorInfoWrapper mMockInfo =
+            mock(ActivityInterceptorInfoWrapper.class);
+    private final UserPackage mMockUserPackage = mock(UserPackage.class);
+    private final SuspendDialogInfo mSuspendDialogInfo = new SuspendDialogInfo.Builder().build();
+
+    private PackageManagerInternal mMockPackageManagerInternal;
+    private MediaTemplateActivityInterceptorForSuspension mInterceptor;
+
+    @Before
+    public void setUp() {
+        LocalServices.removeServiceForTest(PackageManagerInternal.class);
+
+        mMockPackageManagerInternal = mock(PackageManagerInternal.class);
+        LocalServices.addService(PackageManagerInternal.class, mMockPackageManagerInternal);
+        mInterceptor = new MediaTemplateActivityInterceptorForSuspension();
+
+        when(mMockInfo.getUserId()).thenReturn(USER_ID);
+        when(mMockPackageManagerInternal.getSuspendingPackage(anyString(), anyInt()))
+                .thenReturn(mMockUserPackage);
+        when(mMockPackageManagerInternal
+                .getSuspendedDialogInfo(anyString(), eq(mMockUserPackage), anyInt())
+        ).thenReturn(mSuspendDialogInfo);
+    }
+
+    @Test
+    public void mediaInterceptor_whenIntentActionIsEmpty_doesNotIntercept() {
+        Intent intent = new Intent();
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+
+    @Test
+    public void mediaInterceptor_whenMediaComponentExtraIsEmpty_doesNotIntercept() {
+        Intent intent = new Intent(ACTION_MEDIA_TEMPLATE);
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    @Test
+    public void mediaInterceptor_whenIntentActionNotMediaTemplate_doesNotIntercept() {
+        ComponentName componentName = new ComponentName(PACKAGE_NAME, PACKAGE_CLASS_NAME);
+        Intent intent = new Intent(Intent.ACTION_MAIN);
+        intent.putExtra(EXTRA_MEDIA_COMPONENT, componentName.flattenToShortString());
+        when(mMockInfo.getIntent()).thenReturn(intent);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    @Test
+    public void mediaInterceptor_onMediaTemplateIntentAndPackageNotSuspended_doesNotIntercept() {
+        ComponentName componentName = new ComponentName(PACKAGE_NAME, PACKAGE_CLASS_NAME);
+        Intent intent = new Intent(ACTION_MEDIA_TEMPLATE);
+        intent.putExtra(EXTRA_MEDIA_COMPONENT, componentName.flattenToShortString());
+        when(mMockInfo.getIntent()).thenReturn(intent);
+        when(mMockPackageManagerInternal.isPackageSuspended(PACKAGE_NAME, USER_ID))
+                .thenReturn(false);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    @Test
+    public void mediaInterceptor_onMediaTemplateIntentAndMediaPackageSuspended_interceptsLaunch() {
+        ComponentName componentName = new ComponentName(PACKAGE_NAME, PACKAGE_CLASS_NAME);
+        Intent intent = new Intent(ACTION_MEDIA_TEMPLATE);
+        intent.putExtra(EXTRA_MEDIA_COMPONENT, componentName.flattenToShortString());
+        when(mMockInfo.getIntent()).thenReturn(intent);
+        when(mMockPackageManagerInternal.isPackageSuspended(PACKAGE_NAME, USER_ID))
+                .thenReturn(true);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertActivityIntercept(result);
+    }
+
+    @Test
+    public void mediaInterceptor_onMediaTemplateV2IntentAndPackageSuspended_intercepts() {
+        ComponentName componentName = new ComponentName(PACKAGE_NAME, PACKAGE_CLASS_NAME);
+        Intent intent = new Intent(ACTION_MEDIA_TEMPLATE_V2);
+        intent.putExtra(EXTRA_MEDIA_COMPONENT, componentName.flattenToShortString());
+        when(mMockInfo.getIntent()).thenReturn(intent);
+        when(mMockPackageManagerInternal.isPackageSuspended(PACKAGE_NAME, USER_ID))
+                .thenReturn(true);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertActivityIntercept(result);
+    }
+
+    @Test
+    public void mediaInterceptor_onMediaTemplateV3IntentAndPackageSuspended_intercepts() {
+        ComponentName componentName = new ComponentName(PACKAGE_NAME, PACKAGE_CLASS_NAME);
+        Intent intent = new Intent(ACTION_MEDIA_TEMPLATE_V3);
+        intent.putExtra(EXTRA_MEDIA_COMPONENT, componentName.flattenToShortString());
+        when(mMockInfo.getIntent()).thenReturn(intent);
+        when(mMockPackageManagerInternal.isPackageSuspended(PACKAGE_NAME, USER_ID))
+                .thenReturn(true);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertActivityIntercept(result);
+    }
+
+    @Test
+    public void mediaInterceptor_onMediaTemplateV3AlphaIntentAndPackageSuspended_intercepts() {
+        ComponentName componentName = new ComponentName(PACKAGE_NAME, PACKAGE_CLASS_NAME);
+        Intent intent = new Intent(ACTION_MEDIA_TEMPLATE_V3ALPHA);
+        intent.putExtra(EXTRA_MEDIA_COMPONENT, componentName.flattenToShortString());
+        when(mMockInfo.getIntent()).thenReturn(intent);
+        when(mMockPackageManagerInternal.isPackageSuspended(PACKAGE_NAME, USER_ID))
+                .thenReturn(true);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertActivityIntercept(result);
+    }
+
+    @Test
+    public void mediaInterceptor_onInvalidMediaTemplateIntent_doesNotIntercept() {
+        ComponentName componentName = new ComponentName(PACKAGE_NAME, PACKAGE_CLASS_NAME);
+        Intent intent = new Intent(INVALID_PREFIX_ACTION_MEDIA_TEMPLATE);
+        intent.putExtra(EXTRA_MEDIA_COMPONENT, componentName.flattenToShortString());
+        when(mMockInfo.getIntent()).thenReturn(intent);
+        when(mMockPackageManagerInternal.isPackageSuspended(PACKAGE_NAME, USER_ID))
+                .thenReturn(true);
+
+        ActivityInterceptResultWrapper result = mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    private void assertActivityIntercept(ActivityInterceptResultWrapper result) {
+        assertThat(result).isNotNull();
+
+        Intent intent = result.getInterceptResult().getIntent();
+        String suspendedPackageName = intent.getStringExtra(EXTRA_SUSPENDED_PACKAGE);
+        SuspendDialogInfo suspendedDialog = intent.getParcelableExtra(
+                EXTRA_DIALOG_INFO,
+                SuspendDialogInfo.class
+        );
+
+        assertThat(suspendedPackageName).isEqualTo(PACKAGE_NAME);
+        assertThat(suspendedDialog).isEqualTo(mSuspendDialogInfo);
+        // Assert ActivityOptions
+        ActivityOptions activityOptions = result.getInterceptResult().getActivityOptions();
+        assertThat(activityOptions.getPackageName())
+                .isEqualTo(BASIC_ACTIVITY_OPTIONS.getPackageName());
+        assertThat(activityOptions.getLaunchActivityType())
+                .isEqualTo(BASIC_ACTIVITY_OPTIONS.getLaunchActivityType());
+        assertThat(activityOptions.getLaunchDisplayId())
+                .isEqualTo(BASIC_ACTIVITY_OPTIONS.getLaunchDisplayId());
+        assertThat(activityOptions.getCallerDisplayId())
+                .isEqualTo(BASIC_ACTIVITY_OPTIONS.getCallerDisplayId());
+    }
+}
diff --git a/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java b/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
index a6a38da..0c1a8cf 100644
--- a/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
+++ b/updatableServices/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImpl.java
@@ -15,6 +15,7 @@
  */
 package com.android.internal.car.updatable;
 
+import static com.android.car.internal.ExcludeFromCodeCoverageGeneratedReport.DUMP_INFO;
 import static com.android.car.internal.SystemConstants.ICAR_SYSTEM_SERVER_CLIENT;
 import static com.android.car.internal.common.CommonConstants.CAR_SERVICE_INTERFACE;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_SWITCHING;
@@ -26,6 +27,7 @@ import android.car.ICarResultReceiver;
 import android.car.builtin.os.UserManagerHelper;
 import android.car.builtin.util.EventLogHelper;
 import android.car.builtin.util.Slogf;
+import android.car.feature.Flags;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
@@ -41,6 +43,7 @@ import android.os.RemoteException;
 import android.os.SystemProperties;
 import android.os.UserHandle;
 
+import com.android.car.internal.ExcludeFromCodeCoverageGeneratedReport;
 import com.android.car.internal.ICarServiceHelper;
 import com.android.car.internal.ICarSystemServerClient;
 import com.android.car.internal.util.IndentingPrintWriter;
@@ -51,13 +54,13 @@ import com.android.internal.car.CarServiceHelperInterface;
 import com.android.internal.car.CarServiceHelperServiceUpdatable;
 import com.android.server.wm.CarActivityInterceptorInterface;
 import com.android.server.wm.CarActivityInterceptorUpdatableImpl;
-import com.android.server.wm.CarDisplayCompatActivityInterceptor;
 import com.android.server.wm.CarDisplayCompatScaleProviderInterface;
 import com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl;
-import com.android.server.wm.CarLaunchOnPrivateDisplayActivityInterceptor;
 import com.android.server.wm.CarLaunchParamsModifierInterface;
 import com.android.server.wm.CarLaunchParamsModifierUpdatable;
 import com.android.server.wm.CarLaunchParamsModifierUpdatableImpl;
+import com.android.server.wm.CarLaunchRedirectActivityInterceptor;
+import com.android.server.wm.MediaTemplateActivityInterceptorForSuspension;
 
 import java.io.File;
 import java.io.PrintWriter;
@@ -110,8 +113,9 @@ public final class CarServiceHelperServiceUpdatableImpl
 
     private final CarLaunchParamsModifierUpdatableImpl mCarLaunchParamsModifierUpdatable;
     private final CarActivityInterceptorUpdatableImpl mCarActivityInterceptorUpdatable;
-    private final CarDisplayCompatScaleProviderUpdatableImpl
-            mCarDisplayCompatScaleProviderUpdatable;
+    private final CarLaunchRedirectActivityInterceptor
+            mCarLaunchRedirectActivityInterceptor;
+    private CarDisplayCompatScaleProviderUpdatableImpl mCarDisplayCompatScaleProviderUpdatable;
 
     private ExtraDisplayMonitor mExtraDisplayMonitor;
 
@@ -126,9 +130,6 @@ public final class CarServiceHelperServiceUpdatableImpl
         mHandler = new Handler(mHandlerThread.getLooper());
         mCarServiceHelperInterface = (CarServiceHelperInterface) interfaces
                 .get(CarServiceHelperInterface.class.getSimpleName());
-        mCarLaunchParamsModifierUpdatable = new CarLaunchParamsModifierUpdatableImpl(
-                (CarLaunchParamsModifierInterface) interfaces
-                        .get(CarLaunchParamsModifierInterface.class.getSimpleName()));
         mCarActivityInterceptorUpdatable = new CarActivityInterceptorUpdatableImpl(
                 (CarActivityInterceptorInterface) interfaces
                         .get(CarActivityInterceptorInterface.class.getSimpleName()));
@@ -137,12 +138,20 @@ public final class CarServiceHelperServiceUpdatableImpl
                     mContext,
                     (CarDisplayCompatScaleProviderInterface) interfaces
                             .get(CarDisplayCompatScaleProviderInterface.class.getSimpleName()));
-        mCarActivityInterceptorUpdatable.registerInterceptor(0,
-                new CarDisplayCompatActivityInterceptor(context,
-                        mCarDisplayCompatScaleProviderUpdatable));
-        // Interceptor for the launch on a private display
-        mCarActivityInterceptorUpdatable.registerInterceptor(1,
-                new CarLaunchOnPrivateDisplayActivityInterceptor(context));
+        mCarLaunchParamsModifierUpdatable = new CarLaunchParamsModifierUpdatableImpl(
+                (CarLaunchParamsModifierInterface) interfaces.get(
+                        CarLaunchParamsModifierInterface.class.getSimpleName()),
+                mCarDisplayCompatScaleProviderUpdatable);
+        // Interceptor for the launch of suspended media apps
+        mCarActivityInterceptorUpdatable.registerInterceptor(/* index = */ 0,
+                new MediaTemplateActivityInterceptorForSuspension());
+        mCarActivityInterceptorUpdatable.registerInterceptor(/* index = */ 1,
+                mCarDisplayCompatScaleProviderUpdatable);
+        // Interceptor for redirecting launch on a private display or a root task
+        mCarLaunchRedirectActivityInterceptor =
+                new CarLaunchRedirectActivityInterceptor(context);
+        mCarActivityInterceptorUpdatable.registerInterceptor(/* index = */ 2,
+                mCarLaunchRedirectActivityInterceptor);
         // carServiceProxy is Nullable because it is not possible to construct carServiceProxy with
         // "this" object in the previous constructor as CarServiceHelperServiceUpdatableImpl has
         // not been fully constructed.
@@ -311,6 +320,7 @@ public final class CarServiceHelperServiceUpdatableImpl
         }
     }
 
+    @ExcludeFromCodeCoverageGeneratedReport(reason = DUMP_INFO)
     @Override
     public void dump(PrintWriter writer,  String[] args) {
         if (args != null && args.length > 0 && "--user-metrics-only".equals(args[0])) {
@@ -361,6 +371,16 @@ public final class CarServiceHelperServiceUpdatableImpl
                     rootTaskToken);
         }
 
+        @Override
+        public void onRootTaskAppeared(String name, IBinder rootTaskToken) {
+            mCarLaunchRedirectActivityInterceptor.onRootTaskAppeared(name, rootTaskToken);
+        }
+
+        @Override
+        public void onRootTaskVanished(String name) {
+            mCarLaunchRedirectActivityInterceptor.onRootTaskVanished(name);
+        }
+
         @Override
         public void setSafetyMode(boolean safe) {
             mCarServiceHelperInterface.setSafetyMode(safe);
@@ -427,6 +447,21 @@ public final class CarServiceHelperServiceUpdatableImpl
             return mCarDisplayCompatScaleProviderUpdatable.requiresDisplayCompat(packageName,
                     Binder.getCallingUserHandle().getIdentifier());
         }
+
+        @Override
+        public boolean requiresDisplayCompatForUser(String packageName, int userId) {
+            if (Flags.displayCompatibilityCaptionBar()) {
+                return mCarDisplayCompatScaleProviderUpdatable.requiresDisplayCompat(packageName,
+                        userId);
+            }
+            return false;
+        }
+    }
+
+    @VisibleForTesting
+    void setCarDisplayCompatScaleProviderUpdatableImpl(
+            CarDisplayCompatScaleProviderUpdatableImpl carDisplayCompatScaleProviderUpdatableImpl) {
+        mCarDisplayCompatScaleProviderUpdatable = carDisplayCompatScaleProviderUpdatableImpl;
     }
 
     private final class CarServiceConnectedCallback extends ICarResultReceiver.Stub {
diff --git a/updatableServices/src/com/android/internal/car/updatable/CarServiceProxy.java b/updatableServices/src/com/android/internal/car/updatable/CarServiceProxy.java
index c63083e..a0a9896 100644
--- a/updatableServices/src/com/android/internal/car/updatable/CarServiceProxy.java
+++ b/updatableServices/src/com/android/internal/car/updatable/CarServiceProxy.java
@@ -16,6 +16,7 @@
 
 package com.android.internal.car.updatable;
 
+import static com.android.car.internal.ExcludeFromCodeCoverageGeneratedReport.DUMP_INFO;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_CREATED;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_INVISIBLE;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_REMOVED;
@@ -42,6 +43,7 @@ import android.util.Log;
 import android.util.SparseArray;
 import android.util.SparseIntArray;
 
+import com.android.car.internal.ExcludeFromCodeCoverageGeneratedReport;
 import com.android.car.internal.ICarSystemServerClient;
 import com.android.car.internal.common.CommonConstants.UserLifecycleEventType;
 import com.android.car.internal.util.DebugUtils;
@@ -534,6 +536,7 @@ final class CarServiceProxy {
     /**
      * Dump
      */
+    @ExcludeFromCodeCoverageGeneratedReport(reason = DUMP_INFO)
     void dump(IndentingPrintWriter writer) {
         // Do not change the next line, Used in cts test: testCarServiceHelperServiceDump
         writer.println("CarServiceProxy");
@@ -574,6 +577,7 @@ final class CarServiceProxy {
     /**
      * Dump User metrics
      */
+    @ExcludeFromCodeCoverageGeneratedReport(reason = DUMP_INFO)
     void dumpUserMetrics(IndentingPrintWriter writer) {
         mUserMetrics.dump(writer);
     }
diff --git a/updatableServices/src/com/android/internal/car/updatable/UserMetrics.java b/updatableServices/src/com/android/internal/car/updatable/UserMetrics.java
index 31a4bfd..15b159a 100644
--- a/updatableServices/src/com/android/internal/car/updatable/UserMetrics.java
+++ b/updatableServices/src/com/android/internal/car/updatable/UserMetrics.java
@@ -16,6 +16,7 @@
 
 package com.android.internal.car.updatable;
 
+import static com.android.car.internal.ExcludeFromCodeCoverageGeneratedReport.DUMP_INFO;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_STARTING;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_STOPPED;
 import static com.android.car.internal.common.CommonConstants.USER_LIFECYCLE_EVENT_TYPE_STOPPING;
@@ -30,6 +31,7 @@ import android.car.builtin.util.Slogf;
 import android.car.builtin.util.TimeUtils;
 import android.util.SparseArray;
 
+import com.android.car.internal.ExcludeFromCodeCoverageGeneratedReport;
 import com.android.car.internal.common.CommonConstants.UserLifecycleEventType;
 import com.android.car.internal.util.IndentingPrintWriter;
 import com.android.car.internal.util.LocalLog;
@@ -231,6 +233,7 @@ final class UserMetrics {
     /**
      * Dumps its contents.
      */
+    @ExcludeFromCodeCoverageGeneratedReport(reason = DUMP_INFO)
     public void dump(@NonNull IndentingPrintWriter pw) {
         pw.println("* User Metrics *");
         synchronized (mLock) {
@@ -248,6 +251,7 @@ final class UserMetrics {
         }
     }
 
+    @ExcludeFromCodeCoverageGeneratedReport(reason = DUMP_INFO)
     private void dump(@NonNull IndentingPrintWriter pw, @NonNull String message,
             @NonNull SparseArray<? extends BaseUserMetric> metrics) {
         pw.increaseIndent();
diff --git a/updatableServices/src/com/android/server/wm/CarActivityInterceptorUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarActivityInterceptorUpdatableImpl.java
index 0c4d99b..70cd1ce 100644
--- a/updatableServices/src/com/android/server/wm/CarActivityInterceptorUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarActivityInterceptorUpdatableImpl.java
@@ -25,6 +25,7 @@ import android.car.builtin.util.Slogf;
 import android.content.ComponentName;
 import android.os.IBinder;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.util.ArrayMap;
 import android.util.ArraySet;
 import android.util.Log;
@@ -186,6 +187,10 @@ public final class CarActivityInterceptorUpdatableImpl implements CarActivityInt
             return false;
         }
         int userIdFromActivity = activityInterceptorInfoWrapper.getUserId();
+        if (userIdFromActivity == UserHandle.SYSTEM.getIdentifier()) {
+            // System user activity should be allowed to run on any root task
+            return true;
+        }
         int userIdFromRootTask = mBuiltIn.getUserAssignedToDisplay(rootTask
                 .getTaskDisplayArea().getDisplay().getDisplayId());
         if (userIdFromActivity == userIdFromRootTask) {
diff --git a/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java b/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java
deleted file mode 100644
index fe53e15..0000000
--- a/updatableServices/src/com/android/server/wm/CarDisplayCompatActivityInterceptor.java
+++ /dev/null
@@ -1,182 +0,0 @@
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
-package com.android.server.wm;
-
-import static android.content.pm.PackageManager.MATCH_SYSTEM_ONLY;
-import static android.content.pm.PackageManager.PERMISSION_GRANTED;
-import static android.view.Display.DEFAULT_DISPLAY;
-import static android.view.Display.INVALID_DISPLAY;
-
-import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.FEATURE_CAR_DISPLAY_COMPATIBILITY;
-
-import android.annotation.NonNull;
-import android.annotation.Nullable;
-import android.annotation.SystemApi;
-import android.app.ActivityOptions;
-import android.car.builtin.util.Slogf;
-import android.car.feature.Flags;
-import android.content.ComponentName;
-import android.content.Context;
-import android.content.Intent;
-import android.content.pm.PackageManager;
-import android.content.pm.ResolveInfo;
-import android.content.res.Resources;
-import android.os.ServiceSpecificException;
-import android.util.Log;
-
-import com.android.car.internal.dep.Trace;
-import com.android.internal.annotations.VisibleForTesting;
-
-/**
- * This class handles launching the display compat host app.
- *
- * @hide
- */
-@SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
-public final class CarDisplayCompatActivityInterceptor implements CarActivityInterceptorUpdatable {
-
-    public static final String TAG = CarDisplayCompatActivityInterceptor.class.getSimpleName();
-    private static final boolean DBG = Slogf.isLoggable(TAG, Log.DEBUG);
-    private static final ActivityOptionsWrapper EMPTY_LAUNCH_OPTIONS_WRAPPER =
-            ActivityOptionsWrapper.create(ActivityOptions.makeBasic());
-    @VisibleForTesting
-    static final String LAUNCHED_FROM_HOST =
-            "android.car.app.CarDisplayCompatManager.launched_from_host";
-    @VisibleForTesting
-    static final String LAUNCH_ACTIVITY_OPTIONS =
-            "android.car.app.CarDisplayCompatManager.launch_activity_options";
-    @VisibleForTesting
-    static final String PERMISSION_DISPLAY_COMPATIBILITY =
-            "android.car.permission.MANAGE_DISPLAY_COMPATIBILITY";
-    @NonNull
-    private final Context mContext;
-    @NonNull
-    private final CarDisplayCompatScaleProviderUpdatableImpl mDisplayCompatProvider;
-    @Nullable
-    private ComponentName mHostActivity;
-
-    public CarDisplayCompatActivityInterceptor(@NonNull Context context,
-            @NonNull CarDisplayCompatScaleProviderUpdatableImpl carDisplayCompatProvider) {
-        mContext = context;
-        mDisplayCompatProvider = carDisplayCompatProvider;
-        if (!Flags.displayCompatibility()) {
-            Slogf.i(TAG, "Flag %s is not enabled", Flags.FLAG_DISPLAY_COMPATIBILITY);
-            return;
-        }
-        PackageManager packageManager = context.getPackageManager();
-        if (packageManager == null) {
-            // This happens during tests where mock context is used.
-            return;
-        }
-        if (!packageManager.hasSystemFeature(FEATURE_CAR_DISPLAY_COMPATIBILITY)) {
-            Slogf.i(TAG, "Feature %s is not available", FEATURE_CAR_DISPLAY_COMPATIBILITY);
-            return;
-        }
-        Resources r = context.getResources();
-        if (r == null) {
-            // This happens during tests where mock context is used.
-            Slogf.e(TAG, "Couldn't read DisplayCompat host activity.");
-            return;
-        }
-        int id = r.getIdentifier("config_defaultDisplayCompatHostActivity", "string", "android");
-        if (id != 0) {
-            mHostActivity = ComponentName.unflattenFromString(r.getString(id));
-            if (mHostActivity == null) {
-                Slogf.e(TAG, "Couldn't read DisplayCompat host activity.");
-                return;
-            }
-            Intent intent = new Intent();
-            intent.setComponent(mHostActivity);
-            ResolveInfo ri = packageManager.resolveActivity(intent,
-                    PackageManager.ResolveInfoFlags.of(MATCH_SYSTEM_ONLY));
-            if (ri == null) {
-                Slogf.e(TAG, "Couldn't resolve DisplayCompat host activity. %s", mHostActivity);
-                mHostActivity = null;
-                return;
-            }
-        }
-    }
-
-    @Override
-    public ActivityInterceptResultWrapper onInterceptActivityLaunch(
-            ActivityInterceptorInfoWrapper info) {
-        if (mHostActivity == null) {
-            return null;
-        }
-        Intent launchIntent = info.getIntent();
-        if (launchIntent == null || launchIntent.getComponent() == null) {
-            return null;
-        }
-        try {
-            Trace.beginSection(
-                    "CarDisplayActivity-onInterceptActivityLaunchIntentComponent: "
-                            + launchIntent.getComponent());
-            boolean requiresDisplayCompat = mDisplayCompatProvider
-                    .requiresDisplayCompat(launchIntent.getComponent().getPackageName(),
-                            info.getUserId());
-            if (!requiresDisplayCompat) {
-                return null;
-            }
-
-            boolean isLaunchedFromHost = launchIntent
-                    .getBooleanExtra(LAUNCHED_FROM_HOST, false);
-            int callingPid = info.getCallingPid();
-            int callingUid = info.getCallingUid();
-            boolean hasPermission = (mContext.checkPermission(
-                    PERMISSION_DISPLAY_COMPATIBILITY, callingPid, callingUid)
-                            == PERMISSION_GRANTED);
-            if (isLaunchedFromHost && !hasPermission) {
-                Slogf.e(TAG, "Calling package (%s) doesn't have required permissions %s",
-                        info.getCallingPackage(),
-                        PERMISSION_DISPLAY_COMPATIBILITY);
-                // fall-through, we'll launch the host instead.
-            }
-
-            mDisplayCompatProvider.onInterceptActivityLaunch(info);
-
-            ActivityOptionsWrapper launchOptions = info.getCheckedOptions();
-            if (launchOptions == null) {
-                launchOptions = EMPTY_LAUNCH_OPTIONS_WRAPPER;
-            }
-            if (!isLaunchedFromHost || (isLaunchedFromHost && !hasPermission)) {
-                // Launch the host
-                Intent intent = new Intent();
-                intent.setComponent(mHostActivity);
-
-                intent.putExtra(Intent.EXTRA_INTENT, launchIntent);
-                intent.putExtra(LAUNCH_ACTIVITY_OPTIONS, launchOptions.getOptions().toBundle());
-
-                // Launch host on the display that the app was supposed to be launched.
-                ActivityOptionsWrapper optionsWrapper =
-                        ActivityOptionsWrapper.create(ActivityOptions.makeBasic());
-                int launchDisplayId = launchOptions.getOptions().getLaunchDisplayId();
-                int hostDisplayId = (launchDisplayId == INVALID_DISPLAY)
-                        ? DEFAULT_DISPLAY : launchDisplayId;
-                if (DBG) {
-                    Slogf.d(TAG, "DisplayCompat host displayId %d LaunchDisplayId %d",
-                            hostDisplayId, launchDisplayId);
-                }
-                optionsWrapper.setLaunchDisplayId(hostDisplayId);
-                return ActivityInterceptResultWrapper.create(intent, optionsWrapper.getOptions());
-            }
-        } catch (ServiceSpecificException e) {
-            Slogf.e(TAG, "Error while intercepting activity " + launchIntent.getComponent(), e);
-        } finally {
-            Trace.endSection();
-        }
-        return null;
-    }
-}
diff --git a/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
index 98dec3d..6c96046 100644
--- a/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarDisplayCompatScaleProviderUpdatableImpl.java
@@ -277,18 +277,19 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         float compatModeScalingFactor = mCarCompatScaleProviderInterface
                 .getCompatModeScalingFactor(packageName, UserHandle.of(userId));
         if (compatModeScalingFactor == DEFAULT_SCALE) {
-            Slogf.i(TAG, "Returning CompatScale " + compatScale + " for package " + packageName);
+            Slogf.i(TAG, "Returning CompatScale %s for package %s", compatScale, packageName);
             return compatScale;
         }
         // This shouldn't happen outside of CTS, because CompatModeChanges has higher
         // priority and will already return a scale.
         // See {@code com.android.server.wm.CompatModePackage#getCompatScale} for details.
-        if(compatScale != null) {
-            CompatScaleWrapper res = new CompatScaleWrapper(DEFAULT_SCALE,
-                    (1f / compatModeScalingFactor) * compatScale.getDensityScaleFactor());
+        if (compatScale != null) {
+            CompatScaleWrapper res = new CompatScaleWrapper(compatModeScalingFactor,
+                    compatModeScalingFactor * compatScale.getDensityScaleFactor());
+            Slogf.i(TAG, "Returning CompatScale %s for package %s", res, packageName);
             return res;
         }
-        Slogf.i(TAG, "Returning CompatScale " + compatScale + " for package " + packageName);
+        Slogf.i(TAG, "Returning CompatScale %s for package %s", compatScale, packageName);
         return compatScale;
     }
 
@@ -514,7 +515,7 @@ public class CarDisplayCompatScaleProviderUpdatableImpl implements
         }
 
         PackageInfoFlags pkgFlags = PackageInfoFlags
-                .of(GET_CONFIGURATIONS | GET_ACTIVITIES);
+                .of(GET_CONFIGURATIONS | GET_ACTIVITIES | GET_META_DATA);
         PackageInfo pkgInfo = mCarCompatScaleProviderInterface
                 .getPackageInfoAsUser(packageName, pkgFlags, userId);
 
diff --git a/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java b/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
index ed72b3b..52b603a 100644
--- a/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
+++ b/updatableServices/src/com/android/server/wm/CarLaunchParamsModifierUpdatableImpl.java
@@ -16,6 +16,7 @@
 
 package com.android.server.wm;
 
+import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.annotation.SystemApi;
 import android.annotation.UserIdInt;
@@ -55,6 +56,8 @@ public final class CarLaunchParamsModifierUpdatableImpl
     private static final int USER_NULL = -10000;
 
     private final CarLaunchParamsModifierInterface mBuiltin;
+    @NonNull
+    private final CarDisplayCompatScaleProviderUpdatableImpl mDisplayCompatProvider;
     private final Object mLock = new Object();
 
     // Always start with USER_SYSTEM as the timing of handleCurrentUserSwitching(USER_SYSTEM) is not
@@ -84,8 +87,15 @@ public final class CarLaunchParamsModifierUpdatableImpl
     private final ArrayMap<ComponentName, TaskDisplayAreaWrapper> mPersistentActivities =
             new ArrayMap<>();
 
-    public CarLaunchParamsModifierUpdatableImpl(CarLaunchParamsModifierInterface builtin) {
+    public CarLaunchParamsModifierUpdatableImpl(CarLaunchParamsModifierInterface builtin,
+            @NonNull CarDisplayCompatScaleProviderUpdatableImpl carDisplayCompatProvider) {
         mBuiltin = builtin;
+        mDisplayCompatProvider = carDisplayCompatProvider;
+    }
+
+    private boolean requiresDisplayCompat(ComponentName launchIntent, int userId) {
+        return mDisplayCompatProvider
+                .requiresDisplayCompat(launchIntent.getPackageName(), userId);
     }
 
     public DisplayManager.DisplayListener getDisplayListener() {
@@ -390,14 +400,33 @@ public final class CarLaunchParamsModifierUpdatableImpl
                     != ActivityOptionsWrapper.WINDOWING_MODE_UNDEFINED) {
                 outParams.setWindowingMode(options.getLaunchWindowingMode());
             }
+            if (needsSafeRegionBounds(activity)) {
+                outParams.setNeedsSafeRegionBounds(true);
+            }
             Trace.endSection();
             return LaunchParamsWrapper.RESULT_DONE;
+        } else if (needsSafeRegionBounds(activity)) {
+            outParams.setNeedsSafeRegionBounds(true);
+            Trace.endSection();
+            return LaunchParamsWrapper.RESULT_CONTINUE;
         } else {
             Trace.endSection();
             return LaunchParamsWrapper.RESULT_SKIP;
         }
     }
 
+    private boolean needsSafeRegionBounds(ActivityRecordWrapper activity) {
+        if (activity != null && activity.getComponentName() != null
+                && requiresDisplayCompat(activity.getComponentName(), activity.getUserId())) {
+            if (DBG) {
+                Slogf.d(TAG, "Activity:%s needs to be within a safe region",
+                        activity.getComponentName());
+            }
+            return true;
+        }
+        return false;
+    }
+
     @GuardedBy("mLock")
     private int getUserForDisplayLocked(int displayId) {
         int userForDisplay = mDisplayToProfileUserMapping.get(displayId,
diff --git a/updatableServices/src/com/android/server/wm/CarLaunchOnPrivateDisplayActivityInterceptor.java b/updatableServices/src/com/android/server/wm/CarLaunchRedirectActivityInterceptor.java
similarity index 60%
rename from updatableServices/src/com/android/server/wm/CarLaunchOnPrivateDisplayActivityInterceptor.java
rename to updatableServices/src/com/android/server/wm/CarLaunchRedirectActivityInterceptor.java
index 1828815..2803be8 100644
--- a/updatableServices/src/com/android/server/wm/CarLaunchOnPrivateDisplayActivityInterceptor.java
+++ b/updatableServices/src/com/android/server/wm/CarLaunchRedirectActivityInterceptor.java
@@ -32,9 +32,15 @@ import android.content.pm.PackageManager;
 import android.content.pm.ResolveInfo;
 import android.content.res.Resources;
 import android.hardware.display.DisplayManager;
+import android.os.IBinder;
+import android.os.RemoteException;
+import android.util.ArrayMap;
+import android.util.ArraySet;
 import android.util.Log;
 import android.view.Display;
 
+import com.android.car.internal.dep.Trace;
+import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
 
 import java.util.HashSet;
@@ -42,29 +48,32 @@ import java.util.Objects;
 import java.util.Set;
 
 /**
- * This class handles launching the application on a private display.
+ * This class handles launching the application on a private display or a root task.
  *
  * @hide
  */
 @SystemApi(client = SystemApi.Client.MODULE_LIBRARIES)
-public final class CarLaunchOnPrivateDisplayActivityInterceptor implements
+public final class CarLaunchRedirectActivityInterceptor implements
         CarActivityInterceptorUpdatable {
+    // TODO(b/402624224): Enforce checks for multi user policy
     public static final String TAG =
-            CarLaunchOnPrivateDisplayActivityInterceptor.class.getSimpleName();
+            CarLaunchRedirectActivityInterceptor.class.getSimpleName();
     private static final boolean DBG = Slogf.isLoggable(TAG, Log.DEBUG);
     private static final int INVALID_DISPLAY = -1;
     private static final ActivityOptionsWrapper EMPTY_LAUNCH_OPTIONS_WRAPPER =
             ActivityOptionsWrapper.create(ActivityOptions.makeBasic());
-    private static final String NAMESPACE_KEY = "com.android.car.app.private_display";
+    private static final String NAMESPACE_KEY = "com.android.car.app.launch_redirect";
 
     @VisibleForTesting
     static final String PERMISSION_ACCESS_PRIVATE_DISPLAY_ID =
             "android.car.permission.ACCESS_PRIVATE_DISPLAY_ID";
     /**
-     * This key is defined by the applications that want to launch on the private display.
+     * This key is defined by the applications that want to launch on a root task or a private
+     * display.
      */
     @VisibleForTesting
-    static final String LAUNCH_ON_PRIVATE_DISPLAY = NAMESPACE_KEY + ".launch_on_private_display";
+    static final String LAUNCH_REDIRECT_ON_CONTAINER =
+            NAMESPACE_KEY + ".launch_redirect_on_container";
     @VisibleForTesting
     static final String LAUNCH_ACTIVITY = NAMESPACE_KEY + ".launch_activity";
     @VisibleForTesting
@@ -72,6 +81,12 @@ public final class CarLaunchOnPrivateDisplayActivityInterceptor implements
     @VisibleForTesting
     static final String LAUNCH_ACTIVITY_DISPLAY_ID = NAMESPACE_KEY + ".launch_activity_display_id";
 
+    private final Object mLock = new Object();
+    // K: Root task name, V: Root task token
+    @GuardedBy("mLock")
+    private final ArrayMap<String, IBinder> mRootTaskNameToRootTaskMap = new ArrayMap<>();
+    @GuardedBy("mLock")
+    private final Set<IBinder> mKnownRootTasks = new ArraySet<>();
     @NonNull
     private final Context mContext;
     private final DisplayManager mDisplayManager;
@@ -83,12 +98,12 @@ public final class CarLaunchOnPrivateDisplayActivityInterceptor implements
     @Nullable
     private final ComponentName mRouterActivity;
     /**
-     * Contains the names of the packages which are allowlisted to open on the private display.
+     * Contains the names of the packages which are allowlisted to have launches redirected.
      */
     @Nullable
     private final Set<String> mAllowlist;
 
-    public CarLaunchOnPrivateDisplayActivityInterceptor(@NonNull Context context) {
+    public CarLaunchRedirectActivityInterceptor(@NonNull Context context) {
         mContext = context;
         mDisplayManager = context.getSystemService(DisplayManager.class);
         PackageManager packageManager = context.getPackageManager();
@@ -103,7 +118,8 @@ public final class CarLaunchOnPrivateDisplayActivityInterceptor implements
             mRouterActivity = null;
             mAllowlist = null;
             // This happens during tests where mock context is used.
-            Slogf.e(TAG, "Couldn't read LaunchOnPrivateDisplay router activity.");
+            Slogf.e(TAG,
+                    "Couldn't update allowlist or read LaunchOnPrivateDisplay router activity.");
             return;
         }
         mAllowlist = readAllowlistFromConfig(r);
@@ -122,16 +138,7 @@ public final class CarLaunchOnPrivateDisplayActivityInterceptor implements
             return null;
         }
         if (launchIntent.getExtras() == null || !launchIntent.getExtras().containsKey(
-                LAUNCH_ON_PRIVATE_DISPLAY)) {
-            return null;
-        }
-        int callingPid = info.getCallingPid();
-        int callingUid = info.getCallingUid();
-        boolean hasPermission = (mContext.checkPermission(PERMISSION_ACCESS_PRIVATE_DISPLAY_ID,
-                callingPid, callingUid) == PERMISSION_GRANTED);
-        if (!hasPermission) {
-            Slogf.e(TAG, "Calling package (%s) doesn't have required permissions %s",
-                    info.getCallingPackage(), PERMISSION_ACCESS_PRIVATE_DISPLAY_ID);
+                LAUNCH_REDIRECT_ON_CONTAINER)) {
             return null;
         }
         if (!isAllowlistedApplication(launchIntent.getComponent().getPackageName())) {
@@ -148,12 +155,27 @@ public final class CarLaunchOnPrivateDisplayActivityInterceptor implements
         if (launchOptions == null) {
             launchOptions = EMPTY_LAUNCH_OPTIONS_WRAPPER;
         }
+        String containerName = launchIntent.getExtras().getString(LAUNCH_REDIRECT_ON_CONTAINER);
+        IBinder rootTaskToken = getLaunchRootTaskToken(containerName);
+        if (rootTaskToken != null) {
+            if (DBG) {
+                Slogf.d(TAG, "Launch activity %s on root task %s", launchIntent.getComponent(),
+                        containerName);
+            }
+            launchOptions.setLaunchRootTask(rootTaskToken);
+            return ActivityInterceptResultWrapper.create(launchIntent, launchOptions.getOptions());
+        }
+        // Fall through to launch activity on a private display since root task not found
+
+        // Check access private display id permission for a launch redirect on a private display
+        if (!ensureAccessPrivateDisplayIdPermission(info)) {
+            return null;
+        }
         // Launch the router activity
         Intent intent = new Intent();
         intent.setComponent(mRouterActivity);
 
-        String uniqueDisplayName = launchIntent.getExtras().getString(LAUNCH_ON_PRIVATE_DISPLAY);
-        int launchDisplayId = getLogicalDisplayId(uniqueDisplayName);
+        int launchDisplayId = getLogicalDisplayId(containerName);
         if (DBG) {
             Slogf.d(TAG, "Launch activity %s on %d", launchIntent.getComponent(), launchDisplayId);
         }
@@ -161,7 +183,7 @@ public final class CarLaunchOnPrivateDisplayActivityInterceptor implements
             return null;
         }
 
-        launchIntent.removeExtra(LAUNCH_ON_PRIVATE_DISPLAY);
+        launchIntent.removeExtra(LAUNCH_REDIRECT_ON_CONTAINER);
         intent.putExtra(LAUNCH_ACTIVITY, launchIntent);
         if (launchOptions.getOptions() != null) {
             intent.putExtra(LAUNCH_ACTIVITY_OPTIONS, launchOptions.getOptions().toBundle());
@@ -171,6 +193,112 @@ public final class CarLaunchOnPrivateDisplayActivityInterceptor implements
         return ActivityInterceptResultWrapper.create(intent, launchOptions.getOptions());
     }
 
+    /**
+     * Retrieves the root task token associated with the specified container name.
+     *
+     * <p>This method searches for a root task associated with the given {@code containerName}.
+     * If a matching root task is found, its token is returned.
+     *
+     * <p>If no root task is found with the provided {@code containerName}, this method returns
+     * {@code null}. A {@code null} return value indicates that no root task exists with the
+     * specified container name.
+     */
+    private IBinder getLaunchRootTaskToken(String containerName) {
+        synchronized (mLock) {
+            int keyIndex = mRootTaskNameToRootTaskMap.indexOfKey(containerName);
+            if (keyIndex >= 0) {
+                return mRootTaskNameToRootTaskMap.valueAt(keyIndex);
+            }
+            return null;
+        }
+    }
+
+    private boolean ensureAccessPrivateDisplayIdPermission(ActivityInterceptorInfoWrapper info) {
+        int callingPid = info.getCallingPid();
+        int callingUid = info.getCallingUid();
+        boolean hasPermission = (mContext.checkPermission(PERMISSION_ACCESS_PRIVATE_DISPLAY_ID,
+                callingPid, callingUid) == PERMISSION_GRANTED);
+        if (!hasPermission) {
+            Slogf.e(TAG, "Calling package (%s) doesn't have required permissions %s",
+                    info.getCallingPackage(), PERMISSION_ACCESS_PRIVATE_DISPLAY_ID);
+            return false;
+        }
+        return true;
+    }
+
+    /**
+     * Updates {@code mRootTaskNameToRootTaskMap} with root task information that appeared.
+     *
+     * @param name          name of the root task.
+     * @param rootTaskToken the binder token of the root task which appeared.
+     */
+    public void onRootTaskAppeared(String name, IBinder rootTaskToken) {
+        try {
+            beginTraceSection(
+                    "CarLaunchRedirectActivityInterceptor-onRootTaskAppeared: " + rootTaskToken);
+            synchronized (mLock) {
+                if (rootTaskToken == null) {
+                    Slogf.d(TAG, "The root task token is null.");
+                    return;
+                }
+                mRootTaskNameToRootTaskMap.put(name, rootTaskToken);
+                updateRootTaskInformationInKnownRootTasks(rootTaskToken);
+            }
+        } finally {
+            Trace.endSection();
+        }
+    }
+
+    /**
+     * Updates {@code mRootTaskNameToRootTaskMap} with root task information that vanished.
+     *
+     * @param name name of the root task which vanished.
+     */
+    public void onRootTaskVanished(String name) {
+        try {
+            beginTraceSection("CarLaunchRedirectActivityInterceptor-onRootTaskVanished: " + name);
+            synchronized (mLock) {
+                if (name.isEmpty()) {
+                    Slogf.d(TAG, "The name of the root task is empty.");
+                    return;
+                }
+                IBinder rootTaskToken = mRootTaskNameToRootTaskMap.get(name);
+                mRootTaskNameToRootTaskMap.remove(name);
+                mKnownRootTasks.remove(rootTaskToken);
+            }
+        } finally {
+            Trace.endSection();
+        }
+    }
+
+    @GuardedBy("mLock")
+    private void updateRootTaskInformationInKnownRootTasks(IBinder rootTaskToken) {
+        if (!mKnownRootTasks.contains(rootTaskToken)) {
+            // Seeing the token for the first time, set the listener
+            removeRootTaskTokenOnDeath(rootTaskToken);
+            mKnownRootTasks.add(rootTaskToken);
+        }
+    }
+
+    private void removeRootTaskTokenOnDeath(IBinder rootTaskToken) {
+        try {
+            rootTaskToken.linkToDeath(() -> removeRootTaskToken(rootTaskToken), /* flags= */ 0);
+        } catch (RemoteException e) {
+            throw new RuntimeException(e);
+        }
+    }
+
+    private void removeRootTaskToken(IBinder rootTaskToken) {
+        synchronized (mLock) {
+            mKnownRootTasks.remove(rootTaskToken);
+        }
+    }
+
+    private void beginTraceSection(String sectionName) {
+        // Traces can only have max 127 characters
+        Trace.beginSection(sectionName.substring(0, Math.min(sectionName.length(), 127)));
+    }
+
     private boolean isAllowlistedApplication(String packageName) {
         if (mAllowlist == null) {
             return false;
diff --git a/updatableServices/tests/Android.bp b/updatableServices/tests/Android.bp
index f4ee8e2..af14ea5 100644
--- a/updatableServices/tests/Android.bp
+++ b/updatableServices/tests/Android.bp
@@ -41,6 +41,7 @@ android_test {
         "services.core",
         "testng",
         "truth",
+        "wmtests-support",
     ],
 
     // mockito-target-extended dependencies
diff --git a/updatableServices/tests/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImplTest.java b/updatableServices/tests/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImplTest.java
index a9a0291..66c33d4 100644
--- a/updatableServices/tests/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImplTest.java
+++ b/updatableServices/tests/src/com/android/internal/car/updatable/CarServiceHelperServiceUpdatableImplTest.java
@@ -20,6 +20,7 @@ import static com.android.car.internal.common.CommonConstants.CAR_SERVICE_INTERF
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.verify;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.when;
 
+import static com.google.common.truth.Truth.assertThat;
 import static com.google.common.truth.Truth.assertWithMessage;
 
 import static org.mockito.ArgumentMatchers.any;
@@ -29,12 +30,15 @@ import static org.mockito.Mockito.doThrow;
 
 import android.car.ICar;
 import android.car.builtin.os.UserManagerHelper;
+import android.car.feature.Flags;
 import android.car.test.mocks.AbstractExtendedMockitoTestCase;
 import android.content.Context;
 import android.os.Bundle;
 import android.os.IBinder;
 import android.os.RemoteException;
 import android.os.UserHandle;
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.flag.junit.SetFlagsRule;
 import android.util.ArrayMap;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
@@ -42,9 +46,11 @@ import androidx.test.ext.junit.runners.AndroidJUnit4;
 import com.android.internal.car.CarServiceHelperInterface;
 import com.android.server.wm.CarActivityInterceptorInterface;
 import com.android.server.wm.CarDisplayCompatScaleProviderInterface;
+import com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl;
 import com.android.server.wm.CarLaunchParamsModifierInterface;
 
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
@@ -79,6 +85,10 @@ public final class CarServiceHelperServiceUpdatableImplTest
     private ICar mICarBinder;
     @Mock
     private IBinder mIBinder;
+    @Mock
+    private CarDisplayCompatScaleProviderUpdatableImpl mCarDisplayCompatScaleProviderUpdatableImpl;
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
 
     private CarServiceHelperServiceUpdatableImpl mCarServiceHelperServiceUpdatableImpl;
 
@@ -238,6 +248,39 @@ public final class CarServiceHelperServiceUpdatableImplTest
         verify(mCarServiceHelperInterface).unassignUserFromExtraDisplay(userId, displayId);
     }
 
+    @EnableFlags(Flags.FLAG_DISPLAY_COMPATIBILITY_CAPTION_BAR)
+    @Test
+    public void requiresDisplayCompatForUser_returnsTrue() {
+        int userId = 42;
+        String pkgName = "com.test.packagename";
+        mCarServiceHelperServiceUpdatableImpl.setCarDisplayCompatScaleProviderUpdatableImpl(
+                mCarDisplayCompatScaleProviderUpdatableImpl);
+        when(mCarDisplayCompatScaleProviderUpdatableImpl
+                .requiresDisplayCompat(eq(pkgName), eq(userId))).thenReturn(true);
+
+        boolean result = mCarServiceHelperServiceUpdatableImpl.mHelper
+                .requiresDisplayCompatForUser(pkgName, userId);
+
+        assertThat(result).isEqualTo(true);
+    }
+
+    @EnableFlags(Flags.FLAG_DISPLAY_COMPATIBILITY_CAPTION_BAR)
+    @Test
+    public void requiresDisplayCompatForUser_returnsFalse() {
+        int userId = 42;
+        String pkgName = "com.test.packagename";
+        mCarServiceHelperServiceUpdatableImpl.setCarDisplayCompatScaleProviderUpdatableImpl(
+                mCarDisplayCompatScaleProviderUpdatableImpl);
+        when(mCarDisplayCompatScaleProviderUpdatableImpl
+                .requiresDisplayCompat(eq(pkgName), eq(userId))).thenReturn(false);
+
+        boolean result = mCarServiceHelperServiceUpdatableImpl.mHelper
+                .requiresDisplayCompatForUser(pkgName, userId);
+
+        assertThat(result).isEqualTo(false);
+    }
+
+
     private void mockICarBinder() {
         when(ICar.Stub.asInterface(mIBinder)).thenReturn(mICarBinder);
     }
diff --git a/updatableServices/tests/src/com/android/server/wm/CarActivityInterceptorUpdatableTest.java b/updatableServices/tests/src/com/android/server/wm/CarActivityInterceptorUpdatableTest.java
index fa57476..20165fb 100644
--- a/updatableServices/tests/src/com/android/server/wm/CarActivityInterceptorUpdatableTest.java
+++ b/updatableServices/tests/src/com/android/server/wm/CarActivityInterceptorUpdatableTest.java
@@ -33,6 +33,7 @@ import android.content.ComponentName;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
 import android.content.pm.ResolveInfo;
+import android.os.UserHandle;
 import android.view.Display;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
@@ -285,6 +286,27 @@ public class CarActivityInterceptorUpdatableTest {
         assertThat(result).isNull();
     }
 
+    @Test
+    public void interceptActivityLaunch_persistedActivity_systemUser_setsLaunchRootTask() {
+        List<ComponentName> activities = List.of(
+                ComponentName.unflattenFromString("com.example.app/com.example.app.MainActivity"),
+                ComponentName.unflattenFromString("com.example.app2/com.example.app2.MainActivity")
+        );
+        mInterceptor.setPersistentActivityOnRootTask(activities, mRootTaskToken1);
+        ActivityInterceptorInfoWrapper info =
+                createActivityInterceptorInfoWithMainIntent(activities.get(0).getPackageName(),
+                        activities.get(0).getClassName(),
+                        /* userId= */ UserHandle.SYSTEM.getIdentifier());
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(info);
+
+        assertThat(result).isNotNull();
+        assertThat(result.getInterceptResult().getActivityOptions().getLaunchRootTask())
+                .isEqualTo(WindowContainer.fromBinder(mRootTaskToken1)
+                        .mRemoteToken.toWindowContainerToken());
+    }
+
     @Test
     public void setPersistentActivity_nullLaunchRootTask_removesAssociation() {
         List<ComponentName> activities1 = List.of(
diff --git a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatActivityInterceptorTest.java b/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatActivityInterceptorTest.java
deleted file mode 100644
index b3dd895..0000000
--- a/updatableServices/tests/src/com/android/server/wm/CarDisplayCompatActivityInterceptorTest.java
+++ /dev/null
@@ -1,290 +0,0 @@
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
-package com.android.server.wm;
-
-import static android.car.feature.Flags.FLAG_DISPLAY_COMPATIBILITY;
-import static android.content.pm.PackageManager.PERMISSION_DENIED;
-import static android.content.pm.PackageManager.PERMISSION_GRANTED;
-import static android.view.Display.DEFAULT_DISPLAY;
-import static android.view.Display.INVALID_DISPLAY;
-
-import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
-import static com.android.server.wm.CarDisplayCompatActivityInterceptor.LAUNCHED_FROM_HOST;
-import static com.android.server.wm.CarDisplayCompatActivityInterceptor.PERMISSION_DISPLAY_COMPATIBILITY;
-import static com.android.server.wm.CarDisplayCompatScaleProviderUpdatableImpl.FEATURE_CAR_DISPLAY_COMPATIBILITY;
-
-import static com.google.common.truth.Truth.assertThat;
-
-import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.when;
-
-import android.app.ActivityOptions;
-import android.content.ComponentName;
-import android.content.Context;
-import android.content.Intent;
-import android.content.pm.PackageManager;
-import android.content.pm.PackageManager.ResolveInfoFlags;
-import android.content.pm.ResolveInfo;
-import android.content.res.Resources;
-import android.platform.test.annotations.RequiresFlagsEnabled;
-import android.platform.test.flag.junit.CheckFlagsRule;
-import android.platform.test.flag.junit.DeviceFlagsValueProvider;
-
-import androidx.test.ext.junit.runners.AndroidJUnit4;
-
-import org.junit.After;
-import org.junit.Before;
-import org.junit.Rule;
-import org.junit.Test;
-import org.junit.runner.RunWith;
-import org.mockito.Mock;
-import org.mockito.MockitoSession;
-import org.mockito.quality.Strictness;
-
-@RequiresFlagsEnabled(FLAG_DISPLAY_COMPATIBILITY)
-@RunWith(AndroidJUnit4.class)
-public class CarDisplayCompatActivityInterceptorTest {
-
-    @Rule
-    public final CheckFlagsRule checkFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
-
-    private MockitoSession mMockingSession;
-
-    @Mock
-    private Resources mMockResources;
-    @Mock
-    private Context mMockContext;
-    @Mock
-    private PackageManager mMockPackageManager;
-    @Mock
-    private CarDisplayCompatScaleProviderUpdatableImpl mMockCarDisplayCompatScaleProvider;
-    @Mock
-    private ActivityInterceptorInfoWrapper mMockInfo;
-
-
-    private CarDisplayCompatActivityInterceptor mInterceptor;
-    private ComponentName mHostActitivy = ComponentName.unflattenFromString(
-            "com.displaycompathost/.StartActivity");
-
-    @Before
-    public void setUp() {
-        mMockingSession = mockitoSession()
-            .initMocks(this)
-            .strictness(Strictness.LENIENT)
-            .startMocking();
-
-        when(mMockResources.getIdentifier(
-                eq("config_defaultDisplayCompatHostActivity"), eq("string"), eq("android")
-        )).thenReturn(1);
-        when(mMockResources.getString(eq(1))).thenReturn(mHostActitivy.flattenToString());
-        when(mMockContext.getResources()).thenReturn(mMockResources);
-        when(mMockPackageManager.hasSystemFeature(FEATURE_CAR_DISPLAY_COMPATIBILITY))
-                .thenReturn(true);
-        when(mMockPackageManager.resolveActivity(any(Intent.class), any(ResolveInfoFlags.class)))
-                .thenReturn(mock(ResolveInfo.class));
-        when(mMockContext.getPackageManager()).thenReturn(mMockPackageManager);
-
-        mInterceptor = new CarDisplayCompatActivityInterceptor(mMockContext,
-                mMockCarDisplayCompatScaleProvider);
-    }
-
-    @After
-    public void tearDown() {
-        // If the exception is thrown during the MockingSession setUp, mMockingSession can be null.
-        if (mMockingSession != null) {
-            mMockingSession.finishMocking();
-        }
-    }
-
-    @Test
-    public void hostActivity_isIgnored() {
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setComponent(mHostActitivy);
-
-        when(mMockInfo.getIntent()).thenReturn(intent);
-
-        ActivityInterceptResultWrapper result =
-                mInterceptor.onInterceptActivityLaunch(mMockInfo);
-
-        assertThat(result).isNull();
-    }
-
-    @Test
-    public void nonDisplayCompatActivity_isIgnored() {
-        Intent intent = getNoDisplayCompatRequiredActivity();
-        when(mMockInfo.getIntent()).thenReturn(intent);
-
-        ActivityInterceptResultWrapper result =
-                mInterceptor.onInterceptActivityLaunch(mMockInfo);
-
-        assertThat(result).isNull();
-    }
-
-    @Test
-    public void displayCompatActivity_launchedFromHost_isIgnored() {
-        Intent intent = getDisplayCompatRequiredActivity();
-        String packageName = intent.getComponent().getPackageName();
-        intent.putExtra(LAUNCHED_FROM_HOST, true);
-        when(mMockInfo.getIntent()).thenReturn(intent);
-
-        when(mMockInfo.getCallingPackage()).thenReturn(packageName);
-        when(mMockInfo.getCallingPid()).thenReturn(1);
-        when(mMockInfo.getCallingUid()).thenReturn(2);
-        when(mMockContext.checkPermission(PERMISSION_DISPLAY_COMPATIBILITY, 1, 2))
-                .thenReturn(PERMISSION_GRANTED);
-
-        ActivityInterceptResultWrapper result =
-                mInterceptor.onInterceptActivityLaunch(mMockInfo);
-
-        assertThat(result).isNull();
-    }
-
-    @Test
-    public void displayCompatActivity_returnsHost() {
-        Intent intent = getDisplayCompatRequiredActivity();
-        when(mMockInfo.getIntent()).thenReturn(intent);
-
-        ActivityInterceptResultWrapper result =
-                mInterceptor.onInterceptActivityLaunch(mMockInfo);
-
-        assertThat(result).isNotNull();
-        assertThat(result.getInterceptResult()).isNotNull();
-        assertThat(result.getInterceptResult().getIntent()).isNotNull();
-        assertThat(result.getInterceptResult().getIntent().getComponent()).isEqualTo(mHostActitivy);
-        Intent launchIntent = (Intent) result.getInterceptResult().getIntent()
-                .getExtra(Intent.EXTRA_INTENT);
-        assertThat(launchIntent).isNotNull();
-    }
-
-    @Test
-    public void displayCompatActivity_launchedFromDisplayCompatApp_returnsHost() {
-        Intent intent = getDisplayCompatRequiredActivity();
-        String packageName = intent.getComponent().getPackageName();
-        when(mMockInfo.getIntent()).thenReturn(intent);
-        when(mMockCarDisplayCompatScaleProvider
-                .requiresDisplayCompat(eq(packageName), any(int.class)))
-                .thenReturn(true);
-
-        when(mMockInfo.getCallingPackage()).thenReturn(packageName);
-
-        ActivityInterceptResultWrapper result =
-                mInterceptor.onInterceptActivityLaunch(mMockInfo);
-
-        assertThat(result).isNotNull();
-        assertThat(result.getInterceptResult()).isNotNull();
-        assertThat(result.getInterceptResult().getIntent()).isNotNull();
-        assertThat(result.getInterceptResult().getIntent().getComponent()).isEqualTo(mHostActitivy);
-        Intent launchIntent = (Intent) result.getInterceptResult().getIntent()
-                .getExtra(Intent.EXTRA_INTENT);
-        assertThat(launchIntent).isNotNull();
-    }
-
-    @Test
-    public void displayCompatActivity_noPermission_returnsHost() {
-        Intent intent = getDisplayCompatRequiredActivity();
-        String packageName = intent.getComponent().getPackageName();
-        intent.putExtra(LAUNCHED_FROM_HOST, true);
-        when(mMockInfo.getIntent()).thenReturn(intent);
-        when(mMockCarDisplayCompatScaleProvider
-                .requiresDisplayCompat(eq(packageName), any(int.class)))
-                .thenReturn(true);
-
-        when(mMockInfo.getCallingPackage()).thenReturn(packageName);
-        when(mMockInfo.getCallingPid()).thenReturn(1);
-        when(mMockInfo.getCallingUid()).thenReturn(2);
-        when(mMockContext.checkPermission(PERMISSION_DISPLAY_COMPATIBILITY, 1, 2))
-                .thenReturn(PERMISSION_DENIED);
-
-        ActivityInterceptResultWrapper result =
-                mInterceptor.onInterceptActivityLaunch(mMockInfo);
-
-        assertThat(result).isNotNull();
-        assertThat(result.getInterceptResult()).isNotNull();
-        assertThat(result.getInterceptResult().getIntent()).isNotNull();
-        assertThat(result.getInterceptResult().getIntent().getComponent()).isEqualTo(mHostActitivy);
-        Intent launchIntent = (Intent) result.getInterceptResult().getIntent()
-                .getExtra(Intent.EXTRA_INTENT);
-        assertThat(launchIntent).isNotNull();
-    }
-
-    @Test
-    public void hostActivity_whenNoLaunchDisplayId_launchesOnDefaultDisplay() {
-        Intent intent = getDisplayCompatRequiredActivity();
-        when(mMockInfo.getIntent()).thenReturn(intent);
-
-        ActivityOptions mockActivityOptions = mock(ActivityOptions.class);
-        when(mockActivityOptions.getLaunchDisplayId()).thenReturn(INVALID_DISPLAY);
-        ActivityOptionsWrapper mockActivityOptionsWrapper = mock(ActivityOptionsWrapper.class);
-        when(mockActivityOptionsWrapper.getOptions()).thenReturn(mockActivityOptions);
-        when(mMockInfo.getCheckedOptions()).thenReturn(mockActivityOptionsWrapper);
-
-        ActivityInterceptResultWrapper result =
-                mInterceptor.onInterceptActivityLaunch(mMockInfo);
-
-        assertThat(result.getInterceptResult().getActivityOptions().getLaunchDisplayId())
-                .isEqualTo(DEFAULT_DISPLAY);
-    }
-
-    @Test
-    public void hostActivity_withLaunchDisplayId_launchesOnCorrectDisplay() {
-        Intent intent = getDisplayCompatRequiredActivity();
-        when(mMockInfo.getIntent()).thenReturn(intent);
-
-        ActivityOptions mockActivityOptions = mock(ActivityOptions.class);
-        when(mockActivityOptions.getLaunchDisplayId()).thenReturn(2);
-        ActivityOptionsWrapper mockActivityOptionsWrapper = mock(ActivityOptionsWrapper.class);
-        when(mockActivityOptionsWrapper.getOptions()).thenReturn(mockActivityOptions);
-        when(mMockInfo.getCheckedOptions()).thenReturn(mockActivityOptionsWrapper);
-
-        ActivityInterceptResultWrapper result =
-                mInterceptor.onInterceptActivityLaunch(mMockInfo);
-
-        assertThat(result.getInterceptResult().getActivityOptions().getLaunchDisplayId())
-                .isEqualTo(2);
-    }
-
-    /**
-     * Returns an {@link Intent} associated with an {@link Activity} that does not need to run in
-     * display compat mode.
-     */
-    private Intent getNoDisplayCompatRequiredActivity() {
-        ComponentName displayCompatActivity =
-                ComponentName.unflattenFromString("com.test/.NoDisplayCompatRequiredActivity");
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setComponent(displayCompatActivity);
-        when(mMockCarDisplayCompatScaleProvider
-                .requiresDisplayCompat(eq(displayCompatActivity.getPackageName()), any(int.class)))
-                .thenReturn(false);
-        return intent;
-    }
-
-    /**
-     * Returns an {@link Intent} associated with an {@link Activity} that needs to run in
-     * display compat mode.
-     */
-    private Intent getDisplayCompatRequiredActivity() {
-        ComponentName displayCompatActivity =
-                ComponentName.unflattenFromString("com.test/.DisplayCompatRequiredActivity");
-        Intent intent = new Intent(Intent.ACTION_MAIN);
-        intent.setComponent(displayCompatActivity);
-        when(mMockCarDisplayCompatScaleProvider
-                .requiresDisplayCompat(eq(displayCompatActivity.getPackageName()), any(int.class)))
-                .thenReturn(true);
-        return intent;
-    }
-}
diff --git a/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java b/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
index 2bed9dd..c3ca6f3 100644
--- a/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
+++ b/updatableServices/tests/src/com/android/server/wm/CarLaunchParamsModifierUpdatableTest.java
@@ -144,6 +144,8 @@ public class CarLaunchParamsModifierUpdatableTest {
     private TaskDisplayArea mDisplayArea3Overlay;
     @Mock
     private Display mDisplay99Random;
+    @Mock
+    private CarDisplayCompatScaleProviderUpdatableImpl mMockCarDisplayCompatScaleProvider;
     private TaskDisplayArea mDisplayArea99Random;
 
     private TaskDisplayArea mMapTaskDisplayArea;
@@ -217,14 +219,13 @@ public class CarLaunchParamsModifierUpdatableTest {
         when(mUserManagerInternal.getMainDisplayAssignedToUser(anyInt()))
                 .thenReturn(INVALID_DISPLAY);
 
-        LocalServices.removeServiceForTest(WindowManagerInternal.class);
-        LocalServices.removeServiceForTest(ImeTargetVisibilityPolicy.class);
-        mWindowManagerService = WindowManagerService.main(
-                mContext, mInputManagerService, /* showBootMsgs= */ false, /* policy= */ null,
-                mActivityTaskManagerService,
-                /* displayWindowSettingsProvider= */ null, () -> new SurfaceControl.Transaction(),
-                /* surfaceControlFactory= */ null,
-                /* appCompatConfiguration= */ mAppCompatConfiguration);
+        WindowManagerServiceTestSupport.tearDownService();
+        mWindowManagerService = WindowManagerServiceTestSupport.setUpService(mContext,
+                mInputManagerService, mock(WindowManagerPolicy.class),
+                mActivityTaskManagerService, mock(DisplayWindowSettingsProvider.class),
+                new SurfaceControl.Transaction(), new SurfaceControl.Builder(),
+                mAppCompatConfiguration);
+
         mActivityTaskManagerService.mWindowManager = mWindowManagerService;
         mRootWindowContainer.mWindowManager = mWindowManagerService;
 
@@ -258,15 +259,16 @@ public class CarLaunchParamsModifierUpdatableTest {
 
         mModifier = new CarLaunchParamsModifier(mContext);
         mBuiltin = mModifier.getBuiltinInterface();
-        mUpdatable = new CarLaunchParamsModifierUpdatableImpl(mBuiltin);
+        mUpdatable = new CarLaunchParamsModifierUpdatableImpl(mBuiltin,
+                mMockCarDisplayCompatScaleProvider);
         mModifier.setUpdatable(mUpdatable);
         mModifier.init();
     }
 
     @After
     public void tearDown() {
-        LocalServices.removeServiceForTest(WindowManagerInternal.class);
-        LocalServices.removeServiceForTest(WindowManagerPolicy.class);
+        WindowManagerServiceTestSupport.tearDownService();
+
         LocalServices.removeServiceForTest(ColorDisplayService.ColorDisplayServiceInternal.class);
         // If the exception is thrown during the MockingSession setUp, mMockingSession can be null.
         if (mMockingSession != null) {
@@ -323,14 +325,17 @@ public class CarLaunchParamsModifierUpdatableTest {
         assertThat(mOutParams.mPreferredTaskDisplayArea).isNull();
     }
 
-    private ActivityRecord buildActivityRecord(String packageName, String className) {
+    private ActivityRecord buildActivityRecord(String packageName, String className,
+            Intent intent) {
         ActivityInfo info = new ActivityInfo();
         info.packageName = packageName;
         info.name = className;
         info.applicationInfo = new ApplicationInfo();
         info.applicationInfo.packageName = packageName;
-        Intent intent = new Intent();
-        intent.setClassName(packageName, className);
+        if (intent == null) {
+            intent = new Intent();
+            intent.setClassName(packageName, className);
+        }
 
         return new ActivityRecord.Builder(mActivityTaskManagerService)
                 .setIntent(intent)
@@ -339,10 +344,69 @@ public class CarLaunchParamsModifierUpdatableTest {
                 .build();
     }
 
+    private ActivityRecord buildActivityRecord(String packageName, String className) {
+        return buildActivityRecord(packageName, className, null);
+    }
+
     private ActivityRecord buildActivityRecord(ComponentName componentName) {
         return buildActivityRecord(componentName.getPackageName(), componentName.getClassName());
     }
 
+    private ActivityRecord buildActivityRecord(ComponentName componentName, Intent intent) {
+        return buildActivityRecord(componentName.getPackageName(), componentName.getClassName(),
+                intent);
+    }
+
+    @Test
+    @SuppressWarnings("DirectInvocationOnMock")
+    public void testPassengerChange_requiresDisplayCompat_needsSafeRegionBoundsTrue() {
+        mUpdatable.setPassengerDisplays(new int[]{mDisplay10ForPassenger.getDisplayId(),
+                mDisplay11ForPassenger.getDisplayId()});
+
+        int passengerUserId1 = 100;
+        mUpdatable.setDisplayAllowListForUser(passengerUserId1,
+                new int[]{mDisplay11ForPassenger.getDisplayId()});
+
+        int passengerUserId2 = 101;
+        mUpdatable.setDisplayAllowListForUser(passengerUserId2,
+                new int[]{mDisplay11ForPassenger.getDisplayId()});
+
+        Intent intent = getDisplayCompatRequiredActivity();
+        mActivityRecordActivity = buildActivityRecord(intent.getComponent(), intent);
+
+        // 11 not allowed, so reassigned to the 1st passenger display. This will return RESULT_DONE
+        assertDisplayIsReassigned(passengerUserId1, mDisplay11ForPassenger, mDisplay10ForPassenger);
+        // Since activity is display compat, mNeedsSafeRegionBounds should be true
+        assertThat(mOutParams.mNeedsSafeRegionBounds).isTrue();
+    }
+
+    @Test
+    public void testActivityRequiresDisplayCompat_needsSafeRegionBoundsTrue() {
+        Intent intent = getDisplayCompatRequiredActivity();
+        mActivityRecordActivity = buildActivityRecord(intent.getComponent(), intent);
+
+        assertThat(mModifier.onCalculate(mTask, mWindowLayout, mActivityRecordActivity,
+                mActivityRecordSource, mActivityOptions, /* request= */ null, /* phase= */ 0,
+                mCurrentParams, mOutParams))
+                .isEqualTo(LaunchParamsController.LaunchParamsModifier.RESULT_CONTINUE);
+        assertThat(mOutParams.mNeedsSafeRegionBounds).isTrue();
+    }
+
+    /**
+     * Returns an {@link Intent} associated with an {@link android.app.Activity} that needs to run
+     * in display compat mode.
+     */
+    private Intent getDisplayCompatRequiredActivity() {
+        ComponentName displayCompatActivity =
+                ComponentName.unflattenFromString("com.test/.DisplayCompatRequiredActivity");
+        Intent intent = new Intent(Intent.ACTION_MAIN);
+        intent.setComponent(displayCompatActivity);
+        when(mMockCarDisplayCompatScaleProvider
+                .requiresDisplayCompat(eq(displayCompatActivity.getPackageName()), any(int.class)))
+                .thenReturn(true);
+        return intent;
+    }
+
     @Test
     public void testNoPolicySet() {
         final int randomUserId = 1000;
diff --git a/updatableServices/tests/src/com/android/server/wm/CarLaunchOnPrivateDisplayActivityInterceptorTest.java b/updatableServices/tests/src/com/android/server/wm/CarLaunchRedirectActivityInterceptorTest.java
similarity index 75%
rename from updatableServices/tests/src/com/android/server/wm/CarLaunchOnPrivateDisplayActivityInterceptorTest.java
rename to updatableServices/tests/src/com/android/server/wm/CarLaunchRedirectActivityInterceptorTest.java
index 65faa6b..e99fdc9 100644
--- a/updatableServices/tests/src/com/android/server/wm/CarLaunchOnPrivateDisplayActivityInterceptorTest.java
+++ b/updatableServices/tests/src/com/android/server/wm/CarLaunchRedirectActivityInterceptorTest.java
@@ -18,10 +18,10 @@ package com.android.server.wm;
 
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.doReturn;
 import static com.android.dx.mockito.inline.extended.ExtendedMockito.mockitoSession;
-import static com.android.server.wm.CarLaunchOnPrivateDisplayActivityInterceptor.LAUNCH_ACTIVITY;
-import static com.android.server.wm.CarLaunchOnPrivateDisplayActivityInterceptor.LAUNCH_ACTIVITY_DISPLAY_ID;
-import static com.android.server.wm.CarLaunchOnPrivateDisplayActivityInterceptor.LAUNCH_ON_PRIVATE_DISPLAY;
-import static com.android.server.wm.CarLaunchOnPrivateDisplayActivityInterceptor.PERMISSION_ACCESS_PRIVATE_DISPLAY_ID;
+import static com.android.server.wm.CarLaunchRedirectActivityInterceptor.LAUNCH_ACTIVITY;
+import static com.android.server.wm.CarLaunchRedirectActivityInterceptor.LAUNCH_ACTIVITY_DISPLAY_ID;
+import static com.android.server.wm.CarLaunchRedirectActivityInterceptor.LAUNCH_REDIRECT_ON_CONTAINER;
+import static com.android.server.wm.CarLaunchRedirectActivityInterceptor.PERMISSION_ACCESS_PRIVATE_DISPLAY_ID;
 
 import static com.google.common.truth.Truth.assertThat;
 
@@ -53,11 +53,11 @@ import org.mockito.quality.Strictness;
 import java.util.Objects;
 
 /**
- * Unit tests for launching on private displays (physical or virtual).
+ * Unit tests for redirecting launch on private displays (physical or virtual) or root tasks.
  */
 @RunWith(AndroidJUnit4.class)
-public class CarLaunchOnPrivateDisplayActivityInterceptorTest {
-    private static final String DISPLAY_ID_NO_LAUNCH_PRIVATE_DISPLAY_KEY = "-999";
+public class CarLaunchRedirectActivityInterceptorTest {
+    private static final String NO_LAUNCH_REDIRECT_CONTAINER = "-999";
     private static final String INVALID_DISPLAY = "-1";
     private static final int DISPLAY_ID_PHYSICAL_PRIVATE = 0;
     private static final int DISPLAY_ID_VIRTUAL_PRIVATE = 2;
@@ -70,6 +70,8 @@ public class CarLaunchOnPrivateDisplayActivityInterceptorTest {
             "com.test/.LaunchOnPrivateDisplayRouterActivity");
     private final String[] mAllowlistedPackageNames = {"com.test.allowlisted"};
 
+    private WindowContainer.RemoteToken mRootTaskToken;
+
     @Mock
     private Resources mMockResources;
     @Mock
@@ -84,9 +86,11 @@ public class CarLaunchOnPrivateDisplayActivityInterceptorTest {
     private Display mDisplay1;
     @Mock
     private Display mDisplay2;
+    @Mock
+    private Task mWindowContainer;
 
     private MockitoSession mMockingSession;
-    private CarLaunchOnPrivateDisplayActivityInterceptor mInterceptor;
+    private CarLaunchRedirectActivityInterceptor mInterceptor;
 
     @Before
     public void setUp() {
@@ -114,8 +118,10 @@ public class CarLaunchOnPrivateDisplayActivityInterceptorTest {
         when(mMockPackageManager.resolveActivity(any(Intent.class),
                 any(PackageManager.ResolveInfoFlags.class))).thenReturn(mock(ResolveInfo.class));
         when(mMockContext.getPackageManager()).thenReturn(mMockPackageManager);
+        mRootTaskToken = new WindowContainer.RemoteToken(mWindowContainer);
+        mWindowContainer.mRemoteToken = mRootTaskToken;
 
-        mInterceptor = new CarLaunchOnPrivateDisplayActivityInterceptor(mMockContext);
+        mInterceptor = new CarLaunchRedirectActivityInterceptor(mMockContext);
     }
 
     @After
@@ -127,8 +133,8 @@ public class CarLaunchOnPrivateDisplayActivityInterceptorTest {
     }
 
     @Test
-    public void launchOnPhysicalPrivateDisplay_noLaunchOnPrivateDisplayKey_returnsNull() {
-        mMockInfo = createMockActivityInterceptorInfo(DISPLAY_ID_NO_LAUNCH_PRIVATE_DISPLAY_KEY,
+    public void launch_noRootTaskKey_noLaunchOnPrivateDisplayKey_returnsNull() {
+        mMockInfo = createMockActivityInterceptorInfo(NO_LAUNCH_REDIRECT_CONTAINER,
                 ALLOWLISTED_ACTIVITY);
 
         ActivityInterceptResultWrapper result =
@@ -169,6 +175,47 @@ public class CarLaunchOnPrivateDisplayActivityInterceptorTest {
         assertThat(result).isNull();
     }
 
+    @Test
+    public void launchOnRootTask_invalidRootTask_returnsNull() {
+        String testRootTaskName1 = "testRootTaskName1";
+        String testRootTaskName2 = "testRootTaskName2";
+        mInterceptor.onRootTaskAppeared(testRootTaskName1, mRootTaskToken);
+        // Pass in an invalid root task name
+        mMockInfo = createMockActivityInterceptorInfo(testRootTaskName2, ALLOWLISTED_ACTIVITY);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    @Test
+    public void launchOnRootTask_notAllowlisted_returnsNull() {
+        String testRootTaskName = "testRootTaskName";
+        mInterceptor.onRootTaskAppeared(testRootTaskName, mRootTaskToken);
+        mMockInfo = createMockActivityInterceptorInfo(testRootTaskName, DENYLISTED_ACTIVITY);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNull();
+    }
+
+    @Test
+    public void launchOnRootTask_isAllowlisted_returnsNotNull() {
+        String testRootTaskName = "testRootTaskName";
+        mInterceptor.onRootTaskAppeared(testRootTaskName, mRootTaskToken);
+        mMockInfo = createMockActivityInterceptorInfo(testRootTaskName, ALLOWLISTED_ACTIVITY);
+
+        ActivityInterceptResultWrapper result =
+                mInterceptor.onInterceptActivityLaunch(mMockInfo);
+
+        assertThat(result).isNotNull();
+        assertThat(result.getInterceptResult().getActivityOptions().getLaunchRootTask())
+                .isEqualTo(WindowContainer.fromBinder(mRootTaskToken)
+                        .mRemoteToken.toWindowContainerToken());
+    }
+
     @Test
     public void launchOnPhysicalPrivateDisplay_isAllowlisted_returnsNotNull() {
         mMockInfo = createMockActivityInterceptorInfo(UNIQUE_DISPLAY_ID_PHYSICAL_PRIVATE,
@@ -253,13 +300,12 @@ public class CarLaunchOnPrivateDisplayActivityInterceptorTest {
                 LAUNCH_ACTIVITY_DISPLAY_ID)).isEqualTo(displayId);
     }
 
-    private Intent getActivityLaunchOnDisplay(String displayId, String allowlistedActivity) {
-        ComponentName exampleActivity =
-                ComponentName.unflattenFromString(allowlistedActivity);
+    private Intent getActivityLaunchOnContainer(String containerName, String allowlistedActivity) {
+        ComponentName exampleActivity = ComponentName.unflattenFromString(allowlistedActivity);
         Intent intent = new Intent(Intent.ACTION_MAIN);
         intent.setComponent(exampleActivity);
-        if (!Objects.equals(displayId, DISPLAY_ID_NO_LAUNCH_PRIVATE_DISPLAY_KEY)) {
-            intent.putExtra(LAUNCH_ON_PRIVATE_DISPLAY, displayId);
+        if (!Objects.equals(containerName, NO_LAUNCH_REDIRECT_CONTAINER)) {
+            intent.putExtra(LAUNCH_REDIRECT_ON_CONTAINER, containerName);
         }
         return intent;
     }
@@ -271,9 +317,9 @@ public class CarLaunchOnPrivateDisplayActivityInterceptorTest {
                 .thenReturn(permissionValue);
     }
 
-    private ActivityInterceptorInfoWrapper createMockActivityInterceptorInfo(String displayId,
+    private ActivityInterceptorInfoWrapper createMockActivityInterceptorInfo(String containerName,
             String allowlistedActivity) {
-        Intent intent = getActivityLaunchOnDisplay(displayId, allowlistedActivity);
+        Intent intent = getActivityLaunchOnContainer(containerName, allowlistedActivity);
         when(mMockInfo.getIntent()).thenReturn(intent);
         when(mMockInfo.getCallingPackage()).thenReturn(intent.getPackage());
         return mMockInfo;
```

