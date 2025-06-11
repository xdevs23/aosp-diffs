```diff
diff --git a/OWNERS b/OWNERS
index 6010592..ed452e7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,17 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
 # Bug component: 1495529
 yforta@google.com
 carmenjackson@google.com
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 0e5e627..d2838fe 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,3 +1,17 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
 [Builtin Hooks]
 xmllint = true
 bpfmt = true
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 728e4cf..b4f16d4 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,7 +1,7 @@
 {
-  "mainline-presubmit": [
+  "profiling-mainline-presubmit": [
     {
-      "name": "CtsProfilingModuleTests[com.google.android.profiling.apex]",
+      "name": "CtsProfilingModuleTests",
       "options": [
         {
           "exclude-annotation": "androidx.test.filters.LargeTest"
diff --git a/aidl/Android.bp b/aidl/Android.bp
index 478ef74..f0d6075 100644
--- a/aidl/Android.bp
+++ b/aidl/Android.bp
@@ -1,18 +1,19 @@
-//
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
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
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
diff --git a/aidl/android/os/IProfilingResultCallback.aidl b/aidl/android/os/IProfilingResultCallback.aidl
index 69933b5..5157c69 100644
--- a/aidl/android/os/IProfilingResultCallback.aidl
+++ b/aidl/android/os/IProfilingResultCallback.aidl
@@ -20,9 +20,11 @@ package android.os;
  */
 interface IProfilingResultCallback {
 
-    oneway void sendResult(String resultFile, long keyMostSigBits, long keyLeastSigBits, int status, String tag, String error);
+    oneway void sendResult(String resultFile, long keyMostSigBits, long keyLeastSigBits, int status,
+            String tag, String error, int triggerType);
 
-    oneway void generateFile(String filePathRelative, String fileName, long keyMostSigBits, long keyLeastSigBits);
+    oneway void generateFile(String filePathRelative, String fileName, long keyMostSigBits,
+            long keyLeastSigBits);
 
     oneway void deleteFile(String relativeFilePathAndName);
 }
diff --git a/aidl/android/os/IProfilingService.aidl b/aidl/android/os/IProfilingService.aidl
index c1b66c4..5a9a8e3 100644
--- a/aidl/android/os/IProfilingService.aidl
+++ b/aidl/android/os/IProfilingService.aidl
@@ -25,17 +25,21 @@ import android.os.ProfilingTriggerValueParcel;
  */
 interface IProfilingService {
 
-    oneway void requestProfiling(int profilingType, in Bundle params, String tag, long keyMostSigBits, long keyLeastSigBits, String packageName);
+    oneway void requestProfiling(int profilingType, in Bundle params, String tag,
+            long keyMostSigBits, long keyLeastSigBits, String packageName);
 
-    oneway void registerResultsCallback(boolean isGeneralCallback, IProfilingResultCallback callback);
+    oneway void registerResultsCallback(boolean isGeneralCallback,
+            IProfilingResultCallback callback);
 
     oneway void generalListenerAdded();
 
     oneway void requestCancel(long keyMostSigBits, long keyLeastSigBits);
 
-    oneway void receiveFileDescriptor(in ParcelFileDescriptor fileDescriptor, long keyMostSigBits, long keyLeastSigBits);
+    oneway void receiveFileDescriptor(in ParcelFileDescriptor fileDescriptor, long keyMostSigBits,
+            long keyLeastSigBits);
 
-    oneway void addProfilingTriggers(in List<ProfilingTriggerValueParcel> triggers, String packageName);
+    oneway void addProfilingTriggers(in List<ProfilingTriggerValueParcel> triggers,
+            String packageName);
 
     oneway void removeProfilingTriggers(in int[] triggers, String packageName);
 
diff --git a/aidl/android/os/ProfilingTriggerValueParcel.aidl b/aidl/android/os/ProfilingTriggerValueParcel.aidl
index c9ebf2c..5c39053 100644
--- a/aidl/android/os/ProfilingTriggerValueParcel.aidl
+++ b/aidl/android/os/ProfilingTriggerValueParcel.aidl
@@ -22,4 +22,5 @@ package android.os;
 parcelable ProfilingTriggerValueParcel {
     int triggerType;
     int rateLimitingPeriodHours;
-}
\ No newline at end of file
+}
+
diff --git a/apex/Android.bp b/apex/Android.bp
index cf360be..1c56a80 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -39,8 +39,7 @@ apex {
     file_contexts: ":com.android.profiling-file_contexts",
     key: "com.android.profiling.key",
     certificate: ":com.android.profiling.certificate",
-    defaults: ["v-launched-apex-module"],
-    min_sdk_version: "35",
+    defaults: ["b-launched-apex-module"],
 
     binaries: ["trace_redactor"],
 
@@ -89,3 +88,10 @@ bootclasspath_fragment {
         split_packages: ["*"],
     },
 }
+
+sdk {
+    name: "profiling-module-sdk",
+    apexes: [
+        "com.android.profiling",
+    ],
+}
diff --git a/framework/Android.bp b/framework/Android.bp
index 51bf6c8..029519d 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -1,16 +1,18 @@
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
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
 
 package {
     default_visibility: [":__pkg__"],
diff --git a/framework/jarjar-rules.txt b/framework/jarjar-rules.txt
index 69cdc64..48f1123 100644
--- a/framework/jarjar-rules.txt
+++ b/framework/jarjar-rules.txt
@@ -1,3 +1,17 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
 rule com.android.modules.utils.** com.android.internal.profiling.@0
 rule com.google.protobuf.** android.os.protobuf.@1
 
diff --git a/framework/java/android/os/ProfilingManager.java b/framework/java/android/os/ProfilingManager.java
index fa3ac0b..260876c 100644
--- a/framework/java/android/os/ProfilingManager.java
+++ b/framework/java/android/os/ProfilingManager.java
@@ -43,9 +43,11 @@ import java.util.function.Consumer;
 /**
  * <p>
  * This class allows the caller to:
- * - Request profiling and listen for results. Profiling types supported are: system traces,
- *      java heap dumps, heap profiles, and stack traces.
- * - Register triggers for the system to capture profiling on the apps behalf.
+ * <ul>
+ * <li>Request profiling and listen for results. Profiling types supported are: system traces,
+ *     java heap dumps, heap profiles, and stack traces.</li>
+ * <li>Register triggers for the system to capture profiling on the apps behalf.</li>
+ * </ul>
  * </p>
  *
  * <p>
@@ -61,11 +63,13 @@ import java.util.function.Consumer;
  *
  * <p>
  * Apps can provide listeners in one or both of two ways:
- * - A request-specific listener included with the request. This will trigger only with a result
- *     from the request it was provided with.
- * - A global listener provided by {@link #registerForAllProfilingResults}. This will be triggered
+ * <ul>
+ * <li>A request-specific listener included with the request. This will trigger only with a result
+ *     from the request it was provided with.</li>
+ * <li>A global listener provided by {@link #registerForAllProfilingResults}. This will be triggered
  *     for all results belonging to your app. This listener is the only way to receive results from
- *     system triggered profiling instances set up with {@link #addProfilingTriggers}.
+ *     system triggered profiling instances set up with {@link #addProfilingTriggers}.</li>
+ * </ul>
  * </p>
  *
  * <p>
@@ -75,13 +79,37 @@ import java.util.function.Consumer;
  * </p>
  *
  * <p>
+ * For local testing, profiling results can be accessed more easily by enabling debug mode. This
+ * will retain output files in a temporary system directory. The locations of the retained files
+ * will be available in logcat. The behavior and command varies by version:
+ * <ul>
+ * <li>For Android versions 16 and above, debug mode will retain both unredacted (where applicable)
+ * and redacted results in the temporary directory. It can be enabled with the shell command
+ * {@code device_config put profiling_testing delete_temporary_results.disabled true} and disabled
+ * by setting that same value back to false. Retained results are accessible on all build types.
+ * </li>
+ * <li>For Android version 15, debug mode will retain only the unredacted result (where applicable)
+ * in the temporary directory. It can be enabled with the shell command
+ * {@code device_config put profiling_testing delete_unredacted_trace.disabled true} and disabled
+ * by setting that same value back to false. The retained unredacted file can only be accessed on
+ * builds with root access. To access the redacted output file on an unrooted device, apps can copy
+ * the file from {@code /pkg/files/profiling/file.type} to {@code /pkg/cache/file.type}.
+ * </li>
+ * </ul>
+ * </p>
+ *
+ * <p>
  * In order to test profiling triggers, enable testing mode for your app with the shell command
  * {@code device_config put profiling_testing system_triggered_profiling.testing_package_name
  * com.your.app} which will:
- * - Ensure that a background trace is running.
- * - Allow all triggers for the provided package name to pass the system level rate limiter.
- * This mode will continue until manually stopped with the shell command
- * {@code device_config delete profiling_testing system_triggered_profiling.testing_package_name}
+ * <ul>
+ * <li>Ensure that a background trace is running.</li>
+ * <li>Allow all triggers for the provided package name to pass the system level rate limiter.
+ *     This mode will continue until manually stopped with the shell command
+ *     {@code device_config delete profiling_testing
+ *     system_triggered_profiling.testing_package_name}.
+ *     </li>
+ * </ul>
  * </p>
  *
  * <p>
@@ -197,8 +225,10 @@ public final class ProfilingManager {
      *
      * <p class="note">
      *   Note: use of this API directly is not recommended for most use cases.
-     *   Consider using the higher level wrappers provided by AndroidX that will construct the
-     *   request correctly, supporting available options with simplified request parameters
+     *   Consider using the
+     *   <a href="https://developer.android.com/reference/androidx/core/os/Profiling">higher level
+     *   wrappers provided by AndroidX</a> that will construct the request correctly, supporting
+     *   available options with simplified request parameters.
      * </p>
      *
      * <p>
@@ -229,7 +259,9 @@ public final class ProfilingManager {
      *                  {@link android.os.ProfilingResult#ERROR_FAILED_INVALID_REQUEST}. If the
      *                  values for the parameters are out of supported range, the closest possible
      *                  in range value will be chosen.
-     *                  Use of androidx wrappers is recommended over generating this directly.
+     *                  Use of <a href=
+     *                  "https://developer.android.com/reference/androidx/core/os/Profiling">
+     *                  androidx wrappers</a> is recommended over generating this directly.
      * @param tag Caller defined data to help identify the output.
      *                  The first 20 alphanumeric characters, plus dashes, will be lowercased
      *                  and included in the output filename.
@@ -409,18 +441,32 @@ public final class ProfilingManager {
     }
 
     /**
+     * <p>
      * Register the provided list of triggers for this process.
+     * </p>
      *
-     * Profiling triggers are system triggered events that an app can register interest in receiving
-     * profiling of. There is no guarantee that these triggers will be filled. Results, if
-     * available, will be delivered only to a global listener added using
-     * {@link #registerForAllProfilingResults}.
+     * <p>
+     * Profiling triggers are system events that an app can register interest in, and then receive
+     * profiling data when any of the registered triggers occur. There is no guarantee that these
+     * triggers will be filled. Results, if available, will be delivered only to a global listener
+     * added using {@link #registerForAllProfilingResults}.
+     *</p>
      *
+     * <p>
      * Only one of each trigger type can be added at a time.
-     * - If the provided list contains a trigger type that is already registered then the new one
-     *      will replace the existing one.
-     * - If the provided list contains more than one trigger object for a trigger type then only one
-     *      will be kept.
+     * <ul>
+     * <li>If the provided list contains a trigger type that is already registered then the new one
+     *     will replace the existing one.</li>
+     * <li>If the provided list contains more than one trigger object for a trigger type then only
+     *     one will be kept.</li>
+     * </ul>
+     * </p>
+     *
+     * <p>
+     * Apps can define their own per-trigger rate limiting to help ensure they receive results
+     * aligned with their needs. More details can be found at
+     * {@link ProfilingTrigger.Builder#setRateLimitingPeriodHours}.
+     * </p>
      */
     @FlaggedApi(Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
     public void addProfilingTriggers(@NonNull List<ProfilingTrigger> triggers) {
@@ -558,7 +604,7 @@ public final class ProfilingManager {
                         @Override
                         public void sendResult(@Nullable String resultFile, long keyMostSigBits,
                                 long keyLeastSigBits, int status, @Nullable String tag,
-                                @Nullable String error) {
+                                @Nullable String error, int triggerType) {
                             synchronized (mLock) {
                                 if (mCallbacks.isEmpty()) {
                                     // This shouldn't happen - no callbacks, nowhere to report this
@@ -604,9 +650,7 @@ public final class ProfilingManager {
                                             new ProfilingResult(overrideStatusToError
                                                     ? ProfilingResult.ERROR_UNKNOWN : status,
                                                     getAppFileDir() + resultFile, tag, error,
-                                                    Flags.systemTriggeredProfilingNew()
-                                                            ? ProfilingTrigger.TRIGGER_TYPE_NONE
-                                                            : 0)));
+                                                    triggerType)));
                                 }
 
                                 // Remove the single listener that was tied to the request, if
diff --git a/framework/java/android/os/ProfilingResult.java b/framework/java/android/os/ProfilingResult.java
index 0ed84ea..5f06258 100644
--- a/framework/java/android/os/ProfilingResult.java
+++ b/framework/java/android/os/ProfilingResult.java
@@ -21,9 +21,11 @@ import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.os.profiling.Flags;
+import android.text.TextUtils;
 
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
+import java.util.Objects;
 
 /**
  * Encapsulates results of a single profiling request operation.
@@ -31,6 +33,7 @@ import java.lang.annotation.RetentionPolicy;
 @FlaggedApi(Flags.FLAG_TELEMETRY_APIS)
 public final class ProfilingResult implements Parcelable {
 
+    // LINT.IfChange(params)
     /** @see #getErrorCode */
     final @ErrorCode int mErrorCode;
 
@@ -45,6 +48,7 @@ public final class ProfilingResult implements Parcelable {
 
     /** @see #getTriggerType */
     final int mTriggerType;
+    // LINT.ThenChange(:from_parcel)
 
     /** The request was executed and succeeded. */
     public static final int ERROR_NONE = 0;
@@ -87,7 +91,8 @@ public final class ProfilingResult implements Parcelable {
     @Retention(RetentionPolicy.SOURCE)
     @interface ErrorCode {}
 
-    ProfilingResult(@ErrorCode int errorCode, String resultFilePath, String tag,
+    /** @hide */
+    public ProfilingResult(@ErrorCode int errorCode, String resultFilePath, String tag,
             String errorMessage, int triggerType) {
         mErrorCode = errorCode;
         mResultFilePath = resultFilePath;
@@ -96,14 +101,18 @@ public final class ProfilingResult implements Parcelable {
         mTriggerType = triggerType;
     }
 
-    private ProfilingResult(@NonNull Parcel in) {
+    // LINT.IfChange(from_parcel)
+    /** @hide */
+    public ProfilingResult(@NonNull Parcel in) {
         mErrorCode = in.readInt();
         mResultFilePath = in.readString();
         mTag = in.readString();
         mErrorMessage = in.readString();
         mTriggerType = in.readInt();
     }
+    // LINT.ThenChange(:to_parcel)
 
+    // LINT.IfChange(to_parcel)
     @Override
     public void writeToParcel(@NonNull Parcel dest, int flags) {
         dest.writeInt(mErrorCode);
@@ -112,6 +121,7 @@ public final class ProfilingResult implements Parcelable {
         dest.writeString(mErrorMessage);
         dest.writeInt(mTriggerType);
     }
+    // LINT.ThenChange(:equals)
 
     @Override
     public int describeContents() {
@@ -169,4 +179,33 @@ public final class ProfilingResult implements Parcelable {
     public int getTriggerType() {
         return mTriggerType;
     }
+
+    // LINT.IfChange(equals)
+    /** @hide */
+    @Override
+    public boolean equals(@Nullable Object other) {
+        if (other == null || !(other instanceof ProfilingResult)) {
+            return false;
+        }
+
+        final ProfilingResult o = (ProfilingResult) other;
+
+        if (Flags.systemTriggeredProfilingNew()) {
+            if (mTriggerType != o.getTriggerType()) {
+                return false;
+            }
+        }
+
+        return mErrorCode == o.getErrorCode()
+                && TextUtils.equals(mResultFilePath, o.getResultFilePath())
+                && TextUtils.equals(mTag, o.getTag())
+                && TextUtils.equals(mErrorMessage, o.getErrorMessage());
+    }
+
+    /** @hide */
+    @Override
+    public int hashCode() {
+        return Objects.hash(mErrorCode, mResultFilePath, mTag, mErrorMessage, mTriggerType);
+    }
+    // LINT.ThenChange(:params)
 }
diff --git a/framework/java/android/os/ProfilingTrigger.java b/framework/java/android/os/ProfilingTrigger.java
index 1a6bd3a..53ba4e8 100644
--- a/framework/java/android/os/ProfilingTrigger.java
+++ b/framework/java/android/os/ProfilingTrigger.java
@@ -35,7 +35,10 @@ public final class ProfilingTrigger {
     /** Trigger occurs after {@link Activity#reportFullyDrawn} is called for a cold start. */
     public static final int TRIGGER_TYPE_APP_FULLY_DRAWN = 1;
 
-    /** Trigger occurs after the app was killed due to an ANR */
+    /**
+     * Trigger occurs after an ANR has been identified, but before the system would attempt to kill
+     * the app. The trigger does not necessarily indicate that the app was killed due to the ANR.
+     */
     public static final int TRIGGER_TYPE_ANR = 2;
 
     /** @hide */
diff --git a/framework/java/android/os/flags.aconfig b/framework/java/android/os/flags.aconfig
index 1b21e88..2fec64e 100644
--- a/framework/java/android/os/flags.aconfig
+++ b/framework/java/android/os/flags.aconfig
@@ -1,3 +1,17 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
 package: "android.os.profiling"
 container: "com.android.profiling"
 
diff --git a/service/Android.bp b/service/Android.bp
index 4f8bfd5..b007635 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -1,16 +1,18 @@
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
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
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
diff --git a/service/java/com/android/os/profiling/Configs.java b/service/java/com/android/os/profiling/Configs.java
index 27225ca..b09c791 100644
--- a/service/java/com/android/os/profiling/Configs.java
+++ b/service/java/com/android/os/profiling/Configs.java
@@ -135,7 +135,7 @@ public final class Configs {
         sSystemTraceSizeKbDefault = properties.getInt(
                 DeviceConfigHelper.SYSTEM_TRACE_SIZE_KB_DEFAULT, 32768);
         sSystemTraceSizeKbMin = properties.getInt(
-                DeviceConfigHelper.SYSTEM_TRACE_SIZE_KB_MIN, 4);
+                DeviceConfigHelper.SYSTEM_TRACE_SIZE_KB_MIN, 64);
         sSystemTraceSizeKbMax = properties.getInt(
                 DeviceConfigHelper.SYSTEM_TRACE_SIZE_KB_MAX, 32768);
 
@@ -159,7 +159,7 @@ public final class Configs {
         sJavaHeapDumpSizeKbDefault = properties.getInt(
                 DeviceConfigHelper.JAVA_HEAP_DUMP_SIZE_KB_DEFAULT, 256000);
         sJavaHeapDumpSizeKbMin = properties.getInt(
-                DeviceConfigHelper.JAVA_HEAP_DUMP_SIZE_KB_MIN, 4);
+                DeviceConfigHelper.JAVA_HEAP_DUMP_SIZE_KB_MIN, 8192 /* 8 MB */);
         sJavaHeapDumpSizeKbMax = properties.getInt(
                 DeviceConfigHelper.JAVA_HEAP_DUMP_SIZE_KB_MAX, 256000);
 
@@ -189,7 +189,7 @@ public final class Configs {
         sHeapProfileSizeKbDefault = properties.getInt(
                 DeviceConfigHelper.HEAP_PROFILE_SIZE_KB_DEFAULT, 65536);
         sHeapProfileSizeKbMin = properties.getInt(
-                DeviceConfigHelper.HEAP_PROFILE_SIZE_KB_MIN, 4);
+                DeviceConfigHelper.HEAP_PROFILE_SIZE_KB_MIN, 256);
         sHeapProfileSizeKbMax = properties.getInt(
                 DeviceConfigHelper.HEAP_PROFILE_SIZE_KB_MAX, 65536);
         sHeapProfileSamplingIntervalBytesDefault = properties.getLong(
@@ -223,7 +223,7 @@ public final class Configs {
         sStackSamplingSizeKbDefault = properties.getInt(
                 DeviceConfigHelper.STACK_SAMPLING_SAMPLING_SIZE_KB_DEFAULT, 65536);
         sStackSamplingSizeKbMin = properties.getInt(
-                DeviceConfigHelper.STACK_SAMPLING_SAMPLING_SIZE_KB_MIN, 4);
+                DeviceConfigHelper.STACK_SAMPLING_SAMPLING_SIZE_KB_MIN, 64);
         sStackSamplingSizeKbMax = properties.getInt(
                 DeviceConfigHelper.STACK_SAMPLING_SAMPLING_SIZE_KB_MAX, 65536);
         sStackSamplingSamplingFrequencyDefault = properties.getInt(
diff --git a/service/java/com/android/os/profiling/DeviceConfigHelper.java b/service/java/com/android/os/profiling/DeviceConfigHelper.java
index 6a52825..2108832 100644
--- a/service/java/com/android/os/profiling/DeviceConfigHelper.java
+++ b/service/java/com/android/os/profiling/DeviceConfigHelper.java
@@ -31,8 +31,10 @@ public final class DeviceConfigHelper {
 
     // Configs for testing only.
     public static final String RATE_LIMITER_DISABLE_PROPERTY = "rate_limiter.disabled";
-    public static final String DISABLE_DELETE_UNREDACTED_TRACE =
-            "delete_unredacted_trace.disabled";
+
+    public static final String DISABLE_DELETE_TEMPORARY_RESULTS =
+            "delete_temporary_results.disabled";
+
     public static final String SYSTEM_TRIGGERED_TEST_PACKAGE_NAME =
             "system_triggered_profiling.testing_package_name";
 
@@ -149,22 +151,6 @@ public final class DeviceConfigHelper {
 
     // End section: Server registered constants
 
-    /**
-     * Get string param for provided device config name from server side device config namespace
-     * or return default if unavailable for any reason.
-     */
-    public static String getString(String name, String defaultValue) {
-        return DeviceConfig.getString(NAMESPACE, name, defaultValue);
-    }
-
-    /**
-     * Get boolean param for provided device config name from server side device config namespace
-     * or return default if unavailable for any reason.
-     */
-    public static boolean getBoolean(String name, boolean defaultValue) {
-        return DeviceConfig.getBoolean(NAMESPACE, name, defaultValue);
-    }
-
     /**
      * Get int param for provided device config name from server side device config namespace
      * or return default if unavailable for any reason.
@@ -173,14 +159,6 @@ public final class DeviceConfigHelper {
         return DeviceConfig.getInt(NAMESPACE, name, defaultValue);
     }
 
-    /**
-     * Get long param for provided device config name from server side device config namespace
-     * or return default if unavailable for any reason.
-     */
-    public static long getLong(String name, long defaultValue) {
-        return DeviceConfig.getLong(NAMESPACE, name, defaultValue);
-    }
-
     /**
      * Get boolean param for provided device config name from test only device config namespace
      * or return default if unavailable for any reason.
diff --git a/service/java/com/android/os/profiling/ProfilingService.java b/service/java/com/android/os/profiling/ProfilingService.java
index 9fdbc86..e12c59f 100644
--- a/service/java/com/android/os/profiling/ProfilingService.java
+++ b/service/java/com/android/os/profiling/ProfilingService.java
@@ -34,6 +34,7 @@ import android.os.IProfilingService;
 import android.os.ParcelFileDescriptor;
 import android.os.ProfilingManager;
 import android.os.ProfilingResult;
+import android.os.ProfilingTrigger;
 import android.os.ProfilingTriggerValueParcel;
 import android.os.ProfilingTriggersWrapper;
 import android.os.QueuedResultsWrapper;
@@ -160,6 +161,7 @@ public class ProfilingService extends IProfilingService.Stub {
     // the active sessions above as it's not associated with a TracingSession until it has been
     // cloned.
     @VisibleForTesting
+    @GuardedBy("mLock")
     public Process mSystemTriggeredTraceProcess = null;
     @VisibleForTesting
     public String mSystemTriggeredTraceUniqueSessionName = null;
@@ -167,7 +169,7 @@ public class ProfilingService extends IProfilingService.Stub {
 
     // Map of uid + package name to a sparse array of trigger objects.
     @VisibleForTesting
-    public ProcessMap<SparseArray<ProfilingTrigger>> mAppTriggers = new ProcessMap<>();
+    public ProcessMap<SparseArray<ProfilingTriggerData>> mAppTriggers = new ProcessMap<>();
     @VisibleForTesting
     public boolean mAppTriggersLoaded = false;
 
@@ -198,7 +200,7 @@ public class ProfilingService extends IProfilingService.Stub {
 
     /** To be disabled for testing only. */
     @GuardedBy("mLock")
-    private boolean mKeepUnredactedTrace = false;
+    private boolean mKeepResultInTempDir = false;
 
     /** Executor for scheduling system triggered profiling trace. */
     private ScheduledExecutorService mScheduledExecutorService = null;
@@ -324,8 +326,8 @@ public class ProfilingService extends IProfilingService.Stub {
         // Get initial value for whether unredacted trace should be retained.
         // This is used for (automated and manual) testing only.
         synchronized (mLock) {
-            mKeepUnredactedTrace = DeviceConfigHelper.getTestBoolean(
-                    DeviceConfigHelper.DISABLE_DELETE_UNREDACTED_TRACE, false);
+            mKeepResultInTempDir = DeviceConfigHelper.getTestBoolean(
+                    DeviceConfigHelper.DISABLE_DELETE_TEMPORARY_RESULTS, false);
 
             mPersistFrequencyMs = new AtomicInteger(DeviceConfigHelper.getInt(
                     DeviceConfigHelper.PERSIST_TO_DISK_FREQUENCY_MS,
@@ -345,8 +347,8 @@ public class ProfilingService extends IProfilingService.Stub {
                     @Override
                     public void onPropertiesChanged(@NonNull DeviceConfig.Properties properties) {
                         synchronized (mLock) {
-                            mKeepUnredactedTrace = properties.getBoolean(
-                                    DeviceConfigHelper.DISABLE_DELETE_UNREDACTED_TRACE, false);
+                            mKeepResultInTempDir = properties.getBoolean(
+                                    DeviceConfigHelper.DISABLE_DELETE_TEMPORARY_RESULTS, false);
                             getRateLimiter().maybeUpdateRateLimiterDisabled(properties);
 
                             String newTestPackageName = properties.getString(
@@ -588,7 +590,7 @@ public class ProfilingService extends IProfilingService.Stub {
         // Populate in memory app triggers store
         for (int i = 0; i < wrapper.getTriggersCount(); i++) {
             ProfilingTriggersWrapper.ProfilingTrigger triggerProto = wrapper.getTriggers(i);
-            addTrigger(new ProfilingTrigger(triggerProto), false);
+            addTrigger(new ProfilingTriggerData(triggerProto), false);
         }
 
         mAppTriggersLoaded = true;
@@ -789,11 +791,19 @@ public class ProfilingService extends IProfilingService.Stub {
                     // Redaction needed, kick it off.
                     handleRedactionRequiredResult(session);
                 } else {
+                    // For results that don't require redaction, maybe log the location of the
+                    // retained result after profiling completes.
+                    handleRetainedTempFiles(session);
+
                     // No redaction needed, move straight to copying to app storage.
                     beginMoveFileToAppStorage(session);
                 }
                 break;
             case REDACTED:
+                // For results that require redaction, maybe log the location of the retained result
+                // after redaction completes.
+                handleRetainedTempFiles(session);
+
                 // Redaction completed, move on to copying to app storage.
                 beginMoveFileToAppStorage(session);
                 break;
@@ -847,6 +857,12 @@ public class ProfilingService extends IProfilingService.Stub {
     @GuardedBy("mLock")
     @VisibleForTesting
     public void cleanupTemporaryDirectoryLocked(String temporaryDirectoryPath) {
+        if (mKeepResultInTempDir) {
+            // Don't clean up any temporary files while {@link mKeepResultInTempDir} is enabled as
+            // files are being retained for testing purposes.
+            return;
+        }
+
         // Obtain a list of all currently tracked files and create a filter with it. Filter is set
         // to null if the list is empty as that will efficiently accept all files.
         final List<String> trackedFilenames = getTrackedFilenames();
@@ -961,7 +977,7 @@ public class ProfilingService extends IProfilingService.Stub {
             if (DEBUG) Log.d(TAG, "Invalid request profiling type: " + profilingType);
             processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
                     ProfilingResult.ERROR_FAILED_INVALID_REQUEST, null, tag,
-                    "Invalid request profiling type");
+                    "Invalid request profiling type", getTriggerTypeNone());
             return;
         }
 
@@ -971,13 +987,15 @@ public class ProfilingService extends IProfilingService.Stub {
         try {
             if (areAnyTracesRunning()) {
                 processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
-                        ProfilingResult.ERROR_FAILED_PROFILING_IN_PROGRESS, null, tag, null);
+                        ProfilingResult.ERROR_FAILED_PROFILING_IN_PROGRESS, null, tag, null,
+                        getTriggerTypeNone());
                 return;
             }
         } catch (RuntimeException e) {
             if (DEBUG) Log.d(TAG, "Error communicating with perfetto", e);
             processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
-                    ProfilingResult.ERROR_UNKNOWN, null, tag, "Error communicating with perfetto");
+                    ProfilingResult.ERROR_UNKNOWN, null, tag, "Error communicating with perfetto",
+                    getTriggerTypeNone());
             return;
         }
 
@@ -985,7 +1003,8 @@ public class ProfilingService extends IProfilingService.Stub {
             // This shouldn't happen as it should be checked on the app side.
             if (DEBUG) Log.d(TAG, "PackageName is null");
             processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
-                    ProfilingResult.ERROR_UNKNOWN, null, tag, "Couldn't determine package name");
+                    ProfilingResult.ERROR_UNKNOWN, null, tag, "Couldn't determine package name",
+                    getTriggerTypeNone());
             return;
         }
 
@@ -994,7 +1013,8 @@ public class ProfilingService extends IProfilingService.Stub {
             // Failed to get uids for this package, can't validate package name.
             if (DEBUG) Log.d(TAG, "Failed to resolve package name");
             processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
-                    ProfilingResult.ERROR_UNKNOWN, null, tag, "Couldn't determine package name");
+                    ProfilingResult.ERROR_UNKNOWN, null, tag, "Couldn't determine package name",
+                    getTriggerTypeNone());
             return;
         }
 
@@ -1010,7 +1030,7 @@ public class ProfilingService extends IProfilingService.Stub {
             if (DEBUG) Log.d(TAG, "Package name not associated with calling uid");
             processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
                     ProfilingResult.ERROR_FAILED_INVALID_REQUEST, null, tag,
-                    "Package name not associated with calling uid.");
+                    "Package name not associated with calling uid.", getTriggerTypeNone());
             return;
         }
 
@@ -1022,7 +1042,7 @@ public class ProfilingService extends IProfilingService.Stub {
             // Rate limiter approved, try to start the request.
             try {
                 TracingSession session = new TracingSession(profilingType, params, uid,
-                        packageName, tag, keyMostSigBits, keyLeastSigBits);
+                        packageName, tag, keyMostSigBits, keyLeastSigBits, getTriggerTypeNone());
                 advanceTracingSession(session, TracingState.APPROVED);
                 return;
             } catch (IllegalArgumentException e) {
@@ -1034,23 +1054,36 @@ public class ProfilingService extends IProfilingService.Stub {
                             e);
                 }
                 processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
-                        ProfilingResult.ERROR_FAILED_INVALID_REQUEST, null, tag, e.getMessage());
+                        ProfilingResult.ERROR_FAILED_INVALID_REQUEST, null, tag, e.getMessage(),
+                        getTriggerTypeNone());
                 return;
             } catch (RuntimeException e) {
                 // Perfetto error. Systems fault.
                 if (DEBUG) Log.d(TAG, "Perfetto error", e);
                 processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
-                        ProfilingResult.ERROR_UNKNOWN, null, tag, "Perfetto error");
+                        ProfilingResult.ERROR_UNKNOWN, null, tag, "Perfetto error",
+                        getTriggerTypeNone());
                 return;
             }
         } else {
             // Rate limiter denied, notify caller.
             if (DEBUG) Log.d(TAG, "Request denied with status: " + status);
             processResultCallback(uid, keyMostSigBits, keyLeastSigBits,
-                    RateLimiter.statusToResult(status), null, tag, null);
+                    RateLimiter.statusToResult(status), null, tag, null, getTriggerTypeNone());
         }
     }
 
+    /**
+     * Convenience method to make checking the flag for obtaining trigger type none value in code
+     * cleaner. When cleaning up the system triggered flag, remove this method and inline the value.
+     */
+    private int getTriggerTypeNone() {
+        if (Flags.systemTriggeredProfilingNew()) {
+            return ProfilingTrigger.TRIGGER_TYPE_NONE;
+        }
+        return 0;
+    }
+
     /** Call from application to register a callback object. */
     public void registerResultsCallback(boolean isGeneralCallback,
             IProfilingResultCallback callback) {
@@ -1122,6 +1155,9 @@ public class ProfilingService extends IProfilingService.Stub {
         handleQueuedResults(Binder.getCallingUid());
     }
 
+    /**
+     * Call from application to request the stopping of an active profiling with the provided key.
+     */
     public void requestCancel(long keyMostSigBits, long keyLeastSigBits) {
         String key = (new UUID(keyMostSigBits, keyLeastSigBits)).toString();
         if (!isTraceRunning(key)) {
@@ -1153,7 +1189,7 @@ public class ProfilingService extends IProfilingService.Stub {
      * name and the uid of the caller.
      */
     public void removeProfilingTriggers(int[] triggerTypesToRemove, String packageName) {
-        SparseArray<ProfilingTrigger> triggers =
+        SparseArray<ProfilingTriggerData> triggers =
                 mAppTriggers.get(packageName, Binder.getCallingUid());
 
         for (int i = 0; i < triggerTypesToRemove.length; i++) {
@@ -1343,7 +1379,7 @@ public class ProfilingService extends IProfilingService.Stub {
         boolean succeeded = processResultCallback(session.getUid(), session.getKeyMostSigBits(),
                 session.getKeyLeastSigBits(), session.getErrorStatus(),
                 session.getDestinationFileName(OUTPUT_FILE_RELATIVE_PATH),
-                session.getTag(), session.getErrorMessage());
+                session.getTag(), session.getErrorMessage(), session.getTriggerType());
 
         if (continueAdvancing && succeeded) {
             advanceTracingSession(session, TracingState.NOTIFIED_REQUESTER);
@@ -1363,7 +1399,7 @@ public class ProfilingService extends IProfilingService.Stub {
      */
     private boolean processResultCallback(int uid, long keyMostSigBits, long keyLeastSigBits,
             int status, @Nullable String fileResultPathAndName, @Nullable String tag,
-            @Nullable String error) {
+            @Nullable String error, int triggerType) {
         List<IProfilingResultCallback> perUidCallbacks = mResultCallbacks.get(uid);
         if (perUidCallbacks == null || perUidCallbacks.isEmpty()) {
             // No callbacks, nowhere to notify with result or failure.
@@ -1377,10 +1413,10 @@ public class ProfilingService extends IProfilingService.Stub {
                 if (status == ProfilingResult.ERROR_NONE) {
                     perUidCallbacks.get(i).sendResult(
                             fileResultPathAndName, keyMostSigBits, keyLeastSigBits, status, tag,
-                            error);
+                            error, triggerType);
                 } else {
                     perUidCallbacks.get(i).sendResult(
-                            null, keyMostSigBits, keyLeastSigBits, status, tag, error);
+                            null, keyMostSigBits, keyLeastSigBits, status, tag, error, triggerType);
                 }
                 // One success is all we need to know that a callback was sent to the app.
                 // This is not perfect but sufficient given we cannot verify the success of
@@ -1420,7 +1456,9 @@ public class ProfilingService extends IProfilingService.Stub {
             // Request couldn't be processed. This shouldn't happen.
             if (DEBUG) Log.d(TAG, "Request couldn't be processed", e);
             session.setError(ProfilingResult.ERROR_FAILED_INVALID_REQUEST, e.getMessage());
-            moveSessionToQueue(session, true);
+            // Don't bother adding the session to the queue as there is no real value in trying to
+            // deliver this error callback again later in the case that the app no longer has a
+            // registered listener.
             advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
 
@@ -1448,7 +1486,9 @@ public class ProfilingService extends IProfilingService.Stub {
             mActiveTracingSessions.put(session.getKey(), session);
         } else {
             session.setError(ProfilingResult.ERROR_FAILED_EXECUTING, "Trace couldn't be started");
-            moveSessionToQueue(session, true);
+            // Don't bother adding the session to the queue as there is no real value in trying to
+            // deliver this error callback again later in the case that the app no longer has a
+            // registered listener.
             advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
         }
@@ -1466,7 +1506,12 @@ public class ProfilingService extends IProfilingService.Stub {
         advanceTracingSession(session, TracingState.PROFILING_STARTED);
     }
 
-    /** Start a trace to be used for system triggered profiling. */
+    /**
+     * Start a trace to be used for system triggered profiling.
+     *
+     * This should not be called while a system triggered trace is already running. If it is called
+     * with a system triggered trace in progress, this request will be dropped.
+     */
     @VisibleForTesting
     public void startSystemTriggeredTrace() {
         if (!Flags.systemTriggeredProfilingNew()) {
@@ -1482,31 +1527,48 @@ public class ProfilingService extends IProfilingService.Stub {
             return;
         }
 
-        String[] packageNames = getActiveTriggerPackageNames();
-        if (packageNames.length == 0) {
-            // No apps have registered interest in system triggered profiling, so don't bother to
-            // start a trace for it.
-            if (DEBUG) {
-                Log.d(TAG,
-                        "System triggered trace not started due to no apps registering interest");
+        synchronized (mLock) {
+            // Everything from the check if a system triggered trace is in progress to updating the
+            // object to the new running trace should be in a single synchronized block to ensure
+            // that another system triggered start is not attempted while one is in progress.
+
+            if (mSystemTriggeredTraceProcess != null && mSystemTriggeredTraceProcess.isAlive()) {
+                // Only 1 system triggered trace should be running at a time. If one is already
+                // running then this should not be called, return.
+                if (DEBUG) {
+                    Log.d(TAG, "System triggered trace not started due to a system triggered trace "
+                            + "already in progress.");
+                }
+                return;
+            }
+
+            String[] packageNames = getActiveTriggerPackageNames();
+            if (packageNames.length == 0) {
+                // No apps have registered interest in system triggered profiling, so don't bother
+                // to start a trace for it.
+                if (DEBUG) {
+                    Log.d(TAG, "System triggered trace not started due to no apps registering "
+                            + "interest");
+                }
+                return;
             }
-            return;
-        }
 
-        String uniqueSessionName = SYSTEM_TRIGGERED_SESSION_NAME_PREFIX
-                + System.currentTimeMillis();
+            String uniqueSessionName = SYSTEM_TRIGGERED_SESSION_NAME_PREFIX
+                    + System.currentTimeMillis();
 
-        byte[] config = Configs.generateSystemTriggeredTraceConfig(uniqueSessionName, packageNames,
-                mTestPackageName != null);
-        String outputFile = TEMP_TRACE_PATH + SYSTEM_TRIGGERED_SESSION_NAME_PREFIX
-                + OUTPUT_FILE_IN_PROGRESS + OUTPUT_FILE_UNREDACTED_TRACE_SUFFIX;
+            byte[] config = Configs.generateSystemTriggeredTraceConfig(uniqueSessionName,
+                    packageNames,
+                    mTestPackageName != null);
+            String outputFile = TEMP_TRACE_PATH + SYSTEM_TRIGGERED_SESSION_NAME_PREFIX
+                    + OUTPUT_FILE_IN_PROGRESS + OUTPUT_FILE_UNREDACTED_TRACE_SUFFIX;
 
-        Process activeTrace = startProfilingProcess(config, outputFile);
+            Process activeTrace = startProfilingProcess(config, outputFile);
 
-        if (activeTrace != null) {
-            mSystemTriggeredTraceProcess = activeTrace;
-            mSystemTriggeredTraceUniqueSessionName = uniqueSessionName;
-            mLastStartedSystemTriggeredTraceMs = System.currentTimeMillis();
+            if (activeTrace != null) {
+                mSystemTriggeredTraceProcess = activeTrace;
+                mSystemTriggeredTraceUniqueSessionName = uniqueSessionName;
+                mLastStartedSystemTriggeredTraceMs = System.currentTimeMillis();
+            }
         }
     }
 
@@ -1526,7 +1588,7 @@ public class ProfilingService extends IProfilingService.Stub {
             return activeProfiling;
         } catch (Exception e) {
             // Catch all exceptions related to starting process as they'll all be handled similarly.
-            if (DEBUG) Log.d(TAG, "Profiling couldn't be started", e);
+            if (DEBUG) Log.e(TAG, "Profiling couldn't be started", e);
             return null;
         }
     }
@@ -1560,31 +1622,35 @@ public class ProfilingService extends IProfilingService.Stub {
      */
     @VisibleForTesting
     public void processTriggerInternal(int uid, @NonNull String packageName, int triggerType) {
-        if (mSystemTriggeredTraceUniqueSessionName == null) {
-            // If we don't have the session name then we don't know how to clone the trace so stop
-            // it if it's still running and then return.
-            stopSystemTriggeredTrace();
+        synchronized (mLock) {
+            if (mSystemTriggeredTraceUniqueSessionName == null) {
+                // If we don't have the session name then we don't know how to clone the trace so
+                // stop it if it's still running and then return.
+                stopSystemTriggeredTraceLocked();
 
-            // There is no active system triggered trace so there's nothing to clone. Return.
-            if (DEBUG) {
-                Log.d(TAG, "Requested clone system triggered trace but we don't have the session "
-                        + "name.");
+                // There is no active system triggered trace so there's nothing to clone. Return.
+                if (DEBUG) {
+                    Log.d(TAG, "Requested clone system triggered trace but we don't have the "
+                            + "session name.");
+                }
+                return;
             }
-            return;
-        }
 
-        if (mSystemTriggeredTraceProcess == null || !mSystemTriggeredTraceProcess.isAlive()) {
-            // If we make it to this path then session name wasn't set to null but can't be used
-            // anymore as its associated trace is not running, so set to null now.
-            mSystemTriggeredTraceUniqueSessionName = null;
+            if (mSystemTriggeredTraceProcess == null || !mSystemTriggeredTraceProcess.isAlive()) {
+                // If we make it to this path then session name wasn't set to null but can't be used
+                // anymore as its associated trace is not running, so set to null now.
+                mSystemTriggeredTraceUniqueSessionName = null;
 
-            // There is no active system triggered trace so there's nothing to clone. Return.
-            if (DEBUG) Log.d(TAG, "Requested clone system triggered trace but no trace active.");
-            return;
+                // There is no active system triggered trace so there's nothing to clone. Return.
+                if (DEBUG) {
+                    Log.d(TAG, "Requested clone system triggered trace but no trace active.");
+                }
+                return;
+            }
         }
 
         // Then check if the app has registered interest in this combo.
-        SparseArray<ProfilingTrigger> perProcessTriggers = mAppTriggers.get(packageName, uid);
+        SparseArray<ProfilingTriggerData> perProcessTriggers = mAppTriggers.get(packageName, uid);
         if (perProcessTriggers == null) {
             // This uid hasn't registered any triggers.
             if (DEBUG) {
@@ -1594,7 +1660,7 @@ public class ProfilingService extends IProfilingService.Stub {
             return;
         }
 
-        ProfilingTrigger trigger = perProcessTriggers.get(triggerType);
+        ProfilingTriggerData trigger = perProcessTriggers.get(triggerType);
         if (trigger == null) {
             // This uid hasn't registered a trigger for this type.
             if (DEBUG) {
@@ -1682,6 +1748,7 @@ public class ProfilingService extends IProfilingService.Stub {
                 ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE, uid, packageName, triggerType);
         session.setRedactedFileName(baseFileName + OUTPUT_FILE_TRACE_SUFFIX);
         session.setFileName(unredactedFullName);
+        session.setProfilingStartTimeMs(System.currentTimeMillis());
         moveSessionToQueue(session, true);
         advanceTracingSession(session, TracingState.PROFILING_FINISHED);
 
@@ -1692,7 +1759,7 @@ public class ProfilingService extends IProfilingService.Stub {
     @VisibleForTesting
     public void addTrigger(int uid, @NonNull String packageName, int triggerType,
             int rateLimitingPeriodHours) {
-        addTrigger(new ProfilingTrigger(uid, packageName, triggerType, rateLimitingPeriodHours),
+        addTrigger(new ProfilingTriggerData(uid, packageName, triggerType, rateLimitingPeriodHours),
                 true);
     }
 
@@ -1704,17 +1771,17 @@ public class ProfilingService extends IProfilingService.Stub {
      *                          intended to be set to false only when loading triggers from disk.
      */
     @VisibleForTesting
-    public void addTrigger(ProfilingTrigger trigger, boolean maybePersist) {
+    public void addTrigger(ProfilingTriggerData trigger, boolean maybePersist) {
         if (!Flags.systemTriggeredProfilingNew()) {
             // Flag disabled.
             return;
         }
 
-        SparseArray<ProfilingTrigger> perProcessTriggers = mAppTriggers.get(
+        SparseArray<ProfilingTriggerData> perProcessTriggers = mAppTriggers.get(
                 trigger.getPackageName(), trigger.getUid());
 
         if (perProcessTriggers == null) {
-            perProcessTriggers = new SparseArray<ProfilingTrigger>();
+            perProcessTriggers = new SparseArray<ProfilingTriggerData>();
             mAppTriggers.put(trigger.getPackageName(), trigger.getUid(), perProcessTriggers);
         }
 
@@ -1783,12 +1850,14 @@ public class ProfilingService extends IProfilingService.Stub {
         }
     }
 
-    private void stopProfiling(String key) throws RuntimeException {
+    /** Stop active profiling for the given session key. */
+    private void stopProfiling(String key) {
         TracingSession session = mActiveTracingSessions.get(key);
         stopProfiling(session);
     }
 
-    private void stopProfiling(TracingSession session) throws RuntimeException {
+    /** Stop active profiling for the given session. */
+    private void stopProfiling(TracingSession session) {
         if (session == null || session.getActiveTrace() == null) {
             if (DEBUG) Log.d(TAG, "No active trace, nothing to stop.");
             return;
@@ -1812,16 +1881,18 @@ public class ProfilingService extends IProfilingService.Stub {
             if (!session.getActiveTrace().waitFor(mPerfettoDestroyTimeoutMs,
                     TimeUnit.MILLISECONDS)) {
                 if (DEBUG) Log.d(TAG, "Stopping of running trace process timed out.");
-                throw new RuntimeException("Stopping of running trace process timed out.");
+                return;
             }
         } catch (InterruptedException e) {
-            throw new RuntimeException(e);
+            if (DEBUG) Log.d(TAG, "Stopping of running trace error occurred.", e);
+            return;
         }
 
         // If we made it here the result is ready, now run the post processing runnable.
         getHandler().post(session.getProcessResultRunnable());
     }
 
+    /** Check whether a profiling session is running. Not specific to any process. */
     public boolean areAnyTracesRunning() throws RuntimeException {
         for (int i = 0; i < mActiveTracingSessions.size(); i++) {
             if (isTraceRunning(mActiveTracingSessions.keyAt(i))) {
@@ -1866,6 +1937,7 @@ public class ProfilingService extends IProfilingService.Stub {
         }
     }
 
+    /** Check whether a profiling session with the provided key is currently running. */
     public boolean isTraceRunning(String key) throws RuntimeException {
         TracingSession session = mActiveTracingSessions.get(key);
         if (session == null || session.getActiveTrace() == null) {
@@ -2047,27 +2119,78 @@ public class ProfilingService extends IProfilingService.Stub {
                 Log.d(TAG, String.format("Redaction processed failed with error code: %s",
                         redactionErrorCode));
             }
-            cleanupTracingSession(session);
             session.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING);
             advanceTracingSession(session, TracingState.ERROR_OCCURRED);
             return;
         }
 
         // At this point redaction has completed successfully it is safe to delete the
-        // unredacted trace file unless {@link mKeepUnredactedTrace} has been enabled.
+        // unredacted trace file unless {@link mKeepResultInTempDir} has been enabled.
         synchronized (mLock) {
-            if (mKeepUnredactedTrace) {
-                Log.i(TAG, "Unredacted trace file retained at: "
-                        + TEMP_TRACE_PATH + session.getFileName());
-            } else {
-                // TODO b/331988161 Delete after file is delivered to app.
-                maybeDeleteUnredactedTrace(session);
+            if (!mKeepResultInTempDir) {
+                deleteProfilingFiles(session,
+                        false, /* Don't delete the newly redacted file */
+                        true); /* Do delete the no longer needed unredacted file.*/
             }
         }
 
         advanceTracingSession(session, TracingState.REDACTED);
     }
 
+    /**
+     * Handle retained temporary files due to {@link mKeepResultInTempDir} being enabled, by
+     * attempting to make them publicly readable and logging their location
+     */
+    private void handleRetainedTempFiles(TracingSession session) {
+        synchronized (mLock) {
+            if (!mKeepResultInTempDir) {
+                // Results are only retained if {@link mKeepResultInTempDir} is enabled, so don't
+                // log the locations if it's disabled.
+                return;
+            }
+
+            // For all types, output the location of the original profiling output file. For trace,
+            // this will be the unredacted copy. For all other types, this will be the only output
+            // file.
+            boolean makeReadableSucceeded = makeFileReadable(session.getFileName());
+            logRetainedFileDetails(session.getFileName(), makeReadableSucceeded);
+
+            if (session.getProfilingType() == ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE) {
+                // For a trace, output the location of the redacted file.
+                makeReadableSucceeded = makeFileReadable(session.getRedactedFileName());
+                logRetainedFileDetails(session.getFileName(), makeReadableSucceeded);
+            }
+        }
+    }
+
+    /** Wrapper to log all necessary information about retained file locations. */
+    private void logRetainedFileDetails(String fileName, boolean readable) {
+        if (readable) {
+            Log.i(TAG, "Profiling file retained at: " + TEMP_TRACE_PATH + fileName);
+        } else {
+            Log.i(TAG, "Profiling file retained at: " + TEMP_TRACE_PATH + fileName
+                    + " | File is not publicly accessible, root access is required to read.");
+        }
+    }
+
+    /**
+     * Make the provided file within the temp trace directory publicly readable. Access is still
+     * limited by selinux so only adbd will be additionally able to access the file due to this
+     * change.
+     *
+     * @return whether making the file readable succeeded.
+     */
+    @SuppressWarnings("SetWorldReadable")
+    private boolean makeFileReadable(String fileName) {
+        try {
+            File file = new File(TEMP_TRACE_PATH + fileName);
+            return file.setReadable(true, false);
+        } catch (Exception e) {
+            Log.w(TAG, "Failed to make file readable for testing.", e);
+            return false;
+        }
+    }
+
     /**
      * Called whenever a new global listener has been added to the specified uid.
      * Attempts to process queued results if present.
@@ -2149,26 +2272,18 @@ public class ProfilingService extends IProfilingService.Stub {
      */
     private void cleanupTracingSession(TracingSession session,
             @Nullable List<TracingSession> queuedSessions) {
-        // Delete all files
-        if (session.getProfilingType() == ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE) {
-            // If type is trace, try to delete the temp file only if {@link mKeepUnredactedTrace} is
-            // false, and always try to delete redacted file.
-            maybeDeleteUnredactedTrace(session);
-            try {
-                Files.delete(Path.of(TEMP_TRACE_PATH + session.getRedactedFileName()));
-            } catch (Exception exception) {
-                if (DEBUG) Log.e(TAG, "Failed to delete file for discarded record.", exception);
-            }
-        } else {
-            // If type is not trace, try to delete the temp file. There is no redacted file.
-            try {
-                Files.delete(Path.of(TEMP_TRACE_PATH + session.getFileName()));
-            } catch (Exception exception) {
-                if (DEBUG) Log.e(TAG, "Failed to delete file for discarded record.", exception);
+        synchronized (mLock) {
+            if (mKeepResultInTempDir) {
+                // If {@link mKeepResultInTempDir} is enabled, don't cleanup anything. Continue
+                // progressing as if cleanup is complete.
+                advanceTracingSession(session, TracingState.CLEANED_UP);
+                return;
             }
-
         }
 
+        // Delete all files
+        deleteProfilingFiles(session, true, true);
+
         if (queuedSessions != null) {
             queuedSessions.remove(session);
             if (queuedSessions.isEmpty()) {
@@ -2180,17 +2295,26 @@ public class ProfilingService extends IProfilingService.Stub {
     }
 
     /**
-     * Attempt to delete unredacted trace unless mKeepUnredactedTrace is enabled.
+     * Attempt to delete profiling output.
      *
-     * Note: only to be called for types that support redaction.
+     * If both boolean params are false, this method expectedly does nothing.
+     *
+     * @param deleteRedacted Whether to delete the redacted file.
+     * @param deleteUnredacted Whether to delete the unredacted file.
      */
-    private void maybeDeleteUnredactedTrace(TracingSession session) {
-        synchronized (mLock) {
-            if (mKeepUnredactedTrace) {
-                return;
+    private void deleteProfilingFiles(TracingSession session, boolean deleteRedacted,
+            boolean deleteUnredacted) {
+        if (deleteRedacted) {
+            try {
+                Files.deleteIfExists(Path.of(TEMP_TRACE_PATH + session.getRedactedFileName()));
+            } catch (Exception exception) {
+                if (DEBUG) Log.e(TAG, "Failed to delete file.", exception);
             }
+        }
+
+        if (deleteUnredacted) {
             try {
-                Files.delete(Path.of(TEMP_TRACE_PATH + session.getFileName()));
+                Files.deleteIfExists(Path.of(TEMP_TRACE_PATH + session.getFileName()));
             } catch (Exception exception) {
                 if (DEBUG) Log.e(TAG, "Failed to delete file.", exception);
             }
@@ -2204,11 +2328,20 @@ public class ProfilingService extends IProfilingService.Stub {
      * Sessions are expected to be in the queue when their states are between PROFILING_FINISHED and
      * NOTIFIED_REQUESTER, inclusive.
      *
+     * Sessions should only be added to the queue with a valid profiling start time. Sessions added
+     * without a valid start time may be cleaned up in middle of their execution and fail to deliver
+     * any result.
+     *
      * @param session      the session to move to the queue
      * @param maybePersist whether to persist the queue to disk if the queue is eligible to be
      *          persisted
      */
     private void moveSessionToQueue(TracingSession session, boolean maybePersist) {
+        if (DEBUG && session.getProfilingStartTimeMs() == 0) {
+            Log.e(TAG, "Attempting to move session to queue without a start time set.",
+                    new Throwable());
+        }
+
         List<TracingSession> queuedResults = mQueuedTracingResults.get(session.getUid());
         if (queuedResults == null) {
             queuedResults = new ArrayList<TracingSession>();
@@ -2483,20 +2616,21 @@ public class ProfilingService extends IProfilingService.Stub {
 
     /** Receive a callback with each of the tracked profiling triggers. */
     private void forEachTrigger(
-            ArrayMap<String, SparseArray<SparseArray<ProfilingTrigger>>> triggersOuterMap,
-            Consumer<ProfilingTrigger> callback) {
+            ArrayMap<String, SparseArray<SparseArray<ProfilingTriggerData>>> triggersOuterMap,
+            Consumer<ProfilingTriggerData> callback) {
 
         for (int i = 0; i < triggersOuterMap.size(); i++) {
-            SparseArray<SparseArray<ProfilingTrigger>> triggerUidList = triggersOuterMap.valueAt(i);
+            SparseArray<SparseArray<ProfilingTriggerData>> triggerUidList =
+                    triggersOuterMap.valueAt(i);
 
             for (int j = 0; j < triggerUidList.size(); j++) {
                 int uidKey = triggerUidList.keyAt(j);
-                SparseArray<ProfilingTrigger> triggersList = triggerUidList.get(uidKey);
+                SparseArray<ProfilingTriggerData> triggersList = triggerUidList.get(uidKey);
 
                 if (triggersList != null) {
                     for (int k = 0; k < triggersList.size(); k++) {
                         int triggerTypeKey = triggersList.keyAt(k);
-                        ProfilingTrigger trigger = triggersList.get(triggerTypeKey);
+                        ProfilingTriggerData trigger = triggersList.get(triggerTypeKey);
 
                         if (trigger != null) {
                             callback.accept(trigger);
@@ -2517,7 +2651,7 @@ public class ProfilingService extends IProfilingService.Stub {
 
                 // New null state is a changed from previous state, disable test mode.
                 mTestPackageName = null;
-                stopSystemTriggeredTrace();
+                stopSystemTriggeredTraceLocked();
             }
             // If new state is unchanged from previous null state, do nothing.
         } else {
@@ -2528,7 +2662,7 @@ public class ProfilingService extends IProfilingService.Stub {
             // device config should not be sending an update for a value change when the value
             // remains the same, but no need to check as the best experience for caller is to always
             // stop the current trace and start a new one for most up to date package list.
-            stopSystemTriggeredTrace();
+            stopSystemTriggeredTraceLocked();
 
             // Now update the test package name and start the system triggered trace.
             mTestPackageName = newTestPackageName;
@@ -2536,8 +2670,14 @@ public class ProfilingService extends IProfilingService.Stub {
         }
     }
 
-    /** Stop the system triggered trace. */
-    private void stopSystemTriggeredTrace() {
+    /**
+     * Stop the system triggered trace.
+     *
+     * Locked because {link mSystemTriggeredTraceProcess} is guarded and all callers are already
+     * locked.
+     */
+    @GuardedBy("mLock")
+    private void stopSystemTriggeredTraceLocked() {
         // If the trace is alive, stop it.
         if (mSystemTriggeredTraceProcess != null) {
             if (mSystemTriggeredTraceProcess.isAlive()) {
diff --git a/service/java/com/android/os/profiling/ProfilingTrigger.java b/service/java/com/android/os/profiling/ProfilingTriggerData.java
similarity index 90%
rename from service/java/com/android/os/profiling/ProfilingTrigger.java
rename to service/java/com/android/os/profiling/ProfilingTriggerData.java
index 6800cb0..5a93b5b 100644
--- a/service/java/com/android/os/profiling/ProfilingTrigger.java
+++ b/service/java/com/android/os/profiling/ProfilingTriggerData.java
@@ -19,7 +19,7 @@ package android.os.profiling;
 import android.annotation.NonNull;
 import android.os.ProfilingTriggersWrapper;
 
-public final class ProfilingTrigger {
+public final class ProfilingTriggerData {
     // LINT.IfChange(params)
     private final int mUid;
     @NonNull private final String mPackageName;
@@ -28,7 +28,7 @@ public final class ProfilingTrigger {
     private long mLastTriggeredTimeMs = 0;
     // LINT.ThenChange(:from_proto)
 
-    public ProfilingTrigger(int uid, @NonNull String packageName, int triggerType,
+    public ProfilingTriggerData(int uid, @NonNull String packageName, int triggerType,
             int rateLimitingPeriodHours) {
         mUid = uid;
         mPackageName = packageName;
@@ -37,7 +37,8 @@ public final class ProfilingTrigger {
     }
 
     // LINT.IfChange(from_proto)
-    public ProfilingTrigger(@NonNull ProfilingTriggersWrapper.ProfilingTrigger triggerProto) {
+    /** Create object from proto. */
+    public ProfilingTriggerData(@NonNull ProfilingTriggersWrapper.ProfilingTrigger triggerProto) {
         mUid = triggerProto.getUid();
         mPackageName = triggerProto.getPackageName();
         mTriggerType = triggerProto.getTriggerType();
@@ -72,6 +73,7 @@ public final class ProfilingTrigger {
     }
 
     // LINT.IfChange(to_proto)
+    /** Write object to proto. */
     public ProfilingTriggersWrapper.ProfilingTrigger toProto() {
         ProfilingTriggersWrapper.ProfilingTrigger.Builder builder =
                 ProfilingTriggersWrapper.ProfilingTrigger.newBuilder();
diff --git a/service/java/com/android/os/profiling/RateLimiter.java b/service/java/com/android/os/profiling/RateLimiter.java
index a57b840..7e0a9f2 100644
--- a/service/java/com/android/os/profiling/RateLimiter.java
+++ b/service/java/com/android/os/profiling/RateLimiter.java
@@ -67,7 +67,7 @@ public class RateLimiter {
 
     private final Object mLock = new Object();
 
-    private long mPersistToDiskFrequency;
+    @VisibleForTesting public long mPersistToDiskFrequency;
 
     /** To be disabled for testing only. */
     @GuardedBy("mLock")
@@ -85,11 +85,11 @@ public class RateLimiter {
     @VisibleForTesting
     public final EntryGroupWrapper mPastRunsWeek;
 
-    private int mCostJavaHeapDump;
-    private int mCostHeapProfile;
-    private int mCostStackSampling;
-    private int mCostSystemTrace;
-    private int mCostSystemTriggeredSystemTrace;
+    @VisibleForTesting public int mCostJavaHeapDump;
+    @VisibleForTesting public int mCostHeapProfile;
+    @VisibleForTesting public int mCostStackSampling;
+    @VisibleForTesting public int mCostSystemTrace;
+    @VisibleForTesting public int mCostSystemTriggeredSystemTrace;
 
     private final HandlerCallback mHandlerCallback;
 
@@ -174,6 +174,11 @@ public class RateLimiter {
         setupFromPersistedData();
     }
 
+    /**
+     * Check whether a profiling session with the specific details provided is allowed to run per
+     * current rate limiting restrictions. If the request is allowed, it will be stored as having
+     * run.
+     */
     public @RateLimitResult int isProfilingRequestAllowed(int uid,
             int profilingType, boolean isTriggered, @Nullable Bundle params) {
         synchronized (mLock) {
diff --git a/service/java/com/android/os/profiling/TracingSession.java b/service/java/com/android/os/profiling/TracingSession.java
index 428f00b..e6f8a44 100644
--- a/service/java/com/android/os/profiling/TracingSession.java
+++ b/service/java/com/android/os/profiling/TracingSession.java
@@ -48,6 +48,7 @@ public final class TracingSession {
     @Nullable private String mErrorMessage = null;
     // Expected to be populated with ProfilingResult.ERROR_* values.
     private int mErrorStatus = -1; // Default to invalid value.
+    private long mProfilingStartTimeMs;
     // LINT.ThenChange(:from_proto)
 
     // Non-persisted params
@@ -58,7 +59,6 @@ public final class TracingSession {
     @Nullable private String mKey = null;
     @Nullable private String mDestinationFileName = null;
     private long mRedactionStartTimeMs;
-    private long mProfilingStartTimeMs;
     private int mMaxProfilingTimeAllowedMs = 0;
 
     public TracingSession(int profilingType,  int uid, String packageName, int triggerType) {
@@ -73,19 +73,6 @@ public final class TracingSession {
                 triggerType);
     }
 
-    public TracingSession(int profilingType, Bundle params, int uid, String packageName, String tag,
-            long keyMostSigBits, long keyLeastSigBits) {
-        this(
-                profilingType,
-                params,
-                uid,
-                packageName,
-                tag,
-                keyMostSigBits,
-                keyLeastSigBits,
-                -1); // TODO: b/373461116 - set to NONE after API is published.
-    }
-
     public TracingSession(int profilingType, Bundle params, int uid, String packageName, String tag,
             long keyMostSigBits, long keyLeastSigBits, int triggerType) {
         mProfilingType = profilingType;
@@ -120,6 +107,7 @@ public final class TracingSession {
         }
         mErrorStatus = sessionProto.getErrorStatus();
         mTriggerType = sessionProto.getTriggerType();
+        mProfilingStartTimeMs = sessionProto.getProfilingStartTime();
 
         // params is not persisted because we cannot guarantee that it does not contain some large
         // store of data, and because we don't need it anymore once the request has gotten to the
@@ -138,10 +126,15 @@ public final class TracingSession {
     }
     // LINT.ThenChange(:to_proto)
 
+    /** Generates the config for this request and converts to bytes. */
     public byte[] getConfigBytes() throws IllegalArgumentException {
         return Configs.generateConfigForRequest(mProfilingType, mParams, mPackageName);
     }
 
+    /**
+     * Gets the amount of time before the system should start checking whether the profiling is
+     * complete so that post processing can begin.
+     */
     public int getPostProcessingScheduleDelayMs() throws IllegalArgumentException {
         return Configs.getInitialProfilingTimeMs(mProfilingType, mParams);
     }
@@ -159,6 +152,7 @@ public final class TracingSession {
         return mMaxProfilingTimeAllowedMs;
     }
 
+    /** Get the tracing session unique key which was provided by {@link ProfilingManager}. */
     @Nullable
     public String getKey() {
         if (mKey == null) {
@@ -356,6 +350,7 @@ public final class TracingSession {
         }
         tracingSessionBuilder.setErrorStatus(mErrorStatus);
         tracingSessionBuilder.setTriggerType(mTriggerType);
+        tracingSessionBuilder.setProfilingStartTime(mProfilingStartTimeMs);
 
         return tracingSessionBuilder.build();
     }
diff --git a/service/proto/android/os/queue.proto b/service/proto/android/os/queue.proto
index 33d4fee..03b8418 100644
--- a/service/proto/android/os/queue.proto
+++ b/service/proto/android/os/queue.proto
@@ -1,3 +1,19 @@
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
 syntax = "proto2";
 
 package android.os;
@@ -21,7 +37,9 @@ message QueuedResultsWrapper {
     optional string error_message = 12;
     optional int32 error_status = 13;
     optional int32 trigger_type = 14;
+    optional int64 profiling_start_time = 15;
   }
   repeated TracingSession sessions = 1;
 }
-// LINT.ThenChange(/service/java/com/android/os/profiling/TracingSession.java:persisted_params)
\ No newline at end of file
+// LINT.ThenChange(/service/java/com/android/os/profiling/TracingSession.java:persisted_params)
+
diff --git a/service/proto/android/os/ratelimiter.proto b/service/proto/android/os/ratelimiter.proto
index 9275d94..51c7eb0 100644
--- a/service/proto/android/os/ratelimiter.proto
+++ b/service/proto/android/os/ratelimiter.proto
@@ -1,3 +1,19 @@
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
 syntax = "proto2";
 
 package android.os;
diff --git a/service/proto/android/os/trigger.proto b/service/proto/android/os/trigger.proto
index 186b019..20ac364 100644
--- a/service/proto/android/os/trigger.proto
+++ b/service/proto/android/os/trigger.proto
@@ -1,3 +1,19 @@
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
 syntax = "proto2";
 
 package android.os;
@@ -15,4 +31,5 @@ message ProfilingTriggersWrapper {
   }
   repeated ProfilingTrigger triggers = 1;
 }
-// LINT.ThenChange(/service/java/com/android/os/profiling/ProfilingTrigger.java:params)
\ No newline at end of file
+// LINT.ThenChange(/service/java/com/android/os/profiling/ProfilingTriggerData.java:params)
+
diff --git a/tests/cts/Android.bp b/tests/cts/Android.bp
index 4be6a43..de8e31f 100644
--- a/tests/cts/Android.bp
+++ b/tests/cts/Android.bp
@@ -1,3 +1,19 @@
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
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
     default_team: "trendy_team_system_performance",
@@ -33,6 +49,7 @@ android_test {
         "libcts_profiling_module_test_native",
     ],
     jarjar_rules: "jarjar-rules.txt",
+    test_mainline_modules: ["com.google.android.profiling.apex"],
     test_suites: [
         "cts",
         "general-tests",
diff --git a/tests/cts/OWNERS b/tests/cts/OWNERS
index dcba6ee..0be5b21 100644
--- a/tests/cts/OWNERS
+++ b/tests/cts/OWNERS
@@ -1,3 +1,17 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
 # Bug component: 1495529
 include platform/packages/modules/Profiling:/OWNERS
 
diff --git a/tests/cts/README b/tests/cts/README
index 438122e..1b3a213 100644
--- a/tests/cts/README
+++ b/tests/cts/README
@@ -1,3 +1,19 @@
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
 Building and Running Tests -
 
 Currently the Profiling module is considered a packaged APEX and is not currently configured to run
diff --git a/tests/cts/jarjar-rules.txt b/tests/cts/jarjar-rules.txt
index 69cdc64..48f1123 100644
--- a/tests/cts/jarjar-rules.txt
+++ b/tests/cts/jarjar-rules.txt
@@ -1,3 +1,17 @@
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
 rule com.android.modules.utils.** com.android.internal.profiling.@0
 rule com.google.protobuf.** android.os.protobuf.@1
 
diff --git a/tests/cts/jni/Android.bp b/tests/cts/jni/Android.bp
index bae6880..add2c2a 100644
--- a/tests/cts/jni/Android.bp
+++ b/tests/cts/jni/Android.bp
@@ -1,3 +1,19 @@
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
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
diff --git a/tests/cts/src/android/profiling/cts/ProfilingFrameworkInitializerTests.java b/tests/cts/src/android/profiling/cts/ProfilingFrameworkInitializerTests.java
new file mode 100644
index 0000000..6be1687
--- /dev/null
+++ b/tests/cts/src/android/profiling/cts/ProfilingFrameworkInitializerTests.java
@@ -0,0 +1,63 @@
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
+package android.profiling.cts;
+
+import static org.junit.Assert.assertThrows;
+import static org.mockito.Mockito.mock;
+
+import android.os.ProfilingFrameworkInitializer;
+import android.os.ProfilingServiceManager;
+import android.os.profiling.Flags;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+
+import androidx.test.runner.AndroidJUnit4;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+/**
+ * Tests defined in this class are expected to test the implementation of the
+ * ProfilingFrameworkInitializer APIs.
+ */
+@RunWith(AndroidJUnit4.class)
+public class ProfilingFrameworkInitializerTests {
+
+    /**
+     * ProfilingFrameworkInitializer.setProfilingServiceManager() should only be called by during
+     * system initialization. Calling this API at any other time should throw an exception.
+     */
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_TELEMETRY_APIS)
+    public void testSetProfilingServiceManager() {
+        assertThrows(IllegalStateException.class,
+                () -> ProfilingFrameworkInitializer.setProfilingServiceManager(
+                        mock(ProfilingServiceManager.class)));
+    }
+
+    /**
+     * ProfilingFrameworkInitializer.registerServiceWrappers() should only be called by
+     * SystemServiceRegistry during boot up. Calling this API at any other time should throw an
+     * exception.
+     */
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_TELEMETRY_APIS)
+    public void testRegisterServiceWrappers() {
+        assertThrows(
+                IllegalStateException.class,
+                () -> ProfilingFrameworkInitializer.registerServiceWrappers());
+    }
+}
diff --git a/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java b/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
index d85dcc4..1e3fbb6 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingFrameworkTests.java
@@ -33,6 +33,7 @@ import android.content.Context;
 import android.os.Binder;
 import android.os.Bundle;
 import android.os.CancellationSignal;
+import android.os.Parcel;
 import android.os.ProfilingManager;
 import android.os.ProfilingResult;
 import android.os.ProfilingServiceHelper;
@@ -117,6 +118,7 @@ public final class ProfilingFrameworkTests {
     private static final String COMMAND_OVERRIDE_DEVICE_CONFIG_STRING =
             "device_config put %s %s %s";
     private static final String COMMAND_DELETE_DEVICE_CONFIG_STRING = "device_config delete %s %s";
+    private static final String RESET_NAMESPACE = "device_config reset trusted_defaults %s";
 
     private static final String REAL_PACKAGE_NAME = "com.android.profiling.tests";
 
@@ -142,17 +144,17 @@ public final class ProfilingFrameworkTests {
     public final TestName mTestName = new TestName();
 
     @Before
-    public void setup() {
+    public void setup() throws Exception {
         mContext = ApplicationProvider.getApplicationContext();
         mProfilingManager = mContext.getSystemService(ProfilingManager.class);
         mInstrumentation = InstrumentationRegistry.getInstrumentation();
 
+        executeShellCmd(RESET_NAMESPACE, DeviceConfigHelper.NAMESPACE);
+        executeShellCmd(RESET_NAMESPACE, DeviceConfigHelper.NAMESPACE_TESTING);
+
         // This permission is required for Headless (HSUM) tests, including Auto.
         mInstrumentation.getUiAutomation().adoptShellPermissionIdentity(
                 android.Manifest.permission.INTERACT_ACROSS_USERS_FULL);
-
-        // Disable the rate limiter, we're not testing that in any of these tests.
-        disableRateLimiter();
     }
 
     @SuppressWarnings("GuardedBy") // Suppress warning for mProfilingManager.mProfilingService lock.
@@ -173,9 +175,11 @@ public final class ProfilingFrameworkTests {
     /** Test that request with invalid profiling type fails with correct error output. */
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_TELEMETRY_APIS)
-    public void testInvalidProfilingType() {
+    public void testInvalidProfilingType() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         AppCallback callback = new AppCallback();
 
         // This call is passing an invalid profiling request type and should result in an error.
@@ -196,9 +200,11 @@ public final class ProfilingFrameworkTests {
     /** Test that request with invalid profiling params fails with correct error output. */
     @Test
     @RequiresFlagsEnabled(Flags.FLAG_TELEMETRY_APIS)
-    public void testInvalidProfilingParams() {
+    public void testInvalidProfilingParams() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         AppCallback callback = new AppCallback();
 
         Bundle params = new Bundle();
@@ -227,6 +233,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestJavaHeapDumpSuccess() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideJavaHeapDumpDeviceConfigValues(false, ONE_SECOND_MS, TEN_SECONDS_MS);
 
         AppCallback callback = new AppCallback();
@@ -254,6 +262,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestHeapProfileSuccess() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideHeapProfileDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS, FIVE_SECONDS_MS);
 
         AppCallback callback = new AppCallback();
@@ -289,6 +299,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestStackSamplingSuccess() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideStackSamplingDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS,
                 FIVE_SECONDS_MS);
 
@@ -324,6 +336,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestSystemTraceSuccess() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideSystemTraceDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS, FIVE_SECONDS_MS);
 
         AppCallback callback = new AppCallback();
@@ -351,6 +365,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestJavaHeapDumpCancel() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         // Set override duration and timeout to 10 minutes so we can ensure it finishes early when
         // canceled.
         overrideJavaHeapDumpDeviceConfigValues(false, TEN_MINUTES_MS, TEN_MINUTES_MS);
@@ -386,6 +402,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestHeapProfileCancel() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         // Set override durations to 10 minutes so we can ensure it finishes early when canceled.
         overrideHeapProfileDeviceConfigValues(false, TEN_MINUTES_MS, TEN_MINUTES_MS,
                 TEN_MINUTES_MS);
@@ -421,6 +439,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestStackSamplingCancel() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         // Set override durations to 10 minutes so we can ensure it finishes early when canceled.
         overrideStackSamplingDeviceConfigValues(false, TEN_MINUTES_MS, TEN_MINUTES_MS,
                 TEN_MINUTES_MS);
@@ -456,6 +476,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestSystemTraceCancel() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         // Set override durations to 10 minutes so we can ensure it finishes early when canceled.
         overrideSystemTraceDeviceConfigValues(false, TEN_MINUTES_MS, TEN_MINUTES_MS,
                 TEN_MINUTES_MS);
@@ -492,6 +514,8 @@ public final class ProfilingFrameworkTests {
     public void testUnregisterGeneralListener() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideStackSamplingDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS,
                 FIVE_SECONDS_MS);
 
@@ -526,7 +550,55 @@ public final class ProfilingFrameworkTests {
 
         // Assert that the unregistered callback was not triggered.
         assertNull(callbackGeneral.mResult);
+    }
+
+    /** Test that unregistering all global listeners works and that listeners do not get called. */
+    @Test
+    @SuppressWarnings("GuardedBy") // Suppress warning for mProfilingManager.mCallbacks lock.
+    @RequiresFlagsEnabled(Flags.FLAG_TELEMETRY_APIS)
+    public void testUnregisterAllGeneralListeners() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        disableRateLimiter();
+
+        overrideStackSamplingDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS,
+                FIVE_SECONDS_MS);
+
+        // Clear all existing callbacks.
+        mProfilingManager.mCallbacks.clear();
+
+        // Create 3 callbacks, 2 general and 1 specific.
+        AppCallback callbackSpecific = new AppCallback();
+        AppCallback callbackGeneral1 = new AppCallback();
+        AppCallback callbackGeneral2 = new AppCallback();
+
+        // Register both general callbacks.
+        mProfilingManager.registerForAllProfilingResults(
+                new ProfilingTestUtils.ImmediateExecutor(), callbackGeneral1);
+        mProfilingManager.registerForAllProfilingResults(
+                new ProfilingTestUtils.ImmediateExecutor(), callbackGeneral2);
+
+        // Confirm callbacks are properly registered by checking for size of 2.
+        assertTrue(mProfilingManager.mCallbacks.size() == 2);
+
+        // Now unregister the general callbacks.
+        mProfilingManager.unregisterForAllProfilingResults(null);
+
+        // Now kick off the request.
+        mProfilingManager.requestProfiling(
+                ProfilingManager.PROFILING_TYPE_STACK_SAMPLING,
+                ProfilingTestUtils.getOneSecondDurationParamBundle(),
+                null,
+                null,
+                new ProfilingTestUtils.ImmediateExecutor(),
+                callbackSpecific);
+
+        // Wait until callback#onAccept is triggered so we can confirm the result.
+        waitForCallback(callbackSpecific);
 
+        // Assert that the unregistered callbacks were not triggered.
+        assertNull(callbackGeneral1.mResult);
+        assertNull(callbackGeneral2.mResult);
     }
 
     /** Test that a globally registered listener is triggered along with the specific one. */
@@ -535,6 +607,8 @@ public final class ProfilingFrameworkTests {
     public void testTriggerAllListeners() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideStackSamplingDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS,
                 FIVE_SECONDS_MS);
 
@@ -575,6 +649,8 @@ public final class ProfilingFrameworkTests {
     public void testTriggerAllListenersDifferentContexts() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideStackSamplingDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS,
                 FIVE_SECONDS_MS);
 
@@ -621,6 +697,8 @@ public final class ProfilingFrameworkTests {
     public void testRequestTagInFilename() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideStackSamplingDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS,
                 FIVE_SECONDS_MS);
 
@@ -660,6 +738,8 @@ public final class ProfilingFrameworkTests {
     public void testJavaHeapDumpKillswitchEnabled() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideJavaHeapDumpDeviceConfigValues(true, ONE_SECOND_MS, TEN_SECONDS_MS);
 
         AppCallback callback = new AppCallback();
@@ -686,6 +766,8 @@ public final class ProfilingFrameworkTests {
     public void testHeapProfileKillswitchEnabled() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideHeapProfileDeviceConfigValues(true, ONE_SECOND_MS, FIVE_SECONDS_MS, TEN_SECONDS_MS);
 
         AppCallback callback = new AppCallback();
@@ -712,6 +794,8 @@ public final class ProfilingFrameworkTests {
     public void testStackSamplingKillswitchEnabled() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideStackSamplingDeviceConfigValues(true, ONE_SECOND_MS, FIVE_SECONDS_MS,
                 TEN_SECONDS_MS);
 
@@ -739,6 +823,8 @@ public final class ProfilingFrameworkTests {
     public void testSystemTraceKillswitchEnabled() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideSystemTraceDeviceConfigValues(true, ONE_SECOND_MS, FIVE_SECONDS_MS, TEN_SECONDS_MS);
 
         AppCallback callback = new AppCallback();
@@ -772,6 +858,8 @@ public final class ProfilingFrameworkTests {
     public void testAddGeneralListenerNoCurrentListeners() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         // Setup for no current listener - mProfilingService should be null and mCallbacks empty.
         mProfilingManager.mProfilingService = null;
         mProfilingManager.mCallbacks.clear();
@@ -800,6 +888,8 @@ public final class ProfilingFrameworkTests {
     public void testAddSpecificListenerNoCurrentListeners() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideStackSamplingDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS,
                 FIVE_SECONDS_MS);
 
@@ -832,6 +922,8 @@ public final class ProfilingFrameworkTests {
     public void testAddGeneralListenerWithCurrentListener() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         mProfilingManager.mProfilingService = spy(new ProfilingService(mContext));
 
         AppCallback callback = new AppCallback();
@@ -857,6 +949,8 @@ public final class ProfilingFrameworkTests {
     public void testAddSpecificListenerWithCurrentListener() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         overrideStackSamplingDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS,
                 FIVE_SECONDS_MS);
 
@@ -891,12 +985,18 @@ public final class ProfilingFrameworkTests {
     public void testSystemTriggeredProfiling() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         // First add a trigger
         ProfilingTrigger trigger = new ProfilingTrigger.Builder(ProfilingTrigger.TRIGGER_TYPE_ANR)
                 .setRateLimitingPeriodHours(1)
                 .build();
         mProfilingManager.addProfilingTriggers(List.of(trigger));
 
+        // Verify the trigger and rate limiting period.
+        assertEquals(ProfilingTrigger.TRIGGER_TYPE_ANR, trigger.getTriggerType());
+        assertEquals(1, trigger.getRateLimitingPeriodHours());
+
         // And add a global listener
         AppCallback callbackGeneral = new AppCallback();
         mProfilingManager.registerForAllProfilingResults(
@@ -920,7 +1020,8 @@ public final class ProfilingFrameworkTests {
         waitForCallback(callbackGeneral);
 
         // Finally, confirm that a result was received.
-        confirmCollectionSuccess(callbackGeneral.mResult, OUTPUT_FILE_TRACE_SUFFIX);
+        confirmCollectionSuccess(callbackGeneral.mResult, OUTPUT_FILE_TRACE_SUFFIX,
+                ProfilingTrigger.TRIGGER_TYPE_ANR);
     }
 
     /**
@@ -935,6 +1036,8 @@ public final class ProfilingFrameworkTests {
     public void testSystemTriggeredProfilingRemove() throws Exception {
         if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
 
+        disableRateLimiter();
+
         // First add a trigger
         ProfilingTrigger trigger = new ProfilingTrigger.Builder(ProfilingTrigger.TRIGGER_TYPE_ANR)
                 .setRateLimitingPeriodHours(1)
@@ -971,18 +1074,258 @@ public final class ProfilingFrameworkTests {
         assertNull(callbackGeneral.mResult);
     }
 
+    /**
+     * Test clearing all profiling triggers.
+     *
+     * There is no way to check the data structure from this context and that specifically is tested
+     * in {@link ProfilingServiceTests}, so this test just ensures that a result is not received.
+     */
+    @SuppressWarnings("GuardedBy") // Suppress warning for mProfilingManager lock.
+    @Test
+    @RequiresFlagsEnabled(android.os.profiling.Flags.FLAG_SYSTEM_TRIGGERED_PROFILING_NEW)
+    public void testSystemTriggeredProfilingClear() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        disableRateLimiter();
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
+        // Clear all triggers for this process.
+        mProfilingManager.clearProfilingTriggers();
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
+    /**
+     * Test {@link ProfilingResult} parcel read and write implementations match, correctly loading
+     * result with the same values and leaving no data unread.
+     */
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_TELEMETRY_APIS)
+    public void testProfilingResultParcelReadWriteMatch() throws Exception {
+        // Create a fake ProfilingResult with all fields set.
+        ProfilingResult result = new ProfilingResult(
+                ProfilingResult.ERROR_FAILED_RATE_LIMIT_SYSTEM,
+                "/path/to/file.type",
+                "some_tag",
+                "This is an error message.",
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN);
+
+        // Write to parcel.
+        Parcel parcel = Parcel.obtain();
+        result.writeToParcel(parcel, 0 /* flags */);
+
+        // Set the data position back to 0 so it's ready to be read.
+        parcel.setDataPosition(0);
+
+        // Now load from the parcel.
+        ProfilingResult resultFromParcel = new ProfilingResult(parcel);
+
+        // Make sure there is no unread data remaining in the parcel, and confirm that the loaded
+        // object is equal to the one it was written from. Check dataAvail first as if that check
+        // fails then the next check will fail too, but knowing the status of this check will tell
+        // us that we're missing a read or write. Check the objects are equals second as  if the
+        // avail check passes and equals fails, then we know we're reading all the data just not to
+        // the correct fields.
+        assertEquals(0, parcel.dataAvail());
+        assertTrue(result.equals(resultFromParcel));
+    }
+
+    /**
+     * Test that profiling request fails system rate limiter when cost exceeds max.
+     *
+     * This test in particular will fail the hour bucket just to verify end to end a system deny.
+     * Testing for each time bucket is covered in service side tests.
+     */
+    @Test
+    @RequiresFlagsEnabled({Flags.FLAG_TELEMETRY_APIS, Flags.FLAG_REDACTION_ENABLED})
+    public void testRateLimiterDenySystem() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        enableRateLimiter();
+
+        // Override rate limiter values such that the system trace cost is more than the system
+        // limits but less than the process limits.
+        overrideSystemTraceDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS, FIVE_SECONDS_MS);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_1_HOUR, 10);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_24_HOUR, 10);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_7_DAY, 10);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_1_HOUR, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_24_HOUR, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_7_DAY, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.COST_SYSTEM_TRACE, 100);
+
+        AppCallback callback = new AppCallback();
+
+        // Now kick off the request.
+        mProfilingManager.requestProfiling(
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
+                ProfilingTestUtils.getOneSecondDurationParamBundle(),
+                null,
+                null,
+                new ProfilingTestUtils.ImmediateExecutor(),
+                callback);
+
+        // Wait until callback#onAccept is triggered so we can confirm the result.
+        waitForCallback(callback);
+
+        // Assert request failed with system rate limiting error.
+        assertEquals(ProfilingResult.ERROR_FAILED_RATE_LIMIT_SYSTEM,
+                callback.mResult.getErrorCode());
+    }
+
+    /**
+     * Test that profiling request fails process rate limiter when cost exceeds max.
+     *
+     * This test in particular will fail the hour bucket just to verify end to end a process deny.
+     * Testing for each time bucket is covered in service side tests.
+     */
+    @Test
+    @RequiresFlagsEnabled({Flags.FLAG_TELEMETRY_APIS, Flags.FLAG_REDACTION_ENABLED})
+    public void testRateLimiterDenyProcess() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        enableRateLimiter();
+
+        // Override rate limiter values such that the system trace cost is more than the process
+        // limits but less than the system limits.
+        overrideSystemTraceDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS, FIVE_SECONDS_MS);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_1_HOUR, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_24_HOUR, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_7_DAY, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_1_HOUR, 10);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_24_HOUR, 10);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_7_DAY, 10);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.COST_SYSTEM_TRACE, 100);
+
+        AppCallback callback = new AppCallback();
+
+        // Now kick off the request.
+        mProfilingManager.requestProfiling(
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
+                ProfilingTestUtils.getOneSecondDurationParamBundle(),
+                null,
+                null,
+                new ProfilingTestUtils.ImmediateExecutor(),
+                callback);
+
+        // Wait until callback#onAccept is triggered so we can confirm the result.
+        waitForCallback(callback);
+
+        // Assert request failed with process rate limiting error.
+        assertEquals(ProfilingResult.ERROR_FAILED_RATE_LIMIT_PROCESS,
+                callback.mResult.getErrorCode());
+    }
+
+    /** Test that profiling request passes system rate limiter. */
+    @Test
+    @RequiresFlagsEnabled({Flags.FLAG_TELEMETRY_APIS, Flags.FLAG_REDACTION_ENABLED})
+    public void testRateLimiterAllow() throws Exception {
+        if (mProfilingManager == null) throw new TestException("mProfilingManager can not be null");
+
+        enableRateLimiter();
+
+        // Override rate limiter values such that the system trace cost is less than both the system
+        // and process limits.
+        overrideSystemTraceDeviceConfigValues(false, ONE_SECOND_MS, ONE_SECOND_MS, FIVE_SECONDS_MS);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_1_HOUR, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_24_HOUR, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_SYSTEM_7_DAY, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_1_HOUR, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_24_HOUR, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.MAX_COST_PROCESS_7_DAY, 1000);
+        executeShellCmd(COMMAND_OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
+                DeviceConfigHelper.COST_SYSTEM_TRACE, 100);
+
+        AppCallback callback = new AppCallback();
+
+        // Now kick off the request.
+        mProfilingManager.requestProfiling(
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE,
+                ProfilingTestUtils.getOneSecondDurationParamBundle(),
+                null,
+                null,
+                new ProfilingTestUtils.ImmediateExecutor(),
+                callback);
+
+        // Wait until callback#onAccept is triggered so we can confirm the result.
+        waitForCallback(callback);
+
+        // Assert request returned with no error indicating that the rate limiter allowed the run.
+        assertEquals(ProfilingResult.ERROR_NONE, callback.mResult.getErrorCode());
+    }
+
     /** Disable the rate limiter and wait long enough for the update to be picked up. */
-    private void disableRateLimiter() {
-        SystemUtil.runShellCommand(
-                "device_config put profiling_testing rate_limiter.disabled true");
+    private void disableRateLimiter() throws Exception {
+        overrideRateLimiter(true);
+    }
+
+    /** Enable the rate limiter and wait long enough for the update to be picked up. */
+    private void enableRateLimiter() throws Exception {
+        overrideRateLimiter(false);
+    }
+
+    /**
+     * Override the rate limiter to the provided value and wait long enough for the update to be
+     * picked up.
+     */
+    private void overrideRateLimiter(boolean disable) throws Exception {
+        executeShellCmd(
+                "device_config put profiling_testing rate_limiter.disabled %s", disable);
         for (int i = 0; i < RATE_LIMITER_WAIT_TIME_INCREMENTS_COUNT; i++) {
             sleep(RATE_LIMITER_WAIT_TIME_INCREMENT_MS);
-            String output = SystemUtil.runShellCommand(
+            String output = executeShellCmd(
                     "device_config get profiling_testing rate_limiter.disabled");
-            if (Boolean.parseBoolean(output.trim())) {
+            if (Boolean.parseBoolean(output.trim()) == disable) {
                 return;
             }
-
         }
     }
 
@@ -1017,11 +1360,17 @@ public final class ProfilingFrameworkTests {
 
     /** Assert that result matches a success case, specifically: contains a path and no errors. */
     private void confirmCollectionSuccess(ProfilingResult result, String suffix) {
+        confirmCollectionSuccess(result, suffix, 0);
+    }
+
+    /** Assert that result matches a success case, specifically: contains a path and no errors. */
+    private void confirmCollectionSuccess(ProfilingResult result, String suffix, int triggerType) {
         assertNotNull(result);
         assertEquals(ProfilingResult.ERROR_NONE, result.getErrorCode());
         assertNotNull(result.getResultFilePath());
         assertTrue(result.getResultFilePath().contains(suffix));
         assertNull(result.getErrorMessage());
+        assertEquals(triggerType, result.getTriggerType());
 
         // Confirm output file exists and is not empty.
         File file = new File(result.getResultFilePath());
@@ -1123,22 +1472,23 @@ public final class ProfilingFrameworkTests {
 
     // Starts a thread that keeps a CPU busy.
     private static class BusyLoopThread {
-        private Thread thread;
-        private AtomicBoolean done = new AtomicBoolean(false);
-
-        public BusyLoopThread() {
-            done.set(false);
-            thread = new Thread(() -> {
-                while (!done.get()) {
+        private Thread mThread;
+        private AtomicBoolean mDone = new AtomicBoolean(false);
+
+        BusyLoopThread() {
+            mDone.set(false);
+            mThread = new Thread(() -> {
+                while (!mDone.get()) {
+                  // Keep spinning!
                 }
             });
-            thread.start();
+            mThread.start();
         }
 
         public void stop() {
-            done.set(true);
+            mDone.set(true);
             try {
-                thread.join();
+                mThread.join();
             } catch (InterruptedException e) {
                 throw new AssertionError("InterruptedException", e);
             }
@@ -1147,24 +1497,24 @@ public final class ProfilingFrameworkTests {
 
     // Starts a thread that repeatedly issues malloc() and free().
     private static class MallocLoopThread {
-        private Thread thread;
-        private AtomicBoolean done = new AtomicBoolean(false);
+        private Thread mThread;
+        private AtomicBoolean mDone = new AtomicBoolean(false);
 
-        public MallocLoopThread() {
-            done.set(false);
-            thread = new Thread(() -> {
-                while (!done.get()) {
+        MallocLoopThread() {
+            mDone.set(false);
+            mThread = new Thread(() -> {
+                while (!mDone.get()) {
                     doMallocAndFree();
                     sleep(10);
                 }
             });
-            thread.start();
+            mThread.start();
         }
 
         public void stop() {
-            done.set(true);
+            mDone.set(true);
             try {
-                thread.join();
+                mThread.join();
             } catch (InterruptedException e) {
                 throw new AssertionError("InterruptedException", e);
             }
diff --git a/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java b/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
index 80061d1..6d69ea2 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingServiceTests.java
@@ -20,6 +20,7 @@ import static android.os.profiling.ProfilingService.TracingState;
 
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNotEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
@@ -42,9 +43,10 @@ import android.os.Handler;
 import android.os.IProfilingResultCallback;
 import android.os.ProfilingManager;
 import android.os.ProfilingResult;
+import android.os.ProfilingTrigger;
 import android.os.profiling.DeviceConfigHelper;
 import android.os.profiling.ProfilingService;
-import android.os.profiling.ProfilingTrigger;
+import android.os.profiling.ProfilingTriggerData;
 import android.os.profiling.RateLimiter;
 import android.os.profiling.TracingSession;
 import android.platform.test.annotations.EnableFlags;
@@ -91,18 +93,36 @@ public final class ProfilingServiceTests {
     private static final String OVERRIDE_DEVICE_CONFIG_INT = "device_config put %s %s %d";
     private static final String GET_DEVICE_CONFIG = "device_config get %s %s";
     private static final String DELETE_DEVICE_CONFIG = "device_config delete %s %s";
+    private static final String RESET_NAMESPACE = "device_config reset trusted_defaults %s";
 
     private static final String PERSIST_TEST_DIR = "testdir";
     private static final String PERSIST_TEST_FILE = "testfile";
 
     // Key most and least significant bits are used to generate a unique key specific to each
     // request. Key is used to pair request back to caller and callbacks so test to keep consistent.
-    private static final long KEY_MOST_SIG_BITS = 456l;
-    private static final long KEY_LEAST_SIG_BITS = 123l;
+    private static final long KEY_MOST_SIG_BITS = 456L;
+    private static final long KEY_LEAST_SIG_BITS = 123L;
 
     private static final int FAKE_UID = 12345;
     private static final int FAKE_UID_2 = 12346;
 
+    // Stub value for tests when system triggered api is not guaranteed to be enabled so
+    // {@link ProfilingTrigger#TRIGGER_TYPE_NONE} cannot be accessed. Value is the same as trigger
+    // type none. When cleaning up system triggered flag, remove this value and replace with
+    // {@link ProfilingTrigger#TRIGGER_TYPE_NONE}.
+    private static final int TRIGGER_TYPE_NONE = 0;
+
+    private static final int RATE_LIMITING_0_HOURS_BETWEEN = 0;
+
+    private static final int DEFAULT_LIMIT_PROCESS_HOUR = 5;
+    private static final int DEFAULT_LIMIT_PROCESS_DAY = 20;
+    private static final int DEFAULT_LIMIT_PROCESS_WEEK = 50;
+    private static final int DEFAULT_LIMIT_SYSTEM_HOUR = 10;
+    private static final int DEFAULT_LIMIT_SYSTEM_DAY = 50;
+    private static final int DEFAULT_LIMIT_SYSTEM_WEEK = 100;
+    private static final int DEFAULT_PROFILING_RUN_COST = 1;
+    private static final int DEFAULT_PERSIST_TO_DISK_FREQUENCY = 0;
+
     @Rule
     public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
     @Rule public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
@@ -115,9 +135,13 @@ public final class ProfilingServiceTests {
     private RateLimiter mRateLimiter;
 
     @Before
-    public void setUp() {
+    public void setUp() throws Exception {
         MockitoAnnotations.initMocks(this);
         mInstrumentation = InstrumentationRegistry.getInstrumentation();
+
+        executeShellCmd(RESET_NAMESPACE, DeviceConfigHelper.NAMESPACE);
+        executeShellCmd(RESET_NAMESPACE, DeviceConfigHelper.NAMESPACE_TESTING);
+
         mContext = spy(ApplicationProvider.getApplicationContext());
         mProfilingService = spy(new ProfilingService(mContext));
         mRateLimiter = spy(new RateLimiter(new RateLimiter.HandlerCallback() {
@@ -146,6 +170,10 @@ public final class ProfilingServiceTests {
         doReturn(true).when(mProfilingService).setupPersistAppTriggerFiles();
         mProfilingService.mPersistAppTriggersFile =
                 new File(mProfilingService.mPersistStoreDir, PERSIST_TEST_FILE);
+
+        // Since we use mock files we can't rely on the setup call that would typically come from
+        // initialization of rate limiter, so trigger setup manually.
+        mRateLimiter.setupFromPersistedData();
     }
 
     @After
@@ -371,7 +399,7 @@ public final class ProfilingServiceTests {
         // Create a tracing session.
         TracingSession tracingSession = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, 123, APP_PACKAGE_NAME,
-                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, TRIGGER_TYPE_NONE);
 
         // Mock tracing session to be running.
         doReturn(true).when(mActiveTrace).isAlive();
@@ -394,7 +422,7 @@ public final class ProfilingServiceTests {
 
         TracingSession tracingSession = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, 123, APP_PACKAGE_NAME,
-                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, TRIGGER_TYPE_NONE);
         mProfilingService.mActiveTracingSessions.put(
                 (new UUID(KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS)).toString(), tracingSession);
 
@@ -411,7 +439,7 @@ public final class ProfilingServiceTests {
 
         TracingSession tracingSession = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP, null, 123, APP_PACKAGE_NAME,
-                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS);
+                REQUEST_TAG, KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS, TRIGGER_TYPE_NONE);
         mProfilingService.mActiveTracingSessions.put(
                 (new UUID(KEY_MOST_SIG_BITS, KEY_LEAST_SIG_BITS)).toString(), tracingSession);
 
@@ -671,7 +699,155 @@ public final class ProfilingServiceTests {
         assertEquals(0, mRateLimiter.mPastRunsWeek.getEntriesCopy().length);
     }
 
-    // TODO: b/333579817 - Add more rate limiter tests
+    /** Test that rate limiter check for request allows as expected. */
+    @Test
+    public void testRateLimiter_RequestAllow() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Send a request for profiling.
+        int result = mRateLimiter.isProfilingRequestAllowed(
+                FAKE_UID, ProfilingManager.PROFILING_TYPE_HEAP_PROFILE, false, null);
+
+        // Confirm request passes as allowed.
+        assertEquals(RateLimiter.RATE_LIMIT_RESULT_ALLOWED, result);
+    }
+
+    /** Test that rate limiter check for request denies for process hour limit as expected. */
+    @Test
+    public void testRateLimiter_RequestDeny_ProcessHour() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Add a fake run to the same UID with a cost value equal to the process limit but lower
+        // than system limit for this time bucket so that it passes system but fails process.
+        mRateLimiter.mPastRunsHour.add(FAKE_UID, DEFAULT_LIMIT_PROCESS_HOUR,
+                System.currentTimeMillis());
+
+        // Send a request for profiling.
+        int result = mRateLimiter.isProfilingRequestAllowed(
+                FAKE_UID, ProfilingManager.PROFILING_TYPE_HEAP_PROFILE, false, null);
+
+        // Confirm request is denied with process reason.
+        assertEquals(RateLimiter.RATE_LIMIT_RESULT_BLOCKED_PROCESS, result);
+    }
+
+    /** Test that rate limiter check for request denies for process day limit as expected. */
+    @Test
+    public void testRateLimiter_RequestDeny_ProcessDay() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Add a fake run to the same UID with a cost value equal to the process limit but lower
+        // than system limit for this time bucket so that it passes system but fails process.
+        mRateLimiter.mPastRunsDay.add(FAKE_UID, DEFAULT_LIMIT_PROCESS_DAY,
+                System.currentTimeMillis());
+
+        // Send a request for profiling.
+        int result = mRateLimiter.isProfilingRequestAllowed(
+                FAKE_UID, ProfilingManager.PROFILING_TYPE_HEAP_PROFILE, false, null);
+
+        // Confirm request is denied with process reason.
+        assertEquals(RateLimiter.RATE_LIMIT_RESULT_BLOCKED_PROCESS, result);
+    }
+
+    /** Test that rate limiter check for request denies for process week limit as expected. */
+    @Test
+    public void testRateLimiter_RequestDeny_ProcessWeek() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Add a fake run to the same UID with a cost value equal to the process limit but lower
+        // than system limit for this time bucket so that it passes system but fails process.
+        mRateLimiter.mPastRunsWeek.add(FAKE_UID, DEFAULT_LIMIT_PROCESS_WEEK,
+                System.currentTimeMillis());
+
+        // Send a request for profiling.
+        int result = mRateLimiter.isProfilingRequestAllowed(
+                FAKE_UID, ProfilingManager.PROFILING_TYPE_HEAP_PROFILE, false, null);
+
+        // Confirm request is denied with process reason.
+        assertEquals(RateLimiter.RATE_LIMIT_RESULT_BLOCKED_PROCESS, result);
+    }
+
+    /** Test that rate limiter check for request denies for system hour limit as expected. */
+    @Test
+    public void testRateLimiter_RequestDeny_SystemHour() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Add a fake run to a different UID than will be used for the request, with a cost value
+        // equal to the system limit for this time bucket.
+        mRateLimiter.mPastRunsHour.add(FAKE_UID_2, DEFAULT_LIMIT_SYSTEM_HOUR,
+                System.currentTimeMillis());
+
+        // Send a request for profiling.
+        int result = mRateLimiter.isProfilingRequestAllowed(
+                FAKE_UID, ProfilingManager.PROFILING_TYPE_HEAP_PROFILE, false, null);
+
+        // Confirm request is denied with system reason.
+        assertEquals(RateLimiter.RATE_LIMIT_RESULT_BLOCKED_SYSTEM, result);
+    }
+
+    /** Test that rate limiter check for request denies for system day limit as expected. */
+    @Test
+    public void testRateLimiter_RequestDeny_SystemDay() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Add a fake run to a different UID than will be used for the request, with a cost value
+        // equal to the system limit for this time bucket.
+        mRateLimiter.mPastRunsDay.add(FAKE_UID_2, DEFAULT_LIMIT_SYSTEM_DAY,
+                System.currentTimeMillis());
+
+        // Send a request for profiling.
+        int result = mRateLimiter.isProfilingRequestAllowed(
+                FAKE_UID, ProfilingManager.PROFILING_TYPE_HEAP_PROFILE, false, null);
+
+        // Confirm request is denied with system reason.
+        assertEquals(RateLimiter.RATE_LIMIT_RESULT_BLOCKED_SYSTEM, result);
+    }
+
+    /** Test that rate limiter check for request denies for system week limit as expected. */
+    @Test
+    public void testRateLimiter_RequestDeny_SystemWeek() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Add a fake run to a different UID than will be used for the request, with a cost value
+        // equal to the system limit for this time bucket.
+        mRateLimiter.mPastRunsWeek.add(FAKE_UID_2, DEFAULT_LIMIT_SYSTEM_WEEK,
+                System.currentTimeMillis());
+
+        // Send a request for profiling.
+        int result = mRateLimiter.isProfilingRequestAllowed(
+                FAKE_UID, ProfilingManager.PROFILING_TYPE_HEAP_PROFILE, false, null);
+
+        // Confirm request is denied with system reason.
+        assertEquals(RateLimiter.RATE_LIMIT_RESULT_BLOCKED_SYSTEM, result);
+    }
+
+    /** Test that rate limiter check for trigger allows as expected. */
+    @Test
+    public void testRateLimiter_TriggeredAllow() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Send a request for a trigger.
+        int result = mRateLimiter.isProfilingRequestAllowed(FAKE_UID,
+                ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE, true, null);
+
+        // Confirm request passes as allowed.
+        assertEquals(RateLimiter.RATE_LIMIT_RESULT_ALLOWED, result);
+    }
+
+    /** Test that rate limiter check for trigger denies when expected. */
+    @Test
+    public void testRateLimiter_TriggerDeny() throws Exception {
+        overrideRateLimiterDefaults();
+
+        // Add a fake run with a high cost value.
+        mRateLimiter.mPastRunsHour.add(FAKE_UID, 1000, System.currentTimeMillis());
+
+        // Send a request for a trigger.
+        int result = mRateLimiter.isProfilingRequestAllowed(
+                FAKE_UID, ProfilingManager.PROFILING_TYPE_SYSTEM_TRACE, true, null);
+
+        // Confirm request does not pass as allowed.
+        assertNotEquals(RateLimiter.RATE_LIMIT_RESULT_ALLOWED, result);
+    }
 
     /** Test that advancing state in forward direction works as expected. */
     @Test
@@ -684,7 +860,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.PROFILING_FINISHED);
 
         // Trigger an advance to a subsequent state.
@@ -710,7 +887,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.APPROVED);
 
         // Attempt to advance to earlier state.
@@ -739,7 +917,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.REQUESTED);
 
         // Make sure retry count is 0 (default value).
@@ -774,7 +953,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session1.setProfilingStartTimeMs(System.currentTimeMillis());
         session1.setState(TracingState.PROFILING_FINISHED);
 
@@ -785,7 +965,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session2.setProfilingStartTimeMs(System.currentTimeMillis());
         session2.setState(TracingState.ERROR_OCCURRED);
         session2.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING, "some error message");
@@ -797,7 +978,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session3.setProfilingStartTimeMs(System.currentTimeMillis());
         session3.setState(TracingState.REDACTED);
 
@@ -947,7 +1129,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session1.setProfilingStartTimeMs(System.currentTimeMillis());
         session1.setState(TracingState.PROFILING_FINISHED);
         TracingSession session2 = new TracingSession(
@@ -957,7 +1140,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session2.setProfilingStartTimeMs(System.currentTimeMillis());
         session2.setState(TracingState.ERROR_OCCURRED);
         session2.setError(ProfilingResult.ERROR_FAILED_POST_PROCESSING, "some error message");
@@ -1013,7 +1197,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setProfilingStartTimeMs(System.currentTimeMillis());
         session.setState(TracingState.PROFILING_FINISHED);
 
@@ -1055,20 +1240,23 @@ public final class ProfilingServiceTests {
         mProfilingService.mAppTriggers.getMap().clear();
 
         // Create 3 triggers belonging to 2 uids. Add a last triggered time to one of them.
-        ProfilingTrigger trigger1 = new ProfilingTrigger(FAKE_UID, APP_PACKAGE_NAME, 1, 0);
+        ProfilingTriggerData trigger1 = new ProfilingTriggerData(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN, 0);
 
-        ProfilingTrigger trigger2 = new ProfilingTrigger(FAKE_UID, APP_PACKAGE_NAME, 2, 1);
+        ProfilingTriggerData trigger2 = new ProfilingTriggerData(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR, 1);
         trigger2.setLastTriggeredTimeMs(123L);
 
-        ProfilingTrigger trigger3 = new ProfilingTrigger(FAKE_UID_2, APP_PACKAGE_NAME, 1, 2);
+        ProfilingTriggerData trigger3 = new ProfilingTriggerData(FAKE_UID_2, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN, 2);
 
         // Group into sparse arrays by uid.
-        SparseArray<ProfilingTrigger> triggerArray1 = new SparseArray<ProfilingTrigger>();
-        triggerArray1.put(1, trigger1);
-        triggerArray1.put(2, trigger2);
+        SparseArray<ProfilingTriggerData> triggerArray1 = new SparseArray<ProfilingTriggerData>();
+        triggerArray1.put(ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN, trigger1);
+        triggerArray1.put(ProfilingTrigger.TRIGGER_TYPE_ANR, trigger2);
 
-        SparseArray<ProfilingTrigger> triggerArray2 = new SparseArray<ProfilingTrigger>();
-        triggerArray2.put(1, trigger3);
+        SparseArray<ProfilingTriggerData> triggerArray2 = new SparseArray<ProfilingTriggerData>();
+        triggerArray2.put(ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN, trigger3);
 
         mProfilingService.mAppTriggers.put(APP_PACKAGE_NAME, FAKE_UID, triggerArray1);
         mProfilingService.mAppTriggers.put(APP_PACKAGE_NAME, FAKE_UID_2, triggerArray2);
@@ -1088,11 +1276,14 @@ public final class ProfilingServiceTests {
 
         // Finally, verify the loaded contents match the ones that were persisted.
         confirmProfilingTriggerEquals(trigger1,
-                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(1));
+                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                        .get(ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN));
         confirmProfilingTriggerEquals(trigger2,
-                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(2));
+                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                        .get(ProfilingTrigger.TRIGGER_TYPE_ANR));
         confirmProfilingTriggerEquals(trigger3,
-                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID_2).get(1));
+                mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID_2)
+                        .get(ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN));
     }
 
     /**
@@ -1227,7 +1418,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.PROFILING_STARTED);
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(FAKE_UID, queue);
@@ -1265,7 +1457,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.PROFILING_FINISHED);
         session.setRetryCount(3);
         queue.add(session);
@@ -1302,7 +1495,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.PROFILING_FINISHED);
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(uid, queue);
@@ -1340,7 +1534,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.PROFILING_FINISHED);
         queue.add(session);
         mProfilingService.mQueuedTracingResults.put(FAKE_UID, queue);
@@ -1377,7 +1572,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.REDACTED);
         session.setProfilingStartTimeMs(System.currentTimeMillis());
         queue.add(session);
@@ -1419,7 +1615,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.COPIED_FILE);
         session.setError(ProfilingResult.ERROR_NONE);
         queue.add(session);
@@ -1455,7 +1652,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.ERROR_OCCURRED);
         session.setError(ProfilingResult.ERROR_UNKNOWN);
         queue.add(session);
@@ -1492,7 +1690,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.NOTIFIED_REQUESTER);
         session.setError(ProfilingResult.ERROR_NONE);
         queue.add(session);
@@ -1529,7 +1728,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setState(TracingState.COPIED_FILE);
         session.setProfilingStartTimeMs(System.currentTimeMillis() - 1000
                 - ProfilingService.QUEUED_RESULT_MAX_RETAINED_DURATION_MS);
@@ -1572,7 +1772,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session.setFileName(trackedFile.getName());
         mProfilingService.mActiveTracingSessions.put(session.getKey(), session);
         assertEquals(1, mProfilingService.mActiveTracingSessions.size());
@@ -1614,7 +1815,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session1.setRedactedFileName(trackedFile1.getName());
         TracingSession session2 = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP,
@@ -1623,7 +1825,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session2.setFileName(trackedFile2.getName());
         TracingSession session3 = new TracingSession(
                 ProfilingManager.PROFILING_TYPE_JAVA_HEAP_DUMP,
@@ -1632,7 +1835,8 @@ public final class ProfilingServiceTests {
                 APP_PACKAGE_NAME,
                 REQUEST_TAG,
                 KEY_LEAST_SIG_BITS,
-                KEY_MOST_SIG_BITS);
+                KEY_MOST_SIG_BITS,
+                TRIGGER_TYPE_NONE);
         session3.setFileName(trackedFile3.getName());
         // Put 1 session in one list.
         List<TracingSession> sessionList1 = new ArrayList<TracingSession>(Arrays.asList(session1));
@@ -1703,31 +1907,40 @@ public final class ProfilingServiceTests {
 
         // Now add several triggers:
         // First add 2 different triggers to the same uid/package
-        // TODO: b/373461116 - update hardcoded triggers to api value
-        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, 1, 0);
-        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, 2, 0);
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN, RATE_LIMITING_0_HOURS_BETWEEN);
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR, RATE_LIMITING_0_HOURS_BETWEEN);
         // And add one to another uid with the same package name.
-        mProfilingService.addTrigger(FAKE_UID_2, APP_PACKAGE_NAME, 2, 0);
+        mProfilingService.addTrigger(FAKE_UID_2, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR, RATE_LIMITING_0_HOURS_BETWEEN);
 
         // Grab the per process arrays.
-        SparseArray<ProfilingTrigger> uid1Triggers =
+        SparseArray<ProfilingTriggerData> uid1Triggers =
                 mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID);
-        SparseArray<ProfilingTrigger> uid2Triggers =
+        SparseArray<ProfilingTriggerData> uid2Triggers =
                 mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID_2);
 
         // Confirm they are represented correctly.
         assertEquals(2, uid1Triggers.size());
         assertEquals(1, uid2Triggers.size());
-        confirmProfilingTriggerEquals(uid1Triggers.get(1), FAKE_UID, APP_PACKAGE_NAME, 1, 0);
-        confirmProfilingTriggerEquals(uid1Triggers.get(2), FAKE_UID, APP_PACKAGE_NAME, 2, 0);
-        confirmProfilingTriggerEquals(uid2Triggers.get(2), FAKE_UID_2, APP_PACKAGE_NAME, 2, 0);
+        confirmProfilingTriggerEquals(
+                uid1Triggers.get(ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN), FAKE_UID,
+                APP_PACKAGE_NAME, ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN, 0);
+        confirmProfilingTriggerEquals(
+                uid1Triggers.get(ProfilingTrigger.TRIGGER_TYPE_ANR), FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR, 0);
+        confirmProfilingTriggerEquals(
+                uid2Triggers.get(ProfilingTrigger.TRIGGER_TYPE_ANR), FAKE_UID_2, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR, 0);
 
         // Now add a repeated trigger with 1 field changed.
-        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, 2, 100);
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, ProfilingTrigger.TRIGGER_TYPE_ANR,
+                100);
 
         // Confirm the new value is set.
-        assertEquals(100, mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(2)
-                .getRateLimitingPeriodHours());
+        assertEquals(100, mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .get(ProfilingTrigger.TRIGGER_TYPE_ANR).getRateLimitingPeriodHours());
     }
 
     /** Test that app level rate limiting works correctly in the allow case. */
@@ -1746,9 +1959,6 @@ public final class ProfilingServiceTests {
         doReturn(true).when(mActiveTrace).isAlive();
         mProfilingService.mSystemTriggeredTraceProcess = mActiveTrace;
 
-        // TODO: b/373461116 - update hardcoded trigger to api value
-        int fakeTrigger = 1;
-
         // Setup some rate limiting values. Since this is an allow test, set the last run to be 1
         // hour more than the rate limiting period.
         int rateLimitingPeriodHours = 10;
@@ -1756,19 +1966,21 @@ public final class ProfilingServiceTests {
                 - ((rateLimitingPeriodHours + 1) * 60L * 60L * 1000L);
 
         // Add the trigger we'll use.
-        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger,
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, ProfilingTrigger.TRIGGER_TYPE_ANR,
                 rateLimitingPeriodHours);
 
         // Set the last run time.
-        mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(fakeTrigger)
+        mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .get(ProfilingTrigger.TRIGGER_TYPE_ANR)
                 .setLastTriggeredTimeMs(fakeLastTriggerTimeMs);
 
         // Now process the trigger.
-        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger);
+        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR);
 
         // Get the new trigger time and make sure it's later than the fake one, indicating it ran.
         long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
-                .get(fakeTrigger).getLastTriggeredTimeMs();
+                .get(ProfilingTrigger.TRIGGER_TYPE_ANR).getLastTriggeredTimeMs();
         assertTrue(newTriggerTime > fakeLastTriggerTimeMs);
     }
 
@@ -1788,9 +2000,6 @@ public final class ProfilingServiceTests {
         doReturn(true).when(mActiveTrace).isAlive();
         mProfilingService.mSystemTriggeredTraceProcess = mActiveTrace;
 
-        // TODO: b/373461116 - update hardcoded trigger to api value
-        int fakeTrigger = 1;
-
         // Setup some rate limiting values. Since this is a deny test, set the last run to be 1 hour
         // less than the rate limiting period.
         int rateLimitingPeriodHours = 10;
@@ -1798,20 +2007,22 @@ public final class ProfilingServiceTests {
                 - ((rateLimitingPeriodHours - 1) * 60L * 60L * 1000L);
 
         // Add the trigger we'll use,
-        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger,
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, ProfilingTrigger.TRIGGER_TYPE_ANR,
                 rateLimitingPeriodHours);
 
         // Set the last run time.
-        mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID).get(fakeTrigger)
+        mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
+                .get(ProfilingTrigger.TRIGGER_TYPE_ANR)
                 .setLastTriggeredTimeMs(fakeLastTriggerTimeMs);
 
         // Now process the trigger.
-        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger);
+        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_ANR);
 
         // Get the new trigger time and make sure it's equal to the fake one, indicating it did not
         // run.
         long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
-                .get(fakeTrigger).getLastTriggeredTimeMs();
+                .get(ProfilingTrigger.TRIGGER_TYPE_ANR).getLastTriggeredTimeMs();
         assertEquals(fakeLastTriggerTimeMs, newTriggerTime);
     }
 
@@ -1829,22 +2040,18 @@ public final class ProfilingServiceTests {
         doReturn(true).when(mActiveTrace).isAlive();
         mProfilingService.mSystemTriggeredTraceProcess = mActiveTrace;
 
-        // TODO: b/373461116 - update hardcoded trigger to api value
-        int fakeTrigger = 1;
-
-        // Set app level rate limiting to 0, we're not testing that here.
-        int rateLimitingPeriodHours = 0;
-
         // Add the trigger we'll use.
-        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger,
-                rateLimitingPeriodHours);
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN,
+                RATE_LIMITING_0_HOURS_BETWEEN/*Set to 0 as we're not testing rate limiting here.*/);
 
         // Now process the trigger.
-        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger);
+        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN);
 
         // Get the new trigger time and make sure it's later than 0, indicating it ran.
         long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
-                .get(fakeTrigger).getLastTriggeredTimeMs();
+                .get(ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN).getLastTriggeredTimeMs();
         assertTrue(newTriggerTime > 0);
     }
 
@@ -1868,22 +2075,18 @@ public final class ProfilingServiceTests {
         // Wait 1 ms to ensure time has ticked and avoid potential flake.
         sleep(1);
 
-        // TODO: b/373461116 - update hardcoded trigger to api value
-        int fakeTrigger = 1;
-
-        // Set app level rate limiting to 0, we're not testing that here.
-        int rateLimitingPeriodHours = 0;
-
         // Add the trigger we'll use,
-        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger,
-                rateLimitingPeriodHours);
+        mProfilingService.addTrigger(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN,
+                RATE_LIMITING_0_HOURS_BETWEEN/*Set to 0 as we're not testing rate limiting here.*/);
 
         // Now process the trigger.
-        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME, fakeTrigger);
+        mProfilingService.processTriggerInternal(FAKE_UID, APP_PACKAGE_NAME,
+                ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN);
 
         // Get the new trigger time and make sure it's equal to 0, indicating it did not run.
         long newTriggerTime = mProfilingService.mAppTriggers.get(APP_PACKAGE_NAME, FAKE_UID)
-                .get(fakeTrigger).getLastTriggeredTimeMs();
+                .get(ProfilingTrigger.TRIGGER_TYPE_APP_FULLY_DRAWN).getLastTriggeredTimeMs();
         assertEquals(0, newTriggerTime);
     }
 
@@ -1949,39 +2152,34 @@ public final class ProfilingServiceTests {
     private void overrideRateLimiterDefaults() throws Exception {
         // Update DeviceConfig defaults to general high enough limits, cost of 1, and persist
         // frequency 0.
-        overrideRateLimiterDefaults(5, 10, 20, 50, 50, 100, 1, 1, 1, 1, 1, 0);
+        overrideRateLimiterDefaults(
+                DEFAULT_LIMIT_SYSTEM_HOUR,
+                DEFAULT_LIMIT_PROCESS_HOUR,
+                DEFAULT_LIMIT_SYSTEM_DAY,
+                DEFAULT_LIMIT_PROCESS_DAY,
+                DEFAULT_LIMIT_SYSTEM_WEEK,
+                DEFAULT_LIMIT_PROCESS_WEEK,
+                DEFAULT_PROFILING_RUN_COST,
+                DEFAULT_PROFILING_RUN_COST,
+                DEFAULT_PROFILING_RUN_COST,
+                DEFAULT_PROFILING_RUN_COST,
+                DEFAULT_PROFILING_RUN_COST,
+                DEFAULT_PERSIST_TO_DISK_FREQUENCY);
     }
 
     private void overrideRateLimiterDefaults(int systemHour, int processHour, int systemDay,
             int processDay, int systemWeek, int processWeek, int costHeapDump, int costHeapProfile,
             int costStackSampling, int costSystemTrace, int costSystemTriggeredSystemProfiling,
-            int persistToDiskFrequency)
-            throws Exception {
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.MAX_COST_SYSTEM_1_HOUR, systemHour);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.MAX_COST_PROCESS_1_HOUR, processHour);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.MAX_COST_SYSTEM_24_HOUR, systemDay);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.MAX_COST_PROCESS_24_HOUR, processDay);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.MAX_COST_SYSTEM_7_DAY, systemWeek);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.MAX_COST_PROCESS_7_DAY, processWeek);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.COST_JAVA_HEAP_DUMP, costHeapDump);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.COST_HEAP_PROFILE, costHeapProfile);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.COST_STACK_SAMPLING, costStackSampling);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.COST_SYSTEM_TRACE, costSystemTrace);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.COST_SYSTEM_TRIGGERED_SYSTEM_TRACE,
-                costSystemTriggeredSystemProfiling);
-        executeShellCmd(OVERRIDE_DEVICE_CONFIG_INT, DeviceConfigHelper.NAMESPACE,
-                DeviceConfigHelper.PERSIST_TO_DISK_FREQUENCY_MS, persistToDiskFrequency);
+            int persistToDiskFrequency) {
+        mRateLimiter.mPastRunsHour.maybeUpdateMaxCosts(systemHour, processHour);
+        mRateLimiter.mPastRunsDay.maybeUpdateMaxCosts(systemDay, processDay);
+        mRateLimiter.mPastRunsWeek.maybeUpdateMaxCosts(systemWeek, processWeek);
+        mRateLimiter.mCostJavaHeapDump = costHeapDump;
+        mRateLimiter.mCostHeapProfile = costHeapProfile;
+        mRateLimiter.mCostStackSampling = costStackSampling;
+        mRateLimiter.mCostSystemTrace = costSystemTrace;
+        mRateLimiter.mCostSystemTriggeredSystemTrace = costSystemTriggeredSystemProfiling;
+        mRateLimiter.mPersistToDiskFrequency = persistToDiskFrequency;
     }
 
     @FormatMethod
@@ -2015,17 +2213,18 @@ public final class ProfilingServiceTests {
         assertEquals(s1.getErrorMessage(), s2.getErrorMessage());
         assertEquals(s1.getErrorStatus(), s2.getErrorStatus());
         assertEquals(s1.getTriggerType(), s2.getTriggerType());
+        assertEquals(s1.getProfilingStartTimeMs(), s2.getProfilingStartTimeMs());
     }
     // LINT.ThenChange(/service/proto/android/os/queue.proto:proto)
 
     // LINT.IfChange(trigger_equals)
-    private void confirmProfilingTriggerEquals(ProfilingTrigger t1, int uid, String packageName,
+    private void confirmProfilingTriggerEquals(ProfilingTriggerData t1, int uid, String packageName,
             int triggerType, int rateLimitingPeriodHours) {
         confirmProfilingTriggerEquals(t1,
-                new ProfilingTrigger(uid, packageName, triggerType, rateLimitingPeriodHours));
+                new ProfilingTriggerData(uid, packageName, triggerType, rateLimitingPeriodHours));
     }
 
-    private void confirmProfilingTriggerEquals(ProfilingTrigger t1, ProfilingTrigger t2) {
+    private void confirmProfilingTriggerEquals(ProfilingTriggerData t1, ProfilingTriggerData t2) {
         assertEquals(t1.getUid(), t2.getUid());
         assertEquals(t1.getPackageName(), t2.getPackageName());
         assertEquals(t1.getTriggerType(), t2.getTriggerType());
@@ -2089,10 +2288,11 @@ public final class ProfilingServiceTests {
         public int mStatus;
         public String mTag;
         public String mError;
+        public int mTriggerType;
 
         @Override
         public void sendResult(String resultFile, long keyMostSigBits,
-                long keyLeastSigBits, int status, String tag, String error) {
+                long keyLeastSigBits, int status, String tag, String error, int triggerType) {
             mResultSent = true;
             mResultFile = resultFile;
             mKeyMostSigBits = keyMostSigBits;
@@ -2100,6 +2300,7 @@ public final class ProfilingServiceTests {
             mStatus = status;
             mTag = tag;
             mError = error;
+            mTriggerType = triggerType;
         }
 
         @Override
diff --git a/tests/cts/src/android/profiling/cts/ProfilingTestUtils.java b/tests/cts/src/android/profiling/cts/ProfilingTestUtils.java
index 5aba545..6c81477 100644
--- a/tests/cts/src/android/profiling/cts/ProfilingTestUtils.java
+++ b/tests/cts/src/android/profiling/cts/ProfilingTestUtils.java
@@ -22,7 +22,7 @@ import java.util.concurrent.Executor;
 
 public final class ProfilingTestUtils {
 
-    private static String KEY_DURATION_MS = "KEY_DURATION_MS";
+    private static final String KEY_DURATION_MS = "KEY_DURATION_MS";
 
     static class ImmediateExecutor implements Executor {
         public void execute(Runnable r) {
```

