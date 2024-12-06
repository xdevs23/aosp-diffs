```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index abed18f..c2277a5 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -41,6 +41,7 @@ bootclasspath_fragment {
         // result in a build failure due to inconsistent flags.
         package_prefixes: [
             "android.provider.aidl",
+            "android.provider.flags",
             "android.provider.internal.modules.utils.build",
         ],
     },
@@ -87,7 +88,7 @@ apex {
         "com.android.configinfrastructure-systemserverclasspath-fragment",
     ],
     manifest: "manifest.json",
-    file_contexts: ":apex.test-file_contexts",
+    file_contexts: ":com.android.configinfrastructure-file_contexts",
     prebuilts: [
         "current_sdkinfo",
     ],
diff --git a/framework/Android.bp b/framework/Android.bp
index efef3cc..4b52710 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -25,6 +25,7 @@ java_sdk_library {
     defaults: ["framework-module-defaults"],
     permitted_packages: [
         "android.provider",
+        "android.provider.flags",
         "android.provider.aidl",
     ],
     apex_available: [
@@ -35,11 +36,43 @@ java_sdk_library {
     impl_library_visibility: [
         "//packages/modules/ConfigInfrastructure:__subpackages__",
     ],
+    libs: [
+        "configinfra_framework_flags_java_lib",
+    ],
     static_libs: [
         "modules-utils-build",
     ],
+    aconfig_declarations: [
+        "configinfra_framework_flags",
+    ],
     jarjar_rules: "jarjar-rules.txt",
     lint: {
         baseline_filename: "lint-baseline.xml",
     },
 }
+
+aconfig_declarations {
+    name: "configinfra_framework_flags",
+    package: "android.provider.flags",
+    container: "com.android.configinfrastructure",
+    srcs: [
+        "flags.aconfig",
+    ],
+}
+
+java_aconfig_library {
+    name: "configinfra_framework_flags_java_lib",
+    min_sdk_version: "34",
+    apex_available: [
+        "com.android.configinfrastructure",
+        "//apex_available:platform", // Used by DeviceConfigService
+    ],
+    visibility: [
+        "//visibility:public",
+    ],
+    aconfig_declarations: "configinfra_framework_flags",
+    sdk_version: "core_platform",
+    libs: [
+        "fake_device_config",
+    ],
+}
diff --git a/framework/api/module-lib-lint-baseline.txt b/framework/api/module-lib-lint-baseline.txt
index feb6f83..f780781 100644
--- a/framework/api/module-lib-lint-baseline.txt
+++ b/framework/api/module-lib-lint-baseline.txt
@@ -1,3 +1,6 @@
 // Baseline format: 1.0
+Todo: android.provider.StageOtaFlags#stageBooleanAconfigFlagsForBuild(java.util.Map<java.lang.String,java.lang.Boolean>, String):
+    Documentation mentions 'TODO'
+
 UnflaggedApi: android.provider.DeviceConfig#NAMESPACE_TETHERING_NATIVE:
     New API must be flagged with @FlaggedApi: field android.provider.DeviceConfig.NAMESPACE_TETHERING_NATIVE
diff --git a/framework/api/system-current.txt b/framework/api/system-current.txt
index a69e7fd..cbe9399 100644
--- a/framework/api/system-current.txt
+++ b/framework/api/system-current.txt
@@ -7,6 +7,7 @@ package android.provider {
     method @RequiresPermission(android.Manifest.permission.WRITE_DEVICE_CONFIG) public static void clearLocalOverride(@NonNull String, @NonNull String);
     method @RequiresPermission(android.Manifest.permission.MONITOR_DEVICE_CONFIG_ACCESS) public static void clearMonitorCallback(@NonNull android.content.ContentResolver);
     method @RequiresPermission(anyOf={android.Manifest.permission.WRITE_DEVICE_CONFIG, android.Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG}) public static boolean deleteProperty(@NonNull String, @NonNull String);
+    method @FlaggedApi("android.provider.flags.dump_improvements") @RequiresPermission(android.Manifest.permission.DUMP) public static void dump(@NonNull android.os.ParcelFileDescriptor, @NonNull java.io.PrintWriter, @NonNull String, @Nullable String[]);
     method @NonNull public static java.util.Set<java.lang.String> getAdbWritableFlags();
     method @NonNull public static java.util.Set<android.provider.DeviceConfig.Properties> getAllProperties();
     method public static boolean getBoolean(@NonNull String, @NonNull String, boolean);
@@ -141,6 +142,10 @@ package android.provider {
     method @NonNull public android.provider.DeviceConfig.Properties.Builder setString(@NonNull String, @Nullable String);
   }
 
+  @FlaggedApi("android.provider.flags.stage_flags_for_build") public final class StageOtaFlags {
+    method @FlaggedApi("android.provider.flags.stage_flags_for_build") public static void stageBooleanAconfigFlagsForBuild(@NonNull java.util.Map<java.lang.String,java.lang.Boolean>, @NonNull String);
+  }
+
   public final class UpdatableDeviceConfigServiceReadiness {
     method public static boolean shouldStartUpdatableService();
   }
diff --git a/framework/api/system-lint-baseline.txt b/framework/api/system-lint-baseline.txt
index 5cb0f45..9ab7410 100644
--- a/framework/api/system-lint-baseline.txt
+++ b/framework/api/system-lint-baseline.txt
@@ -1,4 +1,7 @@
 // Baseline format: 1.0
+Todo: android.provider.StageOtaFlags#stageBooleanAconfigFlagsForBuild(java.util.Map<java.lang.String,java.lang.Boolean>, String):
+    Documentation mentions 'TODO'
+
 UnflaggedApi: android.provider.DeviceConfig#NAMESPACE_CORE_EXPERIMENTS_TEAM_INTERNAL:
     New API must be flagged with @FlaggedApi: field android.provider.DeviceConfig.NAMESPACE_CORE_EXPERIMENTS_TEAM_INTERNAL
 UnflaggedApi: android.provider.DeviceConfig#NAMESPACE_NFC:
diff --git a/framework/flags.aconfig b/framework/flags.aconfig
new file mode 100644
index 0000000..0d5346f
--- /dev/null
+++ b/framework/flags.aconfig
@@ -0,0 +1,19 @@
+package: "android.provider.flags"
+container: "com.android.configinfrastructure"
+
+flag {
+  name: "stage_flags_for_build"
+  namespace: "core_experiments_team_internal"
+  description: "API flag for stageFlagsForBuild"
+  bug: "360384952"
+  is_fixed_read_only: true
+  is_exported: true
+}
+
+flag {
+    name: "dump_improvements"
+    namespace: "core_experiments_team_internal"
+    description: "Added more information on `dumpsys device_config`"
+    bug: "364399200"
+  is_exported: true
+}
diff --git a/framework/java/android/provider/DeviceConfig.java b/framework/java/android/provider/DeviceConfig.java
index 6351404..7b97151 100644
--- a/framework/java/android/provider/DeviceConfig.java
+++ b/framework/java/android/provider/DeviceConfig.java
@@ -20,9 +20,11 @@ import static android.Manifest.permission.WRITE_ALLOWLISTED_DEVICE_CONFIG;
 import static android.Manifest.permission.READ_DEVICE_CONFIG;
 import static android.Manifest.permission.WRITE_DEVICE_CONFIG;
 import static android.Manifest.permission.READ_WRITE_SYNC_DISABLED_MODE_CONFIG;
+import static android.Manifest.permission.DUMP;
 
 import android.Manifest;
 import android.annotation.CallbackExecutor;
+import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
@@ -32,13 +34,17 @@ import android.annotation.SystemApi;
 import android.content.ContentResolver;
 import android.database.ContentObserver;
 import android.net.Uri;
-import com.android.modules.utils.build.SdkLevel;
+import android.provider.flags.Flags;
 import android.util.ArrayMap;
+import android.util.ArraySet;
 import android.util.Log;
 import android.util.Pair;
 
 import com.android.internal.annotations.GuardedBy;
+import com.android.modules.utils.build.SdkLevel;
 
+import java.io.FileDescriptor;
+import java.io.PrintWriter;
 import java.lang.annotation.ElementType;
 import java.lang.annotation.Retention;
 import java.lang.annotation.RetentionPolicy;
@@ -46,12 +52,15 @@ import java.lang.annotation.Target;
 
 import java.util.Arrays;
 import java.util.Collections;
+import java.util.Comparator;
 import java.util.HashMap;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.Set;
+import java.util.TreeMap;
+import java.util.TreeSet;
 import java.util.concurrent.Executor;
 
 import android.util.Log;
@@ -59,7 +68,9 @@ import android.util.Log;
 import android.provider.aidl.IDeviceConfigManager;
 import android.provider.DeviceConfigServiceManager;
 import android.provider.DeviceConfigInitializer;
+import android.os.Binder;
 import android.os.IBinder;
+import android.os.ParcelFileDescriptor;
 
 /**
  * Device level configuration parameters which can be tuned by a separate configuration service.
@@ -1021,7 +1032,7 @@ public final class DeviceConfig {
      */
     @SystemApi
     public static final int SYNC_DISABLED_MODE_UNTIL_REBOOT = 2;
-    
+
     private static final Object sLock = new Object();
     @GuardedBy("sLock")
     private static ArrayMap<OnPropertiesChangedListener, Pair<String, Executor>> sListeners =
@@ -1524,6 +1535,56 @@ public final class DeviceConfig {
         }
     }
 
+    // NOTE: this API is only used by the framework code, but using MODULE_LIBRARIES causes a
+    // build-time error on CtsDeviceConfigTestCases, so it's using PRIVILEGED_APPS.
+    /**
+     * Dumps internal state into the given {@code fd} or {@code pw}.
+     *
+     * @param fd file descriptor that will output the dump state. Typically used for binary dumps.
+     * @param pw print writer that will output the dump state. Typically used for formatted text.
+     * @param prefix prefix added to each line
+     * @param args (optional) arguments passed by {@code dumpsys}.
+     *
+     * @hide
+     */
+    @SystemApi(client = SystemApi.Client.PRIVILEGED_APPS)
+    @FlaggedApi(Flags.FLAG_DUMP_IMPROVEMENTS)
+    @RequiresPermission(DUMP)
+    public static void dump(@NonNull ParcelFileDescriptor fd, @NonNull PrintWriter pw,
+            @NonNull String dumpPrefix, @Nullable String[] args) {
+        Comparator<OnPropertiesChangedListener> comparator = (o1, o2) -> o1.toString()
+                .compareTo(o2.toString());
+        TreeMap<String, Set<OnPropertiesChangedListener>> listenersByNamespace  =
+                new TreeMap<>();
+        ArraySet<OnPropertiesChangedListener> uniqueListeners = new ArraySet<>();
+        int listenersSize;
+        synchronized (sLock) {
+            listenersSize = sListeners.size();
+            for (int i = 0; i < listenersSize; i++) {
+                var namespace = sListeners.valueAt(i).first;
+                var listener = sListeners.keyAt(i);
+                var listeners = listenersByNamespace.get(namespace);
+                if (listeners == null) {
+                    // Life would be so much easier if Android provided a MultiMap implementation...
+                    listeners = new TreeSet<>(comparator);
+                    listenersByNamespace.put(namespace, listeners);
+                }
+                listeners.add(listener);
+                uniqueListeners.add(listener);
+            }
+        }
+        pw.printf("%s%d listeners for %d namespaces:\n", dumpPrefix, uniqueListeners.size(),
+                listenersByNamespace.size());
+        for (var entry : listenersByNamespace.entrySet()) {
+            var namespace = entry.getKey();
+            var listeners = entry.getValue();
+            pw.printf("%s%s: %d listeners\n", dumpPrefix, namespace, listeners.size());
+            for (var listener : listeners) {
+                pw.printf("%s%s%s\n", dumpPrefix, dumpPrefix, listener);
+            }
+        }
+    }
+
     /**
      * Remove a listener for property changes. The listener will receive no further notification of
      * property changes.
diff --git a/framework/java/android/provider/StageOtaFlags.java b/framework/java/android/provider/StageOtaFlags.java
new file mode 100644
index 0000000..6d56ee6
--- /dev/null
+++ b/framework/java/android/provider/StageOtaFlags.java
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
+package android.provider;
+
+import android.annotation.FlaggedApi;
+import android.annotation.NonNull;
+import android.annotation.SystemApi;
+import android.provider.flags.Flags;
+import android.util.Log;
+import java.util.Map;
+
+/** @hide */
+@SystemApi
+@FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+public final class StageOtaFlags {
+  private static String LOG_TAG = "StageOtaFlags";
+
+  private StageOtaFlags() {}
+
+  /**
+   * Stage aconfig flags to be applied when booting into {@code buildId}.
+   *
+   * <p>Only a single {@code buildId} and its corresponding flags are stored at
+   * once. Every invocation of this method will overwrite whatever mapping was
+   * previously stored.
+   *
+   * It is an implementation error to call this if the storage is not
+   * initialized and ready to receive writes. Callers must ensure that it is
+   * available before invoking.
+   *
+   * TODO(b/361783454): create an isStorageAvailable API and mention it in this
+   * docstring.
+   *
+   * @param flags a map from {@code <packagename>.<flagname>} to flag values
+   * @param buildId when the device boots into buildId, it will apply {@code flags}
+   * @throws IllegalStateException if the storage is not ready to receive writes
+   *
+   * @hide
+   */
+  @SystemApi
+  @FlaggedApi(Flags.FLAG_STAGE_FLAGS_FOR_BUILD)
+  public static void stageBooleanAconfigFlagsForBuild(
+      @NonNull Map<String, Boolean> flags, @NonNull String buildId) {
+    int flagCount = flags.size();
+    Log.d(LOG_TAG, "stageFlagsForBuild invoked for " + flagCount + " flags");
+  }
+}
diff --git a/framework/java/android/provider/WritableFlags.java b/framework/java/android/provider/WritableFlags.java
index 350c100..47f5acf 100644
--- a/framework/java/android/provider/WritableFlags.java
+++ b/framework/java/android/provider/WritableFlags.java
@@ -609,7 +609,6 @@ final class WritableFlags {
                 "device_personalization_services/enable_image_selection_adjustments",
                 "device_personalization_services/enable_indirect_insights",
                 "device_personalization_services/enable_input_context_snapshot_capture",
-                "device_personalization_services/enable_instagram_action",
                 "device_personalization_services/enable_interactions_scoring_table",
                 "device_personalization_services/enable_interests_model",
                 "device_personalization_services/enable_interests_model_asr_biasing",
diff --git a/service/flags.aconfig b/service/flags.aconfig
index e8e98ff..8f5e28e 100644
--- a/service/flags.aconfig
+++ b/service/flags.aconfig
@@ -7,6 +7,7 @@ flag {
     description: "If enabled, a notification appears when flags are staged to be applied on reboot."
     bug: "296462695"
 }
+
 flag {
   name: "enable_unattended_reboot"
   namespace: "core_experiments_team_internal"
@@ -43,4 +44,14 @@ flag {
   metadata {
     purpose: PURPOSE_BUGFIX
   }
+}
+
+flag {
+  name: "use_descriptive_log_message"
+  namespace: "core_experiments_team_internal"
+  description: "Log sticky local override instead of just local override."
+  bug: "335493775"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
 }
\ No newline at end of file
diff --git a/service/jarjar-rules.txt b/service/jarjar-rules.txt
index c284d6e..0299e17 100644
--- a/service/jarjar-rules.txt
+++ b/service/jarjar-rules.txt
@@ -3,4 +3,5 @@ rule com.google.protobuf.** com.android.server.deviceconfig.internal.protobuf.@1
 rule com.google.common.** com.android.server.deviceconfig.internal.common.@1
 rule javax.annotation.** com.android.server.deviceconfig.javax.annotation.@1
 rule com.google.thirdparty.publicsuffix.** com.android.server.deviceconfig.publicsuffix.@1
-rule android.aconfig.** com.android.server.deviceconfig.internal.aconfig.@1
+rule android.aconfig.Aconfig com.android.server.deviceconfig.internal.android.aconfig.Aconfig
+rule android.aconfig.Aconfig$** com.android.server.deviceconfig.internal.android.aconfig.Aconfig$@1
diff --git a/service/java/com/android/server/deviceconfig/DeviceConfigInit.java b/service/java/com/android/server/deviceconfig/DeviceConfigInit.java
index c0998aa..465d241 100644
--- a/service/java/com/android/server/deviceconfig/DeviceConfigInit.java
+++ b/service/java/com/android/server/deviceconfig/DeviceConfigInit.java
@@ -2,6 +2,7 @@ package com.android.server.deviceconfig;
 
 import static com.android.server.deviceconfig.Flags.enableRebootNotification;
 import static com.android.server.deviceconfig.Flags.enableUnattendedReboot;
+import static com.android.server.deviceconfig.Flags.useDescriptiveLogMessage;
 
 import java.io.IOException;
 import java.io.FileDescriptor;
@@ -42,6 +43,7 @@ public class DeviceConfigInit {
     private static final String VENDOR_FLAGS_PATH = "/vendor/etc/aconfig_flags.pb";
 
     private static final String CONFIGURATION_NAMESPACE = "configuration";
+    private static final String OVERRIDES_NAMESPACE = "device_config_overrides";
     private static final String BOOT_NOTIFICATION_FLAG =
             "ConfigInfraFlags__enable_boot_notification";
     private static final String UNATTENDED_REBOOT_FLAG =
@@ -73,6 +75,19 @@ public class DeviceConfigInit {
         /** @hide */
         @Override
         public void onStart() {
+            DeviceConfig.Properties overrideProperties =
+                    DeviceConfig.getProperties(OVERRIDES_NAMESPACE);
+            for (String flagName : overrideProperties.getKeyset()) {
+                String fullName = overrideProperties.getNamespace() + "/" + flagName;
+                String value = overrideProperties.getString(flagName, null);
+                if (useDescriptiveLogMessage()) {
+                    Slog.i(TAG, "DeviceConfig sticky local override is set: "
+                        + fullName + "=" + value);
+                } else {
+                    Slog.i(TAG, "DeviceConfig sticky override is set: " + fullName + "=" + value);
+                }
+            }
+
             boolean notificationEnabled =
                     DeviceConfig.getBoolean(CONFIGURATION_NAMESPACE, BOOT_NOTIFICATION_FLAG, false);
             if (notificationEnabled && enableRebootNotification()) {
diff --git a/service/javatests/Android.bp b/service/javatests/Android.bp
index 15f879a..13f927b 100644
--- a/service/javatests/Android.bp
+++ b/service/javatests/Android.bp
@@ -39,6 +39,7 @@ android_test {
         "androidx.test.rules",
         "androidx.test.runner",
         "androidx.annotation_annotation",
+        "configinfra_framework_flags_java_lib",
         "modules-utils-build",
         "service-configinfrastructure.impl",
         "frameworks-base-testutils",
@@ -47,11 +48,11 @@ android_test {
         "flag-junit",
     ],
     libs: [
-        "android.test.base",
-        "android.test.mock",
-        "android.test.runner",
+        "android.test.base.stubs.system",
+        "android.test.mock.stubs.system",
+        "android.test.runner.stubs.system",
         "framework-connectivity.stubs.module_lib",
-        "framework-configinfrastructure",
+        "framework-configinfrastructure.stubs.module_lib",
         "DeviceConfigServiceResources",
     ],
     // Test coverage system runs on different devices. Need to
diff --git a/service/javatests/src/com/android/server/deviceconfig/DeviceConfigTest.java b/service/javatests/src/com/android/server/deviceconfig/DeviceConfigTest.java
new file mode 100644
index 0000000..a32e131
--- /dev/null
+++ b/service/javatests/src/com/android/server/deviceconfig/DeviceConfigTest.java
@@ -0,0 +1,121 @@
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
+package com.android.server.deviceconfig;
+
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.provider.flags.Flags;
+import android.provider.DeviceConfig;
+import android.provider.DeviceConfig.OnPropertiesChangedListener;
+import android.provider.DeviceConfig.Properties;
+import android.util.Log;
+
+import com.google.common.truth.Expect;
+
+import org.junit.Rule;
+import org.junit.Test;
+
+import java.io.IOException;
+import java.io.PrintWriter;
+import java.io.StringWriter;
+
+public final class DeviceConfigTest {
+
+    private static final String TAG = DeviceConfigTest.class.getSimpleName();
+
+    private static final String NAMESPACE_A = "A Space has no name";
+    private static final String NAMESPACE_B = "B Space has no name";
+
+    private static final String DUMP_PREFIX = "..";
+
+    @Rule public final Expect expect = Expect.create();
+    @Rule public final CheckFlagsRule checkFlagsRule =
+            DeviceFlagsValueProvider.createCheckFlagsRule();
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_DUMP_IMPROVEMENTS)
+    public void testDump_empty() throws Exception {
+        String dump = dump();
+
+        expect.withMessage("dump()").that(dump).isEqualTo(DUMP_PREFIX
+                + "0 listeners for 0 namespaces:\n");
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_DUMP_IMPROVEMENTS)
+    public void testDump_withListeners() throws Exception {
+        var listener1 = new TestOnPropertiesChangedListener();
+        var listener2 = new TestOnPropertiesChangedListener();
+        var listener3 = new TestOnPropertiesChangedListener();
+
+        DeviceConfig.addOnPropertiesChangedListener(NAMESPACE_A, Runnable::run, listener1);
+        DeviceConfig.addOnPropertiesChangedListener(NAMESPACE_A, Runnable::run, listener2);
+        DeviceConfig.addOnPropertiesChangedListener(NAMESPACE_A, Runnable::run, listener3);
+        // Next call will remove listener1 from NAMESPACE_A
+        DeviceConfig.addOnPropertiesChangedListener(NAMESPACE_B, Runnable::run, listener1);
+
+        try {
+            String dump = dump();
+
+            expect.withMessage("dump()").that(dump).isEqualTo(DUMP_PREFIX
+                    + "3 listeners for 2 namespaces:\n"
+                    + DUMP_PREFIX + NAMESPACE_A + ": 2 listeners\n"
+                    + DUMP_PREFIX + DUMP_PREFIX + listener2 + "\n"
+                    + DUMP_PREFIX + DUMP_PREFIX + listener3 + "\n"
+                    + DUMP_PREFIX + NAMESPACE_B + ": 1 listeners\n"
+                    + DUMP_PREFIX + DUMP_PREFIX + listener1 + "\n"
+                    );
+        } finally {
+            DeviceConfig.removeOnPropertiesChangedListener(listener1);
+            DeviceConfig.removeOnPropertiesChangedListener(listener2);
+            DeviceConfig.removeOnPropertiesChangedListener(listener3);
+        }
+    }
+
+    private String dump(String...args) throws IOException {
+        try (StringWriter sw = new StringWriter()) {
+            PrintWriter pw = new PrintWriter(sw);
+
+            DeviceConfig.dump(/* fd= */ null, pw, DUMP_PREFIX, args);
+
+            pw.flush();
+            String dump = sw.toString();
+
+            Log.v(TAG, "dump() output\n" + dump);
+
+            return dump;
+        }
+    }
+
+    private static final class TestOnPropertiesChangedListener
+            implements OnPropertiesChangedListener {
+
+        private static int sNextId;
+
+        private final int mId = ++sNextId;
+
+        @Override
+        public void onPropertiesChanged(Properties properties) {
+            throw new UnsupportedOperationException("Not used in any test (yet?)");
+        }
+
+        @Override
+        public String toString() {
+            return "TestOnPropertiesChangedListener#" + mId;
+        }
+    }
+}
```

