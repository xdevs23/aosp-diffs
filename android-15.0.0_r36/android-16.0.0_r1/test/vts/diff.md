```diff
diff --git a/OWNERS b/OWNERS
index ecc9b44c5..124f4a765 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,7 +1,6 @@
 dshi@google.com
 guangzhu@google.com
 jdesprez@google.com
-sbasi@google.com
 
 # Android xTS Infra Approvers
 wenshan@google.com
diff --git a/tests/angleallowliststrace_test/OWNERS b/tests/angleallowliststrace_test/OWNERS
new file mode 100644
index 000000000..0637328be
--- /dev/null
+++ b/tests/angleallowliststrace_test/OWNERS
@@ -0,0 +1,7 @@
+abdolrashidi@google.com
+cclao@google.com
+cnorthrop@google.com
+hibrian@google.com
+romanl@google.com
+solti@google.com
+yuxinhu@google.com
diff --git a/tests/angleallowliststrace_test/app/Android.bp b/tests/angleallowliststrace_test/app/Android.bp
new file mode 100644
index 000000000..59b17e9ab
--- /dev/null
+++ b/tests/angleallowliststrace_test/app/Android.bp
@@ -0,0 +1,59 @@
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
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "Android-Apache-2.0",
+    ],
+}
+
+android_test_helper_app {
+    name: "VtsAngleTestApp",
+    min_sdk_version: "35",
+    sdk_version: "35",
+    target_sdk_version: "35",
+    srcs: [
+        "src/**/*.java",
+    ],
+    jni_uses_platform_apis: true,
+    compile_multilib: "both",
+    jni_libs: [
+        "libvtsanglelocationtest_jni",
+    ],
+    static_libs: [
+        "androidx.test.rules",
+    ],
+}
+
+cc_test_library {
+    name: "libvtsanglelocationtest_jni",
+    min_sdk_version: "29",
+    header_libs: [
+        "jni_headers",
+    ],
+    static_libs: [
+        "libbase_ndk",
+    ],
+    shared_libs: [
+        "libdl",
+        "liblog",
+    ],
+    compile_multilib: "both",
+    stl: "libc++_static",
+    srcs: [
+        "jni/com_google_android_vts_angle_testAngleLocation.cpp",
+        "jni/onload.cpp",
+    ],
+}
diff --git a/tests/angleallowliststrace_test/app/AndroidManifest.xml b/tests/angleallowliststrace_test/app/AndroidManifest.xml
new file mode 100644
index 000000000..36c97363c
--- /dev/null
+++ b/tests/angleallowliststrace_test/app/AndroidManifest.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+# Copyright (C) 2025 The Android Open Source Project
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
+ -->
+
+<manifest xmlns:android="http://schemas.android.com/apk/res/android"
+     package="com.google.android.vts.angle.testapp"
+     android:targetSandboxVersion="2">
+
+    <application android:debuggable="true">
+        <uses-library android:name="android.test.runner"/>
+    </application>
+
+    <instrumentation android:name="androidx.test.runner.AndroidJUnitRunner"
+         android:targetPackage="com.google.android.vts.angle.testapp"/>
+
+</manifest>
diff --git a/tests/angleallowliststrace_test/app/jni/com_google_android_vts_angle_testAngleLocation.cpp b/tests/angleallowliststrace_test/app/jni/com_google_android_vts_angle_testAngleLocation.cpp
new file mode 100644
index 000000000..0b72a6235
--- /dev/null
+++ b/tests/angleallowliststrace_test/app/jni/com_google_android_vts_angle_testAngleLocation.cpp
@@ -0,0 +1,60 @@
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
+#include <dlfcn.h>
+#include <jni.h>
+#include <utils/Log.h>
+
+#define ARRAY_SIZE(x) (sizeof((x)) / (sizeof(((x)[0]))))
+#define TAG "VtsAngleLocationTest"
+
+#if defined(__LP64__) || defined(_LP64)
+#define SYSTEM_LIB_PATH "/system/lib64"
+#else
+#define SYSTEM_LIB_PATH "/system/lib"
+#endif
+
+jboolean native_testAngleLocation(JNIEnv*, jobject) {
+  if (access(SYSTEM_LIB_PATH "/libEGL_angle.so", R_OK) != 0) {
+    __android_log_print(ANDROID_LOG_ERROR, TAG,
+                        SYSTEM_LIB_PATH "/libEGL_angle.so not found");
+    return JNI_FALSE;
+  }
+  if (access(SYSTEM_LIB_PATH "/libGLESv1_CM_angle.so", R_OK) != 0) {
+    __android_log_print(ANDROID_LOG_ERROR, TAG,
+                        SYSTEM_LIB_PATH "/libGLESv1_CM_angle.so not found");
+    return JNI_FALSE;
+  }
+  if (access(SYSTEM_LIB_PATH "/libGLESv2_angle.so", R_OK) != 0) {
+    __android_log_print(ANDROID_LOG_ERROR, TAG,
+                        SYSTEM_LIB_PATH "/libGLESv2_angle.so not found");
+    return JNI_FALSE;
+  }
+  return JNI_TRUE;
+}
+
+static const JNINativeMethod gVtsAngleLocationTestMethods[] = {
+    {"native_testAngleLocation", "()Z", (void*)native_testAngleLocation},
+};
+
+int register_com_google_android_vts_angle_VtsAngleLocationTest(JNIEnv* env) {
+  jclass clazz =
+      env->FindClass("com/google/android/vts/angle/testapp/VtsAngleTestCase");
+  int ret = env->RegisterNatives(clazz, gVtsAngleLocationTestMethods,
+                                 ARRAY_SIZE(gVtsAngleLocationTestMethods));
+  env->DeleteLocalRef(clazz);
+  return ret;
+}
diff --git a/tests/angleallowliststrace_test/app/jni/onload.cpp b/tests/angleallowliststrace_test/app/jni/onload.cpp
new file mode 100644
index 000000000..163c44c31
--- /dev/null
+++ b/tests/angleallowliststrace_test/app/jni/onload.cpp
@@ -0,0 +1,34 @@
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
+#include <jni.h>
+
+#define ARRAY_SIZE(x) (sizeof((x)) / (sizeof(((x)[0]))))
+
+int register_com_google_android_vts_angle_VtsAngleLocationTest(JNIEnv* env);
+
+extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
+  JNIEnv* env;
+  if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
+    return JNI_ERR;
+  }
+
+  if (register_com_google_android_vts_angle_VtsAngleLocationTest(env) < 0) {
+    return JNI_ERR;
+  }
+
+  return JNI_VERSION_1_6;
+}
diff --git a/tests/angleallowliststrace_test/app/src/com/google/android/vts/angle/testapp/VtsAngleTestCase.java b/tests/angleallowliststrace_test/app/src/com/google/android/vts/angle/testapp/VtsAngleTestCase.java
new file mode 100644
index 000000000..e682d7710
--- /dev/null
+++ b/tests/angleallowliststrace_test/app/src/com/google/android/vts/angle/testapp/VtsAngleTestCase.java
@@ -0,0 +1,39 @@
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
+package com.google.android.vts.angle.testapp;
+
+import static org.junit.Assert.fail;
+
+import androidx.test.runner.AndroidJUnit4;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+@RunWith(AndroidJUnit4.class)
+public class VtsAngleTestCase {
+    static {
+        System.loadLibrary("vtsanglelocationtest_jni");
+    }
+
+    @Test
+    public void testAngleLocation() throws Exception {
+        if (!native_testAngleLocation()) {
+            fail("Failure - ANGLE was not found.");
+        }
+    }
+
+    private native boolean native_testAngleLocation();
+}
diff --git a/tests/angleallowliststrace_test/host/Android.bp b/tests/angleallowliststrace_test/host/Android.bp
new file mode 100644
index 000000000..01b74f6ed
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/Android.bp
@@ -0,0 +1,38 @@
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
+    default_team: "trendy_team_android_gpu",
+    // See: http://go/android-license-faq
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+java_test_host {
+    name: "AngleAllowlistTraceTest",
+    srcs: ["src/**/*.java"],
+    test_suites: ["vts"],
+    libs: [
+        "compatibility-host-util",
+        "compatibility-tradefed",
+        "tradefed",
+    ],
+    device_common_data: [
+        ":VtsAngleTestApp",
+    ],
+}
+
+java_test_helper_library {
+    name: "AngleAllowlistLibrary",
+    srcs: ["src/com/google/android/angleallowlists/vts/AngleAllowlist.java"],
+}
diff --git a/tests/angleallowliststrace_test/host/AndroidTest.xml b/tests/angleallowliststrace_test/host/AndroidTest.xml
new file mode 100644
index 000000000..6a54e5d3c
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/AndroidTest.xml
@@ -0,0 +1,30 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<configuration description="Config for VTS Angle Allowlist Trace Test">
+    <option name="test-suite-tag" value="vts" />
+
+    <!--  Disable GPP -->
+    <target_preparer class="com.android.tradefed.targetprep.DeviceSetup">
+        <option name="force-skip-system-props" value="true" />
+        <option name="set-global-setting" key="verifier_engprod" value="1" />
+        <option name="set-global-setting" key="verifier_verify_adb_installs" value="0" />
+        <option name="restore-settings" value="true" />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.HostTest" >
+        <option name="class" value="com.google.android.angleallowlists.vts.AngleAllowlistTraceTest" />
+    </test>
+</configuration>
diff --git a/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleAllowlist.java b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleAllowlist.java
new file mode 100644
index 000000000..0ffba144e
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleAllowlist.java
@@ -0,0 +1,39 @@
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
+package com.google.android.angleallowlists.vts;
+
+import java.util.HashMap;
+import java.util.Map;
+
+// allowlist apps are defined per GMS requirement: b/369880861
+public class AngleAllowlist {
+    public static final Map<String, String> apps = new HashMap<>();
+    static {
+        apps.put("com.dreamgames.royalmatch", "royal_match");
+        apps.put("com.dts.freefiremax", "free_fire_max");
+        apps.put("com.dxx.firenow", "survivor_io");
+        apps.put("com.gramgames.mergedragons", "merge_dragons");
+        apps.put("com.ludo.king", "ludo_king");
+        apps.put("com.mojang.minecraftpe", "minecraft_bedrock");
+        apps.put("com.my.defense", "rush_royale");
+        apps.put("com.nintendo.zaka", "mario_kart_tour");
+        apps.put("com.os.airforce", "1945_air_force");
+        apps.put("com.playrix.fishdomdd.gplay", "fishdom");
+        apps.put("io.teslatech.callbreak", "callbreak");
+        apps.put("jp.konami.prospia", "professional_baseball_spirits");
+        apps.put("net.peakgames.toonblast", "toon_blast");
+    }
+}
diff --git a/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleAllowlistTraceTest.java b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleAllowlistTraceTest.java
new file mode 100644
index 000000000..3b6c028dd
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleAllowlistTraceTest.java
@@ -0,0 +1,704 @@
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
+package com.google.android.angleallowlists.vts;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
+
+import com.android.compatibility.common.util.FeatureUtil;
+import com.android.compatibility.common.util.PropertyUtil;
+import com.android.compatibility.common.util.VsrTest;
+import com.android.tradefed.config.Option;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+import com.android.tradefed.util.RunUtil;
+import com.google.common.io.Files;
+import java.io.File;
+import java.io.IOException;
+import java.nio.charset.StandardCharsets;
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+import java.util.StringTokenizer;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+import org.junit.After;
+import org.junit.Assume;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TemporaryFolder;
+import org.junit.rules.TestName;
+import org.junit.runner.RunWith;
+
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class AngleAllowlistTraceTest extends BaseHostJUnit4Test {
+    // Object that invokes adb commands and interacts with test devices
+    private Helper mTestHelper;
+
+    // Multi-user system property
+    private String mCurrentUser;
+
+    // ANGLE trace app directory. The directory path is affected by the value of mCurrentUser
+    private String mAngleTraceTestAppHomeDir;
+    private String mAngleTraceTestBlobCacheDir;
+
+    // Properties used for Vulkan feature checks
+    private static final int VULKAN_1_1 = 0x00401000; // 1.1.0
+    private static final String VULKAN_VERSION_FEATURE = "feature:android.hardware.vulkan.version";
+    private static final String VULKAN_LEVEL_FEATURE = "feature:android.hardware.vulkan.level";
+
+    // Package install attempts and intervals before install retries
+    private static final int NUM_ATTEMPTS = 5;
+    private static final int APP_INSTALL_REATTEMPT_SLEEP_MSEC = 5000;
+
+    // Trace test max runs
+    private static final int MAX_TRACE_RUN_COUNT = 5;
+
+    // Trace test FPS requirement
+    private static final double FPS_REQUIREMENT = 60.0;
+
+    // Comparison threshold when NATIVE FPS > 60 and ANGLE FPS < 60
+    // Allow 10% threshold when measuring ANGLE FPS against 60, so that we consider below case as
+    // passing:
+    // NATIVE: 61.18
+    // ANGLE:  59.81
+    private static final double FPS_THRESHOLD = 0.9;
+
+    private static enum DriverType { ANGLE, NATIVE }
+    ;
+
+    // Properties used for ANGLE Trace test
+    @Rule public final TemporaryFolder mTemporaryFolder = new TemporaryFolder();
+
+    @Rule
+    public final DeviceJUnit4ClassRunner.TestMetrics mMetrics =
+            new DeviceJUnit4ClassRunner.TestMetrics();
+
+    @Rule
+    public final DeviceJUnit4ClassRunner.TestLogData mLogData =
+            new DeviceJUnit4ClassRunner.TestLogData();
+
+    @Rule public final TestName mTestName = new TestName();
+
+    @Option(name = "angle_trace_package_path", description = "path to angle trace package files")
+    private String mANGLETracePackagePath = null;
+
+    // Allows partners to run tests on devices that haven't fully configured with proper vendor api
+    // b/377337787#comment25
+    @Option(name = "bypass-vendor-api-requirement",
+            description = "whether to bypass the vendor api requirement check")
+    private boolean mBypassVendorApiRequirement = false;
+
+    private static final String ANGLE_TRACE_TEST_PACKAGE_NAME = "com.android.angle.test";
+    private static final String ANGLE_TRACE_DATA_ON_DEVICE_DIR =
+            "/storage/emulated/0/chromium_tests_root";
+
+    private static final int WAIT_RUN_TRACES_MILLIS = 5 * 60 * 1000;
+    private HashMap<String, Double> mTracePerfANGLEFPS = new HashMap<>();
+    private HashMap<String, Double> mTracePerfNativeFPS = new HashMap<>();
+
+    private HashSet<String> mSkippedTrace = new HashSet<>();
+    private HashSet<String> mTracePerfANGLEBelowRequiredFPS = new HashSet<>();
+
+    // Group 1: e.g. "wall_time"
+    // Group 2: e.g. "1945_air_force".
+    // Group 3: time in ms. e.g. "11.5506817933".
+    private static final Pattern PATTERN_METRICS = Pattern.compile(
+            "TracePerf_(?:vulkan|native)\\.(wall_time|gpu_time): ([^\\s=]*)= ([^\\s]*) ms");
+    private static final Pattern PATTERN_TRACE_NAMES = Pattern.compile("TraceTest.(.*?)\n");
+
+    private String getDefaultANGLETracePathDir() {
+        return System.getProperty("user.dir").concat("/angle_traces");
+    }
+
+    private void setANGLETracePackagePath() {
+        if (mANGLETracePackagePath == null) {
+            mANGLETracePackagePath = getDefaultANGLETracePathDir();
+        }
+    }
+
+    /**
+     * Invokes BaseHostJUnit4Test installPackage() API, with NUM_ATTEMPTS of retries
+     * Difference between this function and Helper.installApkFile() is this function can only
+     * install apks that exist in the same test module (e.g. apks that are specified under
+     * device_common_data or data field in Android.bp), while installApkFile() can install apks from
+     * any directory.
+     */
+    private void installTestApp(String appName) throws Exception {
+        for (int i = 0; i < NUM_ATTEMPTS; i++) {
+            try {
+                installPackage(appName);
+                return;
+            } catch (Exception e) {
+                LogUtil.CLog.e("Exception in installing the app: %s, error message: %s", appName,
+                        e.getMessage());
+                if (i < NUM_ATTEMPTS - 1) {
+                    RunUtil.getDefault().sleep(APP_INSTALL_REATTEMPT_SLEEP_MSEC);
+                } else {
+                    throw e;
+                }
+            }
+        }
+    }
+
+    private String getAngleInstrumentCommand(final String gtestArguments) {
+        return String.format("am instrument -w -e"
+                        + " org.chromium.native_test.NativeTestInstrumentationTestRunner.StdoutFile"
+                        + " %s/files/out.txt -e"
+                        + " org.chromium.native_test.NativeTest.CommandLineFlags \"%s\" -e"
+                        + " org.chromium.native_test."
+                        + "NativeTestInstrumentationTestRunner.ShardNanoTimeout"
+                        + " 1000000000000000000 -e"
+                        + " org.chromium.native_test."
+                        + "NativeTestInstrumentationTestRunner.NativeTestActivity"
+                        + "  com.android.angle.test.AngleUnitTestActivity "
+                        + " com.android.angle.test/"
+                        + "org.chromium.build.gtest_apk.NativeTestInstrumentationTestRunner",
+                mAngleTraceTestAppHomeDir, gtestArguments);
+    }
+
+    private void runAndBlockAngleTestApp(final Helper helper, final String gtestArguments)
+            throws CommandException, InstrumentationCrashException {
+        helper.adbShellInstrumentationCommandCheck(
+                WAIT_RUN_TRACES_MILLIS, getAngleInstrumentCommand(gtestArguments));
+
+        // Cat the stdout file. This will be logged.
+        helper.adbShellCommandCheck(Helper.WAIT_ADB_SHELL_FILE_OP_MILLIS,
+                String.format("run-as %s cat %s/files/out.txt", ANGLE_TRACE_TEST_PACKAGE_NAME,
+                        mAngleTraceTestAppHomeDir));
+    }
+
+    /** Run angle_trace_tests app to get the list of traces */
+    private List<String> runAngleListTrace(final Helper helper, final File gtestStdoutFile)
+            throws CommandException, InstrumentationCrashException, IOException,
+                   DeviceNotAvailableException {
+        // verify the device state
+        helper.assertDeviceStateOk();
+
+        // Remove previous stdout file on the device, if present.
+        helper.adbShellCommandCheck(Helper.WAIT_ADB_SHELL_FILE_OP_MILLIS,
+                String.format("run-as %s rm -f %s/files/out.txt", ANGLE_TRACE_TEST_PACKAGE_NAME,
+                        mAngleTraceTestAppHomeDir));
+
+        // Check file has gone but the directory exists.
+        helper.adbShellCommandCheck(Helper.WAIT_ADB_SHELL_FILE_OP_MILLIS,
+                String.format("run-as %s test ! -f %s/files/out.txt && run-as %s test -d %s",
+                        ANGLE_TRACE_TEST_PACKAGE_NAME, mAngleTraceTestAppHomeDir,
+                        ANGLE_TRACE_TEST_PACKAGE_NAME, mAngleTraceTestAppHomeDir));
+
+        // run angle_trace_tests app with --list-tests arg
+        runAndBlockAngleTestApp(helper, "--list-tests");
+
+        // pull the test output file
+        helper.adbShellCommandWithStdout(Helper.WAIT_ADB_SHELL_FILE_OP_MILLIS, gtestStdoutFile,
+                String.format("run-as %s cat %s/files/out.txt", ANGLE_TRACE_TEST_PACKAGE_NAME,
+                        mAngleTraceTestAppHomeDir));
+
+        // Log it.
+        helper.logTextFile("ListTraceOutput", gtestStdoutFile);
+
+        // Read it.
+        final String stdout = Files.asCharSource(gtestStdoutFile, StandardCharsets.UTF_8).read();
+
+        // Find list of traces to run
+        final Matcher traceNameMatcher = PATTERN_TRACE_NAMES.matcher(stdout);
+
+        // Store the trace names in an ArrayList
+        final ArrayList<String> traceNames = new ArrayList<>();
+
+        while (traceNameMatcher.find()) {
+            final String traceName = traceNameMatcher.group(1);
+            traceNames.add(traceName);
+        }
+        return traceNames;
+    }
+
+    /**
+     * Execute angle trace test on trace with traceName until either of below conditions is met:
+     * 1) trace reaches FPS_REQUIREMENT fps
+     * 2) trace is ran for totalTraceRunCount times
+     */
+    private Double runAngleTracePerfMultiTimes(final String traceName, final File gtestStdoutFile,
+            final Helper helper, final DriverType driverType, final int totalTraceRunCount)
+            throws Throwable {
+        assertTrue("totalTraceRunCount must be greater than 0", totalTraceRunCount > 0);
+        Double traceFPS = null;
+        int traceRunCount = 0;
+        do {
+            runAngleTracePerf(traceName, gtestStdoutFile, helper, driverType);
+            switch (driverType) {
+                case ANGLE:
+                    traceFPS = mTracePerfANGLEFPS.get(traceName);
+                    break;
+                case NATIVE:
+                    traceFPS = mTracePerfNativeFPS.get(traceName);
+                    break;
+                default:
+                    fail("must specify either ANGLE or NATIVE as the driverType");
+            }
+            assertTrue(traceFPS != null);
+        } while ((Double.compare(traceFPS.doubleValue(), FPS_REQUIREMENT) < 0)
+                && ++traceRunCount < totalTraceRunCount);
+
+        return traceFPS;
+    }
+
+    /**
+     * Execute angle trace test on trace with traceName
+     * This function invokes trace test packaged in com.android.angle.test apk through
+     * instrumentation commands
+     */
+    private void runAngleTracePerf(final String testName, final File gtestStdoutFile,
+            final Helper helper, final DriverType driverType)
+            throws CommandException, InstrumentationCrashException, IOException,
+                   DeviceNotAvailableException {
+        // verify device state
+        helper.assertDeviceStateOk();
+
+        // Remove previous stdout file on the device, if present.
+        helper.adbShellCommandCheck(Helper.WAIT_ADB_SHELL_FILE_OP_MILLIS,
+                String.format("run-as %s rm -f %s/files/out.txt", ANGLE_TRACE_TEST_PACKAGE_NAME,
+                        mAngleTraceTestAppHomeDir));
+
+        // Check file has gone but the directory exists.
+        helper.adbShellCommandCheck(Helper.WAIT_ADB_SHELL_FILE_OP_MILLIS,
+                String.format("run-as %s test ! -f %s/files/out.txt && run-as %s test -d %s",
+                        ANGLE_TRACE_TEST_PACKAGE_NAME, mAngleTraceTestAppHomeDir,
+                        ANGLE_TRACE_TEST_PACKAGE_NAME, mAngleTraceTestAppHomeDir));
+
+        // Remove previous stdout file on the host, if present.
+        // noinspection ResultOfMethodCallIgnored
+        gtestStdoutFile.delete();
+
+        // Check file has gone.
+        assertFalse("Failed to delete " + gtestStdoutFile, gtestStdoutFile.exists());
+
+        // Clear blob cache
+        helper.adbShellCommandCheck(Helper.WAIT_ADB_LARGE_FILE_OP_MILLIS,
+                String.format("run-as %s rm -rf %s", ANGLE_TRACE_TEST_PACKAGE_NAME,
+                        mAngleTraceTestBlobCacheDir));
+
+        // Run the trace.
+        switch (driverType) {
+            case ANGLE:
+                // Set trace to run with System ANGLE
+                mTestHelper.adbShellCommandCheck(mTestHelper.WAIT_SET_GLOBAL_SETTING_MILLIS,
+                        "settings put global angle_gl_driver_selection_pkgs"
+                                + " com.android.angle.test");
+                mTestHelper.adbShellCommandCheck(mTestHelper.WAIT_SET_GLOBAL_SETTING_MILLIS,
+                        "settings put global angle_gl_driver_selection_values angle");
+                break;
+            case NATIVE:
+                // Delete global vars so that trace run on default native driver
+                mTestHelper.adbShellCommandCheck(mTestHelper.WAIT_SET_GLOBAL_SETTING_MILLIS,
+                        "settings delete global angle_gl_driver_selection_pkgs");
+                mTestHelper.adbShellCommandCheck(mTestHelper.WAIT_SET_GLOBAL_SETTING_MILLIS,
+                        "settings delete global angle_gl_driver_selection_values");
+                break;
+            default:
+                fail("must specify either ANGLE or NATIVE as the driverType");
+                break;
+        }
+        runAndBlockAngleTestApp(helper,
+                String.format("--gtest_filter=TraceTest.%s "
+                                + "--use-gl=native "
+                                + "--verbose "
+                                + "--verbose-logging "
+                                + "--fps-limit=100 "
+                                + "--fixed-test-time-with-warmup "
+                                + "10",
+                        testName));
+
+        helper.assertDeviceStateOk();
+
+        getAndLogTraceMetrics(testName, gtestStdoutFile, helper, driverType);
+    }
+
+    /**
+     * Parse the trace test result and store the result
+     */
+    private void getAndLogTraceMetrics(final String testName, final File gtestStdoutFile,
+            final Helper helper, final DriverType driverType) throws CommandException, IOException {
+        String renderer = driverType.toString();
+
+        // cat the test output file
+        helper.adbShellCommandWithStdout(Helper.WAIT_ADB_SHELL_FILE_OP_MILLIS, gtestStdoutFile,
+                String.format("run-as %s cat %s/files/out.txt", ANGLE_TRACE_TEST_PACKAGE_NAME,
+                        mAngleTraceTestAppHomeDir));
+
+        // Log it.
+        helper.logTextFile(String.format("%s_stdout", testName), gtestStdoutFile);
+
+        // Read it.
+        final String stdout = Files.asCharSource(gtestStdoutFile, StandardCharsets.UTF_8).read();
+
+        boolean isTraceSkipped = false;
+
+        if (stdout.contains("Test skipped due to missing extension")) {
+            LogUtil.CLog.d("ANGLE trace test skipped: missing ext");
+            isTraceSkipped = true;
+        }
+
+        if (stdout.contains("[  SKIPPED ] 1 test, listed below:")) {
+            LogUtil.CLog.d("ANGLE trace test skipped");
+            isTraceSkipped = true;
+        }
+
+        if (isTraceSkipped) {
+            mSkippedTrace.add(testName);
+            helper.logMetricString(testName, "skipped");
+            return;
+        }
+
+        // Find all metrics of interest in the stdout file and store them into metricsMap.
+        final Matcher metricsMatcher = PATTERN_METRICS.matcher(stdout);
+        final HashMap<String, String> metricsMap = new HashMap<>();
+
+        // Keep a list as well, so that we process the metrics deterministically, in order.
+        final ArrayList<String> metricNames = new ArrayList<>();
+
+        while (metricsMatcher.find()) {
+            final String metricName = metricsMatcher.group(1);
+            final String metricValue = metricsMatcher.group(3);
+
+            if (!metricsMap.containsKey(metricName)) {
+                metricNames.add(metricName);
+            }
+            metricsMap.put(metricName, metricValue);
+        }
+
+        assertTrue("We expect at least one metric.", metricNames.size() >= 1);
+
+        // Add each time as a metric
+        for (final String metricName : metricNames) {
+            final String metricValue = metricsMap.get(metricName);
+
+            // E.g. "1945_air_force.angle.wall_time"
+            // E.g. "1945_air_force.native.wall_time"
+            String fullMetricName = String.format("%s.%s.%s", testName, renderer, metricName);
+
+            helper.logMetricDouble(String.format("%s_ms", fullMetricName), metricValue, "ms");
+
+            if (metricName.equals("wall_time")) {
+                // Calculate FPS
+                double wallTime = Double.parseDouble(metricValue);
+                assertTrue("wallTime should be bigger than 0", Double.compare(wallTime, 0.0) > 0);
+                double fps = 1000.0 / wallTime;
+                switch (driverType) {
+                    case ANGLE:
+                        mTracePerfANGLEFPS.put(testName, Double.valueOf(fps));
+                        break;
+                    case NATIVE:
+                        mTracePerfNativeFPS.put(testName, Double.valueOf(fps));
+                        break;
+                    default:
+                        fail("must specify either ANGLE or NATIVE as the driverType");
+                }
+
+                // Log FPS in metrics, which will be saved as a tradefed result file later with
+                // mTestHelper.saveMetricsAsArtifact()
+                fullMetricName = String.format("%s.%s.fps", testName, renderer);
+                helper.logMetricDouble(fullMetricName, String.valueOf(fps), "fps");
+            }
+        }
+    }
+
+    private void uninstallTestApps() throws CommandException {
+        // Remove the existing ANGLE allowlist trace test apk from the device, if present.
+        mTestHelper.uninstallAppIgnoreErrors(ANGLE_TRACE_TEST_PACKAGE_NAME);
+
+        // Remove previous ANGLE trace data directory, if present
+        mTestHelper.adbShellCommandCheck(mTestHelper.WAIT_ADB_LARGE_FILE_OP_MILLIS,
+                String.format("rm -rf %s", ANGLE_TRACE_DATA_ON_DEVICE_DIR));
+
+        // Remove the existing ANGLE allowlist driver check apk from the device, if present
+        mTestHelper.uninstallAppIgnoreErrors(AngleCommon.ANGLE_TEST_PKG);
+    }
+
+    private boolean isLowRamDevice(ITestDevice device) throws Exception {
+        return "true".equals(device.getProperty("ro.config.low_ram"));
+    }
+
+    /**
+     * Check if device supports vulkan 1.1.
+     * If the device includes a Vulkan driver, feature list returned by
+     * "adb shell pm list features" should contain
+     * "feature:android.hardware.vulkan.level" (FEATURE_VULKAN_HARDWARE_LEVEL) and
+     * "feature:android.hardware.vulkan.version" (FEATURE_VULKAN_HARDWARE_VERSION)
+     * reference: https://source.android.com/docs/core/graphics/implement-vulkan
+     */
+    private boolean isVulkan11Supported(ITestDevice device) throws Exception {
+        final String features = device.executeShellCommand("pm list features");
+
+        StringTokenizer featureToken = new StringTokenizer(features, "\n");
+
+        boolean isVulkanLevelFeatureSupported = false;
+
+        boolean isVulkanVersionFeatureSupported = false;
+
+        boolean isVulkan_1_1_Supported = false;
+
+        while (featureToken.hasMoreTokens()) {
+            String currentFeature = featureToken.nextToken();
+
+            // Check if currentFeature strings starts with "feature:android.hardware.vulkan.level"
+            // Check that currentFeature string length is at least the length of
+            // "feature:android.hardware.vulkan.level" before calling substring so that the endIndex
+            // is not out of bound.
+            if (currentFeature.length() >= VULKAN_LEVEL_FEATURE.length()
+                    && currentFeature.substring(0, VULKAN_LEVEL_FEATURE.length())
+                               .equals(VULKAN_LEVEL_FEATURE)) {
+                isVulkanLevelFeatureSupported = true;
+            }
+
+            // Check if currentFeature strings starts with "feature:android.hardware.vulkan.version"
+            // Check that currentFeature string length is at least the length of
+            // "feature:android.hardware.vulkan.version" before calling substring so that the
+            // endIndex is not out of bound.
+            if (currentFeature.length() >= VULKAN_VERSION_FEATURE.length()
+                    && currentFeature.substring(0, VULKAN_VERSION_FEATURE.length())
+                               .equals(VULKAN_VERSION_FEATURE)) {
+                isVulkanVersionFeatureSupported = true;
+
+                // If android.hardware.vulkan.version feature is supported by the device,
+                // check if the vulkan version supported is at least vulkan 1.1.
+                // ANGLE is only intended to work properly with vulkan version >= vulkan 1.1
+                String[] currentFeatureAndValue = currentFeature.split("=");
+                if (currentFeatureAndValue.length > 1) {
+                    int vulkanVersionLevelSupported = Integer.parseInt(currentFeatureAndValue[1]);
+                    isVulkan_1_1_Supported = vulkanVersionLevelSupported >= VULKAN_1_1;
+                }
+            }
+
+            if (isVulkanLevelFeatureSupported && isVulkanVersionFeatureSupported
+                    && isVulkan_1_1_Supported) {
+                return true;
+            }
+        }
+
+        return false;
+    }
+
+    private boolean isVendorAPILevelMeetingA16Requirement(ITestDevice device) throws Exception {
+        if (mBypassVendorApiRequirement) {
+            return true;
+        }
+        final int vendorApiLevel = PropertyUtil.getVsrApiLevel(device);
+        return vendorApiLevel >= 202504;
+    }
+
+    private void verifyTraceList(List<String> traceNames) {
+        Set<String> traceNamesSet = new HashSet<>();
+        for (String traceName : traceNames) {
+            traceNamesSet.add(traceName);
+        }
+        for (String requiredAppName : AngleAllowlist.apps.values()) {
+            assertTrue(String.format("app %s must be included in the angle trace package",
+                               requiredAppName),
+                    traceNamesSet.contains(requiredAppName));
+        }
+    }
+
+    @Before
+    public void setUp() throws Exception {
+        // Instantiate a Helper object, which also calls Helper.preTestSetup()
+        // that sets the device ready for tests
+        mTestHelper = new Helper(getTestInformation(), mTemporaryFolder, mMetrics, mLogData,
+                mTestName.getMethodName());
+
+        // Query current_user
+        final File cmdStdOutFile = new File(mTemporaryFolder.getRoot(), "cmdStdOut.txt");
+        mCurrentUser = mTestHelper.adbShellCommandWithStdout(
+                mTestHelper.WAIT_SET_GLOBAL_SETTING_MILLIS, cmdStdOutFile, "am get-current-user");
+
+        LogUtil.CLog.d("mCurrentUser is: %s", mCurrentUser);
+
+        mAngleTraceTestAppHomeDir =
+                String.format("/data/user/%s/com.android.angle.test", mCurrentUser);
+        mAngleTraceTestBlobCacheDir =
+                String.format("/data/user_de/%s/com.android.angle.test/cache", mCurrentUser);
+
+        setANGLETracePackagePath();
+
+        uninstallTestApps();
+
+        AngleCommon.clearSettings(getDevice());
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        uninstallTestApps();
+
+        AngleCommon.clearSettings(getDevice());
+    }
+
+    @VsrTest(requirements = {"VSR-5.1"})
+    @Test
+    public void testAngleTraces() throws Throwable {
+        Assume.assumeFalse(isLowRamDevice(getDevice()));
+        Assume.assumeFalse(FeatureUtil.isTV(getDevice()));
+        Assume.assumeTrue(isVulkan11Supported(getDevice()));
+        Assume.assumeTrue(isVendorAPILevelMeetingA16Requirement(getDevice()));
+        // Firstly check ANGLE is available in System Partition
+        // Install driver check app
+        installTestApp(AngleCommon.ANGLE_TEST_APP);
+        // Verify ANGLE is available in system partition
+        runDeviceTests(AngleCommon.ANGLE_TEST_PKG,
+                AngleCommon.ANGLE_TEST_PKG + "." + AngleCommon.ANGLE_DRIVER_TEST_CLASS,
+                AngleCommon.ANGLE_DRIVER_TEST_LOCATION_METHOD);
+
+        // Secondly run trace tests with System ANGLE
+        // We will copy the stdout file content from the device to here.
+        final File gtestStdoutFile = new File(mTemporaryFolder.getRoot(), "out.txt");
+
+        try {
+            LogUtil.CLog.d("Installing angle trace app and pushing trace data to the device.");
+
+            // Create trace data directory on the device.
+            mTestHelper.deviceMkDirP(ANGLE_TRACE_DATA_ON_DEVICE_DIR);
+
+            final File angleTraceTestPackage = new File(mANGLETracePackagePath);
+
+            // Install the ANGLE APK.
+            final File angleApkFile = mTestHelper.path(angleTraceTestPackage, "out",
+                    "AndroidPerformance", "angle_trace_tests_apk", "angle_trace_tests-debug.apk");
+
+            mTestHelper.installApkFile(angleApkFile);
+
+            // grant test apk permissions
+            mTestHelper.adbShellCommandCheck(mTestHelper.WAIT_ADB_SHELL_FILE_OP_MILLIS,
+                    String.format("appops set %s MANAGE_EXTERNAL_STORAGE allow || true",
+                            ANGLE_TRACE_TEST_PACKAGE_NAME));
+
+            // Push trace_list.json
+            final File angleTraceListJson = mTestHelper.path(
+                    angleTraceTestPackage, "out", "AndroidPerformance", "gen", "trace_list.json");
+            mTestHelper.adbCommandCheck(mTestHelper.WAIT_ADB_SHELL_FILE_OP_MILLIS, "push",
+                    angleTraceListJson.toString(),
+                    String.format("%s/gen/trace_list.json", ANGLE_TRACE_DATA_ON_DEVICE_DIR));
+
+            // Create a src/tests/restricted_traces directory on test device, this is required in
+            // order for angle_trace_tests app process to launch successfully
+            mTestHelper.deviceMkDirP(String.format(
+                    "%s/src/tests/restricted_traces", ANGLE_TRACE_DATA_ON_DEVICE_DIR));
+
+            // Launch angle_trace_tests app with --list-test argument to get the list of trace names
+            List<String> traceNames = runAngleListTrace(mTestHelper, gtestStdoutFile);
+
+            // Verify the traces in angle_traces package contains all required ANGLE allowlist apps
+            verifyTraceList(traceNames);
+
+            // Delete angle_debug_package global settings so that when trace is set to run
+            // with DriverType.ANGLE, trace will use system ANGLE, not ANGLE debug apk.
+            mTestHelper.adbShellCommandCheck(mTestHelper.WAIT_SET_GLOBAL_SETTING_MILLIS,
+                    "settings delete global angle_debug_package");
+
+            // Run all the trace test of apps required on ANGLE allowlist.
+            for (final String traceName : AngleAllowlist.apps.values()) {
+                // push the "<traceName>.json" onto the device
+                String traceJsonFileName = String.format("%s.json", traceName);
+                final File traceJsonFile = mTestHelper.path(angleTraceTestPackage, "src", "tests",
+                        "restricted_traces", traceName, traceJsonFileName);
+                mTestHelper.adbCommandCheck(mTestHelper.WAIT_ADB_LARGE_FILE_OP_MILLIS, "push",
+                        traceJsonFile.toString(),
+                        String.format("%s/src/tests/restricted_traces/%s/%s",
+                                ANGLE_TRACE_DATA_ON_DEVICE_DIR, traceName, traceJsonFileName));
+
+                // push the "<traceName>.angledata.gz" file onto the device
+                String traceDataFileName = String.format("%s.angledata.gz", traceName);
+                final File traceDataFile = mTestHelper.path(angleTraceTestPackage, "src", "tests",
+                        "restricted_traces", traceName, traceDataFileName);
+                mTestHelper.adbCommandCheck(mTestHelper.WAIT_ADB_LARGE_FILE_OP_MILLIS, "push",
+                        traceDataFile.toString(),
+                        String.format("%s/src/tests/restricted_traces/%s/%s",
+                                ANGLE_TRACE_DATA_ON_DEVICE_DIR, traceName, traceDataFileName));
+
+                // Run trace test on angle until either of below conditions is met:
+                // 1) trace reaches FPS_REQUIREMENT fps
+                // 2) trace is ran MAX_TRACE_RUN_COUNT times
+                Double currentTraceAngleFPS = runAngleTracePerfMultiTimes(traceName,
+                        gtestStdoutFile, mTestHelper, DriverType.ANGLE, MAX_TRACE_RUN_COUNT);
+
+                // If trace fails to reach FPS_REQUIREMENT fps on ANGLE, run trace on native driver,
+                // too. If trace also fails to reach FPS_REQUIREMENT fps on native, we treat this
+                // trace test passes on ANGLE, as ANGLE doesn't make the trace perform worse.
+                if (Double.compare(currentTraceAngleFPS.doubleValue(), FPS_REQUIREMENT) < 0) {
+                    mTracePerfANGLEBelowRequiredFPS.add(traceName);
+                    runAngleTracePerfMultiTimes(traceName, gtestStdoutFile, mTestHelper,
+                            DriverType.NATIVE, MAX_TRACE_RUN_COUNT);
+                }
+            }
+
+            // Check all required traces completed successfully
+            assertTrue(String.format("Not all required traces are ran, traces that are skipped: %s",
+                               mSkippedTrace.toString()),
+                    mTracePerfANGLEFPS.size() == AngleAllowlist.apps.size());
+
+            // Check trace test result
+            Set<String> failedTraceList = new HashSet<String>();
+            for (String traceName : mTracePerfANGLEBelowRequiredFPS) {
+                final boolean isNativeTraceDataAvailable =
+                        mTracePerfNativeFPS.containsKey(traceName);
+                assertTrue(String.format(
+                                   "trace %s runs slower than %f fps on ANGLE, we expect the trace"
+                                           + " to also execute on native driver, but there is no "
+                                           + "data from native driver run",
+                                   traceName, FPS_REQUIREMENT),
+                        isNativeTraceDataAvailable);
+                Double nativeFps = mTracePerfNativeFPS.get(traceName);
+                boolean nativeFpsReachesRequiredFPS =
+                        Double.compare(nativeFps.doubleValue(), FPS_REQUIREMENT) >= 0;
+                if (!nativeFpsReachesRequiredFPS) {
+                    LogUtil.CLog.d(
+                            "trace %s doesn't reach %f FPS on both ANGLE and NATIVE GLES driver",
+                            traceName, FPS_REQUIREMENT);
+                } else {
+                    Double angleFps = mTracePerfANGLEFPS.get(traceName);
+                    if (angleFps < FPS_REQUIREMENT * FPS_THRESHOLD) {
+                        failedTraceList.add(traceName);
+                    }
+                }
+            }
+            if (!failedTraceList.isEmpty()) {
+                for (String failedTraceName : failedTraceList) {
+                    LogUtil.CLog.e("trace %s reaches %f FPS on NATIVE, native fps: %f, but fails "
+                                    + "on ANGLE, angle fps: %f, and FPS on ANGLE is less than %f "
+                                    + "of %f",
+                            failedTraceName, FPS_REQUIREMENT,
+                            mTracePerfNativeFPS.get(failedTraceName),
+                            mTracePerfANGLEFPS.get(failedTraceName), FPS_THRESHOLD,
+                            FPS_REQUIREMENT);
+                }
+                fail(String.format("There are traces that reaches %f FPS on NATIVE, but fails to "
+                                + "reach %f FPS on ANGLE: %s, and FPS on ANGLE is less than %f "
+                                + "of %f",
+                        FPS_REQUIREMENT, FPS_REQUIREMENT, failedTraceList.toString(), FPS_THRESHOLD,
+                        FPS_REQUIREMENT));
+            }
+        } finally {
+            mTestHelper.saveMetricsAsArtifact();
+        }
+    }
+}
diff --git a/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleCommon.java b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleCommon.java
new file mode 100644
index 000000000..3c638a1bc
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/AngleCommon.java
@@ -0,0 +1,50 @@
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
+package com.google.android.angleallowlists.vts;
+
+import com.android.tradefed.device.ITestDevice;
+import java.util.HashMap;
+import java.util.Map;
+
+public class AngleCommon {
+    // Settings.Global
+    public static final String SETTINGS_GLOBAL_ALL_USE_ANGLE = "angle_gl_driver_all_angle";
+    public static final String SETTINGS_GLOBAL_DRIVER_PKGS = "angle_gl_driver_selection_pkgs";
+    public static final String SETTINGS_GLOBAL_DRIVER_VALUES = "angle_gl_driver_selection_values";
+    public static final String SETTINGS_GLOBAL_ANGLE_DEBUG_PACKAGE = "angle_debug_package";
+
+    // ANGLE
+    public static final String ANGLE_TEST_PKG = "com.google.android.vts.angle.testapp";
+    public static final String ANGLE_TEST_APP = "VtsAngleTestApp.apk";
+
+    public static final String ANGLE_DRIVER_TEST_CLASS = "VtsAngleTestCase";
+    public static final String ANGLE_DRIVER_TEST_LOCATION_METHOD = "testAngleLocation";
+
+    static void setGlobalSetting(ITestDevice device, String globalSetting, String value)
+            throws Exception {
+        device.setSetting("global", globalSetting, value);
+        device.executeShellCommand("am refresh-settings-cache");
+    }
+
+    /** Clear ANGLE-related settings */
+    public static void clearSettings(ITestDevice device) throws Exception {
+        // Cached Activity Manager settings
+        setGlobalSetting(device, SETTINGS_GLOBAL_ALL_USE_ANGLE, "0");
+        setGlobalSetting(device, SETTINGS_GLOBAL_DRIVER_PKGS, "\"\"");
+        setGlobalSetting(device, SETTINGS_GLOBAL_DRIVER_VALUES, "\"\"");
+        setGlobalSetting(device, SETTINGS_GLOBAL_ANGLE_DEBUG_PACKAGE, "\"\"");
+    }
+}
diff --git a/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/CommandException.java b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/CommandException.java
new file mode 100644
index 000000000..65f054293
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/CommandException.java
@@ -0,0 +1,39 @@
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
+package com.google.android.angleallowlists.vts;
+
+import com.android.tradefed.util.ArrayUtil;
+import com.android.tradefed.util.CommandResult;
+
+public class CommandException extends Exception {
+    private final CommandResult mCommandResult;
+
+    private static String getCommandAsString(final String... command) {
+        return ArrayUtil.join(" ", (Object[]) command);
+    }
+
+    public CommandException(final String[] command, final CommandResult commandResult) {
+        super(String.format("Command failed: %s\n%s", getCommandAsString(command),
+                Helper.getCommandResultAsString(commandResult)));
+
+        mCommandResult = commandResult;
+    }
+
+    public CommandResult getCommandResult() {
+        return mCommandResult;
+    }
+}
diff --git a/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/Helper.java b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/Helper.java
new file mode 100644
index 000000000..1ed1e2325
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/Helper.java
@@ -0,0 +1,337 @@
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
+package com.google.android.angleallowlists.vts;
+
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.fail;
+
+import com.android.ddmlib.Log;
+import com.android.tradefed.device.DeviceNotAvailableException;
+import com.android.tradefed.invoker.TestInformation;
+import com.android.tradefed.log.LogUtil;
+import com.android.tradefed.metrics.proto.MetricMeasurement;
+import com.android.tradefed.result.FileInputStreamSource;
+import com.android.tradefed.result.LogDataType;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.util.ArrayUtil;
+import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import com.android.tradefed.util.FileUtil;
+import com.android.tradefed.util.IRunUtil;
+import com.android.tradefed.util.RunUtil;
+import com.google.common.io.Files;
+import java.io.BufferedWriter;
+import java.io.File;
+import java.io.FileNotFoundException;
+import java.io.FileOutputStream;
+import java.io.FileWriter;
+import java.io.IOException;
+import java.io.OutputStream;
+import java.nio.charset.StandardCharsets;
+import org.junit.rules.TemporaryFolder;
+
+public class Helper {
+    /** Runs commands, like adb. */
+    private final IRunUtil mRunUtil;
+
+    /** The serial number of the device, so we can execute adb commands on this device. */
+    private final String mDeviceSerialNumber;
+
+    /** TradeFed object for saving metrics (key-value pairs). */
+    private final DeviceJUnit4ClassRunner.TestMetrics mMetrics;
+
+    /**
+     * TradeFed object for saving "artifacts" (i.e. files) that TradeFed saves for inspection when
+     * investigating the results of tests.
+     */
+    private final DeviceJUnit4ClassRunner.TestLogData mLogData;
+
+    /**
+     * The test method name. Used so that logged metrics (see {@link
+     * Helper#saveMetricsAsArtifact()}) include the test method name.
+     */
+    private final String mMethodName;
+
+    /** The file to which metrics are output. See {@link Helper#mMetricsLog}. */
+    private final File mMetricsTextLogFile;
+
+    /**
+     * Used to store all metrics (i.e. key-value pairs) in CSV format so that all metrics can be
+     * saved as an artifact, which TradeFed saves for inspection when investigating the results of
+     * tests. This is useful for local runs and may be useful in the future because the newer
+     * Android test infrastructure does not ingest metrics.
+     */
+    private final BufferedWriter mMetricsLog;
+
+    // These are timeout values used to wait for certain types of actions to complete.
+    public static final int WAIT_INSTALL_APK_MILLIS = 120 * 1000;
+    public static final int WAIT_SET_GLOBAL_SETTING_MILLIS = 5 * 1000;
+    public static final int WAIT_ADB_SHELL_FILE_OP_MILLIS = 5 * 1000;
+    public static final int WAIT_ADB_LARGE_FILE_OP_MILLIS = 5 * 60 * 1000;
+    public static final int WAIT_APP_UNINSTALL_MILLIS = 5 * 1000;
+
+    public static final int PAUSE_AFTER_REBOOT_MILLIS = 20 * 1000;
+    public static final int PAUSE_AFTER_ADB_COMMAND_MILLIS = 2 * 1000;
+
+    public static final int NUM_RETRIES = 3;
+
+    public Helper(final TestInformation testInformation, final TemporaryFolder temporaryFolder,
+            final DeviceJUnit4ClassRunner.TestMetrics metrics,
+            final DeviceJUnit4ClassRunner.TestLogData logData, final String methodName)
+            throws IOException, DeviceNotAvailableException, CommandException,
+                   InterruptedException {
+        mRunUtil = RunUtil.getDefault();
+        mDeviceSerialNumber = testInformation.getDevice().getSerialNumber();
+        mMetrics = metrics;
+        mLogData = logData;
+
+        mMethodName = methodName;
+        mMetricsTextLogFile = temporaryFolder.newFile(String.format("metrics_%s.txt", mMethodName));
+        mMetricsLog = new BufferedWriter(new FileWriter(mMetricsTextLogFile));
+
+        preTestSetup();
+        assertDeviceStateOk();
+    }
+
+    /** verify that device is ready to run tests */
+    public void assertDeviceStateOk() throws CommandException, DeviceNotAvailableException {
+        // Check if device is locked or screen is off.
+        CommandResult result = adbShellCommandCheck(
+                WAIT_ADB_SHELL_FILE_OP_MILLIS, /*logOutput*/ false, "dumpsys window");
+        try {
+            assertFalse(
+                    "Screen was off", result.getStdout().contains("screenState=SCREEN_STATE_OFF"));
+
+            assertFalse("Screen was locked",
+                    result.getStdout().contains("KeyguardStateMonitor\n        mIsShowing=true"));
+
+        } catch (final Throwable ex) {
+            LogUtil.CLog.e(
+                    "Details of dumpsys window: %s", Helper.getCommandResultAsString(result));
+
+            throw ex;
+        }
+    }
+
+    private void preTestSetup()
+            throws DeviceNotAvailableException, CommandException, InterruptedException {
+        // Keep screen on while plugged in.
+        adbShellCommandCheck(WAIT_ADB_SHELL_FILE_OP_MILLIS, "svc power stayon true");
+        RunUtil.getDefault().sleep(PAUSE_AFTER_ADB_COMMAND_MILLIS);
+
+        // Turn screen on.
+        adbShellCommandCheck(WAIT_ADB_SHELL_FILE_OP_MILLIS, "input keyevent KEYCODE_WAKEUP");
+        RunUtil.getDefault().sleep(PAUSE_AFTER_ADB_COMMAND_MILLIS);
+
+        // Skip lock screen.
+        adbShellCommandCheck(WAIT_ADB_SHELL_FILE_OP_MILLIS, "wm dismiss-keyguard");
+        RunUtil.getDefault().sleep(PAUSE_AFTER_ADB_COMMAND_MILLIS);
+
+        // Disable notifications like "you're entering full screen mode", which may affect the
+        // results.
+        adbShellCommandCheck(WAIT_ADB_SHELL_FILE_OP_MILLIS,
+                "settings put secure immersive_mode_confirmations confirmed");
+        adbShellCommandCheck(WAIT_ADB_SHELL_FILE_OP_MILLIS,
+                "settings put global heads_up_notifications_enabled 0");
+    }
+
+    /**
+     * Saves a text file as an "artifact", which TradeFed saves for inspection when investigating
+     * the results of tests.
+     */
+    public void saveTextFileAsArtifact(final String dataName, final File textFile) {
+        try (FileInputStreamSource fiss = new FileInputStreamSource(textFile)) {
+            mLogData.addTestLog(
+                    String.format("%s_%s", mMethodName, dataName), LogDataType.TEXT, fiss);
+        }
+    }
+
+    /**
+     * Logs the contents of a text file. This goes to the "host log", which TradeFed saves for
+     * inspection when investigating the results of tests.
+     */
+    public void logTextFile(final String tag, final File textFile) throws IOException {
+        final String text = Files.asCharSource(textFile, StandardCharsets.UTF_8).read();
+        Log.d(tag, text);
+    }
+
+    /**
+     * Saves a metric (i.e. key-value pair). Depending on various TradeFed options, these get saved
+     * to a database for querying, ingestion into dashboards, etc. They are also usually output to
+     * the terminal when running a test using `atest`. This function also appends the metric ("key,
+     * value") to {@link Helper#mMetricsLog}, which is saved as an artifact so that all metrics are
+     * made available in a simple CSV format. This is useful for local runs and may be useful in the
+     * future because the newer Android test infrastructure does not ingest metrics.
+     */
+    public void logMetricDouble(final String metricName, final String metricValue,
+            final String unit) throws IOException {
+        final double doubleValue = Double.parseDouble(metricValue);
+
+        final MetricMeasurement.Metric metric =
+                MetricMeasurement.Metric.newBuilder()
+                        .setMeasurements(
+                                MetricMeasurement.Measurements.newBuilder().setSingleDouble(
+                                        doubleValue))
+                        .setUnit(unit)
+                        .build();
+
+        mMetrics.addTestMetric(metricName, metric);
+
+        mMetricsLog.write(String.format("%s#%s,%s", mMethodName, metricName, metricValue));
+        mMetricsLog.newLine();
+    }
+
+    /**
+     * Saves a metric (i.e. key-value pair). Depending on various TradeFed options, these get saved
+     * to a database for querying, ingestion into dashboards, etc. They are also usually output to
+     * the terminal when running a test using `atest`. This function also appends the metric ("key,
+     * value") to {@link Helper#mMetricsLog}, which is saved as an artifact so that all metrics are
+     * made available in a simple CSV format. This is useful for local runs and may be useful in the
+     * future because the newer Android test infrastructure does not ingest metrics.
+     */
+    public void logMetricString(final String metricName, final String metricValue)
+            throws IOException {
+        final MetricMeasurement.Metric metric =
+                MetricMeasurement.Metric.newBuilder()
+                        .setMeasurements(
+                                MetricMeasurement.Measurements.newBuilder().setSingleString(
+                                        metricValue))
+                        .build();
+
+        mMetrics.addTestMetric(metricName, metric);
+
+        mMetricsLog.write(String.format("%s#%s,%s", mMethodName, metricName, metricValue));
+        mMetricsLog.newLine();
+    }
+
+    /**
+     * Saves all metrics (i.e. key-value pairs) as an "artifact", which TradeFed saves for
+     * inspection when investigating the results of tests. The metric functions in {@link Helper}
+     * append every metric ("key, value") to {@link Helper#mMetricsLog}, which this function saves
+     * as an artifact so that all metrics are made available in a simple CSV format. This is useful
+     * for local runs and may be useful in the future because the newer Android test infrastructure
+     * does not ingest metrics.
+     */
+    public void saveMetricsAsArtifact() throws IOException {
+        mMetricsLog.close();
+
+        saveTextFileAsArtifact(
+                Files.getNameWithoutExtension(mMetricsTextLogFile.getName()), mMetricsTextLogFile);
+    }
+
+    /** Install the apkFile onto the device */
+    public void installApkFile(final File apkFile) throws CommandException {
+        adbCommandCheck(WAIT_INSTALL_APK_MILLIS, "install", "-r", "-d", "-g", apkFile.toString());
+    }
+
+    /**
+     * Runs an "adb shell am instrument" command.
+     *
+     * <p>The command must start with "am instrument".
+     *
+     * @throws CommandException if the adb command fails
+     * @throws InstrumentationCrashException if the stdout contains shortMsg=Process crashed
+     */
+    public CommandResult adbShellInstrumentationCommandCheck(final long timeout,
+            final String command) throws CommandException, InstrumentationCrashException {
+        if (!command.startsWith("am instrument")) {
+            throw new IllegalArgumentException(String.format(
+                    "Instrumentation command must start with 'am instrument': %s", command));
+        }
+        final String[] commandArray = new String[] {"shell", command};
+        final CommandResult result = adbCommandCheck(timeout, commandArray);
+        if (result.getStdout().contains("shortMsg=Process crashed")) {
+            throw new InstrumentationCrashException(commandArray, result);
+        }
+        return result;
+    }
+
+    /** Runs adb shell command and returns the result code, also logs the result code */
+    public CommandResult adbShellCommandCheck(final long timeout, final String command)
+            throws CommandException {
+        return adbShellCommandCheck(timeout, true, command);
+    }
+
+    private CommandResult adbShellCommandCheck(final long timeout, final boolean logOutput,
+            final String command) throws CommandException {
+        return adbCommandCheck(timeout, logOutput, "shell", command);
+    }
+
+    /** Runs adb command and returns the command result code, also logs the result code */
+    public CommandResult adbCommandCheck(final long timeout, final String... command)
+            throws CommandException {
+        return adbCommandCheck(timeout, true, command);
+    }
+
+    private CommandResult adbCommandCheck(final long timeout, final boolean logOutput,
+            final String... command) throws CommandException {
+        final String[] newCommand =
+                ArrayUtil.buildArray(new String[] {"adb", "-s", mDeviceSerialNumber}, command);
+        return commandCheck(timeout, logOutput, newCommand);
+    }
+
+    /** Runs command and returns the result */
+    private CommandResult commandCheck(final long timeout, final boolean logOutput,
+            final String... command) throws CommandException {
+        final CommandResult result = mRunUtil.runTimedCmd(timeout, command);
+        if (!result.getStatus().equals(CommandStatus.SUCCESS)) {
+            throw new CommandException(command, result);
+        }
+        if (logOutput) {
+            LogUtil.CLog.d(Helper.getCommandResultAsString(result));
+        }
+        return result;
+    }
+
+    /** compile command result code into a full string */
+    public static String getCommandResultAsString(final CommandResult commandResult) {
+        if (commandResult == null) {
+            return "No details of command result.";
+        }
+        return String.format("Exit code: %d\nStdout: %s\nStderr: %s\n", commandResult.getExitCode(),
+                commandResult.getStdout(), commandResult.getStderr());
+    }
+
+    /** runs adb shell command and return the stdout if there is any */
+    public String adbShellCommandWithStdout(final long timeout, final File stdOutFile,
+            final String... command) throws CommandException, FileNotFoundException, IOException {
+        OutputStream stdout = new FileOutputStream(stdOutFile);
+        final String[] newCommand = ArrayUtil.buildArray(
+                new String[] {"adb", "-s", mDeviceSerialNumber, "shell"}, command);
+        mRunUtil.runTimedCmd(timeout, stdout, null, newCommand);
+        return FileUtil.readStringFromFile(stdOutFile).trim();
+    }
+
+    /** create a directory on test device */
+    public void deviceMkDirP(final String dir) throws CommandException {
+        adbShellCommandCheck(WAIT_ADB_SHELL_FILE_OP_MILLIS, String.format("mkdir -p %s", dir));
+    }
+
+    /** uninstall app */
+    public CommandResult uninstallAppIgnoreErrors(final String appPackageName) {
+        try {
+            return adbCommandCheck(WAIT_APP_UNINSTALL_MILLIS, "uninstall", appPackageName);
+        } catch (final CommandException commandException) {
+            LogUtil.CLog.w(commandException);
+            return commandException.getCommandResult();
+        }
+    }
+
+    /** construct the file full path from initialPath and pathSegments */
+    public static File path(final File initialPath, final String... pathSegments) {
+        return FileUtil.getFileForPath(initialPath, pathSegments);
+    }
+}
diff --git a/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/InstrumentationCrashException.java b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/InstrumentationCrashException.java
new file mode 100644
index 000000000..b9a368331
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/InstrumentationCrashException.java
@@ -0,0 +1,26 @@
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
+package com.google.android.angleallowlists.vts;
+
+import com.android.tradefed.util.CommandResult;
+
+public class InstrumentationCrashException extends Exception {
+    public InstrumentationCrashException(
+            final String[] command, final CommandResult commandResult) {
+        super("Instrumented APK process crashed.", new CommandException(command, commandResult));
+    }
+}
diff --git a/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/RunnableWithThrowable.java b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/RunnableWithThrowable.java
new file mode 100644
index 000000000..cb6be6677
--- /dev/null
+++ b/tests/angleallowliststrace_test/host/src/com/google/android/angleallowlists/vts/RunnableWithThrowable.java
@@ -0,0 +1,23 @@
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
+package com.google.android.angleallowlists.vts;
+
+@FunctionalInterface
+public interface RunnableWithThrowable {
+    /** Body that contains execution code */
+    void run() throws Throwable;
+}
diff --git a/tests/gpu_test/OWNERS b/tests/gpu_test/OWNERS
index 52214e58e..2b0e81dd1 100644
--- a/tests/gpu_test/OWNERS
+++ b/tests/gpu_test/OWNERS
@@ -3,5 +3,4 @@ cclao@google.com
 chrisforbes@google.com
 cnorthrop@google.com
 ianelliott@google.com
-lpy@google.com
 kocdemir@google.com
diff --git a/tests/gpu_test/src/com/android/gpu/vts/Build.java b/tests/gpu_test/src/com/android/gpu/vts/Build.java
index f3219cd64..7a21c686e 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/Build.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/Build.java
@@ -55,4 +55,5 @@ public class Build {
     // Levels are named after the first platform release to employ them.
     public static final int VENDOR_24Q2 = 202404;
     public static final int VENDOR_25Q2 = 202504;
+    public static final int VENDOR_26Q2 = 202604;
 }
diff --git a/tests/gpu_test/src/com/android/gpu/vts/GpuProfilingTest.java b/tests/gpu_test/src/com/android/gpu/vts/GpuProfilingTest.java
index b6d5a1d56..f0b02525e 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/GpuProfilingTest.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/GpuProfilingTest.java
@@ -73,6 +73,8 @@ public class GpuProfilingTest extends BaseHostJUnit4Test {
         assumeTrue("Test does not apply for 32-bits devices",
                 getDevice().getProperty("ro.product.cpu.abi").contains("64"));
         assumeTrue("Test does not apply for non-handheld devices", Util.isHandheld(getDevice()));
+        assumeFalse("Test does not apply for low ram devices",
+                PropertyUtil.propertyEquals(getDevice(), "ro.config.low_ram", "true"));
         assumeFalse(
                 "Test does not apply for devices with only CPU Vulkan support", hasOnlyCpuDevice());
         assumeFalse("Test does not apply for devices with only virtual GPU Vulkan support",
diff --git a/tests/gpu_test/src/com/android/gpu/vts/OpenGlEsTest.java b/tests/gpu_test/src/com/android/gpu/vts/OpenGlEsTest.java
index 592de7e77..971a98d05 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/OpenGlEsTest.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/OpenGlEsTest.java
@@ -54,12 +54,17 @@ public class OpenGlEsTest extends BaseHostJUnit4Test {
                 requiredOpenGlEsDeqpLevel = VulkanTest.DEQP_LEVEL_FOR_T;
                 break;
             case Build.VENDOR_24Q2:
+                requiredOpenGlEsDeqpLevel = VulkanTest.DEQP_LEVEL_FOR_VENDOR_24Q2;
+                break;
             case Build.VENDOR_25Q2:
-                requiredOpenGlEsDeqpLevel = VulkanTest.DEQP_LEVEL_FOR_V;
+                requiredOpenGlEsDeqpLevel = VulkanTest.DEQP_LEVEL_FOR_VENDOR_25Q2;
+                break;
+            case Build.VENDOR_26Q2:
+                requiredOpenGlEsDeqpLevel = VulkanTest.DEQP_LEVEL_FOR_VENDOR_26Q2;
                 break;
             default:
                 final String message = String.format("Test should only run for API levels: "
-                                + "S, Sv2, T, UDC, VENDOR_24Q2, VENDOR_25Q2...\n"
+                                + "S, Sv2, T, UDC, VENDOR_24Q2, VENDOR_25Q2, VENDOR_26Q2...\n"
                                 + "Actual: %s",
                         ReflectionUtils.valueName(Build.class, apiLevel));
                 fail(message);
diff --git a/tests/gpu_test/src/com/android/gpu/vts/Util.java b/tests/gpu_test/src/com/android/gpu/vts/Util.java
index 324228b07..17dea5a5f 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/Util.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/Util.java
@@ -30,6 +30,11 @@ public class Util {
         // ro.vendor.api_level already has the minimum of the vendor api level
         // and the product first api level. It can be read from
         // PropertyUtil.getVsrApiLevel(device)
+        //
+        // TODO: b/390704061
+        // This function is broken for Android 15+ requirements as
+        // ro.product.first_api_level does not take into account GRF end/restarts
+        // so it can return an API level lower than what is actually required.
         final int vendorApiLevel = PropertyUtil.getVsrApiLevel(device);
         LogUtil.CLog.i("ro.vendor.api_level: %d", vendorApiLevel);
         return vendorApiLevel;
diff --git a/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java b/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
index e1e6dddff..46d944082 100644
--- a/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
+++ b/tests/gpu_test/src/com/android/gpu/vts/VulkanTest.java
@@ -45,8 +45,14 @@ public class VulkanTest extends BaseHostJUnit4Test {
     private static final int VULKAN_1_1_API_VERSION = 0x401000;
     private static final int VULKAN_1_3_API_VERSION = 0x403000;
 
+    // Feature version corresponding to dEQP level for 2025-03-01.
+    public static final int DEQP_LEVEL_FOR_VENDOR_26Q2 = 0x7E90301;
+
+    // Feature version corresponding to dEQP level for 2025-03-01.
+    public static final int DEQP_LEVEL_FOR_VENDOR_25Q2 = 0x7E90301;
+
     // Feature version corresponding to dEQP level for 2024-03-01.
-    public static final int DEQP_LEVEL_FOR_V = 0x7E80301;
+    public static final int DEQP_LEVEL_FOR_VENDOR_24Q2 = 0x7E80301;
 
     // Feature version corresponding to dEQP level for 2023-03-01.
     public static final int DEQP_LEVEL_FOR_U = 0x7E70301;
@@ -226,10 +232,17 @@ public class VulkanTest extends BaseHostJUnit4Test {
                 requiredVulkanDeqpLevel = DEQP_LEVEL_FOR_U;
                 break;
             case Build.VENDOR_24Q2:
-                requiredVulkanDeqpLevel = DEQP_LEVEL_FOR_V;
+                requiredVulkanDeqpLevel = DEQP_LEVEL_FOR_VENDOR_24Q2;
+                break;
+            case Build.VENDOR_25Q2:
+                requiredVulkanDeqpLevel = DEQP_LEVEL_FOR_VENDOR_25Q2;
+                break;
+            case Build.VENDOR_26Q2:
+                requiredVulkanDeqpLevel = DEQP_LEVEL_FOR_VENDOR_26Q2;
                 break;
             default:
-                fail("Test should only run for API levels: R, S, Sv2, TM, UDC, 202404...");
+                fail("Test should only run for API levels: R, S, Sv2, TM, UDC, 202404, 202504, "
+                        + "202606...");
                 return;
         }
 
@@ -286,15 +299,28 @@ public class VulkanTest extends BaseHostJUnit4Test {
         }
     }
 
+    private boolean mustChipsetMeetA15Requirement() throws Exception {
+        final long boardApiLevel = getDevice().getIntProperty("ro.board.api_level", Build.VENDOR_24Q2);
+        return boardApiLevel >= Build.VENDOR_24Q2;
+    }
+
+    private boolean mustChipsetMeetA16Requirement() throws Exception {
+        // All SoCs starting or restarting GRF with A16, or not in GRF
+        final long boardFirstApiLevel = getDevice().getIntProperty("ro.board.first_api_level", Build.VENDOR_25Q2);
+        final long boardApiLevel = getDevice().getIntProperty("ro.board.api_level", Build.VENDOR_25Q2);
+
+        return boardApiLevel >= Build.VENDOR_25Q2 ||            // Chipsets at A16 level
+            (boardFirstApiLevel <= 32 && boardApiLevel < 34);   // Old chipsets that would need to reenter at A16
+    }
+
     /**
      * All SoCs released with V must support Skia Vulkan with HWUI
      */
     @VsrTest(requirements = {"VSR-3.2.1-009"})
     @Test
     public void checkSkiaVulkanSupport() throws Exception {
-        final int apiLevel = PropertyUtil.getVendorApiLevel(getDevice());
 
-        assumeTrue("Test does not apply for SoCs launched before V", apiLevel >= Build.VENDOR_24Q2);
+        assumeTrue(mustChipsetMeetA15Requirement());
 
         final String gfxinfo = getDevice().executeShellCommand("dumpsys gfxinfo");
         assertNotNull(gfxinfo);
@@ -328,10 +354,8 @@ public class VulkanTest extends BaseHostJUnit4Test {
     @VsrTest(requirements = {"VSR-3.2.1-008"})
     @Test
     public void checkAndroidBaselineProfile2022Support() throws Exception {
-        final int apiLevel = PropertyUtil.getVendorApiLevel(getDevice());
-
-        assumeTrue("Test does not apply for SoCs launched before V", apiLevel >= Build.VENDOR_24Q2);
-        assumeFalse("Exclude new graphocs requirements for TV", FeatureUtil.isTV(getDevice()));
+        assumeTrue(mustChipsetMeetA15Requirement());
+        assumeFalse("Exclude new graphics requirements for TV", FeatureUtil.isTV(getDevice()));
 
         boolean hasOnlyCpuDevice = true;
         for (JSONObject device : mVulkanDevices) {
@@ -355,10 +379,8 @@ public class VulkanTest extends BaseHostJUnit4Test {
     @VsrTest(requirements = {"VSR-3.2.1-008"})
     @Test
     public void checkVpAndroid15MinimumsSupport() throws Exception {
-        final int apiLevel = PropertyUtil.getVendorApiLevel(getDevice());
-
-        assumeTrue("Test does not apply for SoCs launched before V", apiLevel >= Build.VENDOR_24Q2);
-        assumeFalse("Exclude new graphocs requirements for TV", FeatureUtil.isTV(getDevice()));
+        assumeTrue(mustChipsetMeetA15Requirement());
+        assumeFalse("Exclude new graphics requirements for TV", FeatureUtil.isTV(getDevice()));
 
         boolean hasOnlyCpuDevice = true;
         for (JSONObject device : mVulkanDevices) {
@@ -377,20 +399,81 @@ public class VulkanTest extends BaseHostJUnit4Test {
     }
 
     /**
-     * All SoCs released with V must support protectedMemory and VK_EXT_global_priority
-     * ProtectedMemory and VK_EXT_global_priority should be reuqired for Android 16.
+     * All SoCs starting or restarting GRF with A16 must support VPA16
+     */
+    @VsrTest(requirements = {"VSR-3.2.1-009"})
+    @Test
+    public void checkVpAndroid16MinimumsSupport() throws Exception {
+        assumeTrue(mustChipsetMeetA16Requirement());
+        assumeFalse("Exclude new graphics requirements for TV", FeatureUtil.isTV(getDevice()));
+
+        boolean hasOnlyCpuDevice = true;
+        for (JSONObject device : mVulkanDevices) {
+            if (device.getJSONObject("properties").getInt("deviceType")
+                    != VK_PHYSICAL_DEVICE_TYPE_CPU) {
+                hasOnlyCpuDevice = false;
+            }
+        }
+
+        if (hasOnlyCpuDevice) {
+            return;
+        }
+
+        String supported = mVulkanProfiles.getString("VP_ANDROID_16_minimums");
+        assertEquals("This SoC must support VP_ANDROID_16_minimums.", "SUPPORTED", supported);
+    }
+
+    /**
+     * All SoCs starting or restarting GRF with A17 must support protectedMemory.
+     * For A15/A16 produce assumption failure if this requirement is not met instead of failing.
+     * Swiftshader and other CPU-based implementations are exempt due to meaningful implementations
+     * of protected memory being infeasible for them.
+     */
+    @VsrTest(requirements = {"VSR-3.2.1-011"})
+    @Test
+    public void checkProtectedMemorySupport() throws Exception {
+        final int apiLevel = PropertyUtil.getVendorApiLevel(getDevice());
+
+        final boolean allowSoftFailure = apiLevel <= Build.VENDOR_25Q2;
+        assumeFalse("Exclude new graphics requirements for TV", FeatureUtil.isTV(getDevice()));
+
+        assertTrue(mVulkanDevices.length > 0);
+
+        for (JSONObject device : mVulkanDevices) {
+            // Skip CPU implementations entirely
+            if (device.getJSONObject("properties").getInt("deviceType")
+                    == VK_PHYSICAL_DEVICE_TYPE_CPU) {
+                continue;
+            }
+
+            final int protectedMemory =
+                    device.getJSONObject("protectedMemoryFeatures").getInt("protectedMemory");
+            if (allowSoftFailure)
+                assumeTrue("Chipsets entering GRF before A17 should support protectedMemory",
+                        protectedMemory == 1);
+            else
+                assertTrue("Chipsets starting or restarting GRF with A17 must support protectedMemory",
+                        protectedMemory == 1);
+        }
+    }
+
+    /**
+     * All SoCs starting or restarting GRF with A17 must support VK_EXT_global_priority (or VK_KHR_global_priority).
+     * For A15/A16 produce assumption failure if this requirement is not met instead of failing.
+     * Swiftshader and other CPU-based implementations are exempt.
      */
     @VsrTest(requirements = {"VSR-3.2.1-011"})
     @Test
-    public void checkProtectedMemoryAndGlobalPrioritySupport() throws Exception {
+    public void checkGlobalPrioritySupport() throws Exception {
         final int apiLevel = PropertyUtil.getVendorApiLevel(getDevice());
 
-        assumeTrue("Test does not apply for SoCs launched before W", apiLevel >= Build.VENDOR_25Q2);
-        assumeFalse("Exclude new graphocs requirements for TV", FeatureUtil.isTV(getDevice()));
+        final boolean allowSoftFailure = apiLevel <= Build.VENDOR_25Q2;
+        assumeFalse("Exclude new graphics requirements for TV", FeatureUtil.isTV(getDevice()));
 
         assertTrue(mVulkanDevices.length > 0);
 
         for (JSONObject device : mVulkanDevices) {
+            // Skip CPU implementations entirely
             if (device.getJSONObject("properties").getInt("deviceType")
                     == VK_PHYSICAL_DEVICE_TYPE_CPU) {
                 continue;
@@ -400,13 +483,12 @@ public class VulkanTest extends BaseHostJUnit4Test {
                     VK_EXT_GLOBAL_PRIORITY_EXTENSION_NAME, VK_EXT_GLOBAL_PRIORITY_SPEC_VERSION);
             final boolean khrGlobalPriority = hasExtension(device,
                     VK_KHR_GLOBAL_PRIORITY_EXTENSION_NAME, VK_KHR_GLOBAL_PRIORITY_SPEC_VERSION);
-            assertTrue("All non-cpu Vulkan devices must support global_priority",
-                    extGlobalPriority || khrGlobalPriority);
-
-            final int protectedMemory =
-                    device.getJSONObject("protectedMemoryFeatures").getInt("protectedMemory");
-            assertTrue("All non-cpu Vulkan devices must support protectedMemory",
-                    protectedMemory == 1);
+            if (allowSoftFailure)
+                assumeTrue("Chipsets entering GRF before A17 should support global_priority",
+                        extGlobalPriority || khrGlobalPriority);
+            else
+                assertTrue("Chipsets starting or restarting GRF with A17 must support global_priority",
+                        extGlobalPriority || khrGlobalPriority);
         }
     }
 
diff --git a/tests/kernel_proc_file_api_test/proc_tests/ProcModulesTest.py b/tests/kernel_proc_file_api_test/proc_tests/ProcModulesTest.py
index f3e891282..a37dc993c 100644
--- a/tests/kernel_proc_file_api_test/proc_tests/ProcModulesTest.py
+++ b/tests/kernel_proc_file_api_test/proc_tests/ProcModulesTest.py
@@ -31,7 +31,7 @@ class ProcModulesTest(KernelProcFileTestBase.KernelProcFileTestBase):
         # MODULE_NAME SIZE REFERENCE_COUNT USER1,USER2, STATE BASE_ADDRESS TAINT_FLAG
         # MODULE_NAME is a string
         # SIZE is an integer
-        # REFERENCE_COUNT is an integer or -
+        # REFERENCE_COUNT is an integer >= -1 or -
         # USER1,USER2, is a list of modules using this module with a trailing comma.
         #   If no modules are using this module or if modules cannot be unloaded then
         #   - will appear. If this mdoule cannot be unloaded then [permanent] will be
@@ -39,7 +39,7 @@ class ProcModulesTest(KernelProcFileTestBase.KernelProcFileTestBase):
         # STATE is either Unloading, Loading, or Live
         # BASE_ADDRESS is a memory address
         # TAINT_FLAG is optional and if present, has characters between ( and )
-        test_re = re.compile(r"^\w+ \d+ (\d+|-) (((\w+,)*(\[permanent\],)?)|-) (Unloading|Loading|Live) 0x[0-9a-f]+( \(\w+\))?")
+        test_re = re.compile(r"^\w+ \d+ (\d+|-1|-) (((\w+,)*(\[permanent\],)?)|-) (Unloading|Loading|Live) 0x[0-9a-f]+( \(\w+\))?")
         for line in contents.splitlines():
             if not re.match(test_re, line):
                 raise SyntaxError("Malformed entry in /proc/modules: %s" % line)
diff --git a/tests/kernel_proc_file_api_test/proc_tests/ProcZoneInfoTest.py b/tests/kernel_proc_file_api_test/proc_tests/ProcZoneInfoTest.py
index b0c374aa5..240a4257a 100644
--- a/tests/kernel_proc_file_api_test/proc_tests/ProcZoneInfoTest.py
+++ b/tests/kernel_proc_file_api_test/proc_tests/ProcZoneInfoTest.py
@@ -82,10 +82,14 @@ class ProcZoneInfoTest(KernelProcFileTestBase.KernelProcFileTestBase):
             p[0] = p[1]
 
     def p_cpu(self, p):
-        'cpu : CPU COLON NUMBER NEWLINE colonline colonline colonline \
-                VM STATS THRESHOLD COLON NUMBER NEWLINE'
-
-        p[0] = [p[3], p[5], p[6], p[7], [p[10], p[12]]]
+        '''cpu : CPU COLON NUMBER NEWLINE colonline colonline colonline \
+                VM STATS THRESHOLD COLON NUMBER NEWLINE
+                | CPU COLON NUMBER NEWLINE colonline colonline colonline \
+                colonline colonline VM STATS THRESHOLD COLON NUMBER NEWLINE'''
+        if len(p) == 14:
+            p[0] = [p[3], p[5], p[6], p[7], [p[10], p[12]]]
+        else:
+            p[0] = [p[3], p[5], p[6], p[7], p[8], p[9], [p[12], p[14]]]
 
     def p_colonline(self, p):
         'colonline : STRING COLON NUMBER NEWLINE'
diff --git a/tests/kernel_proc_file_api_test/vts_kernel_proc_file_api_test.py b/tests/kernel_proc_file_api_test/vts_kernel_proc_file_api_test.py
index e2d17599d..c33d813fc 100644
--- a/tests/kernel_proc_file_api_test/vts_kernel_proc_file_api_test.py
+++ b/tests/kernel_proc_file_api_test/vts_kernel_proc_file_api_test.py
@@ -161,37 +161,80 @@ class VtsKernelProcFileApiTest(unittest.TestCase):
             stats_path = "/proc/uid_io/stats"
             out, err, r_code = self.dut.shell.Execute(
                     "cat %s | grep '^%d'" % (stats_path, uid))
+            # On a properly running system, out is a line with 11 fields that
+            # looks like this:
+            # "0 9006642940 84253078 9751207936 1064480768 0 0 0 0 1048 0"
+            # where the stat at each index corresponds to the following:
+            #     0 : uid
+            #     1 : fg_rchar
+            #     2 : fg_wchar
+            #     3 : fg_rbytes
+            #     4 : fg_wbytes
+            #     5 : bg_rchar
+            #     6 : bg_wchar
+            #     7 : bg_rbytes
+            #     8 : bg_wbytes
+            #     9 : fg_fsync
+            #     10: bg_fsync
             return out.split()
 
-        def GetWcharCount(uid, state):
-            """Returns the wchar count (bytes written) for a given uid.
+        def GetUidIoStat(uid, index):
+            """Returns the I/O stat at the given index for a given uid.
 
             Args:
                 uid, uid number.
-                state, boolean. Use False for foreground,
-                and True for background.
+                index, index of the desired I/O stat in the array.
 
             Returns:
-                wchar, the number of bytes written by a uid in the given state..
+                value of the I/O stat at the given index.
             """
-            # fg write chars are at index 2, and bg write chars are at 6.
-            wchar_index = 6 if state else 2
-
             stats = UidIOStats(uid)
             # UidIOStats() can return a blank line if the entries are not found
             # so we need to check the length of the return to prevent a list
             # index out of range exception.
             arr_len = len(stats)
 
-            # On a properly running system, the output of
-            # 'cat /proc/uid_io/stats | grep ^0'
-            # (which is what UidIOStats() does) results in something that has 11
-            # fields and looks like this:
-            # "0 9006642940 84253078 9751207936 1064480768 0 0 0 0 1048 0"
             self.assertTrue(arr_len == 11,
                             "Array len returned by UidIOStats() unexpected: %d" %
                             arr_len)
-            return int(stats[wchar_index])
+            self.assertTrue(index < 11,
+                            "Index passed into GetUidIoStat out of bounds: %d" %
+                            index)
+
+            return int(stats[index])
+
+
+        def GetWcharCount(uid, state):
+            """Returns the wchar count (bytes written) for a given uid.
+
+            Args:
+                uid, uid number.
+                state, boolean. Use False for foreground,
+                and True for background.
+
+            Returns:
+                wchar, the number of bytes written by a uid in the given state.
+            """
+            # fg write chars are at index 2, and bg write chars are at 6.
+            wchar_index = 6 if state else 2
+
+            return GetUidIoStat(uid, wchar_index)
+
+        def GetFsyncCount(uid, state):
+            """Returns the fsync syscall count by a given uid.
+
+            Args:
+                uid, uid number.
+                state, boolean. Use False for foreground,
+                and True for background.
+
+            Returns:
+                fsync, the number of calls to fsync by a uid in the given state.
+            """
+            # fg write chars are at index 2, and bg write chars are at 6.
+            fsync_index = 10 if state else 9
+
+            return GetUidIoStat(uid, fsync_index)
 
         def CheckStatsInState(state):
             """Sets VTS (root uid) into a given state and checks the stats.
@@ -205,15 +248,27 @@ class VtsKernelProcFileApiTest(unittest.TestCase):
             root_uid = 0
 
             old_wchar = GetWcharCount(root_uid, state)
+            old_fsync = GetFsyncCount(root_uid, state)
             self.dut.shell.Execute("echo %d %s > %s" % (root_uid, state, filepath))
+
             # This should increase the number of write syscalls.
             self.dut.shell.Execute("echo foo")
             new_wchar = GetWcharCount(root_uid, state)
+
+            # This should increase the number of fsync syscalls.
+            self.dut.shell.Execute("fsync /tmp")
+            new_fsync = GetFsyncCount(root_uid, state)
+
             self.assertLess(
                 old_wchar,
                 new_wchar,
                 "Number of write syscalls has not increased.")
 
+            self.assertLess(
+                old_fsync,
+                new_fsync,
+                "Number of fsync syscalls has not increased.")
+
         CheckStatsInState(False)
         CheckStatsInState(True)
 
diff --git a/tools/vts-core-tradefed/Android.bp b/tools/vts-core-tradefed/Android.bp
index 84c8c839e..14f9600fe 100644
--- a/tools/vts-core-tradefed/Android.bp
+++ b/tools/vts-core-tradefed/Android.bp
@@ -35,7 +35,7 @@ tradefed_binary_host {
     wrapper: "etc/vts-tradefed",
     short_name: "VTS",
     full_name: "Vendor Test Suite",
-    version: "15_r3",
+    version: "16_r1",
     static_libs: [
         "vts-core-tradefed-harness",
         "cts-tradefed-harness",
diff --git a/tools/vts-core-tradefed/etc/vts-tradefed b/tools/vts-core-tradefed/etc/vts-tradefed
index 9bb9e84ad..e417c80ad 100755
--- a/tools/vts-core-tradefed/etc/vts-tradefed
+++ b/tools/vts-core-tradefed/etc/vts-tradefed
@@ -114,4 +114,4 @@ for j in $(find ${VTS_ROOT}/android-vts/testcases -type f -name '*.jar'); do
 done
 
 VTS_TESTCASES=${VTS_ROOT}/android-vts/testcases/
-VTS_TESTCASES=${VTS_TESTCASES} ${JAVA_BINARY} $RDBG_FLAG -Xmx4096m -XX:+HeapDumpOnOutOfMemoryError -cp ${JAR_PATH} -DVTS_ROOT=${VTS_ROOT} com.android.compatibility.common.tradefed.command.CompatibilityConsole "$@"
+VTS_TESTCASES=${VTS_TESTCASES} ${JAVA_BINARY} $RDBG_FLAG -Xmx16g -XX:+HeapDumpOnOutOfMemoryError -cp ${JAR_PATH} -DVTS_ROOT=${VTS_ROOT} com.android.compatibility.common.tradefed.command.CompatibilityConsole "$@"
diff --git a/tools/vts-core-tradefed/res/config/vts-exclude.xml b/tools/vts-core-tradefed/res/config/vts-exclude.xml
index 5e1702d35..10ba87354 100644
--- a/tools/vts-core-tradefed/res/config/vts-exclude.xml
+++ b/tools/vts-core-tradefed/res/config/vts-exclude.xml
@@ -34,4 +34,7 @@
     <option name="compatibility:exclude-filter" value="VtsHalConfirmationUIV1_0TargetTest *ConfirmationUIHidlTest.MalformedUTF8Test2/*"/>
     <option name="compatibility:exclude-filter" value="VtsHalConfirmationUIV1_0TargetTest *ConfirmationUIHidlTest.MalformedUTF8Test3/*"/>
 
+    <!-- b/366152596: Exclude useAfterClose test cases -->
+    <option name="compatibility:exclude-filter" value="VtsHalAudioEffectV* *UseAfterClose_1*"/>
+
 </configuration>
diff --git a/tools/vts-core-tradefed/res/config/vts-kernel.xml b/tools/vts-core-tradefed/res/config/vts-kernel.xml
index fdb0c1939..2494baf87 100644
--- a/tools/vts-core-tradefed/res/config/vts-kernel.xml
+++ b/tools/vts-core-tradefed/res/config/vts-kernel.xml
@@ -22,7 +22,6 @@
     <option name="compatibility:include-filter" value="binderDriverInterfaceTest" />
     <option name="compatibility:include-filter" value="binderLibTest" />
     <option name="compatibility:include-filter" value="binderSafeInterfaceTest  " />
-    <option name="compatibility:include-filter" value="bpf_module_test" />
     <option name="compatibility:include-filter" value="drop_caches_test" />
     <option name="compatibility:include-filter" value="KernelApiSysfsTest" />
     <option name="compatibility:include-filter" value="KernelAbilistTest" />
diff --git a/tools/vts-core-tradefed/res/config/vts-platinum-prod-normal.xml b/tools/vts-core-tradefed/res/config/vts-platinum-prod-normal.xml
new file mode 100644
index 000000000..c19198ad8
--- /dev/null
+++ b/tools/vts-core-tradefed/res/config/vts-platinum-prod-normal.xml
@@ -0,0 +1,1815 @@
+<?xml version='1.0' encoding='UTF-8'?>
+<!-- Copyright (C) 2024 The Android Open Source Project
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
+<configuration description="Run VTS platinum prod tests.">
+    <include name="vts"/>
+    <!-- CtsResourcesLoaderTests -->
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedlyCustomResources[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addLoadersRepeatedly[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addMultipleLoaders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#addProvidersRepeatedly[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedLoaderNoOps[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#alreadyAddedProviderNoOps[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotCloseUsedProvider[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#cannotUseClosedProvider[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#clearProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#copyContextLoaders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#emptyProvider[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#getProvidersDoesNotLeakMutability[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#loaderUpdatesAffectContexts[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#multipleLoadersHaveSameProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderLoaders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderMultipleLoadersAndProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#reorderProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedAddMultipleLoaders[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveLoaderNoOps[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedRemoveProviderNoOps[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#repeatedSetProvider[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProvidersCustomResources[tableFileBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[fileBasedApkAssetsProvider APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[fileBasedApkAssetsProvider APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[fileBasedApkAssetsProvider APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased APK_RAM_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased ARSC_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased ARSC_RAM_MEMORY]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableBased ARSC_RAM_MEMORY_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableFileBased APK_DISK_FD_OFFSETS]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableFileBased APK_RAM_FD]"/>
+    <option name="compatibility:include-filter" value="CtsResourcesLoaderTests android.content.res.loader.cts.ResourcesLoaderValuesTest#setMultipleProviders[tableFileBased APK_RAM_OFFSETS]"/>
+    <!-- CtsUsbManagerTestCases -->
+    <option name="compatibility:include-filter" value="CtsUsbManagerTestCases android.usb.cts.UsbManagerApiTest#test_UsbApiForUsbGadgetHal"/>
+    <option name="compatibility:include-filter" value="CtsUsbManagerTestCases android.usb.cts.UsbManagerApiTest#test_UsbApiSetGetCurrentFunctionsSys"/>
+    <!-- GpuServiceVendorTests -->
+    <option name="compatibility:include-filter" value="GpuServiceVendorTests com.android.tests.gpuservice.GpuWorkTracepointTest#testGpuWorkPeriodTracepointFormat"/>
+    <option name="compatibility:include-filter" value="GpuServiceVendorTests com.android.tests.gpuservice.GpuWorkTracepointTest#testReadTracingEvents"/>
+    <!-- HalUsbGadgetV1_0HostTest -->
+    <option name="compatibility:include-filter" value="HalUsbGadgetV1_0HostTest com.android.tests.usbgadget.HalUsbGadgetV1_0HostTest#testMIDI"/>
+    <option name="compatibility:include-filter" value="HalUsbGadgetV1_0HostTest com.android.tests.usbgadget.HalUsbGadgetV1_0HostTest#testPtp"/>
+    <!-- KernelApiSysfsTest -->
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testKernelMax"/>
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testKernelStackInitialization"/>
+    <option name="compatibility:include-filter" value="KernelApiSysfsTest com.android.tests.sysfs.KernelApiSysfsTest#testKfenceSampleRate"/>
+    <!-- KernelSelinuxFileApiTest -->
+    <option name="compatibility:include-filter" value="KernelSelinuxFileApiTest com.android.tests.selinux.KernelSelinuxFileApiTest#testSelinuxNull"/>
+    <!-- MicrodroidTestApp -->
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidCapabilitiesTest#avfIsRequired"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidCapabilitiesTest#supportForProtectedOrNonProtectedVms"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#autoCloseVmDescriptor[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#autoCloseVmDescriptor[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#autoCloseVm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#autoCloseVm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenApkPathIsInvalid[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenExtraApkPackageIsInvalid[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenMicrodroidDataIsCompromised[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootFailsWhenPvmFwDataIsCompromised[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootsWithVendorPartition[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#bootsWithVendorPartition[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#changingDebuggableVmNonDebuggableInvalidatesVmIdentity[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#changingNonDebuggableVmDebuggableInvalidatesVmIdentity[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#compatibleConfigTests[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#compatibleConfigTests[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#configuringVendorDiskImageRequiresCustomPermission[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#configuringVendorDiskImageRequiresCustomPermission[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createVmWithConfigRequiresPermission[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#createVmWithConfigRequiresPermission[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#creationFailsWithUnsignedVendorPartition[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#creationFailsWithUnsignedVendorPartition[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#deleteVm[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#deleteVm[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#differentManagersForDifferentContexts[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#differentManagersForDifferentContexts[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#inputShouldBeExplicitlyAllowed[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#inputShouldBeExplicitlyAllowed[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#invalidVmNameIsRejected[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#invalidVmNameIsRejected[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#kernelVersionRequirement[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#kernelVersionRequirement[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#outputShouldBeExplicitlyCaptured[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#outputShouldBeExplicitlyCaptured[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#sameInstancesShareTheSameVmObject[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#sameInstancesShareTheSameVmObject[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testAvfRequiresUpdatableApex[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#testAvfRequiresUpdatableApex[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmAttestationWhenRemoteAttestationIsSupported[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmConfigBuilderValidationTests[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmConfigBuilderValidationTests[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmConfigGetAndSetTests[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmConfigGetAndSetTests[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmDescriptorClosedOnImport[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmDescriptorClosedOnImport[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmFilesStoredInCeDirWhenCreatedFromCEContext[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmFilesStoredInCeDirWhenCreatedFromCEContext[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmFilesStoredInDeDirWhenCreatedFromDEContext[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmFilesStoredInDeDirWhenCreatedFromDEContext[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmLifecycleChecks[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmLifecycleChecks[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmUnitTests[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmUnitTests[protectedVm=true,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmmGetAndCreate[protectedVm=false,gki=null]"/>
+    <option name="compatibility:include-filter" value="MicrodroidTestApp com.android.microdroid.test.MicrodroidTests#vmmGetAndCreate[protectedVm=true,gki=null]"/>
+    <!-- VtsAidlHalContextHubTargetTest -->
+    <option name="compatibility:include-filter" value="VtsAidlHalContextHubTargetTest ContextHub/ContextHubAidl#TestEnableTestMode/CONTEXT_HUB_ID_0"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalContextHubTargetTest ContextHub/ContextHubAidl#TestQueryApps/CONTEXT_HUB_ID_0"/>
+    <!-- VtsAidlHalNfcTargetTest -->
+    <option name="compatibility:include-filter" value="VtsAidlHalNfcTargetTest Nfc/NfcAidl#CloseAfterClose/0_android_hardware_nfc_INfc_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalNfcTargetTest Nfc/NfcAidl#CoreInitializedAfterOpen/0_android_hardware_nfc_INfc_default"/>
+    <option name="compatibility:include-filter" value="VtsAidlHalNfcTargetTest Nfc/NfcAidl#OpenAndCloseForDisable/0_android_hardware_nfc_INfc_default"/>
+    <!-- VtsBootconfigTest -->
+    <option name="compatibility:include-filter" value="VtsBootconfigTest VtsBootconfigTest#ProcCmdlineAndroidbootTest"/>
+    <!-- VtsHalAltitudeServiceTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAltitudeServiceTargetTest AltitudeService/AltitudeServiceTest#TestAddMslAltitudeToLocation/0_android_frameworks_location_altitude_IAltitudeService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAltitudeServiceTargetTest AltitudeService/AltitudeServiceTest#TestGetGeoidHeight/0_android_frameworks_location_altitude_IAltitudeService_default"/>
+    <!-- VtsHalAudioCoreTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothA2dpTest/AudioCoreBluetoothA2dp#Enabled/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothA2dpTest/AudioCoreBluetoothA2dp#OffloadReconfiguration/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothA2dpTest/AudioCoreBluetoothA2dp#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothLeTest/AudioCoreBluetoothLe#Enabled/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothLeTest/AudioCoreBluetoothLe#OffloadReconfiguration/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothLeTest/AudioCoreBluetoothLe#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothTest/AudioCoreBluetooth#HfpConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothTest/AudioCoreBluetooth#HfpConfigInvalid/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothTest/AudioCoreBluetooth#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreBluetoothTest/AudioCoreBluetooth#ScoConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreConfigTest/AudioCoreConfig#CanBeRestarted/0_android_hardware_audio_core_IConfig_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreConfigTest/AudioCoreConfig#GetEngineConfigIsValid/0_android_hardware_audio_core_IConfig_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreConfigTest/AudioCoreConfig#GetSurroundSoundConfigIsValid/0_android_hardware_audio_core_IConfig_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#AddRemoveEffectInvalidArguments/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#BluetoothVariableLatency/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#CanBeRestarted/0_android_hardware_audio_core_IModule_bluetooth"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#CanBeRestarted/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#ConnectDisconnectExternalDeviceInvalidPorts/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#ConnectDisconnectExternalDeviceTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#DisconnectExternalDeviceNonResetPortConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#ExternalDeviceMixPortConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#ExternalDevicePortRoutes/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GenerateHwAvSyncId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetAAudioHardwareBurstMinUsec/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetAAudioMixerBurstCount/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetMicrophones/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetMmapPolicyInfos/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#GetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#MasterMute/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#MasterVolume/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#MicMute/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#Published/0_android_hardware_audio_core_IModule_bluetooth"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#Published/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#Published/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAllExternalDevicePortConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAllStaticAudioPortConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAudioPortConfigInvalidPortAudioGain/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAudioPortConfigInvalidPortConfigId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetAudioPortConfigInvalidPortId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#SetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#TryChangingConnectionSimulationMidway/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#TryConnectMissingDevice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#TwoExternalDevicesMixPortConfigsInterleaved/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#TwoExternalDevicesMixPortConfigsNested/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#UpdateAudioMode/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#UpdateScreenRotation/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreModuleTest/AudioCoreModule#UpdateScreenState/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#GetSupportedAudioModes/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#SameInstance/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#SwitchAudioMode/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#TelecomConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioCoreTelephonyTest/AudioCoreTelephony#TelecomConfigInvalid/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#ActiveMicrophones/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#AddRemoveEffectInvalidArguments/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#CloseTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#GetStreamCommon/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#GetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#HwGainHwVolume/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#MicrophoneDirection/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#MicrophoneFieldDimension/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenAllConfigs/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenInvalidBufferSize/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenInvalidDirection/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenOverMaxCount/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#OpenTwiceSamePortConfig/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#PrepareToCloseTwice/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#PrepareToCloseTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#ResetPortConfigWithOpenStream/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#SendInvalidCommand/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#SetVendorParameters/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamInTest/AudioStreamIn#UpdateHwAvSyncId/2_android_hardware_audio_core_IModule_r_submix"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#CloseTwice/1_android_hardware_audio_core_IModule_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioCoreTargetTest AudioStreamOutTest/AudioStreamOut#CloseTwice/2_android_hardware_audio_core_IModule_r_submix"/>
+    <!-- VtsHalAudioEffectFactoryTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CanBeRestarted/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CreateAndDestroyRepeat/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CreateDestroyWithRestart/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CreateMultipleInstanceOfSameEffect/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#CreateWithInvalidUuid/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#DestroyWithInvalidInterface/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#EffectInvalidAfterRestart/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#QueriedNullImplUuid/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#QueriedNullProxyUuid/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#QueryNullTypeUuid/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#QueryProcess/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#SetupAndTearDown/0_android_hardware_audio_effect_IFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectFactoryTargetTest EffectFactoryTest/EffectFactoryTest#SupportMandatoryEffectTypes/0_android_hardware_audio_effect_IFactory_default"/>
+    <!-- VtsHalAudioEffectTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Auxiliary_Preset_Reverb_UUID_f29a1400_a3bb_11df_8ddc_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Dynamic_Bass_Boost_UUID_8631f300_72e2_11df_b57e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_EqualizerBundle_UUID_ce772f20_847d_11df_bb17_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Insert_Preset_Reverb_UUID_172cdf00_a3bc_11df_a72f_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Virtualizer_UUID_1d4033c0_8557_11df_9f2d_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_NXP_Software_Ltd__name_Volume_UUID_119341a0_8469_11df_81f9_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_DynamicsProcessing_UUID_e0e6539b_1781_7261_676f_6d7573696340"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_Haptic_Generator_UUID_97c4acd1_8b82_4f2f_832e_c2fe5d7a9931"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_Loudness_Enhancer_UUID_fa415329_2034_4bea_b5dc_5b381c8d1e2c"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterReopen/Implementor_The_Android_Open_Source_Project_name_Visualizer_UUID_d069d9e0_8329_11df_9168_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAfterRestart/Implementor_NXP_Software_Ltd__name_Insert_Preset_Reverb_UUID_172cdf00_a3bc_11df_a72f_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataAndRestart/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_NXP_Software_Ltd__name_Dynamic_Bass_Boost_UUID_8631f300_72e2_11df_b57e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_NXP_Software_Ltd__name_EqualizerBundle_UUID_ce772f20_847d_11df_bb17_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_NXP_Software_Ltd__name_Virtualizer_UUID_1d4033c0_8557_11df_9f2d_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_NXP_Software_Ltd__name_Volume_UUID_119341a0_8469_11df_81f9_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_The_Android_Open_Source_Project_name_DynamicsProcessing_UUID_e0e6539b_1781_7261_676f_6d7573696340"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#ConsumeDataInProcessingState/Implementor_The_Android_Open_Source_Project_name_Visualizer_UUID_d069d9e0_8329_11df_9168_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Auxiliary_Preset_Reverb_UUID_f29a1400_a3bb_11df_8ddc_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Dynamic_Bass_Boost_UUID_8631f300_72e2_11df_b57e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_EqualizerBundle_UUID_ce772f20_847d_11df_bb17_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Insert_Preset_Reverb_UUID_172cdf00_a3bc_11df_a72f_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Virtualizer_UUID_1d4033c0_8557_11df_9f2d_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_NXP_Software_Ltd__name_Volume_UUID_119341a0_8469_11df_81f9_0002a5d5c51b"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_DynamicsProcessing_UUID_e0e6539b_1781_7261_676f_6d7573696340"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_Haptic_Generator_UUID_97c4acd1_8b82_4f2f_832e_c2fe5d7a9931"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_Loudness_Enhancer_UUID_fa415329_2034_4bea_b5dc_5b381c8d1e2c"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f"/>
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectTargetTest SingleEffectInstanceTest/AudioEffectDataPathTest#SetCommonParameterAndReopen/Implementor_The_Android_Open_Source_Project_name_Visualizer_UUID_d069d9e0_8329_11df_9168_0002a5d5c51b"/>
+    <!-- VtsHalAudioEffectV7_0TargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalAudioEffectV7_0TargetTest CheckConfig#audioEffectsConfigurationValidation"/>
+    <!-- VtsHalBassBoostTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBassBoostTargetTest BassBoostTest/BassBoostDataTest#IncreasingStrength/Implementor_NXP_Software_Ltd__name_Dynamic_Bass_Boost_UUID_8631f300_72e2_11df_b57e_0002a5d5c51b_layout_3"/>
+    <!-- VtsHalBiometricsFingerprintTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBiometricsFingerprintTargetTest IFingerprint/Fingerprint#GenerateChallengeProducesUniqueChallengesTest/0_android_hardware_biometrics_fingerprint_IFingerprint_default"/>
+    <!-- VtsHalBluetoothAudioTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest AidlTestHelper#CheckNoUnimplementedInterfaces"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_hintBitdepth/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_hintChannelMode/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_hintCodecId/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_hintSamplingFrequencyHz/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_invalidRemoteCapabilities/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_invalidSessionType/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_unknownRemoteCapabilities/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#getA2dpConfiguration_validRemoteCapabilities/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#parseA2dpConfiguration_valid/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#startSession_invalidConfiguration/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderAidl#startSession_valid/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderFactoryAidl#GetProviderFactoryService/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderFactoryAidl#OpenProviderAndCheckCapabilitiesBySession/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpHardwareAidl#StartAndEndHfpHardwareSessionWithPossiblePcmConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpSoftwareDecodingAidl#OpenHfpSoftwareDecodingProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpSoftwareDecodingAidl#StartAndEndHfpDecodingSoftwareSessionWithPossiblePcmConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpSoftwareEncodingAidl#OpenHfpSoftwareEncodingProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderHfpSoftwareEncodingAidl#StartAndEndHfpEncodingSoftwareSessionWithPossiblePcmConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#GetBroadcastConfigurationEmptyCapability/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#GetEmptyBroadcastConfigurationEmptyCapability/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#OpenLeAudioOutputHardwareProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#StartAndEndLeAudioBroadcastSessionWithPossibleBroadcastConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioBroadcastHardwareAidl#StartAndEndLeAudioBroadcastSessionWithPossibleUnicastConfigFromProviderInfo/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioInputHardwareAidl#GetAseConfiguration_Multidirectional/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioInputHardwareAidl#OpenLeAudioInputHardwareProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioInputHardwareAidl#StartAndEndLeAudioInputSessionWithPossibleUnicastConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioInputHardwareAidl#StartAndEndLeAudioInputSessionWithPossibleUnicastConfigFromProviderInfo/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#BluetoothAudioProviderLeAudioOutputHardwareAidl_StartAndEndLeAudioOutputSessionWithInvalidAptxAdaptiveLeAudioConfiguration/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetAseConfiguration_Multidirectional/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetDataPathConfiguration/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetEmptyAseConfigurationEmptyCapability/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetEmptyAseConfigurationMismatchedRequirement/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#GetQoSConfiguration/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#OpenLeAudioOutputHardwareProvider/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#StartAndEndLeAudioOutputSessionWithAptxAdaptiveLeUnicastConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#StartAndEndLeAudioOutputSessionWithPossibleUnicastConfig/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothAudioTargetTest PerInstance/BluetoothAudioProviderLeAudioOutputHardwareAidl#StartAndEndLeAudioOutputSessionWithPossibleUnicastConfigFromProviderInfo/0_android_hardware_bluetooth_audio_IBluetoothAudioProviderFactory_default"/>
+    <!-- VtsHalBluetoothRangingTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBluetoothRangingTargetTest PerInstance/BluetoothRangingTest#WriteRawData/0_android_hardware_bluetooth_ranging_IBluetoothChannelSounding_default"/>
+    <!-- VtsHalBluetoothTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalBluetoothTargetTest PerInstance/BluetoothAidlTest#CallInitializeTwice/0_android_hardware_bluetooth_IBluetoothHci_default"/>
+    <option name="compatibility:include-filter" value="VtsHalBluetoothTargetTest PerInstance/BluetoothAidlTest#HciReset/0_android_hardware_bluetooth_IBluetoothHci_default"/>
+    <!-- VtsHalCasAidlTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyApisWithSession/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyDefaultSessionClosedAfterRelease/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyErrors/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyOobFails/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeyPluginInstalled/0_android_hardware_cas_IMediaCasService_default"/>
+    <option name="compatibility:include-filter" value="VtsHalCasAidlTargetTest PerInstance/MediaCasAidlTest#TestClearKeySessionClosedAfterRelease/0_android_hardware_cas_IMediaCasService_default"/>
+    <!-- VtsHalDownmixTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_11"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_15"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_1539"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_1551"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_1599"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_16777215"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_184383"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_185919"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_259"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_263"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_3"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_319"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_50517567"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_51"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_51303999"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_55"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_63"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_7"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_7534087"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786435"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786439"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786443"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786447"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_786495"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixFoldDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_fold_layout_788031"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_11"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_15"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_1539"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_1551"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_1599"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_16777215"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_184383"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_185919"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_259"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_263"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_319"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_50517567"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_51"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_51303999"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_55"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_63"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_7"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_7534087"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786435"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786439"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786443"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786447"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_786495"/>
+    <option name="compatibility:include-filter" value="VtsHalDownmixTargetTest DownmixTest/DownmixStripDataTest#DownmixProcessData/Implementor_The_Android_Open_Source_Project_name_Multichannel_Downmix_To_Stereo_UUID_93f04452_e4fe_41cc_91f9_e475b6d1d69f_strip_layout_788031"/>
+    <!-- VtsHalDumpstateTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestDeviceLoggingDisabled/0_android_hardware_dumpstate_IDumpstateDevice_default_FULL"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestDeviceLoggingDisabled/7_android_hardware_dumpstate_IDumpstateDevice_default_PROTO"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestNullHandle/0_android_hardware_dumpstate_IDumpstateDevice_default_FULL"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestNullHandle/3_android_hardware_dumpstate_IDumpstateDevice_default_WEAR"/>
+    <option name="compatibility:include-filter" value="VtsHalDumpstateTargetTest PerInstanceAndMode/DumpstateAidlPerModeTest#TestNullHandle/4_android_hardware_dumpstate_IDumpstateDevice_default_CONNECTIVITY"/>
+    <!-- VtsHalEnvironmentalReverbTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_decayHfRatioPm"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_decayTimeMs"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_levelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_roomHfLevelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Auxiliary_Environmental_Reverb_UUID_4a387fc0_8ab3_11df_8bad_0002a5d5c51b_Tag_roomLevelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_decayHfRatioPm"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_decayTimeMs"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_levelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_roomHfLevelMb"/>
+    <option name="compatibility:include-filter" value="VtsHalEnvironmentalReverbTargetTest EnvironmentalReverbTest/EnvironmentalReverbDataTest#WithBypassEnabled/Implementor_NXP_Software_Ltd__name_Insert_Environmental_Reverb_UUID_c7a511a0_a3bb_11df_860e_0002a5d5c51b_Tag_roomLevelMb"/>
+    <!-- VtsHalGatekeeperTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalGatekeeperTargetTest PerInstance/GatekeeperAidlTest#EnrollSuccess/0_android_hardware_gatekeeper_IGatekeeper_default"/>
+    <!-- VtsHalGnssTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#GnssCapabilites/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestAGnssExtension/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestAGnssRilExtension/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestAllExtensions/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestCorrelationVector/0_android_hardware_gnss_IGnss_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGnssTargetTest GnssHalTest#TestGnssVisibilityControlExtension/0_android_hardware_gnss_IGnss_default"/>
+    <!-- VtsHalGraphicsAllocatorAidl_TargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsAllocatorAidlTests#CanAllocate/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsAllocatorAidlTests#RejectsUnknownOptions/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsAllocatorAidlTests#RejectsUnknownUsages/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsFrontBufferTests#FrontBufferGpuToCpu/2_eglClientWaitSync"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsAllocatorAidl_TargetTest PerInstance/GraphicsFrontBufferTests#FrontBufferGpuToGpu/2_eglClientWaitSync"/>
+    <!-- VtsHalGraphicsMapperStableC_TargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#AllV5CallbacksDefined/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#CanAllocate/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#CheckRequiredSettersIfHasGetters/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#DualLoadIsIdentical/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#FlushLockedBufferBadBuffer/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#FlushRereadBasic/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#FreeBufferNegative/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetAllocationSize/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetBufferId/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetChromaSiting/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetCompression/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetCrop/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetCta861_3/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetInterlaced/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetLayerCount/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetMetadataBadValue/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetName/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetPixelFormatFourCC/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetPixelFormatModifier/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetPixelFormatRequested/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetPlaneLayouts/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetProtectedContent/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSetBlendMode/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSetDataspace/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSetSmpte2086/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSmpte2094_10/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetSmpte2094_40/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetStride/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetUnsupportedMetadata/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetUsage/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetUsage64/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#GetWidthHeight/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#ImportBufferNegative/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#ImportFreeBuffer/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#ImportFreeBufferSingleton/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#ListSupportedWorks/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#LockBadAccessRegion/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#LockUnlockBasic/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#LockUnlockNested/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#LockUnlockNoCPUUsage/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_RAW10/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_RAW12/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_YCBCR_420_888/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_YCBCR_P010/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_YCRCB_420_SP/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#Lock_YV12/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#RereadLockedBufferBadBuffer/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#SupportsRequiredGettersSetters/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#UnlockNegative/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#UnlockNotImported/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#UnlockNotLocked/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#VersionChecks/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <option name="compatibility:include-filter" value="VtsHalGraphicsMapperStableC_TargetTest PerInstance/GraphicsMapperStableCTests#YV12SubsampleMetadata/0_android_hardware_graphics_allocator_IAllocator_default"/>
+    <!-- VtsHalHealthTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/BatteryTest#AverageCurrentAgainstChargeStatusFromHal/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/BatteryTest#InstantCurrentAgainstChargeStatusFromHal/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/HealthAidl#getBatteryHealthData/0_android_hardware_health_IHealth_default"/>
+    <option name="compatibility:include-filter" value="VtsHalHealthTargetTest Health/HealthAidl#setChargingPolicy/0_android_hardware_health_IHealth_default"/>
+    <!-- VtsHalLoudnessEnhancerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalLoudnessEnhancerTargetTest LoudnessEnhancerTest/LoudnessEnhancerDataTest#DecreasingGains/Implementor_The_Android_Open_Source_Project_name_Loudness_Enhancer_UUID_fa415329_2034_4bea_b5dc_5b381c8d1e2c"/>
+    <!-- VtsHalMediaC2V1_0TargetAudioDecTest -->
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioDecTest StreamIndexAndEOS/Codec2AudioDecDecodeTest#DecodeTest/software_c2_android_raw_decoder_1_0_38"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioDecTest StreamIndexAndEOS/Codec2AudioDecDecodeTest#DecodeTest/software_c2_android_raw_decoder_1_1_39"/>
+    <!-- VtsHalMediaC2V1_0TargetAudioEncTest -->
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_aac_encoder_0_2_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_aac_encoder_1_1_2"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_aac_encoder_1_2_3"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrnb_encoder_0_2_5"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrnb_encoder_1_1_6"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrwb_encoder_0_2_9"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrwb_encoder_1_1_10"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_amrwb_encoder_1_2_11"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_flac_encoder_0_1_12"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_flac_encoder_0_2_13"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_flac_encoder_1_1_14"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_opus_encoder_0_2_17"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_opus_encoder_1_1_18"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest EncodeTest/Codec2AudioEncEncodeTest#EncodeTest/software_c2_android_opus_encoder_1_2_19"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_aac_encoder_0"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_amrnb_encoder_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_amrwb_encoder_2"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_flac_encoder_3"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#FlushTest/software_c2_android_opus_encoder_4"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_aac_encoder_0"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_amrnb_encoder_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_amrwb_encoder_2"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_flac_encoder_3"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiChannelCountTest/software_c2_android_opus_encoder_4"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiSampleRateTest/software_c2_android_aac_encoder_0"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiSampleRateTest/software_c2_android_amrnb_encoder_1"/>
+    <option name="compatibility:include-filter" value="VtsHalMediaC2V1_0TargetAudioEncTest PerInstance/Codec2AudioEncHidlTest#MultiSampleRateTest/software_c2_android_opus_encoder_4"/>
+    <!-- VtsHalNetNetdV1TargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalNetNetdV1TargetTest PerInstance/NetdAidlTest#TestAddRemoveRoutes/0_android_system_net_netd_INetd_default"/>
+    <!-- VtsHalOemLockTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalOemLockTargetTest PerInstance/OemLockAidlTest#AllowedByDeviceCanBeToggled/0_android_hardware_oemlock_IOemLock_default"/>
+    <option name="compatibility:include-filter" value="VtsHalOemLockTargetTest PerInstance/OemLockAidlTest#CarrierUnlock/0_android_hardware_oemlock_IOemLock_default"/>
+    <!-- VtsHalPowerStatsTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalPowerStatsTargetTest PowerStats/PowerStatsAidl#TestGetStateResidencyAllResultsExceptSkippedEntities/0_android_hardware_power_stats_IPowerStats_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerStatsTargetTest PowerStats/PowerStatsAidl#TestGetStateResidencyAllStateResidenciesExceptSkippedEntities/0_android_hardware_power_stats_IPowerStats_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerStatsTargetTest PowerStats/PowerStatsAidl#TestGetStateResidencySelectedResultsExceptTimedEntities/0_android_hardware_power_stats_IPowerStats_default"/>
+    <!-- VtsHalPowerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/FMQAidl#getAndCloseSessionChannel/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/FMQAidl#writeItems/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#createAndCloseHintSession/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#createHintSessionFailed/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#sendSessionHint/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/HintSessionAidl#updateAndReportDurations/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#createHintSessionWithConfig/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#getHintSessionPreferredRate/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#hasFixedPerformance/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#isBoostSupported/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#isModeSupported/0_android_hardware_power_IPower_default"/>
+    <option name="compatibility:include-filter" value="VtsHalPowerTargetTest Power/PowerAidl#setMode/0_android_hardware_power_IPower_default"/>
+    <!-- VtsHalPresetReverbTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalPresetReverbTargetTest PresetReverbTest/PresetReverbProcessTest#DecreasingRoomSize/Implementor_NXP_Software_Ltd__name_Auxiliary_Preset_Reverb_UUID_f29a1400_a3bb_11df_8ddc_0002a5d5c51b"/>
+    <!-- VtsHalRemotelyProvisionedComponentTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestTest#EmptyRequest_testMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestTest#NewKeyPerCallInTestMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/CertificateRequestTest#NonEmptyRequest_testMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/GenerateKeyTests#generateAndUseEcdsaP256Key_prodMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/GenerateKeyTests#generateEcdsaP256Key_testMode/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <option name="compatibility:include-filter" value="VtsHalRemotelyProvisionedComponentTargetTest PerInstance/GetHardwareInfoTests#supportsValidCurve/0_android_hardware_security_keymint_IRemotelyProvisionedComponent_default"/>
+    <!-- VtsHalSensorManagerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalSensorManagerTargetTest PerInstance/SensorManagerTest#Accelerometer/0_android_frameworks_sensorservice_ISensorManager_default"/>
+    <option name="compatibility:include-filter" value="VtsHalSensorManagerTargetTest PerInstance/SensorManagerTest#Ashmem/0_android_frameworks_sensorservice_ISensorManager_default"/>
+    <option name="compatibility:include-filter" value="VtsHalSensorManagerTargetTest PerInstance/SensorManagerTest#GetDefaultAccelerometer/0_android_frameworks_sensorservice_ISensorManager_default"/>
+    <option name="compatibility:include-filter" value="VtsHalSensorManagerTargetTest PerInstance/SensorManagerTest#List/0_android_frameworks_sensorservice_ISensorManager_default"/>
+    <!-- VtsHalThermalTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#CoolingDeviceTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#NotifyCoolingDeviceChangedTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#NotifyThrottlingTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#RegisterCoolingDeviceChangedCallbackWithTypeTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#RegisterThermalChangedCallbackTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#RegisterThermalChangedCallbackWithTypeTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#TemperatureTest/0_android_hardware_thermal_IThermal_default"/>
+    <option name="compatibility:include-filter" value="VtsHalThermalTargetTest Thermal/ThermalAidlTest#TemperatureThresholdTest/0_android_hardware_thermal_IThermal_default"/>
+    <!-- VtsHalUsbGadgetV1_1HostTest -->
+    <option name="compatibility:include-filter" value="VtsHalUsbGadgetV1_1HostTest com.android.tests.usbgadget.VtsHalUsbGadgetV1_1HostTest#testResetUsbGadget"/>
+    <!-- VtsHalUwbTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalUwbTargetTest Uwb/UwbAidl#GetChip/0_android_hardware_uwb_IUwb_default"/>
+    <!-- VtsHalVibratorTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#AlwaysOn/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#AmplitudeReturnsUnsupportedMatchingCapabilities/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeDelayBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposePwleAmplitudeParameterBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposePwleSegmentBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposePwleSegmentDurationBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposePwleV2Unsupported/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeScaleBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeSizeBoundary/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeValidPrimitives/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ComposeValidPwle/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ExternalAmplitudeControl/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#ExternalControlUnsupportedMatchingCapabilities/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetBandwidthAmplitudeMap/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetFrequencyMinimum/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetFrequencyResolution/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetPrimitiveDuration/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetPwleCompositionSizeMax/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetPwlePrimitiveDurationMax/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetQFactor/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetResonantFrequency/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#GetSupportedBraking/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#PerformVendorEffectEmptyVendorData/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#PerformVendorEffectInvalidScale/TOP_LEVEL_VIBRATOR_0"/>
+    <option name="compatibility:include-filter" value="VtsHalVibratorTargetTest Vibrator/VibratorAidl#PerformVendorEffectSupported/TOP_LEVEL_VIBRATOR_0"/>
+    <!-- VtsHalVirtualizerTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalVirtualizerTargetTest VirtualizerTest/VirtualizerProcessTest#IncreasingStrength/Implementor_NXP_Software_Ltd__name_Virtualizer_UUID_1d4033c0_8557_11df_9f2d_0002a5d5c51b_isInputZero_0"/>
+    <!-- VtsHalVolumeTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalVolumeTargetTest VolumeTest/VolumeDataTest#ApplyLevelMuteUnmute/Implementor_NXP_Software_Ltd__name_Volume_UUID_119341a0_8469_11df_81f9_0002a5d5c51b"/>
+    <!-- VtsHalWifiChipTargetTest -->
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetAvailableModes/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#GetId/0_android_hardware_wifi_IWifi_default"/>
+    <option name="compatibility:include-filter" value="VtsHalWifiChipTargetTest WifiTest/WifiChipAidlTest#RegisterEventCallback/0_android_hardware_wifi_IWifi_default"/>
+    <!-- binderDriverInterfaceTest -->
+    <option name="compatibility:include-filter" value="binderDriverInterfaceTest BinderDriverInterfaceTest#RequestDeathNotification"/>
+    <!-- binderLibTest -->
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibRpcTest#SetRpcClientDebug"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibRpcTest#SetRpcClientDebugTwice"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest#BinderCallContextGuard"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest#CheckNoHeaderMappedInUser"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest#Freeze"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest/BinderLibRpcTestP#SetRpcClientDebugNoKeepAliveBinder/local"/>
+    <option name="compatibility:include-filter" value="binderLibTest BinderLibTest/BinderLibRpcTestP#SetRpcClientDebugNoKeepAliveBinder/remote"/>
+    <option name="compatibility:include-filter" value="binderLibTest ServiceNotifications#Unregister"/>
+    <!-- binderRpcTest -->
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc#CanUseExperimentalWireVersion"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc#Java"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#CheckWaitingForRead/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#CheckWaitingForRead/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#CheckWaitingForRead/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#GoodCertificate/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#GoodCertificate/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#GoodCertificate/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#GoodCertificate/raw_uds_tls_PEM_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousClient/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousClient/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousClient/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousServer/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousServer/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousServer/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MaliciousServer/raw_uds_tls_DER_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MultipleClients/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MultipleClients/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#MultipleClients/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#Trigger/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#Trigger/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#Trigger/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedClient/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedClient/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedClient/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedServer/inet_socket_raw_serverV0"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedServer/inet_socket_raw_serverV1"/>
+    <option name="compatibility:include-filter" value="binderRpcTest BinderRpc/RpcTransportTest#UntrustedServer/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#CannotMixBindersBetweenTwoSessionsToTheSameServer/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#GetInterfaceDescriptor/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#GetInterfaceDescriptor/unix_domain_socket_tls_clientV0_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#MultipleSessions/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#MultipleSessions/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#NestedTransactions/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#RepeatBinder/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#RepeatBinderNull/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#RepeatBinderNull/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendAndGetResultBack/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendAndGetResultBackBig/unix_domain_socket_raw_clientV0_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendAndGetResultBackBig/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendSomethingOneway/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SendSomethingOneway/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#ThreadingStressTest/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTest PerSocket/BinderRpc#WorksWithLibbinderNdkUserTransaction/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <!-- binderRpcTestNoKernel -->
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel BinderRpc#CanUseExperimentalWireVersion"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#OnewayCallQueueingWithFds/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#SessionWithIncomingThreadpoolDoesntLeak/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadPoolGreaterThanEqualRequested/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadingStressTest/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestNoKernel PerSocket/BinderRpc#ThreadingStressTest/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <!-- binderRpcTestSingleThreaded -->
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded BinderRpc#CanUseExperimentalWireVersion"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded BinderRpc#Java"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AppendInvalidFd/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AppendSeparateFormats/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#AppendSeparateFormats/unix_domain_socket_tls_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Callbacks/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenTwoSessionsToTheSameServer/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenTwoSessionsToTheSameServer/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Die/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Die/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Die/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Fds/unix_domain_socket_raw_clientV0_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#Fds/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#FileDescriptorTransportOptionalUnix/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#FileDescriptorTransportOptionalUnix/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#GetInterfaceDescriptor/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#HoldBinder/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#HoldBinder/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#HoldBinder/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#InvalidNullBinderReturn/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#InvalidNullBinderReturn/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#MultipleSessions/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#NestedTransactions/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatBinder/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatRootObject/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatRootObject/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEquality/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEquality/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEquality/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_tls_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendSomethingOneway/unix_domain_socket_tls_clientV0_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SendTooManyFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpc#SingleSession/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreaded PerSocket/BinderRpcAccessor#InjectAndGetServiceHappyPath/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <!-- binderRpcTestSingleThreadedNoKernel -->
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel BinderRpc#CanUseExperimentalWireVersion"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel BinderRpc/RpcTransportTest#GoodCertificate/inet_socket_raw_serverV4026531840"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AidlDelegatorTest/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AppendInvalidFd/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AppendSeparateFormats/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#AppendSeparateFormats/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CallMeBack/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CallMeBack/unix_domain_socket_tls_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Callbacks/unix_domain_socket_tls_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_raw_clientV4026531840_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CannotMixBindersBetweenUnrelatedSocketSessions/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#CannotSendRegularBinderOverSocketBinder/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV1_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#DeathRecipientFailsWithoutIncoming/vm_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Die/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Die/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Die/unix_domain_socket_raw_clientV0_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Fds/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#Fds/unix_domain_socket_tls_clientV0_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#GetInterfaceDescriptor/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#InvalidNullBinderReturn/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV0_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ManySessions/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#NestedTransactions/unix_domain_socket_raw_clientV4026531840_serverV0_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_raw_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_raw_clientV1_serverV0_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#OnewayCallbackWithNoThread/unix_domain_socket_tls_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#ReceiveFile/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#RepeatBinderNull/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#RepeatRootObject/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_tls_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#RepeatTheirBinder/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_raw_clientV0_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_tls_clientV0_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SameBinderEqualityWeak/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendAndGetResultBack/unix_domain_socket_tls_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendAndGetResultBackBig/inet_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/preconnected_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/raw_uds_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_bootstrap_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV1_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV1_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_multi_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendMaxFiles/unix_domain_socket_raw_clientV4026531840_serverV4026531840_single_threaded_with_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#SendSomethingOneway/unix_domain_socket_tls_clientV1_serverV4026531840_multi_threaded_no_kernel"/>
+    <option name="compatibility:include-filter" value="binderRpcTestSingleThreadedNoKernel PerSocket/BinderRpc#UnknownTransaction/unix_domain_socket_tls_clientV4026531840_serverV0_multi_threaded_no_kernel"/>
+    <!-- binderRpcWireProtocolTest -->
+    <option name="compatibility:include-filter" value="binderRpcWireProtocolTest RpcWire#ReleaseBranchHasFrozenRpcWireProtocol"/>
+    <!-- fmq_test -->
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_32_to_32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_32_to_64"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_32_to_rust32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_32_to_rust64"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_64_to_32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_64_to_64"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_64_to_rust32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_64_to_rust64"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_rust32_to_32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_rust32_to_64"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_rust32_to_rust32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_rust32_to_rust64"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_rust64_to_32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_rust64_to_64"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_rust64_to_rust32"/>
+    <option name="compatibility:include-filter" value="fmq_test __main__.TestFmq#test_rust64_to_rust64"/>
+    <!-- hidl_test_java -->
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_32_to_32"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_32_to_64"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_32_to_java"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_64_to_32"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_64_to_64"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_64_to_java"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_java_to_32"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_java_to_64"/>
+    <option name="compatibility:include-filter" value="hidl_test_java __main__.TestHidlJava#test_java_to_java"/>
+    <!-- keystore2_client_tests -->
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_3des_key_tests::keystore2_3des_ecb_cbc_generate_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_3des_key_tests::keystore2_3des_key_encrypt_fails_invalid_input_length"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_3des_key_tests::keystore2_3des_key_fails_unsupported_block_mode"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_ctr_gcm_generate_key_fails_incompatible"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_ctr_gcm_generate_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_gcm_op_fails_invalid_mac_len"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_gcm_op_fails_missing_mac_len"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_gcm_op_fails_unsupported_mac_len"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_key_op_fails_incompatible_blockmode"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_key_op_fails_incompatible_padding"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_aes_key_tests::keystore2_aes_key_op_fails_nonce_prohibited"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_attest_key_tests::keystore2_attest_key_fails_with_invalid_attestation_id"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_attest_key_tests::keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_id"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_attestation_key_with_auth_app_id_app_data_test_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_attested_key_auth_app_id_app_data_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_active_datetime_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_creation_date_time_test_fail_with_invalid_arg_error"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_early_boot_only_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_future_active_datetime_test_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_future_origination_expire_datetime_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_future_usage_expire_datetime_hmac_verify_op_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_include_unique_id_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_max_uses_per_boot"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_origination_expire_datetime_test_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_serial_number_subject_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_count_limit"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_count_limit_one"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_expire_datetime_decrypt_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_expire_datetime_hmac_verify_op_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_key_auth_usage_future_expire_datetime_decrypt_op_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_authorizations_tests::keystore2_gen_non_attested_key_auth_usage_count_limit"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_delete_key_tests::keystore2_delete_key_blob_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_delete_key_tests::keystore2_delete_key_blob_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_delete_key_tests::keystore2_delete_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_delete_key_tests::keystore2_delete_key_with_blob_domain_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_device_unique_attestation_tests::keystore2_gen_ec_key_device_unique_attest_with_strongbox_sec_level_test_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_device_unique_attestation_tests::keystore2_gen_key_device_unique_attest_with_default_sec_level_unimplemented"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::keystore2_create_op_with_incompatible_key_digest"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::keystore2_generate_key_with_blob_domain"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::keystore2_get_key_entry_blob_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::keystore2_key_owner_validation"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_md5_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_md5_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_md5_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_md5_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_none_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_none_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_none_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_none_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha1_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha1_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha1_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha1_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha224_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha224_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha224_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha224_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha256_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha256_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha256_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha256_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha384_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha384_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha384_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha384_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha512_ec_p224"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha512_ec_p256"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha512_ec_p384"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_ec_key_tests::sign_ec_key_op_sha512_ec_p521"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_delete_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_get_info_use_key_perm"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_fails_with_grant_perm_expect_perm_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_fails_with_permission_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_to_multi_users_delete_fails_with_key_not_found_error"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_to_multi_users_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_with_invalid_perm_expecting_syserror"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_grant_key_with_perm_none"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_ungrant_fails_with_non_existing_key_expect_key_not_found_error"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_grant_key_tests::keystore2_ungrant_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_hmac_key_tests::keystore2_hmac_key_op_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_hmac_key_tests::keystore2_hmac_key_op_with_mac_len_greater_than_digest_len_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_hmac_key_tests::keystore2_hmac_key_op_with_mac_len_less_than_min_mac_len_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_import_3des_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_import_aes_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_import_ec_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_import_hmac_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_rsa_import_key_determine_key_size_and_pub_exponent"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_rsa_import_key_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_import_keys_tests::keystore2_rsa_import_key_with_multipurpose_fails_incompt_purpose_error"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::keystore2_ec_agree_key_with_different_curves_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::test_ec_p224_key_agreement"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::test_ec_p256_key_agreement"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::test_ec_p384_key_agreement"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_agreement_tests::test_ec_p521_key_agreement"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_id_domain_tests::keystore2_find_key_with_key_id_as_domain"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_id_domain_tests::keystore2_key_id_alias_rebind_verify_by_alias"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_key_id_domain_tests::keystore2_key_id_alias_rebind_verify_by_key_id"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_get_number_of_entries_fails_perm_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_fails_perm_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_validate_count_and_order_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_with_empty_keystore_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_with_multi_procs_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_batched_with_selinux_domain_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_fails_perm_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_list_entries_tests::keystore2_list_entries_success"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_abort_finalized_op_fail_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_forced_op_perm_denied_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_forced_op_success_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_operation_tests::keystore2_op_abort_success_test"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_md5_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha1_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha224_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha256_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha384_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_no_mgf_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_oaep_sha512_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_none_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_pad_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::encrypt_key_pkcs1_1_5_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_encrypt_key_op_invalid_purpose"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_gen_keys_with_oaep_paddings_without_digest"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_generate_key_with_oaep_padding_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_generate_keys"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_generate_signing_key_padding_pss_fail"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_key_missing_purpose"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_key_unsupported_op"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_key_unsupported_purpose"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::keystore2_rsa_sign_key_op_invalid_purpose"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_none_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_none_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_none_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha256_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pkcs1_1_5_sha512_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_md5_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha1_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha224_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_rsa_key_tests::sign_key_pss_sha384_2048"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_update_subcomponent_tests::keystore2_update_subcomponent_fails_permission_denied"/>
+    <option name="compatibility:include-filter" value="keystore2_client_tests keystore2_client_tests#keystore2_client_update_subcomponent_tests::keystore2_update_subcomponent_success"/>
+    <!-- netd_integration_test -->
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestBpfJitAlwaysOn"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestHaveEfficientUnalignedAccess"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestIsLTS"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestMinRequiredLTS_4_19"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestMinRequiredLTS_5_10"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestSupportsAcceptRaMinLft"/>
+    <option name="compatibility:include-filter" value="netd_integration_test KernelTest#TestSupportsCommonUsbEthernetDongles"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetUtilsWrapperTest#TestFileCapabilities"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#GetFwmarkForNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#GetProcSysNet"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#InterfaceAddRemoveAddress"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#InterfaceGetCfg"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#IpSecSetEncapSocketOwner"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#IpSecTunnelInterface"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#PerAppDefaultNetwork_ExplicitlySelectNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#PerAppDefaultNetwork_ImplicitlySelectNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#PerAppDefaultNetwork_OverlappedUidRanges"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#PerAppDefaultNetwork_UnconnectedSocket"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#SetProcSysNet"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#SocketDestroy"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#TetherForwardAddRemove"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#UidRangeSubPriority_ImplicitlySelectNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdBinderTest#XfrmControllerInit"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckFullNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckMountNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckNetworkNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckNoUserNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdNamespaceTest#CheckUTSNamespaceSupport"/>
+    <option name="compatibility:include-filter" value="netd_integration_test NetdSELinuxTest#CheckProperMTULabels"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/BypassableVPN_selectAppDefaultNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/BypassableVPN_selectSystemDefaultNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/BypassableVPN_selectVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/SecureVPN_selectAppDefaultNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/SecureVPN_selectSystemDefaultNetwork"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnAndSelectNetworkParameterizedTest#ExplicitlySelectNetwork/SecureVPN_selectVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedAppDefault_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/explicitlySelectedSystemDefault_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidNotSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnHasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv4SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6AppLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6GlobalAddrSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalDifferentLocalRoutes"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnLocalRoutesParameterizedTest#localRoutesExclusion/implicitlySelected_uidSubjectToVpnNothasAppDefaultRange_withv6SystemLocalSameLocalAddr"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnParameterizedTest#ImplicitlySelectNetwork/BypassableVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnParameterizedTest#ImplicitlySelectNetwork/SecureVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnParameterizedTest#UnconnectedSocket/BypassableVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppDefaultNetwork/VpnParameterizedTest#UnconnectedSocket/SecureVPN"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppNetworkPermissionsTest#DoesNotAffectDefaultNetworkSelection"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppNetworkPermissionsTest#HasExplicitAccess"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppNetworkPermissionsTest#HasImplicitAccess"/>
+    <option name="compatibility:include-filter" value="netd_integration_test PerAppNetworkPermissionsTest#PermissionDoesNotAffectPerAppDefaultNetworkSelection"/>
+    <!-- vts_approvedBuild_validate_test -->
+    <option name="compatibility:include-filter" value="vts_approvedBuild_validate_test CheckConfig#approvedBuildValidation"/>
+    <!-- vts_eol_enforcement_test -->
+    <option name="compatibility:include-filter" value="vts_eol_enforcement_test EolEnforcementTest#KernelNotEol"/>
+    <!-- vts_fs_test -->
+    <option name="compatibility:include-filter" value="vts_fs_test fs#PartitionTypes"/>
+    <!-- vts_generic_boot_image_test -->
+    <option name="compatibility:include-filter" value="vts_generic_boot_image_test GenericBootImageTest#GenericRamdisk"/>
+    <option name="compatibility:include-filter" value="vts_generic_boot_image_test GenericBootImageTest#KernelReleaseFormat"/>
+    <!-- vts_gki_compliance_test -->
+    <option name="compatibility:include-filter" value="vts_gki_compliance_test KernelVersionTest#AgainstPlatformRelease"/>
+    <option name="compatibility:include-filter" value="vts_gki_compliance_test KernelVersionTest#GrfDevicesMustUseLatestKernel"/>
+    <!-- vts_halManifest_validate_test -->
+    <option name="compatibility:include-filter" value="vts_halManifest_validate_test CheckConfig#halManifestValidation"/>
+    <!-- vts_ibase_test -->
+    <option name="compatibility:include-filter" value="vts_ibase_test VtsHalBaseV1_0TargetTest#CanPing"/>
+    <option name="compatibility:include-filter" value="vts_ibase_test VtsHalBaseV1_0TargetTest#Descriptor"/>
+    <option name="compatibility:include-filter" value="vts_ibase_test VtsHalBaseV1_0TargetTest#InterfaceChain"/>
+    <!-- vts_kernelLifetimes_validate_test -->
+    <option name="compatibility:include-filter" value="vts_kernelLifetimes_validate_test CheckConfig#approvedBuildValidation"/>
+    <!-- vts_kernel_checkpoint_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_checkpoint_test __main__.VtsKernelCheckpointTest#testCheckpointEnabled"/>
+    <option name="compatibility:include-filter" value="vts_kernel_checkpoint_test __main__.VtsKernelCheckpointTest#testCommit"/>
+    <!-- vts_kernel_encryption_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test DmDefaultKeyTest#TestAdiantum"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test DmDefaultKeyTest#TestAes256Xts"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test DmDefaultKeyTest#TestHwWrappedKey"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAdiantumPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesEmmcOptimizedHwWrappedKeyPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesEmmcOptimizedPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesInlineCryptOptimizedHwWrappedKeyPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBEPolicyTest#TestAesInlineCryptOptimizedPolicy"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test FBETest#TestUserDirectoryPolicies"/>
+    <option name="compatibility:include-filter" value="vts_kernel_encryption_test MetadataEncryptionTest#TestRandomness"/>
+    <!-- vts_kernel_fuse_bpf_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_fuse_bpf_test __main__.VtsKernelFuseBpfTest#testFuseBpfEnabled"/>
+    <!-- vts_kernel_loopconfig_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_loopconfig_test KernelLoopConfigTest#ValidLoopPartParameter"/>
+    <!-- vts_kernel_proc_file_api_test -->
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#testProcPagetypeinfo"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#testProcPerUidTimes"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#testProcSysAbiSwpInstruction"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#testProcUidProcstatSet"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcAsoundCardsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcCmdlineTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcCorePattern"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcCorePipeLimit"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcCpuInfoTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDirtyBackgroundBytes"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDirtyBackgroundRatio"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDirtyExpireCentisecs"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDiskstatsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDmesgRestrict"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDomainname"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcDropCaches"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcExtraFreeKbytes"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcFilesystemsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcHostname"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcHungTaskTimeoutSecs"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcKmsgTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcKptrRestrictTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcLoadavgTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMapsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMaxMapCount"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMemInfoTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMisc"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMmapMinAddrTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMmapRndBitsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMmapRndCompatBitsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcModulesDisabled"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcModulesTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcMountsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcOverCommitMemoryTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPageCluster"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPanicOnOops"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPerfEventMaxSampleRate"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPerfEventParanoid"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPidMax"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcPipeMaxSize"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcProtectedHardlinks"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcProtectedSymlinks"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcRandomizeVaSpaceTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcRemoveUidRangeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSchedChildRunsFirst"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSchedRTPeriodUS"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSchedRTRuntimeUS"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcShowUidStatTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcStatTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSuidDumpable"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSwapsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSysKernelRandomBootId"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcSysRqTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidConcurrentActiveTimeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidConcurrentPolicyTimeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidCpuPowerConcurrentActiveTimeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidCpuPowerConcurrentPolicyTimeTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidCpuPowerTimeInStateTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidIoStatsTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUidTimeInStateTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcUptime"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcVersionTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcVmallocInfoTest"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcVmstat"/>
+    <option name="compatibility:include-filter" value="vts_kernel_proc_file_api_test __main__.VtsKernelProcFileApiTest#test_ProcZoneInfoTest"/>
+    <!-- vts_treble_platform_version_test -->
+    <option name="compatibility:include-filter" value="vts_treble_platform_version_test __main__.VtsTreblePlatformVersionTest#testSdkVersion"/>
+    <option name="compatibility:include-filter" value="vts_treble_platform_version_test __main__.VtsTreblePlatformVersionTest#testVndkVersion"/>
+    <!-- vts_treble_sys_prop_test -->
+    <option name="compatibility:include-filter" value="vts_treble_sys_prop_test __main__.VtsTrebleSysPropTest#testExportedPlatformPropertyIntegrity"/>
+    <!-- vts_treble_vintf_framework_test -->
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#DeviceManifestFrameworkMatrixCompatibility"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#FrameworkManifestDeviceMatrixCompatibility"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#KernelCompatibility"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#NoMainlineKernel"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_framework_test SystemVendorTest#VendorFrameworkCompatibility"/>
+    <!-- vts_treble_vintf_vendor_test -->
+    <option name="compatibility:include-filter" value="vts_treble_vintf_vendor_test DeviceManifest/SingleAidlTest#HalIsServed/android_hardware_bluetooth_IBluetoothHci_default_V1_8"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_vendor_test DeviceManifest/SingleAidlTest#HalIsServed/android_hardware_bluetooth_finder_IBluetoothFinder_default_V1_10"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_vendor_test DeviceManifestTest#NoDeprecatedHalsOnManifest"/>
+    <option name="compatibility:include-filter" value="vts_treble_vintf_vendor_test DeviceMatrixTest#VndkVersion"/>
+    <!-- vts_vndk_abi_test -->
+    <option name="compatibility:include-filter" value="vts_vndk_abi_test __main__.VtsVndkAbiTest#testAbiCompatibility32"/>
+    <option name="compatibility:include-filter" value="vts_vndk_abi_test __main__.VtsVndkAbiTest#testAbiCompatibility64"/>
+    <!-- vts_vndk_files_test -->
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testNoLlndkInOdm32"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testNoLlndkInOdm64"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testNoLlndkInVendor32"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testNoLlndkInVendor64"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testVndkCoreDirectory32"/>
+    <option name="compatibility:include-filter" value="vts_vndk_files_test __main__.VtsVndkFilesTest#testVndkCoreDirectory64"/>
+</configuration>
diff --git a/tools/vts-core-tradefed/res/config/vts-sim-include.xml b/tools/vts-core-tradefed/res/config/vts-sim-include.xml
new file mode 100644
index 000000000..7043f9a75
--- /dev/null
+++ b/tools/vts-core-tradefed/res/config/vts-sim-include.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<configuration description="Include VTS test that require SIM card">
+
+    <!-- VTS tests that need SIM card-->
+    <option name="compatibility:include-filter" value="VtsHalRadioV1_0TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalRadioV1_1TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalRadioV1_2TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalRadioV1_3TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalRadioV1_4TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalRadioV1_5TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalRadioV1_6TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalSecureElementV1_0TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalSecureElementV1_1TargetTest" />
+    <option name="compatibility:include-filter" value="VtsHalSecureElementV1_2TargetTest" />
+</configuration>
diff --git a/tools/vts-core-tradefed/res/config/vts-validation-exclude.xml b/tools/vts-core-tradefed/res/config/vts-validation-exclude.xml
index af6920583..0d1b14fe8 100644
--- a/tools/vts-core-tradefed/res/config/vts-validation-exclude.xml
+++ b/tools/vts-core-tradefed/res/config/vts-validation-exclude.xml
@@ -17,7 +17,6 @@
 <configuration description="Excluded tests from vts-validation">
 
     <!-- Exclude selected test modules -->
-    <option name="compatibility:exclude-filter" value="ApkVerityTest" />
     <option name="compatibility:exclude-filter" value="CtsIkeTestCases" />
     <option name="compatibility:exclude-filter" value="CtsInstantAppTests" />
     <option name="compatibility:exclude-filter" value="CtsPackageWatchdogTestCases" />
@@ -25,6 +24,7 @@
     <option name="compatibility:exclude-filter" value="CtsWindowManagerJetpackTestCases" />
     <option name="compatibility:exclude-filter" value="KernelDynamicPartitionsTest" />
     <option name="compatibility:exclude-filter" value="VtsHalBluetoothV1_0TargetTest" />
+    <option name="compatibility:exclude-filter" value="vts_approvedBuild_validate_test" />
     <option name="compatibility:exclude-filter" value="vts_compatibilityMatrix_validate_test" />
     <option name="compatibility:exclude-filter" value="vts_core_liblp_test" />
     <option name="compatibility:exclude-filter" value="vts_defaultPermissions_validate_test" />
@@ -55,4 +55,4 @@
     <option name="compatibility:exclude-filter" value="vts_vndk_dependency_test" />
     <option name="compatibility:exclude-filter" value="vts_vndk_files_test" />
 
-</configuration>
\ No newline at end of file
+</configuration>
diff --git a/tools/vts-core-tradefed/res/config/vts-virtual-device-rules.xml b/tools/vts-core-tradefed/res/config/vts-virtual-device-rules.xml
new file mode 100644
index 000000000..02fb1ee86
--- /dev/null
+++ b/tools/vts-core-tradefed/res/config/vts-virtual-device-rules.xml
@@ -0,0 +1,29 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<configuration description="Extra rules for running VTS on virtual devices">
+
+    <!-- Tell all AndroidJUnitTests to exclude certain annotations -->
+    <option name="compatibility:test-arg" value="com.android.tradefed.testtype.AndroidJUnitTest:exclude-annotation:android.platform.test.annotations.RequiresDevice" />
+
+    <!-- Tell all HostTests to exclude certain annotations -->
+    <option name="compatibility:test-arg" value="com.android.tradefed.testtype.HostTest:exclude-annotation:android.platform.test.annotations.RequiresDevice" />
+    <option name="compatibility:test-arg" value="com.android.compatibility.common.tradefed.testtype.JarHostTest:exclude-annotation:android.platform.test.annotations.RequiresDevice" />
+
+    <!-- add per module rules for virtual devices below -->
+
+    <!-- Virtual devices usually run as root -->
+
+</configuration>
diff --git a/tools/vts-core-tradefed/res/config/vts-virtual-device.xml b/tools/vts-core-tradefed/res/config/vts-virtual-device.xml
new file mode 100644
index 000000000..6c53e3f6b
--- /dev/null
+++ b/tools/vts-core-tradefed/res/config/vts-virtual-device.xml
@@ -0,0 +1,25 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<configuration description="Runs a subset of VTS for virtual devices">
+
+    <include name="vts" />
+
+    <option name="plan" value="vts-virtual-device" />
+
+    <!-- Extra rules for virtual devices -->
+    <include name="vts-virtual-device-rules" />
+
+</configuration>
```

