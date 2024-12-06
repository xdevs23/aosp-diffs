```diff
diff --git a/apex/tests/libstatspull/Android.bp b/apex/tests/libstatspull/Android.bp
index d3079e00..40174434 100644
--- a/apex/tests/libstatspull/Android.bp
+++ b/apex/tests/libstatspull/Android.bp
@@ -43,6 +43,7 @@ android_test {
     privileged: true,
     certificate: "platform",
     compile_multilib: "both",
+    min_sdk_version: "30",
 }
 
 cc_test_library {
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 00000000..9b8a1fe2
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,42 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+// ==========================================================
+// Libraries to expose flags to statsd components
+// ==========================================================
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aconfig_declarations {
+    name: "statsd_aconfig_flags",
+    container: "com.android.os.statsd",
+    package: "com.android.os.statsd.flags",
+    srcs: [
+        "libstatspull_flags.aconfig",
+        "statsd_flags.aconfig",
+    ],
+}
+
+cc_aconfig_library {
+    name: "statsd_flags_c_lib",
+    aconfig_declarations: "statsd_aconfig_flags",
+    min_sdk_version: "30",
+    apex_available: [
+        "com.android.os.statsd",
+    ],
+    host_supported: true,
+}
diff --git a/flags/libstatspull_flags.aconfig b/flags/libstatspull_flags.aconfig
new file mode 100644
index 00000000..8c0f6096
--- /dev/null
+++ b/flags/libstatspull_flags.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.os.statsd.flags"
+container: "com.android.os.statsd"
+
+flag {
+  name: "use_wait_for_service_api"
+  namespace: "statsd"
+  description: "This flag controls transition to AServiceManager_waitForService API"
+  bug: "347947040"
+  is_fixed_read_only: true
+}
diff --git a/flags/statsd_flags.aconfig b/flags/statsd_flags.aconfig
new file mode 100644
index 00000000..c91c4469
--- /dev/null
+++ b/flags/statsd_flags.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.os.statsd.flags"
+container: "com.android.os.statsd"
+
+flag {
+  name: "trigger_uprobestats"
+  namespace: "statsd"
+  description: "Whether to call AUprobestatsClient_startUprobestats."
+  bug: "296108553"
+  is_fixed_read_only: true
+}
diff --git a/framework/Android.bp b/framework/Android.bp
index 7ffa7b58..385de02e 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -63,7 +63,7 @@ java_sdk_library {
 
     libs: [
         "androidx.annotation_annotation",
-        "framework-configinfrastructure",
+        "framework-configinfrastructure.stubs.module_lib",
     ],
 
     static_libs: [
diff --git a/lib/libstatspull/Android.bp b/lib/libstatspull/Android.bp
index 28c0a706..252baca0 100644
--- a/lib/libstatspull/Android.bp
+++ b/lib/libstatspull/Android.bp
@@ -68,7 +68,9 @@ cc_library_shared {
         "test_com.android.os.statsd",
     ],
     min_sdk_version: "30",
-
+    static_libs: [
+        "statsd_flags_c_lib",
+    ],
     stl: "libc++_static",
 }
 
@@ -77,6 +79,11 @@ cc_library_headers {
     export_include_dirs: ["include"],
 }
 
+filegroup {
+    name: "libstatspull_test_default_map",
+    srcs: ["libstatspull_test_default.map"],
+}
+
 // Note: These unit tests only test PullAtomMetadata and subscriptions
 // For full E2E tests of pullers, use LibStatsPullTests
 cc_test {
@@ -98,12 +105,12 @@ cc_test {
     shared_libs: [
         "libstatspull",
         "libstatssocket",
-        "libbase",
         "libbinder",
         "libutils",
         "liblog",
     ],
     static_libs: [
+        "libbase",
         "libgmock",
         "libstatsgtestmatchers",
         "libstatslog_statsdtest",
@@ -115,6 +122,15 @@ cc_test {
     ],
     test_config: "libstatspull_test.xml",
 
+    // This test runs on older platform versions, so many libraries (such as libbase and libc++)
+    // need to be linked statically. The test also needs to be linked with a version script to
+    // ensure that the statically-linked library isn't exported from the executable, where it
+    // would override the shared libraries that the platform itself uses.
+    // See http://b/333438055 for an example of what goes wrong when libc++ is partially exported
+    // from an executable.
+    version_script: ":libstatspull_test_default_map",
+    stl: "libc++_static",
+
     //TODO(b/153588990): Remove when the build system properly separates
     //32bit and 64bit architectures.
     compile_multilib: "both",
diff --git a/lib/libstatspull/libstatspull_test_default.map b/lib/libstatspull/libstatspull_test_default.map
new file mode 100644
index 00000000..5157ea6e
--- /dev/null
+++ b/lib/libstatspull/libstatspull_test_default.map
@@ -0,0 +1,20 @@
+#
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
+#
+{
+  local:
+    *;
+};
+
diff --git a/lib/libstatspull/stats_pull_atom_callback.cpp b/lib/libstatspull/stats_pull_atom_callback.cpp
index b880f0a8..1d2bb226 100644
--- a/lib/libstatspull/stats_pull_atom_callback.cpp
+++ b/lib/libstatspull/stats_pull_atom_callback.cpp
@@ -21,6 +21,7 @@
 #include <android/binder_auto_utils.h>
 #include <android/binder_ibinder.h>
 #include <android/binder_manager.h>
+#include <com_android_os_statsd_flags.h>
 #include <stats_event.h>
 #include <stats_pull_atom_callback.h>
 
@@ -36,6 +37,8 @@ using aidl::android::os::IStatsd;
 using aidl::android::util::StatsEventParcel;
 using ::ndk::SharedRefBase;
 
+namespace flags = com::android::os::statsd::flags;
+
 struct AStatsEventList {
     std::vector<AStatsEvent*> data;
 };
@@ -184,7 +187,22 @@ public:
         std::lock_guard<std::mutex> lock(mStatsdMutex);
         if (!mStatsd) {
             // Fetch statsd
-            ::ndk::SpAIBinder binder(AServiceManager_getService("stats"));
+
+            ::ndk::SpAIBinder binder;
+            // below ifs cannot be combined into single statement due to the way how
+            // macro __builtin_available is handler by compiler:
+            // - it should be used explicitly & independently to guard the corresponding API call
+            // once use_wait_for_service_api flag will be finalized, external if/else pair will be
+            // removed
+            if (flags::use_wait_for_service_api()) {
+                if (__builtin_available(android __ANDROID_API_S__, *)) {
+                    binder.set(AServiceManager_waitForService("stats"));
+                } else {
+                    binder.set(AServiceManager_getService("stats"));
+                }
+            } else {
+                binder.set(AServiceManager_getService("stats"));
+            }
             mStatsd = IStatsd::fromBinder(binder);
             if (mStatsd) {
                 AIBinder_linkToDeath(binder.get(), mDeathRecipient.get(), this);
diff --git a/lib/libstatspull/tests/stats_subscription_test.cpp b/lib/libstatspull/tests/stats_subscription_test.cpp
index 301a9371..7d965d17 100644
--- a/lib/libstatspull/tests/stats_subscription_test.cpp
+++ b/lib/libstatspull/tests/stats_subscription_test.cpp
@@ -81,13 +81,14 @@ protected:
         }
     }
 
-    void LogTestAtomReported(int32_t intFieldValue) {
+    void LogTestAtomReported(int32_t intFieldValue) __INTRODUCED_IN(__ANDROID_API_T__) {
         const BytesField bytesField(trainExpIdsBytes.data(), trainExpIdsBytes.size());
         stats_write(TEST_ATOM_REPORTED, uids.data(), uids.size(), tags, intFieldValue,
                     /*long_field=*/2LL, /*float_field=*/3.0F,
                     /*string_field=*/string1.c_str(),
-                    /*boolean_field=*/false, /*state=*/TEST_ATOM_REPORTED__REPEATED_ENUM_FIELD__OFF,
-                    bytesField, repeatedInts, repeatedLongs, repeatedFloats, repeatedStrings,
+                    /*boolean_field=*/false,
+                    /*state=*/TEST_ATOM_REPORTED__REPEATED_ENUM_FIELD__OFF, bytesField,
+                    repeatedInts, repeatedLongs, repeatedFloats, repeatedStrings,
                     &(repeatedBool[0]), /*repeatedBoolSize=*/2, repeatedEnums);
     }
 
diff --git a/lib/libstatssocket/Android.bp b/lib/libstatssocket/Android.bp
index fce6a757..7d7c9c1a 100644
--- a/lib/libstatssocket/Android.bp
+++ b/lib/libstatssocket/Android.bp
@@ -50,6 +50,7 @@ cc_defaults {
     static_libs: [
         "libbase",
     ],
+    min_sdk_version: "30",
 }
 
 cc_library_shared {
@@ -84,6 +85,18 @@ cc_library_headers {
     min_sdk_version: "29",
 }
 
+filegroup {
+    name: "libstatssocket_test_default_map",
+    srcs: ["libstatssocket_test_default.map"],
+}
+
+
+cc_library_headers {
+    name: "libstatssocket_test_headers",
+    export_include_dirs: ["tests/include"],
+    min_sdk_version: "30",
+}
+
 cc_test {
     name: "libstatssocket_test",
     srcs: [
@@ -99,6 +112,16 @@ cc_test {
         "-Werror",
         "-Wthread-safety",
     ],
+
+    // These tests run on older platform versions, so many libraries (such as libbase and libc++)
+    // need to be linked statically. The tests also need to be linked with a version script to
+    // ensure that the statically-linked library isn't exported from the executable, where it
+    // would override the shared libraries that the platform itself uses.
+    // See http://b/333438055 for an example of what goes wrong when libc++ is partially exported
+    // from an executable.
+    version_script: ":libstatssocket_test_default_map",
+    stl: "c++_static",
+
     static_libs: [
         "libbase",
         "libgmock",
@@ -107,6 +130,9 @@ cc_test {
         "libutils",
         "libstatssocket",
     ],
+    header_libs: [
+        "libstatssocket_test_headers",
+    ],
     test_suites: [
         "device-tests",
         "mts-statsd",
diff --git a/lib/libstatssocket/include/stats_event.h b/lib/libstatssocket/include/stats_event.h
index f131bf5d..1b4abcc8 100644
--- a/lib/libstatssocket/include/stats_event.h
+++ b/lib/libstatssocket/include/stats_event.h
@@ -42,6 +42,14 @@
  * order that they are defined in the atom.
  */
 
+#ifndef __ANDROID_API_T__
+#define __ANDROID_API_T__ 33
+#endif
+
+#ifndef __INTRODUCED_IN
+#define __INTRODUCED_IN(api_level)
+#endif
+
 #ifdef __cplusplus
 extern "C" {
 #endif  // __CPLUSPLUS
diff --git a/lib/libstatssocket/libstatssocket_test_default.map b/lib/libstatssocket/libstatssocket_test_default.map
new file mode 100644
index 00000000..5157ea6e
--- /dev/null
+++ b/lib/libstatssocket/libstatssocket_test_default.map
@@ -0,0 +1,20 @@
+#
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
+#
+{
+  local:
+    *;
+};
+
diff --git a/lib/libstatssocket/stats_socket_loss_reporter.cpp b/lib/libstatssocket/stats_socket_loss_reporter.cpp
index 5e2d2728..6b9c2a6c 100644
--- a/lib/libstatssocket/stats_socket_loss_reporter.cpp
+++ b/lib/libstatssocket/stats_socket_loss_reporter.cpp
@@ -31,7 +31,9 @@ StatsSocketLossReporter::~StatsSocketLossReporter() {
     // due to:
     // - cool down timer was active
     // - no input atoms to trigger loss info dump after cooldown timer expired
-    dumpAtomsLossStats(true);
+    if (__builtin_available(android __ANDROID_API_T__, *)) {
+        dumpAtomsLossStats(true);
+    }
 }
 
 StatsSocketLossReporter& StatsSocketLossReporter::getInstance() {
diff --git a/lib/libstatssocket/stats_socket_loss_reporter.h b/lib/libstatssocket/stats_socket_loss_reporter.h
index b8573216..a721d6de 100644
--- a/lib/libstatssocket/stats_socket_loss_reporter.h
+++ b/lib/libstatssocket/stats_socket_loss_reporter.h
@@ -36,7 +36,7 @@ public:
      * @return true if atom have been written into the socket successfully
      * @return false if atom have been written into the socket with an error
      */
-    void dumpAtomsLossStats(bool forceDump = false);
+    void dumpAtomsLossStats(bool forceDump = false) __INTRODUCED_IN(__ANDROID_API_T__);
 
     ~StatsSocketLossReporter();
 
diff --git a/lib/libstatssocket/statsd_writer.cpp b/lib/libstatssocket/statsd_writer.cpp
index 4133e26b..a1a4586a 100644
--- a/lib/libstatssocket/statsd_writer.cpp
+++ b/lib/libstatssocket/statsd_writer.cpp
@@ -33,6 +33,7 @@
 #include <time.h>
 #include <unistd.h>
 
+#include "stats_event.h"
 #include "stats_socket_loss_reporter.h"
 #include "utils.h"
 
@@ -246,7 +247,9 @@ static int statsdWrite(struct timespec* ts, struct iovec* vec, size_t nr) {
             } else {
                 // try to send socket loss info only when socket connection established
                 // and it is proved by previous write that socket is available
-                StatsSocketLossReporter::getInstance().dumpAtomsLossStats();
+                if (__builtin_available(android __ANDROID_API_T__, *)) {
+                    StatsSocketLossReporter::getInstance().dumpAtomsLossStats();
+                }
             }
         }
     }
diff --git a/lib/libstatssocket/tests/include/sdk_guard_util.h b/lib/libstatssocket/tests/include/sdk_guard_util.h
new file mode 100644
index 00000000..d289efa2
--- /dev/null
+++ b/lib/libstatssocket/tests/include/sdk_guard_util.h
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#define TEST_GUARDED_CLASS_NAME(suite_name, test_name) Guarded##suite_name##test_name
+
+#define TEST_GUARDED_(test_type, suite_name, test_name, sdk)          \
+    class TEST_GUARDED_CLASS_NAME(suite_name, test_name) {            \
+    public:                                                           \
+        static void doTest() __INTRODUCED_IN(sdk);                    \
+    };                                                                \
+                                                                      \
+    test_type(suite_name, test_name) {                                \
+        if (__builtin_available(android sdk, *)) {                    \
+            TEST_GUARDED_CLASS_NAME(suite_name, test_name)::doTest(); \
+        } else {                                                      \
+            GTEST_SKIP();                                             \
+        }                                                             \
+    }                                                                 \
+    void TEST_GUARDED_CLASS_NAME(suite_name, test_name)::doTest()
+
+#define TEST_GUARDED(suite_name, test_name, sdk) TEST_GUARDED_(TEST, suite_name, test_name, sdk)
+
+#define TEST_GUARDED_F_OR_P_(test_type, suite_name, test_name, sdk) \
+    test_type(suite_name, test_name) {                              \
+        if (__builtin_available(android sdk, *)) {                  \
+            suite_name::do##test_name();                            \
+        } else {                                                    \
+            GTEST_SKIP();                                           \
+        }                                                           \
+    }                                                               \
+    void suite_name::do##test_name()
+
+#define TEST_F_GUARDED(suite_name, test_name, sdk) \
+    TEST_GUARDED_F_OR_P_(TEST_F, suite_name, test_name, sdk)
+
+#define TEST_P_GUARDED(suite_name, test_name, sdk) \
+    TEST_GUARDED_F_OR_P_(TEST_P, suite_name, test_name, sdk)
diff --git a/lib/libstatssocket/tests/stats_event_test.cpp b/lib/libstatssocket/tests/stats_event_test.cpp
index dea81c25..34645683 100644
--- a/lib/libstatssocket/tests/stats_event_test.cpp
+++ b/lib/libstatssocket/tests/stats_event_test.cpp
@@ -15,9 +15,12 @@
  */
 
 #include "stats_event.h"
+
 #include <gtest/gtest.h>
 #include <utils/SystemClock.h>
 
+#include "sdk_guard_util.h"
+
 // Keep in sync with stats_event.c. Consider moving to separate header file to avoid duplication.
 /* ERRORS */
 #define ERROR_NO_TIMESTAMP 0x1
@@ -277,7 +280,7 @@ TEST(StatsEventTest, TestNullByteArrays) {
     AStatsEvent_release(event);
 }
 
-TEST(StatsEventTest, TestAllArrays) {
+TEST_GUARDED(StatsEventTest, TestAllArrays, __ANDROID_API_T__) {
     uint32_t atomId = 100;
 
     uint8_t numElements = 3;
@@ -427,7 +430,7 @@ TEST(StatsEventTest, TestFieldAnnotations) {
     AStatsEvent_release(event);
 }
 
-TEST(StatsEventTest, TestArrayFieldAnnotations) {
+TEST_GUARDED(StatsEventTest, TestArrayFieldAnnotations, __ANDROID_API_T__) {
     uint32_t atomId = 100;
 
     // array annotation info
@@ -695,7 +698,7 @@ TEST(StatsEventTest, TestAttributionChainTooLongError) {
     EXPECT_EQ(errors & ERROR_ATTRIBUTION_CHAIN_TOO_LONG, ERROR_ATTRIBUTION_CHAIN_TOO_LONG);
 }
 
-TEST(StatsEventTest, TestListTooLongError) {
+TEST_GUARDED(StatsEventTest, TestListTooLongError, __ANDROID_API_T__) {
     uint32_t atomId = 100;
     uint8_t numElements = 128;
     int32_t int32Array[128] = {1};
diff --git a/service/Android.bp b/service/Android.bp
index b642a0a0..96aff18d 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -33,7 +33,7 @@ java_library {
         // Use the implementation library directly.
         // TODO(b/204183608): Remove when no longer necessary.
         "framework-statsd.impl",
-        "framework-configinfrastructure",
+        "framework-configinfrastructure.stubs.module_lib",
     ],
     static_libs: [
         "modules-utils-build",
diff --git a/statsd/Android.bp b/statsd/Android.bp
index 30e06378..b6c8aeea 100644
--- a/statsd/Android.bp
+++ b/statsd/Android.bp
@@ -16,6 +16,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_telemetry_client_infra",
 }
 
 cc_defaults {
@@ -96,12 +97,15 @@ cc_defaults {
         "src/metrics/EventMetricProducer.cpp",
         "src/metrics/RestrictedEventMetricProducer.cpp",
         "src/metrics/GaugeMetricProducer.cpp",
+        "src/metrics/HistogramValue.cpp",
         "src/metrics/KllMetricProducer.cpp",
         "src/metrics/MetricProducer.cpp",
         "src/metrics/MetricsManager.cpp",
+        "src/metrics/NumericValue.cpp",
         "src/metrics/ValueMetricProducer.cpp",
         "src/metrics/parsing_utils/config_update_utils.cpp",
         "src/metrics/parsing_utils/metrics_manager_util.cpp",
+        "src/metrics/parsing_utils/histogram_parsing_utils.cpp",
         "src/metrics/NumericValueMetricProducer.cpp",
         "src/packages/UidMap.cpp",
         "src/shell/shell_config.proto",
@@ -144,6 +148,7 @@ cc_defaults {
         "libutils",
         "server_configurable_flags",
         "statsd-aidl-ndk",
+        "statsd_flags_c_lib",
         "libsqlite_static_noicu",
     ],
     shared_libs: [
@@ -155,6 +160,7 @@ cc_defaults {
     header_libs: [
         "libgtest_prod_headers",
     ],
+    min_sdk_version: "30",
 }
 
 genrule {
@@ -268,6 +274,7 @@ cc_binary {
         "com.android.os.statsd",
         "test_com.android.os.statsd",
     ],
+    runtime_libs: ["libuprobestats_client"],
     min_sdk_version: "30",
 }
 
@@ -296,6 +303,9 @@ cc_defaults {
         "libgmock",
         "libstatslog_statsdtest",
     ],
+    header_libs: [
+        "libstatssocket_test_headers",
+    ],
     proto: {
         type: "lite",
         include_dirs: [
@@ -311,6 +321,7 @@ cc_library_static {
     defaults: ["statsd_test_defaults"],
     srcs: [
         "tests/metrics/metrics_test_helper.cpp",
+        "tests/metrics/parsing_utils/parsing_test_utils.cpp",
         "tests/statsd_test_util.cpp",
     ],
     tidy_timeout_srcs: [
@@ -322,6 +333,11 @@ cc_library_static {
 // statsd_test
 // ==============
 
+filegroup {
+    name: "statsd_test_default_map",
+    srcs: ["statsd_test_default.map"],
+}
+
 cc_test {
     name: "statsd_test",
     defaults: ["statsd_test_defaults"],
@@ -343,6 +359,15 @@ cc_test {
         },
     },
 
+    // These tests run on older platform versions, so many libraries (such as libbase and libc++)
+    // need to be linked statically. The tests also need to be linked with a version script to
+    // ensure that the statically-linked library isn't exported from the executable, where it
+    // would override the shared libraries that the platform itself uses.
+    // See http://b/333438055 for an example of what goes wrong when libc++ is partially exported
+    // from an executable.
+    version_script: ":statsd_test_default_map",
+    stl: "c++_static",
+
     require_root: true,
 
     tidy_timeout_srcs: [
@@ -408,6 +433,7 @@ cc_test {
         "tests/e2e/RestrictedConfig_e2e_test.cpp",
         "tests/e2e/RestrictedEventMetric_e2e_test.cpp",
         "tests/e2e/StringReplace_e2e_test.cpp",
+        "tests/e2e/ValueMetric_histogram_e2e_test.cpp",
         "tests/e2e/ValueMetric_pull_e2e_test.cpp",
         "tests/e2e/WakelockDuration_e2e_test.cpp",
         "tests/external/puller_util_test.cpp",
@@ -427,12 +453,14 @@ cc_test {
         "tests/metrics/DurationMetricProducer_test.cpp",
         "tests/metrics/EventMetricProducer_test.cpp",
         "tests/metrics/GaugeMetricProducer_test.cpp",
+        "tests/metrics/HistogramValue_test.cpp",
         "tests/metrics/KllMetricProducer_test.cpp",
         "tests/metrics/MaxDurationTracker_test.cpp",
         "tests/metrics/OringDurationTracker_test.cpp",
         "tests/metrics/NumericValueMetricProducer_test.cpp",
         "tests/metrics/RestrictedEventMetricProducer_test.cpp",
         "tests/metrics/parsing_utils/config_update_utils_test.cpp",
+        "tests/metrics/parsing_utils/histogram_parsing_utils_test.cpp",
         "tests/metrics/parsing_utils/metrics_manager_util_test.cpp",
         "tests/subscriber/SubscriberReporter_test.cpp",
         "tests/DataCorruptionReason_test.cpp",
@@ -446,8 +474,8 @@ cc_test {
         "tests/StatsService_test.cpp",
         "tests/storage/StorageManager_test.cpp",
         "tests/UidMap_test.cpp",
-        "tests/utils/MultiConditionTrigger_test.cpp",
         "tests/utils/DbUtils_test.cpp",
+        "tests/utils/MultiConditionTrigger_test.cpp",
     ],
 
     static_libs: [
diff --git a/statsd/corpus/seed-2024-08-29-0 b/statsd/corpus/seed-2024-08-29-0
new file mode 100644
index 00000000..77359986
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-0 differ
diff --git a/statsd/corpus/seed-2024-08-29-1 b/statsd/corpus/seed-2024-08-29-1
new file mode 100644
index 00000000..32e0a610
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-1 differ
diff --git a/statsd/corpus/seed-2024-08-29-10 b/statsd/corpus/seed-2024-08-29-10
new file mode 100644
index 00000000..61e2255d
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-10 differ
diff --git a/statsd/corpus/seed-2024-08-29-2 b/statsd/corpus/seed-2024-08-29-2
new file mode 100644
index 00000000..5125a9ba
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-2 differ
diff --git a/statsd/corpus/seed-2024-08-29-3 b/statsd/corpus/seed-2024-08-29-3
new file mode 100644
index 00000000..2ed88679
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-3 differ
diff --git a/statsd/corpus/seed-2024-08-29-4 b/statsd/corpus/seed-2024-08-29-4
new file mode 100644
index 00000000..4bb7daaf
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-4 differ
diff --git a/statsd/corpus/seed-2024-08-29-5 b/statsd/corpus/seed-2024-08-29-5
new file mode 100644
index 00000000..ed7b4f2d
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-5 differ
diff --git a/statsd/corpus/seed-2024-08-29-6 b/statsd/corpus/seed-2024-08-29-6
new file mode 100644
index 00000000..f71bccb1
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-6 differ
diff --git a/statsd/corpus/seed-2024-08-29-7 b/statsd/corpus/seed-2024-08-29-7
new file mode 100644
index 00000000..1e2a0b9b
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-7 differ
diff --git a/statsd/corpus/seed-2024-08-29-8 b/statsd/corpus/seed-2024-08-29-8
new file mode 100644
index 00000000..33bea46b
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-8 differ
diff --git a/statsd/corpus/seed-2024-08-29-9 b/statsd/corpus/seed-2024-08-29-9
new file mode 100644
index 00000000..d9065881
Binary files /dev/null and b/statsd/corpus/seed-2024-08-29-9 differ
diff --git a/statsd/src/StatsLogProcessor.cpp b/statsd/src/StatsLogProcessor.cpp
index 94273f38..a1f4e65b 100644
--- a/statsd/src/StatsLogProcessor.cpp
+++ b/statsd/src/StatsLogProcessor.cpp
@@ -767,10 +767,17 @@ void StatsLogProcessor::onConfigMetricsReportLocked(
         // Do not call onDumpReport for restricted metrics.
         return;
     }
+
+    // get & forward queue overflow stats to StateManager only when
+    // there is a metric report to be collected, the data loss flags
+    // are not used otherwise
+    processQueueOverflowStatsLocked();
+
     int64_t lastReportTimeNs = it->second->getLastReportTimeNs();
     int64_t lastReportWallClockNs = it->second->getLastReportWallClockNs();
 
-    std::set<string> str_set;
+    std::set<string> strSet;
+    std::set<int32_t> usedUids;
 
     int64_t totalSize = it->second->byteSize();
 
@@ -778,17 +785,16 @@ void StatsLogProcessor::onConfigMetricsReportLocked(
     // First, fill in ConfigMetricsReport using current data on memory, which
     // starts from filling in StatsLogReport's.
     it->second->onDumpReport(dumpTimeStampNs, wallClockNs, include_current_partial_bucket,
-                             erase_data, dumpLatency, &str_set, &tempProto);
+                             erase_data, dumpLatency, &strSet, usedUids, &tempProto);
 
     // Fill in UidMap if there is at least one metric to report.
     // This skips the uid map if it's an empty config.
     if (it->second->getNumMetrics() > 0) {
         uint64_t uidMapToken = tempProto.start(FIELD_TYPE_MESSAGE | FIELD_ID_UID_MAP);
-        mUidMap->appendUidMap(dumpTimeStampNs, key, it->second->versionStringsInReport(),
-                              it->second->installerInReport(),
-                              it->second->packageCertificateHashSizeBytes(),
-                              it->second->omitSystemUidsInUidMap(),
-                              it->second->hashStringInReport() ? &str_set : nullptr, &tempProto);
+        UidMapOptions uidMapOptions = it->second->getUidMapOptions();
+        uidMapOptions.usedUids = std::move(usedUids);
+        mUidMap->appendUidMap(dumpTimeStampNs, key, uidMapOptions,
+                              it->second->hashStringInReport() ? &strSet : nullptr, &tempProto);
         tempProto.end(uidMapToken);
     }
 
@@ -804,7 +810,7 @@ void StatsLogProcessor::onConfigMetricsReportLocked(
     // Dump report reason
     tempProto.write(FIELD_TYPE_INT32 | FIELD_ID_DUMP_REPORT_REASON, dumpReportReason);
 
-    for (const auto& str : str_set) {
+    for (const auto& str : strSet) {
         tempProto.write(FIELD_TYPE_STRING | FIELD_COUNT_REPEATED | FIELD_ID_STRINGS, str);
     }
 
@@ -1556,6 +1562,23 @@ bool StatsLogProcessor::validateAppBreadcrumbEvent(const LogEvent& event) const
     return true;
 }
 
+void StatsLogProcessor::processQueueOverflowStatsLocked() {
+    auto queueOverflowStats = StatsdStats::getInstance().getQueueOverflowAtomsStats();
+
+    for (const auto [atomId, count] : queueOverflowStats) {
+        // are there new atoms dropped due to queue overflow since previous request
+        auto droppedAtomStatsIt = mQueueOverflowAtomsStats.find(atomId);
+        if (droppedAtomStatsIt != mQueueOverflowAtomsStats.end() &&
+            droppedAtomStatsIt->second == count) {
+            // no new dropped atoms detected for the atomId
+            continue;
+        }
+
+        StateManager::getInstance().onLogEventLost(atomId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW);
+    }
+    mQueueOverflowAtomsStats = std::move(queueOverflowStats);
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/StatsLogProcessor.h b/statsd/src/StatsLogProcessor.h
index 05105342..f640460a 100644
--- a/statsd/src/StatsLogProcessor.h
+++ b/statsd/src/StatsLogProcessor.h
@@ -329,6 +329,15 @@ private:
 
     bool validateAppBreadcrumbEvent(const LogEvent& event) const;
 
+    /**
+     * Notifies metrics only when new queue overflow happens since previous request
+     * Performs QueueOverflowAtomsStatsMap tracking via managing stats local copy
+     * The assumption is that QueueOverflowAtomsStatsMap is collected over time, and that
+     * none of atom id counters have disappeared (which is StatsdStats logic until it explicitly
+     * reset, which should not be happen during statsd service lifetime)
+     */
+    void processQueueOverflowStatsLocked();
+
     // Function used to send a broadcast so that receiver for the config key can call getData
     // to retrieve the stored data.
     std::function<bool(const ConfigKey& key)> mSendBroadcast;
@@ -366,7 +375,12 @@ private:
 
     bool mPrintAllLogs = false;
 
+    StatsdStats::QueueOverflowAtomsStatsMap mQueueOverflowAtomsStats;
+
+    friend class GuardedDataCorruptionTestTestStateLostPropagation;
     friend class StatsLogProcessorTestRestricted;
+    friend class ValueMetricHistogramE2eTestClientAggregatedPulledHistogram;
+
     FRIEND_TEST(StatsLogProcessorTest, TestOutOfOrderLogs);
     FRIEND_TEST(StatsLogProcessorTest, TestRateLimitByteSize);
     FRIEND_TEST(StatsLogProcessorTest, TestRateLimitBroadcast);
@@ -493,6 +507,8 @@ private:
     FRIEND_TEST(StringReplaceE2eTest, TestPulledDimension);
     FRIEND_TEST(StringReplaceE2eTest, TestPulledWhat);
     FRIEND_TEST(StringReplaceE2eTest, TestMultipleMatchersForAtom);
+
+    FRIEND_TEST(DataCorruptionTest, TestStateLostFromQueueOverflowPropagation);
 };
 
 }  // namespace statsd
diff --git a/statsd/src/StatsService.cpp b/statsd/src/StatsService.cpp
index c5478534..493bb0fc 100644
--- a/statsd/src/StatsService.cpp
+++ b/statsd/src/StatsService.cpp
@@ -233,7 +233,9 @@ StatsService::~StatsService() {
     onStatsdInitCompletedHandlerTermination();
     if (mEventQueue != nullptr) {
         stopReadingLogs();
-        mLogsReaderThread->join();
+        if (mLogsReaderThread != nullptr) {
+            mLogsReaderThread->join();
+        }
     }
 }
 
diff --git a/statsd/src/external/Uprobestats.cpp b/statsd/src/external/Uprobestats.cpp
index ad6613cf..d747396b 100644
--- a/statsd/src/external/Uprobestats.cpp
+++ b/statsd/src/external/Uprobestats.cpp
@@ -14,12 +14,10 @@
  * limitations under the License.
  */
 
-#define STATSD_DEBUG false  // STOPSHIP if true
 #include "Log.h"
 
-#include <android-base/file.h>
-#include <android-base/properties.h>
-#include <private/android_filesystem_config.h>
+#include <com_android_os_statsd_flags.h>
+#include <dlfcn.h>
 
 #include <string>
 
@@ -29,8 +27,48 @@ namespace android {
 namespace os {
 namespace statsd {
 
+namespace {
+typedef int (*AUprobestatsClient_startUprobestatsFn)(const uint8_t* config, int64_t size);
+
+const char kLibuprobestatsClientPath[] = "libuprobestats_client.so";
+
+AUprobestatsClient_startUprobestatsFn libInit() {
+    if (__builtin_available(android __ANDROID_API_V__, *)) {
+        void* handle = dlopen(kLibuprobestatsClientPath, RTLD_NOW | RTLD_LOCAL);
+        if (!handle) {
+            ALOGE("dlopen error: %s %s", __func__, dlerror());
+            return nullptr;
+        }
+        auto f = reinterpret_cast<AUprobestatsClient_startUprobestatsFn>(
+                dlsym(handle, "AUprobestatsClient_startUprobestats"));
+        if (!f) {
+            ALOGE("dlsym error: %s %s", __func__, dlerror());
+            return nullptr;
+        }
+        return f;
+    }
+    return nullptr;
+}
+
+namespace flags = com::android::os::statsd::flags;
+
+}  // namespace
+
 bool StartUprobeStats(const UprobestatsDetails& config) {
-    // TODO: Add an implementation.
+    if (!flags::trigger_uprobestats()) {
+        return false;
+    }
+    static AUprobestatsClient_startUprobestatsFn AUprobestatsClient_startUprobestats = libInit();
+    if (AUprobestatsClient_startUprobestats == nullptr) {
+        return false;
+    }
+    if (!config.has_config()) {
+        ALOGE("The uprobestats trace config is empty, aborting");
+        return false;
+    }
+    const std::string& cfgProto = config.config();
+    AUprobestatsClient_startUprobestats(reinterpret_cast<const uint8_t*>(cfgProto.c_str()),
+                                        cfgProto.length());
     return true;
 }
 
diff --git a/statsd/src/guardrail/StatsdStats.cpp b/statsd/src/guardrail/StatsdStats.cpp
index baa6d1bd..b8523797 100644
--- a/statsd/src/guardrail/StatsdStats.cpp
+++ b/statsd/src/guardrail/StatsdStats.cpp
@@ -1227,13 +1227,9 @@ bool StatsdStats::hasEventQueueOverflow() const {
     return mOverflowCount != 0;
 }
 
-vector<std::pair<int32_t, int32_t>> StatsdStats::getQueueOverflowAtomsStats() const {
+StatsdStats::QueueOverflowAtomsStatsMap StatsdStats::getQueueOverflowAtomsStats() const {
     lock_guard<std::mutex> lock(mLock);
-
-    vector<std::pair<int32_t, int32_t>> atomsStats(mPushedAtomDropsStats.begin(),
-                                                   mPushedAtomDropsStats.end());
-
-    return atomsStats;
+    return mPushedAtomDropsStats;
 }
 
 bool StatsdStats::hasSocketLoss() const {
@@ -2206,6 +2202,38 @@ InvalidConfigReason createInvalidConfigReasonWithSubscriptionAndAlert(
     return invalidConfigReason;
 }
 
+void PrintTo(const InvalidConfigReason& obj, std::ostream* os) {
+    *os << "{ reason: " << obj.reason;
+    if (obj.metricId.has_value()) {
+        *os << ", metricId: " << obj.metricId.value();
+    }
+    if (obj.stateId.has_value()) {
+        *os << ", stateId: " << obj.stateId.value();
+    }
+    if (obj.alertId.has_value()) {
+        *os << ", alertId: " << obj.alertId.value();
+    }
+    if (obj.alarmId.has_value()) {
+        *os << ", alarmId: " << obj.alarmId.value();
+    }
+    if (obj.subscriptionId.has_value()) {
+        *os << ", subscriptionId: " << obj.subscriptionId.value();
+    }
+    if (!obj.matcherIds.empty()) {
+        *os << ", matcherIds: [";
+        std::copy(obj.matcherIds.begin(), obj.matcherIds.end(),
+                  std::ostream_iterator<int64_t>(*os, ", "));
+        *os << "]";
+    }
+    if (!obj.conditionIds.empty()) {
+        *os << ", conditionIds: [";
+        std::copy(obj.conditionIds.begin(), obj.conditionIds.end(),
+                  std::ostream_iterator<int64_t>(*os, ", "));
+        *os << "]";
+    }
+    *os << " }";
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/guardrail/StatsdStats.h b/statsd/src/guardrail/StatsdStats.h
index e5615cdb..c2e8c38e 100644
--- a/statsd/src/guardrail/StatsdStats.h
+++ b/statsd/src/guardrail/StatsdStats.h
@@ -51,6 +51,9 @@ struct InvalidConfigReason {
                (this->alarmId == other.alarmId) && (this->subscriptionId == other.subscriptionId) &&
                (this->matcherIds == other.matcherIds) && (this->conditionIds == other.conditionIds);
     }
+
+    // For better failure messages in statsd_test
+    friend void PrintTo(const InvalidConfigReason& obj, std::ostream* os);
 };
 
 typedef struct {
@@ -773,8 +776,8 @@ public:
      */
     bool hasEventQueueOverflow() const;
 
-    typedef std::vector<std::pair<int32_t, int32_t>> QueueOverflowAtomsStats;
-    QueueOverflowAtomsStats getQueueOverflowAtomsStats() const;
+    typedef std::unordered_map<int32_t, int32_t> QueueOverflowAtomsStatsMap;
+    QueueOverflowAtomsStatsMap getQueueOverflowAtomsStats() const;
 
     /**
      * Returns true if there is recorded socket loss
@@ -870,7 +873,7 @@ private:
     // Stores the number of times a pushed atom is dropped due to queue overflow event.
     // We do not expect it will happen too often so the map is preferable vs pre-allocated vector
     // The max size of the map is kMaxPushedAtomId + kMaxNonPlatformPushedAtoms.
-    std::unordered_map<int, int> mPushedAtomDropsStats;
+    QueueOverflowAtomsStatsMap mPushedAtomDropsStats;
 
     // Maps PullAtomId to its stats. The size is capped by the puller atom counts.
     std::map<int, PulledAtomStats> mPulledAtomStats;
diff --git a/statsd/src/guardrail/stats_log_enums.proto b/statsd/src/guardrail/stats_log_enums.proto
index c468d52e..c320e170 100644
--- a/statsd/src/guardrail/stats_log_enums.proto
+++ b/statsd/src/guardrail/stats_log_enums.proto
@@ -153,6 +153,17 @@ enum InvalidConfigReasonEnum {
     INVALID_CONFIG_REASON_GAUGE_METRIC_RANDOM_ONE_SAMPLE_WITH_PULL_PROBABILITY = 95;
     INVALID_CONFIG_REASON_VALUE_METRIC_DEFINES_SINGLE_AND_MULTIPLE_AGG_TYPES = 96;
     INVALID_CONFIG_REASON_VALUE_METRIC_AGG_TYPES_DNE_VALUE_FIELDS_SIZE = 97;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_COUNT_DNE_HIST_BIN_CONFIGS_COUNT = 98;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_BIN_CONFIG_ID = 99;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_UNKNOWN_BINNING_STRATEGY = 100;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_GENERATED_BINS_ARGS = 101;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_GENERATED_BINS_INVALID_MIN_MAX = 102;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_FEW_BINS = 103;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_MANY_BINS = 104;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_EXPLICIT_BINS_NOT_STRICTLY_ORDERED = 105;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_WITH_UPLOAD_THRESHOLD = 106;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_INVALID_VALUE_DIRECTION = 107;
+    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_CLIENT_AGGREGATED_NO_POSITION_ALL = 108;
 };
 
 enum InvalidQueryReason {
diff --git a/statsd/src/logd/LogEvent.cpp b/statsd/src/logd/LogEvent.cpp
index affb0808..30cc2ddb 100644
--- a/statsd/src/logd/LogEvent.cpp
+++ b/statsd/src/logd/LogEvent.cpp
@@ -769,7 +769,8 @@ string LogEvent::ToString() const {
 }
 
 void LogEvent::ToProto(ProtoOutputStream& protoOutput) const {
-    writeFieldValueTreeToStream(mTagId, getValues(), &protoOutput);
+    set<int32_t> usedUids;
+    writeFieldValueTreeToStream(mTagId, getValues(), usedUids, &protoOutput);
 }
 
 bool LogEvent::hasAttributionChain(std::pair<size_t, size_t>* indexRange) const {
diff --git a/statsd/src/metrics/CountMetricProducer.cpp b/statsd/src/metrics/CountMetricProducer.cpp
index 32be42e5..0cf5c05b 100644
--- a/statsd/src/metrics/CountMetricProducer.cpp
+++ b/statsd/src/metrics/CountMetricProducer.cpp
@@ -55,6 +55,7 @@ const int FIELD_ID_DIMENSION_PATH_IN_WHAT = 11;
 const int FIELD_ID_IS_ACTIVE = 14;
 const int FIELD_ID_DIMENSION_GUARDRAIL_HIT = 17;
 const int FIELD_ID_ESTIMATED_MEMORY_BYTES = 18;
+const int FIELD_ID_DATA_CORRUPTED_REASON = 19;
 
 // for CountMetricDataWrapper
 const int FIELD_ID_DATA = 1;
@@ -216,13 +217,14 @@ void CountMetricProducer::onSlicedConditionMayChangeLocked(bool overallCondition
 
 void CountMetricProducer::clearPastBucketsLocked(const int64_t dumpTimeNs) {
     mPastBuckets.clear();
+    resetDataCorruptionFlagsLocked();
     mTotalDataSize = 0;
 }
 
 void CountMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
                                              const bool include_current_partial_bucket,
                                              const bool erase_data, const DumpLatency dumpLatency,
-                                             std::set<string>* str_set,
+                                             std::set<string>* str_set, std::set<int32_t>& usedUids,
                                              ProtoOutputStream* protoOutput) {
     if (include_current_partial_bucket) {
         flushLocked(dumpTimeNs);
@@ -233,7 +235,15 @@ void CountMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
     protoOutput->write(FIELD_TYPE_INT64 | FIELD_ID_ID, (long long)mMetricId);
     protoOutput->write(FIELD_TYPE_BOOL | FIELD_ID_IS_ACTIVE, isActiveLocked());
 
+    // Data corrupted reason
+    writeDataCorruptedReasons(*protoOutput, FIELD_ID_DATA_CORRUPTED_REASON,
+                              mDataCorruptedDueToQueueOverflow != DataCorruptionSeverity::kNone,
+                              mDataCorruptedDueToSocketLoss != DataCorruptionSeverity::kNone);
+
     if (mPastBuckets.empty()) {
+        if (erase_data) {
+            resetDataCorruptionFlagsLocked();
+        }
         return;
     }
 
@@ -270,11 +280,13 @@ void CountMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
         if (mShouldUseNestedDimensions) {
             uint64_t dimensionToken = protoOutput->start(
                     FIELD_TYPE_MESSAGE | FIELD_ID_DIMENSION_IN_WHAT);
-            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, protoOutput);
+            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, usedUids,
+                                  protoOutput);
             protoOutput->end(dimensionToken);
         } else {
             writeDimensionLeafNodesToProto(dimensionKey.getDimensionKeyInWhat(),
-                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, protoOutput);
+                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, usedUids,
+                                           protoOutput);
         }
         // Then fill slice_by_state.
         for (auto state : dimensionKey.getStateValuesKey().getValues()) {
@@ -319,6 +331,7 @@ void CountMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
     if (erase_data) {
         mPastBuckets.clear();
         mDimensionGuardrailHit = false;
+        resetDataCorruptionFlagsLocked();
         mTotalDataSize = 0;
     }
 }
@@ -327,6 +340,7 @@ void CountMetricProducer::dropDataLocked(const int64_t dropTimeNs) {
     flushIfNeededLocked(dropTimeNs);
     StatsdStats::getInstance().noteBucketDropped(mMetricId);
     mPastBuckets.clear();
+    resetDataCorruptionFlagsLocked();
     mTotalDataSize = 0;
 }
 
@@ -552,6 +566,18 @@ void CountMetricProducer::onActiveStateChangedLocked(const int64_t eventTimeNs,
     mConditionTimer.onConditionChanged(isActive, eventTimeNs);
 }
 
+MetricProducer::DataCorruptionSeverity CountMetricProducer::determineCorruptionSeverity(
+        int32_t atomId, DataCorruptedReason /*reason*/, LostAtomType atomType) const {
+    switch (atomType) {
+        case LostAtomType::kWhat:
+            return DataCorruptionSeverity::kResetOnDump;
+        case LostAtomType::kCondition:
+        case LostAtomType::kState:
+            return DataCorruptionSeverity::kUnrecoverable;
+    };
+    return DataCorruptionSeverity::kNone;
+};
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/metrics/CountMetricProducer.h b/statsd/src/metrics/CountMetricProducer.h
index d34181c7..bf48a4f2 100644
--- a/statsd/src/metrics/CountMetricProducer.h
+++ b/statsd/src/metrics/CountMetricProducer.h
@@ -71,12 +71,9 @@ protected:
             const std::map<int, HashableDimensionKey>& statePrimaryKeys) override;
 
 private:
-
-    void onDumpReportLocked(const int64_t dumpTimeNs,
-                            const bool include_current_partial_bucket,
-                            const bool erase_data,
-                            const DumpLatency dumpLatency,
-                            std::set<string> *str_set,
+    void onDumpReportLocked(const int64_t dumpTimeNs, const bool include_current_partial_bucket,
+                            const bool erase_data, const DumpLatency dumpLatency,
+                            std::set<string>* str_set, std::set<int32_t>& usedUids,
                             android::util::ProtoOutputStream* protoOutput) override;
 
     void clearPastBucketsLocked(const int64_t dumpTimeNs) override;
@@ -120,6 +117,9 @@ private:
             std::unordered_map<int, std::vector<int>>& deactivationAtomTrackerToMetricMap,
             std::vector<int>& metricsWithActivation) override;
 
+    DataCorruptionSeverity determineCorruptionSeverity(int32_t atomId, DataCorruptedReason reason,
+                                                       LostAtomType atomType) const override;
+
     std::unordered_map<MetricDimensionKey, std::vector<CountBucket>> mPastBuckets;
 
     // The current bucket (may be a partial bucket).
diff --git a/statsd/src/metrics/DurationMetricProducer.cpp b/statsd/src/metrics/DurationMetricProducer.cpp
index b07f2e33..1af07fbe 100644
--- a/statsd/src/metrics/DurationMetricProducer.cpp
+++ b/statsd/src/metrics/DurationMetricProducer.cpp
@@ -54,6 +54,7 @@ const int FIELD_ID_DIMENSION_PATH_IN_WHAT = 11;
 const int FIELD_ID_IS_ACTIVE = 14;
 const int FIELD_ID_DIMENSION_GUARDRAIL_HIT = 17;
 const int FIELD_ID_ESTIMATED_MEMORY_BYTES = 18;
+const int FIELD_ID_DATA_CORRUPTED_REASON = 19;
 // for DurationMetricDataWrapper
 const int FIELD_ID_DATA = 1;
 // for DurationMetricData
@@ -501,16 +502,19 @@ void DurationMetricProducer::dropDataLocked(const int64_t dropTimeNs) {
     flushIfNeededLocked(dropTimeNs);
     StatsdStats::getInstance().noteBucketDropped(mMetricId);
     mPastBuckets.clear();
+    resetDataCorruptionFlagsLocked();
 }
 
 void DurationMetricProducer::clearPastBucketsLocked(const int64_t dumpTimeNs) {
     flushIfNeededLocked(dumpTimeNs);
+    resetDataCorruptionFlagsLocked();
     mPastBuckets.clear();
 }
 
 void DurationMetricProducer::onDumpReportLocked(
         const int64_t dumpTimeNs, const bool include_current_partial_bucket, const bool erase_data,
-        const DumpLatency dumpLatency, std::set<string>* str_set, ProtoOutputStream* protoOutput) {
+        const DumpLatency dumpLatency, std::set<string>* str_set, std::set<int32_t>& usedUids,
+        ProtoOutputStream* protoOutput) {
     if (include_current_partial_bucket) {
         flushLocked(dumpTimeNs);
     } else {
@@ -520,8 +524,16 @@ void DurationMetricProducer::onDumpReportLocked(
     protoOutput->write(FIELD_TYPE_INT64 | FIELD_ID_ID, (long long)mMetricId);
     protoOutput->write(FIELD_TYPE_BOOL | FIELD_ID_IS_ACTIVE, isActiveLocked());
 
+    // Data corrupted reason
+    writeDataCorruptedReasons(*protoOutput, FIELD_ID_DATA_CORRUPTED_REASON,
+                              mDataCorruptedDueToQueueOverflow != DataCorruptionSeverity::kNone,
+                              mDataCorruptedDueToSocketLoss != DataCorruptionSeverity::kNone);
+
     if (mPastBuckets.empty()) {
         VLOG(" Duration metric, empty return");
+        if (erase_data) {
+            resetDataCorruptionFlagsLocked();
+        }
         return;
     }
 
@@ -559,11 +571,13 @@ void DurationMetricProducer::onDumpReportLocked(
         if (mShouldUseNestedDimensions) {
             uint64_t dimensionToken = protoOutput->start(
                     FIELD_TYPE_MESSAGE | FIELD_ID_DIMENSION_IN_WHAT);
-            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, protoOutput);
+            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, usedUids,
+                                  protoOutput);
             protoOutput->end(dimensionToken);
         } else {
             writeDimensionLeafNodesToProto(dimensionKey.getDimensionKeyInWhat(),
-                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, protoOutput);
+                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, usedUids,
+                                           protoOutput);
         }
         // Then fill slice_by_state.
         for (auto state : dimensionKey.getStateValuesKey().getValues()) {
@@ -606,6 +620,7 @@ void DurationMetricProducer::onDumpReportLocked(
     protoOutput->end(protoToken);
     if (erase_data) {
         mPastBuckets.clear();
+        resetDataCorruptionFlagsLocked();
     }
 }
 
@@ -889,6 +904,20 @@ size_t DurationMetricProducer::byteSizeLocked() const {
     return totalSize;
 }
 
+MetricProducer::DataCorruptionSeverity DurationMetricProducer::determineCorruptionSeverity(
+        int32_t /*atomId*/, DataCorruptedReason /*reason*/, LostAtomType atomType) const {
+    switch (atomType) {
+        case LostAtomType::kWhat:
+            // in case of loss stop/start/stopall event the error will be propagated
+            // to next bucket
+            return DataCorruptionSeverity::kUnrecoverable;
+        case LostAtomType::kCondition:
+        case LostAtomType::kState:
+            return DataCorruptionSeverity::kUnrecoverable;
+    };
+    return DataCorruptionSeverity::kNone;
+};
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/metrics/DurationMetricProducer.h b/statsd/src/metrics/DurationMetricProducer.h
index c5403ff8..d67bae26 100644
--- a/statsd/src/metrics/DurationMetricProducer.h
+++ b/statsd/src/metrics/DurationMetricProducer.h
@@ -86,11 +86,9 @@ private:
                           bool condition, int64_t eventTimeNs,
                           const vector<FieldValue>& eventValues);
 
-    void onDumpReportLocked(const int64_t dumpTimeNs,
-                            const bool include_current_partial_bucket,
-                            const bool erase_data,
-                            const DumpLatency dumpLatency,
-                            std::set<string> *str_set,
+    void onDumpReportLocked(const int64_t dumpTimeNs, const bool include_current_partial_bucket,
+                            const bool erase_data, const DumpLatency dumpLatency,
+                            std::set<string>* str_set, std::set<int32_t>& usedUids,
                             android::util::ProtoOutputStream* protoOutput) override;
 
     void clearPastBucketsLocked(const int64_t dumpTimeNs) override;
@@ -142,6 +140,9 @@ private:
     size_t computeBucketSizeLocked(const bool isFullBucket, const MetricDimensionKey& dimKey,
                                    const bool isFirstBucket) const override;
 
+    DataCorruptionSeverity determineCorruptionSeverity(int32_t atomId, DataCorruptedReason reason,
+                                                       LostAtomType atomType) const override;
+
     const DurationMetric_AggregationType mAggregationType;
 
     // Index of the SimpleAtomMatcher which defines the start.
diff --git a/statsd/src/metrics/EventMetricProducer.cpp b/statsd/src/metrics/EventMetricProducer.cpp
index b1e524ca..55aa85a4 100644
--- a/statsd/src/metrics/EventMetricProducer.cpp
+++ b/statsd/src/metrics/EventMetricProducer.cpp
@@ -172,9 +172,8 @@ void EventMetricProducer::clearPastBucketsLocked(const int64_t dumpTimeNs) {
 
 void EventMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
                                              const bool include_current_partial_bucket,
-                                             const bool erase_data,
-                                             const DumpLatency dumpLatency,
-                                             std::set<string> *str_set,
+                                             const bool erase_data, const DumpLatency dumpLatency,
+                                             std::set<string>* str_set, std::set<int32_t>& usedUids,
                                              ProtoOutputStream* protoOutput) {
     protoOutput->write(FIELD_TYPE_INT64 | FIELD_ID_ID, (long long)mMetricId);
     protoOutput->write(FIELD_TYPE_BOOL | FIELD_ID_IS_ACTIVE, isActiveLocked());
@@ -196,7 +195,8 @@ void EventMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
 
         uint64_t atomToken = protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_ATOM);
         writeFieldValueTreeToStream(atomDimensionKey.getAtomTag(),
-                                    atomDimensionKey.getAtomFieldValues().getValues(), protoOutput);
+                                    atomDimensionKey.getAtomFieldValues().getValues(), usedUids,
+                                    protoOutput);
         protoOutput->end(atomToken);
         for (int64_t timestampNs : elapsedTimestampsNs) {
             protoOutput->write(FIELD_TYPE_INT64 | FIELD_COUNT_REPEATED | FIELD_ID_ATOM_TIMESTAMPS,
@@ -258,12 +258,14 @@ size_t EventMetricProducer::byteSizeLocked() const {
 }
 
 MetricProducer::DataCorruptionSeverity EventMetricProducer::determineCorruptionSeverity(
-        DataCorruptedReason reason, LostAtomType atomType) const {
+        int32_t /*atomId*/, DataCorruptedReason reason, LostAtomType atomType) const {
     switch (atomType) {
         case LostAtomType::kWhat:
             return DataCorruptionSeverity::kResetOnDump;
         case LostAtomType::kCondition:
             return DataCorruptionSeverity::kUnrecoverable;
+        case LostAtomType::kState:
+            break;
     };
     return DataCorruptionSeverity::kNone;
 };
diff --git a/statsd/src/metrics/EventMetricProducer.h b/statsd/src/metrics/EventMetricProducer.h
index 5380ecfd..28bf83f6 100644
--- a/statsd/src/metrics/EventMetricProducer.h
+++ b/statsd/src/metrics/EventMetricProducer.h
@@ -57,11 +57,9 @@ private:
             const ConditionKey& conditionKey, bool condition, const LogEvent& event,
             const std::map<int, HashableDimensionKey>& statePrimaryKeys) override;
 
-    void onDumpReportLocked(const int64_t dumpTimeNs,
-                            const bool include_current_partial_bucket,
-                            const bool erase_data,
-                            const DumpLatency dumpLatency,
-                            std::set<string> *str_set,
+    void onDumpReportLocked(const int64_t dumpTimeNs, const bool include_current_partial_bucket,
+                            const bool erase_data, const DumpLatency dumpLatency,
+                            std::set<string>* str_set, std::set<int32_t>& usedUids,
                             android::util::ProtoOutputStream* protoOutput) override;
     void clearPastBucketsLocked(const int64_t dumpTimeNs) override;
 
@@ -94,7 +92,7 @@ private:
 
     void dumpStatesLocked(int out, bool verbose) const override{};
 
-    DataCorruptionSeverity determineCorruptionSeverity(DataCorruptedReason reason,
+    DataCorruptionSeverity determineCorruptionSeverity(int32_t atomId, DataCorruptedReason reason,
                                                        LostAtomType atomType) const override;
 
     // Maps the field/value pairs of an atom to a list of timestamps used to deduplicate atoms.
diff --git a/statsd/src/metrics/GaugeMetricProducer.cpp b/statsd/src/metrics/GaugeMetricProducer.cpp
index 979b3444..bbfad86b 100644
--- a/statsd/src/metrics/GaugeMetricProducer.cpp
+++ b/statsd/src/metrics/GaugeMetricProducer.cpp
@@ -51,6 +51,7 @@ const int FIELD_ID_DIMENSION_PATH_IN_WHAT = 11;
 const int FIELD_ID_IS_ACTIVE = 14;
 const int FIELD_ID_DIMENSION_GUARDRAIL_HIT = 17;
 const int FIELD_ID_ESTIMATED_MEMORY_BYTES = 18;
+const int FIELD_ID_DATA_CORRUPTED_REASON = 19;
 // for GaugeMetricDataWrapper
 const int FIELD_ID_DATA = 1;
 const int FIELD_ID_SKIPPED = 2;
@@ -244,14 +245,14 @@ void GaugeMetricProducer::clearPastBucketsLocked(const int64_t dumpTimeNs) {
     flushIfNeededLocked(dumpTimeNs);
     mPastBuckets.clear();
     mSkippedBuckets.clear();
+    resetDataCorruptionFlagsLocked();
     mTotalDataSize = 0;
 }
 
 void GaugeMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
                                              const bool include_current_partial_bucket,
-                                             const bool erase_data,
-                                             const DumpLatency dumpLatency,
-                                             std::set<string> *str_set,
+                                             const bool erase_data, const DumpLatency dumpLatency,
+                                             std::set<string>* str_set, std::set<int32_t>& usedUids,
                                              ProtoOutputStream* protoOutput) {
     VLOG("Gauge metric %lld report now...", (long long)mMetricId);
     if (include_current_partial_bucket) {
@@ -263,7 +264,15 @@ void GaugeMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
     protoOutput->write(FIELD_TYPE_INT64 | FIELD_ID_ID, (long long)mMetricId);
     protoOutput->write(FIELD_TYPE_BOOL | FIELD_ID_IS_ACTIVE, isActiveLocked());
 
+    // Data corrupted reason
+    writeDataCorruptedReasons(*protoOutput, FIELD_ID_DATA_CORRUPTED_REASON,
+                              mDataCorruptedDueToQueueOverflow != DataCorruptionSeverity::kNone,
+                              mDataCorruptedDueToSocketLoss != DataCorruptionSeverity::kNone);
+
     if (mPastBuckets.empty() && mSkippedBuckets.empty()) {
+        if (erase_data) {
+            resetDataCorruptionFlagsLocked();
+        }
         return;
     }
 
@@ -319,11 +328,13 @@ void GaugeMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
         if (mShouldUseNestedDimensions) {
             uint64_t dimensionToken = protoOutput->start(
                     FIELD_TYPE_MESSAGE | FIELD_ID_DIMENSION_IN_WHAT);
-            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, protoOutput);
+            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, usedUids,
+                                  protoOutput);
             protoOutput->end(dimensionToken);
         } else {
             writeDimensionLeafNodesToProto(dimensionKey.getDimensionKeyInWhat(),
-                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, protoOutput);
+                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, usedUids,
+                                           protoOutput);
         }
 
         // Then fill bucket_info (GaugeBucketInfo).
@@ -350,7 +361,7 @@ void GaugeMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
                             protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_ATOM_VALUE);
                     writeFieldValueTreeToStream(mAtomId,
                                                 atomDimensionKey.getAtomFieldValues().getValues(),
-                                                protoOutput);
+                                                usedUids, protoOutput);
                     protoOutput->end(atomToken);
                     for (int64_t timestampNs : elapsedTimestampsNs) {
                         protoOutput->write(
@@ -375,6 +386,7 @@ void GaugeMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
         mPastBuckets.clear();
         mSkippedBuckets.clear();
         mDimensionGuardrailHit = false;
+        resetDataCorruptionFlagsLocked();
         mTotalDataSize = 0;
     }
 }
@@ -548,7 +560,7 @@ bool GaugeMetricProducer::hitGuardRailLocked(const MetricDimensionKey& newKey) {
 void GaugeMetricProducer::onMatchedLogEventInternalLocked(
         const size_t matcherIndex, const MetricDimensionKey& eventKey,
         const ConditionKey& conditionKey, bool condition, const LogEvent& event,
-        const map<int, HashableDimensionKey>& statePrimaryKeys) {
+        const map<int, HashableDimensionKey>& /*statePrimaryKeys*/) {
     if (condition == false) {
         return;
     }
@@ -629,6 +641,7 @@ void GaugeMetricProducer::dropDataLocked(const int64_t dropTimeNs) {
     flushIfNeededLocked(dropTimeNs);
     StatsdStats::getInstance().noteBucketDropped(mMetricId);
     mPastBuckets.clear();
+    resetDataCorruptionFlagsLocked();
     mTotalDataSize = 0;
 }
 
@@ -753,6 +766,19 @@ size_t GaugeMetricProducer::byteSizeLocked() const {
     return totalSize;
 }
 
+MetricProducer::DataCorruptionSeverity GaugeMetricProducer::determineCorruptionSeverity(
+        int32_t atomId, DataCorruptedReason reason, LostAtomType atomType) const {
+    switch (atomType) {
+        case LostAtomType::kWhat:
+            return DataCorruptionSeverity::kResetOnDump;
+        case LostAtomType::kCondition:
+            return DataCorruptionSeverity::kUnrecoverable;
+        case LostAtomType::kState:
+            break;
+    };
+    return DataCorruptionSeverity::kNone;
+};
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/metrics/GaugeMetricProducer.h b/statsd/src/metrics/GaugeMetricProducer.h
index daff08c3..f5839d12 100644
--- a/statsd/src/metrics/GaugeMetricProducer.h
+++ b/statsd/src/metrics/GaugeMetricProducer.h
@@ -115,11 +115,9 @@ protected:
             const std::map<int, HashableDimensionKey>& statePrimaryKeys) override;
 
 private:
-    void onDumpReportLocked(const int64_t dumpTimeNs,
-                            const bool include_current_partial_bucket,
-                            const bool erase_data,
-                            const DumpLatency dumpLatency,
-                            std::set<string> *str_set,
+    void onDumpReportLocked(const int64_t dumpTimeNs, const bool include_current_partial_bucket,
+                            const bool erase_data, const DumpLatency dumpLatency,
+                            std::set<string>* str_set, std::set<int32_t>& usedUids,
                             android::util::ProtoOutputStream* protoOutput) override;
     void clearPastBucketsLocked(const int64_t dumpTimeNs) override;
 
@@ -175,6 +173,9 @@ private:
                mSamplingType == GaugeMetric::RANDOM_ONE_SAMPLE;
     }
 
+    DataCorruptionSeverity determineCorruptionSeverity(int32_t atomId, DataCorruptedReason reason,
+                                                       LostAtomType atomType) const override;
+
     int mWhatMatcherIndex;
 
     sp<EventMatcherWizard> mEventMatcherWizard;
diff --git a/statsd/src/metrics/HistogramValue.cpp b/statsd/src/metrics/HistogramValue.cpp
new file mode 100644
index 00000000..93d9b61b
--- /dev/null
+++ b/statsd/src/metrics/HistogramValue.cpp
@@ -0,0 +1,199 @@
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
+#define STATSD_DEBUG false  // STOPSHIP if true
+#include "Log.h"
+
+#include "HistogramValue.h"
+
+#include <android/util/ProtoOutputStream.h>
+
+#include <algorithm>
+#include <functional>
+#include <sstream>
+#include <string>
+#include <vector>
+
+using android::util::FIELD_COUNT_REPEATED;
+using android::util::FIELD_TYPE_SINT32;
+using android::util::ProtoOutputStream;
+using std::string;
+using std::vector;
+
+namespace android {
+namespace os {
+namespace statsd {
+namespace {
+constexpr int FIELD_ID_COUNT = 1;
+}  // anonymous namespace
+
+const HistogramValue HistogramValue::ERROR_BINS_MISMATCH = HistogramValue({-1});
+const HistogramValue HistogramValue::ERROR_BIN_COUNT_TOO_HIGH = HistogramValue({-2});
+
+string HistogramValue::toString() const {
+    std::stringstream result("{");
+    std::copy(mBinCounts.begin(), mBinCounts.end(), std::ostream_iterator<int>(result, ", "));
+    return result.str() + "}";
+}
+
+bool HistogramValue::isEmpty() const {
+    return mBinCounts.empty() ||
+           std::all_of(mBinCounts.begin(), mBinCounts.end(), [](int count) { return count <= 0; });
+}
+
+size_t HistogramValue::getSize() const {
+    return sizeof(int) * mBinCounts.size();
+}
+
+void HistogramValue::toProto(ProtoOutputStream& protoOutput) const {
+    for (int binCount : mBinCounts) {
+        protoOutput.write(FIELD_TYPE_SINT32 | FIELD_COUNT_REPEATED | FIELD_ID_COUNT, binCount);
+    }
+}
+
+void HistogramValue::addValue(float value, const BinStarts& binStarts) {
+    if (mBinCounts.empty()) {
+        mBinCounts.resize(binStarts.size(), 0);
+    }
+    size_t index = 0;
+    for (; index < binStarts.size() - 1; index++) {
+        if (value < binStarts[index + 1]) {
+            break;
+        }
+    }
+    mBinCounts[index]++;
+}
+
+HistogramValue HistogramValue::getCompactedHistogramValue() const {
+    size_t compactSize = getCompactedBinCountsSize(mBinCounts);
+    HistogramValue result;
+    result.mBinCounts.reserve(compactSize);
+    int zeroCount = 0;
+    for (int binCount : mBinCounts) {
+        if (binCount <= 0) {
+            zeroCount++;
+        } else {
+            if (zeroCount > 1) {
+                result.mBinCounts.push_back(-zeroCount);
+            } else if (zeroCount == 1) {
+                result.mBinCounts.push_back(0);
+            }
+            result.mBinCounts.push_back(binCount);
+            zeroCount = 0;
+        }
+    }
+    if (zeroCount > 1) {
+        result.mBinCounts.push_back(-zeroCount);
+    } else if (zeroCount == 1) {
+        result.mBinCounts.push_back(0);
+    }
+
+    result.mCompacted = true;
+    return result;
+}
+
+bool HistogramValue::isValid() const {
+    return mCompacted ||
+           std::all_of(mBinCounts.begin(), mBinCounts.end(), [](int count) { return count >= 0; });
+}
+
+HistogramValue& HistogramValue::operator+=(const HistogramValue& rhs) {
+    if (mBinCounts.size() < rhs.mBinCounts.size()) {
+        ALOGE("HistogramValue::operator+=() arg has too many bins");
+        *this = ERROR_BINS_MISMATCH;
+        return *this;
+    }
+    for (size_t i = 0; i < rhs.mBinCounts.size(); i++) {
+        mBinCounts[i] += rhs.mBinCounts[i];
+    }
+    return *this;
+}
+
+HistogramValue operator+(HistogramValue lhs, const HistogramValue& rhs) {
+    lhs += rhs;
+    return lhs;
+}
+
+HistogramValue& HistogramValue::operator-=(const HistogramValue& rhs) {
+    if (mBinCounts.size() < rhs.mBinCounts.size()) {
+        ALOGE("HistogramValue::operator-=() arg has too many bins");
+        *this = ERROR_BINS_MISMATCH;
+        return *this;
+    }
+    for (size_t i = 0; i < rhs.mBinCounts.size(); i++) {
+        if (mBinCounts[i] < rhs.mBinCounts[i]) {
+            ALOGE("HistogramValue::operator-=() arg has a bin count that is too high");
+            *this = ERROR_BIN_COUNT_TOO_HIGH;
+            return *this;
+        }
+        mBinCounts[i] -= rhs.mBinCounts[i];
+    }
+    return *this;
+}
+
+HistogramValue operator-(HistogramValue lhs, const HistogramValue& rhs) {
+    lhs -= rhs;
+    return lhs;
+}
+
+bool operator==(const HistogramValue& lhs, const HistogramValue& rhs) {
+    return lhs.mBinCounts == rhs.mBinCounts;
+}
+
+bool operator!=(const HistogramValue& lhs, const HistogramValue& rhs) {
+    return lhs.mBinCounts != rhs.mBinCounts;
+}
+
+bool operator<(const HistogramValue& lhs, const HistogramValue& rhs) {
+    ALOGE("HistogramValue::operator<() should not be called");
+    return false;
+}
+
+bool operator>(const HistogramValue& lhs, const HistogramValue& rhs) {
+    ALOGE("HistogramValue::operator>() should not be called");
+    return false;
+}
+
+bool operator<=(const HistogramValue& lhs, const HistogramValue& rhs) {
+    ALOGE("HistogramValue::operator<=() should not be called");
+    return false;
+}
+
+bool operator>=(const HistogramValue& lhs, const HistogramValue& rhs) {
+    ALOGE("HistogramValue::operator>=() should not be called");
+    return false;
+}
+
+size_t getCompactedBinCountsSize(const std::vector<int>& binCounts) {
+    if (binCounts.empty()) {
+        return 0;
+    }
+    size_t compactSize = 1;
+    for (size_t i = 1; i < binCounts.size(); i++) {
+        // If current index i and the previous index i-1 hold 0, ie. this is a consecutive bin with
+        // 0, then this bin will be compressed after compaction and not be counted towards the
+        // compacted size. Hence, only increment compactSize if at least one of current index or
+        // the previous index have non-zero bin counts.
+        if (binCounts[i] != 0 || binCounts[i - 1] != 0) {
+            compactSize++;
+        }
+    }
+    return compactSize;
+}
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/metrics/HistogramValue.h b/statsd/src/metrics/HistogramValue.h
new file mode 100644
index 00000000..914ecbee
--- /dev/null
+++ b/statsd/src/metrics/HistogramValue.h
@@ -0,0 +1,104 @@
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
+#include <android/util/ProtoOutputStream.h>
+
+#include <string>
+#include <vector>
+
+#include "stats_util.h"
+
+#pragma once
+
+namespace android {
+namespace os {
+namespace statsd {
+
+size_t getCompactedBinCountsSize(const std::vector<int>& binCounts);
+
+// Encapsulates histogram bin counts. This class is not thread-safe.
+class HistogramValue {
+public:
+    // Default constructor
+    constexpr HistogramValue() noexcept = default;
+
+    // Copy constructor for pre-aggregated bin counts.
+    constexpr HistogramValue(const std::vector<int>& binCounts) : mBinCounts(binCounts) {
+    }
+
+    // Move constructor for pre-aggregated bin counts.
+    constexpr HistogramValue(std::vector<int>&& binCounts) : mBinCounts(std::move(binCounts)) {
+    }
+
+    std::string toString() const;
+
+    bool isEmpty() const;
+
+    size_t getSize() const;
+
+    // Should only be called on HistogramValue instances returned by getCompactedHistogramValue().
+    // Also, this should be called to dump histogram data to proto.
+    void toProto(android::util::ProtoOutputStream& protoOutput) const;
+
+    void addValue(float value, const BinStarts& binStarts);
+
+    // Returns a new HistogramValue where mBinCounts is compressed as follows:
+    // For each entry in mBinCounts, n:
+    //  * n >= 0 represents the actual count
+    //  * n == -1 does not appear
+    //  * n <= -2 represents -n consecutive bins with count of 0
+    // Called on bucket flushes from NumericValueMetricProducer
+    HistogramValue getCompactedHistogramValue() const;
+
+    bool isValid() const;
+
+    HistogramValue& operator+=(const HistogramValue& rhs);
+
+    // Returns a HistogramValue where each bin is the sum of the corresponding bins in lhs and rhs.
+    // If rhs has fewer bins, the remaining lhs bins are copied to the returned HistogramValue.
+    friend HistogramValue operator+(HistogramValue lhs, const HistogramValue& rhs);
+
+    HistogramValue& operator-=(const HistogramValue& rhs);
+
+    // Returns a HistogramValue where each bin in rhs is subtracted from the corresponding bin in
+    // lhs. If rhs has fewer bins, the remaining lhs bins are copied to the returned HistogramValue.
+    // For bins where the returned value would be less than 0, their values are set to 0 instead.
+    friend HistogramValue operator-(HistogramValue lhs, const HistogramValue& rhs);
+
+    friend bool operator==(const HistogramValue& lhs, const HistogramValue& rhs);
+
+    friend bool operator!=(const HistogramValue& lhs, const HistogramValue& rhs);
+
+    friend bool operator<(const HistogramValue& lhs, const HistogramValue& rhs);
+
+    friend bool operator>(const HistogramValue& lhs, const HistogramValue& rhs);
+
+    friend bool operator<=(const HistogramValue& lhs, const HistogramValue& rhs);
+
+    friend bool operator>=(const HistogramValue& lhs, const HistogramValue& rhs);
+
+    // Error states encountered during binary operations.
+    static const HistogramValue ERROR_BINS_MISMATCH;
+    static const HistogramValue ERROR_BIN_COUNT_TOO_HIGH;
+
+private:
+    std::vector<int> mBinCounts;
+    bool mCompacted = false;
+};
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/metrics/KllMetricProducer.cpp b/statsd/src/metrics/KllMetricProducer.cpp
index cc59e3cc..e2814cb5 100644
--- a/statsd/src/metrics/KllMetricProducer.cpp
+++ b/statsd/src/metrics/KllMetricProducer.cpp
@@ -190,6 +190,18 @@ size_t KllMetricProducer::byteSizeLocked() const {
     return totalSize;
 }
 
+MetricProducer::DataCorruptionSeverity KllMetricProducer::determineCorruptionSeverity(
+        int32_t /*atomId*/, DataCorruptedReason /*reason*/, LostAtomType atomType) const {
+    switch (atomType) {
+        case LostAtomType::kWhat:
+            return DataCorruptionSeverity::kResetOnDump;
+        case LostAtomType::kCondition:
+        case LostAtomType::kState:
+            return DataCorruptionSeverity::kUnrecoverable;
+    };
+    return DataCorruptionSeverity::kNone;
+};
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/metrics/KllMetricProducer.h b/statsd/src/metrics/KllMetricProducer.h
index dd5dcbd8..451a82b9 100644
--- a/statsd/src/metrics/KllMetricProducer.h
+++ b/statsd/src/metrics/KllMetricProducer.h
@@ -112,6 +112,9 @@ private:
     // Internal function to calculate the current used bytes.
     size_t byteSizeLocked() const override;
 
+    DataCorruptionSeverity determineCorruptionSeverity(int32_t atomId, DataCorruptedReason reason,
+                                                       LostAtomType atomType) const override;
+
     FRIEND_TEST(KllMetricProducerTest, TestByteSize);
     FRIEND_TEST(KllMetricProducerTest, TestPushedEventsWithoutCondition);
     FRIEND_TEST(KllMetricProducerTest, TestPushedEventsWithCondition);
diff --git a/statsd/src/metrics/MetricProducer.cpp b/statsd/src/metrics/MetricProducer.cpp
index c13065a2..d0e0fc95 100644
--- a/statsd/src/metrics/MetricProducer.cpp
+++ b/statsd/src/metrics/MetricProducer.cpp
@@ -191,9 +191,10 @@ void MetricProducer::onMatchedLogEventLocked(const size_t matcherIndex, const Lo
  *        Inherited classes are responsible for proper severity determination according
  *        to loss parameters (see @determineCorruptionSeverity)
  */
-void MetricProducer::onMatchedLogEventLostLocked(int32_t /*atomId*/, DataCorruptedReason reason,
+void MetricProducer::onMatchedLogEventLostLocked(int32_t atomId, DataCorruptedReason reason,
                                                  LostAtomType atomType) {
-    const DataCorruptionSeverity newSeverity = determineCorruptionSeverity(reason, atomType);
+    const DataCorruptionSeverity newSeverity =
+            determineCorruptionSeverity(atomId, reason, atomType);
     switch (reason) {
         case DATA_CORRUPTED_SOCKET_LOSS:
             mDataCorruptedDueToSocketLoss = std::max(mDataCorruptedDueToSocketLoss, newSeverity);
@@ -356,8 +357,6 @@ void MetricProducer::queryStateValue(int32_t atomId, const HashableDimensionKey&
     if (!StateManager::getInstance().getStateValue(atomId, queryKey, value)) {
         value->mValue = Value(StateTracker::kStateUnknown);
         value->mField.setTag(atomId);
-        ALOGW("StateTracker not found for state atom %d", atomId);
-        return;
     }
 }
 
diff --git a/statsd/src/metrics/MetricProducer.h b/statsd/src/metrics/MetricProducer.h
index 8f088214..5f66319c 100644
--- a/statsd/src/metrics/MetricProducer.h
+++ b/statsd/src/metrics/MetricProducer.h
@@ -213,6 +213,7 @@ public:
     enum class LostAtomType {
         kWhat = 0,
         kCondition,
+        kState,
     };
 
     void onMatchedLogEventLost(int32_t atomId, DataCorruptedReason reason, LostAtomType atomType) {
@@ -239,14 +240,20 @@ public:
                         const HashableDimensionKey& primaryKey, const FieldValue& oldState,
                         const FieldValue& newState){};
 
+    void onStateEventLost(int32_t atomId, DataCorruptedReason reason) override {
+        std::lock_guard<std::mutex> lock(mMutex);
+        onMatchedLogEventLostLocked(atomId, reason, LostAtomType::kState);
+    }
+
     // Output the metrics data to [protoOutput]. All metrics reports end with the same timestamp.
     // This method clears all the past buckets.
     void onDumpReport(const int64_t dumpTimeNs, const bool include_current_partial_bucket,
                       const bool erase_data, const DumpLatency dumpLatency,
-                      std::set<string>* str_set, android::util::ProtoOutputStream* protoOutput) {
+                      std::set<string>* str_set, std::set<int32_t>& usedUids,
+                      android::util::ProtoOutputStream* protoOutput) {
         std::lock_guard<std::mutex> lock(mMutex);
         onDumpReportLocked(dumpTimeNs, include_current_partial_bucket, erase_data, dumpLatency,
-                           str_set, protoOutput);
+                           str_set, usedUids, protoOutput);
     }
 
     virtual optional<InvalidConfigReason> onConfigUpdatedLocked(
@@ -444,7 +451,7 @@ protected:
     virtual void onDumpReportLocked(const int64_t dumpTimeNs,
                                     const bool include_current_partial_bucket,
                                     const bool erase_data, const DumpLatency dumpLatency,
-                                    std::set<string>* str_set,
+                                    std::set<string>* str_set, std::set<int32_t>& usedUids,
                                     android::util::ProtoOutputStream* protoOutput) = 0;
     virtual void clearPastBucketsLocked(const int64_t dumpTimeNs) = 0;
     virtual void prepareFirstBucketLocked(){};
@@ -519,7 +526,7 @@ protected:
 
     // The time when this metric producer was first created. The end time for the current bucket
     // can be computed from this based on mCurrentBucketNum.
-    int64_t mTimeBaseNs;
+    const int64_t mTimeBaseNs;
 
     // Start time may not be aligned with the start of statsd if there is an app upgrade in the
     // middle of a bucket.
@@ -609,8 +616,9 @@ protected:
      *
      * @return DataCorruptionSeverity
      */
-    virtual DataCorruptionSeverity determineCorruptionSeverity(DataCorruptedReason reason,
-                                                               LostAtomType atomType) const {
+    virtual DataCorruptionSeverity determineCorruptionSeverity(int32_t /*atomId*/,
+                                                               DataCorruptedReason /*reason*/,
+                                                               LostAtomType /*atomType*/) const {
         return DataCorruptionSeverity::kNone;
     };
 
@@ -621,6 +629,7 @@ protected:
 
     size_t mTotalDataSize = 0;
 
+    friend class SocketLossInfoTest;
     FRIEND_TEST(CountMetricE2eTest, TestSlicedState);
     FRIEND_TEST(CountMetricE2eTest, TestSlicedStateWithMap);
     FRIEND_TEST(CountMetricE2eTest, TestMultipleSlicedStates);
@@ -658,8 +667,6 @@ protected:
     FRIEND_TEST(ValueMetricE2eTest, TestInitWithSlicedState_WithIncorrectDimensions);
     FRIEND_TEST(ValueMetricE2eTest, TestInitialConditionChanges);
 
-    FRIEND_TEST(SocketLossInfoTest, PropagationTest);
-
     FRIEND_TEST(MetricsManagerUtilTest, TestInitialConditions);
     FRIEND_TEST(MetricsManagerUtilTest, TestSampledMetrics);
 
diff --git a/statsd/src/metrics/MetricsManager.cpp b/statsd/src/metrics/MetricsManager.cpp
index 538af6c7..c0fe2817 100644
--- a/statsd/src/metrics/MetricsManager.cpp
+++ b/statsd/src/metrics/MetricsManager.cpp
@@ -85,7 +85,11 @@ MetricsManager::MetricsManager(const ConfigKey& key, const StatsdConfig& config,
                           config.whitelisted_atom_ids().end()),
       mShouldPersistHistory(config.persist_locally()),
       mUseV2SoftMemoryCalculation(config.statsd_config_options().use_v2_soft_memory_limit()),
-      mOmitSystemUidsInUidMap(config.statsd_config_options().omit_system_uids_in_uidmap()) {
+      mOmitSystemUidsInUidMap(config.statsd_config_options().omit_system_uids_in_uidmap()),
+      mOmitUnusedUidsInUidMap(config.statsd_config_options().omit_unused_uids_in_uidmap()),
+      mAllowlistedUidMapPackages(
+              set<string>(config.statsd_config_options().uidmap_package_allowlist().begin(),
+                          config.statsd_config_options().uidmap_package_allowlist().end())) {
     if (!isAtLeastU() && config.has_restricted_metrics_delegate_package_name()) {
         mInvalidConfigReason =
                 InvalidConfigReason(INVALID_CONFIG_REASON_RESTRICTED_METRIC_NOT_ENABLED);
@@ -200,6 +204,10 @@ bool MetricsManager::updateConfig(const StatsdConfig& config, const int64_t time
     mPackageCertificateHashSizeBytes = config.package_certificate_hash_size_bytes();
     mUseV2SoftMemoryCalculation = config.statsd_config_options().use_v2_soft_memory_limit();
     mOmitSystemUidsInUidMap = config.statsd_config_options().omit_system_uids_in_uidmap();
+    mOmitUnusedUidsInUidMap = config.statsd_config_options().omit_unused_uids_in_uidmap();
+    mAllowlistedUidMapPackages =
+            set<string>(config.statsd_config_options().uidmap_package_allowlist().begin(),
+                        config.statsd_config_options().uidmap_package_allowlist().end());
 
     // Store the sub-configs used.
     mAnnotations.clear();
@@ -479,16 +487,14 @@ void MetricsManager::dropData(const int64_t dropTimeNs) {
 void MetricsManager::onDumpReport(const int64_t dumpTimeStampNs, const int64_t wallClockNs,
                                   const bool include_current_partial_bucket, const bool erase_data,
                                   const DumpLatency dumpLatency, std::set<string>* str_set,
-                                  ProtoOutputStream* protoOutput) {
+                                  std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput) {
     if (hasRestrictedMetricsDelegate()) {
         // TODO(b/268150038): report error to statsdstats
         VLOG("Unexpected call to onDumpReport in restricted metricsmanager.");
         return;
     }
 
-    vector<std::pair<int32_t, int32_t>> queueOverflowStats =
-            StatsdStats::getInstance().getQueueOverflowAtomsStats();
-    processQueueOverflowStats(queueOverflowStats);
+    processQueueOverflowStats();
 
     VLOG("=========================Metric Reports Start==========================");
     // one StatsLogReport per MetricProduer
@@ -498,10 +504,10 @@ void MetricsManager::onDumpReport(const int64_t dumpTimeStampNs, const int64_t w
                                                 FIELD_ID_METRICS);
             if (mHashStringsInReport) {
                 producer->onDumpReport(dumpTimeStampNs, include_current_partial_bucket, erase_data,
-                                       dumpLatency, str_set, protoOutput);
+                                       dumpLatency, str_set, usedUids, protoOutput);
             } else {
                 producer->onDumpReport(dumpTimeStampNs, include_current_partial_bucket, erase_data,
-                                       dumpLatency, nullptr, protoOutput);
+                                       dumpLatency, nullptr, usedUids, protoOutput);
             }
             protoOutput->end(token);
         } else {
@@ -727,7 +733,8 @@ void MetricsManager::onLogEvent(const LogEvent& event) {
 
 void MetricsManager::onLogEventLost(const SocketLossInfo& socketLossInfo) {
     // socketLossInfo stores atomId per UID - to eliminate duplicates using set
-    const set<int> uniqueLostAtomIds(socketLossInfo.atomIds.begin(), socketLossInfo.atomIds.end());
+    const unordered_set<int> uniqueLostAtomIds(socketLossInfo.atomIds.begin(),
+                                               socketLossInfo.atomIds.end());
 
     // pass lost atom id to all relevant metrics
     for (const auto lostAtomId : uniqueLostAtomIds) {
@@ -957,13 +964,13 @@ void MetricsManager::addAllAtomIds(LogEventFilter::AtomIdSet& allIds) const {
     }
 }
 
-void MetricsManager::processQueueOverflowStats(
-        const StatsdStats::QueueOverflowAtomsStats& overflowStats) {
-    assert((overflowStats.size() < mQueueOverflowAtomsStats.size()) &&
+void MetricsManager::processQueueOverflowStats() {
+    auto queueOverflowStats = StatsdStats::getInstance().getQueueOverflowAtomsStats();
+    assert((queueOverflowStats.size() < mQueueOverflowAtomsStats.size()) &&
            "StatsdStats reset unexpected");
 
-    for (const auto [atomId, count] : overflowStats) {
-        // are there new atoms dropped due to queue overflow since previous dumpReport request
+    for (const auto [atomId, count] : queueOverflowStats) {
+        // are there new atoms dropped due to queue overflow since previous request
         auto droppedAtomStatsIt = mQueueOverflowAtomsStats.find(atomId);
         if (droppedAtomStatsIt != mQueueOverflowAtomsStats.end() &&
             droppedAtomStatsIt->second == count) {
@@ -971,18 +978,9 @@ void MetricsManager::processQueueOverflowStats(
             continue;
         }
 
-        if (notifyMetricsAboutLostAtom(atomId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW) > 0) {
-            // there is at least one metric interested in the lost atom, keep track of it
-            // to update it again only if there will be more dropped atoms
-            mQueueOverflowAtomsStats[atomId] = count;
-        } else {
-            // there are no metrics interested in dropped atom
-            if (droppedAtomStatsIt != mQueueOverflowAtomsStats.end()) {
-                // but there were metrics which are interested in the atom and now they are removed
-                mQueueOverflowAtomsStats.erase(droppedAtomStatsIt);
-            }
-        }
+        notifyMetricsAboutLostAtom(atomId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW);
     }
+    mQueueOverflowAtomsStats = std::move(queueOverflowStats);
 }
 
 }  // namespace statsd
diff --git a/statsd/src/metrics/MetricsManager.h b/statsd/src/metrics/MetricsManager.h
index bbad5670..56a83ca4 100644
--- a/statsd/src/metrics/MetricsManager.h
+++ b/statsd/src/metrics/MetricsManager.h
@@ -91,6 +91,16 @@ public:
 
     void dumpStates(int out, bool verbose);
 
+    // Does not set the used uids.
+    inline UidMapOptions getUidMapOptions() const {
+        return {.includeVersionStrings = mVersionStringsInReport,
+                .includeInstaller = mInstallerInReport,
+                .truncatedCertificateHashSize = mPackageCertificateHashSizeBytes,
+                .omitSystemUids = mOmitSystemUidsInUidMap,
+                .omitUnusedUids = mOmitUnusedUidsInUidMap,
+                .allowlistedPackages = mAllowlistedUidMapPackages};
+    }
+
     inline bool isInTtl(const int64_t timestampNs) const {
         return mTtlNs <= 0 || timestampNs < mTtlEndNs;
     };
@@ -99,18 +109,6 @@ public:
         return mHashStringsInReport;
     };
 
-    inline bool versionStringsInReport() const {
-        return mVersionStringsInReport;
-    };
-
-    inline bool installerInReport() const {
-        return mInstallerInReport;
-    };
-
-    inline uint8_t packageCertificateHashSizeBytes() const {
-        return mPackageCertificateHashSizeBytes;
-    }
-
     void refreshTtl(const int64_t currentTimestampNs) {
         if (mTtlNs > 0) {
             mTtlEndNs = currentTimestampNs + mTtlNs;
@@ -136,6 +134,7 @@ public:
     virtual void onDumpReport(const int64_t dumpTimeNs, int64_t wallClockNs,
                               const bool include_current_partial_bucket, const bool erase_data,
                               const DumpLatency dumpLatency, std::set<string>* str_set,
+                              std::set<int32_t>& usedUids,
                               android::util::ProtoOutputStream* protoOutput);
 
     // Computes the total byte size of all metrics managed by a single config source.
@@ -193,10 +192,6 @@ public:
         return mTriggerGetDataBytes;
     }
 
-    inline bool omitSystemUidsInUidMap() const {
-        return mOmitSystemUidsInUidMap;
-    }
-
 private:
     // For test only.
     inline int64_t getTtlEndNs() const {
@@ -257,6 +252,8 @@ private:
     bool mUseV2SoftMemoryCalculation;
 
     bool mOmitSystemUidsInUidMap;
+    bool mOmitUnusedUidsInUidMap;
+    set<string> mAllowlistedUidMapPackages;
 
     // All event tags that are interesting to config metrics matchers.
     std::unordered_map<int, std::vector<int>> mTagIdsToMatchersMap;
@@ -385,15 +382,14 @@ private:
     int notifyMetricsAboutLostAtom(int32_t lostAtomId, DataCorruptedReason reason);
 
     /**
-     * @brief Updates MetricProducers with DataCorruptionReason due to queue overflow atom loss
-     *        Notifies metrics only when new queue overflow happens since previous dumpReport
-     *        Perform QueueOverflowAtomsStats tracking via managing stats local copy
-     *        The assumption is that QueueOverflowAtomsStats collected over time, and that none of
-     *        atom id counters have disappeared (which is StatsdStats logic until it explicitly
-     *        reset, which should not be happen during statsd service lifetime)
-     * @param overflowStats
+     * Updates MetricProducers with DataCorruptionReason due to queue overflow atom loss
+     * Notifies metrics only when new queue overflow happens since previous request
+     * Performs QueueOverflowAtomsStatsMap tracking via managing stats local copy
+     * The assumption is that QueueOverflowAtomsStatsMap collected over time, and that none
+     * of atom id counters have disappeared (which is StatsdStats logic until it explicitly reset,
+     * which should not be happen during statsd service lifetime)
      */
-    void processQueueOverflowStats(const StatsdStats::QueueOverflowAtomsStats& overflowStats);
+    void processQueueOverflowStats();
 
     // The memory limit in bytes for storing metrics
     size_t mMaxMetricsBytes;
@@ -405,9 +401,9 @@ private:
     // this map is not cleared during onDumpReport to preserve tracking information and avoid
     // repeated metric notification about past queue overflow lost event
     // This map represent local copy of StatsdStats::mPushedAtomDropsStats with relevant atoms ids
-    typedef std::unordered_map<int32_t, int32_t> QueueOverflowAtomsStatsMap;
-    QueueOverflowAtomsStatsMap mQueueOverflowAtomsStats;
+    StatsdStats::QueueOverflowAtomsStatsMap mQueueOverflowAtomsStats;
 
+    friend class SocketLossInfoTest;
     FRIEND_TEST(MetricConditionLinkE2eTest, TestMultiplePredicatesAndLinks);
     FRIEND_TEST(AttributionE2eTest, TestAttributionMatchAndSliceByFirstUid);
     FRIEND_TEST(AttributionE2eTest, TestAttributionMatchAndSliceByChain);
@@ -484,11 +480,10 @@ private:
     FRIEND_TEST(ValueMetricE2eTest, TestInitWithMultipleAggTypes);
     FRIEND_TEST(ValueMetricE2eTest, TestInitWithDefaultAggType);
 
-    FRIEND_TEST(SocketLossInfoTest, PropagationTest);
-
     FRIEND_TEST(DataCorruptionQueueOverflowTest, TestNotifyOnlyInterestedMetrics);
     FRIEND_TEST(DataCorruptionQueueOverflowTest, TestNotifyInterestedMetricsWithNewLoss);
     FRIEND_TEST(DataCorruptionQueueOverflowTest, TestDoNotNotifyInterestedMetricsIfNoUpdate);
+    FRIEND_TEST(DataCorruptionQueueOverflowTest, TestDoNotNotifyNewInterestedMetricsIfNoUpdate);
 };
 
 }  // namespace statsd
diff --git a/statsd/src/metrics/NumericValue.cpp b/statsd/src/metrics/NumericValue.cpp
new file mode 100644
index 00000000..58d987d3
--- /dev/null
+++ b/statsd/src/metrics/NumericValue.cpp
@@ -0,0 +1,222 @@
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
+#include "NumericValue.h"
+
+#include <cmath>
+#include <functional>
+#include <limits>
+#include <string>
+#include <utility>
+#include <variant>
+
+#include "HistogramValue.h"
+
+namespace android {
+namespace os {
+namespace statsd {
+namespace {
+
+// std::variant uses the visitor pattern to interact with stored types via std::visit, which applies
+// a Callable (a function object) that accepts all combination of types from the variant. Here, the
+// Callables are implemented as structs with operator() overloads for each combination of types from
+// the variant in NumericValue.
+
+// Templated visitor for binary operations involving two NumericValues
+// Used for implementing operator+= and operator-= for NumericValue.
+template <typename BinaryOp>
+class BinaryOperationVisitor {
+public:
+    constexpr explicit BinaryOperationVisitor(BinaryOp&& op) : mOp(std::forward<BinaryOp>(op)) {
+    }
+
+    void operator()(std::monostate, std::monostate) const {
+    }
+
+    template <typename V>
+    void operator()(V& lhs, const V& rhs) const {
+        lhs = mOp(lhs, rhs);
+    }
+
+    void operator()(auto, auto) const {
+    }
+
+private:
+    const BinaryOp mOp;
+};
+constexpr BinaryOperationVisitor subtract(std::minus{});
+constexpr BinaryOperationVisitor add(std::plus{});
+
+// Visitor for printing type information currently stored in the NumericValue variant.
+struct ToStringVisitor {
+    std::string operator()(int64_t value) const {
+        return std::to_string(value) + "[L]";
+    }
+
+    std::string operator()(double value) const {
+        return std::to_string(value) + "[D]";
+    }
+
+    std::string operator()(const HistogramValue& value) const {
+        return value.toString();
+    }
+
+    std::string operator()(auto) const {
+        return "[UNKNOWN]";
+    }
+};
+
+// Visitor for determining whether the NumericValue variant stores a 0.
+struct IsZeroVisitor {
+    bool operator()(int64_t value) const {
+        return value == 0;
+    }
+
+    bool operator()(double value) const {
+        return fabs(value) <= std::numeric_limits<double>::epsilon();
+    }
+
+    bool operator()(const HistogramValue& value) const {
+        return value.isEmpty();
+    }
+
+    // "Empty" variant does not store 0.
+    bool operator()(std::monostate) const {
+        return false;
+    }
+};
+
+struct GetSizeVisitor {
+    size_t operator()(const HistogramValue& value) const {
+        return value.getSize();
+    }
+
+    size_t operator()(const auto& value) const {
+        return sizeof(value);
+    }
+};
+
+}  // anonymous namespace
+
+std::string NumericValue::toString() const {
+    return std::visit(ToStringVisitor{}, mData);
+}
+
+void NumericValue::reset() {
+    mData.emplace<std::monostate>(std::monostate{});
+}
+
+template <typename V>
+bool NumericValue::is() const {
+    return std::holds_alternative<V>(mData);
+}
+template bool NumericValue::is<int64_t>() const;
+template bool NumericValue::is<double>() const;
+template bool NumericValue::is<HistogramValue>() const;
+
+bool NumericValue::hasValue() const {
+    return !is<std::monostate>();
+}
+
+template <typename V>
+V& NumericValue::getValue() {
+    return std::get<V>(mData);
+}
+template int64_t& NumericValue::getValue<int64_t>();
+template double& NumericValue::getValue<double>();
+template HistogramValue& NumericValue::getValue<HistogramValue>();
+
+template <typename V>
+const V& NumericValue::getValue() const {
+    return std::get<V>(mData);
+}
+template const int64_t& NumericValue::getValue<int64_t>() const;
+template const double& NumericValue::getValue<double>() const;
+template const HistogramValue& NumericValue::getValue<HistogramValue>() const;
+
+template <typename V>
+V& NumericValue::getValueOrDefault(V& defaultValue) {
+    return is<V>() ? getValue<V>() : defaultValue;
+}
+template int64_t& NumericValue::getValueOrDefault<int64_t>(int64_t& defaultValue);
+template double& NumericValue::getValueOrDefault<double>(double& defaultValue);
+template HistogramValue& NumericValue::getValueOrDefault<HistogramValue>(
+        HistogramValue& defaultValue);
+
+template <typename V>
+const V& NumericValue::getValueOrDefault(const V& defaultValue) const {
+    return is<V>() ? getValue<V>() : defaultValue;
+}
+template const int64_t& NumericValue::getValueOrDefault<int64_t>(const int64_t& defaultValue) const;
+template const double& NumericValue::getValueOrDefault<double>(const double& defaultValue) const;
+template const HistogramValue& NumericValue::getValueOrDefault<HistogramValue>(
+        const HistogramValue& defaultValue) const;
+
+bool NumericValue::isZero() const {
+    return std::visit(IsZeroVisitor{}, mData);
+}
+
+size_t NumericValue::getSize() const {
+    return std::visit(GetSizeVisitor{}, mData);
+}
+
+NumericValue& NumericValue::operator+=(const NumericValue& rhs) {
+    std::visit(add, mData, rhs.mData);
+    return *this;
+}
+
+NumericValue operator+(NumericValue lhs, const NumericValue& rhs) {
+    lhs += rhs;
+    return lhs;
+}
+
+NumericValue& NumericValue::operator-=(const NumericValue& rhs) {
+    std::visit(subtract, mData, rhs.mData);
+    return *this;
+}
+
+NumericValue operator-(NumericValue lhs, const NumericValue& rhs) {
+    lhs -= rhs;
+    return lhs;
+}
+
+bool operator==(const NumericValue& lhs, const NumericValue& rhs) {
+    return lhs.mData == rhs.mData;
+}
+
+bool operator!=(const NumericValue& lhs, const NumericValue& rhs) {
+    return !(lhs == rhs);
+}
+
+bool operator<(const NumericValue& lhs, const NumericValue& rhs) {
+    return lhs.mData < rhs.mData;
+}
+
+bool operator>(const NumericValue& lhs, const NumericValue& rhs) {
+    return rhs < lhs;
+}
+
+bool operator<=(const NumericValue& lhs, const NumericValue& rhs) {
+    return !(lhs > rhs);
+}
+
+bool operator>=(const NumericValue& lhs, const NumericValue& rhs) {
+    return !(lhs < rhs);
+}
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/metrics/NumericValue.h b/statsd/src/metrics/NumericValue.h
new file mode 100644
index 00000000..69b5a2f0
--- /dev/null
+++ b/statsd/src/metrics/NumericValue.h
@@ -0,0 +1,114 @@
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
+#include <string>
+#include <utility>
+#include <variant>
+
+#include "HistogramValue.h"
+
+#pragma once
+
+namespace android {
+namespace os {
+namespace statsd {
+
+// Used to store aggregations in NumericValueMetricProducer for ValueMetric.
+// The aggregations are either int64 or double.
+class NumericValue {
+public:
+    NumericValue() noexcept = default;
+
+    // Copy constructor
+    constexpr NumericValue(const NumericValue& other) = default;
+    constexpr NumericValue(NumericValue& other) : NumericValue(std::as_const(other)) {
+    }
+
+    // Copy constructor for contained types
+    template <typename V>
+    constexpr NumericValue(const V& value) : mData(std::in_place_type<V>, value) {
+    }
+
+    // Move constructor
+    constexpr NumericValue(NumericValue&& other) noexcept = default;
+
+    // Move constructor for contained types
+    template <typename V>
+    constexpr NumericValue(V&& value) noexcept
+        : mData(std::in_place_type<V>, std::forward<V>(value)) {
+    }
+
+    // Copy assignment
+    NumericValue& operator=(const NumericValue& rhs) = default;
+
+    // Move assignment
+    NumericValue& operator=(NumericValue&& rhs) noexcept = default;
+
+    ~NumericValue() = default;
+
+    std::string toString() const;
+
+    void reset();
+
+    template <typename V>
+    bool is() const;
+
+    bool hasValue() const;
+
+    template <typename V>
+    V& getValue();
+
+    template <typename V>
+    const V& getValue() const;
+
+    template <typename V>
+    V& getValueOrDefault(V& defaultValue);
+
+    template <typename V>
+    const V& getValueOrDefault(const V& defaultValue) const;
+
+    bool isZero() const;
+
+    size_t getSize() const;
+
+    NumericValue& operator+=(const NumericValue& rhs);
+
+    friend NumericValue operator+(NumericValue lhs, const NumericValue& rhs);
+
+    NumericValue& operator-=(const NumericValue& rhs);
+
+    friend NumericValue operator-(NumericValue lhs, const NumericValue& rhs);
+
+    friend bool operator==(const NumericValue& lhs, const NumericValue& rhs);
+
+    friend bool operator!=(const NumericValue& lhs, const NumericValue& rhs);
+
+    friend bool operator<(const NumericValue& lhs, const NumericValue& rhs);
+
+    friend bool operator>(const NumericValue& lhs, const NumericValue& rhs);
+
+    friend bool operator<=(const NumericValue& lhs, const NumericValue& rhs);
+
+    friend bool operator>=(const NumericValue& lhs, const NumericValue& rhs);
+
+private:
+    // std::monostate represents "empty" or default value.
+    std::variant<std::monostate, int64_t, double, HistogramValue> mData;
+};
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/metrics/NumericValueMetricProducer.cpp b/statsd/src/metrics/NumericValueMetricProducer.cpp
index 524ba898..c12cf69b 100644
--- a/statsd/src/metrics/NumericValueMetricProducer.cpp
+++ b/statsd/src/metrics/NumericValueMetricProducer.cpp
@@ -19,11 +19,14 @@
 
 #include "NumericValueMetricProducer.h"
 
-#include <limits.h>
 #include <stdlib.h>
 
+#include <algorithm>
+
 #include "FieldValue.h"
 #include "guardrail/StatsdStats.h"
+#include "metrics/HistogramValue.h"
+#include "metrics/NumericValue.h"
 #include "metrics/parsing_utils/metrics_manager_util.h"
 #include "stats_log_util.h"
 
@@ -35,7 +38,6 @@ using android::util::FIELD_TYPE_INT64;
 using android::util::FIELD_TYPE_MESSAGE;
 using android::util::FIELD_TYPE_STRING;
 using android::util::ProtoOutputStream;
-using std::optional;
 using std::shared_ptr;
 using std::string;
 using std::unordered_map;
@@ -44,12 +46,14 @@ namespace android {
 namespace os {
 namespace statsd {
 
+namespace {  // anonymous namespace
 // for StatsLogReport
 const int FIELD_ID_VALUE_METRICS = 7;
 // for ValueBucketInfo
 const int FIELD_ID_VALUE_INDEX = 1;
 const int FIELD_ID_VALUE_LONG = 2;
 const int FIELD_ID_VALUE_DOUBLE = 3;
+const int FIELD_ID_VALUE_HISTOGRAM = 5;
 const int FIELD_ID_VALUE_SAMPLESIZE = 4;
 const int FIELD_ID_VALUES = 9;
 const int FIELD_ID_BUCKET_NUM = 4;
@@ -58,8 +62,14 @@ const int FIELD_ID_END_BUCKET_ELAPSED_MILLIS = 6;
 const int FIELD_ID_CONDITION_TRUE_NS = 10;
 const int FIELD_ID_CONDITION_CORRECTION_NS = 11;
 
-const Value ZERO_LONG((int64_t)0);
-const Value ZERO_DOUBLE(0.0);
+const NumericValue ZERO_LONG((int64_t)0);
+const NumericValue ZERO_DOUBLE((double)0);
+
+double toDouble(const NumericValue& value) {
+    return value.is<int64_t>() ? value.getValue<int64_t>() : value.getValueOrDefault<double>(0);
+}
+
+}  // anonymous namespace
 
 // ValueMetric has a minimum bucket size of 10min so that we don't pull too frequently
 NumericValueMetricProducer::NumericValueMetricProducer(
@@ -84,7 +94,8 @@ NumericValueMetricProducer::NumericValueMetricProducer(
       mHasGlobalBase(false),
       mMaxPullDelayNs(metric.has_max_pull_delay_sec() ? metric.max_pull_delay_sec() * NS_PER_SEC
                                                       : StatsdStats::kPullMaxDelayNs),
-      mDedupedFieldMatchers(dedupFieldMatchers(whatOptions.fieldMatchers)) {
+      mDedupedFieldMatchers(dedupFieldMatchers(whatOptions.fieldMatchers)),
+      mBinStartsList(whatOptions.binStartsList) {
     // TODO(b/186677791): Use initializer list to initialize mUploadThreshold.
     if (metric.has_threshold()) {
         mUploadThreshold = metric.threshold();
@@ -111,7 +122,7 @@ void NumericValueMetricProducer::invalidateCurrentBucket(const int64_t dropTimeN
 
 void NumericValueMetricProducer::resetBase() {
     for (auto& [_, dimInfo] : mDimInfos) {
-        for (optional<Value>& base : dimInfo.dimExtras) {
+        for (NumericValue& base : dimInfo.dimExtras) {
             base.reset();
         }
     }
@@ -119,7 +130,7 @@ void NumericValueMetricProducer::resetBase() {
 }
 
 void NumericValueMetricProducer::writePastBucketAggregateToProto(
-        const int aggIndex, const Value& value, const int sampleSize,
+        const int aggIndex, const NumericValue& value, const int sampleSize,
         ProtoOutputStream* const protoOutput) const {
     uint64_t valueToken =
             protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | FIELD_ID_VALUES);
@@ -127,14 +138,23 @@ void NumericValueMetricProducer::writePastBucketAggregateToProto(
     if (mIncludeSampleSize) {
         protoOutput->write(FIELD_TYPE_INT32 | FIELD_ID_VALUE_SAMPLESIZE, sampleSize);
     }
-    if (value.getType() == LONG) {
-        protoOutput->write(FIELD_TYPE_INT64 | FIELD_ID_VALUE_LONG, (long long)value.long_value);
-        VLOG("\t\t value %d: %lld", aggIndex, (long long)value.long_value);
-    } else if (value.getType() == DOUBLE) {
-        protoOutput->write(FIELD_TYPE_DOUBLE | FIELD_ID_VALUE_DOUBLE, value.double_value);
-        VLOG("\t\t value %d: %.2f", aggIndex, value.double_value);
+    if (value.is<int64_t>()) {
+        const int64_t val = value.getValue<int64_t>();
+        protoOutput->write(FIELD_TYPE_INT64 | FIELD_ID_VALUE_LONG, (long long)val);
+        VLOG("\t\t value %d: %lld", aggIndex, (long long)val);
+    } else if (value.is<double>()) {
+        const double val = value.getValue<double>();
+        protoOutput->write(FIELD_TYPE_DOUBLE | FIELD_ID_VALUE_DOUBLE, val);
+        VLOG("\t\t value %d: %.2f", aggIndex, val);
+    } else if (value.is<HistogramValue>()) {
+        const HistogramValue& val = value.getValue<HistogramValue>();
+        const uint64_t histToken =
+                protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_VALUE_HISTOGRAM);
+        val.toProto(*protoOutput);
+        protoOutput->end(histToken);
+        VLOG("\t\t value %d: %s", aggIndex, val.toString().c_str());
     } else {
-        VLOG("Wrong value type for ValueMetric output: %d", value.getType());
+        VLOG("Wrong value type for ValueMetric output");
     }
     protoOutput->end(valueToken);
 }
@@ -369,36 +389,58 @@ bool NumericValueMetricProducer::hitFullBucketGuardRailLocked(const MetricDimens
     return false;
 }
 
-bool getDoubleOrLong(const LogEvent& event, const Matcher& matcher, Value& ret) {
-    for (const FieldValue& value : event.getValues()) {
-        if (value.mField.matches(matcher)) {
-            switch (value.mValue.type) {
-                case INT:
-                    ret.setLong(value.mValue.int_value);
-                    break;
-                case LONG:
-                    ret.setLong(value.mValue.long_value);
-                    break;
-                case FLOAT:
-                    ret.setDouble(value.mValue.float_value);
-                    break;
-                case DOUBLE:
-                    ret.setDouble(value.mValue.double_value);
-                    break;
-                default:
-                    return false;
-                    break;
+namespace {
+NumericValue getAggregationInputValue(const LogEvent& event, const Matcher& matcher) {
+    if (matcher.hasAllPositionMatcher()) {  // client-aggregated histogram
+        vector<int> binCounts;
+        for (const FieldValue& value : event.getValues()) {
+            if (!value.mField.matches(matcher)) {
+                continue;
+            }
+            if (value.mValue.getType() == INT) {
+                binCounts.push_back(value.mValue.int_value);
+            } else {
+                return NumericValue{};
             }
-            return true;
         }
+        return NumericValue(HistogramValue(binCounts));
     }
-    return false;
+
+    for (const FieldValue& value : event.getValues()) {
+        if (!value.mField.matches(matcher)) {
+            continue;
+        }
+        switch (value.mValue.type) {
+            case INT:
+                return NumericValue((int64_t)value.mValue.int_value);
+            case LONG:
+                return NumericValue((int64_t)value.mValue.long_value);
+            case FLOAT:
+                return NumericValue((double)value.mValue.float_value);
+            case DOUBLE:
+                return NumericValue((double)value.mValue.double_value);
+            default:
+                return NumericValue{};
+        }
+    }
+    return NumericValue{};
 }
 
+void addValueToHistogram(const NumericValue& value, const optional<const BinStarts>& binStarts,
+                         HistogramValue& histValue) {
+    if (binStarts == nullopt) {
+        ALOGE("Missing bin configuration!");
+        return;
+    }
+    histValue.addValue(static_cast<float>(toDouble(value)), *binStarts);
+}
+
+}  // anonymous namespace
+
 bool NumericValueMetricProducer::aggregateFields(const int64_t eventTimeNs,
                                                  const MetricDimensionKey& eventKey,
                                                  const LogEvent& event, vector<Interval>& intervals,
-                                                 ValueBases& bases) {
+                                                 Bases& bases) {
     if (bases.size() < mFieldMatchers.size()) {
         VLOG("Resizing number of bases to %zu", mFieldMatchers.size());
         bases.resize(mFieldMatchers.size());
@@ -416,20 +458,35 @@ bool NumericValueMetricProducer::aggregateFields(const int64_t eventTimeNs,
         const Matcher& matcher = mFieldMatchers[i];
         Interval& interval = intervals[i];
         interval.aggIndex = i;
-        optional<Value>& base = bases[i];
-        Value value;
-        if (!getDoubleOrLong(event, matcher, value)) {
+        NumericValue& base = bases[i];
+        NumericValue value = getAggregationInputValue(event, matcher);
+        if (!value.hasValue()) {
             VLOG("Failed to get value %zu from event %s", i, event.ToString().c_str());
             StatsdStats::getInstance().noteBadValueType(mMetricId);
             return seenNewData;
         }
-        seenNewData = true;
+
+        if (value.is<HistogramValue>() && !value.getValue<HistogramValue>().isValid()) {
+            ALOGE("Invalid histogram at %zu from event %s", i, event.ToString().c_str());
+            StatsdStats::getInstance().noteBadValueType(mMetricId);
+            if (mUseDiff) {
+                base.reset();
+            }
+            continue;
+        }
+
         if (mUseDiff) {
-            if (!base.has_value()) {
+            if (!base.hasValue()) {
                 if (mHasGlobalBase && mUseZeroDefaultBase) {
                     // The bucket has global base. This key does not.
                     // Optionally use zero as base.
-                    base = (value.type == LONG ? ZERO_LONG : ZERO_DOUBLE);
+                    if (value.is<int64_t>()) {
+                        base = ZERO_LONG;
+                    } else if (value.is<double>()) {
+                        base = ZERO_DOUBLE;
+                    } else if (value.is<HistogramValue>()) {
+                        base = HistogramValue();
+                    }
                 } else {
                     // no base. just update base and return.
                     base = value;
@@ -437,52 +494,73 @@ bool NumericValueMetricProducer::aggregateFields(const int64_t eventTimeNs,
                     // If we're missing a base, do not use anomaly detection on incomplete data
                     useAnomalyDetection = false;
 
+                    seenNewData = true;
                     // Continue (instead of return) here in order to set base value for other bases
                     continue;
                 }
             }
-            Value diff;
-            switch (mValueDirection) {
-                case ValueMetric::INCREASING:
-                    if (value >= base.value()) {
-                        diff = value - base.value();
-                    } else if (mUseAbsoluteValueOnReset) {
-                        diff = value;
-                    } else {
-                        VLOG("Unexpected decreasing value");
-                        StatsdStats::getInstance().notePullDataError(mPullAtomId);
-                        base = value;
-                        // If we've got bad data, do not use anomaly detection
-                        useAnomalyDetection = false;
-                        continue;
-                    }
-                    break;
-                case ValueMetric::DECREASING:
-                    if (base.value() >= value) {
-                        diff = base.value() - value;
-                    } else if (mUseAbsoluteValueOnReset) {
-                        diff = value;
-                    } else {
-                        VLOG("Unexpected increasing value");
-                        StatsdStats::getInstance().notePullDataError(mPullAtomId);
-                        base = value;
-                        // If we've got bad data, do not use anomaly detection
-                        useAnomalyDetection = false;
-                        continue;
-                    }
-                    break;
-                case ValueMetric::ANY:
-                    diff = value - base.value();
-                    break;
-                default:
-                    break;
+            NumericValue diff{};
+            if (value.is<HistogramValue>()) {
+                diff = value - base;
+                seenNewData = true;
+                base = value;
+                if (diff == HistogramValue::ERROR_BINS_MISMATCH) {
+                    ALOGE("Value %zu from event %s does not have enough bins", i,
+                          event.ToString().c_str());
+                    StatsdStats::getInstance().noteBadValueType(mMetricId);
+                    continue;
+                }
+                if (diff == HistogramValue::ERROR_BIN_COUNT_TOO_HIGH) {
+                    ALOGE("Value %zu from event %s has decreasing bin count", i,
+                          event.ToString().c_str());
+                    StatsdStats::getInstance().noteBadValueType(mMetricId);
+                    continue;
+                }
+            } else {
+                seenNewData = true;
+                switch (mValueDirection) {
+                    case ValueMetric::INCREASING:
+                        if (value >= base) {
+                            diff = value - base;
+                        } else if (mUseAbsoluteValueOnReset) {
+                            diff = value;
+                        } else {
+                            VLOG("Unexpected decreasing value");
+                            StatsdStats::getInstance().notePullDataError(mPullAtomId);
+                            base = value;
+                            // If we've got bad data, do not use anomaly detection
+                            useAnomalyDetection = false;
+                            continue;
+                        }
+                        break;
+                    case ValueMetric::DECREASING:
+                        if (base >= value) {
+                            diff = base - value;
+                        } else if (mUseAbsoluteValueOnReset) {
+                            diff = value;
+                        } else {
+                            VLOG("Unexpected increasing value");
+                            StatsdStats::getInstance().notePullDataError(mPullAtomId);
+                            base = value;
+                            // If we've got bad data, do not use anomaly detection
+                            useAnomalyDetection = false;
+                            continue;
+                        }
+                        break;
+                    case ValueMetric::ANY:
+                        diff = value - base;
+                        break;
+                    default:
+                        break;
+                }
+                base = value;
             }
-            base = value;
             value = diff;
         }
 
+        const ValueMetric::AggregationType aggType = getAggregationTypeLocked(i);
         if (interval.hasValue()) {
-            switch (getAggregationTypeLocked(i)) {
+            switch (aggType) {
                 case ValueMetric::SUM:
                     // for AVG, we add up and take average when flushing the bucket
                 case ValueMetric::AVG:
@@ -494,12 +572,35 @@ bool NumericValueMetricProducer::aggregateFields(const int64_t eventTimeNs,
                 case ValueMetric::MAX:
                     interval.aggregate = max(value, interval.aggregate);
                     break;
+                case ValueMetric::HISTOGRAM:
+                    if (value.is<HistogramValue>()) {
+                        // client-aggregated histogram: add the corresponding bin counts.
+                        NumericValue sum = interval.aggregate + value;
+                        if (sum == HistogramValue::ERROR_BINS_MISMATCH) {
+                            ALOGE("Value %zu from event %s has too many bins", i,
+                                  event.ToString().c_str());
+                            StatsdStats::getInstance().noteBadValueType(mMetricId);
+                            continue;
+                        }
+                        interval.aggregate = sum;
+                    } else {
+                        // statsd-aggregated histogram: add the raw value to histogram.
+                        addValueToHistogram(value, getBinStarts(i),
+                                            interval.aggregate.getValue<HistogramValue>());
+                    }
+                    break;
                 default:
                     break;
             }
+        } else if (aggType == ValueMetric::HISTOGRAM && !value.is<HistogramValue>()) {
+            // statsd-aggregated histogram: add raw value to histogram.
+            interval.aggregate = HistogramValue();
+            addValueToHistogram(value, getBinStarts(i),
+                                interval.aggregate.getValue<HistogramValue>());
         } else {
             interval.aggregate = value;
         }
+        seenNewData = true;
         interval.sampleSize += 1;
     }
 
@@ -507,7 +608,7 @@ bool NumericValueMetricProducer::aggregateFields(const int64_t eventTimeNs,
     // to MULTIPLE_BUCKETS_SKIPPED.
     if (useAnomalyDetection && !multipleBucketsSkipped(calcBucketsForwardCount(eventTimeNs))) {
         // TODO: propgate proper values down stream when anomaly support doubles
-        long wholeBucketVal = intervals[0].aggregate.long_value;
+        long wholeBucketVal = intervals[0].aggregate.getValueOrDefault<int64_t>(0);
         auto prev = mCurrentFullBucket.find(eventKey);
         if (prev != mCurrentFullBucket.end()) {
             wholeBucketVal += prev->second;
@@ -520,9 +621,9 @@ bool NumericValueMetricProducer::aggregateFields(const int64_t eventTimeNs,
     return seenNewData;
 }
 
-PastBucket<Value> NumericValueMetricProducer::buildPartialBucket(int64_t bucketEndTimeNs,
-                                                                 vector<Interval>& intervals) {
-    PastBucket<Value> bucket;
+PastBucket<NumericValue> NumericValueMetricProducer::buildPartialBucket(
+        int64_t bucketEndTimeNs, vector<Interval>& intervals) {
+    PastBucket<NumericValue> bucket;
     bucket.mBucketStartNs = mCurrentBucketStartTimeNs;
     bucket.mBucketEndNs = bucketEndTimeNs;
 
@@ -589,7 +690,8 @@ void NumericValueMetricProducer::appendToFullBucket(const bool isFullBucketReach
                 // TODO: fix this when anomaly can accept double values
                 auto& interval = currentBucket.intervals[0];
                 if (interval.hasValue()) {
-                    mCurrentFullBucket[metricDimensionKey] += interval.aggregate.long_value;
+                    mCurrentFullBucket[metricDimensionKey] +=
+                            interval.aggregate.getValueOrDefault<int64_t>(0);
                 }
             }
             for (const auto& [metricDimensionKey, value] : mCurrentFullBucket) {
@@ -608,9 +710,9 @@ void NumericValueMetricProducer::appendToFullBucket(const bool isFullBucketReach
                         // TODO: fix this when anomaly can accept double values
                         auto& interval = currentBucket.intervals[0];
                         if (interval.hasValue()) {
-                            tracker->addPastBucket(metricDimensionKey,
-                                                   interval.aggregate.long_value,
-                                                   mCurrentBucketNum);
+                            const int64_t longVal =
+                                    interval.aggregate.getValueOrDefault<int64_t>(0);
+                            tracker->addPastBucket(metricDimensionKey, longVal, mCurrentBucketNum);
                         }
                     }
                 }
@@ -623,15 +725,21 @@ void NumericValueMetricProducer::appendToFullBucket(const bool isFullBucketReach
                 // TODO: fix this when anomaly can accept double values
                 auto& interval = currentBucket.intervals[0];
                 if (interval.hasValue()) {
-                    mCurrentFullBucket[metricDimensionKey] += interval.aggregate.long_value;
+                    mCurrentFullBucket[metricDimensionKey] +=
+                            interval.aggregate.getValueOrDefault<int64_t>(0);
                 }
             }
         }
     }
 }
 
+const optional<const BinStarts>& NumericValueMetricProducer::getBinStarts(
+        int valueFieldIndex) const {
+    return mBinStartsList.size() == 1 ? mBinStartsList[0] : mBinStartsList[valueFieldIndex];
+}
+
 // Estimate for the size of NumericValues.
-size_t NumericValueMetricProducer::getAggregatedValueSize(const Value& value) const {
+size_t NumericValueMetricProducer::getAggregatedValueSize(const NumericValue& value) const {
     size_t valueSize = 0;
     // Index
     valueSize += sizeof(int32_t);
@@ -667,10 +775,8 @@ bool NumericValueMetricProducer::valuePassesThreshold(const Interval& interval)
         return true;
     }
 
-    Value finalValue = getFinalValue(interval);
+    double doubleValue = toDouble(getFinalValue(interval));
 
-    double doubleValue =
-            finalValue.type == LONG ? (double)finalValue.long_value : finalValue.double_value;
     switch (mUploadThreshold->value_comparison_case()) {
         case UploadThreshold::kLtInt:
             return doubleValue < (double)mUploadThreshold->lt_int();
@@ -690,13 +796,15 @@ bool NumericValueMetricProducer::valuePassesThreshold(const Interval& interval)
     }
 }
 
-Value NumericValueMetricProducer::getFinalValue(const Interval& interval) const {
+NumericValue NumericValueMetricProducer::getFinalValue(const Interval& interval) const {
+    if (interval.aggregate.is<HistogramValue>()) {
+        return interval.aggregate.getValue<HistogramValue>().getCompactedHistogramValue();
+    }
     if (getAggregationTypeLocked(interval.aggIndex) != ValueMetric::AVG) {
         return interval.aggregate;
     } else {
-        double sum = interval.aggregate.type == LONG ? (double)interval.aggregate.long_value
-                                                     : interval.aggregate.double_value;
-        return Value((double)sum / interval.sampleSize);
+        double sum = toDouble(interval.aggregate);
+        return NumericValue(sum / interval.sampleSize);
     }
 }
 
@@ -709,6 +817,19 @@ NumericValueMetricProducer::DumpProtoFields NumericValueMetricProducer::getDumpP
             FIELD_ID_CONDITION_CORRECTION_NS};
 }
 
+MetricProducer::DataCorruptionSeverity NumericValueMetricProducer::determineCorruptionSeverity(
+        int32_t atomId, DataCorruptedReason /*reason*/, LostAtomType atomType) const {
+    switch (atomType) {
+        case LostAtomType::kWhat:
+            return mUseDiff ? DataCorruptionSeverity::kUnrecoverable
+                            : DataCorruptionSeverity::kResetOnDump;
+        case LostAtomType::kCondition:
+        case LostAtomType::kState:
+            return DataCorruptionSeverity::kUnrecoverable;
+    };
+    return DataCorruptionSeverity::kNone;
+};
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/metrics/NumericValueMetricProducer.h b/statsd/src/metrics/NumericValueMetricProducer.h
index 5444b069..613678e0 100644
--- a/statsd/src/metrics/NumericValueMetricProducer.h
+++ b/statsd/src/metrics/NumericValueMetricProducer.h
@@ -21,14 +21,15 @@
 #include <optional>
 
 #include "ValueMetricProducer.h"
+#include "metrics/NumericValue.h"
+#include "src/stats_util.h"
 
 namespace android {
 namespace os {
 namespace statsd {
 
-// TODO(b/185796344): don't use Value from FieldValue.
-using ValueBases = std::vector<std::optional<Value>>;
-class NumericValueMetricProducer : public ValueMetricProducer<Value, ValueBases> {
+using Bases = std::vector<NumericValue>;
+class NumericValueMetricProducer : public ValueMetricProducer<NumericValue, Bases> {
 public:
     NumericValueMetricProducer(const ConfigKey& key, const ValueMetric& valueMetric,
                                const uint64_t protoHash, const PullOptions& pullOptions,
@@ -81,7 +82,7 @@ private:
                                           const ConditionState newCondition,
                                           const int64_t eventTimeNs) override;
 
-    inline std::string aggregatedValueToString(const Value& value) const override {
+    inline std::string aggregatedValueToString(const NumericValue& value) const override {
         return value.toString();
     }
 
@@ -105,12 +106,12 @@ private:
     void closeCurrentBucket(const int64_t eventTimeNs,
                             const int64_t nextBucketStartTimeNs) override;
 
-    PastBucket<Value> buildPartialBucket(int64_t bucketEndTime,
-                                         std::vector<Interval>& intervals) override;
+    PastBucket<NumericValue> buildPartialBucket(int64_t bucketEndTime,
+                                                std::vector<Interval>& intervals) override;
 
     bool valuePassesThreshold(const Interval& interval) const;
 
-    Value getFinalValue(const Interval& interval) const;
+    NumericValue getFinalValue(const Interval& interval) const;
 
     void initNextSlicedBucket(int64_t nextBucketStartTimeNs) override;
 
@@ -130,13 +131,13 @@ private:
 
     bool aggregateFields(const int64_t eventTimeNs, const MetricDimensionKey& eventKey,
                          const LogEvent& event, std::vector<Interval>& intervals,
-                         ValueBases& bases) override;
+                         Bases& bases) override;
 
     void pullAndMatchEventsLocked(const int64_t timestampNs) override;
 
     DumpProtoFields getDumpProtoFields() const override;
 
-    void writePastBucketAggregateToProto(const int aggIndex, const Value& value,
+    void writePastBucketAggregateToProto(const int aggIndex, const NumericValue& value,
                                          const int sampleSize,
                                          ProtoOutputStream* const protoOutput) const override;
 
@@ -150,7 +151,10 @@ private:
         return mAggregationTypes.size() == 1 ? mAggregationTypes[0] : mAggregationTypes[index];
     }
 
-    size_t getAggregatedValueSize(const Value& value) const override;
+    // Should only be called if there is at least one HISTOGRAM in mAggregationTypes
+    const std::optional<const BinStarts>& getBinStarts(int valueFieldIndex) const;
+
+    size_t getAggregatedValueSize(const NumericValue& value) const override;
 
     bool hasAvgAggregationType(const vector<ValueMetric::AggregationType> aggregationTypes) const {
         for (const int aggType : aggregationTypes) {
@@ -161,6 +165,9 @@ private:
         return false;
     }
 
+    DataCorruptionSeverity determineCorruptionSeverity(int32_t atomId, DataCorruptedReason reason,
+                                                       LostAtomType atomType) const override;
+
     const bool mUseAbsoluteValueOnReset;
 
     const std::vector<ValueMetric::AggregationType> mAggregationTypes;
@@ -193,6 +200,8 @@ private:
     // For anomaly detection.
     std::unordered_map<MetricDimensionKey, int64_t> mCurrentFullBucket;
 
+    const std::vector<std::optional<const BinStarts>> mBinStartsList;
+
     FRIEND_TEST(NumericValueMetricProducerTest, TestAnomalyDetection);
     FRIEND_TEST(NumericValueMetricProducerTest, TestBaseSetOnConditionChange);
     FRIEND_TEST(NumericValueMetricProducerTest, TestBucketBoundariesOnConditionChange);
diff --git a/statsd/src/metrics/RestrictedEventMetricProducer.cpp b/statsd/src/metrics/RestrictedEventMetricProducer.cpp
index 77682dd2..115cc852 100644
--- a/statsd/src/metrics/RestrictedEventMetricProducer.cpp
+++ b/statsd/src/metrics/RestrictedEventMetricProducer.cpp
@@ -67,7 +67,7 @@ void RestrictedEventMetricProducer::onMatchedLogEventInternalLocked(
 
 void RestrictedEventMetricProducer::onDumpReportLocked(
         const int64_t dumpTimeNs, const bool include_current_partial_bucket, const bool erase_data,
-        const DumpLatency dumpLatency, std::set<string>* str_set,
+        const DumpLatency dumpLatency, std::set<string>* str_set, std::set<int32_t>& usedUids,
         android::util::ProtoOutputStream* protoOutput) {
     VLOG("Unexpected call to onDumpReportLocked() in RestrictedEventMetricProducer");
 }
diff --git a/statsd/src/metrics/RestrictedEventMetricProducer.h b/statsd/src/metrics/RestrictedEventMetricProducer.h
index 7f9a5eb1..4555d21f 100644
--- a/statsd/src/metrics/RestrictedEventMetricProducer.h
+++ b/statsd/src/metrics/RestrictedEventMetricProducer.h
@@ -46,7 +46,7 @@ private:
 
     void onDumpReportLocked(const int64_t dumpTimeNs, const bool include_current_partial_bucket,
                             const bool erase_data, const DumpLatency dumpLatency,
-                            std::set<string>* str_set,
+                            std::set<string>* str_set, std::set<int32_t>& usedUids,
                             android::util::ProtoOutputStream* protoOutput) override;
 
     void clearPastBucketsLocked(const int64_t dumpTimeNs) override;
diff --git a/statsd/src/metrics/ValueMetricProducer.cpp b/statsd/src/metrics/ValueMetricProducer.cpp
index ff65792e..61b7341b 100644
--- a/statsd/src/metrics/ValueMetricProducer.cpp
+++ b/statsd/src/metrics/ValueMetricProducer.cpp
@@ -26,6 +26,7 @@
 #include "FieldValue.h"
 #include "HashableDimensionKey.h"
 #include "guardrail/StatsdStats.h"
+#include "metrics/NumericValue.h"
 #include "metrics/parsing_utils/metrics_manager_util.h"
 #include "stats_log_util.h"
 #include "stats_util.h"
@@ -55,6 +56,7 @@ const int FIELD_ID_DIMENSION_PATH_IN_WHAT = 11;
 const int FIELD_ID_IS_ACTIVE = 14;
 const int FIELD_ID_DIMENSION_GUARDRAIL_HIT = 17;
 const int FIELD_ID_ESTIMATED_MEMORY_BYTES = 18;
+const int FIELD_ID_DATA_CORRUPTED_REASON = 19;
 // for *MetricDataWrapper
 const int FIELD_ID_DATA = 1;
 const int FIELD_ID_SKIPPED = 2;
@@ -309,6 +311,7 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::dropDataLocked(const int64
     // so the data is still valid.
     flushIfNeededLocked(dropTimeNs);
     clearPastBucketsLocked(dropTimeNs);
+    resetDataCorruptionFlagsLocked();
 }
 
 template <typename AggregatedValue, typename DimExtras>
@@ -316,13 +319,15 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::clearPastBucketsLocked(
         const int64_t dumpTimeNs) {
     mPastBuckets.clear();
     mSkippedBuckets.clear();
+    resetDataCorruptionFlagsLocked();
     mTotalDataSize = 0;
 }
 
 template <typename AggregatedValue, typename DimExtras>
 void ValueMetricProducer<AggregatedValue, DimExtras>::onDumpReportLocked(
         const int64_t dumpTimeNs, const bool includeCurrentPartialBucket, const bool eraseData,
-        const DumpLatency dumpLatency, set<string>* strSet, ProtoOutputStream* protoOutput) {
+        const DumpLatency dumpLatency, set<string>* strSet, set<int32_t>& usedUids,
+        ProtoOutputStream* protoOutput) {
     VLOG("metric %lld dump report now...", (long long)mMetricId);
 
     // Pulled metrics need to pull before flushing, which is why they do not call flushIfNeeded.
@@ -350,7 +355,16 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::onDumpReportLocked(
 
     protoOutput->write(FIELD_TYPE_INT64 | FIELD_ID_ID, (long long)mMetricId);
     protoOutput->write(FIELD_TYPE_BOOL | FIELD_ID_IS_ACTIVE, isActiveLocked());
+
+    // Data corrupted reason
+    writeDataCorruptedReasons(*protoOutput, FIELD_ID_DATA_CORRUPTED_REASON,
+                              mDataCorruptedDueToQueueOverflow != DataCorruptionSeverity::kNone,
+                              mDataCorruptedDueToSocketLoss != DataCorruptionSeverity::kNone);
+
     if (mPastBuckets.empty() && mSkippedBuckets.empty()) {
+        if (eraseData) {
+            resetDataCorruptionFlagsLocked();
+        }
         return;
     }
 
@@ -405,11 +419,13 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::onDumpReportLocked(
         if (mShouldUseNestedDimensions) {
             uint64_t dimensionToken =
                     protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_DIMENSION_IN_WHAT);
-            writeDimensionToProto(metricDimensionKey.getDimensionKeyInWhat(), strSet, protoOutput);
+            writeDimensionToProto(metricDimensionKey.getDimensionKeyInWhat(), strSet, usedUids,
+                                  protoOutput);
             protoOutput->end(dimensionToken);
         } else {
             writeDimensionLeafNodesToProto(metricDimensionKey.getDimensionKeyInWhat(),
-                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, strSet, protoOutput);
+                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, strSet, usedUids,
+                                           protoOutput);
         }
 
         // Then fill slice_by_state.
@@ -474,6 +490,7 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::onDumpReportLocked(
     if (eraseData) {
         mPastBuckets.clear();
         mSkippedBuckets.clear();
+        resetDataCorruptionFlagsLocked();
         mTotalDataSize = 0;
     }
 }
@@ -929,7 +946,7 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::initNextSlicedBucket(
 }
 
 // Explicit template instantiations
-template class ValueMetricProducer<Value, vector<optional<Value>>>;
+template class ValueMetricProducer<NumericValue, vector<NumericValue>>;
 template class ValueMetricProducer<unique_ptr<KllQuantile>, Empty>;
 
 }  // namespace statsd
diff --git a/statsd/src/metrics/ValueMetricProducer.h b/statsd/src/metrics/ValueMetricProducer.h
index 78761ebe..5b7cae24 100644
--- a/statsd/src/metrics/ValueMetricProducer.h
+++ b/statsd/src/metrics/ValueMetricProducer.h
@@ -89,6 +89,7 @@ public:
         const FieldMatcher& dimensionsInWhat;
         const vector<Matcher>& fieldMatchers;
         const vector<ValueMetric::AggregationType> aggregationTypes;
+        const std::vector<std::optional<const BinStarts>> binStartsList;
     };
 
     struct ConditionOptions {
@@ -156,7 +157,7 @@ protected:
 
     void onDumpReportLocked(const int64_t dumpTimeNs, const bool includeCurrentPartialBucket,
                             const bool eraseData, const DumpLatency dumpLatency,
-                            std::set<string>* strSet,
+                            std::set<string>* strSet, std::set<int32_t>& usedUids,
                             android::util::ProtoOutputStream* protoOutput) override;
 
     struct DumpProtoFields {
diff --git a/statsd/src/metrics/duration_helper/MaxDurationTracker.cpp b/statsd/src/metrics/duration_helper/MaxDurationTracker.cpp
index 8a253e26..397b7c0c 100644
--- a/statsd/src/metrics/duration_helper/MaxDurationTracker.cpp
+++ b/statsd/src/metrics/duration_helper/MaxDurationTracker.cpp
@@ -138,13 +138,14 @@ void MaxDurationTracker::noteStop(const HashableDimensionKey& key, const int64_t
         }
     }
 
-    if (duration.lastDuration > mDuration) {
-        mDuration = duration.lastDuration;
-        VLOG("Max: new max duration: %lld", (long long)mDuration);
-    }
-    // Once an atom duration ends, we erase it. Next time, if we see another atom event with the
-    // same name, they are still considered as different atom durations.
     if (duration.state == DurationState::kStopped) {
+        if (duration.lastDuration > mDuration) {
+            mDuration = duration.lastDuration;
+            VLOG("Max: new max duration: %lld", (long long)mDuration);
+        }
+
+        // Once an atom duration ends, we erase it. Next time, if we see another atom event with the
+        // same name, they are still considered as different atom durations.
         mInfos.erase(key);
     }
 }
diff --git a/statsd/src/metrics/duration_helper/MaxDurationTracker.h b/statsd/src/metrics/duration_helper/MaxDurationTracker.h
index 27692326..417f182d 100644
--- a/statsd/src/metrics/duration_helper/MaxDurationTracker.h
+++ b/statsd/src/metrics/duration_helper/MaxDurationTracker.h
@@ -84,6 +84,7 @@ private:
 
     FRIEND_TEST(MaxDurationTrackerTest, TestSimpleMaxDuration);
     FRIEND_TEST(MaxDurationTrackerTest, TestCrossBucketBoundary);
+    FRIEND_TEST(MaxDurationTrackerTest, TestMaxDurationNestedWithCondition);
     FRIEND_TEST(MaxDurationTrackerTest, TestMaxDurationWithCondition);
     FRIEND_TEST(MaxDurationTrackerTest, TestStopAll);
     FRIEND_TEST(MaxDurationTrackerTest, TestAnomalyDetection);
diff --git a/statsd/src/metrics/parsing_utils/histogram_parsing_utils.cpp b/statsd/src/metrics/parsing_utils/histogram_parsing_utils.cpp
new file mode 100644
index 00000000..77a93991
--- /dev/null
+++ b/statsd/src/metrics/parsing_utils/histogram_parsing_utils.cpp
@@ -0,0 +1,214 @@
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
+#define STATSD_DEBUG false  // STOPSHIP if true
+#include "Log.h"
+
+#include "histogram_parsing_utils.h"
+
+#include <google/protobuf/repeated_field.h>
+
+#include <algorithm>
+#include <cmath>
+#include <optional>
+#include <variant>
+#include <vector>
+
+#include "guardrail/StatsdStats.h"
+#include "src/statsd_config.pb.h"
+#include "stats_util.h"
+
+using google::protobuf::RepeatedPtrField;
+using std::nullopt;
+using std::optional;
+using std::pow;
+using std::variant;
+using std::vector;
+
+namespace android {
+namespace os {
+namespace statsd {
+namespace {
+constexpr int MIN_HISTOGRAM_BIN_COUNT = 2;
+constexpr int MAX_HISTOGRAM_BIN_COUNT = 100;
+
+BinStarts generateLinearBins(float min, float max, int count) {
+    const float binWidth = (max - min) / count;
+
+    // 2 extra bins for underflow and overflow.
+    BinStarts bins(count + 2);
+    bins[0] = UNDERFLOW_BIN_START;
+    bins[1] = min;
+    bins.back() = max;
+    float curBin = min;
+
+    // Generate values starting from 3rd element to (n-1)th element.
+    std::generate(bins.begin() + 2, bins.end() - 1,
+                  [&curBin, binWidth]() { return curBin += binWidth; });
+    return bins;
+}
+
+BinStarts generateExponentialBins(float min, float max, int count) {
+    BinStarts bins(count + 2);
+    bins[0] = UNDERFLOW_BIN_START;
+    bins[1] = min;
+    bins.back() = max;
+
+    // Determine the scale factor f, such that max = min * f^count.
+    // So, f = (max / min)^(1 / count) ie. f is the count'th-root of max / min.
+    const float factor = pow(max / min, 1.0 / count);
+
+    // Generate values starting from 3rd element to (n-1)th element.
+    float curBin = bins[1];
+    std::generate(bins.begin() + 2, bins.end() - 1,
+                  [&curBin, factor]() { return curBin *= factor; });
+
+    return bins;
+}
+
+BinStarts createExplicitBins(const BinStarts& configBins) {
+    BinStarts bins(configBins.size() + 1);
+    bins[0] = UNDERFLOW_BIN_START;
+    std::copy(configBins.begin(), configBins.end(), bins.begin() + 1);
+    return bins;
+}
+}  // anonymous namespace
+
+ParseHistogramBinConfigsResult parseHistogramBinConfigs(
+        const ValueMetric& metric, const vector<ValueMetric::AggregationType>& aggregationTypes) {
+    if (metric.histogram_bin_configs_size() == 0) {
+        return {};
+    }
+    vector<optional<const BinStarts>> binStartsList;
+    binStartsList.reserve(aggregationTypes.size());
+    RepeatedPtrField<HistogramBinConfig>::const_iterator binConfigIt =
+            metric.histogram_bin_configs().cbegin();
+    for (const ValueMetric::AggregationType aggType : aggregationTypes) {
+        if (aggType != ValueMetric::HISTOGRAM) {
+            binStartsList.push_back(nullopt);
+            continue;
+        }
+        const HistogramBinConfig& binConfig = *binConfigIt;
+        if (!binConfig.has_id()) {
+            ALOGE("cannot find id in HistogramBinConfig");
+            return InvalidConfigReason(
+                    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_BIN_CONFIG_ID, metric.id());
+        }
+        switch (binConfig.binning_strategy_case()) {
+            case HistogramBinConfig::kGeneratedBins: {
+                const HistogramBinConfig::GeneratedBins& genBins = binConfig.generated_bins();
+                if (!genBins.has_min() || !genBins.has_max() || !genBins.has_count() ||
+                    !genBins.has_strategy()) {
+                    ALOGE("Missing generated bin arguments");
+                    return InvalidConfigReason(
+                            INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_GENERATED_BINS_ARGS,
+                            metric.id());
+                }
+                if (genBins.count() < MIN_HISTOGRAM_BIN_COUNT) {
+                    ALOGE("Too few generated bins");
+                    return InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_FEW_BINS,
+                                               metric.id());
+                }
+                if (genBins.count() > MAX_HISTOGRAM_BIN_COUNT) {
+                    ALOGE("Too many generated bins");
+                    return InvalidConfigReason(
+                            INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_MANY_BINS, metric.id());
+                }
+                if (genBins.min() >= genBins.max()) {
+                    ALOGE("Min should be lower than max for generated bins");
+                    return InvalidConfigReason(
+                            INVALID_CONFIG_REASON_VALUE_METRIC_HIST_GENERATED_BINS_INVALID_MIN_MAX,
+                            metric.id());
+                }
+
+                switch (genBins.strategy()) {
+                    case HistogramBinConfig::GeneratedBins::LINEAR: {
+                        binStartsList.push_back(
+                                generateLinearBins(genBins.min(), genBins.max(), genBins.count()));
+                        break;
+                    }
+                    case HistogramBinConfig::GeneratedBins::EXPONENTIAL: {
+                        // The starting point of exponential bins has to be greater than 0.
+                        if (genBins.min() <= 0) {
+                            ALOGE("Min should be greater than 0 for exponential bins");
+                            return InvalidConfigReason(
+                                    INVALID_CONFIG_REASON_VALUE_METRIC_HIST_GENERATED_BINS_INVALID_MIN_MAX,
+                                    metric.id());
+                        }
+                        binStartsList.push_back(generateExponentialBins(
+                                genBins.min(), genBins.max(), genBins.count()));
+                        break;
+                    }
+                    default: {
+                        ALOGE("Unknown GeneratedBins strategy");
+                        return InvalidConfigReason(
+                                INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_GENERATED_BINS_ARGS,
+                                metric.id());
+                    }
+                }
+
+                break;
+            }
+            case HistogramBinConfig::kExplicitBins: {
+                const HistogramBinConfig::ExplicitBins& explicitBins = binConfig.explicit_bins();
+                if (explicitBins.bin_size() < MIN_HISTOGRAM_BIN_COUNT) {
+                    ALOGE("Too few explicit bins");
+                    return InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_FEW_BINS,
+                                               metric.id());
+                }
+                if (explicitBins.bin_size() > MAX_HISTOGRAM_BIN_COUNT) {
+                    ALOGE("Too many explicit bins");
+                    return InvalidConfigReason(
+                            INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_MANY_BINS, metric.id());
+                }
+
+                // Ensure explicit bins are strictly ordered in ascending order.
+                // Use adjacent_find to find any 2 adjacent bin boundaries, b1 and b2, such that b1
+                // >= b2. If any such adjacent bins are found, the bins are not strictly ascending
+                // and the bin definition is invalid.
+                if (std::adjacent_find(explicitBins.bin().begin(), explicitBins.bin().end(),
+                                       std::greater_equal<float>()) != explicitBins.bin().end()) {
+                    ALOGE("Explicit bins are not strictly ordered in ascending order");
+                    return InvalidConfigReason(
+                            INVALID_CONFIG_REASON_VALUE_METRIC_HIST_EXPLICIT_BINS_NOT_STRICTLY_ORDERED,
+                            metric.id());
+                }
+
+                binStartsList.push_back(
+                        createExplicitBins({explicitBins.bin().begin(), explicitBins.bin().end()}));
+
+                break;
+            }
+            case HistogramBinConfig::kClientAggregatedBins: {
+                binStartsList.push_back(nullopt);
+                break;
+            }
+            default: {
+                ALOGE("Either generated or explicit binning strategy must be set");
+                return InvalidConfigReason(
+                        INVALID_CONFIG_REASON_VALUE_METRIC_HIST_UNKNOWN_BINNING_STRATEGY,
+                        metric.id());
+                break;
+            }
+        }
+        binConfigIt++;
+    }
+    return binStartsList;
+}
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/metrics/parsing_utils/histogram_parsing_utils.h b/statsd/src/metrics/parsing_utils/histogram_parsing_utils.h
new file mode 100644
index 00000000..f58ecf97
--- /dev/null
+++ b/statsd/src/metrics/parsing_utils/histogram_parsing_utils.h
@@ -0,0 +1,42 @@
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
+#pragma once
+
+#include <optional>
+#include <variant>
+#include <vector>
+
+#include "guardrail/StatsdStats.h"
+#include "src/statsd_config.pb.h"
+#include "stats_util.h"
+
+namespace android {
+namespace os {
+namespace statsd {
+
+constexpr float UNDERFLOW_BIN_START = std::numeric_limits<float>::min();
+
+using ParseHistogramBinConfigsResult =
+        std::variant<std::vector<std::optional<const BinStarts>>, InvalidConfigReason>;
+
+ParseHistogramBinConfigsResult parseHistogramBinConfigs(
+        const ValueMetric& valueMetric,
+        const std::vector<ValueMetric::AggregationType>& aggregationTypes);
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp b/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
index a4272882..445b3e2d 100644
--- a/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
+++ b/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
@@ -21,6 +21,8 @@
 
 #include <inttypes.h>
 
+#include <variant>
+
 #include "FieldValue.h"
 #include "condition/CombinationConditionTracker.h"
 #include "condition/SimpleConditionTracker.h"
@@ -38,6 +40,7 @@
 #include "metrics/MetricProducer.h"
 #include "metrics/NumericValueMetricProducer.h"
 #include "metrics/RestrictedEventMetricProducer.h"
+#include "metrics/parsing_utils/histogram_parsing_utils.h"
 #include "state/StateManager.h"
 #include "stats_util.h"
 
@@ -879,6 +882,43 @@ optional<sp<MetricProducer>> createEventMetricProducerAndUpdateMetadata(
                                     eventActivationMap, eventDeactivationMap)};
 }
 
+namespace {  // anonymous namespace
+bool hasClientAggregatedBins(const ValueMetric& metric, int binConfigIndex) {
+    return metric.histogram_bin_configs_size() > binConfigIndex &&
+           metric.histogram_bin_configs(binConfigIndex).has_client_aggregated_bins();
+}
+
+optional<InvalidConfigReason> validatePositionAllInValueFields(
+        const ValueMetric& metric, int binConfigIndex, ValueMetric::AggregationType aggType,
+        vector<Matcher>::iterator matchersStartIt, const vector<Matcher>::iterator& matchersEndIt) {
+    if (aggType == ValueMetric::HISTOGRAM && hasClientAggregatedBins(metric, binConfigIndex)) {
+        while (matchersStartIt != matchersEndIt) {
+            if (!matchersStartIt->hasAllPositionMatcher()) {
+                ALOGE("value_field requires position ALL for client-aggregated histograms. "
+                      "ValueMetric \"%lld\"",
+                      (long long)metric.id());
+                return InvalidConfigReason(
+                        INVALID_CONFIG_REASON_VALUE_METRIC_HIST_CLIENT_AGGREGATED_NO_POSITION_ALL,
+                        metric.id());
+            }
+            matchersStartIt++;
+        }
+        return nullopt;
+    }
+    while (matchersStartIt != matchersEndIt) {
+        if (matchersStartIt->hasAllPositionMatcher()) {
+            ALOGE("value_field with position ALL is only supported for client-aggregated "
+                  "histograms. ValueMetric \"%lld\"",
+                  (long long)metric.id());
+            return InvalidConfigReason(
+                    INVALID_CONFIG_REASON_VALUE_METRIC_VALUE_FIELD_HAS_POSITION_ALL, metric.id());
+        }
+        matchersStartIt++;
+    }
+    return nullopt;
+}
+}  // anonymous namespace
+
 optional<sp<MetricProducer>> createNumericValueMetricProducerAndUpdateMetadata(
         const ConfigKey& key, const StatsdConfig& config, const int64_t timeBaseNs,
         const int64_t currentTimeNs, const sp<StatsPullerManager>& pullerManager,
@@ -910,13 +950,6 @@ optional<sp<MetricProducer>> createNumericValueMetricProducerAndUpdateMetadata(
                 INVALID_CONFIG_REASON_VALUE_METRIC_MISSING_VALUE_FIELD, metric.id());
         return nullopt;
     }
-    if (HasPositionALL(metric.value_field())) {
-        ALOGE("value field with position ALL is not supported. ValueMetric \"%lld\"",
-              (long long)metric.id());
-        invalidConfigReason = InvalidConfigReason(
-                INVALID_CONFIG_REASON_VALUE_METRIC_VALUE_FIELD_HAS_POSITION_ALL, metric.id());
-        return nullopt;
-    }
     std::vector<Matcher> fieldMatchers;
     translateFieldMatcher(metric.value_field(), &fieldMatchers);
     if (fieldMatchers.size() < 1) {
@@ -927,6 +960,7 @@ optional<sp<MetricProducer>> createNumericValueMetricProducerAndUpdateMetadata(
     }
 
     std::vector<ValueMetric::AggregationType> aggregationTypes;
+    int histogramCount = 0;
     if (!metric.aggregation_types().empty()) {
         if (metric.has_aggregation_type()) {
             invalidConfigReason = InvalidConfigReason(
@@ -941,10 +975,58 @@ optional<sp<MetricProducer>> createNumericValueMetricProducerAndUpdateMetadata(
             return nullopt;
         }
         for (int i = 0; i < metric.aggregation_types_size(); i++) {
-            aggregationTypes.push_back(metric.aggregation_types(i));
+            const ValueMetric::AggregationType aggType = metric.aggregation_types(i);
+            aggregationTypes.push_back(aggType);
+            if (aggType == ValueMetric::HISTOGRAM) {
+                histogramCount++;
+            }
+            invalidConfigReason = validatePositionAllInValueFields(
+                    metric, histogramCount - 1, aggType, fieldMatchers.begin() + i,
+                    fieldMatchers.begin() + i + 1);
+            if (invalidConfigReason != nullopt) {
+                return nullopt;
+            }
         }
     } else {  // aggregation_type() is set or default is used.
-        aggregationTypes.push_back(metric.aggregation_type());
+        const ValueMetric::AggregationType aggType = metric.aggregation_type();
+        aggregationTypes.push_back(aggType);
+        if (aggType == ValueMetric::HISTOGRAM) {
+            histogramCount = 1;
+        }
+        invalidConfigReason = validatePositionAllInValueFields(
+                metric, 0, aggType, fieldMatchers.begin(), fieldMatchers.end());
+        if (invalidConfigReason != nullopt) {
+            return nullopt;
+        }
+    }
+
+    if (metric.histogram_bin_configs_size() != histogramCount) {
+        ALOGE("%d histogram aggregations specified but there are %d histogram_bin_configs",
+              histogramCount, metric.histogram_bin_configs_size());
+        invalidConfigReason = InvalidConfigReason(
+                INVALID_CONFIG_REASON_VALUE_METRIC_HIST_COUNT_DNE_HIST_BIN_CONFIGS_COUNT,
+                metric.id());
+        return nullopt;
+    }
+
+    if (aggregationTypes.front() == ValueMetric::HISTOGRAM && metric.has_threshold()) {
+        invalidConfigReason = InvalidConfigReason(
+                INVALID_CONFIG_REASON_VALUE_METRIC_HIST_WITH_UPLOAD_THRESHOLD, metric.id());
+        return nullopt;
+    }
+
+    if (histogramCount > 0 && metric.has_value_direction() &&
+        metric.value_direction() != ValueMetric::INCREASING) {
+        invalidConfigReason = InvalidConfigReason(
+                INVALID_CONFIG_REASON_VALUE_METRIC_HIST_INVALID_VALUE_DIRECTION, metric.id());
+        return nullopt;
+    }
+
+    ParseHistogramBinConfigsResult parseBinConfigsResult =
+            parseHistogramBinConfigs(metric, aggregationTypes);
+    if (std::holds_alternative<InvalidConfigReason>(parseBinConfigsResult)) {
+        invalidConfigReason = std::get<InvalidConfigReason>(parseBinConfigsResult);
+        return nullopt;
     }
 
     int trackerIndex;
@@ -1039,12 +1121,15 @@ optional<sp<MetricProducer>> createNumericValueMetricProducerAndUpdateMetadata(
                     ? optional<int64_t>(metric.condition_correction_threshold_nanos())
                     : nullopt;
 
+    const vector<optional<const BinStarts>>& binStartsList =
+            std::get<vector<optional<const BinStarts>>>(parseBinConfigsResult);
     sp<MetricProducer> metricProducer = new NumericValueMetricProducer(
             key, metric, metricHash, {pullTagId, pullerManager},
             {timeBaseNs, currentTimeNs, bucketSizeNs, metric.min_bucket_size_nanos(),
              conditionCorrectionThresholdNs, getAppUpgradeBucketSplit(metric)},
             {containsAnyPositionInDimensionsInWhat, shouldUseNestedDimensions, trackerIndex,
-             matcherWizard, metric.dimensions_in_what(), fieldMatchers, aggregationTypes},
+             matcherWizard, metric.dimensions_in_what(), fieldMatchers, aggregationTypes,
+             binStartsList},
             {conditionIndex, metric.links(), initialConditionCache, wizard},
             {metric.state_link(), slicedStateAtoms, stateGroupMap},
             {eventActivationMap, eventDeactivationMap}, {dimensionSoftLimit, dimensionHardLimit},
diff --git a/statsd/src/packages/UidMap.cpp b/statsd/src/packages/UidMap.cpp
index d3bf71ab..8edbb0a5 100644
--- a/statsd/src/packages/UidMap.cpp
+++ b/statsd/src/packages/UidMap.cpp
@@ -74,10 +74,18 @@ const int FIELD_ID_CHANGE_PREV_VERSION_STRING = 9;
 const int FIELD_ID_CHANGE_NEW_VERSION_STRING_HASH = 10;
 const int FIELD_ID_CHANGE_PREV_VERSION_STRING_HASH = 11;
 
-inline bool omitUid(int32_t uid, bool omitSystemUids) {
+bool omitUid(int32_t uid, const string& packageName, const UidMapOptions& options) {
+    // Always allow allowlisted packages
+    if (options.allowlistedPackages.contains(packageName)) {
+        return false;
+    }
     // If omitSystemUids is true, uids for which (uid % AID_USER_OFFSET) is in [0, AID_APP_START)
-    // should be excluded.
-    return omitSystemUids && uid >= 0 && uid % AID_USER_OFFSET < AID_APP_START;
+    // should be excluded. This takes precedence over if the uid is used or not.
+    if (options.omitSystemUids && uid >= 0 && uid % AID_USER_OFFSET < AID_APP_START) {
+        return true;
+    }
+    // If omitUnusedUids is true, omit the uid unless it is in the used set.
+    return options.omitUnusedUids && !options.usedUids.contains(uid);
 }
 
 }  // namespace
@@ -325,22 +333,17 @@ size_t UidMap::getBytesUsed() const {
     return mBytesUsed;
 }
 
-void UidMap::writeUidMapSnapshot(int64_t timestamp, bool includeVersionStrings,
-                                 bool includeInstaller, const uint8_t truncatedCertificateHashSize,
-                                 bool omitSystemUids, const std::set<int32_t>& interestingUids,
+void UidMap::writeUidMapSnapshot(int64_t timestamp, const UidMapOptions& options,
+                                 const std::set<int32_t>& interestingUids,
                                  map<string, int>* installerIndices, std::set<string>* str_set,
                                  ProtoOutputStream* proto) const {
     lock_guard<mutex> lock(mMutex);
 
-    writeUidMapSnapshotLocked(timestamp, includeVersionStrings, includeInstaller,
-                              truncatedCertificateHashSize, omitSystemUids, interestingUids,
-                              installerIndices, str_set, proto);
+    writeUidMapSnapshotLocked(timestamp, options, interestingUids, installerIndices, str_set,
+                              proto);
 }
 
-void UidMap::writeUidMapSnapshotLocked(const int64_t timestamp, const bool includeVersionStrings,
-                                       const bool includeInstaller,
-                                       const uint8_t truncatedCertificateHashSize,
-                                       const bool omitSystemUids,
+void UidMap::writeUidMapSnapshotLocked(const int64_t timestamp, const UidMapOptions& options,
                                        const std::set<int32_t>& interestingUids,
                                        map<string, int>* installerIndices,
                                        std::set<string>* str_set, ProtoOutputStream* proto) const {
@@ -349,7 +352,7 @@ void UidMap::writeUidMapSnapshotLocked(const int64_t timestamp, const bool inclu
     proto->write(FIELD_TYPE_INT64 | FIELD_ID_SNAPSHOT_TIMESTAMP, (long long)timestamp);
     for (const auto& [keyPair, appData] : mMap) {
         const auto& [uid, packageName] = keyPair;
-        if (omitUid(uid, omitSystemUids) ||
+        if (omitUid(uid, packageName, options) ||
             (!interestingUids.empty() && interestingUids.find(uid) == interestingUids.end())) {
             continue;
         }
@@ -357,7 +360,7 @@ void UidMap::writeUidMapSnapshotLocked(const int64_t timestamp, const bool inclu
                                       FIELD_ID_SNAPSHOT_PACKAGE_INFO);
         // Get installer index.
         int installerIndex = -1;
-        if (includeInstaller && installerIndices != nullptr) {
+        if (options.includeInstaller && installerIndices != nullptr) {
             const auto& it = installerIndices->find(appData.installer);
             if (it == installerIndices->end()) {
                 // We have not encountered this installer yet; add it to installerIndices.
@@ -373,12 +376,12 @@ void UidMap::writeUidMapSnapshotLocked(const int64_t timestamp, const bool inclu
             str_set->insert(packageName);
             proto->write(FIELD_TYPE_UINT64 | FIELD_ID_SNAPSHOT_PACKAGE_NAME_HASH,
                          (long long)Hash64(packageName));
-            if (includeVersionStrings) {
+            if (options.includeVersionStrings) {
                 str_set->insert(appData.versionString);
                 proto->write(FIELD_TYPE_UINT64 | FIELD_ID_SNAPSHOT_PACKAGE_VERSION_STRING_HASH,
                              (long long)Hash64(appData.versionString));
             }
-            if (includeInstaller) {
+            if (options.includeInstaller) {
                 str_set->insert(appData.installer);
                 if (installerIndex != -1) {
                     // Write installer index.
@@ -391,11 +394,11 @@ void UidMap::writeUidMapSnapshotLocked(const int64_t timestamp, const bool inclu
             }
         } else {  // Strings not hashed in report
             proto->write(FIELD_TYPE_STRING | FIELD_ID_SNAPSHOT_PACKAGE_NAME, packageName);
-            if (includeVersionStrings) {
+            if (options.includeVersionStrings) {
                 proto->write(FIELD_TYPE_STRING | FIELD_ID_SNAPSHOT_PACKAGE_VERSION_STRING,
                              appData.versionString);
             }
-            if (includeInstaller) {
+            if (options.includeInstaller) {
                 if (installerIndex != -1) {
                     proto->write(FIELD_TYPE_UINT32 | FIELD_ID_SNAPSHOT_PACKAGE_INSTALLER_INDEX,
                                  installerIndex);
@@ -406,9 +409,10 @@ void UidMap::writeUidMapSnapshotLocked(const int64_t timestamp, const bool inclu
             }
         }
 
-        const size_t dumpHashSize = truncatedCertificateHashSize <= appData.certificateHash.size()
-                                            ? truncatedCertificateHashSize
-                                            : appData.certificateHash.size();
+        const size_t dumpHashSize =
+                options.truncatedCertificateHashSize <= appData.certificateHash.size()
+                        ? options.truncatedCertificateHashSize
+                        : appData.certificateHash.size();
         if (dumpHashSize > 0) {
             proto->write(FIELD_TYPE_BYTES | FIELD_ID_SNAPSHOT_PACKAGE_TRUNCATED_CERTIFICATE_HASH,
                          appData.certificateHash.c_str(), dumpHashSize);
@@ -423,13 +427,12 @@ void UidMap::writeUidMapSnapshotLocked(const int64_t timestamp, const bool inclu
 }
 
 void UidMap::appendUidMap(const int64_t timestamp, const ConfigKey& key,
-                          const bool includeVersionStrings, const bool includeInstaller,
-                          const uint8_t truncatedCertificateHashSize, const bool omitSystemUids,
-                          std::set<string>* str_set, ProtoOutputStream* proto) {
+                          const UidMapOptions& options, std::set<string>* str_set,
+                          ProtoOutputStream* proto) {
     lock_guard<mutex> lock(mMutex);  // Lock for updates
 
     for (const ChangeRecord& record : mChanges) {
-        if (omitUid(record.uid, omitSystemUids) ||
+        if (omitUid(record.uid, record.package, options) ||
             record.timestampNs <= mLastUpdatePerConfigKey[key]) {
             continue;
         }
@@ -442,7 +445,7 @@ void UidMap::appendUidMap(const int64_t timestamp, const ConfigKey& key,
             str_set->insert(record.package);
             proto->write(FIELD_TYPE_UINT64 | FIELD_ID_CHANGE_PACKAGE_HASH,
                          (long long)Hash64(record.package));
-            if (includeVersionStrings) {
+            if (options.includeVersionStrings) {
                 str_set->insert(record.versionString);
                 proto->write(FIELD_TYPE_UINT64 | FIELD_ID_CHANGE_NEW_VERSION_STRING_HASH,
                              (long long)Hash64(record.versionString));
@@ -452,7 +455,7 @@ void UidMap::appendUidMap(const int64_t timestamp, const ConfigKey& key,
             }
         } else {
             proto->write(FIELD_TYPE_STRING | FIELD_ID_CHANGE_PACKAGE, record.package);
-            if (includeVersionStrings) {
+            if (options.includeVersionStrings) {
                 proto->write(FIELD_TYPE_STRING | FIELD_ID_CHANGE_NEW_VERSION_STRING,
                              record.versionString);
                 proto->write(FIELD_TYPE_STRING | FIELD_ID_CHANGE_PREV_VERSION_STRING,
@@ -472,8 +475,7 @@ void UidMap::appendUidMap(const int64_t timestamp, const ConfigKey& key,
     // Write snapshot from current uid map state.
     uint64_t snapshotsToken =
             proto->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | FIELD_ID_SNAPSHOTS);
-    writeUidMapSnapshotLocked(timestamp, includeVersionStrings, includeInstaller,
-                              truncatedCertificateHashSize, omitSystemUids,
+    writeUidMapSnapshotLocked(timestamp, options,
                               std::set<int32_t>() /*empty uid set means including every uid*/,
                               &installerIndices, str_set, proto);
     proto->end(snapshotsToken);
@@ -484,7 +486,7 @@ void UidMap::appendUidMap(const int64_t timestamp, const ConfigKey& key,
         installers[index] = installer;
     }
 
-    if (includeInstaller) {
+    if (options.includeInstaller) {
         // Write installer list; either strings or hashes.
         for (const string& installerName : installers) {
             if (str_set == nullptr) {  // Strings not hashed
diff --git a/statsd/src/packages/UidMap.h b/statsd/src/packages/UidMap.h
index 4d5c6772..9774c8d7 100644
--- a/statsd/src/packages/UidMap.h
+++ b/statsd/src/packages/UidMap.h
@@ -87,6 +87,16 @@ struct ChangeRecord {
     }
 };
 
+struct UidMapOptions {
+    bool includeVersionStrings = false;
+    bool includeInstaller = false;
+    uint8_t truncatedCertificateHashSize = 0;
+    bool omitSystemUids = false;
+    bool omitUnusedUids = false;
+    set<int32_t> usedUids = {};
+    set<string> allowlistedPackages = {};
+};
+
 const unsigned int kBytesChangeRecord = sizeof(struct ChangeRecord);
 
 // UidMap keeps track of what the corresponding app name (APK name) and version code for every uid
@@ -138,10 +148,8 @@ public:
     // Gets all snapshots and changes that have occurred since the last output.
     // If every config key has received a change or snapshot record, then this
     // record is deleted.
-    void appendUidMap(int64_t timestamp, const ConfigKey& key, const bool includeVersionStrings,
-                      const bool includeInstaller, const uint8_t truncatedCertificateHashSize,
-                      const bool omitSystemUids, std::set<string>* str_set,
-                      ProtoOutputStream* proto);
+    void appendUidMap(int64_t timestamp, const ConfigKey& key, const UidMapOptions& options,
+                      std::set<string>* str_set, ProtoOutputStream* proto);
 
     // Forces the output to be cleared. We still generate a snapshot based on the current state.
     // This results in extra data uploaded but helps us reconstruct the uid mapping on the server
@@ -158,8 +166,7 @@ public:
     //                  package info for all uids.
     // str_set: if not null, add new string to the set and write str_hash to proto
     //          if null, write string to proto.
-    void writeUidMapSnapshot(int64_t timestamp, bool includeVersionStrings, bool includeInstaller,
-                             const uint8_t truncatedCertificateHashSize, bool omitSystemUids,
+    void writeUidMapSnapshot(int64_t timestamp, const UidMapOptions& options,
                              const std::set<int32_t>& interestingUids,
                              std::map<string, int>* installerIndices, std::set<string>* str_set,
                              ProtoOutputStream* proto) const;
@@ -168,10 +175,7 @@ private:
     std::set<string> getAppNamesFromUidLocked(int32_t uid, bool returnNormalized) const;
     string normalizeAppName(const string& appName) const;
 
-    void writeUidMapSnapshotLocked(const int64_t timestamp, const bool includeVersionStrings,
-                                   const bool includeInstaller,
-                                   const uint8_t truncatedCertificateHashSize,
-                                   const bool omitSystemUids,
+    void writeUidMapSnapshotLocked(const int64_t timestamp, const UidMapOptions& options,
                                    const std::set<int32_t>& interestingUids,
                                    std::map<string, int>* installerIndices,
                                    std::set<string>* str_set, ProtoOutputStream* proto) const;
diff --git a/statsd/src/state/StateListener.h b/statsd/src/state/StateListener.h
index 63880017..d47b8d50 100644
--- a/statsd/src/state/StateListener.h
+++ b/statsd/src/state/StateListener.h
@@ -15,6 +15,7 @@
  */
 #pragma once
 
+#include <src/guardrail/stats_log_enums.pb.h>
 #include <utils/RefBase.h>
 
 #include "HashableDimensionKey.h"
@@ -47,6 +48,12 @@ public:
     virtual void onStateChanged(const int64_t eventTimeNs, const int32_t atomId,
                                 const HashableDimensionKey& primaryKey, const FieldValue& oldState,
                                 const FieldValue& newState) = 0;
+
+    /**
+     * Interface for handling a state event lost.
+     */
+    virtual void onStateEventLost(int32_t atomId, DataCorruptedReason reason) {
+    }
 };
 
 }  // namespace statsd
diff --git a/statsd/src/state/StateManager.cpp b/statsd/src/state/StateManager.cpp
index 1a324952..6f01ffac 100644
--- a/statsd/src/state/StateManager.cpp
+++ b/statsd/src/state/StateManager.cpp
@@ -20,6 +20,9 @@
 #include "StateManager.h"
 
 #include <private/android_filesystem_config.h>
+#include <statslog_statsd.h>
+
+#include <unordered_set>
 
 namespace android {
 namespace os {
@@ -47,12 +50,42 @@ void StateManager::onLogEvent(const LogEvent& event) {
     if (event.GetUid() == AID_ROOT ||
         (event.GetUid() >= AID_SYSTEM && event.GetUid() < AID_SHELL) ||
         mAllowedLogSources.find(event.GetUid()) != mAllowedLogSources.end()) {
-        if (mStateTrackers.find(event.GetTagId()) != mStateTrackers.end()) {
-            mStateTrackers[event.GetTagId()]->onLogEvent(event);
+        const int tagId = event.GetTagId();
+        if (tagId == util::STATS_SOCKET_LOSS_REPORTED) {
+            // Hard coded logic to handle socket loss info to highlight metric corruption reason
+            const std::optional<SocketLossInfo>& lossInfo = toSocketLossInfo(event);
+            if (lossInfo) {
+                handleSocketLossInfo(*lossInfo);
+            }
+        } else {
+            auto stateTrackersForEvent = mStateTrackers.find(tagId);
+            if (stateTrackersForEvent != mStateTrackers.end()) {
+                stateTrackersForEvent->second->onLogEvent(event);
+            }
         }
     }
 }
 
+void StateManager::handleSocketLossInfo(const SocketLossInfo& socketLossInfo) {
+    // socketLossInfo stores atomId per UID - to eliminate duplicates using set
+    const std::unordered_set<int> uniqueLostAtomIds(socketLossInfo.atomIds.begin(),
+                                                    socketLossInfo.atomIds.end());
+
+    // pass lost atom id to all relevant metrics
+    for (const auto lostAtomId : uniqueLostAtomIds) {
+        onLogEventLost(lostAtomId, DATA_CORRUPTED_SOCKET_LOSS);
+    }
+}
+
+bool StateManager::onLogEventLost(int32_t lostAtomId, DataCorruptedReason reason) {
+    auto stateTrackersIt = mStateTrackers.find(lostAtomId);
+    if (stateTrackersIt != mStateTrackers.end()) {
+        stateTrackersIt->second->onLogEventLost(reason);
+        return true;
+    }
+    return false;
+}
+
 void StateManager::registerListener(const int32_t atomId, const wp<StateListener>& listener) {
     // Check if state tracker already exists.
     if (mStateTrackers.find(atomId) == mStateTrackers.end()) {
diff --git a/statsd/src/state/StateManager.h b/statsd/src/state/StateManager.h
index 2db206ec..46f84066 100644
--- a/statsd/src/state/StateManager.h
+++ b/statsd/src/state/StateManager.h
@@ -23,6 +23,7 @@
 #include <unordered_map>
 
 #include "HashableDimensionKey.h"
+#include "logd/logevent_util.h"
 #include "packages/UidMap.h"
 #include "socket/LogEventFilter.h"
 #include "state/StateListener.h"
@@ -73,6 +74,12 @@ public:
 
     void notifyAppChanged(const string& apk, const sp<UidMap>& uidMap);
 
+    /**
+     * @brief Update State Tracker depending on #lostAtomId that it was lost due to #reason
+     * @return true if State Tracker was notified
+     */
+    bool onLogEventLost(int32_t lostAtomId, DataCorruptedReason reason);
+
     inline int getStateTrackersCount() const {
         return mStateTrackers.size();
     }
@@ -88,6 +95,9 @@ public:
     void addAllAtomIds(LogEventFilter::AtomIdSet& allIds) const;
 
 private:
+    // Notifies the correct StateTracker of lost event.
+    void handleSocketLossInfo(const SocketLossInfo& socketLossInfo);
+
     mutable std::mutex mMutex;
 
     // Maps state atom ids to StateTrackers
diff --git a/statsd/src/state/StateTracker.cpp b/statsd/src/state/StateTracker.cpp
index 5394d846..40219b11 100644
--- a/statsd/src/state/StateTracker.cpp
+++ b/statsd/src/state/StateTracker.cpp
@@ -64,6 +64,17 @@ void StateTracker::onLogEvent(const LogEvent& event) {
     updateStateForPrimaryKey(eventTimeNs, primaryKey, newState, nested, mStateMap[primaryKey]);
 }
 
+void StateTracker::onLogEventLost(DataCorruptedReason reason) {
+    // notify listeners about lost state event
+
+    for (const auto& l : mListeners) {
+        auto sl = l.promote();
+        if (sl != nullptr) {
+            sl->onStateEventLost(mField.getTag(), reason);
+        }
+    }
+}
+
 void StateTracker::registerListener(const wp<StateListener>& listener) {
     mListeners.insert(listener);
 }
diff --git a/statsd/src/state/StateTracker.h b/statsd/src/state/StateTracker.h
index 8e8f27f2..8b978956 100644
--- a/statsd/src/state/StateTracker.h
+++ b/statsd/src/state/StateTracker.h
@@ -39,6 +39,8 @@ public:
     // the log event and comparing the old and new states.
     void onLogEvent(const LogEvent& event);
 
+    void onLogEventLost(DataCorruptedReason reason);
+
     // Adds new listeners to set of StateListeners. If a listener is already
     // registered, it is ignored.
     void registerListener(const wp<StateListener>& listener);
diff --git a/statsd/src/stats_log_util.cpp b/statsd/src/stats_log_util.cpp
index 35d5b129..1e4b0244 100644
--- a/statsd/src/stats_log_util.cpp
+++ b/statsd/src/stats_log_util.cpp
@@ -104,7 +104,7 @@ const int FIELD_ID_BUCKET_COUNT = 12;
 namespace {
 
 void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims, size_t* index, int depth,
-                                 int prefix, std::set<string>* str_set,
+                                 int prefix, std::set<string>* str_set, std::set<int32_t>& usedUids,
                                  ProtoOutputStream* protoOutput) {
     size_t count = dims.size();
     while (*index < count) {
@@ -125,6 +125,9 @@ void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims, size_t* in
             protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_FIELD, fieldNum);
             switch (dim.mValue.getType()) {
                 case INT:
+                    if (isUidField(dim) || isAttributionUidField(dim)) {
+                        usedUids.insert(dim.mValue.int_value);
+                    }
                     protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_VALUE_INT,
                                        dim.mValue.int_value);
                     break;
@@ -161,7 +164,7 @@ void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims, size_t* in
             uint64_t tupleToken =
                     protoOutput->start(FIELD_TYPE_MESSAGE | DIMENSIONS_VALUE_VALUE_TUPLE);
             writeDimensionToProtoHelper(dims, index, valueDepth, dim.mField.getPrefix(valueDepth),
-                                        str_set, protoOutput);
+                                        str_set, usedUids, protoOutput);
             protoOutput->end(tupleToken);
             protoOutput->end(dimensionToken);
         } else {
@@ -174,7 +177,7 @@ void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims, size_t* in
 void writeDimensionLeafToProtoHelper(const std::vector<FieldValue>& dims,
                                      const int dimensionLeafField, size_t* index, int depth,
                                      int prefix, std::set<string>* str_set,
-                                     ProtoOutputStream* protoOutput) {
+                                     std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput) {
     size_t count = dims.size();
     while (*index < count) {
         const auto& dim = dims[*index];
@@ -191,6 +194,9 @@ void writeDimensionLeafToProtoHelper(const std::vector<FieldValue>& dims,
                                                 dimensionLeafField);
             switch (dim.mValue.getType()) {
                 case INT:
+                    if (isUidField(dim) || isAttributionUidField(dim)) {
+                        usedUids.insert(dim.mValue.int_value);
+                    }
                     protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_VALUE_INT,
                                        dim.mValue.int_value);
                     break;
@@ -220,9 +226,9 @@ void writeDimensionLeafToProtoHelper(const std::vector<FieldValue>& dims,
             }
             (*index)++;
         } else if (valueDepth == depth + 2 && valuePrefix == prefix) {
-            writeDimensionLeafToProtoHelper(dims, dimensionLeafField,
-                                            index, valueDepth, dim.mField.getPrefix(valueDepth),
-                                            str_set, protoOutput);
+            writeDimensionLeafToProtoHelper(dims, dimensionLeafField, index, valueDepth,
+                                            dim.mField.getPrefix(valueDepth), str_set, usedUids,
+                                            protoOutput);
         } else {
             // Done with the prev sub tree
             return;
@@ -272,8 +278,8 @@ void writeDimensionPathToProtoHelper(const std::vector<Matcher>& fieldMatchers,
 
 }  // namespace
 
-void writeDimensionToProto(const HashableDimensionKey& dimension, std::set<string> *str_set,
-                           ProtoOutputStream* protoOutput) {
+void writeDimensionToProto(const HashableDimensionKey& dimension, std::set<string>* str_set,
+                           std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput) {
     if (dimension.getValues().size() == 0) {
         return;
     }
@@ -281,20 +287,20 @@ void writeDimensionToProto(const HashableDimensionKey& dimension, std::set<strin
                        dimension.getValues()[0].mField.getTag());
     uint64_t topToken = protoOutput->start(FIELD_TYPE_MESSAGE | DIMENSIONS_VALUE_VALUE_TUPLE);
     size_t index = 0;
-    writeDimensionToProtoHelper(dimension.getValues(), &index, 0, 0, str_set, protoOutput);
+    writeDimensionToProtoHelper(dimension.getValues(), &index, 0, 0, str_set, usedUids,
+                                protoOutput);
     protoOutput->end(topToken);
 }
 
 void writeDimensionLeafNodesToProto(const HashableDimensionKey& dimension,
-                                    const int dimensionLeafFieldId,
-                                    std::set<string> *str_set,
-                                    ProtoOutputStream* protoOutput) {
+                                    const int dimensionLeafFieldId, std::set<string>* str_set,
+                                    std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput) {
     if (dimension.getValues().size() == 0) {
         return;
     }
     size_t index = 0;
-    writeDimensionLeafToProtoHelper(dimension.getValues(), dimensionLeafFieldId,
-                                    &index, 0, 0, str_set, protoOutput);
+    writeDimensionLeafToProtoHelper(dimension.getValues(), dimensionLeafFieldId, &index, 0, 0,
+                                    str_set, usedUids, protoOutput);
 }
 
 void writeDimensionPathToProto(const std::vector<Matcher>& fieldMatchers,
@@ -338,6 +344,7 @@ void writeDimensionPathToProto(const std::vector<Matcher>& fieldMatchers,
 //
 void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>& dims,
                                        size_t* index, int depth, int prefix,
+                                       std::set<int32_t>& usedUids,
                                        ProtoOutputStream* protoOutput) {
     size_t count = dims.size();
     while (*index < count) {
@@ -356,6 +363,9 @@ void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>&
         if ((depth == valueDepth || valueDepth == 1) && valuePrefix == prefix) {
             switch (dim.mValue.getType()) {
                 case INT:
+                    if (isUidField(dim) || isAttributionUidField(dim)) {
+                        usedUids.insert(dim.mValue.int_value);
+                    }
                     protoOutput->write(FIELD_TYPE_INT32 | repeatedFieldMask | fieldNum,
                                        dim.mValue.int_value);
                     break;
@@ -388,7 +398,8 @@ void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>&
             // Directly jump to the leaf value because the repeated position field is implied
             // by the position of the sub msg in the parent field.
             writeFieldValueTreeToStreamHelper(tagId, dims, index, valueDepth,
-                                              dim.mField.getPrefix(valueDepth), protoOutput);
+                                              dim.mField.getPrefix(valueDepth), usedUids,
+                                              protoOutput);
             if (msg_token != 0) {
                 protoOutput->end(msg_token);
             }
@@ -400,11 +411,12 @@ void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>&
 }
 
 void writeFieldValueTreeToStream(int tagId, const std::vector<FieldValue>& values,
+                                 std::set<int32_t>& usedUids,
                                  util::ProtoOutputStream* protoOutput) {
     uint64_t atomToken = protoOutput->start(FIELD_TYPE_MESSAGE | tagId);
 
     size_t index = 0;
-    writeFieldValueTreeToStreamHelper(tagId, values, &index, 0, 0, protoOutput);
+    writeFieldValueTreeToStreamHelper(tagId, values, &index, 0, 0, usedUids, protoOutput);
     protoOutput->end(atomToken);
 }
 
diff --git a/statsd/src/stats_log_util.h b/statsd/src/stats_log_util.h
index 5aa4c0b5..7bd99c5f 100644
--- a/statsd/src/stats_log_util.h
+++ b/statsd/src/stats_log_util.h
@@ -32,14 +32,14 @@ namespace os {
 namespace statsd {
 
 void writeFieldValueTreeToStream(int tagId, const std::vector<FieldValue>& values,
-                                 ProtoOutputStream* protoOutput);
-void writeDimensionToProto(const HashableDimensionKey& dimension, std::set<string> *str_set,
-                           ProtoOutputStream* protoOutput);
+                                 std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput);
+
+void writeDimensionToProto(const HashableDimensionKey& dimension, std::set<string>* str_set,
+                           std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput);
 
 void writeDimensionLeafNodesToProto(const HashableDimensionKey& dimension,
-                                    const int dimensionLeafFieldId,
-                                    std::set<string> *str_set,
-                                    ProtoOutputStream* protoOutput);
+                                    const int dimensionLeafFieldId, std::set<string>* str_set,
+                                    std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput);
 
 void writeDimensionPathToProto(const std::vector<Matcher>& fieldMatchers,
                                ProtoOutputStream* protoOutput);
diff --git a/statsd/src/stats_util.h b/statsd/src/stats_util.h
index fabb7e30..07464f0f 100644
--- a/statsd/src/stats_util.h
+++ b/statsd/src/stats_util.h
@@ -47,6 +47,8 @@ using ConditionLinks = google::protobuf::RepeatedPtrField<MetricConditionLink>;
 
 using StateLinks = google::protobuf::RepeatedPtrField<MetricStateLink>;
 
+using BinStarts = std::vector<float>;
+
 struct Empty {};
 
 inline bool isAtLeastS() {
diff --git a/statsd/src/statsd_config.proto b/statsd/src/statsd_config.proto
index 6b2c422e..13ed9c56 100644
--- a/statsd/src/statsd_config.proto
+++ b/statsd/src/statsd_config.proto
@@ -364,6 +364,11 @@ message GaugeMetric {
   reserved 101;
 }
 
+// Empty proto message to indicate that histogram bins are populated in the client process.
+// No additional configuration parameters are needed in this message.
+message ClientAggregatedBins {
+}
+
 message HistogramBinConfig {
   message ExplicitBins {
     repeated float bin = 1;
@@ -386,6 +391,7 @@ message HistogramBinConfig {
   oneof binning_strategy {
     GeneratedBins generated_bins = 2;
     ExplicitBins explicit_bins = 3;
+    ClientAggregatedBins client_aggregated_bins = 4;
   }
 }
 
@@ -676,6 +682,8 @@ message StatsdConfig {
   message StatsdConfigOptions {
     optional bool use_v2_soft_memory_limit = 1;
     optional bool omit_system_uids_in_uidmap = 2;
+    optional bool omit_unused_uids_in_uidmap = 3;
+    repeated string uidmap_package_allowlist = 4;
   }
 
   optional StatsdConfigOptions statsd_config_options = 30;
diff --git a/statsd/src/subscriber/IncidentdReporter.cpp b/statsd/src/subscriber/IncidentdReporter.cpp
index 979b32b6..ec85ec4f 100644
--- a/statsd/src/subscriber/IncidentdReporter.cpp
+++ b/statsd/src/subscriber/IncidentdReporter.cpp
@@ -77,7 +77,8 @@ void getProtoData(const int64_t& rule_id, int64_t metricId, const MetricDimensio
     // optional DimensionsValue dimension_in_what = 2;
     uint64_t dimToken =
             headerProto.start(FIELD_TYPE_MESSAGE | FIELD_ID_METRIC_VALUE_DIMENSION_IN_WHAT);
-    writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), nullptr, &headerProto);
+    set<int32_t> usedUids;
+    writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), nullptr, usedUids, &headerProto);
     headerProto.end(dimToken);
 
     // deprecated field
@@ -103,9 +104,10 @@ void getProtoData(const int64_t& rule_id, int64_t metricId, const MetricDimensio
     if (!uids.empty()) {
         uint64_t token = headerProto.start(FIELD_TYPE_MESSAGE | FIELD_ID_PACKAGE_INFO);
         UidMap::getInstance()->writeUidMapSnapshot(
-                getElapsedRealtimeNs(), true, true,
-                /*trucnatedCertificateHashSize*/ 0, /*omitSystemUids*/ false, uids,
-                nullptr /*installerIndices*/, nullptr /*string set*/, &headerProto);
+                getElapsedRealtimeNs(),
+                {true, true,
+                 /*truncatedCertificateHashSize*/ 0, /*omitSystemUids*/ false},
+                uids, nullptr /*installerIndices*/, nullptr /*string set*/, &headerProto);
         headerProto.end(token);
     }
 
diff --git a/statsd/statsd_test_default.map b/statsd/statsd_test_default.map
new file mode 100644
index 00000000..5157ea6e
--- /dev/null
+++ b/statsd/statsd_test_default.map
@@ -0,0 +1,20 @@
+#
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
+#
+{
+  local:
+    *;
+};
+
diff --git a/statsd/tests/DataCorruptionReason_test.cpp b/statsd/tests/DataCorruptionReason_test.cpp
index fee4b8a4..70e0dcf6 100644
--- a/statsd/tests/DataCorruptionReason_test.cpp
+++ b/statsd/tests/DataCorruptionReason_test.cpp
@@ -46,12 +46,15 @@ constexpr int64_t kAtomsLogTimeNs = kBucketStartTimeNs + 10;
 constexpr int64_t kReportRequestTimeNs = kBucketStartTimeNs + 100;
 
 constexpr int32_t kAppUid = AID_APP_START + 1;
-constexpr int32_t kAtomId = 2;
 constexpr int32_t kInterestAtomId = 3;
 constexpr int32_t kNotInterestedMetricId = 3;
-constexpr int32_t kInterestedMetricId = 4;
 constexpr int32_t kUnusedAtomId = kInterestAtomId + 100;
 
+const string kInterestAtomMatcherName = "CUSTOM_EVENT" + std::to_string(kInterestAtomId);
+const string kInterestedMetricName = "EVENT_METRIC_INTERESTED_IN_" + kInterestAtomMatcherName;
+
+const int64_t kInterestedMetricId = StringToId(kInterestedMetricName);
+
 const string kAppName = "TestApp";
 const set<int32_t> kAppUids = {kAppUid, kAppUid + 10000};
 const map<string, set<int32_t>> kPkgToUids = {{kAppName, kAppUids}};
@@ -61,36 +64,29 @@ StatsdConfig buildGoodEventConfig() {
     config.set_id(kConfigId);
 
     {
-        AtomMatcher* eventMatcher = config.add_atom_matcher();
-        eventMatcher->set_id(StringToId("SCREEN_IS_ON"));
-        SimpleAtomMatcher* simpleAtomMatcher = eventMatcher->mutable_simple_atom_matcher();
-        simpleAtomMatcher->set_atom_id(2 /*SCREEN_STATE_CHANGE*/);
-
-        EventMetric* metric = config.add_event_metric();
-        metric->set_id(kNotInterestedMetricId);
-        metric->set_what(StringToId("SCREEN_IS_ON"));
+        auto atomMatcher = CreateSimpleAtomMatcher("SCREEN_IS_ON", SCREEN_STATE_ATOM_ID);
+        *config.add_atom_matcher() = atomMatcher;
+        *config.add_event_metric() =
+                createEventMetric("EVENT_METRIC_SCREEN_IS_ON", atomMatcher.id(), std::nullopt);
     }
 
     {
-        const int64_t matcherId = StringToId("CUSTOM_EVENT" + std::to_string(kInterestAtomId));
-        AtomMatcher* eventMatcher = config.add_atom_matcher();
-        eventMatcher->set_id(matcherId);
-        SimpleAtomMatcher* simpleAtomMatcher = eventMatcher->mutable_simple_atom_matcher();
-        simpleAtomMatcher->set_atom_id(kInterestAtomId);
-
-        EventMetric* metric = config.add_event_metric();
-        metric->set_id(kInterestedMetricId);
-        metric->set_what(matcherId);
+        auto atomMatcher = CreateSimpleAtomMatcher(kInterestAtomMatcherName, kInterestAtomId);
+        *config.add_atom_matcher() = atomMatcher;
+        auto eventMetric = createEventMetric(kInterestedMetricName, atomMatcher.id(), std::nullopt);
+        *config.add_event_metric() = eventMetric;
+        EXPECT_EQ(eventMetric.id(), kInterestedMetricId);
     }
 
     return config;
 }
 
-ConfigMetricsReport getMetricsReport(MetricsManager& metricsManager) {
+ConfigMetricsReport getMetricsReport(MetricsManager& metricsManager, int64_t reportRequestTs) {
     ProtoOutputStream output;
-    metricsManager.onDumpReport(kReportRequestTimeNs, kReportRequestTimeNs,
+    set<int32_t> usedUids;
+    metricsManager.onDumpReport(reportRequestTs, reportRequestTs,
                                 /*include_current_partial_bucket*/ true, /*erase_data*/ true,
-                                /*dumpLatency*/ NO_TIME_CONSTRAINTS, nullptr, &output);
+                                /*dumpLatency*/ NO_TIME_CONSTRAINTS, nullptr, usedUids, &output);
 
     ConfigMetricsReport metricsReport;
     outputStreamToProto(&output, &metricsReport);
@@ -136,7 +132,7 @@ protected:
 
         // Test parametrized on allowed_atom (true/false)
         if (isAtomAllowedFromAnyUid()) {
-            config.add_whitelisted_atom_ids(kAtomId);
+            config.add_whitelisted_atom_ids(SCREEN_STATE_ATOM_ID);
             config.add_whitelisted_atom_ids(kInterestAtomId);
         }
 
@@ -175,6 +171,12 @@ protected:
     bool isAtomLoggingAllowed() const {
         return isAtomAllowedFromAnyUid() || isAtomFromAllowedUid();
     }
+
+public:
+    void doPropagationTest() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestNotifyOnlyInterestedMetrics() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestNotifyInterestedMetricsWithNewLoss() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestDoNotNotifyInterestedMetricsIfNoUpdate() __INTRODUCED_IN(__ANDROID_API_T__);
 };
 
 INSTANTIATE_TEST_SUITE_P(
@@ -192,7 +194,7 @@ INSTANTIATE_TEST_SUITE_P(
             return std::get<0>(info.param).label + std::get<1>(info.param).label;
         });
 
-TEST_P(SocketLossInfoTest, PropagationTest) {
+TEST_P_GUARDED(SocketLossInfoTest, PropagationTest, __ANDROID_API_T__) {
     LogEvent eventOfInterest(kAppUid /* uid */, 0 /* pid */);
     CreateNoValuesLogEvent(&eventOfInterest, kInterestAtomId /* atom id */, 0 /* timestamp */);
     EXPECT_EQ(mMetricsManager->checkLogCredentials(eventOfInterest), isAtomLoggingAllowed());
@@ -215,18 +217,18 @@ TEST_P(SocketLossInfoTest, PropagationTest) {
             EXPECT_EQ(metricProducer->mDataCorruptedDueToSocketLoss !=
                               MetricProducer::DataCorruptionSeverity::kNone,
                       isAtomLoggingAllowed());
-            continue;
+        } else {
+            EXPECT_EQ(metricProducer->mDataCorruptedDueToSocketLoss,
+                      MetricProducer::DataCorruptionSeverity::kNone);
         }
-        EXPECT_EQ(metricProducer->mDataCorruptedDueToSocketLoss,
-                  MetricProducer::DataCorruptionSeverity::kNone);
     }
 }
 
-TEST_P(SocketLossInfoTest, TestNotifyOnlyInterestedMetrics) {
+TEST_P_GUARDED(SocketLossInfoTest, TestNotifyOnlyInterestedMetrics, __ANDROID_API_T__) {
     const auto eventSocketLossReported = createSocketLossInfoLogEvent(kAppUid, kUnusedAtomId);
 
     mMetricsManager->onLogEvent(*eventSocketLossReported.get());
-    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager);
+    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     EXPECT_EQ(metricsReport.metrics_size(), 2);
     EXPECT_THAT(metricsReport.metrics(),
                 Each(Property(&StatsLogReport::data_corrupted_reason_size, 0)));
@@ -234,67 +236,67 @@ TEST_P(SocketLossInfoTest, TestNotifyOnlyInterestedMetrics) {
     const auto usedEventSocketLossReported = createSocketLossInfoLogEvent(kAppUid, kInterestAtomId);
     mMetricsManager->onLogEvent(*usedEventSocketLossReported.get());
 
-    metricsReport = getMetricsReport(*mMetricsManager);
+    metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs + 100);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
     for (const auto& statsLogReport : metricsReport.metrics()) {
         if (statsLogReport.metric_id() == kInterestedMetricId && isAtomLoggingAllowed()) {
-            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 1);
-            EXPECT_EQ(statsLogReport.data_corrupted_reason(0), DATA_CORRUPTED_SOCKET_LOSS);
-            continue;
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
         }
-        EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
     }
 }
 
-TEST_P(SocketLossInfoTest, TestNotifyInterestedMetricsWithNewLoss) {
+TEST_P_GUARDED(SocketLossInfoTest, TestNotifyInterestedMetricsWithNewLoss, __ANDROID_API_T__) {
     auto usedEventSocketLossReported = createSocketLossInfoLogEvent(kAppUid, kInterestAtomId);
     mMetricsManager->onLogEvent(*usedEventSocketLossReported.get());
 
-    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager);
+    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
     for (const auto& statsLogReport : metricsReport.metrics()) {
         if (statsLogReport.metric_id() == kInterestedMetricId && isAtomLoggingAllowed()) {
-            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 1);
-            EXPECT_EQ(statsLogReport.data_corrupted_reason(0), DATA_CORRUPTED_SOCKET_LOSS);
-            continue;
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
         }
-        EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
     }
 
     // new socket loss event as result event metric should be notified about loss again
     usedEventSocketLossReported = createSocketLossInfoLogEvent(kAppUid, kInterestAtomId);
     mMetricsManager->onLogEvent(*usedEventSocketLossReported.get());
 
-    metricsReport = getMetricsReport(*mMetricsManager);
+    metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs + 100);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
     for (const auto& statsLogReport : metricsReport.metrics()) {
         if (statsLogReport.metric_id() == kInterestedMetricId && isAtomLoggingAllowed()) {
-            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 1);
-            EXPECT_EQ(statsLogReport.data_corrupted_reason(0), DATA_CORRUPTED_SOCKET_LOSS);
-            continue;
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
         }
-        EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
     }
 }
 
-TEST_P(SocketLossInfoTest, TestDoNotNotifyInterestedMetricsIfNoUpdate) {
+TEST_P_GUARDED(SocketLossInfoTest, TestDoNotNotifyInterestedMetricsIfNoUpdate, __ANDROID_API_T__) {
     auto usedEventSocketLossReported = createSocketLossInfoLogEvent(kAppUid, kInterestAtomId);
     mMetricsManager->onLogEvent(*usedEventSocketLossReported.get());
 
-    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager);
+    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
     for (const auto& statsLogReport : metricsReport.metrics()) {
         if (statsLogReport.metric_id() == kInterestedMetricId && isAtomLoggingAllowed()) {
-            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 1);
-            EXPECT_EQ(statsLogReport.data_corrupted_reason(0), DATA_CORRUPTED_SOCKET_LOSS);
-            continue;
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
         }
-        EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
     }
 
     // no more dropped events as result event metric should not be notified about loss events
 
-    metricsReport = getMetricsReport(*mMetricsManager);
+    metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs + 100);
     EXPECT_EQ(metricsReport.metrics_size(), 2);
     EXPECT_THAT(metricsReport.metrics(),
                 Each(Property(&StatsLogReport::data_corrupted_reason_size, 0)));
@@ -309,15 +311,13 @@ protected:
 
         sp<UidMap> uidMap;
         sp<StatsPullerManager> pullerManager = new StatsPullerManager();
-        sp<AlarmMonitor> anomalyAlarmMonitor;
-        sp<AlarmMonitor> periodicAlarmMonitor;
 
         // there will be one event metric interested in kInterestAtomId
         StatsdConfig config = buildGoodEventConfig();
 
-        mMetricsManager = std::make_shared<MetricsManager>(
-                kConfigKey, config, kTimeBaseSec, kTimeBaseSec, uidMap, pullerManager,
-                anomalyAlarmMonitor, periodicAlarmMonitor);
+        mMetricsManager =
+                std::make_shared<MetricsManager>(kConfigKey, config, kTimeBaseSec, kTimeBaseSec,
+                                                 uidMap, pullerManager, nullptr, nullptr);
 
         EXPECT_TRUE(mMetricsManager->isConfigValid());
     }
@@ -335,18 +335,19 @@ TEST_F(DataCorruptionQueueOverflowTest, TestNotifyOnlyInterestedMetrics) {
                                                       /*isSkipped*/ false);
 
     EXPECT_TRUE(mMetricsManager->mQueueOverflowAtomsStats.empty());
-    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager);
+    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
-    ASSERT_EQ(mMetricsManager->mQueueOverflowAtomsStats.size(), 1);
-    EXPECT_EQ(mMetricsManager->mQueueOverflowAtomsStats[kInterestAtomId], 1);
+    EXPECT_THAT(mMetricsManager->mQueueOverflowAtomsStats,
+                UnorderedElementsAre(std::make_pair(kInterestAtomId, 1),
+                                     std::make_pair(kUnusedAtomId, 1)));
 
     for (const auto& statsLogReport : metricsReport.metrics()) {
         if (statsLogReport.metric_id() == kInterestedMetricId) {
-            ASSERT_EQ(statsLogReport.data_corrupted_reason_size(), 1);
-            EXPECT_EQ(statsLogReport.data_corrupted_reason(0), DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW);
-            continue;
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
         }
-        EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
     }
 }
 
@@ -354,36 +355,36 @@ TEST_F(DataCorruptionQueueOverflowTest, TestNotifyInterestedMetricsWithNewLoss)
     StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId,
                                                       /*isSkipped*/ false);
 
-    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager);
+    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
     ASSERT_EQ(mMetricsManager->mQueueOverflowAtomsStats.size(), 1);
     EXPECT_EQ(mMetricsManager->mQueueOverflowAtomsStats[kInterestAtomId], 1);
 
     for (const auto& statsLogReport : metricsReport.metrics()) {
         if (statsLogReport.metric_id() == kInterestedMetricId) {
-            ASSERT_EQ(statsLogReport.data_corrupted_reason_size(), 1);
-            EXPECT_EQ(statsLogReport.data_corrupted_reason(0), DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW);
-            continue;
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
         }
-        EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
     }
 
     // new dropped event as result event metric should be notified about loss events
-    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs + 100, kInterestAtomId,
+    StatsdStats::getInstance().noteEventQueueOverflow(kReportRequestTimeNs + 100, kInterestAtomId,
                                                       /*isSkipped*/ false);
 
-    metricsReport = getMetricsReport(*mMetricsManager);
+    metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs + 200);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
     ASSERT_EQ(mMetricsManager->mQueueOverflowAtomsStats.size(), 1);
     EXPECT_EQ(mMetricsManager->mQueueOverflowAtomsStats[kInterestAtomId], 2);
 
     for (const auto& statsLogReport : metricsReport.metrics()) {
         if (statsLogReport.metric_id() == kInterestedMetricId) {
-            ASSERT_EQ(statsLogReport.data_corrupted_reason_size(), 1);
-            EXPECT_EQ(statsLogReport.data_corrupted_reason(0), DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW);
-            continue;
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
         }
-        EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
     }
 }
 
@@ -391,23 +392,23 @@ TEST_F(DataCorruptionQueueOverflowTest, TestDoNotNotifyInterestedMetricsIfNoUpda
     StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId,
                                                       /*isSkipped*/ false);
 
-    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager);
+    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
     ASSERT_EQ(mMetricsManager->mQueueOverflowAtomsStats.size(), 1);
     EXPECT_EQ(mMetricsManager->mQueueOverflowAtomsStats[kInterestAtomId], 1);
 
     for (const auto& statsLogReport : metricsReport.metrics()) {
         if (statsLogReport.metric_id() == kInterestedMetricId) {
-            ASSERT_EQ(statsLogReport.data_corrupted_reason_size(), 1);
-            EXPECT_EQ(statsLogReport.data_corrupted_reason(0), DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW);
-            continue;
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
         }
-        EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
     }
 
     // no more dropped events as result event metric should not be notified about loss events
 
-    metricsReport = getMetricsReport(*mMetricsManager);
+    metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs + 100);
     ASSERT_EQ(mMetricsManager->mQueueOverflowAtomsStats.size(), 1);
     EXPECT_EQ(mMetricsManager->mQueueOverflowAtomsStats[kInterestAtomId], 1);
     EXPECT_EQ(metricsReport.metrics_size(), 2);
@@ -415,6 +416,157 @@ TEST_F(DataCorruptionQueueOverflowTest, TestDoNotNotifyInterestedMetricsIfNoUpda
                 Each(Property(&StatsLogReport::data_corrupted_reason_size, 0)));
 }
 
+TEST_F(DataCorruptionQueueOverflowTest, TestDoNotNotifyNewInterestedMetricsIfNoUpdate) {
+    const int32_t kNewInterestAtomId = kUnusedAtomId + 1;
+
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId,
+                                                      /*isSkipped*/ false);
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kNewInterestAtomId,
+                                                      /*isSkipped*/ false);
+
+    ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
+    ASSERT_EQ(metricsReport.metrics_size(), 2);
+    EXPECT_THAT(mMetricsManager->mQueueOverflowAtomsStats,
+                UnorderedElementsAre(std::make_pair(kInterestAtomId, 1),
+                                     std::make_pair(kNewInterestAtomId, 1)));
+
+    for (const auto& statsLogReport : metricsReport.metrics()) {
+        if (statsLogReport.metric_id() == kInterestedMetricId) {
+            EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                        ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+        } else {
+            EXPECT_EQ(statsLogReport.data_corrupted_reason_size(), 0);
+        }
+    }
+
+    // adding 2 more metrics interested in atoms to update existing config
+    // new metrics should not be updated with loss atom info from queue overflow
+    // since atom loss events happen before metrics were added
+    {
+        StatsdConfig config = buildGoodEventConfig();
+        const int64_t matcherId = StringToId(kInterestAtomMatcherName);
+        *config.add_event_metric() =
+                createEventMetric("EVENT_METRIC_FOR_EXISTING_ATOM", matcherId, std::nullopt);
+
+        // adding new metric which is interested on unused atom before
+        // for which lost event was detected
+        auto atomMatcher = CreateSimpleAtomMatcher("NewTestMatcher", kNewInterestAtomId);
+        *config.add_atom_matcher() = atomMatcher;
+        *config.add_event_metric() =
+                createEventMetric("EVENT_METRIC_FOR_NEW_ATOM", atomMatcher.id(), std::nullopt);
+
+        mMetricsManager->updateConfig(config, kReportRequestTimeNs + 100,
+                                      kReportRequestTimeNs + 100, nullptr, nullptr);
+    }
+
+    // no more dropped events as result event metric should not be notified about loss events
+
+    metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs + 200);
+    EXPECT_THAT(mMetricsManager->mQueueOverflowAtomsStats,
+                UnorderedElementsAre(std::make_pair(kInterestAtomId, 1),
+                                     std::make_pair(kNewInterestAtomId, 1)));
+    EXPECT_EQ(metricsReport.metrics_size(), 4);
+    EXPECT_THAT(metricsReport.metrics(),
+                Each(Property(&StatsLogReport::data_corrupted_reason_size, 0)));
+}
+
+TEST_GUARDED(DataCorruptionTest, TestStateLostPropagation, __ANDROID_API_T__) {
+    // Initialize config with state and count metric
+    StatsdConfig config;
+
+    auto syncStartMatcher = CreateSyncStartAtomMatcher();
+    *config.add_atom_matcher() = syncStartMatcher;
+
+    auto state = CreateScreenState();
+    *config.add_state() = state;
+
+    // Create count metric that slices by screen state.
+    auto countMetric = config.add_count_metric();
+    countMetric->set_id(kNotInterestedMetricId);
+    countMetric->set_what(syncStartMatcher.id());
+    countMetric->set_bucket(TimeUnit::FIVE_MINUTES);
+    countMetric->add_slice_by_state(state.id());
+
+    // Initialize StatsLogProcessor.
+    const uint64_t bucketSizeNs =
+            TimeUnitToBucketSizeInMillis(config.count_metric(0).bucket()) * 1000000LL;
+    int uid = 12345;
+    int64_t cfgId = 98765;
+    ConfigKey cfgKey(uid, cfgId);
+    auto processor =
+            CreateStatsLogProcessor(kBucketStartTimeNs, kBucketStartTimeNs, config, cfgKey);
+
+    // Check that CountMetricProducer was initialized correctly.
+    ASSERT_EQ(processor->mMetricsManagers.size(), 1u);
+    sp<MetricsManager> metricsManager = processor->mMetricsManagers.begin()->second;
+    EXPECT_TRUE(metricsManager->isConfigValid());
+
+    // Check that StateTrackers were initialized correctly.
+    EXPECT_EQ(1, StateManager::getInstance().getStateTrackersCount());
+    EXPECT_EQ(1, StateManager::getInstance().getListenersCount(SCREEN_STATE_ATOM_ID));
+
+    auto usedEventSocketLossReported =
+            createSocketLossInfoLogEvent(AID_SYSTEM, SCREEN_STATE_ATOM_ID);
+    processor->OnLogEvent(usedEventSocketLossReported.get());
+
+    ConfigMetricsReport metricsReport = getMetricsReport(*metricsManager, kReportRequestTimeNs);
+    ASSERT_EQ(metricsReport.metrics_size(), 1);
+    const auto& statsLogReport = metricsReport.metrics(0);
+    EXPECT_THAT(statsLogReport.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+}
+
+TEST(DataCorruptionTest, TestStateLostFromQueueOverflowPropagation) {
+    // Initialize config with state and count metric
+    StatsdConfig config;
+
+    auto syncStartMatcher = CreateSyncStartAtomMatcher();
+    *config.add_atom_matcher() = syncStartMatcher;
+
+    auto state = CreateScreenState();
+    *config.add_state() = state;
+
+    // Create count metric that slices by screen state.
+    auto countMetric = config.add_count_metric();
+    countMetric->set_id(kNotInterestedMetricId);
+    countMetric->set_what(syncStartMatcher.id());
+    countMetric->set_bucket(TimeUnit::FIVE_MINUTES);
+    countMetric->add_slice_by_state(state.id());
+
+    // Initialize StatsLogProcessor.
+    const uint64_t bucketSizeNs =
+            TimeUnitToBucketSizeInMillis(config.count_metric(0).bucket()) * 1000000LL;
+    int uid = 12345;
+    int64_t cfgId = 98765;
+    ConfigKey cfgKey(uid, cfgId);
+    auto processor =
+            CreateStatsLogProcessor(kBucketStartTimeNs, kBucketStartTimeNs, config, cfgKey);
+
+    // Check that CountMetricProducer was initialized correctly.
+    ASSERT_EQ(processor->mMetricsManagers.size(), 1u);
+    sp<MetricsManager> metricsManager = processor->mMetricsManagers.begin()->second;
+    EXPECT_TRUE(metricsManager->isConfigValid());
+
+    // Check that StateTrackers were initialized correctly.
+    EXPECT_EQ(1, StateManager::getInstance().getStateTrackersCount());
+    EXPECT_EQ(1, StateManager::getInstance().getListenersCount(SCREEN_STATE_ATOM_ID));
+
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, SCREEN_STATE_ATOM_ID,
+                                                      /*isSkipped*/ false);
+
+    vector<uint8_t> buffer;
+    ConfigMetricsReportList reports;
+    processor->onDumpReport(cfgKey, kBucketStartTimeNs + bucketSizeNs * 2 + 1, false, true,
+                            ADB_DUMP, FAST, &buffer);
+    ASSERT_GT(buffer.size(), 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    ASSERT_EQ(1, reports.reports_size());
+    const ConfigMetricsReport metricsReport = reports.reports(0);
+    ASSERT_EQ(metricsReport.metrics_size(), 1);
+    const auto& statsLogReport = metricsReport.metrics(0);
+    EXPECT_THAT(statsLogReport.data_corrupted_reason(),
+                ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/FieldValue_test.cpp b/statsd/tests/FieldValue_test.cpp
index 8e9f789e..32940544 100644
--- a/statsd/tests/FieldValue_test.cpp
+++ b/statsd/tests/FieldValue_test.cpp
@@ -61,8 +61,8 @@ void makeLogEvent(LogEvent* logEvent, const int32_t atomId, const int64_t timest
     parseStatsEventToLogEvent(statsEvent, logEvent);
 }
 
-void makeRepeatedIntLogEvent(LogEvent* logEvent, const int32_t atomId,
-                             const vector<int>& intArray) {
+void makeRepeatedIntLogEvent(LogEvent* logEvent, const int32_t atomId, const vector<int>& intArray)
+        __INTRODUCED_IN(__ANDROID_API_T__) {
     AStatsEvent* statsEvent = AStatsEvent_obtain();
     AStatsEvent_setAtomId(statsEvent, atomId);
     AStatsEvent_writeInt32Array(statsEvent, intArray.data(), intArray.size());
@@ -192,7 +192,7 @@ TEST(AtomMatcherTest, TestFilter_FIRST) {
     EXPECT_EQ("some value", output.getValues()[2].mValue.str_value);
 };
 
-TEST(AtomMatcherTest, TestFilterRepeated_FIRST) {
+TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_FIRST, __ANDROID_API_T__) {
     FieldMatcher matcher;
     matcher.set_field(123);
     FieldMatcher* child = matcher.add_child();
@@ -214,7 +214,7 @@ TEST(AtomMatcherTest, TestFilterRepeated_FIRST) {
     EXPECT_EQ((int32_t)21, output.getValues()[0].mValue.int_value);
 }
 
-TEST(AtomMatcherTest, TestFilterRepeated_LAST) {
+TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_LAST, __ANDROID_API_T__) {
     FieldMatcher matcher;
     matcher.set_field(123);
     FieldMatcher* child = matcher.add_child();
@@ -236,7 +236,7 @@ TEST(AtomMatcherTest, TestFilterRepeated_LAST) {
     EXPECT_EQ((int32_t)13, output.getValues()[0].mValue.int_value);
 }
 
-TEST(AtomMatcherTest, TestFilterRepeated_ALL) {
+TEST_GUARDED(AtomMatcherTest, TestFilterRepeated_ALL, __ANDROID_API_T__) {
     FieldMatcher matcher;
     matcher.set_field(123);
     FieldMatcher* child = matcher.add_child();
@@ -753,7 +753,8 @@ TEST(AtomMatcherTest, TestWriteDimensionToProto) {
     dim.addValue(FieldValue(field4, value4));
 
     android::util::ProtoOutputStream protoOut;
-    writeDimensionToProto(dim, nullptr /* include strings */, &protoOut);
+    set<int32_t> usedUids;
+    writeDimensionToProto(dim, nullptr /* include strings */, usedUids, &protoOut);
 
     vector<uint8_t> outData;
     outData.resize(protoOut.size());
@@ -815,7 +816,8 @@ TEST(AtomMatcherTest, TestWriteDimensionLeafNodesToProto) {
     dim.addValue(FieldValue(field4, value4));
 
     android::util::ProtoOutputStream protoOut;
-    writeDimensionLeafNodesToProto(dim, 1, nullptr /* include strings */, &protoOut);
+    set<int32_t> usedUids;
+    writeDimensionLeafNodesToProto(dim, 1, nullptr /* include strings */, usedUids, &protoOut);
 
     vector<uint8_t> outData;
     outData.resize(protoOut.size());
@@ -857,7 +859,8 @@ TEST(AtomMatcherTest, TestWriteAtomToProto) {
     makeLogEvent(&event, 4 /*atomId*/, 12345, attributionUids, attributionTags, 999);
 
     android::util::ProtoOutputStream protoOutput;
-    writeFieldValueTreeToStream(event.GetTagId(), event.getValues(), &protoOutput);
+    set<int32_t> usedUids;
+    writeFieldValueTreeToStream(event.GetTagId(), event.getValues(), usedUids, &protoOutput);
 
     vector<uint8_t> outData;
     outData.resize(protoOutput.size());
@@ -882,7 +885,7 @@ TEST(AtomMatcherTest, TestWriteAtomToProto) {
     EXPECT_EQ(999, atom.num_results());
 }
 
-TEST(AtomMatcherTest, TestWriteAtomWithRepeatedFieldsToProto) {
+TEST_GUARDED(AtomMatcherTest, TestWriteAtomWithRepeatedFieldsToProto, __ANDROID_API_T__) {
     vector<int> intArray = {3, 6};
     vector<int64_t> longArray = {1000L, 10002L};
     vector<float> floatArray = {0.3f, 0.09f};
@@ -899,7 +902,8 @@ TEST(AtomMatcherTest, TestWriteAtomWithRepeatedFieldsToProto) {
             enumArray);
 
     android::util::ProtoOutputStream protoOutput;
-    writeFieldValueTreeToStream(event->GetTagId(), event->getValues(), &protoOutput);
+    set<int32_t> usedUids;
+    writeFieldValueTreeToStream(event->GetTagId(), event->getValues(), usedUids, &protoOutput);
 
     vector<uint8_t> outData;
     outData.resize(protoOutput.size());
diff --git a/statsd/tests/LogEntryMatcher_test.cpp b/statsd/tests/LogEntryMatcher_test.cpp
index 75ec3b50..e989c9b9 100644
--- a/statsd/tests/LogEntryMatcher_test.cpp
+++ b/statsd/tests/LogEntryMatcher_test.cpp
@@ -108,16 +108,16 @@ void makeBoolLogEvent(LogEvent* logEvent, const int32_t atomId, const int64_t ti
     parseStatsEventToLogEvent(statsEvent, logEvent);
 }
 
-void makeRepeatedIntLogEvent(LogEvent* logEvent, const int32_t atomId,
-                             const vector<int>& intArray) {
+void makeRepeatedIntLogEvent(LogEvent* logEvent, const int32_t atomId, const vector<int>& intArray)
+        __INTRODUCED_IN(__ANDROID_API_T__) {
     AStatsEvent* statsEvent = AStatsEvent_obtain();
     AStatsEvent_setAtomId(statsEvent, atomId);
     AStatsEvent_writeInt32Array(statsEvent, intArray.data(), intArray.size());
     parseStatsEventToLogEvent(statsEvent, logEvent);
 }
 
-void makeRepeatedUidLogEvent(LogEvent* logEvent, const int32_t atomId,
-                             const vector<int>& intArray) {
+void makeRepeatedUidLogEvent(LogEvent* logEvent, const int32_t atomId, const vector<int>& intArray)
+        __INTRODUCED_IN(__ANDROID_API_T__) {
     AStatsEvent* statsEvent = AStatsEvent_obtain();
     AStatsEvent_setAtomId(statsEvent, atomId);
     AStatsEvent_writeInt32Array(statsEvent, intArray.data(), intArray.size());
@@ -126,7 +126,8 @@ void makeRepeatedUidLogEvent(LogEvent* logEvent, const int32_t atomId,
 }
 
 void makeRepeatedStringLogEvent(LogEvent* logEvent, const int32_t atomId,
-                                const vector<string>& stringArray) {
+                                const vector<string>& stringArray)
+        __INTRODUCED_IN(__ANDROID_API_T__) {
     vector<const char*> cStringArray(stringArray.size());
     for (int i = 0; i < cStringArray.size(); i++) {
         cStringArray[i] = stringArray[i].c_str();
@@ -424,7 +425,7 @@ TEST(AtomMatcherTest, TestUidFieldMatcher) {
     EXPECT_FALSE(matchesSimple(uidMap, *simpleMatcher, event2).matched);
 }
 
-TEST(AtomMatcherTest, TestRepeatedUidFieldMatcher) {
+TEST_GUARDED(AtomMatcherTest, TestRepeatedUidFieldMatcher, __ANDROID_API_T__) {
     sp<UidMap> uidMap = new UidMap();
 
     UidData uidData;
@@ -689,7 +690,7 @@ TEST(AtomMatcherTest, TestStringMatcher) {
     EXPECT_TRUE(matchesSimple(uidMap, *simpleMatcher, event).matched);
 }
 
-TEST(AtomMatcherTest, TestIntMatcher_EmptyRepeatedField) {
+TEST_GUARDED(AtomMatcherTest, TestIntMatcher_EmptyRepeatedField, __ANDROID_API_T__) {
     sp<UidMap> uidMap = new UidMap();
 
     // Set up the log event.
@@ -718,7 +719,7 @@ TEST(AtomMatcherTest, TestIntMatcher_EmptyRepeatedField) {
     EXPECT_FALSE(matchesSimple(uidMap, *simpleMatcher, event).matched);
 }
 
-TEST(AtomMatcherTest, TestIntMatcher_RepeatedIntField) {
+TEST_GUARDED(AtomMatcherTest, TestIntMatcher_RepeatedIntField, __ANDROID_API_T__) {
     sp<UidMap> uidMap = new UidMap();
 
     // Set up the log event.
@@ -760,7 +761,7 @@ TEST(AtomMatcherTest, TestIntMatcher_RepeatedIntField) {
     EXPECT_TRUE(matchesSimple(uidMap, *simpleMatcher, event).matched);
 }
 
-TEST(AtomMatcherTest, TestLtIntMatcher_RepeatedIntField) {
+TEST_GUARDED(AtomMatcherTest, TestLtIntMatcher_RepeatedIntField, __ANDROID_API_T__) {
     sp<UidMap> uidMap = new UidMap();
 
     // Set up the log event.
@@ -808,7 +809,7 @@ TEST(AtomMatcherTest, TestLtIntMatcher_RepeatedIntField) {
     EXPECT_TRUE(matchesSimple(uidMap, *simpleMatcher, event).matched);
 }
 
-TEST(AtomMatcherTest, TestStringMatcher_RepeatedStringField) {
+TEST_GUARDED(AtomMatcherTest, TestStringMatcher_RepeatedStringField, __ANDROID_API_T__) {
     sp<UidMap> uidMap = new UidMap();
 
     // Set up the log event.
@@ -853,7 +854,7 @@ TEST(AtomMatcherTest, TestStringMatcher_RepeatedStringField) {
     EXPECT_TRUE(matchesSimple(uidMap, *simpleMatcher, event).matched);
 }
 
-TEST(AtomMatcherTest, TestEqAnyStringMatcher_RepeatedStringField) {
+TEST_GUARDED(AtomMatcherTest, TestEqAnyStringMatcher_RepeatedStringField, __ANDROID_API_T__) {
     sp<UidMap> uidMap = new UidMap();
 
     // Set up the log event.
@@ -910,7 +911,7 @@ TEST(AtomMatcherTest, TestEqAnyStringMatcher_RepeatedStringField) {
     EXPECT_TRUE(matchesSimple(uidMap, *simpleMatcher, event).matched);
 }
 
-TEST(AtomMatcherTest, TestNeqAnyStringMatcher_RepeatedStringField) {
+TEST_GUARDED(AtomMatcherTest, TestNeqAnyStringMatcher_RepeatedStringField, __ANDROID_API_T__) {
     sp<UidMap> uidMap = new UidMap();
 
     // Set up the log event.
diff --git a/statsd/tests/LogEvent_test.cpp b/statsd/tests/LogEvent_test.cpp
index 27f2d52d..292eea16 100644
--- a/statsd/tests/LogEvent_test.cpp
+++ b/statsd/tests/LogEvent_test.cpp
@@ -193,6 +193,20 @@ public:
     static std::string ToString(testing::TestParamInfo<bool> info) {
         return info.param ? "PrefetchTrue" : "PrefetchFalse";
     }
+
+public:
+    void doTestArrayParsing() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestEmptyStringArray() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestArrayTooManyElements() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestEmptyArray() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestEmptyArrayWithAnnotations() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestAnnotationIdIsUid_RepeatedIntAndOtherFields() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestAnnotationIdIsUid_RepeatedIntOneEntry() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestAnnotationIdIsUid_EmptyIntArray() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestAnnotationIdIsUid_BadRepeatedInt64() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestAnnotationIdIsUid_BadRepeatedString() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestUidAnnotationWithInt8MaxValues() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestInvalidBufferParsing() __INTRODUCED_IN(__ANDROID_API_T__);
 };
 
 INSTANTIATE_TEST_SUITE_P(LogEventTestBufferParsing, LogEventTest, testing::Bool(),
@@ -519,7 +533,7 @@ TEST_P(LogEventTest, TestAttributionChainTooManyElements) {
     AStatsEvent_release(event);
 }
 
-TEST_P(LogEventTest, TestArrayParsing) {
+TEST_P_GUARDED(LogEventTest, TestArrayParsing, __ANDROID_API_T__) {
     size_t numElements = 2;
     int32_t int32Array[2] = {3, 6};
     int64_t int64Array[2] = {1000L, 1002L};
@@ -618,7 +632,7 @@ TEST_P(LogEventTest, TestArrayParsing) {
     EXPECT_EQ("str2", stringArrayItem2.mValue.str_value);
 }
 
-TEST_P(LogEventTest, TestEmptyStringArray) {
+TEST_P_GUARDED(LogEventTest, TestEmptyStringArray, __ANDROID_API_T__) {
     const char* cStringArray[2];
     string empty = "";
     cStringArray[0] = empty.c_str();
@@ -657,7 +671,7 @@ TEST_P(LogEventTest, TestEmptyStringArray) {
     AStatsEvent_release(event);
 }
 
-TEST_P(LogEventTest, TestArrayTooManyElements) {
+TEST_P_GUARDED(LogEventTest, TestArrayTooManyElements, __ANDROID_API_T__) {
     int32_t numElements = 128;
     int32_t int32Array[numElements];
 
@@ -679,7 +693,7 @@ TEST_P(LogEventTest, TestArrayTooManyElements) {
     AStatsEvent_release(event);
 }
 
-TEST_P(LogEventTest, TestEmptyArray) {
+TEST_P_GUARDED(LogEventTest, TestEmptyArray, __ANDROID_API_T__) {
     int32_t int32Array[0] = {};
 
     AStatsEvent* event = AStatsEvent_obtain();
@@ -702,7 +716,7 @@ TEST_P(LogEventTest, TestEmptyArray) {
     AStatsEvent_release(event);
 }
 
-TEST_P(LogEventTest, TestEmptyArrayWithAnnotations) {
+TEST_P_GUARDED(LogEventTest, TestEmptyArrayWithAnnotations, __ANDROID_API_T__) {
     int32_t int32Array[0] = {};
 
     AStatsEvent* event = AStatsEvent_obtain();
@@ -739,7 +753,7 @@ TEST_P(LogEventTest, TestAnnotationIdIsUid) {
     EXPECT_TRUE(isUidField(values.at(0)));
 }
 
-TEST_P(LogEventTest, TestAnnotationIdIsUid_RepeatedIntAndOtherFields) {
+TEST_P_GUARDED(LogEventTest, TestAnnotationIdIsUid_RepeatedIntAndOtherFields, __ANDROID_API_T__) {
     size_t numElements = 2;
     int32_t int32Array[2] = {3, 6};
 
@@ -772,7 +786,7 @@ TEST_P(LogEventTest, TestAnnotationIdIsUid_RepeatedIntAndOtherFields) {
     EXPECT_FALSE(isUidField(values.at(4)));
 }
 
-TEST_P(LogEventTest, TestAnnotationIdIsUid_RepeatedIntOneEntry) {
+TEST_P_GUARDED(LogEventTest, TestAnnotationIdIsUid_RepeatedIntOneEntry, __ANDROID_API_T__) {
     size_t numElements = 1;
     int32_t int32Array[1] = {3};
 
@@ -793,7 +807,7 @@ TEST_P(LogEventTest, TestAnnotationIdIsUid_RepeatedIntOneEntry) {
     EXPECT_TRUE(isUidField(values.at(0)));
 }
 
-TEST_P(LogEventTest, TestAnnotationIdIsUid_EmptyIntArray) {
+TEST_P_GUARDED(LogEventTest, TestAnnotationIdIsUid_EmptyIntArray, __ANDROID_API_T__) {
     int32_t int32Array[0] = {};
 
     AStatsEvent* statsEvent = AStatsEvent_obtain();
@@ -813,7 +827,7 @@ TEST_P(LogEventTest, TestAnnotationIdIsUid_EmptyIntArray) {
     EXPECT_EQ(values.size(), 1);
 }
 
-TEST_P(LogEventTest, TestAnnotationIdIsUid_BadRepeatedInt64) {
+TEST_P_GUARDED(LogEventTest, TestAnnotationIdIsUid_BadRepeatedInt64, __ANDROID_API_T__) {
     int64_t int64Array[2] = {1000L, 1002L};
 
     AStatsEvent* statsEvent = AStatsEvent_obtain();
@@ -832,7 +846,7 @@ TEST_P(LogEventTest, TestAnnotationIdIsUid_BadRepeatedInt64) {
     AStatsEvent_release(statsEvent);
 }
 
-TEST_P(LogEventTest, TestAnnotationIdIsUid_BadRepeatedString) {
+TEST_P_GUARDED(LogEventTest, TestAnnotationIdIsUid_BadRepeatedString, __ANDROID_API_T__) {
     size_t numElements = 2;
     vector<string> stringArray = {"str1", "str2"};
     const char* cStringArray[2];
@@ -887,7 +901,8 @@ TEST_P(LogEventTest, TestAnnotationIdStateNested) {
 TEST_P(LogEventTestBadAnnotationFieldTypes, TestAnnotationIdStateNested) {
     LogEvent event(/*uid=*/0, /*pid=*/0);
 
-    if (std::get<0>(GetParam()) != INT32_TYPE) {
+    if (std::get<0>(GetParam()) != INT32_TYPE &&
+        (std::get<0>(GetParam()) != LIST_TYPE || isAtLeastT())) {
         EXPECT_FALSE(createFieldWithBoolAnnotationLogEvent(
                 &event, std::get<0>(GetParam()), ASTATSLOG_ANNOTATION_ID_STATE_NESTED, true,
                 /*doHeaderPrefetch=*/std::get<1>(GetParam())));
@@ -915,7 +930,8 @@ TEST_P(LogEventTest, TestPrimaryFieldAnnotation) {
 TEST_P(LogEventTestBadAnnotationFieldTypes, TestPrimaryFieldAnnotation) {
     LogEvent event(/*uid=*/0, /*pid=*/0);
 
-    if (std::get<0>(GetParam()) == LIST_TYPE || std::get<0>(GetParam()) == ATTRIBUTION_CHAIN_TYPE) {
+    if ((std::get<0>(GetParam()) == LIST_TYPE && isAtLeastT()) ||
+        std::get<0>(GetParam()) == ATTRIBUTION_CHAIN_TYPE) {
         EXPECT_FALSE(createFieldWithBoolAnnotationLogEvent(
                 &event, std::get<0>(GetParam()), ASTATSLOG_ANNOTATION_ID_PRIMARY_FIELD, true,
                 /*doHeaderPrefetch=*/std::get<1>(GetParam())));
@@ -943,7 +959,8 @@ TEST_P(LogEventTest, TestExclusiveStateAnnotation) {
 TEST_P(LogEventTestBadAnnotationFieldTypes, TestExclusiveStateAnnotation) {
     LogEvent event(/*uid=*/0, /*pid=*/0);
 
-    if (std::get<0>(GetParam()) != INT32_TYPE) {
+    if (std::get<0>(GetParam()) != INT32_TYPE &&
+        (std::get<0>(GetParam()) != LIST_TYPE || isAtLeastT())) {
         EXPECT_FALSE(createFieldWithBoolAnnotationLogEvent(
                 &event, std::get<0>(GetParam()), ASTATSLOG_ANNOTATION_ID_EXCLUSIVE_STATE, true,
                 /*doHeaderPrefetch=*/std::get<1>(GetParam())));
@@ -993,7 +1010,8 @@ TEST_P(LogEventTest, TestPrimaryFieldFirstUidAnnotation) {
 TEST_P(LogEventTestBadAnnotationFieldTypes, TestPrimaryFieldFirstUidAnnotation) {
     LogEvent event(/*uid=*/0, /*pid=*/0);
 
-    if (std::get<0>(GetParam()) != ATTRIBUTION_CHAIN_TYPE) {
+    if (std::get<0>(GetParam()) != ATTRIBUTION_CHAIN_TYPE &&
+        (std::get<0>(GetParam()) != LIST_TYPE || isAtLeastT())) {
         EXPECT_FALSE(createFieldWithBoolAnnotationLogEvent(
                 &event, std::get<0>(GetParam()), ASTATSLOG_ANNOTATION_ID_PRIMARY_FIELD_FIRST_UID,
                 true,
@@ -1059,7 +1077,8 @@ TEST_P(LogEventTestBadAnnotationFieldTypes, TestResetStateAnnotation) {
     LogEvent event(/*uid=*/0, /*pid=*/0);
     int32_t resetState = 10;
 
-    if (std::get<0>(GetParam()) != INT32_TYPE) {
+    if (std::get<0>(GetParam()) != INT32_TYPE &&
+        (std::get<0>(GetParam()) != LIST_TYPE || isAtLeastT())) {
         EXPECT_FALSE(createFieldWithIntAnnotationLogEvent(
                 &event, std::get<0>(GetParam()), ASTATSLOG_ANNOTATION_ID_TRIGGER_STATE_RESET,
                 resetState,
@@ -1074,7 +1093,7 @@ TEST_P(LogEventTest, TestResetStateAnnotation_NotBoolAnnotation) {
             /*doHeaderPrefetch=*/GetParam()));
 }
 
-TEST_P(LogEventTest, TestUidAnnotationWithInt8MaxValues) {
+TEST_P_GUARDED(LogEventTest, TestUidAnnotationWithInt8MaxValues, __ANDROID_API_T__) {
     int32_t numElements = INT8_MAX;
     int32_t int32Array[numElements];
 
@@ -1120,7 +1139,7 @@ TEST_P(LogEventTest, TestEmptyAttributionChainWithPrimaryFieldFirstUidAnnotation
     AStatsEvent_release(event);
 }
 
-TEST_P(LogEventTest, TestInvalidBufferParsing) {
+TEST_P_GUARDED(LogEventTest, TestInvalidBufferParsing, __ANDROID_API_T__) {
     size_t emptyAtomBufferSize = 0;
     {
         // creating valid event to get valid buffer header size when no data fields
diff --git a/statsd/tests/StatsLogProcessor_test.cpp b/statsd/tests/StatsLogProcessor_test.cpp
index 61e861f7..1d341bbc 100644
--- a/statsd/tests/StatsLogProcessor_test.cpp
+++ b/statsd/tests/StatsLogProcessor_test.cpp
@@ -75,7 +75,7 @@ public:
                 (const int64_t dumpTimeNs, const int64_t wallClockNs,
                  const bool include_current_partial_bucket, const bool erase_data,
                  const DumpLatency dumpLatency, std::set<string>* str_set,
-                 android::util::ProtoOutputStream* protoOutput),
+                 std::set<int32_t>& usedUids, android::util::ProtoOutputStream* protoOutput),
                 (override));
 };
 
@@ -215,7 +215,7 @@ public:
                 (const int64_t dumpTimeNs, const int64_t wallClockNs,
                  const bool include_current_partial_bucket, const bool erase_data,
                  const DumpLatency dumpLatency, std::set<string>* str_set,
-                 android::util::ProtoOutputStream* protoOutput),
+                 std::set<int32_t>& usedUids, android::util::ProtoOutputStream* protoOutput),
                 (override));
     MOCK_METHOD(size_t, byteSize, (), (override));
     MOCK_METHOD(void, flushRestrictedData, (), (override));
@@ -2026,7 +2026,8 @@ TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogIsolatedUidAttributionCha
  * - multiple isolated uids
  * - multiple host and isolated uids
  */
-TEST(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogRepeatedUidField) {
+TEST_GUARDED(StatsLogProcessorTest_mapIsolatedUidToHostUid, LogRepeatedUidField,
+             __ANDROID_API_T__) {
     int hostUid1 = 21;
     int hostUid2 = 22;
     int isolatedUid1 = 31;
diff --git a/statsd/tests/UidMap_test.cpp b/statsd/tests/UidMap_test.cpp
index ac18b562..55405c25 100644
--- a/statsd/tests/UidMap_test.cpp
+++ b/statsd/tests/UidMap_test.cpp
@@ -56,6 +56,11 @@ const vector<string> kInstallers{"", "", "com.android.vending"};
 const vector<vector<uint8_t>> kCertificateHashes{{'a', 'z'}, {'b', 'c'}, {'d', 'e'}};
 const vector<uint8_t> kDeleted(3, false);
 
+const UidMapOptions DEFAULT_OPTIONS = {.includeVersionStrings = true,
+                                       .includeInstaller = true,
+                                       .truncatedCertificateHashSize = 0,
+                                       .omitSystemUids = false};
+
 UidData createUidData(const vector<int32_t>& uids, const vector<int64_t>& versions,
                       const vector<string>& versionStrings, const vector<string>& apps,
                       const vector<string>& installers,
@@ -348,10 +353,7 @@ TEST(UidMapTest, TestOutputIncludesAtLeastOneSnapshot) {
     m.mLastUpdatePerConfigKey[config1] = 2;
 
     ProtoOutputStream proto;
-    m.appendUidMap(/* timestamp */ 3, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
-                   /* str_set */ nullptr, &proto);
+    m.appendUidMap(/* timestamp */ 3, config1, DEFAULT_OPTIONS, /* str_set */ nullptr, &proto);
 
     // Check there's still a uidmap attached this one.
     UidMapping results;
@@ -373,9 +375,7 @@ TEST(UidMapTest, TestRemovedAppRetained) {
     m.removeApp(2, kApp2, 1000);
 
     ProtoOutputStream proto;
-    m.appendUidMap(/* timestamp */ 3, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 3, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
 
     // Snapshot should still contain this item as deleted.
@@ -401,9 +401,7 @@ TEST(UidMapTest, TestRemovedAppOverGuardrail) {
     // First, verify that we have the expected number of items.
     UidMapping results;
     ProtoOutputStream proto;
-    m.appendUidMap(/* timestamp */ 3, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 3, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     outputStreamToProto(&proto, &results);
     ASSERT_EQ(maxDeletedApps + 10, results.snapshots(0).package_info_size());
@@ -415,9 +413,7 @@ TEST(UidMapTest, TestRemovedAppOverGuardrail) {
     }
 
     proto.clear();
-    m.appendUidMap(/* timestamp */ 5, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 5, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     // Snapshot drops the first nine items.
     outputStreamToProto(&proto, &results);
@@ -438,9 +434,7 @@ TEST(UidMapTest, TestClearingOutput) {
     m.updateMap(1 /* timestamp */, uidData);
 
     ProtoOutputStream proto;
-    m.appendUidMap(/* timestamp */ 2, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 2, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     UidMapping results;
     outputStreamToProto(&proto, &results);
@@ -448,9 +442,7 @@ TEST(UidMapTest, TestClearingOutput) {
 
     // We have to keep at least one snapshot in memory at all times.
     proto.clear();
-    m.appendUidMap(/* timestamp */ 2, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 2, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     outputStreamToProto(&proto, &results);
     ASSERT_EQ(1, results.snapshots_size());
@@ -460,9 +452,7 @@ TEST(UidMapTest, TestClearingOutput) {
     m.updateApp(5, kApp1, 1000, 40, "v40", "", /* certificateHash */ {});
     ASSERT_EQ(1U, m.mChanges.size());
     proto.clear();
-    m.appendUidMap(/* timestamp */ 6, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 6, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     outputStreamToProto(&proto, &results);
     ASSERT_EQ(1, results.snapshots_size());
@@ -475,9 +465,7 @@ TEST(UidMapTest, TestClearingOutput) {
 
     // We still can't remove anything.
     proto.clear();
-    m.appendUidMap(/* timestamp */ 8, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 8, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     outputStreamToProto(&proto, &results);
     ASSERT_EQ(1, results.snapshots_size());
@@ -485,9 +473,7 @@ TEST(UidMapTest, TestClearingOutput) {
     ASSERT_EQ(2U, m.mChanges.size());
 
     proto.clear();
-    m.appendUidMap(/* timestamp */ 9, config2, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 9, config2, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     outputStreamToProto(&proto, &results);
     ASSERT_EQ(1, results.snapshots_size());
@@ -510,15 +496,11 @@ TEST(UidMapTest, TestMemoryComputed) {
     m.updateApp(3, kApp1, 1000, 40, "v40", "", /* certificateHash */ {});
 
     ProtoOutputStream proto;
-    m.appendUidMap(/* timestamp */ 2, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 2, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     size_t prevBytes = m.mBytesUsed;
 
-    m.appendUidMap(/* timestamp */ 4, config1, /* includeVersionStrings */ true,
-                   /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                   /* omitSystemUids */ false,
+    m.appendUidMap(/* timestamp */ 4, config1, DEFAULT_OPTIONS,
                    /* str_set */ nullptr, &proto);
     EXPECT_TRUE(m.mBytesUsed < prevBytes);
 }
@@ -580,9 +562,7 @@ protected:
 TEST_F(UidMapTestAppendUidMap, TestInstallersInReportIncludeInstallerAndHashStrings) {
     ProtoOutputStream proto;
     set<string> strSet;
-    uidMap->appendUidMap(/* timestamp */ 3, cfgKey, /* includeVersionStrings */ true,
-                         /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                         /* omitSystemUids */ false, &strSet, &proto);
+    uidMap->appendUidMap(/* timestamp */ 3, cfgKey, DEFAULT_OPTIONS, &strSet, &proto);
 
     UidMapping results;
     outputStreamToProto(&proto, &results);
@@ -616,9 +596,7 @@ TEST_F(UidMapTestAppendUidMap, TestInstallersInReportIncludeInstallerAndHashStri
 
 TEST_F(UidMapTestAppendUidMap, TestInstallersInReportIncludeInstallerAndDontHashStrings) {
     ProtoOutputStream proto;
-    uidMap->appendUidMap(/* timestamp */ 3, cfgKey, /* includeVersionStrings */ true,
-                         /* includeInstaller */ true, /* truncatedCertificateHashSize */ 0,
-                         /* omitSystemUids */ false,
+    uidMap->appendUidMap(/* timestamp */ 3, cfgKey, DEFAULT_OPTIONS,
                          /* str_set */ nullptr, &proto);
 
     UidMapping results;
@@ -666,9 +644,9 @@ INSTANTIATE_TEST_SUITE_P(
 
 TEST_P(UidMapTestAppendUidMapHashStrings, TestNoIncludeInstallersInReport) {
     ProtoOutputStream proto;
-    uidMap->appendUidMap(/* timestamp */ 3, cfgKey, /* includeVersionStrings */ true,
-                         /* includeInstaller */ false, /* truncatedCertificateHashSize */ 0,
-                         /* omitSystemUids */ false,
+    UidMapOptions options = DEFAULT_OPTIONS;
+    options.includeInstaller = false;
+    uidMap->appendUidMap(/* timestamp */ 3, cfgKey, options,
                          /* str_set */ GetParam(), &proto);
 
     UidMapping results;
@@ -700,8 +678,10 @@ INSTANTIATE_TEST_SUITE_P(ZeroOneTwoThree, UidMapTestTruncateCertificateHash,
 TEST_P(UidMapTestTruncateCertificateHash, TestCertificateHashesTruncated) {
     const uint8_t hashSize = GetParam();
     ProtoOutputStream proto;
-    uidMap->appendUidMap(/* timestamp */ 3, cfgKey, /* includeVersionStrings */ true,
-                         /* includeInstaller */ false, hashSize, /* omitSystemUids */ false,
+    UidMapOptions options = DEFAULT_OPTIONS;
+    options.includeInstaller = false;
+    options.truncatedCertificateHashSize = hashSize;
+    uidMap->appendUidMap(/* timestamp */ 3, cfgKey, options,
                          /* str_set */ nullptr, &proto);
 
     UidMapping results;
diff --git a/statsd/tests/anomaly/AnomalyTracker_test.cpp b/statsd/tests/anomaly/AnomalyTracker_test.cpp
index 827f8f52..c35f57f4 100644
--- a/statsd/tests/anomaly/AnomalyTracker_test.cpp
+++ b/statsd/tests/anomaly/AnomalyTracker_test.cpp
@@ -76,8 +76,8 @@ int64_t getBucketValue(const std::shared_ptr<DimToValMap>& bucket,
 // Returns true if keys in trueList are detected as anomalies and keys in falseList are not.
 bool detectAnomaliesPass(AnomalyTracker& tracker, int64_t bucketNum,
                          const std::shared_ptr<DimToValMap>& currentBucket,
-                         const std::set<const MetricDimensionKey>& trueList,
-                         const std::set<const MetricDimensionKey>& falseList) {
+                         const std::set<MetricDimensionKey>& trueList,
+                         const std::set<MetricDimensionKey>& falseList) {
     for (const MetricDimensionKey& key : trueList) {
         if (!tracker.detectAnomaly(bucketNum, key, getBucketValue(currentBucket, key))) {
             return false;
diff --git a/statsd/tests/e2e/CountMetric_e2e_test.cpp b/statsd/tests/e2e/CountMetric_e2e_test.cpp
index f7e5aeaa..fdd7b681 100644
--- a/statsd/tests/e2e/CountMetric_e2e_test.cpp
+++ b/statsd/tests/e2e/CountMetric_e2e_test.cpp
@@ -1153,7 +1153,7 @@ TEST(CountMetricE2eTest, TestUploadThreshold) {
                         3);
 }
 
-TEST(CountMetricE2eTest, TestRepeatedFieldsAndEmptyArrays) {
+TEST_GUARDED(CountMetricE2eTest, TestRepeatedFieldsAndEmptyArrays, __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedAtomMatcher =
@@ -1220,7 +1220,7 @@ TEST(CountMetricE2eTest, TestRepeatedFieldsAndEmptyArrays) {
                         2);
 }
 
-TEST(CountMetricE2eTest, TestMatchRepeatedFieldPositionAny) {
+TEST_GUARDED(CountMetricE2eTest, TestMatchRepeatedFieldPositionAny, __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedStateAnyOnAtomMatcher =
@@ -1285,7 +1285,7 @@ TEST(CountMetricE2eTest, TestMatchRepeatedFieldPositionAny) {
                         2);
 }
 
-TEST(CountMetricE2eTest, TestRepeatedFieldDimension_PositionFirst) {
+TEST_GUARDED(CountMetricE2eTest, TestRepeatedFieldDimension_PositionFirst, __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedAtomMatcher =
@@ -1372,7 +1372,7 @@ TEST(CountMetricE2eTest, TestRepeatedFieldDimension_PositionFirst) {
               TestAtomReported::ON);
 }
 
-TEST(CountMetricE2eTest, TestRepeatedFieldDimension_PositionLast) {
+TEST_GUARDED(CountMetricE2eTest, TestRepeatedFieldDimension_PositionLast, __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedAtomMatcher =
@@ -1450,7 +1450,7 @@ TEST(CountMetricE2eTest, TestRepeatedFieldDimension_PositionLast) {
               TestAtomReported::ON);
 }
 
-TEST(CountMetricE2eTest, TestRepeatedFieldDimension_PositionAll) {
+TEST_GUARDED(CountMetricE2eTest, TestRepeatedFieldDimension_PositionAll, __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedAtomMatcher =
@@ -1503,8 +1503,8 @@ TEST(CountMetricE2eTest, TestRepeatedFieldDimension_PositionAll) {
                             FAST, &buffer);
     ASSERT_GT(buffer.size(), 0);
     EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
-    // Don't need to backfill dimension path because dimensions with position ALL are not encoded
-    // with the path format.
+    // Don't need to backfill dimension path because dimensions with position ALL are not
+    // encoded with the path format.
     backfillStringInReport(&reports);
     backfillStartEndTimestamp(&reports);
 
@@ -1555,7 +1555,8 @@ TEST(CountMetricE2eTest, TestRepeatedFieldDimension_PositionAll) {
               TestAtomReported::ON);
 }
 
-TEST(CountMetricE2eTest, TestMultipleRepeatedFieldDimensions_PositionFirst) {
+TEST_GUARDED(CountMetricE2eTest, TestMultipleRepeatedFieldDimensions_PositionFirst,
+             __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedAtomMatcher =
@@ -1669,7 +1670,8 @@ TEST(CountMetricE2eTest, TestMultipleRepeatedFieldDimensions_PositionFirst) {
               TestAtomReported::ON);
 }
 
-TEST(CountMetricE2eTest, TestMultipleRepeatedFieldDimensions_PositionAll) {
+TEST_GUARDED(CountMetricE2eTest, TestMultipleRepeatedFieldDimensions_PositionAll,
+             __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedAtomMatcher =
@@ -1798,7 +1800,8 @@ TEST(CountMetricE2eTest, TestMultipleRepeatedFieldDimensions_PositionAll) {
               TestAtomReported::OFF);
 }
 
-TEST(CountMetricE2eTest, TestConditionSlicedByRepeatedUidWithUidDimension) {
+TEST_GUARDED(CountMetricE2eTest, TestConditionSlicedByRepeatedUidWithUidDimension,
+             __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher uidProcessStateChangedAtomMatcher = CreateUidProcessStateChangedAtomMatcher();
diff --git a/statsd/tests/e2e/DurationMetric_e2e_test.cpp b/statsd/tests/e2e/DurationMetric_e2e_test.cpp
index 308ef52e..6b93dd3c 100644
--- a/statsd/tests/e2e/DurationMetric_e2e_test.cpp
+++ b/statsd/tests/e2e/DurationMetric_e2e_test.cpp
@@ -1566,7 +1566,7 @@ TEST(DurationMetricE2eTest, TestUploadThreshold) {
     EXPECT_EQ(baseTimeNs + bucketSizeNs * 2, data.bucket_info(0).end_bucket_elapsed_nanos());
 }
 
-TEST(DurationMetricE2eTest, TestConditionOnRepeatedEnumField) {
+TEST_GUARDED(DurationMetricE2eTest, TestConditionOnRepeatedEnumField, __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher repeatedStateFirstOffAtomMatcher = CreateTestAtomRepeatedStateFirstOffAtomMatcher();
diff --git a/statsd/tests/e2e/EventMetric_e2e_test.cpp b/statsd/tests/e2e/EventMetric_e2e_test.cpp
index 6909dc2f..1ee4b696 100644
--- a/statsd/tests/e2e/EventMetric_e2e_test.cpp
+++ b/statsd/tests/e2e/EventMetric_e2e_test.cpp
@@ -37,6 +37,10 @@ class EventMetricE2eTest : public ::testing::Test {
     void TearDown() override {
         FlagProvider::getInstance().resetOverrides();
     }
+
+public:
+    void doTestRepeatedFieldsAndEmptyArrays();
+    void doTestMatchRepeatedFieldPositionFirst();
 };
 
 TEST_F(EventMetricE2eTest, TestEventMetricDataAggregated) {
@@ -102,7 +106,7 @@ TEST_F(EventMetricE2eTest, TestEventMetricDataAggregated) {
     EXPECT_EQ(data.atom().wakelock_state_changed().tag(), "wl2");
 }
 
-TEST_F(EventMetricE2eTest, TestRepeatedFieldsAndEmptyArrays) {
+TEST_F_GUARDED(EventMetricE2eTest, TestRepeatedFieldsAndEmptyArrays, __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedAtomMatcher =
@@ -193,7 +197,7 @@ TEST_F(EventMetricE2eTest, TestRepeatedFieldsAndEmptyArrays) {
     EXPECT_THAT(atom.repeated_enum_field(), ElementsAreArray(enumArray));
 }
 
-TEST_F(EventMetricE2eTest, TestMatchRepeatedFieldPositionFirst) {
+TEST_F_GUARDED(EventMetricE2eTest, TestMatchRepeatedFieldPositionFirst, __ANDROID_API_T__) {
     StatsdConfig config;
 
     AtomMatcher testAtomReportedStateFirstOnAtomMatcher =
diff --git a/statsd/tests/e2e/GaugeMetric_e2e_push_test.cpp b/statsd/tests/e2e/GaugeMetric_e2e_push_test.cpp
index 1f355647..4bfa4bdd 100644
--- a/statsd/tests/e2e/GaugeMetric_e2e_push_test.cpp
+++ b/statsd/tests/e2e/GaugeMetric_e2e_push_test.cpp
@@ -122,6 +122,9 @@ class GaugeMetricE2ePushedTest : public ::testing::Test {
     void TearDown() override {
         FlagProvider::getInstance().resetOverrides();
     }
+
+public:
+    void doTestRepeatedFieldsForPushedEvent();
 };
 
 TEST_F(GaugeMetricE2ePushedTest, TestMultipleFieldsForPushedEvent) {
@@ -320,7 +323,7 @@ TEST_F(GaugeMetricE2ePushedTest, TestMultipleFieldsForPushedEvent) {
     }
 }
 
-TEST_F(GaugeMetricE2ePushedTest, TestRepeatedFieldsForPushedEvent) {
+TEST_F_GUARDED(GaugeMetricE2ePushedTest, TestRepeatedFieldsForPushedEvent, __ANDROID_API_T__) {
     for (const auto& sampling_type :
          {GaugeMetric::FIRST_N_SAMPLES, GaugeMetric::RANDOM_ONE_SAMPLE}) {
         StatsdConfig config = CreateStatsdConfigForRepeatedFieldsPushedEvent(sampling_type);
diff --git a/statsd/tests/e2e/StringReplace_e2e_test.cpp b/statsd/tests/e2e/StringReplace_e2e_test.cpp
index d92499d5..4f7ef63e 100644
--- a/statsd/tests/e2e/StringReplace_e2e_test.cpp
+++ b/statsd/tests/e2e/StringReplace_e2e_test.cpp
@@ -20,12 +20,12 @@
 #include "src/StatsLogProcessor.h"
 #include "tests/statsd_test_util.h"
 
+#ifdef __ANDROID__
+
 namespace android {
 namespace os {
 namespace statsd {
 
-#ifdef __ANDROID__
-
 namespace {
 
 const int64_t metricId = 123456;
diff --git a/statsd/tests/e2e/ValueMetric_histogram_e2e_test.cpp b/statsd/tests/e2e/ValueMetric_histogram_e2e_test.cpp
new file mode 100644
index 00000000..66a1e511
--- /dev/null
+++ b/statsd/tests/e2e/ValueMetric_histogram_e2e_test.cpp
@@ -0,0 +1,908 @@
+/*
+ * Copyright (C) 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <aidl/android/os/BnPullAtomCallback.h>
+#include <aidl/android/os/IPullAtomCallback.h>
+#include <aidl/android/os/IPullAtomResultReceiver.h>
+#include <aidl/android/util/StatsEventParcel.h>
+#include <gtest/gtest.h>
+
+#include <memory>
+#include <optional>
+
+#include "src/StatsLogProcessor.h"
+#include "src/logd/LogEvent.h"
+#include "src/stats_log.pb.h"
+#include "src/stats_log_util.h"
+#include "src/statsd_config.pb.h"
+#include "tests/metrics/parsing_utils/parsing_test_utils.h"
+#include "tests/statsd_test_util.h"
+
+#ifdef __ANDROID__
+
+using aidl::android::util::StatsEventParcel;
+using namespace std;
+using namespace testing;
+
+namespace android {
+namespace os {
+namespace statsd {
+namespace {
+
+class ValueMetricHistogramE2eTest : public Test {
+protected:
+    void createProcessor(const StatsdConfig& config,
+                         const shared_ptr<IPullAtomCallback>& puller = nullptr,
+                         int32_t pullAtomId = 0) {
+        processor = CreateStatsLogProcessor(baseTimeNs, bucketStartTimeNs, config, cfgKey, puller,
+                                            pullAtomId);
+    }
+
+    optional<ConfigMetricsReportList> getReports(int64_t dumpTimeNs) {
+        ConfigMetricsReportList reports;
+        vector<uint8_t> buffer;
+        processor->onDumpReport(cfgKey, dumpTimeNs,
+                                /*include_current_bucket*/ false, true, ADB_DUMP, FAST, &buffer);
+        if (reports.ParseFromArray(&buffer[0], buffer.size())) {
+            backfillDimensionPath(&reports);
+            backfillStringInReport(&reports);
+            backfillStartEndTimestamp(&reports);
+            return reports;
+        }
+        return nullopt;
+    }
+
+    optional<ConfigMetricsReportList> getReports() {
+        return getReports(bucketStartTimeNs + bucketSizeNs);
+    }
+
+    void logEvents(const vector<shared_ptr<LogEvent>>& events) {
+        for (const shared_ptr<LogEvent> event : events) {
+            processor->OnLogEvent(event.get());
+        }
+    }
+
+    void validateHistogram(const ConfigMetricsReportList& reports, int valueIndex,
+                           const vector<int>& binCounts) {
+        ASSERT_EQ(reports.reports_size(), 1);
+        ConfigMetricsReport report = reports.reports(0);
+        ASSERT_EQ(report.metrics_size(), 1);
+        StatsLogReport metricReport = report.metrics(0);
+        ASSERT_TRUE(metricReport.has_value_metrics());
+        ASSERT_EQ(metricReport.value_metrics().skipped_size(), 0);
+        ValueMetricData data = metricReport.value_metrics().data(0);
+        ASSERT_EQ(data.bucket_info_size(), 1);
+        ValueBucketInfo bucket = data.bucket_info(0);
+        ASSERT_GE(bucket.values_size(), valueIndex + 1);
+        ASSERT_THAT(bucket.values(valueIndex),
+                    Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        ASSERT_THAT(bucket.values(valueIndex).histogram().count(), ElementsAreArray(binCounts));
+    }
+
+    const uint64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(TEN_MINUTES) * 1000000LL;
+    const uint64_t baseTimeNs = getElapsedRealtimeNs();
+    const uint64_t bucketStartTimeNs = baseTimeNs + bucketSizeNs;  // 0:10
+    ConfigKey cfgKey;
+    sp<StatsLogProcessor> processor;
+};
+
+class ValueMetricHistogramE2eTestPushedExplicitBins : public ValueMetricHistogramE2eTest {
+protected:
+    void SetUp() override {
+        StatsdConfig config = createExplicitHistogramStatsdConfig(/* bins */ {1, 7, 10, 20});
+        createProcessor(config);
+    }
+};
+
+TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestNoEvents) {
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_TRUE(metricReport.has_value_metrics());
+    ASSERT_EQ(metricReport.value_metrics().skipped_size(), 1);
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInFirstBinAfterUnderflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 5,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {0, 1, -3});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInOverflowAndUnderflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 0,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* value1 */ 20,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {1, -3, 1});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInUnderflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ -1,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {1, -4});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInOverflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 100,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {-4, 1});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInFirstBinBeforeOverflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 15,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {-3, 1, 0});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInMiddleBin) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 7,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {-2, 1, -2});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestMultipleEvents) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 8,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* value1 */ 15,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 30, /* value1 */ 19,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 40, /* value1 */ 3,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 50, /* value1 */ 9,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 60, /* value1 */ 3,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {0, 2, 2, 2, 0});
+}
+
+class ValueMetricHistogramE2eTestPushedLinearBins : public ValueMetricHistogramE2eTest {
+protected:
+    void SetUp() override {
+        // Bin starts: [UNDERFLOW, -10, -6, -2, 2, 6, 10]
+        StatsdConfig config =
+                createGeneratedHistogramStatsdConfig(/* min */ -10, /* max */ 10, /* count */ 5,
+                                                     HistogramBinConfig::GeneratedBins::LINEAR);
+        createProcessor(config);
+    }
+};
+
+TEST_F(ValueMetricHistogramE2eTestPushedLinearBins, TestNoEvents) {
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_TRUE(metricReport.has_value_metrics());
+    ASSERT_EQ(metricReport.value_metrics().skipped_size(), 1);
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedLinearBins, TestOneEventInFirstBinAfterUnderflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ -10,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {0, 1, -5});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedLinearBins, TestOneEventInOverflowAndUnderflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ -11,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* value1 */ 10,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {1, -5, 1});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedLinearBins, TestOneEventInUnderflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ -15,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {1, -6});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedLinearBins, TestOneEventInOverflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 100,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {-6, 1});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedLinearBins, TestOneEventInFirstBinBeforeOverflow) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 6,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {-5, 1, 0});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedLinearBins, TestOneEventInMiddleBin) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 0,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {-3, 1, -3});
+}
+
+TEST_F(ValueMetricHistogramE2eTestPushedLinearBins, TestMultipleEvents) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 1,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* value1 */ 4,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 30, /* value1 */ -9,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 40, /* value1 */ 3,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 50, /* value1 */ 8,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 60, /* value1 */ -11,
+                                      /* value2 */ 0)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {1, 1, 0, 1, 2, 1, 0});
+}
+
+class ValueMetricHistogramE2eTestMultiplePushedHistograms : public ValueMetricHistogramE2eTest {
+protected:
+    void SetUp() override {
+        StatsdConfig config;
+        *config.add_atom_matcher() = CreateSimpleAtomMatcher("matcher", /* atomId */ 1);
+        *config.add_value_metric() =
+                createValueMetric("ValueMetric", config.atom_matcher(0), /* valueFields */ {1, 2},
+                                  {ValueMetric::HISTOGRAM, ValueMetric::HISTOGRAM},
+                                  /* condition */ nullopt, /* states */ {});
+
+        // Bin starts: [UNDERFLOW, 5, 10, 20, 40, 80, 160]
+        *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+                createGeneratedBinConfig(/* id */ 1, /* min */ 5, /* max */ 160, /* count */ 5,
+                                         HistogramBinConfig::GeneratedBins::EXPONENTIAL);
+
+        // Bin starts: [UNDERFLOW, -10, -6, -2, 2, 6, 10]
+        *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+                createGeneratedBinConfig(/* id */ 2, /* min */ -10, /* max */ 10, /* count */ 5,
+                                         HistogramBinConfig::GeneratedBins::LINEAR);
+
+        createProcessor(config);
+    }
+};
+
+TEST_F(ValueMetricHistogramE2eTestMultiplePushedHistograms, TestNoEvents) {
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_TRUE(metricReport.has_value_metrics());
+    ASSERT_EQ(metricReport.value_metrics().skipped_size(), 1);
+}
+
+TEST_F(ValueMetricHistogramE2eTestMultiplePushedHistograms, TestMultipleEvents) {
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 90,
+                                      /* value2 */ 0),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* value1 */ 6,
+                                      /* value2 */ 12),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 30, /* value1 */ 50,
+                                      /* value2 */ -1),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 40, /* value1 */ 30,
+                                      /* value2 */ 5),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 50, /* value1 */ 15,
+                                      /* value2 */ 2),
+               CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 60, /* value1 */ 160,
+                                      /* value2 */ 9)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 0, {0, 1, 1, 1, 1, 1, 1});
+    TRACE_CALL(validateHistogram, *reports, /* valueIndex */ 1, {-3, 2, 2, 1, 1});
+}
+
+TEST_F(ValueMetricHistogramE2eTest, TestDimensionConditionAndMultipleAggregationTypes) {
+    StatsdConfig config;
+    *config.add_atom_matcher() = CreateSimpleAtomMatcher("matcher", /* atomId */ 1);
+    *config.add_atom_matcher() = CreateScreenTurnedOnAtomMatcher();
+    *config.add_atom_matcher() = CreateScreenTurnedOffAtomMatcher();
+    *config.add_predicate() = CreateScreenIsOnPredicate();
+    config.mutable_predicate(0)->mutable_simple_predicate()->set_initial_value(
+            SimplePredicate::FALSE);
+    *config.add_value_metric() =
+            createValueMetric("ValueMetric", config.atom_matcher(0), /* valueFields */ {1, 2, 2},
+                              {ValueMetric::HISTOGRAM, ValueMetric::SUM, ValueMetric::MIN},
+                              /* condition */ config.predicate(0).id(), /* states */ {});
+    *config.mutable_value_metric(0)->mutable_dimensions_in_what() =
+            CreateDimensions(/* atomId */ 1, {3 /* value3 */});
+
+    // Bin starts: [UNDERFLOW, 5, 10, 20, 40, 80, 160]
+    *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+            createGeneratedBinConfig(/* id */ 1, /* min */ 5, /* max */ 160, /* count */ 5,
+                                     HistogramBinConfig::GeneratedBins::EXPONENTIAL);
+
+    createProcessor(config);
+
+    logEvents(
+            {CreateThreeValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 90,
+                                      /* value2 */ 0, /* value3 */ 1),
+             CreateScreenStateChangedEvent(bucketStartTimeNs + 15, android::view::DISPLAY_STATE_ON),
+             CreateThreeValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* value1 */ 6,
+                                      /* value2 */ 12, /* value3 */ 1),
+             CreateThreeValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 30, /* value1 */ 50,
+                                      /* value2 */ -1, /* value3 */ 1),
+             CreateThreeValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 40, /* value1 */ 30,
+                                      /* value2 */ 5, /* value3 */ 2),
+             CreateThreeValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 50, /* value1 */ 15,
+                                      /* value2 */ 2, /* value3 */ 1),
+             CreateThreeValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 60, /* value1 */ 5,
+                                      /* value2 */ 3, /* value3 */ 2),
+             CreateScreenStateChangedEvent(bucketStartTimeNs + 65,
+                                           android::view::DISPLAY_STATE_OFF),
+             CreateThreeValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 70, /* value1 */ 160,
+                                      /* value2 */ 9, /* value3 */ 1),
+             CreateThreeValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 80, /* value1 */ 70,
+                                      /* value2 */ 20, /* value3 */ 2)});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+
+    ASSERT_NE(reports, nullopt);
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    ASSERT_TRUE(metricReport.has_value_metrics());
+    ASSERT_EQ(metricReport.value_metrics().skipped_size(), 0);
+    ASSERT_EQ(metricReport.value_metrics().data_size(), 2);
+
+    // Dimension 1
+    {
+        ValueMetricData data = metricReport.value_metrics().data(0);
+        ASSERT_EQ(data.bucket_info_size(), 1);
+        ValueBucketInfo bucket = data.bucket_info(0);
+        ASSERT_EQ(bucket.values_size(), 3);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(0).histogram().count(), ElementsAreArray({0, 1, 1, 0, 1, -2}));
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(1).value_long(), 13);
+        ASSERT_THAT(bucket.values(2), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(2).value_long(), -1);
+    }
+
+    // Dimension 2
+    {
+        ValueMetricData data = metricReport.value_metrics().data(1);
+        ASSERT_EQ(data.bucket_info_size(), 1);
+        ValueBucketInfo bucket = data.bucket_info(0);
+        ASSERT_EQ(bucket.values_size(), 3);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(0).histogram().count(), ElementsAreArray({0, 1, 0, 1, -3}));
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(1).value_long(), 8);
+        ASSERT_THAT(bucket.values(2), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(2).value_long(), 3);
+    }
+}
+
+// Test fixture which uses a ValueMetric on a pushed atom with a statsd-aggregated histogram as well
+// as a client-aggregated histogram.
+class ValueMetricHistogramE2eTestClientAggregatedPushedHistogram
+    : public ValueMetricHistogramE2eTest {
+protected:
+    void SetUp() override {
+        StatsdConfig config;
+        *config.add_atom_matcher() = CreateSimpleAtomMatcher("matcher", /* atomId */ 1);
+        *config.add_value_metric() =
+                createValueMetric("ValueMetric", config.atom_matcher(0), /* valueFields */ {2, 3},
+                                  {ValueMetric::HISTOGRAM, ValueMetric::HISTOGRAM},
+                                  /* condition */ nullopt, /* states */ {});
+        config.mutable_value_metric(0)->mutable_value_field()->mutable_child(1)->set_position(ALL);
+        *config.mutable_value_metric(0)->mutable_dimensions_in_what() =
+                CreateRepeatedDimensions(/* atomId */ 1, {1 /* uid */}, {Position::FIRST});
+
+        // Bin starts: [UNDERFLOW, -10, -6, -2, 2, 6, 10]
+        *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+                createGeneratedBinConfig(/* id */ 1, /* min */ -10, /* max */ 10, /* count */ 5,
+                                         HistogramBinConfig::GeneratedBins::LINEAR);
+
+        config.mutable_value_metric(0)->add_histogram_bin_configs()->set_id(2);
+        config.mutable_value_metric(0)
+                ->mutable_histogram_bin_configs(1)
+                ->mutable_client_aggregated_bins();
+
+        createProcessor(config);
+
+        StatsdStats::getInstance().reset();
+    }
+
+public:
+    void doTestMultipleEvents() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestBadHistograms() __INTRODUCED_IN(__ANDROID_API_T__);
+};
+
+TEST_F_GUARDED(ValueMetricHistogramE2eTestClientAggregatedPushedHistogram, TestMultipleEvents,
+               __ANDROID_API_T__) {
+    logEvents({makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* uids */ {1},
+                                       /* value1 */ 0, /* value2 */ {0, 0, 1, 1}),
+               makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* uids */ {1},
+                                       /* value1 */ 12, /* value2 */ {0, 2, 0, 1}),
+               makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 30, /* uids */ {2},
+                                       /* value1 */ -1, /* value2 */ {1, 0, 0, 0}),
+               makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 40, /* uids */ {1},
+                                       /* value1 */ 5, /* value2 */ {0, 0, 0, 0}),
+               makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 50, /* uids */ {2},
+                                       /* value1 */ 2, /* value2 */ {0, 2, 0, 1}),
+               makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 60, /* uids */ {2},
+                                       /* value1 */ 9, /* value2 */ {10, 5, 2, 2})});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    ASSERT_TRUE(metricReport.has_value_metrics());
+    ASSERT_EQ(metricReport.value_metrics().skipped_size(), 0);
+    ASSERT_EQ(metricReport.value_metrics().data_size(), 2);
+
+    // Dimension 1
+    {
+        ValueMetricData data = metricReport.value_metrics().data(0);
+        ASSERT_EQ(data.bucket_info_size(), 1);
+        ValueBucketInfo bucket = data.bucket_info(0);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(0).histogram().count(), ElementsAreArray({-3, 1, 1, 0, 1}));
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({0, 2, 1, 2}));
+    }
+
+    // Dimension 2
+    {
+        ValueMetricData data = metricReport.value_metrics().data(1);
+        ASSERT_EQ(data.bucket_info_size(), 1);
+        ValueBucketInfo bucket = data.bucket_info(0);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(0).histogram().count(), ElementsAreArray({-3, 1, 1, 1, 0}));
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({11, 7, 2, 3}));
+    }
+}
+
+TEST_F_GUARDED(ValueMetricHistogramE2eTestClientAggregatedPushedHistogram, TestBadHistograms,
+               __ANDROID_API_T__) {
+    logEvents(
+            {// Histogram has negative bin count.
+             makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* uids */ {1},
+                                     /* value1 */ 0, /* value2 */ {0, 0, -1, 1}),
+
+             // Good histogram, recorded in interval.
+             makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* uids */ {1},
+                                     /* value1 */ 12, /* value2 */ {0, 2, 0, 1}),
+
+             // Histogram has more bins than what's already aggregated. Aggregation is not updated.
+             makeRepeatedUidLogEvent(/* atomId */ 1, bucketStartTimeNs + 30, /* uids */ {1},
+                                     /* value1 */ -1, /* value2 */ {1, 0, 0, 0, 0})});
+
+    optional<ConfigMetricsReportList> reports = getReports();
+    ASSERT_NE(reports, nullopt);
+
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    ASSERT_TRUE(metricReport.has_value_metrics());
+    EXPECT_EQ(metricReport.value_metrics().skipped_size(), 0);
+    ASSERT_EQ(metricReport.value_metrics().data_size(), 1);
+    ValueMetricData data = metricReport.value_metrics().data(0);
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    ValueBucketInfo bucket = data.bucket_info(0);
+    ASSERT_EQ(bucket.values_size(), 2);
+    ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+    EXPECT_THAT(bucket.values(0).histogram().count(), ElementsAreArray({-3, 2, -2, 1}));
+    ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+    EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({0, 2, 0, 1}));
+
+    StatsdStatsReport statsdStatsReport = getStatsdStatsReport();
+    ASSERT_EQ(statsdStatsReport.atom_metric_stats_size(), 1);
+    EXPECT_EQ(statsdStatsReport.atom_metric_stats(0).bad_value_type(), 2);
+}
+
+class Puller : public BnPullAtomCallback {
+public:
+    int curPullNum = 0;
+
+    // Mapping of uid to histograms for each pull
+    const map<int, vector<vector<int>>> histMap;
+
+    Puller(const map<int, vector<vector<int>>>& histMap) : histMap(histMap) {
+    }
+
+    Status onPullAtom(int atomId,
+                      const shared_ptr<IPullAtomResultReceiver>& resultReceiver) override {
+        if (__builtin_available(android __ANDROID_API_T__, *)) {
+            vector<StatsEventParcel> parcels;
+            for (auto const& [uid, histograms] : histMap) {
+                const vector<int>& histogram = histograms[curPullNum];
+                AStatsEvent* statsEvent = AStatsEvent_obtain();
+                AStatsEvent_setAtomId(statsEvent, atomId);
+                AStatsEvent_writeInt32(statsEvent, uid);
+                AStatsEvent_writeInt32(statsEvent, curPullNum);
+                AStatsEvent_writeInt32Array(statsEvent, histogram.data(), histogram.size());
+                AStatsEvent_build(statsEvent);
+                size_t size;
+                uint8_t* buffer = AStatsEvent_getBuffer(statsEvent, &size);
+
+                StatsEventParcel p;
+                // vector.assign() creates a copy, but this is inevitable unless
+                // stats_event.h/c uses a vector as opposed to a buffer.
+                p.buffer.assign(buffer, buffer + size);
+                parcels.push_back(std::move(p));
+                AStatsEvent_release(statsEvent);
+            }
+            curPullNum++;
+            resultReceiver->pullFinished(atomId, /*success=*/true, parcels);
+        }
+        return Status::ok();
+    }
+};
+
+}  // anonymous namespace
+
+// Test fixture which uses a ValueMetric on a pulled atom with a client-aggregated histogram.
+class ValueMetricHistogramE2eTestClientAggregatedPulledHistogram
+    : public ValueMetricHistogramE2eTest {
+protected:
+    const int atomId = 10'000;
+    StatsdConfig config;
+
+    void SetUp() override {
+        *config.add_atom_matcher() = CreateSimpleAtomMatcher("matcher", atomId);
+
+        *config.add_value_metric() =
+                createValueMetric("ValueMetric", config.atom_matcher(0), /* valueFields */ {2, 3},
+                                  {ValueMetric::SUM, ValueMetric::HISTOGRAM},
+                                  nullopt /* condition */, /* states */ {});
+
+        config.mutable_value_metric(0)->mutable_value_field()->mutable_child(1)->set_position(ALL);
+        *config.mutable_value_metric(0)->mutable_dimensions_in_what() =
+                CreateDimensions(atomId, {1 /* uid */});
+
+        config.mutable_value_metric(0)->add_histogram_bin_configs()->set_id(1);
+        config.mutable_value_metric(0)
+                ->mutable_histogram_bin_configs(0)
+                ->mutable_client_aggregated_bins();
+
+        config.mutable_value_metric(0)->set_skip_zero_diff_output(false);
+
+        config.add_default_pull_packages("AID_ROOT");
+
+        StatsdStats::getInstance().reset();
+    }
+
+    void createProcessorWithHistData(const map<int, vector<vector<int>>>& histData) {
+        createProcessor(config, SharedRefBase::make<Puller>(histData), atomId);
+    }
+
+public:
+    void doTestPulledAtom() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestBadHistograms() __INTRODUCED_IN(__ANDROID_API_T__);
+    void doTestZeroDefaultBase() __INTRODUCED_IN(__ANDROID_API_T__);
+};
+
+TEST_F_GUARDED(ValueMetricHistogramE2eTestClientAggregatedPulledHistogram, TestPulledAtom,
+               __ANDROID_API_T__) {
+    map<int, vector<vector<int>>> histData;
+    histData[1].push_back({0, 0, 0, 0});
+    histData[1].push_back({1, 0, 2, 0});
+    histData[1].push_back({1, 1, 3, 5});
+    histData[1].push_back({1, 1, 3, 5});
+    histData[1].push_back({3, 1, 3, 5});
+    histData[2].push_back({0, 1, 0, 0});
+    histData[2].push_back({1, 3, 0, 2});
+    histData[2].push_back({1, 3, 0, 2});
+    histData[2].push_back({2, 9, 3, 5});
+    histData[2].push_back({3, 9, 3, 5});
+    createProcessorWithHistData(histData);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 2 + 1);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 3 + 2);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 4 + 3);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 5 + 4);
+
+    optional<ConfigMetricsReportList> reports = getReports(baseTimeNs + bucketSizeNs * 6 + 100);
+    ASSERT_NE(reports, nullopt);
+
+    ASSERT_NE(reports, nullopt);
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+
+    StatsLogReport metricReport = report.metrics(0);
+    ASSERT_TRUE(metricReport.has_value_metrics());
+    EXPECT_EQ(metricReport.value_metrics().skipped_size(), 0);
+    ASSERT_EQ(metricReport.value_metrics().data_size(), 2);
+    StatsLogReport::ValueMetricDataWrapper valueMetrics;
+    sortMetricDataByDimensionsValue(metricReport.value_metrics(), &valueMetrics);
+
+    // Dimension uid = 1
+    {
+        ValueMetricData data = valueMetrics.data(0);
+        ASSERT_EQ(data.bucket_info_size(), 4);
+
+        ValueBucketInfo bucket = data.bucket_info(0);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(0).value_long(), 1);
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({1, 0, 2, 0}));
+
+        bucket = data.bucket_info(1);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(0).value_long(), 1);
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({0, 1, 1, 5}));
+
+        bucket = data.bucket_info(2);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(0).value_long(), 1);
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({-4}));
+
+        bucket = data.bucket_info(3);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(0).value_long(), 1);
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({2, -3}));
+    }
+
+    // Dimension uid = 2
+    {
+        ValueMetricData data = valueMetrics.data(1);
+        ASSERT_EQ(data.bucket_info_size(), 4);
+
+        ValueBucketInfo bucket = data.bucket_info(0);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(0).value_long(), 1);
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({1, 2, 0, 2}));
+
+        bucket = data.bucket_info(1);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(0).value_long(), 1);
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({-4}));
+
+        bucket = data.bucket_info(2);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(0).value_long(), 1);
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({1, 6, 3, 3}));
+
+        bucket = data.bucket_info(3);
+        ASSERT_EQ(bucket.values_size(), 2);
+        ASSERT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+        EXPECT_EQ(bucket.values(0).value_long(), 1);
+        ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+        EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({1, -3}));
+    }
+}
+
+TEST_F_GUARDED(ValueMetricHistogramE2eTestClientAggregatedPulledHistogram, TestBadHistograms,
+               __ANDROID_API_T__) {
+    map<int, vector<vector<int>>> histData;
+    histData[1].push_back({0, 0, 0, 0});  // base updated.
+
+    histData[1].push_back({1, 0, 2});  // base updated, no aggregate recorded due to
+                                       // ERROR_BINS_MISMATCH
+
+    histData[1].push_back({1, -1, 3});  // base is reset, no aggregate recorded due to
+                                        // negative bin count
+
+    histData[1].push_back({1, 2, 3});  // base updated, no aggregate recorded
+
+    histData[1].push_back({2, 6, 3});  // base updated, aggregate updated
+
+    histData[1].push_back({3, 9, 4});  // base updated, aggregate updated
+
+    histData[1].push_back({4, 8, 5});  // base updated, no aggregate recorded because 2nd bin
+                                       // decreased
+
+    createProcessorWithHistData(histData);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 2 + 1);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 3 + 2);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 4 + 3);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 5 + 4);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 6 + 5);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 7 + 6);
+
+    optional<ConfigMetricsReportList> reports = getReports(baseTimeNs + bucketSizeNs * 8 + 100);
+
+    ASSERT_NE(reports, nullopt);
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+
+    StatsLogReport metricReport = report.metrics(0);
+    ASSERT_TRUE(metricReport.has_value_metrics());
+    EXPECT_EQ(metricReport.value_metrics().skipped_size(), 0);
+
+    EXPECT_EQ(metricReport.value_metrics().data_size(), 1);
+    ValueMetricData data = metricReport.value_metrics().data(0);
+    EXPECT_EQ(data.bucket_info_size(), 6);
+
+    ValueBucketInfo bucket = data.bucket_info(0);
+    ASSERT_EQ(bucket.values_size(), 1);
+    EXPECT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+
+    bucket = data.bucket_info(1);
+    ASSERT_EQ(bucket.values_size(), 1);
+    EXPECT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+
+    bucket = data.bucket_info(2);
+    ASSERT_EQ(bucket.values_size(), 1);
+    EXPECT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+
+    bucket = data.bucket_info(3);
+    ASSERT_EQ(bucket.values_size(), 2);
+    EXPECT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+    ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+    EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({1, 4, 0}));
+
+    bucket = data.bucket_info(4);
+    ASSERT_EQ(bucket.values_size(), 2);
+    EXPECT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+    ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+    EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({1, 3, 1}));
+
+    bucket = data.bucket_info(5);
+    ASSERT_EQ(bucket.values_size(), 1);
+    EXPECT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+
+    StatsdStatsReport statsdStatsReport = getStatsdStatsReport();
+    ASSERT_EQ(statsdStatsReport.atom_metric_stats_size(), 1);
+    EXPECT_EQ(statsdStatsReport.atom_metric_stats(0).bad_value_type(), 3);
+}
+
+TEST_F_GUARDED(ValueMetricHistogramE2eTestClientAggregatedPulledHistogram, TestZeroDefaultBase,
+               __ANDROID_API_T__) {
+    config.mutable_value_metric(0)->set_use_zero_default_base(true);
+
+    map<int, vector<vector<int>>> histData;
+    histData[1].push_back({-1, 0, 2});  // base not updated
+    histData[1].push_back({1, 0, 2});   // base updated, aggregate also recorded.
+    histData[1].push_back({2, 0, 2});   // base updated, aggregate also recorded.
+
+    createProcessorWithHistData(histData);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 2 + 1);
+
+    processor->mPullerManager->ForceClearPullerCache();
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 3 + 1);
+
+    optional<ConfigMetricsReportList> reports = getReports(baseTimeNs + bucketSizeNs * 4 + 100);
+
+    ASSERT_NE(reports, nullopt);
+    ASSERT_EQ(reports->reports_size(), 1);
+    ConfigMetricsReport report = reports->reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+
+    StatsLogReport metricReport = report.metrics(0);
+    ASSERT_TRUE(metricReport.has_value_metrics());
+    EXPECT_EQ(metricReport.value_metrics().skipped_size(), 0);
+
+    EXPECT_EQ(metricReport.value_metrics().data_size(), 1);
+    ValueMetricData data = metricReport.value_metrics().data(0);
+    EXPECT_EQ(data.bucket_info_size(), 2);
+
+    ValueBucketInfo bucket = data.bucket_info(0);
+    ASSERT_EQ(bucket.values_size(), 2);
+    EXPECT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+    EXPECT_EQ(bucket.values(0).value_long(), 1);
+    ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+    EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({1, 0, 2}));
+
+    bucket = data.bucket_info(1);
+    ASSERT_EQ(bucket.values_size(), 2);
+    EXPECT_THAT(bucket.values(0), Property(&ValueBucketInfo::Value::has_value_long, IsTrue()));
+    EXPECT_EQ(bucket.values(0).value_long(), 1);
+    ASSERT_THAT(bucket.values(1), Property(&ValueBucketInfo::Value::has_histogram, IsTrue()));
+    EXPECT_THAT(bucket.values(1).histogram().count(), ElementsAreArray({1, -2}));
+}
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
+#else
+GTEST_LOG_(INFO) << "This test does nothing.\n";
+#endif
diff --git a/statsd/tests/external/puller_util_test.cpp b/statsd/tests/external/puller_util_test.cpp
index 71f4de49..a577f8d7 100644
--- a/statsd/tests/external/puller_util_test.cpp
+++ b/statsd/tests/external/puller_util_test.cpp
@@ -430,7 +430,7 @@ TEST(PullerUtilTest, MultipleIsolatedUidToOneHostUidAttributionChain) {
 }
 
 // Test that repeated fields are treated as non-additive fields even when marked as additive.
-TEST(PullerUtilTest, RepeatedAdditiveField) {
+TEST_GUARDED(PullerUtilTest, RepeatedAdditiveField, __ANDROID_API_T__) {
     vector<int> int32Array1 = {3, 6};
     vector<int> int32Array2 = {6, 9};
 
@@ -451,8 +451,8 @@ TEST(PullerUtilTest, RepeatedAdditiveField) {
     mapAndMergeIsolatedUidsToHostUid(data, uidMap, uidAtomTagId, additiveFields);
 
     ASSERT_EQ(2, (int)data.size());
-    // Events 1 and 3 are merged - non-additive fields, including the repeated additive field, are
-    // equal.
+    // Events 1 and 3 are merged - non-additive fields, including the repeated additive field,
+    // are equal.
     const vector<FieldValue>* actualFieldValues = &data[0]->getValues();
     ASSERT_EQ(4, actualFieldValues->size());
     EXPECT_EQ(hostUid, actualFieldValues->at(0).mValue.int_value);
@@ -470,7 +470,7 @@ TEST(PullerUtilTest, RepeatedAdditiveField) {
 }
 
 // Test that repeated uid events are sorted and merged correctly.
-TEST(PullerUtilTest, RepeatedUidField) {
+TEST_GUARDED(PullerUtilTest, RepeatedUidField, __ANDROID_API_T__) {
     vector<int> uidArray1 = {isolatedUid1, hostUid};
     vector<int> uidArray2 = {isolatedUid1, isolatedUid3};
     vector<int> uidArray3 = {isolatedUid1, hostUid, isolatedUid2};
@@ -542,7 +542,7 @@ TEST(PullerUtilTest, RepeatedUidField) {
 
 // Test that repeated uid events with multiple repeated non-additive fields are sorted and merged
 // correctly.
-TEST(PullerUtilTest, MultipleRepeatedFields) {
+TEST_GUARDED(PullerUtilTest, MultipleRepeatedFields, __ANDROID_API_T__) {
     vector<int> uidArray1 = {isolatedUid1, hostUid};
     vector<int> uidArray2 = {isolatedUid1, isolatedUid3};
     vector<int> uidArray3 = {isolatedUid1, hostUid, isolatedUid2};
@@ -565,7 +565,8 @@ TEST(PullerUtilTest, MultipleRepeatedFields) {
             makeRepeatedUidLogEvent(uidAtomTagId, timestamp, uidArray2, hostAdditiveData,
                                     nonAdditiveArray1),
 
-            // Event 3 {30, 20, 40}->21->{1, 2} (different repeated fields with total length equal
+            // Event 3 {30, 20, 40}->21->{1, 2} (different repeated fields with total length
+            // equal
             // to event 1, merged with event 6)
             makeRepeatedUidLogEvent(uidAtomTagId, timestamp, uidArray3, hostAdditiveData,
                                     nonAdditiveArray3),
@@ -579,7 +580,8 @@ TEST(PullerUtilTest, MultipleRepeatedFields) {
             makeRepeatedUidLogEvent(uidAtomTagId, timestamp, uidArray1, hostAdditiveData,
                                     nonAdditiveArray2),
 
-            // Event 6 {30, 20, 40}->22->{1, 2} (different repeated fields with total length equal
+            // Event 6 {30, 20, 40}->22->{1, 2} (different repeated fields with total length
+            // equal
             // to event 1, merged with event 3)
             makeRepeatedUidLogEvent(uidAtomTagId, timestamp, uidArray3, isolatedAdditiveData,
                                     nonAdditiveArray3),
diff --git a/statsd/tests/metrics/CountMetricProducer_test.cpp b/statsd/tests/metrics/CountMetricProducer_test.cpp
index 8db5bcee..e84bc333 100644
--- a/statsd/tests/metrics/CountMetricProducer_test.cpp
+++ b/statsd/tests/metrics/CountMetricProducer_test.cpp
@@ -60,6 +60,13 @@ void makeLogEvent(LogEvent* logEvent, int64_t timestampNs, int atomId, string ui
     parseStatsEventToLogEvent(statsEvent, logEvent);
 }
 
+StatsLogReport onDumpReport(CountMetricProducer& producer, int64_t dumpTimeNs) {
+    ProtoOutputStream output;
+    set<int32_t> usedUids;
+    producer.onDumpReport(dumpTimeNs, true /*include current partial bucket*/, true /*erase data*/,
+                          FAST, nullptr, usedUids, &output);
+    return outputStreamToProto(&output);
+}
 }  // namespace
 
 // Setup for parameterized tests.
@@ -549,6 +556,112 @@ TEST(CountMetricProducerTest, TestOneWeekTimeUnit) {
     EXPECT_EQ(fiveWeeksOneDayNs, countProducer.getCurrentBucketEndTimeNs());
 }
 
+TEST(CountMetricProducerTest, TestCorruptedDataReason_WhatLoss) {
+    const int64_t bucketStartTimeNs = 10000000000;
+    const int tagId = 1;
+    const int conditionId = 10;
+
+    CountMetric metric;
+    metric.set_id(1);
+    metric.set_bucket(ONE_MINUTE);
+
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+    CountMetricProducer countProducer(kConfigKey, metric, 0 /*condition index*/,
+                                      {ConditionState::kUnknown}, wizard, protoHash,
+                                      bucketStartTimeNs, bucketStartTimeNs, provider);
+
+    countProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_SOCKET_LOSS,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(countProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    countProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(countProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+    }
+
+    countProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_SOCKET_LOSS,
+                                        MetricProducer::LostAtomType::kWhat);
+    countProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(countProducer, bucketStartTimeNs + 250);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(CountMetricProducerTest, TestCorruptedDataReason_ConditionLoss) {
+    const int64_t bucketStartTimeNs = 10000000000;
+    const int conditionId = 10;
+
+    CountMetric metric;
+    metric.set_id(1);
+    metric.set_bucket(ONE_MINUTE);
+
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+    CountMetricProducer countProducer(kConfigKey, metric, 0 /*condition index*/,
+                                      {ConditionState::kUnknown}, wizard, protoHash,
+                                      bucketStartTimeNs, bucketStartTimeNs, provider);
+
+    countProducer.onMatchedLogEventLost(conditionId, DATA_CORRUPTED_SOCKET_LOSS,
+                                        MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(countProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    countProducer.onMatchedLogEventLost(conditionId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                        MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(countProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(CountMetricProducerTest, TestCorruptedDataReason_StateLoss) {
+    const int64_t bucketStartTimeNs = 10000000000;
+    const int stateAtomId = 10;
+
+    CountMetric metric;
+    metric.set_id(1);
+    metric.set_bucket(ONE_MINUTE);
+
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+    CountMetricProducer countProducer(kConfigKey, metric, 0 /*condition index*/,
+                                      {ConditionState::kUnknown}, wizard, protoHash,
+                                      bucketStartTimeNs, bucketStartTimeNs, provider);
+
+    countProducer.onStateEventLost(stateAtomId, DATA_CORRUPTED_SOCKET_LOSS);
+    {
+        // Check dump report content.
+        ProtoOutputStream output;
+        StatsLogReport report = onDumpReport(countProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    // validation that data corruption signal remains accurate after another dump
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(countProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/metrics/DurationMetricProducer_test.cpp b/statsd/tests/metrics/DurationMetricProducer_test.cpp
index 5cf0221c..e32804c0 100644
--- a/statsd/tests/metrics/DurationMetricProducer_test.cpp
+++ b/statsd/tests/metrics/DurationMetricProducer_test.cpp
@@ -54,6 +54,14 @@ void makeLogEvent(LogEvent* logEvent, int64_t timestampNs, int atomId) {
     parseStatsEventToLogEvent(statsEvent, logEvent);
 }
 
+StatsLogReport onDumpReport(DurationMetricProducer& producer, int64_t dumpTimeNs) {
+    ProtoOutputStream output;
+    set<int32_t> usedUids;
+    producer.onDumpReport(dumpTimeNs, true /*include current partial bucket*/, true /*erase data*/,
+                          FAST, nullptr, usedUids, &output);
+    return outputStreamToProto(&output);
+}
+
 }  // namespace
 
 // Setup for parameterized tests.
@@ -625,6 +633,111 @@ TEST(DurationMetricProducerTest, TestClearCurrentSlicedTrackerMapWhenStop) {
     EXPECT_EQ(1, durationProducer.getCurrentBucketNum());
 }
 
+TEST(DurationMetricProducerTest, TestCorruptedDataReason_WhatLoss) {
+    const int64_t bucketStartTimeNs = 10000000000;
+    const int tagId = 1;
+
+    DurationMetric metric;
+    metric.set_id(1);
+    metric.set_bucket(ONE_MINUTE);
+    metric.set_aggregation_type(DurationMetric_AggregationType_SUM);
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    FieldMatcher dimensions;
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+
+    DurationMetricProducer durationProducer(
+            kConfigKey, metric, 0 /* condition index */, {ConditionState::kUnknown},
+            -1 /*what index not needed*/, 1 /* start index */, 2 /* stop index */,
+            3 /* stop_all index */, false /*nesting*/, wizard, protoHash, dimensions,
+            bucketStartTimeNs, bucketStartTimeNs, provider);
+
+    durationProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_SOCKET_LOSS,
+                                           MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(durationProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    durationProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                           MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(durationProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(DurationMetricProducerTest, TestCorruptedDataReason_ConditionLoss) {
+    const int64_t bucketStartTimeNs = 10000000000;
+    const int conditionId = 10;
+
+    DurationMetric metric;
+    metric.set_id(1);
+    metric.set_bucket(ONE_MINUTE);
+    metric.set_aggregation_type(DurationMetric_AggregationType_SUM);
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    FieldMatcher dimensions;
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+
+    DurationMetricProducer durationProducer(
+            kConfigKey, metric, 0 /* condition index */, {ConditionState::kUnknown},
+            -1 /*what index not needed*/, 1 /* start index */, 2 /* stop index */,
+            3 /* stop_all index */, false /*nesting*/, wizard, protoHash, dimensions,
+            bucketStartTimeNs, bucketStartTimeNs, provider);
+
+    durationProducer.onMatchedLogEventLost(conditionId, DATA_CORRUPTED_SOCKET_LOSS,
+                                           MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(durationProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    durationProducer.onMatchedLogEventLost(conditionId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                           MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(durationProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(DurationMetricProducerTest, TestCorruptedDataReason_StateLoss) {
+    const int64_t bucketStartTimeNs = 10000000000;
+    const int stateAtomId = 10;
+
+    DurationMetric metric;
+    metric.set_id(1);
+    metric.set_bucket(ONE_MINUTE);
+    metric.set_aggregation_type(DurationMetric_AggregationType_SUM);
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    FieldMatcher dimensions;
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+
+    DurationMetricProducer durationProducer(
+            kConfigKey, metric, 0 /* condition index */, {ConditionState::kUnknown},
+            -1 /*what index not needed*/, 1 /* start index */, 2 /* stop index */,
+            3 /* stop_all index */, false /*nesting*/, wizard, protoHash, dimensions,
+            bucketStartTimeNs, bucketStartTimeNs, provider);
+
+    durationProducer.onStateEventLost(stateAtomId, DATA_CORRUPTED_SOCKET_LOSS);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(durationProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    // validation that data corruption signal remains accurate after another dump
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(durationProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/metrics/EventMetricProducer_test.cpp b/statsd/tests/metrics/EventMetricProducer_test.cpp
index f2f9beab..d31e9333 100644
--- a/statsd/tests/metrics/EventMetricProducer_test.cpp
+++ b/statsd/tests/metrics/EventMetricProducer_test.cpp
@@ -53,6 +53,14 @@ void makeLogEvent(LogEvent* logEvent, int32_t atomId, int64_t timestampNs, strin
     parseStatsEventToLogEvent(statsEvent, logEvent);
 }
 
+StatsLogReport onDumpReport(EventMetricProducer& producer, int64_t dumpTimeNs) {
+    ProtoOutputStream output;
+    set<int32_t> usedUids;
+    producer.onDumpReport(dumpTimeNs, true /*include current partial bucket*/, true /*erase data*/,
+                          FAST, nullptr, usedUids, &output);
+    return outputStreamToProto(&output);
+}
+
 }  // anonymous namespace
 
 class EventMetricProducerTest : public ::testing::Test {
@@ -89,12 +97,7 @@ TEST_F(EventMetricProducerTest, TestNoCondition) {
     eventProducer.onMatchedLogEvent(1 /*matcher index*/, event2);
 
     // Check dump report content.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    eventProducer.onDumpReport(bucketStartTimeNs + 20, true /*include current partial bucket*/,
-                               true /*erase data*/, FAST, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 20);
     backfillAggregatedAtoms(&report);
     EXPECT_TRUE(report.has_event_metrics());
     ASSERT_EQ(2, report.event_metrics().data_size());
@@ -132,12 +135,7 @@ TEST_F(EventMetricProducerTest, TestEventsWithNonSlicedCondition) {
     eventProducer.onMatchedLogEvent(1 /*matcher index*/, event2);
 
     // Check dump report content.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    eventProducer.onDumpReport(bucketStartTimeNs + 20, true /*include current partial bucket*/,
-                               true /*erase data*/, FAST, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 20);
     EXPECT_TRUE(report.has_event_metrics());
     backfillAggregatedAtoms(&report);
     ASSERT_EQ(1, report.event_metrics().data_size());
@@ -186,12 +184,7 @@ TEST_F(EventMetricProducerTest, TestEventsWithSlicedCondition) {
     eventProducer.onMatchedLogEvent(1 /*matcher index*/, event2);
 
     // Check dump report content.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    eventProducer.onDumpReport(bucketStartTimeNs + 20, true /*include current partial bucket*/,
-                               true /*erase data*/, FAST, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 20);
     backfillAggregatedAtoms(&report);
     EXPECT_TRUE(report.has_event_metrics());
     ASSERT_EQ(1, report.event_metrics().data_size());
@@ -226,12 +219,7 @@ TEST_F(EventMetricProducerTest, TestOneAtomTagAggregatedEvents) {
     eventProducer.onMatchedLogEvent(1 /*matcher index*/, event4);
 
     // Check dump report content.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    eventProducer.onDumpReport(bucketStartTimeNs + 50, true /*include current partial bucket*/,
-                               true /*erase data*/, FAST, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 50);
     EXPECT_TRUE(report.has_event_metrics());
     ASSERT_EQ(2, report.event_metrics().data_size());
 
@@ -279,12 +267,7 @@ TEST_F(EventMetricProducerTest, TestBytesFieldAggregatedEvents) {
     eventProducer.onMatchedLogEvent(1 /*matcher index*/, event4);
 
     // Check dump report content.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    eventProducer.onDumpReport(bucketStartTimeNs + 50, true /*include current partial bucket*/,
-                               true /*erase data*/, FAST, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 50);
     EXPECT_TRUE(report.has_event_metrics());
     ASSERT_EQ(2, report.event_metrics().data_size());
 
@@ -328,12 +311,8 @@ TEST_F(EventMetricProducerTest, TestTwoAtomTagAggregatedEvents) {
     eventProducer.onMatchedLogEvent(1 /*matcher index*/, event3);
 
     // Check dump report content.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    eventProducer.onDumpReport(bucketStartTimeNs + 50, true /*include current partial bucket*/,
-                               true /*erase data*/, FAST, &strSet, &output);
+    StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 50);
 
-    StatsLogReport report = outputStreamToProto(&output);
     EXPECT_TRUE(report.has_event_metrics());
     ASSERT_EQ(2, report.event_metrics().data_size());
 
@@ -378,11 +357,8 @@ TEST_F(EventMetricProducerTest, TestCorruptedDataReason_OnDumpReport) {
 
     {
         // Check dump report content.
-        ProtoOutputStream output;
-        eventProducer.onDumpReport(bucketStartTimeNs + 50, true /*include current partial bucket*/,
-                                   true /*erase data*/, FAST, nullptr, &output);
+        StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 50);
 
-        StatsLogReport report = outputStreamToProto(&output);
         EXPECT_TRUE(report.has_event_metrics());
         EXPECT_EQ(1, report.event_metrics().data_size());
         ASSERT_EQ(1, report.data_corrupted_reason_size());
@@ -407,12 +383,8 @@ TEST_F(EventMetricProducerTest, TestCorruptedDataReason_OnDumpReport) {
 
     {
         // Check dump report content.
-        ProtoOutputStream output;
-        std::set<string> strSet;
-        eventProducer.onDumpReport(bucketStartTimeNs + 150, true /*include current partial bucket*/,
-                                   true /*erase data*/, FAST, &strSet, &output);
+        StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 150);
 
-        StatsLogReport report = outputStreamToProto(&output);
         EXPECT_TRUE(report.has_event_metrics());
         EXPECT_EQ(1, report.event_metrics().data_size());
         ASSERT_EQ(1, report.data_corrupted_reason_size());
@@ -439,12 +411,8 @@ TEST_F(EventMetricProducerTest, TestCorruptedDataReason_OnDumpReport) {
 
     {
         // Check dump report content.
-        ProtoOutputStream output;
-        std::set<string> strSet;
-        eventProducer.onDumpReport(bucketStartTimeNs + 250, true /*include current partial bucket*/,
-                                   true /*erase data*/, FAST, &strSet, &output);
+        StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 250);
 
-        StatsLogReport report = outputStreamToProto(&output);
         EXPECT_TRUE(report.has_event_metrics());
         EXPECT_EQ(1, report.event_metrics().data_size());
         EXPECT_EQ(2, report.data_corrupted_reason_size());
@@ -681,11 +649,8 @@ TEST_F(EventMetricProducerTest, TestCorruptedDataReason_UnrecoverableLossOfCondi
 
     {
         // Check dump report content.
-        ProtoOutputStream output;
-        eventProducer.onDumpReport(bucketStartTimeNs + 50, true /*include current partial bucket*/,
-                                   true /*erase data*/, FAST, nullptr, &output);
+        StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 50);
 
-        StatsLogReport report = outputStreamToProto(&output);
         EXPECT_TRUE(report.has_event_metrics());
         ASSERT_EQ(1, report.event_metrics().data_size());
         EXPECT_EQ(1, report.data_corrupted_reason_size());
@@ -711,11 +676,7 @@ TEST_F(EventMetricProducerTest, TestCorruptedDataReason_UnrecoverableLossOfCondi
 
     {
         // Check dump report content.
-        ProtoOutputStream output;
-        eventProducer.onDumpReport(bucketStartTimeNs + 150, true /*include current partial bucket*/,
-                                   true /*erase data*/, FAST, nullptr, &output);
-
-        StatsLogReport report = outputStreamToProto(&output);
+        StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 150);
         EXPECT_TRUE(report.has_event_metrics());
         EXPECT_EQ(1, report.event_metrics().data_size());
         EXPECT_EQ(2, report.data_corrupted_reason_size());
@@ -743,11 +704,8 @@ TEST_F(EventMetricProducerTest, TestCorruptedDataReason_UnrecoverableLossOfCondi
 
     {
         // Check dump report content.
-        ProtoOutputStream output;
-        eventProducer.onDumpReport(bucketStartTimeNs + 150, true /*include current partial bucket*/,
-                                   true /*erase data*/, FAST, nullptr, &output);
+        StatsLogReport report = onDumpReport(eventProducer, bucketStartTimeNs + 150);
 
-        StatsLogReport report = outputStreamToProto(&output);
         EXPECT_TRUE(report.has_event_metrics());
         EXPECT_EQ(1, report.event_metrics().data_size());
         EXPECT_EQ(2, report.data_corrupted_reason_size());
diff --git a/statsd/tests/metrics/GaugeMetricProducer_test.cpp b/statsd/tests/metrics/GaugeMetricProducer_test.cpp
index ff3d8d14..ae74dca1 100644
--- a/statsd/tests/metrics/GaugeMetricProducer_test.cpp
+++ b/statsd/tests/metrics/GaugeMetricProducer_test.cpp
@@ -70,6 +70,16 @@ shared_ptr<LogEvent> makeLogEvent(int32_t atomId, int64_t timestampNs, int32_t v
     parseStatsEventToLogEvent(statsEvent, logEvent.get());
     return logEvent;
 }
+
+StatsLogReport onDumpReport(GaugeMetricProducer& producer, int64_t dumpTimeNs,
+                            DumpLatency latency = FAST) {
+    ProtoOutputStream output;
+    set<int32_t> usedUids;
+    producer.onDumpReport(dumpTimeNs, true /*include current partial bucket*/, true /*erase data*/,
+                          latency, nullptr, usedUids, &output);
+    return outputStreamToProto(&output);
+}
+
 }  // anonymous namespace
 
 // Setup for parameterized tests.
@@ -912,12 +922,7 @@ TEST(GaugeMetricProducerTest_BucketDrop, TestBucketDropWhenBucketTooSmall) {
     gaugeProducer.onMatchedLogEvent(1 /*log matcher index*/, triggerEvent);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    gaugeProducer.onDumpReport(bucketStartTimeNs + 9000000, true /* include recent buckets */, true,
-                               FAST /* dump_latency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 9000000);
     EXPECT_TRUE(report.has_gauge_metrics());
     ASSERT_EQ(0, report.gauge_metrics().data_size());
     ASSERT_EQ(1, report.gauge_metrics().skipped_size());
@@ -993,13 +998,8 @@ TEST(GaugeMetricProducerTest, TestPullDimensionalSampling) {
     gaugeProducer.onMatchedLogEvent(1 /*log matcher index*/, triggerEvent);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000000000;
-    gaugeProducer.onDumpReport(dumpReportTimeNs, true /* include current buckets */, true,
-                               NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(gaugeProducer, dumpReportTimeNs, NO_TIME_CONSTRAINTS);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     backfillAggregatedAtoms(&report);
@@ -1022,6 +1022,148 @@ TEST(GaugeMetricProducerTest, TestPullDimensionalSampling) {
                              {bucketStartTimeNs + 10, bucketStartTimeNs + 20});
 }
 
+TEST(GaugeMetricProducerTest, TestCorruptedDataReason_WhatLoss) {
+    StatsdConfig config;
+
+    const int tagId = 1;
+    const int triggerId = 5;
+    const int conditionId = 10;
+
+    GaugeMetric sampledGaugeMetric = createGaugeMetric(
+            "GaugePullSampled", tagId, GaugeMetric::FIRST_N_SAMPLES, nullopt, triggerId);
+    sampledGaugeMetric.set_max_pull_delay_sec(INT_MAX);
+    *config.add_gauge_metric() = sampledGaugeMetric;
+
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    sp<EventMatcherWizard> eventMatcherWizard =
+            createEventMatcherWizard(tagId, logEventMatcherIndex);
+    sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+    GaugeMetricProducer gaugeProducer(
+            kConfigKey, sampledGaugeMetric, 0 /*condition index*/, {ConditionState::kUnknown},
+            wizard, protoHash, logEventMatcherIndex, eventMatcherWizard, tagId, triggerId, tagId,
+            bucketStartTimeNs, bucketStartTimeNs, pullerManager, provider);
+
+    gaugeProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_SOCKET_LOSS,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    gaugeProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+    }
+
+    gaugeProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_SOCKET_LOSS,
+                                        MetricProducer::LostAtomType::kWhat);
+    gaugeProducer.onMatchedLogEventLost(tagId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 250);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(GaugeMetricProducerTest, TestCorruptedDataReason_TriggerLoss) {
+    StatsdConfig config;
+
+    const int tagId = 1;
+    const int triggerId = 5;
+    const int conditionId = 10;
+
+    GaugeMetric sampledGaugeMetric = createGaugeMetric(
+            "GaugePullSampled", tagId, GaugeMetric::FIRST_N_SAMPLES, nullopt, triggerId);
+    sampledGaugeMetric.set_max_pull_delay_sec(INT_MAX);
+    *config.add_gauge_metric() = sampledGaugeMetric;
+
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    sp<EventMatcherWizard> eventMatcherWizard =
+            createEventMatcherWizard(tagId, logEventMatcherIndex);
+    sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+    GaugeMetricProducer gaugeProducer(
+            kConfigKey, sampledGaugeMetric, 0 /*condition index*/, {ConditionState::kUnknown},
+            wizard, protoHash, logEventMatcherIndex, eventMatcherWizard, tagId, triggerId, tagId,
+            bucketStartTimeNs, bucketStartTimeNs, pullerManager, provider);
+
+    gaugeProducer.onMatchedLogEventLost(triggerId, DATA_CORRUPTED_SOCKET_LOSS,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    gaugeProducer.onMatchedLogEventLost(triggerId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+    }
+
+    gaugeProducer.onMatchedLogEventLost(triggerId, DATA_CORRUPTED_SOCKET_LOSS,
+                                        MetricProducer::LostAtomType::kWhat);
+    gaugeProducer.onMatchedLogEventLost(triggerId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                        MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 250);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(GaugeMetricProducerTest, TestCorruptedDataReason_ConditionLoss) {
+    StatsdConfig config;
+
+    const int tagId = 1;
+    const int triggerId = 5;
+    const int conditionId = 10;
+
+    GaugeMetric sampledGaugeMetric = createGaugeMetric(
+            "GaugePullSampled", tagId, GaugeMetric::FIRST_N_SAMPLES, nullopt, triggerId);
+    sampledGaugeMetric.set_max_pull_delay_sec(INT_MAX);
+    *config.add_gauge_metric() = sampledGaugeMetric;
+
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+    sp<EventMatcherWizard> eventMatcherWizard =
+            createEventMatcherWizard(tagId, logEventMatcherIndex);
+    sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+    GaugeMetricProducer gaugeProducer(
+            kConfigKey, sampledGaugeMetric, 0 /*condition index*/, {ConditionState::kUnknown},
+            wizard, protoHash, logEventMatcherIndex, eventMatcherWizard, tagId, triggerId, tagId,
+            bucketStartTimeNs, bucketStartTimeNs, pullerManager, provider);
+
+    gaugeProducer.onMatchedLogEventLost(conditionId, DATA_CORRUPTED_SOCKET_LOSS,
+                                        MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 50);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    gaugeProducer.onMatchedLogEventLost(conditionId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                        MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(gaugeProducer, bucketStartTimeNs + 150);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/metrics/HistogramValue_test.cpp b/statsd/tests/metrics/HistogramValue_test.cpp
new file mode 100644
index 00000000..017fdfa0
--- /dev/null
+++ b/statsd/tests/metrics/HistogramValue_test.cpp
@@ -0,0 +1,64 @@
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
+#include "src/metrics/HistogramValue.h"
+
+#include <gtest/gtest.h>
+
+#ifdef __ANDROID__
+
+using namespace testing;
+
+namespace android {
+namespace os {
+namespace statsd {
+namespace {
+
+TEST(HistogramValueTest, TestGetCompactedBinCountsSize) {
+    EXPECT_EQ(getCompactedBinCountsSize({}), 0);
+    EXPECT_EQ(getCompactedBinCountsSize({0}), 1);
+    EXPECT_EQ(getCompactedBinCountsSize({1}), 1);
+    EXPECT_EQ(getCompactedBinCountsSize({0, 0}), 1);
+    EXPECT_EQ(getCompactedBinCountsSize({0, 1}), 2);
+    EXPECT_EQ(getCompactedBinCountsSize({1, 0}), 2);
+    EXPECT_EQ(getCompactedBinCountsSize({1, 1}), 2);
+    EXPECT_EQ(getCompactedBinCountsSize({1, 0, 0}), 2);
+    EXPECT_EQ(getCompactedBinCountsSize({1, 0, 1}), 3);
+    EXPECT_EQ(getCompactedBinCountsSize({1, 0, 0, 1}), 3);
+    EXPECT_EQ(getCompactedBinCountsSize({1, 0, 1, 0}), 4);
+    EXPECT_EQ(getCompactedBinCountsSize({0, 0, 1, 0, 0}), 3);
+}
+
+TEST(HistogramValueTest, TestErrorBinsMismatch) {
+    EXPECT_EQ(HistogramValue({1, 1, 1}) + HistogramValue({2, 2, 3, 4}),
+              HistogramValue::ERROR_BINS_MISMATCH);
+    EXPECT_EQ(HistogramValue({3, 4, 5}) - HistogramValue({1, 2, 3, 4}),
+              HistogramValue::ERROR_BINS_MISMATCH);
+}
+
+TEST(HistogramValueTest, TestErrorBinCountTooHigh) {
+    EXPECT_EQ(HistogramValue({3, 4, 5}) - HistogramValue({4, 2, 3}),
+              HistogramValue::ERROR_BIN_COUNT_TOO_HIGH);
+}
+
+}  // anonymous namespace
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
+#else
+GTEST_LOG_(INFO) << "This test does nothing.\n";
+#endif
diff --git a/statsd/tests/metrics/KllMetricProducer_test.cpp b/statsd/tests/metrics/KllMetricProducer_test.cpp
index 58d8a731..02406190 100644
--- a/statsd/tests/metrics/KllMetricProducer_test.cpp
+++ b/statsd/tests/metrics/KllMetricProducer_test.cpp
@@ -97,6 +97,15 @@ static void assertPastBucketsSingleKey(
     }
 }
 
+StatsLogReport onDumpReport(sp<KllMetricProducer>& producer, int64_t dumpTimeNs,
+                            bool includeCurrentBucket) {
+    ProtoOutputStream output;
+    set<int32_t> usedUids;
+    producer->onDumpReport(dumpTimeNs, includeCurrentBucket, true /*erase data*/, FAST, nullptr,
+                           usedUids, &output);
+    return outputStreamToProto(&output);
+}
+
 }  // anonymous namespace
 
 class KllMetricProducerTestHelper {
@@ -312,13 +321,9 @@ TEST(KllMetricProducerTest_BucketDrop, TestInvalidBucketWhenConditionUnknown) {
     kllProducer->onConditionChanged(true, bucketStartTimeNs + 50);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000;
-    kllProducer->onDumpReport(dumpReportTimeNs, true /* include recent buckets */, true,
-                              NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report =
+            onDumpReport(kllProducer, dumpReportTimeNs, true /* include current bucket */);
     EXPECT_TRUE(report.has_kll_metrics());
     ASSERT_EQ(0, report.kll_metrics().data_size());
     ASSERT_EQ(1, report.kll_metrics().skipped_size());
@@ -350,13 +355,9 @@ TEST(KllMetricProducerTest_BucketDrop, TestBucketDropWhenBucketTooSmall) {
     kllProducer->onMatchedLogEvent(1 /*log matcher index*/, event1);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 9000000;
-    kllProducer->onDumpReport(dumpReportTimeNs, true /* include recent buckets */, true,
-                              NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report =
+            onDumpReport(kllProducer, dumpReportTimeNs, true /* include current bucket */);
     EXPECT_TRUE(report.has_kll_metrics());
     ASSERT_EQ(0, report.kll_metrics().data_size());
     ASSERT_EQ(1, report.kll_metrics().skipped_size());
@@ -382,13 +383,9 @@ TEST(KllMetricProducerTest_BucketDrop, TestBucketDropWhenDataUnavailable) {
             metric, ConditionState::kFalse);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000000000;  // 10 seconds
-    kllProducer->onDumpReport(dumpReportTimeNs, true /* include current bucket */, true,
-                              NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report =
+            onDumpReport(kllProducer, dumpReportTimeNs, true /* include current bucket */);
     EXPECT_TRUE(report.has_kll_metrics());
     ASSERT_EQ(0, report.kll_metrics().data_size());
     ASSERT_EQ(1, report.kll_metrics().skipped_size());
@@ -418,13 +415,9 @@ TEST(KllMetricProducerTest, TestForcedBucketSplitWhenConditionUnknownSkipsBucket
     kllProducer->notifyAppUpgrade(appUpdateTimeNs);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000000000;  // 10 seconds
-    kllProducer->onDumpReport(dumpReportTimeNs, false /* include current buckets */, true,
-                              NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report =
+            onDumpReport(kllProducer, dumpReportTimeNs, false /* include current bucket */);
     EXPECT_TRUE(report.has_kll_metrics());
     ASSERT_EQ(0, report.kll_metrics().data_size());
     ASSERT_EQ(1, report.kll_metrics().skipped_size());
@@ -461,6 +454,96 @@ TEST(KllMetricProducerTest, TestByteSize) {
     EXPECT_EQ(expectedSize, kllProducer->byteSize());
 }
 
+TEST(KllMetricProducerTest, TestCorruptedDataReason_WhatLoss) {
+    const KllMetric& metric = KllMetricProducerTestHelper::createMetric();
+    sp<KllMetricProducer> kllProducer =
+            KllMetricProducerTestHelper::createKllProducerNoConditions(metric);
+
+    kllProducer->onMatchedLogEventLost(atomId, DATA_CORRUPTED_SOCKET_LOSS,
+                                       MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(kllProducer, bucketStartTimeNs + 50,
+                                             true /* include current bucket */);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    kllProducer->onMatchedLogEventLost(atomId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                       MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(kllProducer, bucketStartTimeNs + 150,
+                                             true /* include current bucket */);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+    }
+
+    kllProducer->onMatchedLogEventLost(atomId, DATA_CORRUPTED_SOCKET_LOSS,
+                                       MetricProducer::LostAtomType::kWhat);
+    kllProducer->onMatchedLogEventLost(atomId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                       MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(kllProducer, bucketStartTimeNs + 250,
+                                             true /* include current bucket */);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(KllMetricProducerTest, TestCorruptedDataReason_ConditionLoss) {
+    const int conditionId = 10;
+
+    const KllMetric& metric = KllMetricProducerTestHelper::createMetricWithCondition();
+
+    sp<KllMetricProducer> kllProducer = KllMetricProducerTestHelper::createKllProducerWithCondition(
+            metric, ConditionState::kFalse);
+
+    kllProducer->onMatchedLogEventLost(conditionId, DATA_CORRUPTED_SOCKET_LOSS,
+                                       MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(kllProducer, bucketStartTimeNs + 50,
+                                             true /* include current bucket */);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    kllProducer->onMatchedLogEventLost(conditionId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                       MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(kllProducer, bucketStartTimeNs + 150,
+                                             true /* include current bucket */);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(KllMetricProducerTest, TestCorruptedDataReason_StateLoss) {
+    const int stateAtomId = 10;
+
+    const KllMetric& metric = KllMetricProducerTestHelper::createMetricWithCondition();
+
+    sp<KllMetricProducer> kllProducer = KllMetricProducerTestHelper::createKllProducerWithCondition(
+            metric, ConditionState::kFalse);
+
+    kllProducer->onStateEventLost(stateAtomId, DATA_CORRUPTED_SOCKET_LOSS);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(kllProducer, bucketStartTimeNs + 50,
+                                             true /* include current bucket */);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    // validation that data corruption signal remains accurate after another dump
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(kllProducer, bucketStartTimeNs + 150,
+                                             true /* include current bucket */);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/metrics/MaxDurationTracker_test.cpp b/statsd/tests/metrics/MaxDurationTracker_test.cpp
index 1df37e93..824b8d34 100644
--- a/statsd/tests/metrics/MaxDurationTracker_test.cpp
+++ b/statsd/tests/metrics/MaxDurationTracker_test.cpp
@@ -246,6 +246,61 @@ TEST(MaxDurationTrackerTest, TestMaxDurationWithCondition) {
     EXPECT_EQ((int64_t)(13LL * NS_PER_SEC), item[0].mDuration);
 }
 
+TEST(MaxDurationTrackerTest, TestMaxDurationNestedWithCondition) {
+    const HashableDimensionKey conditionDimKey = key1;
+
+    sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
+
+    ConditionKey conditionKey1;
+    MetricDimensionKey eventKey = getMockedMetricDimensionKey(TagId, 1, "1");
+    conditionKey1[StringToId("APP_BACKGROUND")] = conditionDimKey;
+
+    /**
+     * The test sequence is to confirm that max duration is updated
+     * only when nested predicated is completely stopped
+     * If report dump happens while predicate is paused - no max duration is reported
+     */
+    int64_t bucketStartTimeNs = 10000000000;
+    int64_t bucketEndTimeNs = bucketStartTimeNs + bucketSizeNs;
+    int64_t event1StartTimeNs = bucketStartTimeNs + 10 * NS_PER_SEC;
+    int64_t conditionStart1Ns = event1StartTimeNs;
+    int64_t event2StartTimeNs = bucketStartTimeNs + 30 * NS_PER_SEC;
+    int64_t conditionStop1Ns = bucketStartTimeNs + 50 * NS_PER_SEC;
+    int64_t conditionStart2Ns = bucketStartTimeNs + 60 * NS_PER_SEC;
+    int64_t event2StopTimeNs = bucketStartTimeNs + 100 * NS_PER_SEC;
+    int64_t dumpReport1TimeNs = bucketStartTimeNs + 110 * NS_PER_SEC;
+    int64_t event1StopTimeNs = bucketStartTimeNs + 130 * NS_PER_SEC;
+    int64_t dumpReport2TimeNs = bucketStartTimeNs + 150 * NS_PER_SEC;
+
+    int64_t metricId = 1;
+    MaxDurationTracker tracker(kConfigKey, metricId, eventKey, wizard, 1, /*nesting*/ true,
+                               bucketStartTimeNs, 0, bucketStartTimeNs, bucketSizeNs, true, false,
+                               {});
+
+    tracker.noteStart(key1, false, event1StartTimeNs, conditionKey1,
+                      StatsdStats::kDimensionKeySizeHardLimitMin);
+    tracker.noteConditionChanged(key1, true, conditionStart1Ns);
+    tracker.noteStart(key1, true, event2StartTimeNs, conditionKey1,
+                      StatsdStats::kDimensionKeySizeHardLimitMin);
+    // will update lastDuration
+    tracker.noteConditionChanged(key1, false, conditionStop1Ns);
+    tracker.noteConditionChanged(key1, true, conditionStart2Ns);
+    // must not update maxDuration - since nested predicate is not finished yet
+    tracker.noteStop(key1, event2StopTimeNs, false);
+
+    unordered_map<MetricDimensionKey, vector<DurationBucket>> buckets;
+    tracker.flushIfNeeded(dumpReport1TimeNs, emptyThreshold, &buckets);
+    ASSERT_EQ(0U, buckets.size());
+
+    // must update maxDuration - since nested predicate is finished
+    tracker.noteStop(key1, event1StopTimeNs, false);
+    tracker.flushIfNeeded(dumpReport2TimeNs, emptyThreshold, &buckets);
+    ASSERT_EQ(1U, buckets.size());
+    vector<DurationBucket> item = buckets.begin()->second;
+    ASSERT_EQ(1UL, item.size());
+    EXPECT_EQ((int64_t)(110LL * NS_PER_SEC), item[0].mDuration);
+}
+
 TEST(MaxDurationTrackerTest, TestAnomalyDetection) {
     sp<MockConditionWizard> wizard = new NaggyMock<MockConditionWizard>();
 
diff --git a/statsd/tests/metrics/NumericValueMetricProducer_test.cpp b/statsd/tests/metrics/NumericValueMetricProducer_test.cpp
index ed9a296c..2d48b4b6 100644
--- a/statsd/tests/metrics/NumericValueMetricProducer_test.cpp
+++ b/statsd/tests/metrics/NumericValueMetricProducer_test.cpp
@@ -61,7 +61,8 @@ const int64_t bucket6StartTimeNs = bucketStartTimeNs + 5 * bucketSizeNs;
 double epsilon = 0.001;
 
 static void assertPastBucketValuesSingleKey(
-        const std::unordered_map<MetricDimensionKey, std::vector<PastBucket<Value>>>& mPastBuckets,
+        const std::unordered_map<MetricDimensionKey, std::vector<PastBucket<NumericValue>>>&
+                mPastBuckets,
         const std::initializer_list<int>& expectedValuesList,
         const std::initializer_list<int64_t>& expectedDurationNsList,
         const std::initializer_list<int64_t>& expectedCorrectionNsList,
@@ -86,9 +87,9 @@ static void assertPastBucketValuesSingleKey(
     ASSERT_EQ(1, mPastBuckets.size());
     ASSERT_EQ(expectedValues.size(), mPastBuckets.begin()->second.size());
 
-    const vector<PastBucket<Value>>& buckets = mPastBuckets.begin()->second;
+    const vector<PastBucket<NumericValue>>& buckets = mPastBuckets.begin()->second;
     for (int i = 0; i < expectedValues.size(); i++) {
-        EXPECT_EQ(expectedValues[i], buckets[i].aggregates[0].long_value)
+        EXPECT_EQ(expectedValues[i], buckets[i].aggregates[0].getValue<int64_t>())
                 << "Values differ at index " << i;
         EXPECT_EQ(expectedDurationNs[i], buckets[i].mConditionTrueNs)
                 << "Condition duration value differ at index " << i;
@@ -101,6 +102,15 @@ static void assertPastBucketValuesSingleKey(
     }
 }
 
+StatsLogReport onDumpReport(sp<NumericValueMetricProducer>& producer, int64_t dumpTimeNs,
+                            bool includeCurrentBucket, DumpLatency dumpLatency) {
+    ProtoOutputStream output;
+    set<int32_t> usedUids;
+    producer->onDumpReport(dumpTimeNs, includeCurrentBucket, true /*erase data*/, dumpLatency,
+                           nullptr, usedUids, &output);
+    return outputStreamToProto(&output);
+}
+
 }  // anonymous namespace
 
 class NumericValueMetricProducerTestHelper {
@@ -319,10 +329,10 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsNoCondition) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     // dimInfos holds the base
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
 
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(11, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(11, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {8}, {bucketSizeNs}, {0},
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
 
@@ -335,8 +345,8 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsNoCondition) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
 
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(23, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(23, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(
             valueProducer->mPastBuckets, {8, 12}, {bucketSizeNs, bucketSizeNs}, {0, 0},
             {bucketStartTimeNs, bucket2StartTimeNs}, {bucket2StartTimeNs, bucket3StartTimeNs});
@@ -350,8 +360,8 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsNoCondition) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
 
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(36, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(36, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {8, 12, 13},
                                     {bucketSizeNs, bucketSizeNs, bucketSizeNs}, {0, 0, 0},
                                     {bucketStartTimeNs, bucket2StartTimeNs, bucket3StartTimeNs},
@@ -444,10 +454,10 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsWithFiltering) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     // dimInfos holds the base
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
 
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(11, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(11, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {8}, {bucketSizeNs}, {0},
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
 
@@ -466,8 +476,8 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsWithFiltering) {
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
 
     // the base was reset
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(36, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(36, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {8}, {bucketSizeNs}, {0},
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
 }
@@ -495,10 +505,10 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsTakeAbsoluteValueOnReset) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     // dimInfos holds the base
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
 
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(11, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(11, curBase.getValue<int64_t>());
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
     allData.clear();
@@ -509,8 +519,8 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsTakeAbsoluteValueOnReset) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(10, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(10, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {10}, {bucketSizeNs}, {0},
                                     {bucket2StartTimeNs}, {bucket3StartTimeNs});
 
@@ -520,8 +530,8 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsTakeAbsoluteValueOnReset) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(36, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(36, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(
             valueProducer->mPastBuckets, {10, 26}, {bucketSizeNs, bucketSizeNs}, {0, 0},
             {bucket2StartTimeNs, bucket3StartTimeNs}, {bucket3StartTimeNs, bucket4StartTimeNs});
@@ -548,10 +558,10 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsTakeZeroOnReset) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     // mDimInfos holds the base
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
 
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(11, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(11, curBase.getValue<int64_t>());
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
     allData.clear();
@@ -561,8 +571,8 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsTakeZeroOnReset) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(10, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(10, curBase.getValue<int64_t>());
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
     allData.clear();
@@ -571,8 +581,8 @@ TEST(NumericValueMetricProducerTest, TestPulledEventsTakeZeroOnReset) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(36, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(36, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {26}, {bucketSizeNs}, {0},
                                     {bucket3StartTimeNs}, {bucket4StartTimeNs});
 }
@@ -619,10 +629,10 @@ TEST(NumericValueMetricProducerTest, TestEventsWithNonSlicedCondition) {
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     // startUpdated:false sum:0 start:100
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(100, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(100, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
@@ -636,8 +646,8 @@ TEST(NumericValueMetricProducerTest, TestEventsWithNonSlicedCondition) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(110, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(110, curBase.getValue<int64_t>());
 
     valueProducer->onConditionChanged(false, bucket2StartTimeNs + 1);
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {10}, {bucketSizeNs - 8}, {0},
@@ -649,8 +659,8 @@ TEST(NumericValueMetricProducerTest, TestEventsWithNonSlicedCondition) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(20, curInterval.aggregate.long_value);
-    EXPECT_EQ(false, curBase.has_value());
+    EXPECT_EQ(20, curInterval.aggregate.getValue<int64_t>());
+    EXPECT_FALSE(curBase.hasValue());
 
     valueProducer->onConditionChanged(true, bucket3StartTimeNs + 1);
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {10, 20}, {bucketSizeNs - 8, 1},
@@ -867,8 +877,8 @@ TEST(NumericValueMetricProducerTest, TestPushedEventsWithoutCondition) {
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(10, curInterval.aggregate.long_value);
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_EQ(10, curInterval.aggregate.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
 
     valueProducer->onMatchedLogEvent(1 /*log matcher index*/, event2);
@@ -876,14 +886,11 @@ TEST(NumericValueMetricProducerTest, TestPushedEventsWithoutCondition) {
     // has one slice
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(30, curInterval.aggregate.long_value);
+    EXPECT_EQ(30, curInterval.aggregate.getValue<int64_t>());
 
     // Check dump report.
-    ProtoOutputStream output;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 10000, false /* include recent buckets */,
-                                true, FAST /* dumpLatency */, nullptr, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 10000,
+                                         false /* include recent buckets */, FAST);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -929,7 +936,7 @@ TEST(NumericValueMetricProducerTest, TestPushedEventsWithCondition) {
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(20, curInterval.aggregate.long_value);
+    EXPECT_EQ(20, curInterval.aggregate.getValue<int64_t>());
 
     LogEvent event3(/*uid=*/0, /*pid=*/0);
     CreateRepeatedValueLogEvent(&event3, tagId, bucketStartTimeNs + 30, 30);
@@ -938,7 +945,7 @@ TEST(NumericValueMetricProducerTest, TestPushedEventsWithCondition) {
     // has one slice
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(50, curInterval.aggregate.long_value);
+    EXPECT_EQ(50, curInterval.aggregate.getValue<int64_t>());
 
     valueProducer->onConditionChangedLocked(false, bucketStartTimeNs + 35);
 
@@ -949,14 +956,11 @@ TEST(NumericValueMetricProducerTest, TestPushedEventsWithCondition) {
     // has one slice
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(50, curInterval.aggregate.long_value);
+    EXPECT_EQ(50, curInterval.aggregate.getValue<int64_t>());
 
     // Check dump report.
-    ProtoOutputStream output;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 10000, false /* include recent buckets */,
-                                true, FAST /* dumpLatency */, nullptr, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 10000,
+                                         false /* include recent buckets */, FAST);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -1110,11 +1114,11 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryNoCondition) {
     // empty since bucket is finished
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
 
     // startUpdated:true sum:0 start:11
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(11, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(11, curBase.getValue<int64_t>());
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
     // pull 2 at correct time
@@ -1126,8 +1130,8 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryNoCondition) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     // tartUpdated:false sum:12
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(23, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(23, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {12}, {bucketSizeNs}, {0},
                                     {bucket2StartTimeNs}, {bucket3StartTimeNs});
 
@@ -1142,8 +1146,8 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryNoCondition) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     // startUpdated:false sum:12
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(36, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(36, curBase.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {12}, {bucketSizeNs}, {0},
                                     {bucket2StartTimeNs}, {bucket3StartTimeNs});
     // The 1st bucket is dropped because of no data
@@ -1199,9 +1203,9 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryWithCondition) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(100, curBase.value().long_value);
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(100, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
@@ -1212,7 +1216,7 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryWithCondition) {
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {20}, {bucketSizeNs - 8}, {1},
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
-    EXPECT_EQ(false, curBase.has_value());
+    EXPECT_FALSE(curBase.hasValue());
 
     // Now the alarm is delivered.
     // since the condition turned to off before this pull finish, it has no effect
@@ -1225,7 +1229,7 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryWithCondition) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(false, curBase.has_value());
+    EXPECT_FALSE(curBase.hasValue());
 }
 
 /*
@@ -1272,10 +1276,10 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryWithCondition2) {
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     // startUpdated:false sum:0 start:100
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(100, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(100, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
@@ -1286,7 +1290,7 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryWithCondition2) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(false, curBase.has_value());
+    EXPECT_FALSE(curBase.hasValue());
 
     // condition changed to true again, before the pull alarm is delivered
     valueProducer->onConditionChanged(true, bucket2StartTimeNs + 25);
@@ -1296,8 +1300,8 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryWithCondition2) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(130, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(130, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
 
     // Now the alarm is delivered, but it is considered late, the data will be used
@@ -1310,10 +1314,10 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundaryWithCondition2) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(140, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(140, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(10, curInterval.aggregate.long_value);
+    EXPECT_EQ(10, curInterval.aggregate.getValue<int64_t>());
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {20}, {bucketSizeNs - 8}, {1},
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
 
@@ -1350,7 +1354,7 @@ TEST(NumericValueMetricProducerTest, TestPushedAggregateMin) {
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(10, curInterval.aggregate.long_value);
+    EXPECT_EQ(10, curInterval.aggregate.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
 
     valueProducer->onMatchedLogEvent(1 /*log matcher index*/, event2);
@@ -1358,7 +1362,7 @@ TEST(NumericValueMetricProducerTest, TestPushedAggregateMin) {
     // has one slice
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(10, curInterval.aggregate.long_value);
+    EXPECT_EQ(10, curInterval.aggregate.getValue<int64_t>());
 
     valueProducer->flushIfNeededLocked(bucket2StartTimeNs);
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
@@ -1387,7 +1391,7 @@ TEST(NumericValueMetricProducerTest, TestPushedAggregateMax) {
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(10, curInterval.aggregate.long_value);
+    EXPECT_EQ(10, curInterval.aggregate.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
 
     LogEvent event2(/*uid=*/0, /*pid=*/0);
@@ -1397,7 +1401,7 @@ TEST(NumericValueMetricProducerTest, TestPushedAggregateMax) {
     // has one slice
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(20, curInterval.aggregate.long_value);
+    EXPECT_EQ(20, curInterval.aggregate.getValue<int64_t>());
 
     valueProducer->flushIfNeededLocked(bucket2StartTimeNs);
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {20}, {bucketSizeNs}, {0},
@@ -1430,23 +1434,25 @@ TEST(NumericValueMetricProducerTest, TestPushedAggregateAvg) {
     NumericValueMetricProducer::Interval curInterval;
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     EXPECT_EQ(1, curInterval.sampleSize);
-    EXPECT_EQ(10, curInterval.aggregate.long_value);
+    EXPECT_EQ(10, curInterval.aggregate.getValue<int64_t>());
 
     valueProducer->onMatchedLogEvent(1 /*log matcher index*/, event2);
 
     // has one slice
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(25, curInterval.aggregate.long_value);
+    EXPECT_EQ(25, curInterval.aggregate.getValue<int64_t>());
     EXPECT_EQ(2, curInterval.sampleSize);
 
     valueProducer->flushIfNeededLocked(bucket2StartTimeNs);
     ASSERT_EQ(1UL, valueProducer->mPastBuckets.size());
     ASSERT_EQ(1UL, valueProducer->mPastBuckets.begin()->second.size());
 
-    EXPECT_TRUE(
-            std::abs(valueProducer->mPastBuckets.begin()->second.back().aggregates[0].double_value -
-                     12.5) < epsilon);
+    EXPECT_TRUE(std::abs(valueProducer->mPastBuckets.begin()
+                                 ->second.back()
+                                 .aggregates[0]
+                                 .getValue<double>() -
+                         12.5) < epsilon);
     EXPECT_EQ(2, valueProducer->mPastBuckets.begin()->second.back().sampleSizes[0]);
 }
 
@@ -1473,7 +1479,7 @@ TEST(NumericValueMetricProducerTest, TestPushedAggregateSum) {
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(10, curInterval.aggregate.long_value);
+    EXPECT_EQ(10, curInterval.aggregate.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
 
     valueProducer->onMatchedLogEvent(1 /*log matcher index*/, event2);
@@ -1481,7 +1487,7 @@ TEST(NumericValueMetricProducerTest, TestPushedAggregateSum) {
     // has one slice
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    EXPECT_EQ(25, curInterval.aggregate.long_value);
+    EXPECT_EQ(25, curInterval.aggregate.getValue<int64_t>());
 
     valueProducer->flushIfNeededLocked(bucket2StartTimeNs);
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {25}, {bucketSizeNs}, {0},
@@ -1511,9 +1517,9 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutput) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(10, curBase.value().long_value);
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(10, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
 
     LogEvent event2(/*uid=*/0, /*pid=*/0);
@@ -1525,10 +1531,10 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutput) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(15, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(15, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(5, curInterval.aggregate.long_value);
+    EXPECT_EQ(5, curInterval.aggregate.getValue<int64_t>());
 
     // no change in data.
     LogEvent event3(/*uid=*/0, /*pid=*/0);
@@ -1539,10 +1545,10 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutput) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(15, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(15, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(0, curInterval.aggregate.long_value);
+    EXPECT_EQ(0, curInterval.aggregate.getValue<int64_t>());
 
     LogEvent event4(/*uid=*/0, /*pid=*/0);
     CreateRepeatedValueLogEvent(&event4, tagId, bucket2StartTimeNs + 15, 15);
@@ -1551,10 +1557,10 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutput) {
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(15, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(15, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(0, curInterval.aggregate.long_value);
+    EXPECT_EQ(0, curInterval.aggregate.getValue<int64_t>());
 
     valueProducer->flushIfNeededLocked(bucket3StartTimeNs);
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {5}, {bucketSizeNs}, {10},
@@ -1588,12 +1594,12 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutputMultiValue) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(10, curBase.value().long_value);
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(10, curBase.getValue<int64_t>());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[1];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(20, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(20, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
 
     valueProducer->onMatchedLogEvent(1 /*log matcher index*/, event2);
@@ -1603,16 +1609,16 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutputMultiValue) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(15, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(15, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(5, curInterval.aggregate.long_value);
+    EXPECT_EQ(5, curInterval.aggregate.getValue<int64_t>());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[1];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[1];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(22, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(22, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(2, curInterval.aggregate.long_value);
+    EXPECT_EQ(2, curInterval.aggregate.getValue<int64_t>());
 
     // no change in first value field
     LogEvent event3(/*uid=*/0, /*pid=*/0);
@@ -1623,16 +1629,16 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutputMultiValue) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(15, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(15, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(0, curInterval.aggregate.long_value);
+    EXPECT_EQ(0, curInterval.aggregate.getValue<int64_t>());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[1];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[1];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(25, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(25, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(3, curInterval.aggregate.long_value);
+    EXPECT_EQ(3, curInterval.aggregate.getValue<int64_t>());
 
     LogEvent event4(/*uid=*/0, /*pid=*/0);
     CreateThreeValueLogEvent(&event4, tagId, bucket2StartTimeNs + 15, 1, 15, 29);
@@ -1641,16 +1647,16 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutputMultiValue) {
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(15, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(15, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(0, curInterval.aggregate.long_value);
+    EXPECT_EQ(0, curInterval.aggregate.getValue<int64_t>());
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[1];
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[1];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(29, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(29, curBase.getValue<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(3, curInterval.aggregate.long_value);
+    EXPECT_EQ(3, curInterval.aggregate.getValue<int64_t>());
 
     valueProducer->flushIfNeededLocked(bucket3StartTimeNs);
 
@@ -1660,13 +1666,13 @@ TEST(NumericValueMetricProducerTest, TestSkipZeroDiffOutputMultiValue) {
     ASSERT_EQ(1UL, valueProducer->mPastBuckets.begin()->second[1].aggregates.size());
 
     EXPECT_EQ(bucketSizeNs, valueProducer->mPastBuckets.begin()->second[0].mConditionTrueNs);
-    EXPECT_EQ(5, valueProducer->mPastBuckets.begin()->second[0].aggregates[0].long_value);
+    EXPECT_EQ(5, valueProducer->mPastBuckets.begin()->second[0].aggregates[0].getValue<int64_t>());
     EXPECT_EQ(0, valueProducer->mPastBuckets.begin()->second[0].aggIndex[0]);
-    EXPECT_EQ(2, valueProducer->mPastBuckets.begin()->second[0].aggregates[1].long_value);
+    EXPECT_EQ(2, valueProducer->mPastBuckets.begin()->second[0].aggregates[1].getValue<int64_t>());
     EXPECT_EQ(1, valueProducer->mPastBuckets.begin()->second[0].aggIndex[1]);
 
     EXPECT_EQ(bucketSizeNs, valueProducer->mPastBuckets.begin()->second[1].mConditionTrueNs);
-    EXPECT_EQ(3, valueProducer->mPastBuckets.begin()->second[1].aggregates[0].long_value);
+    EXPECT_EQ(3, valueProducer->mPastBuckets.begin()->second[1].aggregates[0].getValue<int64_t>());
     EXPECT_EQ(1, valueProducer->mPastBuckets.begin()->second[1].aggIndex[0]);
 }
 
@@ -1699,8 +1705,8 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBase) {
     auto iterBase = valueProducer->mDimInfos.begin();
     auto& base1 = iterBase->second.dimExtras[0];
     EXPECT_EQ(1, iter->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
-    EXPECT_EQ(true, base1.has_value());
-    EXPECT_EQ(3, base1.value().long_value);
+    EXPECT_TRUE(base1.is<int64_t>());
+    EXPECT_EQ(3, base1.getValue<int64_t>());
     EXPECT_EQ(0, interval1.sampleSize);
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
@@ -1713,8 +1719,8 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBase) {
     valueProducer->onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS, bucket2StartTimeNs);
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(2UL, valueProducer->mDimInfos.size());
-    EXPECT_EQ(true, base1.has_value());
-    EXPECT_EQ(11, base1.value().long_value);
+    EXPECT_TRUE(base1.is<int64_t>());
+    EXPECT_EQ(11, base1.getValue<int64_t>());
 
     auto itBase = valueProducer->mDimInfos.begin();
     for (; itBase != valueProducer->mDimInfos.end(); itBase++) {
@@ -1724,16 +1730,16 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBase) {
     }
     EXPECT_TRUE(itBase != iterBase);
     auto& base2 = itBase->second.dimExtras[0];
-    EXPECT_EQ(true, base2.has_value());
-    EXPECT_EQ(4, base2.value().long_value);
+    EXPECT_TRUE(base2.is<int64_t>());
+    EXPECT_EQ(4, base2.getValue<int64_t>());
 
     ASSERT_EQ(2UL, valueProducer->mPastBuckets.size());
     auto iterator = valueProducer->mPastBuckets.begin();
     EXPECT_EQ(bucketSizeNs, iterator->second[0].mConditionTrueNs);
-    EXPECT_EQ(8, iterator->second[0].aggregates[0].long_value);
+    EXPECT_EQ(8, iterator->second[0].aggregates[0].getValue<int64_t>());
     iterator++;
     EXPECT_EQ(bucketSizeNs, iterator->second[0].mConditionTrueNs);
-    EXPECT_EQ(4, iterator->second[0].aggregates[0].long_value);
+    EXPECT_EQ(4, iterator->second[0].aggregates[0].getValue<int64_t>());
 }
 
 /*
@@ -1762,11 +1768,11 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBaseWithPullFailures) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     const auto& it = valueProducer->mCurrentSlicedBucket.begin();
     NumericValueMetricProducer::Interval& interval1 = it->second.intervals[0];
-    optional<Value>& base1 =
+    NumericValue& base1 =
             valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat())->second.dimExtras[0];
     EXPECT_EQ(1, it->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
-    EXPECT_EQ(true, base1.has_value());
-    EXPECT_EQ(3, base1.value().long_value);
+    EXPECT_TRUE(base1.is<int64_t>());
+    EXPECT_EQ(3, base1.getValue<int64_t>());
     EXPECT_EQ(0, interval1.sampleSize);
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
@@ -1779,8 +1785,8 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBaseWithPullFailures) {
     valueProducer->onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS, bucket2StartTimeNs);
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(2UL, valueProducer->mDimInfos.size());
-    EXPECT_EQ(true, base1.has_value());
-    EXPECT_EQ(11, base1.value().long_value);
+    EXPECT_TRUE(base1.is<int64_t>());
+    EXPECT_EQ(11, base1.getValue<int64_t>());
 
     auto itBase2 = valueProducer->mDimInfos.begin();
     for (; itBase2 != valueProducer->mDimInfos.end(); itBase2++) {
@@ -1788,11 +1794,11 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBaseWithPullFailures) {
             break;
         }
     }
-    optional<Value>& base2 = itBase2->second.dimExtras[0];
+    NumericValue& base2 = itBase2->second.dimExtras[0];
     EXPECT_TRUE(base2 != base1);
     EXPECT_EQ(2, itBase2->first.getValues()[0].mValue.int_value);
-    EXPECT_EQ(true, base2.has_value());
-    EXPECT_EQ(4, base2.value().long_value);
+    EXPECT_TRUE(base2.is<int64_t>());
+    EXPECT_EQ(4, base2.getValue<int64_t>());
     ASSERT_EQ(2UL, valueProducer->mPastBuckets.size());
 
     // next pull somehow did not happen, skip to end of bucket 3
@@ -1804,9 +1810,9 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBaseWithPullFailures) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     EXPECT_EQ(2, valueProducer->mDimInfos.begin()->first.getValues()[0].mValue.int_value);
-    optional<Value>& base3 = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, base3.has_value());
-    EXPECT_EQ(5, base3.value().long_value);
+    NumericValue& base3 = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(base3.is<int64_t>());
+    EXPECT_EQ(5, base3.getValue<int64_t>());
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
     ASSERT_EQ(2UL, valueProducer->mPastBuckets.size());
 
@@ -1817,14 +1823,14 @@ TEST(NumericValueMetricProducerTest, TestUseZeroDefaultBaseWithPullFailures) {
 
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(2UL, valueProducer->mDimInfos.size());
-    optional<Value>& base4 = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    optional<Value>& base5 = std::next(valueProducer->mDimInfos.begin())->second.dimExtras[0];
+    NumericValue& base4 = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    NumericValue& base5 = std::next(valueProducer->mDimInfos.begin())->second.dimExtras[0];
 
-    EXPECT_EQ(true, base4.has_value());
-    EXPECT_EQ(5, base4.value().long_value);
+    EXPECT_TRUE(base4.is<int64_t>());
+    EXPECT_EQ(5, base4.getValue<int64_t>());
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
-    EXPECT_EQ(true, base5.has_value());
-    EXPECT_EQ(13, base5.value().long_value);
+    EXPECT_TRUE(base5.is<int64_t>());
+    EXPECT_EQ(13, base5.getValue<int64_t>());
 
     ASSERT_EQ(2UL, valueProducer->mPastBuckets.size());
 }
@@ -1857,8 +1863,8 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     auto iterBase = valueProducer->mDimInfos.begin();
     auto& base1 = iterBase->second.dimExtras[0];
     EXPECT_EQ(1, iter->first.getDimensionKeyInWhat().getValues()[0].mValue.int_value);
-    EXPECT_EQ(true, base1.has_value());
-    EXPECT_EQ(3, base1.value().long_value);
+    EXPECT_TRUE(base1.is<int64_t>());
+    EXPECT_EQ(3, base1.getValue<int64_t>());
     EXPECT_EQ(0, interval1.sampleSize);
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
@@ -1870,8 +1876,8 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
 
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(2UL, valueProducer->mDimInfos.size());
-    EXPECT_EQ(true, base1.has_value());
-    EXPECT_EQ(11, base1.value().long_value);
+    EXPECT_TRUE(base1.is<int64_t>());
+    EXPECT_EQ(11, base1.getValue<int64_t>());
     EXPECT_FALSE(iterBase->second.seenNewData);
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {8}, {bucketSizeNs}, {0},
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
@@ -1885,8 +1891,8 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     EXPECT_TRUE(itBase != iterBase);
     auto base2 = itBase->second.dimExtras[0];
     EXPECT_EQ(2, itBase->first.getValues()[0].mValue.int_value);
-    EXPECT_EQ(true, base2.has_value());
-    EXPECT_EQ(4, base2.value().long_value);
+    EXPECT_TRUE(base2.is<int64_t>());
+    EXPECT_EQ(4, base2.getValue<int64_t>());
     EXPECT_FALSE(itBase->second.seenNewData);
 
     // next pull somehow did not happen, skip to end of bucket 3
@@ -1898,8 +1904,8 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     base2 = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     EXPECT_EQ(2, valueProducer->mDimInfos.begin()->first.getValues()[0].mValue.int_value);
-    EXPECT_EQ(true, base2.has_value());
-    EXPECT_EQ(5, base2.value().long_value);
+    EXPECT_TRUE(base2.is<int64_t>());
+    EXPECT_EQ(5, base2.getValue<int64_t>());
     EXPECT_FALSE(valueProducer->mDimInfos.begin()->second.seenNewData);
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {8}, {bucketSizeNs}, {0},
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
@@ -1928,11 +1934,11 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     ASSERT_EQ(2, iterator->second.size());
     EXPECT_EQ(bucket4StartTimeNs, iterator->second[0].mBucketStartNs);
     EXPECT_EQ(bucket5StartTimeNs, iterator->second[0].mBucketEndNs);
-    EXPECT_EQ(9, iterator->second[0].aggregates[0].long_value);
+    EXPECT_EQ(9, iterator->second[0].aggregates[0].getValue<int64_t>());
     EXPECT_EQ(bucketSizeNs, iterator->second[0].mConditionTrueNs);
     EXPECT_EQ(bucket5StartTimeNs, iterator->second[1].mBucketStartNs);
     EXPECT_EQ(bucket6StartTimeNs, iterator->second[1].mBucketEndNs);
-    EXPECT_EQ(6, iterator->second[1].aggregates[0].long_value);
+    EXPECT_EQ(6, iterator->second[1].aggregates[0].getValue<int64_t>());
     EXPECT_EQ(bucketSizeNs, iterator->second[1].mConditionTrueNs);
     iterator++;
     // Dimension = 1
@@ -1941,11 +1947,11 @@ TEST(NumericValueMetricProducerTest, TestTrimUnusedDimensionKey) {
     ASSERT_EQ(2, iterator->second.size());
     EXPECT_EQ(bucketStartTimeNs, iterator->second[0].mBucketStartNs);
     EXPECT_EQ(bucket2StartTimeNs, iterator->second[0].mBucketEndNs);
-    EXPECT_EQ(8, iterator->second[0].aggregates[0].long_value);
+    EXPECT_EQ(8, iterator->second[0].aggregates[0].getValue<int64_t>());
     EXPECT_EQ(bucketSizeNs, iterator->second[0].mConditionTrueNs);
     EXPECT_EQ(bucket5StartTimeNs, iterator->second[1].mBucketStartNs);
     EXPECT_EQ(bucket6StartTimeNs, iterator->second[1].mBucketEndNs);
-    EXPECT_EQ(5, iterator->second[1].aggregates[0].long_value);
+    EXPECT_EQ(5, iterator->second[1].aggregates[0].getValue<int64_t>());
     EXPECT_EQ(bucketSizeNs, iterator->second[1].mConditionTrueNs);
 }
 
@@ -1971,16 +1977,16 @@ TEST(NumericValueMetricProducerTest, TestResetBaseOnPullFailAfterConditionChange
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     NumericValueMetricProducer::Interval& curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value>& curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(100, curBase.value().long_value);
+    NumericValue& curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(100, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
 
     vector<shared_ptr<LogEvent>> allData;
     valueProducer->onDataPulled(allData, PullResult::PULL_RESULT_FAIL, bucket2StartTimeNs);
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    EXPECT_EQ(false, curBase.has_value());
+    EXPECT_FALSE(curBase.hasValue());
     EXPECT_EQ(false, valueProducer->mHasGlobalBase);
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
     ASSERT_EQ(1UL, valueProducer->mSkippedBuckets.size());
@@ -2011,9 +2017,9 @@ TEST(NumericValueMetricProducerTest, TestResetBaseOnPullFailAfterConditionChange
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval& curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value>& curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(100, curBase.value().long_value);
+    NumericValue& curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(100, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
     ASSERT_EQ(0UL, valueProducer->mPastBuckets.size());
 
@@ -2023,7 +2029,7 @@ TEST(NumericValueMetricProducerTest, TestResetBaseOnPullFailAfterConditionChange
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     EXPECT_EQ(0, curInterval.sampleSize);
-    EXPECT_EQ(false, curBase.has_value());
+    EXPECT_FALSE(curBase.hasValue());
     EXPECT_EQ(false, valueProducer->mHasGlobalBase);
 }
 
@@ -2060,8 +2066,8 @@ TEST(NumericValueMetricProducerTest, TestResetBaseOnPullFailBeforeConditionChang
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval& curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(false, curBase.has_value());
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_FALSE(curBase.hasValue());
     EXPECT_EQ(0, curInterval.sampleSize);
     EXPECT_EQ(false, valueProducer->mHasGlobalBase);
 }
@@ -2131,9 +2137,9 @@ TEST(NumericValueMetricProducerTest, TestBaseSetOnConditionChange) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval& curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(100, curBase.value().long_value);
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(100, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
 }
@@ -2183,18 +2189,14 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenOneConditio
     // Contains base from last pull which was successful.
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(140, curBase.value().long_value);
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(140, curBase.getValue<int64_t>());
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 10, false /* include partial bucket */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 10,
+                                         false /* include recent buckets */, FAST);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -2251,13 +2253,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenGuardRailHi
     ASSERT_EQ(1UL, valueProducer->mSkippedBuckets.size());
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 10000, false /* include recent buckets */,
-                                true, FAST /* dumpLatency */, &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 10000,
+                                         false /* include recent buckets */, FAST);
     ASSERT_EQ(true, StatsdStats::getInstance().hasHitDimensionGuardrail(metricId));
-
-    StatsLogReport report = outputStreamToProto(&output);
     EXPECT_TRUE(report.dimension_guardrail_hit());
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
@@ -2323,18 +2321,14 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenInitialPull
     // Contains base from last pull which was successful.
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(140, curBase.value().long_value);
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(140, curBase.getValue<int64_t>());
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 10000, false /* include recent buckets */,
-                                true, FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 10000,
+                                         false /* include recent buckets */, FAST);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -2400,17 +2394,13 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenLastPullFai
     // Last pull failed so base has been reset.
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(false, curBase.has_value());
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_FALSE(curBase.hasValue());
     EXPECT_EQ(false, valueProducer->mHasGlobalBase);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 10000, false /* include recent buckets */,
-                                true, FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 10000,
+                                         false /* include recent buckets */, FAST);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -2521,8 +2511,8 @@ TEST(NumericValueMetricProducerTest, TestEmptyDataResetsBase_onConditionChanged)
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval& curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
 
@@ -2540,8 +2530,8 @@ TEST(NumericValueMetricProducerTest, TestEmptyDataResetsBase_onConditionChanged)
     curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     EXPECT_EQ(0, curInterval.sampleSize);
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(10, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(10, curBase.getValue<int64_t>());
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
 
     vector<shared_ptr<LogEvent>> allData;
@@ -2550,8 +2540,8 @@ TEST(NumericValueMetricProducerTest, TestEmptyDataResetsBase_onConditionChanged)
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(120, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(120, curBase.getValue<int64_t>());
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
     assertPastBucketValuesSingleKey(valueProducer->mPastBuckets, {110}, {bucketSizeNs - 20}, {0},
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
@@ -2596,8 +2586,8 @@ TEST(NumericValueMetricProducerTest, TestEmptyDataResetsBase_onBucketBoundary) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval& curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_TRUE(curBase.is<int64_t>());
     EXPECT_TRUE(curInterval.hasValue());
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
 
@@ -2647,8 +2637,8 @@ TEST(NumericValueMetricProducerTest, TestPartialResetOnBucketBoundaries) {
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     auto baseInfoIter = valueProducer->mDimInfos.begin();
-    EXPECT_EQ(true, baseInfoIter->second.dimExtras[0].has_value());
-    EXPECT_EQ(2, baseInfoIter->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(baseInfoIter->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(2, baseInfoIter->second.dimExtras[0].getValue<int64_t>());
 
     EXPECT_EQ(true, valueProducer->mHasGlobalBase);
 }
@@ -2761,8 +2751,8 @@ TEST(NumericValueMetricProducerTest, TestBucketBoundariesOnConditionChange) {
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     auto curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     auto curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(true, curBase.has_value());
-    EXPECT_EQ(5, curBase.value().long_value);
+    EXPECT_TRUE(curBase.is<int64_t>());
+    EXPECT_EQ(5, curBase.getValue<int64_t>());
     EXPECT_EQ(0, curInterval.sampleSize);
 
     valueProducer->onConditionChanged(false, bucket3StartTimeNs + 10);
@@ -2902,7 +2892,7 @@ TEST(NumericValueMetricProducerTest, TestDataIsNotUpdatedWhenNoConditionChanged)
     auto curInterval = valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
     auto curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(2, curInterval.aggregate.long_value);
+    EXPECT_EQ(2, curInterval.aggregate.getValue<int64_t>());
 
     vector<shared_ptr<LogEvent>> allData;
     allData.push_back(CreateRepeatedValueLogEvent(tagId, bucket2StartTimeNs + 1, 10));
@@ -2992,12 +2982,8 @@ TEST(NumericValueMetricProducerTest, TestFastDumpWithoutCurrentBucket) {
     allData.push_back(CreateThreeValueLogEvent(tagId, bucket2StartTimeNs + 1, tagId, 2, 2));
     valueProducer->onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS, bucket2StartTimeNs);
 
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket4StartTimeNs, false /* include recent buckets */, true, FAST,
-                                &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket4StartTimeNs,
+                                         false /* include recent buckets */, FAST);
     // Previous bucket is part of the report, and the current bucket is not skipped.
     ASSERT_EQ(1, report.value_metrics().data_size());
     EXPECT_EQ(0, report.value_metrics().data(0).bucket_info(0).bucket_num());
@@ -3033,12 +3019,8 @@ TEST(NumericValueMetricProducerTest, TestPullNeededNoTimeConstraints) {
             NumericValueMetricProducerTestHelper::createValueProducerNoConditions(pullerManager,
                                                                                   metric);
 
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucketStartTimeNs + 10, true /* include recent buckets */, true,
-                                NO_TIME_CONSTRAINTS, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 10,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     ASSERT_EQ(1, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().data(0).bucket_info_size());
     EXPECT_EQ(2, report.value_metrics().data(0).bucket_info(0).values(0).value_long());
@@ -3098,10 +3080,10 @@ TEST(NumericValueMetricProducerTest, TestPulledData_noDiff_withMultipleCondition
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     NumericValueMetricProducer::Interval curInterval =
             valueProducer->mCurrentSlicedBucket.begin()->second.intervals[0];
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(false, curBase.has_value());
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_FALSE(curBase.hasValue());
     EXPECT_TRUE(curInterval.hasValue());
-    EXPECT_EQ(20, curInterval.aggregate.long_value);
+    EXPECT_EQ(20, curInterval.aggregate.getValue<int64_t>());
 
     // Now the alarm is delivered. Condition is off though.
     vector<shared_ptr<LogEvent>> allData;
@@ -3113,7 +3095,7 @@ TEST(NumericValueMetricProducerTest, TestPulledData_noDiff_withMultipleCondition
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(false, curBase.has_value());
+    EXPECT_FALSE(curBase.hasValue());
 }
 
 TEST(NumericValueMetricProducerTest, TestPulledData_noDiff_bucketBoundaryTrue) {
@@ -3144,8 +3126,8 @@ TEST(NumericValueMetricProducerTest, TestPulledData_noDiff_bucketBoundaryTrue) {
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
-    optional<Value> curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
-    EXPECT_EQ(false, curBase.has_value());
+    NumericValue curBase = valueProducer->mDimInfos.begin()->second.dimExtras[0];
+    EXPECT_FALSE(curBase.hasValue());
 }
 
 TEST(NumericValueMetricProducerTest, TestPulledData_noDiff_bucketBoundaryFalse) {
@@ -3233,14 +3215,11 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenDumpReportR
     valueProducer->onConditionChanged(true, bucketStartTimeNs + 20);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucketStartTimeNs + 40, true /* include recent buckets */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 40,
+                                         true /* include recent buckets */, FAST);
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
 
-    StatsLogReport report = outputStreamToProto(&output);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3289,12 +3268,8 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenConditionEv
     valueProducer->onConditionChanged(false, bucket2StartTimeNs - 100);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 100, true /* include recent buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 100,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(1, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3355,12 +3330,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenAccumulateE
     valueProducer->accumulateEvents(allData, bucket2StartTimeNs - 100, bucket2StartTimeNs - 100);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 100, true /* include recent buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 100,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
 
-    StatsLogReport report = outputStreamToProto(&output);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(1, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3410,13 +3382,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenConditionUn
     valueProducer->onConditionChanged(true, bucketStartTimeNs + 50);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include recent buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3460,13 +3428,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenPullFailed)
     valueProducer->onConditionChanged(true, bucketStartTimeNs + 50);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include recent buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3524,12 +3488,8 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestInvalidBucketWhenMultipleBuc
     int64_t dumpTimeNs = bucket4StartTimeNs + 1000;
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(dumpTimeNs, true /* include current buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(2, report.value_metrics().skipped_size());
@@ -3594,13 +3554,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestBucketDropWhenBucketTooSmall
     valueProducer->onConditionChanged(true, bucketStartTimeNs + 10);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 9000000;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include recent buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3629,13 +3585,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestBucketDropWhenDataUnavailabl
                     pullerManager, metric, ConditionState::kFalse);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000000000;  // 10 seconds
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include current bucket */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3697,13 +3649,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestConditionUnknownMultipleBuck
     valueProducer->onConditionChanged(true, conditionChangeTimeNs);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucket2StartTimeNs + 15 * NS_PER_SEC;  // 15 seconds
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include current bucket */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(3, report.value_metrics().skipped_size());
@@ -3779,13 +3727,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop,
     valueProducer->notifyAppUpgrade(appUpdateTimeNs);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucket2StartTimeNs + 10000000000;  // 10 seconds
-    valueProducer->onDumpReport(dumpReportTimeNs, false /* include current buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         false /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(1, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3830,13 +3774,9 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestMultipleBucketDropEvents) {
     valueProducer->onConditionChanged(true, bucketStartTimeNs + 10);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 1000;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include recent buckets */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report =
+            onDumpReport(valueProducer, dumpReportTimeNs, true /* include recent buckets */, FAST);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -3913,15 +3853,12 @@ TEST(NumericValueMetricProducerTest_BucketDrop, TestMaxBucketDropEvents) {
     valueProducer->onConditionChanged(true, bucketStartTimeNs + 220);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 1000;
     // Because we already have 10 dump events in the current bucket,
     // this case should not be added to the list of dump events.
-    valueProducer->onDumpReport(bucketStartTimeNs + 1000, true /* include recent buckets */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
+    StatsLogReport report =
+            onDumpReport(valueProducer, dumpReportTimeNs, true /* include recent buckets */, FAST);
 
-    StatsLogReport report = outputStreamToProto(&output);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -4047,8 +3984,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     // Base for dimension key {
     auto it = valueProducer->mCurrentSlicedBucket.begin();
     auto itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(3, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(3, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
@@ -4070,8 +4007,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(5, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(5, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
@@ -4090,7 +4027,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(2, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 5 * NS_PER_SEC);
 
@@ -4103,8 +4040,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(9, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(9, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_OFF,
               itBase->second.currentState.getValues()[0].mValue.int_value);
@@ -4122,7 +4059,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(4, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(4, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 10 * NS_PER_SEC);
     // Value for dimension, state key {{}, kStateUnknown}
@@ -4132,7 +4069,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(2, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 5 * NS_PER_SEC);
 
@@ -4145,8 +4082,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(21, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(21, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
@@ -4157,7 +4094,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_OFF,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(12, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(12, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 15 * NS_PER_SEC);
     // Value for dimension, state key {{}, ON}
@@ -4167,7 +4104,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(4, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(4, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, true, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 15 * NS_PER_SEC);
     // Value for dimension, state key {{}, kStateUnknown}
@@ -4177,24 +4114,21 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(2, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 5 * NS_PER_SEC);
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucketStartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
 
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(30, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(30, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON,
@@ -4207,7 +4141,6 @@ TEST(NumericValueMetricProducerTest, TestSlicedState) {
     EXPECT_EQ(it->second.intervals[0].sampleSize, 0);
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 50 * NS_PER_SEC);
 
-    StatsLogReport report = outputStreamToProto(&output);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(3, report.value_metrics().data_size());
 
@@ -4321,8 +4254,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     // Base for dimension key {}
     auto it = valueProducer->mCurrentSlicedBucket.begin();
     auto itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(3, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(3, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
@@ -4344,8 +4277,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(5, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(5, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
@@ -4363,7 +4296,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(2, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 5 * NS_PER_SEC);
 
@@ -4377,8 +4310,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(5, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(5, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
@@ -4396,7 +4329,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(2, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 5 * NS_PER_SEC);
 
@@ -4410,8 +4343,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(5, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(5, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOnGroup.group_id(),
@@ -4429,7 +4362,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(2, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 5 * NS_PER_SEC);
 
@@ -4442,8 +4375,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(21, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(21, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOffGroup.group_id(),
@@ -4461,7 +4394,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_EQ(screenOnGroup.group_id(),
               it->first.getStateValuesKey().getValues()[0].mValue.long_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(16, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(16, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucketStartTimeNs + 15 * NS_PER_SEC);
     // Value for dimension, state key {{}, kStateUnknown}
@@ -4471,24 +4404,21 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
     EXPECT_EQ(-1 /* StateTracker::kStateUnknown */,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(2, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 5 * NS_PER_SEC,
                          bucketStartTimeNs + 5 * NS_PER_SEC);
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucketStartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
 
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     // Base for dimension key {}
     it = valueProducer->mCurrentSlicedBucket.begin();
     itBase = valueProducer->mDimInfos.find(it->first.getDimensionKeyInWhat());
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(30, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(30, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(screenOffGroup.group_id(),
@@ -4500,7 +4430,6 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMap) {
               it->first.getStateValuesKey().getValues()[0].mValue.long_value);
     assertConditionTimer(it->second.conditionTimer, true, 0, bucketStartTimeNs + 50 * NS_PER_SEC);
 
-    StatsLogReport report = outputStreamToProto(&output);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(3, report.value_metrics().data_size());
 
@@ -4723,13 +4652,10 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithPrimaryField_WithDimensi
     ASSERT_EQ(2UL, valueProducer->mDimInfos.size());
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucket2StartTimeNs + 50 * NS_PER_SEC;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include recent buckets */, true,
-                                NO_TIME_CONSTRAINTS, &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
 
-    StatsLogReport report = outputStreamToProto(&output);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -4977,13 +4903,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataInStateChange
                          bucketStartTimeNs + 10 * NS_PER_SEC);
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucketStartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -5082,13 +5003,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMissingDataThenFlushBuck
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucketStartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
@@ -5275,15 +5191,12 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithNoPullOnBucketBoundary)
     assertConditionTimer(it->second.conditionTimer, true, 0, bucket2StartTimeNs + 30 * NS_PER_SEC);
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
+
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
 
-    StatsLogReport report = outputStreamToProto(&output);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -5493,15 +5406,11 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithDataMissingInConditionCh
     ASSERT_EQ(2UL, valueProducer->mCurrentSlicedBucket.size());
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucketStartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     ASSERT_EQ(1UL, valueProducer->mCurrentSlicedBucket.size());
 
-    StatsLogReport report = outputStreamToProto(&output);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -5739,15 +5648,11 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMultipleDimensions) {
     ASSERT_EQ(4UL, valueProducer->mCurrentSlicedBucket.size());
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     ASSERT_EQ(3UL, valueProducer->mDimInfos.size());
     ASSERT_EQ(3UL, valueProducer->mCurrentSlicedBucket.size());
 
-    StatsLogReport report = outputStreamToProto(&output);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -5871,8 +5776,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     std::unordered_map<HashableDimensionKey,
                        NumericValueMetricProducer::DimensionsInWhatInfo>::iterator itBase =
             valueProducer->mDimInfos.find(DEFAULT_DIMENSION_KEY);
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(3, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(3, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
@@ -5902,8 +5807,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     // Base for dimension key {}
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     itBase = valueProducer->mDimInfos.find(DEFAULT_DIMENSION_KEY);
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(5, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(5, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
@@ -5923,7 +5828,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     EXPECT_EQ(BatterySaverModeStateChanged::ON,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(2, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(2, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucketStartTimeNs + 30 * NS_PER_SEC);
     // Value for key {{}, -1}
@@ -5942,8 +5847,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     // Base for dimension key {}
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     itBase = valueProducer->mDimInfos.find(DEFAULT_DIMENSION_KEY);
-    EXPECT_TRUE(itBase->second.dimExtras[0].has_value());
-    EXPECT_EQ(11, itBase->second.dimExtras[0].value().long_value);
+    EXPECT_TRUE(itBase->second.dimExtras[0].is<int64_t>());
+    EXPECT_EQ(11, itBase->second.dimExtras[0].getValue<int64_t>());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
@@ -5957,7 +5862,7 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     // Base for dimension key {}
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
     itBase = valueProducer->mDimInfos.find(DEFAULT_DIMENSION_KEY);
-    EXPECT_FALSE(itBase->second.dimExtras[0].has_value());
+    EXPECT_FALSE(itBase->second.dimExtras[0].hasValue());
     EXPECT_TRUE(itBase->second.hasCurrentState);
     ASSERT_EQ(1, itBase->second.currentState.getValues().size());
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
@@ -5970,18 +5875,13 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithCondition) {
     EXPECT_EQ(BatterySaverModeStateChanged::OFF,
               it->first.getStateValuesKey().getValues()[0].mValue.int_value);
     EXPECT_GT(it->second.intervals[0].sampleSize, 0);
-    EXPECT_EQ(4, it->second.intervals[0].aggregate.long_value);
+    EXPECT_EQ(4, it->second.intervals[0].aggregate.getValue<int64_t>());
     assertConditionTimer(it->second.conditionTimer, false, 10 * NS_PER_SEC,
                          bucket2StartTimeNs + 10 * NS_PER_SEC);
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(2, report.value_metrics().data_size());
 
@@ -6123,13 +6023,8 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithConditionFalseMultipleBu
     ASSERT_EQ(3UL, valueProducer->mCurrentSlicedBucket.size());
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket3StartTimeNs + 30 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket3StartTimeNs + 30 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -6323,15 +6218,11 @@ TEST(NumericValueMetricProducerTest, TestSlicedStateWithMultipleDimensionsMissin
     ASSERT_EQ(4UL, valueProducer->mCurrentSlicedBucket.size());
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket2StartTimeNs + 50 * NS_PER_SEC,
-                                true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket2StartTimeNs + 50 * NS_PER_SEC,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     ASSERT_EQ(3UL, valueProducer->mDimInfos.size());
     ASSERT_EQ(3UL, valueProducer->mCurrentSlicedBucket.size());
 
-    StatsLogReport report = outputStreamToProto(&output);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -6432,13 +6323,9 @@ TEST(NumericValueMetricProducerTest, TestForcedBucketSplitWhenConditionUnknownSk
     valueProducer->notifyAppUpgrade(appUpdateTimeNs);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000000000;  // 10 seconds
-    valueProducer->onDumpReport(dumpReportTimeNs, false /* include current buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         false /* include recent buckets */, NO_TIME_CONSTRAINTS);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(0, report.value_metrics().data_size());
     ASSERT_EQ(1, report.value_metrics().skipped_size());
@@ -6498,13 +6385,9 @@ TEST(NumericValueMetricProducerTest, TestUploadThreshold) {
     valueProducer->onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS, bucket2StartTimeNs);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucket2StartTimeNs + 10000000000;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include current buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -6980,12 +6863,8 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestThresholdNotDefined
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
 
     // generate dump report and validate correction value in the reported buckets
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket3StartTimeNs, false /* include partial bucket */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket3StartTimeNs,
+                                         false /* include recent buckets */, FAST);
 
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(1, report.value_metrics().data_size());
@@ -7036,12 +6915,8 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestThresholdDefinedZer
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
 
     // generate dump report and validate correction value in the reported buckets
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket3StartTimeNs, false /* include partial bucket */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket3StartTimeNs,
+                                         false /* include recent buckets */, FAST);
 
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(1, report.value_metrics().data_size());
@@ -7105,12 +6980,8 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestThresholdUploadPass
                                     {bucket2StartTimeNs, bucket3StartTimeNs});
 
     // generate dump report and validate correction value in the reported buckets
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket3StartTimeNs, false /* include partial bucket */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket3StartTimeNs,
+                                         false /* include recent buckets */, FAST);
 
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(1, report.value_metrics().data_size());
@@ -7165,12 +7036,8 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestThresholdUploadPass
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
 
     // generate dump report and validate correction value in the reported buckets
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket3StartTimeNs, false /* include partial bucket */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket3StartTimeNs,
+                                         false /* include recent buckets */, FAST);
 
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(1, report.value_metrics().data_size());
@@ -7223,12 +7090,8 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestThresholdUploadSkip
                                     {bucketStartTimeNs}, {bucket2StartTimeNs});
 
     // generate dump report and validate correction value in the reported buckets
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket3StartTimeNs, false /* include partial bucket */, true,
-                                FAST /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket3StartTimeNs,
+                                         false /* include recent buckets */, FAST);
 
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(1, report.value_metrics().data_size());
@@ -7318,12 +7181,8 @@ TEST(NumericValueMetricProducerTest_ConditionCorrection, TestLateStateChangeSlic
     ASSERT_EQ(1UL, valueProducer->mDimInfos.size());
 
     // Start dump report and check output.
-    ProtoOutputStream output;
-    std::set<string> strSet;
-    valueProducer->onDumpReport(bucket4StartTimeNs + 10, false /* do not include partial buckets */,
-                                true, NO_TIME_CONSTRAINTS, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket4StartTimeNs + 10,
+                                         false /* include recent buckets */, NO_TIME_CONSTRAINTS);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
     ASSERT_EQ(3, report.value_metrics().data_size());
@@ -7404,15 +7263,12 @@ TEST(NumericValueMetricProducerTest, TestSubsetDimensions) {
     ASSERT_EQ(2UL, valueProducer->mDimInfos.size());
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucket2StartTimeNs + 10000000000;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include current buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     ASSERT_EQ(0UL, valueProducer->mCurrentSlicedBucket.size());
     ASSERT_EQ(2UL, valueProducer->mDimInfos.size());
 
-    StatsLogReport report = outputStreamToProto(&output);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -7436,7 +7292,8 @@ TEST(NumericValueMetricProducerTest, TestSubsetDimensions) {
     ValidateValueBucket(data.bucket_info(1), bucket2StartTimeNs, dumpReportTimeNs, {26}, -1, 0);
 }
 
-TEST(NumericValueMetricProducerTest, TestRepeatedValueFieldAndDimensions) {
+TEST_GUARDED(NumericValueMetricProducerTest, TestRepeatedValueFieldAndDimensions,
+             __ANDROID_API_T__) {
     ValueMetric metric = NumericValueMetricProducerTestHelper::createMetricWithRepeatedValueField();
     metric.mutable_dimensions_in_what()->set_field(tagId);
     FieldMatcher* valueChild = metric.mutable_dimensions_in_what()->add_child();
@@ -7481,13 +7338,9 @@ TEST(NumericValueMetricProducerTest, TestRepeatedValueFieldAndDimensions) {
     valueProducer->onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS, bucket2StartTimeNs);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucket2StartTimeNs + 10000000000;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include current buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -7572,13 +7425,8 @@ TEST(NumericValueMetricProducerTest, TestSampleSize) {
     valueProducerSumWithSampleSize->flushIfNeededLocked(bucket2StartTimeNs);
 
     // Start dump report and check output.
-    ProtoOutputStream outputAvg;
-    std::set<string> strSetAvg;
-    valueProducerAvg->onDumpReport(bucket2StartTimeNs + 50 * NS_PER_SEC,
-                                   true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                   &strSetAvg, &outputAvg);
-
-    StatsLogReport reportAvg = outputStreamToProto(&outputAvg);
+    StatsLogReport reportAvg = onDumpReport(valueProducerAvg, bucket2StartTimeNs + 50 * NS_PER_SEC,
+                                            true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     ASSERT_EQ(1, reportAvg.value_metrics().data_size());
 
     ValueMetricData data = reportAvg.value_metrics().data(0);
@@ -7588,13 +7436,8 @@ TEST(NumericValueMetricProducerTest, TestSampleSize) {
     EXPECT_TRUE(std::abs(data.bucket_info(0).values(0).value_double() - 12.5) < epsilon);
 
     // Start dump report and check output.
-    ProtoOutputStream outputSum;
-    std::set<string> strSetSum;
-    valueProducerSum->onDumpReport(bucket2StartTimeNs + 50 * NS_PER_SEC,
-                                   true /* include recent buckets */, true, NO_TIME_CONSTRAINTS,
-                                   &strSetSum, &outputSum);
-
-    StatsLogReport reportSum = outputStreamToProto(&outputSum);
+    StatsLogReport reportSum = onDumpReport(valueProducerSum, bucket2StartTimeNs + 50 * NS_PER_SEC,
+                                            true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     ASSERT_EQ(1, reportSum.value_metrics().data_size());
 
     data = reportSum.value_metrics().data(0);
@@ -7604,13 +7447,9 @@ TEST(NumericValueMetricProducerTest, TestSampleSize) {
     EXPECT_FALSE(data.bucket_info(0).values(0).has_sample_size());
 
     // Start dump report and check output.
-    ProtoOutputStream outputSumWithSampleSize;
-    std::set<string> strSetSumWithSampleSize;
-    valueProducerSumWithSampleSize->onDumpReport(
-            bucket2StartTimeNs + 50 * NS_PER_SEC, true /* include recent buckets */, true,
-            NO_TIME_CONSTRAINTS, &strSetSumWithSampleSize, &outputSumWithSampleSize);
-
-    StatsLogReport reportSumWithSampleSize = outputStreamToProto(&outputSumWithSampleSize);
+    StatsLogReport reportSumWithSampleSize =
+            onDumpReport(valueProducerSumWithSampleSize, bucket2StartTimeNs + 50 * NS_PER_SEC,
+                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     ASSERT_EQ(1, reportSumWithSampleSize.value_metrics().data_size());
 
     data = reportSumWithSampleSize.value_metrics().data(0);
@@ -7662,13 +7501,9 @@ TEST(NumericValueMetricProducerTest, TestDimensionalSampling) {
                     pullerManager, sampledValueMetric);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucketStartTimeNs + 10000000000;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include current buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -7781,13 +7616,9 @@ TEST(NumericValueMetricProducerTest, TestMultipleAggTypesPulled) {
     valueProducer->onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS, bucket2StartTimeNs);
 
     // Check dump report.
-    ProtoOutputStream output;
-    std::set<string> strSet;
     int64_t dumpReportTimeNs = bucket2StartTimeNs + 55 * NS_PER_SEC;
-    valueProducer->onDumpReport(dumpReportTimeNs, true /* include current buckets */, true,
-                                NO_TIME_CONSTRAINTS /* dumpLatency */, &strSet, &output);
-
-    StatsLogReport report = outputStreamToProto(&output);
+    StatsLogReport report = onDumpReport(valueProducer, dumpReportTimeNs,
+                                         true /* include recent buckets */, NO_TIME_CONSTRAINTS);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -7913,11 +7744,9 @@ TEST(NumericValueMetricProducerTest, TestMultipleAggTypesPushed) {
     valueProducer->onMatchedLogEvent(1 /*log matcher index*/, event12);
 
     // Check dump report.
-    ProtoOutputStream output;
-    valueProducer->onDumpReport(bucket3StartTimeNs + 10000, false /* include recent buckets */,
-                                true, FAST /* dumpLatency */, nullptr, &output);
+    StatsLogReport report = onDumpReport(valueProducer, bucket3StartTimeNs + 10000,
+                                         false /* include recent buckets */, FAST);
 
-    StatsLogReport report = outputStreamToProto(&output);
     backfillDimensionPath(&report);
     backfillStartEndTimestamp(&report);
     EXPECT_TRUE(report.has_value_metrics());
@@ -7967,6 +7796,123 @@ TEST(NumericValueMetricProducerTest, TestMultipleAggTypesPushed) {
     }
 }
 
+TEST(NumericValueMetricProducerTest, TestCorruptedDataReason_WhatLoss) {
+    ValueMetric metric = NumericValueMetricProducerTestHelper::createMetric();
+    *metric.mutable_dimensions_in_what() = CreateDimensions(tagId, {1 /*uid*/});
+
+    sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
+    sp<NumericValueMetricProducer> valueProducer =
+            NumericValueMetricProducerTestHelper::createValueProducerNoConditions(
+                    pullerManager, metric, /*pullAtomId=*/-1);
+
+    valueProducer->onMatchedLogEventLost(tagId, DATA_CORRUPTED_SOCKET_LOSS,
+                                         MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50,
+                                             true /* include recent buckets */, FAST);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    valueProducer->onMatchedLogEventLost(tagId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                         MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 150,
+                                             true /* include recent buckets */, FAST);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW));
+    }
+}
+
+TEST(NumericValueMetricProducerTest, TestCorruptedDataReason_WhatLossDiffedMetric) {
+    ValueMetric metric = NumericValueMetricProducerTestHelper::createMetric();
+    *metric.mutable_dimensions_in_what() = CreateDimensions(tagId, {1 /*uid*/});
+
+    sp<MockStatsPullerManager> pullerManager = new NiceMock<MockStatsPullerManager>();
+    sp<NumericValueMetricProducer> valueProducer =
+            NumericValueMetricProducerTestHelper::createValueProducerNoConditions(
+                    pullerManager, metric, /*pullAtomId=*/1);
+
+    valueProducer->onMatchedLogEventLost(tagId, DATA_CORRUPTED_SOCKET_LOSS,
+                                         MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50,
+                                             true /* include recent buckets */, FAST);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    valueProducer->onMatchedLogEventLost(tagId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                         MetricProducer::LostAtomType::kWhat);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 150,
+                                             true /* include recent buckets */, FAST);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(NumericValueMetricProducerTest, TestCorruptedDataReason_ConditionLoss) {
+    const int conditionId = 10;
+
+    ValueMetric metric = NumericValueMetricProducerTestHelper::createMetricWithCondition();
+
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+    sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
+    sp<NumericValueMetricProducer> valueProducer =
+            NumericValueMetricProducerTestHelper::createValueProducerWithCondition(
+                    pullerManager, metric, ConditionState::kFalse);
+
+    valueProducer->onMatchedLogEventLost(conditionId, DATA_CORRUPTED_SOCKET_LOSS,
+                                         MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50,
+                                             true /* include recent buckets */, FAST);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    valueProducer->onMatchedLogEventLost(conditionId, DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW,
+                                         MetricProducer::LostAtomType::kCondition);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 150,
+                                             true /* include recent buckets */, FAST);
+        EXPECT_THAT(report.data_corrupted_reason(),
+                    ElementsAre(DATA_CORRUPTED_EVENT_QUEUE_OVERFLOW, DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
+TEST(NumericValueMetricProducerTest, TestCorruptedDataReason_StateLoss) {
+    const int stateAtomId = 10;
+
+    ValueMetric metric = NumericValueMetricProducerTestHelper::createMetricWithCondition();
+
+    sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
+    sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
+    sp<NumericValueMetricProducer> valueProducer =
+            NumericValueMetricProducerTestHelper::createValueProducerWithCondition(
+                    pullerManager, metric, ConditionState::kFalse);
+
+    valueProducer->onStateEventLost(stateAtomId, DATA_CORRUPTED_SOCKET_LOSS);
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 50,
+                                             true /* include recent buckets */, FAST);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+
+    // validation that data corruption signal remains accurate after another dump
+    {
+        // Check dump report content.
+        StatsLogReport report = onDumpReport(valueProducer, bucketStartTimeNs + 150,
+                                             true /* include recent buckets */, FAST);
+        EXPECT_THAT(report.data_corrupted_reason(), ElementsAre(DATA_CORRUPTED_SOCKET_LOSS));
+    }
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/metrics/RestrictedEventMetricProducer_test.cpp b/statsd/tests/metrics/RestrictedEventMetricProducer_test.cpp
index 2085e11c..5c05acf3 100644
--- a/statsd/tests/metrics/RestrictedEventMetricProducer_test.cpp
+++ b/statsd/tests/metrics/RestrictedEventMetricProducer_test.cpp
@@ -175,9 +175,10 @@ TEST_F(RestrictedEventMetricProducerTest, TestOnDumpReportNoOp) {
     producer.onMatchedLogEvent(/*matcherIndex=*/1, *event1);
     ProtoOutputStream output;
     std::set<string> strSet;
+    std::set<int32_t> usedUids;
     producer.onDumpReport(/*dumpTimeNs=*/10,
                           /*include_current_partial_bucket=*/true,
-                          /*erase_data=*/true, FAST, &strSet, &output);
+                          /*erase_data=*/true, FAST, &strSet, usedUids, &output);
 
     ASSERT_EQ(output.size(), 0);
     ASSERT_EQ(strSet.size(), 0);
diff --git a/statsd/tests/metrics/parsing_utils/histogram_parsing_utils_test.cpp b/statsd/tests/metrics/parsing_utils/histogram_parsing_utils_test.cpp
new file mode 100644
index 00000000..5ccf6b90
--- /dev/null
+++ b/statsd/tests/metrics/parsing_utils/histogram_parsing_utils_test.cpp
@@ -0,0 +1,347 @@
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
+#include "src/metrics/parsing_utils/histogram_parsing_utils.h"
+
+#include <gtest/gtest.h>
+
+#include <algorithm>
+#include <numeric>
+#include <variant>
+#include <vector>
+
+#include "src/guardrail/StatsdStats.h"
+#include "src/stats_util.h"
+#include "src/statsd_config.pb.h"
+#include "tests/metrics/parsing_utils/parsing_test_utils.h"
+#include "tests/statsd_test_util.h"
+
+#ifdef __ANDROID__
+
+using namespace std;
+using namespace testing;
+
+namespace android {
+namespace os {
+namespace statsd {
+namespace {
+
+using HistogramParsingUtilsTest = InitConfigTest;
+
+constexpr auto LINEAR = HistogramBinConfig::GeneratedBins::LINEAR;
+constexpr auto EXPONENTIAL = HistogramBinConfig::GeneratedBins::EXPONENTIAL;
+
+TEST_F(HistogramParsingUtilsTest, TestMissingHistogramBinConfigId) {
+    StatsdConfig config = createExplicitHistogramStatsdConfig(/* bins */ {5});
+    config.mutable_value_metric(0)->mutable_histogram_bin_configs()->Mutable(0)->clear_id();
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_BIN_CONFIG_ID,
+                                  config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestMissingHistogramBinConfigBinningStrategy) {
+    StatsdConfig config = createHistogramStatsdConfig();
+    config.mutable_value_metric(0)->add_histogram_bin_configs()->set_id(1);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_UNKNOWN_BINNING_STRATEGY,
+                                  config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestGeneratedBinsMissingMin) {
+    StatsdConfig config =
+            createGeneratedHistogramStatsdConfig(/* min */ 1, /* max */ 10, /* count */ 5, LINEAR);
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_generated_bins()
+            ->clear_min();
+
+    EXPECT_EQ(
+            initConfig(config),
+            InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_GENERATED_BINS_ARGS,
+                                config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestGeneratedBinsMissingMax) {
+    StatsdConfig config =
+            createGeneratedHistogramStatsdConfig(/* min */ 1, /* max */ 10, /* count */ 5, LINEAR);
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_generated_bins()
+            ->clear_max();
+
+    EXPECT_EQ(
+            initConfig(config),
+            InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_GENERATED_BINS_ARGS,
+                                config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestGeneratedBinsMissingCount) {
+    StatsdConfig config =
+            createGeneratedHistogramStatsdConfig(/* min */ 1, /* max */ 10, /* count */ 5, LINEAR);
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_generated_bins()
+            ->clear_count();
+
+    EXPECT_EQ(
+            initConfig(config),
+            InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_GENERATED_BINS_ARGS,
+                                config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestGeneratedBinsMissingStrategy) {
+    StatsdConfig config = createHistogramStatsdConfig();
+    *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+            createGeneratedBinConfig(/* id */ 1, /* min */ 1, /* max */ 10, /* count */ 5,
+                                     HistogramBinConfig::GeneratedBins::UNKNOWN);
+
+    EXPECT_EQ(
+            initConfig(config),
+            InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_GENERATED_BINS_ARGS,
+                                config.value_metric(0).id()));
+
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_generated_bins()
+            ->clear_strategy();
+
+    clearData();
+    EXPECT_EQ(
+            initConfig(config),
+            InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_MISSING_GENERATED_BINS_ARGS,
+                                config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestGeneratedBinsMinNotLessThanMax) {
+    StatsdConfig config =
+            createGeneratedHistogramStatsdConfig(/* min */ 10, /* max */ 10, /* count */ 5, LINEAR);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_GENERATED_BINS_INVALID_MIN_MAX,
+                      config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestExponentialBinsMinNotLessThanMax) {
+    StatsdConfig config = createGeneratedHistogramStatsdConfig(/* min */ 10, /* max */ 10,
+                                                               /* count */ 5, EXPONENTIAL);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_GENERATED_BINS_INVALID_MIN_MAX,
+                      config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestExponentialBinsZeroMin) {
+    StatsdConfig config = createGeneratedHistogramStatsdConfig(/* min */ 0, /* max */ 10,
+                                                               /* count */ 5, EXPONENTIAL);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_GENERATED_BINS_INVALID_MIN_MAX,
+                      config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestTooFewGeneratedBins) {
+    StatsdConfig config =
+            createGeneratedHistogramStatsdConfig(/* min */ 10, /* max */ 50, /* count */ 2, LINEAR);
+
+    EXPECT_EQ(initConfig(config), nullopt);
+
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_generated_bins()
+            ->set_count(1);
+
+    clearData();
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_FEW_BINS,
+                                  config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestTooManyGeneratedBins) {
+    StatsdConfig config = createGeneratedHistogramStatsdConfig(/* min */ 10, /* max */ 50,
+                                                               /* count */ 100, LINEAR);
+
+    EXPECT_EQ(initConfig(config), nullopt);
+
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_generated_bins()
+            ->set_count(101);
+
+    clearData();
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_MANY_BINS,
+                                  config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestTooFewExplicitBins) {
+    StatsdConfig config = createExplicitHistogramStatsdConfig(/* bins */ {1});
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_FEW_BINS,
+                                  config.value_metric(0).id()));
+
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_explicit_bins()
+            ->add_bin(2);
+
+    clearData();
+    EXPECT_EQ(initConfig(config), nullopt);
+}
+
+TEST_F(HistogramParsingUtilsTest, TestTooManyExplicitBins) {
+    BinStarts bins(100);
+    // Fill bins with values 1, 2, ..., 100.
+    std::iota(std::begin(bins), std::end(bins), 1);
+    StatsdConfig config = createExplicitHistogramStatsdConfig(bins);
+
+    EXPECT_EQ(initConfig(config), nullopt);
+
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_explicit_bins()
+            ->add_bin(101);
+
+    clearData();
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_TOO_MANY_BINS,
+                                  config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestExplicitBinsDuplicateValues) {
+    BinStarts bins(50);
+    // Fill bins with values 1, 2, ..., 50.
+    std::iota(std::begin(bins), std::end(bins), 1);
+    StatsdConfig config = createExplicitHistogramStatsdConfig(bins);
+
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_explicit_bins()
+            ->add_bin(50);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_EXPLICIT_BINS_NOT_STRICTLY_ORDERED,
+                      config.value_metric(0).id()));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestExplicitBinsUnsortedValues) {
+    BinStarts bins(50);
+    // Fill bins with values 1, 2, ..., 50.
+    std::iota(std::begin(bins), std::end(bins), 1);
+
+    // Swap values at indices 10 and 40.
+    std::swap(bins[10], bins[40]);
+
+    StatsdConfig config = createExplicitHistogramStatsdConfig(bins);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_EXPLICIT_BINS_NOT_STRICTLY_ORDERED,
+                      config.value_metric(0).id()));
+}
+
+const BinStarts getParsedBins(const ValueMetric& metric) {
+    ParseHistogramBinConfigsResult result =
+            parseHistogramBinConfigs(metric, /* aggregationTypes */ {ValueMetric::HISTOGRAM});
+    return holds_alternative<vector<optional<const BinStarts>>>(result)
+                   ? *get<vector<optional<const BinStarts>>>(result).front()
+                   : BinStarts();
+}
+
+const BinStarts getParsedGeneratedBins(float min, float max, int count,
+                                       HistogramBinConfig::GeneratedBins::Strategy strategy) {
+    StatsdConfig config = createGeneratedHistogramStatsdConfig(min, max, count, strategy);
+
+    return getParsedBins(config.value_metric(0));
+}
+
+const BinStarts getParsedLinearBins(float min, float max, int count) {
+    return getParsedGeneratedBins(min, max, count, LINEAR);
+}
+
+TEST_F(HistogramParsingUtilsTest, TestValidLinearBins) {
+    EXPECT_THAT(getParsedLinearBins(-10, 10, 5),
+                ElementsAre(UNDERFLOW_BIN_START, -10, -6, -2, 2, 6, 10));
+    EXPECT_THAT(getParsedLinearBins(-10, 10, 2), ElementsAre(UNDERFLOW_BIN_START, -10, 0, 10));
+    EXPECT_THAT(getParsedLinearBins(-100, -50, 3),
+                ElementsAre(UNDERFLOW_BIN_START, -100, FloatNear(-83.33, 0.01),
+                            FloatNear(-66.67, 0.01), -50));
+    EXPECT_THAT(getParsedLinearBins(2.5, 11.3, 7),
+                ElementsAre(UNDERFLOW_BIN_START, 2.5, FloatNear(3.76, 0.01), FloatNear(5.01, 0.01),
+                            FloatNear(6.27, 0.01), FloatNear(7.53, 0.01), FloatNear(8.79, 0.01),
+                            FloatNear(10.04, 0.01), 11.3));
+}
+
+BinStarts getParsedExponentialBins(float min, float max, int count) {
+    return getParsedGeneratedBins(min, max, count, EXPONENTIAL);
+}
+
+TEST_F(HistogramParsingUtilsTest, TestValidExponentialBins) {
+    EXPECT_THAT(getParsedExponentialBins(5, 160, 5),
+                ElementsAre(UNDERFLOW_BIN_START, 5, 10, 20, 40, 80, 160));
+    EXPECT_THAT(getParsedExponentialBins(3, 1875, 4),
+                ElementsAre(UNDERFLOW_BIN_START, 3, FloatEq(15), FloatEq(75), FloatEq(375), 1875));
+    EXPECT_THAT(getParsedExponentialBins(1, 1000, 3),
+                ElementsAre(UNDERFLOW_BIN_START, 1, 10, 100, 1000));
+}
+
+BinStarts getParsedExplicitBins(BinStarts bins) {
+    StatsdConfig config = createExplicitHistogramStatsdConfig(bins);
+
+    return getParsedBins(config.value_metric(0));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestValidExplicitBins) {
+    EXPECT_THAT(getParsedExplicitBins({0, 1, 2}), ElementsAre(UNDERFLOW_BIN_START, 0, 1, 2));
+    EXPECT_THAT(getParsedExplicitBins({-1, 5, 200}), ElementsAre(UNDERFLOW_BIN_START, -1, 5, 200));
+}
+
+TEST_F(HistogramParsingUtilsTest, TestMultipleHistogramBinConfigs) {
+    StatsdConfig config = createGeneratedHistogramStatsdConfig(/* min */ -100, /* max */ 0,
+                                                               /* count */ 5, LINEAR);
+    config.mutable_value_metric(0)->clear_aggregation_type();
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::HISTOGRAM);
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::HISTOGRAM);
+    config.mutable_value_metric(0)->mutable_value_field()->add_child()->set_field(2);
+    *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+            createExplicitBinConfig(/* id */ 2, {1, 9, 30});
+
+    ParseHistogramBinConfigsResult result = parseHistogramBinConfigs(
+            config.value_metric(0),
+            /* aggregationTypes */ {ValueMetric::HISTOGRAM, ValueMetric::HISTOGRAM});
+    ASSERT_TRUE(holds_alternative<vector<optional<const BinStarts>>>(result));
+    const vector<optional<const BinStarts>>& histograms =
+            get<vector<optional<const BinStarts>>>(result);
+    ASSERT_EQ(histograms.size(), 2);
+
+    EXPECT_THAT(*(histograms[0]), ElementsAre(UNDERFLOW_BIN_START, -100, -80, -60, -40, -20, 0));
+    EXPECT_THAT(*(histograms[1]), ElementsAre(UNDERFLOW_BIN_START, 1, 9, 30));
+}
+
+}  // anonymous namespace
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
+#else
+GTEST_LOG_(INFO) << "This test does nothing.\n";
+#endif
diff --git a/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp b/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
index 1a64c20a..d8ae123f 100644
--- a/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
+++ b/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
@@ -19,6 +19,7 @@
 #include <private/android_filesystem_config.h>
 #include <stdio.h>
 
+#include <numeric>
 #include <set>
 #include <unordered_map>
 #include <vector>
@@ -34,6 +35,7 @@
 #include "src/state/StateManager.h"
 #include "src/statsd_config.pb.h"
 #include "tests/metrics/metrics_test_helper.h"
+#include "tests/metrics/parsing_utils/parsing_test_utils.h"
 #include "tests/statsd_test_util.h"
 
 using namespace testing;
@@ -51,46 +53,6 @@ namespace os {
 namespace statsd {
 
 namespace {
-const int kConfigId = 12345;
-const ConfigKey kConfigKey(0, kConfigId);
-const long timeBaseSec = 1000;
-const long kAlertId = 3;
-
-sp<UidMap> uidMap = new UidMap();
-sp<StatsPullerManager> pullerManager = new StatsPullerManager();
-sp<AlarmMonitor> anomalyAlarmMonitor;
-sp<AlarmMonitor> periodicAlarmMonitor;
-sp<ConfigMetadataProvider> configMetadataProvider;
-unordered_map<int, vector<int>> allTagIdsToMatchersMap;
-vector<sp<AtomMatchingTracker>> allAtomMatchingTrackers;
-unordered_map<int64_t, int> atomMatchingTrackerMap;
-vector<sp<ConditionTracker>> allConditionTrackers;
-unordered_map<int64_t, int> conditionTrackerMap;
-vector<sp<MetricProducer>> allMetricProducers;
-unordered_map<int64_t, int> metricProducerMap;
-vector<sp<AnomalyTracker>> allAnomalyTrackers;
-unordered_map<int64_t, int> alertTrackerMap;
-vector<sp<AlarmTracker>> allAlarmTrackers;
-unordered_map<int, vector<int>> conditionToMetricMap;
-unordered_map<int, vector<int>> trackerToMetricMap;
-unordered_map<int, vector<int>> trackerToConditionMap;
-unordered_map<int, vector<int>> activationAtomTrackerToMetricMap;
-unordered_map<int, vector<int>> deactivationAtomTrackerToMetricMap;
-vector<int> metricsWithActivation;
-map<int64_t, uint64_t> stateProtoHashes;
-set<int64_t> noReportMetricIds;
-
-optional<InvalidConfigReason> initConfig(const StatsdConfig& config) {
-    // initStatsdConfig returns nullopt if config is valid
-    return initStatsdConfig(
-            kConfigKey, config, uidMap, pullerManager, anomalyAlarmMonitor, periodicAlarmMonitor,
-            timeBaseSec, timeBaseSec, configMetadataProvider, allTagIdsToMatchersMap,
-            allAtomMatchingTrackers, atomMatchingTrackerMap, allConditionTrackers,
-            conditionTrackerMap, allMetricProducers, metricProducerMap, allAnomalyTrackers,
-            allAlarmTrackers, conditionToMetricMap, trackerToMetricMap, trackerToConditionMap,
-            activationAtomTrackerToMetricMap, deactivationAtomTrackerToMetricMap, alertTrackerMap,
-            metricsWithActivation, stateProtoHashes, noReportMetricIds);
-}
 
 StatsdConfig buildCircleMatchers() {
     StatsdConfig config;
@@ -363,30 +325,7 @@ StatsdConfig buildConfigWithDifferentPredicates() {
     return config;
 }
 
-class MetricsManagerUtilTest : public ::testing::Test {
-public:
-    void SetUp() override {
-        allTagIdsToMatchersMap.clear();
-        allAtomMatchingTrackers.clear();
-        atomMatchingTrackerMap.clear();
-        allConditionTrackers.clear();
-        conditionTrackerMap.clear();
-        allMetricProducers.clear();
-        metricProducerMap.clear();
-        allAnomalyTrackers.clear();
-        allAlarmTrackers.clear();
-        conditionToMetricMap.clear();
-        trackerToMetricMap.clear();
-        trackerToConditionMap.clear();
-        activationAtomTrackerToMetricMap.clear();
-        deactivationAtomTrackerToMetricMap.clear();
-        alertTrackerMap.clear();
-        metricsWithActivation.clear();
-        stateProtoHashes.clear();
-        noReportMetricIds.clear();
-        StateManager::getInstance().clear();
-    }
-};
+using MetricsManagerUtilTest = InitConfigTest;
 
 struct DimLimitTestCase {
     int configLimit;
@@ -1123,7 +1062,8 @@ TEST_F(MetricsManagerUtilTest, TestValueMetricValueFieldHasPositionAll) {
     metric->set_id(metricId);
     metric->set_what(1);
 
-    metric->mutable_value_field()->set_position(ALL);
+    metric->mutable_value_field()->add_child()->set_field(2);
+    metric->mutable_value_field()->mutable_child(0)->set_position(ALL);
 
     EXPECT_EQ(initConfig(config),
               InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_VALUE_FIELD_HAS_POSITION_ALL,
@@ -2455,6 +2395,138 @@ TEST_F(MetricsManagerUtilTest, TestCombinationMatcherWithStringReplace) {
     EXPECT_THAT(actualInvalidConfigReason->matcherIds, ElementsAre(222));
 }
 
+TEST_F(MetricsManagerUtilTest, TestNumericValueMetricMissingHistogramBinConfigSingleAggType) {
+    StatsdConfig config = createHistogramStatsdConfig();
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_COUNT_DNE_HIST_BIN_CONFIGS_COUNT,
+                      config.value_metric(0).id()));
+}
+
+TEST_F(MetricsManagerUtilTest, TestNumericValueMetricMissingHistogramBinConfigMultipleAggTypes) {
+    StatsdConfig config = createHistogramStatsdConfig();
+    config.mutable_value_metric(0)->clear_aggregation_type();
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::SUM);
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::HISTOGRAM);
+    config.mutable_value_metric(0)->mutable_value_field()->add_child()->set_field(2);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_COUNT_DNE_HIST_BIN_CONFIGS_COUNT,
+                      config.value_metric(0).id()));
+}
+
+TEST_F(MetricsManagerUtilTest, TestNumericValueMetricExtraHistogramBinConfig) {
+    StatsdConfig config = createExplicitHistogramStatsdConfig({5, 10, 12});
+    *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+            createExplicitBinConfig(/* id */ 1, /* bins */ {5, 10, 20});
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_COUNT_DNE_HIST_BIN_CONFIGS_COUNT,
+                      config.value_metric(0).id()));
+}
+
+TEST_F(MetricsManagerUtilTest, TestNumericValueMetricHistogramMultipleValueFields) {
+    StatsdConfig config = createExplicitHistogramStatsdConfig({5, 10, 12});
+    config.mutable_value_metric(0)->mutable_value_field()->add_child()->set_field(2);
+
+    EXPECT_EQ(initConfig(config), nullopt);
+}
+
+TEST_F(MetricsManagerUtilTest, TestNumericValueMetricHistogramWithUploadThreshold) {
+    StatsdConfig config = createExplicitHistogramStatsdConfig({5, 10, 12});
+    config.mutable_value_metric(0)->mutable_threshold()->set_lt_float(1.0);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_WITH_UPLOAD_THRESHOLD,
+                                  config.value_metric(0).id()));
+
+    clearData();
+    config.mutable_value_metric(0)->clear_aggregation_type();
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::HISTOGRAM);
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::SUM);
+    config.mutable_value_metric(0)->mutable_value_field()->add_child()->set_field(2);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_WITH_UPLOAD_THRESHOLD,
+                                  config.value_metric(0).id()));
+}
+
+TEST_F(MetricsManagerUtilTest,
+       TestValueMetricValueFieldHasPositionAllWithStatsdAggregatedHistogram) {
+    StatsdConfig config = createExplicitHistogramStatsdConfig({5, 10, 12});
+    config.mutable_value_metric(0)->mutable_value_field()->mutable_child(0)->set_position(ALL);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_VALUE_FIELD_HAS_POSITION_ALL,
+                                  config.value_metric(0).id()));
+
+    clearData();
+    config.mutable_value_metric(0)->clear_aggregation_type();
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::HISTOGRAM);
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::SUM);
+    config.mutable_value_metric(0)->mutable_value_field()->add_child()->set_field(2);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_VALUE_FIELD_HAS_POSITION_ALL,
+                                  config.value_metric(0).id()));
+}
+
+TEST_F(MetricsManagerUtilTest,
+       TestValueMetricValueFieldHasNoPositionAllWithClientAggregatedHistogram) {
+    StatsdConfig config = createHistogramStatsdConfig();
+    config.mutable_value_metric(0)->add_histogram_bin_configs()->set_id(1);
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_client_aggregated_bins();
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(
+                      INVALID_CONFIG_REASON_VALUE_METRIC_HIST_CLIENT_AGGREGATED_NO_POSITION_ALL,
+                      config.value_metric(0).id()));
+}
+
+TEST_F(MetricsManagerUtilTest,
+       TestValueMetricValueFieldHasPositionAllWithClientAggregatedHistogram) {
+    StatsdConfig config = createHistogramStatsdConfig();
+    config.mutable_value_metric(0)->add_histogram_bin_configs()->set_id(1);
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_client_aggregated_bins();
+    config.mutable_value_metric(0)->mutable_value_field()->mutable_child(0)->set_position(ALL);
+
+    EXPECT_EQ(initConfig(config), nullopt);
+}
+
+TEST_F(MetricsManagerUtilTest, TestValueMetricHistogramWithValueDirectionNotIncreasing) {
+    StatsdConfig config = createHistogramStatsdConfig();
+    config.mutable_value_metric(0)->mutable_value_field()->mutable_child(0)->set_position(ALL);
+    config.mutable_value_metric(0)->add_histogram_bin_configs()->set_id(1);
+    config.mutable_value_metric(0)
+            ->mutable_histogram_bin_configs(0)
+            ->mutable_client_aggregated_bins();
+    config.mutable_value_metric(0)->set_value_direction(ValueMetric::DECREASING);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_INVALID_VALUE_DIRECTION,
+                                  config.value_metric(0).id()));
+
+    clearData();
+    config.mutable_value_metric(0)->clear_aggregation_type();
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::SUM);
+    config.mutable_value_metric(0)->add_aggregation_types(ValueMetric::HISTOGRAM);
+    config.mutable_value_metric(0)->mutable_value_field()->mutable_child(0)->clear_position();
+    config.mutable_value_metric(0)->mutable_value_field()->add_child()->set_field(2);
+    config.mutable_value_metric(0)->mutable_value_field()->mutable_child(1)->set_position(ALL);
+    config.mutable_value_metric(0)->set_value_direction(ValueMetric::ANY);
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_VALUE_METRIC_HIST_INVALID_VALUE_DIRECTION,
+                                  config.value_metric(0).id()));
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/metrics/parsing_utils/parsing_test_utils.cpp b/statsd/tests/metrics/parsing_utils/parsing_test_utils.cpp
new file mode 100644
index 00000000..2bc22536
--- /dev/null
+++ b/statsd/tests/metrics/parsing_utils/parsing_test_utils.cpp
@@ -0,0 +1,108 @@
+
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
+#include "parsing_test_utils.h"
+
+#include <optional>
+#include <vector>
+
+#include "src/external/StatsPullerManager.h"
+#include "src/guardrail/StatsdStats.h"
+#include "src/metrics/parsing_utils/metrics_manager_util.h"
+#include "src/packages/UidMap.h"
+#include "src/state/StateManager.h"
+#include "src/stats_util.h"
+#include "src/statsd_config.pb.h"
+#include "tests/statsd_test_util.h"
+
+namespace android {
+namespace os {
+namespace statsd {
+
+InitConfigTest::InitConfigTest() : uidMap(new UidMap()), pullerManager(new StatsPullerManager()) {
+}
+
+void InitConfigTest::clearData() {
+    allTagIdsToMatchersMap.clear();
+    allAtomMatchingTrackers.clear();
+    atomMatchingTrackerMap.clear();
+    allConditionTrackers.clear();
+    conditionTrackerMap.clear();
+    allMetricProducers.clear();
+    metricProducerMap.clear();
+    allAnomalyTrackers.clear();
+    allAlarmTrackers.clear();
+    conditionToMetricMap.clear();
+    trackerToMetricMap.clear();
+    trackerToConditionMap.clear();
+    activationAtomTrackerToMetricMap.clear();
+    deactivationAtomTrackerToMetricMap.clear();
+    alertTrackerMap.clear();
+    metricsWithActivation.clear();
+    stateProtoHashes.clear();
+    noReportMetricIds.clear();
+}
+
+std::optional<InvalidConfigReason> InitConfigTest::initConfig(const StatsdConfig& config) {
+    // initStatsdConfig returns nullopt if config is valid
+    return initStatsdConfig(
+            kConfigKey, config, uidMap, pullerManager, anomalyAlarmMonitor, periodicAlarmMonitor,
+            timeBaseSec, timeBaseSec, configMetadataProvider, allTagIdsToMatchersMap,
+            allAtomMatchingTrackers, atomMatchingTrackerMap, allConditionTrackers,
+            conditionTrackerMap, allMetricProducers, metricProducerMap, allAnomalyTrackers,
+            allAlarmTrackers, conditionToMetricMap, trackerToMetricMap, trackerToConditionMap,
+            activationAtomTrackerToMetricMap, deactivationAtomTrackerToMetricMap, alertTrackerMap,
+            metricsWithActivation, stateProtoHashes, noReportMetricIds);
+}
+
+void InitConfigTest::SetUp() {
+    clearData();
+    StateManager::getInstance().clear();
+}
+
+StatsdConfig createHistogramStatsdConfig() {
+    StatsdConfig config;
+    *config.add_atom_matcher() = CreateSimpleAtomMatcher("matcher", /* atomId */ 1);
+    *config.add_value_metric() =
+            createValueMetric("ValueMetric", config.atom_matcher(0), /* valueField */ 1,
+                              /* condition */ nullopt, /* states */ {});
+    config.mutable_value_metric(0)->set_aggregation_type(ValueMetric::HISTOGRAM);
+
+    return config;
+}
+
+StatsdConfig createExplicitHistogramStatsdConfig(BinStarts bins) {
+    StatsdConfig config = createHistogramStatsdConfig();
+    *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+            createExplicitBinConfig(/* id */ 1, bins);
+
+    return config;
+}
+
+StatsdConfig createGeneratedHistogramStatsdConfig(
+        float binsMin, float binsMax, int binsCount,
+        HistogramBinConfig::GeneratedBins::Strategy binStrategy) {
+    StatsdConfig config = createHistogramStatsdConfig();
+    *config.mutable_value_metric(0)->add_histogram_bin_configs() =
+            createGeneratedBinConfig(/* id */ 1, binsMin, binsMax, binsCount, binStrategy);
+
+    return config;
+}
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/tests/metrics/parsing_utils/parsing_test_utils.h b/statsd/tests/metrics/parsing_utils/parsing_test_utils.h
new file mode 100644
index 00000000..54070f4f
--- /dev/null
+++ b/statsd/tests/metrics/parsing_utils/parsing_test_utils.h
@@ -0,0 +1,96 @@
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
+#pragma once
+
+#include <gtest/gtest.h>
+#include <utils/RefBase.h>
+
+#include <cstdint>
+#include <map>
+#include <optional>
+#include <set>
+#include <unordered_map>
+#include <vector>
+
+#include "src/anomaly/AlarmMonitor.h"
+#include "src/anomaly/AlarmTracker.h"
+#include "src/anomaly/AnomalyTracker.h"
+#include "src/condition/ConditionTracker.h"
+#include "src/config/ConfigMetadataProvider.h"
+#include "src/external/StatsPullerManager.h"
+#include "src/guardrail/StatsdStats.h"
+#include "src/matchers/AtomMatchingTracker.h"
+#include "src/metrics/MetricProducer.h"
+#include "src/packages/UidMap.h"
+#include "src/stats_util.h"
+#include "src/statsd_config.pb.h"
+
+namespace android {
+namespace os {
+namespace statsd {
+
+constexpr int kConfigId = 12345;
+const ConfigKey kConfigKey(0, kConfigId);
+constexpr long timeBaseSec = 1000;
+constexpr long kAlertId = 3;
+
+class InitConfigTest : public ::testing::Test {
+protected:
+    InitConfigTest();
+
+    void clearData();
+
+    std::optional<InvalidConfigReason> initConfig(const StatsdConfig& config);
+
+    void SetUp() override;
+
+    sp<UidMap> uidMap;
+    sp<StatsPullerManager> pullerManager;
+    sp<AlarmMonitor> anomalyAlarmMonitor;
+    sp<AlarmMonitor> periodicAlarmMonitor;
+    sp<ConfigMetadataProvider> configMetadataProvider;
+    std::unordered_map<int, vector<int>> allTagIdsToMatchersMap;
+    std::vector<sp<AtomMatchingTracker>> allAtomMatchingTrackers;
+    std::unordered_map<int64_t, int> atomMatchingTrackerMap;
+    std::vector<sp<ConditionTracker>> allConditionTrackers;
+    std::unordered_map<int64_t, int> conditionTrackerMap;
+    std::vector<sp<MetricProducer>> allMetricProducers;
+    std::unordered_map<int64_t, int> metricProducerMap;
+    std::vector<sp<AnomalyTracker>> allAnomalyTrackers;
+    std::unordered_map<int64_t, int> alertTrackerMap;
+    std::vector<sp<AlarmTracker>> allAlarmTrackers;
+    std::unordered_map<int, std::vector<int>> conditionToMetricMap;
+    std::unordered_map<int, std::vector<int>> trackerToMetricMap;
+    std::unordered_map<int, std::vector<int>> trackerToConditionMap;
+    std::unordered_map<int, std::vector<int>> activationAtomTrackerToMetricMap;
+    std::unordered_map<int, std::vector<int>> deactivationAtomTrackerToMetricMap;
+    std::vector<int> metricsWithActivation;
+    std::map<int64_t, uint64_t> stateProtoHashes;
+    std::set<int64_t> noReportMetricIds;
+};
+
+StatsdConfig createHistogramStatsdConfig();
+
+StatsdConfig createExplicitHistogramStatsdConfig(BinStarts bins);
+
+StatsdConfig createGeneratedHistogramStatsdConfig(
+        float binsMin, float binsMax, int binsCount,
+        HistogramBinConfig::GeneratedBins::Strategy binStrategy);
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/tests/shell/ShellSubscriber_test.cpp b/statsd/tests/shell/ShellSubscriber_test.cpp
index 0245c095..34addb12 100644
--- a/statsd/tests/shell/ShellSubscriber_test.cpp
+++ b/statsd/tests/shell/ShellSubscriber_test.cpp
@@ -309,8 +309,8 @@ protected:
         configBytes = protoToBytes(getPulledConfig());
 
         // Used to call pullAndSendHeartbeatsIfNeeded directly without depending on sleep.
-        shellSubscriberClient = std::move(ShellSubscriberClient::create(
-                configBytes, callback, /* startTimeSec= */ 0, uidMap, pullerManager));
+        shellSubscriberClient = ShellSubscriberClient::create(
+                configBytes, callback, /* startTimeSec= */ 0, uidMap, pullerManager);
     }
 
     unique_ptr<ShellSubscriberClient> shellSubscriberClient;
diff --git a/statsd/tests/statsd_test_util.cpp b/statsd/tests/statsd_test_util.cpp
index 2d385cae..d30a498e 100644
--- a/statsd/tests/statsd_test_util.cpp
+++ b/statsd/tests/statsd_test_util.cpp
@@ -20,6 +20,7 @@
 #include <android-base/stringprintf.h>
 
 #include "matchers/SimpleAtomMatchingTracker.h"
+#include "metrics/parsing_utils/histogram_parsing_utils.h"
 #include "stats_event.h"
 #include "stats_util.h"
 
@@ -598,12 +599,25 @@ GaugeMetric createGaugeMetric(const string& name, const int64_t what,
 
 ValueMetric createValueMetric(const string& name, const AtomMatcher& what, const int valueField,
                               const optional<int64_t>& condition, const vector<int64_t>& states) {
+    return createValueMetric(name, what, {valueField}, /* aggregationTypes */ {}, condition,
+                             states);
+}
+
+ValueMetric createValueMetric(const string& name, const AtomMatcher& what,
+                              const vector<int>& valueFields,
+                              const vector<ValueMetric::AggregationType>& aggregationTypes,
+                              const optional<int64_t>& condition, const vector<int64_t>& states) {
     ValueMetric metric;
     metric.set_id(StringToId(name));
     metric.set_what(what.id());
     metric.set_bucket(TEN_MINUTES);
     metric.mutable_value_field()->set_field(what.simple_atom_matcher().atom_id());
-    metric.mutable_value_field()->add_child()->set_field(valueField);
+    for (int valueField : valueFields) {
+        metric.mutable_value_field()->add_child()->set_field(valueField);
+    }
+    for (const ValueMetric::AggregationType aggType : aggregationTypes) {
+        metric.add_aggregation_types(aggType);
+    }
     if (condition) {
         metric.set_condition(condition.value());
     }
@@ -613,6 +627,24 @@ ValueMetric createValueMetric(const string& name, const AtomMatcher& what, const
     return metric;
 }
 
+HistogramBinConfig createGeneratedBinConfig(int id, float min, float max, int count,
+                                            HistogramBinConfig::GeneratedBins::Strategy strategy) {
+    HistogramBinConfig binConfig;
+    binConfig.set_id(id);
+    binConfig.mutable_generated_bins()->set_min(min);
+    binConfig.mutable_generated_bins()->set_max(max);
+    binConfig.mutable_generated_bins()->set_count(count);
+    binConfig.mutable_generated_bins()->set_strategy(strategy);
+    return binConfig;
+}
+
+HistogramBinConfig createExplicitBinConfig(int id, const vector<float>& bins) {
+    HistogramBinConfig binConfig;
+    binConfig.set_id(id);
+    *binConfig.mutable_explicit_bins()->mutable_bin() = {bins.begin(), bins.end()};
+    return binConfig;
+}
+
 KllMetric createKllMetric(const string& name, const AtomMatcher& what, const int kllField,
                           const optional<int64_t>& condition) {
     KllMetric metric;
@@ -1119,13 +1151,27 @@ std::unique_ptr<LogEvent> CreateTestAtomReportedEvent(
     AStatsEvent_writeBool(statsEvent, boolField);
     AStatsEvent_writeInt32(statsEvent, enumField);
     AStatsEvent_writeByteArray(statsEvent, bytesField.data(), bytesField.size());
-    AStatsEvent_writeInt32Array(statsEvent, repeatedIntField.data(), repeatedIntField.size());
-    AStatsEvent_writeInt64Array(statsEvent, repeatedLongField.data(), repeatedLongField.size());
-    AStatsEvent_writeFloatArray(statsEvent, repeatedFloatField.data(), repeatedFloatField.size());
-    AStatsEvent_writeStringArray(statsEvent, cRepeatedStringField.data(),
-                                 repeatedStringField.size());
-    AStatsEvent_writeBoolArray(statsEvent, repeatedBoolField, repeatedBoolFieldLength);
-    AStatsEvent_writeInt32Array(statsEvent, repeatedEnumField.data(), repeatedEnumField.size());
+    if (__builtin_available(android __ANDROID_API_T__, *)) {
+        /* CreateTestAtomReportedEvent is used in CreateTestAtomReportedEventVariableRepeatedFields
+           and CreateTestAtomReportedEventWithPrimitives. Only
+           CreateTestAtomReportedEventVariableRepeatedFields writes repeated fields, so wrapping
+           this portion in a __builtin_available and
+           CreateTestAtomReportedEventVariableRepeatedFields is annotated with __INTRODUCED_IN.
+        */
+        AStatsEvent_writeInt32Array(statsEvent, repeatedIntField.data(), repeatedIntField.size());
+        AStatsEvent_writeInt64Array(statsEvent, repeatedLongField.data(), repeatedLongField.size());
+        AStatsEvent_writeFloatArray(statsEvent, repeatedFloatField.data(),
+                                    repeatedFloatField.size());
+        AStatsEvent_writeStringArray(statsEvent, cRepeatedStringField.data(),
+                                     repeatedStringField.size());
+        AStatsEvent_writeBoolArray(statsEvent, repeatedBoolField, repeatedBoolFieldLength);
+        AStatsEvent_writeInt32Array(statsEvent, repeatedEnumField.data(), repeatedEnumField.size());
+    } else if (!repeatedIntField.empty() || !repeatedLongField.empty() ||
+               !repeatedFloatField.empty() || !cRepeatedStringField.empty() ||
+               repeatedBoolFieldLength != 0 || !repeatedEnumField.empty()) {
+        ADD_FAILURE() << "CreateTestAtomReportedEvent w/ repeated fields is only available in "
+                         "Android T and above.";
+    }
 
     std::unique_ptr<LogEvent> logEvent = std::make_unique<LogEvent>(/*uid=*/0, /*pid=*/0);
     parseStatsEventToLogEvent(statsEvent, logEvent.get());
@@ -1507,6 +1553,11 @@ sp<NumericValueMetricProducer> createNumericValueMetricProducer(
         aggregationTypes.push_back(metric.aggregation_type());
     }
 
+    ParseHistogramBinConfigsResult parseBinConfigsResult =
+            parseHistogramBinConfigs(metric, aggregationTypes);
+    const vector<optional<const BinStarts>>& binStartsList =
+            std::get<vector<optional<const BinStarts>>>(parseBinConfigsResult);
+
     sp<MockConfigMetadataProvider> provider = makeMockConfigMetadataProvider(/*enabled=*/false);
     const int pullAtomId = isPulled ? atomId : -1;
     return new NumericValueMetricProducer(
@@ -1514,7 +1565,8 @@ sp<NumericValueMetricProducer> createNumericValueMetricProducer(
             {timeBaseNs, startTimeNs, bucketSizeNs, metric.min_bucket_size_nanos(),
              conditionCorrectionThresholdNs, metric.split_bucket_for_app_upgrade()},
             {containsAnyPositionInDimensionsInWhat, shouldUseNestedDimensions, logEventMatcherIndex,
-             eventMatcherWizard, metric.dimensions_in_what(), fieldMatchers, aggregationTypes},
+             eventMatcherWizard, metric.dimensions_in_what(), fieldMatchers, aggregationTypes,
+             binStartsList},
             {conditionIndex, metric.links(), initialConditionCache, wizard},
             {metric.state_link(), slicedStateAtoms, stateGroupMap},
             {/*eventActivationMap=*/{}, /*eventDeactivationMap=*/{}},
@@ -2191,9 +2243,10 @@ void writeBootFlag(const string& flagName, const string& flagValue) {
 
 PackageInfoSnapshot getPackageInfoSnapshot(const sp<UidMap> uidMap) {
     ProtoOutputStream protoOutputStream;
-    uidMap->writeUidMapSnapshot(/* timestamp */ 1, /* includeVersionStrings */ true,
-                                /* includeInstaller */ true, /* certificateHashSize */ UINT8_MAX,
-                                /* omitSystemUids */ false,
+    uidMap->writeUidMapSnapshot(/* timestamp */ 1,
+                                {/* includeVersionStrings */ true,
+                                 /* includeInstaller */ true, /* certificateHashSize */ UINT8_MAX,
+                                 /* omitSystemUids */ false},
                                 /* interestingUids */ {},
                                 /* installerIndices */ nullptr, /* str_set */ nullptr,
                                 &protoOutputStream);
@@ -2297,7 +2350,15 @@ void fillStatsEventWithSampleValue(AStatsEvent* statsEvent, uint8_t typeId) {
             AStatsEvent_writeString(statsEvent, "test");
             break;
         case LIST_TYPE:
-            AStatsEvent_writeInt32Array(statsEvent, int32Array, 2);
+            if (__builtin_available(android __ANDROID_API_T__, *)) {
+                /* CAUTION: when using this function with LIST_TYPE,
+                    wrap the code in a __builtin_available or __INTRODUCED_IN w/ T.
+                 */
+                AStatsEvent_writeInt32Array(statsEvent, int32Array, 2);
+            } else {
+                ADD_FAILURE() << "fillStatsEventWithSampleValue() w/ typeId LIST_TYPE should only "
+                                 "be used on Android T or above.";
+            }
             break;
         case FLOAT_TYPE:
             AStatsEvent_writeFloat(statsEvent, 1.3f);
diff --git a/statsd/tests/statsd_test_util.h b/statsd/tests/statsd_test_util.h
index 152e5da5..02d8bec7 100644
--- a/statsd/tests/statsd_test_util.h
+++ b/statsd/tests/statsd_test_util.h
@@ -24,6 +24,7 @@
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
+#include "sdk_guard_util.h"
 #include "src/StatsLogProcessor.h"
 #include "src/StatsService.h"
 #include "src/flags/FlagProvider.h"
@@ -353,6 +354,16 @@ GaugeMetric createGaugeMetric(const string& name, int64_t what,
 ValueMetric createValueMetric(const string& name, const AtomMatcher& what, int valueField,
                               const optional<int64_t>& condition, const vector<int64_t>& states);
 
+ValueMetric createValueMetric(const string& name, const AtomMatcher& what,
+                              const vector<int>& valueFields,
+                              const vector<ValueMetric::AggregationType>& aggregationTypes,
+                              const optional<int64_t>& condition, const vector<int64_t>& states);
+
+HistogramBinConfig createGeneratedBinConfig(int id, float min, float max, int count,
+                                            HistogramBinConfig::GeneratedBins::Strategy strategy);
+
+HistogramBinConfig createExplicitBinConfig(int id, const std::vector<float>& bins);
+
 KllMetric createKllMetric(const string& name, const AtomMatcher& what, int kllField,
                           const optional<int64_t>& condition);
 
@@ -409,26 +420,30 @@ void CreateNoValuesLogEvent(LogEvent* logEvent, int atomId, int64_t eventTimeNs)
 AStatsEvent* makeUidStatsEvent(int atomId, int64_t eventTimeNs, int uid, int data1, int data2);
 
 AStatsEvent* makeUidStatsEvent(int atomId, int64_t eventTimeNs, int uid, int data1,
-                               const vector<int>& data2);
+                               const vector<int>& data2) __INTRODUCED_IN(__ANDROID_API_T__);
 
 std::shared_ptr<LogEvent> makeUidLogEvent(int atomId, int64_t eventTimeNs, int uid, int data1,
                                           int data2);
 
 std::shared_ptr<LogEvent> makeUidLogEvent(int atomId, int64_t eventTimeNs, int uid, int data1,
-                                          const vector<int>& data2);
+                                          const vector<int>& data2)
+        __INTRODUCED_IN(__ANDROID_API_T__);
 
 shared_ptr<LogEvent> makeExtraUidsLogEvent(int atomId, int64_t eventTimeNs, int uid1, int data1,
                                            int data2, const std::vector<int>& extraUids);
 
 std::shared_ptr<LogEvent> makeRepeatedUidLogEvent(int atomId, int64_t eventTimeNs,
-                                                  const std::vector<int>& uids);
+                                                  const std::vector<int>& uids)
+        __INTRODUCED_IN(__ANDROID_API_T__);
 
 shared_ptr<LogEvent> makeRepeatedUidLogEvent(int atomId, int64_t eventTimeNs,
-                                             const vector<int>& uids, int data1, int data2);
+                                             const vector<int>& uids, int data1, int data2)
+        __INTRODUCED_IN(__ANDROID_API_T__);
 
 shared_ptr<LogEvent> makeRepeatedUidLogEvent(int atomId, int64_t eventTimeNs,
                                              const vector<int>& uids, int data1,
-                                             const vector<int>& data2);
+                                             const vector<int>& data2)
+        __INTRODUCED_IN(__ANDROID_API_T__);
 
 std::shared_ptr<LogEvent> makeAttributionLogEvent(int atomId, int64_t eventTimeNs,
                                                   const vector<int>& uids,
@@ -574,7 +589,8 @@ void fillStatsEventWithSampleValue(AStatsEvent* statsEvent, uint8_t typeId);
 SocketLossInfo createSocketLossInfo(int32_t uid, int32_t atomId);
 
 // helper API to create STATS_SOCKET_LOSS_REPORTED LogEvent
-std::unique_ptr<LogEvent> createSocketLossInfoLogEvent(int32_t uid, int32_t lossAtomId);
+std::unique_ptr<LogEvent> createSocketLossInfoLogEvent(int32_t uid, int32_t lossAtomId)
+        __INTRODUCED_IN(__ANDROID_API_T__);
 
 // Create a statsd log event processor upon the start time in seconds, config and key.
 sp<StatsLogProcessor> CreateStatsLogProcessor(
@@ -794,6 +810,11 @@ inline bool isAtLeastSFuncFalse() {
     return false;
 }
 
+inline bool isAtLeastT() {
+    const static bool isAtLeastT = android::modules::sdklevel::IsAtLeastT();
+    return isAtLeastT;
+}
+
 inline std::string getServerFlagFuncTrue(const std::string& flagNamespace,
                                          const std::string& flagName,
                                          const std::string& defaultValue) {
diff --git a/statsd/tools/localtools/src/com/android/statsd/shelltools/ExtensionAtomsRegistry.java b/statsd/tools/localtools/src/com/android/statsd/shelltools/ExtensionAtomsRegistry.java
index a1291acb..adf18a94 100644
--- a/statsd/tools/localtools/src/com/android/statsd/shelltools/ExtensionAtomsRegistry.java
+++ b/statsd/tools/localtools/src/com/android/statsd/shelltools/ExtensionAtomsRegistry.java
@@ -19,12 +19,15 @@ import com.android.internal.os.ExperimentIdsProto;
 import com.android.internal.os.UidDataProto;
 import com.android.os.ActiveConfigProto;
 import com.android.os.ShellConfig;
+import com.android.os.accessibility.AccessibilityExtensionAtoms;
+import com.android.os.adpf.AdpfExtensionAtoms;
 import com.android.os.adservices.AdservicesExtensionAtoms;
 import com.android.os.art.ArtExtensionAtoms;
-import com.android.os.art.BackgroundExtensionDexoptAtoms;
+import com.android.os.art.BackgroundDexoptExtensionAtoms;
 import com.android.os.art.OdrefreshExtensionAtoms;
 import com.android.os.automotive.caruilib.AutomotiveCaruilibAtoms;
 import com.android.os.bluetooth.BluetoothExtensionAtoms;
+import com.android.os.broadcasts.BroadcastsExtensionAtoms;
 import com.android.os.devicelogs.DeviceLogsAtoms;
 import com.android.os.dnd.DndAtoms;
 import com.android.os.dnd.DndExtensionAtoms;
@@ -65,6 +68,8 @@ import android.os.statsd.media.MediaCodecExtensionAtoms;
 import com.android.os.credentials.CredentialsExtensionAtoms;
 import com.android.os.sdksandbox.SdksandboxExtensionAtoms;
 import com.android.os.apex.ApexExtensionAtoms;
+import com.android.os.photopicker.PhotopickerExtensionAtoms;
+import com.android.os.uprobestats.UprobestatsExtensionAtoms;
 
 import com.google.protobuf.ExtensionRegistry;
 
@@ -142,7 +147,12 @@ public class ExtensionAtomsRegistry {
         SdksandboxExtensionAtoms.registerAllExtensions(extensionRegistry);
         ArtExtensionAtoms.registerAllExtensions(extensionRegistry);
         ApexExtensionAtoms.registerAllExtensions(extensionRegistry);
-        BackgroundExtensionDexoptAtoms.registerAllExtensions(extensionRegistry);
+        BackgroundDexoptExtensionAtoms.registerAllExtensions(extensionRegistry);
         OdrefreshExtensionAtoms.registerAllExtensions(extensionRegistry);
+        AdpfExtensionAtoms.registerAllExtensions(extensionRegistry);
+        PhotopickerExtensionAtoms.registerAllExtensions(extensionRegistry);
+        UprobestatsExtensionAtoms.registerAllExtensions(extensionRegistry);
+        AccessibilityExtensionAtoms.registerAllExtensions(extensionRegistry);
+        BroadcastsExtensionAtoms.registerAllExtensions(extensionRegistry);
     }
 }
diff --git a/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java b/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
index 47edb25e..d7cfe9eb 100644
--- a/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
+++ b/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
@@ -103,6 +103,8 @@ public class TestDrive {
             "com.android.ondevicepersonalization.services",
             "com.google.android.ondevicepersonalization.services",
             "AID_UPROBESTATS",
+            "com.google.android.hardware.biometrics.face",
+            "com.google.android.photopicker",
     };
     private static final String[] DEFAULT_PULL_SOURCES = {
             "AID_KEYSTORE", "AID_RADIO", "AID_SYSTEM",
diff --git a/tests/Android.bp b/tests/Android.bp
index c4c54756..22dd224f 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -14,6 +14,7 @@
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_telemetry_client_infra",
 }
 
 java_test_host {
diff --git a/tests/apps/atomstormapp/Android.bp b/tests/apps/atomstormapp/Android.bp
index 1162c55e..cf1eeacc 100644
--- a/tests/apps/atomstormapp/Android.bp
+++ b/tests/apps/atomstormapp/Android.bp
@@ -25,9 +25,9 @@ android_test_helper_app {
         "src/**/*.java",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "junit",
-        "org.apache.http.legacy",
+        "org.apache.http.legacy.stubs.system",
     ],
     privileged: true,
     static_libs: [
diff --git a/tests/apps/statsdapp/Android.bp b/tests/apps/statsdapp/Android.bp
index 7dd3d19a..f3c9ecb3 100644
--- a/tests/apps/statsdapp/Android.bp
+++ b/tests/apps/statsdapp/Android.bp
@@ -40,9 +40,9 @@ android_test_helper_app {
         ":statslog-statsd-cts-java-gen",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
         "junit",
-        "org.apache.http.legacy",
+        "org.apache.http.legacy.stubs.system",
     ],
     privileged: true,
     static_libs: [
diff --git a/tests/apps/statsdapp/AndroidManifest.xml b/tests/apps/statsdapp/AndroidManifest.xml
index 1f4f6647..d9ee535e 100644
--- a/tests/apps/statsdapp/AndroidManifest.xml
+++ b/tests/apps/statsdapp/AndroidManifest.xml
@@ -38,7 +38,7 @@
     <uses-permission android:name="android.permission.WRITE_SYNC_SETTINGS"/>
     <uses-permission android:name="android.permission.WRITE_SECURE_SETTINGS"/>
 
-    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="24" />
+    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35" />
     <application android:label="@string/app_name">
         <uses-library android:name="android.test.runner"/>
         <uses-library android:name="org.apache.http.legacy"
diff --git a/tests/src/android/cts/statsd/metadata/MetadataTests.java b/tests/src/android/cts/statsd/metadata/MetadataTests.java
index fb35878f..0688cad4 100644
--- a/tests/src/android/cts/statsd/metadata/MetadataTests.java
+++ b/tests/src/android/cts/statsd/metadata/MetadataTests.java
@@ -82,7 +82,7 @@ public class MetadataTests extends MetadataTestCase {
         AtomTestUtils.sendAppBreadcrumbReportedAtom(getDevice(),
                 AtomsProto.AppBreadcrumbReported.State.START.getNumber(), /* irrelevant val */
                 6); // Event, after TTL_TIME_SEC secs.
-        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_SHORT);
+        RunUtil.getDefault().sleep(2_000);
         report = getStatsdStatsReport();
         LogUtil.CLog.d("got following statsdstats report: " + report.toString());
         foundActiveConfig = false;
@@ -95,7 +95,7 @@ public class MetadataTests extends MetadataTestCase {
                             .that(stats.hasDeletionTimeSec()).isTrue();
                     assertWithMessage(
                             "Config deletion time should be about %s after creation", TTL_TIME_SEC
-                    ).that(Math.abs(stats.getDeletionTimeSec() - expectedTime)).isAtMost(2);
+                    ).that(Math.abs(stats.getDeletionTimeSec() - expectedTime)).isAtMost(3);
                 }
                 // There should still be one active config, that is marked as reset.
                 if (!stats.hasDeletionTimeSec()) {
@@ -109,7 +109,7 @@ public class MetadataTests extends MetadataTestCase {
                             .that(stats.getResetTimeSec()).isEqualTo(stats.getCreationTimeSec());
                     assertWithMessage(
                             "Reset config should be created when the original config TTL'd"
-                    ).that(Math.abs(stats.getCreationTimeSec() - expectedTime)).isAtMost(2);
+                    ).that(Math.abs(stats.getCreationTimeSec() - expectedTime)).isAtMost(3);
                 }
             }
         }
```

