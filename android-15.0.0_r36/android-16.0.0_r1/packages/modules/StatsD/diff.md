```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 00d637f0..5b80e362 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -5,6 +5,4 @@ clang_format = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
-
 hidden_api_txt_checksorted_hook = ${REPO_ROOT}/tools/platform-compat/hiddenapi/checksorted_sha.sh ${PREUPLOAD_COMMIT} ${REPO_ROOT}
diff --git a/aidl/Android.bp b/aidl/Android.bp
index c79f0b8d..46413b4d 100644
--- a/aidl/Android.bp
+++ b/aidl/Android.bp
@@ -48,10 +48,7 @@ aidl_interface {
         },
         ndk: {
             enabled: true,
-            apex_available: [
-                "com.android.os.statsd",
-                "test_com.android.os.statsd",
-            ],
+            apex_available: ["com.android.os.statsd"],
             min_sdk_version: "30",
         },
     }
diff --git a/apex/testing/Android.bp b/apex/testing/Android.bp
index e5213262..bbf20644 100644
--- a/apex/testing/Android.bp
+++ b/apex/testing/Android.bp
@@ -24,6 +24,7 @@ apex_test {
     defaults: ["com.android.os.statsd-defaults"],
     manifest: "test_manifest.json",
     file_contexts: ":com.android.os.statsd-file_contexts",
+    apex_available_name: "com.android.os.statsd",
     // Test APEX, should never be installed
     installable: false,
 }
diff --git a/flags/Android.bp b/flags/Android.bp
index 9b8a1fe2..4b799778 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -27,6 +27,7 @@ aconfig_declarations {
     package: "com.android.os.statsd.flags",
     srcs: [
         "libstatspull_flags.aconfig",
+        "libstatssocket_flags.aconfig",
         "statsd_flags.aconfig",
     ],
 }
@@ -40,3 +41,14 @@ cc_aconfig_library {
     ],
     host_supported: true,
 }
+
+java_aconfig_library {
+    name: "statsd_flags_java_lib-host",
+    aconfig_declarations: "statsd_aconfig_flags",
+    min_sdk_version: "30",
+    host_supported: true,
+    visibility: [
+        "//packages/modules/StatsD:__subpackages__",
+    ],
+    libs: ["fake_device_config"],
+}
diff --git a/flags/libstatssocket_flags.aconfig b/flags/libstatssocket_flags.aconfig
new file mode 100644
index 00000000..bb900b41
--- /dev/null
+++ b/flags/libstatssocket_flags.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.os.statsd.flags"
+container: "com.android.os.statsd"
+
+flag {
+  name: "logging_rate_limit_enabled"
+  namespace: "statsd"
+  description: "This flag controls logging rate limit in listatssocket"
+  bug: "375682465"
+  is_fixed_read_only: true
+}
diff --git a/flags/statsd_flags.aconfig b/flags/statsd_flags.aconfig
index ce1b0e04..46915e19 100644
--- a/flags/statsd_flags.aconfig
+++ b/flags/statsd_flags.aconfig
@@ -1,6 +1,16 @@
 package: "com.android.os.statsd.flags"
 container: "com.android.os.statsd"
 
+flag {
+  name: "parallel_pulls"
+  namespace: "statsd"
+  description: "Whether to enable parallel pulls on alarms."
+  bug: "390014362"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
 flag {
   name: "trigger_uprobestats"
   namespace: "statsd"
@@ -17,3 +27,10 @@ flag {
     is_fixed_read_only: true
 }
 
+flag {
+    name: "enable_logging_rate_stats_collection"
+    namespace: "statsd"
+    description: "Enables atoms logging rate distribution per atom id collection"
+    bug: "382574781"
+    is_fixed_read_only: true
+}
diff --git a/framework/Android.bp b/framework/Android.bp
index 11a1dd36..dd8571bf 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -129,10 +129,7 @@ cc_library_shared {
         "-Wno-unused-parameter",
         "-Wthread-safety",
     ],
-    apex_available: [
-        "com.android.os.statsd",
-        "test_com.android.os.statsd",
-    ],
+    apex_available: ["com.android.os.statsd"],
     min_sdk_version: "30",
     visibility: [
         "//packages/modules/StatsD/apex:__subpackages__",
diff --git a/lib/libkll/Android.bp b/lib/libkll/Android.bp
index 16bd45a5..156eadd2 100644
--- a/lib/libkll/Android.bp
+++ b/lib/libkll/Android.bp
@@ -48,7 +48,6 @@ cc_library {
     export_include_dirs: ["include"],
     apex_available: [
         "com.android.os.statsd",
-        "test_com.android.os.statsd",
         "//apex_available:platform",
     ],
     min_sdk_version: "30",
diff --git a/lib/libkll/encoding/Android.bp b/lib/libkll/encoding/Android.bp
index 0ca3f99e..8312ed4b 100644
--- a/lib/libkll/encoding/Android.bp
+++ b/lib/libkll/encoding/Android.bp
@@ -38,7 +38,6 @@ cc_library_static {
     ],
     apex_available: [
         "com.android.os.statsd",
-        "test_com.android.os.statsd",
         "//apex_available:platform",
     ],
     min_sdk_version: "30",
diff --git a/lib/libkll/proto/Android.bp b/lib/libkll/proto/Android.bp
index ec85a7e9..1f5bbb9f 100644
--- a/lib/libkll/proto/Android.bp
+++ b/lib/libkll/proto/Android.bp
@@ -34,7 +34,6 @@ cc_library_static {
     },
     apex_available: [
         "com.android.os.statsd",
-        "test_com.android.os.statsd",
         "//apex_available:platform",
     ],
     min_sdk_version: "30",
diff --git a/lib/libstatsgtestmatchers/include/gtest_matchers.h b/lib/libstatsgtestmatchers/include/gtest_matchers.h
index 3d9b792b..aabd5edc 100644
--- a/lib/libstatsgtestmatchers/include/gtest_matchers.h
+++ b/lib/libstatsgtestmatchers/include/gtest_matchers.h
@@ -21,6 +21,7 @@
 
 #include "frameworks/proto_logging/stats/atoms.pb.h"
 #include "frameworks/proto_logging/stats/attribution_node.pb.h"
+#include "packages/modules/StatsD/statsd/src/guardrail/stats_log_enums.pb.h"
 #include "packages/modules/StatsD/statsd/src/shell/shell_data.pb.h"
 #include "packages/modules/StatsD/statsd/src/stats_log.pb.h"
 
@@ -234,11 +235,43 @@ TYPE_PRINTER(Atom,
 
 EQ_MATCHER(ShellData,
         REPEATED_PROPERTY_MATCHER(ShellData, atom, EqAtom),
-        REPEATED_PROPERTY_EQ(ShellData, elapsed_timestamp_nanos)
+        REPEATED_PROPERTY_EQ(ShellData, elapsed_timestamp_nanos),
+        REPEATED_PROPERTY_EQ(ShellData, logging_uid)
 );
 TYPE_PRINTER(ShellData,
         REPEATED_PROPERTY_PRINT(atom)
         REPEATED_PROPERTY_PRINT(elapsed_timestamp_nanos)
+        REPEATED_PROPERTY_PRINT(logging_uid)
+);
+
+using CounterStats = StatsdStatsReport_CounterStats;
+
+EQ_MATCHER(CounterStats,
+        PROPERTY_EQ(CounterStats, counter_type),
+        PROPERTY_EQ(CounterStats, count)
+);
+TYPE_PRINTER(CounterStats,
+        PROPERTY_PRINT(counter_type)
+        PROPERTY_PRINT(count)
+);
+
+using AtomStats = StatsdStatsReport_AtomStats;
+
+EQ_MATCHER(AtomStats,
+        PROPERTY_EQ(AtomStats, tag),
+        PROPERTY_EQ(AtomStats, count),
+        PROPERTY_EQ(AtomStats, error_count),
+        PROPERTY_EQ(AtomStats, dropped_count),
+        PROPERTY_EQ(AtomStats, skip_count),
+        PROPERTY_EQ(AtomStats, peak_rate)
+);
+TYPE_PRINTER(AtomStats,
+        PROPERTY_PRINT(tag)
+        PROPERTY_PRINT(count)
+        PROPERTY_PRINT(error_count)
+        PROPERTY_PRINT(dropped_count)
+        PROPERTY_PRINT(skip_count)
+        PROPERTY_PRINT(peak_rate)
 );
 
 // clang-format on
diff --git a/lib/libstatspull/Android.bp b/lib/libstatspull/Android.bp
index e57eab73..efba0c4e 100644
--- a/lib/libstatspull/Android.bp
+++ b/lib/libstatspull/Android.bp
@@ -28,6 +28,7 @@ cc_defaults {
         "stats_subscription.cpp",
         "stats_provider.cpp",
         "stats_pull_atom_callback.cpp",
+        "utils.cpp",
     ],
     cflags: [
         "-Wall",
@@ -65,10 +66,7 @@ cc_library_shared {
             "30",
         ],
     },
-    apex_available: [
-        "com.android.os.statsd",
-        "test_com.android.os.statsd",
-    ],
+    apex_available: ["com.android.os.statsd"],
     min_sdk_version: "30",
     static_libs: [
         "statsd_flags_c_lib",
@@ -79,6 +77,11 @@ cc_library_shared {
 cc_library_headers {
     name: "libstatspull_headers",
     export_include_dirs: ["include"],
+    apex_available: [
+        "com.android.uprobestats",
+        "//apex_available:platform",
+    ],
+    min_sdk_version: "30",
 }
 
 filegroup {
diff --git a/lib/libstatspull/stats_provider.cpp b/lib/libstatspull/stats_provider.cpp
index bee8e89a..16008a3f 100644
--- a/lib/libstatspull/stats_provider.cpp
+++ b/lib/libstatspull/stats_provider.cpp
@@ -17,6 +17,8 @@
 #include <android/binder_manager.h>
 #include <stats_provider.h>
 
+#include "utils.h"
+
 using aidl::android::os::IStatsd;
 
 StatsProvider::StatsProvider(StatsProviderBinderDiedCallback callback)
@@ -31,7 +33,7 @@ std::shared_ptr<IStatsd> StatsProvider::getStatsService() {
     std::lock_guard<std::mutex> lock(mMutex);
     if (!mStatsd) {
         // Fetch statsd
-        ::ndk::SpAIBinder binder(AServiceManager_getService("stats"));
+        ::ndk::SpAIBinder binder(getStatsdBinder());
         mStatsd = IStatsd::fromBinder(binder);
         if (mStatsd) {
             AIBinder_linkToDeath(binder.get(), mDeathRecipient.get(), this);
diff --git a/lib/libstatspull/stats_pull_atom_callback.cpp b/lib/libstatspull/stats_pull_atom_callback.cpp
index 1d2bb226..849fa2fb 100644
--- a/lib/libstatspull/stats_pull_atom_callback.cpp
+++ b/lib/libstatspull/stats_pull_atom_callback.cpp
@@ -21,7 +21,6 @@
 #include <android/binder_auto_utils.h>
 #include <android/binder_ibinder.h>
 #include <android/binder_manager.h>
-#include <com_android_os_statsd_flags.h>
 #include <stats_event.h>
 #include <stats_pull_atom_callback.h>
 
@@ -30,6 +29,8 @@
 #include <thread>
 #include <vector>
 
+#include "utils.h"
+
 using Status = ::ndk::ScopedAStatus;
 using aidl::android::os::BnPullAtomCallback;
 using aidl::android::os::IPullAtomResultReceiver;
@@ -37,8 +38,6 @@ using aidl::android::os::IStatsd;
 using aidl::android::util::StatsEventParcel;
 using ::ndk::SharedRefBase;
 
-namespace flags = com::android::os::statsd::flags;
-
 struct AStatsEventList {
     std::vector<AStatsEvent*> data;
 };
@@ -187,22 +186,7 @@ public:
         std::lock_guard<std::mutex> lock(mStatsdMutex);
         if (!mStatsd) {
             // Fetch statsd
-
-            ::ndk::SpAIBinder binder;
-            // below ifs cannot be combined into single statement due to the way how
-            // macro __builtin_available is handler by compiler:
-            // - it should be used explicitly & independently to guard the corresponding API call
-            // once use_wait_for_service_api flag will be finalized, external if/else pair will be
-            // removed
-            if (flags::use_wait_for_service_api()) {
-                if (__builtin_available(android __ANDROID_API_S__, *)) {
-                    binder.set(AServiceManager_waitForService("stats"));
-                } else {
-                    binder.set(AServiceManager_getService("stats"));
-                }
-            } else {
-                binder.set(AServiceManager_getService("stats"));
-            }
+            ndk::SpAIBinder binder(getStatsdBinder());
             mStatsd = IStatsd::fromBinder(binder);
             if (mStatsd) {
                 AIBinder_linkToDeath(binder.get(), mDeathRecipient.get(), this);
diff --git a/lib/libstatspull/utils.cpp b/lib/libstatspull/utils.cpp
new file mode 100644
index 00000000..53f6ac76
--- /dev/null
+++ b/lib/libstatspull/utils.cpp
@@ -0,0 +1,43 @@
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
+#include "utils.h"
+
+#include <android/binder_manager.h>
+#include <com_android_os_statsd_flags.h>
+
+namespace flags = com::android::os::statsd::flags;
+
+ndk::SpAIBinder getStatsdBinder() {
+    ndk::SpAIBinder binder;
+    // below ifs cannot be combined into single statement due to the way how
+    // macro __builtin_available is handler by compiler:
+    // - it should be used explicitly & independently to guard the corresponding API call
+    // once use_wait_for_service_api flag will be finalized, external if/else pair will be
+    // removed
+#ifdef __ANDROID__
+    if (flags::use_wait_for_service_api()) {
+        if (__builtin_available(android __ANDROID_API_S__, *)) {
+            binder.set(AServiceManager_waitForService("stats"));
+        } else {
+            binder.set(AServiceManager_getService("stats"));
+        }
+    } else {
+        binder.set(AServiceManager_getService("stats"));
+    }
+#endif  //  __ANDROID__
+    return binder;
+}
\ No newline at end of file
diff --git a/lib/libstatspull/utils.h b/lib/libstatspull/utils.h
new file mode 100644
index 00000000..58029a70
--- /dev/null
+++ b/lib/libstatspull/utils.h
@@ -0,0 +1,19 @@
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
+#include <android/binder_auto_utils.h>
+
+ndk::SpAIBinder getStatsdBinder();
diff --git a/lib/libstatssocket/Android.bp b/lib/libstatssocket/Android.bp
index a0bfa51e..cc38035f 100644
--- a/lib/libstatssocket/Android.bp
+++ b/lib/libstatssocket/Android.bp
@@ -25,7 +25,7 @@ package {
 cc_defaults {
     name: "libstatssocket_defaults",
     srcs: [
-        "stats_buffer_writer.c",
+        "stats_buffer_writer.cpp",
         "stats_buffer_writer_queue.cpp",
         "stats_event.c",
         "stats_socket.c",
@@ -52,6 +52,7 @@ cc_defaults {
     ],
     static_libs: [
         "libbase",
+        "statsd_flags_c_lib",
     ],
     min_sdk_version: "30",
 }
@@ -77,10 +78,7 @@ cc_library_shared {
             "30",
         ],
     },
-    apex_available: [
-        "com.android.os.statsd",
-        "test_com.android.os.statsd",
-    ],
+    apex_available: ["com.android.os.statsd"],
 }
 
 cc_library_headers {
@@ -108,6 +106,7 @@ cc_test {
     name: "libstatssocket_test",
     defaults: ["libstatssocket_defaults"],
     srcs: [
+        "tests/logging_rate_limiter_test.cpp",
         "tests/stats_event_test.cpp",
         "tests/stats_writer_test.cpp",
         "tests/stats_buffer_writer_queue_test.cpp",
@@ -130,6 +129,7 @@ cc_test {
 
     static_libs: [
         "libbase",
+        "libflagtest",
         "libgmock",
     ],
     shared_libs: [
diff --git a/lib/libstatssocket/logging_rate_limiter.h b/lib/libstatssocket/logging_rate_limiter.h
new file mode 100644
index 00000000..d87fe73d
--- /dev/null
+++ b/lib/libstatssocket/logging_rate_limiter.h
@@ -0,0 +1,83 @@
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
+#include <stdint.h>
+
+#include <thread>
+#include <unordered_map>
+
+#include "utils.h"
+
+class RealTimeClock {
+public:
+    static int64_t getTimeNs() {
+        return get_elapsed_realtime_ns();
+    }
+};
+
+template <typename Clock>
+class LoggingRateLimiter {
+public:
+    LoggingRateLimiter(int32_t logFrequencyThreshold, int32_t logFrequencyWindowMs)
+        : mLogFrequencyThreshold(logFrequencyThreshold),
+          mLogFrequencyWindowNs(logFrequencyWindowMs * 1000000) {
+    }
+
+    bool canLogAtom(uint32_t atomId) {
+        const int64_t nowNs = Clock::getTimeNs();
+
+        std::unique_lock<std::mutex> lock(mMutex);
+
+        // update current logging frequency
+        auto atomFrequencyIt = mLogFrequencies.find(atomId);
+
+        if (atomFrequencyIt != mLogFrequencies.end()) {
+            Frequency& frequency = atomFrequencyIt->second;
+            if (nowNs - frequency.intervalStartNs >= mLogFrequencyWindowNs) {
+                frequency.intervalStartNs = nowNs;
+                frequency.logsCount = 1;
+                return true;
+            } else {
+                // update frequency
+                frequency.logsCount++;
+            }
+            return isLoggingUnderThreshold(frequency.logsCount);
+        }
+        // atomId not found, add it to the map with initial frequency
+        mLogFrequencies[atomId] = {nowNs, 1};
+        return true;
+    }
+
+private:
+    bool isLoggingUnderThreshold(int32_t logsCount) const {
+        return logsCount <= mLogFrequencyThreshold;
+    }
+
+    std::mutex mMutex;
+
+    const int32_t mLogFrequencyThreshold;
+    const int64_t mLogFrequencyWindowNs;
+
+    struct Frequency {
+        int64_t intervalStartNs;
+        int32_t logsCount;
+    };
+
+    // Key is atom id.
+    std::unordered_map<uint32_t, Frequency> mLogFrequencies;
+};
diff --git a/lib/libstatssocket/stats_buffer_writer.c b/lib/libstatssocket/stats_buffer_writer.cpp
similarity index 75%
rename from lib/libstatssocket/stats_buffer_writer.c
rename to lib/libstatssocket/stats_buffer_writer.cpp
index 33e2ef77..1c8b3bfc 100644
--- a/lib/libstatssocket/stats_buffer_writer.c
+++ b/lib/libstatssocket/stats_buffer_writer.cpp
@@ -14,12 +14,14 @@
  * limitations under the License.
  */
 
-#include "include/stats_buffer_writer.h"
+#include "stats_buffer_writer.h"
 
+#include <com_android_os_statsd_flags.h>
 #include <errno.h>
 #include <sys/time.h>
 #include <sys/uio.h>
 
+#include "logging_rate_limiter.h"
 #include "stats_buffer_writer_impl.h"
 #include "stats_buffer_writer_queue.h"
 #include "statsd_writer.h"
@@ -28,6 +30,8 @@ static const uint32_t kStatsEventTag = 1937006964;
 
 extern struct android_log_transport_write statsdLoggerWrite;
 
+namespace flags = com::android::os::statsd::flags;
+
 static int __write_to_statsd_init(struct iovec* vec, size_t nr);
 static int (*__write_to_statsd)(struct iovec* vec, size_t nr) = __write_to_statsd_init;
 
@@ -54,17 +58,39 @@ int stats_log_is_closed() {
     return statsdLoggerWrite.isClosed && (*statsdLoggerWrite.isClosed)();
 }
 
+bool can_log_atom(uint32_t atomId) {
+    // Below values should be justified with experiments, as of now idea is to
+    // allow to fill 10% of socket buffer at max (max_dgram_qlen == 2400) within 100ms.
+    // This allows to fill entire buffer within a second.
+    // Higher frequency considered as abnormality
+    constexpr int32_t kLogFrequencyThreshold = 240;
+    constexpr int32_t kLoggingFrequencyWindowMs = 100;
+
+    static LoggingRateLimiter<RealTimeClock> rateLimiter(kLogFrequencyThreshold,
+                                                         kLoggingFrequencyWindowMs);
+    return rateLimiter.canLogAtom(atomId);
+}
+
 int write_buffer_to_statsd(void* buffer, size_t size, uint32_t atomId) {
-    const int kQueueOverflowErrorCode = 1;
+    constexpr int kQueueOverflowErrorCode = 1;
+    constexpr int kLoggingRateLimitExceededErrorCode = 2;
+
     if (should_write_via_queue(atomId)) {
-        const bool ret = write_buffer_to_statsd_queue(buffer, size, atomId);
+        const bool ret =
+                write_buffer_to_statsd_queue(static_cast<const uint8_t*>(buffer), size, atomId);
         if (!ret) {
             // to account on the loss, note atom drop with predefined internal error code
             note_log_drop(kQueueOverflowErrorCode, atomId);
         }
         return ret;
     }
-    return write_buffer_to_statsd_impl(buffer, size, atomId, true);
+
+    if (flags::logging_rate_limit_enabled() && !can_log_atom(atomId)) {
+        note_log_drop(kLoggingRateLimitExceededErrorCode, atomId);
+        return 0;
+    }
+
+    return write_buffer_to_statsd_impl(buffer, size, atomId, /*doNoteDrop*/ true);
 }
 
 int write_buffer_to_statsd_impl(void* buffer, size_t size, uint32_t atomId, bool doNoteDrop) {
diff --git a/lib/libstatssocket/stats_socket_loss_reporter.cpp b/lib/libstatssocket/stats_socket_loss_reporter.cpp
index 6b9c2a6c..b604f1e8 100644
--- a/lib/libstatssocket/stats_socket_loss_reporter.cpp
+++ b/lib/libstatssocket/stats_socket_loss_reporter.cpp
@@ -89,6 +89,9 @@ void StatsSocketLossReporter::dumpAtomsLossStats(bool forceDump) {
         // - before writing STATS_SOCKET_LOSS_REPORTED do check the timestamp to keep some delay
         return;
     }
+    // since the delay before next attempt is significantly larger than this API call
+    // duration it is ok to have correctness of timestamp in a range of 10us
+    startCooldownTimer(currentRealtimeTsNanos);
 
     // intention to hold mutex here during the stats_write() to avoid data copy overhead
     std::unique_lock<std::mutex> lock(mMutex);
@@ -122,9 +125,6 @@ void StatsSocketLossReporter::dumpAtomsLossStats(bool forceDump) {
         mFirstTsNanos.store(0, std::memory_order_relaxed);
         mLastTsNanos.store(0, std::memory_order_relaxed);
     }
-    // since the delay before next attempt is significantly larger than this API call
-    // duration it is ok to have correctness of timestamp in a range of 10us
-    startCooldownTimer(currentRealtimeTsNanos);
 }
 
 void StatsSocketLossReporter::startCooldownTimer(int64_t elapsedRealtimeNanos) {
diff --git a/lib/libstatssocket/tests/logging_rate_limiter_test.cpp b/lib/libstatssocket/tests/logging_rate_limiter_test.cpp
new file mode 100644
index 00000000..7bcc4092
--- /dev/null
+++ b/lib/libstatssocket/tests/logging_rate_limiter_test.cpp
@@ -0,0 +1,137 @@
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
+#include "logging_rate_limiter.h"
+
+#include <gtest/gtest.h>
+
+using namespace ::testing;
+
+class ManualClock {
+    static int64_t mTime;
+
+public:
+    static int64_t getTimeNs() {
+        return mTime;
+    }
+
+    static void setTimeNs(int64_t newTime) {
+        mTime = newTime;
+    }
+
+    static void advanceTimeNs(int64_t advanceTimeValue) {
+        mTime += advanceTimeValue;
+    }
+};
+
+int64_t ManualClock::mTime = 0;
+
+TEST(RateLimiter, TestRateLimitActivatedSimple) {
+    // write events in a tight loop
+    // LoggingRateLimiter should be activated after first event
+
+    constexpr int32_t kLogFrequencyThreshold = 1;
+    constexpr int32_t kLoggingFrequencyWindowMs = 1;
+
+    LoggingRateLimiter<ManualClock> rateLimiter(kLogFrequencyThreshold, kLoggingFrequencyWindowMs);
+    ManualClock::setTimeNs(0);
+
+    EXPECT_TRUE(rateLimiter.canLogAtom(/*atomId*/ 1));
+    EXPECT_FALSE(rateLimiter.canLogAtom(/*atomId*/ 1));
+
+    // advance clock to next time window
+    ManualClock::advanceTimeNs(kLoggingFrequencyWindowMs * 1'000'000);
+
+    EXPECT_TRUE(rateLimiter.canLogAtom(/*atomId*/ 1));
+    EXPECT_FALSE(rateLimiter.canLogAtom(/*atomId*/ 1));
+}
+
+TEST(RateLimiter, TestRateLimitActivated) {
+    // write events in a tight loop
+    // LoggingRateLimiter should be activated 100 events
+
+    constexpr int32_t kLogFrequencyThreshold = 100;
+    constexpr int32_t kLoggingFrequencyWindowMs = 100;
+    constexpr int32_t kMaxTestEvents = 2400;
+
+    LoggingRateLimiter<ManualClock> rateLimiter(kLogFrequencyThreshold, kLoggingFrequencyWindowMs);
+    ManualClock::setTimeNs(0);
+
+    int32_t eventsCount = 0;
+    for (int event = 0; event < kMaxTestEvents; event++) {
+        if (rateLimiter.canLogAtom(/*atomId*/ 1)) {
+            eventsCount++;
+        }
+    }
+    EXPECT_EQ(eventsCount, kLogFrequencyThreshold);
+}
+
+TEST(RateLimiter, TestRateLimitNotActivated) {
+    // write events in a tight loop
+    // LoggingRateLimiter should not be activated
+
+    constexpr int32_t kLogFrequencyThreshold = 100;
+    constexpr int32_t kLoggingFrequencyWindowMs = 100;
+    constexpr int32_t kMaxTestEvents = 2400;
+
+    LoggingRateLimiter<ManualClock> rateLimiter(kLogFrequencyThreshold, kLoggingFrequencyWindowMs);
+    ManualClock::setTimeNs(0);
+
+    int32_t eventsCount = 0;
+    for (int event = 0; event < kMaxTestEvents; event++) {
+        if (rateLimiter.canLogAtom(/*atomId*/ 1)) {
+            eventsCount++;
+        }
+        // Simulate logging at single event per 10ms pace to satisfy rate limit
+        // restrictions
+        ManualClock::advanceTimeNs(10 * 1'000'000);
+    }
+
+    // check the values are in the range allowing 10% deviations
+    EXPECT_EQ(eventsCount, kMaxTestEvents);
+}
+
+TEST(RateLimiter, TestRateLimitAcrossTimeWindow) {
+    // write events in a tight loop
+    // LoggingRateLimiter should be activated after 100 events within 100ms
+    // time window, but once next window starts - it will allow logging again
+
+    constexpr int32_t kLogFrequencyThreshold = 100;
+    constexpr int32_t kLoggingFrequencyWindowMs = 100;
+    constexpr int32_t kMaxTestEvents = 2400;
+
+    LoggingRateLimiter<ManualClock> rateLimiter(kLogFrequencyThreshold, kLoggingFrequencyWindowMs);
+    ManualClock::setTimeNs(0);
+
+    int32_t eventsCount = 0;
+    for (int event = 0; event < kMaxTestEvents; event++) {
+        if (rateLimiter.canLogAtom(/*atomId*/ 1)) {
+            eventsCount++;
+        }
+    }
+    EXPECT_EQ(eventsCount, kLogFrequencyThreshold);
+
+    // advance clock to next time window
+    ManualClock::advanceTimeNs(kLoggingFrequencyWindowMs * 1'000'000);
+
+    eventsCount = 0;
+    for (int event = 0; event < kMaxTestEvents; event++) {
+        if (rateLimiter.canLogAtom(/*atomId*/ 1)) {
+            eventsCount++;
+        }
+    }
+    EXPECT_EQ(eventsCount, kLogFrequencyThreshold);
+}
diff --git a/lib/libstatssocket/tests/stats_writer_test.cpp b/lib/libstatssocket/tests/stats_writer_test.cpp
index 749599ff..5e4c8924 100644
--- a/lib/libstatssocket/tests/stats_writer_test.cpp
+++ b/lib/libstatssocket/tests/stats_writer_test.cpp
@@ -14,10 +14,19 @@
  * limitations under the License.
  */
 
+#include <com_android_os_statsd_flags.h>
+#include <flag_macros.h>
+#include <gmock/gmock.h>
 #include <gtest/gtest.h>
+
 #include "stats_buffer_writer.h"
 #include "stats_event.h"
 #include "stats_socket.h"
+#include "utils.h"
+
+using namespace ::testing;
+
+#define TEST_NS com::android::os::statsd::flags
 
 TEST(StatsWriterTest, TestSocketClose) {
     AStatsEvent* event = AStatsEvent_obtain();
@@ -34,3 +43,32 @@ TEST(StatsWriterTest, TestSocketClose) {
 
     EXPECT_TRUE(stats_log_is_closed());
 }
+
+TEST_WITH_FLAGS(StatsWriterTest, TestRateLimit,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(TEST_NS, logging_rate_limit_enabled))) {
+    // write events in a tight loop
+    // libstatssocket should start rate limit after 240 events
+
+    const int32_t maxTestEvents = 2400;
+    const int64_t startNs = get_elapsed_realtime_ns();
+    int32_t eventsCount = 0;
+    for (int i = 0; i < maxTestEvents; i++) {
+        AStatsEvent* event = AStatsEvent_obtain();
+        AStatsEvent_setAtomId(event, 100);
+        AStatsEvent_writeInt32(event, 5);
+        int bytesWritten = AStatsEvent_write(event);
+        AStatsEvent_release(event);
+        if (bytesWritten > 0) {
+            eventsCount++;
+        }
+    }
+
+    const int64_t timeToRateLimitMs = (get_elapsed_realtime_ns() - startNs) / 1'000'000;
+
+    // threshold values are aligned with stats_buffer_writer.cpp
+    constexpr int32_t kLogFrequencyThreshold = 240;
+    constexpr int32_t kLoggingFrequencyWindowMs = 100;
+
+    EXPECT_LE(eventsCount, kLogFrequencyThreshold);
+    EXPECT_THAT(timeToRateLimitMs, Le(kLoggingFrequencyWindowMs));
+}
diff --git a/service/Android.bp b/service/Android.bp
index 96aff18d..bd8d2da0 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -41,10 +41,7 @@ java_library {
     lint: {
         strict_updatability_linting: true
     },
-    apex_available: [
-        "com.android.os.statsd",
-        "test_com.android.os.statsd",
-    ],
+    apex_available: ["com.android.os.statsd"],
     min_sdk_version: "30",
     installable: true,
 }
diff --git a/service/java/com/android/server/stats/StatsCompanionService.java b/service/java/com/android/server/stats/StatsCompanionService.java
index cd7b5167..31ed68cb 100644
--- a/service/java/com/android/server/stats/StatsCompanionService.java
+++ b/service/java/com/android/server/stats/StatsCompanionService.java
@@ -274,6 +274,12 @@ public class StatsCompanionService extends IStatsCompanionService.Stub {
                     Log.e(TAG, "Failed to send uid map to statsd");
                 } catch (IOException e) {
                     Log.e(TAG, "Failed to close the read side of the pipe.", e);
+                } catch (RuntimeException e) {
+                    if (e.getCause() != null && e.getCause() instanceof IOException) {
+                        Log.e(TAG, "Failed to flush write side of the pipe.", e);
+                    } else {
+                        throw e;
+                    }
                 }
                 if (DEBUG) {
                     Log.d(TAG, "Sent data for " + numRecords + " apps");
diff --git a/statsd/Android.bp b/statsd/Android.bp
index 79451d3e..d027759e 100644
--- a/statsd/Android.bp
+++ b/statsd/Android.bp
@@ -111,6 +111,7 @@ cc_defaults {
         "src/shell/shell_config.proto",
         "src/shell/ShellSubscriber.cpp",
         "src/shell/ShellSubscriberClient.cpp",
+        "src/socket/BaseStatsSocketListener.cpp",
         "src/socket/StatsSocketListener.cpp",
         "src/state/StateManager.cpp",
         "src/state/StateTracker.cpp",
@@ -119,6 +120,7 @@ cc_defaults {
         "src/statscompanion_util.cpp",
         "src/statsd_config.proto",
         "src/statsd_metadata.proto",
+        "src/guardrail/LoggingRate.cpp",
         "src/guardrail/stats_log_enums.proto",
         "src/StatsLogProcessor.cpp",
         "src/StatsService.cpp",
@@ -150,6 +152,7 @@ cc_defaults {
         "statsd-aidl-ndk",
         "statsd_flags_c_lib",
         "libsqlite_static_noicu",
+        "libaconfig_storage_read_api_cc",
     ],
     shared_libs: [
         "libbinder_ndk",
@@ -229,10 +232,7 @@ cc_library_static {
     generated_sources: ["statslog_statsd.cpp"],
     generated_headers: ["statslog_statsd.h"],
     export_generated_headers: ["statslog_statsd.h"],
-    apex_available: [
-        "com.android.os.statsd",
-        "test_com.android.os.statsd",
-    ],
+    apex_available: ["com.android.os.statsd"],
     min_sdk_version: "30",
     shared_libs: [
         "libstatssocket",
@@ -301,6 +301,7 @@ cc_defaults {
         "-Wno-unused-variable",
     ],
     static_libs: [
+        "libflagtest",
         "libgmock",
         "libstatslog_statsdtest",
     ],
@@ -504,13 +505,14 @@ cc_benchmark {
         "benchmark/hello_world_benchmark.cpp",
         "benchmark/log_event_benchmark.cpp",
         "benchmark/log_event_filter_benchmark.cpp",
+        "benchmark/loss_info_container_benchmark.cpp",
         "benchmark/main.cpp",
         "benchmark/on_log_event_benchmark.cpp",
         "benchmark/stats_write_benchmark.cpp",
-        "benchmark/loss_info_container_benchmark.cpp",
         "benchmark/string_transform_benchmark.cpp",
-        "benchmark/value_metric_benchmark.cpp",
         "benchmark/tex_metric_benchmark.cpp",
+        "benchmark/utils.cpp",
+        "benchmark/value_metric_benchmark.cpp",
     ],
 
     cflags: [
@@ -518,6 +520,8 @@ cc_benchmark {
         "-Wno-varargs",
     ],
 
+    test_config: "benchmark/AndroidTest.xml",
+
     static_libs: [
         "libgtest",
         "libstats_test_utils",
diff --git a/statsd/benchmark/AndroidTest.xml b/statsd/benchmark/AndroidTest.xml
new file mode 100644
index 00000000..9e754cd9
--- /dev/null
+++ b/statsd/benchmark/AndroidTest.xml
@@ -0,0 +1,28 @@
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
+<configuration description="Config for statsd_benchmark">
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="cleanup" value="true" />
+        <option name="push" value="statsd_benchmark->/data/local/tmp/benchmarktest/statsd_benchmark" />
+    </target_preparer>
+    <option name="test-suite-tag" value="apct" />
+    <option name="not-shardable" value="true" />
+    <test class="com.android.tradefed.testtype.GoogleBenchmarkTest" >
+        <option name="native-benchmark-device-path" value="/data/local/tmp/benchmarktest" />
+        <option name="benchmark-module-name" value="statsd_benchmark" />
+        <option name="file-exclusion-filter-regex" value=".*\.config$" />
+    </test>
+</configuration>
\ No newline at end of file
diff --git a/statsd/benchmark/data_structures_benchmark.cpp b/statsd/benchmark/data_structures_benchmark.cpp
index 5ee451c5..e3b5e95b 100644
--- a/statsd/benchmark/data_structures_benchmark.cpp
+++ b/statsd/benchmark/data_structures_benchmark.cpp
@@ -13,11 +13,15 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+#include <benchmark/benchmark.h>
+
 #include <cstdlib>
 #include <ctime>
+#include <map>
+#include <unordered_map>
 #include <vector>
 
-#include "benchmark/benchmark.h"
+#include "utils.h"
 
 namespace android {
 namespace os {
@@ -56,6 +60,30 @@ void benchmarkStdFillForVector(std::vector<ContainerType>& vec, int capacity) {
     benchmark::DoNotOptimize(resultInt);
 }
 
+template <typename ContainerType>
+void benchmarkUpdateKeyValueContainer(benchmark::State& state) {
+    const int kHashesCount = state.range(0);
+
+    ContainerType matcherStats;
+
+    auto hashIds = generateRandomHashIds(kHashesCount);
+    for (auto& v : hashIds) {
+        matcherStats[v] = 1;
+    }
+
+    int64_t result = 0;
+    while (state.KeepRunning()) {
+        for (auto& v : hashIds) {
+            matcherStats[v]++;
+        }
+        for (auto& v : hashIds) {
+            result += matcherStats[v];
+        }
+        benchmark::DoNotOptimize(result);
+        benchmark::ClobberMemory();
+    }
+}
+
 }  //  namespace
 
 static void BM_BasicVectorBoolUsage(benchmark::State& state) {
@@ -98,6 +126,16 @@ static void BM_VectorInt8StdFill(benchmark::State& state) {
 }
 BENCHMARK(BM_VectorInt8StdFill)->Args({5})->Args({10})->Args({20})->Args({50})->Args({100});
 
+static void BM_DictUpdateWithMap(benchmark::State& state) {
+    benchmarkUpdateKeyValueContainer<std::map<int64_t, int>>(state);
+}
+BENCHMARK(BM_DictUpdateWithMap)->Args({500})->Args({1000})->Args({2000});
+
+static void BM_DictUpdateWithUnorderedMap(benchmark::State& state) {
+    benchmarkUpdateKeyValueContainer<std::unordered_map<int64_t, int>>(state);
+}
+BENCHMARK(BM_DictUpdateWithUnorderedMap)->Args({500})->Args({1000})->Args({2000});
+
 }  //  namespace statsd
 }  //  namespace os
 }  //  namespace android
diff --git a/statsd/benchmark/loss_info_container_benchmark.cpp b/statsd/benchmark/loss_info_container_benchmark.cpp
index 634a1736..27bfc95d 100644
--- a/statsd/benchmark/loss_info_container_benchmark.cpp
+++ b/statsd/benchmark/loss_info_container_benchmark.cpp
@@ -13,14 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-#include <cstdlib>
-#include <ctime>
+#include <benchmark/benchmark.h>
+
 #include <map>
 #include <unordered_map>
 #include <unordered_set>
 #include <vector>
 
-#include "benchmark/benchmark.h"
+#include "utils.h"
 
 namespace android {
 namespace os {
@@ -28,20 +28,6 @@ namespace statsd {
 
 namespace {
 
-std::vector<int> generateRandomIds(int count, int maxRange) {
-    std::srand(std::time(nullptr));
-
-    std::unordered_set<int> unique_values;
-
-    while (unique_values.size() <= count) {
-        unique_values.insert(std::rand() % maxRange);
-    }
-
-    std::vector<int> result(unique_values.begin(), unique_values.end());
-
-    return result;
-}
-
 const int kMaxAtomId = 100000;
 const int kMaxErrorCode = 20;
 
diff --git a/statsd/benchmark/on_log_event_benchmark.cpp b/statsd/benchmark/on_log_event_benchmark.cpp
index d3e5709a..7c6222e4 100644
--- a/statsd/benchmark/on_log_event_benchmark.cpp
+++ b/statsd/benchmark/on_log_event_benchmark.cpp
@@ -15,6 +15,7 @@
  */
 
 #include "benchmark/benchmark.h"
+#include "src/matchers/SimpleAtomMatchingTracker.h"
 #include "tests/statsd_test_util.h"
 
 using namespace std;
@@ -56,6 +57,42 @@ static void BM_OnLogEvent(benchmark::State& state) {
 }
 BENCHMARK(BM_OnLogEvent);
 
+static void BM_EventMatcherWizard(benchmark::State& state) {
+    sp<UidMap> uidMap = new UidMap();
+    std::vector<AtomMatcher> matchers;
+    std::vector<sp<AtomMatchingTracker>> eventTrackers;
+
+    const int pullAtomId = 1000;  // last one in the eventTrackers array
+    // config will contain 1000 distinct matchers where is only one matcher for pullAtomId
+    for (int atomId = 1; atomId <= pullAtomId; atomId++) {
+        auto matcher = CreateSimpleAtomMatcher("matcher" + to_string(atomId), atomId);
+        FieldValueMatcher* rootFvm =
+                matcher.mutable_simple_atom_matcher()->add_field_value_matcher();
+        rootFvm->set_field(2);
+        rootFvm->set_eq_int(20000);
+
+        matchers.push_back(matcher);
+        SimpleAtomMatcher* simpleMatcher = matcher.mutable_simple_atom_matcher();
+        eventTrackers.push_back(
+                new SimpleAtomMatchingTracker(matcher.id(), atomId, *simpleMatcher, uidMap));
+    }
+
+    const int whatMatcherIndex = eventTrackers.size() - 1;
+
+    sp<EventMatcherWizard> eventMatcherWizard = new EventMatcherWizard(eventTrackers);
+
+    shared_ptr<LogEvent> event =
+            makeUidLogEvent(pullAtomId, 2 * 60 * NS_PER_SEC, 10000, 20000, 30000);
+
+    // mimic pulled metrics onDataPulled() flow
+    for (auto _ : state) {
+        for (int i = 0; i < 1000; i++) {
+            benchmark::DoNotOptimize(eventMatcherWizard->matchLogEvent(*event, whatMatcherIndex));
+        }
+    }
+}
+BENCHMARK(BM_EventMatcherWizard);
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/benchmark/utils.cpp b/statsd/benchmark/utils.cpp
new file mode 100644
index 00000000..70799195
--- /dev/null
+++ b/statsd/benchmark/utils.cpp
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
+#include "utils.h"
+
+#include <cstdlib>
+#include <ctime>
+#include <limits>
+#include <random>
+#include <unordered_set>
+
+namespace android {
+namespace os {
+namespace statsd {
+
+std::vector<int> generateRandomIds(int count, int maxRange) {
+    std::srand(std::time(nullptr));
+
+    std::unordered_set<int> unique_values;
+
+    while (unique_values.size() <= count) {
+        unique_values.insert(std::rand() % maxRange);
+    }
+
+    std::vector<int> result(unique_values.begin(), unique_values.end());
+
+    return result;
+}
+
+std::vector<int64_t> generateRandomHashIds(int count) {
+    std::srand(std::time(nullptr));
+
+    std::random_device rd;
+    std::mt19937_64 eng(rd());
+
+    std::uniform_int_distribution<int64_t> distr;
+
+    std::unordered_set<int> unique_values;
+
+    while (unique_values.size() <= count) {
+        unique_values.insert(distr(eng));
+    }
+
+    std::vector<int64_t> result(unique_values.begin(), unique_values.end());
+
+    return result;
+}
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
\ No newline at end of file
diff --git a/statsd/benchmark/utils.h b/statsd/benchmark/utils.h
new file mode 100644
index 00000000..399da815
--- /dev/null
+++ b/statsd/benchmark/utils.h
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
+#include <stdint.h>
+
+#include <vector>
+
+namespace android {
+namespace os {
+namespace statsd {
+
+std::vector<int> generateRandomIds(int count, int maxRange);
+
+std::vector<int64_t> generateRandomHashIds(int count);
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
\ No newline at end of file
diff --git a/statsd/fuzzers/statsd_socket_data_fuzzer.cpp b/statsd/fuzzers/statsd_socket_data_fuzzer.cpp
index bfdfd8b8..d65b010f 100644
--- a/statsd/fuzzers/statsd_socket_data_fuzzer.cpp
+++ b/statsd/fuzzers/statsd_socket_data_fuzzer.cpp
@@ -14,20 +14,21 @@
  * limitations under the License.
  */
 
-#include "socket/StatsSocketListener.h"
+#include "socket/BaseStatsSocketListener.h"
 
 namespace android {
 namespace os {
 namespace statsd {
 
 void fuzzSocket(const uint8_t* data, size_t size) {
-    LogEventQueue queue(50000);
-    LogEventFilter filter;
-    filter.setFilteringEnabled(false);
+    std::shared_ptr<LogEventQueue> queue(new LogEventQueue(50000));
+    std::shared_ptr<LogEventFilter> filter(new LogEventFilter());
+    filter->setFilteringEnabled(false);
 
-    StatsSocketListener::processSocketMessage((const char*)data, size, 0, 0, queue, filter);
+    BaseStatsSocketListener statsSocketListener(queue, filter);
 
-    StatsSocketListener::processStatsEventBuffer(data, size, 0, 0, queue, filter);
+    statsSocketListener.processSocketMessage((void*) data, size, 0, 0);
+    statsSocketListener.processStatsEventBuffer(data, size, 0, 0, *queue, *filter);
 }
 
 }  // namespace statsd
diff --git a/statsd/src/HashableDimensionKey.cpp b/statsd/src/HashableDimensionKey.cpp
index 03a42296..fb42efd5 100644
--- a/statsd/src/HashableDimensionKey.cpp
+++ b/statsd/src/HashableDimensionKey.cpp
@@ -227,15 +227,21 @@ bool filterPrimaryKey(const std::vector<FieldValue>& values, HashableDimensionKe
     return num_matches > 0;
 }
 
-void filterGaugeValues(const std::vector<Matcher>& matcherFields,
-                       const std::vector<FieldValue>& values, std::vector<FieldValue>* output) {
+vector<FieldValue> filterValues(const std::vector<Matcher>& matcherFields,
+                                const std::vector<FieldValue>& values, bool omitMatches) {
+    if (matcherFields.empty()) {
+        return values;
+    }
+
+    vector<FieldValue> output;
     for (const auto& field : matcherFields) {
         for (const auto& value : values) {
-            if (value.mField.matches(field)) {
-                output->push_back(value);
+            if (value.mField.matches(field) ^ omitMatches) {
+                output.push_back(value);
             }
         }
     }
+    return output;
 }
 
 void getDimensionForCondition(const std::vector<FieldValue>& eventValues,
diff --git a/statsd/src/HashableDimensionKey.h b/statsd/src/HashableDimensionKey.h
index 4792e8d9..e3f82b62 100644
--- a/statsd/src/HashableDimensionKey.h
+++ b/statsd/src/HashableDimensionKey.h
@@ -227,8 +227,8 @@ bool filterPrimaryKey(const std::vector<FieldValue>& values, HashableDimensionKe
  * In contrast to the above function, this function will not do any modification to the original
  * data. Considering it as taking a snapshot on the atom event.
  */
-void filterGaugeValues(const std::vector<Matcher>& matchers, const std::vector<FieldValue>& values,
-                       std::vector<FieldValue>* output);
+std::vector<FieldValue> filterValues(const std::vector<Matcher>& matchers,
+                                     const std::vector<FieldValue>& values, bool omitMatches);
 
 void getDimensionForCondition(const std::vector<FieldValue>& eventValues,
                               const Metric2Condition& links,
diff --git a/statsd/src/StatsLogProcessor.cpp b/statsd/src/StatsLogProcessor.cpp
index 88524f6c..6be387ff 100644
--- a/statsd/src/StatsLogProcessor.cpp
+++ b/statsd/src/StatsLogProcessor.cpp
@@ -407,18 +407,16 @@ void StatsLogProcessor::OnLogEvent(LogEvent* event) {
 }
 
 void StatsLogProcessor::OnLogEvent(LogEvent* event, int64_t elapsedRealtimeNs) {
-    std::lock_guard<std::mutex> lock(mMetricsMutex);
-
-    // Tell StatsdStats about new event
     const int64_t eventElapsedTimeNs = event->GetElapsedTimestampNs();
     const int atomId = event->GetTagId();
-    StatsdStats::getInstance().noteAtomLogged(atomId, eventElapsedTimeNs / NS_PER_SEC,
-                                              event->isParsedHeaderOnly());
+
     if (!event->isValid()) {
         StatsdStats::getInstance().noteAtomError(atomId);
         return;
     }
 
+    std::lock_guard<std::mutex> lock(mMetricsMutex);
+
     // Hard-coded logic to update train info on disk and fill in any information
     // this log event may be missing.
     if (atomId == util::BINARY_PUSH_STATE_CHANGED) {
@@ -505,7 +503,7 @@ void StatsLogProcessor::OnLogEvent(LogEvent* event, int64_t elapsedRealtimeNs) {
         }
         // The activation state of this config changed.
         if (isPrevActive != isCurActive) {
-            VLOG("Active status changed for uid  %d", uid);
+            ALOGI("Active status changed for uid  %d", uid);
             uidsWithActiveConfigsChanged.insert(uid);
             StatsdStats::getInstance().noteActiveStatusChanged(pair.first, isCurActive);
         }
@@ -520,20 +518,20 @@ void StatsLogProcessor::OnLogEvent(LogEvent* event, int64_t elapsedRealtimeNs) {
             if (elapsedRealtimeNs - lastBroadcastTime->second <
                 StatsdStats::kMinActivationBroadcastPeriodNs) {
                 StatsdStats::getInstance().noteActivationBroadcastGuardrailHit(uid);
-                VLOG("StatsD would've sent an activation broadcast but the rate limit stopped us.");
+                ALOGI("StatsD would've sent an activation broadcast but the guardrail stopped us.");
                 return;
             }
         }
         auto activeConfigs = activeConfigsPerUid.find(uid);
         if (activeConfigs != activeConfigsPerUid.end()) {
             if (mSendActivationBroadcast(uid, activeConfigs->second)) {
-                VLOG("StatsD sent activation notice for uid %d", uid);
+                ALOGI("StatsD sent activation notice for uid %d", uid);
                 mLastActivationBroadcastTimes[uid] = elapsedRealtimeNs;
             }
         } else {
             std::vector<int64_t> emptyActiveConfigs;
             if (mSendActivationBroadcast(uid, emptyActiveConfigs)) {
-                VLOG("StatsD sent EMPTY activation notice for uid %d", uid);
+                ALOGI("StatsD sent EMPTY activation notice for uid %d", uid);
                 mLastActivationBroadcastTimes[uid] = elapsedRealtimeNs;
             }
         }
@@ -1528,13 +1526,18 @@ LogEventFilter::AtomIdSet StatsLogProcessor::getDefaultAtomIdSet() {
 }
 
 void StatsLogProcessor::updateLogEventFilterLocked() const {
-    VLOG("StatsLogProcessor: Updating allAtomIds");
+    VLOG("StatsLogProcessor: Updating allAtomIds at %lld", (long long)getElapsedRealtimeNs());
     LogEventFilter::AtomIdSet allAtomIds = getDefaultAtomIdSet();
     for (const auto& metricsManager : mMetricsManagers) {
         metricsManager.second->addAllAtomIds(allAtomIds);
     }
     StateManager::getInstance().addAllAtomIds(allAtomIds);
     VLOG("StatsLogProcessor: Updating allAtomIds done. Total atoms %d", (int)allAtomIds.size());
+#ifdef STATSD_DEBUG
+    for (auto atomId : allAtomIds) {
+        VLOG("Atom in use %d", atomId);
+    }
+#endif  // STATSD_DEBUG
     mLogEventFilter->setAtomIds(std::move(allAtomIds), this);
 }
 
diff --git a/statsd/src/StatsLogProcessor.h b/statsd/src/StatsLogProcessor.h
index f640460a..732e2259 100644
--- a/statsd/src/StatsLogProcessor.h
+++ b/statsd/src/StatsLogProcessor.h
@@ -489,6 +489,13 @@ private:
     FRIEND_TEST(DurationMetricE2eTest, TestUploadThreshold);
     FRIEND_TEST(DurationMetricE2eTest, TestConditionOnRepeatedEnumField);
 
+    FRIEND_TEST(EventMetricE2eTest, TestSlicedState);
+
+    FRIEND_TEST(GaugeMetricE2ePulledTest, TestSliceByStates);
+    FRIEND_TEST(GaugeMetricE2ePulledTest, TestSliceByStatesWithTriggerAndCondition);
+    FRIEND_TEST(GaugeMetricE2ePulledTest, TestSliceByStatesWithMapAndTrigger);
+    FRIEND_TEST(GaugeMetricE2ePulledTest, TestSliceByStatesWithPrimaryFieldsAndTrigger);
+
     FRIEND_TEST(ValueMetricE2eTest, TestInitialConditionChanges);
     FRIEND_TEST(ValueMetricE2eTest, TestPulledEvents);
     FRIEND_TEST(ValueMetricE2eTest, TestPulledEvents_LateAlarm);
diff --git a/statsd/src/StatsService.cpp b/statsd/src/StatsService.cpp
index 493bb0fc..6f8ca663 100644
--- a/statsd/src/StatsService.cpp
+++ b/statsd/src/StatsService.cpp
@@ -166,7 +166,7 @@ StatsService::StatsService(const sp<UidMap>& uidMap, shared_ptr<LogEventQueue> q
             [this](const ConfigKey& key) {
                 shared_ptr<IPendingIntentRef> receiver = mConfigManager->GetConfigReceiver(key);
                 if (receiver == nullptr) {
-                    VLOG("Could not find a broadcast receiver for %s", key.ToString().c_str());
+                    ALOGE("Could not find a broadcast receiver for %s", key.ToString().c_str());
                     return false;
                 }
                 Status status = receiver->sendDataBroadcast(mProcessor->getLastReportTimeNs(key));
@@ -177,26 +177,26 @@ StatsService::StatsService(const sp<UidMap>& uidMap, shared_ptr<LogEventQueue> q
                     status.getStatus() == STATUS_DEAD_OBJECT) {
                     mConfigManager->RemoveConfigReceiver(key, receiver);
                 }
-                VLOG("Failed to send a broadcast for receiver %s", key.ToString().c_str());
+                ALOGE("Failed to send a broadcast for receiver %s", key.ToString().c_str());
                 return false;
             },
             [this](const int& uid, const vector<int64_t>& activeConfigs) {
                 shared_ptr<IPendingIntentRef> receiver =
                     mConfigManager->GetActiveConfigsChangedReceiver(uid);
                 if (receiver == nullptr) {
-                    VLOG("Could not find receiver for uid %d", uid);
+                    ALOGE("Could not find receiver for uid %d", uid);
                     return false;
                 }
                 Status status = receiver->sendActiveConfigsChangedBroadcast(activeConfigs);
                 if (status.isOk()) {
-                    VLOG("StatsService::active configs broadcast succeeded for uid %d" , uid);
+                    ALOGI("StatsService::active configs broadcast succeeded for uid %d" , uid);
                     return true;
                 }
                 if (status.getExceptionCode() == EX_TRANSACTION_FAILED &&
                     status.getStatus() == STATUS_DEAD_OBJECT) {
                     mConfigManager->RemoveActiveConfigsChangedReceiver(uid, receiver);
                 }
-                VLOG("StatsService::active configs broadcast failed for uid %d", uid);
+                ALOGE("StatsService::active configs broadcast failed for uid %d", uid);
                 return false;
             },
             [this](const ConfigKey& key, const string& delegatePackage,
@@ -1248,6 +1248,10 @@ Status StatsService::addConfiguration(int64_t key, const vector <uint8_t>& confi
 }
 
 bool StatsService::addConfigurationChecked(int uid, int64_t key, const vector<uint8_t>& config) {
+    const bool pastFilterState = mLogEventFilter->getFilteringEnabled();
+    // disabling filter to avoid skipping potentially interesting atoms required by
+    // the new or updated configuration
+    mLogEventFilter->setFilteringEnabled(false);
     ConfigKey configKey(uid, key);
     StatsdConfig cfg;
     if (config.size() > 0) {  // If the config is empty, skip parsing.
@@ -1256,6 +1260,7 @@ bool StatsService::addConfigurationChecked(int uid, int64_t key, const vector<ui
         }
     }
     mConfigManager->UpdateConfig(configKey, cfg);
+    mLogEventFilter->setFilteringEnabled(pastFilterState);
     return true;
 }
 
diff --git a/statsd/src/external/StatsPullerManager.cpp b/statsd/src/external/StatsPullerManager.cpp
index bba32b99..81e586ab 100644
--- a/statsd/src/external/StatsPullerManager.cpp
+++ b/statsd/src/external/StatsPullerManager.cpp
@@ -19,11 +19,13 @@
 
 #include "StatsPullerManager.h"
 
+#include <com_android_os_statsd_flags.h>
 #include <cutils/log.h>
 #include <math.h>
 #include <stdint.h>
 
 #include <algorithm>
+#include <atomic>
 #include <iostream>
 
 #include "../StatsService.h"
@@ -37,15 +39,30 @@
 using std::shared_ptr;
 using std::vector;
 
+namespace flags = com::android::os::statsd::flags;
+
 namespace android {
 namespace os {
 namespace statsd {
 
 // Values smaller than this may require to update the alarm.
 const int64_t NO_ALARM_UPDATE = INT64_MAX;
+// Use 3 threads to avoid overwhelming system server binder threads
+const int32_t PULLER_THREAD_COUNT = 3;
+
+static PullErrorCode pullImpl(const PullerKey& key, const sp<StatsPuller>& puller,
+                              const int64_t eventTimeNs, vector<shared_ptr<LogEvent>>* data) {
+    VLOG("Initiating pulling %d", key.atomTag);
+    PullErrorCode status = puller->Pull(eventTimeNs, data);
+    VLOG("pulled %zu items", data->size());
+    if (status != PULL_SUCCESS) {
+        StatsdStats::getInstance().notePullFailed(key.atomTag);
+    }
+    return status;
+}
 
 StatsPullerManager::StatsPullerManager()
-    : kAllPullAtomInfo({
+    : mAllPullAtomInfo({
               // TrainInfo.
               {{.uid = AID_STATSD, .atomTag = util::TRAIN_INFO}, new TrainInfoPuller()},
       }),
@@ -69,21 +86,9 @@ bool StatsPullerManager::Pull(int tagId, const vector<int32_t>& uids, const int6
 bool StatsPullerManager::PullLocked(int tagId, const ConfigKey& configKey,
                                     const int64_t eventTimeNs, vector<shared_ptr<LogEvent>>* data) {
     vector<int32_t> uids;
-    const auto& uidProviderIt = mPullUidProviders.find(configKey);
-    if (uidProviderIt == mPullUidProviders.end()) {
-        ALOGE("Error pulling tag %d. No pull uid provider for config key %s", tagId,
-              configKey.ToString().c_str());
-        StatsdStats::getInstance().notePullUidProviderNotFound(tagId);
+    if (!getPullerUidsLocked(tagId, configKey, uids)) {
         return false;
     }
-    sp<PullUidProvider> pullUidProvider = uidProviderIt->second.promote();
-    if (pullUidProvider == nullptr) {
-        ALOGE("Error pulling tag %d, pull uid provider for config %s is gone.", tagId,
-              configKey.ToString().c_str());
-        StatsdStats::getInstance().notePullUidProviderNotFound(tagId);
-        return false;
-    }
-    uids = pullUidProvider->getPullAtomUids(tagId);
     return PullLocked(tagId, uids, eventTimeNs, data);
 }
 
@@ -92,12 +97,17 @@ bool StatsPullerManager::PullLocked(int tagId, const vector<int32_t>& uids,
     VLOG("Initiating pulling %d", tagId);
     for (int32_t uid : uids) {
         PullerKey key = {.uid = uid, .atomTag = tagId};
-        auto pullerIt = kAllPullAtomInfo.find(key);
-        if (pullerIt != kAllPullAtomInfo.end()) {
-            PullErrorCode status = pullerIt->second->Pull(eventTimeNs, data);
-            VLOG("pulled %zu items", data->size());
-            if (status != PULL_SUCCESS) {
-                StatsdStats::getInstance().notePullFailed(tagId);
+        auto pullerIt = mAllPullAtomInfo.find(key);
+        if (pullerIt != mAllPullAtomInfo.end()) {
+            PullErrorCode status = PULL_SUCCESS;
+            if (flags::parallel_pulls()) {
+                status = pullImpl(key, pullerIt->second, eventTimeNs, data);
+            } else {
+                status = pullerIt->second->Pull(eventTimeNs, data);
+                VLOG("pulled %zu items", data->size());
+                if (status != PULL_SUCCESS) {
+                    StatsdStats::getInstance().notePullFailed(tagId);
+                }
             }
             // If we received a dead object exception, it means the client process has died.
             // We can remove the puller from the map.
@@ -105,7 +115,7 @@ bool StatsPullerManager::PullLocked(int tagId, const vector<int32_t>& uids,
                 StatsdStats::getInstance().notePullerCallbackRegistrationChanged(
                         tagId,
                         /*registered=*/false);
-                kAllPullAtomInfo.erase(pullerIt);
+                mAllPullAtomInfo.erase(pullerIt);
             }
             return status == PULL_SUCCESS;
         }
@@ -141,7 +151,7 @@ void StatsPullerManager::SetStatsCompanionService(
     std::lock_guard<std::mutex> _l(mLock);
     shared_ptr<IStatsCompanionService> tmpForLock = mStatsCompanionService;
     mStatsCompanionService = statsCompanionService;
-    for (const auto& pulledAtom : kAllPullAtomInfo) {
+    for (const auto& pulledAtom : mAllPullAtomInfo) {
         pulledAtom.second->SetStatsCompanionService(statsCompanionService);
     }
     if (mStatsCompanionService != nullptr) {
@@ -218,13 +228,131 @@ void StatsPullerManager::UnregisterPullUidProvider(const ConfigKey& configKey,
     }
 }
 
+static void processPullerQueue(ThreadSafeQueue<StatsPullerManager::PullerParams>& pullerQueue,
+                               std::queue<StatsPullerManager::PulledInfo>& pulledData,
+                               const int64_t wallClockNs, const int64_t elapsedTimeNs,
+                               std::atomic_int& pendingThreads,
+                               std::condition_variable& mainThreadCondition,
+                               std::mutex& mainThreadConditionLock) {
+    std::optional<StatsPullerManager::PullerParams> queueResult = pullerQueue.pop();
+    while (queueResult.has_value()) {
+        const StatsPullerManager::PullerParams pullerParams = queueResult.value();
+        vector<shared_ptr<LogEvent>> data;
+        PullErrorCode pullErrorCode =
+                pullImpl(pullerParams.key, pullerParams.puller, elapsedTimeNs, &data);
+
+        if (pullErrorCode != PULL_SUCCESS) {
+            VLOG("pull failed at %lld, will try again later", (long long)elapsedTimeNs);
+        }
+
+        // Convention is to mark pull atom timestamp at request time.
+        // If we pull at t0, puller starts at t1, finishes at t2, and send back
+        // at t3, we mark t0 as its timestamp, which should correspond to its
+        // triggering event, such as condition change at t0.
+        // Here the triggering event is alarm fired from AlarmManager.
+        // In ValueMetricProducer and GaugeMetricProducer we do same thing
+        // when pull on condition change, etc.
+        for (auto& event : data) {
+            event->setElapsedTimestampNs(elapsedTimeNs);
+            event->setLogdWallClockTimestampNs(wallClockNs);
+        }
+
+        StatsPullerManager::PulledInfo pulledInfo;
+        pulledInfo.pullErrorCode = pullErrorCode;
+        pulledInfo.pullerKey = pullerParams.key;
+        pulledInfo.receiverInfo = std::move(pullerParams.receivers);
+        pulledInfo.data = std::move(data);
+        mainThreadConditionLock.lock();
+        pulledData.push(pulledInfo);
+        mainThreadConditionLock.unlock();
+        mainThreadCondition.notify_one();
+
+        queueResult = pullerQueue.pop();
+    }
+    pendingThreads--;
+    mainThreadCondition.notify_one();
+}
+
 void StatsPullerManager::OnAlarmFired(int64_t elapsedTimeNs) {
     ATRACE_CALL();
     std::lock_guard<std::mutex> _l(mLock);
     int64_t wallClockNs = getWallClockNs();
 
     int64_t minNextPullTimeNs = NO_ALARM_UPDATE;
+    if (flags::parallel_pulls()) {
+        ThreadSafeQueue<PullerParams> pullerQueue;
+        std::queue<PulledInfo> pulledData;
+        initPullerQueue(pullerQueue, pulledData, elapsedTimeNs, minNextPullTimeNs);
+        std::mutex mainThreadConditionLock;
+        std::condition_variable waitForPullerThreadsCondition;
+        vector<thread> pullerThreads;
+        std::atomic_int pendingThreads = PULLER_THREAD_COUNT;
+        pullerThreads.reserve(PULLER_THREAD_COUNT);
+        // Spawn multiple threads to simultaneously pull all necessary pullers. These pullers push
+        // the pulled data to a queue for the main thread to process.
+        for (int i = 0; i < PULLER_THREAD_COUNT; ++i) {
+            pullerThreads.emplace_back(
+                    processPullerQueue, std::ref(pullerQueue), std::ref(pulledData), wallClockNs,
+                    elapsedTimeNs, std::ref(pendingThreads),
+                    std::ref(waitForPullerThreadsCondition), std::ref(mainThreadConditionLock));
+        }
 
+        // Process all pull results on the main thread without waiting for the puller threads
+        // to finish.
+        while (true) {
+            std::unique_lock<std::mutex> lock(mainThreadConditionLock);
+            waitForPullerThreadsCondition.wait(lock, [&pulledData, &pendingThreads]() -> bool {
+                return pendingThreads == 0 || !pulledData.empty();
+            });
+            if (!pulledData.empty()) {
+                const PulledInfo pullResultInfo = std::move(pulledData.front());
+                pulledData.pop();
+                const PullErrorCode pullErrorCode = pullResultInfo.pullErrorCode;
+                const vector<ReceiverInfo*>& receiverInfos = pullResultInfo.receiverInfo;
+                const vector<shared_ptr<LogEvent>>& data = pullResultInfo.data;
+                for (const auto& receiverInfo : receiverInfos) {
+                    sp<PullDataReceiver> receiverPtr = receiverInfo->receiver.promote();
+                    if (receiverPtr != nullptr) {
+                        PullResult pullResult = pullErrorCode == PULL_SUCCESS
+                                                        ? PullResult::PULL_RESULT_SUCCESS
+                                                        : PullResult::PULL_RESULT_FAIL;
+                        receiverPtr->onDataPulled(data, pullResult, elapsedTimeNs);
+                        // We may have just come out of a coma, compute next pull time.
+                        int numBucketsAhead = (elapsedTimeNs - receiverInfo->nextPullTimeNs) /
+                                              receiverInfo->intervalNs;
+                        receiverInfo->nextPullTimeNs +=
+                                (numBucketsAhead + 1) * receiverInfo->intervalNs;
+                        minNextPullTimeNs = min(receiverInfo->nextPullTimeNs, minNextPullTimeNs);
+                    } else {
+                        VLOG("receiver already gone.");
+                    }
+                }
+                if (pullErrorCode == PULL_DEAD_OBJECT) {
+                    mAllPullAtomInfo.erase(pullResultInfo.pullerKey);
+                }
+                // else if is used here for the edge case of all threads being completed but
+                // there are remaining pulled results in the queue to process.
+            } else if (pendingThreads == 0) {
+                break;
+            }
+        }
+
+        for (thread& pullerThread : pullerThreads) {
+            pullerThread.join();
+        }
+
+    } else {
+        onAlarmFiredSynchronous(elapsedTimeNs, wallClockNs, minNextPullTimeNs);
+    }
+    VLOG("mNextPullTimeNs: %lld updated to %lld", (long long)mNextPullTimeNs,
+         (long long)minNextPullTimeNs);
+    mNextPullTimeNs = minNextPullTimeNs;
+    updateAlarmLocked();
+}
+
+void StatsPullerManager::onAlarmFiredSynchronous(const int64_t elapsedTimeNs,
+                                                 const int64_t wallClockNs,
+                                                 int64_t& minNextPullTimeNs) {
     vector<pair<const ReceiverKey*, vector<ReceiverInfo*>>> needToPull;
     for (auto& pair : mReceivers) {
         vector<ReceiverInfo*> receivers;
@@ -289,18 +417,92 @@ void StatsPullerManager::OnAlarmFired(int64_t elapsedTimeNs) {
             }
         }
     }
+}
 
-    VLOG("mNextPullTimeNs: %lld updated to %lld", (long long)mNextPullTimeNs,
-         (long long)minNextPullTimeNs);
-    mNextPullTimeNs = minNextPullTimeNs;
-    updateAlarmLocked();
+bool StatsPullerManager::getPullerUidsLocked(const int tagId, const ConfigKey& configKey,
+                                             vector<int32_t>& uids) {
+    const auto& uidProviderIt = mPullUidProviders.find(configKey);
+    if (uidProviderIt == mPullUidProviders.end()) {
+        ALOGE("Error pulling tag %d. No pull uid provider for config key %s", tagId,
+              configKey.ToString().c_str());
+        StatsdStats::getInstance().notePullUidProviderNotFound(tagId);
+        return false;
+    }
+    sp<PullUidProvider> pullUidProvider = uidProviderIt->second.promote();
+    if (pullUidProvider == nullptr) {
+        ALOGE("Error pulling tag %d, pull uid provider for config %s is gone.", tagId,
+              configKey.ToString().c_str());
+        StatsdStats::getInstance().notePullUidProviderNotFound(tagId);
+        return false;
+    }
+    uids = pullUidProvider->getPullAtomUids(tagId);
+    return true;
+}
+
+void StatsPullerManager::initPullerQueue(ThreadSafeQueue<PullerParams>& pullerQueue,
+                                         std::queue<PulledInfo>& pulledData,
+                                         const int64_t elapsedTimeNs, int64_t& minNextPullTimeNs) {
+    for (auto& pair : mReceivers) {
+        vector<ReceiverInfo*> receivers;
+        if (pair.second.size() != 0) {
+            for (ReceiverInfo& receiverInfo : pair.second) {
+                // If pullNecessary and enough time has passed for the next bucket, then add
+                // receiver to the list that will pull on this alarm.
+                // If pullNecessary is false, check if next pull time needs to be updated.
+                sp<PullDataReceiver> receiverPtr = receiverInfo.receiver.promote();
+                if (receiverInfo.nextPullTimeNs <= elapsedTimeNs && receiverPtr != nullptr &&
+                    receiverPtr->isPullNeeded()) {
+                    receivers.push_back(&receiverInfo);
+                } else {
+                    if (receiverInfo.nextPullTimeNs <= elapsedTimeNs) {
+                        receiverPtr->onDataPulled({}, PullResult::PULL_NOT_NEEDED, elapsedTimeNs);
+                        int numBucketsAhead = (elapsedTimeNs - receiverInfo.nextPullTimeNs) /
+                                              receiverInfo.intervalNs;
+                        receiverInfo.nextPullTimeNs +=
+                                (numBucketsAhead + 1) * receiverInfo.intervalNs;
+                    }
+                    minNextPullTimeNs = min(receiverInfo.nextPullTimeNs, minNextPullTimeNs);
+                }
+            }
+            if (receivers.size() > 0) {
+                bool foundPuller = false;
+                int tagId = pair.first.atomTag;
+                vector<int32_t> uids;
+                if (getPullerUidsLocked(tagId, pair.first.configKey, uids)) {
+                    for (int32_t uid : uids) {
+                        PullerKey key = {.uid = uid, .atomTag = tagId};
+                        auto pullerIt = mAllPullAtomInfo.find(key);
+                        if (pullerIt != mAllPullAtomInfo.end()) {
+                            PullerParams params;
+                            params.key = key;
+                            params.puller = pullerIt->second;
+                            params.receivers = std::move(receivers);
+                            pullerQueue.push(params);
+                            foundPuller = true;
+                            break;
+                        }
+                    }
+                    if (!foundPuller) {
+                        StatsdStats::getInstance().notePullerNotFound(tagId);
+                        ALOGW("StatsPullerManager: Unknown tagId %d", tagId);
+                    }
+                }
+                if (!foundPuller) {
+                    PulledInfo pulledInfo;
+                    pulledInfo.pullErrorCode = PullErrorCode::PULL_FAIL;
+                    pulledInfo.receiverInfo = std::move(receivers);
+                    pulledData.push(pulledInfo);
+                }
+            }
+        }
+    }
 }
 
 int StatsPullerManager::ForceClearPullerCache() {
     ATRACE_CALL();
     std::lock_guard<std::mutex> _l(mLock);
     int totalCleared = 0;
-    for (const auto& pulledAtom : kAllPullAtomInfo) {
+    for (const auto& pulledAtom : mAllPullAtomInfo) {
         totalCleared += pulledAtom.second->ForceClearCache();
     }
     return totalCleared;
@@ -310,7 +512,7 @@ int StatsPullerManager::ClearPullerCacheIfNecessary(int64_t timestampNs) {
     ATRACE_CALL();
     std::lock_guard<std::mutex> _l(mLock);
     int totalCleared = 0;
-    for (const auto& pulledAtom : kAllPullAtomInfo) {
+    for (const auto& pulledAtom : mAllPullAtomInfo) {
         totalCleared += pulledAtom.second->ClearCacheIfNecessary(timestampNs);
     }
     return totalCleared;
@@ -335,12 +537,12 @@ void StatsPullerManager::RegisterPullAtomCallback(const int uid, const int32_t a
     sp<StatsCallbackPuller> puller = new StatsCallbackPuller(atomTag, callback, actualCoolDownNs,
                                                              actualTimeoutNs, additiveFields);
     PullerKey key = {.uid = uid, .atomTag = atomTag};
-    auto it = kAllPullAtomInfo.find(key);
-    if (it != kAllPullAtomInfo.end()) {
+    auto it = mAllPullAtomInfo.find(key);
+    if (it != mAllPullAtomInfo.end()) {
         StatsdStats::getInstance().notePullerCallbackRegistrationChanged(atomTag,
                                                                          /*registered=*/false);
     }
-    kAllPullAtomInfo[key] = puller;
+    mAllPullAtomInfo[key] = puller;
     StatsdStats::getInstance().notePullerCallbackRegistrationChanged(atomTag, /*registered=*/true);
 }
 
@@ -348,10 +550,10 @@ void StatsPullerManager::UnregisterPullAtomCallback(const int uid, const int32_t
     ATRACE_CALL();
     std::lock_guard<std::mutex> _l(mLock);
     PullerKey key = {.uid = uid, .atomTag = atomTag};
-    if (kAllPullAtomInfo.find(key) != kAllPullAtomInfo.end()) {
+    if (mAllPullAtomInfo.find(key) != mAllPullAtomInfo.end()) {
         StatsdStats::getInstance().notePullerCallbackRegistrationChanged(atomTag,
                                                                          /*registered=*/false);
-        kAllPullAtomInfo.erase(key);
+        mAllPullAtomInfo.erase(key);
     }
 }
 
diff --git a/statsd/src/external/StatsPullerManager.h b/statsd/src/external/StatsPullerManager.h
index 4d09ffeb..3f0c6228 100644
--- a/statsd/src/external/StatsPullerManager.h
+++ b/statsd/src/external/StatsPullerManager.h
@@ -26,6 +26,7 @@
 #include "PullDataReceiver.h"
 #include "PullUidProvider.h"
 #include "StatsPuller.h"
+#include "ThreadSafeQueue.h"
 #include "guardrail/StatsdStats.h"
 #include "logd/LogEvent.h"
 #include "packages/UidMap.h"
@@ -40,9 +41,9 @@ namespace statsd {
 
 typedef struct PullerKey {
     // The uid of the process that registers this puller.
-    const int uid = -1;
+    int uid = -1;
     // The atom that this puller is for.
-    const int atomTag;
+    int atomTag;
 
     bool operator<(const PullerKey& that) const {
         if (uid < that.uid) {
@@ -57,6 +58,7 @@ typedef struct PullerKey {
     bool operator==(const PullerKey& that) const {
         return uid == that.uid && atomTag == that.atomTag;
     };
+
 } PullerKey;
 
 class StatsPullerManager : public virtual RefBase {
@@ -66,6 +68,34 @@ public:
     virtual ~StatsPullerManager() {
     }
 
+    // A struct containing an atom id and a Config Key
+    typedef struct ReceiverKey {
+        const int atomTag;
+        const ConfigKey configKey;
+
+        inline bool operator<(const ReceiverKey& that) const {
+            return atomTag == that.atomTag ? configKey < that.configKey : atomTag < that.atomTag;
+        }
+    } ReceiverKey;
+
+    typedef struct {
+        int64_t nextPullTimeNs;
+        int64_t intervalNs;
+        wp<PullDataReceiver> receiver;
+    } ReceiverInfo;
+
+    typedef struct {
+        PullerKey key;
+        sp<StatsPuller> puller;
+        vector<ReceiverInfo*> receivers;
+    } PullerParams;
+
+    typedef struct {
+        PullErrorCode pullErrorCode;
+        PullerKey pullerKey;
+        std::vector<ReceiverInfo*> receiverInfo;
+        std::vector<shared_ptr<LogEvent>> data;
+    } PulledInfo;
 
     // Registers a receiver for tagId. It will be pulled on the nextPullTimeNs
     // and then every intervalNs thereafter.
@@ -123,29 +153,13 @@ public:
 
     void UnregisterPullAtomCallback(const int uid, const int32_t atomTag);
 
-    std::map<const PullerKey, sp<StatsPuller>> kAllPullAtomInfo;
+    std::map<const PullerKey, sp<StatsPuller>> mAllPullAtomInfo;
 
 private:
     const static int64_t kMinCoolDownNs = NS_PER_SEC;
     const static int64_t kMaxTimeoutNs = 10 * NS_PER_SEC;
     shared_ptr<IStatsCompanionService> mStatsCompanionService = nullptr;
 
-    // A struct containing an atom id and a Config Key
-    typedef struct ReceiverKey {
-        const int atomTag;
-        const ConfigKey configKey;
-
-        inline bool operator<(const ReceiverKey& that) const {
-            return atomTag == that.atomTag ? configKey < that.configKey : atomTag < that.atomTag;
-        }
-    } ReceiverKey;
-
-    typedef struct {
-        int64_t nextPullTimeNs;
-        int64_t intervalNs;
-        wp<PullDataReceiver> receiver;
-    } ReceiverInfo;
-
     // mapping from Receiver Key to receivers
     std::map<ReceiverKey, std::list<ReceiverInfo>> mReceivers;
 
@@ -158,6 +172,14 @@ private:
     bool PullLocked(int tagId, const vector<int32_t>& uids, int64_t eventTimeNs,
                     vector<std::shared_ptr<LogEvent>>* data);
 
+    bool getPullerUidsLocked(const int tagId, const ConfigKey& configKey, vector<int32_t>& uids);
+
+    void initPullerQueue(ThreadSafeQueue<PullerParams>& pullerQueue,
+                         std::queue<PulledInfo>& pulledData, int64_t elapsedTimeNs,
+                         int64_t& minNextPullTimeNs);
+
+    void onAlarmFiredSynchronous(const int64_t elapsedTimeNs, const int64_t wallClockNs,
+                                 int64_t& minNextPullTimeNs);
     // locks for data receiver and StatsCompanionService changes
     std::mutex mLock;
 
@@ -171,6 +193,7 @@ private:
     FRIEND_TEST(GaugeMetricE2ePulledTest, TestRandomSamplePulledEvent_LateAlarm);
     FRIEND_TEST(GaugeMetricE2ePulledTest, TestRandomSamplePulledEventsWithActivation);
     FRIEND_TEST(GaugeMetricE2ePulledTest, TestRandomSamplePulledEventsNoCondition);
+    FRIEND_TEST(GaugeMetricE2ePulledTest, TestSliceByStates);
     FRIEND_TEST(ValueMetricE2eTest, TestPulledEvents);
     FRIEND_TEST(ValueMetricE2eTest, TestPulledEvents_LateAlarm);
     FRIEND_TEST(ValueMetricE2eTest, TestPulledEvents_WithActivation);
diff --git a/statsd/src/external/ThreadSafeQueue.h b/statsd/src/external/ThreadSafeQueue.h
new file mode 100644
index 00000000..de578c28
--- /dev/null
+++ b/statsd/src/external/ThreadSafeQueue.h
@@ -0,0 +1,55 @@
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
+#pragma once
+
+#include <mutex>
+#include <queue>
+
+namespace android {
+namespace os {
+namespace statsd {
+
+template <typename T>
+class ThreadSafeQueue {
+public:
+    std::optional<T> pop() {
+        std::unique_lock<std::mutex> lock(mMutex);
+        if (mQueue.empty()) {
+            return std::nullopt;
+        }
+        T value = std::move(mQueue.front());
+        mQueue.pop();
+        return value;
+    }
+
+    void push(const T value) {
+        std::unique_lock<std::mutex> lock(mMutex);
+        mQueue.push(value);
+    }
+
+    bool empty() const {
+        std::unique_lock<std::mutex> lock(mMutex);
+        return mQueue.empty();
+    }
+
+private:
+    mutable std::mutex mMutex;
+    std::queue<T> mQueue;
+};
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/guardrail/LoggingRate.cpp b/statsd/src/guardrail/LoggingRate.cpp
new file mode 100644
index 00000000..8d205e65
--- /dev/null
+++ b/statsd/src/guardrail/LoggingRate.cpp
@@ -0,0 +1,93 @@
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
+#define STATSD_DEBUG false  // STOPSHIP if true
+
+#include "Log.h"
+
+#include "LoggingRate.h"
+
+#include <algorithm>
+
+using namespace std;
+
+namespace android {
+namespace os {
+namespace statsd {
+
+LoggingRate::LoggingRate(int maxStatsNum, int64_t logFrequencyWindowNs)
+    : mMaxRateInfoSize(maxStatsNum), mLogFrequencyWindowNs(logFrequencyWindowNs) {
+}
+
+void LoggingRate::noteLogEvent(uint32_t atomId, int64_t eventTimestampNs) {
+    auto rateInfoIt = mRateInfo.find(atomId);
+
+    if (rateInfoIt != mRateInfo.end()) {
+        RateInfo& rateInfo = rateInfoIt->second;
+        if (eventTimestampNs - rateInfo.intervalStartNs >= mLogFrequencyWindowNs) {
+            rateInfo.intervalStartNs = eventTimestampNs;
+            rateInfo.rate = 1;
+        } else {
+            // update rateInfo
+            rateInfo.rate++;
+#ifdef STATSD_DEBUG
+            if (rateInfo.maxRate < rateInfo.rate) {
+                VLOG("For Atom %d new maxRate is %d", atomId, rateInfo.rate);
+            }
+#endif
+            rateInfo.maxRate = max(rateInfo.maxRate, rateInfo.rate);
+        }
+    } else if (mRateInfo.size() < mMaxRateInfoSize) {
+        // atomId not found, add it to the map with initial frequency
+        mRateInfo[atomId] = {eventTimestampNs, 1, 1};
+    }
+}
+
+int32_t LoggingRate::getMaxRate(uint32_t atomId) const {
+    const auto rateInfoIt = mRateInfo.find(atomId);
+    if (rateInfoIt != mRateInfo.end()) {
+        return rateInfoIt->second.maxRate;
+    }
+    return 0;
+}
+
+std::vector<LoggingRate::PeakRatePerAtomId> LoggingRate::getMaxRates(size_t topN) const {
+    std::vector<PeakRatePerAtomId> result;
+    result.reserve(mRateInfo.size());
+
+    for (auto& [atomId, rateInfo] : mRateInfo) {
+        result.emplace_back(atomId, rateInfo.maxRate);
+    }
+
+    std::sort(result.begin(), result.end(),
+              [](const PeakRatePerAtomId& a, const PeakRatePerAtomId& b) {
+                  return a.second > b.second;
+              });
+
+    if (topN < result.size()) {
+        result.erase(result.begin() + topN, result.end());
+    }
+
+    return result;
+}
+
+void LoggingRate::reset() {
+    mRateInfo.clear();
+}
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/guardrail/LoggingRate.h b/statsd/src/guardrail/LoggingRate.h
new file mode 100644
index 00000000..7c582849
--- /dev/null
+++ b/statsd/src/guardrail/LoggingRate.h
@@ -0,0 +1,65 @@
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
+#pragma once
+
+#include <gtest/gtest_prod.h>
+#include <stdint.h>
+
+#include <unordered_map>
+#include <vector>
+
+namespace android {
+namespace os {
+namespace statsd {
+
+/**
+ * @brief This class tracks the logging rate for each atom id.
+ *        The rate is calculated as a fixed time window counter
+ */
+class LoggingRate {
+public:
+    LoggingRate(int maxStatsNum, int64_t logFrequencyWindowNs);
+
+    void noteLogEvent(uint32_t atomId, int64_t eventTimestampNs);
+
+    // returns max logging rate recorded for atomId if available, 0 otherwise
+    int32_t getMaxRate(uint32_t atomId) const;
+
+    using PeakRatePerAtomId = std::pair<int32_t, int32_t>;
+
+    std::vector<PeakRatePerAtomId> getMaxRates(size_t topN) const;
+
+    void reset();
+
+private:
+    struct RateInfo {
+        int64_t intervalStartNs;
+        int32_t rate;
+        int32_t maxRate;
+    };
+
+    const size_t mMaxRateInfoSize;
+    const int64_t mLogFrequencyWindowNs;
+
+    std::unordered_map<uint32_t, RateInfo> mRateInfo;
+
+    FRIEND_TEST(StatsdStatsTest, TestLoggingRateReportReset);
+};
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/guardrail/StatsdStats.cpp b/statsd/src/guardrail/StatsdStats.cpp
index c08d9311..5ebfa8c3 100644
--- a/statsd/src/guardrail/StatsdStats.cpp
+++ b/statsd/src/guardrail/StatsdStats.cpp
@@ -19,6 +19,7 @@
 #include "StatsdStats.h"
 
 #include <android/util/ProtoOutputStream.h>
+#include <com_android_os_statsd_flags.h>
 
 #include "../stats_log_util.h"
 #include "shell/ShellSubscriber.h"
@@ -30,6 +31,8 @@ namespace android {
 namespace os {
 namespace statsd {
 
+namespace flags = com::android::os::statsd::flags;
+
 using android::util::FIELD_COUNT_REPEATED;
 using android::util::FIELD_TYPE_BOOL;
 using android::util::FIELD_TYPE_ENUM;
@@ -64,6 +67,8 @@ const int FIELD_ID_SUBSCRIPTION_STATS = 23;
 const int FIELD_ID_SOCKET_LOSS_STATS = 24;
 const int FIELD_ID_QUEUE_STATS = 25;
 const int FIELD_ID_SOCKET_READ_STATS = 26;
+const int FIELD_ID_ERROR_STATS = 27;
+const int FIELD_ID_PEAK_LOGGING_RATES = 28;
 
 const int FIELD_ID_RESTRICTED_METRIC_QUERY_STATS_CALLING_UID = 1;
 const int FIELD_ID_RESTRICTED_METRIC_QUERY_STATS_CONFIG_ID = 2;
@@ -80,6 +85,7 @@ const int FIELD_ID_ATOM_STATS_COUNT = 2;
 const int FIELD_ID_ATOM_STATS_ERROR_COUNT = 3;
 const int FIELD_ID_ATOM_STATS_DROPS_COUNT = 4;
 const int FIELD_ID_ATOM_STATS_SKIP_COUNT = 5;
+const int FIELD_ID_ATOM_STATS_PEAK_RATE = 6;
 
 const int FIELD_ID_ANOMALY_ALARMS_REGISTERED = 1;
 const int FIELD_ID_PERIODIC_ALARMS_REGISTERED = 1;
@@ -218,14 +224,26 @@ const int FIELD_ID_LARGE_BATCH_SOCKET_READ_ATOM_STATS = 6;
 const int FIELD_ID_LARGE_BATCH_SOCKET_READ_ATOM_STATS_ATOM_ID = 1;
 const int FIELD_ID_LARGE_BATCH_SOCKET_READ_ATOM_STATS_COUNT = 2;
 
+// ErrorStats
+const int FIELD_ID_ERROR_STATS_COUNTERS = 1;
+
+// CounterStats counters
+const int FIELD_ID_COUNTER_STATS_COUNTER_TYPE = 1;
+const int FIELD_ID_COUNTER_STATS_COUNT = 2;
+
 const std::map<int, std::pair<size_t, size_t>> StatsdStats::kAtomDimensionKeySizeLimitMap = {
         {util::BINDER_CALLS, {6000, 10000}},
         {util::LOOPER_STATS, {1500, 2500}},
         {util::CPU_TIME_PER_UID_FREQ, {6000, 10000}},
 };
 
+constexpr int64_t kLogFrequencyWindowNs = 100 * 1'000'000;  // 100ms
+constexpr size_t kTopNPeakRatesToReport = 50;
+
 StatsdStats::StatsdStats()
-    : mStatsdStatsId(rand()), mSocketBatchReadHistogram(kNumBinsInSocketBatchReadHistogram) {
+    : mStatsdStatsId(rand()),
+      mLoggingRateStats(kMaxPushedAtomId + kMaxNonPlatformPushedAtoms, kLogFrequencyWindowNs),
+      mSocketBatchReadHistogram(kNumBinsInSocketBatchReadHistogram) {
     mPushedAtomStats.resize(kMaxPushedAtomId + 1);
     mStartTimeSec = getWallClockSec();
 }
@@ -408,8 +426,7 @@ void StatsdStats::noteDataDropped(const ConfigKey& key, const size_t totalBytes)
     noteDataDropped(key, totalBytes, getWallClockSec());
 }
 
-void StatsdStats::noteEventQueueOverflow(int64_t oldestEventTimestampNs, int32_t atomId,
-                                         bool isSkipped) {
+void StatsdStats::noteEventQueueOverflow(int64_t oldestEventTimestampNs, int32_t atomId) {
     lock_guard<std::mutex> lock(mLock);
 
     mOverflowCount++;
@@ -424,7 +441,6 @@ void StatsdStats::noteEventQueueOverflow(int64_t oldestEventTimestampNs, int32_t
         mMinQueueHistoryNs = history;
     }
 
-    noteAtomLoggedLocked(atomId, isSkipped);
     noteAtomDroppedLocked(atomId);
 }
 
@@ -747,19 +763,20 @@ void StatsdStats::notePullExceedMaxDelay(int pullAtomId) {
     mPulledAtomStats[pullAtomId].pullExceedMaxDelay++;
 }
 
-void StatsdStats::noteAtomLogged(int atomId, int32_t /*timeSec*/, bool isSkipped) {
+void StatsdStats::noteAtomLogged(int atomId, int64_t eventTimestampNs, bool isSkipped) {
     lock_guard<std::mutex> lock(mLock);
 
-    noteAtomLoggedLocked(atomId, isSkipped);
+    noteAtomLoggedLocked(atomId, eventTimestampNs, isSkipped);
 }
 
-void StatsdStats::noteAtomLoggedLocked(int atomId, bool isSkipped) {
+void StatsdStats::noteAtomLoggedLocked(int atomId, int64_t eventTimestampNs, bool isSkipped) {
     if (atomId >= 0 && atomId <= kMaxPushedAtomId) {
         mPushedAtomStats[atomId].logCount++;
         mPushedAtomStats[atomId].skipCount += isSkipped;
     } else {
         if (atomId < 0) {
             android_errorWriteLog(0x534e4554, "187957589");
+            return;
         }
         if (mNonPlatformPushedAtomStats.size() < kMaxNonPlatformPushedAtoms ||
             mNonPlatformPushedAtomStats.find(atomId) != mNonPlatformPushedAtomStats.end()) {
@@ -767,6 +784,10 @@ void StatsdStats::noteAtomLoggedLocked(int atomId, bool isSkipped) {
             mNonPlatformPushedAtomStats[atomId].skipCount += isSkipped;
         }
     }
+
+    if (flags::enable_logging_rate_stats_collection()) {
+        mLoggingRateStats.noteLogEvent(atomId, eventTimestampNs);
+    }
 }
 
 void StatsdStats::noteSystemServerRestart(int32_t timeSec) {
@@ -880,6 +901,11 @@ void StatsdStats::noteAtomError(int atomTag, bool pull) {
     }
 }
 
+void StatsdStats::noteIllegalState(CounterType counter) {
+    lock_guard<std::mutex> lock(mLock);
+    mErrorStats[counter]++;
+}
+
 bool StatsdStats::hasHitDimensionGuardrail(int64_t metricId) const {
     lock_guard<std::mutex> lock(mLock);
     auto atomMetricStatsIter = mAtomMetricStats.find(metricId);
@@ -1113,7 +1139,7 @@ void StatsdStats::resetInternalLocked() {
     mSystemServerRestartSec.clear();
     mLogLossStats.clear();
     mOverflowCount = 0;
-    mMinQueueHistoryNs = kInt64Max;
+    mMinQueueHistoryNs = std::numeric_limits<int64_t>::max();
     mMaxQueueHistoryNs = 0;
     mEventQueueMaxSizeObserved = 0;
     mEventQueueMaxSizeObservedElapsedNanos = 0;
@@ -1187,6 +1213,9 @@ void StatsdStats::resetInternalLocked() {
             ++it;
         }
     }
+
+    mErrorStats.clear();
+    mLoggingRateStats.reset();
 }
 
 string buildTimeString(int64_t timeSec) {
@@ -1215,6 +1244,10 @@ int StatsdStats::getPushedAtomDropsLocked(int atomId) const {
     }
 }
 
+int StatsdStats::getLoggingRateLocked(int atomId) const {
+    return mLoggingRateStats.getMaxRate(atomId);
+}
+
 bool StatsdStats::hasRestrictedConfigErrors(const std::shared_ptr<ConfigStats>& configStats) const {
     return configStats->device_info_table_creation_failed || configStats->db_corrupted_count ||
            configStats->db_deletion_size_exceeded_limit || configStats->db_deletion_stat_failed ||
@@ -1431,15 +1464,20 @@ void StatsdStats::dumpStats(int out) const {
     for (size_t i = 2; i < atomCounts; i++) {
         if (mPushedAtomStats[i].logCount > 0) {
             dprintf(out,
-                    "Atom %zu->(total count)%d, (error count)%d, (drop count)%d, (skip count)%d\n",
-                    i, mPushedAtomStats[i].logCount, getPushedAtomErrorsLocked((int)i),
-                    getPushedAtomDropsLocked((int)i), mPushedAtomStats[i].skipCount);
+                    "Atom %d->(total count)%d, (error count)%d, (drop count)%d, (skip count)%d "
+                    "(peak rate)%d \n",
+                    (int)i, mPushedAtomStats[i].logCount, getPushedAtomErrorsLocked((int)i),
+                    getPushedAtomDropsLocked((int)i), mPushedAtomStats[i].skipCount,
+                    getLoggingRateLocked((int)i));
         }
     }
     for (const auto& pair : mNonPlatformPushedAtomStats) {
-        dprintf(out, "Atom %d->(total count)%d, (error count)%d, (drop count)%d, (skip count)%d\n",
+        dprintf(out,
+                "Atom %d->(total count)%d, (error count)%d, (drop count)%d, (skip count)%d "
+                "(peak rate)%d \n",
                 pair.first, pair.second.logCount, getPushedAtomErrorsLocked(pair.first),
-                getPushedAtomDropsLocked((int)pair.first), pair.second.skipCount);
+                getPushedAtomDropsLocked(pair.first), pair.second.skipCount,
+                getLoggingRateLocked(pair.first));
     }
 
     dprintf(out, "********Pulled Atom stats***********\n");
@@ -1619,6 +1657,12 @@ void StatsdStats::dumpStats(int out) const {
             }
         }
     }
+    dprintf(out, "********ErrorStats***********\n");
+    for (const auto& [errorType, count] : mErrorStats) {
+        // TODO(b/343464656): add enum toString helper API
+        dprintf(out, "IllegalState type %d: count=%d\n", errorType, count);
+    }
+    dprintf(out, "\n");
     dprintf(out, "********Statsd Stats Id***********\n");
     dprintf(out, "Statsd Stats Id %d\n", mStatsdStatsId);
     dprintf(out, "********Shard Offset Provider stats***********\n");
@@ -1626,6 +1670,26 @@ void StatsdStats::dumpStats(int out) const {
     dprintf(out, "\n");
 }
 
+void addErrorStatsToProto(const std::map<CounterType, int32_t>& stats, ProtoOutputStream* proto) {
+    if (stats.empty()) {
+        return;
+    }
+
+    uint64_t token = proto->start(FIELD_TYPE_MESSAGE | FIELD_ID_ERROR_STATS);
+
+    for (auto& [type, count] : stats) {
+        uint64_t tmpToken = proto->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED |
+                                         FIELD_ID_ERROR_STATS_COUNTERS);
+
+        proto->write(FIELD_TYPE_INT32 | FIELD_ID_COUNTER_STATS_COUNTER_TYPE, type);
+        proto->write(FIELD_TYPE_INT32 | FIELD_ID_COUNTER_STATS_COUNT, count);
+
+        proto->end(tmpToken);
+    }
+
+    proto->end(token);
+}
+
 void addConfigStatsToProto(const ConfigStats& configStats, ProtoOutputStream* proto) {
     uint64_t token =
             proto->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | FIELD_ID_CONFIG_STATS);
@@ -1850,6 +1914,12 @@ void StatsdStats::dumpStats(vector<uint8_t>* output, bool reset) {
         addConfigStatsToProto(*(pair.second), &proto);
     }
 
+    std::unordered_map<int32_t, int32_t> atomsLoggingPeakRates;
+    if (flags::enable_logging_rate_stats_collection()) {
+        auto result = mLoggingRateStats.getMaxRates(kTopNPeakRatesToReport);
+        atomsLoggingPeakRates = std::unordered_map<int32_t, int32_t>(result.begin(), result.end());
+    }
+
     const size_t atomCounts = mPushedAtomStats.size();
     for (size_t i = 2; i < atomCounts; i++) {
         if (mPushedAtomStats[i].logCount > 0) {
@@ -1865,6 +1935,13 @@ void StatsdStats::dumpStats(vector<uint8_t>* output, bool reset) {
                                      &proto);
             writeNonZeroStatToStream(FIELD_TYPE_INT32 | FIELD_ID_ATOM_STATS_SKIP_COUNT,
                                      mPushedAtomStats[i].skipCount, &proto);
+            if (flags::enable_logging_rate_stats_collection()) {
+                auto peakRateIt = atomsLoggingPeakRates.find((int32_t)i);
+                if (peakRateIt != atomsLoggingPeakRates.end()) {
+                    writeNonZeroStatToStream(FIELD_TYPE_INT32 | FIELD_ID_ATOM_STATS_PEAK_RATE,
+                                             peakRateIt->second, &proto);
+                }
+            }
             proto.end(token);
         }
     }
@@ -1881,6 +1958,13 @@ void StatsdStats::dumpStats(vector<uint8_t>* output, bool reset) {
         writeNonZeroStatToStream(FIELD_TYPE_INT32 | FIELD_ID_ATOM_STATS_DROPS_COUNT, drops, &proto);
         writeNonZeroStatToStream(FIELD_TYPE_INT32 | FIELD_ID_ATOM_STATS_SKIP_COUNT,
                                  pair.second.skipCount, &proto);
+        if (flags::enable_logging_rate_stats_collection()) {
+            auto peakRateIt = atomsLoggingPeakRates.find(pair.first);
+            if (peakRateIt != atomsLoggingPeakRates.end()) {
+                writeNonZeroStatToStream(FIELD_TYPE_INT32 | FIELD_ID_ATOM_STATS_PEAK_RATE,
+                                         peakRateIt->second, &proto);
+            }
+        }
         proto.end(token);
     }
 
@@ -2102,6 +2186,8 @@ void StatsdStats::dumpStats(vector<uint8_t>* output, bool reset) {
     }
     proto.end(socketReadStatsToken);
 
+    addErrorStatsToProto(mErrorStats, &proto);
+
     output->clear();
     proto.serializeToVector(output);
 
diff --git a/statsd/src/guardrail/StatsdStats.h b/statsd/src/guardrail/StatsdStats.h
index c2e8c38e..57c58e77 100644
--- a/statsd/src/guardrail/StatsdStats.h
+++ b/statsd/src/guardrail/StatsdStats.h
@@ -19,12 +19,14 @@
 #include <log/log_time.h>
 #include <src/guardrail/stats_log_enums.pb.h>
 
+#include <limits>
 #include <list>
 #include <mutex>
 #include <string>
 #include <unordered_map>
 #include <vector>
 
+#include "LoggingRate.h"
 #include "config/ConfigKey.h"
 #include "logd/logevent_util.h"
 
@@ -115,7 +117,7 @@ struct ConfigStats {
     std::list<DumpReportStats> dump_report_stats;
 
     // Stores how many times a matcher have been matched. The map size is capped by kMaxConfigCount.
-    std::map<const int64_t, int> matcher_stats;
+    std::unordered_map<int64_t, int> matcher_stats;
 
     // Stores the number of output tuple of condition trackers when it's bigger than
     // kDimensionKeySizeSoftLimit. When you see the number is kDimensionKeySizeHardLimit +1,
@@ -286,13 +288,13 @@ public:
 
     // Maximum atom id value that we consider a platform pushed atom.
     // This should be updated once highest pushed atom id in atoms.proto approaches this value.
-    static const int kMaxPushedAtomId = 1500;
+    static const int32_t kMaxPushedAtomId = 1500;
 
     // Atom id that is the start of the pulled atoms.
-    static const int kPullAtomStartTag = 10000;
+    static const int32_t kPullAtomStartTag = 10000;
 
     // Atom id that is the start of vendor atoms.
-    static const int kVendorAtomStartTag = 100000;
+    static const int32_t kVendorAtomStartTag = 100000;
 
     // Vendor pulled atom start id.
     static const int32_t kVendorPulledAtomStartTag = 150000;
@@ -306,8 +308,6 @@ public:
     // Max accepted atom id.
     static const int32_t kMaxAtomTag = 200000;
 
-    static const int64_t kInt64Max = 0x7fffffffffffffffLL;
-
     static const int32_t kMaxLoggedBucketDropEvents = 10;
 
     static const int32_t kNumBinsInSocketBatchReadHistogram = 30;
@@ -315,6 +315,8 @@ public:
     static const int32_t kMaxLargeBatchReadSize = 20;
     static const int32_t kMaxLargeBatchReadAtomThreshold = 50;
 
+    static const int32_t kMaxLoggingRateStatsToReport = 50;
+
     /**
      * Report a new config has been received and report the static stats about the config.
      *
@@ -459,7 +461,7 @@ public:
     /**
      * Report an atom event has been logged.
      */
-    void noteAtomLogged(int atomId, int32_t timeSec, bool isSkipped);
+    void noteAtomLogged(int atomId, int64_t eventTimestampNs, bool isSkipped);
 
     /**
      * Report that statsd modified the anomaly alarm registered with StatsCompanionService.
@@ -630,8 +632,10 @@ public:
     void noteBucketUnknownCondition(int64_t metricId);
 
     /* Reports one event id has been dropped due to queue overflow, and the oldest event timestamp
-     * in the queue */
-    void noteEventQueueOverflow(int64_t oldestEventTimestampNs, int32_t atomId, bool isSkipped);
+     * in the queue. There is an expectation that noteAtomLogged() is called for the same
+     * atomId
+     */
+    void noteEventQueueOverflow(int64_t oldestEventTimestampNs, int32_t atomId);
 
     /* Notes queue max size seen so far and associated timestamp */
     void noteEventQueueSize(int32_t size, int64_t eventTimestampNs);
@@ -652,6 +656,11 @@ public:
      */
     void noteAtomError(int atomTag, bool pull = false);
 
+    /**
+     * Increases counter associated with a CounterType.
+     */
+    void noteIllegalState(CounterType error);
+
     /** Report query of restricted metric succeed **/
     void noteQueryRestrictedMetricSucceed(const int64_t configId, const string& configPackage,
                                           const std::optional<int32_t> configUid,
@@ -878,6 +887,9 @@ private:
     // Maps PullAtomId to its stats. The size is capped by the puller atom counts.
     std::map<int, PulledAtomStats> mPulledAtomStats;
 
+    // Tracks counter associated with CounterType to represent errors. Max capacity == CounterType
+    std::map<CounterType, int32_t> mErrorStats;
+
     // Stores the number of times a pushed atom was logged erroneously. The
     // corresponding counts for pulled atoms are stored in PulledAtomStats.
     // The max size of this map is kMaxPushedAtomErrorStatsSize.
@@ -946,7 +958,7 @@ private:
 
     // Min of {(now - oldestEventTimestamp) when overflow happens}.
     // This number is helpful to understand how FAST the events floods to statsd.
-    int64_t mMinQueueHistoryNs = kInt64Max;
+    int64_t mMinQueueHistoryNs = std::numeric_limits<int64_t>::max();
 
     // Total number of events that are lost due to queue overflow.
     int32_t mOverflowCount = 0;
@@ -960,6 +972,8 @@ private:
     // Timestamps when we detect log loss, and the number of logs lost.
     std::list<LogLossStats> mLogLossStats;
 
+    LoggingRate mLoggingRateStats;
+
     std::list<int32_t> mSystemServerRestartSec;
 
     std::vector<int64_t> mSocketBatchReadHistogram;
@@ -1043,7 +1057,7 @@ private:
 
     void resetInternalLocked();
 
-    void noteAtomLoggedLocked(int atomId, bool isSkipped);
+    void noteAtomLoggedLocked(int atomId, int64_t eventTimestampNs, bool isSkipped);
 
     void noteAtomDroppedLocked(int atomId);
 
@@ -1064,6 +1078,8 @@ private:
 
     int getPushedAtomDropsLocked(int atomId) const;
 
+    int getLoggingRateLocked(int atomId) const;
+
     bool hasRestrictedConfigErrors(const std::shared_ptr<ConfigStats>& configStats) const;
 
     /**
@@ -1075,6 +1091,9 @@ private:
     FRIEND_TEST(LogEventQueue_test, TestQueueMaxSize);
     FRIEND_TEST(SocketParseMessageTest, TestProcessMessage);
     FRIEND_TEST(StatsLogProcessorTest, InvalidConfigRemoved);
+    FRIEND_TEST(StatsPullerManagerTest, TestOnAlarmFiredNoPullerForUidNotesPullerNotFound);
+    FRIEND_TEST(StatsPullerManagerTest, TestOnAlarmFiredNoUidProviderUpdatesNextPullTime);
+    FRIEND_TEST(StatsPullerManagerTest, TestOnAlarmFiredUidsNotRegisteredInPullAtomCallback);
     FRIEND_TEST(StatsdStatsTest, TestActivationBroadcastGuardrailHit);
     FRIEND_TEST(StatsdStatsTest, TestAnomalyMonitor);
     FRIEND_TEST(StatsdStatsTest, TestAtomDroppedStats);
@@ -1110,6 +1129,11 @@ private:
     FRIEND_TEST(StatsdStatsTest, TestTimestampThreshold);
     FRIEND_TEST(StatsdStatsTest, TestValidConfigAdd);
     FRIEND_TEST(StatsdStatsTest, TestSocketBatchReadStats);
+    FRIEND_TEST(StatsdStatsTest, TestErrorStatsReport);
+    FRIEND_TEST(StatsdStatsTest, TestErrorStatsReportReset);
+    FRIEND_TEST(StatsdStatsTest, TestLoggingRateReport);
+    FRIEND_TEST(StatsdStatsTest, TestLoggingRateReportOnlyTopN);
+    FRIEND_TEST(StatsdStatsTest, TestLoggingRateReportReset);
 };
 
 InvalidConfigReason createInvalidConfigReasonWithMatcher(const InvalidConfigReasonEnum reason,
diff --git a/statsd/src/guardrail/stats_log_enums.proto b/statsd/src/guardrail/stats_log_enums.proto
index 0e243d51..2019c277 100644
--- a/statsd/src/guardrail/stats_log_enums.proto
+++ b/statsd/src/guardrail/stats_log_enums.proto
@@ -99,7 +99,7 @@ enum InvalidConfigReasonEnum {
     INVALID_CONFIG_REASON_KLL_METRIC_MISSING_KLL_FIELD = 41;
     INVALID_CONFIG_REASON_KLL_METRIC_KLL_FIELD_HAS_POSITION_ALL = 42;
     INVALID_CONFIG_REASON_KLL_METRIC_HAS_INCORRECT_KLL_FIELD = 43;
-    INVALID_CONFIG_REASON_GAUGE_METRIC_INCORRECT_FIELD_FILTER = 44;
+    INVALID_CONFIG_REASON_METRIC_INCORRECT_FIELD_FILTER = 44;
     INVALID_CONFIG_REASON_GAUGE_METRIC_TRIGGER_NO_PULL_ATOM = 45;
     INVALID_CONFIG_REASON_GAUGE_METRIC_TRIGGER_NO_FIRST_N_SAMPLES = 46;
     INVALID_CONFIG_REASON_GAUGE_METRIC_FIRST_N_SAMPLES_WITH_WRONG_EVENT = 47 [deprecated = true];
@@ -178,3 +178,8 @@ enum InvalidQueryReason {
     INCONSISTENT_ROW_SIZE = 7;
     NULL_CALLBACK = 8;
 };
+
+enum CounterType {
+    COUNTER_TYPE_UNKNOWN = 0;
+    COUNTER_TYPE_ERROR_ATOM_FILTER_SKIPPED = 1;
+};
diff --git a/statsd/src/logd/LogEvent.h b/statsd/src/logd/LogEvent.h
index db2bc4e1..96d81e27 100644
--- a/statsd/src/logd/LogEvent.h
+++ b/statsd/src/logd/LogEvent.h
@@ -347,7 +347,7 @@ private:
         // only decorate last position for depths with repeated fields (depth 1)
         if (depth > 0 && last[1]) f.decorateLastPos(1);
 
-        Value v = Value(value);
+        Value v(value);
         mValues.push_back(FieldValue(f, v));
     }
 
diff --git a/statsd/src/matchers/EventMatcherWizard.cpp b/statsd/src/matchers/EventMatcherWizard.cpp
index 07f6f4cd..602196aa 100644
--- a/statsd/src/matchers/EventMatcherWizard.cpp
+++ b/statsd/src/matchers/EventMatcherWizard.cpp
@@ -24,11 +24,16 @@ MatchLogEventResult EventMatcherWizard::matchLogEvent(const LogEvent& event, int
         return {MatchingState::kNotComputed, nullptr};
     }
     std::fill(mMatcherCache.begin(), mMatcherCache.end(), MatchingState::kNotComputed);
-    std::fill(mMatcherTransformations.begin(), mMatcherTransformations.end(), nullptr);
+    // There is only one input of LogEvent - there is only one transformation instance
+    // will be produced at a time. Also there is no full support for CombinationAtomMatchingTracker
+    // transformations - see INVALID_CONFIG_REASON_MATCHER_COMBINATION_WITH_STRING_REPLACE
+    mMatcherTransformations[matcherIndex].reset();
     mAllEventMatchers[matcherIndex]->onLogEvent(event, matcherIndex, mAllEventMatchers,
                                                 mMatcherCache, mMatcherTransformations);
 
-    return {mMatcherCache[matcherIndex], mMatcherTransformations[matcherIndex]};
+    MatchLogEventResult result = {mMatcherCache[matcherIndex],
+                                  std::move(mMatcherTransformations[matcherIndex])};
+    return result;
 }
 
 }  // namespace statsd
diff --git a/statsd/src/metrics/EventMetricProducer.cpp b/statsd/src/metrics/EventMetricProducer.cpp
index b3540f28..beb52362 100644
--- a/statsd/src/metrics/EventMetricProducer.cpp
+++ b/statsd/src/metrics/EventMetricProducer.cpp
@@ -58,6 +58,10 @@ const int FIELD_ID_AGGREGATED_ATOM = 4;
 // for AggregatedAtomInfo
 const int FIELD_ID_ATOM = 1;
 const int FIELD_ID_ATOM_TIMESTAMPS = 2;
+const int FIELD_ID_AGGREGATED_STATE = 3;
+// for AggregatedStateInfo
+const int FIELD_ID_SLICE_BY_STATE = 1;
+const int FIELD_ID_STATE_TIMESTAMPS = 2;
 
 EventMetricProducer::EventMetricProducer(
         const ConfigKey& key, const EventMetric& metric, const int conditionIndex,
@@ -71,7 +75,9 @@ EventMetricProducer::EventMetricProducer(
     : MetricProducer(metric.id(), key, startTimeNs, conditionIndex, initialConditionCache, wizard,
                      protoHash, eventActivationMap, eventDeactivationMap, slicedStateAtoms,
                      stateGroupMap, /*splitBucketForAppUpgrade=*/nullopt, configMetadataProvider),
-      mSamplingPercentage(metric.sampling_percentage()) {
+      mSamplingPercentage(metric.sampling_percentage()),
+      mFieldMatchers(translateFieldsFilter(metric.fields_filter())),
+      mOmitFields(metric.fields_filter().has_omit_fields()) {
     if (metric.links().size() > 0) {
         for (const auto& link : metric.links()) {
             Metric2Condition mc;
@@ -83,6 +89,14 @@ EventMetricProducer::EventMetricProducer(
         mConditionSliced = true;
     }
 
+    for (const auto& stateLink : metric.state_link()) {
+        Metric2State ms;
+        ms.stateAtomId = stateLink.state_atom_id();
+        translateFieldMatcher(stateLink.fields_in_what(), &ms.metricFields);
+        translateFieldMatcher(stateLink.fields_in_state(), &ms.stateFields);
+        mMetric2StateLinks.push_back(ms);
+    }
+
     VLOG("metric %lld created. bucket size %lld start_time: %lld", (long long)mMetricId,
          (long long)mBucketSizeNs, (long long)mTimeBaseNs);
 }
@@ -138,6 +152,7 @@ optional<InvalidConfigReason> EventMetricProducer::onConfigUpdatedLocked(
 
 void EventMetricProducer::dropDataLocked(const int64_t dropTimeNs) {
     mAggregatedAtoms.clear();
+    mAggAtomsAndStates.clear();
     resetDataCorruptionFlagsLocked();
     mTotalDataSize = 0;
     StatsdStats::getInstance().noteBucketDropped(mMetricId);
@@ -166,6 +181,7 @@ std::unique_ptr<std::vector<uint8_t>> serializeProtoLocked(ProtoOutputStream& pr
 
 void EventMetricProducer::clearPastBucketsLocked(const int64_t dumpTimeNs) {
     mAggregatedAtoms.clear();
+    mAggAtomsAndStates.clear();
     resetDataCorruptionFlagsLocked();
     mTotalDataSize = 0;
 }
@@ -181,11 +197,13 @@ void EventMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
     writeDataCorruptedReasons(*protoOutput, FIELD_ID_DATA_CORRUPTED_REASON,
                               mDataCorruptedDueToQueueOverflow != DataCorruptionSeverity::kNone,
                               mDataCorruptedDueToSocketLoss != DataCorruptionSeverity::kNone);
-    if (!mAggregatedAtoms.empty()) {
+    if (!mAggregatedAtoms.empty() || !mAggAtomsAndStates.empty()) {
         protoOutput->write(FIELD_TYPE_INT64 | FIELD_ID_ESTIMATED_MEMORY_BYTES,
                            (long long)byteSizeLocked());
     }
     uint64_t protoToken = protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_EVENT_METRICS);
+    // mAggregatedAtoms used for non-state metrics.
+    // mAggregatedAtoms will be empty if states are used.
     for (const auto& [atomDimensionKey, elapsedTimestampsNs] : mAggregatedAtoms) {
         uint64_t wrapperToken =
                 protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | FIELD_ID_DATA);
@@ -205,10 +223,44 @@ void EventMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
         protoOutput->end(aggregatedToken);
         protoOutput->end(wrapperToken);
     }
+    // mAggAtomsAndStates used for state metrics.
+    // mAggAtomsAndStates will only have entries if states are used.
+    for (const auto& [atomDimensionKey, aggregatedStates] : mAggAtomsAndStates) {
+        uint64_t wrapperToken =
+                protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | FIELD_ID_DATA);
+
+        uint64_t aggregatedToken =
+                protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_AGGREGATED_ATOM);
+
+        uint64_t atomToken = protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_ATOM);
+        writeFieldValueTreeToStream(atomDimensionKey.getAtomTag(),
+                                    atomDimensionKey.getAtomFieldValues().getValues(), mUidFields,
+                                    usedUids, protoOutput);
+        protoOutput->end(atomToken);
+        for (const auto& [stateKey, elapsedTimestampsNs] : aggregatedStates) {
+            uint64_t stateInfoToken = protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED |
+                                                         FIELD_ID_AGGREGATED_STATE);
+            for (auto state : stateKey.getValues()) {
+                uint64_t stateToken = protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED |
+                                                         FIELD_ID_SLICE_BY_STATE);
+                writeStateToProto(state, protoOutput);
+                protoOutput->end(stateToken);
+            }
+            for (int64_t timestampNs : elapsedTimestampsNs) {
+                protoOutput->write(
+                        FIELD_TYPE_INT64 | FIELD_COUNT_REPEATED | FIELD_ID_STATE_TIMESTAMPS,
+                        (long long)timestampNs);
+            }
+            protoOutput->end(stateInfoToken);
+        }
+        protoOutput->end(aggregatedToken);
+        protoOutput->end(wrapperToken);
+    }
 
     protoOutput->end(protoToken);
     if (erase_data) {
         mAggregatedAtoms.clear();
+        mAggAtomsAndStates.clear();
         resetDataCorruptionFlagsLocked();
         mTotalDataSize = 0;
     }
@@ -220,6 +272,14 @@ void EventMetricProducer::onConditionChangedLocked(const bool conditionMet,
     mCondition = conditionMet ? ConditionState::kTrue : ConditionState::kFalse;
 }
 
+void EventMetricProducer::onStateChanged(const int64_t eventTimeNs, const int32_t atomId,
+                                         const HashableDimensionKey& primaryKey,
+                                         const FieldValue& oldState, const FieldValue& newState) {
+    VLOG("EventMetric %lld onStateChanged time %lld, State%d, key %s, %d -> %d",
+         (long long)mMetricId, (long long)eventTimeNs, atomId, primaryKey.toString().c_str(),
+         oldState.mValue.int_value, newState.mValue.int_value);
+}
+
 void EventMetricProducer::onMatchedLogEventInternalLocked(
         const size_t matcherIndex, const MetricDimensionKey& eventKey,
         const ConditionKey& conditionKey, bool condition, const LogEvent& event,
@@ -233,10 +293,11 @@ void EventMetricProducer::onMatchedLogEventInternalLocked(
     }
 
     const int64_t elapsedTimeNs = truncateTimestampIfNecessary(event);
-    AtomDimensionKey key(event.GetTagId(), HashableDimensionKey(event.getValues()));
-
-    std::vector<int64_t>& aggregatedTimestampsNs = mAggregatedAtoms[key];
-    if (aggregatedTimestampsNs.empty()) {
+    AtomDimensionKey key(
+            event.GetTagId(),
+            HashableDimensionKey(filterValues(mFieldMatchers, event.getValues(), mOmitFields)));
+    // TODO(b/383929503): Optimize slice_by_state performance
+    if (!mAggregatedAtoms.contains(key) && !mAggAtomsAndStates.contains(key)) {
         sp<ConfigMetadataProvider> provider = getConfigMetadataProvider();
         if (provider != nullptr && provider->useV2SoftMemoryCalculation()) {
             mTotalDataSize += getFieldValuesSizeV2(key.getAtomFieldValues().getValues());
@@ -244,8 +305,21 @@ void EventMetricProducer::onMatchedLogEventInternalLocked(
             mTotalDataSize += getSize(key.getAtomFieldValues().getValues());
         }
     }
-    aggregatedTimestampsNs.push_back(elapsedTimeNs);
-    mTotalDataSize += sizeof(int64_t);  // Add the size of the event timestamp
+
+    if (eventKey.getStateValuesKey().getValues().empty()) {  // Metric does not use slice_by_state
+        mAggregatedAtoms[key].push_back(elapsedTimeNs);
+        mTotalDataSize += sizeof(int64_t);  // Add the size of the event timestamp
+    } else {                                // Metric does use slice_by_state
+        std::unordered_map<HashableDimensionKey, std::vector<int64_t>>& aggStateTimestampsNs =
+                mAggAtomsAndStates[key];
+        std::vector<int64_t>& aggTimestampsNs = aggStateTimestampsNs[eventKey.getStateValuesKey()];
+        if (aggTimestampsNs.empty()) {
+            // Add the size of the states
+            mTotalDataSize += getFieldValuesSizeV2(eventKey.getStateValuesKey().getValues());
+        }
+        aggTimestampsNs.push_back(elapsedTimeNs);
+        mTotalDataSize += sizeof(int64_t);  // Add the size of the event timestamp
+    }
 }
 
 size_t EventMetricProducer::byteSizeLocked() const {
diff --git a/statsd/src/metrics/EventMetricProducer.h b/statsd/src/metrics/EventMetricProducer.h
index 28bf83f6..cd9f511f 100644
--- a/statsd/src/metrics/EventMetricProducer.h
+++ b/statsd/src/metrics/EventMetricProducer.h
@@ -51,6 +51,10 @@ public:
         return METRIC_TYPE_EVENT;
     }
 
+    void onStateChanged(const int64_t eventTimeNs, const int32_t atomId,
+                        const HashableDimensionKey& primaryKey, const FieldValue& oldState,
+                        const FieldValue& newState) override;
+
 private:
     void onMatchedLogEventInternalLocked(
             const size_t matcherIndex, const MetricDimensionKey& eventKey,
@@ -96,9 +100,22 @@ private:
                                                        LostAtomType atomType) const override;
 
     // Maps the field/value pairs of an atom to a list of timestamps used to deduplicate atoms.
+    // Used when event metric DOES NOT use slice_by_state. Empty otherwise.
     std::unordered_map<AtomDimensionKey, std::vector<int64_t>> mAggregatedAtoms;
 
+    // Maps the field/value pairs of an atom to the field/value pairs of a state to a list of
+    // timestamps used to deduplicate atoms and states.
+    // Used when event metric DOES use slice_by_state. Empty otherwise.
+    std::unordered_map<AtomDimensionKey,
+                       std::unordered_map<HashableDimensionKey, std::vector<int64_t>>>
+            mAggAtomsAndStates;
+
     const int mSamplingPercentage;
+
+    // Allowlist/denylist of fields to report. Empty means all are reported.
+    // If mOmitFields == true, this is a denylist, otherwise it's an allowlist.
+    const std::vector<Matcher> mFieldMatchers;
+    const bool mOmitFields;
 };
 
 }  // namespace statsd
diff --git a/statsd/src/metrics/GaugeMetricProducer.cpp b/statsd/src/metrics/GaugeMetricProducer.cpp
index 893f1a39..c9f81cc2 100644
--- a/statsd/src/metrics/GaugeMetricProducer.cpp
+++ b/statsd/src/metrics/GaugeMetricProducer.cpp
@@ -66,6 +66,7 @@ const int FIELD_ID_DROP_TIME = 2;
 const int FIELD_ID_DIMENSION_IN_WHAT = 1;
 const int FIELD_ID_BUCKET_INFO = 3;
 const int FIELD_ID_DIMENSION_LEAF_IN_WHAT = 4;
+const int FIELD_ID_SLICE_BY_STATE = 6;
 // for GaugeBucketInfo
 const int FIELD_ID_BUCKET_NUM = 6;
 const int FIELD_ID_START_BUCKET_ELAPSED_MILLIS = 7;
@@ -74,6 +75,7 @@ const int FIELD_ID_AGGREGATED_ATOM = 9;
 // for AggregatedAtomInfo
 const int FIELD_ID_ATOM_VALUE = 1;
 const int FIELD_ID_ATOM_TIMESTAMPS = 2;
+const int FIELD_ID_AGGREGATED_STATE = 3;
 
 GaugeMetricProducer::GaugeMetricProducer(
         const ConfigKey& key, const GaugeMetric& metric, const int conditionIndex,
@@ -85,11 +87,12 @@ GaugeMetricProducer::GaugeMetricProducer(
         const wp<ConfigMetadataProvider> configMetadataProvider,
         const unordered_map<int, shared_ptr<Activation>>& eventActivationMap,
         const unordered_map<int, vector<shared_ptr<Activation>>>& eventDeactivationMap,
+        const vector<int>& slicedStateAtoms,
+        const unordered_map<int, unordered_map<int, int64_t>>& stateGroupMap,
         const size_t dimensionSoftLimit, const size_t dimensionHardLimit)
     : MetricProducer(metric.id(), key, timeBaseNs, conditionIndex, initialConditionCache, wizard,
-                     protoHash, eventActivationMap, eventDeactivationMap, /*slicedStateAtoms=*/{},
-                     /*stateGroupMap=*/{}, getAppUpgradeBucketSplit(metric),
-                     configMetadataProvider),
+                     protoHash, eventActivationMap, eventDeactivationMap, slicedStateAtoms,
+                     stateGroupMap, getAppUpgradeBucketSplit(metric), configMetadataProvider),
       mWhatMatcherIndex(whatMatcherIndex),
       mEventMatcherWizard(matcherWizard),
       mPullerManager(pullerManager),
@@ -98,6 +101,8 @@ GaugeMetricProducer::GaugeMetricProducer(
       mAtomId(atomId),
       mIsPulled(pullTagId != -1),
       mMinBucketSizeNs(metric.min_bucket_size_nanos()),
+      mFieldMatchers(translateFieldsFilter(metric.gauge_fields_filter())),
+      mOmitFields(metric.gauge_fields_filter().has_omit_fields()),
       mSamplingType(metric.sampling_type()),
       mMaxPullDelayNs(metric.max_pull_delay_sec() > 0 ? metric.max_pull_delay_sec() * NS_PER_SEC
                                                       : StatsdStats::kPullMaxDelayNs),
@@ -117,10 +122,6 @@ GaugeMetricProducer::GaugeMetricProducer(
     }
     mBucketSizeNs = bucketSizeMills * 1000000;
 
-    if (!metric.gauge_fields_filter().include_all()) {
-        translateFieldMatcher(metric.gauge_fields_filter().fields(), &mFieldMatchers);
-    }
-
     if (metric.has_dimensions_in_what()) {
         translateFieldMatcher(metric.dimensions_in_what(), &mDimensionsInWhat);
         mContainANYPositionInDimensionsInWhat = HasPositionANY(metric.dimensions_in_what());
@@ -136,6 +137,15 @@ GaugeMetricProducer::GaugeMetricProducer(
         }
         mConditionSliced = true;
     }
+
+    for (const auto& stateLink : metric.state_link()) {
+        Metric2State ms;
+        ms.stateAtomId = stateLink.state_atom_id();
+        translateFieldMatcher(stateLink.fields_in_what(), &ms.metricFields);
+        translateFieldMatcher(stateLink.fields_in_state(), &ms.stateFields);
+        mMetric2StateLinks.push_back(ms);
+    }
+
     mShouldUseNestedDimensions = ShouldUseNestedDimensions(metric.dimensions_in_what());
 
     flushIfNeededLocked(startTimeNs);
@@ -224,6 +234,14 @@ optional<InvalidConfigReason> GaugeMetricProducer::onConfigUpdatedLocked(
     return nullopt;
 }
 
+void GaugeMetricProducer::onStateChanged(const int64_t eventTimeNs, const int32_t atomId,
+                                         const HashableDimensionKey& primaryKey,
+                                         const FieldValue& oldState, const FieldValue& newState) {
+    VLOG("GaugeMetric %lld onStateChanged time %lld, State%d, key %s, %d -> %d",
+         (long long)mMetricId, (long long)eventTimeNs, atomId, primaryKey.toString().c_str(),
+         oldState.mValue.int_value, newState.mValue.int_value);
+}
+
 void GaugeMetricProducer::dumpStatesLocked(int out, bool verbose) const {
     if (mCurrentSlicedBucket == nullptr ||
         mCurrentSlicedBucket->size() == 0) {
@@ -337,6 +355,14 @@ void GaugeMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
                                            usedUids, protoOutput);
         }
 
+        // Then fill slice_by_state.
+        for (auto state : dimensionKey.getStateValuesKey().getValues()) {
+            uint64_t stateToken = protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED |
+                                                     FIELD_ID_SLICE_BY_STATE);
+            writeStateToProto(state, protoOutput);
+            protoOutput->end(stateToken);
+        }
+
         // Then fill bucket_info (GaugeBucketInfo).
         for (const auto& bucket : pair.second) {
             uint64_t bucketInfoToken = protoOutput->start(
@@ -487,21 +513,16 @@ void GaugeMetricProducer::onSlicedConditionMayChangeLocked(bool overallCondition
     }  // else: Push mode. No need to proactively pull the gauge data.
 }
 
-std::shared_ptr<vector<FieldValue>> GaugeMetricProducer::getGaugeFields(const LogEvent& event) {
-    std::shared_ptr<vector<FieldValue>> gaugeFields;
-    if (mFieldMatchers.size() > 0) {
-        gaugeFields = std::make_shared<vector<FieldValue>>();
-        filterGaugeValues(mFieldMatchers, event.getValues(), gaugeFields.get());
-    } else {
-        gaugeFields = std::make_shared<vector<FieldValue>>(event.getValues());
-    }
+vector<FieldValue> GaugeMetricProducer::getGaugeFields(const LogEvent& event) {
+    vector<FieldValue> gaugeFields = filterValues(mFieldMatchers, event.getValues(), mOmitFields);
+
     // Trim all dimension fields from output. Dimensions will appear in output report and will
     // benefit from dictionary encoding. For large pulled atoms, this can give the benefit of
     // optional repeated field.
     for (const auto& field : mDimensionsInWhat) {
-        for (auto it = gaugeFields->begin(); it != gaugeFields->end();) {
+        for (auto it = gaugeFields.begin(); it != gaugeFields.end();) {
             if (it->mField.matches(field)) {
-                it = gaugeFields->erase(it);
+                it = gaugeFields.erase(it);
             } else {
                 it++;
             }
@@ -560,7 +581,7 @@ bool GaugeMetricProducer::hitGuardRailLocked(const MetricDimensionKey& newKey) {
 void GaugeMetricProducer::onMatchedLogEventInternalLocked(
         const size_t matcherIndex, const MetricDimensionKey& eventKey,
         const ConditionKey& conditionKey, bool condition, const LogEvent& event,
-        const map<int, HashableDimensionKey>& /*statePrimaryKeys*/) {
+        const map<int, HashableDimensionKey>& statePrimaryKeys) {
     if (condition == false) {
         return;
     }
@@ -605,8 +626,8 @@ void GaugeMetricProducer::onMatchedLogEventInternalLocked(
     // Anomaly detection on gauge metric only works when there is one numeric
     // field specified.
     if (mAnomalyTrackers.size() > 0) {
-        if (gaugeAtom.mFields->size() == 1) {
-            const Value& value = gaugeAtom.mFields->begin()->mValue;
+        if (gaugeAtom.mFields.size() == 1) {
+            const Value& value = gaugeAtom.mFields.begin()->mValue;
             long gaugeVal = 0;
             if (value.getType() == INT) {
                 gaugeVal = (long)value.int_value;
@@ -626,7 +647,7 @@ void GaugeMetricProducer::updateCurrentSlicedBucketForAnomaly() {
         if (slice.second.empty()) {
             continue;
         }
-        const Value& value = slice.second.front().mFields->front().mValue;
+        const Value& value = slice.second.front().mFields.front().mValue;
         long gaugeVal = 0;
         if (value.getType() == INT) {
             gaugeVal = (long)value.int_value;
@@ -685,7 +706,7 @@ void GaugeMetricProducer::flushCurrentBucketLocked(const int64_t eventTimeNs,
         for (const auto& slice : *mCurrentSlicedBucket) {
             info.mAggregatedAtoms.clear();
             for (const GaugeAtom& atom : slice.second) {
-                AtomDimensionKey key(mAtomId, HashableDimensionKey(*atom.mFields));
+                AtomDimensionKey key(mAtomId, HashableDimensionKey(atom.mFields));
                 vector<int64_t>& elapsedTimestampsNs = info.mAggregatedAtoms[key];
                 elapsedTimestampsNs.push_back(atom.mElapsedTimestampNs);
             }
diff --git a/statsd/src/metrics/GaugeMetricProducer.h b/statsd/src/metrics/GaugeMetricProducer.h
index f5839d12..9408785c 100644
--- a/statsd/src/metrics/GaugeMetricProducer.h
+++ b/statsd/src/metrics/GaugeMetricProducer.h
@@ -34,10 +34,10 @@ namespace os {
 namespace statsd {
 
 struct GaugeAtom {
-    GaugeAtom(const std::shared_ptr<vector<FieldValue>>& fields, int64_t elapsedTimeNs)
+    GaugeAtom(std::vector<FieldValue> fields, int64_t elapsedTimeNs)
         : mFields(fields), mElapsedTimestampNs(elapsedTimeNs) {
     }
-    std::shared_ptr<vector<FieldValue>> mFields;
+    std::vector<FieldValue> mFields;
     int64_t mElapsedTimestampNs;
 };
 
@@ -70,6 +70,8 @@ public:
             const std::unordered_map<int, std::shared_ptr<Activation>>& eventActivationMap = {},
             const std::unordered_map<int, std::vector<std::shared_ptr<Activation>>>&
                     eventDeactivationMap = {},
+            const std::vector<int>& slicedStateAtoms = {},
+            const std::unordered_map<int, std::unordered_map<int, int64_t>>& stateGroupMap = {},
             const size_t dimensionSoftLimit = StatsdStats::kDimensionKeySizeSoftLimit,
             const size_t dimensionHardLimit = StatsdStats::kDimensionKeySizeHardLimit);
 
@@ -108,6 +110,10 @@ public:
         return METRIC_TYPE_GAUGE;
     }
 
+    void onStateChanged(const int64_t eventTimeNs, const int32_t atomId,
+                        const HashableDimensionKey& primaryKey, const FieldValue& oldState,
+                        const FieldValue& newState) override;
+
 protected:
     void onMatchedLogEventInternalLocked(
             const size_t matcherIndex, const MetricDimensionKey& eventKey,
@@ -181,6 +187,7 @@ private:
     sp<EventMatcherWizard> mEventMatcherWizard;
 
     sp<StatsPullerManager> mPullerManager;
+
     // tagId for pulled data. -1 if this is not pulled
     const int mPullTagId;
 
@@ -209,15 +216,17 @@ private:
     // for each slice with the latest value.
     void updateCurrentSlicedBucketForAnomaly();
 
-    // Allowlist of fields to report. Empty means all are reported.
-    std::vector<Matcher> mFieldMatchers;
+    // Allowlist/denylist of fields to report. Empty means all are reported.
+    // If mOmitFields == true, this is a denylist, otherwise it's an allowlist.
+    const std::vector<Matcher> mFieldMatchers;
+    const bool mOmitFields;
 
     GaugeMetric::SamplingType mSamplingType;
 
     const int64_t mMaxPullDelayNs;
 
     // apply an allowlist on the original input
-    std::shared_ptr<vector<FieldValue>> getGaugeFields(const LogEvent& event);
+    std::vector<FieldValue> getGaugeFields(const LogEvent& event);
 
     // Util function to check whether the specified dimension hits the guardrail.
     bool hitGuardRailLocked(const MetricDimensionKey& newKey);
diff --git a/statsd/src/metrics/MetricProducer.h b/statsd/src/metrics/MetricProducer.h
index 7059e615..d7b2a36a 100644
--- a/statsd/src/metrics/MetricProducer.h
+++ b/statsd/src/metrics/MetricProducer.h
@@ -659,6 +659,8 @@ protected:
     FRIEND_TEST(DurationMetricE2eTest, TestWithSlicedStatePrimaryFieldsSubset);
     FRIEND_TEST(DurationMetricE2eTest, TestUploadThreshold);
 
+    FRIEND_TEST(EventMetricE2eTest, TestSlicedState);
+
     FRIEND_TEST(MetricActivationE2eTest, TestCountMetric);
     FRIEND_TEST(MetricActivationE2eTest, TestCountMetricWithOneDeactivation);
     FRIEND_TEST(MetricActivationE2eTest, TestCountMetricWithTwoDeactivations);
diff --git a/statsd/src/metrics/MetricsManager.cpp b/statsd/src/metrics/MetricsManager.cpp
index c0fe2817..c38aa3a0 100644
--- a/statsd/src/metrics/MetricsManager.cpp
+++ b/statsd/src/metrics/MetricsManager.cpp
@@ -605,8 +605,9 @@ void MetricsManager::onLogEvent(const LogEvent& event) {
         // This should not happen if metric config is defined for certain atom id
         const int64_t firstMatcherId =
                 mAllAtomMatchingTrackers[*matchersIt->second.begin()]->getId();
-        ALOGW("Atom %d is mistakenly skipped - there is a matcher %lld for it", tagId,
-              (long long)firstMatcherId);
+        ALOGW("Atom %d is mistakenly skipped - there is a matcher %lld for it (ts %lld)", tagId,
+              (long long)firstMatcherId, (long long)event.GetElapsedTimestampNs());
+        StatsdStats::getInstance().noteIllegalState(COUNTER_TYPE_ERROR_ATOM_FILTER_SKIPPED);
         return;
     }
 
@@ -906,6 +907,7 @@ void MetricsManager::loadMetadata(const metadata::StatsMetadata& metadata,
         const auto& it = mMetricProducerMap.find(metricId);
         if (it == mMetricProducerMap.end()) {
             ALOGE("No metricProducer found for metricId %lld", (long long)metricId);
+            continue;
         }
         mAllMetricProducers[it->second]->loadMetricMetadataFromProto(metricMetadata);
     }
diff --git a/statsd/src/metrics/MetricsManager.h b/statsd/src/metrics/MetricsManager.h
index a7b18ac7..5ef9baac 100644
--- a/statsd/src/metrics/MetricsManager.h
+++ b/statsd/src/metrics/MetricsManager.h
@@ -471,6 +471,8 @@ private:
     FRIEND_TEST(DurationMetricE2eTest, TestWithSlicedStatePrimaryFieldsSubset);
     FRIEND_TEST(DurationMetricE2eTest, TestUploadThreshold);
 
+    FRIEND_TEST(EventMetricE2eTest, TestSlicedState);
+
     FRIEND_TEST(ValueMetricE2eTest, TestInitialConditionChanges);
     FRIEND_TEST(ValueMetricE2eTest, TestPulledEvents);
     FRIEND_TEST(ValueMetricE2eTest, TestPulledEvents_LateAlarm);
diff --git a/statsd/src/metrics/RestrictedEventMetricProducer.cpp b/statsd/src/metrics/RestrictedEventMetricProducer.cpp
index 115cc852..14ee0b96 100644
--- a/statsd/src/metrics/RestrictedEventMetricProducer.cpp
+++ b/statsd/src/metrics/RestrictedEventMetricProducer.cpp
@@ -13,7 +13,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-#define STATSD_DEBUG true
+#define STATSD_DEBUG false
 #include "Log.h"
 
 #include "RestrictedEventMetricProducer.h"
diff --git a/statsd/src/metrics/parsing_utils/config_update_utils.cpp b/statsd/src/metrics/parsing_utils/config_update_utils.cpp
index a296dad8..f4c2409b 100644
--- a/statsd/src/metrics/parsing_utils/config_update_utils.cpp
+++ b/statsd/src/metrics/parsing_utils/config_update_utils.cpp
@@ -883,10 +883,10 @@ optional<InvalidConfigReason> updateMetrics(
                 producer = createEventMetricProducerAndUpdateMetadata(
                         key, config, timeBaseNs, metric, metricIndex, allAtomMatchingTrackers,
                         newAtomMatchingTrackerMap, allConditionTrackers, conditionTrackerMap,
-                        initialConditionCache, wizard, metricToActivationMap, trackerToMetricMap,
-                        conditionToMetricMap, activationAtomTrackerToMetricMap,
-                        deactivationAtomTrackerToMetricMap, metricsWithActivation,
-                        invalidConfigReason, configMetadataProvider);
+                        initialConditionCache, wizard, stateAtomIdMap, allStateGroupMaps,
+                        metricToActivationMap, trackerToMetricMap, conditionToMetricMap,
+                        activationAtomTrackerToMetricMap, deactivationAtomTrackerToMetricMap,
+                        metricsWithActivation, invalidConfigReason, configMetadataProvider);
                 break;
             }
             default: {
@@ -969,9 +969,10 @@ optional<InvalidConfigReason> updateMetrics(
                         key, config, timeBaseNs, currentTimeNs, pullerManager, metric, metricIndex,
                         allAtomMatchingTrackers, newAtomMatchingTrackerMap, allConditionTrackers,
                         conditionTrackerMap, initialConditionCache, wizard, matcherWizard,
-                        metricToActivationMap, trackerToMetricMap, conditionToMetricMap,
-                        activationAtomTrackerToMetricMap, deactivationAtomTrackerToMetricMap,
-                        metricsWithActivation, invalidConfigReason, configMetadataProvider);
+                        stateAtomIdMap, allStateGroupMaps, metricToActivationMap,
+                        trackerToMetricMap, conditionToMetricMap, activationAtomTrackerToMetricMap,
+                        deactivationAtomTrackerToMetricMap, metricsWithActivation,
+                        invalidConfigReason, configMetadataProvider);
                 break;
             }
             default: {
diff --git a/statsd/src/metrics/parsing_utils/histogram_parsing_utils.h b/statsd/src/metrics/parsing_utils/histogram_parsing_utils.h
index f58ecf97..5feb9d33 100644
--- a/statsd/src/metrics/parsing_utils/histogram_parsing_utils.h
+++ b/statsd/src/metrics/parsing_utils/histogram_parsing_utils.h
@@ -28,7 +28,7 @@ namespace android {
 namespace os {
 namespace statsd {
 
-constexpr float UNDERFLOW_BIN_START = std::numeric_limits<float>::min();
+constexpr float UNDERFLOW_BIN_START = std::numeric_limits<float>::lowest();
 
 using ParseHistogramBinConfigsResult =
         std::variant<std::vector<std::optional<const BinStarts>>, InvalidConfigReason>;
diff --git a/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp b/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
index 57b72dfb..a8ca6003 100644
--- a/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
+++ b/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
@@ -838,6 +838,8 @@ optional<sp<MetricProducer>> createEventMetricProducerAndUpdateMetadata(
         vector<sp<ConditionTracker>>& allConditionTrackers,
         const unordered_map<int64_t, int>& conditionTrackerMap,
         const vector<ConditionState>& initialConditionCache, const sp<ConditionWizard>& wizard,
+        const std::unordered_map<int64_t, int>& stateAtomIdMap,
+        const std::unordered_map<int64_t, std::unordered_map<int, int64_t>>& allStateGroupMaps,
         const unordered_map<int64_t, int>& metricToActivationMap,
         unordered_map<int, vector<int>>& trackerToMetricMap,
         unordered_map<int, vector<int>>& conditionToMetricMap,
@@ -851,6 +853,18 @@ optional<sp<MetricProducer>> createEventMetricProducerAndUpdateMetadata(
                 InvalidConfigReason(INVALID_CONFIG_REASON_METRIC_MISSING_ID_OR_WHAT, metric.id());
         return nullopt;
     }
+
+    if (metric.has_fields_filter()) {
+        const FieldFilter& filter = metric.fields_filter();
+        if ((filter.has_fields() && !hasLeafNode(filter.fields())) ||
+            (filter.has_omit_fields() && !hasLeafNode(filter.omit_fields()))) {
+            ALOGW("Incorrect field filter setting in EventMetric %lld", (long long)metric.id());
+            invalidConfigReason = InvalidConfigReason(
+                    INVALID_CONFIG_REASON_METRIC_INCORRECT_FIELD_FILTER, metric.id());
+            return nullopt;
+        }
+    }
+
     int trackerIndex;
     invalidConfigReason = handleMetricWithAtomMatchingTrackers(
             metric.what(), metric.id(), metricIndex, false, allAtomMatchingTrackers,
@@ -876,6 +890,22 @@ optional<sp<MetricProducer>> createEventMetricProducerAndUpdateMetadata(
         }
     }
 
+    std::vector<int> slicedStateAtoms;
+    unordered_map<int, unordered_map<int, int64_t>> stateGroupMap;
+    if (metric.slice_by_state_size() > 0) {
+        invalidConfigReason =
+                handleMetricWithStates(config, metric.id(), metric.slice_by_state(), stateAtomIdMap,
+                                       allStateGroupMaps, slicedStateAtoms, stateGroupMap);
+        if (invalidConfigReason.has_value()) {
+            return nullopt;
+        }
+    } else if (metric.state_link_size() > 0) {
+        ALOGW("EventMetric has a MetricStateLink but doesn't have a sliced state");
+        invalidConfigReason =
+                InvalidConfigReason(INVALID_CONFIG_REASON_METRIC_STATELINK_NO_STATE, metric.id());
+        return nullopt;
+    }
+
     if (metric.sampling_percentage() < 1 || metric.sampling_percentage() > 100) {
         invalidConfigReason = InvalidConfigReason(
                 INVALID_CONFIG_REASON_METRIC_INCORRECT_SAMPLING_PERCENTAGE, metric.id());
@@ -901,11 +931,13 @@ optional<sp<MetricProducer>> createEventMetricProducerAndUpdateMetadata(
     if (config.has_restricted_metrics_delegate_package_name()) {
         metricProducer = new RestrictedEventMetricProducer(
                 key, metric, conditionIndex, initialConditionCache, wizard, metricHash, timeBaseNs,
-                configMetadataProvider, eventActivationMap, eventDeactivationMap);
+                configMetadataProvider, eventActivationMap, eventDeactivationMap, slicedStateAtoms,
+                stateGroupMap);
     } else {
         metricProducer = new EventMetricProducer(
                 key, metric, conditionIndex, initialConditionCache, wizard, metricHash, timeBaseNs,
-                configMetadataProvider, eventActivationMap, eventDeactivationMap);
+                configMetadataProvider, eventActivationMap, eventDeactivationMap, slicedStateAtoms,
+                stateGroupMap);
     }
 
     invalidConfigReason = setUidFieldsIfNecessary(metric, metricProducer);
@@ -1362,6 +1394,8 @@ optional<sp<MetricProducer>> createGaugeMetricProducerAndUpdateMetadata(
         const unordered_map<int64_t, int>& conditionTrackerMap,
         const vector<ConditionState>& initialConditionCache, const sp<ConditionWizard>& wizard,
         const sp<EventMatcherWizard>& matcherWizard,
+        const std::unordered_map<int64_t, int>& stateAtomIdMap,
+        const std::unordered_map<int64_t, std::unordered_map<int, int64_t>>& allStateGroupMaps,
         const unordered_map<int64_t, int>& metricToActivationMap,
         unordered_map<int, vector<int>>& trackerToMetricMap,
         unordered_map<int, vector<int>>& conditionToMetricMap,
@@ -1376,21 +1410,15 @@ optional<sp<MetricProducer>> createGaugeMetricProducerAndUpdateMetadata(
         return nullopt;
     }
 
-    if ((!metric.gauge_fields_filter().has_include_all() ||
-         (metric.gauge_fields_filter().include_all() == false)) &&
-        !hasLeafNode(metric.gauge_fields_filter().fields())) {
-        ALOGW("Incorrect field filter setting in GaugeMetric %lld", (long long)metric.id());
-        invalidConfigReason = InvalidConfigReason(
-                INVALID_CONFIG_REASON_GAUGE_METRIC_INCORRECT_FIELD_FILTER, metric.id());
-        return nullopt;
-    }
-    if ((metric.gauge_fields_filter().has_include_all() &&
-         metric.gauge_fields_filter().include_all() == true) &&
-        hasLeafNode(metric.gauge_fields_filter().fields())) {
-        ALOGW("Incorrect field filter setting in GaugeMetric %lld", (long long)metric.id());
-        invalidConfigReason = InvalidConfigReason(
-                INVALID_CONFIG_REASON_GAUGE_METRIC_INCORRECT_FIELD_FILTER, metric.id());
-        return nullopt;
+    if (metric.has_gauge_fields_filter()) {
+        const FieldFilter& filter = metric.gauge_fields_filter();
+        if ((filter.has_fields() && !hasLeafNode(filter.fields())) ||
+            (filter.has_omit_fields() && !hasLeafNode(filter.omit_fields()))) {
+            ALOGW("Incorrect field filter setting in GaugeMetric %lld", (long long)metric.id());
+            invalidConfigReason = InvalidConfigReason(
+                    INVALID_CONFIG_REASON_METRIC_INCORRECT_FIELD_FILTER, metric.id());
+            return nullopt;
+        }
     }
 
     int trackerIndex;
@@ -1450,6 +1478,22 @@ optional<sp<MetricProducer>> createGaugeMetricProducerAndUpdateMetadata(
         }
     }
 
+    std::vector<int> slicedStateAtoms;
+    std::unordered_map<int, std::unordered_map<int, int64_t>> stateGroupMap;
+    if (metric.slice_by_state_size() > 0) {
+        invalidConfigReason =
+                handleMetricWithStates(config, metric.id(), metric.slice_by_state(), stateAtomIdMap,
+                                       allStateGroupMaps, slicedStateAtoms, stateGroupMap);
+        if (invalidConfigReason.has_value()) {
+            return nullopt;
+        }
+    } else if (metric.state_link_size() > 0) {
+        ALOGE("GaugeMetric has a MetricStateLink but doesn't have a sliced state");
+        invalidConfigReason =
+                InvalidConfigReason(INVALID_CONFIG_REASON_METRIC_STATELINK_NO_STATE, metric.id());
+        return nullopt;
+    }
+
     if (pullTagId != -1 && metric.sampling_percentage() != 100) {
         invalidConfigReason = InvalidConfigReason(
                 INVALID_CONFIG_REASON_GAUGE_METRIC_PULLED_WITH_SAMPLING, metric.id());
@@ -1508,7 +1552,7 @@ optional<sp<MetricProducer>> createGaugeMetricProducerAndUpdateMetadata(
             key, metric, conditionIndex, initialConditionCache, wizard, metricHash, trackerIndex,
             matcherWizard, pullTagId, triggerAtomId, atomTagId, timeBaseNs, currentTimeNs,
             pullerManager, configMetadataProvider, eventActivationMap, eventDeactivationMap,
-            dimensionSoftLimit, dimensionHardLimit);
+            slicedStateAtoms, stateGroupMap, dimensionSoftLimit, dimensionHardLimit);
 
     SamplingInfo samplingInfo;
     std::vector<Matcher> dimensionsInWhat;
@@ -1797,10 +1841,10 @@ optional<InvalidConfigReason> initMetrics(
         optional<sp<MetricProducer>> producer = createEventMetricProducerAndUpdateMetadata(
                 key, config, timeBaseTimeNs, metric, metricIndex, allAtomMatchingTrackers,
                 atomMatchingTrackerMap, allConditionTrackers, conditionTrackerMap,
-                initialConditionCache, wizard, metricToActivationMap, trackerToMetricMap,
-                conditionToMetricMap, activationAtomTrackerToMetricMap,
-                deactivationAtomTrackerToMetricMap, metricsWithActivation, invalidConfigReason,
-                configMetadataProvider);
+                initialConditionCache, wizard, stateAtomIdMap, allStateGroupMaps,
+                metricToActivationMap, trackerToMetricMap, conditionToMetricMap,
+                activationAtomTrackerToMetricMap, deactivationAtomTrackerToMetricMap,
+                metricsWithActivation, invalidConfigReason, configMetadataProvider);
         if (!producer) {
             return invalidConfigReason;
         }
@@ -1851,8 +1895,8 @@ optional<InvalidConfigReason> initMetrics(
         optional<sp<MetricProducer>> producer = createGaugeMetricProducerAndUpdateMetadata(
                 key, config, timeBaseTimeNs, currentTimeNs, pullerManager, metric, metricIndex,
                 allAtomMatchingTrackers, atomMatchingTrackerMap, allConditionTrackers,
-                conditionTrackerMap, initialConditionCache, wizard, matcherWizard,
-                metricToActivationMap, trackerToMetricMap, conditionToMetricMap,
+                conditionTrackerMap, initialConditionCache, wizard, matcherWizard, stateAtomIdMap,
+                allStateGroupMaps, metricToActivationMap, trackerToMetricMap, conditionToMetricMap,
                 activationAtomTrackerToMetricMap, deactivationAtomTrackerToMetricMap,
                 metricsWithActivation, invalidConfigReason, configMetadataProvider);
         if (!producer) {
diff --git a/statsd/src/metrics/parsing_utils/metrics_manager_util.h b/statsd/src/metrics/parsing_utils/metrics_manager_util.h
index 8a73ff0d..75ec66b7 100644
--- a/statsd/src/metrics/parsing_utils/metrics_manager_util.h
+++ b/statsd/src/metrics/parsing_utils/metrics_manager_util.h
@@ -145,6 +145,8 @@ optional<sp<MetricProducer>> createEventMetricProducerAndUpdateMetadata(
         std::vector<sp<ConditionTracker>>& allConditionTrackers,
         const std::unordered_map<int64_t, int>& conditionTrackerMap,
         const std::vector<ConditionState>& initialConditionCache, const sp<ConditionWizard>& wizard,
+        const std::unordered_map<int64_t, int>& stateAtomIdMap,
+        const std::unordered_map<int64_t, std::unordered_map<int, int64_t>>& allStateGroupMaps,
         const std::unordered_map<int64_t, int>& metricToActivationMap,
         std::unordered_map<int, std::vector<int>>& trackerToMetricMap,
         std::unordered_map<int, std::vector<int>>& conditionToMetricMap,
@@ -187,6 +189,8 @@ optional<sp<MetricProducer>> createGaugeMetricProducerAndUpdateMetadata(
         const std::unordered_map<int64_t, int>& conditionTrackerMap,
         const std::vector<ConditionState>& initialConditionCache, const sp<ConditionWizard>& wizard,
         const sp<EventMatcherWizard>& matcherWizard,
+        const std::unordered_map<int64_t, int>& stateAtomIdMap,
+        const std::unordered_map<int64_t, std::unordered_map<int, int64_t>>& allStateGroupMaps,
         const std::unordered_map<int64_t, int>& metricToActivationMap,
         std::unordered_map<int, std::vector<int>>& trackerToMetricMap,
         std::unordered_map<int, std::vector<int>>& conditionToMetricMap,
diff --git a/statsd/src/packages/UidMap.cpp b/statsd/src/packages/UidMap.cpp
index 8edbb0a5..abfe08f4 100644
--- a/statsd/src/packages/UidMap.cpp
+++ b/statsd/src/packages/UidMap.cpp
@@ -657,6 +657,8 @@ const std::map<string, uint32_t> UidMap::sAidToUidMapping = {{"AID_ROOT", 0},
                                                              {"AID_SECURITY_LOG_WRITER", 1091},
                                                              {"AID_PRNG_SEEDER", 1092},
                                                              {"AID_UPROBESTATS", 1093},
+                                                             {"AID_CROS_EC", 1094},
+                                                             {"AID_MMD", 1095},
                                                              {"AID_SHELL", 2000},
                                                              {"AID_CACHE", 2001},
                                                              {"AID_DIAG", 2002},
diff --git a/statsd/src/shell/ShellSubscriber.cpp b/statsd/src/shell/ShellSubscriber.cpp
index 56c3ccd8..807c51a5 100644
--- a/statsd/src/shell/ShellSubscriber.cpp
+++ b/statsd/src/shell/ShellSubscriber.cpp
@@ -198,7 +198,6 @@ void ShellSubscriber::unsubscribe(const shared_ptr<IStatsSubscriptionCallback>&
 }
 
 void ShellSubscriber::updateLogEventFilterLocked() const {
-    VLOG("ShellSubscriber: Updating allAtomIds");
     LogEventFilter::AtomIdSet allAtomIds;
     for (const auto& client : mClientSet) {
         client->addAllAtomIds(allAtomIds);
diff --git a/statsd/src/shell/ShellSubscriberClient.cpp b/statsd/src/shell/ShellSubscriberClient.cpp
index 67f7eb12..89f27394 100644
--- a/statsd/src/shell/ShellSubscriberClient.cpp
+++ b/statsd/src/shell/ShellSubscriberClient.cpp
@@ -32,6 +32,7 @@ namespace statsd {
 
 const static int FIELD_ID_SHELL_DATA__ATOM = 1;
 const static int FIELD_ID_SHELL_DATA__ELAPSED_TIMESTAMP_NANOS = 2;
+const static int FIELD_ID_SHELL_DATA__LOGGING_UID = 3;
 
 // Store next subscription ID for StatsdStats.
 // Not thread-safe; should only be accessed while holding ShellSubscriber::mMutex lock.
@@ -40,6 +41,7 @@ static int nextSubId = 0;
 struct ReadConfigResult {
     vector<SimpleAtomMatcher> pushedMatchers;
     vector<ShellSubscriberClient::PullInfo> pullInfo;
+    bool collect_uids;
 };
 
 // Read and parse single config. There should only one config in the input.
@@ -75,6 +77,8 @@ static optional<ReadConfigResult> readConfig(const vector<uint8_t>& configBytes,
               pulled.matcher().atom_id());
     }
 
+    result.collect_uids = config.collect_uids();
+
     return result;
 }
 
@@ -136,9 +140,13 @@ unique_ptr<ShellSubscriberClient> ShellSubscriberClient::create(
         return nullptr;
     }
 
-    return make_unique<ShellSubscriberClient>(
+    auto result = unique_ptr<ShellSubscriberClient>(new ShellSubscriberClient(
             nextSubId++, out, /*callback=*/nullptr, readConfigResult->pushedMatchers,
-            readConfigResult->pullInfo, timeoutSec, startTimeSec, uidMap, pullerMgr);
+            readConfigResult->pullInfo, timeoutSec, startTimeSec, uidMap, pullerMgr));
+    if (result != nullptr) {
+        result->setCollectUids(readConfigResult->collect_uids);
+    }
+    return result;
 }
 
 unique_ptr<ShellSubscriberClient> ShellSubscriberClient::create(
@@ -168,9 +176,13 @@ unique_ptr<ShellSubscriberClient> ShellSubscriberClient::create(
 
     StatsdStats::getInstance().noteSubscriptionStarted(id, readConfigResult->pushedMatchers.size(),
                                                        readConfigResult->pullInfo.size());
-    return make_unique<ShellSubscriberClient>(
+    auto result = unique_ptr<ShellSubscriberClient>(new ShellSubscriberClient(
             id, /*out=*/-1, callback, readConfigResult->pushedMatchers, readConfigResult->pullInfo,
-            /*timeoutSec=*/-1, startTimeSec, uidMap, pullerMgr);
+            /*timeoutSec=*/-1, startTimeSec, uidMap, pullerMgr));
+    if (result != nullptr) {
+        result->setCollectUids(readConfigResult->collect_uids);
+    }
+    return result;
 }
 
 bool ShellSubscriberClient::writeEventToProtoIfMatched(const LogEvent& event,
@@ -196,6 +208,13 @@ bool ShellSubscriberClient::writeEventToProtoIfMatched(const LogEvent& event,
     // Update byte size of cached data.
     mCacheSize += getSize(eventRef.getValues()) + sizeof(timestampNs);
 
+    if (mDoCollectUids) {
+        mProtoOut.write(util::FIELD_TYPE_INT32 | util::FIELD_COUNT_REPEATED |
+                                FIELD_ID_SHELL_DATA__LOGGING_UID,
+                        eventRef.GetUid());
+        mCacheSize += sizeof(int32_t);
+    }
+
     return true;
 }
 
diff --git a/statsd/src/shell/ShellSubscriberClient.h b/statsd/src/shell/ShellSubscriberClient.h
index 9d1724ae..f46a3e77 100644
--- a/statsd/src/shell/ShellSubscriberClient.h
+++ b/statsd/src/shell/ShellSubscriberClient.h
@@ -63,14 +63,6 @@ public:
             const std::shared_ptr<IStatsSubscriptionCallback>& callback, int64_t startTimeSec,
             const sp<UidMap>& uidMap, const sp<StatsPullerManager>& pullerMgr);
 
-    // Should only be called by the create() factory.
-    explicit ShellSubscriberClient(int id, int out,
-                                   const std::shared_ptr<IStatsSubscriptionCallback>& callback,
-                                   const std::vector<SimpleAtomMatcher>& pushedMatchers,
-                                   const std::vector<PullInfo>& pulledInfo, int64_t timeoutSec,
-                                   int64_t startTimeSec, const sp<UidMap>& uidMap,
-                                   const sp<StatsPullerManager>& pullerMgr);
-
     void onLogEvent(const LogEvent& event);
 
     int64_t pullAndSendHeartbeatsIfNeeded(int64_t nowSecs, int64_t nowMillis, int64_t nowNanos);
@@ -102,6 +94,18 @@ public:
     // Minimum sleep for the pull thread for callback subscriptions.
     static constexpr int64_t kMinCallbackSleepIntervalMs = 2000;  // 2 seconds.
 private:
+    // Should only be called by the create() factory which has access to implementation.
+    explicit ShellSubscriberClient(int id, int out,
+                                   const std::shared_ptr<IStatsSubscriptionCallback>& callback,
+                                   const std::vector<SimpleAtomMatcher>& pushedMatchers,
+                                   const std::vector<PullInfo>& pulledInfo, int64_t timeoutSec,
+                                   int64_t startTimeSec, const sp<UidMap>& uidMap,
+                                   const sp<StatsPullerManager>& pullerMgr);
+
+    void setCollectUids(bool doCollect) {
+        mDoCollectUids = doCollect;
+    }
+
     int64_t pullIfNeeded(int64_t nowSecs, int64_t nowMillis, int64_t nowNanos);
 
     void writePulledAtomsLocked(const vector<std::shared_ptr<LogEvent>>& data,
@@ -154,6 +158,8 @@ private:
     // mEventTimestampNs and mProtoOut.
     size_t mCacheSize;
 
+    bool mDoCollectUids = false;
+
     static constexpr int64_t kMsBetweenHeartbeats = 1000;
 
     // Cap the buffer size of configs to guard against bad allocations
diff --git a/statsd/src/shell/shell_config.proto b/statsd/src/shell/shell_config.proto
index 6b2890c8..fbe95732 100644
--- a/statsd/src/shell/shell_config.proto
+++ b/statsd/src/shell/shell_config.proto
@@ -36,4 +36,5 @@ message PulledAtomSubscription {
 message ShellSubscription {
     repeated SimpleAtomMatcher pushed = 1;
     repeated PulledAtomSubscription pulled = 2;
+    optional bool collect_uids = 3 [default = false];
 }
diff --git a/statsd/src/shell/shell_data.proto b/statsd/src/shell/shell_data.proto
index fdfbcc3b..b483e834 100644
--- a/statsd/src/shell/shell_data.proto
+++ b/statsd/src/shell/shell_data.proto
@@ -27,4 +27,5 @@ import "frameworks/proto_logging/stats/atoms.proto";
 message ShellData {
     repeated Atom atom = 1;
     repeated int64 elapsed_timestamp_nanos = 2 [packed = true];
+    repeated int32 logging_uid = 3 [packed = true];
 }
diff --git a/statsd/src/socket/BaseStatsSocketListener.cpp b/statsd/src/socket/BaseStatsSocketListener.cpp
new file mode 100644
index 00000000..8a3f67fd
--- /dev/null
+++ b/statsd/src/socket/BaseStatsSocketListener.cpp
@@ -0,0 +1,177 @@
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
+#define STATSD_DEBUG false  // STOPSHIP if true
+#include "Log.h"
+
+#include "BaseStatsSocketListener.h"
+
+#include <ctype.h>
+#include <cutils/sockets.h>
+#include <limits.h>
+#include <stdio.h>
+#include <sys/cdefs.h>
+#include <sys/prctl.h>
+#include <sys/socket.h>
+#include <sys/types.h>
+#include <sys/un.h>
+#include <thread>
+#include <unistd.h>
+
+#include "guardrail/StatsdStats.h"
+#include "android-base/scopeguard.h"
+#include "logd/logevent_util.h"
+#include "stats_log_util.h"
+#include "statslog_statsd.h"
+#include "utils/api_tracing.h"
+
+using namespace std;
+
+namespace android {
+namespace os {
+namespace statsd {
+BaseStatsSocketListener::BaseStatsSocketListener(const std::shared_ptr<LogEventQueue>& queue,
+                        const std::shared_ptr<LogEventFilter>& logEventFilter)
+                        : mQueue(queue),
+                          mLogEventFilter(logEventFilter){};
+
+tuple<int32_t, int64_t> BaseStatsSocketListener::processSocketMessage(void* buffer,
+                                                                  const uint32_t len, uint32_t uid,
+                                                                  uint32_t pid) {
+    ATRACE_CALL_DEBUG();
+    static const uint32_t kStatsEventTag = 1937006964;
+
+    if (len <= (ssize_t)(sizeof(android_log_header_t)) + sizeof(uint32_t)) {
+        return {-1, 0};
+    }
+
+    const uint8_t* ptr = ((uint8_t*)buffer) + sizeof(android_log_header_t);
+    uint32_t bufferLen = len - sizeof(android_log_header_t);
+
+    // When a log failed to write to statsd socket (e.g., due ot EBUSY), a special message would
+    // be sent to statsd when the socket communication becomes available again.
+    // The format is android_log_event_int_t with a single integer in the payload indicating the
+    // number of logs that failed. (*FORMAT MUST BE IN SYNC WITH system/core/libstats*)
+    // Note that all normal stats logs are in the format of event_list, so there won't be confusion.
+    //
+    // TODO(b/80538532): In addition to log it in StatsdStats, we should properly reset the config.
+    if (bufferLen == sizeof(android_log_event_long_t)) {
+        const android_log_event_long_t* long_event =
+                reinterpret_cast<const android_log_event_long_t*>(ptr);
+        if (long_event->payload.type == EVENT_TYPE_LONG) {
+            int64_t composed_long = long_event->payload.data;
+
+            // format:
+            // |last_tag|dropped_count|
+            int32_t dropped_count = (int32_t)(0xffffffff & composed_long);
+            int32_t last_atom_tag = (int32_t)((0xffffffff00000000 & (uint64_t)composed_long) >> 32);
+
+            ALOGE("Found dropped events: %d error %d last atom tag %d from uid %d", dropped_count,
+                  long_event->header.tag, last_atom_tag, uid);
+            StatsdStats::getInstance().noteLogLost((int32_t)getWallClockSec(), dropped_count,
+                                                   long_event->header.tag, last_atom_tag, uid, pid);
+            return {-1, 0};
+        }
+    }
+
+    // test that received valid StatsEvent buffer
+    const uint32_t statsEventTag = *reinterpret_cast<const uint32_t*>(ptr);
+    if (statsEventTag != kStatsEventTag) {
+        return {-1, 0};
+    }
+
+    // move past the 4-byte StatsEventTag
+    const uint8_t* msg = ptr + sizeof(uint32_t);
+    bufferLen -= sizeof(uint32_t);
+
+    return processStatsEventBuffer(msg, bufferLen, uid, pid, *mQueue, *mLogEventFilter);
+}
+
+tuple<int32_t, int64_t> BaseStatsSocketListener::processStatsEventBuffer(const uint8_t* msg,
+                                                                     const uint32_t len,
+                                                                     uint32_t uid, uint32_t pid,
+                                                                     LogEventQueue& queue,
+                                                                     const LogEventFilter& filter) {
+    ATRACE_CALL_DEBUG();
+    std::unique_ptr<LogEvent> logEvent = std::make_unique<LogEvent>(uid, pid);
+
+    if (filter.getFilteringEnabled()) {
+        const LogEvent::BodyBufferInfo bodyInfo = logEvent->parseHeader(msg, len);
+        if (filter.isAtomInUse(logEvent->GetTagId())) {
+            logEvent->parseBody(bodyInfo);
+        }
+    } else {
+        logEvent->parseBuffer(msg, len);
+    }
+
+    const int32_t atomId = logEvent->GetTagId();
+    const bool isAtomSkipped = logEvent->isParsedHeaderOnly();
+    const int64_t atomTimestamp = logEvent->GetElapsedTimestampNs();
+
+    // Tell StatsdStats about new event
+    StatsdStats::getInstance().noteAtomLogged(atomId, atomTimestamp, isAtomSkipped);
+
+    if (atomId == util::STATS_SOCKET_LOSS_REPORTED) {
+        if (isAtomSkipped) {
+            ALOGW("Atom STATS_SOCKET_LOSS_REPORTED should not be skipped");
+        }
+
+        // handling socket loss info reported atom
+        // processing it here to not lose info due to queue overflow
+        const std::optional<SocketLossInfo>& lossInfo = toSocketLossInfo(*logEvent);
+        if (lossInfo) {
+            StatsdStats::getInstance().noteAtomSocketLoss(*lossInfo);
+        } else {
+            ALOGW("Atom STATS_SOCKET_LOSS_REPORTED content is invalid");
+        }
+    }
+
+    const auto [success, oldestTimestamp, queueSize] = queue.push(std::move(logEvent));
+    if (success) {
+        StatsdStats::getInstance().noteEventQueueSize(queueSize, atomTimestamp);
+    } else {
+        StatsdStats::getInstance().noteEventQueueOverflow(oldestTimestamp, atomId);
+    }
+    return {atomId, atomTimestamp};
+}
+
+int BaseStatsSocketListener::getLogSocket() {
+    static const char socketName[] = "statsdw";
+    int sock = android_get_control_socket(socketName);
+
+    if (sock < 0) {  // statsd started up in init.sh
+        sock = socket_local_server(socketName, ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_DGRAM);
+
+        int on = 1;
+        if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on))) {
+            return -1;
+        }
+    }
+    return sock;
+}
+
+void BaseStatsSocketListener::noteBatchSocketRead(int32_t size, int64_t lastReadTimeNs,
+                                          int64_t currReadTimeNs, int64_t minAtomReadTimeNs,
+                                          int64_t maxAtomReadTimeNs,
+                                          const std::unordered_map <int32_t, int32_t> &atomCounts) {
+    StatsdStats::getInstance().noteBatchSocketRead(size, lastReadTimeNs, currReadTimeNs,
+                                               minAtomReadTimeNs, maxAtomReadTimeNs, atomCounts);
+    mLastSocketReadTimeNs = currReadTimeNs;
+    mAtomCounts.clear();
+}
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/socket/BaseStatsSocketListener.h b/statsd/src/socket/BaseStatsSocketListener.h
new file mode 100644
index 00000000..d64a2dee
--- /dev/null
+++ b/statsd/src/socket/BaseStatsSocketListener.h
@@ -0,0 +1,120 @@
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
+#pragma once
+
+#include <gtest/gtest_prod.h>
+#include <utils/RefBase.h>
+
+#include "LogEventFilter.h"
+#include "logd/LogEventQueue.h"
+
+// DEFAULT_OVERFLOWUID is defined in linux/highuid.h, which is not part of
+// the uapi headers for userspace to use.  This value is filled in on the
+// out-of-band socket credentials if the OS fails to find one available.
+// One of the causes of this is if SO_PASSCRED is set, all the packets before
+// that point will have this value.  We also use it in a fake credential if
+// no socket credentials are supplied.
+#ifndef DEFAULT_OVERFLOWUID
+#define DEFAULT_OVERFLOWUID 65534
+#endif
+
+namespace android {
+namespace os {
+namespace statsd {
+
+class BaseStatsSocketListener : public virtual RefBase {
+public:
+    /**
+     * Constructor of the BaseStatsSocketListener class
+     *
+     * @param queue queue to submit the event
+     * @param logEventFilter to be used for event evaluation
+     */
+    explicit BaseStatsSocketListener(const std::shared_ptr<LogEventQueue>& queue,
+                            const std::shared_ptr<LogEventFilter>& logEventFilter);
+protected:
+    static int getLogSocket();
+
+    /**
+     * @brief Helper API to parse raw socket data buffer, make the LogEvent & submit it into the
+     * queue. Performs preliminary data validation.
+     * Created as a separate API to be easily tested without StatsSocketListener instance
+     *
+     * @param buffer buffer to parse
+     * @param len size of buffer in bytes
+     * @param uid arguments for LogEvent constructor
+     * @param pid arguments for LogEvent constructor
+     * @param queue queue to submit the event
+     * @param filter to be used for event evaluation
+     * @return tuple of <atom id, elapsed time>
+     */
+    std::tuple<int32_t, int64_t> processSocketMessage(void* buffer, uint32_t len,
+                                                             uint32_t uid, uint32_t pid);
+
+
+
+    void noteBatchSocketRead(int32_t size, int64_t lastReadTimeNs, int64_t currReadTimeNs,
+                             int64_t minAtomReadTimeNs, int64_t maxAtomReadTimeNs,
+                             const std::unordered_map<int32_t, int32_t>& atomCounts);
+
+
+
+    int64_t mLastSocketReadTimeNs = 0;
+
+    // Tracks the atom counts per read. Member variable to avoid churn.
+    std::unordered_map<int32_t, int32_t> mAtomCounts;
+
+    /**
+     * Who is going to get the events when they're read.
+     */
+    std::shared_ptr<LogEventQueue> mQueue;
+
+    std::shared_ptr<LogEventFilter> mLogEventFilter;
+
+private:
+    /**
+     * @brief Helper API to parse buffer, make the LogEvent & submit it into the queue
+     * Created as a separate API to be easily tested without StatsSocketListener instance
+     *
+     * @param msg buffer to parse
+     * @param len size of buffer in bytes
+     * @param uid arguments for LogEvent constructor
+     * @param pid arguments for LogEvent constructor
+     * @param queue queue to submit the event
+     * @param filter to be used for event evaluation
+     * @return tuple of <atom id, elapsed time>
+     */
+    static std::tuple<int32_t, int64_t> processStatsEventBuffer(const uint8_t* msg, uint32_t len,
+                                                                uint32_t uid, uint32_t pid,
+                                                                LogEventQueue& queue,
+                                                                const LogEventFilter& filter);
+    friend void fuzzSocket(const uint8_t* data, size_t size);
+
+    friend class SocketParseMessageTest;
+    friend void generateAtomLogging(LogEventQueue& queue, const LogEventFilter& filter,
+                                    int eventCount, int startAtomId);
+
+    FRIEND_TEST(SocketParseMessageTest, TestProcessMessage);
+    FRIEND_TEST(SocketParseMessageTest, TestProcessMessageEmptySetExplicitSet);
+    FRIEND_TEST(SocketParseMessageTest, TestProcessMessageFilterCompleteSet);
+    FRIEND_TEST(SocketParseMessageTest, TestProcessMessageFilterPartialSet);
+    FRIEND_TEST(SocketParseMessageTest, TestProcessMessageFilterToggle);
+    FRIEND_TEST(LogEventQueue_test, TestQueueMaxSize);
+};
+
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/socket/StatsSocketListener.cpp b/statsd/src/socket/StatsSocketListener.cpp
index a42e4536..ccdbc8b7 100644
--- a/statsd/src/socket/StatsSocketListener.cpp
+++ b/statsd/src/socket/StatsSocketListener.cpp
@@ -43,14 +43,12 @@ namespace statsd {
 
 StatsSocketListener::StatsSocketListener(const std::shared_ptr<LogEventQueue>& queue,
                                          const std::shared_ptr<LogEventFilter>& logEventFilter)
-    : SocketListener(getLogSocket(), false /*start listen*/),
-      mQueue(queue),
-      mLogEventFilter(logEventFilter),
-      mLastSocketReadTimeNs(0) {
+    : BaseStatsSocketListener(queue, logEventFilter),
+      SocketListener(getLogSocket(), false /*start listen*/){
 }
 
 bool StatsSocketListener::onDataAvailable(SocketClient* cli) {
-    ATRACE_CALL();
+    ATRACE_CALL_DEBUG();
     static bool name_set;
     if (!name_set) {
         prctl(PR_SET_NAME, "statsd.writer");
@@ -107,133 +105,17 @@ bool StatsSocketListener::onDataAvailable(SocketClient* cli) {
         const uint32_t pid = cred->pid;
 
         auto [atomId, atomTimeNs] =
-                processSocketMessage(buffer, n, uid, pid, *mQueue, *mLogEventFilter);
+                processSocketMessage(buffer, n, uid, pid);
         mAtomCounts[atomId]++;
         minAtomReadTime = min(minAtomReadTime, atomTimeNs);
         maxAtomReadTime = max(maxAtomReadTime, atomTimeNs);
     }
 
-    StatsdStats::getInstance().noteBatchSocketRead(i, mLastSocketReadTimeNs, elapsedTimeNs,
-                                                   minAtomReadTime, maxAtomReadTime, mAtomCounts);
-    mLastSocketReadTimeNs = elapsedTimeNs;
-    mAtomCounts.clear();
+    noteBatchSocketRead(i, mLastSocketReadTimeNs, elapsedTimeNs, minAtomReadTime, maxAtomReadTime,
+                        mAtomCounts);
     return true;
 }
 
-tuple<int32_t, int64_t> StatsSocketListener::processSocketMessage(const char* buffer,
-                                                                  const uint32_t len, uint32_t uid,
-                                                                  uint32_t pid,
-                                                                  LogEventQueue& queue,
-                                                                  const LogEventFilter& filter) {
-    ATRACE_CALL();
-    static const uint32_t kStatsEventTag = 1937006964;
-
-    if (len <= (ssize_t)(sizeof(android_log_header_t)) + sizeof(uint32_t)) {
-        return {-1, 0};
-    }
-
-    const uint8_t* ptr = ((uint8_t*)buffer) + sizeof(android_log_header_t);
-    uint32_t bufferLen = len - sizeof(android_log_header_t);
-
-    // When a log failed to write to statsd socket (e.g., due ot EBUSY), a special message would
-    // be sent to statsd when the socket communication becomes available again.
-    // The format is android_log_event_int_t with a single integer in the payload indicating the
-    // number of logs that failed. (*FORMAT MUST BE IN SYNC WITH system/core/libstats*)
-    // Note that all normal stats logs are in the format of event_list, so there won't be confusion.
-    //
-    // TODO(b/80538532): In addition to log it in StatsdStats, we should properly reset the config.
-    if (bufferLen == sizeof(android_log_event_long_t)) {
-        const android_log_event_long_t* long_event =
-                reinterpret_cast<const android_log_event_long_t*>(ptr);
-        if (long_event->payload.type == EVENT_TYPE_LONG) {
-            int64_t composed_long = long_event->payload.data;
-
-            // format:
-            // |last_tag|dropped_count|
-            int32_t dropped_count = (int32_t)(0xffffffff & composed_long);
-            int32_t last_atom_tag = (int32_t)((0xffffffff00000000 & (uint64_t)composed_long) >> 32);
-
-            ALOGE("Found dropped events: %d error %d last atom tag %d from uid %d", dropped_count,
-                  long_event->header.tag, last_atom_tag, uid);
-            StatsdStats::getInstance().noteLogLost((int32_t)getWallClockSec(), dropped_count,
-                                                   long_event->header.tag, last_atom_tag, uid, pid);
-            return {-1, 0};
-        }
-    }
-
-    // test that received valid StatsEvent buffer
-    const uint32_t statsEventTag = *reinterpret_cast<const uint32_t*>(ptr);
-    if (statsEventTag != kStatsEventTag) {
-        return {-1, 0};
-    }
-
-    // move past the 4-byte StatsEventTag
-    const uint8_t* msg = ptr + sizeof(uint32_t);
-    bufferLen -= sizeof(uint32_t);
-
-    return processStatsEventBuffer(msg, bufferLen, uid, pid, queue, filter);
-}
-
-tuple<int32_t, int64_t> StatsSocketListener::processStatsEventBuffer(const uint8_t* msg,
-                                                                     const uint32_t len,
-                                                                     uint32_t uid, uint32_t pid,
-                                                                     LogEventQueue& queue,
-                                                                     const LogEventFilter& filter) {
-    ATRACE_CALL();
-    std::unique_ptr<LogEvent> logEvent = std::make_unique<LogEvent>(uid, pid);
-
-    if (filter.getFilteringEnabled()) {
-        const LogEvent::BodyBufferInfo bodyInfo = logEvent->parseHeader(msg, len);
-        if (filter.isAtomInUse(logEvent->GetTagId())) {
-            logEvent->parseBody(bodyInfo);
-        }
-    } else {
-        logEvent->parseBuffer(msg, len);
-    }
-
-    const int32_t atomId = logEvent->GetTagId();
-    const bool isAtomSkipped = logEvent->isParsedHeaderOnly();
-    const int64_t atomTimestamp = logEvent->GetElapsedTimestampNs();
-
-    if (atomId == util::STATS_SOCKET_LOSS_REPORTED) {
-        if (isAtomSkipped) {
-            ALOGW("Atom STATS_SOCKET_LOSS_REPORTED should not be skipped");
-        }
-
-        // handling socket loss info reported atom
-        // processing it here to not lose info due to queue overflow
-        const std::optional<SocketLossInfo>& lossInfo = toSocketLossInfo(*logEvent);
-        if (lossInfo) {
-            StatsdStats::getInstance().noteAtomSocketLoss(*lossInfo);
-        } else {
-            ALOGW("Atom STATS_SOCKET_LOSS_REPORTED content is invalid");
-        }
-    }
-
-    const auto [success, oldestTimestamp, queueSize] = queue.push(std::move(logEvent));
-    if (success) {
-        StatsdStats::getInstance().noteEventQueueSize(queueSize, atomTimestamp);
-    } else {
-        StatsdStats::getInstance().noteEventQueueOverflow(oldestTimestamp, atomId, isAtomSkipped);
-    }
-    return {atomId, atomTimestamp};
-}
-
-int StatsSocketListener::getLogSocket() {
-    static const char socketName[] = "statsdw";
-    int sock = android_get_control_socket(socketName);
-
-    if (sock < 0) {  // statsd started up in init.sh
-        sock = socket_local_server(socketName, ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_DGRAM);
-
-        int on = 1;
-        if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on))) {
-            return -1;
-        }
-    }
-    return sock;
-}
-
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/socket/StatsSocketListener.h b/statsd/src/socket/StatsSocketListener.h
index d688f524..cb39e8e4 100644
--- a/statsd/src/socket/StatsSocketListener.h
+++ b/statsd/src/socket/StatsSocketListener.h
@@ -21,22 +21,13 @@
 
 #include "LogEventFilter.h"
 #include "logd/LogEventQueue.h"
-
-// DEFAULT_OVERFLOWUID is defined in linux/highuid.h, which is not part of
-// the uapi headers for userspace to use.  This value is filled in on the
-// out-of-band socket credentials if the OS fails to find one available.
-// One of the causes of this is if SO_PASSCRED is set, all the packets before
-// that point will have this value.  We also use it in a fake credential if
-// no socket credentials are supplied.
-#ifndef DEFAULT_OVERFLOWUID
-#define DEFAULT_OVERFLOWUID 65534
-#endif
+#include "BaseStatsSocketListener.h"
 
 namespace android {
 namespace os {
 namespace statsd {
 
-class StatsSocketListener : public SocketListener, public virtual RefBase {
+class StatsSocketListener : public SocketListener, public virtual BaseStatsSocketListener {
 public:
     explicit StatsSocketListener(const std::shared_ptr<LogEventQueue>& queue,
                                  const std::shared_ptr<LogEventFilter>& logEventFilter);
@@ -45,69 +36,6 @@ public:
 
 protected:
     bool onDataAvailable(SocketClient* cli) override;
-
-private:
-    static int getLogSocket();
-
-    /**
-     * @brief Helper API to parse raw socket data buffer, make the LogEvent & submit it into the
-     * queue. Performs preliminary data validation.
-     * Created as a separate API to be easily tested without StatsSocketListener instance
-     *
-     * @param buffer buffer to parse
-     * @param len size of buffer in bytes
-     * @param uid arguments for LogEvent constructor
-     * @param pid arguments for LogEvent constructor
-     * @param queue queue to submit the event
-     * @param filter to be used for event evaluation
-     * @return tuple of <atom id, elapsed time>
-     */
-    static std::tuple<int32_t, int64_t> processSocketMessage(const char* buffer, uint32_t len,
-                                                             uint32_t uid, uint32_t pid,
-                                                             LogEventQueue& queue,
-                                                             const LogEventFilter& filter);
-
-    /**
-     * @brief Helper API to parse buffer, make the LogEvent & submit it into the queue
-     * Created as a separate API to be easily tested without StatsSocketListener instance
-     *
-     * @param msg buffer to parse
-     * @param len size of buffer in bytes
-     * @param uid arguments for LogEvent constructor
-     * @param pid arguments for LogEvent constructor
-     * @param queue queue to submit the event
-     * @param filter to be used for event evaluation
-     * @return tuple of <atom id, elapsed time>
-     */
-    static std::tuple<int32_t, int64_t> processStatsEventBuffer(const uint8_t* msg, uint32_t len,
-                                                                uint32_t uid, uint32_t pid,
-                                                                LogEventQueue& queue,
-                                                                const LogEventFilter& filter);
-
-    /**
-     * Who is going to get the events when they're read.
-     */
-    std::shared_ptr<LogEventQueue> mQueue;
-
-    std::shared_ptr<LogEventFilter> mLogEventFilter;
-
-    int64_t mLastSocketReadTimeNs;
-
-    // Tracks the atom counts per read. Member variable to avoid churn.
-    std::unordered_map<int32_t, int32_t> mAtomCounts;
-
-    friend void fuzzSocket(const uint8_t* data, size_t size);
-
-    friend class SocketParseMessageTest;
-    friend void generateAtomLogging(LogEventQueue& queue, const LogEventFilter& filter,
-                                    int eventCount, int startAtomId);
-
-    FRIEND_TEST(SocketParseMessageTest, TestProcessMessage);
-    FRIEND_TEST(SocketParseMessageTest, TestProcessMessageEmptySetExplicitSet);
-    FRIEND_TEST(SocketParseMessageTest, TestProcessMessageFilterCompleteSet);
-    FRIEND_TEST(SocketParseMessageTest, TestProcessMessageFilterPartialSet);
-    FRIEND_TEST(SocketParseMessageTest, TestProcessMessageFilterToggle);
-    FRIEND_TEST(LogEventQueue_test, TestQueueMaxSize);
 };
 
 }  // namespace statsd
diff --git a/statsd/src/stats_log.proto b/statsd/src/stats_log.proto
index 941e0ff9..63ace823 100644
--- a/statsd/src/stats_log.proto
+++ b/statsd/src/stats_log.proto
@@ -51,10 +51,18 @@ message StateValue {
   }
 }
 
+message AggregatedStateInfo {
+  repeated StateValue slice_by_state = 1;
+
+  repeated int64 elapsed_timestamp_nanos = 2;
+}
+
 message AggregatedAtomInfo {
     optional Atom atom = 1;
 
     repeated int64 elapsed_timestamp_nanos = 2;
+
+    repeated AggregatedStateInfo state_info = 3; // Only used when metrics have slice_by_state
 }
 
 message EventMetricData {
@@ -65,6 +73,8 @@ message EventMetricData {
   optional int64 wall_clock_timestamp_nanos = 3 [deprecated = true];
 
   optional AggregatedAtomInfo aggregated_atom_info = 4;
+
+  repeated StateValue slice_by_state = 5;
 }
 
 message CountBucketInfo {
@@ -157,6 +167,7 @@ message ValueBucketInfo {
           Histogram histogram = 5;
       }
       optional int32 sample_size = 4;
+      reserved 6;
   }
 
   repeated Value values = 9;
@@ -242,7 +253,6 @@ message GaugeBucketInfo {
 message GaugeMetricData {
   optional DimensionsValue dimensions_in_what = 1;
 
-  // Currently unsupported
   repeated StateValue slice_by_state = 6;
 
   repeated GaugeBucketInfo bucket_info = 3;
@@ -453,6 +463,11 @@ message StatsdStatsReport {
       repeated int64 condition_id = 8;
     }
 
+    message CounterStats {
+      optional CounterType counter_type = 1;
+      optional int32 count = 2;
+    }
+
     message MatcherStats {
         optional int64 id = 1;
         optional int32 matched_times = 2;
@@ -526,6 +541,7 @@ message StatsdStatsReport {
         optional int32 error_count = 3;
         optional int32 dropped_count = 4;
         optional int32 skip_count = 5;
+        optional int32 peak_rate = 6;
     }
 
     repeated AtomStats atom_stats = 7;
@@ -734,6 +750,12 @@ message StatsdStatsReport {
     }
 
     optional SocketReadStats socket_read_stats = 26;
+
+    message ErrorStats {
+        repeated CounterStats counters = 1;
+    }
+
+    optional ErrorStats error_stats = 27;
 }
 
 message AlertTriggerDetails {
diff --git a/statsd/src/stats_log_util.cpp b/statsd/src/stats_log_util.cpp
index 83e60d5c..43d6bc87 100644
--- a/statsd/src/stats_log_util.cpp
+++ b/statsd/src/stats_log_util.cpp
@@ -687,6 +687,18 @@ std::string toHexString(const string& bytes) {
     return hex;
 }
 
+vector<Matcher> translateFieldsFilter(const FieldFilter& fieldFilter) {
+    if (!fieldFilter.has_fields() && !fieldFilter.has_omit_fields()) {
+        return {};
+    }
+
+    vector<Matcher> fieldMatchers;
+    translateFieldMatcher(
+            fieldFilter.has_fields() ? fieldFilter.fields() : fieldFilter.omit_fields(),
+            &fieldMatchers);
+    return fieldMatchers;
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/stats_log_util.h b/statsd/src/stats_log_util.h
index d7a3987a..6520f8e1 100644
--- a/statsd/src/stats_log_util.h
+++ b/statsd/src/stats_log_util.h
@@ -130,6 +130,8 @@ void mapIsolatedUidsToHostUidInLogEvent(const sp<UidMap>& uidMap, LogEvent& even
 
 std::string toHexString(const string& bytes);
 
+std::vector<Matcher> translateFieldsFilter(const FieldFilter& fieldFilter);
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/src/statsd_config.proto b/statsd/src/statsd_config.proto
index f110dd87..6fdeb08f 100644
--- a/statsd/src/statsd_config.proto
+++ b/statsd/src/statsd_config.proto
@@ -213,7 +213,11 @@ message MetricStateLink {
 
 message FieldFilter {
   optional bool include_all = 1 [default = false];
-  optional FieldMatcher fields = 2;
+
+  oneof field_matcher {
+      FieldMatcher fields = 2;
+      FieldMatcher omit_fields = 3;
+  }
 }
 
 message UploadThreshold {
@@ -240,12 +244,18 @@ message EventMetric {
 
   optional int64 condition = 3;
 
+  repeated int64 slice_by_state = 7;
+
   repeated MetricConditionLink links = 4;
 
+  repeated MetricStateLink state_link = 8;
+
   optional int32 sampling_percentage = 5 [default = 100];
 
   optional FieldMatcher uid_fields = 6;
 
+  optional FieldFilter fields_filter = 9;
+
   reserved 100;
   reserved 101;
 }
@@ -334,6 +344,8 @@ message GaugeMetric {
 
   optional int64 condition = 4;
 
+  repeated int64 slice_by_state = 20;
+
   optional FieldMatcher dimensions_in_what = 5;
 
   optional FieldMatcher dimensions_in_condition = 8 [deprecated = true];
@@ -342,6 +354,8 @@ message GaugeMetric {
 
   repeated MetricConditionLink links = 7;
 
+  repeated MetricStateLink state_link = 21;
+
   enum SamplingType {
     RANDOM_ONE_SAMPLE = 1;
     ALL_CONDITION_CHANGES = 2 [deprecated = true];
diff --git a/statsd/src/utils/api_tracing.h b/statsd/src/utils/api_tracing.h
index 69edeae8..78f726dd 100644
--- a/statsd/src/utils/api_tracing.h
+++ b/statsd/src/utils/api_tracing.h
@@ -19,3 +19,9 @@
 #define ATRACE_TAG ATRACE_TAG_APP
 
 #include <utils/Trace.h>
+
+// Use the local value to turn on/off atrace logs.
+// The advantage is that in production compiler can remove the logging code if the local
+// STATSD_DEBUG/VERBOSE is false.
+#define ATRACE_CALL_DEBUG(...) \
+    if (STATSD_DEBUG) ATRACE_CALL(__VA_ARGS__);
diff --git a/statsd/tests/DataCorruptionReason_test.cpp b/statsd/tests/DataCorruptionReason_test.cpp
index 70e0dcf6..9e6b10d0 100644
--- a/statsd/tests/DataCorruptionReason_test.cpp
+++ b/statsd/tests/DataCorruptionReason_test.cpp
@@ -328,11 +328,8 @@ protected:
 };
 
 TEST_F(DataCorruptionQueueOverflowTest, TestNotifyOnlyInterestedMetrics) {
-    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId,
-                                                      /*isSkipped*/ false);
-
-    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kUnusedAtomId,
-                                                      /*isSkipped*/ false);
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId);
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kUnusedAtomId);
 
     EXPECT_TRUE(mMetricsManager->mQueueOverflowAtomsStats.empty());
     ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
@@ -352,8 +349,7 @@ TEST_F(DataCorruptionQueueOverflowTest, TestNotifyOnlyInterestedMetrics) {
 }
 
 TEST_F(DataCorruptionQueueOverflowTest, TestNotifyInterestedMetricsWithNewLoss) {
-    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId,
-                                                      /*isSkipped*/ false);
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId);
 
     ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
@@ -370,8 +366,7 @@ TEST_F(DataCorruptionQueueOverflowTest, TestNotifyInterestedMetricsWithNewLoss)
     }
 
     // new dropped event as result event metric should be notified about loss events
-    StatsdStats::getInstance().noteEventQueueOverflow(kReportRequestTimeNs + 100, kInterestAtomId,
-                                                      /*isSkipped*/ false);
+    StatsdStats::getInstance().noteEventQueueOverflow(kReportRequestTimeNs + 100, kInterestAtomId);
 
     metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs + 200);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
@@ -389,8 +384,7 @@ TEST_F(DataCorruptionQueueOverflowTest, TestNotifyInterestedMetricsWithNewLoss)
 }
 
 TEST_F(DataCorruptionQueueOverflowTest, TestDoNotNotifyInterestedMetricsIfNoUpdate) {
-    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId,
-                                                      /*isSkipped*/ false);
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId);
 
     ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
@@ -419,10 +413,8 @@ TEST_F(DataCorruptionQueueOverflowTest, TestDoNotNotifyInterestedMetricsIfNoUpda
 TEST_F(DataCorruptionQueueOverflowTest, TestDoNotNotifyNewInterestedMetricsIfNoUpdate) {
     const int32_t kNewInterestAtomId = kUnusedAtomId + 1;
 
-    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId,
-                                                      /*isSkipped*/ false);
-    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kNewInterestAtomId,
-                                                      /*isSkipped*/ false);
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kInterestAtomId);
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, kNewInterestAtomId);
 
     ConfigMetricsReport metricsReport = getMetricsReport(*mMetricsManager, kReportRequestTimeNs);
     ASSERT_EQ(metricsReport.metrics_size(), 2);
@@ -550,8 +542,7 @@ TEST(DataCorruptionTest, TestStateLostFromQueueOverflowPropagation) {
     EXPECT_EQ(1, StateManager::getInstance().getStateTrackersCount());
     EXPECT_EQ(1, StateManager::getInstance().getListenersCount(SCREEN_STATE_ATOM_ID));
 
-    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, SCREEN_STATE_ATOM_ID,
-                                                      /*isSkipped*/ false);
+    StatsdStats::getInstance().noteEventQueueOverflow(kAtomsLogTimeNs, SCREEN_STATE_ATOM_ID);
 
     vector<uint8_t> buffer;
     ConfigMetricsReportList reports;
diff --git a/statsd/tests/StatsLogProcessor_test.cpp b/statsd/tests/StatsLogProcessor_test.cpp
index 1d341bbc..43ef4ddb 100644
--- a/statsd/tests/StatsLogProcessor_test.cpp
+++ b/statsd/tests/StatsLogProcessor_test.cpp
@@ -2149,8 +2149,7 @@ TEST(StatsLogProcessorTest, TestDataCorruptedEnum) {
     StatsdConfig config = MakeConfig(true);
     sp<StatsLogProcessor> processor = CreateStatsLogProcessor(1, 1, config, cfgKey);
 
-    StatsdStats::getInstance().noteEventQueueOverflow(/*oldestEventTimestampNs=*/0, /*atomId=*/100,
-                                                      /*isSkipped=*/false);
+    StatsdStats::getInstance().noteEventQueueOverflow(/*oldestEventTimestampNs=*/0, /*atomId=*/100);
     StatsdStats::getInstance().noteLogLost(/*wallClockTimeSec=*/0, /*count=*/1, /*lastError=*/0,
                                            /*lastTag=*/0, /*uid=*/0, /*pid=*/0);
     vector<uint8_t> bytes;
diff --git a/statsd/tests/e2e/EventMetric_e2e_test.cpp b/statsd/tests/e2e/EventMetric_e2e_test.cpp
index 1ee4b696..36f3a75a 100644
--- a/statsd/tests/e2e/EventMetric_e2e_test.cpp
+++ b/statsd/tests/e2e/EventMetric_e2e_test.cpp
@@ -344,6 +344,694 @@ TEST_F(EventMetricE2eTest, TestEventMetricSampling) {
     ASSERT_EQ(metricReport.event_metrics().data_size(), 46);
 }
 
+/**
+ * Test an event metric that has one slice_by_state with no primary fields.
+ *
+ * Once the EventMetricProducer is initialized, it has one atom id in
+ * mSlicedStateAtoms and no entries in mStateGroupMap.
+
+ * One StateTracker tracks the state atom, and it has one listener which is the
+ * EventMetricProducer that was initialized.
+ */
+TEST_F(EventMetricE2eTest, TestSlicedState) {
+    // Initialize config.
+    StatsdConfig config;
+
+    auto syncStartMatcher = CreateSyncStartAtomMatcher();
+    *config.add_atom_matcher() = syncStartMatcher;
+
+    auto state = CreateScreenState();
+    *config.add_state() = state;
+
+    // Create event metric that slices by screen state.
+    EventMetric syncStateEventMetric =
+            createEventMetric("SyncStartReported", syncStartMatcher.id(), nullopt, {state.id()});
+    *config.add_event_metric() = syncStateEventMetric;
+
+    // Initialize StatsLogProcessor.
+    const uint64_t bucketStartTimeNs = 10000000000;  // 0:10
+    ConfigKey key(123, 987);
+    auto processor = CreateStatsLogProcessor(bucketStartTimeNs, bucketStartTimeNs, config, key);
+
+    // Check that EventMetricProducer was initialized correctly.
+    ASSERT_EQ(processor->mMetricsManagers.size(), 1u);
+    sp<MetricsManager> metricsManager = processor->mMetricsManagers.begin()->second;
+    EXPECT_TRUE(metricsManager->isConfigValid());
+    ASSERT_EQ(metricsManager->mAllMetricProducers.size(), 1);
+    sp<MetricProducer> metricProducer = metricsManager->mAllMetricProducers[0];
+    ASSERT_EQ(metricProducer->mSlicedStateAtoms.size(), 1);
+    EXPECT_EQ(metricProducer->mSlicedStateAtoms.at(0), SCREEN_STATE_ATOM_ID);
+    ASSERT_EQ(metricProducer->mStateGroupMap.size(), 0);
+
+    // Check that StateTrackers were initialized correctly.
+    EXPECT_EQ(1, StateManager::getInstance().getStateTrackersCount());
+    EXPECT_EQ(1, StateManager::getInstance().getListenersCount(SCREEN_STATE_ATOM_ID));
+
+    // Initialize log events.
+    std::vector<int> attributionUids1 = {123};
+    std::vector<string> attributionTags1 = {"App1"};
+
+    std::vector<std::unique_ptr<LogEvent>> events;
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 50 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_ON));  // 1:00
+    events.push_back(CreateSyncStartEvent(bucketStartTimeNs + 75 * NS_PER_SEC, attributionUids1,
+                                          attributionTags1, "sync_name"));  // 1:25
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 200 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_OFF));  // 3:30
+    events.push_back(CreateSyncStartEvent(bucketStartTimeNs + 250 * NS_PER_SEC, attributionUids1,
+                                          attributionTags1, "sync_name"));  // 4:20
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    // Check dump report.
+    uint64_t dumpTimeNs = bucketStartTimeNs + 2000 * NS_PER_SEC;
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(key, dumpTimeNs, true, true, ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_EQ(metricReport.metric_id(), syncStateEventMetric.id());
+    EXPECT_TRUE(metricReport.has_event_metrics());
+    ASSERT_EQ(metricReport.event_metrics().data_size(), 2);
+
+    // For each EventMetricData, check StateValue info is correct
+    EventMetricData data = metricReport.event_metrics().data(0);
+
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 75 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_value());
+    EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_ON, data.slice_by_state(0).value());
+
+    data = metricReport.event_metrics().data(1);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 250 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_value());
+    EXPECT_EQ(android::view::DisplayStateEnum::DISPLAY_STATE_OFF, data.slice_by_state(0).value());
+}
+
+/**
+ * Test an event metric that has one slice_by_state with a mapping and no
+ * primary fields.
+ *
+ * Once the EventMetricProducer is initialized, it has one atom id in
+ * mSlicedStateAtoms and has one entry per state value in mStateGroupMap.
+ *
+ * One StateTracker tracks the state atom, and it has one listener which is the
+ * EventMetricProducer that was initialized.
+ */
+TEST_F(EventMetricE2eTest, TestSlicedStateWithMap) {
+    // Initialize config.
+    StatsdConfig config;
+
+    auto syncStartMatcher = CreateSyncStartAtomMatcher();
+    *config.add_atom_matcher() = syncStartMatcher;
+
+    int64_t screenOnId = 4444;
+    int64_t screenOffId = 9876;
+    auto state = CreateScreenStateWithOnOffMap(screenOnId, screenOffId);
+    *config.add_state() = state;
+
+    // Create event metric that slices by screen state with on/off map.
+    EventMetric syncStateEventMetric =
+            createEventMetric("SyncStartReported", syncStartMatcher.id(), nullopt, {state.id()});
+    *config.add_event_metric() = syncStateEventMetric;
+
+    // Initialize StatsLogProcessor.
+    const uint64_t bucketStartTimeNs = 10000000000;  // 0:10
+    ConfigKey key(123, 987);
+    auto processor = CreateStatsLogProcessor(bucketStartTimeNs, bucketStartTimeNs, config, key);
+
+    /*
+    |     1     2     3     4(minutes)
+    |-----------------------|-
+      x   x     x       x     (syncStartEvents)
+     -------------------------SCREEN_OFF events
+             |                (ScreenStateOffEvent = 1)
+         |                    (ScreenStateDozeEvent = 3)
+     -------------------------SCREEN_ON events
+       |                      (ScreenStateOnEvent = 2)
+                      |       (ScreenStateVrEvent = 5)
+
+    Based on the diagram above, a Sync Start Event querying for Screen State would return:
+    - Event 0: StateTracker::kStateUnknown
+    - Event 1: Off
+    - Event 2: Off
+    - Event 3: On
+    */
+    // Initialize log events
+    std::vector<int> attributionUids1 = {123};
+    std::vector<string> attributionTags1 = {"App1"};
+
+    std::vector<std::unique_ptr<LogEvent>> events;
+    events.push_back(CreateSyncStartEvent(bucketStartTimeNs + 20 * NS_PER_SEC, attributionUids1,
+                                          attributionTags1, "sync_name"));  // 0:30
+    // Event 0 Occurred
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 30 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_ON));  // 0:40
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 50 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_DOZE));  // 1:00
+    events.push_back(CreateSyncStartEvent(bucketStartTimeNs + 60 * NS_PER_SEC, attributionUids1,
+                                          attributionTags1, "sync_name"));  // 1:10
+    // Event 1 Occurred
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 90 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_OFF));  // 1:40
+    events.push_back(CreateSyncStartEvent(bucketStartTimeNs + 120 * NS_PER_SEC, attributionUids1,
+                                          attributionTags1, "sync_name"));  // 2:10
+    // Event 2 Occurred
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 180 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_VR));  // 3:10
+    events.push_back(CreateSyncStartEvent(bucketStartTimeNs + 200 * NS_PER_SEC, attributionUids1,
+                                          attributionTags1, "sync_name"));  // 3:30
+    // Event 3 Occurred
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    // Check dump report.
+    uint64_t dumpTimeNs = bucketStartTimeNs + 2000 * NS_PER_SEC;
+    vector<uint8_t> buffer;
+    ConfigMetricsReportList reports;
+    processor->onDumpReport(key, dumpTimeNs, false, true, ADB_DUMP, FAST, &buffer);
+    ASSERT_GT(buffer.size(), 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_EQ(metricReport.metric_id(), syncStateEventMetric.id());
+    EXPECT_TRUE(metricReport.has_event_metrics());
+    ASSERT_EQ(metricReport.event_metrics().data_size(), 4);
+
+    // For each EventMetricData, check StateValue info is correct
+    EventMetricData data = metricReport.event_metrics().data(0);
+
+    // StateTracker::kStateUnknown
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 20 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_value());
+    EXPECT_EQ(-1 /* StateTracker::kStateUnknown */, data.slice_by_state(0).value());
+
+    // Off
+    data = metricReport.event_metrics().data(1);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 60 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_group_id());
+    EXPECT_EQ(screenOffId, data.slice_by_state(0).group_id());
+
+    // Off
+    data = metricReport.event_metrics().data(2);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 120 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_group_id());
+    EXPECT_EQ(screenOffId, data.slice_by_state(0).group_id());
+
+    // On
+    data = metricReport.event_metrics().data(3);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 200 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_group_id());
+    EXPECT_EQ(screenOnId, data.slice_by_state(0).group_id());
+}
+
+/**
+* Test an event metric that has one slice_by_state with a primary field.
+
+* Once the EventMetricProducer is initialized, it should have one
+* MetricStateLink stored. State querying using a non-empty primary key
+* should also work as intended.
+*/
+TEST_F(EventMetricE2eTest, TestSlicedStateWithPrimaryFields) {
+    // Initialize config.
+    StatsdConfig config;
+
+    auto appCrashMatcher = CreateSimpleAtomMatcher("APP_CRASH_OCCURRED", util::APP_CRASH_OCCURRED);
+    *config.add_atom_matcher() = appCrashMatcher;
+
+    auto state = CreateUidProcessState();
+    *config.add_state() = state;
+
+    // Create event metric that slices by uid process state.
+    EventMetric appCrashEventMetric =
+            createEventMetric("AppCrashReported", appCrashMatcher.id(), nullopt, {state.id()});
+    MetricStateLink* stateLink = appCrashEventMetric.add_state_link();
+    stateLink->set_state_atom_id(UID_PROCESS_STATE_ATOM_ID);
+    auto fieldsInWhat = stateLink->mutable_fields_in_what();
+    *fieldsInWhat = CreateDimensions(util::APP_CRASH_OCCURRED, {1 /*uid*/});
+    auto fieldsInState = stateLink->mutable_fields_in_state();
+    *fieldsInState = CreateDimensions(UID_PROCESS_STATE_ATOM_ID, {1 /*uid*/});
+    *config.add_event_metric() = appCrashEventMetric;
+
+    // Initialize StatsLogProcessor.
+    const uint64_t bucketStartTimeNs = 10000000000;  // 0:10
+    ConfigKey key(123, 987);
+    auto processor = CreateStatsLogProcessor(bucketStartTimeNs, bucketStartTimeNs, config, key);
+
+    /*
+    NOTE: "1" or "2" represents the uid associated with the state/app crash event
+    |    1    2    3
+    |--------------|-
+      1   1       2 1(AppCrashEvents)
+     ----------------PROCESS STATE events
+            2        (TopEvent = 1002)
+       1             (ImportantForegroundEvent = 1005)
+
+    Based on the diagram above, an AppCrashEvent querying for process state value would return:
+    - Event 0: StateTracker::kStateUnknown
+    - Event 1: Important Foreground
+    - Event 2: Top
+    - Event 3: Important Foreground
+    */
+    // Initialize log events
+    std::vector<std::unique_ptr<LogEvent>> events;
+    events.push_back(
+            CreateAppCrashOccurredEvent(bucketStartTimeNs + 20 * NS_PER_SEC, 1 /*uid*/));  // 0:30
+    // Event 0 Occurred
+    events.push_back(CreateUidProcessStateChangedEvent(
+            bucketStartTimeNs + 30 * NS_PER_SEC, 1 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND));  // 0:40
+    events.push_back(
+            CreateAppCrashOccurredEvent(bucketStartTimeNs + 60 * NS_PER_SEC, 1 /*uid*/));  // 1:10
+    // Event 1 Occurred
+    events.push_back(CreateUidProcessStateChangedEvent(
+            bucketStartTimeNs + 90 * NS_PER_SEC, 2 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_TOP));  // 1:40
+    events.push_back(
+            CreateAppCrashOccurredEvent(bucketStartTimeNs + 160 * NS_PER_SEC, 2 /*uid*/));  // 2:50
+    // Event 2 Occurred
+    events.push_back(
+            CreateAppCrashOccurredEvent(bucketStartTimeNs + 180 * NS_PER_SEC, 1 /*uid*/));  // 3:10
+    // Event 3 Occurred
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    // Check dump report.
+    uint64_t dumpTimeNs = bucketStartTimeNs + 2000 * NS_PER_SEC;
+    vector<uint8_t> buffer;
+    ConfigMetricsReportList reports;
+    processor->onDumpReport(key, dumpTimeNs, false, true, ADB_DUMP, FAST, &buffer);
+    ASSERT_GT(buffer.size(), 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_EQ(metricReport.metric_id(), appCrashEventMetric.id());
+    EXPECT_TRUE(metricReport.has_event_metrics());
+    ASSERT_EQ(metricReport.event_metrics().data_size(), 4);
+
+    // For each EventMetricData, check StateValue info is correct
+    EventMetricData data = metricReport.event_metrics().data(0);
+
+    // StateTracker::kStateUnknown
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 20 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(UID_PROCESS_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_value());
+    EXPECT_EQ(-1 /* StateTracker::kStateUnknown */, data.slice_by_state(0).value());
+
+    // Important Foreground
+    data = metricReport.event_metrics().data(1);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 60 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(UID_PROCESS_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_value());
+    EXPECT_EQ(android::app::PROCESS_STATE_IMPORTANT_FOREGROUND, data.slice_by_state(0).value());
+
+    // Top
+    data = metricReport.event_metrics().data(2);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 160 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(UID_PROCESS_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_value());
+    EXPECT_EQ(android::app::PROCESS_STATE_TOP, data.slice_by_state(0).value());
+
+    // Important Foreground
+    data = metricReport.event_metrics().data(3);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 180 * NS_PER_SEC);
+    ASSERT_EQ(1, data.slice_by_state_size());
+    EXPECT_EQ(UID_PROCESS_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_value());
+    EXPECT_EQ(android::app::PROCESS_STATE_IMPORTANT_FOREGROUND, data.slice_by_state(0).value());
+}
+
+TEST_F(EventMetricE2eTest, TestMultipleSlicedStates) {
+    // Initialize config.
+    StatsdConfig config;
+
+    auto appCrashMatcher = CreateSimpleAtomMatcher("APP_CRASH_OCCURRED", util::APP_CRASH_OCCURRED);
+    *config.add_atom_matcher() = appCrashMatcher;
+
+    int64_t screenOnId = 4444;
+    int64_t screenOffId = 9876;
+    auto state1 = CreateScreenStateWithOnOffMap(screenOnId, screenOffId);
+    *config.add_state() = state1;
+    auto state2 = CreateUidProcessState();
+    *config.add_state() = state2;
+
+    // Create event metric that slices by screen state with on/off map and
+    // slices by uid process state.
+    EventMetric appCrashEventMetric = createEventMetric("AppCrashReported", appCrashMatcher.id(),
+                                                        nullopt, {state1.id(), state2.id()});
+    MetricStateLink* stateLink = appCrashEventMetric.add_state_link();
+    stateLink->set_state_atom_id(UID_PROCESS_STATE_ATOM_ID);
+    auto fieldsInWhat = stateLink->mutable_fields_in_what();
+    *fieldsInWhat = CreateDimensions(util::APP_CRASH_OCCURRED, {1 /*uid*/});
+    auto fieldsInState = stateLink->mutable_fields_in_state();
+    *fieldsInState = CreateDimensions(UID_PROCESS_STATE_ATOM_ID, {1 /*uid*/});
+    *config.add_event_metric() = appCrashEventMetric;
+
+    // Initialize StatsLogProcessor.
+    const uint64_t bucketStartTimeNs = 10000000000;  // 0:10
+    ConfigKey key(123, 987);
+    auto processor = CreateStatsLogProcessor(bucketStartTimeNs, bucketStartTimeNs, config, key);
+
+    /*
+      |    1    2    3  (minutes)
+      |-----------------
+        1  1    1     1 (AppCrashEvents)
+       -----------------SCREEN_OFF events
+             |          (ScreenOffEvent = 1)
+         |              (ScreenDozeEvent = 3)
+       -----------------SCREEN_ON events
+                   |    (ScreenOnEvent = 2)
+       -----------------PROCESS STATE events
+             1          (TopEvent = 1002)
+       1          1     (ImportantForegroundEvent = 1005)
+
+       Based on the diagram above, Screen State / Process State pairs for each
+       AppCrashEvent are:
+       - 0: StateTracker::kStateUnknown / Important Foreground
+       - 1: Off / Important Foreground
+       - 2: Off / Top
+       - 3: On  / Important Foreground
+      */
+
+    // Initialize log events
+    std::vector<std::unique_ptr<LogEvent>> events;
+    events.push_back(CreateUidProcessStateChangedEvent(
+            bucketStartTimeNs + 5 * NS_PER_SEC, 1 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND));  // 0:15
+    events.push_back(
+            CreateAppCrashOccurredEvent(bucketStartTimeNs + 20 * NS_PER_SEC, 1 /*uid*/));  // 0:30
+    // Event 0 Occurred
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 30 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_DOZE));  // 0:40
+    events.push_back(
+            CreateAppCrashOccurredEvent(bucketStartTimeNs + 60 * NS_PER_SEC, 1 /*uid*/));  // 1:10
+    // Event 1 Occurred
+    events.push_back(CreateUidProcessStateChangedEvent(
+            bucketStartTimeNs + 90 * NS_PER_SEC, 1 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_TOP));  // 1:40
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 90 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_OFF));  // 1:40
+    events.push_back(
+            CreateAppCrashOccurredEvent(bucketStartTimeNs + 120 * NS_PER_SEC, 1 /*uid*/));  // 2:10
+    // Event 2 Occurred
+    events.push_back(CreateUidProcessStateChangedEvent(
+            bucketStartTimeNs + 150 * NS_PER_SEC, 1 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND));  // 2:40
+    events.push_back(CreateScreenStateChangedEvent(
+            bucketStartTimeNs + 160 * NS_PER_SEC,
+            android::view::DisplayStateEnum::DISPLAY_STATE_ON));  // 2:50
+    events.push_back(
+            CreateAppCrashOccurredEvent(bucketStartTimeNs + 200 * NS_PER_SEC, 1 /*uid*/));  // 3:30
+    // Event 3 Occurred
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    // Check dump report.
+    uint64_t dumpTimeNs = bucketStartTimeNs + 2000 * NS_PER_SEC;
+    vector<uint8_t> buffer;
+    ConfigMetricsReportList reports;
+    processor->onDumpReport(key, dumpTimeNs, false, true, ADB_DUMP, FAST, &buffer);
+    ASSERT_GT(buffer.size(), 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_EQ(metricReport.metric_id(), appCrashEventMetric.id());
+    EXPECT_TRUE(metricReport.has_event_metrics());
+    ASSERT_EQ(metricReport.event_metrics().data_size(), 4);
+
+    // For each EventMetricData, check StateValue info is correct
+    EventMetricData data = metricReport.event_metrics().data(0);
+
+    // Screen State: StateTracker::kStateUnknown
+    // Process State: Important Foreground
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 20 * NS_PER_SEC);
+    ASSERT_EQ(2, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_value());
+    EXPECT_EQ(-1 /* StateTracker::kStateUnknown */, data.slice_by_state(0).value());
+    EXPECT_EQ(UID_PROCESS_STATE_ATOM_ID, data.slice_by_state(1).atom_id());
+    EXPECT_TRUE(data.slice_by_state(1).has_value());
+    EXPECT_EQ(android::app::PROCESS_STATE_IMPORTANT_FOREGROUND, data.slice_by_state(1).value());
+
+    // Screen State: Off
+    // Process State: Important Foreground
+    data = metricReport.event_metrics().data(1);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 60 * NS_PER_SEC);
+    ASSERT_EQ(2, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_group_id());
+    EXPECT_EQ(screenOffId, data.slice_by_state(0).group_id());
+    EXPECT_EQ(UID_PROCESS_STATE_ATOM_ID, data.slice_by_state(1).atom_id());
+    EXPECT_TRUE(data.slice_by_state(1).has_value());
+    EXPECT_EQ(android::app::PROCESS_STATE_IMPORTANT_FOREGROUND, data.slice_by_state(1).value());
+
+    // Screen State: Off
+    // Process State: Top
+    data = metricReport.event_metrics().data(2);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 120 * NS_PER_SEC);
+    ASSERT_EQ(2, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_group_id());
+    EXPECT_EQ(screenOffId, data.slice_by_state(0).group_id());
+    EXPECT_EQ(UID_PROCESS_STATE_ATOM_ID, data.slice_by_state(1).atom_id());
+    EXPECT_TRUE(data.slice_by_state(1).has_value());
+    EXPECT_EQ(android::app::PROCESS_STATE_TOP, data.slice_by_state(1).value());
+
+    // Screen State: On
+    // Process State: Important Foreground
+    data = metricReport.event_metrics().data(3);
+    EXPECT_EQ(data.elapsed_timestamp_nanos(), bucketStartTimeNs + 200 * NS_PER_SEC);
+    ASSERT_EQ(2, data.slice_by_state_size());
+    EXPECT_EQ(SCREEN_STATE_ATOM_ID, data.slice_by_state(0).atom_id());
+    EXPECT_TRUE(data.slice_by_state(0).has_group_id());
+    EXPECT_EQ(screenOnId, data.slice_by_state(0).group_id());
+    EXPECT_EQ(UID_PROCESS_STATE_ATOM_ID, data.slice_by_state(1).atom_id());
+    EXPECT_TRUE(data.slice_by_state(1).has_value());
+    EXPECT_EQ(android::app::PROCESS_STATE_IMPORTANT_FOREGROUND, data.slice_by_state(1).value());
+}
+
+TEST_F(EventMetricE2eTest, TestEventMetricFieldsFilter) {
+    StatsdConfig config;
+
+    AtomMatcher testAtomReportedAtomMatcher =
+            CreateSimpleAtomMatcher("TestAtomReportedMatcher", util::TEST_ATOM_REPORTED);
+    *config.add_atom_matcher() = testAtomReportedAtomMatcher;
+
+    EventMetric metric =
+            createEventMetric("EventTestAtomReported", testAtomReportedAtomMatcher.id(), nullopt);
+    metric.mutable_fields_filter()->mutable_fields()->set_field(util::TEST_ATOM_REPORTED);
+    metric.mutable_fields_filter()->mutable_fields()->add_child()->set_field(2);  // int_field
+    *config.add_event_metric() = metric;
+
+    ConfigKey key(123, 987);
+    uint64_t bucketStartTimeNs = 10000000000;  // 0:10
+    sp<StatsLogProcessor> processor =
+            CreateStatsLogProcessor(bucketStartTimeNs, bucketStartTimeNs, config, key);
+
+    // Initialize log events before update.
+    std::vector<std::unique_ptr<LogEvent>> events;
+
+    events.push_back(CreateTestAtomReportedEventWithPrimitives(
+            bucketStartTimeNs + 10 * NS_PER_SEC, 1 /* intField */, 1l /* longField */,
+            1.0f /* floatField */, "string_field1", false /* boolField */,
+            TestAtomReported::OFF /* enumField */));
+    events.push_back(CreateTestAtomReportedEventWithPrimitives(
+            bucketStartTimeNs + 20 * NS_PER_SEC, 2 /* intField */, 2l /* longField */,
+            2.0f /* floatField */, "string_field2", true /* boolField */,
+            TestAtomReported::ON /* enumField */));
+    events.push_back(CreateTestAtomReportedEventWithPrimitives(
+            bucketStartTimeNs + 30 * NS_PER_SEC, 3 /* intField */, 3l /* longField */,
+            3.0f /* floatField */, "string_field3", false /* boolField */,
+            TestAtomReported::ON /* enumField */));
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    uint64_t dumpTimeNs = bucketStartTimeNs + 100 * NS_PER_SEC;
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(key, dumpTimeNs, true, true, ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport testAtomEventMetricReport = report.metrics(0);
+    EXPECT_EQ(testAtomEventMetricReport.metric_id(), metric.id());
+    EXPECT_TRUE(testAtomEventMetricReport.has_event_metrics());
+    ASSERT_EQ(testAtomEventMetricReport.event_metrics().data_size(), 3);
+
+    TestAtomReported atom =
+            testAtomEventMetricReport.event_metrics().data(0).atom().test_atom_reported();
+    EXPECT_EQ(atom.int_field(), 1);
+    EXPECT_FALSE(atom.has_long_field());
+    EXPECT_FALSE(atom.has_float_field());
+    EXPECT_FALSE(atom.has_string_field());
+    EXPECT_FALSE(atom.has_boolean_field());
+    EXPECT_FALSE(atom.has_state());
+
+    atom = testAtomEventMetricReport.event_metrics().data(1).atom().test_atom_reported();
+    EXPECT_EQ(atom.int_field(), 2);
+    EXPECT_FALSE(atom.has_long_field());
+    EXPECT_FALSE(atom.has_float_field());
+    EXPECT_FALSE(atom.has_string_field());
+    EXPECT_FALSE(atom.has_boolean_field());
+    EXPECT_FALSE(atom.has_state());
+
+    atom = testAtomEventMetricReport.event_metrics().data(2).atom().test_atom_reported();
+    EXPECT_EQ(atom.int_field(), 3);
+    EXPECT_FALSE(atom.has_long_field());
+    EXPECT_FALSE(atom.has_float_field());
+    EXPECT_FALSE(atom.has_string_field());
+    EXPECT_FALSE(atom.has_boolean_field());
+    EXPECT_FALSE(atom.has_state());
+}
+
+TEST_F(EventMetricE2eTest, TestEventMetricFieldsFilterOmit) {
+    StatsdConfig config;
+
+    AtomMatcher testAtomReportedAtomMatcher =
+            CreateSimpleAtomMatcher("TestAtomReportedMatcher", util::TEST_ATOM_REPORTED);
+    *config.add_atom_matcher() = testAtomReportedAtomMatcher;
+
+    EventMetric metric =
+            createEventMetric("EventTestAtomReported", testAtomReportedAtomMatcher.id(), nullopt);
+    metric.mutable_fields_filter()->mutable_omit_fields()->set_field(util::TEST_ATOM_REPORTED);
+    metric.mutable_fields_filter()->mutable_omit_fields()->add_child()->set_field(2);  // int_field
+    *config.add_event_metric() = metric;
+
+    ConfigKey key(123, 987);
+    uint64_t bucketStartTimeNs = 10000000000;  // 0:10
+    sp<StatsLogProcessor> processor =
+            CreateStatsLogProcessor(bucketStartTimeNs, bucketStartTimeNs, config, key);
+
+    // Initialize log events before update.
+    std::vector<std::unique_ptr<LogEvent>> events;
+
+    events.push_back(CreateTestAtomReportedEventWithPrimitives(
+            bucketStartTimeNs + 10 * NS_PER_SEC, 1 /* intField */, 1l /* longField */,
+            1.0f /* floatField */, "string_field1", false /* boolField */,
+            TestAtomReported::OFF /* enumField */));
+    events.push_back(CreateTestAtomReportedEventWithPrimitives(
+            bucketStartTimeNs + 20 * NS_PER_SEC, 2 /* intField */, 2l /* longField */,
+            2.0f /* floatField */, "string_field2", true /* boolField */,
+            TestAtomReported::ON /* enumField */));
+    events.push_back(CreateTestAtomReportedEventWithPrimitives(
+            bucketStartTimeNs + 30 * NS_PER_SEC, 3 /* intField */, 3l /* longField */,
+            3.0f /* floatField */, "string_field3", false /* boolField */,
+            TestAtomReported::ON /* enumField */));
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    uint64_t dumpTimeNs = bucketStartTimeNs + 100 * NS_PER_SEC;
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(key, dumpTimeNs, true, true, ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport testAtomEventMetricReport = report.metrics(0);
+    EXPECT_EQ(testAtomEventMetricReport.metric_id(), metric.id());
+    EXPECT_TRUE(testAtomEventMetricReport.has_event_metrics());
+    ASSERT_EQ(testAtomEventMetricReport.event_metrics().data_size(), 3);
+
+    TestAtomReported atom =
+            testAtomEventMetricReport.event_metrics().data(0).atom().test_atom_reported();
+    EXPECT_FALSE(atom.has_int_field());
+    EXPECT_EQ(atom.long_field(), 1l);
+    EXPECT_EQ(atom.float_field(), 1.0f);
+    EXPECT_EQ(atom.string_field(), "string_field1");
+    EXPECT_FALSE(atom.boolean_field());
+    EXPECT_EQ(atom.state(), TestAtomReported::OFF);
+
+    atom = testAtomEventMetricReport.event_metrics().data(1).atom().test_atom_reported();
+    EXPECT_FALSE(atom.has_int_field());
+    EXPECT_EQ(atom.long_field(), 2l);
+    EXPECT_EQ(atom.float_field(), 2.0f);
+    EXPECT_EQ(atom.string_field(), "string_field2");
+    EXPECT_TRUE(atom.boolean_field());
+    EXPECT_EQ(atom.state(), TestAtomReported::ON);
+
+    atom = testAtomEventMetricReport.event_metrics().data(2).atom().test_atom_reported();
+    EXPECT_FALSE(atom.has_int_field());
+    EXPECT_EQ(atom.long_field(), 3l);
+    EXPECT_EQ(atom.float_field(), 3.0f);
+    EXPECT_EQ(atom.string_field(), "string_field3");
+    EXPECT_FALSE(atom.boolean_field());
+    EXPECT_EQ(atom.state(), TestAtomReported::ON);
+}
 #else
 GTEST_LOG_(INFO) << "This test does nothing.\n";
 #endif
diff --git a/statsd/tests/e2e/GaugeMetric_e2e_pull_test.cpp b/statsd/tests/e2e/GaugeMetric_e2e_pull_test.cpp
index e9d5b0ec..f472ca85 100644
--- a/statsd/tests/e2e/GaugeMetric_e2e_pull_test.cpp
+++ b/statsd/tests/e2e/GaugeMetric_e2e_pull_test.cpp
@@ -53,7 +53,6 @@ StatsdConfig CreateStatsdConfig(const GaugeMetric::SamplingType sampling_type,
         gaugeMetric->set_condition(screenIsOffPredicate.id());
     }
     gaugeMetric->set_sampling_type(sampling_type);
-    gaugeMetric->mutable_gauge_fields_filter()->set_include_all(true);
     *gaugeMetric->mutable_dimensions_in_what() =
             CreateDimensions(ATOM_TAG, {1 /* subsystem name */});
     gaugeMetric->set_bucket(FIVE_MINUTES);
@@ -1370,6 +1369,573 @@ TEST(GaugeMetricE2ePulledTest, TestGaugeMetricPullProbabilityWithCondition) {
              (int64_t)340 * NS_PER_SEC});
 }
 
+TEST(GaugeMetricE2ePulledTest, TestSliceByStates) {
+    StatsdConfig config =
+            CreateStatsdConfig(GaugeMetric::RANDOM_ONE_SAMPLE, /*useCondition=*/false);
+    auto gaugeMetric = config.mutable_gauge_metric(0);
+
+    auto state = CreateScreenState();
+    *config.add_state() = state;
+    gaugeMetric->add_slice_by_state(state.id());
+
+    int64_t baseTimeNs = getElapsedRealtimeNs();
+    int64_t configAddedTimeNs = 10 * 60 * NS_PER_SEC + baseTimeNs;
+    int64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(config.gauge_metric(0).bucket()) * 1000000;
+
+    ConfigKey cfgKey;
+    auto processor =
+            CreateStatsLogProcessor(baseTimeNs, configAddedTimeNs, config, cfgKey,
+                                    SharedRefBase::make<FakeSubsystemSleepCallback>(), ATOM_TAG);
+    processor->mPullerManager->ForceClearPullerCache();
+
+    // When creating the config, the gauge metric producer should register the alarm at the
+    // end of the current bucket.
+    ASSERT_EQ((size_t)1, processor->mPullerManager->mReceivers.size());
+    EXPECT_EQ(bucketSizeNs,
+              processor->mPullerManager->mReceivers.begin()->second.front().intervalNs);
+    int64_t& nextPullTimeNs =
+            processor->mPullerManager->mReceivers.begin()->second.front().nextPullTimeNs;
+
+    std::vector<std::unique_ptr<LogEvent>> events;
+    // First Bucket
+    events.push_back(CreateScreenStateChangedEvent(configAddedTimeNs + 55,
+                                                   android::view::DISPLAY_STATE_OFF));
+    events.push_back(CreateScreenStateChangedEvent(configAddedTimeNs + 100,
+                                                   android::view::DISPLAY_STATE_ON));
+    events.push_back(CreateScreenStateChangedEvent(configAddedTimeNs + 150,
+                                                   android::view::DISPLAY_STATE_OFF));
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    // Pulling alarm arrives on time and reset the sequential pulling alarm.
+    processor->informPullAlarmFired(nextPullTimeNs + 1);
+
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(cfgKey, configAddedTimeNs + (2 * bucketSizeNs) + 10, false, true,
+                            ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(buffer.size() > 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillDimensionPath(&reports);
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+    ASSERT_EQ(reports.reports(0).metrics_size(), 1);
+    StatsLogReport::GaugeMetricDataWrapper gaugeMetrics;
+    sortMetricDataByDimensionsValue(reports.reports(0).metrics(0).gauge_metrics(), &gaugeMetrics);
+    EXPECT_EQ((int)gaugeMetrics.data_size(), 4);
+
+    // Data 0, StateTracker::kStateUnknown, subsystem_name_1
+    auto data = gaugeMetrics.data(0);
+    EXPECT_EQ(data.dimensions_in_what().field(), ATOM_TAG);
+    ASSERT_EQ(data.dimensions_in_what().value_tuple().dimensions_value_size(), 1);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).field(),
+              1 /* subsystem name field */);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_1");
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), SCREEN_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).value(), -1 /* StateTracker::kStateUnknown */);
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs,
+                             /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs)});
+
+    // Data 1, DISPLAY_STATE_OFF, subsystem_name_1
+    data = gaugeMetrics.data(1);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_1");
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).value(), android::view::DisplayStateEnum::DISPLAY_STATE_OFF);
+    // Second Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*endTimeNs=*/configAddedTimeNs + 2 * bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + bucketSizeNs + 1)});
+
+    // Data 2, StateTracker::kStateUnknown, subsystem_name_2
+    data = gaugeMetrics.data(2);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_2");
+    EXPECT_EQ(data.slice_by_state(0).value(), -1 /* StateTracker::kStateUnknown */);
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs,
+                             /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs)});
+
+    // Data 3, DISPLAY_STATE_OFF, subsystem_name_2
+    data = gaugeMetrics.data(3);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_2");
+    EXPECT_EQ(data.slice_by_state(0).value(), android::view::DisplayStateEnum::DISPLAY_STATE_OFF);
+    // Second Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*endTimeNs=*/configAddedTimeNs + 2 * bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + bucketSizeNs + 1)});
+}
+
+TEST(GaugeMetricE2ePulledTest, TestSliceByStatesWithTriggerAndCondition) {
+    StatsdConfig config = CreateStatsdConfig(GaugeMetric::FIRST_N_SAMPLES, /*useCondition=*/false);
+    auto gaugeMetric = config.mutable_gauge_metric(0);
+
+    *config.add_atom_matcher() = CreateBatteryStateNoneMatcher();
+    *config.add_atom_matcher() = CreateBatteryStateUsbMatcher();
+    auto deviceUnpluggedPredicate = CreateDeviceUnpluggedPredicate();
+    *config.add_predicate() = deviceUnpluggedPredicate;
+    gaugeMetric->set_condition(deviceUnpluggedPredicate.id());
+
+    auto triggerEventMatcher = CreateBatterySaverModeStartAtomMatcher();
+    *config.add_atom_matcher() = triggerEventMatcher;
+    gaugeMetric->set_trigger_event(triggerEventMatcher.id());
+
+    auto state = CreateScreenState();
+    *config.add_state() = state;
+    gaugeMetric->add_slice_by_state(state.id());
+
+    int64_t baseTimeNs = getElapsedRealtimeNs();
+    int64_t configAddedTimeNs = 10 * 60 * NS_PER_SEC + baseTimeNs;
+    int64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(config.gauge_metric(0).bucket()) * 1000000;
+
+    ConfigKey cfgKey;
+    auto processor =
+            CreateStatsLogProcessor(baseTimeNs, configAddedTimeNs, config, cfgKey,
+                                    SharedRefBase::make<FakeSubsystemSleepCallback>(), ATOM_TAG);
+    processor->mPullerManager->ForceClearPullerCache();
+
+    std::vector<std::unique_ptr<LogEvent>> events;
+    // First Bucket
+    // Condition True
+    events.push_back(CreateBatteryStateChangedEvent(configAddedTimeNs + 10,
+                                                    BatteryPluggedStateEnum::BATTERY_PLUGGED_NONE));
+    // State Changed - No Pull
+    events.push_back(CreateScreenStateChangedEvent(configAddedTimeNs + 50,
+                                                   android::view::DISPLAY_STATE_OFF));
+    // Trigger Event - Pull
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 100));
+    // Condition False
+    events.push_back(CreateBatteryStateChangedEvent(configAddedTimeNs + 150,
+                                                    BatteryPluggedStateEnum::BATTERY_PLUGGED_USB));
+    // State Changed - No Pull
+    events.push_back(CreateScreenStateChangedEvent(configAddedTimeNs + 200,
+                                                   android::view::DISPLAY_STATE_ON));
+    // Trigger Event - No Pull
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 250));
+    // Condition True
+    events.push_back(CreateBatteryStateChangedEvent(configAddedTimeNs + 300,
+                                                    BatteryPluggedStateEnum::BATTERY_PLUGGED_NONE));
+
+    // Second Bucket
+    // Trigger Event - Pull
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + bucketSizeNs + 50));
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(cfgKey, configAddedTimeNs + (2 * bucketSizeNs) + 10, false, true,
+                            ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(buffer.size() > 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillDimensionPath(&reports);
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+    ASSERT_EQ(reports.reports(0).metrics_size(), 1);
+    StatsLogReport::GaugeMetricDataWrapper gaugeMetrics;
+    sortMetricDataByDimensionsValue(reports.reports(0).metrics(0).gauge_metrics(), &gaugeMetrics);
+    EXPECT_EQ((int)gaugeMetrics.data_size(), 4);
+    // Data Size is 4: 2 states (DISPLAY_STATE_ON, DISPLAY_STATE_OFF) and 2 dim_in_what
+    // (subsystem_name_1, subsystem_name_2). The latter 2 entries are the same as the first 2 but
+    // for subsystem_name_2
+
+    // Data 0, DISPLAY_STATE_OFF, subsystem_name_1
+    auto data = gaugeMetrics.data(0);
+    EXPECT_EQ(data.dimensions_in_what().field(), ATOM_TAG);
+    ASSERT_EQ(data.dimensions_in_what().value_tuple().dimensions_value_size(), 1);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).field(),
+              1 /* subsystem name field */);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_1");
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), SCREEN_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).value(), android::view::DisplayStateEnum::DISPLAY_STATE_OFF);
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs,
+                             /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + 100)});
+
+    // Data 1, DISPLAY_STATE_ON, subsystem_name_1
+    data = gaugeMetrics.data(1);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_1");
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).value(), android::view::DisplayStateEnum::DISPLAY_STATE_ON);
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*endTimeNs=*/configAddedTimeNs + 2 * bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + bucketSizeNs + 50)});
+}
+
+TEST(GaugeMetricE2ePulledTest, TestSliceByStatesWithMapAndTrigger) {
+    StatsdConfig config = CreateStatsdConfig(GaugeMetric::FIRST_N_SAMPLES, /*useCondition=*/false);
+    auto gaugeMetric = config.mutable_gauge_metric(0);
+
+    auto triggerEventMatcher = CreateBatterySaverModeStartAtomMatcher();
+    *config.add_atom_matcher() = triggerEventMatcher;
+    gaugeMetric->set_trigger_event(triggerEventMatcher.id());
+
+    int64_t screenOnId = 4444;
+    int64_t screenOffId = 9876;
+    auto state = CreateScreenStateWithOnOffMap(screenOnId, screenOffId);
+    *config.add_state() = state;
+    gaugeMetric->add_slice_by_state(state.id());
+
+    int64_t baseTimeNs = getElapsedRealtimeNs();
+    int64_t configAddedTimeNs = 10 * 60 * NS_PER_SEC + baseTimeNs;
+    int64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(config.gauge_metric(0).bucket()) * 1000000;
+
+    ConfigKey cfgKey;
+    auto processor =
+            CreateStatsLogProcessor(baseTimeNs, configAddedTimeNs, config, cfgKey,
+                                    SharedRefBase::make<FakeSubsystemSleepCallback>(), ATOM_TAG);
+    processor->mPullerManager->ForceClearPullerCache();
+
+    std::vector<std::unique_ptr<LogEvent>> events;
+    // First Bucket
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 50));
+
+    events.push_back(CreateScreenStateChangedEvent(configAddedTimeNs + 100,
+                                                   android::view::DISPLAY_STATE_ON));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 110));
+
+    events.push_back(CreateScreenStateChangedEvent(
+            configAddedTimeNs + 150, android::view::DisplayStateEnum::DISPLAY_STATE_DOZE));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 160));
+
+    events.push_back(CreateScreenStateChangedEvent(
+            configAddedTimeNs + 200, android::view::DisplayStateEnum::DISPLAY_STATE_OFF));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 210));
+
+    // Second Bucket
+    events.push_back(
+            CreateScreenStateChangedEvent(configAddedTimeNs + bucketSizeNs + 10,
+                                          android::view::DisplayStateEnum::DISPLAY_STATE_VR));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + bucketSizeNs + 50));
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(cfgKey, configAddedTimeNs + (2 * bucketSizeNs) + 10, false, true,
+                            ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(buffer.size() > 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillDimensionPath(&reports);
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+    ASSERT_EQ(reports.reports(0).metrics_size(), 1);
+    StatsLogReport::GaugeMetricDataWrapper gaugeMetrics;
+    sortMetricDataByDimensionsValue(reports.reports(0).metrics(0).gauge_metrics(), &gaugeMetrics);
+    EXPECT_EQ((int)gaugeMetrics.data_size(), 6);
+    // Data Size is 6: 3 states (kStateUnknown, screenOn, screenOff) and 2 dim_in_what
+    // (subsystem_name_1, subsystem_name_2). The latter 3 are same as the first 3 but for
+    // subsystem_name_2
+
+    // Data 0, StateTracker::kStateUnknown, subsystem_name_1
+    auto data = gaugeMetrics.data(0);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_1");
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).value(), -1 /* StateTracker::kStateUnknown */);
+    // First Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs,
+                             /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + 50)});
+
+    // Data 1, State Group Screen On, subsystem_name_1
+    data = gaugeMetrics.data(1);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_1");
+    ASSERT_EQ(data.bucket_info_size(), 2);
+    EXPECT_EQ(data.slice_by_state(0).group_id(), screenOnId);
+    // First Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs,
+                             /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + 110)});
+    // Second Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(1),
+                             /*startTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*endTimeNs=*/configAddedTimeNs + 2 * bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + bucketSizeNs + 50)});
+
+    // Data 2, State Group Screen Off, subsystem_name_1
+    data = gaugeMetrics.data(2);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_str(),
+              "subsystem_name_1");
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).group_id(), screenOffId);
+    // First Bucket
+    ValidateGaugeBucketTimes(
+            data.bucket_info(0),
+            /*startTimeNs=*/configAddedTimeNs,
+            /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+            /*eventTimesNs=*/
+            {(int64_t)(configAddedTimeNs + 160), (int64_t)(configAddedTimeNs + 210)});
+}
+
+TEST(GaugeMetricE2ePulledTest, TestSliceByStatesWithPrimaryFieldsAndTrigger) {
+    StatsdConfig config;
+    config.add_default_pull_packages("AID_ROOT");  // Fake puller is registered with root.
+    auto cpuTimePerUidMatcher =
+            CreateSimpleAtomMatcher("CpuTimePerUidMatcher", util::CPU_TIME_PER_UID);
+    *config.add_atom_matcher() = cpuTimePerUidMatcher;
+
+    auto gaugeMetric = config.add_gauge_metric();
+    gaugeMetric->set_id(metricId);
+    gaugeMetric->set_what(cpuTimePerUidMatcher.id());
+    gaugeMetric->set_sampling_type(GaugeMetric::FIRST_N_SAMPLES);
+    *gaugeMetric->mutable_dimensions_in_what() =
+            CreateDimensions(util::CPU_TIME_PER_UID, {1 /* uid */});
+    gaugeMetric->set_bucket(FIVE_MINUTES);
+    gaugeMetric->set_max_pull_delay_sec(INT_MAX);
+    config.set_hash_strings_in_metric_report(false);
+    gaugeMetric->set_split_bucket_for_app_upgrade(true);
+    gaugeMetric->set_min_bucket_size_nanos(1000);
+
+    auto triggerEventMatcher = CreateBatterySaverModeStartAtomMatcher();
+    *config.add_atom_matcher() = triggerEventMatcher;
+    gaugeMetric->set_trigger_event(triggerEventMatcher.id());
+
+    auto state = CreateUidProcessState();
+    *config.add_state() = state;
+    gaugeMetric->add_slice_by_state(state.id());
+
+    MetricStateLink* stateLink = gaugeMetric->add_state_link();
+    stateLink->set_state_atom_id(UID_PROCESS_STATE_ATOM_ID);
+    auto fieldsInWhat = stateLink->mutable_fields_in_what();
+    *fieldsInWhat = CreateDimensions(util::CPU_TIME_PER_UID, {1 /* uid */});
+    auto fieldsInState = stateLink->mutable_fields_in_state();
+    *fieldsInState = CreateDimensions(UID_PROCESS_STATE_ATOM_ID, {1 /* uid */});
+
+    int64_t baseTimeNs = getElapsedRealtimeNs();
+    int64_t configAddedTimeNs = 10 * 60 * NS_PER_SEC + baseTimeNs;
+    int64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(config.gauge_metric(0).bucket()) * 1000000;
+
+    ConfigKey cfgKey;
+    auto processor = CreateStatsLogProcessor(baseTimeNs, configAddedTimeNs, config, cfgKey,
+                                             SharedRefBase::make<FakeCpuTimeCallback>(),
+                                             util::CPU_TIME_PER_UID);
+    processor->mPullerManager->ForceClearPullerCache();
+
+    std::vector<std::unique_ptr<LogEvent>> events;
+    // First Bucket
+    events.push_back(CreateUidProcessStateChangedEvent(
+            configAddedTimeNs + 55, 1 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 80));
+
+    events.push_back(CreateUidProcessStateChangedEvent(
+            configAddedTimeNs + 100, 2 /*uid*/, android::app::ProcessStateEnum::PROCESS_STATE_TOP));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 150));
+
+    events.push_back(CreateUidProcessStateChangedEvent(
+            configAddedTimeNs + 200, 1 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_BACKGROUND));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + 250));
+
+    // Second Bucket
+    events.push_back(CreateUidProcessStateChangedEvent(
+            configAddedTimeNs + bucketSizeNs + 50, 1 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + bucketSizeNs + 150));
+
+    events.push_back(CreateUidProcessStateChangedEvent(
+            configAddedTimeNs + bucketSizeNs + 200, 2 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + bucketSizeNs + 220));
+
+    events.push_back(
+            CreateUidProcessStateChangedEvent(configAddedTimeNs + bucketSizeNs + 250, 2 /*uid*/,
+                                              android::app::ProcessStateEnum::PROCESS_STATE_TOP));
+    events.push_back(CreateBatterySaverOnEvent(configAddedTimeNs + bucketSizeNs + 300));
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(cfgKey, configAddedTimeNs + (2 * bucketSizeNs) + 10, false, true,
+                            ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(buffer.size() > 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillDimensionPath(&reports);
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+    ASSERT_EQ(reports.reports(0).metrics_size(), 1);
+    StatsLogReport::GaugeMetricDataWrapper gaugeMetrics;
+    sortMetricDataByDimensionsValue(reports.reports(0).metrics(0).gauge_metrics(), &gaugeMetrics);
+    EXPECT_EQ((int)gaugeMetrics.data_size(), 5);
+
+    // Data 0, PROCESS_STATE_IMPORTANT_FOREGROUND, UID 1
+    auto data = gaugeMetrics.data(0);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_int(),
+              1 /* uid value */);
+    ASSERT_EQ(data.bucket_info_size(), 2);
+    EXPECT_EQ(data.slice_by_state(0).value(),
+              android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND);
+    // First Bucket
+    ValidateGaugeBucketTimes(
+            data.bucket_info(0),
+            /*startTimeNs=*/configAddedTimeNs,
+            /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+            /*eventTimesNs=*/
+            {(int64_t)(configAddedTimeNs + 80), (int64_t)(configAddedTimeNs + 150)});
+    // Second Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(1),
+                             /*startTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*endTimeNs=*/configAddedTimeNs + 2 * bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + bucketSizeNs + 150),
+                              (int64_t)(configAddedTimeNs + bucketSizeNs + 220),
+                              (int64_t)(configAddedTimeNs + bucketSizeNs + 300)});
+
+    // Data 1, PROCESS_STATE_IMPORTANT_BACKGROUND, UID 1
+    data = gaugeMetrics.data(1);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_int(),
+              1 /* uid value */);
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).value(),
+              android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_BACKGROUND);
+    // First Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs,
+                             /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + 250)});
+
+    // Data 2, StateTracker::kStateUnknown, UID 2
+    data = gaugeMetrics.data(2);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_int(),
+              2 /* uid value */);
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).value(), -1 /* StateTracker::kStateUnknown */);
+    // First Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs,
+                             /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + 80)});
+
+    // Data 3, PROCESS_STATE_TOP, UID 2
+    data = gaugeMetrics.data(3);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_int(),
+              2 /* uid value */);
+    ASSERT_EQ(data.bucket_info_size(), 2);
+    EXPECT_EQ(data.slice_by_state(0).value(), android::app::ProcessStateEnum::PROCESS_STATE_TOP);
+    // First Bucket
+    ValidateGaugeBucketTimes(
+            data.bucket_info(0),
+            /*startTimeNs=*/configAddedTimeNs,
+            /*endTimeNs=*/configAddedTimeNs + bucketSizeNs,
+            /*eventTimesNs=*/
+            {(int64_t)(configAddedTimeNs + 150), (int64_t)(configAddedTimeNs + 250)});
+    // Second Bucket
+    ValidateGaugeBucketTimes(data.bucket_info(1),
+                             /*startTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*endTimeNs=*/configAddedTimeNs + 2 * bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + bucketSizeNs + 150),
+                              (int64_t)(configAddedTimeNs + bucketSizeNs + 300)});
+
+    // Data 4, PROCESS_STATE_IMPORTANT_FOREGROUND, UID 2
+    data = gaugeMetrics.data(4);
+    EXPECT_EQ(data.dimensions_in_what().value_tuple().dimensions_value(0).value_int(),
+              2 /* uid value */);
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).value(),
+              android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND);
+    // Second Bucket Only
+    ValidateGaugeBucketTimes(data.bucket_info(0),
+                             /*startTimeNs=*/configAddedTimeNs + bucketSizeNs,
+                             /*endTimeNs=*/configAddedTimeNs + 2 * bucketSizeNs,
+                             /*eventTimesNs=*/
+                             {(int64_t)(configAddedTimeNs + bucketSizeNs + 220)});
+}
+
+TEST(GaugeMetricE2ePulledTest, TestFieldFilterOmit) {
+    auto config = CreateStatsdConfig(GaugeMetric::RANDOM_ONE_SAMPLE, /* useCondition */ false);
+    config.mutable_gauge_metric(0)->mutable_gauge_fields_filter()->mutable_omit_fields()->set_field(
+            ATOM_TAG);
+    config.mutable_gauge_metric(0)
+            ->mutable_gauge_fields_filter()
+            ->mutable_omit_fields()
+            ->add_child()
+            ->set_field(2);  // subsystem_subname
+    int64_t baseTimeNs = getElapsedRealtimeNs();
+    int64_t configAddedTimeNs = 10 * 60 * NS_PER_SEC + baseTimeNs;
+    int64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(config.gauge_metric(0).bucket()) * 1000000;
+
+    ConfigKey cfgKey;
+    auto processor =
+            CreateStatsLogProcessor(baseTimeNs, configAddedTimeNs, config, cfgKey,
+                                    SharedRefBase::make<FakeSubsystemSleepCallback>(), ATOM_TAG);
+
+    processor->informPullAlarmFired(baseTimeNs + bucketSizeNs * 2 + 1);
+
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(cfgKey, configAddedTimeNs + 3 * bucketSizeNs + 10, false, true,
+                            ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(buffer.size() > 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillDimensionPath(&reports);
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(1, reports.reports_size());
+    ASSERT_EQ(1, reports.reports(0).metrics_size());
+    StatsLogReport::GaugeMetricDataWrapper gaugeMetrics;
+    sortMetricDataByDimensionsValue(reports.reports(0).metrics(0).gauge_metrics(), &gaugeMetrics);
+    ASSERT_GT((int)gaugeMetrics.data_size(), 1);
+
+    auto data = gaugeMetrics.data(0);
+    ASSERT_EQ(data.bucket_info_size(), 1);
+    ASSERT_EQ(data.bucket_info(0).atom_size(), 1);
+    EXPECT_FALSE(data.bucket_info(0).atom(0).subsystem_sleep_state().has_subname());
+    EXPECT_EQ(data.bucket_info(0).atom(0).subsystem_sleep_state().count(), 1);
+    EXPECT_GT(data.bucket_info(0).atom(0).subsystem_sleep_state().time_millis(), 0);
+}
 #else
 GTEST_LOG_(INFO) << "This test does nothing.\n";
 #endif
diff --git a/statsd/tests/e2e/GaugeMetric_e2e_push_test.cpp b/statsd/tests/e2e/GaugeMetric_e2e_push_test.cpp
index 4bfa4bdd..9440d5f7 100644
--- a/statsd/tests/e2e/GaugeMetric_e2e_push_test.cpp
+++ b/statsd/tests/e2e/GaugeMetric_e2e_push_test.cpp
@@ -46,7 +46,6 @@ StatsdConfig CreateStatsdConfigForPushedEvent(const GaugeMetric::SamplingType sa
     gaugeMetric->set_id(123456);
     gaugeMetric->set_what(atomMatcher.id());
     gaugeMetric->set_condition(isInBackgroundPredicate.id());
-    gaugeMetric->mutable_gauge_fields_filter()->set_include_all(false);
     gaugeMetric->set_sampling_type(sampling_type);
     auto fieldMatcher = gaugeMetric->mutable_gauge_fields_filter()->mutable_fields();
     fieldMatcher->set_field(util::APP_START_OCCURRED);
@@ -674,6 +673,373 @@ TEST_F(GaugeMetricE2ePushedTest, TestPushedGaugeMetricSamplingWithDimensionalSam
                               210 * NS_PER_SEC, 300 * NS_PER_SEC});
 }
 
+TEST_F(GaugeMetricE2ePushedTest, TestPushedGaugeMetricSliceByStates) {
+    StatsdConfig config;
+    config.add_allowed_log_source("AID_ROOT");  // LogEvent defaults to UID of root.
+
+    auto syncStartMatcher = CreateSyncStartAtomMatcher();
+    *config.add_atom_matcher() = syncStartMatcher;
+
+    auto state = CreateScreenState();
+    *config.add_state() = state;
+
+    // Create gauge metric that slices by screen state.
+    GaugeMetric syncStateGaugeMetric =
+            createGaugeMetric("GaugeSyncState", syncStartMatcher.id(), GaugeMetric::FIRST_N_SAMPLES,
+                              nullopt, nullopt, {state.id()});
+    syncStateGaugeMetric.set_max_num_gauge_atoms_per_bucket(2);
+    *config.add_gauge_metric() = syncStateGaugeMetric;
+
+    const int64_t configAddedTimeNs = 10 * NS_PER_SEC;  // 0:10
+    const int64_t bucketSizeNs =
+            TimeUnitToBucketSizeInMillis(config.gauge_metric(0).bucket()) * 1000LL * 1000LL;
+
+    // Initialize StatsLogProcessor.
+    int uid = 12345;
+    int64_t cfgId = 98765;
+    ConfigKey cfgKey(uid, cfgId);
+
+    sp<StatsLogProcessor> processor = CreateStatsLogProcessor(
+            configAddedTimeNs, configAddedTimeNs, config, cfgKey, nullptr, 0, new UidMap());
+
+    // Initialize log events.
+    std::vector<int> attributionUids1 = {123};
+    std::vector<string> attributionTags1 = {"App1"};
+
+    const int64_t gaugeEventTimeNs1 = configAddedTimeNs + 50 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs2 = configAddedTimeNs + 75 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs3 = configAddedTimeNs + 150 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs4 = configAddedTimeNs + 180 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs5 = configAddedTimeNs + 200 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs6 = configAddedTimeNs + 250 * NS_PER_SEC;
+
+    std::vector<std::unique_ptr<LogEvent>> events;
+    events.push_back(CreateScreenStateChangedEvent(
+            gaugeEventTimeNs1,
+            android::view::DisplayStateEnum::DISPLAY_STATE_ON));  // 1:00
+    events.push_back(CreateSyncStartEvent(gaugeEventTimeNs2, attributionUids1, attributionTags1,
+                                          "sync_name"));  // 1:25
+    events.push_back(CreateSyncStartEvent(gaugeEventTimeNs3, attributionUids1, attributionTags1,
+                                          "sync_name"));  // 2:40
+    // Not logged since max gauge atoms have been reached
+    events.push_back(CreateSyncStartEvent(gaugeEventTimeNs4, attributionUids1, attributionTags1,
+                                          "sync_name"));  // 3:10
+    events.push_back(CreateScreenStateChangedEvent(
+            gaugeEventTimeNs5,
+            android::view::DisplayStateEnum::DISPLAY_STATE_OFF));  // 3:30
+    events.push_back(CreateSyncStartEvent(gaugeEventTimeNs6, attributionUids1, attributionTags1,
+                                          "sync_name"));  // 4:20
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    // Check dump report.
+    uint64_t dumpTimeNs = configAddedTimeNs + bucketSizeNs;
+    ConfigMetricsReportList reports;
+    vector<uint8_t> buffer;
+    processor->onDumpReport(cfgKey, dumpTimeNs, true, true, ADB_DUMP, FAST, &buffer);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_EQ(metricReport.metric_id(), syncStateGaugeMetric.id());
+    EXPECT_TRUE(metricReport.has_gauge_metrics());
+    ASSERT_EQ(metricReport.gauge_metrics().data_size(), 2);
+
+    // For each GaugeMetricData, check StateValue info is correct
+    GaugeMetricData data = metricReport.gauge_metrics().data(0);
+
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), SCREEN_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).value(), android::view::DisplayStateEnum::DISPLAY_STATE_ON);
+    ASSERT_EQ(data.bucket_info(0).atom_size(), 2);
+    ValidateGaugeBucketTimes(data.bucket_info(0), configAddedTimeNs,
+                             configAddedTimeNs + bucketSizeNs,
+                             {gaugeEventTimeNs2, gaugeEventTimeNs3});
+
+    data = metricReport.gauge_metrics().data(1);
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), SCREEN_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).value(), android::view::DisplayStateEnum::DISPLAY_STATE_OFF);
+    ASSERT_EQ(data.bucket_info(0).atom_size(), 1);
+    ValidateGaugeBucketTimes(data.bucket_info(0), configAddedTimeNs,
+                             configAddedTimeNs + bucketSizeNs, {gaugeEventTimeNs6});
+}
+
+TEST_F(GaugeMetricE2ePushedTest, TestSlicedStateWithMap) {
+    StatsdConfig config;
+
+    auto syncStartMatcher = CreateSyncStartAtomMatcher();
+    *config.add_atom_matcher() = syncStartMatcher;
+
+    int64_t screenOnId = 4444;
+    int64_t screenOffId = 9876;
+    auto state = CreateScreenStateWithOnOffMap(screenOnId, screenOffId);
+    *config.add_state() = state;
+
+    // Create gauge metric that slices by screen state with on/off map.
+    GaugeMetric syncStateGaugeMetric =
+            createGaugeMetric("GaugeSyncStart", syncStartMatcher.id(), GaugeMetric::FIRST_N_SAMPLES,
+                              nullopt, nullopt, {state.id()});
+    *config.add_gauge_metric() = syncStateGaugeMetric;
+
+    const int64_t configAddedTimeNs = 10 * NS_PER_SEC;  // 0:10
+    const int64_t bucketSizeNs =
+            TimeUnitToBucketSizeInMillis(config.gauge_metric(0).bucket()) * 1000LL * 1000LL;
+
+    // Initialize StatsLogProcessor.
+    int uid = 12345;
+    int64_t cfgId = 98765;
+    ConfigKey cfgKey(uid, cfgId);
+
+    sp<StatsLogProcessor> processor = CreateStatsLogProcessor(
+            configAddedTimeNs, configAddedTimeNs, config, cfgKey, nullptr, 0, new UidMap());
+
+    /*
+    |     1     2     3     4(minutes)
+    |-----------------------|-
+      x   x     x       x     (syncStartEvents)
+     -------------------------SCREEN_OFF events
+             |                (ScreenStateOffEvent = 1)
+         |                    (ScreenStateDozeEvent = 3)
+     -------------------------SCREEN_ON events
+       |                      (ScreenStateOnEvent = 2)
+                      |       (ScreenStateVrEvent = 5)
+
+    Based on the diagram above, a Sync Start Event querying for Screen State would return:
+    - Event 0: StateTracker::kStateUnknown
+    - Event 1: Off
+    - Event 2: Off
+    - Event 3: On
+    */
+
+    const int64_t gaugeEventTimeNs1 = configAddedTimeNs + 20 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs2 = configAddedTimeNs + 30 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs3 = configAddedTimeNs + 50 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs4 = configAddedTimeNs + 60 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs5 = configAddedTimeNs + 90 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs6 = configAddedTimeNs + 120 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs7 = configAddedTimeNs + 180 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs8 = configAddedTimeNs + 200 * NS_PER_SEC;
+    // Initialize log events
+    std::vector<int> attributionUids1 = {123};
+    std::vector<string> attributionTags1 = {"App1"};
+
+    std::vector<std::unique_ptr<LogEvent>> events;
+    events.push_back(CreateSyncStartEvent(gaugeEventTimeNs1, attributionUids1, attributionTags1,
+                                          "sync_name"));  // 0:30
+    // Event 0 Occurred
+    events.push_back(CreateScreenStateChangedEvent(
+            gaugeEventTimeNs2,
+            android::view::DisplayStateEnum::DISPLAY_STATE_ON));  // 0:40
+    events.push_back(CreateScreenStateChangedEvent(
+            gaugeEventTimeNs3,
+            android::view::DisplayStateEnum::DISPLAY_STATE_DOZE));  // 1:00
+    events.push_back(CreateSyncStartEvent(gaugeEventTimeNs4, attributionUids1, attributionTags1,
+                                          "sync_name"));  // 1:10
+    // Event 1 Occurred
+    events.push_back(CreateScreenStateChangedEvent(
+            gaugeEventTimeNs5,
+            android::view::DisplayStateEnum::DISPLAY_STATE_OFF));  // 1:40
+    events.push_back(CreateSyncStartEvent(gaugeEventTimeNs6, attributionUids1, attributionTags1,
+                                          "sync_name"));  // 2:10
+    // Event 2 Occurred
+    events.push_back(CreateScreenStateChangedEvent(
+            gaugeEventTimeNs7,
+            android::view::DisplayStateEnum::DISPLAY_STATE_VR));  // 3:10
+    events.push_back(CreateSyncStartEvent(gaugeEventTimeNs8, attributionUids1, attributionTags1,
+                                          "sync_name"));  // 3:30
+    // Event 3 Occurred
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    // Check dump report.
+    uint64_t dumpTimeNs = configAddedTimeNs + bucketSizeNs;
+    vector<uint8_t> buffer;
+    ConfigMetricsReportList reports;
+    processor->onDumpReport(cfgKey, dumpTimeNs, false, true, ADB_DUMP, FAST, &buffer);
+    ASSERT_GT(buffer.size(), 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_EQ(metricReport.metric_id(), syncStateGaugeMetric.id());
+    EXPECT_TRUE(metricReport.has_gauge_metrics());
+    ASSERT_EQ(metricReport.gauge_metrics().data_size(), 3);
+
+    // For each GaugeMetricData, check StateValue info is correct
+    GaugeMetricData data = metricReport.gauge_metrics().data(0);
+
+    // StateTracker::kStateUnknown
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), SCREEN_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).value(), -1 /* StateTracker::kStateUnknown */);
+    ValidateGaugeBucketTimes(data.bucket_info(0), configAddedTimeNs,
+                             configAddedTimeNs + bucketSizeNs, {gaugeEventTimeNs1});
+
+    // Off
+    data = metricReport.gauge_metrics().data(1);
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), SCREEN_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).group_id(), screenOffId);
+    ValidateGaugeBucketTimes(data.bucket_info(0), configAddedTimeNs,
+                             configAddedTimeNs + bucketSizeNs,
+                             {gaugeEventTimeNs4, gaugeEventTimeNs6});
+
+    // On
+    data = metricReport.gauge_metrics().data(2);
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), SCREEN_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).group_id(), screenOnId);
+    ValidateGaugeBucketTimes(data.bucket_info(0), configAddedTimeNs,
+                             configAddedTimeNs + bucketSizeNs, {gaugeEventTimeNs8});
+}
+
+TEST_F(GaugeMetricE2ePushedTest, TestSlicedStateWithPrimaryFields) {
+    StatsdConfig config;
+
+    auto appCrashMatcher = CreateSimpleAtomMatcher("APP_CRASH_OCCURRED", util::APP_CRASH_OCCURRED);
+    *config.add_atom_matcher() = appCrashMatcher;
+
+    auto state = CreateUidProcessState();
+    *config.add_state() = state;
+
+    // Create gauge metric that slices by uid process state.
+    GaugeMetric appCrashGaugeMetric =
+            createGaugeMetric("AppCrashReported", appCrashMatcher.id(),
+                              GaugeMetric::FIRST_N_SAMPLES, nullopt, nullopt, {state.id()});
+    *appCrashGaugeMetric.mutable_dimensions_in_what() =
+            CreateDimensions(util::APP_CRASH_OCCURRED, {1 /* uid */});
+    MetricStateLink* stateLink = appCrashGaugeMetric.add_state_link();
+    stateLink->set_state_atom_id(UID_PROCESS_STATE_ATOM_ID);
+    auto fieldsInWhat = stateLink->mutable_fields_in_what();
+    *fieldsInWhat = CreateDimensions(util::APP_CRASH_OCCURRED, {1 /*uid*/});
+    auto fieldsInState = stateLink->mutable_fields_in_state();
+    *fieldsInState = CreateDimensions(UID_PROCESS_STATE_ATOM_ID, {1 /*uid*/});
+    *config.add_gauge_metric() = appCrashGaugeMetric;
+
+    const int64_t configAddedTimeNs = 10 * NS_PER_SEC;  // 0:10
+    const int64_t bucketSizeNs =
+            TimeUnitToBucketSizeInMillis(config.gauge_metric(0).bucket()) * 1000LL * 1000LL;
+
+    // Initialize StatsLogProcessor.
+    int uid = 12345;
+    int64_t cfgId = 98765;
+    ConfigKey cfgKey(uid, cfgId);
+
+    sp<StatsLogProcessor> processor = CreateStatsLogProcessor(
+            configAddedTimeNs, configAddedTimeNs, config, cfgKey, nullptr, 0, new UidMap());
+
+    /*
+    NOTE: "1" or "2" represents the uid associated with the state/app crash event
+    |    1    2    3
+    |--------------|-
+      1   1       2 1(AppCrashEvents)
+     ----------------PROCESS STATE events
+            2        (TopEvent = 1002)
+       1             (ImportantForegroundEvent = 1005)
+
+    Based on the diagram above, an AppCrashEvent querying for process state value would return:
+    - Event 0: StateTracker::kStateUnknown
+    - Event 1: Important Foreground
+    - Event 2: Top
+    - Event 3: Important Foreground
+    */
+
+    const int64_t gaugeEventTimeNs1 = configAddedTimeNs + 20 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs2 = configAddedTimeNs + 30 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs3 = configAddedTimeNs + 60 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs4 = configAddedTimeNs + 90 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs5 = configAddedTimeNs + 160 * NS_PER_SEC;
+    const int64_t gaugeEventTimeNs6 = configAddedTimeNs + 180 * NS_PER_SEC;
+    // Initialize log events
+    std::vector<std::unique_ptr<LogEvent>> events;
+    events.push_back(CreateAppCrashOccurredEvent(gaugeEventTimeNs1, 1 /*uid*/));  // 0:30
+    // Event 0 Occurred
+    events.push_back(CreateUidProcessStateChangedEvent(
+            gaugeEventTimeNs2, 1 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_IMPORTANT_FOREGROUND));  // 0:40
+    events.push_back(CreateAppCrashOccurredEvent(gaugeEventTimeNs3, 1 /*uid*/));   // 1:10
+    // Event 1 Occurred
+    events.push_back(CreateUidProcessStateChangedEvent(
+            gaugeEventTimeNs4, 2 /*uid*/,
+            android::app::ProcessStateEnum::PROCESS_STATE_TOP));                  // 1:40
+    events.push_back(CreateAppCrashOccurredEvent(gaugeEventTimeNs5, 2 /*uid*/));  // 2:50
+    // Event 2 Occurred
+    events.push_back(CreateAppCrashOccurredEvent(gaugeEventTimeNs6, 1 /*uid*/));  // 3:10
+    // Event 3 Occurred
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        processor->OnLogEvent(event.get());
+    }
+
+    // Check dump report.
+    uint64_t dumpTimeNs = configAddedTimeNs + bucketSizeNs;
+    vector<uint8_t> buffer;
+    ConfigMetricsReportList reports;
+    processor->onDumpReport(cfgKey, dumpTimeNs, false, true, ADB_DUMP, FAST, &buffer);
+    ASSERT_GT(buffer.size(), 0);
+    EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+    backfillDimensionPath(&reports);
+    backfillStringInReport(&reports);
+    backfillStartEndTimestamp(&reports);
+    backfillAggregatedAtoms(&reports);
+    ASSERT_EQ(reports.reports_size(), 1);
+
+    ConfigMetricsReport report = reports.reports(0);
+    ASSERT_EQ(report.metrics_size(), 1);
+    StatsLogReport metricReport = report.metrics(0);
+    EXPECT_EQ(metricReport.metric_id(), appCrashGaugeMetric.id());
+    EXPECT_TRUE(metricReport.has_gauge_metrics());
+    ASSERT_EQ(metricReport.gauge_metrics().data_size(), 3);
+
+    // For each GaugeMetricData, check StateValue info is correct
+    GaugeMetricData data = metricReport.gauge_metrics().data(0);
+
+    // StateTracker::kStateUnknown
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), UID_PROCESS_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).value(), -1 /* StateTracker::kStateUnknown */);
+    ValidateUidDimension(data.dimensions_in_what(), util::APP_CRASH_OCCURRED, 1 /* uid */);
+    ValidateGaugeBucketTimes(data.bucket_info(0), configAddedTimeNs,
+                             configAddedTimeNs + bucketSizeNs, {gaugeEventTimeNs1});
+
+    // Important Foreground
+    data = metricReport.gauge_metrics().data(1);
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), UID_PROCESS_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).value(), android::app::PROCESS_STATE_IMPORTANT_FOREGROUND);
+    ValidateUidDimension(data.dimensions_in_what(), util::APP_CRASH_OCCURRED, 1 /* uid */);
+    ValidateGaugeBucketTimes(data.bucket_info(0), configAddedTimeNs,
+                             configAddedTimeNs + bucketSizeNs,
+                             {gaugeEventTimeNs3, gaugeEventTimeNs6});
+
+    // Top
+    data = metricReport.gauge_metrics().data(2);
+    ASSERT_EQ(data.slice_by_state_size(), 1);
+    EXPECT_EQ(data.slice_by_state(0).atom_id(), UID_PROCESS_STATE_ATOM_ID);
+    EXPECT_EQ(data.slice_by_state(0).value(), android::app::PROCESS_STATE_TOP);
+    ValidateUidDimension(data.dimensions_in_what(), util::APP_CRASH_OCCURRED, 2 /* uid */);
+    ValidateGaugeBucketTimes(data.bucket_info(0), configAddedTimeNs,
+                             configAddedTimeNs + bucketSizeNs, {gaugeEventTimeNs5});
+}
+
 #else
 GTEST_LOG_(INFO) << "This test does nothing.\n";
 #endif
diff --git a/statsd/tests/e2e/PartialBucket_e2e_test.cpp b/statsd/tests/e2e/PartialBucket_e2e_test.cpp
index c3503ea7..2f4e766a 100644
--- a/statsd/tests/e2e/PartialBucket_e2e_test.cpp
+++ b/statsd/tests/e2e/PartialBucket_e2e_test.cpp
@@ -88,7 +88,6 @@ StatsdConfig MakeGaugeMetricConfig(int64_t minTime) {
     auto gaugeMetric = config.add_gauge_metric();
     gaugeMetric->set_id(123456);
     gaugeMetric->set_what(pulledAtomMatcher.id());
-    gaugeMetric->mutable_gauge_fields_filter()->set_include_all(true);
     *gaugeMetric->mutable_dimensions_in_what() =
             CreateDimensions(util::SUBSYSTEM_SLEEP_STATE, {1 /* subsystem name */});
     gaugeMetric->set_bucket(FIVE_MINUTES);
diff --git a/statsd/tests/e2e/ValueMetric_histogram_e2e_test.cpp b/statsd/tests/e2e/ValueMetric_histogram_e2e_test.cpp
index 66a1e511..9e74ad96 100644
--- a/statsd/tests/e2e/ValueMetric_histogram_e2e_test.cpp
+++ b/statsd/tests/e2e/ValueMetric_histogram_e2e_test.cpp
@@ -102,7 +102,7 @@ protected:
 class ValueMetricHistogramE2eTestPushedExplicitBins : public ValueMetricHistogramE2eTest {
 protected:
     void SetUp() override {
-        StatsdConfig config = createExplicitHistogramStatsdConfig(/* bins */ {1, 7, 10, 20});
+        StatsdConfig config = createExplicitHistogramStatsdConfig(/* bins */ {-1, 7, 10, 20});
         createProcessor(config);
     }
 };
@@ -130,7 +130,7 @@ TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInFirstBinAfte
 }
 
 TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInOverflowAndUnderflow) {
-    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ 0,
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ -5,
                                       /* value2 */ 0),
                CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 20, /* value1 */ 20,
                                       /* value2 */ 0)});
@@ -142,7 +142,7 @@ TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInOverflowAndU
 }
 
 TEST_F(ValueMetricHistogramE2eTestPushedExplicitBins, TestOneEventInUnderflow) {
-    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ -1,
+    logEvents({CreateTwoValueLogEvent(/* atomId */ 1, bucketStartTimeNs + 10, /* value1 */ -2,
                                       /* value2 */ 0)});
 
     optional<ConfigMetricsReportList> reports = getReports();
diff --git a/statsd/tests/external/StatsPullerManager_test.cpp b/statsd/tests/external/StatsPullerManager_test.cpp
index 98d1872f..b112d802 100644
--- a/statsd/tests/external/StatsPullerManager_test.cpp
+++ b/statsd/tests/external/StatsPullerManager_test.cpp
@@ -19,6 +19,7 @@
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
+#include <atomic>
 #include <thread>
 
 #include "stats_event.h"
@@ -38,13 +39,17 @@ namespace {
 
 int pullTagId1 = 10101;
 int pullTagId2 = 10102;
+int pullTagIdWithoutUid = 99999;
 int uid1 = 9999;
 int uid2 = 8888;
+int unRegisteredUid1 = 7777;
+int unRegisteredUid2 = 7778;
 ConfigKey configKey(50, 12345);
 ConfigKey badConfigKey(60, 54321);
 int unregisteredUid = 98765;
 int64_t coolDownNs = NS_PER_SEC;
 int64_t timeoutNs = NS_PER_SEC / 2;
+std::atomic_int pullReceiverCounter;
 
 AStatsEvent* createSimpleEvent(int32_t atomId, int32_t value) {
     AStatsEvent* event = AStatsEvent_obtain();
@@ -99,6 +104,12 @@ public:
     }
 };
 
+class FakeAllowAllAtomsUidProvider : public PullUidProvider {
+public:
+    vector<int32_t> getPullAtomUids(int atomId) override {
+        return {uid1, uid2};
+    }
+};
 class MockPullAtomCallback : public FakePullAtomCallback {
 public:
     MockPullAtomCallback(int32_t uid, int32_t pullDurationNs = 0)
@@ -127,8 +138,14 @@ sp<StatsPullerManager> createPullerManagerAndRegister(int32_t pullDurationMs = 0
     pullerManager->RegisterPullAtomCallback(uid1, pullTagId1, coolDownNs, timeoutNs, {}, cb1);
     shared_ptr<FakePullAtomCallback> cb2 =
             SharedRefBase::make<FakePullAtomCallback>(uid2, pullDurationMs);
+    shared_ptr<FakePullAtomCallback> cb3 =
+            SharedRefBase::make<FakePullAtomCallback>(uid2, pullDurationMs);
     pullerManager->RegisterPullAtomCallback(uid2, pullTagId1, coolDownNs, timeoutNs, {}, cb2);
     pullerManager->RegisterPullAtomCallback(uid1, pullTagId2, coolDownNs, timeoutNs, {}, cb1);
+    pullerManager->RegisterPullAtomCallback(unRegisteredUid1, pullTagIdWithoutUid, coolDownNs,
+                                            timeoutNs, {}, cb3);
+    pullerManager->RegisterPullAtomCallback(unRegisteredUid2, pullTagIdWithoutUid, coolDownNs,
+                                            timeoutNs, {}, cb3);
     return pullerManager;
 }
 }  // anonymous namespace
@@ -229,6 +246,133 @@ TEST(StatsPullerManagerTest, TestSameAtomIsPulledInABatch) {
     std::this_thread::sleep_for(std::chrono::nanoseconds(pullDurationNs * 3));
 }
 
+TEST(StatsPullerManagerTest, TestOnAlarmFiredMultipleReceivers) {
+    pullReceiverCounter.store(0);
+    sp<StatsPullerManager> pullerManager = createPullerManagerAndRegister();
+    sp<FakePullUidProvider> uidProvider = new FakePullUidProvider();
+    sp<MockPullDataReceiver> receiver = new StrictMock<MockPullDataReceiver>();
+    EXPECT_CALL(*receiver, onDataPulled(_, PullResult::PULL_RESULT_SUCCESS, _))
+            .WillRepeatedly(Invoke([]() { pullReceiverCounter++; }));
+    for (int i = 0; i < 250; i++) {
+        ConfigKey newConfigKey(uid1, i);
+        pullerManager->RegisterReceiver(pullTagId1, newConfigKey, receiver,
+                                        /*nextPullTimeNs =*/0,
+                                        /*intervalNs =*/(250 - i) * 60 * NS_PER_SEC);
+        pullerManager->RegisterPullUidProvider(newConfigKey, uidProvider);
+    }
+
+    pullerManager->OnAlarmFired(100);
+
+    EXPECT_EQ(pullReceiverCounter.load(), 250);
+
+    pullerManager->OnAlarmFired(60 * NS_PER_SEC + 100);
+    EXPECT_EQ(pullReceiverCounter.load(), 251);
+}
+
+TEST(StatsPullerManagerTest, TestOnAlarmFiredMultiplePulls) {
+    pullReceiverCounter.store(0);
+    sp<StatsPullerManager> pullerManager = createPullerManagerAndRegister();
+    sp<FakeAllowAllAtomsUidProvider> uidProvider = new FakeAllowAllAtomsUidProvider();
+    sp<MockPullDataReceiver> receiver = new StrictMock<MockPullDataReceiver>();
+    EXPECT_CALL(*receiver, onDataPulled(_, PullResult::PULL_RESULT_SUCCESS, _))
+            .WillRepeatedly(Invoke([]() { pullReceiverCounter++; }));
+    pullerManager->RegisterPullUidProvider(configKey, uidProvider);
+    for (int i = 0; i < 250; i++) {
+        pullerManager->RegisterReceiver(pullTagId1 + i, configKey, receiver,
+                                        /*nextPullTimeNs =*/0,
+                                        /*intervalNs =*/1000);
+        shared_ptr<FakePullAtomCallback> fakeCallback =
+                SharedRefBase::make<FakePullAtomCallback>(uid1, /*pullDurationMs= */ 0);
+        pullerManager->RegisterPullAtomCallback(uid1, pullTagId1 + i, coolDownNs, timeoutNs, {},
+                                                fakeCallback);
+    }
+
+    pullerManager->OnAlarmFired(100);
+
+    EXPECT_EQ(pullReceiverCounter.load(), 250);
+}
+
+TEST(StatsPullerManagerTest, TestOnAlarmFiredNoPullerForUidNotesPullerNotFound) {
+    StatsdStats::getInstance().reset();
+
+    sp<MockPullDataReceiver> receiver = new StrictMock<MockPullDataReceiver>();
+    EXPECT_CALL(*receiver, onDataPulled(_, PullResult::PULL_RESULT_FAIL, _)).Times(1);
+    sp<StatsPullerManager> pullerManager = createPullerManagerAndRegister();
+    sp<FakePullUidProvider> uidProvider = new FakePullUidProvider();
+    pullerManager->RegisterPullUidProvider(configKey, uidProvider);
+    pullerManager->RegisterReceiver(pullTagIdWithoutUid, configKey, receiver, /*nextPullTimeNs =*/0,
+                                    /*intervalNs =*/60 * NS_PER_SEC);
+
+    pullerManager->OnAlarmFired(100);
+    // Assert that mNextPullTime is correctly set. The #onDataPulled mock is only invoked once.
+    pullerManager->OnAlarmFired(100);
+
+    EXPECT_EQ(StatsdStats::getInstance().mPulledAtomStats[pullTagIdWithoutUid].pullerNotFound, 1);
+    EXPECT_EQ(StatsdStats::getInstance().mPulledAtomStats[pullTagIdWithoutUid].pullFailed, 0);
+}
+
+TEST(StatsPullerManagerTest, TestOnAlarmFiredNoUidProviderUpdatesNextPullTime) {
+    StatsdStats::getInstance().reset();
+
+    sp<MockPullDataReceiver> receiver = new StrictMock<MockPullDataReceiver>();
+    EXPECT_CALL(*receiver, onDataPulled(_, PullResult::PULL_RESULT_FAIL, _)).Times(1);
+    sp<StatsPullerManager> pullerManager = createPullerManagerAndRegister();
+    pullerManager->RegisterReceiver(pullTagId1, configKey, receiver, /*nextPullTimeNs =*/0,
+                                    /*intervalNs =*/60 * NS_PER_SEC);
+
+    pullerManager->OnAlarmFired(100);
+    // Assert that mNextPullTime is correctly set. The #onDataPulled mock is only invoked once.
+    pullerManager->OnAlarmFired(100);
+
+    EXPECT_EQ(StatsdStats::getInstance().mPulledAtomStats[pullTagId1].pullUidProviderNotFound, 1);
+    EXPECT_EQ(StatsdStats::getInstance().mPulledAtomStats[pullTagId1].pullerNotFound, 0);
+}
+
+TEST(StatsPullerManagerTest, TestOnAlarmFiredMultipleUidsSelectsFirstUid) {
+    pullReceiverCounter.store(0);
+    sp<MockPullDataReceiver> receiver = new StrictMock<MockPullDataReceiver>();
+    EXPECT_CALL(*receiver, onDataPulled(_, PullResult::PULL_RESULT_SUCCESS, _))
+            .WillRepeatedly(Invoke([]() { pullReceiverCounter++; }));
+    sp<StatsPullerManager> pullerManager = new StatsPullerManager();
+    shared_ptr<MockPullAtomCallback> cb1 =
+            SharedRefBase::make<MockPullAtomCallback>(uid1, /*=pullDurationMs=*/0);
+    shared_ptr<MockPullAtomCallback> cb2 =
+            SharedRefBase::make<MockPullAtomCallback>(uid2, /*=pullDurationMs=*/0);
+    EXPECT_CALL(*cb1, onPullAtomCalled(pullTagId1)).Times(0);
+    // We expect cb2 to be invoked because uid2 is provided before uid1 in the PullUidProvider.
+    EXPECT_CALL(*cb2, onPullAtomCalled(pullTagId1)).Times(1);
+    pullerManager->RegisterPullAtomCallback(uid1, pullTagId1, coolDownNs, timeoutNs, {}, cb1);
+    pullerManager->RegisterPullAtomCallback(uid2, pullTagId1, coolDownNs, timeoutNs, {}, cb2);
+    sp<FakePullUidProvider> uidProvider = new FakePullUidProvider();
+    pullerManager->RegisterPullUidProvider(configKey, uidProvider);
+    pullerManager->RegisterReceiver(pullTagId1, configKey, receiver, /*nextPullTimeNs =*/0,
+                                    /*intervalNs =*/1000);
+
+    pullerManager->OnAlarmFired(100);
+
+    EXPECT_EQ(pullReceiverCounter.load(), 1);
+}
+
+TEST(StatsPullerManagerTest, TestOnAlarmFiredUidsNotRegisteredInPullAtomCallback) {
+    sp<MockPullDataReceiver> receiver = new StrictMock<MockPullDataReceiver>();
+    EXPECT_CALL(*receiver, onDataPulled(_, PullResult::PULL_RESULT_FAIL, _)).Times(1);
+    sp<StatsPullerManager> pullerManager = new StatsPullerManager();
+    shared_ptr<MockPullAtomCallback> cb1 =
+            SharedRefBase::make<MockPullAtomCallback>(unRegisteredUid1, /*=pullDurationMs=*/0);
+    EXPECT_CALL(*cb1, onPullAtomCalled(pullTagId1)).Times(0);
+    pullerManager->RegisterPullAtomCallback(unRegisteredUid1, pullTagId1, coolDownNs, timeoutNs, {},
+                                            cb1);
+    sp<FakePullUidProvider> uidProvider = new FakePullUidProvider();
+    pullerManager->RegisterPullUidProvider(configKey, uidProvider);
+    pullerManager->RegisterReceiver(pullTagId1, configKey, receiver, /*nextPullTimeNs =*/0,
+                                    /*intervalNs =*/1000);
+
+    pullerManager->OnAlarmFired(100);
+
+    EXPECT_EQ(StatsdStats::getInstance().mPulledAtomStats[pullTagId1].pullerNotFound, 1);
+    EXPECT_EQ(StatsdStats::getInstance().mPulledAtomStats[pullTagId1].pullFailed, 0);
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/guardrail/StatsdStats_test.cpp b/statsd/tests/guardrail/StatsdStats_test.cpp
index 53367a31..b324604b 100644
--- a/statsd/tests/guardrail/StatsdStats_test.cpp
+++ b/statsd/tests/guardrail/StatsdStats_test.cpp
@@ -14,6 +14,8 @@
 
 #include "src/guardrail/StatsdStats.h"
 
+#include <com_android_os_statsd_flags.h>
+#include <flag_macros.h>
 #include <gtest/gtest.h>
 
 #include <vector>
@@ -44,6 +46,8 @@ using std::tuple;
 using std::unordered_map;
 using std::vector;
 
+#define TEST_NS com::android::os::statsd::flags
+
 class StatsdStatsTest_GetAtomDimensionKeySizeLimit_InMap
     : public TestWithParam<tuple<int, size_t>> {};
 INSTANTIATE_TEST_SUITE_P(StatsdStatsTest_GetAtomDimensionKeySizeLimit_InMap,
@@ -739,10 +743,14 @@ TEST(StatsdStatsTest, TestAtomDroppedStats) {
 
     const int numDropped = 10;
     for (int i = 0; i < numDropped; i++) {
-        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, pushAtomTag, false);
-        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, nonPlatformPushAtomTag, false);
+        stats.noteAtomLogged(pushAtomTag, /*timeSec*/ 0, /*isSkipped*/ false);
+        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, pushAtomTag);
+        stats.noteAtomLogged(nonPlatformPushAtomTag, /*timeSec*/ 0, /*isSkipped*/ false);
+        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, nonPlatformPushAtomTag);
     }
 
+    ASSERT_EQ(2, stats.mPushedAtomDropsStats.size());
+
     StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ true);
 
     ASSERT_EQ(0, stats.mPushedAtomDropsStats.size());
@@ -789,8 +797,10 @@ TEST(StatsdStatsTest, TestAtomLoggedAndDroppedStats) {
 
     const int numDropped = 10;
     for (int i = 0; i < numDropped; i++) {
-        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, pushAtomTag, false);
-        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, nonPlatformPushAtomTag, false);
+        stats.noteAtomLogged(pushAtomTag, /*timeSec*/ 0, /*isSkipped*/ false);
+        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, pushAtomTag);
+        stats.noteAtomLogged(nonPlatformPushAtomTag, /*timeSec*/ 0, /*isSkipped*/ false);
+        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, nonPlatformPushAtomTag);
     }
 
     StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ false);
@@ -857,8 +867,10 @@ TEST(StatsdStatsTest, TestAtomLoggedAndDroppedAndSkippedStats) {
 
     const int numDropped = 10;
     for (int i = 0; i < numDropped; i++) {
-        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, pushAtomTag, true);
-        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, nonPlatformPushAtomTag, true);
+        stats.noteAtomLogged(pushAtomTag, /*timeSec*/ 0, /*isSkipped*/ true);
+        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, pushAtomTag);
+        stats.noteAtomLogged(nonPlatformPushAtomTag, /*timeSec*/ 0, /*isSkipped*/ true);
+        stats.noteEventQueueOverflow(/*oldestEventTimestampNs*/ 0, nonPlatformPushAtomTag);
     }
 
     StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ false);
@@ -1208,6 +1220,239 @@ TEST_P(StatsdStatsTest_GetAtomDimensionKeySizeLimit_NotInMap, TestGetAtomDimensi
             (std::pair<size_t, size_t>(StatsdStats::kDimensionKeySizeSoftLimit, defaultHardLimit)));
 }
 
+CounterStats buildCounterStats(CounterType counter, int32_t count) {
+    CounterStats msg;
+    msg.set_counter_type(counter);
+    msg.set_count(count);
+    return msg;
+}
+
+TEST(StatsdStatsTest, TestErrorStatsReport) {
+    StatsdStats stats;
+    stats.noteIllegalState(COUNTER_TYPE_UNKNOWN);
+    stats.noteIllegalState(COUNTER_TYPE_UNKNOWN);
+    stats.noteIllegalState(COUNTER_TYPE_ERROR_ATOM_FILTER_SKIPPED);
+    stats.noteIllegalState(COUNTER_TYPE_ERROR_ATOM_FILTER_SKIPPED);
+    auto report = getStatsdStatsReport(stats, /* reset stats */ false);
+
+    EXPECT_TRUE(report.has_error_stats());
+
+    vector<CounterStats> expectedCounterStats{
+            buildCounterStats(COUNTER_TYPE_UNKNOWN, 2),
+            buildCounterStats(COUNTER_TYPE_ERROR_ATOM_FILTER_SKIPPED, 2)};
+    EXPECT_THAT(report.error_stats().counters(),
+                UnorderedPointwise(EqCounterStats(), expectedCounterStats));
+}
+
+TEST(StatsdStatsTest, TestErrorStatsReportReset) {
+    StatsdStats stats;
+    stats.noteIllegalState(COUNTER_TYPE_UNKNOWN);
+    stats.noteIllegalState(COUNTER_TYPE_UNKNOWN);
+    stats.noteIllegalState(COUNTER_TYPE_ERROR_ATOM_FILTER_SKIPPED);
+    stats.noteIllegalState(COUNTER_TYPE_ERROR_ATOM_FILTER_SKIPPED);
+    auto report = getStatsdStatsReport(stats, /* reset stats */ true);
+
+    EXPECT_TRUE(stats.mErrorStats.empty());
+}
+
+AtomStats buildAtomStats(int32_t atomId, int32_t count) {
+    AtomStats msg;
+    msg.set_tag(atomId);
+    msg.set_count(count);
+    return msg;
+}
+
+AtomStats buildAtomStats(int32_t atomId, int32_t count, int32_t peakRate) {
+    AtomStats msg;
+    msg.set_tag(atomId);
+    msg.set_count(count);
+    msg.set_peak_rate(peakRate);
+    return msg;
+}
+
+TEST_WITH_FLAGS(StatsdStatsTest, TestLoggingRateReport,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(TEST_NS,
+                                                    enable_logging_rate_stats_collection))) {
+    StatsdStats stats;
+
+    const int32_t platformAtom = StatsdStats::kMaxPushedAtomId - 1;
+    const int32_t nonPlatformAtom = StatsdStats::kMaxPushedAtomId + 1;
+
+    const int64_t kTimeWindow = 100'000'000;  // 100ms
+
+    // test validates that peak logging rate reporting is preserved
+    // across report dump & variable logging rates across time windows
+    // example rates for 4 time windows are 1, 2, 1000, 1
+    // expectation is 1000 should be reported as peak rate starting from third
+    // time window
+
+    const int32_t samplePeakRate = 1000;
+
+    int64_t ts = 0;
+
+    stats.noteAtomLogged(platformAtom, ts, false);
+    stats.noteAtomLogged(nonPlatformAtom, ts, false);
+    {
+        StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ false);
+        vector<AtomStats> expectedAtomStats{buildAtomStats(platformAtom, 1, 1),
+                                            buildAtomStats(nonPlatformAtom, 1, 1)};
+        EXPECT_THAT(report.atom_stats(), UnorderedPointwise(EqAtomStats(), expectedAtomStats));
+    }
+
+    ts += kTimeWindow;
+    stats.noteAtomLogged(platformAtom, ts, false);
+    stats.noteAtomLogged(nonPlatformAtom, ts, false);
+    stats.noteAtomLogged(platformAtom, ts + 1, false);
+    stats.noteAtomLogged(nonPlatformAtom, ts + 1, false);
+
+    {
+        StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ false);
+        vector<AtomStats> expectedAtomStats{buildAtomStats(platformAtom, 3, 2),
+                                            buildAtomStats(nonPlatformAtom, 3, 2)};
+        EXPECT_THAT(report.atom_stats(), UnorderedPointwise(EqAtomStats(), expectedAtomStats));
+    }
+
+    ts += kTimeWindow;
+    for (int i = 0; i < samplePeakRate; i++) {
+        stats.noteAtomLogged(platformAtom, ts + i, false);
+        stats.noteAtomLogged(nonPlatformAtom, ts + i, false);
+    }
+
+    {
+        StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ false);
+        vector<AtomStats> expectedAtomStats{
+                buildAtomStats(platformAtom, 3 + samplePeakRate, samplePeakRate),
+                buildAtomStats(nonPlatformAtom, 3 + samplePeakRate, samplePeakRate)};
+        EXPECT_THAT(report.atom_stats(), UnorderedPointwise(EqAtomStats(), expectedAtomStats));
+    }
+
+    ts += kTimeWindow;
+    stats.noteAtomLogged(platformAtom, ts, false);
+    stats.noteAtomLogged(nonPlatformAtom, ts, false);
+
+    {
+        StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ false);
+        vector<AtomStats> expectedAtomStats{
+                buildAtomStats(platformAtom, 4 + samplePeakRate, samplePeakRate),
+                buildAtomStats(nonPlatformAtom, 4 + samplePeakRate, samplePeakRate)};
+        EXPECT_THAT(report.atom_stats(), UnorderedPointwise(EqAtomStats(), expectedAtomStats));
+    }
+}
+
+TEST_WITH_FLAGS(StatsdStatsTest, TestLoggingRateReportReset,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(TEST_NS,
+                                                    enable_logging_rate_stats_collection))) {
+    StatsdStats stats;
+
+    const int32_t platformAtom = StatsdStats::kMaxPushedAtomId - 1;
+    const int32_t nonPlatformAtom = StatsdStats::kMaxPushedAtomId + 1;
+
+    int64_t ts = 0;
+
+    const int64_t kTimeWindow = 100'000'000;  // 100ms
+
+    stats.noteAtomLogged(platformAtom, ts, false);
+    stats.noteAtomLogged(nonPlatformAtom, ts, false);
+
+    stats.noteAtomLogged(platformAtom, ts + kTimeWindow, false);
+    stats.noteAtomLogged(nonPlatformAtom, ts + kTimeWindow, false);
+
+    StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ true);
+    EXPECT_TRUE(stats.mLoggingRateStats.mRateInfo.empty());
+}
+
+TEST_WITH_FLAGS(StatsdStatsTest, TestLoggingRateReportOnlyTopN,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(TEST_NS,
+                                                    enable_logging_rate_stats_collection))) {
+    StatsdStats stats;
+
+    const int platformAtomsToLog = 100;
+    const int nonPlatformAtomsToLog = 100;
+
+    const int32_t platformAtomStartId = 2;
+    const int32_t nonPlatformAtomStartId = StatsdStats::kMaxPushedAtomId + 1;
+    const int32_t expectedStats = StatsdStats::kMaxLoggingRateStatsToReport;
+
+    int64_t ts = 0;
+
+    vector<AtomStats> expectedAtomStats;
+
+    for (int i = 0; i < platformAtomsToLog; i++) {
+        const int loggingRateForAtom = (i + 1) * 10;  // max rate = 1000
+        const int atomId = platformAtomStartId + i;
+        for (int j = 0; j < loggingRateForAtom; j++) {
+            stats.noteAtomLogged(atomId, ts, false);
+        }
+        if (i < (platformAtomsToLog - (expectedStats / 2))) {
+            // going to be skipped due to only top 50 frequencies are populated
+            expectedAtomStats.push_back(buildAtomStats(atomId, loggingRateForAtom));
+        } else {
+            expectedAtomStats.push_back(
+                    buildAtomStats(atomId, loggingRateForAtom, loggingRateForAtom));
+        }
+    }
+
+    for (int i = 0; i < nonPlatformAtomsToLog; i++) {
+        const int loggingRateForAtom = (i + 1) * 10;  // max rate = 1000
+        const int atomId = nonPlatformAtomStartId + i;
+        for (int j = 0; j < loggingRateForAtom; j++) {
+            stats.noteAtomLogged(atomId, ts, false);
+        }
+        if (i < (nonPlatformAtomsToLog - (expectedStats / 2))) {
+            // going to be skipped due to only top 50 frequencies are populated
+            expectedAtomStats.push_back(buildAtomStats(atomId, loggingRateForAtom));
+        } else {
+            expectedAtomStats.push_back(
+                    buildAtomStats(atomId, loggingRateForAtom, loggingRateForAtom));
+        }
+    }
+
+    StatsdStatsReport report = getStatsdStatsReport(stats, /* reset stats */ false);
+    EXPECT_THAT(report.atom_stats(), UnorderedPointwise(EqAtomStats(), expectedAtomStats));
+}
+
+TEST_WITH_FLAGS(StatsdStatsTest, TestLoggingRate,
+                REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(TEST_NS,
+                                                    enable_logging_rate_stats_collection))) {
+    const int64_t kTimeWindow = 100'000'000;  // 100ms
+
+    LoggingRate loggingRate(/*maxStatsNum*/ 1000, kTimeWindow);
+
+    const int platformAtomsToLog = 10;
+    const int nonPlatformAtomsToLog = 10;
+
+    const int32_t platformAtomStartId = 2;
+    const int32_t nonPlatformAtomStartId = StatsdStats::kMaxPushedAtomId + 1;
+    const int32_t expectedStats = 20;
+
+    int64_t ts = 0;
+
+    for (int i = 0; i < platformAtomsToLog; i++) {
+        const int loggingRateForAtom = (i + 1) * 10;  // max rate = 100
+        for (int j = 0; j < loggingRateForAtom; j++) {
+            loggingRate.noteLogEvent(platformAtomStartId + i, ts + i);
+        }
+    }
+
+    for (int i = 0; i < nonPlatformAtomsToLog; i++) {
+        const int loggingRateForAtom = (i + 1) * 10;  // max rate = 100
+        for (int j = 0; j < loggingRateForAtom; j++) {
+            loggingRate.noteLogEvent(nonPlatformAtomStartId + i, ts + i);
+        }
+    }
+
+    auto result = loggingRate.getMaxRates(expectedStats);
+    EXPECT_EQ(expectedStats, result.size());
+
+    // reported rates should be sorted from greatest to least
+    for (int i = 1; i < expectedStats; i++) {
+        EXPECT_GE(result[i - 1].second, result[i].second);
+    }
+
+    EXPECT_EQ(100, result[0].second);
+    EXPECT_EQ(100, result[1].second);
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/metrics/GaugeMetricProducer_test.cpp b/statsd/tests/metrics/GaugeMetricProducer_test.cpp
index ae74dca1..35e8b54d 100644
--- a/statsd/tests/metrics/GaugeMetricProducer_test.cpp
+++ b/statsd/tests/metrics/GaugeMetricProducer_test.cpp
@@ -96,7 +96,6 @@ TEST(GaugeMetricProducerTest, TestFirstBucket) {
     GaugeMetric metric;
     metric.set_id(metricId);
     metric.set_bucket(ONE_MINUTE);
-    metric.mutable_gauge_fields_filter()->set_include_all(false);
     auto gaugeFieldMatcher = metric.mutable_gauge_fields_filter()->mutable_fields();
     gaugeFieldMatcher->set_field(tagId);
     gaugeFieldMatcher->add_child()->set_field(1);
@@ -127,7 +126,6 @@ TEST(GaugeMetricProducerTest, TestPulledEventsNoCondition) {
     GaugeMetric metric;
     metric.set_id(metricId);
     metric.set_bucket(ONE_MINUTE);
-    metric.mutable_gauge_fields_filter()->set_include_all(false);
     metric.set_max_pull_delay_sec(INT_MAX);
     auto gaugeFieldMatcher = metric.mutable_gauge_fields_filter()->mutable_fields();
     gaugeFieldMatcher->set_field(tagId);
@@ -165,7 +163,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsNoCondition) {
 
     gaugeProducer.onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS, bucket2StartTimeNs);
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
-    auto it = gaugeProducer.mCurrentSlicedBucket->begin()->second.front().mFields->begin();
+    auto it = gaugeProducer.mCurrentSlicedBucket->begin()->second.front().mFields.begin();
     EXPECT_EQ(INT, it->mValue.getType());
     EXPECT_EQ(10, it->mValue.int_value);
     it++;
@@ -183,7 +181,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsNoCondition) {
     allData.push_back(makeLogEvent(tagId, bucket3StartTimeNs + 10, 24, "some value", 25));
     gaugeProducer.onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS, bucket3StartTimeNs);
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
-    it = gaugeProducer.mCurrentSlicedBucket->begin()->second.front().mFields->begin();
+    it = gaugeProducer.mCurrentSlicedBucket->begin()->second.front().mFields.begin();
     EXPECT_EQ(INT, it->mValue.getType());
     EXPECT_EQ(24, it->mValue.int_value);
     it++;
@@ -227,7 +225,6 @@ TEST_P(GaugeMetricProducerTest_PartialBucket, TestPushedEvents) {
     GaugeMetric metric;
     metric.set_id(metricId);
     metric.set_bucket(ONE_MINUTE);
-    metric.mutable_gauge_fields_filter()->set_include_all(true);
     metric.set_split_bucket_for_app_upgrade(true);
 
     Alert alert;
@@ -352,7 +349,7 @@ TEST_P(GaugeMetricProducerTest_PartialBucket, TestPulled) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(1, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
-                         .mFields->begin()
+                         .mFields.begin()
                          ->mValue.int_value);
 
     switch (GetParam()) {
@@ -373,7 +370,7 @@ TEST_P(GaugeMetricProducerTest_PartialBucket, TestPulled) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(2, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
-                         .mFields->begin()
+                         .mFields.begin()
                          ->mValue.int_value);
 
     allData.clear();
@@ -384,7 +381,7 @@ TEST_P(GaugeMetricProducerTest_PartialBucket, TestPulled) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(3, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
-                         .mFields->begin()
+                         .mFields.begin()
                          ->mValue.int_value);
 }
 
@@ -423,7 +420,7 @@ TEST(GaugeMetricProducerTest, TestPulledWithAppUpgradeDisabled) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(1, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
-                         .mFields->begin()
+                         .mFields.begin()
                          ->mValue.int_value);
 
     gaugeProducer.notifyAppUpgrade(partialBucketSplitTimeNs);
@@ -433,7 +430,7 @@ TEST(GaugeMetricProducerTest, TestPulledWithAppUpgradeDisabled) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(1, gaugeProducer.mCurrentSlicedBucket->begin()
                          ->second.front()
-                         .mFields->begin()
+                         .mFields.begin()
                          ->mValue.int_value);
 }
 
@@ -477,7 +474,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsWithCondition) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(100, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
-                           .mFields->begin()
+                           .mFields.begin()
                            ->mValue.int_value);
     ASSERT_EQ(0UL, gaugeProducer.mPastBuckets.size());
 
@@ -489,7 +486,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsWithCondition) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(110, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
-                           .mFields->begin()
+                           .mFields.begin()
                            ->mValue.int_value);
     ASSERT_EQ(1UL, gaugeProducer.mPastBuckets.size());
 
@@ -519,7 +516,6 @@ TEST(GaugeMetricProducerTest, TestPulledEventsWithSlicedCondition) {
     GaugeMetric metric;
     metric.set_id(1111111);
     metric.set_bucket(ONE_MINUTE);
-    metric.mutable_gauge_fields_filter()->set_include_all(true);
     metric.set_condition(StringToId("APP_DIED"));
     metric.set_max_pull_delay_sec(INT_MAX);
     auto dim = metric.mutable_dimensions_in_what();
@@ -628,7 +624,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsAnomalyDetection) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(13L, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
-                           .mFields->begin()
+                           .mFields.begin()
                            ->mValue.int_value);
     EXPECT_EQ(anomalyTracker->getRefractoryPeriodEndsSec(DEFAULT_METRIC_DIMENSION_KEY), 0U);
 
@@ -642,7 +638,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsAnomalyDetection) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(15L, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
-                           .mFields->begin()
+                           .mFields.begin()
                            ->mValue.int_value);
     EXPECT_EQ(anomalyTracker->getRefractoryPeriodEndsSec(DEFAULT_METRIC_DIMENSION_KEY),
               std::ceil(1.0 * event2->GetElapsedTimestampNs() / NS_PER_SEC) + refPeriodSec);
@@ -655,7 +651,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsAnomalyDetection) {
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
     EXPECT_EQ(26L, gaugeProducer.mCurrentSlicedBucket->begin()
                            ->second.front()
-                           .mFields->begin()
+                           .mFields.begin()
                            ->mValue.int_value);
     EXPECT_EQ(anomalyTracker->getRefractoryPeriodEndsSec(DEFAULT_METRIC_DIMENSION_KEY),
               std::ceil(1.0 * event2->GetElapsedTimestampNs() / NS_PER_SEC + refPeriodSec));
@@ -666,7 +662,7 @@ TEST(GaugeMetricProducerTest, TestPulledEventsAnomalyDetection) {
     gaugeProducer.onDataPulled(allData, PullResult::PULL_RESULT_SUCCESS,
                                bucketStartTimeNs + 3 * bucketSizeNs);
     ASSERT_EQ(1UL, gaugeProducer.mCurrentSlicedBucket->size());
-    EXPECT_TRUE(gaugeProducer.mCurrentSlicedBucket->begin()->second.front().mFields->empty());
+    EXPECT_TRUE(gaugeProducer.mCurrentSlicedBucket->begin()->second.front().mFields.empty());
 }
 
 TEST(GaugeMetricProducerTest, TestPullOnTrigger) {
@@ -674,7 +670,6 @@ TEST(GaugeMetricProducerTest, TestPullOnTrigger) {
     metric.set_id(metricId);
     metric.set_bucket(ONE_MINUTE);
     metric.set_sampling_type(GaugeMetric::FIRST_N_SAMPLES);
-    metric.mutable_gauge_fields_filter()->set_include_all(false);
     metric.set_max_pull_delay_sec(INT_MAX);
     auto gaugeFieldMatcher = metric.mutable_gauge_fields_filter()->mutable_fields();
     gaugeFieldMatcher->set_field(tagId);
@@ -799,7 +794,6 @@ TEST(GaugeMetricProducerTest, TestRemoveDimensionInOutput) {
     metric.set_id(metricId);
     metric.set_bucket(ONE_MINUTE);
     metric.set_sampling_type(GaugeMetric::FIRST_N_SAMPLES);
-    metric.mutable_gauge_fields_filter()->set_include_all(true);
     metric.set_max_pull_delay_sec(INT_MAX);
     auto dimensionMatcher = metric.mutable_dimensions_in_what();
     // use field 1 as dimension.
diff --git a/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp b/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
index 6b6ab370..b72e0415 100644
--- a/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
+++ b/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
@@ -592,6 +592,30 @@ TEST_F(MetricsManagerUtilTest, TestEventMetricValidSamplingPercentage) {
     EXPECT_EQ(initConfig(config), nullopt);
 }
 
+TEST_F(MetricsManagerUtilTest, TestEventMetricIncorrectFieldFilter) {
+    StatsdConfig config;
+    int64_t metricId = 1;
+    EventMetric* metric = config.add_event_metric();
+    metric->set_id(metricId);
+    metric->set_what(1);
+    metric->mutable_fields_filter()->mutable_fields();
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_METRIC_INCORRECT_FIELD_FILTER, metricId));
+}
+
+TEST_F(MetricsManagerUtilTest, TestEventMetricIncorrectFieldFilterOmitNoLeafValues) {
+    StatsdConfig config;
+    int64_t metricId = 1;
+    EventMetric* metric = config.add_event_metric();
+    metric->set_id(metricId);
+    metric->set_what(1);
+    metric->mutable_fields_filter()->mutable_omit_fields();
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_METRIC_INCORRECT_FIELD_FILTER, metricId));
+}
+
 TEST_F(MetricsManagerUtilTest, TestGaugeMetricInvalidSamplingPercentage) {
     StatsdConfig config;
     GaugeMetric* metric = config.add_gauge_metric();
@@ -1123,16 +1147,28 @@ TEST_F(MetricsManagerUtilTest, TestKllMetricHasIncorrectKllField) {
                                   metricId));
 }
 
-TEST_F(MetricsManagerUtilTest, TestGaugeMetricIncorrectFieldFilter) {
+TEST_F(MetricsManagerUtilTest, TestGaugeMetricIncorrectFieldFilterNoLeafValues) {
     StatsdConfig config;
     int64_t metricId = 1;
     GaugeMetric* metric = config.add_gauge_metric();
     metric->set_id(metricId);
     metric->set_what(1);
+    metric->mutable_gauge_fields_filter()->mutable_fields();
 
     EXPECT_EQ(initConfig(config),
-              InvalidConfigReason(INVALID_CONFIG_REASON_GAUGE_METRIC_INCORRECT_FIELD_FILTER,
-                                  metricId));
+              InvalidConfigReason(INVALID_CONFIG_REASON_METRIC_INCORRECT_FIELD_FILTER, metricId));
+}
+
+TEST_F(MetricsManagerUtilTest, TestGaugeMetricIncorrectFieldFilterOmitNoLeafValues) {
+    StatsdConfig config;
+    int64_t metricId = 1;
+    GaugeMetric* metric = config.add_gauge_metric();
+    metric->set_id(metricId);
+    metric->set_what(1);
+    metric->mutable_gauge_fields_filter()->mutable_omit_fields();
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_METRIC_INCORRECT_FIELD_FILTER, metricId));
 }
 
 TEST_F(MetricsManagerUtilTest, TestGaugeMetricTriggerNoPullAtom) {
@@ -1141,7 +1177,6 @@ TEST_F(MetricsManagerUtilTest, TestGaugeMetricTriggerNoPullAtom) {
     GaugeMetric* metric = config.add_gauge_metric();
     metric->set_id(metricId);
     metric->set_what(StringToId("ScreenTurnedOn"));
-    metric->mutable_gauge_fields_filter()->set_include_all(true);
     metric->set_trigger_event(1);
 
     *config.add_atom_matcher() = CreateScreenTurnedOnAtomMatcher();
@@ -1160,7 +1195,6 @@ TEST_F(MetricsManagerUtilTest, TestGaugeMetricTriggerNoFirstNSamples) {
     *config.add_atom_matcher() =
             CreateSimpleAtomMatcher(/*name=*/"Matcher", /*atomId=*/util::SUBSYSTEM_SLEEP_STATE);
 
-    metric->mutable_gauge_fields_filter()->set_include_all(true);
     metric->set_trigger_event(StringToId("Matcher"));
 
     EXPECT_EQ(initConfig(config),
diff --git a/statsd/tests/shell/ShellSubscriber_test.cpp b/statsd/tests/shell/ShellSubscriber_test.cpp
index 34addb12..21cdf5dd 100644
--- a/statsd/tests/shell/ShellSubscriber_test.cpp
+++ b/statsd/tests/shell/ShellSubscriber_test.cpp
@@ -83,17 +83,23 @@ const int kSingleClient = 1;
 const int kNumClients = 11;
 
 // Utility to make an expected pulled atom shell data
-ShellData getExpectedPulledData() {
+ShellData getExpectedPulledData(bool withLoggingUid = false) {
     ShellData shellData;
     auto* atom1 = shellData.add_atom()->mutable_cpu_active_time();
     atom1->set_uid(kUid1);
     atom1->set_time_millis(kCpuTime1);
     shellData.add_elapsed_timestamp_nanos(kCpuActiveTimeEventTimestampNs);
+    if (withLoggingUid) {
+        shellData.add_logging_uid(0);
+    }
 
     auto* atom2 = shellData.add_atom()->mutable_cpu_active_time();
     atom2->set_uid(kUid2);
     atom2->set_time_millis(kCpuTime2);
     shellData.add_elapsed_timestamp_nanos(kCpuActiveTimeEventTimestampNs);
+    if (withLoggingUid) {
+        shellData.add_logging_uid(0);
+    }
 
     return shellData;
 }
@@ -125,13 +131,13 @@ vector<std::shared_ptr<LogEvent>> getPushedEvents() {
     vector<std::shared_ptr<LogEvent>> pushedList;
     // Create the LogEvent from an AStatsEvent
     std::unique_ptr<LogEvent> logEvent1 = CreateScreenStateChangedEvent(
-            1000 /*timestamp*/, ::android::view::DisplayStateEnum::DISPLAY_STATE_ON);
+            1000 /*timestamp*/, ::android::view::DisplayStateEnum::DISPLAY_STATE_ON, kUid1);
     std::unique_ptr<LogEvent> logEvent2 = CreateScreenStateChangedEvent(
-            2000 /*timestamp*/, ::android::view::DisplayStateEnum::DISPLAY_STATE_OFF);
+            2000 /*timestamp*/, ::android::view::DisplayStateEnum::DISPLAY_STATE_OFF, kUid1);
     std::unique_ptr<LogEvent> logEvent3 = CreateBatteryStateChangedEvent(
-            3000 /*timestamp*/, BatteryPluggedStateEnum::BATTERY_PLUGGED_USB);
+            3000 /*timestamp*/, BatteryPluggedStateEnum::BATTERY_PLUGGED_USB, kUid2);
     std::unique_ptr<LogEvent> logEvent4 = CreateBatteryStateChangedEvent(
-            4000 /*timestamp*/, BatteryPluggedStateEnum::BATTERY_PLUGGED_NONE);
+            4000 /*timestamp*/, BatteryPluggedStateEnum::BATTERY_PLUGGED_NONE, kUid2);
     pushedList.push_back(std::move(logEvent1));
     pushedList.push_back(std::move(logEvent2));
     pushedList.push_back(std::move(logEvent3));
@@ -716,7 +722,19 @@ TEST_F(ShellSubscriberCallbackPulledTest, testMinSleep) {
     EXPECT_THAT(sleepTimeMs, Eq(ShellSubscriberClient::kMinCallbackSleepIntervalMs));
 }
 
-TEST(ShellSubscriberTest, testPushedSubscription) {
+class ShellSubscriberTest : public testing::TestWithParam<bool> {
+public:
+    bool doCollectUids() const {
+        return GetParam();
+    }
+};
+
+INSTANTIATE_TEST_SUITE_P(ShellSubscriberTest, ShellSubscriberTest, testing::Values(false, true),
+                         [](const testing::TestParamInfo<ShellSubscriberTest::ParamType>& info) {
+                             return info.param ? "withUid" : "noUids";
+                         });
+
+TEST_P(ShellSubscriberTest, testPushedSubscription) {
     sp<MockUidMap> uidMap = new NaggyMock<MockUidMap>();
     sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
 
@@ -725,6 +743,7 @@ TEST(ShellSubscriberTest, testPushedSubscription) {
     // create a simple config to get screen events
     ShellSubscription config;
     config.add_pushed()->set_atom_id(SCREEN_STATE_CHANGED);
+    config.set_collect_uids(doCollectUids());
 
     // this is the expected screen event atom.
     vector<ShellData> expectedData;
@@ -736,6 +755,12 @@ TEST(ShellSubscriberTest, testPushedSubscription) {
     shellData2.add_atom()->mutable_screen_state_changed()->set_state(
             ::android::view::DisplayStateEnum::DISPLAY_STATE_OFF);
     shellData2.add_elapsed_timestamp_nanos(pushedList[1]->GetElapsedTimestampNs());
+
+    if (doCollectUids()) {
+        shellData1.add_logging_uid(kUid1);
+        shellData2.add_logging_uid(kUid1);
+    }
+
     expectedData.push_back(shellData1);
     expectedData.push_back(shellData2);
 
@@ -747,7 +772,7 @@ TEST(ShellSubscriberTest, testPushedSubscription) {
     TRACE_CALL(runShellTest, config, uidMap, pullerManager, pushedList, expectedData, kNumClients);
 }
 
-TEST(ShellSubscriberTest, testPulledSubscription) {
+TEST_P(ShellSubscriberTest, testPulledSubscription) {
     sp<MockUidMap> uidMap = new NaggyMock<MockUidMap>();
     sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
 
@@ -770,7 +795,7 @@ TEST(ShellSubscriberTest, testPulledSubscription) {
                {getExpectedPulledData()}, kNumClients);
 }
 
-TEST(ShellSubscriberTest, testBothSubscriptions) {
+TEST_P(ShellSubscriberTest, testBothSubscriptions) {
     sp<MockUidMap> uidMap = new NaggyMock<MockUidMap>();
     sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
 
@@ -788,6 +813,7 @@ TEST(ShellSubscriberTest, testBothSubscriptions) {
 
     ShellSubscription config = getPulledConfig();
     config.add_pushed()->set_atom_id(SCREEN_STATE_CHANGED);
+    config.set_collect_uids(doCollectUids());
 
     vector<ShellData> expectedData;
     ShellData shellData1;
@@ -798,7 +824,13 @@ TEST(ShellSubscriberTest, testBothSubscriptions) {
     shellData2.add_atom()->mutable_screen_state_changed()->set_state(
             ::android::view::DisplayStateEnum::DISPLAY_STATE_OFF);
     shellData2.add_elapsed_timestamp_nanos(pushedList[1]->GetElapsedTimestampNs());
-    expectedData.push_back(getExpectedPulledData());
+
+    if (doCollectUids()) {
+        shellData1.add_logging_uid(pushedList[0]->GetUid());
+        shellData2.add_logging_uid(pushedList[1]->GetUid());
+    }
+
+    expectedData.push_back(getExpectedPulledData(doCollectUids()));
     expectedData.push_back(shellData1);
     expectedData.push_back(shellData2);
 
@@ -810,7 +842,7 @@ TEST(ShellSubscriberTest, testBothSubscriptions) {
     TRACE_CALL(runShellTest, config, uidMap, pullerManager, pushedList, expectedData, kNumClients);
 }
 
-TEST(ShellSubscriberTest, testMaxSizeGuard) {
+TEST_P(ShellSubscriberTest, testMaxSizeGuard) {
     sp<MockUidMap> uidMap = new NaggyMock<MockUidMap>();
     sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
     sp<ShellSubscriber> shellManager =
@@ -834,7 +866,7 @@ TEST(ShellSubscriberTest, testMaxSizeGuard) {
     close(fds_data[1]);
 }
 
-TEST(ShellSubscriberTest, testMaxSubscriptionsGuard) {
+TEST_P(ShellSubscriberTest, testMaxSubscriptionsGuard) {
     sp<MockUidMap> uidMap = new NaggyMock<MockUidMap>();
     sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
     sp<ShellSubscriber> shellManager =
@@ -843,6 +875,7 @@ TEST(ShellSubscriberTest, testMaxSubscriptionsGuard) {
     // create a simple config to get screen events
     ShellSubscription config;
     config.add_pushed()->set_atom_id(SCREEN_STATE_CHANGED);
+    config.set_collect_uids(doCollectUids());
 
     size_t bufferSize = config.ByteSize();
     vector<uint8_t> buffer(bufferSize);
@@ -884,7 +917,7 @@ TEST(ShellSubscriberTest, testMaxSubscriptionsGuard) {
     // Not closing fds_datas[i][0] because this causes writes within ShellSubscriberClient to hang
 }
 
-TEST(ShellSubscriberTest, testDifferentConfigs) {
+TEST_P(ShellSubscriberTest, testDifferentConfigs) {
     sp<MockUidMap> uidMap = new NaggyMock<MockUidMap>();
     sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
     sp<ShellSubscriber> shellManager =
@@ -896,7 +929,9 @@ TEST(ShellSubscriberTest, testDifferentConfigs) {
     // create a simple config to get screen events
     ShellSubscription configs[numConfigs];
     configs[0].add_pushed()->set_atom_id(SCREEN_STATE_CHANGED);
+    configs[0].set_collect_uids(doCollectUids());
     configs[1].add_pushed()->set_atom_id(PLUGGED_STATE_CHANGED);
+    configs[1].set_collect_uids(doCollectUids());
 
     vector<vector<uint8_t>> configBuffers;
     for (int i = 0; i < numConfigs; i++) {
@@ -938,6 +973,9 @@ TEST(ShellSubscriberTest, testDifferentConfigs) {
     expected1.add_atom()->mutable_screen_state_changed()->set_state(
             ::android::view::DisplayStateEnum::DISPLAY_STATE_ON);
     expected1.add_elapsed_timestamp_nanos(pushedList[0]->GetElapsedTimestampNs());
+    if (doCollectUids()) {
+        expected1.add_logging_uid(pushedList[0]->GetUid());
+    }
     EXPECT_THAT(expected1, EqShellData(actual1));
 
     ShellData actual2 = readData(fds_datas[0][0]);
@@ -945,6 +983,9 @@ TEST(ShellSubscriberTest, testDifferentConfigs) {
     expected2.add_atom()->mutable_screen_state_changed()->set_state(
             ::android::view::DisplayStateEnum::DISPLAY_STATE_OFF);
     expected2.add_elapsed_timestamp_nanos(pushedList[1]->GetElapsedTimestampNs());
+    if (doCollectUids()) {
+        expected2.add_logging_uid(pushedList[1]->GetUid());
+    }
     EXPECT_THAT(expected2, EqShellData(actual2));
 
     // Validate Config 2, repeating the process
@@ -953,6 +994,9 @@ TEST(ShellSubscriberTest, testDifferentConfigs) {
     expected3.add_atom()->mutable_plugged_state_changed()->set_state(
             BatteryPluggedStateEnum::BATTERY_PLUGGED_USB);
     expected3.add_elapsed_timestamp_nanos(pushedList[2]->GetElapsedTimestampNs());
+    if (doCollectUids()) {
+        expected3.add_logging_uid(pushedList[2]->GetUid());
+    }
     EXPECT_THAT(expected3, EqShellData(actual3));
 
     ShellData actual4 = readData(fds_datas[1][0]);
@@ -960,12 +1004,15 @@ TEST(ShellSubscriberTest, testDifferentConfigs) {
     expected4.add_atom()->mutable_plugged_state_changed()->set_state(
             BatteryPluggedStateEnum::BATTERY_PLUGGED_NONE);
     expected4.add_elapsed_timestamp_nanos(pushedList[3]->GetElapsedTimestampNs());
+    if (doCollectUids()) {
+        expected4.add_logging_uid(pushedList[3]->GetUid());
+    }
     EXPECT_THAT(expected4, EqShellData(actual4));
 
     // Not closing fds_datas[i][0] because this causes writes within ShellSubscriberClient to hang
 }
 
-TEST(ShellSubscriberTest, testPushedSubscriptionRestrictedEvent) {
+TEST_P(ShellSubscriberTest, testPushedSubscriptionRestrictedEvent) {
     sp<MockUidMap> uidMap = new NaggyMock<MockUidMap>();
     sp<MockStatsPullerManager> pullerManager = new StrictMock<MockStatsPullerManager>();
 
@@ -975,6 +1022,7 @@ TEST(ShellSubscriberTest, testPushedSubscriptionRestrictedEvent) {
     // create a simple config to get screen events
     ShellSubscription config;
     config.add_pushed()->set_atom_id(10);
+    config.set_collect_uids(doCollectUids());
 
     // expect empty data
     vector<ShellData> expectedData;
diff --git a/statsd/tests/statsd_test_util.cpp b/statsd/tests/statsd_test_util.cpp
index 6185c556..6ffd6c33 100644
--- a/statsd/tests/statsd_test_util.cpp
+++ b/statsd/tests/statsd_test_util.cpp
@@ -537,13 +537,16 @@ FieldMatcher CreateAttributionUidAndOtherDimensions(const int atomId,
 }
 
 EventMetric createEventMetric(const string& name, const int64_t what,
-                              const optional<int64_t>& condition) {
+                              const optional<int64_t>& condition, const vector<int64_t>& states) {
     EventMetric metric;
     metric.set_id(StringToId(name));
     metric.set_what(what);
     if (condition) {
         metric.set_condition(condition.value());
     }
+    for (const int64_t state : states) {
+        metric.add_slice_by_state(state);
+    }
     return metric;
 }
 
@@ -581,7 +584,8 @@ DurationMetric createDurationMetric(const string& name, const int64_t what,
 GaugeMetric createGaugeMetric(const string& name, const int64_t what,
                               const GaugeMetric::SamplingType samplingType,
                               const optional<int64_t>& condition,
-                              const optional<int64_t>& triggerEvent) {
+                              const optional<int64_t>& triggerEvent,
+                              const vector<int64_t>& states) {
     GaugeMetric metric;
     metric.set_id(StringToId(name));
     metric.set_what(what);
@@ -593,7 +597,9 @@ GaugeMetric createGaugeMetric(const string& name, const int64_t what,
     if (triggerEvent) {
         metric.set_trigger_event(triggerEvent.value());
     }
-    metric.mutable_gauge_fields_filter()->set_include_all(true);
+    for (const int64_t state : states) {
+        metric.add_slice_by_state(state);
+    }
     return metric;
 }
 
@@ -2151,6 +2157,17 @@ void backfillAggregatedAtomsInEventMetric(StatsLogReport::EventMetricDataWrapper
             data.set_elapsed_timestamp_nanos(atomInfo->elapsed_timestamp_nanos(j));
             metricData.push_back(data);
         }
+        for (int j = 0; j < atomInfo->state_info_size(); j++) {
+            for (auto timestampNs : atomInfo->state_info(j).elapsed_timestamp_nanos()) {
+                EventMetricData data;
+                *(data.mutable_atom()) = atomInfo->atom();
+                for (auto state : atomInfo->state_info(j).slice_by_state()) {
+                    *(data.add_slice_by_state()) = state;
+                }
+                data.set_elapsed_timestamp_nanos(timestampNs);
+                metricData.push_back(data);
+            }
+        }
     }
 
     if (metricData.size() == 0) {
@@ -2244,6 +2261,32 @@ Status FakeSubsystemSleepCallback::onPullAtom(int atomTag,
     return Status::ok();
 }
 
+Status FakeCpuTimeCallback::onPullAtom(int atomTag,
+                                       const shared_ptr<IPullAtomResultReceiver>& resultReceiver) {
+    // Convert stats_events into StatsEventParcels.
+    std::vector<StatsEventParcel> parcels;
+    for (int i = 1; i < 3; i++) {
+        AStatsEvent* event = AStatsEvent_obtain();
+        AStatsEvent_setAtomId(event, atomTag);
+        AStatsEvent_writeInt32(event, /*uid=*/i);
+        AStatsEvent_writeInt64(event, /*user_time_micros= */ pullNum * pullNum * 100 + i);
+        AStatsEvent_writeInt64(event, /*sys_time_micros= */ pullNum * pullNum * 100 * i);
+        AStatsEvent_build(event);
+        size_t size;
+        uint8_t* buffer = AStatsEvent_getBuffer(event, &size);
+
+        StatsEventParcel p;
+        // vector.assign() creates a copy, but this is inevitable unless
+        // stats_event.h/c uses a vector as opposed to a buffer.
+        p.buffer.assign(buffer, buffer + size);
+        parcels.push_back(std::move(p));
+        AStatsEvent_release(event);
+    }
+    pullNum++;
+    resultReceiver->pullFinished(atomTag, /*success=*/true, parcels);
+    return Status::ok();
+}
+
 void writeFlag(const string& flagName, const string& flagValue) {
     SetProperty(StringPrintf("persist.device_config.%s.%s", STATSD_NATIVE_NAMESPACE.c_str(),
                              flagName.c_str()),
diff --git a/statsd/tests/statsd_test_util.h b/statsd/tests/statsd_test_util.h
index 294553d6..404d9e2a 100644
--- a/statsd/tests/statsd_test_util.h
+++ b/statsd/tests/statsd_test_util.h
@@ -337,7 +337,8 @@ FieldMatcher CreateAttributionUidAndOtherDimensions(const int atomId,
                                                     const std::vector<Position>& positions,
                                                     const std::vector<int>& fields);
 
-EventMetric createEventMetric(const string& name, int64_t what, const optional<int64_t>& condition);
+EventMetric createEventMetric(const string& name, int64_t what, const optional<int64_t>& condition,
+                              const vector<int64_t>& states = {});
 
 CountMetric createCountMetric(const string& name, int64_t what, const optional<int64_t>& condition,
                               const vector<int64_t>& states);
@@ -349,7 +350,8 @@ DurationMetric createDurationMetric(const string& name, int64_t what,
 GaugeMetric createGaugeMetric(const string& name, int64_t what,
                               const GaugeMetric::SamplingType samplingType,
                               const optional<int64_t>& condition,
-                              const optional<int64_t>& triggerEvent);
+                              const optional<int64_t>& triggerEvent,
+                              const vector<int64_t>& states = {});
 
 ValueMetric createValueMetric(const string& name, const AtomMatcher& what, int valueField,
                               const optional<int64_t>& condition, const vector<int64_t>& states);
@@ -709,6 +711,14 @@ public:
                       const shared_ptr<IPullAtomResultReceiver>& resultReceiver) override;
 };
 
+class FakeCpuTimeCallback : public BnPullAtomCallback {
+public:
+    // Track the number of pulls.
+    int pullNum = 1;
+    Status onPullAtom(int atomTag,
+                      const shared_ptr<IPullAtomResultReceiver>& resultReceiver) override;
+};
+
 template <typename T>
 void backfillDimensionPath(const DimensionsValue& whatPath, T* metricData) {
     for (int i = 0; i < metricData->data_size(); ++i) {
diff --git a/statsd/tools/localtools/src/com/android/statsd/shelltools/ExtensionAtomsRegistry.java b/statsd/tools/localtools/src/com/android/statsd/shelltools/ExtensionAtomsRegistry.java
index adf18a94..fb710bbd 100644
--- a/statsd/tools/localtools/src/com/android/statsd/shelltools/ExtensionAtomsRegistry.java
+++ b/statsd/tools/localtools/src/com/android/statsd/shelltools/ExtensionAtomsRegistry.java
@@ -44,6 +44,7 @@ import com.android.os.locale.LocaleAtoms;
 import com.android.os.location.LocationAtoms;
 import com.android.os.location.LocationExtensionAtoms;
 import com.android.os.media.MediaDrmAtoms;
+import com.android.os.memory.ZramExtensionAtoms;
 import com.android.os.memorysafety.MemorysafetyExtensionAtoms;
 import com.android.os.permissioncontroller.PermissioncontrollerExtensionAtoms;
 import com.android.os.providers.mediaprovider.MediaProviderAtoms;
@@ -154,5 +155,6 @@ public class ExtensionAtomsRegistry {
         UprobestatsExtensionAtoms.registerAllExtensions(extensionRegistry);
         AccessibilityExtensionAtoms.registerAllExtensions(extensionRegistry);
         BroadcastsExtensionAtoms.registerAllExtensions(extensionRegistry);
+        ZramExtensionAtoms.registerAllExtensions(extensionRegistry);
     }
 }
diff --git a/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java b/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
index d7cfe9eb..e3952d86 100644
--- a/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
+++ b/statsd/tools/localtools/src/com/android/statsd/shelltools/testdrive/TestDrive.java
@@ -31,6 +31,7 @@ import com.android.os.StatsLog.ConfigMetricsReport;
 import com.android.os.StatsLog.ConfigMetricsReportList;
 import com.android.os.StatsLog.StatsLogReport;
 import com.android.os.framework.FrameworkExtensionAtoms;
+import com.android.os.memory.ZramExtensionAtoms;
 import com.android.os.telephony.qns.QnsExtensionAtoms;
 import com.android.statsd.shelltools.Utils;
 
@@ -105,6 +106,8 @@ public class TestDrive {
             "AID_UPROBESTATS",
             "com.google.android.hardware.biometrics.face",
             "com.google.android.photopicker",
+            "AID_MMD",
+            "com.google.android.desktop.identity.login",
     };
     private static final String[] DEFAULT_PULL_SOURCES = {
             "AID_KEYSTORE", "AID_RADIO", "AID_SYSTEM",
@@ -622,6 +625,16 @@ public class TestDrive {
                                     .setAtomId(QnsExtensionAtoms
                                             .QNS_HANDOVER_PINGPONG_FIELD_NUMBER)
                                     .addPackages("com.android.telephony.qns"))
+                    .addPullAtomPackages(
+                            PullAtomPackages.newBuilder()
+                                    .setAtomId(ZramExtensionAtoms
+                                            .ZRAM_MM_STAT_MMD_FIELD_NUMBER)
+                                    .addPackages("AID_MMD"))
+                    .addPullAtomPackages(
+                            PullAtomPackages.newBuilder()
+                                    .setAtomId(ZramExtensionAtoms
+                                            .ZRAM_BD_STAT_MMD_FIELD_NUMBER)
+                                    .addPackages("AID_MMD"))
                     .setHashStringsInMetricReport(false);
         }
     }
diff --git a/tests/Android.bp b/tests/Android.bp
index e58f1d42..74f03961 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -32,19 +32,20 @@ java_test_host {
         "mts-statsd",
         "mcts-statsd",
     ],
-
     libs: [
         "compatibility-host-util",
         "cts-tradefed",
         "host-libprotobuf-java-full",
-        "platformprotos",
         "tradefed",
         "truth",
     ],
     static_libs: [
+        "platformprotos",
         "core_cts_test_resources",
         "perfetto_config-full",
         "cts-statsd-atom-host-test-utils",
+        "statsd_flags_java_lib-host",
+        "flag-junit-host",
     ],
     data: [
         "**/*.pbtxt",
@@ -53,4 +54,5 @@ java_test_host {
         ":CtsStatsdApp",
         ":StatsdAtomStormApp",
     ],
+    jarjar_rules: "jarjar-rules.txt",
 }
diff --git a/tests/apps/statsdapp/src/com/android/server/cts/device/statsd/AtomTests.java b/tests/apps/statsdapp/src/com/android/server/cts/device/statsd/AtomTests.java
index d457fd80..5f6794aa 100644
--- a/tests/apps/statsdapp/src/com/android/server/cts/device/statsd/AtomTests.java
+++ b/tests/apps/statsdapp/src/com/android/server/cts/device/statsd/AtomTests.java
@@ -642,15 +642,14 @@ public class AtomTests {
         StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED, uids, tags, 42,
                 Long.MAX_VALUE, 3.14f, "This is a basic test!", false,
                 StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__ON, testAtomNestedMsg,
-                int32Array,
-                int64Array, floatArray, stringArray, boolArray, enumArray);
+                int32Array, int64Array, floatArray, stringArray, boolArray, enumArray, int32Array,
+                int32Array, int32Array);
 
         // All nulls. Should get dropped since cts app is not in the attribution chain.
         StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED, null, null, 0, 0,
                 0f, null,
                 false, StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__ON, null, null, null,
-                null,
-                null, null, null);
+                null, null, null, null, null, null, null);
 
         // Null tag in attribution chain.
         int[] uids2 = {9999, appInfo.uid};
@@ -658,23 +657,22 @@ public class AtomTests {
         StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED, uids2, tags2, 100,
                 Long.MIN_VALUE, -2.5f, "Test null uid", true,
                 StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__UNKNOWN, testAtomNestedMsg,
-                int32Array,
-                int64Array, floatArray, stringArray, boolArray, enumArray);
+                int32Array, int64Array, floatArray, stringArray, boolArray, enumArray, int32Array,
+                int32Array, int32Array);
 
         // Non chained non-null
         StatsLogStatsdCts.write_non_chained(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED,
                 appInfo.uid,
                 "tag1", -256, -1234567890L, 42.01f, "Test non chained", true,
                 StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__OFF, testAtomNestedMsg,
-                new int[0],
-                new long[0], new float[0], new String[0], new boolean[0], new int[0]);
+                new int[0], new long[0], new float[0], new String[0], new boolean[0], new int[0],
+                new int[0], new int[0], new int[0]);
 
         // Non chained all null
         StatsLogStatsdCts.write_non_chained(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED,
                 appInfo.uid, null,
                 0, 0, 0f, null, true, StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__OFF,
-                null, null,
-                null, null, null, null, null);
+                null, null, null, null, null, null, null, null, null, null);
     }
 
     @Test
diff --git a/tests/jarjar-rules.txt b/tests/jarjar-rules.txt
new file mode 100644
index 00000000..0d84e417
--- /dev/null
+++ b/tests/jarjar-rules.txt
@@ -0,0 +1,2 @@
+rule com.android.os.StatsLog.** com.android.os.internal.StatsLog.@0
+rule android.cts.statsdatom.lib.** android.cts.internal.statsdatom.lib.@0
\ No newline at end of file
diff --git a/tests/src/android/cts/statsd/metadata/MetadataTestCase.java b/tests/src/android/cts/statsd/metadata/MetadataTestCase.java
index 1f0e5a1b..7e046527 100644
--- a/tests/src/android/cts/statsd/metadata/MetadataTestCase.java
+++ b/tests/src/android/cts/statsd/metadata/MetadataTestCase.java
@@ -18,28 +18,31 @@ package android.cts.statsd.metadata;
 
 import static com.google.common.truth.Truth.assertThat;
 
-import android.cts.statsd.atom.BufferDebug;
 import android.cts.statsd.metric.MetricsUtils;
 import android.cts.statsdatom.lib.ConfigUtils;
 import android.cts.statsdatom.lib.DeviceUtils;
 import android.cts.statsdatom.lib.ReportUtils;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.host.HostFlagsValueProvider;
 
 import com.android.internal.os.StatsdConfigProto.StatsdConfig;
 import com.android.os.AtomsProto.Atom;
 import com.android.os.StatsLog.StatsdStatsReport;
 import com.android.tradefed.build.IBuildInfo;
-import com.android.tradefed.device.CollectingByteOutputReceiver;
-import com.android.tradefed.device.DeviceNotAvailableException;
 import com.android.tradefed.log.LogUtil;
-import com.android.tradefed.testtype.DeviceTestCase;
 import com.android.tradefed.testtype.IBuildReceiver;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 import com.android.tradefed.util.RunUtil;
 
-import com.google.protobuf.InvalidProtocolBufferException;
-import com.google.protobuf.MessageLite;
-import com.google.protobuf.Parser;
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+
+public class MetadataTestCase extends BaseHostJUnit4Test implements IBuildReceiver {
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule =
+            HostFlagsValueProvider.createCheckFlagsRule(this::getDevice);
 
-public class MetadataTestCase extends DeviceTestCase implements IBuildReceiver {
     public static final String DUMP_METADATA_CMD = "cmd stats print-stats";
 
     protected IBuildInfo mCtsBuild;
@@ -62,9 +65,8 @@ public class MetadataTestCase extends DeviceTestCase implements IBuildReceiver {
         return builder;
     }
 
-    @Override
-    protected void setUp() throws Exception {
-        super.setUp();
+    @Before
+    public void setUp() throws Exception {
         assertThat(mCtsBuild).isNotNull();
         ConfigUtils.removeConfig(getDevice());
         ReportUtils.clearReports(getDevice());
@@ -73,12 +75,11 @@ public class MetadataTestCase extends DeviceTestCase implements IBuildReceiver {
         RunUtil.getDefault().sleep(1000);
     }
 
-    @Override
-    protected void tearDown() throws Exception {
+    @After
+    public void tearDown() throws Exception {
         ConfigUtils.removeConfig(getDevice());
         ReportUtils.clearReports(getDevice());
         DeviceUtils.uninstallTestApp(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE);
-        super.tearDown();
     }
 
     @Override
diff --git a/tests/src/android/cts/statsd/metadata/MetadataTests.java b/tests/src/android/cts/statsd/metadata/MetadataTests.java
index 0688cad4..772774e3 100644
--- a/tests/src/android/cts/statsd/metadata/MetadataTests.java
+++ b/tests/src/android/cts/statsd/metadata/MetadataTests.java
@@ -22,6 +22,7 @@ import android.cts.statsd.metric.MetricsUtils;
 import android.cts.statsdatom.lib.AtomTestUtils;
 import android.cts.statsdatom.lib.ConfigUtils;
 import android.cts.statsdatom.lib.DeviceUtils;
+import android.platform.test.annotations.RequiresFlagsEnabled;
 
 import com.android.compatibility.common.util.ApiLevelUtil;
 import com.android.internal.os.StatsdConfigProto.StatsdConfig;
@@ -33,14 +34,18 @@ import com.android.os.StatsLog.StatsdStatsReport.ConfigStats;
 import com.android.os.StatsLog.StatsdStatsReport.LogLossStats;
 import com.android.os.StatsLog.StatsdStatsReport.SocketLossStats.LossStatsPerUid;
 import com.android.os.StatsLog.StatsdStatsReport.SocketLossStats.LossStatsPerUid.AtomIdLossStats;
+import com.android.os.statsd.flags.Flags;
 import com.android.tradefed.log.LogUtil;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
 import com.android.tradefed.util.RunUtil;
 
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
 import java.util.HashSet;
 
-/**
- * Statsd Metadata tests.
- */
+/** Statsd Metadata tests. */
+@RunWith(DeviceJUnit4ClassRunner.class)
 public class MetadataTests extends MetadataTestCase {
 
     private static final String TAG = "Statsd.MetadataTests";
@@ -48,6 +53,7 @@ public class MetadataTests extends MetadataTestCase {
     private static final int SHELL_UID = 2000;
 
     // Tests that the statsd config is reset after the specified ttl.
+    @Test
     public void testConfigTtl() throws Exception {
         final int TTL_TIME_SEC = 8;
         StatsdConfig.Builder config = getBaseConfig();
@@ -118,12 +124,14 @@ public class MetadataTests extends MetadataTestCase {
     }
 
     private static final int LIB_STATS_SOCKET_QUEUE_OVERFLOW_ERROR_CODE = 1;
+    private static final int LIB_STATS_SOCKET_RATE_LIMIT_ERROR_CODE = 2;
     private static final int EVENT_STORM_ITERATIONS_COUNT = 10;
 
     /**
      * Tests that logging many atoms back to back potentially leads to socket overflow and data
      * loss. And if it happens the corresponding info is propagated to statsd stats
      */
+    @Test
     public void testAtomLossInfoCollection() throws Exception {
         DeviceUtils.runDeviceTests(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE,
                 ".StatsdStressLogging", "testLogAtomsBackToBack");
@@ -139,6 +147,49 @@ public class MetadataTests extends MetadataTestCase {
         // atom of interest
         for (LogLossStats lossStats : report.getDetectedLogLossList()) {
             if (lossStats.getLastTag() == Atom.APP_BREADCRUMB_REPORTED_FIELD_NUMBER) {
+
+                return;
+            }
+        }
+
+        if (report.getSocketLossStats() == null) {
+            return;
+        }
+        // if many atoms were lost the information in DetectedLogLoss can be overwritten
+        // looking into alternative stats to find the information
+        for (LossStatsPerUid lossStats : report.getSocketLossStats().getLossStatsPerUidList()) {
+            for (AtomIdLossStats atomLossStats : lossStats.getAtomIdLossStatsList()) {
+                if (atomLossStats.getAtomId() == Atom.APP_BREADCRUMB_REPORTED_FIELD_NUMBER) {
+                    return;
+                }
+            }
+        }
+        org.junit.Assert.fail("Socket loss detected but no info about atom of interest");
+    }
+
+    /** Tests logging rate limiting applied by libstatssocket */
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_LOGGING_RATE_LIMIT_ENABLED)
+    public void testSocketRateLimiting() throws Exception {
+        DeviceUtils.runDeviceTests(
+                getDevice(),
+                MetricsUtils.DEVICE_SIDE_TEST_PACKAGE,
+                ".StatsdStressLogging",
+                "testLogAtomsBackToBack");
+
+        StatsdStatsReport report = getStatsdStatsReport();
+        assertThat(report).isNotNull();
+
+        if (report.getDetectedLogLossList().size() == 0) {
+            return;
+        }
+        // it can be the case that system throughput is sufficient to overcome the
+        // simulated event storm, but if loss happens report can contain information about
+        // atom of interest
+        for (LogLossStats lossStats : report.getDetectedLogLossList()) {
+            if (lossStats.getLastTag() == Atom.APP_BREADCRUMB_REPORTED_FIELD_NUMBER) {
+                assertThat(lossStats.getLastError())
+                        .isEqualTo(LIB_STATS_SOCKET_RATE_LIMIT_ERROR_CODE);
                 return;
             }
         }
@@ -151,6 +202,8 @@ public class MetadataTests extends MetadataTestCase {
         for (LossStatsPerUid lossStats : report.getSocketLossStats().getLossStatsPerUidList()) {
             for (AtomIdLossStats atomLossStats : lossStats.getAtomIdLossStatsList()) {
                 if (atomLossStats.getAtomId() == Atom.APP_BREADCRUMB_REPORTED_FIELD_NUMBER) {
+                    assertThat(atomLossStats.getError())
+                            .isEqualTo(LIB_STATS_SOCKET_RATE_LIMIT_ERROR_CODE);
                     return;
                 }
             }
@@ -159,8 +212,9 @@ public class MetadataTests extends MetadataTestCase {
     }
 
     /** Tests that SystemServer logged atoms in case of loss event has error code 1. */
+    @Test
     public void testSystemServerLossErrorCode() throws Exception {
-        if (!sdkLevelAtLeast(34, "V")) {
+        if (!sdkLevelAtLeast(35, "V")) {
             return;
         }
 
@@ -231,8 +285,9 @@ public class MetadataTests extends MetadataTestCase {
     }
 
     /** Test libstatssocket logging queue atom id distribution collection */
+    @Test
     public void testAtomIdLossDistributionCollection() throws Exception {
-        if (!sdkLevelAtLeast(34, "V")) {
+        if (!sdkLevelAtLeast(35, "V")) {
             return;
         }
 
diff --git a/tests/src/android/cts/statsd/validation/ValidationTests.java b/tests/src/android/cts/statsd/validation/ValidationTests.java
index a3f01091..0f80b629 100644
--- a/tests/src/android/cts/statsd/validation/ValidationTests.java
+++ b/tests/src/android/cts/statsd/validation/ValidationTests.java
@@ -107,7 +107,7 @@ public class ValidationTests extends DeviceTestCase implements IBuildReceiver {
     private static final boolean ENABLE_LOAD_TEST = false;
 
     public void testPartialWakelock() throws Exception {
-        if (!DeviceUtils.hasFeature(getDevice(), FEATURE_AUTOMOTIVE)) return;
+        if (DeviceUtils.hasFeature(getDevice(), FEATURE_AUTOMOTIVE)) return;
         resetBatteryStats();
         DeviceUtils.unplugDevice(getDevice());
         DeviceUtils.flushBatteryStatsHandlers(getDevice());
@@ -119,11 +119,9 @@ public class ValidationTests extends DeviceTestCase implements IBuildReceiver {
 
         final int atomTag = Atom.WAKELOCK_STATE_CHANGED_FIELD_NUMBER;
         Set<Integer> wakelockOn = new HashSet<>(Arrays.asList(
-                WakelockStateChanged.State.ACQUIRE_VALUE,
-                WakelockStateChanged.State.CHANGE_ACQUIRE_VALUE));
+                WakelockStateChanged.State.ACQUIRE_VALUE));
         Set<Integer> wakelockOff = new HashSet<>(Arrays.asList(
-                WakelockStateChanged.State.RELEASE_VALUE,
-                WakelockStateChanged.State.CHANGE_RELEASE_VALUE));
+                WakelockStateChanged.State.RELEASE_VALUE));
 
         final String EXPECTED_TAG = "StatsdPartialWakelock";
         final WakeLockLevelEnum EXPECTED_LEVEL = WakeLockLevelEnum.PARTIAL_WAKE_LOCK;
@@ -154,7 +152,7 @@ public class ValidationTests extends DeviceTestCase implements IBuildReceiver {
 
     @RestrictedBuildTest
     public void testPartialWakelockDuration() throws Exception {
-        if (!DeviceUtils.hasFeature(getDevice(), FEATURE_AUTOMOTIVE)) return;
+        if (DeviceUtils.hasFeature(getDevice(), FEATURE_AUTOMOTIVE)) return;
 
         // getUid() needs shell command via ADB. turnScreenOff() sometimes let system go to suspend.
         // ADB disconnection causes failure of getUid(). Move up here before turnScreenOff().
```

