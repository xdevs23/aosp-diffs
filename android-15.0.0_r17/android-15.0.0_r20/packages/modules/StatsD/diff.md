```diff
diff --git a/apex/tests/libstatspull/Android.bp b/apex/tests/libstatspull/Android.bp
index 40174434..ab3cce86 100644
--- a/apex/tests/libstatspull/Android.bp
+++ b/apex/tests/libstatspull/Android.bp
@@ -62,5 +62,4 @@ cc_test_library {
     static_libs: [
         "libbase",
     ],
-    test_for: ["com.android.os.statsd"],
 }
diff --git a/flags/statsd_flags.aconfig b/flags/statsd_flags.aconfig
index c91c4469..ce1b0e04 100644
--- a/flags/statsd_flags.aconfig
+++ b/flags/statsd_flags.aconfig
@@ -8,3 +8,12 @@ flag {
   bug: "296108553"
   is_fixed_read_only: true
 }
+
+flag {
+    name: "enable_iouring"
+    namespace: "statsd"
+    description: "Enables iouring implementation of the statsd"
+    bug: "380509817"
+    is_fixed_read_only: true
+}
+
diff --git a/framework/Android.bp b/framework/Android.bp
index 385de02e..11a1dd36 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -94,6 +94,7 @@ java_sdk_library {
         "//packages/modules/StatsD/framework/test:__subpackages__",
         "//packages/modules/StatsD/tests/utils:__pkg__",
         "//packages/modules/StatsD/service:__subpackages__",
+        "//frameworks/base/ravenwood",
     ],
 
     apex_available: [
@@ -103,6 +104,14 @@ java_sdk_library {
     min_sdk_version: "30",
 }
 
+filegroup {
+    name: "framework-statsd-ravenwood-policies",
+    srcs: [
+        "framework-statsd-ravenwood-policies.txt",
+    ],
+    visibility: ["//frameworks/base/ravenwood"],
+}
+
 // JNI library for StatsLog.write
 cc_library_shared {
     name: "libstats_jni",
@@ -110,7 +119,7 @@ cc_library_shared {
     header_libs: ["libnativehelper_header_only"],
     shared_libs: [
         "liblog",  // Has a stable abi - should not be copied into apex.
-        "libstatssocket",
+        "libstatssocket#impl",
     ],
     stl: "libc++_static",
     cflags: [
diff --git a/framework/framework-statsd-ravenwood-policies.txt b/framework/framework-statsd-ravenwood-policies.txt
new file mode 100644
index 00000000..9838ec7f
--- /dev/null
+++ b/framework/framework-statsd-ravenwood-policies.txt
@@ -0,0 +1,10 @@
+# Policy file for ravenwood
+
+# Auto generated class by stats_log_api_gen.
+# We could update stats_log_api_gen and add the annotation to the generated code, but
+# then we need to make sure to add "framework-annotations-lib" as a dependency to all the build
+# modules. (Or else, make an option for this.)
+class com.android.internal.statsd.StatsdStatsLog keepclass
+
+# TODO(b/375040589) Convert to the annotation after fixing the issue.
+class android.util.StatsLog keepclass
\ No newline at end of file
diff --git a/framework/java/android/util/StatsEvent.java b/framework/java/android/util/StatsEvent.java
index 5538f4bc..ab49ae95 100644
--- a/framework/java/android/util/StatsEvent.java
+++ b/framework/java/android/util/StatsEvent.java
@@ -31,6 +31,8 @@ import com.android.internal.annotations.VisibleForTesting;
 
 import java.nio.ByteBuffer;
 import java.util.Arrays;
+import java.util.concurrent.atomic.AtomicReference;
+
 
 /**
  * StatsEvent builds and stores the buffer sent over the statsd socket.
@@ -59,6 +61,7 @@ import java.util.Arrays;
  * @hide
  **/
 @SystemApi
+@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public final class StatsEvent {
     // Type Ids.
     /**
@@ -846,29 +849,37 @@ public final class StatsEvent {
     }
 
     private static final class Buffer {
-        private static Object sLock = new Object();
 
-        @GuardedBy("sLock")
-        private static Buffer sPool;
+        private static AtomicReference<Buffer> sPool = new AtomicReference<>();
 
         private byte[] mBytes;
         private boolean mOverflow = false;
         private int mMaxSize = MAX_PULL_PAYLOAD_SIZE;
 
+        // The initial size of the buffer 512 bytes. The buffer will be expanded
+        // if needed up to mMaxSize.
+        private static final int INITIAL_BUFFER_SIZE = 512;
+
         @NonNull
         private static Buffer obtain() {
-            final Buffer buffer;
-            synchronized (sLock) {
-                buffer = null == sPool ? new Buffer() : sPool;
-                sPool = null;
+            Buffer buffer = sPool.getAndSet(null);
+            if (buffer == null) {
+                buffer = new Buffer();
+            } else {
+                buffer.reset();
             }
-            buffer.reset();
             return buffer;
         }
 
         private Buffer() {
-            final ByteBuffer tempBuffer = ByteBuffer.allocateDirect(MAX_PUSH_PAYLOAD_SIZE);
-            mBytes = tempBuffer.hasArray() ? tempBuffer.array() : new byte [MAX_PUSH_PAYLOAD_SIZE];
+            // b/366165284, b/192105193 - the allocateDirect() reduces the churn
+            // of passing a byte[] from Java to native. However, it's only
+            // useful for pushed atoms. In the case of pulled atom, the
+            // allocateDirect doesn't help anything as the data is later copied
+            // to a new array in build(). In addition, when the buffer is to be expanded, it
+            // also allocates a new array.
+            final ByteBuffer tempBuffer = ByteBuffer.allocateDirect(INITIAL_BUFFER_SIZE);
+            mBytes = tempBuffer.hasArray() ? tempBuffer.array() : new byte [INITIAL_BUFFER_SIZE];
         }
 
         @NonNull
@@ -879,11 +890,7 @@ public final class StatsEvent {
         private void release() {
             // Recycle this Buffer if its size is MAX_PUSH_PAYLOAD_SIZE or under.
             if (mMaxSize <= MAX_PUSH_PAYLOAD_SIZE) {
-                synchronized (sLock) {
-                    if (null == sPool) {
-                        sPool = this;
-                    }
-                }
+                sPool.compareAndSet(null, this);
             }
         }
 
diff --git a/framework/java/android/util/StatsLog.java b/framework/java/android/util/StatsLog.java
index f38751a9..79ec2fb5 100644
--- a/framework/java/android/util/StatsLog.java
+++ b/framework/java/android/util/StatsLog.java
@@ -42,12 +42,24 @@ import java.lang.annotation.RetentionPolicy;
  * StatsLog provides an API for developers to send events to statsd. The events can be used to
  * define custom metrics inside statsd.
  */
+// TODO(b/375040589) Can't use ravenwood annotations on public mainline APIs?
+// for now we use the policy text file instead.
+//@android.ravenwood.annotation.RavenwoodKeepWholeClass
 public final class StatsLog {
 
     // Load JNI library
     static {
+        loadNativeLibrary();
+    }
+
+    @android.ravenwood.annotation.RavenwoodReplace
+    private static void loadNativeLibrary() {
         System.loadLibrary("stats_jni");
     }
+
+    private static void loadNativeLibrary$ravenwood() {
+    }
+
     private static final String TAG = "StatsLog";
     private static final boolean DEBUG = false;
     private static final int EXPERIMENT_IDS_FIELD_ID = 1;
@@ -452,8 +464,14 @@ public final class StatsLog {
      * @param size      The number of bytes from the buffer to write.
      * @param atomId    The id of the atom to which the event belongs.
      */
+
+    @android.ravenwood.annotation.RavenwoodReplace
     private static native void writeImpl(@NonNull byte[] buffer, int size, int atomId);
 
+    private static void writeImpl$ravenwood(@NonNull byte[] buffer, int size, int atomId) {
+        // No actual logging on Ravenwood (for now).
+    }
+
     /**
      * Write an event to stats log using the raw format encapsulated in StatsEvent.
      * After writing to stats log, release() is called on the StatsEvent object.
diff --git a/framework/test/hostsidetests/Android.bp b/framework/test/hostsidetests/Android.bp
index b3e253c6..9a34d741 100644
--- a/framework/test/hostsidetests/Android.bp
+++ b/framework/test/hostsidetests/Android.bp
@@ -63,7 +63,7 @@ java_test_host {
         "device-tests",
         "mts-statsd",
     ],
-    data: [
+    device_common_data: [
         ":StatsdFrameworkTestApp",
         ":StatsdFrameworkTestAppNoPermission",
     ],
diff --git a/lib/libstatspull/Android.bp b/lib/libstatspull/Android.bp
index 252baca0..e57eab73 100644
--- a/lib/libstatspull/Android.bp
+++ b/lib/libstatspull/Android.bp
@@ -19,6 +19,7 @@
 // ==========================================================
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_telemetry_client_infra",
 }
 
 cc_defaults {
@@ -37,7 +38,7 @@ cc_defaults {
     shared_libs: [
         "libbinder_ndk",
         "liblog",
-        "libstatssocket",
+        "libstatssocket#impl",
     ],
     static_libs: [
         "libutils",
@@ -57,6 +58,7 @@ cc_library_shared {
         },
     },
     // enumerate stable entry points for APEX use
+    version_script: "libstatspull.map.txt",
     stubs: {
         symbol_file: "libstatspull.map.txt",
         versions: [
@@ -154,5 +156,4 @@ cc_test {
     ],
     require_root: true,
     min_sdk_version: "30",
-    test_for: ["com.android.os.statsd"],
 }
diff --git a/lib/libstatssocket/Android.bp b/lib/libstatssocket/Android.bp
index 7d7c9c1a..a0bfa51e 100644
--- a/lib/libstatssocket/Android.bp
+++ b/lib/libstatssocket/Android.bp
@@ -19,6 +19,7 @@
 // =========================================================================
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_telemetry_client_infra",
 }
 
 cc_defaults {
@@ -32,9 +33,11 @@ cc_defaults {
         "stats_socket_loss_reporter.cpp",
         "utils.cpp",
     ],
+    local_include_dirs: [
+        "include",
+    ],
     generated_sources: ["stats_statsdsocketlog.cpp"],
     generated_headers: ["stats_statsdsocketlog.h"],
-    export_include_dirs: ["include"],
     header_libs: [
         "libcutils_headers",
         "liblog_headers",
@@ -60,8 +63,14 @@ cc_library_shared {
     ],
     host_supported: true,
     stl: "libc++_static",
-
+    export_include_dirs: ["include"],
     // enumerate stable entry points for APEX use
+    target: {
+        darwin: {
+            enabled: false,
+        },
+    },
+    version_script: "libstatssocket.map.txt",
     stubs: {
         symbol_file: "libstatssocket.map.txt",
         versions: [
@@ -72,7 +81,6 @@ cc_library_shared {
         "com.android.os.statsd",
         "test_com.android.os.statsd",
     ],
-    min_sdk_version: "30",
 }
 
 cc_library_headers {
@@ -90,7 +98,6 @@ filegroup {
     srcs: ["libstatssocket_test_default.map"],
 }
 
-
 cc_library_headers {
     name: "libstatssocket_test_headers",
     export_include_dirs: ["tests/include"],
@@ -99,14 +106,13 @@ cc_library_headers {
 
 cc_test {
     name: "libstatssocket_test",
+    defaults: ["libstatssocket_defaults"],
     srcs: [
         "tests/stats_event_test.cpp",
         "tests/stats_writer_test.cpp",
         "tests/stats_buffer_writer_queue_test.cpp",
         "tests/stats_socketlog_test.cpp",
     ],
-    generated_sources: ["stats_statsdsocketlog.cpp"],
-    generated_headers: ["stats_statsdsocketlog.h"],
     cflags: [
         "-Wall",
         "-Werror",
@@ -128,7 +134,6 @@ cc_test {
     ],
     shared_libs: [
         "libutils",
-        "libstatssocket",
     ],
     header_libs: [
         "libstatssocket_test_headers",
@@ -150,8 +155,6 @@ cc_test {
         },
     },
     require_root: true,
-    min_sdk_version: "30",
-    test_for: ["com.android.os.statsd"],
 }
 
 genrule {
@@ -187,9 +190,6 @@ cc_fuzz {
     srcs: [
         "fuzzers/stats_event_fuzzer.cpp",
     ],
-    local_include_dirs: [
-        "include",
-    ],
     host_supported: true,
     cflags: [
         "-Wall",
diff --git a/lib/libstatssocket/libstatssocket.map.txt b/lib/libstatssocket/libstatssocket.map.txt
index f48e1595..e1edee51 100644
--- a/lib/libstatssocket/libstatssocket.map.txt
+++ b/lib/libstatssocket/libstatssocket.map.txt
@@ -23,3 +23,13 @@ LIBSTATSSOCKET {
     local:
         *;
 };
+
+LIBSTATSSOCKET_PRIVATE {
+    global:
+        AStatsEvent_getBuffer;
+        AStatsEvent_getErrors;
+        AStatsEvent_overwriteTimestamp;
+        write_buffer_to_statsd;
+    local:
+        *;
+} LIBSTATSSOCKET;
\ No newline at end of file
diff --git a/lib/libstatssocket/stats_buffer_writer_queue.cpp b/lib/libstatssocket/stats_buffer_writer_queue.cpp
index bf62dc08..f1d6ba7b 100644
--- a/lib/libstatssocket/stats_buffer_writer_queue.cpp
+++ b/lib/libstatssocket/stats_buffer_writer_queue.cpp
@@ -27,6 +27,10 @@
 #include "stats_buffer_writer_queue_impl.h"
 #include "utils.h"
 
+namespace {
+constexpr int32_t kBootTimeEventElapsedTimeAtomId = 240;
+}
+
 BufferWriterQueue::BufferWriterQueue() : mWorkThread(&BufferWriterQueue::processCommands, this) {
     pthread_setname_np(mWorkThread.native_handle(), "socket_writer_queue");
 }
@@ -152,11 +156,13 @@ bool write_buffer_to_statsd_queue(const uint8_t* buffer, size_t size, uint32_t a
     return queue.write(buffer, size, atomId);
 }
 
-#ifdef ENABLE_BENCHMARK_SUPPORT
 bool should_write_via_queue(uint32_t atomId) {
-#else
-bool should_write_via_queue(uint32_t /*atomId*/) {
-#endif
+    // bootstats is very short living process - queue does not have sufficient
+    // time to be drained entirely so writing this atom straight to socket
+    if (atomId == kBootTimeEventElapsedTimeAtomId) {
+        return false;
+    }
+
     const uint32_t appUid = getuid();
 
     // hard-coded push all system server atoms to queue
diff --git a/service/java/com/android/server/stats/StatsCompanionService.java b/service/java/com/android/server/stats/StatsCompanionService.java
index 6e920c52..cd7b5167 100644
--- a/service/java/com/android/server/stats/StatsCompanionService.java
+++ b/service/java/com/android/server/stats/StatsCompanionService.java
@@ -341,6 +341,9 @@ public class StatsCompanionService extends IStatsCompanionService.Stub {
              * waste, we ignore the REMOVE and ADD broadcasts that contain the replacing flag.
              * If we can't find the value for EXTRA_REPLACING, we default to false.
              */
+            if (intent.getAction() == null) {
+                return;
+            }
             if (!intent.getAction().equals(Intent.ACTION_PACKAGE_REPLACED)
                     && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
                 return; // Keep only replacing or normal add and remove.
@@ -473,6 +476,9 @@ public class StatsCompanionService extends IStatsCompanionService.Stub {
             /**
              * Skip immediately if intent is not relevant to device shutdown.
              */
+            if (intent.getAction() == null) {
+                return;
+            }
             if (!intent.getAction().equals(Intent.ACTION_REBOOT)
                     && !(intent.getAction().equals(Intent.ACTION_SHUTDOWN)
                     && (intent.getFlags() & Intent.FLAG_RECEIVER_FOREGROUND) != 0)) {
diff --git a/statsd/Android.bp b/statsd/Android.bp
index b6c8aeea..79451d3e 100644
--- a/statsd/Android.bp
+++ b/statsd/Android.bp
@@ -155,7 +155,7 @@ cc_defaults {
         "libbinder_ndk",
         "libincident",
         "liblog",
-        "libstatssocket",
+        "libstatssocket#impl",
     ],
     header_libs: [
         "libgtest_prod_headers",
@@ -258,12 +258,13 @@ cc_binary {
         "-Wextra",
         "-Werror",
         "-Wno-unused-parameter",
-        // optimize for size (protobuf glop can get big)
-        "-Os",
         // "-g",
         // "-O0",
     ],
 
+    // optimize for size (protobuf glop can get big)
+    optimize_for_size: true,
+
     proto: {
         type: "lite",
         static: true,
@@ -484,7 +485,6 @@ cc_test {
     ],
 
     min_sdk_version: "30",
-    test_for: ["com.android.os.statsd"],
 }
 
 //#############################
@@ -510,6 +510,7 @@ cc_benchmark {
         "benchmark/loss_info_container_benchmark.cpp",
         "benchmark/string_transform_benchmark.cpp",
         "benchmark/value_metric_benchmark.cpp",
+        "benchmark/tex_metric_benchmark.cpp",
     ],
 
     cflags: [
@@ -522,7 +523,6 @@ cc_benchmark {
         "libstats_test_utils",
     ],
 
-    test_for: ["com.android.os.statsd"],
 }
 
 // ====  java proto device library (for test only)  ==============================
@@ -625,7 +625,6 @@ cc_fuzz {
         "fuzzers/statsd_service_fuzzer.cpp",
     ],
     shared_libs: [
-        "libstatssocket",
         "libvndksupport",
     ],
     cflags: [
@@ -655,9 +654,6 @@ cc_fuzz {
     srcs: [
         "fuzzers/statsd_socket_data_fuzzer.cpp",
     ],
-    shared_libs: [
-        "libstatssocket",
-    ],
     cflags: [
         "-Wall",
         "-Wextra",
diff --git a/statsd/benchmark/tex_metric_benchmark.cpp b/statsd/benchmark/tex_metric_benchmark.cpp
new file mode 100644
index 00000000..101521a6
--- /dev/null
+++ b/statsd/benchmark/tex_metric_benchmark.cpp
@@ -0,0 +1,152 @@
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
+#include <memory>
+
+#include "benchmark/benchmark.h"
+#include "src/statsd_config.pb.h"
+#include "tests/statsd_test_util.h"
+
+using namespace std;
+
+namespace android {
+namespace os {
+namespace statsd {
+namespace {
+
+const ConfigKey cfgKey(0, 12345);
+const int numOfMetrics = 4;
+
+vector<shared_ptr<LogEvent>> createExpressEventReportedEvents() {
+    vector<shared_ptr<LogEvent>> events;
+    for (int i = 0; i < numOfMetrics; i++) {
+        events.push_back(CreateTwoValueLogEvent(/* atomId */ util::EXPRESS_EVENT_REPORTED,
+                                                /* eventTimeNs */ i,
+                                                /* metric_id */ i % numOfMetrics, /* value */ 1));
+    }
+    return events;
+}
+
+AtomMatcher CreateExpressEventReportedAtomMatcher(const string& name, int64_t metricIdHash) {
+    AtomMatcher atom_matcher = CreateSimpleAtomMatcher(name, util::EXPRESS_EVENT_REPORTED);
+    auto simple_atom_matcher = atom_matcher.mutable_simple_atom_matcher();
+    auto field_value_matcher = simple_atom_matcher->add_field_value_matcher();
+    field_value_matcher->set_field(1);  // metric id hash as int64
+    field_value_matcher->set_eq_int(metricIdHash);
+    return atom_matcher;
+}
+
+StatsdConfig createTexConfig() {
+    StatsdConfig config;
+    *config.add_atom_matcher() = CreateExpressEventReportedAtomMatcher("texMatcher1", 0);
+    *config.add_atom_matcher() = CreateExpressEventReportedAtomMatcher("texMatcher2", 1);
+    *config.add_atom_matcher() = CreateExpressEventReportedAtomMatcher("texMatcher3", 2);
+    *config.add_atom_matcher() = CreateExpressEventReportedAtomMatcher("texMatcher4", 3);
+
+    *config.add_value_metric() =
+            createValueMetric("texValue1", config.atom_matcher(0), /* valueField */ 2,
+                              /* condition */ nullopt, /* states */ {});
+    *config.add_value_metric() =
+            createValueMetric("texValue2", config.atom_matcher(1), /* valueField */ 2,
+                              /* condition */ nullopt, /* states */ {});
+    *config.add_value_metric() =
+            createValueMetric("texValue3", config.atom_matcher(2), /* valueField */ 2,
+                              /* condition */ nullopt, /* states */ {});
+    *config.add_value_metric() =
+            createValueMetric("texValue4", config.atom_matcher(3), /* valueField */ 2,
+                              /* condition */ nullopt, /* states */ {});
+    return config;
+}
+
+StatsdConfig createCountMetricConfig() {
+    StatsdConfig config;
+    *config.add_atom_matcher() =
+            CreateSimpleAtomMatcher("someCounterMatcher", /*atomId*/ util::EXPRESS_EVENT_REPORTED);
+
+    CountMetric* countMetric = config.add_count_metric();
+    *countMetric = createCountMetric("CountMetricAsCounter", /* what */ config.atom_matcher(0).id(),
+                                     /* condition */ nullopt, /* states */ {});
+    countMetric->mutable_dimensions_in_what()->set_field(util::EXPRESS_EVENT_REPORTED);
+    countMetric->mutable_dimensions_in_what()->add_child()->set_field(1);
+    return config;
+}
+
+StatsdConfig createValueMetricConfig() {
+    StatsdConfig config;
+    *config.add_atom_matcher() =
+            CreateSimpleAtomMatcher("someValueMatcher", /*atomId*/ util::EXPRESS_EVENT_REPORTED);
+
+    ValueMetric* valueMetric = config.add_value_metric();
+    *valueMetric = createValueMetric("ValueMetricAsCounter", /* what */ config.atom_matcher(0),
+                                     /* valueField */ 2,
+                                     /* condition */ nullopt,
+                                     /* states */ {});
+    valueMetric->mutable_dimensions_in_what()->set_field(util::EXPRESS_EVENT_REPORTED);
+    valueMetric->mutable_dimensions_in_what()->add_child()->set_field(1);
+    return config;
+}
+
+void testScenario(benchmark::State& state, sp<StatsLogProcessor>& processor) {
+    const int64_t elevenMinutesInNanos = NS_PER_SEC * 60 * 11;
+    vector<shared_ptr<LogEvent>> events = createExpressEventReportedEvents();
+    state.counters["MetricsSize"] = processor->GetMetricsSize(cfgKey);
+    int64_t eventIndex = 0;
+    for (auto _ : state) {
+        for (int i = 0; i < 1000; i++) {
+            auto event = events[eventIndex % numOfMetrics].get();
+            event->setElapsedTimestampNs(eventIndex * 10);
+            processor->OnLogEvent(event);
+            benchmark::DoNotOptimize(processor);
+            eventIndex++;
+        }
+    }
+    vector<uint8_t> buffer;
+    processor->onDumpReport(cfgKey, elevenMinutesInNanos, true, false, ADB_DUMP, FAST, &buffer);
+    state.counters["ReportBufferSize"] = buffer.size();
+    state.counters["MetricsSizeFinal"] = processor->GetMetricsSize(cfgKey);
+}
+
+void BM_TexCounter(benchmark::State& state) {
+    // idea is to have 1 standalone value metric with dimensions to mimic 4 tex metrics
+    // and compare performance - see BM_TexCounterAsValueMetric
+    StatsdConfig config = createTexConfig();
+    sp<StatsLogProcessor> processor = CreateStatsLogProcessor(1, 1, config, cfgKey);
+    testScenario(state, processor);
+}
+BENCHMARK(BM_TexCounter);
+
+void BM_TexCounterAsValueMetric(benchmark::State& state) {
+    // idea is to have 1 standalone value metric with dimensions to mimic 4 tex metrics
+    // and compare performance - see BM_TexCounter
+    StatsdConfig config = createValueMetricConfig();
+    sp<StatsLogProcessor> processor = CreateStatsLogProcessor(1, 1, config, cfgKey);
+    testScenario(state, processor);
+}
+BENCHMARK(BM_TexCounterAsValueMetric);
+
+void BM_TexCounterAsCountMetric(benchmark::State& state) {
+    // idea is to have 1 standalone count metric with dimensions to mimic 4 tex metrics
+    // and compare performance - see BM_TexCounter
+    StatsdConfig config = createCountMetricConfig();
+    sp<StatsLogProcessor> processor = CreateStatsLogProcessor(1, 1, config, cfgKey);
+    testScenario(state, processor);
+}
+BENCHMARK(BM_TexCounterAsCountMetric);
+
+}  // anonymous namespace
+}  // namespace statsd
+}  // namespace os
+}  // namespace android
diff --git a/statsd/src/StatsLogProcessor.cpp b/statsd/src/StatsLogProcessor.cpp
index a1f4e65b..88524f6c 100644
--- a/statsd/src/StatsLogProcessor.cpp
+++ b/statsd/src/StatsLogProcessor.cpp
@@ -91,6 +91,18 @@ constexpr const char* kPermissionUsage = "android.permission.PACKAGE_USAGE_STATS
 // Cool down period for writing data to disk to avoid overwriting files.
 #define WRITE_DATA_COOL_DOWN_SEC 15
 
+namespace {
+
+const char* getOnLogEventCallName(int32_t tagId) {
+    static std::string name;
+    // to avoid new string allocation on each call
+    name.reserve(30);
+    name = "OnLogEvent-" + std::to_string(tagId);
+    return name.c_str();
+}
+
+}  // namespace
+
 StatsLogProcessor::StatsLogProcessor(
         const sp<UidMap>& uidMap, const sp<StatsPullerManager>& pullerManager,
         const sp<AlarmMonitor>& anomalyAlarmMonitor, const sp<AlarmMonitor>& periodicAlarmMonitor,
@@ -390,7 +402,7 @@ void StatsLogProcessor::resetConfigsLocked(const int64_t timestampNs) {
 }
 
 void StatsLogProcessor::OnLogEvent(LogEvent* event) {
-    ATRACE_CALL();
+    ATRACE_NAME(getOnLogEventCallName(event->GetTagId()));
     OnLogEvent(event, getElapsedRealtimeNs());
 }
 
diff --git a/statsd/src/external/StatsPullerManager.h b/statsd/src/external/StatsPullerManager.h
index 9f5a41c8..4d09ffeb 100644
--- a/statsd/src/external/StatsPullerManager.h
+++ b/statsd/src/external/StatsPullerManager.h
@@ -179,6 +179,8 @@ private:
 
     FRIEND_TEST(ConfigUpdateE2eTest, TestGaugeMetric);
     FRIEND_TEST(ConfigUpdateE2eTest, TestValueMetric);
+
+    FRIEND_TEST(StatsPullerManagerTest, TestSameAtomIsPulledInABatch);
 };
 
 }  // namespace statsd
diff --git a/statsd/src/guardrail/StatsdStats.cpp b/statsd/src/guardrail/StatsdStats.cpp
index b8523797..c08d9311 100644
--- a/statsd/src/guardrail/StatsdStats.cpp
+++ b/statsd/src/guardrail/StatsdStats.cpp
@@ -231,8 +231,8 @@ StatsdStats::StatsdStats()
 }
 
 StatsdStats& StatsdStats::getInstance() {
-    static StatsdStats statsInstance;
-    return statsInstance;
+    static StatsdStats* statsInstance = new StatsdStats();
+    return *statsInstance;
 }
 
 void StatsdStats::addToIceBoxLocked(shared_ptr<ConfigStats>& stats) {
diff --git a/statsd/src/guardrail/stats_log_enums.proto b/statsd/src/guardrail/stats_log_enums.proto
index c320e170..0e243d51 100644
--- a/statsd/src/guardrail/stats_log_enums.proto
+++ b/statsd/src/guardrail/stats_log_enums.proto
@@ -164,6 +164,7 @@ enum InvalidConfigReasonEnum {
     INVALID_CONFIG_REASON_VALUE_METRIC_HIST_WITH_UPLOAD_THRESHOLD = 106;
     INVALID_CONFIG_REASON_VALUE_METRIC_HIST_INVALID_VALUE_DIRECTION = 107;
     INVALID_CONFIG_REASON_VALUE_METRIC_HIST_CLIENT_AGGREGATED_NO_POSITION_ALL = 108;
+    INVALID_CONFIG_REASON_UID_FIELDS_WITH_POSITION_ANY = 109;
 };
 
 enum InvalidQueryReason {
diff --git a/statsd/src/logd/LogEvent.cpp b/statsd/src/logd/LogEvent.cpp
index 30cc2ddb..d51499b0 100644
--- a/statsd/src/logd/LogEvent.cpp
+++ b/statsd/src/logd/LogEvent.cpp
@@ -770,7 +770,7 @@ string LogEvent::ToString() const {
 
 void LogEvent::ToProto(ProtoOutputStream& protoOutput) const {
     set<int32_t> usedUids;
-    writeFieldValueTreeToStream(mTagId, getValues(), usedUids, &protoOutput);
+    writeFieldValueTreeToStream(mTagId, getValues(), {}, usedUids, &protoOutput);
 }
 
 bool LogEvent::hasAttributionChain(std::pair<size_t, size_t>* indexRange) const {
diff --git a/statsd/src/metrics/CountMetricProducer.cpp b/statsd/src/metrics/CountMetricProducer.cpp
index 0cf5c05b..b5e5f92b 100644
--- a/statsd/src/metrics/CountMetricProducer.cpp
+++ b/statsd/src/metrics/CountMetricProducer.cpp
@@ -280,13 +280,13 @@ void CountMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
         if (mShouldUseNestedDimensions) {
             uint64_t dimensionToken = protoOutput->start(
                     FIELD_TYPE_MESSAGE | FIELD_ID_DIMENSION_IN_WHAT);
-            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, usedUids,
-                                  protoOutput);
+            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), mUidFields, str_set,
+                                  usedUids, protoOutput);
             protoOutput->end(dimensionToken);
         } else {
             writeDimensionLeafNodesToProto(dimensionKey.getDimensionKeyInWhat(),
-                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, usedUids,
-                                           protoOutput);
+                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, mUidFields, str_set,
+                                           usedUids, protoOutput);
         }
         // Then fill slice_by_state.
         for (auto state : dimensionKey.getStateValuesKey().getValues()) {
diff --git a/statsd/src/metrics/DurationMetricProducer.cpp b/statsd/src/metrics/DurationMetricProducer.cpp
index 1af07fbe..b795b25c 100644
--- a/statsd/src/metrics/DurationMetricProducer.cpp
+++ b/statsd/src/metrics/DurationMetricProducer.cpp
@@ -571,13 +571,13 @@ void DurationMetricProducer::onDumpReportLocked(
         if (mShouldUseNestedDimensions) {
             uint64_t dimensionToken = protoOutput->start(
                     FIELD_TYPE_MESSAGE | FIELD_ID_DIMENSION_IN_WHAT);
-            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, usedUids,
-                                  protoOutput);
+            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), mUidFields, str_set,
+                                  usedUids, protoOutput);
             protoOutput->end(dimensionToken);
         } else {
             writeDimensionLeafNodesToProto(dimensionKey.getDimensionKeyInWhat(),
-                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, usedUids,
-                                           protoOutput);
+                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, mUidFields, str_set,
+                                           usedUids, protoOutput);
         }
         // Then fill slice_by_state.
         for (auto state : dimensionKey.getStateValuesKey().getValues()) {
diff --git a/statsd/src/metrics/EventMetricProducer.cpp b/statsd/src/metrics/EventMetricProducer.cpp
index 55aa85a4..b3540f28 100644
--- a/statsd/src/metrics/EventMetricProducer.cpp
+++ b/statsd/src/metrics/EventMetricProducer.cpp
@@ -195,8 +195,8 @@ void EventMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
 
         uint64_t atomToken = protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_ATOM);
         writeFieldValueTreeToStream(atomDimensionKey.getAtomTag(),
-                                    atomDimensionKey.getAtomFieldValues().getValues(), usedUids,
-                                    protoOutput);
+                                    atomDimensionKey.getAtomFieldValues().getValues(), mUidFields,
+                                    usedUids, protoOutput);
         protoOutput->end(atomToken);
         for (int64_t timestampNs : elapsedTimestampsNs) {
             protoOutput->write(FIELD_TYPE_INT64 | FIELD_COUNT_REPEATED | FIELD_ID_ATOM_TIMESTAMPS,
diff --git a/statsd/src/metrics/GaugeMetricProducer.cpp b/statsd/src/metrics/GaugeMetricProducer.cpp
index bbfad86b..893f1a39 100644
--- a/statsd/src/metrics/GaugeMetricProducer.cpp
+++ b/statsd/src/metrics/GaugeMetricProducer.cpp
@@ -328,13 +328,13 @@ void GaugeMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
         if (mShouldUseNestedDimensions) {
             uint64_t dimensionToken = protoOutput->start(
                     FIELD_TYPE_MESSAGE | FIELD_ID_DIMENSION_IN_WHAT);
-            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), str_set, usedUids,
-                                  protoOutput);
+            writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), mUidFields, str_set,
+                                  usedUids, protoOutput);
             protoOutput->end(dimensionToken);
         } else {
             writeDimensionLeafNodesToProto(dimensionKey.getDimensionKeyInWhat(),
-                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, str_set, usedUids,
-                                           protoOutput);
+                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, mUidFields, str_set,
+                                           usedUids, protoOutput);
         }
 
         // Then fill bucket_info (GaugeBucketInfo).
@@ -361,7 +361,7 @@ void GaugeMetricProducer::onDumpReportLocked(const int64_t dumpTimeNs,
                             protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_ATOM_VALUE);
                     writeFieldValueTreeToStream(mAtomId,
                                                 atomDimensionKey.getAtomFieldValues().getValues(),
-                                                usedUids, protoOutput);
+                                                mUidFields, usedUids, protoOutput);
                     protoOutput->end(atomToken);
                     for (int64_t timestampNs : elapsedTimestampsNs) {
                         protoOutput->write(
diff --git a/statsd/src/metrics/MetricProducer.cpp b/statsd/src/metrics/MetricProducer.cpp
index d0e0fc95..a72c68de 100644
--- a/statsd/src/metrics/MetricProducer.cpp
+++ b/statsd/src/metrics/MetricProducer.cpp
@@ -464,6 +464,15 @@ size_t MetricProducer::computeOverheadSizeLocked(const bool hasPastBuckets,
             overheadSize += sizeof(int32_t) * mDimensionsInWhat.size();
         }
     }
+
+    const int32_t dataCorruptedReasonsCount =
+            (mDataCorruptedDueToQueueOverflow != DataCorruptionSeverity::kNone) +
+            (mDataCorruptedDueToSocketLoss != DataCorruptionSeverity::kNone);
+    if (dataCorruptedReasonsCount > 0) {
+        // adding extra int32 to account for the array length
+        overheadSize += (dataCorruptedReasonsCount + 1) * sizeof(int32_t);
+    }
+
     return overheadSize;
 }
 
diff --git a/statsd/src/metrics/MetricProducer.h b/statsd/src/metrics/MetricProducer.h
index 5f66319c..7059e615 100644
--- a/statsd/src/metrics/MetricProducer.h
+++ b/statsd/src/metrics/MetricProducer.h
@@ -390,6 +390,12 @@ public:
         mSampledWhatFields.swap(samplingInfo.sampledWhatFields);
         mShardCount = samplingInfo.shardCount;
     }
+
+    void setUidFields(std::vector<Matcher> uidFields) {
+        std::lock_guard<std::mutex> lock(mMutex);
+        mUidFields.swap(uidFields);
+    }
+
     // End: getters/setters
 protected:
     /**
@@ -602,6 +608,10 @@ protected:
 
     int mShardCount;
 
+    // For tracking uid fields in a metric. Only needed if the field is not annotated in the atom
+    // and omit_unused_uids_in_uidmap = true.
+    std::vector<Matcher> mUidFields;
+
     sp<ConfigMetadataProvider> getConfigMetadataProvider() const;
 
     wp<ConfigMetadataProvider> mConfigMetadataProvider;
@@ -669,6 +679,7 @@ protected:
 
     FRIEND_TEST(MetricsManagerUtilTest, TestInitialConditions);
     FRIEND_TEST(MetricsManagerUtilTest, TestSampledMetrics);
+    FRIEND_TEST(MetricsManagerUtilTest, TestUidFields);
 
     FRIEND_TEST(ConfigUpdateTest, TestUpdateMetricActivations);
     FRIEND_TEST(ConfigUpdateTest, TestUpdateCountMetrics);
diff --git a/statsd/src/metrics/MetricsManager.h b/statsd/src/metrics/MetricsManager.h
index 56a83ca4..a7b18ac7 100644
--- a/statsd/src/metrics/MetricsManager.h
+++ b/statsd/src/metrics/MetricsManager.h
@@ -444,6 +444,7 @@ private:
     FRIEND_TEST(MetricsManagerTest_SPlus, TestRestrictedMetricsConfig);
     FRIEND_TEST(MetricsManagerTest_SPlus, TestRestrictedMetricsConfigUpdate);
     FRIEND_TEST(MetricsManagerUtilTest, TestSampledMetrics);
+    FRIEND_TEST(MetricsManagerUtilTest, TestUidFields);
 
     FRIEND_TEST(StatsLogProcessorTest, TestActiveConfigMetricDiskWriteRead);
     FRIEND_TEST(StatsLogProcessorTest, TestActivationOnBoot);
diff --git a/statsd/src/metrics/ValueMetricProducer.cpp b/statsd/src/metrics/ValueMetricProducer.cpp
index 61b7341b..a053f82f 100644
--- a/statsd/src/metrics/ValueMetricProducer.cpp
+++ b/statsd/src/metrics/ValueMetricProducer.cpp
@@ -419,13 +419,13 @@ void ValueMetricProducer<AggregatedValue, DimExtras>::onDumpReportLocked(
         if (mShouldUseNestedDimensions) {
             uint64_t dimensionToken =
                     protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_ID_DIMENSION_IN_WHAT);
-            writeDimensionToProto(metricDimensionKey.getDimensionKeyInWhat(), strSet, usedUids,
-                                  protoOutput);
+            writeDimensionToProto(metricDimensionKey.getDimensionKeyInWhat(), mUidFields, strSet,
+                                  usedUids, protoOutput);
             protoOutput->end(dimensionToken);
         } else {
             writeDimensionLeafNodesToProto(metricDimensionKey.getDimensionKeyInWhat(),
-                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, strSet, usedUids,
-                                           protoOutput);
+                                           FIELD_ID_DIMENSION_LEAF_IN_WHAT, mUidFields, strSet,
+                                           usedUids, protoOutput);
         }
 
         // Then fill slice_by_state.
diff --git a/statsd/src/metrics/duration_helper/DurationTracker.h b/statsd/src/metrics/duration_helper/DurationTracker.h
index a6cbfffb..058dd37b 100644
--- a/statsd/src/metrics/duration_helper/DurationTracker.h
+++ b/statsd/src/metrics/duration_helper/DurationTracker.h
@@ -209,10 +209,6 @@ protected:
         }
     }
 
-    void setEventKey(const MetricDimensionKey& eventKey) {
-        mEventKey = eventKey;
-    }
-
     bool durationPassesThreshold(const optional<UploadThreshold>& uploadThreshold,
                                  int64_t duration) {
         if (duration <= 0) {
diff --git a/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp b/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
index 445b3e2d..57b72dfb 100644
--- a/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
+++ b/statsd/src/metrics/parsing_utils/metrics_manager_util.cpp
@@ -361,6 +361,22 @@ optional<InvalidConfigReason> handleMetricWithDimensionalSampling(
     return nullopt;
 }
 
+template <typename T>
+optional<InvalidConfigReason> setUidFieldsIfNecessary(const T& metric,
+                                                      sp<MetricProducer> metricProducer) {
+    if (metric.has_uid_fields()) {
+        if (HasPositionANY(metric.uid_fields())) {
+            ALOGE("Metric %lld has position ANY in uid fields", (long long)metric.id());
+            return InvalidConfigReason(INVALID_CONFIG_REASON_UID_FIELDS_WITH_POSITION_ANY,
+                                       metric.id());
+        }
+        std::vector<Matcher> uidFields;
+        translateFieldMatcher(metric.uid_fields(), &uidFields);
+        metricProducer->setUidFields(uidFields);
+    }
+    return nullopt;
+}
+
 // Validates a metricActivation and populates state.
 // EventActivationMap and EventDeactivationMap are supplied to a MetricProducer
 //      to provide the producer with state about its activators and deactivators.
@@ -616,6 +632,10 @@ optional<sp<MetricProducer>> createCountMetricProducerAndUpdateMetadata(
         metricProducer->setSamplingInfo(samplingInfo);
     }
 
+    invalidConfigReason = setUidFieldsIfNecessary(metric, metricProducer);
+    if (invalidConfigReason.has_value()) {
+        return nullopt;
+    }
     return metricProducer;
 }
 
@@ -802,6 +822,11 @@ optional<sp<MetricProducer>> createDurationMetricProducerAndUpdateMetadata(
         metricProducer->setSamplingInfo(samplingInfo);
     }
 
+    invalidConfigReason = setUidFieldsIfNecessary(metric, metricProducer);
+    if (invalidConfigReason.has_value()) {
+        return nullopt;
+    }
+
     return metricProducer;
 }
 
@@ -872,14 +897,23 @@ optional<sp<MetricProducer>> createEventMetricProducerAndUpdateMetadata(
         return nullopt;
     }
 
+    sp<MetricProducer> metricProducer;
     if (config.has_restricted_metrics_delegate_package_name()) {
-        return {new RestrictedEventMetricProducer(
+        metricProducer = new RestrictedEventMetricProducer(
+                key, metric, conditionIndex, initialConditionCache, wizard, metricHash, timeBaseNs,
+                configMetadataProvider, eventActivationMap, eventDeactivationMap);
+    } else {
+        metricProducer = new EventMetricProducer(
                 key, metric, conditionIndex, initialConditionCache, wizard, metricHash, timeBaseNs,
-                configMetadataProvider, eventActivationMap, eventDeactivationMap)};
+                configMetadataProvider, eventActivationMap, eventDeactivationMap);
     }
-    return {new EventMetricProducer(key, metric, conditionIndex, initialConditionCache, wizard,
-                                    metricHash, timeBaseNs, configMetadataProvider,
-                                    eventActivationMap, eventDeactivationMap)};
+
+    invalidConfigReason = setUidFieldsIfNecessary(metric, metricProducer);
+    if (invalidConfigReason.has_value()) {
+        return nullopt;
+    }
+
+    return metricProducer;
 }
 
 namespace {  // anonymous namespace
@@ -1145,6 +1179,11 @@ optional<sp<MetricProducer>> createNumericValueMetricProducerAndUpdateMetadata(
         metricProducer->setSamplingInfo(samplingInfo);
     }
 
+    invalidConfigReason = setUidFieldsIfNecessary(metric, metricProducer);
+    if (invalidConfigReason.has_value()) {
+        return nullopt;
+    }
+
     return metricProducer;
 }
 
@@ -1305,6 +1344,11 @@ optional<sp<MetricProducer>> createKllMetricProducerAndUpdateMetadata(
         metricProducer->setSamplingInfo(samplingInfo);
     }
 
+    invalidConfigReason = setUidFieldsIfNecessary(metric, metricProducer);
+    if (invalidConfigReason.has_value()) {
+        return nullopt;
+    }
+
     return metricProducer;
 }
 
@@ -1478,6 +1522,11 @@ optional<sp<MetricProducer>> createGaugeMetricProducerAndUpdateMetadata(
         metricProducer->setSamplingInfo(samplingInfo);
     }
 
+    invalidConfigReason = setUidFieldsIfNecessary(metric, metricProducer);
+    if (invalidConfigReason.has_value()) {
+        return nullopt;
+    }
+
     return metricProducer;
 }
 
diff --git a/statsd/src/stats_log_util.cpp b/statsd/src/stats_log_util.cpp
index 1e4b0244..83e60d5c 100644
--- a/statsd/src/stats_log_util.cpp
+++ b/statsd/src/stats_log_util.cpp
@@ -38,6 +38,7 @@ using android::util::ProtoOutputStream;
 using aidl::android::os::IStatsCompanionService;
 using std::shared_ptr;
 using std::string;
+using std::vector;
 
 namespace android {
 namespace os {
@@ -103,7 +104,20 @@ const int FIELD_ID_BUCKET_COUNT = 12;
 
 namespace {
 
-void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims, size_t* index, int depth,
+bool isUidField(const FieldValue& fieldValue, const vector<Matcher>& uidFields) {
+    if (isUidField(fieldValue)) {
+        return true;
+    }
+    for (const Matcher& uidField : uidFields) {
+        if (fieldValue.mField.matches(uidField)) {
+            return true;
+        }
+    }
+    return false;
+}
+
+void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims,
+                                 const vector<Matcher>& uidFields, size_t* index, int depth,
                                  int prefix, std::set<string>* str_set, std::set<int32_t>& usedUids,
                                  ProtoOutputStream* protoOutput) {
     size_t count = dims.size();
@@ -125,7 +139,7 @@ void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims, size_t* in
             protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_FIELD, fieldNum);
             switch (dim.mValue.getType()) {
                 case INT:
-                    if (isUidField(dim) || isAttributionUidField(dim)) {
+                    if (isUidField(dim, uidFields) || isAttributionUidField(dim)) {
                         usedUids.insert(dim.mValue.int_value);
                     }
                     protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_VALUE_INT,
@@ -163,8 +177,9 @@ void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims, size_t* in
             protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_FIELD, fieldNum);
             uint64_t tupleToken =
                     protoOutput->start(FIELD_TYPE_MESSAGE | DIMENSIONS_VALUE_VALUE_TUPLE);
-            writeDimensionToProtoHelper(dims, index, valueDepth, dim.mField.getPrefix(valueDepth),
-                                        str_set, usedUids, protoOutput);
+            writeDimensionToProtoHelper(dims, uidFields, index, valueDepth,
+                                        dim.mField.getPrefix(valueDepth), str_set, usedUids,
+                                        protoOutput);
             protoOutput->end(tupleToken);
             protoOutput->end(dimensionToken);
         } else {
@@ -175,9 +190,10 @@ void writeDimensionToProtoHelper(const std::vector<FieldValue>& dims, size_t* in
 }
 
 void writeDimensionLeafToProtoHelper(const std::vector<FieldValue>& dims,
-                                     const int dimensionLeafField, size_t* index, int depth,
-                                     int prefix, std::set<string>* str_set,
-                                     std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput) {
+                                     const int dimensionLeafField, const vector<Matcher>& uidFields,
+                                     size_t* index, int depth, int prefix,
+                                     std::set<string>* str_set, std::set<int32_t>& usedUids,
+                                     ProtoOutputStream* protoOutput) {
     size_t count = dims.size();
     while (*index < count) {
         const auto& dim = dims[*index];
@@ -194,7 +210,7 @@ void writeDimensionLeafToProtoHelper(const std::vector<FieldValue>& dims,
                                                 dimensionLeafField);
             switch (dim.mValue.getType()) {
                 case INT:
-                    if (isUidField(dim) || isAttributionUidField(dim)) {
+                    if (isUidField(dim, uidFields) || isAttributionUidField(dim)) {
                         usedUids.insert(dim.mValue.int_value);
                     }
                     protoOutput->write(FIELD_TYPE_INT32 | DIMENSIONS_VALUE_VALUE_INT,
@@ -226,7 +242,7 @@ void writeDimensionLeafToProtoHelper(const std::vector<FieldValue>& dims,
             }
             (*index)++;
         } else if (valueDepth == depth + 2 && valuePrefix == prefix) {
-            writeDimensionLeafToProtoHelper(dims, dimensionLeafField, index, valueDepth,
+            writeDimensionLeafToProtoHelper(dims, dimensionLeafField, uidFields, index, valueDepth,
                                             dim.mField.getPrefix(valueDepth), str_set, usedUids,
                                             protoOutput);
         } else {
@@ -278,8 +294,9 @@ void writeDimensionPathToProtoHelper(const std::vector<Matcher>& fieldMatchers,
 
 }  // namespace
 
-void writeDimensionToProto(const HashableDimensionKey& dimension, std::set<string>* str_set,
-                           std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput) {
+void writeDimensionToProto(const HashableDimensionKey& dimension, const vector<Matcher>& uidFields,
+                           std::set<string>* str_set, std::set<int32_t>& usedUids,
+                           ProtoOutputStream* protoOutput) {
     if (dimension.getValues().size() == 0) {
         return;
     }
@@ -287,20 +304,21 @@ void writeDimensionToProto(const HashableDimensionKey& dimension, std::set<strin
                        dimension.getValues()[0].mField.getTag());
     uint64_t topToken = protoOutput->start(FIELD_TYPE_MESSAGE | DIMENSIONS_VALUE_VALUE_TUPLE);
     size_t index = 0;
-    writeDimensionToProtoHelper(dimension.getValues(), &index, 0, 0, str_set, usedUids,
+    writeDimensionToProtoHelper(dimension.getValues(), uidFields, &index, 0, 0, str_set, usedUids,
                                 protoOutput);
     protoOutput->end(topToken);
 }
 
 void writeDimensionLeafNodesToProto(const HashableDimensionKey& dimension,
-                                    const int dimensionLeafFieldId, std::set<string>* str_set,
+                                    const int dimensionLeafFieldId,
+                                    const vector<Matcher>& uidFields, std::set<string>* str_set,
                                     std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput) {
     if (dimension.getValues().size() == 0) {
         return;
     }
     size_t index = 0;
-    writeDimensionLeafToProtoHelper(dimension.getValues(), dimensionLeafFieldId, &index, 0, 0,
-                                    str_set, usedUids, protoOutput);
+    writeDimensionLeafToProtoHelper(dimension.getValues(), dimensionLeafFieldId, uidFields, &index,
+                                    0, 0, str_set, usedUids, protoOutput);
 }
 
 void writeDimensionPathToProto(const std::vector<Matcher>& fieldMatchers,
@@ -343,8 +361,8 @@ void writeDimensionPathToProto(const std::vector<Matcher>& fieldMatchers,
 //
 //
 void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>& dims,
-                                       size_t* index, int depth, int prefix,
-                                       std::set<int32_t>& usedUids,
+                                       const vector<Matcher>& uidFields, size_t* index, int depth,
+                                       int prefix, std::set<int32_t>& usedUids,
                                        ProtoOutputStream* protoOutput) {
     size_t count = dims.size();
     while (*index < count) {
@@ -363,7 +381,7 @@ void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>&
         if ((depth == valueDepth || valueDepth == 1) && valuePrefix == prefix) {
             switch (dim.mValue.getType()) {
                 case INT:
-                    if (isUidField(dim) || isAttributionUidField(dim)) {
+                    if (isUidField(dim, uidFields) || isAttributionUidField(dim)) {
                         usedUids.insert(dim.mValue.int_value);
                     }
                     protoOutput->write(FIELD_TYPE_INT32 | repeatedFieldMask | fieldNum,
@@ -397,7 +415,7 @@ void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>&
             msg_token = protoOutput->start(FIELD_TYPE_MESSAGE | FIELD_COUNT_REPEATED | fieldNum);
             // Directly jump to the leaf value because the repeated position field is implied
             // by the position of the sub msg in the parent field.
-            writeFieldValueTreeToStreamHelper(tagId, dims, index, valueDepth,
+            writeFieldValueTreeToStreamHelper(tagId, dims, uidFields, index, valueDepth,
                                               dim.mField.getPrefix(valueDepth), usedUids,
                                               protoOutput);
             if (msg_token != 0) {
@@ -411,12 +429,13 @@ void writeFieldValueTreeToStreamHelper(int tagId, const std::vector<FieldValue>&
 }
 
 void writeFieldValueTreeToStream(int tagId, const std::vector<FieldValue>& values,
-                                 std::set<int32_t>& usedUids,
+                                 const vector<Matcher>& uidFields, std::set<int32_t>& usedUids,
                                  util::ProtoOutputStream* protoOutput) {
     uint64_t atomToken = protoOutput->start(FIELD_TYPE_MESSAGE | tagId);
 
     size_t index = 0;
-    writeFieldValueTreeToStreamHelper(tagId, values, &index, 0, 0, usedUids, protoOutput);
+    writeFieldValueTreeToStreamHelper(tagId, values, uidFields, &index, 0, 0, usedUids,
+                                      protoOutput);
     protoOutput->end(atomToken);
 }
 
diff --git a/statsd/src/stats_log_util.h b/statsd/src/stats_log_util.h
index 7bd99c5f..d7a3987a 100644
--- a/statsd/src/stats_log_util.h
+++ b/statsd/src/stats_log_util.h
@@ -32,14 +32,18 @@ namespace os {
 namespace statsd {
 
 void writeFieldValueTreeToStream(int tagId, const std::vector<FieldValue>& values,
-                                 std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput);
+                                 const std::vector<Matcher>& uidFields, std::set<int32_t>& usedUids,
+                                 ProtoOutputStream* protoOutput);
 
-void writeDimensionToProto(const HashableDimensionKey& dimension, std::set<string>* str_set,
+void writeDimensionToProto(const HashableDimensionKey& dimension,
+                           const std::vector<Matcher>& uidFields, std::set<string>* str_set,
                            std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput);
 
 void writeDimensionLeafNodesToProto(const HashableDimensionKey& dimension,
-                                    const int dimensionLeafFieldId, std::set<string>* str_set,
-                                    std::set<int32_t>& usedUids, ProtoOutputStream* protoOutput);
+                                    const int dimensionLeafFieldId,
+                                    const std::vector<Matcher>& uidFields,
+                                    std::set<string>* str_set, std::set<int32_t>& usedUids,
+                                    ProtoOutputStream* protoOutput);
 
 void writeDimensionPathToProto(const std::vector<Matcher>& fieldMatchers,
                                ProtoOutputStream* protoOutput);
diff --git a/statsd/src/statsd_config.proto b/statsd/src/statsd_config.proto
index 13ed9c56..f110dd87 100644
--- a/statsd/src/statsd_config.proto
+++ b/statsd/src/statsd_config.proto
@@ -244,6 +244,8 @@ message EventMetric {
 
   optional int32 sampling_percentage = 5 [default = 100];
 
+  optional FieldMatcher uid_fields = 6;
+
   reserved 100;
   reserved 101;
 }
@@ -275,6 +277,8 @@ message CountMetric {
 
   optional int32 max_dimensions_per_bucket = 13;
 
+  optional FieldMatcher uid_fields = 14;
+
   reserved 100;
   reserved 101;
 }
@@ -313,6 +317,8 @@ message DurationMetric {
 
   optional int32 max_dimensions_per_bucket = 14;
 
+  optional FieldMatcher uid_fields = 15;
+
   reserved 100;
   reserved 101;
 }
@@ -360,6 +366,8 @@ message GaugeMetric {
 
   optional int32 pull_probability = 18 [default = 100];
 
+  optional FieldMatcher uid_fields = 19;
+
   reserved 100;
   reserved 101;
 }
@@ -464,6 +472,8 @@ message ValueMetric {
 
   optional int32 max_dimensions_per_bucket = 24;
 
+  optional FieldMatcher uid_fields = 27;
+
   reserved 100;
   reserved 101;
 }
@@ -495,6 +505,8 @@ message KllMetric {
 
   optional int32 max_dimensions_per_bucket = 13;
 
+  optional FieldMatcher uid_fields = 14;
+
   reserved 100;
   reserved 101;
 }
diff --git a/statsd/src/subscriber/IncidentdReporter.cpp b/statsd/src/subscriber/IncidentdReporter.cpp
index ec85ec4f..76a2033c 100644
--- a/statsd/src/subscriber/IncidentdReporter.cpp
+++ b/statsd/src/subscriber/IncidentdReporter.cpp
@@ -78,7 +78,8 @@ void getProtoData(const int64_t& rule_id, int64_t metricId, const MetricDimensio
     uint64_t dimToken =
             headerProto.start(FIELD_TYPE_MESSAGE | FIELD_ID_METRIC_VALUE_DIMENSION_IN_WHAT);
     set<int32_t> usedUids;
-    writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), nullptr, usedUids, &headerProto);
+    writeDimensionToProto(dimensionKey.getDimensionKeyInWhat(), {}, nullptr, usedUids,
+                          &headerProto);
     headerProto.end(dimToken);
 
     // deprecated field
diff --git a/statsd/src/utils/DbUtils.cpp b/statsd/src/utils/DbUtils.cpp
index 35ad1501..bc605672 100644
--- a/statsd/src/utils/DbUtils.cpp
+++ b/statsd/src/utils/DbUtils.cpp
@@ -410,39 +410,39 @@ static bool getDeviceInfoInsertStmt(sqlite3* db, sqlite3_stmt** stmt, string err
     sqlite3_bind_int(*stmt, index, sdkVersion);
     ++index;
 
-    string model = GetProperty("ro.product.model", "(unknown)");
+    string model = GetProperty("ro.product.model", "unknown");
     sqlite3_bind_text(*stmt, index, model.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
-    string product = GetProperty("ro.product.name", "(unknown)");
+    string product = GetProperty("ro.product.name", "unknown");
     sqlite3_bind_text(*stmt, index, product.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
-    string hardware = GetProperty("ro.hardware", "(unknown)");
+    string hardware = GetProperty("ro.hardware", "unknown");
     sqlite3_bind_text(*stmt, index, hardware.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
-    string device = GetProperty("ro.product.device", "(unknown)");
+    string device = GetProperty("ro.product.device", "unknown");
     sqlite3_bind_text(*stmt, index, device.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
-    string osBuild = GetProperty("ro.build.id", "(unknown)");
+    string osBuild = GetProperty("ro.build.id", "unknown");
     sqlite3_bind_text(*stmt, index, osBuild.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
-    string fingerprint = GetProperty("ro.build.fingerprint", "(unknown)");
+    string fingerprint = GetProperty("ro.build.fingerprint", "unknown");
     sqlite3_bind_text(*stmt, index, fingerprint.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
-    string brand = GetProperty("ro.product.brand", "(unknown)");
+    string brand = GetProperty("ro.product.brand", "unknown");
     sqlite3_bind_text(*stmt, index, brand.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
-    string manufacturer = GetProperty("ro.product.manufacturer", "(unknown)");
+    string manufacturer = GetProperty("ro.product.manufacturer", "unknown");
     sqlite3_bind_text(*stmt, index, manufacturer.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
-    string board = GetProperty("ro.product.board", "(unknown)");
+    string board = GetProperty("ro.product.board", "unknown");
     sqlite3_bind_text(*stmt, index, board.c_str(), -1, SQLITE_TRANSIENT);
     ++index;
 
diff --git a/statsd/tests/FieldValue_test.cpp b/statsd/tests/FieldValue_test.cpp
index 32940544..539469c8 100644
--- a/statsd/tests/FieldValue_test.cpp
+++ b/statsd/tests/FieldValue_test.cpp
@@ -754,7 +754,8 @@ TEST(AtomMatcherTest, TestWriteDimensionToProto) {
 
     android::util::ProtoOutputStream protoOut;
     set<int32_t> usedUids;
-    writeDimensionToProto(dim, nullptr /* include strings */, usedUids, &protoOut);
+    writeDimensionToProto(dim, /*uidfields*/ {}, nullptr /* include strings */, usedUids,
+                          &protoOut);
 
     vector<uint8_t> outData;
     outData.resize(protoOut.size());
@@ -817,7 +818,8 @@ TEST(AtomMatcherTest, TestWriteDimensionLeafNodesToProto) {
 
     android::util::ProtoOutputStream protoOut;
     set<int32_t> usedUids;
-    writeDimensionLeafNodesToProto(dim, 1, nullptr /* include strings */, usedUids, &protoOut);
+    writeDimensionLeafNodesToProto(dim, 1, /*uidfields*/ {}, nullptr /* include strings */,
+                                   usedUids, &protoOut);
 
     vector<uint8_t> outData;
     outData.resize(protoOut.size());
@@ -860,7 +862,8 @@ TEST(AtomMatcherTest, TestWriteAtomToProto) {
 
     android::util::ProtoOutputStream protoOutput;
     set<int32_t> usedUids;
-    writeFieldValueTreeToStream(event.GetTagId(), event.getValues(), usedUids, &protoOutput);
+    writeFieldValueTreeToStream(event.GetTagId(), event.getValues(), /*uidfields*/ {}, usedUids,
+                                &protoOutput);
 
     vector<uint8_t> outData;
     outData.resize(protoOutput.size());
@@ -903,7 +906,8 @@ TEST_GUARDED(AtomMatcherTest, TestWriteAtomWithRepeatedFieldsToProto, __ANDROID_
 
     android::util::ProtoOutputStream protoOutput;
     set<int32_t> usedUids;
-    writeFieldValueTreeToStream(event->GetTagId(), event->getValues(), usedUids, &protoOutput);
+    writeFieldValueTreeToStream(event->GetTagId(), event->getValues(), /*uidfields*/ {}, usedUids,
+                                &protoOutput);
 
     vector<uint8_t> outData;
     outData.resize(protoOutput.size());
diff --git a/statsd/tests/UidMap_test.cpp b/statsd/tests/UidMap_test.cpp
index 55405c25..7a0b4995 100644
--- a/statsd/tests/UidMap_test.cpp
+++ b/statsd/tests/UidMap_test.cpp
@@ -36,6 +36,7 @@ namespace android {
 namespace os {
 namespace statsd {
 
+using aidl::android::util::StatsEventParcel;
 using android::util::ProtoOutputStream;
 using android::util::ProtoReader;
 using ::ndk::SharedRefBase;
@@ -703,7 +704,7 @@ TEST_P(UidMapTestTruncateCertificateHash, TestCertificateHashesTruncated) {
                 UnorderedPointwise(EqPackageInfo(), expectedPackageInfos));
 }
 
-class UidMapTestAppendUidMapSystemUids : public UidMapTestAppendUidMapBase {
+class UidMapTestAppendUidMapSystemUsedUids : public UidMapTestAppendUidMapBase {
 protected:
     static const uint64_t bucketStartTimeNs = 10000000000;  // 0:10
     uint64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(TEN_MINUTES) * 1000000LL;
@@ -734,7 +735,7 @@ protected:
                           /* installer */ "", /* certificateHash */ {});
 
         *config.add_atom_matcher() =
-                CreateSimpleAtomMatcher("TestAtomMatcher", util::TEST_ATOM_REPORTED);
+                CreateSimpleAtomMatcher("TestAtomMatcher", util::SYNC_STATE_CHANGED);
         *config.add_event_metric() =
                 createEventMetric("TestAtomReported", config.atom_matcher(0).id(), nullopt);
     }
@@ -754,28 +755,30 @@ protected:
     }
 };
 
-TEST_F(UidMapTestAppendUidMapSystemUids, testHasSystemUids) {
+TEST_F(UidMapTestAppendUidMapSystemUsedUids, testHasSystemAndUnusedUids) {
     sp<StatsLogProcessor> processor = createStatsLogProcessor(config);
     UidMapping results = getUidMapping(processor);
 
     ASSERT_EQ(results.snapshots_size(), 1);
-    EXPECT_THAT(results.snapshots(0).package_info(),
-                IsSupersetOf({
-                        Property(&PackageInfo::uid, AID_LMKD),
-                        Property(&PackageInfo::uid, AID_USER_OFFSET + AID_UWB),
-                        Property(&PackageInfo::uid, AID_ROOT),
-                        Property(&PackageInfo::uid, AID_APP_START - 1),
-                }));
-
-    EXPECT_THAT(results.changes(), IsSupersetOf({
-                                           Property(&Change::uid, AID_LMKD),
-                                           Property(&Change::uid, AID_USER_OFFSET + AID_UWB),
-                                           Property(&Change::uid, AID_ROOT),
-                                           Property(&Change::uid, AID_APP_START - 1),
-                                   }));
+    EXPECT_THAT(
+            results.snapshots(0).package_info(),
+            UnorderedElementsAre(Property(&PackageInfo::uid, AID_LMKD),
+                                 Property(&PackageInfo::uid, AID_USER_OFFSET + AID_UWB),
+                                 Property(&PackageInfo::uid, AID_ROOT),
+                                 Property(&PackageInfo::uid, AID_APP_START - 1),
+                                 Property(&PackageInfo::uid, AID_APP_START),
+                                 Property(&PackageInfo::uid, AID_APP_START + 1),
+                                 Property(&PackageInfo::uid, AID_USER_OFFSET + AID_APP_START + 2)));
+
+    EXPECT_THAT(results.changes(),
+                UnorderedElementsAre(Property(&Change::uid, AID_LMKD),
+                                     Property(&Change::uid, AID_USER_OFFSET + AID_UWB),
+                                     Property(&Change::uid, AID_ROOT),
+                                     Property(&Change::uid, AID_APP_START - 1),
+                                     Property(&Change::uid, AID_APP_START)));
 }
 
-TEST_F(UidMapTestAppendUidMapSystemUids, testHasNoSystemUids) {
+TEST_F(UidMapTestAppendUidMapSystemUsedUids, testHasNoSystemUids) {
     config.mutable_statsd_config_options()->set_omit_system_uids_in_uidmap(true);
     sp<StatsLogProcessor> processor = createStatsLogProcessor(config);
     UidMapping results = getUidMapping(processor);
@@ -789,6 +792,400 @@ TEST_F(UidMapTestAppendUidMapSystemUids, testHasNoSystemUids) {
     EXPECT_THAT(results.changes(), ElementsAre(Property(&Change::uid, AID_APP_START)));
 }
 
+TEST_F(UidMapTestAppendUidMapSystemUsedUids, testOmitSystemAndUnusedUidsEmpty) {
+    config.mutable_statsd_config_options()->set_omit_system_uids_in_uidmap(true);
+    config.mutable_statsd_config_options()->set_omit_unused_uids_in_uidmap(true);
+
+    sp<StatsLogProcessor> processor = createStatsLogProcessor(config);
+    UidMapping results = getUidMapping(processor);
+
+    ASSERT_EQ(results.snapshots_size(), 1);
+    ASSERT_EQ(results.snapshots(0).package_info_size(), 0);
+    ASSERT_EQ(results.changes_size(), 0);
+}
+
+TEST_F(UidMapTestAppendUidMapSystemUsedUids, testOmitSystemAndUnusedUids) {
+    config.mutable_statsd_config_options()->set_omit_system_uids_in_uidmap(true);
+    config.mutable_statsd_config_options()->set_omit_unused_uids_in_uidmap(true);
+
+    sp<StatsLogProcessor> processor = createStatsLogProcessor(config);
+
+    auto event = CreateSyncStartEvent(bucketStartTimeNs + 1, {AID_LMKD, AID_APP_START + 1},
+                                      {"tag", "tag"}, "sync_name");
+    processor->OnLogEvent(event.get());
+
+    UidMapping results = getUidMapping(processor);
+
+    ASSERT_EQ(results.snapshots_size(), 1);
+    EXPECT_THAT(results.snapshots(0).package_info(),
+                UnorderedElementsAre(Property(&PackageInfo::uid, AID_APP_START + 1)));
+    ASSERT_EQ(results.changes_size(), 0);
+}
+
+TEST_F(UidMapTestAppendUidMapSystemUsedUids, testOmitSystemAndUnusedUidsEmptyWithAllowlist) {
+    config.mutable_statsd_config_options()->set_omit_system_uids_in_uidmap(true);
+    config.mutable_statsd_config_options()->set_omit_unused_uids_in_uidmap(true);
+    config.mutable_statsd_config_options()->add_uidmap_package_allowlist("LMKD");
+    config.mutable_statsd_config_options()->add_uidmap_package_allowlist("app4");
+
+    sp<StatsLogProcessor> processor = createStatsLogProcessor(config);
+    UidMapping results = getUidMapping(processor);
+
+    ASSERT_EQ(results.snapshots_size(), 1);
+    EXPECT_THAT(results.snapshots(0).package_info(),
+                UnorderedElementsAre(Property(&PackageInfo::uid, AID_LMKD),
+                                     Property(&PackageInfo::uid, AID_APP_START)));
+    EXPECT_THAT(results.changes(), UnorderedElementsAre(Property(&Change::uid, AID_LMKD),
+                                                        Property(&Change::uid, AID_APP_START)));
+}
+
+TEST_F(UidMapTestAppendUidMapSystemUsedUids, testOmitSystemAndUnusedUidsWithAllowlist) {
+    config.mutable_statsd_config_options()->set_omit_system_uids_in_uidmap(true);
+    config.mutable_statsd_config_options()->set_omit_unused_uids_in_uidmap(true);
+    config.mutable_statsd_config_options()->add_uidmap_package_allowlist("LMKD");
+    config.mutable_statsd_config_options()->add_uidmap_package_allowlist("app1");
+
+    sp<StatsLogProcessor> processor = createStatsLogProcessor(config);
+    auto event = CreateSyncStartEvent(bucketStartTimeNs + 1, {AID_ROOT, AID_LMKD, AID_APP_START},
+                                      {"tag", "tag", "tag"}, "sync_name");
+    processor->OnLogEvent(event.get());
+    UidMapping results = getUidMapping(processor);
+
+    ASSERT_EQ(results.snapshots_size(), 1);
+    EXPECT_THAT(results.snapshots(0).package_info(),
+                UnorderedElementsAre(Property(&PackageInfo::uid, AID_LMKD),
+                                     Property(&PackageInfo::uid, AID_APP_START),
+                                     Property(&PackageInfo::uid, AID_APP_START + 1)));
+    EXPECT_THAT(results.changes(), UnorderedElementsAre(Property(&Change::uid, AID_LMKD),
+                                                        Property(&Change::uid, AID_APP_START)));
+}
+
+TEST(UidMapTest, TestUsedUidsE2e) {
+    const int ATOM_1 = 1, ATOM_2 = 2, ATOM_3 = 3, ATOM_4 = 4, ATOM_5 = 10001, ATOM_6 = 6;
+    StatsdConfig config;
+    config.mutable_statsd_config_options()->set_omit_unused_uids_in_uidmap(true);
+    config.add_default_pull_packages("AID_ROOT");  // Fake puller is registered with root.
+    AtomMatcher eventMatcher = CreateSimpleAtomMatcher("M1", ATOM_1);
+    *config.add_atom_matcher() = eventMatcher;
+    AtomMatcher countMatcher = CreateSimpleAtomMatcher("M2", ATOM_2);
+    *config.add_atom_matcher() = countMatcher;
+    AtomMatcher durationStartMatcher = CreateSimpleAtomMatcher("M3_START", ATOM_3);
+    auto fvmStart = durationStartMatcher.mutable_simple_atom_matcher()->add_field_value_matcher();
+    fvmStart->set_field(2);  // State field.
+    fvmStart->set_eq_int(0);
+    *config.add_atom_matcher() = durationStartMatcher;
+    AtomMatcher durationStopMatcher = CreateSimpleAtomMatcher("M3_STOP", ATOM_3);
+    auto fvmStop = durationStopMatcher.mutable_simple_atom_matcher()->add_field_value_matcher();
+    fvmStop->set_field(2);
+    fvmStop->set_eq_int(1);
+    *config.add_atom_matcher() = durationStopMatcher;
+    AtomMatcher gaugeMatcher = CreateSimpleAtomMatcher("M4", ATOM_4);
+    *config.add_atom_matcher() = gaugeMatcher;
+    AtomMatcher valueMatcher = CreateSimpleAtomMatcher("M5", ATOM_5);
+    *config.add_atom_matcher() = valueMatcher;
+    AtomMatcher kllMatcher = CreateSimpleAtomMatcher("M6", ATOM_6);
+    *config.add_atom_matcher() = kllMatcher;
+
+    Predicate predicate;
+    predicate.set_id(StringToId("P1"));
+    predicate.mutable_simple_predicate()->set_start(StringToId("M3_START"));
+    predicate.mutable_simple_predicate()->set_stop(StringToId("M3_STOP"));
+    FieldMatcher durDims = CreateDimensions(ATOM_3, {1});
+    *predicate.mutable_simple_predicate()->mutable_dimensions() = durDims;
+    *config.add_predicate() = predicate;
+
+    *config.add_event_metric() = createEventMetric("EVENT", eventMatcher.id(), nullopt);
+    CountMetric countMetric = createCountMetric("COUNT", countMatcher.id(), nullopt, {});
+    *countMetric.mutable_dimensions_in_what() =
+            CreateAttributionUidDimensions(ATOM_2, {Position::FIRST});
+    *config.add_count_metric() = countMetric;
+    DurationMetric durationMetric = createDurationMetric("DUR", predicate.id(), nullopt, {});
+    *durationMetric.mutable_dimensions_in_what() = durDims;
+    *config.add_duration_metric() = durationMetric;
+    GaugeMetric gaugeMetric = createGaugeMetric("GAUGE", gaugeMatcher.id(),
+                                                GaugeMetric::FIRST_N_SAMPLES, nullopt, nullopt);
+    *gaugeMetric.mutable_dimensions_in_what() = CreateDimensions(ATOM_4, {1});
+    *config.add_gauge_metric() = gaugeMetric;
+    ValueMetric valueMetric = createValueMetric("VALUE", valueMatcher, 2, nullopt, {});
+    valueMetric.set_skip_zero_diff_output(false);
+    *valueMetric.mutable_dimensions_in_what() =
+            CreateAttributionUidDimensions(ATOM_5, {Position::FIRST});
+    *config.add_value_metric() = valueMetric;
+    KllMetric kllMetric = createKllMetric("KLL", kllMatcher, 2, nullopt);
+    *kllMetric.mutable_dimensions_in_what() = CreateDimensions(ATOM_6, {1});
+    *config.add_kll_metric() = kllMetric;
+
+    int64_t startTimeNs = getElapsedRealtimeNs();
+    sp<UidMap> uidMap = new UidMap();
+    const int UID_1 = 11, UID_2 = 12, UID_3 = 13, UID_4 = 14, UID_5 = 15, UID_6 = 16, UID_7 = 17,
+              UID_8 = 18, UID_9 = 19;
+    int extraUids = 10;  // Extra uids in the uid map that aren't referenced in the metric report.
+    int extraUidStart = 1000;
+    vector<int> uids = {UID_1, UID_2, UID_3, UID_4, UID_5, UID_6, UID_7, UID_8, UID_9};
+    int numUids = extraUids + uids.size();
+    for (int i = 0; i < extraUids; i++) {
+        uids.push_back(extraUidStart + i);
+    }
+    // We only care about the uids for this test. Give defaults to everything else.
+    vector<int64_t> versions(numUids, 0);
+    vector<string> versionStrings(numUids, "");
+    vector<string> apps(numUids, "");
+    vector<string> installers(numUids, "");
+    vector<uint8_t> hash;
+    vector<vector<uint8_t>> certHashes(numUids, hash);
+    uidMap->updateMap(startTimeNs,
+                      createUidData(uids, versions, versionStrings, apps, installers, certHashes));
+
+    class FakePullAtomCallback : public BnPullAtomCallback {
+    public:
+        int pullNum = 1;
+        Status onPullAtom(int atomTag,
+                          const shared_ptr<IPullAtomResultReceiver>& resultReceiver) override {
+            std::vector<StatsEventParcel> parcels;
+            AStatsEvent* event = makeAttributionStatsEvent(atomTag, 0, {UID_8}, {""}, pullNum, 0);
+            AStatsEvent_build(event);
+
+            size_t size;
+            uint8_t* buffer = AStatsEvent_getBuffer(event, &size);
+
+            StatsEventParcel p;
+            p.buffer.assign(buffer, buffer + size);
+            parcels.push_back(std::move(p));
+            AStatsEvent_release(event);
+            pullNum++;
+            resultReceiver->pullFinished(atomTag, /*success=*/true, parcels);
+            return Status::ok();
+        }
+    };
+
+    ConfigKey key(123, 987);
+    sp<StatsLogProcessor> p =
+            CreateStatsLogProcessor(startTimeNs, startTimeNs, config, key,
+                                    SharedRefBase::make<FakePullAtomCallback>(), ATOM_5, uidMap);
+
+    const uint64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(TEN_MINUTES) * 1000000LL;
+    std::vector<std::shared_ptr<LogEvent>> events;
+    events.push_back(makeUidLogEvent(ATOM_1, startTimeNs + 10, UID_1, 0, 0));
+    events.push_back(makeUidLogEvent(ATOM_1, startTimeNs + 11, UID_2, 0, 0));
+    events.push_back(makeAttributionLogEvent(ATOM_2, startTimeNs + 12, {UID_3}, {""}, 0, 0));
+    events.push_back(makeUidLogEvent(ATOM_3, startTimeNs + 15, UID_5, 0, 0));  // start
+    events.push_back(makeUidLogEvent(ATOM_3, startTimeNs + 18, UID_5, 1, 0));  // stop
+    events.push_back(makeExtraUidsLogEvent(ATOM_4, startTimeNs + 20, UID_6, 0, 0, {UID_7}));
+    events.push_back(makeUidLogEvent(ATOM_6, startTimeNs + 22, UID_9, 0, 0));
+
+    events.push_back(
+            makeAttributionLogEvent(ATOM_2, startTimeNs + bucketSizeNs + 10, {UID_4}, {""}, 0, 0));
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        p->OnLogEvent(event.get());
+    }
+
+    int64_t dumpTimeNs = startTimeNs + bucketSizeNs + 100 * NS_PER_SEC;
+
+    {
+        ConfigMetricsReportList reports;
+        vector<uint8_t> buffer;
+        p->onDumpReport(key, dumpTimeNs, true, true, ADB_DUMP, NO_TIME_CONSTRAINTS, &buffer);
+        EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+        ASSERT_EQ(reports.reports_size(), 1);
+
+        UidMapping uidMappingProto = reports.reports(0).uid_map();
+        ASSERT_EQ(uidMappingProto.snapshots_size(), 1);
+        const RepeatedPtrField<PackageInfo>& pkgs = uidMappingProto.snapshots(0).package_info();
+        set<int32_t> actualUsedUids;
+        std::for_each(pkgs.begin(), pkgs.end(),
+                      [&actualUsedUids](const PackageInfo& p) { actualUsedUids.insert(p.uid()); });
+
+        EXPECT_THAT(actualUsedUids, UnorderedElementsAre(UID_1, UID_2, UID_3, UID_4, UID_5, UID_6,
+                                                         UID_7, UID_8, UID_9));
+    }
+
+    // Verify the set is cleared and only contains the correct ids on the next dump.
+    p->OnLogEvent(makeUidLogEvent(ATOM_1, dumpTimeNs + 10, UID_1, 0, 0).get());
+    {
+        ConfigMetricsReportList reports;
+        vector<uint8_t> buffer;
+        p->onDumpReport(key, dumpTimeNs + 20, true, false, ADB_DUMP, FAST, &buffer);
+        EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+        ASSERT_EQ(reports.reports_size(), 1);
+
+        UidMapping uidMappingProto = reports.reports(0).uid_map();
+        ASSERT_EQ(uidMappingProto.snapshots_size(), 1);
+        const RepeatedPtrField<PackageInfo>& pkgs = uidMappingProto.snapshots(0).package_info();
+        set<int32_t> actualUsedUids;
+        std::for_each(pkgs.begin(), pkgs.end(),
+                      [&actualUsedUids](const PackageInfo& p) { actualUsedUids.insert(p.uid()); });
+
+        EXPECT_THAT(actualUsedUids, UnorderedElementsAre(UID_1));
+    }
+}
+
+TEST(UidMapTest, TestUsedUidsFromMetricE2e) {
+    const int ATOM_1 = 1, ATOM_2 = 2, ATOM_3 = 3, ATOM_4 = 4, ATOM_5 = 10001, ATOM_6 = 6;
+    StatsdConfig config;
+    config.mutable_statsd_config_options()->set_omit_unused_uids_in_uidmap(true);
+    config.add_default_pull_packages("AID_ROOT");  // Fake puller is registered with root.
+    AtomMatcher eventMatcher = CreateSimpleAtomMatcher("M1", ATOM_1);
+    *config.add_atom_matcher() = eventMatcher;
+    AtomMatcher countMatcher = CreateSimpleAtomMatcher("M2", ATOM_2);
+    *config.add_atom_matcher() = countMatcher;
+    AtomMatcher durationStartMatcher = CreateSimpleAtomMatcher("M3_START", ATOM_3);
+    auto fvmStart = durationStartMatcher.mutable_simple_atom_matcher()->add_field_value_matcher();
+    fvmStart->set_field(2);  // State field.
+    fvmStart->set_eq_int(0);
+    *config.add_atom_matcher() = durationStartMatcher;
+    AtomMatcher durationStopMatcher = CreateSimpleAtomMatcher("M3_STOP", ATOM_3);
+    auto fvmStop = durationStopMatcher.mutable_simple_atom_matcher()->add_field_value_matcher();
+    fvmStop->set_field(2);
+    fvmStop->set_eq_int(1);
+    *config.add_atom_matcher() = durationStopMatcher;
+    AtomMatcher gaugeMatcher = CreateSimpleAtomMatcher("M4", ATOM_4);
+    *config.add_atom_matcher() = gaugeMatcher;
+    AtomMatcher valueMatcher = CreateSimpleAtomMatcher("M5", ATOM_5);
+    *config.add_atom_matcher() = valueMatcher;
+    AtomMatcher kllMatcher = CreateSimpleAtomMatcher("M6", ATOM_6);
+    *config.add_atom_matcher() = kllMatcher;
+
+    Predicate predicate;
+    predicate.set_id(StringToId("P1"));
+    predicate.mutable_simple_predicate()->set_start(StringToId("M3_START"));
+    predicate.mutable_simple_predicate()->set_stop(StringToId("M3_STOP"));
+    FieldMatcher durDims = CreateDimensions(ATOM_3, {1});
+    *predicate.mutable_simple_predicate()->mutable_dimensions() = durDims;
+    *config.add_predicate() = predicate;
+
+    EventMetric eventMetric = createEventMetric("EVENT", eventMatcher.id(), nullopt);
+    *eventMetric.mutable_uid_fields() = CreateDimensions(ATOM_1, {1});
+    *config.add_event_metric() = eventMetric;
+    CountMetric countMetric = createCountMetric("COUNT", countMatcher.id(), nullopt, {});
+    *countMetric.mutable_dimensions_in_what() = CreateDimensions(ATOM_2, {1});
+    *countMetric.mutable_uid_fields() = CreateDimensions(ATOM_2, {1});
+    *config.add_count_metric() = countMetric;
+    DurationMetric durationMetric = createDurationMetric("DUR", predicate.id(), nullopt, {});
+    *durationMetric.mutable_dimensions_in_what() = durDims;
+    *durationMetric.mutable_uid_fields() = durDims;
+    *config.add_duration_metric() = durationMetric;
+    GaugeMetric gaugeMetric = createGaugeMetric("GAUGE", gaugeMatcher.id(),
+                                                GaugeMetric::FIRST_N_SAMPLES, nullopt, nullopt);
+    *gaugeMetric.mutable_dimensions_in_what() = CreateDimensions(ATOM_4, {1});
+    *gaugeMetric.mutable_uid_fields() = CreateDimensions(ATOM_4, {1, 2});
+    *config.add_gauge_metric() = gaugeMetric;
+    ValueMetric valueMetric = createValueMetric("VALUE", valueMatcher, 2, nullopt, {});
+    valueMetric.set_skip_zero_diff_output(false);
+    *valueMetric.mutable_dimensions_in_what() = CreateDimensions(ATOM_5, {1});
+    *valueMetric.mutable_uid_fields() = CreateDimensions(ATOM_5, {1});
+    *config.add_value_metric() = valueMetric;
+    KllMetric kllMetric = createKllMetric("KLL", kllMatcher, 2, nullopt);
+    *kllMetric.mutable_dimensions_in_what() = CreateDimensions(ATOM_6, {1});
+    *kllMetric.mutable_uid_fields() = CreateDimensions(ATOM_6, {1});
+    *config.add_kll_metric() = kllMetric;
+
+    int64_t startTimeNs = getElapsedRealtimeNs();
+    sp<UidMap> uidMap = new UidMap();
+    const int UID_1 = 11, UID_2 = 12, UID_3 = 13, UID_4 = 14, UID_5 = 15, UID_6 = 16, UID_7 = 17,
+              UID_8 = 18, UID_9 = 19;
+    int extraUids = 10;  // Extra uids in the uid map that aren't referenced in the metric report.
+    int extraUidStart = 1000;
+    vector<int> uids = {UID_1, UID_2, UID_3, UID_4, UID_5, UID_6, UID_7, UID_8, UID_9};
+    int numUids = extraUids + uids.size();
+    for (int i = 0; i < extraUids; i++) {
+        uids.push_back(extraUidStart + i);
+    }
+    // We only care about the uids for this test. Give defaults to everything else.
+    vector<int64_t> versions(numUids, 0);
+    vector<string> versionStrings(numUids, "");
+    vector<string> apps(numUids, "");
+    vector<string> installers(numUids, "");
+    vector<uint8_t> hash;
+    vector<vector<uint8_t>> certHashes(numUids, hash);
+    uidMap->updateMap(startTimeNs,
+                      createUidData(uids, versions, versionStrings, apps, installers, certHashes));
+
+    class FakePullAtomCallback : public BnPullAtomCallback {
+    public:
+        int pullNum = 1;
+        Status onPullAtom(int atomTag,
+                          const shared_ptr<IPullAtomResultReceiver>& resultReceiver) override {
+            std::vector<StatsEventParcel> parcels;
+            AStatsEvent* event = makeTwoValueStatsEvent(atomTag, 0, UID_8, pullNum);
+            AStatsEvent_build(event);
+
+            size_t size;
+            uint8_t* buffer = AStatsEvent_getBuffer(event, &size);
+
+            StatsEventParcel p;
+            p.buffer.assign(buffer, buffer + size);
+            parcels.push_back(std::move(p));
+            AStatsEvent_release(event);
+            pullNum++;
+            resultReceiver->pullFinished(atomTag, /*success=*/true, parcels);
+            return Status::ok();
+        }
+    };
+
+    ConfigKey key(123, 987);
+    sp<StatsLogProcessor> p =
+            CreateStatsLogProcessor(startTimeNs, startTimeNs, config, key,
+                                    SharedRefBase::make<FakePullAtomCallback>(), ATOM_5, uidMap);
+
+    const uint64_t bucketSizeNs = TimeUnitToBucketSizeInMillis(TEN_MINUTES) * 1000000LL;
+    std::vector<std::shared_ptr<LogEvent>> events;
+    events.push_back(CreateTwoValueLogEvent(ATOM_1, startTimeNs + 10, UID_1, 0));
+    events.push_back(CreateTwoValueLogEvent(ATOM_1, startTimeNs + 11, UID_2, 0));
+    events.push_back(CreateTwoValueLogEvent(ATOM_2, startTimeNs + 12, UID_3, 0));
+    events.push_back(CreateTwoValueLogEvent(ATOM_3, startTimeNs + 15, UID_5, 0));  // start
+    events.push_back(CreateTwoValueLogEvent(ATOM_3, startTimeNs + 18, UID_5, 1));  // stop
+    events.push_back(CreateTwoValueLogEvent(ATOM_4, startTimeNs + 20, UID_6, UID_7));
+    events.push_back(CreateTwoValueLogEvent(ATOM_6, startTimeNs + 22, UID_9, 0));
+
+    events.push_back(CreateTwoValueLogEvent(ATOM_2, startTimeNs + bucketSizeNs + 10, UID_4, 0));
+
+    // Send log events to StatsLogProcessor.
+    for (auto& event : events) {
+        p->OnLogEvent(event.get());
+    }
+
+    int64_t dumpTimeNs = startTimeNs + bucketSizeNs + 100 * NS_PER_SEC;
+
+    {
+        ConfigMetricsReportList reports;
+        vector<uint8_t> buffer;
+        p->onDumpReport(key, dumpTimeNs, true, true, ADB_DUMP, NO_TIME_CONSTRAINTS, &buffer);
+        EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+        ASSERT_EQ(reports.reports_size(), 1);
+
+        UidMapping uidMappingProto = reports.reports(0).uid_map();
+        ASSERT_EQ(uidMappingProto.snapshots_size(), 1);
+        const RepeatedPtrField<PackageInfo>& pkgs = uidMappingProto.snapshots(0).package_info();
+        set<int32_t> actualUsedUids;
+        std::for_each(pkgs.begin(), pkgs.end(),
+                      [&actualUsedUids](const PackageInfo& p) { actualUsedUids.insert(p.uid()); });
+
+        EXPECT_THAT(actualUsedUids, UnorderedElementsAre(UID_1, UID_2, UID_3, UID_4, UID_5, UID_6,
+                                                         UID_7, UID_8, UID_9));
+    }
+
+    // Verify the set is cleared and only contains the correct ids on the next dump.
+    p->OnLogEvent(CreateTwoValueLogEvent(ATOM_1, dumpTimeNs + 10, UID_1, 0).get());
+    {
+        ConfigMetricsReportList reports;
+        vector<uint8_t> buffer;
+        p->onDumpReport(key, dumpTimeNs + 20, true, false, ADB_DUMP, FAST, &buffer);
+        EXPECT_TRUE(reports.ParseFromArray(&buffer[0], buffer.size()));
+        ASSERT_EQ(reports.reports_size(), 1);
+
+        UidMapping uidMappingProto = reports.reports(0).uid_map();
+        ASSERT_EQ(uidMappingProto.snapshots_size(), 1);
+        const RepeatedPtrField<PackageInfo>& pkgs = uidMappingProto.snapshots(0).package_info();
+        set<int32_t> actualUsedUids;
+        std::for_each(pkgs.begin(), pkgs.end(),
+                      [&actualUsedUids](const PackageInfo& p) { actualUsedUids.insert(p.uid()); });
+
+        EXPECT_THAT(actualUsedUids, UnorderedElementsAre(UID_1));
+    }
+}
+
 }  // anonymous namespace
 #else
 GTEST_LOG_(INFO) << "This test does nothing.\n";
diff --git a/statsd/tests/external/StatsPullerManager_test.cpp b/statsd/tests/external/StatsPullerManager_test.cpp
index 0d539f47..98d1872f 100644
--- a/statsd/tests/external/StatsPullerManager_test.cpp
+++ b/statsd/tests/external/StatsPullerManager_test.cpp
@@ -19,6 +19,8 @@
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
+#include <thread>
+
 #include "stats_event.h"
 #include "tests/statsd_test_util.h"
 
@@ -54,9 +56,12 @@ AStatsEvent* createSimpleEvent(int32_t atomId, int32_t value) {
 
 class FakePullAtomCallback : public BnPullAtomCallback {
 public:
-    FakePullAtomCallback(int32_t uid) : mUid(uid){};
+    FakePullAtomCallback(int32_t uid, int32_t pullDurationNs = 0)
+        : mUid(uid), mDurationNs(pullDurationNs) {};
     Status onPullAtom(int atomTag,
                       const shared_ptr<IPullAtomResultReceiver>& resultReceiver) override {
+        onPullAtomCalled(atomTag);
+
         vector<StatsEventParcel> parcels;
         AStatsEvent* event = createSimpleEvent(atomTag, mUid);
         size_t size;
@@ -68,10 +73,18 @@ public:
         p.buffer.assign(buffer, buffer + size);
         parcels.push_back(std::move(p));
         AStatsEvent_release(event);
+
+        if (mDurationNs > 0) {
+            std::this_thread::sleep_for(std::chrono::nanoseconds(mDurationNs));
+        }
+
         resultReceiver->pullFinished(atomTag, /*success*/ true, parcels);
         return Status::ok();
     }
     int32_t mUid;
+    int32_t mDurationNs;
+
+    virtual void onPullAtomCalled(int atomTag) const {};
 };
 
 class FakePullUidProvider : public PullUidProvider {
@@ -86,11 +99,34 @@ public:
     }
 };
 
-sp<StatsPullerManager> createPullerManagerAndRegister() {
+class MockPullAtomCallback : public FakePullAtomCallback {
+public:
+    MockPullAtomCallback(int32_t uid, int32_t pullDurationNs = 0)
+        : FakePullAtomCallback(uid, pullDurationNs) {
+    }
+
+    MOCK_METHOD(void, onPullAtomCalled, (int), (const override));
+};
+
+class MockPullDataReceiver : public PullDataReceiver {
+public:
+    virtual ~MockPullDataReceiver() = default;
+
+    MOCK_METHOD(void, onDataPulled,
+                (const std::vector<std::shared_ptr<LogEvent>>&, PullResult, int64_t), (override));
+
+    bool isPullNeeded() const override {
+        return true;
+    };
+};
+
+sp<StatsPullerManager> createPullerManagerAndRegister(int32_t pullDurationMs = 0) {
     sp<StatsPullerManager> pullerManager = new StatsPullerManager();
-    shared_ptr<FakePullAtomCallback> cb1 = SharedRefBase::make<FakePullAtomCallback>(uid1);
+    shared_ptr<FakePullAtomCallback> cb1 =
+            SharedRefBase::make<FakePullAtomCallback>(uid1, pullDurationMs);
     pullerManager->RegisterPullAtomCallback(uid1, pullTagId1, coolDownNs, timeoutNs, {}, cb1);
-    shared_ptr<FakePullAtomCallback> cb2 = SharedRefBase::make<FakePullAtomCallback>(uid2);
+    shared_ptr<FakePullAtomCallback> cb2 =
+            SharedRefBase::make<FakePullAtomCallback>(uid2, pullDurationMs);
     pullerManager->RegisterPullAtomCallback(uid2, pullTagId1, coolDownNs, timeoutNs, {}, cb2);
     pullerManager->RegisterPullAtomCallback(uid1, pullTagId2, coolDownNs, timeoutNs, {}, cb1);
     return pullerManager;
@@ -145,6 +181,54 @@ TEST(StatsPullerManagerTest, TestPullConfigKeyNoPullerWithUid) {
     EXPECT_FALSE(pullerManager->Pull(pullTagId2, configKey, /*timestamp =*/1, &data));
 }
 
+TEST(StatsPullerManagerTest, TestSameAtomIsPulledInABatch) {
+    // define 2 puller callbacks with small duration each to guaranty that
+    // call sequence callback A + callback B will invalidate pull cache
+    // for callback A if PullerManager does not group receivers by tagId
+
+    const int64_t pullDurationNs = (int)(timeoutNs * 0.9);
+
+    sp<StatsPullerManager> pullerManager = new StatsPullerManager();
+    auto cb1 = SharedRefBase::make<StrictMock<MockPullAtomCallback>>(uid1, pullDurationNs);
+    pullerManager->RegisterPullAtomCallback(uid1, pullTagId1, coolDownNs, timeoutNs, {}, cb1);
+    auto cb2 = SharedRefBase::make<StrictMock<MockPullAtomCallback>>(uid2, pullDurationNs);
+    pullerManager->RegisterPullAtomCallback(uid2, pullTagId2, coolDownNs, timeoutNs, {}, cb2);
+
+    sp<FakePullUidProvider> uidProvider = new FakePullUidProvider();
+    pullerManager->RegisterPullUidProvider(configKey, uidProvider);
+
+    const int64_t bucketBoundary = NS_PER_SEC * 60 * 60 * 1;  // 1 hour
+
+    // create 10 receivers to simulate 10 distinct metrics for pulled atoms
+    // add 10 metric where 5 depends on atom A and 5 on atom B
+    vector<sp<MockPullDataReceiver>> receivers;
+    receivers.reserve(10);
+    for (int i = 0; i < 10; i++) {
+        auto receiver = new StrictMock<MockPullDataReceiver>();
+        EXPECT_CALL(*receiver, onDataPulled(_, _, _)).Times(1);
+        receivers.push_back(receiver);
+
+        const int32_t atomTag = i % 2 == 0 ? pullTagId1 : pullTagId2;
+        pullerManager->RegisterReceiver(atomTag, configKey, receiver, bucketBoundary,
+                                        bucketBoundary);
+    }
+
+    // check that only 2 pulls will be done and remaining 8 pulls from cache
+    EXPECT_CALL(*cb1, onPullAtomCalled(pullTagId1)).Times(1);
+    EXPECT_CALL(*cb2, onPullAtomCalled(pullTagId2)).Times(1);
+
+    // validate that created 2 receivers groups just for 2 atoms with 5 receivers in each
+    ASSERT_EQ(pullerManager->mReceivers.size(), 2);
+    ASSERT_EQ(pullerManager->mReceivers.begin()->second.size(), 5);
+    ASSERT_EQ(pullerManager->mReceivers.rbegin()->second.size(), 5);
+
+    // simulate pulls
+    pullerManager->OnAlarmFired(bucketBoundary + 1);
+
+    // to allow async pullers to complete + some extra time
+    std::this_thread::sleep_for(std::chrono::nanoseconds(pullDurationNs * 3));
+}
+
 }  // namespace statsd
 }  // namespace os
-}  // namespace android
\ No newline at end of file
+}  // namespace android
diff --git a/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp b/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
index d8ae123f..6b6ab370 100644
--- a/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
+++ b/statsd/tests/metrics/parsing_utils/metrics_manager_util_test.cpp
@@ -1850,7 +1850,7 @@ TEST_F(MetricsManagerUtilTest, TestMetricHasRepeatedSampledField_PositionANY) {
             util::TEST_ATOM_REPORTED, {9 /*repeated_int_field*/}, {Position::ANY});
     *metric.mutable_dimensional_sampling_info()->mutable_sampled_what_field() =
             CreateRepeatedDimensions(util::TEST_ATOM_REPORTED, {9 /*repeated_int_field*/},
-                                     {Position::ALL});
+                                     {Position::ANY});
     metric.mutable_dimensional_sampling_info()->set_shard_count(2);
     *config.add_count_metric() = metric;
 
@@ -2527,6 +2527,136 @@ TEST_F(MetricsManagerUtilTest, TestValueMetricHistogramWithValueDirectionNotIncr
                                   config.value_metric(0).id()));
 }
 
+TEST_F(MetricsManagerUtilTest, TestUidFields) {
+    StatsdConfig config;
+
+    AtomMatcher appCrashMatcher =
+            CreateSimpleAtomMatcher("APP_CRASH_OCCURRED", util::APP_CRASH_OCCURRED);
+    *config.add_atom_matcher() = appCrashMatcher;
+
+    *config.add_atom_matcher() = CreateAcquireWakelockAtomMatcher();
+    *config.add_atom_matcher() = CreateReleaseWakelockAtomMatcher();
+
+    AtomMatcher bleScanResultReceivedMatcher =
+            CreateSimpleAtomMatcher("Ble", util::BLE_SCAN_RESULT_RECEIVED);
+    *config.add_atom_matcher() = bleScanResultReceivedMatcher;
+
+    Predicate holdingWakelockPredicate = CreateHoldingWakelockPredicate();
+    *holdingWakelockPredicate.mutable_simple_predicate()->mutable_dimensions() =
+            CreateAttributionUidDimensions(util::WAKELOCK_STATE_CHANGED, {Position::FIRST});
+    *config.add_predicate() = holdingWakelockPredicate;
+
+    CountMetric uidCountMetric = createCountMetric("C1", appCrashMatcher.id(), nullopt, {});
+    *uidCountMetric.mutable_uid_fields() = CreateDimensions(util::APP_CRASH_OCCURRED, {1 /*uid*/});
+    *config.add_count_metric() = uidCountMetric;
+
+    CountMetric countMetric = createCountMetric("C2", appCrashMatcher.id(), nullopt, {});
+    *config.add_count_metric() = countMetric;
+
+    DurationMetric uidDurationMetric =
+            createDurationMetric("D1", holdingWakelockPredicate.id(), nullopt, {});
+    *uidDurationMetric.mutable_uid_fields() =
+            CreateAttributionUidDimensions(util::WAKELOCK_STATE_CHANGED, {Position::FIRST});
+    *config.add_duration_metric() = uidDurationMetric;
+
+    DurationMetric durationMetric =
+            createDurationMetric("D2", holdingWakelockPredicate.id(), nullopt, {});
+    *config.add_duration_metric() = durationMetric;
+
+    EventMetric uidEventMetric = createEventMetric("E1", appCrashMatcher.id(), nullopt);
+    *uidEventMetric.mutable_uid_fields() = CreateDimensions(util::APP_CRASH_OCCURRED, {1 /*uid*/});
+    *config.add_event_metric() = uidEventMetric;
+
+    EventMetric eventMetric = createEventMetric("E2", appCrashMatcher.id(), nullopt);
+    *config.add_event_metric() = eventMetric;
+
+    ValueMetric uidValueMetric = createValueMetric("V1", bleScanResultReceivedMatcher,
+                                                   /*num_results=*/2, nullopt, {});
+    *uidValueMetric.mutable_uid_fields() =
+            CreateDimensions(util::BLE_SCAN_RESULT_RECEIVED, {1 /* uid */});
+    *config.add_value_metric() = uidValueMetric;
+
+    ValueMetric valueMetric = createValueMetric("V2", bleScanResultReceivedMatcher,
+                                                /*num_results=*/2, nullopt, {});
+    *config.add_value_metric() = valueMetric;
+
+    KllMetric uidKllMetric = createKllMetric("K1", bleScanResultReceivedMatcher,
+                                             /*num_results=*/2, nullopt);
+    *uidKllMetric.mutable_uid_fields() =
+            CreateDimensions(util::BLE_SCAN_RESULT_RECEIVED, {1 /* uid */});
+    *config.add_kll_metric() = uidKllMetric;
+
+    KllMetric kllMetric =
+            createKllMetric("K2", bleScanResultReceivedMatcher, /*num_results=*/2, nullopt);
+    *config.add_kll_metric() = kllMetric;
+
+    GaugeMetric uidGaugeMetric = createGaugeMetric("G1", appCrashMatcher.id(),
+                                                   GaugeMetric::FIRST_N_SAMPLES, nullopt, nullopt);
+    *uidGaugeMetric.mutable_uid_fields() =
+            CreateDimensions(util::APP_CRASH_OCCURRED, {1 /* uid */});
+    *config.add_gauge_metric() = uidGaugeMetric;
+
+    GaugeMetric gaugeMetric = createGaugeMetric("G2", appCrashMatcher.id(),
+                                                GaugeMetric::FIRST_N_SAMPLES, nullopt, nullopt);
+    *config.add_gauge_metric() = gaugeMetric;
+
+    ConfigKey key(123, 987);
+    uint64_t timeNs = 456;
+    sp<StatsPullerManager> pullerManager = new StatsPullerManager();
+    sp<AlarmMonitor> anomalyAlarmMonitor;
+    sp<AlarmMonitor> periodicAlarmMonitor;
+    sp<UidMap> uidMap;
+    sp<MetricsManager> metricsManager =
+            new MetricsManager(key, config, timeNs, timeNs, uidMap, pullerManager,
+                               anomalyAlarmMonitor, periodicAlarmMonitor);
+    ASSERT_TRUE(metricsManager->isConfigValid());
+    ASSERT_EQ(12, metricsManager->mAllMetricProducers.size());
+
+    sp<MetricProducer> uidCountMetricProducer = metricsManager->mAllMetricProducers[0];
+    sp<MetricProducer> countMetricProducer = metricsManager->mAllMetricProducers[1];
+    sp<MetricProducer> uidDurationMetricProducer = metricsManager->mAllMetricProducers[2];
+    sp<MetricProducer> durationMetricProducer = metricsManager->mAllMetricProducers[3];
+    sp<MetricProducer> uidEventMetricProducer = metricsManager->mAllMetricProducers[4];
+    sp<MetricProducer> eventMetricProducer = metricsManager->mAllMetricProducers[5];
+    sp<MetricProducer> uidValueMetricProducer = metricsManager->mAllMetricProducers[6];
+    sp<MetricProducer> valueMetricProducer = metricsManager->mAllMetricProducers[7];
+    sp<MetricProducer> uidKllMetricProducer = metricsManager->mAllMetricProducers[8];
+    sp<MetricProducer> kllMetricProducer = metricsManager->mAllMetricProducers[9];
+    sp<MetricProducer> uidGaugeMetricProducer = metricsManager->mAllMetricProducers[10];
+    sp<MetricProducer> gaugeMetricProducer = metricsManager->mAllMetricProducers[11];
+
+    // Check uid what fields is set correctly or empty.
+    EXPECT_EQ(1, uidCountMetricProducer->mUidFields.size());
+    EXPECT_EQ(true, countMetricProducer->mUidFields.empty());
+    EXPECT_EQ(1, uidDurationMetricProducer->mUidFields.size());
+    EXPECT_EQ(true, durationMetricProducer->mUidFields.empty());
+    EXPECT_EQ(1, uidEventMetricProducer->mUidFields.size());
+    EXPECT_EQ(true, eventMetricProducer->mUidFields.empty());
+    EXPECT_EQ(1, uidValueMetricProducer->mUidFields.size());
+    EXPECT_EQ(true, valueMetricProducer->mUidFields.empty());
+    EXPECT_EQ(1, uidKllMetricProducer->mUidFields.size());
+    EXPECT_EQ(true, kllMetricProducer->mUidFields.empty());
+    EXPECT_EQ(1, uidGaugeMetricProducer->mUidFields.size());
+    EXPECT_EQ(true, gaugeMetricProducer->mUidFields.empty());
+}
+
+TEST_F(MetricsManagerUtilTest, TestMetricHasRepeatedUidField_PositionANY) {
+    AtomMatcher testAtomReportedMatcher =
+            CreateSimpleAtomMatcher("TEST_ATOM_REPORTED", util::TEST_ATOM_REPORTED);
+
+    StatsdConfig config;
+    *config.add_atom_matcher() = testAtomReportedMatcher;
+
+    CountMetric metric = createCountMetric("CountSampledTestAtomReportedPerRepeatedIntField",
+                                           testAtomReportedMatcher.id(), nullopt, {});
+    *metric.mutable_uid_fields() = CreateRepeatedDimensions(
+            util::TEST_ATOM_REPORTED, {9 /*repeated_int_field*/}, {Position::ANY});
+    *config.add_count_metric() = metric;
+
+    EXPECT_EQ(initConfig(config),
+              InvalidConfigReason(INVALID_CONFIG_REASON_UID_FIELDS_WITH_POSITION_ANY, metric.id()));
+}
+
 }  // namespace statsd
 }  // namespace os
 }  // namespace android
diff --git a/statsd/tests/statsd_test_util.cpp b/statsd/tests/statsd_test_util.cpp
index d30a498e..6185c556 100644
--- a/statsd/tests/statsd_test_util.cpp
+++ b/statsd/tests/statsd_test_util.cpp
@@ -768,8 +768,8 @@ bool parseStatsEventToLogEvent(AStatsEvent* statsEvent, LogEvent* logEvent) {
     return result;
 }
 
-void CreateTwoValueLogEvent(LogEvent* logEvent, int atomId, int64_t eventTimeNs, int32_t value1,
-                            int32_t value2) {
+AStatsEvent* makeTwoValueStatsEvent(int atomId, int64_t eventTimeNs, int32_t value1,
+                                    int32_t value2) {
     AStatsEvent* statsEvent = AStatsEvent_obtain();
     AStatsEvent_setAtomId(statsEvent, atomId);
     AStatsEvent_overwriteTimestamp(statsEvent, eventTimeNs);
@@ -777,6 +777,12 @@ void CreateTwoValueLogEvent(LogEvent* logEvent, int atomId, int64_t eventTimeNs,
     AStatsEvent_writeInt32(statsEvent, value1);
     AStatsEvent_writeInt32(statsEvent, value2);
 
+    return statsEvent;
+}
+
+void CreateTwoValueLogEvent(LogEvent* logEvent, int atomId, int64_t eventTimeNs, int32_t value1,
+                            int32_t value2) {
+    AStatsEvent* statsEvent = makeTwoValueStatsEvent(atomId, eventTimeNs, value1, value2);
     parseStatsEventToLogEvent(statsEvent, logEvent);
 }
 
@@ -865,6 +871,19 @@ AStatsEvent* makeUidStatsEvent(int atomId, int64_t eventTimeNs, int uid, int dat
     return statsEvent;
 }
 
+AStatsEvent* makeAttributionStatsEvent(int atomId, int64_t eventTimeNs, const vector<int>& uids,
+                                       const vector<string>& tags, int data1, int data2) {
+    AStatsEvent* statsEvent = AStatsEvent_obtain();
+    AStatsEvent_setAtomId(statsEvent, atomId);
+    AStatsEvent_overwriteTimestamp(statsEvent, eventTimeNs);
+
+    writeAttribution(statsEvent, uids, tags);
+    AStatsEvent_writeInt32(statsEvent, data1);
+    AStatsEvent_writeInt32(statsEvent, data2);
+
+    return statsEvent;
+}
+
 shared_ptr<LogEvent> makeUidLogEvent(int atomId, int64_t eventTimeNs, int uid, int data1,
                                      int data2) {
     AStatsEvent* statsEvent = makeUidStatsEvent(atomId, eventTimeNs, uid, data1, data2);
@@ -946,13 +965,8 @@ shared_ptr<LogEvent> makeRepeatedUidLogEvent(int atomId, int64_t eventTimeNs,
 shared_ptr<LogEvent> makeAttributionLogEvent(int atomId, int64_t eventTimeNs,
                                              const vector<int>& uids, const vector<string>& tags,
                                              int data1, int data2) {
-    AStatsEvent* statsEvent = AStatsEvent_obtain();
-    AStatsEvent_setAtomId(statsEvent, atomId);
-    AStatsEvent_overwriteTimestamp(statsEvent, eventTimeNs);
-
-    writeAttribution(statsEvent, uids, tags);
-    AStatsEvent_writeInt32(statsEvent, data1);
-    AStatsEvent_writeInt32(statsEvent, data2);
+    AStatsEvent* statsEvent =
+            makeAttributionStatsEvent(atomId, eventTimeNs, uids, tags, data1, data2);
 
     shared_ptr<LogEvent> logEvent = std::make_shared<LogEvent>(/*uid=*/0, /*pid=*/0);
     parseStatsEventToLogEvent(statsEvent, logEvent.get());
@@ -1480,6 +1494,7 @@ sp<StatsLogProcessor> CreateStatsLogProcessor(const int64_t timeBaseNs, const in
                                               const int32_t atomTag, const sp<UidMap> uidMap,
                                               const shared_ptr<LogEventFilter>& logEventFilter) {
     sp<StatsPullerManager> pullerManager = new StatsPullerManager();
+    StatsPuller::SetUidMap(uidMap);
     if (puller != nullptr) {
         pullerManager->RegisterPullAtomCallback(/*uid=*/0, atomTag, NS_PER_SEC, NS_PER_SEC * 10, {},
                                                 puller);
@@ -1574,13 +1589,13 @@ sp<NumericValueMetricProducer> createNumericValueMetricProducer(
 }
 
 LogEventFilter::AtomIdSet CreateAtomIdSetDefault() {
-    LogEventFilter::AtomIdSet resultList(std::move(StatsLogProcessor::getDefaultAtomIdSet()));
+    LogEventFilter::AtomIdSet resultList(StatsLogProcessor::getDefaultAtomIdSet());
     StateManager::getInstance().addAllAtomIds(resultList);
     return resultList;
 }
 
 LogEventFilter::AtomIdSet CreateAtomIdSetFromConfig(const StatsdConfig& config) {
-    LogEventFilter::AtomIdSet resultList(std::move(StatsLogProcessor::getDefaultAtomIdSet()));
+    LogEventFilter::AtomIdSet resultList(StatsLogProcessor::getDefaultAtomIdSet());
 
     // Parse the config for atom ids. A combination atom matcher is a combination of (in the end)
     // simple atom matchers. So by adding all the atoms from the simple atom matchers
diff --git a/statsd/tests/statsd_test_util.h b/statsd/tests/statsd_test_util.h
index 02d8bec7..294553d6 100644
--- a/statsd/tests/statsd_test_util.h
+++ b/statsd/tests/statsd_test_util.h
@@ -392,6 +392,9 @@ void writeAttribution(AStatsEvent* statsEvent, const vector<int>& attributionUid
 // Builds statsEvent to get buffer that is parsed into logEvent then releases statsEvent.
 bool parseStatsEventToLogEvent(AStatsEvent* statsEvent, LogEvent* logEvent);
 
+AStatsEvent* makeTwoValueStatsEvent(int atomId, int64_t eventTimeNs, int32_t value1,
+                                    int32_t value2);
+
 shared_ptr<LogEvent> CreateTwoValueLogEvent(int atomId, int64_t eventTimeNs, int32_t value1,
                                             int32_t value2);
 
@@ -417,6 +420,9 @@ std::shared_ptr<LogEvent> CreateNoValuesLogEvent(int atomId, int64_t eventTimeNs
 
 void CreateNoValuesLogEvent(LogEvent* logEvent, int atomId, int64_t eventTimeNs);
 
+AStatsEvent* makeAttributionStatsEvent(int atomId, int64_t eventTimeNs, const vector<int>& uids,
+                                       const vector<string>& tags, int data1, int data2);
+
 AStatsEvent* makeUidStatsEvent(int atomId, int64_t eventTimeNs, int uid, int data1, int data2);
 
 AStatsEvent* makeUidStatsEvent(int atomId, int64_t eventTimeNs, int uid, int data1,
diff --git a/tests/Android.bp b/tests/Android.bp
index 22dd224f..e58f1d42 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -19,7 +19,6 @@ package {
 
 java_test_host {
     name: "CtsStatsdHostTestCases",
-    team: "trendy_team_android_telemetry_infra",
 
     srcs: [
         "src/**/*.java",
@@ -49,6 +48,8 @@ java_test_host {
     ],
     data: [
         "**/*.pbtxt",
+    ],
+    device_common_data: [
         ":CtsStatsdApp",
         ":StatsdAtomStormApp",
     ],
diff --git a/tests/apps/statsdapp/AndroidManifest.xml b/tests/apps/statsdapp/AndroidManifest.xml
index d9ee535e..8ed9a930 100644
--- a/tests/apps/statsdapp/AndroidManifest.xml
+++ b/tests/apps/statsdapp/AndroidManifest.xml
@@ -30,9 +30,11 @@
     <uses-permission android:name="android.permission.CONFIGURE_DISPLAY_BRIGHTNESS"/>
     <uses-permission android:name="android.permission.DUMP"/> <!-- must be granted via pm grant -->
     <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_CAMERA"/>
     <uses-permission android:name="android.permission.INTERNET"/>
     <uses-permission android:name="android.permission.READ_SYNC_STATS"/>
     <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
+    <uses-permission android:name="android.permission.SYSTEM_CAMERA"/>
     <uses-permission android:name="android.permission.VIBRATE"/>
     <uses-permission android:name="android.permission.WAKE_LOCK"/>
     <uses-permission android:name="android.permission.WRITE_SYNC_SETTINGS"/>
diff --git a/tests/apps/statsdapp/src/com/android/server/cts/device/statsd/AtomTests.java b/tests/apps/statsdapp/src/com/android/server/cts/device/statsd/AtomTests.java
index 41481392..d457fd80 100644
--- a/tests/apps/statsdapp/src/com/android/server/cts/device/statsd/AtomTests.java
+++ b/tests/apps/statsdapp/src/com/android/server/cts/device/statsd/AtomTests.java
@@ -575,6 +575,107 @@ public class AtomTests {
         StatsLog.write(builder.build());
     }
 
+    @Test
+    public void testWriteRawTestAtom() throws Exception {
+        Context context = InstrumentationRegistry.getTargetContext();
+        ApplicationInfo appInfo = context.getPackageManager()
+                .getApplicationInfo(context.getPackageName(), 0);
+        int[] uids = {1234, appInfo.uid};
+        String[] tags = {"tag1", "tag2"};
+        byte[] experimentIds = {8, 1, 8, 2, 8, 3}; // Corresponds to 1, 2, 3.
+
+        int[] int32Array = {3, 6};
+        long[] int64Array = {1000L, 1002L};
+        float[] floatArray = {0.3f, 0.09f};
+        String[] stringArray = {"str1", "str2"};
+        boolean[] boolArray = {true, false};
+        int[] enumArray = {StatsLogStatsdCts.TEST_ATOM_REPORTED__STATE__OFF,
+                StatsLogStatsdCts.TEST_ATOM_REPORTED__STATE__ON};
+
+        StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_ATOM_REPORTED, uids, tags, 42,
+                Long.MAX_VALUE, 3.14f, "This is a basic test!", false,
+                StatsLogStatsdCts.TEST_ATOM_REPORTED__STATE__ON, experimentIds, int32Array,
+                int64Array, floatArray, stringArray, boolArray, enumArray);
+
+        // All nulls. Should get dropped since cts app is not in the attribution chain.
+        StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_ATOM_REPORTED, null, null, 0, 0, 0f, null,
+                false, StatsLogStatsdCts.TEST_ATOM_REPORTED__STATE__ON, null, null, null, null,
+                null, null, null);
+
+        // Null tag in attribution chain.
+        int[] uids2 = {9999, appInfo.uid};
+        String[] tags2 = {"tag9999", null};
+        StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_ATOM_REPORTED, uids2, tags2, 100,
+                Long.MIN_VALUE, -2.5f, "Test null uid", true,
+                StatsLogStatsdCts.TEST_ATOM_REPORTED__STATE__UNKNOWN, experimentIds, int32Array,
+                int64Array, floatArray, stringArray, boolArray, enumArray);
+
+        // Non chained non-null
+        StatsLogStatsdCts.write_non_chained(StatsLogStatsdCts.TEST_ATOM_REPORTED, appInfo.uid,
+                "tag1", -256, -1234567890L, 42.01f, "Test non chained", true,
+                StatsLogStatsdCts.TEST_ATOM_REPORTED__STATE__OFF, experimentIds, new int[0],
+                new long[0], new float[0], new String[0], new boolean[0], new int[0]);
+
+        // Non chained all null
+        StatsLogStatsdCts.write_non_chained(StatsLogStatsdCts.TEST_ATOM_REPORTED, appInfo.uid, null,
+                0, 0, 0f, null, true, StatsLogStatsdCts.TEST_ATOM_REPORTED__STATE__OFF, null, null,
+                null, null, null, null, null);
+    }
+
+    @Test
+    public void testWriteExtensionTestAtom() throws Exception {
+        Context context = InstrumentationRegistry.getTargetContext();
+        ApplicationInfo appInfo = context.getPackageManager()
+                .getApplicationInfo(context.getPackageName(), 0);
+        int[] uids = {1234, appInfo.uid};
+        String[] tags = {"tag1", "tag2"};
+        byte[] testAtomNestedMsg = {8, 1, 8, 2, 8, 3}; // Corresponds to 1, 2, 3.
+
+        int[] int32Array = {3, 6};
+        long[] int64Array = {1000L, 1002L};
+        float[] floatArray = {0.3f, 0.09f};
+        String[] stringArray = {"str1", "str2"};
+        boolean[] boolArray = {true, false};
+        int[] enumArray = {StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__OFF,
+                StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__ON};
+
+        StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED, uids, tags, 42,
+                Long.MAX_VALUE, 3.14f, "This is a basic test!", false,
+                StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__ON, testAtomNestedMsg,
+                int32Array,
+                int64Array, floatArray, stringArray, boolArray, enumArray);
+
+        // All nulls. Should get dropped since cts app is not in the attribution chain.
+        StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED, null, null, 0, 0,
+                0f, null,
+                false, StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__ON, null, null, null,
+                null,
+                null, null, null);
+
+        // Null tag in attribution chain.
+        int[] uids2 = {9999, appInfo.uid};
+        String[] tags2 = {"tag9999", null};
+        StatsLogStatsdCts.write(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED, uids2, tags2, 100,
+                Long.MIN_VALUE, -2.5f, "Test null uid", true,
+                StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__UNKNOWN, testAtomNestedMsg,
+                int32Array,
+                int64Array, floatArray, stringArray, boolArray, enumArray);
+
+        // Non chained non-null
+        StatsLogStatsdCts.write_non_chained(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED,
+                appInfo.uid,
+                "tag1", -256, -1234567890L, 42.01f, "Test non chained", true,
+                StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__OFF, testAtomNestedMsg,
+                new int[0],
+                new long[0], new float[0], new String[0], new boolean[0], new int[0]);
+
+        // Non chained all null
+        StatsLogStatsdCts.write_non_chained(StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED,
+                appInfo.uid, null,
+                0, 0, 0f, null, true, StatsLogStatsdCts.TEST_EXTENSION_ATOM_REPORTED__STATE__OFF,
+                null, null,
+                null, null, null, null, null);
+    }
 
     @Test
     public void testWakelockLoad() {
diff --git a/tests/src/android/cts/statsd/atom/AtomParsingTests.java b/tests/src/android/cts/statsd/atom/AtomParsingTests.java
new file mode 100644
index 00000000..d8a25011
--- /dev/null
+++ b/tests/src/android/cts/statsd/atom/AtomParsingTests.java
@@ -0,0 +1,307 @@
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
+package android.cts.statsd.atom;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.cts.statsd.metric.MetricsUtils;
+import android.cts.statsdatom.lib.AtomTestUtils;
+import android.cts.statsdatom.lib.ConfigUtils;
+import android.cts.statsdatom.lib.DeviceUtils;
+import android.cts.statsdatom.lib.ReportUtils;
+
+import com.android.os.AtomsProto.Atom;
+import com.android.os.AttributionNode;
+import com.android.os.StatsLog.EventMetricData;
+import com.android.os.AtomsProto.TestAtomReported;
+import com.android.os.statsd.StatsdExtensionAtoms;
+import com.android.os.statsd.StatsdExtensionAtoms.TestExtensionAtomReported;
+import com.android.tradefed.build.IBuildInfo;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.build.IBuildInfo;
+import com.android.tradefed.testtype.DeviceTestCase;
+import com.android.tradefed.testtype.IBuildReceiver;
+import com.android.tradefed.util.RunUtil;
+
+import com.google.protobuf.ExtensionRegistry;
+
+import java.util.List;
+import java.util.concurrent.Flow.Subscription;
+
+public class AtomParsingTests extends DeviceTestCase implements IBuildReceiver {
+
+    private IBuildInfo mCtsBuild;
+
+    @Override
+    protected void setUp() throws Exception {
+        super.setUp();
+        assertThat(mCtsBuild).isNotNull();
+        ConfigUtils.removeConfig(getDevice());
+        ReportUtils.clearReports(getDevice());
+        DeviceUtils.installTestApp(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_APK,
+                MetricsUtils.DEVICE_SIDE_TEST_PACKAGE, mCtsBuild);
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_LONG);
+    }
+
+    @Override
+    protected void tearDown() throws Exception {
+        super.tearDown();
+        ConfigUtils.removeConfig(getDevice());
+        ReportUtils.clearReports(getDevice());
+        DeviceUtils.uninstallTestApp(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE);
+    }
+
+    @Override
+    public void setBuild(IBuildInfo buildInfo) {
+        mCtsBuild = buildInfo;
+    }
+
+    public void testWriteExtensionTestAtom() throws Exception {
+        final int atomTag = StatsdExtensionAtoms.TEST_EXTENSION_ATOM_REPORTED_FIELD_NUMBER;
+        ConfigUtils.uploadConfigForPushedAtomWithUid(getDevice(),
+                MetricsUtils.DEVICE_SIDE_TEST_PACKAGE, atomTag, /*useUidAttributionChain=*/true);
+
+        DeviceUtils.runDeviceTests(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE,
+                ".AtomTests", "testWriteExtensionTestAtom");
+
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_SHORT);
+        // Sorted list of events in order in which they occurred.
+
+        ExtensionRegistry registry = ExtensionRegistry.newInstance();
+        StatsdExtensionAtoms.registerAllExtensions(registry);
+
+        List<EventMetricData> data = ReportUtils.getEventMetricDataList(getDevice(), registry);
+        assertThat(data).hasSize(4);
+
+        TestExtensionAtomReported atom = data.get(0).getAtom().getExtension(
+                StatsdExtensionAtoms.testExtensionAtomReported);
+        List<AttributionNode> attrChain = atom.getAttributionNodeList();
+        assertThat(attrChain).hasSize(2);
+        assertThat(attrChain.get(0).getUid()).isEqualTo(1234);
+        assertThat(attrChain.get(0).getTag()).isEqualTo("tag1");
+        assertThat(attrChain.get(1).getUid()).isEqualTo(
+                DeviceUtils.getAppUid(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE));
+        assertThat(attrChain.get(1).getTag()).isEqualTo("tag2");
+
+        assertThat(atom.getIntField()).isEqualTo(42);
+        assertThat(atom.getLongField()).isEqualTo(Long.MAX_VALUE);
+        assertThat(atom.getFloatField()).isEqualTo(3.14f);
+        assertThat(atom.getStringField()).isEqualTo("This is a basic test!");
+        assertThat(atom.getBooleanField()).isFalse();
+        assertThat(atom.getState().getNumber()).isEqualTo(TestExtensionAtomReported.State.ON_VALUE);
+        assertThat(atom.getBytesField().getLongFieldList())
+                .containsExactly(1L, 2L, 3L).inOrder();
+
+        assertThat(atom.getRepeatedIntFieldList()).containsExactly(3, 6).inOrder();
+        assertThat(atom.getRepeatedLongFieldList()).containsExactly(1000L, 1002L).inOrder();
+        assertThat(atom.getRepeatedFloatFieldList()).containsExactly(0.3f, 0.09f).inOrder();
+        assertThat(atom.getRepeatedStringFieldList()).containsExactly("str1", "str2").inOrder();
+        assertThat(atom.getRepeatedBooleanFieldList()).containsExactly(true, false).inOrder();
+        assertThat(atom.getRepeatedEnumFieldList())
+                .containsExactly(TestExtensionAtomReported.State.OFF,
+                    TestExtensionAtomReported.State.ON).inOrder();
+
+        atom = data.get(1).getAtom().getExtension(
+            StatsdExtensionAtoms.testExtensionAtomReported);
+        attrChain = atom.getAttributionNodeList();
+        assertThat(attrChain).hasSize(2);
+        assertThat(attrChain.get(0).getUid()).isEqualTo(9999);
+        assertThat(attrChain.get(0).getTag()).isEqualTo("tag9999");
+        assertThat(attrChain.get(1).getUid()).isEqualTo(
+                DeviceUtils.getAppUid(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE));
+        assertThat(attrChain.get(1).getTag()).isEmpty();
+
+        assertThat(atom.getIntField()).isEqualTo(100);
+        assertThat(atom.getLongField()).isEqualTo(Long.MIN_VALUE);
+        assertThat(atom.getFloatField()).isEqualTo(-2.5f);
+        assertThat(atom.getStringField()).isEqualTo("Test null uid");
+        assertThat(atom.getBooleanField()).isTrue();
+        assertThat(atom.getState().getNumber()).isEqualTo(
+                TestExtensionAtomReported.State.UNKNOWN_VALUE);
+        assertThat(atom.getBytesField().getLongFieldList())
+                .containsExactly(1L, 2L, 3L).inOrder();
+        assertThat(atom.getRepeatedIntFieldList()).containsExactly(3, 6).inOrder();
+        assertThat(atom.getRepeatedLongFieldList()).containsExactly(1000L, 1002L).inOrder();
+        assertThat(atom.getRepeatedFloatFieldList()).containsExactly(0.3f, 0.09f).inOrder();
+        assertThat(atom.getRepeatedStringFieldList()).containsExactly("str1", "str2").inOrder();
+        assertThat(atom.getRepeatedBooleanFieldList()).containsExactly(true, false).inOrder();
+        assertThat(atom.getRepeatedEnumFieldList())
+                .containsExactly(TestExtensionAtomReported.State.OFF,
+                        TestExtensionAtomReported.State.ON)
+                .inOrder();
+
+        atom = data.get(2).getAtom().getExtension(
+            StatsdExtensionAtoms.testExtensionAtomReported);
+        attrChain = atom.getAttributionNodeList();
+        assertThat(attrChain).hasSize(1);
+        assertThat(attrChain.get(0).getUid()).isEqualTo(
+                DeviceUtils.getAppUid(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE));
+        assertThat(attrChain.get(0).getTag()).isEqualTo("tag1");
+
+        assertThat(atom.getIntField()).isEqualTo(-256);
+        assertThat(atom.getLongField()).isEqualTo(-1234567890L);
+        assertThat(atom.getFloatField()).isEqualTo(42.01f);
+        assertThat(atom.getStringField()).isEqualTo("Test non chained");
+        assertThat(atom.getBooleanField()).isTrue();
+        assertThat(atom.getState().getNumber()).isEqualTo(
+                TestExtensionAtomReported.State.OFF_VALUE);
+        assertThat(atom.getBytesField().getLongFieldList())
+                .containsExactly(1L, 2L, 3L).inOrder();
+        assertThat(atom.getRepeatedIntFieldList()).isEmpty();
+        assertThat(atom.getRepeatedLongFieldList()).isEmpty();
+        assertThat(atom.getRepeatedFloatFieldList()).isEmpty();
+        assertThat(atom.getRepeatedStringFieldList()).isEmpty();
+        assertThat(atom.getRepeatedBooleanFieldList()).isEmpty();
+        assertThat(atom.getRepeatedEnumFieldList()).isEmpty();
+
+        atom = data.get(3).getAtom().getExtension(
+            StatsdExtensionAtoms.testExtensionAtomReported);
+        attrChain = atom.getAttributionNodeList();
+        assertThat(attrChain).hasSize(1);
+        assertThat(attrChain.get(0).getUid()).isEqualTo(
+                DeviceUtils.getAppUid(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE));
+        assertThat(attrChain.get(0).getTag()).isEmpty();
+
+        assertThat(atom.getIntField()).isEqualTo(0);
+        assertThat(atom.getLongField()).isEqualTo(0L);
+        assertThat(atom.getFloatField()).isEqualTo(0f);
+        assertThat(atom.getStringField()).isEmpty();
+        assertThat(atom.getBooleanField()).isTrue();
+        assertThat(atom.getState().getNumber()).isEqualTo(
+                TestExtensionAtomReported.State.OFF_VALUE);
+        assertThat(atom.getBytesField().getLongFieldList()).isEmpty();
+        assertThat(atom.getRepeatedIntFieldList()).isEmpty();
+        assertThat(atom.getRepeatedLongFieldList()).isEmpty();
+        assertThat(atom.getRepeatedFloatFieldList()).isEmpty();
+        assertThat(atom.getRepeatedStringFieldList()).isEmpty();
+        assertThat(atom.getRepeatedBooleanFieldList()).isEmpty();
+        assertThat(atom.getRepeatedEnumFieldList()).isEmpty();
+    }
+
+    public void testWriteRawTestAtom() throws Exception {
+        final int atomTag = Atom.TEST_ATOM_REPORTED_FIELD_NUMBER;
+        ConfigUtils.uploadConfigForPushedAtomWithUid(getDevice(),
+                MetricsUtils.DEVICE_SIDE_TEST_PACKAGE, atomTag, /*useUidAttributionChain=*/true);
+
+        DeviceUtils.runDeviceTests(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE,
+                ".AtomTests", "testWriteRawTestAtom");
+
+        RunUtil.getDefault().sleep(AtomTestUtils.WAIT_TIME_SHORT);
+        // Sorted list of events in order in which they occurred.
+        List<EventMetricData> data = ReportUtils.getEventMetricDataList(getDevice());
+        assertThat(data).hasSize(4);
+
+        TestAtomReported atom = data.get(0).getAtom().getTestAtomReported();
+        List<AttributionNode> attrChain = atom.getAttributionNodeList();
+        assertThat(attrChain).hasSize(2);
+        assertThat(attrChain.get(0).getUid()).isEqualTo(1234);
+        assertThat(attrChain.get(0).getTag()).isEqualTo("tag1");
+        assertThat(attrChain.get(1).getUid()).isEqualTo(
+                DeviceUtils.getAppUid(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE));
+        assertThat(attrChain.get(1).getTag()).isEqualTo("tag2");
+
+        assertThat(atom.getIntField()).isEqualTo(42);
+        assertThat(atom.getLongField()).isEqualTo(Long.MAX_VALUE);
+        assertThat(atom.getFloatField()).isEqualTo(3.14f);
+        assertThat(atom.getStringField()).isEqualTo("This is a basic test!");
+        assertThat(atom.getBooleanField()).isFalse();
+        assertThat(atom.getState().getNumber()).isEqualTo(TestAtomReported.State.ON_VALUE);
+        assertThat(atom.getBytesField().getExperimentIdList())
+                .containsExactly(1L, 2L, 3L).inOrder();
+
+        assertThat(atom.getRepeatedIntFieldList()).containsExactly(3, 6).inOrder();
+        assertThat(atom.getRepeatedLongFieldList()).containsExactly(1000L, 1002L).inOrder();
+        assertThat(atom.getRepeatedFloatFieldList()).containsExactly(0.3f, 0.09f).inOrder();
+        assertThat(atom.getRepeatedStringFieldList()).containsExactly("str1", "str2").inOrder();
+        assertThat(atom.getRepeatedBooleanFieldList()).containsExactly(true, false).inOrder();
+        assertThat(atom.getRepeatedEnumFieldList())
+                .containsExactly(TestAtomReported.State.OFF, TestAtomReported.State.ON)
+                .inOrder();
+
+        atom = data.get(1).getAtom().getTestAtomReported();
+        attrChain = atom.getAttributionNodeList();
+        assertThat(attrChain).hasSize(2);
+        assertThat(attrChain.get(0).getUid()).isEqualTo(9999);
+        assertThat(attrChain.get(0).getTag()).isEqualTo("tag9999");
+        assertThat(attrChain.get(1).getUid()).isEqualTo(
+                DeviceUtils.getAppUid(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE));
+        assertThat(attrChain.get(1).getTag()).isEmpty();
+
+        assertThat(atom.getIntField()).isEqualTo(100);
+        assertThat(atom.getLongField()).isEqualTo(Long.MIN_VALUE);
+        assertThat(atom.getFloatField()).isEqualTo(-2.5f);
+        assertThat(atom.getStringField()).isEqualTo("Test null uid");
+        assertThat(atom.getBooleanField()).isTrue();
+        assertThat(atom.getState().getNumber()).isEqualTo(TestAtomReported.State.UNKNOWN_VALUE);
+        assertThat(atom.getBytesField().getExperimentIdList())
+                .containsExactly(1L, 2L, 3L).inOrder();
+
+        assertThat(atom.getRepeatedIntFieldList()).containsExactly(3, 6).inOrder();
+        assertThat(atom.getRepeatedLongFieldList()).containsExactly(1000L, 1002L).inOrder();
+        assertThat(atom.getRepeatedFloatFieldList()).containsExactly(0.3f, 0.09f).inOrder();
+        assertThat(atom.getRepeatedStringFieldList()).containsExactly("str1", "str2").inOrder();
+        assertThat(atom.getRepeatedBooleanFieldList()).containsExactly(true, false).inOrder();
+        assertThat(atom.getRepeatedEnumFieldList())
+                .containsExactly(TestAtomReported.State.OFF, TestAtomReported.State.ON)
+                .inOrder();
+
+        atom = data.get(2).getAtom().getTestAtomReported();
+        attrChain = atom.getAttributionNodeList();
+        assertThat(attrChain).hasSize(1);
+        assertThat(attrChain.get(0).getUid()).isEqualTo(
+                DeviceUtils.getAppUid(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE));
+        assertThat(attrChain.get(0).getTag()).isEqualTo("tag1");
+
+        assertThat(atom.getIntField()).isEqualTo(-256);
+        assertThat(atom.getLongField()).isEqualTo(-1234567890L);
+        assertThat(atom.getFloatField()).isEqualTo(42.01f);
+        assertThat(atom.getStringField()).isEqualTo("Test non chained");
+        assertThat(atom.getBooleanField()).isTrue();
+        assertThat(atom.getState().getNumber()).isEqualTo(TestAtomReported.State.OFF_VALUE);
+        assertThat(atom.getBytesField().getExperimentIdList())
+                .containsExactly(1L, 2L, 3L).inOrder();
+
+        assertThat(atom.getRepeatedIntFieldList()).isEmpty();
+        assertThat(atom.getRepeatedLongFieldList()).isEmpty();
+        assertThat(atom.getRepeatedFloatFieldList()).isEmpty();
+        assertThat(atom.getRepeatedStringFieldList()).isEmpty();
+        assertThat(atom.getRepeatedBooleanFieldList()).isEmpty();
+        assertThat(atom.getRepeatedEnumFieldList()).isEmpty();
+
+        atom = data.get(3).getAtom().getTestAtomReported();
+        attrChain = atom.getAttributionNodeList();
+        assertThat(attrChain).hasSize(1);
+        assertThat(attrChain.get(0).getUid()).isEqualTo(
+                DeviceUtils.getAppUid(getDevice(), MetricsUtils.DEVICE_SIDE_TEST_PACKAGE));
+        assertThat(attrChain.get(0).getTag()).isEmpty();
+
+        assertThat(atom.getIntField()).isEqualTo(0);
+        assertThat(atom.getLongField()).isEqualTo(0L);
+        assertThat(atom.getFloatField()).isEqualTo(0f);
+        assertThat(atom.getStringField()).isEmpty();
+        assertThat(atom.getBooleanField()).isTrue();
+        assertThat(atom.getState().getNumber()).isEqualTo(TestAtomReported.State.OFF_VALUE);
+        assertThat(atom.getBytesField().getExperimentIdList()).isEmpty();
+
+        assertThat(atom.getRepeatedIntFieldList()).isEmpty();
+        assertThat(atom.getRepeatedLongFieldList()).isEmpty();
+        assertThat(atom.getRepeatedFloatFieldList()).isEmpty();
+        assertThat(atom.getRepeatedStringFieldList()).isEmpty();
+        assertThat(atom.getRepeatedBooleanFieldList()).isEmpty();
+        assertThat(atom.getRepeatedEnumFieldList()).isEmpty();
+    }
+}
```

