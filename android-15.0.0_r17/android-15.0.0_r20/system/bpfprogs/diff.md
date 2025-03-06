```diff
diff --git a/Android.bp b/Android.bp
index 0b4af16..426ce24 100644
--- a/Android.bp
+++ b/Android.bp
@@ -32,47 +32,18 @@ bpf {
     srcs: ["timeInState.c"],
     include_dirs: [
         "system/bpf/progs/include",
+        "system/bpf/include/defs",
     ],
 }
 
-cc_library {
-    name: "lib_mock_bpf_time_in_state",
+libbpf_prog {
+    name: "timeInState.bpf",
     srcs: ["timeInState.c"],
-    header_libs: ["bpf_prog_headers"],
-    cflags: [
-        "-Wall",
-        "-Werror",
-        "-DMOCK_BPF",
+    header_libs: [
+        "bpf_prog_headers",
+        "libcutils_headers",
+        "android_bpf_defs",
     ],
-    static_libs: [
-        "lib_mock_bpf",
-    ],
-}
-
-cc_test {
-    name: "bpf-time-in-state-tests",
-    test_suites: ["general-tests"],
-    gtest: true,
-    isolated: false,
-    host_supported: false,
-    srcs: [
-        "time_in_state_test.cpp",
-    ],
-    header_libs: ["bpf_prog_headers"],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
-    whole_static_libs: [
-        "lib_mock_bpf_time_in_state",
-    ],
-    static_libs: [
-        "libgtest_isolated",
-        "lib_mock_bpf",
-    ],
-    static_executable: true,
-    stl: "libc++_static",
-    licenses: ["Android-Apache-2.0"],
 }
 
 bpf {
@@ -80,5 +51,6 @@ bpf {
     srcs: ["fuseMedia.c"],
     include_dirs: [
         "external/libfuse/include",
+        "system/bpf/include/defs",
     ],
 }
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 5553ece..e8415a5 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,8 +1,5 @@
 {
     "presubmit": [
-        {
-            "name": "bpf-time-in-state-tests"
-        },
         {
             "name": "libtimeinstate_test"
         }
diff --git a/fuseMedia.c b/fuseMedia.c
index 41d5406..cb1795d 100644
--- a/fuseMedia.c
+++ b/fuseMedia.c
@@ -14,19 +14,11 @@
  *
  */
 
-#include <bpf_helpers.h>
-
+#include <android_bpf_defs.h>
 #include <stdint.h>
-
 #define __KERNEL__
 #include <fuse_kernel.h>
 
-#define bpf_printk(fmt, ...)                                       \
-    ({                                                             \
-        char ____fmt[] = fmt;                                      \
-        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
-    })
-
 DEFINE_BPF_PROG("fuse/media", AID_ROOT, AID_MEDIA_RW, fuse_media)
 (struct fuse_bpf_args* fa) {
     switch (fa->opcode) {
diff --git a/test/Android.bp b/test/Android.bp
index 919440e..a524d5e 100644
--- a/test/Android.bp
+++ b/test/Android.bp
@@ -22,13 +22,3 @@ bpf {
     name: "bpfLoadTpProg.o",
     srcs: ["bpfLoadTpProg.c"],
 }
-
-cc_library {
-    name: "lib_mock_bpf",
-    srcs: ["mock_bpf.cpp"],
-    header_libs: ["bpf_prog_headers"],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
-}
diff --git a/test/mock_bpf.cpp b/test/mock_bpf.cpp
deleted file mode 100644
index 1197377..0000000
--- a/test/mock_bpf.cpp
+++ /dev/null
@@ -1,137 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#include <inttypes.h>
-#include <linux/bpf.h>
-#include <test/mock_bpf_helpers.h>
-#include <map>
-#include <unordered_map>
-#include <vector>
-
-struct ByteArrayHash {
-    std::size_t operator()(std::vector<uint8_t> const& bytes) const {
-        size_t result = 0;
-        for (size_t i = 0; i < bytes.size(); i++) {
-            result = (result * 31) ^ bytes[i];
-        }
-        return result;
-    }
-};
-
-typedef std::unordered_map<std::vector<uint8_t>, std::vector<uint8_t>, ByteArrayHash> byteArrayMap;
-
-struct mock_bpf_map {
-    uint32_t type;
-    size_t key_size;
-    size_t value_size;
-
-    // Per-CPU hash map.  Cross-CPU maps have just one key-value pair, the key being 0.
-    std::map<uint32_t, byteArrayMap> map;
-};
-
-static uint64_t gKtimeNs;
-static uint32_t gSmpProcessorId;
-static uint32_t gUid;
-static uint32_t gPidTgid;
-
-uint64_t bpf_ktime_get_ns() {
-    return gKtimeNs;
-}
-
-void mock_bpf_set_ktime_ns(uint64_t time_ns) {
-    gKtimeNs = time_ns;
-}
-
-void mock_bpf_set_smp_processor_id(uint32_t cpu) {
-    gSmpProcessorId = cpu;
-}
-
-uint64_t bpf_get_smp_processor_id() {
-    return gSmpProcessorId;
-}
-
-void mock_bpf_set_current_uid_gid(uint32_t uid) {
-    gUid = uid;
-}
-
-uint64_t bpf_get_current_uid_gid() {
-    return gUid;
-}
-
-void mock_bpf_set_current_pid_tgid(uint64_t pid_tgid) {
-    gPidTgid = pid_tgid;
-}
-
-uint64_t bpf_get_current_pid_tgid() {
-    return gPidTgid;
-}
-
-mock_bpf_map_t mock_bpf_map_create(uint32_t key_size, uint32_t value_size, uint32_t type) {
-    mock_bpf_map* map = new mock_bpf_map();
-    map->type = type;
-    map->key_size = key_size;
-    map->value_size = value_size;
-    return map;
-}
-
-static byteArrayMap& getCurrentMap(mock_bpf_map* map) {
-    if (map->type == BPF_MAP_TYPE_PERCPU_HASH || map->type == BPF_MAP_TYPE_PERCPU_ARRAY) {
-        return map->map[gSmpProcessorId];
-    } else {
-        return map->map[0];
-    }
-}
-
-void* mock_bpf_lookup_elem(mock_bpf_map_t mock_map, void* key) {
-    mock_bpf_map* map = (mock_bpf_map*)mock_map;
-    std::vector<uint8_t> keyVector(map->key_size);
-    memcpy(keyVector.data(), key, map->key_size);
-    byteArrayMap& currentMap = getCurrentMap(map);
-    if (currentMap.find(keyVector) == currentMap.end()) {
-        return NULL;
-    }
-    return currentMap[keyVector].data();
-}
-
-int mock_bpf_update_elem(mock_bpf_map_t mock_map, void* key, void* value, uint64_t flags) {
-    mock_bpf_map* map = (mock_bpf_map*)mock_map;
-    std::vector<uint8_t> keyVector(map->key_size);
-    memcpy(keyVector.data(), key, map->key_size);
-    std::vector<uint8_t> value_vector(map->value_size);
-    memcpy(value_vector.data(), value, map->value_size);
-
-    byteArrayMap& currentMap = getCurrentMap(map);
-    if (flags & BPF_EXIST) {
-        if (currentMap.find(keyVector) == currentMap.end()) {
-            return 0;
-        }
-    } else if (flags & BPF_NOEXIST) {
-        if (currentMap.find(keyVector) != currentMap.end()) {
-            return 0;
-        }
-    }
-    currentMap[keyVector] = value_vector;
-    return 1;
-}
-
-int mock_bpf_delete_elem(mock_bpf_map_t mock_map, void* key) {
-    mock_bpf_map* map = (mock_bpf_map*)mock_map;
-    std::vector<uint8_t> keyVector(map->key_size);
-    memcpy(keyVector.data(), key, map->key_size);
-
-    byteArrayMap& currentMap = getCurrentMap(map);
-    return currentMap.erase(keyVector);
-}
diff --git a/timeInState.c b/timeInState.c
index 85dda97..f72aa02 100644
--- a/timeInState.c
+++ b/timeInState.c
@@ -14,15 +14,16 @@
  *
  */
 
-#ifdef MOCK_BPF
-#include <test/mock_bpf_helpers.h>
-#else
-#include <bpf_helpers.h>
-#endif
-
+#include <android_bpf_defs.h>
 #include <bpf_timeinstate.h>
 #include <errno.h>
 
+#ifdef ENABLE_LIBBPF
+#include <linux/bpf.h>
+#include <private/android_filesystem_config.h>
+#include <stdbool.h>
+#endif  // ENABLE_LIBBPF
+
 DEFINE_BPF_MAP_GRW(total_time_in_state_map, PERCPU_ARRAY, uint32_t, uint64_t, MAX_FREQS_FOR_TOTAL,
                    AID_SYSTEM)
 
@@ -100,7 +101,8 @@ static inline __always_inline void update_uid(uint32_t uid, uint64_t delta, uint
     return;
 }
 
-DEFINE_BPF_PROG("tracepoint/sched/sched_switch", AID_ROOT, AID_SYSTEM, tp_sched_switch)
+DEFINE_BPF_PROG("tracepoint/sched/sched_switch", AID_ROOT, AID_SYSTEM,
+                tracepoint_sched_sched_switch)
 (struct switch_args* args) {
     const int ALLOW = 1;  // return 1 to avoid blocking simpleperf from receiving events.
     uint32_t zero = 0;
@@ -234,7 +236,8 @@ struct cpufreq_args {
     unsigned int cpu_id;
 };
 
-DEFINE_BPF_PROG("tracepoint/power/cpu_frequency", AID_ROOT, AID_SYSTEM, tp_cpufreq)
+DEFINE_BPF_PROG("tracepoint/power/cpu_frequency", AID_ROOT, AID_SYSTEM,
+                tracepoint_power_cpu_frequency)
 (struct cpufreq_args* args) {
     const int ALLOW = 1;  // return 1 to avoid blocking simpleperf from receiving events.
     uint32_t cpu = args->cpu_id;
@@ -259,7 +262,8 @@ struct sched_process_free_args {
     int prio;
 };
 
-DEFINE_BPF_PROG("tracepoint/sched/sched_process_free", AID_ROOT, AID_SYSTEM, tp_sched_process_free)
+DEFINE_BPF_PROG("tracepoint/sched/sched_process_free", AID_ROOT, AID_SYSTEM,
+                tracepoint_sched_sched_process_free)
 (struct sched_process_free_args* args) {
     const int ALLOW = 1;
 
diff --git a/time_in_state_test.cpp b/time_in_state_test.cpp
deleted file mode 100644
index 2408501..0000000
--- a/time_in_state_test.cpp
+++ /dev/null
@@ -1,266 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
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
-#include <bpf_timeinstate.h>
-#include <gtest/gtest.h>
-#include <test/mock_bpf_helpers.h>
-
-extern "C" {
-
-uint64_t* bpf_cpu_last_update_map_lookup_elem(uint32_t* zero);
-uint64_t* bpf_uid_last_update_map_lookup_elem(uint32_t* uid);
-int bpf_cpu_last_update_map_update_elem(uint32_t* zero, uint64_t* time, uint64_t flags);
-int bpf_nr_active_map_update_elem(uint32_t* zero, uint32_t* time, uint64_t flags);
-int bpf_cpu_policy_map_update_elem(uint32_t* zero, uint32_t* time, uint64_t flags);
-int bpf_policy_freq_idx_map_update_elem(uint32_t* policy, uint8_t* index, uint64_t flags);
-int bpf_policy_nr_active_map_update_elem(uint32_t* policy, uint32_t* active, uint64_t flags);
-uint8_t* bpf_policy_freq_idx_map_lookup_elem(uint32_t* policy);
-int bpf_policy_freq_idx_map_update_elem(uint32_t* policy, uint8_t* index, uint64_t flags);
-int bpf_freq_to_idx_map_update_elem(freq_idx_key_t* freq_idx_key, uint8_t* index, uint64_t flags);
-tis_val_t* bpf_uid_time_in_state_map_lookup_elem(time_key_t* key);
-concurrent_val_t* bpf_uid_concurrent_times_map_lookup_elem(time_key_t* key);
-int bpf_cpu_last_pid_map_update_elem(uint32_t* zero, pid_t* pid, uint64_t flags);
-
-struct switch_args {
-    unsigned long long ignore;
-    char prev_comm[16];
-    int prev_pid;
-    int prev_prio;
-    long long prev_state;
-    char next_comm[16];
-    int next_pid;
-    int next_prio;
-};
-
-int tp_sched_switch(struct switch_args* args);
-
-struct cpufreq_args {
-    unsigned long long ignore;
-    unsigned int state;
-    unsigned int cpu_id;
-};
-
-int tp_cpufreq(struct cpufreq_args* args);
-
-}  // extern "C"
-
-static void enableTracking() {
-    uint32_t zero = 0;
-    bpf_nr_active_map_update_elem(&zero, &zero, BPF_ANY);
-}
-
-// Defines a CPU cluster <policy> containing CPUs <cpu_ids> with available frequencies
-// <frequencies> and marks it as <active>
-static void initCpuPolicy(uint32_t policy, std::vector<uint32_t> cpuIds,
-                          std::vector<uint32_t> frequencies, bool active) {
-    for (uint32_t cpuId : cpuIds) {
-        bpf_cpu_policy_map_update_elem(&cpuId, &policy, BPF_ANY);
-
-        mock_bpf_set_smp_processor_id(cpuId);
-
-        // Initialize time - this must be done per-CPU
-        uint32_t zero = 0;
-        uint64_t time = 0;
-        bpf_cpu_last_update_map_update_elem(&zero, &time, BPF_ANY);
-
-        pid_t pid = 0;
-        bpf_cpu_last_pid_map_update_elem(&zero, &pid, BPF_ANY);
-    }
-    for (uint8_t i = 0; i < frequencies.size(); i++) {
-        uint8_t index = i + 1;  // Frequency indexes start with 1
-        freq_idx_key_t freqIdxKey{.policy = policy, .freq = frequencies[i]};
-        bpf_freq_to_idx_map_update_elem(&freqIdxKey, &index, BPF_ANY);
-    }
-    if (active) {
-        uint32_t zero = 0;
-        bpf_policy_nr_active_map_update_elem(&policy, &zero, BPF_ANY);
-    }
-}
-
-static void noteCpuFrequencyChange(uint32_t cpuId, uint32_t frequency) {
-    cpufreq_args args{.state = frequency, .cpu_id = cpuId};
-    int ret = tp_cpufreq(&args);  // Tracepoint event power/cpu_frequency
-    ASSERT_EQ(1, ret);
-}
-
-static void noteSchedSwitch(pid_t prevPid, pid_t nextPid) {
-    switch_args args{.prev_pid = prevPid, .next_pid = nextPid};
-    int ret = tp_sched_switch(&args);  // Tracepoint event sched/sched_switch
-    ASSERT_EQ(1, ret);
-}
-
-static void assertTimeInState(uint32_t uid, uint32_t bucket,
-                              std::vector<uint64_t> expectedTimeInState) {
-    time_key_t timeKey{.uid = uid, .bucket = bucket};
-    tis_val_t* value = bpf_uid_time_in_state_map_lookup_elem(&timeKey);
-    ASSERT_TRUE(value);
-
-    for (int i = 0; i < FREQS_PER_ENTRY; i++) {
-        if (i < expectedTimeInState.size()) {
-            ASSERT_EQ(expectedTimeInState[i], value->ar[i]);
-        } else {
-            ASSERT_EQ(0, value->ar[i]);
-        }
-    }
-}
-
-static void assertConcurrentTimes(uint32_t uid, uint32_t bucket,
-                                  std::vector<uint64_t> expectedPolicy,
-                                  std::vector<uint64_t> expectedActive) {
-    time_key_t timeKey{.uid = uid, .bucket = bucket};
-    concurrent_val_t* value = bpf_uid_concurrent_times_map_lookup_elem(&timeKey);
-    ASSERT_TRUE(value);
-
-    for (int i = 0; i < CPUS_PER_ENTRY; i++) {
-        if (i < expectedPolicy.size()) {
-            ASSERT_EQ(expectedPolicy[i], value->policy[i]);
-        } else {
-            ASSERT_EQ(0, value->policy[i]);
-        }
-    }
-
-    for (int i = 0; i < CPUS_PER_ENTRY; i++) {
-        if (i < expectedActive.size()) {
-            ASSERT_EQ(expectedActive[i], value->active[i]);
-        } else {
-            ASSERT_EQ(0, value->active[i]);
-        }
-    }
-}
-
-static void assertUidLastUpdateTime(uint32_t uid, uint64_t expectedTime) {
-    uint64_t* value = bpf_uid_last_update_map_lookup_elem(&uid);
-    ASSERT_TRUE(value);
-    ASSERT_EQ(expectedTime, *value);
-}
-
-TEST(time_in_state, tp_cpufreq) {
-    initCpuPolicy(0, {0, 1, 2}, {1000, 2000}, true);
-    initCpuPolicy(1, {3, 4}, {3000, 4000, 5000}, true);
-
-    noteCpuFrequencyChange(1, 2000);
-    {
-        uint32_t policy = 0;  // CPU 1 belongs to Cluster 0
-        uint8_t* freqIndex = bpf_policy_freq_idx_map_lookup_elem(&policy);
-        ASSERT_TRUE(freqIndex);
-        // Freq idx starts with 1. Cluster 0 is now running at the _second_ frequency
-        ASSERT_EQ(2, *freqIndex);
-    }
-
-    noteCpuFrequencyChange(4, 5000);
-    {
-        uint32_t policy = 1;  // CPU 4 belongs to Cluster 1
-        uint8_t* freqIndex = bpf_policy_freq_idx_map_lookup_elem(&policy);
-        ASSERT_TRUE(freqIndex);
-        // Freq idx starts with 1. Cluster 1 is now running at the _third_ frequency
-        ASSERT_EQ(3, *freqIndex);
-    }
-}
-
-TEST(time_in_state, tp_sched_switch) {
-    mock_bpf_set_ktime_ns(1000);
-    mock_bpf_set_current_uid_gid(42);
-
-    initCpuPolicy(0, {0, 1, 2}, {1000, 2000}, true);
-    initCpuPolicy(1, {3, 4}, {3000, 4000, 5000}, true);
-
-    enableTracking();
-
-    mock_bpf_set_smp_processor_id(2);
-
-    // First call is ignored, because there is no "delta" to be computed
-    noteSchedSwitch(0, 100);
-
-    noteCpuFrequencyChange(2, 1000);
-
-    mock_bpf_set_ktime_ns(1314);
-
-    noteSchedSwitch(100, 200);
-
-    // 1314 - 1000 = 314
-    assertTimeInState(42, 0, {314, 0});
-    assertConcurrentTimes(42, 0, {314, 0, 0, 0, 0}, {314, 0, 0, 0, 0});
-
-    mock_bpf_set_current_uid_gid(51);
-    mock_bpf_set_smp_processor_id(3);
-
-    // First call on this CPU is also ignored
-    noteSchedSwitch(200, 300);
-
-    mock_bpf_set_ktime_ns(2718);
-
-    noteCpuFrequencyChange(3, 5000);
-    noteSchedSwitch(300, 400);
-
-    mock_bpf_set_ktime_ns(5859);
-
-    noteCpuFrequencyChange(3, 4000);
-    noteSchedSwitch(400, 500);
-
-    assertTimeInState(51, 0, {0, 5859 - 2718, 2718 - 1314});
-
-    // (2718-1314)+(5859-2718) = 4545
-    assertConcurrentTimes(51, 0, {4545, 0, 0, 0, 0}, {0, 4545, 0, 0, 0});
-
-    assertUidLastUpdateTime(42, 1314);
-    assertUidLastUpdateTime(51, 5859);
-}
-
-TEST(time_in_state, tp_sched_switch_active_cpus) {
-    mock_bpf_set_ktime_ns(1000);
-    mock_bpf_set_current_uid_gid(42);
-
-    initCpuPolicy(0, {0}, {1000, 2000}, true);
-
-    enableTracking();
-
-    mock_bpf_set_smp_processor_id(0);
-
-    noteSchedSwitch(0, 1);
-
-    mock_bpf_set_ktime_ns(1100);
-
-    noteSchedSwitch(0, 1);
-
-    mock_bpf_set_ktime_ns(1200);
-
-    noteSchedSwitch(1, 2);
-
-    assertConcurrentTimes(42, 0, {100}, {100});
-}
-
-TEST(time_in_state, tp_sched_switch_sdk_sandbox) {
-    mock_bpf_set_ktime_ns(1000);
-    mock_bpf_set_current_uid_gid(AID_SDK_SANDBOX_PROCESS_START);
-
-    initCpuPolicy(0, {0}, {1000, 2000}, true);
-
-    enableTracking();
-
-    mock_bpf_set_smp_processor_id(0);
-
-    noteSchedSwitch(0, 1);
-
-    mock_bpf_set_ktime_ns(1100);
-
-    noteSchedSwitch(1, 2);
-
-    assertTimeInState(AID_APP_START, 0, {100, 0});
-    assertTimeInState(AID_SDK_SANDBOX, 0, {100, 0});
-
-    assertConcurrentTimes(AID_APP_START, 0, {100}, {100});
-    assertConcurrentTimes(AID_SDK_SANDBOX, 0, {100}, {100});
-}
```

