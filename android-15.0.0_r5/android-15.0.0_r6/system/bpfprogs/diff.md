```diff
diff --git a/Android.bp b/Android.bp
index c775063..0b4af16 100644
--- a/Android.bp
+++ b/Android.bp
@@ -30,11 +30,6 @@ license {
 bpf {
     name: "timeInState.o",
     srcs: ["timeInState.c"],
-    btf: true,
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
     include_dirs: [
         "system/bpf/progs/include",
     ],
@@ -83,10 +78,6 @@ cc_test {
 bpf {
     name: "fuseMedia.o",
     srcs: ["fuseMedia.c"],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
     include_dirs: [
         "external/libfuse/include",
     ],
diff --git a/test/Android.bp b/test/Android.bp
index 8e32cdd..919440e 100644
--- a/test/Android.bp
+++ b/test/Android.bp
@@ -21,20 +21,6 @@ package {
 bpf {
     name: "bpfLoadTpProg.o",
     srcs: ["bpfLoadTpProg.c"],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
-}
-
-bpf {
-    name: "bpfLoadTpProgBtf.o",
-    srcs: ["bpfLoadTpProgBtf.c"],
-    btf: true,
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
 }
 
 cc_library {
diff --git a/test/bpfLoadTpProg.c b/test/bpfLoadTpProg.c
index 1d0ff85..7462552 100644
--- a/test/bpfLoadTpProg.c
+++ b/test/bpfLoadTpProg.c
@@ -56,7 +56,7 @@ struct wakeup_args {
 };
 
 DEFINE_BPF_PROG_KVER("tracepoint/sched/sched_wakeup", AID_ROOT, AID_ROOT, tp_sched_wakeup, KVER_INF)
-(struct wakeup_args* args) {
+(struct wakeup_args* __unused args) {
     return 0;
 }
 
diff --git a/test/bpfLoadTpProgBtf.c b/test/bpfLoadTpProgBtf.c
deleted file mode 120000
index 5884344..0000000
--- a/test/bpfLoadTpProgBtf.c
+++ /dev/null
@@ -1 +0,0 @@
-bpfLoadTpProg.c
\ No newline at end of file
diff --git a/timeInState.c b/timeInState.c
index 7c09736..85dda97 100644
--- a/timeInState.c
+++ b/timeInState.c
@@ -21,6 +21,7 @@
 #endif
 
 #include <bpf_timeinstate.h>
+#include <errno.h>
 
 DEFINE_BPF_MAP_GRW(total_time_in_state_map, PERCPU_ARRAY, uint32_t, uint64_t, MAX_FREQS_FOR_TOTAL,
                    AID_SYSTEM)
@@ -155,7 +156,16 @@ DEFINE_BPF_PROG("tracepoint/sched/sched_switch", AID_ROOT, AID_SYSTEM, tp_sched_
     // freq_to_idx_map uses 1 as its minimum index so that *freq_idxp == 0 only when uninitialized
     uint8_t freq_idx = *freq_idxp - 1;
 
-    uint32_t uid = bpf_get_current_uid_gid();
+    // The bpf_get_current_uid_gid() helper function returns a u64 value, with the lower 32 bits
+    // containing the UID and the upper 32 bits containing the GID. Additionally, in rare cases,
+    // (usually something is very wrong with the kernel) the helper can return -EINVAL, in which
+    // case we should just return early.
+    unsigned long long uid_gid = bpf_get_current_uid_gid();
+    if (uid_gid == (unsigned long long)(-EINVAL)) return ALLOW;
+
+    // Mask out the uid part of the uid_gid value returned from the kernel.
+    uint32_t uid = uid_gid & 0xFFFFFFFF;
+
     uint64_t delta = time - old_last;
 
     // For UIDs in the SDK sandbox range, we account per-UID times twice, both to the corresponding
diff --git a/time_in_state_test.cpp b/time_in_state_test.cpp
index 1042221..2408501 100644
--- a/time_in_state_test.cpp
+++ b/time_in_state_test.cpp
@@ -91,7 +91,7 @@ static void initCpuPolicy(uint32_t policy, std::vector<uint32_t> cpuIds,
 }
 
 static void noteCpuFrequencyChange(uint32_t cpuId, uint32_t frequency) {
-    cpufreq_args args{.cpu_id = cpuId, .state = frequency};
+    cpufreq_args args{.state = frequency, .cpu_id = cpuId};
     int ret = tp_cpufreq(&args);  // Tracepoint event power/cpu_frequency
     ASSERT_EQ(1, ret);
 }
```

