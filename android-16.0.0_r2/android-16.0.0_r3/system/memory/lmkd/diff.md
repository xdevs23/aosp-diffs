```diff
diff --git a/Android.bp b/Android.bp
index ec0be49..a4f0f84 100644
--- a/Android.bp
+++ b/Android.bp
@@ -63,7 +63,6 @@ cc_binary {
         "-Wall",
         "-Werror",
         "-Wextra",
-        "-DLMKD_TRACE_KILLS",
     ],
     init_rc: ["lmkd.rc"],
     defaults: [
diff --git a/README.md b/README.md
index d140016..bf54340 100644
--- a/README.md
+++ b/README.md
@@ -60,7 +60,8 @@ properties:
                                  any eligible task (fast decision). Default = false
 
   - `ro.lmk.kill_timeout_ms`:    duration in ms after a kill when no additional
-                                 kill will be done. Default = 100
+                                 kill will be done. Setting to 0 means an infinite
+                                 timeout. Default = 100
 
   - `ro.lmk.debug`:              enable lmkd debug logs, Default = false
 
diff --git a/lmkd.cpp b/lmkd.cpp
index 3cb458d..88dfc84 100644
--- a/lmkd.cpp
+++ b/lmkd.cpp
@@ -41,6 +41,7 @@
 #include <vector>
 
 #include <BpfSyscallWrappers.h>
+#include <android-base/stringify.h>
 #include <android-base/unique_fd.h>
 #include <bpf/WaitForProgsLoaded.h>
 #include <cutils/properties.h>
@@ -60,30 +61,9 @@
 #include "statslog.h"
 #include "watchdog.h"
 
-/*
- * Define LMKD_TRACE_KILLS to record lmkd kills in kernel traces
- * to profile and correlate with OOM kills
- */
-#ifdef LMKD_TRACE_KILLS
-
 #define ATRACE_TAG ATRACE_TAG_ALWAYS
 #include <cutils/trace.h>
 
-static inline void trace_kill_start(const char *desc) {
-    ATRACE_BEGIN(desc);
-}
-
-static inline void trace_kill_end() {
-    ATRACE_END();
-}
-
-#else /* LMKD_TRACE_KILLS */
-
-static inline void trace_kill_start(const char *) {}
-static inline void trace_kill_end() {}
-
-#endif /* LMKD_TRACE_KILLS */
-
 #ifndef __unused
 #define __unused __attribute__((__unused__))
 #endif
@@ -117,9 +97,6 @@ static inline void trace_kill_end() {}
 /* Defined as ProcessList.SYSTEM_ADJ in ProcessList.java */
 #define SYSTEM_ADJ (-900)
 
-#define STRINGIFY(x) STRINGIFY_INTERNAL(x)
-#define STRINGIFY_INTERNAL(x) #x
-
 #define PROCFS_PATH_MAX 64
 
 /*
@@ -583,7 +560,7 @@ static long page_k; /* page size in kB */
 static bool update_props();
 static bool init_monitors();
 static void destroy_monitors();
-static bool init_memevent_listener_monitoring();
+static void init_memevent();
 
 static int clamp(int low, int high, int value) {
     return std::max(std::min(value, high), low);
@@ -1629,15 +1606,7 @@ static void ctrl_command_handler(int dsock_idx) {
              * Initialize the memevent listener after boot is completed to prevent
              * waiting, during boot-up, for BPF programs to be loaded.
              */
-            if (init_memevent_listener_monitoring()) {
-                ALOGI("Using memevents for direct reclaim and kswapd detection");
-            } else {
-                ALOGI("Using vmstats for direct reclaim and kswapd detection");
-                if (direct_reclaim_threshold_ms > 0) {
-                    ALOGW("Kernel support for direct_reclaim_threshold_ms is not found");
-                    direct_reclaim_threshold_ms = 0;
-                }
-            }
+            init_memevent();
             result = 0;
             boot_completed_handled = true;
         }
@@ -2476,21 +2445,16 @@ static int kill_one_process(struct proc* procp, int min_oom_score, struct kill_i
       ALOGI("Skipping kill; %ld kB freed elsewhere.", result * page_k);
       return result;
     }
-
-    trace_kill_start(desc);
-
     start_wait_for_proc_kill(pidfd < 0 ? pid : pidfd);
     kill_result = reaper.kill({ pidfd, pid, uid }, false);
 
-    trace_kill_end();
-
     if (kill_result) {
         stop_wait_for_proc_kill(false);
         ALOGE("kill(%d): errno=%d", pid, errno);
         /* Delete process record even when we fail to kill so that we don't get stuck on it */
         goto out;
     }
-
+    ATRACE_INSTANT_FOR_TRACK(LOG_TAG, desc);
     last_kill_tm = *tm;
 
     inc_killcnt(procp->oomadj);
@@ -2731,6 +2695,7 @@ static void __mp_event_psi(enum event_source source, union psi_event_data data,
     static int64_t prev_thrash_growth = 0;
     static bool check_filecache = false;
     static int max_thrashing = 0;
+    static bool initialized = false;
 
     union meminfo mi;
     union vmstat vs;
@@ -2812,15 +2777,18 @@ static void __mp_event_psi(enum event_source source, union psi_event_data data,
         return;
     }
 
-    /* Reset states after process got killed */
-    if (killing) {
-        killing = false;
-        cycle_after_kill = true;
+    /* Initialize states the first time we get here and reset after a kill */
+    if (!initialized || killing) {
+        if (killing) {
+            killing = false;
+            cycle_after_kill = true;
+        }
         /* Reset file-backed pagecache size and refault amounts after a kill */
         base_file_lru = vs.field.nr_inactive_file + vs.field.nr_active_file;
         init_ws_refault = workingset_refault_file;
         thrashing_reset_tm = curr_tm;
         prev_thrash_growth = 0;
+        initialized = true;
     }
 
     /* Check free swap levels */
@@ -2887,7 +2855,17 @@ static void __mp_event_psi(enum event_source source, union psi_event_data data,
          * counter in that case to ensure a kill if a new eligible process appears.
          */
         if (windows_passed > 1 || prev_thrash_growth < thrashing_limit) {
-            prev_thrash_growth >>= windows_passed;
+            if (static_cast<size_t>(windows_passed) < 8 * sizeof(prev_thrash_growth)) {
+                prev_thrash_growth >>= windows_passed;
+            } else {
+                /*
+                 * Reset to 0 explicitly if windows_passed is too large. Shifting by a value
+                 * greater than or equal to the size of the left operand is undefined behavior,
+                 * and in practice (for example, ASR instruction on Arm) only the lowest 6 bits
+                 * are used, which can produce incorrect results.
+                 */
+                prev_thrash_growth = 0;
+            }
         }
 
         /* Record file-backed pagecache size when crossing THRASHING_RESET_INTERVAL_MS */
@@ -3042,7 +3020,7 @@ update_watermarks:
     }
 
     /* Check if a cached app should be killed */
-    if (kill_reason == NONE && wmark < WMARK_HIGH) {
+    if (kill_reason == NONE && wmark < WMARK_HIGH && lowmem_min_oom_score <= OOM_SCORE_ADJ_MAX) {
         kill_reason = LOW_MEM;
         snprintf(kill_desc, sizeof(kill_desc), "%s watermark is breached",
             wmark < WMARK_LOW ? "min" : "low");
@@ -3191,7 +3169,7 @@ static void mp_event_common(int data, uint32_t events, struct polling_params *po
 
     record_wakeup_time(&curr_tm, events ? Event : Polling, &wi);
 
-    if (kill_timeout_ms &&
+    if (kill_timeout_ms == 0 ||
         get_time_diff_ms(&last_kill_tm, &curr_tm) < static_cast<long>(kill_timeout_ms)) {
         /*
          * If we're within the no-kill timeout, see if there's pending reclaim work
@@ -3558,6 +3536,18 @@ static bool init_memevent_listener_monitoring() {
     return true;
 }
 
+static void init_memevent() {
+    if (init_memevent_listener_monitoring()) {
+        ALOGI("Using memevents for direct reclaim and kswapd detection");
+    } else {
+        ALOGI("Using vmstats for direct reclaim and kswapd detection");
+        if (direct_reclaim_threshold_ms > 0) {
+            ALOGW("Kernel support for direct_reclaim_threshold_ms is not found");
+            direct_reclaim_threshold_ms = 0;
+        }
+    }
+}
+
 static bool init_psi_monitors() {
     /*
      * When PSI is used on low-ram devices or on high-end devices without memfree levels
@@ -3892,6 +3882,14 @@ static int init(void) {
         return -1;
     }
 
+    /*
+     * If boot is already complete (e.g., due to an LMKD crash
+     * and restart), initialize the memevent listener now.
+     */
+    if (property_get_bool("sys.boot_completed", false)) {
+        init_memevent();
+    }
+
     return 0;
 }
 
diff --git a/statslog.cpp b/statslog.cpp
index ccba857..51c8c9b 100644
--- a/statslog.cpp
+++ b/statslog.cpp
@@ -32,14 +32,12 @@
 
 #include <string>
 
+#include <android-base/stringify.h>
 #include <lmkd.h>
 #include <processgroup/processgroup.h>
 
 #ifdef LMKD_LOG_STATS
 
-#define STRINGIFY(x) STRINGIFY_INTERNAL(x)
-#define STRINGIFY_INTERNAL(x) #x
-
 /**
  * Used to make sure that the payload is always smaller than LMKD_REPLY_MAX_SIZE
  */
@@ -72,7 +70,9 @@ static void memory_stat_parse_line(const char* line, struct memory_stat* mem_st)
     char key[MAX_TASKNAME_LEN + 1];
     int64_t value;
 
-    sscanf(line, "%" STRINGIFY(MAX_TASKNAME_LEN) "s  %" SCNd64 "", key, &value);
+    if (sscanf(line, "%" STRINGIFY(MAX_TASKNAME_LEN) "s  %" SCNd64 "", key, &value) != 2) {
+        return;
+    }
 
     if (strcmp(key, "total_") < 0) {
         return;
diff --git a/statslog.h b/statslog.h
index 4c51f70..fb0dc4a 100644
--- a/statslog.h
+++ b/statslog.h
@@ -36,13 +36,16 @@ __BEGIN_DECLS
  * Max LMKD reply packet length in bytes
  * Notes about size calculation:
  * 4 bytes for packet type
- * 88 bytes for the LmkKillOccurred fields: memory_stat + kill_stat
+ * 80 bytes for the LmkKillOccurred fields: memory_stat + kill_stat (note that
+ *     two of kill_stat's 64-bit fields are encoded as 32-bit fields).
  * 2 bytes for process name string size
  * MAX_TASKNAME_LEN bytes for the process name string
  *
- * Must be in sync with LmkdConnection.java
+ * Must be in sync with:
+ * - LMKD_REPLY_MAX_SIZE in LmkdConnection.java
+ * - KILL_OCCURRED_MSG_SIZE in LmkdStatsReporter.java
  */
-#define LMKD_REPLY_MAX_SIZE 222
+#define LMKD_REPLY_MAX_SIZE 214
 
 /* LMK_MEMORY_STATS packet payload */
 struct memory_stat {
diff --git a/tests/lmkd_tests.cpp b/tests/lmkd_tests.cpp
index 28ee35f..2b1aa0e 100644
--- a/tests/lmkd_tests.cpp
+++ b/tests/lmkd_tests.cpp
@@ -43,6 +43,8 @@ using namespace android::base;
 #define LMKD_REAP_TIME_TEMPLATE LMKD_LOGCAT_MARKER ": Process %d was reaped in %ldms"
 #define LMKD_REAP_MRELESE_ERR_MARKER ": process_mrelease"
 #define LMKD_REAP_NO_PROCESS_TEMPLATE ": process_mrelease %d failed: No such process"
+#define LMKD_OOM_KILL_MARKER "oom-killer"
+#define LMKD_OOM_KILL_LINE "lmkd_tests invoked oom-killer"
 
 #define ONE_MB (1 << 20)
 
@@ -140,6 +142,12 @@ class LmkdTest : public ::testing::Test {
         return ExecCommand(cmd);
     }
 
+    static std::string ReadKernelLogcat(const std::string& regex) {
+        std::string cmd = "logcat -d -b kernel";
+        cmd += " -e \"" + regex + "\"";
+        return ExecCommand(cmd);
+    }
+
     static size_t ConsumeMemory(size_t total_size, size_t step_size, size_t step_delay) {
         volatile void* ptr;
         size_t allocated_size = 0;
@@ -216,7 +224,13 @@ TEST_F(LmkdTest, TargetReaping) {
 
     // find kill report
     size_t line_start = logcat_out.find(LMKD_KILL_LINE_START);
-    ASSERT_TRUE(line_start != std::string::npos) << "Kill report is not found";
+    if (line_start == std::string::npos) {
+        // no kill report, test might have been killed by the OOM killer
+        if (ReadKernelLogcat(LMKD_OOM_KILL_MARKER).find(LMKD_OOM_KILL_LINE) != std::string::npos) {
+            return;
+        }
+        FAIL() << "Kill report is not found";
+    }
     size_t line_end = logcat_out.find('\n', line_start);
     std::string line = logcat_out.substr(
             line_start, line_end == std::string::npos ? std::string::npos : line_end - line_start);
```

