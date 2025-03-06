```diff
diff --git a/lmkd.cpp b/lmkd.cpp
index 1030147..54129c7 100644
--- a/lmkd.cpp
+++ b/lmkd.cpp
@@ -94,6 +94,7 @@ static inline void trace_kill_end() {}
 #define PROC_STATUS_TGID_FIELD "Tgid:"
 #define PROC_STATUS_RSS_FIELD "VmRSS:"
 #define PROC_STATUS_SWAP_FIELD "VmSwap:"
+#define NODE_STATS_MARKER "  per-node stats"
 
 #define PERCEPTIBLE_APP_ADJ 200
 #define PREVIOUS_APP_ADJ 700
@@ -210,6 +211,7 @@ static int mpevfd[VMPRESS_LEVEL_COUNT] = { -1, -1, -1 };
 static bool pidfd_supported;
 static int last_kill_pid_or_fd = -1;
 static struct timespec last_kill_tm;
+enum vmpressure_level prev_level = VMPRESS_LEVEL_LOW;
 static bool monitors_initialized;
 static bool boot_completed_handled = false;
 
@@ -245,6 +247,8 @@ static struct psi_threshold psi_thresholds[VMPRESS_LEVEL_COUNT] = {
     { PSI_FULL, 70 },    /* 70ms out of 1sec for complete stall */
 };
 
+static uint64_t mp_event_count;
+
 static android_log_context ctx;
 static Reaper reaper;
 static int reaper_comm_fd[2];
@@ -1859,6 +1863,15 @@ static int zoneinfo_parse(struct zoneinfo *zi) {
         int node_id;
         if (sscanf(line, "Node %d, zone %" STRINGIFY(LINE_MAX) "s", &node_id, zone_name) == 2) {
             if (!node || node->id != node_id) {
+                line = strtok_r(NULL, "\n", &save_ptr);
+                if (strncmp(line, NODE_STATS_MARKER, strlen(NODE_STATS_MARKER)) != 0) {
+                    /*
+                     * per-node stats are only present in the first non-empty zone of
+                     * the node.
+                     */
+                    continue;
+                }
+
                 /* new node is found */
                 if (node) {
                     node->zone_count = zone_idx + 1;
@@ -2716,11 +2729,31 @@ static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_
     long direct_reclaim_duration_ms;
     bool in_kswapd_reclaim;
 
+    mp_event_count++;
+    if (debug_process_killing) {
+        ALOGI("%s memory pressure event #%" PRIu64 " is triggered",
+              level_name[level], mp_event_count);
+    }
+
     if (clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_tm) != 0) {
         ALOGE("Failed to get current time");
         return;
     }
 
+    if (events > 0 ) {
+        /* Ignore a lower event within the first polling window. */
+        if (level < prev_level) {
+            if (debug_process_killing)
+                ALOGI("Ignoring %s pressure event; occurred too soon.",
+                       level_name[level]);
+            return;
+        }
+        prev_level = level;
+    } else {
+        /* Reset event level after the first polling window. */
+        prev_level = VMPRESS_LEVEL_LOW;
+    }
+
     record_wakeup_time(&curr_tm, events ? Event : Polling, &wi);
 
     bool kill_pending = is_kill_pending();
@@ -3066,8 +3099,10 @@ static void mp_event_common(int data, uint32_t events, struct polling_params *po
     };
     static struct wakeup_info wi;
 
+    mp_event_count++;
     if (debug_process_killing) {
-        ALOGI("%s memory pressure event is triggered", level_name[level]);
+        ALOGI("%s memory pressure event #%" PRIu64 " is triggered",
+              level_name[level], mp_event_count);
     }
 
     if (!use_psi_monitors) {
@@ -3582,6 +3617,8 @@ static void kernel_event_handler(int data __unused, uint32_t events __unused,
 }
 
 static bool init_monitors() {
+    ALOGI("Wakeup counter is reset from %" PRIu64 " to 0", mp_event_count);
+    mp_event_count = 0;
     /* Try to use psi monitor first if kernel has it */
     use_psi_monitors = GET_LMK_PROPERTY(bool, "use_psi", true) &&
         init_psi_monitors();
@@ -3815,6 +3852,7 @@ static void call_handler(struct event_handler_info* handler_info,
          */
         poll_params->poll_start_tm = curr_tm;
         poll_params->poll_handler = handler_info;
+        poll_params->last_poll_tm = curr_tm;
         break;
     case POLLING_PAUSE:
         poll_params->paused_handler = handler_info;
@@ -3911,11 +3949,15 @@ static void mainloop(void) {
          */
         for (i = 0, evt = &events[0]; i < nevents; ++i, evt++) {
             if ((evt->events & EPOLLHUP) && evt->data.ptr) {
-                ALOGI("lmkd data connection dropped");
                 handler_info = (struct event_handler_info*)evt->data.ptr;
-                watchdog.start();
-                ctrl_data_close(handler_info->data);
-                watchdog.stop();
+                if (handler_info->handler == kill_done_handler) {
+                    call_handler(handler_info, &poll_params, evt->events);
+                } else {
+                    ALOGI("lmkd data connection dropped");
+                    watchdog.start();
+                    ctrl_data_close(handler_info->data);
+                    watchdog.stop();
+                }
             }
         }
 
diff --git a/tests/lmkd_tests.cpp b/tests/lmkd_tests.cpp
index 0c582b7..28ee35f 100644
--- a/tests/lmkd_tests.cpp
+++ b/tests/lmkd_tests.cpp
@@ -30,10 +30,6 @@
 
 using namespace android::base;
 
-#ifndef __NR_process_mrelease
-#define __NR_process_mrelease 448
-#endif
-
 #define INKERNEL_MINFREE_PATH "/sys/module/lowmemorykiller/parameters/minfree"
 
 #define LMKD_LOGCAT_MARKER "lowmemorykiller"
```

