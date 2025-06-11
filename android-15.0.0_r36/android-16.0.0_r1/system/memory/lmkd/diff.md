```diff
diff --git a/Android.bp b/Android.bp
index 9d70642..ec0be49 100644
--- a/Android.bp
+++ b/Android.bp
@@ -88,6 +88,10 @@ cc_library_static {
         "liblog",
         "libprocessgroup",
     ],
+    header_libs: [
+        "libmemevents_headers",
+        "libbase_headers",
+    ],
 }
 
 cc_library_static {
diff --git a/README.md b/README.md
index b5748d4..d140016 100644
--- a/README.md
+++ b/README.md
@@ -60,14 +60,13 @@ properties:
                                  any eligible task (fast decision). Default = false
 
   - `ro.lmk.kill_timeout_ms`:    duration in ms after a kill when no additional
-                                 kill will be done. Default = 0 (disabled)
+                                 kill will be done. Default = 100
 
   - `ro.lmk.debug`:              enable lmkd debug logs, Default = false
 
   - `ro.lmk.swap_free_low_percentage`: level of free swap as a percentage of the
                                  total swap space used as a threshold to consider
-                                 the system as swap space starved. Default for
-                                 low-RAM devices = 10, for high-end devices = 20
+                                 the system as swap space starved. Default = 10
 
   - `ro.lmk.thrashing_limit`:    number of workingset refaults as a percentage of
                                 the file-backed pagecache size used as a threshold
diff --git a/lmkd.cpp b/lmkd.cpp
index 54129c7..3cb458d 100644
--- a/lmkd.cpp
+++ b/lmkd.cpp
@@ -214,6 +214,7 @@ static struct timespec last_kill_tm;
 enum vmpressure_level prev_level = VMPRESS_LEVEL_LOW;
 static bool monitors_initialized;
 static bool boot_completed_handled = false;
+static bool mem_event_update_zoneinfo_supported;
 
 /* lmkd configurable parameters */
 static bool debug_process_killing;
@@ -2233,6 +2234,10 @@ static struct proc *proc_get_heaviest(int oomadj) {
     struct adjslot_list *curr = head->next;
     struct proc *maxprocp = NULL;
     int maxsize = 0;
+    if ((curr != head) && (curr->next == head)) {
+        // Our list only has one process.  No need to access procfs for its size.
+        return (struct proc *)curr;
+    }
     while (curr != head) {
         int pid = ((struct proc *)curr)->pid;
         int tasksize = proc_get_size(pid);
@@ -2638,6 +2643,8 @@ struct zone_watermarks {
     long min_wmark;
 };
 
+static struct zone_watermarks watermarks;
+
 /*
  * Returns lowest breached watermark or WMARK_NONE.
  */
@@ -2677,6 +2684,15 @@ void calc_zone_watermarks(struct zoneinfo *zi, struct zone_watermarks *watermark
     }
 }
 
+static int update_zoneinfo_watermarks(struct zoneinfo *zi) {
+    if (zoneinfo_parse(zi) < 0) {
+        ALOGE("Failed to parse zoneinfo!");
+        return -1;
+    }
+    calc_zone_watermarks(zi, &watermarks);
+    return 0;
+}
+
 static int calc_swap_utilization(union meminfo *mi) {
     int64_t swap_used = mi->field.total_swap - get_free_swap(mi);
     int64_t total_swappable = mi->field.active_anon + mi->field.inactive_anon +
@@ -2684,7 +2700,18 @@ static int calc_swap_utilization(union meminfo *mi) {
     return total_swappable > 0 ? (swap_used * 100) / total_swappable : 0;
 }
 
-static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_params) {
+enum event_source {
+    PSI,
+    VENDOR,
+};
+
+union psi_event_data {
+    enum vmpressure_level level;
+    mem_event_t vendor_event;
+};
+
+static void __mp_event_psi(enum event_source source, union psi_event_data data,
+                           uint32_t events, struct polling_params *poll_params) {
     enum reclaim_state {
         NO_RECLAIM = 0,
         KSWAPD_RECLAIM,
@@ -2698,7 +2725,6 @@ static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_
     static int64_t init_pgrefill;
     static bool killing;
     static int thrashing_limit = thrashing_limit_pct;
-    static struct zone_watermarks watermarks;
     static struct timespec wmark_update_tm;
     static struct wakeup_info wi;
     static struct timespec thrashing_reset_tm;
@@ -2712,7 +2738,7 @@ static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_
     struct timespec curr_tm;
     int64_t thrashing = 0;
     bool swap_is_low = false;
-    enum vmpressure_level level = (enum vmpressure_level)data;
+    enum vmpressure_level level = (source == PSI) ? data.level: (enum vmpressure_level)0;
     enum kill_reasons kill_reason = NONE;
     bool cycle_after_kill = false;
     enum reclaim_state reclaim = NO_RECLAIM;
@@ -2731,8 +2757,11 @@ static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_
 
     mp_event_count++;
     if (debug_process_killing) {
-        ALOGI("%s memory pressure event #%" PRIu64 " is triggered",
-              level_name[level], mp_event_count);
+        if (source == PSI)
+            ALOGI("%s memory pressure event #%" PRIu64 " is triggered",
+                  level_name[level], mp_event_count);
+        else
+            ALOGI("vendor kill event #%" PRIu64 " is triggered", mp_event_count);
     }
 
     if (clock_gettime(CLOCK_MONOTONIC_COARSE, &curr_tm) != 0) {
@@ -2740,21 +2769,23 @@ static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_
         return;
     }
 
-    if (events > 0 ) {
-        /* Ignore a lower event within the first polling window. */
-        if (level < prev_level) {
-            if (debug_process_killing)
-                ALOGI("Ignoring %s pressure event; occurred too soon.",
-                       level_name[level]);
-            return;
+    if (source == PSI) {
+        if (events > 0 ) {
+            /* Ignore a lower event within the first polling window. */
+            if (level < prev_level) {
+                if (debug_process_killing)
+                    ALOGI("Ignoring %s pressure event; occurred too soon.",
+                           level_name[level]);
+                return;
+            }
+            prev_level = level;
+        } else {
+            /* Reset event level after the first polling window. */
+            prev_level = VMPRESS_LEVEL_LOW;
         }
-        prev_level = level;
-    } else {
-        /* Reset event level after the first polling window. */
-        prev_level = VMPRESS_LEVEL_LOW;
-    }
 
-    record_wakeup_time(&curr_tm, events ? Event : Polling, &wi);
+        record_wakeup_time(&curr_tm, events ? Event : Polling, &wi);
+    }
 
     bool kill_pending = is_kill_pending();
     if (kill_pending && (kill_timeout_ms == 0 ||
@@ -2821,7 +2852,8 @@ static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_
         init_pgscan_kswapd = vs.field.pgscan_kswapd;
         init_pgrefill = vs.field.pgrefill;
         reclaim = KSWAPD_RECLAIM;
-    } else if (workingset_refault_file == prev_workingset_refault) {
+    } else if ((workingset_refault_file == prev_workingset_refault) &&
+                (source == PSI)) {
         /*
          * Device is not thrashing and not reclaiming, bail out early until we see these stats
          * changing
@@ -2875,19 +2907,18 @@ static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_
 
 update_watermarks:
     /*
-     * Refresh watermarks once per min in case user updated one of the margins.
-     * TODO: b/140521024 replace this periodic update with an API for AMS to notify LMKD
-     * that zone watermarks were changed by the system software.
+     * Refresh watermarks:
+     * 1. watermarks haven't been initialized (high_wmark == 0)
+     * 2. per min in case user updated one of the margins if mem_event update_zoneinfo is NOT
+     *    supported.
      */
-    if (watermarks.high_wmark == 0 || get_time_diff_ms(&wmark_update_tm, &curr_tm) > 60000) {
+    if (watermarks.high_wmark == 0 || (!mem_event_update_zoneinfo_supported &&
+        get_time_diff_ms(&wmark_update_tm, &curr_tm) > 60000)) {
         struct zoneinfo zi;
 
-        if (zoneinfo_parse(&zi) < 0) {
-            ALOGE("Failed to parse zoneinfo!");
+        if (update_zoneinfo_watermarks(&zi) < 0) {
             return;
         }
-
-        calc_zone_watermarks(&zi, &watermarks);
         wmark_update_tm = curr_tm;
     }
 
@@ -2901,7 +2932,23 @@ update_watermarks:
      * TODO: move this logic into a separate function
      * Decide if killing a process is necessary and record the reason
      */
-    if (cycle_after_kill && wmark < WMARK_LOW) {
+    if (source == VENDOR) {
+        int vendor_kill_reason = data.vendor_event.event_data.vendor_kill.reason;
+        short vendor_kill_min_oom_score_adj =
+            data.vendor_event.event_data.vendor_kill.min_oom_score_adj;
+        if (vendor_kill_reason < 0 ||
+            vendor_kill_reason > VENDOR_KILL_REASON_END ||
+            vendor_kill_min_oom_score_adj < 0) {
+            ALOGE("Invalid vendor kill reason %d, min_oom_score_adj %d",
+                  vendor_kill_reason, vendor_kill_min_oom_score_adj);
+            return;
+        }
+
+        kill_reason = (enum kill_reasons)(vendor_kill_reason + VENDOR_KILL_REASON_BASE);
+        min_score_adj = vendor_kill_min_oom_score_adj;
+        snprintf(kill_desc, sizeof(kill_desc),
+            "vendor kill with the reason %d, min_score_adj %d", kill_reason, min_score_adj);
+    } else if (cycle_after_kill && wmark < WMARK_LOW) {
         /*
          * Prevent kills not freeing enough memory which might lead to OOM kill.
          * This might happen when a process is consuming memory faster than reclaim can
@@ -2910,6 +2957,7 @@ update_watermarks:
         min_score_adj = pressure_after_kill_min_score;
         kill_reason = PRESSURE_AFTER_KILL;
         strncpy(kill_desc, "min watermark is breached even after kill", sizeof(kill_desc));
+        kill_desc[sizeof(kill_desc) - 1] = '\0';
     } else if (level == VMPRESS_LEVEL_CRITICAL && events != 0) {
         /*
          * Device is too busy reclaiming memory which might lead to ANR.
@@ -2918,6 +2966,7 @@ update_watermarks:
          */
         kill_reason = NOT_RESPONDING;
         strncpy(kill_desc, "device is not responding", sizeof(kill_desc));
+        kill_desc[sizeof(kill_desc) - 1] = '\0';
     } else if (swap_is_low && thrashing > thrashing_limit_pct) {
         /* Page cache is thrashing while swap is low */
         kill_reason = LOW_SWAP_AND_THRASHING;
@@ -3065,6 +3114,11 @@ no_kill:
     }
 }
 
+static void mp_event_psi(int data, uint32_t events, struct polling_params *poll_params) {
+    union psi_event_data event_data = {.level = (enum vmpressure_level)data};
+    __mp_event_psi(PSI, event_data, events, poll_params);
+}
+
 static std::string GetCgroupAttributePath(const char* attr) {
     std::string path;
     if (!CgroupGetAttributePath(attr, &path)) {
@@ -3389,7 +3443,7 @@ static MemcgVersion memcg_version() {
 }
 
 static void memevent_listener_notification(int data __unused, uint32_t events __unused,
-                                           struct polling_params* poll_params __unused) {
+                                           struct polling_params* poll_params) {
     struct timespec curr_tm;
     std::vector<mem_event_t> mem_events;
 
@@ -3426,6 +3480,16 @@ static void memevent_listener_notification(int data __unused, uint32_t events __
                 kswapd_start_tm.tv_sec = 0;
                 kswapd_start_tm.tv_nsec = 0;
                 break;
+            case MEM_EVENT_VENDOR_LMK_KILL: {
+                union psi_event_data event_data = {.vendor_event = mem_event};
+                 __mp_event_psi(VENDOR, event_data, 0, poll_params);
+                break;
+            }
+            case MEM_EVENT_UPDATE_ZONEINFO: {
+                struct zoneinfo zi;
+                update_zoneinfo_watermarks(&zi);
+                break;
+            }
         }
     }
 }
@@ -3460,6 +3524,17 @@ static bool init_memevent_listener_monitoring() {
         return false;
     }
 
+    if (!memevent_listener->registerEvent(MEM_EVENT_VENDOR_LMK_KILL)) {
+        ALOGI("Failed to register android_vendor_kill memevents");
+    }
+
+    if (!memevent_listener->registerEvent(MEM_EVENT_UPDATE_ZONEINFO)) {
+        mem_event_update_zoneinfo_supported = false;
+        ALOGI("update_zoneinfo memevents are not supported");
+    } else {
+        mem_event_update_zoneinfo_supported = true;
+    }
+
     int memevent_listener_fd = memevent_listener->getRingBufferFd();
     if (memevent_listener_fd < 0) {
         memevent_listener.reset();
diff --git a/statslog.cpp b/statslog.cpp
index fbb8867..ccba857 100644
--- a/statslog.cpp
+++ b/statslog.cpp
@@ -158,12 +158,11 @@ struct memory_stat *stats_read_memory_stat(bool per_app_memcg, int pid, uid_t ui
         if (memory_stat_from_cgroup(&mem_st, pid, uid) == 0) {
             return &mem_st;
         }
-    } else {
-        if (memory_stat_from_procfs(&mem_st, pid) == 0) {
-            mem_st.rss_in_bytes = rss_bytes;
-            mem_st.swap_in_bytes = swap_bytes;
-            return &mem_st;
-        }
+    }
+    if (memory_stat_from_procfs(&mem_st, pid) == 0) {
+        mem_st.rss_in_bytes = rss_bytes;
+        mem_st.swap_in_bytes = swap_bytes;
+        return &mem_st;
     }
 
     return NULL;
diff --git a/statslog.h b/statslog.h
index 60c7016..4c51f70 100644
--- a/statslog.h
+++ b/statslog.h
@@ -26,6 +26,7 @@
 #include <sys/types.h>
 
 #include <cutils/properties.h>
+#include <memevents/memevents.h>
 
 __BEGIN_DECLS
 
@@ -66,6 +67,9 @@ enum kill_reasons {
     LOW_FILECACHE_AFTER_THRASHING,
     LOW_MEM,
     DIRECT_RECL_STUCK,
+    /* reserve aosp kill 0 ~ 999 */
+    VENDOR_KILL_REASON_BASE = 1000,
+    VENDOR_KILL_REASON_END = VENDOR_KILL_REASON_BASE + NUM_VENDOR_LMK_KILL_REASON - 1,
     KILL_REASON_COUNT
 };
 
```

