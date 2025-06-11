```diff
diff --git a/include/meminfo/sysmeminfo.h b/include/meminfo/sysmeminfo.h
index a695584..6e410b3 100644
--- a/include/meminfo/sysmeminfo.h
+++ b/include/meminfo/sysmeminfo.h
@@ -162,5 +162,9 @@ bool ReadDmabufHeapTotalExportedKb(
         uint64_t* size, const std::string& dma_heap_root = kDmabufHeapRoot,
         const std::string& dma_buf_sysfs_path = "/sys/kernel/dmabuf/buffers");
 
+// Read total amount of memory in kb allocated by kernel drivers through CMA.
+bool ReadKernelCmaUsageKb(uint64_t* size,
+                          const std::string& cma_stats_sysfs_path = "/sys/kernel/mm/cma");
+
 }  // namespace meminfo
 }  // namespace android
diff --git a/libdmabufinfo/include/dmabufinfo/dmabufinfo.h b/libdmabufinfo/include/dmabufinfo/dmabufinfo.h
index 9b5c945..4709d5d 100644
--- a/libdmabufinfo/include/dmabufinfo/dmabufinfo.h
+++ b/libdmabufinfo/include/dmabufinfo/dmabufinfo.h
@@ -113,13 +113,6 @@ bool ReadDmaBufMapRefs(pid_t pid, std::vector<DmaBuffer>* dmabufs,
                        const std::string& procfs_path = "/proc",
                        const std::string& dmabuf_sysfs_path = "/sys/kernel/dmabuf/buffers");
 
-
-
-// Get the DMA buffers PSS contribution for the specified @pid
-// Returns true on success, false otherwise
-bool ReadDmaBufPss(int pid, uint64_t* pss, const std::string& procfs_path = "/proc",
-                   const std::string& dmabuf_sysfs_path = "/sys/kernel/dmabuf/buffers");
-
 // Writes DmaBuffer info into an existing vector (which will be cleared first.)
 // Will include all DmaBuffers, whether thay are retained or mapped.
 // Returns true on success, otherwise false.
diff --git a/libmemevents/Android.bp b/libmemevents/Android.bp
index fe3d90d..2d8edd0 100644
--- a/libmemevents/Android.bp
+++ b/libmemevents/Android.bp
@@ -51,6 +51,11 @@ cc_library {
     srcs: ["memevents.cpp"],
 }
 
+cc_library_headers {
+    name: "libmemevents_headers",
+    export_include_dirs: ["include"],
+}
+
 cc_test {
     name: "memevents_test",
     srcs: [
diff --git a/libmemevents/bpfprogs/bpfMemEvents.c b/libmemevents/bpfprogs/bpfMemEvents.c
index 66c6bde..ed727e5 100644
--- a/libmemevents/bpfprogs/bpfMemEvents.c
+++ b/libmemevents/bpfprogs/bpfMemEvents.c
@@ -17,6 +17,7 @@
 #include <string.h>
 
 #include <linux/bpf_perf_event.h>
+#include <linux/oom.h>
 
 #include <memevents/bpf_helpers.h>
 #include <memevents/bpf_types.h>
@@ -27,7 +28,7 @@ DEFINE_BPF_RINGBUF(ams_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_
 DEFINE_BPF_RINGBUF(lmkd_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID,
                    AID_SYSTEM, 0660)
 
-DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_ams, KVER_5_8)
+DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_ams, KVER_5_10)
 (struct mark_victim_args* args) {
     unsigned long long timestamp_ns = bpf_ktime_get_ns();
     struct mem_event_t* data = bpf_ams_rb_reserve();
@@ -53,7 +54,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_dr_start, KVER_5_8)
+                     tp_lmkd_dr_start, KVER_5_10)
 (struct direct_reclaim_begin_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -66,7 +67,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AI
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_end/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_dr_end, KVER_5_8)
+                     tp_lmkd_dr_end, KVER_5_10)
 (struct direct_reclaim_end_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -79,7 +80,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_end/lmkd", AID_
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_wake/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_kswapd_wake, KVER_5_8)
+                     tp_lmkd_kswapd_wake, KVER_5_10)
 (struct kswapd_wake_args* args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -95,7 +96,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_wake/lmkd", AID_ROOT, A
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_sleep/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_kswapd_sleep, KVER_5_8)
+                     tp_lmkd_kswapd_sleep, KVER_5_10)
 (struct kswapd_sleep_args* args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -108,5 +109,43 @@ DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_sleep/lmkd", AID_ROOT,
     return 0;
 }
 
+DEFINE_BPF_PROG_KVER("tracepoint/android_vendor_lmk/android_trigger_vendor_lmk_kill/lmkd",
+                     AID_ROOT, AID_SYSTEM, tp_lmkd_vendor_lmk_kill, KVER_6_1)
+(struct vendor_lmk_kill_args* args) {
+    struct mem_event_t* data;
+    uint32_t reason = args->reason;
+    short min_oom_score_adj = args->min_oom_score_adj;
+
+    if (min_oom_score_adj < OOM_SCORE_ADJ_MIN ||
+        min_oom_score_adj > OOM_SCORE_ADJ_MAX)
+        return 0;
+
+    if (reason < 0 || reason >= NUM_VENDOR_LMK_KILL_REASON)
+        return 0;
+
+    data = bpf_lmkd_rb_reserve();
+    if (data == NULL) return 1;
+
+    data->type = MEM_EVENT_VENDOR_LMK_KILL;
+    data->event_data.vendor_kill.reason = reason;
+    data->event_data.vendor_kill.min_oom_score_adj = min_oom_score_adj;
+
+    bpf_lmkd_rb_submit(data);
+
+    return 0;
+}
+
+DEFINE_BPF_PROG_KVER("tracepoint/kmem/mm_calculate_totalreserve_pages/lmkd", AID_ROOT, AID_SYSTEM,
+                     tp_lmkd_calculate_totalreserve_pages, KVER_6_1)
+(struct calculate_totalreserve_pages_args* __unused args) {
+    struct mem_event_t* data = bpf_lmkd_rb_reserve();
+    if (data == NULL) return 1;
+
+    data->type = MEM_EVENT_UPDATE_ZONEINFO;
+
+    bpf_lmkd_rb_submit(data);
+
+    return 0;
+}
 // bpf_probe_read_str is GPL only symbol
 LICENSE("GPL");
diff --git a/libmemevents/bpfprogs/bpfMemEventsTest.c b/libmemevents/bpfprogs/bpfMemEventsTest.c
index 36d8b84..c3a737d 100644
--- a/libmemevents/bpfprogs/bpfMemEventsTest.c
+++ b/libmemevents/bpfprogs/bpfMemEventsTest.c
@@ -17,6 +17,7 @@
 #include <string.h>
 
 #include <linux/bpf_perf_event.h>
+#include <linux/oom.h>
 
 #include <memevents/bpf_helpers.h>
 #include <memevents/bpf_types.h>
@@ -25,7 +26,7 @@
 DEFINE_BPF_RINGBUF(rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID, AID_SYSTEM,
                    0660)
 
-DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams, KVER_5_8)
+DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams, KVER_5_10)
 (struct mark_victim_args* args) {
     unsigned long long timestamp_ns = bpf_ktime_get_ns();
     struct mem_event_t* data = bpf_rb_reserve();
@@ -56,7 +57,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams,
  * executed manually with BPF_PROG_RUN, and the tracepoint bpf-progs do not
  * currently implement this BPF_PROG_RUN operation.
  */
-DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_oom, KVER_5_8)
+DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_oom, KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -81,7 +82,7 @@ DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_begin", AID_ROOT, AID_ROOT,
-                     tp_memevents_test_dr_begin, KVER_5_8)
+                     tp_memevents_test_dr_begin, KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -94,7 +95,7 @@ DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_begin", AID_ROOT, AID_ROOT,
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, tp_memevents_test_dr_end,
-                     KVER_5_8)
+                     KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -107,7 +108,7 @@ DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, tp_memev
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, tp_memevents_test_kswapd_wake,
-                     KVER_5_8)
+                     KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -124,7 +125,7 @@ DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, tp_memevents_te
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/kswapd_sleep", AID_ROOT, AID_ROOT, tp_memevents_test_kswapd_sleep,
-                     KVER_5_8)
+                     KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -138,5 +139,44 @@ DEFINE_BPF_PROG_KVER("skfilter/kswapd_sleep", AID_ROOT, AID_ROOT, tp_memevents_t
     return 0;
 }
 
+DEFINE_BPF_PROG_KVER("skfilter/android_trigger_vendor_lmk_kill", AID_ROOT, AID_SYSTEM,
+                     tp_memevents_test_lmkd_vendor_lmk_kill, KVER_6_1)
+(void* __unused ctx) {
+    struct mem_event_t* data;
+    uint32_t reason = mocked_vendor_lmk_kill_event.event_data.vendor_kill.reason;
+    short min_oom_score_adj = mocked_vendor_lmk_kill_event.event_data.vendor_kill.min_oom_score_adj;
+
+    if (min_oom_score_adj < OOM_SCORE_ADJ_MIN || min_oom_score_adj > OOM_SCORE_ADJ_MAX)
+        return 0;
+
+    if (reason < 0 || reason >= NUM_VENDOR_LMK_KILL_REASON)
+        return 0;
+
+    data = bpf_rb_reserve();
+    if (data == NULL) return 1;
+
+    data->type = MEM_EVENT_VENDOR_LMK_KILL;
+    data->event_data.vendor_kill.reason = reason;
+    data->event_data.vendor_kill.min_oom_score_adj = min_oom_score_adj;
+
+    bpf_rb_submit(data);
+
+    return 0;
+}
+
+DEFINE_BPF_PROG_KVER("skfilter/calculate_totalreserve_pages", AID_ROOT, AID_ROOT,
+                     tp_memevents_test_calculate_totalreserve_pages, KVER_6_1)
+(void* __unused ctx) {
+    struct mem_event_t* data = bpf_rb_reserve();
+    if (data == NULL) return 1;
+
+    data->type = MEM_EVENT_UPDATE_ZONEINFO;
+    data->event_data.reserve_pages.num_pages =
+            mocked_total_reserve_pages_event.event_data.reserve_pages.num_pages;
+
+    bpf_rb_submit(data);
+
+    return 0;
+}
 // bpf_probe_read_str is GPL only symbol
 LICENSE("GPL");
diff --git a/libmemevents/include/memevents/bpf_types.h b/libmemevents/include/memevents/bpf_types.h
index 9950d6d..9208b48 100644
--- a/libmemevents/include/memevents/bpf_types.h
+++ b/libmemevents/include/memevents/bpf_types.h
@@ -30,9 +30,11 @@ typedef unsigned int mem_event_type_t;
 #define MEM_EVENT_DIRECT_RECLAIM_END 2
 #define MEM_EVENT_KSWAPD_WAKE 3
 #define MEM_EVENT_KSWAPD_SLEEP 4
+#define MEM_EVENT_VENDOR_LMK_KILL 5
+#define MEM_EVENT_UPDATE_ZONEINFO 6
 
 // This always comes after the last valid event type
-#define NR_MEM_EVENTS 5
+#define NR_MEM_EVENTS 7
 
 /* BPF-Rb Paths */
 #define MEM_EVENTS_AMS_RB "/sys/fs/bpf/memevents/map_bpfMemEvents_ams_rb"
@@ -51,9 +53,23 @@ typedef unsigned int mem_event_type_t;
     "/sys/fs/bpf/memevents/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_kswapd_wake_lmkd"
 #define MEM_EVENTS_LMKD_VMSCAN_KSWAPD_SLEEP_TP \
     "/sys/fs/bpf/memevents/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_kswapd_sleep_lmkd"
+#define MEM_EVENTS_LMKD_TRIGGER_VENDOR_LMK_KILL_TP \
+    "/sys/fs/bpf/memevents/"                       \
+    "prog_bpfMemEvents_tracepoint_android_vendor_lmk_android_trigger_vendor_lmk_kill_lmkd"
+#define MEM_EVENTS_LMKD_CALCULATE_TOTALRESERVE_PAGES_TP \
+    "/sys/fs/bpf/memevents/prog_bpfMemEvents_tracepoint_kmem_mm_calculate_totalreserve_pages_lmkd"
 #define MEM_EVENTS_TEST_OOM_MARK_VICTIM_TP \
     "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_tracepoint_oom_mark_victim"
 
+/* Number of kill reasons.  Currently,
+*  kill reasons are values from 0 to 999.
+*  This range is expected to cover all
+*  foreseeable kill reasons.  If the number of
+*  kill reasons exceeds this limit in the future,
+*  this constant should be adjusted accordingly.
+*/
+#define NUM_VENDOR_LMK_KILL_REASON 1000
+
 /* Struct to collect data from tracepoints */
 struct mem_event_t {
     uint64_t type;
@@ -81,6 +97,15 @@ struct mem_event_t {
         struct KswapdSleep {
             uint32_t node_id;
         } kswapd_sleep;
+
+        struct VendorKill {
+            uint32_t reason;
+            short min_oom_score_adj;
+        } vendor_kill;
+
+        struct TotalReservePages {
+            uint32_t num_pages;
+        } reserve_pages;
     } event_data;
 };
 
@@ -122,4 +147,16 @@ struct kswapd_sleep_args {
     uint32_t nid;
 };
 
+struct vendor_lmk_kill_args {
+    uint64_t __ignore;
+    /* Actual fields start at offset 8 */
+    uint32_t reason;
+    short min_oom_score_adj;
+};
+
+struct calculate_totalreserve_pages_args {
+    uint64_t __ignore;
+    /* Actual fields start at offset 8 */
+    uint64_t totalreserve_pages;
+};
 #endif /* MEM_EVENTS_BPF_TYES_H_ */
diff --git a/libmemevents/include/memevents/memevents_test.h b/libmemevents/include/memevents/memevents_test.h
index de6660b..28b6026 100644
--- a/libmemevents/include/memevents/memevents_test.h
+++ b/libmemevents/include/memevents/memevents_test.h
@@ -31,6 +31,10 @@
     "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_kswapd_wake"
 #define MEM_EVENTS_TEST_KSWAPD_SLEEP_TP \
     "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_kswapd_sleep"
+#define MEM_EVENTS_TEST_LMKD_TRIGGER_VENDOR_LMK_KILL_TP \
+    "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_android_trigger_vendor_lmk_kill"
+#define MEM_EVENTS_TEST_CALCULATE_TOTALRESERVE_PAGES_TP \
+    "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_calculate_totalreserve_pages"
 
 // clang-format off
 const struct mem_event_t mocked_oom_event = {
@@ -61,6 +65,19 @@ const struct mem_event_t mocked_kswapd_sleep_event = {
      .event_data.kswapd_sleep = {
         .node_id = 3,
 }};
+
+const struct mem_event_t mocked_vendor_lmk_kill_event = {
+     .type = MEM_EVENT_VENDOR_LMK_KILL,
+     .event_data.vendor_kill = {
+        .reason = 3,
+        .min_oom_score_adj = 900,
+}};
+
+const struct mem_event_t mocked_total_reserve_pages_event = {
+     .type = MEM_EVENT_UPDATE_ZONEINFO,
+     .event_data.reserve_pages = {
+        .num_pages = 1234,
+}};
 // clang-format on
 
 #endif /* MEM_EVENTS_TEST_H_ */
\ No newline at end of file
diff --git a/libmemevents/memevents.cpp b/libmemevents/memevents.cpp
index c27303b..db3c1b8 100644
--- a/libmemevents/memevents.cpp
+++ b/libmemevents/memevents.cpp
@@ -123,6 +123,18 @@ static const std::vector<std::vector<struct MemBpfAttachment>> attachments = {
             .tpEvent = "mm_vmscan_kswapd_sleep",
             .event_type = MEM_EVENT_KSWAPD_SLEEP
         },
+        {
+            .prog = MEM_EVENTS_LMKD_TRIGGER_VENDOR_LMK_KILL_TP,
+            .tpGroup = "android_vendor_lmk",
+            .tpEvent = "android_trigger_vendor_lmk_kill",
+            .event_type = MEM_EVENT_VENDOR_LMK_KILL
+        },
+        {
+            .prog = MEM_EVENTS_LMKD_CALCULATE_TOTALRESERVE_PAGES_TP,
+            .tpGroup = "kmem",
+            .tpEvent = "mm_calculate_totalreserve_pages",
+            .event_type = MEM_EVENT_UPDATE_ZONEINFO
+        },
     },
     // MemEventsTest
     {
diff --git a/libmemevents/memevents_test.cpp b/libmemevents/memevents_test.cpp
index 82aac86..3c29687 100644
--- a/libmemevents/memevents_test.cpp
+++ b/libmemevents/memevents_test.cpp
@@ -51,7 +51,8 @@ static const std::string bpfRbsPaths[MemEventClient::NR_CLIENTS] = {
 static const std::string testBpfSkfilterProgPaths[NR_MEM_EVENTS] = {
         MEM_EVENTS_TEST_OOM_KILL_TP, MEM_EVENTS_TEST_DIRECT_RECLAIM_START_TP,
         MEM_EVENTS_TEST_DIRECT_RECLAIM_END_TP, MEM_EVENTS_TEST_KSWAPD_WAKE_TP,
-        MEM_EVENTS_TEST_KSWAPD_SLEEP_TP};
+        MEM_EVENTS_TEST_KSWAPD_SLEEP_TP, MEM_EVENTS_TEST_LMKD_TRIGGER_VENDOR_LMK_KILL_TP,
+        MEM_EVENTS_TEST_CALCULATE_TOTALRESERVE_PAGES_TP};
 static const std::filesystem::path sysrq_trigger_path = "proc/sysrq-trigger";
 
 static void initializeTestListener(std::unique_ptr<MemEventListener>& memevent_listener,
@@ -393,6 +394,15 @@ class MemEventsListenerBpf : public ::testing::Test {
                 android::bpf::runProgram(mProgram, &kswapd_sleep_fake_args,
                                          sizeof(kswapd_sleep_fake_args));
                 break;
+            case MEM_EVENT_VENDOR_LMK_KILL:
+                struct vendor_lmk_kill_args vendor_lmk_kill_args;
+                android::bpf::runProgram(mProgram, &vendor_lmk_kill_args,
+                                         sizeof(vendor_lmk_kill_args));
+                break;
+            case MEM_EVENT_UPDATE_ZONEINFO:
+                struct calculate_totalreserve_pages_args ctp_fake_args;
+                android::bpf::runProgram(mProgram, &ctp_fake_args, sizeof(ctp_fake_args));
+                break;
             default:
                 FAIL() << "Invalid event type provided";
         }
@@ -495,6 +505,19 @@ class MemEventsListenerBpf : public ::testing::Test {
                           mocked_kswapd_sleep_event.event_data.kswapd_sleep.node_id)
                         << "MEM_EVENT_KSWAPD_SLEEP: Didn't receive expected node id";
                 break;
+            case MEM_EVENT_VENDOR_LMK_KILL:
+                ASSERT_EQ(mem_event.event_data.vendor_kill.reason,
+                          mocked_vendor_lmk_kill_event.event_data.vendor_kill.reason)
+                        << "MEM_EVENT_VENDOR_LMK_KILL: Didn't receive expected reason";
+                ASSERT_EQ(mem_event.event_data.vendor_kill.min_oom_score_adj,
+                          mocked_vendor_lmk_kill_event.event_data.vendor_kill.min_oom_score_adj)
+                        << "MEM_EVENT_VENDOR_LMK_KILL: Didn't receive expected min_oom_score_adj";
+                break;
+            case MEM_EVENT_UPDATE_ZONEINFO:
+                ASSERT_EQ(mem_event.event_data.reserve_pages.num_pages,
+                          mocked_total_reserve_pages_event.event_data.reserve_pages.num_pages)
+                        << "MEM_EVENT_UPDATE_ZONEINFO: Didn't receive expected reserved pages";
+                break;
         }
     }
 };
@@ -576,6 +599,33 @@ TEST_F(MemEventsListenerBpf, listener_bpf_kswapd_sleep) {
     validateMockedEvent(mem_events[0]);
 }
 
+TEST_F(MemEventsListenerBpf, listener_bpf_vendor_lmk_kill) {
+    const mem_event_type_t event_type = MEM_EVENT_VENDOR_LMK_KILL;
+
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
+    testListenEvent(event_type);
+
+    std::vector<mem_event_t> mem_events;
+    ASSERT_TRUE(memevent_listener->getMemEvents(mem_events)) << "Failed fetching events";
+    ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
+    ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a vendor lmk kill event";
+    validateMockedEvent(mem_events[0]);
+}
+
+TEST_F(MemEventsListenerBpf, listener_bpf_calculate_totalreserve_pages) {
+    const mem_event_type_t event_type = MEM_EVENT_UPDATE_ZONEINFO;
+
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
+    testListenEvent(event_type);
+
+    std::vector<mem_event_t> mem_events;
+    ASSERT_TRUE(memevent_listener->getMemEvents(mem_events)) << "Failed fetching events";
+    ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
+    ASSERT_EQ(mem_events[0].type, event_type)
+            << "Didn't receive a calculate totalreserve pages event";
+    validateMockedEvent(mem_events[0]);
+}
+
 /*
  * `listen()` should timeout, and return false, when a memory event that
  * we are not registered for is triggered.
diff --git a/libmeminfo_test.cpp b/libmeminfo_test.cpp
index 2d59e42..3b4d915 100644
--- a/libmeminfo_test.cpp
+++ b/libmeminfo_test.cpp
@@ -1227,6 +1227,40 @@ TEST(SysMemInfo, TestReadGpuTotalUsageKb) {
     EXPECT_TRUE(size >= 0);
 }
 
+class CmaSysfsStats : public ::testing::Test {
+  public:
+    virtual void SetUp() {
+        fs::current_path(fs::temp_directory_path());
+        cma_sysfs_stats_path = fs::current_path() / "cma_sysfs_stats";
+        ASSERT_TRUE(fs::create_directory(cma_sysfs_stats_path));
+        test_region_path = cma_sysfs_stats_path / "test_region";
+        ASSERT_TRUE(fs::create_directory(test_region_path));
+    }
+    virtual void TearDown() {
+        fs::remove_all(test_region_path);
+        fs::remove_all(cma_sysfs_stats_path);
+    }
+
+    fs::path test_region_path;
+    fs::path cma_sysfs_stats_path;
+};
+
+TEST_F(CmaSysfsStats, TestReadKernelCmaUsageKb) {
+    auto pages_allocated_success_path = test_region_path / "alloc_pages_success";
+    const std::string pages_allocated_success = "8";
+    ASSERT_TRUE(android::base::WriteStringToFile(pages_allocated_success,
+                                                 pages_allocated_success_path));
+
+    auto pages_released_success_path = test_region_path / "release_pages_success";
+    const std::string pages_released_success = "4";
+    ASSERT_TRUE(android::base::WriteStringToFile(pages_released_success,
+                                                 pages_released_success_path));
+
+    uint64_t size;
+    ASSERT_TRUE(ReadKernelCmaUsageKb(&size, cma_sysfs_stats_path));
+    ASSERT_EQ(size, (4 * getpagesize()) / 1024);
+}
+
 TEST(AndroidProcHeaps, ExtractAndroidHeapStatsFromFileTest) {
     std::string smaps =
             R"smaps(12c00000-13440000 rw-p 00000000 00:00 0  [anon:dalvik-main space (region space)]
diff --git a/pageacct.cpp b/pageacct.cpp
index cb17af8..7049459 100644
--- a/pageacct.cpp
+++ b/pageacct.cpp
@@ -32,12 +32,19 @@ static inline off64_t pfn_to_idle_bitmap_offset(uint64_t pfn) {
     return static_cast<off64_t>((pfn >> 6) << 3);
 }
 
-uint64_t pagesize(void) {
-    static uint64_t pagesize = sysconf(_SC_PAGE_SIZE);
-    return pagesize;
+static bool is_page_size_emulated() {
+#if defined (__x86_64__)
+    return getpagesize() != 4096;
+#else
+    return false;
+#endif
 }
 
 bool PageAcct::InitPageAcct(bool pageidle_enable) {
+    if (is_page_size_emulated()) {
+        return true;
+    }
+
     if (pageidle_enable && !PageAcct::KernelHasPageIdle()) {
         LOG(ERROR) << "Idle page tracking is not supported by the kernel";
         return false;
@@ -77,6 +84,11 @@ bool PageAcct::InitPageAcct(bool pageidle_enable) {
 bool PageAcct::PageFlags(uint64_t pfn, uint64_t* flags) {
     if (!flags) return false;
 
+    if (is_page_size_emulated()) {
+        *flags = 0;
+        return true;
+    }
+
     if (kpageflags_fd_ < 0) {
         if (!InitPageAcct()) return false;
     }
@@ -92,6 +104,11 @@ bool PageAcct::PageFlags(uint64_t pfn, uint64_t* flags) {
 bool PageAcct::PageMapCount(uint64_t pfn, uint64_t* mapcount) {
     if (!mapcount) return false;
 
+    if (is_page_size_emulated()) {
+        *mapcount = 1;
+        return true;
+    }
+
     if (kpagecount_fd_ < 0) {
         if (!InitPageAcct()) return false;
     }
@@ -105,6 +122,10 @@ bool PageAcct::PageMapCount(uint64_t pfn, uint64_t* mapcount) {
 }
 
 int PageAcct::IsPageIdle(uint64_t pfn) {
+    if (is_page_size_emulated()) {
+        return 0;
+    }
+
     if (pageidle_fd_ < 0) {
         if (!InitPageAcct(true)) return -EOPNOTSUPP;
     }
diff --git a/procmeminfo.cpp b/procmeminfo.cpp
index 91ffa68..63708ef 100644
--- a/procmeminfo.cpp
+++ b/procmeminfo.cpp
@@ -219,7 +219,6 @@ const std::vector<Vma>& ProcMemInfo::Smaps(const std::string& path, bool collect
     auto collect_vmas = [&](Vma& vma) {
         if (std::find(g_excluded_vmas.begin(), g_excluded_vmas.end(), vma.name) ==
                 g_excluded_vmas.end()) {
-            maps_.emplace_back(vma);
             if (collect_usage) {
                 add_mem_usage(&usage_, vma.usage);
             }
@@ -229,6 +228,7 @@ const std::vector<Vma>& ProcMemInfo::Smaps(const std::string& path, bool collect
                            << "-" << vma.end << "]";
                 return false;
             }
+            maps_.emplace_back(vma);
         }
         return true;
     };
diff --git a/sysmeminfo.cpp b/sysmeminfo.cpp
index f64becc..a36d960 100644
--- a/sysmeminfo.cpp
+++ b/sysmeminfo.cpp
@@ -471,5 +471,42 @@ bool ReadGpuTotalUsageKb(uint64_t* size) {
     return ReadProcessGpuUsageKb(0, 0, size);
 }
 
+bool ReadKernelCmaUsageKb(uint64_t* size, const std::string& cma_stats_sysfs_path) {
+    uint64_t totalKernelCmaUsageKb = 0;
+    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(cma_stats_sysfs_path.c_str()), closedir);
+    if (!dir) {
+        LOG(ERROR) << "Failed to open CMA sysfs stats directory: " << cma_stats_sysfs_path;
+        return false;
+    }
+
+    struct dirent* dent;
+    while ((dent = readdir(dir.get()))) {
+        if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) continue;
+
+        uint64_t allocPagesSuccess;
+        std::string allocPagesSuccessPath = ::android::base::StringPrintf(
+                                                "%s/%s/alloc_pages_success",
+                                                cma_stats_sysfs_path.c_str(),
+                                                dent->d_name);
+        if (!ReadSysfsFile(allocPagesSuccessPath, &allocPagesSuccess)) return false;
+
+        uint64_t releasePagesSuccess;
+        std::string releasePagesSuccessPath = ::android::base::StringPrintf(
+                                                "%s/%s/release_pages_success",
+                                                cma_stats_sysfs_path.c_str(),
+                                                dent->d_name);
+        if (!ReadSysfsFile(releasePagesSuccessPath, &releasePagesSuccess)) return false;
+
+        totalKernelCmaUsageKb += allocPagesSuccess - releasePagesSuccess;
+    }
+
+    totalKernelCmaUsageKb *= getpagesize() / 1024;
+    if (size) {
+        *size = totalKernelCmaUsageKb;
+    }
+
+    return true;
+}
+
 }  // namespace meminfo
 }  // namespace android
diff --git a/tools/alloctop/.gitignore b/tools/alloctop/.gitignore
new file mode 100644
index 0000000..543a865
--- /dev/null
+++ b/tools/alloctop/.gitignore
@@ -0,0 +1,4 @@
+debug/
+target/
+
+Cargo.lock
diff --git a/tools/alloctop/Android.bp b/tools/alloctop/Android.bp
new file mode 100644
index 0000000..bfc9bd0
--- /dev/null
+++ b/tools/alloctop/Android.bp
@@ -0,0 +1,44 @@
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_library {
+    name: "liballoctop",
+    crate_name: "alloctop",
+    srcs: ["src/lib.rs"],
+}
+
+rust_test {
+    name: "alloctop_test",
+    srcs: ["tests/tests.rs"],
+    rustlibs: [
+        "liballoctop",
+        "libtempfile",
+    ],
+    test_suites: ["general-tests"],
+}
+
+rust_binary {
+    name: "alloctop",
+    srcs: ["src/main.rs"],
+    rustlibs: [
+        "liballoctop",
+        "liblibc",
+    ],
+}
diff --git a/tools/alloctop/Cargo.toml b/tools/alloctop/Cargo.toml
new file mode 100644
index 0000000..b0f2764
--- /dev/null
+++ b/tools/alloctop/Cargo.toml
@@ -0,0 +1,18 @@
+[package]
+name = "alloctop"
+version = "0.0.1"
+edition = "2021"
+
+[lib]
+name = "alloctop"
+crate-type = ["lib"]
+
+[[bin]]
+name = "alloctop"
+path = "src/main.rs"
+
+[dependencies]
+libc = "0.2.169"
+
+[dev-dependencies]
+tempfile = "3"
diff --git a/tools/alloctop/src/lib.rs b/tools/alloctop/src/lib.rs
new file mode 100644
index 0000000..b65b17c
--- /dev/null
+++ b/tools/alloctop/src/lib.rs
@@ -0,0 +1,249 @@
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
+//! Helper library to handle the contents of /proc/allocinfo
+
+use std::collections::HashMap;
+use std::fs::File;
+use std::io::{self, BufRead, BufReader};
+
+/// `PROC_ALLOCINFO` is a constant string that represents the default path to the allocinfo file.
+///
+/// This file is expected to contain allocation information in a specific format, which is parsed by the `parse_allocinfo` function.
+pub const PROC_ALLOCINFO: &str = "/proc/allocinfo";
+
+/// `AllocInfo` represents a single allocation record.
+#[derive(Debug, PartialEq, Eq)]
+pub struct AllocInfo {
+    /// The total size of all allocations in bytes (unsigned 64-bit integer).
+    pub size: u64,
+    /// The total number of all allocation calls (unsigned 64-bit integer).
+    pub calls: u64,
+    /// A string representing the tag or label associated with this allocation (source code path and line, and function name).
+    pub tag: String,
+}
+
+/// `AllocGlobal` represents aggregated global allocation statistics.
+pub struct AllocGlobal {
+    /// The total size of all allocations in bytes (unsigned 64-bit integer).
+    pub size: u64,
+    /// The total number of all allocation calls (unsigned 64-bit integer).
+    pub calls: u64,
+}
+
+/// `SortBy` is an enumeration representing the different criteria by which allocation data can be sorted.
+#[derive(Debug, Clone, Copy, PartialEq, Eq)]
+pub enum SortBy {
+    /// Sort by the size of the allocation.
+    Size,
+    /// Sort by the number of allocation calls.
+    Calls,
+    /// Sort by the allocation tag.
+    Tag,
+}
+
+/// `parse_allocinfo` parses allocation information from a file.
+///
+/// This function reads and parses an allocinfo file, returning a vector of `AllocInfo` structs.
+/// It expects each line of the file (after the first header line) to contain at least three whitespace-separated fields:
+/// size, calls, and tag.
+///
+/// # Arguments
+///
+/// * `filename`: The path to the allocinfo file.
+///
+/// # Returns
+///
+/// A `Result` containing either a vector of `AllocInfo` structs or an `io::Error` if an error occurred during file reading or parsing.
+pub fn parse_allocinfo(filename: &str) -> io::Result<Vec<AllocInfo>> {
+    let file = File::open(filename)?;
+    let reader = BufReader::new(file);
+    let mut alloc_info_list = Vec::new();
+
+    for (index, line) in reader.lines().enumerate() {
+        // Skip the first line (also the second line can be skipped, but it's handled as a comment)
+        if index < 1 {
+            continue;
+        }
+
+        let line = line?;
+        let fields: Vec<&str> = line.split_whitespace().collect();
+
+        if fields.len() >= 3 && fields[0] != "#" {
+            let size = fields[0].parse::<u64>().unwrap_or(0);
+            let calls = fields[1].parse::<u64>().unwrap_or(0);
+            let tag = fields[2..].join(" ");
+
+            // One possible implementation would be to check for the minimum size here, but skipping
+            // lines at parsing time won't give correct results when the data is aggregated (e.g., for
+            // tree view).
+            alloc_info_list.push(AllocInfo { size, calls, tag });
+        }
+    }
+
+    Ok(alloc_info_list)
+}
+
+/// `sort_allocinfo` sorts a slice of `AllocInfo` structs based on the specified criteria.
+///
+/// # Arguments
+///
+/// * `data`: A mutable slice of `AllocInfo` structs to be sorted.
+/// * `sort_by`: The criteria by which to sort the data, as defined by the `SortBy` enum.
+pub fn sort_allocinfo(data: &mut [AllocInfo], sort_by: SortBy) {
+    match sort_by {
+        SortBy::Size => data.sort_by(|a, b| b.size.cmp(&a.size)),
+        SortBy::Calls => data.sort_by(|a, b| b.calls.cmp(&a.calls)),
+        SortBy::Tag => data.sort_by(|a, b| a.tag.cmp(&b.tag)),
+    }
+}
+
+/// `aggregate_tree` aggregates allocation data into a tree structure based on hierarchical tags.
+///
+/// This function takes a slice of `AllocInfo` and aggregates the size and calls for each unique tag prefix,
+/// creating a hierarchical representation of the allocation data.
+///
+/// # Arguments
+///
+/// * `data`: A slice of `AllocInfo` structs to be aggregated.
+///
+/// # Returns
+///
+/// A `HashMap` where keys are tag prefixes (representing nodes in the tree) and values are tuples containing
+/// the aggregated size and calls for that tag prefix.
+pub fn aggregate_tree(data: &[AllocInfo]) -> HashMap<String, (u64, u64)> {
+    let mut aggregated_data: HashMap<String, (u64, u64)> = HashMap::new();
+
+    for info in data {
+        let parts: Vec<&str> = info.tag.split('/').collect();
+        for i in 0..parts.len() {
+            let tag_prefix = parts[..=i].join("/");
+            let entry = aggregated_data.entry(tag_prefix).or_insert((0, 0));
+            entry.0 += info.size;
+            entry.1 += info.calls;
+        }
+    }
+
+    aggregated_data
+}
+
+/// `print_tree_data` prints the aggregated tree data, filtering by a minimum size.
+///
+/// This function prints the aggregated allocation data in a tree-like format, sorted by tag.
+/// It only prints entries where the aggregated size is greater than or equal to `min_size`.
+///
+/// # Arguments
+///
+/// * `data`: A reference to a `HashMap` containing the aggregated tree data, as produced by `aggregate_tree`.
+/// * `min_size`: The minimum aggregated size (in bytes) for an entry to be printed.
+pub fn print_tree_data(data: &HashMap<String, (u64, u64)>, min_size: u64) {
+    let mut sorted_data: Vec<_> = data.iter().collect();
+    sorted_data.sort_by(|a, b| a.0.cmp(b.0));
+
+    println!("{:>10} {:>10} Tag", "Size", "Calls");
+    for (tag, (size, calls)) in sorted_data {
+        if *size < min_size {
+            continue;
+        }
+        println!("{:>10} {:>10} {}", size, calls, tag);
+    }
+}
+
+/// `aggregate_global` aggregates allocation data to calculate global statistics.
+///
+/// This function computes the total size and total number of calls across all allocations.
+///
+/// # Arguments
+///
+/// * `data`: A slice of `AllocInfo` structs to be aggregated.
+///
+/// # Returns
+///
+/// An `AllocGlobal` struct containing the total size and total number of calls.
+pub fn aggregate_global(data: &[AllocInfo]) -> AllocGlobal {
+    let mut globals = AllocGlobal { size: 0, calls: 0 };
+
+    for info in data {
+        globals.size += info.size;
+        globals.calls += info.calls;
+    }
+
+    globals
+}
+
+/// `print_aggregated_global_data` prints the aggregated global allocation statistics.
+///
+/// This function prints the total size and total number of allocation calls.
+///
+/// # Arguments
+///
+/// * `data`: A reference to an `AllocGlobal` struct containing the aggregated data.
+pub fn print_aggregated_global_data(data: &AllocGlobal) {
+    println!("{:>11} : {}", "Total Size", data.size);
+    println!("{:>11} : {}\n", "Total Calls", data.calls);
+}
+
+/// `run` is the main entry point for the allocation analysis logic.
+///
+/// This function orchestrates the process of reading, parsing, aggregating, and displaying allocation information.
+/// It handles both flat and tree-based aggregation and display, based on the provided options.
+///
+/// # Arguments
+///
+/// * `max_lines`: The maximum number of lines to print in the flat view.
+/// * `sort_by`: An optional `SortBy` enum value indicating how to sort the data in the flat view.
+/// * `min_size`: The minimum size for an allocation to be included in the output (flat view) or printed (tree view).
+/// * `use_tree`: A boolean flag indicating whether to use tree-based aggregation and display.
+/// * `filename`: The path to the allocinfo file.
+///
+/// # Returns
+///
+/// A `Result` indicating success (`Ok(())`) or an error message (`Err(String)`) if an error occurred.
+pub fn run(
+    max_lines: usize,
+    sort_by: Option<SortBy>,
+    min_size: u64,
+    use_tree: bool,
+    filename: &str,
+) -> Result<(), String> {
+    match parse_allocinfo(filename) {
+        Ok(mut data) => {
+            {
+                let aggregated_data = aggregate_global(&data);
+                print_aggregated_global_data(&aggregated_data);
+            }
+
+            if use_tree {
+                let tree_data = aggregate_tree(&data);
+                print_tree_data(&tree_data, min_size);
+            } else {
+                data.retain(|alloc_info| alloc_info.size >= min_size);
+
+                if let Some(sort_by) = sort_by {
+                    sort_allocinfo(&mut data, sort_by);
+                }
+
+                let printable_lines = if max_lines <= data.len() { max_lines } else { data.len() };
+                println!("{:>10} {:>10} Tag", "Size", "Calls");
+                for info in &data[0..printable_lines] {
+                    println!("{:>10} {:>10} {}", info.size, info.calls, info.tag);
+                }
+            }
+            Ok(())
+        }
+        Err(e) => Err(format!("Error reading or parsing allocinfo: {}", e)),
+    }
+}
diff --git a/tools/alloctop/src/main.rs b/tools/alloctop/src/main.rs
new file mode 100644
index 0000000..d31f28b
--- /dev/null
+++ b/tools/alloctop/src/main.rs
@@ -0,0 +1,141 @@
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
+//! Tool to help the parsing and filtering of /proc/allocinfo
+
+use alloctop::{run, SortBy};
+use std::env;
+use std::process;
+
+fn print_help() {
+    println!("alloctop - A tool for analyzing memory allocations from /proc/allocinfo\n");
+    println!("Usage: alloctop [OPTIONS]\n");
+    println!("Options:");
+    println!("  -m, --min <size>    Only display allocations with size greater than <size>");
+    println!("  -n, --lines <num>   Only output the first <num> lines");
+    println!("  -o, --once          Display the output once and then exit.");
+    println!("  -s, --sort <s|c|t>  Sort the output by size (s), number of calls (c), or tag (t)");
+    println!("  -t, --tree          Aggregate output data by tag components. Only the \"min\"");
+    println!("                      option is implemented for this visualization\n");
+    println!("  -h, --help          Display this help message and exit");
+}
+
+#[cfg(unix)]
+fn reset_sigpipe() {
+    // SAFETY:
+    // This is safe because we are simply resetting the SIGPIPE signal handler to its default behavior.
+    // The `signal` function itself is marked as unsafe because it can globally modify process state.
+    // However, in this specific case, we are restoring the default behavior of ignoring the signal
+    // which is a well-defined and safe operation.
+    unsafe {
+        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
+    }
+}
+
+#[cfg(not(unix))]
+fn reset_sigpipe() {
+    // no-op
+}
+
+fn main() {
+    reset_sigpipe();
+
+    let args: Vec<String> = env::args().collect();
+    let mut max_lines: usize = usize::MAX;
+    let mut sort_by = None;
+    let mut min_size = 0;
+    let mut use_tree = false;
+    let mut display_once = false;
+
+    let mut i = 1;
+    while i < args.len() {
+        match args[i].as_str() {
+            "-h" | "--help" => {
+                print_help();
+                process::exit(0);
+            }
+            "-s" | "--sort" => {
+                i += 1;
+                if i < args.len() {
+                    sort_by = match args[i].as_str() {
+                        "s" => Some(SortBy::Size),
+                        "c" => Some(SortBy::Calls),
+                        "t" => Some(SortBy::Tag),
+                        _ => {
+                            eprintln!("Invalid sort option. Use 's', 'c', or 't'.");
+                            process::exit(1);
+                        }
+                    };
+                } else {
+                    eprintln!("Missing argument for --sort.");
+                    process::exit(1);
+                }
+            }
+            "-m" | "--min" => {
+                i += 1;
+                if i < args.len() {
+                    min_size = match args[i].parse::<u64>() {
+                        Ok(val) => val,
+                        Err(_) => {
+                            eprintln!("Invalid minimum size. Please provide a valid number.");
+                            process::exit(1);
+                        }
+                    };
+                } else {
+                    eprintln!("Missing argument for --min.");
+                    process::exit(1);
+                }
+            }
+            "-n" | "--lines" => {
+                i += 1;
+                if i < args.len() {
+                    max_lines = match args[i].parse::<usize>() {
+                        Ok(val) => val,
+                        Err(_) => {
+                            eprintln!("Invalid lines. Please provide a valid number.");
+                            process::exit(1);
+                        }
+                    };
+                } else {
+                    eprintln!("Missing argument for --lines.");
+                    process::exit(1);
+                }
+            }
+            "-o" | "--once" => {
+                display_once = true;
+            }
+            "-t" | "--tree" => {
+                use_tree = true;
+            }
+            _ => {
+                eprintln!("Invalid argument: {}", args[i]);
+                print_help();
+                process::exit(1);
+            }
+        }
+        i += 1;
+    }
+
+    if !display_once {
+        eprintln!("Only \"display once\" mode currently available, run with \"-o\".");
+        process::exit(1);
+    }
+
+    if let Err(e) = run(max_lines, sort_by, min_size, use_tree, alloctop::PROC_ALLOCINFO) {
+        eprintln!("{}", e);
+        process::exit(1);
+    }
+}
diff --git a/tools/alloctop/tests/tests.rs b/tools/alloctop/tests/tests.rs
new file mode 100644
index 0000000..26d7685
--- /dev/null
+++ b/tools/alloctop/tests/tests.rs
@@ -0,0 +1,271 @@
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
+#[cfg(test)]
+mod tests {
+    use alloctop::*;
+    use std::io::Write;
+    use tempfile::NamedTempFile;
+
+    /// Tests the handling of missing input files.
+    ///
+    /// This test verifies that the `run` function correctly handles cases where
+    /// the input file specified does not exist. It ensures that an error is returned
+    /// and that the error message indicates an issue with file reading.
+    #[test]
+    fn test_missing_file_handling() {
+        // Define a non-existent file path
+        let non_existent_file = "/this/file/should/not/exist.txt";
+
+        // Attempt to run the alloctop logic with the non-existent file
+        let result = run(
+            usize::MAX,         // max_lines (not relevant for this test)
+            Some(SortBy::Size), // sort_by (not relevant for this test)
+            0,                  // min_size (not relevant for this test)
+            false,              // use_tree (not relevant for this test)
+            non_existent_file,
+        );
+
+        // Assert that the result is an error
+        assert!(result.is_err());
+
+        // Optionally, check the error message to ensure it's related to file access
+        if let Err(msg) = result {
+            assert!(
+                msg.contains("Error reading or parsing allocinfo"),
+                "Error message should indicate an issue with file reading"
+            );
+        }
+    }
+
+    /// Tests parsing an empty allocinfo file.
+    ///
+    /// This test verifies that the `parse_allocinfo` function correctly handles
+    /// an empty input file. It ensures that an empty vector of `AllocInfo` is returned.
+    #[test]
+    fn test_parse_allocinfo_empty_file() {
+        let mut temp_file = NamedTempFile::new().unwrap();
+        writeln!(temp_file).unwrap();
+
+        let result = parse_allocinfo(temp_file.path().to_str().unwrap()).unwrap();
+
+        assert_eq!(result.len(), 0);
+    }
+
+    /// Tests parsing a valid allocinfo file.
+    ///
+    /// This test verifies that the `parse_allocinfo` function correctly parses
+    /// a valid allocinfo file with multiple valid lines. It checks that the correct
+    /// number of `AllocInfo` entries are parsed and that the values within each entry
+    /// are correct.
+    #[test]
+    fn test_parse_allocinfo_valid_file() {
+        let mut temp_file = NamedTempFile::new().unwrap();
+        writeln!(
+            temp_file,
+            "allocinfo - version: 1.0
+             #     <size>  <calls> <tag info>
+             1024 5 /some/tag/path
+             2048 2 /another/tag
+             512 10 /third/tag/here"
+        )
+        .unwrap();
+
+        let result = parse_allocinfo(temp_file.path().to_str().unwrap()).unwrap();
+
+        assert_eq!(result.len(), 3);
+        assert_eq!(
+            result[0],
+            AllocInfo { size: 1024, calls: 5, tag: "/some/tag/path".to_string() }
+        );
+        assert_eq!(result[1], AllocInfo { size: 2048, calls: 2, tag: "/another/tag".to_string() });
+        assert_eq!(
+            result[2],
+            AllocInfo { size: 512, calls: 10, tag: "/third/tag/here".to_string() }
+        );
+    }
+
+    /// Tests parsing an allocinfo file with invalid lines.
+    ///
+    /// This test verifies that the `parse_allocinfo` function correctly handles
+    /// invalid lines within the input file. It checks that valid lines are parsed
+    /// correctly and invalid lines are skipped, with potentially incomplete data if possible.
+    #[test]
+    fn test_parse_allocinfo_invalid_lines() {
+        let mut temp_file = NamedTempFile::new().unwrap();
+        writeln!(
+            temp_file,
+            "allocinfo - version: 1.0
+             #     <size>  <calls> <tag info>
+             1024 5 /some/tag/path
+             invalid line
+             512 abc /third/tag/here"
+        )
+        .unwrap();
+
+        let result = parse_allocinfo(temp_file.path().to_str().unwrap()).unwrap();
+
+        assert_eq!(result.len(), 2);
+        assert_eq!(
+            result[0],
+            AllocInfo { size: 1024, calls: 5, tag: "/some/tag/path".to_string() }
+        );
+        assert_eq!(
+            result[1],
+            AllocInfo { size: 512, calls: 0, tag: "/third/tag/here".to_string() }
+        );
+    }
+
+    /// Tests parsing a missing allocinfo file.
+    ///
+    /// This test verifies that the `parse_allocinfo` function correctly handles
+    /// cases where the input file does not exist. It ensures that an error is returned.
+    #[test]
+    fn test_parse_allocinfo_missing_file() {
+        let result = parse_allocinfo("nonexistent_file.txt");
+        assert!(result.is_err());
+    }
+
+    /// Tests parsing an allocinfo file with comments.
+    ///
+    /// This test verifies that the `parse_allocinfo` function correctly handles
+    /// comment lines within the input file. It ensures that comment lines are ignored
+    /// and valid lines are parsed correctly.
+    #[test]
+    fn test_parse_allocinfo_comments() {
+        let mut temp_file = NamedTempFile::new().unwrap();
+        writeln!(
+            temp_file,
+            "allocinfo - version: 1.0
+             #     <size>  <calls> <tag info># This is a comment
+             1024 5 /some/tag/path
+             # Another comment
+             512 10 /third/tag/here"
+        )
+        .unwrap();
+
+        let result = parse_allocinfo(temp_file.path().to_str().unwrap()).unwrap();
+
+        assert_eq!(result.len(), 2);
+        assert_eq!(
+            result[0],
+            AllocInfo { size: 1024, calls: 5, tag: "/some/tag/path".to_string() }
+        );
+        assert_eq!(
+            result[1],
+            AllocInfo { size: 512, calls: 10, tag: "/third/tag/here".to_string() }
+        );
+    }
+
+    /// Tests sorting allocinfo data by size.
+    ///
+    /// This test verifies that the `sort_allocinfo` function correctly sorts
+    /// a vector of `AllocInfo` entries by size in descending order.
+    #[test]
+    fn test_sort_allocinfo_by_size() {
+        let mut data = vec![
+            AllocInfo { size: 1024, calls: 5, tag: "/tag1".to_string() },
+            AllocInfo { size: 512, calls: 10, tag: "/tag2".to_string() },
+            AllocInfo { size: 2048, calls: 2, tag: "/tag3".to_string() },
+        ];
+
+        sort_allocinfo(&mut data, SortBy::Size);
+
+        assert_eq!(data[0].size, 2048);
+        assert_eq!(data[1].size, 1024);
+        assert_eq!(data[2].size, 512);
+    }
+
+    /// Tests sorting allocinfo data by number of calls.
+    ///
+    /// This test verifies that the `sort_allocinfo` function correctly sorts
+    /// a vector of `AllocInfo` entries by the number of calls in descending order.
+    #[test]
+    fn test_sort_allocinfo_by_calls() {
+        let mut data = vec![
+            AllocInfo { size: 1024, calls: 5, tag: "/tag1".to_string() },
+            AllocInfo { size: 512, calls: 10, tag: "/tag2".to_string() },
+            AllocInfo { size: 2048, calls: 2, tag: "/tag3".to_string() },
+        ];
+
+        sort_allocinfo(&mut data, SortBy::Calls);
+
+        assert_eq!(data[0].calls, 10);
+        assert_eq!(data[1].calls, 5);
+        assert_eq!(data[2].calls, 2);
+    }
+
+    /// Tests sorting allocinfo data by tag.
+    ///
+    /// This test verifies that the `sort_allocinfo` function correctly sorts
+    /// a vector of `AllocInfo` entries by tag in ascending order.
+    #[test]
+    fn test_sort_allocinfo_by_tag() {
+        let mut data = vec![
+            AllocInfo { size: 1024, calls: 5, tag: "/tag2".to_string() },
+            AllocInfo { size: 512, calls: 10, tag: "/tag3".to_string() },
+            AllocInfo { size: 2048, calls: 2, tag: "/tag1".to_string() },
+        ];
+
+        sort_allocinfo(&mut data, SortBy::Tag);
+
+        assert_eq!(data[0].tag, "/tag1");
+        assert_eq!(data[1].tag, "/tag2");
+        assert_eq!(data[2].tag, "/tag3");
+    }
+
+    /// Tests aggregating allocinfo data into a tree structure.
+    ///
+    /// This test verifies that the `aggregate_tree` function correctly aggregates
+    /// allocation data into a tree structure based on the tags. It checks that the
+    /// total size and calls are correctly summed for each node in the tree.
+    #[test]
+    fn test_aggregate_tree() {
+        let data = vec![
+            AllocInfo { size: 100, calls: 10, tag: "/A/B/C".to_string() },
+            AllocInfo { size: 200, calls: 20, tag: "/A/B".to_string() },
+            AllocInfo { size: 300, calls: 30, tag: "/A/X".to_string() },
+            AllocInfo { size: 50, calls: 5, tag: "/A/B/C".to_string() },
+        ];
+
+        let result = aggregate_tree(&data);
+
+        assert_eq!(result.get("/A"), Some(&(650, 65)));
+        assert_eq!(result.get("/A/B"), Some(&(350, 35)));
+        assert_eq!(result.get("/A/X"), Some(&(300, 30)));
+        assert_eq!(result.get("/A/B/C"), Some(&(150, 15)));
+        assert_eq!(result.get("/A/Y"), None);
+    }
+
+    /// Tests aggregating allocinfo data globally.
+    ///
+    /// This test verifies that the `aggregate_global` function correctly aggregates
+    /// allocation data into a single `AllocInfo` entry representing the total size
+    /// and number of calls across all entries.
+    #[test]
+    fn test_aggregate_global() {
+        let data = vec![
+            AllocInfo { size: 100, calls: 10, tag: "/A/B/C".to_string() },
+            AllocInfo { size: 200, calls: 20, tag: "/A/B".to_string() },
+            AllocInfo { size: 300, calls: 30, tag: "/A/X".to_string() },
+        ];
+
+        let result = aggregate_global(&data);
+
+        assert_eq!(result.size, 600);
+        assert_eq!(result.calls, 60);
+    }
+}
```

