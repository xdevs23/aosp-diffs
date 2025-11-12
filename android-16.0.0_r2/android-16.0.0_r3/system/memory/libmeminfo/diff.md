```diff
diff --git a/include/meminfo/sysmeminfo.h b/include/meminfo/sysmeminfo.h
index 6e410b3..0f67b95 100644
--- a/include/meminfo/sysmeminfo.h
+++ b/include/meminfo/sysmeminfo.h
@@ -59,6 +59,7 @@ class SysMemInfo final {
     static constexpr const char kMemInactiveFile[] = "Inactive(file):";
     static constexpr const char kMemCmaTotal[] = "CmaTotal:";
     static constexpr const char kMemCmaFree[] = "CmaFree:";
+    static constexpr const char kMemSwapCached[] = "SwapCached:";
 
     static constexpr std::initializer_list<std::string_view> kDefaultSysMemInfoTags = {
             SysMemInfo::kMemTotal,      SysMemInfo::kMemFree,         SysMemInfo::kMemBuffers,
@@ -69,7 +70,7 @@ class SysMemInfo final {
             SysMemInfo::kMemActive,     SysMemInfo::kMemInactive,     SysMemInfo::kMemUnevictable,
             SysMemInfo::kMemAvailable,  SysMemInfo::kMemActiveAnon,   SysMemInfo::kMemInactiveAnon,
             SysMemInfo::kMemActiveFile, SysMemInfo::kMemInactiveFile, SysMemInfo::kMemCmaTotal,
-            SysMemInfo::kMemCmaFree,
+            SysMemInfo::kMemCmaFree,    SysMemInfo::kMemSwapCached,
     };
 
     SysMemInfo() = default;
@@ -112,6 +113,7 @@ class SysMemInfo final {
     uint64_t mem_inactive_file_kb() const { return find_mem_by_tag(kMemInactiveFile); }
     uint64_t mem_cma_total_kb() const { return find_mem_by_tag(kMemCmaTotal); }
     uint64_t mem_cma_free_kb() const { return find_mem_by_tag(kMemCmaFree); }
+    uint64_t mem_swap_cached_kb() { return find_mem_by_tag(kMemSwapCached); }
     uint64_t mem_zram_kb(const char* zram_dev = nullptr) const;
     uint64_t mem_compacted_kb(const char* zram_dev = nullptr);
 
diff --git a/libelf64/tests/page_size_16kb/elf_alignment_test.cpp b/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
index 33f3aee..1691b34 100644
--- a/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
+++ b/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
@@ -79,9 +79,10 @@ class ElfAlignmentTest :public ::testing::TestWithParam<std::string> {
         // Ignore VNDK APEXes. They are prebuilts from old branches, and would
         // only be used on devices with old vendor images.
         escapeForRegex("/apex/com.android.vndk.v"),
-        // Ignore Trusty VM images as they don't run in userspace, so 16K is not
-        // required. See b/365240530 for more context.
-        escapeForRegex("/system_ext/etc/vm/trusty_vm"),
+        // Ignore Trusty VM images under */etc/vm/trusty_vm as they don't run
+        // in userspace, so 16K is not required. See b/365240530 and b/406626518
+        // for more context.
+        ".*" + escapeForRegex("/etc/vm/trusty_vm"),
         // Ignore non-Android firmware images.
         escapeForRegex("/odm/firmware/"),
         escapeForRegex("/vendor/firmware/"),
diff --git a/libmemevents/bpfprogs/Android.bp b/libmemevents/bpfprogs/Android.bp
index 68c6a14..70cce56 100644
--- a/libmemevents/bpfprogs/Android.bp
+++ b/libmemevents/bpfprogs/Android.bp
@@ -15,6 +15,7 @@ bpf {
     name: "bpfMemEvents.o",
     srcs: ["bpfMemEvents.c"],
     include_dirs: [
+        "system/bpf/include/defs",
         "system/memory/libmeminfo/libmemevents/include",
     ],
     sub_dir: "memevents",
@@ -24,7 +25,28 @@ bpf {
     name: "bpfMemEventsTest.o",
     srcs: ["bpfMemEventsTest.c"],
     include_dirs: [
+        "system/bpf/include/defs",
         "system/memory/libmeminfo/libmemevents/include",
     ],
     sub_dir: "memevents",
 }
+
+libbpf_prog {
+    name: "bpfMemEvents.bpf",
+    srcs: ["bpfMemEvents.c"],
+    header_libs: [
+        "android_bpf_defs",
+        "libmemevents_headers",
+    ],
+    relative_install_path: "memevents",
+}
+
+libbpf_prog {
+    name: "bpfMemEventsTest.bpf",
+    srcs: ["bpfMemEventsTest.c"],
+    header_libs: [
+        "android_bpf_defs",
+        "libmemevents_headers",
+    ],
+    relative_install_path: "memevents",
+}
diff --git a/libmemevents/bpfprogs/bpfMemEvents.c b/libmemevents/bpfprogs/bpfMemEvents.c
index ed727e5..2e02ce6 100644
--- a/libmemevents/bpfprogs/bpfMemEvents.c
+++ b/libmemevents/bpfprogs/bpfMemEvents.c
@@ -28,8 +28,8 @@ DEFINE_BPF_RINGBUF(ams_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_
 DEFINE_BPF_RINGBUF(lmkd_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID,
                    AID_SYSTEM, 0660)
 
-DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_ams, KVER_5_10)
-(struct mark_victim_args* args) {
+DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM,
+                     tracepoint_oom_mark_victim_ams, KVER_5_10)(struct mark_victim_args* args) {
     unsigned long long timestamp_ns = bpf_ktime_get_ns();
     struct mem_event_t* data = bpf_ams_rb_reserve();
     if (data == NULL) return 1;
@@ -54,7 +54,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_dr_start, KVER_5_10)
+                     tracepoint_vmscan_mm_vmscan_direct_reclaim_begin_lmkd, KVER_5_10)
 (struct direct_reclaim_begin_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -67,7 +67,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AI
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_end/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_dr_end, KVER_5_10)
+                     tracepoint_vmscan_mm_vmscan_direct_reclaim_end_lmkd, KVER_5_10)
 (struct direct_reclaim_end_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -80,7 +80,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_end/lmkd", AID_
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_wake/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_kswapd_wake, KVER_5_10)
+                     tracepoint_vmscan_mm_vmscan_kswapd_wake_lmkd, KVER_5_10)
 (struct kswapd_wake_args* args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -96,7 +96,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_wake/lmkd", AID_ROOT, A
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_sleep/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_kswapd_sleep, KVER_5_10)
+                     tracepoint_vmscan_mm_vmscan_kswapd_sleep_lmkd, KVER_5_10)
 (struct kswapd_sleep_args* args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -109,8 +109,9 @@ DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_sleep/lmkd", AID_ROOT,
     return 0;
 }
 
-DEFINE_BPF_PROG_KVER("tracepoint/android_vendor_lmk/android_trigger_vendor_lmk_kill/lmkd",
-                     AID_ROOT, AID_SYSTEM, tp_lmkd_vendor_lmk_kill, KVER_6_1)
+DEFINE_BPF_PROG_KVER("tracepoint/android_vendor_lmk/android_trigger_vendor_lmk_kill/lmkd", AID_ROOT,
+                     AID_SYSTEM, tracepoint_android_vendor_lmk_android_trigger_vendor_lmk_kill_lmkd,
+                     KVER_6_1)
 (struct vendor_lmk_kill_args* args) {
     struct mem_event_t* data;
     uint32_t reason = args->reason;
@@ -136,7 +137,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/android_vendor_lmk/android_trigger_vendor_lmk_k
 }
 
 DEFINE_BPF_PROG_KVER("tracepoint/kmem/mm_calculate_totalreserve_pages/lmkd", AID_ROOT, AID_SYSTEM,
-                     tp_lmkd_calculate_totalreserve_pages, KVER_6_1)
+                     tracepoint_kmem_mm_calculate_totalreserve_pages_lmkd, KVER_6_1)
 (struct calculate_totalreserve_pages_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
diff --git a/libmemevents/bpfprogs/bpfMemEventsTest.c b/libmemevents/bpfprogs/bpfMemEventsTest.c
index c3a737d..3eeb2af 100644
--- a/libmemevents/bpfprogs/bpfMemEventsTest.c
+++ b/libmemevents/bpfprogs/bpfMemEventsTest.c
@@ -26,7 +26,8 @@
 DEFINE_BPF_RINGBUF(rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID, AID_SYSTEM,
                    0660)
 
-DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams, KVER_5_10)
+DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tracepoint_oom_mark_victim,
+                     KVER_5_10)
 (struct mark_victim_args* args) {
     unsigned long long timestamp_ns = bpf_ktime_get_ns();
     struct mem_event_t* data = bpf_rb_reserve();
@@ -57,7 +58,7 @@ DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams,
  * executed manually with BPF_PROG_RUN, and the tracepoint bpf-progs do not
  * currently implement this BPF_PROG_RUN operation.
  */
-DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_oom, KVER_5_10)
+DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, skfilter_oom_kill, KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -82,7 +83,7 @@ DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_begin", AID_ROOT, AID_ROOT,
-                     tp_memevents_test_dr_begin, KVER_5_10)
+                     skfilter_direct_reclaim_begin, KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -94,7 +95,7 @@ DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_begin", AID_ROOT, AID_ROOT,
     return 0;
 }
 
-DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, tp_memevents_test_dr_end,
+DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, skfilter_direct_reclaim_end,
                      KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
@@ -107,8 +108,7 @@ DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, tp_memev
     return 0;
 }
 
-DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, tp_memevents_test_kswapd_wake,
-                     KVER_5_10)
+DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, skfilter_kswapd_wake, KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -124,8 +124,7 @@ DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, tp_memevents_te
     return 0;
 }
 
-DEFINE_BPF_PROG_KVER("skfilter/kswapd_sleep", AID_ROOT, AID_ROOT, tp_memevents_test_kswapd_sleep,
-                     KVER_5_10)
+DEFINE_BPF_PROG_KVER("skfilter/kswapd_sleep", AID_ROOT, AID_ROOT, skfilter_kswapd_sleep, KVER_5_10)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -140,7 +139,7 @@ DEFINE_BPF_PROG_KVER("skfilter/kswapd_sleep", AID_ROOT, AID_ROOT, tp_memevents_t
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/android_trigger_vendor_lmk_kill", AID_ROOT, AID_SYSTEM,
-                     tp_memevents_test_lmkd_vendor_lmk_kill, KVER_6_1)
+                     skfilter_android_trigger_vendor_lmk_kill, KVER_6_1)
 (void* __unused ctx) {
     struct mem_event_t* data;
     uint32_t reason = mocked_vendor_lmk_kill_event.event_data.vendor_kill.reason;
@@ -165,7 +164,7 @@ DEFINE_BPF_PROG_KVER("skfilter/android_trigger_vendor_lmk_kill", AID_ROOT, AID_S
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/calculate_totalreserve_pages", AID_ROOT, AID_ROOT,
-                     tp_memevents_test_calculate_totalreserve_pages, KVER_6_1)
+                     skfilter_calculate_totalreserve_pages, KVER_6_1)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
diff --git a/libmemevents/include/memevents/bpf_helpers.h b/libmemevents/include/memevents/bpf_helpers.h
index e5d414d..b6a638b 100644
--- a/libmemevents/include/memevents/bpf_helpers.h
+++ b/libmemevents/include/memevents/bpf_helpers.h
@@ -17,7 +17,7 @@
 #ifndef MEM_EVENTS_BPF_HELPERS_H_
 #define MEM_EVENTS_BPF_HELPERS_H_
 
-#include <bpf_helpers.h>
+#include <android_bpf_defs.h>
 
 static inline void read_str(char* base, uint32_t __data_loc_var, char* str, uint32_t size) {
     short offset = __data_loc_var & 0xFFFF;
diff --git a/libmeminfo_benchmark.cpp b/libmeminfo_benchmark.cpp
index 548f017..071d0c1 100644
--- a/libmeminfo_benchmark.cpp
+++ b/libmeminfo_benchmark.cpp
@@ -55,6 +55,7 @@ enum {
     MEMINFO_VMALLOC_USED,
     MEMINFO_PAGE_TABLES,
     MEMINFO_KERNEL_STACK,
+    MEMINFO_SWAP_CACHED,
     MEMINFO_COUNT
 };
 
@@ -79,11 +80,11 @@ static void get_mem_info(uint64_t mem[], const char* file) {
     buffer[len] = 0;
 
     static const char* const tags[] = {
-            "MemTotal:",     "MemFree:",    "Buffers:",     "Cached:",   "Shmem:", "Slab:",
-            "SReclaimable:", "SUnreclaim:", "SwapTotal:",   "SwapFree:", "ZRam:",  "Mapped:",
-            "VmallocUsed:",  "PageTables:", "KernelStack:", NULL};
+            "MemTotal:",     "MemFree:",    "Buffers:",     "Cached:",     "Shmem:", "Slab:",
+            "SReclaimable:", "SUnreclaim:", "SwapTotal:",   "SwapFree:",   "ZRam:",  "Mapped:",
+            "VmallocUsed:",  "PageTables:", "KernelStack:", "SwapCached:", NULL};
 
-    static const int tagsLen[] = {9, 8, 8, 7, 6, 5, 13, 11, 10, 9, 5, 7, 12, 11, 12, 0};
+    static const int tagsLen[] = {9, 8, 8, 7, 6, 5, 13, 11, 10, 9, 5, 7, 12, 11, 12, 11, 0};
 
     memset(mem, 0, sizeof(uint64_t) * 15);
     char* p = buffer;
@@ -226,7 +227,7 @@ Hugepagesize:       2048 kB)meminfo";
             SysMemInfo::kMemCached,     SysMemInfo::kMemShmem,       SysMemInfo::kMemSlab,
             SysMemInfo::kMemSReclaim,   SysMemInfo::kMemSUnreclaim,  SysMemInfo::kMemSwapTotal,
             SysMemInfo::kMemSwapFree,   SysMemInfo::kMemMapped,      SysMemInfo::kMemVmallocUsed,
-            SysMemInfo::kMemPageTables, SysMemInfo::kMemKernelStack,
+            SysMemInfo::kMemPageTables, SysMemInfo::kMemKernelStack, SysMemInfo::kMemSwapCached,
     };
 
     SysMemInfo smi;
diff --git a/libmeminfo_test.cpp b/libmeminfo_test.cpp
index 3b4d915..98fa40c 100644
--- a/libmeminfo_test.cpp
+++ b/libmeminfo_test.cpp
@@ -912,7 +912,7 @@ MemFree:         1809728 kB
 MemAvailable:    2546560 kB
 Buffers:           54736 kB
 Cached:           776052 kB
-SwapCached:            0 kB
+SwapCached:        29252 kB
 Active:           445856 kB
 Inactive:         459092 kB
 Active(anon):      78492 kB
@@ -984,6 +984,7 @@ Hugepagesize:       2048 kB)meminfo";
     EXPECT_EQ(mi.mem_inactive_file_kb(), 456852);
     EXPECT_EQ(mi.mem_cma_total_kb(), 131072);
     EXPECT_EQ(mi.mem_cma_free_kb(), 130380);
+    EXPECT_EQ(mi.mem_swap_cached_kb(), 29252);
 }
 
 TEST(SysMemInfo, TestEmptyFile) {
@@ -1035,6 +1036,7 @@ enum {
     MEMINFO_INACTIVE_FILE,
     MEMINFO_CMA_TOTAL,
     MEMINFO_CMA_FREE,
+    MEMINFO_SWAP_CACHED,
     MEMINFO_COUNT
 };
 
@@ -1044,7 +1046,7 @@ MemFree:         1809728 kB
 MemAvailable:    2546560 kB
 Buffers:           54736 kB
 Cached:           776052 kB
-SwapCached:            0 kB
+SwapCached:        29252 kB
 Active:           445856 kB
 Inactive:         459092 kB
 Active(anon):      78492 kB
@@ -1124,6 +1126,7 @@ Hugepagesize:       2048 kB)meminfo";
     EXPECT_EQ(mem[MEMINFO_INACTIVE_FILE], 456852);
     EXPECT_EQ(mem[MEMINFO_CMA_TOTAL], 131072);
     EXPECT_EQ(mem[MEMINFO_CMA_FREE], 130380);
+    EXPECT_EQ(mem[MEMINFO_SWAP_CACHED], 29252);
 }
 
 TEST(SysMemInfo, TestVmallocInfoNoMemory) {
diff --git a/libsmapinfo/smapinfo.cpp b/libsmapinfo/smapinfo.cpp
index 8fe6bee..9abfee3 100644
--- a/libsmapinfo/smapinfo.cpp
+++ b/libsmapinfo/smapinfo.cpp
@@ -20,6 +20,7 @@
 #include <sys/mman.h>
 #include <unistd.h>
 
+#include <algorithm>
 #include <chrono>
 #include <functional>
 #include <iomanip>
diff --git a/sysmeminfo.cpp b/sysmeminfo.cpp
index a36d960..8829bbe 100644
--- a/sysmeminfo.cpp
+++ b/sysmeminfo.cpp
@@ -475,7 +475,18 @@ bool ReadKernelCmaUsageKb(uint64_t* size, const std::string& cma_stats_sysfs_pat
     uint64_t totalKernelCmaUsageKb = 0;
     std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(cma_stats_sysfs_path.c_str()), closedir);
     if (!dir) {
-        LOG(ERROR) << "Failed to open CMA sysfs stats directory: " << cma_stats_sysfs_path;
+        static bool missingDirLogged = false;
+        // Kernels prior to 6.12 may not have this directory available, so log an error only once
+        // to avoid spamming the logs in that scenario.
+        //
+        // Log all other types of errors.
+        if (errno == ENOENT) {
+            if (missingDirLogged) {
+                return false;
+            }
+            missingDirLogged = true;
+        }
+        PLOG(ERROR) << "Failed to open CMA sysfs stats directory: " << cma_stats_sysfs_path;
         return false;
     }
 
diff --git a/tools/procmem.cpp b/tools/procmem.cpp
index 5eb2f55..5eb7b35 100644
--- a/tools/procmem.cpp
+++ b/tools/procmem.cpp
@@ -20,6 +20,7 @@
 #include <sys/mman.h>
 #include <unistd.h>
 
+#include <algorithm>
 #include <functional>
 #include <iostream>
 #include <sstream>
diff --git a/tools/procrank.cpp b/tools/procrank.cpp
index a5d022d..0a42b1f 100644
--- a/tools/procrank.cpp
+++ b/tools/procrank.cpp
@@ -44,6 +44,11 @@ using ::android::smapinfo::SortOrder;
               << "    -u  Sort by USS." << std::endl
               << "    -s  Sort by swap." << std::endl
               << "        (Default sort order is PSS.)" << std::endl
+              << "        Note:" << std::endl
+              << "        - Swap is the total amount of uncompressed swap memory." << std::endl
+              << "        - PSwap is uncompressed PSS in swap memory" << std::endl
+              << "        - USwap is uncompressed exclusive memory in swap" << std::endl
+              << "        - ZSwap is the actual memory cost of swap in ZRAM." << std::endl
               << "    -R  Reverse sort order (default is descending)." << std::endl
               << "    -c  Only show cached (storage backed) pages" << std::endl
               << "    -C  Only show non-cached (ram/swap backed) pages" << std::endl
```

