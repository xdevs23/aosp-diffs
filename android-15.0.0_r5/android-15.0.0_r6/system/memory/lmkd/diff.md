```diff
diff --git a/Android.bp b/Android.bp
index bce1523..9d70642 100644
--- a/Android.bp
+++ b/Android.bp
@@ -54,9 +54,7 @@ cc_binary {
     static_libs: [
         "libstatslogc",
         "liblmkd_utils",
-        "liburing",
     ],
-    include_dirs: ["bionic/libc/kernel"],
     header_libs: [
         "bpf_headers",
     ],
diff --git a/include/lmkd.h b/include/lmkd.h
index 7922d8c..54c6a08 100644
--- a/include/lmkd.h
+++ b/include/lmkd.h
@@ -245,11 +245,14 @@ static inline size_t lmkd_pack_set_subscribe(LMKD_CTRL_PACKET packet, enum async
  * Prepare LMK_PROCKILL unsolicited packet and return packet size in bytes.
  * Warning: no checks performed, caller should ensure valid parameters.
  */
-static inline size_t lmkd_pack_set_prockills(LMKD_CTRL_PACKET packet, pid_t pid, uid_t uid) {
+static inline size_t lmkd_pack_set_prockills(LMKD_CTRL_PACKET packet, pid_t pid, uid_t uid,
+                                             int rss_kb) {
     packet[0] = htonl(LMK_PROCKILL);
     packet[1] = htonl(pid);
     packet[2] = htonl(uid);
-    return 3 * sizeof(int);
+    packet[3] = htonl(rss_kb);
+
+    return 4 * sizeof(int);
 }
 
 /*
diff --git a/include/lmkd_hooks.h b/include/lmkd_hooks.h
index 259a3fd..1656ea6 100644
--- a/include/lmkd_hooks.h
+++ b/include/lmkd_hooks.h
@@ -50,6 +50,11 @@ bool lmkd_init_hook();
  */
 int lmkd_free_memory_before_kill_hook(struct proc* procp, int proc_size_pages,
                                       int proc_oom_score, int kill_reason);
+/*
+ * Invoked when LMKD has no more candidates to kill at any priority. The hook
+ * may attempt to free memory elsewhere to try to preserve system stability.
+ */
+void lmkd_no_kill_candidates_hook();
 
 #else /* LMKD_USE_HOOKS */
 
@@ -59,6 +64,7 @@ static inline int lmkd_free_memory_before_kill_hook(struct proc*, int, int,
                                                     int) {
   return 0;
 }
+static inline void lmkd_no_kill_candidates_hook() {}
 
 #endif /* LMKD_USE_HOOKS */
 
diff --git a/lmkd.cpp b/lmkd.cpp
index 2a0f69b..1030147 100644
--- a/lmkd.cpp
+++ b/lmkd.cpp
@@ -40,12 +40,12 @@
 #include <shared_mutex>
 #include <vector>
 
-#include <bpf/KernelUtils.h>
+#include <BpfSyscallWrappers.h>
+#include <android-base/unique_fd.h>
 #include <bpf/WaitForProgsLoaded.h>
 #include <cutils/properties.h>
 #include <cutils/sockets.h>
 #include <liblmkd_utils.h>
-#include <liburing.h>
 #include <lmkd.h>
 #include <lmkd_hooks.h>
 #include <log/log.h>
@@ -60,9 +60,6 @@
 #include "statslog.h"
 #include "watchdog.h"
 
-#define BPF_FD_JUST_USE_INT
-#include "BpfSyscallWrappers.h"
-
 /*
  * Define LMKD_TRACE_KILLS to record lmkd kills in kernel traces
  * to profile and correlate with OOM kills
@@ -208,11 +205,6 @@ static std::unique_ptr<android::bpf::memevents::MemEventListener> memevent_liste
 static struct timespec direct_reclaim_start_tm;
 static struct timespec kswapd_start_tm;
 
-/* io_uring for LMK_PROCS_PRIO */
-static struct io_uring lmk_io_uring_ring;
-/* IO_URING_OP_READ/WRITE opcodes were introduced only on 5.6 kernel */
-static const bool isIoUringSupported = android::bpf::isAtLeastKernelVersion(5, 6, 0);
-
 static int level_oomadj[VMPRESS_LEVEL_COUNT];
 static int mpevfd[VMPRESS_LEVEL_COUNT] = { -1, -1, -1 };
 static bool pidfd_supported;
@@ -808,9 +800,9 @@ static int ctrl_data_write(int dsock_idx, char* buf, size_t bufsz) {
  * Write the pid/uid pair over the data socket, note: all active clients
  * will receive this unsolicited notification.
  */
-static void ctrl_data_write_lmk_kill_occurred(pid_t pid, uid_t uid) {
+static void ctrl_data_write_lmk_kill_occurred(pid_t pid, uid_t uid, int64_t rss_kb) {
     LMKD_CTRL_PACKET packet;
-    size_t len = lmkd_pack_set_prockills(packet, pid, uid);
+    size_t len = lmkd_pack_set_prockills(packet, pid, uid, static_cast<int>(rss_kb));
 
     for (int i = 0; i < MAX_DATA_CONN; i++) {
         if (data_sock[i].sock >= 0 && data_sock[i].async_event_mask & 1 << LMK_ASYNC_EVENT_KILL) {
@@ -867,6 +859,7 @@ static void poll_kernel(int poll_fd) {
         int16_t min_score_adj;
         int64_t starttime;
         char* taskname = 0;
+        int64_t rss_kb;
 
         int fields_read =
                 sscanf(rd_buf,
@@ -877,9 +870,10 @@ static void poll_kernel(int poll_fd) {
 
         /* only the death of the group leader process is logged */
         if (fields_read == 10 && group_leader_pid == pid) {
-            ctrl_data_write_lmk_kill_occurred((pid_t)pid, (uid_t)uid);
-            mem_st.process_start_time_ns = starttime * (NS_PER_SEC / sysconf(_SC_CLK_TCK));
             mem_st.rss_in_bytes = rss_in_pages * pagesize;
+            rss_kb = mem_st.rss_in_bytes >> 10;
+            ctrl_data_write_lmk_kill_occurred((pid_t)pid, (uid_t)uid, rss_kb);
+            mem_st.process_start_time_ns = starttime * (NS_PER_SEC / sysconf(_SC_CLK_TCK));
 
             struct kill_stat kill_st = {
                 .uid = static_cast<int32_t>(uid),
@@ -1050,7 +1044,7 @@ static bool read_proc_status(int pid, char *buf, size_t buf_sz) {
 
     size = read_all(fd, buf, buf_sz - 1);
     close(fd);
-    if (size < 0) {
+    if (size <= 0) {
         return false;
     }
     buf[size] = 0;
@@ -1118,7 +1112,7 @@ static char *proc_get_name(int pid, char *buf, size_t buf_size) {
     }
     ret = read_all(fd, buf, buf_size - 1);
     close(fd);
-    if (ret < 0) {
+    if (ret <= 0) {
         return NULL;
     }
     buf[ret] = '\0';
@@ -1486,180 +1480,6 @@ static void cmd_target(int ntargets, LMKD_CTRL_PACKET packet) {
     }
 }
 
-static void handle_io_uring_procs_prio(const struct lmk_procs_prio& params, const int procs_count,
-                                       struct ucred* cred) {
-    struct io_uring_sqe* sqe;
-    struct io_uring_cqe* cqe;
-    int fds[PROCS_PRIO_MAX_RECORD_COUNT];
-    char buffers[PROCS_PRIO_MAX_RECORD_COUNT]
-                [256]; /* Reading proc/stat and write to proc/oom_score_adj */
-    char path[PROCFS_PATH_MAX];
-    char val[20];
-    int64_t tgid;
-    int ret;
-    int num_requests = 0;
-
-    ret = io_uring_queue_init(PROCS_PRIO_MAX_RECORD_COUNT, &lmk_io_uring_ring, 0);
-    if (ret) {
-        ALOGE("LMK_PROCS_PRIO failed to setup io_uring ring: %s", strerror(-ret));
-        return;
-    }
-
-    std::fill_n(fds, PROCS_PRIO_MAX_RECORD_COUNT, -1);
-    for (int i = 0; i < procs_count; i++) {
-        if (params.procs[i].oomadj < OOM_SCORE_ADJ_MIN ||
-            params.procs[i].oomadj > OOM_SCORE_ADJ_MAX)
-            ALOGW("Skipping invalid PROCS_PRIO oomadj=%d for pid=%d", params.procs[i].oomadj,
-                  params.procs[i].pid);
-        else if (params.procs[i].ptype < PROC_TYPE_FIRST ||
-                 params.procs[i].ptype >= PROC_TYPE_COUNT)
-            ALOGW("Skipping invalid PROCS_PRIO pid=%d for invalid process type arg %d",
-                  params.procs[i].pid, params.procs[i].ptype);
-        else {
-            snprintf(path, PROCFS_PATH_MAX, "/proc/%d/status", params.procs[i].pid);
-            fds[i] = open(path, O_RDONLY | O_CLOEXEC);
-            if (fds[i] < 0) continue;
-
-            sqe = io_uring_get_sqe(&lmk_io_uring_ring);
-            if (!sqe) {
-                ALOGE("LMK_PROCS_PRIO skipping pid (%d), failed to get SQE for read proc status",
-                      params.procs[i].pid);
-                close(fds[i]);
-                fds[i] = -1;
-                continue;
-            }
-
-            io_uring_prep_read(sqe, fds[i], &buffers[i], sizeof(buffers[i]), 0);
-            sqe->user_data = i;
-            num_requests++;
-        }
-    }
-
-    if (num_requests == 0) {
-        ALOGW("LMK_PROCS_PRIO has no read proc status requests to process");
-        goto err;
-    }
-
-    ret = io_uring_submit(&lmk_io_uring_ring);
-    if (ret <= 0 || ret != num_requests) {
-        ALOGE("Error submitting read processes' status to SQE: %s", strerror(ret));
-        goto err;
-    }
-
-    for (int i = 0; i < num_requests; i++) {
-        ret = TEMP_FAILURE_RETRY(io_uring_wait_cqe(&lmk_io_uring_ring, &cqe));
-        if (ret < 0 || !cqe) {
-            ALOGE("Failed to get CQE, in LMK_PROCS_PRIO, for read batching: %s", strerror(-ret));
-            goto err;
-        }
-        if (cqe->res < 0) {
-            ALOGE("Error in LMK_PROCS_PRIO for async proc status read operation: %s",
-                  strerror(-cqe->res));
-            continue;
-        }
-        if (cqe->user_data < 0 || static_cast<int>(cqe->user_data) > procs_count) {
-            ALOGE("Invalid LMK_PROCS_PRIO CQE read data: %llu", cqe->user_data);
-            continue;
-        }
-
-        const int procs_idx = cqe->user_data;
-        close(fds[procs_idx]);
-        fds[procs_idx] = -1;
-        io_uring_cqe_seen(&lmk_io_uring_ring, cqe);
-
-        if (parse_status_tag(buffers[procs_idx], PROC_STATUS_TGID_FIELD, &tgid) &&
-            tgid != params.procs[procs_idx].pid) {
-            ALOGE("Attempt to register a task that is not a thread group leader "
-                  "(tid %d, tgid %" PRId64 ")",
-                  params.procs[procs_idx].pid, tgid);
-            continue;
-        }
-
-        /* Open write file to prepare for write batch */
-        snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", params.procs[procs_idx].pid);
-        fds[procs_idx] = open(path, O_WRONLY | O_CLOEXEC);
-        if (fds[procs_idx] < 0) {
-            ALOGW("Failed to open %s; errno=%d: process %d might have been killed, skipping for "
-                  "LMK_PROCS_PRIO",
-                  path, errno, params.procs[procs_idx].pid);
-            continue;
-        }
-    }
-
-    /* Prepare to write the new OOM score */
-    num_requests = 0;
-    for (int i = 0; i < procs_count; i++) {
-        if (fds[i] < 0) continue;
-
-        /* gid containing AID_READPROC required */
-        /* CAP_SYS_RESOURCE required */
-        /* CAP_DAC_OVERRIDE required */
-        snprintf(buffers[i], sizeof(buffers[i]), "%d", params.procs[i].oomadj);
-        sqe = io_uring_get_sqe(&lmk_io_uring_ring);
-        if (!sqe) {
-            ALOGE("LMK_PROCS_PRIO skipping pid (%d), failed to get SQE for write",
-                  params.procs[i].pid);
-            close(fds[i]);
-            fds[i] = -1;
-            continue;
-        }
-        io_uring_prep_write(sqe, fds[i], &buffers[i], sizeof(buffers[i]), 0);
-        sqe->user_data = i;
-        num_requests++;
-    }
-
-    if (num_requests == 0) {
-        ALOGW("LMK_PROCS_PRIO has no write proc oomadj requests to process");
-        goto err;
-    }
-
-    ret = io_uring_submit(&lmk_io_uring_ring);
-    if (ret <= 0 || ret != num_requests) {
-        ALOGE("Error submitting write data to sqe: %s", strerror(ret));
-        goto err;
-    }
-
-    /* Handle async write completions for proc/<pid>/oom_score_adj */
-    for (int i = 0; i < num_requests; i++) {
-        ret = TEMP_FAILURE_RETRY(io_uring_wait_cqe(&lmk_io_uring_ring, &cqe));
-        if (ret < 0 || !cqe) {
-            ALOGE("Failed to get CQE, in LMK_PROCS_PRIO, for write batching: %s", strerror(-ret));
-            goto err;
-        }
-        if (cqe->res < 0) {
-            ALOGE("Error in LMK_PROCS_PRIO for async proc status read operation: %s",
-                  strerror(-cqe->res));
-            continue;
-        }
-        if (cqe->user_data < 0 || static_cast<int>(cqe->user_data) > procs_count) {
-            ALOGE("Invalid LMK_PROCS_PRIO CQE read data: %llu", cqe->user_data);
-            continue;
-        }
-
-        const int procs_idx = cqe->user_data;
-        close(fds[procs_idx]);
-        fds[procs_idx] = -1;
-        io_uring_cqe_seen(&lmk_io_uring_ring, cqe);
-
-        if (use_inkernel_interface) {
-            stats_store_taskname(params.procs[procs_idx].pid,
-                                 proc_get_name(params.procs[procs_idx].pid, path, sizeof(path)));
-            continue;
-        }
-
-        register_oom_adj_proc(params.procs[procs_idx], cred);
-    }
-
-    io_uring_queue_exit(&lmk_io_uring_ring);
-    return;
-
-err:
-    for (int fd : fds)
-        if (fd >= 0) close(fd);
-    io_uring_queue_exit(&lmk_io_uring_ring);
-    return;
-}
-
 static void cmd_procs_prio(LMKD_CTRL_PACKET packet, const int field_count, struct ucred* cred) {
     struct lmk_procs_prio params;
 
@@ -1669,10 +1489,8 @@ static void cmd_procs_prio(LMKD_CTRL_PACKET packet, const int field_count, struc
         return;
     }
 
-    if (isIoUringSupported) {
-        handle_io_uring_procs_prio(params, procs_count, cred);
-    } else {
-        for (int i = 0; i < procs_count; i++) apply_proc_prio(params.procs[i], cred);
+    for (int i = 0; i < procs_count; i++) {
+        apply_proc_prio(params.procs[i], cred);
     }
 }
 
@@ -2116,12 +1934,12 @@ static bool meminfo_parse_line(char *line, union meminfo *mi) {
 }
 
 static int64_t read_gpu_total_kb() {
-    static int fd = android::bpf::bpfFdGet(
-            "/sys/fs/bpf/map_gpuMem_gpu_mem_total_map", BPF_F_RDONLY);
+    static android::base::unique_fd fd(
+            android::bpf::mapRetrieveRO("/sys/fs/bpf/map_gpuMem_gpu_mem_total_map"));
     static constexpr uint64_t kBpfKeyGpuTotalUsage = 0;
     uint64_t value;
 
-    if (fd < 0) {
+    if (!fd.ok()) {
         return 0;
     }
 
@@ -2683,7 +2501,7 @@ static int kill_one_process(struct proc* procp, int min_oom_score, struct kill_i
     kill_st.free_swap_kb = get_free_swap(mi) * page_k;
     stats_write_lmk_kill_occurred(&kill_st, mem_st);
 
-    ctrl_data_write_lmk_kill_occurred((pid_t)pid, uid);
+    ctrl_data_write_lmk_kill_occurred((pid_t)pid, uid, rss_kb);
 
     result = rss_kb / page_k;
 
@@ -3430,6 +3248,10 @@ do_kill:
 
         pages_freed = find_and_kill_process(min_score_adj, NULL, &mi, &wi, &curr_tm, NULL);
 
+        if (pages_freed == 0 && min_score_adj == 0) {
+            lmkd_no_kill_candidates_hook();
+        }
+
         if (pages_freed == 0) {
             /* Rate limit kill reports when nothing was reclaimed */
             if (get_time_diff_ms(&last_report_tm, &curr_tm) < FAIL_REPORT_RLIMIT_MS) {
diff --git a/tests/lmkd_tests.cpp b/tests/lmkd_tests.cpp
index 9b70d38..0c582b7 100644
--- a/tests/lmkd_tests.cpp
+++ b/tests/lmkd_tests.cpp
@@ -42,6 +42,7 @@ using namespace android::base;
 #define LMKD_REAP_FAIL_TEMPLATE "process_mrelease %d failed"
 
 #define LMKD_KILL_LINE_START LMKD_LOGCAT_MARKER ": Kill"
+#define LMKD_KILLED_LINE_START LMKD_LOGCAT_MARKER ": Process got killed"
 #define LMKD_REAP_LINE_START LMKD_LOGCAT_MARKER ": Process"
 #define LMKD_REAP_TIME_TEMPLATE LMKD_LOGCAT_MARKER ": Process %d was reaped in %ldms"
 #define LMKD_REAP_MRELESE_ERR_MARKER ": process_mrelease"
@@ -209,6 +210,9 @@ TEST_F(LmkdTest, TargetReaping) {
         FAIL() << "Target process " << pid << " was not killed";
     }
 
+    // wait 200ms for the reaper thread to write its output in the logcat
+    usleep(200000);
+
     std::string regex = StringPrintf("((" LMKD_KILL_TEMPLATE ")|(" LMKD_REAP_TEMPLATE
                                      ")|(" LMKD_REAP_FAIL_TEMPLATE "))",
                                      pid, pid, pid);
@@ -223,8 +227,10 @@ TEST_F(LmkdTest, TargetReaping) {
     long rss, swap;
     ASSERT_TRUE(ParseProcSize(line, rss, swap)) << "Kill report format is invalid";
 
+    line_start = 0;
+retry:
     // find reap duration report
-    line_start = logcat_out.find(LMKD_REAP_LINE_START);
+    line_start = logcat_out.find(LMKD_REAP_LINE_START, line_start);
     if (line_start == std::string::npos) {
         // Target might have exited before reaping started
         line_start = logcat_out.find(LMKD_REAP_MRELESE_ERR_MARKER);
@@ -240,6 +246,11 @@ TEST_F(LmkdTest, TargetReaping) {
     line_end = logcat_out.find('\n', line_start);
     line = logcat_out.substr(
             line_start, line_end == std::string::npos ? std::string::npos : line_end - line_start);
+    if (line.find(LMKD_KILLED_LINE_START) != std::string::npos) {
+        // we found process kill report, keep looking for reaping report
+        line_start = line_end;
+        goto retry;
+    }
     long reap_time;
     ASSERT_TRUE(ParseReapTime(line, pid, reap_time) && reap_time >= 0)
             << "Reaping time report format is invalid";
```

