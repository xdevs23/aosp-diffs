```diff
diff --git a/abench.sh b/abench.sh
new file mode 100755
index 0000000..9f4f7d0
--- /dev/null
+++ b/abench.sh
@@ -0,0 +1,149 @@
+#!/bin/bash
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+set -e
+
+unset TRACE_FILE
+unset QUERY_FILE
+unset WORKLOAD
+unset SET_ROOT
+unset PERFETTO_CONFIG_FILE
+unset PERFETTO_PID
+unset SERIAL
+
+
+function help {
+  echo "Usage: $0 [OPTION]..."
+  echo "Options: "
+  echo "  -h, --help          Print this message"
+  echo "  -r, --root          Switch the target device to root"
+  echo "  -c, --config PERFETTO_CONFIG Path to file containing the Perfetto"
+  echo "                      configuration"
+  echo "  -q, --query QUERY   Path to file containing the SQL query to run on"
+  echo "                      the Perfetto trace with trace_processor"
+  echo "  -t, --trace TRACE   Path to which the Perfetto trace will be written to"
+  echo "  -w, --workload WORKLOAD Benchmark to run Dittobench with"
+  echo "  -s, --serial SERIAL Serial address for ADB"
+}
+
+
+while [ "$#" -gt "0" ]; do
+  case $1 in
+    -w|--workload)
+      WORKLOAD="$2"
+      shift
+      shift
+      ;;
+    -q|--query)
+      QUERY_FILE="$2"
+      shift
+      shift
+      ;;
+    -t|--trace)
+      TRACE_FILE="$2"
+      shift
+      shift
+      ;;
+    -c|--config)
+      PERFETTO_CONFIG_FILE="$2"
+      shift
+      shift
+      ;;
+    -s|--serial)
+      SERIAL="-s $2"
+      shift
+      shift
+      ;;
+    -r|--root)
+      SET_ROOT=1
+      shift
+      ;;
+    -h|--help)
+      help
+      exit 0
+      shift
+      ;;
+    -*|--*)
+      echo "Unknown option $1"
+      help
+      exit 1
+      ;;
+  esac
+done
+
+
+if [ -z "${ANDROID_HOST_OUT}" ] ; then
+  echo "This script requires an Android environment. It needs to be run from an"
+  echo "Android repository after the initialization scripts:"
+  echo "$ source build/envsetup.sh"
+  echo "$ lunch aosp_cf_x86_64_phone-trunk_staging-userdebug"
+  exit 1
+fi
+
+
+# If the user specified a WORKLOAD, make sure that Dittobench is built, better
+# before enabling tracing.
+if [ ! -z "${WORKLOAD}" ] ; then
+  if [ ! -z "${SET_ROOT}" ] ; then
+    adb ${SERIAL} shell whoami | grep root || adb ${SERIAL} root
+    sleep 2
+  fi
+
+  m dittobench
+  adb ${SERIAL} push ${ANDROID_PRODUCT_OUT}/system/bin/dittobench /data/local/tmp/
+fi
+
+
+if [ ! -z "${PERFETTO_CONFIG_FILE}" ] ; then
+  if [ -z "${TRACE_FILE}" ] ; then
+    TRACE_FILE=$(mktemp)
+    echo "Using temporary trace file path: \"${TRACE_FILE}\""
+  fi
+  ${ANDROID_BUILD_TOP}/external/perfetto/tools/record_android_trace ${SERIAL} --no-open \
+    -c ${PERFETTO_CONFIG_FILE} \
+    -o ${TRACE_FILE} &
+  PERFETTO_PID=$!
+
+  echo "Perfetto started (${PERFETTO_PID}), cooling down..."
+  sleep 5
+fi
+
+
+if [ ! -z "${WORKLOAD}" ] ; then
+  adb ${SERIAL} shell /data/local/tmp/dittobench -w ${WORKLOAD} -f csv | column -t -s ","
+  echo "Cooldown..."
+  sleep 5
+fi
+
+
+# If there is an instance of record_android_trace, kill it gracefully, so that
+# the trace file is correctly pulled from the device.
+if [ ! -z "${PERFETTO_PID}" ] ; then
+  kill -s 15 $PERFETTO_PID # SIGTERM
+  wait $PERFETTO_PID
+fi
+
+
+if [ ! -z "${QUERY_FILE}" ] ; then
+  if [ -z "${TRACE_FILE}" ] ; then
+    echo "A TRACE file needs to be specified to run a query, unless Perfetto is"
+    echo "run as a result of setting the PERFETTO_CONFIG parameter"
+    exit 1
+  fi
+  [ ! which trace_processor_shell ] && m trace_processor_shell
+  trace_processor_shell -q ${QUERY_FILE} ${TRACE_FILE} | column -t -s ','
+fi
+
diff --git a/perfetto_configs/trace_all.pbtx b/perfetto_configs/trace_all.pbtx
new file mode 100644
index 0000000..11d3b94
--- /dev/null
+++ b/perfetto_configs/trace_all.pbtx
@@ -0,0 +1,203 @@
+buffers {
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}
+buffers {
+  size_kb: 16384
+  fill_policy: RING_BUFFER
+}
+buffers {
+  size_kb: 512
+  fill_policy: RING_BUFFER
+}
+buffers {
+  size_kb: 1045876
+  fill_policy: RING_BUFFER
+}
+buffers {
+  size_kb: 40960
+  fill_policy: DISCARD
+}
+buffers {
+  size_kb: 40960
+  fill_policy: DISCARD
+}
+data_sources {
+  config {
+    name: "android.packages_list"
+    target_buffer: 0
+  }
+}
+data_sources {
+  config {
+    name: "linux.process_stats"
+    target_buffer: 1
+    process_stats_config {
+      scan_all_processes_on_start: true
+    }
+  }
+}
+data_sources {
+  config {
+    name: "linux.sys_stats"
+    target_buffer: 2
+    sys_stats_config {
+      meminfo_period_ms: 5000
+      meminfo_counters: MEMINFO_ACTIVE_ANON
+      meminfo_counters: MEMINFO_ACTIVE_FILE
+      meminfo_counters: MEMINFO_INACTIVE_ANON
+      meminfo_counters: MEMINFO_INACTIVE_FILE
+      meminfo_counters: MEMINFO_KERNEL_STACK
+      meminfo_counters: MEMINFO_MLOCKED
+      meminfo_counters: MEMINFO_SHMEM
+      meminfo_counters: MEMINFO_SLAB
+      meminfo_counters: MEMINFO_SLAB_UNRECLAIMABLE
+      meminfo_counters: MEMINFO_VMALLOC_USED
+      meminfo_counters: MEMINFO_MEM_FREE
+      meminfo_counters: MEMINFO_SWAP_FREE
+    }
+  }
+}
+data_sources {
+  config {
+    name: "linux.process_stats"
+    target_buffer: 2
+    process_stats_config {
+      proc_stats_poll_ms: 30000
+      quirks: DISABLE_ON_DEMAND
+    }
+  }
+}
+data_sources {
+  config {
+    name: "linux.ftrace"
+    target_buffer: 3
+    ftrace_config {
+      buffer_size_kb: 131072
+      symbolize_ksyms: true
+      ftrace_events: "ftrace/print"
+      atrace_apps: "lmkd"
+      ftrace_events: "lowmemorykiller/lowmemory_kill"
+      ftrace_events: "oom/oom_score_adj_update"
+      ftrace_events: "oom/mark_victim"
+      ftrace_events: "gpu_mem/gpu_mem_total"
+      ftrace_events: "dmabuf_heap/dma_heap_stat"
+      ftrace_events: "ion/ion_stat"
+      ftrace_events: "kmem/ion_heap_grow"
+      ftrace_events: "kmem/ion_heap_shrink"
+      ftrace_events: "rss_stat"
+      ftrace_events: "fastrpc/fastrpc_dma_stat"
+      ftrace_events: "power/suspend_resume"
+      ftrace_events: "sched/sched_blocked_reason"
+      ftrace_events: "sched/sched_process_free"
+      ftrace_events: "sched/sched_switch"
+      ftrace_events: "task/task_newtask"
+      ftrace_events: "task/task_rename"
+      ftrace_events: "sched/sched_waking"
+      ftrace_events: "sched/sched_wakeup"
+      ftrace_events: "sched/sched_wakeup_new"
+      ftrace_events: "irq/irq_handler_entry"
+      ftrace_events: "irq/irq_handler_exit"
+      ftrace_events: "irq/softirq_entry"
+      ftrace_events: "irq/softirq_exit"
+      ftrace_events: "irq/softirq_raise"
+      ftrace_events: "irq/ipi_entry"
+      ftrace_events: "irq/ipi_exit"
+      ftrace_events: "irq/ipi_raise"
+      ftrace_events: "workqueue/workqueue_activate_work"
+      ftrace_events: "workqueue/workqueue_execute_end"
+      ftrace_events: "workqueue/workqueue_execute_start"
+      ftrace_events: "workqueue/workqueue_queue_work"
+      ftrace_events: "vmscan/mm_vmscan_kswapd_wake"
+      ftrace_events: "vmscan/mm_vmscan_kswapd_sleep"
+      ftrace_events: "vmscan/mm_vmscan_direct_reclaim_begin"
+      ftrace_events: "vmscan/mm_vmscan_direct_reclaim_end"
+      ftrace_events: "compaction/mm_compaction_begin"
+      ftrace_events: "compaction/mm_compaction_end"
+      ftrace_events: "f2fs/f2fs_iostat"
+      ftrace_events: "f2fs/f2fs_iostat_latency"
+      ftrace_events: "filemap/mm_filemap_add_to_page_cache"
+      ftrace_events: "filemap/mm_filemap_delete_from_page_cache"
+      atrace_categories: "am"
+      atrace_categories: "camera"
+      atrace_categories: "ss"
+      atrace_categories: "dalvik"
+      atrace_categories: "bionic"
+      atrace_categories: "aidl"
+      atrace_categories: "binder_driver"
+      atrace_categories: "disk"
+      atrace_categories: "freq"
+      atrace_categories: "gfx"
+      atrace_categories: "hal"
+      atrace_categories: "res"
+      atrace_categories: "sched"
+      atrace_categories: "view"
+      atrace_categories: "wm"
+      atrace_categories: "thermal"
+      atrace_categories: "input"
+      atrace_apps: "system_server"
+      atrace_apps: "com.android.systemui"
+      atrace_apps: "com.google.android.apps.nexuslauncher"
+      atrace_apps: "com.google.android.GoogleCamera"
+      atrace_apps: "com.android.settings"
+      atrace_apps: "com.google.android.gms"
+      atrace_apps: "com.google.android.gms.persistent"
+      atrace_apps: "com.google.android.apps.betterbug"
+      atrace_apps: "com.google.android.apps.betterbug.partners"
+      atrace_apps: "com.google.android.apps.internal.betterbug"
+      atrace_apps: "com.google.android.apps.maps"
+      atrace_apps: "com.google.android.apps.searchlite"
+      atrace_apps: "com.google.android.apps.photos"
+      atrace_apps: "com.google.android.apps.magazines"
+      atrace_apps: "com.google.android.apps.messaging"
+      atrace_apps: "com.google.android.apps.photosgo"
+      atrace_apps: "com.google.android.apps.tv.launcherx"
+      atrace_apps: "com.google.android.gm"
+      atrace_apps: "com.google.android.wearable.app"
+      atrace_apps: "com.google.android.apps.freighter"
+      atrace_apps: "com.google.android.apps.gmm.qp"
+      atrace_apps: "com.google.android.apps.subscriptions.red"
+      atrace_apps: "com.google.android.dialer"
+      atrace_apps: "com.google.android.apps.gmm"
+      atrace_apps: "com.google.android.googlequicksearchbox"
+      atrace_apps: "com.google.android.apps.dynamite"
+      compact_sched {
+        enabled: true
+      }
+    }
+  }
+}
+data_sources {
+  config {
+    name: "android.surfaceflinger.frametimeline"
+    target_buffer: 3
+  }
+}
+data_sources {
+  config {
+    name: "android.log"
+    target_buffer: 5
+    android_log_config {
+      log_ids: LID_DEFAULT
+      log_ids: LID_SYSTEM
+      log_ids: LID_EVENTS
+      log_ids: LID_CRASH
+    }
+  }
+}
+data_sources {
+  config {
+    name: "track_event"
+    track_event_config {
+      enabled_categories: "frameworks_cat"
+    }
+  }
+}
+duration_ms: 100000
+enable_extra_guardrails: false
+statsd_metadata {
+}
+bugreport_score: 10
+statsd_logging: STATSD_LOGGING_DISABLED
+trace_uuid_msb: -1144811896348994114
+trace_uuid_lsb: 4198742672997587126
diff --git a/perfetto_queries/all_slices.sql b/perfetto_queries/all_slices.sql
new file mode 100644
index 0000000..6ad84c7
--- /dev/null
+++ b/perfetto_queries/all_slices.sql
@@ -0,0 +1,6 @@
+SELECT
+  *
+FROM
+  slice
+WHERE 1=1
+LIMIT 1000
diff --git a/perfetto_queries/priority_inversion.sql b/perfetto_queries/priority_inversion.sql
new file mode 100644
index 0000000..f14ac41
--- /dev/null
+++ b/perfetto_queries/priority_inversion.sql
@@ -0,0 +1,21 @@
+INCLUDE PERFETTO MODULE slices.with_context;
+
+SELECT
+  process_name,
+  thread_name,
+  name AS instruction_name,
+  MIN(dur) AS duration_min_ns,
+  AVG(dur) AS duration_avg_ns,
+  MAX(dur) AS duration_max_ns
+FROM thread_slice as slice
+WHERE 1=1
+  AND ( 0=1
+    OR thread_name LIKE "%High_%"
+    OR thread_name LIKE "%Mid_%"
+    OR thread_name LIKE "%Low_%"
+  )
+  AND name = "lock"
+GROUP BY
+  process_name, thread_name, name
+ORDER BY
+  process_name, thread_name, name
diff --git a/src/syscall.cpp b/src/syscall.cpp
index c3e4073..ae2a216 100644
--- a/src/syscall.cpp
+++ b/src/syscall.cpp
@@ -86,43 +86,6 @@ int64_t Syscall::ReadLink(const std::string& path_name, char* buf, int64_t bufsi
   return readlink(path_name.c_str(), buf, bufsiz);
 }
 
-#ifndef __NR_sched_setattr
-
-/* Define all the __NR_sched_setattr syscall numbers for every architecture */
-
-#ifdef __x86_64__
-#define __NR_sched_setattr 314
-#endif
-
-#ifdef __i386__
-#define __NR_sched_setattr 351
-#endif
-
-#ifdef __arm__
-#define __NR_sched_setattr 380
-#endif
-
-/* If none of the architecture above have been matched, then use the
- * asm-generic/unistd.h definition 274, which also matches the aarch64
- * definition of __NR_sched_setattr. */
-#ifndef __NR_sched_setattr
-#define __NR_sched_setattr 274
-#endif
-
-#else /* __NR_sched_setattr */
-
-/* Make sure the __NR_sched_setattr syscall numbers are consistent with the
-Linux implementation */
-
-#if ((defined(__x86_64__) && __NR_sched_setattr != 314) || \
-     (defined(__i386__) && __NR_sched_setattr != 351) ||   \
-     (defined(__arm__) && __NR_sched_setattr != 380)) &&   \
-    __NR_sched_setattr != 274 /* aarch64 and asm-generic/unistd.h */
-#error "Wrong definition of __NR_sched_setattr"
-#endif
-
-#endif /* __NR_sched_setattr */
-
 int Syscall::SchedSetattr(pid_t pid, const SchedAttr__& attr, unsigned int flags) {
   long ret = syscall(__NR_sched_setattr, pid, &attr, flags);
   if (ret == -1) {
```

