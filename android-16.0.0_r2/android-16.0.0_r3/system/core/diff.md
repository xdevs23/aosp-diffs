```diff
diff --git a/bootstat/Android.bp b/bootstat/Android.bp
index 0c8760c2d1..f4248e1320 100644
--- a/bootstat/Android.bp
+++ b/bootstat/Android.bp
@@ -67,9 +67,6 @@ cc_binary {
     name: "bootstat",
     defaults: ["bootstat_defaults"],
     static_libs: ["libbootstat"],
-    shared_libs: [
-        "libstatslog"
-    ],
     init_rc: ["bootstat.rc"],
     product_variables: {
         debuggable: {
@@ -77,6 +74,15 @@ cc_binary {
         },
     },
     srcs: ["bootstat.cpp"],
+    generated_sources: [
+        "statslog_bootstats.cpp",
+    ],
+    generated_headers: [
+        "statslog_bootstats.h",
+    ],
+    shared_libs: [
+        "libstatssocket",
+    ],
 }
 
 // Native tests
@@ -98,3 +104,30 @@ cc_test {
         unit_test: true,
     },
 }
+
+// StatsD atom logging
+//------------------------------------------------------------------------------
+genrule {
+    name: "statslog_bootstats.h",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen)" +
+        " --header $(genDir)/statslog_bootstats.h" +
+        " --module bootstats" +
+        " --namespace android,util,bootstats",
+    out: [
+        "statslog_bootstats.h",
+    ],
+}
+
+genrule {
+    name: "statslog_bootstats.cpp",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen)" +
+        " --cpp $(genDir)/statslog_bootstats.cpp" +
+        " --module bootstats" +
+        " --namespace android,util,bootstats" +
+        " --importHeader statslog_bootstats.h",
+    out: [
+        "statslog_bootstats.cpp",
+    ],
+}
diff --git a/bootstat/bootstat.cpp b/bootstat/bootstat.cpp
index 96c5b81462..64f1ca4a84 100644
--- a/bootstat/bootstat.cpp
+++ b/bootstat/bootstat.cpp
@@ -46,7 +46,7 @@
 #include <android/log.h>
 #include <cutils/android_reboot.h>
 #include <cutils/properties.h>
-#include <statslog.h>
+#include <statslog_bootstats.h>
 
 #include "boot_event_record_store.h"
 
@@ -62,78 +62,80 @@ struct AtomInfo {
 const std::unordered_map<std::string_view, AtomInfo> kBootEventToAtomInfo = {
     // ELAPSED_TIME
     {"ro.boottime.init",
-     {android::util::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__ANDROID_INIT_STAGE_1}},
+     {android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__ANDROID_INIT_STAGE_1}},
     {"boot_complete",
-     {android::util::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__BOOT_COMPLETE}},
+     {android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__BOOT_COMPLETE}},
     {"boot_complete_no_encryption",
-     {android::util::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__BOOT_COMPLETE_NO_ENCRYPTION}},
+     {android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__BOOT_COMPLETE_NO_ENCRYPTION}},
     {"factory_reset_boot_complete",
-     {android::util::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__FACTORY_RESET_BOOT_COMPLETE}},
+     {android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__FACTORY_RESET_BOOT_COMPLETE}},
     {"factory_reset_boot_complete_no_encryption",
-     {android::util::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
-      android::util::
+     {android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
+      android::util::bootstats::
           BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__FACTORY_RESET_BOOT_COMPLETE_NO_ENCRYPTION}},
     {"ota_boot_complete",
-     {android::util::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__OTA_BOOT_COMPLETE}},
+     {android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__OTA_BOOT_COMPLETE}},
     {"ota_boot_complete_no_encryption",
-     {android::util::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__OTA_BOOT_COMPLETE_NO_ENCRYPTION}},
+     {android::util::bootstats::BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
+      android::util::bootstats::
+          BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__OTA_BOOT_COMPLETE_NO_ENCRYPTION}},
     // DURATION
     {"absolute_boot_time",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__ABSOLUTE_BOOT_TIME}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__ABSOLUTE_BOOT_TIME}},
     {"boottime.bootloader.1BLE",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_FIRST_STAGE_EXEC}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_FIRST_STAGE_EXEC}},
     {"boottime.bootloader.1BLL",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_FIRST_STAGE_LOAD}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_FIRST_STAGE_LOAD}},
     {"boottime.bootloader.KL",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_KERNEL_LOAD}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_KERNEL_LOAD}},
     {"boottime.bootloader.2BLE",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_SECOND_STAGE_EXEC}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_SECOND_STAGE_EXEC}},
     {"boottime.bootloader.2BLL",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_SECOND_STAGE_LOAD}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_SECOND_STAGE_LOAD}},
     {"boottime.bootloader.SW",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_UI_WAIT}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_UI_WAIT}},
     {"boottime.bootloader.total",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_TOTAL}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__BOOTLOADER_TOTAL}},
     {"boottime.init.cold_boot_wait",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__COLDBOOT_WAIT}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__COLDBOOT_WAIT}},
     {"time_since_factory_reset",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__FACTORY_RESET_TIME_SINCE_RESET}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__FACTORY_RESET_TIME_SINCE_RESET}},
     {"ro.boottime.init.first_stage",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__ANDROID_INIT_STAGE_1}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__ANDROID_INIT_STAGE_1}},
     {"ro.boottime.init.selinux",
-     {android::util::BOOT_TIME_EVENT_DURATION_REPORTED,
-      android::util::BOOT_TIME_EVENT_DURATION__EVENT__SELINUX_INIT}},
+     {android::util::bootstats::BOOT_TIME_EVENT_DURATION_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_DURATION__EVENT__SELINUX_INIT}},
     // UTC_TIME
     {"factory_reset",
-     {android::util::BOOT_TIME_EVENT_UTC_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_RESET_TIME}},
+     {android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_RESET_TIME}},
     {"factory_reset_current_time",
-     {android::util::BOOT_TIME_EVENT_UTC_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_CURRENT_TIME}},
+     {android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_CURRENT_TIME}},
     {"factory_reset_record_value",
-     {android::util::BOOT_TIME_EVENT_UTC_TIME_REPORTED,
-      android::util::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_RECORD_VALUE}},
+     {android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME_REPORTED,
+      android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_RECORD_VALUE}},
     // ERROR_CODE
     {"factory_reset_current_time_failure",
-     {android::util::BOOT_TIME_EVENT_ERROR_CODE_REPORTED,
-      android::util::BOOT_TIME_EVENT_ERROR_CODE__EVENT__FACTORY_RESET_CURRENT_TIME_FAILURE}},
+     {android::util::bootstats::BOOT_TIME_EVENT_ERROR_CODE_REPORTED,
+      android::util::bootstats::
+          BOOT_TIME_EVENT_ERROR_CODE__EVENT__FACTORY_RESET_CURRENT_TIME_FAILURE}},
 };
 
 // Scans the boot event record store for record files and logs each boot event
@@ -146,14 +148,14 @@ void LogBootEvents() {
     const auto& name = event.first;
     const auto& info = kBootEventToAtomInfo.find(name);
     if (info != kBootEventToAtomInfo.end()) {
-      if (info->second.atom == android::util::BOOT_TIME_EVENT_ERROR_CODE_REPORTED) {
-        android::util::stats_write(static_cast<int32_t>(info->second.atom),
-                                   static_cast<int32_t>(info->second.event),
-                                   static_cast<int32_t>(event.second));
+      if (info->second.atom == android::util::bootstats::BOOT_TIME_EVENT_ERROR_CODE_REPORTED) {
+        android::util::bootstats::stats_write(static_cast<int32_t>(info->second.atom),
+                                              static_cast<int32_t>(info->second.event),
+                                              static_cast<int32_t>(event.second));
       } else {
-        android::util::stats_write(static_cast<int32_t>(info->second.atom),
-                                   static_cast<int32_t>(info->second.event),
-                                   static_cast<int64_t>(event.second));
+        android::util::bootstats::stats_write(static_cast<int32_t>(info->second.atom),
+                                              static_cast<int32_t>(info->second.event),
+                                              static_cast<int64_t>(event.second));
       }
     } else {
       notSupportedEvents.push_back(name);
@@ -422,7 +424,7 @@ const std::map<std::string, int32_t> kBootReasonMap = {
     {"reboot,mount_userdata_failed", 190},
     {"reboot,forcedsilent", 191},
     {"reboot,forcednonsilent", 192},
-    {"reboot,thermal,tj", 193},
+    {"reboot,thermal,tj.*", 193},
     {"reboot,emergency", 194},
     {"reboot,factory", 195},
     {"reboot,fastboot", 196},
@@ -470,6 +472,7 @@ const std::map<std::string, int32_t> kBootReasonMap = {
     {"reboot,fship.*", 238},
     {"reboot,ocp,.*", 239},
     {"reboot,ntc,pmic,sub", 240},
+    {"reboot,telemtemp,pmic,main", 241},
 };
 
 // Converts a string value representing the reason the system booted to an
@@ -1271,10 +1274,16 @@ void LogBootInfoToStatsd(std::chrono::milliseconds end_time,
                          double time_since_last_boot_sec) {
   auto reason = android::base::GetProperty(bootloader_reboot_reason_property, "<EMPTY>");
   auto system_reason = android::base::GetProperty(system_reboot_reason_property, "<EMPTY>");
-  android::util::stats_write(android::util::BOOT_SEQUENCE_REPORTED, reason.c_str(),
-                             system_reason.c_str(), end_time.count(), total_duration.count(),
-                             (int64_t)bootloader_duration_ms,
-                             (int64_t)time_since_last_boot_sec * 1000);
+  auto system_reason_parts = android::base::Split(system_reason, ",");
+  std::string main_reason, sub_reason, detail;
+  main_reason = (system_reason_parts.size() > 0) ? system_reason_parts[0] : "";
+  sub_reason = (system_reason_parts.size() > 1) ? system_reason_parts[1] : "";
+  detail = (system_reason_parts.size() > 2) ? system_reason_parts[2] : "";
+  android::util::bootstats::stats_write(
+      android::util::bootstats::BOOT_SEQUENCE_REPORTED, reason.c_str(), system_reason.c_str(),
+      end_time.count(), total_duration.count(), (int64_t)bootloader_duration_ms,
+      (int64_t)time_since_last_boot_sec * 1000,
+      main_reason.c_str(), sub_reason.c_str(), detail.c_str());
 }
 
 void SetSystemBootReason() {
@@ -1427,10 +1436,11 @@ void RecordFactoryReset() {
   if (current_time_utc < 0) {
     // UMA does not display negative values in buckets, so convert to positive.
     // Logging via BootEventRecordStore.
-    android::util::stats_write(
-        static_cast<int32_t>(android::util::BOOT_TIME_EVENT_ERROR_CODE_REPORTED),
+    android::util::bootstats::stats_write(
+        static_cast<int32_t>(android::util::bootstats::BOOT_TIME_EVENT_ERROR_CODE_REPORTED),
         static_cast<int32_t>(
-            android::util::BOOT_TIME_EVENT_ERROR_CODE__EVENT__FACTORY_RESET_CURRENT_TIME_FAILURE),
+            android::util::bootstats::
+                BOOT_TIME_EVENT_ERROR_CODE__EVENT__FACTORY_RESET_CURRENT_TIME_FAILURE),
         static_cast<int32_t>(std::abs(current_time_utc)));
 
     // Logging via BootEventRecordStore to see if using android::metricslogger::LogHistogram
@@ -1439,10 +1449,10 @@ void RecordFactoryReset() {
                                            std::abs(current_time_utc));
     return;
   } else {
-    android::util::stats_write(
-        static_cast<int32_t>(android::util::BOOT_TIME_EVENT_UTC_TIME_REPORTED),
+    android::util::bootstats::stats_write(
+        static_cast<int32_t>(android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME_REPORTED),
         static_cast<int32_t>(
-            android::util::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_CURRENT_TIME),
+            android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_CURRENT_TIME),
         static_cast<int64_t>(current_time_utc));
 
     // Logging via BootEventRecordStore to see if using android::metricslogger::LogHistogram
@@ -1463,10 +1473,10 @@ void RecordFactoryReset() {
   // Calculate and record the difference in time between now and the
   // factory_reset time.
   time_t factory_reset_utc = record.second;
-  android::util::stats_write(
-      static_cast<int32_t>(android::util::BOOT_TIME_EVENT_UTC_TIME_REPORTED),
+  android::util::bootstats::stats_write(
+      static_cast<int32_t>(android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME_REPORTED),
       static_cast<int32_t>(
-          android::util::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_RECORD_VALUE),
+          android::util::bootstats::BOOT_TIME_EVENT_UTC_TIME__EVENT__FACTORY_RESET_RECORD_VALUE),
       static_cast<int64_t>(factory_reset_utc));
 
   // Logging via BootEventRecordStore to see if using android::metricslogger::LogHistogram
diff --git a/debuggerd/Android.bp b/debuggerd/Android.bp
index 0e62ceb8f6..16b3e779de 100644
--- a/debuggerd/Android.bp
+++ b/debuggerd/Android.bp
@@ -581,6 +581,41 @@ prebuilt_etc {
     },
 }
 
+prebuilt_etc {
+    name: "crash_dump.no_mmap_mprotect_prctl.policy",
+    sub_dir: "seccomp_policy",
+    filename_from_src: true,
+    arch: {
+        arm: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm.policy",
+            required: [
+                "crash_dump.policy_no_mmap_mprotect_prctl_other",
+            ],
+        },
+        arm64: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm64.policy",
+            required: [
+                "crash_dump.policy_no_mmap_mprotect_prctl_other",
+            ],
+        },
+        riscv64: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.riscv64.policy",
+        },
+        x86: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86.policy",
+            required: [
+                "crash_dump.policy_no_mmap_mprotect_prctl_other",
+            ],
+        },
+        x86_64: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86_64.policy",
+            required: [
+                "crash_dump.policy_no_mmap_mprotect_prctl_other",
+            ],
+        },
+    },
+}
+
 // This installs the "other" architecture (so 32-bit on 64-bit device).
 prebuilt_etc {
     name: "crash_dump.policy_other",
@@ -604,3 +639,26 @@ prebuilt_etc {
         },
     },
 }
+
+prebuilt_etc {
+    name: "crash_dump.policy_no_mmap_mprotect_prctl_other",
+    sub_dir: "seccomp_policy",
+    filename_from_src: true,
+    arch: {
+        arm: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm64.policy",
+        },
+        arm64: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm.policy",
+        },
+        riscv64: {
+            enabled: false,
+        },
+        x86: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86_64.policy",
+        },
+        x86_64: {
+            src: "seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86.policy",
+        },
+    },
+}
diff --git a/debuggerd/crash_dump.cpp b/debuggerd/crash_dump.cpp
index 92d81b326d..6b83df886f 100644
--- a/debuggerd/crash_dump.cpp
+++ b/debuggerd/crash_dump.cpp
@@ -302,7 +302,7 @@ static void ParseArgs(int argc, char** argv, pid_t* pseudothread_tid, DebuggerdD
 static void ReadCrashInfo(unique_fd& fd, siginfo_t* siginfo,
                           std::unique_ptr<unwindstack::Regs>* regs, ProcessInfo* process_info,
                           bool* recoverable_crash) {
-  std::aligned_storage<sizeof(CrashInfo) + 1, alignof(CrashInfo)>::type buf;
+  std::aligned_storage<sizeof(CrashInfo) + 1, alignof(CrashInfo)>::type buf = {};
   CrashInfo* crash_info = reinterpret_cast<CrashInfo*>(&buf);
   ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), &buf, sizeof(buf)));
   *recoverable_crash = false;
@@ -310,19 +310,19 @@ static void ReadCrashInfo(unique_fd& fd, siginfo_t* siginfo,
     PLOG(FATAL) << "failed to read target ucontext";
   }
   ssize_t expected_size = 0;
-  switch (crash_info->header.version) {
+  switch (crash_info->c.version) {
     case 1:
     case 2:
     case 3:
-      expected_size = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataStatic);
+      expected_size = sizeof(CrashInfoDataCommon);
       break;
 
     case 4:
-      expected_size = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataDynamic);
+      expected_size = sizeof(CrashInfo);
       break;
 
     default:
-      LOG(FATAL) << "unexpected CrashInfo version: " << crash_info->header.version;
+      LOG(FATAL) << "unexpected CrashInfo version: " << crash_info->c.version;
       break;
   }
 
@@ -331,24 +331,24 @@ static void ReadCrashInfo(unique_fd& fd, siginfo_t* siginfo,
                 << expected_size;
   }
 
-  switch (crash_info->header.version) {
+  switch (crash_info->c.version) {
     case 4:
-      process_info->fdsan_table_address = crash_info->data.d.fdsan_table_address;
-      process_info->gwp_asan_state = crash_info->data.d.gwp_asan_state;
-      process_info->gwp_asan_metadata = crash_info->data.d.gwp_asan_metadata;
-      process_info->scudo_stack_depot = crash_info->data.d.scudo_stack_depot;
-      process_info->scudo_stack_depot_size = crash_info->data.d.scudo_stack_depot_size;
-      process_info->scudo_region_info = crash_info->data.d.scudo_region_info;
-      process_info->scudo_ring_buffer = crash_info->data.d.scudo_ring_buffer;
-      process_info->scudo_ring_buffer_size = crash_info->data.d.scudo_ring_buffer_size;
-      *recoverable_crash = crash_info->data.d.recoverable_crash;
-      process_info->crash_detail_page = crash_info->data.d.crash_detail_page;
+      process_info->fdsan_table_address = crash_info->d.fdsan_table_address;
+      process_info->gwp_asan_state = crash_info->d.gwp_asan_state;
+      process_info->gwp_asan_metadata = crash_info->d.gwp_asan_metadata;
+      process_info->scudo_stack_depot = crash_info->d.scudo_stack_depot;
+      process_info->scudo_stack_depot_size = crash_info->d.scudo_stack_depot_size;
+      process_info->scudo_region_info = crash_info->d.scudo_region_info;
+      process_info->scudo_ring_buffer = crash_info->d.scudo_ring_buffer;
+      process_info->scudo_ring_buffer_size = crash_info->d.scudo_ring_buffer_size;
+      *recoverable_crash = crash_info->d.recoverable_crash;
+      process_info->crash_detail_page = crash_info->d.crash_detail_page;
       FALLTHROUGH_INTENDED;
     case 1:
     case 2:
     case 3:
-      process_info->abort_msg_address = crash_info->data.s.abort_msg_address;
-      *siginfo = crash_info->data.s.siginfo;
+      process_info->abort_msg_address = crash_info->c.abort_msg_address;
+      *siginfo = crash_info->c.siginfo;
       if (signal_has_si_addr(siginfo)) {
         process_info->has_fault_address = true;
         process_info->maybe_tagged_fault_address = reinterpret_cast<uintptr_t>(siginfo->si_addr);
@@ -356,7 +356,7 @@ static void ReadCrashInfo(unique_fd& fd, siginfo_t* siginfo,
             untag_address(reinterpret_cast<uintptr_t>(siginfo->si_addr));
       }
       regs->reset(unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentArch(),
-                                                        &crash_info->data.s.ucontext));
+                                                        &crash_info->c.ucontext));
       break;
 
     default:
@@ -706,6 +706,7 @@ int main(int argc, char** argv) {
         info.siginfo = &siginfo;
         info.signo = info.siginfo->si_signo;
 
+        info.executable_name = get_executable_name(g_target_thread);
         info.command_line = get_command_line(g_target_thread);
       } else {
         info.registers.reset(unwindstack::Regs::RemoteGet(thread));
diff --git a/debuggerd/crasher/crasher.cpp b/debuggerd/crasher/crasher.cpp
index c3dd92b43c..f3c4345299 100644
--- a/debuggerd/crasher/crasher.cpp
+++ b/debuggerd/crasher/crasher.cpp
@@ -145,12 +145,24 @@ noinline int crash(int a) {
 #pragma clang diagnostic push
 #pragma clang diagnostic ignored "-Wfree-nonheap-object"
 
-noinline void abuse_heap() {
+noinline void invalid_free() {
     char buf[16];
-    free(buf); // GCC is smart enough to warn about this, but we're doing it deliberately.
+    free(buf); // The compiler is smart enough to warn about this, but we're doing it deliberately.
 }
 #pragma clang diagnostic pop
 
+noinline void heap_buffer_overflow() {
+    volatile char* p = reinterpret_cast<volatile char*>(malloc(32));
+    p[32] = p[32];
+}
+
+noinline void use_after_free() {
+    void* allocation = malloc(32);
+    volatile char* p = reinterpret_cast<volatile char*>(allocation);
+    free(allocation);
+    p[0] = p[0];
+}
+
 noinline void leak() {
     while (true) {
         void* mapping =
@@ -164,6 +176,16 @@ noinline void sigsegv_non_null() {
     *a = 42;
 }
 
+noinline void sigsegv_write() {
+  int* a = reinterpret_cast<int*>(0xdeadbeef);
+  *a = 10;
+}
+
+noinline void sigsegv_read() {
+  int* a = reinterpret_cast<int*>(0xdeadbeef);
+  int value = *a;
+}
+
 noinline void fprintf_null() {
     FILE* sneaky_null = nullptr;
     fprintf(sneaky_null, "oops");
@@ -187,7 +209,10 @@ static int usage() {
     fprintf(stderr, "  stack-overflow        recurse until the stack overflows\n");
     fprintf(stderr, "  nostack               crash with a NULL stack pointer\n");
     fprintf(stderr, "\n");
-    fprintf(stderr, "  heap-usage            cause a libc abort by abusing a heap function\n");
+    fprintf(stderr, "  heap-buffer-overflow  write past the end of a heap allocation\n");
+    fprintf(stderr, "  invalid-free          pass a non-heap pointer to free()\n");
+    fprintf(stderr, "  use-after-free        write to a buffer after free()\n");
+    fprintf(stderr, "\n");
     fprintf(stderr, "  call-null             cause a crash by calling through a nullptr\n");
     fprintf(stderr, "  leak                  leak memory until we get OOM-killed\n");
     fprintf(stderr, "\n");
@@ -215,6 +240,8 @@ static int usage() {
     fprintf(stderr, "  SIGSEGV               cause a SIGSEGV at address 0x0 (synonym: crash)\n");
     fprintf(stderr, "  SIGSEGV-non-null      cause a SIGSEGV at a non-zero address\n");
     fprintf(stderr, "  SIGSEGV-unmapped      mmap/munmap a region of memory and then attempt to access it\n");
+    fprintf(stderr, "  SIGSEGV-read          cause a SIGSEGV reading from a non-zero address\n");
+    fprintf(stderr, "  SIGSEGV-write         cause a SIGSEGV writing to a non-zero address\n");
     fprintf(stderr, "  SIGTRAP               cause a SIGTRAP\n");
     fprintf(stderr, "\n");
     fprintf(stderr, "  fprintf-NULL          pass a null pointer to fprintf\n");
@@ -280,6 +307,10 @@ noinline int do_action(const char* arg) {
     // Actions.
     if (!strcasecmp(arg, "SIGSEGV-non-null")) {
       sigsegv_non_null();
+    } else if (!strcasecmp(arg, "SIGSEGV-read")) {
+      sigsegv_read();
+    } else if (!strcasecmp(arg, "SIGSEGV-write")) {
+      sigsegv_write();
     } else if (!strcasecmp(arg, "smash-stack")) {
       volatile int len = 128;
       return smash_stack(&len);
@@ -351,8 +382,12 @@ noinline int do_action(const char* arg) {
       return strlen_null();
     } else if (!strcasecmp(arg, "pthread_join-NULL")) {
       return pthread_join(0, nullptr);
-    } else if (!strcasecmp(arg, "heap-usage")) {
-      abuse_heap();
+    } else if (!strcasecmp(arg, "heap-buffer-overflow")) {
+      heap_buffer_overflow();
+    } else if (!strcasecmp(arg, "invalid-free")) {
+      invalid_free();
+    } else if (!strcasecmp(arg, "use-after-free")) {
+      use_after_free();
     } else if (!strcasecmp(arg, "leak")) {
       leak();
     } else if (!strcasecmp(arg, "SIGSEGV-unmapped")) {
@@ -398,7 +433,7 @@ noinline int do_action(const char* arg) {
         return usage();
     }
 
-    fprintf(stderr, "%s: exiting normally!\n", getprogname());
+    fprintf(stderr, "%s: exiting normally (which is unexpected)!\n", getprogname());
     return EXIT_SUCCESS;
 }
 
diff --git a/debuggerd/debuggerd_test.cpp b/debuggerd/debuggerd_test.cpp
index 34f2c450c6..ed39cb4b2d 100644
--- a/debuggerd/debuggerd_test.cpp
+++ b/debuggerd/debuggerd_test.cpp
@@ -17,13 +17,16 @@
 #include <dirent.h>
 #include <dlfcn.h>
 #include <err.h>
+#include <errno.h>
 #include <fcntl.h>
 #include <inttypes.h>
 #include <linux/prctl.h>
 #include <malloc.h>
 #include <pthread.h>
 #include <setjmp.h>
+#include <signal.h>
 #include <stdlib.h>
+#include <string.h>
 #include <sys/capability.h>
 #include <sys/mman.h>
 #include <sys/prctl.h>
@@ -31,8 +34,10 @@
 #include <sys/resource.h>
 #include <sys/syscall.h>
 #include <sys/types.h>
+#include <sys/utsname.h>
 #include <unistd.h>
 
+#include <atomic>
 #include <chrono>
 #include <regex>
 #include <set>
@@ -189,11 +194,11 @@ class CrasherTest : public ::testing::Test {
 
   void StartIntercept(unique_fd* output_fd, DebuggerdDumpType intercept_type = kDebuggerdTombstone);
 
-  // Returns -1 if we fail to read a response from tombstoned, otherwise the received return code.
-  void FinishIntercept(int* result);
+  ssize_t GetInterceptResponse(InterceptResponse& response);
+  // Asserts unless a kStarted response status is returned.
+  void FinishIntercept();
 
   void StartProcess(std::function<void()> function, std::function<pid_t()> forker = fork);
-  void StartCrasher(const std::string& crash_type);
   void FinishCrasher();
   void AssertDeath(int signo);
 
@@ -231,20 +236,25 @@ void CrasherTest::StartIntercept(unique_fd* output_fd, DebuggerdDumpType interce
       << "Error message: " << response.error_message;
 }
 
-void CrasherTest::FinishIntercept(int* result) {
-  InterceptResponse response;
+ssize_t CrasherTest::GetInterceptResponse(InterceptResponse& response) {
+  return TIMEOUT(30, read(intercept_fd.get(), &response, sizeof(response)));
+}
 
-  ssize_t rc = TIMEOUT(30, read(intercept_fd.get(), &response, sizeof(response)));
+void CrasherTest::FinishIntercept() {
+  InterceptResponse response;
+  ssize_t rc = GetInterceptResponse(response);
   if (rc == -1) {
     FAIL() << "failed to read response from tombstoned: " << strerror(errno);
   } else if (rc == 0) {
-    *result = -1;
+    FAIL() << "tombstoned closed fd without a response";
   } else if (rc != sizeof(response)) {
     FAIL() << "received packet of unexpected length from tombstoned: expected " << sizeof(response)
            << ", received " << rc;
-  } else {
-    *result = response.status == InterceptStatus::kStarted ? 1 : 0;
+  } else if (response.status == InterceptStatus::kTimeout) {
+    FAIL() << "tombstoned timeout out waiting for process";
   }
+  ASSERT_EQ(InterceptStatus::kStarted, response.status)
+      << "tombstoned did not return expected result";
 }
 
 void CrasherTest::StartProcess(std::function<void()> function, std::function<pid_t()> forker) {
@@ -279,6 +289,14 @@ void CrasherTest::FinishCrasher() {
   }
 }
 
+static std::string Signal2String(int signo) {
+  char str[SIG2STR_MAX];
+  if (sig2str(signo, str) == 0) {
+    return "SIG" + std::string(str);
+  }
+  return "Unknown";
+}
+
 void CrasherTest::AssertDeath(int signo) {
   int status;
   pid_t pid = TIMEOUT(30, waitpid(crasher_pid, &status, 0));
@@ -291,11 +309,12 @@ void CrasherTest::AssertDeath(int signo) {
 
   if (signo == 0) {
     ASSERT_TRUE(WIFEXITED(status)) << "Terminated due to unexpected signal " << WTERMSIG(status);
-    ASSERT_EQ(0, WEXITSTATUS(signo));
+    ASSERT_EQ(0, WEXITSTATUS(status));
   } else {
     ASSERT_FALSE(WIFEXITED(status));
     ASSERT_TRUE(WIFSIGNALED(status)) << "crasher didn't terminate via a signal";
-    ASSERT_EQ(signo, WTERMSIG(status));
+    ASSERT_EQ(signo, WTERMSIG(status)) << "Expected signal: " << Signal2String(signo)
+                                       << " real signal: " << Signal2String(WTERMSIG(status));
   }
   crasher_pid = -1;
 }
@@ -318,18 +337,15 @@ class LogcatCollector {
 };
 
 TEST_F(CrasherTest, smoke) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     *reinterpret_cast<volatile char*>(0xdead) = '1';
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -348,24 +364,62 @@ TEST_F(CrasherTest, smoke) {
   }
 }
 
+TEST_F(CrasherTest, fault_address_write) {
+#if defined(__riscv)
+  GTEST_SKIP() << "Showing fault type not supported on riscv until "
+                  "https://github.com/google/android-riscv64/issues/118 is fixed.";
+#endif
+
+  StartProcess([]() { *reinterpret_cast<volatile char*>(0xdead) = '1'; });
+
+  unique_fd output_fd;
+  StartIntercept(&output_fd);
+  FinishCrasher();
+  AssertDeath(SIGSEGV);
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
+
+  std::string result;
+  ConsumeFd(std::move(output_fd), &result);
+  ASSERT_MATCH(result,
+               R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x0+dead \(write\))");
+}
+
+TEST_F(CrasherTest, fault_address_read) {
+#if defined(__riscv)
+  GTEST_SKIP() << "Showing fault type not supported on riscv until "
+                  "https://github.com/google/android-riscv64/issues/118 is fixed.";
+#endif
+
+  StartProcess([]() { volatile char value = *reinterpret_cast<volatile char*>(0xdead); });
+
+  unique_fd output_fd;
+  StartIntercept(&output_fd);
+  FinishCrasher();
+  AssertDeath(SIGSEGV);
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
+
+  std::string result;
+  ConsumeFd(std::move(output_fd), &result);
+  ASSERT_MATCH(result,
+               R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x0+dead \(read\))");
+}
+
 TEST_F(CrasherTest, tagged_fault_addr) {
 #if !defined(__aarch64__)
   GTEST_SKIP() << "Requires aarch64";
 #endif
   // HWASan crashes with SIGABRT on tag mismatch.
   SKIP_WITH_HWASAN;
-  int intercept_result;
-  unique_fd output_fd;
+
   StartProcess([]() {
     *reinterpret_cast<volatile char*>(0x100000000000dead) = '1';
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -389,13 +443,13 @@ TEST_F(CrasherTest, heap_addr_in_register) {
   // in the HWASan dump function, rather the faulting context. This is a known
   // issue.
   SKIP_WITH_HWASAN;
-  int intercept_result;
-  unique_fd output_fd;
+
   StartProcess([]() {
     // Crash with a heap pointer in the first argument register.
     Trap(malloc(1));
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   int status;
@@ -403,9 +457,7 @@ TEST_F(CrasherTest, heap_addr_in_register) {
   ASSERT_TRUE(WIFSIGNALED(status)) << "crasher didn't terminate via a signal";
   // Don't test the signal number because different architectures use different signals for
   // __builtin_trap().
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -435,6 +487,10 @@ static void SetTagCheckingLevelAsync() {
     abort();
   }
 }
+#else
+static void SetTagCheckingLevelSync() {}
+
+static void SetTagCheckingLevelAsync() {}
 #endif
 
 struct SizeParamCrasherTest : CrasherTest, testing::WithParamInterface<size_t> {};
@@ -442,7 +498,10 @@ struct SizeParamCrasherTest : CrasherTest, testing::WithParamInterface<size_t> {
 INSTANTIATE_TEST_SUITE_P(Sizes, SizeParamCrasherTest, testing::Values(0, 16, 131072));
 
 TEST_P(SizeParamCrasherTest, mte_uaf) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
@@ -452,10 +511,6 @@ TEST_P(SizeParamCrasherTest, mte_uaf) {
     return;
   }
 
-  LogcatCollector logcat_collector;
-
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     volatile int* p = (volatile int*)malloc(GetParam());
@@ -463,15 +518,15 @@ TEST_P(SizeParamCrasherTest, mte_uaf) {
     p[0] = 42;
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::vector<std::string> log_sources(2);
   ConsumeFd(std::move(output_fd), &log_sources[0]);
+  LogcatCollector logcat_collector;
   logcat_collector.Collect(&log_sources[1]);
   // Tag dump only available in the tombstone, not logcat.
   ASSERT_MATCH(log_sources[0], "Memory tags around the fault address");
@@ -483,19 +538,17 @@ TEST_P(SizeParamCrasherTest, mte_uaf) {
     ASSERT_MATCH(result, R"(deallocated by thread .*?\n.*#00 pc)");
     ASSERT_MATCH(result, R"((^|\s)allocated by thread .*?\n.*#00 pc)");
   }
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_P(SizeParamCrasherTest, mte_oob_uaf) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     volatile int* p = (volatile int*)malloc(GetParam());
@@ -503,47 +556,43 @@ TEST_P(SizeParamCrasherTest, mte_oob_uaf) {
     p[-1] = 42;
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
 
   ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\))");
   ASSERT_NOT_MATCH(result, R"(Cause: \[MTE\]: Use After Free, 4 bytes left)");
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_P(SizeParamCrasherTest, mte_overflow) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  LogcatCollector logcat_collector;
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     volatile char* p = (volatile char*)malloc(GetParam());
     p[GetParam()] = 42;
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::vector<std::string> log_sources(2);
   ConsumeFd(std::move(output_fd), &log_sources[0]);
+  LogcatCollector logcat_collector;
   logcat_collector.Collect(&log_sources[1]);
 
   // Tag dump only in tombstone, not logcat, and tagging is not used for
@@ -558,31 +607,28 @@ TEST_P(SizeParamCrasherTest, mte_overflow) {
                              std::to_string(GetParam()) + R"(-byte allocation)");
     ASSERT_MATCH(result, R"((^|\s)allocated by thread .*?\n.*#00 pc)");
   }
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_P(SizeParamCrasherTest, mte_underflow) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     volatile int* p = (volatile int*)malloc(GetParam());
     p[-1] = 42;
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -593,9 +639,6 @@ TEST_P(SizeParamCrasherTest, mte_underflow) {
   ASSERT_MATCH(result, R"((^|\s)allocated by thread .*
       #00 pc)");
   ASSERT_MATCH(result, "Memory tags around the fault address");
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 __attribute__((noinline)) void mte_illegal_setjmp_helper(jmp_buf& jump_buf) {
@@ -607,19 +650,20 @@ __attribute__((noinline)) void mte_illegal_setjmp_helper(jmp_buf& jump_buf) {
 }
 
 TEST_F(CrasherTest, DISABLED_mte_illegal_setjmp) {
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   // This setjmp is illegal because it jumps back into a function that already returned.
   // Quoting man 3 setjmp:
   //     If the function which called setjmp() returns before longjmp() is
   //     called, the behavior is undefined.  Some kind of subtle or
   //     unsubtle chaos is sure to result.
   // https://man7.org/linux/man-pages/man3/longjmp.3.html
-#if defined(__aarch64__)
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     jmp_buf jump_buf;
@@ -627,12 +671,11 @@ TEST_F(CrasherTest, DISABLED_mte_illegal_setjmp) {
     longjmp(jump_buf, 1);
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -641,18 +684,17 @@ TEST_F(CrasherTest, DISABLED_mte_illegal_setjmp) {
   // interpreted as unsigned integer, and thus is "too large".
   // TODO(fmayer): fix the error message for this
   ASSERT_MATCH(result, R"(memtag_handle_longjmp: stack adjustment too large)");
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_F(CrasherTest, mte_async) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  int intercept_result;
   unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelAsync();
@@ -663,29 +705,23 @@ TEST_F(CrasherTest, mte_async) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
 
   ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code [89] \(SEGV_MTE[AS]ERR\), fault addr)");
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_F(CrasherTest, mte_multiple_causes) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  LogcatCollector logcat_collector;
-
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     SetTagCheckingLevelSync();
 
@@ -709,15 +745,15 @@ TEST_F(CrasherTest, mte_multiple_causes) {
     }
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::vector<std::string> log_sources(2);
   ConsumeFd(std::move(output_fd), &log_sources[0]);
+  LogcatCollector logcat_collector;
   logcat_collector.Collect(&log_sources[1]);
 
   // Tag dump only in the tombstone, not logcat.
@@ -736,9 +772,6 @@ TEST_F(CrasherTest, mte_multiple_causes) {
         result,
         R"((^|\s)allocated by thread .*?\n.*#00 pc(.|\n)*?(^|\s)allocated by thread .*?\n.*#00 pc)");
   }
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 #if defined(__aarch64__)
@@ -760,27 +793,31 @@ static uintptr_t CreateTagMapping() {
   }
   return mapping_uptr + page_size;
 }
+#else
+static uintptr_t CreateTagMapping() {
+  return 0;
+}
 #endif
 
 TEST_F(CrasherTest, mte_register_tag_dump) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     Trap(reinterpret_cast<void *>(CreateTagMapping()));
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -790,62 +827,56 @@ TEST_F(CrasherTest, mte_register_tag_dump) {
 .*
     01.............0 0000000000000000 0000000000000000  ................
     00.............0)");
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_F(CrasherTest, mte_fault_tag_dump_front_truncated) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     volatile char* p = reinterpret_cast<char*>(CreateTagMapping());
     p[0] = 0;  // Untagged pointer, tagged memory.
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
 
   ASSERT_MATCH(result, R"(Memory tags around the fault address.*
 \s*=>0x[0-9a-f]+000:\[1\] 0  1  0)");
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_F(CrasherTest, mte_fault_tag_dump) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     volatile char* p = reinterpret_cast<char*>(CreateTagMapping());
     p[320] = 0;  // Untagged pointer, tagged memory.
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -855,19 +886,17 @@ TEST_F(CrasherTest, mte_fault_tag_dump) {
 \s*=>0x[0-9a-f]+: 1  0  1  0 \[1\] 0  1  0  1  0  1  0  1  0  1  0
 \s*0x[0-9a-f]+: 1  0  1  0  1  0  1  0  1  0  1  0  1  0  1  0
 )");
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_F(CrasherTest, mte_fault_tag_dump_rear_truncated) {
-#if defined(__aarch64__)
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
   if (!mte_supported() || !mte_enabled()) {
     GTEST_SKIP() << "Requires MTE";
   }
 
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&]() {
     SetTagCheckingLevelSync();
     size_t page_size = getpagesize();
@@ -875,12 +904,11 @@ TEST_F(CrasherTest, mte_fault_tag_dump_rear_truncated) {
     p[page_size - kTagGranuleSize * 2] = 0;  // Untagged pointer, tagged memory.
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -891,25 +919,19 @@ TEST_F(CrasherTest, mte_fault_tag_dump_rear_truncated) {
 \s*=>0x[0-9a-f]+: 1  0  1  0  1  0  1  0  1  0  1  0  1  0 \[1\] 0
 
 )");  // Ensure truncation happened and there's a newline after the tag fault.
-#else
-  GTEST_SKIP() << "Requires aarch64";
-#endif
 }
 
 TEST_F(CrasherTest, LD_PRELOAD) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     setenv("LD_PRELOAD", "nonexistent.so", 1);
     *reinterpret_cast<volatile char*>(0xdead) = '1';
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -917,17 +939,15 @@ TEST_F(CrasherTest, LD_PRELOAD) {
 }
 
 TEST_F(CrasherTest, abort) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -935,21 +955,19 @@ TEST_F(CrasherTest, abort) {
 }
 
 TEST_F(CrasherTest, signal) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     while (true) {
       sleep(1);
     }
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   ASSERT_EQ(0, kill(crasher_pid, SIGSEGV));
 
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -960,8 +978,6 @@ TEST_F(CrasherTest, signal) {
 }
 
 TEST_F(CrasherTest, abort_message) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     // Arrived at experimentally;
     // logd truncates at 4062.
@@ -973,12 +989,12 @@ TEST_F(CrasherTest, abort_message) {
     android_set_abort_message(buf);
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -995,18 +1011,16 @@ inline crash_detail_t* _Nullable android_register_crash_detail_strs(const char*
 }
 
 TEST_F(CrasherTest, crash_detail_single) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     android_register_crash_detail_strs("CRASH_DETAIL_NAME", g_crash_detail_value);
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1014,19 +1028,17 @@ TEST_F(CrasherTest, crash_detail_single) {
 }
 
 TEST_F(CrasherTest, crash_detail_replace_data) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     auto *cd = android_register_crash_detail_strs("CRASH_DETAIL_NAME", "original_data");
     android_crash_detail_replace_data(cd, "new_data", strlen("new_data"));
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1037,19 +1049,17 @@ TEST_F(CrasherTest, crash_detail_replace_data) {
 }
 
 TEST_F(CrasherTest, crash_detail_replace_name) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     auto *cd = android_register_crash_detail_strs("old_name", g_crash_detail_value);
     android_crash_detail_replace_name(cd, "new_name", strlen("new_name"));
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1060,39 +1070,34 @@ TEST_F(CrasherTest, crash_detail_replace_name) {
 }
 
 TEST_F(CrasherTest, crash_detail_single_byte_name) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     android_register_crash_detail_strs("CRASH_DETAIL_NAME\1", g_crash_detail_value);
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
   ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME\\1: 'crash_detail_value')");
 }
 
-
 TEST_F(CrasherTest, crash_detail_single_bytes) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     android_crash_detail_register("CRASH_DETAIL_NAME", strlen("CRASH_DETAIL_NAME"), "\1",
                                   sizeof("\1"));
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1100,19 +1105,17 @@ TEST_F(CrasherTest, crash_detail_single_bytes) {
 }
 
 TEST_F(CrasherTest, crash_detail_mixed) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     const char data[] = "helloworld\1\255\3";
     android_register_crash_detail_strs("CRASH_DETAIL_NAME", data);
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1120,8 +1123,6 @@ TEST_F(CrasherTest, crash_detail_mixed) {
 }
 
 TEST_F(CrasherTest, crash_detail_many) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     for (int i = 0; i < 1000; ++i) {
       std::string name = "CRASH_DETAIL_NAME" + std::to_string(i);
@@ -1134,12 +1135,12 @@ TEST_F(CrasherTest, crash_detail_many) {
     android_register_crash_detail_strs("FINAL_NAME2", "FINAL_VALUE2");
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1150,19 +1151,17 @@ TEST_F(CrasherTest, crash_detail_many) {
 }
 
 TEST_F(CrasherTest, crash_detail_single_changes) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     android_register_crash_detail_strs("CRASH_DETAIL_NAME", g_crash_detail_value_changes);
     g_crash_detail_value_changes[0] = 'C';
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1170,19 +1169,17 @@ TEST_F(CrasherTest, crash_detail_single_changes) {
 }
 
 TEST_F(CrasherTest, crash_detail_multiple) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     android_register_crash_detail_strs("CRASH_DETAIL_NAME", g_crash_detail_value);
     android_register_crash_detail_strs("CRASH_DETAIL_NAME2", g_crash_detail_value2);
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1191,20 +1188,18 @@ TEST_F(CrasherTest, crash_detail_multiple) {
 }
 
 TEST_F(CrasherTest, crash_detail_remove) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     auto* detail1 = android_register_crash_detail_strs("CRASH_DETAIL_NAME", g_crash_detail_value);
     android_crash_detail_unregister(detail1);
     android_register_crash_detail_strs("CRASH_DETAIL_NAME2", g_crash_detail_value2);
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1213,18 +1208,16 @@ TEST_F(CrasherTest, crash_detail_remove) {
 }
 
 TEST_F(CrasherTest, abort_message_newline_trimmed) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     android_set_abort_message("Message with a newline.\n");
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1232,18 +1225,16 @@ TEST_F(CrasherTest, abort_message_newline_trimmed) {
 }
 
 TEST_F(CrasherTest, abort_message_multiple_newlines_trimmed) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     android_set_abort_message("Message with multiple newlines.\n\n\n\n\n");
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1251,19 +1242,17 @@ TEST_F(CrasherTest, abort_message_multiple_newlines_trimmed) {
 }
 
 TEST_F(CrasherTest, abort_message_backtrace) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     android_set_abort_message("not actually aborting");
     raise(BIONIC_SIGNAL_DEBUGGER);
     exit(0);
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(0);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1271,18 +1260,17 @@ TEST_F(CrasherTest, abort_message_backtrace) {
 }
 
 TEST_F(CrasherTest, intercept_timeout) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd);
 
   // Don't let crasher finish until we timeout.
-  FinishIntercept(&intercept_result);
-
-  ASSERT_NE(1, intercept_result) << "tombstoned reported success? (intercept_result = "
-                                 << intercept_result << ")";
+  InterceptResponse response = {};
+  EXPECT_LT(0, GetInterceptResponse(response)) << "tombstoned did not properly respond";
+  EXPECT_EQ(InterceptStatus::kTimeout, response.status) << "tombstoned did not timeout";
 
   FinishCrasher();
   AssertDeath(SIGABRT);
@@ -1310,13 +1298,11 @@ TEST_F(CrasherTest, wait_for_debugger) {
 }
 
 TEST_F(CrasherTest, backtrace) {
-  std::string result;
-  int intercept_result;
-  unique_fd output_fd;
-
   StartProcess([]() {
     abort();
   });
+
+  unique_fd output_fd;
   StartIntercept(&output_fd, kDebuggerdNativeBacktrace);
 
   std::this_thread::sleep_for(500ms);
@@ -1324,8 +1310,8 @@ TEST_F(CrasherTest, backtrace) {
   sigval val;
   val.sival_int = 1;
   ASSERT_EQ(0, sigqueue(crasher_pid, BIONIC_SIGNAL_DEBUGGER, val)) << strerror(errno);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
+  std::string result;
   ConsumeFd(std::move(output_fd), &result);
   ASSERT_BACKTRACE_FRAME(result, "read");
 
@@ -1335,26 +1321,22 @@ TEST_F(CrasherTest, backtrace) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
   ConsumeFd(std::move(output_fd), &result);
   ASSERT_BACKTRACE_FRAME(result, "abort");
 }
 
 TEST_F(CrasherTest, PR_SET_DUMPABLE_0_crash) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() {
     prctl(PR_SET_DUMPABLE, 0);
     abort();
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1409,19 +1391,14 @@ TEST_F(CrasherTest, capabilities) {
   FinishCrasher();
   AssertDeath(SIGSYS);
 
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
   std::string result;
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
   ConsumeFd(std::move(output_fd), &result);
   ASSERT_MATCH(result, R"(name: thread_name\s+>>> .+debuggerd_test(32|64) <<<)");
   ASSERT_BACKTRACE_FRAME(result, "tgkill");
 }
 
 TEST_F(CrasherTest, fake_pid) {
-  int intercept_result;
-  unique_fd output_fd;
-
   // Prime the getpid/gettid caches.
   UNUSED(getpid());
   UNUSED(gettid());
@@ -1437,12 +1414,11 @@ TEST_F(CrasherTest, fake_pid) {
       },
       clone_fn);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1466,27 +1442,31 @@ static void setup_jail(minijail* jail) {
   policy += "\nclone: 1";
   policy += "\nsigaltstack: 1";
   policy += "\nnanosleep: 1";
+  // fdsan can make a call to getrlimit
+#if defined(__LP64__)
   policy += "\ngetrlimit: 1";
+#else
+  // On 32-bit, getrlimit is implemented by the ugetrlimit syscall
   policy += "\nugetrlimit: 1";
+#endif
 
-  FILE* tmp_file = tmpfile();
-  if (!tmp_file) {
-    PLOG(FATAL) << "tmpfile failed";
+  TemporaryFile tf;
+  if (tf.fd == -1) {
+    PLOG(FATAL) << "Cannot create tempory file " << tf.path;
   }
 
-  unique_fd tmp_fd(TEMP_FAILURE_RETRY(dup(fileno(tmp_file))));
-  if (!android::base::WriteStringToFd(policy, tmp_fd.get())) {
-    PLOG(FATAL) << "failed to write policy to tmpfile";
+  if (!android::base::WriteStringToFd(policy, tf.fd)) {
+    PLOG(FATAL) << "failed to write policy to temporary file " << tf.path;
   }
 
-  if (lseek(tmp_fd.get(), 0, SEEK_SET) != 0) {
-    PLOG(FATAL) << "failed to seek tmp_fd";
+  if (lseek(tf.fd, 0, SEEK_SET) != 0) {
+    PLOG(FATAL) << "failed to seek tf.fd";
   }
 
   minijail_no_new_privs(jail);
   minijail_log_seccomp_filter_failures(jail);
   minijail_use_seccomp_filter(jail);
-  minijail_parse_seccomp_filters_from_fd(jail, tmp_fd.release());
+  minijail_parse_seccomp_filters_from_fd(jail, tf.release());
 }
 
 static pid_t seccomp_fork_impl(void (*prejail)()) {
@@ -1527,16 +1507,13 @@ static pid_t seccomp_fork() {
 }
 
 TEST_F(CrasherTest, seccomp_crash) {
-  int intercept_result;
-  unique_fd output_fd;
-
   StartProcess([]() { abort(); }, &seccomp_fork);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1557,9 +1534,6 @@ static pid_t seccomp_fork_rlimit() {
 }
 
 TEST_F(CrasherTest, seccomp_crash_oom) {
-  int intercept_result;
-  unique_fd output_fd;
-
   StartProcess(
       []() {
         std::vector<void*> vec;
@@ -1574,11 +1548,11 @@ TEST_F(CrasherTest, seccomp_crash_oom) {
       },
       &seccomp_fork_rlimit);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  FinishIntercept();
 
   // We can't actually generate a backtrace, just make sure that the process terminates.
 }
@@ -1603,38 +1577,40 @@ __attribute__((__noinline__)) extern "C" bool raise_debugger_signal(DebuggerdDum
   return true;
 }
 
-extern "C" void foo() {
+extern "C" void foo(std::atomic_bool& ready) {
   LOG(INFO) << "foo";
-  std::this_thread::sleep_for(1s);
+  ready = true;
+  std::this_thread::sleep_for(1000s);
 }
 
-extern "C" void bar() {
+extern "C" void bar(std::atomic_bool& ready) {
   LOG(INFO) << "bar";
-  std::this_thread::sleep_for(1s);
+  ready = true;
+  std::this_thread::sleep_for(1000s);
 }
 
 TEST_F(CrasherTest, seccomp_tombstone) {
-  int intercept_result;
-  unique_fd output_fd;
-
   static const auto dump_type = kDebuggerdTombstone;
   StartProcess(
       []() {
-        std::thread a(foo);
-        std::thread b(bar);
+        std::atomic_bool foo_ready;
+        std::thread a([&foo_ready] { foo(foo_ready); });
+        std::atomic_bool bar_ready;
+        std::thread b([&bar_ready] { bar(bar_ready); });
 
-        std::this_thread::sleep_for(100ms);
+        while (!foo_ready || !bar_ready) {
+        }
 
         raise_debugger_signal(dump_type);
         _exit(0);
       },
       &seccomp_fork);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd, dump_type);
   FinishCrasher();
   AssertDeath(0);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1644,9 +1620,6 @@ TEST_F(CrasherTest, seccomp_tombstone) {
 }
 
 TEST_F(CrasherTest, seccomp_tombstone_thread_abort) {
-  int intercept_result;
-  unique_fd output_fd;
-
   static const auto dump_type = kDebuggerdTombstone;
   StartProcess(
       []() {
@@ -1655,11 +1628,11 @@ TEST_F(CrasherTest, seccomp_tombstone_thread_abort) {
       },
       &seccomp_fork);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd, dump_type);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1670,27 +1643,27 @@ TEST_F(CrasherTest, seccomp_tombstone_thread_abort) {
 }
 
 TEST_F(CrasherTest, seccomp_tombstone_multiple_threads_abort) {
-  int intercept_result;
-  unique_fd output_fd;
-
   static const auto dump_type = kDebuggerdTombstone;
   StartProcess(
       []() {
-        std::thread a(foo);
-        std::thread b(bar);
+        std::atomic_bool foo_ready;
+        std::thread a([&foo_ready] { foo(foo_ready); });
+        std::atomic_bool bar_ready;
+        std::thread b([&bar_ready] { bar(bar_ready); });
 
-        std::this_thread::sleep_for(100ms);
+        while (!foo_ready || !bar_ready) {
+        }
 
         std::thread abort_thread([] { abort(); });
         abort_thread.join();
       },
       &seccomp_fork);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd, dump_type);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1701,27 +1674,27 @@ TEST_F(CrasherTest, seccomp_tombstone_multiple_threads_abort) {
 }
 
 TEST_F(CrasherTest, seccomp_backtrace) {
-  int intercept_result;
-  unique_fd output_fd;
-
   static const auto dump_type = kDebuggerdNativeBacktrace;
   StartProcess(
       []() {
-        std::thread a(foo);
-        std::thread b(bar);
+        std::atomic_bool foo_ready;
+        std::thread a([&foo_ready] { foo(foo_ready); });
+        std::atomic_bool bar_ready;
+        std::thread b([&bar_ready] { bar(bar_ready); });
 
-        std::this_thread::sleep_for(100ms);
+        while (!foo_ready || !bar_ready) {
+        }
 
         raise_debugger_signal(dump_type);
         _exit(0);
       },
       &seccomp_fork);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd, dump_type);
   FinishCrasher();
   AssertDeath(0);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1731,16 +1704,16 @@ TEST_F(CrasherTest, seccomp_backtrace) {
 }
 
 TEST_F(CrasherTest, seccomp_backtrace_from_thread) {
-  int intercept_result;
-  unique_fd output_fd;
-
   static const auto dump_type = kDebuggerdNativeBacktrace;
   StartProcess(
       []() {
-        std::thread a(foo);
-        std::thread b(bar);
+        std::atomic_bool foo_ready;
+        std::thread a([&foo_ready] { foo(foo_ready); });
+        std::atomic_bool bar_ready;
+        std::thread b([&bar_ready] { bar(bar_ready); });
 
-        std::this_thread::sleep_for(100ms);
+        while (!foo_ready || !bar_ready) {
+        }
 
         std::thread raise_thread([] {
           raise_debugger_signal(dump_type);
@@ -1750,11 +1723,11 @@ TEST_F(CrasherTest, seccomp_backtrace_from_thread) {
       },
       &seccomp_fork);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd, dump_type);
   FinishCrasher();
   AssertDeath(0);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1776,16 +1749,16 @@ extern "C" void malloc_enable();
 extern "C" void malloc_disable();
 
 TEST_F(CrasherTest, seccomp_tombstone_no_allocation) {
-  int intercept_result;
-  unique_fd output_fd;
-
   static const auto dump_type = kDebuggerdTombstone;
   StartProcess(
       []() {
-        std::thread a(foo);
-        std::thread b(bar);
+        std::atomic_bool foo_ready;
+        std::thread a([&foo_ready] { foo(foo_ready); });
+        std::atomic_bool bar_ready;
+        std::thread b([&bar_ready] { bar(bar_ready); });
 
-        std::this_thread::sleep_for(100ms);
+        while (!foo_ready || !bar_ready) {
+        }
 
         // Disable allocations to verify that nothing in the fallback
         // signal handler does an allocation.
@@ -1795,11 +1768,11 @@ TEST_F(CrasherTest, seccomp_tombstone_no_allocation) {
       },
       &seccomp_fork);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd, dump_type);
   FinishCrasher();
   AssertDeath(0);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1809,16 +1782,16 @@ TEST_F(CrasherTest, seccomp_tombstone_no_allocation) {
 }
 
 TEST_F(CrasherTest, seccomp_backtrace_no_allocation) {
-  int intercept_result;
-  unique_fd output_fd;
-
   static const auto dump_type = kDebuggerdNativeBacktrace;
   StartProcess(
       []() {
-        std::thread a(foo);
-        std::thread b(bar);
+        std::atomic_bool foo_ready;
+        std::thread a([&foo_ready] { foo(foo_ready); });
+        std::atomic_bool bar_ready;
+        std::thread b([&bar_ready] { bar(bar_ready); });
 
-        std::this_thread::sleep_for(100ms);
+        while (!foo_ready || !bar_ready) {
+        }
 
         // Disable allocations to verify that nothing in the fallback
         // signal handler does an allocation.
@@ -1828,11 +1801,11 @@ TEST_F(CrasherTest, seccomp_backtrace_no_allocation) {
       },
       &seccomp_fork);
 
+  unique_fd output_fd;
   StartIntercept(&output_fd, dump_type);
   FinishCrasher();
   AssertDeath(0);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1841,13 +1814,44 @@ TEST_F(CrasherTest, seccomp_backtrace_no_allocation) {
   ASSERT_BACKTRACE_FRAME(result, "bar");
 }
 
-TEST_F(CrasherTest, competing_tracer) {
-  int intercept_result;
+TEST_F(CrasherTest, seccomp_mte) {
+#if !defined(__aarch64__)
+  GTEST_SKIP() << "Requires aarch64";
+#endif
+
+  if (!mte_supported() || !mte_enabled()) {
+    GTEST_SKIP() << "Requires MTE";
+  }
+
+  size_t allocation_size = 1;
+  StartProcess(
+      [&]() {
+        SetTagCheckingLevelSync();
+        volatile int* p = (volatile int*)malloc(allocation_size);
+        free((void*)p);
+        p[0] = 42;
+      },
+      &seccomp_fork);
+
   unique_fd output_fd;
+  StartIntercept(&output_fd);
+  FinishCrasher();
+  AssertDeath(SIGSEGV);
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
+
+  // The fallback path does not support getting MTE error data, so simply check
+  // that we get the correct type of crash.
+  std::string result;
+  ConsumeFd(std::move(output_fd), &result);
+  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 9 \(SEGV_MTESERR)");
+}
+
+TEST_F(CrasherTest, competing_tracer) {
   StartProcess([]() {
     raise(SIGABRT);
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
 
   ASSERT_EQ(0, ptrace(PTRACE_SEIZE, crasher_pid, 0, 0));
@@ -1859,8 +1863,7 @@ TEST_F(CrasherTest, competing_tracer) {
   ASSERT_EQ(SIGABRT, WSTOPSIG(status));
 
   ASSERT_EQ(0, ptrace(PTRACE_CONT, crasher_pid, 0, SIGABRT));
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -1941,8 +1944,6 @@ TEST_P(GwpAsanCrasherTest, run_gwp_asan_test) {
   bool recoverable = std::get<1>(GetParam());
   LogcatCollector logcat_collector;
 
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([&recoverable]() {
     const char* env[] = {"GWP_ASAN_SAMPLE_RATE=1", "GWP_ASAN_PROCESS_SAMPLING=1",
                          "GWP_ASAN_MAX_ALLOCS=40000", nullptr, nullptr};
@@ -1966,6 +1967,7 @@ TEST_P(GwpAsanCrasherTest, run_gwp_asan_test) {
     execve(this_binary.c_str(), const_cast<char**>(args), const_cast<char**>(env));
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   if (recoverable) {
@@ -1973,9 +1975,7 @@ TEST_P(GwpAsanCrasherTest, run_gwp_asan_test) {
   } else {
     AssertDeath(SIGSEGV);
   }
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::vector<std::string> log_sources(2);
   ConsumeFd(std::move(output_fd), &log_sources[0]);
@@ -2032,9 +2032,6 @@ TEST_P(GwpAsanCrasherTest, DISABLED_run_gwp_asan_test) {
 }
 
 TEST_F(CrasherTest, fdsan_warning_abort_message) {
-  int intercept_result;
-  unique_fd output_fd;
-
   StartProcess([]() {
     android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE);
     unique_fd fd(TEMP_FAILURE_RETRY(open("/dev/null", O_RDONLY | O_CLOEXEC)));
@@ -2045,11 +2042,11 @@ TEST_F(CrasherTest, fdsan_warning_abort_message) {
     _exit(0);
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(0);
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2443,16 +2440,13 @@ static __attribute__((__noinline__)) void overflow_stack(void* p) {
 }
 
 TEST_F(CrasherTest, stack_overflow) {
-  int intercept_result;
-  unique_fd output_fd;
   StartProcess([]() { overflow_stack(nullptr); });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2485,8 +2479,6 @@ static void CreateEmbeddedLibrary(int out_fd) {
 }
 
 TEST_F(CrasherTest, non_zero_offset_in_library) {
-  int intercept_result;
-  unique_fd output_fd;
   TemporaryFile tf;
   CreateEmbeddedLibrary(tf.fd);
   StartProcess([&tf]() {
@@ -2505,12 +2497,11 @@ TEST_F(CrasherTest, non_zero_offset_in_library) {
     crash_func();
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2532,11 +2523,9 @@ static bool CopySharedLibrary(const char* tmp_dir, std::string* tmp_so_name) {
 }
 
 TEST_F(CrasherTest, unreadable_elf) {
-  int intercept_result;
-  unique_fd output_fd;
   std::string tmp_so_name;
-  StartProcess([&tmp_so_name]() {
-    TemporaryDir td;
+  TemporaryDir td;
+  StartProcess([&td, &tmp_so_name]() {
     if (!CopySharedLibrary(td.path, &tmp_so_name)) {
       _exit(1);
     }
@@ -2556,12 +2545,11 @@ TEST_F(CrasherTest, unreadable_elf) {
     crash_func();
   });
 
+  unique_fd output_fd;
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2672,10 +2660,7 @@ TEST_F(CrasherTest, intercept_for_main_thread_signal_on_side_thread) {
   StartIntercept(&output_fd, kDebuggerdNativeBacktrace);
   FinishCrasher();
   AssertDeath(0);
-
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2724,10 +2709,7 @@ TEST_F(CrasherTest, fault_address_before_first_map) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2756,10 +2738,7 @@ TEST_F(CrasherTest, fault_address_after_last_map) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2812,10 +2791,7 @@ TEST_F(CrasherTest, fault_address_between_maps) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2852,10 +2828,7 @@ TEST_F(CrasherTest, fault_address_in_map) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -2891,8 +2864,8 @@ static constexpr uint32_t kDexData[] = {
 };
 
 TEST_F(CrasherTest, verify_dex_pc_with_function_name) {
-  StartProcess([]() {
-    TemporaryDir td;
+  TemporaryDir td;
+  StartProcess([&td]() {
     std::string tmp_so_name;
     if (!CopySharedLibrary(td.path, &tmp_so_name)) {
       _exit(1);
@@ -2983,10 +2956,7 @@ TEST_F(CrasherTest, verify_dex_pc_with_function_name) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGSEGV);
-
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3047,10 +3017,7 @@ TEST_F(CrasherTest, verify_map_format) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3104,19 +3071,24 @@ TEST_F(CrasherTest, verify_header) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
 
   std::string match_str = android::base::StringPrintf(
-      "Build fingerprint: '%s'\\nRevision: '%s'\\n",
-      android::base::GetProperty("ro.build.fingerprint", "unknown").c_str(),
-      android::base::GetProperty("ro.revision", "unknown").c_str());
+      "Build fingerprint: '%s'\n",
+      android::base::GetProperty("ro.build.fingerprint", "unknown").c_str());
+
+  utsname buf;
+  ASSERT_EQ(0, uname(&buf));
+  match_str += android::base::StringPrintf("Kernel Release: '%s'\n", buf.release);
+
+  match_str += android::base::StringPrintf(
+      "Revision: '%s'\n", android::base::GetProperty("ro.revision", "unknown").c_str());
+
   match_str += android::base::StringPrintf("ABI: '%s'\n", ABI_STRING);
+
   ASSERT_MATCH(result, match_str);
 }
 
@@ -3149,9 +3121,7 @@ TEST_F(CrasherTest, verify_thread_header) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   // Read the tid data out.
   pid_t tid;
@@ -3182,9 +3152,7 @@ TEST_F(CrasherTest, verify_build_id) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3229,9 +3197,7 @@ TEST_F(CrasherTest, logd_skips_reading_logs) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3259,10 +3225,7 @@ TEST_F(CrasherTest, logd_skips_reading_logs_not_main_thread) {
   StartIntercept(&output_fd, kDebuggerdTombstone);
   FinishCrasher();
   AssertDeath(0);
-
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3284,9 +3247,7 @@ TEST_F(CrasherTest, DISABLED_max_log_messages) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3305,9 +3266,7 @@ TEST_F(CrasherTest, log_with_newline) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3358,9 +3317,7 @@ TEST_F(CrasherTest, log_with_non_printable_ascii_verify_encoded) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3382,9 +3339,7 @@ TEST_F(CrasherTest, log_with_with_special_printable_ascii) {
   StartIntercept(&output_fd);
   FinishCrasher();
   AssertDeath(SIGABRT);
-  int intercept_result;
-  FinishIntercept(&intercept_result);
-  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
 
   std::string result;
   ConsumeFd(std::move(output_fd), &result);
@@ -3400,3 +3355,31 @@ TEST_F(CrasherTest, log_with_with_special_printable_ascii) {
   EXPECT_TRUE(result.find(" after", pos + 1) != std::string::npos)
       << "Couldn't find sanitized log message: " << result;
 }
+
+TEST_F(CrasherTest, executable) {
+  SKIP_WITH_HWASAN << "prctl(PR_SET_MM, PR_SET_MM_ARG_{START,END} not supported on hwasan.";
+
+  StartProcess([]() {
+    const char command_line[] = "TestCommand";
+
+    EXPECT_EQ(0, prctl(PR_SET_MM, PR_SET_MM_ARG_START,
+                       reinterpret_cast<unsigned long>(command_line), 0, 0))
+        << strerror(errno);
+    EXPECT_EQ(0,
+              prctl(PR_SET_MM, PR_SET_MM_ARG_END,
+                    reinterpret_cast<unsigned long>(&command_line[sizeof(command_line) - 1]), 0, 0))
+        << strerror(errno);
+    abort();
+  });
+
+  unique_fd output_fd;
+  StartIntercept(&output_fd);
+  FinishCrasher();
+  AssertDeath(SIGABRT);
+  ASSERT_NO_FATAL_FAILURE(FinishIntercept());
+
+  std::string result;
+  ConsumeFd(std::move(output_fd), &result);
+  ASSERT_MATCH(result, R"(Executable: \S*debuggerd_test\S*\n)");
+  ASSERT_MATCH(result, R"(Cmdline: TestCommand\n)");
+}
diff --git a/debuggerd/handler/debuggerd_fallback.cpp b/debuggerd/handler/debuggerd_fallback.cpp
index 8ab5f253fc..a8556e5179 100644
--- a/debuggerd/handler/debuggerd_fallback.cpp
+++ b/debuggerd/handler/debuggerd_fallback.cpp
@@ -94,8 +94,6 @@ class ScopedUseFallbackAllocator {
 };
 
 static void debuggerd_fallback_trace(int output_fd, ucontext_t* ucontext) {
-  std::unique_ptr<unwindstack::Regs> regs;
-
   ThreadInfo thread;
   thread.pid = getpid();
   thread.tid = gettid();
diff --git a/debuggerd/handler/debuggerd_handler.cpp b/debuggerd/handler/debuggerd_handler.cpp
index 88278ca667..86920f58e3 100644
--- a/debuggerd/handler/debuggerd_handler.cpp
+++ b/debuggerd/handler/debuggerd_handler.cpp
@@ -39,6 +39,7 @@
 #include <time.h>
 #include <unistd.h>
 
+#include <android-base/file.h>
 #include <android-base/macros.h>
 #include <android-base/parsebool.h>
 #include <android-base/parseint.h>
@@ -102,19 +103,61 @@ static bool property_parse_bool(const char* name) {
   return cookie;
 }
 
+// Avoid using any other libc/libbase functions in this function to avoid doing
+// any allocations and to avoid calling any disallowed functions by accident.
+static const char* get_command_no_alloc(char* command, const size_t length) {
+  int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
+  if (fd == -1) {
+    async_safe_format_log(ANDROID_LOG_WARN, "libc", "Opening /proc/self/cmdline failed: %s",
+                          strerrorname_np(errno));
+    return nullptr;
+  }
+  // Force the buffer to be null terminated to avoid cases where the first
+  // argument is longer than the total buffer. This might truncate the first
+  // argument of the command-line, but it's still possible to use the
+  // truncated name.
+  command[length - 1] = '\0';
+  ssize_t bytes = TEMP_FAILURE_RETRY(read(fd, command, length - 1));
+  close(fd);
+  if (bytes <= 0) {
+    async_safe_format_log(ANDROID_LOG_WARN, "libc", "/proc/self/cmdline read error: %s",
+                          bytes == -1 ? strerrorname_np(errno) : "zero bytes read");
+    return nullptr;
+  }
+
+  // Find the basename of the first argument in the command-line.
+  const char* arg0 = strrchr(command, '/');
+  return arg0 != nullptr ? &arg0[1] : command;
+}
+
 static bool is_permissive_mte() {
-  // Environment variable for testing or local use from shell.
+  // DO NOT REPLACE property_parse_bool with GetBoolProperty. That uses std::string which allocates,
+  // so it is not async-safe, and this function gets used in a signal handler.
   char* permissive_env = getenv("MTE_PERMISSIVE");
+  if (permissive_env && ParseBool(permissive_env) == ParseBoolResult::kTrue) {
+    return true;
+  }
+
+  if (property_parse_bool("persist.sys.mte.permissive") ||
+      property_parse_bool("persist.device_config.memory_safety_native.permissive.default")) {
+    return true;
+  }
+
+  // getprogrname() always returns nullptr in this context, so we need to read
+  // the cmdline directly to get the name of the running program.
+  // In addition, use /proc/self/cmdline instead of readlink of /proc/self/exe
+  // so that any process forked from the zygote has the correct name.
+  char command_buffer[256];
+  const char* command = get_command_no_alloc(command_buffer, sizeof(command_buffer));
+  if (command == nullptr) {
+    return false;
+  }
+
   char process_sysprop_name[512];
   async_safe_format_buffer(process_sysprop_name, sizeof(process_sysprop_name),
                            "persist.device_config.memory_safety_native.permissive.process.%s",
-                           getprogname());
-  // DO NOT REPLACE this with GetBoolProperty. That uses std::string which allocates, so it is
-  // not async-safe, and this function gets used in a signal handler.
-  return property_parse_bool("persist.sys.mte.permissive") ||
-         property_parse_bool("persist.device_config.memory_safety_native.permissive.default") ||
-         property_parse_bool(process_sysprop_name) ||
-         (permissive_env && ParseBool(permissive_env) == ParseBoolResult::kTrue);
+                           command);
+  return property_parse_bool(process_sysprop_name);
 }
 
 static bool parse_uint_with_error_reporting(const char* s, const char* name, int* v) {
@@ -421,41 +464,61 @@ static int debuggerd_dispatch_pseudothread(void* arg) {
     fatal_errno("failed to create pipe");
   }
 
-  uint32_t version;
-  ssize_t expected;
+  // The crash data is sent in four parts:
+  //   part 1: uint32_t (version number)
+  //   part 2: siginfo_t
+  //   part 3: ucontext_t
+  // Static executable crash:
+  //   part 4: uintptr_t (abort message pointer)
+  // Dynamic executable crash:
+  //   part 4: debugger_process_info
+  //     where debugger_process_info starts with uintptr_t abort_msg
+
+  // Verify that the CrashInfo structure is aligned such that there is no space
+  // between the fields since the parts are sent without space and read directly
+  // into a CrashInfo structure.
+  static_assert(offsetof(CrashInfo, c.version) == 0);
+  static_assert(offsetof(CrashInfo, c.version) + sizeof(uint32_t) ==
+                offsetof(CrashInfo, c.siginfo));
+  static_assert(offsetof(CrashInfo, c.siginfo) + sizeof(siginfo_t) ==
+                offsetof(CrashInfo, c.ucontext));
+  static_assert(offsetof(CrashInfo, c.ucontext) + sizeof(ucontext_t) ==
+                offsetof(CrashInfo, c.abort_msg_address));
 
+  uint32_t version;
   // ucontext_t is absurdly large on AArch64, so piece it together manually with writev.
   struct iovec iovs[4] = {
       {.iov_base = &version, .iov_len = sizeof(version)},
       {.iov_base = thread_info->siginfo, .iov_len = sizeof(siginfo_t)},
       {.iov_base = thread_info->ucontext, .iov_len = sizeof(ucontext_t)},
   };
+  constexpr size_t kCurrentCrashInfoSize = sizeof(version) + sizeof(siginfo_t) + sizeof(ucontext_t);
 
-  constexpr size_t kHeaderSize = sizeof(version) + sizeof(siginfo_t) + sizeof(ucontext_t);
-
+  ssize_t expected;
   if (thread_info->process_info.fdsan_table) {
     // Dynamic executables always use version 4. There is no need to increment the version number if
     // the format changes, because the sender (linker) and receiver (crash_dump) are version locked.
     version = 4;
-    expected = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataDynamic);
+    expected = sizeof(CrashInfo);
 
-    static_assert(sizeof(CrashInfoHeader) + sizeof(CrashInfoDataDynamic) ==
-                      kHeaderSize + sizeof(thread_info->process_info),
+    static_assert(sizeof(CrashInfo) == kCurrentCrashInfoSize + sizeof(thread_info->process_info),
                   "Wire protocol structs do not match the data sent.");
-#define ASSERT_SAME_OFFSET(MEMBER1, MEMBER2) \
-    static_assert(sizeof(CrashInfoHeader) + offsetof(CrashInfoDataDynamic, MEMBER1) == \
-                      kHeaderSize + offsetof(debugger_process_info, MEMBER2), \
-                  "Wire protocol offset does not match data sent: " #MEMBER1);
-    ASSERT_SAME_OFFSET(fdsan_table_address, fdsan_table);
-    ASSERT_SAME_OFFSET(gwp_asan_state, gwp_asan_state);
-    ASSERT_SAME_OFFSET(gwp_asan_metadata, gwp_asan_metadata);
-    ASSERT_SAME_OFFSET(scudo_stack_depot, scudo_stack_depot);
-    ASSERT_SAME_OFFSET(scudo_region_info, scudo_region_info);
-    ASSERT_SAME_OFFSET(scudo_ring_buffer, scudo_ring_buffer);
-    ASSERT_SAME_OFFSET(scudo_ring_buffer_size, scudo_ring_buffer_size);
-    ASSERT_SAME_OFFSET(scudo_stack_depot_size, scudo_stack_depot_size);
-    ASSERT_SAME_OFFSET(recoverable_crash, recoverable_crash);
-    ASSERT_SAME_OFFSET(crash_detail_page, crash_detail_page);
+#define ASSERT_SAME_OFFSET(MEMBER1, MEMBER2)                                          \
+  static_assert(offsetof(CrashInfo, MEMBER1) ==                                       \
+                    kCurrentCrashInfoSize + offsetof(debugger_process_info, MEMBER2), \
+                "Wire protocol offset does not match data sent: " #MEMBER1);
+    static_assert(offsetof(debugger_process_info, abort_msg) == 0,
+                  "abort_msg must be the first element in debugger_process_info");
+    ASSERT_SAME_OFFSET(d.fdsan_table_address, fdsan_table);
+    ASSERT_SAME_OFFSET(d.gwp_asan_state, gwp_asan_state);
+    ASSERT_SAME_OFFSET(d.gwp_asan_metadata, gwp_asan_metadata);
+    ASSERT_SAME_OFFSET(d.scudo_stack_depot, scudo_stack_depot);
+    ASSERT_SAME_OFFSET(d.scudo_region_info, scudo_region_info);
+    ASSERT_SAME_OFFSET(d.scudo_ring_buffer, scudo_ring_buffer);
+    ASSERT_SAME_OFFSET(d.scudo_ring_buffer_size, scudo_ring_buffer_size);
+    ASSERT_SAME_OFFSET(d.scudo_stack_depot_size, scudo_stack_depot_size);
+    ASSERT_SAME_OFFSET(d.recoverable_crash, recoverable_crash);
+    ASSERT_SAME_OFFSET(d.crash_detail_page, crash_detail_page);
 #undef ASSERT_SAME_OFFSET
 
     iovs[3] = {.iov_base = &thread_info->process_info,
@@ -463,11 +526,10 @@ static int debuggerd_dispatch_pseudothread(void* arg) {
   } else {
     // Static executables always use version 1.
     version = 1;
-    expected = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataStatic);
+    expected = sizeof(CrashInfoDataCommon);
 
-    static_assert(
-        sizeof(CrashInfoHeader) + sizeof(CrashInfoDataStatic) == kHeaderSize + sizeof(uintptr_t),
-        "Wire protocol structs do not match the data sent.");
+    static_assert(sizeof(CrashInfoDataCommon) == kCurrentCrashInfoSize + sizeof(uintptr_t),
+                  "Wire protocol structs do not match the data sent.");
 
     iovs[3] = {.iov_base = &thread_info->process_info.abort_msg, .iov_len = sizeof(uintptr_t)};
   }
diff --git a/debuggerd/libdebuggerd/include/libdebuggerd/types.h b/debuggerd/libdebuggerd/include/libdebuggerd/types.h
index f7fc2a3b7d..a0246a10fd 100644
--- a/debuggerd/libdebuggerd/include/libdebuggerd/types.h
+++ b/debuggerd/libdebuggerd/include/libdebuggerd/types.h
@@ -34,6 +34,7 @@ struct ThreadInfo {
 
   pid_t pid;
 
+  std::string executable_name;
   std::vector<std::string> command_line;
   std::string selinux_label;
 
diff --git a/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h b/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h
index 819a99d2d9..a9610e3611 100644
--- a/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h
+++ b/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h
@@ -20,8 +20,9 @@
 
 #include <stddef.h>
 
-std::string describe_tagged_addr_ctrl(long ctrl);
+std::string describe_esr(uint64_t value);
 std::string describe_pac_enabled_keys(long keys);
+std::string describe_tagged_addr_ctrl(long ctrl);
 
 // Number of bytes per MTE granule.
 constexpr size_t kTagGranuleSize = 16;
diff --git a/debuggerd/libdebuggerd/tombstone.cpp b/debuggerd/libdebuggerd/tombstone.cpp
index 30c6fe4c50..66ce9c8d19 100644
--- a/debuggerd/libdebuggerd/tombstone.cpp
+++ b/debuggerd/libdebuggerd/tombstone.cpp
@@ -65,6 +65,7 @@ void engrave_tombstone_ucontext(int tombstone_fd, int proto_fd, uint64_t abort_m
   log.amfd_data = nullptr;
 
   std::string thread_name = get_thread_name(target_tid);
+  std::string executable_name = get_executable_name(target_tid);
   std::vector<std::string> command_line = get_command_line(pid);
 
   std::unique_ptr<unwindstack::Regs> regs(
@@ -74,14 +75,21 @@ void engrave_tombstone_ucontext(int tombstone_fd, int proto_fd, uint64_t abort_m
   android::base::ReadFileToString("/proc/self/attr/current", &selinux_label);
 
   std::map<pid_t, ThreadInfo> threads;
-  threads[target_tid] = ThreadInfo {
-    .registers = std::move(regs), .uid = uid, .tid = target_tid,
-    .thread_name = std::move(thread_name), .pid = pid, .command_line = std::move(command_line),
-    .selinux_label = std::move(selinux_label), .siginfo = siginfo, .signo = siginfo->si_signo,
-    // Only supported on aarch64 for now.
+  threads[target_tid] = ThreadInfo{
+      .registers = std::move(regs),
+      .uid = uid,
+      .tid = target_tid,
+      .thread_name = std::move(thread_name),
+      .pid = pid,
+      .executable_name = std::move(executable_name),
+      .command_line = std::move(command_line),
+      .selinux_label = std::move(selinux_label),
+      .siginfo = siginfo,
+      .signo = siginfo->si_signo,
+  // Only supported on aarch64 for now.
 #if defined(__aarch64__)
-    .tagged_addr_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0),
-    .pac_enabled_keys = prctl(PR_PAC_GET_ENABLED_KEYS, 0, 0, 0, 0),
+      .tagged_addr_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0),
+      .pac_enabled_keys = prctl(PR_PAC_GET_ENABLED_KEYS, 0, 0, 0, 0),
 #endif
   };
   const ThreadInfo& thread = threads[pid];
diff --git a/debuggerd/libdebuggerd/tombstone_proto.cpp b/debuggerd/libdebuggerd/tombstone_proto.cpp
index d3ac49a17f..c5c716dc1c 100644
--- a/debuggerd/libdebuggerd/tombstone_proto.cpp
+++ b/debuggerd/libdebuggerd/tombstone_proto.cpp
@@ -32,6 +32,7 @@
 #include <string.h>
 #include <sys/mman.h>
 #include <sys/sysinfo.h>
+#include <sys/utsname.h>
 #include <time.h>
 
 #include <map>
@@ -66,6 +67,10 @@
 #include <procinfo/process.h>
 #include <unwindstack/AndroidUnwinder.h>
 #include <unwindstack/Error.h>
+#include <unwindstack/MachineArm.h>
+#include <unwindstack/MachineArm64.h>
+#include <unwindstack/MachineX86.h>
+#include <unwindstack/MachineX86_64.h>
 #include <unwindstack/MapInfo.h>
 #include <unwindstack/Maps.h>
 #include <unwindstack/Regs.h>
@@ -581,6 +586,27 @@ static void dump_registers(unwindstack::AndroidUnwinder* unwinder,
       *thread.add_memory_dump() = std::move(dump);
     }
   });
+#if defined(__aarch64__)
+  Register esr;
+  esr.set_name("esr");
+  esr.set_u64(regs->GetExtraRegister(unwindstack::Arm64Reg::ARM64_EXTRA_REG_ESR));
+  *thread.add_registers() = esr;
+#elif defined(__arm__)
+  Register error_code;
+  error_code.set_name("error_code");
+  error_code.set_u64(regs->GetExtraRegister(unwindstack::ArmReg::ARM_EXTRA_REG_ERROR_CODE));
+  *thread.add_registers() = error_code;
+#elif defined(__i386__)
+  Register err;
+  err.set_name("err");
+  err.set_u64(regs->GetExtraRegister(unwindstack::X86Reg::X86_EXTRA_REG_ERR));
+  *thread.add_registers() = err;
+#elif defined(__x86_64__)
+  Register err;
+  err.set_name("err");
+  err.set_u64(regs->GetExtraRegister(unwindstack::X86_64Reg::X86_64_EXTRA_REG_ERR));
+  *thread.add_registers() = err;
+#endif
 }
 
 static void dump_thread_backtrace(std::vector<unwindstack::FrameData>& frames, Thread& thread) {
@@ -852,6 +878,11 @@ void engrave_tombstone_proto(Tombstone* tombstone, unwindstack::AndroidUnwinder*
   result.set_revision(android::base::GetProperty("ro.revision", "unknown"));
   result.set_timestamp(get_timestamp());
 
+  utsname buf;
+  if (uname(&buf) == 0) {
+    result.set_kernel_release(buf.release);
+  }
+
   const ThreadInfo& target_thread = threads.at(target_tid);
   result.set_pid(target_thread.pid);
   result.set_tid(target_thread.tid);
@@ -875,6 +906,7 @@ void engrave_tombstone_proto(Tombstone* tombstone, unwindstack::AndroidUnwinder*
   result.set_page_size(getpagesize());
   result.set_has_been_16kb_mode(android::base::GetBoolProperty("ro.misctrl.16kb_before", false));
 
+  result.set_executable_name(target_thread.executable_name);
   auto cmd_line = result.mutable_command_line();
   for (const auto& arg : target_thread.command_line) {
     *cmd_line->Add() = arg;
diff --git a/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp b/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
index 11841b290d..1705e894a0 100644
--- a/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
+++ b/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
@@ -19,6 +19,7 @@
 
 #include <ctype.h>
 #include <inttypes.h>
+#include <signal.h>
 
 #include <algorithm>
 #include <functional>
@@ -103,6 +104,11 @@ static uint64_t untag_address(Architecture arch, uint64_t addr) {
 static void print_thread_header(CallbackType callback, const Tombstone& tombstone,
                                 const Thread& thread, bool should_log) {
   const char* process_name = "<unknown>";
+  if (!tombstone.executable_name().empty()) {
+    CB(should_log, "Executable: %s", tombstone.executable_name().c_str());
+  } else {
+    CB(should_log, "Executable: <unknown>");
+  }
   if (!tombstone.command_line().empty()) {
     process_name = tombstone.command_line()[0].c_str();
     CB(should_log, "Cmdline: %s", android::base::Join(tombstone.command_line(), " ").c_str());
@@ -120,6 +126,16 @@ static void print_thread_header(CallbackType callback, const Tombstone& tombston
     CB(should_log, "pac_enabled_keys: %016" PRIx64 "%s", thread.pac_enabled_keys(),
        describe_pac_enabled_keys(thread.pac_enabled_keys()).c_str());
   }
+
+  if (tombstone.arch() == Architecture::ARM64) {
+    // See if the esr register exists.
+    for (const auto& reg : thread.registers()) {
+      if (reg.name() == "esr" && reg.u64() != 0U) {
+        CB(should_log, "esr: %016" PRIx64 " %s", reg.u64(), describe_esr(reg.u64()).c_str());
+        break;
+      }
+    }
+  }
 }
 
 static void print_register_row(CallbackType callback, int word_size,
@@ -143,11 +159,11 @@ static void print_thread_registers(CallbackType callback, const Tombstone& tombs
 
   switch (tombstone.arch()) {
     case Architecture::ARM32:
-      special_registers = {"ip", "lr", "sp", "pc", "pst"};
+      special_registers = {"ip", "lr", "sp", "pc", "pst", "error_code"};
       break;
 
     case Architecture::ARM64:
-      special_registers = {"ip", "lr", "sp", "pc", "pst"};
+      special_registers = {"ip", "lr", "sp", "pc", "pst", "esr"};
       break;
 
     case Architecture::RISCV64:
@@ -155,11 +171,11 @@ static void print_thread_registers(CallbackType callback, const Tombstone& tombs
       break;
 
     case Architecture::X86:
-      special_registers = {"ebp", "esp", "eip"};
+      special_registers = {"ebp", "esp", "eip", "err"};
       break;
 
     case Architecture::X86_64:
-      special_registers = {"rbp", "rsp", "rip"};
+      special_registers = {"rbp", "rsp", "rip", "err"};
       break;
 
     default:
@@ -169,7 +185,7 @@ static void print_thread_registers(CallbackType callback, const Tombstone& tombs
 
   for (const auto& reg : thread.registers()) {
     auto row = &current_row;
-    if (special_registers.count(reg.name()) == 1) {
+    if (special_registers.contains(reg.name())) {
       row = &special_row;
     }
 
@@ -184,7 +200,16 @@ static void print_thread_registers(CallbackType callback, const Tombstone& tombs
     print_register_row(callback, word_size, current_row, should_log);
   }
 
-  print_register_row(callback, word_size, special_row, should_log);
+  if (special_row.size() > column_count) {
+    std::vector<std::pair<std::string, uint64_t>> first_row(special_row.begin(),
+                                                            special_row.begin() + column_count);
+    std::vector<std::pair<std::string, uint64_t>> second_row(special_row.begin() + column_count,
+                                                             special_row.end());
+    print_register_row(callback, word_size, first_row, should_log);
+    print_register_row(callback, word_size, second_row, should_log);
+  } else {
+    print_register_row(callback, word_size, special_row, should_log);
+  }
 }
 
 static void print_backtrace(CallbackType callback, SymbolizeCallbackType symbolize,
@@ -420,6 +445,33 @@ static void print_memory_maps(CallbackType callback, const Tombstone& tombstone)
   }
 }
 
+static std::string get_crash_type(const Thread& thread, const std::string& reg_name,
+                                  const uint64_t write_mask) {
+  for (const auto& reg : thread.registers()) {
+    if (reg.name() == reg_name) {
+      if (reg.u64() & write_mask) {
+        return " (write)";
+      }
+      return " (read)";
+    }
+  }
+  return "";
+}
+
+static std::string get_read_write_desc(const Architecture& arch, const Thread& thread) {
+  switch (arch) {
+    case Architecture::ARM32:
+      return get_crash_type(thread, "error_code", (1U << 11));
+    case Architecture::ARM64:
+      return get_crash_type(thread, "esr", (1U << 6));
+    case Architecture::X86:
+    case Architecture::X86_64:
+      return get_crash_type(thread, "err", (1U << 1));
+    default:
+      return "";
+  }
+}
+
 static void print_main_thread(CallbackType callback, SymbolizeCallbackType symbolize,
                               const Tombstone& tombstone, const Thread& thread) {
   print_thread_header(callback, tombstone, thread, true);
@@ -441,6 +493,7 @@ static void print_main_thread(CallbackType callback, SymbolizeCallbackType symbo
     if (signal_info.has_fault_address()) {
       fault_addr_desc =
           StringPrintf("0x%0*" PRIx64, 2 * pointer_width(tombstone), signal_info.fault_address());
+      fault_addr_desc += get_read_write_desc(tombstone.arch(), thread);
     } else {
       fault_addr_desc = "--------";
     }
@@ -448,11 +501,9 @@ static void print_main_thread(CallbackType callback, SymbolizeCallbackType symbo
     CBL("signal %d (%s), code %d (%s%s), fault addr %s", signal_info.number(),
         signal_info.name().c_str(), signal_info.code(), signal_info.code_name().c_str(),
         sender_desc.c_str(), fault_addr_desc.c_str());
-#ifdef SEGV_MTEAERR
     is_async_mte_crash = signal_info.number() == SIGSEGV && signal_info.code() == SEGV_MTEAERR;
     is_mte_crash = is_async_mte_crash ||
                    (signal_info.number() == SIGSEGV && signal_info.code() == SEGV_MTESERR);
-#endif
   }
 
   if (tombstone.causes_size() == 1) {
@@ -582,6 +633,9 @@ bool tombstone_proto_to_text(const Tombstone& tombstone, CallbackType callback,
                              SymbolizeCallbackType symbolize) {
   CBL("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***");
   CBL("Build fingerprint: '%s'", tombstone.build_fingerprint().c_str());
+  if (!tombstone.kernel_release().empty()) {
+    CBL("Kernel Release: '%s'", tombstone.kernel_release().c_str());
+  }
   CBL("Revision: '%s'", tombstone.revision().c_str());
   CBL("ABI: '%s'", abi_string(tombstone.arch()));
   if (tombstone.guest_arch() != Architecture::NONE) {
diff --git a/debuggerd/libdebuggerd/utility_host.cpp b/debuggerd/libdebuggerd/utility_host.cpp
index d87f4fb8e1..f2354582a2 100644
--- a/debuggerd/libdebuggerd/utility_host.cpp
+++ b/debuggerd/libdebuggerd/utility_host.cpp
@@ -103,6 +103,105 @@ std::string describe_pac_enabled_keys(long value) {
   return describe_end(value, desc);
 }
 
+static std::string describe_ec(uint8_t ec) {
+  // ESR exception encodings:
+  //   https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-
+  //   https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-
+  //   https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/ESR-EL3--Exception-Syndrome-Register--EL3-
+  // Kernel header:
+  //    https://android.googlesource.com/kernel/common/+/android-mainline/arch/arm64/include/asm/esr.h
+  switch (ec) {
+    case 0x00:
+      return "Unknown";
+    case 0x01:
+      return "WFx";
+    case 0x03:
+      return "MCR/MRC";
+    case 0x04:
+      return "MCRR/MRRC";
+    case 0x05:
+      return "MCR/MRC";
+    case 0x06:
+      return "LDC/STC";
+    case 0x07:
+      return "SIMD/SME/SVE";
+    case 0x08:  // EL2 only
+      return "VMRS";
+    case 0x09:  // EL2 and above
+    case 0x1C:  // EL1 and above
+      return "PAC";
+    case 0x0C:
+      return "MRRC";
+    case 0x0D:
+      return "BTI";
+    case 0x0E:
+      return "Illegal Instruction";
+    case 0x11:
+      return "SVC32";
+    case 0x12:  // EL2 only
+      return "HVC32";
+    case 0x13:  // EL2 and above
+      return "SMC32";
+    case 0x15:
+      return "SVC64";
+    case 0x16:  // EL2 and above
+      return "HVC64";
+    case 0x17:  // EL2 and above
+      return "SMC64";
+    case 0x18:
+      return "SYS64";
+    case 0x19:
+      return "SVE";
+    case 0x1A:  // EL2 only
+      return "ERET";
+    case 0x1D:
+      return "SME";
+    case 0x1F:  // EL3 only
+      return "Implementation Defined";
+    case 0x20:
+    case 0x21:
+      return "Instruction Abort";
+    case 0x22:
+      return "PC Alignment";
+    case 0x24:
+    case 0x25:
+      return "Data Abort";
+    case 0x26:
+      return "SP Alignment";
+    case 0x27:
+      return "MOPS";
+    case 0x28:
+    case 0x2C:
+      return "FP Exception";
+    case 0x2D:
+      return "GCS";
+    case 0x2F:
+      return "SERROR";
+    case 0x30:
+    case 0x31:
+    case 0x38:
+      return "BKPT";
+    case 0x32:
+    case 0x33:
+      return "SW Step";
+    case 0x34:
+    case 0x35:
+      return "Watchpoint";
+    case 0x3A:  // EL2 only
+      return "Vector Catch";
+    case 0x3C:
+      return "BRK";
+    default:
+      return "Unrecognized";
+  }
+}
+
+std::string describe_esr(uint64_t value) {
+  // EC part of the esr.
+  uint8_t ec = (value >> 26) & 0x3f;
+  return android::base::StringPrintf("(%s Exception 0x%02x)", describe_ec(ec).c_str(), ec);
+}
+
 static std::string oct_encode(const std::string& data, bool (*should_encode_func)(int)) {
   std::string oct_encoded;
   oct_encoded.reserve(data.size());
diff --git a/debuggerd/proto/tombstone.proto b/debuggerd/proto/tombstone.proto
index 9deeeec9e1..9078f746ce 100644
--- a/debuggerd/proto/tombstone.proto
+++ b/debuggerd/proto/tombstone.proto
@@ -58,11 +58,14 @@ message Tombstone {
   uint32 uid = 7;
   string selinux_label = 8;
 
+  string executable_name = 27;
   repeated string command_line = 9;
 
   // Process uptime in seconds.
   uint32 process_uptime = 20;
 
+  string kernel_release = 28;
+
   Signal signal_info = 10;
   string abort_message = 14;
   repeated CrashDetail crash_details = 21;
@@ -79,7 +82,7 @@ message Tombstone {
 
   StackHistoryBuffer stack_history_buffer = 26;
 
-  reserved 27 to 999;
+  reserved 29 to 999;
 }
 
 enum Architecture {
diff --git a/debuggerd/protocol.h b/debuggerd/protocol.h
index 9af7377df8..ae5c28df3a 100644
--- a/debuggerd/protocol.h
+++ b/debuggerd/protocol.h
@@ -72,6 +72,7 @@ enum class InterceptStatus : uint8_t {
   kFailed,
   kStarted,
   kRegistered,
+  kTimeout,
 };
 
 // Sent either immediately upon failure, or when the intercept has been used.
@@ -81,17 +82,14 @@ struct InterceptResponse {
 };
 
 // Sent from handler to crash_dump via pipe.
-struct __attribute__((__packed__)) CrashInfoHeader {
+struct __attribute__((__packed__)) CrashInfoDataCommon {
   uint32_t version;
-};
-
-struct __attribute__((__packed__)) CrashInfoDataStatic {
   siginfo_t siginfo;
   ucontext_t ucontext;
   uintptr_t abort_msg_address;
 };
 
-struct __attribute__((__packed__)) CrashInfoDataDynamic : public CrashInfoDataStatic {
+struct __attribute__((__packed__)) CrashInfoDataDynamic {
   uintptr_t fdsan_table_address;
   uintptr_t gwp_asan_state;
   uintptr_t gwp_asan_metadata;
@@ -105,9 +103,8 @@ struct __attribute__((__packed__)) CrashInfoDataDynamic : public CrashInfoDataSt
 };
 
 struct __attribute__((__packed__)) CrashInfo {
-  CrashInfoHeader header;
-  union {
-    CrashInfoDataStatic s;
-    CrashInfoDataDynamic d;
-  } data;
+  // Present in both static executable and dynamic executable crashes.
+  CrashInfoDataCommon c;
+  // Present in only dynamic exectuable crashes.
+  CrashInfoDataDynamic d;
 };
diff --git a/debuggerd/seccomp_policy/crash_dump.arm.policy b/debuggerd/seccomp_policy/crash_dump.arm.policy
index a70ab203d2..624fae61a4 100644
--- a/debuggerd/seccomp_policy/crash_dump.arm.policy
+++ b/debuggerd/seccomp_policy/crash_dump.arm.policy
@@ -1,3 +1,8 @@
+# This file was auto-generated for the architecture arm.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
 read: 1
 write: 1
 exit: 1
@@ -18,22 +23,24 @@ close: 1
 lseek: 1
 getdents64: 1
 faccessat: 1
+readlinkat: 1
 recvmsg: 1
 recvfrom: 1
 setsockopt: 1
 sysinfo: 1
+uname: 1
 process_vm_readv: 1
 tgkill: 1
 rt_sigprocmask: 1
 rt_sigaction: 1
 rt_tgsigqueueinfo: 1
+mmap2: arg2 in 0x1|0x2
+mprotect: arg2 in 0x1|0x2
 prctl: arg0 == PR_GET_NO_NEW_PRIVS || arg0 == 0x53564d41
 madvise: 1
-mprotect: arg2 in 0x1|0x2
 munmap: 1
 getuid32: 1
 fstat64: 1
-mmap2: arg2 in 0x1|0x2
 geteuid32: 1
 getgid32: 1
 getegid32: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.arm64.policy b/debuggerd/seccomp_policy/crash_dump.arm64.policy
index c5d10d66b8..6e1aa3fd8d 100644
--- a/debuggerd/seccomp_policy/crash_dump.arm64.policy
+++ b/debuggerd/seccomp_policy/crash_dump.arm64.policy
@@ -1,3 +1,8 @@
+# This file was auto-generated for the architecture arm64.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
 read: 1
 write: 1
 exit: 1
@@ -17,22 +22,24 @@ close: 1
 lseek: 1
 getdents64: 1
 faccessat: 1
+readlinkat: 1
 recvmsg: 1
 recvfrom: 1
 setsockopt: 1
 sysinfo: 1
+uname: 1
 process_vm_readv: 1
 tgkill: 1
 rt_sigprocmask: 1
 rt_sigaction: 1
 rt_tgsigqueueinfo: 1
+mmap: arg2 in 0x1|0x2|0x20
+mprotect: arg2 in 0x1|0x2|0x20
 prctl: arg0 == PR_GET_NO_NEW_PRIVS || arg0 == 0x53564d41 || arg0 == PR_PAC_RESET_KEYS || arg0 == 56 || arg0 == 61
 madvise: 1
-mprotect: arg2 in 0x1|0x2|0x20
 munmap: 1
 getuid: 1
 fstat: 1
-mmap: arg2 in 0x1|0x2|0x20
 geteuid: 1
 getgid: 1
 getegid: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm.policy b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm.policy
new file mode 100644
index 0000000000..5c87ad236b
--- /dev/null
+++ b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm.policy
@@ -0,0 +1,44 @@
+# This file was auto-generated for the architecture arm.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
+read: 1
+write: 1
+exit: 1
+rt_sigreturn: 1
+sigreturn: 1
+exit_group: 1
+clock_gettime: 1
+gettimeofday: 1
+futex: 1
+getrandom: 1
+getpid: 1
+gettid: 1
+ppoll: 1
+pipe2: 1
+openat: 1
+dup: 1
+close: 1
+lseek: 1
+getdents64: 1
+faccessat: 1
+readlinkat: 1
+recvmsg: 1
+recvfrom: 1
+setsockopt: 1
+sysinfo: 1
+uname: 1
+process_vm_readv: 1
+tgkill: 1
+rt_sigprocmask: 1
+rt_sigaction: 1
+rt_tgsigqueueinfo: 1
+madvise: 1
+munmap: 1
+getuid32: 1
+fstat64: 1
+geteuid32: 1
+getgid32: 1
+getegid32: 1
+getgroups32: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm64.policy b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm64.policy
new file mode 100644
index 0000000000..d4ede2fe7b
--- /dev/null
+++ b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.arm64.policy
@@ -0,0 +1,43 @@
+# This file was auto-generated for the architecture arm64.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
+read: 1
+write: 1
+exit: 1
+rt_sigreturn: 1
+exit_group: 1
+clock_gettime: 1
+gettimeofday: 1
+futex: 1
+getrandom: 1
+getpid: 1
+gettid: 1
+ppoll: 1
+pipe2: 1
+openat: 1
+dup: 1
+close: 1
+lseek: 1
+getdents64: 1
+faccessat: 1
+readlinkat: 1
+recvmsg: 1
+recvfrom: 1
+setsockopt: 1
+sysinfo: 1
+uname: 1
+process_vm_readv: 1
+tgkill: 1
+rt_sigprocmask: 1
+rt_sigaction: 1
+rt_tgsigqueueinfo: 1
+madvise: 1
+munmap: 1
+getuid: 1
+fstat: 1
+geteuid: 1
+getgid: 1
+getegid: 1
+getgroups: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.riscv64.policy b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.riscv64.policy
new file mode 100644
index 0000000000..6d5cf02d09
--- /dev/null
+++ b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.riscv64.policy
@@ -0,0 +1,43 @@
+# This file was auto-generated for the architecture riscv64.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
+read: 1
+write: 1
+exit: 1
+rt_sigreturn: 1
+exit_group: 1
+clock_gettime: 1
+gettimeofday: 1
+futex: 1
+getrandom: 1
+getpid: 1
+gettid: 1
+ppoll: 1
+pipe2: 1
+openat: 1
+dup: 1
+close: 1
+lseek: 1
+getdents64: 1
+faccessat: 1
+readlinkat: 1
+recvmsg: 1
+recvfrom: 1
+setsockopt: 1
+sysinfo: 1
+uname: 1
+process_vm_readv: 1
+tgkill: 1
+rt_sigprocmask: 1
+rt_sigaction: 1
+rt_tgsigqueueinfo: 1
+madvise: 1
+munmap: 1
+getuid: 1
+fstat: 1
+geteuid: 1
+getgid: 1
+getegid: 1
+getgroups: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86.policy b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86.policy
new file mode 100644
index 0000000000..7fbdd12a25
--- /dev/null
+++ b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86.policy
@@ -0,0 +1,44 @@
+# This file was auto-generated for the architecture x86.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
+read: 1
+write: 1
+exit: 1
+rt_sigreturn: 1
+sigreturn: 1
+exit_group: 1
+clock_gettime: 1
+gettimeofday: 1
+futex: 1
+getrandom: 1
+getpid: 1
+gettid: 1
+ppoll: 1
+pipe2: 1
+openat: 1
+dup: 1
+close: 1
+lseek: 1
+getdents64: 1
+faccessat: 1
+readlinkat: 1
+recvmsg: 1
+recvfrom: 1
+setsockopt: 1
+sysinfo: 1
+uname: 1
+process_vm_readv: 1
+tgkill: 1
+rt_sigprocmask: 1
+rt_sigaction: 1
+rt_tgsigqueueinfo: 1
+madvise: 1
+munmap: 1
+getuid32: 1
+fstat64: 1
+geteuid32: 1
+getgid32: 1
+getegid32: 1
+getgroups32: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86_64.policy b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86_64.policy
new file mode 100644
index 0000000000..3ab15e16d5
--- /dev/null
+++ b/debuggerd/seccomp_policy/crash_dump.no_mmap_mprotect_prctl.x86_64.policy
@@ -0,0 +1,43 @@
+# This file was auto-generated for the architecture x86_64.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
+read: 1
+write: 1
+exit: 1
+rt_sigreturn: 1
+exit_group: 1
+clock_gettime: 1
+gettimeofday: 1
+futex: 1
+getrandom: 1
+getpid: 1
+gettid: 1
+ppoll: 1
+pipe2: 1
+openat: 1
+dup: 1
+close: 1
+lseek: 1
+getdents64: 1
+faccessat: 1
+readlinkat: 1
+recvmsg: 1
+recvfrom: 1
+setsockopt: 1
+sysinfo: 1
+uname: 1
+process_vm_readv: 1
+tgkill: 1
+rt_sigprocmask: 1
+rt_sigaction: 1
+rt_tgsigqueueinfo: 1
+madvise: 1
+munmap: 1
+getuid: 1
+fstat: 1
+geteuid: 1
+getgid: 1
+getegid: 1
+getgroups: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.policy.def b/debuggerd/seccomp_policy/crash_dump.policy.def
index dc751da6be..5f6b72cb07 100644
--- a/debuggerd/seccomp_policy/crash_dump.policy.def
+++ b/debuggerd/seccomp_policy/crash_dump.policy.def
@@ -23,10 +23,12 @@ close: 1
 lseek: 1
 getdents64: 1
 faccessat: 1
+readlinkat: 1
 recvmsg: 1
 recvfrom: 1
 setsockopt: 1
 sysinfo: 1
+uname: 1
 
 process_vm_readv: 1
 
@@ -46,9 +48,9 @@ rt_tgsigqueueinfo: 1
 
 #if defined(__aarch64__)
 // PR_PAC_RESET_KEYS happens on aarch64 in pthread_create path.
-prctl: arg0 == PR_GET_NO_NEW_PRIVS || arg0 == PR_SET_VMA || arg0 == PR_PAC_RESET_KEYS || arg0 == PR_GET_TAGGED_ADDR_CTRL || arg0 == PR_PAC_GET_ENABLED_KEYS
+#define PRCTL_RESTRICTIONS arg0 == PR_GET_NO_NEW_PRIVS || arg0 == PR_SET_VMA || arg0 == PR_PAC_RESET_KEYS || arg0 == PR_GET_TAGGED_ADDR_CTRL || arg0 == PR_PAC_GET_ENABLED_KEYS
 #else
-prctl: arg0 == PR_GET_NO_NEW_PRIVS || arg0 == PR_SET_VMA
+#define PRCTL_RESTRICTIONS arg0 == PR_GET_NO_NEW_PRIVS || arg0 == PR_SET_VMA
 #endif
 
 #if 0
@@ -60,26 +62,33 @@ Define values for PROT_READ, PROT_WRITE and PROT_MTE ourselves to maintain backw
 #define PROT_MTE 0x20
 #endif
 
-madvise: 1
 #if defined(__aarch64__)
-mprotect: arg2 in PROT_READ|PROT_WRITE|PROT_MTE
+#define MAP_FLAGS PROT_READ|PROT_WRITE|PROT_MTE
+#else
+#define MAP_FLAGS PROT_READ|PROT_WRITE
+#endif
+
+#if defined(__LP64__)
+#define MMAP mmap
 #else
-mprotect: arg2 in PROT_READ|PROT_WRITE
+#define MMAP mmap2
 #endif
+
+#if !defined(NO_MMAP_MPROTECT_PRCTL_RULES)
+MMAP: arg2 in MAP_FLAGS
+mprotect: arg2 in MAP_FLAGS
+prctl: PRCTL_RESTRICTIONS
+#endif // !defined(NO_MMAP_MPROTECT_PRCTL_RULES)
+
+madvise: 1
 munmap: 1
 
 #if defined(__LP64__)
 getuid: 1
 fstat: 1
-#if defined(__aarch64__)
-mmap: arg2 in PROT_READ|PROT_WRITE|PROT_MTE
-#else
-mmap: arg2 in PROT_READ|PROT_WRITE
-#endif
 #else
 getuid32: 1
 fstat64: 1
-mmap2: arg2 in PROT_READ|PROT_WRITE
 #endif
 
 // Needed for logging.
diff --git a/debuggerd/seccomp_policy/crash_dump.riscv64.policy b/debuggerd/seccomp_policy/crash_dump.riscv64.policy
index 94a56772a6..eb471b48a0 100644
--- a/debuggerd/seccomp_policy/crash_dump.riscv64.policy
+++ b/debuggerd/seccomp_policy/crash_dump.riscv64.policy
@@ -1,3 +1,8 @@
+# This file was auto-generated for the architecture riscv64.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
 read: 1
 write: 1
 exit: 1
@@ -17,22 +22,24 @@ close: 1
 lseek: 1
 getdents64: 1
 faccessat: 1
+readlinkat: 1
 recvmsg: 1
 recvfrom: 1
 setsockopt: 1
 sysinfo: 1
+uname: 1
 process_vm_readv: 1
 tgkill: 1
 rt_sigprocmask: 1
 rt_sigaction: 1
 rt_tgsigqueueinfo: 1
+mmap: arg2 in 0x1|0x2
+mprotect: arg2 in 0x1|0x2
 prctl: arg0 == PR_GET_NO_NEW_PRIVS || arg0 == 0x53564d41
 madvise: 1
-mprotect: arg2 in 0x1|0x2
 munmap: 1
 getuid: 1
 fstat: 1
-mmap: arg2 in 0x1|0x2
 geteuid: 1
 getgid: 1
 getegid: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.x86.policy b/debuggerd/seccomp_policy/crash_dump.x86.policy
index a70ab203d2..d360b7e9f8 100644
--- a/debuggerd/seccomp_policy/crash_dump.x86.policy
+++ b/debuggerd/seccomp_policy/crash_dump.x86.policy
@@ -1,3 +1,8 @@
+# This file was auto-generated for the architecture x86.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
 read: 1
 write: 1
 exit: 1
@@ -18,22 +23,24 @@ close: 1
 lseek: 1
 getdents64: 1
 faccessat: 1
+readlinkat: 1
 recvmsg: 1
 recvfrom: 1
 setsockopt: 1
 sysinfo: 1
+uname: 1
 process_vm_readv: 1
 tgkill: 1
 rt_sigprocmask: 1
 rt_sigaction: 1
 rt_tgsigqueueinfo: 1
+mmap2: arg2 in 0x1|0x2
+mprotect: arg2 in 0x1|0x2
 prctl: arg0 == PR_GET_NO_NEW_PRIVS || arg0 == 0x53564d41
 madvise: 1
-mprotect: arg2 in 0x1|0x2
 munmap: 1
 getuid32: 1
 fstat64: 1
-mmap2: arg2 in 0x1|0x2
 geteuid32: 1
 getgid32: 1
 getegid32: 1
diff --git a/debuggerd/seccomp_policy/crash_dump.x86_64.policy b/debuggerd/seccomp_policy/crash_dump.x86_64.policy
index 94a56772a6..c812492269 100644
--- a/debuggerd/seccomp_policy/crash_dump.x86_64.policy
+++ b/debuggerd/seccomp_policy/crash_dump.x86_64.policy
@@ -1,3 +1,8 @@
+# This file was auto-generated for the architecture x86_64.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
 read: 1
 write: 1
 exit: 1
@@ -17,22 +22,24 @@ close: 1
 lseek: 1
 getdents64: 1
 faccessat: 1
+readlinkat: 1
 recvmsg: 1
 recvfrom: 1
 setsockopt: 1
 sysinfo: 1
+uname: 1
 process_vm_readv: 1
 tgkill: 1
 rt_sigprocmask: 1
 rt_sigaction: 1
 rt_tgsigqueueinfo: 1
+mmap: arg2 in 0x1|0x2
+mprotect: arg2 in 0x1|0x2
 prctl: arg0 == PR_GET_NO_NEW_PRIVS || arg0 == 0x53564d41
 madvise: 1
-mprotect: arg2 in 0x1|0x2
 munmap: 1
 getuid: 1
 fstat: 1
-mmap: arg2 in 0x1|0x2
 geteuid: 1
 getgid: 1
 getegid: 1
diff --git a/debuggerd/seccomp_policy/generate.sh b/debuggerd/seccomp_policy/generate.sh
index c467d9efc1..37cac94367 100755
--- a/debuggerd/seccomp_policy/generate.sh
+++ b/debuggerd/seccomp_policy/generate.sh
@@ -1,11 +1,47 @@
 #!/bin/bash
 
-set -ex
+set -e
 
 cd "$(dirname "$0")"
 CPP='cpp -undef -E -P crash_dump.policy.def'
-$CPP -D__arm__ -o crash_dump.arm.policy
-$CPP -D__aarch64__ -D__LP64__ -o crash_dump.arm64.policy
-$CPP -D__riscv -D__LP64__ -o crash_dump.riscv64.policy
-$CPP -D__i386__ -o crash_dump.x86.policy
-$CPP -D__x86_64__ -D__LP64__ -o crash_dump.x86_64.policy
+arches=( \
+  "arm"      "-D__arm__" \
+  "arm64"    "-D__aarch64__ -D__LP64__" \
+  "riscv64"  "-D__riscv -D__LP64__" \
+  "x86"      "-D__i386__" \
+  "x86_64"   "-D__x86_64__ -D__LP64__" \
+)
+
+function generate_header() {
+  HEADER=\
+"# This file was auto-generated for the architecture ${1}.
+# Do not modify this file directly.
+# To regenerate all policy files run:
+#   cd system/core/debuggerd/seccomp_policy
+#   ./generate.sh
+"
+}
+
+# Normal pass
+for ((i = 0; i < ${#arches[@]}; i = i + 2)); do
+  arch=${arches[$i]}
+  arch_defines=${arches[$((i+1))]}
+  echo "Generating normal policy for ${arch}"
+  file="crash_dump.${arch}.policy"
+  ${CPP} ${arch_defines} -o ${file}
+  generate_header ${arch}
+  echo -e "${HEADER}$(cat ${file})" > ${file}
+done
+
+# Generate version without mmap/mprotect/prctl rules
+# This is needed for swcodec to be able to include the policy file since that
+# process requires a more permissive version of these syscalls.
+for ((i = 0; i < ${#arches[@]}; i = i + 2)); do
+  arch=${arches[$i]}
+  arch_defines=${arches[$((i+1))]}
+  echo "Generating no mmap/mprotect/prctl policy for ${arch}"
+  file="crash_dump.no_mmap_mprotect_prctl.${arch}.policy"
+  ${CPP} ${arch_defines} -DNO_MMAP_MPROTECT_PRCTL_RULES -o ${file}
+  generate_header ${arch}
+  echo -e "${HEADER}$(cat ${file})" > ${file}
+done
diff --git a/debuggerd/tombstoned/intercept_manager.cpp b/debuggerd/tombstoned/intercept_manager.cpp
index ac7b431329..2ee0b95161 100644
--- a/debuggerd/tombstoned/intercept_manager.cpp
+++ b/debuggerd/tombstoned/intercept_manager.cpp
@@ -56,6 +56,10 @@ static void intercept_close_cb(evutil_socket_t sockfd, short event, void* arg) {
   const char* reason = (event & EV_TIMEOUT) ? "due to timeout" : "due to input";
   LOG(INFO) << "intercept for pid " << intercept->pid << " and type " << intercept->dump_type
             << " terminated: " << reason;
+  if (event & EV_TIMEOUT) {
+    InterceptResponse response = {.status = InterceptStatus::kTimeout};
+    TEMP_FAILURE_RETRY(write(intercept->sockfd, &response, sizeof(response)));
+  }
 }
 
 void InterceptManager::Unregister(Intercept* intercept) {
@@ -260,8 +264,7 @@ bool InterceptManager::FindIntercept(pid_t pid, DebuggerdDumpType dump_type,
 
   LOG(INFO) << "found intercept fd " << intercept->output_fd.get() << " for pid " << pid
             << " and type " << intercept->dump_type;
-  InterceptResponse response = {};
-  response.status = InterceptStatus::kStarted;
+  InterceptResponse response = {.status = InterceptStatus::kStarted};
   TEMP_FAILURE_RETRY(write(intercept->sockfd, &response, sizeof(response)));
   *out_fd = std::move(intercept->output_fd);
 
diff --git a/debuggerd/tombstoned/tombstoned.cpp b/debuggerd/tombstoned/tombstoned.cpp
index dd20dc5dff..7177279ba8 100644
--- a/debuggerd/tombstoned/tombstoned.cpp
+++ b/debuggerd/tombstoned/tombstoned.cpp
@@ -54,11 +54,6 @@ using android::base::unique_fd;
 
 static InterceptManager* intercept_manager;
 
-enum CrashStatus {
-  kCrashStatusRunning,
-  kCrashStatusQueued,
-};
-
 struct CrashArtifact {
   unique_fd fd;
 
diff --git a/debuggerd/util.cpp b/debuggerd/util.cpp
index df033dfcc9..b80946887e 100644
--- a/debuggerd/util.cpp
+++ b/debuggerd/util.cpp
@@ -27,6 +27,8 @@
 #include <android-base/strings.h>
 #include "protocol.h"
 
+constexpr const char kUnknown[] = "<unknown>";
+
 std::vector<std::string> get_command_line(pid_t pid) {
   std::vector<std::string> result;
 
@@ -41,25 +43,33 @@ std::vector<std::string> get_command_line(pid_t pid) {
     it = std::find_if(terminator, cmdline.cend(), [](char c) { return c != '\0'; });
   }
   if (result.empty()) {
-    result.emplace_back("<unknown>");
+    return {kUnknown};
   }
 
   return result;
 }
 
 std::string get_process_name(pid_t pid) {
-  std::string result = "<unknown>";
+  std::string result(kUnknown);
   android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/cmdline", pid), &result);
   // We only want the name, not the whole command line, so truncate at the first NUL.
   return result.c_str();
 }
 
 std::string get_thread_name(pid_t tid) {
-  std::string result = "<unknown>";
+  std::string result(kUnknown);
   android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/comm", tid), &result);
   return android::base::Trim(result);
 }
 
+std::string get_executable_name(pid_t pid) {
+  std::string result;
+  if (!android::base::Readlink(android::base::StringPrintf("/proc/%d/exe", pid), &result)) {
+    return kUnknown;
+  }
+  return result;
+}
+
 std::string get_timestamp() {
   timespec ts;
   clock_gettime(CLOCK_REALTIME, &ts);
diff --git a/debuggerd/util.h b/debuggerd/util.h
index 43758702f2..46c398cd83 100644
--- a/debuggerd/util.h
+++ b/debuggerd/util.h
@@ -24,6 +24,7 @@
 #include <sys/types.h>
 
 std::vector<std::string> get_command_line(pid_t pid);
+std::string get_executable_name(pid_t pid);
 std::string get_process_name(pid_t pid);
 std::string get_thread_name(pid_t tid);
 
diff --git a/fastboot/device/commands.cpp b/fastboot/device/commands.cpp
index e522f4d4d3..06723fa93b 100644
--- a/fastboot/device/commands.cpp
+++ b/fastboot/device/commands.cpp
@@ -70,7 +70,7 @@ struct VariableHandlers {
 };
 
 static bool IsSnapshotUpdateInProgress(FastbootDevice* device) {
-    auto hal = device->boot1_1();
+    auto hal = device->boot_control_hal();
     if (!hal) {
         return false;
     }
@@ -349,8 +349,8 @@ bool SetActiveHandler(FastbootDevice* device, const std::vector<std::string>& ar
     }
 
     // Check how to handle the current snapshot state.
-    if (auto hal11 = device->boot1_1()) {
-        auto merge_status = hal11->getSnapshotMergeStatus();
+    if (auto hal = device->boot_control_hal()) {
+        auto merge_status = hal->getSnapshotMergeStatus();
         if (merge_status == MergeStatus::MERGING) {
             return device->WriteFail("Cannot change slots while a snapshot update is in progress");
         }
@@ -470,7 +470,7 @@ PartitionBuilder::PartitionBuilder(FastbootDevice* device, const std::string& pa
     : device_(device) {
     std::string slot_suffix = GetSuperSlotSuffix(device, partition_name);
     slot_number_ = android::fs_mgr::SlotNumberForSlotSuffix(slot_suffix);
-    auto super_device = FindPhysicalPartition(fs_mgr_get_super_partition_name(slot_number_));
+    auto super_device = FindPhysicalPartition(fs_mgr_get_super_partition_name());
     if (!super_device) {
         return;
     }
@@ -693,7 +693,7 @@ bool GsiHandler(FastbootDevice* device, const std::vector<std::string>& args) {
 bool SnapshotUpdateHandler(FastbootDevice* device, const std::vector<std::string>& args) {
     // Note that we use the HAL rather than mounting /metadata, since we want
     // our results to match the bootloader.
-    auto hal = device->boot1_1();
+    auto hal = device->boot_control_hal();
     if (!hal) return device->WriteFail("Not supported");
 
     // If no arguments, return the same thing as a getvar. Note that we get the
diff --git a/fastboot/device/fastboot_device.cpp b/fastboot/device/fastboot_device.cpp
index 0dc4e97640..43fd1bf355 100644
--- a/fastboot/device/fastboot_device.cpp
+++ b/fastboot/device/fastboot_device.cpp
@@ -150,14 +150,6 @@ std::string FastbootDevice::GetCurrentSlot() {
     return suffix;
 }
 
-BootControlClient* FastbootDevice::boot1_1() const {
-    if (boot_control_hal_ &&
-        boot_control_hal_->GetVersion() >= android::hal::BootControlVersion::BOOTCTL_V1_1) {
-        return boot_control_hal_.get();
-    }
-    return nullptr;
-}
-
 bool FastbootDevice::WriteStatus(FastbootResult result, const std::string& message) {
     constexpr size_t kResponseReasonSize = 4;
     constexpr size_t kNumResponseTypes = 4;  // "FAIL", "OKAY", "INFO", "DATA"
diff --git a/fastboot/device/fastboot_device.h b/fastboot/device/fastboot_device.h
index fcaf249d36..c0e5bf22ae 100644
--- a/fastboot/device/fastboot_device.h
+++ b/fastboot/device/fastboot_device.h
@@ -51,7 +51,6 @@ class FastbootDevice {
     std::vector<char>& download_data() { return download_data_; }
     Transport* get_transport() { return transport_.get(); }
     BootControlClient* boot_control_hal() const { return boot_control_hal_.get(); }
-    BootControlClient* boot1_1() const;
     std::shared_ptr<aidl::android::hardware::fastboot::IFastboot> fastboot_hal() {
         return fastboot_hal_;
     }
diff --git a/fastboot/device/flashing.cpp b/fastboot/device/flashing.cpp
index 05186a2ef2..520d92b601 100644
--- a/fastboot/device/flashing.cpp
+++ b/fastboot/device/flashing.cpp
@@ -185,14 +185,10 @@ int Flash(FastbootDevice* device, const std::string& partition_name) {
         return -EINVAL;
     }
     uint64_t block_device_size = get_block_device_size(handle.fd());
-    if (data.size() > block_device_size) {
-        LOG(ERROR) << "Cannot flash " << data.size() << " bytes to block device of size "
-                   << block_device_size;
-        return -EOVERFLOW;
-    } else if (data.size() < block_device_size &&
-               (partition_name == "boot" || partition_name == "boot_a" ||
-                partition_name == "boot_b" || partition_name == "init_boot" ||
-                partition_name == "init_boot_a" || partition_name == "init_boot_b")) {
+    if (data.size() < block_device_size &&
+        (partition_name == "boot" || partition_name == "boot_a" || partition_name == "boot_b" ||
+         partition_name == "init_boot" || partition_name == "init_boot_a" ||
+         partition_name == "init_boot_b")) {
         CopyAVBFooter(&data, block_device_size);
     }
     if (android::base::GetProperty("ro.system.build.type", "") != "user") {
diff --git a/fastboot/device/utility.cpp b/fastboot/device/utility.cpp
index e12ee64790..2655625349 100644
--- a/fastboot/device/utility.cpp
+++ b/fastboot/device/utility.cpp
@@ -52,7 +52,7 @@ bool OpenLogicalPartition(FastbootDevice* device, const std::string& partition_n
                           PartitionHandle* handle) {
     std::string slot_suffix = GetSuperSlotSuffix(device, partition_name);
     uint32_t slot_number = SlotNumberForSlotSuffix(slot_suffix);
-    auto path = FindPhysicalPartition(fs_mgr_get_super_partition_name(slot_number));
+    auto path = FindPhysicalPartition(fs_mgr_get_super_partition_name());
     if (!path) {
         return false;
     }
@@ -117,7 +117,7 @@ static const LpMetadataPartition* FindLogicalPartition(const LpMetadata& metadat
 bool LogicalPartitionExists(FastbootDevice* device, const std::string& name, bool* is_zero_length) {
     std::string slot_suffix = GetSuperSlotSuffix(device, name);
     uint32_t slot_number = SlotNumberForSlotSuffix(slot_suffix);
-    auto path = FindPhysicalPartition(fs_mgr_get_super_partition_name(slot_number));
+    auto path = FindPhysicalPartition(fs_mgr_get_super_partition_name());
     if (!path) {
         return false;
     }
@@ -164,31 +164,17 @@ std::vector<std::string> ListPartitions(FastbootDevice* device) {
         }
     }
 
-    // Find metadata in each super partition (on retrofit devices, there will
-    // be two).
-    std::vector<std::unique_ptr<LpMetadata>> metadata_list;
-
     uint32_t current_slot = SlotNumberForSlotSuffix(device->GetCurrentSlot());
-    std::string super_name = fs_mgr_get_super_partition_name(current_slot);
-    if (auto metadata = ReadMetadata(super_name, current_slot)) {
-        metadata_list.emplace_back(std::move(metadata));
-    }
-
-    uint32_t other_slot = (current_slot == 0) ? 1 : 0;
-    std::string other_super = fs_mgr_get_super_partition_name(other_slot);
-    if (super_name != other_super) {
-        if (auto metadata = ReadMetadata(other_super, other_slot)) {
-            metadata_list.emplace_back(std::move(metadata));
-        }
+    std::string super_name = fs_mgr_get_super_partition_name();
+    auto metadata = ReadMetadata(super_name, current_slot);
+    if (!metadata) {
+        return {};
     }
 
-    for (const auto& metadata : metadata_list) {
-        for (const auto& partition : metadata->partitions) {
-            std::string partition_name = GetPartitionName(partition);
-            if (std::find(partitions.begin(), partitions.end(), partition_name) ==
-                partitions.end()) {
-                partitions.emplace_back(partition_name);
-            }
+    for (const auto& partition : metadata->partitions) {
+        std::string partition_name = GetPartitionName(partition);
+        if (std::find(partitions.begin(), partitions.end(), partition_name) == partitions.end()) {
+            partitions.emplace_back(partition_name);
         }
     }
     return partitions;
@@ -218,7 +204,7 @@ std::string GetSuperSlotSuffix(FastbootDevice* device, const std::string& partit
     // retrofit device, and we should take the current slot.
     std::string current_slot_suffix = device->GetCurrentSlot();
     uint32_t current_slot_number = SlotNumberForSlotSuffix(current_slot_suffix);
-    std::string super_partition = fs_mgr_get_super_partition_name(current_slot_number);
+    std::string super_partition = fs_mgr_get_super_partition_name();
     if (GetPartitionSlotSuffix(super_partition).empty()) {
         return current_slot_suffix;
     }
diff --git a/fastboot/device/variables.cpp b/fastboot/device/variables.cpp
index 77210abcbc..59f2ba7014 100644
--- a/fastboot/device/variables.cpp
+++ b/fastboot/device/variables.cpp
@@ -451,10 +451,9 @@ bool GetHardwareRevision(FastbootDevice* /* device */, const std::vector<std::st
     return true;
 }
 
-bool GetSuperPartitionName(FastbootDevice* device, const std::vector<std::string>& /* args */,
+bool GetSuperPartitionName(FastbootDevice* /* device */, const std::vector<std::string>& /* args */,
                            std::string* message) {
-    uint32_t slot_number = SlotNumberForSlotSuffix(device->GetCurrentSlot());
-    *message = fs_mgr_get_super_partition_name(slot_number);
+    *message = fs_mgr_get_super_partition_name();
     return true;
 }
 
@@ -462,7 +461,7 @@ bool GetSnapshotUpdateStatus(FastbootDevice* device, const std::vector<std::stri
                              std::string* message) {
     // Note that we use the HAL rather than mounting /metadata, since we want
     // our results to match the bootloader.
-    auto hal = device->boot1_1();
+    auto hal = device->boot_control_hal();
     if (!hal) {
         *message = "not supported";
         return false;
diff --git a/fastboot/fastboot.cpp b/fastboot/fastboot.cpp
index 1c52da2382..0a521da600 100644
--- a/fastboot/fastboot.cpp
+++ b/fastboot/fastboot.cpp
@@ -1052,43 +1052,29 @@ int64_t get_sparse_limit(int64_t size, const FlashingPlan* fp) {
     return 0;
 }
 
-static bool load_buf_fd(unique_fd fd, struct fastboot_buffer* buf, const FlashingPlan* fp) {
-    int64_t sz = get_file_size(fd);
-    if (sz == -1) {
+static bool load_buf_fd(unique_fd fd, struct fastboot_buffer* buf) {
+    buf->sz = get_file_size(fd);
+    if (buf->sz == -1) {
         return false;
     }
 
-    if (sparse_file* s = sparse_file_import(fd.get(), false, false)) {
-        buf->image_size = sparse_file_len(s, false, false);
+    if (SparsePtr s(sparse_file_import(fd.get(), false, false), sparse_file_destroy); s) {
+        buf->image_size = sparse_file_len(s.get(), false, false);
         if (buf->image_size < 0) {
             LOG(ERROR) << "Could not compute length of sparse file";
             return false;
         }
-        sparse_file_destroy(s);
         buf->file_type = FB_BUFFER_SPARSE;
     } else {
-        buf->image_size = sz;
+        buf->image_size = buf->sz;
         buf->file_type = FB_BUFFER_FD;
     }
 
-    lseek(fd.get(), 0, SEEK_SET);
-    int64_t limit = get_sparse_limit(sz, fp);
     buf->fd = std::move(fd);
-    if (limit) {
-        buf->files = load_sparse_files(buf->fd.get(), limit);
-        if (buf->files.empty()) {
-            return false;
-        }
-        buf->type = FB_BUFFER_SPARSE;
-    } else {
-        buf->type = FB_BUFFER_FD;
-        buf->sz = sz;
-    }
-
     return true;
 }
 
-static bool load_buf(const char* fname, struct fastboot_buffer* buf, const FlashingPlan* fp) {
+static bool load_buf(const char* fname, struct fastboot_buffer* buf) {
     unique_fd fd(TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_BINARY)));
 
     if (fd == -1) {
@@ -1104,7 +1090,7 @@ static bool load_buf(const char* fname, struct fastboot_buffer* buf, const Flash
         return false;
     }
 
-    return load_buf_fd(std::move(fd), buf, fp);
+    return load_buf_fd(std::move(fd), buf);
 }
 
 static void rewrite_vbmeta_buffer(struct fastboot_buffer* buf, bool vbmeta_in_boot) {
@@ -1199,10 +1185,10 @@ static uint64_t get_partition_size(const std::string& partition) {
     return partition_size;
 }
 
-static void copy_avb_footer(const ImageSource* source, const std::string& partition,
+static void copy_avb_footer(const FlashingPlan* fp, const std::string& partition,
                             struct fastboot_buffer* buf) {
     if (buf->sz < AVB_FOOTER_SIZE || is_logical(partition) ||
-        should_flash_in_userspace(source, partition)) {
+        should_flash_in_userspace(fp->source.get(), partition)) {
         return;
     }
 
@@ -1268,9 +1254,9 @@ void flash_partition_files(const std::string& partition, const std::vector<Spars
     }
 }
 
-static void flash_buf(const ImageSource* source, const std::string& partition,
+static void flash_buf(const FlashingPlan* fp, const std::string& partition,
                       struct fastboot_buffer* buf, const bool apply_vbmeta) {
-    copy_avb_footer(source, partition, buf);
+    copy_avb_footer(fp, partition, buf);
 
     // Rewrite vbmeta if that's what we're flashing and modification has been requested.
     if (g_disable_verity || g_disable_verification) {
@@ -1284,16 +1270,15 @@ static void flash_buf(const ImageSource* source, const std::string& partition,
         }
     }
 
-    switch (buf->type) {
-        case FB_BUFFER_SPARSE: {
-            flash_partition_files(partition, buf->files);
-            break;
+    lseek(buf->fd.get(), 0, SEEK_SET);
+    if (int64_t limit = get_sparse_limit(buf->sz, fp)) {
+        auto files = load_sparse_files(buf->fd.get(), limit);
+        if (files.empty()) {
+            LOG(FATAL) << "Failed to resparse image for partition: " << partition;
         }
-        case FB_BUFFER_FD:
-            fb->FlashPartition(partition, buf->fd, buf->sz);
-            break;
-        default:
-            die("unknown buffer type: %d", buf->type);
+        flash_partition_files(partition, files);
+    } else {
+        fp->fb->FlashPartition(partition, buf->fd, buf->sz);
     }
 }
 
@@ -1483,7 +1468,7 @@ static std::string repack_ramdisk(const char* pname, struct fastboot_buffer* buf
         !android::base::StartsWith(pname_sv, "vendor_boot_b:")) {
         return std::string(pname_sv);
     }
-    if (buf->type != FB_BUFFER_FD) {
+    if (buf->file_type != FB_BUFFER_FD) {
         die("Flashing sparse vendor ramdisk image is not supported.");
     }
     if (buf->sz <= 0) {
@@ -1493,11 +1478,11 @@ static std::string repack_ramdisk(const char* pname, struct fastboot_buffer* buf
     std::string ramdisk(pname_sv.substr(pname_sv.find(':') + 1));
 
     if (!g_dtb_path.empty()) {
-        if (!load_buf(g_dtb_path.c_str(), &dtb_buf, nullptr)) {
+        if (!load_buf(g_dtb_path.c_str(), &dtb_buf)) {
             die("cannot load '%s': %s", g_dtb_path.c_str(), strerror(errno));
         }
 
-        if (dtb_buf.type != FB_BUFFER_FD) {
+        if (dtb_buf.file_type != FB_BUFFER_FD) {
             die("Flashing sparse vendor ramdisk image with dtb is not supported.");
         }
         if (dtb_buf.sz <= 0) {
@@ -1531,7 +1516,7 @@ void do_flash(const char* pname, const char* fname, const bool apply_vbmeta,
 
     if (fp->source) {
         unique_fd fd = fp->source->OpenFile(fname);
-        if (fd < 0 || !load_buf_fd(std::move(fd), &buf, fp)) {
+        if (fd < 0 || !load_buf_fd(std::move(fd), &buf)) {
             die("could not load '%s': %s", fname, strerror(errno));
         }
         std::vector<char> signature_data;
@@ -1541,7 +1526,7 @@ void do_flash(const char* pname, const char* fname, const bool apply_vbmeta,
             fb->Download("signature", signature_data);
             fb->RawCommand("signature", "installing signature");
         }
-    } else if (!load_buf(fname, &buf, fp)) {
+    } else if (!load_buf(fname, &buf)) {
         die("cannot load '%s': %s", fname, strerror(errno));
     }
 
@@ -1549,7 +1534,7 @@ void do_flash(const char* pname, const char* fname, const bool apply_vbmeta,
         fb->ResizePartition(pname, std::to_string(buf.image_size));
     }
     std::string flash_pname = repack_ramdisk(pname, &buf, fp->fb);
-    flash_buf(fp->source.get(), flash_pname, &buf, apply_vbmeta);
+    flash_buf(fp, flash_pname, &buf, apply_vbmeta);
 }
 
 // Sets slot_override as the active slot. If slot_override is blank,
@@ -1942,7 +1927,7 @@ void FlashAllTool::AddFlashTasks(const std::vector<std::pair<const Image*, std::
     for (const auto& [image, slot] : images) {
         fastboot_buffer buf;
         unique_fd fd = fp_->source->OpenFile(image->img_name);
-        if (fd < 0 || !load_buf_fd(std::move(fd), &buf, fp_)) {
+        if (fd < 0 || !load_buf_fd(std::move(fd), &buf)) {
             if (image->optional_if_no_image) {
                 continue;
             }
@@ -2101,11 +2086,11 @@ void fb_perform_format(const std::string& partition, int skip_if_not_supported,
     if (fd == -1) {
         die("Cannot open generated image: %s", strerror(errno));
     }
-    if (!load_buf_fd(std::move(fd), &buf, fp)) {
+    if (!load_buf_fd(std::move(fd), &buf)) {
         die("Cannot read image: %s", strerror(errno));
     }
 
-    flash_buf(fp->source.get(), partition, &buf, is_vbmeta_partition(partition));
+    flash_buf(fp, partition, &buf, is_vbmeta_partition(partition));
     return;
 
 failed:
@@ -2566,7 +2551,7 @@ int FastBootTool::Main(int argc, char* argv[]) {
             std::string filename = next_arg(&args);
 
             struct fastboot_buffer buf;
-            if (!load_buf(filename.c_str(), &buf, fp.get()) || buf.type != FB_BUFFER_FD) {
+            if (!load_buf(filename.c_str(), &buf) || buf.file_type != FB_BUFFER_FD) {
                 die("cannot load '%s'", filename.c_str());
             }
             fb->Download(filename, buf.fd.get(), buf.sz);
diff --git a/fastboot/fastboot.h b/fastboot/fastboot.h
index 6a4997049c..0ca9511740 100644
--- a/fastboot/fastboot.h
+++ b/fastboot/fastboot.h
@@ -57,9 +57,7 @@ enum fb_buffer_type {
 };
 
 struct fastboot_buffer {
-    fb_buffer_type type;
     fb_buffer_type file_type;
-    std::vector<SparsePtr> files;
     int64_t sz;
     unique_fd fd;
     int64_t image_size;
diff --git a/fs_mgr/Android.bp b/fs_mgr/Android.bp
index 87db98b087..a2d11bcc64 100644
--- a/fs_mgr/Android.bp
+++ b/fs_mgr/Android.bp
@@ -238,3 +238,26 @@ cc_binary {
         "set-verity-state",
     ],
 }
+
+cc_binary {
+    name: "userdata_alias_remove",
+    srcs: [
+        "userdata_alias_remove.cpp",
+    ],
+    header_libs: [
+        "libbase_headers",
+    ],
+    static_libs: [
+        "libfstab",
+    ],
+    shared_libs: [
+        "libbase",
+    ],
+    system_ext_specific: true,
+    init_rc: ["userdata.alias.remove.rc"],
+    cflags: [
+        "-Werror",
+        "-Wall",
+        "-Wextra",
+    ],
+}
diff --git a/fs_mgr/README.overlayfs.md b/fs_mgr/README.overlayfs.md
index df5d775fa4..d114cd20f4 100644
--- a/fs_mgr/README.overlayfs.md
+++ b/fs_mgr/README.overlayfs.md
@@ -96,12 +96,6 @@ Caveats
   may fail because of the scratch partition. If this happens, clear the scratch
   storage by running either either _fastboot flashall_ or _adb enable-verity_.
   Then reinstate the overrides and continue.
-- For implementation simplicity on retrofit dynamic partition devices,
-  take the whole alternate super (eg: if "*a*" slot, then the whole of
-  "*system_b*").
-  Since landing a filesystem on the alternate super physical device
-  without differentiating if it is setup to support logical or physical,
-  the alternate slot metadata and previous content will be lost.
 - There are other subtle caveats requiring complex logic to solve.
   Have evaluated them as too complex or not worth the trouble, please
   File a bug if a use case needs to be covered.
diff --git a/fs_mgr/fs_mgr.cpp b/fs_mgr/fs_mgr.cpp
index 204e690936..8c9544504d 100644
--- a/fs_mgr/fs_mgr.cpp
+++ b/fs_mgr/fs_mgr.cpp
@@ -49,6 +49,7 @@
 #include <android-base/chrono_utils.h>
 #include <android-base/file.h>
 #include <android-base/properties.h>
+#include <android-base/scopeguard.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <android-base/unique_fd.h>
@@ -92,11 +93,15 @@
 #define SYSFS_EXT4_VERITY "/sys/fs/ext4/features/verity"
 #define SYSFS_EXT4_CASEFOLD "/sys/fs/ext4/features/casefold"
 
+#define SYSFS_F2FS_LINEAR_LOOKUP "/sys/fs/f2fs/features/linear_lookup"
+
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
 
 using android::base::Basename;
 using android::base::GetBoolProperty;
+using android::base::GetIntProperty;
 using android::base::GetUintProperty;
+using android::base::make_scope_guard;
 using android::base::Realpath;
 using android::base::SetProperty;
 using android::base::StartsWith;
@@ -184,6 +189,28 @@ static bool umount_retry(const std::string& mount_point) {
     return umounted;
 }
 
+static const char* get_disable_linear_lookup_option(void) {
+    std::string linear_lookup_support;
+
+    if (!android::base::ReadFileToString(SYSFS_F2FS_LINEAR_LOOKUP, &linear_lookup_support)) {
+        PERROR << "Failed to open " << SYSFS_F2FS_LINEAR_LOOKUP;
+        return nullptr;
+    }
+
+    if (android::base::Trim(linear_lookup_support) != "supported") {
+        PERROR << "Current f2fs linear_lookup not supported by kernel";
+        return nullptr;
+    }
+
+    std::string prop = android::base::GetProperty("persist.fsck.disable_linear_lookup", "");
+    if (prop == "on") {
+        return "--nolinear-lookup=1";
+    } else if (prop == "off") {
+        return "--nolinear-lookup=0";
+    }
+    return nullptr;
+}
+
 static void check_fs(const std::string& blk_device, const std::string& fs_type,
                      const std::string& target, int* fs_stat) {
     int status;
@@ -256,23 +283,26 @@ static void check_fs(const std::string& blk_device, const std::string& fs_type,
             }
         }
     } else if (is_f2fs(fs_type)) {
-        const char* f2fs_fsck_argv[] = {F2FS_FSCK_BIN,     "-a", "-c", "10000", "--debug-cache",
-                                        blk_device.c_str()};
-        const char* f2fs_fsck_forced_argv[] = {
-                F2FS_FSCK_BIN, "-f", "-c", "10000", "--debug-cache", blk_device.c_str()};
-
         if (access(F2FS_FSCK_BIN, X_OK)) {
             LINFO << "Not running " << F2FS_FSCK_BIN << " on " << realpath(blk_device)
                   << " (executable not in system image)";
         } else {
-            if (should_force_check(*fs_stat)) {
-                LINFO << "Running " << F2FS_FSCK_BIN << " -f -c 10000 --debug-cache "
-                      << realpath(blk_device);
-                ret = logwrap_fork_execvp(ARRAY_SIZE(f2fs_fsck_forced_argv), f2fs_fsck_forced_argv,
-                                          &status, false, LOG_KLOG | LOG_FILE, false,
-                                          FSCK_LOG_FILE);
+            const char* linear_lookup_option = get_disable_linear_lookup_option();
+            const char* force = should_force_check(*fs_stat) ? "-f" : "-a";
+
+            if (linear_lookup_option) {
+                const char* f2fs_fsck_argv[] = {
+                        F2FS_FSCK_BIN,     force,           "-c",
+                        "10000",           "--debug-cache", linear_lookup_option,
+                        blk_device.c_str()};
+                LINFO << "Running " << F2FS_FSCK_BIN << " " << force << " -c 10000 --debug-cache "
+                      << linear_lookup_option << " " << realpath(blk_device);
+                ret = logwrap_fork_execvp(ARRAY_SIZE(f2fs_fsck_argv), f2fs_fsck_argv, &status,
+                                          false, LOG_KLOG | LOG_FILE, false, FSCK_LOG_FILE);
             } else {
-                LINFO << "Running " << F2FS_FSCK_BIN << " -a -c 10000 --debug-cache "
+                const char* f2fs_fsck_argv[] = {F2FS_FSCK_BIN, force,           "-c",
+                                                "10000",       "--debug-cache", blk_device.c_str()};
+                LINFO << "Running " << F2FS_FSCK_BIN << " " << force << " -c 10000 --debug-cache "
                       << realpath(blk_device);
                 ret = logwrap_fork_execvp(ARRAY_SIZE(f2fs_fsck_argv), f2fs_fsck_argv, &status,
                                           false, LOG_KLOG | LOG_FILE, false, FSCK_LOG_FILE);
@@ -829,6 +859,8 @@ static int __mount(const std::string& source, const std::string& target, const F
     std::string checkpoint_opts;
     bool try_f2fs_gc_allowance = is_f2fs(entry.fs_type) && entry.fs_checkpoint_opts.length() > 0;
     bool try_f2fs_fallback = false;
+    bool try_f2fs_quota =
+            is_f2fs(entry.fs_type) && GetIntProperty("ro.product.first_api_level", -1) > 36;
     Timer t;
 
     do {
@@ -846,6 +878,9 @@ static int __mount(const std::string& source, const std::string& target, const F
             checkpoint_opts = "";
         }
         opts = entry.fs_options + checkpoint_opts;
+        if (try_f2fs_quota) {
+            opts += ",usrquota,grpquota,prjquota";
+        }
         if (save_errno == EAGAIN) {
             PINFO << "Retrying mount (source=" << source << ",target=" << target
                   << ",type=" << entry.fs_type << ", gc_allowance=" << gc_allowance << "%)=" << ret
@@ -1988,9 +2023,12 @@ static bool PrepareZramBackingDevice(off64_t size) {
         PERROR << "Cannot open target path: " << file_path;
         return false;
     }
+
+    // Always unlink zram_swap file to prevent file system access.
+    auto unlink_zram_swap_guard = make_scope_guard([] { unlink(file_path); });
+
     if (fallocate(target_fd.get(), 0, 0, size) < 0) {
         PERROR << "Cannot truncate target path: " << file_path;
-        unlink(file_path);
         return false;
     }
 
@@ -2248,7 +2286,7 @@ bool fs_mgr_verity_is_check_at_most_once(const android::fs_mgr::FstabEntry& entr
     return hashtree_info->check_at_most_once;
 }
 
-std::string fs_mgr_get_super_partition_name(int slot) {
+std::string fs_mgr_get_super_partition_name() {
     // Devices upgrading to dynamic partitions are allowed to specify a super
     // partition name. This includes cuttlefish, which is a non-A/B device.
     std::string super_partition;
@@ -2256,18 +2294,7 @@ std::string fs_mgr_get_super_partition_name(int slot) {
         return super_partition;
     }
     if (fs_mgr_get_boot_config("super_partition", &super_partition)) {
-        if (fs_mgr_get_slot_suffix().empty()) {
-            return super_partition;
-        }
-        std::string suffix;
-        if (slot == 0) {
-            suffix = "_a";
-        } else if (slot == 1) {
-            suffix = "_b";
-        } else if (slot == -1) {
-            suffix = fs_mgr_get_slot_suffix();
-        }
-        return super_partition + suffix;
+        return super_partition;
     }
     return LP_METADATA_DEFAULT_PARTITION_NAME;
 }
@@ -2427,25 +2454,11 @@ OverlayfsCheckResult CheckOverlayfs() {
         return {.supported = false};
     }
 
-    if (!use_override_creds) {
-        if (major > 5 || (major == 5 && minor >= 15)) {
-            return {.supported = true, ",userxattr"};
-        }
-        return {.supported = true};
+    if (major > 5 || (major == 5 && minor >= 15)) {
+        return {.supported = true, ",userxattr"};
     }
 
-    // Overlayfs available in the kernel, and patched for override_creds?
-    if (access("/sys/module/overlay/parameters/override_creds", F_OK) == 0) {
-        auto mount_flags = ",override_creds=off"s;
-        if (major > 5 || (major == 5 && minor >= 15)) {
-            mount_flags += ",userxattr"s;
-        }
-        return {.supported = true, .mount_flags = mount_flags};
-    }
-    if (major < 4 || (major == 4 && minor <= 3)) {
-        return {.supported = true};
-    }
-    return {.supported = false};
+    return {.supported = true};
 }
 
 }  // namespace fs_mgr
diff --git a/fs_mgr/fs_mgr_overlayfs_control.cpp b/fs_mgr/fs_mgr_overlayfs_control.cpp
index 489b32e7e7..20d3177d02 100644
--- a/fs_mgr/fs_mgr_overlayfs_control.cpp
+++ b/fs_mgr/fs_mgr_overlayfs_control.cpp
@@ -389,7 +389,7 @@ bool MakeScratchFilesystem(const std::string& scratch_device) {
         fs_type = "f2fs";
         command = kMkF2fs + " -b "s;
         command += std::to_string(fs_mgr_f2fs_ideal_block_size());
-        command += " -f -d1 -l" + android::base::Basename(kScratchMountPoint);
+        command += " -g android -f -d1 -l" + android::base::Basename(kScratchMountPoint);
     } else if (!access(kMkExt4, X_OK) && fs_mgr_filesystem_available("ext4")) {
         fs_type = "ext4";
         command = kMkExt4 + " -F -b 4096 -t ext4 -m 0 -O has_journal -M "s + kScratchMountPoint;
diff --git a/fs_mgr/fs_mgr_overlayfs_mount.cpp b/fs_mgr/fs_mgr_overlayfs_mount.cpp
index 762e70dc7e..1b54b54962 100644
--- a/fs_mgr/fs_mgr_overlayfs_mount.cpp
+++ b/fs_mgr/fs_mgr_overlayfs_mount.cpp
@@ -49,10 +49,6 @@
 #include "fs_mgr_overlayfs_mount.h"
 #include "fs_mgr_priv.h"
 
-// Flag to simplify algorithm for choosing which partitions to overlay to simply overlay
-// all dynamic partitions
-constexpr bool overlay_dynamic_partitions_only = true;
-
 using namespace std::literals;
 using namespace android::fs_mgr;
 using namespace android::storage_literals;
@@ -133,95 +129,6 @@ bool fs_mgr_filesystem_has_space(const std::string& mount_point) {
            (static_cast<uint64_t>(vst.f_bfree) * vst.f_frsize) >= kSizeThreshold;
 }
 
-static bool fs_mgr_update_blk_device(FstabEntry* entry) {
-    if (entry->fs_mgr_flags.logical) {
-        fs_mgr_update_logical_partition(entry);
-    }
-    if (access(entry->blk_device.c_str(), F_OK) == 0) {
-        return true;
-    }
-    if (entry->blk_device != "/dev/root") {
-        return false;
-    }
-
-    // special case for system-as-root (taimen and others)
-    auto blk_device = kPhysicalDevice + "system"s;
-    if (access(blk_device.c_str(), F_OK)) {
-        blk_device += fs_mgr_get_slot_suffix();
-        if (access(blk_device.c_str(), F_OK)) {
-            return false;
-        }
-    }
-    entry->blk_device = blk_device;
-    return true;
-}
-
-static bool fs_mgr_has_shared_blocks(const std::string& mount_point, const std::string& dev) {
-    struct statfs fs;
-    if ((statfs((mount_point + "/lost+found").c_str(), &fs) == -1) ||
-        (fs.f_type != EXT4_SUPER_MAGIC)) {
-        return false;
-    }
-
-    android::base::unique_fd fd(open(dev.c_str(), O_RDONLY | O_CLOEXEC));
-    if (fd < 0) return false;
-
-    struct ext4_super_block sb;
-    if ((TEMP_FAILURE_RETRY(lseek64(fd, 1024, SEEK_SET)) < 0) ||
-        (TEMP_FAILURE_RETRY(read(fd, &sb, sizeof(sb))) < 0)) {
-        return false;
-    }
-
-    struct fs_info info;
-    if (ext4_parse_sb(&sb, &info) < 0) return false;
-
-    return (info.feat_ro_compat & EXT4_FEATURE_RO_COMPAT_SHARED_BLOCKS) != 0;
-}
-
-#define F2FS_SUPER_OFFSET 1024
-#define F2FS_FEATURE_OFFSET 2180
-#define F2FS_FEATURE_RO 0x4000
-static bool fs_mgr_is_read_only_f2fs(const std::string& dev) {
-    if (!fs_mgr_is_f2fs(dev)) return false;
-
-    android::base::unique_fd fd(open(dev.c_str(), O_RDONLY | O_CLOEXEC));
-    if (fd < 0) return false;
-
-    __le32 feat;
-    if ((TEMP_FAILURE_RETRY(lseek64(fd, F2FS_SUPER_OFFSET + F2FS_FEATURE_OFFSET, SEEK_SET)) < 0) ||
-        (TEMP_FAILURE_RETRY(read(fd, &feat, sizeof(feat))) < 0)) {
-        return false;
-    }
-
-    return (feat & cpu_to_le32(F2FS_FEATURE_RO)) != 0;
-}
-
-static bool fs_mgr_overlayfs_enabled(FstabEntry* entry) {
-    // readonly filesystem, can not be mount -o remount,rw
-    // for squashfs, erofs, or if there are shared blocks that prevent remount,rw
-    if (entry->fs_type == "erofs" || entry->fs_type == "squashfs") {
-        return true;
-    }
-
-    // blk_device needs to be setup so we can check superblock.
-    // If we fail here, because during init first stage and have doubts.
-    if (!fs_mgr_update_blk_device(entry)) {
-        return true;
-    }
-
-    // f2fs read-only mode doesn't support remount,rw
-    if (fs_mgr_is_read_only_f2fs(entry->blk_device)) {
-        return true;
-    }
-
-    // check if ext4 de-dupe
-    auto has_shared_blocks = fs_mgr_has_shared_blocks(entry->mount_point, entry->blk_device);
-    if (!has_shared_blocks && (entry->mount_point == "/system")) {
-        has_shared_blocks = fs_mgr_has_shared_blocks("/", entry->blk_device);
-    }
-    return has_shared_blocks;
-}
-
 const std::string fs_mgr_mount_point(const std::string& mount_point) {
     if ("/"s != mount_point) return mount_point;
     return "/system";
@@ -644,24 +551,7 @@ bool OverlayfsSetupAllowed(bool verbose) {
 }
 
 bool fs_mgr_wants_overlayfs(FstabEntry* entry) {
-    // Don't check entries that are managed by vold.
-    if (entry->fs_mgr_flags.vold_managed || entry->fs_mgr_flags.recovery_only) return false;
-
-    // *_other doesn't want overlayfs.
-    if (entry->fs_mgr_flags.slot_select_other) return false;
-
-    // Only concerned with readonly partitions.
-    if (!(entry->flags & MS_RDONLY)) return false;
-
-    // If unbindable, do not allow overlayfs as this could expose us to
-    // security issues.  On Android, this could also be used to turn off
-    // the ability to overlay an otherwise acceptable filesystem since
-    // /system and /vendor are never bound(sic) to.
-    if (entry->flags & MS_UNBINDABLE) return false;
-
-    if (!fs_mgr_overlayfs_enabled(entry)) return false;
-
-    return true;
+    return entry->fs_mgr_flags.overlay_on || entry->fs_mgr_flags.logical;
 }
 
 Fstab fs_mgr_overlayfs_candidate_list(const Fstab& fstab) {
@@ -675,38 +565,9 @@ Fstab fs_mgr_overlayfs_candidate_list(const Fstab& fstab) {
     for (const auto& entry : fstab) {
         // fstab overlay flag overrides all other behavior
         if (entry.fs_mgr_flags.overlay_off) continue;
-        if (entry.fs_mgr_flags.overlay_on) {
+        if (entry.fs_mgr_flags.overlay_on || entry.fs_mgr_flags.logical) {
             candidates.push_back(entry);
-            continue;
-        }
-
-        // overlay_dynamic_partitions_only simplifies logic to overlay exactly dynamic partitions
-        if (overlay_dynamic_partitions_only) {
-            if (entry.fs_mgr_flags.logical) candidates.push_back(entry);
-            continue;
-        }
-
-        // Filter out partitions whose type doesn't match what's mounted.
-        // This avoids spammy behavior on devices which can mount different
-        // filesystems for each partition.
-        auto proc_mount_point = (entry.mount_point == "/system") ? "/" : entry.mount_point;
-        auto mounted = GetEntryForMountPoint(&mounts, proc_mount_point);
-        if (!mounted || mounted->fs_type != entry.fs_type) {
-            continue;
-        }
-
-        FstabEntry new_entry = entry;
-        if (!fs_mgr_overlayfs_already_mounted(entry.mount_point) &&
-            !fs_mgr_wants_overlayfs(&new_entry)) {
-            continue;
-        }
-        const auto new_mount_point = fs_mgr_mount_point(new_entry.mount_point);
-        if (std::find_if(candidates.begin(), candidates.end(), [&](const auto& it) {
-                return fs_mgr_mount_point(it.mount_point) == new_mount_point;
-            }) != candidates.end()) {
-            continue;
         }
-        candidates.push_back(std::move(new_entry));
     }
     return candidates;
 }
diff --git a/fs_mgr/fs_mgr_remount.cpp b/fs_mgr/fs_mgr_remount.cpp
index f91d2327c8..4118004a83 100644
--- a/fs_mgr/fs_mgr_remount.cpp
+++ b/fs_mgr/fs_mgr_remount.cpp
@@ -150,8 +150,7 @@ static bool ReadFstab(const char* fstab_file, android::fs_mgr::Fstab* fstab) {
 }
 
 bool VerifyCheckpointing() {
-    if (!android::base::GetBoolProperty("ro.virtual_ab.enabled", false) &&
-        !android::base::GetBoolProperty("ro.virtual_ab.retrofit", false)) {
+    if (!android::base::GetBoolProperty("ro.virtual_ab.enabled", false)) {
         return true;
     }
 
diff --git a/fs_mgr/include/fs_mgr.h b/fs_mgr/include/fs_mgr.h
index 79690874e2..cfa574395d 100644
--- a/fs_mgr/include/fs_mgr.h
+++ b/fs_mgr/include/fs_mgr.h
@@ -99,10 +99,8 @@ int fs_mgr_do_format(const android::fs_mgr::FstabEntry& entry);
 #define FS_MGR_SETUP_VERITY_SUCCESS 0
 int fs_mgr_setup_verity(android::fs_mgr::FstabEntry* fstab, bool wait_for_verity_dev);
 
-// Return the name of the super partition if it exists. If a slot number is
-// specified, the super partition for the corresponding metadata slot will be
-// returned. Otherwise, it will use the current slot.
-std::string fs_mgr_get_super_partition_name(int slot = -1);
+// Return the name of the super partition if it exists.
+std::string fs_mgr_get_super_partition_name();
 
 // Set readonly for the block device
 bool fs_mgr_set_blk_ro(const std::string& blockdev, bool readonly = true);
diff --git a/fs_mgr/include/fs_mgr_overlayfs.h b/fs_mgr/include/fs_mgr_overlayfs.h
index 253013bdf5..bf68b2c813 100644
--- a/fs_mgr/include/fs_mgr_overlayfs.h
+++ b/fs_mgr/include/fs_mgr_overlayfs.h
@@ -43,11 +43,5 @@ void MapScratchPartitionIfNeeded(Fstab* fstab,
 // overlays if any partition is flashed or updated.
 void TeardownAllOverlayForMountPoint(const std::string& mount_point = {});
 
-// Are we using overlayfs's non-upstreamed override_creds feature?
-// b/388912628 removes the need for override_creds
-// Once this bug is fixed and has had enough soak time, remove this variable and hard code to false
-// where it used
-constexpr bool use_override_creds = false;
-
 }  // namespace fs_mgr
 }  // namespace android
diff --git a/fs_mgr/libdm/dm.cpp b/fs_mgr/libdm/dm.cpp
index 94c320ac4d..2f84f6a512 100644
--- a/fs_mgr/libdm/dm.cpp
+++ b/fs_mgr/libdm/dm.cpp
@@ -329,7 +329,7 @@ bool DeviceMapper::LoadTable(const std::string& name, const DmTable& table) {
         io->flags |= DM_READONLY_FLAG;
     }
     if (ioctl(fd_, DM_TABLE_LOAD, io)) {
-        PLOG(ERROR) << "DM_TABLE_LOAD failed";
+        PLOG(ERROR) << "DM_TABLE_LOAD failed: name=" << name << ", table=" << table.Serialize();
         return false;
     }
     return true;
diff --git a/fs_mgr/libdm/include/libdm/dm_target.h b/fs_mgr/libdm/include/libdm/dm_target.h
index c49fc5ec82..5d8821bcd7 100644
--- a/fs_mgr/libdm/include/libdm/dm_target.h
+++ b/fs_mgr/libdm/include/libdm/dm_target.h
@@ -309,7 +309,7 @@ class DmTargetDefaultKey final : public DmTarget {
           blockdev_(blockdev),
           start_sector_(start_sector) {}
 
-    std::string name() const override { return kName; }
+    std::string name() const override { return "default-key"; }
     bool Valid() const override;
     std::string GetParameterString() const override;
     void SetUseLegacyOptionsFormat() { use_legacy_options_format_ = true; }
@@ -317,8 +317,6 @@ class DmTargetDefaultKey final : public DmTarget {
     void SetWrappedKeyV0() { is_hw_wrapped_ = true; }
 
   private:
-    inline static const std::string kName = "default-key";
-
     std::string cipher_;
     std::string key_;
     std::string blockdev_;
diff --git a/fs_mgr/libdm/include/libdm/loop_control.h b/fs_mgr/libdm/include/libdm/loop_control.h
index f5190544e3..946abd811d 100644
--- a/fs_mgr/libdm/include/libdm/loop_control.h
+++ b/fs_mgr/libdm/include/libdm/loop_control.h
@@ -43,6 +43,12 @@ class LoopControl final {
     // Detach the loop device given by 'loopdev' from the attached backing file.
     bool Detach(const std::string& loopdev) const;
 
+    // Add a new loop device with given 'id'.
+    bool Add(int id) const;
+
+    // Remove the device with given 'id'.
+    bool Remove(int id) const;
+
     // Enable Direct I/O on a loop device. This requires kernel 4.9+.
     static bool EnableDirectIo(int fd);
 
@@ -60,6 +66,8 @@ class LoopControl final {
     static constexpr const char* kLoopControlDevice = "/dev/loop-control";
 
     android::base::unique_fd control_fd_;
+
+    friend struct LoopControlTest;
 };
 
 // Create a temporary loop device around a file descriptor or path.
diff --git a/fs_mgr/libdm/loop_control.cpp b/fs_mgr/libdm/loop_control.cpp
index 32d5f383e7..949204b56c 100644
--- a/fs_mgr/libdm/loop_control.cpp
+++ b/fs_mgr/libdm/loop_control.cpp
@@ -98,6 +98,27 @@ bool LoopControl::Detach(const std::string& loopdev) const {
     return true;
 }
 
+bool LoopControl::Add(int id) const {
+    int rc = ioctl(control_fd_, LOOP_CTL_ADD, id);
+    if (rc < 0) {
+        // To avoid logspam
+        if (errno != EEXIST) {
+            PLOG(ERROR) << "Failed LOOP_CTL_ADD to add a loop device " << id;
+        }
+        return false;
+    }
+    return true;
+}
+
+bool LoopControl::Remove(int id) const {
+    int rc = ioctl(control_fd_, LOOP_CTL_REMOVE, id);
+    if (rc < 0) {
+        PLOG(ERROR) << "Failed LOOP_CTL_REMOVE to remove a loop device " << id;
+        return false;
+    }
+    return true;
+}
+
 bool LoopControl::FindFreeLoopDevice(std::string* loopdev) const {
     int rc = ioctl(control_fd_, LOOP_CTL_GET_FREE);
     if (rc < 0) {
diff --git a/fs_mgr/libdm/loop_control_test.cpp b/fs_mgr/libdm/loop_control_test.cpp
index 0749f26d99..27c45b3fcf 100644
--- a/fs_mgr/libdm/loop_control_test.cpp
+++ b/fs_mgr/libdm/loop_control_test.cpp
@@ -29,8 +29,10 @@
 #include "test_util.h"
 
 using namespace std;
-using namespace android::dm;
-using unique_fd = android::base::unique_fd;
+using android::base::Basename;
+using android::base::unique_fd;
+
+namespace android::dm {
 
 static unique_fd TempFile() {
     // A loop device needs to be at least one sector to actually work, so fill
@@ -62,3 +64,26 @@ TEST(libdm, LoopControl) {
     ASSERT_TRUE(android::base::ReadFully(loop_fd, buffer, sizeof(buffer)));
     ASSERT_EQ(memcmp(buffer, "Hello", 6), 0);
 }
+
+struct LoopControlTest : ::testing::Test {
+    LoopControl control;
+    // indirection to access private LoopControl::FindFreeLoopDevice() method
+    bool FindFreeLoopDevice(std::string* loopdev) const {
+        return control.FindFreeLoopDevice(loopdev);
+    }
+};
+
+TEST_F(LoopControlTest, AddRemove) {
+    // Get an id for a free loop device first
+    std::string path;
+    ASSERT_TRUE(FindFreeLoopDevice(&path));
+    std::string name = Basename(path);
+    ASSERT_EQ(name.substr(0, 4), "loop");
+    int id = atoi(name.substr(4).c_str());
+
+    ASSERT_FALSE(control.Add(id));
+    ASSERT_TRUE(control.Remove(id));
+    ASSERT_TRUE(control.Add(id));
+}
+
+}  // namespace android::dm
diff --git a/fs_mgr/libfiemap/image_manager.cpp b/fs_mgr/libfiemap/image_manager.cpp
index bc61d15bce..435f7bdf9e 100644
--- a/fs_mgr/libfiemap/image_manager.cpp
+++ b/fs_mgr/libfiemap/image_manager.cpp
@@ -521,36 +521,38 @@ bool ImageManager::MapImageDevice(const std::string& name,
         return false;
     }
 
-    auto image_header = GetImageHeaderPath(name);
-
 #ifndef __ANDROID_RAMDISK__
-    // If there is a device-mapper node wrapping the block device, then we're
-    // able to create another node around it; the dm layer does not carry the
-    // exclusion lock down the stack when a mount occurs.
-    //
-    // If there is no intermediate device-mapper node, then partitions cannot be
-    // opened writable due to sepolicy and exclusivity of having a mounted
-    // filesystem. This should only happen on devices with no encryption, or
-    // devices with FBE and no metadata encryption. For these cases we COULD
-    // perform normal writes to /data/gsi (which is unencrypted), but given that
-    // metadata encryption has been mandated since Android R, we don't actually
-    // support or test this.
-    //
-    // So, we validate here that /data is backed by device-mapper. This code
-    // isn't needed in recovery since there is no /data.
-    //
-    // If this logic sticks for a release, we can remove MapWithLoopDevice, as
-    // well as WrapUserdataIfNeeded in fs_mgr.
-    std::string block_device;
-    bool can_use_devicemapper;
-    if (!FiemapWriter::GetBlockDeviceForFile(image_header, &block_device, &can_use_devicemapper)) {
-        LOG(ERROR) << "Could not determine block device for " << image_header;
-        return false;
-    }
+    auto image_header = GetImageHeaderPath(name);
+    if (access(image_header.c_str(), F_OK) == 0) {
+        // If there is a device-mapper node wrapping the block device, then we're
+        // able to create another node around it; the dm layer does not carry the
+        // exclusion lock down the stack when a mount occurs.
+        //
+        // If there is no intermediate device-mapper node, then partitions cannot be
+        // opened writable due to sepolicy and exclusivity of having a mounted
+        // filesystem. This should only happen on devices with no encryption, or
+        // devices with FBE and no metadata encryption. For these cases we COULD
+        // perform normal writes to /data/gsi (which is unencrypted), but given that
+        // metadata encryption has been mandated since Android R, we don't actually
+        // support or test this.
+        //
+        // So, we validate here that /data is backed by device-mapper. This code
+        // isn't needed in recovery since there is no /data.
+        //
+        // If this logic sticks for a release, we can remove MapWithLoopDevice, as
+        // well as WrapUserdataIfNeeded in fs_mgr.
+        std::string block_device;
+        bool can_use_devicemapper;
+        if (!FiemapWriter::GetBlockDeviceForFile(image_header, &block_device,
+                                                 &can_use_devicemapper)) {
+            LOG(ERROR) << "Could not determine block device for " << image_header;
+            return false;
+        }
 
-    if (!can_use_devicemapper) {
-        LOG(ERROR) << "Cannot map image: /data must be mounted on top of device-mapper.";
-        return false;
+        if (!can_use_devicemapper) {
+            LOG(ERROR) << "Cannot map image: /data must be mounted on top of device-mapper.";
+            return false;
+        }
     }
 #endif
 
diff --git a/fs_mgr/libfs_avb/tests/fs_avb_device_test.cpp b/fs_mgr/libfs_avb/tests/fs_avb_device_test.cpp
index c8605d748f..79ddbebebf 100644
--- a/fs_mgr/libfs_avb/tests/fs_avb_device_test.cpp
+++ b/fs_mgr/libfs_avb/tests/fs_avb_device_test.cpp
@@ -59,9 +59,7 @@ TEST(FsAvbUtilTest, GetHashtreeDescriptor_SystemOther) {
     if (fs_mgr_get_slot_suffix() == "") return;
 
     // Skip running this test if system_other is a logical partition.
-    // Note that system_other is still a physical partition on "retrofit" devices.
-    if (android::base::GetBoolProperty("ro.boot.dynamic_partitions", false) &&
-        !android::base::GetBoolProperty("ro.boot.dynamic_partitions_retrofit", false)) {
+    if (android::base::GetBoolProperty("ro.boot.dynamic_partitions", false)) {
         return;
     }
 
@@ -98,9 +96,7 @@ TEST(AvbHandleTest, LoadAndVerifyVbmeta_SystemOther) {
     if (fs_mgr_get_slot_suffix() == "") return;
 
     // Skip running this test if system_other is a logical partition.
-    // Note that system_other is still a physical partition on "retrofit" devices.
-    if (android::base::GetBoolProperty("ro.boot.dynamic_partitions", false) &&
-        !android::base::GetBoolProperty("ro.boot.dynamic_partitions_retrofit", false)) {
+    if (android::base::GetBoolProperty("ro.boot.dynamic_partitions", false)) {
         return;
     }
 
diff --git a/fs_mgr/libfstab/fstab.cpp b/fs_mgr/libfstab/fstab.cpp
index ec23ce5cf1..d4067d57ef 100644
--- a/fs_mgr/libfstab/fstab.cpp
+++ b/fs_mgr/libfstab/fstab.cpp
@@ -170,7 +170,21 @@ void ParseUserDevices(const std::string& arg, FstabEntry* entry) {
         entry->fs_mgr_flags.is_zoned = true;
     }
     entry->user_devices.push_back(param[1]);
-    entry->device_aliased.push_back(param[0] == "exp_alias" ? 1 : 0);
+
+    if (param[0] == "exp_alias") {
+        std::string_view exp_alias_prefix = "userdata_exp.";
+        std::string deviceName = android::base::Basename(param[1]);
+        if (!android::base::StartsWith(deviceName, exp_alias_prefix)) {
+            LERROR << "Device aliasing file " << deviceName << " doesn't start with "
+                   << exp_alias_prefix;
+            entry->user_devices.pop_back();
+            return;
+        }
+
+        entry->device_aliased.push_back(1);
+    } else {
+        entry->device_aliased.push_back(0);
+    }
 }
 
 bool ParseFsMgrFlags(const std::string& flags, FstabEntry* entry) {
diff --git a/fs_mgr/liblp/Android.bp b/fs_mgr/liblp/Android.bp
index b211e83dab..24bebb960a 100644
--- a/fs_mgr/liblp/Android.bp
+++ b/fs_mgr/liblp/Android.bp
@@ -88,13 +88,14 @@ cc_defaults {
             static_libs: [
                 "libfs_mgr",
             ],
-        }
+        },
     },
     stl: "libc++_static",
     srcs: [
         "builder_test.cpp",
         "super_layout_builder_test.cpp",
         "utility_test.cpp",
+        "writer_test.cpp",
         ":TestPartitionOpener_group",
     ],
 }
@@ -105,7 +106,7 @@ cc_test {
     test_suites: ["device-tests"],
     auto_gen_config: true,
     require_root: true,
-    host_supported: true
+    host_supported: true,
 }
 
 cc_test {
@@ -125,6 +126,6 @@ cc_test {
 }
 
 filegroup {
-   name: "TestPartitionOpener_group",
-   srcs: [ "test_partition_opener.cpp"],
+    name: "TestPartitionOpener_group",
+    srcs: ["test_partition_opener.cpp"],
 }
diff --git a/fs_mgr/liblp/builder.cpp b/fs_mgr/liblp/builder.cpp
index 4e6e97b675..bac1583e4e 100644
--- a/fs_mgr/liblp/builder.cpp
+++ b/fs_mgr/liblp/builder.cpp
@@ -224,18 +224,6 @@ std::unique_ptr<MetadataBuilder> MetadataBuilder::NewForUpdate(const IPartitionO
         return nullptr;
     }
 
-    // On retrofit DAP devices, modify the metadata so that it is suitable for being written
-    // to the target slot later. We detect retrofit DAP devices by checking the super partition
-    // name and system properties.
-    // See comments for UpdateMetadataForOtherSuper.
-    auto super_device = GetMetadataSuperBlockDevice(*metadata.get());
-    if (android::fs_mgr::GetBlockDevicePartitionName(*super_device) != "super" &&
-        IsRetrofitDynamicPartitionsDevice()) {
-        if (!UpdateMetadataForOtherSuper(metadata.get(), source_slot_number, target_slot_number)) {
-            return nullptr;
-        }
-    }
-
     if (IPropertyFetcher::GetInstance()->GetBoolProperty("ro.virtual_ab.enabled", false)) {
         if (always_keep_source_slot) {
             // always_keep_source_slot implies the target build does not support snapshots.
@@ -254,50 +242,7 @@ std::unique_ptr<MetadataBuilder> MetadataBuilder::NewForUpdate(const IPartitionO
     return New(*metadata.get(), &opener);
 }
 
-// For retrofit DAP devices, there are (conceptually) two super partitions. We'll need to translate
-// block device and group names to update their slot suffixes.
-// (On the other hand, On non-retrofit DAP devices there is only one location for metadata: the
-// super partition. update_engine will remove and resize partitions as needed.)
-bool MetadataBuilder::UpdateMetadataForOtherSuper(LpMetadata* metadata, uint32_t source_slot_number,
-                                                  uint32_t target_slot_number) {
-    // Clear partitions and extents, since they have no meaning on the target
-    // slot. We also clear groups since they are re-added during OTA.
-    metadata->partitions.clear();
-    metadata->extents.clear();
-    metadata->groups.clear();
-
-    std::string source_slot_suffix = SlotSuffixForSlotNumber(source_slot_number);
-    std::string target_slot_suffix = SlotSuffixForSlotNumber(target_slot_number);
-
-    // Translate block devices.
-    auto source_block_devices = std::move(metadata->block_devices);
-    for (const auto& source_block_device : source_block_devices) {
-        std::string partition_name =
-                android::fs_mgr::GetBlockDevicePartitionName(source_block_device);
-        std::string slot_suffix = GetPartitionSlotSuffix(partition_name);
-        if (slot_suffix.empty() || slot_suffix != source_slot_suffix) {
-            // This should never happen. It means that the source metadata
-            // refers to a target or unknown block device.
-            LERROR << "Invalid block device for slot " << source_slot_suffix << ": "
-                   << partition_name;
-            return false;
-        }
-        std::string new_name =
-                partition_name.substr(0, partition_name.size() - slot_suffix.size()) +
-                target_slot_suffix;
-
-        auto new_device = source_block_device;
-        if (!UpdateBlockDevicePartitionName(&new_device, new_name)) {
-            LERROR << "Partition name too long: " << new_name;
-            return false;
-        }
-        metadata->block_devices.emplace_back(new_device);
-    }
-
-    return true;
-}
-
-MetadataBuilder::MetadataBuilder() : auto_slot_suffixing_(false) {
+MetadataBuilder::MetadataBuilder() {
     memset(&geometry_, 0, sizeof(geometry_));
     geometry_.magic = LP_METADATA_GEOMETRY_MAGIC;
     geometry_.struct_size = sizeof(geometry_);
@@ -789,9 +734,7 @@ std::vector<Interval> MetadataBuilder::PrioritizeSecondHalfOfSuper(
     std::vector<Interval> first_half;
     std::vector<Interval> second_half;
     for (const auto& region : free_list) {
-        // Note: deprioritze if not the main super partition. Even though we
-        // don't call this for retrofit devices, we will allow adding additional
-        // block devices on non-retrofit devices.
+        // Note: deprioritze if not the main super partition.
         if (region.device_index != 0 || region.end <= midpoint) {
             first_half.emplace_back(region);
             continue;
@@ -884,9 +827,6 @@ std::unique_ptr<LpMetadata> MetadataBuilder::Export() {
     // Assign this early so the extent table can read it.
     for (const auto& block_device : block_devices_) {
         metadata->block_devices.emplace_back(block_device);
-        if (auto_slot_suffixing_) {
-            metadata->block_devices.back().flags |= LP_BLOCK_DEVICE_SLOT_SUFFIXED;
-        }
     }
 
     std::map<std::string, size_t> group_indices;
@@ -897,9 +837,6 @@ std::unique_ptr<LpMetadata> MetadataBuilder::Export() {
             LERROR << "Partition group name is too long: " << group->name();
             return nullptr;
         }
-        if (auto_slot_suffixing_ && group->name() != kDefaultGroup) {
-            out.flags |= LP_GROUP_SLOT_SUFFIXED;
-        }
         strncpy(out.name, group->name().c_str(), sizeof(out.name));
         out.maximum_size = group->maximum_size();
 
@@ -931,9 +868,6 @@ std::unique_ptr<LpMetadata> MetadataBuilder::Export() {
         part.first_extent_index = static_cast<uint32_t>(metadata->extents.size());
         part.num_extents = static_cast<uint32_t>(partition->extents().size());
         part.attributes = partition->attributes();
-        if (auto_slot_suffixing_) {
-            part.attributes |= LP_PARTITION_ATTR_SLOT_SUFFIXED;
-        }
 
         auto iter = group_indices.find(partition->group_name());
         if (iter == group_indices.end()) {
@@ -1202,10 +1136,6 @@ bool MetadataBuilder::ImportPartition(const LpMetadata& metadata,
     return true;
 }
 
-void MetadataBuilder::SetAutoSlotSuffixing() {
-    auto_slot_suffixing_ = true;
-}
-
 void MetadataBuilder::SetVirtualABDeviceFlag() {
     RequireExpandedMetadataHeader();
     header_.flags |= LP_HEADER_FLAG_VIRTUAL_AB_DEVICE;
@@ -1224,11 +1154,6 @@ bool MetadataBuilder::IsABDevice() {
     return !IPropertyFetcher::GetInstance()->GetProperty("ro.boot.slot_suffix", "").empty();
 }
 
-bool MetadataBuilder::IsRetrofitDynamicPartitionsDevice() {
-    return IPropertyFetcher::GetInstance()->GetBoolProperty("ro.boot.dynamic_partitions_retrofit",
-                                                            false);
-}
-
 bool MetadataBuilder::ShouldHalveSuper() const {
     return GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME &&
            !IPropertyFetcher::GetInstance()->GetBoolProperty("ro.virtual_ab.enabled", false);
diff --git a/fs_mgr/liblp/device_test.cpp b/fs_mgr/liblp/device_test.cpp
index 236fd8dd3b..2fec5ec675 100644
--- a/fs_mgr/liblp/device_test.cpp
+++ b/fs_mgr/liblp/device_test.cpp
@@ -56,24 +56,7 @@ TEST_F(DeviceTest, BlockDeviceInfo) {
 TEST_F(DeviceTest, ReadSuperPartitionCurrentSlot) {
     auto slot_suffix = fs_mgr_get_slot_suffix();
     auto slot_number = SlotNumberForSlotSuffix(slot_suffix);
-    auto super_name = fs_mgr_get_super_partition_name(slot_number);
+    auto super_name = fs_mgr_get_super_partition_name();
     auto metadata = ReadMetadata(super_name, slot_number);
     EXPECT_NE(metadata, nullptr);
 }
-
-TEST_F(DeviceTest, ReadSuperPartitionOtherSlot) {
-    auto other_slot_suffix = fs_mgr_get_other_slot_suffix();
-    if (other_slot_suffix.empty()) {
-        GTEST_SKIP() << "No other slot, skipping";
-    }
-    if (IPropertyFetcher::GetInstance()->GetBoolProperty("ro.boot.dynamic_partitions_retrofit",
-                                                         false)) {
-        GTEST_SKIP() << "Device with retrofit dynamic partition may not have metadata at other "
-                     << "slot, skipping";
-    }
-
-    auto other_slot_number = SlotNumberForSlotSuffix(other_slot_suffix);
-    auto other_super_name = fs_mgr_get_super_partition_name(other_slot_number);
-    auto other_metadata = ReadMetadata(other_super_name, other_slot_number);
-    EXPECT_NE(other_metadata, nullptr);
-}
diff --git a/fs_mgr/liblp/fuzzer/liblp_builder_fuzzer.cpp b/fs_mgr/liblp/fuzzer/liblp_builder_fuzzer.cpp
index 2e5933280b..d7878f9947 100644
--- a/fs_mgr/liblp/fuzzer/liblp_builder_fuzzer.cpp
+++ b/fs_mgr/liblp/fuzzer/liblp_builder_fuzzer.cpp
@@ -337,7 +337,6 @@ void BuilderFuzzer::invokeBuilderAPIs() {
                     },
                     [&]() { mBuilder->HasBlockDevice(mFdp.PickValueInArray(mPartitionNames)); },
                     [&]() { mBuilder->SetVirtualABDeviceFlag(); },
-                    [&]() { mBuilder->SetAutoSlotSuffixing(); },
                     [&]() { mBuilder->ListGroups(); },
                     [&]() { mBuilder->UsedSpace(); },
                     [&]() { mBuilder->RequireExpandedMetadataHeader(); },
diff --git a/fs_mgr/liblp/images.cpp b/fs_mgr/liblp/images.cpp
index a2dbb1052c..6476d22aff 100644
--- a/fs_mgr/liblp/images.cpp
+++ b/fs_mgr/liblp/images.cpp
@@ -112,7 +112,10 @@ std::unique_ptr<LpMetadata> ReadFromImageFile(const std::string& image_file) {
 
 bool WriteToImageFile(borrowed_fd fd, const LpMetadata& input) {
     std::string geometry = SerializeGeometry(input.geometry);
-    std::string metadata = SerializeMetadata(input);
+    std::string metadata = ValidateAndSerializeMetadata(input);
+    if (metadata.empty()) {
+        return false;
+    }
 
     std::string everything = geometry + metadata;
 
@@ -223,7 +226,7 @@ bool ImageBuilder::Export(const std::string& file) {
         return false;
     }
     if (device_images_.size() > 1) {
-        LERROR << "Cannot export to a single image on retrofit builds.";
+        LERROR << "Cannot export to a single image on multi-super configurations.";
         return false;
     }
     // No gzip compression; no checksum.
@@ -298,7 +301,10 @@ bool ImageBuilder::Build() {
     }
 
     std::string geometry_blob = SerializeGeometry(geometry_);
-    std::string metadata_blob = SerializeMetadata(metadata_);
+    std::string metadata_blob = ValidateAndSerializeMetadata(metadata_);
+    if (metadata_blob.empty()) {
+        return false;
+    }
     metadata_blob.resize(geometry_.metadata_max_size);
 
     // Two copies of geometry, then two copies of each metadata slot.
diff --git a/fs_mgr/liblp/include/liblp/builder.h b/fs_mgr/liblp/include/liblp/builder.h
index 957b96b09c..d99e99a604 100644
--- a/fs_mgr/liblp/include/liblp/builder.h
+++ b/fs_mgr/liblp/include/liblp/builder.h
@@ -221,10 +221,8 @@ class MetadataBuilder {
 
     // This is when performing an A/B update. The source partition must be a
     // super partition. On a normal device, the metadata for the source slot
-    // is imported and the target slot is ignored. On a retrofit device, the
-    // metadata may not have the target slot's devices listed yet, in which
-    // case, it is automatically upgraded to include all available block
-    // devices.
+    // is imported and the target slot is ignored.
+    //
     // If |always_keep_source_slot| is set, on a Virtual A/B device
     // - source slot partitions are kept.
     // - UPDATED flag is cleared.
@@ -342,8 +340,6 @@ class MetadataBuilder {
     // Remove all partitions belonging to a group, then remove the group.
     void RemoveGroupAndPartitions(std::string_view group_name);
 
-    // Set the LP_METADATA_AUTO_SLOT_SUFFIXING flag.
-    void SetAutoSlotSuffixing();
     // Set the LP_HEADER_FLAG_VIRTUAL_AB_DEVICE flag.
     void SetVirtualABDeviceFlag();
     // Set or unset the LP_HEADER_FLAG_OVERLAYS_ACTIVE flag.
@@ -397,9 +393,6 @@ class MetadataBuilder {
     // Return true if the device is an AB device.
     static bool IsABDevice();
 
-    // Return true if the device is retrofitting dynamic partitions.
-    static bool IsRetrofitDynamicPartitionsDevice();
-
     // Return true if _b partitions should be prioritized at the second half of the device.
     bool ShouldHalveSuper() const;
 
@@ -423,7 +416,6 @@ class MetadataBuilder {
     std::vector<std::unique_ptr<Partition>> partitions_;
     std::vector<std::unique_ptr<PartitionGroup>> groups_;
     std::vector<LpMetadataBlockDevice> block_devices_;
-    bool auto_slot_suffixing_;
 };
 
 // Read BlockDeviceInfo for a given block device. This always returns false
diff --git a/fs_mgr/liblp/include/liblp/metadata_format.h b/fs_mgr/liblp/include/liblp/metadata_format.h
index 8d77097ed6..9d7eb699ff 100644
--- a/fs_mgr/liblp/include/liblp/metadata_format.h
+++ b/fs_mgr/liblp/include/liblp/metadata_format.h
@@ -56,12 +56,9 @@ extern "C" {
 #define LP_PARTITION_ATTR_NONE 0x0
 #define LP_PARTITION_ATTR_READONLY (1 << 0)
 
-/* This flag is only intended to be used with super_empty.img and super.img on
- * retrofit devices. On these devices there are A and B super partitions, and
- * we don't know ahead of time which slot the image will be applied to.
+/* This flag is historical and is no longer supported.
  *
- * If set, the partition name needs a slot suffix applied. The slot suffix is
- * determined by the metadata slot number (0 = _a, 1 = _b).
+ * If set, the partition name needs a slot suffix applied.
  */
 #define LP_PARTITION_ATTR_SLOT_SUFFIXED (1 << 1)
 
@@ -319,9 +316,9 @@ typedef struct LpMetadataPartitionGroup {
     uint64_t maximum_size;
 } __attribute__((packed)) LpMetadataPartitionGroup;
 
-/* This flag is only intended to be used with super_empty.img and super.img on
- * retrofit devices. If set, the group needs a slot suffix to be interpreted
- * correctly. The suffix is automatically applied by ReadMetadata().
+/* This flag is historical and is no longer supported.
+ *
+ * If set, the group needs a slot suffix to be interpreted correctly.
  */
 #define LP_GROUP_SLOT_SUFFIXED (1 << 0)
 
@@ -370,13 +367,10 @@ typedef struct LpMetadataBlockDevice {
     uint32_t flags;
 } __attribute__((packed)) LpMetadataBlockDevice;
 
-/* This flag is only intended to be used with super_empty.img and super.img on
- * retrofit devices. On these devices there are A and B super partitions, and
- * we don't know ahead of time which slot the image will be applied to.
+/* This flag is historical and is no longer supported.
  *
- * If set, the block device needs a slot suffix applied before being used with
- * IPartitionOpener. The slot suffix is determined by the metadata slot number
- * (0 = _a, 1 = _b).
+ * If set, the block device needs a slot suffix to be interpreted
+ * correctly.
  */
 #define LP_BLOCK_DEVICE_SLOT_SUFFIXED (1 << 0)
 
diff --git a/fs_mgr/liblp/include/liblp/property_fetcher.h b/fs_mgr/liblp/include/liblp/property_fetcher.h
index e73a1f5621..54ee07cbe3 100644
--- a/fs_mgr/liblp/include/liblp/property_fetcher.h
+++ b/fs_mgr/liblp/include/liblp/property_fetcher.h
@@ -28,7 +28,7 @@ class IPropertyFetcher {
     virtual bool GetBoolProperty(const std::string& key, bool defaultValue) = 0;
 
     static IPropertyFetcher* GetInstance();
-    static void OverrideForTesting(std::unique_ptr<IPropertyFetcher>&&);
+    static void OverrideForTesting(std::shared_ptr<IPropertyFetcher>&&);
 };
 
 class PropertyFetcher : public IPropertyFetcher {
diff --git a/fs_mgr/liblp/io_test.cpp b/fs_mgr/liblp/io_test.cpp
index d1233047c0..d137bf69b3 100644
--- a/fs_mgr/liblp/io_test.cpp
+++ b/fs_mgr/liblp/io_test.cpp
@@ -627,85 +627,7 @@ TEST_F(LiblpTest, FlashSparseImage) {
     ASSERT_NE(ReadBackupMetadata(fd.get(), geometry, 0), nullptr);
 }
 
-TEST_F(LiblpTest, AutoSlotSuffixing) {
-    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
-    ASSERT_NE(builder, nullptr);
-    ASSERT_TRUE(AddDefaultPartitions(builder.get()));
-    ASSERT_TRUE(builder->AddGroup("example", 0));
-    builder->SetAutoSlotSuffixing();
-
-    auto fd = CreateFakeDisk();
-    ASSERT_GE(fd, 0);
-
-    // Note: we bind the same fd to both names, since we want to make sure the
-    // exact same bits are getting read back in each test.
-    TestPartitionOpener opener({{"super_a", fd}, {"super_b", fd}},
-                               {{"super_a", kSuperInfo}, {"super_b", kSuperInfo}});
-    auto exported = builder->Export();
-    ASSERT_NE(exported, nullptr);
-    ASSERT_TRUE(FlashPartitionTable(opener, "super_a", *exported.get()));
-
-    auto metadata = ReadMetadata(opener, "super_b", 1);
-    ASSERT_NE(metadata, nullptr);
-    ASSERT_EQ(metadata->partitions.size(), static_cast<size_t>(1));
-    EXPECT_EQ(GetPartitionName(metadata->partitions[0]), "system_b");
-    ASSERT_EQ(metadata->block_devices.size(), static_cast<size_t>(1));
-    EXPECT_EQ(GetBlockDevicePartitionName(metadata->block_devices[0]), "super_b");
-    ASSERT_EQ(metadata->groups.size(), static_cast<size_t>(2));
-    EXPECT_EQ(GetPartitionGroupName(metadata->groups[0]), "default");
-    EXPECT_EQ(GetPartitionGroupName(metadata->groups[1]), "example_b");
-    EXPECT_EQ(metadata->groups[0].flags, 0);
-    EXPECT_EQ(metadata->groups[1].flags, 0);
-
-    metadata = ReadMetadata(opener, "super_a", 0);
-    ASSERT_NE(metadata, nullptr);
-    ASSERT_EQ(metadata->partitions.size(), static_cast<size_t>(1));
-    EXPECT_EQ(GetPartitionName(metadata->partitions[0]), "system_a");
-    ASSERT_EQ(metadata->block_devices.size(), static_cast<size_t>(1));
-    EXPECT_EQ(GetBlockDevicePartitionName(metadata->block_devices[0]), "super_a");
-    ASSERT_EQ(metadata->groups.size(), static_cast<size_t>(2));
-    EXPECT_EQ(GetPartitionGroupName(metadata->groups[0]), "default");
-    EXPECT_EQ(GetPartitionGroupName(metadata->groups[1]), "example_a");
-    EXPECT_EQ(metadata->groups[0].flags, 0);
-    EXPECT_EQ(metadata->groups[1].flags, 0);
-}
-
-TEST_F(LiblpTest, UpdateRetrofit) {
-    ON_CALL(*GetMockedPropertyFetcher(), GetBoolProperty("ro.boot.dynamic_partitions_retrofit", _))
-            .WillByDefault(Return(true));
-
-    unique_ptr<MetadataBuilder> builder = CreateDefaultBuilder();
-    ASSERT_NE(builder, nullptr);
-    ASSERT_TRUE(AddDefaultPartitions(builder.get()));
-    ASSERT_TRUE(builder->AddGroup("example", 0));
-    builder->SetAutoSlotSuffixing();
-
-    auto fd = CreateFakeDisk();
-    ASSERT_GE(fd, 0);
-
-    // Note: we bind the same fd to both names, since we want to make sure the
-    // exact same bits are getting read back in each test.
-    TestPartitionOpener opener({{"super_a", fd}, {"super_b", fd}},
-                               {{"super_a", kSuperInfo}, {"super_b", kSuperInfo}});
-    auto exported = builder->Export();
-    ASSERT_NE(exported, nullptr);
-    ASSERT_TRUE(FlashPartitionTable(opener, "super_a", *exported.get()));
-
-    builder = MetadataBuilder::NewForUpdate(opener, "super_a", 0, 1);
-    ASSERT_NE(builder, nullptr);
-    auto updated = builder->Export();
-    ASSERT_NE(updated, nullptr);
-    ASSERT_EQ(updated->block_devices.size(), static_cast<size_t>(1));
-    EXPECT_EQ(GetBlockDevicePartitionName(updated->block_devices[0]), "super_b");
-    ASSERT_TRUE(updated->groups.empty());
-    ASSERT_TRUE(updated->partitions.empty());
-    ASSERT_TRUE(updated->extents.empty());
-}
-
-TEST_F(LiblpTest, UpdateNonRetrofit) {
-    ON_CALL(*GetMockedPropertyFetcher(), GetBoolProperty("ro.boot.dynamic_partitions_retrofit", _))
-            .WillByDefault(Return(false));
-
+TEST_F(LiblpTest, UpdateLaunchDap) {
     unique_fd fd = CreateFlashedDisk();
     ASSERT_GE(fd, 0);
 
diff --git a/fs_mgr/liblp/partition_opener.cpp b/fs_mgr/liblp/partition_opener.cpp
index 4696ff173b..469cbade5a 100644
--- a/fs_mgr/liblp/partition_opener.cpp
+++ b/fs_mgr/liblp/partition_opener.cpp
@@ -22,9 +22,12 @@
 #if !defined(_WIN32)
 #include <sys/ioctl.h>
 #endif
+#include <sys/file.h>
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <cerrno>
+
 #include <android-base/file.h>
 #include <android-base/strings.h>
 
@@ -110,7 +113,21 @@ bool GetBlockDeviceInfo(const std::string& block_device, BlockDeviceInfo* device
 
 unique_fd PartitionOpener::Open(const std::string& partition_name, int flags) const {
     std::string path = GetPartitionAbsolutePath(partition_name);
-    return GetControlFileOrOpen(path.c_str(), flags | O_CLOEXEC);
+    unique_fd fd = GetControlFileOrOpen(path.c_str(), flags | O_CLOEXEC);
+    if (fd < 0) {
+        return {};
+    }
+
+#if !defined(_WIN32)
+    // Acquire a lock.
+    int lock_flags = ((flags & O_RDWR) || (flags & O_WRONLY)) ? LOCK_EX : LOCK_SH;
+    if (TEMP_FAILURE_RETRY(flock(fd.get(), lock_flags)) == -1) {
+        PERROR << __PRETTY_FUNCTION__ << " flock failed on " << path;
+        return {};
+    }
+#endif
+
+    return fd;
 }
 
 bool PartitionOpener::GetInfo(const std::string& partition_name, BlockDeviceInfo* info) const {
diff --git a/fs_mgr/liblp/property_fetcher.cpp b/fs_mgr/liblp/property_fetcher.cpp
index 038ef4dc4e..76bbe285ee 100644
--- a/fs_mgr/liblp/property_fetcher.cpp
+++ b/fs_mgr/liblp/property_fetcher.cpp
@@ -31,8 +31,8 @@ bool PropertyFetcher::GetBoolProperty(const std::string& key, bool default_value
     return android::base::GetBoolProperty(key, default_value);
 }
 
-static std::unique_ptr<IPropertyFetcher>* GetInstanceAllocation() {
-    static std::unique_ptr<IPropertyFetcher> instance = std::make_unique<PropertyFetcher>();
+static std::shared_ptr<IPropertyFetcher>* GetInstanceAllocation() {
+    static std::shared_ptr<IPropertyFetcher> instance = std::make_shared<PropertyFetcher>();
     return &instance;
 }
 
@@ -40,7 +40,7 @@ IPropertyFetcher* IPropertyFetcher::GetInstance() {
     return GetInstanceAllocation()->get();
 }
 
-void IPropertyFetcher::OverrideForTesting(std::unique_ptr<IPropertyFetcher>&& fetcher) {
+void IPropertyFetcher::OverrideForTesting(std::shared_ptr<IPropertyFetcher>&& fetcher) {
     GetInstanceAllocation()->swap(fetcher);
     fetcher.reset();
 }
diff --git a/fs_mgr/liblp/reader.cpp b/fs_mgr/liblp/reader.cpp
index 24ccc0f9de..9264f247a1 100644
--- a/fs_mgr/liblp/reader.cpp
+++ b/fs_mgr/liblp/reader.cpp
@@ -393,49 +393,6 @@ std::unique_ptr<LpMetadata> ReadBackupMetadata(int fd, const LpMetadataGeometry&
     return ParseMetadata(geometry, fd);
 }
 
-namespace {
-
-bool AdjustMetadataForSlot(LpMetadata* metadata, uint32_t slot_number) {
-    std::string slot_suffix = SlotSuffixForSlotNumber(slot_number);
-    for (auto& partition : metadata->partitions) {
-        if (!(partition.attributes & LP_PARTITION_ATTR_SLOT_SUFFIXED)) {
-            continue;
-        }
-        std::string partition_name = GetPartitionName(partition) + slot_suffix;
-        if (partition_name.size() > sizeof(partition.name)) {
-            LERROR << __PRETTY_FUNCTION__ << " partition name too long: " << partition_name;
-            return false;
-        }
-        strncpy(partition.name, partition_name.c_str(), sizeof(partition.name));
-        partition.attributes &= ~LP_PARTITION_ATTR_SLOT_SUFFIXED;
-    }
-    for (auto& block_device : metadata->block_devices) {
-        if (!(block_device.flags & LP_BLOCK_DEVICE_SLOT_SUFFIXED)) {
-            continue;
-        }
-        std::string partition_name = GetBlockDevicePartitionName(block_device) + slot_suffix;
-        if (!UpdateBlockDevicePartitionName(&block_device, partition_name)) {
-            LERROR << __PRETTY_FUNCTION__ << " partition name too long: " << partition_name;
-            return false;
-        }
-        block_device.flags &= ~LP_BLOCK_DEVICE_SLOT_SUFFIXED;
-    }
-    for (auto& group : metadata->groups) {
-        if (!(group.flags & LP_GROUP_SLOT_SUFFIXED)) {
-            continue;
-        }
-        std::string group_name = GetPartitionGroupName(group) + slot_suffix;
-        if (!UpdatePartitionGroupName(&group, group_name)) {
-            LERROR << __PRETTY_FUNCTION__ << " group name too long: " << group_name;
-            return false;
-        }
-        group.flags &= ~LP_GROUP_SLOT_SUFFIXED;
-    }
-    return true;
-}
-
-}  // namespace
-
 std::unique_ptr<LpMetadata> ReadMetadata(const IPartitionOpener& opener,
                                          const std::string& super_partition, uint32_t slot_number) {
     android::base::unique_fd fd = opener.Open(super_partition, O_RDONLY);
@@ -468,9 +425,6 @@ std::unique_ptr<LpMetadata> ReadMetadata(const IPartitionOpener& opener,
             break;
         }
     }
-    if (!metadata || !AdjustMetadataForSlot(metadata.get(), slot_number)) {
-        return nullptr;
-    }
     return metadata;
 }
 
diff --git a/fs_mgr/liblp/super_layout_builder.cpp b/fs_mgr/liblp/super_layout_builder.cpp
index bff26ea21d..d0bc535a1e 100644
--- a/fs_mgr/liblp/super_layout_builder.cpp
+++ b/fs_mgr/liblp/super_layout_builder.cpp
@@ -129,7 +129,10 @@ std::vector<SuperImageExtent> SuperLayoutBuilder::GetImageLayout() {
 
     // Write the primary and backup copies of each metadata slot. When flashing,
     // all metadata copies are the same, even for different slots.
-    std::string metadata_bytes = SerializeMetadata(*metadata.get());
+    std::string metadata_bytes = ValidateAndSerializeMetadata(*metadata.get());
+    if (metadata_bytes.empty()) {
+        return {};
+    }
 
     // Align metadata size to 4KB. This makes the layout easily compatible with
     // libsparse.
diff --git a/fs_mgr/liblp/super_layout_builder_test.cpp b/fs_mgr/liblp/super_layout_builder_test.cpp
index 714b6b439e..3e1b4743ae 100644
--- a/fs_mgr/liblp/super_layout_builder_test.cpp
+++ b/fs_mgr/liblp/super_layout_builder_test.cpp
@@ -46,7 +46,9 @@ TEST(SuperImageTool, Layout) {
     ASSERT_NE(metadata, nullptr);
 
     auto geometry_blob = std::make_shared<std::string>(SerializeGeometry(metadata->geometry));
-    auto metadata_blob = std::make_shared<std::string>(SerializeMetadata(*metadata.get()));
+    auto metadata_blob =
+            std::make_shared<std::string>(ValidateAndSerializeMetadata(*metadata.get()));
+    ASSERT_FALSE(metadata_blob->empty());
     metadata_blob->resize(4_KiB, '\0');
 
     auto extents = tool.GetImageLayout();
@@ -96,21 +98,6 @@ TEST(SuperImageTool, NoRetrofit) {
     ASSERT_FALSE(tool.Open(*metadata.get()));
 }
 
-TEST(SuperImageTool, NoRetrofit2) {
-    auto builder = MetadataBuilder::New(4_MiB, 8_KiB, 2);
-    ASSERT_NE(builder, nullptr);
-
-    Partition* p = builder->AddPartition(
-            "system_a", LP_PARTITION_ATTR_READONLY | LP_PARTITION_ATTR_SLOT_SUFFIXED);
-    ASSERT_NE(p, nullptr);
-
-    auto metadata = builder->Export();
-    ASSERT_NE(metadata, nullptr);
-
-    SuperLayoutBuilder tool;
-    ASSERT_FALSE(tool.Open(*metadata.get()));
-}
-
 TEST(SuperImageTool, NoFixedPartitions) {
     auto builder = MetadataBuilder::New(4_MiB, 8_KiB, 2);
     ASSERT_NE(builder, nullptr);
diff --git a/fs_mgr/liblp/writer.cpp b/fs_mgr/liblp/writer.cpp
index 2708efa156..00afdb51c2 100644
--- a/fs_mgr/liblp/writer.cpp
+++ b/fs_mgr/liblp/writer.cpp
@@ -47,7 +47,8 @@ static bool CompareGeometry(const LpMetadataGeometry& g1, const LpMetadataGeomet
            g1.logical_block_size == g2.logical_block_size;
 }
 
-std::string SerializeMetadata(const LpMetadata& input) {
+// Unvalidated serialization.
+static std::string SerializeMetadata(const LpMetadata& input) {
     LpMetadata metadata = input;
     LpMetadataHeader& header = metadata.header;
 
@@ -81,26 +82,35 @@ std::string SerializeMetadata(const LpMetadata& input) {
     return header_blob + tables;
 }
 
-// Perform checks so we don't accidentally overwrite valid metadata with
-// potentially invalid metadata, or random partition data with metadata.
-static bool ValidateAndSerializeMetadata([[maybe_unused]] const IPartitionOpener& opener,
-                                         const LpMetadata& metadata, const std::string& slot_suffix,
-                                         std::string* blob) {
+// Validated serialization.
+std::string ValidateAndSerializeMetadata(const LpMetadata& metadata) {
     const LpMetadataGeometry& geometry = metadata.geometry;
 
-    *blob = SerializeMetadata(metadata);
+    std::string blob = SerializeMetadata(metadata);
 
     // Make sure we're writing within the space reserved.
-    if (blob->size() > geometry.metadata_max_size) {
-        LERROR << "Logical partition metadata is too large. " << blob->size() << " > "
+    if (blob.size() > geometry.metadata_max_size) {
+        LERROR << "Logical partition metadata is too large. " << blob.size() << " > "
                << geometry.metadata_max_size;
+        return {};
+    }
+    return blob;
+}
+
+// Perform checks so we don't accidentally overwrite valid metadata with
+// potentially invalid metadata, or random partition data with metadata.
+static bool ValidateAndSerializeMetadata([[maybe_unused]] const IPartitionOpener& opener,
+                                         const LpMetadata& metadata, std::string* blob) {
+    *blob = ValidateAndSerializeMetadata(metadata);
+    if (blob->empty()) {
         return false;
     }
 
     // Make sure the device has enough space to store two backup copies of the
     // metadata.
-    uint64_t reserved_size = LP_METADATA_GEOMETRY_SIZE +
-                             uint64_t(geometry.metadata_max_size) * geometry.metadata_slot_count;
+    uint64_t reserved_size =
+            LP_METADATA_GEOMETRY_SIZE +
+            uint64_t(metadata.geometry.metadata_max_size) * metadata.geometry.metadata_slot_count;
     uint64_t total_reserved = LP_PARTITION_RESERVED_BYTES + reserved_size * 2;
 
     const LpMetadataBlockDevice* super_device = GetMetadataSuperBlockDevice(metadata);
@@ -116,12 +126,8 @@ static bool ValidateAndSerializeMetadata([[maybe_unused]] const IPartitionOpener
     for (const auto& block_device : metadata.block_devices) {
         std::string partition_name = GetBlockDevicePartitionName(block_device);
         if (block_device.flags & LP_BLOCK_DEVICE_SLOT_SUFFIXED) {
-            if (slot_suffix.empty()) {
-                LERROR << "Block device " << partition_name << " requires a slot suffix,"
-                       << " which could not be derived from the super partition name.";
-                return false;
-            }
-            partition_name += slot_suffix;
+            LERROR << "Slot-suffixed super is no longer supported.";
+            return false;
         }
 
         if ((block_device.first_logical_sector + 1) * LP_SECTOR_SIZE > block_device.size) {
@@ -253,21 +259,15 @@ bool FlashPartitionTable(const IPartitionOpener& opener, const std::string& supe
         return false;
     }
 
-    // This is only used in update_engine and fastbootd, where the super
-    // partition should be specified as a name (or by-name link), and
-    // therefore, we should be able to extract a slot suffix.
-    std::string slot_suffix = GetPartitionSlotSuffix(super_partition);
-
     // Before writing geometry and/or logical partition tables, perform some
     // basic checks that the geometry and tables are coherent, and will fit
     // on the given block device.
     std::string metadata_blob;
-    if (!ValidateAndSerializeMetadata(opener, metadata, slot_suffix, &metadata_blob)) {
+    if (!ValidateAndSerializeMetadata(opener, metadata, &metadata_blob)) {
         return false;
     }
 
-    // On retrofit devices, super_partition is system_other and might be set to readonly by
-    // fs_mgr_set_blk_ro(). Unset readonly so that fd can be written to.
+    // Make sure the block device is writable.
     if (!SetBlockReadonly(fd.get(), false)) {
         PWARNING << __PRETTY_FUNCTION__ << " BLKROSET 0 failed: " << super_partition;
     }
@@ -329,13 +329,11 @@ bool UpdatePartitionTable(const IPartitionOpener& opener, const std::string& sup
         return false;
     }
 
-    std::string slot_suffix = SlotSuffixForSlotNumber(slot_number);
-
     // Before writing geometry and/or logical partition tables, perform some
     // basic checks that the geometry and tables are coherent, and will fit
     // on the given block device.
     std::string blob;
-    if (!ValidateAndSerializeMetadata(opener, metadata, slot_suffix, &blob)) {
+    if (!ValidateAndSerializeMetadata(opener, metadata, &blob)) {
         return false;
     }
 
@@ -367,7 +365,7 @@ bool UpdatePartitionTable(const IPartitionOpener& opener, const std::string& sup
         // synchronize the backup copy. This guarantees that a partial write
         // still leaves one copy intact.
         std::string old_blob;
-        if (!ValidateAndSerializeMetadata(opener, *primary.get(), slot_suffix, &old_blob)) {
+        if (!ValidateAndSerializeMetadata(opener, *primary.get(), &old_blob)) {
             LERROR << "Error serializing primary metadata to repair corrupted backup";
             return false;
         }
@@ -379,7 +377,7 @@ bool UpdatePartitionTable(const IPartitionOpener& opener, const std::string& sup
         // The backup copy is coherent, and the primary is not. Sync it for
         // safety.
         std::string old_blob;
-        if (!ValidateAndSerializeMetadata(opener, *backup.get(), slot_suffix, &old_blob)) {
+        if (!ValidateAndSerializeMetadata(opener, *backup.get(), &old_blob)) {
             LERROR << "Error serializing backup metadata to repair corrupted primary";
             return false;
         }
diff --git a/fs_mgr/liblp/writer.h b/fs_mgr/liblp/writer.h
index 6f1da0f209..3641fbab7c 100644
--- a/fs_mgr/liblp/writer.h
+++ b/fs_mgr/liblp/writer.h
@@ -25,8 +25,8 @@
 namespace android {
 namespace fs_mgr {
 
+std::string ValidateAndSerializeMetadata(const LpMetadata& metadata);
 std::string SerializeGeometry(const LpMetadataGeometry& input);
-std::string SerializeMetadata(const LpMetadata& input);
 
 // These variants are for testing only. The path-based functions should be used
 // for actual operation, so that open() is called with the correct flags.
diff --git a/fs_mgr/liblp/writer_test.cpp b/fs_mgr/liblp/writer_test.cpp
new file mode 100644
index 0000000000..448a88847a
--- /dev/null
+++ b/fs_mgr/liblp/writer_test.cpp
@@ -0,0 +1,45 @@
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
+#include <android-base/file.h>
+#include <gtest/gtest.h>
+#include <liblp/builder.h>
+#include <liblp/liblp.h>
+#include <storage_literals/storage_literals.h>
+
+using android::fs_mgr::LpMetadata;
+using android::fs_mgr::MetadataBuilder;
+using namespace android::storage_literals;
+
+TEST(Writer, WriteValidation) {
+    auto builder = MetadataBuilder::New(2_GiB, 16_KiB, 2);
+    ASSERT_NE(builder, nullptr);
+
+    auto p = builder->AddPartition("system", LP_PARTITION_ATTR_NONE);
+    ASSERT_NE(p, nullptr);
+
+    // Add too many extents.
+    for (size_t i = 0; i < 32000; i += 2) {
+        ASSERT_TRUE(builder->AddLinearExtent(p, "super", 1, i));
+    }
+
+    auto exported = builder->Export();
+    ASSERT_NE(exported, nullptr);
+
+    TemporaryFile temp;
+    ASSERT_GE(temp.fd, 0);
+    ASSERT_FALSE(WriteToImageFile(temp.fd, *exported.get()));
+}
diff --git a/fs_mgr/libsnapshot/Android.bp b/fs_mgr/libsnapshot/Android.bp
index af1991a7fc..9f43bebabb 100644
--- a/fs_mgr/libsnapshot/Android.bp
+++ b/fs_mgr/libsnapshot/Android.bp
@@ -393,7 +393,6 @@ cc_binary {
         "liblp",
         "libprotobuf-cpp-lite",
         "libsnapshot",
-        "libstatslog",
         "libutils",
     ],
     header_libs: [
diff --git a/fs_mgr/libsnapshot/android/snapshot/snapshot.proto b/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
index 94d8e9fc44..155b7e97ed 100644
--- a/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
+++ b/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
@@ -181,6 +181,7 @@ enum MergeFailureCode {
     MemAlignConsistencyCheck = 18;
     DirectReadConsistencyCheck = 19;
     WrongMergeCountConsistencyCheck = 20;
+    IncorrectMergePhase = 21;
 };
 
 message SnapshotUpdateStatus {
diff --git a/fs_mgr/libsnapshot/device_info.cpp b/fs_mgr/libsnapshot/device_info.cpp
index 19f3e0293a..2b9a58e28c 100644
--- a/fs_mgr/libsnapshot/device_info.cpp
+++ b/fs_mgr/libsnapshot/device_info.cpp
@@ -70,8 +70,8 @@ const android::fs_mgr::IPartitionOpener& DeviceInfo::GetPartitionOpener() const
     return opener_;
 }
 
-std::string DeviceInfo::GetSuperDevice(uint32_t slot) const {
-    return fs_mgr_get_super_partition_name(slot);
+std::string DeviceInfo::GetSuperDevice() const {
+    return fs_mgr_get_super_partition_name();
 }
 
 bool DeviceInfo::IsOverlayfsSetup() const {
@@ -86,10 +86,6 @@ bool DeviceInfo::EnsureBootHal() {
             LOG(ERROR) << "Could not find IBootControl HAL";
             return false;
         }
-        if (hal->GetVersion() < BootControlVersion::BOOTCTL_V1_1) {
-            LOG(ERROR) << "Could not find IBootControl 1.1 HAL";
-            return false;
-        }
         boot_control_ = std::move(hal);
     }
     return true;
diff --git a/fs_mgr/libsnapshot/device_info.h b/fs_mgr/libsnapshot/device_info.h
index e93ec4960d..49ae795c12 100644
--- a/fs_mgr/libsnapshot/device_info.h
+++ b/fs_mgr/libsnapshot/device_info.h
@@ -34,7 +34,7 @@ class DeviceInfo final : public SnapshotManager::IDeviceInfo {
     std::string GetSlotSuffix() const override;
     std::string GetOtherSlotSuffix() const override;
     const android::fs_mgr::IPartitionOpener& GetPartitionOpener() const override;
-    std::string GetSuperDevice(uint32_t slot) const override;
+    std::string GetSuperDevice() const override;
     bool IsOverlayfsSetup() const override;
     bool SetBootControlMergeStatus(MergeStatus status) override;
     bool SetActiveBootSlot(unsigned int slot) override;
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/cow_reader.h b/fs_mgr/libsnapshot/include/libsnapshot/cow_reader.h
index 3389f5863e..bb9b0002f9 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/cow_reader.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/cow_reader.h
@@ -172,10 +172,10 @@ class CowReader final : public ICowReader {
     bool ParseV2(android::base::borrowed_fd fd, std::optional<uint64_t> label);
     bool PrepMergeOps();
     // sequence data is stored as an operation with actual data residing in the data offset.
-    bool GetSequenceDataV2(std::vector<uint32_t>* merge_op_blocks, std::vector<int>* other_ops,
+    bool GetSequenceDataV2(std::vector<uint32_t>* merge_op_blocks, std::vector<uint32_t>* other_ops,
                            std::unordered_map<uint32_t, int>* block_map);
     // v3 of the cow writes sequence data within its own separate sequence buffer.
-    bool GetSequenceData(std::vector<uint32_t>* merge_op_blocks, std::vector<int>* other_ops,
+    bool GetSequenceData(std::vector<uint32_t>* merge_op_blocks, std::vector<uint32_t>* other_ops,
                          std::unordered_map<uint32_t, int>* block_map);
     uint64_t FindNumCopyops();
     uint8_t GetCompressionType();
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/mock_device_info.h b/fs_mgr/libsnapshot/include/libsnapshot/mock_device_info.h
index ca1ac1e6b2..0d5a05b391 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/mock_device_info.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/mock_device_info.h
@@ -25,7 +25,7 @@ class MockDeviceInfo : public SnapshotManager::IDeviceInfo {
     MOCK_METHOD(std::string, GetMetadataDir, (), (const, override));
     MOCK_METHOD(std::string, GetSlotSuffix, (), (const, override));
     MOCK_METHOD(std::string, GetOtherSlotSuffix, (), (const, override));
-    MOCK_METHOD(std::string, GetSuperDevice, (uint32_t slot), (const, override));
+    MOCK_METHOD(std::string, GetSuperDevice, (), (const, override));
     MOCK_METHOD(const android::fs_mgr::IPartitionOpener&, GetPartitionOpener, (), (const));
     MOCK_METHOD(bool, IsOverlayfsSetup, (), (const, override));
     MOCK_METHOD(bool, SetBootControlMergeStatus, (MergeStatus status), (override));
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h b/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
index 4520b21a96..f4e9826fd4 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
@@ -107,7 +107,7 @@ class ISnapshotManager {
         virtual std::string GetMetadataDir() const = 0;
         virtual std::string GetSlotSuffix() const = 0;
         virtual std::string GetOtherSlotSuffix() const = 0;
-        virtual std::string GetSuperDevice(uint32_t slot) const = 0;
+        virtual std::string GetSuperDevice() const = 0;
         virtual const android::fs_mgr::IPartitionOpener& GetPartitionOpener() const = 0;
         virtual bool IsOverlayfsSetup() const = 0;
         virtual bool SetBootControlMergeStatus(MergeStatus status) = 0;
diff --git a/fs_mgr/libsnapshot/include_test/libsnapshot/test_helpers.h b/fs_mgr/libsnapshot/include_test/libsnapshot/test_helpers.h
index 1cd66515ed..8a92a265a8 100644
--- a/fs_mgr/libsnapshot/include_test/libsnapshot/test_helpers.h
+++ b/fs_mgr/libsnapshot/include_test/libsnapshot/test_helpers.h
@@ -82,7 +82,7 @@ class TestDeviceInfo : public SnapshotManager::IDeviceInfo {
     std::string GetMetadataDir() const override { return metadata_dir_; }
     std::string GetSlotSuffix() const override { return slot_suffix_; }
     std::string GetOtherSlotSuffix() const override { return slot_suffix_ == "_a" ? "_b" : "_a"; }
-    std::string GetSuperDevice([[maybe_unused]] uint32_t slot) const override { return "super"; }
+    std::string GetSuperDevice() const override { return "super"; }
     const android::fs_mgr::IPartitionOpener& GetPartitionOpener() const override {
         return *opener_.get();
     }
@@ -185,6 +185,7 @@ class SnapshotTestPropertyFetcher : public android::fs_mgr::IPropertyFetcher {
 
     std::string GetProperty(const std::string& key, const std::string& defaultValue) override;
     bool GetBoolProperty(const std::string& key, bool defaultValue) override;
+    void SetProperty(const std::string& key, const std::string& value);
 
     static void SetUp(const std::string& slot_suffix = "_a") { Reset(slot_suffix); }
     static void TearDown() { Reset("_a"); }
@@ -192,7 +193,7 @@ class SnapshotTestPropertyFetcher : public android::fs_mgr::IPropertyFetcher {
   private:
     static void Reset(const std::string& slot_suffix) {
         IPropertyFetcher::OverrideForTesting(
-                std::make_unique<SnapshotTestPropertyFetcher>(slot_suffix));
+                std::make_shared<SnapshotTestPropertyFetcher>(slot_suffix));
     }
 
   private:
diff --git a/fs_mgr/libsnapshot/libsnapshot_cow/cow_reader.cpp b/fs_mgr/libsnapshot/libsnapshot_cow/cow_reader.cpp
index 127735d014..2395d3a857 100644
--- a/fs_mgr/libsnapshot/libsnapshot_cow/cow_reader.cpp
+++ b/fs_mgr/libsnapshot/libsnapshot_cow/cow_reader.cpp
@@ -285,7 +285,7 @@ uint32_t CowReader::GetMaxCompressionSize() {
 //                        Replace-op-4, Zero-op-9, Replace-op-5 }
 //==============================================================
 bool CowReader::PrepMergeOps() {
-    std::vector<int> other_ops;
+    std::vector<uint32_t> other_ops;
     std::vector<uint32_t> merge_op_blocks;
     std::unordered_map<uint32_t, int> block_map;
 
@@ -322,7 +322,7 @@ bool CowReader::PrepMergeOps() {
     if (reader_flag_ == ReaderFlags::USERSPACE_MERGE) {
         std::sort(other_ops.begin(), other_ops.end());
     } else {
-        std::sort(other_ops.begin(), other_ops.end(), std::greater<int>());
+        std::sort(other_ops.begin(), other_ops.end(), std::greater<uint32_t>());
     }
 
     merge_op_blocks.insert(merge_op_blocks.end(), other_ops.begin(), other_ops.end());
@@ -356,7 +356,7 @@ bool CowReader::PrepMergeOps() {
 }
 
 bool CowReader::GetSequenceDataV2(std::vector<uint32_t>* merge_op_blocks,
-                                  std::vector<int>* other_ops,
+                                  std::vector<uint32_t>* other_ops,
                                   std::unordered_map<uint32_t, int>* block_map) {
     auto seq_ops_set = std::unordered_set<uint32_t>();
     size_t num_seqs = 0;
@@ -394,7 +394,7 @@ bool CowReader::GetSequenceDataV2(std::vector<uint32_t>* merge_op_blocks,
     return false;
 }
 
-bool CowReader::GetSequenceData(std::vector<uint32_t>* merge_op_blocks, std::vector<int>* other_ops,
+bool CowReader::GetSequenceData(std::vector<uint32_t>* merge_op_blocks, std::vector<uint32_t>* other_ops,
                                 std::unordered_map<uint32_t, int>* block_map) {
     std::unordered_set<uint32_t> seq_ops_set;
     // read sequence ops data
@@ -468,7 +468,7 @@ bool CowReader::VerifyMergeOps() {
         if (overwritten_blocks.count(block)) {
             overwrite = overwritten_blocks[block];
             LOG(ERROR) << "Invalid Sequence! Block needed for op:\n"
-                       << op << "\noverwritten by previously merged op:\n"
+                       << *op << "\noverwritten by previously merged op:\n"
                        << *overwrite;
         }
         if (misaligned && overwritten_blocks.count(block + 1)) {
diff --git a/fs_mgr/libsnapshot/libsnapshot_cow/create_cow.cpp b/fs_mgr/libsnapshot/libsnapshot_cow/create_cow.cpp
index b15e6ab9cb..ac635e9261 100644
--- a/fs_mgr/libsnapshot/libsnapshot_cow/create_cow.cpp
+++ b/fs_mgr/libsnapshot/libsnapshot_cow/create_cow.cpp
@@ -43,6 +43,7 @@ DEFINE_string(
 DEFINE_string(compression, "lz4",
               "Compression algorithm. Default is set to lz4. Available options: lz4, zstd, gz");
 DEFINE_bool(merkel_tree, false, "If true, source image hash is obtained from verity merkel tree");
+DEFINE_bool(inplace_copy_ops, false, "If true, inplace copy ops are added to the snapshot patch");
 
 namespace android {
 namespace snapshot {
@@ -58,7 +59,7 @@ class CreateSnapshot {
   public:
     CreateSnapshot(const std::string& src_file, const std::string& target_file,
                    const std::string& patch_file, const std::string& compression,
-                   const bool& merkel_tree);
+                   const bool& merkel_tree, const bool& inplace_copy_ops);
     bool CreateSnapshotPatch();
 
   private:
@@ -75,6 +76,7 @@ class CreateSnapshot {
      */
     std::string parsing_file_;
     bool create_snapshot_patch_ = false;
+    bool incremental_ = true;
 
     const int kNumThreads = 6;
     const size_t kBlockSizeToRead = 1_MiB;
@@ -103,6 +105,7 @@ class CreateSnapshot {
     bool ReadBlocks(off_t offset, const int skip_blocks, const uint64_t dev_sz);
     std::string ToHexString(const uint8_t* buf, size_t len);
 
+    bool CreateSnapshotFullOta();
     bool CreateSnapshotFile();
     bool FindSourceBlockHash();
     bool PrepareParse(std::string& parsing_file, const bool createSnapshot);
@@ -121,6 +124,7 @@ class CreateSnapshot {
     bool ParseSourceMerkelTree();
 
     bool use_merkel_tree_ = false;
+    bool allow_inplace_copy_ops_ = false;
     std::vector<uint8_t> target_salt_;
     std::vector<uint8_t> source_salt_;
 };
@@ -136,14 +140,19 @@ void CreateSnapshotLogger(android::base::LogId, android::base::LogSeverity sever
 
 CreateSnapshot::CreateSnapshot(const std::string& src_file, const std::string& target_file,
                                const std::string& patch_file, const std::string& compression,
-                               const bool& merkel_tree)
+                               const bool& merkel_tree, const bool& inplace_copy_ops)
     : src_file_(src_file),
       target_file_(target_file),
       patch_file_(patch_file),
-      use_merkel_tree_(merkel_tree) {
+      use_merkel_tree_(merkel_tree),
+      allow_inplace_copy_ops_(inplace_copy_ops) {
     if (!compression.empty()) {
         compression_ = compression;
     }
+
+    if (src_file_.empty()) {
+        incremental_ = false;
+    }
 }
 
 bool CreateSnapshot::PrepareParse(std::string& parsing_file, const bool createSnapshot) {
@@ -259,10 +268,21 @@ bool CreateSnapshot::CreateSnapshotFile() {
     return ParsePartition();
 }
 
+bool CreateSnapshot::CreateSnapshotFullOta() {
+    if (!PrepareParse(target_file_, true)) {
+        return false;
+    }
+    return ParsePartition();
+}
+
 /*
  * Creates snapshot patch file by comparing source.img and target.img
  */
 bool CreateSnapshot::CreateSnapshotPatch() {
+    if (!incremental_) {
+        return CreateSnapshotFullOta();
+    }
+
     if (!FindSourceBlockHash()) {
         return false;
     }
@@ -289,22 +309,24 @@ std::string CreateSnapshot::ToHexString(const uint8_t* buf, size_t len) {
 
 void CreateSnapshot::PrepareMergeBlock(const void* buffer, uint64_t block,
                                        std::string& block_hash) {
-    if (std::memcmp(zblock_.get(), buffer, BLOCK_SZ) == 0) {
-        std::lock_guard<std::mutex> lock(write_lock_);
-        zero_blocks_.push_back(block);
-        return;
-    }
-
-    auto iter = source_block_hash_.find(block_hash);
-    if (iter != source_block_hash_.end()) {
-        std::lock_guard<std::mutex> lock(write_lock_);
-        // In-place copy is skipped
-        if (block != iter->second) {
-            copy_blocks_[block] = iter->second;
-        } else {
-            in_place_ops_ += 1;
+    if (incremental_) {
+        if (std::memcmp(zblock_.get(), buffer, BLOCK_SZ) == 0) {
+            std::lock_guard<std::mutex> lock(write_lock_);
+            zero_blocks_.push_back(block);
+            return;
+        }
+
+        auto iter = source_block_hash_.find(block_hash);
+        if (iter != source_block_hash_.end()) {
+            std::lock_guard<std::mutex> lock(write_lock_);
+            // In-place copy is skipped conditionally
+            if (allow_inplace_copy_ops_ || (block != iter->second)) {
+                copy_blocks_[block] = iter->second;
+            } else {
+                in_place_ops_ += 1;
+            }
+            return;
         }
-        return;
     }
     std::lock_guard<std::mutex> lock(write_lock_);
     replace_blocks_.push_back(block);
@@ -376,29 +398,83 @@ bool CreateSnapshot::WriteNonOrderedSnapshots() {
     }
     return true;
 }
-
 bool CreateSnapshot::WriteOrderedSnapshots() {
-    std::unordered_map<uint64_t, uint64_t> overwritten_blocks;
-    std::vector<std::pair<uint64_t, uint64_t>> merge_sequence;
-    for (auto it = copy_blocks_.begin(); it != copy_blocks_.end(); it++) {
-        if (overwritten_blocks.count(it->second)) {
-            replace_blocks_.push_back(it->first);
-            continue;
+    // Sort copy_blocks_ by target block index so consecutive
+    // target blocks can be together
+    std::vector<std::pair<uint64_t, uint64_t>> sorted_copy_blocks_(copy_blocks_.begin(),
+                                                                   copy_blocks_.end());
+    std::sort(sorted_copy_blocks_.begin(), sorted_copy_blocks_.end());
+    std::unordered_map<uint64_t, std::vector<uint64_t>> dependency_graph;
+    std::unordered_map<uint64_t, int> in_degree;
+
+    // Initialize in-degree and build the dependency graph
+    for (const auto& [target, source] : sorted_copy_blocks_) {
+        in_degree[target] = 0;
+        if (copy_blocks_.count(source)) {
+            // this source block itself gets modified
+            // Only add a dependency if it's not a self-loop causing it.
+            // An X->X operation should not make X depend on itself in a way that forms a cycle.
+            if (source != target) {
+                dependency_graph[source].push_back(target);
+                in_degree[target]++;
+            }
         }
-        overwritten_blocks[it->first] = it->second;
-        merge_sequence.emplace_back(std::make_pair(it->first, it->second));
     }
-    // Sort the blocks so that if the blocks are contiguous, it would help
-    // compress multiple blocks in one shot based on the compression factor.
-    std::sort(replace_blocks_.begin(), replace_blocks_.end());
 
-    copy_ops_ = merge_sequence.size();
-    for (auto it = merge_sequence.begin(); it != merge_sequence.end(); it++) {
-        if (!writer_->AddCopy(it->first, it->second, 1)) {
-            return false;
+    std::vector<uint64_t> ordered_copy_ops_;
+    std::deque<uint64_t> queue;
+
+    // Add nodes with in-degree 0 (no dependency) to the queue
+    for (const auto& [target, degree] : in_degree) {
+        if (degree == 0) {
+            queue.push_back(target);
         }
     }
 
+    while (!queue.empty()) {
+        uint64_t current_target = queue.front();
+        queue.pop_front();
+        ordered_copy_ops_.push_back(current_target);
+
+        if (dependency_graph.count(current_target)) {
+            for (uint64_t neighbor : dependency_graph[current_target]) {
+                in_degree[neighbor]--;
+                if (in_degree[neighbor] == 0) {
+                    queue.push_back(neighbor);
+                }
+            }
+        }
+    }
+
+    // Detect cycles and change those blocks to replace blocks
+    if (ordered_copy_ops_.size() != copy_blocks_.size()) {
+        LOG(INFO) << "Cycle detected in copy operations! Converting some to replace.";
+        std::unordered_set<uint64_t> safe_targets_(ordered_copy_ops_.begin(),
+                                                   ordered_copy_ops_.end());
+        for (auto it = copy_blocks_.begin(); it != copy_blocks_.end();) {
+            if (safe_targets_.find(it->first) == safe_targets_.end()) {
+                replace_blocks_.push_back(it->first);
+                it = copy_blocks_.erase(it);
+            } else {
+                ++it;
+            }
+        }
+    }
+
+    std::reverse(ordered_copy_ops_.begin(), ordered_copy_ops_.end());
+    // Add the copy blocks
+    copy_ops_ = 0;
+    for (uint64_t target : ordered_copy_ops_) {
+        LOG(DEBUG) << "copy target: " << target << " source: " << copy_blocks_[target];
+        if (!writer_->AddCopy(target, copy_blocks_[target], 1)) {
+            return false;
+        }
+        copy_ops_++;
+    }
+    // Sort the blocks so that if the blocks are contiguous, it would help
+    // compress multiple blocks in one shot based on the compression factor.
+    std::sort(replace_blocks_.begin(), replace_blocks_.end());
+    LOG(DEBUG) << "Total copy ops: " << copy_ops_;
     return true;
 }
 
@@ -567,15 +643,16 @@ bool CreateSnapshot::ParsePartition() {
 
 constexpr char kUsage[] = R"(
 NAME
-    create_snapshot - Create snapshot patches by comparing two partition images
+    create_snapshot - Create snapshot patches
 
 SYNOPSIS
-    create_snapshot --source=<source.img> --target=<target.img> --compression="<compression-algorithm"
+    $create_snapshot --source=<source.img> --target=<target.img> --compression="<compression-algorithm"
 
     source.img -> Source partition image
     target.img -> Target partition image
     compression -> compression algorithm. Default set to lz4. Supported types are gz, lz4, zstd.
     merkel_tree -> If true, source image hash is obtained from verity merkel tree.
+    inplace_copy_ops -> If true, inplace copy ops are added to the snapshot patch.
     output_dir -> Output directory to write the patch file to. Defaults to current working directory if not set.
 
 EXAMPLES
@@ -583,6 +660,7 @@ EXAMPLES
    $ create_snapshot $SOURCE_BUILD/system.img $TARGET_BUILD/system.img
    $ create_snapshot $SOURCE_BUILD/product.img $TARGET_BUILD/product.img --compression="zstd"
    $ create_snapshot $SOURCE_BUILD/product.img $TARGET_BUILD/product.img --merkel_tree --output_dir=/tmp/create_snapshot_output
+   $ create_snapshot $SOURCE_BUILD/product.img $TARGET_BUILD/product.img --inplace_copy_ops
 
 )";
 
@@ -591,7 +669,12 @@ int main(int argc, char* argv[]) {
     ::gflags::SetUsageMessage(kUsage);
     ::gflags::ParseCommandLineFlags(&argc, &argv, true);
 
-    if (FLAGS_source.empty() || FLAGS_target.empty()) {
+    if (FLAGS_target.empty()) {
+        LOG(INFO) << kUsage;
+        return 0;
+    }
+
+    if (FLAGS_target.empty() && !FLAGS_source.empty()) {
         LOG(INFO) << kUsage;
         return 0;
     }
@@ -603,7 +686,8 @@ int main(int argc, char* argv[]) {
         snapshotfile = FLAGS_output_dir + "/" + snapshotfile;
     }
     android::snapshot::CreateSnapshot snapshot(FLAGS_source, FLAGS_target, snapshotfile,
-                                               FLAGS_compression, FLAGS_merkel_tree);
+                                               FLAGS_compression, FLAGS_merkel_tree,
+                                               FLAGS_inplace_copy_ops);
 
     if (!snapshot.CreateSnapshotPatch()) {
         LOG(ERROR) << "Snapshot creation failed";
diff --git a/fs_mgr/libsnapshot/scratch_super.cpp b/fs_mgr/libsnapshot/scratch_super.cpp
index 2d1912394f..fd53767881 100644
--- a/fs_mgr/libsnapshot/scratch_super.cpp
+++ b/fs_mgr/libsnapshot/scratch_super.cpp
@@ -60,7 +60,7 @@ using namespace android::storage_literals;
 namespace android {
 namespace snapshot {
 
-static bool UmountScratch() {
+bool UmountScratch(const bool cleanup_ota_dir) {
     Fstab fstab;
     if (!ReadFstabFromProcMounts(&fstab)) {
         LOG(ERROR) << "Cannot read /proc/mounts";
@@ -72,10 +72,12 @@ static bool UmountScratch() {
 
     auto ota_dir = std::string(kOtaMetadataMount) + "/" + "ota";
 
-    std::error_code ec;
-    if (std::filesystem::remove_all(ota_dir, ec) == static_cast<std::uintmax_t>(-1)) {
-        LOG(ERROR) << "Failed to remove OTA directory: " << ec.message();
-        return false;
+    if (cleanup_ota_dir) {
+        std::error_code ec;
+        if (std::filesystem::remove_all(ota_dir, ec) == static_cast<std::uintmax_t>(-1)) {
+            LOG(ERROR) << "Failed to remove OTA directory: " << ec.message();
+            return false;
+        }
     }
 
     if (umount(kOtaMetadataMount) != 0) {
@@ -88,7 +90,7 @@ static bool UmountScratch() {
 }
 
 bool CleanupScratchOtaMetadataIfPresent(const ISnapshotManager::IDeviceInfo* info) {
-    if (!UmountScratch()) {
+    if (!UmountScratch(true)) {
         return false;
     }
 
@@ -322,8 +324,7 @@ bool IsScratchOtaMetadataOnSuper() {
     auto source_slot = fs_mgr_get_slot_suffix();
     auto source_slot_number = SlotNumberForSlotSuffix(source_slot);
 
-    const auto super_device =
-            kPhysicalDevice + fs_mgr_get_super_partition_name(!source_slot_number);
+    const auto super_device = kPhysicalDevice + fs_mgr_get_super_partition_name();
 
     auto metadata = android::fs_mgr::ReadMetadata(super_device, !source_slot_number);
     if (!metadata) {
diff --git a/fs_mgr/libsnapshot/scratch_super.h b/fs_mgr/libsnapshot/scratch_super.h
index 7a16f97d97..077bcdd4e8 100644
--- a/fs_mgr/libsnapshot/scratch_super.h
+++ b/fs_mgr/libsnapshot/scratch_super.h
@@ -28,6 +28,7 @@ std::string GetScratchOtaMetadataPartition();
 std::string MapScratchOtaMetadataPartition(const std::string& device);
 bool CreateScratchOtaMetadataOnSuper(const ISnapshotManager::IDeviceInfo* info = nullptr);
 bool CleanupScratchOtaMetadataIfPresent(const ISnapshotManager::IDeviceInfo* info = nullptr);
+bool UmountScratch(const bool cleanup_ota_dir);
 
 }  // namespace snapshot
 }  // namespace android
diff --git a/fs_mgr/libsnapshot/scripts/apply-update.sh b/fs_mgr/libsnapshot/scripts/apply-update.sh
index 92bff3b935..90df424592 100755
--- a/fs_mgr/libsnapshot/scripts/apply-update.sh
+++ b/fs_mgr/libsnapshot/scripts/apply-update.sh
@@ -30,9 +30,18 @@ log_file="$HOST_PATH/snapshot.log"
 
 # Function to log messages to both console and log file
 log_message() {
-    message="$1"
-    echo "$message"  # Print to stdout
-    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$log_file"  # Append to log file with timestamp
+  message="$1"
+  echo "$message"                                               # Print to stdout
+  echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$log_file" # Append to log file with timestamp
+}
+
+# Wrap fastboot to pick up the preferred serial from environment. adb already honors $ANDROID_SERIAL.
+fastboot() {
+  if [ -z "$FASTBOOT_SERIAL" ]; then
+    command fastboot "$@"
+  else
+    command fastboot -s "$FASTBOOT_SERIAL" "$@"
+  fi
 }
 
 # Function to check for create_snapshot and build if needed
@@ -65,8 +74,8 @@ flash_static_partitions() {
   fastboot flashall --exclude-dynamic-partitions --disable-super-optimization --skip-reboot
 
   if (( wipe_flag )); then
-      log_message "Wiping device..."
-      fastboot -w
+    log_message "Wiping device..."
+    fastboot -w
   fi
   fastboot reboot
 }
@@ -127,6 +136,7 @@ EOF
 skip_static_partitions=0
 boot_snapshot=0
 flash_bootloader=1
+userspace_fastboot=0
 wipe_flag=0
 help_flag=0
 
@@ -145,6 +155,9 @@ for arg in "$@"; do
     --boot_snapshot)
       boot_snapshot=1
       ;;
+    --userspace_fastboot)
+      userspace_fastboot=1
+      ;;
     --help)
       help_flag=1
       ;;
@@ -156,15 +169,20 @@ for arg in "$@"; do
 done
 
 # Check if help flag is set
-if (( help_flag )); then
+if ((help_flag)); then
   show_help
   exit 0
 fi
 
+if (( flash_bootloader && userspace_fastboot )); then
+  echo "Bootloader cannot be flashed with userspace fastboot"
+  exit 1
+fi
+
 rm -rf $HOST_PATH
 
-adb root
 adb wait-for-device
+adb root
 
 adb shell rm -rf $DEVICE_PATH
 adb shell mkdir -p $DEVICE_PATH
@@ -214,22 +232,26 @@ adb push -q $HOST_PATH/*.patch $DEVICE_PATH
 
 log_message "Applying update"
 
-if (( boot_snapshot)); then
+if ((boot_snapshot)); then
   adb shell snapshotctl map-snapshots $DEVICE_PATH
-elif (( wipe_flag )); then
+elif ((wipe_flag)); then
   adb shell snapshotctl apply-update $DEVICE_PATH -w
 else
   adb shell snapshotctl apply-update $DEVICE_PATH
 fi
 
 if (( skip_static_partitions )); then
-    log_message "Rebooting device - Skipping flashing static partitions"
-    adb reboot
+  log_message "Rebooting device - Skipping flashing static partitions"
+  adb reboot
 else
-    log_message "Rebooting device to bootloader"
+  log_message "Rebooting device to bootloader"
+  if (( userspace_fastboot )); then
+    adb reboot fastboot
+  else
     adb reboot bootloader
-    log_message "Waiting to enter fastboot bootloader"
-    flash_static_partitions "$wipe_flag" "$flash_bootloader"
+  fi
+  log_message "Waiting to enter fastboot bootloader"
+  flash_static_partitions "$wipe_flag" "$flash_bootloader"
 fi
 
 log_message "Update completed"
diff --git a/fs_mgr/libsnapshot/snapshot.cpp b/fs_mgr/libsnapshot/snapshot.cpp
index fa2f569d20..7728738bd2 100644
--- a/fs_mgr/libsnapshot/snapshot.cpp
+++ b/fs_mgr/libsnapshot/snapshot.cpp
@@ -43,6 +43,7 @@
 #include <libdm/dm.h>
 #include <libfiemap/image_manager.h>
 #include <liblp/liblp.h>
+#include <liblp/property_fetcher.h>
 
 #include <android/snapshot/snapshot.pb.h>
 #include <libsnapshot/snapshot_stats.h>
@@ -72,6 +73,7 @@ using android::fs_mgr::CreateLogicalPartition;
 using android::fs_mgr::CreateLogicalPartitionParams;
 using android::fs_mgr::GetPartitionGroupName;
 using android::fs_mgr::GetPartitionName;
+using android::fs_mgr::IPropertyFetcher;
 using android::fs_mgr::LpMetadata;
 using android::fs_mgr::MetadataBuilder;
 using android::fs_mgr::SlotNumberForSlotSuffix;
@@ -763,7 +765,7 @@ bool SnapshotManager::MapSourceDevice(LockedFile* lock, const std::string& name,
     auto slot = SlotNumberForSlotSuffix(slot_suffix);
 
     CreateLogicalPartitionParams params = {
-            .block_device = device_->GetSuperDevice(slot),
+            .block_device = device_->GetSuperDevice(),
             .metadata = metadata,
             .partition_name = old_name,
             .timeout_ms = timeout_ms,
@@ -956,6 +958,11 @@ bool SnapshotManager::InitiateMerge() {
         return false;
     }
 
+    if (GetDebugFlag("block_merge_switchover")) {
+        LOG(INFO) << "Merge switchover blocked for testing.";
+        return true;
+    }
+
     auto reported_code = MergeFailureCode::Ok;
     for (const auto& snapshot : *merge_group) {
         // If this fails, we have no choice but to continue. Everything must
@@ -1372,38 +1379,51 @@ auto SnapshotManager::CheckTargetMergeState(LockedFile* lock, const std::string&
             return MergeResult(UpdateState::MergeFailed, MergeFailureCode::UnknownTargetType);
         }
 
-        // This is the case when device reboots during merge. Once the device boots,
-        // snapuserd daemon will not resume merge immediately in first stage init.
-        // This is slightly different as compared to dm-snapshot-merge; In this
-        // case, metadata file will have "MERGING" state whereas the daemon will be
-        // waiting to resume the merge. Thus, we resume the merge at this point.
-        if (merge_status == "snapshot" && snapshot_status.state() == SnapshotState::MERGING) {
-            if (!snapuserd_client_->InitiateMerge(name)) {
-                return MergeResult(UpdateState::MergeFailed, MergeFailureCode::UnknownTargetType);
+        if (merge_status == "snapshot") {
+            // This is the case when device reboots during merge. Once the device boots,
+            // snapuserd daemon will not resume merge immediately in first stage init.
+            // This is slightly different as compared to dm-snapshot-merge; In this
+            // case, metadata file will have "MERGING" state whereas the daemon will be
+            // waiting to resume the merge. Thus, we resume the merge at this point.
+            if (snapshot_status.state() == SnapshotState::MERGING) {
+                if (!snapuserd_client_->InitiateMerge(name)) {
+                    return MergeResult(UpdateState::MergeFailed,
+                                       MergeFailureCode::UnknownTargetType);
+                }
+                return MergeResult(UpdateState::Merging);
             }
-            return MergeResult(UpdateState::Merging);
-        }
 
-        if (merge_status == "snapshot" &&
-            DecideMergePhase(snapshot_status) == MergePhase::SECOND_PHASE) {
-            if (update_status.merge_phase() == MergePhase::FIRST_PHASE) {
+            auto intended_phase = DecideMergePhase(snapshot_status);
+            if (intended_phase == MergePhase::SECOND_PHASE &&
+                update_status.merge_phase() == MergePhase::FIRST_PHASE) {
                 // The snapshot is not being merged because it's in the wrong phase.
                 return MergeResult(UpdateState::None);
-            } else {
-                // update_status is already in second phase but the
-                // snapshot_status is still not set to SnapshotState::MERGING.
-                //
-                // Resume the merge at this point. see b/374225913
-                LOG(INFO) << "SwitchSnapshotToMerge: " << name << " after resuming merge";
-                auto code = SwitchSnapshotToMerge(lock, name);
-                if (code != MergeFailureCode::Ok) {
-                    LOG(ERROR) << "Failed to switch snapshot: " << name
-                               << " to merge during second phase";
-                    return MergeResult(UpdateState::MergeFailed,
-                                       MergeFailureCode::UnknownTargetType);
-                }
+            }
+
+            // The inverse of the above condition should never be true. We
+            // should not enter the next phase without completing the first
+            // phase.
+            if (intended_phase != update_status.merge_phase()) {
+                LOG(ERROR) << "Snapshot " << name << " is out of phase";
+                return MergeResult(UpdateState::MergeFailed, MergeFailureCode::IncorrectMergePhase);
+            }
+
+            if (GetDebugFlag("block_merge_switchover")) {
+                LOG(INFO) << "Delayed merge switchover blocked for testing.";
                 return MergeResult(UpdateState::Merging);
             }
+
+            // Resume the merge at this point. see b/374225913. We were probably
+            // interrupted during a phase change.
+            LOG(INFO) << "SwitchSnapshotToMerge: " << name << " after resuming merge";
+
+            auto code = SwitchSnapshotToMerge(lock, name);
+            if (code != MergeFailureCode::Ok) {
+                LOG(ERROR) << "Failed to switch snapshot: " << name
+                           << " to merge during second phase";
+                return MergeResult(UpdateState::MergeFailed, MergeFailureCode::UnknownTargetType);
+            }
+            return MergeResult(UpdateState::Merging);
         }
 
         if (merge_status == "snapshot-merge") {
@@ -1665,7 +1685,7 @@ bool SnapshotManager::CollapseSnapshotDevice(LockedFile* lock, const std::string
     uint32_t slot = SlotNumberForSlotSuffix(device_->GetSlotSuffix());
     // Create a DmTable that is identical to the base device.
     CreateLogicalPartitionParams base_device_params{
-            .block_device = device_->GetSuperDevice(slot),
+            .block_device = device_->GetSuperDevice(),
             .metadata_slot = slot,
             .partition_name = name,
             .partition_opener = &device_->GetPartitionOpener(),
@@ -1930,7 +1950,7 @@ bool SnapshotManager::PerformInitTransition(InitTransition transition,
 std::unique_ptr<LpMetadata> SnapshotManager::ReadCurrentMetadata() {
     const auto& opener = device_->GetPartitionOpener();
     uint32_t slot = SlotNumberForSlotSuffix(device_->GetSlotSuffix());
-    auto super_device = device_->GetSuperDevice(slot);
+    auto super_device = device_->GetSuperDevice();
     auto metadata = android::fs_mgr::ReadMetadata(opener, super_device, slot);
     if (!metadata) {
         LOG(ERROR) << "Could not read dynamic partition metadata for device: " << super_device;
@@ -1999,7 +2019,7 @@ bool SnapshotManager::GetSnapshotFlashingStatus(LockedFile* lock,
     // metadata are in sync, so flashing all partitions on the source slot will
     // remove the UPDATED flag on the target slot as well.
     const auto& opener = device_->GetPartitionOpener();
-    auto super_device = device_->GetSuperDevice(target_slot);
+    auto super_device = device_->GetSuperDevice();
     auto metadata = android::fs_mgr::ReadMetadata(opener, super_device, target_slot);
     if (!metadata) {
         return false;
@@ -2476,17 +2496,20 @@ bool SnapshotManager::NeedSnapshotsInFirstStageMount() {
         if (slot == Slot::Source) {
             // Device is rebooting into the original slot, so mark this as a
             // rollback.
+            auto contents = ReadUpdateSourceSlotSuffix();
             auto path = GetRollbackIndicatorPath();
             if (!android::base::WriteStringToFile("1", path)) {
                 PLOG(ERROR) << "Unable to write rollback indicator: " << path;
             } else {
-                LOG(INFO) << "Rollback detected, writing rollback indicator to " << path;
+                LOG(INFO) << "Rollback detected, writing rollback indicator to " << path
+                          << ". UpdateSourceSlot: " << contents;
                 if (device_->IsTempMetadata()) {
                     CleanupScratchOtaMetadataIfPresent();
                 }
             }
         }
-        LOG(INFO) << "Not booting from new slot. Will not mount snapshots.";
+        LOG(INFO) << "Not booting from new slot: " << device_->GetSlotSuffix()
+                  << ". Will not mount snapshots.";
         return false;
     }
 
@@ -3010,7 +3033,7 @@ bool SnapshotManager::MapAllSnapshots(const std::chrono::milliseconds& timeout_m
     const auto& opener = device_->GetPartitionOpener();
     auto slot_suffix = device_->GetOtherSlotSuffix();
     auto slot_number = SlotNumberForSlotSuffix(slot_suffix);
-    auto super_device = device_->GetSuperDevice(slot_number);
+    auto super_device = device_->GetSuperDevice();
     auto metadata = android::fs_mgr::ReadMetadata(opener, super_device, slot_number);
     if (!metadata) {
         LOG(ERROR) << "MapAllSnapshots could not read dynamic partition metadata for device: "
@@ -3445,7 +3468,7 @@ Return SnapshotManager::CreateUpdateSnapshots(const DeltaArchiveManifest& manife
     uint32_t current_slot = SlotNumberForSlotSuffix(current_suffix);
     auto target_suffix = device_->GetOtherSlotSuffix();
     uint32_t target_slot = SlotNumberForSlotSuffix(target_suffix);
-    auto current_super = device_->GetSuperDevice(current_slot);
+    auto current_super = device_->GetSuperDevice();
 
     auto current_metadata = MetadataBuilder::New(opener, current_super, current_slot);
     if (current_metadata == nullptr) {
@@ -3478,14 +3501,6 @@ Return SnapshotManager::CreateUpdateSnapshots(const DeltaArchiveManifest& manife
     // free regions.
     UnmapAndDeleteCowPartition(current_metadata.get());
 
-    // Check that all these metadata is not retrofit dynamic partitions. Snapshots on
-    // devices with retrofit dynamic partitions does not make sense.
-    // This ensures that current_metadata->GetFreeRegions() uses the same device
-    // indices as target_metadata (i.e. 0 -> "super").
-    // This is also assumed in MapCowDevices() call below.
-    CHECK(current_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME &&
-          target_metadata->GetBlockDevicePartitionName(0) == LP_METADATA_DEFAULT_PARTITION_NAME);
-
     const auto& dap_metadata = manifest.dynamic_partition_metadata();
 
     std::string vabc_disable_reason;
@@ -3592,8 +3607,8 @@ Return SnapshotManager::CreateUpdateSnapshots(const DeltaArchiveManifest& manife
                                     all_snapshot_status);
     if (!ret.is_ok()) return ret;
 
-    if (!UpdatePartitionTable(opener, device_->GetSuperDevice(target_slot),
-                              *exported_target_metadata, target_slot)) {
+    if (!UpdatePartitionTable(opener, device_->GetSuperDevice(), *exported_target_metadata,
+                              target_slot)) {
         LOG(ERROR) << "Cannot write target metadata";
         return Return::Error();
     }
@@ -4042,7 +4057,7 @@ bool SnapshotManager::UnmapAllPartitionsInRecovery() {
 
     const auto& opener = device_->GetPartitionOpener();
     uint32_t slot = SlotNumberForSlotSuffix(device_->GetSlotSuffix());
-    auto super_device = device_->GetSuperDevice(slot);
+    auto super_device = device_->GetSuperDevice();
     auto metadata = android::fs_mgr::ReadMetadata(opener, super_device, slot);
     if (!metadata) {
         LOG(ERROR) << "Could not read dynamic partition metadata for device: " << super_device;
@@ -4233,7 +4248,7 @@ bool SnapshotManager::HandleImminentDataWipe(const std::function<void()>& callba
 
     if (try_merge) {
         auto slot_number = SlotNumberForSlotSuffix(device_->GetSlotSuffix());
-        auto super_path = device_->GetSuperDevice(slot_number);
+        auto super_path = device_->GetSuperDevice();
         if (!CreateLogicalAndSnapshotPartitions(super_path, 20s)) {
             LOG(ERROR) << "Unable to map partitions to complete merge.";
             return false;
@@ -4281,7 +4296,7 @@ bool SnapshotManager::FinishMergeInRecovery() {
     }
 
     auto slot_number = SlotNumberForSlotSuffix(device_->GetSlotSuffix());
-    auto super_path = device_->GetSuperDevice(slot_number);
+    auto super_path = device_->GetSuperDevice();
     if (!CreateLogicalAndSnapshotPartitions(super_path, 20s)) {
         LOG(ERROR) << "Unable to map partitions to complete merge.";
         return false;
@@ -4412,7 +4427,7 @@ CreateResult SnapshotManager::RecoveryCreateSnapshotDevices(
 
     auto slot_suffix = device_->GetOtherSlotSuffix();
     auto slot_number = SlotNumberForSlotSuffix(slot_suffix);
-    auto super_path = device_->GetSuperDevice(slot_number);
+    auto super_path = device_->GetSuperDevice();
     if (!CreateLogicalAndSnapshotPartitions(super_path, 20s)) {
         LOG(ERROR) << "Unable to map partitions.";
         return CreateResult::ERROR;
diff --git a/fs_mgr/libsnapshot/snapshot_test.cpp b/fs_mgr/libsnapshot/snapshot_test.cpp
index 7719a295c4..8791ed8b97 100644
--- a/fs_mgr/libsnapshot/snapshot_test.cpp
+++ b/fs_mgr/libsnapshot/snapshot_test.cpp
@@ -80,7 +80,6 @@ using android::fs_mgr::BlockDeviceInfo;
 using android::fs_mgr::CreateLogicalPartitionParams;
 using android::fs_mgr::DestroyLogicalPartition;
 using android::fs_mgr::EnsurePathMounted;
-using android::fs_mgr::EnsurePathUnmounted;
 using android::fs_mgr::Extent;
 using android::fs_mgr::Fstab;
 using android::fs_mgr::GetPartitionGroupName;
@@ -154,8 +153,8 @@ class SnapshotTest : public ::testing::Test {
             properties["ro.virtual_ab.io_uring.enabled"] = "false";
         }
 
-        auto fetcher = std::make_unique<SnapshotTestPropertyFetcher>("_a", std::move(properties));
-        IPropertyFetcher::OverrideForTesting(std::move(fetcher));
+        fetcher_ = std::make_shared<SnapshotTestPropertyFetcher>("_a", std::move(properties));
+        IPropertyFetcher::OverrideForTesting(fetcher_);
 
         if (GetLegacyCompressionEnabledProperty() || CanUseUserspaceSnapshots()) {
             // If we're asked to test the device's actual configuration, then it
@@ -534,6 +533,7 @@ class SnapshotTest : public ::testing::Test {
     std::string fake_super_;
     bool snapuserd_required_ = false;
     std::string test_name_;
+    std::shared_ptr<SnapshotTestPropertyFetcher> fetcher_;
 };
 
 TEST_F(SnapshotTest, CreateSnapshot) {
@@ -2133,23 +2133,6 @@ TEST_F(MetadataMountedTest, Android) {
     EXPECT_TRUE(sm->CancelUpdate()) << "Metadata dir should never be unmounted in Android mode";
 }
 
-TEST_F(MetadataMountedTest, Recovery) {
-    GTEST_SKIP() << "b/350715463";
-
-    test_device->set_recovery(true);
-    metadata_dir_ = test_device->GetMetadataDir();
-
-    EXPECT_TRUE(android::fs_mgr::EnsurePathUnmounted(&fstab_, metadata_dir_));
-    EXPECT_FALSE(IsMetadataMounted());
-
-    auto device = sm->EnsureMetadataMounted();
-    EXPECT_NE(nullptr, device);
-    EXPECT_TRUE(IsMetadataMounted());
-
-    device.reset();
-    EXPECT_FALSE(IsMetadataMounted());
-}
-
 // Test that during a merge, we can wipe data in recovery.
 TEST_F(SnapshotUpdateTest, MergeInRecovery) {
     // Execute the first update.
@@ -2829,6 +2812,40 @@ TEST_F(SnapshotUpdateTest, BadCowVersion) {
     ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
 }
 
+TEST_F(SnapshotUpdateTest, MergeSwitchoverInterrupted) {
+    if (!snapuserd_required_) {
+        GTEST_SKIP() << "VABC only";
+    }
+
+    auto old_sys_size = GetSize(sys_);
+    auto old_prd_size = GetSize(prd_);
+
+    // Grow |sys| but shrink |prd|.
+    SetSize(sys_, old_sys_size * 2);
+    sys_->set_estimate_cow_size(8_MiB);
+    SetSize(prd_, old_prd_size / 2);
+    prd_->set_estimate_cow_size(1_MiB);
+
+    AddOperationForPartitions();
+
+    ASSERT_TRUE(sm->BeginUpdate());
+    ASSERT_TRUE(sm->CreateUpdateSnapshots(manifest_));
+    ASSERT_TRUE(WriteSnapshots());
+    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));
+    ASSERT_TRUE(UnmapAll());
+
+    fetcher_->SetProperty("persist.virtual_ab.testing.block_merge_switchover", "true");
+
+    auto init = NewManagerForFirstStageMount("_b");
+    ASSERT_NE(init, nullptr);
+    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
+    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
+    ASSERT_TRUE(init->InitiateMerge());
+
+    fetcher_->SetProperty("persist.virtual_ab.testing.block_merge_switchover", "false");
+    ASSERT_EQ(init->ProcessUpdateState(), UpdateState::MergeCompleted);
+}
+
 TEST_F(SnapshotTest, FlagCheck) {
     if (!snapuserd_required_) {
         GTEST_SKIP() << "Skipping snapuserd test";
diff --git a/fs_mgr/libsnapshot/snapshotctl.cpp b/fs_mgr/libsnapshot/snapshotctl.cpp
index 32c8e37612..47051a9ee2 100644
--- a/fs_mgr/libsnapshot/snapshotctl.cpp
+++ b/fs_mgr/libsnapshot/snapshotctl.cpp
@@ -173,7 +173,7 @@ bool MapSnapshots::PrepareUpdate() {
 
     auto source_slot = fs_mgr_get_slot_suffix();
     auto source_slot_number = SlotNumberForSlotSuffix(source_slot);
-    auto super_source = fs_mgr_get_super_partition_name(source_slot_number);
+    auto super_source = fs_mgr_get_super_partition_name();
 
     // Get current partition information.
     PartitionOpener opener;
@@ -281,6 +281,8 @@ bool MapSnapshots::GetCowDevicePath(std::string partition_name, std::string* cow
 }
 
 bool MapSnapshots::ApplyUpdate() {
+    auto scope_guard = android::base::make_scope_guard([]() { UmountScratch(false); });
+
     if (!PrepareUpdate()) {
         LOG(ERROR) << "PrepareUpdate failed";
         return false;
@@ -649,6 +651,12 @@ bool ApplyUpdate(int argc, char** argv) {
             metadata_on_super = true;
         }
     }
+
+    if (!std::filesystem::exists(path) || std::filesystem::is_empty(path)) {
+        LOG(ERROR) << path << " doesn't exist";
+        return false;
+    }
+
     MapSnapshots cow(path, metadata_on_super);
     if (!cow.ApplyUpdate()) {
         return false;
@@ -921,6 +929,11 @@ bool MapPrecreatedSnapshots(int argc, char** argv) {
     std::string path = std::string(argv[2]);
     std::vector<std::string> patchfiles;
 
+    if (!std::filesystem::exists(path) || std::filesystem::is_empty(path)) {
+        LOG(ERROR) << path << " doesn't exist";
+        return false;
+    }
+
     for (const auto& entry : std::filesystem::directory_iterator(path)) {
         if (android::base::EndsWith(entry.path().generic_string(), ".patch")) {
             patchfiles.push_back(android::base::Basename(entry.path().generic_string()));
@@ -987,7 +1000,7 @@ bool CreateTestUpdate(SnapshotManager* sm) {
     auto source_slot_number = SlotNumberForSlotSuffix(source_slot);
     auto target_slot = fs_mgr_get_other_slot_suffix();
     auto target_slot_number = SlotNumberForSlotSuffix(target_slot);
-    auto super_source = fs_mgr_get_super_partition_name(source_slot_number);
+    auto super_source = fs_mgr_get_super_partition_name();
 
     // Get current partition information.
     PartitionOpener opener;
@@ -1019,7 +1032,7 @@ bool CreateTestUpdate(SnapshotManager* sm) {
     // Write the "new" system partition.
     auto system_target_name = "system" + target_slot;
     CreateLogicalPartitionParams clpp = {
-            .block_device = fs_mgr_get_super_partition_name(target_slot_number),
+            .block_device = fs_mgr_get_super_partition_name(),
             .metadata_slot = {target_slot_number},
             .partition_name = system_target_name,
             .timeout_ms = 10s,
diff --git a/fs_mgr/libsnapshot/snapuserd/Android.bp b/fs_mgr/libsnapshot/snapuserd/Android.bp
index 9972bc76d1..9508484cba 100644
--- a/fs_mgr/libsnapshot/snapuserd/Android.bp
+++ b/fs_mgr/libsnapshot/snapuserd/Android.bp
@@ -283,6 +283,12 @@ cc_test {
     test_options: {
         // VABC mandatory in Android T per VSR.
         min_shipping_api_level: 32,
+        test_runner_options: [
+            {
+                name: "native-test-timeout",
+                value: "5m",
+            },
+        ],
     },
 }
 
diff --git a/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp b/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
index 693fe39b61..c94c45164b 100644
--- a/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
@@ -190,7 +190,8 @@ bool SnapuserdClient::WaitForDeviceDelete(const std::string& control_device) {
     }
     std::string response = Receivemsg();
     if (response != "success") {
-        LOG(ERROR) << "Failed waiting to delete device " << control_device;
+        LOG(ERROR) << "Failed waiting to delete device " << control_device << " received:'"
+                   << response << "'";
         return false;
     }
     return true;
@@ -214,7 +215,7 @@ std::string SnapuserdClient::Receivemsg() {
         return {};
     }
     if (ret == 0) {
-        LOG(DEBUG) << "Snapuserd:client disconnected";
+        LOG(INFO) << "Snapuserd:client disconnected";
         return {};
     }
     return std::string(msg, ret);
diff --git a/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp b/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
index d29223e4b8..0adc0c5c36 100644
--- a/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
@@ -21,7 +21,6 @@
 #include <snapuserd/snapuserd_client.h>
 
 #include <storage_literals/storage_literals.h>
-#include "user-space-merge/snapuserd_core.h"
 
 #include "snapuserd_daemon.h"
 
@@ -37,8 +36,7 @@ DEFINE_bool(io_uring, false, "If true, io_uring feature is enabled");
 DEFINE_bool(o_direct, false, "If true, enable direct reads on source device");
 DEFINE_bool(skip_verification, false, "If true, skip verification of partitions");
 DEFINE_int32(cow_op_merge_size, 0, "number of operations to be processed at once");
-DEFINE_int32(worker_count, android::snapshot::kNumWorkerThreads,
-             "number of worker threads used to serve I/O requests to dm-user");
+DEFINE_int32(worker_count, 4, "number of worker threads used to serve I/O requests to dm-user");
 DEFINE_int32(verify_block_size, 1_MiB, "block sized used during verification of snapshots");
 DEFINE_int32(num_verify_threads, 3, "number of threads used during verification phase");
 
@@ -117,7 +115,7 @@ bool Daemon::StartServerForUserspaceSnapshots(int arg_start, int argc, char** ar
     for (int i = arg_start; i < argc; i++) {
         auto parts = android::base::Split(argv[i], ",");
         if (parts.size() != 4) {
-            LOG(ERROR) << "Malformed message, expected at least four sub-arguments.";
+            LOG(ERROR) << "Malformed message, expected four sub-arguments.";
             return false;
         }
         HandlerOptions options = {
diff --git a/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.h b/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.h
index 303e394a84..1693d347ac 100644
--- a/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.h
+++ b/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.h
@@ -16,9 +16,6 @@
 
 #include <poll.h>
 
-#include <string>
-#include <vector>
-
 #include "user-space-merge/snapuserd_server.h"
 
 namespace android {
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.h
index d10d8e8592..4ae1e7c5c9 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/handler_manager.h
@@ -95,9 +95,6 @@ class ISnapshotHandlerManager {
     // Returns whether all snapshots have verified.
     virtual bool GetVerificationStatus() = 0;
 
-    // Disable partition verification
-    virtual void DisableVerification() = 0;
-
     // Pause Merge threads
     virtual void PauseMerge() = 0;
 
@@ -123,7 +120,6 @@ class SnapshotHandlerManager final : public ISnapshotHandlerManager {
     void TerminateMergeThreads() override;
     double GetMergePercentage() override;
     bool GetVerificationStatus() override;
-    void DisableVerification() override { perform_verification_ = false; }
     void PauseMerge() override;
     void ResumeMerge() override;
 
@@ -150,7 +146,6 @@ class SnapshotHandlerManager final : public ISnapshotHandlerManager {
     int num_partitions_merge_complete_ = 0;
     std::queue<std::shared_ptr<HandlerThread>> merge_handlers_;
     android::base::unique_fd monitor_merge_event_fd_;
-    bool perform_verification_ = true;
 };
 
 }  // namespace snapshot
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
index 660082f73c..fd063788a5 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
@@ -14,10 +14,11 @@
  * limitations under the License.
  */
 
-#include <libsnapshot/cow_format.h>
 #include <pthread.h>
+#include <sys/prctl.h>
 
 #include <android-base/properties.h>
+#include <libsnapshot/cow_format.h>
 
 #include "merge_worker.h"
 #include "snapuserd_core.h"
@@ -598,7 +599,8 @@ void MergeWorker::FinalizeIouring() {
 bool MergeWorker::Run() {
     SNAP_LOG(DEBUG) << "Waiting for merge begin...";
 
-    pthread_setname_np(pthread_self(), "MergeWorker");
+    std::string thread_name = "MergeWorker_" + misc_name_;
+    prctl(PR_SET_NAME, thread_name.c_str());
 
     if (!snapuserd_->WaitForMergeBegin()) {
         return true;
@@ -611,10 +613,10 @@ bool MergeWorker::Run() {
     }
 
     if (!SetProfiles({"CPUSET_SP_BACKGROUND"})) {
-        SNAP_PLOG(ERROR) << "Failed to assign task profile to Mergeworker thread";
+        SNAP_LOG(ERROR) << "Failed to assign task profile to Mergeworker thread";
     }
 
-    SNAP_LOG(INFO) << "Merge starting..";
+    SNAP_LOG(INFO) << "Merge starting: " << thread_name;
 
     bufsink_.Initialize(PAYLOAD_BUFFER_SZ);
 
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/read_worker.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/read_worker.cpp
index 33767d6547..8065576866 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/read_worker.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/read_worker.cpp
@@ -18,6 +18,7 @@
 
 #include <libsnapshot/cow_format.h>
 #include <pthread.h>
+#include <sys/prctl.h>
 
 #include "read_worker.h"
 #include "snapuserd_core.h"
@@ -247,8 +248,8 @@ bool ReadWorker::Init() {
             ssize_t page_size = getpagesize();
             if (posix_memalign(&aligned_addr, page_size, page_size) < 0) {
                 direct_read_ = false;
-                SNAP_PLOG(ERROR) << "posix_memalign failed "
-                                 << " page_size: " << page_size << " read_sz: " << page_size;
+                SNAP_PLOG(ERROR) << "posix_memalign failed " << " page_size: " << page_size
+                                 << " read_sz: " << page_size;
             } else {
                 aligned_buffer_.reset(aligned_addr);
             }
@@ -266,7 +267,9 @@ bool ReadWorker::Init() {
 bool ReadWorker::Run() {
     SNAP_LOG(INFO) << "Processing snapshot I/O requests....";
 
-    pthread_setname_np(pthread_self(), "ReadWorker");
+    std::string thread_name = "ReadWorker_" + misc_name_;
+    prctl(PR_SET_NAME, thread_name.c_str());
+
     auto worker_thread_priority = android::base::GetUintProperty<uint32_t>(
             "ro.virtual_ab.worker_thread_priority", ANDROID_PRIORITY_NORMAL);
 
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.cpp
index 1f3d3a0dff..4de090317a 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.cpp
@@ -48,7 +48,7 @@ SnapshotHandler::SnapshotHandler(std::string misc_name, std::string cow_device,
 }
 
 bool SnapshotHandler::InitializeWorkers() {
-    for (int i = 0; i < num_worker_threads_; i++) {
+    for (int i = 0; i < handler_options_.num_worker_threads; i++) {
         auto wt = std::make_unique<ReadWorker>(cow_device_, backing_store_device_, misc_name_,
                                                base_path_merge_, GetSharedPtr(),
                                                block_server_opener_, handler_options_.o_direct);
@@ -323,7 +323,7 @@ bool SnapshotHandler::Start() {
     // Now that the worker threads are up, scan the partitions.
     // If the snapshot-merge is being resumed, there is no need to scan as the
     // current slot is already marked as boot complete.
-    if (perform_verification_ && !resume_merge_) {
+    if (!handler_options_.skip_verification && !resume_merge_) {
         update_verify_->VerifyUpdatePartition();
     }
 
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
index 9c5d58b941..6192726b2c 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
@@ -58,8 +58,6 @@ using namespace android::storage_literals;
 static constexpr size_t PAYLOAD_BUFFER_SZ = (1UL << 20);
 static_assert(PAYLOAD_BUFFER_SZ >= BLOCK_SZ);
 
-static constexpr int kNumWorkerThreads = 4;
-
 #define SNAP_LOG(level) LOG(level) << misc_name_ << ": "
 #define SNAP_PLOG(level) PLOG(level) << misc_name_ << ": "
 
@@ -245,8 +243,6 @@ class SnapshotHandler : public std::enable_shared_from_this<SnapshotHandler> {
     bool merge_monitored_ = false;
     bool attached_ = false;
     bool scratch_space_ = false;
-    int num_worker_threads_ = kNumWorkerThreads;
-    bool perform_verification_ = true;
     bool resume_merge_ = false;
     bool merge_complete_ = false;
     HandlerOptions handler_options_;
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_readahead.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_readahead.cpp
index c7ae519268..07eb4a65c9 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_readahead.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_readahead.cpp
@@ -17,6 +17,7 @@
 #include "snapuserd_readahead.h"
 
 #include <pthread.h>
+#include <sys/prctl.h>
 
 #include "android-base/properties.h"
 #include "snapuserd_core.h"
@@ -341,8 +342,8 @@ bool ReadAhead::ReadAheadAsyncIO() {
             // Submit the IO for all the COW ops in a single syscall
             int ret = io_uring_submit(ring_.get());
             if (ret != pending_ios_to_submit) {
-                SNAP_PLOG(ERROR) << "io_uring_submit failed for read-ahead: "
-                                 << " io submit: " << ret << " expected: " << pending_ios_to_submit;
+                SNAP_PLOG(ERROR) << "io_uring_submit failed for read-ahead: " << " io submit: "
+                                 << ret << " expected: " << pending_ios_to_submit;
                 return false;
             }
 
@@ -777,7 +778,8 @@ void ReadAhead::FinalizeIouring() {
 bool ReadAhead::RunThread() {
     SNAP_LOG(INFO) << "ReadAhead thread started.";
 
-    pthread_setname_np(pthread_self(), "ReadAhead");
+    std::string thread_name = "RA_" + misc_name_;
+    prctl(PR_SET_NAME, thread_name.c_str());
 
     if (!InitializeFds()) {
         return false;
@@ -797,15 +799,31 @@ bool ReadAhead::RunThread() {
         SNAP_PLOG(ERROR) << "Failed to set thread priority";
     }
 
-    if (!SetProfiles({"CPUSET_SP_BACKGROUND"})) {
-        SNAP_PLOG(ERROR) << "Failed to assign task profile to readahead thread";
-    }
+    SNAP_LOG(INFO) << "ReadAhead processing: " << thread_name;
 
-    SNAP_LOG(INFO) << "ReadAhead processing.";
+    bool set_profiles = false;
+    // having bools store these values will help up avoid unnecessary GetProperty() calls which is
+    // important as this loop is very busy
+    bool should_set_profiles =
+            android::base::GetBoolProperty("ro.virtual_ab.set_task_profiles", false);
+    bool finished_boot = false;
     while (!RAIterDone()) {
         if (!ReadAheadIOStart()) {
             break;
         }
+
+        if (!finished_boot &&
+            !(finished_boot = android::base::GetBoolProperty("sys.boot_completed", false))) {
+            continue;
+        }
+
+        if (should_set_profiles && !set_profiles) {
+            if (!SetProfiles({"CPUSET_SP_BACKGROUND"})) {
+                SNAP_LOG(ERROR) << "Failed to assign task profile to readahead thread: "
+                                << thread_name;
+            }
+            set_profiles = true;
+        }
     }
 
     FinalizeIouring();
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
index b21189c8e5..38d39b9bf1 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
@@ -367,9 +367,9 @@ std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(const std::string&
         options.num_worker_threads = 1;
     }
 
-    if (options.skip_verification || android::base::EndsWith(misc_name, "-init") ||
-        is_socket_present_ || (access(kBootSnapshotsWithoutSlotSwitch, F_OK) == 0)) {
-        handlers_->DisableVerification();
+    if (android::base::EndsWith(misc_name, "-init") || is_socket_present_ ||
+        (access(kBootSnapshotsWithoutSlotSwitch, F_OK) == 0)) {
+        options.skip_verification = true;
     }
 
     auto opener = block_server_factory_->CreateOpener(misc_name);
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
index f3795a1c33..32c234a573 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
@@ -729,12 +729,12 @@ void SnapuserdTest::CreateCowDeviceOrderedOps() {
 void SnapuserdTest::InitCowDevice() {
     auto factory = harness_->GetBlockServerFactory();
     auto opener = factory->CreateOpener(system_device_ctrl_name_);
-    handlers_->DisableVerification();
     const TestParam params = GetParam();
     HandlerOptions options = {
-            .num_worker_threads = params.num_threads,
+            .num_worker_threads = 1,
             .use_iouring = params.io_uring,
             .o_direct = params.o_direct,
+            .skip_verification = true,
             .cow_op_merge_size = params.cow_op_merge_size,
             .verify_block_size = params.verification_block_size,
             .num_verification_threads = params.num_verification_threads,
@@ -1282,7 +1282,7 @@ void HandlerTest::InitializeDevice() {
 
     const TestParam params = GetParam();
     HandlerOptions options = {
-            .num_worker_threads = params.num_threads,
+            .num_worker_threads = 1,
             .use_iouring = params.io_uring,
             .o_direct = params.o_direct,
             .cow_op_merge_size = params.cow_op_merge_size,
diff --git a/fs_mgr/libsnapshot/test_helpers.cpp b/fs_mgr/libsnapshot/test_helpers.cpp
index 2eac347499..7b7e6a14ed 100644
--- a/fs_mgr/libsnapshot/test_helpers.cpp
+++ b/fs_mgr/libsnapshot/test_helpers.cpp
@@ -218,7 +218,6 @@ SnapshotTestPropertyFetcher::SnapshotTestPropertyFetcher(
     : properties_(std::move(props)) {
     properties_["ro.boot.slot_suffix"] = slot_suffix;
     properties_["ro.boot.dynamic_partitions"] = "true";
-    properties_["ro.boot.dynamic_partitions_retrofit"] = "false";
     properties_["ro.virtual_ab.enabled"] = "true";
 }
 
@@ -246,5 +245,9 @@ bool SnapshotTestPropertyFetcher::GetBoolProperty(const std::string& key, bool d
     }
 }
 
+void SnapshotTestPropertyFetcher::SetProperty(const std::string& key, const std::string& value) {
+    properties_[key] = value;
+}
+
 }  // namespace snapshot
 }  // namespace android
diff --git a/fs_mgr/libsnapshot/utility.cpp b/fs_mgr/libsnapshot/utility.cpp
index 04ee069598..c71f542879 100644
--- a/fs_mgr/libsnapshot/utility.cpp
+++ b/fs_mgr/libsnapshot/utility.cpp
@@ -316,5 +316,15 @@ bool KernelSupportsCompressedSnapshots() {
     return dm.GetTargetByName("user", nullptr);
 }
 
+static bool IsDebuggable() {
+    return android::base::GetBoolProperty("ro.debuggable", false);
+}
+
+bool GetDebugFlag(const std::string& flag) {
+    auto fetcher = IPropertyFetcher::GetInstance();
+    std::string prop_name = "persist.virtual_ab.testing." + flag;
+    return IsDebuggable() && fetcher->GetBoolProperty(prop_name, false);
+}
+
 }  // namespace snapshot
 }  // namespace android
diff --git a/fs_mgr/libsnapshot/utility.h b/fs_mgr/libsnapshot/utility.h
index eaf51c1cbd..b07aa3b530 100644
--- a/fs_mgr/libsnapshot/utility.h
+++ b/fs_mgr/libsnapshot/utility.h
@@ -141,6 +141,7 @@ bool GetSkipVerificationProperty();
 bool CanUseUserspaceSnapshots();
 bool IsDmSnapshotTestingEnabled();
 bool IsVendorFromAndroid12();
+bool GetDebugFlag(const std::string& flag);
 
 // Swap the suffix of a partition name.
 std::string GetOtherPartitionName(const std::string& name);
diff --git a/fs_mgr/tools/Android.bp b/fs_mgr/tools/Android.bp
index 462777d131..e9e8edaf96 100644
--- a/fs_mgr/tools/Android.bp
+++ b/fs_mgr/tools/Android.bp
@@ -29,6 +29,8 @@ cc_binary {
     shared_libs: [
         "libbase",
         "liblog",
+        "liblp",
+        "libcrypto_utils",
     ],
 
     cflags: ["-Werror"],
diff --git a/fs_mgr/tools/dmctl.cpp b/fs_mgr/tools/dmctl.cpp
index 00f8038e19..0cfaa492a7 100644
--- a/fs_mgr/tools/dmctl.cpp
+++ b/fs_mgr/tools/dmctl.cpp
@@ -25,6 +25,8 @@
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/unique_fd.h>
+#include <fs_mgr.h>
+#include <fs_mgr_dm_linear.h>
 #include <libdm/dm.h>
 
 #include <fstream>
@@ -48,6 +50,7 @@ static int Usage(void) {
     std::cerr << "       dmctl -f file" << std::endl;
     std::cerr << "commands:" << std::endl;
     std::cerr << "  create <dm-name> [-ro] <targets...>" << std::endl;
+    std::cerr << "  create-from-super <partition> <dm-name> [-ro]" << std::endl;
     std::cerr << "  delete <dm-name>" << std::endl;
     std::cerr << "  list <devices | targets> [-v]" << std::endl;
     std::cerr << "  message <dm-name> <sector> <message>" << std::endl;
@@ -615,6 +618,40 @@ static int ResumeCmdHandler(int argc, char** argv) {
     return 0;
 }
 
+static int CreateFromSuperCmdHandler(int argc, char** argv) {
+    if (argc < 2 || argc > 3) {
+        std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
+        return -EINVAL;
+    }
+
+    bool writable = true;
+    if (argc >= 3) {
+        if (argv[2] != "-ro"s) {
+            std::cerr << "Expected -ro" << std::endl;
+            return -EINVAL;
+        }
+        writable = false;
+    }
+
+    auto super_device = "/dev/block/by-name/" + fs_mgr_get_super_partition_name();
+    auto slot_number = android::fs_mgr::SlotNumberForSlotSuffix(fs_mgr_get_slot_suffix());
+    android::fs_mgr::CreateLogicalPartitionParams params = {
+            .block_device = super_device,
+            .metadata_slot = {slot_number},
+            .partition_name = argv[0],
+            .force_writable = writable,
+            .device_name = argv[1],
+    };
+
+    std::string path;
+    if (!android::fs_mgr::CreateLogicalPartition(params, &path)) {
+        std::cerr << "Failed to create partition" << std::endl;
+        return -EIO;
+    }
+    std::cout << path << std::endl;
+    return 0;
+}
+
 static int SuspendCmdHandler(int argc, char** argv) {
     if (argc != 1) {
         std::cerr << "Invalid arguments, see \'dmctl help\'" << std::endl;
@@ -632,6 +669,7 @@ static int SuspendCmdHandler(int argc, char** argv) {
 static std::map<std::string, std::function<int(int, char**)>> cmdmap = {
         // clang-format off
         {"create", DmCreateCmdHandler},
+        {"create-from-super", CreateFromSuperCmdHandler},
         {"delete", DmDeleteCmdHandler},
         {"replace", DmReplaceCmdHandler},
         {"list", DmListCmdHandler},
diff --git a/fs_mgr/userdata.alias.remove.rc b/fs_mgr/userdata.alias.remove.rc
new file mode 100644
index 0000000000..87ce2baba4
--- /dev/null
+++ b/fs_mgr/userdata.alias.remove.rc
@@ -0,0 +1,7 @@
+# Userdata device aliasing file control service
+
+service userdata_alias_remove /system_ext/bin/userdata_alias_remove
+    user root
+    group system
+    disabled
+    oneshot
diff --git a/fs_mgr/userdata_alias_remove.cpp b/fs_mgr/userdata_alias_remove.cpp
new file mode 100644
index 0000000000..94a791e312
--- /dev/null
+++ b/fs_mgr/userdata_alias_remove.cpp
@@ -0,0 +1,66 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+/*
+ * This removes a userdata aliasing file, which maps storage space for
+ * a specific purpose to a special-purpose partition, allowing for its
+ * later release.
+ */
+
+#include <errno.h>
+#include <error.h>
+#include <stdio.h>
+
+#include <android-base/file.h>
+#include <android-base/properties.h>
+
+#include <fstab/fstab.h>
+
+static constexpr const char* ALIAS_REMOVE_PROP_NAME = "userdata.alias.remove";
+
+int main(void) {
+    android::fs_mgr::Fstab fstab;
+    if (!android::fs_mgr::ReadDefaultFstab(&fstab)) {
+        error(1, 0, "no valid fstab");
+    }
+
+    android::fs_mgr::FstabEntry* dataEntry =
+            android::fs_mgr::GetEntryForMountPoint(&fstab, "/data");
+    if (!dataEntry) {
+        error(1, 0, "/data is not mounted yet");
+    }
+
+    /* Only F2FS supports device aliasing file */
+    if (dataEntry->fs_type != "f2fs") {
+        return 0;
+    }
+
+    std::string target = android::base::GetProperty(ALIAS_REMOVE_PROP_NAME, "");
+    for (size_t i = 0; i < dataEntry->user_devices.size(); ++i) {
+        if (dataEntry->device_aliased[i]) {
+            std::string deviceName = android::base::Basename(dataEntry->user_devices[i]);
+            if (target == deviceName) {
+                std::string filename = "/data/" + target;
+                if (unlink(filename.c_str())) {
+                    error(1, errno, "Failed to remove file: %s", filename.c_str());
+                }
+                return 0;
+            }
+        }
+    }
+
+    error(1, 0, "%s is not a device aliasing file", target.c_str());
+}
diff --git a/healthd/Android.bp b/healthd/Android.bp
index 7eb6edde1e..37b74d9584 100644
--- a/healthd/Android.bp
+++ b/healthd/Android.bp
@@ -294,6 +294,30 @@ cc_binary {
     },
 }
 
+cc_test {
+    name: "battery_monitor_test",
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    shared_libs: [
+        "libutils",
+    ],
+    static_libs: [
+        "android.hardware.health-V4-ndk",
+        "libbatterymonitor",
+    ],
+    srcs: ["battery_monitor_test.cpp"],
+    whole_static_libs: [
+        "android.hardware.health-translate-ndk",
+    ],
+    test_suites: [
+        "general-tests",
+        "device-tests",
+    ],
+    require_root: true,
+}
+
 cc_test {
     name: "charger_test",
     defaults: ["charger_defaults"],
diff --git a/healthd/BatteryMonitor.cpp b/healthd/BatteryMonitor.cpp
index 64c85e2d72..bea8fe35d3 100644
--- a/healthd/BatteryMonitor.cpp
+++ b/healthd/BatteryMonitor.cpp
@@ -19,6 +19,7 @@
 #include <healthd/healthd.h>
 #include <healthd/BatteryMonitor.h>
 
+#include <ctype.h>
 #include <dirent.h>
 #include <errno.h>
 #include <fcntl.h>
@@ -147,18 +148,6 @@ BatteryMonitor::BatteryMonitor()
 
 BatteryMonitor::~BatteryMonitor() {}
 
-HealthInfo_1_0 BatteryMonitor::getHealthInfo_1_0() const {
-    HealthInfo_1_0 health_info_1_0;
-    translateToHidl(*mHealthInfo, &health_info_1_0);
-    return health_info_1_0;
-}
-
-HealthInfo_2_0 BatteryMonitor::getHealthInfo_2_0() const {
-    HealthInfo_2_0 health_info_2_0;
-    translateToHidl(*mHealthInfo, &health_info_2_0);
-    return health_info_2_0;
-}
-
 HealthInfo_2_1 BatteryMonitor::getHealthInfo_2_1() const {
     HealthInfo_2_1 health_info_2_1;
     translateToHidl(*mHealthInfo, &health_info_2_1);
@@ -353,6 +342,30 @@ static T getIntField(const String8& path) {
     return value;
 }
 
+String8 sanitizeSerialNumber(const std::string& serial) {
+    String8 sanitized;
+    for (const auto& c : serial) {
+        if (isupper(c) || isdigit(c)) {
+            sanitized.appendFormat("%c", c);
+        } else if (islower(c)) {
+            sanitized.appendFormat("%c", toupper(c));
+        } else {
+            // Some devices return non-ASCII characters as part of the serial
+            // number. Handle these gracefully since VTS requires alphanumeric
+            // characters.
+            sanitized.appendFormat("%02X", (unsigned int)c);
+        }
+    }
+    return sanitized;
+}
+
+static String8 readSerialNumber(const String8& path) {
+    std::string unsanitized;
+    if (readFromFile(path, &unsanitized) <= 0) return {};
+
+    return sanitizeSerialNumber(unsanitized);
+}
+
 static bool isScopedPowerSupply(const char* name) {
     constexpr char kScopeDevice[] = "Device";
 
@@ -423,6 +436,11 @@ void BatteryMonitor::updateValues(void) {
         ensureBatteryHealthData(mHealthInfo.get())->batteryFirstUsageSeconds =
                 getIntField<int64_t>(mHealthdConfig->batteryFirstUsageDatePath);
 
+    if (!mHealthdConfig->batterySerialPath.empty()) {
+        ensureBatteryHealthData(mHealthInfo.get())->batterySerialNumber =
+                readSerialNumber(mHealthdConfig->batterySerialPath);
+    }
+
     mHealthInfo->batteryTemperatureTenthsCelsius =
             mBatteryFixedTemperature ? mBatteryFixedTemperature
                                      : getIntField(mHealthdConfig->batteryTemperaturePath);
@@ -488,12 +506,19 @@ void BatteryMonitor::updateValues(void) {
                               mChargerNames[i].c_str());
             int ChargingCurrent = (access(path.c_str(), R_OK) == 0) ? getIntField(path) : 0;
 
+            int ChargingVoltage;
             path.clear();
             path.appendFormat("%s/%s/voltage_max", POWER_SUPPLY_SYSFS_PATH,
                               mChargerNames[i].c_str());
-
-            int ChargingVoltage =
-                    (access(path.c_str(), R_OK) == 0) ? getIntField(path) : DEFAULT_VBUS_VOLTAGE;
+            if (access(path.c_str(), R_OK) == 0) {
+                ChargingVoltage = getIntField(path);
+            } else {
+                path.clear();
+                path.appendFormat("%s/%s/voltage_max_design", POWER_SUPPLY_SYSFS_PATH,
+                                  mChargerNames[i].c_str());
+                ChargingVoltage = (access(path.c_str(), R_OK) == 0) ? getIntField(path)
+                                                                    : DEFAULT_VBUS_VOLTAGE;
+            }
 
             double power = ((double)ChargingCurrent / MILLION) *
                            ((double)ChargingVoltage / MILLION);
@@ -707,7 +732,9 @@ status_t BatteryMonitor::getProperty(int id, struct BatteryProperty *val) {
 }
 
 status_t BatteryMonitor::getSerialNumber(std::optional<std::string>* out) {
-    *out = std::nullopt;
+    if (!mHealthdConfig->batterySerialPath.empty()) {
+        *out = readSerialNumber(mHealthdConfig->batterySerialPath);
+    }
     return OK;
 }
 
@@ -976,6 +1003,12 @@ void BatteryMonitor::init(struct healthd_config *hc) {
                     if (access(path.c_str(), R_OK) == 0) mHealthdConfig->chargingPolicyPath = path;
                 }
 
+                if (mHealthdConfig->batterySerialPath.empty()) {
+                    path.clear();
+                    path.appendFormat("%s/%s/serial_number", POWER_SUPPLY_SYSFS_PATH, name);
+                    if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batterySerialPath = path;
+                }
+
                 break;
 
             case ANDROID_POWER_SUPPLY_TYPE_UNKNOWN:
@@ -1038,6 +1071,8 @@ void BatteryMonitor::init(struct healthd_config *hc) {
             KLOG_WARNING(LOG_TAG, "chargingStatePath not found\n");
         if (mHealthdConfig->chargingPolicyPath.empty())
             KLOG_WARNING(LOG_TAG, "chargingPolicyPath not found\n");
+        if (mHealthdConfig->batterySerialPath.empty())
+            KLOG_WARNING(LOG_TAG, "batterySerialPath not found\n");
     }
 
     if (property_get("ro.boot.fake_battery", pval, NULL) > 0
diff --git a/healthd/BatteryMonitor_v1.cpp b/healthd/BatteryMonitor_v1.cpp
index 2e0cfc9718..588b08836f 100644
--- a/healthd/BatteryMonitor_v1.cpp
+++ b/healthd/BatteryMonitor_v1.cpp
@@ -141,18 +141,6 @@ BatteryMonitor::BatteryMonitor()
 
 BatteryMonitor::~BatteryMonitor() {}
 
-HealthInfo_1_0 BatteryMonitor::getHealthInfo_1_0() const {
-    HealthInfo_1_0 health_info_1_0;
-    translateToHidl(*mHealthInfo, &health_info_1_0);
-    return health_info_1_0;
-}
-
-HealthInfo_2_0 BatteryMonitor::getHealthInfo_2_0() const {
-    HealthInfo_2_0 health_info_2_0;
-    translateToHidl(*mHealthInfo, &health_info_2_0);
-    return health_info_2_0;
-}
-
 HealthInfo_2_1 BatteryMonitor::getHealthInfo_2_1() const {
     HealthInfo_2_1 health_info_2_1;
     translateToHidl(*mHealthInfo, &health_info_2_1);
diff --git a/healthd/TEST_MAPPING b/healthd/TEST_MAPPING
index 17e363d465..60baef4fe0 100644
--- a/healthd/TEST_MAPPING
+++ b/healthd/TEST_MAPPING
@@ -4,6 +4,11 @@
       "name": "libhealthd_charger_test"
     }
   ],
+  "postsubmit": [
+    {
+      "name": "battery_monitor_test"
+    }
+  ],
   "hwasan-postsubmit": [
     {
       "name": "libhealthd_charger_test"
diff --git a/mini_keyctl/mini_keyctl_utils.h b/healthd/battery_monitor_internal.h
similarity index 70%
rename from mini_keyctl/mini_keyctl_utils.h
rename to healthd/battery_monitor_internal.h
index cc31d29ce1..33fd375e75 100644
--- a/mini_keyctl/mini_keyctl_utils.h
+++ b/healthd/battery_monitor_internal.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2019 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,16 +13,14 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
-#ifndef _MINI_KEYCTL_MINI_KEYCTL_UTILS_H_
-#define _MINI_KEYCTL_MINI_KEYCTL_UTILS_H_
+#pragma once
 
 #include <string>
 
-#include <keyutils.h>
+#include <utils/String8.h>
 
 namespace android {
-key_serial_t GetKeyringId(const std::string& keyring_desc);
-}  // namespace android
 
-#endif  // _MINI_KEYCTL_MINI_KEYCTL_UTILS_H_
+String8 sanitizeSerialNumber(const std::string& serial);
+
+}  // namespace android
diff --git a/healthd/battery_monitor_test.cpp b/healthd/battery_monitor_test.cpp
new file mode 100644
index 0000000000..e8a06e1eb6
--- /dev/null
+++ b/healthd/battery_monitor_test.cpp
@@ -0,0 +1,27 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "battery_monitor_internal.h"
+
+#include <gtest/gtest.h>
+
+using namespace android;
+
+TEST(BatteryMonitor, SanitizeSerialNumber) {
+    ASSERT_EQ(sanitizeSerialNumber("abcd1234"), "ABCD1234");
+    ASSERT_EQ(sanitizeSerialNumber("ABCD1234"), "ABCD1234");
+    ASSERT_EQ(sanitizeSerialNumber("H+-"), "H2B2D");
+}
diff --git a/healthd/include/healthd/BatteryMonitor.h b/healthd/include/healthd/BatteryMonitor.h
index b30458d3cc..5fbf68fe03 100644
--- a/healthd/include/healthd/BatteryMonitor.h
+++ b/healthd/include/healthd/BatteryMonitor.h
@@ -74,8 +74,6 @@ class BatteryMonitor {
     status_t getProperty(int id, struct BatteryProperty *val);
     void dumpState(int fd);
 
-    android::hardware::health::V1_0::HealthInfo getHealthInfo_1_0() const;
-    android::hardware::health::V2_0::HealthInfo getHealthInfo_2_0() const;
     android::hardware::health::V2_1::HealthInfo getHealthInfo_2_1() const;
     const aidl::android::hardware::health::HealthInfo& getHealthInfo() const;
 
diff --git a/healthd/include/healthd/BatteryMonitor_v1.h b/healthd/include/healthd/BatteryMonitor_v1.h
index 49f6f9d4b7..d939a28f5b 100644
--- a/healthd/include/healthd/BatteryMonitor_v1.h
+++ b/healthd/include/healthd/BatteryMonitor_v1.h
@@ -63,8 +63,6 @@ class BatteryMonitor {
     status_t getProperty(int id, struct BatteryProperty *val);
     void dumpState(int fd);
 
-    android::hardware::health::V1_0::HealthInfo getHealthInfo_1_0() const;
-    android::hardware::health::V2_0::HealthInfo getHealthInfo_2_0() const;
     android::hardware::health::V2_1::HealthInfo getHealthInfo_2_1() const;
     const aidl::android::hardware::health::HealthInfo& getHealthInfo() const;
 
diff --git a/healthd/include/healthd/healthd.h b/healthd/include/healthd/healthd.h
index 688e458e7e..e5d5ff7fcb 100644
--- a/healthd/include/healthd/healthd.h
+++ b/healthd/include/healthd/healthd.h
@@ -78,6 +78,7 @@ struct healthd_config {
     android::String8 batteryFirstUsageDatePath;
     android::String8 chargingStatePath;
     android::String8 chargingPolicyPath;
+    android::String8 batterySerialPath;
 
     int (*energyCounter)(int64_t *);
     int boot_min_cap;
diff --git a/init/Android.bp b/init/Android.bp
index ed8123e380..aa0c283b65 100644
--- a/init/Android.bp
+++ b/init/Android.bp
@@ -82,6 +82,7 @@ init_device_sources = [
     "switch_root.cpp",
     "tradeinmode.cpp",
     "uevent_listener.cpp",
+    "uevent_dependency_graph.cpp",
     "ueventd.cpp",
     "ueventd_parser.cpp",
 ]
@@ -163,6 +164,7 @@ libinit_cc_defaults {
         },
     },
     static_libs: [
+        "libapexd_flags",
         "libavb",
         "libavf_cc_flags",
         "libbootloader_message",
@@ -177,7 +179,6 @@ libinit_cc_defaults {
         "libsnapshot_cow",
         "libsnapshot_init",
         "libxml2",
-        "lib_apex_manifest_proto_lite",
         "update_metadata-protos",
         "libgenfslabelsversion.ffi",
     ],
@@ -368,6 +369,7 @@ init_first_stage_cc_defaults {
     ],
 
     static_libs: [
+        "libapexd_flags",
         "libfs_avb",
         "libavf_cc_flags",
         "libfs_mgr",
@@ -405,6 +407,7 @@ init_first_stage_cc_defaults {
         "-Wall",
         "-Wextra",
         "-Wno-unused-parameter",
+        "-Wexit-time-destructors",
         "-Werror",
         "-DALLOW_FIRST_STAGE_CONSOLE=0",
         "-DALLOW_LOCAL_PROP_OVERRIDE=0",
@@ -512,6 +515,8 @@ cc_test {
         "service_test.cpp",
         "subcontext_test.cpp",
         "tokenizer_test.cpp",
+        "uevent_dependency_graph.cpp",
+        "uevent_dependency_graph_test.cpp",
         "ueventd_parser_test.cpp",
         "ueventd_test.cpp",
         "util_test.cpp",
@@ -599,18 +604,18 @@ cc_defaults {
         "-Werror",
     ],
     static_libs: [
-        "libbase",
         "libfstab",
-        "libselinux",
         "libpropertyinfoserializer",
         "libpropertyinfoparser",
     ],
     whole_static_libs: ["libcap"],
     shared_libs: [
+        "libbase",
         "libcutils",
         "liblog",
         "libprocessgroup",
         "libprotobuf-cpp-lite",
+        "libselinux",
     ],
     proto: {
         type: "lite",
diff --git a/init/README.md b/init/README.md
index 6a66f14396..a2e1a8e61a 100644
--- a/init/README.md
+++ b/init/README.md
@@ -716,12 +716,11 @@ provides the `aidl_lazy_test_1` interface.
   _options_ include "barrier=1", "noauto\_da\_alloc", "discard", ... as
   a comma separated string, e.g. barrier=1,noauto\_da\_alloc
 
-`perform_apex_config [--bootstrap]`
+`perform_apex_config`
 > Performs tasks after APEXes are mounted. For example, creates data directories
   for the mounted APEXes, parses config file(s) from them, and updates linker
   configurations. Intended to be used only once when apexd notifies the mount
   event by setting `apexd.status` to ready.
-  Use --bootstrap when invoking in the bootstrap mount namespace.
 
 `restart [--only-if-running] <service>`
 > Stops and restarts a running service, does nothing if the service is currently
diff --git a/init/README.ueventd.md b/init/README.ueventd.md
index 0e84c6f5fc..ba7a5b11d3 100644
--- a/init/README.ueventd.md
+++ b/init/README.ueventd.md
@@ -211,3 +211,31 @@ For example
     parallel_restorecon_dir /sys/devices
     parallel_restorecon_dir /sys/devices/platform
     parallel_restorecon_dir /sys/devices/platform/soc
+
+## Parallel uevent main loop
+--------
+After coldboot is complete, ueventd enters its main loop. The main loop handles all uevents that
+happen after coldboot. This main loop is not parallelized by default unlike the coldboot process
+described above. You can optionally parallelize this main loop by.
+
+    parallel_ueventd_main_loop enabled
+
+By default this spawns the same number of threads as the number of the logical cores. You can
+optionally tweak the number of workers.
+
+    parallel_ueventd_main_loop_max_workers 2
+
+There are two motivations you might want to try parallelizing the main loop; boot time and kernel
+module initialization time.
+
+The main loop handles events that occur when you modify device states (e.g. plug/unplug a new
+device), but it also processes uevents necessary for the boot process such as uevents related to
+`/data` partitions. These uevents block the boot process, so parallelizing the main loop might help
+the boot time for the same reason as parallel restorecon does in coldboot (e.g. labeling sysfs nodes
+that cannot be migrated to genfscon).
+
+Some kernel modules take a perceptible time for initialization. If a device is supposed to
+initialize multiple number of such kernel modules, parallelizing them reduces the total
+initialization time. In addition, these kernel module initializations can block following events for
+`/data` block devices until they complete. In that case, this also contributes to making the boot
+time faster.
diff --git a/init/apex_init_util.cpp b/init/apex_init_util.cpp
index 809c805c42..30bcf09447 100644
--- a/init/apex_init_util.cpp
+++ b/init/apex_init_util.cpp
@@ -33,6 +33,11 @@
 #include "service_list.h"
 #include "util.h"
 
+static constexpr const char* kCompressedApexSysprop = "apexd.config.compressed_apex";
+static constexpr const char* kMetadataApexDir = "/metadata/apex";
+static constexpr const char* kMetadataApexConfigMountBeforeData =
+        "/metadata/apex/config/mount_before_data";
+
 namespace android {
 namespace init {
 
@@ -142,9 +147,9 @@ Result<void> ParseRcScriptsFromApex(const std::string& apex_name) {
     return ParseRcScripts(configs);
 }
 
-Result<void> ParseRcScriptsFromAllApexes(bool bootstrap) {
+Result<void> ParseRcScriptsFromAllApexes(bool is_default_mnt_ns) {
     std::set<std::string> skip_apexes;
-    if (!bootstrap) {
+    if (is_default_mnt_ns) {
         // In case we already loaded config files from bootstrap APEXes, we need to avoid loading
         // them again. We can get the list of bootstrap APEXes by scanning /bootstrap-apex and
         // skip them in CollectRcScriptsFromApex.
@@ -154,5 +159,24 @@ Result<void> ParseRcScriptsFromAllApexes(bool bootstrap) {
     return ParseRcScripts(configs);
 }
 
+bool CanMountApexBeforeData() {
+    // For the first boot after factory reset: since there's no data apexes, init can decide by
+    //     looking up "apexd.config.compressed_apex". If there's no compressed apexes, apexd should
+    //     be able to mount apexes before data.
+    //
+    // Otherwise, apexd had a chance to decide whether it can mount apexes before data partition.
+    //     Hence, init just looks up /metadata/apex/config/mount_before_data which is created by
+    //     apexd.
+
+    // Check /metadata/apex to see if this is the first boot. If it doesn't exist, this is the first
+    // boot.
+    bool first_boot = access(kMetadataApexDir, F_OK) != 0;
+    if (first_boot) {
+        return !base::GetBoolProperty(kCompressedApexSysprop, true);
+    } else {
+        return access(kMetadataApexConfigMountBeforeData, F_OK) == 0;
+    }
+}
+
 }  // namespace init
 }  // namespace android
diff --git a/init/apex_init_util.h b/init/apex_init_util.h
index 75dfee1ae4..3f4d9372d0 100644
--- a/init/apex_init_util.h
+++ b/init/apex_init_util.h
@@ -32,7 +32,10 @@ std::set<std::string> GetApexListFrom(const std::string& apex_dir);
 Result<void> ParseRcScriptsFromApex(const std::string& apex_name);
 
 // Parse all RC scripts for all apexes under /apex.
-Result<void> ParseRcScriptsFromAllApexes(bool bootstrap);
+Result<void> ParseRcScriptsFromAllApexes(bool is_default_mnt_ns);
+
+// Checks if apexd can mount apexes before data partition
+bool CanMountApexBeforeData();
 
 }  // namespace init
 }  // namespace android
diff --git a/init/block_dev_initializer.cpp b/init/block_dev_initializer.cpp
index deb68e9ac2..b1ebefacf7 100644
--- a/init/block_dev_initializer.cpp
+++ b/init/block_dev_initializer.cpp
@@ -79,6 +79,11 @@ bool BlockDevInitializer::InitBootDevicesFromPartUuid() {
     return true;
 }
 
+// Second_stage_init requires loop-control before ueventd starts.
+void BlockDevInitializer::InitLoopDevices() {
+    (void)InitMiscDevice("loop-control");
+}
+
 bool BlockDevInitializer::InitDeviceMapper() {
     return InitMiscDevice("device-mapper");
 }
diff --git a/init/block_dev_initializer.h b/init/block_dev_initializer.h
index 25107c97f5..739a095519 100644
--- a/init/block_dev_initializer.h
+++ b/init/block_dev_initializer.h
@@ -36,6 +36,7 @@ class BlockDevInitializer final {
     bool InitDmDevice(const std::string& device);
     bool InitPlatformDevice(const std::string& device);
     bool InitHvcDevice(const std::string& device);
+    void InitLoopDevices();
 
   private:
     ListenerAction HandleUevent(const Uevent& uevent, std::set<std::string>* devices);
diff --git a/init/bootchart.cpp b/init/bootchart.cpp
index f46fb09938..af7b889e60 100644
--- a/init/bootchart.cpp
+++ b/init/bootchart.cpp
@@ -47,8 +47,8 @@ namespace init {
 
 static std::thread* g_bootcharting_thread;
 
-static std::mutex g_bootcharting_finished_mutex;
-static std::condition_variable g_bootcharting_finished_cv;
+[[clang::no_destroy]] static std::mutex g_bootcharting_finished_mutex;
+[[clang::no_destroy]] static std::condition_variable g_bootcharting_finished_cv;
 static bool g_bootcharting_finished;
 
 static long long get_uptime_jiffies() {
diff --git a/init/builtins.cpp b/init/builtins.cpp
index 38aed9c64c..1f1b914876 100644
--- a/init/builtins.cpp
+++ b/init/builtins.cpp
@@ -142,7 +142,7 @@ inline ErrorIgnoreEnoent ErrnoErrorIgnoreEnoent() {
     return ErrorIgnoreEnoent(errno);
 }
 
-std::vector<std::string> late_import_paths;
+[[clang::no_destroy]] std::vector<std::string> late_import_paths;
 
 static constexpr std::chrono::nanoseconds kCommandRetryTimeout = 5s;
 
@@ -1187,14 +1187,6 @@ static Result<void> GenerateLinkerConfiguration() {
         return ErrnoError() << "failed to execute linkerconfig";
     }
 
-    auto current_mount_ns = GetCurrentMountNamespace();
-    if (!current_mount_ns.ok()) {
-        return current_mount_ns.error();
-    }
-    if (*current_mount_ns == NS_DEFAULT) {
-        SetDefaultMountNamespaceReady();
-    }
-
     LOG(INFO) << "linkerconfig generated " << linkerconfig_target
               << " with mounted APEX modules info";
 
@@ -1214,9 +1206,6 @@ static Result<void> MountLinkerConfigForDefaultNamespace() {
 
     return {};
 }
-static Result<void> do_update_linker_config(const BuiltinArguments&) {
-    return GenerateLinkerConfiguration();
-}
 
 /*
  * Creates a directory under /data/misc/apexdata/ for each APEX.
@@ -1233,30 +1222,34 @@ static void create_apex_data_dirs() {
 }
 
 static Result<void> do_perform_apex_config(const BuiltinArguments& args) {
-    bool bootstrap = false;
-    if (args.size() == 2) {
-        if (args[1] != "--bootstrap") {
-            return Error() << "Unexpected argument: " << args[1];
-        }
-        bootstrap = true;
-    }
-
-    if (!bootstrap) {
+    // Do create apex data directories if /data/misc/apexdata exists
+    if (access("/data/misc/apexdata", 0) == 0) {
         create_apex_data_dirs();
     }
-
-    auto parse_result = ParseRcScriptsFromAllApexes(bootstrap);
-    if (!parse_result.ok()) {
-        return parse_result.error();
+    constexpr const char* kApexInfolist = "/apex/apex-info-list.xml";
+    if (selinux_android_restorecon(kApexInfolist, 0) == -1) {
+        PLOG(ERROR) << "restorecon failed: " << kApexInfolist;
     }
 
-    auto update_linker_config = do_update_linker_config(args);
-    if (!update_linker_config.ok()) {
-        return update_linker_config.error();
-    }
+    MountNamespace current_mnt_ns = GetCurrentMountNamespace().value_or(NS_BOOTSTRAP);
+    // We don't want to parse the same apexes twice in the same mount namespace.
+    static std::map<MountNamespace, bool> apex_parsed;
+    if (!std::exchange(apex_parsed[current_mnt_ns], true)) {
+        if (auto st = ParseRcScriptsFromAllApexes(current_mnt_ns == NS_DEFAULT); !st.ok()) {
+            LOG(ERROR) << st.error();
+        }
+        if (auto st = GenerateLinkerConfiguration(); !st.ok()) {
+            LOG(ERROR) << st.error();
+        }
 
-    if (!bootstrap) {
-        ServiceList::GetInstance().StartDelayedServices();
+        // Once the linker configuration is generated for the default mount namespace, processes can
+        // be started. Note that if there's only a single mount namespace, the bootstrap mount
+        // namespace is equal to the default mount namespace.
+        if (current_mnt_ns == NS_DEFAULT || !NeedsTwoMountNamespaces()) {
+            SetDefaultMountNamespaceReady();
+            // Now, we can start delayed services as well.
+            ServiceList::GetInstance().StartDelayedServices();
+        }
     }
     return {};
 }
@@ -1322,7 +1315,6 @@ const BuiltinFunctionMap& GetBuiltinFunctionMap() {
         {"perform_apex_config",     {0,     1,    {false,  do_perform_apex_config}}},
         {"umount",                  {1,     1,    {false,  do_umount}}},
         {"umount_all",              {0,     1,    {false,  do_umount_all}}},
-        {"update_linker_config",    {0,     0,    {false,  do_update_linker_config}}},
         {"readahead",               {1,     2,    {true,   do_readahead}}},
         {"restart",                 {1,     2,    {false,  do_restart}}},
         {"restorecon",              {1,     kMax, {true,   do_restorecon}}},
diff --git a/init/capabilities.cpp b/init/capabilities.cpp
index 0e2cd2acc3..eb6dadd7a6 100644
--- a/init/capabilities.cpp
+++ b/init/capabilities.cpp
@@ -27,7 +27,7 @@
 namespace android {
 namespace init {
 
-static const std::map<std::string, int> cap_map = {
+[[clang::no_destroy]] static const std::map<std::string, int> cap_map = {
         CAP_MAP_ENTRY(CHOWN),
         CAP_MAP_ENTRY(DAC_OVERRIDE),
         CAP_MAP_ENTRY(DAC_READ_SEARCH),
diff --git a/init/devices.cpp b/init/devices.cpp
index cead726167..c16620b4dd 100644
--- a/init/devices.cpp
+++ b/init/devices.cpp
@@ -24,6 +24,7 @@
 #include <chrono>
 #include <filesystem>
 #include <memory>
+#include <mutex>
 #include <string>
 #include <string_view>
 #include <thread>
@@ -240,7 +241,7 @@ bool DeviceHandler::IsBootDevice(const Uevent& uevent) const {
 }
 
 std::string DeviceHandler::GetPartitionNameForDevice(const std::string& query_device) {
-    static const auto partition_map = [] {
+    [[clang::no_destroy]] static const auto partition_map = [] {
         std::vector<std::pair<std::string, std::string>> partition_map;
         auto parser = [&partition_map](const std::string& key, const std::string& value) {
             if (key != "androidboot.partition_map") {
@@ -362,6 +363,7 @@ void DeviceHandler::TrackDeviceUevent(const Uevent& uevent) {
     std::string device;
     if (!Realpath(path, &device)) return;
 
+    std::lock_guard<std::mutex> lock(device_update_lock_);
     tracked_uevents_.emplace_back(uevent, device);
 }
 
@@ -642,7 +644,8 @@ void DeviceHandler::HandleDevice(const std::string& action, const std::string& d
 
 void DeviceHandler::HandleAshmemUevent(const Uevent& uevent) {
     if (uevent.device_name == "ashmem") {
-        static const std::string boot_id_path = "/proc/sys/kernel/random/boot_id";
+        [[clang::no_destroy]] static const std::string boot_id_path =
+                "/proc/sys/kernel/random/boot_id";
         std::string boot_id;
         if (!ReadFileToString(boot_id_path, &boot_id)) {
             PLOG(ERROR) << "Cannot duplicate ashmem device node. Failed to read " << boot_id_path;
@@ -732,10 +735,14 @@ void DeviceHandler::HandleUevent(const Uevent& uevent) {
     }
 
     if (uevent.action == "bind") {
+        std::lock_guard<std::mutex> lock(device_update_lock_);
+
         bound_drivers_[uevent.path] = uevent.driver;
         HandleBindInternal(uevent.driver, "add", uevent);
         return;
     } else if (uevent.action == "unbind") {
+        std::lock_guard<std::mutex> lock(device_update_lock_);
+
         if (bound_drivers_.count(uevent.path) == 0) return;
         HandleBindInternal(bound_drivers_[uevent.path], "remove", uevent);
 
@@ -810,8 +817,8 @@ DeviceHandler::DeviceHandler(std::vector<Permissions> dev_permissions,
       sysfs_permissions_(std::move(sysfs_permissions)),
       drivers_(std::move(drivers)),
       subsystems_(std::move(subsystems)),
-      boot_devices_(std::move(boot_devices)),
       boot_part_uuid_(boot_part_uuid),
+      boot_devices_(std::move(boot_devices)),
       skip_restorecon_(skip_restorecon),
       sysfs_mount_point_("/sys") {
     // If both a boot partition UUID and a list of boot devices are
diff --git a/init/devices.h b/init/devices.h
index 69a2449788..8ddf8b04ed 100644
--- a/init/devices.h
+++ b/init/devices.h
@@ -22,11 +22,13 @@
 
 #include <algorithm>
 #include <map>
+#include <mutex>
 #include <set>
 #include <string>
 #include <vector>
 
 #include <android-base/file.h>
+#include <android-base/thread_annotations.h>
 #include <selinux/label.h>
 
 #include "uevent.h"
@@ -135,7 +137,7 @@ class DeviceHandler : public UeventHandler {
     virtual ~DeviceHandler() = default;
 
     bool CheckUeventForBootPartUuid(const Uevent& uevent);
-    void HandleUevent(const Uevent& uevent) override;
+    void HandleUevent(const Uevent& uevent) override EXCLUDES(device_update_lock_);
 
     // `androidboot.partition_map` allows associating a partition name for a raw block device
     // through a comma separated and semicolon deliminated list. For example,
@@ -169,21 +171,25 @@ class DeviceHandler : public UeventHandler {
     void FixupSysPermissions(const std::string& upath, const std::string& subsystem) const;
     void HandleAshmemUevent(const Uevent& uevent);
 
-    void TrackDeviceUevent(const Uevent& uevent);
-    void HandleBindInternal(std::string driver_name, std::string action, const Uevent& uevent);
+    void TrackDeviceUevent(const Uevent& uevent) EXCLUDES(device_update_lock_);
+    void HandleBindInternal(std::string driver_name, std::string action, const Uevent& uevent)
+            EXCLUSIVE_LOCKS_REQUIRED(device_update_lock_);
 
-    std::vector<Permissions> dev_permissions_;
-    std::vector<SysfsPermissions> sysfs_permissions_;
-    std::vector<Subsystem> drivers_;
-    std::vector<Subsystem> subsystems_;
+    const std::vector<Permissions> dev_permissions_;
+    const std::vector<SysfsPermissions> sysfs_permissions_;
+    const std::vector<Subsystem> drivers_;
+    const std::vector<Subsystem> subsystems_;
+    const std::string boot_part_uuid_;
+
+    // These non const members are modified only at initialization or test
     std::set<std::string> boot_devices_;
-    std::string boot_part_uuid_;
     bool found_boot_part_uuid_;
     bool skip_restorecon_;
     std::string sysfs_mount_point_;
 
-    std::vector<TrackedUevent> tracked_uevents_;
-    std::map<std::string, std::string> bound_drivers_;
+    std::mutex device_update_lock_;
+    std::vector<TrackedUevent> tracked_uevents_ GUARDED_BY(device_update_lock_);
+    std::map<std::string, std::string> bound_drivers_ GUARDED_BY(device_update_lock_);
 };
 
 // Exposed for testing
diff --git a/init/firmware_handler.cpp b/init/firmware_handler.cpp
index dcfda52d67..031dbfb7a1 100644
--- a/init/firmware_handler.cpp
+++ b/init/firmware_handler.cpp
@@ -134,9 +134,17 @@ ExternalFirmwareHandler::ExternalFirmwareHandler(std::string devpath, uid_t uid,
     : ExternalFirmwareHandler(devpath, uid, 0, handler_path) {}
 
 FirmwareHandler::FirmwareHandler(std::vector<std::string> firmware_directories,
-                                 std::vector<ExternalFirmwareHandler> external_firmware_handlers)
+                                 std::vector<ExternalFirmwareHandler> external_firmware_handlers,
+                                 bool serial_handler_after_coldboot)
     : firmware_directories_(std::move(firmware_directories)),
-      external_firmware_handlers_(std::move(external_firmware_handlers)) {}
+      external_firmware_handlers_(std::move(external_firmware_handlers)),
+      serial_handler_after_coldboot_(serial_handler_after_coldboot) {}
+
+void FirmwareHandler::ColdbootDone() {
+    if (serial_handler_after_coldboot_) {
+        enables_parallel_handlers_ = false;
+    }
+}
 
 std::string FirmwareHandler::GetFirmwarePath(const Uevent& uevent) const {
     for (const auto& external_handler : external_firmware_handlers_) {
@@ -265,21 +273,31 @@ bool FirmwareHandler::ForEachFirmwareDirectory(
     return false;
 }
 
+void FirmwareHandler::HandleUeventInternal(const Uevent& uevent) const {
+    Timer t;
+    auto firmware = GetFirmwarePath(uevent);
+    ProcessFirmwareEvent(uevent.path, firmware);
+    LOG(INFO) << "loading " << uevent.path << " took " << t;
+}
+
 void FirmwareHandler::HandleUevent(const Uevent& uevent) {
     if (uevent.subsystem != "firmware" || uevent.action != "add") return;
 
-    // Loading the firmware in a child means we can do that in parallel...
-    auto pid = fork();
-    if (pid == -1) {
-        PLOG(ERROR) << "could not fork to process firmware event for " << uevent.firmware;
-    }
-    if (pid == 0) {
-        Timer t;
-        auto firmware = GetFirmwarePath(uevent);
-        ProcessFirmwareEvent(uevent.path, firmware);
-        LOG(INFO) << "loading " << uevent.path << " took " << t;
-        _exit(EXIT_SUCCESS);
+    if (enables_parallel_handlers_) {
+        // Loading the firmware in a child means we can do that in parallel...
+        auto pid = fork();
+        if (pid == -1) {
+            PLOG(ERROR) << "could not fork to process firmware event for " << uevent.firmware;
+        } else if (pid == 0) {
+            // Child does the actual work
+            HandleUeventInternal(uevent);
+            _exit(EXIT_SUCCESS);
+        } else {
+            // The main process returns here. Let the child do the actual work in parallel.
+            return;
+        }
     }
+    HandleUeventInternal(uevent);
 }
 
 }  // namespace init
diff --git a/init/firmware_handler.h b/init/firmware_handler.h
index e5d3538096..fd25164329 100644
--- a/init/firmware_handler.h
+++ b/init/firmware_handler.h
@@ -45,21 +45,26 @@ struct ExternalFirmwareHandler {
 class FirmwareHandler : public UeventHandler {
   public:
     FirmwareHandler(std::vector<std::string> firmware_directories,
-                    std::vector<ExternalFirmwareHandler> external_firmware_handlers);
+                    std::vector<ExternalFirmwareHandler> external_firmware_handlers,
+                    bool serial_handler_after_coldboot);
     virtual ~FirmwareHandler() = default;
 
     void HandleUevent(const Uevent& uevent) override;
+    void ColdbootDone() override;
 
   private:
     friend void FirmwareTestWithExternalHandler(const std::string& test_name,
                                                 bool expect_new_firmware);
+    void HandleUeventInternal(const Uevent& uevent) const;
 
     std::string GetFirmwarePath(const Uevent& uevent) const;
     void ProcessFirmwareEvent(const std::string& path, const std::string& firmware) const;
     bool ForEachFirmwareDirectory(std::function<bool(const std::string&)> handler) const;
 
-    std::vector<std::string> firmware_directories_;
-    std::vector<ExternalFirmwareHandler> external_firmware_handlers_;
+    std::atomic_bool enables_parallel_handlers_ = true;
+    const std::vector<std::string> firmware_directories_;
+    const std::vector<ExternalFirmwareHandler> external_firmware_handlers_;
+    const bool serial_handler_after_coldboot_ = true;
 };
 
 }  // namespace init
diff --git a/init/firmware_handler_test.cpp b/init/firmware_handler_test.cpp
index f6e75b01ff..10a06fcb41 100644
--- a/init/firmware_handler_test.cpp
+++ b/init/firmware_handler_test.cpp
@@ -35,7 +35,8 @@ void FirmwareTestWithExternalHandler(const std::string& test_name, bool expect_n
     auto external_firmware_handler = ExternalFirmwareHandler(
             "/devices/led/firmware/test_firmware001.bin", getuid(), test_path);
 
-    auto firmware_handler = FirmwareHandler({"/test"}, {external_firmware_handler});
+    auto firmware_handler = FirmwareHandler({"/test"}, {external_firmware_handler},
+                                            /*serial_handler_after_cold_boot=*/false);
 
     auto uevent = Uevent{
             .path = "/devices/led/firmware/test_firmware001.bin",
diff --git a/init/first_stage_mount.cpp b/init/first_stage_mount.cpp
index 6b413f6d65..472ef48f2e 100644
--- a/init/first_stage_mount.cpp
+++ b/init/first_stage_mount.cpp
@@ -35,6 +35,7 @@
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <android/avf_cc_flags.h>
+#include <com_android_apex_flags.h>
 #include <fs_avb/fs_avb.h>
 #include <fs_mgr.h>
 #include <fs_mgr_dm_linear.h>
@@ -113,7 +114,6 @@ class FirstStageMountVBootV2 : public FirstStageMount {
 
     bool InitAvbHandle();
 
-    bool need_dm_verity_;
     bool dsu_not_on_userdata_ = false;
     bool use_snapuserd_ = false;
 
@@ -309,6 +309,11 @@ bool FirstStageMountVBootV2::InitDevices() {
             return false;
         }
     }
+
+    if constexpr (com::android::apex::flags::mount_before_data()) {
+        block_dev_init_.InitLoopDevices();
+    }
+
     return true;
 }
 
@@ -369,7 +374,7 @@ bool FirstStageMountVBootV2::CreateLogicalPartitions() {
         return false;
     }
 
-    if (SnapshotManager::IsSnapshotManagerNeeded()) {
+    if (!IsMicrodroid() && SnapshotManager::IsSnapshotManagerNeeded()) {
         auto init_devices = [this](const std::string& device) -> bool {
             if (android::base::StartsWith(device, "/dev/block/dm-")) {
                 return block_dev_init_.InitDmDevice(device);
@@ -726,7 +731,7 @@ void FirstStageMountVBootV2::UseDsuIfPresent() {
 }
 
 FirstStageMountVBootV2::FirstStageMountVBootV2(Fstab fstab)
-    : need_dm_verity_(false), fstab_(std::move(fstab)), avb_handle_(nullptr) {
+    : fstab_(std::move(fstab)), avb_handle_(nullptr) {
     super_partition_name_ = fs_mgr_get_super_partition_name();
 
     std::string device_tree_vbmeta_parts;
@@ -750,14 +755,14 @@ FirstStageMountVBootV2::FirstStageMountVBootV2(Fstab fstab)
 }
 
 bool FirstStageMountVBootV2::GetDmVerityDevices(std::set<std::string>* devices) {
-    need_dm_verity_ = false;
+    bool need_dm_verity = false;
 
     std::set<std::string> logical_partitions;
 
     // fstab_rec->blk_device has A/B suffix.
     for (const auto& fstab_entry : fstab_) {
         if (fstab_entry.fs_mgr_flags.avb) {
-            need_dm_verity_ = true;
+            need_dm_verity = true;
         }
         // Skip pseudo filesystems.
         if (fstab_entry.fs_type == "overlay") {
@@ -773,7 +778,7 @@ bool FirstStageMountVBootV2::GetDmVerityDevices(std::set<std::string>* devices)
 
     // Any partitions needed for verifying the partitions used in first stage mount, e.g. vbmeta
     // must be provided as vbmeta_partitions.
-    if (need_dm_verity_) {
+    if (need_dm_verity) {
         if (vbmeta_partitions_.empty()) {
             LOG(ERROR) << "Missing vbmeta partitions";
             return false;
diff --git a/init/fuzzer/init_ueventHandler_fuzzer.cpp b/init/fuzzer/init_ueventHandler_fuzzer.cpp
index b6d5f8a42b..5f48f13633 100644
--- a/init/fuzzer/init_ueventHandler_fuzzer.cpp
+++ b/init/fuzzer/init_ueventHandler_fuzzer.cpp
@@ -104,7 +104,8 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
                         firmware_directories.push_back(fdp.ConsumeRandomLengthString(kMaxBytes));
                     }
                     FirmwareHandler firmware_handler =
-                            FirmwareHandler(firmware_directories, external_handlers);
+                            FirmwareHandler(firmware_directories, external_handlers,
+                                            /*serial_handler_after_coldboot=*/false);
                     Uevent uevent = CreateUevent(&fdp);
                     if (fdp.ConsumeBool() && uevent.path.size() != 0 &&
                         uevent.path.find(kPath) == 0) {
diff --git a/init/host_init_verifier.cpp b/init/host_init_verifier.cpp
index 287857a5cd..7b8ca91efb 100644
--- a/init/host_init_verifier.cpp
+++ b/init/host_init_verifier.cpp
@@ -59,10 +59,10 @@ using android::base::Split;
 using android::properties::ParsePropertyInfoFile;
 using android::properties::PropertyInfoEntry;
 
-static std::vector<std::string> passwd_files;
+[[clang::no_destroy]] static std::vector<std::string> passwd_files;
 
 // NOTE: Keep this in sync with the order used by init.cpp LoadBootScripts()
-static const std::vector<std::string> partition_search_order =
+[[clang::no_destroy]] static const std::vector<std::string> partition_search_order =
         std::vector<std::string>({"system", "system_ext", "odm", "vendor", "product"});
 
 static std::vector<std::pair<std::string, int>> GetVendorPasswd(const std::string& passwd_file) {
diff --git a/init/init.cpp b/init/init.cpp
index f6b2941365..aaf00e30bd 100644
--- a/init/init.cpp
+++ b/init/init.cpp
@@ -50,9 +50,11 @@
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <android-base/thread_annotations.h>
+#include <com_android_apex_flags.h>
 #include <fs_avb/fs_avb.h>
 #include <fs_mgr_vendor_overlay.h>
 #include <libavb/libavb.h>
+#include <libdm/loop_control.h>
 #include <libgsi/libgsi.h>
 #include <libsnapshot/snapshot.h>
 #include <logwrap/logwrap.h>
@@ -128,8 +130,8 @@ struct PendingControlMessage {
     pid_t pid;
     int fd;
 };
-static std::mutex pending_control_messages_lock;
-static std::queue<PendingControlMessage> pending_control_messages;
+[[clang::no_destroy]] static std::mutex pending_control_messages_lock;
+[[clang::no_destroy]] static std::queue<PendingControlMessage> pending_control_messages;
 
 // Init epolls various FDs to wait for various inputs.  It previously waited on property changes
 // with a blocking socket that contained the information related to the change, however, it was easy
@@ -236,7 +238,7 @@ void ResetWaitForProp() {
     prop_waiter_state.ResetWaitForProp();
 }
 
-static class ShutdownState {
+[[clang::no_destroy]] static class ShutdownState {
   public:
     void TriggerShutdown(const std::string& command) {
         // We can't call HandlePowerctlMessage() directly in this function,
@@ -369,6 +371,12 @@ void PropertyChanged(const std::string& name, const std::string& value) {
     // commands to be executed.
     if (name == "sys.powerctl") {
         trigger_shutdown(value);
+    } else if (name == "sys.shutdown.requested") {
+        // Higher layers send "sys.shutdown.requested" before they're ready to ask the init
+        // system to shutdown via the above "sys.powerctl". Use the early warning to start
+        // the watchdog so that if higher layers hang before setting "sys.powerctl" we
+        // don't end up hung.
+        HandleShutdownRequestedMessage(value);
     }
 
     if (property_triggers_enabled) {
@@ -507,6 +515,7 @@ using ControlMessageFunction = std::function<Result<void>(Service*)>;
 
 static const std::map<std::string, ControlMessageFunction, std::less<>>& GetControlMessageMap() {
     // clang-format off
+    [[clang::no_destroy]]
     static const std::map<std::string, ControlMessageFunction, std::less<>> control_message_functions = {
         {"sigstop_on",        [](auto* service) { service->set_sigstop(true); return Result<void>{}; }},
         {"sigstop_off",       [](auto* service) { service->set_sigstop(false); return Result<void>{}; }},
@@ -853,6 +862,22 @@ static void MountExtraFilesystems() {
 #undef CHECKCALL
 }
 
+static void InitExtraDevices() {
+    if constexpr (com::android::apex::flags::mount_before_data()) {
+        // Pre-create a bunch of loop devices to accelerate apexd later. This effectively overrides
+        // CONFIG_BLK_DEV_LOOP_MIN_COUNT. 128 loop devices should be enough for now because most
+        // devices have < 100 apexes.
+        constexpr int kMaxLoopDevices = 128;
+        // Fire off a thread to pre-create the loop devices to avoid blocking the init.
+        std::thread([]() {
+            dm::LoopControl loop_control;
+            for (int i = 0; i < kMaxLoopDevices; i++) {
+                (void)loop_control.Add(i);
+            }
+        }).detach();
+    }
+}
+
 static void RecordStageBoottimes(const boot_clock::time_point& second_stage_start_time) {
     int64_t first_stage_start_time_ns = -1;
     if (auto first_stage_start_time_str = getenv(kEnvFirstStageStartedAt);
@@ -1048,6 +1073,11 @@ int SecondStageMain(int argc, char** argv) {
     InstallInitNotifier(&epoll);
     StartPropertyService(&property_fd);
 
+    // Initialize extra devices required during second stage init.
+    // This may spawn threads for background work. Hence, this should be after
+    // InstallSignalFdHandler() which needs to be called before spawning any threads.
+    InitExtraDevices();
+
     // If boot_timeout property has been set in a debug build, start the boot monitor
     if (GetBoolProperty("ro.debuggable", false)) {
         int timeout = GetIntProperty("ro.boot.boot_timeout", 0);
@@ -1184,6 +1214,10 @@ int SecondStageMain(int argc, char** argv) {
         if (next_action_time != far_future) {
             epoll_timeout = std::chrono::ceil<std::chrono::milliseconds>(
                     std::max(next_action_time - boot_clock::now(), 0ns));
+        } else {
+            // If we are unlikely to do anything soon, release memory from the
+            // allocator.
+            mallopt(M_PURGE_ALL, 0);
         }
         auto epoll_result = epoll.Wait(epoll_timeout);
         if (!epoll_result.ok()) {
diff --git a/init/init_test.cpp b/init/init_test.cpp
index f280de96d1..cf7beaf614 100644
--- a/init/init_test.cpp
+++ b/init/init_test.cpp
@@ -175,6 +175,35 @@ execute_third
     EXPECT_EQ(3, num_executed);
 }
 
+TEST(init, IgnoreDuplicateService) {
+    std::string init_script = R"init(
+service A something
+    class first
+    user nobody
+
+service A something
+    class second
+    user nobody
+
+# parser should keep parsing
+service B /path/to/B
+    user nobody
+
+)init";
+
+    ActionManager action_manager;
+    ServiceList service_list;
+    TestInitText(init_script, BuiltinFunctionMap(), {}, &action_manager, &service_list);
+
+    auto service_a = service_list.FindService("A");
+    ASSERT_NE(nullptr, service_a);
+    EXPECT_EQ(std::set<std::string>({"first"}), service_a->classnames());
+
+    auto service_b = service_list.FindService("B");
+    ASSERT_NE(nullptr, service_b);
+    EXPECT_EQ(std::vector<std::string>({"/path/to/B"}), service_b->args());
+}
+
 TEST(init, OverrideService) {
     std::string init_script = R"init(
 service A something
diff --git a/init/libprefetch/prefetch/src/tracer/mem.rs b/init/libprefetch/prefetch/src/tracer/mem.rs
index 42120da1bc..920647ebc8 100644
--- a/init/libprefetch/prefetch/src/tracer/mem.rs
+++ b/init/libprefetch/prefetch/src/tracer/mem.rs
@@ -281,6 +281,8 @@ struct TraceLineInfo {
     inode: InodeNumber,
     offset: u64,
     timestamp: u64,
+    // Only supported in kernel 6.x (with page cache folio support).
+    order: Option<u32>,
 }
 
 impl TraceLineInfo {
@@ -294,6 +296,14 @@ impl TraceLineInfo {
         let ino = &caps["ino"];
         let offset = &caps["offset"];
         let timestamp = build_timestamp(&caps["seconds"], &caps["microseconds"])?;
+        let order = caps
+            .name("order")
+            .map(|m| {
+                m.as_str().parse::<u32>().map_err(|e| Error::Custom {
+                    error: format!("failed parsing order: {} : {}", m.as_str(), e),
+                })
+            })
+            .transpose()?;
         Ok(Some(TraceLineInfo {
             device: build_device_number(major, minor)?,
             inode: u64::from_str_radix(ino, 16).map_err(|e| Error::Custom {
@@ -303,6 +313,7 @@ impl TraceLineInfo {
                 error: format!("failed parsing offset: {} : {}", offset, e),
             })?,
             timestamp,
+            order,
         }))
     }
 
@@ -313,8 +324,9 @@ impl TraceLineInfo {
         inode: u64,
         offset: u64,
         timestamp: u64,
+        order: Option<u32>,
     ) -> Self {
-        Self { device: makedev(major, minor), inode, offset, timestamp }
+        Self { device: makedev(major, minor), inode, offset, timestamp, order }
     }
 
     // Convenience function to create regex. Used once per life of `record` but multiple times in
@@ -333,7 +345,7 @@ impl TraceLineInfo {
             r"(?:\s+(?P<page>page=\S+))?",
             r"\s+(?P<pfn>\S+)",
             r"\s+ofs=(?P<offset>[0-9]+)",
-            r"(?:\s+(?P<order>\S+))?"
+            r"(?:\s+order=(?P<order>\S+))?"
         ))
         .map_err(|e| Error::Custom {
             error: format!("create regex for tracing failed with: {}", e),
@@ -523,10 +535,12 @@ impl TraceSubsystem for MemTraceSubsystem {
                 .unwrap()
                 .insert(info.inode, file_id.clone());
 
+            let length = self.page_size << info.order.unwrap_or(0);
+
             self.records.push(Record {
                 file_id,
                 offset: info.offset,
-                length: self.page_size,
+                length,
                 timestamp: info.timestamp,
             });
         }
@@ -699,7 +713,7 @@ mod tests {
         " logcat-686     [001] ..... 148217.776227: mm_filemap_add_to_page_cache: dev 254:85 ino 3f15 pfn=0x21d306 ofs=532480 order=0\n",
         " logcat-686     [003] ..... 148219.044389: mm_filemap_add_to_pag_ecache: dev 254:85 ino 3f15 pfn=0x224b8d ofs=536576 order=0\n",
         " logcat-686     [001] ..... 148220.780964: mm_filemap_add_to_page_cache: dev 254:85 ino 3f15 pfn=0x1bfe0a ofs=540672 order=0\n",
-        " logcat-686     [001] ..... 148223.046560: mm_filemap_add_to_page_cache: dev 254:85 ino 3f15 pfn=0x1f3d29 ofs=544768 order=0",
+        " logcat-686     [001] ..... 148223.046560: mm_filemap_add_to_page_cache: dev 254:85 ino 3f15 pfn=0x1f3d29 ofs=544768 order=1",
     );
 
     fn sample_mem_traces() -> (String, Vec<Option<TraceLineInfo>>) {
@@ -708,19 +722,19 @@ mod tests {
             vec![
                 // 5.x
                 None,
-                Some(TraceLineInfo::from_fields(254, 6, 0xcf1, 57344, 484360311000)),
+                Some(TraceLineInfo::from_fields(254, 6, 0xcf1, 57344, 484360311000, None)),
                 None,
-                Some(TraceLineInfo::from_fields(254, 6, 0xcf2, 0, 485276990000)),
-                Some(TraceLineInfo::from_fields(254, 6, 0x1, 13578240, 485545516000)),
-                Some(TraceLineInfo::from_fields(254, 6, 0xcf3, 0, 485545820000)),
-                Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1310720, 494029396000)),
-                Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1314816, 494029398000)),
+                Some(TraceLineInfo::from_fields(254, 6, 0xcf2, 0, 485276990000, None)),
+                Some(TraceLineInfo::from_fields(254, 6, 0x1, 13578240, 485545516000, None)),
+                Some(TraceLineInfo::from_fields(254, 6, 0xcf3, 0, 485545820000, None)),
+                Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1310720, 494029396000, None)),
+                Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1314816, 494029398000, None)),
                 // 6.x
                 None,
-                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 532480, 148217776227000)),
+                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 532480, 148217776227000, Some(0))),
                 None,
-                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 540672, 148220780964000)),
-                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 544768, 148223046560000)),
+                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 540672, 148220780964000, Some(0))),
+                Some(TraceLineInfo::from_fields(254, 85, 0x3f15, 544768, 148223046560000, Some(1))),
             ],
         )
     }
diff --git a/init/mount_namespace.cpp b/init/mount_namespace.cpp
index 7918f23e9e..36c0fd73ab 100644
--- a/init/mount_namespace.cpp
+++ b/init/mount_namespace.cpp
@@ -26,9 +26,15 @@
 #include <android-base/properties.h>
 #include <android-base/result.h>
 #include <android-base/unique_fd.h>
+#include <com_android_apex_flags.h>
 
+#include "apex_init_util.h"
 #include "util.h"
 
+using android::base::GetBoolProperty;
+using android::base::GetIntProperty;
+using android::base::SetProperty;
+
 namespace android {
 namespace init {
 namespace {
@@ -66,21 +72,34 @@ static std::string GetMountNamespaceId() {
     return ret;
 }
 
-static android::base::unique_fd bootstrap_ns_fd;
-static android::base::unique_fd default_ns_fd;
+[[clang::no_destroy]] static android::base::unique_fd bootstrap_ns_fd;
+[[clang::no_destroy]] static android::base::unique_fd default_ns_fd;
 
-static std::string bootstrap_ns_id;
-static std::string default_ns_id;
+[[clang::no_destroy]] static std::string bootstrap_ns_id;
+[[clang::no_destroy]] static std::string default_ns_id;
 
 }  // namespace
 
 // In case we have two sets of APEXes (non-updatable, updatable), we need two separate mount
 // namespaces.
 bool NeedsTwoMountNamespaces() {
-    if (IsRecoveryMode()) return false;
-    // In microdroid, there's only one set of APEXes in built-in directories include block devices.
-    if (IsMicrodroid()) return false;
-    return true;
+    static bool needs_two_mount_namespaces = []() {
+        if (IsRecoveryMode()) return false;
+        // In microdroid, there's only one set of APEXes in built-in directories include block
+        // devices.
+        if (IsMicrodroid()) return false;
+
+        if constexpr (com::android::apex::flags::mount_before_data()) {
+            // If apexd can mount APEXes before the data partition is ready, a single mount
+            // namespace is enough.
+            if (CanMountApexBeforeData()) {
+                return false;
+            }
+        }
+
+        return true;
+    }();
+    return needs_two_mount_namespaces;
 }
 
 bool SetupMountNamespaces() {
@@ -148,8 +167,8 @@ bool SetupMountNamespaces() {
     // activated by apexd. In the namespace for pre-apexd processes, small
     // number of essential APEXes (e.g. com.android.runtime) are activated.
     // In the namespace for post-apexd processes, all APEXes are activated.
-    bool success = true;
-    if (NeedsTwoMountNamespaces()) {
+    bool needs_two_mnt_ns = NeedsTwoMountNamespaces();
+    if (needs_two_mnt_ns) {
         // Creating a new namespace by cloning, saving, and switching back to
         // the original namespace.
         if (unshare(CLONE_NEWNS) == -1) {
@@ -186,8 +205,13 @@ bool SetupMountNamespaces() {
         default_ns_id = GetMountNamespaceId();
     }
 
+    if constexpr (com::android::apex::flags::mount_before_data()) {
+        // Expose the decision to other components like apexd
+        SetProperty("ro.init.mnt_ns.count", needs_two_mnt_ns ? "2" : "1");
+    }
+
     LOG(INFO) << "SetupMountNamespaces done";
-    return success;
+    return true;
 }
 
 // Switch the mount namespace of the current process from bootstrap to default OR from default to
diff --git a/init/persistent_properties.cpp b/init/persistent_properties.cpp
index 1d17e3c106..3c3d1be3ed 100644
--- a/init/persistent_properties.cpp
+++ b/init/persistent_properties.cpp
@@ -41,7 +41,8 @@ using android::base::WriteStringToFd;
 namespace android {
 namespace init {
 
-std::string persistent_property_filename = "/data/property/persistent_properties";
+[[clang::no_destroy]] std::string persistent_property_filename =
+        "/data/property/persistent_properties";
 
 namespace {
 
diff --git a/init/property_service.cpp b/init/property_service.cpp
index 83e9a0da35..a3c277288d 100644
--- a/init/property_service.cpp
+++ b/init/property_service.cpp
@@ -115,12 +115,12 @@ static bool persistent_properties_loaded = false;
 static int from_init_socket = -1;
 static int init_socket = -1;
 static bool accept_messages = false;
-static std::mutex accept_messages_lock;
-static std::mutex selinux_check_access_lock;
-static std::thread property_service_thread;
-static std::thread property_service_for_system_thread;
+[[clang::no_destroy]] static std::mutex accept_messages_lock;
+[[clang::no_destroy]] static std::mutex selinux_check_access_lock;
+[[clang::no_destroy]] static std::thread property_service_thread;
+[[clang::no_destroy]] static std::thread property_service_for_system_thread;
 
-static PropertyInfoAreaFile property_info_area;
+[[clang::no_destroy]] static PropertyInfoAreaFile property_info_area;
 
 struct PropertyAuditData {
     const ucred* cr;
@@ -380,7 +380,7 @@ class PersistWriteThread {
     std::deque<std::tuple<std::string, std::string, SocketConnection>> work_;
 };
 
-static std::unique_ptr<PersistWriteThread> persist_write_thread;
+[[clang::no_destroy]] static std::unique_ptr<PersistWriteThread> persist_write_thread;
 
 static std::optional<uint32_t> PropertySet(const std::string& name, const std::string& value,
                                            SocketConnection* socket, std::string* error) {
@@ -574,7 +574,7 @@ std::optional<uint32_t> HandlePropertySet(const std::string& name, const std::st
     // We use a thread to do this restorecon operation to prevent holding up init, as it may take
     // a long time to complete.
     if (name == kRestoreconProperty && cr.pid != 1 && !value.empty()) {
-        static AsyncRestorecon async_restorecon;
+        [[clang::no_destroy]] static AsyncRestorecon async_restorecon;
         async_restorecon.TriggerRestorecon(value);
         return {PROP_SUCCESS};
     }
@@ -843,13 +843,16 @@ static void LoadPropertiesFromSecondStageRes(std::map<std::string, std::string>*
 // So we need to apply the same rule of build/make/tools/post_process_props.py
 // on runtime.
 static void update_sys_usb_config() {
-    bool is_debuggable = android::base::GetBoolProperty("ro.debuggable", false);
+    // emulators don't have USB, they enable adb another way.
+    const bool add_adb_func = android::base::GetBoolProperty("ro.debuggable", false) &&
+                              android::base::GetBoolProperty("ro.adb.has_usb", true);
+
     std::string config = android::base::GetProperty("persist.sys.usb.config", "");
     // b/150130503, add (config == "none") condition here to prevent appending
     // ",adb" if "none" is explicitly defined in default prop.
     if (config.empty() || config == "none") {
-        InitPropertySet("persist.sys.usb.config", is_debuggable ? "adb" : "none");
-    } else if (is_debuggable && config.find("adb") == std::string::npos &&
+        InitPropertySet("persist.sys.usb.config", add_adb_func ? "adb" : "none");
+    } else if (add_adb_func && config.find("adb") == std::string::npos &&
                config.length() + 4 < PROP_VALUE_MAX) {
         config.append(",adb");
         InitPropertySet("persist.sys.usb.config", config);
diff --git a/init/reboot.cpp b/init/reboot.cpp
index a26149f77e..b3322f693f 100644
--- a/init/reboot.cpp
+++ b/init/reboot.cpp
@@ -14,10 +14,13 @@
  * limitations under the License.
  */
 
+#define LOG_TAG "init"
+
 #include "reboot.h"
 
 #include <dirent.h>
 #include <fcntl.h>
+#include <linux/ext4.h>
 #include <linux/f2fs.h>
 #include <linux/fs.h>
 #include <linux/loop.h>
@@ -49,6 +52,7 @@
 #include <android-base/unique_fd.h>
 #include <bootloader_message/bootloader_message.h>
 #include <cutils/android_reboot.h>
+#include <cutils/klog.h>
 #include <fs_mgr.h>
 #include <libsnapshot/snapshot.h>
 #include <logwrap/logwrap.h>
@@ -111,8 +115,7 @@ enum UmountStat {
     UMOUNT_STAT_TIMEOUT = 2,
     /* could not run due to error */
     UMOUNT_STAT_ERROR = 3,
-    /* not used by init but reserved for other part to use this to represent the
-       the state where umount status before reboot is not found / available. */
+    /* umount status before reboot is not found / available. */
     UMOUNT_STAT_NOT_AVAILABLE = 4,
 };
 
@@ -204,30 +207,35 @@ static Result<void> CallVdc(const std::string& system, const std::string& cmd) {
     return Error() << "'/system/bin/vdc " << system << " " << cmd << "' failed : " << status;
 }
 
-static void LogShutdownTime(UmountStat stat, Timer* t) {
-    LOG(WARNING) << "powerctl_shutdown_time_ms:" << std::to_string(t->duration().count()) << ":"
-                 << stat;
+// This function should be called just before kernel reboot/shutdown. At this point, the logd
+// is killed, regular logger does not work. Use KLOG to make sure the log is available in
+// pstore console file, preventing log data from losing.
+static void LogShutdownTime(UmountStat stat, const Timer& t) {
+    KLOG_WARNING(LOG_TAG, "powerctl_shutdown_time_ms:%lld:%d\n", t.duration().count(), stat);
 }
 
-static bool IsDataMounted(const std::string& fstype) {
+// Gets the filesystem type of the /data partition.
+// Returns the filesystem type as a string (e.g., "ext4", "f2fs") or an empty string if not found
+// or if an error occurs.
+static std::string GetDataFsType() {
     std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
     if (fp == nullptr) {
         PLOG(ERROR) << "Failed to open /proc/mounts";
-        return false;
+        return "";
     }
     mntent* mentry;
     while ((mentry = getmntent(fp.get())) != nullptr) {
         if (mentry->mnt_dir == "/data"s) {
-            return fstype == "*" || mentry->mnt_type == fstype;
+            return mentry->mnt_type;
         }
     }
-    return false;
+    return "";
 }
 
 // Find all read+write block devices and emulated devices in /proc/mounts and add them to
 // the correpsponding list.
 static bool FindPartitionsToUmount(std::vector<MountEntry>* block_dev_partitions,
-                                   std::vector<MountEntry>* emulated_partitions, bool dump) {
+                                   std::vector<MountEntry>* emulated_partitions) {
     std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
     if (fp == nullptr) {
         PLOG(ERROR) << "Failed to open /proc/mounts";
@@ -235,10 +243,7 @@ static bool FindPartitionsToUmount(std::vector<MountEntry>* block_dev_partitions
     }
     mntent* mentry;
     while ((mentry = getmntent(fp.get())) != nullptr) {
-        if (dump) {
-            LOG(INFO) << "mount entry " << mentry->mnt_fsname << ":" << mentry->mnt_dir << " opts "
-                      << mentry->mnt_opts << " type " << mentry->mnt_type;
-        } else if (MountEntry::IsBlockDevice(*mentry) && hasmntopt(mentry, "rw")) {
+        if (MountEntry::IsBlockDevice(*mentry) && hasmntopt(mentry, "rw")) {
             std::string mount_dir(mentry->mnt_dir);
             // These are R/O partitions changed to R/W after adb remount.
             // Do not umount them as shutdown critical services may rely on them.
@@ -253,6 +258,20 @@ static bool FindPartitionsToUmount(std::vector<MountEntry>* block_dev_partitions
     return true;
 }
 
+static void DumpPartitions() {
+    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
+    if (fp == nullptr) {
+        PLOG(ERROR) << "Failed to open /proc/mounts";
+        return;
+    }
+
+    mntent* mentry;
+    while ((mentry = getmntent(fp.get())) != nullptr) {
+        LOG(INFO) << "mount entry " << mentry->mnt_fsname << ":" << mentry->mnt_dir << " opts "
+                  << mentry->mnt_opts << " type " << mentry->mnt_type;
+    }
+}
+
 static void DumpUmountDebuggingInfo() {
     int status;
     if (!security_getenforce()) {
@@ -261,12 +280,72 @@ static void DumpUmountDebuggingInfo() {
         logwrap_fork_execvp(arraysize(lsof_argv), lsof_argv, &status, false, LOG_KLOG, true,
                             nullptr);
     }
-    FindPartitionsToUmount(nullptr, nullptr, true);
+    DumpPartitions();
     // dump current CPU stack traces and uninterruptible tasks
     WriteStringToFile("l", PROC_SYSRQ);
     WriteStringToFile("w", PROC_SYSRQ);
 }
 
+/** Attempts to unmount partitions
+ *
+ * @param force If true, forces the unmount operation, even if the filesystem is busy.
+ * @return UMOUNT_STAT_SUCCESS: if all partitions were unmounted successfully, or if no partitions
+ *         were found to unmount after umounting.
+ *         UMOUNT_STAT_NOT_AVAILABLE: failed to read umount stats from /proc/mounts.
+ *         UMOUNT_STAT_ERROR: failed to umount all partitions.
+ */
+static UmountStat TryUmountPartitions(bool force) {
+    std::vector<MountEntry> block_devices;
+    std::vector<MountEntry> emulated_devices;
+
+    // Find partitions to umount and store the mount entries in block_devices and emulated_devices
+    if (!FindPartitionsToUmount(&block_devices, &emulated_devices)) {
+        return UMOUNT_STAT_NOT_AVAILABLE;
+    }
+
+    // Success if there are no partitions need to umount
+    if (block_devices.empty()) {
+        return UMOUNT_STAT_SUCCESS;
+    }
+
+    bool unmount_success = true;
+    // Umount emulated device since /data partition needs all pending writes to be completed and
+    // all emulated partitions unmounted.
+    if (emulated_devices.size() > 0) {
+        for (auto& entry : emulated_devices) {
+            if (!entry.Umount(false)) unmount_success = false;
+        }
+        if (unmount_success) {
+            sync();
+        }
+    }
+
+    for (auto& entry : block_devices) {
+        if (!entry.Umount(force)) unmount_success = false;
+    }
+
+    if (unmount_success) {
+        return UMOUNT_STAT_SUCCESS;
+    }
+
+    // Some identical mount points may be umounted twice during unmounting, which can cause an
+    // INVALID_ARGUMENT error at second umount. However, they were actually unmounted
+    // successfully. Update the list of partitions that need to be umounted after the first
+    // attempt. If there are no partitions left to umount, we should consider the umount
+    // successful.
+    block_devices.clear();
+    emulated_devices.clear();
+    if (!FindPartitionsToUmount(&block_devices, &emulated_devices)) {
+        return UMOUNT_STAT_NOT_AVAILABLE;
+    }
+
+    if (block_devices.empty() && emulated_devices.empty()) {
+        return UMOUNT_STAT_SUCCESS;
+    }
+
+    return UMOUNT_STAT_ERROR;
+}
+
 static UmountStat UmountPartitions(std::chrono::milliseconds timeout) {
     // Terminate (SIGTERM) the services before unmounting partitions.
     // If the processes block the signal, then partitions will eventually fail
@@ -282,34 +361,20 @@ static UmountStat UmountPartitions(std::chrono::milliseconds timeout) {
     ReapAnyOutstandingChildren();
 
     Timer t;
-    /* data partition needs all pending writes to be completed and all emulated partitions
-     * umounted.If the current waiting is not good enough, give
-     * up and leave it to e2fsck after reboot to fix it.
+    /* If the current waiting is not good enough, give up and leave it to e2fsck after reboot to
+     * fix it.
      */
     while (true) {
-        std::vector<MountEntry> block_devices;
-        std::vector<MountEntry> emulated_devices;
-        if (!FindPartitionsToUmount(&block_devices, &emulated_devices, false)) {
-            return UMOUNT_STAT_ERROR;
-        }
-        if (block_devices.size() == 0) {
+        // force umount operation if timeout is not set
+        UmountStat stat = TryUmountPartitions(/*force=*/timeout == 0ms);
+        if (stat == UMOUNT_STAT_SUCCESS) {
             return UMOUNT_STAT_SUCCESS;
         }
-        bool unmount_done = true;
-        if (emulated_devices.size() > 0) {
-            for (auto& entry : emulated_devices) {
-                if (!entry.Umount(false)) unmount_done = false;
-            }
-            if (unmount_done) {
-                sync();
-            }
-        }
-        for (auto& entry : block_devices) {
-            if (!entry.Umount(timeout == 0ms)) unmount_done = false;
-        }
-        if (unmount_done) {
-            return UMOUNT_STAT_SUCCESS;
+
+        if (stat == UMOUNT_STAT_NOT_AVAILABLE || timeout == 0ms) {
+            return UMOUNT_STAT_ERROR;
         }
+
         if ((timeout < t.duration())) {  // try umount at least once
             return UMOUNT_STAT_TIMEOUT;
         }
@@ -321,90 +386,91 @@ static void KillAllProcesses() {
     WriteStringToFile("i", PROC_SYSRQ);
 }
 
-// Create reboot/shutdwon monitor thread
-void RebootMonitorThread(unsigned int cmd, const std::string& reboot_target,
-                         sem_t* reboot_semaphore, std::chrono::milliseconds shutdown_timeout,
-                         bool* reboot_monitor_run) {
-    unsigned int remaining_shutdown_time = 0;
-
-    // 300 seconds more than the timeout passed to the thread as there is a final Umount pass
-    // after the timeout is reached.
+// Reboot/shutdown monitor thread
+static void RebootMonitorThread(unsigned int cmd, const Timer& shutdown_timer) {
+    // We want quite a long timeout here since the "sync" in the calling
+    // thread can be quite slow.
     constexpr unsigned int shutdown_watchdog_timeout_default = 300;
+    constexpr unsigned int shutdown_watchdog_timeout_min = 60;
     auto shutdown_watchdog_timeout = android::base::GetUintProperty(
             "ro.build.shutdown.watchdog.timeout", shutdown_watchdog_timeout_default);
-    remaining_shutdown_time = shutdown_watchdog_timeout + shutdown_timeout.count() / 1000;
 
-    while (*reboot_monitor_run == true) {
-        if (TEMP_FAILURE_RETRY(sem_wait(reboot_semaphore)) == -1) {
-            LOG(ERROR) << "sem_wait failed and exit RebootMonitorThread()";
-            return;
-        }
+    if (shutdown_watchdog_timeout < shutdown_watchdog_timeout_min) {
+        LOG(WARNING) << "ro.build.shutdown.watchdog.timeout = " << shutdown_watchdog_timeout
+                     << " is too small; bumping up to " << shutdown_watchdog_timeout_min;
+        shutdown_watchdog_timeout = shutdown_watchdog_timeout_min;
+    }
 
-        timespec shutdown_timeout_timespec;
-        if (clock_gettime(CLOCK_MONOTONIC, &shutdown_timeout_timespec) == -1) {
-            LOG(ERROR) << "clock_gettime() fail! exit RebootMonitorThread()";
-            return;
+    LOG(INFO) << "RebootMonitorThread started for " << shutdown_watchdog_timeout << "s";
+    std::chrono::duration timeout = std::chrono::seconds(shutdown_watchdog_timeout);
+
+    constexpr unsigned int num_steps = 10;
+    std::chrono::duration sleep_amount =
+            std::chrono::duration_cast<std::chrono::milliseconds>(timeout) / num_steps;
+
+    for (unsigned int i = 0; i < num_steps - 1; i++) {
+        std::this_thread::sleep_for(sleep_amount);
+
+        // Print a message periodically as we're waiting so there is some
+        // warning in the logs if we're getting close to triggering. Use this
+        // as a chance to try to preserve data by using the "sync" and
+        // "force remount readonly" sysrq requests, both of which kick off
+        // background work and are non-blocking. We'll do "sync" most of the
+        // time and only do the more intrusive remount right before the last
+        // delay (to give it time to take effect).
+        LOG(WARNING) << "Reboot monitor still running, forced reboot in "
+                     << ((num_steps - i - 1) * sleep_amount.count()) << " ms";
+        if (i == num_steps - 2) {
+            WriteStringToFile("u", PROC_SYSRQ);
+        } else {
+            WriteStringToFile("s", PROC_SYSRQ);
         }
-
-        // If there are some remaining shutdown time left from previous round, we use
-        // remaining time here.
-        shutdown_timeout_timespec.tv_sec += remaining_shutdown_time;
-
-        LOG(INFO) << "shutdown_timeout_timespec.tv_sec: " << shutdown_timeout_timespec.tv_sec;
-
-        int sem_return = 0;
-        while ((sem_return = sem_timedwait_monotonic_np(reboot_semaphore,
-                                                        &shutdown_timeout_timespec)) == -1 &&
-               errno == EINTR) {
+    }
+    std::this_thread::sleep_for(sleep_amount);
+
+    LOG(ERROR) << "Reboot thread timed out";
+
+    if (android::base::GetBoolProperty("ro.debuggable", false) == true) {
+        if (false) {
+            // SEPolicy will block debuggerd from running and this is intentional.
+            // But these lines are left to be enabled during debugging.
+            LOG(INFO) << "Try to dump init process call trace:";
+            const char* vdc_argv[] = {"/system/bin/debuggerd", "-b", "1"};
+            int status;
+            logwrap_fork_execvp(arraysize(vdc_argv), vdc_argv, &status, false, LOG_KLOG, true,
+                                nullptr);
         }
+        LOG(INFO) << "Show stack for all active CPU:";
+        WriteStringToFile("l", PROC_SYSRQ);
 
-        if (sem_return == -1) {
-            LOG(ERROR) << "Reboot thread timed out";
-
-            if (android::base::GetBoolProperty("ro.debuggable", false) == true) {
-                if (false) {
-                    // SEPolicy will block debuggerd from running and this is intentional.
-                    // But these lines are left to be enabled during debugging.
-                    LOG(INFO) << "Try to dump init process call trace:";
-                    const char* vdc_argv[] = {"/system/bin/debuggerd", "-b", "1"};
-                    int status;
-                    logwrap_fork_execvp(arraysize(vdc_argv), vdc_argv, &status, false, LOG_KLOG,
-                                        true, nullptr);
-                }
-                LOG(INFO) << "Show stack for all active CPU:";
-                WriteStringToFile("l", PROC_SYSRQ);
-
-                LOG(INFO) << "Show tasks that are in disk sleep(uninterruptable sleep), which are "
-                             "like "
-                             "blocked in mutex or hardware register access:";
-                WriteStringToFile("w", PROC_SYSRQ);
-            }
-
-            // In shutdown case,notify kernel to sync and umount fs to read-only before shutdown.
-            if (cmd == ANDROID_RB_POWEROFF || cmd == ANDROID_RB_THERMOFF) {
-                WriteStringToFile("s", PROC_SYSRQ);
-
-                WriteStringToFile("u", PROC_SYSRQ);
-
-                RebootSystem(cmd, reboot_target);
-            }
+        LOG(INFO) << "Show tasks that are in disk sleep(uninterruptable sleep), which are "
+                     "like "
+                     "blocked in mutex or hardware register access:";
+        WriteStringToFile("w", PROC_SYSRQ);
+    }
 
-            LOG(ERROR) << "Trigger crash at last!";
-            WriteStringToFile("c", PROC_SYSRQ);
-        } else {
-            timespec current_time_timespec;
+    if (cmd == ANDROID_RB_POWEROFF || cmd == ANDROID_RB_THERMOFF) {
+        LogShutdownTime(UMOUNT_STAT_TIMEOUT, shutdown_timer);
+        RebootSystem(cmd, "");
+    }
 
-            if (clock_gettime(CLOCK_MONOTONIC, &current_time_timespec) == -1) {
-                LOG(ERROR) << "clock_gettime() fail! exit RebootMonitorThread()";
-                return;
-            }
+    LOG(ERROR) << "Trigger crash at last!";
+    WriteStringToFile("c", PROC_SYSRQ);
+}
 
-            remaining_shutdown_time =
-                    shutdown_timeout_timespec.tv_sec - current_time_timespec.tv_sec;
+// Create reboot/shutdown monitor thread
+static void StartRebootMonitorThread(unsigned int cmd, const Timer& shutdown_timer) {
+    static std::atomic_flag started{};
 
-            LOG(INFO) << "remaining_shutdown_time: " << remaining_shutdown_time;
-        }
+    // Only allow the monitor to be started once.
+    if (started.test_and_set(std::memory_order_acquire)) {
+        LOG(INFO) << "RebootMonitorThread already started";
+        return;
     }
+
+    LOG(INFO) << "Starting RebootMonitorThread";
+    std::thread reboot_monitor_thread(&RebootMonitorThread, cmd, shutdown_timer);
+    reboot_monitor_thread.detach();
 }
 
 static bool UmountDynamicPartitions(const std::vector<std::string>& dynamic_partitions) {
@@ -435,27 +501,30 @@ static bool UmountDynamicPartitions(const std::vector<std::string>& dynamic_part
  * return true when umount was successful. false when timed out.
  */
 static UmountStat TryUmountAndFsck(unsigned int cmd, bool run_fsck,
-                                   std::chrono::milliseconds timeout, sem_t* reboot_semaphore) {
+                                   std::chrono::milliseconds timeout) {
     Timer t;
     std::vector<MountEntry> block_devices;
     std::vector<MountEntry> emulated_devices;
     std::vector<std::string> dynamic_partitions;
 
-    if (run_fsck && !FindPartitionsToUmount(&block_devices, &emulated_devices, false)) {
+    if (run_fsck && !FindPartitionsToUmount(&block_devices, &emulated_devices)) {
         return UMOUNT_STAT_ERROR;
     }
-    auto sm = snapshot::SnapshotManager::New();
     bool ota_update_in_progress = false;
-    if (sm->IsUserspaceSnapshotUpdateInProgress(dynamic_partitions)) {
-        LOG(INFO) << "OTA update in progress. Pause snapshot merge";
-        if (!sm->PauseSnapshotMerge()) {
-            LOG(ERROR) << "Snapshot-merge pause failed";
+    if (!IsMicrodroid()) {
+        auto sm = snapshot::SnapshotManager::New();
+        if (sm->IsUserspaceSnapshotUpdateInProgress(dynamic_partitions)) {
+            LOG(INFO) << "OTA update in progress. Pause snapshot merge";
+            if (!sm->PauseSnapshotMerge()) {
+                LOG(ERROR) << "Snapshot-merge pause failed";
+            }
+            ota_update_in_progress = true;
         }
-        ota_update_in_progress = true;
     }
     UmountStat stat = UmountPartitions(timeout - t.duration());
     if (stat != UMOUNT_STAT_SUCCESS) {
-        LOG(INFO) << "umount timeout, last resort, kill all and try";
+        // Do not delete: Critical log for reboot_fs_integrity_test.
+        KLOG_INFO(LOG_TAG, "umount timeout, last resort, kill all and try");
         if (DUMP_ON_UMOUNT_FAILURE) DumpUmountDebuggingInfo();
         // Since umount timedout, we will try to kill all processes
         // and do one more attempt to umount the partitions.
@@ -490,17 +559,9 @@ static UmountStat TryUmountAndFsck(unsigned int cmd, bool run_fsck,
     }
 
     if (stat == UMOUNT_STAT_SUCCESS && run_fsck) {
-        LOG(INFO) << "Pause reboot monitor thread before fsck";
-        sem_post(reboot_semaphore);
-
-        // fsck part is excluded from timeout check. It only runs for user initiated shutdown
-        // and should not affect reboot time.
         for (auto& entry : block_devices) {
             entry.DoFsck();
         }
-
-        LOG(INFO) << "Resume reboot monitor thread after fsck";
-        sem_post(reboot_semaphore);
     }
     return stat;
 }
@@ -532,7 +593,7 @@ static Result<void> KillZramBackingDevice() {
         return ErrnoError() << "Failed to read " << ZRAM_BACK_DEV;
     }
 
-    android::base::Trim(backing_dev);
+    backing_dev = android::base::Trim(backing_dev);
 
     if (android::base::StartsWith(backing_dev, "none")) {
         LOG(INFO) << "No zram backing device configured";
@@ -557,7 +618,7 @@ static Result<void> KillZramBackingDevice() {
         return ErrnoError() << "Failed to read " << ZRAM_BACK_DEV;
     }
 
-    android::base::Trim(backing_dev);
+    backing_dev = android::base::Trim(backing_dev);
 
     if (!android::base::StartsWith(backing_dev, "/dev/block/loop")) {
         LOG(INFO) << backing_dev << " is not a loop device. Exiting early";
@@ -657,35 +718,25 @@ static void DoReboot(unsigned int cmd, const std::string& reason, const std::str
 
     bool is_thermal_shutdown = cmd == ANDROID_RB_THERMOFF;
 
-    auto shutdown_timeout = 0ms;
+    auto clean_shutdown_timeout = 0ms;
     if (!SHUTDOWN_ZERO_TIMEOUT) {
-        constexpr unsigned int shutdown_timeout_default = 6;
-        constexpr unsigned int max_thermal_shutdown_timeout = 3;
-        auto shutdown_timeout_final = android::base::GetUintProperty("ro.build.shutdown_timeout",
-                                                                     shutdown_timeout_default);
-        if (is_thermal_shutdown && shutdown_timeout_final > max_thermal_shutdown_timeout) {
-            shutdown_timeout_final = max_thermal_shutdown_timeout;
+        constexpr unsigned int clean_shutdown_timeout_default = 6;
+        constexpr unsigned int max_clean_thermal_shutdown_timeout = 3;
+        constexpr unsigned int max_clean_shutdown_timeout = 10;
+        auto shutdown_timeout_final = android::base::GetUintProperty(
+                "ro.build.shutdown_timeout", clean_shutdown_timeout_default);
+        if (is_thermal_shutdown && shutdown_timeout_final > max_clean_thermal_shutdown_timeout) {
+            shutdown_timeout_final = max_clean_thermal_shutdown_timeout;
+        } else if (shutdown_timeout_final > max_clean_shutdown_timeout) {
+            LOG(WARNING) << "Shorten clean shutdown timeout from " << shutdown_timeout_final
+                         << " s to " << max_clean_shutdown_timeout << " s";
+            shutdown_timeout_final = max_clean_shutdown_timeout;
         }
-        shutdown_timeout = std::chrono::seconds(shutdown_timeout_final);
-    }
-    LOG(INFO) << "Shutdown timeout: " << shutdown_timeout.count() << " ms";
-
-    sem_t reboot_semaphore;
-    if (sem_init(&reboot_semaphore, false, 0) == -1) {
-        // These should never fail, but if they do, skip the graceful reboot and reboot immediately.
-        LOG(ERROR) << "sem_init() fail and RebootSystem() return!";
-        RebootSystem(cmd, reboot_target, reason);
+        clean_shutdown_timeout = std::chrono::seconds(shutdown_timeout_final);
     }
+    LOG(INFO) << "Clean shutdown timeout: " << clean_shutdown_timeout.count() << " ms";
 
-    // Start a thread to monitor init shutdown process
-    LOG(INFO) << "Create reboot monitor thread.";
-    bool reboot_monitor_run = true;
-    std::thread reboot_monitor_thread(&RebootMonitorThread, cmd, reboot_target, &reboot_semaphore,
-                                      shutdown_timeout, &reboot_monitor_run);
-    reboot_monitor_thread.detach();
-
-    // Start reboot monitor thread
-    sem_post(&reboot_semaphore);
+    StartRebootMonitorThread(cmd, t);
 
     // Ensure last reboot reason is reduced to canonical
     // alias reported in bootloader or system boot reason.
@@ -700,8 +751,9 @@ static void DoReboot(unsigned int cmd, const std::string& reason, const std::str
 
     // If /data isn't mounted then we can skip the extra reboot steps below, since we don't need to
     // worry about unmounting it.
-    if (!IsDataMounted("*")) {
+    if (GetDataFsType().empty()) {
         sync();
+        LogShutdownTime(UMOUNT_STAT_SKIPPED, t);
         RebootSystem(cmd, reboot_target, reason);
         abort();
     }
@@ -771,8 +823,8 @@ static void DoReboot(unsigned int cmd, const std::string& reason, const std::str
 
     // optional shutdown step
     // 1. terminate all services except shutdown critical ones. wait for delay to finish
-    if (shutdown_timeout > 0ms) {
-        StopServicesAndLogViolations(stop_first, shutdown_timeout / 2, true /* SIGTERM */);
+    if (clean_shutdown_timeout > 0ms) {
+        StopServicesAndLogViolations(stop_first, clean_shutdown_timeout / 2, true /* SIGTERM */);
     }
     // Send SIGKILL to ones that didn't terminate cleanly.
     StopServicesAndLogViolations(stop_first, 0ms, false /* SIGKILL */);
@@ -808,8 +860,7 @@ static void DoReboot(unsigned int cmd, const std::string& reason, const std::str
     if (auto ret = UnmountAllApexes(); !ret.ok()) {
         LOG(ERROR) << ret.error();
     }
-    UmountStat stat =
-            TryUmountAndFsck(cmd, run_fsck, shutdown_timeout - t.duration(), &reboot_semaphore);
+    UmountStat stat = TryUmountAndFsck(cmd, run_fsck, clean_shutdown_timeout - t.duration());
     // Follow what linux shutdown is doing: one more sync with little bit delay
     {
         Timer sync_timer;
@@ -818,24 +869,38 @@ static void DoReboot(unsigned int cmd, const std::string& reason, const std::str
         LOG(INFO) << "sync() after umount took" << sync_timer;
     }
     if (!is_thermal_shutdown) std::this_thread::sleep_for(100ms);
-    LogShutdownTime(stat, &t);
-
-    // Send signal to terminate reboot monitor thread.
-    reboot_monitor_run = false;
-    sem_post(&reboot_semaphore);
 
     // Reboot regardless of umount status. If umount fails, fsck after reboot will fix it.
-    if (IsDataMounted("f2fs")) {
-        uint32_t flag = F2FS_GOING_DOWN_FULLSYNC;
-        unique_fd fd(TEMP_FAILURE_RETRY(open("/data", O_RDONLY)));
-        LOG(INFO) << "Invoking F2FS_IOC_SHUTDOWN during shutdown";
-        int ret = ioctl(fd.get(), F2FS_IOC_SHUTDOWN, &flag);
-        if (ret) {
-            PLOG(ERROR) << "Shutdown /data: ";
+    std::string data_fs_type = GetDataFsType();
+    if (!data_fs_type.empty()) {
+        // Do not delete: Critical log for reboot_fs_integrity_test.
+        KLOG_WARNING(LOG_TAG, "Umount /data failed, try to use ioctl to shutdown");
+        if (data_fs_type == "f2fs") {
+            uint32_t flag = F2FS_GOING_DOWN_FULLSYNC;
+            unique_fd fd(TEMP_FAILURE_RETRY(open("/data", O_RDONLY)));
+            LOG(INFO) << "Invoking F2FS_IOC_SHUTDOWN during shutdown";
+            int ret = ioctl(fd.get(), F2FS_IOC_SHUTDOWN, &flag);
+            if (ret) {
+                PLOG(ERROR) << "Shutdown /data: ";
+            } else {
+                LOG(INFO) << "Shutdown /data";
+            }
+        } else if (data_fs_type == "ext4") {
+            uint32_t flag = EXT4_GOING_FLAGS_DEFAULT;
+            unique_fd fd(TEMP_FAILURE_RETRY(open("/data", O_RDONLY)));
+            LOG(INFO) << "Invoking EXT4_IOC_SHUTDOWN during shutdown";
+            int ret = ioctl(fd.get(), EXT4_IOC_SHUTDOWN, &flag);
+            if (ret) {
+                PLOG(ERROR) << "Shutdown /data: ";
+            } else {
+                LOG(INFO) << "Shutdown /data";
+            }
         } else {
-            LOG(INFO) << "Shutdown /data";
+            LOG(ERROR) << "Unknown /data fs type: " << data_fs_type;
         }
     }
+
+    LogShutdownTime(stat, t);
     RebootSystem(cmd, reboot_target, reason);
     abort();
 }
@@ -875,6 +940,21 @@ static bool CommandIsPresent(bootloader_message* boot) {
     return false;
 }
 
+void HandleShutdownRequestedMessage(const std::string& command) {
+    int cmd;
+    Timer t;
+
+    if (command.starts_with("0thermal")) {
+        cmd = ANDROID_RB_THERMOFF;
+    } else if (command.starts_with("0")) {
+        cmd = ANDROID_RB_POWEROFF;
+    } else {
+        cmd = ANDROID_RB_RESTART2;
+    }
+
+    StartRebootMonitorThread(cmd, t);
+}
+
 void HandlePowerctlMessage(const std::string& command) {
     unsigned int cmd = 0;
     std::vector<std::string> cmd_params = Split(command, ",");
diff --git a/init/reboot.h b/init/reboot.h
index 551a114f62..1525b23ba2 100644
--- a/init/reboot.h
+++ b/init/reboot.h
@@ -28,6 +28,8 @@ namespace init {
 // Returns number of violators.
 int StopServicesAndLogViolations(const std::set<std::string>& services,
                                  std::chrono::milliseconds timeout, bool terminate);
+// Parses and handles a setprop sys.shutdown.requested message.
+void HandleShutdownRequestedMessage(const std::string& command);
 // Parses and handles a setprop sys.powerctl message.
 void HandlePowerctlMessage(const std::string& command);
 
diff --git a/init/reboot_utils.cpp b/init/reboot_utils.cpp
index 547b1869f3..85a707bfdb 100644
--- a/init/reboot_utils.cpp
+++ b/init/reboot_utils.cpp
@@ -37,7 +37,7 @@
 namespace android {
 namespace init {
 
-static std::string init_fatal_reboot_target = "bootloader";
+[[clang::no_destroy]] static std::string init_fatal_reboot_target = "bootloader";
 static bool init_fatal_panic = false;
 
 // this needs to read the /proc/* files directly because it is called before
diff --git a/init/rlimit_parser.cpp b/init/rlimit_parser.cpp
index c2a3fa1298..046111f429 100644
--- a/init/rlimit_parser.cpp
+++ b/init/rlimit_parser.cpp
@@ -29,16 +29,17 @@ namespace init {
 
 // Builtins and service definitions both have their arguments start at 1 and finish at 3.
 Result<std::pair<int, rlimit>> ParseRlimit(const std::vector<std::string>& args) {
-    static const std::vector<std::pair<const char*, int>> text_to_resources = {
-            {"cpu", RLIMIT_CPU},           {"fsize", RLIMIT_FSIZE},
-            {"data", RLIMIT_DATA},         {"stack", RLIMIT_STACK},
-            {"core", RLIMIT_CORE},         {"rss", RLIMIT_RSS},
-            {"nproc", RLIMIT_NPROC},       {"nofile", RLIMIT_NOFILE},
-            {"memlock", RLIMIT_MEMLOCK},   {"as", RLIMIT_AS},
-            {"locks", RLIMIT_LOCKS},       {"sigpending", RLIMIT_SIGPENDING},
-            {"msgqueue", RLIMIT_MSGQUEUE}, {"nice", RLIMIT_NICE},
-            {"rtprio", RLIMIT_RTPRIO},     {"rttime", RLIMIT_RTTIME},
-    };
+    [[clang::no_destroy]] static const std::vector<std::pair<const char*, int>> text_to_resources =
+            {
+                    {"cpu", RLIMIT_CPU},           {"fsize", RLIMIT_FSIZE},
+                    {"data", RLIMIT_DATA},         {"stack", RLIMIT_STACK},
+                    {"core", RLIMIT_CORE},         {"rss", RLIMIT_RSS},
+                    {"nproc", RLIMIT_NPROC},       {"nofile", RLIMIT_NOFILE},
+                    {"memlock", RLIMIT_MEMLOCK},   {"as", RLIMIT_AS},
+                    {"locks", RLIMIT_LOCKS},       {"sigpending", RLIMIT_SIGPENDING},
+                    {"msgqueue", RLIMIT_MSGQUEUE}, {"nice", RLIMIT_NICE},
+                    {"rtprio", RLIMIT_RTPRIO},     {"rttime", RLIMIT_RTTIME},
+            };
 
     int resource;
 
diff --git a/init/selinux.cpp b/init/selinux.cpp
index 03fd2d2bf1..081cf6e2a9 100644
--- a/init/selinux.cpp
+++ b/init/selinux.cpp
@@ -68,6 +68,7 @@
 #include <android-base/strings.h>
 #include <android-base/unique_fd.h>
 #include <android/avf_cc_flags.h>
+#include <com_android_apex_flags.h>
 #include <fs_avb/fs_avb.h>
 #include <fs_mgr.h>
 #include <fs_mgr_overlayfs.h>
@@ -484,6 +485,10 @@ void SelinuxRestoreContext() {
     selinux_android_restorecon("/dev/dm-user", SELINUX_ANDROID_RESTORECON_RECURSE);
     selinux_android_restorecon("/dev/device-mapper", 0);
 
+    if constexpr (com::android::apex::flags::mount_before_data()) {
+        selinux_android_restorecon("/dev/loop-control", 0);
+    }
+
     selinux_android_restorecon("/apex", 0);
     selinux_android_restorecon("/bootstrap-apex", 0);
     selinux_android_restorecon("/linkerconfig", 0);
@@ -576,7 +581,8 @@ void MountMissingSystemPartitions() {
         LOG(ERROR) << "Could not read /proc/mounts";
     }
 
-    static const std::vector<std::string> kPartitionNames = {"system_ext", "product"};
+    [[clang::no_destroy]] static const std::vector<std::string> kPartitionNames = {"system_ext",
+                                                                                   "product"};
 
     android::fs_mgr::Fstab extra_fstab;
     for (const auto& name : kPartitionNames) {
@@ -703,8 +709,6 @@ void LoadSelinuxPolicyAndroid() {
 
 #ifdef ALLOW_REMOUNT_OVERLAYS
 bool EarlySetupOverlays() {
-    if (android::fs_mgr::use_override_creds) return false;
-
     bool has_overlays = false;
     std::string contents;
     auto result = android::base::ReadFileToString("/proc/mounts", &contents, true);
diff --git a/init/service.cpp b/init/service.cpp
index 56300205d2..f22e53f379 100644
--- a/init/service.cpp
+++ b/init/service.cpp
@@ -632,6 +632,13 @@ Result<void> Service::Start() {
         return result;
     }
 
+    auto expanded_path = ExpandProps(args_[0]);
+    if (!expanded_path.ok()) {
+        flags_ |= SVC_DISABLED;
+        return ErrnoError() << "Cannot expand path: " << expanded_path.error();
+    }
+    args_[0] = *expanded_path;
+
     struct stat sb;
     if (stat(args_[0].c_str(), &sb) == -1) {
         flags_ |= SVC_DISABLED;
diff --git a/init/service.h b/init/service.h
index 7193d7eb1b..0095c82706 100644
--- a/init/service.h
+++ b/init/service.h
@@ -239,7 +239,7 @@ class Service {
 
     bool updatable_ = false;
 
-    const std::vector<std::string> args_;
+    std::vector<std::string> args_;
 
     std::vector<std::function<void(const siginfo_t& siginfo)>> reap_callbacks_;
 
diff --git a/init/service_parser.cpp b/init/service_parser.cpp
index bd6930065e..8049762b0b 100644
--- a/init/service_parser.cpp
+++ b/init/service_parser.cpp
@@ -543,7 +543,7 @@ Result<void> ServiceParser::ParseUser(std::vector<std::string>&& args) {
 // We can't get these paths from TaskProfiles because profile definitions are changing
 // when we migrate to cgroups v2 while these hardcoded paths stay the same.
 static std::optional<const std::string> ConvertTaskFileToProfile(const std::string& file) {
-    static const std::map<const std::string, const std::string> map = {
+    [[clang::no_destroy]] static const std::map<const std::string, const std::string> map = {
             {"/dev/cpuset/camera-daemon/tasks", "CameraServiceCapacity"},
             {"/dev/cpuset/foreground/tasks", "ProcessCapacityHigh"},
             {"/dev/cpuset/system-background/tasks", "ServiceCapacityLow"},
@@ -579,7 +579,7 @@ Result<void> ServiceParser::ParseUpdatable(std::vector<std::string>&& args) {
 const KeywordMap<ServiceParser::OptionParser>& ServiceParser::GetParserMap() const {
     constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
     // clang-format off
-    static const KeywordMap<ServiceParser::OptionParser> parser_map = {
+    [[clang::no_destroy]] static const KeywordMap<ServiceParser::OptionParser> parser_map = {
         {"capabilities",            {0,     kMax, &ServiceParser::ParseCapabilities}},
         {"class",                   {1,     kMax, &ServiceParser::ParseClass}},
         {"console",                 {0,     1,    &ServiceParser::ParseConsole}},
diff --git a/init/subcontext.cpp b/init/subcontext.cpp
index 3fe448fe34..e2ec35b53c 100644
--- a/init/subcontext.cpp
+++ b/init/subcontext.cpp
@@ -55,9 +55,9 @@ namespace android {
 namespace init {
 namespace {
 
-std::string shutdown_command;
+[[clang::no_destroy]] std::string shutdown_command;
 static bool subcontext_terminated_by_shutdown;
-static std::unique_ptr<Subcontext> subcontext;
+[[clang::no_destroy]] static std::unique_ptr<Subcontext> subcontext;
 
 class SubcontextProcess {
   public:
diff --git a/init/test_reboot_fs_integrity/Android.bp b/init/test_reboot_fs_integrity/Android.bp
new file mode 100644
index 0000000000..ced620f5cb
--- /dev/null
+++ b/init/test_reboot_fs_integrity/Android.bp
@@ -0,0 +1,35 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
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
+    // See: http://go/android-license-faq
+    // A large-scale-change added 'default_applicable_licenses' to import
+    // all of the 'license_kinds' from "system_core_init_license"
+    // to get the below license kinds:
+    //   SPDX-license-identifier-Apache-2.0
+    default_applicable_licenses: ["system_core_init_license"],
+}
+
+java_test_host {
+    name: "reboot_fs_integrity_test",
+    srcs: ["src/**/*.java"],
+    libs: [
+        "tradefed",
+        "compatibility-host-util",
+    ],
+    test_config: "AndroidTest.xml",
+    test_suites: ["general-tests"],
+}
diff --git a/init/test_reboot_fs_integrity/AndroidTest.xml b/init/test_reboot_fs_integrity/AndroidTest.xml
new file mode 100644
index 0000000000..fb3392797e
--- /dev/null
+++ b/init/test_reboot_fs_integrity/AndroidTest.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Runs the Reboot fs integrity tests">
+    <option name="test-suite-tag" value="apct" />
+    <option name="test-suite-tag" value="apct-native" />
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
+    <test class="com.android.tradefed.testtype.HostTest" >
+        <option name="class" value="com.android.tests.init.RebootFsIntegrityTest" />
+    </test>
+</configuration>
diff --git a/init/test_reboot_fs_integrity/OWNERS b/init/test_reboot_fs_integrity/OWNERS
new file mode 100644
index 0000000000..184b9a999f
--- /dev/null
+++ b/init/test_reboot_fs_integrity/OWNERS
@@ -0,0 +1 @@
+yuanyaogoog@google.com
diff --git a/init/test_reboot_fs_integrity/src/com/android/tests/init/RebootFsIntegrityTest.java b/init/test_reboot_fs_integrity/src/com/android/tests/init/RebootFsIntegrityTest.java
new file mode 100644
index 0000000000..d4f8b82a0e
--- /dev/null
+++ b/init/test_reboot_fs_integrity/src/com/android/tests/init/RebootFsIntegrityTest.java
@@ -0,0 +1,95 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.tests.init;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import static org.junit.Assume.assumeTrue;
+
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.io.BufferedReader;
+import java.io.File;
+import java.io.FileReader;
+import java.io.IOException;
+import java.util.Arrays;
+import java.util.List;
+import java.util.regex.Matcher;
+import java.util.regex.Pattern;
+
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class RebootFsIntegrityTest extends BaseHostJUnit4Test {
+    private ITestDevice mDevice;
+
+    private final List<String> pstorePaths = Arrays.asList(
+            "/sys/fs/pstore/console-ramoops-0",
+            "/sys/fs/pstore/console-ramoops"
+    );
+    private final List<String> mErrorPatterns = Arrays.asList(
+            "Umount /data failed, try to use ioctl to shutdown",
+            "umount timeout, last resort, kill all and try"
+    );
+
+    @Before
+    public void setUp() throws Exception {
+        mDevice = getDevice();
+    }
+
+    @Test
+    public void rebootFsIntegrity() throws Exception {
+        mDevice.reboot("Reboot to check logs in pstore");
+        File pstoreFile = tryGetPstoreFile();
+        assumeTrue("Skip test: pstore console log is not available", pstoreFile != null);
+        assertThat(findUmountError(pstoreFile)).isEqualTo(null);
+    }
+
+    private File tryGetPstoreFile() throws Exception {
+        for (String pathString : pstorePaths) {
+            // possible kernel console output paths to check
+            // Check if the current file exists
+            if (mDevice.doesFileExist(pathString)) {
+                return mDevice.pullFile(pathString);
+            }
+        }
+        return null;
+    }
+
+    // Return umount error message if found in logFile, if there's no any error
+    // found, return null.
+    private String findUmountError(File logFile) {
+        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
+            String line;
+            while ((line = reader.readLine()) != null) {
+                for (String pattern : mErrorPatterns) {
+                    if (line.contains(pattern)) {
+                        return pattern;
+                    }
+                }
+            }
+        } catch (IOException e) {
+            return "Error reading log file: " + e.getMessage();
+        }
+        return null;
+    }
+}
diff --git a/init/uevent.h b/init/uevent.h
index e7ed2266e5..3ae8f9a0fb 100644
--- a/init/uevent.h
+++ b/init/uevent.h
@@ -35,6 +35,7 @@ struct Uevent {
     int partition_num;
     int major;
     int minor;
+    long long seqnum;
 };
 
 }  // namespace init
diff --git a/init/uevent_dependency_graph.cpp b/init/uevent_dependency_graph.cpp
new file mode 100644
index 0000000000..a60c88a892
--- /dev/null
+++ b/init/uevent_dependency_graph.cpp
@@ -0,0 +1,142 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "uevent_dependency_graph.h"
+
+#include <condition_variable>
+#include <mutex>
+#include <optional>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/thread_annotations.h>
+
+namespace android {
+namespace init {
+
+/**
+ * Finds the sequence number of the latest event that the given uevent depends on.
+ * Dependencies arise from:
+ * 1. Ancestor devices (e.g., "devices/block/sda" must be processed before
+ *    "devices/block/sda/sda1").
+ * 2. Descendant devices for "remove" actions (e.g., "devices/block/sda/sda1" must be removed
+ *    before "devices/block/sda").
+ * 3. Events for the identical device path with a lower sequence number.
+ * Note rename events are not processed currently since it's not processed in the main ueventd.
+ */
+std::optional<UeventDependencyGraph::seqnum_t> UeventDependencyGraph::FindDependency(
+        const Uevent& uevent) {
+    int max_seqnum = -1;
+
+    // e.g. devices/virtual/mac80211_hwsim/hwsim0 is descendant of devices/virtual/mac80211_hwsim.
+    // They immediately follow uevent.path in the sorted event_paths_ map.
+    auto descendant = event_paths_.upper_bound({uevent.path, uevent.seqnum});
+    while (descendant != event_paths_.end() && descendant->first.starts_with(uevent.path)) {
+        if (descendant->second < uevent.seqnum && descendant->second > max_seqnum) {
+            max_seqnum = descendant->second;
+        }
+        descendant++;
+    }
+
+    // Find events of ancestor devices and the identical device with lower seqnum.
+    // e.g. devices/some_device is descendant of devices/some_device/wakeup
+    for (auto ancestor = uevent.path; ancestor != "/" && ancestor != ".";
+         ancestor = base::Dirname(ancestor)) {
+        auto it = event_paths_.upper_bound({ancestor, uevent.seqnum});
+        if (it == event_paths_.begin()) {
+            continue;
+        }
+        it--;
+        if (it->first == ancestor && it->second > max_seqnum) {
+            max_seqnum = it->second;
+        }
+    }
+
+    if (max_seqnum == -1) {
+        return std::nullopt;
+    } else {
+        return {max_seqnum};
+    }
+}
+
+void UeventDependencyGraph::Add(Uevent uevent) {
+    bool should_wake_thread = false;
+    {
+        std::lock_guard<std::mutex> lock(graph_lock_);
+        std::optional<UeventDependencyGraph::seqnum_t> dependency = FindDependency(uevent);
+        if (dependency) {
+            dependencies_.emplace(dependency.value(), uevent.seqnum);
+        } else {
+            dependency_free_events_.emplace(uevent.seqnum);
+            should_wake_thread = true;
+        }
+        event_paths_.emplace(uevent.path, uevent.seqnum);
+        events_.emplace(uevent.seqnum, std::move(uevent));
+    }
+    if (should_wake_thread) {
+        graph_condvar_.notify_one();
+    }
+}
+
+std::optional<Uevent> UeventDependencyGraph::PopDependencyFreeEventWithoutLock() {
+    if (dependency_free_events_.empty()) {
+        return std::nullopt;
+    }
+    auto seqnum = dependency_free_events_.front();
+    dependency_free_events_.pop();
+    return events_.find(seqnum)->second;
+}
+
+std::optional<Uevent> UeventDependencyGraph::PopDependencyFreeEvent() {
+    std::lock_guard<std::mutex> lock(graph_lock_);
+    return PopDependencyFreeEventWithoutLock();
+}
+
+Uevent UeventDependencyGraph::WaitDependencyFreeEvent() {
+    std::unique_lock<std::mutex> lock(graph_lock_);
+    // Assertion is required to make thread safety annotations work well with a unique_lock
+    base::ScopedLockAssertion mutex_lock_assertion(graph_lock_);
+
+    if (dependency_free_events_.empty()) {
+        graph_condvar_.wait(lock, [this] {
+            base::ScopedLockAssertion mutex_lock_assertion(graph_lock_);
+            return !dependency_free_events_.empty();
+        });
+    }
+
+    return PopDependencyFreeEventWithoutLock().value();
+}
+
+void UeventDependencyGraph::MarkEventCompleted(seqnum_t seqnum) {
+    bool should_wake_thread = false;
+    {
+        std::lock_guard<std::mutex> lock(graph_lock_);
+        auto dependency = dependencies_.equal_range(seqnum);
+        for (auto it = dependency.first; it != dependency.second; ++it) {
+            dependency_free_events_.emplace(it->second);
+            should_wake_thread = true;
+        }
+        dependencies_.erase(dependency.first, dependency.second);
+        event_paths_.erase({events_.find(seqnum)->second.path, seqnum});
+        events_.erase(seqnum);
+    }
+    if (should_wake_thread) {
+        graph_condvar_.notify_one();
+    }
+}
+
+}  // namespace init
+}  // namespace android
diff --git a/init/uevent_dependency_graph.h b/init/uevent_dependency_graph.h
new file mode 100644
index 0000000000..b27c3bbc31
--- /dev/null
+++ b/init/uevent_dependency_graph.h
@@ -0,0 +1,121 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#pragma once
+
+#include <condition_variable>
+#include <map>
+#include <queue>
+#include <set>
+
+#include <android-base/thread_annotations.h>
+
+#include "uevent.h"
+
+namespace android {
+namespace init {
+
+/**
+ * Manages dependencies between uevents to ensure they are processed in the correct order.
+ *
+ * Uevents often have dependencies based on their device path. For example, a child device's
+ * uevent should typically be processed only after its parent device's uevent has been processed.
+ * Similarly, events for the same device should be processed sequentially based on their sequence
+ * number.
+ *
+ * This class builds a dependency graph based on device paths and sequence numbers. It allows
+ * adding new uevents and retrieving events that have no outstanding dependencies, ready for
+ * processing. Once an event is processed, it should be marked as completed to unblock any
+ * dependent events.
+ *
+ * This class is thread-safe.
+ */
+class UeventDependencyGraph {
+    using seqnum_t = long long;
+
+  public:
+    UeventDependencyGraph() = default;
+
+    /**
+     * Adds a new uevent to the dependency graph.
+     *
+     * @param uevent The uevent to add to the graph.
+     */
+    void Add(Uevent uevent);
+
+    /**
+     * Retrieves and removes a uevent that has no outstanding dependencies.
+     *
+     * This method returns any uevents ready for processing (i.e., all their
+     * dependencies have been met).  If no events are ready, it returns std::nullopt immediately.
+     *
+     * @return An optional containing a dependency-free uevent if one is available, otherwise
+     * std::nullopt.
+     */
+    std::optional<Uevent> PopDependencyFreeEvent();
+
+    /**
+     * Waits until a dependency-free uevent is available, then retrieves and removes it.
+     *
+     * If no dependency-free events are currently available, this method blocks until one becomes
+     * available (due to a call to Add() or MarkEventCompleted()).
+     *
+     * @return The next available dependency-free uevent.
+     */
+    Uevent WaitDependencyFreeEvent();
+
+    /**
+     * Marks a uevent as completed, potentially unblocking dependent events.
+     *
+     * @param seqnum The sequence number of the uevent that has been completed.
+     */
+    void MarkEventCompleted(seqnum_t seqnum);
+
+  private:
+    /**
+     * Finds the sequence number of the latest event that the given uevent depends on.
+     *
+     * @param uevent The uevent to find dependencies for.
+     * @return An optional containing the sequence number of the dependency if found, otherwise
+     * std::nullopt.
+     */
+    std::optional<seqnum_t> FindDependency(const Uevent& uevent)
+            EXCLUSIVE_LOCKS_REQUIRED(graph_lock_);
+
+    /**
+     * Internal implementation of PopDependencyFreeEvent without locking.
+     * Assumes the caller holds the graph_lock_.
+     *
+     * @return An optional containing a dependency-free uevent if one is available, otherwise
+     * std::nullopt.
+     */
+    std::optional<Uevent> PopDependencyFreeEventWithoutLock() EXCLUSIVE_LOCKS_REQUIRED(graph_lock_);
+
+    std::condition_variable graph_condvar_;
+    std::mutex graph_lock_;
+    // Stores all uevents currently in the graph, keyed by sequence number.
+    std::map<seqnum_t, Uevent> events_ GUARDED_BY(graph_lock_);
+    // Queue of events that are ready to be processed.
+    std::queue<seqnum_t> dependency_free_events_ GUARDED_BY(graph_lock_);
+    // Multimap storing dependencies: key is the sequence number of the prerequisite event,
+    // value is the sequence number of the dependent event.
+    std::multimap<seqnum_t, seqnum_t> dependencies_ GUARDED_BY(graph_lock_);
+    // Set storing pairs of (device path, sequence number) for efficient dependency lookup.
+    std::set<std::pair<std::string, seqnum_t>> event_paths_ GUARDED_BY(graph_lock_);
+};
+
+}  // namespace init
+}  // namespace android
diff --git a/init/uevent_dependency_graph_test.cpp b/init/uevent_dependency_graph_test.cpp
new file mode 100644
index 0000000000..fc8998a114
--- /dev/null
+++ b/init/uevent_dependency_graph_test.cpp
@@ -0,0 +1,295 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "uevent_dependency_graph.h"
+
+#include <cstdlib>
+#include <mutex>
+#include <optional>
+#include <thread>
+
+#include <gtest/gtest.h>
+
+#include "uevent.h"
+
+namespace android {
+namespace init {
+
+TEST(UeventDependencyGraphTest, NoDependency) {
+    UeventDependencyGraph graph;
+    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
+    Uevent uevent2 = {.action = "add", .path = "devices/block/sdb", .seqnum = 2};
+
+    graph.Add(uevent1);
+    graph.Add(uevent2);
+
+    std::optional<Uevent> result1 = graph.PopDependencyFreeEvent();
+    std::optional<Uevent> result2 = graph.PopDependencyFreeEvent();
+
+    EXPECT_TRUE(result1.has_value());
+    EXPECT_TRUE(result2.has_value());
+    EXPECT_EQ(1, result1->seqnum);
+    EXPECT_EQ(2, result2->seqnum);
+}
+
+TEST(UeventDependencyGraphTest, AncestorDependencies) {
+    UeventDependencyGraph graph;
+    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
+    Uevent uevent2 = {.action = "add", .path = "devices/block/sda/child1", .seqnum = 2};
+    Uevent uevent3 = {.action = "add", .path = "devices/block/sda/child2", .seqnum = 3};
+    Uevent uevent4 = {.action = "add", .path = "devices/block/sda/child1/grandchild", .seqnum = 4};
+
+    graph.Add(uevent1);
+    graph.Add(uevent2);
+    graph.Add(uevent3);
+    graph.Add(uevent4);
+
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent1.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent2.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent3.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent2.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent4.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+}
+
+TEST(UeventDependencyGraphTest, DescendantDependencies) {
+    UeventDependencyGraph graph;
+    Uevent uevent1 = {
+            .action = "remove", .path = "devices/block/sda/child1/grandchild", .seqnum = 1};
+    Uevent uevent2 = {.action = "remove", .path = "devices/block/sda/child1", .seqnum = 2};
+    Uevent uevent3 = {.action = "remove", .path = "devices/block/sda", .seqnum = 3};
+
+    graph.Add(uevent1);
+    graph.Add(uevent2);
+    graph.Add(uevent3);
+
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent1.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent2.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent2.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent3.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+}
+
+TEST(UeventDependencyGraphTest, IdenticalEventDependencies) {
+    UeventDependencyGraph graph;
+    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
+    Uevent uevent2 = {.action = "change", .path = "devices/block/sda", .seqnum = 2};
+    Uevent uevent3 = {.action = "remove", .path = "devices/block/sda", .seqnum = 3};
+
+    graph.Add(uevent1);
+    graph.Add(uevent2);
+    graph.Add(uevent3);
+
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent1.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent2.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent2.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent3.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+}
+
+TEST(UeventDependencyGraphTest, MixedDependencies) {
+    UeventDependencyGraph graph;
+    Uevent uevent = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
+    Uevent uevent_child_dep = {
+            .action = "add", .path = "devices/block/sda/child_dependency", .seqnum = 2};
+    Uevent uevent_parent_dep = {.action = "change", .path = "devices/block/sda", .seqnum = 3};
+    Uevent uevent_self_dep = {.action = "remove", .path = "devices/block/sda", .seqnum = 4};
+    Uevent uevent_no_dependency = {.action = "add", .path = "devices/snd/foo", .seqnum = 5};
+
+    graph.Add(uevent);
+    graph.Add(uevent_child_dep);
+    graph.Add(uevent_parent_dep);
+    graph.Add(uevent_self_dep);
+    graph.Add(uevent_no_dependency);
+
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_no_dependency.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_child_dep.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent_child_dep.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_parent_dep.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent_parent_dep.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_self_dep.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent_self_dep.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+}
+
+TEST(UeventDependencyGraphTest, DependsOnLaterEventsNotOnEarlier) {
+    UeventDependencyGraph graph;
+    Uevent uevent = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
+    Uevent uevent_child_add = {
+            .action = "add", .path = "devices/block/sda/child_dependency", .seqnum = 2};
+    Uevent uevent_grandchild_add1 = {
+            .action = "add", .path = "devices/block/sda/child_dependency", .seqnum = 3};
+    Uevent uevent_removal = {.action = "remove", .path = "devices/block/sda", .seqnum = 4};
+    Uevent uevent_grandchild_add2 = {
+            .action = "add", .path = "devices/block/sda/child_dependency/grandchild", .seqnum = 5};
+
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    graph.Add(uevent);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    // New events should not be immediately available due to the dependency.
+    graph.Add(uevent_child_add);
+    graph.Add(uevent_grandchild_add1);
+    graph.Add(uevent_removal);
+    graph.Add(uevent_grandchild_add2);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    // Should kick only uevent_child_add
+    graph.MarkEventCompleted(uevent.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_child_add.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    // Should kick only uevent_grandchild_add1
+    graph.MarkEventCompleted(uevent_child_add.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_grandchild_add1.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    // Should kick only uevent_removal
+    graph.MarkEventCompleted(uevent_grandchild_add1.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_removal.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    // Should kick only uevent_grandchild_add2
+    graph.MarkEventCompleted(uevent_removal.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_grandchild_add2.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    // No more events should be available
+    graph.MarkEventCompleted(uevent_grandchild_add2.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+}
+
+TEST(UeventDependencyGraphTest, PushEventsWithDependencyOnPending) {
+    UeventDependencyGraph graph;
+    Uevent uevent = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
+    Uevent uevent_child_dep = {
+            .action = "add", .path = "devices/block/sda/child_dependency", .seqnum = 2};
+    Uevent uevent_grandchild_dep1 = {
+            .action = "add",
+            .path = "devices/block/sda/child_dependency/grandchild_dependency1",
+            .seqnum = 3};
+    Uevent uevent_grandchild_dep2 = {
+            .action = "add",
+            .path = "devices/block/sda/child_dependency/grandchild_dependency2",
+            .seqnum = 4};
+
+    graph.Add(uevent);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    graph.Add(uevent_child_dep);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.MarkEventCompleted(uevent.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_child_dep.seqnum);
+
+    graph.Add(uevent_grandchild_dep1);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+    graph.Add(uevent_grandchild_dep2);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    graph.MarkEventCompleted(uevent_child_dep.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_grandchild_dep1.seqnum);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_grandchild_dep2.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+}
+
+TEST(UeventDependencyGraphTest, WaitDependencyFreeEventBlocksUntilDependencyIsMet) {
+    UeventDependencyGraph graph;
+    bool t_started = false;
+    std::mutex m;
+    std::condition_variable cv;
+
+    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
+    Uevent uevent2 = {.action = "add", .path = "devices/block/sda/child", .seqnum = 2};
+    Uevent uevent3 = {.action = "add", .path = "devices/block/sda/child/grandchild", .seqnum = 3};
+
+    graph.Add(uevent1);
+    graph.Add(uevent2);
+    graph.Add(uevent3);
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    std::thread t([&graph, &uevent2, &t_started, &m, &cv]() {
+        m.lock();
+        t_started = true;
+        m.unlock();
+        cv.notify_all();
+        // Should wait until uevent2 is available
+        EXPECT_EQ(graph.WaitDependencyFreeEvent().seqnum, uevent2.seqnum);
+        // Unblock uevent3
+        graph.MarkEventCompleted(uevent2.seqnum);
+    });
+
+    // Wait for the thread to start, which waits for uevent2
+    std::unique_lock<std::mutex> lock(m);
+    cv.wait(lock, [&t_started] { return t_started; });
+    lock.unlock();
+    // Kick the uevent2 for the thread
+    graph.MarkEventCompleted(uevent1.seqnum);
+    t.join();
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent3.seqnum);
+}
+
+TEST(UeventDependencyGraphTest, WaitDependencyFreeEventReturnsIfDependencyFreeOneIsAvailable) {
+    UeventDependencyGraph graph;
+    bool t_started = false;
+    std::mutex m;
+    std::condition_variable cv;
+
+    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
+    Uevent uevent2 = {.action = "add", .path = "devices/block/sda/child", .seqnum = 2};
+    Uevent uevent3 = {.action = "add", .path = "devices/block/sda/child/grandchild", .seqnum = 3};
+
+    graph.Add(uevent1);
+    graph.Add(uevent2);
+    graph.Add(uevent3);
+
+    // No dependency free events are available until uevent1 is processed
+    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+
+    // Should kick uevent2 and WaitDependencyFreeEvent immediately returns it.
+    graph.MarkEventCompleted(uevent1.seqnum);
+    EXPECT_EQ(graph.WaitDependencyFreeEvent().seqnum, uevent2.seqnum);
+
+    // Should kick uevent3 and WaitDependencyFreeEvent immediately returns it.
+    graph.MarkEventCompleted(uevent2.seqnum);
+    EXPECT_EQ(graph.WaitDependencyFreeEvent().seqnum, uevent3.seqnum);
+
+    // No more events should be available
+    graph.MarkEventCompleted(uevent3.seqnum);
+    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
+}
+
+}  // namespace init
+}  // namespace android
diff --git a/init/uevent_listener.cpp b/init/uevent_listener.cpp
index d329c174fa..a7ecd43377 100644
--- a/init/uevent_listener.cpp
+++ b/init/uevent_listener.cpp
@@ -33,6 +33,7 @@ static void ParseEvent(const char* msg, Uevent* uevent) {
     uevent->partition_num = -1;
     uevent->major = -1;
     uevent->minor = -1;
+    uevent->seqnum = -1;
     uevent->action.clear();
     uevent->path.clear();
     uevent->subsystem.clear();
@@ -41,7 +42,6 @@ static void ParseEvent(const char* msg, Uevent* uevent) {
     uevent->partition_name.clear();
     uevent->device_name.clear();
     uevent->modalias.clear();
-    // currently ignoring SEQNUM
     while (*msg) {
         if (!strncmp(msg, "ACTION=", 7)) {
             msg += 7;
@@ -67,6 +67,9 @@ static void ParseEvent(const char* msg, Uevent* uevent) {
         } else if (!strncmp(msg, "PARTN=", 6)) {
             msg += 6;
             uevent->partition_num = atoi(msg);
+        } else if (!strncmp(msg, "SEQNUM=", 7)) {
+            msg += 7;
+            uevent->seqnum = atoll(msg);
         } else if (!strncmp(msg, "PARTNAME=", 9)) {
             msg += 9;
             uevent->partition_name = msg;
diff --git a/init/ueventd.cpp b/init/ueventd.cpp
index cb6b851d68..4c224abb66 100644
--- a/init/ueventd.cpp
+++ b/init/ueventd.cpp
@@ -43,6 +43,7 @@
 #include "modalias_handler.h"
 #include "selabel.h"
 #include "selinux.h"
+#include "uevent_dependency_graph.h"
 #include "uevent_handler.h"
 #include "uevent_listener.h"
 #include "ueventd_parser.h"
@@ -68,14 +69,17 @@
 // time during cold boot.
 
 // Handling of uevent messages has two unique properties:
-// 1) It can be done in isolation; it doesn't need to read or write any status once it is started.
-// 2) It uses setegid() and setfscreatecon() so either care (aka locking) must be taken to ensure
-//    that no file system operations are done while the uevent process has an abnormal egid or
-//    fscreatecon or this handling must happen in a separate process.
-// Given the above two properties, it is best to fork() subprocesses to handle the uevents.  This
-// reduces the overhead and complexity that would be required in a solution with threads and locks.
-// In testing, a racy multithreaded solution has the same performance as the fork() solution, so
-// there is no reason to deal with the complexity of the former.
+// 1) Messages can be handled in isolation when they do not depend on another. A device event
+//    depends on another when the device is the same, parent, or child of another device which
+//    should be handled first by another event. e.g. An add event must be handled first before
+//    removal. A device foo must be added before foo/bar.
+// 2) The cold boot is unlikely to have events that depend on another in a critical manner.
+// Therefore, ueventd handles uevent message in parallel by fork() subprocesses. We chose fork()
+// instead of threads, since selabel_lookup_best_match function was not thread-safe. It's
+// been fixed today, and we are testing the thread-safety of selabel_lookup_best_match and other
+// necessary functions (setfscreatecon and setegid syscall wrapper of bionic) in ueventd_test.
+// However, we have not moved to thread-based parallelization. We didn't observe any significant
+// performance gain with threads compared to multi-processes, and multi-process is simpler.
 
 // One other important caveat during the boot process is the handling of SELinux restorecon.
 // Since many devices have child devices, calling selinux_android_restorecon() recursively for each
@@ -334,6 +338,42 @@ static UeventdConfiguration GetConfiguration() {
     return ParseConfig(canonical);
 }
 
+void main_loop(const UeventListener& uevent_listener,
+               const std::vector<std::unique_ptr<UeventHandler>>& uevent_handlers) {
+    uevent_listener.Poll([&uevent_handlers](const Uevent& uevent) {
+        for (auto& uevent_handler : uevent_handlers) {
+            uevent_handler->HandleUevent(uevent);
+        }
+        return ListenerAction::kContinue;
+    });
+}
+
+void parallel_main_loop(const UeventListener& uevent_listener,
+                        const std::vector<std::unique_ptr<UeventHandler>>& uevent_handlers,
+                        size_t num_threads) {
+    LOG(INFO) << "parallel main loop is enabled with " << num_threads << " threads";
+
+    std::vector<std::thread> threads;
+    UeventDependencyGraph graph;
+
+    for (unsigned int i = 0; i < num_threads; i++) {
+        threads.emplace_back([&graph, &uevent_handlers] {
+            while (true) {
+                auto uevent = graph.WaitDependencyFreeEvent();
+                for (auto& uevent_handler : uevent_handlers) {
+                    uevent_handler->HandleUevent(uevent);
+                }
+                graph.MarkEventCompleted(uevent.seqnum);
+            }
+        });
+    }
+
+    uevent_listener.Poll([&graph](const Uevent& uevent) {
+        graph.Add(uevent);
+        return ListenerAction::kContinue;
+    });
+}
+
 int ueventd_main(int argc, char** argv) {
     /*
      * init sets the umask to 077 for forked processes. We need to
@@ -374,7 +414,8 @@ int ueventd_main(int argc, char** argv) {
     uevent_handlers.emplace_back(std::move(device_handler));
     uevent_handlers.emplace_back(std::make_unique<FirmwareHandler>(
             std::move(ueventd_configuration.firmware_directories),
-            std::move(ueventd_configuration.external_firmware_handlers)));
+            std::move(ueventd_configuration.external_firmware_handlers),
+            /*serial_handler_after_cold_boot=*/false));
 
     if (ueventd_configuration.enable_modalias_handling) {
         std::vector<std::string> base_paths = {"/odm/lib/modules", "/vendor/lib/modules"};
@@ -400,14 +441,21 @@ int ueventd_main(int argc, char** argv) {
 
     // Restore prio before main loop
     setpriority(PRIO_PROCESS, 0, 0);
-    uevent_listener.Poll([&uevent_handlers](const Uevent& uevent) {
-        for (auto& uevent_handler : uevent_handlers) {
-            uevent_handler->HandleUevent(uevent);
+
+    if (ueventd_configuration.enable_parallel_ueventd_main_loop) {
+        size_t num_threads =
+                std::thread::hardware_concurrency() != 0 ? std::thread::hardware_concurrency() : 4;
+        if (ueventd_configuration.parallel_main_loop_max_workers.has_value()) {
+            num_threads = std::min(num_threads,
+                                   ueventd_configuration.parallel_main_loop_max_workers.value());
         }
-        return ListenerAction::kContinue;
-    });
+        parallel_main_loop(uevent_listener, uevent_handlers, num_threads);
+    } else {
+        main_loop(uevent_listener, uevent_handlers);
+    }
 
-    return 0;
+    LOG(ERROR) << "main loop exited unexpectedly";
+    return EXIT_FAILURE;
 }
 
 }  // namespace init
diff --git a/init/ueventd_parser.cpp b/init/ueventd_parser.cpp
index 097ef09d7b..ad475fc184 100644
--- a/init/ueventd_parser.cpp
+++ b/init/ueventd_parser.cpp
@@ -178,6 +178,23 @@ Result<void> ParseUeventSocketRcvbufSizeLine(std::vector<std::string>&& args,
     return {};
 }
 
+Result<void> ParseMainLoopMaxWorkers(std::vector<std::string>&& args,
+                                     std::optional<size_t>* max_workers) {
+    if (args.size() != 2) {
+        return Error() << "parallel_ueventd_main_loop_max_workers lines take exactly one parameter";
+    }
+
+    size_t parsed_worker_num;
+    if (!ParseByteCount(args[1], &parsed_worker_num)) {
+        return Error() << "could not parse size '" << args[1]
+                       << "' for parallel_ueventd_main_loop_max_workers";
+    }
+
+    *max_workers = parsed_worker_num;
+
+    return {};
+}
+
 class SubsystemParser : public SectionParser {
   public:
     SubsystemParser(std::vector<Subsystem>* subsystems) : subsystems_(subsystems) {}
@@ -291,6 +308,12 @@ UeventdConfiguration ParseConfig(const std::vector<std::string>& configs) {
     parser.AddSingleLineParser("parallel_restorecon",
                                std::bind(ParseEnabledDisabledLine, _1,
                                          &ueventd_configuration.enable_parallel_restorecon));
+    parser.AddSingleLineParser("parallel_ueventd_main_loop_max_workers",
+                               std::bind(ParseMainLoopMaxWorkers, _1,
+                                         &ueventd_configuration.parallel_main_loop_max_workers));
+    parser.AddSingleLineParser("parallel_ueventd_main_loop",
+                               std::bind(ParseEnabledDisabledLine, _1,
+                                         &ueventd_configuration.enable_parallel_ueventd_main_loop));
 
     for (const auto& config : configs) {
         parser.ParseConfig(config);
diff --git a/init/ueventd_parser.h b/init/ueventd_parser.h
index ffe6072dfe..b0cc7b6405 100644
--- a/init/ueventd_parser.h
+++ b/init/ueventd_parser.h
@@ -36,6 +36,8 @@ struct UeventdConfiguration {
     bool enable_modalias_handling = false;
     size_t uevent_socket_rcvbuf_size = 0;
     bool enable_parallel_restorecon = false;
+    bool enable_parallel_ueventd_main_loop = false;
+    std::optional<size_t> parallel_main_loop_max_workers;
 };
 
 UeventdConfiguration ParseConfig(const std::vector<std::string>& configs);
diff --git a/init/util.cpp b/init/util.cpp
index 375e905d50..2c84edc6e4 100644
--- a/init/util.cpp
+++ b/init/util.cpp
@@ -689,7 +689,7 @@ bool Has32BitAbi() {
 }
 
 std::string GetApexNameFromFileName(const std::string& path) {
-    static const std::string kApexDir = "/apex/";
+    [[clang::no_destroy]] static const std::string kApexDir = "/apex/";
     if (StartsWith(path, kApexDir)) {
         auto begin = kApexDir.size();
         auto end = path.find('/', begin);
diff --git a/libcutils/ashmem-dev.cpp b/libcutils/ashmem-dev.cpp
index 80c4f4c1ea..2fcb6bfebb 100644
--- a/libcutils/ashmem-dev.cpp
+++ b/libcutils/ashmem-dev.cpp
@@ -16,11 +16,6 @@
 
 #include <cutils/ashmem.h>
 
-/*
- * Implementation of the user-space ashmem API for devices, which have our
- * ashmem-enabled kernel. See ashmem-sim.c for the "fake" tmp-based version,
- * used by the simulator.
- */
 #define LOG_TAG "ashmem"
 
 #include <errno.h>
@@ -28,9 +23,6 @@
 #include <linux/ashmem.h>
 #include <linux/memfd.h>
 #include <log/log.h>
-#include <pthread.h>
-#include <stdio.h>
-#include <string.h>
 #include <sys/ioctl.h>
 #include <sys/mman.h>
 #include <sys/stat.h>
@@ -46,66 +38,30 @@
 
 #include "ashmem-internal.h"
 
-/* ashmem identity */
-static dev_t __ashmem_rdev;
-/*
- * If we trigger a signal handler in the middle of locked activity and the
- * signal handler calls ashmem, we could get into a deadlock state.
- */
-static pthread_mutex_t __ashmem_lock = PTHREAD_MUTEX_INITIALIZER;
+#include <atomic>
 
 /*
- * has_memfd_support() determines if the device can use memfd. memfd support
- * has been there for long time, but certain things in it may be missing.  We
- * check for needed support in it. Also we check if the VNDK version of
- * libcutils being used is new enough, if its not, then we cannot use memfd
- * since the older copies may be using ashmem so we just use ashmem. Once all
- * Android devices that are getting updates are new enough (ex, they were
- * originally shipped with Android release > P), then we can just use memfd and
- * delete all ashmem code from libcutils (while preserving the interface).
+ * Implementation of the userspace ashmem API for devices.
  *
- * NOTE:
- * The sys.use_memfd property is set by default to false in Android
- * to temporarily disable memfd, till vendor and apps are ready for it.
- * The main issue: either apps or vendor processes can directly make ashmem
- * IOCTLs on FDs they receive by assuming they are ashmem, without going
- * through libcutils. Such fds could have very well be originally created with
- * libcutils hence they could be memfd. Thus the IOCTLs will break.
+ * This may use ashmem or memfd. See has_memfd_support().
  *
- * Set default value of sys.use_memfd property to true once the issue is
- * resolved, so that the code can then self-detect if kernel support is present
- * on the device. The property can also set to true from adb shell, for
- * debugging.
+ * See ashmem-host.cpp for the temporary file based alternative for the host.
  */
 
+/* ashmem identity */
+static std::atomic<dev_t> __ashmem_rdev;
+
 /* set to true for verbose logging and other debug  */
 static bool debug_log = false;
 
-/* Determine if vendor processes would be ok with memfd in the system:
- *
- * Previously this function checked if memfd is supported by checking if
- * vendor VNDK version is greater than Q. As we can assume all treblelized
- * device using this code is up to date enough to use memfd, memfd is allowed
- * if the device is treblelized.
- */
-static bool check_vendor_memfd_allowed() {
-    static bool is_treblelized = android::base::GetBoolProperty("ro.treble.enabled", false);
-
-    return is_treblelized;
-}
-
 /* Determine if memfd can be supported. This is just one-time hardwork
  * which will be cached by the caller.
  */
 static bool __has_memfd_support() {
-    if (check_vendor_memfd_allowed() == false) {
-        return false;
-    }
-
-    /* Used to turn on/off the detection at runtime, in the future this
-     * property will be removed once we switch everything over to ashmem.
-     * Currently it is used only for debugging to switch the system over.
-     */
+    // Used to turn on/off the detection at runtime, in the future this
+    // property will be removed once we switch everything over to memfd.
+    //
+    // This can be set to true from the adb shell for debugging.
     if (!android::base::GetBoolProperty("sys.use_memfd", false)) {
         if (debug_log) {
             ALOGD("sys.use_memfd=false so memfd disabled");
@@ -113,31 +69,30 @@ static bool __has_memfd_support() {
         return false;
     }
 
-    // Check if kernel support exists, otherwise fall back to ashmem.
-    // This code needs to build on old API levels, so we can't use the libc
-    // wrapper.
+    // Check that the kernel supports memfd_create().
+    // This code needs to build on API levels before 30,
+    // so we can't use the libc wrapper.
     android::base::unique_fd fd(
             syscall(__NR_memfd_create, "test_android_memfd", MFD_CLOEXEC | MFD_ALLOW_SEALING));
     if (fd == -1) {
-        ALOGE("memfd_create failed: %m, no memfd support");
+        ALOGE("memfd_create() failed: %m, no memfd support");
         return false;
     }
 
+    // Check that the kernel supports sealing.
     if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == -1) {
         ALOGE("fcntl(F_ADD_SEALS) failed: %m, no memfd support");
         return false;
     }
 
+    // Check that the kernel supports truncation.
     size_t buf_size = getpagesize();
     if (ftruncate(fd, buf_size) == -1) {
         ALOGE("ftruncate(%zd) failed to set memfd buffer size: %m, no memfd support", buf_size);
         return false;
     }
 
-    /*
-     * Ensure that the kernel supports ashmem ioctl commands on memfds. If not,
-     * fall back to using ashmem.
-     */
+    // Check that the kernel supports the ashmem ioctls on a memfd.
     int ashmem_size = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, 0));
     if (ashmem_size != static_cast<int>(buf_size)) {
         ALOGE("ioctl(ASHMEM_GET_SIZE): %d != buf_size: %zd , no ashmem-memfd compat support",
@@ -168,8 +123,7 @@ static std::string get_ashmem_device_path() {
     return "/dev/ashmem" + boot_id;
 }
 
-/* logistics of getting file descriptor for ashmem */
-static int __ashmem_open_locked() {
+int __ashmem_open() {
     static const std::string ashmem_device_path = get_ashmem_device_path();
 
     if (ashmem_device_path.empty()) {
@@ -184,9 +138,11 @@ static int __ashmem_open_locked() {
 
     struct stat st;
     if (TEMP_FAILURE_RETRY(fstat(fd, &st)) == -1) {
+        ALOGE("Unable to fstat ashmem device: %m");
         return -1;
     }
     if (!S_ISCHR(st.st_mode) || !st.st_rdev) {
+        ALOGE("ashmem device is not a character device");
         errno = ENOTTY;
         return -1;
     }
@@ -195,54 +151,32 @@ static int __ashmem_open_locked() {
     return fd.release();
 }
 
-static int __ashmem_open() {
-    pthread_mutex_lock(&__ashmem_lock);
-    int fd = __ashmem_open_locked();
-    pthread_mutex_unlock(&__ashmem_lock);
-    return fd;
+static void __init_ashmem_rdev() {
+    // If __ashmem_rdev hasn't been initialized yet,
+    // create an ashmem fd for that side effect.
+    // This shouldn't happen if all ashmem fds come from us,
+    // but we know that the libcutils code has been copy & pasted.
+    // (Chrome, for example, contains a copy of an old version.)
+    android::base::unique_fd fd(__ashmem_open());
 }
 
 /* Make sure file descriptor references ashmem, negative number means false */
+// TODO: return bool
 static int __ashmem_is_ashmem(int fd, bool fatal) {
-    struct stat st;
-    if (fstat(fd, &st) < 0) {
-        return -1;
-    }
-
-    dev_t rdev = 0; /* Too much complexity to sniff __ashmem_rdev */
-    if (S_ISCHR(st.st_mode) && st.st_rdev) {
-        pthread_mutex_lock(&__ashmem_lock);
-        rdev = __ashmem_rdev;
-        if (rdev) {
-            pthread_mutex_unlock(&__ashmem_lock);
-        } else {
-            int fd = __ashmem_open_locked();
-            if (fd < 0) {
-                pthread_mutex_unlock(&__ashmem_lock);
-                return -1;
-            }
-            rdev = __ashmem_rdev;
-            pthread_mutex_unlock(&__ashmem_lock);
-
-            close(fd);
-        }
+    if (__ashmem_rdev == 0) __init_ashmem_rdev();
 
-        if (st.st_rdev == rdev) {
-            return 0;
-        }
+    struct stat st;
+    if (fstat(fd, &st) == -1) return -1;
+    if (S_ISCHR(st.st_mode) && st.st_rdev == __ashmem_rdev) {
+      return 0;
     }
 
+    // TODO: move this to the single caller that actually wants it
     if (fatal) {
-        if (rdev) {
-            LOG_ALWAYS_FATAL("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o %d:%d",
-              fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
-              S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP,
-              major(rdev), minor(rdev));
-        } else {
-            LOG_ALWAYS_FATAL("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o",
-              fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
-              S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP);
-        }
+        LOG_ALWAYS_FATAL("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o %d:%d",
+            fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
+            S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP,
+            major(__ashmem_rdev), minor(__ashmem_rdev));
         /* NOTREACHED */
     }
 
@@ -283,8 +217,8 @@ int ashmem_valid(int fd) {
 }
 
 static int memfd_create_region(const char* name, size_t size) {
-    // This code needs to build on old API levels, so we can't use the libc
-    // wrapper.
+    // This code needs to build on API levels before 30,
+    // so we can't use the libc wrapper.
     android::base::unique_fd fd(syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING));
 
     if (fd == -1) {
diff --git a/libcutils/ashmem-internal.h b/libcutils/ashmem-internal.h
index 7bd037b716..358b0f0fa7 100644
--- a/libcutils/ashmem-internal.h
+++ b/libcutils/ashmem-internal.h
@@ -17,3 +17,4 @@
 #pragma once
 
 bool has_memfd_support();
+int __ashmem_open();
diff --git a/libcutils/ashmem_test.cpp b/libcutils/ashmem_test.cpp
index 2bf274c95c..5cbee5d3e1 100644
--- a/libcutils/ashmem_test.cpp
+++ b/libcutils/ashmem_test.cpp
@@ -33,8 +33,8 @@
 
 using android::base::unique_fd;
 
-static void TestCreateRegion(size_t size, unique_fd &fd, int prot) {
-    fd = unique_fd(ashmem_create_region(nullptr, size));
+static void TestCreateRegion(size_t size, unique_fd &fd, int prot, const char *name=nullptr) {
+    fd = unique_fd(ashmem_create_region(name, size));
     ASSERT_TRUE(fd >= 0);
     ASSERT_TRUE(ashmem_valid(fd));
     ASSERT_EQ(size, static_cast<size_t>(ashmem_get_size_region(fd)));
@@ -269,6 +269,19 @@ static void ForkMultiRegionTest(unique_fd fds[], int nRegions, size_t size) {
 
 }
 
+static void GetNameAshmemTest(const std::string &name) {
+    // We use __ashmem_open() to guarantee we get an ashmem fd. We need to do this since ashmem and
+    // memfd have different maximum name lengths.
+    unique_fd fd(__ashmem_open());
+    ASSERT_TRUE(fd >= 0);
+
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_SET_NAME, name.c_str()));
+
+    char retName[ASHMEM_NAME_LEN];
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_GET_NAME, retName));
+    ASSERT_STREQ(retName, name.substr(0, ASHMEM_NAME_LEN - 1).c_str());
+}
+
 TEST(AshmemTest, ForkTest) {
     const size_t size = getpagesize();
     unique_fd fd;
@@ -319,6 +332,50 @@ TEST(AshmemTest, ForkMultiRegionTest) {
     ASSERT_NO_FATAL_FAILURE(ForkMultiRegionTest(fds, nRegions, size));
 }
 
+// We don't run a similar test as part of the AshmemTestMemfdAshmemCompat tests, since the SET_NAME
+// ioctl is not supported.
+TEST(AshmemTest, SetNameKernelAccessTest) {
+    size_t pageSize = getpagesize();
+    // We use mmap to get a page-aligned area, since the smallest accessibility granule is a page.
+    // We also allocate 2 pages worth of virtual address space so that when we unmap the 2nd page
+    // we can be sure we've created a hole in the process' address space.
+    void *testArea = mmap(nullptr, 2 * pageSize, PROT_READ | PROT_WRITE,
+                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
+    ASSERT_NE(testArea, MAP_FAILED);
+
+    // Create a hole in the address space to catch accesses beyond the string from the kernel, which
+    // would cause TestCreateRegion() to fail.
+    char *secondPage = static_cast<char *>(testArea) + pageSize;
+    ASSERT_EQ(0, munmap(secondPage, pageSize));
+
+    // Write the name such that even if the implementation of the SET_NAME ioctl is always reading
+    // ASHMEM_NAME_LEN bytes, it is guaranteed to succeed given the start address of "test-buf".
+    char *name = secondPage - ASHMEM_NAME_LEN;
+    strcpy(name, "test-buf");
+
+    unique_fd fd;
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(pageSize, fd, PROT_READ | PROT_WRITE, name));
+
+    unique_fd fd2;
+    // This should not fail either, as "est-buf" is also a valid string, but a broken
+    // implementation of the SET_NAME ioctl can blindly read ASHMEM_NAME_LEN bytes each time,
+    // instead of searching for the NUL terminating byte.
+    //
+    // If it fails, it's because the kernel accessed the unmapped region.
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(pageSize, fd2, PROT_READ | PROT_WRITE, &name[1]));
+
+    ASSERT_EQ(0, munmap(testArea, pageSize));
+}
+
+TEST(AshmemTest, GetLongNameAshmemTests) {
+    std::string longName(ASHMEM_NAME_LEN - 1, 'A');
+    ASSERT_NO_FATAL_FAILURE(GetNameAshmemTest(longName));
+
+    longName.append(1, 'A');
+    // This should not fail because ashmem will just truncate the name if it is too long.
+    ASSERT_NO_FATAL_FAILURE(GetNameAshmemTest(longName));
+}
+
 class AshmemTestMemfdAshmemCompat : public ::testing::Test {
  protected:
   void SetUp() override {
@@ -348,6 +405,26 @@ TEST_F(AshmemTestMemfdAshmemCompat, GetNameTest) {
     ASSERT_STREQ(testBuf, "none");
 }
 
+TEST_F(AshmemTestMemfdAshmemCompat, GetLongNameMemfdTests) {
+    // memfd names have a maximum length of 249 bytes excluding the NUL terminating byte.
+    // See: https://man7.org/linux/man-pages/man2/memfd_create.2.html
+    const size_t max_memfd_name_len = 249;
+    std::string longName(max_memfd_name_len, 'A');
+    size_t pageSize = getpagesize();
+    unique_fd fd;
+    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(pageSize, fd, PROT_READ | PROT_WRITE | PROT_EXEC,
+                                             longName.c_str()));
+
+    char retName[max_memfd_name_len + 1];
+    ASSERT_EQ(0, ioctl(fd, ASHMEM_GET_NAME, retName));
+    ASSERT_STREQ(retName, longName.c_str());
+
+    longName.append(1, 'A');
+    // Use ashmem_create_region() since it should fail, since the string is now over the maximum
+    // length.
+    ASSERT_LT(ashmem_create_region(longName.c_str(), pageSize), 0);
+}
+
 TEST_F(AshmemTestMemfdAshmemCompat, SetSizeTest) {
     unique_fd fd;
 
diff --git a/libcutils/properties_test.cpp b/libcutils/properties_test.cpp
index efc01833ab..399f71401f 100644
--- a/libcutils/properties_test.cpp
+++ b/libcutils/properties_test.cpp
@@ -24,13 +24,12 @@
 
 #include <android/log.h>
 #include <android-base/macros.h>
+#include <android-base/stringify.h>
 #include <cutils/properties.h>
 #include <gtest/gtest.h>
 
 namespace android {
 
-#define STRINGIFY_INNER(x) #x
-#define STRINGIFY(x) STRINGIFY_INNER(x)
 #define ASSERT_OK(x) ASSERT_EQ(0, (x))
 #define EXPECT_OK(x) EXPECT_EQ(0, (x))
 
diff --git a/libkeyutils/.clang-format b/libkeyutils/.clang-format
deleted file mode 120000
index fd0645fdf9..0000000000
--- a/libkeyutils/.clang-format
+++ /dev/null
@@ -1 +0,0 @@
-../.clang-format-2
\ No newline at end of file
diff --git a/libkeyutils/Android.bp b/libkeyutils/Android.bp
deleted file mode 100644
index 3af07b47ce..0000000000
--- a/libkeyutils/Android.bp
+++ /dev/null
@@ -1,31 +0,0 @@
-package {
-    default_applicable_licenses: ["system_core_libkeyutils_license"],
-}
-
-license {
-    name: "system_core_libkeyutils_license",
-    visibility: [":__subpackages__"],
-    license_kinds: ["SPDX-license-identifier-BSD"],
-    license_text: ["NOTICE"],
-}
-
-cc_library {
-    name: "libkeyutils",
-    cflags: ["-Werror"],
-    defaults: ["linux_bionic_supported"],
-    ramdisk_available: true,
-    vendor_ramdisk_available: true,
-    recovery_available: true,
-    export_include_dirs: ["include/"],
-    local_include_dirs: ["include/"],
-    srcs: ["keyutils.cpp"],
-    stl: "none",
-}
-
-cc_test {
-    name: "libkeyutils-tests",
-    cflags: ["-Werror"],
-    shared_libs: ["libkeyutils"],
-    srcs: ["keyutils_test.cpp"],
-    test_suites: ["device-tests"],
-}
diff --git a/libkeyutils/NOTICE b/libkeyutils/NOTICE
deleted file mode 100644
index 5828550d53..0000000000
--- a/libkeyutils/NOTICE
+++ /dev/null
@@ -1,25 +0,0 @@
-Copyright (C) 2017 The Android Open Source Project
-All rights reserved.
-
-Redistribution and use in source and binary forms, with or without
-modification, are permitted provided that the following conditions
-are met:
- * Redistributions of source code must retain the above copyright
-   notice, this list of conditions and the following disclaimer.
- * Redistributions in binary form must reproduce the above copyright
-   notice, this list of conditions and the following disclaimer in
-   the documentation and/or other materials provided with the
-   distribution.
-
-THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
-"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
-LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
-FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
-COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
-INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
-BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
-OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
-AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
-OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
-OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-SUCH DAMAGE.
diff --git a/libkeyutils/include/keyutils.h b/libkeyutils/include/keyutils.h
deleted file mode 100644
index c508f27902..0000000000
--- a/libkeyutils/include/keyutils.h
+++ /dev/null
@@ -1,60 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#ifndef _KEYUTILS_H_
-#define _KEYUTILS_H_
-
-#include <linux/keyctl.h>
-#include <stdint.h>
-#include <sys/cdefs.h>
-
-__BEGIN_DECLS
-
-typedef int32_t key_serial_t;
-
-key_serial_t add_key(const char* type, const char* description, const void* payload,
-                     size_t payload_length, key_serial_t ring_id);
-
-key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create);
-
-long keyctl_revoke(key_serial_t id); /* TODO: remove this */
-
-long keyctl_search(key_serial_t ring_id, const char* type, const char* description,
-                   key_serial_t dest_ring_id);
-
-long keyctl_setperm(key_serial_t id, int permissions);
-
-long keyctl_unlink(key_serial_t key, key_serial_t keyring);
-
-long keyctl_restrict_keyring(key_serial_t keyring, const char* type, const char* restriction);
-
-long keyctl_get_security(key_serial_t key, char* buffer, size_t buflen);
-
-__END_DECLS
-
-#endif
diff --git a/libkeyutils/keyutils.cpp b/libkeyutils/keyutils.cpp
deleted file mode 100644
index 1c5acc9adb..0000000000
--- a/libkeyutils/keyutils.cpp
+++ /dev/null
@@ -1,69 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <keyutils.h>
-
-#include <stdarg.h>
-#include <sys/syscall.h>
-#include <unistd.h>
-
-// keyctl(2) is deliberately not exposed. Callers should use the typed APIs instead.
-
-key_serial_t add_key(const char* type, const char* description, const void* payload,
-                     size_t payload_length, key_serial_t ring_id) {
-  return syscall(__NR_add_key, type, description, payload, payload_length, ring_id);
-}
-
-key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create) {
-  return syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, id, create);
-}
-
-long keyctl_revoke(key_serial_t id) {
-  return syscall(__NR_keyctl, KEYCTL_REVOKE, id);
-}
-
-long keyctl_search(key_serial_t ring_id, const char* type, const char* description,
-                   key_serial_t dest_ring_id) {
-  return syscall(__NR_keyctl, KEYCTL_SEARCH, ring_id, type, description, dest_ring_id);
-}
-
-long keyctl_setperm(key_serial_t id, int permissions) {
-  return syscall(__NR_keyctl, KEYCTL_SETPERM, id, permissions);
-}
-
-long keyctl_unlink(key_serial_t key, key_serial_t keyring) {
-  return syscall(__NR_keyctl, KEYCTL_UNLINK, key, keyring);
-}
-
-long keyctl_restrict_keyring(key_serial_t keyring, const char* type, const char* restriction) {
-  return syscall(__NR_keyctl, KEYCTL_RESTRICT_KEYRING, keyring, type, restriction);
-}
-
-long keyctl_get_security(key_serial_t id, char* buffer, size_t buflen) {
-  return syscall(__NR_keyctl, KEYCTL_GET_SECURITY, id, buffer, buflen);
-}
diff --git a/libkeyutils/keyutils_test.cpp b/libkeyutils/keyutils_test.cpp
deleted file mode 100644
index d03747b3ec..0000000000
--- a/libkeyutils/keyutils_test.cpp
+++ /dev/null
@@ -1,46 +0,0 @@
-/*
- * Copyright (C) 2017 The Android Open Source Project
- * All rights reserved.
- *
- * Redistribution and use in source and binary forms, with or without
- * modification, are permitted provided that the following conditions
- * are met:
- *  * Redistributions of source code must retain the above copyright
- *    notice, this list of conditions and the following disclaimer.
- *  * Redistributions in binary form must reproduce the above copyright
- *    notice, this list of conditions and the following disclaimer in
- *    the documentation and/or other materials provided with the
- *    distribution.
- *
- * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
- * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
- * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
- * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
- * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
- * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
- * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
- * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
- * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
- * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
- * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
- * SUCH DAMAGE.
- */
-
-#include <keyutils.h>
-
-#include <dlfcn.h>
-
-#include <gtest/gtest.h>
-
-TEST(keyutils, smoke) {
-  // Check that the exported type is the right size.
-  ASSERT_EQ(4U, sizeof(key_serial_t));
-
-  // Check that all the functions actually exist.
-  ASSERT_TRUE(dlsym(nullptr, "add_key") != nullptr);
-  ASSERT_TRUE(dlsym(nullptr, "keyctl_get_keyring_ID") != nullptr);
-  ASSERT_TRUE(dlsym(nullptr, "keyctl_revoke") != nullptr);
-  ASSERT_TRUE(dlsym(nullptr, "keyctl_search") != nullptr);
-  ASSERT_TRUE(dlsym(nullptr, "keyctl_setperm") != nullptr);
-  ASSERT_TRUE(dlsym(nullptr, "keyctl_unlink") != nullptr);
-}
diff --git a/libmodprobe/Android.bp b/libmodprobe/Android.bp
index 78b4c83e3c..700e617295 100644
--- a/libmodprobe/Android.bp
+++ b/libmodprobe/Android.bp
@@ -6,6 +6,7 @@ cc_library_static {
     name: "libmodprobe",
     cflags: [
         "-Werror",
+        "-Wthread-safety",
     ],
     vendor_available: true,
     ramdisk_available: true,
diff --git a/libmodprobe/include/modprobe/modprobe.h b/libmodprobe/include/modprobe/modprobe.h
index d33e17ddde..92a3684392 100644
--- a/libmodprobe/include/modprobe/modprobe.h
+++ b/libmodprobe/include/modprobe/modprobe.h
@@ -16,6 +16,7 @@
 
 #pragma once
 
+#include <atomic>
 #include <functional>
 #include <mutex>
 #include <set>
@@ -31,24 +32,24 @@ class Modprobe {
     Modprobe(const std::vector<std::string>&, const std::string load_file = "modules.load",
              bool use_blocklist = true);
 
-    bool LoadModulesParallel(int num_threads);
+    bool LoadModulesParallel(int num_threads) EXCLUDES(module_loaded_lock_);
     bool LoadListedModules(bool strict = true);
     bool LoadWithAliases(const std::string& module_name, bool strict,
-                         const std::string& parameters = "");
+                         const std::string& parameters = "") EXCLUDES(module_loaded_lock_);
     bool Remove(const std::string& module_name);
     std::vector<std::string> ListModules(const std::string& pattern);
     bool GetAllDependencies(const std::string& module, std::vector<std::string>* pre_dependencies,
                             std::vector<std::string>* dependencies,
                             std::vector<std::string>* post_dependencies);
-    void ResetModuleCount() { module_count_ = 0; }
     int GetModuleCount() { return module_count_; }
     bool IsBlocklisted(const std::string& module_name);
 
   private:
     std::string MakeCanonical(const std::string& module_path);
     bool InsmodWithDeps(const std::string& module_name, const std::string& parameters);
-    bool Insmod(const std::string& path_name, const std::string& parameters);
-    bool Rmmod(const std::string& module_name);
+    bool Insmod(const std::string& path_name, const std::string& parameters)
+            EXCLUDES(module_loaded_lock_);
+    bool Rmmod(const std::string& module_name) EXCLUDES(module_loaded_lock_);
     std::vector<std::string> GetDependencies(const std::string& module);
     bool ModuleExists(const std::string& module_name);
     void AddOption(const std::string& module_name, const std::string& option_name,
@@ -65,6 +66,7 @@ class Modprobe {
     void ParseKernelCmdlineOptions();
     void ParseCfg(const std::string& cfg, std::function<bool(const std::vector<std::string>&)> f);
 
+    // These non const fields are initialized by the constructor and never be modified.
     std::vector<std::pair<std::string, std::string>> module_aliases_;
     std::unordered_map<std::string, std::vector<std::string>> module_deps_;
     std::vector<std::pair<std::string, std::string>> module_pre_softdep_;
@@ -72,9 +74,10 @@ class Modprobe {
     std::vector<std::string> module_load_;
     std::unordered_map<std::string, std::string> module_options_;
     std::set<std::string> module_blocklist_;
+
     std::mutex module_loaded_lock_;
-    std::unordered_set<std::string> module_loaded_;
-    std::unordered_set<std::string> module_loaded_paths_;
-    int module_count_ = 0;
-    bool blocklist_enabled = false;
+    std::unordered_set<std::string> module_loaded_ GUARDED_BY(module_loaded_lock_);
+    std::unordered_set<std::string> module_loaded_paths_ GUARDED_BY(module_loaded_lock_);
+    std::atomic_int module_count_ = 0;
+    const bool blocklist_enabled = false;
 };
diff --git a/libmodprobe/libmodprobe.cpp b/libmodprobe/libmodprobe.cpp
index bdd114c4b7..f74e15fb74 100644
--- a/libmodprobe/libmodprobe.cpp
+++ b/libmodprobe/libmodprobe.cpp
@@ -458,21 +458,24 @@ bool Modprobe::InsmodWithDeps(const std::string& module_name, const std::string&
 
 bool Modprobe::LoadWithAliases(const std::string& module_name, bool strict,
                                const std::string& parameters) {
-    auto canonical_name = MakeCanonical(module_name);
-    if (module_loaded_.count(canonical_name)) {
-        return true;
-    }
-
-    std::set<std::string> modules_to_load = {canonical_name};
+    std::set<std::string> modules_to_load;
     bool module_loaded = false;
+    {
+        std::lock_guard guard(module_loaded_lock_);
 
-    // use aliases to expand list of modules to load (multiple modules
-    // may alias themselves to the requested name)
-    for (const auto& [alias, aliased_module] : module_aliases_) {
-        if (fnmatch(alias.c_str(), module_name.c_str(), 0) != 0) continue;
-        LOG(VERBOSE) << "Found alias for '" << module_name << "': '" << aliased_module;
-        if (module_loaded_.count(MakeCanonical(aliased_module))) continue;
-        modules_to_load.emplace(aliased_module);
+        auto canonical_name = MakeCanonical(module_name);
+        if (module_loaded_.count(canonical_name)) {
+            return true;
+        }
+        modules_to_load.insert(std::move(canonical_name));
+        // use aliases to expand list of modules to load (multiple modules
+        // may alias themselves to the requested name)
+        for (const auto& [alias, aliased_module] : module_aliases_) {
+            if (fnmatch(alias.c_str(), module_name.c_str(), 0) != 0) continue;
+            LOG(VERBOSE) << "Found alias for '" << module_name << "': '" << aliased_module;
+            if (module_loaded_.count(MakeCanonical(aliased_module))) continue;
+            modules_to_load.emplace(aliased_module);
+        }
     }
 
     // attempt to load all modules aliased to this name
diff --git a/libprocessgroup/processgroup.cpp b/libprocessgroup/processgroup.cpp
index a8fa50a9fd..964faf696f 100644
--- a/libprocessgroup/processgroup.cpp
+++ b/libprocessgroup/processgroup.cpp
@@ -44,6 +44,7 @@
 #include <android-base/logging.h>
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
+#include <build_flags.h>
 #include <cutils/android_filesystem_config.h>
 #include <processgroup/processgroup.h>
 #include <task_profiles.h>
@@ -298,6 +299,16 @@ void removeAllEmptyProcessGroups() {
     if (CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &path)) {
         cgroups.push_back(path);
     }
+    if (android::libprocessgroup_flags::cgroup_v2_sys_app_isolation()) {
+        for (const char* sub : {"apps", "system"}) {
+            std::string subpath = path + "/" + sub;
+            struct stat st;
+            if (stat(subpath.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
+                cgroups.push_back(subpath);
+            }
+        }
+    }
+
     if (CgroupGetMemcgAppsPath(&memcg_apps_path) && memcg_apps_path != path) {
         cgroups.push_back(memcg_apps_path);
     }
diff --git a/libprocessgroup/setup/cgroup_map_write.cpp b/libprocessgroup/setup/cgroup_map_write.cpp
index 0d1739e994..899b4e9524 100644
--- a/libprocessgroup/setup/cgroup_map_write.cpp
+++ b/libprocessgroup/setup/cgroup_map_write.cpp
@@ -174,7 +174,7 @@ static bool ActivateV2CgroupController(const CgroupDescriptor& descriptor) {
 
     if (!Mkdir(controller->path(), descriptor.mode(), descriptor.uid(), descriptor.gid())) {
         LOG(ERROR) << "Failed to create directory for " << controller->name() << " cgroup";
-        return false;
+        return descriptor.controller()->flags() & CGROUPRC_CONTROLLER_FLAG_OPTIONAL;
     }
 
     return ::ActivateControllers(controller->path(), {{controller->name(), descriptor}});
@@ -189,22 +189,19 @@ static bool MountV1CgroupController(const CgroupDescriptor& descriptor) {
         return false;
     }
 
-    // Unfortunately historically cpuset controller was mounted using a mount command
-    // different from all other controllers. This results in controller attributes not
-    // to be prepended with controller name. For example this way instead of
-    // /dev/cpuset/cpuset.cpus the attribute becomes /dev/cpuset/cpus which is what
-    // the system currently expects.
-    int res;
+    std::string options = controller->name();
+
     if (!strcmp(controller->name(), "cpuset")) {
-        // mount cpuset none /dev/cpuset nodev noexec nosuid
-        res = mount("none", controller->path(), controller->name(),
-                    MS_NODEV | MS_NOEXEC | MS_NOSUID, nullptr);
-    } else {
-        // mount cgroup none <path> nodev noexec nosuid <controller>
-        res = mount("none", controller->path(), "cgroup", MS_NODEV | MS_NOEXEC | MS_NOSUID,
-                    controller->name());
+        // Android depends on the noprefix option for cpuset so that cgroupfs files are not prefixed
+        // with the controller name. For example /dev/cpuset/cpus instead of
+        //                                       /dev/cpuset/cpuset.cpus.
+        // cpuset_v2_mode is required to restore the original cpu mask after a cpu is offlined, and
+        // then onlined in cgroup v1.
+        options += ",noprefix,cpuset_v2_mode";
     }
-    if (res != 0) {
+
+    if (mount("none", controller->path(), "cgroup", MS_NODEV | MS_NOEXEC | MS_NOSUID,
+              options.c_str())) {
         if (IsOptionalController(controller)) {
             PLOG(INFO) << "Failed to mount optional controller " << controller->name();
             return true;
@@ -294,8 +291,8 @@ bool CgroupSetup() {
         }
 
         if (!SetupCgroup(descriptor)) {
-            // issue a warning and proceed with the next cgroup
-            LOG(WARNING) << "Failed to setup " << name << " cgroup";
+            LOG(ERROR) << "Failed to setup " << name << " cgroup";
+            return false;
         }
     }
 
diff --git a/libsparse/sparse.cpp b/libsparse/sparse.cpp
index ca7e5fe626..dba3a27f40 100644
--- a/libsparse/sparse.cpp
+++ b/libsparse/sparse.cpp
@@ -120,7 +120,9 @@ static int write_all_blocks(struct sparse_file* s, struct output_file* out) {
   for (bb = backed_block_iter_new(s->backed_block_list); bb; bb = backed_block_iter_next(bb)) {
     if (backed_block_block(bb) > last_block) {
       unsigned int blocks = backed_block_block(bb) - last_block;
-      write_skip_chunk(out, (int64_t)blocks * s->block_size);
+      if (ret = write_skip_chunk(out, (int64_t)blocks * s->block_size); ret != 0) {
+        return ret;
+      }
     }
     ret = sparse_file_write_block(out, bb);
     if (ret) return ret;
@@ -130,7 +132,9 @@ static int write_all_blocks(struct sparse_file* s, struct output_file* out) {
   pad = s->len - (int64_t)last_block * s->block_size;
   assert(pad >= 0);
   if (pad > 0) {
-    write_skip_chunk(out, pad);
+    if (ret = write_skip_chunk(out, pad); ret != 0) {
+      return ret;
+    }
   }
 
   return 0;
diff --git a/libstats/OWNERS b/libstats/OWNERS
index efd3686277..bb6a08da4f 100644
--- a/libstats/OWNERS
+++ b/libstats/OWNERS
@@ -1,7 +1,6 @@
 jeffreyhuang@google.com
 monicamwang@google.com
 muhammadq@google.com
-rayhdez@google.com
 sharaienko@google.com
 singhtejinder@google.com
 tsaichristine@google.com
diff --git a/libstats/bootstrap/Android.bp b/libstats/bootstrap/Android.bp
index 332d9c81ba..2f8a31f170 100644
--- a/libstats/bootstrap/Android.bp
+++ b/libstats/bootstrap/Android.bp
@@ -36,7 +36,6 @@ cc_defaults {
     shared_libs: [
         "libbinder",
         "libutils",
-        "android.os.statsbootstrap_aidl-cpp",
     ],
 }
 
@@ -45,5 +44,3 @@ cc_library {
     defaults: ["libstatsbootstrap_defaults"],
     export_include_dirs: ["include"],
 }
-
-
diff --git a/libstats/pull_rust/Android.bp b/libstats/pull_rust/Android.bp
index ae00e75750..7a50090c9d 100644
--- a/libstats/pull_rust/Android.bp
+++ b/libstats/pull_rust/Android.bp
@@ -51,6 +51,7 @@ rust_bindgen {
     apex_available: [
         "//apex_available:platform",
         "com.android.resolv",
+        "com.android.uprobestats",
         "com.android.virt",
     ],
 }
diff --git a/libutils/Looper.cpp b/libutils/Looper.cpp
index 2541aa807a..590072f70e 100644
--- a/libutils/Looper.cpp
+++ b/libutils/Looper.cpp
@@ -19,6 +19,7 @@
 
 #include <utils/Looper.h>
 
+#include <atomic>
 #include <sys/eventfd.h>
 #include <cinttypes>
 
@@ -216,13 +217,13 @@ int Looper::pollInner(int timeoutMillis) {
     mResponseIndex = 0;
 
     // We are about to idle.
-    mPolling = true;
+    std::atomic_store_explicit(&mPolling, true, std::memory_order_relaxed);
 
     struct epoll_event eventItems[EPOLL_MAX_EVENTS];
     int eventCount = epoll_wait(mEpollFd.get(), eventItems, EPOLL_MAX_EVENTS, timeoutMillis);
 
     // No longer idling.
-    mPolling = false;
+    std::atomic_store_explicit(&mPolling, false, std::memory_order_relaxed);
 
     // Acquire lock.
     mLock.lock();
@@ -673,7 +674,7 @@ void Looper::removeMessages(const sp<MessageHandler>& handler, int what) {
 }
 
 bool Looper::isPolling() const {
-    return mPolling;
+    return std::atomic_load_explicit(&mPolling, std::memory_order_relaxed);
 }
 
 uint32_t Looper::Request::getEpollEvents() const {
diff --git a/libutils/LruCache_fuzz.cpp b/libutils/LruCache_fuzz.cpp
index f8bacfcbc2..ff6d100883 100644
--- a/libutils/LruCache_fuzz.cpp
+++ b/libutils/LruCache_fuzz.cpp
@@ -58,6 +58,10 @@ static const std::vector<std::function<void(FuzzedDataProvider*, FuzzCache*)>> o
             size_t key = dataProvider->ConsumeIntegral<size_t>();
             cache->remove(key);
         },
+        [](FuzzedDataProvider* dataProvider, FuzzCache* cache) -> void {
+            size_t key = dataProvider->ConsumeIntegral<size_t>();
+            cache->contains(key);
+        },
         [](FuzzedDataProvider*, FuzzCache* cache) -> void {
             cache->setOnEntryRemovedListener(&callback);
         }};
diff --git a/libutils/LruCache_test.cpp b/libutils/LruCache_test.cpp
index 5cd3cbb90c..7c0f23b1da 100644
--- a/libutils/LruCache_test.cpp
+++ b/libutils/LruCache_test.cpp
@@ -166,6 +166,10 @@ TEST_F(LruCacheTest, Simple) {
     cache.put(1, "one");
     cache.put(2, "two");
     cache.put(3, "three");
+    EXPECT_TRUE(cache.contains(1));
+    EXPECT_TRUE(cache.contains(2));
+    EXPECT_TRUE(cache.contains(3));
+    EXPECT_FALSE(cache.contains(4));
     EXPECT_STREQ("one", cache.get(1));
     EXPECT_STREQ("two", cache.get(2));
     EXPECT_STREQ("three", cache.get(3));
@@ -195,6 +199,10 @@ TEST_F(LruCacheTest, RemoveLru) {
     EXPECT_STREQ("two", cache.get(2));
     EXPECT_STREQ("three", cache.get(3));
     EXPECT_EQ(2u, cache.size());
+
+    EXPECT_FALSE(cache.contains(1));
+    EXPECT_TRUE(cache.contains(2));
+    EXPECT_TRUE(cache.contains(3));
 }
 
 TEST_F(LruCacheTest, GetUpdatesLru) {
diff --git a/libutils/binder/RefBase.cpp b/libutils/binder/RefBase.cpp
index bf803e72b7..d35c5af11e 100644
--- a/libutils/binder/RefBase.cpp
+++ b/libutils/binder/RefBase.cpp
@@ -455,6 +455,10 @@ void RefBase::incStrong(const void* id) const
     refs->addStrongRef(id);
     const int32_t c = refs->mStrong.fetch_add(1, std::memory_order_relaxed);
     ALOG_ASSERT(c > 0, "incStrong() called on %p after last strong ref", refs);
+    LOG_ALWAYS_FATAL_IF(BAD_STRONG(c),
+                        "incStrong() called on %p too many times,"
+                        " strong refs = %d ",
+                        refs, c);
 #if PRINT_REFS
     ALOGD("incStrong of %p from %p: cnt=%d\n", this, id, c);
 #endif
@@ -563,6 +567,8 @@ void RefBase::weakref_type::incWeak(const void* id)
     const int32_t c __unused = impl->mWeak.fetch_add(1,
             std::memory_order_relaxed);
     ALOG_ASSERT(c >= 0, "incWeak called on %p after last weak ref", this);
+    LOG_ALWAYS_FATAL_IF(c != 0 && BAD_WEAK(c),
+                        "incWeak called on %p too many times, weak refs = %d", this, c);
 }
 
 void RefBase::weakref_type::incWeakRequireWeak(const void* id)
diff --git a/libutils/binder/VectorImpl.cpp b/libutils/binder/VectorImpl.cpp
index a62664f7b1..4396a2139d 100644
--- a/libutils/binder/VectorImpl.cpp
+++ b/libutils/binder/VectorImpl.cpp
@@ -94,7 +94,7 @@ void* VectorImpl::editArrayImpl()
             // Fail instead of returning a pointer to storage that's not
             // editable. Otherwise we'd be editing the contents of a buffer
             // for which we're not the only owner, which is undefined behaviour.
-            LOG_ALWAYS_FATAL_IF(editable == nullptr);
+            LOG_ALWAYS_FATAL_IF(editable == nullptr, "size: %zu", sb->size());
             _do_copy(editable->data(), mStorage, mCount);
             release_storage();
             mStorage = editable->data();
diff --git a/libutils/include/utils/Looper.h b/libutils/include/utils/Looper.h
index eea348e379..3217faa98a 100644
--- a/libutils/include/utils/Looper.h
+++ b/libutils/include/utils/Looper.h
@@ -26,6 +26,7 @@
 
 #include <android-base/unique_fd.h>
 
+#include <atomic>
 #include <unordered_map>
 #include <utility>
 
@@ -479,7 +480,7 @@ private:
 
     // Whether we are currently waiting for work.  Not protected by a lock,
     // any use of it is racy anyway.
-    volatile bool mPolling;
+    std::atomic<bool> mPolling;
 
     android::base::unique_fd mEpollFd;  // guarded by mLock but only modified on the looper thread
     bool mEpollRebuildRequired; // guarded by mLock
diff --git a/libutils/include/utils/LruCache.h b/libutils/include/utils/LruCache.h
index 70901b63b4..211186797a 100644
--- a/libutils/include/utils/LruCache.h
+++ b/libutils/include/utils/LruCache.h
@@ -48,6 +48,7 @@ public:
     size_t size() const;
     const TValue& get(const TKey& key);
     bool put(const TKey& key, const TValue& value);
+    bool contains(const TKey& key) const;
     bool remove(const TKey& key);
     bool removeOldest();
     void clear();
@@ -103,7 +104,7 @@ private:
     void attachToCache(Entry& entry);
     void detachFromCache(Entry& entry);
 
-    typename LruCacheSet::iterator findByKey(const TKey& key) {
+    typename LruCacheSet::iterator findByKey(const TKey& key) const {
         EntryForSearch entryForSearch(key);
         typename LruCacheSet::iterator result = mSet->find(&entryForSearch);
         return result;
@@ -216,6 +217,11 @@ bool LruCache<TKey, TValue>::put(const TKey& key, const TValue& value) {
     return true;
 }
 
+template <typename TKey, typename TValue>
+bool LruCache<TKey, TValue>::contains(const TKey& key) const {
+    return findByKey(key) != mSet->end();
+}
+
 template <typename TKey, typename TValue>
 bool LruCache<TKey, TValue>::remove(const TKey& key) {
     typename LruCacheSet::const_iterator find_result = findByKey(key);
diff --git a/libutils/include/utils/Singleton.h b/libutils/include/utils/Singleton.h
index 44d8ad79cc..82163c62bb 100644
--- a/libutils/include/utils/Singleton.h
+++ b/libutils/include/utils/Singleton.h
@@ -70,7 +70,7 @@ protected:
 private:
     Singleton(const Singleton&);
     Singleton& operator = (const Singleton&);
-    static Mutex sLock;
+    [[clang::no_destroy]] static Mutex sLock;
     static TYPE* sInstance;
 };
 
diff --git a/libvendorsupport/tests/version_props_test.cpp b/libvendorsupport/tests/version_props_test.cpp
index ad54c8895f..d8715cdf00 100644
--- a/libvendorsupport/tests/version_props_test.cpp
+++ b/libvendorsupport/tests/version_props_test.cpp
@@ -24,12 +24,20 @@ namespace {
 TEST(VendorSupport, GetCorrespondingVendorApiLevel) {
     ASSERT_EQ(__ANDROID_API_U__, AVendorSupport_getVendorApiLevelOf(__ANDROID_API_U__));
     ASSERT_EQ(202404, AVendorSupport_getVendorApiLevelOf(__ANDROID_API_V__));
+    // No more __ANDROID_API_FOO__ constants are defined after V since numeric API levels
+    // are preferred, so add more tests (to make the helper function behaviour crystal
+    // clear) using numeric API levels.
+    ASSERT_EQ(202504, AVendorSupport_getVendorApiLevelOf(36));
     ASSERT_EQ(__INVALID_API_LEVEL, AVendorSupport_getVendorApiLevelOf(__ANDROID_API_FUTURE__));
 }
 
 TEST(VendorSupport, GetCorrespondingSdkApiLevel) {
     ASSERT_EQ(__ANDROID_API_U__, AVendorSupport_getSdkApiLevelOf(__ANDROID_API_U__));
     ASSERT_EQ(__ANDROID_API_V__, AVendorSupport_getSdkApiLevelOf(202404));
+    // No more __ANDROID_API_FOO__ constants are defined after V since numeric API levels
+    // are preferred, so add more tests (to make the helper function behaviour crystal
+    // clear) using numeric API levels.
+    ASSERT_EQ(36, AVendorSupport_getSdkApiLevelOf(202504));
     ASSERT_EQ(__INVALID_API_LEVEL, AVendorSupport_getSdkApiLevelOf(__ANDROID_VENDOR_API_MAX__));
     ASSERT_EQ(__INVALID_API_LEVEL, AVendorSupport_getSdkApiLevelOf(35));
 }
diff --git a/mini_keyctl/Android.bp b/mini_keyctl/Android.bp
deleted file mode 100644
index 0325c5b4b9..0000000000
--- a/mini_keyctl/Android.bp
+++ /dev/null
@@ -1,32 +0,0 @@
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_library_static {
-    name: "libmini_keyctl_static",
-    srcs: [
-        "mini_keyctl_utils.cpp"
-    ],
-    shared_libs: [
-        "libbase",
-        "libkeyutils",
-    ],
-    cflags: ["-Werror", "-Wall", "-Wextra"],
-    export_include_dirs: ["."],
-    recovery_available: true,
-}
-
-cc_binary {
-    name: "mini-keyctl",
-    srcs: [
-        "mini_keyctl.cpp",
-    ],
-    static_libs: [
-        "libmini_keyctl_static",
-    ],
-    shared_libs: [
-        "libbase",
-        "libkeyutils",
-    ],
-    cflags: ["-Werror", "-Wall", "-Wextra"],
-}
diff --git a/mini_keyctl/OWNERS b/mini_keyctl/OWNERS
deleted file mode 100644
index 1f2485a0c4..0000000000
--- a/mini_keyctl/OWNERS
+++ /dev/null
@@ -1,4 +0,0 @@
-ebiggers@google.com
-jeffv@google.com
-jiyong@google.com
-victorhsieh@google.com
diff --git a/mini_keyctl/mini_keyctl.cpp b/mini_keyctl/mini_keyctl.cpp
deleted file mode 100644
index 8aace9adbb..0000000000
--- a/mini_keyctl/mini_keyctl.cpp
+++ /dev/null
@@ -1,178 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-/*
- * A tool loads keys to keyring.
- */
-
-#include <dirent.h>
-#include <errno.h>
-#include <error.h>
-#include <stdio.h>
-#include <sys/types.h>
-#include <unistd.h>
-
-#include <iostream>
-#include <iterator>
-#include <string>
-
-#include <android-base/file.h>
-#include <android-base/parseint.h>
-#include <keyutils.h>
-#include <mini_keyctl_utils.h>
-
-constexpr int kMaxCertSize = 4096;
-
-static void Usage(int exit_code) {
-  fprintf(stderr, "usage: mini-keyctl <action> [args,]\n");
-  fprintf(stderr, "       mini-keyctl add <type> <desc> <data> <keyring>\n");
-  fprintf(stderr, "       mini-keyctl padd <type> <desc> <keyring>\n");
-  fprintf(stderr, "       mini-keyctl unlink <key> <keyring>\n");
-  fprintf(stderr, "       mini-keyctl restrict_keyring <keyring>\n");
-  fprintf(stderr, "       mini-keyctl security <key>\n");
-  _exit(exit_code);
-}
-
-static key_serial_t parseKeyOrDie(const char* str) {
-  key_serial_t key;
-  if (!android::base::ParseInt(str, &key)) {
-    error(1 /* exit code */, 0 /* errno */, "Unparsable key: '%s'\n", str);
-  }
-  return key;
-}
-
-int Unlink(key_serial_t key, const std::string& keyring) {
-  key_serial_t keyring_id = android::GetKeyringId(keyring);
-  if (keyctl_unlink(key, keyring_id) < 0) {
-    error(1, errno, "Failed to unlink key %x from keyring %s", key, keyring.c_str());
-    return 1;
-  }
-  return 0;
-}
-
-int Add(const std::string& type, const std::string& desc, const std::string& data,
-        const std::string& keyring) {
-  if (data.size() > kMaxCertSize) {
-    error(1, 0, "Certificate too large");
-    return 1;
-  }
-
-  key_serial_t keyring_id = android::GetKeyringId(keyring);
-  key_serial_t key = add_key(type.c_str(), desc.c_str(), data.c_str(), data.size(), keyring_id);
-
-  if (key < 0) {
-    error(1, errno, "Failed to add key");
-    return 1;
-  }
-
-  std::cout << key << std::endl;
-  return 0;
-}
-
-int Padd(const std::string& type, const std::string& desc, const std::string& keyring) {
-  key_serial_t keyring_id = android::GetKeyringId(keyring);
-
-  // read from stdin to get the certificates
-  std::istreambuf_iterator<char> begin(std::cin), end;
-  std::string data(begin, end);
-
-  if (data.size() > kMaxCertSize) {
-    error(1, 0, "Certificate too large");
-    return 1;
-  }
-
-  key_serial_t key = add_key(type.c_str(), desc.c_str(), data.c_str(), data.size(), keyring_id);
-
-  if (key < 0) {
-    error(1, errno, "Failed to add key");
-    return 1;
-  }
-
-  std::cout << key << std::endl;
-  return 0;
-}
-
-int RestrictKeyring(const std::string& keyring) {
-  key_serial_t keyring_id = android::GetKeyringId(keyring);
-  if (keyctl_restrict_keyring(keyring_id, nullptr, nullptr) < 0) {
-    error(1, errno, "Cannot restrict keyring '%s'", keyring.c_str());
-    return 1;
-  }
-  return 0;
-}
-
-std::string RetrieveSecurityContext(key_serial_t key) {
-  // Simply assume this size is enough in practice.
-  const int kMaxSupportedSize = 256;
-  std::string context;
-  context.resize(kMaxSupportedSize);
-  long retval = keyctl_get_security(key, context.data(), kMaxSupportedSize);
-  if (retval < 0) {
-    error(1, errno, "Cannot get security context of key %x", key);
-    return std::string();
-  }
-  if (retval > kMaxSupportedSize) {
-    error(1, 0, "The key has unexpectedly long security context than %d", kMaxSupportedSize);
-    return std::string();
-  }
-  context.resize(retval);
-  return context;
-}
-
-int main(int argc, const char** argv) {
-  if (argc < 2) Usage(1);
-  const std::string action = argv[1];
-
-  if (action == "add") {
-    if (argc != 6) Usage(1);
-    std::string type = argv[2];
-    std::string desc = argv[3];
-    std::string data = argv[4];
-    std::string keyring = argv[5];
-    return Add(type, desc, data, keyring);
-  } else if (action == "padd") {
-    if (argc != 5) Usage(1);
-    std::string type = argv[2];
-    std::string desc = argv[3];
-    std::string keyring = argv[4];
-    return Padd(type, desc, keyring);
-  } else if (action == "restrict_keyring") {
-    if (argc != 3) Usage(1);
-    std::string keyring = argv[2];
-    return RestrictKeyring(keyring);
-  } else if (action == "unlink") {
-    if (argc != 4) Usage(1);
-    key_serial_t key = parseKeyOrDie(argv[2]);
-    const std::string keyring = argv[3];
-    return Unlink(key, keyring);
-  } else if (action == "security") {
-    if (argc != 3) Usage(1);
-    const char* key_str = argv[2];
-    key_serial_t key = parseKeyOrDie(key_str);
-    std::string context = RetrieveSecurityContext(key);
-    if (context.empty()) {
-      perror(key_str);
-      return 1;
-    }
-    fprintf(stderr, "%s\n", context.c_str());
-    return 0;
-  } else {
-    fprintf(stderr, "Unrecognized action: %s\n", action.c_str());
-    Usage(1);
-  }
-
-  return 0;
-}
diff --git a/mini_keyctl/mini_keyctl_utils.cpp b/mini_keyctl/mini_keyctl_utils.cpp
deleted file mode 100644
index fb9503f14b..0000000000
--- a/mini_keyctl/mini_keyctl_utils.cpp
+++ /dev/null
@@ -1,83 +0,0 @@
-/*
- * Copyright (C) 2019 The Android Open Source Project
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
-#include <mini_keyctl_utils.h>
-
-#include <fstream>
-#include <iterator>
-#include <sstream>
-#include <string>
-#include <vector>
-
-#include <android-base/logging.h>
-#include <android-base/parseint.h>
-
-namespace android {
-
-namespace {
-
-std::vector<std::string> SplitBySpace(const std::string& s) {
-  std::istringstream iss(s);
-  return std::vector<std::string>{std::istream_iterator<std::string>{iss},
-                                  std::istream_iterator<std::string>{}};
-}
-
-}  // namespace
-
-// Find the keyring id. request_key(2) only finds keys in the process, session or thread keyring
-// hierarchy, but not internal keyring of a kernel subsystem (e.g. .fs-verity). To support all
-// cases, this function looks up a keyring's ID by parsing /proc/keys. The keyring description may
-// contain other information in the descritption section depending on the key type, only the first
-// word in the keyring description is used for searching.
-key_serial_t GetKeyringId(const std::string& keyring_desc) {
-  // If the keyring id is already a hex number, directly convert it to keyring id
-  key_serial_t keyring_id;
-  if (android::base::ParseInt(keyring_desc.c_str(), &keyring_id)) {
-    return keyring_id;
-  }
-
-  // Only keys allowed by SELinux rules will be shown here.
-  std::ifstream proc_keys_file("/proc/keys");
-  if (!proc_keys_file.is_open()) {
-    PLOG(ERROR) << "Failed to open /proc/keys";
-    return -1;
-  }
-
-  std::string line;
-  while (getline(proc_keys_file, line)) {
-    std::vector<std::string> tokens = SplitBySpace(line);
-    if (tokens.size() < 9) {
-      continue;
-    }
-    std::string key_id = "0x" + tokens[0];
-    std::string key_type = tokens[7];
-    // The key description may contain space.
-    std::string key_desc_prefix = tokens[8];
-    // The prefix has a ":" at the end
-    std::string key_desc_pattern = keyring_desc + ":";
-    if (key_type != "keyring" || key_desc_prefix != key_desc_pattern) {
-      continue;
-    }
-    if (!android::base::ParseInt(key_id.c_str(), &keyring_id)) {
-      LOG(ERROR) << "Unexpected key format in /proc/keys: " << key_id;
-      return -1;
-    }
-    return keyring_id;
-  }
-  return -1;
-}
-
-}  // namespace android
diff --git a/mkbootfs/Android.bp b/mkbootfs/Android.bp
index e0191f0dcc..681de8ce63 100644
--- a/mkbootfs/Android.bp
+++ b/mkbootfs/Android.bp
@@ -13,6 +13,7 @@ cc_binary_host {
         "libcutils",
         "liblog",
     ],
+    stl: "libc++_static",
     dist: {
         targets: ["dist_files"],
     },
diff --git a/rootdir/etc/linker.config.json b/rootdir/etc/linker.config.json
index 8b3542f325..24e17dcc6c 100644
--- a/rootdir/etc/linker.config.json
+++ b/rootdir/etc/linker.config.json
@@ -23,7 +23,9 @@
     // adbd
     "libadb_pairing_auth.so",
     "libadb_pairing_connection.so",
-    "libadb_pairing_server.so"
+    "libadb_pairing_server.so",
+    // media.swcodec
+    "libcom.android.media.swcodec.apexcodecs.so"
 
     // LLNDK libraries in APEXes will be added automatically from the build,
     // using build variable LLNDK_MOVED_TO_APEX_LIBRARIES.
diff --git a/rootdir/init.rc b/rootdir/init.rc
index 471059bc87..2b1e68ae83 100644
--- a/rootdir/init.rc
+++ b/rootdir/init.rc
@@ -75,11 +75,14 @@ on early-init
     # Mount tracefs (with GID=AID_READTRACEFS)
     mount tracefs tracefs /sys/kernel/tracing gid=3012
 
+    # Run the init_dev_config service to configure the device.
+    exec_start init_dev_config
+
     # Run apexd-bootstrap so that APEXes that provide critical libraries
     # become available. Note that this is executed as exec_start to ensure that
     # the libraries are available to the processes started after this statement.
     exec_start apexd-bootstrap
-    perform_apex_config --bootstrap
+    perform_apex_config
 
     # These must already exist by the time boringssl_self_test32 / boringssl_self_test64 run.
     mkdir /dev/boringssl 0755 root root
@@ -116,13 +119,14 @@ on init
 
     # cpuctl hierarchy for devices using utilclamp
     mkdir /dev/cpuctl/foreground
-    mkdir /dev/cpuctl/foreground_window
     mkdir /dev/cpuctl/background
     mkdir /dev/cpuctl/top-app
     mkdir /dev/cpuctl/rt
     mkdir /dev/cpuctl/system
     mkdir /dev/cpuctl/system-background
     mkdir /dev/cpuctl/dex2oat
+    # move foreground_window to the bottom to preserve the original order
+    mkdir /dev/cpuctl/foreground_window
     chown system system /dev/cpuctl
     chown system system /dev/cpuctl/foreground
     chown system system /dev/cpuctl/foreground_window
@@ -313,9 +317,6 @@ on init
     mkdir /dev/cpuset/foreground
     copy /dev/cpuset/cpus /dev/cpuset/foreground/cpus
     copy /dev/cpuset/mems /dev/cpuset/foreground/mems
-    mkdir /dev/cpuset/foreground_window
-    copy /dev/cpuset/cpus /dev/cpuset/foreground_window/cpus
-    copy /dev/cpuset/mems /dev/cpuset/foreground_window/mems
     mkdir /dev/cpuset/background
     copy /dev/cpuset/cpus /dev/cpuset/background/cpus
     copy /dev/cpuset/mems /dev/cpuset/background/mems
@@ -336,6 +337,11 @@ on init
     copy /dev/cpuset/cpus /dev/cpuset/top-app/cpus
     copy /dev/cpuset/mems /dev/cpuset/top-app/mems
 
+    # move foreground_window to the bottom to preserve the original order
+    mkdir /dev/cpuset/foreground_window
+    copy /dev/cpuset/cpus /dev/cpuset/foreground_window/cpus
+    copy /dev/cpuset/mems /dev/cpuset/foreground_window/mems
+
     # create a cpuset for camera daemon processes
     mkdir /dev/cpuset/camera-daemon
     copy /dev/cpuset/cpus /dev/cpuset/camera-daemon/cpus
@@ -605,6 +611,8 @@ on post-fs
 
     mkdir /metadata/apex 0700 root system
     mkdir /metadata/apex/sessions 0700 root system
+    mkdir /metadata/apex/images 0700 root system
+    mkdir /metadata/apex/config 0700 root system
     # On some devices we see a weird behaviour in which /metadata/apex doesn't
     # have a correct label. To workaround this bug, explicitly call restorecon
     # on /metadata/apex. For most of the boot sequences /metadata/apex will
@@ -727,6 +735,7 @@ on post-fs-data
     mkdir /data/apex/active 0755 root system
     mkdir /data/apex/backup 0700 root system
     mkdir /data/apex/decompressed 0755 root system encryption=Require
+    mkdir /data/apex/images 0755 root system
     mkdir /data/app-staging 0751 system system encryption=DeleteIfNecessary
     mkdir /data/apex/ota_reserved 0700 root system encryption=Require
     setprop apexd.status ""
@@ -788,7 +797,6 @@ on post-fs-data
     mkdir /data/misc/boottrace 0771 system shell
     mkdir /data/misc/update_engine 0700 root root
     mkdir /data/misc/update_engine_log 02750 root update_engine_log
-    chown root update_engine_log /data/misc/update_engine_log
     mkdir /data/misc/trace 0700 root root
     # create location to store surface and window trace files
     mkdir /data/misc/wmtrace 0700 system system
@@ -1002,11 +1010,7 @@ on post-fs-data
     wait_for_prop keystore.module_hash.sent true
     perform_apex_config
 
-    exec_start system_aconfigd_mainline_init
     start system_aconfigd_socket_service
-
-    # start mainline aconfigd init, after transition, the above system_aconfigd_mainline_init
-    # will be deprecated
     exec_start mainline_aconfigd_init
     start mainline_aconfigd_socket_service
 
@@ -1049,11 +1053,6 @@ on post-fs-data
     # completed and apexd.status becomes "ready".
     exec_start apexd-snapshotde
 
-    # sys.memfd_use set to false by default, which keeps it disabled
-    # until it is confirmed that apps and vendor processes don't make
-    # IOCTLs on ashmem fds any more.
-    setprop sys.use_memfd false
-
     # Set fscklog permission
     chown root system /dev/fscklogs/log
     chmod 0770 /dev/fscklogs/log
@@ -1098,6 +1097,13 @@ on boot && property:ro.config.low_ram=true
     write /proc/sys/vm/dirty_expire_centisecs 200
     write /proc/sys/vm/dirty_background_ratio  5
 
+on property:sys.boot_completed=1 && property:ro.config.batteryless=true
+    # Flush data and checkpoint more aggressively to prepare sudden power cuts
+    write /proc/sys/vm/dirty_expire_centisecs 200
+    write /proc/sys/vm/dirty_writeback_centisecs 200
+    write /proc/sys/vm/dirty_background_ratio  5
+    write /dev/sys/fs/by-name/userdata/cp_interval 2
+
 on boot && property:suspend.disable_sync_on_suspend=true
     write /sys/power/sync_on_suspend 0
 
@@ -1136,7 +1142,7 @@ on boot
     # to avoid power consumption when system becomes mostly idle. Be careful
     # to make it too large, since it may bring userdata loss, if they
     # are not aware of using fsync()/sync() to prepare sudden power-cut.
-    write /dev/sys/fs/by-name/userdata/cp_interval 200
+    write /dev/sys/fs/by-name/userdata/cp_interval 30
     write /dev/sys/fs/by-name/userdata/gc_urgent_sleep_time 50
     write /dev/sys/fs/by-name/userdata/iostat_period_ms 1000
     write /dev/sys/fs/by-name/userdata/iostat_enable 1
@@ -1294,6 +1300,18 @@ service ueventd /system/bin/ueventd
     user root
     shutdown critical
 
+# This service takes care of early initialization of device configuration at
+# runtime, like per-SKU settings or sysprops. The service runs before apexd
+# bootstrap, which means it can also be used to perform conditional APEX
+# activation via selection sysprops (e.g. setting ro.boot.vendor.apex.*).
+# The 'ro.vendor.init_dev_config.path' sysprop should be configured at build
+# time via PRODUCT_VENDOR_PROPERTIES, and must point to a binary built with
+# bootstrap bionic and labeled as 'init_dev_config_exec'.
+service init_dev_config ${ro.vendor.init_dev_config.path}
+    oneshot
+    user system
+    seclabel u:r:init_dev_config:s0
+
 service console /system/bin/sh
     class core
     console
diff --git a/rootdir/ramdisk_node_list b/rootdir/ramdisk_node_list
index 4f45faaec4..864a39b3e9 100644
--- a/rootdir/ramdisk_node_list
+++ b/rootdir/ramdisk_node_list
@@ -2,3 +2,4 @@ dir dev 0755 0 0
 nod dev/null 0600 0 0 c 1 3
 nod dev/console 0600 0 0 c 5 1
 nod dev/urandom 0600 0 0 c 1 9
+nod dev/kmsg 0600 0 0 c 1 11
diff --git a/rootdir/ueventd.rc b/rootdir/ueventd.rc
index 3927501a47..61f73dd9b3 100644
--- a/rootdir/ueventd.rc
+++ b/rootdir/ueventd.rc
@@ -79,6 +79,10 @@ subsystem vfio
 /dev/kvm                  0666   root       root
 /dev/vhost-vsock          0666   root       root
 
+# apexd creates DM for downloaded APEX files, which should be readable by
+# system_server (PackageManager).
+/dev/block/dm-*           0640   root       system
+
 # sysfs properties
 /sys/devices/platform/trusty.*      trusty_version        0440  root   log
 /sys/devices/virtual/input/input*   enable      0660  root   input
diff --git a/shell_and_utilities/Android.bp b/shell_and_utilities/Android.bp
index 0a1f7c5a29..db55b28ac5 100644
--- a/shell_and_utilities/Android.bp
+++ b/shell_and_utilities/Android.bp
@@ -22,7 +22,6 @@ phony {
         "fsck.exfat",
         "ldd",
         "logwrapper",
-        "mini-keyctl",
         "mkfs.exfat",
         "mkshrc",
         "newfs_msdos",
diff --git a/storaged/tests/Android.bp b/storaged/tests/Android.bp
new file mode 100644
index 0000000000..b7d44e6dd9
--- /dev/null
+++ b/storaged/tests/Android.bp
@@ -0,0 +1,24 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+filegroup {
+    name: "storaged_check_for_ufs_script",
+    srcs: ["check_for_ufs.sh"],
+}
diff --git a/storaged/tests/OWNERS b/storaged/tests/OWNERS
new file mode 100644
index 0000000000..3df1452243
--- /dev/null
+++ b/storaged/tests/OWNERS
@@ -0,0 +1,4 @@
+# By default, use the OWNERS from higher levels
+
+# For this single file, add the folks working on some performance automation.
+per-file check_for_ufs.sh = file:platform/frameworks/base:/tests/BouncyBall/OWNERS
diff --git a/storaged/tests/check_for_ufs.sh b/storaged/tests/check_for_ufs.sh
new file mode 100644
index 0000000000..882bf742f2
--- /dev/null
+++ b/storaged/tests/check_for_ufs.sh
@@ -0,0 +1,185 @@
+#!/system/bin/sh
+
+# Copyright (C) 2025 The Android Open Source Project
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
+
+# This script is used to determine if an Android device is using UFS or eMMC.
+# We consider using UFS to be a "success" (exit code 0), and using eMMC or
+# other unexpected issues to be a "failure" (non-zero exit code).
+
+# There is no universal straight-forward way to determine UFS vs. eMMC, so
+# we use educated guesses.  Due to places where this script is used, we also
+# need this to work without root access on the device.
+
+# Our high level logic:
+#
+# Assume /dev/block/by-name/userdata is a symlink to /dev/block/USERDATA_BLOCK.
+# - If USERDATA_BLOCK starts with "mmc", then this is eMMC.
+#
+# Assume /sys/class/block/USERDATA_BLOCK is a symlink to FULL_PATH.
+# - If FULL_PATH contains "/host0/", this is UFS.
+# - Otherwise, this is eMMC.
+#
+# If any of our assumptions don't hold (can't access/find certain paths),
+# then we consider it a failure.
+#
+# Note that we don't expect to be able to access FULL_PATH without root.  But
+# fortunately we don't need access, just the name.
+
+
+# Exit codes
+# LINT.IfChange
+readonly USING_UFS=0  # Must be 0 to indicate non-error
+readonly USING_EMMC=1
+readonly SETUP_ISSUE=2
+readonly INTERNAL_ERROR=3
+# LINT.ThenChange(//cts/hostsidetests/edi/src/android/edi/cts/StorageIoInterfaceDeviceInfo.java)
+
+# All of these shell commands are assumed to be on the device.
+readonly REQUIRED_CMDS="readlink sed"
+
+readonly USERDATA_BY_NAME="/dev/block/by-name/userdata"
+
+# Global variables (I know, but it's shell, so this is easiest)
+userdata_block="UNSET"
+# "Return value" of get_symlink_path()
+symlink_path_result="UNSET"
+
+
+# The output of this script will be used by automated testing, and analyzed
+# at scale.  As such, we want to normalize the output, and try to just have
+# a single line to analyze.
+function exit_script() {
+  local exit_code=$1
+  local message="$2"
+
+  local prefix=""
+  case ${exit_code} in
+    ${USING_UFS}) prefix="UFS Detected";;
+    ${USING_EMMC}) prefix="eMMC Detected";;
+    ${SETUP_ISSUE}) prefix="ERROR";;
+    ${INTERNAL_ERROR}) prefix="INTERNAL ERROR";;
+    *)
+      prefix="UNEXPECTED EXIT CODE (${exit_code})"
+      exit_code=${INTERNAL_ERROR}
+      ;;
+  esac
+
+  # LINT.IfChange
+  echo "${prefix}: ${message}"
+  # LINT.ThenChange(//cts/hostsidetests/edi/src/android/edi/cts/StorageIoInterfaceDeviceInfo.java)
+  exit ${exit_code}
+}
+
+# Exit in failure if we lack commands this script needs.
+function check_setup() {
+  # We explicitly check for these commands, because if we're missing any,
+  # this error message will be vastly easier to debug.
+  local missing_cmds=""
+  for cmd in ${REQUIRED_CMDS}; do
+    if ! command -v "${cmd}" > /dev/null; then
+      missing_cmds="${missing_cmds} ${cmd}"
+    fi
+  done
+
+  if [ -n "${missing_cmds}" ]; then
+    local msg="Missing at least one of the required binaries: ${missing_cmds}"
+    exit_script ${SETUP_ISSUE} "${msg}"
+  fi
+}
+
+
+# Populate the global "symlink_path_result" with the first level of what
+# the given "symlink" points to.  Exit in error if we can't figure it out.
+function get_symlink_path() {
+  # Using global symlink_path_result
+
+  local symlink="$1"
+
+  # "-L" tests if the file is a symbolic link.  We perform this check first
+  # to give a more specific error message to aid debugging.  Very notably,
+  # we do not use "-e" to check existence here, because that will fail if
+  # we don't have access permissions to the destination of the link.
+  if [ ! -L ${symlink} ]; then
+    local msg="Could not find/access symlink ${symlink}"
+    exit_script ${SETUP_ISSUE} "${msg}"
+  fi
+
+  # Note we do not use "-e" here, as we don't expect to have (non-root)
+  # access to the full resolution of some of our symlinks.
+  symlink_path_result=`readlink ${symlink}`
+  local readlink_result=$?
+
+  if [ ${readlink_result} -ne 0 ]; then
+    local msg="Failed 'readlink ${symlink}'"
+    exit_script ${SETUP_ISSUE} "${msg}"
+  fi
+}
+
+
+# Set the global variable userdata_block, or exit in failure if we can't.
+function set_userdata_block {
+  # Using globals userdata_block, symlink_path_result
+
+  get_symlink_path "${USERDATA_BY_NAME}"
+
+  # Remove the "/dev/block/" part.
+  userdata_block=`echo ${symlink_path_result} | sed 's#/dev/block/##'`
+
+  # Done using this global.
+  symlink_path_result="UNSET"
+}
+
+
+# If the userdata block starts with "mmc", it's eMMC.
+function exit_if_userdata_block_is_emmc {
+  # Using global userdata_block
+
+  case "${userdata_block}" in
+     mmc*)
+       local msg="userdata block is ${userdata_block}"
+       exit_script ${USING_EMMC} "${msg}"
+       ;;
+  esac
+}
+
+
+# See if our userdata_block resolves to something under host0.
+function check_for_userdata_block_within_host0 {
+  # Using globals userdata_block, symlink_path_result
+
+  get_symlink_path "/sys/class/block/${userdata_block}"
+
+  case "${symlink_path_result}" in
+    */host0/*)
+      local msg="userdata ${userdata_block} is within host0"
+      exit_script ${USING_UFS} "${msg}"
+      ;;
+  esac
+
+  local msg="userdata ${userdata_block} is not within host0 (${symlink_path_result})"
+  exit_script ${USING_EMMC} "${msg}"
+}
+
+
+check_setup
+
+set_userdata_block
+exit_if_userdata_block_is_emmc
+
+# This function will exit, concluding either eMMC or UFS.
+check_for_userdata_block_within_host0
+
+exit_script ${INTERNAL_ERROR} "Unexpectedly at the end of the script file"
diff --git a/toolbox/modprobe.cpp b/toolbox/modprobe.cpp
index fe49ec811e..c5025e7b49 100644
--- a/toolbox/modprobe.cpp
+++ b/toolbox/modprobe.cpp
@@ -46,7 +46,7 @@ void print_usage(void) {
     LOG(INFO) << "  modprobe [options] [-d DIR] MODULE [symbol=value]...";
     LOG(INFO);
     LOG(INFO) << "Options:";
-    LOG(INFO) << "  --all=FILE: FILE to acquire module names from";
+    LOG(INFO) << "  -a, --all=FILE: FILE to acquire module names from";
     LOG(INFO) << "  -b, --use-blocklist: Apply blocklist to module names too";
     LOG(INFO) << "  -d, --dirname=DIR: Load modules from DIR, option may be used multiple times";
     LOG(INFO) << "  -D, --show-depends: Print dependencies for modules only, do not load";
diff --git a/trusty/gatekeeper/Android.bp b/trusty/gatekeeper/Android.bp
index 0b43754205..90e39a31d5 100644
--- a/trusty/gatekeeper/Android.bp
+++ b/trusty/gatekeeper/Android.bp
@@ -57,5 +57,11 @@ cc_binary {
         "libtrusty",
     ],
 
-    vintf_fragments: ["android.hardware.gatekeeper-service.trusty.xml"],
+    vintf_fragment_modules: ["android.hardware.gatekeeper-service.trusty.xml"],
+}
+
+vintf_fragment {
+    name: "android.hardware.gatekeeper-service.trusty.xml",
+    src: "android.hardware.gatekeeper-service.trusty.xml",
+    vendor: true,
 }
diff --git a/trusty/libtrusty/include/trusty/tipc.h b/trusty/libtrusty/include/trusty/tipc.h
index b44afd3379..e09536ae11 100644
--- a/trusty/libtrusty/include/trusty/tipc.h
+++ b/trusty/libtrusty/include/trusty/tipc.h
@@ -24,6 +24,17 @@ extern "C" {
 #include <sys/uio.h>
 #include <trusty/ipc.h>
 
+/*
+ * The Trusty driver uses a 4096-byte shared buffer to transfer messages.
+ * However, the virtio/TIPC bridge overestimates the portion of the buffer
+ * available to it. Specifically, it does not account for the TIPC headers
+ * and the FDs being transferred. We reserve some of the buffer here to
+ * account for this. The reserved size is chosen to allow room for the
+ * TIPC header (16 bytes), 8x FD (24 bytes), plus some margin.
+ */
+#define TIPC_HDR_AND_FDS_MAX_SIZE 256
+#define VIRTIO_VSOCK_MSG_SIZE_LIMIT (4096 - TIPC_HDR_AND_FDS_MAX_SIZE)
+
 int tipc_connect(const char *dev_name, const char *srv_name);
 ssize_t tipc_send(int fd, const struct iovec* iov, int iovcnt, struct trusty_shm* shm, int shmcnt);
 int tipc_close(int fd);
diff --git a/trusty/secretkeeper/Android.bp b/trusty/secretkeeper/Android.bp
index d399bf86d0..6523edaf69 100644
--- a/trusty/secretkeeper/Android.bp
+++ b/trusty/secretkeeper/Android.bp
@@ -27,16 +27,18 @@ rust_binary {
         "src/hal_main.rs",
     ],
     rustlibs: [
-        "android.hardware.security.secretkeeper-V1-rust",
         "libandroid_logger",
         "libauthgraph_hal",
         "libauthgraph_wire",
         "libbinder_rs",
         "liblibc",
         "liblog_rust",
-        "libsecretkeeper_hal_v1",
+        "libsecretkeeper_hal",
         "libtrusty-rs",
     ],
+    defaults: [
+        "secretkeeper_use_latest_hal_aidl_rust",
+    ],
     prefer_rlib: true,
 }
 
diff --git a/trusty/secretkeeper/android.hardware.security.secretkeeper.trusty.xml b/trusty/secretkeeper/android.hardware.security.secretkeeper.trusty.xml
index 2ac152bf27..31e092dd22 100644
--- a/trusty/secretkeeper/android.hardware.security.secretkeeper.trusty.xml
+++ b/trusty/secretkeeper/android.hardware.security.secretkeeper.trusty.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.security.secretkeeper</name>
-        <version>1</version>
+        <version>2</version>
         <fqname>ISecretkeeper/default</fqname>
     </hal>
 </manifest>
diff --git a/trusty/storage/proxy/ipc.c b/trusty/storage/proxy/ipc.c
index 57cf600b63..171777d9db 100644
--- a/trusty/storage/proxy/ipc.c
+++ b/trusty/storage/proxy/ipc.c
@@ -102,7 +102,7 @@ int ipc_respond(struct storage_msg *msg, void *out, size_t out_size)
 
     msg->cmd |= STORAGE_RESP_BIT;
 
-    rc = writev(tipc_fd, iovs, out ? 2 : 1);
+    rc = TEMP_FAILURE_RETRY(writev(tipc_fd, iovs, out ? 2 : 1));
     if (rc < 0) {
         ALOGE("error sending response 0x%x: %s\n",
               msg->cmd, strerror(errno));
diff --git a/trusty/storage/proxy/proxy.c b/trusty/storage/proxy/proxy.c
index 6cb72d5976..ebd43d8303 100644
--- a/trusty/storage/proxy/proxy.c
+++ b/trusty/storage/proxy/proxy.c
@@ -15,6 +15,7 @@
  */
 #include <errno.h>
 #include <getopt.h>
+#include <signal.h>
 #include <stdbool.h>
 #include <stdint.h>
 #include <stdlib.h>
@@ -37,6 +38,8 @@
 #define REQ_BUFFER_SIZE 4096
 static uint8_t req_buffer[REQ_BUFFER_SIZE + 1];
 
+static volatile sig_atomic_t terminate = false;
+
 static const char* ss_data_root;
 static const char* trusty_devname;
 static const char* rpmb_devname;
@@ -120,6 +123,10 @@ static void show_usage_and_exit(int code) {
     exit(code);
 }
 
+static void handle_sigterm(int signum __attribute__((unused))) {
+    terminate = true;
+}
+
 static int handle_req(struct storage_msg* msg, const void* req, size_t req_len) {
     int rc;
 
@@ -218,10 +225,14 @@ static int proxy_loop(void) {
     struct storage_msg msg;
 
     /* enter main message handling loop */
-    while (true) {
+    while (!terminate) {
         /* get incoming message */
         rc = ipc_get_msg(&msg, req_buffer, REQ_BUFFER_SIZE);
-        if (rc < 0) return rc;
+        if (rc == EINTR && terminate) {
+            return 0;
+        } else if (rc < 0) {
+            return rc;
+        }
 
         /* handle request */
         req_buffer[rc] = 0; /* force zero termination */
@@ -303,6 +314,12 @@ int main(int argc, char* argv[]) {
      */
     umask(S_IRWXG | S_IRWXO);
 
+    /* catch SIGTERM for graceful shutdown */
+    const struct sigaction sa = {
+            .sa_handler = handle_sigterm,
+    };
+    sigaction(SIGTERM, &sa, NULL);
+
     /* parse arguments */
     parse_args(argc, argv);
 
@@ -332,10 +349,14 @@ int main(int argc, char* argv[]) {
 
     /* enter main loop */
     rc = proxy_loop();
-    ALOGE("exiting proxy loop with status (%d)\n", rc);
+    if (terminate) {
+        ALOGI("proxy loop terminated with status (%d)\n", rc);
+    } else {
+        ALOGE("exiting proxy loop with status (%d)\n", rc);
+    }
 
     ipc_disconnect();
     rpmb_close();
 
-    return (rc < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
+    _exit((rc < 0) ? EXIT_FAILURE : EXIT_SUCCESS);
 }
diff --git a/trusty/storage/proxy/rpmb.c b/trusty/storage/proxy/rpmb.c
index 1f5d107969..86a7c30074 100644
--- a/trusty/storage/proxy/rpmb.c
+++ b/trusty/storage/proxy/rpmb.c
@@ -407,7 +407,9 @@ static int send_ufs_rpmb_req(int sg_fd, const struct storage_rpmb_send_req* req,
      * receive an async notification that the service is started to avoid
      * blocking (see main).
      */
+    watch_progress(watcher, "rpmb ufs acquire wake_lock");
     wl_rc = acquire_wake_lock(PARTIAL_WAKE_LOCK, UFS_WAKE_LOCK_NAME);
+    watch_progress(watcher, "rpmb ufs acquire wake_lock done");
     if (wl_rc < 0) {
         ALOGE("%s: failed to acquire wakelock: %d, %s\n", __func__, wl_rc, strerror(errno));
         return wl_rc;
@@ -476,7 +478,9 @@ static int send_ufs_rpmb_req(int sg_fd, const struct storage_rpmb_send_req* req,
     }
 
 err_op:
+    watch_progress(watcher, "rpmb ufs release wake_lock");
     wl_rc = release_wake_lock(UFS_WAKE_LOCK_NAME);
+    watch_progress(watcher, "rpmb ufs release wake_lock done");
     if (wl_rc < 0) {
         ALOGE("%s: failed to release wakelock: %d, %s\n", __func__, wl_rc, strerror(errno));
     }
diff --git a/trusty/test/driver/trusty_driver_test.py b/trusty/test/driver/trusty_driver_test.py
index 608fd470f0..d86b48b600 100644
--- a/trusty/test/driver/trusty_driver_test.py
+++ b/trusty/test/driver/trusty_driver_test.py
@@ -31,35 +31,56 @@ def WriteFile(file_path, s):
 def IsTrustySupported():
     return os.path.exists("/dev/trusty-ipc-dev0")
 
+def MatchTrustyDevice(de: os.DirEntry, suffix: str):
+    for core in ["-core", ""]:
+        candidate = f":trusty{core}{suffix}"
+        if de.name == candidate[1:]:
+            return de
+        if de.name.endswith(candidate):
+            return de
+
+    return None
+
+def FindTrustyDevice(suffix: str):
+    with os.scandir("/sys/bus/platform/devices") as it:
+        candidates = (MatchTrustyDevice(de, suffix) for de in it)
+        final = (de.name for de in candidates if de is not None)
+        return next(final)
+
 @unittest.skipIf(not IsTrustySupported(), "Device does not support Trusty")
 class TrustyDriverTest(unittest.TestCase):
     def testIrqDriverBinding(self):
-        WriteFile("/sys/bus/platform/drivers/trusty-irq/unbind", "trusty:irq")
-        WriteFile("/sys/bus/platform/drivers/trusty-irq/bind", "trusty:irq")
+        dev = FindTrustyDevice(":irq")
+        WriteFile("/sys/bus/platform/drivers/trusty-irq/unbind", dev)
+        WriteFile("/sys/bus/platform/drivers/trusty-irq/bind", dev)
 
     def testLogDriverBinding(self):
-        WriteFile("/sys/bus/platform/drivers/trusty-log/unbind", "trusty:log")
-        WriteFile("/sys/bus/platform/drivers/trusty-log/bind", "trusty:log")
+        dev = FindTrustyDevice(":log")
+        WriteFile("/sys/bus/platform/drivers/trusty-log/unbind", dev)
+        WriteFile("/sys/bus/platform/drivers/trusty-log/bind", dev)
 
     @unittest.skip("TODO(b/142275662): virtio remove currently hangs")
     def testVirtioDriverBinding(self):
-        WriteFile("/sys/bus/platform/drivers/trusty-virtio/unbind",
-                  "trusty:virtio")
-        WriteFile("/sys/bus/platform/drivers/trusty-virtio/bind",
-                  "trusty:virtio")
+        dev = FindTrustyDevice(":virtio")
+        WriteFile("/sys/bus/platform/drivers/trusty-virtio/unbind", dev)
+        WriteFile("/sys/bus/platform/drivers/trusty-virtio/bind", dev)
 
     @unittest.skip("TODO(b/142275662): virtio remove currently hangs")
     def testTrustyDriverBinding(self):
-        WriteFile("/sys/bus/platform/drivers/trusty/unbind", "trusty")
-        WriteFile("/sys/bus/platform/drivers/trusty/bind", "trusty")
+        dev = FindTrustyDevice("")
+        WriteFile("/sys/bus/platform/drivers/trusty/unbind", dev)
+        WriteFile("/sys/bus/platform/drivers/trusty/bind", dev)
 
     def testTrustyDriverVersion(self):
-        ver = ReadFile("/sys/bus/platform/devices/trusty/trusty_version")
+        dev = FindTrustyDevice("")
+        ver = ReadFile(f"/sys/bus/platform/devices/{dev}/trusty_version")
         self.assertTrue(ver.startswith("Project:"))
 
     def testUntaintedLinux(self):
-        tainted = ReadFile("/proc/sys/kernel/tainted")
-        self.assertEqual(tainted, "0")
+        tainted = int(ReadFile("/proc/sys/kernel/tainted"))
+        # Filter out the out-of-tree and unsigned module bits
+        tainted &= ~0x3000
+        self.assertEqual(tainted, 0)
 
     # stdcall test with shared memory buffers.
     # Each test run takes up to 4 arguments:
@@ -73,7 +94,8 @@ class TrustyDriverTest(unittest.TestCase):
     # Test 10 4K shared memory objects, shared 10 times, each accessed
     # 10 times.
     def testStdCall(self):
-        test = "/sys/devices/platform/trusty/trusty:test/trusty_test_run"
+        dev = FindTrustyDevice(":test")
+        test = f"/sys/bus/platform/devices/{dev}/trusty_test_run"
         args = "0x1000 0x800000,10,2,2 0x800000,2,100,0 0x1000,10,10,10"
         WriteFile(test, args)
 
```

