```diff
diff --git a/boottime_tools/bootanalyze/bootanalyze.py b/boottime_tools/bootanalyze/bootanalyze.py
index 2b47a899..5bdcb546 100755
--- a/boottime_tools/bootanalyze/bootanalyze.py
+++ b/boottime_tools/bootanalyze/bootanalyze.py
@@ -40,6 +40,7 @@ KERNEL_TIME_KEY = "kernel"
 BOOT_ANIM_END_TIME_KEY = "BootAnimEnd"
 KERNEL_BOOT_COMPLETE = "BootComplete_kernel"
 LOGCAT_BOOT_COMPLETE = "BootComplete"
+ANDROID_INIT_SECOND_STAGE = "android_init_2st_stage"
 CARWATCHDOG_BOOT_COMPLETE = "CarWatchdogBootupProfilingComplete"
 LAUNCHER_START = "LauncherStart"
 CARWATCHDOG_DUMP_COMMAND = "adb shell dumpsys android.automotive.watchdog.ICarWatchdog/default"
@@ -318,8 +319,12 @@ def handle_reboot_log(capture_log_on_error, shutdown_events_pattern, components_
 
 def collect_dmesg_events(search_events_pattern, timings_pattern, results):
   dmesg_events, kernel_timing_events = collect_events(search_events_pattern, ADB_CMD +\
-                                                      ' shell su root dmesg -w', timings_pattern,\
-                                                      [KERNEL_BOOT_COMPLETE], True)
+                                                      ' shell su root dmesg -w', timings_pattern,
+                                                      [
+                                                        KERNEL_BOOT_COMPLETE,
+                                                        ANDROID_INIT_SECOND_STAGE
+                                                      ],
+                                                      False, True)
   results.append(dmesg_events)
   results.append(kernel_timing_events)
 
@@ -349,7 +354,7 @@ def iterate(args, search_events_pattern, timings_pattern, shutdown_events_patter
     logcat_stop_events.append(CARWATCHDOG_BOOT_COMPLETE)
   logcat_events, logcat_timing_events = collect_events(
     search_events_pattern, ADB_CMD + ' logcat -b all -v epoch', timings_pattern,\
-    logcat_stop_events, False)
+    logcat_stop_events, True, False)
 
   t.join()
   dmesg_events = results[0]
@@ -389,16 +394,27 @@ def iterate(args, search_events_pattern, timings_pattern, shutdown_events_patter
     diffs.append((logcat_event_time[KERNEL_TIME_KEY], logcat_event_time[KERNEL_TIME_KEY]))
 
   if logcat_event_time.get(BOOT_ANIM_END_TIME_KEY) and dmesg_event_time.get(BOOT_ANIM_END_TIME_KEY):
-      diffs.append((logcat_event_time[BOOT_ANIM_END_TIME_KEY],\
+    diffs.append((logcat_event_time[BOOT_ANIM_END_TIME_KEY],\
                     logcat_event_time[BOOT_ANIM_END_TIME_KEY] -\
                       dmesg_event_time[BOOT_ANIM_END_TIME_KEY]))
-  if not dmesg_event_time.get(KERNEL_BOOT_COMPLETE):
-      print("BootAnimEnd time or BootComplete-kernel not captured in both log" +\
-        ", cannot get time diff")
-      print("dmesg {} logcat {}".format(dmesg_event_time, logcat_event_time))
-      return None, None, None, None, None, None
-  diffs.append((logcat_event_time[LOGCAT_BOOT_COMPLETE],\
-                logcat_event_time[LOGCAT_BOOT_COMPLETE] - dmesg_event_time[KERNEL_BOOT_COMPLETE]))
+  if logcat_event_time.get(LOGCAT_BOOT_COMPLETE) and dmesg_event_time.get(KERNEL_BOOT_COMPLETE):
+    diffs.append((
+        logcat_event_time[LOGCAT_BOOT_COMPLETE],
+        logcat_event_time[LOGCAT_BOOT_COMPLETE] - dmesg_event_time[KERNEL_BOOT_COMPLETE],
+    ))
+  elif logcat_event_time.get(ANDROID_INIT_SECOND_STAGE) and \
+      dmesg_event_time.get(ANDROID_INIT_SECOND_STAGE):
+    print("BootAnimEnd time or BootComplete-kernel not captured in both log" +\
+      ", use Android init 2nd stage get time diff")
+    diffs.append((
+      logcat_event_time[ANDROID_INIT_SECOND_STAGE],
+      logcat_event_time[ANDROID_INIT_SECOND_STAGE] - dmesg_event_time[ANDROID_INIT_SECOND_STAGE],
+    ))
+  else:
+    print("BootComplete and Android init 2nd stage not captured in both log" +\
+          ", cannot get time diff")
+    print('dmesg {} logcat {}'.format(dmesg_event_time, logcat_event_time))
+    return None, None, None, None, None, None
 
   for k, v in logcat_event_time.items():
     debug("event[{0}, {1}]".format(k, v))
@@ -419,10 +435,10 @@ def iterate(args, search_events_pattern, timings_pattern, shutdown_events_patter
       diff = diffs[0]
     events[k] = events[k] - diff[1]
     if events[k] < 0.0:
-        if events[k] < -0.1: # maybe previous one is better fit
-          events[k] = events[k] + diff[1] - diff_prev[1]
-        else:
-          events[k] = 0.0
+      if events[k] < -0.1: # maybe previous one is better fit
+        events[k] = events[k] + diff[1] - diff_prev[1]
+      else:
+        events[k] = 0.0
 
   data_points = collections.OrderedDict()
 
@@ -672,7 +688,8 @@ def log_timeout(time_left, stop_events, events, timing_events):
   print(" remaininig events {}, event {} timing events {}".\
     format(stop_events, events, timing_events))
 
-def collect_events(search_events, command, timings, stop_events, disable_timing_after_zygote):
+def collect_events(search_events, command, timings, stop_events,
+                   collects_all_events, disable_timing_after_zygote):
   events = collections.OrderedDict()
   timing_events = {}
 
@@ -681,7 +698,10 @@ def collect_events(search_events, command, timings, stop_events, disable_timing_
   start_time = time.time()
   zygote_found = False
   line = None
-  print("remaining stop_events:", stop_events)
+  if collects_all_events:
+    print("remaining stop_events:", stop_events)
+  else:
+    print("waiting for any of stop_events:", stop_events)
   init = True
   while True:
     if init:
@@ -740,8 +760,12 @@ def collect_events(search_events, command, timings, stop_events, disable_timing_
           new_event = update_name_if_already_exist(events, event)
           events[new_event] = line
         if event in stop_events:
-          stop_events.remove(event)
-          print("remaining stop_events:", stop_events)
+          if collects_all_events:
+            stop_events.remove(event)
+            print("remaining stop_events:", stop_events)
+          else:
+            # no need to wait for others
+            stop_events = []
 
       timing_event = get_boot_event(line, timings)
       if timing_event and (not disable_timing_after_zygote or not zygote_found):
@@ -826,7 +850,7 @@ def do_reboot(serial, use_adb_reboot):
   while retry < 20:
     current_devices = subprocess.check_output("adb devices", shell=True).decode('utf-8', 'ignore')
     if original_devices != current_devices:
-      if not serial or (serial and current_devices.find(serial) < 0):
+      if not serial or (serial and re.findall(serial + ".*offline", current_devices, re.MULTILINE)):
         return True
     time.sleep(1)
     retry += 1
diff --git a/boottime_tools/bootanalyze/bootanalyze.sh b/boottime_tools/bootanalyze/bootanalyze.sh
index bada4656..0398a490 100755
--- a/boottime_tools/bootanalyze/bootanalyze.sh
+++ b/boottime_tools/bootanalyze/bootanalyze.sh
@@ -28,6 +28,7 @@ Flags:
 -a : Uses "adb reboot" (instead of "adb shell su root svc power reboot") command to reboot
 -b : If set grabs bootchart
 -w : If set grabs carwatchdog perf stats
+-s : Set the device serial for adb
 '
     exit
 }
@@ -53,14 +54,16 @@ fi
 echo "RESULTS_DIR=$RESULTS_DIR"
 mkdir -p $RESULTS_DIR
 
-ADB_REBOOT_FLAG=""
+REBOOT_FLAG=""
 BOOTCHART_FLAG=""
 CARWATCHDOG_FLAG=""
+PY_SERIAL_FLAG=""
+ADB_SERIAL_FLAG=""
 
-while getopts 'abw' OPTION; do
+while getopts 'abws:' OPTION; do
   case "$OPTION" in
     a)
-      ADB_REBOOT_FLAG="-a"
+      REBOOT_FLAG="-a"
       ;;
     b)
       BOOTCHART_FLAG="-b"
@@ -68,6 +71,10 @@ while getopts 'abw' OPTION; do
     w)
       CARWATCHDOG_FLAG="-W"
       ;;
+    s)
+      PY_SERIAL_FLAG="--serial ${OPTARG}"
+      ADB_SERIAL_FLAG="-s ${OPTARG}"
+      ;;
     ?)
       echo 'Error: Invalid flag set'
       readme
@@ -77,7 +84,7 @@ done
 shift "$(($OPTIND -1))"
 
 
-adb shell 'touch /data/bootchart/enabled'
+adb $ADB_SERIAL_FLAG shell 'touch /data/bootchart/enabled'
 
 if [[ -z $LOOPS ]]; then
 	LOOPS=1
@@ -92,7 +99,7 @@ for (( l=$START; l<=$LOOPS; l++ )); do
     SECONDS=0
     mkdir $RESULTS_DIR/$l
     $SCRIPT_DIR/bootanalyze.py -c $CONFIG_YMAL -G 4M -r \
-        $ADB_REBOOT_FLAG $BOOTCHART_FLAG $CARWATCHDOG_FLAG \
+        $PY_SERIAL_FLAG $REBOOT_FLAG $BOOTCHART_FLAG $CARWATCHDOG_FLAG \
         -o "$RESULTS_DIR/$l" 1> "$RESULTS_DIR/$l/boot.txt"
     if [[ $? -ne 0 ]]; then
         echo "bootanalyze.py failed"
@@ -107,4 +114,4 @@ for (( l=$START; l<=$LOOPS; l++ )); do
 done
 
 echo
-echo "Complete $LOOPS"
\ No newline at end of file
+echo "Complete $LOOPS"
diff --git a/boottime_tools/bootanalyze/config.yaml b/boottime_tools/bootanalyze/config.yaml
index a41cfadd..009a0b1e 100644
--- a/boottime_tools/bootanalyze/config.yaml
+++ b/boottime_tools/bootanalyze/config.yaml
@@ -61,7 +61,7 @@ events:
   KeyguardShown: KeyguardServiceDelegate.*\*\*\*\* SHOWN CALLED \*\*\*\*
   BootComplete: Starting phase 1000
   BootComplete_kernel: processing action \(sys\.boot_completed=1\)
-  LauncherStart: START.*HOME.*(NexusLauncherActivity|GEL|LensPickerTrampolineActivity|SetupWizard|CarLauncher|launcher.*Launcher)
+  LauncherStart: START.*HOME.*(NexusLauncherActivity|GEL|LensPickerTrampolineActivity|SetupWizard|CarLauncher|launcher.*Launcher|LoginLauncherActivity)
   FsStat: fs_stat, partition:userdata stat:(0x\S+)
   CarWatchdogBootupProfilingComplete: Switching to PERIODIC_COLLECTION and PERIODIC_MONITOR
 shutdown_events:
diff --git a/ext4_utils/Android.bp b/ext4_utils/Android.bp
index b28e84f3..4db055bd 100644
--- a/ext4_utils/Android.bp
+++ b/ext4_utils/Android.bp
@@ -87,7 +87,12 @@ python_binary_host {
 
 prebuilt_etc {
     name: "mke2fs.conf",
-    recovery_available: true,
+    src: "mke2fs.conf",
+}
+
+prebuilt_etc {
+    name: "mke2fs.conf.recovery",
+    recovery: true,
     src: "mke2fs.conf",
 }
 
diff --git a/libatrace_rust/Android.bp b/libatrace_rust/Android.bp
index 01dd1a14..e08ca1e0 100644
--- a/libatrace_rust/Android.bp
+++ b/libatrace_rust/Android.bp
@@ -10,6 +10,7 @@ rust_defaults {
         "libtracing",
         "libtracing_subscriber",
     ],
+    min_sdk_version: "35",
 }
 
 rust_library {
@@ -43,6 +44,7 @@ rust_defaults {
         "libstatic_assertions",
         "libbitflags",
     ],
+    min_sdk_version: "35",
 }
 
 rust_library {
@@ -88,6 +90,7 @@ rust_bindgen {
         "//apex_available:platform",
         "//apex_available:anyapex",
     ],
+    min_sdk_version: "35",
 }
 
 // TODO: b/291544011 - Replace with autogenerated wrappers once they are supported.
@@ -104,4 +107,5 @@ cc_library_static {
         "//apex_available:platform",
         "//apex_available:anyapex",
     ],
+    min_sdk_version: "35",
 }
diff --git a/memory_replay/Alloc.cpp b/memory_replay/Alloc.cpp
index b2112188..e97dca0a 100644
--- a/memory_replay/Alloc.cpp
+++ b/memory_replay/Alloc.cpp
@@ -19,28 +19,29 @@
 #include <stdio.h>
 #include <unistd.h>
 
+#include <memory_trace/MemoryTrace.h>
+
 #include "Alloc.h"
-#include "AllocParser.h"
 #include "Pointers.h"
 #include "Utils.h"
 
-bool AllocDoesFree(const AllocEntry& entry) {
+bool AllocDoesFree(const memory_trace::Entry& entry) {
   switch (entry.type) {
-    case MALLOC:
-    case CALLOC:
-    case MEMALIGN:
-    case THREAD_DONE:
+    case memory_trace::MALLOC:
+    case memory_trace::CALLOC:
+    case memory_trace::MEMALIGN:
+    case memory_trace::THREAD_DONE:
       return false;
 
-    case FREE:
+    case memory_trace::FREE:
       return entry.ptr != 0;
 
-    case REALLOC:
+    case memory_trace::REALLOC:
       return entry.u.old_ptr != 0;
   }
 }
 
-static uint64_t MallocExecute(const AllocEntry& entry, Pointers* pointers) {
+static uint64_t MallocExecute(const memory_trace::Entry& entry, Pointers* pointers) {
   int pagesize = getpagesize();
   uint64_t time_nsecs = Nanotime();
   void* memory = malloc(entry.size);
@@ -52,7 +53,7 @@ static uint64_t MallocExecute(const AllocEntry& entry, Pointers* pointers) {
   return time_nsecs;
 }
 
-static uint64_t CallocExecute(const AllocEntry& entry, Pointers* pointers) {
+static uint64_t CallocExecute(const memory_trace::Entry& entry, Pointers* pointers) {
   int pagesize = getpagesize();
   uint64_t time_nsecs = Nanotime();
   void* memory = calloc(entry.u.n_elements, entry.size);
@@ -64,7 +65,7 @@ static uint64_t CallocExecute(const AllocEntry& entry, Pointers* pointers) {
   return time_nsecs;
 }
 
-static uint64_t ReallocExecute(const AllocEntry& entry, Pointers* pointers) {
+static uint64_t ReallocExecute(const memory_trace::Entry& entry, Pointers* pointers) {
   void* old_memory = nullptr;
   if (entry.u.old_ptr != 0) {
     old_memory = pointers->Remove(entry.u.old_ptr);
@@ -81,7 +82,7 @@ static uint64_t ReallocExecute(const AllocEntry& entry, Pointers* pointers) {
   return time_nsecs;
 }
 
-static uint64_t MemalignExecute(const AllocEntry& entry, Pointers* pointers) {
+static uint64_t MemalignExecute(const memory_trace::Entry& entry, Pointers* pointers) {
   int pagesize = getpagesize();
   uint64_t time_nsecs = Nanotime();
   void* memory = memalign(entry.u.align, entry.size);
@@ -93,7 +94,7 @@ static uint64_t MemalignExecute(const AllocEntry& entry, Pointers* pointers) {
   return time_nsecs;
 }
 
-static uint64_t FreeExecute(const AllocEntry& entry, Pointers* pointers) {
+static uint64_t FreeExecute(const memory_trace::Entry& entry, Pointers* pointers) {
   if (entry.ptr == 0) {
     return 0;
   }
@@ -104,17 +105,17 @@ static uint64_t FreeExecute(const AllocEntry& entry, Pointers* pointers) {
   return Nanotime() - time_nsecs;
 }
 
-uint64_t AllocExecute(const AllocEntry& entry, Pointers* pointers) {
+uint64_t AllocExecute(const memory_trace::Entry& entry, Pointers* pointers) {
   switch (entry.type) {
-    case MALLOC:
+    case memory_trace::MALLOC:
       return MallocExecute(entry, pointers);
-    case CALLOC:
+    case memory_trace::CALLOC:
       return CallocExecute(entry, pointers);
-    case REALLOC:
+    case memory_trace::REALLOC:
       return ReallocExecute(entry, pointers);
-    case MEMALIGN:
+    case memory_trace::MEMALIGN:
       return MemalignExecute(entry, pointers);
-    case FREE:
+    case memory_trace::FREE:
       return FreeExecute(entry, pointers);
     default:
       return 0;
diff --git a/memory_replay/Alloc.h b/memory_replay/Alloc.h
index f4dcc83c..b4c87687 100644
--- a/memory_replay/Alloc.h
+++ b/memory_replay/Alloc.h
@@ -16,11 +16,12 @@
 
 #pragma once
 
-#include "AllocParser.h"
-
 // Forward Declarations.
+namespace memory_trace {
+struct Entry;
+}
 class Pointers;
 
-bool AllocDoesFree(const AllocEntry& entry);
+bool AllocDoesFree(const memory_trace::Entry& entry);
 
-uint64_t AllocExecute(const AllocEntry& entry, Pointers* pointers);
+uint64_t AllocExecute(const memory_trace::Entry& entry, Pointers* pointers);
diff --git a/memory_replay/AllocParser.cpp b/memory_replay/AllocParser.cpp
deleted file mode 100644
index ac6664a2..00000000
--- a/memory_replay/AllocParser.cpp
+++ /dev/null
@@ -1,92 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
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
-#include <err.h>
-#include <inttypes.h>
-#include <stdio.h>
-
-#include "AllocParser.h"
-
-#include <iostream>
-
-void AllocGetData(const std::string& line, AllocEntry* entry) {
-    int op_prefix_pos = 0;
-    char name[128];
-    // All lines have this format:
-    //   TID: ALLOCATION_TYPE POINTER
-    // where
-    //   TID is the thread id of the thread doing the operation.
-    //   ALLOCATION_TYPE is one of malloc, calloc, memalign, realloc, free, thread_done
-    //   POINTER is the hex value of the actual pointer
-    if (sscanf(line.c_str(), "%d: %127s %" SCNx64 " %n", &entry->tid, name, &entry->ptr,
-               &op_prefix_pos) != 3) {
-        errx(1, "File Error: Failed to process %s", line.c_str());
-    }
-    std::string type(name);
-    if (type == "thread_done") {
-        entry->type = THREAD_DONE;
-    } else {
-        int args_offset = 0;
-        const char* args_beg = &line[op_prefix_pos];
-        if (type == "malloc") {
-            // Format:
-            //   TID: malloc POINTER SIZE_OF_ALLOCATION
-            if (sscanf(args_beg, "%zu%n", &entry->size, &args_offset) != 1) {
-                errx(1, "File Error: Failed to read malloc data %s", line.c_str());
-            }
-            entry->type = MALLOC;
-        } else if (type == "free") {
-            // Format:
-            //   TID: free POINTER
-            entry->type = FREE;
-        } else if (type == "calloc") {
-            // Format:
-            //   TID: calloc POINTER ITEM_COUNT ITEM_SIZE
-            if (sscanf(args_beg, "%" SCNd64 " %zu%n", &entry->u.n_elements, &entry->size,
-                       &args_offset) != 2) {
-                errx(1, "File Error: Failed to read calloc data %s", line.c_str());
-            }
-            entry->type = CALLOC;
-        } else if (type == "realloc") {
-            // Format:
-            //   TID: realloc POINTER OLD_POINTER NEW_SIZE
-            if (sscanf(args_beg, "%" SCNx64 " %zu%n", &entry->u.old_ptr, &entry->size,
-                       &args_offset) != 2) {
-                errx(1, "File Error: Failed to read realloc data %s", line.c_str());
-            }
-            entry->type = REALLOC;
-        } else if (type == "memalign") {
-            // Format:
-            //   TID: memalign POINTER ALIGNMENT SIZE
-            if (sscanf(args_beg, "%" SCNd64 " %zu%n", &entry->u.align, &entry->size,
-                       &args_offset) != 2) {
-                errx(1, "File Error: Failed to read memalign data %s", line.c_str());
-            }
-            entry->type = MEMALIGN;
-        } else {
-            errx(1, "File Error: Unknown type %s", type.c_str());
-        }
-
-        const char* timestamps_beg = &args_beg[args_offset];
-
-        // Timestamps come after the alloc args if present, for example,
-        //   TID: malloc POINTER SIZE_OF_ALLOCATION START_TIME END_TIME
-        int n_match = sscanf(timestamps_beg, "%" SCNd64 " %" SCNd64, &entry->st, &entry->et);
-        if (n_match != EOF && n_match != 2) {
-            errx(1, "File Error: Failed to read timestamps %s", line.c_str());
-        }
-    }
-}
diff --git a/memory_replay/Android.bp b/memory_replay/Android.bp
index e1f3b68a..c75218fe 100644
--- a/memory_replay/Android.bp
+++ b/memory_replay/Android.bp
@@ -33,32 +33,46 @@ license {
 }
 
 cc_defaults {
-    name: "memory_flag_defaults",
-    host_supported: false,
+    name: "memory_replay_flag_defaults",
+
+    host_supported: true,
 
     cflags: [
         "-Wall",
         "-Wextra",
         "-Werror",
     ],
+}
 
-    compile_multilib: "both",
+cc_defaults {
+    name: "memory_replay_defaults",
+    defaults: ["memory_replay_flag_defaults"],
+
+    shared_libs: [
+        "libbase",
+        "liblog",
+        "libziparchive",
+    ],
 }
 
 cc_library_static {
-    name: "liballoc_parser",
+    name: "libmemory_trace",
     host_supported: true,
-    defaults: ["memory_flag_defaults"],
+    defaults: ["memory_replay_flag_defaults"],
 
-    export_include_dirs: ["."],
-    srcs: [
-        "AllocParser.cpp",
+    export_include_dirs: ["include"],
+    shared_libs: ["libbase"],
+    srcs: ["MemoryTrace.cpp"],
+
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.runtime",
     ],
 }
 
-cc_defaults {
-    name: "memory_replay_defaults",
-    defaults: ["memory_flag_defaults"],
+cc_library_static {
+    name: "libmemory_replay",
+    defaults: ["memory_replay_defaults"],
 
     srcs: [
         "Alloc.cpp",
@@ -69,24 +83,23 @@ cc_defaults {
         "Threads.cpp",
     ],
 
-    shared_libs: [
-        "libbase",
-        "libziparchive",
-    ],
-
-    static_libs: [
-        "liballoc_parser",
+    whole_static_libs: [
+        "libmemory_trace",
     ],
 }
 
 cc_binary {
     name: "memory_replay",
     defaults: ["memory_replay_defaults"],
+    host_supported: false,
 
     srcs: ["main.cpp"],
 
-    static_libs: ["liblog"],
+    static_libs: [
+        "libmemory_replay",
+    ],
 
+    compile_multilib: "both",
     multilib: {
         lib32: {
             suffix: "32",
@@ -99,28 +112,40 @@ cc_binary {
 
 cc_binary_host {
     name: "filter_trace",
+    defaults: ["memory_replay_defaults"],
 
-    cflags: [
-        "-Wall",
-        "-Wextra",
-        "-Werror",
+    static_libs: [
+        "libmemory_replay",
     ],
 
-    shared_libs: [
-        "libziparchive",
+    srcs: [
+        "FilterTrace.cpp",
     ],
+}
+
+cc_binary_host {
+    name: "print_trace",
+    defaults: ["memory_replay_defaults"],
 
     static_libs: [
-        "liballoc_parser",
-        "libbase",
-        "liblog",
+        "libmemory_replay",
     ],
 
     srcs: [
-        "Alloc.cpp",
-        "File.cpp",
-        "FilterTrace.cpp",
-        "Pointers.cpp",
+        "PrintTrace.cpp",
+    ],
+}
+
+cc_binary_host {
+    name: "verify_trace",
+    defaults: ["memory_replay_defaults"],
+
+    static_libs: [
+        "libmemory_replay",
+    ],
+
+    srcs: [
+        "VerifyTrace.cpp",
     ],
 }
 
@@ -130,8 +155,8 @@ cc_test {
     isolated: true,
 
     srcs: [
-        "tests/AllocTest.cpp",
         "tests/FileTest.cpp",
+        "tests/MemoryTraceTest.cpp",
         "tests/NativeInfoTest.cpp",
         "tests/PointersTest.cpp",
         "tests/ThreadTest.cpp",
@@ -140,35 +165,28 @@ cc_test {
 
     local_include_dirs: ["tests"],
 
-    target: {
-        android: {
-            test_suites: ["device-tests"],
-        },
-    },
+    static_libs: [
+        "libmemory_replay",
+    ],
 
     data: [
         "tests/test.txt",
         "tests/test.zip",
     ],
+
+    test_suites: ["general-tests"],
 }
 
 cc_benchmark {
     name: "trace_benchmark",
-    defaults: ["memory_flag_defaults"],
+    defaults: ["memory_replay_defaults"],
 
     srcs: [
-        "Alloc.cpp",
         "TraceBenchmark.cpp",
-        "File.cpp",
-    ],
-
-    shared_libs: [
-        "libbase",
-        "libziparchive",
     ],
 
     static_libs: [
-        "liballoc_parser",
+        "libmemory_replay",
     ],
 
     data: [
diff --git a/memory_replay/AndroidTest.xml b/memory_replay/AndroidTest.xml
deleted file mode 100644
index cf3879af..00000000
--- a/memory_replay/AndroidTest.xml
+++ /dev/null
@@ -1,26 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2017 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-<configuration description="Config for memory_replay_tests">
-    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
-        <option name="cleanup" value="true" />
-        <option name="push" value="memory_replay_tests->/data/local/tmp/memory_replay_tests" />
-    </target_preparer>
-    <option name="test-suite-tag" value="apct" />
-    <test class="com.android.tradefed.testtype.GTest" >
-        <option name="native-test-device-path" value="/data/local/tmp" />
-        <option name="module-name" value="memory_replay_tests" />
-    </test>
-</configuration>
diff --git a/memory_replay/File.cpp b/memory_replay/File.cpp
index e44c5007..4983b4de 100644
--- a/memory_replay/File.cpp
+++ b/memory_replay/File.cpp
@@ -28,8 +28,8 @@
 #include <android-base/strings.h>
 #include <ziparchive/zip_archive.h>
 
-#include "Alloc.h"
-#include "AllocParser.h"
+#include <memory_trace/MemoryTrace.h>
+
 #include "File.h"
 
 std::string ZipGetContents(const char* filename) {
@@ -77,7 +77,7 @@ static void WaitPid(pid_t pid) {
 
 // This function should not do any memory allocations in the main function.
 // Any true allocation should happen in fork'd code.
-void GetUnwindInfo(const char* filename, AllocEntry** entries, size_t* num_entries) {
+void GetUnwindInfo(const char* filename, memory_trace::Entry** entries, size_t* num_entries) {
   void* mem =
       mmap(nullptr, sizeof(size_t), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
   if (mem == MAP_FAILED) {
@@ -123,12 +123,13 @@ void GetUnwindInfo(const char* filename, AllocEntry** entries, size_t* num_entri
   *num_entries = *reinterpret_cast<size_t*>(mem);
   munmap(mem, sizeof(size_t));
 
-  mem = mmap(nullptr, *num_entries * sizeof(AllocEntry), PROT_READ | PROT_WRITE,
+  mem = mmap(nullptr, *num_entries * sizeof(memory_trace::Entry), PROT_READ | PROT_WRITE,
              MAP_ANONYMOUS | MAP_SHARED, -1, 0);
   if (mem == MAP_FAILED) {
-    err(1, "Unable to allocate a shared map of size %zu", *num_entries * sizeof(AllocEntry));
+    err(1, "Unable to allocate a shared map of size %zu",
+        *num_entries * sizeof(memory_trace::Entry));
   }
-  *entries = reinterpret_cast<AllocEntry*>(mem);
+  *entries = reinterpret_cast<memory_trace::Entry*>(mem);
 
   if ((pid = fork()) == 0) {
     std::string contents;
@@ -153,7 +154,11 @@ void GetUnwindInfo(const char* filename, AllocEntry** entries, size_t* num_entri
         errx(1, "Too many entries, stopped at entry %zu", entry_idx);
       }
       contents[end_str] = '\0';
-      AllocGetData(&contents[start_str], &(*entries)[entry_idx++]);
+      std::string error;
+      if (!memory_trace::FillInEntryFromString(&contents[start_str], (*entries)[entry_idx++],
+                                               error)) {
+        errx(1, "%s", error.c_str());
+      }
       start_str = end_str + 1;
     }
     if (entry_idx != *num_entries) {
@@ -167,6 +172,6 @@ void GetUnwindInfo(const char* filename, AllocEntry** entries, size_t* num_entri
   WaitPid(pid);
 }
 
-void FreeEntries(AllocEntry* entries, size_t num_entries) {
-  munmap(entries, num_entries * sizeof(AllocEntry));
+void FreeEntries(memory_trace::Entry* entries, size_t num_entries) {
+  munmap(entries, num_entries * sizeof(memory_trace::Entry));
 }
diff --git a/memory_replay/File.h b/memory_replay/File.h
index c1447bba..e70ca28e 100644
--- a/memory_replay/File.h
+++ b/memory_replay/File.h
@@ -21,11 +21,13 @@
 #include <string>
 
 // Forward Declarations.
-struct AllocEntry;
+namespace memory_trace {
+struct Entry;
+}
 
 std::string ZipGetContents(const char* filename);
 
 // If filename ends with .zip, treat as a zip file to decompress.
-void GetUnwindInfo(const char* filename, AllocEntry** entries, size_t* num_entries);
+void GetUnwindInfo(const char* filename, memory_trace::Entry** entries, size_t* num_entries);
 
-void FreeEntries(AllocEntry* entries, size_t num_entries);
+void FreeEntries(memory_trace::Entry* entries, size_t num_entries);
diff --git a/memory_replay/FilterTrace.cpp b/memory_replay/FilterTrace.cpp
index 27f1945b..65543f02 100644
--- a/memory_replay/FilterTrace.cpp
+++ b/memory_replay/FilterTrace.cpp
@@ -28,7 +28,8 @@
 #include <android-base/parseint.h>
 #include <android-base/strings.h>
 
-#include "AllocParser.h"
+#include <memory_trace/MemoryTrace.h>
+
 #include "File.h"
 
 static std::string GetBaseExec() {
@@ -108,42 +109,18 @@ static bool ParseOptions(int argc, char** argv, size_t& min_size, size_t& max_si
   return true;
 }
 
-static void PrintEntry(const AllocEntry& entry, size_t size, bool print_trace_format) {
+static void PrintEntry(const memory_trace::Entry& entry, size_t size, bool print_trace_format) {
   if (print_trace_format) {
-    switch (entry.type) {
-      case REALLOC:
-        if (entry.u.old_ptr == 0) {
-          // Convert to a malloc since it is functionally the same.
-          printf("%d: malloc %p %zu\n", entry.tid, reinterpret_cast<void*>(entry.ptr), entry.size);
-        } else {
-          printf("%d: realloc %p %p %zu\n", entry.tid, reinterpret_cast<void*>(entry.ptr),
-                 reinterpret_cast<void*>(entry.u.old_ptr), entry.size);
-        }
-        break;
-      case MALLOC:
-        printf("%d: malloc %p %zu\n", entry.tid, reinterpret_cast<void*>(entry.ptr), entry.size);
-        break;
-      case MEMALIGN:
-        printf("%d: memalign %p %zu %zu\n", entry.tid, reinterpret_cast<void*>(entry.ptr),
-               entry.u.align, entry.size);
-        break;
-      case CALLOC:
-        printf("%d: calloc %p %zu %zu\n", entry.tid, reinterpret_cast<void*>(entry.ptr),
-               entry.u.n_elements, entry.size);
-        break;
-      default:
-        errx(1, "Invalid entry type found %d\n", entry.type);
-        break;
-    }
+    printf("%s\n", memory_trace::CreateStringFromEntry(entry).c_str());
   } else {
-    printf("%s size %zu\n", entry.type == REALLOC && entry.u.old_ptr != 0 ? "realloc" : "alloc",
-           size);
+    printf("%s size %zu\n",
+           entry.type == memory_trace::REALLOC && entry.u.old_ptr != 0 ? "realloc" : "alloc", size);
   }
 }
 
 static void ProcessTrace(const std::string_view& trace, size_t min_size, size_t max_size,
                          bool print_trace_format) {
-  AllocEntry* entries;
+  memory_trace::Entry* entries;
   size_t num_entries;
   GetUnwindInfo(trace.data(), &entries, &num_entries);
 
@@ -159,14 +136,14 @@ static void ProcessTrace(const std::string_view& trace, size_t min_size, size_t
   size_t total_allocs = 0;
   size_t total_reallocs = 0;
   for (size_t i = 0; i < num_entries; i++) {
-    const AllocEntry& entry = entries[i];
+    const memory_trace::Entry& entry = entries[i];
     switch (entry.type) {
-      case MALLOC:
-      case MEMALIGN:
-      case REALLOC:
+      case memory_trace::MALLOC:
+      case memory_trace::MEMALIGN:
+      case memory_trace::REALLOC:
         if (entry.size >= min_size && entry.size <= max_size) {
           PrintEntry(entry, entry.size, print_trace_format);
-          if (entry.type == REALLOC) {
+          if (entry.type == memory_trace::REALLOC) {
             total_reallocs++;
           } else {
             total_allocs++;
@@ -174,15 +151,15 @@ static void ProcessTrace(const std::string_view& trace, size_t min_size, size_t
         }
         break;
 
-      case CALLOC:
+      case memory_trace::CALLOC:
         if (size_t size = entry.u.n_elements * entry.size;
             size >= min_size && entry.size <= max_size) {
           PrintEntry(entry, size, print_trace_format);
         }
         break;
 
-      case FREE:
-      case THREAD_DONE:
+      case memory_trace::FREE:
+      case memory_trace::THREAD_DONE:
       default:
         break;
     }
diff --git a/memory_replay/MemoryTrace.cpp b/memory_replay/MemoryTrace.cpp
new file mode 100644
index 00000000..e6d21dfc
--- /dev/null
+++ b/memory_replay/MemoryTrace.cpp
@@ -0,0 +1,230 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+#include <inttypes.h>
+#include <stdio.h>
+#include <unistd.h>
+
+#include <string>
+
+#include <android-base/stringprintf.h>
+
+#include <memory_trace/MemoryTrace.h>
+
+namespace memory_trace {
+
+// This is larger than the maximum length of a possible line.
+constexpr size_t kBufferLen = 256;
+
+bool FillInEntryFromString(const std::string& line, Entry& entry, std::string& error) {
+  // All lines have this format:
+  //   TID: ALLOCATION_TYPE POINTER [START_TIME_NS END_TIME_NS]
+  // where
+  //   TID is the thread id of the thread doing the operation.
+  //   ALLOCATION_TYPE is one of malloc, calloc, memalign, realloc, free, thread_done
+  //   POINTER is the hex value of the actual pointer
+  //   START_TIME_NS is the start time of the operation in nanoseconds.
+  //   END_TIME_NS is the end time of the operation in nanoseconds.
+  // The START_TIME_NS and END_TIME_NS are optional parameters, either both
+  // are present are neither are present.
+  int op_prefix_pos = 0;
+  char name[128];
+  if (sscanf(line.c_str(), "%d: %127s %" SCNx64 " %n", &entry.tid, name, &entry.ptr,
+             &op_prefix_pos) != 3) {
+    error = "Failed to process line: " + line;
+    return false;
+  }
+
+  // Handle each individual type of entry type.
+  std::string type(name);
+  if (type == "thread_done") {
+    //   TID: thread_done 0x0 [END_TIME_NS]
+    // Where END_TIME_NS is optional.
+    entry.type = THREAD_DONE;
+    entry.start_ns = 0;
+    // Thread done has an optional time which is when the thread ended.
+    // This is the only entry type that has a single timestamp.
+    int n_match = sscanf(&line[op_prefix_pos], " %" SCNd64, &entry.end_ns);
+    entry.start_ns = 0;
+    if (n_match == EOF) {
+      entry.end_ns = 0;
+    } else if (n_match != 1) {
+      error = "Failed to read thread_done end time: " + line;
+      return false;
+    }
+    return true;
+  }
+
+  int args_offset = 0;
+  const char* args_beg = &line[op_prefix_pos];
+  if (type == "malloc") {
+    // Format:
+    //   TID: malloc POINTER SIZE_OF_ALLOCATION [START_TIME_NS END_TIME_NS]
+    if (sscanf(args_beg, "%zu%n", &entry.size, &args_offset) != 1) {
+      error = "Failed to read malloc data: " + line;
+      return false;
+    }
+    entry.type = MALLOC;
+  } else if (type == "free") {
+    // Format:
+    //   TID: free POINTER [START_TIME_NS END_TIME_NS]
+    entry.type = FREE;
+  } else if (type == "calloc") {
+    // Format:
+    //   TID: calloc POINTER ITEM_COUNT ITEM_SIZE [START_TIME_NS END_TIME_NS]
+    if (sscanf(args_beg, "%" SCNd64 " %zu%n", &entry.u.n_elements, &entry.size, &args_offset) !=
+        2) {
+      error = "Failed to read calloc data: " + line;
+      return false;
+    }
+    entry.type = CALLOC;
+  } else if (type == "realloc") {
+    // Format:
+    //   TID: realloc POINTER OLD_POINTER NEW_SIZE [START_TIME_NS END_TIME_NS]
+    if (sscanf(args_beg, "%" SCNx64 " %zu%n", &entry.u.old_ptr, &entry.size, &args_offset) != 2) {
+      error = "Failed to read realloc data: " + line;
+      return false;
+    }
+    entry.type = REALLOC;
+  } else if (type == "memalign") {
+    // Format:
+    //   TID: memalign POINTER ALIGNMENT SIZE [START_TIME_NS END_TIME_NS]
+    if (sscanf(args_beg, "%" SCNd64 " %zu%n", &entry.u.align, &entry.size, &args_offset) != 2) {
+      error = "Failed to read memalign data: " + line;
+      return false;
+    }
+    entry.type = MEMALIGN;
+  } else {
+    printf("Unknown type %s: %s\n", type.c_str(), line.c_str());
+    error = "Unknown type " + type + ": " + line;
+    return false;
+  }
+
+  const char* timestamps_beg = &args_beg[args_offset];
+
+  // Get the optional timestamps if they exist.
+  int n_match = sscanf(timestamps_beg, "%" SCNd64 " %" SCNd64, &entry.start_ns, &entry.end_ns);
+  if (n_match == EOF) {
+    entry.start_ns = 0;
+    entry.end_ns = 0;
+  } else if (n_match != 2) {
+    error = "Failed to read timestamps: " + line;
+    return false;
+  }
+  return true;
+}
+
+static const char* TypeToName(const TypeEnum type) {
+  switch (type) {
+    case CALLOC:
+      return "calloc";
+    case FREE:
+      return "free";
+    case MALLOC:
+      return "malloc";
+    case MEMALIGN:
+      return "memalign";
+    case REALLOC:
+      return "realloc";
+    case THREAD_DONE:
+      return "thread_done";
+  }
+  return "unknown";
+}
+
+static size_t FormatEntry(const Entry& entry, char* buffer, size_t buffer_len) {
+  int len = snprintf(buffer, buffer_len, "%d: %s 0x%" PRIx64, entry.tid, TypeToName(entry.type),
+                     entry.ptr);
+  if (len < 0) {
+    return 0;
+  }
+  size_t cur_len = len;
+  switch (entry.type) {
+    case FREE:
+      len = 0;
+      break;
+    case CALLOC:
+      len = snprintf(&buffer[cur_len], buffer_len - cur_len, " %" PRIu64 " %zu", entry.u.n_elements,
+                     entry.size);
+      break;
+    case MALLOC:
+      len = snprintf(&buffer[cur_len], buffer_len - cur_len, " %zu", entry.size);
+      break;
+    case MEMALIGN:
+      len = snprintf(&buffer[cur_len], buffer_len - cur_len, " %" PRIu64 " %zu", entry.u.align,
+                     entry.size);
+      break;
+    case REALLOC:
+      len = snprintf(&buffer[cur_len], buffer_len - cur_len, " 0x%" PRIx64 " %zu", entry.u.old_ptr,
+                     entry.size);
+      break;
+    case THREAD_DONE:
+      // Thread done only has a single optional timestamp, end_ns.
+      if (entry.end_ns != 0) {
+        len = snprintf(&buffer[cur_len], buffer_len - cur_len, " %" PRId64, entry.end_ns);
+        if (len < 0) {
+          return 0;
+        }
+        return cur_len + len;
+      }
+      return cur_len;
+    default:
+      return 0;
+  }
+  if (len < 0) {
+    return 0;
+  }
+
+  cur_len += len;
+  if (entry.start_ns == 0) {
+    return cur_len;
+  }
+
+  len = snprintf(&buffer[cur_len], buffer_len - cur_len, " %" PRIu64 " %" PRIu64, entry.start_ns,
+                 entry.end_ns);
+  if (len < 0) {
+    return 0;
+  }
+  return cur_len + len;
+}
+
+std::string CreateStringFromEntry(const Entry& entry) {
+  std::string line(kBufferLen, '\0');
+
+  size_t size = FormatEntry(entry, line.data(), line.size());
+  if (size == 0) {
+    return "";
+  }
+  line.resize(size);
+  return line;
+}
+
+bool WriteEntryToFd(int fd, const Entry& entry) {
+  char buffer[kBufferLen];
+  size_t size = FormatEntry(entry, buffer, sizeof(buffer));
+  if (size == 0 || size == sizeof(buffer)) {
+    return false;
+  }
+  buffer[size++] = '\n';
+  buffer[size] = '\0';
+  ssize_t bytes = TEMP_FAILURE_RETRY(write(fd, buffer, size));
+  if (bytes < 0 || static_cast<size_t>(bytes) != size) {
+    return false;
+  }
+  return true;
+}
+
+}  // namespace memory_trace
diff --git a/memory_replay/PrintTrace.cpp b/memory_replay/PrintTrace.cpp
new file mode 100644
index 00000000..951c31ac
--- /dev/null
+++ b/memory_replay/PrintTrace.cpp
@@ -0,0 +1,49 @@
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
+#include <stdio.h>
+
+#include <android-base/file.h>
+
+#include <memory_trace/MemoryTrace.h>
+
+#include "File.h"
+
+static void Usage() {
+  fprintf(stderr, "Usage: %s TRACE_FILE\n",
+          android::base::Basename(android::base::GetExecutablePath()).c_str());
+  fprintf(stderr, "  TRACE_FILE\n");
+  fprintf(stderr, "      The trace file\n");
+  fprintf(stderr, "\n  Print a trace to stdout.\n");
+}
+
+int main(int argc, char** argv) {
+  if (argc != 2) {
+    Usage();
+    return 1;
+  }
+
+  memory_trace::Entry* entries;
+  size_t num_entries;
+  GetUnwindInfo(argv[1], &entries, &num_entries);
+
+  for (size_t i = 0; i < num_entries; i++) {
+    printf("%s\n", memory_trace::CreateStringFromEntry(entries[i]).c_str());
+  }
+
+  FreeEntries(entries, num_entries);
+  return 0;
+}
diff --git a/memory_replay/TEST_MAPPING b/memory_replay/TEST_MAPPING
new file mode 100644
index 00000000..286527a9
--- /dev/null
+++ b/memory_replay/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "presubmit": [
+    {
+      "name": "memory_replay_tests"
+    }
+  ]
+}
diff --git a/memory_replay/Thread.h b/memory_replay/Thread.h
index ffab01b4..810bde7a 100644
--- a/memory_replay/Thread.h
+++ b/memory_replay/Thread.h
@@ -21,7 +21,9 @@
 #include <sys/types.h>
 
 // Forward Declarations.
-struct AllocEntry;
+namespace memory_trace {
+struct Entry;
+}
 class Pointers;
 
 class Thread {
@@ -39,8 +41,8 @@ class Thread {
   void set_pointers(Pointers* pointers) { pointers_ = pointers; }
   Pointers* pointers() { return pointers_; }
 
-  void SetAllocEntry(const AllocEntry* entry) { entry_ = entry; }
-  const AllocEntry& GetAllocEntry() { return *entry_; }
+  void SetEntry(const memory_trace::Entry* entry) { entry_ = entry; }
+  const memory_trace::Entry& GetEntry() { return *entry_; }
 
  private:
   pthread_mutex_t mutex_ = PTHREAD_MUTEX_INITIALIZER;
@@ -53,7 +55,7 @@ class Thread {
 
   Pointers* pointers_ = nullptr;
 
-  const AllocEntry* entry_;
+  const memory_trace::Entry* entry_;
 
   friend class Threads;
 };
diff --git a/memory_replay/Threads.cpp b/memory_replay/Threads.cpp
index 15fc69f1..3fcedc0d 100644
--- a/memory_replay/Threads.cpp
+++ b/memory_replay/Threads.cpp
@@ -26,6 +26,8 @@
 
 #include <new>
 
+#include <memory_trace/MemoryTrace.h>
+
 #include "Alloc.h"
 #include "Pointers.h"
 #include "Thread.h"
@@ -35,9 +37,9 @@ void* ThreadRunner(void* data) {
   Thread* thread = reinterpret_cast<Thread*>(data);
   while (true) {
     thread->WaitForPending();
-    const AllocEntry& entry = thread->GetAllocEntry();
+    const memory_trace::Entry& entry = thread->GetEntry();
     thread->AddTimeNsecs(AllocExecute(entry, thread->pointers()));
-    bool thread_done = entry.type == THREAD_DONE;
+    bool thread_done = entry.type == memory_trace::THREAD_DONE;
     thread->ClearPending();
     if (thread_done) {
       break;
@@ -143,10 +145,10 @@ void Threads::Finish(Thread* thread) {
 }
 
 void Threads::FinishAll() {
-  AllocEntry thread_done = {.type = THREAD_DONE};
+  memory_trace::Entry thread_done = {.type = memory_trace::THREAD_DONE};
   for (size_t i = 0; i < max_threads_; i++) {
     if (threads_[i].tid_ != 0) {
-      threads_[i].SetAllocEntry(&thread_done);
+      threads_[i].SetEntry(&thread_done);
       threads_[i].SetPending();
       Finish(threads_ + i);
     }
diff --git a/memory_replay/TraceBenchmark.cpp b/memory_replay/TraceBenchmark.cpp
index a3aad57a..16129970 100644
--- a/memory_replay/TraceBenchmark.cpp
+++ b/memory_replay/TraceBenchmark.cpp
@@ -35,12 +35,13 @@
 #include <android-base/strings.h>
 #include <benchmark/benchmark.h>
 
-#include "Alloc.h"
+#include <memory_trace/MemoryTrace.h>
+
 #include "File.h"
 #include "Utils.h"
 
 struct TraceDataType {
-  AllocEntry* entries = nullptr;
+  memory_trace::Entry* entries = nullptr;
   size_t num_entries = 0;
   void** ptrs = nullptr;
   size_t num_ptrs = 0;
@@ -99,17 +100,17 @@ static void GetTraceData(const std::string& filename, TraceDataType* trace_data)
   std::stack<size_t> free_indices;
   std::unordered_map<uint64_t, size_t> ptr_to_index;
   for (size_t i = 0; i < trace_data->num_entries; i++) {
-    AllocEntry* entry = &trace_data->entries[i];
+    memory_trace::Entry* entry = &trace_data->entries[i];
     switch (entry->type) {
-      case MALLOC:
-      case CALLOC:
-      case MEMALIGN: {
+      case memory_trace::MALLOC:
+      case memory_trace::CALLOC:
+      case memory_trace::MEMALIGN: {
         size_t idx = GetIndex(free_indices, &trace_data->num_ptrs);
         ptr_to_index[entry->ptr] = idx;
         entry->ptr = idx;
         break;
       }
-      case REALLOC: {
+      case memory_trace::REALLOC: {
         if (entry->u.old_ptr != 0) {
           auto idx_entry = ptr_to_index.find(entry->u.old_ptr);
           if (idx_entry == ptr_to_index.end()) {
@@ -125,7 +126,7 @@ static void GetTraceData(const std::string& filename, TraceDataType* trace_data)
         entry->ptr = idx;
         break;
       }
-      case FREE:
+      case memory_trace::FREE:
         if (entry->ptr != 0) {
           auto idx_entry = ptr_to_index.find(entry->ptr);
           if (idx_entry == ptr_to_index.end()) {
@@ -136,7 +137,7 @@ static void GetTraceData(const std::string& filename, TraceDataType* trace_data)
           ptr_to_index.erase(idx_entry);
         }
         break;
-      case THREAD_DONE:
+      case memory_trace::THREAD_DONE:
         break;
     }
   }
@@ -156,9 +157,9 @@ static void RunTrace(benchmark::State& state, TraceDataType* trace_data) {
   void** ptrs = trace_data->ptrs;
   for (size_t i = 0; i < trace_data->num_entries; i++) {
     void* ptr;
-    const AllocEntry& entry = trace_data->entries[i];
+    const memory_trace::Entry& entry = trace_data->entries[i];
     switch (entry.type) {
-      case MALLOC:
+      case memory_trace::MALLOC:
         start_ns = Nanotime();
         ptr = malloc(entry.size);
         if (ptr == nullptr) {
@@ -173,7 +174,7 @@ static void RunTrace(benchmark::State& state, TraceDataType* trace_data) {
         ptrs[entry.ptr] = ptr;
         break;
 
-      case CALLOC:
+      case memory_trace::CALLOC:
         start_ns = Nanotime();
         ptr = calloc(entry.u.n_elements, entry.size);
         if (ptr == nullptr) {
@@ -188,7 +189,7 @@ static void RunTrace(benchmark::State& state, TraceDataType* trace_data) {
         ptrs[entry.ptr] = ptr;
         break;
 
-      case MEMALIGN:
+      case memory_trace::MEMALIGN:
         start_ns = Nanotime();
         ptr = memalign(entry.u.align, entry.size);
         if (ptr == nullptr) {
@@ -203,7 +204,7 @@ static void RunTrace(benchmark::State& state, TraceDataType* trace_data) {
         ptrs[entry.ptr] = ptr;
         break;
 
-      case REALLOC:
+      case memory_trace::REALLOC:
         start_ns = Nanotime();
         if (entry.u.old_ptr == 0) {
           ptr = realloc(nullptr, entry.size);
@@ -225,7 +226,7 @@ static void RunTrace(benchmark::State& state, TraceDataType* trace_data) {
         ptrs[entry.ptr] = ptr;
         break;
 
-      case FREE:
+      case memory_trace::FREE:
         if (entry.ptr != 0) {
           ptr = ptrs[entry.ptr - 1];
           ptrs[entry.ptr - 1] = nullptr;
@@ -237,7 +238,7 @@ static void RunTrace(benchmark::State& state, TraceDataType* trace_data) {
         total_ns += Nanotime() - start_ns;
         break;
 
-      case THREAD_DONE:
+      case memory_trace::THREAD_DONE:
         break;
     }
   }
@@ -249,7 +250,8 @@ static void RunTrace(benchmark::State& state, TraceDataType* trace_data) {
 // Run a trace as if all of the allocations occurred in a single thread.
 // This is not completely realistic, but it is a possible worst case that
 // could happen in an app.
-static void BenchmarkTrace(benchmark::State& state, const char* filename, bool enable_decay_time) {
+static void BenchmarkTrace(benchmark::State& state, const char* filename,
+                           [[maybe_unused]] bool enable_decay_time) {
 #if defined(__BIONIC__)
   if (enable_decay_time) {
     mallopt(M_DECAY_TIME, 1);
diff --git a/memory_replay/VerifyTrace.cpp b/memory_replay/VerifyTrace.cpp
new file mode 100644
index 00000000..0094940c
--- /dev/null
+++ b/memory_replay/VerifyTrace.cpp
@@ -0,0 +1,233 @@
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
+#include <fcntl.h>
+#include <getopt.h>
+#include <inttypes.h>
+#include <stdio.h>
+#include <unistd.h>
+
+#include <string>
+#include <unordered_map>
+#include <utility>
+
+#include <android-base/file.h>
+
+#include <memory_trace/MemoryTrace.h>
+
+#include "File.h"
+
+static void Usage() {
+  fprintf(stderr, "Usage: %s [--attempt_repair] TRACE_FILE1 TRACE_FILE2 ...\n",
+          android::base::Basename(android::base::GetExecutablePath()).c_str());
+  fprintf(stderr, "  --attempt_repair\n");
+  fprintf(stderr, "    If a trace file has some errors, try to fix them. The new\n");
+  fprintf(stderr, "    file will be named TRACE_FILE.repair\n");
+  fprintf(stderr, "  TRACE_FILE1 TRACE_FILE2 ...\n");
+  fprintf(stderr, "      The trace files to verify\n");
+  fprintf(stderr, "\n  Verify trace are valid.\n");
+  exit(1);
+}
+
+static bool WriteRepairEntries(const std::string& repair_file, memory_trace::Entry* entries,
+                               size_t num_entries) {
+  int fd = open(repair_file.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
+  if (fd == -1) {
+    printf("  Failed to create repair file %s: %s\n", repair_file.c_str(), strerror(errno));
+    return false;
+  }
+  bool valid = true;
+  for (size_t i = 0; i < num_entries; i++) {
+    if (!memory_trace::WriteEntryToFd(fd, entries[i])) {
+      printf("  Failed to write entry to file:\n");
+      valid = false;
+      break;
+    }
+  }
+  close(fd);
+  if (!valid) {
+    unlink(repair_file.c_str());
+  }
+  return valid;
+}
+
+static void VerifyTrace(const char* trace_file, bool attempt_repair) {
+  printf("Checking %s\n", trace_file);
+
+  memory_trace::Entry* entries;
+  size_t num_entries;
+  GetUnwindInfo(trace_file, &entries, &num_entries);
+
+  size_t errors_found = 0;
+  size_t errors_repaired = 0;
+  std::unordered_map<uint64_t, std::pair<memory_trace::Entry*, size_t>> live_ptrs;
+  std::pair<memory_trace::Entry*, size_t> erased(nullptr, 0);
+  for (size_t i = 0; i < num_entries; i++) {
+    memory_trace::Entry* entry = &entries[i];
+
+    uint64_t ptr = 0;
+    switch (entry->type) {
+      case memory_trace::MALLOC:
+      case memory_trace::MEMALIGN:
+        ptr = entry->ptr;
+        break;
+      case memory_trace::CALLOC:
+        ptr = entry->ptr;
+        break;
+      case memory_trace::REALLOC:
+        if (entry->ptr != 0) {
+          ptr = entry->ptr;
+        }
+        if (entry->u.old_ptr != 0) {
+          // Verify old pointer
+          auto entry_iter = live_ptrs.find(entry->u.old_ptr);
+          if (entry_iter == live_ptrs.end()) {
+            // Verify the pointer didn't get realloc'd to itself.
+            if (entry->u.old_ptr != entry->ptr) {
+              printf("  Line %zu: freeing of unknown ptr 0x%" PRIx64 "\n", i + 1, entry->u.old_ptr);
+              printf("    %s\n", memory_trace::CreateStringFromEntry(*entry).c_str());
+              errors_found++;
+              if (attempt_repair) {
+                printf("  Unable to repair this failure.\n");
+              }
+            }
+          } else {
+            if (attempt_repair) {
+              erased = entry_iter->second;
+            }
+            live_ptrs.erase(entry_iter);
+          }
+        }
+        break;
+      case memory_trace::FREE:
+        if (entry->ptr != 0) {
+          // Verify pointer is present.
+          auto entry_iter = live_ptrs.find(entry->ptr);
+          if (entry_iter == live_ptrs.end()) {
+            printf("  Line %zu: freeing of unknown ptr 0x%" PRIx64 "\n", i + 1, entry->ptr);
+            printf("    %s\n", memory_trace::CreateStringFromEntry(*entry).c_str());
+            errors_found++;
+            if (attempt_repair) {
+              printf("  Unable to repair this failure.\n");
+            }
+          } else {
+            live_ptrs.erase(entry_iter);
+          }
+        }
+        break;
+      case memory_trace::THREAD_DONE:
+        break;
+    }
+
+    if (ptr != 0) {
+      auto old_entry = live_ptrs.find(ptr);
+      if (old_entry != live_ptrs.end()) {
+        printf("  Line %zu: duplicate ptr 0x%" PRIx64 "\n", i + 1, ptr);
+        printf("    Original entry at line %zu:\n", old_entry->second.second);
+        printf("      %s\n", memory_trace::CreateStringFromEntry(*old_entry->second.first).c_str());
+        printf("    Duplicate entry at line %zu:\n", i + 1);
+        printf("      %s\n", memory_trace::CreateStringFromEntry(*entry).c_str());
+        errors_found++;
+        if (attempt_repair) {
+          // There is a small chance of a race where the same pointer is returned
+          // in two different threads before the free is recorded. If this occurs,
+          // the way to repair is to search forward for the free of the pointer and
+          // swap the two entries.
+          bool fixed = false;
+          for (size_t j = i + 1; j < num_entries; j++) {
+            if ((entries[j].type == memory_trace::FREE && entries[j].ptr == ptr) ||
+                (entries[j].type == memory_trace::REALLOC && entries[j].u.old_ptr == ptr)) {
+              memory_trace::Entry tmp_entry = *entry;
+              *entry = entries[j];
+              entries[j] = tmp_entry;
+              errors_repaired++;
+
+              live_ptrs.erase(old_entry);
+              if (entry->type == memory_trace::REALLOC) {
+                if (entry->ptr != 0) {
+                  // Need to add the newly allocated pointer.
+                  live_ptrs[entry->ptr] = std::make_pair(entry, i + 1);
+                }
+                if (erased.first != nullptr) {
+                  // Need to put the erased old ptr back.
+                  live_ptrs[tmp_entry.u.old_ptr] = erased;
+                }
+              }
+              fixed = true;
+              break;
+            }
+          }
+          if (!fixed) {
+            printf("  Unable to fix error.\n");
+          }
+        }
+      } else {
+        live_ptrs[ptr] = std::make_pair(entry, i + 1);
+      }
+    }
+  }
+
+  if (errors_found != 0) {
+    printf("Trace %s is not valid.\n", trace_file);
+    if (attempt_repair) {
+      // Save the repaired data out to a file.
+      std::string repair_file(std::string(trace_file) + ".repair");
+      printf("Creating repaired trace file %s...\n", repair_file.c_str());
+      if (!WriteRepairEntries(repair_file, entries, num_entries)) {
+        printf("Failed trying to write repaired entries to file.\n");
+      } else if (errors_repaired == errors_found) {
+        printf("Repaired file is complete, no more errors.\n");
+      } else {
+        printf("Repaired file is still not valid.\n");
+      }
+    }
+  } else if (attempt_repair) {
+    printf("Trace %s is valid, no repair needed.\n", trace_file);
+  } else {
+    printf("Trace %s is valid.\n", trace_file);
+  }
+
+  FreeEntries(entries, num_entries);
+}
+
+int main(int argc, char** argv) {
+  option options[] = {
+      {"attempt_repair", no_argument, nullptr, 'a'},
+      {nullptr, 0, nullptr, 0},
+  };
+  int option_index = 0;
+  int opt = getopt_long(argc, argv, "", options, &option_index);
+  if (argc == 1 || (argc == 2 && opt != -1)) {
+    fprintf(stderr, "Requires at least one TRACE_FILE\n");
+    Usage();
+  }
+
+  bool attempt_repair = false;
+  if (opt == 'a') {
+    attempt_repair = true;
+  } else if (opt != -1) {
+    Usage();
+  }
+
+  for (int i = 1; i < argc; i++) {
+    if (i + 1 == optind) {
+      continue;
+    }
+    VerifyTrace(argv[i], attempt_repair);
+  }
+
+  return 0;
+}
diff --git a/memory_replay/AllocParser.h b/memory_replay/include/memory_trace/MemoryTrace.h
similarity index 51%
rename from memory_replay/AllocParser.h
rename to memory_replay/include/memory_trace/MemoryTrace.h
index e58be489..108a9218 100644
--- a/memory_replay/AllocParser.h
+++ b/memory_replay/include/memory_trace/MemoryTrace.h
@@ -16,31 +16,40 @@
 
 #pragma once
 
-#include <sys/types.h>
+#include <stdint.h>
 
 #include <string>
 
-enum AllocEnum : uint8_t {
-    MALLOC = 0,
-    CALLOC,
-    MEMALIGN,
-    REALLOC,
-    FREE,
-    THREAD_DONE,
+namespace memory_trace {
+
+enum TypeEnum : uint8_t {
+  MALLOC = 0,
+  CALLOC,
+  MEMALIGN,
+  REALLOC,
+  FREE,
+  THREAD_DONE,
 };
 
-struct AllocEntry {
-    pid_t tid;
-    AllocEnum type;
-    uint64_t ptr = 0;
-    size_t size = 0;
-    union {
-        uint64_t old_ptr = 0;
-        uint64_t n_elements;
-        uint64_t align;
-    } u;
-    uint64_t st = 0;
-    uint64_t et = 0;
+struct Entry {
+  pid_t tid;
+  TypeEnum type;
+  uint64_t ptr = 0;
+  size_t size = 0;
+  union {
+    uint64_t old_ptr = 0;
+    uint64_t n_elements;
+    uint64_t align;
+  } u;
+  uint64_t start_ns = 0;
+  uint64_t end_ns = 0;
 };
 
-void AllocGetData(const std::string& line, AllocEntry* entry);
+bool FillInEntryFromString(const std::string& line, Entry& entry, std::string& error);
+
+std::string CreateStringFromEntry(const Entry& entry);
+
+// Guaranteed not to allocate.
+bool WriteEntryToFd(int fd, const Entry& entry);
+
+}  // namespace memory_trace
diff --git a/memory_replay/main.cpp b/memory_replay/main.cpp
index 7d7c5383..0f509533 100644
--- a/memory_replay/main.cpp
+++ b/memory_replay/main.cpp
@@ -27,6 +27,8 @@
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <memory_trace/MemoryTrace.h>
+
 #include "Alloc.h"
 #include "File.h"
 #include "NativeInfo.h"
@@ -39,28 +41,28 @@
 
 constexpr size_t kDefaultMaxThreads = 512;
 
-static size_t GetMaxAllocs(const AllocEntry* entries, size_t num_entries) {
+static size_t GetMaxAllocs(const memory_trace::Entry* entries, size_t num_entries) {
   size_t max_allocs = 0;
   size_t num_allocs = 0;
   for (size_t i = 0; i < num_entries; i++) {
     switch (entries[i].type) {
-      case THREAD_DONE:
+      case memory_trace::THREAD_DONE:
         break;
-      case MALLOC:
-      case CALLOC:
-      case MEMALIGN:
+      case memory_trace::MALLOC:
+      case memory_trace::CALLOC:
+      case memory_trace::MEMALIGN:
         if (entries[i].ptr != 0) {
           num_allocs++;
         }
         break;
-      case REALLOC:
+      case memory_trace::REALLOC:
         if (entries[i].ptr == 0 && entries[i].u.old_ptr != 0) {
           num_allocs--;
         } else if (entries[i].ptr != 0 && entries[i].u.old_ptr == 0) {
           num_allocs++;
         }
         break;
-      case FREE:
+      case memory_trace::FREE:
         if (entries[i].ptr != 0) {
           num_allocs--;
         }
@@ -109,7 +111,8 @@ static void PrintLogStats(const char* log_name) {
   android_logger_list_close(list);
 }
 
-static void ProcessDump(const AllocEntry* entries, size_t num_entries, size_t max_threads) {
+static void ProcessDump(const memory_trace::Entry* entries, size_t num_entries,
+                        size_t max_threads) {
   // Do a pass to get the maximum number of allocations used at one
   // time to allow a single mmap that can hold the maximum number of
   // pointers needed at once.
@@ -128,7 +131,7 @@ static void ProcessDump(const AllocEntry* entries, size_t num_entries, size_t ma
       dprintf(STDOUT_FILENO, "  At line %zu:\n", i + 1);
       NativePrintInfo("    ");
     }
-    const AllocEntry& entry = entries[i];
+    const memory_trace::Entry& entry = entries[i];
     Thread* thread = threads.FindThread(entry.tid);
     if (thread == nullptr) {
       thread = threads.CreateThread(entry.tid);
@@ -138,7 +141,7 @@ static void ProcessDump(const AllocEntry* entries, size_t num_entries, size_t ma
     // the next action.
     thread->WaitForReady();
 
-    thread->SetAllocEntry(&entry);
+    thread->SetEntry(&entry);
 
     bool does_free = AllocDoesFree(entry);
     if (does_free) {
@@ -151,7 +154,7 @@ static void ProcessDump(const AllocEntry* entries, size_t num_entries, size_t ma
     // Tell the thread to execute the action.
     thread->SetPending();
 
-    if (entries[i].type == THREAD_DONE) {
+    if (entries[i].type == memory_trace::THREAD_DONE) {
       // Wait for the thread to finish and clear the thread entry.
       threads.Finish(thread);
     }
@@ -223,7 +226,7 @@ int main(int argc, char** argv) {
     max_threads = atoi(argv[2]);
   }
 
-  AllocEntry* entries;
+  memory_trace::Entry* entries;
   size_t num_entries;
   GetUnwindInfo(argv[1], &entries, &num_entries);
 
diff --git a/memory_replay/tests/AllocTest.cpp b/memory_replay/tests/AllocTest.cpp
deleted file mode 100644
index d5dd0573..00000000
--- a/memory_replay/tests/AllocTest.cpp
+++ /dev/null
@@ -1,146 +0,0 @@
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
-#include <stdint.h>
-
-#include <string>
-
-#include <gtest/gtest.h>
-
-#include "Alloc.h"
-
-TEST(AllocTest, malloc_valid) {
-  std::string line = "1234: malloc 0xabd0000 20";
-  AllocEntry entry;
-  AllocGetData(line, &entry);
-  EXPECT_EQ(MALLOC, entry.type);
-  EXPECT_EQ(1234, entry.tid);
-  EXPECT_EQ(0xabd0000U, entry.ptr);
-  EXPECT_EQ(20U, entry.size);
-  EXPECT_EQ(0U, entry.u.align);
-}
-
-TEST(AllocTest, malloc_invalid) {
-  std::string line = "1234: malloc 0xabd0000";
-  AllocEntry entry;
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-
-  line = "1234: malloc";
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-}
-
-TEST(AllocTest, free_valid) {
-  std::string line = "1235: free 0x5000";
-  AllocEntry entry;
-  AllocGetData(line, &entry);
-  EXPECT_EQ(FREE, entry.type);
-  EXPECT_EQ(1235, entry.tid);
-  EXPECT_EQ(0x5000U, entry.ptr);
-  EXPECT_EQ(0U, entry.size);
-  EXPECT_EQ(0U, entry.u.align);
-}
-
-TEST(AllocTest, free_invalid) {
-  std::string line = "1234: free";
-  AllocEntry entry;
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-}
-
-TEST(AllocTest, calloc_valid) {
-  std::string line = "1236: calloc 0x8000 50 30";
-  AllocEntry entry;
-  AllocGetData(line, &entry);
-  EXPECT_EQ(CALLOC, entry.type);
-  EXPECT_EQ(1236, entry.tid);
-  EXPECT_EQ(0x8000U, entry.ptr);
-  EXPECT_EQ(30U, entry.size);
-  EXPECT_EQ(50U, entry.u.n_elements);
-}
-
-TEST(AllocTest, calloc_invalid) {
-  std::string line = "1236: calloc 0x8000 50";
-  AllocEntry entry;
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-
-  line = "1236: calloc 0x8000";
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-
-  line = "1236: calloc";
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-}
-
-TEST(AllocTest, realloc_valid) {
-  std::string line = "1237: realloc 0x9000 0x4000 80";
-  AllocEntry entry;
-  AllocGetData(line, &entry);
-  EXPECT_EQ(REALLOC, entry.type);
-  EXPECT_EQ(1237, entry.tid);
-  EXPECT_EQ(0x9000U, entry.ptr);
-  EXPECT_EQ(80U, entry.size);
-  EXPECT_EQ(0x4000U, entry.u.old_ptr);
-}
-
-TEST(AllocTest, realloc_invalid) {
-  std::string line = "1237: realloc 0x9000 0x4000";
-  AllocEntry entry;
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-
-  line = "1237: realloc 0x9000";
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-
-  line = "1237: realloc";
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-}
-
-TEST(AllocTest, memalign_valid) {
-  std::string line = "1238: memalign 0xa000 16 89";
-  AllocEntry entry;
-  AllocGetData(line, &entry);
-  EXPECT_EQ(MEMALIGN, entry.type);
-  EXPECT_EQ(1238, entry.tid);
-  EXPECT_EQ(0xa000U, entry.ptr);
-  EXPECT_EQ(89U, entry.size);
-  EXPECT_EQ(16U, entry.u.align);
-}
-
-TEST(AllocTest, memalign_invalid) {
-  std::string line = "1238: memalign 0xa000 16";
-  AllocEntry entry;
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-
-  line = "1238: memalign 0xa000";
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-
-  line = "1238: memalign";
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-}
-
-TEST(AllocTest, thread_done_valid) {
-  std::string line = "1239: thread_done 0x0";
-  AllocEntry entry;
-  AllocGetData(line, &entry);
-  EXPECT_EQ(THREAD_DONE, entry.type);
-  EXPECT_EQ(1239, entry.tid);
-  EXPECT_EQ(0U, entry.ptr);
-  EXPECT_EQ(0U, entry.size);
-  EXPECT_EQ(0U, entry.u.old_ptr);
-}
-
-TEST(AllocTest, thread_done_invalid) {
-  std::string line = "1240: thread_done";
-  AllocEntry entry;
-  EXPECT_DEATH(AllocGetData(line, &entry), "");
-}
diff --git a/memory_replay/tests/FileTest.cpp b/memory_replay/tests/FileTest.cpp
index 77c0593d..5d92c3de 100644
--- a/memory_replay/tests/FileTest.cpp
+++ b/memory_replay/tests/FileTest.cpp
@@ -22,7 +22,8 @@
 #include <android-base/file.h>
 #include <gtest/gtest.h>
 
-#include "Alloc.h"
+#include <memory_trace/MemoryTrace.h>
+
 #include "File.h"
 
 static std::string GetTestDirectory() {
@@ -46,7 +47,7 @@ TEST(FileTest, get_unwind_info_from_zip_file) {
   std::string file_name = GetTestZip();
 
   size_t mallinfo_before = mallinfo().uordblks;
-  AllocEntry* entries;
+  memory_trace::Entry* entries;
   size_t num_entries;
   GetUnwindInfo(file_name.c_str(), &entries, &num_entries);
   size_t mallinfo_after = mallinfo().uordblks;
@@ -56,13 +57,13 @@ TEST(FileTest, get_unwind_info_from_zip_file) {
 
   ASSERT_EQ(2U, num_entries);
   EXPECT_EQ(12345, entries[0].tid);
-  EXPECT_EQ(MALLOC, entries[0].type);
+  EXPECT_EQ(memory_trace::MALLOC, entries[0].type);
   EXPECT_EQ(0x1000U, entries[0].ptr);
   EXPECT_EQ(16U, entries[0].size);
   EXPECT_EQ(0U, entries[0].u.old_ptr);
 
   EXPECT_EQ(12345, entries[1].tid);
-  EXPECT_EQ(FREE, entries[1].type);
+  EXPECT_EQ(memory_trace::FREE, entries[1].type);
   EXPECT_EQ(0x1000U, entries[1].ptr);
   EXPECT_EQ(0U, entries[1].size);
   EXPECT_EQ(0U, entries[1].u.old_ptr);
@@ -71,7 +72,7 @@ TEST(FileTest, get_unwind_info_from_zip_file) {
 }
 
 TEST(FileTest, get_unwind_info_bad_zip_file) {
-  AllocEntry* entries;
+  memory_trace::Entry* entries;
   size_t num_entries;
   EXPECT_DEATH(GetUnwindInfo("/does/not/exist.zip", &entries, &num_entries), "");
 }
@@ -81,7 +82,7 @@ TEST(FileTest, get_unwind_info_from_text_file) {
   std::string file_name = GetTestDirectory() + "/test.txt";
 
   size_t mallinfo_before = mallinfo().uordblks;
-  AllocEntry* entries;
+  memory_trace::Entry* entries;
   size_t num_entries;
   GetUnwindInfo(file_name.c_str(), &entries, &num_entries);
   size_t mallinfo_after = mallinfo().uordblks;
@@ -91,13 +92,13 @@ TEST(FileTest, get_unwind_info_from_text_file) {
 
   ASSERT_EQ(2U, num_entries);
   EXPECT_EQ(98765, entries[0].tid);
-  EXPECT_EQ(MEMALIGN, entries[0].type);
+  EXPECT_EQ(memory_trace::MEMALIGN, entries[0].type);
   EXPECT_EQ(0xa000U, entries[0].ptr);
   EXPECT_EQ(124U, entries[0].size);
   EXPECT_EQ(16U, entries[0].u.align);
 
   EXPECT_EQ(98765, entries[1].tid);
-  EXPECT_EQ(FREE, entries[1].type);
+  EXPECT_EQ(memory_trace::FREE, entries[1].type);
   EXPECT_EQ(0xa000U, entries[1].ptr);
   EXPECT_EQ(0U, entries[1].size);
   EXPECT_EQ(0U, entries[1].u.old_ptr);
@@ -106,7 +107,7 @@ TEST(FileTest, get_unwind_info_from_text_file) {
 }
 
 TEST(FileTest, get_unwind_info_bad_file) {
-  AllocEntry* entries;
+  memory_trace::Entry* entries;
   size_t num_entries;
   EXPECT_DEATH(GetUnwindInfo("/does/not/exist", &entries, &num_entries), "");
 }
diff --git a/memory_replay/tests/MemoryTraceTest.cpp b/memory_replay/tests/MemoryTraceTest.cpp
new file mode 100644
index 00000000..1cdd3e29
--- /dev/null
+++ b/memory_replay/tests/MemoryTraceTest.cpp
@@ -0,0 +1,371 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+#include <stdint.h>
+#include <unistd.h>
+
+#include <string>
+
+#include <gtest/gtest.h>
+
+#include <android-base/file.h>
+#include <memory_trace/MemoryTrace.h>
+
+TEST(MemoryTraceReadTest, malloc_valid) {
+  std::string line = "1234: malloc 0xabd0000 20";
+  memory_trace::Entry entry{.start_ns = 1, .end_ns = 1};
+  std::string error;
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::MALLOC, entry.type);
+  EXPECT_EQ(1234, entry.tid);
+  EXPECT_EQ(0xabd0000U, entry.ptr);
+  EXPECT_EQ(20U, entry.size);
+  EXPECT_EQ(0U, entry.u.align);
+  EXPECT_EQ(0U, entry.start_ns);
+  EXPECT_EQ(0U, entry.end_ns);
+
+  line += " 1000 1020";
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::MALLOC, entry.type);
+  EXPECT_EQ(1234, entry.tid);
+  EXPECT_EQ(0xabd0000U, entry.ptr);
+  EXPECT_EQ(20U, entry.size);
+  EXPECT_EQ(0U, entry.u.align);
+  EXPECT_EQ(1000U, entry.start_ns);
+  EXPECT_EQ(1020U, entry.end_ns);
+}
+
+TEST(MemoryTraceReadTest, malloc_invalid) {
+  // Missing size
+  std::string line = "1234: malloc 0xabd0000";
+  memory_trace::Entry entry;
+  std::string error;
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read malloc data: 1234: malloc 0xabd0000", error);
+
+  // Missing pointer and size
+  line = "1234: malloc";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to process line: 1234: malloc", error);
+
+  // Missing end time
+  line = "1234: malloc 0xabd0000 10 100";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read timestamps: 1234: malloc 0xabd0000 10 100", error);
+}
+
+TEST(MemoryTraceReadTest, free_valid) {
+  std::string line = "1235: free 0x5000";
+  memory_trace::Entry entry{.start_ns = 1, .end_ns = 1};
+  std::string error;
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::FREE, entry.type);
+  EXPECT_EQ(1235, entry.tid);
+  EXPECT_EQ(0x5000U, entry.ptr);
+  EXPECT_EQ(0U, entry.size);
+  EXPECT_EQ(0U, entry.u.align);
+  EXPECT_EQ(0U, entry.start_ns);
+  EXPECT_EQ(0U, entry.end_ns);
+
+  line += " 540 2000";
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::FREE, entry.type);
+  EXPECT_EQ(1235, entry.tid);
+  EXPECT_EQ(0x5000U, entry.ptr);
+  EXPECT_EQ(0U, entry.size);
+  EXPECT_EQ(0U, entry.u.align);
+  EXPECT_EQ(540U, entry.start_ns);
+  EXPECT_EQ(2000U, entry.end_ns);
+}
+
+TEST(MemoryTraceReadTest, free_invalid) {
+  // Missing pointer
+  std::string line = "1234: free";
+  memory_trace::Entry entry;
+  std::string error;
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to process line: 1234: free", error);
+
+  // Missing end time
+  line = "1234: free 0x100 100";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read timestamps: 1234: free 0x100 100", error);
+}
+
+TEST(MemoryTraceReadTest, calloc_valid) {
+  std::string line = "1236: calloc 0x8000 50 30";
+  memory_trace::Entry entry{.start_ns = 1, .end_ns = 1};
+  std::string error;
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::CALLOC, entry.type);
+  EXPECT_EQ(1236, entry.tid);
+  EXPECT_EQ(0x8000U, entry.ptr);
+  EXPECT_EQ(30U, entry.size);
+  EXPECT_EQ(50U, entry.u.n_elements);
+  EXPECT_EQ(0U, entry.start_ns);
+  EXPECT_EQ(0U, entry.end_ns);
+
+  line += " 700 1000";
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::CALLOC, entry.type);
+  EXPECT_EQ(1236, entry.tid);
+  EXPECT_EQ(0x8000U, entry.ptr);
+  EXPECT_EQ(30U, entry.size);
+  EXPECT_EQ(50U, entry.u.n_elements);
+  EXPECT_EQ(700U, entry.start_ns);
+  EXPECT_EQ(1000U, entry.end_ns);
+}
+
+TEST(MemoryTraceReadTest, calloc_invalid) {
+  // Missing number of elements
+  std::string line = "1236: calloc 0x8000 50";
+  memory_trace::Entry entry;
+  std::string error;
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read calloc data: 1236: calloc 0x8000 50", error);
+
+  // Missing size and number of elements
+  line = "1236: calloc 0x8000";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read calloc data: 1236: calloc 0x8000", error);
+
+  // Missing pointer, size and number of elements
+  line = "1236: calloc";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to process line: 1236: calloc", error);
+
+  // Missing end time
+  line = "1236: calloc 0x8000 50 20 100";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read timestamps: 1236: calloc 0x8000 50 20 100", error);
+}
+
+TEST(MemoryTraceReadTest, realloc_valid) {
+  std::string line = "1237: realloc 0x9000 0x4000 80";
+  memory_trace::Entry entry{.start_ns = 1, .end_ns = 1};
+  std::string error;
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::REALLOC, entry.type);
+  EXPECT_EQ(1237, entry.tid);
+  EXPECT_EQ(0x9000U, entry.ptr);
+  EXPECT_EQ(80U, entry.size);
+  EXPECT_EQ(0x4000U, entry.u.old_ptr);
+  EXPECT_EQ(0U, entry.start_ns);
+  EXPECT_EQ(0U, entry.end_ns);
+
+  line += " 3999 10020";
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::REALLOC, entry.type);
+  EXPECT_EQ(1237, entry.tid);
+  EXPECT_EQ(0x9000U, entry.ptr);
+  EXPECT_EQ(80U, entry.size);
+  EXPECT_EQ(0x4000U, entry.u.old_ptr);
+  EXPECT_EQ(3999U, entry.start_ns);
+  EXPECT_EQ(10020U, entry.end_ns);
+}
+
+TEST(MemoryTraceReadTest, realloc_invalid) {
+  // Missing size
+  std::string line = "1237: realloc 0x9000 0x4000";
+  memory_trace::Entry entry;
+  std::string error;
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read realloc data: 1237: realloc 0x9000 0x4000", error);
+
+  // Missing size and old pointer
+  line = "1237: realloc 0x9000";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read realloc data: 1237: realloc 0x9000", error);
+
+  // Missing new pointer, size and old pointer
+  line = "1237: realloc";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to process line: 1237: realloc", error);
+
+  // Missing end time
+  line = "1237: realloc 0x9000 0x4000 10 500";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read timestamps: 1237: realloc 0x9000 0x4000 10 500", error);
+}
+
+TEST(MemoryTraceReadTest, memalign_valid) {
+  std::string line = "1238: memalign 0xa000 16 89";
+  memory_trace::Entry entry{.start_ns = 1, .end_ns = 1};
+  std::string error;
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::MEMALIGN, entry.type);
+  EXPECT_EQ(1238, entry.tid);
+  EXPECT_EQ(0xa000U, entry.ptr);
+  EXPECT_EQ(89U, entry.size);
+  EXPECT_EQ(16U, entry.u.align);
+  EXPECT_EQ(0U, entry.start_ns);
+  EXPECT_EQ(0U, entry.end_ns);
+
+  line += " 900 1000";
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::MEMALIGN, entry.type);
+  EXPECT_EQ(1238, entry.tid);
+  EXPECT_EQ(0xa000U, entry.ptr);
+  EXPECT_EQ(89U, entry.size);
+  EXPECT_EQ(16U, entry.u.align);
+  EXPECT_EQ(900U, entry.start_ns);
+  EXPECT_EQ(1000U, entry.end_ns);
+}
+
+TEST(MemoryTraceReadTest, memalign_invalid) {
+  // Missing size
+  std::string line = "1238: memalign 0xa000 16";
+  memory_trace::Entry entry;
+  std::string error;
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read memalign data: 1238: memalign 0xa000 16", error);
+
+  // Missing alignment and size
+  line = "1238: memalign 0xa000";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read memalign data: 1238: memalign 0xa000", error);
+
+  // Missing pointer, alignment and size
+  line = "1238: memalign";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to process line: 1238: memalign", error);
+
+  // Missing end time
+  line = "1238: memalign 0xa000 16 10 800";
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to read timestamps: 1238: memalign 0xa000 16 10 800", error);
+}
+
+TEST(MemoryTraceReadTest, thread_done_valid) {
+  std::string line = "1239: thread_done 0x0";
+  memory_trace::Entry entry{.start_ns = 1, .end_ns = 1};
+  std::string error;
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::THREAD_DONE, entry.type);
+  EXPECT_EQ(1239, entry.tid);
+  EXPECT_EQ(0U, entry.ptr);
+  EXPECT_EQ(0U, entry.size);
+  EXPECT_EQ(0U, entry.u.old_ptr);
+  EXPECT_EQ(0U, entry.start_ns);
+  EXPECT_EQ(0U, entry.end_ns);
+
+  line += " 290";
+  ASSERT_TRUE(memory_trace::FillInEntryFromString(line, entry, error)) << error;
+  EXPECT_EQ(memory_trace::THREAD_DONE, entry.type);
+  EXPECT_EQ(1239, entry.tid);
+  EXPECT_EQ(0U, entry.ptr);
+  EXPECT_EQ(0U, entry.size);
+  EXPECT_EQ(0U, entry.u.old_ptr);
+  EXPECT_EQ(0U, entry.start_ns);
+  EXPECT_EQ(290U, entry.end_ns);
+}
+
+TEST(MemoryTraceReadTest, thread_done_invalid) {
+  // Missing pointer
+  std::string line = "1240: thread_done";
+  memory_trace::Entry entry;
+  std::string error;
+  EXPECT_FALSE(memory_trace::FillInEntryFromString(line, entry, error));
+  EXPECT_EQ("Failed to process line: 1240: thread_done", error);
+}
+
+class MemoryTraceOutputTest : public ::testing::Test {
+ protected:
+  void SetUp() override {
+    tmp_file_ = new TemporaryFile();
+    ASSERT_TRUE(tmp_file_->fd != -1);
+  }
+
+  void TearDown() override { delete tmp_file_; }
+
+  void WriteAndReadString(const memory_trace::Entry& entry, std::string& str) {
+    EXPECT_EQ(lseek(tmp_file_->fd, 0, SEEK_SET), 0);
+    EXPECT_TRUE(memory_trace::WriteEntryToFd(tmp_file_->fd, entry));
+    EXPECT_EQ(lseek(tmp_file_->fd, 0, SEEK_SET), 0);
+    EXPECT_TRUE(android::base::ReadFdToString(tmp_file_->fd, &str));
+  }
+
+  std::string WriteAndGetString(const memory_trace::Entry& entry) {
+    std::string str;
+    WriteAndReadString(entry, str);
+    return str;
+  }
+
+  void VerifyEntry(const memory_trace::Entry& entry, const std::string expected) {
+    EXPECT_EQ(expected, memory_trace::CreateStringFromEntry(entry));
+    // The WriteEntryToFd always appends a newline, but string creation doesn't.
+    EXPECT_EQ(expected + "\n", WriteAndGetString(entry));
+  }
+
+  TemporaryFile* tmp_file_ = nullptr;
+};
+
+TEST_F(MemoryTraceOutputTest, malloc_output) {
+  memory_trace::Entry entry{.tid = 123, .type = memory_trace::MALLOC, .ptr = 0x123, .size = 50};
+  VerifyEntry(entry, "123: malloc 0x123 50");
+
+  entry.start_ns = 10;
+  entry.end_ns = 200;
+  VerifyEntry(entry, "123: malloc 0x123 50 10 200");
+}
+
+TEST_F(MemoryTraceOutputTest, calloc_output) {
+  memory_trace::Entry entry{
+      .tid = 123, .type = memory_trace::CALLOC, .ptr = 0x123, .size = 200, .u.n_elements = 400};
+  VerifyEntry(entry, "123: calloc 0x123 400 200");
+
+  entry.start_ns = 15;
+  entry.end_ns = 315;
+  VerifyEntry(entry, "123: calloc 0x123 400 200 15 315");
+}
+
+TEST_F(MemoryTraceOutputTest, memalign_output) {
+  memory_trace::Entry entry{
+      .tid = 123, .type = memory_trace::MEMALIGN, .ptr = 0x123, .size = 1024, .u.align = 0x10};
+  VerifyEntry(entry, "123: memalign 0x123 16 1024");
+
+  entry.start_ns = 23;
+  entry.end_ns = 289;
+  VerifyEntry(entry, "123: memalign 0x123 16 1024 23 289");
+}
+
+TEST_F(MemoryTraceOutputTest, realloc_output) {
+  memory_trace::Entry entry{
+      .tid = 123, .type = memory_trace::REALLOC, .ptr = 0x123, .size = 300, .u.old_ptr = 0x125};
+  VerifyEntry(entry, "123: realloc 0x123 0x125 300");
+
+  entry.start_ns = 45;
+  entry.end_ns = 1000;
+  VerifyEntry(entry, "123: realloc 0x123 0x125 300 45 1000");
+}
+
+TEST_F(MemoryTraceOutputTest, free_output) {
+  memory_trace::Entry entry{.tid = 123, .type = memory_trace::FREE, .ptr = 0x123};
+  VerifyEntry(entry, "123: free 0x123");
+
+  entry.start_ns = 60;
+  entry.end_ns = 2000;
+  VerifyEntry(entry, "123: free 0x123 60 2000");
+}
+
+TEST_F(MemoryTraceOutputTest, thread_done_output) {
+  memory_trace::Entry entry{.tid = 123, .type = memory_trace::THREAD_DONE};
+  VerifyEntry(entry, "123: thread_done 0x0");
+
+  entry.start_ns = 0;
+  entry.end_ns = 2500;
+  VerifyEntry(entry, "123: thread_done 0x0 2500");
+}
diff --git a/memory_replay/tests/ThreadsTest.cpp b/memory_replay/tests/ThreadsTest.cpp
index 990c9130..f9516f12 100644
--- a/memory_replay/tests/ThreadsTest.cpp
+++ b/memory_replay/tests/ThreadsTest.cpp
@@ -16,7 +16,8 @@
 
 #include <gtest/gtest.h>
 
-#include "Alloc.h"
+#include <memory_trace/MemoryTrace.h>
+
 #include "Pointers.h"
 #include "Thread.h"
 #include "Threads.h"
@@ -32,8 +33,8 @@ TEST(ThreadsTest, single_thread) {
   Thread* found_thread = threads.FindThread(900);
   ASSERT_EQ(thread, found_thread);
 
-  AllocEntry thread_done = {.type = THREAD_DONE};
-  thread->SetAllocEntry(&thread_done);
+  memory_trace::Entry thread_done = {.type = memory_trace::THREAD_DONE};
+  thread->SetEntry(&thread_done);
 
   thread->SetPending();
 
@@ -67,10 +68,10 @@ TEST(ThreadsTest, multiple_threads) {
   Thread* found_thread3 = threads.FindThread(902);
   ASSERT_EQ(thread3, found_thread3);
 
-  AllocEntry thread_done = {.type = THREAD_DONE};
-  thread1->SetAllocEntry(&thread_done);
-  thread2->SetAllocEntry(&thread_done);
-  thread3->SetAllocEntry(&thread_done);
+  memory_trace::Entry thread_done = {.type = memory_trace::THREAD_DONE};
+  thread1->SetEntry(&thread_done);
+  thread2->SetEntry(&thread_done);
+  thread3->SetEntry(&thread_done);
 
   thread1->SetPending();
   threads.Finish(thread1);
@@ -96,25 +97,25 @@ TEST(ThreadsTest, verify_quiesce) {
   // If WaitForAllToQuiesce is not correct, then this should provoke an error
   // since we are overwriting the action data while it's being used.
   constexpr size_t kAllocEntries = 512;
-  std::vector<AllocEntry> mallocs(kAllocEntries);
-  std::vector<AllocEntry> frees(kAllocEntries);
+  std::vector<memory_trace::Entry> mallocs(kAllocEntries);
+  std::vector<memory_trace::Entry> frees(kAllocEntries);
   for (size_t i = 0; i < kAllocEntries; i++) {
-    mallocs[i].type = MALLOC;
+    mallocs[i].type = memory_trace::MALLOC;
     mallocs[i].ptr = 0x1234 + i;
     mallocs[i].size = 100;
-    thread->SetAllocEntry(&mallocs[i]);
+    thread->SetEntry(&mallocs[i]);
     thread->SetPending();
     threads.WaitForAllToQuiesce();
 
-    frees[i].type = FREE;
+    frees[i].type = memory_trace::FREE;
     frees[i].ptr = 0x1234 + i;
-    thread->SetAllocEntry(&frees[i]);
+    thread->SetEntry(&frees[i]);
     thread->SetPending();
     threads.WaitForAllToQuiesce();
   }
 
-  AllocEntry thread_done = {.type = THREAD_DONE};
-  thread->SetAllocEntry(&thread_done);
+  memory_trace::Entry thread_done = {.type = memory_trace::THREAD_DONE};
+  thread->SetEntry(&thread_done);
   thread->SetPending();
   threads.Finish(thread);
   ASSERT_EQ(0U, threads.num_threads());
diff --git a/mtectrl/OWNERS b/mtectrl/OWNERS
index 79625dfb..c95d3cfd 100644
--- a/mtectrl/OWNERS
+++ b/mtectrl/OWNERS
@@ -1,5 +1,4 @@
 fmayer@google.com
 
 eugenis@google.com
-mitchp@google.com
 pcc@google.com
diff --git a/profcollectd/libprofcollectd/lib.rs b/profcollectd/libprofcollectd/lib.rs
index 87ce50b6..4663e686 100644
--- a/profcollectd/libprofcollectd/lib.rs
+++ b/profcollectd/libprofcollectd/lib.rs
@@ -20,13 +20,8 @@ mod config;
 mod report;
 mod scheduler;
 mod service;
-mod simpleperf_etm_trace_provider;
-mod simpleperf_lbr_trace_provider;
 mod trace_provider;
 
-#[cfg(feature = "test")]
-mod logging_trace_provider;
-
 use anyhow::{Context, Result};
 use profcollectd_aidl_interface::aidl::com::android::server::profcollect::IProfCollectd::{
     self, BnProfCollectd,
diff --git a/profcollectd/libprofcollectd/trace_provider.rs b/profcollectd/libprofcollectd/trace_provider.rs
index a620743e..a57d3bab 100644
--- a/profcollectd/libprofcollectd/trace_provider.rs
+++ b/profcollectd/libprofcollectd/trace_provider.rs
@@ -16,17 +16,23 @@
 
 //! ProfCollect trace provider trait and helper functions.
 
+mod simpleperf_etm;
+mod simpleperf_lbr;
+
+#[cfg(feature = "test")]
+mod logging;
+
 use anyhow::{anyhow, Result};
 use chrono::Utc;
 use std::path::{Path, PathBuf};
 use std::sync::{Arc, Mutex};
 use std::time::Duration;
 
-use crate::simpleperf_etm_trace_provider::SimpleperfEtmTraceProvider;
-use crate::simpleperf_lbr_trace_provider::SimpleperfLbrTraceProvider;
+use simpleperf_etm::SimpleperfEtmTraceProvider;
+use simpleperf_lbr::SimpleperfLbrTraceProvider;
 
 #[cfg(feature = "test")]
-use crate::logging_trace_provider::LoggingTraceProvider;
+use logging::LoggingTraceProvider;
 
 pub trait TraceProvider {
     fn get_name(&self) -> &'static str;
diff --git a/profcollectd/libprofcollectd/logging_trace_provider.rs b/profcollectd/libprofcollectd/trace_provider/logging.rs
similarity index 100%
rename from profcollectd/libprofcollectd/logging_trace_provider.rs
rename to profcollectd/libprofcollectd/trace_provider/logging.rs
diff --git a/profcollectd/libprofcollectd/simpleperf_etm_trace_provider.rs b/profcollectd/libprofcollectd/trace_provider/simpleperf_etm.rs
similarity index 100%
rename from profcollectd/libprofcollectd/simpleperf_etm_trace_provider.rs
rename to profcollectd/libprofcollectd/trace_provider/simpleperf_etm.rs
diff --git a/profcollectd/libprofcollectd/simpleperf_lbr_trace_provider.rs b/profcollectd/libprofcollectd/trace_provider/simpleperf_lbr.rs
similarity index 90%
rename from profcollectd/libprofcollectd/simpleperf_lbr_trace_provider.rs
rename to profcollectd/libprofcollectd/trace_provider/simpleperf_lbr.rs
index a12d935b..11ae1531 100644
--- a/profcollectd/libprofcollectd/simpleperf_lbr_trace_provider.rs
+++ b/profcollectd/libprofcollectd/trace_provider/simpleperf_lbr.rs
@@ -25,6 +25,8 @@ use crate::trace_provider;
 
 static LBR_TRACEFILE_EXTENSION: &str = "lbrtrace";
 static LBR_PROFILE_EXTENSION: &str = "data";
+// Use a prime value to make sure that there are no weird interactions with e.g. short loops.
+static LBR_SAMPLE_PERIOD: &str = "500009";
 
 pub struct SimpleperfLbrTraceProvider {}
 
@@ -47,13 +49,18 @@ impl TraceProvider for SimpleperfLbrTraceProvider {
         let trace_file = trace_provider::get_path(trace_dir, tag, LBR_TRACEFILE_EXTENSION);
         // Record ETM data for kernel space only when it's not filtered out by binary_filter. So we
         // can get more ETM data for user space when ETM data for kernel space isn't needed.
-        let event_name =
-            if binary_filter.contains("kernel") { "cpu-cycles" } else { "cpu-cycles:u" };
+        let event_name = if binary_filter.contains("kernel") {
+            "BR_INST_RETIRED.NEAR_TAKEN"
+        } else {
+            "BR_INST_RETIRED.NEAR_TAKEN:u"
+        };
         let duration: String = sampling_period.as_secs_f64().to_string();
         let args: Vec<&str> = vec![
             "-a",
             "-e",
             event_name,
+            "-c",
+            LBR_SAMPLE_PERIOD,
             "--duration",
             &duration,
             "-b",
@@ -76,13 +83,15 @@ impl TraceProvider for SimpleperfLbrTraceProvider {
         processes: &str,
     ) {
         let trace_file = trace_provider::get_path(trace_dir, tag, LBR_TRACEFILE_EXTENSION);
-        let event_name = "cpu-cycles:u";
+        let event_name = "BR_INST_RETIRED.NEAR_TAKEN:u";
         let duration: String = sampling_period.as_secs_f64().to_string();
         let args: Vec<&str> = vec![
             "-p",
             processes,
             "-e",
             event_name,
+            "-c",
+            LBR_SAMPLE_PERIOD,
             "--duration",
             &duration,
             "-b",
diff --git a/simpleperf/Android.bp b/simpleperf/Android.bp
index 7cf76118..c1b45f1e 100644
--- a/simpleperf/Android.bp
+++ b/simpleperf/Android.bp
@@ -801,6 +801,9 @@ genrule {
         "scripts/**/*",
         "testdata/**/*",
     ],
+    exclude_srcs: [
+        "scripts/binary_cache/**/*",
+    ],
     cmd: "$(location soong_zip) -o $(out) -C system/extras/simpleperf " +
         "-D system/extras/simpleperf ",
     out: [
diff --git a/simpleperf/BranchListFile.cpp b/simpleperf/BranchListFile.cpp
index 253dcdbc..13ab72ee 100644
--- a/simpleperf/BranchListFile.cpp
+++ b/simpleperf/BranchListFile.cpp
@@ -17,6 +17,7 @@
 #include "BranchListFile.h"
 
 #include "ETMDecoder.h"
+#include "ZstdUtil.h"
 #include "system/extras/simpleperf/branch_list.pb.h"
 
 namespace simpleperf {
@@ -59,44 +60,11 @@ static std::optional<proto::ETMBinary::BinaryType> ToProtoBinaryType(DsoType dso
 }
 
 bool ETMBinaryMapToString(const ETMBinaryMap& binary_map, std::string& s) {
-  proto::BranchList branch_list_proto;
-  branch_list_proto.set_magic(ETM_BRANCH_LIST_PROTO_MAGIC);
-  std::vector<char> branch_buf;
-  for (const auto& p : binary_map) {
-    const BinaryKey& key = p.first;
-    const ETMBinary& binary = p.second;
-    auto binary_proto = branch_list_proto.add_etm_data();
-
-    binary_proto->set_path(key.path);
-    if (!key.build_id.IsEmpty()) {
-      binary_proto->set_build_id(key.build_id.ToString().substr(2));
-    }
-    auto opt_binary_type = ToProtoBinaryType(binary.dso_type);
-    if (!opt_binary_type.has_value()) {
-      return false;
-    }
-    binary_proto->set_type(opt_binary_type.value());
-
-    for (const auto& addr_p : binary.branch_map) {
-      auto addr_proto = binary_proto->add_addrs();
-      addr_proto->set_addr(addr_p.first);
-
-      for (const auto& branch_p : addr_p.second) {
-        const std::vector<bool>& branch = branch_p.first;
-        auto branch_proto = addr_proto->add_branches();
-
-        branch_proto->set_branch(ETMBranchToProtoString(branch));
-        branch_proto->set_branch_size(branch.size());
-        branch_proto->set_count(branch_p.second);
-      }
-    }
-
-    if (binary.dso_type == DSO_KERNEL) {
-      binary_proto->mutable_kernel_info()->set_kernel_start_addr(key.kernel_start_addr);
-    }
+  auto writer = BranchListProtoWriter::CreateForString(&s, false);
+  if (!writer) {
+    return false;
   }
-  if (!branch_list_proto.SerializeToString(&s)) {
-    LOG(ERROR) << "failed to serialize branch list binary map";
+  if (!writer->Write(binary_map)) {
     return false;
   }
   return true;
@@ -116,24 +84,13 @@ static std::optional<DsoType> ToDsoType(proto::ETMBinary::BinaryType binary_type
   }
 }
 
-static UnorderedETMBranchMap BuildUnorderedETMBranchMap(const proto::ETMBinary& binary_proto) {
-  UnorderedETMBranchMap branch_map;
-  for (size_t i = 0; i < binary_proto.addrs_size(); i++) {
-    const auto& addr_proto = binary_proto.addrs(i);
-    auto& b_map = branch_map[addr_proto.addr()];
-    for (size_t j = 0; j < addr_proto.branches_size(); j++) {
-      const auto& branch_proto = addr_proto.branches(j);
-      std::vector<bool> branch =
-          ProtoStringToETMBranch(branch_proto.branch(), branch_proto.branch_size());
-      b_map[branch] = branch_proto.count();
-    }
-  }
-  return branch_map;
-}
-
 bool StringToETMBinaryMap(const std::string& s, ETMBinaryMap& binary_map) {
   LBRData lbr_data;
-  return ParseBranchListData(s, binary_map, lbr_data);
+  auto reader = BranchListProtoReader::CreateForString(s);
+  if (!reader) {
+    return false;
+  }
+  return reader->Read(binary_map, lbr_data);
 }
 
 class ETMThreadTreeWhenRecording : public ETMThreadTree {
@@ -359,79 +316,424 @@ std::unique_ptr<ETMBranchListGenerator> ETMBranchListGenerator::Create(bool dump
 ETMBranchListGenerator::~ETMBranchListGenerator() {}
 
 bool LBRDataToString(const LBRData& data, std::string& s) {
-  proto::BranchList branch_list_proto;
-  branch_list_proto.set_magic(ETM_BRANCH_LIST_PROTO_MAGIC);
-  auto lbr_proto = branch_list_proto.mutable_lbr_data();
-  for (const LBRSample& sample : data.samples) {
-    auto sample_proto = lbr_proto->add_samples();
-    sample_proto->set_binary_id(sample.binary_id);
-    sample_proto->set_vaddr_in_file(sample.vaddr_in_file);
+  auto writer = BranchListProtoWriter::CreateForString(&s, false);
+  if (!writer) {
+    return false;
+  }
+  if (!writer->Write(data)) {
+    return false;
+  }
+  return true;
+}
+
+std::unique_ptr<BranchListProtoWriter> BranchListProtoWriter::CreateForFile(
+    const std::string& output_filename, bool compress, size_t max_branches_per_message) {
+  auto writer = std::unique_ptr<BranchListProtoWriter>(
+      new BranchListProtoWriter(output_filename, nullptr, compress, max_branches_per_message));
+  if (!writer->WriteHeader()) {
+    return nullptr;
+  }
+  return writer;
+}
+
+std::unique_ptr<BranchListProtoWriter> BranchListProtoWriter::CreateForString(
+    std::string* output_str, bool compress, size_t max_branches_per_message) {
+  auto writer = std::unique_ptr<BranchListProtoWriter>(
+      new BranchListProtoWriter("", output_str, compress, max_branches_per_message));
+  if (!writer->WriteHeader()) {
+    return nullptr;
+  }
+  return writer;
+}
+
+bool BranchListProtoWriter::Write(const ETMBinaryMap& etm_data) {
+  if (!output_fp_ && !WriteHeader()) {
+    return false;
+  }
+  std::unique_ptr<proto::BranchList> proto_branch_list = std::make_unique<proto::BranchList>();
+  proto::ETMBinary* proto_binary = nullptr;
+  proto::ETMBinary_Address* proto_addr = nullptr;
+  size_t branch_count = 0;
+
+  auto add_proto_binary = [&](const BinaryKey& key, const ETMBinary& binary) {
+    proto_binary = proto_branch_list->add_etm_data();
+    proto_binary->set_path(key.path);
+    if (!key.build_id.IsEmpty()) {
+      proto_binary->set_build_id(key.build_id.ToString().substr(2));
+    }
+    auto opt_binary_type = ToProtoBinaryType(binary.dso_type);
+    if (!opt_binary_type.has_value()) {
+      return false;
+    }
+    proto_binary->set_type(opt_binary_type.value());
+    if (binary.dso_type == DSO_KERNEL) {
+      proto_binary->mutable_kernel_info()->set_kernel_start_addr(key.kernel_start_addr);
+    }
+    return true;
+  };
+
+  auto add_proto_addr = [&](uint64_t addr) {
+    proto_addr = proto_binary->add_addrs();
+    proto_addr->set_addr(addr);
+  };
+
+  for (const auto& [key, binary] : etm_data) {
+    if (!add_proto_binary(key, binary)) {
+      return false;
+    }
+    for (const auto& [addr, branch_map] : binary.branch_map) {
+      add_proto_addr(addr);
+      size_t new_branch_count = 0;
+      for (const auto& [branch, _] : branch_map) {
+        new_branch_count += branch.size();
+      }
+      if (branch_count + new_branch_count > max_branches_per_message_) {
+        if (!WriteProtoBranchList(*proto_branch_list)) {
+          return false;
+        }
+        proto_branch_list.reset(new proto::BranchList);
+        if (!add_proto_binary(key, binary)) {
+          return false;
+        }
+        add_proto_addr(addr);
+        branch_count = 0;
+      }
+      branch_count += new_branch_count;
+      for (const auto& [branch, count] : branch_map) {
+        proto::ETMBinary_Address_Branch* proto_branch = proto_addr->add_branches();
+        proto_branch->set_branch(ETMBranchToProtoString(branch));
+        proto_branch->set_branch_size(branch.size());
+        proto_branch->set_count(count);
+      }
+    }
+  }
+  return WriteProtoBranchList(*proto_branch_list);
+}
+
+bool BranchListProtoWriter::Write(const LBRData& lbr_data) {
+  if (!output_fp_ && !WriteHeader()) {
+    return false;
+  }
+  proto::BranchList proto_branch_list;
+  proto_branch_list.set_magic(ETM_BRANCH_LIST_PROTO_MAGIC);
+  auto proto_lbr = proto_branch_list.mutable_lbr_data();
+  for (const LBRSample& sample : lbr_data.samples) {
+    auto proto_sample = proto_lbr->add_samples();
+    proto_sample->set_binary_id(sample.binary_id);
+    proto_sample->set_vaddr_in_file(sample.vaddr_in_file);
     for (const LBRBranch& branch : sample.branches) {
-      auto branch_proto = sample_proto->add_branches();
-      branch_proto->set_from_binary_id(branch.from_binary_id);
-      branch_proto->set_to_binary_id(branch.to_binary_id);
-      branch_proto->set_from_vaddr_in_file(branch.from_vaddr_in_file);
-      branch_proto->set_to_vaddr_in_file(branch.to_vaddr_in_file);
+      auto proto_branch = proto_sample->add_branches();
+      proto_branch->set_from_binary_id(branch.from_binary_id);
+      proto_branch->set_to_binary_id(branch.to_binary_id);
+      proto_branch->set_from_vaddr_in_file(branch.from_vaddr_in_file);
+      proto_branch->set_to_vaddr_in_file(branch.to_vaddr_in_file);
+    }
+  }
+  for (const BinaryKey& binary : lbr_data.binaries) {
+    auto proto_binary = proto_lbr->add_binaries();
+    proto_binary->set_path(binary.path);
+    proto_binary->set_build_id(binary.build_id.ToString().substr(2));
+  }
+  return WriteProtoBranchList(proto_branch_list);
+}
+
+bool BranchListProtoWriter::WriteHeader() {
+  if (!output_filename_.empty()) {
+    output_fp_.reset(fopen(output_filename_.c_str(), "wbe"));
+    if (!output_fp_) {
+      PLOG(ERROR) << "failed to open " << output_filename_;
+      return false;
     }
+  } else {
+    output_str_->clear();
+  }
+  if (!WriteData(ETM_BRANCH_LIST_PROTO_MAGIC, strlen(ETM_BRANCH_LIST_PROTO_MAGIC))) {
+    return false;
   }
-  for (const BinaryKey& binary : data.binaries) {
-    auto binary_proto = lbr_proto->add_binaries();
-    binary_proto->set_path(binary.path);
-    binary_proto->set_build_id(binary.build_id.ToString().substr(2));
+  uint32_t version = 1;
+  if (!WriteData(&version, sizeof(version))) {
+    return false;
   }
-  if (!branch_list_proto.SerializeToString(&s)) {
-    LOG(ERROR) << "failed to serialize lbr data";
+  uint8_t compress = compress_ ? 1 : 0;
+  if (!WriteData(&compress, sizeof(compress))) {
     return false;
   }
   return true;
 }
 
-bool ParseBranchListData(const std::string& s, ETMBinaryMap& etm_data, LBRData& lbr_data) {
-  proto::BranchList branch_list_proto;
-  if (!branch_list_proto.ParseFromString(s)) {
-    PLOG(ERROR) << "failed to read ETMBranchList msg";
+bool BranchListProtoWriter::WriteProtoBranchList(proto::BranchList& branch_list) {
+  std::string s;
+  if (!branch_list.SerializeToString(&s)) {
+    LOG(ERROR) << "failed to serialize branch list binary map";
     return false;
   }
-  if (branch_list_proto.magic() != ETM_BRANCH_LIST_PROTO_MAGIC) {
-    PLOG(ERROR) << "not in etm branch list format in branch_list.proto";
+  if (compress_ && !ZstdCompress(s.data(), s.size(), s)) {
     return false;
   }
-  for (size_t i = 0; i < branch_list_proto.etm_data_size(); i++) {
-    const auto& binary_proto = branch_list_proto.etm_data(i);
-    BinaryKey key(binary_proto.path(), BuildId(binary_proto.build_id()));
-    if (binary_proto.has_kernel_info()) {
-      key.kernel_start_addr = binary_proto.kernel_info().kernel_start_addr();
+  uint32_t msg_size = s.size();
+  return WriteData(&msg_size, sizeof(msg_size)) && WriteData(s.data(), s.size());
+}
+
+bool BranchListProtoWriter::WriteData(const void* data, size_t size) {
+  if (output_fp_) {
+    if (fwrite(data, size, 1, output_fp_.get()) != 1) {
+      LOG(ERROR) << "failed to write to " << output_filename_;
+      return false;
     }
-    ETMBinary& binary = etm_data[key];
-    auto dso_type = ToDsoType(binary_proto.type());
-    if (!dso_type) {
-      LOG(ERROR) << "invalid binary type " << binary_proto.type();
+  } else {
+    output_str_->insert(output_str_->size(), static_cast<const char*>(data), size);
+  }
+  return true;
+}
+
+std::unique_ptr<BranchListProtoReader> BranchListProtoReader::CreateForFile(
+    const std::string& input_filename) {
+  return std::unique_ptr<BranchListProtoReader>(new BranchListProtoReader(input_filename, ""));
+}
+
+std::unique_ptr<BranchListProtoReader> BranchListProtoReader::CreateForString(
+    const std::string& input_str) {
+  return std::unique_ptr<BranchListProtoReader>(new BranchListProtoReader("", input_str));
+}
+
+bool BranchListProtoReader::Read(ETMBinaryMap& etm_data, LBRData& lbr_data) {
+  if (!input_filename_.empty()) {
+    input_fp_.reset(fopen(input_filename_.c_str(), "rbe"));
+    if (!input_fp_) {
+      PLOG(ERROR) << "failed to open " << input_filename_;
+      return false;
+    }
+  }
+  char magic[24];
+  if (!ReadData(magic, sizeof(magic)) ||
+      memcmp(magic, ETM_BRANCH_LIST_PROTO_MAGIC, sizeof(magic)) != 0) {
+    return ReadOldFileFormat(etm_data, lbr_data);
+  }
+  uint32_t version;
+  if (!ReadData(&version, sizeof(version)) && version != 1) {
+    LOG(ERROR) << "unsupported version in " << input_filename_;
+    return false;
+  }
+  uint8_t compress;
+  if (!ReadData(&compress, sizeof(compress))) {
+    return false;
+  }
+  compress_ = compress == 1;
+  long file_offset = ftell(input_fp_.get());
+  if (file_offset == -1) {
+    PLOG(ERROR) << "failed to call ftell";
+    return false;
+  }
+  uint64_t file_size = GetFileSize(input_filename_);
+  while (file_offset < file_size) {
+    uint32_t msg_size;
+    if (!ReadData(&msg_size, sizeof(msg_size))) {
+      return false;
+    }
+    proto::BranchList proto_branch_list;
+    if (!ReadProtoBranchList(msg_size, proto_branch_list)) {
+      return false;
+    }
+    for (size_t i = 0; i < proto_branch_list.etm_data_size(); i++) {
+      const proto::ETMBinary& proto_binary = proto_branch_list.etm_data(i);
+      if (!AddETMBinary(proto_binary, etm_data)) {
+        return false;
+      }
+    }
+    if (proto_branch_list.has_lbr_data()) {
+      AddLBRData(proto_branch_list.lbr_data(), lbr_data);
+    }
+    file_offset += 4 + msg_size;
+  }
+  return true;
+}
+
+bool BranchListProtoReader::AddETMBinary(const proto::ETMBinary& proto_binary,
+                                         ETMBinaryMap& etm_data) {
+  BinaryKey key(proto_binary.path(), BuildId(proto_binary.build_id()));
+  if (proto_binary.has_kernel_info()) {
+    key.kernel_start_addr = proto_binary.kernel_info().kernel_start_addr();
+  }
+  ETMBinary& binary = etm_data[key];
+  auto dso_type = ToDsoType(proto_binary.type());
+  if (!dso_type) {
+    LOG(ERROR) << "invalid binary type " << proto_binary.type();
+    return false;
+  }
+  binary.dso_type = dso_type.value();
+  auto& branch_map = binary.branch_map;
+  for (size_t i = 0; i < proto_binary.addrs_size(); i++) {
+    const auto& proto_addr = proto_binary.addrs(i);
+    auto& b_map = branch_map[proto_addr.addr()];
+    for (size_t j = 0; j < proto_addr.branches_size(); j++) {
+      const auto& proto_branch = proto_addr.branches(j);
+      std::vector<bool> branch =
+          ProtoStringToETMBranch(proto_branch.branch(), proto_branch.branch_size());
+      b_map[branch] = proto_branch.count();
+    }
+  }
+  return true;
+}
+
+void BranchListProtoReader::AddLBRData(const proto::LBRData& proto_lbr_data, LBRData& lbr_data) {
+  for (size_t i = 0; i < proto_lbr_data.samples_size(); ++i) {
+    const auto& proto_sample = proto_lbr_data.samples(i);
+    lbr_data.samples.resize(lbr_data.samples.size() + 1);
+    LBRSample& sample = lbr_data.samples.back();
+    sample.binary_id = proto_sample.binary_id();
+    sample.vaddr_in_file = proto_sample.vaddr_in_file();
+    sample.branches.resize(proto_sample.branches_size());
+    for (size_t j = 0; j < proto_sample.branches_size(); ++j) {
+      const auto& proto_branch = proto_sample.branches(j);
+      LBRBranch& branch = sample.branches[j];
+      branch.from_binary_id = proto_branch.from_binary_id();
+      branch.to_binary_id = proto_branch.to_binary_id();
+      branch.from_vaddr_in_file = proto_branch.from_vaddr_in_file();
+      branch.to_vaddr_in_file = proto_branch.to_vaddr_in_file();
+    }
+  }
+  for (size_t i = 0; i < proto_lbr_data.binaries_size(); ++i) {
+    const auto& proto_binary = proto_lbr_data.binaries(i);
+    lbr_data.binaries.emplace_back(proto_binary.path(), BuildId(proto_binary.build_id()));
+  }
+}
+
+bool BranchListProtoReader::ReadProtoBranchList(uint32_t size,
+                                                proto::BranchList& proto_branch_list) {
+  std::string s;
+  s.resize(size);
+  if (!ReadData(s.data(), size)) {
+    return false;
+  }
+  if (compress_ && !ZstdDecompress(s.data(), s.size(), s)) {
+    return false;
+  }
+  if (!proto_branch_list.ParseFromString(s)) {
+    PLOG(ERROR) << "failed to read ETMBranchList msg";
+    return false;
+  }
+  return true;
+}
+
+void BranchListProtoReader::Rewind() {
+  if (input_fp_) {
+    rewind(input_fp_.get());
+  } else {
+    input_str_pos_ = 0;
+  }
+}
+
+bool BranchListProtoReader::ReadData(void* data, size_t size) {
+  if (input_fp_) {
+    if (fread(data, size, 1, input_fp_.get()) != 1) {
+      PLOG(ERROR) << "failed to read " << input_filename_;
       return false;
     }
-    binary.dso_type = dso_type.value();
-    binary.branch_map = BuildUnorderedETMBranchMap(binary_proto);
-  }
-  if (branch_list_proto.has_lbr_data()) {
-    const auto& lbr_data_proto = branch_list_proto.lbr_data();
-    lbr_data.samples.resize(lbr_data_proto.samples_size());
-    for (size_t i = 0; i < lbr_data_proto.samples_size(); ++i) {
-      const auto& sample_proto = lbr_data_proto.samples(i);
-      LBRSample& sample = lbr_data.samples[i];
-      sample.binary_id = sample_proto.binary_id();
-      sample.vaddr_in_file = sample_proto.vaddr_in_file();
-      sample.branches.resize(sample_proto.branches_size());
-      for (size_t j = 0; j < sample_proto.branches_size(); ++j) {
-        const auto& branch_proto = sample_proto.branches(j);
-        LBRBranch& branch = sample.branches[j];
-        branch.from_binary_id = branch_proto.from_binary_id();
-        branch.to_binary_id = branch_proto.to_binary_id();
-        branch.from_vaddr_in_file = branch_proto.from_vaddr_in_file();
-        branch.to_vaddr_in_file = branch_proto.to_vaddr_in_file();
+  } else {
+    if (input_str_pos_ + size > input_str_.size()) {
+      LOG(ERROR) << "failed to read BranchList from string";
+      return false;
+    }
+    memcpy(data, &input_str_[input_str_pos_], size);
+    input_str_pos_ += size;
+  }
+  return true;
+}
+
+bool BranchListProtoReader::ReadOldFileFormat(ETMBinaryMap& etm_data, LBRData& lbr_data) {
+  size_t size = 0;
+  if (!input_filename_.empty()) {
+    size = static_cast<size_t>(GetFileSize(input_filename_));
+    if (android::base::EndsWith(input_filename_, ".zst")) {
+      compress_ = true;
+    }
+  } else {
+    size = input_str_.size();
+  }
+  Rewind();
+  proto::BranchList proto_branch_list;
+  if (!ReadProtoBranchList(size, proto_branch_list)) {
+    return false;
+  }
+  if (proto_branch_list.magic() != ETM_BRANCH_LIST_PROTO_MAGIC) {
+    PLOG(ERROR) << "not in format of branch_list.proto";
+  }
+  for (size_t i = 0; i < proto_branch_list.etm_data_size(); i++) {
+    const proto::ETMBinary& proto_binary = proto_branch_list.etm_data(i);
+    if (!AddETMBinary(proto_binary, etm_data)) {
+      return false;
+    }
+  }
+  if (proto_branch_list.has_lbr_data()) {
+    AddLBRData(proto_branch_list.lbr_data(), lbr_data);
+  }
+  return true;
+}
+
+bool DumpBranchListFile(std::string filename) {
+  ETMBinaryMap etm_data;
+  LBRData lbr_data;
+  auto reader = BranchListProtoReader::CreateForFile(filename);
+  if (!reader || !reader->Read(etm_data, lbr_data)) {
+    return false;
+  }
+
+  if (!etm_data.empty()) {
+    std::vector<BinaryKey> sorted_keys;
+    for (const auto& [key, _] : etm_data) {
+      sorted_keys.emplace_back(key);
+    }
+    std::sort(sorted_keys.begin(), sorted_keys.end(),
+              [](const BinaryKey& key1, const BinaryKey& key2) { return key1.path < key2.path; });
+    PrintIndented(0, "etm_data:\n");
+    for (size_t i = 0; i < sorted_keys.size(); ++i) {
+      const auto& key = sorted_keys[i];
+      const auto& binary = etm_data[key];
+      PrintIndented(1, "binary[%zu].path: %s\n", i, key.path.c_str());
+      PrintIndented(1, "binary[%zu].build_id: %s\n", i, key.build_id.ToString().c_str());
+      PrintIndented(1, "binary[%zu].binary_type: %s\n", i, DsoTypeToString(binary.dso_type));
+      if (binary.dso_type == DSO_KERNEL) {
+        PrintIndented(1, "binary[%zu].kernel_start_addr: 0x%" PRIx64 "\n", i,
+                      key.kernel_start_addr);
+      }
+      PrintIndented(1, "binary[%zu].addrs:\n", i);
+      size_t addr_id = 0;
+      for (const auto& [addr, branches] : binary.GetOrderedBranchMap()) {
+        PrintIndented(2, "addr[%zu]: 0x%" PRIx64 "\n", addr_id++, addr);
+        size_t branch_id = 0;
+        for (const auto& [branch, count] : branches) {
+          std::string s = "0b";
+          for (auto it = branch.rbegin(); it != branch.rend(); ++it) {
+            s.push_back(*it ? '1' : '0');
+          }
+          PrintIndented(3, "branch[%zu].branch: %s\n", branch_id, s.c_str());
+          PrintIndented(3, "branch[%zu].count: %" PRIu64 "\n", branch_id, count);
+          ++branch_id;
+        }
+      }
+    }
+  }
+  if (!lbr_data.samples.empty()) {
+    PrintIndented(0, "lbr_data:\n");
+    for (size_t i = 0; i < lbr_data.samples.size(); ++i) {
+      const auto& sample = lbr_data.samples[i];
+      PrintIndented(1, "sample[%zu].binary_id: %u\n", i, sample.binary_id);
+      PrintIndented(1, "sample[%zu].vaddr_in_file: 0x%" PRIx64 "\n", i, sample.vaddr_in_file);
+      PrintIndented(1, "sample[%zu].branches:\n", i);
+      for (size_t j = 0; j < sample.branches.size(); ++j) {
+        const auto& branch = sample.branches[j];
+        PrintIndented(2, "branch[%zu].from_binary_id: %u\n", j, branch.from_binary_id);
+        PrintIndented(2, "branch[%zu].from_vaddr_in_file: 0x%" PRIx64 "\n", j,
+                      branch.from_vaddr_in_file);
+        PrintIndented(2, "branch[%zu].to_binary_id: %u\n", j, branch.to_binary_id);
+        PrintIndented(2, "branch[%zu].to_vaddr_in_file: 0x%" PRIx64 "\n", j,
+                      branch.to_vaddr_in_file);
       }
     }
-    for (size_t i = 0; i < lbr_data_proto.binaries_size(); ++i) {
-      const auto& binary_proto = lbr_data_proto.binaries(i);
-      lbr_data.binaries.emplace_back(binary_proto.path(), BuildId(binary_proto.build_id()));
+    for (size_t i = 0; i < lbr_data.binaries.size(); ++i) {
+      const auto& binary = lbr_data.binaries[i];
+      PrintIndented(1, "binary[%zu].path: %s\n", i, binary.path.c_str());
+      PrintIndented(1, "binary[%zu].build_id: %s\n", i, binary.build_id.ToString().c_str());
     }
   }
   return true;
diff --git a/simpleperf/BranchListFile.h b/simpleperf/BranchListFile.h
index 72009086..64a00abb 100644
--- a/simpleperf/BranchListFile.h
+++ b/simpleperf/BranchListFile.h
@@ -170,7 +170,73 @@ struct LBRData {
 };
 
 bool LBRDataToString(const LBRData& data, std::string& s);
-bool ParseBranchListData(const std::string& s, ETMBinaryMap& etm_data, LBRData& lbr_data);
+
+namespace proto {
+class BranchList;
+class ETMBinary;
+class LBRData;
+}  // namespace proto
+
+class BranchListProtoWriter {
+ private:
+  // This value is choosen to prevent exceeding the 2GB size limit for a protobuf message.
+  static constexpr size_t kMaxBranchesPerMessage = 100000000;
+
+ public:
+  static std::unique_ptr<BranchListProtoWriter> CreateForFile(
+      const std::string& output_filename, bool compress,
+      size_t max_branches_per_message = kMaxBranchesPerMessage);
+  static std::unique_ptr<BranchListProtoWriter> CreateForString(
+      std::string* output_str, bool compress,
+      size_t max_branches_per_message = kMaxBranchesPerMessage);
+
+  bool Write(const ETMBinaryMap& etm_data);
+  bool Write(const LBRData& lbr_data);
+
+ private:
+  BranchListProtoWriter(const std::string& output_filename, std::string* output_str, bool compress,
+                        size_t max_branches_per_message)
+      : output_filename_(output_filename),
+        compress_(compress),
+        max_branches_per_message_(max_branches_per_message),
+        output_fp_(nullptr, fclose),
+        output_str_(output_str) {}
+
+  bool WriteHeader();
+  bool WriteProtoBranchList(proto::BranchList& branch_list);
+  bool WriteData(const void* data, size_t size);
+
+  const std::string output_filename_;
+  const bool compress_;
+  const size_t max_branches_per_message_;
+  std::unique_ptr<FILE, decltype(&fclose)> output_fp_;
+  std::string* output_str_;
+};
+
+class BranchListProtoReader {
+ public:
+  static std::unique_ptr<BranchListProtoReader> CreateForFile(const std::string& input_filename);
+  static std::unique_ptr<BranchListProtoReader> CreateForString(const std::string& input_str);
+  bool Read(ETMBinaryMap& etm_data, LBRData& lbr_data);
+
+ private:
+  BranchListProtoReader(const std::string& input_filename, const std::string& input_str)
+      : input_filename_(input_filename), input_fp_(nullptr, fclose), input_str_(input_str) {}
+  bool ReadProtoBranchList(uint32_t size, proto::BranchList& proto_branch_list);
+  bool AddETMBinary(const proto::ETMBinary& proto_binary, ETMBinaryMap& etm_data);
+  void AddLBRData(const proto::LBRData& proto_lbr_data, LBRData& lbr_data);
+  void Rewind();
+  bool ReadData(void* data, size_t size);
+  bool ReadOldFileFormat(ETMBinaryMap& etm_data, LBRData& lbr_data);
+
+  const std::string input_filename_;
+  std::unique_ptr<FILE, decltype(&fclose)> input_fp_;
+  const std::string& input_str_;
+  size_t input_str_pos_ = 0;
+  bool compress_ = false;
+};
+
+bool DumpBranchListFile(std::string filename);
 
 // for testing
 std::string ETMBranchToProtoString(const std::vector<bool>& branch);
diff --git a/simpleperf/BranchListFile_test.cpp b/simpleperf/BranchListFile_test.cpp
index d7f9a6a5..b5c7ec60 100644
--- a/simpleperf/BranchListFile_test.cpp
+++ b/simpleperf/BranchListFile_test.cpp
@@ -17,6 +17,7 @@
 #include <gtest/gtest.h>
 
 #include "BranchListFile.h"
+#include "get_test_data.h"
 
 using namespace simpleperf;
 
@@ -34,3 +35,129 @@ TEST(BranchListFile, etm_branch_to_proto_string) {
     ASSERT_EQ(branch, branch2);
   }
 }
+
+static bool IsETMDataEqual(ETMBinaryMap& data1, ETMBinaryMap& data2) {
+  if (data1.size() != data2.size()) {
+    return false;
+  }
+  for (const auto& [key, binary1] : data1) {
+    auto it = data2.find(key);
+    if (it == data2.end()) {
+      return false;
+    }
+    ETMBinary& binary2 = it->second;
+    if (binary1.dso_type != binary2.dso_type) {
+      return false;
+    }
+    const UnorderedETMBranchMap& branch_map1 = binary1.branch_map;
+    const UnorderedETMBranchMap& branch_map2 = binary2.branch_map;
+    if (branch_map1.size() != branch_map2.size()) {
+      return false;
+    }
+    for (const auto& [addr, b_map1] : branch_map1) {
+      auto it2 = branch_map2.find(addr);
+      if (it2 == branch_map2.end()) {
+        return false;
+      }
+      const auto& b_map2 = it2->second;
+      if (b_map1.size() != b_map2.size()) {
+        return false;
+      }
+      for (const auto& [branch, count1] : b_map1) {
+        auto it3 = b_map2.find(branch);
+        if (it3 == b_map2.end()) {
+          return false;
+        }
+        if (count1 != it3->second) {
+          return false;
+        }
+      }
+    }
+  }
+  return true;
+}
+
+static bool IsLBRDataEqual(const LBRData& data1, const LBRData& data2) {
+  if (data1.samples.size() != data2.samples.size()) {
+    return false;
+  }
+  for (size_t i = 0; i < data1.samples.size(); i++) {
+    const LBRSample& sample1 = data1.samples[i];
+    const LBRSample& sample2 = data2.samples[i];
+    if (sample1.binary_id != sample2.binary_id) {
+      return false;
+    }
+    if (sample1.vaddr_in_file != sample2.vaddr_in_file) {
+      return false;
+    }
+    if (sample1.branches.size() != sample2.branches.size()) {
+      return false;
+    }
+    for (size_t j = 0; j < sample1.branches.size(); j++) {
+      const LBRBranch& b1 = sample1.branches[j];
+      const LBRBranch& b2 = sample2.branches[j];
+      if (b1.from_binary_id != b2.from_binary_id || b1.to_binary_id != b2.to_binary_id ||
+          b1.from_vaddr_in_file != b2.from_vaddr_in_file ||
+          b1.to_vaddr_in_file != b2.to_vaddr_in_file) {
+        return false;
+      }
+    }
+  }
+  return data1.binaries == data2.binaries;
+}
+
+// @CddTest = 6.1/C-0-2
+TEST(BranchListProtoReaderWriter, smoke) {
+  ETMBinaryMap etm_data;
+  ETMBinary& binary = etm_data[BinaryKey("fake_binary", BuildId())];
+  binary.dso_type = DSO_ELF_FILE;
+  UnorderedETMBranchMap& branch_map = binary.branch_map;
+  for (size_t addr = 0; addr <= 1024; addr++) {
+    auto& b_map = branch_map[addr];
+    std::vector<bool> branch1 = {true};
+    b_map[branch1] = 1;
+    std::vector<bool> branch2 = {true, false};
+    b_map[branch2] = 2;
+  }
+  LBRData lbr_data;
+  lbr_data.binaries.emplace_back(BinaryKey("binary1", BuildId()));
+  lbr_data.binaries.emplace_back(BinaryKey("binary2", BuildId()));
+  for (uint64_t from_addr = 0; from_addr <= 10; from_addr++) {
+    for (uint64_t to_addr = 100; to_addr <= 110; to_addr++) {
+      LBRBranch branch = {0, 1, from_addr, to_addr};
+      LBRSample sample = {0, from_addr, {branch}};
+      lbr_data.samples.emplace_back(sample);
+    }
+  }
+
+  TemporaryFile tmpfile;
+  close(tmpfile.fd);
+  for (size_t max_branches_per_message : {100, 100000000}) {
+    for (bool compress : {false, true}) {
+      auto writer =
+          BranchListProtoWriter::CreateForFile(tmpfile.path, compress, max_branches_per_message);
+      ASSERT_TRUE(writer);
+      ASSERT_TRUE(writer->Write(etm_data));
+      ASSERT_TRUE(writer->Write(lbr_data));
+      writer = nullptr;
+      auto reader = BranchListProtoReader::CreateForFile(tmpfile.path);
+      ASSERT_TRUE(reader);
+      ETMBinaryMap new_etm_data;
+      LBRData new_lbr_data;
+      ASSERT_TRUE(reader->Read(new_etm_data, new_lbr_data));
+      ASSERT_TRUE(IsETMDataEqual(etm_data, new_etm_data));
+      ASSERT_TRUE(IsLBRDataEqual(lbr_data, new_lbr_data));
+    }
+  }
+}
+
+// @CddTest = 6.1/C-0-2
+TEST(BranchListProtoReaderWriter, read_old_branch_list_file) {
+  std::string path = GetTestData("etm/old_branch_list.data");
+  auto reader = BranchListProtoReader::CreateForFile(path);
+  ASSERT_TRUE(reader);
+  ETMBinaryMap etm_data;
+  LBRData lbr_data;
+  ASSERT_TRUE(reader->Read(etm_data, lbr_data));
+  ASSERT_EQ(etm_data.size(), 1u);
+}
diff --git a/simpleperf/ETMDecoder.cpp b/simpleperf/ETMDecoder.cpp
index d8bf4878..cf77beab 100644
--- a/simpleperf/ETMDecoder.cpp
+++ b/simpleperf/ETMDecoder.cpp
@@ -937,50 +937,82 @@ class BranchDecoder {
 
 android::base::expected<void, std::string> ConvertETMBranchMapToInstrRanges(
     Dso* dso, const ETMBranchMap& branch_map, const ETMDecoder::InstrRangeCallbackFn& callback) {
-  ETMInstrRange instr_range;
-  instr_range.dso = dso;
-
   BranchDecoder decoder;
   if (auto result = decoder.Init(dso); !result.ok()) {
     return result;
   }
 
+  struct MapEntry {
+    bool valid = false;
+    bool end_with_branch = false;
+    bool end_with_direct_branch = false;
+    uint32_t end_instr_size = 0;
+    uint64_t end_addr = 0;
+    uint64_t branch_addr = 0;
+    uint64_t branch_taken_count = 0;
+    uint64_t branch_not_taken_count = 0;
+  };
+  std::unordered_map<uint64_t, MapEntry> cache;
+
   for (const auto& addr_p : branch_map) {
-    uint64_t start_addr = addr_p.first & ~1ULL;
-    bool is_thumb = addr_p.first & 1;
     for (const auto& branch_p : addr_p.second) {
       const std::vector<bool>& branch = branch_p.first;
       uint64_t count = branch_p.second;
-      decoder.SetAddr(start_addr, is_thumb);
-
+      uint64_t start_addr = addr_p.first & ~1ULL;
+      bool is_thumb = addr_p.first & 1;
       for (bool b : branch) {
-        ocsd_instr_info& instr = decoder.InstrInfo();
-        uint64_t from_addr = instr.instr_addr;
-        if (!decoder.FindNextBranch()) {
+        auto it = cache.find(start_addr);
+        if (it == cache.end()) {
+          MapEntry entry;
+          decoder.SetAddr(start_addr, is_thumb);
+          if (decoder.FindNextBranch()) {
+            ocsd_instr_info& instr = decoder.InstrInfo();
+            entry.valid = true;
+            entry.end_with_branch =
+                instr.type == OCSD_INSTR_BR || instr.type == OCSD_INSTR_BR_INDIRECT;
+            entry.end_with_direct_branch = instr.type == OCSD_INSTR_BR;
+            entry.end_addr = instr.instr_addr;
+            entry.end_instr_size = instr.instr_size;
+            // For OCSD_INSTR_BR_INDIRECT, instr.branch_addr points to old branch addresses.
+            // So only use instr.branch_addr for direct branch instructions.
+            entry.branch_addr = (entry.end_with_direct_branch ? instr.branch_addr : 0);
+          }
+          it = cache.emplace(start_addr, entry).first;
+        }
+        MapEntry& entry = it->second;
+        if (!entry.valid) {
           break;
         }
-        bool end_with_branch = instr.type == OCSD_INSTR_BR || instr.type == OCSD_INSTR_BR_INDIRECT;
-        bool branch_taken = end_with_branch && b;
-        instr_range.start_addr = from_addr;
-        instr_range.end_addr = instr.instr_addr;
-        if (instr.type == OCSD_INSTR_BR) {
-          instr_range.branch_to_addr = instr.branch_addr;
+        bool branch_taken = entry.end_with_branch && b;
+        // As in "Table D4-10 Meaning of Atom elements in AArch64 A64" of ARMv9 manual,
+        // for branch instructions, b == true means branch taken. But for other instructions
+        // (like ISB), CPU continus to execute following instructions.
+        if (branch_taken) {
+          entry.branch_taken_count += count;
+          start_addr = entry.branch_addr & ~1ULL;
+          is_thumb = entry.branch_addr & 1;
         } else {
-          instr_range.branch_to_addr = 0;
-        }
-        instr_range.branch_taken_count = branch_taken ? count : 0;
-        instr_range.branch_not_taken_count = branch_taken ? 0 : count;
-
-        callback(instr_range);
-
-        if (b) {
-          instr.instr_addr = instr.branch_addr;
-        } else {
-          instr.instr_addr += instr.instr_size;
+          entry.branch_not_taken_count += count;
+          start_addr = entry.end_addr + entry.end_instr_size;
         }
       }
     }
   }
+
+  for (auto& p : cache) {
+    uint64_t start_addr = p.first;
+    MapEntry& entry = p.second;
+    if (entry.valid) {
+      ETMInstrRange instr_range;
+      instr_range.start_addr = start_addr;
+      instr_range.end_addr = entry.end_addr;
+      instr_range.branch_to_addr = entry.branch_addr;
+      instr_range.branch_taken_count = entry.branch_taken_count;
+      instr_range.branch_not_taken_count = entry.branch_not_taken_count;
+      callback(instr_range);
+    }
+  }
+
   return {};
 }
 
diff --git a/simpleperf/ZstdUtil.cpp b/simpleperf/ZstdUtil.cpp
index 1fed444d..cd4fdb41 100644
--- a/simpleperf/ZstdUtil.cpp
+++ b/simpleperf/ZstdUtil.cpp
@@ -183,5 +183,31 @@ std::unique_ptr<Decompressor> CreateZstdDecompressor() {
   }
   return std::unique_ptr<Decompressor>(new ZstdDecompressor(std::move(dctx)));
 }
+bool ZstdCompress(const char* input_data, size_t input_size, std::string& output_data) {
+  std::unique_ptr<Compressor> compressor = CreateZstdCompressor();
+  CHECK(compressor != nullptr);
+  if (!compressor->AddInputData(input_data, input_size)) {
+    return false;
+  }
+  if (!compressor->FlushOutputData()) {
+    return false;
+  }
+  std::string_view output = compressor->GetOutputData();
+  output_data.clear();
+  output_data.insert(0, output.data(), output.size());
+  return true;
+}
+
+bool ZstdDecompress(const char* input_data, size_t input_size, std::string& output_data) {
+  std::unique_ptr<Decompressor> decompressor = CreateZstdDecompressor();
+  CHECK(decompressor != nullptr);
+  if (!decompressor->AddInputData(input_data, input_size)) {
+    return false;
+  }
+  std::string_view output = decompressor->GetOutputData();
+  output_data.clear();
+  output_data.insert(0, output.data(), output.size());
+  return true;
+}
 
 }  // namespace simpleperf
diff --git a/simpleperf/ZstdUtil.h b/simpleperf/ZstdUtil.h
index 9b9cd0e1..4b90f608 100644
--- a/simpleperf/ZstdUtil.h
+++ b/simpleperf/ZstdUtil.h
@@ -14,6 +14,7 @@
  * limitations under the License.
  */
 
+#pragma once
 #include <memory>
 #include <string_view>
 
@@ -50,4 +51,7 @@ class Decompressor {
 std::unique_ptr<Compressor> CreateZstdCompressor(size_t compression_level = 3);
 std::unique_ptr<Decompressor> CreateZstdDecompressor();
 
+bool ZstdCompress(const char* input_data, size_t input_size, std::string& output_data);
+bool ZstdDecompress(const char* input_data, size_t input_size, std::string& output_data);
+
 }  // namespace simpleperf
diff --git a/simpleperf/branch_list.proto b/simpleperf/branch_list.proto
index 6d6bfb17..706f411b 100644
--- a/simpleperf/branch_list.proto
+++ b/simpleperf/branch_list.proto
@@ -14,8 +14,18 @@
  * limitations under the License.
  */
 
-// The branch list file format is generated by the inject command. It contains
-// a single BranchList message.
+// The branch list file format is generated by the inject command. The new format is:
+// struct BranchListFile {
+//   char magic[24] = "simpleperf:EtmBranchList";
+//   uint32 version = 1;
+//   uint8 compressed;  // 1 if compressed, otherwise 0
+//   struct {
+//      uint32 msg_size;
+//      message BranchList msg;
+//   } msgs[];
+// };
+// The old format is a single BranchList message.
+//
 
 syntax = "proto3";
 
diff --git a/simpleperf/cmd_inject.cpp b/simpleperf/cmd_inject.cpp
index 381561e4..380b6468 100644
--- a/simpleperf/cmd_inject.cpp
+++ b/simpleperf/cmd_inject.cpp
@@ -21,6 +21,7 @@
 #include <memory>
 #include <optional>
 #include <string>
+#include <thread>
 
 #include <android-base/parseint.h>
 #include <android-base/strings.h>
@@ -28,6 +29,7 @@
 #include "BranchListFile.h"
 #include "ETMDecoder.h"
 #include "RegEx.h"
+#include "ZstdUtil.h"
 #include "command.h"
 #include "record_file.h"
 #include "system/extras/simpleperf/branch_list.pb.h"
@@ -219,14 +221,17 @@ class PerfDataReader {
 
 class ETMThreadTreeWithFilter : public ETMThreadTree {
  public:
-  ETMThreadTreeWithFilter(ThreadTree& thread_tree, std::optional<int>& exclude_pid)
-      : thread_tree_(thread_tree), exclude_pid_(exclude_pid) {}
+  ETMThreadTreeWithFilter(ThreadTree& thread_tree, std::optional<int>& exclude_pid,
+                          const std::vector<std::unique_ptr<RegEx>>& exclude_process_names)
+      : thread_tree_(thread_tree),
+        exclude_pid_(exclude_pid),
+        exclude_process_names_(exclude_process_names) {}
 
   void DisableThreadExitRecords() override { thread_tree_.DisableThreadExitRecords(); }
 
   const ThreadEntry* FindThread(int tid) override {
     const ThreadEntry* thread = thread_tree_.FindThread(tid);
-    if (thread != nullptr && exclude_pid_ && thread->pid == exclude_pid_) {
+    if (thread != nullptr && ShouldExcludePid(thread->pid)) {
       return nullptr;
     }
     return thread;
@@ -235,18 +240,37 @@ class ETMThreadTreeWithFilter : public ETMThreadTree {
   const MapSet& GetKernelMaps() override { return thread_tree_.GetKernelMaps(); }
 
  private:
+  bool ShouldExcludePid(int pid) {
+    if (exclude_pid_ && pid == exclude_pid_) {
+      return true;
+    }
+    if (!exclude_process_names_.empty()) {
+      const ThreadEntry* process = thread_tree_.FindThread(pid);
+      if (process != nullptr) {
+        for (const auto& regex : exclude_process_names_) {
+          if (regex->Search(process->comm)) {
+            return true;
+          }
+        }
+      }
+    }
+    return false;
+  }
+
   ThreadTree& thread_tree_;
   std::optional<int>& exclude_pid_;
+  const std::vector<std::unique_ptr<RegEx>>& exclude_process_names_;
 };
 
 // Read perf.data with ETM data and generate AutoFDO or branch list data.
 class ETMPerfDataReader : public PerfDataReader {
  public:
   ETMPerfDataReader(std::unique_ptr<RecordFileReader> reader, bool exclude_perf,
+                    const std::vector<std::unique_ptr<RegEx>>& exclude_process_names,
                     const RegEx* binary_name_regex, ETMDumpOption etm_dump_option)
       : PerfDataReader(std::move(reader), exclude_perf, binary_name_regex),
         etm_dump_option_(etm_dump_option),
-        etm_thread_tree_(thread_tree_, exclude_pid_) {}
+        etm_thread_tree_(thread_tree_, exclude_pid_, exclude_process_names) {}
 
   bool Read() override {
     if (reader_->HasFeature(PerfFileFormat::FEAT_ETM_BRANCH_LIST)) {
@@ -513,22 +537,20 @@ class LBRPerfDataReader : public PerfDataReader {
 // Read a protobuf file specified by branch_list.proto.
 class BranchListReader {
  public:
-  BranchListReader(const std::string& filename, const RegEx* binary_name_regex)
+  BranchListReader(std::string_view filename, const RegEx* binary_name_regex)
       : filename_(filename), binary_filter_(binary_name_regex) {}
 
   void AddCallback(const ETMBinaryCallback& callback) { etm_binary_callback_ = callback; }
   void AddCallback(const LBRDataCallback& callback) { lbr_data_callback_ = callback; }
 
   bool Read() {
-    std::string s;
-    if (!android::base::ReadFileToString(filename_, &s)) {
-      PLOG(ERROR) << "failed to read " << filename_;
+    auto reader = BranchListProtoReader::CreateForFile(filename_);
+    if (!reader) {
       return false;
     }
     ETMBinaryMap etm_data;
     LBRData lbr_data;
-    if (!ParseBranchListData(s, etm_data, lbr_data)) {
-      PLOG(ERROR) << "file is in wrong format: " << filename_;
+    if (!reader->Read(etm_data, lbr_data)) {
       return false;
     }
     if (etm_binary_callback_ && !etm_data.empty()) {
@@ -618,11 +640,10 @@ class ETMBranchListToAutoFDOConverter {
     autofdo_binary->executable_segments = GetExecutableSegments(dso.get());
 
     if (dso->type() == DSO_KERNEL) {
-      ModifyBranchMapForKernel(dso.get(), key.kernel_start_addr, binary);
+      CHECK_EQ(key.kernel_start_addr, 0);
     }
 
     auto process_instr_range = [&](const ETMInstrRange& range) {
-      CHECK_EQ(range.dso, dso.get());
       autofdo_binary->AddInstrRange(range);
     };
 
@@ -645,21 +666,6 @@ class ETMBranchListToAutoFDOConverter {
     return GetBuildIdFromDsoPath(dso->GetDebugFilePath(), &build_id) &&
            build_id == expected_build_id;
   }
-
-  void ModifyBranchMapForKernel(Dso* dso, uint64_t kernel_start_addr, ETMBinary& binary) {
-    if (kernel_start_addr == 0) {
-      // vmlinux has been provided when generating branch lists. Addresses in branch lists are
-      // already vaddrs in vmlinux.
-      return;
-    }
-    // Addresses are still kernel ip addrs in memory. Need to convert them to vaddrs in vmlinux.
-    UnorderedETMBranchMap new_branch_map;
-    for (auto& p : binary.branch_map) {
-      uint64_t vaddr_in_file = dso->IpToVaddrInFile(p.first, kernel_start_addr, 0);
-      new_branch_map[vaddr_in_file] = std::move(p.second);
-    }
-    binary.branch_map = std::move(new_branch_map);
-  }
 };
 
 // Write instruction ranges to a file in AutoFDO text format.
@@ -857,6 +863,13 @@ struct BranchListMerger {
     }
   }
 
+  void Merge(BranchListMerger& other) {
+    for (auto& p : other.GetETMData()) {
+      AddETMBinary(p.first, p.second);
+    }
+    AddLBRData(other.GetLBRData());
+  }
+
   ETMBinaryMap& GetETMData() { return etm_data_; }
 
   LBRData& GetLBRData() { return lbr_data_; }
@@ -867,28 +880,139 @@ struct BranchListMerger {
   std::unordered_map<BinaryKey, uint32_t, BinaryKeyHash> lbr_binary_id_map_;
 };
 
-// Write branch lists to a protobuf file specified by branch_list.proto.
-static bool WriteBranchListFile(const std::string& output_filename, const ETMBinaryMap& etm_data,
-                                const LBRData& lbr_data) {
-  std::string s;
-  if (!etm_data.empty()) {
-    if (!ETMBinaryMapToString(etm_data, s)) {
-      return false;
+// Read multiple branch list files and merge them using BranchListMerger.
+class BranchListMergedReader {
+ public:
+  BranchListMergedReader(bool allow_mismatched_build_id, const RegEx* binary_name_regex,
+                         size_t jobs)
+      : allow_mismatched_build_id_(allow_mismatched_build_id),
+        binary_name_regex_(binary_name_regex),
+        jobs_(jobs) {}
+
+  std::unique_ptr<BranchListMerger> Read(const std::vector<std::string>& input_filenames) {
+    std::mutex input_file_mutex;
+    size_t input_file_index = 0;
+    auto get_input_file = [&]() -> std::string_view {
+      std::lock_guard<std::mutex> guard(input_file_mutex);
+      if (input_file_index == input_filenames.size()) {
+        return "";
+      }
+      if ((input_file_index + 1) % 100 == 0) {
+        LOG(VERBOSE) << "Read input file " << (input_file_index + 1) << "/"
+                     << input_filenames.size();
+      }
+      return input_filenames[input_file_index++];
+    };
+
+    std::atomic_size_t failed_to_read_count = 0;
+    size_t thread_count = std::min(jobs_, input_filenames.size()) - 1;
+    std::vector<BranchListMerger> thread_mergers(thread_count);
+    std::vector<std::unique_ptr<std::thread>> threads;
+
+    for (size_t i = 0; i < thread_count; i++) {
+      threads.emplace_back(new std::thread([&, i]() {
+        ReadInThreadFunction(get_input_file, thread_mergers[i], failed_to_read_count);
+      }));
     }
-  } else if (!lbr_data.samples.empty()) {
-    if (!LBRDataToString(lbr_data, s)) {
-      return false;
+    auto merger = std::make_unique<BranchListMerger>();
+    ReadInThreadFunction(get_input_file, *merger, failed_to_read_count);
+    for (size_t i = 0; i < thread_count; i++) {
+      threads[i]->join();
+      merger->Merge(thread_mergers[i]);
+    }
+    if (failed_to_read_count == input_filenames.size()) {
+      LOG(ERROR) << "No valid input file";
+      return nullptr;
+    }
+    return merger;
+  }
+
+ private:
+  void ReadInThreadFunction(const std::function<std::string_view()>& get_input_file,
+                            BranchListMerger& merger, std::atomic_size_t& failed_to_read_count) {
+    auto etm_callback = [&](const BinaryKey& key, ETMBinary& binary) {
+      BinaryKey new_key = key;
+      if (allow_mismatched_build_id_) {
+        new_key.build_id = BuildId();
+      }
+      if (binary.dso_type == DsoType::DSO_KERNEL) {
+        ModifyBranchMapForKernel(new_key, binary);
+      }
+      merger.AddETMBinary(new_key, binary);
+    };
+    auto lbr_callback = [&](LBRData& lbr_data) {
+      if (allow_mismatched_build_id_) {
+        for (BinaryKey& key : lbr_data.binaries) {
+          key.build_id = BuildId();
+        }
+      }
+      merger.AddLBRData(lbr_data);
+    };
+    while (true) {
+      std::string_view input_file = get_input_file();
+      if (input_file.empty()) {
+        break;
+      }
+      BranchListReader reader(input_file, binary_name_regex_);
+      reader.AddCallback(etm_callback);
+      reader.AddCallback(lbr_callback);
+      if (!reader.Read()) {
+        failed_to_read_count++;
+      }
     }
-  } else {
-    // Don't produce empty output file.
-    LOG(INFO) << "Skip empty output file.";
-    unlink(output_filename.c_str());
-    return true;
   }
-  if (!android::base::WriteStringToFile(s, output_filename)) {
-    PLOG(ERROR) << "failed to write to " << output_filename;
+
+  void ModifyBranchMapForKernel(BinaryKey& key, ETMBinary& binary) {
+    if (key.kernel_start_addr == 0) {
+      // vmlinux has been provided when generating branch lists. Addresses in branch lists are
+      // already vaddrs in vmlinux.
+      return;
+    }
+    {
+      std::lock_guard<std::mutex> guard(kernel_dso_mutex_);
+      if (!kernel_dso_) {
+        BuildId build_id = key.build_id;
+        kernel_dso_ = Dso::CreateDsoWithBuildId(binary.dso_type, key.path, build_id);
+        if (!kernel_dso_) {
+          return;
+        }
+        // Call IpToVaddrInFile once to initialize kernel start addr from vmlinux.
+        kernel_dso_->IpToVaddrInFile(0, key.kernel_start_addr, 0);
+      }
+    }
+    // Addresses are still kernel ip addrs in memory. Need to convert them to vaddrs in vmlinux.
+    UnorderedETMBranchMap new_branch_map;
+    for (auto& p : binary.branch_map) {
+      uint64_t vaddr_in_file = kernel_dso_->IpToVaddrInFile(p.first, key.kernel_start_addr, 0);
+      new_branch_map[vaddr_in_file] = std::move(p.second);
+    }
+    binary.branch_map = std::move(new_branch_map);
+    key.kernel_start_addr = 0;
+  }
+
+  const bool allow_mismatched_build_id_;
+  const RegEx* binary_name_regex_;
+  size_t jobs_;
+  std::unique_ptr<Dso> kernel_dso_;
+  std::mutex kernel_dso_mutex_;
+};
+
+// Write branch lists to a protobuf file specified by branch_list.proto.
+static bool WriteBranchListFile(const std::string& output_filename, const ETMBinaryMap& etm_data,
+                                const LBRData& lbr_data, bool compress) {
+  auto writer = BranchListProtoWriter::CreateForFile(output_filename, compress);
+  if (!writer) {
     return false;
   }
+  if (!etm_data.empty()) {
+    return writer->Write(etm_data);
+  }
+  if (!lbr_data.samples.empty()) {
+    return writer->Write(lbr_data);
+  }
+  // Don't produce empty output file.
+  LOG(INFO) << "Skip empty output file.";
+  unlink(output_filename.c_str());
   return true;
 }
 
@@ -912,8 +1036,13 @@ class InjectCommand : public Command {
 "                             Default is autofdo.\n"
 "--dump-etm type1,type2,...   Dump etm data. A type is one of raw, packet and element.\n"
 "--exclude-perf               Exclude trace data for the recording process.\n"
+"--exclude-process-name process_name_regex      Exclude data for processes with name containing\n"
+"                                               the regular expression.\n"
 "--symdir <dir>               Look for binaries in a directory recursively.\n"
 "--allow-mismatched-build-id  Allow mismatched build ids when searching for debug binaries.\n"
+"-j <jobs>                    Use multiple threads to process branch list files.\n"
+"-z                           Compress branch-list output\n"
+"--dump <file>                Dump a branch list file.\n"
 "\n"
 "Examples:\n"
 "1. Generate autofdo text output.\n"
@@ -930,6 +1059,9 @@ class InjectCommand : public Command {
     if (!ParseOptions(args)) {
       return false;
     }
+    if (!dump_branch_list_file_.empty()) {
+      return DumpBranchListFile(dump_branch_list_file_);
+    }
 
     CHECK(!input_filenames_.empty());
     if (IsPerfDataFile(input_filenames_[0])) {
@@ -958,12 +1090,16 @@ class InjectCommand : public Command {
     const OptionFormatMap option_formats = {
         {"--allow-mismatched-build-id", {OptionValueType::NONE, OptionType::SINGLE}},
         {"--binary", {OptionValueType::STRING, OptionType::SINGLE}},
+        {"--dump", {OptionValueType::STRING, OptionType::SINGLE}},
         {"--dump-etm", {OptionValueType::STRING, OptionType::SINGLE}},
         {"--exclude-perf", {OptionValueType::NONE, OptionType::SINGLE}},
+        {"--exclude-process-name", {OptionValueType::STRING, OptionType::MULTIPLE}},
         {"-i", {OptionValueType::STRING, OptionType::MULTIPLE}},
+        {"-j", {OptionValueType::UINT, OptionType::SINGLE}},
         {"-o", {OptionValueType::STRING, OptionType::SINGLE}},
         {"--output", {OptionValueType::STRING, OptionType::SINGLE}},
         {"--symdir", {OptionValueType::STRING, OptionType::MULTIPLE}},
+        {"-z", {OptionValueType::NONE, OptionType::SINGLE}},
     };
     OptionValueMap options;
     std::vector<std::pair<OptionName, OptionValue>> ordered_options;
@@ -972,6 +1108,7 @@ class InjectCommand : public Command {
     }
 
     if (options.PullBoolValue("--allow-mismatched-build-id")) {
+      allow_mismatched_build_id_ = true;
       Dso::AllowMismatchedBuildId();
     }
     if (auto value = options.PullValue("--binary"); value) {
@@ -980,12 +1117,20 @@ class InjectCommand : public Command {
         return false;
       }
     }
+    options.PullStringValue("--dump", &dump_branch_list_file_);
     if (auto value = options.PullValue("--dump-etm"); value) {
       if (!ParseEtmDumpOption(value->str_value, &etm_dump_option_)) {
         return false;
       }
     }
     exclude_perf_ = options.PullBoolValue("--exclude-perf");
+    for (const std::string& value : options.PullStringValues("--exclude-process-name")) {
+      std::unique_ptr<RegEx> regex = RegEx::Create(value);
+      if (regex == nullptr) {
+        return false;
+      }
+      exclude_process_names_.emplace_back(std::move(regex));
+    }
 
     for (const OptionValue& value : options.PullValues("-i")) {
       std::vector<std::string> files = android::base::Split(value.str_value, ",");
@@ -1002,6 +1147,9 @@ class InjectCommand : public Command {
     if (input_filenames_.empty()) {
       input_filenames_.emplace_back("perf.data");
     }
+    if (!options.PullUintValue("-j", &jobs_, 1)) {
+      return false;
+    }
     options.PullStringValue("-o", &output_filename_);
     if (auto value = options.PullValue("--output"); value) {
       const std::string& output = value->str_value;
@@ -1027,6 +1175,7 @@ class InjectCommand : public Command {
       // prevent cleaning from happening.
       placeholder_dso_ = Dso::CreateDso(DSO_UNKNOWN_FILE, "unknown");
     }
+    compress_ = options.PullBoolValue("-z");
     CHECK(options.values.empty());
     return true;
   }
@@ -1063,7 +1212,8 @@ class InjectCommand : public Command {
       std::unique_ptr<PerfDataReader> reader;
       if (data_type == "etm") {
         reader.reset(new ETMPerfDataReader(std::move(file_reader), exclude_perf_,
-                                           binary_name_regex_.get(), etm_dump_option_));
+                                           exclude_process_names_, binary_name_regex_.get(),
+                                           etm_dump_option_));
       } else if (data_type == "lbr") {
         reader.reset(
             new LBRPerfDataReader(std::move(file_reader), exclude_perf_, binary_name_regex_.get()));
@@ -1109,29 +1259,22 @@ class InjectCommand : public Command {
     if (!ReadPerfDataFiles(reader_callback)) {
       return false;
     }
-    return WriteBranchListFile(output_filename_, merger.GetETMData(), merger.GetLBRData());
+    return WriteBranchListFile(output_filename_, merger.GetETMData(), merger.GetLBRData(),
+                               compress_);
   }
 
   bool ConvertBranchListToAutoFDO() {
     // Step1 : Merge branch lists from all input files.
-    BranchListMerger merger;
-    auto etm_callback = [&](const BinaryKey& key, ETMBinary& binary) {
-      merger.AddETMBinary(key, binary);
-    };
-    auto lbr_callback = [&](LBRData& lbr_data) { merger.AddLBRData(lbr_data); };
-    for (const auto& input_filename : input_filenames_) {
-      BranchListReader reader(input_filename, binary_name_regex_.get());
-      reader.AddCallback(etm_callback);
-      reader.AddCallback(lbr_callback);
-      if (!reader.Read()) {
-        return false;
-      }
+    BranchListMergedReader reader(allow_mismatched_build_id_, binary_name_regex_.get(), jobs_);
+    std::unique_ptr<BranchListMerger> merger = reader.Read(input_filenames_);
+    if (!merger) {
+      return false;
     }
 
     // Step2: Convert ETMBinary and LBRData to AutoFDOBinaryInfo.
     AutoFDOWriter autofdo_writer;
     ETMBranchListToAutoFDOConverter converter;
-    for (auto& p : merger.GetETMData()) {
+    for (auto& p : merger->GetETMData()) {
       const BinaryKey& key = p.first;
       ETMBinary& binary = p.second;
       std::unique_ptr<AutoFDOBinaryInfo> autofdo_binary = converter.Convert(key, binary);
@@ -1141,8 +1284,8 @@ class InjectCommand : public Command {
         autofdo_writer.AddAutoFDOBinary(BinaryKey(key.path, key.build_id), *autofdo_binary);
       }
     }
-    if (!merger.GetLBRData().samples.empty()) {
-      LBRData& lbr_data = merger.GetLBRData();
+    if (!merger->GetLBRData().samples.empty()) {
+      LBRData& lbr_data = merger->GetLBRData();
       std::optional<std::vector<AutoFDOBinaryInfo>> binaries = ConvertLBRDataToAutoFDO(lbr_data);
       if (!binaries) {
         return false;
@@ -1169,29 +1312,27 @@ class InjectCommand : public Command {
 
   bool ConvertBranchListToBranchList() {
     // Step1 : Merge branch lists from all input files.
-    BranchListMerger merger;
-    auto etm_callback = [&](const BinaryKey& key, ETMBinary& binary) {
-      merger.AddETMBinary(key, binary);
-    };
-    auto lbr_callback = [&](LBRData& lbr_data) { merger.AddLBRData(lbr_data); };
-    for (const auto& input_filename : input_filenames_) {
-      BranchListReader reader(input_filename, binary_name_regex_.get());
-      reader.AddCallback(etm_callback);
-      reader.AddCallback(lbr_callback);
-      if (!reader.Read()) {
-        return false;
-      }
+    BranchListMergedReader reader(allow_mismatched_build_id_, binary_name_regex_.get(), jobs_);
+    std::unique_ptr<BranchListMerger> merger = reader.Read(input_filenames_);
+    if (!merger) {
+      return false;
     }
     // Step2: Write ETMBinary.
-    return WriteBranchListFile(output_filename_, merger.GetETMData(), merger.GetLBRData());
+    return WriteBranchListFile(output_filename_, merger->GetETMData(), merger->GetLBRData(),
+                               compress_);
   }
 
   std::unique_ptr<RegEx> binary_name_regex_;
   bool exclude_perf_ = false;
+  std::vector<std::unique_ptr<RegEx>> exclude_process_names_;
   std::vector<std::string> input_filenames_;
   std::string output_filename_ = "perf_inject.data";
   OutputFormat output_format_ = OutputFormat::AutoFDO;
   ETMDumpOption etm_dump_option_;
+  bool compress_ = false;
+  bool allow_mismatched_build_id_ = false;
+  size_t jobs_ = 1;
+  std::string dump_branch_list_file_;
 
   std::unique_ptr<Dso> placeholder_dso_;
 };
diff --git a/simpleperf/cmd_inject_test.cpp b/simpleperf/cmd_inject_test.cpp
index c8202ac9..8ecdec20 100644
--- a/simpleperf/cmd_inject_test.cpp
+++ b/simpleperf/cmd_inject_test.cpp
@@ -107,6 +107,16 @@ TEST(cmd_inject, output_option) {
   CheckMatchingExpectedData("perf_inject_bolt.data", bolt_data);
 }
 
+// @CddTest = 6.1/C-0-2
+TEST(cmd_inject, compress_option) {
+  TemporaryFile tmpfile;
+  close(tmpfile.release());
+  ASSERT_TRUE(RunInjectCmd({"--output", "branch-list", "-z", "-o", tmpfile.path}));
+  std::string autofdo_data;
+  ASSERT_TRUE(RunInjectCmd({"-i", tmpfile.path, "--output", "autofdo"}, &autofdo_data));
+  CheckMatchingExpectedData("perf_inject.data", autofdo_data);
+}
+
 // @CddTest = 6.1/C-0-2
 TEST(cmd_inject, skip_empty_output_file) {
   TemporaryFile tmpfile;
@@ -188,6 +198,13 @@ TEST(cmd_inject, merge_branch_list_files) {
   std::string autofdo_data;
   ASSERT_TRUE(RunInjectCmd({"-i", tmpfile2.path, "--output", "autofdo"}, &autofdo_data));
   ASSERT_NE(autofdo_data.find("106c->1074:200"), std::string::npos);
+
+  // Accept invalid branch list files.
+  TemporaryFile tmpfile3;
+  close(tmpfile3.release());
+  ASSERT_TRUE(android::base::WriteStringToFile("bad content", tmpfile3.path));
+  ASSERT_TRUE(RunInjectCmd({"-i", std::string(tmpfile.path) + "," + tmpfile3.path, "--output",
+                            "branch-list", "-o", tmpfile2.path}));
 }
 
 // @CddTest = 6.1/C-0-2
@@ -249,15 +266,13 @@ TEST(cmd_inject, read_lbr_data) {
 
   const std::string perf_data_path = GetTestData("lbr/perf_lbr.data");
   std::string data;
-  /*
   ASSERT_TRUE(get_autofdo_data({"-i", perf_data_path}, &data));
   data.erase(std::remove(data.begin(), data.end(), '\r'), data.end());
-  */
 
   std::string expected_data;
   ASSERT_TRUE(android::base::ReadFileToString(
       GetTestData(std::string("lbr") + OS_PATH_SEPARATOR + "inject_lbr.data"), &expected_data));
-  // ASSERT_EQ(data, expected_data);
+  ASSERT_EQ(data, expected_data);
 
   // Convert perf.data to branch_list.proto format.
   // Then convert branch_list.proto format to AutoFDO text format.
@@ -300,3 +315,58 @@ TEST(cmd_inject, inject_small_binary) {
   ASSERT_TRUE(RunInjectCmd({"-i", perf_data, "--output", "bolt"}, &data));
   CheckMatchingExpectedData("perf_inject_small_bolt.data", data);
 }
+
+// @CddTest = 6.1/C-0-2
+TEST(cmd_inject, j_option) {
+  TemporaryFile tmpfile;
+  close(tmpfile.release());
+  ASSERT_TRUE(RunInjectCmd({"--output", "branch-list", "-o", tmpfile.path}));
+  std::string autofdo_data;
+  ASSERT_TRUE(RunInjectCmd(
+      {"-i", std::string(tmpfile.path) + "," + tmpfile.path, "--output", "autofdo", "-j", "1"},
+      &autofdo_data));
+  ASSERT_NE(autofdo_data.find("106c->1074:200"), std::string::npos);
+
+  ASSERT_TRUE(RunInjectCmd(
+      {"-i", std::string(tmpfile.path) + "," + tmpfile.path, "--output", "autofdo", "-j", "2"},
+      &autofdo_data));
+  ASSERT_NE(autofdo_data.find("106c->1074:200"), std::string::npos);
+
+  // Invalid job count.
+  ASSERT_FALSE(RunInjectCmd(
+      {"-i", std::string(tmpfile.path) + "," + tmpfile.path, "--output", "autofdo", "-j", "0"},
+      &autofdo_data));
+}
+
+// @CddTest = 6.1/C-0-2
+TEST(cmd_inject, dump_option) {
+  TemporaryFile tmpfile;
+  close(tmpfile.release());
+  ASSERT_TRUE(RunInjectCmd({"--output", "branch-list", "-o", tmpfile.path}));
+
+  CaptureStdout capture;
+  ASSERT_TRUE(capture.Start());
+  ASSERT_TRUE(InjectCmd()->Run({"--dump", tmpfile.path}));
+  std::string data = capture.Finish();
+  ASSERT_NE(data.find("binary[0].build_id: 0x0c9a20bf9c009d0e4e8bbf9fad0300ae00000000"),
+            std::string::npos);
+
+  ASSERT_TRUE(RunInjectCmd(
+      {"--output", "branch-list", "-o", tmpfile.path, "-i", GetTestData("lbr/perf_lbr.data")}));
+
+  ASSERT_TRUE(capture.Start());
+  ASSERT_TRUE(InjectCmd()->Run({"--dump", tmpfile.path}));
+  data = capture.Finish();
+  ASSERT_NE(data.find("binary[0].path: /home/yabinc/lbr_test_loop"), std::string::npos);
+}
+
+// @CddTest = 6.1/C-0-2
+TEST(cmd_inject, exclude_process_name_option) {
+  TemporaryFile tmpfile;
+  close(tmpfile.release());
+  ASSERT_TRUE(RunInjectCmd(
+      {"--output", "branch-list", "--exclude-process-name", "etm_test_loop", "-o", tmpfile.path}));
+  struct stat st;
+  ASSERT_EQ(stat(tmpfile.path, &st), -1);
+  ASSERT_EQ(errno, ENOENT);
+}
diff --git a/simpleperf/cmd_list.cpp b/simpleperf/cmd_list.cpp
index 926b7f7e..f6a474d1 100644
--- a/simpleperf/cmd_list.cpp
+++ b/simpleperf/cmd_list.cpp
@@ -27,6 +27,7 @@
 #include <android-base/logging.h>
 
 #include "ETMRecorder.h"
+#include "RegEx.h"
 #include "command.h"
 #include "environment.h"
 #include "event_attr.h"
@@ -39,9 +40,13 @@ namespace simpleperf {
 extern std::unordered_map<std::string, std::unordered_set<int>> cpu_supported_raw_events;
 
 #if defined(__aarch64__) || defined(__arm__)
-extern std::unordered_map<uint64_t, std::string> arm64_cpuid_to_name;
+extern std::unordered_map<uint64_t, std::string> cpuid_to_name;
 #endif  // defined(__aarch64__) || defined(__arm__)
 
+#if defined(__riscv)
+extern std::map<std::tuple<uint64_t, std::string, std::string>, std::string> cpuid_to_name;
+#endif  // defined(__riscv)
+
 namespace {
 
 struct RawEventTestThreadArg {
@@ -76,24 +81,50 @@ struct RawEventSupportStatus {
   std::vector<int> may_supported_cpus;
 };
 
+#if defined(__riscv)
+std::string to_hex_string(uint64_t value) {
+  std::stringstream stream;
+  stream << "0x" << std::hex << value;
+  return stream.str();
+}
+
+auto find_cpu_name(
+    const std::tuple<uint64_t, uint64_t, uint64_t>& cpu_id,
+    const std::map<std::tuple<uint64_t, std::string, std::string>, std::string>& cpuid_to_name) {
+  // cpu_id: mvendorid, marchid, mimpid
+  // cpuid_to_name: mvendorid, marchid regex, mimpid regex
+
+  std::string marchid_hex = to_hex_string(get<1>(cpu_id));
+  std::string mimpid_hex = to_hex_string(get<2>(cpu_id));
+  uint64_t mvendorid = std::get<0>(cpu_id);
+
+  // Search the first entry that matches mvendorid
+  auto it = cpuid_to_name.lower_bound({mvendorid, "", ""});
+
+  // Search the iterator of correct regex for current CPU from entries with same mvendorid
+  for (; it != cpuid_to_name.end() && std::get<0>(it->first) == mvendorid; ++it) {
+    const auto& [_, marchid_regex, mimpid_regex] = it->first;
+    if (RegEx::Create(marchid_regex)->Match(marchid_hex) &&
+        RegEx::Create(mimpid_regex)->Match(mimpid_hex)) {
+      break;
+    }
+  }
+
+  return it;
+}
+#endif  // defined(__riscv)
+
 class RawEventSupportChecker {
  public:
   bool Init() {
-#if defined(__aarch64__) || defined(__arm__)
-    cpu_models_ = GetARMCpuModels();
+    cpu_models_ = GetCpuModels();
     if (cpu_models_.empty()) {
       LOG(ERROR) << "can't get device cpu info";
       return false;
     }
     for (const auto& model : cpu_models_) {
-      uint64_t cpu_id = (static_cast<uint64_t>(model.implementer) << 32) | model.partnum;
-      if (auto it = arm64_cpuid_to_name.find(cpu_id); it != arm64_cpuid_to_name.end()) {
-        cpu_model_names_.push_back(it->second);
-      } else {
-        cpu_model_names_.push_back("");
-      }
+      cpu_model_names_.push_back(GetCpuModelName(model));
     }
-#endif  // defined(__aarch64__) || defined(__arm__)
     return true;
   }
 
@@ -106,19 +137,33 @@ class RawEventSupportChecker {
     }
 
     for (size_t i = 0; i < cpu_models_.size(); ++i) {
-      const ARMCpuModel& model = cpu_models_[i];
+      const CpuModel& model = cpu_models_[i];
       const std::string& model_name = cpu_model_names_[i];
+      bool got_status = false;
       bool supported = false;
       bool may_supported = false;
-      if (!required_cpu_model.empty()) {
-        // This is a cpu model specific event, only supported on required_cpu_model.
-        supported = model_name == required_cpu_model;
-      } else if (!model_name.empty()) {
-        // We know events supported on this cpu model.
-        auto it = cpu_supported_raw_events.find(model_name);
-        CHECK(it != cpu_supported_raw_events.end()) << "no events configuration for " << model_name;
-        supported = it->second.count(event_type.config) > 0;
-      } else {
+
+      if (model.arch == "arm") {
+        if (!required_cpu_model.empty()) {
+          // This is a cpu model specific event, only supported on required_cpu_model.
+          supported = model_name == required_cpu_model;
+          got_status = true;
+        } else if (!model_name.empty()) {
+          // We know events supported on this cpu model.
+          auto it = cpu_supported_raw_events.find(model_name);
+          CHECK(it != cpu_supported_raw_events.end())
+              << "no events configuration for " << model_name;
+          supported = it->second.count(event_type.config) > 0;
+          got_status = true;
+        }
+      } else if (model.arch == "x86") {
+        if (event_type.limited_arch != model_name) {
+          supported = false;
+          got_status = true;
+        }
+      }
+
+      if (!got_status) {
         // We need to test the event support status.
         TestEventSupportOnCpu(event_type, model.cpus[0], supported, may_supported);
       }
@@ -135,6 +180,32 @@ class RawEventSupportChecker {
   }
 
  private:
+  std::string GetCpuModelName(const CpuModel& model) {
+#if defined(__aarch64__) || defined(__arm__)
+    uint64_t cpu_id =
+        (static_cast<uint64_t>(model.arm_data.implementer) << 32) | model.arm_data.partnum;
+    auto it = cpuid_to_name.find(cpu_id);
+    if (it != cpuid_to_name.end()) {
+      return it->second;
+    }
+#elif defined(__riscv)
+    std::tuple<uint64_t, uint64_t, uint64_t> cpu_id = {
+        model.riscv_data.mvendorid, model.riscv_data.marchid, model.riscv_data.mimpid};
+    auto it = find_cpu_name(cpu_id, cpuid_to_name);
+    if (it != cpuid_to_name.end()) {
+      return it->second;
+    }
+#elif defined(__i386__) || defined(__x86_64__)
+    if (model.x86_data.vendor_id == "GenuineIntel") {
+      return "x86-intel";
+    }
+    if (model.x86_data.vendor_id == "AuthenticAMD") {
+      return "x86-amd";
+    }
+#endif  // defined(__i386__) || defined(__x86_64__)
+    return "";
+  }
+
   void TestEventSupportOnCpu(const EventType& event_type, int cpu, bool& supported,
                              bool& may_supported) {
     // Because the kernel may not check whether the raw event is supported by the cpu pmu.
@@ -171,7 +242,8 @@ class RawEventSupportChecker {
     }
   }
 
-  std::vector<ARMCpuModel> cpu_models_;
+  std::vector<CpuModel> cpu_models_;
+
   std::vector<std::string> cpu_model_names_;
 };
 
@@ -318,22 +390,28 @@ bool ListCommand::Run(const std::vector<std::string>& args) {
   }
 
   static std::map<std::string, std::pair<std::string, std::function<bool(const EventType&)>>>
-      type_map =
-  { {"hw", {"hardware events", [](const EventType& e) { return e.type == PERF_TYPE_HARDWARE; }}},
-    {"sw", {"software events", [](const EventType& e) { return e.type == PERF_TYPE_SOFTWARE; }}},
-    {"cache", {"hw-cache events", [](const EventType& e) { return e.type == PERF_TYPE_HW_CACHE; }}},
-    {"raw",
-     {"raw events provided by cpu pmu",
-      [](const EventType& e) { return e.type == PERF_TYPE_RAW; }}},
-    {"tracepoint",
-     {"tracepoint events", [](const EventType& e) { return e.type == PERF_TYPE_TRACEPOINT; }}},
+      type_map = {
+          {"hw",
+           {"hardware events", [](const EventType& e) { return e.type == PERF_TYPE_HARDWARE; }}},
+          {"sw",
+           {"software events", [](const EventType& e) { return e.type == PERF_TYPE_SOFTWARE; }}},
+          {"cache",
+           {"hw-cache events", [](const EventType& e) { return e.type == PERF_TYPE_HW_CACHE; }}},
+          {"raw",
+           {"raw events provided by cpu pmu",
+            [](const EventType& e) { return e.type == PERF_TYPE_RAW; }}},
+          {"tracepoint",
+           {"tracepoint events",
+            [](const EventType& e) { return e.type == PERF_TYPE_TRACEPOINT; }}},
 #if defined(__arm__) || defined(__aarch64__)
-    {"cs-etm",
-     {"coresight etm events",
-      [](const EventType& e) { return e.type == ETMRecorder::GetInstance().GetEtmEventType(); }}},
+          {"cs-etm",
+           {"coresight etm events",
+            [](const EventType& e) {
+              return e.type == ETMRecorder::GetInstance().GetEtmEventType();
+            }}},
 #endif
-    {"pmu", {"pmu events", [](const EventType& e) { return e.IsPmuEvent(); }}},
-  };
+          {"pmu", {"pmu events", [](const EventType& e) { return e.IsPmuEvent(); }}},
+      };
 
   std::vector<std::string> names;
   if (args.empty()) {
diff --git a/simpleperf/command.cpp b/simpleperf/command.cpp
index 3c0aa61a..2019a0d3 100644
--- a/simpleperf/command.cpp
+++ b/simpleperf/command.cpp
@@ -270,6 +270,10 @@ bool RunSimpleperfCmd(int argc, char** argv) {
   }
 
   android::base::ScopedLogSeverity severity(log_severity);
+  if (log_severity == android::base::VERBOSE) {
+    // If verbose, use android::base::StderrLogger to add time info.
+    android::base::SetLogger(android::base::StderrLogger);
+  }
 
   if (args.empty()) {
     args.push_back("help");
diff --git a/simpleperf/doc/README.md b/simpleperf/doc/README.md
index 2efa323b..b4f991b1 100644
--- a/simpleperf/doc/README.md
+++ b/simpleperf/doc/README.md
@@ -263,6 +263,7 @@ disassembly for C++ code and fully compiled Java code. Simpleperf supports two w
    2) Generate binary_cache, containing elf files with debug information. Use -lib option to add
      libs with debug info. Do it with
      `binary_cache_builder.py -i perf.data -lib <dir_of_lib_with_debug_info>`.
+     For Android platform, we can add debug binaries as in [Android platform profiling](android_platform_profiling.md#general-tips).
    3) Use report_html.py to generate report.html with annotated source code and disassembly,
      as described [here](https://android.googlesource.com/platform/system/extras/+/main/simpleperf/doc/scripts_reference.md#report_html_py).
 
@@ -271,6 +272,11 @@ disassembly for C++ code and fully compiled Java code. Simpleperf supports two w
    2) Use pprof_proto_generator.py to generate pprof proto file. `pprof_proto_generator.py`.
    3) Use pprof to report a function with annotated source code, as described [here](https://android.googlesource.com/platform/system/extras/+/main/simpleperf/doc/scripts_reference.md#pprof_proto_generator_py).
 
+3. Through Continuous PProf UI.
+   1) Generate pprof proto file as above.
+   2) Upload pprof.profile to pprof/. It can show source file path and line numbers for each symbol.
+      An example is [here](https://pprof.corp.google.com/?id=f5588600d3a225737a1901cb28f3f5b1).
+
 
 ### Reduce lost samples and samples with truncated stack
 
diff --git a/simpleperf/doc/android_platform_profiling.md b/simpleperf/doc/android_platform_profiling.md
index 52bccda7..16c967c3 100644
--- a/simpleperf/doc/android_platform_profiling.md
+++ b/simpleperf/doc/android_platform_profiling.md
@@ -33,12 +33,24 @@ $ ./app_profiler.py -np surfaceflinger -r "--call-graph fp --duration 10"
 # Collect unstripped binaries from $ANDROID_PRODUCT_OUT/symbols to binary_cache/.
 $ ./binary_cache_builder.py -lib $ANDROID_PRODUCT_OUT/symbols
 
-# Report source code and disassembly. Disassembling all binaries is slow, so it's better to add
-# --binary_filter option to only disassemble selected binaries.
+# Collect unstripped binaries from symbol file downloaded from builder server to binary_cache/.
+$ unzip comet-symbols-12488474.zip
+$ ./binary_cache_builder.py -lib out
+
+# To verify that the binaries in binary_cache/ include debug sections, you can perform a manual
+# check.
+
+# Generate an HTML report with source code and disassembly.
+# Disassembling all binaries can be slow, so you can use the --binary_filter
+# option to disassemble only specific binaries, like surfaceflinger.so in this example.
 $ ./report_html.py --add_source_code --source_dirs $ANDROID_BUILD_TOP --add_disassembly \
   --binary_filter surfaceflinger.so
 ```
 
+For a comprehensive guide to displaying source code and disassembly, see
+[Show Annotated Source Code and Disassembly](README.md#show-annotated-source-code-and-disassembly).
+
+
 ## Start simpleperf from system_server process
 
 Sometimes we want to profile a process/system-wide when a special situation happens. In this case,
diff --git a/simpleperf/doc/collect_etm_data_for_autofdo.md b/simpleperf/doc/collect_etm_data_for_autofdo.md
index 37ba0b1b..53cf72fe 100644
--- a/simpleperf/doc/collect_etm_data_for_autofdo.md
+++ b/simpleperf/doc/collect_etm_data_for_autofdo.md
@@ -4,16 +4,24 @@
 
 ## Introduction
 
-ETM is a hardware feature available on arm64 devices. It collects the instruction stream running on
-each cpu. ARM uses ETM as an alternative for LBR (last branch record) on x86.
-Simpleperf supports collecting ETM data, and converting it to input files for AutoFDO, which can
-then be used for PGO (profile-guided optimization) during compilation.
+The ARM Embedded Trace Macrocell (ETM) is an instruction tracing unit available on ARM SoCs. ETM
+traces the instruction stream executed on each core and sends the stream to system memory via other
+Coresight components. ETM data contains branch records, similar to Last Branch Records (LBRs) on
+x86 architectures.
 
-On ARMv8, ETM is considered as an external debug interface (unless ARMv8.4 Self-hosted Trace
-extension is impelemented). So it needs to be enabled explicitly in the bootloader, and isn't
-available on user devices. For Pixel devices, it's available on EVT and DVT devices on Pixel 4,
-Pixel 4a (5G) and Pixel 5. To test if it's available on other devices, you can follow commands in
-this doc and see if you can record any ETM data.
+Simpleperf supports collecting ETM data and converting it to input files for AutoFDO, which can
+then be used for Profile-Guided Optimization (PGO) during compilation.
+
+On ARMv8, the ETM and other Coresight components are considered part of the external debug
+interface. Therefore, they are typically only used internally and are disabled on production
+devices. ARMv9 introduces the Embedded Trace Extension (ETE) and Trace Buffer Extension (TRBE)
+to enhance self-hosted ETM data collection. This new hardware is not bound to the external debug
+interface and can be used more widely to collect AutoFDO profiles.
+
+For Pixel devices, ETM data collection is supported on EVT and DVT devices starting with Pixel 4.
+For other devices, you can try the commands in this document to see if ETM data recording is
+possible. To enable ETM data collection on a device, refer to the documentation in
+[Enable ETM data collection](#enable-etm-data-collection).
 
 ## Examples
 
@@ -102,7 +110,7 @@ The source code is in [etm_test_loop.cpp](https://android.googlesource.com/platf
 The build script is in [Android.bp](https://android.googlesource.com/platform/system/extras/+/main/simpleperf/runtest/Android.bp).
 It builds an executable called `etm_test_loop`, which runs on device.
 
-Step 1: Build `etm_test_loop` binary.
+**Step 1: Build `etm_test_loop` binary**
 
 ```sh
 (host) <AOSP>$ . build/envsetup.sh
@@ -110,7 +118,7 @@ Step 1: Build `etm_test_loop` binary.
 (host) <AOSP>$ make etm_test_loop
 ```
 
-Step 2: Run `etm_test_loop` on device, and collect ETM data for its running.
+**Step 2: Run `etm_test_loop` on device, and collect ETM data for its running**
 
 ```sh
 (host) <AOSP>$ adb push out/target/product/generic_arm64/system/bin/etm_test_loop /data/local/tmp
@@ -126,7 +134,7 @@ simpleperf I cmd_record.cpp:879] Aux data traced: 1,134,720
 (host) <AOSP>$ adb pull /data/local/tmp/branch_list.data
 ```
 
-Step 3: Convert ETM data to AutoFDO data.
+**Step 3: Convert ETM data to AutoFDO profile**
 
 ```sh
 # Build simpleperf tool on host.
@@ -146,7 +154,7 @@ Step 3: Convert ETM data to AutoFDO data.
 rw-r--r-- 1 user group 241 Apr 30 09:52 etm_test_loop.afdo
 ```
 
-Step 4: Use AutoFDO data to build optimized binary.
+**Step 4: Use AutoFDO profile to build optimized binary**
 
 ```sh
 (host) <AOSP>$ cp etm_test_loop.afdo toolchain/pgo-profiles/sampling/
@@ -187,6 +195,76 @@ We can check if `etm_test_loop.afdo` is used when building etm_test_loop.
 If comparing the disassembly of `out/target/product/generic_arm64/symbols/system/bin/etm_test_loop`
 before and after optimizing with AutoFDO data, we can see different preferences when branching.
 
+### A complete example: kernel
+
+This example demonstrates how to collect ETM data for the Android kernel on a device, convert it to
+an AutoFDO profile on the host machine, and then use that profile to build an optimized kernel.
+
+
+**Step 1 (Optional): Build a Kernel with `-fdebug-info-for-profiling`**
+
+While not strictly required, we recommend building the vmlinux file with the
+`-fdebug-info-for-profiling` compiler flag. This option adds extra debug information that helps map
+instructions accurately to source code, improving profile quality. For more details, see
+[this LLVM review](https://reviews.llvm.org/D25435).
+
+An example of how to add this flag to a kernel build can be found in
+[this Android kernel commit](https://android-review.googlesource.com/c/kernel/common/+/3101987).
+
+
+**Step 2: Collect ETM data for the kernel on device**
+
+```sh
+(host) $ adb root && adb shell
+(device) / $ cd /data/local/tmp
+# Record ETM data while running a representative workload (e.g., launching applications or
+# running benchmarks):
+(device) / $ simpleperf record -e cs-etm:k -a --duration 60 -z -o perf.data
+simpleperf I cmd_record.cpp:826] Recorded for 60.0796 seconds. Start post processing.
+simpleperf I cmd_record.cpp:902] Aux data traced: 91,780,432
+simpleperf I cmd_record.cpp:894] Record compressed: 27.76 MB (original 110.13 MB, ratio 4)
+# Convert the raw ETM data to a branch list to reduce file size:
+(device) / $ mkdir branch_data
+(device) / $ simpleperf inject -i perf.data -o branch_data/branch01.data --output branch-list \
+             --binary kernel.kallsyms
+(device) / $ ls branch01.data
+-rw-rw-rw- 1 root  root  437K 2024-10-17 23:03 branch01.data
+# Run the record command and the inject command multiple times to capture a wider range of kernel
+# code execution. ETM data traces the instruction stream, and under heavy load, much of this data
+# can be lost due to overflow and rate limiting within simpleperf. Recording multiple profiles and
+# merging them improves coverage.
+```
+
+Alternative: Instead of manual recording, you can use `profcollectd` to continuously collect ETM
+data in the background. See the [Collect ETM Data with a Daemon](#collect-etm-data-with-a-daemon)
+section for more information.
+
+
+**Step 3: Convert ETM data to AutoFDO Profile on Host**
+
+```sh
+(host) $ adb pull /data/local/tmp/branch_data
+(host) $ cd branch_data
+# Download the corresponding vmlinux file and place it in the current directory.
+# Merge the branch data files and generate an AutoFDO profile:
+(host) $ simpleperf inject -i branch01.data,branch02.data,... --binary kernel.kallsyms --symdir . \
+         --allow-mismatched-build-id -o kernel.autofdo -j 20
+(host) $ ls -lh kernel.autofdo
+-rw-r--r-- 1 yabinc primarygroup 1.3M Oct 17 16:39 kernel.autofdo
+# Convert the AutoFDO profile to the LLVM profile format:
+(host) $ create_llvm_prof --profiler text --binary=vmlinux --profile=kernel.autofdo \
+				--out=kernel.llvm_profdata --format extbinary
+(host) $ ls -lh kernel.llvm_profdata
+-rw-r--r-- 1 yabinc primarygroup 1.4M Oct 17 19:00 kernel.llvm_profdata
+```
+
+**Step 4: Use the AutoFDO Profile when Building a New Kernel**
+
+Integrate the generated kernel.llvm_profdata file into your kernel build process. An example of
+how to use this profile data with vmlinux can be found in
+[this Android kernel commit](https://android-review.googlesource.com/c/kernel/common/+/3293642).
+
+
 ## Convert ETM data for llvm-bolt (experiment)
 
 We can also convert ETM data to profiles for [llvm-bolt](https://github.com/llvm/llvm-project/tree/main/bolt).
@@ -213,71 +291,262 @@ The binaries should have an unstripped symbol table, and linked with relocations
 Android also has a daemon collecting ETM data periodically. It only runs on userdebug and eng
 devices. The source code is in https://android.googlesource.com/platform/system/extras/+/main/profcollectd/.
 
-## Support ETM in the kernel
+## Options for collecting ETM data
 
-To let simpleperf use ETM function, we need to enable Coresight driver in the kernel, which lives in
-`<linux_kernel>/drivers/hwtracing/coresight`.
+Simpleperf provides several options for ETM data collection, which are listed in the
+"ETM recording options" section of the `simpleperf record -h` output. Here's an introduction to some
+of them:
 
-The Coresight driver can be enabled by below kernel configs:
+ETM traces the instruction stream and can generate a large amount of data in a short time. The
+kernel uses a buffer to store this data.  The default buffer size is 4MB, which can be controlled
+with the `--aux-buffer-size` option. Simpleperf periodically reads data from this buffer, by default
+every 100ms. This interval can be adjusted using the `--etm-flush-interval` option. If the buffer
+overflows, excess ETM data is lost. The default data generation rate is 40MB/s. This is true when
+using ETR, TRBE might copy data more frequently.
 
-```config
-	CONFIG_CORESIGHT=y
-	CONFIG_CORESIGHT_LINK_AND_SINK_TMC=y
-	CONFIG_CORESIGHT_SOURCE_ETM4X=y
+To reduce storage size, ETM data can be compressed before being written to disk using the `-z`
+option. In practice, this reduces storage size by 75%.
+
+Another way to reduce storage size is to decode ETM data before storing it, using the `--decode-etm`
+option. This can achieve around a 98% reduction in storage size. However, it doubles CPU cycles and
+and power for recording, and can lead to data loss if processing doesn't keep up with the data
+generation rate. For this reason, profcollectd currently uses `-z` for compression instead of
+`--decode-etm`.
+
+## Enable ETM data collection
+
+To enable ETM data collection on a device, you must first verify that the required hardware is
+present. Then, you need to enable ETM in both the bootloader and the kernel.
+
+### Check hardware support
+
+In ARMv8, instruction tracing relies on two Coresight components:
+
+**Coresight ETM**: Generates the ETM data, recording the instruction stream.
+
+**Coresight ETR**: Transfers the ETM data to system memory for analysis.
+
+ARMv9 offers more flexibility with the introduction of new components:
+
+**Embedded Trace Extension (ETE)**: Replaces the Coresight ETM as the instruction trace source.
+
+**Trace Buffer Extension (TRBE)**: Provides an alternative to Coresight ETR for transferring trace
+data to memory. For example:
+
+Pixel 7: Uses Coresight ETM and Coresight ETR (ARMv8).
+
+Pixel 8: Uses ETE and Coresight ETR (ARMv9). While the Pixel 8 has TRBE, known errata with TRBE on
+         its Cortex cores makes it unsuitable for use.
+
+Finding Device Support Information:
+
+**ETE and TRBE support**: Refer to the relevant core's technical reference manual (e.g.,
+                          [Arm® Cortex-X4 Core Technical Reference Manual](https://developer.arm.com/documentation/102484/0002)).
+
+**TRBE errata**: Consult the core's errata notice (e.g.,
+                 [Arm® Cortex-X4 (MP161) Software Developer Errata Notice](https://developer.arm.com/documentation/SDEN-2432808/0800/?lang=en)).
+
+**Coresight ETR support**: Typically detailed in the SoC's manual.
+
+### Enable ETM in the bootloader
+
+To enable Coresight ETM and Coresight ETR on ARMv8 devices (or only Coresight ETR on ARMv9 devices),
+you need to allow non-secure, non-invasive debug access on the CPU. The specific method for doing
+this varies depending on the SoC. After enabling ETM in the bootloader and kernel, you can verify
+that Coresight ETM and ETR are operational by checking their respective `TRCAUTHSTATUS` registers.
+Following is an example of Pixel 6 with ETM enabled:
+
+```sh
+oriole:/ # cat /sys/bus/coresight/devices/etm0/mgmt/trcauthstatus
+0xcc
+oriole:/ # cat /sys/bus/coresight/devices/tmc_etr0/mgmt/authstatus
+0x33
 ```
 
-On Kernel 5.10+, we recommend building Coresight driver as kernel modules. Because it works with
-GKI kernel.
+To enable ETE on ARMv9 devices, you need to allow the kernel to access trace system registers. This
+is done by setting the `ENABLE_SYS_REG_TRACE_FOR_NS` build option in Trusted Firmware-A (see
+[documentation](https://trustedfirmware-a.readthedocs.io/en/v2.11/getting_started/build-options.html)).
+
+To enable TRBE on ARMv9 devices, you need to allow the kernel to access trace buffer control
+registers. This is done by setting the `ENABLE_TRBE_FOR_NS` build option in Trusted Firmware-A (see
+[documentation](https://trustedfirmware-a.readthedocs.io/en/v2.11/getting_started/build-options.html)).
+
 
+### Enable ETM in the kernel
+
+Android kernels from version 6.x onwards generally include the necessary patches for ETM data
+collection. To enable ETM in the kernel, you need to build the required kernel modules and add the
+appropriate device tree entries.
+
+Enable the following kernel configuration options to include the ETM kernel modules:
 ```config
 	CONFIG_CORESIGHT=m
 	CONFIG_CORESIGHT_LINK_AND_SINK_TMC=m
 	CONFIG_CORESIGHT_SOURCE_ETM4X=m
+	CONFIG_CORESIGHT_TRBE=m
 ```
 
-Android common kernel 5.10+ should have all the Coresight patches needed to collect ETM data.
-Android common kernel 5.4 misses two patches. But by adding patches in
-https://android-review.googlesource.com/q/topic:test_etm_on_hikey960_5.4, we can collect ETM data
-on hikey960 with 5.4 kernel.
-For Android common kernel 4.14 and 4.19, we have backported all necessary Coresight patches.
+These options will build the following kernel modules:
+```
+coresight.ko
+coresight-etm4x.ko
+coresight-funnel.ko
+coresight-replicator.ko
+coresight-tmc.ko
+coresight-trbe.ko
+```
+
+Different SoCs have varying Coresight device connections, address assignments, and interrupt
+configurations. Therefore, providing a universal device tree example is not feasible. However, the
+following examples from Pixel devices illustrate how device tree entries for ETM components might
+look.
+
+**Example 1: Coresight ETM and Coresight ETR (Pixel 6)**
+
+This example shows the device tree entries for Coresight ETM and ETR on Pixel 6
+(source: [gs101-debug.dtsi](https://android.googlesource.com/kernel/devices/google/gs101/+/refs/heads/android-gs-tangorpro-6.1-android16-dp/dts/gs101-debug.dtsi#287)).
+
+```device-tree
+etm0: etm@25840000 {
+    compatible = "arm,primecell";
+    arm,primecell-periphid = <0x000bb95d>;
+    reg = <0 0x25840000 0x1000>;
+    cpu = <&cpu0>;
+    coresight-name = "coresight-etm0";
+    clocks = <&clock ATCLK>;
+    clock-names = "apb_pclk";
+    arm,coresight-loses-context-with-cpu;
+    out-ports {
+        port {
+            etm0_out_port: endpoint {
+                remote-endpoint = <&funnel0_in_port0>;
+            };
+        };
+    };
+};
+
+// ... etm1 to etm7, funnel0 to funnel2, etf0, etf1 ...
+
+etr: etr@2500a000 {
+    compatible = "arm,coresight-tmc", "arm,primecell";
+    arm,primecell-periphid = <0x001bb961>;
+    reg = <0 0x2500a000 0x1000>;
+    coresight-name = "coresight-etr";
+    arm,scatter-gather;
+    clocks = <&clock ATCLK>;
+    clock-names = "apb_pclk";
+    in-ports {
+        port {
+            etr_in_port: endpoint {
+                remote-endpoint = <&funnel2_out_port>;
+            };
+        };
+    };
+};
+
+**Example 2: ETE and Coresight ETR (Pixel 8)**
+
+This example shows the device tree entries for ETE and Coresight ETR on Pixel 8
+(source: [zuma-debug.dtsi](https://android.googlesource.com/kernel/devices/google/zuma/+/refs/heads/android-gs-shusky-6.1-android16-dp/dts/zuma-debug.dtsi#428)).
+
+```device-tree
+ete0 {
+    compatible = "arm,embedded-trace-extension";
+    cpu = <&cpu0>;
+    arm,coresight-loses-context-with-cpu;
+    out-ports {
+        port {
+            ete0_out_port: endpoint {
+                remote-endpoint = <&funnel0_in_port0>;
+            };
+        };
+    };
+};
+
+// ... ete1 to ete8, funnel0 to funnel2, etf0 ...
+
+etr: etr@2a00a000 {
+    compatible = "arm,coresight-tmc", "arm,primecell";
+    arm,primecell-periphid = <0x001bb961>;
+    reg = <0 0x2a00a000 0x1000>;
+    coresight-name = "coresight-etr";
+    arm,scatter-gather;
+    clocks = <&clock ATCLK>;
+    clock-names = "apb_pclk";
+    in-ports {
+        port {
+            etr_in_port: endpoint {
+                remote-endpoint = <&funnel2_out_port>;
+            };
+        };
+    };
+};
+```
 
-Besides Coresight driver, we also need to add Coresight devices in device tree. An example is in
-https://github.com/torvalds/linux/blob/master/arch/arm64/boot/dts/arm/juno-base.dtsi. There should
-be a path flowing ETM data from ETM device through funnels, ETF and replicators, all the way to
-ETR, which writes ETM data to system memory.
+**Example 3: TRBE
 
-One optional flag in ETM device tree is "arm,coresight-loses-context-with-cpu". It saves ETM
-registers when a CPU enters low power state. It may be needed to avoid
-"coresight_disclaim_device_unlocked" warning when doing system wide collection.
+This example shows a basic device tree entry for TRBE.
 
-One optional flag in ETR device tree is "arm,scatter-gather". Simpleperf requests 4M system memory
-for ETR to store ETM data. Without IOMMU, the memory needs to be contiguous. If the kernel can't
-fulfill the request, simpleperf will report out of memory error. Fortunately, we can use
-"arm,scatter-gather" flag to let ETR run in scatter gather mode, which uses non-contiguous memory.
+```device-tree
+trbe {
+    compatible = "arm,trace-buffer-extension";
+    interrupts = <GIC_PPI 0 IRQ_TYPE_LEVEL_HIGH 0>;
+};
+```
 
+One optional flag in the ETM/ETE device tree is `arm,coresight-loses-context-with-cpu`. This flag
+ensures that ETM registers are saved when a CPU enters a low-power state. It is necessary if the
+CPU powers down the ETM/ETE during low-power states. Without this flag, the kernel cannot properly
+resume ETM data collection after the CPU wakes up, and you will likely see a
+`coresight_disclaim_device_unlocked` warning during system-wide data collection.
 
-### A possible problem: trace_id mismatch
+Another optional flag in the ETR device tree is `arm,scatter-gather`. Simpleperf requires 4MB of
+contiguous system memory for the ETR to store ETM data (unless an IOMMU is present). If the kernel
+cannot provide this contiguous memory, simpleperf will report an out-of-memory error.  Using the
+`arm,scatter-gather` flag allows the ETR to operate in scatter-gather mode, enabling it to utilize
+non-contiguous memory.
 
-Each CPU has an ETM device, which has a unique trace_id assigned from the kernel.
-The formula is: `trace_id = 0x10 + cpu * 2`, as in https://github.com/torvalds/linux/blob/master/include/linux/coresight-pmu.h#L37.
-If the formula is modified by local patches, then simpleperf inject command can't parse ETM data
-properly and is likely to give empty output.
+Each CPU has an ETM device with a unique trace_id assigned by the kernel. The standard formula for
+determining the trace_id is: `trace_id = 0x10 + cpu * 2` (as defined in
+[coresight-pmu.h](https://github.com/torvalds/linux/blob/master/include/linux/coresight-pmu.h#L22)).
+If your kernel uses a different formula due to local patches, the simpleperf inject command may
+fail to parse the ETM data correctly, potentially resulting in empty output.
 
 
-## Enable ETM in the bootloader
+### Check ETM enable status in /sys
 
-Unless ARMv8.4 Self-hosted Trace extension is implemented, ETM is considered as an external debug
-interface. It may be disabled by fuse (like JTAG). So we need to check if ETM is disabled, and
-if bootloader provides a way to reenable it.
+The status of ETM devices is reflected in /sys. The following is an example from a Pixel 9.
 
-We can tell if ETM is disable by checking its TRCAUTHSTATUS register, which is exposed in sysfs,
-like /sys/bus/coresight/devices/coresight-etm0/mgmt/trcauthstatus. To reenable ETM, we need to
-enable non-Secure non-invasive debug on ARM CPU. The method depends on chip vendors(SOCs).
+```sh
+# List available Coresight devices, including ETE and TRBE.
+comet:/sys/bus/coresight/devices $ ls
+ete0  ete1  ete2  ete3  ete4  ete5  ete6  ete7  funnel0  funnel1  funnel2  tmc_etf0  tmc_etr0
+
+# Check if Coresight ETR is enabled.
+comet:/sys/bus/coresight/devices $ cat tmc_etr0/mgmt/authstatus
+0x33
+
+# Check if we have Coresight ETM/ETE devices as perf event sources.
+comet:/sys/bus/event_source/devices/cs_etm $ ls -l
+total 0
+lrwxrwxrwx 1 root root    0 2024-12-03 17:37 cpu0 -> ../platform/ete0/ete0
+lrwxrwxrwx 1 root root    0 2024-12-03 17:37 cpu1 -> ../platform/ete1/ete1
+lrwxrwxrwx 1 root root    0 2024-12-03 17:37 cpu2 -> ../platform/ete2/ete2
+lrwxrwxrwx 1 root root    0 2024-12-03 17:37 cpu3 -> ../platform/ete3/ete3
+lrwxrwxrwx 1 root root    0 2024-12-03 17:37 cpu4 -> ../platform/ete4/ete4
+lrwxrwxrwx 1 root root    0 2024-12-03 17:37 cpu5 -> ../platform/ete5/ete5
+lrwxrwxrwx 1 root root    0 2024-12-03 17:37 cpu6 -> ../platform/ete6/ete6
+lrwxrwxrwx 1 root root    0 2024-12-03 17:37 cpu7 -> ../platform/ete7/ete7
+
+# Check if we have Coresight ETR/TRBE to move ETM data to system memory.
+comet:/sys/bus/event_source/devices/cs_etm/sinks $ ls
+tmc_etf0  tmc_etr0
+```
 
 
 ## Related docs
 
-* [Arm Architecture Reference Manual Armv8, D3 AArch64 Self-hosted Trace](https://developer.arm.com/documentation/ddi0487/latest)
+* [Arm Architecture Reference Manual for A-profile architecture, D3-D6](https://developer.arm.com/documentation/ddi0487/latest/)
 * [ARM ETM Architecture Specification](https://developer.arm.com/documentation/ihi0064/latest/)
 * [ARM CoreSight Architecture Specification](https://developer.arm.com/documentation/ihi0029/latest)
 * [CoreSight Components Technical Reference Manual](https://developer.arm.com/documentation/ddi0314/h/)
diff --git a/simpleperf/doc/pictures/perfetto.png b/simpleperf/doc/pictures/perfetto.png
new file mode 100644
index 00000000..fac732f7
Binary files /dev/null and b/simpleperf/doc/pictures/perfetto.png differ
diff --git a/simpleperf/doc/scripts_reference.md b/simpleperf/doc/scripts_reference.md
index af74458e..18611678 100644
--- a/simpleperf/doc/scripts_reference.md
+++ b/simpleperf/doc/scripts_reference.md
@@ -225,16 +225,9 @@ $ pprof -http=:8080 pprof.profile
 
 Converts `perf.data` to [Gecko Profile
 Format](https://github.com/firefox-devtools/profiler/blob/main/docs-developer/gecko-profile-format.md),
-the format read by https://profiler.firefox.com/.
-
-Firefox Profiler is a powerful general-purpose profiler UI which runs locally in
-any browser (not just Firefox), with:
-
-- Per-thread tracks
-- Flamegraphs
-- Search, focus for specific stacks
-- A time series view for seeing your samples in timestamp order
-- Filtering by thread and duration
+a format readable by both the [Perfetto UI](https://ui.perfetto.dev/) and
+[Firefox Profiler](https://profiler.firefox.com/).
+[View the profile](view_the_profile.md) provides more information on both options.
 
 Usage:
 
@@ -246,7 +239,8 @@ $ ./app_profiler.py -p simpleperf.example.cpp
 $ ./gecko_profile_generator.py -i perf.data | gzip > gecko-profile.json.gz
 ```
 
-Then open `gecko-profile.json.gz` in https://profiler.firefox.com/.
+Then open `gecko-profile.json.gz` in https://ui.perfetto.dev/ or
+https://profiler.firefox.com/.
 
 ### report_sample.py
 
@@ -255,6 +249,7 @@ Then open `gecko-profile.json.gz` in https://profiler.firefox.com/.
 
 This format can be imported into:
 
+- [Perfetto](https://ui.perfetto.dev)
 - [FlameGraph](https://github.com/brendangregg/FlameGraph)
 - [Flamescope](https://github.com/Netflix/flamescope)
 - [Firefox
diff --git a/simpleperf/doc/view_the_profile.md b/simpleperf/doc/view_the_profile.md
index 509b3fbf..fa67ad9e 100644
--- a/simpleperf/doc/view_the_profile.md
+++ b/simpleperf/doc/view_the_profile.md
@@ -4,26 +4,27 @@
 
 ## Introduction
 
-After using `simpleperf record` or `app_profiler.py`, we get a profile data file. The file contains
-a list of samples. Each sample has a timestamp, a thread id, a callstack, events (like cpu-cycles
-or cpu-clock) used in this sample, etc. We have many choices for viewing the profile. We can show
-samples in chronological order, or show aggregated flamegraphs. We can show reports in text format,
-or in some interactive UIs.
-
-Below shows some recommended UIs to view the profile. Google developers can find more examples in
+After using `simpleperf record` or `app_profiler.py`, we get a profile data
+file. The file contains a list of samples. Each sample has a timestamp, a thread
+id, a callstack, events (like cpu-cycles or cpu-clock) used in this sample, etc.
+We have many choices for viewing the profile. We can show samples in
+chronological order, or show aggregated flamegraphs. We can show reports in text
+format, or in some interactive UIs.
+
+Below shows some recommended UIs to view the profile. Google developers can find
+more examples in
 [go/gmm-profiling](go/gmm-profiling?polyglot=linux-workstation#viewing-the-profile).
 
-
 ## Continuous PProf UI (great flamegraph UI, but only available internally)
 
-[PProf](https://github.com/google/pprof) is a mature profiling technology used extensively on
-Google servers, with a powerful flamegraph UI, with strong drilldown, search, pivot, profile diff,
-and graph visualisation.
+[PProf](https://github.com/google/pprof) is a mature profiling technology used
+extensively on Google servers, with a powerful flamegraph UI, with strong
+drilldown, search, pivot, profile diff, and graph visualisation.
 
 ![Example](./pictures/continuous_pprof.png)
 
-We can use `pprof_proto_generator.py` to convert profiles into pprof.profile protobufs for use in
-pprof.
+We can use `pprof_proto_generator.py` to convert profiles into pprof.profile
+protobufs for use in pprof.
 
 ```
 # Output all threads, broken down by threadpool.
@@ -36,19 +37,19 @@ pprof.
 ./pprof_proto_generator.py --comm com.example.android.displayingbitmaps
 ```
 
-This will print some debug logs about Failed to read symbols: this is usually OK, unless those
-symbols are hotspots.
+This will print some debug logs about Failed to read symbols: this is usually
+OK, unless those symbols are hotspots.
 
-The continuous pprof server has a file upload size limit of 50MB. To get around this limit, compress
-the profile before uploading:
+The continuous pprof server has a file upload size limit of 50MB. To get around
+this limit, compress the profile before uploading:
 
 ```
 gzip pprof.profile
 ```
 
-After compressing, you can upload the `pprof.profile.gz` file to http://pprof/. The website has an
-'Upload' tab for this purpose. Alternatively, you can use the following `pprof` command to upload
-the compressed profile:
+After compressing, you can upload the `pprof.profile.gz` file to http://pprof/.
+The website has an 'Upload' tab for this purpose. Alternatively, you can use the
+following `pprof` command to upload the compressed profile:
 
 ```
 # Upload all threads in profile, grouped by threadpool.
@@ -63,19 +64,60 @@ pprof --flame pprof.profile.gz
 This will output a URL, example: https://pprof.corp.google.com/?id=589a60852306144c880e36429e10b166
 ```
 
+## Perfetto (preferred chronological UI and flamegraph UI for public)
+
+The [Perfetto UI](https://ui.perfetto.dev) is a web-based visualizer combining
+the chronological view of the profile with a powerful flamegraph UI.
+
+The Perfetto UI shows stack samples over time, exactly as collected by perf and
+allows selecting both region of time and certain threads and/or processes to
+analyse only matching samples. Moreover, it has a similar flamegraph UI to pprof
+very similar drilldown, search and pivot functionality. Finally, it also has an
+SQL query language (PerfettoSQL) which allows programmatic queries on profiles.
+
+![Example](./pictures/perfetto.png)
+
+We can use `gecko_profile_generator.py` to convert raw perf.data files into a
+Gecko format; while Perfetto supports opening raw perf.data files as well,
+symbolization and deobfuscation does not work out of the box.
+
+```
+# Create Gecko format profile
+./gecko_profile_generator.py > gecko_profile.json
+
+# Create Gecko format profile with Proguard map for deobfuscation
+./gecko_profile_generator.py --proguard-mapping-file proguard.map > gecko_profile.json
+```
+
+Then drag-and-drop `gecko_profile.json` into https://ui.perfetto.dev/.
+Alternatively, to open from the command line, you can also do:
+
+```
+curl -L https://github.com/google/perfetto/raw/main/tools/open_trace_in_ui | python - -i gecko_profile.json
+```
+
+Note: if running the above on a remote machine over SSH, you need to first port
+forward `9001` to your local machine. For example, you could do this by running:
+
+```
+ssh -fNT -L 9001:localhost:9001 <hostname>
+```
+
 ## Firefox Profiler (great chronological UI)
 
-We can view Android profiles using Firefox Profiler: https://profiler.firefox.com/. This does not
-require Firefox installation -- Firefox Profiler is just a website, you can open it in any browser.
-There is also an internal Google-Hosted Firefox Profiler, at go/profiler or go/firefox-profiler.
+We can view Android profiles using Firefox Profiler:
+https://profiler.firefox.com/. This does not require Firefox installation --
+Firefox Profiler is just a website, you can open it in any browser. There is
+also an internal Google-Hosted Firefox Profiler, at go/profiler or
+go/firefox-profiler.
 
 ![Example](./pictures/firefox_profiler.png)
 
-Firefox Profiler has a great chronological view, as it doesn't pre-aggregate similar stack traces
-like pprof does.
+Firefox Profiler has a great chronological view, as it doesn't pre-aggregate
+similar stack traces like pprof does.
 
-We can use `gecko_profile_generator.py` to convert raw perf.data files into a Firefox Profile, with
-Proguard deobfuscation.
+We can use `gecko_profile_generator.py` to convert raw perf.data files into a
+Firefox Profile, with Proguard deobfuscation.
 
 ```
 # Create Gecko Profile
@@ -89,24 +131,26 @@ Then drag-and-drop gecko_profile.json.gz into https://profiler.firefox.com/.
 
 Firefox Profiler supports:
 
-1. Aggregated Flamegraphs
-2. Chronological Stackcharts
+1.  Aggregated Flamegraphs
+2.  Chronological Stackcharts
 
 And allows filtering by:
 
-1. Individual threads
-2. Multiple threads (Ctrl+Click thread names to select many)
-3. Timeline period
-4. Stack frame text search
+1.  Individual threads
+2.  Multiple threads (Ctrl+Click thread names to select many)
+3.  Timeline period
+4.  Stack frame text search
 
 ## FlameScope (great jank-finding UI)
 
-[Netflix's FlameScope](https://github.com/Netflix/flamescope) is a rough, proof-of-concept UI that
-lets you spot repeating patterns of work by laying out the profile as a subsecond heatmap.
+[Netflix's FlameScope](https://github.com/Netflix/flamescope) is a rough,
+proof-of-concept UI that lets you spot repeating patterns of work by laying out
+the profile as a subsecond heatmap.
 
-Below, each vertical stripe is one second, and each cell is 10ms. Redder cells have more samples.
-See https://www.brendangregg.com/blog/2018-11-08/flamescope-pattern-recognition.html for how to
-spot patterns.
+Below, each vertical stripe is one second, and each cell is 10ms. Redder cells
+have more samples. See
+https://www.brendangregg.com/blog/2018-11-08/flamescope-pattern-recognition.html
+for how to spot patterns.
 
 This is an example of a 60s DisplayBitmaps app Startup Profile.
 
@@ -114,11 +158,10 @@ This is an example of a 60s DisplayBitmaps app Startup Profile.
 
 You can see:
 
-  The thick red vertical line on the left is startup.
-  The long white vertical sections on the left shows the app is mostly idle, waiting for commands
-  from instrumented tests.
-  Then we see periodically red blocks, which shows the app is periodically busy handling commands
-  from instrumented tests.
+The thick red vertical line on the left is startup. The long white vertical
+sections on the left shows the app is mostly idle, waiting for commands from
+instrumented tests. Then we see periodically red blocks, which shows the app is
+periodically busy handling commands from instrumented tests.
 
 Click the start and end cells of a duration:
 
@@ -141,8 +184,9 @@ python3 run.py
 
 Then open FlameScope in-browser: http://localhost:5000/.
 
-FlameScope can read gzipped perf script format profiles. Convert simpleperf perf.data to this
-format with `report_sample.py`, and place it in Flamescope's examples directory:
+FlameScope can read gzipped perf script format profiles. Convert simpleperf
+perf.data to this format with `report_sample.py`, and place it in Flamescope's
+examples directory:
 
 ```
 # Create `Linux perf script` format profile.
@@ -154,8 +198,8 @@ report_sample.py \
   | gzip > ~/flamescope/examples/my_simpleperf_profile.gz
 ```
 
-Open the profile "as Linux Perf", and click start and end sections to get a flamegraph of that
-timespan.
+Open the profile "as Linux Perf", and click start and end sections to get a
+flamegraph of that timespan.
 
 To investigate UI Thread Jank, filter to UI thread samples only:
 
@@ -165,20 +209,22 @@ report_sample.py \
   | gzip > ~/flamescope/examples/uithread.gz
 ```
 
-Once you've identified the timespan of interest, consider also zooming into that section with
-Firefox Profiler, which has a more powerful flamegraph viewer.
+Once you've identified the timespan of interest, consider also zooming into that
+section with Firefox Profiler, which has a more powerful flamegraph viewer.
 
 ## Differential FlameGraph
 
-See Brendan Gregg's [Differential Flame Graphs](https://www.brendangregg.com/blog/2014-11-09/differential-flame-graphs.html) blog.
+See Brendan Gregg's
+[Differential Flame Graphs](https://www.brendangregg.com/blog/2014-11-09/differential-flame-graphs.html)
+blog.
 
-Use Simpleperf's `stackcollapse.py` to convert perf.data to Folded Stacks format for the FlameGraph
-toolkit.
+Use Simpleperf's `stackcollapse.py` to convert perf.data to Folded Stacks format
+for the FlameGraph toolkit.
 
 Consider diffing both directions: After minus Before, and Before minus After.
 
-If you've recorded before and after your optimisation as perf_before.data and perf_after.data, and
-you're only interested in the UI thread:
+If you've recorded before and after your optimisation as perf_before.data and
+perf_after.data, and you're only interested in the UI thread:
 
 ```
 # Generate before and after folded stacks from perf.data files
@@ -200,36 +246,37 @@ FlameGraph/difffolded.pl -n --negate perf_after.folded perf_before.folded \
 
 ## Android Studio Profiler
 
-Android Studio Profiler supports recording and reporting profiles of app processes. It supports
-several recording methods, including one using simpleperf as backend. You can use Android Studio
-Profiler for both recording and reporting.
+Android Studio Profiler supports recording and reporting profiles of app
+processes. It supports several recording methods, including one using simpleperf
+as backend. You can use Android Studio Profiler for both recording and
+reporting.
 
-In Android Studio:
-Open View -> Tool Windows -> Profiler
-Click + -> Your Device -> Profileable Processes -> Your App
+In Android Studio: Open View -> Tool Windows -> Profiler Click + -> Your Device
+-> Profileable Processes -> Your App
 
 ![Example](./pictures/android_studio_profiler_select_process.png)
 
 Click into "CPU" Chart
 
-Choose Callstack Sample Recording. Even if you're using Java, this provides better observability,
-into ART, malloc, and the kernel.
+Choose Callstack Sample Recording. Even if you're using Java, this provides
+better observability, into ART, malloc, and the kernel.
 
 ![Example](./pictures/android_studio_profiler_select_recording_method.png)
 
 Click Record, run your test on the device, then Stop when you're done.
 
-Click on a thread track, and "Flame Chart" to see a chronological chart on the left, and an
-aggregated flamechart on the right:
+Click on a thread track, and "Flame Chart" to see a chronological chart on the
+left, and an aggregated flamechart on the right:
 
 ![Example](./pictures/android_studio_profiler_flame_chart.png)
 
-If you want more flexibility in recording options, or want to add proguard mapping file, you can
-record using simpleperf, and report using Android Studio Profiler.
-
-We can use `simpleperf report-sample` to convert perf.data to trace files for Android Studio
+If you want more flexibility in recording options, or want to add proguard
+mapping file, you can record using simpleperf, and report using Android Studio
 Profiler.
 
+We can use `simpleperf report-sample` to convert perf.data to trace files for
+Android Studio Profiler.
+
 ```
 # Convert perf.data to perf.trace for Android Studio Profiler.
 # If on Mac/Windows, use simpleperf host executable for those platforms instead.
@@ -244,18 +291,19 @@ In Android Studio: Open File -> Open -> Select perf.trace
 
 ![Example](./pictures/android_studio_profiler_open_perf_trace.png)
 
-
 ## Simpleperf HTML Report
 
-Simpleperf can generate its own HTML Profile, which is able to show Android-specific information
-and separate flamegraphs for all threads, with a much rougher flamegraph UI.
+Simpleperf can generate its own HTML Profile, which is able to show
+Android-specific information and separate flamegraphs for all threads, with a
+much rougher flamegraph UI.
 
 ![Example](./pictures/report_html.png)
 
-This UI is fairly rough; we recommend using the Continuous PProf UI or Firefox Profiler instead. But
-it's useful for a quick look at your data.
+This UI is fairly rough; we recommend using the Continuous PProf UI or Firefox
+Profiler instead. But it's useful for a quick look at your data.
 
-Each of the following commands take as input ./perf.data and output ./report.html.
+Each of the following commands take as input ./perf.data and output
+./report.html.
 
 ```
 # Make an HTML report.
@@ -265,18 +313,19 @@ Each of the following commands take as input ./perf.data and output ./report.htm
 ./report_html.py --proguard-mapping-file proguard.map
 ```
 
-This will print some debug logs about Failed to read symbols: this is usually OK, unless those
-symbols are hotspots.
-
-See also [report_html.py's README](scripts_reference.md#report_htmlpy) and `report_html.py -h`.
+This will print some debug logs about Failed to read symbols: this is usually
+OK, unless those symbols are hotspots.
 
+See also [report_html.py's README](scripts_reference.md#report_htmlpy) and
+`report_html.py -h`.
 
 ## PProf Interactive Command Line
 
-Unlike Continuous PProf UI, [PProf](https://github.com/google/pprof) command line is publicly
-available, and allows drilldown, pivoting and filtering.
+Unlike Continuous PProf UI, [PProf](https://github.com/google/pprof) command
+line is publicly available, and allows drilldown, pivoting and filtering.
 
-The below session demonstrates filtering to stack frames containing processBitmap.
+The below session demonstrates filtering to stack frames containing
+processBitmap.
 
 ```
 $ pprof pprof.profile
@@ -289,7 +338,8 @@ Showing nodes accounting for 2.45s, 11.44% of 21.46s total
      2.45s 11.44% 11.44%      2.45s 11.44%  com.example.android.displayingbitmaps.util.ImageFetcher.processBitmap
 ```
 
-And then showing the tags of those frames, to tell what threads they are running on:
+And then showing the tags of those frames, to tell what threads they are running
+on:
 
 ```
 (pprof) tags
@@ -320,8 +370,8 @@ Showing nodes accounting for 1.05s, 4.88% of 21.46s total
      1.05s  4.88%  4.88%      1.05s  4.88%  com.example.android.displayingbitmaps.util.ImageCache.addBitmapToCache
 ```
 
-For more information, see the [pprof README](https://github.com/google/pprof/blob/main/doc/README.md#interactive-terminal-use).
-
+For more information, see the
+[pprof README](https://github.com/google/pprof/blob/main/doc/README.md#interactive-terminal-use).
 
 ## Simpleperf Report Command Line
 
@@ -339,14 +389,16 @@ $ ./report.py --children
 $ bin/linux/x86_64/simpleperf report -g -i perf.data
 ```
 
-See also [report command's README](executable_commands_reference.md#The-report-command) and
-`report.py -h`.
-
+See also
+[report command's README](executable_commands_reference.md#The-report-command)
+and `report.py -h`.
 
 ## Custom Report Interface
 
-If the above View UIs can't fulfill your need, you can use `simpleperf_report_lib.py` to parse
-perf.data, extract sample information, and feed it to any views you like.
+If the above View UIs can't fulfill your need, you can use
+`simpleperf_report_lib.py` to parse perf.data, extract sample information, and
+feed it to any views you like.
 
-See [simpleperf_report_lib.py's README](scripts_reference.md#simpleperf_report_libpy) for more
-details.
+See
+[simpleperf_report_lib.py's README](scripts_reference.md#simpleperf_report_libpy)
+for more details.
diff --git a/simpleperf/dso.cpp b/simpleperf/dso.cpp
index 3c8393f9..e953acff 100644
--- a/simpleperf/dso.cpp
+++ b/simpleperf/dso.cpp
@@ -221,9 +221,12 @@ std::string DebugElfFileFinder::GetPathInSymFsDir(const std::string& path) {
   return add_symfs_prefix(elf_path);
 }
 
-std::optional<std::string> DebugElfFileFinder::SearchFileMapByPath(const std::string& path) {
-  std::string filename;
-  if (size_t pos = path.rfind('/'); pos != std::string::npos) {
+std::optional<std::string> DebugElfFileFinder::SearchFileMapByPath(std::string_view path) {
+  if (path == "[kernel.kallsyms]") {
+    path = "vmlinux";
+  }
+  std::string_view filename;
+  if (size_t pos = path.rfind('/'); pos != path.npos) {
     filename = path.substr(pos + 1);
   } else {
     filename = path;
diff --git a/simpleperf/dso.h b/simpleperf/dso.h
index 10b5879b..00b9d3f8 100644
--- a/simpleperf/dso.h
+++ b/simpleperf/dso.h
@@ -48,7 +48,7 @@ class DebugElfFileFinder {
 
  private:
   void CollectBuildIdInDir(const std::string& dir);
-  std::optional<std::string> SearchFileMapByPath(const std::string& path);
+  std::optional<std::string> SearchFileMapByPath(std::string_view path);
   bool CheckDebugFilePath(const std::string& path, BuildId& build_id,
                           bool report_build_id_mismatch);
 
diff --git a/simpleperf/environment.cpp b/simpleperf/environment.cpp
index ed50cd51..316aee41 100644
--- a/simpleperf/environment.cpp
+++ b/simpleperf/environment.cpp
@@ -918,18 +918,33 @@ int GetAndroidVersion() {
   static int android_version = -1;
   if (android_version == -1) {
     android_version = 0;
+
+    auto parse_version = [&](const std::string& s) {
+      // The release string can be a list of numbers (like 8.1.0), a character (like Q)
+      // or many characters (like OMR1).
+      if (!s.empty()) {
+        // Each Android version has a version number: L is 5, M is 6, N is 7, O is 8, etc.
+        if (s[0] >= 'L' && s[0] <= 'V') {
+          android_version = s[0] - 'P' + kAndroidVersionP;
+        } else if (isdigit(s[0])) {
+          sscanf(s.c_str(), "%d", &android_version);
+        }
+      }
+    };
     std::string s = android::base::GetProperty("ro.build.version.codename", "REL");
-    if (s == "REL") {
+    if (s != "REL") {
+      parse_version(s);
+    }
+    if (android_version == 0) {
       s = android::base::GetProperty("ro.build.version.release", "");
+      parse_version(s);
     }
-    // The release string can be a list of numbers (like 8.1.0), a character (like Q)
-    // or many characters (like OMR1).
-    if (!s.empty()) {
-      // Each Android version has a version number: L is 5, M is 6, N is 7, O is 8, etc.
-      if (s[0] >= 'A' && s[0] <= 'Z') {
-        android_version = s[0] - 'P' + kAndroidVersionP;
-      } else if (isdigit(s[0])) {
-        sscanf(s.c_str(), "%d", &android_version);
+    if (android_version == 0) {
+      s = android::base::GetProperty("ro.build.version.sdk", "");
+      int sdk_version = 0;
+      const int SDK_VERSION_V = 35;
+      if (sscanf(s.c_str(), "%d", &sdk_version) == 1 && sdk_version >= SDK_VERSION_V) {
+        android_version = kAndroidVersionV;
       }
     }
   }
@@ -1033,54 +1048,137 @@ std::optional<uid_t> GetProcessUid(pid_t pid) {
   return std::nullopt;
 }
 
-std::vector<ARMCpuModel> GetARMCpuModels() {
-  std::vector<ARMCpuModel> cpu_models;
-  LineReader reader("/proc/cpuinfo");
-  if (!reader.Ok()) {
+namespace {
+
+class CPUModelParser {
+ public:
+  std::vector<CpuModel> ParseARMCpuModel(const std::vector<std::string>& lines) {
+    std::vector<CpuModel> cpu_models;
+    uint32_t processor = 0;
+    CpuModel model;
+    model.arch = "arm";
+    int parsed = 0;
+
+    auto line_callback = [&](const std::string& name, const std::string& value) {
+      if (name == "processor" && android::base::ParseUint(value, &processor)) {
+        parsed |= 1;
+      } else if (name == "CPU implementer" &&
+                 android::base::ParseUint(value, &model.arm_data.implementer)) {
+        parsed |= 2;
+      } else if (name == "CPU part" && android::base::ParseUint(value, &model.arm_data.partnum) &&
+                 parsed == 0x3) {
+        AddCpuModel(processor, model, cpu_models);
+        parsed = 0;
+      }
+    };
+    ProcessLines(lines, line_callback);
     return cpu_models;
   }
-  auto add_cpu = [&](uint32_t processor, uint32_t implementer, uint32_t partnum) {
-    for (auto& model : cpu_models) {
-      if (model.implementer == implementer && model.partnum == partnum) {
-        model.cpus.push_back(processor);
-        return;
+
+  std::vector<CpuModel> ParseRISCVCpuModel(const std::vector<std::string>& lines) {
+    std::vector<CpuModel> cpu_models;
+    uint32_t processor = 0;
+    CpuModel model;
+    model.arch = "riscv";
+    int parsed = 0;
+
+    auto line_callback = [&](const std::string& name, const std::string& value) {
+      if (name == "processor" && android::base::ParseUint(value, &processor)) {
+        parsed |= 1;
+      } else if (name == "mvendorid" &&
+                 android::base::ParseUint(value, &model.riscv_data.mvendorid)) {
+        parsed |= 2;
+      } else if (name == "marchid" && android::base::ParseUint(value, &model.riscv_data.marchid)) {
+        parsed |= 4;
+      } else if (name == "mimpid" && android::base::ParseUint(value, &model.riscv_data.mimpid) &&
+                 parsed == 0x7) {
+        AddCpuModel(processor, model, cpu_models);
+        parsed = 0;
       }
-    }
-    cpu_models.resize(cpu_models.size() + 1);
-    ARMCpuModel& model = cpu_models.back();
-    model.implementer = implementer;
-    model.partnum = partnum;
-    model.cpus.push_back(processor);
-  };
+    };
+    ProcessLines(lines, line_callback);
+    return cpu_models;
+  }
 
-  uint32_t processor = 0;
-  uint32_t implementer = 0;
-  uint32_t partnum = 0;
-  int parsed = 0;
-  std::string* line;
-  while ((line = reader.ReadLine()) != nullptr) {
-    std::vector<std::string> strs = android::base::Split(*line, ":");
-    if (strs.size() != 2) {
-      continue;
-    }
-    std::string name = android::base::Trim(strs[0]);
-    std::string value = android::base::Trim(strs[1]);
-    if (name == "processor") {
-      if (android::base::ParseUint(value, &processor)) {
+  std::vector<CpuModel> ParseX86CpuModel(const std::vector<std::string>& lines) {
+    std::vector<CpuModel> cpu_models;
+    uint32_t processor = 0;
+    CpuModel model;
+    model.arch = "x86";
+    int parsed = 0;
+
+    auto line_callback = [&](const std::string& name, const std::string& value) {
+      if (name == "processor" && android::base::ParseUint(value, &processor)) {
         parsed |= 1;
+      } else if (name == "vendor_id") {
+        model.x86_data.vendor_id = value;
+        AddCpuModel(processor, model, cpu_models);
+        parsed = 0;
       }
-    } else if (name == "CPU implementer") {
-      if (android::base::ParseUint(value, &implementer)) {
-        parsed |= 2;
+    };
+    ProcessLines(lines, line_callback);
+    return cpu_models;
+  }
+
+ private:
+  void ProcessLines(const std::vector<std::string>& lines,
+                    const std::function<void(const std::string&, const std::string&)>& callback) {
+    for (const auto& line : lines) {
+      std::vector<std::string> strs = android::base::Split(line, ":");
+      if (strs.size() != 2) {
+        continue;
       }
-    } else if (name == "CPU part") {
-      if (android::base::ParseUint(value, &partnum) && parsed == 0x3) {
-        add_cpu(processor, implementer, partnum);
+      std::string name = android::base::Trim(strs[0]);
+      std::string value = android::base::Trim(strs[1]);
+      callback(name, value);
+    }
+  }
+
+  void AddCpuModel(uint32_t processor, const CpuModel& model, std::vector<CpuModel>& cpu_models) {
+    for (auto& m : cpu_models) {
+      if (model.arch == "arm") {
+        if (model.arm_data.implementer == m.arm_data.implementer &&
+            model.arm_data.partnum == m.arm_data.partnum) {
+          m.cpus.push_back(processor);
+          return;
+        }
+      } else if (model.arch == "riscv") {
+        if (model.riscv_data.mvendorid == m.riscv_data.mvendorid &&
+            model.riscv_data.marchid == m.riscv_data.marchid &&
+            model.riscv_data.mimpid == m.riscv_data.mimpid) {
+          m.cpus.push_back(processor);
+          return;
+        }
+      } else if (model.arch == "x86") {
+        if (model.x86_data.vendor_id == m.x86_data.vendor_id) {
+          m.cpus.push_back(processor);
+          return;
+        }
       }
-      parsed = 0;
     }
+    cpu_models.push_back(model);
+    cpu_models.back().cpus.push_back(processor);
   }
-  return cpu_models;
+};
+
+}  // namespace
+
+std::vector<CpuModel> GetCpuModels() {
+  std::string data;
+  if (!android::base::ReadFileToString("/proc/cpuinfo", &data)) {
+    return {};
+  }
+  std::vector<std::string> lines = android::base::Split(data, "\n");
+  CPUModelParser parser;
+#if defined(__aarch64__) || defined(__arm__)
+  return parser.ParseARMCpuModel(lines);
+#elif defined(__riscv)
+  return parser.ParseRISCVCpuModel(lines);
+#elif defined(__x86_64__) || defined(__i386__)
+  return parser.ParseX86CpuModel(lines);
+#else
+  return {};
+#endif
 }
 
 }  // namespace simpleperf
diff --git a/simpleperf/environment.h b/simpleperf/environment.h
index 8aaa7192..7d0d7f03 100644
--- a/simpleperf/environment.h
+++ b/simpleperf/environment.h
@@ -122,6 +122,9 @@ enum {
   kAndroidVersionQ = 10,
   kAndroidVersionR = 11,
   kAndroidVersionS = 12,
+  kAndroidVersionT = 13,
+  kAndroidVersionU = 14,
+  kAndroidVersionV = 15,
 };
 
 // Return 0 if no android version.
@@ -152,13 +155,24 @@ static inline int gettid() {
 }
 #endif
 
-struct ARMCpuModel {
-  uint32_t implementer = 0;
-  uint32_t partnum = 0;
+struct CpuModel {
+  std::string arch;  // "arm", "riscv" or "x86"
+  struct {
+    uint32_t implementer = 0;
+    uint32_t partnum = 0;
+  } arm_data;
+  struct {
+    uint64_t mvendorid = 0;
+    uint64_t marchid = 0;
+    uint64_t mimpid = 0;
+  } riscv_data;
+  struct {
+    std::string vendor_id;
+  } x86_data;
   std::vector<int> cpus;
 };
 
-std::vector<ARMCpuModel> GetARMCpuModels();
+std::vector<CpuModel> GetCpuModels();
 
 #endif  // defined(__linux__)
 
diff --git a/simpleperf/environment_test.cpp b/simpleperf/environment_test.cpp
index 5772e472..3a404056 100644
--- a/simpleperf/environment_test.cpp
+++ b/simpleperf/environment_test.cpp
@@ -153,11 +153,11 @@ TEST(environment, GetMemorySize) {
 }
 
 // @CddTest = 6.1/C-0-2
-TEST(environment, GetARMCpuModels) {
-#if defined(__aarch64__) && defined(__ANDROID__)
-  auto models = GetARMCpuModels();
+TEST(environment, GetCpuModels) {
+#if defined(__ANDROID__)
+  auto models = GetCpuModels();
   ASSERT_FALSE(models.empty());
   ASSERT_FALSE(models[0].cpus.empty());
   ASSERT_EQ(models[0].cpus[0], 0);
-#endif  // defined(__aarch64__) && defined(__ANDROID__)
+#endif  // defined(__ANDROID__)
 }
diff --git a/simpleperf/event_selection_set.cpp b/simpleperf/event_selection_set.cpp
index ca0bb699..58f82506 100644
--- a/simpleperf/event_selection_set.cpp
+++ b/simpleperf/event_selection_set.cpp
@@ -40,7 +40,7 @@ namespace simpleperf {
 using android::base::StringPrintf;
 
 bool IsBranchSamplingSupported() {
-  const EventType* type = FindEventTypeByName("cpu-cycles");
+  const EventType* type = FindEventTypeByName("BR_INST_RETIRED.NEAR_TAKEN");
   if (type == nullptr) {
     return false;
   }
diff --git a/simpleperf/event_table.json b/simpleperf/event_table.json
index acff512c..ddcbfbf7 100644
--- a/simpleperf/event_table.json
+++ b/simpleperf/event_table.json
@@ -1038,5 +1038,19 @@
         ]
       }
     ]
+  },
+  "riscv64": {
+    "events": [],
+    "cpus": []
+  },
+  "x86-intel": {
+    "events": [
+      ["0x20c4", "BR_INST_RETIRED.NEAR_TAKEN", "Taken branch instructions retired"]
+    ]
+  },
+  "x86-amd": {
+    "events": [
+      ["0xc4", "ex_ret_brn_tkn", "Retired taken branch instructions"]
+    ]
   }
 }
diff --git a/simpleperf/event_table_generator.py b/simpleperf/event_table_generator.py
index d7a3e1b5..d44cbb6b 100755
--- a/simpleperf/event_table_generator.py
+++ b/simpleperf/event_table_generator.py
@@ -19,6 +19,7 @@ import dataclasses
 from dataclasses import dataclass
 import json
 import sys
+from typing import List
 
 
 def gen_event_type_entry_str(event_type_name, event_type, event_config, description='',
@@ -122,6 +123,9 @@ class CpuModel:
     name: str
     implementer: int
     partnum: int
+    mvendorid: int
+    marchid: str
+    mimpid: str
     supported_raw_events: list[int] = dataclasses.field(default_factory=list)
 
 
@@ -140,9 +144,17 @@ class ArchData:
             self.events.append(RawEvent(number, name, desc, self.arch))
         for cpu in data['cpus']:
             cpu_name = cpu['name'].lower().replace('_', '-')
-            cpu_model = CpuModel(cpu['name'], int(cpu['implementer'], 16),
-                                 int(cpu['partnum'], 16), [])
+            cpu_model = CpuModel(
+                cpu['name'],
+                int(cpu.get('implementer', '0'), 16),
+                int(cpu.get('partnum', '0'), 16),
+                int(cpu.get('mvendorid', '0'), 16),
+                cpu.get('marchid', '0'),
+                cpu.get('mimpid', '0'),
+                []
+            )
             cpu_index = len(self.cpus)
+
             self.cpus.append(cpu_model)
             # Load common events supported in this cpu model.
             for number in cpu['common_events']:
@@ -167,60 +179,125 @@ class ArchData:
         raise Exception(f'no event for event number {event_number}')
 
 
+class X86ArchData:
+    def __init__(self, arch: str):
+        self.arch = arch
+        self.events: List[RawEvent] = []
+
+    def load_from_json_data(self, data) -> None:
+        for event in data['events']:
+            number = int(event[0], 16)
+            name = event[1]
+            desc = event[2]
+            self.events.append(RawEvent(number, name, desc, self.arch))
+
+
 class RawEventGenerator:
     def __init__(self, event_table_file: str):
         with open(event_table_file, 'r') as fh:
             event_table = json.load(fh)
             self.arm64_data = ArchData('arm64')
             self.arm64_data.load_from_json_data(event_table['arm64'])
+            self.riscv64_data = ArchData('riscv64')
+            self.riscv64_data.load_from_json_data(event_table['riscv64'])
+            self.x86_intel_data = X86ArchData('x86-intel')
+            self.x86_intel_data.load_from_json_data(event_table['x86-intel'])
+            self.x86_amd_data = X86ArchData('x86-amd')
+            self.x86_amd_data.load_from_json_data(event_table['x86-amd'])
 
     def generate_raw_events(self) -> str:
-        lines = []
-        for event in self.arm64_data.events:
-            lines.append(gen_event_type_entry_str(event.name, 'PERF_TYPE_RAW', '0x%x' %
+        def generate_event_entries(events, guard) -> list:
+            lines = []
+            for event in events:
+                lines.append(gen_event_type_entry_str(event.name, 'PERF_TYPE_RAW', '0x%x' %
                          event.number, event.desc, event.limited_arch))
-        return self.add_arm_guard(''.join(lines))
+            return guard(''.join(lines))
+
+        lines_arm64 = generate_event_entries(self.arm64_data.events, self.add_arm_guard)
+        lines_riscv64 = generate_event_entries(self.riscv64_data.events, self.add_riscv_guard)
+        lines_x86_intel = generate_event_entries(self.x86_intel_data.events, self.add_x86_guard)
+        lines_x86_amd = generate_event_entries(self.x86_amd_data.events, self.add_x86_guard)
+
+        return lines_arm64 + lines_riscv64 + lines_x86_intel + lines_x86_amd
 
     def generate_cpu_support_events(self) -> str:
-        text = """
-        // Map from cpu model to raw events supported on that cpu.',
-        std::unordered_map<std::string, std::unordered_set<int>> cpu_supported_raw_events = {
+        def generate_cpu_events(data, guard) -> str:
+            lines = []
+            for cpu in data:
+                event_list = ', '.join('0x%x' % number for number in cpu.supported_raw_events)
+                lines.append('{"%s", {%s}},' % (cpu.name, event_list))
+            return guard('\n'.join(lines))
+
+        text = f"""
+        // Map from cpu model to raw events supported on that cpu.
+        std::unordered_map<std::string, std::unordered_set<int>> cpu_supported_raw_events = {{
+        {generate_cpu_events(self.arm64_data.cpus, self.add_arm_guard)}
+        {generate_cpu_events(self.riscv64_data.cpus, self.add_riscv_guard)}
+        }};\n
         """
 
-        lines = []
-        for cpu in self.arm64_data.cpus:
-            event_list = ', '.join('0x%x' % number for number in cpu.supported_raw_events)
-            lines.append('{"%s", {%s}},' % (cpu.name, event_list))
-        text += self.add_arm_guard('\n'.join(lines))
-        text += '};\n'
         return text
 
     def generate_cpu_models(self) -> str:
-        text = """
-        std::unordered_map<uint64_t, std::string> arm64_cpuid_to_name = {
-        """
-        lines = []
-        for cpu in self.arm64_data.cpus:
-            cpu_id = (cpu.implementer << 32) | cpu.partnum
-            lines.append('{0x%xull, "%s"},' % (cpu_id, cpu.name))
-        text += '\n'.join(lines)
-        text += '};\n'
-        return self.add_arm_guard(text)
+        def generate_model(data, map_type, map_key_type, id_func) -> str:
+            lines = [f'std::{map_type}<{map_key_type}, std::string> cpuid_to_name = {{']
+            for cpu in data:
+                cpu_id = id_func(cpu)
+                lines.append(f'{{{cpu_id}, "{cpu.name}"}},')
+            lines.append('};')
+            return '\n'.join(lines)
+
+        arm64_model = generate_model(
+            self.arm64_data.cpus,
+            "unordered_map",
+            "uint64_t",
+            lambda cpu: f"0x{((cpu.implementer << 32) | cpu.partnum):x}ull"
+        )
+
+        riscv64_model = generate_model(
+            self.riscv64_data.cpus,
+            "map",
+            "std::tuple<uint64_t, std::string, std::string>",
+            lambda cpu: f'{{0x{cpu.mvendorid:x}ull, "{cpu.marchid}", "{cpu.mimpid}"}}'
+        )
+
+        return self.add_arm_guard(arm64_model) + "\n" + self.add_riscv_guard(riscv64_model)
 
     def add_arm_guard(self, data: str) -> str:
         return f'#if defined(__aarch64__) || defined(__arm__)\n{data}\n#endif\n'
 
+    def add_riscv_guard(self, data: str) -> str:
+        return f'#if defined(__riscv)\n{data}\n#endif\n'
+
+    def add_x86_guard(self, data: str) -> str:
+        return f'#if defined(__i386__) || defined(__x86_64__)\n{data}\n#endif\n'
+
 
 def gen_events(event_table_file: str):
     generated_str = """
         #include <unordered_map>
         #include <unordered_set>
+        #include <map>
+        #include <string_view>
 
         #include "event_type.h"
 
         namespace simpleperf {
 
-        std::set<EventType> builtin_event_types = {
+        // A constexpr-constructible version of EventType for the built-in table.
+        struct BuiltinEventType {
+          std::string_view name;
+          uint32_t type;
+          uint64_t config;
+          std::string_view description;
+          std::string_view limited_arch;
+
+          explicit operator EventType() const {
+            return {std::string(name), type, config, std::string(description), std::string(limited_arch)};
+          }
+        };
+
+        static constexpr BuiltinEventType kBuiltinEventTypes[] = {
     """
     generated_str += gen_hardware_events() + '\n'
     generated_str += gen_software_events() + '\n'
@@ -230,6 +307,12 @@ def gen_events(event_table_file: str):
     generated_str += """
         };
 
+        void LoadBuiltinEventTypes(std::set<EventType>& set) {
+          for (const auto& event_type : kBuiltinEventTypes) {
+            set.insert(static_cast<EventType>(event_type));
+          }
+        }
+
 
     """
     generated_str += raw_event_generator.generate_cpu_support_events()
diff --git a/simpleperf/event_type.cpp b/simpleperf/event_type.cpp
index d8379141..fef1a9f1 100644
--- a/simpleperf/event_type.cpp
+++ b/simpleperf/event_type.cpp
@@ -44,7 +44,7 @@ struct EventFormat {
   int shift;
 };
 
-extern std::set<EventType> builtin_event_types;
+void LoadBuiltinEventTypes(std::set<EventType>&);
 
 enum class EventFinderType {
   BUILTIN,
@@ -93,7 +93,7 @@ class BuiltinTypeFinder : public EventTypeFinder {
   BuiltinTypeFinder() : EventTypeFinder(EventFinderType::BUILTIN) {}
 
  protected:
-  void LoadTypes() override { types_ = std::move(builtin_event_types); }
+  void LoadTypes() override { LoadBuiltinEventTypes(types_); }
 };
 
 class TracepointStringFinder : public EventTypeFinder {
diff --git a/simpleperf/scripts/.gitignore b/simpleperf/scripts/.gitignore
new file mode 100644
index 00000000..19ceb163
--- /dev/null
+++ b/simpleperf/scripts/.gitignore
@@ -0,0 +1 @@
+binary_cache/
diff --git a/simpleperf/scripts/simpleperf_utils.py b/simpleperf/scripts/simpleperf_utils.py
index e536b1b5..93cd76d9 100644
--- a/simpleperf/scripts/simpleperf_utils.py
+++ b/simpleperf/scripts/simpleperf_utils.py
@@ -367,20 +367,31 @@ class AdbHelper(object):
 
     def get_android_version(self) -> int:
         """ Get Android version on device, like 7 is for Android N, 8 is for Android O."""
-        build_version = self.get_property('ro.build.version.codename')
-        if not build_version or build_version == 'REL':
-            build_version = self.get_property('ro.build.version.release')
-        android_version = 0
-        if build_version:
-            if build_version[0].isdigit():
+        def parse_version(s: str) -> int:
+            if not s:
+                return 0
+            if s[0].isdigit():
                 i = 1
-                while i < len(build_version) and build_version[i].isdigit():
+                while i < len(s) and s[i].isdigit():
                     i += 1
-                android_version = int(build_version[:i])
+                return int(s[:i])
             else:
-                c = build_version[0].upper()
-                if c.isupper() and c >= 'L':
-                    android_version = ord(c) - ord('L') + 5
+                c = s[0].upper()
+                if c.isupper() and 'L' <= c <= 'V':
+                    return ord(c) - ord('L') + 5
+            return 0
+
+        android_version = 0
+        s = self.get_property('ro.build.version.codename')
+        if s != 'REL':
+            android_version = parse_version(s)
+        if android_version == 0:
+            s = self.get_property('ro.build.version.release')
+            android_version = parse_version(s)
+        if android_version == 0:
+            s = self.get_property('ro.build.version.sdk')
+            if int(s) >= 35:
+                android_version = 15
         return android_version
 
 
diff --git a/simpleperf/scripts/test/app_profiler_test.py b/simpleperf/scripts/test/app_profiler_test.py
index b6b39ba8..99982f5f 100644
--- a/simpleperf/scripts/test/app_profiler_test.py
+++ b/simpleperf/scripts/test/app_profiler_test.py
@@ -62,6 +62,9 @@ class TestNativeProfiling(TestBase):
             stderr=subprocess.PIPE, text=True)
         self.assertIn('No Android device is connected via ADB.', proc.stderr)
 
+    def test_android_version(self):
+        self.assertGreaterEqual(TestHelper.adb.get_android_version(), 9)
+
 
 class TestNativeLibDownloader(TestBase):
     def setUp(self):
diff --git a/simpleperf/testdata/etm/old_branch_list.data b/simpleperf/testdata/etm/old_branch_list.data
new file mode 100644
index 00000000..434f4178
Binary files /dev/null and b/simpleperf/testdata/etm/old_branch_list.data differ
diff --git a/torq/Android.bp b/torq/Android.bp
index 94d25d5c..e3245df1 100644
--- a/torq/Android.bp
+++ b/torq/Android.bp
@@ -27,6 +27,8 @@ python_defaults {
         "device.py",
         "config_builder.py",
         "open_ui.py",
+        "utils.py",
+        "validate_simpleperf.py",
     ],
 }
 
@@ -99,3 +101,19 @@ python_test_host {
         unit_test: true,
     },
 }
+
+python_test_host {
+    name: "validate_simpleperf_unit_test",
+    main: "tests/validate_simpleperf_unit_test.py",
+    srcs: ["tests/validate_simpleperf_unit_test.py"],
+    defaults: ["torq_defaults"],
+    version: {
+        py3: {
+            enabled: true,
+            embedded_launcher: false,
+        },
+    },
+    test_options: {
+        unit_test: true,
+    },
+}
diff --git a/torq/README.md b/torq/README.md
index 70ea7705..128669fd 100644
--- a/torq/README.md
+++ b/torq/README.md
@@ -56,6 +56,8 @@ cpu-cycles and instructions, are collected.
 config.
 ### ./torq config show memory
 - Print the contents of the memory predefined Perfetto config to the terminal.
+### ./torq open trace.perfetto-trace
+- Open a trace in the perfetto UI.
 ### ./torq -d 10000 --exclude-ftrace-event power/cpu_idle
 - Run a custom event for 10 seconds, using the "default" predefined Perfetto
 config, in which the ftrace event, power/cpu_idle, is not collected.
@@ -63,28 +65,29 @@ config, in which the ftrace event, power/cpu_idle, is not collected.
 
 ## CLI Arguments
 
-| Argument                 | Description                                                                                                                                                                                                                                                                        | Currently Supported Arguments                                                                | Default                    |
-|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|----------------------------|
-| `-e, --event`            | The event to trace/profile.                                                                                                                                                                                                                                                        | `boot`, `user-switch`,`app-startup`, `custom`                                                | `custom`                   |
-| `-p, --profiler`         | The performance data profiler.                                                                                                                                                                                                                                                     | `perfetto`, (`simpleperf` coming soon)                                                       | `perfetto`                 |
-| `-o, --out-dir`          | The path to the output directory.                                                                                                                                                                                                                                                  | Any local path                                                                               | Current directory: `.`     |
-| `-d, --dur-ms`           | The duration (ms) of the event. Determines when to stop collecting performance data.                                                                                                                                                                                               | Float >= `3000`                                                                              | `10000`                    |
-| `-a, --app`              | The package name of the app to start.<br/>(Requires use of `-e app-startup`)                                                                                                                                                                                                       | Any package on connected device                                                              |                            |
-| `-r, --runs`             | The amount of times to run the event and capture the performance data.                                                                                                                                                                                                             | Integer >= `1`                                                                               | `1`                        |
-| `--serial`               | The serial of the connected device that you want to use.<br/>(If not provided, the ANDROID_SERIAL environment variable is used. If ANDROID_SERIAL is also not set and there is only one device connected, the device is chosen.)                                                   |                                                                                              |                            |
-| `--perfetto-config`      | The local file path of the user's Perfetto config or used to specify a predefined Perfetto configs.                                                                                                                                                                                | `default`, any local perfetto config,<br/>(`lightweight`, `memory` coming soon)              | `default`                  |
-| `--between-dur-ms`       | The amount of time (ms) to wait between different runs.<br/>(Requires that `--r` is set to a value greater than 1)                                                                                                                                                                 | Float >= `3000`                                                                              | `10000`                    |
-| `--ui`                   | Specifies opening of UI visualization tool after profiling is complete.<br/>(Requires that `-r` is not set to a value greater than 1)                                                                                                                                              | `--ui`, `--no-ui`,                                                                           | `ui` if `runs` is `1`      |
-| `--exclude-ftrace-event` | Excludes the ftrace event from the Perfetto config. Can be defined multiple times in a command.<br/>(Requires use of `-p perfetto`)<br/>(Currently only works with `--perfetto-config default`,<br/>support for local Perfetto configs, `lightweight`, and `memory` coming soon)   | Any supported perfetto ftrace event<br/>(e.g., `power/cpu_idle`, `sched/sched_process_exit`) | Empty list                 |
-| `--include-ftrace-event` | Includes the ftrace event in the Perfetto config. Can be defined multiple times in a command.<br/>(Requires use of `-p perfetto`)<br/>(Currently only works with `--perfetto-config default`,<br/>support for any local Perfetto configs, `lightweight`, and `memory` coming soon) | Any supported perfetto ftrace event<br/>(e.g., `power/cpu_idle`, `sched/sched_process_exit`) | Empty list                 |
-| `--from-user`            | The user ID from which to start the user switch. (Requires use of `-e user-switch`)                                                                                                                                                                                                | ID of any user on connected device                                                           | Current user on the device |
-| `--to-user`              | The user ID of user that device is switching to. (Requires use of `-e user-switch`).                                                                                                                                                                                               | ID of any user on connected device                                                           |                            |
+| Argument                                | Description                                                                                                                                                                                                                                                                        | Currently Supported Arguments                                                                | Default                              |
+|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|--------------------------------------|
+| `-e, --event`                           | The event to trace/profile.                                                                                                                                                                                                                                                        | `boot`, `user-switch`,`app-startup`, `custom`                                                | `custom`                             |
+| `-p, --profiler`                        | The performance data profiler.                                                                                                                                                                                                                                                     | `perfetto`, (`simpleperf` coming soon)                                                       | `perfetto`                           |
+| `-o, --out-dir`                         | The path to the output directory.                                                                                                                                                                                                                                                  | Any local path                                                                               | Current directory: `.`               |
+| `-d, --dur-ms`                          | The duration (ms) of the event. Determines when to stop collecting performance data.                                                                                                                                                                                               | Float >= `3000`                                                                              | `10000`                              |
+| `-a, --app`                             | The package name of the app to start.<br/>(Requires use of `-e app-startup`)                                                                                                                                                                                                       | Any package on connected device                                                              |                                      |
+| `-r, --runs`                            | The amount of times to run the event and capture the performance data.                                                                                                                                                                                                             | Integer >= `1`                                                                               | `1`                                  |
+| `--serial`                              | The serial of the connected device that you want to use.<br/>(If not provided, the ANDROID_SERIAL environment variable is used. If ANDROID_SERIAL is also not set and there is only one device connected, the device is chosen.)                                                   |                                                                                              |                                      |
+| `--perfetto-config`                     | The local file path of the user's Perfetto config or used to specify a predefined Perfetto configs.                                                                                                                                                                                | `default`, any local perfetto config,<br/>(`lightweight`, `memory` coming soon)              | `default`                            |
+| `--between-dur-ms`                      | The amount of time (ms) to wait between different runs.<br/>(Requires that `--r` is set to a value greater than 1)                                                                                                                                                                 | Float >= `3000`                                                                              | `10000`                              |
+| `--ui`                                  | Specifies opening of UI visualization tool after profiling is complete.<br/>(Requires that `-r` is not set to a value greater than 1)                                                                                                                                              | `--ui`, `--no-ui`,                                                                           | `ui` if `runs` is `1`                |
+| `--exclude-ftrace-event`                | Excludes the ftrace event from the Perfetto config. Can be defined multiple times in a command.<br/>(Requires use of `-p perfetto`)<br/>(Currently only works with `--perfetto-config default`,<br/>support for local Perfetto configs, `lightweight`, and `memory` coming soon)   | Any supported perfetto ftrace event<br/>(e.g., `power/cpu_idle`, `sched/sched_process_exit`) | Empty list                           |
+| `--include-ftrace-event`                | Includes the ftrace event in the Perfetto config. Can be defined multiple times in a command.<br/>(Requires use of `-p perfetto`)<br/>(Currently only works with `--perfetto-config default`,<br/>support for any local Perfetto configs, `lightweight`, and `memory` coming soon) | Any supported perfetto ftrace event<br/>(e.g., `power/cpu_idle`, `sched/sched_process_exit`) | Empty list                           |
+| `--from-user`                           | The user ID from which to start the user switch. (Requires use of `-e user-switch`)                                                                                                                                                                                                | ID of any user on connected device                                                           | Current user on the device           |
+| `--to-user`                             | The user ID of user that device is switching to. (Requires use of `-e user-switch`).                                                                                                                                                                                               | ID of any user on connected device                                                           |                                      |
+| `config list`                           | Subcommand to list the predefined Perfetto configs (`default`, `lightweight`, `memory`).                                                                                                                                                                                           |                                                                                              |                                      |
+| `config show <config-name>`             | Subcommand to print the contents of a predefined Perfetto config to the terminal.                                                                                                                                                                                                  | `default`, `lightweight`, `memory`                                                           |                                      |
+| `config pull <config-name> [file-path]` | Subcommand to download a predefined Perfetto config to a specified local file path.                                                                                                                                                                                                | <config-name>: `default`, `lightweight`, `memory`<br/> [file-path]: Any local file path      | [file-path]: `./<config-name>.pbtxt` |
+| `open <file-path>`                      | Subcommand to open a Perfetto or Simpleperf trace in the Perfetto UI.                                                                                                                                                                                                              | Any local path to a Perfetto or Simpleperf trace file                                        |                                      |
 
 ## Functionality Coming Soon
 
 | Argument                                | Description                                                                                                                                                   | Accepted Values                                                                         | Default                               |
 |-----------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|---------------------------------------|
 | `-s, --simpleperf-event`                | Simpleperf supported events that should be collected. Can be defined multiple times in a command.                                                             | Any supported simpleperf event<br/>(e.g., `cpu-cycles`, `instructions`)                 | Empty list                            |
-| `config list`                           | Subcommand to list the predefined Perfetto configs (`default`, `lightweight`, `memory`).                                                                      |                                                                                         |                                       |
-| `config show <config-name>`             | Subcommand to print the contents of a predefined Perfetto config to the terminal.                                                                             | `default`, `lightweight`, `memory`                                                      |                                       |
-| `config pull <config-name> [file-path]` | Subcommand to download a predefined Perfetto config to a specified local file path.                                                                           | <config-name>: `default`, `lightweight`, `memory`<br/> [file-path]: Any local file path | [file-path]: `./<config-name>.config` |
diff --git a/torq/command.py b/torq/command.py
index 9148abcb..a2a72620 100644
--- a/torq/command.py
+++ b/torq/command.py
@@ -17,9 +17,11 @@
 from abc import ABC, abstractmethod
 from command_executor import ProfilerCommandExecutor, \
   UserSwitchCommandExecutor, BootCommandExecutor, AppStartupCommandExecutor, \
-  HWCommandExecutor, ConfigCommandExecutor
+  ConfigCommandExecutor, WEB_UI_ADDRESS
 from validation_error import ValidationError
+from open_ui import open_trace
 
+ANDROID_SDK_VERSION_T = 33
 
 class Command(ABC):
   """
@@ -78,10 +80,14 @@ class ProfilerCommand(Command):
   def validate(self, device):
     print("Further validating arguments of ProfilerCommand.")
     if self.simpleperf_event is not None:
-      device.simpleperf_event_exists(self.simpleperf_event)
+      error = device.simpleperf_event_exists(self.simpleperf_event)
+      if error is not None:
+        return error
     match self.event:
       case "user-switch":
         return self.validate_user_switch(device)
+      case "boot":
+        return self.validate_boot(device)
       case "app-startup":
         return self.validate_app_startup(device)
 
@@ -104,6 +110,16 @@ class ProfilerCommand(Command):
                              " the --from-user ID.")
     return None
 
+  @staticmethod
+  def validate_boot(device):
+    if device.get_android_sdk_version() < ANDROID_SDK_VERSION_T:
+      return ValidationError(
+          ("Cannot perform trace on boot because only devices with version Android 13"
+           " (T) or newer can be configured to automatically start recording traces on"
+           " boot."), ("Update your device or use a different device with"
+                      " Android 13 (T) or newer."))
+    return None
+
   def validate_app_startup(self, device):
     packages = device.get_packages()
     if self.app not in packages:
@@ -121,45 +137,34 @@ class ProfilerCommand(Command):
     return None
 
 
-class HWCommand(Command):
+class ConfigCommand(Command):
   """
-  Represents commands which get information from the device or changes the
-  device's hardware.
+  Represents commands which get information about the predefined configs.
   """
-  def __init__(self, type, hw_config, num_cpus, memory):
+  def __init__(self, type, config_name, file_path, dur_ms,
+      excluded_ftrace_events, included_ftrace_events):
     super().__init__(type)
-    self.hw_config = hw_config
-    self.num_cpus = num_cpus
-    self.memory = memory
-    self.command_executor = HWCommandExecutor()
+    self.config_name = config_name
+    self.file_path = file_path
+    self.dur_ms = dur_ms
+    self.excluded_ftrace_events = excluded_ftrace_events
+    self.included_ftrace_events = included_ftrace_events
+    self.command_executor = ConfigCommandExecutor()
 
   def validate(self, device):
-    print("Further validating arguments of HWCommand.")
-    if self.num_cpus is not None:
-      if self.num_cpus > device.get_max_num_cpus():
-        return ValidationError(("The number of cpus requested is not"
-                                " available on the device. Requested: %d,"
-                                " Available: %d"
-                                % (self.num_cpus, device.get_max_num_cpus())),
-                               None)
-    if self.memory is not None:
-      if self.memory > device.get_max_memory():
-        return ValidationError(("The amount of memory requested is not"
-                                "available on the device. Requested: %s,"
-                                " Available: %s"
-                                % (self.memory, device.get_max_memory())), None)
-    return None
+    raise NotImplementedError
 
 
-class ConfigCommand(Command):
+class OpenCommand(Command):
   """
-  Represents commands which get information about the predefined configs.
+  Represents commands which open traces.
   """
-  def __init__(self, type, config_name, file_path):
+  def __init__(self, file_path):
     super().__init__(type)
-    self.config_name = config_name
     self.file_path = file_path
-    self.command_executor = ConfigCommandExecutor()
 
   def validate(self, device):
     raise NotImplementedError
+
+  def execute(self, device):
+    open_trace(self.file_path, WEB_UI_ADDRESS)
diff --git a/torq/command_executor.py b/torq/command_executor.py
index dba9a29b..20ce3a44 100644
--- a/torq/command_executor.py
+++ b/torq/command_executor.py
@@ -14,15 +14,20 @@
 # limitations under the License.
 #
 
+import datetime
+import subprocess
 import time
 from abc import ABC, abstractmethod
 from config_builder import PREDEFINED_PERFETTO_CONFIGS, build_custom_config
 from open_ui import open_trace
+from device import SIMPLEPERF_TRACE_FILE
 
 PERFETTO_TRACE_FILE = "/data/misc/perfetto-traces/trace.perfetto-trace"
 PERFETTO_BOOT_TRACE_FILE = "/data/misc/perfetto-traces/boottrace.perfetto-trace"
-PERFETTO_WEB_UI_ADDRESS = "https://ui.perfetto.dev"
-PERFETTO_TRACE_START_DELAY_SECS = 0.5
+WEB_UI_ADDRESS = "https://ui.perfetto.dev"
+TRACE_START_DELAY_SECS = 0.5
+MAX_WAIT_FOR_INIT_USER_SWITCH_SECS = 180
+ANDROID_SDK_VERSION_T = 33
 
 
 class CommandExecutor(ABC):
@@ -50,7 +55,7 @@ class CommandExecutor(ABC):
 class ProfilerCommandExecutor(CommandExecutor):
 
   def execute_command(self, command, device):
-    config, error = self.create_config(command)
+    config, error = self.create_config(command, device.get_android_sdk_version())
     if error is not None:
       return error
     error = self.prepare_device(command, device, config)
@@ -58,8 +63,12 @@ class ProfilerCommandExecutor(CommandExecutor):
       return error
     host_file = None
     for run in range(1, command.runs + 1):
-      host_file = f"{command.out_dir}/trace-{run}.perfetto-trace"
-      error = self.prepare_device_for_run(command, device, run)
+      timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
+      if command.profiler == "perfetto":
+        host_file = f"{command.out_dir}/trace-{timestamp}.perfetto-trace"
+      else:
+        host_file = f"{command.out_dir}/perf-{timestamp}.data"
+      error = self.prepare_device_for_run(command, device)
       if error is not None:
         return error
       error = self.execute_run(command, device, config, run)
@@ -74,28 +83,36 @@ class ProfilerCommandExecutor(CommandExecutor):
     if error is not None:
       return error
     if command.use_ui:
-      open_trace(host_file, PERFETTO_WEB_UI_ADDRESS)
+      open_trace(host_file, WEB_UI_ADDRESS)
     return None
 
-  def create_config(self, command):
+  @staticmethod
+  def create_config(command, android_sdk_version):
     if command.perfetto_config in PREDEFINED_PERFETTO_CONFIGS:
-      return PREDEFINED_PERFETTO_CONFIGS[command.perfetto_config](command)
+      return PREDEFINED_PERFETTO_CONFIGS[command.perfetto_config](
+          command, android_sdk_version)
     else:
       return build_custom_config(command)
 
   def prepare_device(self, command, device, config):
     return None
 
-  def prepare_device_for_run(self, command, device, run):
-    device.remove_file(PERFETTO_TRACE_FILE)
+  def prepare_device_for_run(self, command, device):
+    if command.profiler == "perfetto":
+      device.remove_file(PERFETTO_TRACE_FILE)
+    else:
+      device.remove_file(SIMPLEPERF_TRACE_FILE)
 
   def execute_run(self, command, device, config, run):
     print("Performing run %s" % run)
-    process = device.start_perfetto_trace(config)
-    time.sleep(PERFETTO_TRACE_START_DELAY_SECS)
+    if command.profiler == "perfetto":
+      process = device.start_perfetto_trace(config)
+    else:
+      process = device.start_simpleperf_trace(command)
+    time.sleep(TRACE_START_DELAY_SECS)
     error = self.trigger_system_event(command, device)
     if error is not None:
-      device.kill_pid("perfetto")
+      device.kill_pid(command.profiler)
       return error
     process.wait()
 
@@ -103,7 +120,10 @@ class ProfilerCommandExecutor(CommandExecutor):
     return None
 
   def retrieve_perf_data(self, command, device, host_file):
-    device.pull_file(PERFETTO_TRACE_FILE, host_file)
+    if command.profiler == "perfetto":
+      device.pull_file(PERFETTO_TRACE_FILE, host_file)
+    else:
+      device.pull_file(SIMPLEPERF_TRACE_FILE, host_file)
 
   def cleanup(self, command, device):
     return None
@@ -111,13 +131,21 @@ class ProfilerCommandExecutor(CommandExecutor):
 
 class UserSwitchCommandExecutor(ProfilerCommandExecutor):
 
-  def prepare_device_for_run(self, command, device, run):
-    super().prepare_device_for_run(command, device, run)
+  def prepare_device_for_run(self, command, device):
+    super().prepare_device_for_run(command, device)
     current_user = device.get_current_user()
     if command.from_user != current_user:
-      print("Switching from the current user, %s, to the from-user, %s."
-            % (current_user, command.from_user))
+      dur_seconds = min(command.dur_ms / 1000,
+                        MAX_WAIT_FOR_INIT_USER_SWITCH_SECS)
+      print("Switching from the current user, %s, to the from-user, %s. Waiting"
+            " for %s seconds."
+            % (current_user, command.from_user, dur_seconds))
       device.perform_user_switch(command.from_user)
+      time.sleep(dur_seconds)
+      if device.get_current_user() != command.from_user:
+        raise Exception(("Device with serial %s took more than %d secs to "
+                         "switch to the initial user."
+                         % (device.serial, dur_seconds)))
 
   def trigger_system_event(self, command, device):
     print("Switching from the from-user, %s, to the to-user, %s."
@@ -136,7 +164,7 @@ class BootCommandExecutor(ProfilerCommandExecutor):
   def prepare_device(self, command, device, config):
     device.write_to_file("/data/misc/perfetto-configs/boottrace.pbtxt", config)
 
-  def prepare_device_for_run(self, command, device, run):
+  def prepare_device_for_run(self, command, device):
     device.remove_file(PERFETTO_BOOT_TRACE_FILE)
     device.set_prop("persist.debug.perfetto.boottrace", "1")
 
@@ -169,53 +197,37 @@ class AppStartupCommandExecutor(ProfilerCommandExecutor):
     return device.start_package(command.app)
 
 
-class HWCommandExecutor(CommandExecutor):
-
-  def execute_command(self, hw_command, device):
-    match hw_command.get_type():
-      case "hw set":
-        return self.execute_hw_set_command(device, hw_command.hw_config,
-                                           hw_command.num_cpus,
-                                           hw_command.memory)
-      case "hw get":
-        return self.execute_hw_get_command(device)
-      case "hw list":
-        return self.execute_hw_list_command(device)
-      case _:
-        raise ValueError("Invalid hw subcommand was used.")
-
-  def execute_hw_set_command(self, device, hw_config, num_cpus, memory):
-    return None
-
-  def execute_hw_get_command(self, device):
-    return None
-
-  def execute_hw_list_command(self, device):
-    return None
-
-
 class ConfigCommandExecutor(CommandExecutor):
 
   def execute(self, command, device):
     return self.execute_command(command, device)
 
-  def execute_command(self, config_command, device):
-    match config_command.get_type():
+  def execute_command(self, command, device):
+    match command.get_type():
       case "config list":
-        return self.execute_config_list_command()
-      case "config show":
-        return self.execute_config_show_command(config_command.config_name)
-      case "config pull":
-        return self.execute_config_pull_command(config_command.config_name,
-                                                config_command.file_path)
+        print("\n".join(list(PREDEFINED_PERFETTO_CONFIGS.keys())))
+        return None
+      case "config show" | "config pull":
+        return self.execute_config_command(command, device)
       case _:
         raise ValueError("Invalid config subcommand was used.")
 
-  def execute_config_list_command(self):
-    return None
+  def execute_config_command(self, command, device):
+    android_sdk_version = ANDROID_SDK_VERSION_T
+    error = device.check_device_connection()
+    if error is None:
+      device.root_device()
+      android_sdk_version = device.get_android_sdk_version()
 
-  def execute_config_show_command(self, config_name):
-    return None
+    config, error = PREDEFINED_PERFETTO_CONFIGS[command.config_name](
+        command, android_sdk_version)
+
+    if error is not None:
+      return error
+
+    if command.get_type() == "config pull":
+      subprocess.run(("cat > %s %s" % (command.file_path, config)), shell=True)
+    else:
+      print("\n".join(config.strip().split("\n")[2:-2]))
 
-  def execute_config_pull_command(self, config_name, file_path):
     return None
diff --git a/torq/config_builder.py b/torq/config_builder.py
index ce94cf2c..fab42d6a 100644
--- a/torq/config_builder.py
+++ b/torq/config_builder.py
@@ -17,6 +17,8 @@
 import textwrap
 from validation_error import ValidationError
 
+ANDROID_SDK_VERSION_T = 33
+
 
 def create_ftrace_events_string(predefined_ftrace_events,
     excluded_ftrace_events, included_ftrace_events):
@@ -51,7 +53,7 @@ def create_ftrace_events_string(predefined_ftrace_events,
   return ftrace_events_string, None
 
 
-def build_default_config(command):
+def build_default_config(command, android_sdk_version):
   if command.dur_ms is None:
     # This is always defined because it has a default value that is always
     # set in torq.py.
@@ -91,6 +93,9 @@ def build_default_config(command):
       command.included_ftrace_events)
   if error is not None:
     return None, error
+  cpufreq_period_string = "cpufreq_period_ms: 500"
+  if android_sdk_version < ANDROID_SDK_VERSION_T:
+    cpufreq_period_string = ""
   config = f'''\
     <<EOF
 
@@ -164,8 +169,7 @@ def build_default_config(command):
           vmstat_counters: VMSTAT_PGSCAN_KSWAPD
           vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
           vmstat_counters: VMSTAT_WORKINGSET_REFAULT
-          # Below field not available on < Android SC-V2 releases.
-          cpufreq_period_ms: 500
+          {cpufreq_period_string}
         }}
       }}
     }}
@@ -234,11 +238,11 @@ def build_default_config(command):
   return textwrap.dedent(config), None
 
 
-def build_lightweight_config(command):
+def build_lightweight_config(command, android_sdk_version):
   raise NotImplementedError
 
 
-def build_memory_config(command):
+def build_memory_config(command, android_sdk_version):
   raise NotImplementedError
 
 
@@ -275,4 +279,3 @@ def build_custom_config(command):
                                   % (command.perfetto_config, str(e))), None)
   config_string = f"<<EOF\n\n{file_content}\n{appended_duration}\n\nEOF"
   return config_string, None
-
diff --git a/torq/device.py b/torq/device.py
index 93df1a21..323c3001 100644
--- a/torq/device.py
+++ b/torq/device.py
@@ -14,15 +14,17 @@
 # limitations under the License.
 #
 
-import subprocess
+import math
 import os
+import subprocess
 import time
+
 from validation_error import ValidationError
 
 ADB_ROOT_TIMED_OUT_LIMIT_SECS = 5
 ADB_BOOT_COMPLETED_TIMED_OUT_LIMIT_SECS = 30
 POLLING_INTERVAL_SECS = 0.5
-
+SIMPLEPERF_TRACE_FILE = "/data/misc/perfetto-traces/perf.data"
 
 class AdbDevice:
   """
@@ -97,7 +99,7 @@ class AdbDevice:
                        " being rooted." % self.serial))
 
   def remove_file(self, file_path):
-    subprocess.run(["adb", "-s", self.serial, "shell", "rm", file_path])
+    subprocess.run(["adb", "-s", self.serial, "shell", "rm", "-f", file_path])
 
   def start_perfetto_trace(self, config):
     return subprocess.Popen(("adb -s %s shell perfetto -c - --txt -o"
@@ -105,6 +107,16 @@ class AdbDevice:
                              "trace.perfetto-trace %s"
                              % (self.serial, config)), shell=True)
 
+  def start_simpleperf_trace(self, command):
+    events_param = "-e " + ",".join(command.simpleperf_event)
+    return subprocess.Popen(("adb -s %s shell simpleperf record -a -f 1000 "
+                             "--post-unwind=yes -m 8192 -g --duration %d"
+                             " %s -o %s"
+                             % (self.serial,
+                                int(math.ceil(command.dur_ms/1000)),
+                                events_param, SIMPLEPERF_TRACE_FILE)),
+                            shell=True)
+
   def pull_file(self, file_path, host_file):
     subprocess.run(["adb", "-s", self.serial, "pull", file_path, host_file])
 
@@ -143,6 +155,12 @@ class AdbDevice:
 
   def reboot(self):
     subprocess.run(["adb", "-s", self.serial, "reboot"])
+    if not self.poll_is_task_completed(ADB_ROOT_TIMED_OUT_LIMIT_SECS,
+                                       POLLING_INTERVAL_SECS,
+                                       lambda: self.serial not in
+                                               self.get_adb_devices()):
+      raise Exception(("Device with serial %s took too long to start"
+                       " rebooting." % self.serial))
 
   def wait_for_device(self):
     subprocess.run(["adb", "-s", self.serial, "wait-for-device"])
@@ -192,26 +210,45 @@ class AdbDevice:
     subprocess.run(["adb", "-s", self.serial, "shell", "am", "force-stop",
                     package])
 
-  def get_num_cpus(self):
-    raise NotImplementedError
-
-  def get_memory(self):
-    raise NotImplementedError
-
-  def get_max_num_cpus(self):
-    raise NotImplementedError
-
-  def get_max_memory(self):
-    raise NotImplementedError
-
-  def set_hw_config(self, hw_config):
-    raise NotImplementedError
-
-  def set_num_cpus(self, num_cpus):
-    raise NotImplementedError
-
-  def set_memory(self, memory):
-    raise NotImplementedError
-
-  def simpleperf_event_exists(self, simpleperf_event):
-    raise NotImplementedError
+  def get_prop(self, prop):
+    return subprocess.run(
+        ["adb", "-s", self.serial, "shell", "getprop", prop],
+        capture_output=True).stdout.decode("utf-8").split("\n")[0]
+
+  def get_android_sdk_version(self):
+    return int(self.get_prop("ro.build.version.sdk"))
+
+  def simpleperf_event_exists(self, simpleperf_events):
+    events_copy = simpleperf_events.copy()
+    grep_command = "grep"
+    for event in simpleperf_events:
+      grep_command += " -e " + event.lower()
+
+    output = subprocess.run(["adb", "-s", self.serial, "shell",
+                             "simpleperf", "list", "|", grep_command],
+                            capture_output=True)
+
+    if output is None or len(output.stdout) == 0:
+      raise Exception("Error while validating simpleperf events.")
+    lines = output.stdout.decode("utf-8").split("\n")
+
+    # Anything that does not start with two spaces is not a command.
+    # Any command with a space will have the command before the first space.
+    for line in lines:
+      if len(line) <= 3 or line[:2] != "  " or line[2] == "#":
+        # Line doesn't contain a simpleperf event
+        continue
+      event = line[2:].split(" ")[0]
+      if event in events_copy:
+        events_copy.remove(event)
+        if len(events_copy) == 0:
+          # All of the events exist, exit early
+          break
+
+    if len(events_copy) > 0:
+      return ValidationError("The following simpleperf event(s) are invalid:"
+                             " %s."
+                             % events_copy,
+                             "Run adb shell simpleperf list to"
+                             " see valid simpleperf events.")
+    return None
diff --git a/torq/tests/command_executor_unit_test.py b/torq/tests/command_executor_unit_test.py
index 33be392b..19226bf9 100644
--- a/torq/tests/command_executor_unit_test.py
+++ b/torq/tests/command_executor_unit_test.py
@@ -16,13 +16,16 @@
 
 import unittest
 import subprocess
+import sys
+import io
 from unittest import mock
-from command import ProfilerCommand
+from command import ProfilerCommand, ConfigCommand
 from device import AdbDevice
 from validation_error import ValidationError
-from torq import DEFAULT_DUR_MS, DEFAULT_OUT_DIR
+from torq import DEFAULT_DUR_MS, DEFAULT_OUT_DIR, PREDEFINED_PERFETTO_CONFIGS
 
 PROFILER_COMMAND_TYPE = "profiler"
+PROFILER_TYPE = "perfetto"
 TEST_ERROR_MSG = "test-error"
 TEST_EXCEPTION = Exception(TEST_ERROR_MSG)
 TEST_VALIDATION_ERROR = ValidationError(TEST_ERROR_MSG, None)
@@ -35,18 +38,349 @@ TEST_PACKAGE_1 = "test-package-1"
 TEST_PACKAGE_2 = "test-package-2"
 TEST_PACKAGE_3 = "test-package-3"
 TEST_DURATION = 0
+ANDROID_SDK_VERSION_S = 32
+ANDROID_SDK_VERSION_T = 33
+
+TEST_DEFAULT_CONFIG = f'''\
+buffers: {{
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}}
+buffers {{
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}}
+buffers: {{
+  size_kb: 260096
+  fill_policy: RING_BUFFER
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.process_stats"
+    process_stats_config {{
+      scan_all_processes_on_start: true
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.log"
+    android_log_config {{
+    }}
+  }}
+}}
+
+data_sources {{
+  config {{
+    name: "android.packages_list"
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.sys_stats"
+    target_buffer: 1
+    sys_stats_config {{
+      stat_period_ms: 500
+      stat_counters: STAT_CPU_TIMES
+      stat_counters: STAT_FORK_COUNT
+      meminfo_period_ms: 1000
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
+      vmstat_period_ms: 1000
+      vmstat_counters: VMSTAT_PGFAULT
+      vmstat_counters: VMSTAT_PGMAJFAULT
+      vmstat_counters: VMSTAT_PGFREE
+      vmstat_counters: VMSTAT_PGPGIN
+      vmstat_counters: VMSTAT_PGPGOUT
+      vmstat_counters: VMSTAT_PSWPIN
+      vmstat_counters: VMSTAT_PSWPOUT
+      vmstat_counters: VMSTAT_PGSCAN_DIRECT
+      vmstat_counters: VMSTAT_PGSTEAL_DIRECT
+      vmstat_counters: VMSTAT_PGSCAN_KSWAPD
+      vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
+      vmstat_counters: VMSTAT_WORKINGSET_REFAULT
+      cpufreq_period_ms: 500
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.surfaceflinger.frametimeline"
+    target_buffer: 2
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.ftrace"
+    target_buffer: 2
+    ftrace_config {{
+      ftrace_events: "dmabuf_heap/dma_heap_stat"
+      ftrace_events: "ftrace/print"
+      ftrace_events: "gpu_mem/gpu_mem_total"
+      ftrace_events: "ion/ion_stat"
+      ftrace_events: "kmem/ion_heap_grow"
+      ftrace_events: "kmem/ion_heap_shrink"
+      ftrace_events: "kmem/rss_stat"
+      ftrace_events: "lowmemorykiller/lowmemory_kill"
+      ftrace_events: "mm_event/mm_event_record"
+      ftrace_events: "oom/mark_victim"
+      ftrace_events: "oom/oom_score_adj_update"
+      ftrace_events: "power/cpu_frequency"
+      ftrace_events: "power/cpu_idle"
+      ftrace_events: "power/gpu_frequency"
+      ftrace_events: "power/suspend_resume"
+      ftrace_events: "power/wakeup_source_activate"
+      ftrace_events: "power/wakeup_source_deactivate"
+      ftrace_events: "sched/sched_blocked_reason"
+      ftrace_events: "sched/sched_process_exit"
+      ftrace_events: "sched/sched_process_free"
+      ftrace_events: "sched/sched_switch"
+      ftrace_events: "sched/sched_wakeup"
+      ftrace_events: "sched/sched_wakeup_new"
+      ftrace_events: "sched/sched_waking"
+      ftrace_events: "task/task_newtask"
+      ftrace_events: "task/task_rename"
+      ftrace_events: "vmscan/*"
+      ftrace_events: "workqueue/*"
+      atrace_categories: "aidl"
+      atrace_categories: "am"
+      atrace_categories: "dalvik"
+      atrace_categories: "binder_lock"
+      atrace_categories: "binder_driver"
+      atrace_categories: "bionic"
+      atrace_categories: "camera"
+      atrace_categories: "disk"
+      atrace_categories: "freq"
+      atrace_categories: "idle"
+      atrace_categories: "gfx"
+      atrace_categories: "hal"
+      atrace_categories: "input"
+      atrace_categories: "pm"
+      atrace_categories: "power"
+      atrace_categories: "res"
+      atrace_categories: "rro"
+      atrace_categories: "sched"
+      atrace_categories: "sm"
+      atrace_categories: "ss"
+      atrace_categories: "thermal"
+      atrace_categories: "video"
+      atrace_categories: "view"
+      atrace_categories: "wm"
+      atrace_apps: "lmkd"
+      atrace_apps: "system_server"
+      atrace_apps: "com.android.systemui"
+      atrace_apps: "com.google.android.gms"
+      atrace_apps: "com.google.android.gms.persistent"
+      atrace_apps: "android:ui"
+      atrace_apps: "com.google.android.apps.maps"
+      atrace_apps: "*"
+      buffer_size_kb: 16384
+      drain_period_ms: 150
+      symbolize_ksyms: true
+    }}
+  }}
+}}
+duration_ms: 10000
+write_into_file: true
+file_write_period_ms: 5000
+max_file_size_bytes: 100000000000
+flush_period_ms: 5000
+incremental_state_config {{
+  clear_period_ms: 5000
+}}
+'''
+
+TEST_DEFAULT_CONFIG_OLD_ANDROID = f'''\
+buffers: {{
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}}
+buffers {{
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}}
+buffers: {{
+  size_kb: 260096
+  fill_policy: RING_BUFFER
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.process_stats"
+    process_stats_config {{
+      scan_all_processes_on_start: true
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.log"
+    android_log_config {{
+    }}
+  }}
+}}
+
+data_sources {{
+  config {{
+    name: "android.packages_list"
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.sys_stats"
+    target_buffer: 1
+    sys_stats_config {{
+      stat_period_ms: 500
+      stat_counters: STAT_CPU_TIMES
+      stat_counters: STAT_FORK_COUNT
+      meminfo_period_ms: 1000
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
+      vmstat_period_ms: 1000
+      vmstat_counters: VMSTAT_PGFAULT
+      vmstat_counters: VMSTAT_PGMAJFAULT
+      vmstat_counters: VMSTAT_PGFREE
+      vmstat_counters: VMSTAT_PGPGIN
+      vmstat_counters: VMSTAT_PGPGOUT
+      vmstat_counters: VMSTAT_PSWPIN
+      vmstat_counters: VMSTAT_PSWPOUT
+      vmstat_counters: VMSTAT_PGSCAN_DIRECT
+      vmstat_counters: VMSTAT_PGSTEAL_DIRECT
+      vmstat_counters: VMSTAT_PGSCAN_KSWAPD
+      vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
+      vmstat_counters: VMSTAT_WORKINGSET_REFAULT
+
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.surfaceflinger.frametimeline"
+    target_buffer: 2
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.ftrace"
+    target_buffer: 2
+    ftrace_config {{
+      ftrace_events: "dmabuf_heap/dma_heap_stat"
+      ftrace_events: "ftrace/print"
+      ftrace_events: "gpu_mem/gpu_mem_total"
+      ftrace_events: "ion/ion_stat"
+      ftrace_events: "kmem/ion_heap_grow"
+      ftrace_events: "kmem/ion_heap_shrink"
+      ftrace_events: "kmem/rss_stat"
+      ftrace_events: "lowmemorykiller/lowmemory_kill"
+      ftrace_events: "mm_event/mm_event_record"
+      ftrace_events: "oom/mark_victim"
+      ftrace_events: "oom/oom_score_adj_update"
+      ftrace_events: "power/cpu_frequency"
+      ftrace_events: "power/cpu_idle"
+      ftrace_events: "power/gpu_frequency"
+      ftrace_events: "power/suspend_resume"
+      ftrace_events: "power/wakeup_source_activate"
+      ftrace_events: "power/wakeup_source_deactivate"
+      ftrace_events: "sched/sched_blocked_reason"
+      ftrace_events: "sched/sched_process_exit"
+      ftrace_events: "sched/sched_process_free"
+      ftrace_events: "sched/sched_switch"
+      ftrace_events: "sched/sched_wakeup"
+      ftrace_events: "sched/sched_wakeup_new"
+      ftrace_events: "sched/sched_waking"
+      ftrace_events: "task/task_newtask"
+      ftrace_events: "task/task_rename"
+      ftrace_events: "vmscan/*"
+      ftrace_events: "workqueue/*"
+      atrace_categories: "aidl"
+      atrace_categories: "am"
+      atrace_categories: "dalvik"
+      atrace_categories: "binder_lock"
+      atrace_categories: "binder_driver"
+      atrace_categories: "bionic"
+      atrace_categories: "camera"
+      atrace_categories: "disk"
+      atrace_categories: "freq"
+      atrace_categories: "idle"
+      atrace_categories: "gfx"
+      atrace_categories: "hal"
+      atrace_categories: "input"
+      atrace_categories: "pm"
+      atrace_categories: "power"
+      atrace_categories: "res"
+      atrace_categories: "rro"
+      atrace_categories: "sched"
+      atrace_categories: "sm"
+      atrace_categories: "ss"
+      atrace_categories: "thermal"
+      atrace_categories: "video"
+      atrace_categories: "view"
+      atrace_categories: "wm"
+      atrace_apps: "lmkd"
+      atrace_apps: "system_server"
+      atrace_apps: "com.android.systemui"
+      atrace_apps: "com.google.android.gms"
+      atrace_apps: "com.google.android.gms.persistent"
+      atrace_apps: "android:ui"
+      atrace_apps: "com.google.android.apps.maps"
+      atrace_apps: "*"
+      buffer_size_kb: 16384
+      drain_period_ms: 150
+      symbolize_ksyms: true
+    }}
+  }}
+}}
+duration_ms: 10000
+write_into_file: true
+file_write_period_ms: 5000
+max_file_size_bytes: 100000000000
+flush_period_ms: 5000
+incremental_state_config {{
+  clear_period_ms: 5000
+}}
+'''
 
 
 class ProfilerCommandExecutorUnitTest(unittest.TestCase):
 
   def setUp(self):
     self.command = ProfilerCommand(
-        PROFILER_COMMAND_TYPE, "custom", None, DEFAULT_OUT_DIR, DEFAULT_DUR_MS,
+        PROFILER_COMMAND_TYPE, "custom", PROFILER_TYPE, DEFAULT_OUT_DIR, DEFAULT_DUR_MS,
         None, 1, None, DEFAULT_PERFETTO_CONFIG, None, False, None, None, None,
         None)
     self.mock_device = mock.create_autospec(AdbDevice, instance=True,
                                             serial=TEST_SERIAL)
     self.mock_device.check_device_connection.return_value = None
+    self.mock_device.get_android_sdk_version.return_value = ANDROID_SDK_VERSION_T
 
   @mock.patch.object(subprocess, "Popen", autospec=True)
   def test_execute_one_run_and_use_ui_success(self, mock_process):
@@ -229,7 +563,7 @@ class UserSwitchCommandExecutorUnitTest(unittest.TestCase):
 
   def setUp(self):
     self.command = ProfilerCommand(
-        PROFILER_COMMAND_TYPE, "user-switch", None, DEFAULT_OUT_DIR,
+        PROFILER_COMMAND_TYPE, "user-switch", PROFILER_TYPE, DEFAULT_OUT_DIR,
         DEFAULT_DUR_MS, None, 1, None, DEFAULT_PERFETTO_CONFIG, None, False,
         None, None, None, None)
     self.mock_device = mock.create_autospec(AdbDevice, instance=True,
@@ -238,6 +572,7 @@ class UserSwitchCommandExecutorUnitTest(unittest.TestCase):
     self.mock_device.user_exists.return_value = None
     self.current_user = TEST_USER_ID_3
     self.mock_device.get_current_user.side_effect = lambda: self.current_user
+    self.mock_device.get_android_sdk_version.return_value = ANDROID_SDK_VERSION_T
 
   @mock.patch.object(subprocess, "Popen", autospec=True)
   def test_execute_all_users_different_success(self, mock_process):
@@ -352,12 +687,13 @@ class BootCommandExecutorUnitTest(unittest.TestCase):
 
   def setUp(self):
     self.command = ProfilerCommand(
-        PROFILER_COMMAND_TYPE, "boot", None, DEFAULT_OUT_DIR, TEST_DURATION,
-        None, 1, None, DEFAULT_PERFETTO_CONFIG, TEST_DURATION, False, None,
-        None, None, None)
+        PROFILER_COMMAND_TYPE, "boot", PROFILER_TYPE, DEFAULT_OUT_DIR,
+        TEST_DURATION, None, 1, None, DEFAULT_PERFETTO_CONFIG, TEST_DURATION,
+        False, None, None, None, None)
     self.mock_device = mock.create_autospec(AdbDevice, instance=True,
                                             serial=TEST_SERIAL)
     self.mock_device.check_device_connection.return_value = None
+    self.mock_device.get_android_sdk_version.return_value = ANDROID_SDK_VERSION_T
 
   def test_execute_reboot_success(self):
     error = self.command.execute(self.mock_device)
@@ -385,6 +721,21 @@ class BootCommandExecutorUnitTest(unittest.TestCase):
     self.assertEqual(self.mock_device.reboot.call_count, 1)
     self.assertEqual(self.mock_device.pull_file.call_count, 0)
 
+  def test_execute_get_prop_and_old_android_version_failure(self):
+    self.mock_device.get_android_sdk_version.return_value = ANDROID_SDK_VERSION_S
+
+    error = self.command.execute(self.mock_device)
+
+    self.assertNotEqual(error, None)
+    self.assertEqual(error.message, (
+        "Cannot perform trace on boot because only devices with version Android 13 (T)"
+        " or newer can be configured to automatically start recording traces on boot."))
+    self.assertEqual(error.suggestion, (
+        "Update your device or use a different device with Android 13 (T) or"
+        " newer."))
+    self.assertEqual(self.mock_device.reboot.call_count, 0)
+    self.assertEqual(self.mock_device.pull_file.call_count, 0)
+
   def test_execute_write_to_file_failure(self):
     self.mock_device.write_to_file.side_effect = TEST_EXCEPTION
 
@@ -450,7 +801,7 @@ class AppStartupExecutorUnitTest(unittest.TestCase):
 
   def setUp(self):
     self.command = ProfilerCommand(
-        PROFILER_COMMAND_TYPE, "app-startup", None, DEFAULT_OUT_DIR,
+        PROFILER_COMMAND_TYPE, "app-startup", PROFILER_TYPE, DEFAULT_OUT_DIR,
         DEFAULT_DUR_MS, TEST_PACKAGE_1, 1, None, DEFAULT_PERFETTO_CONFIG, None,
         False, None, None, None, None)
     self.mock_device = mock.create_autospec(AdbDevice, instance=True,
@@ -459,6 +810,7 @@ class AppStartupExecutorUnitTest(unittest.TestCase):
     self.mock_device.get_packages.return_value = [TEST_PACKAGE_1,
                                                   TEST_PACKAGE_2]
     self.mock_device.is_package_running.return_value = False
+    self.mock_device.get_android_sdk_version.return_value = ANDROID_SDK_VERSION_T
 
   def test_app_startup_command_success(self):
     self.mock_device.start_package.return_value = None
@@ -560,5 +912,103 @@ class AppStartupExecutorUnitTest(unittest.TestCase):
     self.assertEqual(self.mock_device.pull_file.call_count, 0)
 
 
+class ConfigCommandExecutorUnitTest(unittest.TestCase):
+
+  def setUp(self):
+    self.mock_device = mock.create_autospec(AdbDevice, instance=True,
+                                            serial=TEST_SERIAL)
+    self.mock_device.check_device_connection.return_value = None
+    self.mock_device.get_android_sdk_version.return_value = (
+        ANDROID_SDK_VERSION_T)
+
+  @staticmethod
+  def generate_mock_completed_process(stdout_string=b'\n', stderr_string=b'\n'):
+    return mock.create_autospec(subprocess.CompletedProcess, instance=True,
+                                stdout=stdout_string, stderr=stderr_string)
+
+  def test_config_list(self):
+    terminal_output = io.StringIO()
+    sys.stdout = terminal_output
+
+    self.command = ConfigCommand("config list", None, None, None, None, None)
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+    self.assertEqual(terminal_output.getvalue(), (
+        "%s\n" % "\n".join(list(PREDEFINED_PERFETTO_CONFIGS.keys()))))
+
+  def test_config_show(self):
+    terminal_output = io.StringIO()
+    sys.stdout = terminal_output
+
+    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+    self.assertEqual(terminal_output.getvalue(), TEST_DEFAULT_CONFIG)
+
+  def test_config_show_no_device_connection(self):
+    self.mock_device.check_device_connection.return_value = (
+        TEST_VALIDATION_ERROR)
+    terminal_output = io.StringIO()
+    sys.stdout = terminal_output
+
+    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+    self.assertEqual(terminal_output.getvalue(), TEST_DEFAULT_CONFIG)
+
+  def test_config_show_old_android_version(self):
+    self.mock_device.get_android_sdk_version.return_value = (
+        ANDROID_SDK_VERSION_S)
+    terminal_output = io.StringIO()
+    sys.stdout = terminal_output
+
+    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+    self.assertEqual(terminal_output.getvalue(),
+                     TEST_DEFAULT_CONFIG_OLD_ANDROID)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_config_pull(self, mock_subprocess_run):
+    mock_subprocess_run.return_value = self.generate_mock_completed_process()
+    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_config_pull_no_device_connection(self, mock_subprocess_run):
+    self.mock_device.check_device_connection.return_value = (
+        TEST_VALIDATION_ERROR)
+    mock_subprocess_run.return_value = self.generate_mock_completed_process()
+    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_config_pull_old_android_version(self, mock_subprocess_run):
+    self.mock_device.get_android_sdk_version.return_value = (
+        ANDROID_SDK_VERSION_S)
+    mock_subprocess_run.return_value = self.generate_mock_completed_process()
+    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+
+
 if __name__ == '__main__':
   unittest.main()
diff --git a/torq/tests/config_builder_unit_test.py b/torq/tests/config_builder_unit_test.py
index 6deec4bc..42e9f4eb 100644
--- a/torq/tests/config_builder_unit_test.py
+++ b/torq/tests/config_builder_unit_test.py
@@ -24,8 +24,10 @@ from torq import DEFAULT_DUR_MS
 TEST_FAILURE_MSG = "Test failure."
 TEST_DUR_MS = 9000
 INVALID_DUR_MS = "invalid-dur-ms"
+ANDROID_SDK_VERSION_T = 33
+ANDROID_SDK_VERSION_S_V2 = 32
 
-COMMON_DEFAULT_CONFIG_BEGINNING_STRING = f'''\
+COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1 = f'''\
 <<EOF
 
 buffers: {{
@@ -97,9 +99,11 @@ data_sources: {{
       vmstat_counters: VMSTAT_PGSTEAL_DIRECT
       vmstat_counters: VMSTAT_PGSCAN_KSWAPD
       vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
-      vmstat_counters: VMSTAT_WORKINGSET_REFAULT
-      # Below field not available on < Android SC-V2 releases.
-      cpufreq_period_ms: 500
+      vmstat_counters: VMSTAT_WORKINGSET_REFAULT'''
+
+CPUFREQ_STRING_NEW_ANDROID = f'      cpufreq_period_ms: 500'
+
+COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2 = f'''\
     }}
   }}
 }}
@@ -168,8 +172,7 @@ incremental_state_config {{
 
 '''
 
-DEFAULT_CONFIG_9000_DUR_MS = f'''\
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+COMMON_DEFAULT_FTRACE_EVENTS = f'''\
       ftrace_events: "dmabuf_heap/dma_heap_stat"
       ftrace_events: "ftrace/print"
       ftrace_events: "gpu_mem/gpu_mem_total"
@@ -197,13 +200,21 @@ DEFAULT_CONFIG_9000_DUR_MS = f'''\
       ftrace_events: "task/task_newtask"
       ftrace_events: "task/task_rename"
       ftrace_events: "vmscan/*"
-      ftrace_events: "workqueue/*"
+      ftrace_events: "workqueue/*"'''
+
+DEFAULT_CONFIG_9000_DUR_MS = f'''\
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1}
+{CPUFREQ_STRING_NEW_ANDROID}
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2}
+{COMMON_DEFAULT_FTRACE_EVENTS}
 {COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
 duration_ms: {TEST_DUR_MS}
 {COMMON_CONFIG_ENDING_STRING}EOF'''
 
 DEFAULT_CONFIG_EXCLUDED_FTRACE_EVENTS = f'''\
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1}
+{CPUFREQ_STRING_NEW_ANDROID}
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2}
       ftrace_events: "dmabuf_heap/dma_heap_stat"
       ftrace_events: "ftrace/print"
       ftrace_events: "gpu_mem/gpu_mem_total"
@@ -235,7 +246,9 @@ duration_ms: {DEFAULT_DUR_MS}
 {COMMON_CONFIG_ENDING_STRING}EOF'''
 
 DEFAULT_CONFIG_INCLUDED_FTRACE_EVENTS = f'''\
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1}
+{CPUFREQ_STRING_NEW_ANDROID}
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2}
       ftrace_events: "dmabuf_heap/dma_heap_stat"
       ftrace_events: "ftrace/print"
       ftrace_events: "gpu_mem/gpu_mem_total"
@@ -270,6 +283,15 @@ DEFAULT_CONFIG_INCLUDED_FTRACE_EVENTS = f'''\
 duration_ms: {DEFAULT_DUR_MS}
 {COMMON_CONFIG_ENDING_STRING}EOF'''
 
+DEFAULT_CONFIG_OLD_ANDROID = f'''\
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1}
+
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2}
+{COMMON_DEFAULT_FTRACE_EVENTS}
+{COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
+duration_ms: {DEFAULT_DUR_MS}
+{COMMON_CONFIG_ENDING_STRING}EOF'''
+
 COMMON_CUSTOM_CONFIG_BEGINNING_STRING = f'''\
 
 buffers: {{
@@ -322,16 +344,22 @@ class ConfigBuilderUnitTest(unittest.TestCase):
   def test_build_default_config_setting_valid_dur_ms(self):
     self.command.dur_ms = TEST_DUR_MS
 
-    config, error = build_default_config(self.command)
+    config, error = build_default_config(self.command, ANDROID_SDK_VERSION_T)
 
     self.assertEqual(error, None)
     self.assertEqual(config, DEFAULT_CONFIG_9000_DUR_MS)
 
+  def test_build_default_config_on_old_android_version(self):
+    config, error = build_default_config(self.command, ANDROID_SDK_VERSION_S_V2)
+
+    self.assertEqual(error, None)
+    self.assertEqual(config, DEFAULT_CONFIG_OLD_ANDROID)
+
   def test_build_default_config_setting_invalid_dur_ms(self):
     self.command.dur_ms = None
 
     with self.assertRaises(ValueError) as e:
-      build_default_config(self.command)
+      build_default_config(self.command, ANDROID_SDK_VERSION_T)
 
     self.assertEqual(str(e.exception), ("Cannot create config because a valid"
                                         " dur_ms was not set."))
@@ -340,7 +368,7 @@ class ConfigBuilderUnitTest(unittest.TestCase):
     self.command.excluded_ftrace_events = ["power/suspend_resume",
                                            "mm_event/mm_event_record"]
 
-    config, error = build_default_config(self.command)
+    config, error = build_default_config(self.command, ANDROID_SDK_VERSION_T)
 
     self.assertEqual(error, None)
     self.assertEqual(config, DEFAULT_CONFIG_EXCLUDED_FTRACE_EVENTS)
@@ -348,7 +376,7 @@ class ConfigBuilderUnitTest(unittest.TestCase):
   def test_build_default_config_removing_invalid_excluded_ftrace_events(self):
     self.command.excluded_ftrace_events = ["invalid_ftrace_event"]
 
-    config, error = build_default_config(self.command)
+    config, error = build_default_config(self.command, ANDROID_SDK_VERSION_T)
 
     self.assertEqual(config, None)
     self.assertNotEqual(error, None)
@@ -392,7 +420,7 @@ class ConfigBuilderUnitTest(unittest.TestCase):
     self.command.included_ftrace_events = ["mock_ftrace_event1",
                                            "mock_ftrace_event2"]
 
-    config, error = build_default_config(self.command)
+    config, error = build_default_config(self.command, ANDROID_SDK_VERSION_T)
 
     self.assertEqual(error, None)
     self.assertEqual(config, DEFAULT_CONFIG_INCLUDED_FTRACE_EVENTS)
@@ -400,7 +428,7 @@ class ConfigBuilderUnitTest(unittest.TestCase):
   def test_build_default_config_adding_invalid_included_ftrace_events(self):
     self.command.included_ftrace_events = ["power/suspend_resume"]
 
-    config, error = build_default_config(self.command)
+    config, error = build_default_config(self.command, ANDROID_SDK_VERSION_T)
 
     self.assertEqual(config, None)
     self.assertNotEqual(error, None)
diff --git a/torq/tests/device_unit_test.py b/torq/tests/device_unit_test.py
index 9d8db839..da0c3724 100644
--- a/torq/tests/device_unit_test.py
+++ b/torq/tests/device_unit_test.py
@@ -18,6 +18,7 @@ import unittest
 import os
 import subprocess
 from unittest import mock
+from command import ProfilerCommand
 from device import AdbDevice
 
 TEST_DEVICE_SERIAL = "test-device-serial"
@@ -35,7 +36,7 @@ TEST_PROP = "test-prop"
 TEST_PROP_VALUE = "test-prop-value"
 TEST_PID_OUTPUT = b"8241\n"
 BOOT_COMPLETE_OUTPUT = b"1\n"
-
+ANDROID_SDK_VERSION_T = 33
 
 class DeviceUnitTest(unittest.TestCase):
 
@@ -347,6 +348,34 @@ class DeviceUnitTest(unittest.TestCase):
 
     self.assertEqual(str(e.exception), TEST_FAILURE_MSG)
 
+  @mock.patch.object(subprocess, "Popen", autospec=True)
+  def test_start_simpleperf_trace_success(self, mock_subprocess_popen):
+    # Mocking the return value of subprocess.Popen to ensure it's
+    # not modified and returned by AdbDevice.start_simpleperf_trace
+    mock_subprocess_popen.return_value = mock.Mock()
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+    command = ProfilerCommand("profiler", "custom", None, None,
+                              10000, None, None, ["cpu-cycles"], None, None,
+                              None, None, None, None, None)
+    mock_process = adbDevice.start_simpleperf_trace(command)
+
+    # No exception is expected to be thrown
+    self.assertEqual(mock_process, mock_subprocess_popen.return_value)
+
+  @mock.patch.object(subprocess, "Popen", autospec=True)
+  def test_start_simpleperf_trace_failure(self, mock_subprocess_popen):
+    mock_subprocess_popen.side_effect = TEST_EXCEPTION
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    command = ProfilerCommand("profiler", "custom", None, None,
+                              10000, None, None, ["cpu-cycles"], None, None,
+                              None, None, None, None, None)
+    with self.assertRaises(Exception) as e:
+      adbDevice.start_simpleperf_trace(command)
+
+    self.assertEqual(str(e.exception), TEST_FAILURE_MSG)
+
+
   @mock.patch.object(subprocess, "run", autospec=True)
   def test_pull_file_success(self, mock_subprocess_run):
     mock_subprocess_run.return_value = self.generate_mock_completed_process()
@@ -743,6 +772,91 @@ class DeviceUnitTest(unittest.TestCase):
 
     self.assertEqual(str(e.exception), TEST_FAILURE_MSG)
 
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_get_prop_success(self, mock_subprocess_run):
+    test_prop_value = ANDROID_SDK_VERSION_T
+    mock_subprocess_run.return_value = self.generate_mock_completed_process(
+        stdout_string=b'%d\n' % test_prop_value)
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    prop_value = int(adbDevice.get_prop(TEST_PROP))
+
+    self.assertEqual(prop_value, test_prop_value)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_get_prop_package_failure(self, mock_subprocess_run):
+    mock_subprocess_run.side_effect = TEST_EXCEPTION
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    with self.assertRaises(Exception) as e:
+      adbDevice.get_prop(TEST_PROP)
+
+    self.assertEqual(str(e.exception), TEST_FAILURE_MSG)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_get_android_sdk_version_success(self, mock_subprocess_run):
+    mock_subprocess_run.return_value = self.generate_mock_completed_process(
+        stdout_string=b'%d\n' % ANDROID_SDK_VERSION_T)
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    prop_value = adbDevice.get_android_sdk_version()
+
+    self.assertEqual(prop_value, ANDROID_SDK_VERSION_T)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_get_android_sdk_version_failure(self, mock_subprocess_run):
+    mock_subprocess_run.side_effect = TEST_EXCEPTION
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    with self.assertRaises(Exception) as e:
+      adbDevice.get_android_sdk_version()
+
+    self.assertEqual(str(e.exception), TEST_FAILURE_MSG)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_simpleperf_event_exists_success(self, mock_subprocess_run):
+    mock_subprocess_run.return_value = (
+        self.generate_mock_completed_process(b'List of software events:\n  '
+                                             b'alignment-faults\n  '
+                                             b'context-switches\n  '
+                                             b'cpu-clock\n  '
+                                             b'cpu-migrations\n  '
+                                             b'emulation-faults\n  '
+                                             b'major-faults\n  '
+                                             b'minor-faults\n  page-faults\n  '
+                                             b'task-clock'))
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    events = ["cpu-clock", "minor-faults"]
+    # No exception is expected to be thrown
+    error = adbDevice.simpleperf_event_exists(events)
+
+    self.assertEqual(error, None)
+    # Check that the list passed to the function is unchanged
+    self.assertEqual(events, ["cpu-clock", "minor-faults"])
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_simpleperf_event_exists_failure(self, mock_subprocess_run):
+    mock_subprocess_run.return_value = (
+        self.generate_mock_completed_process(b'List of software events:\n  '
+                                             b'alignment-faults\n  '
+                                             b'context-switches\n  '
+                                             b'cpu-clock\n  '
+                                             b'cpu-migrations\n  '
+                                             b'emulation-faults\n  '
+                                             b'major-faults\n  '
+                                             b'minor-faults\n  page-faults\n  '
+                                             b'task-clock'))
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    error = adbDevice.simpleperf_event_exists(["cpu-clock", "minor-faults",
+                                               "List"])
+
+    self.assertEqual(error.message, "The following simpleperf event(s) are "
+                                    "invalid: ['List'].")
+    self.assertEqual(error.suggestion, "Run adb shell simpleperf list to"
+                                       " see valid simpleperf events.")
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/torq/tests/torq_unit_test.py b/torq/tests/torq_unit_test.py
index 938cb180..5a0e4a91 100644
--- a/torq/tests/torq_unit_test.py
+++ b/torq/tests/torq_unit_test.py
@@ -23,6 +23,8 @@ from torq import create_parser, verify_args, get_command_type,\
 
 TEST_USER_ID = 10
 TEST_PACKAGE = "com.android.contacts"
+TEST_FILE = "file.pbtxt"
+SYMBOLS_PATH = "/folder/symbols"
 
 
 class TorqUnitTest(unittest.TestCase):
@@ -89,7 +91,11 @@ class TorqUnitTest(unittest.TestCase):
     with self.assertRaises(SystemExit):
       parser.parse_args()
 
-  def test_create_parser_valid_profiler_names(self):
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  def test_create_parser_valid_profiler_names(self, mock_isdir, mock_exists):
+    mock_isdir.return_value = True
+    mock_exists.return_value = True
     parser = self.set_up_parser("torq.py -p perfetto")
 
     args = parser.parse_args()
@@ -98,7 +104,8 @@ class TorqUnitTest(unittest.TestCase):
     self.assertEqual(error, None)
     self.assertEqual(args.profiler, "perfetto")
 
-    parser = self.set_up_parser("torq.py -p simpleperf")
+    parser = self.set_up_parser("torq.py -p simpleperf --symbols %s"
+                                % SYMBOLS_PATH)
 
     args = parser.parse_args()
     args, error = verify_args(args)
@@ -481,8 +488,14 @@ class TorqUnitTest(unittest.TestCase):
                                         " torq --event app-startup --app"
                                         " <package-name>"))
 
-  def test_verify_args_profiler_and_simpleperf_event_valid_dependencies(self):
-    parser = self.set_up_parser("torq.py -p simpleperf")
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  def test_verify_args_profiler_and_simpleperf_event_valid_dependencies(self,
+      mock_isdir, mock_exists):
+    mock_isdir.return_value = True
+    mock_exists.return_value = True
+    parser = self.set_up_parser("torq.py -p simpleperf --symbols %s"
+                                % SYMBOLS_PATH)
 
     args = parser.parse_args()
     args, error = verify_args(args)
@@ -491,7 +504,8 @@ class TorqUnitTest(unittest.TestCase):
     self.assertEqual(len(args.simpleperf_event), 1)
     self.assertEqual(args.simpleperf_event[0], "cpu-cycles")
 
-    parser = self.set_up_parser("torq.py -p simpleperf -s cpu-cycles")
+    parser = self.set_up_parser("torq.py -p simpleperf -s cpu-cycles "
+                                "--symbols %s" % SYMBOLS_PATH)
 
     args = parser.parse_args()
     args, error = verify_args(args)
@@ -706,9 +720,15 @@ class TorqUnitTest(unittest.TestCase):
                                         " include power/cpu_idle in the"
                                         " config."))
 
-  def test_verify_args_multiple_valid_simpleperf_events(self):
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  def test_verify_args_multiple_valid_simpleperf_events(self, mock_isdir,
+      mock_exists):
+    mock_isdir.return_value = True
+    mock_exists.return_value = True
     parser = self.set_up_parser(("torq.py -p simpleperf -s cpu-cycles"
-                                 " -s instructions"))
+                                 " -s instructions --symbols %s"
+                                 % SYMBOLS_PATH))
 
     args = parser.parse_args()
     args, error = verify_args(args)
@@ -736,24 +756,6 @@ class TorqUnitTest(unittest.TestCase):
     with self.assertRaises(SystemExit):
       parser.parse_args()
 
-  def test_verify_args_invalid_mixing_of_profiler_and_hw_subcommand(self):
-    parser = self.set_up_parser("torq.py -d 20000 hw set seahawk")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error.message, ("Command is invalid because profiler"
-                                     " command is followed by a hw or"
-                                     " config command."))
-    self.assertEqual(error.suggestion, ("Remove the 'hw' or 'config' subcommand"
-                                        " to profile the device instead."))
-
-  def test_create_parser_invalid_mixing_of_profiler_and_hw_subcommand(self):
-    parser = self.set_up_parser("torq.py hw set seahawk -d 20000 ")
-
-    with self.assertRaises(SystemExit):
-      parser.parse_args()
-
   def test_verify_args_invalid_mixing_of_profiler_and_config_subcommand(self):
     parser = self.set_up_parser("torq.py -d 20000 config pull lightweight")
 
@@ -761,10 +763,10 @@ class TorqUnitTest(unittest.TestCase):
     args, error = verify_args(args)
 
     self.assertEqual(error.message, ("Command is invalid because profiler"
-                                     " command is followed by a hw or"
-                                     " config command."))
-    self.assertEqual(error.suggestion, ("Remove the 'hw' or 'config' subcommand"
-                                        " to profile the device instead."))
+                                     " command is followed by a config"
+                                     " command."))
+    self.assertEqual(error.suggestion, ("Remove the 'config' subcommand to"
+                                        " profile the device instead."))
 
   def test_create_parser_invalid_mixing_of_profiler_and_config_subcommand(self):
     parser = self.set_up_parser("torq.py config pull lightweight -d 20000")
@@ -782,7 +784,7 @@ class TorqUnitTest(unittest.TestCase):
     self.assertEqual(error, None)
     self.assertEqual(command.get_type(), "profiler")
 
-  def test_create_parser_valid_hw_config_show_values(self):
+  def test_create_parser_valid_config_show_values(self):
     parser = self.set_up_parser("torq.py config show default")
 
     args = parser.parse_args()
@@ -807,13 +809,13 @@ class TorqUnitTest(unittest.TestCase):
     self.assertEqual(error, None)
     self.assertEqual(args.config_name, "memory")
 
-  def test_create_parser_invalid_hw_config_show_values(self):
+  def test_create_parser_invalid_config_show_values(self):
     parser = self.set_up_parser("torq.py config show fake-config")
 
     with self.assertRaises(SystemExit):
       parser.parse_args()
 
-  def test_create_parser_valid_hw_config_pull_values(self):
+  def test_create_parser_valid_config_pull_values(self):
     parser = self.set_up_parser("torq.py config pull default")
 
     args = parser.parse_args()
@@ -838,201 +840,12 @@ class TorqUnitTest(unittest.TestCase):
     self.assertEqual(error, None)
     self.assertEqual(args.config_name, "memory")
 
-  def test_create_parser_invalid_hw_config_pull_values(self):
+  def test_create_parser_invalid_config_pull_values(self):
     parser = self.set_up_parser("torq.py config pull fake-config")
 
     with self.assertRaises(SystemExit):
       parser.parse_args()
 
-  def test_verify_args_valid_hw_num_cpus_and_memory_values(self):
-    parser = self.set_up_parser("torq.py hw set -n 2")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(args.num_cpus, 2)
-
-    parser = self.set_up_parser("torq.py hw set -m 4G")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(args.memory, "4G")
-
-    parser = self.set_up_parser("torq.py hw set -n 2 -m 4G")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(args.num_cpus, 2)
-    self.assertEqual(args.memory, "4G")
-
-    parser = self.set_up_parser("torq.py hw set -m 4G -n 2")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(args.memory, "4G")
-    self.assertEqual(args.num_cpus, 2)
-
-  def test_verify_args_invalid_hw_num_cpus_values(self):
-    parser = self.set_up_parser("torq.py hw set -n 0")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error.message, ("Command is invalid because hw set"
-                                     " --num-cpus cannot be set to smaller"
-                                     " than 1."))
-    self.assertEqual(error.suggestion, ("Set hw set --num-cpus 1 to set 1"
-                                        " active core in hardware."))
-
-    parser = self.set_up_parser("torq.py hw set -n -1")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error.message, ("Command is invalid because hw set"
-                                     " --num-cpus cannot be set to smaller"
-                                     " than 1."))
-    self.assertEqual(error.suggestion, ("Set hw set --num-cpus 1 to set 1"
-                                        " active core in hardware."))
-
-  def test_verify_args_invalid_hw_memory_values(self):
-    parser = self.set_up_parser("torq.py hw set -m 0G")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error.message, ("Command is invalid because hw set"
-                                     " --memory cannot be set to smaller"
-                                     " than 1."))
-    self.assertEqual(error.suggestion, ("Set hw set --memory 4G to limit the"
-                                        " memory of the device to 4"
-                                        " gigabytes."))
-
-    parser = self.set_up_parser("torq.py hw set -m 4g")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error.message, ("Command is invalid because the argument"
-                                     " for hw set --memory does not match"
-                                     " the <int>G format."))
-    self.assertEqual(error.suggestion, ("Set hw set --memory 4G to limit the"
-                                        " memory of the device to 4"
-                                        " gigabytes."))
-
-    parser = self.set_up_parser("torq.py hw set -m G")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error.message, ("Command is invalid because the argument"
-                                     " for hw set --memory does not match"
-                                     " the <int>G format."))
-    self.assertEqual(error.suggestion, ("Set hw set --memory 4G to limit the"
-                                        " memory of the device to 4"
-                                        " gigabytes."))
-
-  def test_create_parser_invalid_hw_memory_values(self):
-    parser = self.set_up_parser("torq.py hw set -m -1G")
-
-    with self.assertRaises(SystemExit):
-      parser.parse_args()
-
-  def test_create_parser_valid_hw_set_values(self):
-    parser = self.set_up_parser("torq.py hw set seahawk")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(args.hw_set_config, "seahawk")
-
-    parser = self.set_up_parser("torq.py hw set seaturtle")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(args.hw_set_config, "seaturtle")
-
-  def test_create_parser_invalid_hw_set_values(self):
-    parser = self.set_up_parser("torq.py hw set fake-device")
-
-    with self.assertRaises(SystemExit):
-      parser.parse_args()
-
-  def test_create_parser_hw_set_invalid_dependencies(self):
-    parser = self.set_up_parser("torq.py set seahawk -n 2")
-
-    with self.assertRaises(SystemExit):
-      parser.parse_args()
-
-    parser = self.set_up_parser("torq.py set seahawk -m 4G")
-
-    with self.assertRaises(SystemExit):
-      parser.parse_args()
-
-    parser = self.set_up_parser("torq.py set seahawk -n 2 m 4G")
-
-    with self.assertRaises(SystemExit):
-      parser.parse_args()
-
-  def test_verify_args_invalid_hw_set_subcommands(self):
-    parser = self.set_up_parser("torq.py hw set")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-
-    self.assertEqual(error.message, ("Command is invalid because torq hw set"
-                                     " cannot be called without a"
-                                     " subcommand."))
-    self.assertEqual(error.suggestion, ("Use one of the following"
-                                        " subcommands:\n"
-                                        "\t (torq hw set <config>,"
-                                        " torq hw set --num-cpus <int>,\n"
-                                        "\t torq hw set --memory <int>G,\n"
-                                        "\t torq hw set --num-cpus <int>"
-                                        " --memory <int>G,\n"
-                                        "\t torq hw set --memory <int>G"
-                                        " --num-cpus <int>)"))
-
-  def test_get_command_type_hw_set(self):
-    parser = self.set_up_parser("torq.py hw set seahawk")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-    command = get_command_type(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(command.get_type(), "hw set")
-
-  def test_get_command_type_hw_get(self):
-    parser = self.set_up_parser("torq.py hw get")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-    command = get_command_type(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(command.get_type(), "hw get")
-
-  def test_get_command_type_hw_list(self):
-    parser = self.set_up_parser("torq.py hw list")
-
-    args = parser.parse_args()
-    args, error = verify_args(args)
-    command = get_command_type(args)
-
-    self.assertEqual(error, None)
-    self.assertEqual(command.get_type(), "hw list")
-
   def test_verify_args_invalid_config_subcommands(self):
     parser = self.set_up_parser("torq.py config")
 
@@ -1079,6 +892,25 @@ class TorqUnitTest(unittest.TestCase):
     self.assertEqual(error, None)
     self.assertEqual(args.file_path, "./memory.pbtxt")
 
+  @mock.patch.object(os.path, "isfile", autospec=True)
+  def test_verify_args_default_config_pull_invalid_filepath(self, mock_is_file):
+    mock_invalid_file_path = "mock-invalid-file-path"
+    mock_is_file.return_value = False
+    parser = self.set_up_parser(("torq.py config pull default %s"
+                                 % mock_invalid_file_path))
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error.message, (
+        "Command is invalid because %s is not a valid filepath."
+        % mock_invalid_file_path))
+    self.assertEqual(error.suggestion, (
+        "A default filepath can be used if you do not specify a file-path:\n\t"
+        " torq pull default to copy to ./default.pbtxt\n\t"
+        " torq pull lightweight to copy to ./lightweight.pbtxt\n\t "
+        "torq pull memory to copy to ./memory.pbtxt"))
+
   def test_get_command_type_config_list(self):
     parser = self.set_up_parser("torq.py config list")
 
@@ -1109,6 +941,35 @@ class TorqUnitTest(unittest.TestCase):
     self.assertEqual(error, None)
     self.assertEqual(command.get_type(), "config pull")
 
+  @mock.patch.object(os.path, "exists", autospec=True)
+  def test_create_parser_valid_open_subcommand(self, mock_exists):
+    mock_exists.return_value = True
+    parser = self.set_up_parser("torq.py open %s" % TEST_FILE)
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error, None)
+    self.assertEqual(args.file_path, TEST_FILE)
+
+  def test_create_parser_open_subcommand_no_file(self):
+    parser = self.set_up_parser("torq.py open")
+
+    with self.assertRaises(SystemExit):
+      parser.parse_args()
+
+  @mock.patch.object(os.path, "exists", autospec=True)
+  def test_create_parser_open_subcommand_invalid_file(self, mock_exists):
+    mock_exists.return_value = False
+    parser = self.set_up_parser("torq.py open %s" % TEST_FILE)
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error.message, "Command is invalid because %s is an "
+                                    "invalid file path." % TEST_FILE)
+    self.assertEqual(error.suggestion, "Make sure your file exists.")
+
 
 if __name__ == '__main__':
   unittest.main()
diff --git a/torq/tests/validate_simpleperf_unit_test.py b/torq/tests/validate_simpleperf_unit_test.py
new file mode 100644
index 00000000..3eec988d
--- /dev/null
+++ b/torq/tests/validate_simpleperf_unit_test.py
@@ -0,0 +1,229 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+import builtins
+import unittest
+import sys
+import os
+import subprocess
+from unittest import mock
+from torq import create_parser, verify_args
+
+TORQ_TEMP_DIR = "/tmp/.torq"
+ANDROID_BUILD_TOP = "/folder"
+ANDROID_PRODUCT_OUT = "/folder/out/product/seahawk"
+SYMBOLS_PATH = "/folder/symbols"
+
+
+class ValidateSimpleperfUnitTest(unittest.TestCase):
+
+  def set_up_parser(self, command_string):
+    parser = create_parser()
+    sys.argv = command_string.split()
+    return parser
+
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  @mock.patch.dict(os.environ, {"ANDROID_BUILD_TOP": ANDROID_BUILD_TOP,
+                                "ANDROID_PRODUCT_OUT": ANDROID_PRODUCT_OUT},
+                   clear=True)
+  def test_create_parser_valid_symbols(self, mock_isdir, mock_exists):
+    mock_isdir.return_value = True
+    mock_exists.return_value = True
+    parser = self.set_up_parser("torq.py -p simpleperf "
+                                "--symbols %s" % SYMBOLS_PATH)
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error, None)
+    self.assertEqual(args.symbols, SYMBOLS_PATH)
+    self.assertEqual(args.scripts_path, "%s/system/extras/simpleperf/scripts"
+                     % ANDROID_BUILD_TOP)
+
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  @mock.patch.dict(os.environ, {"ANDROID_BUILD_TOP": ANDROID_BUILD_TOP,
+                                "ANDROID_PRODUCT_OUT": ANDROID_PRODUCT_OUT},
+                   clear=True)
+  def test_create_parser_valid_android_product_out_no_symbols(self,
+      mock_isdir, mock_exists):
+    mock_isdir.return_value = True
+    mock_exists.return_value = True
+    parser = self.set_up_parser("torq.py -p simpleperf")
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error, None)
+    self.assertEqual(args.symbols, ANDROID_PRODUCT_OUT)
+    self.assertEqual(args.scripts_path, "%s/system/extras/simpleperf/scripts"
+                     % ANDROID_BUILD_TOP)
+
+  @mock.patch.dict(os.environ, {"ANDROID_PRODUCT_OUT": ANDROID_PRODUCT_OUT},
+                   clear=True)
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  def test_create_parser_invalid_android_product_no_symbols(self,
+      mock_isdir, mock_exists):
+    mock_isdir.return_value = False
+    mock_exists.return_value = False
+    parser = self.set_up_parser("torq.py -p simpleperf")
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error.message, ("%s is not a valid $ANDROID_PRODUCT_OUT."
+                                     % ANDROID_PRODUCT_OUT))
+    self.assertEqual(error.suggestion, "Set --symbols to a valid symbols lib "
+                                       "path or set $ANDROID_PRODUCT_OUT to "
+                                       "your android product out directory "
+                                       "(<ANDROID_BUILD_TOP>/out/target/product"
+                                       "/<TARGET>).")
+
+  @mock.patch.dict(os.environ, {},
+                   clear=True)
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  def test_create_parser_invalid_symbols_no_android_product_out(self,
+      mock_isdir, mock_exists):
+    mock_isdir.return_value = False
+    mock_exists.return_value = False
+    parser = self.set_up_parser("torq.py -p simpleperf "
+                                "--symbols %s" % SYMBOLS_PATH)
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error.message, ("%s is not a valid path." % SYMBOLS_PATH))
+    self.assertEqual(error.suggestion, "Set --symbols to a valid symbols lib "
+                                       "path or set $ANDROID_PRODUCT_OUT to "
+                                       "your android product out directory "
+                                       "(<ANDROID_BUILD_TOP>/out/target/product"
+                                       "/<TARGET>).")
+
+  @mock.patch.dict(os.environ, {}, clear=True)
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  def test_create_parser_no_android_product_out_no_symbols(self, mock_isdir,
+      mock_exists):
+    mock_isdir.return_value = False
+    mock_exists.return_value = False
+    parser = self.set_up_parser("torq.py -p simpleperf")
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error.message, "ANDROID_PRODUCT_OUT is not set.")
+    self.assertEqual(error.suggestion, "Set --symbols to a valid symbols lib "
+                                       "path or set $ANDROID_PRODUCT_OUT to "
+                                       "your android product out directory "
+                                       "(<ANDROID_BUILD_TOP>/out/target/"
+                                       "product/<TARGET>).")
+
+  @mock.patch.dict(os.environ, {"ANDROID_PRODUCT_OUT": ANDROID_PRODUCT_OUT},
+                   clear=True)
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  @mock.patch.object(subprocess, "run", autospec=True)
+  @mock.patch.object(builtins, "input")
+  def test_create_parser_successfully_download_scripts(self, mock_input,
+      mock_subprocess_run, mock_isdir, mock_exists):
+    mock_isdir.return_value = True
+    mock_input.return_value = "y"
+    mock_exists.side_effect = [False, True]
+    mock_subprocess_run.return_value = None
+    parser = self.set_up_parser("torq.py -p simpleperf")
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error, None)
+    self.assertEqual(args.symbols, ANDROID_PRODUCT_OUT)
+    self.assertEqual(args.scripts_path, TORQ_TEMP_DIR)
+
+  @mock.patch.dict(os.environ, {"ANDROID_BUILD_TOP": ANDROID_BUILD_TOP},
+                   clear=True)
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  @mock.patch.object(subprocess, "run", autospec=True)
+  @mock.patch.object(builtins, "input")
+  def test_create_parser_failed_to_download_scripts(self, mock_input,
+      mock_subprocess_run, mock_isdir, mock_exists):
+    mock_isdir.return_value = True
+    mock_input.return_value = "y"
+    mock_exists.side_effect = [False, False, False]
+    mock_subprocess_run.return_value = None
+    parser = self.set_up_parser("torq.py -p simpleperf --symbols %s"
+                                % SYMBOLS_PATH)
+
+    args = parser.parse_args()
+    with self.assertRaises(Exception) as e:
+      args, error = verify_args(args)
+
+    self.assertEqual(str(e.exception),
+                     "Error while downloading simpleperf scripts. Try "
+                     "again or set $ANDROID_BUILD_TOP to your android root "
+                     "path and make sure you have $ANDROID_BUILD_TOP/system"
+                     "/extras/simpleperf/scripts downloaded.")
+
+  @mock.patch.dict(os.environ, {"ANDROID_BUILD_TOP": ANDROID_BUILD_TOP},
+                   clear=True)
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  @mock.patch.object(builtins, "input")
+  def test_create_parser_download_scripts_wrong_input(self, mock_input,
+      mock_isdir, mock_exists):
+    mock_isdir.return_value = True
+    mock_input.return_value = "bad-input"
+    mock_exists.side_effect = [False, False]
+    parser = self.set_up_parser("torq.py -p simpleperf --symbols %s"
+                                % SYMBOLS_PATH)
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error.message, "Invalid inputs.")
+    self.assertEqual(error.suggestion, "Set $ANDROID_BUILD_TOP to your android "
+                                       "root path and make sure you have "
+                                       "$ANDROID_BUILD_TOP/system/extras/"
+                                       "simpleperf/scripts downloaded.")
+
+  @mock.patch.dict(os.environ, {"ANDROID_BUILD_TOP": ANDROID_BUILD_TOP},
+                   clear=True)
+  @mock.patch.object(os.path, "exists", autospec=True)
+  @mock.patch.object(os.path, "isdir", autospec=True)
+  @mock.patch.object(builtins, "input")
+  def test_create_parser_download_scripts_refuse_download(self, mock_input,
+      mock_isdir, mock_exists):
+    mock_isdir.return_value = True
+    mock_input.return_value = "n"
+    mock_exists.side_effect = [False, False]
+    parser = self.set_up_parser("torq.py -p simpleperf --symbols %s"
+                                % SYMBOLS_PATH)
+
+    args = parser.parse_args()
+    args, error = verify_args(args)
+
+    self.assertEqual(error.message, "Did not download simpleperf scripts.")
+    self.assertEqual(error.suggestion, "Set $ANDROID_BUILD_TOP to your android "
+                                       "root path and make sure you have "
+                                       "$ANDROID_BUILD_TOP/system/extras/"
+                                       "simpleperf/scripts downloaded.")
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/torq/torq.py b/torq/torq.py
index c666a8da..a01dadbe 100644
--- a/torq/torq.py
+++ b/torq/torq.py
@@ -16,10 +16,12 @@
 
 import argparse
 import os
-from command import ProfilerCommand, HWCommand, ConfigCommand
+from command import ProfilerCommand, ConfigCommand, OpenCommand
 from device import AdbDevice
 from validation_error import ValidationError
 from config_builder import PREDEFINED_PERFETTO_CONFIGS
+from utils import path_exists
+from validate_simpleperf import verify_simpleperf_args
 
 DEFAULT_DUR_MS = 10000
 MIN_DURATION_MS = 3000
@@ -71,31 +73,9 @@ def create_parser():
   parser.add_argument('--serial',
                       help=(('Specifies serial of the device that will be'
                              ' used.')))
+  parser.add_argument('--symbols',
+                      help='Specifies path to symbols library.')
   subparsers = parser.add_subparsers(dest='subcommands', help='Subcommands')
-  hw_parser = subparsers.add_parser('hw',
-                                    help=('The hardware subcommand used to'
-                                          ' change the H/W configuration of'
-                                          ' the device.'))
-  hw_subparsers = hw_parser.add_subparsers(dest='hw_subcommand',
-                                           help='torq hw subcommands')
-  hw_set_parser = hw_subparsers.add_parser('set',
-                                           help=('Command to set a new'
-                                                 ' hardware configuration'))
-  hw_set_parser.add_argument('hw_set_config', nargs='?',
-                             choices=['seahawk', 'seaturtle'],
-                             help='Pre-defined hardware configuration')
-  hw_set_parser.add_argument('-n', '--num-cpus', type=int,
-                             help='The amount of active cores in the hardware.')
-  hw_set_parser.add_argument('-m', '--memory',
-                             help=('The memory limit the device would have.'
-                                   ' E.g. 4G'))
-  hw_subparsers.add_parser('get',
-                           help=('Command to get the current hardware'
-                                 ' configuration. Will provide the number of'
-                                 ' cpus and memory available.'))
-  hw_subparsers.add_parser('list',
-                           help=('Command to list the supported HW'
-                                 ' configurations.'))
   config_parser = subparsers.add_parser('config',
                                         help=('The config subcommand used'
                                               ' to list and show the'
@@ -126,6 +106,11 @@ def create_parser():
   config_pull_parser.add_argument('file_path', nargs='?',
                                   help=('File path to copy the predefined'
                                         ' config to'))
+  open_parser = subparsers.add_parser('open',
+                                      help=('The open subcommand is used '
+                                            'to open trace files in the '
+                                            'perfetto ui.'))
+  open_parser.add_argument('file_path', help='Path to trace file.')
   return parser
 
 
@@ -151,9 +136,9 @@ def verify_args(args):
   if (args.subcommands is not None and
       user_changed_default_arguments(args)):
     return None, ValidationError(
-        ("Command is invalid because profiler command is followed by a hw"
-         " or config command."),
-        "Remove the 'hw' or 'config' subcommand to profile the device instead.")
+        ("Command is invalid because profiler command is followed by a config"
+         " command."),
+        "Remove the 'config' subcommand to profile the device instead.")
 
   if args.out_dir != DEFAULT_OUT_DIR and not os.path.isdir(args.out_dir):
     return None, ValidationError(
@@ -187,6 +172,13 @@ def verify_args(args):
         ("Set --event %s --to-user <user-id> to perform a %s."
          % (args.event, args.event)))
 
+  # TODO(b/374313202): Support for simpleperf boot event will
+  #                    be added in the future
+  if args.event == "boot" and args.profiler == "simpleperf":
+    return None, ValidationError(
+        "Boot event is not yet implemented for simpleperf.",
+        "Please try another event.")
+
   if args.app is not None and args.event != "app-startup":
     return None, ValidationError(
         ("Command is invalid because --app is passed and --event is not set"
@@ -308,74 +300,6 @@ def verify_args(args):
                         % (event, event, event, event)
                         for event in ftrace_event_intersection)))
 
-  if args.subcommands == "hw" and args.hw_subcommand is None:
-    return None, ValidationError(
-        ("Command is invalid because torq hw cannot be called without"
-         " a subcommand."),
-        ("Use one of the following subcommands:\n"
-         "\t torq hw set <config-name>\n"
-         "\t torq hw get\n"
-         "\t torq hw list"))
-
-  if (args.subcommands == "hw" and args.hw_subcommand == "set" and
-      args.hw_set_config is not None and args.num_cpus is not None):
-    return None, ValidationError(
-        ("Command is invalid because torq hw --num-cpus cannot be passed if a"
-         " new hardware configuration is also set at the same time"),
-        ("Set torq hw --num-cpus 2 by itself to set 2 active"
-         " cores in the hardware."))
-
-  if (args.subcommands == "hw" and args.hw_subcommand == "set" and
-      args.hw_set_config is not None and args.memory is not None):
-    return None, ValidationError(
-        ("Command is invalid because torq hw --memory cannot be passed if a"
-         " new hardware configuration is also set at the same time"),
-        ("Set torq hw --memory 4G by itself to limit the memory"
-         " of the device to 4 gigabytes."))
-
-  if (args.subcommands == "hw" and args.hw_subcommand == "set" and
-      args.num_cpus is not None and args.num_cpus < 1):
-    return None, ValidationError(
-        ("Command is invalid because hw set --num-cpus cannot be set to"
-         " smaller than 1."),
-        ("Set hw set --num-cpus 1 to set 1 active core in"
-         " hardware."))
-
-  if (args.subcommands == "hw" and args.hw_subcommand == "set" and
-      args.memory is not None):
-    index = args.memory.find("G")
-    if index == -1 or args.memory[-1] != "G" or len(args.memory) == 1:
-      return None, ValidationError(
-          ("Command is invalid because the argument for hw set --memory does"
-           " not match the <int>G format."),
-          ("Set hw set --memory 4G to limit the memory of the"
-           " device to 4 gigabytes."))
-    for i in range(index):
-      if not args.memory[i].isdigit():
-        return None, ValidationError(
-            ("Command is invalid because the argument for hw set --memory"
-             " does not match the <int>G format."),
-            ("Set hw set --memory 4G to limit the memory of"
-             " the device to 4 gigabytes."))
-    if args.memory[0] == "0":
-      return None, ValidationError(
-          ("Command is invalid because hw set --memory cannot be set to"
-           " smaller than 1."),
-          ("Set hw set --memory 4G to limit the memory of"
-           " the device to 4 gigabytes."))
-
-  if (args.subcommands == "hw" and args.hw_subcommand == "set" and
-      args.hw_set_config is None and args.num_cpus is None and
-      args.memory is None):
-    return None, ValidationError(
-        ("Command is invalid because torq hw set cannot be called without"
-         " a subcommand."),
-        ("Use one of the following subcommands:\n"
-         "\t (torq hw set <config>, torq hw set --num-cpus <int>,\n"
-         "\t torq hw set --memory <int>G,\n"
-         "\t torq hw set --num-cpus <int> --memory <int>G,\n"
-         "\t torq hw set --memory <int>G --num-cpus <int>)"))
-
   if args.subcommands == "config" and args.config_subcommand is None:
     return None, ValidationError(
         ("Command is invalid because torq config cannot be called"
@@ -391,9 +315,29 @@ def verify_args(args):
   if args.ui is None:
     args.ui = args.runs == 1
 
-  if (args.subcommands == "config" and args.config_subcommand == "pull" and
-      args.file_path is None):
-    args.file_path = "./" + args.config_name + ".pbtxt"
+  if args.subcommands == "config" and args.config_subcommand == "pull":
+    if args.file_path is None:
+      args.file_path = "./" + args.config_name + ".pbtxt"
+    elif not os.path.isfile(args.file_path):
+      return None, ValidationError(
+          ("Command is invalid because %s is not a valid filepath."
+           % args.file_path),
+          ("A default filepath can be used if you do not specify a file-path:\n"
+           "\t torq pull default to copy to ./default.pbtxt\n"
+           "\t torq pull lightweight to copy to ./lightweight.pbtxt\n"
+           "\t torq pull memory to copy to ./memory.pbtxt"))
+
+  if args.subcommands == "open" and not path_exists(args.file_path):
+    return None, ValidationError(
+        "Command is invalid because %s is an invalid file path."
+        % args.file_path, "Make sure your file exists.")
+
+  if args.profiler == "simpleperf":
+    args, error = verify_simpleperf_args(args)
+    if error is not None:
+      return None, error
+  else:
+    args.scripts_path = None
 
   return args, None
 
@@ -408,26 +352,23 @@ def create_profiler_command(args):
                          args.to_user)
 
 
-def create_hw_command(args):
-  command = None
-  type = "hw " + args.hw_subcommand
-  if args.hw_subcommand == "set":
-    command = HWCommand(type, args.hw_set_config, args.num_cpus,
-                        args.memory)
-  else:
-    command = HWCommand(type, None, None, None)
-  return command
-
-
 def create_config_command(args):
-  command = None
   type = "config " + args.config_subcommand
-  if args.config_subcommand == "pull":
-    command = ConfigCommand(type, args.config_name, args.file_path)
-  if args.config_subcommand == "show":
-    command = ConfigCommand(type, args.config_name, None)
-  if args.config_subcommand == "list":
-    command = ConfigCommand(type, None, None)
+  config_name = None
+  file_path = None
+  dur_ms = None
+  excluded_ftrace_events = None
+  included_ftrace_events = None
+  if args.config_subcommand == "pull" or args.config_subcommand == "show":
+    config_name = args.config_name
+    dur_ms = args.dur_ms
+    excluded_ftrace_events = args.excluded_ftrace_events
+    included_ftrace_events = args.included_ftrace_events
+    if args.config_subcommand == "pull":
+      file_path = args.file_path
+
+  command = ConfigCommand(type, config_name, file_path, dur_ms,
+      excluded_ftrace_events, included_ftrace_events)
   return command
 
 
@@ -435,10 +376,10 @@ def get_command_type(args):
   command = None
   if args.subcommands is None:
     command = create_profiler_command(args)
-  if args.subcommands == "hw":
-    command = create_hw_command(args)
   if args.subcommands == "config":
     command = create_config_command(args)
+  if args.subcommands == "open":
+    command = OpenCommand(args.file_path)
   return command
 
 
diff --git a/torq/utils.py b/torq/utils.py
new file mode 100644
index 00000000..8716d9f9
--- /dev/null
+++ b/torq/utils.py
@@ -0,0 +1,27 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+import os
+
+def path_exists(path: str):
+  if path is None:
+    return False
+  return os.path.exists(os.path.expanduser(path))
+
+def dir_exists(path: str):
+  if path is None:
+    return False
+  return os.path.isdir(os.path.expanduser(path))
diff --git a/torq/validate_simpleperf.py b/torq/validate_simpleperf.py
new file mode 100644
index 00000000..4b8c41ca
--- /dev/null
+++ b/torq/validate_simpleperf.py
@@ -0,0 +1,106 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+import os
+import subprocess
+from utils import path_exists, dir_exists
+from validation_error import ValidationError
+
+TORQ_TEMP_DIR = "/tmp/.torq"
+TEMP_CACHE_BUILDER_SCRIPT = TORQ_TEMP_DIR + "/binary_cache_builder.py"
+SIMPLEPERF_SCRIPTS_DIR = "/system/extras/simpleperf/scripts"
+BUILDER_SCRIPT = SIMPLEPERF_SCRIPTS_DIR + "/binary_cache_builder.py"
+
+def verify_simpleperf_args(args):
+  args.scripts_path = TORQ_TEMP_DIR
+  if ("ANDROID_BUILD_TOP" in os.environ
+      and path_exists(os.environ["ANDROID_BUILD_TOP"] + BUILDER_SCRIPT)):
+    args.scripts_path = (os.environ["ANDROID_BUILD_TOP"]
+                         + SIMPLEPERF_SCRIPTS_DIR)
+
+  if args.symbols is None or not dir_exists(args.symbols):
+    if args.symbols is not None:
+      return None, ValidationError(
+          ("%s is not a valid path." % args.symbols),
+          "Set --symbols to a valid symbols lib path or set "
+          "$ANDROID_PRODUCT_OUT to your android product out directory "
+          "(<ANDROID_BUILD_TOP>/out/target/product/<TARGET>).")
+    if "ANDROID_PRODUCT_OUT" not in os.environ:
+      return None, ValidationError(
+          "ANDROID_PRODUCT_OUT is not set.",
+          "Set --symbols to a valid symbols lib path or set "
+          "$ANDROID_PRODUCT_OUT to your android product out directory "
+          "(<ANDROID_BUILD_TOP>/out/target/product/<TARGET>).")
+    if not dir_exists(os.environ["ANDROID_PRODUCT_OUT"]):
+      return None, ValidationError(
+          ("%s is not a valid $ANDROID_PRODUCT_OUT."
+           % (os.environ["ANDROID_PRODUCT_OUT"])),
+          "Set --symbols to a valid symbols lib path or set "
+          "$ANDROID_PRODUCT_OUT to your android product out directory "
+          "(<ANDROID_BUILD_TOP>/out/target/product/<TARGET>).")
+    args.symbols = os.environ["ANDROID_PRODUCT_OUT"]
+
+  if (args.scripts_path != TORQ_TEMP_DIR or
+      path_exists(TEMP_CACHE_BUILDER_SCRIPT)):
+    return args, None
+
+  error = download_simpleperf_scripts()
+
+  if error is not None:
+    return None, error
+
+  return args, None
+
+def download_simpleperf_scripts():
+  i = 0
+  while i <= 3:
+    i += 1
+    confirmation = input("You do not have an Android Root configured with "
+                         "the simpleperf directory. To use simpleperf, torq "
+                         "will download simpleperf scripts to '%s'. "
+                         "Are you ok with this download? [Y/N]: "
+                         % TORQ_TEMP_DIR)
+
+    if confirmation.lower() == "y":
+      break
+    elif confirmation.lower() == "n":
+      return ValidationError("Did not download simpleperf scripts.",
+                             "Set $ANDROID_BUILD_TOP to your android root "
+                             "path and make sure you have $ANDROID_BUILD_TOP"
+                             "/system/extras/simpleperf/scripts "
+                             "downloaded.")
+    if i == 3:
+      return ValidationError("Invalid inputs.",
+                             "Set $ANDROID_BUILD_TOP to your android root "
+                             "path and make sure you have $ANDROID_BUILD_TOP"
+                             "/system/extras/simpleperf/scripts "
+                             "downloaded.")
+
+  subprocess.run(("mkdir -p %s && wget -P %s "
+                 "https://android.googlesource.com/platform/system/extras"
+                 "/+archive/refs/heads/main/simpleperf/scripts.tar.gz "
+                 "&& tar -xvzf %s/scripts.tar.gz -C %s"
+                  % (TORQ_TEMP_DIR, TORQ_TEMP_DIR, TORQ_TEMP_DIR,
+                     TORQ_TEMP_DIR)),
+                 shell=True)
+
+  if not path_exists(TEMP_CACHE_BUILDER_SCRIPT):
+    raise Exception("Error while downloading simpleperf scripts. Try again "
+                    "or set $ANDROID_BUILD_TOP to your android root path and "
+                    "make sure you have $ANDROID_BUILD_TOP/system/extras/"
+                    "simpleperf/scripts downloaded.")
+
+  return None
```

