```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 000000000..c77a80337
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_system_core",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/METADATA b/METADATA
deleted file mode 100644
index d97975ca3..000000000
--- a/METADATA
+++ /dev/null
@@ -1,3 +0,0 @@
-third_party {
-  license_type: NOTICE
-}
diff --git a/debuggerd/Android.bp b/debuggerd/Android.bp
index c365cac52..0e62ceb8f 100644
--- a/debuggerd/Android.bp
+++ b/debuggerd/Android.bp
@@ -200,22 +200,18 @@ cc_library {
     ramdisk_available: true,
     recovery_available: true,
     vendor_ramdisk_available: true,
+    host_supported: true,
 
     local_include_dirs: ["libdebuggerd/include"],
     export_include_dirs: ["libdebuggerd/include"],
 
     srcs: [
         "libdebuggerd/tombstone_proto_to_text.cpp",
-    ],
-
-    header_libs: [
-        "bionic_libc_platform_headers",
+        "libdebuggerd/utility_host.cpp",
     ],
 
     static_libs: [
         "libbase",
-        "liblog_for_runtime_apex",
-        "libunwindstack",
     ],
 
     whole_static_libs: [
@@ -223,6 +219,10 @@ cc_library {
         "libprotobuf-cpp-lite",
     ],
 
+    shared_libs: [
+        "liblog",
+    ],
+
     apex_available: [
         "//apex_available:platform",
         "com.android.runtime",
@@ -331,15 +331,18 @@ cc_library_static {
 
 cc_binary {
     name: "pbtombstone",
+    host_supported: true,
     defaults: ["debuggerd_defaults"],
-    srcs: ["pbtombstone.cpp"],
+    srcs: [
+        "pbtombstone.cpp",
+        "tombstone_symbolize.cpp",
+    ],
     static_libs: [
         "libbase",
-        "libdebuggerd",
+        "libdebuggerd_tombstone_proto_to_text",
         "liblog",
         "libprotobuf-cpp-lite",
         "libtombstone_proto",
-        "libunwindstack",
     ],
 }
 
@@ -502,6 +505,7 @@ cc_binary {
         "libbase",
         "libdebuggerd_client",
         "liblog",
+        "libprocessgroup",
         "libprocinfo",
     ],
 
diff --git a/debuggerd/crash_dump.cpp b/debuggerd/crash_dump.cpp
index c9235eeff..15e8319a9 100644
--- a/debuggerd/crash_dump.cpp
+++ b/debuggerd/crash_dump.cpp
@@ -470,14 +470,12 @@ static bool GetGuestRegistersFromCrashedProcess([[maybe_unused]] pid_t tid,
   }
 
   NativeBridgeGuestStateHeader header;
-  if (!process_memory->ReadFully(header_ptr, &header, sizeof(NativeBridgeGuestStateHeader))) {
-    PLOG(ERROR) << "failed to get the guest state header for thread " << tid;
-    return false;
-  }
-  if (header.signature != NATIVE_BRIDGE_GUEST_STATE_SIGNATURE) {
+  if (!process_memory->ReadFully(header_ptr, &header, sizeof(NativeBridgeGuestStateHeader)) ||
+      header.signature != NATIVE_BRIDGE_GUEST_STATE_SIGNATURE) {
     // Return when ptr points to unmapped memory or no valid guest state.
     return false;
   }
+
   auto guest_state_data_copy = std::make_unique<unsigned char[]>(header.guest_state_data_size);
   if (!process_memory->ReadFully(reinterpret_cast<uintptr_t>(header.guest_state_data),
                                  guest_state_data_copy.get(), header.guest_state_data_size)) {
diff --git a/debuggerd/debuggerd.cpp b/debuggerd/debuggerd.cpp
index 0d4b91f75..7a2500c60 100644
--- a/debuggerd/debuggerd.cpp
+++ b/debuggerd/debuggerd.cpp
@@ -23,11 +23,11 @@
 #include <string_view>
 #include <thread>
 
-#include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/unique_fd.h>
 #include <debuggerd/client.h>
+#include <processgroup/processgroup.h>
 #include <procinfo/process.h>
 #include "util.h"
 
@@ -92,13 +92,8 @@ int main(int argc, char* argv[]) {
   }
 
   // unfreeze if pid is frozen.
-  const std::string freeze_file = android::base::StringPrintf(
-      "/sys/fs/cgroup/uid_%d/pid_%d/cgroup.freeze", proc_info.uid, proc_info.pid);
-  if (std::string freeze_status;
-      android::base::ReadFileToString(freeze_file, &freeze_status) && freeze_status[0] == '1') {
-    android::base::WriteStringToFile("0", freeze_file);
-    // we don't restore the frozen state as this is considered a benign change.
-  }
+  SetProcessProfiles(proc_info.uid, proc_info.pid, {"Unfrozen"});
+  // we don't restore the frozen state as this is considered a benign change.
 
   unique_fd output_fd(fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0));
   if (output_fd.get() == -1) {
diff --git a/debuggerd/debuggerd_test.cpp b/debuggerd/debuggerd_test.cpp
index e33cea5c8..5bdc94646 100644
--- a/debuggerd/debuggerd_test.cpp
+++ b/debuggerd/debuggerd_test.cpp
@@ -70,6 +70,7 @@
 #include "crash_test.h"
 #include "debuggerd/handler.h"
 #include "gtest/gtest.h"
+#include "libdebuggerd/utility_host.h"
 #include "protocol.h"
 #include "tombstoned/tombstoned.h"
 #include "util.h"
@@ -741,8 +742,6 @@ TEST_F(CrasherTest, mte_multiple_causes) {
 }
 
 #if defined(__aarch64__)
-constexpr size_t kTagGranuleSize = 16;
-
 static uintptr_t CreateTagMapping() {
   // Some of the MTE tag dump tests assert that there is an inaccessible page to the left and right
   // of the PROT_MTE page, so map three pages and set the two guard pages to PROT_NONE.
@@ -3303,3 +3302,30 @@ TEST_F(CrasherTest, log_with_newline) {
   ASSERT_MATCH(result, ":\\s*This line has a newline.");
   ASSERT_MATCH(result, ":\\s*This is on the next line.");
 }
+
+TEST_F(CrasherTest, log_with_non_utf8) {
+  StartProcess([]() { LOG(FATAL) << "Invalid UTF-8: \xA0\xB0\xC0\xD0 and some other data."; });
+
+  unique_fd output_fd;
+  StartIntercept(&output_fd);
+  FinishCrasher();
+  AssertDeath(SIGABRT);
+  int intercept_result;
+  FinishIntercept(&intercept_result);
+  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
+
+  std::string result;
+  ConsumeFd(std::move(output_fd), &result);
+  // Verify the abort message is sanitized properly.
+  size_t pos = result.find(
+      "Abort message: 'Invalid UTF-8: "
+      "\x5C\x32\x34\x30\x5C\x32\x36\x30\x5C\x33\x30\x30\x5C\x33\x32\x30 and some other data.'");
+  EXPECT_TRUE(pos != std::string::npos) << "Couldn't find sanitized abort message: " << result;
+
+  // Make sure that the log message is sanitized properly too.
+  EXPECT_TRUE(
+      result.find("Invalid UTF-8: \x5C\x32\x34\x30\x5C\x32\x36\x30\x5C\x33\x30\x30\x5C\x33\x32\x30 "
+                  "and some other data.",
+                  pos + 30) != std::string::npos)
+      << "Couldn't find sanitized log message: " << result;
+}
diff --git a/debuggerd/handler/debuggerd_handler.cpp b/debuggerd/handler/debuggerd_handler.cpp
index ddc3244f1..88278ca66 100644
--- a/debuggerd/handler/debuggerd_handler.cpp
+++ b/debuggerd/handler/debuggerd_handler.cpp
@@ -389,6 +389,13 @@ static DebuggerdDumpType get_dump_type(const debugger_thread_info* thread_info)
   return kDebuggerdTombstoneProto;
 }
 
+static const char* get_unwind_type(const debugger_thread_info* thread_info) {
+  if (thread_info->siginfo->si_signo == BIONIC_SIGNAL_DEBUGGER) {
+    return "Unwind request";
+  }
+  return "Crash due to signal";
+}
+
 static int debuggerd_dispatch_pseudothread(void* arg) {
   debugger_thread_info* thread_info = static_cast<debugger_thread_info*>(arg);
 
@@ -502,8 +509,8 @@ static int debuggerd_dispatch_pseudothread(void* arg) {
 
     execle(CRASH_DUMP_PATH, CRASH_DUMP_NAME, main_tid, pseudothread_tid, debuggerd_dump_type,
            nullptr, nullptr);
-    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "failed to exec crash_dump helper: %s",
-                          strerror(errno));
+    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "%s: failed to exec crash_dump helper: %s",
+                          get_unwind_type(thread_info), strerror(errno));
     return 1;
   }
 
@@ -524,26 +531,30 @@ static int debuggerd_dispatch_pseudothread(void* arg) {
   } else {
     // Something went wrong, log it.
     if (rc == -1) {
-      async_safe_format_log(ANDROID_LOG_FATAL, "libc", "read of IPC pipe failed: %s",
-                            strerror(errno));
+      async_safe_format_log(ANDROID_LOG_FATAL, "libc", "%s: read of IPC pipe failed: %s",
+                            get_unwind_type(thread_info), strerror(errno));
     } else if (rc == 0) {
       async_safe_format_log(ANDROID_LOG_FATAL, "libc",
-                            "crash_dump helper failed to exec, or was killed");
+                            "%s: crash_dump helper failed to exec, or was killed",
+                            get_unwind_type(thread_info));
     } else if (rc != 1) {
       async_safe_format_log(ANDROID_LOG_FATAL, "libc",
-                            "read of IPC pipe returned unexpected value: %zd", rc);
+                            "%s: read of IPC pipe returned unexpected value: %zd",
+                            get_unwind_type(thread_info), rc);
     } else if (buf[0] != '\1') {
-      async_safe_format_log(ANDROID_LOG_FATAL, "libc", "crash_dump helper reported failure");
+      async_safe_format_log(ANDROID_LOG_FATAL, "libc", "%s: crash_dump helper reported failure",
+                            get_unwind_type(thread_info));
     }
   }
 
   // Don't leave a zombie child.
   int status;
   if (TEMP_FAILURE_RETRY(waitpid(crash_dump_pid, &status, 0)) == -1) {
-    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "failed to wait for crash_dump helper: %s",
-                          strerror(errno));
+    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "%s: failed to wait for crash_dump helper: %s",
+                          get_unwind_type(thread_info), strerror(errno));
   } else if (WIFSTOPPED(status) || WIFSIGNALED(status)) {
-    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "crash_dump helper crashed or stopped");
+    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "%s: crash_dump helper crashed or stopped",
+                          get_unwind_type(thread_info));
   }
 
   if (success) {
diff --git a/debuggerd/libdebuggerd/include/libdebuggerd/tombstone.h b/debuggerd/libdebuggerd/include/libdebuggerd/tombstone.h
index 074b0957a..39989c3a3 100644
--- a/debuggerd/libdebuggerd/include/libdebuggerd/tombstone.h
+++ b/debuggerd/libdebuggerd/include/libdebuggerd/tombstone.h
@@ -67,10 +67,6 @@ void engrave_tombstone_proto(Tombstone* tombstone, unwindstack::AndroidUnwinder*
                              const Architecture* guest_arch,
                              unwindstack::AndroidUnwinder* guest_unwinder);
 
-bool tombstone_proto_to_text(
-    const Tombstone& tombstone,
-    std::function<void(const std::string& line, bool should_log)> callback);
-
 void fill_in_backtrace_frame(BacktraceFrame* f, const unwindstack::FrameData& frame);
 void set_human_readable_cause(Cause* cause, uint64_t fault_addr);
 #if defined(__aarch64__)
diff --git a/libprocessgroup/cgrouprc_format/include/processgroup/format/cgroup_file.h b/debuggerd/libdebuggerd/include/libdebuggerd/tombstone_proto_to_text.h
similarity index 54%
rename from libprocessgroup/cgrouprc_format/include/processgroup/format/cgroup_file.h
rename to debuggerd/libdebuggerd/include/libdebuggerd/tombstone_proto_to_text.h
index 2d9786fe6..2de972344 100644
--- a/libprocessgroup/cgrouprc_format/include/processgroup/format/cgroup_file.h
+++ b/debuggerd/libdebuggerd/include/libdebuggerd/tombstone_proto_to_text.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2019 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -16,23 +16,13 @@
 
 #pragma once
 
-#include <cstdint>
+#include <functional>
+#include <string>
 
-#include <processgroup/format/cgroup_controller.h>
+class BacktraceFrame;
+class Tombstone;
 
-namespace android {
-namespace cgrouprc {
-namespace format {
-
-struct CgroupFile {
-    uint32_t version_;
-    uint32_t controller_count_;
-    CgroupController controllers_[];
-
-    static constexpr uint32_t FILE_VERSION_1 = 1;
-    static constexpr uint32_t FILE_CURR_VERSION = FILE_VERSION_1;
-};
-
-}  // namespace format
-}  // namespace cgrouprc
-}  // namespace android
+bool tombstone_proto_to_text(
+    const Tombstone& tombstone,
+    std::function<void(const std::string& line, bool should_log)> callback,
+    std::function<void(const BacktraceFrame& frame)> symbolize);
diff --git a/debuggerd/libdebuggerd/include/libdebuggerd/utility.h b/debuggerd/libdebuggerd/include/libdebuggerd/utility.h
index 26c2cd44a..b86c13d08 100644
--- a/debuggerd/libdebuggerd/include/libdebuggerd/utility.h
+++ b/debuggerd/libdebuggerd/include/libdebuggerd/utility.h
@@ -91,10 +91,3 @@ bool signal_has_si_addr(const siginfo_t*);
 void get_signal_sender(char* buf, size_t n, const siginfo_t*);
 const char* get_signame(const siginfo_t*);
 const char* get_sigcode(const siginfo_t*);
-
-// Number of bytes per MTE granule.
-constexpr size_t kTagGranuleSize = 16;
-
-// Number of rows and columns to display in an MTE tag dump.
-constexpr size_t kNumTagColumns = 16;
-constexpr size_t kNumTagRows = 16;
diff --git a/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h b/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h
new file mode 100644
index 000000000..df22e017c
--- /dev/null
+++ b/debuggerd/libdebuggerd/include/libdebuggerd/utility_host.h
@@ -0,0 +1,33 @@
+/*
+ * Copyright 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
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
+#include <string>
+
+#include <stddef.h>
+
+std::string describe_tagged_addr_ctrl(long ctrl);
+std::string describe_pac_enabled_keys(long keys);
+
+// Number of bytes per MTE granule.
+constexpr size_t kTagGranuleSize = 16;
+
+// Number of rows and columns to display in an MTE tag dump.
+constexpr size_t kNumTagColumns = 16;
+constexpr size_t kNumTagRows = 16;
+
+std::string oct_encode(const std::string& data);
diff --git a/debuggerd/libdebuggerd/scudo.cpp b/debuggerd/libdebuggerd/scudo.cpp
index 4ee87c841..71d5fcfa7 100644
--- a/debuggerd/libdebuggerd/scudo.cpp
+++ b/debuggerd/libdebuggerd/scudo.cpp
@@ -18,6 +18,7 @@
 
 #include "libdebuggerd/scudo.h"
 #include "libdebuggerd/tombstone.h"
+#include "libdebuggerd/utility_host.h"
 
 #include "unwindstack/AndroidUnwinder.h"
 #include "unwindstack/Memory.h"
diff --git a/debuggerd/libdebuggerd/test/mte_stack_record_test.cpp b/debuggerd/libdebuggerd/test/mte_stack_record_test.cpp
index 4b788f3b7..bcda0ca5d 100644
--- a/debuggerd/libdebuggerd/test/mte_stack_record_test.cpp
+++ b/debuggerd/libdebuggerd/test/mte_stack_record_test.cpp
@@ -26,6 +26,8 @@
 #include "unwindstack/Memory.h"
 
 #include <android-base/test_utils.h>
+#include <procinfo/process_map.h>
+
 #include "gtest/gtest.h"
 
 #include "libdebuggerd/tombstone.h"
@@ -82,6 +84,33 @@ TEST(MteStackHistoryUnwindTest, TestOne) {
   EXPECT_EQ(e.tag(), 1ULL);
 }
 
+static std::optional<android::procinfo::MapInfo> FindMapping(void* data) {
+  std::optional<android::procinfo::MapInfo> result;
+  android::procinfo::ReadMapFile(
+      "/proc/self/maps", [&result, data](const android::procinfo::MapInfo& info) {
+        auto data_int = reinterpret_cast<uint64_t>(data) & ((1ULL << 56ULL) - 1ULL);
+        if (info.start <= data_int && data_int < info.end) {
+          result = info;
+        }
+      });
+  return result;
+}
+
+TEST_P(MteStackHistoryTest, TestFree) {
+  int size_cls = GetParam();
+  size_t size = stack_mte_ringbuffer_size(size_cls);
+  void* data = stack_mte_ringbuffer_allocate(size_cls, nullptr);
+  EXPECT_EQ(stack_mte_ringbuffer_size_from_pointer(reinterpret_cast<uintptr_t>(data)), size);
+  auto before = FindMapping(data);
+  ASSERT_TRUE(before.has_value());
+  EXPECT_EQ(before->end - before->start, size);
+  stack_mte_free_ringbuffer(reinterpret_cast<uintptr_t>(data));
+  for (size_t i = 0; i < size; i += page_size()) {
+    auto after = FindMapping(static_cast<char*>(data) + i);
+    EXPECT_TRUE(!after.has_value() || after->name != before->name);
+  }
+}
+
 TEST_P(MteStackHistoryTest, TestEmpty) {
   int size_cls = GetParam();
   size_t size = stack_mte_ringbuffer_size(size_cls);
diff --git a/debuggerd/libdebuggerd/test/tombstone_proto_to_text_test.cpp b/debuggerd/libdebuggerd/test/tombstone_proto_to_text_test.cpp
index 4fd264301..aad209a06 100644
--- a/debuggerd/libdebuggerd/test/tombstone_proto_to_text_test.cpp
+++ b/debuggerd/libdebuggerd/test/tombstone_proto_to_text_test.cpp
@@ -22,6 +22,7 @@
 #include <android-base/test_utils.h>
 
 #include "libdebuggerd/tombstone.h"
+#include "libdebuggerd/tombstone_proto_to_text.h"
 #include "tombstone.pb.h"
 
 using CallbackType = std::function<void(const std::string& line, bool should_log)>;
@@ -60,12 +61,16 @@ class TombstoneProtoToTextTest : public ::testing::Test {
 
   void ProtoToString() {
     text_ = "";
-    EXPECT_TRUE(
-        tombstone_proto_to_text(*tombstone_, [this](const std::string& line, bool should_log) {
+    EXPECT_TRUE(tombstone_proto_to_text(
+        *tombstone_,
+        [this](const std::string& line, bool should_log) {
           if (should_log) {
             text_ += "LOG ";
           }
           text_ += line + '\n';
+        },
+        [&](const BacktraceFrame& frame) {
+          text_ += "SYMBOLIZE " + frame.build_id() + " " + std::to_string(frame.pc()) + "\n";
         }));
   }
 
@@ -162,3 +167,11 @@ TEST_F(TombstoneProtoToTextTest, stack_record) {
   EXPECT_MATCH(text_, "stack_record fp:0x1 tag:0xb pc:foo\\.so\\+0x567 \\(BuildId: ABC123\\)");
   EXPECT_MATCH(text_, "stack_record fp:0x2 tag:0xc pc:bar\\.so\\+0x678");
 }
+
+TEST_F(TombstoneProtoToTextTest, symbolize) {
+  BacktraceFrame* frame = main_thread_->add_current_backtrace();
+  frame->set_pc(12345);
+  frame->set_build_id("0123456789abcdef");
+  ProtoToString();
+  EXPECT_MATCH(text_, "\\(BuildId: 0123456789abcdef\\)\\nSYMBOLIZE 0123456789abcdef 12345\\n");
+}
diff --git a/debuggerd/libdebuggerd/tombstone.cpp b/debuggerd/libdebuggerd/tombstone.cpp
index 0ce55738a..30c6fe4c5 100644
--- a/debuggerd/libdebuggerd/tombstone.cpp
+++ b/debuggerd/libdebuggerd/tombstone.cpp
@@ -17,6 +17,7 @@
 #define LOG_TAG "DEBUG"
 
 #include "libdebuggerd/tombstone.h"
+#include "libdebuggerd/tombstone_proto_to_text.h"
 
 #include <errno.h>
 #include <signal.h>
@@ -145,7 +146,10 @@ void engrave_tombstone(unique_fd output_fd, unique_fd proto_fd,
   log.tfd = output_fd.get();
   log.amfd_data = amfd_data;
 
-  tombstone_proto_to_text(tombstone, [&log](const std::string& line, bool should_log) {
-    _LOG(&log, should_log ? logtype::HEADER : logtype::LOGS, "%s\n", line.c_str());
-  });
+  tombstone_proto_to_text(
+      tombstone,
+      [&log](const std::string& line, bool should_log) {
+        _LOG(&log, should_log ? logtype::HEADER : logtype::LOGS, "%s\n", line.c_str());
+      },
+      [](const BacktraceFrame&) {});
 }
diff --git a/debuggerd/libdebuggerd/tombstone_proto.cpp b/debuggerd/libdebuggerd/tombstone_proto.cpp
index ed4fd5369..ef303f065 100644
--- a/debuggerd/libdebuggerd/tombstone_proto.cpp
+++ b/debuggerd/libdebuggerd/tombstone_proto.cpp
@@ -34,10 +34,13 @@
 #include <sys/sysinfo.h>
 #include <time.h>
 
+#include <map>
 #include <memory>
 #include <optional>
 #include <set>
 #include <string>
+#include <utility>
+#include <vector>
 
 #include <async_safe/log.h>
 
@@ -69,6 +72,7 @@
 
 #include "libdebuggerd/open_files_list.h"
 #include "libdebuggerd/utility.h"
+#include "libdebuggerd/utility_host.h"
 #include "util.h"
 
 #include "tombstone.pb.h"
@@ -462,7 +466,8 @@ static void dump_abort_message(Tombstone* tombstone,
   }
   msg.resize(index);
 
-  tombstone->set_abort_message(msg);
+  // Make sure only UTF8 characters are present since abort_message is a string.
+  tombstone->set_abort_message(oct_encode(msg));
 }
 
 static void dump_open_fds(Tombstone* tombstone, const OpenFilesList* open_files) {
@@ -770,7 +775,8 @@ static void dump_log_file(Tombstone* tombstone, const char* logger, pid_t pid) {
       log_msg->set_tid(log_entry.entry.tid);
       log_msg->set_priority(prio);
       log_msg->set_tag(tag);
-      log_msg->set_message(msg);
+      // Make sure only UTF8 characters are present since message is a string.
+      log_msg->set_message(oct_encode(msg));
     } while ((msg = nl));
   }
   android_logger_list_free(logger_list);
diff --git a/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp b/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
index c3f94700f..e885c5a73 100644
--- a/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
+++ b/debuggerd/libdebuggerd/tombstone_proto_to_text.cpp
@@ -14,13 +14,14 @@
  * limitations under the License.
  */
 
-#include <libdebuggerd/tombstone.h>
+#include <libdebuggerd/tombstone_proto_to_text.h>
+#include <libdebuggerd/utility_host.h>
 
 #include <inttypes.h>
 
-#include <charconv>
+#include <algorithm>
 #include <functional>
-#include <limits>
+#include <optional>
 #include <set>
 #include <string>
 #include <unordered_set>
@@ -30,9 +31,8 @@
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <android-base/unique_fd.h>
-#include <bionic/macros.h>
-#include <sys/prctl.h>
 
+#include "libdebuggerd/utility_host.h"
 #include "tombstone.pb.h"
 
 using android::base::StringAppendF;
@@ -42,6 +42,7 @@ using android::base::StringPrintf;
 #define CBL(...) CB(true, __VA_ARGS__)
 #define CBS(...) CB(false, __VA_ARGS__)
 using CallbackType = std::function<void(const std::string& line, bool should_log)>;
+using SymbolizeCallbackType = std::function<void(const BacktraceFrame& frame)>;
 
 #define DESCRIBE_FLAG(flag) \
   if (value & flag) {       \
@@ -57,28 +58,6 @@ static std::string describe_end(long value, std::string& desc) {
   return desc.empty() ? "" : " (" + desc.substr(2) + ")";
 }
 
-static std::string describe_tagged_addr_ctrl(long value) {
-  std::string desc;
-  DESCRIBE_FLAG(PR_TAGGED_ADDR_ENABLE);
-  DESCRIBE_FLAG(PR_MTE_TCF_SYNC);
-  DESCRIBE_FLAG(PR_MTE_TCF_ASYNC);
-  if (value & PR_MTE_TAG_MASK) {
-    desc += StringPrintf(", mask 0x%04lx", (value & PR_MTE_TAG_MASK) >> PR_MTE_TAG_SHIFT);
-    value &= ~PR_MTE_TAG_MASK;
-  }
-  return describe_end(value, desc);
-}
-
-static std::string describe_pac_enabled_keys(long value) {
-  std::string desc;
-  DESCRIBE_FLAG(PR_PAC_APIAKEY);
-  DESCRIBE_FLAG(PR_PAC_APIBKEY);
-  DESCRIBE_FLAG(PR_PAC_APDAKEY);
-  DESCRIBE_FLAG(PR_PAC_APDBKEY);
-  DESCRIBE_FLAG(PR_PAC_APGAKEY);
-  return describe_end(value, desc);
-}
-
 static const char* abi_string(const Architecture& arch) {
   switch (arch) {
     case Architecture::ARM32:
@@ -113,6 +92,13 @@ static int pointer_width(const Tombstone& tombstone) {
   }
 }
 
+static uint64_t untag_address(Architecture arch, uint64_t addr) {
+  if (arch == Architecture::ARM64) {
+    return addr & ((1ULL << 56) - 1);
+  }
+  return addr;
+}
+
 static void print_thread_header(CallbackType callback, const Tombstone& tombstone,
                                 const Thread& thread, bool should_log) {
   const char* process_name = "<unknown>";
@@ -200,7 +186,8 @@ static void print_thread_registers(CallbackType callback, const Tombstone& tombs
   print_register_row(callback, word_size, special_row, should_log);
 }
 
-static void print_backtrace(CallbackType callback, const Tombstone& tombstone,
+static void print_backtrace(CallbackType callback, SymbolizeCallbackType symbolize,
+                            const Tombstone& tombstone,
                             const google::protobuf::RepeatedPtrField<BacktraceFrame>& backtrace,
                             bool should_log) {
   int index = 0;
@@ -225,11 +212,14 @@ static void print_backtrace(CallbackType callback, const Tombstone& tombstone,
     }
     line += function + build_id;
     CB(should_log, "%s", line.c_str());
+
+    symbolize(frame);
   }
 }
 
-static void print_thread_backtrace(CallbackType callback, const Tombstone& tombstone,
-                                   const Thread& thread, bool should_log) {
+static void print_thread_backtrace(CallbackType callback, SymbolizeCallbackType symbolize,
+                                   const Tombstone& tombstone, const Thread& thread,
+                                   bool should_log) {
   CBS("");
   CB(should_log, "%d total frames", thread.current_backtrace().size());
   CB(should_log, "backtrace:");
@@ -237,7 +227,7 @@ static void print_thread_backtrace(CallbackType callback, const Tombstone& tombs
     CB(should_log, "  NOTE: %s",
        android::base::Join(thread.backtrace_note(), "\n  NOTE: ").c_str());
   }
-  print_backtrace(callback, tombstone, thread.current_backtrace(), should_log);
+  print_backtrace(callback, symbolize, tombstone, thread.current_backtrace(), should_log);
 }
 
 static void print_thread_memory_dump(CallbackType callback, const Tombstone& tombstone,
@@ -290,10 +280,11 @@ static void print_thread_memory_dump(CallbackType callback, const Tombstone& tom
   }
 }
 
-static void print_thread(CallbackType callback, const Tombstone& tombstone, const Thread& thread) {
+static void print_thread(CallbackType callback, SymbolizeCallbackType symbolize,
+                         const Tombstone& tombstone, const Thread& thread) {
   print_thread_header(callback, tombstone, thread, false);
   print_thread_registers(callback, tombstone, thread, false);
-  print_thread_backtrace(callback, tombstone, thread, false);
+  print_thread_backtrace(callback, symbolize, tombstone, thread, false);
   print_thread_memory_dump(callback, tombstone, thread);
 }
 
@@ -321,7 +312,8 @@ static void print_tag_dump(CallbackType callback, const Tombstone& tombstone) {
 
   size_t tag_index = 0;
   size_t num_tags = tags.length();
-  uintptr_t fault_granule = untag_address(signal.fault_address()) & ~(kTagGranuleSize - 1);
+  uintptr_t fault_granule =
+      untag_address(tombstone.arch(), signal.fault_address()) & ~(kTagGranuleSize - 1);
   for (size_t row = 0; tag_index < num_tags; ++row) {
     uintptr_t row_addr =
         (memory_dump.begin_address() + row * kNumTagColumns * kTagGranuleSize) & kRowStartMask;
@@ -369,7 +361,7 @@ static void print_memory_maps(CallbackType callback, const Tombstone& tombstone)
 
   const Signal& signal_info = tombstone.signal_info();
   bool has_fault_address = signal_info.has_fault_address();
-  uint64_t fault_address = untag_address(signal_info.fault_address());
+  uint64_t fault_address = untag_address(tombstone.arch(), signal_info.fault_address());
   bool preamble_printed = false;
   bool printed_fault_address_marker = false;
   for (const auto& map : tombstone.memory_mappings()) {
@@ -427,29 +419,8 @@ static void print_memory_maps(CallbackType callback, const Tombstone& tombstone)
   }
 }
 
-static std::string oct_encode(const std::string& data) {
-  std::string oct_encoded;
-  oct_encoded.reserve(data.size());
-
-  // N.B. the unsigned here is very important, otherwise e.g. \255 would render as
-  // \-123 (and overflow our buffer).
-  for (unsigned char c : data) {
-    if (isprint(c)) {
-      oct_encoded += c;
-    } else {
-      std::string oct_digits("\\\0\0\0", 4);
-      // char is encodable in 3 oct digits
-      static_assert(std::numeric_limits<unsigned char>::max() <= 8 * 8 * 8);
-      auto [ptr, ec] = std::to_chars(oct_digits.data() + 1, oct_digits.data() + 4, c, 8);
-      oct_digits.resize(ptr - oct_digits.data());
-      oct_encoded += oct_digits;
-    }
-  }
-  return oct_encoded;
-}
-
-static void print_main_thread(CallbackType callback, const Tombstone& tombstone,
-                              const Thread& thread) {
+static void print_main_thread(CallbackType callback, SymbolizeCallbackType symbolize,
+                              const Tombstone& tombstone, const Thread& thread) {
   print_thread_header(callback, tombstone, thread, true);
 
   const Signal& signal_info = tombstone.signal_info();
@@ -503,7 +474,7 @@ static void print_main_thread(CallbackType callback, const Tombstone& tombstone,
     CBL("      in this process. The stack trace below is the first system call or context");
     CBL("      switch that was executed after the memory corruption happened.");
   }
-  print_thread_backtrace(callback, tombstone, thread, true);
+  print_thread_backtrace(callback, symbolize, tombstone, thread, true);
 
   if (tombstone.causes_size() > 1) {
     CBS("");
@@ -536,13 +507,13 @@ static void print_main_thread(CallbackType callback, const Tombstone& tombstone,
       if (heap_object.deallocation_backtrace_size() != 0) {
         CBS("");
         CBL("deallocated by thread %" PRIu64 ":", heap_object.deallocation_tid());
-        print_backtrace(callback, tombstone, heap_object.deallocation_backtrace(), true);
+        print_backtrace(callback, symbolize, tombstone, heap_object.deallocation_backtrace(), true);
       }
 
       if (heap_object.allocation_backtrace_size() != 0) {
         CBS("");
         CBL("allocated by thread %" PRIu64 ":", heap_object.allocation_tid());
-        print_backtrace(callback, tombstone, heap_object.allocation_backtrace(), true);
+        print_backtrace(callback, symbolize, tombstone, heap_object.allocation_backtrace(), true);
       }
     }
   }
@@ -591,8 +562,9 @@ void print_logs(CallbackType callback, const Tombstone& tombstone, int tail) {
   }
 }
 
-static void print_guest_thread(CallbackType callback, const Tombstone& tombstone,
-                               const Thread& guest_thread, pid_t tid, bool should_log) {
+static void print_guest_thread(CallbackType callback, SymbolizeCallbackType symbolize,
+                               const Tombstone& tombstone, const Thread& guest_thread, pid_t tid,
+                               bool should_log) {
   CBS("--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---");
   CBS("Guest thread information for tid: %d", tid);
   print_thread_registers(callback, tombstone, guest_thread, should_log);
@@ -600,12 +572,13 @@ static void print_guest_thread(CallbackType callback, const Tombstone& tombstone
   CBS("");
   CB(true, "%d total frames", guest_thread.current_backtrace().size());
   CB(true, "backtrace:");
-  print_backtrace(callback, tombstone, guest_thread.current_backtrace(), should_log);
+  print_backtrace(callback, symbolize, tombstone, guest_thread.current_backtrace(), should_log);
 
   print_thread_memory_dump(callback, tombstone, guest_thread);
 }
 
-bool tombstone_proto_to_text(const Tombstone& tombstone, CallbackType callback) {
+bool tombstone_proto_to_text(const Tombstone& tombstone, CallbackType callback,
+                             SymbolizeCallbackType symbolize) {
   CBL("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***");
   CBL("Build fingerprint: '%s'", tombstone.build_fingerprint().c_str());
   CBL("Revision: '%s'", tombstone.revision().c_str());
@@ -633,14 +606,15 @@ bool tombstone_proto_to_text(const Tombstone& tombstone, CallbackType callback)
 
   const auto& main_thread = main_thread_it->second;
 
-  print_main_thread(callback, tombstone, main_thread);
+  print_main_thread(callback, symbolize, tombstone, main_thread);
 
   print_logs(callback, tombstone, 50);
 
   const auto& guest_threads = tombstone.guest_threads();
   auto main_guest_thread_it = guest_threads.find(tombstone.tid());
   if (main_guest_thread_it != threads.end()) {
-    print_guest_thread(callback, tombstone, main_guest_thread_it->second, tombstone.tid(), true);
+    print_guest_thread(callback, symbolize, tombstone, main_guest_thread_it->second,
+                       tombstone.tid(), true);
   }
 
   // protobuf's map is unordered, so sort the keys first.
@@ -653,10 +627,10 @@ bool tombstone_proto_to_text(const Tombstone& tombstone, CallbackType callback)
 
   for (const auto& tid : thread_ids) {
     CBS("--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---");
-    print_thread(callback, tombstone, threads.find(tid)->second);
+    print_thread(callback, symbolize, tombstone, threads.find(tid)->second);
     auto guest_thread_it = guest_threads.find(tid);
     if (guest_thread_it != guest_threads.end()) {
-      print_guest_thread(callback, tombstone, guest_thread_it->second, tid, false);
+      print_guest_thread(callback, symbolize, tombstone, guest_thread_it->second, tid, false);
     }
   }
 
diff --git a/debuggerd/libdebuggerd/utility.cpp b/debuggerd/libdebuggerd/utility.cpp
index 742ac7c27..b5a93b7db 100644
--- a/debuggerd/libdebuggerd/utility.cpp
+++ b/debuggerd/libdebuggerd/utility.cpp
@@ -17,6 +17,7 @@
 #define LOG_TAG "DEBUG"
 
 #include "libdebuggerd/utility.h"
+#include "libdebuggerd/utility_host.h"
 
 #include <errno.h>
 #include <signal.h>
diff --git a/debuggerd/libdebuggerd/utility_host.cpp b/debuggerd/libdebuggerd/utility_host.cpp
new file mode 100644
index 000000000..4efa03c8c
--- /dev/null
+++ b/debuggerd/libdebuggerd/utility_host.cpp
@@ -0,0 +1,124 @@
+/*
+ * Copyright 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "libdebuggerd/utility_host.h"
+
+#include <sys/prctl.h>
+
+#include <charconv>
+#include <limits>
+#include <string>
+
+#include <android-base/stringprintf.h>
+
+using android::base::StringPrintf;
+
+#ifndef PR_MTE_TAG_SHIFT
+#define PR_MTE_TAG_SHIFT 3
+#endif
+
+#ifndef PR_MTE_TAG_MASK
+#define PR_MTE_TAG_MASK (0xffffUL << PR_MTE_TAG_SHIFT)
+#endif
+
+#ifndef PR_MTE_TCF_ASYNC
+#define PR_MTE_TCF_ASYNC (1UL << 2)
+#endif
+
+#ifndef PR_MTE_TCF_SYNC
+#define PR_MTE_TCF_SYNC (1UL << 1)
+#endif
+
+#ifndef PR_PAC_APIAKEY
+#define PR_PAC_APIAKEY (1UL << 0)
+#endif
+
+#ifndef PR_PAC_APIBKEY
+#define PR_PAC_APIBKEY (1UL << 1)
+#endif
+
+#ifndef PR_PAC_APDAKEY
+#define PR_PAC_APDAKEY (1UL << 2)
+#endif
+
+#ifndef PR_PAC_APDBKEY
+#define PR_PAC_APDBKEY (1UL << 3)
+#endif
+
+#ifndef PR_PAC_APGAKEY
+#define PR_PAC_APGAKEY (1UL << 4)
+#endif
+
+#ifndef PR_TAGGED_ADDR_ENABLE
+#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
+#endif
+
+#define DESCRIBE_FLAG(flag) \
+  if (value & flag) {       \
+    desc += ", ";           \
+    desc += #flag;          \
+    value &= ~flag;         \
+  }
+
+static std::string describe_end(long value, std::string& desc) {
+  if (value) {
+    desc += StringPrintf(", unknown 0x%lx", value);
+  }
+  return desc.empty() ? "" : " (" + desc.substr(2) + ")";
+}
+
+std::string describe_tagged_addr_ctrl(long value) {
+  std::string desc;
+  DESCRIBE_FLAG(PR_TAGGED_ADDR_ENABLE);
+  DESCRIBE_FLAG(PR_MTE_TCF_SYNC);
+  DESCRIBE_FLAG(PR_MTE_TCF_ASYNC);
+  if (value & PR_MTE_TAG_MASK) {
+    desc += StringPrintf(", mask 0x%04lx", (value & PR_MTE_TAG_MASK) >> PR_MTE_TAG_SHIFT);
+    value &= ~PR_MTE_TAG_MASK;
+  }
+  return describe_end(value, desc);
+}
+
+std::string describe_pac_enabled_keys(long value) {
+  std::string desc;
+  DESCRIBE_FLAG(PR_PAC_APIAKEY);
+  DESCRIBE_FLAG(PR_PAC_APIBKEY);
+  DESCRIBE_FLAG(PR_PAC_APDAKEY);
+  DESCRIBE_FLAG(PR_PAC_APDBKEY);
+  DESCRIBE_FLAG(PR_PAC_APGAKEY);
+  return describe_end(value, desc);
+}
+
+std::string oct_encode(const std::string& data) {
+  std::string oct_encoded;
+  oct_encoded.reserve(data.size());
+
+  // N.B. the unsigned here is very important, otherwise e.g. \255 would render as
+  // \-123 (and overflow our buffer).
+  for (unsigned char c : data) {
+    if (isprint(c)) {
+      oct_encoded += c;
+    } else {
+      std::string oct_digits("\\\0\0\0", 4);
+      // char is encodable in 3 oct digits
+      static_assert(std::numeric_limits<unsigned char>::max() <= 8 * 8 * 8);
+      auto [ptr, ec] = std::to_chars(oct_digits.data() + 1, oct_digits.data() + 4, c, 8);
+      oct_digits.resize(ptr - oct_digits.data());
+      oct_encoded += oct_digits;
+    }
+  }
+  return oct_encoded;
+}
diff --git a/debuggerd/pbtombstone.cpp b/debuggerd/pbtombstone.cpp
index 7527e31e1..0902b386f 100644
--- a/debuggerd/pbtombstone.cpp
+++ b/debuggerd/pbtombstone.cpp
@@ -16,32 +16,55 @@
 
 #include <err.h>
 #include <fcntl.h>
+#include <getopt.h>
 #include <stdio.h>
 #include <unistd.h>
 
+#include <string>
+#include <vector>
+
 #include <android-base/unique_fd.h>
-#include <libdebuggerd/tombstone.h>
+#include <libdebuggerd/tombstone_proto_to_text.h>
 
 #include "tombstone.pb.h"
+#include "tombstone_symbolize.h"
 
 using android::base::unique_fd;
 
 [[noreturn]] void usage(bool error) {
-  fprintf(stderr, "usage: pbtombstone TOMBSTONE.PB\n");
+  fprintf(stderr, "usage: pbtombstone [OPTION] TOMBSTONE.PB\n");
   fprintf(stderr, "Convert a protobuf tombstone to text.\n");
+  fprintf(stderr, "Arguments:\n");
+  fprintf(stderr, "  -h, --help                   print this message\n");
+  fprintf(stderr, "  --debug-file-directory PATH  specify the path to a symbols directory\n");
   exit(error);
 }
 
-int main(int argc, const char* argv[]) {
-  if (argc != 2) {
-    usage(true);
+int main(int argc, char* argv[]) {
+  std::vector<std::string> debug_file_directories;
+  static struct option long_options[] = {
+      {"debug-file-directory", required_argument, 0, 0},
+      {"help", no_argument, 0, 'h'},
+      {},
+  };
+  int c;
+  while ((c = getopt_long(argc, argv, "h", long_options, 0)) != -1) {
+    switch (c) {
+      case 0:
+        debug_file_directories.push_back(optarg);
+        break;
+
+      case 'h':
+        usage(false);
+        break;
+    }
   }
 
-  if (strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0) {
-    usage(false);
+  if (optind != argc-1) {
+    usage(true);
   }
 
-  unique_fd fd(open(argv[1], O_RDONLY | O_CLOEXEC));
+  unique_fd fd(open(argv[optind], O_RDONLY | O_CLOEXEC));
   if (fd == -1) {
     err(1, "failed to open tombstone '%s'", argv[1]);
   }
@@ -51,8 +74,11 @@ int main(int argc, const char* argv[]) {
     err(1, "failed to parse tombstone");
   }
 
+  Symbolizer sym;
+  sym.Start(debug_file_directories);
   bool result = tombstone_proto_to_text(
-      tombstone, [](const std::string& line, bool) { printf("%s\n", line.c_str()); });
+      tombstone, [](const std::string& line, bool) { printf("%s\n", line.c_str()); },
+      [&](const BacktraceFrame& frame) { symbolize_backtrace_frame(frame, sym); });
 
   if (!result) {
     errx(1, "tombstone was malformed");
diff --git a/debuggerd/proto/Android.bp b/debuggerd/proto/Android.bp
index 7b9e780cc..70deb3cdd 100644
--- a/debuggerd/proto/Android.bp
+++ b/debuggerd/proto/Android.bp
@@ -38,6 +38,7 @@ cc_library_static {
     ramdisk_available: true,
     recovery_available: true,
     vendor_ramdisk_available: true,
+    host_supported: true,
 }
 
 java_library_static {
diff --git a/debuggerd/test_permissive_mte/Android.bp b/debuggerd/test_permissive_mte/Android.bp
index 0ad32439d..f333242cc 100644
--- a/debuggerd/test_permissive_mte/Android.bp
+++ b/debuggerd/test_permissive_mte/Android.bp
@@ -39,7 +39,7 @@ java_test_host {
         "src/**/PermissiveMteTest.java",
         ":libtombstone_proto-src",
     ],
-    data: [":mte_crash"],
+    device_first_data: [":mte_crash"],
     test_config: "AndroidTest.xml",
     test_suites: ["general-tests"],
 }
diff --git a/debuggerd/tombstone_symbolize.cpp b/debuggerd/tombstone_symbolize.cpp
new file mode 100644
index 000000000..07735d0ee
--- /dev/null
+++ b/debuggerd/tombstone_symbolize.cpp
@@ -0,0 +1,160 @@
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
+#include "tombstone_symbolize.h"
+
+#include <fcntl.h>
+#include <inttypes.h>
+#include <unistd.h>
+
+#include <string>
+#include <vector>
+
+#include "android-base/stringprintf.h"
+#include "android-base/unique_fd.h"
+
+#include "tombstone.pb.h"
+
+using android::base::StringPrintf;
+using android::base::unique_fd;
+
+bool Symbolizer::Start(const std::vector<std::string>& debug_file_directories) {
+  unique_fd parent_in, parent_out, child_in, child_out;
+  if (!Pipe(&parent_in, &child_out) || !Pipe(&child_in, &parent_out)) {
+    return false;
+  }
+
+  std::vector<const char *> args;
+  args.push_back("llvm-symbolizer");
+  for (const std::string &dir : debug_file_directories) {
+    args.push_back("--debug-file-directory");
+    args.push_back(dir.c_str());
+  }
+  args.push_back(0);
+
+  int pid = fork();
+  if (pid == -1) {
+    return false;
+  } else if (pid == 0) {
+    parent_in.reset();
+    parent_out.reset();
+
+    dup2(child_in.get(), STDIN_FILENO);
+    dup2(child_out.get(), STDOUT_FILENO);
+
+    execvp("llvm-symbolizer", const_cast<char *const *>(args.data()));
+
+    fprintf(stderr, "unable to start llvm-symbolizer: %s\n", strerror(errno));
+    _exit(1);
+  } else {
+    child_in.reset();
+    child_out.reset();
+
+    // TODO: Check that llvm-symbolizer started up successfully.
+    // There used to be an easy way to do this, but it was removed in:
+    // https://github.com/llvm/llvm-project/commit/1792852f86dc75efa1f44d46b1a0daf386d64afa
+
+    in_fd = std::move(parent_in);
+    out_fd = std::move(parent_out);
+    return true;
+  }
+}
+
+std::string Symbolizer::read_response() {
+  std::string resp;
+
+  while (resp.size() < 2 || resp[resp.size() - 2] != '\n' || resp[resp.size() - 1] != '\n') {
+    char buf[4096];
+    ssize_t size = read(in_fd, buf, 4096);
+    if (size <= 0) {
+      return "";
+    }
+    resp.append(buf, size);
+  }
+
+  return resp;
+}
+
+std::vector<Symbolizer::Frame> Symbolizer::SymbolizeCode(std::string path, uint64_t rel_pc) {
+  std::string request = StringPrintf("CODE %s 0x%" PRIx64 "\n", path.c_str(), rel_pc);
+  if (write(out_fd, request.c_str(), request.size()) != static_cast<ssize_t>(request.size())) {
+    return {};
+  }
+
+  std::string response = read_response();
+  if (response.empty()) {
+    return {};
+  }
+
+  std::vector<Symbolizer::Frame> frames;
+
+  size_t frame_start = 0;
+  while (frame_start < response.size() - 1) {
+    Symbolizer::Frame frame;
+
+    size_t second_line_start = response.find('\n', frame_start) + 1;
+    if (second_line_start == std::string::npos + 1) {
+      return {};
+    }
+
+    size_t third_line_start = response.find('\n', second_line_start) + 1;
+    if (third_line_start == std::string::npos + 1) {
+      return {};
+    }
+
+    frame.function_name = response.substr(frame_start, second_line_start - frame_start - 1);
+
+    size_t column_number_start = response.rfind(':', third_line_start);
+    if (column_number_start == std::string::npos) {
+      return {};
+    }
+
+    size_t line_number_start = response.rfind(':', column_number_start - 1);
+    if (line_number_start == std::string::npos) {
+      return {};
+    }
+
+    frame.file = response.substr(second_line_start, line_number_start - second_line_start);
+
+    errno = 0;
+    frame.line = strtoull(response.c_str() + line_number_start + 1, 0, 10);
+    frame.column = strtoull(response.c_str() + column_number_start + 1, 0, 10);
+    if (errno != 0) {
+      return {};
+    }
+
+    frames.push_back(frame);
+
+    frame_start = third_line_start;
+  }
+
+  if (frames.size() == 1 && frames[0].file == "??") {
+    return {};
+  }
+
+  return frames;
+}
+
+void symbolize_backtrace_frame(const BacktraceFrame& frame, Symbolizer& sym) {
+  if (frame.build_id().empty()) {
+    return;
+  }
+
+  for (Symbolizer::Frame f : sym.SymbolizeCode("BUILDID:" + frame.build_id(), frame.rel_pc())) {
+    printf("          %s:%" PRId64 ":%" PRId64 " (%s)\n", f.file.c_str(), f.line, f.column,
+           f.function_name.c_str());
+  }
+}
diff --git a/debuggerd/tombstone_symbolize.h b/debuggerd/tombstone_symbolize.h
new file mode 100644
index 000000000..c22d677ee
--- /dev/null
+++ b/debuggerd/tombstone_symbolize.h
@@ -0,0 +1,42 @@
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
+#pragma once
+
+#include <string>
+#include <vector>
+
+#include "android-base/unique_fd.h"
+
+class BacktraceFrame;
+
+class Symbolizer {
+  android::base::unique_fd in_fd, out_fd;
+
+  std::string read_response();
+
+ public:
+  bool Start(const std::vector<std::string>& debug_file_directories);
+
+  struct Frame {
+    std::string function_name, file;
+    uint64_t line, column;
+  };
+
+  std::vector<Frame> SymbolizeCode(std::string path, uint64_t rel_pc);
+};
+
+void symbolize_backtrace_frame(const BacktraceFrame& frame, Symbolizer& sym);
diff --git a/fastboot/Android.bp b/fastboot/Android.bp
index bfe0768f8..4d9898758 100644
--- a/fastboot/Android.bp
+++ b/fastboot/Android.bp
@@ -170,7 +170,7 @@ cc_binary {
         "android.hardware.fastboot@1.1",
         "android.hardware.fastboot-V1-ndk",
         "android.hardware.health@2.0",
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "libasyncio",
         "libbase",
         "libbinder_ndk",
@@ -201,7 +201,6 @@ cc_binary {
         "update_metadata-protos",
         "liburing",
     ],
-    include_dirs: ["bionic/libc/kernel"],
 
     header_libs: [
         "avb_headers",
@@ -430,6 +429,7 @@ cc_test_host {
     ],
     data: [
         ":fastboot_test_dtb",
+        ":fastboot_test_dtb_replace",
         ":fastboot_test_bootconfig",
         ":fastboot_test_vendor_ramdisk_none",
         ":fastboot_test_vendor_ramdisk_platform",
diff --git a/fastboot/fastboot.cpp b/fastboot/fastboot.cpp
index 6b9e493eb..156dc3b33 100644
--- a/fastboot/fastboot.cpp
+++ b/fastboot/fastboot.cpp
@@ -552,6 +552,12 @@ static int show_help() {
             "                            Secondary images may be flashed to inactive slot.\n"
             " flash PARTITION [FILENAME] Flash given partition, using the image from\n"
             "                            $ANDROID_PRODUCT_OUT if no filename is given.\n"
+            " flash vendor_boot:RAMDISK [FILENAME]\n"
+            "                            Flash vendor_boot ramdisk, fetching the existing\n"
+            "                            vendor_boot image and repackaging it with the new\n"
+            "                            ramdisk.\n"
+            " --dtb DTB                  If set with flash vendor_boot:RAMDISK, then\n"
+            "                            update the vendor_boot image with provided DTB.\n"
             "\n"
             "basics:\n"
             " devices [-l]               List devices in bootloader (-l: with device paths).\n"
@@ -1020,6 +1026,8 @@ static uint64_t get_uint_var(const char* var_name, fastboot::IFastBootDriver* fb
 }
 
 int64_t get_sparse_limit(int64_t size, const FlashingPlan* fp) {
+    if (!fp) return 0;
+
     int64_t limit = int64_t(fp->sparse_limit);
     if (limit == 0) {
         // Unlimited, so see what the target device's limit is.
@@ -1465,6 +1473,7 @@ static void do_fetch(const std::string& partition, const std::string& slot_overr
 static std::string repack_ramdisk(const char* pname, struct fastboot_buffer* buf,
                                   fastboot::IFastBootDriver* fb) {
     std::string_view pname_sv{pname};
+    struct fastboot_buffer dtb_buf = {.sz = 0, .fd = unique_fd(-1)};
 
     if (!android::base::StartsWith(pname_sv, "vendor_boot:") &&
         !android::base::StartsWith(pname_sv, "vendor_boot_a:") &&
@@ -1480,10 +1489,25 @@ static std::string repack_ramdisk(const char* pname, struct fastboot_buffer* buf
     std::string partition(pname_sv.substr(0, pname_sv.find(':')));
     std::string ramdisk(pname_sv.substr(pname_sv.find(':') + 1));
 
+    if (!g_dtb_path.empty()) {
+        if (!load_buf(g_dtb_path.c_str(), &dtb_buf, nullptr)) {
+            die("cannot load '%s': %s", g_dtb_path.c_str(), strerror(errno));
+        }
+
+        if (dtb_buf.type != FB_BUFFER_FD) {
+            die("Flashing sparse vendor ramdisk image with dtb is not supported.");
+        }
+        if (dtb_buf.sz <= 0) {
+            die("repack_ramdisk() sees invalid dtb size: %" PRId64, buf->sz);
+        }
+        verbose("Updating DTB with %s", pname_sv.data());
+    }
+
     unique_fd vendor_boot(make_temporary_fd("vendor boot repack"));
     uint64_t vendor_boot_size = fetch_partition(partition, vendor_boot, fb);
     auto repack_res = replace_vendor_ramdisk(vendor_boot, vendor_boot_size, ramdisk, buf->fd,
-                                             static_cast<uint64_t>(buf->sz));
+                                             static_cast<uint64_t>(buf->sz), dtb_buf.fd,
+                                             static_cast<uint64_t>(dtb_buf.sz));
     if (!repack_res.ok()) {
         die("%s", repack_res.error().message().c_str());
     }
diff --git a/fastboot/fuzzer/fastboot_fuzzer.cpp b/fastboot/fuzzer/fastboot_fuzzer.cpp
index 60940fe3d..4594a8ab4 100644
--- a/fastboot/fuzzer/fastboot_fuzzer.cpp
+++ b/fastboot/fuzzer/fastboot_fuzzer.cpp
@@ -15,6 +15,7 @@
  *
  */
 #include <android-base/file.h>
+#include <android-base/unique_fd.h>
 #include "fastboot.h"
 #include "socket.h"
 #include "socket_mock_fuzz.h"
@@ -25,6 +26,7 @@
 #include <fuzzer/FuzzedDataProvider.h>
 
 using namespace std;
+using android::base::unique_fd;
 
 const size_t kYearMin = 2000;
 const size_t kYearMax = 2127;
@@ -255,7 +257,7 @@ void FastbootFuzzer::InvokeVendorBootImgUtils(const uint8_t* data, size_t size)
     uint64_t ramdisk_size =
             fdp_->ConsumeBool() ? content_ramdisk_fd.size() : fdp_->ConsumeIntegral<uint64_t>();
     (void)replace_vendor_ramdisk(vendor_boot_fd, vendor_boot_size, ramdisk_name, ramdisk_fd,
-                                 ramdisk_size);
+                                 ramdisk_size, unique_fd(-1), 0);
     close(vendor_boot_fd);
     close(ramdisk_fd);
 }
diff --git a/fastboot/testdata/Android.bp b/fastboot/testdata/Android.bp
index a490fe270..47bf0959e 100644
--- a/fastboot/testdata/Android.bp
+++ b/fastboot/testdata/Android.bp
@@ -40,6 +40,14 @@ genrule {
     cmd: "$(location fastboot_gen_rand) --seed dtb --length 1024 > $(out)",
 }
 
+// Fake dtb image for replacement.
+genrule {
+    name: "fastboot_test_dtb_replace",
+    defaults: ["fastboot_test_data_gen_defaults"],
+    out: ["dtb_replace.img"],
+    cmd: "$(location fastboot_gen_rand) --seed dtb --length 2048 > $(out)",
+}
+
 // Fake bootconfig image.
 genrule {
     name: "fastboot_test_bootconfig",
diff --git a/fastboot/vendor_boot_img_utils.cpp b/fastboot/vendor_boot_img_utils.cpp
index 9f05253c0..da547f1bf 100644
--- a/fastboot/vendor_boot_img_utils.cpp
+++ b/fastboot/vendor_boot_img_utils.cpp
@@ -209,7 +209,8 @@ inline uint32_t round_up(uint32_t value, uint32_t page_size) {
 
 // Replace the vendor ramdisk as a whole.
 [[nodiscard]] Result<std::string> replace_default_vendor_ramdisk(const std::string& vendor_boot,
-                                                                 const std::string& new_ramdisk) {
+                                                                 const std::string& new_ramdisk,
+                                                                 const std::string& new_dtb) {
     if (auto res = check_vendor_boot_hdr(vendor_boot, 3); !res.ok()) return res.error();
     auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v3*>(vendor_boot.data());
     auto hdr_size = get_vendor_boot_header_size(hdr);
@@ -244,8 +245,19 @@ inline uint32_t round_up(uint32_t value, uint32_t page_size) {
         return res.error();
     if (auto res = updater.CheckOffset(o + p, o + new_p); !res.ok()) return res.error();
 
-    // Copy DTB (Q bytes).
-    if (auto res = updater.Copy(q); !res.ok()) return res.error();
+    // Copy DTB (Q bytes). Replace if a new one was provided.
+    new_hdr->dtb_size = !new_dtb.empty() ? new_dtb.size() : hdr->dtb_size;
+    const uint32_t new_q = round_up(new_hdr->dtb_size, new_hdr->page_size);
+    if (new_dtb.empty()) {
+        if (auto res = updater.Copy(q); !res.ok()) return res.error();
+    } else {
+        if (auto res = updater.Replace(hdr->dtb_size, new_dtb); !res.ok()) return res.error();
+        if (auto res = updater.Skip(q - hdr->dtb_size, new_q - new_hdr->dtb_size); !res.ok())
+            return res.error();
+    }
+    if (auto res = updater.CheckOffset(o + p + q, o + new_p + new_q); !res.ok()) {
+        return res.error();
+    }
 
     if (new_hdr->header_version >= 4) {
         auto hdr_v4 = static_cast<const vendor_boot_img_hdr_v4*>(hdr);
@@ -256,7 +268,7 @@ inline uint32_t round_up(uint32_t value, uint32_t page_size) {
         auto new_hdr_v4 = static_cast<const vendor_boot_img_hdr_v4*>(new_hdr);
         auto new_r = round_up(new_hdr_v4->vendor_ramdisk_table_size, new_hdr->page_size);
         if (auto res = updater.Skip(r, new_r); !res.ok()) return res.error();
-        if (auto res = updater.CheckOffset(o + p + q + r, o + new_p + q + new_r); !res.ok())
+        if (auto res = updater.CheckOffset(o + p + q + r, o + new_p + new_q + new_r); !res.ok())
             return res.error();
 
         // Replace table with single entry representing the full ramdisk.
@@ -303,7 +315,8 @@ inline uint32_t round_up(uint32_t value, uint32_t page_size) {
 // replace it with the content of |new_ramdisk|.
 [[nodiscard]] Result<std::string> replace_vendor_ramdisk_fragment(const std::string& ramdisk_name,
                                                                   const std::string& vendor_boot,
-                                                                  const std::string& new_ramdisk) {
+                                                                  const std::string& new_ramdisk,
+                                                                  const std::string& new_dtb) {
     if (auto res = check_vendor_boot_hdr(vendor_boot, 4); !res.ok()) return res.error();
     auto hdr = reinterpret_cast<const vendor_boot_img_hdr_v4*>(vendor_boot.data());
     auto hdr_size = get_vendor_boot_header_size(hdr);
@@ -368,8 +381,19 @@ inline uint32_t round_up(uint32_t value, uint32_t page_size) {
         return res.error();
     if (auto res = updater.CheckOffset(o + p, o + new_p); !res.ok()) return res.error();
 
-    // Copy DTB (Q bytes).
-    if (auto res = updater.Copy(q); !res.ok()) return res.error();
+    // Copy DTB (Q bytes). Replace if a new one was provided.
+    new_hdr->dtb_size = !new_dtb.empty() ? new_dtb.size() : hdr->dtb_size;
+    const uint32_t new_q = round_up(new_hdr->dtb_size, new_hdr->page_size);
+    if (new_dtb.empty()) {
+        if (auto res = updater.Copy(q); !res.ok()) return res.error();
+    } else {
+        if (auto res = updater.Replace(hdr->dtb_size, new_dtb); !res.ok()) return res.error();
+        if (auto res = updater.Skip(q - hdr->dtb_size, new_q - new_hdr->dtb_size); !res.ok())
+            return res.error();
+    }
+    if (auto res = updater.CheckOffset(o + p + q, o + new_p + new_q); !res.ok()) {
+        return res.error();
+    }
 
     // Copy table, but with corresponding entries modified, including:
     // - ramdisk_size of the entry replaced
@@ -392,7 +416,7 @@ inline uint32_t round_up(uint32_t value, uint32_t page_size) {
                                             hdr->vendor_ramdisk_table_entry_size);
         !res.ok())
         return res.error();
-    if (auto res = updater.CheckOffset(o + p + q + r, o + new_p + q + r); !res.ok())
+    if (auto res = updater.CheckOffset(o + p + q + r, o + new_p + new_q + r); !res.ok())
         return res.error();
 
     // Copy bootconfig (S bytes).
@@ -404,11 +428,11 @@ inline uint32_t round_up(uint32_t value, uint32_t page_size) {
 
 }  // namespace
 
-[[nodiscard]] Result<void> replace_vendor_ramdisk(android::base::borrowed_fd vendor_boot_fd,
-                                                  uint64_t vendor_boot_size,
-                                                  const std::string& ramdisk_name,
-                                                  android::base::borrowed_fd new_ramdisk_fd,
-                                                  uint64_t new_ramdisk_size) {
+[[nodiscard]] Result<void> replace_vendor_ramdisk(
+        android::base::borrowed_fd vendor_boot_fd, uint64_t vendor_boot_size,
+        const std::string& ramdisk_name, android::base::borrowed_fd new_ramdisk_fd,
+        uint64_t new_ramdisk_size, android::base::borrowed_fd new_dtb_fd, uint64_t new_dtb_size) {
+    Result<std::string> new_dtb = {""};
     if (new_ramdisk_size > std::numeric_limits<uint32_t>::max()) {
         return Errorf("New vendor ramdisk is too big");
     }
@@ -417,12 +441,17 @@ inline uint32_t round_up(uint32_t value, uint32_t page_size) {
     if (!vendor_boot.ok()) return vendor_boot.error();
     auto new_ramdisk = load_file(new_ramdisk_fd, new_ramdisk_size, "new vendor ramdisk");
     if (!new_ramdisk.ok()) return new_ramdisk.error();
+    if (new_dtb_size > 0 && new_dtb_fd >= 0) {
+        new_dtb = load_file(new_dtb_fd, new_dtb_size, "new dtb");
+        if (!new_dtb.ok()) return new_dtb.error();
+    }
 
     Result<std::string> new_vendor_boot;
     if (ramdisk_name == "default") {
-        new_vendor_boot = replace_default_vendor_ramdisk(*vendor_boot, *new_ramdisk);
+        new_vendor_boot = replace_default_vendor_ramdisk(*vendor_boot, *new_ramdisk, *new_dtb);
     } else {
-        new_vendor_boot = replace_vendor_ramdisk_fragment(ramdisk_name, *vendor_boot, *new_ramdisk);
+        new_vendor_boot =
+                replace_vendor_ramdisk_fragment(ramdisk_name, *vendor_boot, *new_ramdisk, *new_dtb);
     }
     if (!new_vendor_boot.ok()) return new_vendor_boot.error();
     if (auto res = store_file(vendor_boot_fd, *new_vendor_boot, "new vendor boot image"); !res.ok())
diff --git a/fastboot/vendor_boot_img_utils.h b/fastboot/vendor_boot_img_utils.h
index 0b702bc4d..0ca78dae2 100644
--- a/fastboot/vendor_boot_img_utils.h
+++ b/fastboot/vendor_boot_img_utils.h
@@ -31,4 +31,4 @@
 [[nodiscard]] android::base::Result<void> replace_vendor_ramdisk(
         android::base::borrowed_fd vendor_boot_fd, uint64_t vendor_boot_size,
         const std::string& ramdisk_name, android::base::borrowed_fd new_ramdisk_fd,
-        uint64_t new_ramdisk_size);
+        uint64_t new_ramdisk_size, android::base::borrowed_fd new_dtb_fd, uint64_t new_dtb_size);
diff --git a/fastboot/vendor_boot_img_utils_test.cpp b/fastboot/vendor_boot_img_utils_test.cpp
index 81072705d..841e532ac 100644
--- a/fastboot/vendor_boot_img_utils_test.cpp
+++ b/fastboot/vendor_boot_img_utils_test.cpp
@@ -241,6 +241,7 @@ RepackVendorBootImgTestEnv* env = nullptr;
 
 struct RepackVendorBootImgTestParam {
     std::string vendor_boot_file_name;
+    std::string dtb_file_name;
     uint32_t expected_header_version;
     friend std::ostream& operator<<(std::ostream& os, const RepackVendorBootImgTestParam& param) {
         return os << param.vendor_boot_file_name;
@@ -252,22 +253,50 @@ class RepackVendorBootImgTest : public ::testing::TestWithParam<RepackVendorBoot
     virtual void SetUp() {
         vboot = std::make_unique<ReadWriteTestFileHandle>(GetParam().vendor_boot_file_name);
         ASSERT_RESULT_OK(vboot->Open());
+
+        if (!GetParam().dtb_file_name.empty()) {
+            dtb_replacement = std::make_unique<ReadOnlyTestFileHandle>(GetParam().dtb_file_name);
+            ASSERT_RESULT_OK(dtb_replacement->Open());
+        }
     }
     std::unique_ptr<TestFileHandle> vboot;
+    std::unique_ptr<TestFileHandle> dtb_replacement;
 };
 
 TEST_P(RepackVendorBootImgTest, InvalidSize) {
-    EXPECT_ERROR(replace_vendor_ramdisk(vboot->fd(), vboot->size() + 1, "default",
-                                        env->replace->fd(), env->replace->size()),
-                 HasSubstr("Size of vendor boot does not match"));
-    EXPECT_ERROR(replace_vendor_ramdisk(vboot->fd(), vboot->size(), "default", env->replace->fd(),
-                                        env->replace->size() + 1),
-                 HasSubstr("Size of new vendor ramdisk does not match"));
+    EXPECT_ERROR(
+            replace_vendor_ramdisk(vboot->fd(), vboot->size() + 1, "default", env->replace->fd(),
+                                   env->replace->size(),
+                                   !GetParam().dtb_file_name.empty() ? dtb_replacement->fd()
+                                                                     : android::base::unique_fd(-1),
+                                   !GetParam().dtb_file_name.empty() ? dtb_replacement->size() : 0),
+            HasSubstr("Size of vendor boot does not match"));
+    EXPECT_ERROR(
+            replace_vendor_ramdisk(vboot->fd(), vboot->size(), "default", env->replace->fd(),
+                                   env->replace->size() + 1,
+                                   !GetParam().dtb_file_name.empty() ? dtb_replacement->fd()
+                                                                     : android::base::unique_fd(-1),
+                                   !GetParam().dtb_file_name.empty() ? dtb_replacement->size() : 0),
+            HasSubstr("Size of new vendor ramdisk does not match"));
+    if (!GetParam().dtb_file_name.empty()) {
+        EXPECT_ERROR(replace_vendor_ramdisk(vboot->fd(), vboot->size(), "default",
+                                            env->replace->fd(), env->replace->size(),
+                                            dtb_replacement->fd(), dtb_replacement->size() + 1),
+                     HasSubstr("Size of new dtb does not match"));
+    }
+    EXPECT_ERROR(
+            replace_vendor_ramdisk(
+                    vboot->fd(), vboot->size(), "default", env->replace->fd(), env->replace->size(),
+                    android::base::unique_fd(std::numeric_limits<int32_t>::max()), 1),
+            HasSubstr("Can't seek to the beginning of new dtb image"));
 }
 
 TEST_P(RepackVendorBootImgTest, ReplaceUnknown) {
-    auto res = replace_vendor_ramdisk(vboot->fd(), vboot->size(), "unknown", env->replace->fd(),
-                                      env->replace->size());
+    auto res = replace_vendor_ramdisk(
+            vboot->fd(), vboot->size(), "unknown", env->replace->fd(), env->replace->size(),
+            !GetParam().dtb_file_name.empty() ? dtb_replacement->fd()
+                                              : android::base::unique_fd(-1),
+            !GetParam().dtb_file_name.empty() ? dtb_replacement->size() : 0);
     if (GetParam().expected_header_version == 3) {
         EXPECT_ERROR(res, Eq("Require vendor boot header V4 but is V3"));
     } else if (GetParam().expected_header_version == 4) {
@@ -279,8 +308,11 @@ TEST_P(RepackVendorBootImgTest, ReplaceDefault) {
     auto old_content = vboot->Read();
     ASSERT_RESULT_OK(old_content);
 
-    ASSERT_RESULT_OK(replace_vendor_ramdisk(vboot->fd(), vboot->size(), "default",
-                                            env->replace->fd(), env->replace->size()));
+    ASSERT_RESULT_OK(replace_vendor_ramdisk(
+            vboot->fd(), vboot->size(), "default", env->replace->fd(), env->replace->size(),
+            !GetParam().dtb_file_name.empty() ? dtb_replacement->fd()
+                                              : android::base::unique_fd(-1),
+            !GetParam().dtb_file_name.empty() ? dtb_replacement->size() : 0));
     EXPECT_RESULT(vboot->fsize(), vboot->size()) << "File size should not change after repack";
 
     auto new_content_res = vboot->Read();
@@ -291,14 +323,23 @@ TEST_P(RepackVendorBootImgTest, ReplaceDefault) {
     ASSERT_EQ(0, memcmp(VENDOR_BOOT_MAGIC, hdr->magic, VENDOR_BOOT_MAGIC_SIZE));
     ASSERT_EQ(GetParam().expected_header_version, hdr->header_version);
     EXPECT_EQ(hdr->vendor_ramdisk_size, env->replace->size());
-    EXPECT_EQ(hdr->dtb_size, env->dtb->size());
+    if (GetParam().dtb_file_name.empty()) {
+        EXPECT_EQ(hdr->dtb_size, env->dtb->size());
+    } else {
+        EXPECT_EQ(hdr->dtb_size, dtb_replacement->size());
+    }
 
     auto o = round_up(sizeof(vendor_boot_img_hdr_v3), hdr->page_size);
     auto p = round_up(hdr->vendor_ramdisk_size, hdr->page_size);
     auto q = round_up(hdr->dtb_size, hdr->page_size);
 
     EXPECT_THAT(new_content.substr(o, p), IsPadded(env->replace_content));
-    EXPECT_THAT(new_content.substr(o + p, q), IsPadded(env->dtb_content));
+    if (GetParam().dtb_file_name.empty()) {
+        EXPECT_THAT(new_content.substr(o + p, q), IsPadded(env->dtb_content));
+    } else {
+        auto dtb_content_res = dtb_replacement->Read();
+        EXPECT_THAT(new_content.substr(o + p, q), IsPadded(*dtb_content_res));
+    }
 
     if (hdr->header_version < 4) return;
 
@@ -321,11 +362,17 @@ TEST_P(RepackVendorBootImgTest, ReplaceDefault) {
 
 INSTANTIATE_TEST_SUITE_P(
         RepackVendorBootImgTest, RepackVendorBootImgTest,
-        ::testing::Values(RepackVendorBootImgTestParam{"vendor_boot_v3.img", 3},
-                          RepackVendorBootImgTestParam{"vendor_boot_v4_with_frag.img", 4},
-                          RepackVendorBootImgTestParam{"vendor_boot_v4_without_frag.img", 4}),
+        ::testing::Values(RepackVendorBootImgTestParam{"vendor_boot_v3.img", "", 3},
+                          RepackVendorBootImgTestParam{"vendor_boot_v4_with_frag.img", "", 4},
+                          RepackVendorBootImgTestParam{"vendor_boot_v4_without_frag.img", "", 4},
+                          RepackVendorBootImgTestParam{"vendor_boot_v4_with_frag.img",
+                                                       "dtb_replace.img", 4},
+                          RepackVendorBootImgTestParam{"vendor_boot_v4_without_frag.img",
+                                                       "dtb_replace.img", 4}),
         [](const auto& info) {
-            return android::base::StringReplace(info.param.vendor_boot_file_name, ".", "_", false);
+            std::string test_name =
+                    android::base::StringReplace(info.param.vendor_boot_file_name, ".", "_", false);
+            return test_name + (!info.param.dtb_file_name.empty() ? "_replace_dtb" : "");
         });
 
 std::string_view GetRamdiskName(const vendor_ramdisk_table_entry_v4* entry) {
@@ -368,7 +415,8 @@ TEST_P(RepackVendorBootImgTestV4, Replace) {
     ASSERT_RESULT_OK(old_content);
 
     ASSERT_RESULT_OK(replace_vendor_ramdisk(vboot->fd(), vboot->size(), replace_ramdisk_name,
-                                            env->replace->fd(), env->replace->size()));
+                                            env->replace->fd(), env->replace->size(),
+                                            android::base::unique_fd(-1), 0));
     EXPECT_RESULT(vboot->fsize(), vboot->size()) << "File size should not change after repack";
 
     auto new_content_res = vboot->Read();
diff --git a/fs_mgr/TEST_MAPPING b/fs_mgr/TEST_MAPPING
index 192232d6c..13af1e2a3 100644
--- a/fs_mgr/TEST_MAPPING
+++ b/fs_mgr/TEST_MAPPING
@@ -27,7 +27,9 @@
     },
     {
       "name": "cow_api_test"
-    },
+    }
+  ],
+  "postsubmit": [
     {
       "name": "snapuserd_test"
     }
diff --git a/fs_mgr/fs_mgr.cpp b/fs_mgr/fs_mgr.cpp
index fbd990b96..9f52f4483 100644
--- a/fs_mgr/fs_mgr.cpp
+++ b/fs_mgr/fs_mgr.cpp
@@ -1603,7 +1603,8 @@ int fs_mgr_mount_all(Fstab* fstab, int mount_mode) {
                                    attempted_entry.fs_type,
                                    attempted_entry.fs_mgr_flags.is_zoned ? "true" : "false",
                                    std::to_string(attempted_entry.length),
-                                   android::base::Join(attempted_entry.user_devices, ' ')},
+                                   android::base::Join(attempted_entry.user_devices, ' '),
+                                   android::base::Join(attempted_entry.device_aliased, ' ')},
                                   nullptr)) {
                         LERROR << "Encryption failed";
                         set_type_property(encryptable);
@@ -1655,7 +1656,8 @@ int fs_mgr_mount_all(Fstab* fstab, int mount_mode) {
                                formattable_entry->fs_type,
                                formattable_entry->fs_mgr_flags.is_zoned ? "true" : "false",
                                std::to_string(formattable_entry->length),
-                               android::base::Join(formattable_entry->user_devices, ' ')},
+                               android::base::Join(formattable_entry->user_devices, ' '),
+                               android::base::Join(formattable_entry->device_aliased, ' ')},
                               nullptr)) {
                     LERROR << "Encryption failed";
                 } else {
@@ -2213,11 +2215,11 @@ bool fs_mgr_mount_overlayfs_fstab_entry(const FstabEntry& entry) {
 
 #if ALLOW_ADBD_DISABLE_VERITY == 0
     // Allowlist the mount point if user build.
-    static const std::vector<const std::string> kAllowedPaths = {
+    static const std::vector<std::string> kAllowedPaths = {
             "/odm",         "/odm_dlkm",   "/oem",    "/product",
             "/system_dlkm", "/system_ext", "/vendor", "/vendor_dlkm",
     };
-    static const std::vector<const std::string> kAllowedPrefixes = {
+    static const std::vector<std::string> kAllowedPrefixes = {
             "/mnt/product/",
             "/mnt/vendor/",
     };
@@ -2314,6 +2316,14 @@ std::string fs_mgr_get_context(const std::string& mount_point) {
     return context;
 }
 
+int fs_mgr_f2fs_ideal_block_size() {
+#if defined(__i386__) || defined(__x86_64__)
+    return 4096;
+#else
+    return getpagesize();
+#endif
+}
+
 namespace android {
 namespace fs_mgr {
 
diff --git a/fs_mgr/fs_mgr_format.cpp b/fs_mgr/fs_mgr_format.cpp
index 0dde1d374..57e35a275 100644
--- a/fs_mgr/fs_mgr_format.cpp
+++ b/fs_mgr/fs_mgr_format.cpp
@@ -32,6 +32,7 @@
 #include <selinux/android.h>
 #include <selinux/label.h>
 #include <selinux/selinux.h>
+#include <filesystem>
 #include <string>
 
 #include "fs_mgr_priv.h"
@@ -126,7 +127,8 @@ static int format_ext4(const std::string& fs_blkdev, const std::string& fs_mnt_p
 
 static int format_f2fs(const std::string& fs_blkdev, uint64_t dev_sz, bool needs_projid,
                        bool needs_casefold, bool fs_compress, bool is_zoned,
-                       const std::vector<std::string>& user_devices) {
+                       const std::vector<std::string>& user_devices,
+                       const std::vector<int>& device_aliased) {
     if (!dev_sz) {
         int rc = get_dev_sz(fs_blkdev, &dev_sz);
         if (rc) {
@@ -164,9 +166,15 @@ static int format_f2fs(const std::string& fs_blkdev, uint64_t dev_sz, bool needs
     if (is_zoned) {
         args.push_back("-m");
     }
-    for (auto& device : user_devices) {
+    for (size_t i = 0; i < user_devices.size(); i++) {
+        std::string device_name = user_devices[i];
+
         args.push_back("-c");
-        args.push_back(device.c_str());
+        if (device_aliased[i]) {
+            std::filesystem::path path = device_name;
+            device_name += "@" + path.filename().string();
+        }
+        args.push_back(device_name.c_str());
     }
 
     if (user_devices.empty()) {
@@ -191,7 +199,7 @@ int fs_mgr_do_format(const FstabEntry& entry) {
     if (entry.fs_type == "f2fs") {
         return format_f2fs(entry.blk_device, entry.length, needs_projid, needs_casefold,
                            entry.fs_mgr_flags.fs_compress, entry.fs_mgr_flags.is_zoned,
-                           entry.user_devices);
+                           entry.user_devices, entry.device_aliased);
     } else if (entry.fs_type == "ext4") {
         return format_ext4(entry.blk_device, entry.mount_point, needs_projid,
                            entry.fs_mgr_flags.ext_meta_csum);
diff --git a/fs_mgr/fs_mgr_overlayfs_control.cpp b/fs_mgr/fs_mgr_overlayfs_control.cpp
index 08ad80caa..489b32e7e 100644
--- a/fs_mgr/fs_mgr_overlayfs_control.cpp
+++ b/fs_mgr/fs_mgr_overlayfs_control.cpp
@@ -387,10 +387,8 @@ bool MakeScratchFilesystem(const std::string& scratch_device) {
     auto command = ""s;
     if (!access(kMkF2fs, X_OK) && fs_mgr_filesystem_available("f2fs")) {
         fs_type = "f2fs";
-        command = kMkF2fs + " -w "s;
-        command += std::to_string(getpagesize());
         command = kMkF2fs + " -b "s;
-        command += std::to_string(getpagesize());
+        command += std::to_string(fs_mgr_f2fs_ideal_block_size());
         command += " -f -d1 -l" + android::base::Basename(kScratchMountPoint);
     } else if (!access(kMkExt4, X_OK) && fs_mgr_filesystem_available("ext4")) {
         fs_type = "ext4";
diff --git a/fs_mgr/include/fs_mgr.h b/fs_mgr/include/fs_mgr.h
index 9cfa93f78..79690874e 100644
--- a/fs_mgr/include/fs_mgr.h
+++ b/fs_mgr/include/fs_mgr.h
@@ -137,3 +137,6 @@ bool fs_mgr_mount_overlayfs_fstab_entry(const android::fs_mgr::FstabEntry& entry
 // File name used to track if encryption was interrupted, leading to a known bad fs state
 std::string fs_mgr_metadata_encryption_in_progress_file_name(
         const android::fs_mgr::FstabEntry& entry);
+
+// Returns the ideal block size for make_f2fs. Returns -1 on failure.
+int fs_mgr_f2fs_ideal_block_size();
diff --git a/fs_mgr/libdm/Android.bp b/fs_mgr/libdm/Android.bp
index c3ca758ae..1efd7debc 100644
--- a/fs_mgr/libdm/Android.bp
+++ b/fs_mgr/libdm/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/fs_mgr/libfiemap/Android.bp b/fs_mgr/libfiemap/Android.bp
index c8d575630..a6be58582 100644
--- a/fs_mgr/libfiemap/Android.bp
+++ b/fs_mgr/libfiemap/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/fs_mgr/libfiemap/fiemap_writer_test.cpp b/fs_mgr/libfiemap/fiemap_writer_test.cpp
index c37329c36..115f53e8e 100644
--- a/fs_mgr/libfiemap/fiemap_writer_test.cpp
+++ b/fs_mgr/libfiemap/fiemap_writer_test.cpp
@@ -66,7 +66,11 @@ class FiemapWriterTest : public ::testing::Test {
         testfile = gTestDir + "/"s + tinfo->name();
     }
 
-    void TearDown() override { unlink(testfile.c_str()); }
+    void TearDown() override {
+        truncate(testfile.c_str(), 0);
+        unlink(testfile.c_str());
+        sync();
+    }
 
     // name of the file we use for testing
     std::string testfile;
diff --git a/fs_mgr/libfiemap/split_fiemap_writer.cpp b/fs_mgr/libfiemap/split_fiemap_writer.cpp
index 0df61253c..1f32d2f99 100644
--- a/fs_mgr/libfiemap/split_fiemap_writer.cpp
+++ b/fs_mgr/libfiemap/split_fiemap_writer.cpp
@@ -196,10 +196,13 @@ bool SplitFiemap::RemoveSplitFiles(const std::string& file_path, std::string* me
             if (access(file.c_str(), F_OK) != 0 && (errno == ENOENT || errno == ENAMETOOLONG)) {
                 continue;
             }
+            truncate(file.c_str(), 0);
             ok &= android::base::RemoveFileIfExists(file, message);
         }
     }
+    truncate(file_path.c_str(), 0);
     ok &= android::base::RemoveFileIfExists(file_path, message);
+    sync();
     return ok;
 }
 
diff --git a/fs_mgr/libfstab/fstab.cpp b/fs_mgr/libfstab/fstab.cpp
index d344b2d19..010fbc81d 100644
--- a/fs_mgr/libfstab/fstab.cpp
+++ b/fs_mgr/libfstab/fstab.cpp
@@ -39,10 +39,6 @@
 #include "fstab_priv.h"
 #include "logging_macros.h"
 
-#if !defined(MS_LAZYTIME)
-#define MS_LAZYTIME (1 << 25)
-#endif
-
 using android::base::EndsWith;
 using android::base::ParseByteCount;
 using android::base::ParseInt;
@@ -79,6 +75,7 @@ FlagList kMountFlagsList[] = {
         {"slave", MS_SLAVE},
         {"shared", MS_SHARED},
         {"lazytime", MS_LAZYTIME},
+        {"nosymfollow", MS_NOSYMFOLLOW},
         {"defaults", 0},
 };
 
@@ -173,6 +170,7 @@ void ParseUserDevices(const std::string& arg, FstabEntry* entry) {
         entry->fs_mgr_flags.is_zoned = true;
     }
     entry->user_devices.push_back(param[1]);
+    entry->device_aliased.push_back(param[0] == "exp_alias" ? 1 : 0);
 }
 
 bool ParseFsMgrFlags(const std::string& flags, FstabEntry* entry) {
@@ -261,7 +259,7 @@ bool ParseFsMgrFlags(const std::string& flags, FstabEntry* entry) {
             if (!arg.empty() && arg.back() == '%') {
                 arg.pop_back();
                 int val;
-                if (ParseInt(arg, &val, 0, 100)) {
+                if (ParseInt(arg, &val, 0, 200)) {
                     entry->zram_size = CalculateZramSize(val);
                 } else {
                     LWARNING << "Warning: zramsize= flag malformed: " << arg;
@@ -949,6 +947,22 @@ std::set<std::string> GetBootDevices() {
     return ExtraBootDevices(fstab);
 }
 
+std::string GetBootPartUuid() {
+    std::string boot_part_uuid;
+
+    if (GetBootconfig("androidboot.boot_part_uuid", &boot_part_uuid)) {
+        return boot_part_uuid;
+    }
+
+    ImportKernelCmdline([&](std::string key, std::string value) {
+        if (key == "androidboot.boot_part_uuid") {
+            boot_part_uuid = value;
+        }
+    });
+
+    return boot_part_uuid;
+}
+
 std::string GetVerityDeviceName(const FstabEntry& entry) {
     std::string base_device;
     if (entry.mount_point == "/") {
diff --git a/fs_mgr/libfstab/include/fstab/fstab.h b/fs_mgr/libfstab/include/fstab/fstab.h
index 21fe01726..0ff3188d4 100644
--- a/fs_mgr/libfstab/include/fstab/fstab.h
+++ b/fs_mgr/libfstab/include/fstab/fstab.h
@@ -33,6 +33,7 @@ namespace fs_mgr {
 struct FstabEntry {
     std::string blk_device;
     std::vector<std::string> user_devices;
+    std::vector<int> device_aliased;
     std::string logical_partition_name;
     std::string mount_point;
     std::string fs_type;
@@ -125,6 +126,16 @@ void TransformFstabForDsu(Fstab* fstab, const std::string& dsu_slot,
 
 std::set<std::string> GetBootDevices();
 
+// Get the Partition UUID the kernel loaded from if the bootloader passed it.
+//
+// If the kernel's Partition UUID is provided then we can use this to help
+// identify which block device contains the filesystems we care about.
+//
+// NOTE: Nothing secures a UUID other than the convention that two disks
+// aren't supposed to both have the same UUID. We still need other mechanisms
+// to ensure we've got the right disk.
+std::string GetBootPartUuid();
+
 // Return the name of the dm-verity device for the given fstab entry. This does
 // not check whether the device is valid or exists; it merely returns the
 // expected name.
diff --git a/fs_mgr/liblp/Android.bp b/fs_mgr/liblp/Android.bp
index 24eebdfb9..b211e83da 100644
--- a/fs_mgr/liblp/Android.bp
+++ b/fs_mgr/liblp/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/fs_mgr/liblp/super_layout_builder.cpp b/fs_mgr/liblp/super_layout_builder.cpp
index fd7416bb2..bff26ea21 100644
--- a/fs_mgr/liblp/super_layout_builder.cpp
+++ b/fs_mgr/liblp/super_layout_builder.cpp
@@ -184,7 +184,7 @@ std::vector<SuperImageExtent> SuperLayoutBuilder::GetImageLayout() {
                 return {};
             }
 
-            size_t size = e.num_sectors * LP_SECTOR_SIZE;
+            uint64_t size = e.num_sectors * LP_SECTOR_SIZE;
             uint64_t super_offset = e.target_data * LP_SECTOR_SIZE;
             extents.emplace_back(super_offset, size, image_name, image_offset);
 
diff --git a/fs_mgr/libsnapshot/Android.bp b/fs_mgr/libsnapshot/Android.bp
index 50efb03bd..966696b05 100644
--- a/fs_mgr/libsnapshot/Android.bp
+++ b/fs_mgr/libsnapshot/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/fs_mgr/libsnapshot/android/snapshot/snapshot.proto b/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
index 62f99013e..5fb71a37b 100644
--- a/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
+++ b/fs_mgr/libsnapshot/android/snapshot/snapshot.proto
@@ -233,6 +233,8 @@ message SnapshotUpdateStatus {
     // Number of cow operations to be merged at once
     uint32 cow_op_merge_size = 13;
 
+    // Number of worker threads to serve I/O from dm-user
+    uint32 num_worker_threads = 14;
 }
 
 // Next: 10
diff --git a/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h b/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
index 7ae55db31..de2052631 100644
--- a/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
+++ b/fs_mgr/libsnapshot/include/libsnapshot/snapshot.h
@@ -442,6 +442,7 @@ class SnapshotManager final : public ISnapshotManager {
     FRIEND_TEST(SnapshotUpdateTest, QueryStatusError);
     FRIEND_TEST(SnapshotUpdateTest, SnapshotStatusFileWithoutCow);
     FRIEND_TEST(SnapshotUpdateTest, SpaceSwapUpdate);
+    FRIEND_TEST(SnapshotUpdateTest, InterruptMergeDuringPhaseUpdate);
     FRIEND_TEST(SnapshotUpdateTest, MapAllSnapshotsWithoutSlotSwitch);
     friend class SnapshotTest;
     friend class SnapshotUpdateTest;
@@ -838,6 +839,10 @@ class SnapshotManager final : public ISnapshotManager {
 
     // Get value of maximum cow op merge size
     uint32_t GetUpdateCowOpMergeSize(LockedFile* lock);
+
+    // Get number of threads to perform post OTA boot verification
+    uint32_t GetUpdateWorkerCount(LockedFile* lock);
+
     // Wrapper around libdm, with diagnostics.
     bool DeleteDeviceIfExists(const std::string& name,
                               const std::chrono::milliseconds& timeout_ms = {});
diff --git a/fs_mgr/libsnapshot/libsnapshot_cow/test_v2.cpp b/fs_mgr/libsnapshot/libsnapshot_cow/test_v2.cpp
index ce80cd705..b7bc2c8b7 100644
--- a/fs_mgr/libsnapshot/libsnapshot_cow/test_v2.cpp
+++ b/fs_mgr/libsnapshot/libsnapshot_cow/test_v2.cpp
@@ -1487,7 +1487,7 @@ TEST_F(CowTest, InvalidMergeOrderTest) {
     writer = std::make_unique<CowWriterV2>(options, GetCowFd());
     ASSERT_TRUE(writer->Initialize());
     ASSERT_TRUE(writer->AddCopy(2, 1));
-    ASSERT_TRUE(writer->AddXorBlocks(3, &data, data.size(), 1, 1));
+    ASSERT_TRUE(writer->AddXorBlocks(3, data.data(), data.size(), 1, 1));
     ASSERT_TRUE(writer->Finalize());
     ASSERT_TRUE(reader.Parse(cow_->fd));
     ASSERT_FALSE(reader.VerifyMergeOps());
diff --git a/fs_mgr/libsnapshot/scripts/apply-update.sh b/fs_mgr/libsnapshot/scripts/apply-update.sh
new file mode 100755
index 000000000..90b0119a2
--- /dev/null
+++ b/fs_mgr/libsnapshot/scripts/apply-update.sh
@@ -0,0 +1,77 @@
+#!/bin/bash
+
+# This is a debug script to quicky test end-to-end flow
+# of snapshot updates without going through update-engine.
+#
+# Usage:
+#
+#  To update both dynamic and static partitions:
+#
+# ./system/core/fs_mgr/libsnapshot/apply_update.sh [--update-static-partitions] [--wipe]
+#
+# --update-static-partitions: This will update bootloader and static A/B
+# partitions
+# --wipe: Allows data wipe as part of update flow
+#
+#  To update dynamic partitions only (this should be used when static
+#  partitions are present in both the slots):
+#
+#  ./system/core/fs_mgr/libsnapshot/apply_update.sh
+#
+#
+
+rm -f $OUT/*.patch
+
+# Compare images and create snapshot patches. Currently, this
+# just compares two identical images in $OUT. In general, any source
+# and target images could be passed to create snapshot patches. However,
+# care must be taken to ensure source images are already present on the device.
+#
+# create_snapshot is a host side binary. Build it with `m create_snapshot`
+create_snapshot --source=$OUT/system.img --target=$OUT/system.img &
+create_snapshot --source=$OUT/product.img --target=$OUT/product.img &
+create_snapshot --source=$OUT/vendor.img --target=$OUT/vendor.img &
+create_snapshot --source=$OUT/system_ext.img --target=$OUT/system_ext.img &
+create_snapshot --source=$OUT/vendor_dlkm.img --target=$OUT/vendor_dlkm.img &
+create_snapshot --source=$OUT/system_dlkm.img --target=$OUT/system_dlkm.img &
+
+echo "Waiting for snapshot patch creation"
+wait $(jobs -p)
+echo "Snapshot patch creation completed"
+
+mv *.patch $OUT/
+
+adb root
+adb wait-for-device
+adb shell mkdir -p /data/update/
+adb push $OUT/*.patch /data/update/
+
+if [[ "$2" == "--wipe" ]]; then
+  adb shell snapshotctl apply-update /data/update/ -w
+else
+  adb shell snapshotctl apply-update /data/update/
+fi
+
+# Check if the --update-static-partitions option is provided.
+# For quick developer workflow, there is no need to repeatedly
+# apply static partitions.
+if [[ "$1" == "--update-static-partitions" ]]; then
+  adb reboot bootloader
+  sleep 5
+  if [[ "$2" == "--wipe" ]]; then
+      fastboot -w
+  fi
+  fastboot flash bootloader $OUT/bootloader.img
+  sleep 1
+  fastboot reboot bootloader
+  sleep 1
+  fastboot flash radio $OUT/radio.img
+  sleep 1
+  fastboot reboot bootloader
+  sleep 1
+  fastboot flashall --exclude-dynamic-partitions --disable-super-optimization
+else
+  adb reboot
+fi
+
+echo "Update completed"
diff --git a/fs_mgr/libsnapshot/snapshot.cpp b/fs_mgr/libsnapshot/snapshot.cpp
index 6c3bedd86..ecf567eb8 100644
--- a/fs_mgr/libsnapshot/snapshot.cpp
+++ b/fs_mgr/libsnapshot/snapshot.cpp
@@ -1235,8 +1235,8 @@ auto SnapshotManager::CheckMergeState(LockedFile* lock,
                 wrong_phase = true;
                 break;
             default:
-                LOG(ERROR) << "Unknown merge status for \"" << snapshot << "\": "
-                           << "\"" << result.state << "\"";
+                LOG(ERROR) << "Unknown merge status for \"" << snapshot << "\": " << "\""
+                           << result.state << "\"";
                 if (failure_code == MergeFailureCode::Ok) {
                     failure_code = MergeFailureCode::UnexpectedMergeState;
                 }
@@ -1343,10 +1343,25 @@ auto SnapshotManager::CheckTargetMergeState(LockedFile* lock, const std::string&
         }
 
         if (merge_status == "snapshot" &&
-            DecideMergePhase(snapshot_status) == MergePhase::SECOND_PHASE &&
-            update_status.merge_phase() == MergePhase::FIRST_PHASE) {
-            // The snapshot is not being merged because it's in the wrong phase.
-            return MergeResult(UpdateState::None);
+            DecideMergePhase(snapshot_status) == MergePhase::SECOND_PHASE) {
+            if (update_status.merge_phase() == MergePhase::FIRST_PHASE) {
+                // The snapshot is not being merged because it's in the wrong phase.
+                return MergeResult(UpdateState::None);
+            } else {
+                // update_status is already in second phase but the
+                // snapshot_status is still not set to SnapshotState::MERGING.
+                //
+                // Resume the merge at this point. see b/374225913
+                LOG(INFO) << "SwitchSnapshotToMerge: " << name << " after resuming merge";
+                auto code = SwitchSnapshotToMerge(lock, name);
+                if (code != MergeFailureCode::Ok) {
+                    LOG(ERROR) << "Failed to switch snapshot: " << name
+                               << " to merge during second phase";
+                    return MergeResult(UpdateState::MergeFailed,
+                                       MergeFailureCode::UnknownTargetType);
+                }
+                return MergeResult(UpdateState::Merging);
+            }
         }
 
         if (merge_status == "snapshot-merge") {
@@ -1442,8 +1457,14 @@ MergeFailureCode SnapshotManager::MergeSecondPhaseSnapshots(LockedFile* lock) {
         return MergeFailureCode::WriteStatus;
     }
 
+    auto current_slot_suffix = device_->GetSlotSuffix();
     MergeFailureCode result = MergeFailureCode::Ok;
     for (const auto& snapshot : snapshots) {
+        if (!android::base::EndsWith(snapshot, current_slot_suffix)) {
+            LOG(ERROR) << "Skipping invalid snapshot: " << snapshot
+                       << " during MergeSecondPhaseSnapshots";
+            continue;
+        }
         SnapshotStatus snapshot_status;
         if (!ReadSnapshotStatus(lock, snapshot, &snapshot_status)) {
             return MergeFailureCode::ReadStatus;
@@ -1725,6 +1746,10 @@ bool SnapshotManager::PerformInitTransition(InitTransition transition,
         if (cow_op_merge_size != 0) {
             snapuserd_argv->emplace_back("-cow_op_merge_size=" + std::to_string(cow_op_merge_size));
         }
+        uint32_t worker_count = GetUpdateWorkerCount(lock.get());
+        if (worker_count != 0) {
+            snapuserd_argv->emplace_back("-worker_count=" + std::to_string(worker_count));
+        }
     }
 
     size_t num_cows = 0;
@@ -2152,6 +2177,11 @@ uint32_t SnapshotManager::GetUpdateCowOpMergeSize(LockedFile* lock) {
     return update_status.cow_op_merge_size();
 }
 
+uint32_t SnapshotManager::GetUpdateWorkerCount(LockedFile* lock) {
+    SnapshotUpdateStatus update_status = ReadSnapshotUpdateStatus(lock);
+    return update_status.num_worker_threads();
+}
+
 bool SnapshotManager::MarkSnapuserdFromSystem() {
     auto path = GetSnapuserdFromSystemPath();
 
@@ -2374,6 +2404,9 @@ bool SnapshotManager::NeedSnapshotsInFirstStageMount() {
                 PLOG(ERROR) << "Unable to write rollback indicator: " << path;
             } else {
                 LOG(INFO) << "Rollback detected, writing rollback indicator to " << path;
+                if (device_->IsTempMetadata()) {
+                    CleanupScratchOtaMetadataIfPresent();
+                }
             }
         }
         LOG(INFO) << "Not booting from new slot. Will not mount snapshots.";
@@ -3140,6 +3173,7 @@ bool SnapshotManager::WriteUpdateState(LockedFile* lock, UpdateState state,
         status.set_legacy_snapuserd(old_status.legacy_snapuserd());
         status.set_o_direct(old_status.o_direct());
         status.set_cow_op_merge_size(old_status.cow_op_merge_size());
+        status.set_num_worker_threads(old_status.num_worker_threads());
     }
     return WriteSnapshotUpdateStatus(lock, status);
 }
@@ -3524,6 +3558,9 @@ Return SnapshotManager::CreateUpdateSnapshots(const DeltaArchiveManifest& manife
         }
         status.set_cow_op_merge_size(
                 android::base::GetUintProperty<uint32_t>("ro.virtual_ab.cow_op_merge_size", 0));
+        status.set_num_worker_threads(
+                android::base::GetUintProperty<uint32_t>("ro.virtual_ab.num_worker_threads", 0));
+
     } else if (legacy_compression) {
         LOG(INFO) << "Virtual A/B using legacy snapuserd";
     } else {
@@ -3960,6 +3997,7 @@ bool SnapshotManager::Dump(std::ostream& os) {
     ss << "Using io_uring: " << update_status.io_uring_enabled() << std::endl;
     ss << "Using o_direct: " << update_status.o_direct() << std::endl;
     ss << "Cow op merge size (0 for uncapped): " << update_status.cow_op_merge_size() << std::endl;
+    ss << "Worker thread count: " << update_status.num_worker_threads() << std::endl;
     ss << "Using XOR compression: " << GetXorCompressionEnabledProperty() << std::endl;
     ss << "Current slot: " << device_->GetSlotSuffix() << std::endl;
     ss << "Boot indicator: booting from " << GetCurrentSlot() << " slot" << std::endl;
@@ -4576,8 +4614,7 @@ bool SnapshotManager::DeleteDeviceIfExists(const std::string& name,
         }
     }
 
-    LOG(ERROR) << "Device-mapper device " << name << "(" << full_path << ")"
-               << " still in use."
+    LOG(ERROR) << "Device-mapper device " << name << "(" << full_path << ")" << " still in use."
                << "  Probably a file descriptor was leaked or held open, or a loop device is"
                << " attached.";
     return false;
diff --git a/fs_mgr/libsnapshot/snapshot_test.cpp b/fs_mgr/libsnapshot/snapshot_test.cpp
index 46c3a35e9..1a0d55979 100644
--- a/fs_mgr/libsnapshot/snapshot_test.cpp
+++ b/fs_mgr/libsnapshot/snapshot_test.cpp
@@ -1607,6 +1607,146 @@ TEST_F(SnapshotUpdateTest, SpaceSwapUpdate) {
     }
 }
 
+// Test that shrinking and growing partitions at the same time is handled
+// correctly in VABC.
+TEST_F(SnapshotUpdateTest, InterruptMergeDuringPhaseUpdate) {
+    if (!snapuserd_required_) {
+        // b/179111359
+        GTEST_SKIP() << "Skipping snapuserd test";
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
+
+    // Check that the old partition sizes were saved correctly.
+    {
+        ASSERT_TRUE(AcquireLock());
+        auto local_lock = std::move(lock_);
+
+        SnapshotStatus status;
+        ASSERT_TRUE(sm->ReadSnapshotStatus(local_lock.get(), "prd_b", &status));
+        ASSERT_EQ(status.old_partition_size(), 3145728);
+        ASSERT_TRUE(sm->ReadSnapshotStatus(local_lock.get(), "sys_b", &status));
+        ASSERT_EQ(status.old_partition_size(), 3145728);
+    }
+
+    ASSERT_TRUE(WriteSnapshotAndHash(sys_));
+    ASSERT_TRUE(WriteSnapshotAndHash(vnd_));
+    ASSERT_TRUE(ShiftAllSnapshotBlocks("prd_b", old_prd_size));
+
+    sync();
+
+    // Assert that source partitions aren't affected.
+    for (const auto& name : {"sys_a", "vnd_a", "prd_a"}) {
+        ASSERT_TRUE(IsPartitionUnchanged(name));
+    }
+
+    ASSERT_TRUE(sm->FinishedSnapshotWrites(false));
+
+    // Simulate shutting down the device.
+    ASSERT_TRUE(UnmapAll());
+
+    // After reboot, init does first stage mount.
+    auto init = NewManagerForFirstStageMount("_b");
+    ASSERT_NE(init, nullptr);
+    ASSERT_TRUE(init->NeedSnapshotsInFirstStageMount());
+    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
+
+    // Check that the target partitions have the same content.
+    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
+        ASSERT_TRUE(IsPartitionUnchanged(name));
+    }
+
+    // Initiate the merge and wait for it to be completed.
+    if (ShouldSkipLegacyMerging()) {
+        LOG(INFO) << "Skipping legacy merge in test";
+        return;
+    }
+    ASSERT_TRUE(init->InitiateMerge());
+    ASSERT_EQ(init->IsSnapuserdRequired(), snapuserd_required_);
+    {
+        // Check that the merge phase is FIRST_PHASE until at least one call
+        // to ProcessUpdateState() occurs.
+        ASSERT_TRUE(AcquireLock());
+        auto local_lock = std::move(lock_);
+        auto status = init->ReadSnapshotUpdateStatus(local_lock.get());
+        ASSERT_EQ(status.merge_phase(), MergePhase::FIRST_PHASE);
+    }
+
+    // Wait until prd_b merge is completed which is part of first phase
+    std::chrono::milliseconds timeout(6000);
+    auto start = std::chrono::steady_clock::now();
+    // Keep polling until the merge is complete or timeout is reached
+    while (true) {
+        // Query the merge status
+        const auto merge_status = init->snapuserd_client()->QuerySnapshotStatus("prd_b");
+        if (merge_status == "snapshot-merge-complete") {
+            break;
+        }
+
+        auto now = std::chrono::steady_clock::now();
+        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
+
+        ASSERT_TRUE(elapsed < timeout);
+        // sleep for a second and allow merge to complete
+        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
+    }
+
+    // Now, forcefully update the snapshot-update status to SECOND PHASE
+    // This will not update the snapshot status of sys_b to MERGING
+    if (init->UpdateUsesUserSnapshots()) {
+        ASSERT_TRUE(AcquireLock());
+        auto local_lock = std::move(lock_);
+        auto status = init->ReadSnapshotUpdateStatus(local_lock.get());
+        status.set_merge_phase(MergePhase::SECOND_PHASE);
+        ASSERT_TRUE(init->WriteSnapshotUpdateStatus(local_lock.get(), status));
+    }
+
+    // Simulate shutting down the device and creating partitions again.
+    ASSERT_TRUE(UnmapAll());
+    ASSERT_TRUE(init->CreateLogicalAndSnapshotPartitions("super", snapshot_timeout_));
+
+    DeviceMapper::TargetInfo target;
+    ASSERT_TRUE(init->IsSnapshotDevice("prd_b", &target));
+
+    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "user");
+    ASSERT_TRUE(init->IsSnapshotDevice("sys_b", &target));
+    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "user");
+    ASSERT_TRUE(init->IsSnapshotDevice("vnd_b", &target));
+    ASSERT_EQ(DeviceMapper::GetTargetType(target.spec), "user");
+
+    // Complete the merge; "sys" and "vnd" should resume the merge
+    // even though merge was interrupted after update_status was updated to
+    // SECOND_PHASE
+    ASSERT_EQ(UpdateState::MergeCompleted, init->ProcessUpdateState());
+
+    // Make sure the second phase ran and deleted snapshots.
+    {
+        ASSERT_TRUE(AcquireLock());
+        auto local_lock = std::move(lock_);
+        std::vector<std::string> snapshots;
+        ASSERT_TRUE(init->ListSnapshots(local_lock.get(), &snapshots));
+        ASSERT_TRUE(snapshots.empty());
+    }
+
+    // Check that the target partitions have the same content after the merge.
+    for (const auto& name : {"sys_b", "vnd_b", "prd_b"}) {
+        ASSERT_TRUE(IsPartitionUnchanged(name))
+                << "Content of " << name << " changes after the merge";
+    }
+}
+
 // Test that if new system partitions uses empty space in super, that region is not snapshotted.
 TEST_F(SnapshotUpdateTest, DirectWriteEmptySpace) {
     GTEST_SKIP() << "b/141889746";
@@ -2518,9 +2658,6 @@ TEST_F(SnapshotUpdateTest, MapAllSnapshotsWithoutSlotSwitch) {
     // Remove the indicators
     ASSERT_TRUE(sm->PrepareDeviceToBootWithoutSnapshot());
 
-    // Ensure snapshots are still mounted
-    ASSERT_TRUE(sm->IsUserspaceSnapshotUpdateInProgress());
-
     // Cleanup snapshots
     ASSERT_TRUE(sm->UnmapAllSnapshots());
 }
diff --git a/fs_mgr/libsnapshot/snapshotctl.cpp b/fs_mgr/libsnapshot/snapshotctl.cpp
index 97a8cb210..46de991d0 100644
--- a/fs_mgr/libsnapshot/snapshotctl.cpp
+++ b/fs_mgr/libsnapshot/snapshotctl.cpp
@@ -105,7 +105,7 @@ class MapSnapshots {
     bool FinishSnapshotWrites();
     bool UnmapCowImagePath(std::string& name);
     bool DeleteSnapshots();
-    bool CleanupSnapshot() { return sm_->PrepareDeviceToBootWithoutSnapshot(); }
+    bool CleanupSnapshot();
     bool BeginUpdate();
     bool ApplyUpdate();
 
@@ -495,6 +495,11 @@ bool MapSnapshots::UnmapCowImagePath(std::string& name) {
     return sm_->UnmapCowImage(name);
 }
 
+bool MapSnapshots::CleanupSnapshot() {
+    sm_ = SnapshotManager::New();
+    return sm_->PrepareDeviceToBootWithoutSnapshot();
+}
+
 bool MapSnapshots::DeleteSnapshots() {
     sm_ = SnapshotManager::New();
     lock_ = sm_->LockExclusive();
diff --git a/fs_mgr/libsnapshot/snapuserd/Android.bp b/fs_mgr/libsnapshot/snapuserd/Android.bp
index 8d0bf7d6b..639116e8d 100644
--- a/fs_mgr/libsnapshot/snapuserd/Android.bp
+++ b/fs_mgr/libsnapshot/snapuserd/Android.bp
@@ -15,6 +15,7 @@
 //
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -85,11 +86,9 @@ cc_library_static {
         "libsnapshot_cow",
         "liburing",
         "libprocessgroup",
+        "libprocessgroup_util",
         "libjsoncpp",
-        "libcgrouprc",
-        "libcgrouprc_format",
     ],
-    include_dirs: ["bionic/libc/kernel"],
     export_include_dirs: ["include"],
     header_libs: [
         "libcutils_headers",
@@ -129,9 +128,8 @@ cc_defaults {
         "libsnapshot_cow",
         "libsnapuserd",
         "libprocessgroup",
+        "libprocessgroup_util",
         "libjsoncpp",
-        "libcgrouprc",
-        "libcgrouprc_format",
         "libsnapuserd_client",
         "libz",
         "liblz4",
@@ -145,7 +143,6 @@ cc_defaults {
         "libstorage_literals_headers",
     ],
 
-    include_dirs: ["bionic/libc/kernel"],
     system_shared_libs: [],
 
     // snapuserd is started during early boot by first-stage init. At that
@@ -221,14 +218,12 @@ cc_defaults {
         "libsnapshot_cow",
         "libsnapuserd",
         "libprocessgroup",
+        "libprocessgroup_util",
         "libjsoncpp",
-        "libcgrouprc",
-        "libcgrouprc_format",
         "liburing",
         "libz",
     ],
     include_dirs: [
-        "bionic/libc/kernel",
         ".",
     ],
     header_libs: [
@@ -267,6 +262,10 @@ cc_test {
                 name: "force-no-test-error",
                 value: "false",
             },
+            {
+                name: "native-test-timeout",
+                value: "15m",
+            },
         ],
     },
 }
@@ -318,13 +317,10 @@ cc_binary_host {
         "libsnapuserd",
         "libprocessgroup",
         "libjsoncpp",
-        "libcgrouprc",
-        "libcgrouprc_format",
         "liburing",
         "libz",
     ],
     include_dirs: [
-        "bionic/libc/kernel",
         ".",
     ],
     header_libs: [
diff --git a/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp b/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
index ddefb9f91..7c820f32b 100644
--- a/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/snapuserd_client.cpp
@@ -311,6 +311,11 @@ double SnapuserdClient::GetMergePercent() {
     }
     std::string response = Receivemsg();
 
+    // If server socket disconnects most likely because of device reboot,
+    // then we just return 0.
+    if (response.empty()) {
+        return 0.0;
+    }
     return std::stod(response);
 }
 
diff --git a/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp b/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
index dd2dd5659..32e16cc80 100644
--- a/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/snapuserd_daemon.cpp
@@ -31,6 +31,7 @@ DEFINE_bool(user_snapshot, false, "If true, user-space snapshots are used");
 DEFINE_bool(io_uring, false, "If true, io_uring feature is enabled");
 DEFINE_bool(o_direct, false, "If true, enable direct reads on source device");
 DEFINE_int32(cow_op_merge_size, 0, "number of operations to be processed at once");
+DEFINE_int32(worker_count, 4, "number of worker threads used to serve I/O requests to dm-user");
 
 namespace android {
 namespace snapshot {
@@ -114,8 +115,9 @@ bool Daemon::StartServerForUserspaceSnapshots(int arg_start, int argc, char** ar
             LOG(ERROR) << "Malformed message, expected at least four sub-arguments.";
             return false;
         }
-        auto handler = user_server_.AddHandler(parts[0], parts[1], parts[2], parts[3],
-                                               FLAGS_o_direct, FLAGS_cow_op_merge_size);
+        auto handler =
+                user_server_.AddHandler(parts[0], parts[1], parts[2], parts[3], FLAGS_worker_count,
+                                        FLAGS_o_direct, FLAGS_cow_op_merge_size);
         if (!handler || !user_server_.StartHandler(parts[0])) {
             return false;
         }
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
index e2c58741a..febb4847d 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/merge_worker.cpp
@@ -55,7 +55,7 @@ int MergeWorker::PrepareMerge(uint64_t* source_offset, int* pending_ops,
                 break;
             }
 
-            *source_offset = cow_op->new_block * BLOCK_SZ;
+            *source_offset = static_cast<uint64_t>(cow_op->new_block) * BLOCK_SZ;
             if (!checkOrderedOp) {
                 replace_zero_vec->push_back(cow_op);
                 if (cow_op->type() == kCowReplaceOp) {
@@ -74,7 +74,7 @@ int MergeWorker::PrepareMerge(uint64_t* source_offset, int* pending_ops,
                     break;
                 }
 
-                uint64_t next_offset = op->new_block * BLOCK_SZ;
+                uint64_t next_offset = static_cast<uint64_t>(op->new_block) * BLOCK_SZ;
                 if (next_offset != (*source_offset + nr_consecutive * BLOCK_SZ)) {
                     break;
                 }
@@ -233,6 +233,11 @@ bool MergeWorker::MergeOrderedOpsAsync() {
             return false;
         }
 
+        std::optional<std::lock_guard<std::mutex>> buffer_lock;
+        // Acquire the buffer lock at this point so that RA thread
+        // doesn't step into this buffer. See b/377819507
+        buffer_lock.emplace(snapuserd_->GetBufferLock());
+
         snapuserd_->SetMergeInProgress(ra_block_index_);
 
         loff_t offset = 0;
@@ -383,6 +388,9 @@ bool MergeWorker::MergeOrderedOpsAsync() {
         // Mark the block as merge complete
         snapuserd_->SetMergeCompleted(ra_block_index_);
 
+        // Release the buffer lock
+        buffer_lock.reset();
+
         // Notify RA thread that the merge thread is ready to merge the next
         // window
         snapuserd_->NotifyRAForMergeReady();
@@ -415,6 +423,11 @@ bool MergeWorker::MergeOrderedOps() {
             return false;
         }
 
+        std::optional<std::lock_guard<std::mutex>> buffer_lock;
+        // Acquire the buffer lock at this point so that RA thread
+        // doesn't step into this buffer. See b/377819507
+        buffer_lock.emplace(snapuserd_->GetBufferLock());
+
         snapuserd_->SetMergeInProgress(ra_block_index_);
 
         loff_t offset = 0;
@@ -468,6 +481,9 @@ bool MergeWorker::MergeOrderedOps() {
         // Mark the block as merge complete
         snapuserd_->SetMergeCompleted(ra_block_index_);
 
+        // Release the buffer lock
+        buffer_lock.reset();
+
         // Notify RA thread that the merge thread is ready to merge the next
         // window
         snapuserd_->NotifyRAForMergeReady();
@@ -582,7 +598,6 @@ bool MergeWorker::Run() {
     pthread_setname_np(pthread_self(), "MergeWorker");
 
     if (!snapuserd_->WaitForMergeBegin()) {
-        SNAP_LOG(ERROR) << "Merge terminated early...";
         return true;
     }
     auto merge_thread_priority = android::base::GetUintProperty<uint32_t>(
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/read_worker.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/read_worker.cpp
index ef311d475..33767d654 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/read_worker.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/read_worker.cpp
@@ -104,6 +104,8 @@ bool ReadWorker::ProcessCopyOp(const CowOperation* cow_op, void* buffer) {
 }
 
 bool ReadWorker::ProcessXorOp(const CowOperation* cow_op, void* buffer) {
+    using WordType = std::conditional_t<sizeof(void*) == sizeof(uint64_t), uint64_t, uint32_t>;
+
     if (!ReadFromSourceDevice(cow_op, buffer)) {
         return false;
     }
@@ -120,9 +122,12 @@ bool ReadWorker::ProcessXorOp(const CowOperation* cow_op, void* buffer) {
         return false;
     }
 
-    auto xor_out = reinterpret_cast<uint8_t*>(buffer);
-    for (size_t i = 0; i < BLOCK_SZ; i++) {
-        xor_out[i] ^= xor_buffer_[i];
+    auto xor_in = reinterpret_cast<const WordType*>(xor_buffer_.data());
+    auto xor_out = reinterpret_cast<WordType*>(buffer);
+    auto num_words = BLOCK_SZ / sizeof(WordType);
+
+    for (auto i = 0; i < num_words; i++) {
+        xor_out[i] ^= xor_in[i];
     }
     return true;
 }
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
index c7de9951f..2340b0b20 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_core.h
@@ -186,6 +186,7 @@ class SnapshotHandler : public std::enable_shared_from_this<SnapshotHandler> {
 
     bool IsIouringSupported();
     bool CheckPartitionVerification();
+    std::mutex& GetBufferLock() { return buffer_lock_; }
 
   private:
     bool ReadMetadata();
@@ -216,6 +217,9 @@ class SnapshotHandler : public std::enable_shared_from_this<SnapshotHandler> {
     std::mutex lock_;
     std::condition_variable cv;
 
+    // Lock the buffer used for snapshot-merge
+    std::mutex buffer_lock_;
+
     void* mapped_addr_;
     size_t total_mapped_addr_length_;
 
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_readahead.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_readahead.cpp
index 6b1ed0cd7..c7ae51926 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_readahead.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_readahead.cpp
@@ -458,6 +458,7 @@ bool ReadAhead::ReapIoCompletions(int pending_ios_to_complete) {
 void ReadAhead::ProcessXorData(size_t& block_xor_index, size_t& xor_index,
                                std::vector<const CowOperation*>& xor_op_vec, void* buffer,
                                loff_t& buffer_offset) {
+    using WordType = std::conditional_t<sizeof(void*) == sizeof(uint64_t), uint64_t, uint32_t>;
     loff_t xor_buf_offset = 0;
 
     while (block_xor_index < blocks_.size()) {
@@ -470,13 +471,14 @@ void ReadAhead::ProcessXorData(size_t& block_xor_index, size_t& xor_index,
             // Check if this block is an XOR op
             if (xor_op->new_block == new_block) {
                 // Pointer to the data read from base device
-                uint8_t* buffer = reinterpret_cast<uint8_t*>(bufptr);
+                auto buffer_words = reinterpret_cast<WordType*>(bufptr);
                 // Get the xor'ed data read from COW device
-                uint8_t* xor_data = reinterpret_cast<uint8_t*>((char*)bufsink_.GetPayloadBufPtr() +
-                                                               xor_buf_offset);
+                auto xor_data_words = reinterpret_cast<WordType*>(
+                        (char*)bufsink_.GetPayloadBufPtr() + xor_buf_offset);
+                auto num_words = BLOCK_SZ / sizeof(WordType);
 
-                for (size_t byte_offset = 0; byte_offset < BLOCK_SZ; byte_offset++) {
-                    buffer[byte_offset] ^= xor_data[byte_offset];
+                for (auto i = 0; i < num_words; i++) {
+                    buffer_words[i] ^= xor_data_words[i];
                 }
 
                 // Move to next XOR op
@@ -700,28 +702,35 @@ bool ReadAhead::ReadAheadIOStart() {
     // window. If there is a crash during this time frame, merge should resume
     // based on the contents of the scratch space.
     if (!snapuserd_->WaitForMergeReady()) {
-        SNAP_LOG(ERROR) << "ReadAhead failed to wait for merge ready";
+        SNAP_LOG(VERBOSE) << "ReadAhead failed to wait for merge ready";
         return false;
     }
 
-    // Copy the data to scratch space
-    memcpy(metadata_buffer_, ra_temp_meta_buffer_.get(), snapuserd_->GetBufferMetadataSize());
-    memcpy(read_ahead_buffer_, ra_temp_buffer_.get(), total_blocks_merged_ * BLOCK_SZ);
+    // Acquire buffer lock before doing memcpy to the scratch buffer. Although,
+    // by now snapshot-merge thread shouldn't be working on this scratch space
+    // but we take additional measure to ensure that the buffer is not being
+    // used by the merge thread at this point. see b/377819507
+    {
+        std::lock_guard<std::mutex> buffer_lock(snapuserd_->GetBufferLock());
+        // Copy the data to scratch space
+        memcpy(metadata_buffer_, ra_temp_meta_buffer_.get(), snapuserd_->GetBufferMetadataSize());
+        memcpy(read_ahead_buffer_, ra_temp_buffer_.get(), total_blocks_merged_ * BLOCK_SZ);
 
-    loff_t offset = 0;
-    std::unordered_map<uint64_t, void*>& read_ahead_buffer_map = snapuserd_->GetReadAheadMap();
-    read_ahead_buffer_map.clear();
+        loff_t offset = 0;
+        std::unordered_map<uint64_t, void*>& read_ahead_buffer_map = snapuserd_->GetReadAheadMap();
+        read_ahead_buffer_map.clear();
 
-    for (size_t block_index = 0; block_index < blocks_.size(); block_index++) {
-        void* bufptr = static_cast<void*>((char*)read_ahead_buffer_ + offset);
-        uint64_t new_block = blocks_[block_index];
+        for (size_t block_index = 0; block_index < blocks_.size(); block_index++) {
+            void* bufptr = static_cast<void*>((char*)read_ahead_buffer_ + offset);
+            uint64_t new_block = blocks_[block_index];
 
-        read_ahead_buffer_map[new_block] = bufptr;
-        offset += BLOCK_SZ;
-    }
+            read_ahead_buffer_map[new_block] = bufptr;
+            offset += BLOCK_SZ;
+        }
 
-    total_ra_blocks_completed_ += total_blocks_merged_;
-    snapuserd_->SetMergedBlockCountForNextCommit(total_blocks_merged_);
+        total_ra_blocks_completed_ += total_blocks_merged_;
+        snapuserd_->SetMergedBlockCountForNextCommit(total_blocks_merged_);
+    }
 
     // Flush the scratch data - Technically, we should flush only for overlapping
     // blocks; However, since this region is mmap'ed, the dirty pages can still
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
index 013df350b..3bb8a3037 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.cpp
@@ -35,6 +35,7 @@
 #include <snapuserd/dm_user_block_server.h>
 #include <snapuserd/snapuserd_client.h>
 #include "snapuserd_server.h"
+#include "user-space-merge/snapuserd_core.h"
 
 namespace android {
 namespace snapshot {
@@ -125,7 +126,7 @@ bool UserSnapshotServer::Receivemsg(android::base::borrowed_fd fd, const std::st
             return Sendmsg(fd, "fail");
         }
 
-        auto handler = AddHandler(out[1], out[2], out[3], out[4]);
+        auto handler = AddHandler(out[1], out[2], out[3], out[4], std::nullopt);
         if (!handler) {
             return Sendmsg(fd, "fail");
         }
@@ -341,12 +342,11 @@ void UserSnapshotServer::Interrupt() {
     SetTerminating();
 }
 
-std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(const std::string& misc_name,
-                                                              const std::string& cow_device_path,
-                                                              const std::string& backing_device,
-                                                              const std::string& base_path_merge,
-                                                              const bool o_direct,
-                                                              uint32_t cow_op_merge_size) {
+std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(
+        const std::string& misc_name, const std::string& cow_device_path,
+        const std::string& backing_device, const std::string& base_path_merge,
+        std::optional<uint32_t> num_worker_threads, const bool o_direct,
+        uint32_t cow_op_merge_size) {
     // We will need multiple worker threads only during
     // device boot after OTA. For all other purposes,
     // one thread is sufficient. We don't want to consume
@@ -355,7 +355,9 @@ std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(const std::string&
     //
     // During boot up, we need multiple threads primarily for
     // update-verification.
-    int num_worker_threads = kNumWorkerThreads;
+    if (!num_worker_threads.has_value()) {
+        num_worker_threads = kNumWorkerThreads;
+    }
     if (is_socket_present_) {
         num_worker_threads = 1;
     }
@@ -368,7 +370,7 @@ std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(const std::string&
     auto opener = block_server_factory_->CreateOpener(misc_name);
 
     return handlers_->AddHandler(misc_name, cow_device_path, backing_device, base_path_merge,
-                                 opener, num_worker_threads, io_uring_enabled_, o_direct,
+                                 opener, num_worker_threads.value(), io_uring_enabled_, o_direct,
                                  cow_op_merge_size);
 }
 
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.h
index ceea36ae4..f002e8d9a 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_server.h
@@ -87,6 +87,7 @@ class UserSnapshotServer {
                                               const std::string& cow_device_path,
                                               const std::string& backing_device,
                                               const std::string& base_path_merge,
+                                              std::optional<uint32_t> num_worker_threads,
                                               bool o_direct = false,
                                               uint32_t cow_op_merge_size = 0);
     bool StartHandler(const std::string& misc_name);
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
index 4dfb9bf4e..469fd091a 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_test.cpp
@@ -82,6 +82,8 @@ class SnapuserdTestBase : public ::testing::TestWithParam<TestParam> {
 
     unique_fd GetCowFd() { return unique_fd{dup(cow_system_->fd)}; }
 
+    bool ShouldSkipSetUp();
+
     std::unique_ptr<ITestHarness> harness_;
     size_t size_ = 10_MiB;
     int total_base_size_ = 0;
@@ -97,6 +99,10 @@ class SnapuserdTestBase : public ::testing::TestWithParam<TestParam> {
 };
 
 void SnapuserdTestBase::SetUp() {
+    if (ShouldSkipSetUp()) {
+        GTEST_SKIP() << "snapuserd not supported on this device";
+    }
+
 #if __ANDROID__
     harness_ = std::make_unique<DmUserTestHarness>();
 #else
@@ -104,6 +110,16 @@ void SnapuserdTestBase::SetUp() {
 #endif
 }
 
+bool SnapuserdTestBase::ShouldSkipSetUp() {
+#ifdef __ANDROID__
+    if (!android::snapshot::CanUseUserspaceSnapshots() ||
+        android::snapshot::IsVendorFromAndroid12()) {
+        return true;
+    }
+#endif
+    return false;
+}
+
 void SnapuserdTestBase::TearDown() {
     cow_system_ = nullptr;
 }
@@ -302,6 +318,9 @@ class SnapuserdTest : public SnapuserdTestBase {
 };
 
 void SnapuserdTest::SetUp() {
+    if (ShouldSkipSetUp()) {
+        GTEST_SKIP() << "snapuserd not supported on this device";
+    }
     ASSERT_NO_FATAL_FAILURE(SnapuserdTestBase::SetUp());
     handlers_ = std::make_unique<SnapshotHandlerManager>();
 }
@@ -312,6 +331,9 @@ void SnapuserdTest::TearDown() {
 }
 
 void SnapuserdTest::Shutdown() {
+    if (!handlers_) {
+        return;
+    }
     if (dmuser_dev_) {
         ASSERT_TRUE(dmuser_dev_->Destroy());
     }
@@ -1181,6 +1203,9 @@ void SnapuserdVariableBlockSizeTest::ReadSnapshotWithVariableBlockSize() {
 }
 
 void SnapuserdVariableBlockSizeTest::SetUp() {
+    if (ShouldSkipSetUp()) {
+        GTEST_SKIP() << "snapuserd not supported on this device";
+    }
     ASSERT_NO_FATAL_FAILURE(SnapuserdTest::SetUp());
 }
 
@@ -1244,6 +1269,9 @@ void HandlerTest::InitializeDevice() {
 }
 
 void HandlerTest::SetUp() {
+    if (ShouldSkipSetUp()) {
+        GTEST_SKIP() << "snapuserd not supported on this device";
+    }
     ASSERT_NO_FATAL_FAILURE(SnapuserdTestBase::SetUp());
     ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
     ASSERT_NO_FATAL_FAILURE(SetUpV2Cow());
@@ -1251,6 +1279,9 @@ void HandlerTest::SetUp() {
 }
 
 void HandlerTest::TearDown() {
+    if (ShouldSkipSetUp()) {
+        return;
+    }
     ASSERT_TRUE(factory_.DeleteQueue(system_device_ctrl_name_));
     ASSERT_TRUE(handler_thread_.get());
     SnapuserdTestBase::TearDown();
@@ -1326,6 +1357,9 @@ class HandlerTestV3 : public HandlerTest {
 };
 
 void HandlerTestV3::SetUp() {
+    if (ShouldSkipSetUp()) {
+        GTEST_SKIP() << "snapuserd not supported on this device";
+    }
     ASSERT_NO_FATAL_FAILURE(SnapuserdTestBase::SetUp());
     ASSERT_NO_FATAL_FAILURE(CreateBaseDevice());
     ASSERT_NO_FATAL_FAILURE(SetUpV3Cow());
@@ -1530,14 +1564,6 @@ INSTANTIATE_TEST_SUITE_P(Io, HandlerTest, ::testing::ValuesIn(GetTestConfigs()))
 int main(int argc, char** argv) {
     ::testing::InitGoogleTest(&argc, argv);
 
-#ifdef __ANDROID__
-    if (!android::snapshot::CanUseUserspaceSnapshots() ||
-        android::snapshot::IsVendorFromAndroid12()) {
-        std::cerr << "snapuserd_test not supported on this device\n";
-        return 0;
-    }
-#endif
-
     gflags::ParseCommandLineFlags(&argc, &argv, false);
 
     return RUN_ALL_TESTS();
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_transitions.cpp b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_transitions.cpp
index 2ad4ea1c2..714c64124 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_transitions.cpp
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_transitions.cpp
@@ -202,7 +202,7 @@ bool SnapshotHandler::WaitForMergeBegin() {
     cv.wait(lock, [this]() -> bool { return MergeInitiated() || IsMergeBeginError(io_state_); });
 
     if (IsMergeBeginError(io_state_)) {
-        SNAP_LOG(ERROR) << "WaitForMergeBegin failed with state: " << io_state_;
+        SNAP_LOG(VERBOSE) << "WaitForMergeBegin failed with state: " << io_state_;
         return false;
     }
 
@@ -276,7 +276,9 @@ bool SnapshotHandler::WaitForMergeReady() {
         if (io_state_ == MERGE_IO_TRANSITION::MERGE_FAILED ||
             io_state_ == MERGE_IO_TRANSITION::MERGE_COMPLETE ||
             io_state_ == MERGE_IO_TRANSITION::IO_TERMINATED) {
-            SNAP_LOG(ERROR) << "Wait for merge ready failed: " << io_state_;
+            if (io_state_ == MERGE_IO_TRANSITION::MERGE_FAILED) {
+                SNAP_LOG(ERROR) << "Wait for merge ready failed: " << io_state_;
+            }
             return false;
         }
         return true;
diff --git a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.h b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.h
index 7c9908515..b300a7000 100644
--- a/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.h
+++ b/fs_mgr/libsnapshot/snapuserd/user-space-merge/snapuserd_verify.h
@@ -62,8 +62,8 @@ class UpdateVerify {
      * (/proc/pressure/{cpu,memory}; and monitoring the Inactive(file) and
      * Active(file) pages from /proc/meminfo.
      *
-     * Additionally, for low memory devices, it is advisible to use O_DIRECT
-     * fucntionality for source block device.
+     * Additionally, for low memory devices, it is advisable to use O_DIRECT
+     * functionality for source block device.
      */
     int kMinThreadsToVerify = 1;
     int kMaxThreadsToVerify = 3;
diff --git a/fs_mgr/tests/fs_mgr_test.cpp b/fs_mgr/tests/fs_mgr_test.cpp
index 6522c02e8..fc3d5dc0e 100644
--- a/fs_mgr/tests/fs_mgr_test.cpp
+++ b/fs_mgr/tests/fs_mgr_test.cpp
@@ -37,10 +37,6 @@
 using namespace android::fs_mgr;
 using namespace testing;
 
-#if !defined(MS_LAZYTIME)
-#define MS_LAZYTIME (1 << 25)
-#endif
-
 namespace {
 
 const std::string cmdline =
@@ -334,6 +330,7 @@ TEST(fs_mgr, fs_mgr_read_fstab_file_proc_mounts) {
                 {"slave", MS_SLAVE},
                 {"shared", MS_SHARED},
                 {"lazytime", MS_LAZYTIME},
+                {"nosymfollow", MS_NOSYMFOLLOW},
                 {"defaults", 0},
                 {0, 0},
         };
@@ -710,6 +707,7 @@ source none2       swap   defaults      zramsize=blah%
 source none3       swap   defaults      zramsize=5%
 source none4       swap   defaults      zramsize=105%
 source none5       swap   defaults      zramsize=%
+source none6       swap   defaults      zramsize=210%
 )fs";
     ASSERT_TRUE(android::base::WriteStringToFile(fstab_contents, tf.path));
 
@@ -742,12 +740,17 @@ source none5       swap   defaults      zramsize=%
 
     EXPECT_EQ("none4", entry->mount_point);
     EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
-    EXPECT_EQ(0, entry->zram_size);
+    EXPECT_NE(0, entry->zram_size);
     entry++;
 
     EXPECT_EQ("none5", entry->mount_point);
     EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
     EXPECT_EQ(0, entry->zram_size);
+    entry++;
+
+    EXPECT_EQ("none6", entry->mount_point);
+    EXPECT_TRUE(CompareFlags(flags, entry->fs_mgr_flags));
+    EXPECT_EQ(0, entry->zram_size);
 }
 
 TEST(fs_mgr, ReadFstabFromFile_FsMgrOptions_FileEncryption) {
diff --git a/gatekeeperd/fuzzer/GateKeeperServiceFuzzer.cpp b/gatekeeperd/fuzzer/GateKeeperServiceFuzzer.cpp
index bc0d5fe05..a3cc3f32c 100644
--- a/gatekeeperd/fuzzer/GateKeeperServiceFuzzer.cpp
+++ b/gatekeeperd/fuzzer/GateKeeperServiceFuzzer.cpp
@@ -22,6 +22,8 @@ using android::fuzzService;
 using android::GateKeeperProxy;
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+    // TODO(b/183141167): need to rewrite 'dump' to avoid SIGPIPE.
+    signal(SIGPIPE, SIG_IGN);
     auto gatekeeperService = new GateKeeperProxy();
     fuzzService(gatekeeperService, FuzzedDataProvider(data, size));
     return 0;
diff --git a/healthd/Android.bp b/healthd/Android.bp
index e158e07e4..7eb6edde1 100644
--- a/healthd/Android.bp
+++ b/healthd/Android.bp
@@ -4,7 +4,10 @@ package {
 
 cc_defaults {
     name: "libbatterymonitor_defaults",
-    cflags: ["-Wall", "-Werror"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
     vendor_available: true,
     recovery_available: true,
     export_include_dirs: ["include"],
@@ -76,7 +79,7 @@ cc_library_static {
     defaults: ["libbatterymonitor_defaults"],
     srcs: ["BatteryMonitor.cpp"],
     static_libs: [
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
     ],
     whole_static_libs: [
         // Need to translate HIDL to AIDL to support legacy APIs in
@@ -165,12 +168,12 @@ cc_library_static {
     defaults: ["libhealthd_charger_ui_defaults"],
 
     static_libs: [
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "android.hardware.health-translate-ndk",
     ],
 
     export_static_lib_headers: [
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
     ],
 }
 
@@ -242,7 +245,7 @@ cc_defaults {
     static_libs: [
         // common
         "android.hardware.health@1.0-convert",
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "libbatterymonitor",
         "libcharger_sysprop",
         "libhealthd_charger_nops",
@@ -287,8 +290,8 @@ cc_binary {
                 "libminui",
                 "libsuspend",
             ],
-        }
-    }
+        },
+    },
 }
 
 cc_test {
@@ -307,7 +310,7 @@ cc_test {
     defaults: ["charger_defaults"],
     srcs: [
         "AnimationParser_test.cpp",
-        "healthd_mode_charger_test.cpp"
+        "healthd_mode_charger_test.cpp",
     ],
     static_libs: [
         "android.hardware.health@1.0",
diff --git a/init/Android.bp b/init/Android.bp
index 18a79d6c4..ed19b4b86 100644
--- a/init/Android.bp
+++ b/init/Android.bp
@@ -163,7 +163,6 @@ libinit_cc_defaults {
         "libavb",
         "libavf_cc_flags",
         "libbootloader_message",
-        "libcgrouprc_format",
         "liblmkd_utils",
         "liblz4",
         "libzstd",
@@ -177,6 +176,7 @@ libinit_cc_defaults {
         "libxml2",
         "lib_apex_manifest_proto_lite",
         "update_metadata-protos",
+        "libgenfslabelsversion.ffi",
     ],
     shared_libs: [
         "libbase",
@@ -268,7 +268,6 @@ phony {
 
 cc_defaults {
     name: "init_second_stage_defaults",
-    recovery_available: true,
     stem: "init",
     defaults: ["init_defaults"],
     srcs: ["main.cpp"],
@@ -280,37 +279,38 @@ cc_binary {
     defaults: ["init_second_stage_defaults"],
     static_libs: ["libinit"],
     visibility: ["//visibility:any_system_partition"],
-    target: {
-        platform: {
-            required: [
-                "init.rc",
-                "ueventd.rc",
-                "e2fsdroid",
-                "extra_free_kbytes",
-                "make_f2fs",
-                "mke2fs",
-                "sload_f2fs",
-            ],
-        },
-        recovery: {
-            cflags: ["-DRECOVERY"],
-            exclude_static_libs: [
-                "libxml2",
-            ],
-            exclude_shared_libs: [
-                "libbinder",
-                "libutils",
-            ],
-            required: [
-                "init_recovery.rc",
-                "ueventd.rc.recovery",
-                "e2fsdroid.recovery",
-                "make_f2fs.recovery",
-                "mke2fs.recovery",
-                "sload_f2fs.recovery",
-            ],
-        },
-    },
+    required: [
+        "init.rc",
+        "ueventd.rc",
+        "e2fsdroid",
+        "extra_free_kbytes",
+        "make_f2fs",
+        "mke2fs",
+        "sload_f2fs",
+    ],
+}
+
+cc_binary {
+    name: "init_second_stage.recovery",
+    defaults: ["init_second_stage_defaults"],
+    static_libs: ["libinit"],
+    recovery: true,
+    cflags: ["-DRECOVERY"],
+    exclude_static_libs: [
+        "libxml2",
+    ],
+    exclude_shared_libs: [
+        "libbinder",
+        "libutils",
+    ],
+    required: [
+        "init_recovery.rc",
+        "ueventd.rc.recovery",
+        "e2fsdroid.recovery",
+        "make_f2fs.recovery",
+        "mke2fs.recovery",
+        "sload_f2fs.recovery",
+    ],
 }
 
 cc_binary {
@@ -319,7 +319,6 @@ cc_binary {
         "avf_build_flags_cc",
         "init_second_stage_defaults",
     ],
-    recovery_available: false,
     static_libs: ["libinit.microdroid"],
     cflags: ["-DMICRODROID=1"],
     no_full_install: true,
@@ -390,6 +389,7 @@ init_first_stage_cc_defaults {
         "libsnapshot_init",
         "update_metadata-protos",
         "libprocinfo",
+        "libbootloader_message",
     ],
 
     static_executable: true,
diff --git a/init/README.ueventd.md b/init/README.ueventd.md
index 7d00195eb..0e84c6f5f 100644
--- a/init/README.ueventd.md
+++ b/init/README.ueventd.md
@@ -39,6 +39,33 @@ for the node path:
      `device_id` is `uevent MINOR % 128 + 1`.
   3. All other devices are created as `/dev/<basename uevent DEVPATH>`
 
+Whether a device is considered a "boot device" is a bit complicated.
+
+ - The recommended way to specify the boot device is to provide the "partition UUID" containing the
+   kernel (or, really, any parition on the boot device) and then boot device is the block device
+   containing that partition. This is passed via `androidboot.boot_part_uuid` which can be provided
+   either via the kernel bootconfig or via the kernel commandline. As an example, you could set
+   `androidboot.boot_part_uuid=12345678-abcd-ef01-0234-6789abcdef01`.
+ - Though using `boot_part_uuid` is preferred, you can also specify the boot device via
+   `androidboot.boot_device` or `androidboot.boot_devices`. These can be passed via the kernel
+   bootconfig or the kernel command line. It is also possible to pass this via device tree by
+   creating a `boot_devices` property in the Android firmware node. In most cases the `boot_device`
+   is the sysfs path (without the `/sys/devices` or `/sys/devices/platform` prefix) to the closest
+   parent of the block device that's on the "platform" bus. As an example, if the block device is
+   `/sys/devices/platform/soc@0/7c4000.mmc/mmc_host/mmc1/mmc1:0001/block/mmcblk1` then the
+   `boot_device` is `soc@0/7c4000.mmc` since we strip off the `/sys/devices/platform` and nothing
+   past the `7c4000.mmc` directory represents a device on the "platform" bus. In the case that none
+   of the parents are on the "platform" bus there are special rules for block devices under PCI
+   and VBD (Virtual Block Device). NOTE: sysfs paths for block devices are not guaranteed to be
+   stable between kernel versions, which is one of the reasons why it is suggested to use
+   `boot_part_uuid` instead of `boot_devices`. ALSO NOTE: If more than one device matches (either
+   because multiple `boot_devices` were listed or because there was more than one block device
+   under the found sysfs directory) and these multiple matching devices provide some of the same
+   named partitions then the behavior is unspecified.
+ - There is a further fallback to determine "boot devices" via the vstab, but providing at least
+   `boot_devices` has been required since Android 12 so this further fallback will not be described
+   here.
+
 The permissions can be modified using a ueventd.rc script and a line that beings with `/dev`. These
 lines take the format of
 
@@ -49,17 +76,17 @@ For example
 When `/dev/null` is created, its mode will be set to `0666`, its user to `root` and its group to
 `root`.
 
-The path can be modified using a ueventd.rc script and a `subsystem` section. There are three to set
-for a subsystem: the subsystem name, which device name to use, and which directory to place the
-device in. The section takes the below format of
+The path can be modified using a ueventd.rc script and a `subsystem` and/or `driver` section.
+There are three options to set for a subsystem or driver: the name, which device name to use,
+and which directory to place the device in. The section takes the below format of
 
     subsystem <subsystem_name>
       devname uevent_devname|uevent_devpath
       [dirname <directory>]
 
-`subsystem_name` is used to match uevent `SUBSYSTEM` value
+`subsystem_name` is used to match the uevent `SUBSYSTEM` value.
 
-`devname` takes one of three options
+`devname` takes one of three options:
   1. `uevent_devname` specifies that the name of the node will be the uevent `DEVNAME`
   2. `uevent_devpath` specifies that the name of the node will be basename uevent `DEVPATH`
   3. `sys_name` specifies that the name of the node will be the contents of `/sys/DEVPATH/name`
@@ -72,9 +99,13 @@ For example
     subsystem sound
       devname uevent_devpath
       dirname /dev/snd
-Indicates that all uevents with `SUBSYSTEM=sound` will create nodes as `/dev/snd/<basename uevent
+indicates that all uevents with `SUBSYSTEM=sound` will create nodes as `/dev/snd/<basename uevent
 DEVPATH>`.
 
+The `driver` section has the exact same structure as a `subsystem` section, but
+will instead match the `DRIVER` value in a `bind`/`unbind` uevent. However, the
+`driver` section will be ignored for block devices.
+
 ## /sys
 ----
 Ueventd by default takes no action for `/sys`, however it can be instructed to set permissions for
diff --git a/init/apex_init_util.cpp b/init/apex_init_util.cpp
index e5a7fbcc0..809c805c4 100644
--- a/init/apex_init_util.cpp
+++ b/init/apex_init_util.cpp
@@ -101,14 +101,21 @@ std::set<std::string> GetApexListFrom(const std::string& apex_dir) {
     return apex_list;
 }
 
+static int GetCurrentSdk() {
+    bool is_preview = base::GetProperty("ro.build.version.codename", "") != "REL";
+    if (is_preview) {
+        return __ANDROID_API_FUTURE__;
+    }
+    return android::base::GetIntProperty("ro.build.version.sdk", __ANDROID_API_FUTURE__);
+}
+
 static Result<void> ParseRcScripts(const std::vector<std::string>& files) {
     if (files.empty()) {
         return {};
     }
     // APEXes can have versioned RC files. These should be filtered based on
     // SDK version.
-    int sdk = android::base::GetIntProperty("ro.build.version.sdk", INT_MAX);
-    if (sdk < 35) sdk = 35;  // aosp/main merges only into sdk=35+ (ie. __ANDROID_API_V__+)
+    static int sdk = GetCurrentSdk();
     auto filtered = FilterVersionedConfigs(files, sdk);
     if (filtered.empty()) {
         return {};
diff --git a/init/block_dev_initializer.cpp b/init/block_dev_initializer.cpp
index 8f5215856..deb68e9ac 100644
--- a/init/block_dev_initializer.cpp
+++ b/init/block_dev_initializer.cpp
@@ -33,7 +33,50 @@ BlockDevInitializer::BlockDevInitializer() : uevent_listener_(16 * 1024 * 1024)
     auto boot_devices = android::fs_mgr::GetBootDevices();
     device_handler_ = std::make_unique<DeviceHandler>(
             std::vector<Permissions>{}, std::vector<SysfsPermissions>{}, std::vector<Subsystem>{},
-            std::move(boot_devices), false);
+            std::vector<Subsystem>{}, std::move(boot_devices), android::fs_mgr::GetBootPartUuid(),
+            false);
+}
+
+// If boot_part_uuid is specified, use it to set boot_devices
+//
+// When `androidboot.boot_part_uuid` is specified then that's the partition UUID
+// of the kernel. Look for that partition and then set `boot_devices` to be
+// exactly one item: the block device containing that partition.
+//
+// NOTE that `boot_part_uuid` is only specified on newer devices. Older devices
+// specified `boot_devices` directly.
+bool BlockDevInitializer::InitBootDevicesFromPartUuid() {
+    bool uuid_check_done = false;
+
+    auto boot_part_callback = [&, this](const Uevent& uevent) -> ListenerAction {
+        uuid_check_done = device_handler_->CheckUeventForBootPartUuid(uevent);
+        return uuid_check_done ? ListenerAction::kStop : ListenerAction::kContinue;
+    };
+
+    // Re-run already arrived uevents looking for the boot partition UUID.
+    //
+    // NOTE: If we're not using the boot partition UUID to find the boot
+    // device then the first uevent we analyze will cause us to stop looking
+    // and set `uuid_check_done`. This will shortcut all of the UUID logic.
+    // Replaying one uevent is not expected to be slow.
+    uevent_listener_.RegenerateUevents(boot_part_callback);
+
+    // If we're not done looking, poll for uevents for longer
+    if (!uuid_check_done) {
+        Timer t;
+        uevent_listener_.Poll(boot_part_callback, 10s);
+        LOG(INFO) << "Wait for boot partition returned after " << t;
+    }
+
+    // Give a nicer error message if we were expecting to find the kernel boot
+    // partition but didn't. Later code would fail too but the message there
+    // is a bit further from the root cause of the problem.
+    if (!uuid_check_done) {
+        LOG(ERROR) << __PRETTY_FUNCTION__ << ": boot partition not found after polling timeout.";
+        return false;
+    }
+
+    return true;
 }
 
 bool BlockDevInitializer::InitDeviceMapper() {
@@ -98,11 +141,43 @@ ListenerAction BlockDevInitializer::HandleUevent(const Uevent& uevent,
 
     LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": found partition: " << name;
 
-    devices->erase(iter);
+    // Remove the partition from the list of partitions we're waiting for.
+    //
+    // Partitions that we're waiting for here are expected to be on the boot
+    // device, so only remove from the list if they're on the boot device.
+    // This prevents us from being confused if there are multiple disks (some
+    // perhaps connected via USB) that have matching partition names.
+    //
+    // ...but...
+    //
+    // Some products (especialy emulators) don't seem to set up boot_devices
+    // or possibly not all the partitions that we need to wait for are on the
+    // specified boot device. Thus, only require partitions to be on the boot
+    // device in "strict" mode, which should be used on newer systems.
+    if (device_handler_->IsBootDevice(uevent) || !device_handler_->IsBootDeviceStrict()) {
+        devices->erase(iter);
+    }
+
     device_handler_->HandleUevent(uevent);
     return devices->empty() ? ListenerAction::kStop : ListenerAction::kContinue;
 }
 
+// Wait for partitions that are expected to be on the "boot device" to initialize.
+//
+// Wait (for up to 10 seconds) for partitions passed in `devices` to show up.
+// All block devices found while waiting will be initialized, which includes
+// creating symlinks for them in /dev/block. Once all `devices` are found we'll
+// return success (true). If any devices aren't found we'll return failure
+// (false). As devices are found they will be removed from `devices`.
+//
+// The contents of `devices` is the names of the partitions. This can be:
+// - The `partition_name` reported by a uevent, or the final component in the
+//   `path` reported by a uevent if the `partition_name` is blank.
+// - The result of DeviceHandler::GetPartitionNameForDevice() on the
+//   `device_name` reported by a uevent.
+//
+// NOTE: on newer systems partitions _must_ be on the "boot device". See
+// comments inside HandleUevent().
 bool BlockDevInitializer::InitDevices(std::set<std::string> devices) {
     auto uevent_callback = [&, this](const Uevent& uevent) -> ListenerAction {
         return HandleUevent(uevent, &devices);
diff --git a/init/block_dev_initializer.h b/init/block_dev_initializer.h
index cb1d36555..25107c97f 100644
--- a/init/block_dev_initializer.h
+++ b/init/block_dev_initializer.h
@@ -29,6 +29,7 @@ class BlockDevInitializer final {
   public:
     BlockDevInitializer();
 
+    bool InitBootDevicesFromPartUuid();
     bool InitDeviceMapper();
     bool InitDmUser(const std::string& name);
     bool InitDevices(std::set<std::string> devices);
diff --git a/init/builtins.cpp b/init/builtins.cpp
index c4af5b503..38aed9c64 100644
--- a/init/builtins.cpp
+++ b/init/builtins.cpp
@@ -471,6 +471,7 @@ static struct {
     { "private",    MS_PRIVATE },
     { "slave",      MS_SLAVE },
     { "shared",     MS_SHARED },
+    { "nosymfollow", MS_NOSYMFOLLOW },
     { "defaults",   0 },
     { 0,            0 },
 };
diff --git a/init/devices.cpp b/init/devices.cpp
index f2bb9d276..aeaa43133 100644
--- a/init/devices.cpp
+++ b/init/devices.cpp
@@ -45,6 +45,7 @@
 using namespace std::chrono_literals;
 
 using android::base::Basename;
+using android::base::ConsumePrefix;
 using android::base::Dirname;
 using android::base::ReadFileToString;
 using android::base::Readlink;
@@ -188,6 +189,56 @@ void SysfsPermissions::SetPermissions(const std::string& path) const {
     }
 }
 
+BlockDeviceInfo DeviceHandler::GetBlockDeviceInfo(const std::string& uevent_path) const {
+    BlockDeviceInfo info;
+
+    if (!boot_part_uuid_.empty()) {
+        // Only use the more specific "MMC" / "NVME" / "SCSI" match if a
+        // partition UUID was passed.
+        //
+        // Old bootloaders that aren't passing the partition UUID instead
+        // pass the path to the closest "platform" device. It would
+        // break them if we chose this deeper (more specific) path.
+        //
+        // When we have a UUID we _want_ the more specific path since it can
+        // handle, for instance, differentiating two USB disks that are on
+        // the same USB controller. Using the closest platform device would
+        // classify them both the same by using the path to the USB controller.
+        if (FindMmcDevice(uevent_path, &info.str)) {
+            info.type = "mmc";
+        } else if (FindNvmeDevice(uevent_path, &info.str)) {
+            info.type = "nvme";
+        } else if (FindScsiDevice(uevent_path, &info.str)) {
+            info.type = "scsi";
+        }
+    } else if (FindPlatformDevice(uevent_path, &info.str)) {
+        info.type = "platform";
+    } else if (FindPciDevicePrefix(uevent_path, &info.str)) {
+        info.type = "pci";
+    } else if (FindVbdDevicePrefix(uevent_path, &info.str)) {
+        info.type = "vbd";
+    } else {
+        // Re-clear device to be extra certain in case one of the FindXXX()
+        // functions returned false but still modified it.
+        info.str = "";
+    }
+
+    info.is_boot_device = boot_devices_.find(info.str) != boot_devices_.end();
+
+    return info;
+}
+
+bool DeviceHandler::IsBootDeviceStrict() const {
+    // When using the newer "boot_part_uuid" to specify the boot device then
+    // we require all core system partitions to be on the boot device.
+    return !boot_part_uuid_.empty();
+}
+
+bool DeviceHandler::IsBootDevice(const Uevent& uevent) const {
+    auto device = GetBlockDeviceInfo(uevent.path);
+    return device.is_boot_device;
+}
+
 std::string DeviceHandler::GetPartitionNameForDevice(const std::string& query_device) {
     static const auto partition_map = [] {
         std::vector<std::pair<std::string, std::string>> partition_map;
@@ -218,11 +269,12 @@ std::string DeviceHandler::GetPartitionNameForDevice(const std::string& query_de
     return {};
 }
 
-// Given a path that may start with a platform device, find the parent platform device by finding a
-// parent directory with a 'subsystem' symlink that points to the platform bus.
-// If it doesn't start with a platform device, return false
-bool DeviceHandler::FindPlatformDevice(std::string path, std::string* platform_device_path) const {
-    platform_device_path->clear();
+// Given a path to a device that may have a parent in the passed set of
+// subsystems, find the parent device that's in the passed set of subsystems.
+// If we don't find a parent in the passed set of subsystems, return false.
+bool DeviceHandler::FindSubsystemDevice(std::string path, std::string* device_path,
+                                        const std::set<std::string>& subsystem_paths) const {
+    device_path->clear();
 
     // Uevents don't contain the mount point, so we need to add it here.
     path.insert(0, sysfs_mount_point_);
@@ -232,11 +284,20 @@ bool DeviceHandler::FindPlatformDevice(std::string path, std::string* platform_d
     while (directory != "/" && directory != ".") {
         std::string subsystem_link_path;
         if (Realpath(directory + "/subsystem", &subsystem_link_path) &&
-            (subsystem_link_path == sysfs_mount_point_ + "/bus/platform" ||
-             subsystem_link_path == sysfs_mount_point_ + "/bus/amba")) {
+            subsystem_paths.find(subsystem_link_path) != subsystem_paths.end()) {
             // We need to remove the mount point that we added above before returning.
             directory.erase(0, sysfs_mount_point_.size());
-            *platform_device_path = directory;
+
+            // Skip /devices/platform or /devices/ if present
+            static constexpr std::string_view devices_platform_prefix = "/devices/platform/";
+            static constexpr std::string_view devices_prefix = "/devices/";
+            std::string_view sv = directory;
+
+            if (!ConsumePrefix(&sv, devices_platform_prefix)) {
+                ConsumePrefix(&sv, devices_prefix);
+            }
+            *device_path = sv;
+
             return true;
         }
 
@@ -250,6 +311,60 @@ bool DeviceHandler::FindPlatformDevice(std::string path, std::string* platform_d
     return false;
 }
 
+bool DeviceHandler::FindPlatformDevice(const std::string& path,
+                                       std::string* platform_device_path) const {
+    const std::set<std::string> subsystem_paths = {
+            sysfs_mount_point_ + "/bus/platform",
+            sysfs_mount_point_ + "/bus/amba",
+    };
+
+    return FindSubsystemDevice(path, platform_device_path, subsystem_paths);
+}
+
+bool DeviceHandler::FindMmcDevice(const std::string& path, std::string* mmc_device_path) const {
+    const std::set<std::string> subsystem_paths = {
+            sysfs_mount_point_ + "/bus/mmc",
+    };
+
+    return FindSubsystemDevice(path, mmc_device_path, subsystem_paths);
+}
+
+bool DeviceHandler::FindNvmeDevice(const std::string& path, std::string* nvme_device_path) const {
+    const std::set<std::string> subsystem_paths = {
+            sysfs_mount_point_ + "/class/nvme",
+    };
+
+    return FindSubsystemDevice(path, nvme_device_path, subsystem_paths);
+}
+
+bool DeviceHandler::FindScsiDevice(const std::string& path, std::string* scsi_device_path) const {
+    const std::set<std::string> subsystem_paths = {
+            sysfs_mount_point_ + "/bus/scsi",
+    };
+
+    return FindSubsystemDevice(path, scsi_device_path, subsystem_paths);
+}
+
+void DeviceHandler::TrackDeviceUevent(const Uevent& uevent) {
+    // No need to track any events if we won't bother handling any bind events
+    // later.
+    if (drivers_.size() == 0) return;
+
+    // Only track add, and not for block devices. We don't track remove because
+    // unbind events may arrive after remove events, so unbind will be the
+    // trigger to untrack those events.
+    if ((uevent.action != "add") || uevent.subsystem == "block" ||
+        (uevent.major < 0 || uevent.minor < 0)) {
+        return;
+    }
+
+    std::string path = sysfs_mount_point_ + uevent.path + "/device";
+    std::string device;
+    if (!Realpath(path, &device)) return;
+
+    tracked_uevents_.emplace_back(uevent, device);
+}
+
 void DeviceHandler::FixupSysPermissions(const std::string& upath,
                                         const std::string& subsystem) const {
     // upaths omit the "/sys" that paths in this list
@@ -371,44 +486,30 @@ void SanitizePartitionName(std::string* string) {
 }
 
 std::vector<std::string> DeviceHandler::GetBlockDeviceSymlinks(const Uevent& uevent) const {
-    std::string device;
-    std::string type;
+    BlockDeviceInfo info;
     std::string partition;
     std::string uuid;
 
-    if (FindPlatformDevice(uevent.path, &device)) {
-        // Skip /devices/platform or /devices/ if present
-        static constexpr std::string_view devices_platform_prefix = "/devices/platform/";
-        static constexpr std::string_view devices_prefix = "/devices/";
-
-        if (StartsWith(device, devices_platform_prefix)) {
-            device = device.substr(devices_platform_prefix.length());
-        } else if (StartsWith(device, devices_prefix)) {
-            device = device.substr(devices_prefix.length());
-        }
-
-        type = "platform";
-    } else if (FindPciDevicePrefix(uevent.path, &device)) {
-        type = "pci";
-    } else if (FindVbdDevicePrefix(uevent.path, &device)) {
-        type = "vbd";
-    } else if (FindDmDevice(uevent, &partition, &uuid)) {
+    if (FindDmDevice(uevent, &partition, &uuid)) {
         std::vector<std::string> symlinks = {"/dev/block/mapper/" + partition};
         if (!uuid.empty()) {
             symlinks.emplace_back("/dev/block/mapper/by-uuid/" + uuid);
         }
         return symlinks;
-    } else {
+    }
+
+    info = GetBlockDeviceInfo(uevent.path);
+
+    if (info.type.empty()) {
         return {};
     }
 
     std::vector<std::string> links;
 
-    LOG(VERBOSE) << "found " << type << " device " << device;
+    LOG(VERBOSE) << "found " << info.type << " device " << info.str;
 
-    auto link_path = "/dev/block/" + type + "/" + device;
+    auto link_path = "/dev/block/" + info.type + "/" + info.str;
 
-    bool is_boot_device = boot_devices_.find(device) != boot_devices_.end();
     if (!uevent.partition_name.empty()) {
         std::string partition_name_sanitized(uevent.partition_name);
         SanitizePartitionName(&partition_name_sanitized);
@@ -418,10 +519,10 @@ std::vector<std::string> DeviceHandler::GetBlockDeviceSymlinks(const Uevent& uev
         }
         links.emplace_back(link_path + "/by-name/" + partition_name_sanitized);
         // Adds symlink: /dev/block/by-name/<partition_name>.
-        if (is_boot_device) {
+        if (info.is_boot_device) {
             links.emplace_back("/dev/block/by-name/" + partition_name_sanitized);
         }
-    } else if (is_boot_device) {
+    } else if (info.is_boot_device) {
         // If we don't have a partition name but we are a partition on a boot device, create a
         // symlink of /dev/block/by-name/<device_name> for symmetry.
         links.emplace_back("/dev/block/by-name/" + uevent.device_name);
@@ -541,12 +642,95 @@ void DeviceHandler::HandleAshmemUevent(const Uevent& uevent) {
     }
 }
 
+// Check Uevents looking for the kernel's boot partition UUID
+//
+// When we can stop checking uevents (either because we're done or because
+// we weren't looking for the kernel's boot partition UUID) then return
+// true. Return false if we're not done yet.
+bool DeviceHandler::CheckUeventForBootPartUuid(const Uevent& uevent) {
+    // If we aren't using boot_part_uuid then we're done.
+    if (boot_part_uuid_.empty()) {
+        return true;
+    }
+
+    // Finding the boot partition is a one-time thing that we do at init
+    // time, not steady state. This is because the boot partition isn't
+    // allowed to go away or change. Once we found the boot partition we don't
+    // expect to run again.
+    if (found_boot_part_uuid_) {
+        LOG(WARNING) << __PRETTY_FUNCTION__
+                     << " shouldn't run after kernel boot partition is found";
+        return true;
+    }
+
+    // We only need to look at newly-added block devices. Note that if someone
+    // is replaying events all existing devices will get "add"ed.
+    if (uevent.subsystem != "block" || uevent.action != "add") {
+        return false;
+    }
+
+    // If it's not the partition we care about then move on.
+    if (uevent.partition_uuid != boot_part_uuid_) {
+        return false;
+    }
+
+    auto device = GetBlockDeviceInfo(uevent.path);
+
+    LOG(INFO) << "Boot device " << device.str << " found via partition UUID";
+    found_boot_part_uuid_ = true;
+    boot_devices_.clear();
+    boot_devices_.insert(device.str);
+
+    return true;
+}
+
+void DeviceHandler::HandleBindInternal(std::string driver_name, std::string action,
+                                       const Uevent& uevent) {
+    if (uevent.subsystem == "block") {
+        LOG(FATAL) << "Tried to handle bind event for block device";
+    }
+
+    // Get tracked uevents for all devices that have this uevent's path as
+    // their canonical device path. Then handle those again if their driver
+    // is one of the ones we're interested in.
+    const auto driver = std::find(drivers_.cbegin(), drivers_.cend(), driver_name);
+    if (driver == drivers_.cend()) return;
+
+    std::string bind_path = sysfs_mount_point_ + uevent.path;
+    for (const TrackedUevent& tracked : tracked_uevents_) {
+        if (tracked.canonical_device_path != bind_path) continue;
+
+        LOG(VERBOSE) << "Propagating " << uevent.action << " as " << action << " for "
+                     << uevent.path;
+
+        std::string devpath = driver->ParseDevPath(tracked.uevent);
+        mkdir_recursive(Dirname(devpath), 0755);
+        HandleDevice(action, devpath, false, tracked.uevent.major, tracked.uevent.minor,
+                     std::vector<std::string>{});
+    }
+}
+
 void DeviceHandler::HandleUevent(const Uevent& uevent) {
     if (uevent.action == "add" || uevent.action == "change" || uevent.action == "bind" ||
         uevent.action == "online") {
         FixupSysPermissions(uevent.path, uevent.subsystem);
     }
 
+    if (uevent.action == "bind") {
+        bound_drivers_[uevent.path] = uevent.driver;
+        HandleBindInternal(uevent.driver, "add", uevent);
+        return;
+    } else if (uevent.action == "unbind") {
+        if (bound_drivers_.count(uevent.path) == 0) return;
+        HandleBindInternal(bound_drivers_[uevent.path], "remove", uevent);
+
+        std::string sys_path = sysfs_mount_point_ + uevent.path;
+        std::erase_if(tracked_uevents_, [&sys_path](const TrackedUevent& tracked) {
+            return sys_path == tracked.canonical_device_path;
+        });
+        return;
+    }
+
     // if it's not a /dev device, nothing to do
     if (uevent.major < 0 || uevent.minor < 0) return;
 
@@ -554,6 +738,8 @@ void DeviceHandler::HandleUevent(const Uevent& uevent) {
     std::vector<std::string> links;
     bool block = false;
 
+    TrackDeviceUevent(uevent);
+
     if (uevent.subsystem == "block") {
         block = true;
         devpath = "/dev/block/" + Basename(uevent.path);
@@ -602,18 +788,29 @@ void DeviceHandler::ColdbootDone() {
 
 DeviceHandler::DeviceHandler(std::vector<Permissions> dev_permissions,
                              std::vector<SysfsPermissions> sysfs_permissions,
-                             std::vector<Subsystem> subsystems, std::set<std::string> boot_devices,
+                             std::vector<Subsystem> drivers, std::vector<Subsystem> subsystems,
+                             std::set<std::string> boot_devices, std::string boot_part_uuid,
                              bool skip_restorecon)
     : dev_permissions_(std::move(dev_permissions)),
       sysfs_permissions_(std::move(sysfs_permissions)),
+      drivers_(std::move(drivers)),
       subsystems_(std::move(subsystems)),
       boot_devices_(std::move(boot_devices)),
+      boot_part_uuid_(boot_part_uuid),
       skip_restorecon_(skip_restorecon),
-      sysfs_mount_point_("/sys") {}
+      sysfs_mount_point_("/sys") {
+    // If both a boot partition UUID and a list of boot devices are
+    // specified then we ignore the boot_devices in favor of boot_part_uuid.
+    if (boot_devices_.size() && !boot_part_uuid.empty()) {
+        LOG(WARNING) << "Both boot_devices and boot_part_uuid provided; ignoring bootdevices";
+        boot_devices_.clear();
+    }
+}
 
 DeviceHandler::DeviceHandler()
     : DeviceHandler(std::vector<Permissions>{}, std::vector<SysfsPermissions>{},
-                    std::vector<Subsystem>{}, std::set<std::string>{}, false) {}
+                    std::vector<Subsystem>{}, std::vector<Subsystem>{}, std::set<std::string>{}, "",
+                    false) {}
 
 }  // namespace init
 }  // namespace android
diff --git a/init/devices.h b/init/devices.h
index 6da123259..69a244978 100644
--- a/init/devices.h
+++ b/init/devices.h
@@ -21,6 +21,7 @@
 #include <sys/types.h>
 
 #include <algorithm>
+#include <map>
 #include <set>
 #include <string>
 #include <vector>
@@ -116,16 +117,24 @@ class Subsystem {
     std::string dir_name_ = "/dev";
 };
 
+struct BlockDeviceInfo {
+    std::string str;
+    std::string type;
+    bool is_boot_device;
+};
+
 class DeviceHandler : public UeventHandler {
   public:
     friend class DeviceHandlerTester;
 
     DeviceHandler();
     DeviceHandler(std::vector<Permissions> dev_permissions,
-                  std::vector<SysfsPermissions> sysfs_permissions, std::vector<Subsystem> subsystems,
-                  std::set<std::string> boot_devices, bool skip_restorecon);
+                  std::vector<SysfsPermissions> sysfs_permissions, std::vector<Subsystem> drivers,
+                  std::vector<Subsystem> subsystems, std::set<std::string> boot_devices,
+                  std::string boot_part_uuid, bool skip_restorecon);
     virtual ~DeviceHandler() = default;
 
+    bool CheckUeventForBootPartUuid(const Uevent& uevent);
     void HandleUevent(const Uevent& uevent) override;
 
     // `androidboot.partition_map` allows associating a partition name for a raw block device
@@ -133,10 +142,23 @@ class DeviceHandler : public UeventHandler {
     // `androidboot.partition_map=vdb,metadata;vdc,userdata` maps `vdb` to `metadata` and `vdc` to
     // `userdata`.
     static std::string GetPartitionNameForDevice(const std::string& device);
+    bool IsBootDeviceStrict() const;
+    bool IsBootDevice(const Uevent& uevent) const;
 
   private:
+    struct TrackedUevent {
+        Uevent uevent;
+        std::string canonical_device_path;
+    };
+
     void ColdbootDone() override;
-    bool FindPlatformDevice(std::string path, std::string* platform_device_path) const;
+    BlockDeviceInfo GetBlockDeviceInfo(const std::string& uevent_path) const;
+    bool FindSubsystemDevice(std::string path, std::string* device_path,
+                             const std::set<std::string>& subsystem_paths) const;
+    bool FindPlatformDevice(const std::string& path, std::string* platform_device_path) const;
+    bool FindMmcDevice(const std::string& path, std::string* mmc_device_path) const;
+    bool FindNvmeDevice(const std::string& path, std::string* nvme_device_path) const;
+    bool FindScsiDevice(const std::string& path, std::string* scsi_device_path) const;
     std::tuple<mode_t, uid_t, gid_t> GetDevicePermissions(
         const std::string& path, const std::vector<std::string>& links) const;
     void MakeDevice(const std::string& path, bool block, int major, int minor,
@@ -147,12 +169,21 @@ class DeviceHandler : public UeventHandler {
     void FixupSysPermissions(const std::string& upath, const std::string& subsystem) const;
     void HandleAshmemUevent(const Uevent& uevent);
 
+    void TrackDeviceUevent(const Uevent& uevent);
+    void HandleBindInternal(std::string driver_name, std::string action, const Uevent& uevent);
+
     std::vector<Permissions> dev_permissions_;
     std::vector<SysfsPermissions> sysfs_permissions_;
+    std::vector<Subsystem> drivers_;
     std::vector<Subsystem> subsystems_;
     std::set<std::string> boot_devices_;
+    std::string boot_part_uuid_;
+    bool found_boot_part_uuid_;
     bool skip_restorecon_;
     std::string sysfs_mount_point_;
+
+    std::vector<TrackedUevent> tracked_uevents_;
+    std::map<std::string, std::string> bound_drivers_;
 };
 
 // Exposed for testing
diff --git a/init/epoll.cpp b/init/epoll.cpp
index cd73a0c3d..719a53271 100644
--- a/init/epoll.cpp
+++ b/init/epoll.cpp
@@ -47,8 +47,8 @@ Result<void> Epoll::RegisterHandler(int fd, Handler handler, uint32_t events) {
 
     auto [it, inserted] = epoll_handlers_.emplace(
             fd, Info{
-                        .events = events,
                         .handler = std::move(handler),
+                        .events = events,
                 });
     if (!inserted) {
         return Error() << "Cannot specify two epoll handlers for a given FD";
diff --git a/init/firmware_handler.cpp b/init/firmware_handler.cpp
index 01957eff0..dcfda52d6 100644
--- a/init/firmware_handler.cpp
+++ b/init/firmware_handler.cpp
@@ -38,6 +38,8 @@
 #include <android-base/strings.h>
 #include <android-base/unique_fd.h>
 
+#include "exthandler/exthandler.h"
+
 using android::base::ReadFdToString;
 using android::base::Socketpair;
 using android::base::Split;
@@ -136,100 +138,6 @@ FirmwareHandler::FirmwareHandler(std::vector<std::string> firmware_directories,
     : firmware_directories_(std::move(firmware_directories)),
       external_firmware_handlers_(std::move(external_firmware_handlers)) {}
 
-Result<std::string> FirmwareHandler::RunExternalHandler(const std::string& handler, uid_t uid,
-                                                        gid_t gid, const Uevent& uevent) const {
-    unique_fd child_stdout;
-    unique_fd parent_stdout;
-    if (!Socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &child_stdout, &parent_stdout)) {
-        return ErrnoError() << "Socketpair() for stdout failed";
-    }
-
-    unique_fd child_stderr;
-    unique_fd parent_stderr;
-    if (!Socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &child_stderr, &parent_stderr)) {
-        return ErrnoError() << "Socketpair() for stderr failed";
-    }
-
-    signal(SIGCHLD, SIG_DFL);
-
-    auto pid = fork();
-    if (pid < 0) {
-        return ErrnoError() << "fork() failed";
-    }
-
-    if (pid == 0) {
-        setenv("FIRMWARE", uevent.firmware.c_str(), 1);
-        setenv("DEVPATH", uevent.path.c_str(), 1);
-        parent_stdout.reset();
-        parent_stderr.reset();
-        close(STDOUT_FILENO);
-        close(STDERR_FILENO);
-        dup2(child_stdout.get(), STDOUT_FILENO);
-        dup2(child_stderr.get(), STDERR_FILENO);
-
-        auto args = Split(handler, " ");
-        std::vector<char*> c_args;
-        for (auto& arg : args) {
-            c_args.emplace_back(arg.data());
-        }
-        c_args.emplace_back(nullptr);
-
-        if (gid != 0) {
-            if (setgid(gid) != 0) {
-                fprintf(stderr, "setgid() failed: %s", strerror(errno));
-                _exit(EXIT_FAILURE);
-            }
-        }
-
-        if (setuid(uid) != 0) {
-            fprintf(stderr, "setuid() failed: %s", strerror(errno));
-            _exit(EXIT_FAILURE);
-        }
-
-        execv(c_args[0], c_args.data());
-        fprintf(stderr, "exec() failed: %s", strerror(errno));
-        _exit(EXIT_FAILURE);
-    }
-
-    child_stdout.reset();
-    child_stderr.reset();
-
-    int status;
-    pid_t waited_pid = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
-    if (waited_pid == -1) {
-        return ErrnoError() << "waitpid() failed";
-    }
-
-    std::string stdout_content;
-    if (!ReadFdToString(parent_stdout.get(), &stdout_content)) {
-        return ErrnoError() << "ReadFdToString() for stdout failed";
-    }
-
-    std::string stderr_content;
-    if (ReadFdToString(parent_stderr.get(), &stderr_content)) {
-        auto messages = Split(stderr_content, "\n");
-        for (const auto& message : messages) {
-            if (!message.empty()) {
-                LOG(ERROR) << "External Firmware Handler: " << message;
-            }
-        }
-    } else {
-        LOG(ERROR) << "ReadFdToString() for stderr failed";
-    }
-
-    if (WIFEXITED(status)) {
-        if (WEXITSTATUS(status) == EXIT_SUCCESS) {
-            return Trim(stdout_content);
-        } else {
-            return Error() << "exited with status " << WEXITSTATUS(status);
-        }
-    } else if (WIFSIGNALED(status)) {
-        return Error() << "killed by signal " << WTERMSIG(status);
-    }
-
-    return Error() << "unexpected exit status " << status;
-}
-
 std::string FirmwareHandler::GetFirmwarePath(const Uevent& uevent) const {
     for (const auto& external_handler : external_firmware_handlers_) {
         if (external_handler.match(uevent.path)) {
@@ -237,11 +145,15 @@ std::string FirmwareHandler::GetFirmwarePath(const Uevent& uevent) const {
                       << "' for devpath: '" << uevent.path << "' firmware: '" << uevent.firmware
                       << "'";
 
+            std::unordered_map<std::string, std::string> envs_map;
+            envs_map["FIRMWARE"] = uevent.firmware;
+            envs_map["DEVPATH"] = uevent.path;
+
             auto result = RunExternalHandler(external_handler.handler_path, external_handler.uid,
-                                             external_handler.gid, uevent);
+                                             external_handler.gid, envs_map);
             if (!result.ok() && NeedsRerunExternalHandler()) {
                 auto res = RunExternalHandler(external_handler.handler_path, external_handler.uid,
-                                              external_handler.gid, uevent);
+                                              external_handler.gid, envs_map);
                 result = std::move(res);
             }
             if (!result.ok()) {
diff --git a/init/firmware_handler.h b/init/firmware_handler.h
index fceb392db..e5d353809 100644
--- a/init/firmware_handler.h
+++ b/init/firmware_handler.h
@@ -54,8 +54,6 @@ class FirmwareHandler : public UeventHandler {
     friend void FirmwareTestWithExternalHandler(const std::string& test_name,
                                                 bool expect_new_firmware);
 
-    Result<std::string> RunExternalHandler(const std::string& handler, uid_t uid, gid_t gid,
-                                           const Uevent& uevent) const;
     std::string GetFirmwarePath(const Uevent& uevent) const;
     void ProcessFirmwareEvent(const std::string& path, const std::string& firmware) const;
     bool ForEachFirmwareDirectory(std::function<bool(const std::string&)> handler) const;
diff --git a/init/first_stage_mount.cpp b/init/first_stage_mount.cpp
index c26b31e93..aa6b55166 100644
--- a/init/first_stage_mount.cpp
+++ b/init/first_stage_mount.cpp
@@ -32,9 +32,12 @@
 #include <android-base/chrono_utils.h>
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/parseint.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <android/avf_cc_flags.h>
+#include <bootloader_message/bootloader_message.h>
+#include <cutils/android_reboot.h>
 #include <fs_avb/fs_avb.h>
 #include <fs_mgr.h>
 #include <fs_mgr_dm_linear.h>
@@ -46,6 +49,7 @@
 
 #include "block_dev_initializer.h"
 #include "devices.h"
+#include "reboot_utils.h"
 #include "result.h"
 #include "snapuserd_transition.h"
 #include "switch_root.h"
@@ -111,6 +115,8 @@ class FirstStageMountVBootV2 : public FirstStageMount {
     bool GetDmVerityDevices(std::set<std::string>* devices);
     bool SetUpDmVerity(FstabEntry* fstab_entry);
 
+    void RequestTradeInModeWipeIfNeeded();
+
     bool InitAvbHandle();
 
     bool need_dm_verity_;
@@ -156,13 +162,6 @@ static Result<Fstab> ReadFirstStageFstabAndroid() {
     return fstab;
 }
 
-static bool IsRequestingMicrodroidVendorPartition(const std::string& cmdline) {
-    if (virtualization::IsEnableTpuAssignableDeviceFlagEnabled()) {
-        return access("/proc/device-tree/avf/vendor_hashtree_descriptor_root_digest", F_OK) == 0;
-    }
-    return cmdline.find("androidboot.microdroid.mount_vendor=1") != std::string::npos;
-}
-
 // Note: this is a temporary solution to avoid blocking devs that depend on /vendor partition in
 // Microdroid. For the proper solution the /vendor fstab should probably be defined in the DT.
 // TODO(b/285855430): refactor this
@@ -173,7 +172,7 @@ static Result<Fstab> ReadFirstStageFstabMicrodroid(const std::string& cmdline) {
     if (!ReadDefaultFstab(&fstab)) {
         return Error() << "failed to read fstab";
     }
-    if (!IsRequestingMicrodroidVendorPartition(cmdline)) {
+    if (cmdline.find("androidboot.microdroid.mount_vendor=1") == std::string::npos) {
         // We weren't asked to mount /vendor partition, filter it out from the fstab.
         auto predicate = [](const auto& entry) { return entry.mount_point == "/vendor"; };
         fstab.erase(std::remove_if(fstab.begin(), fstab.end(), predicate), fstab.end());
@@ -270,6 +269,8 @@ bool FirstStageMountVBootV2::DoCreateDevices() {
 }
 
 bool FirstStageMountVBootV2::DoFirstStageMount() {
+    RequestTradeInModeWipeIfNeeded();
+
     if (!IsDmLinearEnabled() && fstab_.empty()) {
         // Nothing to mount.
         LOG(INFO) << "First stage mount skipped (missing/incompatible/empty fstab in device tree)";
@@ -287,6 +288,10 @@ static bool IsMicrodroidStrictBoot() {
 }
 
 bool FirstStageMountVBootV2::InitDevices() {
+    if (!block_dev_init_.InitBootDevicesFromPartUuid()) {
+        return false;
+    }
+
     std::set<std::string> devices;
     GetSuperDeviceName(&devices);
 
@@ -312,11 +317,6 @@ bool FirstStageMountVBootV2::InitDevices() {
             return false;
         }
     }
-
-    if (IsArcvm() && !block_dev_init_.InitHvcDevice("hvc1")) {
-        return false;
-    }
-
     return true;
 }
 
@@ -890,6 +890,55 @@ bool FirstStageMountVBootV2::InitAvbHandle() {
     return true;
 }
 
+void FirstStageMountVBootV2::RequestTradeInModeWipeIfNeeded() {
+    static constexpr const char* kWipeIndicator = "/metadata/tradeinmode/wipe";
+    static constexpr size_t kWipeAttempts = 3;
+
+    if (access(kWipeIndicator, R_OK) == -1) {
+        return;
+    }
+
+    // Write a counter to the wipe indicator, to try and prevent boot loops if
+    // recovery fails to wipe data.
+    uint32_t counter = 0;
+    std::string contents;
+    if (ReadFileToString(kWipeIndicator, &contents)) {
+        android::base::ParseUint(contents, &counter);
+        contents = std::to_string(++counter);
+        if (android::base::WriteStringToFile(contents, kWipeIndicator)) {
+            sync();
+        } else {
+            PLOG(ERROR) << "Failed to update " << kWipeIndicator;
+        }
+    } else {
+        PLOG(ERROR) << "Failed to read " << kWipeIndicator;
+    }
+
+    std::string err;
+    auto misc_device = get_misc_blk_device(&err);
+    if (misc_device.empty()) {
+        LOG(FATAL) << "Could not find misc device: " << err;
+    }
+
+    auto misc_name = android::base::Basename(misc_device);
+    if (!block_dev_init_.InitDevices({misc_name})) {
+        LOG(FATAL) << "Could not find misc device: " << misc_device;
+    }
+
+    // If we've failed to wipe three times, don't include the wipe command. This
+    // will force us to boot into the recovery menu instead where a manual wipe
+    // can be attempted.
+    std::vector<std::string> options;
+    if (counter <= kWipeAttempts) {
+        options.emplace_back("--wipe_data");
+        options.emplace_back("--reason=tradeinmode");
+    }
+    if (!write_bootloader_message(options, &err)) {
+        LOG(FATAL) << "Could not issue wipe: " << err;
+    }
+    RebootSystem(ANDROID_RB_RESTART2, "recovery", "reboot,tradeinmode,wipe");
+}
+
 void SetInitAvbVersionInRecovery() {
     if (!IsRecoveryMode()) {
         LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not in recovery mode)";
diff --git a/init/init.cpp b/init/init.cpp
index 6c8089926..5b0b0ddee 100644
--- a/init/init.cpp
+++ b/init/init.cpp
@@ -315,8 +315,7 @@ Parser CreateApexConfigParser(ActionManager& action_manager, ServiceList& servic
         if (apex_info_list.has_value()) {
             std::vector<std::string> subcontext_apexes;
             for (const auto& info : apex_info_list->getApexInfo()) {
-                if (info.hasPreinstalledModulePath() &&
-                    subcontext->PathMatchesSubcontext(info.getPreinstalledModulePath())) {
+                if (subcontext->PartitionMatchesSubcontext(info.getPartition())) {
                     subcontext_apexes.push_back(info.getModuleName());
                 }
             }
@@ -636,9 +635,6 @@ static Result<void> SetupCgroupsAction(const BuiltinArguments&) {
         LOG(INFO) << "Cgroups support in kernel is not enabled";
         return {};
     }
-    // Have to create <CGROUPS_RC_DIR> using make_dir function
-    // for appropriate sepolicy to be set for it
-    make_dir(android::base::Dirname(CGROUPS_RC_PATH), 0711);
     if (!CgroupSetup()) {
         return ErrnoError() << "Failed to setup cgroups";
     }
diff --git a/init/libprefetch/prefetch/Android.bp b/init/libprefetch/prefetch/Android.bp
new file mode 100644
index 000000000..778ea8a8c
--- /dev/null
+++ b/init/libprefetch/prefetch/Android.bp
@@ -0,0 +1,80 @@
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
+
+package {
+    default_team: "trendy_team_android_kernel",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_library_rlib {
+    name: "libprefetch_rs",
+    crate_name: "prefetch_rs",
+    srcs: ["src/lib.rs"],
+    rustlibs: [
+        "libandroid_logger",
+        "libargh",
+        "libchrono",
+        "libcrc32fast",
+        "libcsv",
+        "liblibc",
+        "liblog_rust",
+        "liblru_cache",
+        "libnix",
+        "librand",
+        "librayon",
+        "libregex",
+        "libserde_cbor",
+        "libserde_json",
+        "libserde",
+        "libthiserror",
+        "libwalkdir",
+        "librustutils",
+    ],
+    prefer_rlib: true,
+    features: [
+        "derive",
+        "error-context",
+        "help",
+        "std",
+        "usage",
+        "use_argh",
+    ],
+}
+
+rust_binary {
+    name: "prefetch",
+    crate_name: "prefetch",
+    srcs: ["src/main.rs"],
+    rustlibs: [
+        "libprefetch_rs",
+        "liblog_rust",
+        "libandroid_logger",
+    ],
+    prefer_rlib: true,
+    features: [
+        "default",
+        "derive",
+        "error-context",
+        "help",
+        "std",
+        "usage",
+        "use_argh",
+    ],
+    init_rc: [
+        "prefetch.rc",
+    ],
+}
+
+// TODO: Add rust_test to enable unit testing - b/378554334
diff --git a/init/libprefetch/prefetch/Cargo.lock b/init/libprefetch/prefetch/Cargo.lock
new file mode 100644
index 000000000..d6b214d26
--- /dev/null
+++ b/init/libprefetch/prefetch/Cargo.lock
@@ -0,0 +1,743 @@
+# This file is automatically @generated by Cargo.
+# It is not intended for manual editing.
+version = 3
+
+[[package]]
+name = "aho-corasick"
+version = "0.7.15"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "7404febffaa47dac81aa44dba71523c9d069b1bdc50a77db41195149e17f68e5"
+dependencies = [
+ "memchr",
+]
+
+[[package]]
+name = "android_log-sys"
+version = "0.2.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "85965b6739a430150bdd138e2374a98af0c3ee0d030b3bb7fc3bddff58d0102e"
+
+[[package]]
+name = "android_logger"
+version = "0.10.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "d9ed09b18365ed295d722d0b5ed59c01b79a826ff2d2a8f73d5ecca8e6fb2f66"
+dependencies = [
+ "android_log-sys",
+ "env_logger",
+ "lazy_static",
+ "log",
+]
+
+[[package]]
+name = "argh"
+version = "0.1.10"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "ab257697eb9496bf75526f0217b5ed64636a9cfafa78b8365c71bd283fcef93e"
+dependencies = [
+ "argh_derive",
+ "argh_shared",
+]
+
+[[package]]
+name = "argh_derive"
+version = "0.1.10"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "b382dbd3288e053331f03399e1db106c9fb0d8562ad62cb04859ae926f324fa6"
+dependencies = [
+ "argh_shared",
+ "proc-macro2",
+ "quote",
+ "syn",
+]
+
+[[package]]
+name = "argh_shared"
+version = "0.1.12"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5693f39141bda5760ecc4111ab08da40565d1771038c4a0250f03457ec707531"
+dependencies = [
+ "serde",
+]
+
+[[package]]
+name = "atty"
+version = "0.2.14"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "d9b39be18770d11421cdb1b9947a45dd3f37e93092cbf377614828a319d5fee8"
+dependencies = [
+ "hermit-abi 0.1.19",
+ "libc",
+ "winapi 0.3.9",
+]
+
+[[package]]
+name = "autocfg"
+version = "1.1.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "d468802bab17cbc0cc575e9b053f41e72aa36bfa6b7f55e3529ffa43161b97fa"
+
+[[package]]
+name = "bincode"
+version = "0.9.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "b92615d57e4048e480bd7e3c2d7f6ec252819fffec95efbc30ec7c68744aa66c"
+dependencies = [
+ "byteorder",
+ "serde",
+]
+
+[[package]]
+name = "bitflags"
+version = "2.6.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "b048fb63fd8b5923fc5aa7b340d8e156aec7ec02f0c78fa8a6ddc2613f6f71de"
+
+[[package]]
+name = "bstr"
+version = "0.2.15"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a40b47ad93e1a5404e6c18dec46b628214fee441c70f4ab5d6942142cc268a3d"
+dependencies = [
+ "lazy_static",
+ "memchr",
+ "regex-automata",
+ "serde",
+]
+
+[[package]]
+name = "byteorder"
+version = "1.5.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "1fd0f2584146f6f2ef48085050886acf353beff7305ebd1ae69500e27c67f64b"
+
+[[package]]
+name = "cfg-if"
+version = "1.0.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd"
+
+[[package]]
+name = "cfg_aliases"
+version = "0.1.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "fd16c4719339c4530435d38e511904438d07cce7950afa3718a84ac36c10e89e"
+
+[[package]]
+name = "chrono"
+version = "0.4.19"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "670ad68c9088c2a963aaa298cb369688cf3f9465ce5e2d4ca10e6e0098a1ce73"
+dependencies = [
+ "libc",
+ "num-integer",
+ "num-traits",
+ "serde",
+ "time",
+ "winapi 0.3.9",
+]
+
+[[package]]
+name = "crc32fast"
+version = "1.3.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "b540bd8bc810d3885c6ea91e2018302f68baba2129ab3e88f32389ee9370880d"
+dependencies = [
+ "cfg-if",
+]
+
+[[package]]
+name = "crossbeam-channel"
+version = "0.5.11"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "176dc175b78f56c0f321911d9c8eb2b77a78a4860b9c19db83835fea1a46649b"
+dependencies = [
+ "crossbeam-utils",
+]
+
+[[package]]
+name = "crossbeam-deque"
+version = "0.8.5"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "613f8cc01fe9cf1a3eb3d7f488fd2fa8388403e97039e2f73692932e291a770d"
+dependencies = [
+ "crossbeam-epoch",
+ "crossbeam-utils",
+]
+
+[[package]]
+name = "crossbeam-epoch"
+version = "0.9.18"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5b82ac4a3c2ca9c3460964f020e1402edd5753411d7737aa39c3714ad1b5420e"
+dependencies = [
+ "crossbeam-utils",
+]
+
+[[package]]
+name = "crossbeam-utils"
+version = "0.8.19"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "248e3bacc7dc6baa3b21e405ee045c3047101a49145e7e9eca583ab4c2ca5345"
+
+[[package]]
+name = "csv"
+version = "1.1.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "22813a6dc45b335f9bade10bf7271dc477e81113e89eb251a0bc2a8a81c536e1"
+dependencies = [
+ "bstr",
+ "csv-core",
+ "itoa",
+ "ryu",
+ "serde",
+]
+
+[[package]]
+name = "csv-core"
+version = "0.1.11"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5efa2b3d7902f4b634a20cae3c9c4e6209dc4779feb6863329607560143efa70"
+dependencies = [
+ "memchr",
+]
+
+[[package]]
+name = "either"
+version = "1.9.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a26ae43d7bcc3b814de94796a5e736d4029efb0ee900c12e2d54c993ad1a1e07"
+
+[[package]]
+name = "env_logger"
+version = "0.8.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a19187fea3ac7e84da7dacf48de0c45d63c6a76f9490dae389aead16c243fce3"
+dependencies = [
+ "atty",
+ "humantime",
+ "log",
+ "regex",
+ "termcolor",
+]
+
+[[package]]
+name = "fuchsia-cprng"
+version = "0.1.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a06f77d526c1a601b7c4cdd98f54b5eaabffc14d5f2f0296febdc7f357c6d3ba"
+
+[[package]]
+name = "getrandom"
+version = "0.2.12"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "190092ea657667030ac6a35e305e62fc4dd69fd98ac98631e5d3a2b1575a12b5"
+dependencies = [
+ "cfg-if",
+ "libc",
+ "wasi 0.11.0+wasi-snapshot-preview1",
+]
+
+[[package]]
+name = "half"
+version = "1.8.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "eabb4a44450da02c90444cf74558da904edde8fb4e9035a9a6a4e15445af0bd7"
+
+[[package]]
+name = "hermit-abi"
+version = "0.1.19"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "62b467343b94ba476dcb2500d242dadbb39557df889310ac77c5d99100aaac33"
+dependencies = [
+ "libc",
+]
+
+[[package]]
+name = "hermit-abi"
+version = "0.3.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5d3d0e0f38255e7fa3cf31335b3a56f05febd18025f4db5ef7a0cfb4f8da651f"
+
+[[package]]
+name = "humantime"
+version = "2.1.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "9a3a5bfb195931eeb336b2a7b4d761daec841b97f947d34394601737a7bba5e4"
+
+[[package]]
+name = "itoa"
+version = "0.4.8"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "b71991ff56294aa922b450139ee08b3bfc70982c6b2c7562771375cf73542dd4"
+
+[[package]]
+name = "kernel32-sys"
+version = "0.2.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "7507624b29483431c0ba2d82aece8ca6cdba9382bff4ddd0f7490560c056098d"
+dependencies = [
+ "winapi 0.2.8",
+ "winapi-build",
+]
+
+[[package]]
+name = "lazy_static"
+version = "1.4.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "e2abad23fbc42b3700f2f279844dc832adb2b2eb069b2df918f455c4e18cc646"
+
+[[package]]
+name = "libc"
+version = "0.2.162"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "18d287de67fe55fd7e1581fe933d965a5a9477b38e949cfa9f8574ef01506398"
+
+[[package]]
+name = "linked-hash-map"
+version = "0.5.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "0717cef1bc8b636c6e1c1bbdefc09e6322da8a9321966e8928ef80d20f7f770f"
+
+[[package]]
+name = "log"
+version = "0.4.14"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "51b9bbe6c47d51fc3e1a9b945965946b4c44142ab8792c50835a980d362c2710"
+dependencies = [
+ "cfg-if",
+]
+
+[[package]]
+name = "lru-cache"
+version = "0.1.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "31e24f1ad8321ca0e8a1e0ac13f23cb668e6f5466c2c57319f6a5cf1cc8e3b1c"
+dependencies = [
+ "linked-hash-map",
+]
+
+[[package]]
+name = "memchr"
+version = "2.3.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "0ee1c47aaa256ecabcaea351eae4a9b01ef39ed810004e298d2511ed284b1525"
+
+[[package]]
+name = "nix"
+version = "0.28.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "ab2156c4fce2f8df6c499cc1c763e4394b7482525bf2a9701c9d79d215f519e4"
+dependencies = [
+ "bitflags",
+ "cfg-if",
+ "cfg_aliases",
+ "libc",
+]
+
+[[package]]
+name = "num-integer"
+version = "0.1.45"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "225d3389fb3509a24c93f5c29eb6bde2586b98d9f016636dff58d7c6f7569cd9"
+dependencies = [
+ "autocfg",
+ "num-traits",
+]
+
+[[package]]
+name = "num-traits"
+version = "0.2.17"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "39e3200413f237f41ab11ad6d161bc7239c84dcb631773ccd7de3dfe4b5c267c"
+dependencies = [
+ "autocfg",
+]
+
+[[package]]
+name = "num_cpus"
+version = "1.16.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "4161fcb6d602d4d2081af7c3a45852d875a03dd337a6bfdd6e06407b61342a43"
+dependencies = [
+ "hermit-abi 0.3.4",
+ "libc",
+]
+
+[[package]]
+name = "ppv-lite86"
+version = "0.2.17"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5b40af805b3121feab8a3c29f04d8ad262fa8e0561883e7653e024ae4479e6de"
+
+[[package]]
+name = "prefetch"
+version = "0.1.0"
+dependencies = [
+ "android_logger",
+ "argh",
+ "bincode",
+ "chrono",
+ "crc32fast",
+ "csv",
+ "env_logger",
+ "libc",
+ "log",
+ "lru-cache",
+ "memchr",
+ "nix",
+ "proc-macro2",
+ "quote",
+ "rand 0.8.5",
+ "rayon",
+ "rayon-core",
+ "regex",
+ "serde",
+ "serde_cbor",
+ "serde_derive",
+ "serde_json",
+ "tempfile",
+ "thiserror",
+ "thiserror-impl",
+ "walkdir",
+]
+
+[[package]]
+name = "proc-macro2"
+version = "1.0.26"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a152013215dca273577e18d2bf00fa862b89b24169fb78c4c95aeb07992c9cec"
+dependencies = [
+ "unicode-xid",
+]
+
+[[package]]
+name = "quote"
+version = "1.0.9"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "c3d0b9745dc2debf507c8422de05d7226cc1f0644216dfdfead988f9b1ab32a7"
+dependencies = [
+ "proc-macro2",
+]
+
+[[package]]
+name = "rand"
+version = "0.3.23"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "64ac302d8f83c0c1974bf758f6b041c6c8ada916fbb44a609158ca8b064cc76c"
+dependencies = [
+ "libc",
+ "rand 0.4.6",
+]
+
+[[package]]
+name = "rand"
+version = "0.4.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "552840b97013b1a26992c11eac34bdd778e464601a4c2054b5f0bff7c6761293"
+dependencies = [
+ "fuchsia-cprng",
+ "libc",
+ "rand_core 0.3.1",
+ "rdrand",
+ "winapi 0.3.9",
+]
+
+[[package]]
+name = "rand"
+version = "0.8.5"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "34af8d1a0e25924bc5b7c43c079c942339d8f0a8b57c39049bef581b46327404"
+dependencies = [
+ "libc",
+ "rand_chacha",
+ "rand_core 0.6.4",
+]
+
+[[package]]
+name = "rand_chacha"
+version = "0.3.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "e6c10a63a0fa32252be49d21e7709d4d4baf8d231c2dbce1eaa8141b9b127d88"
+dependencies = [
+ "ppv-lite86",
+ "rand_core 0.6.4",
+]
+
+[[package]]
+name = "rand_core"
+version = "0.3.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "7a6fdeb83b075e8266dcc8762c22776f6877a63111121f5f8c7411e5be7eed4b"
+dependencies = [
+ "rand_core 0.4.2",
+]
+
+[[package]]
+name = "rand_core"
+version = "0.4.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "9c33a3c44ca05fa6f1807d8e6743f3824e8509beca625669633be0acbdf509dc"
+
+[[package]]
+name = "rand_core"
+version = "0.6.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "ec0be4795e2f6a28069bec0b5ff3e2ac9bafc99e6a9a7dc3547996c5c816922c"
+dependencies = [
+ "getrandom",
+]
+
+[[package]]
+name = "rayon"
+version = "1.5.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "8b0d8e0819fadc20c74ea8373106ead0600e3a67ef1fe8da56e39b9ae7275674"
+dependencies = [
+ "autocfg",
+ "crossbeam-deque",
+ "either",
+ "rayon-core",
+]
+
+[[package]]
+name = "rayon-core"
+version = "1.9.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "9ab346ac5921dc62ffa9f89b7a773907511cdfa5490c572ae9be1be33e8afa4a"
+dependencies = [
+ "crossbeam-channel",
+ "crossbeam-deque",
+ "crossbeam-utils",
+ "lazy_static",
+ "num_cpus",
+]
+
+[[package]]
+name = "rdrand"
+version = "0.4.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "678054eb77286b51581ba43620cc911abf02758c91f93f479767aed0f90458b2"
+dependencies = [
+ "rand_core 0.3.1",
+]
+
+[[package]]
+name = "redox_syscall"
+version = "0.1.57"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "41cc0f7e4d5d4544e8861606a285bb08d3e70712ccc7d2b84d7c0ccfaf4b05ce"
+
+[[package]]
+name = "regex"
+version = "1.4.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "2a26af418b574bd56588335b3a3659a65725d4e636eb1016c2f9e3b38c7cc759"
+dependencies = [
+ "aho-corasick",
+ "memchr",
+ "regex-syntax",
+]
+
+[[package]]
+name = "regex-automata"
+version = "0.1.10"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "6c230d73fb8d8c1b9c0b3135c5142a8acee3a0558fb8db5cf1cb65f8d7862132"
+
+[[package]]
+name = "regex-syntax"
+version = "0.6.29"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f162c6dd7b008981e4d40210aca20b4bd0f9b60ca9271061b07f78537722f2e1"
+
+[[package]]
+name = "ryu"
+version = "1.0.16"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f98d2aa92eebf49b69786be48e4477826b256916e84a57ff2a4f21923b48eb4c"
+
+[[package]]
+name = "same-file"
+version = "1.0.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "93fc1dc3aaa9bfed95e02e6eadabb4baf7e3078b0bd1b4d7b6b0b68378900502"
+dependencies = [
+ "winapi-util",
+]
+
+[[package]]
+name = "serde"
+version = "1.0.123"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "92d5161132722baa40d802cc70b15262b98258453e85e5d1d365c757c73869ae"
+dependencies = [
+ "serde_derive",
+]
+
+[[package]]
+name = "serde_cbor"
+version = "0.11.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "2bef2ebfde456fb76bbcf9f59315333decc4fda0b2b44b420243c11e0f5ec1f5"
+dependencies = [
+ "half",
+ "serde",
+]
+
+[[package]]
+name = "serde_derive"
+version = "1.0.123"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "9391c295d64fc0abb2c556bad848f33cb8296276b1ad2677d1ae1ace4f258f31"
+dependencies = [
+ "proc-macro2",
+ "quote",
+ "syn",
+]
+
+[[package]]
+name = "serde_json"
+version = "1.0.62"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "ea1c6153794552ea7cf7cf63b1231a25de00ec90db326ba6264440fa08e31486"
+dependencies = [
+ "itoa",
+ "ryu",
+ "serde",
+]
+
+[[package]]
+name = "syn"
+version = "1.0.80"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "d010a1623fbd906d51d650a9916aaefc05ffa0e4053ff7fe601167f3e715d194"
+dependencies = [
+ "proc-macro2",
+ "quote",
+ "unicode-xid",
+]
+
+[[package]]
+name = "tempfile"
+version = "2.2.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "11ce2fe9db64b842314052e2421ac61a73ce41b898dc8e3750398b219c5fc1e0"
+dependencies = [
+ "kernel32-sys",
+ "libc",
+ "rand 0.3.23",
+ "redox_syscall",
+ "winapi 0.2.8",
+]
+
+[[package]]
+name = "termcolor"
+version = "1.4.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "06794f8f6c5c898b3275aebefa6b8a1cb24cd2c6c79397ab15774837a0bc5755"
+dependencies = [
+ "winapi-util",
+]
+
+[[package]]
+name = "thiserror"
+version = "1.0.24"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "e0f4a65597094d4483ddaed134f409b2cb7c1beccf25201a9f73c719254fa98e"
+dependencies = [
+ "thiserror-impl",
+]
+
+[[package]]
+name = "thiserror-impl"
+version = "1.0.24"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "7765189610d8241a44529806d6fd1f2e0a08734313a35d5b3a556f92b381f3c0"
+dependencies = [
+ "proc-macro2",
+ "quote",
+ "syn",
+]
+
+[[package]]
+name = "time"
+version = "0.1.45"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "1b797afad3f312d1c66a56d11d0316f916356d11bd158fbc6ca6389ff6bf805a"
+dependencies = [
+ "libc",
+ "wasi 0.10.0+wasi-snapshot-preview1",
+ "winapi 0.3.9",
+]
+
+[[package]]
+name = "unicode-xid"
+version = "0.2.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f962df74c8c05a667b5ee8bcf162993134c104e96440b663c8daa176dc772d8c"
+
+[[package]]
+name = "walkdir"
+version = "2.4.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "d71d857dc86794ca4c280d616f7da00d2dbfd8cd788846559a6813e6aa4b54ee"
+dependencies = [
+ "same-file",
+ "winapi-util",
+]
+
+[[package]]
+name = "wasi"
+version = "0.10.0+wasi-snapshot-preview1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "1a143597ca7c7793eff794def352d41792a93c481eb1042423ff7ff72ba2c31f"
+
+[[package]]
+name = "wasi"
+version = "0.11.0+wasi-snapshot-preview1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "9c8d87e72b64a3b4db28d11ce29237c246188f4f51057d65a7eab63b7987e423"
+
+[[package]]
+name = "winapi"
+version = "0.2.8"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "167dc9d6949a9b857f3451275e911c3f44255842c1f7a76f33c55103a909087a"
+
+[[package]]
+name = "winapi"
+version = "0.3.9"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419"
+dependencies = [
+ "winapi-i686-pc-windows-gnu",
+ "winapi-x86_64-pc-windows-gnu",
+]
+
+[[package]]
+name = "winapi-build"
+version = "0.1.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "2d315eee3b34aca4797b2da6b13ed88266e6d612562a0c46390af8299fc699bc"
+
+[[package]]
+name = "winapi-i686-pc-windows-gnu"
+version = "0.4.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6"
+
+[[package]]
+name = "winapi-util"
+version = "0.1.6"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f29e6f9198ba0d26b4c9f07dbe6f9ed633e1f3d5b8b414090084349e46a52596"
+dependencies = [
+ "winapi 0.3.9",
+]
+
+[[package]]
+name = "winapi-x86_64-pc-windows-gnu"
+version = "0.4.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f"
diff --git a/init/libprefetch/prefetch/Cargo.toml b/init/libprefetch/prefetch/Cargo.toml
new file mode 100644
index 000000000..7da4fc68b
--- /dev/null
+++ b/init/libprefetch/prefetch/Cargo.toml
@@ -0,0 +1,51 @@
+[package]
+name = "prefetch"
+version = "0.1.0"
+edition = "2018"
+default-run = "prefetch"
+
+[lib]
+name = "prefetch_rs"
+path = "src/lib.rs"
+
+[[bin]]
+name = "prefetch"
+path = "src/main.rs"
+
+[features]
+default = ["use_argh"]
+use_argh = ["argh"]
+
+[dependencies]
+argh = { version = "0.1.10", optional = true }
+chrono = { version = "=0.4.19", features = ["serde"] }
+crc32fast = "1.2.1"
+csv = "=1.1.6"
+libc = "0.2.82"
+log = "=0.4.14"
+lru-cache = "0.1.2"
+memchr = "=2.3.4"
+nix = {version = "0.28", features = ["fs", "time", "feature", "mman", "uio"]}
+proc-macro2 = "=1.0.26"
+quote = "=1.0.9"
+rand = "0.8.3"
+rayon = "=1.5.0"
+rayon-core = "=1.9.0"
+regex = "1.4.5"
+serde = { version = "*", features = ["derive"] }
+serde_cbor = "0.11.2"
+serde_derive = "=1.0.123"
+serde_json = "=1.0.62"
+thiserror = "=1.0.24"
+thiserror-impl = "1.0.24"
+walkdir = "2.3.2"
+
+# crates required for android builds
+[target.'cfg(target_os = "android")'.dependencies]
+android_logger = "0.10.1"
+
+# crates not present in android builds
+[target.'cfg(not(target_os = "android"))'.dependencies]
+bincode = "=0.9.0"
+env_logger = "=0.8.4"
+tempfile = "2.2.0"
diff --git a/init/libprefetch/prefetch/OWNERS b/init/libprefetch/prefetch/OWNERS
new file mode 100644
index 000000000..a1b54bf5c
--- /dev/null
+++ b/init/libprefetch/prefetch/OWNERS
@@ -0,0 +1,3 @@
+akailash@google.com
+auradkar@google.com
+takayas@google.com
diff --git a/init/libprefetch/prefetch/prefetch.rc b/init/libprefetch/prefetch/prefetch.rc
new file mode 100644
index 000000000..fb3fb3b6a
--- /dev/null
+++ b/init/libprefetch/prefetch/prefetch.rc
@@ -0,0 +1,29 @@
+on init && property:ro.prefetch_boot.enabled=true
+    start prefetch
+
+service prefetch /system/bin/prefetch start
+    class main
+    user root
+    group root system
+    disabled
+    oneshot
+
+on property:ro.prefetch_boot.record=true
+    start prefetch_record
+
+service prefetch_record /system/bin/prefetch record --duration ${ro.prefetch_boot.duration_s:-0}
+    class main
+    user root
+    group root system
+    disabled
+    oneshot
+
+on property:ro.prefetch_boot.replay=true
+    start prefetch_replay
+
+service prefetch_replay /system/bin/prefetch replay --io-depth ${ro.prefetch_boot.io_depth:-2} --max-fds ${ro.prefetch_boot.max_fds:-128}
+    class main
+    user root
+    group root system
+    disabled
+    oneshot
diff --git a/init/libprefetch/prefetch/src/arch/android.rs b/init/libprefetch/prefetch/src/arch/android.rs
new file mode 100644
index 000000000..3404e42b1
--- /dev/null
+++ b/init/libprefetch/prefetch/src/arch/android.rs
@@ -0,0 +1,118 @@
+use crate::Error;
+use crate::RecordArgs;
+use crate::StartArgs;
+use log::info;
+use log::warn;
+use std::fs::File;
+use std::fs::OpenOptions;
+use std::io::Write;
+use std::time::Duration;
+
+use rustutils::system_properties::error::PropertyWatcherError;
+use rustutils::system_properties::PropertyWatcher;
+
+const PREFETCH_RECORD_PROPERTY: &str = "prefetch_boot.record";
+const PREFETCH_REPLAY_PROPERTY: &str = "prefetch_boot.replay";
+const PREFETCH_RECORD_PROPERTY_STOP: &str = "ro.prefetch_boot.record_stop";
+
+fn wait_for_property_true(
+    property_name: &str,
+    timeout: Option<Duration>,
+) -> Result<(), PropertyWatcherError> {
+    let mut prop = PropertyWatcher::new(property_name)?;
+    prop.wait_for_value("1", timeout)?;
+    Ok(())
+}
+
+/// Wait for record to stop
+pub fn wait_for_record_stop() {
+    wait_for_property_true(PREFETCH_RECORD_PROPERTY_STOP, None).unwrap_or_else(|e| {
+        warn!("failed to wait for {} with error: {}", PREFETCH_RECORD_PROPERTY_STOP, e)
+    });
+}
+
+fn start_prefetch_service(property_name: &str) -> Result<(), Error> {
+    match rustutils::system_properties::write(property_name, "true") {
+        Ok(_) => {}
+        Err(_) => {
+            return Err(Error::Custom { error: "Failed to start prefetch service".to_string() });
+        }
+    }
+    Ok(())
+}
+
+/// Start prefetch service
+///
+/// 1: Check the presence of the file 'prefetch_ready'. If it doesn't
+/// exist then the device is booting for the first time after wipe.
+/// Thus, we would just create the file and exit as we do not want
+/// to initiate the record after data wipe primiarly because boot
+/// after data wipe is long and the I/O pattern during first boot may not actually match
+/// with subsequent boot.
+///
+/// 2: If the file 'prefetch_ready' is present:
+///
+///   a: Compare the build-finger-print of the device with the one record format
+///   is associated with by reading the file 'build_finger_print'. If they match,
+///   start the prefetch_replay.
+///
+///   b: If they don't match, then the device was updated through OTA. Hence, start
+///   a fresh record and delete the build-finger-print file. This should also cover
+///   the case of device rollback.
+///
+///   c: If the build-finger-print file doesn't exist, then just restart the record
+///   from scratch.
+pub fn start_prefetch(args: &StartArgs) -> Result<(), Error> {
+    if !args.path.exists() {
+        match File::create(args.path.clone()) {
+            Ok(_) => {}
+            Err(_) => {
+                return Err(Error::Custom { error: "File Creation failed".to_string() });
+            }
+        }
+        return Ok(());
+    }
+
+    if args.build_fingerprint_path.exists() {
+        let device_build_fingerprint = rustutils::system_properties::read("ro.build.fingerprint")
+            .map_err(|e| Error::Custom {
+            error: format!("Failed to read ro.build.fingerprint: {}", e),
+        })?;
+        let pack_build_fingerprint = std::fs::read_to_string(&args.build_fingerprint_path)?;
+        if pack_build_fingerprint.trim() == device_build_fingerprint.as_deref().unwrap_or_default()
+        {
+            info!("Start replay");
+            start_prefetch_service(PREFETCH_REPLAY_PROPERTY)?;
+        } else {
+            info!("Start record");
+            std::fs::remove_file(&args.build_fingerprint_path)?;
+            start_prefetch_service(PREFETCH_RECORD_PROPERTY)?;
+        }
+    } else {
+        info!("Start record");
+        start_prefetch_service(PREFETCH_RECORD_PROPERTY)?;
+    }
+    Ok(())
+}
+
+/// Write build finger print to associate prefetch pack file
+pub fn write_build_fingerprint(args: &RecordArgs) -> Result<(), Error> {
+    let mut build_fingerprint_file = OpenOptions::new()
+        .write(true)
+        .create(true)
+        .truncate(true)
+        .open(&args.build_fingerprint_path)
+        .map_err(|source| Error::Create {
+            source,
+            path: args.build_fingerprint_path.to_str().unwrap().to_owned(),
+        })?;
+
+    let device_build_fingerprint =
+        rustutils::system_properties::read("ro.build.fingerprint").unwrap_or_default();
+    let device_build_fingerprint = device_build_fingerprint.unwrap_or_default();
+
+    build_fingerprint_file.write_all(device_build_fingerprint.as_bytes())?;
+    build_fingerprint_file.sync_all()?;
+
+    Ok(())
+}
diff --git a/init/libprefetch/prefetch/src/args.rs b/init/libprefetch/prefetch/src/args.rs
new file mode 100644
index 000000000..e534210b5
--- /dev/null
+++ b/init/libprefetch/prefetch/src/args.rs
@@ -0,0 +1,112 @@
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
+
+pub(crate) static DEFAULT_IO_DEPTH: u16 = 2;
+pub(crate) static DEFAULT_MAX_FDS: u16 = 128;
+pub(crate) static DEFAULT_EXIT_ON_ERROR: bool = false;
+
+mod args_argh;
+use args_argh as args_internal;
+
+use std::path::Path;
+use std::path::PathBuf;
+use std::process::exit;
+
+pub use args_internal::OutputFormat;
+pub use args_internal::ReplayArgs;
+#[cfg(target_os = "android")]
+pub use args_internal::StartArgs;
+pub use args_internal::TracerType;
+pub use args_internal::{DumpArgs, MainArgs, RecordArgs, SubCommands};
+use serde::Deserialize;
+use serde::Serialize;
+
+use crate::Error;
+use log::error;
+
+// Deserialized form of the config file
+#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
+pub struct ConfigFile {
+    // Files to be excluded in prefetch. These files might have been
+    // added in the record file while recording,but we do not want to
+    // replay these files. These can be two types of files:
+    // 1) installation-specific files (e.g. files in /data) and
+    // 2) large files which we do not want to load in replay (e.g. APK files).
+    pub files_to_exclude_regex: Vec<String>,
+    // Files that are not in the record file, but need to be loaded during replay
+    pub additional_replay_files: Vec<String>,
+}
+
+fn verify_and_fix(args: &mut MainArgs) -> Result<(), Error> {
+    match &mut args.nested {
+        SubCommands::Record(arg) => {
+            if arg.debug && arg.int_path.is_none() {
+                arg.int_path = Some(PathBuf::from(format!("{}.int", arg.path.to_str().unwrap())));
+            }
+
+            if let Some(p) = &arg.int_path {
+                ensure_path_doesnt_exist(p)?;
+            }
+        }
+        SubCommands::Replay(arg) => {
+            ensure_path_exists(&arg.path)?;
+            if !arg.config_path.as_os_str().is_empty() {
+                ensure_path_exists(&arg.config_path)?;
+            }
+        }
+        SubCommands::Dump(arg) => {
+            ensure_path_exists(&arg.path)?;
+        }
+        #[cfg(target_os = "android")]
+        SubCommands::Start(_arg) => return Ok(()),
+    }
+    Ok(())
+}
+
+/// Returns error if the given path at `p` exist.
+pub(crate) fn ensure_path_doesnt_exist(p: &Path) -> Result<(), Error> {
+    if p.exists() {
+        Err(Error::InvalidArgs {
+            arg_name: "path".to_string(),
+            arg_value: p.display().to_string(),
+            error: "Path already exists".to_string(),
+        })
+    } else {
+        Ok(())
+    }
+}
+
+/// Returns error if the given path at `p` doesn't exist.
+pub(crate) fn ensure_path_exists(p: &Path) -> Result<(), Error> {
+    if p.is_file() {
+        Ok(())
+    } else {
+        Err(Error::InvalidArgs {
+            arg_name: "path".to_string(),
+            arg_value: p.display().to_string(),
+            error: "Path does not exist".to_string(),
+        })
+    }
+}
+
+/// Builds `MainArgs` from command line arguments. On error prints error/help message
+/// and exits.
+pub fn args_from_env() -> MainArgs {
+    let mut args = args_internal::args_from_env();
+    if let Err(e) = verify_and_fix(&mut args) {
+        error!("failed to verify args: {}", e);
+        exit(1);
+    }
+    args
+}
diff --git a/init/libprefetch/prefetch/src/args/args_argh.rs b/init/libprefetch/prefetch/src/args/args_argh.rs
new file mode 100644
index 000000000..65084eeaa
--- /dev/null
+++ b/init/libprefetch/prefetch/src/args/args_argh.rs
@@ -0,0 +1,254 @@
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
+
+use std::{option::Option, path::PathBuf, result::Result::Ok, str::FromStr};
+
+use argh::FromArgs;
+use serde::Deserialize;
+
+use crate::args::DEFAULT_EXIT_ON_ERROR;
+use crate::args::DEFAULT_IO_DEPTH;
+use crate::args::DEFAULT_MAX_FDS;
+use crate::Error;
+
+/// prefetch-rs
+#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
+pub struct MainArgs {
+    /// subcommands
+    #[argh(subcommand)]
+    pub nested: SubCommands,
+}
+
+/// Sub commands for prefetch functions
+#[derive(Eq, PartialEq, Debug, FromArgs)]
+#[argh(subcommand)]
+pub enum SubCommands {
+    /// Records prefetch data.
+    Record(RecordArgs),
+    /// Replays from prefetch data
+    Replay(ReplayArgs),
+    /// Dump prefetch data in human readable format
+    Dump(DumpArgs),
+    /// Start prefetch service if possible
+    /// If the pack file is present, then prefetch replay is started
+    /// If the pack file is absent or if the build fingerprint
+    /// of the current pack file is different, then prefetch record is started.
+    #[cfg(target_os = "android")]
+    Start(StartArgs),
+}
+
+#[cfg(target_os = "android")]
+fn default_ready_path() -> PathBuf {
+    PathBuf::from("/metadata/prefetch/prefetch_ready")
+}
+
+#[cfg(target_os = "android")]
+fn default_build_finger_print_path() -> PathBuf {
+    PathBuf::from("/metadata/prefetch/build_finger_print")
+}
+
+#[cfg(target_os = "android")]
+#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
+/// Start prefetch service based on if pack file is present.
+#[argh(subcommand, name = "start")]
+pub struct StartArgs {
+    /// file path to check if prefetch_ready is present.
+    ///
+    /// A new file is created at the given path if it's not present.
+    #[argh(option, default = "default_ready_path()")]
+    pub path: PathBuf,
+
+    /// file path where build fingerprint is stored
+    #[argh(option, default = "default_build_finger_print_path()")]
+    pub build_fingerprint_path: PathBuf,
+}
+
+impl Default for SubCommands {
+    fn default() -> Self {
+        Self::Dump(DumpArgs::default())
+    }
+}
+
+fn default_path() -> PathBuf {
+    PathBuf::from("/metadata/prefetch/prefetch.pack")
+}
+
+fn parse_tracing_instance(value: &str) -> Result<Option<String>, String> {
+    Ok(Some(value.to_string()))
+}
+
+#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
+/// Records prefect data.
+#[argh(subcommand, name = "record")]
+pub struct RecordArgs {
+    /// duration in seconds to record the data
+    ///
+    /// On Android, if duration count is set to zero, recording
+    /// will continue until the property sys.boot_completed = 1.
+    #[argh(option)]
+    pub duration: u16,
+
+    /// file path where the records will be written to
+    ///
+    /// A new file is created at the given path. If the path exists, it
+    /// will be overwritten
+    #[argh(option, default = "default_path()")]
+    pub path: PathBuf,
+
+    /// when set an intermediate file will be created that provides more information
+    /// about collected data.
+    #[argh(option, default = "false")]
+    pub debug: bool,
+
+    /// file path where the intermediate file will be written to
+    ///
+    /// A new file is created at the given path. Errors out if the file
+    /// already exists.
+    #[argh(option)]
+    pub int_path: Option<PathBuf>,
+
+    /// size of the trace buffer which holds trace events. We need larger
+    /// buffer on a system that has faster disks or has large number of events
+    /// enabled. Defaults to TRACE_BUFFER_SIZE_KIB KiB.
+    #[argh(option, long = "trace-buffer-size")]
+    pub trace_buffer_size_kib: Option<u64>,
+
+    /// trace subsystem to use. "mem" subsystem is set by default.
+    #[argh(option, default = "Default::default()")]
+    pub tracing_subsystem: TracerType,
+
+    /// if true enables all the needed trace events. And at the end it restores
+    /// the values of those events.
+    /// If false, assumes that user has setup the needed trace events.
+    #[argh(option, default = "true")]
+    pub setup_tracing: bool,
+
+    /// if specified, works on a tracing instance (like /sys/kernel/tracing/instance/my_instance)
+    /// rather than using on shared global instance (i.e. /sys/kernel/tracing)."
+    #[argh(
+        option,
+        default = "Some(\"prefetch\".to_string())",
+        from_str_fn(parse_tracing_instance)
+    )]
+    pub tracing_instance: Option<String>,
+
+    #[cfg(target_os = "android")]
+    /// store build_finger_print to tie the pack format
+    #[argh(option, default = "default_build_finger_print_path()")]
+    pub build_fingerprint_path: PathBuf,
+}
+
+/// Type of tracing subsystem to use.
+#[derive(Deserialize, Clone, Eq, PartialEq, Debug)]
+pub enum TracerType {
+    /// mem tracing subsystem relies on when a file's in-memory page gets added to the fs cache.
+    Mem,
+}
+
+impl FromStr for TracerType {
+    type Err = Error;
+    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
+        Ok(match s.to_lowercase().as_str() {
+            "mem" => Self::Mem,
+            _ => {
+                return Err(Error::InvalidArgs {
+                    arg_name: "tracing_subsystem".to_owned(),
+                    arg_value: s.to_owned(),
+                    error: "unknown value".to_owned(),
+                })
+            }
+        })
+    }
+}
+
+impl Default for TracerType {
+    fn default() -> Self {
+        Self::Mem
+    }
+}
+
+#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
+/// Prefetch data from the recorded file.
+#[argh(subcommand, name = "replay")]
+pub struct ReplayArgs {
+    /// file path from where the records will be read
+    #[argh(option, default = "default_path()")]
+    pub path: PathBuf,
+
+    /// IO depth. Number of IO that can go in parallel.
+    #[argh(option, long = "io-depth", default = "DEFAULT_IO_DEPTH")]
+    pub io_depth: u16,
+
+    /// max number of open fds to cache
+    #[argh(option, arg_name = "max-fds", default = "DEFAULT_MAX_FDS")]
+    pub max_fds: u16,
+
+    /// if true, command exits on encountering any error.
+    ///
+    /// This defaults to false as there is not harm prefetching if we encounter
+    /// non-fatal errors.
+    #[argh(option, default = "DEFAULT_EXIT_ON_ERROR")]
+    pub exit_on_error: bool,
+
+    /// file path from where the prefetch config file will be read
+    #[argh(option, default = "PathBuf::new()")]
+    pub config_path: PathBuf,
+}
+
+/// dump records file in given format
+#[derive(Eq, PartialEq, Debug, Default, FromArgs)]
+#[argh(subcommand, name = "dump")]
+pub struct DumpArgs {
+    /// file path from where the records will be read
+    #[argh(option)]
+    pub path: PathBuf,
+    /// output format. One of json or csv.
+    /// Note: In csv format, few fields are excluded from the output.
+    #[argh(option)]
+    pub format: OutputFormat,
+}
+
+#[derive(Deserialize, Eq, PartialEq, Debug)]
+pub enum OutputFormat {
+    Json,
+    Csv,
+}
+
+impl FromStr for OutputFormat {
+    type Err = Error;
+    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
+        Ok(match s.to_lowercase().as_str() {
+            "csv" => Self::Csv,
+            "json" => Self::Json,
+            _ => {
+                return Err(Error::InvalidArgs {
+                    arg_name: "format".to_owned(),
+                    arg_value: s.to_owned(),
+                    error: "unknown value".to_owned(),
+                })
+            }
+        })
+    }
+}
+
+impl Default for OutputFormat {
+    fn default() -> Self {
+        Self::Json
+    }
+}
+
+/// Build args struct from command line arguments
+pub fn args_from_env() -> MainArgs {
+    argh::from_env()
+}
diff --git a/init/libprefetch/prefetch/src/error.rs b/init/libprefetch/prefetch/src/error.rs
new file mode 100644
index 000000000..8dd938a7e
--- /dev/null
+++ b/init/libprefetch/prefetch/src/error.rs
@@ -0,0 +1,187 @@
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
+
+use thiserror::Error;
+
+use crate::{format::FileId, InodeInfo};
+
+/// Enumerates all possible errors returned by this library.
+#[derive(Debug, Error)]
+pub enum Error {
+    /// Represents a failure to open a file.
+    #[error("Open error: {path}: {source}")]
+    Open {
+        /// The IO error
+        source: std::io::Error,
+        /// Path on which the operation failed.
+        path: String,
+    },
+
+    /// Represents a failure to create a file.
+    #[error("Create error. {path} {source}")]
+    Create {
+        /// The IO error
+        source: std::io::Error,
+        /// Path on which the operation failed.
+        path: String,
+    },
+
+    /// Represents a failure to read trace file.
+    #[error("Read error. {error}")]
+    Read {
+        /// Detailed error message.
+        error: String,
+    },
+
+    /// Represents a failure to write to a file.
+    #[error("Write error. {source}")]
+    Write {
+        /// The IO error
+        source: std::io::Error,
+
+        /// file path
+        path: String,
+    },
+
+    /// Represents a failure to delete a file.
+    #[error("Delete error. {path} {source}")]
+    Delete {
+        /// The IO error
+        source: std::io::Error,
+        /// Path on which the operation failed.
+        path: String,
+    },
+
+    /// Represents a failure to stat a file.
+    #[error("Stat error. {path} {source}")]
+    Stat {
+        /// The IO error
+        source: std::io::Error,
+        /// Path on which the operation failed.
+        path: String,
+    },
+
+    /// Represents a failure to stat a file.
+    #[error("clone failed. {id} {source}")]
+    FileClone {
+        /// The IO error
+        source: std::io::Error,
+        /// File id for which we could not clone the file.
+        id: FileId,
+    },
+
+    /// Represents a failure to mmap a file.
+    #[error("mmap failed. {path} {error}")]
+    Mmap {
+        /// Detailed error message.
+        error: String,
+        /// Path on which the operation failed.
+        path: String,
+    },
+
+    /// Represents a failure to munmap a file.
+    #[error("munmap failed. {length} {error}")]
+    Munmap {
+        /// Detailed error message.
+        error: String,
+        /// Size of file which this munmap failed
+        length: usize,
+    },
+
+    /// Represents all other cases of `std::io::Error`.
+    ///
+    #[error(transparent)]
+    IoError(
+        /// The IO error
+        #[from]
+        std::io::Error,
+    ),
+
+    /// Represents a failure to map FileId to path
+    ///
+    #[error("Failed to map id to path: {id}")]
+    IdNoFound {
+        /// File id for which path lookup failed.
+        id: FileId,
+    },
+
+    /// Indicates that the file is skipped for prefetching
+    /// because it is in the exclude files list.
+    ///
+    #[error("Skipped prefetching file from path: {path}")]
+    SkipPrefetch {
+        /// Path to file for which prefetching is skipped.
+        path: String,
+    },
+
+    /// Represents spurious InodeInfo or missing Record.
+    ///
+    #[error(
+        "Stale inode(s) info found.\n\
+            missing_file_ids: {missing_file_ids:#?}\n\
+            stale_inodes: {stale_inodes:#?} \n\
+            missing_paths:{missing_paths:#?}"
+    )]
+    StaleInode {
+        /// FileIds for which InodeInfo is missing.
+        missing_file_ids: Vec<FileId>,
+
+        /// InodeInfos for which no records exist.
+        stale_inodes: Vec<InodeInfo>,
+
+        /// InodeInfos in which no paths were found.
+        missing_paths: Vec<InodeInfo>,
+    },
+
+    /// Represents a failure to serialize records file.
+    #[error("Serialize error: {error}")]
+    Serialize {
+        /// Detailed error message.
+        error: String,
+    },
+
+    /// Represents a failure to deserialize records file.
+    #[error("Deserialize error: {error}")]
+    Deserialize {
+        /// Detailed error message.
+        error: String,
+    },
+
+    /// Represents a failure from thread pool.
+    #[error("Thread pool error: {error}")]
+    ThreadPool {
+        /// Detailed error message.
+        error: String,
+    },
+
+    /// Represents a failure to setup file.
+    #[error("Failed to setup prefetch: {error}")]
+    Custom {
+        /// Detailed error message.
+        error: String,
+    },
+
+    /// Represents a failure to parse args.
+    #[error("Failed to parse arg:{arg_name} value:{arg_value} error:{error}")]
+    InvalidArgs {
+        /// Arg name.
+        arg_name: String,
+
+        /// Arg value.
+        arg_value: String,
+
+        /// Detailed error message.
+        error: String,
+    },
+}
diff --git a/init/libprefetch/prefetch/src/format.rs b/init/libprefetch/prefetch/src/format.rs
new file mode 100644
index 000000000..ac89a74eb
--- /dev/null
+++ b/init/libprefetch/prefetch/src/format.rs
@@ -0,0 +1,823 @@
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
+
+use std::cmp::{max, min};
+use std::collections::{BTreeMap, HashMap, HashSet};
+use std::fmt;
+use std::fmt::Display;
+use std::fs::{File, Metadata, OpenOptions};
+use std::hash::Hash;
+use std::io::Write;
+use std::ops::{Deref, DerefMut};
+use std::os::unix::fs::MetadataExt;
+use std::time::SystemTime;
+
+use crc32fast::Hasher;
+use log::debug;
+use regex::Regex;
+use serde::Deserializer;
+use serde::Serialize;
+use serde::{Deserialize, Serializer};
+
+use crate::error::Error;
+
+static MAGIC_UUID: [u8; 16] = [
+    0x10, 0x54, 0x3c, 0xb8, 0x60, 0xdb, 0x49, 0x45, 0xa1, 0xd5, 0xde, 0xa7, 0xd2, 0x3b, 0x05, 0x49,
+];
+static MAJOR_VERSION: u16 = 0;
+static MINOR_VERSION: u16 = 1;
+
+/// Represents inode number which is unique within a filesystem.
+pub(crate) type InodeNumber = u64;
+
+/// Represents device number which is unique for given block device.
+pub(crate) type DeviceNumber = u64;
+
+/// Convenience name for string that represents a path.
+pub(crate) type PathString = String;
+
+/// Represents unique file id across filesystems.
+#[derive(Clone, Debug, Deserialize, Eq, Hash, Default, PartialEq, PartialOrd, Ord, Serialize)]
+pub struct FileId(pub u64);
+
+impl Display for FileId {
+    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+        self.0.fmt(f)
+    }
+}
+
+fn serialize_hashmap<S, K: Ord + Serialize + Clone, V: Serialize + Clone>(
+    value: &HashMap<K, V>,
+    serializer: S,
+) -> Result<S::Ok, S::Error>
+where
+    S: Serializer,
+{
+    let mut btree = BTreeMap::new();
+    for (k, v) in value {
+        btree.insert(k.clone(), v.clone());
+    }
+    btree.serialize(serializer)
+}
+
+#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
+pub(crate) struct SerializableHashMap<
+    K: Ord + Serialize + Clone + Hash + PartialEq,
+    V: Serialize + Clone,
+> {
+    #[serde(serialize_with = "serialize_hashmap")]
+    pub map: HashMap<K, V>,
+}
+
+impl<K, V> Deref for SerializableHashMap<K, V>
+where
+    K: Ord + Serialize + Clone + Hash + PartialEq,
+    V: Serialize + Clone,
+{
+    type Target = HashMap<K, V>;
+    fn deref(&self) -> &Self::Target {
+        &self.map
+    }
+}
+
+impl<K, V> DerefMut for SerializableHashMap<K, V>
+where
+    K: Ord + Serialize + Clone + Hash + PartialEq,
+    V: Serialize + Clone,
+{
+    fn deref_mut(&mut self) -> &mut Self::Target {
+        &mut self.map
+    }
+}
+
+/// The InodeInfo is unique per (device, inode) combination. It is
+/// used to verify that we are prefetching a file for which we generated
+/// the records for.
+/// `Record` refers to this information with a unique `FileId`.
+#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
+pub struct InodeInfo {
+    // Inode number of the file.
+    pub(crate) inode_number: InodeNumber,
+
+    // File size in bytes.
+    pub(crate) file_size: u64,
+
+    // Helps to get to a file from a Record. The field is used to get to the file
+    // that needs to be prefetched.
+    //
+    // This struct is built by getting data from trace lines and querying filesystem
+    // for other fields about the file/inode.
+    //
+    // One instance per file to be prefetched. A file/inode can have multiple paths.
+    // We store multiple paths so that we can still get to it if some of the
+    // paths get deleted.
+    //
+    // See comments for `Record`.
+    #[serde(deserialize_with = "check_inode_info_paths")]
+    pub(crate) paths: Vec<PathString>,
+
+    // Block device number on which the file is located.
+    pub(crate) device_number: DeviceNumber,
+}
+
+impl InodeInfo {
+    /// Returns InodeInfo.
+    pub fn new(
+        inode_number: InodeNumber,
+        file_size: u64,
+        paths: Vec<String>,
+        device_number: DeviceNumber,
+    ) -> Self {
+        Self { inode_number, file_size, paths, device_number }
+    }
+}
+
+// Helps us check block alignment.
+//
+// A records file can have multiple FsInfos.
+#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
+pub struct FsInfo {
+    // This is filesystem block size and is not underlying device's block size
+    pub(crate) block_size: u64,
+}
+
+/// Prefetch record.
+/// Each record translates to one filesystem `read()` request.
+///
+/// Tracer builds `Record` by parsing trace lines or by querying filesystem.
+///
+/// Multiple `Record`s can belong to a single InodeInfo. For example if there were two
+/// reads for file `/data/my.apk` which is assigned FileId 10 at offsets 0 and 8k of length
+/// 1 byte each then we will have two `Records` in `RecordsFile` that look like
+/// `Record {file_id: 10, offset: 0, length: 1, timestamp: t1}`
+/// `Record {file_id: 10, offset: 8192, length: 1, timestamp: t2}`
+#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
+pub struct Record {
+    /// Points to the file that should be fetched./ file_id is unique per `InodeInfo`
+    /// in a `RecordsFile`
+    pub file_id: FileId,
+
+    /// start offset to fetch data from. This is FsInfo.block_size aligned.
+    pub offset: u64,
+
+    /// length of the read. This is generally rounded up to Fs.Info.block_size
+    /// except when the rounding up crosses `InodeInfo.file_size`
+    pub length: u64,
+
+    /// Timestamp in nanoseconds since the start when the data was loaded.
+    pub timestamp: u64,
+}
+
+impl Record {
+    /// Returns a new record if two records belong to same file and overlap.
+    fn overlaps(&self, other: &Self) -> Option<Self> {
+        if self.file_id == other.file_id {
+            let self_start = self.offset;
+            let self_end = self.offset + self.length;
+            let other_start = other.offset;
+            let other_end = other.offset + other.length;
+
+            if (self_start <= other_end) && (self_end >= other_start) {
+                let offset = min(self_start, other_start);
+                let length = max(self_end, other_end) - offset;
+                return Some(Self {
+                    file_id: self.file_id.clone(),
+                    offset,
+                    length,
+                    timestamp: min(self.timestamp, other.timestamp),
+                });
+            }
+        }
+        None
+    }
+}
+
+fn group_record_by_file_id(records: Vec<Record>) -> Vec<Record> {
+    let mut map: HashMap<FileId, BTreeMap<u64, Record>> = HashMap::new();
+
+    for record in &records {
+        let recs = map.entry(record.file_id.clone()).or_default();
+        recs.entry(record.offset).or_insert_with(|| record.clone());
+    }
+
+    let mut grouped = vec![];
+    for record in &records {
+        if let Some(inode) = map.get(&record.file_id) {
+            for rec in inode.values() {
+                grouped.push(rec.clone());
+            }
+        }
+        let _ = map.remove(&record.file_id);
+    }
+
+    grouped
+}
+
+/// When records are coalesced, because their file ids match and IO offsets overlap, the least
+/// timestamp of the coalesced records is retained.
+pub(crate) fn coalesce_records(records: Vec<Record>, group_by_file_id: bool) -> Vec<Record> {
+    let records = if group_by_file_id { group_record_by_file_id(records) } else { records };
+
+    let mut coalesced = vec![];
+    let mut current: Option<Record> = None;
+    for r in records {
+        current = match current {
+            None => Some(r),
+            Some(c) => {
+                let merged = c.overlaps(&r);
+                match merged {
+                    None => {
+                        coalesced.push(c);
+                        Some(r)
+                    }
+                    Some(m) => Some(m),
+                }
+            }
+        }
+    }
+    if let Some(r) = current {
+        coalesced.push(r);
+    }
+    coalesced
+}
+
+// Records file header.
+#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
+pub struct Header {
+    /// magic number as uuid to identify the header/format.
+    #[serde(deserialize_with = "check_magic")]
+    magic: [u8; 16],
+
+    // major version number.
+    #[serde(deserialize_with = "check_major_number")]
+    major_number: u16,
+
+    // minor version number.
+    #[serde(deserialize_with = "check_minor_number")]
+    minor_number: u16,
+
+    /// timestamp when the records file was generated.
+    date: SystemTime,
+
+    /// Checksum of the `RecordsFile` with `digest` being empty vector.
+    digest: u32,
+}
+
+fn check_version_number<'de, D>(
+    deserializer: D,
+    expected: u16,
+    version_type: &str,
+) -> Result<u16, D::Error>
+where
+    D: Deserializer<'de>,
+{
+    let found = u16::deserialize(deserializer)?;
+    if expected != found {
+        return Err(serde::de::Error::custom(format!(
+            "Failed to parse {} version. Expected: {} Found: {}",
+            version_type, expected, found
+        )));
+    }
+    Ok(found)
+}
+
+fn check_major_number<'de, D>(deserializer: D) -> Result<u16, D::Error>
+where
+    D: Deserializer<'de>,
+{
+    check_version_number(deserializer, MAJOR_VERSION, "major")
+}
+
+fn check_minor_number<'de, D>(deserializer: D) -> Result<u16, D::Error>
+where
+    D: Deserializer<'de>,
+{
+    check_version_number(deserializer, MINOR_VERSION, "minor")
+}
+
+fn check_magic<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
+where
+    D: Deserializer<'de>,
+{
+    let found: [u8; 16] = <[u8; 16]>::deserialize(deserializer)?;
+    if found != MAGIC_UUID {
+        return Err(serde::de::Error::custom(format!(
+            "Failed to parse magic number. Expected: {:?} Found: {:?}",
+            MAGIC_UUID, found
+        )));
+    }
+    Ok(found)
+}
+
+fn check_inode_info_paths<'de, D>(deserializer: D) -> Result<Vec<PathString>, D::Error>
+where
+    D: Deserializer<'de>,
+{
+    let parsed: Vec<PathString> = Vec::deserialize(deserializer)?;
+    if parsed.is_empty() {
+        return Err(serde::de::Error::custom("No paths found for in InodeInfo"));
+    }
+    Ok(parsed)
+}
+
+// Helper inner struct of RecordsFile meant to verify checksum.
+#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
+pub(crate) struct RecordsFileInner {
+    // One instance per mounted block device.
+    pub(crate) filesystems: SerializableHashMap<DeviceNumber, FsInfo>,
+
+    /// Helps to get to a file path from a given `FileId`.
+    /// One instance per file to be prefetched.
+    pub(crate) inode_map: SerializableHashMap<FileId, InodeInfo>,
+
+    /// Helps to get to a file and offset to be replayed..
+    ///
+    // The records are chronologically arranged meaning the data that
+    // needs first is at the beginning of the vector and the data that
+    // needs last is at the end.
+    //
+    // One instance per part of the file that needs to be prefetched.
+    pub records: Vec<Record>,
+}
+
+/// Deserialized form of records file.
+#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
+#[serde(remote = "Self")]
+pub struct RecordsFile {
+    /// Helps the prefetch tool to parse rest of the file
+    pub header: Header,
+
+    /// Helps the prefetch tool to verify checksum.
+    pub(crate) inner: RecordsFileInner,
+}
+
+impl RecordsFile {
+    /// Given file id, looks up path of the file and returns open File handle.
+    pub fn open_file(&self, id: FileId, exclude_files_regex: &[Regex]) -> Result<File, Error> {
+        if let Some(inode) = self.inner.inode_map.get(&id) {
+            let path = inode.paths.first().unwrap();
+
+            for regex in exclude_files_regex {
+                if regex.is_match(path) {
+                    return Err(Error::SkipPrefetch { path: path.to_owned() });
+                }
+            }
+            debug!("Opening {} file {}", id.0, path);
+            OpenOptions::new()
+                .read(true)
+                .write(false)
+                .open(path)
+                .map_err(|source| Error::Open { source, path: path.to_owned() })
+        } else {
+            Err(Error::IdNoFound { id })
+        }
+    }
+
+    /// Inserts given record in RecordsFile
+    pub fn insert_record(&mut self, records: Record) {
+        self.inner.records.push(records);
+    }
+
+    /// Inserts given InodeInfo into in RecordsFile.
+    pub fn insert_or_update_inode_info(&mut self, id: FileId, info: InodeInfo) {
+        if let Some(inode) = self.inner.inode_map.get_mut(&id) {
+            if let Some(first_path) = info.paths.first() {
+                inode.paths.push(first_path.clone());
+            }
+        } else {
+            self.inner.inode_map.insert(id, info);
+        }
+    }
+
+    /// Verifies the integrity of records file.
+    ///
+    /// check saves us from serializing a improperly built record file or replaying an inconsistent
+    /// `RecordFile`.
+    ///
+    /// Note: check only works on the `RecordsFile` and doesn't access filesystem. We limit the
+    /// scope so that we avoid issuing filesystem operations(directory lookup, stats) twice - once
+    /// during check and once during replaying.
+    pub fn check(&self) -> Result<(), Error> {
+        let mut unique_files = HashSet::new();
+        let mut missing_file_ids = vec![];
+
+        for record in &self.inner.records {
+            if !self.inner.inode_map.contains_key(&record.file_id) {
+                missing_file_ids.push(record.file_id.clone());
+            }
+            unique_files.insert(record.file_id.clone());
+        }
+
+        let mut stale_inodes = vec![];
+        let mut missing_paths = vec![];
+        for (file_id, inode_info) in &self.inner.inode_map.map {
+            if inode_info.paths.is_empty() {
+                missing_paths.push(inode_info.clone());
+            }
+            if !unique_files.contains(file_id) {
+                stale_inodes.push(inode_info.clone());
+            }
+        }
+
+        if !stale_inodes.is_empty() || !missing_paths.is_empty() || !missing_file_ids.is_empty() {
+            return Err(Error::StaleInode { stale_inodes, missing_paths, missing_file_ids });
+        }
+
+        Ok(())
+    }
+
+    /// Builds InodeInfo from args and inserts inode info in RecordsFile.
+    pub fn insert_or_update_inode(&mut self, id: FileId, stat: &Metadata, path: PathString) {
+        self.insert_or_update_inode_info(
+            id,
+            InodeInfo {
+                inode_number: stat.ino(),
+                file_size: stat.len(),
+                paths: vec![path],
+                device_number: stat.dev(),
+            },
+        )
+    }
+
+    /// Serialize records in the form of csv.
+    pub fn serialize_records_to_csv(&self, writer: &mut dyn Write) -> Result<(), Error> {
+        let mut wtr = csv::Writer::from_writer(writer);
+
+        #[derive(Serialize)]
+        struct TempRecord<'a> {
+            timestamp: u64,
+            file: &'a PathString,
+            offset: u64,
+            length: u64,
+            file_size: u64,
+        }
+
+        for record in &self.inner.records {
+            if let Some(inode_info) = self.inner.inode_map.get(&record.file_id) {
+                let mut inode_info = inode_info.clone();
+                inode_info.paths.sort();
+
+                if let Some(first_path) = inode_info.paths.first().cloned() {
+                    // Clone the &String inside Option
+                    let record = TempRecord {
+                        timestamp: record.timestamp,
+                        file: &first_path, // Now you have &String
+                        offset: record.offset,
+                        length: record.length,
+                        file_size: inode_info.file_size,
+                    };
+                    wtr.serialize(&record)
+                        .map_err(|e| Error::Serialize { error: e.to_string() })?;
+                }
+            }
+        }
+        wtr.flush()?;
+        Ok(())
+    }
+
+    fn compute_digest(&mut self) -> Result<u32, Error> {
+        self.header.digest = Default::default();
+        let serialized = serde_cbor::to_vec(self)
+            .map_err(|source| Error::Serialize { error: source.to_string() })?;
+
+        let mut hasher = Hasher::new();
+        hasher.update(&serialized);
+
+        Ok(hasher.finalize())
+    }
+
+    /// Convenience wrapper around serialize that adds checksum/digest to the file
+    /// to verify file consistency during replay/deserialize.
+    pub fn add_checksum_and_serialize(&mut self) -> Result<Vec<u8>, Error> {
+        self.header.digest = self.compute_digest()?;
+
+        serde_cbor::to_vec(self).map_err(|source| Error::Serialize { error: source.to_string() })
+    }
+}
+
+impl Default for Header {
+    fn default() -> Self {
+        Self {
+            major_number: MAJOR_VERSION,
+            minor_number: MINOR_VERSION,
+            date: SystemTime::now(),
+            digest: 0,
+            magic: MAGIC_UUID,
+        }
+    }
+}
+
+// Wrapper around deserialize to check any inconsistencies in the file format.
+impl<'de> Deserialize<'de> for RecordsFile {
+    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
+    where
+        D: Deserializer<'de>,
+    {
+        let rf = Self::deserialize(deserializer)?;
+
+        rf.check().map_err(|e| {
+            serde::de::Error::custom(format!("failed to validate records file: {}", e))
+        })?;
+
+        let mut zero_digest = rf.clone();
+        zero_digest.header.digest = 0;
+        let digest =
+            zero_digest.compute_digest().map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
+
+        if digest != rf.header.digest {
+            return Err(serde::de::Error::custom(format!(
+                "file consistency check failed. Expected: {}. Found: {}",
+                digest, rf.header.digest
+            )));
+        }
+
+        Ok(rf)
+    }
+}
+
+// Wrapper around serialize to check any inconsistencies in the file format before serializing
+impl Serialize for RecordsFile {
+    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
+    where
+        S: Serializer,
+    {
+        self.check().map(|_| self).map_err(|e| {
+            serde::ser::Error::custom(format!("failed to validate records file: {}", e))
+        })?;
+        Self::serialize(self, serializer)
+    }
+}
+
+#[cfg(test)]
+pub mod tests {
+
+    use std::assert_eq;
+
+    use super::*;
+
+    #[test]
+    fn test_major_version_mismatch() {
+        let mut rf = RecordsFile::default();
+
+        rf.header.major_number += 1;
+
+        let serialized: Result<RecordsFile, serde_cbor::Error> =
+            serde_cbor::from_slice(&serde_cbor::to_vec(&rf).unwrap());
+
+        assert_eq!(
+            serialized.unwrap_err().to_string(),
+            format!(
+                "Failed to parse major version. Expected: {} Found: {}",
+                MAJOR_VERSION,
+                MAJOR_VERSION + 1
+            )
+        );
+    }
+
+    #[test]
+    fn test_minor_version_mismatch() {
+        let mut rf = RecordsFile::default();
+
+        rf.header.minor_number += 1;
+
+        let serialized: Result<RecordsFile, serde_cbor::Error> =
+            serde_cbor::from_slice(&serde_cbor::to_vec(&rf).unwrap());
+
+        assert_eq!(
+            serialized.unwrap_err().to_string(),
+            format!(
+                "Failed to parse minor version. Expected: {} Found: {}",
+                MINOR_VERSION,
+                MINOR_VERSION + 1
+            )
+        );
+    }
+
+    #[test]
+    fn deserialize_inode_info_without_path() {
+        let inode = InodeInfo { inode_number: 1, file_size: 10, paths: vec![], device_number: 1 };
+        let serialized = serde_cbor::to_vec(&inode).unwrap();
+        let deserialized: Result<InodeInfo, serde_cbor::Error> =
+            serde_cbor::from_slice(&serialized);
+        assert_eq!(
+            deserialized.unwrap_err().to_string(),
+            "No paths found for in InodeInfo".to_owned()
+        );
+    }
+    #[test]
+    fn test_serialize_records_to_csv() {
+        let mut rf = RecordsFile::default();
+        let file_count = 4;
+        for i in 0..file_count {
+            rf.insert_or_update_inode_info(
+                FileId(i),
+                InodeInfo {
+                    inode_number: i,
+                    file_size: i * 10,
+                    paths: vec![format!("/hello/{}", i)],
+                    device_number: i + 10,
+                },
+            )
+        }
+        for i in 0..10 {
+            rf.insert_record(Record {
+                file_id: FileId(i % file_count),
+                offset: i * 3,
+                length: i + 4,
+                timestamp: i * file_count,
+            });
+        }
+
+        let mut buf = vec![];
+        rf.serialize_records_to_csv(&mut buf).unwrap();
+
+        let data = String::from_utf8(buf).unwrap();
+        assert_eq!(
+            data,
+            "timestamp,file,offset,length,file_size\n\
+            0,/hello/0,0,4,0\n\
+            4,/hello/1,3,5,10\n\
+            8,/hello/2,6,6,20\n\
+            12,/hello/3,9,7,30\n\
+            16,/hello/0,12,8,0\n\
+            20,/hello/1,15,9,10\n\
+            24,/hello/2,18,10,20\n\
+            28,/hello/3,21,11,30\n\
+            32,/hello/0,24,12,0\n\
+            36,/hello/1,27,13,10\n"
+        );
+    }
+
+    fn new_record(file: u64, offset: u64, length: u64, timestamp: u64) -> Record {
+        Record { file_id: FileId(file), offset, length, timestamp }
+    }
+
+    #[test]
+    fn test_coalesced_without_group() {
+        let non_coalescable_same_inode =
+            vec![new_record(1, 2, 3, 4), new_record(1, 6, 3, 5), new_record(1, 10, 3, 6)];
+        assert_eq!(
+            coalesce_records(non_coalescable_same_inode.clone(), false),
+            non_coalescable_same_inode
+        );
+
+        let non_coalescable_different_inode =
+            vec![new_record(1, 2, 3, 4), new_record(2, 5, 3, 5), new_record(3, 8, 3, 6)];
+        assert_eq!(
+            coalesce_records(non_coalescable_different_inode.clone(), false),
+            non_coalescable_different_inode
+        );
+
+        let some_coalesced =
+            vec![new_record(1, 2, 3, 4), new_record(1, 5, 3, 5), new_record(3, 8, 3, 6)];
+        assert_eq!(
+            coalesce_records(some_coalesced, false),
+            vec![new_record(1, 2, 6, 4), new_record(3, 8, 3, 6),]
+        );
+
+        let coalesced_into_one =
+            vec![new_record(1, 2, 3, 4), new_record(1, 5, 3, 5), new_record(1, 8, 3, 6)];
+        assert_eq!(coalesce_records(coalesced_into_one, false), vec![new_record(1, 2, 9, 4)]);
+
+        let no_grouping_or_coalescing =
+            vec![new_record(1, 2, 3, 4), new_record(3, 8, 3, 5), new_record(1, 5, 3, 6)];
+        assert_eq!(
+            coalesce_records(no_grouping_or_coalescing, false),
+            vec![new_record(1, 2, 3, 4), new_record(3, 8, 3, 5), new_record(1, 5, 3, 6),]
+        );
+    }
+
+    #[test]
+    fn test_coalesced_with_grouping() {
+        let non_coalescable_same_inode =
+            vec![new_record(1, 2, 3, 4), new_record(1, 6, 3, 5), new_record(1, 10, 3, 6)];
+        assert_eq!(
+            coalesce_records(non_coalescable_same_inode.clone(), true),
+            non_coalescable_same_inode
+        );
+
+        let non_coalescable_different_inode =
+            vec![new_record(1, 2, 3, 4), new_record(2, 5, 3, 5), new_record(3, 8, 3, 6)];
+        assert_eq!(
+            coalesce_records(non_coalescable_different_inode.clone(), true),
+            non_coalescable_different_inode
+        );
+
+        let some_coalesced =
+            vec![new_record(1, 2, 3, 4), new_record(1, 5, 3, 5), new_record(3, 8, 3, 6)];
+        assert_eq!(
+            coalesce_records(some_coalesced, true),
+            vec![new_record(1, 2, 6, 4), new_record(3, 8, 3, 6),]
+        );
+
+        let coalesced_into_one =
+            vec![new_record(1, 2, 3, 4), new_record(1, 5, 3, 5), new_record(1, 8, 3, 6)];
+        assert_eq!(coalesce_records(coalesced_into_one, true), vec![new_record(1, 2, 9, 4)]);
+
+        let some_grouped_coalesced =
+            vec![new_record(1, 2, 3, 4), new_record(3, 8, 3, 5), new_record(1, 5, 3, 6)];
+        assert_eq!(
+            coalesce_records(some_grouped_coalesced, true),
+            vec![new_record(1, 2, 6, 4), new_record(3, 8, 3, 5),]
+        );
+    }
+
+    #[test]
+    fn check_missing_records() {
+        let mut rf = RecordsFile::default();
+        rf.inner.inode_map.insert(
+            FileId(0),
+            InodeInfo {
+                inode_number: 0,
+                file_size: 1,
+                paths: vec!["hello".to_owned()],
+                device_number: 2,
+            },
+        );
+        rf.insert_record(Record { file_id: FileId(0), offset: 10, length: 20, timestamp: 30 });
+
+        rf.inner.inode_map.insert(
+            FileId(1),
+            InodeInfo {
+                inode_number: 1,
+                file_size: 2,
+                paths: vec!["world".to_owned()],
+                device_number: 3,
+            },
+        );
+        let e = rf.check().unwrap_err();
+        assert_eq!(
+            e.to_string(),
+            "Stale inode(s) info found.\n\
+                missing_file_ids: []\n\
+                stale_inodes: [\n    \
+                    InodeInfo {\n        \
+                        inode_number: 1,\n        \
+                        file_size: 2,\n        \
+                        paths: [\n            \"world\",\n        ],\n        \
+                        device_number: 3,\n    },\n] \n\
+                missing_paths:[]"
+        );
+    }
+
+    #[test]
+    fn check_missing_file() {
+        let mut rf = RecordsFile::default();
+        rf.inner.inode_map.insert(
+            FileId(0),
+            InodeInfo {
+                inode_number: 0,
+                file_size: 1,
+                paths: vec!["hello".to_owned()],
+                device_number: 2,
+            },
+        );
+        rf.insert_record(Record { file_id: FileId(0), offset: 10, length: 20, timestamp: 30 });
+        rf.insert_record(Record { file_id: FileId(1), offset: 10, length: 20, timestamp: 30 });
+
+        let e = rf.check().unwrap_err();
+        assert_eq!(
+            e.to_string(),
+            "Stale inode(s) info found.\n\
+                missing_file_ids: [\n    \
+                    FileId(\n        1,\n    ),\n]\n\
+                stale_inodes: [] \n\
+                missing_paths:[]"
+        );
+    }
+
+    #[test]
+    fn check_missing_paths() {
+        let mut rf = RecordsFile::default();
+        rf.inner.inode_map.insert(
+            FileId(0),
+            InodeInfo { inode_number: 0, file_size: 1, paths: vec![], device_number: 2 },
+        );
+        rf.insert_record(Record { file_id: FileId(0), offset: 10, length: 20, timestamp: 30 });
+
+        let e = rf.check().unwrap_err();
+        assert_eq!(
+            e.to_string(),
+            "Stale inode(s) info found.\n\
+                missing_file_ids: []\n\
+                stale_inodes: [] \n\
+                missing_paths:[\n    \
+                    InodeInfo {\n        \
+                        inode_number: 0,\n        \
+                        file_size: 1,\n        \
+                        paths: [],\n        \
+                        device_number: 2,\n    },\n]"
+        );
+    }
+}
diff --git a/init/libprefetch/prefetch/src/lib.rs b/init/libprefetch/prefetch/src/lib.rs
new file mode 100644
index 000000000..6564c4bc6
--- /dev/null
+++ b/init/libprefetch/prefetch/src/lib.rs
@@ -0,0 +1,180 @@
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
+
+//! A library to prefetch files on the file system to optimize startup times
+//!
+
+mod args;
+mod error;
+mod format;
+mod replay;
+mod tracer;
+#[cfg(target_os = "android")]
+mod arch {
+    pub mod android;
+}
+
+use std::fs::File;
+use std::fs::OpenOptions;
+use std::io;
+use std::io::Write;
+use std::os::unix::fs::PermissionsExt;
+use std::string::ToString;
+use std::thread;
+use std::time::Duration;
+
+#[cfg(target_os = "android")]
+use log::Level;
+#[cfg(target_os = "linux")]
+use log::LevelFilter;
+
+pub use args::args_from_env;
+use args::OutputFormat;
+pub use args::ReplayArgs;
+#[cfg(target_os = "android")]
+pub use args::StartArgs;
+pub use args::{DumpArgs, MainArgs, RecordArgs, SubCommands};
+pub use error::Error;
+pub use format::FileId;
+pub use format::InodeInfo;
+pub use format::Record;
+pub use format::RecordsFile;
+use log::info;
+pub use replay::Replay;
+pub use tracer::nanoseconds_since_boot;
+
+#[cfg(target_os = "android")]
+pub use arch::android::*;
+
+/// Records prefetch data for the given configuration
+pub fn record(args: &RecordArgs) -> Result<(), Error> {
+    let (mut tracer, exit_tx) = tracer::Tracer::create(
+        args.trace_buffer_size_kib,
+        args.tracing_subsystem.clone(),
+        args.tracing_instance.clone(),
+        args.setup_tracing,
+    )?;
+    let duration = Duration::from_secs(args.duration as u64);
+
+    let thd = thread::spawn(move || {
+        if !duration.is_zero() {
+            info!("Record start - waiting for duration: {:?}", duration);
+            thread::sleep(duration);
+        } else {
+            #[cfg(target_os = "android")]
+            wait_for_record_stop();
+        }
+
+        info!("Prefetch record exiting");
+        // We want to unwrap here on failure to send this signal. Otherwise
+        // tracer will continue generating huge records data.
+        exit_tx.send(()).unwrap();
+    });
+
+    let mut rf = tracer.trace(args.int_path.as_ref())?;
+    thd.join()
+        .map_err(|_| Error::ThreadPool { error: "Failed to join timeout thread".to_string() })?;
+
+    let mut out_file =
+        OpenOptions::new().write(true).create(true).truncate(true).open(&args.path).map_err(
+            |source| Error::Create { source, path: args.path.to_str().unwrap().to_owned() },
+        )?;
+
+    std::fs::set_permissions(&args.path, std::fs::Permissions::from_mode(0o644))
+        .map_err(|source| Error::Create { source, path: args.path.to_str().unwrap().to_owned() })?;
+
+    // Write the record file
+    out_file
+        .write_all(&rf.add_checksum_and_serialize()?)
+        .map_err(|source| Error::Write { path: args.path.to_str().unwrap().to_owned(), source })?;
+    out_file.sync_all()?;
+
+    // Write build-finger-print file
+    #[cfg(target_os = "android")]
+    write_build_fingerprint(args)?;
+
+    Ok(())
+}
+
+/// Replays prefetch data for the given configuration
+pub fn replay(args: &ReplayArgs) -> Result<(), Error> {
+    let replay = Replay::new(args)?;
+    replay.replay()
+}
+
+/// Dumps prefetch data in the human readable form
+pub fn dump(args: &DumpArgs) -> Result<(), Error> {
+    let reader = File::open(&args.path)
+        .map_err(|source| Error::Open { source, path: args.path.to_str().unwrap().to_string() })?;
+    let rf: RecordsFile =
+        serde_cbor::from_reader(reader).map_err(|e| Error::Deserialize { error: e.to_string() })?;
+    match args.format {
+        OutputFormat::Json => println!(
+            "{:#}",
+            serde_json::to_string_pretty(&rf)
+                .map_err(|e| Error::Serialize { error: e.to_string() })?
+        ),
+        OutputFormat::Csv => rf.serialize_records_to_csv(&mut io::stdout())?,
+    }
+    Ok(())
+}
+
+/// An alias of android_logger::Level to use log level across android and linux.
+#[cfg(target_os = "android")]
+pub type LogLevel = Level;
+
+/// An alias of log::LevelFilter to use log level across android and linux.
+#[cfg(not(target_os = "android"))]
+pub type LogLevel = LevelFilter;
+
+/// Convenience logging initializer that is shared between the prefetch tool and c wrapper library
+#[cfg(target_os = "android")]
+pub fn init_logging(_level: LogLevel) {
+    android_logger::init_once(
+        android_logger::Config::default().with_max_level(log::LevelFilter::Info).format(
+            |f, record| {
+                write!(
+                    f,
+                    "{} prefetch_rs: {}:{} {}: {}",
+                    nanoseconds_since_boot(),
+                    record.file().unwrap_or("unknown_file"),
+                    record.line().unwrap_or(0),
+                    record.level(),
+                    record.args()
+                )
+            },
+        ),
+    )
+}
+
+/// Convenience logging initializer that is shared between the prefetch tool and c wrapper library
+#[cfg(target_os = "linux")]
+pub fn init_logging(level: LogLevel) {
+    let mut builder = env_logger::Builder::from_default_env();
+
+    builder
+        .filter(None, level)
+        .format(|buf, record| {
+            writeln!(
+                buf,
+                "{} prefetch_rs: {}:{} {}: {}",
+                nanoseconds_since_boot(),
+                record.file().unwrap_or("unknown_file"),
+                record.line().unwrap_or(0),
+                record.level(),
+                record.args()
+            )
+        })
+        .init();
+}
diff --git a/init/libprefetch/prefetch/src/main.rs b/init/libprefetch/prefetch/src/main.rs
new file mode 100644
index 000000000..eab826f25
--- /dev/null
+++ b/init/libprefetch/prefetch/src/main.rs
@@ -0,0 +1,45 @@
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
+
+//! A utility wrapper around libprefetch that allows to record, replay and dump
+//! prefetch data.
+
+use log::error;
+
+use prefetch_rs::args_from_env;
+use prefetch_rs::dump;
+use prefetch_rs::init_logging;
+use prefetch_rs::record;
+use prefetch_rs::replay;
+#[cfg(target_os = "android")]
+use prefetch_rs::start_prefetch;
+use prefetch_rs::LogLevel;
+use prefetch_rs::MainArgs;
+use prefetch_rs::SubCommands;
+
+fn main() {
+    init_logging(LogLevel::Debug);
+    let args: MainArgs = args_from_env();
+    let ret = match &args.nested {
+        SubCommands::Record(args) => record(args),
+        SubCommands::Replay(args) => replay(args),
+        SubCommands::Dump(args) => dump(args),
+        #[cfg(target_os = "android")]
+        SubCommands::Start(args) => start_prefetch(args),
+    };
+
+    if let Err(err) = ret {
+        error!("{:?} command failed: {:?}", args, err);
+    }
+}
diff --git a/init/libprefetch/prefetch/src/replay.rs b/init/libprefetch/prefetch/src/replay.rs
new file mode 100644
index 000000000..b68d74762
--- /dev/null
+++ b/init/libprefetch/prefetch/src/replay.rs
@@ -0,0 +1,762 @@
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
+
+use std::clone::Clone;
+use std::convert::TryInto;
+use std::fmt::Display;
+use std::mem::replace;
+use std::os::unix::io::AsRawFd;
+use std::sync::Arc;
+use std::sync::Mutex;
+use std::sync::RwLock;
+use std::thread;
+
+use log::debug;
+use log::error;
+use log::warn;
+use lru_cache::LruCache;
+use nix::errno::Errno;
+use nix::fcntl::posix_fadvise;
+use regex::Regex;
+
+use crate::args::ConfigFile;
+use crate::format::Record;
+use crate::format::{FileId, RecordsFile};
+use crate::Error;
+use crate::ReplayArgs;
+use libc::{c_void, off64_t, pread64};
+use std::fs::File;
+
+const READ_SZ: usize = 1024 * 1024;
+
+struct ScopedLog<T: Display + Sized> {
+    msg: T,
+    thd_id: usize,
+}
+
+fn scoped_log<T: Display + Sized>(ctx: usize, msg: T) -> ScopedLog<T> {
+    let thd_id = ctx;
+    debug!("{} {} start", thd_id, msg);
+    ScopedLog { msg, thd_id }
+}
+
+impl<T: Display> Drop for ScopedLog<T> {
+    fn drop(&mut self) {
+        debug!("{} {} end", self.thd_id, self.msg);
+    }
+}
+
+fn readahead(
+    id: usize,
+    file: Arc<File>,
+    record: &Record,
+    buffer: &mut [u8; READ_SZ],
+) -> Result<(), Error> {
+    debug!("readahead {:?}", record);
+    let _dbg = scoped_log(id, "readahead");
+
+    let mut current_offset: off64_t = record
+        .offset
+        .try_into()
+        .map_err(|_| Error::Read { error: "Failed to convert offset".to_string() })?;
+    let mut remaining_data: usize = record
+        .length
+        .try_into()
+        .map_err(|_| Error::Read { error: "Failed to convert length".to_string() })?;
+
+    while remaining_data > 0 {
+        let read_size = std::cmp::min(READ_SZ, remaining_data);
+
+        // SAFETY: This is safe because
+        // - the file is known to exist and opened
+        // - buffer is allocated upfront and is guaranteed by the fact it comes from a mutable slice reference.
+        // - read_size is guaranteed not to exceed length of the buffer.
+        let bytes_read = unsafe {
+            pread64(file.as_raw_fd(), buffer.as_mut_ptr() as *mut c_void, read_size, current_offset)
+        };
+
+        if bytes_read == -1 {
+            return Err(Error::Read { error: format!("readahead failed: {}", Errno::last_raw()) });
+        }
+
+        if bytes_read == 0 {
+            break; // End of file reached
+        }
+
+        current_offset += bytes_read as off64_t;
+        remaining_data -= bytes_read as usize;
+    }
+
+    // TODO: Try readahead() syscall or async I/O
+    Ok(())
+}
+
+fn worker_internal(
+    id: usize,
+    state: Arc<Mutex<SharedState>>,
+    records_file: Arc<RwLock<RecordsFile>>,
+    exit_on_error: bool,
+    exclude_files_regex: Vec<Regex>,
+    buffer: &mut [u8],
+) -> Result<(), Error> {
+    loop {
+        let index = {
+            let mut state = state.lock().unwrap();
+            if state.result.is_err() {
+                return Ok(());
+            }
+            state.next_record()
+        };
+
+        let record = {
+            let rf = records_file.read().unwrap();
+            if index >= rf.inner.records.len() {
+                return Ok(());
+            }
+            rf.inner.records.get(index).unwrap().clone()
+        };
+
+        let _dbg = scoped_log(id, "record_replay");
+
+        let file = state.lock().unwrap().fds.get_mut(&record.file_id).map(|f| f.clone());
+
+        let file = match file {
+            Some(file) => file,
+            None => {
+                let file = Arc::new({
+                    let file = records_file
+                        .read()
+                        .unwrap()
+                        .open_file(record.file_id.clone(), &exclude_files_regex);
+                    if let Err(e) = file {
+                        if exit_on_error {
+                            return Err(e);
+                        } else {
+                            match e {
+                                Error::SkipPrefetch { path } => {
+                                    debug!("Skipping file during replay: {}", path);
+                                }
+                                _ => error!(
+                                    "Failed to open file id: {} with {}",
+                                    record.file_id.clone(),
+                                    e.to_string()
+                                ),
+                            }
+                            continue;
+                        }
+                    }
+
+                    let file = file.unwrap();
+                    // We do not want the filesystem be intelligent and prefetch more than what this
+                    // code is reading. So turn off prefetch.
+
+                    if let Err(e) = posix_fadvise(
+                        file.as_raw_fd(),
+                        0,
+                        0,
+                        nix::fcntl::PosixFadviseAdvice::POSIX_FADV_RANDOM,
+                    ) {
+                        warn!(
+                            "Failed to turn off filesystem read ahead for file id: {} with {}",
+                            record.file_id.clone(),
+                            e.to_string()
+                        );
+                    }
+                    file
+                });
+                let cache_file = file.clone();
+                state.lock().unwrap().fds.insert(record.file_id.clone(), cache_file);
+                file
+            }
+        };
+        if let Err(e) = readahead(id, file, &record, buffer.try_into().unwrap()) {
+            if exit_on_error {
+                return Err(e);
+            } else {
+                error!(
+                    "readahead failed on file id: {} with: {}",
+                    record.file_id.clone(),
+                    e.to_string()
+                );
+                continue;
+            }
+        }
+    }
+}
+
+fn worker(
+    id: usize,
+    state: Arc<Mutex<SharedState>>,
+    records_file: Arc<RwLock<RecordsFile>>,
+    exit_on_error: bool,
+    exclude_files_regex: Vec<Regex>,
+    buffer: &mut [u8],
+) {
+    let _dbg = scoped_log(id, "read_loop");
+    let result = worker_internal(
+        id,
+        state.clone(),
+        records_file,
+        exit_on_error,
+        exclude_files_regex,
+        buffer,
+    );
+    if result.is_err() {
+        error!("worker failed with {:?}", result);
+        let mut state = state.lock().unwrap();
+        if state.result.is_ok() {
+            state.result = result;
+        }
+    }
+}
+
+#[derive(Debug)]
+pub struct SharedState {
+    fds: LruCache<FileId, Arc<File>>,
+    records_index: usize,
+    result: Result<(), Error>,
+}
+
+impl SharedState {
+    fn next_record(&mut self) -> usize {
+        let ret = self.records_index;
+        self.records_index += 1;
+        ret
+    }
+}
+
+/// Runtime, in-memory, representation of records file structure.
+#[derive(Debug)]
+pub struct Replay {
+    records_file: Arc<RwLock<RecordsFile>>,
+    io_depth: u16,
+    exit_on_error: bool,
+    state: Arc<Mutex<SharedState>>,
+    exclude_files_regex: Vec<Regex>,
+}
+
+impl Replay {
+    /// Creates Replay from input `args`.
+    pub fn new(args: &ReplayArgs) -> Result<Self, Error> {
+        let _dbg = scoped_log(1, "new");
+        let reader: File = File::open(&args.path).map_err(|source| Error::Open {
+            source,
+            path: args.path.to_str().unwrap().to_owned(),
+        })?;
+        let rf: RecordsFile = serde_cbor::from_reader(reader)
+            .map_err(|error| Error::Deserialize { error: error.to_string() })?;
+
+        let mut exclude_files_regex: Vec<Regex> = Vec::new();
+        // The path to the configuration file is optional in the command.
+        // If the path is provided, the configuration file will be read.
+        if !&args.config_path.as_os_str().is_empty() {
+            let config_reader = File::open(&args.config_path).map_err(|source| Error::Open {
+                source,
+                path: args.path.to_str().unwrap().to_owned(),
+            })?;
+            let cf: ConfigFile = serde_json::from_reader(config_reader)
+                .map_err(|error| Error::Deserialize { error: error.to_string() })?;
+
+            for file_to_exclude in &cf.files_to_exclude_regex {
+                exclude_files_regex.push(Regex::new(file_to_exclude).unwrap());
+            }
+        }
+
+        Ok(Self {
+            records_file: Arc::new(RwLock::new(rf)),
+            io_depth: args.io_depth,
+            exit_on_error: args.exit_on_error,
+            state: Arc::new(Mutex::new(SharedState {
+                fds: LruCache::new(args.max_fds.into()),
+                records_index: 0,
+                result: Ok(()),
+            })),
+            exclude_files_regex,
+        })
+    }
+
+    /// Replay records.
+    pub fn replay(self) -> Result<(), Error> {
+        let _dbg = scoped_log(1, "replay");
+        let mut threads = vec![];
+        for i in 0..self.io_depth {
+            let i_clone = i as usize;
+            let state = self.state.clone();
+            let records_file = self.records_file.clone();
+            let exit_on_error = self.exit_on_error;
+            let exclude_files_regex = self.exclude_files_regex.clone();
+
+            let mut buffer = Box::new([0u8; READ_SZ]);
+
+            threads.push(thread::Builder::new().spawn(move || {
+                worker(
+                    i_clone,
+                    state,
+                    records_file,
+                    exit_on_error,
+                    exclude_files_regex,
+                    buffer.as_mut_slice(),
+                )
+            }));
+        }
+        for thread in threads {
+            thread.unwrap().join().unwrap();
+        }
+        replace(&mut self.state.lock().unwrap().result, Ok(()))
+    }
+}
+
+// WARNING: flaky tests.
+// In these tests we create files, invalidate their caches and then replay.
+// Verify that after reply the same portions of data is in memory.
+//
+// Since these tests to rely on presence or absence of data in cache, the
+// files used by the tests should not be in tmp filesystem. So we use relative
+// path as target directory. There is no guarantee that this target directory
+// is not on temp filesystem but chances are better than using target directory
+// in tempfs.
+//
+// Tests can be flaky if the system under tests is running low on memory. The
+// tests create file using O_DIRECT so that no data is left in file cache.
+// Though this is sufficient to avoid caching, but other processes reading these
+// files(like anti-virus) or some other system processes might change the state
+// of the cache. Or it may happen that the filesystem evicts the file before
+// we verify that read ahead worked as intended.
+#[cfg(test)]
+pub mod tests {
+    use std::{
+        assert,
+        io::Write,
+        ops::Range,
+        path::{Path, PathBuf},
+        time::Duration,
+    };
+
+    use crate::format::DeviceNumber;
+    use crate::format::FsInfo;
+    use crate::format::InodeNumber;
+    use crate::nanoseconds_since_boot;
+    use nix::sys::mman::MapFlags;
+    use nix::sys::mman::ProtFlags;
+    use serde::Deserialize;
+    use serde::Serialize;
+    use std::collections::HashMap;
+    use std::fs::OpenOptions;
+    use std::num::NonZeroUsize;
+    use std::os::fd::AsFd;
+    use std::os::unix::fs::symlink;
+    use std::os::unix::fs::MetadataExt;
+    use std::ptr::NonNull;
+    use tempfile::NamedTempFile;
+
+    use super::*;
+    use crate::tracer::{
+        page_size,
+        tests::{copy_uncached_files_and_record_from, setup_test_dir},
+    };
+
+    static MB: u64 = 1024 * 1024;
+    static KB: u64 = 1024;
+
+    fn random_write(file: &mut NamedTempFile, base: u64) -> Range<u64> {
+        let start: u64 = base + (rand::random::<u64>() % (base / 2)) as u64;
+        let len: u64 = rand::random::<u64>() % (32 * KB);
+        let buf = vec![5; len as usize];
+        nix::sys::uio::pwrite(file.as_fd(), &buf, start as i64).unwrap();
+        start..(start + len)
+    }
+
+    pub(crate) fn create_file(
+        path: Option<&Path>,
+        align: Option<u64>,
+    ) -> (NamedTempFile, Vec<Range<u64>>) {
+        let mut file = if let Some(path) = path {
+            NamedTempFile::new_in(path).unwrap()
+        } else {
+            NamedTempFile::new().unwrap()
+        };
+        let range1 = random_write(&mut file, 32 * KB);
+        let range2 = random_write(&mut file, 128 * KB);
+        let range3 = random_write(&mut file, 4 * MB);
+        if let Some(align) = align {
+            let orig_size = file.metadata().unwrap().len();
+            let aligned_size = orig_size + (align - (orig_size % align));
+            file.set_len(aligned_size).unwrap();
+        }
+        (file, vec![range1, range2, range3])
+    }
+
+    pub(crate) fn generate_cached_files_and_record(
+        path: Option<&Path>,
+        create_symlink: bool,
+        align: Option<u64>,
+    ) -> (RecordsFile, Vec<(NamedTempFile, Vec<Range<u64>>)>) {
+        let file1 = create_file(path, align);
+        let file2 = create_file(path, align);
+        let file3 = create_file(path, align);
+
+        let mut f: RecordsFileBuilder = Default::default();
+        f.add_file(file1.0.path().to_str().unwrap());
+        f.add_file(file2.0.path().to_str().unwrap());
+        f.add_file(file3.0.path().to_str().unwrap());
+        if create_symlink {
+            let symlink_path = format!("{}-symlink", file1.0.path().to_str().unwrap());
+            symlink(file1.0.path().file_name().unwrap(), &symlink_path).unwrap();
+
+            f.add_file(&symlink_path);
+        }
+        let rf = f.build().unwrap();
+        (rf, vec![file1, file2, file3])
+    }
+
+    /// RecordsFileBuilder is primarily used for testing purpose. This
+    /// is a thin wrapper around "Record". This gives the ability
+    /// to test Records functionality. The flow of this test is as follows:
+    ///
+    /// 1: generate_cached_files_and_record -> This will create temporary files of different length
+    /// and builds the "RecordFile" format.
+    /// 2: For each of the file path create, a "RecordsFile" is generated.
+    ///    a: mmap the file based on the length.
+    ///    b: call mincore() to get the residency of pages in memory for the given
+    ///    length.
+    ///    c: Iterate over the buffer of pages returned by mincore(). If a page
+    ///    is not resident in RAM, construct the "Record" structure.
+    /// 3: build() function will finally return a constructed Prefetch Record which
+    /// contains all the "Record" structure required for "Replay".
+    #[derive(Debug, Default, Deserialize, Serialize)]
+    pub struct RecordsFileBuilder {
+        // Temporarily holds paths of all files opened by other processes.
+        pub(crate) paths: HashMap<String, FileId>,
+
+        // Read inode numbers
+        inode_numbers: HashMap<(DeviceNumber, InodeNumber), FileId>,
+    }
+
+    impl RecordsFileBuilder {
+        pub fn add_file(&mut self, path: &str) {
+            if self.paths.contains_key(path) {
+                return;
+            }
+
+            self.paths.insert(path.to_owned(), FileId(self.paths.len() as u64));
+        }
+
+        pub fn build(&mut self) -> Result<RecordsFile, Error> {
+            let mut rf = RecordsFile::default();
+            for (path, mut id) in self.paths.drain() {
+                let stat = Path::new(&path)
+                    .metadata()
+                    .map_err(|source| Error::Stat { source, path: path.clone() })?;
+
+                rf.inner
+                    .filesystems
+                    .entry(stat.dev())
+                    .or_insert(FsInfo { block_size: stat.blksize() });
+
+                if let Some(orig_id) = self.inode_numbers.get(&(stat.dev(), stat.ino())) {
+                    let inode = rf.inner.inode_map.get_mut(orig_id).unwrap();
+                    inode.paths.push(path.clone());
+
+                    // There may be multiple paths for the file so from those path we may have multiple
+                    // ids. Override the id.
+                    id = orig_id.clone();
+                } else {
+                    self.inode_numbers.insert((stat.dev(), stat.ino()), id.clone());
+                    rf.insert_or_update_inode(id.clone(), &stat, path.clone());
+                }
+                if let Some(mmap) = Mmap::create(&path, id)? {
+                    mmap.get_records(&mut rf.inner.records)?;
+                }
+            }
+            Ok(rf)
+        }
+    }
+
+    #[derive(Debug)]
+    pub(crate) struct Mmap {
+        map_addr: *mut c_void,
+        length: usize,
+        #[allow(dead_code)]
+        file: File,
+        file_id: FileId,
+    }
+
+    impl Mmap {
+        pub fn create(path: &str, file_id: FileId) -> Result<Option<Self>, Error> {
+            let file = OpenOptions::new()
+                .read(true)
+                .write(false)
+                .open(path)
+                .map_err(|source| Error::Open { source, path: path.to_owned() })?;
+
+            let length = file
+                .metadata()
+                .map_err(|source| Error::Stat { source, path: path.to_owned() })?
+                .len() as usize;
+
+            if length == 0 {
+                return Ok(None);
+            }
+
+            // SAFETY: This is safe because
+            // - the length is checked for zero
+            // - offset is set to 0
+            let map_addr = unsafe {
+                nix::sys::mman::mmap(
+                    None,
+                    NonZeroUsize::new(length).unwrap(),
+                    ProtFlags::PROT_READ,
+                    MapFlags::MAP_SHARED,
+                    file.as_fd(),
+                    0,
+                )
+                .map_err(|source| Error::Mmap {
+                    error: source.to_string(),
+                    path: path.to_owned(),
+                })?
+            };
+
+            Ok(Some(Self { map_addr: map_addr.as_ptr(), length, file, file_id }))
+        }
+
+        /// Construct the "Record" file based on pages resident in RAM.
+        pub(crate) fn get_records(&self, records: &mut Vec<Record>) -> Result<(), Error> {
+            let page_size = page_size()?;
+            let page_count = (self.length + page_size - 1) / page_size;
+            let mut buf: Vec<u8> = vec![0_u8; page_count];
+            // SAFETY: This is safe because
+            // - the file is mapped
+            // - buf points to a valid and sufficiently large memory region with the
+            //   requirement of (length+PAGE_SIZE-1) / PAGE_SIZE bytes
+            let ret = unsafe { libc::mincore(self.map_addr, self.length, buf.as_mut_ptr()) };
+            if ret < 0 {
+                return Err(Error::Custom {
+                    error: format!("failed to query resident pages: {}", Errno::last_raw()),
+                });
+            }
+            let mut i = 0;
+
+            let mut offset_length: Option<(u64, u64)> = None;
+            for (index, resident) in buf.iter().enumerate() {
+                if *resident != 0 {
+                    if let Some((_, length)) = &mut offset_length {
+                        *length += page_size as u64;
+                    } else {
+                        offset_length = Some((index as u64 * page_size as u64, page_size as u64));
+                    }
+                } else if let Some((offset, length)) = offset_length {
+                    i += 1;
+                    records.push(Record {
+                        file_id: self.file_id.clone(),
+                        offset,
+                        length,
+                        timestamp: nanoseconds_since_boot(),
+                    });
+
+                    offset_length = None;
+                }
+            }
+
+            if let Some((offset, length)) = offset_length {
+                i += 1;
+                records.push(Record {
+                    file_id: self.file_id.clone(),
+                    offset,
+                    length,
+                    timestamp: nanoseconds_since_boot(),
+                });
+            }
+            debug!("records found: {} for {:?}", i, self);
+
+            Ok(())
+        }
+    }
+
+    impl Drop for Mmap {
+        fn drop(&mut self) {
+            // SAFETY: This is safe because
+            // - addr is mapped and is multiple of page_size
+            let ret = unsafe {
+                nix::sys::mman::munmap(NonNull::new(self.map_addr).unwrap(), self.length)
+            };
+            if let Err(e) = ret {
+                error!(
+                    "failed to munmap {:p} {} with {}",
+                    self.map_addr,
+                    self.length,
+                    e.to_string()
+                );
+            }
+        }
+    }
+
+    // Please see comment above RecordsFileBuilder.
+    fn rebuild_records_file(files: &[(PathBuf, Vec<Range<u64>>)]) -> RecordsFile {
+        // Validate that caches are dropped
+        let mut f: RecordsFileBuilder = Default::default();
+        for (path, _) in files {
+            f.add_file(path.to_str().unwrap());
+        }
+        f.build().unwrap()
+    }
+
+    fn ensure_files_not_cached(files: &mut [(PathBuf, Vec<Range<u64>>)]) {
+        assert!(rebuild_records_file(files).inner.records.is_empty());
+    }
+
+    fn has_record(records: &[Record], key: &Record) -> bool {
+        for r in records {
+            if r.offset == key.offset && r.length == key.length {
+                return true;
+            }
+        }
+        false
+    }
+
+    fn compare_records(old: &[Record], new: &[Record]) {
+        for key in new {
+            if !has_record(old, key) {
+                panic!("Failed to file {:?} in {:?}", key, old);
+            }
+        }
+    }
+
+    fn create_test_config_file(files_to_exclude_regex: Vec<String>) -> String {
+        let cfg = ConfigFile { files_to_exclude_regex, ..Default::default() };
+        serde_json::to_string(&cfg).unwrap()
+    }
+
+    // TODO: Split this into individual tests for better readability.
+    // b/378554334
+    fn test_replay_internal(
+        create_symlink: bool,
+        exit_on_error: bool,
+        inject_error: bool,
+        exclude_all_files: bool,
+        empty_exclude_file_list: bool,
+    ) {
+        let page_size = page_size().unwrap() as u64;
+        let test_base_dir = setup_test_dir();
+        let (rf, mut files) =
+            generate_cached_files_and_record(None, create_symlink, Some(page_size));
+
+        // Here "uncached_files" emulate the files after reboot when none of those files data is in cache.
+        let (mut uncached_rf, mut uncached_files) =
+            copy_uncached_files_and_record_from(Path::new(&test_base_dir), &mut files, &rf);
+
+        // Injects error(s) in the form of invalid filename
+        if inject_error {
+            if let Some(v) = uncached_rf.inner.inode_map.values_mut().next() {
+                for path in &mut v.paths {
+                    path.push('-');
+                }
+            }
+        }
+
+        let mut file = NamedTempFile::new().unwrap();
+        file.write_all(&uncached_rf.add_checksum_and_serialize().unwrap()).unwrap();
+        let mut config_file = NamedTempFile::new().unwrap();
+
+        let mut files_to_exclude: Vec<String> = Vec::new();
+        if exclude_all_files {
+            // Exclude files from replay by adding them in config
+            for v in uncached_rf.inner.inode_map.values_mut() {
+                for path in &mut v.paths {
+                    files_to_exclude.push(path.to_string())
+                }
+            }
+        } else if empty_exclude_file_list {
+            files_to_exclude.extend(vec![]);
+        } else {
+            // Exclude file1 and file2 during replay
+            files_to_exclude.extend(vec!["file1".to_owned(), "file2".to_owned()]);
+        }
+
+        // Create a config json to exclude files during replay
+        let config_file_contents = create_test_config_file(files_to_exclude);
+        config_file.write_all(config_file_contents.as_bytes()).unwrap();
+
+        ensure_files_not_cached(&mut uncached_files);
+
+        let replay = Replay::new(&ReplayArgs {
+            path: file.path().to_owned(),
+            io_depth: 32,
+            max_fds: 128,
+            exit_on_error,
+            config_path: config_file.path().to_owned(),
+        })
+        .unwrap();
+
+        let result = replay.replay();
+        // Sleep a bit so that readaheads are complete.
+        thread::sleep(Duration::from_secs(1));
+
+        if exit_on_error && inject_error {
+            result.expect_err("Failure was expected");
+        } else if exclude_all_files {
+            let new_rf = rebuild_records_file(&uncached_files);
+            assert!(new_rf.inner.records.is_empty());
+        } else {
+            result.unwrap();
+
+            // At this point, we have prefetched data for uncached file bringing same set of
+            // data in memory as the original cached files.
+            // If we record prefetch data for new files, we should get same records files
+            // (offset and lengths) except that the file names should be different.
+            // This block verifies it.
+            // Note: `new_rf` is for uncached_files. But, [un]fortunately, those "uncached_files"
+            // are now cached after we replayed the records.
+            let new_rf = rebuild_records_file(&uncached_files);
+            assert!(!new_rf.inner.records.is_empty());
+            assert_eq!(rf.inner.inode_map.len(), new_rf.inner.inode_map.len());
+            assert_eq!(rf.inner.records.len(), new_rf.inner.records.len());
+            compare_records(&rf.inner.records, &new_rf.inner.records);
+        }
+    }
+
+    #[test]
+    fn test_replay() {
+        test_replay_internal(true, false, false, false, false);
+    }
+
+    #[test]
+    fn test_replay_strict() {
+        test_replay_internal(true, true, false, false, false);
+    }
+
+    #[test]
+    fn test_replay_no_symlink() {
+        test_replay_internal(false, false, false, false, false);
+    }
+
+    #[test]
+    fn test_replay_no_symlink_strict() {
+        test_replay_internal(false, true, false, false, false);
+    }
+
+    #[test]
+    fn test_replay_fails_on_error() {
+        test_replay_internal(true, true, true, false, false);
+    }
+
+    #[test]
+    fn test_replay_exclude_all_files() {
+        test_replay_internal(true, false, false, true, false);
+    }
+
+    #[test]
+    fn test_replay_empty_exclude_files_list() {
+        test_replay_internal(true, false, false, false, true);
+    }
+}
diff --git a/init/libprefetch/prefetch/src/tracer/mem.rs b/init/libprefetch/prefetch/src/tracer/mem.rs
new file mode 100644
index 000000000..f69ae807b
--- /dev/null
+++ b/init/libprefetch/prefetch/src/tracer/mem.rs
@@ -0,0 +1,897 @@
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
+
+//! See top level documentation for `crate::tracer`.
+
+use std::collections::hash_map::Iter;
+use std::fs::symlink_metadata;
+use std::io::{ErrorKind, Write};
+use std::iter::Iterator;
+use std::mem::take;
+use std::os::unix::fs::MetadataExt;
+use std::{
+    collections::{HashMap, HashSet},
+    fs::read_to_string,
+    option::Option,
+    path::{Path, PathBuf},
+};
+
+use log::{debug, error, info, warn};
+use regex::Regex;
+use serde::Deserialize;
+use serde::Serialize;
+use walkdir::{DirEntry, WalkDir};
+
+use crate::format::{coalesce_records, FsInfo};
+use crate::tracer::{page_size, TracerConfigs};
+use crate::{
+    format::{DeviceNumber, InodeNumber},
+    tracer::{TraceSubsystem, EXCLUDE_PATHS},
+    Error, FileId, Record, RecordsFile,
+};
+
+static MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
+
+// Trace events to enable
+// Paths are relative to trace mount point
+static TRACE_EVENTS: &[&str] =
+    &["events/filemap/mm_filemap_add_to_page_cache/enable", "tracing_on"];
+
+// Filesystem types to ignore
+static EXCLUDED_FILESYSTEM_TYPES: &[&str] = &[
+    "binder",
+    "bpf",
+    "cgroup",
+    "cgroup2",
+    "configfs",
+    "devpts",
+    "fuse", // No emulated storage
+    "fusectl",
+    "proc",
+    "pstore",
+    "selinuxfs",
+    "sysfs",
+    "tmpfs", // Check for apex mount points
+    "tracefs",
+    "functionfs", // adb, fastboot
+    "f2fs",       // Skip /data mounts
+];
+
+#[cfg(target_os = "linux")]
+type MajorMinorType = u32;
+#[cfg(target_os = "android")]
+type MajorMinorType = i32;
+
+// TODO(b/302056482): Once we uprev nix crate, we can use the function exported by the crate.
+fn major(dev: DeviceNumber) -> MajorMinorType {
+    (((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff)) as MajorMinorType
+}
+
+// TODO(b/302056482): Once we uprev nix crate, we can use the function exported by the crate.
+fn minor(dev: DeviceNumber) -> MajorMinorType {
+    (((dev >> 12) & 0xffff_ff00) | ((dev) & 0x0000_00ff)) as MajorMinorType
+}
+
+// TODO(b/302056482): Once we uprev nix crate, we can use the function exported by the crate.
+fn makedev(major: MajorMinorType, minor: MajorMinorType) -> DeviceNumber {
+    let major = major as DeviceNumber;
+    let minor = minor as DeviceNumber;
+    ((major & 0xffff_f000) << 32)
+        | ((major & 0x0000_0fff) << 8)
+        | ((minor & 0xffff_ff00) << 12)
+        | (minor & 0x0000_00ff)
+}
+
+fn build_device_number(major: &str, minor: &str) -> Result<DeviceNumber, Error> {
+    Ok(makedev(
+        major.parse::<MajorMinorType>().map_err(|e| Error::Custom {
+            error: format!("Failed to parse major number from {} with {}", major, e),
+        })?,
+        minor.parse::<MajorMinorType>().map_err(|e| Error::Custom {
+            error: format!("Failed to parse major number from {} with {}", major, e),
+        })?,
+    ))
+}
+
+// Returns timestamp in nanoseconds
+fn build_timestamp(seconds: &str, microseconds: &str) -> Result<u64, Error> {
+    let seconds = seconds.parse::<u64>().map_err(|e| Error::Custom {
+        error: format!("Failed to parse seconds from {} with {}", seconds, e),
+    })?;
+    let microseconds = microseconds.parse::<u64>().map_err(|e| Error::Custom {
+        error: format!("Failed to parse microseconds from {} with {}", seconds, e),
+    })?;
+    Ok((seconds * 1_000_000_000) + (microseconds * 1_000))
+}
+
+#[cfg(not(target_os = "android"))]
+fn is_highly_privileged_path(_path: &Path) -> bool {
+    false
+}
+
+#[cfg(target_os = "android")]
+fn is_highly_privileged_path(path: &Path) -> bool {
+    // Following directories contain a mix of files with and without access to stat/read.
+    // We do not completely exclude these directories as there is still a lot of
+    // file we can issue readahead on. Some of the files on which readahead fails include
+    // - /system/bin/run-as
+    // - /data/data/com.android.storagemanager
+    // - /system/apex/com.android.art/bin/dex2oat32
+    // - /data/user/0/com.android.systemui
+    //
+    // - TODO: /system/apex: Apex files in read-only partition may be read during boot.
+    // However, some files may not have access. Double check the record files
+    // to filter out the exact path.
+    let privileged_paths = [
+        "/data/data",
+        "/data/user/0",
+        "/data/user_de/0",
+        "/system/bin/",
+        "/system/etc/selinux/",
+        "/system/system_ext/etc/selinux/",
+        "/system/product/etc/selinux/",
+        "/system/vendor/etc/selinux/",
+        "/system_ext/etc/selinux/",
+        "/product/etc/selinux/",
+        "/vendor/etc/selinux/",
+        "/system/xbin",
+        "/system/etc/",
+        "/data/",
+        "/postinstall/",
+        "/mnt/",
+        "/metadata/",
+    ];
+    for privileged in privileged_paths {
+        if path.to_str().unwrap().starts_with(privileged) {
+            return true;
+        }
+    }
+    false
+}
+
+enum DeviceState {
+    Include((DeviceNumber, PathBuf)),
+    Exclude(DeviceNumber),
+}
+
+/// Utility struct that helps to include and exclude devices and mount points that need and don't
+/// need prefetching.
+#[derive(Debug, Deserialize, Serialize)]
+struct MountInfo {
+    // Map of device number to mount points
+    included_devices: HashMap<DeviceNumber, PathBuf>,
+
+    // Devices that we don't want to prefetch - like devices backing tempfs and sysfs
+    excluded_devices: HashSet<DeviceNumber>,
+}
+
+impl MountInfo {
+    // Parses file at `path` to build `Self`.`
+    fn create(path: &str) -> Result<Self, Error> {
+        let buf = read_to_string(path)
+            .map_err(|e| Error::Read { error: format!("Reading {} failed with: {}", path, e) })?;
+        Self::with_buf(&buf)
+    }
+
+    // Parses string in `buf` to build `Self`.
+    fn with_buf(buf: &str) -> Result<Self, Error> {
+        let regex = Self::get_regex()?;
+        let mut included_devices: HashMap<DeviceNumber, PathBuf> = HashMap::new();
+        let mut excluded_devices = HashSet::new();
+        let excluded_filesystem_types: HashSet<String> =
+            EXCLUDED_FILESYSTEM_TYPES.iter().map(|s| String::from(*s)).collect();
+        for line in buf.lines() {
+            if let Some(state) = Self::parse_line(&regex, &excluded_filesystem_types, line)? {
+                match state {
+                    DeviceState::Include((device, path)) => {
+                        included_devices.insert(device, path);
+                    }
+                    DeviceState::Exclude(device) => {
+                        excluded_devices.insert(device);
+                    }
+                }
+            }
+        }
+
+        Ok(Self { included_devices, excluded_devices })
+    }
+
+    fn parse_line(
+        re: &Regex,
+        excluded_filesystem_types: &HashSet<String>,
+        line: &str,
+    ) -> Result<Option<DeviceState>, Error> {
+        let caps = match re.captures(line) {
+            Some(caps) => caps,
+            None => {
+                return Ok(None);
+            }
+        };
+        if &caps["relative_path"] != "/" {
+            return Ok(None);
+        }
+
+        let mount_point = &caps["mount_point"];
+        let mnt_pnt_with_slash = format!("{}/", mount_point);
+        let device_number = build_device_number(&caps["major"], &caps["minor"])?;
+        let fs_type = &caps["fs_type"];
+
+        if excluded_filesystem_types.contains(fs_type) {
+            info!(
+                "excluding fs type: {} for {} mount-point {} slash {}",
+                fs_type, line, mount_point, mnt_pnt_with_slash
+            );
+            return Ok(Some(DeviceState::Exclude(device_number)));
+        }
+
+        for excluded in EXCLUDE_PATHS {
+            if mnt_pnt_with_slash.starts_with(excluded) {
+                info!(
+                    "exclude-paths fs type: {} for {} mount-point {} slash {}",
+                    fs_type, line, mount_point, mnt_pnt_with_slash
+                );
+                return Ok(Some(DeviceState::Exclude(device_number)));
+            }
+        }
+
+        Ok(Some(DeviceState::Include((device_number, PathBuf::from(mount_point)))))
+    }
+
+    fn get_regex() -> Result<Regex, Error> {
+        Regex::new(concat!(
+            r"^\s*(?P<id_unknown1>\S+)",
+            r"\s+(?P<id_unknown2>\S+)",
+            r"\s+(?P<major>[0-9]+):(?P<minor>[0-9]+)",
+            r"\s+(?P<relative_path>\S+)",
+            r"\s+(?P<mount_point>\S+)",
+            r"\s+(?P<mount_opt>\S+)",
+            r"\s+(?P<shared>\S+)",
+            r"\s+\S+",
+            r"\s+(?P<fs_type>\S+)",
+            r"\s+(?P<device_path>\S+)"
+        ))
+        .map_err(|e| Error::Custom {
+            error: format!("create regex for parsing mountinfo failed with: {}", e),
+        })
+    }
+
+    fn is_excluded(&self, device: &DeviceNumber) -> bool {
+        self.excluded_devices.contains(device)
+    }
+
+    fn get_included(&self) -> Iter<DeviceNumber, PathBuf> {
+        self.included_devices.iter()
+    }
+}
+
+#[derive(Default, PartialEq, Debug, Eq, Hash)]
+struct TraceLineInfo {
+    device: DeviceNumber,
+    inode: InodeNumber,
+    offset: u64,
+    timestamp: u64,
+}
+
+impl TraceLineInfo {
+    pub fn from_trace_line(re: &Regex, line: &str) -> Result<Option<Self>, Error> {
+        let caps = match re.captures(line) {
+            Some(caps) => caps,
+            None => return Ok(None),
+        };
+        let major = &caps["major"];
+        let minor = &caps["minor"];
+        let ino = &caps["ino"];
+        let offset = &caps["offset"];
+        let timestamp = build_timestamp(&caps["seconds"], &caps["microseconds"])?;
+        Ok(Some(TraceLineInfo {
+            device: build_device_number(major, minor)?,
+            inode: u64::from_str_radix(ino, 16).map_err(|e| Error::Custom {
+                error: format!("failed parsing inode: {} : {}", ino, e),
+            })?,
+            offset: offset.parse::<u64>().map_err(|e| Error::Custom {
+                error: format!("failed parsing offset: {} : {}", offset, e),
+            })?,
+            timestamp,
+        }))
+    }
+
+    #[cfg(test)]
+    pub fn from_fields(
+        major: MajorMinorType,
+        minor: MajorMinorType,
+        inode: u64,
+        offset: u64,
+        timestamp: u64,
+    ) -> Self {
+        Self { device: makedev(major, minor), inode, offset, timestamp }
+    }
+
+    // Convenience function to create regex. Used once per life of `record` but multiple times in
+    // case of tests.
+    pub fn get_trace_line_regex() -> Result<Regex, Error> {
+        // TODO: Fix this Regex expression for 5.15 kernels. This expression
+        // works only on 6.1+. Prior to 6.1, "<page>" was present in the output.
+        Regex::new(concat!(
+            r"^\s+(?P<cmd_pid>\S+)",
+            r"\s+(?P<cpu>\S+)",
+            r"\s+(?P<irq_stuff>\S+)",
+            r"\s+(?P<seconds>[0-9]+)\.(?P<microseconds>[0-9]+):",
+            r"\s+mm_filemap_add_to_page_cache:",
+            r"\s+dev\s+(?P<major>[0-9]+):(?P<minor>[0-9]+)",
+            r"\s+ino\s+(?P<ino>\S+)",
+            //r"\s+(?P<page>\S+)",
+            r"\s+(?P<pfn>\S+)",
+            r"\s+ofs=(?P<offset>[0-9]+)"
+        ))
+        .map_err(|e| Error::Custom {
+            error: format!("create regex for tracing failed with: {}", e),
+        })
+    }
+}
+
+#[derive(Debug, Serialize, Deserialize)]
+struct MissingFile {
+    major_no: MajorMinorType,
+    minor_no: MajorMinorType,
+    inode: InodeNumber,
+    records: Vec<Record>,
+}
+
+#[derive(Debug, Default, Deserialize, Serialize)]
+struct DebugInfo {
+    // Check all inodes for which paths don't exists. These are the files which
+    // * got deleted before we got to them
+    // * are filesystem internal files that fs access only via inode numbers.
+    missing_files: HashMap<FileId, MissingFile>,
+
+    // Number of bytes read that belongs to directory type inodes.
+    directory_read_bytes: u64,
+
+    // Number of bytes read from files for which we could not find a path in
+    // the filesystems.
+    missing_path_bytes: u64,
+
+    // Paths for which the current process doesn't have read permission.
+    privileged_paths: Vec<PathBuf>,
+}
+
+#[derive(Debug, Serialize)]
+pub(crate) struct MemTraceSubsystem {
+    device_inode_map: HashMap<DeviceNumber, HashMap<InodeNumber, FileId>>,
+    // Count of all InodeNumber held by `device_inode_map`. This is handy to assign unique
+    // FileId.
+    inode_count: u64,
+
+    // `Record`s built from parsing read trace lines.
+    records: Vec<Record>,
+
+    // Regex to parse lines from trace_pipe.
+    #[serde(skip_serializing)]
+    regex: Regex,
+
+    // Mounted devices/filesystems either at the time of parsing trace file or at the time
+    // of building RecordsFile from parsed lines.
+    mount_info: MountInfo,
+
+    // A copy of TracerConfigs
+    tracer_configs: Option<TracerConfigs>,
+
+    // system page size stored to avoid frequent syscall to get the page size.
+    page_size: u64,
+
+    // The fields of the debug_info are populated when build_records_file is called (after lines
+    // are parsed from the trace file/pipe).
+    debug_info: DebugInfo,
+}
+
+impl MemTraceSubsystem {
+    pub fn update_configs(configs: &mut TracerConfigs) {
+        for path in EXCLUDE_PATHS {
+            configs.excluded_paths.push(path.to_owned().to_string());
+        }
+
+        for event in TRACE_EVENTS {
+            configs.trace_events.push(event.to_owned().to_string());
+        }
+        configs.mountinfo_path = Some(MOUNTINFO_PATH.to_string());
+    }
+
+    pub fn create_with_configs(tracer_configs: TracerConfigs) -> Result<Self, Error> {
+        static INITIAL_RECORDS_CAPACITY: usize = 100_000;
+        debug!("TracerConfig: {:#?}", tracer_configs);
+
+        let regex = TraceLineInfo::get_trace_line_regex()?;
+        let mount_info = MountInfo::create(tracer_configs.mountinfo_path.as_ref().unwrap())?;
+        debug!("mountinfo: {:#?}", mount_info);
+
+        Ok(Self {
+            device_inode_map: HashMap::new(),
+            inode_count: 0,
+            // For one product of android, we see around 50k records. To avoid a lot allocations
+            // and copying of records, we create a vec of this size.
+            //
+            // We do this to reduces chances of losing data, however unlikely, coming over
+            // `trace_pipe`.
+            //
+            // Note: Once we are done reading trace lines, we are less pedantic about allocations
+            // and mem copies.
+            records: Vec::with_capacity(INITIAL_RECORDS_CAPACITY),
+            regex,
+            mount_info,
+            tracer_configs: Some(tracer_configs),
+            page_size: page_size()? as u64,
+            debug_info: DebugInfo {
+                missing_files: HashMap::new(),
+                directory_read_bytes: 0,
+                missing_path_bytes: 0,
+                privileged_paths: vec![],
+            },
+        })
+    }
+
+    fn new_file_id(&mut self) -> FileId {
+        let id = self.inode_count;
+        self.inode_count += 1;
+        FileId(id)
+    }
+
+    fn get_trace_info(&self, line: &str) -> Result<Option<TraceLineInfo>, Error> {
+        TraceLineInfo::from_trace_line(&self.regex, line)
+    }
+
+    // Returns true if the file or directory is on a device which is excluded from walking.
+    // If the path was excluded because the current process doesn't have privileged to read it,
+    // the path gets added to `privileged` list.
+    fn is_excluded(&self, entry: &DirEntry, device: u64, privileged: &mut Vec<PathBuf>) -> bool {
+        // We skip paths that are reside on excluded devices here. This is ok because a
+        // non-excluded mount point will have a separate entry in MountInfo. For example
+        // - `/` has ext4
+        // - `/tmp` has tempfs
+        // - `/tmp/mnt` has ext4 that we are interested in.
+        // MountInfo will have three entries - `/`, `/tmp/` and `/tmp/mnt`. Skipping walking
+        // `/tmp` while walking `/` is ok as next `mount_info.get_included()` will return
+        // `/tmp/mnt` path.
+        //
+        //
+        // We skip links here as they can refer to mount points across
+        // filesystems. If that path is valid and access are valid, then
+        // we should have entry by the file's <device, inode> pair.
+        //
+        //
+        // We skip devices that don't match current walking device because we eventually
+        // walk other devices.
+        match symlink_metadata(entry.path()) {
+            Ok(lstat) => {
+                if self.mount_info.is_excluded(&lstat.dev())
+                    || lstat.dev() != device
+                    || lstat.file_type().is_symlink()
+                {
+                    return true;
+                }
+            }
+            Err(e) => {
+                error!("stat on {} failed with {}", entry.path().to_str().unwrap(), e);
+
+                // We treat EACCES special because on some platforms, like android, process needs to
+                // have very special set of permissions to access some inodes.
+                // We ignore errors in such cases *after* making an effort to get to them.
+                if e.kind() == ErrorKind::PermissionDenied
+                    && is_highly_privileged_path(entry.path())
+                {
+                    privileged.push(entry.path().to_owned());
+                    return true;
+                }
+            }
+        }
+
+        // On error, we return false because if lstat has failed, it will fail following operations
+        // including stat.
+        false
+    }
+}
+
+impl TraceSubsystem for MemTraceSubsystem {
+    fn add_line(&mut self, line: &str) -> Result<(), Error> {
+        if let Some(info) = self.get_trace_info(line)? {
+            if self.mount_info.is_excluded(&info.device) {
+                return Ok(());
+            }
+
+            self.device_inode_map.entry(info.device).or_default();
+
+            let file_id = if let Some(id) =
+                self.device_inode_map.get_mut(&info.device).unwrap().get(&info.inode)
+            {
+                id.clone()
+            } else {
+                self.new_file_id()
+            };
+            self.device_inode_map
+                .get_mut(&info.device)
+                .unwrap()
+                .insert(info.inode, file_id.clone());
+
+            self.records.push(Record {
+                file_id,
+                offset: info.offset,
+                length: self.page_size,
+                timestamp: info.timestamp,
+            });
+        }
+
+        Ok(())
+    }
+
+    fn build_records_file(&mut self) -> Result<RecordsFile, Error> {
+        // reset debug_info in case build_records_file was called twice.
+        self.debug_info = DebugInfo::default();
+        let mut rf = RecordsFile::default();
+        let mut directories = HashSet::new();
+
+        // TODO(b/302194377): We are holding all privileged_paths in this variable and then
+        // transferring it to `self.debug_info.privileged_paths` later. We can avoid this step
+        // if we directly update `self.debug_info.privileged_paths`. To do so, we need to refactor
+        // code to make borrow not complain at several places - ex. immutably borrowing
+        // `self.mount_info` in outer loop and then mutably borrowing
+        // `self.debug_info.privileged_paths`.
+        let mut privileged_paths = vec![];
+
+        // Reload mount_info. When we created mount_info for the first time, maybe
+        // the system was in early boot phase. Reload the mount_info so as to get
+        // current/new mount points.
+        if let Some(tracer_config) = &self.tracer_configs {
+            self.mount_info = MountInfo::create(tracer_config.mountinfo_path.as_ref().unwrap())?;
+            debug!("reloaded mountinfo: {:#?}", self.mount_info);
+        }
+
+        for (device, root_path) in self.mount_info.get_included() {
+            let inode_map = if let Some(map) = self.device_inode_map.get(device) {
+                map
+            } else {
+                continue;
+            };
+
+            if inode_map.is_empty() {
+                return Err(Error::Custom {
+                    error: format!("Unexpected empty records for {:?}", root_path),
+                });
+            }
+
+            let mut block_size = 0;
+            let walker = WalkDir::new(root_path).into_iter();
+
+            for entry in
+                walker.filter_entry(|e| !self.is_excluded(e, *device, &mut privileged_paths))
+            {
+                let path = match entry {
+                    Ok(entry) => entry.path().to_owned(),
+                    Err(e) => {
+                        error!("walking directory failed: {} {}", root_path.to_str().unwrap(), e);
+                        continue;
+                    }
+                };
+
+                let stat = match path.metadata() {
+                    Ok(stat) => stat,
+                    Err(e) => {
+                        error!("stat on {} failed with {}", path.to_str().unwrap(), e);
+                        continue;
+                    }
+                };
+
+                block_size = stat.blksize();
+
+                let file_id = if let Some(id) = inode_map.get(&stat.ino()) {
+                    id.clone()
+                } else {
+                    continue;
+                };
+
+                // We cannot issue a normal readahead on directories. So we skip those records that
+                // belong to directories.
+                if stat.file_type().is_dir() {
+                    info!(
+                        "skipping directory readahead record for file_id:{file_id} ino:{} path:{} ",
+                        stat.ino(),
+                        path.to_str().unwrap()
+                    );
+                    directories.insert(file_id.clone());
+                    continue;
+                }
+
+                rf.insert_or_update_inode(file_id, &stat, path.to_str().unwrap().to_owned());
+            }
+
+            rf.inner.filesystems.insert(*device, FsInfo { block_size });
+        }
+
+        self.debug_info.privileged_paths.append(&mut privileged_paths);
+
+        for (device, inode_map) in &self.device_inode_map {
+            for (inode, file_id) in inode_map {
+                if !rf.inner.inode_map.contains_key(file_id) {
+                    let major_no: MajorMinorType = major(*device);
+                    let minor_no: MajorMinorType = minor(*device);
+                    self.debug_info.missing_files.insert(
+                        file_id.clone(),
+                        MissingFile { major_no, minor_no, inode: *inode, records: vec![] },
+                    );
+                }
+            }
+        }
+
+        // Remove all records that belong to directories or for which we did not find paths.
+        let mut records = vec![];
+        for record in take(&mut self.records) {
+            if directories.contains(&record.file_id) {
+                self.debug_info.directory_read_bytes += record.length;
+            } else if let Some(missing_file) =
+                self.debug_info.missing_files.get_mut(&record.file_id)
+            {
+                self.debug_info.missing_path_bytes += record.length;
+                missing_file.records.push(record);
+            } else {
+                records.push(record);
+            }
+        }
+
+        warn!(
+            "Recorded {} bytes worth of data read from directories",
+            self.debug_info.directory_read_bytes
+        );
+        warn!(
+            "Recorded {} bytes worth of data read from files that don't have paths",
+            self.debug_info.missing_path_bytes
+        );
+
+        rf.inner.records = coalesce_records(records, true);
+
+        Ok(rf)
+    }
+
+    fn serialize(&self, write: &mut dyn Write) -> Result<(), Error> {
+        write
+            .write_all(
+                &serde_json::to_vec(&self)
+                    .map_err(|e| Error::Serialize { error: e.to_string() })?,
+            )
+            .map_err(|source| Error::Write { path: "intermediate file".to_owned(), source })
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use nix::sys::stat::{major, minor};
+    use std::assert_eq;
+    use std::path::Path;
+
+    use crate::tracer::tests::{copy_uncached_files_and_record_from, setup_test_dir};
+
+    use crate::replay::tests::generate_cached_files_and_record;
+
+    use super::*;
+
+    static TRACE_BUFFER: &str = r#"
+ Settingide-502  [001] ....   484.360292: mm_filemap_add_to_page_CACHE: dev 254:6 ino cf1 page=68d477 pfn=59833 ofs=32768
+ Settingide-502  [001] ....   484.360311: mm_filemap_add_to_page_cache: dev 254:6 ino cf1 page=759458 pfn=59827 ofs=57344
+ BOX_ENTDED-3071 [001] ....   485.276715: mm_filemap_add_to_pag_ecache: dev 254:6 ino 1 page=00cc1c pfn=81748 ofs=13574144
+ BOX_ENTDED-3071 [001] ....   485.276990: mm_filemap_add_to_page_cache: dev 254:6 ino cf2 page=36540b pfn=60952 ofs=0
+ .gms.peent-843  [001] ....   485.545516: mm_filemap_add_to_page_cache: dev 254:6 ino 1 page=002e8b pfn=58928 ofs=13578240
+ .gms.peent-843  [001] ....   485.545820: mm_filemap_add_to_page_cache: dev 254:6 ino cf3 page=6233ce pfn=58108 ofs=0
+      an.bg-459  [001] ....   494.029396: mm_filemap_add_to_page_cache: dev 254:3 ino 7cf page=c5b5c7 pfn=373933 ofs=1310720
+      an.bg-459  [001] ....   494.029398: mm_filemap_add_to_page_cache: dev 254:3 ino 7cf page=b8b9ec pfn=410074 ofs=1314816
+       "#;
+
+    fn sample_mem_traces() -> (String, Vec<Option<TraceLineInfo>>) {
+        (
+            TRACE_BUFFER.to_owned(),
+            vec![
+                None,
+                None,
+                Some(TraceLineInfo::from_fields(254, 6, 0xcf1, 57344, 484360311000)),
+                None,
+                Some(TraceLineInfo::from_fields(254, 6, 0xcf2, 0, 485276990000)),
+                Some(TraceLineInfo::from_fields(254, 6, 0x1, 13578240, 485545516000)),
+                Some(TraceLineInfo::from_fields(254, 6, 0xcf3, 0, 485545820000)),
+                Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1310720, 494029396000)),
+                Some(TraceLineInfo::from_fields(254, 3, 0x7cf, 1314816, 494029398000)),
+                None,
+            ],
+        )
+    }
+
+    #[test]
+    fn test_parse_trace_line() {
+        let (buf, res) = sample_mem_traces();
+        let re = TraceLineInfo::get_trace_line_regex().unwrap();
+        for (index, line) in buf.lines().enumerate() {
+            let found = TraceLineInfo::from_trace_line(&re, line).unwrap();
+            let expected = res.get(index).unwrap();
+            assert_eq!(found.is_some(), expected.is_some());
+            if found.is_some() {
+                assert_eq!(found.unwrap(), *expected.as_ref().unwrap());
+            }
+        }
+    }
+
+    #[test]
+    fn test_add_line() {
+        let test_base_dir = setup_test_dir();
+        let (rf, mut files) =
+            generate_cached_files_and_record(None, true, Some(page_size().unwrap() as u64));
+        let (_uncached_rf, uncached_files) =
+            copy_uncached_files_and_record_from(Path::new(&test_base_dir), &mut files, &rf);
+        let mut mount_include = HashMap::new();
+
+        let included_dev = uncached_files.get(0).unwrap().0.metadata().unwrap().dev();
+        let included_inode1 = uncached_files.get(0).unwrap().0.metadata().unwrap().ino();
+        let included_inode2 = uncached_files.get(1).unwrap().0.metadata().unwrap().ino();
+        let included_major = major(included_dev);
+        let included_minor = minor(included_dev);
+        mount_include.insert(included_dev, std::fs::canonicalize(test_base_dir).unwrap());
+        let mut mount_exclude = HashSet::new();
+        mount_exclude.insert(0);
+
+        let mut mem_tracer = MemTraceSubsystem {
+            device_inode_map: HashMap::new(),
+            inode_count: 0,
+            records: vec![],
+            regex: TraceLineInfo::get_trace_line_regex().unwrap(),
+            mount_info: MountInfo {
+                included_devices: mount_include,
+                excluded_devices: mount_exclude,
+            },
+            tracer_configs: None,
+            page_size: page_size().unwrap() as u64,
+            debug_info: DebugInfo {
+                missing_files: HashMap::new(),
+                directory_read_bytes: 0,
+                missing_path_bytes: 0,
+                privileged_paths: vec![],
+            },
+        };
+
+        let pg_size = page_size().unwrap();
+        // Format is major, minor, inode, offset
+        let inputs = vec![
+            (0, 0, 2, 10), // to be excluded. bad device.
+            (included_major, included_minor, included_inode1, 0),
+            (included_major, included_minor, included_inode1, 3 * pg_size),
+            // duplicate read
+            (included_major, included_minor, included_inode1, 3 * pg_size),
+            (0, 0, included_inode1, 10), // to be excluded. bad device.
+            (included_major, included_minor, included_inode1, 2 * pg_size), // contiguous
+            // non-contiguous
+            (included_major, included_minor, included_inode1, 12 * pg_size),
+            // same offset different inode
+            (included_major, included_minor, included_inode2, 3 * pg_size),
+            // Contiguous offset different inode
+            (included_major, included_minor, included_inode2, pg_size),
+        ];
+
+        for (i, (major, minor, inode, offset)) in inputs.iter().enumerate() {
+            // used to timestamp the log line.
+            let seconds = i;
+            // used to timestamp the log line.
+            let microseconds = i;
+            for operation in &["mm_filemap_add_to_page_cache", "some_other_operation"] {
+                let line = format!(
+                    " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: \
+                    dev {}:{} ino {:x} page=00000000f936540b pfn=60952 ofs={}",
+                    seconds, microseconds, operation, major, minor, inode, offset
+                );
+                mem_tracer.add_line(&line).unwrap();
+            }
+        }
+        assert_eq!(mem_tracer.records.len(), 7);
+        assert_eq!(mem_tracer.device_inode_map.len(), 1);
+        assert_eq!(mem_tracer.device_inode_map.get(&included_dev).unwrap().len(), 2);
+        assert!(mem_tracer
+            .device_inode_map
+            .get(&included_dev)
+            .unwrap()
+            .contains_key(&included_inode1));
+        assert!(mem_tracer
+            .device_inode_map
+            .get(&included_dev)
+            .unwrap()
+            .contains_key(&included_inode2));
+    }
+
+    fn new_record(file: u64, offset: u64, length: u64, timestamp: u64) -> Record {
+        Record { file_id: FileId(file), offset, length, timestamp }
+    }
+
+    #[test]
+    fn test_get_records_file() {
+        let test_base_dir = setup_test_dir();
+        let (rf, mut files) =
+            generate_cached_files_and_record(None, true, Some(page_size().unwrap() as u64));
+        let (_uncached_rf, uncached_files) =
+            copy_uncached_files_and_record_from(Path::new(&test_base_dir), &mut files, &rf);
+        let mut mount_include = HashMap::new();
+
+        let included_dev = uncached_files.get(0).unwrap().0.metadata().unwrap().dev();
+        let included_inode1 = uncached_files.get(0).unwrap().0.metadata().unwrap().ino();
+        let included_inode2 = uncached_files.get(1).unwrap().0.metadata().unwrap().ino();
+        let included_major = major(included_dev);
+        let included_minor = minor(included_dev);
+        mount_include.insert(included_dev, std::fs::canonicalize(test_base_dir).unwrap());
+        let mut mount_exclude = HashSet::new();
+        mount_exclude.insert(0);
+
+        let mut mem_tracer = MemTraceSubsystem {
+            device_inode_map: HashMap::new(),
+            inode_count: 0,
+            records: vec![],
+            regex: TraceLineInfo::get_trace_line_regex().unwrap(),
+            mount_info: MountInfo {
+                included_devices: mount_include,
+                excluded_devices: mount_exclude,
+            },
+            tracer_configs: None,
+            page_size: page_size().unwrap() as u64,
+            debug_info: DebugInfo {
+                missing_files: HashMap::new(),
+                directory_read_bytes: 0,
+                missing_path_bytes: 0,
+                privileged_paths: vec![],
+            },
+        };
+
+        let pg_size = page_size().unwrap() as u64;
+        // Format is major, minor, inode, offset
+        let inputs = vec![
+            (0, 0, 2, 10), // to be excluded. bad device.
+            (included_major, included_minor, included_inode1, 0),
+            (included_major, included_minor, included_inode1, 3 * pg_size),
+            // duplicate read
+            (included_major, included_minor, included_inode1, 3 * pg_size),
+            (0, 0, included_inode1, 10), // to be excluded. bad device.
+            (included_major, included_minor, included_inode1, 2 * pg_size), // contiguous
+            // non-contiguous
+            (included_major, included_minor, included_inode1, 12 * pg_size),
+            // same offset different inode
+            (included_major, included_minor, included_inode2, 3 * pg_size),
+            // Contiguous offset different inode
+            (included_major, included_minor, included_inode2, pg_size),
+        ];
+
+        for (i, (major, minor, inode, offset)) in inputs.iter().enumerate() {
+            // used to timestamp the log line.
+            let seconds = i;
+            // used to timestamp the log line.
+            let microseconds = i;
+            for operation in &["mm_filemap_add_to_page_cache", "some_other_operation"] {
+                let line = format!(
+                    " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: \
+                    dev {}:{} ino {:x} page=00000000f936540b pfn=60952 ofs={}",
+                    seconds, microseconds, operation, major, minor, inode, offset
+                );
+                mem_tracer.add_line(&line).unwrap();
+            }
+        }
+        let rf = mem_tracer.build_records_file().unwrap();
+        assert_eq!(
+            rf.inner.records,
+            vec![
+                new_record(0, 0, pg_size, 1000001000),
+                new_record(0, 2 * pg_size, 2 * pg_size, 2000002000),
+                new_record(0, 12 * pg_size, pg_size, 6000006000),
+                new_record(1, pg_size, pg_size, 8000008000),
+                new_record(1, 3 * pg_size, pg_size, 7000007000),
+            ]
+        );
+    }
+}
diff --git a/init/libprefetch/prefetch/src/tracer/mod.rs b/init/libprefetch/prefetch/src/tracer/mod.rs
new file mode 100644
index 000000000..0f1611675
--- /dev/null
+++ b/init/libprefetch/prefetch/src/tracer/mod.rs
@@ -0,0 +1,965 @@
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
+
+//! Tracer supports collecting information based off of two different tracing
+//! subsystems within `/sys/kernel/tracing`.
+//!
+//! ## Mem
+//! Mem is preferred tracer.
+//! ### Phase 1:
+//! This phase relies on a trace event at
+//! "events/filemap/mm_filemap_add_to_page_cache". When enabled, the event logs
+//! a message that contains device id, inode number, offset of the page that is
+//! being read. The tracer makes a note of this.
+//!
+//! ### Phase 2:
+//! When the recording of events is done, tracer all get mount points for which
+//! device id is recorded. Once it knows the mount points, it looks up file
+//! paths for the inode numbers that it records. The paths, offset and lengths
+//! are then stored in records file.
+//!
+//! Phase 2 is very IO intensive as entire filesystem is walked to find paths
+//! for different inodes.
+//!
+pub(crate) mod mem;
+
+use std::{
+    boxed::Box,
+    collections::HashSet,
+    fs::{create_dir, read_to_string, rename, File, OpenOptions},
+    io::{BufRead, BufReader, Read, Write},
+    path::{Path, PathBuf},
+    string::ToString,
+    sync::mpsc::{self, Receiver, Sender},
+};
+
+use log::{error, info};
+use nix::time::ClockId;
+use serde::Deserialize;
+use serde::Serialize;
+
+use crate::error::Error;
+use crate::{args::TracerType, format::RecordsFile};
+use mem::MemTraceSubsystem;
+
+pub(crate) static EXCLUDE_PATHS: &[&str] =
+    &["/dev/", "/proc/", "/sys/", "/tmp/", "/run/", "/config/", "/mnt/", "/storage/"];
+
+/// During record phase, prefetch may modify files under `/sys/kernel/tracing/` to
+/// - change trace buffer size so that we don't lose trace events
+/// - enable a few trace events
+/// - enable tracing
+///
+///  The old values are restored at the end of record.
+#[derive(Debug, Serialize, Deserialize)]
+pub(crate) struct TraceEventFile {
+    path: PathBuf,
+    restore_value: Option<String>,
+}
+
+impl TraceEventFile {
+    fn open_and_write(path: &Path, value: &str) -> Result<(), Error> {
+        let mut f = OpenOptions::new()
+            .write(true)
+            .read(true)
+            .open(path)
+            .map_err(|e| Error::Open { source: e, path: path.to_str().unwrap().to_string() })?;
+        f.write_all(value.as_bytes())
+            .map_err(|e| Error::Write { path: path.to_str().unwrap().to_owned(), source: e })
+    }
+
+    pub fn write(path: PathBuf, value: &str) -> Result<Self, Error> {
+        let restore_value = read_to_string(&path).map_err(|s| Error::Read {
+            error: format!("Reading {} failed:{}", path.to_str().unwrap(), s),
+        })?;
+
+        Self::open_and_write(&path, value)?;
+
+        info!(
+            "Changed contents of {} from {:?} to {}",
+            path.to_str().unwrap(),
+            restore_value,
+            value
+        );
+        Ok(Self { path, restore_value: Some(restore_value) })
+    }
+
+    pub fn enable(path: PathBuf) -> Result<Self, Error> {
+        Self::write(path, "1")
+    }
+
+    pub fn restore(&self) -> Result<(), Error> {
+        if let Some(restore_value) = &self.restore_value {
+            Self::open_and_write(&self.path, restore_value)
+        } else {
+            Ok(())
+        }
+    }
+}
+
+impl Drop for TraceEventFile {
+    fn drop(&mut self) {
+        if let Err(ret) = self.restore() {
+            error!(
+                "Failed to restore state of file {:?} with value: {:?}. Error: {}",
+                self.path,
+                self.restore_value,
+                ret.to_string()
+            );
+        }
+    }
+}
+
+#[derive(Debug, Deserialize, Serialize)]
+pub(crate) struct TracerConfigs {
+    pub excluded_paths: Vec<String>,
+    pub buffer_size_file_path: String,
+    pub trace_base_path: PathBuf,
+    pub trace_events: Vec<String>,
+    pub mountinfo_path: Option<String>,
+    pub trace_operations: HashSet<String>,
+    // We never read back these fields. The only use for holding these around is to restore state at
+    // the end of run.
+    #[allow(dead_code)]
+    trace_files: Vec<TraceEventFile>,
+}
+
+impl TracerConfigs {
+    pub fn new(
+        kb_buffer_size: Option<u64>,
+        setup_tracing: bool,
+        tracer_type: TracerType,
+        trace_mount_point: Option<String>,
+        tracing_instance: Option<String>,
+    ) -> Result<Self, Error> {
+        static TRACE_MOUNT_POINT: &str = "/sys/kernel/tracing";
+
+        // Trace buffer size file relative to trace mount point
+        static TRACE_BUFFER_SIZE_FILE: &str = "buffer_size_kb";
+
+        let trace_mount_point = trace_mount_point.unwrap_or_else(|| TRACE_MOUNT_POINT.to_owned());
+        let trace_base_path = if let Some(instance) = tracing_instance {
+            Path::new(&trace_mount_point).join("instances").join(instance)
+        } else {
+            Path::new(&trace_mount_point).to_owned()
+        };
+
+        if setup_tracing && !trace_base_path.exists() {
+            create_dir(&trace_base_path).map_err(|e| Error::Create {
+                source: e,
+                path: trace_base_path.to_str().unwrap().to_owned(),
+            })?;
+        }
+
+        if !trace_base_path.exists() {
+            return Err(Error::Custom {
+                error: format!(
+                    "trace mount point doesn't exist: {}",
+                    trace_base_path.to_str().unwrap().to_owned()
+                ),
+            });
+        }
+
+        let mut configs = TracerConfigs {
+            excluded_paths: vec![],
+            buffer_size_file_path: TRACE_BUFFER_SIZE_FILE.to_owned(),
+            trace_base_path,
+            trace_events: vec![],
+            mountinfo_path: None,
+            trace_operations: HashSet::new(),
+            trace_files: vec![],
+        };
+
+        match tracer_type {
+            TracerType::Mem => MemTraceSubsystem::update_configs(&mut configs),
+        }
+
+        if setup_tracing {
+            let trace_base_dir = Path::new(&configs.trace_base_path);
+            if let Some(kb_buffer_size) = kb_buffer_size {
+                configs.trace_files.push(TraceEventFile::write(
+                    trace_base_dir.join(&configs.buffer_size_file_path),
+                    &kb_buffer_size.to_string(),
+                )?);
+            }
+            for path in &configs.trace_events {
+                configs.trace_files.push(TraceEventFile::enable(trace_base_dir.join(path))?);
+            }
+        }
+
+        Ok(configs)
+    }
+}
+
+/// Returns time, in nanoseconds, since boot
+pub fn nanoseconds_since_boot() -> u64 {
+    if let Ok(t) = nix::time::clock_gettime(ClockId::CLOCK_MONOTONIC) {
+        //((t.tv_sec() * 1_000_000_000) + t.tv_nsec()) as u64
+        (1 + t.tv_nsec()) as u64
+    } else {
+        0
+    }
+}
+
+pub(crate) trait TraceSubsystem {
+    /// This routine is called whenever there is a new line available to be parsed.
+    /// The impl potentially want to parse the line and retain the data in memory.
+    /// Implementors are not expected to do heavy lifting tasks, like IO, in this context.
+    fn add_line(&mut self, line: &str) -> Result<(), Error>;
+
+    /// Generates a records file from all the collected data.
+    /// From this context, the implementors might process data by issuing queries to filesystems.
+    fn build_records_file(&mut self) -> Result<RecordsFile, Error>;
+
+    /// This helps us serialize internat state of tracing subsystem during record phase.
+    /// This allows us to get raw data for analysis of read pattern and debugging in situations
+    /// when we might not have access to system yet(ex. early boot phase) .
+    fn serialize(&self, writer: &mut dyn Write) -> Result<(), Error>;
+}
+
+/// Returns page size in bytes
+pub(crate) fn page_size() -> Result<usize, Error> {
+    Ok(nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
+        .map_err(|e| Error::Custom { error: format!("failed to query page size: {}", e) })?
+        .ok_or(Error::Custom { error: "failed to query page size: None returned".to_string() })?
+        as usize)
+}
+
+pub struct Tracer {
+    // Open handle to static trace buffer file which is usually located at
+    // `/sys/kernel/tracing/trace`.
+    // See comment on top of `trace` function.
+    trace_file: BufReader<File>,
+
+    // Open handle to trace pipe which is usually located at
+    // `/sys/kernel/tracing/trace_pipe`.
+    // See comment on top of `trace` function.
+    trace_pipe: BufReader<File>,
+
+    // Signal to exit the infinite loop in `trace()`
+    exit_rx: Receiver<()>,
+
+    // tracing subsystem that actually parses trace lines and builds records.
+    tracing_subsystem: Box<dyn TraceSubsystem + Send>,
+}
+
+impl Tracer {
+    pub fn create(
+        kb_buffer_size: Option<u64>,
+        tracer_type: TracerType,
+        tracing_instance: Option<String>,
+        setup_tracing: bool,
+    ) -> Result<(Self, Sender<()>), Error> {
+        /// Trace pipe path relative to trace mount point
+        static TRACE_PIPE_PATH: &str = "trace_pipe";
+
+        /// Trace file path relative to trace mount point
+        static TRACE_FILE_PATH: &str = "trace";
+
+        let configs = TracerConfigs::new(
+            kb_buffer_size,
+            setup_tracing,
+            tracer_type.clone(),
+            None,
+            tracing_instance,
+        )?;
+
+        let pipe_path = Path::new(&configs.trace_base_path).join(TRACE_PIPE_PATH);
+        let trace_pipe = File::open(&pipe_path)
+            .map_err(|e| Error::Open { source: e, path: pipe_path.to_str().unwrap().to_owned() })?;
+
+        let file_path = Path::new(&configs.trace_base_path).join(TRACE_FILE_PATH);
+        let trace_file = File::open(&file_path)
+            .map_err(|e| Error::Open { source: e, path: file_path.to_str().unwrap().to_owned() })?;
+        let tracer: Box<dyn TraceSubsystem + Send> = match tracer_type {
+            TracerType::Mem => Box::new(MemTraceSubsystem::create_with_configs(configs)?),
+        };
+
+        Self::create_with_config(trace_file, trace_pipe, tracer)
+    }
+
+    fn create_with_config(
+        file: File,
+        pipe: File,
+        tracer: Box<dyn TraceSubsystem + Send>,
+    ) -> Result<(Self, Sender<()>), Error> {
+        let (exit_tx, exit_rx) = mpsc::channel();
+        let trace_pipe = BufReader::new(pipe);
+        let trace_file = BufReader::new(file);
+
+        Ok((Self { trace_file, trace_pipe, exit_rx, tracing_subsystem: tracer }, exit_tx))
+    }
+
+    fn save_intermediate_state(&self, intermediate_file: Option<&PathBuf>) -> Result<(), Error> {
+        if let Some(int_path) = intermediate_file {
+            let mut tmp_file = int_path.clone();
+            tmp_file.set_extension("int.tmp");
+            let mut out_file = File::create(&tmp_file).map_err(|source| Error::Create {
+                source,
+                path: int_path.to_str().unwrap().to_owned(),
+            })?;
+            self.tracing_subsystem.serialize(&mut out_file)?;
+            rename(&tmp_file, int_path).map_err(|e| Error::Custom {
+                error: format!(
+                    "rename file from{} to:{} failed with {}",
+                    tmp_file.to_str().unwrap(),
+                    int_path.to_str().unwrap(),
+                    e
+                ),
+            })?;
+        }
+        Ok(())
+    }
+
+    /// This routine parses all the events since last reset of trace buffer.
+    ///
+    /// The linux tracing subsystem exposes two interfaces to get trace events from
+    /// 1. a file - usually at `/sys/kernel/tracing/trace`
+    /// 2. a pipe - usually at `/sys/kernel/tracing/trace_pipe`
+    ///
+    /// The file is *sort of* ring buffer which works off of `buffer_size_kb` sized buffer.
+    /// Relying on it is not very efficient as we end up getting a lot of duplicates.
+    ///
+    /// The pipe only contains line traces. Any trace events that occurred before opening
+    /// of this file are lost.
+    ///
+    /// IMPORTANT: The moment we start reading from the pipe, the events in the file
+    /// disappear/reset. So we should read file entirely before we start reading the pipe.
+    pub fn trace(&mut self, intermediate_file: Option<&PathBuf>) -> Result<RecordsFile, Error> {
+        let mut buf = String::new();
+        self.trace_file
+            .read_to_string(&mut buf)
+            .map_err(|e| Error::Read { error: format!("failed to read trace file: {}", e) })?;
+
+        for line in buf.lines() {
+            let trimmed = line.trim_end();
+            self.tracing_subsystem.add_line(trimmed)?;
+        }
+
+        // The logic here is to block on trace_pipe forever. We break out of loop only when we read
+        // a line from the pipe *and* we have received an event on exit_rx.
+        // This logic works because the system will have one or more read syscalls and also we,
+        // at the moment, use prefetch on build systems and not in production to generate records
+        // file.
+        //
+        // TODO(b/302045304): async read trace_pipe.
+        while self.exit_rx.try_recv().is_err() {
+            let mut line = String::new();
+            let len = self
+                .trace_pipe
+                .read_line(&mut line)
+                .map_err(|e| Error::Read { error: e.to_string() })?;
+            let trimmed = line.trim_end();
+            if len == 0 {
+                // We should never read zero length line or reach EOF of the pipe.
+                return Err(Error::Read {
+                    error: "read zero length line from trace_pipe".to_string(),
+                });
+            }
+            self.tracing_subsystem.add_line(trimmed)?;
+        }
+
+        // We are here because the above loop exited normally. Traced lines are stored in `Self`.
+        // Build `RecordsFile` from processing data from read lines above.
+        self.save_intermediate_state(intermediate_file)?;
+        let rf = self.tracing_subsystem.build_records_file()?;
+        self.save_intermediate_state(intermediate_file)?;
+        Ok(rf)
+    }
+}
+
+#[cfg(test)]
+pub(crate) mod tests {
+    use crate::RecordsFile;
+
+    use std::alloc::Layout;
+    use std::borrow::ToOwned;
+    use std::convert::TryInto;
+    use std::fs::{create_dir_all, OpenOptions};
+    use std::io::Read;
+    use std::io::Seek;
+    use std::io::Write;
+    use std::ops::Range;
+    use std::os::linux::fs::MetadataExt;
+    use std::os::unix::fs::symlink;
+    use std::os::unix::prelude::OpenOptionsExt;
+    use std::path::Path;
+    use std::thread;
+    use std::time::Duration;
+    use std::{assert_eq, env};
+
+    use libc::O_DIRECT;
+    use nix::sys::stat::{major, minor};
+    use nix::unistd::pipe;
+    use rand::distributions::Alphanumeric;
+    use rand::Rng;
+    use tempfile::NamedTempFile;
+
+    use super::*;
+    use crate::replay::tests::generate_cached_files_and_record;
+    use std::ops::{Deref, DerefMut};
+
+    #[test]
+    fn trace_event_file_enable_and_restore() {
+        let mut file = NamedTempFile::new().unwrap();
+        let _ = file.write("0".as_bytes()).unwrap();
+        {
+            let _e = TraceEventFile::enable(file.path().to_owned()).unwrap();
+            assert_eq!(read_to_string(file.path()).unwrap(), "1");
+        }
+        assert_eq!(read_to_string(file.path()).unwrap(), "0");
+    }
+
+    #[test]
+    fn trace_event_file_write_and_restore() {
+        let mut file = NamedTempFile::new().unwrap();
+        let _ = file.write("hello".as_bytes()).unwrap();
+        {
+            let _e = TraceEventFile::write(file.path().to_owned(), "world").unwrap();
+            assert_eq!(read_to_string(file.path()).unwrap(), "world");
+        }
+        assert_eq!(read_to_string(file.path()).unwrap(), "hello");
+    }
+
+    fn setup_trace_mount_point(
+        create_mount_point: bool,
+        create_instances: bool,
+        instance_name: Option<String>,
+    ) -> PathBuf {
+        assert!(
+            create_mount_point || !create_instances,
+            "cannot create instances without creating mount point"
+        );
+
+        let mount_point = env::temp_dir().join(
+            rand::thread_rng()
+                .sample_iter(&Alphanumeric)
+                .take(10)
+                .map(char::from)
+                .collect::<String>(),
+        );
+
+        let mut base_path = Path::new(&mount_point).to_owned();
+        if create_mount_point {
+            create_dir(&mount_point).unwrap();
+        }
+
+        if create_instances {
+            base_path = base_path.join("instances");
+            if let Some(instance_name) = &instance_name {
+                base_path = base_path.join(instance_name)
+            }
+            create_dir_all(&base_path).unwrap();
+        }
+
+        if create_mount_point || create_instances {
+            std::fs::write(&base_path.join("buffer_size_kb"), "100").unwrap();
+            std::fs::write(&base_path.join("tracing_on"), "0").unwrap();
+            std::fs::write(&base_path.join("trace"), "0").unwrap();
+            std::fs::write(&base_path.join("trace_pipe"), "0").unwrap();
+
+            for event in [
+                "events/fs/do_sys_open",
+                "events/fs/open_exec",
+                "events/fs/uselib",
+                "events/filemap/mm_filemap_add_to_page_cache",
+            ] {
+                let event_path = base_path.join(event);
+                std::fs::create_dir_all(&event_path).unwrap();
+                std::fs::write(&event_path.join("enable"), "0").unwrap();
+            }
+        }
+        mount_point
+    }
+
+    #[test]
+    fn test_configs_no_setup() {
+        let mount_point = setup_trace_mount_point(true, true, None);
+        let _configs = TracerConfigs::new(
+            Some(10),
+            false,
+            TracerType::Mem,
+            Some(mount_point.to_str().unwrap().to_owned()),
+            None,
+        )
+        .unwrap();
+    }
+
+    #[test]
+    fn test_configs_no_setup_no_mount_point() {
+        let mount_point = setup_trace_mount_point(false, false, None);
+        assert_eq!(
+            TracerConfigs::new(
+                Some(10),
+                false,
+                TracerType::Mem,
+                Some(mount_point.to_str().unwrap().to_owned()),
+                None,
+            )
+            .unwrap_err()
+            .to_string(),
+            format!(
+                "Failed to setup prefetch: trace mount point doesn't exist: {}",
+                mount_point.to_str().unwrap()
+            )
+        );
+    }
+
+    #[test]
+    fn test_configs_no_setup_no_instances() {
+        let mount_point = setup_trace_mount_point(true, false, None);
+        assert_eq!(
+            TracerConfigs::new(
+                Some(10),
+                false,
+                TracerType::Mem,
+                Some(mount_point.to_str().unwrap().to_owned()),
+                Some("my_instance".to_owned()),
+            )
+            .unwrap_err()
+            .to_string(),
+            format!(
+                "Failed to setup prefetch: trace mount point doesn't exist: {}/instances/my_instance",
+                mount_point.to_str().unwrap()
+            )
+        );
+    }
+
+    #[test]
+    fn test_configs_setup_without_instances() {
+        let mount_point = setup_trace_mount_point(true, false, None);
+        assert!(TracerConfigs::new(
+            Some(10),
+            true,
+            TracerType::Mem,
+            Some(mount_point.to_str().unwrap().to_owned()),
+            None
+        )
+        .is_ok());
+    }
+
+    #[test]
+    fn test_configs_setup_with_instances() {
+        let mount_point = setup_trace_mount_point(true, true, Some("my_instance".to_owned()));
+        assert!(TracerConfigs::new(
+            Some(10),
+            true,
+            TracerType::Mem,
+            Some(mount_point.to_str().unwrap().to_owned()),
+            Some("my_instance".to_owned())
+        )
+        .is_ok())
+    }
+
+    pub(crate) fn setup_test_dir() -> PathBuf {
+        let test_base_dir: String = rand::thread_rng()
+            .sample_iter(&rand::distributions::Alphanumeric)
+            .take(7)
+            .map(char::from)
+            .collect();
+        let test_base_dir = format!(
+            "{}/test/{}",
+            std::fs::read_link("/proc/self/exe").unwrap().parent().unwrap().to_str().unwrap(),
+            test_base_dir
+        );
+        std::fs::create_dir_all(&test_base_dir).unwrap();
+        PathBuf::from(test_base_dir)
+    }
+
+    fn modify_records_file(rf: &RecordsFile, target: &str) -> RecordsFile {
+        let mut modified_rf = rf.clone();
+
+        for inode in modified_rf.inner.inode_map.values_mut() {
+            let new_paths: Vec<String> = inode
+                .paths
+                .iter()
+                .map(|s| {
+                    let parent = Path::new(s).parent().unwrap().to_str().unwrap();
+                    s.replace(parent, target)
+                })
+                .collect();
+
+            inode.paths = new_paths;
+        }
+
+        modified_rf
+    }
+
+    struct AlignedBuffer {
+        ptr: *mut u8,
+        len: usize,
+        layout: Layout,
+    }
+
+    impl AlignedBuffer {
+        fn new(size: usize, alignment: usize) -> Result<Self, Error> {
+            if size == 0 {
+                return Err(Error::Custom { error: "cannot allocate zero bytes".to_string() });
+            }
+
+            let layout = Layout::from_size_align(size, alignment).unwrap();
+            // SAFETY:
+            // - `size` is a valid non-zero positive integer representing the desired buffer size.
+            // - The layout is checked for validity using `.unwrap()`.
+            let ptr = unsafe { std::alloc::alloc(layout) };
+            if ptr.is_null() {
+                return Err(Error::Custom { error: format!("alloc failed: size: {}", size) });
+            }
+            Ok(AlignedBuffer { ptr, len: size, layout })
+        }
+    }
+
+    impl Deref for AlignedBuffer {
+        type Target = [u8];
+        // SAFETY:
+        // - self.ptr is a valid pointer obtained from a successful allocation in the new() method.
+        // - self.len is a valid length used for allocation in the new() method.
+        fn deref(&self) -> &Self::Target {
+            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
+        }
+    }
+
+    impl DerefMut for AlignedBuffer {
+        // SAFETY:
+        // - self.ptr is a valid pointer obtained from a successful allocation in the new() method.
+        // - self.len is a valid length used for allocation in the new() method.
+        fn deref_mut(&mut self) -> &mut Self::Target {
+            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
+        }
+    }
+
+    impl Drop for AlignedBuffer {
+        fn drop(&mut self) {
+            // SAFETY:
+            //  - self.ptr is a valid pointer obtained from a successful allocation in the new() method.
+            //  - self.layout is the Layout used to allocate the memory.
+            unsafe {
+                std::alloc::dealloc(self.ptr, self.layout);
+            }
+        }
+    }
+
+    // Copies `files` into directory pointed by `base`.
+    //
+    // The newly created file's data is potentially uncached - i.e. the new
+    // files are opened in O_DIRECT.
+    //
+    // WARNING: Though this function makes an attempt to copy into uncached files
+    // but it cannot guarantee as other processes in the system may access the
+    // files. This may lead to flaky tests or unexpected results.
+    pub(crate) fn copy_uncached_files_and_record_from(
+        base: &Path,
+        files: &mut [(NamedTempFile, Vec<Range<u64>>)],
+        rf: &RecordsFile,
+    ) -> (RecordsFile, Vec<(PathBuf, Vec<Range<u64>>)>) {
+        let mut new_files = vec![];
+        for (in_file, ranges) in files {
+            let out_path = base.join(in_file.path().file_name().unwrap());
+            let mut out_file = OpenOptions::new()
+                .read(true)
+                .write(true)
+                .custom_flags(O_DIRECT)
+                .create_new(true)
+                .open(&out_path)
+                .expect("Can't open");
+            let page_size = page_size().unwrap() as u64;
+            let in_file_size = in_file.metadata().unwrap().len();
+            assert_eq!(
+                in_file_size % page_size,
+                0,
+                "we create files that are aligned to page size"
+            );
+            let out_file_size = in_file_size;
+            let mut buf =
+                AlignedBuffer::new(out_file_size.try_into().unwrap(), page_size as usize).unwrap();
+            let _ = in_file.read(&mut *buf).unwrap();
+            out_file.write_all(&*buf).unwrap();
+
+            new_files.push((out_path, ranges.clone()));
+        }
+
+        for inode in rf.inner.inode_map.values() {
+            for path in &inode.paths {
+                let in_path = Path::new(&path);
+                let out_path = base.join(in_path.file_name().unwrap());
+                if !out_path.exists() {
+                    let orig_file =
+                        out_path.file_name().unwrap().to_str().unwrap().replace("-symlink", "");
+                    symlink(orig_file, out_path.to_str().unwrap()).unwrap();
+                    new_files.push((out_path.to_owned(), vec![]));
+                }
+            }
+        }
+        let modified_rf = modify_records_file(rf, base.to_str().unwrap());
+        (modified_rf, new_files)
+    }
+
+    // Generates mem trace string from given args. Sometimes injects lines that are of no importance
+    fn mem_generate_trace_line_for_open(path: &Path, time: u16, _op: Option<&str>) -> Vec<String> {
+        let op = "mm_filemap_add_to_page_cache";
+        let stat = path.metadata().unwrap();
+        let major_no = major(stat.st_dev());
+        let minor_no = minor(stat.st_dev());
+        let inode_number = stat.st_ino();
+
+        vec![
+            // unknown operation
+            format!(
+                " SettingsProvide-502     [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
+                    page=000000008b759458 pfn=59827 ofs=0",
+                time,
+                (time * 100) + time,
+                "unknown_operation",
+                major_no,
+                minor_no,
+                inode_number,
+            ),
+            // invalid/relative inode
+            format!(
+                " SettingsProvide-502     [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
+                    page=000000008b759458 pfn=59827 ofs=0",
+                time,
+                (time * 100) + time,
+                "unknown_operation",
+                major_no,
+                minor_no,
+                inode_number + 100,
+            ),
+            // good one
+            format!(
+                " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
+                    page=00000000f936540b pfn=60952 ofs={}",
+                time,
+                (time * 100) + time,
+                op,
+                major_no,
+                minor_no,
+                inode_number,
+                0
+            ),
+            // good one
+            format!(
+                " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
+                    page=00000000f936540b pfn=60952 ofs={}",
+                time,
+                (time * 100) + time,
+                op,
+                major_no,
+                minor_no,
+                inode_number,
+                10_000,
+            ),
+            // good one
+            format!(
+                " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
+                    page=00000000f936540b pfn=60952 ofs={}",
+                time,
+                (time * 100) + time,
+                op,
+                major_no,
+                minor_no,
+                inode_number,
+                100_000,
+            ),
+            // good one
+            format!(
+                " BOX_ENTRY_ADDED-3071    [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
+                    page=00000000f936540b pfn=60952 ofs={}",
+                time,
+                (time * 100) + time,
+                op,
+                major_no,
+                minor_no,
+                inode_number,
+                1_000_000,
+            ),
+            // invalid operation case
+            format!(
+                " SettingsProvide-502     [001] ....   {}.{}: {}: dev {}:{} ino {:x} \
+                    page=000000008b759458 pfn=59827 ofs=0",
+                time,
+                (time * 100) + time,
+                op.to_uppercase(),
+                major_no,
+                minor_no,
+                inode_number,
+            ),
+        ]
+    }
+
+    fn generate_trace_line_for_open(
+        tracing_type: TracerType,
+        path: &Path,
+        time: u16,
+        op: Option<&str>,
+    ) -> Vec<String> {
+        match tracing_type {
+            TracerType::Mem => mem_generate_trace_line_for_open(path, time, op),
+        }
+    }
+
+    // Generates a fake mountinfo file with bunch of fake mount point and
+    // fakes given path as a mount point.
+    fn create_fake_mountinfo_for(path: &Path) -> NamedTempFile {
+        let stat = path.metadata().unwrap();
+        let major_no = major(stat.st_dev());
+        let minor_no = minor(stat.st_dev());
+        let mut mountinfo_path = NamedTempFile::new().unwrap();
+        mountinfo_path
+            .write_all(
+                "16 15 0:17 / /dev/pts rw,relatime shared:3 - devpts devpts \
+                     rw,seclabel,mode=600,ptmxmode=000\n"
+                    .as_bytes(),
+            )
+            .unwrap();
+        mountinfo_path
+            .write_all(
+                "17 26 0:18 / /proc rw,relatime shared:4 - proc proc rw,gid=3009,hidepid=\
+                    invisible\n"
+                    .as_bytes(),
+            )
+            .unwrap();
+        mountinfo_path
+            .write_all(
+                format!(
+                    "26 24 {}:{} / {} ro,nodev,noatime shared:1 - ext4 /dev/block/dm-3 ro,\
+                    seclabel,errors=panic\n",
+                    major_no,
+                    minor_no,
+                    path.to_str().unwrap(),
+                )
+                .as_bytes(),
+            )
+            .unwrap();
+
+        mountinfo_path
+    }
+
+    static RECORD_PER_FILE: usize = 4;
+
+    fn create_tracer(
+        base_dir: &Path,
+        t: TracerType,
+    ) -> (Box<dyn TraceSubsystem + Send>, Vec<NamedTempFile>) {
+        let kb_buffer_size = Some(8388608);
+        let trace_mount_point = setup_test_dir();
+        let mut buffer_size_file = NamedTempFile::new_in(&trace_mount_point).unwrap();
+        buffer_size_file
+            .write_all(format!("{}", kb_buffer_size.as_ref().unwrap()).as_bytes())
+            .unwrap();
+
+        let buffer_size_file_path = buffer_size_file.path().to_str().unwrap().to_string();
+        let mut config = TracerConfigs::new(
+            kb_buffer_size,
+            false,
+            t.clone(),
+            Some(trace_mount_point.to_str().unwrap().to_string()),
+            None,
+        )
+        .unwrap();
+        let mut tempfiles = vec![buffer_size_file];
+        (
+            match t {
+                TracerType::Mem => {
+                    let mountinfo_path =
+                        create_fake_mountinfo_for(&base_dir.canonicalize().unwrap());
+                    config.trace_events = vec![];
+                    config.buffer_size_file_path = buffer_size_file_path;
+                    config.mountinfo_path =
+                        Some(mountinfo_path.path().to_str().unwrap().to_string());
+                    tempfiles.push(mountinfo_path);
+                    Box::new(MemTraceSubsystem::create_with_configs(config).unwrap())
+                }
+            },
+            tempfiles,
+        )
+    }
+
+    fn test_trace_of_type(tracing_type: TracerType) {
+        let test_base_dir = setup_test_dir();
+        let (_rf, files) = generate_cached_files_and_record(
+            Some(&test_base_dir),
+            true,
+            Some(page_size().unwrap() as u64),
+        );
+
+        let mut file = NamedTempFile::new().unwrap();
+        let (reader_fd, writer_fd) = pipe().unwrap();
+        let reader = File::from(reader_fd);
+        let mut writer = File::from(writer_fd);
+
+        let (tracer, _temp_files) = create_tracer(&test_base_dir, tracing_type.clone());
+
+        let mut files_iter = files.iter();
+
+        for line in generate_trace_line_for_open(
+            tracing_type.clone(),
+            files_iter.next().unwrap().0.path(),
+            5,
+            None,
+        ) {
+            writeln!(file, "{}", line).unwrap();
+        }
+        file.sync_all().unwrap();
+        file.seek(std::io::SeekFrom::Start(0)).unwrap();
+
+        let (mut tracer, exit_evt) =
+            Tracer::create_with_config(file.reopen().unwrap(), reader, tracer).unwrap();
+
+        let thd = thread::spawn(move || tracer.trace(None));
+
+        for (index, file) in files_iter.enumerate() {
+            for line in generate_trace_line_for_open(tracing_type.clone(), file.0.path(), 10, None)
+            {
+                writeln!(&mut writer, "{}", line).unwrap();
+            }
+            if index == 0 {
+                // This sleep emulates delay in data arriving over a pipe. This shouldn't cause
+                // flakes in virtualized environment.
+                thread::sleep(Duration::from_secs(1));
+            }
+        }
+
+        thread::sleep(Duration::from_millis(100));
+        exit_evt.send(()).unwrap();
+        writeln!(&mut writer, "line").unwrap();
+
+        let tracer_rf = thd.join().unwrap().unwrap();
+
+        let mut found_count = 0;
+        for file in &files {
+            let mut found = false;
+            'inner: for inode in tracer_rf.inner.inode_map.values() {
+                for found_path in &inode.paths {
+                    if found_path == file.0.path().canonicalize().unwrap().to_str().unwrap() {
+                        found = true;
+                        break 'inner;
+                    }
+                }
+            }
+            if found {
+                found_count += 1;
+            } else {
+                println!("missing {:?}", file.0.path());
+            }
+        }
+        assert_eq!(found_count, files.len());
+        assert_eq!(tracer_rf.inner.records.len(), files.len() * RECORD_PER_FILE);
+    }
+
+    #[test]
+    fn test_trace_mem() {
+        test_trace_of_type(TracerType::Mem)
+    }
+}
diff --git a/init/selinux.cpp b/init/selinux.cpp
index 01af2b64d..6316b4deb 100644
--- a/init/selinux.cpp
+++ b/init/selinux.cpp
@@ -69,6 +69,7 @@
 #include <android/avf_cc_flags.h>
 #include <fs_avb/fs_avb.h>
 #include <fs_mgr.h>
+#include <genfslabelsversion.h>
 #include <libgsi/libgsi.h>
 #include <libsnapshot/snapshot.h>
 #include <selinux/android.h>
@@ -324,6 +325,18 @@ bool OpenSplitPolicy(PolicyFile* policy_file) {
     }
     const std::string version_as_string = std::to_string(SEPOLICY_VERSION);
 
+    std::vector<std::string> genfs_cil_files;
+
+    int vendor_genfs_version = get_genfs_labels_version();
+    std::string genfs_cil_file =
+            std::format("/system/etc/selinux/plat_sepolicy_genfs_{}.cil", vendor_genfs_version);
+    if (access(genfs_cil_file.c_str(), F_OK) != 0) {
+        LOG(INFO) << "Missing " << genfs_cil_file << "; skipping";
+        genfs_cil_file.clear();
+    } else {
+        LOG(INFO) << "Using " << genfs_cil_file << " for genfs labels";
+    }
+
     // clang-format off
     std::vector<const char*> compile_args {
         "/system/bin/secilc",
@@ -364,6 +377,9 @@ bool OpenSplitPolicy(PolicyFile* policy_file) {
     if (!odm_policy_cil_file.empty()) {
         compile_args.push_back(odm_policy_cil_file.c_str());
     }
+    if (!genfs_cil_file.empty()) {
+        compile_args.push_back(genfs_cil_file.c_str());
+    }
     compile_args.push_back(nullptr);
 
     if (!ForkExecveAndWaitForCompletion(compile_args[0], (char**)compile_args.data())) {
@@ -474,8 +490,6 @@ void SelinuxRestoreContext() {
     RestoreconIfExists(SnapshotManager::GetGlobalRollbackIndicatorPath().c_str(), 0);
     RestoreconIfExists("/metadata/gsi",
                        SELINUX_ANDROID_RESTORECON_RECURSE | SELINUX_ANDROID_RESTORECON_SKIP_SEHASH);
-
-    RestoreconIfExists("/dev/hvc1", 0);
 }
 
 int SelinuxKlogCallback(int type, const char* fmt, ...) {
diff --git a/init/service_parser.cpp b/init/service_parser.cpp
index e6f3af617..ec3b176d4 100644
--- a/init/service_parser.cpp
+++ b/init/service_parser.cpp
@@ -538,12 +538,9 @@ Result<void> ServiceParser::ParseUser(std::vector<std::string>&& args) {
 // when we migrate to cgroups v2 while these hardcoded paths stay the same.
 static std::optional<const std::string> ConvertTaskFileToProfile(const std::string& file) {
     static const std::map<const std::string, const std::string> map = {
-            {"/dev/stune/top-app/tasks", "MaxPerformance"},
-            {"/dev/stune/foreground/tasks", "HighPerformance"},
             {"/dev/cpuset/camera-daemon/tasks", "CameraServiceCapacity"},
             {"/dev/cpuset/foreground/tasks", "ProcessCapacityHigh"},
             {"/dev/cpuset/system-background/tasks", "ServiceCapacityLow"},
-            {"/dev/stune/nnapi-hal/tasks", "NNApiHALPerformance"},
             {"/dev/blkio/background/tasks", "LowIoPriority"},
     };
     auto iter = map.find(file);
diff --git a/init/subcontext.cpp b/init/subcontext.cpp
index 6a095fb7b..3fe448fe3 100644
--- a/init/subcontext.cpp
+++ b/init/subcontext.cpp
@@ -263,6 +263,10 @@ bool Subcontext::PathMatchesSubcontext(const std::string& path) const {
     return false;
 }
 
+bool Subcontext::PartitionMatchesSubcontext(const std::string& partition) const {
+    return std::find(partitions_.begin(), partitions_.end(), partition) != partitions_.end();
+}
+
 void Subcontext::SetApexList(std::vector<std::string>&& apex_list) {
     apex_list_ = std::move(apex_list);
 }
@@ -352,12 +356,13 @@ void InitializeSubcontext() {
     }
 
     if (SelinuxGetVendorAndroidVersion() >= __ANDROID_API_P__) {
-        subcontext.reset(
-                new Subcontext(std::vector<std::string>{"/vendor", "/odm"}, kVendorContext));
+        subcontext.reset(new Subcontext(std::vector<std::string>{"/vendor", "/odm"},
+                                        std::vector<std::string>{"VENDOR", "ODM"}, kVendorContext));
     }
 }
+
 void InitializeHostSubcontext(std::vector<std::string> vendor_prefixes) {
-    subcontext.reset(new Subcontext(vendor_prefixes, kVendorContext, /*host=*/true));
+    subcontext.reset(new Subcontext(vendor_prefixes, {}, kVendorContext, /*host=*/true));
 }
 
 Subcontext* GetSubcontext() {
diff --git a/init/subcontext.h b/init/subcontext.h
index 93ebacea2..23c4a241c 100644
--- a/init/subcontext.h
+++ b/init/subcontext.h
@@ -36,8 +36,10 @@ static constexpr const char kTestContext[] = "test-test-test";
 
 class Subcontext {
   public:
-    Subcontext(std::vector<std::string> path_prefixes, std::string_view context, bool host = false)
+    Subcontext(std::vector<std::string> path_prefixes, std::vector<std::string> partitions,
+               std::string_view context, bool host = false)
         : path_prefixes_(std::move(path_prefixes)),
+          partitions_(std::move(partitions)),
           context_(context.begin(), context.end()),
           pid_(0) {
         if (!host) {
@@ -49,6 +51,7 @@ class Subcontext {
     Result<std::vector<std::string>> ExpandArgs(const std::vector<std::string>& args);
     void Restart();
     bool PathMatchesSubcontext(const std::string& path) const;
+    bool PartitionMatchesSubcontext(const std::string& partition) const;
     void SetApexList(std::vector<std::string>&& apex_list);
 
     const std::string& context() const { return context_; }
@@ -59,6 +62,7 @@ class Subcontext {
     Result<SubcontextReply> TransmitMessage(const SubcontextCommand& subcontext_command);
 
     std::vector<std::string> path_prefixes_;
+    std::vector<std::string> partitions_;
     std::vector<std::string> apex_list_;
     std::string context_;
     pid_t pid_;
diff --git a/init/subcontext_benchmark.cpp b/init/subcontext_benchmark.cpp
index ccef2f36a..172ee3173 100644
--- a/init/subcontext_benchmark.cpp
+++ b/init/subcontext_benchmark.cpp
@@ -33,7 +33,7 @@ static void BenchmarkSuccess(benchmark::State& state) {
         return;
     }
 
-    auto subcontext = Subcontext({"path"}, context);
+    auto subcontext = Subcontext({"path"}, {"partition"}, context);
     free(context);
 
     while (state.KeepRunning()) {
diff --git a/init/subcontext_test.cpp b/init/subcontext_test.cpp
index da1f45550..85a2f2a94 100644
--- a/init/subcontext_test.cpp
+++ b/init/subcontext_test.cpp
@@ -41,7 +41,7 @@ namespace init {
 
 template <typename F>
 void RunTest(F&& test_function) {
-    auto subcontext = Subcontext({"dummy_path"}, kTestContext);
+    auto subcontext = Subcontext({"dummy_path"}, {"dummy_partition"}, kTestContext);
     ASSERT_NE(0, subcontext.pid());
 
     test_function(subcontext);
@@ -177,6 +177,19 @@ TEST(subcontext, ExpandArgsFailure) {
     });
 }
 
+TEST(subcontext, PartitionMatchesSubcontext) {
+    RunTest([](auto& subcontext) {
+        static auto& existent_partition = "dummy_partition";
+        static auto& non_existent_partition = "not_dummy_partition";
+
+        auto existent_result = subcontext.PartitionMatchesSubcontext(existent_partition);
+        auto non_existent_result = subcontext.PartitionMatchesSubcontext(non_existent_partition);
+
+        ASSERT_TRUE(existent_result);
+        ASSERT_FALSE(non_existent_result);
+    });
+}
+
 BuiltinFunctionMap BuildTestFunctionMap() {
     // For CheckDifferentPid
     auto do_return_pids_as_error = [](const BuiltinArguments& args) -> Result<void> {
diff --git a/init/test_upgrade_mte/Android.bp b/init/test_upgrade_mte/Android.bp
index 1bfc76c69..dfea325a2 100644
--- a/init/test_upgrade_mte/Android.bp
+++ b/init/test_upgrade_mte/Android.bp
@@ -17,25 +17,34 @@ package {
 }
 
 cc_binary {
-  name: "mte_upgrade_test_helper",
-  srcs: ["mte_upgrade_test_helper.cpp"],
-  sanitize: {
-    memtag_heap: true,
-    diag: {
-      memtag_heap: false,
+    name: "mte_upgrade_test_helper",
+    srcs: ["mte_upgrade_test_helper.cpp"],
+    sanitize: {
+        memtag_heap: true,
+        diag: {
+            memtag_heap: false,
+        },
     },
-  },
-  init_rc: [
-    "mte_upgrade_test.rc",
-  ],
+    init_rc: [
+        "mte_upgrade_test.rc",
+    ],
 }
 
 java_test_host {
     name: "mte_upgrade_test",
     libs: ["tradefed"],
-    static_libs: ["frameworks-base-hostutils", "cts-install-lib-host"],
-    srcs:  ["src/**/MteUpgradeTest.java", ":libtombstone_proto-src"],
-    data: [":mte_upgrade_test_helper", "mte_upgrade_test.rc" ],
+    static_libs: [
+        "frameworks-base-hostutils",
+        "cts-install-lib-host",
+    ],
+    srcs: [
+        "src/**/MteUpgradeTest.java",
+        ":libtombstone_proto-src",
+    ],
+    device_first_data: [
+        ":mte_upgrade_test_helper",
+        "mte_upgrade_test.rc",
+    ],
     test_config: "AndroidTest.xml",
     test_suites: ["general-tests"],
 }
diff --git a/init/test_upgrade_mte/OWNERS b/init/test_upgrade_mte/OWNERS
index 79625dfb1..c95d3cfd0 100644
--- a/init/test_upgrade_mte/OWNERS
+++ b/init/test_upgrade_mte/OWNERS
@@ -1,5 +1,4 @@
 fmayer@google.com
 
 eugenis@google.com
-mitchp@google.com
 pcc@google.com
diff --git a/init/uevent.h b/init/uevent.h
index dc35fd968..e7ed2266e 100644
--- a/init/uevent.h
+++ b/init/uevent.h
@@ -26,8 +26,10 @@ struct Uevent {
     std::string action;
     std::string path;
     std::string subsystem;
+    std::string driver;
     std::string firmware;
     std::string partition_name;
+    std::string partition_uuid;
     std::string device_name;
     std::string modalias;
     int partition_num;
diff --git a/init/uevent_listener.cpp b/init/uevent_listener.cpp
index 5da67777d..d329c174f 100644
--- a/init/uevent_listener.cpp
+++ b/init/uevent_listener.cpp
@@ -36,6 +36,7 @@ static void ParseEvent(const char* msg, Uevent* uevent) {
     uevent->action.clear();
     uevent->path.clear();
     uevent->subsystem.clear();
+    uevent->driver.clear();
     uevent->firmware.clear();
     uevent->partition_name.clear();
     uevent->device_name.clear();
@@ -51,6 +52,9 @@ static void ParseEvent(const char* msg, Uevent* uevent) {
         } else if (!strncmp(msg, "SUBSYSTEM=", 10)) {
             msg += 10;
             uevent->subsystem = msg;
+        } else if (!strncmp(msg, "DRIVER=", 7)) {
+            msg += 7;
+            uevent->driver = msg;
         } else if (!strncmp(msg, "FIRMWARE=", 9)) {
             msg += 9;
             uevent->firmware = msg;
@@ -66,6 +70,9 @@ static void ParseEvent(const char* msg, Uevent* uevent) {
         } else if (!strncmp(msg, "PARTNAME=", 9)) {
             msg += 9;
             uevent->partition_name = msg;
+        } else if (!strncmp(msg, "PARTUUID=", 9)) {
+            msg += 9;
+            uevent->partition_uuid = msg;
         } else if (!strncmp(msg, "DEVNAME=", 8)) {
             msg += 8;
             uevent->device_name = msg;
@@ -82,7 +89,7 @@ static void ParseEvent(const char* msg, Uevent* uevent) {
     if (LOG_UEVENTS) {
         LOG(INFO) << "event { '" << uevent->action << "', '" << uevent->path << "', '"
                   << uevent->subsystem << "', '" << uevent->firmware << "', " << uevent->major
-                  << ", " << uevent->minor << " }";
+                  << ", " << uevent->minor << ", " << uevent->partition_uuid << " }";
     }
 }
 
diff --git a/init/ueventd.cpp b/init/ueventd.cpp
index 3f0d0e95b..cb6b851d6 100644
--- a/init/ueventd.cpp
+++ b/init/ueventd.cpp
@@ -353,10 +353,25 @@ int ueventd_main(int argc, char** argv) {
 
     auto ueventd_configuration = GetConfiguration();
 
-    uevent_handlers.emplace_back(std::make_unique<DeviceHandler>(
+    UeventListener uevent_listener(ueventd_configuration.uevent_socket_rcvbuf_size);
+
+    // Right after making DeviceHandler, replay all events looking for which
+    // block device has the boot partition. This lets us make symlinks
+    // for all of the other partitions on the same disk. Note that by the time
+    // we get here we know that the boot partition has already shown up (if
+    // we're looking for it) so just regenerating events is enough to know
+    // we'll see it.
+    std::unique_ptr<DeviceHandler> device_handler = std::make_unique<DeviceHandler>(
             std::move(ueventd_configuration.dev_permissions),
             std::move(ueventd_configuration.sysfs_permissions),
-            std::move(ueventd_configuration.subsystems), android::fs_mgr::GetBootDevices(), true));
+            std::move(ueventd_configuration.drivers), std::move(ueventd_configuration.subsystems),
+            android::fs_mgr::GetBootDevices(), android::fs_mgr::GetBootPartUuid(), true);
+    uevent_listener.RegenerateUevents([&](const Uevent& uevent) -> ListenerAction {
+        bool uuid_check_done = device_handler->CheckUeventForBootPartUuid(uevent);
+        return uuid_check_done ? ListenerAction::kStop : ListenerAction::kContinue;
+    });
+
+    uevent_handlers.emplace_back(std::move(device_handler));
     uevent_handlers.emplace_back(std::make_unique<FirmwareHandler>(
             std::move(ueventd_configuration.firmware_directories),
             std::move(ueventd_configuration.external_firmware_handlers)));
@@ -365,8 +380,6 @@ int ueventd_main(int argc, char** argv) {
         std::vector<std::string> base_paths = {"/odm/lib/modules", "/vendor/lib/modules"};
         uevent_handlers.emplace_back(std::make_unique<ModaliasHandler>(base_paths));
     }
-    UeventListener uevent_listener(ueventd_configuration.uevent_socket_rcvbuf_size);
-
     if (!android::base::GetBoolProperty(kColdBootDoneProp, false)) {
         ColdBoot cold_boot(uevent_listener, uevent_handlers,
                            ueventd_configuration.enable_parallel_restorecon,
diff --git a/init/ueventd_parser.cpp b/init/ueventd_parser.cpp
index 4395d8838..097ef09d7 100644
--- a/init/ueventd_parser.cpp
+++ b/init/ueventd_parser.cpp
@@ -264,6 +264,8 @@ UeventdConfiguration ParseConfig(const std::vector<std::string>& configs) {
     parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));
     parser.AddSectionParser("subsystem",
                             std::make_unique<SubsystemParser>(&ueventd_configuration.subsystems));
+    parser.AddSectionParser("driver",
+                            std::make_unique<SubsystemParser>(&ueventd_configuration.drivers));
 
     using namespace std::placeholders;
     parser.AddSingleLineParser(
diff --git a/init/ueventd_parser.h b/init/ueventd_parser.h
index 81f4e9d54..ffe6072df 100644
--- a/init/ueventd_parser.h
+++ b/init/ueventd_parser.h
@@ -27,6 +27,7 @@ namespace init {
 
 struct UeventdConfiguration {
     std::vector<Subsystem> subsystems;
+    std::vector<Subsystem> drivers;
     std::vector<SysfsPermissions> sysfs_permissions;
     std::vector<Permissions> dev_permissions;
     std::vector<std::string> firmware_directories;
diff --git a/init/ueventd_parser_test.cpp b/init/ueventd_parser_test.cpp
index 41924e235..6d910398a 100644
--- a/init/ueventd_parser_test.cpp
+++ b/init/ueventd_parser_test.cpp
@@ -106,7 +106,32 @@ subsystem test_devpath_dirname
             {"test_devname2", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev"},
             {"test_devpath_dirname", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev/graphics"}};
 
-    TestUeventdFile(ueventd_file, {subsystems, {}, {}, {}, {}, {}});
+    TestUeventdFile(ueventd_file, {subsystems, {}, {}, {}, {}, {}, {}});
+}
+
+TEST(ueventd_parser, Drivers) {
+    auto ueventd_file = R"(
+driver test_devname
+    devname uevent_devname
+
+driver test_devpath_no_dirname
+    devname uevent_devpath
+
+driver test_devname2
+    devname uevent_devname
+
+driver test_devpath_dirname
+    devname uevent_devpath
+    dirname /dev/graphics
+)";
+
+    auto drivers = std::vector<Subsystem>{
+            {"test_devname", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev"},
+            {"test_devpath_no_dirname", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev"},
+            {"test_devname2", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev"},
+            {"test_devpath_dirname", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev/graphics"}};
+
+    TestUeventdFile(ueventd_file, {{}, drivers, {}, {}, {}, {}, {}, {}});
 }
 
 TEST(ueventd_parser, Permissions) {
@@ -132,7 +157,7 @@ TEST(ueventd_parser, Permissions) {
             {"/sys/devices/virtual/*/input", "poll_delay", 0660, AID_ROOT, AID_INPUT, true},
     };
 
-    TestUeventdFile(ueventd_file, {{}, sysfs_permissions, permissions, {}, {}, {}});
+    TestUeventdFile(ueventd_file, {{}, {}, sysfs_permissions, permissions, {}, {}, {}});
 }
 
 TEST(ueventd_parser, FirmwareDirectories) {
@@ -148,7 +173,7 @@ firmware_directories /more
             "/more",
     };
 
-    TestUeventdFile(ueventd_file, {{}, {}, {}, firmware_directories, {}, {}});
+    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, firmware_directories, {}, {}});
 }
 
 TEST(ueventd_parser, ExternalFirmwareHandlers) {
@@ -214,7 +239,7 @@ external_firmware_handler /devices/path/firmware/something004.bin radio radio "/
             },
     };
 
-    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, external_firmware_handlers, {}});
+    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, external_firmware_handlers, {}});
 }
 
 TEST(ueventd_parser, ExternalFirmwareHandlersDuplicate) {
@@ -232,7 +257,7 @@ external_firmware_handler devpath root handler_path2
             },
     };
 
-    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, external_firmware_handlers, {}});
+    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, external_firmware_handlers, {}});
 }
 
 TEST(ueventd_parser, ParallelRestoreconDirs) {
@@ -246,7 +271,7 @@ parallel_restorecon_dir /sys/devices
             "/sys/devices",
     };
 
-    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, parallel_restorecon_dirs});
+    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, {}, parallel_restorecon_dirs});
 }
 
 TEST(ueventd_parser, UeventSocketRcvbufSize) {
@@ -255,7 +280,7 @@ uevent_socket_rcvbuf_size 8k
 uevent_socket_rcvbuf_size 8M
 )";
 
-    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, {}, false, 8 * 1024 * 1024});
+    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, {}, {}, false, 8 * 1024 * 1024});
 }
 
 TEST(ueventd_parser, EnabledDisabledLines) {
@@ -265,7 +290,7 @@ parallel_restorecon enabled
 modalias_handling disabled
 )";
 
-    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, {}, false, 0, true});
+    TestUeventdFile(ueventd_file, {{}, {}, {}, {}, {}, {}, {}, false, 0, true});
 
     auto ueventd_file2 = R"(
 parallel_restorecon enabled
@@ -273,7 +298,7 @@ modalias_handling enabled
 parallel_restorecon disabled
 )";
 
-    TestUeventdFile(ueventd_file2, {{}, {}, {}, {}, {}, {}, true, 0, false});
+    TestUeventdFile(ueventd_file2, {{}, {}, {}, {}, {}, {}, {}, true, 0, false});
 }
 
 TEST(ueventd_parser, AllTogether) {
@@ -286,6 +311,9 @@ firmware_directories /first/ /second /third
 subsystem test_devname
     devname uevent_devname
 
+driver d_test_devpath
+    devname uevent_devpath
+
 /dev/graphics/*           0660   root       graphics
 
 subsystem test_devpath_no_dirname
@@ -303,6 +331,10 @@ subsystem test_devpath_dirname
     devname uevent_devpath
     dirname /dev/graphics
 
+driver d_test_devname_dirname
+    devname uevent_devname
+    dirname /dev/sound
+
 /dev/*/test               0660   root       system
 /sys/devices/virtual/*/input   poll_delay  0660  root   input    no_fnm_pathname
 firmware_directories /more
@@ -325,6 +357,10 @@ parallel_restorecon_dir /sys/devices
             {"test_devname2", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev"},
             {"test_devpath_dirname", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev/graphics"}};
 
+    auto drivers = std::vector<Subsystem>{
+            {"d_test_devpath", Subsystem::DEVNAME_UEVENT_DEVPATH, "/dev"},
+            {"d_test_devname_dirname", Subsystem::DEVNAME_UEVENT_DEVNAME, "/dev/graphics"}};
+
     auto permissions = std::vector<Permissions>{
             {"/dev/rtc0", 0640, AID_SYSTEM, AID_SYSTEM, false},
             {"/dev/graphics/*", 0660, AID_ROOT, AID_GRAPHICS, false},
@@ -356,7 +392,7 @@ parallel_restorecon_dir /sys/devices
     size_t uevent_socket_rcvbuf_size = 6 * 1024 * 1024;
 
     TestUeventdFile(ueventd_file,
-                    {subsystems, sysfs_permissions, permissions, firmware_directories,
+                    {subsystems, drivers, sysfs_permissions, permissions, firmware_directories,
                      external_firmware_handlers, parallel_restorecon_dirs, true,
                      uevent_socket_rcvbuf_size, true});
 }
diff --git a/init/util.h b/init/util.h
index 056539181..aa24123df 100644
--- a/init/util.h
+++ b/init/util.h
@@ -18,7 +18,6 @@
 
 #include <sys/stat.h>
 #include <sys/types.h>
-#include <sys/unistd.h>
 
 #include <chrono>
 #include <functional>
@@ -109,10 +108,6 @@ inline constexpr bool IsMicrodroid() {
 #endif
 }
 
-inline bool IsArcvm() {
-    return !access("/is_arcvm", F_OK);
-}
-
 bool Has32BitAbi();
 
 std::string GetApexNameFromFileName(const std::string& path);
diff --git a/libcutils/Android.bp b/libcutils/Android.bp
index 3c3eeb663..ec9b75493 100644
--- a/libcutils/Android.bp
+++ b/libcutils/Android.bp
@@ -1,4 +1,5 @@
 package {
+    default_team: "trendy_team_native_tools_libraries",
     default_applicable_licenses: ["system_core_libcutils_license"],
 }
 
@@ -20,6 +21,17 @@ filegroup {
     srcs: ["include/private/android_filesystem_config.h"],
 }
 
+rust_bindgen {
+    name: "libandroid_ids",
+    crate_name: "android_ids",
+    source_stem: "bindings",
+    wrapper_src: "rust/aid_bindings.h",
+    header_libs: ["libcutils_headers"],
+    visibility: [
+        "//system/bpf/loader",
+    ],
+}
+
 cc_defaults {
     name: "libcutils_defaults",
     cflags: [
@@ -278,7 +290,6 @@ test_libraries = [
     "liblog",
     "libbase",
     "libprocessgroup",
-    "libcgrouprc",
 ]
 
 cc_test {
@@ -301,7 +312,7 @@ cc_defaults {
         android: {
             static_executable: true,
             static_libs: [
-                "libcgrouprc_format",
+                "libprocessgroup_util",
             ] + test_libraries + always_static_test_libraries,
         },
         not_windows: {
diff --git a/libcutils/ashmem-dev.cpp b/libcutils/ashmem-dev.cpp
index 46b8ef263..cebfa5d12 100644
--- a/libcutils/ashmem-dev.cpp
+++ b/libcutils/ashmem-dev.cpp
@@ -114,8 +114,14 @@ static bool __has_memfd_support() {
     // Check if kernel support exists, otherwise fall back to ashmem.
     // This code needs to build on old API levels, so we can't use the libc
     // wrapper.
+    //
+    // MFD_NOEXEC_SEAL is used to match the semantics of the ashmem device,
+    // which did not have executable permissions. This also seals the executable
+    // permissions of the buffer (i.e. they cannot be changed by fchmod()).
+    //
+    // MFD_NOEXEC_SEAL implies MFD_ALLOW_SEALING.
     android::base::unique_fd fd(
-            syscall(__NR_memfd_create, "test_android_memfd", MFD_CLOEXEC | MFD_ALLOW_SEALING));
+            syscall(__NR_memfd_create, "test_android_memfd", MFD_CLOEXEC | MFD_NOEXEC_SEAL));
     if (fd == -1) {
         ALOGE("memfd_create failed: %s, no memfd support.\n", strerror(errno));
         return false;
@@ -289,7 +295,13 @@ int ashmem_valid(int fd)
 static int memfd_create_region(const char* name, size_t size) {
     // This code needs to build on old API levels, so we can't use the libc
     // wrapper.
-    android::base::unique_fd fd(syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING));
+    //
+    // MFD_NOEXEC_SEAL to match the semantics of the ashmem device, which did
+    // not have executable permissions. This also seals the executable
+    // permissions of the buffer (i.e. they cannot be changed by fchmod()).
+    //
+    // MFD_NOEXEC_SEAL implies MFD_ALLOW_SEALING.
+    android::base::unique_fd fd(syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_NOEXEC_SEAL));
 
     if (fd == -1) {
         ALOGE("memfd_create(%s, %zd) failed: %s\n", name, size, strerror(errno));
diff --git a/libcutils/include/private/android_filesystem_config.h b/libcutils/include/private/android_filesystem_config.h
index b0bddf501..2aaafbe24 100644
--- a/libcutils/include/private/android_filesystem_config.h
+++ b/libcutils/include/private/android_filesystem_config.h
@@ -143,6 +143,7 @@
 #define AID_PRNG_SEEDER 1092         /* PRNG seeder daemon */
 #define AID_UPROBESTATS 1093         /* uid for uprobestats */
 #define AID_CROS_EC 1094             /* uid for accessing ChromeOS EC (cros_ec) */
+#define AID_MMD 1095                 /* uid for memory management daemon */
 // Additions to this file must be made in AOSP, *not* in internal branches.
 // You will also need to update expect_ids() in bionic/tests/grp_pwd_test.cpp.
 
diff --git a/libcutils/rust/aid_bindings.h b/libcutils/rust/aid_bindings.h
new file mode 100644
index 000000000..1b175a26f
--- /dev/null
+++ b/libcutils/rust/aid_bindings.h
@@ -0,0 +1,16 @@
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
+#include <private/android_filesystem_config.h>
diff --git a/libcutils/sched_policy_test.cpp b/libcutils/sched_policy_test.cpp
index 50bd6d0b8..264174309 100644
--- a/libcutils/sched_policy_test.cpp
+++ b/libcutils/sched_policy_test.cpp
@@ -67,13 +67,6 @@ static void AssertPolicy(SchedPolicy expected_policy) {
 }
 
 TEST(SchedPolicy, set_sched_policy) {
-    if (!schedboost_enabled()) {
-        // schedboost_enabled() (i.e. CONFIG_CGROUP_SCHEDTUNE) is optional;
-        // it's only needed on devices using energy-aware scheduler.
-        GTEST_LOG_(INFO) << "skipping test that requires CONFIG_CGROUP_SCHEDTUNE";
-        return;
-    }
-
     ASSERT_EQ(0, set_sched_policy(0, SP_BACKGROUND));
     ASSERT_EQ(0, set_cpuset_policy(0, SP_BACKGROUND));
     AssertPolicy(SP_BACKGROUND);
diff --git a/libmodprobe/Android.bp b/libmodprobe/Android.bp
index 12906cc39..78b4c83e3 100644
--- a/libmodprobe/Android.bp
+++ b/libmodprobe/Android.bp
@@ -13,6 +13,7 @@ cc_library_static {
     vendor_ramdisk_available: true,
     host_supported: true,
     srcs: [
+        "exthandler.cpp",
         "libmodprobe.cpp",
         "libmodprobe_ext.cpp",
     ],
@@ -30,6 +31,7 @@ cc_test {
     ],
     local_include_dirs: ["include/"],
     srcs: [
+        "exthandler.cpp",
         "libmodprobe_test.cpp",
         "libmodprobe.cpp",
         "libmodprobe_ext_test.cpp",
diff --git a/libmodprobe/exthandler.cpp b/libmodprobe/exthandler.cpp
new file mode 100644
index 000000000..f48c25976
--- /dev/null
+++ b/libmodprobe/exthandler.cpp
@@ -0,0 +1,131 @@
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
+#include <exthandler/exthandler.h>
+
+#include <android-base/chrono_utils.h>
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/parseint.h>
+#include <android-base/strings.h>
+#include <android-base/unique_fd.h>
+#include <fnmatch.h>
+#include <grp.h>
+#include <pwd.h>
+#include <sys/wait.h>
+
+using android::base::ErrnoError;
+using android::base::Error;
+using android::base::ReadFdToString;
+using android::base::Result;
+using android::base::Split;
+using android::base::Trim;
+using android::base::unique_fd;
+
+Result<std::string> RunExternalHandler(const std::string& handler, uid_t uid, gid_t gid,
+                                       std::unordered_map<std::string, std::string>& envs_map) {
+    unique_fd child_stdout;
+    unique_fd parent_stdout;
+    if (!Socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &child_stdout, &parent_stdout)) {
+        return ErrnoError() << "Socketpair() for stdout failed";
+    }
+
+    unique_fd child_stderr;
+    unique_fd parent_stderr;
+    if (!Socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, &child_stderr, &parent_stderr)) {
+        return ErrnoError() << "Socketpair() for stderr failed";
+    }
+
+    signal(SIGCHLD, SIG_DFL);
+
+    auto pid = fork();
+    if (pid < 0) {
+        return ErrnoError() << "fork() failed";
+    }
+
+    if (pid == 0) {
+        for (auto it = envs_map.begin(); it != envs_map.end(); ++it) {
+            setenv(it->first.c_str(), it->second.c_str(), 1);
+        }
+        parent_stdout.reset();
+        parent_stderr.reset();
+        close(STDOUT_FILENO);
+        close(STDERR_FILENO);
+        dup2(child_stdout.get(), STDOUT_FILENO);
+        dup2(child_stderr.get(), STDERR_FILENO);
+
+        auto args = Split(handler, " ");
+        std::vector<char*> c_args;
+        for (auto& arg : args) {
+            c_args.emplace_back(arg.data());
+        }
+        c_args.emplace_back(nullptr);
+
+        if (gid != 0) {
+            if (setgid(gid) != 0) {
+                fprintf(stderr, "setgid() failed: %s", strerror(errno));
+                _exit(EXIT_FAILURE);
+            }
+        }
+
+        if (setuid(uid) != 0) {
+            fprintf(stderr, "setuid() failed: %s", strerror(errno));
+            _exit(EXIT_FAILURE);
+        }
+
+        execv(c_args[0], c_args.data());
+        fprintf(stderr, "exec() failed: %s", strerror(errno));
+        _exit(EXIT_FAILURE);
+    }
+
+    child_stdout.reset();
+    child_stderr.reset();
+
+    int status;
+    pid_t waited_pid = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
+    if (waited_pid == -1) {
+        return ErrnoError() << "waitpid() failed";
+    }
+
+    std::string stdout_content;
+    if (!ReadFdToString(parent_stdout.get(), &stdout_content)) {
+        return ErrnoError() << "ReadFdToString() for stdout failed";
+    }
+
+    std::string stderr_content;
+    if (ReadFdToString(parent_stderr.get(), &stderr_content)) {
+        auto messages = Split(stderr_content, "\n");
+        for (const auto& message : messages) {
+            if (!message.empty()) {
+                LOG(ERROR) << "External Handler: " << message;
+            }
+        }
+    } else {
+        LOG(ERROR) << "ReadFdToString() for stderr failed";
+    }
+
+    if (WIFEXITED(status)) {
+        if (WEXITSTATUS(status) == EXIT_SUCCESS) {
+            return Trim(stdout_content);
+        } else {
+            return Error() << "exited with status " << WEXITSTATUS(status);
+        }
+    } else if (WIFSIGNALED(status)) {
+        return Error() << "killed by signal " << WTERMSIG(status);
+    }
+
+    return Error() << "unexpected exit status " << status;
+}
diff --git a/libmodprobe/include/exthandler/exthandler.h b/libmodprobe/include/exthandler/exthandler.h
new file mode 100644
index 000000000..232aa95a4
--- /dev/null
+++ b/libmodprobe/include/exthandler/exthandler.h
@@ -0,0 +1,23 @@
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
+#pragma once
+#include <android-base/result.h>
+#include <string>
+
+android::base::Result<std::string> RunExternalHandler(
+        const std::string& handler, uid_t uid, gid_t gid,
+        std::unordered_map<std::string, std::string>& envs_map);
diff --git a/libmodprobe/include/modprobe/modprobe.h b/libmodprobe/include/modprobe/modprobe.h
index d7a90c488..7b691b13a 100644
--- a/libmodprobe/include/modprobe/modprobe.h
+++ b/libmodprobe/include/modprobe/modprobe.h
@@ -59,6 +59,7 @@ class Modprobe {
     bool ParseSoftdepCallback(const std::vector<std::string>& args);
     bool ParseLoadCallback(const std::vector<std::string>& args);
     bool ParseOptionsCallback(const std::vector<std::string>& args);
+    bool ParseDynOptionsCallback(const std::vector<std::string>& args);
     bool ParseBlocklistCallback(const std::vector<std::string>& args);
     void ParseKernelCmdlineOptions();
     void ParseCfg(const std::string& cfg, std::function<bool(const std::vector<std::string>&)> f);
diff --git a/libmodprobe/libmodprobe.cpp b/libmodprobe/libmodprobe.cpp
index 8cc0b9b2e..bdd114c4b 100644
--- a/libmodprobe/libmodprobe.cpp
+++ b/libmodprobe/libmodprobe.cpp
@@ -17,8 +17,11 @@
 #include <modprobe/modprobe.h>
 
 #include <fnmatch.h>
+#include <grp.h>
+#include <pwd.h>
 #include <sys/stat.h>
 #include <sys/syscall.h>
+#include <sys/wait.h>
 
 #include <algorithm>
 #include <map>
@@ -30,9 +33,12 @@
 #include <android-base/chrono_utils.h>
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/parseint.h>
 #include <android-base/strings.h>
 #include <android-base/unique_fd.h>
 
+#include "exthandler/exthandler.h"
+
 std::string Modprobe::MakeCanonical(const std::string& module_path) {
     auto start = module_path.find_last_of('/');
     if (start == std::string::npos) {
@@ -164,6 +170,10 @@ bool Modprobe::ParseOptionsCallback(const std::vector<std::string>& args) {
     auto it = args.begin();
     const std::string& type = *it++;
 
+    if (type == "dyn_options") {
+        return ParseDynOptionsCallback(std::vector<std::string>(it, args.end()));
+    }
+
     if (type != "options") {
         LOG(ERROR) << "non-options line encountered in modules.options";
         return false;
@@ -197,6 +207,57 @@ bool Modprobe::ParseOptionsCallback(const std::vector<std::string>& args) {
     return true;
 }
 
+bool Modprobe::ParseDynOptionsCallback(const std::vector<std::string>& args) {
+    auto it = args.begin();
+    int arg_size = 3;
+
+    if (args.size() < arg_size) {
+        LOG(ERROR) << "dyn_options lines in modules.options must have at least" << arg_size
+                   << " entries, not " << args.size();
+        return false;
+    }
+
+    const std::string& module = *it++;
+
+    const std::string& canonical_name = MakeCanonical(module);
+    if (canonical_name.empty()) {
+        return false;
+    }
+
+    const std::string& pwnam = *it++;
+    passwd* pwd = getpwnam(pwnam.c_str());
+    if (!pwd) {
+        LOG(ERROR) << "invalid handler uid'" << pwnam << "'";
+        return false;
+    }
+
+    std::string handler_with_args =
+            android::base::Join(std::vector<std::string>(it, args.end()), ' ');
+    handler_with_args.erase(std::remove(handler_with_args.begin(), handler_with_args.end(), '\"'),
+                            handler_with_args.end());
+
+    LOG(DEBUG) << "Launching external module options handler: '" << handler_with_args
+               << " for module: " << module;
+
+    // There is no need to set envs for external module options handler - pass
+    // empty map.
+    std::unordered_map<std::string, std::string> envs_map;
+    auto result = RunExternalHandler(handler_with_args, pwd->pw_uid, 0, envs_map);
+    if (!result.ok()) {
+        LOG(ERROR) << "External module handler failed: " << result.error();
+        return false;
+    }
+
+    LOG(INFO) << "Dynamic options for module: " << module << " are '" << *result << "'";
+
+    auto [unused, inserted] = this->module_options_.emplace(canonical_name, *result);
+    if (!inserted) {
+        LOG(ERROR) << "multiple options lines present for module " << module;
+        return false;
+    }
+    return true;
+}
+
 bool Modprobe::ParseBlocklistCallback(const std::vector<std::string>& args) {
     auto it = args.begin();
     const std::string& type = *it++;
diff --git a/libprocessgroup/Android.bp b/libprocessgroup/Android.bp
index a60bfe973..1e76e766f 100644
--- a/libprocessgroup/Android.bp
+++ b/libprocessgroup/Android.bp
@@ -17,7 +17,7 @@ soong_config_module_type {
 
 libprocessgroup_flag_aware_cc_defaults {
     name: "libprocessgroup_build_flags_cc",
-    cpp_std: "gnu++20",
+    cpp_std: "gnu++23",
     soong_config_variables: {
         memcg_v2_force_enabled: {
             cflags: [
@@ -75,7 +75,6 @@ cc_library {
     double_loadable: true,
     shared_libs: [
         "libbase",
-        "libcgrouprc",
     ],
     static_libs: [
         "libjsoncpp",
@@ -111,10 +110,10 @@ cc_test {
     ],
     shared_libs: [
         "libbase",
-        "libcgrouprc",
         "libprocessgroup",
     ],
     static_libs: [
         "libgmock",
+        "libprocessgroup_util",
     ],
 }
diff --git a/libprocessgroup/OWNERS b/libprocessgroup/OWNERS
index d5aa7211a..accd7dfcc 100644
--- a/libprocessgroup/OWNERS
+++ b/libprocessgroup/OWNERS
@@ -1,4 +1,3 @@
 # Bug component: 1293033
 surenb@google.com
-tjmercier@google.com
-carlosgalo@google.com
+tjmercier@google.com
\ No newline at end of file
diff --git a/libprocessgroup/cgroup_map.cpp b/libprocessgroup/cgroup_map.cpp
index fb01cfda9..32bef13a1 100644
--- a/libprocessgroup/cgroup_map.cpp
+++ b/libprocessgroup/cgroup_map.cpp
@@ -25,12 +25,10 @@
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/stringprintf.h>
-#include <android-base/strings.h>
 #include <cgroup_map.h>
 #include <processgroup/processgroup.h>
 #include <processgroup/util.h>
 
-using android::base::StartsWith;
 using android::base::StringPrintf;
 using android::base::WriteStringToFile;
 
@@ -40,17 +38,17 @@ static constexpr const char* CGROUP_TASKS_FILE_V2 = "/cgroup.threads";
 
 uint32_t CgroupControllerWrapper::version() const {
     CHECK(HasValue());
-    return ACgroupController_getVersion(controller_);
+    return controller_->version();
 }
 
 const char* CgroupControllerWrapper::name() const {
     CHECK(HasValue());
-    return ACgroupController_getName(controller_);
+    return controller_->name();
 }
 
 const char* CgroupControllerWrapper::path() const {
     CHECK(HasValue());
-    return ACgroupController_getPath(controller_);
+    return controller_->path();
 }
 
 bool CgroupControllerWrapper::HasValue() const {
@@ -62,7 +60,7 @@ bool CgroupControllerWrapper::IsUsable() {
 
     if (state_ == UNKNOWN) {
         if (__builtin_available(android 30, *)) {
-            uint32_t flags = ACgroupController_getFlags(controller_);
+            uint32_t flags = controller_->flags();
             state_ = (flags & CGROUPRC_CONTROLLER_FLAG_MOUNTED) != 0 ? USABLE : MISSING;
         } else {
             state_ = access(GetProcsFilePath("", 0, 0).c_str(), F_OK) == 0 ? USABLE : MISSING;
@@ -129,8 +127,8 @@ bool CgroupControllerWrapper::GetTaskGroup(pid_t tid, std::string* group) const
 }
 
 CgroupMap::CgroupMap() {
-    if (!LoadRcFile()) {
-        LOG(ERROR) << "CgroupMap::LoadRcFile called for [" << getpid() << "] failed";
+    if (!LoadDescriptors()) {
+        LOG(ERROR) << "CgroupMap::LoadDescriptors called for [" << getpid() << "] failed";
     }
 }
 
@@ -141,9 +139,9 @@ CgroupMap& CgroupMap::GetInstance() {
     return *instance;
 }
 
-bool CgroupMap::LoadRcFile() {
+bool CgroupMap::LoadDescriptors() {
     if (!loaded_) {
-        loaded_ = (ACgroupFile_getVersion() != 0);
+        loaded_ = ReadDescriptors(&descriptors_);
     }
     return loaded_;
 }
@@ -151,43 +149,30 @@ bool CgroupMap::LoadRcFile() {
 void CgroupMap::Print() const {
     if (!loaded_) {
         LOG(ERROR) << "CgroupMap::Print called for [" << getpid()
-                   << "] failed, RC file was not initialized properly";
+                   << "] failed, cgroups were not initialized properly";
         return;
     }
-    LOG(INFO) << "File version = " << ACgroupFile_getVersion();
-    LOG(INFO) << "File controller count = " << ACgroupFile_getControllerCount();
+    LOG(INFO) << "Controller count = " << descriptors_.size();
 
     LOG(INFO) << "Mounted cgroups:";
 
-    auto controller_count = ACgroupFile_getControllerCount();
-    for (uint32_t i = 0; i < controller_count; ++i) {
-        const ACgroupController* controller = ACgroupFile_getController(i);
-        if (__builtin_available(android 30, *)) {
-            LOG(INFO) << "\t" << ACgroupController_getName(controller) << " ver "
-                      << ACgroupController_getVersion(controller) << " path "
-                      << ACgroupController_getPath(controller) << " flags "
-                      << ACgroupController_getFlags(controller);
-        } else {
-            LOG(INFO) << "\t" << ACgroupController_getName(controller) << " ver "
-                      << ACgroupController_getVersion(controller) << " path "
-                      << ACgroupController_getPath(controller);
-        }
+    for (const auto& [name, descriptor] : descriptors_) {
+        LOG(INFO) << "\t" << descriptor.controller()->name() << " ver "
+                  << descriptor.controller()->version() << " path "
+                  << descriptor.controller()->path() << " flags "
+                  << descriptor.controller()->flags();
     }
 }
 
 CgroupControllerWrapper CgroupMap::FindController(const std::string& name) const {
     if (!loaded_) {
         LOG(ERROR) << "CgroupMap::FindController called for [" << getpid()
-                   << "] failed, RC file was not initialized properly";
+                   << "] failed, cgroups were not initialized properly";
         return CgroupControllerWrapper(nullptr);
     }
 
-    auto controller_count = ACgroupFile_getControllerCount();
-    for (uint32_t i = 0; i < controller_count; ++i) {
-        const ACgroupController* controller = ACgroupFile_getController(i);
-        if (name == ACgroupController_getName(controller)) {
-            return CgroupControllerWrapper(controller);
-        }
+    if (const auto it = descriptors_.find(name); it != descriptors_.end()) {
+        return CgroupControllerWrapper(it->second.controller());
     }
 
     return CgroupControllerWrapper(nullptr);
@@ -196,47 +181,19 @@ CgroupControllerWrapper CgroupMap::FindController(const std::string& name) const
 CgroupControllerWrapper CgroupMap::FindControllerByPath(const std::string& path) const {
     if (!loaded_) {
         LOG(ERROR) << "CgroupMap::FindControllerByPath called for [" << getpid()
-                   << "] failed, RC file was not initialized properly";
+                   << "] failed, cgroups were not initialized properly";
         return CgroupControllerWrapper(nullptr);
     }
 
-    auto controller_count = ACgroupFile_getControllerCount();
-    for (uint32_t i = 0; i < controller_count; ++i) {
-        const ACgroupController* controller = ACgroupFile_getController(i);
-        if (StartsWith(path, ACgroupController_getPath(controller))) {
-            return CgroupControllerWrapper(controller);
+    for (const auto& [name, descriptor] : descriptors_) {
+        if (path.starts_with(descriptor.controller()->path())) {
+            return CgroupControllerWrapper(descriptor.controller());
         }
     }
 
     return CgroupControllerWrapper(nullptr);
 }
 
-int CgroupMap::ActivateControllers(const std::string& path) const {
-    if (__builtin_available(android 30, *)) {
-        auto controller_count = ACgroupFile_getControllerCount();
-        for (uint32_t i = 0; i < controller_count; ++i) {
-            const ACgroupController* controller = ACgroupFile_getController(i);
-            const uint32_t flags = ACgroupController_getFlags(controller);
-            uint32_t max_activation_depth = UINT32_MAX;
-            if (__builtin_available(android 36, *)) {
-                max_activation_depth = ACgroupController_getMaxActivationDepth(controller);
-            }
-            const int depth = util::GetCgroupDepth(ACgroupController_getPath(controller), path);
-
-            if (flags & CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION && depth < max_activation_depth) {
-                std::string str("+");
-                str.append(ACgroupController_getName(controller));
-                if (!WriteStringToFile(str, path + "/cgroup.subtree_control")) {
-                    if (flags & CGROUPRC_CONTROLLER_FLAG_OPTIONAL) {
-                        PLOG(WARNING) << "Activation of cgroup controller " << str
-                                      << " failed in path " << path;
-                    } else {
-                        return -errno;
-                    }
-                }
-            }
-        }
-        return 0;
-    }
-    return -ENOSYS;
+bool CgroupMap::ActivateControllers(const std::string& path) const {
+    return ::ActivateControllers(path, descriptors_);
 }
diff --git a/libprocessgroup/cgroup_map.h b/libprocessgroup/cgroup_map.h
index 364279414..fb9907645 100644
--- a/libprocessgroup/cgroup_map.h
+++ b/libprocessgroup/cgroup_map.h
@@ -18,15 +18,17 @@
 
 #include <sys/types.h>
 
+#include <cstdint>
 #include <string>
 
-#include <android/cgrouprc.h>
+#include <processgroup/cgroup_controller.h>
+#include <processgroup/util.h>
 
-// Convenient wrapper of an ACgroupController pointer.
+// Convenient wrapper of a CgroupController pointer.
 class CgroupControllerWrapper {
   public:
     // Does not own controller
-    explicit CgroupControllerWrapper(const ACgroupController* controller)
+    explicit CgroupControllerWrapper(const CgroupController* controller)
         : controller_(controller) {}
 
     uint32_t version() const;
@@ -47,7 +49,7 @@ class CgroupControllerWrapper {
         MISSING = 2,
     };
 
-    const ACgroupController* controller_ = nullptr;
+    const CgroupController* controller_ = nullptr; // CgroupMap owns the object behind this pointer
     ControllerState state_ = ControllerState::UNKNOWN;
 };
 
@@ -56,11 +58,12 @@ class CgroupMap {
     static CgroupMap& GetInstance();
     CgroupControllerWrapper FindController(const std::string& name) const;
     CgroupControllerWrapper FindControllerByPath(const std::string& path) const;
-    int ActivateControllers(const std::string& path) const;
+    bool ActivateControllers(const std::string& path) const;
 
   private:
     bool loaded_ = false;
+    CgroupDescriptorMap descriptors_;
     CgroupMap();
-    bool LoadRcFile();
+    bool LoadDescriptors();
     void Print() const;
 };
diff --git a/libprocessgroup/cgrouprc/Android.bp b/libprocessgroup/cgrouprc/Android.bp
index cb912476e..9e46b8e7c 100644
--- a/libprocessgroup/cgrouprc/Android.bp
+++ b/libprocessgroup/cgrouprc/Android.bp
@@ -19,9 +19,6 @@ package {
 cc_library {
     name: "libcgrouprc",
     host_supported: true,
-    ramdisk_available: true,
-    vendor_ramdisk_available: true,
-    recovery_available: true,
     // Do not ever mark this as vendor_available; otherwise, vendor modules
     // that links to the static library will behave unexpectedly. All on-device
     // modules should use libprocessgroup which links to the LL-NDK library
@@ -49,7 +46,8 @@ cc_library {
         "libbase",
     ],
     static_libs: [
-        "libcgrouprc_format",
+        "libjsoncpp",
+        "libprocessgroup_util",
     ],
     stubs: {
         symbol_file: "libcgrouprc.map.txt",
diff --git a/libprocessgroup/cgrouprc/a_cgroup_controller.cpp b/libprocessgroup/cgrouprc/a_cgroup_controller.cpp
index 889b3becf..5a326e55d 100644
--- a/libprocessgroup/cgrouprc/a_cgroup_controller.cpp
+++ b/libprocessgroup/cgrouprc/a_cgroup_controller.cpp
@@ -32,11 +32,6 @@ uint32_t ACgroupController_getFlags(const ACgroupController* controller) {
     return controller->flags();
 }
 
-uint32_t ACgroupController_getMaxActivationDepth(const ACgroupController* controller) {
-    CHECK(controller != nullptr);
-    return controller->max_activation_depth();
-}
-
 const char* ACgroupController_getName(const ACgroupController* controller) {
     CHECK(controller != nullptr);
     return controller->name();
diff --git a/libprocessgroup/cgrouprc/a_cgroup_file.cpp b/libprocessgroup/cgrouprc/a_cgroup_file.cpp
index e26d84114..33c8376f4 100644
--- a/libprocessgroup/cgrouprc/a_cgroup_file.cpp
+++ b/libprocessgroup/cgrouprc/a_cgroup_file.cpp
@@ -14,93 +14,51 @@
  * limitations under the License.
  */
 
-#include <sys/mman.h>
-#include <sys/stat.h>
-
-#include <memory>
+#include <iterator>
 
 #include <android-base/logging.h>
-#include <android-base/stringprintf.h>
-#include <android-base/unique_fd.h>
 #include <android/cgrouprc.h>
-#include <processgroup/processgroup.h>
+#include <processgroup/util.h>
 
 #include "cgrouprc_internal.h"
 
-using android::base::StringPrintf;
-using android::base::unique_fd;
-
-using android::cgrouprc::format::CgroupController;
-using android::cgrouprc::format::CgroupFile;
-
-static CgroupFile* LoadRcFile() {
-    struct stat sb;
-
-    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_RC_PATH, O_RDONLY | O_CLOEXEC)));
-    if (fd < 0) {
-        PLOG(ERROR) << "open() failed for " << CGROUPS_RC_PATH;
-        return nullptr;
-    }
-
-    if (fstat(fd, &sb) < 0) {
-        PLOG(ERROR) << "fstat() failed for " << CGROUPS_RC_PATH;
-        return nullptr;
-    }
-
-    size_t file_size = sb.st_size;
-    if (file_size < sizeof(CgroupFile)) {
-        LOG(ERROR) << "Invalid file format " << CGROUPS_RC_PATH;
+static CgroupDescriptorMap* LoadDescriptors() {
+    CgroupDescriptorMap* descriptors = new CgroupDescriptorMap;
+    if (!ReadDescriptors(descriptors)) {
+        LOG(ERROR) << "Failed to load cgroup description file";
         return nullptr;
     }
-
-    CgroupFile* file_data = (CgroupFile*)mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
-    if (file_data == MAP_FAILED) {
-        PLOG(ERROR) << "Failed to mmap " << CGROUPS_RC_PATH;
-        return nullptr;
-    }
-
-    if (file_data->version_ != CgroupFile::FILE_CURR_VERSION) {
-        LOG(ERROR) << CGROUPS_RC_PATH << " file version mismatch";
-        munmap(file_data, file_size);
-        return nullptr;
-    }
-
-    auto expected = sizeof(CgroupFile) + file_data->controller_count_ * sizeof(CgroupController);
-    if (file_size != expected) {
-        LOG(ERROR) << CGROUPS_RC_PATH << " file has invalid size, expected " << expected
-                   << ", actual " << file_size;
-        munmap(file_data, file_size);
-        return nullptr;
-    }
-
-    return file_data;
+    return descriptors;
 }
 
-static CgroupFile* GetInstance() {
+static const CgroupDescriptorMap* GetInstance() {
     // Deliberately leak this object (not munmap) to avoid a race between destruction on
     // process exit and concurrent access from another thread.
-    static auto* file = LoadRcFile();
-    return file;
+    static const CgroupDescriptorMap* descriptors = LoadDescriptors();
+    return descriptors;
 }
 
 uint32_t ACgroupFile_getVersion() {
-    auto file = GetInstance();
-    if (file == nullptr) return 0;
-    return file->version_;
+    static constexpr uint32_t FILE_VERSION_1 = 1;
+    auto descriptors = GetInstance();
+    if (descriptors == nullptr) return 0;
+    // There has only ever been one version, and there will be no more since cgroup.rc is no more
+    return FILE_VERSION_1;
 }
 
 uint32_t ACgroupFile_getControllerCount() {
-    auto file = GetInstance();
-    if (file == nullptr) return 0;
-    return file->controller_count_;
+    auto descriptors = GetInstance();
+    if (descriptors == nullptr) return 0;
+    return descriptors->size();
 }
 
 const ACgroupController* ACgroupFile_getController(uint32_t index) {
-    auto file = GetInstance();
-    if (file == nullptr) return nullptr;
-    CHECK(index < file->controller_count_);
+    auto descriptors = GetInstance();
+    if (descriptors == nullptr) return nullptr;
+    CHECK(index < descriptors->size());
     // Although the object is not actually an ACgroupController object, all ACgroupController_*
     // functions implicitly convert ACgroupController* back to CgroupController* before invoking
     // member functions.
-    return static_cast<ACgroupController*>(&file->controllers_[index]);
+    const CgroupController* p = std::next(descriptors->begin(), index)->second.controller();
+    return static_cast<const ACgroupController*>(p);
 }
diff --git a/libprocessgroup/cgrouprc/cgrouprc_internal.h b/libprocessgroup/cgrouprc/cgrouprc_internal.h
index cd02f0304..d51770346 100644
--- a/libprocessgroup/cgrouprc/cgrouprc_internal.h
+++ b/libprocessgroup/cgrouprc/cgrouprc_internal.h
@@ -16,9 +16,6 @@
 
 #pragma once
 
-#include <android/cgrouprc.h>
+#include <processgroup/cgroup_controller.h>
 
-#include <processgroup/format/cgroup_controller.h>
-#include <processgroup/format/cgroup_file.h>
-
-struct ACgroupController : android::cgrouprc::format::CgroupController {};
+struct ACgroupController : CgroupController {};
diff --git a/libprocessgroup/cgrouprc/include/android/cgrouprc.h b/libprocessgroup/cgrouprc/include/android/cgrouprc.h
index 3a57df547..e704a36aa 100644
--- a/libprocessgroup/cgrouprc/include/android/cgrouprc.h
+++ b/libprocessgroup/cgrouprc/include/android/cgrouprc.h
@@ -78,14 +78,6 @@ __attribute__((warn_unused_result)) uint32_t ACgroupController_getVersion(const
 __attribute__((warn_unused_result, weak)) uint32_t ACgroupController_getFlags(
         const ACgroupController*) __INTRODUCED_IN(30);
 
-/**
- * Returns the maximum activation depth of the given controller.
- * Only applicable to cgroup v2 controllers.
- * Returns UINT32_MAX if no maximum activation depth is set.
- */
-__attribute__((warn_unused_result, weak)) uint32_t ACgroupController_getMaxActivationDepth(
-        const ACgroupController* controller) __INTRODUCED_IN(36);
-
 /**
  * Returns the name of the given controller.
  * If the given controller is null, return nullptr.
diff --git a/libprocessgroup/cgrouprc/libcgrouprc.map.txt b/libprocessgroup/cgrouprc/libcgrouprc.map.txt
index 30bd25f18..b62b10f3b 100644
--- a/libprocessgroup/cgrouprc/libcgrouprc.map.txt
+++ b/libprocessgroup/cgrouprc/libcgrouprc.map.txt
@@ -16,10 +16,3 @@ LIBCGROUPRC_30 { # introduced=30
   local:
     *;
 };
-
-LIBCGROUPRC_36 { # introduced=36
-  global:
-    ACgroupController_getMaxActivationDepth; # llndk=202504 systemapi
-  local:
-    *;
-};
diff --git a/libprocessgroup/cgrouprc_format/Android.bp b/libprocessgroup/cgrouprc_format/Android.bp
deleted file mode 100644
index 059092419..000000000
--- a/libprocessgroup/cgrouprc_format/Android.bp
+++ /dev/null
@@ -1,39 +0,0 @@
-// Copyright (C) 2019 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_library_static {
-    name: "libcgrouprc_format",
-    host_supported: true,
-    ramdisk_available: true,
-    vendor_ramdisk_available: true,
-    recovery_available: true,
-    native_bridge_supported: true,
-    srcs: [
-        "cgroup_controller.cpp",
-    ],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
-    export_include_dirs: [
-        "include",
-    ],
-    shared_libs: [
-        "libbase",
-    ],
-}
diff --git a/libprocessgroup/include/processgroup/processgroup.h b/libprocessgroup/include/processgroup/processgroup.h
index ffffeb48b..6a026a717 100644
--- a/libprocessgroup/include/processgroup/processgroup.h
+++ b/libprocessgroup/include/processgroup/processgroup.h
@@ -16,7 +16,6 @@
 
 #pragma once
 
-#include <sys/cdefs.h>
 #include <sys/types.h>
 #include <initializer_list>
 #include <span>
@@ -24,10 +23,7 @@
 #include <string_view>
 #include <vector>
 
-__BEGIN_DECLS
-
-static constexpr const char* CGROUPV2_HIERARCHY_NAME = "cgroup2";
-[[deprecated]] static constexpr const char* CGROUPV2_CONTROLLER_NAME = "cgroup2";
+static constexpr std::string CGROUPV2_HIERARCHY_NAME = "cgroup2";
 
 bool CgroupsAvailable();
 bool CgroupGetControllerPath(const std::string& cgroup_name, std::string* path);
@@ -40,8 +36,6 @@ bool SetTaskProfiles(pid_t tid, const std::vector<std::string>& profiles,
 bool SetProcessProfiles(uid_t uid, pid_t pid, const std::vector<std::string>& profiles);
 bool SetUserProfiles(uid_t uid, const std::vector<std::string>& profiles);
 
-__END_DECLS
-
 bool SetTaskProfiles(pid_t tid, std::initializer_list<std::string_view> profiles,
                      bool use_fd_cache = false);
 bool SetProcessProfiles(uid_t uid, pid_t pid, std::initializer_list<std::string_view> profiles);
@@ -51,14 +45,11 @@ bool SetTaskProfiles(pid_t tid, std::span<const std::string_view> profiles,
 bool SetProcessProfiles(uid_t uid, pid_t pid, std::span<const std::string_view> profiles);
 #endif
 
-__BEGIN_DECLS
 
 #ifndef __ANDROID_VNDK__
 
 bool SetProcessProfilesCached(uid_t uid, pid_t pid, const std::vector<std::string>& profiles);
 
-static constexpr const char* CGROUPS_RC_PATH = "/dev/cgroup_info/cgroup.rc";
-
 bool UsePerAppMemcg();
 
 // Drop the fd cache of cgroup path. It is used for when resource caching is enabled and a process
@@ -99,5 +90,3 @@ bool getAttributePathForTask(const std::string& attr_name, pid_t tid, std::strin
 bool isProfileValidForProcess(const std::string& profile_name, uid_t uid, pid_t pid);
 
 #endif // __ANDROID_VNDK__
-
-__END_DECLS
diff --git a/libprocessgroup/include/processgroup/sched_policy.h b/libprocessgroup/include/processgroup/sched_policy.h
index 1b6ea669d..92cd367bf 100644
--- a/libprocessgroup/include/processgroup/sched_policy.h
+++ b/libprocessgroup/include/processgroup/sched_policy.h
@@ -29,14 +29,6 @@ extern "C" {
  */
 extern bool cpusets_enabled();
 
-/*
- * Check if Linux kernel enables SCHEDTUNE feature (only available in Android
- * common kernel or Linaro LSK, not in mainline Linux as of v4.9)
- *
- * Return value: 1 if Linux kernel CONFIG_CGROUP_SCHEDTUNE=y; 0 otherwise.
- */
-extern bool schedboost_enabled();
-
 /* Keep in sync with THREAD_GROUP_* in frameworks/base/core/java/android/os/Process.java */
 typedef enum {
     SP_DEFAULT = -1,
diff --git a/libprocessgroup/internal.h b/libprocessgroup/internal.h
new file mode 100644
index 000000000..ef855790d
--- /dev/null
+++ b/libprocessgroup/internal.h
@@ -0,0 +1,21 @@
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
+#pragma once
+
+#include <string>
+
+static const std::string CGROUP_V2_ROOT_DEFAULT = "/sys/fs/cgroup";
\ No newline at end of file
diff --git a/libprocessgroup/processgroup.cpp b/libprocessgroup/processgroup.cpp
index 83a2258bf..95221594b 100644
--- a/libprocessgroup/processgroup.cpp
+++ b/libprocessgroup/processgroup.cpp
@@ -37,19 +37,18 @@
 #include <mutex>
 #include <set>
 #include <string>
+#include <string_view>
 #include <thread>
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
-#include <android-base/strings.h>
 #include <cutils/android_filesystem_config.h>
 #include <processgroup/processgroup.h>
 #include <task_profiles.h>
 
 using android::base::GetBoolProperty;
-using android::base::StartsWith;
 using android::base::StringPrintf;
 using android::base::WriteStringToFile;
 
@@ -255,7 +254,7 @@ static bool RemoveEmptyUidCgroups(const std::string& uid_path) {
                 continue;
             }
 
-            if (!StartsWith(dir->d_name, "pid_")) {
+            if (!std::string_view(dir->d_name).starts_with("pid_")) {
                 continue;
             }
 
@@ -296,7 +295,7 @@ void removeAllEmptyProcessGroups() {
                     continue;
                 }
 
-                if (!StartsWith(dir->d_name, "uid_")) {
+                if (!std::string_view(dir->d_name).starts_with("uid_")) {
                     continue;
                 }
 
@@ -662,10 +661,9 @@ static int createProcessGroupInternal(uid_t uid, pid_t initialPid, std::string c
         return -errno;
     }
     if (activate_controllers) {
-        ret = CgroupMap::GetInstance().ActivateControllers(uid_path);
-        if (ret) {
-            LOG(ERROR) << "Failed to activate controllers in " << uid_path;
-            return ret;
+        if (!CgroupMap::GetInstance().ActivateControllers(uid_path)) {
+            PLOG(ERROR) << "Failed to activate controllers in " << uid_path;
+            return -errno;
         }
     }
 
diff --git a/libprocessgroup/profiles/Android.bp b/libprocessgroup/profiles/Android.bp
index 885971a7a..baa454646 100644
--- a/libprocessgroup/profiles/Android.bp
+++ b/libprocessgroup/profiles/Android.bp
@@ -13,17 +13,13 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
 prebuilt_etc {
     name: "cgroups.json",
     src: "cgroups.json",
-    required: [
-        "cgroups_28.json",
-        "cgroups_29.json",
-        "cgroups_30.json",
-    ],
 }
 
 prebuilt_etc {
@@ -33,50 +29,9 @@ prebuilt_etc {
     src: "cgroups.recovery.json",
 }
 
-prebuilt_etc {
-    name: "cgroups_28.json",
-    src: "cgroups_28.json",
-    sub_dir: "task_profiles",
-}
-
-prebuilt_etc {
-    name: "cgroups_29.json",
-    src: "cgroups_29.json",
-    sub_dir: "task_profiles",
-}
-
-prebuilt_etc {
-    name: "cgroups_30.json",
-    src: "cgroups_30.json",
-    sub_dir: "task_profiles",
-}
-
 prebuilt_etc {
     name: "task_profiles.json",
     src: "task_profiles.json",
-    required: [
-        "task_profiles_28.json",
-        "task_profiles_29.json",
-        "task_profiles_30.json",
-    ],
-}
-
-prebuilt_etc {
-    name: "task_profiles_28.json",
-    src: "task_profiles_28.json",
-    sub_dir: "task_profiles",
-}
-
-prebuilt_etc {
-    name: "task_profiles_29.json",
-    src: "task_profiles_29.json",
-    sub_dir: "task_profiles",
-}
-
-prebuilt_etc {
-    name: "task_profiles_30.json",
-    src: "task_profiles_30.json",
-    sub_dir: "task_profiles",
 }
 
 cc_defaults {
diff --git a/libprocessgroup/profiles/cgroups_28.json b/libprocessgroup/profiles/cgroups_28.json
deleted file mode 100644
index 17d492949..000000000
--- a/libprocessgroup/profiles/cgroups_28.json
+++ /dev/null
@@ -1,11 +0,0 @@
-{
-  "Cgroups": [
-    {
-      "Controller": "schedtune",
-      "Path": "/dev/stune",
-      "Mode": "0755",
-      "UID": "system",
-      "GID": "system"
-    }
-  ]
-}
diff --git a/libprocessgroup/profiles/cgroups_29.json b/libprocessgroup/profiles/cgroups_29.json
deleted file mode 100644
index 17d492949..000000000
--- a/libprocessgroup/profiles/cgroups_29.json
+++ /dev/null
@@ -1,11 +0,0 @@
-{
-  "Cgroups": [
-    {
-      "Controller": "schedtune",
-      "Path": "/dev/stune",
-      "Mode": "0755",
-      "UID": "system",
-      "GID": "system"
-    }
-  ]
-}
diff --git a/libprocessgroup/profiles/cgroups_30.json b/libprocessgroup/profiles/cgroups_30.json
deleted file mode 100644
index 80a074bf1..000000000
--- a/libprocessgroup/profiles/cgroups_30.json
+++ /dev/null
@@ -1,12 +0,0 @@
-{
-  "Cgroups": [
-    {
-      "Controller": "schedtune",
-      "Path": "/dev/stune",
-      "Mode": "0755",
-      "UID": "system",
-      "GID": "system",
-      "Optional": true
-    }
-  ]
-}
diff --git a/libprocessgroup/profiles/task_profiles.json b/libprocessgroup/profiles/task_profiles.json
index 411c38c80..28902efe8 100644
--- a/libprocessgroup/profiles/task_profiles.json
+++ b/libprocessgroup/profiles/task_profiles.json
@@ -202,6 +202,19 @@
         }
       ]
     },
+    {
+      "Name": "RealTimeInputScheduling",
+      "Actions": [
+        {
+          "Name": "SetSchedulerPolicy",
+          "Params":
+          {
+            "Policy": "SCHED_FIFO",
+            "Priority": "2"
+          }
+        }
+      ]
+    },
     {
       "Name": "CameraServicePerformance",
       "Actions": [
@@ -571,33 +584,6 @@
       ]
     },
 
-    {
-      "Name": "PerfBoost",
-      "Actions": [
-        {
-          "Name": "SetClamps",
-          "Params":
-          {
-            "Boost": "50%",
-            "Clamp": "0"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "PerfClamp",
-      "Actions": [
-        {
-          "Name": "SetClamps",
-          "Params":
-          {
-            "Boost": "0",
-            "Clamp": "30%"
-          }
-        }
-      ]
-    },
-
     {
       "Name": "LowMemoryUsage",
       "Actions": [
@@ -731,7 +717,7 @@
     },
     {
       "Name": "InputPolicy",
-      "Profiles": [ "MaxPerformance", "ProcessCapacityMax", "TimerSlackNormal" ]
+      "Profiles": [ "RealTimeInputScheduling", "MaxPerformance", "ProcessCapacityMax", "TimerSlackNormal" ]
     }
   ]
 }
diff --git a/libprocessgroup/profiles/task_profiles_28.json b/libprocessgroup/profiles/task_profiles_28.json
deleted file mode 100644
index e7be5487d..000000000
--- a/libprocessgroup/profiles/task_profiles_28.json
+++ /dev/null
@@ -1,160 +0,0 @@
-{
-  "Attributes": [
-    {
-      "Name": "STuneBoost",
-      "Controller": "schedtune",
-      "File": "schedtune.boost"
-    },
-    {
-      "Name": "STunePreferIdle",
-      "Controller": "schedtune",
-      "File": "schedtune.prefer_idle"
-    }
-  ],
-
-  "Profiles": [
-    {
-      "Name": "HighEnergySaving",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "NormalPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": ""
-          }
-        }
-      ]
-    },
-    {
-      "Name": "ServicePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "HighPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "foreground"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "MaxPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "top-app"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "RealtimePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "rt"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CameraServicePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "camera-daemon"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "NNApiHALPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "nnapi-hal"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "Dex2oatPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CpuPolicySpread",
-      "Actions": [
-        {
-          "Name": "SetAttribute",
-          "Params":
-          {
-            "Name": "STunePreferIdle",
-            "Value": "1"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CpuPolicyPack",
-      "Actions": [
-        {
-          "Name": "SetAttribute",
-          "Params":
-          {
-            "Name": "STunePreferIdle",
-            "Value": "0"
-          }
-        }
-      ]
-    }
-  ]
-}
diff --git a/libprocessgroup/profiles/task_profiles_29.json b/libprocessgroup/profiles/task_profiles_29.json
deleted file mode 100644
index 6174c8d0f..000000000
--- a/libprocessgroup/profiles/task_profiles_29.json
+++ /dev/null
@@ -1,160 +0,0 @@
-{
-  "Attributes": [
-    {
-      "Name": "STuneBoost",
-      "Controller": "schedtune",
-      "File": "schedtune.boost"
-    },
-    {
-      "Name": "STunePreferIdle",
-      "Controller": "schedtune",
-      "File": "schedtune.prefer_idle"
-    }
-  ],
-
-  "Profiles": [
-    {
-      "Name": "HighEnergySaving",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "NormalPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": ""
-          }
-        }
-      ]
-    },
-    {
-      "Name": "HighPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "foreground"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "ServicePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "MaxPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "top-app"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "RealtimePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "rt"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CameraServicePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "camera-daemon"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "NNApiHALPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "nnapi-hal"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "Dex2oatPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CpuPolicySpread",
-      "Actions": [
-        {
-          "Name": "SetAttribute",
-          "Params":
-          {
-            "Name": "STunePreferIdle",
-            "Value": "1"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CpuPolicyPack",
-      "Actions": [
-        {
-          "Name": "SetAttribute",
-          "Params":
-          {
-            "Name": "STunePreferIdle",
-            "Value": "0"
-          }
-        }
-      ]
-    }
-  ]
-}
diff --git a/libprocessgroup/profiles/task_profiles_30.json b/libprocessgroup/profiles/task_profiles_30.json
deleted file mode 100644
index e7be5487d..000000000
--- a/libprocessgroup/profiles/task_profiles_30.json
+++ /dev/null
@@ -1,160 +0,0 @@
-{
-  "Attributes": [
-    {
-      "Name": "STuneBoost",
-      "Controller": "schedtune",
-      "File": "schedtune.boost"
-    },
-    {
-      "Name": "STunePreferIdle",
-      "Controller": "schedtune",
-      "File": "schedtune.prefer_idle"
-    }
-  ],
-
-  "Profiles": [
-    {
-      "Name": "HighEnergySaving",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "NormalPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": ""
-          }
-        }
-      ]
-    },
-    {
-      "Name": "ServicePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "HighPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "foreground"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "MaxPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "top-app"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "RealtimePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "rt"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CameraServicePerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "camera-daemon"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "NNApiHALPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "nnapi-hal"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "Dex2oatPerformance",
-      "Actions": [
-        {
-          "Name": "JoinCgroup",
-          "Params":
-          {
-            "Controller": "schedtune",
-            "Path": "background"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CpuPolicySpread",
-      "Actions": [
-        {
-          "Name": "SetAttribute",
-          "Params":
-          {
-            "Name": "STunePreferIdle",
-            "Value": "1"
-          }
-        }
-      ]
-    },
-    {
-      "Name": "CpuPolicyPack",
-      "Actions": [
-        {
-          "Name": "SetAttribute",
-          "Params":
-          {
-            "Name": "STunePreferIdle",
-            "Value": "0"
-          }
-        }
-      ]
-    }
-  ]
-}
diff --git a/libprocessgroup/sched_policy.cpp b/libprocessgroup/sched_policy.cpp
index 042bcd24c..5a53c35de 100644
--- a/libprocessgroup/sched_policy.cpp
+++ b/libprocessgroup/sched_policy.cpp
@@ -148,20 +148,10 @@ bool cpusets_enabled() {
     return enabled;
 }
 
-static bool schedtune_enabled() {
-    return (CgroupMap::GetInstance().FindController("schedtune").IsUsable());
-}
-
 static bool cpuctl_enabled() {
     return (CgroupMap::GetInstance().FindController("cpu").IsUsable());
 }
 
-bool schedboost_enabled() {
-    static bool enabled = schedtune_enabled() || cpuctl_enabled();
-
-    return enabled;
-}
-
 static int getCGroupSubsys(pid_t tid, const char* subsys, std::string& subgroup) {
     auto controller = CgroupMap::GetInstance().FindController(subsys);
 
@@ -201,9 +191,8 @@ int get_sched_policy(pid_t tid, SchedPolicy* policy) {
     }
 
     std::string group;
-    if (schedboost_enabled()) {
-        if ((getCGroupSubsys(tid, "schedtune", group) < 0) &&
-            (getCGroupSubsys(tid, "cpu", group) < 0)) {
+    if (cpuctl_enabled()) {
+        if (getCGroupSubsys(tid, "cpu", group) < 0) {
             LOG(ERROR) << "Failed to find cpu cgroup for tid " << tid;
             return -1;
         }
diff --git a/libprocessgroup/setup/Android.bp b/libprocessgroup/setup/Android.bp
index 1a4ad0118..25737f5b2 100644
--- a/libprocessgroup/setup/Android.bp
+++ b/libprocessgroup/setup/Android.bp
@@ -29,11 +29,9 @@ cc_library_shared {
     ],
     shared_libs: [
         "libbase",
-        "libcgrouprc",
         "libjsoncpp",
     ],
     static_libs: [
-        "libcgrouprc_format",
         "libprocessgroup_util",
     ],
     header_libs: [
diff --git a/libprocessgroup/setup/cgroup_descriptor.h b/libprocessgroup/setup/cgroup_descriptor.h
index 06ce186fd..1afd2ee9c 100644
--- a/libprocessgroup/setup/cgroup_descriptor.h
+++ b/libprocessgroup/setup/cgroup_descriptor.h
@@ -21,10 +21,7 @@
 
 #include <sys/stat.h>
 
-#include <processgroup/format/cgroup_controller.h>
-
-namespace android {
-namespace cgrouprc {
+#include <processgroup/cgroup_controller.h>
 
 // Complete controller description for mounting cgroups
 class CgroupDescriptor {
@@ -33,7 +30,7 @@ class CgroupDescriptor {
                      mode_t mode, const std::string& uid, const std::string& gid, uint32_t flags,
                      uint32_t max_activation_depth);
 
-    const format::CgroupController* controller() const { return &controller_; }
+    const CgroupController* controller() const { return &controller_; }
     mode_t mode() const { return mode_; }
     std::string uid() const { return uid_; }
     std::string gid() const { return gid_; }
@@ -41,11 +38,8 @@ class CgroupDescriptor {
     void set_mounted(bool mounted);
 
   private:
-    format::CgroupController controller_;
+    CgroupController controller_;
     mode_t mode_ = 0;
     std::string uid_;
     std::string gid_;
 };
-
-}  // namespace cgrouprc
-}  // namespace android
diff --git a/libprocessgroup/setup/cgroup_map_write.cpp b/libprocessgroup/setup/cgroup_map_write.cpp
index bd4187475..c4e1fb680 100644
--- a/libprocessgroup/setup/cgroup_map_write.cpp
+++ b/libprocessgroup/setup/cgroup_map_write.cpp
@@ -22,45 +22,28 @@
 #include <fcntl.h>
 #include <grp.h>
 #include <pwd.h>
-#include <sys/mman.h>
 #include <sys/mount.h>
 #include <sys/stat.h>
 #include <sys/types.h>
-#include <time.h>
 #include <unistd.h>
 
 #include <optional>
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
-#include <android-base/properties.h>
-#include <android-base/stringprintf.h>
-#include <android-base/unique_fd.h>
-#include <android/cgrouprc.h>
-#include <json/reader.h>
-#include <json/value.h>
-#include <processgroup/format/cgroup_file.h>
+#include <processgroup/cgroup_descriptor.h>
 #include <processgroup/processgroup.h>
 #include <processgroup/setup.h>
 #include <processgroup/util.h>
 
 #include "../build_flags.h"
-#include "cgroup_descriptor.h"
-
-using android::base::GetUintProperty;
-using android::base::StringPrintf;
-using android::base::unique_fd;
-
-namespace android {
-namespace cgrouprc {
+#include "../internal.h"
 
 static constexpr const char* CGROUPS_DESC_FILE = "/etc/cgroups.json";
 static constexpr const char* CGROUPS_DESC_VENDOR_FILE = "/vendor/etc/cgroups.json";
 
 static constexpr const char* TEMPLATE_CGROUPS_DESC_API_FILE = "/etc/task_profiles/cgroups_%u.json";
 
-static const std::string CGROUP_V2_ROOT_DEFAULT = "/sys/fs/cgroup";
-
 static bool ChangeDirModeAndOwner(const std::string& path, mode_t mode, const std::string& uid,
                                   const std::string& gid, bool permissive_mode = false) {
     uid_t pw_uid = -1;
@@ -148,149 +131,15 @@ static bool Mkdir(const std::string& path, mode_t mode, const std::string& uid,
     return true;
 }
 
-static void MergeCgroupToDescriptors(std::map<std::string, CgroupDescriptor>* descriptors,
-                                     const Json::Value& cgroup, const std::string& name,
-                                     const std::string& root_path, int cgroups_version) {
-    const std::string cgroup_path = cgroup["Path"].asString();
-    std::string path;
-
-    if (!root_path.empty()) {
-        path = root_path;
-        if (cgroup_path != ".") {
-            path += "/";
-            path += cgroup_path;
-        }
-    } else {
-        path = cgroup_path;
-    }
-
-    uint32_t controller_flags = 0;
-
-    if (cgroup["NeedsActivation"].isBool() && cgroup["NeedsActivation"].asBool()) {
-        controller_flags |= CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION;
-    }
-
-    if (cgroup["Optional"].isBool() && cgroup["Optional"].asBool()) {
-        controller_flags |= CGROUPRC_CONTROLLER_FLAG_OPTIONAL;
-    }
-
-    uint32_t max_activation_depth = UINT32_MAX;
-    if (cgroup.isMember("MaxActivationDepth")) {
-        max_activation_depth = cgroup["MaxActivationDepth"].asUInt();
-    }
-
-    CgroupDescriptor descriptor(
-            cgroups_version, name, path, std::strtoul(cgroup["Mode"].asString().c_str(), 0, 8),
-            cgroup["UID"].asString(), cgroup["GID"].asString(), controller_flags,
-            max_activation_depth);
-
-    auto iter = descriptors->find(name);
-    if (iter == descriptors->end()) {
-        descriptors->emplace(name, descriptor);
-    } else {
-        iter->second = descriptor;
-    }
-}
-
-static const bool force_memcg_v2 = android::libprocessgroup_flags::force_memcg_v2();
-
-static bool ReadDescriptorsFromFile(const std::string& file_name,
-                                    std::map<std::string, CgroupDescriptor>* descriptors) {
-    std::vector<CgroupDescriptor> result;
-    std::string json_doc;
-
-    if (!android::base::ReadFileToString(file_name, &json_doc)) {
-        PLOG(ERROR) << "Failed to read task profiles from " << file_name;
-        return false;
-    }
-
-    Json::CharReaderBuilder builder;
-    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
-    Json::Value root;
-    std::string errorMessage;
-    if (!reader->parse(&*json_doc.begin(), &*json_doc.end(), &root, &errorMessage)) {
-        LOG(ERROR) << "Failed to parse cgroups description: " << errorMessage;
-        return false;
-    }
-
-    if (root.isMember("Cgroups")) {
-        const Json::Value& cgroups = root["Cgroups"];
-        for (Json::Value::ArrayIndex i = 0; i < cgroups.size(); ++i) {
-            std::string name = cgroups[i]["Controller"].asString();
-
-            if (force_memcg_v2 && name == "memory") continue;
-
-            MergeCgroupToDescriptors(descriptors, cgroups[i], name, "", 1);
-        }
-    }
-
-    bool memcgv2_present = false;
-    std::string root_path;
-    if (root.isMember("Cgroups2")) {
-        const Json::Value& cgroups2 = root["Cgroups2"];
-        root_path = cgroups2["Path"].asString();
-        MergeCgroupToDescriptors(descriptors, cgroups2, CGROUPV2_HIERARCHY_NAME, "", 2);
-
-        const Json::Value& childGroups = cgroups2["Controllers"];
-        for (Json::Value::ArrayIndex i = 0; i < childGroups.size(); ++i) {
-            std::string name = childGroups[i]["Controller"].asString();
-
-            if (force_memcg_v2 && name == "memory") memcgv2_present = true;
-
-            MergeCgroupToDescriptors(descriptors, childGroups[i], name, root_path, 2);
-        }
-    }
-
-    if (force_memcg_v2 && !memcgv2_present) {
-        LOG(INFO) << "Forcing memcg to v2 hierarchy";
-        Json::Value memcgv2;
-        memcgv2["Controller"] = "memory";
-        memcgv2["NeedsActivation"] = true;
-        memcgv2["Path"] = ".";
-        memcgv2["Optional"] = true;  // In case of cgroup_disabled=memory, so we can still boot
-        MergeCgroupToDescriptors(descriptors, memcgv2, "memory",
-                                 root_path.empty() ? CGROUP_V2_ROOT_DEFAULT : root_path, 2);
-    }
-
-    return true;
-}
-
-static bool ReadDescriptors(std::map<std::string, CgroupDescriptor>* descriptors) {
-    // load system cgroup descriptors
-    if (!ReadDescriptorsFromFile(CGROUPS_DESC_FILE, descriptors)) {
-        return false;
-    }
-
-    // load API-level specific system cgroups descriptors if available
-    unsigned int api_level = GetUintProperty<unsigned int>("ro.product.first_api_level", 0);
-    if (api_level > 0) {
-        std::string api_cgroups_path =
-                android::base::StringPrintf(TEMPLATE_CGROUPS_DESC_API_FILE, api_level);
-        if (!access(api_cgroups_path.c_str(), F_OK) || errno != ENOENT) {
-            if (!ReadDescriptorsFromFile(api_cgroups_path, descriptors)) {
-                return false;
-            }
-        }
-    }
-
-    // load vendor cgroup descriptors if the file exists
-    if (!access(CGROUPS_DESC_VENDOR_FILE, F_OK) &&
-        !ReadDescriptorsFromFile(CGROUPS_DESC_VENDOR_FILE, descriptors)) {
-        return false;
-    }
-
-    return true;
-}
-
 // To avoid issues in sdk_mac build
 #if defined(__ANDROID__)
 
-static bool IsOptionalController(const format::CgroupController* controller) {
+static bool IsOptionalController(const CgroupController* controller) {
     return controller->flags() & CGROUPRC_CONTROLLER_FLAG_OPTIONAL;
 }
 
 static bool MountV2CgroupController(const CgroupDescriptor& descriptor) {
-    const format::CgroupController* controller = descriptor.controller();
+    const CgroupController* controller = descriptor.controller();
 
     // /sys/fs/cgroup is created by cgroup2 with specific selinux permissions,
     // try to create again in case the mount point is changed
@@ -324,36 +173,18 @@ static bool MountV2CgroupController(const CgroupDescriptor& descriptor) {
 }
 
 static bool ActivateV2CgroupController(const CgroupDescriptor& descriptor) {
-    const format::CgroupController* controller = descriptor.controller();
+    const CgroupController* controller = descriptor.controller();
 
     if (!Mkdir(controller->path(), descriptor.mode(), descriptor.uid(), descriptor.gid())) {
         LOG(ERROR) << "Failed to create directory for " << controller->name() << " cgroup";
         return false;
     }
 
-    if (controller->flags() & CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION &&
-        controller->max_activation_depth() > 0) {
-        std::string str = "+";
-        str += controller->name();
-        std::string path = controller->path();
-        path += "/cgroup.subtree_control";
-
-        if (!base::WriteStringToFile(str, path)) {
-            if (IsOptionalController(controller)) {
-                PLOG(INFO) << "Failed to activate optional controller " << controller->name()
-                           << " at " << path;
-                return true;
-            }
-            PLOG(ERROR) << "Failed to activate controller " << controller->name();
-            return false;
-        }
-    }
-
-    return true;
+    return ::ActivateControllers(controller->path(), {{controller->name(), descriptor}});
 }
 
 static bool MountV1CgroupController(const CgroupDescriptor& descriptor) {
-    const format::CgroupController* controller = descriptor.controller();
+    const CgroupController* controller = descriptor.controller();
 
     // mkdir <path> [mode] [owner] [group]
     if (!Mkdir(controller->path(), descriptor.mode(), descriptor.uid(), descriptor.gid())) {
@@ -388,10 +219,10 @@ static bool MountV1CgroupController(const CgroupDescriptor& descriptor) {
 }
 
 static bool SetupCgroup(const CgroupDescriptor& descriptor) {
-    const format::CgroupController* controller = descriptor.controller();
+    const CgroupController* controller = descriptor.controller();
 
     if (controller->version() == 2) {
-        if (!strcmp(controller->name(), CGROUPV2_HIERARCHY_NAME)) {
+        if (controller->name() == CGROUPV2_HIERARCHY_NAME) {
             return MountV2CgroupController(descriptor);
         } else {
             return ActivateV2CgroupController(descriptor);
@@ -410,35 +241,6 @@ static bool SetupCgroup(const CgroupDescriptor&) {
 
 #endif
 
-static bool WriteRcFile(const std::map<std::string, CgroupDescriptor>& descriptors) {
-    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_RC_PATH, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
-                                         S_IRUSR | S_IRGRP | S_IROTH)));
-    if (fd < 0) {
-        PLOG(ERROR) << "open() failed for " << CGROUPS_RC_PATH;
-        return false;
-    }
-
-    format::CgroupFile fl;
-    fl.version_ = format::CgroupFile::FILE_CURR_VERSION;
-    fl.controller_count_ = descriptors.size();
-    int ret = TEMP_FAILURE_RETRY(write(fd, &fl, sizeof(fl)));
-    if (ret < 0) {
-        PLOG(ERROR) << "write() failed for " << CGROUPS_RC_PATH;
-        return false;
-    }
-
-    for (const auto& [name, descriptor] : descriptors) {
-        ret = TEMP_FAILURE_RETRY(
-                write(fd, descriptor.controller(), sizeof(format::CgroupController)));
-        if (ret < 0) {
-            PLOG(ERROR) << "write() failed for " << CGROUPS_RC_PATH;
-            return false;
-        }
-    }
-
-    return true;
-}
-
 CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
                                    const std::string& path, mode_t mode, const std::string& uid,
                                    const std::string& gid, uint32_t flags,
@@ -458,9 +260,6 @@ void CgroupDescriptor::set_mounted(bool mounted) {
     controller_.set_flags(flags);
 }
 
-}  // namespace cgrouprc
-}  // namespace android
-
 static std::optional<bool> MGLRUDisabled() {
     const std::string file_name = "/sys/kernel/mm/lru_gen/enabled";
     std::string content;
@@ -472,9 +271,8 @@ static std::optional<bool> MGLRUDisabled() {
     return content == "0x0000";
 }
 
-static std::optional<bool> MEMCGDisabled(
-        const std::map<std::string, android::cgrouprc::CgroupDescriptor>& descriptors) {
-    std::string cgroup_v2_root = android::cgrouprc::CGROUP_V2_ROOT_DEFAULT;
+static std::optional<bool> MEMCGDisabled(const CgroupDescriptorMap& descriptors) {
+    std::string cgroup_v2_root = CGROUP_V2_ROOT_DEFAULT;
     const auto it = descriptors.find(CGROUPV2_HIERARCHY_NAME);
     if (it == descriptors.end()) {
         LOG(WARNING) << "No Cgroups2 path found in cgroups.json. Vendor has modified Android, and "
@@ -495,14 +293,10 @@ static std::optional<bool> MEMCGDisabled(
     return content.find("memory") == std::string::npos;
 }
 
-static bool CreateV2SubHierarchy(
-        const std::string& path,
-        const std::map<std::string, android::cgrouprc::CgroupDescriptor>& descriptors) {
-    using namespace android::cgrouprc;
-
+static bool CreateV2SubHierarchy(const std::string& path, const CgroupDescriptorMap& descriptors) {
     const auto cgv2_iter = descriptors.find(CGROUPV2_HIERARCHY_NAME);
     if (cgv2_iter == descriptors.end()) return false;
-    const android::cgrouprc::CgroupDescriptor cgv2_descriptor = cgv2_iter->second;
+    const CgroupDescriptor cgv2_descriptor = cgv2_iter->second;
 
     if (!Mkdir(path, cgv2_descriptor.mode(), cgv2_descriptor.uid(), cgv2_descriptor.gid())) {
         PLOG(ERROR) << "Failed to create directory for " << path;
@@ -511,46 +305,17 @@ static bool CreateV2SubHierarchy(
 
     // Activate all v2 controllers in path so they can be activated in
     // children as they are created.
-    for (const auto& [name, descriptor] : descriptors) {
-        const format::CgroupController* controller = descriptor.controller();
-        std::uint32_t flags = controller->flags();
-        std::uint32_t max_activation_depth = controller->max_activation_depth();
-        const int depth = util::GetCgroupDepth(controller->path(), path);
-
-        if (controller->version() == 2 && name != CGROUPV2_HIERARCHY_NAME &&
-            flags & CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION && depth < max_activation_depth) {
-            std::string str("+");
-            str += controller->name();
-            if (!android::base::WriteStringToFile(str, path + "/cgroup.subtree_control")) {
-                if (flags & CGROUPRC_CONTROLLER_FLAG_OPTIONAL) {
-                    PLOG(WARNING) << "Activation of cgroup controller " << str << " failed in path "
-                                  << path;
-                } else {
-                    return false;
-                }
-            }
-        }
-    }
-    return true;
+    return ::ActivateControllers(path, descriptors);
 }
 
 bool CgroupSetup() {
-    using namespace android::cgrouprc;
-
-    std::map<std::string, CgroupDescriptor> descriptors;
+    CgroupDescriptorMap descriptors;
 
     if (getpid() != 1) {
         LOG(ERROR) << "Cgroup setup can be done only by init process";
         return false;
     }
 
-    // Make sure we do this only one time. No need for std::call_once because
-    // init is a single-threaded process
-    if (access(CGROUPS_RC_PATH, F_OK) == 0) {
-        LOG(WARNING) << "Attempt to call CgroupSetup() more than once";
-        return true;
-    }
-
     // load cgroups.json file
     if (!ReadDescriptors(&descriptors)) {
         LOG(ERROR) << "Failed to load cgroup description file";
@@ -559,15 +324,18 @@ bool CgroupSetup() {
 
     // setup cgroups
     for (auto& [name, descriptor] : descriptors) {
-        if (SetupCgroup(descriptor)) {
-            descriptor.set_mounted(true);
-        } else {
+        if (descriptor.controller()->flags() & CGROUPRC_CONTROLLER_FLAG_MOUNTED) {
+            LOG(WARNING) << "Attempt to call CgroupSetup() more than once";
+            return true;
+        }
+
+        if (!SetupCgroup(descriptor)) {
             // issue a warning and proceed with the next cgroup
             LOG(WARNING) << "Failed to setup " << name << " cgroup";
         }
     }
 
-    if (force_memcg_v2) {
+    if (android::libprocessgroup_flags::force_memcg_v2()) {
         if (MGLRUDisabled().value_or(false)) {
             LOG(WARNING) << "Memcg forced to v2 hierarchy with MGLRU disabled! "
                          << "Global reclaim performance will suffer.";
@@ -593,26 +361,5 @@ bool CgroupSetup() {
         }
     }
 
-    // mkdir <CGROUPS_RC_DIR> 0711 system system
-    if (!Mkdir(android::base::Dirname(CGROUPS_RC_PATH), 0711, "system", "system")) {
-        LOG(ERROR) << "Failed to create directory for " << CGROUPS_RC_PATH << " file";
-        return false;
-    }
-
-    // Generate <CGROUPS_RC_FILE> file which can be directly mmapped into
-    // process memory. This optimizes performance, memory usage
-    // and limits infrormation shared with unprivileged processes
-    // to the minimum subset of information from cgroups.json
-    if (!WriteRcFile(descriptors)) {
-        LOG(ERROR) << "Failed to write " << CGROUPS_RC_PATH << " file";
-        return false;
-    }
-
-    // chmod 0644 <CGROUPS_RC_PATH>
-    if (fchmodat(AT_FDCWD, CGROUPS_RC_PATH, 0644, AT_SYMLINK_NOFOLLOW) < 0) {
-        PLOG(ERROR) << "fchmodat() failed";
-        return false;
-    }
-
     return true;
 }
diff --git a/libprocessgroup/task_profiles.cpp b/libprocessgroup/task_profiles.cpp
index 67ecc1d50..dc6c8c07f 100644
--- a/libprocessgroup/task_profiles.cpp
+++ b/libprocessgroup/task_profiles.cpp
@@ -17,11 +17,17 @@
 //#define LOG_NDEBUG 0
 #define LOG_TAG "libprocessgroup"
 
+#include <task_profiles.h>
+
+#include <map>
+#include <optional>
+#include <string>
+
 #include <dirent.h>
 #include <fcntl.h>
+#include <sched.h>
+#include <sys/resource.h>
 #include <unistd.h>
-#include <task_profiles.h>
-#include <string>
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
@@ -30,18 +36,13 @@
 #include <android-base/strings.h>
 #include <android-base/threads.h>
 
+#include <build_flags.h>
+
 #include <cutils/android_filesystem_config.h>
 
 #include <json/reader.h>
 #include <json/value.h>
 
-#include <build_flags.h>
-
-// To avoid issues in sdk_mac build
-#if defined(__ANDROID__)
-#include <sys/prctl.h>
-#endif
-
 using android::base::GetThreadId;
 using android::base::GetUintProperty;
 using android::base::StringPrintf;
@@ -54,6 +55,7 @@ static constexpr const char* TASK_PROFILE_DB_VENDOR_FILE = "/vendor/etc/task_pro
 
 static constexpr const char* TEMPLATE_TASK_PROFILE_API_FILE =
         "/etc/task_profiles/task_profiles_%u.json";
+namespace {
 
 class FdCacheHelper {
   public:
@@ -64,8 +66,11 @@ class FdCacheHelper {
     };
 
     static void Cache(const std::string& path, android::base::unique_fd& fd);
+
     static void Drop(android::base::unique_fd& fd);
+
     static void Init(const std::string& path, android::base::unique_fd& fd);
+
     static bool IsCached(const android::base::unique_fd& fd) { return fd > FDS_INACCESSIBLE; }
 
   private:
@@ -116,6 +121,17 @@ bool FdCacheHelper::IsAppDependentPath(const std::string& path) {
     return path.find("<uid>", 0) != std::string::npos || path.find("<pid>", 0) != std::string::npos;
 }
 
+std::optional<long> readLong(const std::string& str) {
+    char* end;
+    const long result = strtol(str.c_str(), &end, 10);
+    if (end > str.c_str()) {
+        return result;
+    }
+    return std::nullopt;
+}
+
+}  // namespace
+
 IProfileAttribute::~IProfileAttribute() = default;
 
 const std::string& ProfileAttribute::file_name() const {
@@ -188,61 +204,20 @@ bool ProfileAttribute::GetPathForUID(uid_t uid, std::string* path) const {
     return true;
 }
 
-bool SetClampsAction::ExecuteForProcess(uid_t, pid_t) const {
-    // TODO: add support when kernel supports util_clamp
-    LOG(WARNING) << "SetClampsAction::ExecuteForProcess is not supported";
-    return false;
-}
-
-bool SetClampsAction::ExecuteForTask(int) const {
-    // TODO: add support when kernel supports util_clamp
-    LOG(WARNING) << "SetClampsAction::ExecuteForTask is not supported";
-    return false;
-}
-
-// To avoid issues in sdk_mac build
-#if defined(__ANDROID__)
-
-bool SetTimerSlackAction::IsTimerSlackSupported(pid_t tid) {
-    auto file = StringPrintf("/proc/%d/timerslack_ns", tid);
-
-    return (access(file.c_str(), W_OK) == 0);
-}
-
 bool SetTimerSlackAction::ExecuteForTask(pid_t tid) const {
-    static bool sys_supports_timerslack = IsTimerSlackSupported(tid);
-
-    // v4.6+ kernels support the /proc/<tid>/timerslack_ns interface.
-    // TODO: once we've backported this, log if the open(2) fails.
-    if (sys_supports_timerslack) {
-        auto file = StringPrintf("/proc/%d/timerslack_ns", tid);
-        if (!WriteStringToFile(std::to_string(slack_), file)) {
-            if (errno == ENOENT) {
-                // This happens when process is already dead
-                return true;
-            }
-            PLOG(ERROR) << "set_timerslack_ns write failed";
-        }
-    }
-
-    // TODO: Remove when /proc/<tid>/timerslack_ns interface is backported.
-    if (tid == 0 || tid == GetThreadId()) {
-        if (prctl(PR_SET_TIMERSLACK, slack_) == -1) {
-            PLOG(ERROR) << "set_timerslack_ns prctl failed";
+    const auto file = StringPrintf("/proc/%d/timerslack_ns", tid);
+    if (!WriteStringToFile(std::to_string(slack_), file)) {
+        if (errno == ENOENT) {
+            // This happens when process is already dead
+            return true;
         }
+        PLOG(ERROR) << "set_timerslack_ns write failed";
+        return false;
     }
 
     return true;
 }
 
-#else
-
-bool SetTimerSlackAction::ExecuteForTask(int) const {
-    return true;
-};
-
-#endif
-
 bool SetAttributeAction::WriteValueToFile(const std::string& path) const {
     if (!WriteStringToFile(value_, path)) {
         if (access(path.c_str(), F_OK) < 0) {
@@ -672,6 +647,57 @@ bool WriteFileAction::IsValidForTask(int) const {
     return access(task_path_.c_str(), W_OK) == 0;
 }
 
+bool SetSchedulerPolicyAction::isNormalPolicy(int policy) {
+    return policy == SCHED_OTHER || policy == SCHED_BATCH || policy == SCHED_IDLE;
+}
+
+bool SetSchedulerPolicyAction::toPriority(int policy, int virtual_priority, int& priority_out) {
+    constexpr int VIRTUAL_PRIORITY_MIN = 1;
+    constexpr int VIRTUAL_PRIORITY_MAX = 99;
+
+    if (virtual_priority < VIRTUAL_PRIORITY_MIN || virtual_priority > VIRTUAL_PRIORITY_MAX) {
+        LOG(WARNING) << "SetSchedulerPolicy: invalid priority (" << virtual_priority
+                     << ") for policy (" << policy << ")";
+        return false;
+    }
+
+    const int min = sched_get_priority_min(policy);
+    if (min == -1) {
+        PLOG(ERROR) << "SetSchedulerPolicy: Cannot get min sched priority for policy " << policy;
+        return false;
+    }
+
+    const int max = sched_get_priority_max(policy);
+    if (max == -1) {
+        PLOG(ERROR) << "SetSchedulerPolicy: Cannot get max sched priority for policy " << policy;
+        return false;
+    }
+
+    priority_out = min + (virtual_priority - VIRTUAL_PRIORITY_MIN) * (max - min) /
+        (VIRTUAL_PRIORITY_MAX - VIRTUAL_PRIORITY_MIN);
+
+    return true;
+}
+
+bool SetSchedulerPolicyAction::ExecuteForTask(pid_t tid) const {
+    struct sched_param param = {};
+    param.sched_priority = isNormalPolicy(policy_) ? 0 : *priority_or_nice_;
+    if (sched_setscheduler(tid, policy_, &param) == -1) {
+        PLOG(WARNING) << "SetSchedulerPolicy: Failed to apply scheduler policy (" << policy_
+                      << ") with priority (" << *priority_or_nice_ << ") to tid " << tid;
+        return false;
+    }
+
+    if (isNormalPolicy(policy_) && priority_or_nice_ &&
+        setpriority(PRIO_PROCESS, tid, *priority_or_nice_) == -1) {
+        PLOG(WARNING) << "SetSchedulerPolicy: Failed to apply nice (" << *priority_or_nice_
+                      << ") to tid " << tid;
+        return false;
+    }
+
+    return true;
+}
+
 bool ApplyProfileAction::ExecuteForProcess(uid_t uid, pid_t pid) const {
     for (const auto& profile : profiles_) {
         profile->ExecuteForProcess(uid, pid);
@@ -903,15 +929,12 @@ bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name) {
                     LOG(WARNING) << "JoinCgroup: controller " << controller_name << " is not found";
                 }
             } else if (action_name == "SetTimerSlack") {
-                std::string slack_value = params_val["Slack"].asString();
-                char* end;
-                unsigned long slack;
-
-                slack = strtoul(slack_value.c_str(), &end, 10);
-                if (end > slack_value.c_str()) {
-                    profile->Add(std::make_unique<SetTimerSlackAction>(slack));
+                const std::string slack_string = params_val["Slack"].asString();
+                std::optional<long> slack = readLong(slack_string);
+                if (slack && *slack >= 0) {
+                    profile->Add(std::make_unique<SetTimerSlackAction>(*slack));
                 } else {
-                    LOG(WARNING) << "SetTimerSlack: invalid parameter: " << slack_value;
+                    LOG(WARNING) << "SetTimerSlack: invalid parameter: " << slack_string;
                 }
             } else if (action_name == "SetAttribute") {
                 std::string attr_name = params_val["Name"].asString();
@@ -925,23 +948,6 @@ bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name) {
                 } else {
                     LOG(WARNING) << "SetAttribute: unknown attribute: " << attr_name;
                 }
-            } else if (action_name == "SetClamps") {
-                std::string boost_value = params_val["Boost"].asString();
-                std::string clamp_value = params_val["Clamp"].asString();
-                char* end;
-                unsigned long boost;
-
-                boost = strtoul(boost_value.c_str(), &end, 10);
-                if (end > boost_value.c_str()) {
-                    unsigned long clamp = strtoul(clamp_value.c_str(), &end, 10);
-                    if (end > clamp_value.c_str()) {
-                        profile->Add(std::make_unique<SetClampsAction>(boost, clamp));
-                    } else {
-                        LOG(WARNING) << "SetClamps: invalid parameter " << clamp_value;
-                    }
-                } else {
-                    LOG(WARNING) << "SetClamps: invalid parameter: " << boost_value;
-                }
             } else if (action_name == "WriteFile") {
                 std::string attr_filepath = params_val["FilePath"].asString();
                 std::string attr_procfilepath = params_val["ProcFilePath"].asString();
@@ -959,6 +965,73 @@ bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name) {
                     LOG(WARNING) << "WriteFile: invalid parameter: "
                                  << "empty value";
                 }
+            } else if (action_name == "SetSchedulerPolicy") {
+                const std::map<std::string, int> POLICY_MAP = {
+                    {"SCHED_OTHER", SCHED_OTHER},
+                    {"SCHED_BATCH", SCHED_BATCH},
+                    {"SCHED_IDLE", SCHED_IDLE},
+                    {"SCHED_FIFO", SCHED_FIFO},
+                    {"SCHED_RR", SCHED_RR},
+                };
+                const std::string policy_str = params_val["Policy"].asString();
+
+                const auto it = POLICY_MAP.find(policy_str);
+                if (it == POLICY_MAP.end()) {
+                    LOG(WARNING) << "SetSchedulerPolicy: invalid policy " << policy_str;
+                    continue;
+                }
+
+                const int policy = it->second;
+
+                if (SetSchedulerPolicyAction::isNormalPolicy(policy)) {
+                    if (params_val.isMember("Priority")) {
+                        LOG(WARNING) << "SetSchedulerPolicy: Normal policies (" << policy_str
+                                     << ") use Nice values, not Priority values";
+                    }
+
+                    if (params_val.isMember("Nice")) {
+                        // If present, this optional value will be passed in an additional syscall
+                        // to setpriority(), since the sched_priority value must be 0 for calls to
+                        // sched_setscheduler() with "normal" policies.
+                        const std::string nice_string = params_val["Nice"].asString();
+                        const std::optional<int> nice = readLong(nice_string);
+
+                        if (!nice) {
+                            LOG(FATAL) << "Invalid nice value specified: " << nice_string;
+                        }
+                        const int LINUX_MIN_NICE = -20;
+                        const int LINUX_MAX_NICE = 19;
+                        if (*nice < LINUX_MIN_NICE || *nice > LINUX_MAX_NICE) {
+                            LOG(WARNING) << "SetSchedulerPolicy: Provided nice (" << *nice
+                                         << ") appears out of range.";
+                        }
+                        profile->Add(std::make_unique<SetSchedulerPolicyAction>(policy, *nice));
+                    } else {
+                        profile->Add(std::make_unique<SetSchedulerPolicyAction>(policy));
+                    }
+                } else {
+                    if (params_val.isMember("Nice")) {
+                        LOG(WARNING) << "SetSchedulerPolicy: Real-time policies (" << policy_str
+                                     << ") use Priority values, not Nice values";
+                    }
+
+                    // This is a "virtual priority" as described by `man 2 sched_get_priority_min`
+                    // that will be mapped onto the following range for the provided policy:
+                    // [sched_get_priority_min(), sched_get_priority_max()]
+
+                    const std::string priority_string = params_val["Priority"].asString();
+                    std::optional<long> virtual_priority = readLong(priority_string);
+                    if (virtual_priority && *virtual_priority > 0) {
+                        int priority;
+                        if (SetSchedulerPolicyAction::toPriority(policy, *virtual_priority,
+                                                                 priority)) {
+                            profile->Add(
+                                    std::make_unique<SetSchedulerPolicyAction>(policy, priority));
+                        }
+                    } else {
+                        LOG(WARNING) << "Invalid priority value: " << priority_string;
+                    }
+                }
             } else {
                 LOG(WARNING) << "Unknown profile action: " << action_name;
             }
diff --git a/libprocessgroup/task_profiles.h b/libprocessgroup/task_profiles.h
index abb3ca5c3..d0b50436c 100644
--- a/libprocessgroup/task_profiles.h
+++ b/libprocessgroup/task_profiles.h
@@ -21,6 +21,7 @@
 #include <map>
 #include <memory>
 #include <mutex>
+#include <optional>
 #include <span>
 #include <string>
 #include <string_view>
@@ -77,7 +78,7 @@ class ProfileAction {
 
     // Default implementations will fail
     virtual bool ExecuteForProcess(uid_t, pid_t) const { return false; }
-    virtual bool ExecuteForTask(int) const { return false; }
+    virtual bool ExecuteForTask(pid_t) const { return false; }
     virtual bool ExecuteForUID(uid_t) const { return false; }
 
     virtual void EnableResourceCaching(ResourceCacheType) {}
@@ -90,19 +91,6 @@ class ProfileAction {
 };
 
 // Profile actions
-class SetClampsAction : public ProfileAction {
-  public:
-    SetClampsAction(int boost, int clamp) noexcept : boost_(boost), clamp_(clamp) {}
-
-    const char* Name() const override { return "SetClamps"; }
-    bool ExecuteForProcess(uid_t uid, pid_t pid) const override;
-    bool ExecuteForTask(pid_t tid) const override;
-
-  protected:
-    int boost_;
-    int clamp_;
-};
-
 class SetTimerSlackAction : public ProfileAction {
   public:
     SetTimerSlackAction(unsigned long slack) noexcept : slack_(slack) {}
@@ -114,8 +102,6 @@ class SetTimerSlackAction : public ProfileAction {
 
   private:
     unsigned long slack_;
-
-    static bool IsTimerSlackSupported(pid_t tid);
 };
 
 // Set attribute profile element
@@ -189,6 +175,25 @@ class WriteFileAction : public ProfileAction {
     CacheUseResult UseCachedFd(ResourceCacheType cache_type, const std::string& value) const;
 };
 
+// Set scheduler policy action
+class SetSchedulerPolicyAction : public ProfileAction {
+  public:
+    SetSchedulerPolicyAction(int policy)
+        : policy_(policy) {}
+    SetSchedulerPolicyAction(int policy, int priority_or_nice)
+        : policy_(policy), priority_or_nice_(priority_or_nice) {}
+
+    const char* Name() const override { return "SetSchedulerPolicy"; }
+    bool ExecuteForTask(pid_t tid) const override;
+
+    static bool isNormalPolicy(int policy);
+    static bool toPriority(int policy, int virtual_priority, int& priority_out);
+
+  private:
+    int policy_;
+    std::optional<int> priority_or_nice_;
+};
+
 class TaskProfile {
   public:
     TaskProfile(const std::string& name) : name_(name), res_cached_(false) {}
diff --git a/libprocessgroup/util/Android.bp b/libprocessgroup/util/Android.bp
index 54ba69b4e..1c74d4ed5 100644
--- a/libprocessgroup/util/Android.bp
+++ b/libprocessgroup/util/Android.bp
@@ -37,8 +37,16 @@ cc_library_static {
         "include",
     ],
     srcs: [
+        "cgroup_controller.cpp",
+        "cgroup_descriptor.cpp",
         "util.cpp",
     ],
+    shared_libs: [
+        "libbase",
+    ],
+    static_libs: [
+        "libjsoncpp",
+    ],
     defaults: ["libprocessgroup_build_flags_cc"],
 }
 
diff --git a/libprocessgroup/cgrouprc_format/cgroup_controller.cpp b/libprocessgroup/util/cgroup_controller.cpp
similarity index 90%
rename from libprocessgroup/cgrouprc_format/cgroup_controller.cpp
rename to libprocessgroup/util/cgroup_controller.cpp
index 0dd909a29..fb4168075 100644
--- a/libprocessgroup/cgrouprc_format/cgroup_controller.cpp
+++ b/libprocessgroup/util/cgroup_controller.cpp
@@ -14,11 +14,9 @@
  * limitations under the License.
  */
 
-#include <processgroup/format/cgroup_controller.h>
+#include <processgroup/cgroup_controller.h>
 
-namespace android {
-namespace cgrouprc {
-namespace format {
+#include <cstring>
 
 CgroupController::CgroupController(uint32_t version, uint32_t flags, const std::string& name,
                                    const std::string& path, uint32_t max_activation_depth)
@@ -54,8 +52,4 @@ const char* CgroupController::path() const {
 
 void CgroupController::set_flags(uint32_t flags) {
     flags_ = flags;
-}
-
-}  // namespace format
-}  // namespace cgrouprc
-}  // namespace android
+}
\ No newline at end of file
diff --git a/libprocessgroup/util/cgroup_descriptor.cpp b/libprocessgroup/util/cgroup_descriptor.cpp
new file mode 100644
index 000000000..4d3347f34
--- /dev/null
+++ b/libprocessgroup/util/cgroup_descriptor.cpp
@@ -0,0 +1,38 @@
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
+#include <processgroup/cgroup_descriptor.h>
+
+#include <processgroup/util.h>  // For flag values
+
+CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
+                                   const std::string& path, mode_t mode, const std::string& uid,
+                                   const std::string& gid, uint32_t flags,
+                                   uint32_t max_activation_depth)
+    : controller_(version, flags, name, path, max_activation_depth),
+      mode_(mode),
+      uid_(uid),
+      gid_(gid) {}
+
+void CgroupDescriptor::set_mounted(bool mounted) {
+    uint32_t flags = controller_.flags();
+    if (mounted) {
+        flags |= CGROUPRC_CONTROLLER_FLAG_MOUNTED;
+    } else {
+        flags &= ~CGROUPRC_CONTROLLER_FLAG_MOUNTED;
+    }
+    controller_.set_flags(flags);
+}
diff --git a/libprocessgroup/cgrouprc_format/include/processgroup/format/cgroup_controller.h b/libprocessgroup/util/include/processgroup/cgroup_controller.h
similarity index 87%
rename from libprocessgroup/cgrouprc_format/include/processgroup/format/cgroup_controller.h
rename to libprocessgroup/util/include/processgroup/cgroup_controller.h
index c0c1f6034..fe6a829a0 100644
--- a/libprocessgroup/cgrouprc_format/include/processgroup/format/cgroup_controller.h
+++ b/libprocessgroup/util/include/processgroup/cgroup_controller.h
@@ -20,11 +20,7 @@
 #include <cstdint>
 #include <string>
 
-namespace android {
-namespace cgrouprc {
-namespace format {
-
-// Minimal controller description to be mmapped into process address space
+// Minimal controller description
 struct CgroupController {
   public:
     CgroupController() = default;
@@ -48,8 +44,4 @@ struct CgroupController {
     uint32_t max_activation_depth_ = UINT32_MAX;
     char name_[CGROUP_NAME_BUF_SZ] = {};
     char path_[CGROUP_PATH_BUF_SZ] = {};
-};
-
-}  // namespace format
-}  // namespace cgrouprc
-}  // namespace android
+};
\ No newline at end of file
diff --git a/libprocessgroup/util/include/processgroup/cgroup_descriptor.h b/libprocessgroup/util/include/processgroup/cgroup_descriptor.h
new file mode 100644
index 000000000..1afd2ee9c
--- /dev/null
+++ b/libprocessgroup/util/include/processgroup/cgroup_descriptor.h
@@ -0,0 +1,45 @@
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
+#pragma once
+
+#include <cstdint>
+#include <string>
+
+#include <sys/stat.h>
+
+#include <processgroup/cgroup_controller.h>
+
+// Complete controller description for mounting cgroups
+class CgroupDescriptor {
+  public:
+    CgroupDescriptor(uint32_t version, const std::string& name, const std::string& path,
+                     mode_t mode, const std::string& uid, const std::string& gid, uint32_t flags,
+                     uint32_t max_activation_depth);
+
+    const CgroupController* controller() const { return &controller_; }
+    mode_t mode() const { return mode_; }
+    std::string uid() const { return uid_; }
+    std::string gid() const { return gid_; }
+
+    void set_mounted(bool mounted);
+
+  private:
+    CgroupController controller_;
+    mode_t mode_ = 0;
+    std::string uid_;
+    std::string gid_;
+};
diff --git a/libprocessgroup/util/include/processgroup/util.h b/libprocessgroup/util/include/processgroup/util.h
index 8d013af55..2c7b32926 100644
--- a/libprocessgroup/util/include/processgroup/util.h
+++ b/libprocessgroup/util/include/processgroup/util.h
@@ -16,10 +16,20 @@
 
 #pragma once
 
+#include <map>
 #include <string>
 
-namespace util {
+#include "cgroup_descriptor.h"
+
+// Duplicated from cgrouprc.h. Don't depend on libcgrouprc here.
+#define CGROUPRC_CONTROLLER_FLAG_MOUNTED 0x1
+#define CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION 0x2
+#define CGROUPRC_CONTROLLER_FLAG_OPTIONAL 0x4
 
 unsigned int GetCgroupDepth(const std::string& controller_root, const std::string& cgroup_path);
 
-}  // namespace util
+using CgroupControllerName = std::string;
+using CgroupDescriptorMap = std::map<CgroupControllerName, CgroupDescriptor>;
+bool ReadDescriptors(CgroupDescriptorMap* descriptors);
+
+bool ActivateControllers(const std::string& path, const CgroupDescriptorMap& descriptors);
diff --git a/libprocessgroup/util/tests/util.cpp b/libprocessgroup/util/tests/util.cpp
index 1de7d6f3f..6caef8ee3 100644
--- a/libprocessgroup/util/tests/util.cpp
+++ b/libprocessgroup/util/tests/util.cpp
@@ -18,8 +18,6 @@
 
 #include "gtest/gtest.h"
 
-using util::GetCgroupDepth;
-
 TEST(EmptyInputs, bothEmpty) {
     EXPECT_EQ(GetCgroupDepth({}, {}), 0);
 }
diff --git a/libprocessgroup/util/util.cpp b/libprocessgroup/util/util.cpp
index 9b88a223a..14016751c 100644
--- a/libprocessgroup/util/util.cpp
+++ b/libprocessgroup/util/util.cpp
@@ -18,9 +18,33 @@
 
 #include <algorithm>
 #include <iterator>
+#include <optional>
+#include <string_view>
+
+#include <mntent.h>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/properties.h>
+#include <android-base/stringprintf.h>
+#include <json/reader.h>
+#include <json/value.h>
+
+#include "../build_flags.h"
+#include "../internal.h"
+
+using android::base::GetUintProperty;
 
 namespace {
 
+constexpr const char* CGROUPS_DESC_FILE = "/etc/cgroups.json";
+constexpr const char* CGROUPS_DESC_VENDOR_FILE = "/vendor/etc/cgroups.json";
+constexpr const char* TEMPLATE_CGROUPS_DESC_API_FILE = "/etc/task_profiles/cgroups_%u.json";
+
+// This should match the publicly declared value in processgroup.h,
+// but we don't want this library to depend on libprocessgroup.
+constexpr std::string CGROUPV2_HIERARCHY_NAME_INTERNAL = "cgroup2";
+
 const char SEP = '/';
 
 std::string DeduplicateAndTrimSeparators(const std::string& path) {
@@ -42,9 +66,135 @@ std::string DeduplicateAndTrimSeparators(const std::string& path) {
     return ret;
 }
 
+void MergeCgroupToDescriptors(CgroupDescriptorMap* descriptors, const Json::Value& cgroup,
+                              const std::string& name, const std::string& root_path,
+                              int cgroups_version) {
+    const std::string cgroup_path = cgroup["Path"].asString();
+    std::string path;
+
+    if (!root_path.empty()) {
+        path = root_path;
+        if (cgroup_path != ".") {
+            path += "/";
+            path += cgroup_path;
+        }
+    } else {
+        path = cgroup_path;
+    }
+
+    uint32_t controller_flags = 0;
+
+    if (cgroup["NeedsActivation"].isBool() && cgroup["NeedsActivation"].asBool()) {
+        controller_flags |= CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION;
+    }
+
+    if (cgroup["Optional"].isBool() && cgroup["Optional"].asBool()) {
+        controller_flags |= CGROUPRC_CONTROLLER_FLAG_OPTIONAL;
+    }
+
+    uint32_t max_activation_depth = UINT32_MAX;
+    if (cgroup.isMember("MaxActivationDepth")) {
+        max_activation_depth = cgroup["MaxActivationDepth"].asUInt();
+    }
+
+    CgroupDescriptor descriptor(
+            cgroups_version, name, path, std::strtoul(cgroup["Mode"].asString().c_str(), 0, 8),
+            cgroup["UID"].asString(), cgroup["GID"].asString(), controller_flags,
+            max_activation_depth);
+
+    auto iter = descriptors->find(name);
+    if (iter == descriptors->end()) {
+        descriptors->emplace(name, descriptor);
+    } else {
+        iter->second = descriptor;
+    }
+}
+
+bool ReadDescriptorsFromFile(const std::string& file_name, CgroupDescriptorMap* descriptors) {
+    static constexpr bool force_memcg_v2 = android::libprocessgroup_flags::force_memcg_v2();
+    std::vector<CgroupDescriptor> result;
+    std::string json_doc;
+
+    if (!android::base::ReadFileToString(file_name, &json_doc)) {
+        PLOG(ERROR) << "Failed to read task profiles from " << file_name;
+        return false;
+    }
+
+    Json::CharReaderBuilder builder;
+    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
+    Json::Value root;
+    std::string errorMessage;
+    if (!reader->parse(&*json_doc.begin(), &*json_doc.end(), &root, &errorMessage)) {
+        LOG(ERROR) << "Failed to parse cgroups description: " << errorMessage;
+        return false;
+    }
+
+    if (root.isMember("Cgroups")) {
+        const Json::Value& cgroups = root["Cgroups"];
+        for (Json::Value::ArrayIndex i = 0; i < cgroups.size(); ++i) {
+            std::string name = cgroups[i]["Controller"].asString();
+
+            if (force_memcg_v2 && name == "memory") continue;
+
+            MergeCgroupToDescriptors(descriptors, cgroups[i], name, "", 1);
+        }
+    }
+
+    bool memcgv2_present = false;
+    std::string root_path;
+    if (root.isMember("Cgroups2")) {
+        const Json::Value& cgroups2 = root["Cgroups2"];
+        root_path = cgroups2["Path"].asString();
+        MergeCgroupToDescriptors(descriptors, cgroups2, CGROUPV2_HIERARCHY_NAME_INTERNAL, "", 2);
+
+        const Json::Value& childGroups = cgroups2["Controllers"];
+        for (Json::Value::ArrayIndex i = 0; i < childGroups.size(); ++i) {
+            std::string name = childGroups[i]["Controller"].asString();
+
+            if (force_memcg_v2 && name == "memory") memcgv2_present = true;
+
+            MergeCgroupToDescriptors(descriptors, childGroups[i], name, root_path, 2);
+        }
+    }
+
+    if (force_memcg_v2 && !memcgv2_present) {
+        LOG(INFO) << "Forcing memcg to v2 hierarchy";
+        Json::Value memcgv2;
+        memcgv2["Controller"] = "memory";
+        memcgv2["NeedsActivation"] = true;
+        memcgv2["Path"] = ".";
+        memcgv2["Optional"] = true;  // In case of cgroup_disabled=memory, so we can still boot
+        MergeCgroupToDescriptors(descriptors, memcgv2, "memory",
+                                 root_path.empty() ? CGROUP_V2_ROOT_DEFAULT : root_path, 2);
+    }
+
+    return true;
+}
+
+using MountDir = std::string;
+using MountOpts = std::string;
+static std::optional<std::map<MountDir, MountOpts>> ReadCgroupV1Mounts() {
+    FILE* fp = setmntent("/proc/mounts", "r");
+    if (fp == nullptr) {
+        PLOG(ERROR) << "Failed to read mounts";
+        return std::nullopt;
+    }
+
+    std::map<MountDir, MountOpts> mounts;
+    const std::string_view CGROUP_V1_TYPE = "cgroup";
+    for (mntent* mentry = getmntent(fp); mentry != nullptr; mentry = getmntent(fp)) {
+        if (mentry->mnt_type && CGROUP_V1_TYPE == mentry->mnt_type &&
+            mentry->mnt_dir && mentry->mnt_opts) {
+            mounts[mentry->mnt_dir] = mentry->mnt_opts;
+        }
+    }
+    endmntent(fp);
+
+    return mounts;
+}
+
 }  // anonymous namespace
 
-namespace util {
 
 unsigned int GetCgroupDepth(const std::string& controller_root, const std::string& cgroup_path) {
     const std::string deduped_root = DeduplicateAndTrimSeparators(controller_root);
@@ -56,4 +206,70 @@ unsigned int GetCgroupDepth(const std::string& controller_root, const std::strin
     return std::count(deduped_path.begin() + deduped_root.size(), deduped_path.end(), SEP);
 }
 
-}  // namespace util
+bool ReadDescriptors(CgroupDescriptorMap* descriptors) {
+    // load system cgroup descriptors
+    if (!ReadDescriptorsFromFile(CGROUPS_DESC_FILE, descriptors)) {
+        return false;
+    }
+
+    // load API-level specific system cgroups descriptors if available
+    unsigned int api_level = GetUintProperty<unsigned int>("ro.product.first_api_level", 0);
+    if (api_level > 0) {
+        std::string api_cgroups_path =
+                android::base::StringPrintf(TEMPLATE_CGROUPS_DESC_API_FILE, api_level);
+        if (!access(api_cgroups_path.c_str(), F_OK) || errno != ENOENT) {
+            if (!ReadDescriptorsFromFile(api_cgroups_path, descriptors)) {
+                return false;
+            }
+        }
+    }
+
+    // load vendor cgroup descriptors if the file exists
+    if (!access(CGROUPS_DESC_VENDOR_FILE, F_OK) &&
+        !ReadDescriptorsFromFile(CGROUPS_DESC_VENDOR_FILE, descriptors)) {
+        return false;
+    }
+
+    // check for v1 mount/usability status
+    std::optional<std::map<MountDir, MountOpts>> v1Mounts;
+    for (auto& [name, descriptor] : *descriptors) {
+        const CgroupController* const controller = descriptor.controller();
+
+        if (controller->version() != 1) continue;
+
+        // Read only once, and only if we have at least one v1 controller
+        if (!v1Mounts) {
+            v1Mounts = ReadCgroupV1Mounts();
+            if (!v1Mounts) return false;
+        }
+
+        if (const auto it = v1Mounts->find(controller->path()); it != v1Mounts->end()) {
+            if (it->second.contains(controller->name())) descriptor.set_mounted(true);
+        }
+    }
+
+    return true;
+}
+
+bool ActivateControllers(const std::string& path, const CgroupDescriptorMap& descriptors) {
+    for (const auto& [name, descriptor] : descriptors) {
+        const uint32_t flags = descriptor.controller()->flags();
+        const uint32_t max_activation_depth = descriptor.controller()->max_activation_depth();
+        const unsigned int depth = GetCgroupDepth(descriptor.controller()->path(), path);
+
+        if (flags & CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION && depth < max_activation_depth) {
+            std::string str("+");
+            str.append(descriptor.controller()->name());
+            if (!android::base::WriteStringToFile(str, path + "/cgroup.subtree_control")) {
+                if (flags & CGROUPRC_CONTROLLER_FLAG_OPTIONAL) {
+                    PLOG(WARNING) << "Activation of cgroup controller " << str
+                                  << " failed in path " << path;
+                } else {
+                    return false;
+                }
+            }
+        }
+    }
+    return true;
+}
+
diff --git a/libstats/expresslog/Android.bp b/libstats/expresslog/Android.bp
index 96ab59b10..f70252afc 100644
--- a/libstats/expresslog/Android.bp
+++ b/libstats/expresslog/Android.bp
@@ -1,4 +1,3 @@
-
 //
 // Copyright (C) 2023 The Android Open Source Project
 //
@@ -16,6 +15,7 @@
 //
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_telemetry_client_infra",
 }
 
 cc_defaults {
@@ -28,6 +28,7 @@ cc_defaults {
 
 cc_library {
     name: "libexpresslog",
+    host_supported: true,
     defaults: ["expresslog_defaults"],
     cflags: [
         "-DNAMESPACE_FOR_HASH_FUNCTIONS=farmhash",
@@ -74,6 +75,7 @@ genrule {
 
 cc_library_static {
     name: "libstatslog_express",
+    host_supported: true,
     generated_sources: ["statslog_express.cpp"],
     generated_headers: ["statslog_express.h"],
     export_generated_headers: ["statslog_express.h"],
@@ -119,5 +121,5 @@ cc_test {
     ],
     shared_libs: [
         "libstatssocket",
-    ]
+    ],
 }
diff --git a/libstats/pull_lazy/Android.bp b/libstats/pull_lazy/Android.bp
index 65dce26a0..71af17068 100644
--- a/libstats/pull_lazy/Android.bp
+++ b/libstats/pull_lazy/Android.bp
@@ -32,7 +32,7 @@ cc_test {
         "-Wall",
         "-Werror",
     ],
-    test_suites: ["device-tests", "mts-statsd"],
+    test_suites: ["device-tests"],
     test_config: "libstatspull_lazy_test.xml",
     // TODO(b/153588990): Remove when the build system properly separates.
     // 32bit and 64bit architectures.
diff --git a/libstats/pull_rust/Android.bp b/libstats/pull_rust/Android.bp
index 69020267d..2a8939edb 100644
--- a/libstats/pull_rust/Android.bp
+++ b/libstats/pull_rust/Android.bp
@@ -61,7 +61,6 @@ rust_library {
     srcs: ["stats_pull.rs"],
     rustlibs: [
         "liblog_rust",
-        "libonce_cell",
         "libstatslog_rust_header",
         "libstatspull_bindgen",
     ],
diff --git a/libstats/pull_rust/stats_pull.rs b/libstats/pull_rust/stats_pull.rs
index b2bebcc4e..03929e3b2 100644
--- a/libstats/pull_rust/stats_pull.rs
+++ b/libstats/pull_rust/stats_pull.rs
@@ -14,13 +14,12 @@
 
 //! A Rust interface for the StatsD pull API.
 
-use once_cell::sync::Lazy;
 use statslog_rust_header::{Atoms, Stat, StatsError};
 use statspull_bindgen::*;
 use std::collections::HashMap;
 use std::convert::TryInto;
 use std::os::raw::c_void;
-use std::sync::Mutex;
+use std::sync::{LazyLock, Mutex};
 
 /// The return value of callbacks.
 pub type StatsPullResult = Vec<Box<dyn Stat>>;
@@ -107,8 +106,8 @@ impl Default for Metadata {
     }
 }
 
-static COOKIES: Lazy<Mutex<HashMap<i32, fn() -> StatsPullResult>>> =
-    Lazy::new(|| Mutex::new(HashMap::new()));
+static COOKIES: LazyLock<Mutex<HashMap<i32, fn() -> StatsPullResult>>> =
+    LazyLock::new(|| Mutex::new(HashMap::new()));
 
 /// # Safety
 ///
diff --git a/libstats/socket_lazy/Android.bp b/libstats/socket_lazy/Android.bp
index 241e87af3..945a7c494 100644
--- a/libstats/socket_lazy/Android.bp
+++ b/libstats/socket_lazy/Android.bp
@@ -36,7 +36,6 @@ cc_test {
     ],
     test_suites: [
         "device-tests",
-        "mts-statsd",
     ],
     test_config: "libstatssocket_lazy_test.xml",
     // TODO(b/153588990): Remove when the build system properly separates.
diff --git a/libsysutils/EventLogTags.logtags b/libsysutils/EventLogTags.logtags
index 713f8cd6b..bb06d3433 100644
--- a/libsysutils/EventLogTags.logtags
+++ b/libsysutils/EventLogTags.logtags
@@ -1,4 +1,4 @@
-# See system/core/logcat/event.logtags for a description of the format of this file.
+# See system/logging/logcat/event.logtags for a description of the format of this file.
 
 # FrameworkListener dispatchCommand overflow
 78001 exp_det_dispatchCommand_overflow
diff --git a/libutils/OWNERS b/libutils/OWNERS
index 40164aae0..4ce689304 100644
--- a/libutils/OWNERS
+++ b/libutils/OWNERS
@@ -1 +1,2 @@
+shayba@google.com
 smoreland@google.com
diff --git a/libutils/Threads.cpp b/libutils/Threads.cpp
index d8d75acf4..111d46af9 100644
--- a/libutils/Threads.cpp
+++ b/libutils/Threads.cpp
@@ -313,11 +313,6 @@ void androidSetCreateThreadFunc(android_create_thread_fn func)
 int androidSetThreadPriority(pid_t tid, int pri)
 {
     int rc = 0;
-    int curr_pri = getpriority(PRIO_PROCESS, tid);
-
-    if (curr_pri == pri) {
-        return rc;
-    }
 
     if (setpriority(PRIO_PROCESS, tid, pri) < 0) {
         rc = INVALID_OPERATION;
diff --git a/libutils/binder/RefBase.cpp b/libutils/binder/RefBase.cpp
index 2d2e40b7e..4291f1e21 100644
--- a/libutils/binder/RefBase.cpp
+++ b/libutils/binder/RefBase.cpp
@@ -787,7 +787,7 @@ RefBase::~RefBase()
             // sp<T>(T*) constructor, assuming that if the object is around, it is already
             // owned by an sp<>.
             ALOGW("RefBase: Explicit destruction, weak count = %d (in %p). Use sp<> to manage this "
-                  "object.",
+                  "object. Note - if weak count is 0, this leaks mRefs (weakref_impl).",
                   mRefs->mWeak.load(), this);
 
 #if ANDROID_UTILS_CALLSTACK_ENABLED
diff --git a/libutils/binder/VectorImpl.cpp b/libutils/binder/VectorImpl.cpp
index d951b8bbb..a62664f7b 100644
--- a/libutils/binder/VectorImpl.cpp
+++ b/libutils/binder/VectorImpl.cpp
@@ -463,7 +463,8 @@ void VectorImpl::_shrink(size_t where, size_t amount)
     size_t new_size;
     LOG_ALWAYS_FATAL_IF(__builtin_sub_overflow(mCount, amount, &new_size));
 
-    if (new_size < (capacity() / 2)) {
+    const size_t prev_capacity = capacity();
+    if (new_size < (prev_capacity / 2) && prev_capacity > kMinVectorCapacity) {
         // NOTE: (new_size * 2) is safe because capacity didn't overflow and
         // new_size < (capacity / 2)).
         const size_t new_capacity = max(kMinVectorCapacity, new_size * 2);
diff --git a/libvendorsupport/Android.bp b/libvendorsupport/Android.bp
index a22737c06..f9a889b94 100644
--- a/libvendorsupport/Android.bp
+++ b/libvendorsupport/Android.bp
@@ -35,32 +35,3 @@ cc_library {
         "libbase",
     ],
 }
-
-cc_library_headers {
-    name: "libvendorsupport_llndk_headers",
-    host_supported: true,
-    vendor_available: true,
-    recovery_available: true,
-    ramdisk_available: true,
-    vendor_ramdisk_available: true,
-    native_bridge_supported: true,
-
-    export_include_dirs: ["include_llndk"],
-    llndk: {
-        llndk_headers: true,
-    },
-
-    apex_available: [
-        "//apex_available:platform",
-        "//apex_available:anyapex",
-    ],
-    min_sdk_version: "apex_inherit",
-
-    system_shared_libs: [],
-    stl: "none",
-
-    // This header library is used for libc and must be available to any sdk
-    // versions.
-    // Setting sdk_version to the lowest version allows the dependencies.
-    sdk_version: "1",
-}
diff --git a/libvendorsupport/include_llndk/android/llndk-versioning.h b/libvendorsupport/include_llndk/android/llndk-versioning.h
deleted file mode 100644
index cf82fb712..000000000
--- a/libvendorsupport/include_llndk/android/llndk-versioning.h
+++ /dev/null
@@ -1,45 +0,0 @@
-// Copyright (C) 2024 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#pragma once
-
-// LLNDK (https://source.android.com/docs/core/architecture/vndk/build-system#ll-ndk) is similar to
-// NDK, but uses its own versioning of YYYYMM format for vendor builds. The LLNDK symbols are
-// enabled when the vendor api level is equal to or newer than the ro.board.api_level. These symbols
-// must be annotated in map.txt files with the `# llndk=YYYYMM` annotation. They also must be marked
-// with `__INTRODUCED_IN_LLNDK(YYYYMM)` in the header files. It leaves a no-op annotation for ABI
-// analysis.
-#if !defined(__INTRODUCED_IN_LLNDK)
-#define __INTRODUCED_IN_LLNDK(vendor_api_level) \
-    __attribute__((annotate("introduced_in_llndk=" #vendor_api_level)))
-#endif
-
-#if defined(__ANDROID_VENDOR__)
-
-// Use this macro as an `if` statement to call an API that are available to both NDK and LLNDK.
-// This returns true for the vendor modules if the vendor_api_level is less than or equal to the
-// ro.board.api_level.
-#define API_LEVEL_AT_LEAST(sdk_api_level, vendor_api_level) \
-    constexpr(__ANDROID_VENDOR_API__ >= vendor_api_level)
-
-#else  // __ANDROID_VENDOR__
-
-// For non-vendor modules, API_LEVEL_AT_LEAST is replaced with __builtin_available(sdk_api_level) to
-// guard the API for __INTRODUCED_IN.
-#if !defined(API_LEVEL_AT_LEAST)
-#define API_LEVEL_AT_LEAST(sdk_api_level, vendor_api_level) \
-    (__builtin_available(android sdk_api_level, *))
-#endif
-
-#endif  // __ANDROID_VENDOR__
diff --git a/mkbootfs/Android.bp b/mkbootfs/Android.bp
index cd2a6245a..e0191f0dc 100644
--- a/mkbootfs/Android.bp
+++ b/mkbootfs/Android.bp
@@ -6,7 +6,7 @@ package {
 
 cc_binary_host {
     name: "mkbootfs",
-    srcs: ["mkbootfs.c"],
+    srcs: ["mkbootfs.cpp"],
     cflags: ["-Werror"],
     static_libs: [
         "libbase",
diff --git a/mkbootfs/mkbootfs.c b/mkbootfs/mkbootfs.cpp
similarity index 94%
rename from mkbootfs/mkbootfs.c
rename to mkbootfs/mkbootfs.cpp
index 84a0a4eee..a45c6a20a 100644
--- a/mkbootfs/mkbootfs.c
+++ b/mkbootfs/mkbootfs.cpp
@@ -19,6 +19,9 @@
 #include <private/android_filesystem_config.h>
 #include <private/fs_config.h>
 
+#include <android-base/file.h>
+#include <string>
+
 /* NOTES
 **
 ** - see https://www.kernel.org/doc/Documentation/early-userspace/buffer-format.txt
@@ -75,7 +78,7 @@ static void fix_stat(const char *path, struct stat *s)
     }
 }
 
-static void _eject(struct stat *s, char *out, int olen, char *data, unsigned datasize)
+static void _eject(struct stat *s, const char *out, int olen, char *data, unsigned datasize)
 {
     // Nothing is special about this value, just picked something in the
     // approximate range that was being used already, and avoiding small
@@ -151,9 +154,10 @@ static void _archive_dir(char *in, char *out, int ilen, int olen)
     DIR* d = opendir(in);
     if (d == NULL) err(1, "cannot open directory '%s'", in);
 
+    // TODO: switch to std::vector
     int size = 32;
     int entries = 0;
-    char** names = malloc(size * sizeof(char*));
+    char** names = (char**) malloc(size * sizeof(char*));
     if (names == NULL) {
       errx(1, "failed to allocate dir names array (size %d)", size);
     }
@@ -167,7 +171,7 @@ static void _archive_dir(char *in, char *out, int ilen, int olen)
 
         if (entries >= size) {
           size *= 2;
-          names = realloc(names, size * sizeof(char*));
+          names = (char**) realloc(names, size * sizeof(char*));
           if (names == NULL) {
             errx(1, "failed to reallocate dir names array (size %d)", size);
           }
@@ -211,20 +215,12 @@ static void _archive(char *in, char *out, int ilen, int olen)
     if(lstat(in, &s)) err(1, "could not stat '%s'", in);
 
     if(S_ISREG(s.st_mode)){
-        int fd = open(in, O_RDONLY);
-        if(fd < 0) err(1, "cannot open '%s' for read", in);
-
-        char* tmp = (char*) malloc(s.st_size);
-        if(tmp == 0) errx(1, "cannot allocate %zd bytes", s.st_size);
-
-        if(read(fd, tmp, s.st_size) != s.st_size) {
-            err(1, "cannot read %zd bytes", s.st_size);
+        std::string content;
+        if (!android::base::ReadFileToString(in, &content)) {
+            err(1, "cannot read '%s'", in);
         }
 
-        _eject(&s, out, olen, tmp, s.st_size);
-
-        free(tmp);
-        close(fd);
+        _eject(&s, out, olen, content.data(), content.size());
     } else if(S_ISDIR(s.st_mode)) {
         _eject(&s, out, olen, 0, 0);
         _archive_dir(in, out, ilen, olen);
@@ -445,15 +441,12 @@ int main(int argc, char *argv[])
     int num_dirs = argc - optind;
     argv += optind;
 
-    while(num_dirs-- > 0){
+    while (num_dirs-- > 0){
         char *x = strchr(*argv, '=');
-        if(x != 0) {
-            *x++ = 0;
-        } else {
-            x = "";
+        if (x != nullptr) {
+            *x++ = '\0';
         }
-
-        archive(*argv, x);
+        archive(*argv, x ?: "");
 
         argv++;
     }
diff --git a/property_service/libpropertyinfoserializer/property_info_serializer_test.cpp b/property_service/libpropertyinfoserializer/property_info_serializer_test.cpp
index a484441c9..bed4a73bd 100644
--- a/property_service/libpropertyinfoserializer/property_info_serializer_test.cpp
+++ b/property_service/libpropertyinfoserializer/property_info_serializer_test.cpp
@@ -729,7 +729,6 @@ TEST(propertyinfoserializer, RealProperties) {
       {"sys.ims.QMI_DAEMON_STATUS", "u:object_r:qcom_ims_prop:s0"},
       {"sys.listeners.registered", "u:object_r:qseecomtee_prop:s0"},
       {"sys.logbootcomplete", "u:object_r:system_prop:s0"},
-      {"sys.oem_unlock_allowed", "u:object_r:system_prop:s0"},
       {"sys.qcom.devup", "u:object_r:system_prop:s0"},
       {"sys.sysctl.extra_free_kbytes", "u:object_r:system_prop:s0"},
       {"sys.usb.config", "u:object_r:system_radio_prop:s0"},
diff --git a/reboot/Android.bp b/reboot/Android.bp
index 7b243bd56..1cca82457 100644
--- a/reboot/Android.bp
+++ b/reboot/Android.bp
@@ -4,10 +4,25 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-cc_binary {
-    name: "reboot",
+cc_defaults {
+    name: "reboot_defaults",
     srcs: ["reboot.c"],
     shared_libs: ["libcutils"],
     cflags: ["-Werror"],
-    recovery_available: true,
+}
+
+cc_binary {
+    name: "reboot",
+    defaults: [
+        "reboot_defaults",
+    ],
+}
+
+cc_binary {
+    name: "reboot.recovery",
+    defaults: [
+        "reboot_defaults",
+    ],
+    recovery: true,
+    stem: "reboot",
 }
diff --git a/rootdir/init.rc b/rootdir/init.rc
index 1acd63774..ae6a6588b 100644
--- a/rootdir/init.rc
+++ b/rootdir/init.rc
@@ -54,6 +54,10 @@ on early-init
     mkdir /linkerconfig/bootstrap 0755
     mkdir /linkerconfig/default 0755
 
+    # Greatly extend dm-verity's Merkle tree cache timeout.  The default timeout
+    # is much too short and is unnecessary, given that there is also a shrinker.
+    write /sys/module/dm_bufio/parameters/max_age_seconds 86400
+
     # Disable dm-verity hash prefetching, since it doesn't help performance
     # Read more in b/136247322
     write /sys/module/dm_verity/parameters/prefetch_cluster 0
@@ -70,6 +74,9 @@ on early-init
 
     start ueventd
 
+    # Mount tracefs (with GID=AID_READTRACEFS)
+    mount tracefs tracefs /sys/kernel/tracing gid=3012
+
     # Run apexd-bootstrap so that APEXes that provide critical libraries
     # become available. Note that this is executed as exec_start to ensure that
     # the libraries are available to the processes started after this statement.
@@ -80,9 +87,6 @@ on early-init
     mkdir /dev/boringssl 0755 root root
     mkdir /dev/boringssl/selftest 0755 root root
 
-    # Mount tracefs (with GID=AID_READTRACEFS)
-    mount tracefs tracefs /sys/kernel/tracing gid=3012
-
     # create sys dirctory
     mkdir /dev/sys 0755 system system
     mkdir /dev/sys/fs 0755 system system
@@ -112,37 +116,6 @@ on init
     # Create socket dir for ot-daemon
     mkdir /dev/socket/ot-daemon 0770 thread_network thread_network
 
-    # Create energy-aware scheduler tuning nodes
-    mkdir /dev/stune/foreground
-    mkdir /dev/stune/background
-    mkdir /dev/stune/top-app
-    mkdir /dev/stune/rt
-    chown system system /dev/stune
-    chown system system /dev/stune/foreground
-    chown system system /dev/stune/background
-    chown system system /dev/stune/top-app
-    chown system system /dev/stune/rt
-    chown system system /dev/stune/tasks
-    chown system system /dev/stune/foreground/tasks
-    chown system system /dev/stune/background/tasks
-    chown system system /dev/stune/top-app/tasks
-    chown system system /dev/stune/rt/tasks
-    chown system system /dev/stune/cgroup.procs
-    chown system system /dev/stune/foreground/cgroup.procs
-    chown system system /dev/stune/background/cgroup.procs
-    chown system system /dev/stune/top-app/cgroup.procs
-    chown system system /dev/stune/rt/cgroup.procs
-    chmod 0664 /dev/stune/tasks
-    chmod 0664 /dev/stune/foreground/tasks
-    chmod 0664 /dev/stune/background/tasks
-    chmod 0664 /dev/stune/top-app/tasks
-    chmod 0664 /dev/stune/rt/tasks
-    chmod 0664 /dev/stune/cgroup.procs
-    chmod 0664 /dev/stune/foreground/cgroup.procs
-    chmod 0664 /dev/stune/background/cgroup.procs
-    chmod 0664 /dev/stune/top-app/cgroup.procs
-    chmod 0664 /dev/stune/rt/cgroup.procs
-
     # cpuctl hierarchy for devices using utilclamp
     mkdir /dev/cpuctl/foreground
     mkdir /dev/cpuctl/foreground_window
@@ -216,24 +189,6 @@ on init
     chmod 0664 /dev/cpuctl/camera-daemon/tasks
     chmod 0664 /dev/cpuctl/camera-daemon/cgroup.procs
 
-    # Create an stune group for camera-specific processes
-    mkdir /dev/stune/camera-daemon
-    chown system system /dev/stune/camera-daemon
-    chown system system /dev/stune/camera-daemon/tasks
-    chown system system /dev/stune/camera-daemon/cgroup.procs
-    chmod 0664 /dev/stune/camera-daemon/tasks
-    chmod 0664 /dev/stune/camera-daemon/cgroup.procs
-
-    # Create an stune group for NNAPI HAL processes
-    mkdir /dev/stune/nnapi-hal
-    chown system system /dev/stune/nnapi-hal
-    chown system system /dev/stune/nnapi-hal/tasks
-    chown system system /dev/stune/nnapi-hal/cgroup.procs
-    chmod 0664 /dev/stune/nnapi-hal/tasks
-    chmod 0664 /dev/stune/nnapi-hal/cgroup.procs
-    write /dev/stune/nnapi-hal/schedtune.boost 1
-    write /dev/stune/nnapi-hal/schedtune.prefer_idle 1
-
     # Create blkio group and apply initial settings.
     # This feature needs kernel to support it, and the
     # device's init.rc must actually set the correct values.
@@ -644,6 +599,8 @@ on post-fs
     mkdir /metadata/ota 0750 root system
     mkdir /metadata/ota/snapshots 0750 root system
     mkdir /metadata/watchdog 0770 root system
+    mkdir /metadata/tradeinmode 0770 root system
+    mkdir /metadata/prefetch 0770 root system
 
     mkdir /metadata/apex 0700 root system
     mkdir /metadata/apex/sessions 0700 root system
@@ -656,14 +613,6 @@ on post-fs
 
     mkdir /metadata/staged-install 0770 root system
 
-    mkdir /metadata/aconfig 0775 root system
-    mkdir /metadata/aconfig/flags 0770 root system
-    mkdir /metadata/aconfig/maps 0775 root system
-    mkdir /metadata/aconfig/boot 0775 root system
-
-    mkdir /metadata/aconfig_test_missions 0775 root system
-    exec_start aconfigd-platform-init
-
 on late-fs
     # Ensure that tracefs has the correct permissions.
     # This does not work correctly if it is called in post-fs.
@@ -780,7 +729,6 @@ on post-fs-data
     mkdir /data/apex/active 0755 root system
     mkdir /data/apex/backup 0700 root system
     mkdir /data/apex/decompressed 0755 root system encryption=Require
-    mkdir /data/apex/hashtree 0700 root system
     mkdir /data/apex/sessions 0700 root system
     mkdir /data/app-staging 0751 system system encryption=DeleteIfNecessary
     mkdir /data/apex/ota_reserved 0700 root system encryption=Require
@@ -826,6 +774,8 @@ on post-fs-data
     mkdir /data/misc/shared_relro 0771 shared_relro shared_relro
     mkdir /data/misc/systemkeys 0700 system system
     mkdir /data/misc/wifi 0770 wifi wifi
+    mkdir /data/misc/wifi/mainline_supplicant 0770 wifi wifi
+    mkdir /data/misc/wifi/mainline_supplicant/sockets 0770 wifi wifi
     mkdir /data/misc/wifi/sockets 0770 wifi wifi
     mkdir /data/misc/wifi/wpa_supplicant 0770 wifi wifi
     mkdir /data/misc/ethernet 0770 system system
@@ -1050,8 +1000,14 @@ on post-fs-data
     # Wait for apexd to finish activating APEXes before starting more processes.
     wait_for_prop apexd.status activated
     perform_apex_config
-    exec_start aconfigd-mainline-init
-    start aconfigd
+
+    exec_start system_aconfigd_mainline_init
+    start system_aconfigd_socket_service
+
+    # start mainline aconfigd init, after transition, the above system_aconfigd_mainline_init
+    # will be deprecated
+    exec_start mainline_aconfigd_init
+    start mainline_aconfigd_socket_service
 
     # Create directories for boot animation.
     mkdir /data/misc/bootanim 0755 system system
@@ -1161,9 +1117,9 @@ on boot
 
     # System server manages zram writeback
     chown root system /sys/block/zram0/idle
-    chmod 0664 /sys/block/zram0/idle
+    chmod 0220 /sys/block/zram0/idle
     chown root system /sys/block/zram0/writeback
-    chmod 0664 /sys/block/zram0/writeback
+    chmod 0220 /sys/block/zram0/writeback
 
     # to access F2FS sysfs on dm-<num> directly
     mkdir /dev/sys/fs/by-name 0755 system system
@@ -1243,6 +1199,9 @@ on boot
     chown system system /sys/kernel/ipv4/tcp_rmem_min
     chown system system /sys/kernel/ipv4/tcp_rmem_def
     chown system system /sys/kernel/ipv4/tcp_rmem_max
+    chown system system /sys/firmware/acpi/tables
+    chown system system /sys/firmware/acpi/tables/BERT
+    chown system system /sys/firmware/acpi/tables/data/BERT
     chown root radio /proc/cmdline
     chown root system /proc/bootconfig
 
diff --git a/shell_and_utilities/Android.bp b/shell_and_utilities/Android.bp
index d5893de63..0a1f7c5a2 100644
--- a/shell_and_utilities/Android.bp
+++ b/shell_and_utilities/Android.bp
@@ -43,9 +43,10 @@ phony {
     required: [
         "sh.recovery",
         "toolbox.recovery",
-        "toybox.recovery",
+        "toybox_recovery",
         "ziptool.recovery",
     ],
+    recovery: true,
 }
 
 phony {
@@ -58,6 +59,7 @@ phony {
         "toolbox_vendor",
         "toybox_vendor",
     ],
+    vendor: true,
 }
 
 // shell and utilities for first stage console. The list of binaries are
diff --git a/storaged/Android.bp b/storaged/Android.bp
index 357c0e601..335874280 100644
--- a/storaged/Android.bp
+++ b/storaged/Android.bp
@@ -24,7 +24,7 @@ cc_defaults {
     shared_libs: [
         "android.hardware.health@1.0",
         "android.hardware.health@2.0",
-        "android.hardware.health-V3-ndk",
+        "android.hardware.health-V4-ndk",
         "libbase",
         "libbinder",
         "libbinder_ndk",
@@ -47,7 +47,7 @@ cc_defaults {
         "-Wall",
         "-Werror",
         "-Wextra",
-        "-Wno-unused-parameter"
+        "-Wno-unused-parameter",
     ],
 }
 
diff --git a/toolbox/Android.bp b/toolbox/Android.bp
index 120cc6e16..314254298 100644
--- a/toolbox/Android.bp
+++ b/toolbox/Android.bp
@@ -68,10 +68,16 @@ cc_defaults {
 cc_binary {
     name: "toolbox",
     defaults: ["toolbox_binary_defaults"],
-    recovery_available: true,
     vendor_ramdisk_available: true,
 }
 
+cc_binary {
+    name: "toolbox.recovery",
+    defaults: ["toolbox_binary_defaults"],
+    recovery: true,
+    stem: "toolbox",
+}
+
 cc_binary {
     name: "toolbox_vendor",
     stem: "toolbox",
diff --git a/trusty/keymaster/Android.bp b/trusty/keymaster/Android.bp
index aca59b6c6..8ebfc1aeb 100644
--- a/trusty/keymaster/Android.bp
+++ b/trusty/keymaster/Android.bp
@@ -105,10 +105,8 @@ cc_binary {
         "keymint/TrustySharedSecret.cpp",
         "keymint/service.cpp",
     ],
-    defaults: [
-        "keymint_use_latest_hal_aidl_ndk_shared",
-    ],
     shared_libs: [
+        "android.hardware.security.keymint-V4-ndk",
         "android.hardware.security.rkp-V3-ndk",
         "android.hardware.security.secureclock-V1-ndk",
         "android.hardware.security.sharedsecret-V1-ndk",
@@ -117,14 +115,15 @@ cc_binary {
         "libbinder_ndk",
         "libhardware",
         "libkeymaster_messages",
-        "libkeymint",
+        "libkeymasterconfig",
         "liblog",
         "libtrusty",
         "libutils",
     ],
-    required: [
-        "android.hardware.hardware_keystore.xml",
-    ],
+    required: select(release_flag("RELEASE_AIDL_USE_UNFROZEN"), {
+        true: ["android.hardware.hardware_keystore.xml"],
+        default: ["android.hardware.hardware_keystore_V3.xml"],
+    }),
 }
 
 prebuilt_etc {
diff --git a/trusty/keymaster/TrustyKeymaster.cpp b/trusty/keymaster/TrustyKeymaster.cpp
index b118a2001..723229d03 100644
--- a/trusty/keymaster/TrustyKeymaster.cpp
+++ b/trusty/keymaster/TrustyKeymaster.cpp
@@ -295,6 +295,13 @@ GetRootOfTrustResponse TrustyKeymaster::GetRootOfTrust(const GetRootOfTrustReque
     return response;
 }
 
+SetAdditionalAttestationInfoResponse TrustyKeymaster::SetAdditionalAttestationInfo(
+        const SetAdditionalAttestationInfoRequest& request) {
+    SetAdditionalAttestationInfoResponse response(message_version());
+    ForwardCommand(KM_SET_ADDITIONAL_ATTESTATION_INFO, request, &response);
+    return response;
+}
+
 GetHwInfoResponse TrustyKeymaster::GetHwInfo() {
     GetHwInfoResponse response(message_version());
     ForwardCommand(KM_GET_HW_INFO, GetHwInfoRequest(message_version()), &response);
diff --git a/trusty/keymaster/include/trusty_keymaster/TrustyKeyMintDevice.h b/trusty/keymaster/include/trusty_keymaster/TrustyKeyMintDevice.h
index c8d8932c4..5e876d3d3 100644
--- a/trusty/keymaster/include/trusty_keymaster/TrustyKeyMintDevice.h
+++ b/trusty/keymaster/include/trusty_keymaster/TrustyKeyMintDevice.h
@@ -85,6 +85,7 @@ class TrustyKeyMintDevice : public BnKeyMintDevice {
     ScopedAStatus getRootOfTrust(const array<uint8_t, 16>& challenge,
                                  vector<uint8_t>* rootOfTrust) override;
     ScopedAStatus sendRootOfTrust(const vector<uint8_t>& rootOfTrust) override;
+    ScopedAStatus setAdditionalAttestationInfo(const vector<KeyParameter>& info) override;
 
   protected:
     std::shared_ptr<TrustyKeymaster> impl_;
diff --git a/trusty/keymaster/include/trusty_keymaster/TrustyKeymaster.h b/trusty/keymaster/include/trusty_keymaster/TrustyKeymaster.h
index c50178bcf..65d7217e0 100644
--- a/trusty/keymaster/include/trusty_keymaster/TrustyKeymaster.h
+++ b/trusty/keymaster/include/trusty_keymaster/TrustyKeymaster.h
@@ -70,6 +70,8 @@ class TrustyKeymaster {
     ConfigureVendorPatchlevelResponse ConfigureVendorPatchlevel(
             const ConfigureVendorPatchlevelRequest& request);
     GetRootOfTrustResponse GetRootOfTrust(const GetRootOfTrustRequest& request);
+    SetAdditionalAttestationInfoResponse SetAdditionalAttestationInfo(
+            const SetAdditionalAttestationInfoRequest& request);
     GetHwInfoResponse GetHwInfo();
 
     uint32_t message_version() const { return message_version_; }
diff --git a/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h b/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h
index 822e93334..721315d6f 100644
--- a/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h
+++ b/trusty/keymaster/include/trusty_keymaster/ipc/keymaster_ipc.h
@@ -62,6 +62,7 @@ enum keymaster_command : uint32_t {
     KM_GET_ROOT_OF_TRUST            = (34 << KEYMASTER_REQ_SHIFT),
     KM_GET_HW_INFO                  = (35 << KEYMASTER_REQ_SHIFT),
     KM_GENERATE_CSR_V2              = (36 << KEYMASTER_REQ_SHIFT),
+    KM_SET_ADDITIONAL_ATTESTATION_INFO = (37 << KEYMASTER_REQ_SHIFT),
 
     // Bootloader/provisioning calls.
     KM_SET_BOOT_PARAMS = (0x1000 << KEYMASTER_REQ_SHIFT),
diff --git a/trusty/keymaster/keymint/TrustyKeyMintDevice.cpp b/trusty/keymaster/keymint/TrustyKeyMintDevice.cpp
index fec4c60fe..154597f99 100644
--- a/trusty/keymaster/keymint/TrustyKeyMintDevice.cpp
+++ b/trusty/keymaster/keymint/TrustyKeyMintDevice.cpp
@@ -349,4 +349,18 @@ ScopedAStatus TrustyKeyMintDevice::sendRootOfTrust(const vector<uint8_t>& /* roo
     return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
 }
 
+ScopedAStatus TrustyKeyMintDevice::setAdditionalAttestationInfo(const vector<KeyParameter>& info) {
+    keymaster::SetAdditionalAttestationInfoRequest request(impl_->message_version());
+    request.info.Reinitialize(KmParamSet(info));
+
+    keymaster::SetAdditionalAttestationInfoResponse response =
+            impl_->SetAdditionalAttestationInfo(request);
+
+    if (response.error != KM_ERROR_OK) {
+        return kmError2ScopedAStatus(response.error);
+    } else {
+        return ScopedAStatus::ok();
+    }
+}
+
 }  // namespace aidl::android::hardware::security::keymint::trusty
diff --git a/trusty/keymaster/keymint/android.hardware.security.keymint-service.trusty.xml b/trusty/keymaster/keymint/android.hardware.security.keymint-service.trusty.xml
index 3dc9c88ea..f74d21285 100644
--- a/trusty/keymaster/keymint/android.hardware.security.keymint-service.trusty.xml
+++ b/trusty/keymaster/keymint/android.hardware.security.keymint-service.trusty.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.security.keymint</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IKeyMintDevice/default</fqname>
     </hal>
     <hal format="aidl">
diff --git a/trusty/keymint/Android.bp b/trusty/keymint/Android.bp
index 5cdd381e1..36efb1b89 100644
--- a/trusty/keymint/Android.bp
+++ b/trusty/keymint/Android.bp
@@ -42,9 +42,10 @@ rust_binary {
     defaults: ["android.hardware.security.keymint-service.rust.trusty.default"],
     init_rc: ["android.hardware.security.keymint-service.rust.trusty.rc"],
     vintf_fragments: ["android.hardware.security.keymint-service.rust.trusty.xml"],
-    required: [
-        "android.hardware.hardware_keystore.xml",
-    ],
+    required: select(release_flag("RELEASE_AIDL_USE_UNFROZEN"), {
+        true: ["android.hardware.hardware_keystore.xml"],
+        default: ["android.hardware.hardware_keystore_V3.xml"],
+    }),
 }
 
 rust_binary {
diff --git a/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.system.nonsecure.rc b/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.system.nonsecure.rc
index 2799188c4..e5806510f 100644
--- a/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.system.nonsecure.rc
+++ b/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.system.nonsecure.rc
@@ -11,7 +11,7 @@ service system.keymint.rust-trusty.nonsecure \
 # Only starts the non-secure KeyMint HALs when the KeyMint VM feature is enabled
 # TODO(b/357821690): Start the KeyMint HALs when the KeyMint VM is ready once the Trusty VM
 # has a mechanism to notify the host.
-on late-fs && property:ro.hardware.security.keymint.trusty.system=1 && \
-   property:trusty_vm_system.vm_cid=*
-    setprop system.keymint.trusty_ipc_dev VSOCK:${trusty_vm_system.vm_cid}:1
+on late-fs && property:trusty.security_vm.keymint.enabled=1 && \
+   property:trusty.security_vm.vm_cid=*
+    setprop system.keymint.trusty_ipc_dev VSOCK:${trusty.security_vm.vm_cid}:1
     start system.keymint.rust-trusty.nonsecure
diff --git a/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.xml b/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.xml
index 3dc9c88ea..f74d21285 100644
--- a/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.xml
+++ b/trusty/keymint/android.hardware.security.keymint-service.rust.trusty.xml
@@ -1,7 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.security.keymint</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IKeyMintDevice/default</fqname>
     </hal>
     <hal format="aidl">
diff --git a/trusty/libtrusty/tipc-test/tipc_test.c b/trusty/libtrusty/tipc-test/tipc_test.c
index 3cf0c05f9..121837dc0 100644
--- a/trusty/libtrusty/tipc-test/tipc_test.c
+++ b/trusty/libtrusty/tipc-test/tipc_test.c
@@ -67,7 +67,7 @@ static const char *main_ctrl_name = "com.android.ipc-unittest.ctrl";
 static const char* receiver_name = "com.android.trusty.memref.receiver";
 static const size_t memref_chunk_size = 4096;
 
-static const char* _sopts = "hsvDS:t:r:m:b:B:";
+static const char* _sopts = "hsvD:S:t:r:m:b:B:";
 /* clang-format off */
 static const struct option _lopts[] =  {
     {"help",    no_argument,       0, 'h'},
diff --git a/trusty/metrics/include/trusty/metrics/tipc.h b/trusty/metrics/include/trusty/metrics/tipc.h
index b4428d576..4c4d37df1 100644
--- a/trusty/metrics/include/trusty/metrics/tipc.h
+++ b/trusty/metrics/include/trusty/metrics/tipc.h
@@ -43,6 +43,8 @@
 
 #define UUID_STR_SIZE (37)
 
+#define HASH_SIZE_BYTES 64
+
 /**
  * enum metrics_cmd - command identifiers for metrics interface
  * @METRICS_CMD_RESP_BIT:             message is a response
@@ -112,10 +114,22 @@ struct metrics_report_exit_req {
  *          "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  * @crash_reason: architecture-specific code representing the reason for the
  *                crash
+ * @far: Fault Address Register corresponding to the crash. It is set to 0 and
+ *       not always revealed
+ * @far_hash: Fault Address Register obfuscated, always revealed
+ * @elr: Exception Link Register corresponding to the crash. It is set to 0 and
+ *       not always revealed
+ * @elr_hash: Exception Link Register obfuscated, always revealed
+ * @is_hash: Boolean value indicating whether far and elr have been ob
  */
 struct metrics_report_crash_req {
     char app_id[UUID_STR_SIZE];
     uint32_t crash_reason;
+    uint64_t far;
+    uint8_t far_hash[HASH_SIZE_BYTES];
+    uint64_t elr;
+    uint8_t elr_hash[HASH_SIZE_BYTES];
+    bool is_hash;
 } __attribute__((__packed__));
 
 enum TrustyStorageErrorType {
diff --git a/trusty/secretkeeper/Android.bp b/trusty/secretkeeper/Android.bp
index 6523edaf6..d399bf86d 100644
--- a/trusty/secretkeeper/Android.bp
+++ b/trusty/secretkeeper/Android.bp
@@ -27,18 +27,16 @@ rust_binary {
         "src/hal_main.rs",
     ],
     rustlibs: [
+        "android.hardware.security.secretkeeper-V1-rust",
         "libandroid_logger",
         "libauthgraph_hal",
         "libauthgraph_wire",
         "libbinder_rs",
         "liblibc",
         "liblog_rust",
-        "libsecretkeeper_hal",
+        "libsecretkeeper_hal_v1",
         "libtrusty-rs",
     ],
-    defaults: [
-        "secretkeeper_use_latest_hal_aidl_rust",
-    ],
     prefer_rlib: true,
 }
 
diff --git a/trusty/storage/interface/Android.bp b/trusty/storage/interface/Android.bp
index d031b0c1e..769f53d8e 100644
--- a/trusty/storage/interface/Android.bp
+++ b/trusty/storage/interface/Android.bp
@@ -20,6 +20,7 @@ package {
 
 cc_library_static {
     name: "libtrustystorageinterface",
-    vendor: true,
+    vendor_available: true,
+    system_ext_specific: true,
     export_include_dirs: ["include"],
 }
diff --git a/trusty/storage/proxy/Android.bp b/trusty/storage/proxy/Android.bp
index 7ef0e6f83..f32188a22 100644
--- a/trusty/storage/proxy/Android.bp
+++ b/trusty/storage/proxy/Android.bp
@@ -18,10 +18,8 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-cc_binary {
-    name: "storageproxyd",
-    vendor: true,
-
+cc_defaults {
+    name: "storageproxyd.defaults",
     srcs: [
         "checkpoint_handling.cpp",
         "ipc.c",
@@ -47,14 +45,22 @@ cc_binary {
         "libtrustystorageinterface",
         "libtrusty",
     ],
-    target: {
-        vendor: {
-            // vendor variant requires this flag
-            cflags: ["-DVENDOR_FS_READY_PROPERTY"],
-        },
-    },
     cflags: [
         "-Wall",
         "-Werror",
     ],
 }
+
+cc_binary {
+    name: "storageproxyd",
+    defaults: ["storageproxyd.defaults"],
+    vendor: true,
+    // vendor variant requires this flag
+    cflags: ["-DVENDOR_FS_READY_PROPERTY"],
+}
+
+cc_binary {
+    name: "storageproxyd.system",
+    defaults: ["storageproxyd.defaults"],
+    system_ext_specific: true,
+}
diff --git a/trusty/trusty-storage-cf.mk b/trusty/trusty-storage-cf.mk
new file mode 100644
index 000000000..acefd3e99
--- /dev/null
+++ b/trusty/trusty-storage-cf.mk
@@ -0,0 +1,26 @@
+#
+# Copyright (C) 2024 The Android Open-Source Project
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
+#
+# This makefile should be included by the cuttlefish device
+# when enabling the Trusty VM to pull in the baseline set
+# of storage specific modules
+
+PRODUCT_PACKAGES += \
+	storageproxyd.system \
+	rpmb_dev.system \
+	rpmb_dev.test.system \
+
diff --git a/trusty/utils/rpmb_dev/Android.bp b/trusty/utils/rpmb_dev/Android.bp
index 603a1a80a..2f362e8b7 100644
--- a/trusty/utils/rpmb_dev/Android.bp
+++ b/trusty/utils/rpmb_dev/Android.bp
@@ -15,11 +15,8 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-cc_binary {
-    name: "rpmb_dev",
-    vendor: true,
-    host_supported: true,
-
+cc_defaults {
+    name: "rpmb_dev.cc_defaults",
     srcs: [
         "rpmb_dev.c",
     ],
@@ -32,7 +29,41 @@ cc_binary {
         "-Wall",
         "-Werror",
     ],
+}
+
+cc_binary {
+    name: "rpmb_dev",
+    defaults: ["rpmb_dev.cc_defaults"],
+    vendor: true,
+    host_supported: true,
     init_rc: [
         "rpmb_dev.rc",
     ],
 }
+
+cc_binary {
+    name: "rpmb_dev.system",
+    defaults: ["rpmb_dev.cc_defaults"],
+    system_ext_specific: true,
+    init_rc: [
+        "rpmb_dev.system.rc",
+    ],
+}
+
+cc_binary {
+    name: "rpmb_dev.wv.system",
+    defaults: ["rpmb_dev.cc_defaults"],
+    system_ext_specific: true,
+    init_rc: [
+        "rpmb_dev.wv.system.rc",
+    ],
+}
+
+cc_binary {
+    name: "rpmb_dev.test.system",
+    defaults: ["rpmb_dev.cc_defaults"],
+    system_ext_specific: true,
+    init_rc: [
+        "rpmb_dev.test.system.rc",
+    ],
+}
diff --git a/trusty/utils/rpmb_dev/rpmb_dev.system.rc b/trusty/utils/rpmb_dev/rpmb_dev.system.rc
new file mode 100644
index 000000000..52419ed18
--- /dev/null
+++ b/trusty/utils/rpmb_dev/rpmb_dev.system.rc
@@ -0,0 +1,64 @@
+service storageproxyd_system /system_ext/bin/storageproxyd.system \
+        -d ${storageproxyd_system.trusty_ipc_dev:-/dev/trusty-ipc-dev0} \
+        -r /dev/socket/rpmb_mock_system \
+        -p /data/secure_storage_system \
+        -t sock
+    disabled
+    user system
+    group system
+
+service rpmb_mock_init_system /system_ext/bin/rpmb_dev.system \
+        --dev /mnt/secure_storage_rpmb_system/persist/RPMB_DATA --init --size 2048
+    disabled
+    user system
+    group system
+    oneshot
+
+service rpmb_mock_system /system_ext/bin/rpmb_dev.system \
+        --dev /mnt/secure_storage_rpmb_system/persist/RPMB_DATA \
+        --sock rpmb_mock_system
+    disabled
+    user system
+    group system
+    socket rpmb_mock_system stream 660 system system
+
+# storageproxyd
+on late-fs && \
+    property:trusty.security_vm.nonsecure_vm_ready=1 && \
+    property:storageproxyd_system.trusty_ipc_dev=*
+    wait /dev/socket/rpmb_mock_system
+    start storageproxyd_system
+
+
+# RPMB Mock
+on post-fs && \
+    property:trusty.security_vm.nonsecure_vm_ready=1 && \
+    property:trusty.security_vm.vm_cid=*
+    # Create a persistent location for the RPMB data
+    # (work around lack of RPMb block device on CF).
+    # file contexts secure_storage_rpmb_system_file
+    # (only used on Cuttlefish as this is non secure)
+    mkdir /metadata/secure_storage_rpmb_system 0770 system system
+    mkdir /mnt/secure_storage_rpmb_system 0770 system system
+    symlink /metadata/secure_storage_rpmb_system \
+            /mnt/secure_storage_rpmb_system/persist
+    # Create a system persist directory in /metadata
+    # (work around lack of dedicated system persist partition).
+    # file contexts secure_storage_persist_system_file
+    mkdir /metadata/secure_storage_persist_system 0770 system system
+    mkdir /mnt/secure_storage_persist_system 0770 system system
+    symlink /metadata/secure_storage_persist_system \
+            /mnt/secure_storage_persist_system/persist
+    setprop storageproxyd_system.trusty_ipc_dev VSOCK:${trusty.security_vm.vm_cid}:1
+    exec_start rpmb_mock_init_system
+    start rpmb_mock_system
+
+on post-fs-data && \
+    property:trusty.security_vm.nonsecure_vm_ready=1 && \
+    property:storageproxyd_system.trusty_ipc_dev=*
+    # file contexts secure_storage_system_file
+    mkdir /data/secure_storage_system 0770 root system
+    symlink /mnt/secure_storage_persist_system/persist \
+            /data/secure_storage_system/persist
+    chown root system /data/secure_storage_system/persist
+    restart storageproxyd_system
diff --git a/trusty/utils/rpmb_dev/rpmb_dev.test.system.rc b/trusty/utils/rpmb_dev/rpmb_dev.test.system.rc
new file mode 100644
index 000000000..2127798e1
--- /dev/null
+++ b/trusty/utils/rpmb_dev/rpmb_dev.test.system.rc
@@ -0,0 +1,56 @@
+service trusty_test_vm /apex/com.android.virt/bin/vm run \
+    /data/local/tmp/TrustyTestVM_UnitTests/trusty-test_vm-config.json
+    disabled
+    user system
+    group system
+
+service storageproxyd_test_system /system_ext/bin/storageproxyd.system \
+        -d VSOCK:${trusty.test_vm.vm_cid}:1 \
+        -r /dev/socket/rpmb_mock_test_system \
+        -p /data/secure_storage_test_system \
+        -t sock
+    disabled
+    class hal
+    user system
+    group system
+
+service rpmb_mock_init_test_system /system_ext/bin/rpmb_dev.test.system \
+        --dev /mnt/secure_storage_rpmb_test_system/persist/RPMB_DATA --init --size 2048
+    disabled
+    user system
+    group system
+    oneshot
+
+service rpmb_mock_test_system /system_ext/bin/rpmb_dev.test.system \
+        --dev /mnt/secure_storage_rpmb_test_system/persist/RPMB_DATA \
+        --sock rpmb_mock_test_system
+    disabled
+    user system
+    group system
+    socket rpmb_mock_test_system stream 660 system system
+
+# RPMB Mock
+on post-fs-data
+    # Create a persistent location for the RPMB data
+    # (work around lack of RPMb block device on CF).
+    # file contexts secure_storage_rpmb_system_file
+    # (only used on Cuttlefish as this is non secure)
+    mkdir /metadata/secure_storage_rpmb_test_system 0770 system system
+    mkdir /mnt/secure_storage_rpmb_test_system 0770 system system
+    symlink /metadata/secure_storage_rpmb_test_system \
+            /mnt/secure_storage_rpmb_test_system/persist
+    # Create a system persist directory in /metadata
+    # (work around lack of dedicated system persist partition).
+    # file contexts secure_storage_persist_system_file
+    mkdir /metadata/secure_storage_persist_test_system 0770 system system
+    mkdir /mnt/secure_storage_persist_test_system 0770 system system
+    symlink /metadata/secure_storage_persist_test_system \
+            /mnt/secure_storage_persist_test_system/persist
+    # file contexts secure_storage_system_file
+    mkdir /data/secure_storage_test_system 0770 root system
+    symlink /mnt/secure_storage_persist_test_system/persist \
+            /data/secure_storage_test_system/persist
+    chown root system /data/secure_storage_test_system/persist
+    # setprop storageproxyd_test_system.trusty_ipc_dev VSOCK:${trusty.test_vm.vm_cid}:1
+    exec_start rpmb_mock_init_test_system
+    start rpmb_mock_test_system
diff --git a/trusty/utils/rpmb_dev/rpmb_dev.wv.system.rc b/trusty/utils/rpmb_dev/rpmb_dev.wv.system.rc
new file mode 100644
index 000000000..3e7f8b44f
--- /dev/null
+++ b/trusty/utils/rpmb_dev/rpmb_dev.wv.system.rc
@@ -0,0 +1,62 @@
+service storageproxyd_wv_system /system_ext/bin/storageproxyd.system \
+        -d ${storageproxyd_wv_system.trusty_ipc_dev:-/dev/trusty-ipc-dev0} \
+        -r /dev/socket/rpmb_mock_wv_system \
+        -p /data/secure_storage_wv_system \
+        -t sock
+    disabled
+    class hal
+    user system
+    group system
+
+service rpmb_mock_init_wv_system /system_ext/bin/rpmb_dev.wv.system \
+        --dev /mnt/secure_storage_rpmb_wv_system/persist/RPMB_DATA --init --size 2048
+    disabled
+    user system
+    group system
+    oneshot
+
+service rpmb_mock_wv_system /system_ext/bin/rpmb_dev.wv.system \
+        --dev /mnt/secure_storage_rpmb_wv_system/persist/RPMB_DATA \
+        --sock rpmb_mock_wv_system
+    disabled
+    user system
+    group system
+    socket rpmb_mock_wv_system stream 660 system system
+
+# storageproxyd
+on boot && \
+    property:trusty.widevine_vm.nonsecure_vm_ready=1 && \
+    property:storageproxyd_wv_system.trusty_ipc_dev=*
+    wait /dev/socket/rpmb_mock_wv_system
+    enable storageproxyd_wv_system
+
+
+# RPMB Mock
+on early-boot && \
+    property:ro.hardware.security.trusty.widevine_vm.system=1 && \
+    property:trusty.widevine_vm.vm_cid=* && \
+    property:ro.boot.vendor.apex.com.android.services.widevine=\
+com.android.services.widevine.cf_guest_trusty_nonsecure
+    # Create a persistent location for the RPMB data
+    # (work around lack of RPMb block device on CF).
+    # file contexts secure_storage_rpmb_system_file
+    # (only used on Cuttlefish as this is non secure)
+    mkdir /metadata/secure_storage_rpmb_wv_system 0770 system system
+    mkdir /mnt/secure_storage_rpmb_wv_system 0770 system system
+    symlink /metadata/secure_storage_rpmb_wv_system \
+            /mnt/secure_storage_rpmb_wv_system/persist
+    # Create a system persist directory in /metadata
+    # (work around lack of dedicated system persist partition).
+    # file contexts secure_storage_persist_system_file
+    mkdir /metadata/secure_storage_persist_wv_system 0770 system system
+    mkdir /mnt/secure_storage_persist_wv_system 0770 system system
+    symlink /metadata/secure_storage_persist_wv_system \
+            /mnt/secure_storage_persist_wv_system/persist
+    # file contexts secure_storage_system_file
+    mkdir /data/secure_storage_wv_system 0770 root system
+    symlink /mnt/secure_storage_persist_wv_system/persist \
+            /data/secure_storage_wv_system/persist
+    chown root system /data/secure_storage_wv_system/persist
+    setprop storageproxyd_wv_system.trusty_ipc_dev VSOCK:${trusty.widevine_vm.vm_cid}:1
+    exec_start rpmb_mock_init_wv_system
+    start rpmb_mock_wv_system
diff --git a/trusty/utils/trusty-ut-ctrl/Android.bp b/trusty/utils/trusty-ut-ctrl/Android.bp
index 6fc2a48d7..c255614b0 100644
--- a/trusty/utils/trusty-ut-ctrl/Android.bp
+++ b/trusty/utils/trusty-ut-ctrl/Android.bp
@@ -16,9 +16,8 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-cc_binary {
-    name: "trusty-ut-ctrl",
-    vendor: true,
+cc_defaults {
+    name: "trusty-ut-ctrl.defaults",
 
     srcs: ["ut-ctrl.c"],
     shared_libs: [
@@ -33,3 +32,15 @@ cc_binary {
         "-Werror",
     ],
 }
+
+cc_binary {
+    name: "trusty-ut-ctrl",
+    defaults: ["trusty-ut-ctrl.defaults"],
+    vendor: true,
+}
+
+cc_binary {
+    name: "trusty-ut-ctrl.system",
+    defaults: ["trusty-ut-ctrl.defaults"],
+    system_ext_specific: true,
+}
diff --git a/trusty/utils/trusty-ut-ctrl/ut-ctrl.c b/trusty/utils/trusty-ut-ctrl/ut-ctrl.c
index 6cc66707e..31cfd4c79 100644
--- a/trusty/utils/trusty-ut-ctrl/ut-ctrl.c
+++ b/trusty/utils/trusty-ut-ctrl/ut-ctrl.c
@@ -95,12 +95,26 @@ enum test_message_header {
     TEST_FAILED = 1,
     TEST_MESSAGE = 2,
     TEST_TEXT = 3,
+    TEST_OPCODE_COUNT,
 };
 
+static int get_msg_len(const char* buf, int max_buf_len) {
+    int buf_len;
+    for (buf_len = 0; buf_len < max_buf_len; buf_len++) {
+        if ((unsigned char)buf[buf_len] < TEST_OPCODE_COUNT) {
+            break;
+        }
+    }
+    return buf_len;
+}
+
 static int run_trusty_unitest(const char* utapp) {
     int fd;
-    int rc;
-    char rx_buf[1024];
+    char read_buf[1024];
+    int read_len;
+    char* rx_buf;
+    int rx_buf_len;
+    int cmd = -1;
 
     /* connect to unitest app */
     fd = tipc_connect(dev_name, utapp);
@@ -110,22 +124,39 @@ static int run_trusty_unitest(const char* utapp) {
     }
 
     /* wait for test to complete */
+    rx_buf_len = 0;
     for (;;) {
-        rc = read(fd, rx_buf, sizeof(rx_buf));
-        if (rc <= 0 || rc >= (int)sizeof(rx_buf)) {
-            fprintf(stderr, "%s: Read failed: %d\n", __func__, rc);
-            tipc_close(fd);
-            return -1;
+        if (rx_buf_len == 0) {
+            read_len = read(fd, read_buf, sizeof(read_buf));
+            if (read_len <= 0 || read_len > (int)sizeof(read_buf)) {
+                fprintf(stderr, "%s: Read failed: %d, %s\n", __func__, read_len,
+                        read_len < 0 ? strerror(errno) : "");
+                tipc_close(fd);
+                return -1;
+            }
+            rx_buf = read_buf;
+            rx_buf_len = read_len;
+        }
+
+        int msg_len = get_msg_len(rx_buf, rx_buf_len);
+        if (msg_len == 0) {
+            cmd = rx_buf[0];
+            rx_buf++;
+            rx_buf_len--;
         }
 
-        if (rx_buf[0] == TEST_PASSED) {
+        if (cmd == TEST_PASSED) {
             break;
-        } else if (rx_buf[0] == TEST_FAILED) {
+        } else if (cmd == TEST_FAILED) {
             break;
-        } else if (rx_buf[0] == TEST_MESSAGE || rx_buf[0] == TEST_TEXT) {
-            write(STDOUT_FILENO, rx_buf + 1, rc - 1);
+        } else if (cmd == TEST_MESSAGE || cmd == TEST_TEXT) {
+            if (msg_len) {
+                write(STDOUT_FILENO, rx_buf, msg_len);
+                rx_buf += msg_len;
+                rx_buf_len -= msg_len;
+            }
         } else {
-            fprintf(stderr, "%s: Bad message header: %d\n", __func__, rx_buf[0]);
+            fprintf(stderr, "%s: Bad message header: %d\n", __func__, cmd);
             break;
         }
     }
@@ -133,7 +164,7 @@ static int run_trusty_unitest(const char* utapp) {
     /* close connection to unitest app */
     tipc_close(fd);
 
-    return rx_buf[0] == TEST_PASSED ? 0 : -1;
+    return cmd == TEST_PASSED ? 0 : -1;
 }
 
 int main(int argc, char** argv) {
diff --git a/watchdogd/Android.bp b/watchdogd/Android.bp
index 03882082f..bc7ffb656 100644
--- a/watchdogd/Android.bp
+++ b/watchdogd/Android.bp
@@ -2,9 +2,8 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-cc_binary {
-    name: "watchdogd",
-    recovery_available: true,
+cc_defaults {
+    name: "watchdogd_defaults",
     srcs: ["watchdogd.cpp"],
     cflags: [
         "-Wall",
@@ -16,3 +15,19 @@ cc_binary {
         misc_undefined: ["signed-integer-overflow"],
     },
 }
+
+cc_binary {
+    name: "watchdogd",
+    defaults: [
+        "watchdogd_defaults",
+    ],
+}
+
+cc_binary {
+    name: "watchdogd.recovery",
+    defaults: [
+        "watchdogd_defaults",
+    ],
+    recovery: true,
+    stem: "watchdogd",
+}
```

